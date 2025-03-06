```diff
diff --git a/Android.bp b/Android.bp
index 82df238..08dbeaf 100644
--- a/Android.bp
+++ b/Android.bp
@@ -146,8 +146,6 @@ cc_defaults {
         "f2fs-tools-defaults",
         "make_f2fs_src_files",
     ],
-    host_supported: true,
-    recovery_available: true,
     target: {
         android: {
             static_libs: [
@@ -159,6 +157,16 @@ cc_defaults {
                 "libbase",
             ],
         },
+    },
+}
+
+cc_defaults {
+    name: "make_f2fs_host_defaults",
+    defaults: [
+        "make_f2fs_defaults",
+    ],
+    host_supported: true,
+    target: {
         host: {
             static_libs: [
                 "libf2fs_fmt_host",
@@ -180,16 +188,26 @@ cc_defaults {
 
 cc_binary {
     name: "make_f2fs",
+    defaults: [
+        "make_f2fs_host_defaults",
+    ],
+}
+
+cc_binary {
+    name: "make_f2fs.recovery",
     defaults: [
         "make_f2fs_defaults",
     ],
+    recovery: true,
+    stem: "make_f2fs",
 }
 
 cc_binary_host {
     name: "make_f2fs_casefold",
     defaults: [
-        "make_f2fs_defaults",
+        "make_f2fs_host_defaults",
     ],
+    recovery_available: true,
     target: {
         host: {
             cflags: ["-DCONF_CASEFOLD", "-DCONF_PROJID"],
@@ -203,8 +221,9 @@ cc_binary_host {
 cc_binary_host {
     name: "make_f2fs.static",
     defaults: [
-        "make_f2fs_defaults",
+        "make_f2fs_host_defaults",
     ],
+    recovery_available: true,
     static_executable: true,
     stl: "libc++_static",
 }
@@ -219,18 +238,14 @@ cc_defaults {
     srcs: ["fsck/fsck.c", "fsck/resize.c", "fsck/defrag.c"],
 }
 
-cc_binary {
-    name: "fsck.f2fs",
+cc_defaults {
+    name: "fsck.f2fs_partition_common_defaults",
     defaults: [
         "f2fs-tools-defaults",
         "fsck_main_src_files",
         "fsck.f2fs_defaults",
     ],
-    host_supported: true,
-    vendor_available: true,
-    recovery_available: true,
     symlinks: ["resize.f2fs", "defrag.f2fs", "dump.f2fs"],
-    vendor_ramdisk_available: true,
     shared_libs: [
         "libext2_uuid",
         "libsparse",
@@ -239,6 +254,27 @@ cc_binary {
     bootstrap: true,
 }
 
+cc_binary {
+    name: "fsck.f2fs",
+    defaults: [
+        "fsck.f2fs_partition_common_defaults",
+    ],
+    host_supported: true,
+    vendor_available: true,
+    vendor_ramdisk_available: true,
+    bootstrap: true,
+}
+
+cc_binary {
+    name: "fsck.f2fs.recovery",
+    defaults: [
+        "fsck.f2fs_partition_common_defaults",
+    ],
+    recovery: true,
+    bootstrap: true,
+    stem: "fsck.f2fs",
+}
+
 cc_binary {
     name: "fsck.f2fs_ramdisk",
     stem: "fsck.f2fs",
@@ -257,14 +293,12 @@ cc_binary {
     ],
 }
 
-cc_binary {
-    name: "sload_f2fs",
+cc_defaults {
+    name: "sload_f2fs_defaults",
     defaults: [
         "f2fs-tools-defaults",
         "fsck_main_src_files",
     ],
-    host_supported: true,
-    recovery_available: true,
     cflags: ["-DWITH_SLOAD"],
     srcs: [
         "fsck/fsck.c",
@@ -284,6 +318,16 @@ cc_binary {
                 "liblz4",
             ],
         },
+    },
+}
+
+cc_binary {
+    name: "sload_f2fs",
+    defaults: [
+        "sload_f2fs_defaults",
+    ],
+    host_supported: true,
+    target: {
         host: {
             static_libs: [
                 "libext2_uuid",
@@ -300,6 +344,15 @@ cc_binary {
     },
 }
 
+cc_binary {
+    name: "sload_f2fs.recovery",
+    defaults: [
+        "sload_f2fs_defaults",
+    ],
+    recovery: true,
+    stem: "sload_f2fs",
+}
+
 cc_binary {
     name: "check_f2fs",
     host_supported: false,
diff --git a/METADATA b/METADATA
index b35d533..79bcd6a 100644
--- a/METADATA
+++ b/METADATA
@@ -8,13 +8,13 @@ third_party {
   license_type: RESTRICTED
   last_upgrade_date {
     year: 2024
-    month: 8
-    day: 16
+    month: 11
+    day: 13
   }
   homepage: "https://git.kernel.org/pub/scm/linux/kernel/git/jaegeuk/f2fs-tools.git/"
   identifier {
     type: "Git"
     value: "https://git.kernel.org/pub/scm/linux/kernel/git/jaegeuk/f2fs-tools.git"
-    version: "b9a68f381b3447b8df10102757a34431cc2b2eb6"
+    version: "ad3736cca5284ca1b1521e5826f81f496d86d0ff"
   }
 }
diff --git a/configure.ac b/configure.ac
index 21c6391..2053a65 100644
--- a/configure.ac
+++ b/configure.ac
@@ -139,6 +139,8 @@ AC_CHECK_HEADERS(m4_flatten([
 	fcntl.h
 	kernel/uapi/linux/blkzoned.h
 	linux/blkzoned.h
+	linux/rw_hint.h
+	linux/fcntl.h
 	linux/falloc.h
 	linux/fiemap.h
 	linux/fs.h
diff --git a/fsck/defrag.c b/fsck/defrag.c
index 361fe73..9889b70 100644
--- a/fsck/defrag.c
+++ b/fsck/defrag.c
@@ -23,12 +23,13 @@ static int migrate_block(struct f2fs_sb_info *sbi, u64 from, u64 to)
 	ret = dev_read_block(raw, from);
 	ASSERT(ret >= 0);
 
+	/* get segment type */
+	se = get_seg_entry(sbi, GET_SEGNO(sbi, from));
 	/* write to */
-	ret = dev_write_block(raw, to);
+	ret = dev_write_block(raw, to, f2fs_io_type_to_rw_hint(se->type));
 	ASSERT(ret >= 0);
 
 	/* update sit bitmap & valid_blocks && se->type */
-	se = get_seg_entry(sbi, GET_SEGNO(sbi, from));
 	offset = OFFSET_IN_SEG(sbi, from);
 	type = se->type;
 	se->valid_blocks--;
diff --git a/fsck/dir.c b/fsck/dir.c
index 3fac850..4debda8 100644
--- a/fsck/dir.c
+++ b/fsck/dir.c
@@ -299,7 +299,9 @@ add_dentry:
 
 	if (c.zoned_model == F2FS_ZONED_HM) {
 		if (datablk_alloced) {
-			ret = dev_write_block(dentry_blk, dn.data_blkaddr);
+			/* dentry uses hot data segment */
+			ret = dev_write_block(dentry_blk, dn.data_blkaddr,
+				f2fs_io_type_to_rw_hint(CURSEG_HOT_DATA));
 		} else {
 			ret = update_block(sbi, dentry_blk, &dn.data_blkaddr,
 					dn.node_blk);
@@ -309,7 +311,9 @@ add_dentry:
 				dn.ndirty = 1;
 		}
 	} else {
-		ret = dev_write_block(dentry_blk, dn.data_blkaddr);
+		/* dentry uses hot data segment */
+		ret = dev_write_block(dentry_blk, dn.data_blkaddr,
+				f2fs_io_type_to_rw_hint(CURSEG_HOT_DATA));
 	}
 	ASSERT(ret >= 0);
 
@@ -336,8 +340,13 @@ add_dentry:
 	}
 
 	if (dn.ndirty) {
+		struct seg_entry *se;
+
+		/* get segment type for rw hint */
+		se = get_seg_entry(sbi, GET_SEGNO(sbi, dn.node_blkaddr));
 		ret = dn.alloced ?
-			dev_write_block(dn.node_blk, dn.node_blkaddr) :
+			dev_write_block(dn.node_blk, dn.node_blkaddr,
+					f2fs_io_type_to_rw_hint(se->type)) :
 			update_block(sbi, dn.node_blk, &dn.node_blkaddr, NULL);
 		ASSERT(ret >= 0);
 	}
@@ -388,7 +397,8 @@ static void make_empty_dir(struct f2fs_sb_info *sbi, struct f2fs_node *inode)
 	ret = reserve_new_block(sbi, &blkaddr, &sum, CURSEG_HOT_DATA, 0);
 	ASSERT(!ret);
 
-	ret = dev_write_block(dent_blk, blkaddr);
+	ret = dev_write_block(dent_blk, blkaddr,
+			      f2fs_io_type_to_rw_hint(CURSEG_HOT_DATA));
 	ASSERT(ret >= 0);
 
 	inode->i.i_addr[get_extra_isize(inode)] = cpu_to_le32(blkaddr);
@@ -424,7 +434,8 @@ static void page_symlink(struct f2fs_sb_info *sbi, struct f2fs_node *inode,
 	ret = reserve_new_block(sbi, &blkaddr, &sum, CURSEG_WARM_DATA, 0);
 	ASSERT(!ret);
 
-	ret = dev_write_block(data_blk, blkaddr);
+	ret = dev_write_block(data_blk, blkaddr,
+			      f2fs_io_type_to_rw_hint(CURSEG_WARM_DATA));
 	ASSERT(ret >= 0);
 
 	inode->i.i_addr[get_extra_isize(inode)] = cpu_to_le32(blkaddr);
@@ -618,7 +629,8 @@ int convert_inline_dentry(struct f2fs_sb_info *sbi, struct f2fs_node *node,
 		memcpy(dst.filename, src.filename, src.max * F2FS_SLOT_LEN);
 
 		ret = datablk_alloced ?
-			dev_write_block(dentry_blk, dn.data_blkaddr) :
+			dev_write_block(dentry_blk, dn.data_blkaddr,
+					f2fs_io_type_to_rw_hint(CURSEG_HOT_DATA)) :
 			update_block(sbi, dentry_blk, &dn.data_blkaddr, NULL);
 		ASSERT(ret >= 0);
 
@@ -818,7 +830,8 @@ int f2fs_create(struct f2fs_sb_info *sbi, struct dentry *de)
 	update_nat_blkaddr(sbi, de->ino, de->ino, blkaddr);
 
 write_child_dir:
-	ret = nodeblk_alloced ? dev_write_block(child, blkaddr) :
+	ret = nodeblk_alloced ? dev_write_block(child, blkaddr,
+			f2fs_io_type_to_rw_hint(CURSEG_HOT_NODE)) :
 		update_block(sbi, child, &blkaddr, NULL);
 	ASSERT(ret >= 0);
 
diff --git a/fsck/dump.c b/fsck/dump.c
index 448c0ef..dc3c199 100644
--- a/fsck/dump.c
+++ b/fsck/dump.c
@@ -527,6 +527,19 @@ static int dump_inode_blk(struct f2fs_sb_info *sbi, u32 nid,
 	}
 
 	c.show_file_map_max_offset = f2fs_max_file_offset(&node_blk->i);
+
+	if (IS_DEVICE_ALIASING(&node_blk->i)) {
+		u32 blkaddr = le32_to_cpu(node_blk->i.i_ext.blk_addr);
+		u32 len = le32_to_cpu(node_blk->i.i_ext.len);
+		u32 idx;
+
+		for (idx = 0; idx < len; idx++)
+			dump_data_blk(sbi, idx * F2FS_BLKSIZE, blkaddr++, type);
+		print_extent(true);
+
+		goto dump_xattr;
+	}
+
 	addr_per_block = ADDRS_PER_BLOCK(&node_blk->i);
 
 	/* check data blocks in inode */
diff --git a/fsck/fsck.c b/fsck/fsck.c
index a18bee9..aa3fb97 100644
--- a/fsck/fsck.c
+++ b/fsck/fsck.c
@@ -216,7 +216,7 @@ static int is_valid_ssa_node_blk(struct f2fs_sb_info *sbi, u32 nid,
 		int ret2;
 
 		ssa_blk = GET_SUM_BLKADDR(sbi, segno);
-		ret2 = dev_write_block(sum_blk, ssa_blk);
+		ret2 = dev_write_block(sum_blk, ssa_blk, WRITE_LIFE_NONE);
 		ASSERT(ret2 >= 0);
 	}
 out:
@@ -350,7 +350,7 @@ static int is_valid_ssa_data_blk(struct f2fs_sb_info *sbi, u32 blk_addr,
 		int ret2;
 
 		ssa_blk = GET_SUM_BLKADDR(sbi, segno);
-		ret2 = dev_write_block(sum_blk, ssa_blk);
+		ret2 = dev_write_block(sum_blk, ssa_blk, WRITE_LIFE_NONE);
 		ASSERT(ret2 >= 0);
 	}
 out:
@@ -902,6 +902,7 @@ void fsck_chk_inode_blk(struct f2fs_sb_info *sbi, u32 nid,
 	int need_fix = 0;
 	int ret;
 	u32 cluster_size = 1 << node_blk->i.i_log_cluster_size;
+	bool is_aliasing = IS_DEVICE_ALIASING(&node_blk->i);
 
 	if (!compressed)
 		goto check_next;
@@ -1132,6 +1133,33 @@ check_next:
 				addrs_per_blk * NIDS_PER_BLOCK *
 				NIDS_PER_BLOCK) * F2FS_BLKSIZE;
 	}
+
+	if (is_aliasing) {
+		struct extent_info ei;
+
+		get_extent_info(&ei, &node_blk->i.i_ext);
+		for (idx = 0; idx < ei.len; idx++, child.pgofs++) {
+			block_t blkaddr = ei.blk + idx;
+
+			/* check extent info */
+			check_extent_info(&child, blkaddr, 0);
+			ret = fsck_chk_data_blk(sbi, &node_blk->i, blkaddr,
+				&child, (i_blocks == *blk_cnt),	ftype, nid,
+				idx, ni->version, node_blk);
+			if (!ret) {
+				*blk_cnt = *blk_cnt + 1;
+				if (cur_qtype != -1)
+					qf_last_blkofs[cur_qtype] = child.pgofs;
+			} else if (c.fix_on) {
+				node_blk->i.i_ext.len = cpu_to_le32(idx);
+				need_fix = 1;
+				break;
+			}
+		}
+
+		goto check;
+	}
+
 	for (idx = 0; idx < addrs; idx++, child.pgofs++) {
 		block_t blkaddr = le32_to_cpu(node_blk->i.i_addr[ofs + idx]);
 
@@ -1164,11 +1192,11 @@ check_next:
 				child.pgofs - cbc->cheader_pgofs < cluster_size)
 			cbc->cnt++;
 		ret = fsck_chk_data_blk(sbi,
-				IS_CASEFOLDED(&node_blk->i),
+				&node_blk->i,
 				blkaddr,
 				&child, (i_blocks == *blk_cnt),
 				ftype, nid, idx, ni->version,
-				file_is_encrypt(&node_blk->i), node_blk);
+				node_blk);
 		if (blkaddr != le32_to_cpu(node_blk->i.i_addr[ofs + idx]))
 			need_fix = 1;
 		if (!ret) {
@@ -1307,17 +1335,51 @@ skip_blkcnt_fix:
 						nid, i_links, child.links);
 			}
 		}
-		if (child.dots < 2 &&
-				!(node_blk->i.i_inline & F2FS_INLINE_DOTS)) {
-			ASSERT_MSG("ino: 0x%x dots: %u",
-					nid, child.dots);
+		if (child.dot == 0 || child.dotdot == 0) {
+			ASSERT_MSG("ino: 0x%x has no '.' and/or '..' dirents, dot: %u, dotdot: %u",
+					nid, child.dot, child.dotdot);
 			if (c.fix_on) {
-				node_blk->i.i_inline |= F2FS_INLINE_DOTS;
+				umode_t mode = le16_to_cpu(node_blk->i.i_mode);
+
+				ret = convert_inline_dentry(sbi, node_blk,
+								&ni->blk_addr);
+				FIX_MSG("convert inline dentry ino: %u, pino: %u, ret: %d",
+						nid, child_d->p_ino, ret);
+				if (ret)
+					goto skip_dot_fix;
+
+				if (child.dot == 0) {
+					char *name = ".";
+
+					ret = f2fs_add_link(sbi, node_blk,
+						(const unsigned char *)name,
+						1, nid, map_de_type(mode),
+						&ni->blk_addr, 0);
+					FIX_MSG("add missing '%s' dirent in ino: %u, pino: %u, ret:%d",
+						name, nid, child_d->p_ino, ret);
+					if (ret)
+						goto skip_dot_fix;
+				}
+
+				if (child.dotdot == 0) {
+					char *name = "..";
+
+					ret = f2fs_add_link(sbi, node_blk,
+						(const unsigned char *)name,
+						2, child_d->p_ino,
+						map_de_type(mode),
+						&ni->blk_addr, 0);
+					FIX_MSG("add missing '%s' dirent in ino: %u, pino: %u, ret:%d",
+						name, nid, child_d->p_ino, ret);
+					if (ret)
+						goto skip_dot_fix;
+				}
+
 				need_fix = 1;
-				FIX_MSG("Dir: 0x%x set inline_dots", nid);
 			}
 		}
 	}
+skip_dot_fix:
 
 	i_gc_failures = le16_to_cpu(node_blk->i.i_gc_failures);
 
@@ -1362,7 +1424,7 @@ skip_blkcnt_fix:
 	}
 
 	/* drop extent information to avoid potential wrong access */
-	if (need_fix && f2fs_dev_is_writable())
+	if (need_fix && f2fs_dev_is_writable() && !is_aliasing)
 		node_blk->i.i_ext.len = 0;
 
 	if ((c.feature & F2FS_FEATURE_INODE_CHKSUM) &&
@@ -1386,8 +1448,6 @@ skip_blkcnt_fix:
 	}
 
 	if (need_fix && f2fs_dev_is_writable()) {
-		if (c.zoned_model == F2FS_ZONED_HM)
-			node_blk->i.i_ext.len = 0;
 		ret = update_block(sbi, node_blk, &ni->blk_addr, NULL);
 		ASSERT(ret >= 0);
 	}
@@ -1436,11 +1496,9 @@ int fsck_chk_dnode_blk(struct f2fs_sb_info *sbi, struct f2fs_inode *inode,
 		if (!compr_rel && blkaddr == NEW_ADDR && child->pgofs -
 				cbc->cheader_pgofs < cluster_size)
 			cbc->cnt++;
-		ret = fsck_chk_data_blk(sbi, IS_CASEFOLDED(inode),
-			blkaddr, child,
+		ret = fsck_chk_data_blk(sbi, inode, blkaddr, child,
 			le64_to_cpu(inode->i_blocks) == *blk_cnt, ftype,
-			nid, idx, ni->version,
-			file_is_encrypt(inode), node_blk);
+			nid, idx, ni->version, node_blk);
 		if (blkaddr != le32_to_cpu(node_blk->dn.addr[idx]))
 			need_fix = 1;
 		if (!ret) {
@@ -1862,26 +1920,45 @@ static int __chk_dentries(struct f2fs_sb_info *sbi, int casefolded,
 
 		/* Becareful. 'dentry.file_type' is not imode. */
 		if (ftype == F2FS_FT_DIR) {
-			if ((name[0] == '.' && name_len == 1) ||
-				(name[0] == '.' && name[1] == '.' &&
-							name_len == 2)) {
-				ret = __chk_dots_dentries(sbi, casefolded, &dentry[i],
-					child, name, name_len, &filenames[i],
-					enc_name);
-				switch (ret) {
-				case 1:
+			enum dot_type dot_type = NON_DOT;
+
+			if (name[0] == '.' && name_len == 1)
+				dot_type = TYPE_DOT;
+			else if (name[0] == '.' && name[1] == '.' &&
+						name_len == 2)
+				dot_type = TYPE_DOTDOT;
+
+			if (dot_type != NON_DOT) {
+				bool need_del = false;
+
+				DBG(3, "i:%u, dot_type:%u, ino:%u, p:%u, pp:%u\n",
+					i, dot_type, dentry[i].ino,
+					child->p_ino, child->pp_ino);
+
+				ret = __chk_dots_dentries(sbi, casefolded,
+					&dentry[i], child, name, name_len,
+					&filenames[i], enc_name);
+				if (ret)
 					fixed = 1;
-					fallthrough;
-				case 0:
-					child->dots++;
-					break;
+
+				if (dot_type == TYPE_DOT) {
+					if (child->dot == 0)
+						child->dot++;
+					else
+						need_del = true;
+				} else if (dot_type == TYPE_DOTDOT) {
+					if (child->dotdot == 0)
+						child->dotdot++;
+					else
+						need_del = true;
 				}
 
-				if (child->dots > 2) {
-					ASSERT_MSG("More than one '.' or '..', should delete the extra one\n");
+				if (need_del) {
+					ASSERT_MSG("More than one '%s', should delete the extra one, i: %u, ino:%u",
+						dot_type == TYPE_DOT ? "." : "..",
+						i, dentry[i].ino);
 					nullify_dentry(&dentry[i], i,
 						       &filenames[i], &bitmap);
-					child->dots--;
 					fixed = 1;
 				}
 
@@ -2044,12 +2121,15 @@ int fsck_chk_dentry_blk(struct f2fs_sb_info *sbi, int casefolded, u32 blk_addr,
 	return 0;
 }
 
-int fsck_chk_data_blk(struct f2fs_sb_info *sbi, int casefolded,
+int fsck_chk_data_blk(struct f2fs_sb_info *sbi, struct f2fs_inode *inode,
 		u32 blk_addr, struct child_info *child, int last_blk,
 		enum FILE_TYPE ftype, u32 parent_nid, u16 idx_in_node, u8 ver,
-		int enc_name, struct f2fs_node *node_blk)
+		struct f2fs_node *node_blk)
 {
 	struct f2fs_fsck *fsck = F2FS_FSCK(sbi);
+	int casefolded = IS_CASEFOLDED(inode);
+	int enc_name = file_is_encrypt(inode);
+	int aliasing = IS_DEVICE_ALIASING(inode);
 
 	/* Is it reserved block? */
 	if (blk_addr == NEW_ADDR) {
@@ -2062,7 +2142,7 @@ int fsck_chk_data_blk(struct f2fs_sb_info *sbi, int casefolded,
 		return -EINVAL;
 	}
 
-	if (is_valid_ssa_data_blk(sbi, blk_addr, parent_nid,
+	if (!aliasing && is_valid_ssa_data_blk(sbi, blk_addr, parent_nid,
 						idx_in_node, ver)) {
 		ASSERT_MSG("summary data block is not valid. [0x%x]",
 						parent_nid);
@@ -2153,7 +2233,8 @@ int fsck_chk_orphan_node(struct f2fs_sb_info *sbi)
 		if (f2fs_dev_is_writable() && c.fix_on &&
 				entry_count != new_entry_count) {
 			F2FS_ORPHAN_BLOCK_FOOTER(new_blk)->entry_count = cpu_to_le32(new_entry_count);
-			ret = dev_write_block(new_blk, start_blk + i);
+			ret = dev_write_block(new_blk, start_blk + i,
+					      WRITE_LIFE_NONE);
 			ASSERT(ret >= 0);
 		}
 		memset(orphan_blk, 0, F2FS_BLKSIZE);
@@ -2569,12 +2650,13 @@ static void fix_checkpoint(struct f2fs_sb_info *sbi)
 	if (sbi->cur_cp == 2)
 		cp_blk_no += 1 << get_sb(log_blocks_per_seg);
 
-	ret = dev_write_block(cp, cp_blk_no++);
+	ret = dev_write_block(cp, cp_blk_no++, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 
 	for (i = 0; i < get_sb(cp_payload); i++) {
 		ret = dev_write_block(((unsigned char *)cp) +
-					(i + 1) * F2FS_BLKSIZE, cp_blk_no++);
+					(i + 1) * F2FS_BLKSIZE, cp_blk_no++,
+					WRITE_LIFE_NONE);
 		ASSERT(ret >= 0);
 	}
 
@@ -2586,7 +2668,8 @@ static void fix_checkpoint(struct f2fs_sb_info *sbi)
 		if (!(flags & CP_UMOUNT_FLAG) && IS_NODESEG(i))
 			continue;
 
-		ret = dev_write_block(curseg->sum_blk, cp_blk_no++);
+		ret = dev_write_block(curseg->sum_blk, cp_blk_no++,
+				      WRITE_LIFE_NONE);
 		ASSERT(ret >= 0);
 	}
 
@@ -2597,7 +2680,7 @@ static void fix_checkpoint(struct f2fs_sb_info *sbi)
 	ret = f2fs_fsync_device();
 	ASSERT(ret >= 0);
 
-	ret = dev_write_block(cp, cp_blk_no++);
+	ret = dev_write_block(cp, cp_blk_no++, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 
 	ret = f2fs_fsync_device();
@@ -3328,9 +3411,11 @@ static int chk_and_fix_wp_with_sit(int UNUSED(i), void *blkzone, void *opaque)
 	if (ret) {
 		u64 fill_sects = blk_zone_length(blkz) -
 			(blk_zone_wp_sector(blkz) - blk_zone_sector(blkz));
+		struct seg_entry *se = get_seg_entry(sbi, wp_segno);
 		printf("[FSCK] Finishing zone failed: %s\n", dev->path);
 		ret = dev_fill(NULL, wp_block * F2FS_BLKSIZE,
-			(fill_sects >> log_sectors_per_block) * F2FS_BLKSIZE);
+			(fill_sects >> log_sectors_per_block) * F2FS_BLKSIZE,
+			f2fs_io_type_to_rw_hint(se->type));
 		if (ret)
 			printf("[FSCK] Fill up zone failed: %s\n", dev->path);
 	}
@@ -3646,7 +3731,8 @@ int fsck_verify(struct f2fs_sb_info *sbi)
 					ssa_blk = GET_SUM_BLKADDR(sbi,
 							curseg->segno);
 					ret = dev_write_block(curseg->sum_blk,
-							ssa_blk);
+							ssa_blk,
+							WRITE_LIFE_NONE);
 					ASSERT(ret >= 0);
 				}
 				if (c.roll_forward)
diff --git a/fsck/fsck.h b/fsck/fsck.h
index a8f187e..b581d3e 100644
--- a/fsck/fsck.h
+++ b/fsck/fsck.h
@@ -70,7 +70,8 @@ struct child_info {
 	u32 links;
 	u32 files;
 	u32 pgofs;
-	u8 dots;
+	u8 dot;
+	u8 dotdot;
 	u8 dir_level;
 	u32 p_ino;		/* parent ino */
 	char p_name[F2FS_NAME_LEN + 1]; /* parent name */
@@ -179,9 +180,9 @@ extern int fsck_chk_idnode_blk(struct f2fs_sb_info *, struct f2fs_inode *,
 extern int fsck_chk_didnode_blk(struct f2fs_sb_info *, struct f2fs_inode *,
 		enum FILE_TYPE, struct f2fs_node *, u32 *,
 		struct f2fs_compr_blk_cnt *, struct child_info *);
-extern int fsck_chk_data_blk(struct f2fs_sb_info *, int,
+extern int fsck_chk_data_blk(struct f2fs_sb_info *, struct f2fs_inode *,
 		u32, struct child_info *, int, enum FILE_TYPE, u32, u16, u8,
-		int, struct f2fs_node *);
+		struct f2fs_node *);
 extern int fsck_chk_dentry_blk(struct f2fs_sb_info *, int,
 		u32, struct child_info *, int, int, struct f2fs_node *);
 int fsck_chk_inline_dentries(struct f2fs_sb_info *, struct f2fs_node *,
diff --git a/fsck/inject.c b/fsck/inject.c
index 9dc085f..bd6ab84 100644
--- a/fsck/inject.c
+++ b/fsck/inject.c
@@ -10,6 +10,7 @@
  */
 
 #include <getopt.h>
+#include "node.h"
 #include "inject.h"
 
 static void print_raw_nat_entry_info(struct f2fs_nat_entry *ne)
@@ -74,6 +75,17 @@ static void print_node_footer_info(struct node_footer *footer)
 	DISP_u32(footer, next_blkaddr);
 }
 
+static void print_raw_dentry_info(struct f2fs_dir_entry *dentry)
+{
+	if (!c.dbg_lv)
+		return;
+
+	DISP_u32(dentry, hash_code);
+	DISP_u32(dentry, ino);
+	DISP_u16(dentry, name_len);
+	DISP_u8(dentry, file_type);
+}
+
 void inject_usage(void)
 {
 	MSG(0, "\nUsage: inject.f2fs [options] device\n");
@@ -92,6 +104,7 @@ void inject_usage(void)
 	MSG(0, "  --sit <0|1|2> --mb <name> --blk <blk> [--idx <index>] --val <value> inject sit entry\n");
 	MSG(0, "  --ssa --mb <name> --blk <blk> [--idx <index>] --val <value> inject summary entry\n");
 	MSG(0, "  --node --mb <name> --nid <nid> [--idx <index>] --val <value> inject node\n");
+	MSG(0, "  --dent --mb <name> --nid <ino> [--idx <index>] --val <value> inject ino's dentry\n");
 	MSG(0, "  --dry-run do not really inject\n");
 
 	exit(1);
@@ -186,6 +199,16 @@ static void inject_node_usage(void)
 	MSG(0, "  addr: inject {in}direct node nid/addr array selected by --idx <index>\n");
 }
 
+static void inject_dent_usage(void)
+{
+	MSG(0, "inject.f2fs --dent --mb <name> --nid <nid> [--idx <index>] --val <value> inject dentry\n");
+	MSG(0, "[mb]:\n");
+	MSG(0, "  d_bitmap: inject dentry block d_bitmap of nid\n");
+	MSG(0, "  d_hash: inject dentry hash\n");
+	MSG(0, "  d_ino: inject dentry ino\n");
+	MSG(0, "  d_ftype: inject dentry ftype\n");
+}
+
 int inject_parse_options(int argc, char *argv[], struct inject_option *opt)
 {
 	int o = 0;
@@ -206,6 +229,7 @@ int inject_parse_options(int argc, char *argv[], struct inject_option *opt)
 		{"blk", required_argument, 0, 11},
 		{"ssa", no_argument, 0, 12},
 		{"node", no_argument, 0, 13},
+		{"dent", no_argument, 0, 14},
 		{0, 0, 0, 0}
 	};
 
@@ -298,6 +322,10 @@ int inject_parse_options(int argc, char *argv[], struct inject_option *opt)
 			opt->node = true;
 			MSG(0, "Info: inject node\n");
 			break;
+		case 14:
+			opt->dent = true;
+			MSG(0, "Info: inject dentry\n");
+			break;
 		case 'd':
 			if (optarg[0] == '-' || !is_digits(optarg))
 				return EWRONG_OPT;
@@ -327,6 +355,9 @@ int inject_parse_options(int argc, char *argv[], struct inject_option *opt)
 			} else if (opt->node) {
 				inject_node_usage();
 				exit(0);
+			} else if (opt->dent) {
+				inject_dent_usage();
+				exit(0);
 			}
 			return EUNKNOWN_OPT;
 		}
@@ -565,7 +596,7 @@ static int inject_nat(struct f2fs_sb_info *sbi, struct inject_option *opt)
 	}
 	print_raw_nat_entry_info(ne);
 
-	ret = dev_write_block(nat_blk, blk_addr);
+	ret = dev_write_block(nat_blk, blk_addr, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 	/* restore NAT version bitmap */
 	if (is_set)
@@ -724,7 +755,7 @@ static int inject_ssa(struct f2fs_sb_info *sbi, struct inject_option *opt)
 	print_sum_footer_info(footer);
 
 	ssa_blkaddr = GET_SUM_BLKADDR(sbi, segno);
-	ret = dev_write_block(sum_blk, ssa_blkaddr);
+	ret = dev_write_block(sum_blk, ssa_blkaddr, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 
 out:
@@ -902,6 +933,157 @@ out:
 	return ret;
 }
 
+static int find_dir_entry(struct f2fs_dentry_ptr *d, nid_t ino)
+{
+	struct f2fs_dir_entry *de;
+	int slot = 0;
+
+	while (slot < d->max) {
+		if (!test_bit_le(slot, d->bitmap)) {
+			slot++;
+			continue;
+		}
+
+		de = &d->dentry[slot];
+		if (le32_to_cpu(de->ino) == ino && de->hash_code != 0)
+			return slot;
+		if (de->name_len == 0) {
+			slot++;
+			continue;
+		}
+		slot += GET_DENTRY_SLOTS(le16_to_cpu(de->name_len));
+	}
+
+	return -ENOENT;
+}
+
+static int inject_dentry(struct f2fs_sb_info *sbi, struct inject_option *opt)
+{
+	struct node_info ni;
+	struct f2fs_node *node_blk = NULL;
+	struct f2fs_inode *inode;
+	struct f2fs_dentry_ptr d;
+	void *inline_dentry;
+	struct f2fs_dentry_block *dent_blk = NULL;
+	block_t addr = 0;
+	void *buf = NULL;
+	struct f2fs_dir_entry *dent = NULL;
+	struct dnode_of_data dn;
+	nid_t pino;
+	int slot = -ENOENT, ret;
+
+	node_blk = malloc(F2FS_BLKSIZE);
+	ASSERT(node_blk != NULL);
+
+	/* get child inode */
+	get_node_info(sbi, opt->nid, &ni);
+	ret = dev_read_block(node_blk, ni.blk_addr);
+	ASSERT(ret >= 0);
+	pino = le32_to_cpu(node_blk->i.i_pino);
+
+	/* get parent inode */
+	get_node_info(sbi, pino, &ni);
+	ret = dev_read_block(node_blk, ni.blk_addr);
+	ASSERT(ret >= 0);
+	inode = &node_blk->i;
+
+	/* find child dentry */
+	if (inode->i_inline & F2FS_INLINE_DENTRY) {
+		inline_dentry = inline_data_addr(node_blk);
+		make_dentry_ptr(&d, node_blk, inline_dentry, 2);
+		addr = ni.blk_addr;
+		buf = node_blk;
+
+		slot = find_dir_entry(&d, opt->nid);
+		if (slot >= 0)
+			dent = &d.dentry[slot];
+	} else {
+		unsigned int level, dirlevel, nbucket;
+		unsigned long i, end;
+
+		level = le32_to_cpu(inode->i_current_depth);
+		dirlevel = le32_to_cpu(inode->i_dir_level);
+		nbucket = dir_buckets(level, dirlevel);
+		end = dir_block_index(level, dirlevel, nbucket) +
+						bucket_blocks(level);
+
+		dent_blk = malloc(F2FS_BLKSIZE);
+		ASSERT(dent_blk != NULL);
+
+		for (i = 0; i < end; i++) {
+			memset(&dn, 0, sizeof(dn));
+			set_new_dnode(&dn, node_blk, NULL, pino);
+			ret = get_dnode_of_data(sbi, &dn, i, LOOKUP_NODE);
+			if (ret < 0)
+				break;
+			addr = dn.data_blkaddr;
+			if (dn.inode_blk != dn.node_blk)
+				free(dn.node_blk);
+			if (addr == NULL_ADDR || addr == NEW_ADDR)
+				continue;
+			if (!f2fs_is_valid_blkaddr(sbi, addr, DATA_GENERIC)) {
+				MSG(0, "invalid blkaddr 0x%x at offset %lu\n",
+				    addr, i);
+				continue;
+			}
+			ret = dev_read_block(dent_blk, addr);
+			ASSERT(ret >= 0);
+
+			make_dentry_ptr(&d, node_blk, dent_blk, 1);
+			slot = find_dir_entry(&d, opt->nid);
+			if (slot >= 0) {
+				dent = &d.dentry[slot];
+				buf = dent_blk;
+				break;
+			}
+		}
+	}
+
+	if (slot < 0) {
+		ERR_MSG("dentry of ino %u not found\n", opt->nid);
+		ret = -ENOENT;
+		goto out;
+	}
+
+	if (!strcmp(opt->mb, "d_bitmap")) {
+		MSG(0, "Info: inject dentry bitmap of nid %u: 1 -> 0\n",
+		    opt->nid);
+		test_and_clear_bit_le(slot, d.bitmap);
+	} else if (!strcmp(opt->mb, "d_hash")) {
+		MSG(0, "Info: inject dentry d_hash of nid %u: "
+		    "0x%x -> 0x%x\n", opt->nid, le32_to_cpu(dent->hash_code),
+		    (u32)opt->val);
+		dent->hash_code = cpu_to_le32((u32)opt->val);
+	} else if (!strcmp(opt->mb, "d_ino")) {
+		MSG(0, "Info: inject dentry d_ino of nid %u: "
+		    "%u -> %u\n", opt->nid, le32_to_cpu(dent->ino),
+		    (nid_t)opt->val);
+		dent->ino = cpu_to_le32((nid_t)opt->val);
+	} else if (!strcmp(opt->mb, "d_ftype")) {
+		MSG(0, "Info: inject dentry d_type of nid %u: "
+		    "%d -> %d\n", opt->nid, dent->file_type,
+		    (u8)opt->val);
+		dent->file_type = (u8)opt->val;
+	} else {
+		ERR_MSG("unknown or unsupported member \"%s\"\n", opt->mb);
+		ret = -EINVAL;
+		goto out;
+	}
+
+	print_raw_dentry_info(dent);
+
+	if (inode->i_inline & F2FS_INLINE_DENTRY)
+		ret = update_inode(sbi, buf, &addr);
+	else
+		ret = update_block(sbi, buf, &addr, NULL);
+	ASSERT(ret >= 0);
+
+out:
+	free(node_blk);
+	free(dent_blk);
+	return ret;
+}
+
 int do_inject(struct f2fs_sb_info *sbi)
 {
 	struct inject_option *opt = (struct inject_option *)c.private;
@@ -919,6 +1101,8 @@ int do_inject(struct f2fs_sb_info *sbi)
 		ret = inject_ssa(sbi, opt);
 	else if (opt->node)
 		ret = inject_node(sbi, opt);
+	else if (opt->dent)
+		ret = inject_dentry(sbi, opt);
 
 	return ret;
 }
diff --git a/fsck/inject.h b/fsck/inject.h
index 9b14c31..43c21b5 100644
--- a/fsck/inject.h
+++ b/fsck/inject.h
@@ -32,6 +32,7 @@ struct inject_option {
 	int sit;		/* which sit pack */
 	bool ssa;
 	bool node;
+	bool dent;
 };
 
 void inject_usage(void);
diff --git a/fsck/main.c b/fsck/main.c
index 8881936..25d50e2 100644
--- a/fsck/main.c
+++ b/fsck/main.c
@@ -77,6 +77,7 @@ void fsck_usage()
 	MSG(0, "  -d debug level [default:0]\n");
 	MSG(0, "  -f check/fix entire partition\n");
 	MSG(0, "  -g add default options\n");
+	MSG(0, "  -H support write hint\n");
 	MSG(0, "  -l show superblock/checkpoint\n");
 	MSG(0, "  -M show a file map\n");
 	MSG(0, "  -O feature1[feature2,feature3,...] e.g. \"encrypt\"\n");
@@ -108,6 +109,7 @@ void dump_usage()
 	MSG(0, "  -b blk_addr (in 4KB)\n");
 	MSG(0, "  -r dump out from the root inode\n");
 	MSG(0, "  -f do not prompt before dumping\n");
+	MSG(0, "  -H support write hint\n");
 	MSG(0, "  -y alias for -f\n");
 	MSG(0, "  -o dump inodes to the given path\n");
 	MSG(0, "  -P preserve mode/owner/group for dumped inode\n");
@@ -122,6 +124,7 @@ void defrag_usage()
 	MSG(0, "\nUsage: defrag.f2fs [options] device\n");
 	MSG(0, "[options]:\n");
 	MSG(0, "  -d debug level [default:0]\n");
+	MSG(0, "  -H support write hint\n");
 	MSG(0, "  -s start block address [default: main_blkaddr]\n");
 	MSG(0, "  -S sparse_mode\n");
 	MSG(0, "  -l length [default:512 (2MB)]\n");
@@ -136,6 +139,7 @@ void resize_usage()
 	MSG(0, "\nUsage: resize.f2fs [options] device\n");
 	MSG(0, "[options]:\n");
 	MSG(0, "  -d debug level [default:0]\n");
+	MSG(0, "  -H support write hint\n");
 	MSG(0, "  -i extended node bitmap, node ratio is 20%% by default\n");
 	MSG(0, "  -o overprovision percentage [default:auto]\n");
 	MSG(0, "  -s safe resize (Does not resize metadata)\n");
@@ -246,7 +250,7 @@ void f2fs_parse_options(int argc, char *argv[])
 	}
 
 	if (!strcmp("fsck.f2fs", prog)) {
-		const char *option_string = ":aC:c:m:Md:fg:lO:p:q:StyV";
+		const char *option_string = ":aC:c:m:Md:fg:HlO:p:q:StyV";
 		int opt = 0, val;
 		char *token;
 		struct option long_opt[] = {
@@ -295,6 +299,10 @@ void f2fs_parse_options(int argc, char *argv[])
 					MSG(0, "Info: Set conf for android\n");
 				}
 				break;
+			case 'H':
+				c.need_whint = true;
+				c.whint = WRITE_LIFE_NOT_SET;
+				break;
 			case 'l':
 				c.layout = 1;
 				break;
@@ -517,7 +525,7 @@ void f2fs_parse_options(int argc, char *argv[])
 #endif
 	} else if (!strcmp("defrag.f2fs", prog)) {
 #ifdef WITH_DEFRAG
-		const char *option_string = "d:s:Sl:t:iV";
+		const char *option_string = "d:Hs:Sl:t:iV";
 
 		c.func = DEFRAG;
 		while ((option = getopt(argc, argv, option_string)) != EOF) {
@@ -533,6 +541,10 @@ void f2fs_parse_options(int argc, char *argv[])
 				MSG(0, "Info: Debug level = %d\n",
 							c.dbg_lv);
 				break;
+			case 'H':
+				c.need_whint = true;
+				c.whint = WRITE_LIFE_NOT_SET;
+				break;
 			case 's':
 				if (strncmp(optarg, "0x", 2))
 					ret = sscanf(optarg, "%"PRIu64"",
@@ -577,7 +589,7 @@ void f2fs_parse_options(int argc, char *argv[])
 #endif
 	} else if (!strcmp("resize.f2fs", prog)) {
 #ifdef WITH_RESIZE
-		const char *option_string = "d:fst:io:V";
+		const char *option_string = "d:fHst:io:V";
 
 		c.func = RESIZE;
 		while ((option = getopt(argc, argv, option_string)) != EOF) {
@@ -597,6 +609,10 @@ void f2fs_parse_options(int argc, char *argv[])
 				c.force = 1;
 				MSG(0, "Info: Force to resize\n");
 				break;
+			case 'H':
+				c.need_whint = true;
+				c.whint = WRITE_LIFE_NOT_SET;
+				break;
 			case 's':
 				c.safe_resize = 1;
 				break;
@@ -850,6 +866,12 @@ void f2fs_parse_options(int argc, char *argv[])
 #endif /* WITH_INJECT */
 	}
 
+#if defined(__MINGW32__)
+	if (c.need_whint) {
+		MSG(0, "-H not supported for Windows\n");
+		err = EWRONG_OPT;
+	}
+#endif
 	if (err == NOERROR) {
 		add_default_options();
 
@@ -892,6 +914,7 @@ static int do_fsck(struct f2fs_sb_info *sbi)
 	u32 flag = le32_to_cpu(ckpt->ckpt_flags);
 	u32 blk_cnt;
 	struct f2fs_compr_blk_cnt cbc;
+	struct child_info child = { 0 };
 	errcode_t ret;
 
 	fsck_init(sbi);
@@ -957,8 +980,9 @@ static int do_fsck(struct f2fs_sb_info *sbi)
 	if (fsck_sanity_check_nat(sbi, sbi->root_ino_num))
 		fsck_chk_root_inode(sbi);
 
+	child.p_ino = sbi->root_ino_num;
 	fsck_chk_node_blk(sbi, NULL, sbi->root_ino_num,
-			F2FS_FT_DIR, TYPE_INODE, &blk_cnt, &cbc, NULL);
+			F2FS_FT_DIR, TYPE_INODE, &blk_cnt, &cbc, &child);
 	fsck_chk_quota_files(sbi);
 
 	ret = fsck_verify(sbi);
@@ -1015,6 +1039,11 @@ static int do_defrag(struct f2fs_sb_info *sbi)
 		return -1;
 	}
 
+	if (get_sb(feature) & F2FS_FEATURE_DEVICE_ALIAS) {
+		MSG(0, "Not support on image with device aliasing feature.\n");
+		return -1;
+	}
+
 	if (c.defrag_start > get_sb(block_count))
 		goto out_range;
 	if (c.defrag_start < SM_I(sbi)->main_blkaddr)
diff --git a/fsck/mount.c b/fsck/mount.c
index dab0611..a189ba7 100644
--- a/fsck/mount.c
+++ b/fsck/mount.c
@@ -889,7 +889,7 @@ void update_superblock(struct f2fs_super_block *sb, int sb_mask)
 	memcpy(buf + F2FS_SUPER_OFFSET, sb, sizeof(*sb));
 	for (addr = SB0_ADDR; addr < SB_MAX_ADDR; addr++) {
 		if (SB_MASK(addr) & sb_mask) {
-			ret = dev_write_block(buf, addr);
+			ret = dev_write_block(buf, addr, WRITE_LIFE_NONE);
 			ASSERT(ret >= 0);
 		}
 	}
@@ -1783,7 +1783,8 @@ void write_nat_bits(struct f2fs_sb_info *sbi,
 	DBG(1, "\tWriting NAT bits pages, at offset 0x%08x\n", blkaddr);
 
 	for (i = 0; i < nat_bits_blocks; i++) {
-		if (dev_write_block(nat_bits + i * F2FS_BLKSIZE, blkaddr + i))
+		if (dev_write_block(nat_bits + i * F2FS_BLKSIZE, blkaddr + i,
+				    WRITE_LIFE_NONE))
 			ASSERT_MSG("\tError: write NAT bits to disk!!!\n");
 	}
 	MSG(0, "Info: Write valid nat_bits in checkpoint\n");
@@ -2155,7 +2156,8 @@ void update_sum_entry(struct f2fs_sb_info *sbi, block_t blk_addr,
 							SUM_TYPE_DATA;
 
 	/* write SSA all the time */
-	ret = dev_write_block(sum_blk, GET_SUM_BLKADDR(sbi, segno));
+	ret = dev_write_block(sum_blk, GET_SUM_BLKADDR(sbi, segno),
+			      WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 
 	if (type == SEG_TYPE_NODE || type == SEG_TYPE_DATA ||
@@ -2262,7 +2264,7 @@ void rewrite_current_sit_page(struct f2fs_sb_info *sbi,
 {
 	block_t blk_addr = current_sit_addr(sbi, segno);
 
-	ASSERT(dev_write_block(sit_blk, blk_addr) >= 0);
+	ASSERT(dev_write_block(sit_blk, blk_addr, WRITE_LIFE_NONE) >= 0);
 }
 
 void check_block_count(struct f2fs_sb_info *sbi,
@@ -2552,7 +2554,7 @@ void update_nat_blkaddr(struct f2fs_sb_info *sbi, nid_t ino,
 		entry->ino = cpu_to_le32(ino);
 	entry->block_addr = cpu_to_le32(newaddr);
 
-	ret = dev_write_block(nat_block, block_addr);
+	ret = dev_write_block(nat_block, block_addr, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 update_cache:
 	if (c.func == FSCK)
@@ -2848,7 +2850,7 @@ next:
 	memcpy(&nat_block->entries[entry_off], &nat_in_journal(journal, i),
 					sizeof(struct f2fs_nat_entry));
 
-	ret = dev_write_block(nat_block, block_addr);
+	ret = dev_write_block(nat_block, block_addr, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 	i++;
 	goto next;
@@ -3028,7 +3030,8 @@ int find_next_free_block(struct f2fs_sb_info *sbi, u64 *to, int left,
 			}
 
 			ssa_blk = GET_SUM_BLKADDR(sbi, curseg->segno);
-			ret = dev_write_block(curseg->sum_blk, ssa_blk);
+			ret = dev_write_block(curseg->sum_blk, ssa_blk,
+					      WRITE_LIFE_NONE);
 			ASSERT(ret >= 0);
 
 			curseg->segno = segno;
@@ -3133,7 +3136,7 @@ void move_one_curseg_info(struct f2fs_sb_info *sbi, u64 from, int left,
 
 	/* update original SSA too */
 	ssa_blk = GET_SUM_BLKADDR(sbi, curseg->segno);
-	ret = dev_write_block(curseg->sum_blk, ssa_blk);
+	ret = dev_write_block(curseg->sum_blk, ssa_blk, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 bypass_ssa:
 	to = from;
@@ -3286,7 +3289,7 @@ void nullify_nat_entry(struct f2fs_sb_info *sbi, u32 nid)
 		FIX_MSG("Remove nid [0x%x] in NAT", nid);
 	}
 
-	ret = dev_write_block(nat_block, block_addr);
+	ret = dev_write_block(nat_block, block_addr, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 	free(nat_block);
 }
@@ -3318,7 +3321,7 @@ void duplicate_checkpoint(struct f2fs_sb_info *sbi)
 	ASSERT(ret >= 0);
 
 	ret = dev_write(buf, dst << F2FS_BLKSIZE_BITS,
-				seg_size << F2FS_BLKSIZE_BITS);
+				seg_size << F2FS_BLKSIZE_BITS, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 
 	free(buf);
@@ -3383,7 +3386,7 @@ void write_checkpoint(struct f2fs_sb_info *sbi)
 		cp_blk_no += 1 << get_sb(log_blocks_per_seg);
 
 	/* write the first cp */
-	ret = dev_write_block(cp, cp_blk_no++);
+	ret = dev_write_block(cp, cp_blk_no++, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 
 	/* skip payload */
@@ -3399,13 +3402,15 @@ void write_checkpoint(struct f2fs_sb_info *sbi)
 		if (!(flags & CP_UMOUNT_FLAG) && IS_NODESEG(i))
 			continue;
 
-		ret = dev_write_block(curseg->sum_blk, cp_blk_no++);
+		ret = dev_write_block(curseg->sum_blk, cp_blk_no++,
+				      WRITE_LIFE_NONE);
 		ASSERT(ret >= 0);
 
 		if (!(get_sb(feature) & F2FS_FEATURE_RO)) {
 			/* update original SSA too */
 			ssa_blk = GET_SUM_BLKADDR(sbi, curseg->segno);
-			ret = dev_write_block(curseg->sum_blk, ssa_blk);
+			ret = dev_write_block(curseg->sum_blk, ssa_blk,
+					      WRITE_LIFE_NONE);
 			ASSERT(ret >= 0);
 		}
 	}
@@ -3419,7 +3424,7 @@ void write_checkpoint(struct f2fs_sb_info *sbi)
 	ASSERT(ret >= 0);
 
 	/* write the last cp */
-	ret = dev_write_block(cp, cp_blk_no++);
+	ret = dev_write_block(cp, cp_blk_no++, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 
 	ret = f2fs_fsync_device();
@@ -3455,12 +3460,12 @@ void write_raw_cp_blocks(struct f2fs_sb_info *sbi,
 		cp_blkaddr += 1 << get_sb(log_blocks_per_seg);
 
 	/* write the first cp block in this CP pack */
-	ret = dev_write_block(cp, cp_blkaddr);
+	ret = dev_write_block(cp, cp_blkaddr, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 
 	/* write the second cp block in this CP pack */
 	cp_blkaddr += get_cp(cp_pack_total_block_count) - 1;
-	ret = dev_write_block(cp, cp_blkaddr);
+	ret = dev_write_block(cp, cp_blkaddr, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 }
 
@@ -3695,6 +3700,7 @@ static int loop_node_chain_fix(block_t blkaddr_fast,
 		block_t blkaddr, struct f2fs_node *node_blk)
 {
 	block_t blkaddr_entry, blkaddr_tmp;
+	enum rw_hint whint;
 	int err;
 
 	/* find the entry point of the looped node chain */
@@ -3722,10 +3728,11 @@ static int loop_node_chain_fix(block_t blkaddr_fast,
 
 	/* fix the blkaddr of last node with NULL_ADDR. */
 	F2FS_NODE_FOOTER(node_blk)->next_blkaddr = NULL_ADDR;
+	whint = f2fs_io_type_to_rw_hint(CURSEG_WARM_NODE);
 	if (IS_INODE(node_blk))
-		err = write_inode(node_blk, blkaddr_tmp);
+		err = write_inode(node_blk, blkaddr_tmp, whint);
 	else
-		err = dev_write_block(node_blk, blkaddr_tmp);
+		err = dev_write_block(node_blk, blkaddr_tmp, whint);
 	if (!err)
 		FIX_MSG("Fix looped node chain on blkaddr %u\n",
 				blkaddr_tmp);
@@ -4215,7 +4222,7 @@ int f2fs_sparse_initialize_meta(struct f2fs_sb_info *sbi)
 	DBG(1, "\tSparse: filling sit area at block offset: 0x%08"PRIx64" len: %u\n",
 							sit_seg_addr, sit_size);
 	ret = dev_fill(NULL, sit_seg_addr * F2FS_BLKSIZE,
-					sit_size * F2FS_BLKSIZE);
+			sit_size * F2FS_BLKSIZE, WRITE_LIFE_NONE);
 	if (ret) {
 		MSG(1, "\tError: While zeroing out the sit area "
 				"on disk!!!\n");
@@ -4229,7 +4236,7 @@ int f2fs_sparse_initialize_meta(struct f2fs_sb_info *sbi)
 	DBG(1, "\tSparse: filling nat area at block offset 0x%08"PRIx64" len: %u\n",
 							nat_seg_addr, nat_size);
 	ret = dev_fill(NULL, nat_seg_addr * F2FS_BLKSIZE,
-					nat_size * F2FS_BLKSIZE);
+			nat_size * F2FS_BLKSIZE, WRITE_LIFE_NONE);
 	if (ret) {
 		MSG(1, "\tError: While zeroing out the nat area "
 				"on disk!!!\n");
@@ -4241,7 +4248,7 @@ int f2fs_sparse_initialize_meta(struct f2fs_sb_info *sbi)
 	DBG(1, "\tSparse: filling bitmap area at block offset 0x%08"PRIx64" len: %u\n",
 					payload_addr, get_sb(cp_payload));
 	ret = dev_fill(NULL, payload_addr * F2FS_BLKSIZE,
-					get_sb(cp_payload) * F2FS_BLKSIZE);
+			get_sb(cp_payload) * F2FS_BLKSIZE, WRITE_LIFE_NONE);
 	if (ret) {
 		MSG(1, "\tError: While zeroing out the nat/sit bitmap area "
 				"on disk!!!\n");
@@ -4253,7 +4260,7 @@ int f2fs_sparse_initialize_meta(struct f2fs_sb_info *sbi)
 	DBG(1, "\tSparse: filling bitmap area at block offset 0x%08"PRIx64" len: %u\n",
 					payload_addr, get_sb(cp_payload));
 	ret = dev_fill(NULL, payload_addr * F2FS_BLKSIZE,
-					get_sb(cp_payload) * F2FS_BLKSIZE);
+			get_sb(cp_payload) * F2FS_BLKSIZE, WRITE_LIFE_NONE);
 	if (ret) {
 		MSG(1, "\tError: While zeroing out the nat/sit bitmap area "
 				"on disk!!!\n");
diff --git a/fsck/node.c b/fsck/node.c
index 632151a..8d4479c 100644
--- a/fsck/node.c
+++ b/fsck/node.c
@@ -78,7 +78,7 @@ int f2fs_rebuild_qf_inode(struct f2fs_sb_info *sbi, int qtype)
 		goto err_out;
 	}
 
-	ret = write_inode(raw_node, blkaddr);
+	ret = write_inode(raw_node, blkaddr, f2fs_io_type_to_rw_hint(CURSEG_HOT_NODE));
 	if (ret < 0) {
 		MSG(1, "\tError: While rebuilding the quota inode to disk!\n");
 		goto err_out;
@@ -282,8 +282,13 @@ int get_dnode_of_data(struct f2fs_sb_info *sbi, struct dnode_of_data *dn,
 			/* Parent node has changed */
 			if (!parent_alloced)
 				ret = update_block(sbi, parent, &nblk[i - 1], NULL);
-			else
-				ret = dev_write_block(parent, nblk[i - 1]);
+			else {
+				struct seg_entry *se;
+
+				se = get_seg_entry(sbi, GET_SEGNO(sbi, nblk[i - 1]));
+				ret = dev_write_block(parent, nblk[i - 1],
+						f2fs_io_type_to_rw_hint(se->type));
+			}
 			ASSERT(ret >= 0);
 
 			/* Function new_node_blk get a new f2fs_node blk and update*/
diff --git a/fsck/resize.c b/fsck/resize.c
index 049ddd3..9b3b071 100644
--- a/fsck/resize.c
+++ b/fsck/resize.c
@@ -189,7 +189,8 @@ static void migrate_main(struct f2fs_sb_info *sbi, unsigned int offset)
 			ASSERT(ret >= 0);
 
 			to = from + offset;
-			ret = dev_write_block(raw, to);
+			ret = dev_write_block(raw, to,
+					      f2fs_io_type_to_rw_hint(se->type));
 			ASSERT(ret >= 0);
 
 			get_sum_entry(sbi, from, &sum);
@@ -218,7 +219,8 @@ static void move_ssa(struct f2fs_sb_info *sbi, unsigned int segno,
 	if (type < SEG_TYPE_MAX) {
 		int ret;
 
-		ret = dev_write_block(sum_blk, new_sum_blk_addr);
+		ret = dev_write_block(sum_blk, new_sum_blk_addr,
+				      WRITE_LIFE_NONE);
 		ASSERT(ret >= 0);
 		DBG(1, "Write summary block: (%d) segno=%x/%x --> (%d) %x\n",
 				type, segno, GET_SUM_BLKADDR(sbi, segno),
@@ -252,7 +254,8 @@ static void migrate_ssa(struct f2fs_sb_info *sbi,
 			if (blkaddr < expand_sum_blkaddr) {
 				move_ssa(sbi, offset++, blkaddr++);
 			} else {
-				ret = dev_write_block(zero_block, blkaddr++);
+				ret = dev_write_block(zero_block, blkaddr++,
+						      WRITE_LIFE_NONE);
 				ASSERT(ret >=0);
 			}
 		}
@@ -261,7 +264,8 @@ static void migrate_ssa(struct f2fs_sb_info *sbi,
 		offset = MAIN_SEGS(sbi) - 1;
 		while (blkaddr >= new_sum_blkaddr) {
 			if (blkaddr >= expand_sum_blkaddr) {
-				ret = dev_write_block(zero_block, blkaddr--);
+				ret = dev_write_block(zero_block, blkaddr--,
+						      WRITE_LIFE_NONE);
 				ASSERT(ret >=0);
 			} else {
 				move_ssa(sbi, offset--, blkaddr--);
@@ -360,7 +364,7 @@ static void migrate_nat(struct f2fs_sb_info *sbi,
 				(block_off & ((1 << sbi->log_blocks_per_seg) - 1)));
 
 		/* new bitmap should be zeros */
-		ret = dev_write_block(nat_block, block_addr);
+		ret = dev_write_block(nat_block, block_addr, WRITE_LIFE_NONE);
 		ASSERT(ret >= 0);
 	}
 	/* zero out newly assigned nids */
@@ -381,7 +385,7 @@ static void migrate_nat(struct f2fs_sb_info *sbi,
 		block_addr = (pgoff_t)(new_nat_blkaddr +
 				(seg_off << sbi->log_blocks_per_seg << 1) +
 				(block_off & ((1 << sbi->log_blocks_per_seg) - 1)));
-		ret = dev_write_block(nat_block, block_addr);
+		ret = dev_write_block(nat_block, block_addr, WRITE_LIFE_NONE);
 		ASSERT(ret >= 0);
 		DBG(3, "Write NAT: %lx\n", block_addr);
 	}
@@ -407,7 +411,8 @@ static void migrate_sit(struct f2fs_sb_info *sbi,
 
 	/* initialize with zeros */
 	for (index = 0; index < sit_blks; index++) {
-		ret = dev_write_block(sit_blk, get_newsb(sit_blkaddr) + index);
+		ret = dev_write_block(sit_blk, get_newsb(sit_blkaddr) + index,
+				      WRITE_LIFE_NONE);
 		ASSERT(ret >= 0);
 		DBG(3, "Write zero sit: %x\n", get_newsb(sit_blkaddr) + index);
 	}
@@ -425,7 +430,8 @@ static void migrate_sit(struct f2fs_sb_info *sbi,
 
 		if (ofs != pre_ofs) {
 			blk_addr = get_newsb(sit_blkaddr) + pre_ofs;
-			ret = dev_write_block(sit_blk, blk_addr);
+			ret = dev_write_block(sit_blk, blk_addr,
+					      WRITE_LIFE_NONE);
 			ASSERT(ret >= 0);
 			DBG(1, "Write valid sit: %x\n", blk_addr);
 
@@ -439,7 +445,7 @@ static void migrate_sit(struct f2fs_sb_info *sbi,
 							se->valid_blocks);
 	}
 	blk_addr = get_newsb(sit_blkaddr) + ofs;
-	ret = dev_write_block(sit_blk, blk_addr);
+	ret = dev_write_block(sit_blk, blk_addr, WRITE_LIFE_NONE);
 	DBG(1, "Write valid sit: %x\n", blk_addr);
 	ASSERT(ret >= 0);
 
@@ -558,12 +564,12 @@ static void rebuild_checkpoint(struct f2fs_sb_info *sbi,
 		new_cp_blk_no += 1 << get_sb(log_blocks_per_seg);
 
 	/* write first cp */
-	ret = dev_write_block(new_cp, new_cp_blk_no++);
+	ret = dev_write_block(new_cp, new_cp_blk_no++, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 
 	memset(buf, 0, F2FS_BLKSIZE);
 	for (i = 0; i < get_newsb(cp_payload); i++) {
-		ret = dev_write_block(buf, new_cp_blk_no++);
+		ret = dev_write_block(buf, new_cp_blk_no++, WRITE_LIFE_NONE);
 		ASSERT(ret >= 0);
 	}
 
@@ -573,7 +579,7 @@ static void rebuild_checkpoint(struct f2fs_sb_info *sbi,
 		ret = dev_read_block(buf, orphan_blk_no++);
 		ASSERT(ret >= 0);
 
-		ret = dev_write_block(buf, new_cp_blk_no++);
+		ret = dev_write_block(buf, new_cp_blk_no++, WRITE_LIFE_NONE);
 		ASSERT(ret >= 0);
 	}
 
@@ -581,12 +587,13 @@ static void rebuild_checkpoint(struct f2fs_sb_info *sbi,
 	for (i = 0; i < NO_CHECK_TYPE; i++) {
 		struct curseg_info *curseg = CURSEG_I(sbi, i);
 
-		ret = dev_write_block(curseg->sum_blk, new_cp_blk_no++);
+		ret = dev_write_block(curseg->sum_blk, new_cp_blk_no++,
+				      WRITE_LIFE_NONE);
 		ASSERT(ret >= 0);
 	}
 
 	/* write the last cp */
-	ret = dev_write_block(new_cp, new_cp_blk_no++);
+	ret = dev_write_block(new_cp, new_cp_blk_no++, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 
 	/* Write nat bits */
@@ -595,7 +602,7 @@ static void rebuild_checkpoint(struct f2fs_sb_info *sbi,
 
 	/* disable old checkpoint */
 	memset(buf, 0, F2FS_BLKSIZE);
-	ret = dev_write_block(buf, old_cp_blk_no);
+	ret = dev_write_block(buf, old_cp_blk_no, WRITE_LIFE_NONE);
 	ASSERT(ret >= 0);
 
 	free(buf);
diff --git a/fsck/segment.c b/fsck/segment.c
index 9bea105..96de22a 100644
--- a/fsck/segment.c
+++ b/fsck/segment.c
@@ -322,12 +322,16 @@ static u64 f2fs_write_ex(struct f2fs_sb_info *sbi, nid_t ino, u8 *buffer,
 		ASSERT(remained_blkentries > 0);
 
 		if (!has_data) {
+			struct seg_entry *se;
+
+			se = get_seg_entry(sbi, GET_SEGNO(sbi, dn.node_blkaddr));
 			dn.data_blkaddr = addr_type;
 			set_data_blkaddr(&dn);
 			idirty |= dn.idirty;
 			if (dn.ndirty) {
 				ret = dn.alloced ? dev_write_block(dn.node_blk,
-					dn.node_blkaddr) :
+					dn.node_blkaddr,
+					f2fs_io_type_to_rw_hint(se->type)) :
 					update_block(sbi, dn.node_blk,
 					&dn.node_blkaddr, NULL);
 				ASSERT(ret >= 0);
@@ -365,7 +369,8 @@ static u64 f2fs_write_ex(struct f2fs_sb_info *sbi, nid_t ino, u8 *buffer,
 
 		if (c.zoned_model == F2FS_ZONED_HM) {
 			if (datablk_alloced) {
-				ret = dev_write_block(wbuf, blkaddr);
+				ret = dev_write_block(wbuf, blkaddr,
+					f2fs_io_type_to_rw_hint(CURSEG_WARM_DATA));
 			} else {
 				ret = update_block(sbi, wbuf, &blkaddr,
 						dn.node_blk);
@@ -375,7 +380,8 @@ static u64 f2fs_write_ex(struct f2fs_sb_info *sbi, nid_t ino, u8 *buffer,
 					dn.ndirty = 1;
 			}
 		} else {
-			ret = dev_write_block(wbuf, blkaddr);
+			ret = dev_write_block(wbuf, blkaddr,
+					f2fs_io_type_to_rw_hint(CURSEG_WARM_DATA));
 		}
 		ASSERT(ret >= 0);
 
@@ -386,8 +392,11 @@ static u64 f2fs_write_ex(struct f2fs_sb_info *sbi, nid_t ino, u8 *buffer,
 
 		dn.ofs_in_node++;
 		if ((--remained_blkentries == 0 || count == 0) && (dn.ndirty)) {
+			struct seg_entry *se;
+			se = get_seg_entry(sbi, GET_SEGNO(sbi, dn.node_blkaddr));
 			ret = dn.alloced ?
-				dev_write_block(dn.node_blk, dn.node_blkaddr) :
+				dev_write_block(dn.node_blk, dn.node_blkaddr,
+						f2fs_io_type_to_rw_hint(se->type)) :
 				update_block(sbi, dn.node_blk, &dn.node_blkaddr, NULL);
 			ASSERT(ret >= 0);
 		}
@@ -764,7 +773,7 @@ int update_block(struct f2fs_sb_info *sbi, void *buf, u32 *blkaddr,
 	int ret, type;
 
 	if (c.zoned_model != F2FS_ZONED_HM)
-		return dev_write_block(buf, old_blkaddr);
+		return dev_write_block(buf, old_blkaddr, WRITE_LIFE_NONE);
 
 	/* update sit bitmap & valid_blocks && se->type for old block*/
 	se = get_seg_entry(sbi, GET_SEGNO(sbi, old_blkaddr));
@@ -784,7 +793,7 @@ int update_block(struct f2fs_sb_info *sbi, void *buf, u32 *blkaddr,
 		ASSERT(0);
 	}
 
-	ret = dev_write_block(buf, new_blkaddr);
+	ret = dev_write_block(buf, new_blkaddr, f2fs_io_type_to_rw_hint(type));
 	ASSERT(ret >= 0);
 
 	*blkaddr = new_blkaddr;
diff --git a/fsck/xattr.c b/fsck/xattr.c
index 241e339..6373c06 100644
--- a/fsck/xattr.c
+++ b/fsck/xattr.c
@@ -95,6 +95,7 @@ void write_all_xattrs(struct f2fs_sb_info *sbi,
 	u64 inline_size = inline_xattr_size(&inode->i);
 	int ret;
 	bool xattrblk_alloced = false;
+	struct seg_entry *se;
 
 	memcpy(inline_xattr_addr(&inode->i), txattr_addr, inline_size);
 
@@ -126,8 +127,9 @@ void write_all_xattrs(struct f2fs_sb_info *sbi,
 	xattr_addr = (void *)xattr_node;
 	memcpy(xattr_addr, txattr_addr + inline_size,
 			F2FS_BLKSIZE - sizeof(struct node_footer));
-
-	ret = xattrblk_alloced ? dev_write_block(xattr_node, blkaddr) :
+	se = get_seg_entry(sbi, GET_SEGNO(sbi, blkaddr));
+	ret = xattrblk_alloced ? dev_write_block(xattr_node, blkaddr,
+					f2fs_io_type_to_rw_hint(se->type)) :
 		update_block(sbi, xattr_node, &blkaddr, NULL);
 
 free_xattr_node:
diff --git a/include/android_config.h b/include/android_config.h
index 9c8b163..f5cd4de 100644
--- a/include/android_config.h
+++ b/include/android_config.h
@@ -1,9 +1,11 @@
 #if defined(__linux__)
+#define HAVE_ARCH_STRUCT_FLOCK 1
 #define HAVE_BLK_ZONE_REP_V2 1
 #define HAVE_BYTESWAP_H 1
 #define HAVE_FCNTL_H 1
 #define HAVE_FALLOC_H 1
 #define HAVE_FSYNC 1
+#define HAVE_LINUX_FCNTL_H 1
 #define HAVE_LINUX_HDREG_H 1
 #define HAVE_LINUX_LIMITS_H 1
 #define HAVE_LINUX_LOOP_H 1
diff --git a/include/f2fs_fs.h b/include/f2fs_fs.h
index 15a1c82..0cb9228 100644
--- a/include/f2fs_fs.h
+++ b/include/f2fs_fs.h
@@ -28,6 +28,7 @@
 #include <stddef.h>
 #include <string.h>
 #include <time.h>
+#include <stdbool.h>
 
 #ifdef HAVE_CONFIG_H
 #include <config.h>
@@ -60,6 +61,19 @@
 #include <linux/blkzoned.h>
 #endif
 
+#ifdef HAVE_LINUX_RW_HINT_H
+#include <linux/rw_hint.h>
+#else
+enum rw_hint {
+	WRITE_LIFE_NOT_SET	= 0,
+	WRITE_LIFE_NONE,
+	WRITE_LIFE_SHORT,
+	WRITE_LIFE_MEDIUM,
+	WRITE_LIFE_LONG,
+	WRITE_LIFE_EXTREME
+};
+#endif
+
 #ifdef HAVE_LIBSELINUX
 #include <selinux/selinux.h>
 #include <selinux/label.h>
@@ -106,9 +120,6 @@ typedef uint16_t	u16;
 typedef uint8_t		u8;
 typedef u32		block_t;
 typedef u32		nid_t;
-#ifndef bool
-typedef u8		bool;
-#endif
 typedef unsigned long	pgoff_t;
 typedef unsigned short	umode_t;
 
@@ -444,6 +455,7 @@ struct device_info {
 	uint64_t start_blkaddr;
 	uint64_t end_blkaddr;
 	uint32_t total_segments;
+	char *alias_filename;
 
 	/* to handle zone block devices */
 	int zoned_model;
@@ -666,6 +678,8 @@ enum {
 #define F2FS_IMMUTABLE_FL		0x00000010 /* Immutable file */
 #define F2FS_NOATIME_FL			0x00000080 /* do not update atime */
 #define F2FS_CASEFOLD_FL		0x40000000 /* Casefolded file */
+#define F2FS_DEVICE_ALIAS_FL		0x80000000 /* File for aliasing a device */
+#define IS_DEVICE_ALIASING(fi)	((fi)->i_flags & cpu_to_le32(F2FS_DEVICE_ALIAS_FL))
 
 #define F2FS_ENC_UTF8_12_1	1
 #define F2FS_ENC_STRICT_MODE_FL	(1 << 0)
@@ -698,6 +712,7 @@ enum {
 #define F2FS_FEATURE_CASEFOLD		0x1000
 #define F2FS_FEATURE_COMPRESSION	0x2000
 #define F2FS_FEATURE_RO			0x4000
+#define F2FS_FEATURE_DEVICE_ALIAS	0x8000
 
 #define MAX_NR_FEATURE			32
 
@@ -1429,6 +1444,12 @@ enum FILE_TYPE {
 	F2FS_FT_LAST_FILE_TYPE = F2FS_FT_XATTR,
 };
 
+enum dot_type {
+	NON_DOT,
+	TYPE_DOT,
+	TYPE_DOTDOT
+};
+
 #define LINUX_S_IFMT  00170000
 #define LINUX_S_IFREG  0100000
 #define LINUX_S_IFDIR  0040000
@@ -1520,11 +1541,16 @@ struct f2fs_configuration {
 	time_t fixed_time;
 	int roll_forward;
 	bool need_fsync;
+	bool need_whint;
+	int whint;
+	int aliased_devices;
+	uint32_t aliased_segments;
 
 	/* mkfs parameters */
 	int fake_seed;
 	uint32_t next_free_nid;
 	uint32_t lpf_ino;
+	uint32_t first_alias_ino;
 	uint32_t root_uid;
 	uint32_t root_gid;
 	uint32_t blksize;
@@ -1581,7 +1607,7 @@ extern unsigned int addrs_per_page(struct f2fs_inode *, bool);
 extern unsigned int f2fs_max_file_offset(struct f2fs_inode *);
 extern __u32 f2fs_inode_chksum(struct f2fs_node *);
 extern __u32 f2fs_checkpoint_chksum(struct f2fs_checkpoint *);
-extern int write_inode(struct f2fs_node *, u64);
+extern int write_inode(struct f2fs_node *, u64, enum rw_hint);
 
 extern int get_bits_in_byte(unsigned char n);
 extern int test_and_set_bit_le(u32, u8 *);
@@ -1618,15 +1644,16 @@ extern int dev_readahead(__u64, size_t);
 #else
 extern int dev_readahead(__u64, size_t UNUSED(len));
 #endif
-extern int dev_write(void *, __u64, size_t);
-extern int dev_write_block(void *, __u64);
+extern enum rw_hint f2fs_io_type_to_rw_hint(int);
+extern int dev_write(void *, __u64, size_t, enum rw_hint);
+extern int dev_write_block(void *, __u64, enum rw_hint);
 extern int dev_write_dump(void *, __u64, size_t);
 #if !defined(__MINGW32__)
 extern int dev_write_symlink(char *, size_t);
 #endif
 /* All bytes in the buffer must be 0 use dev_fill(). */
-extern int dev_fill(void *, __u64, size_t);
-extern int dev_fill_block(void *, __u64);
+extern int dev_fill(void *, __u64, size_t, enum rw_hint);
+extern int dev_fill_block(void *, __u64, enum rw_hint);
 
 extern int dev_read_block(void *, __u64);
 extern int dev_reada_block(__u64);
diff --git a/lib/libf2fs.c b/lib/libf2fs.c
index 1e0f422..ecd22d4 100644
--- a/lib/libf2fs.c
+++ b/lib/libf2fs.c
@@ -603,12 +603,12 @@ __u32 f2fs_checkpoint_chksum(struct f2fs_checkpoint *cp)
 	return chksum;
 }
 
-int write_inode(struct f2fs_node *inode, u64 blkaddr)
+int write_inode(struct f2fs_node *inode, u64 blkaddr, enum rw_hint whint)
 {
 	if (c.feature & F2FS_FEATURE_INODE_CHKSUM)
 		inode->i.i_inode_checksum =
 			cpu_to_le32(f2fs_inode_chksum(inode));
-	return dev_write_block(inode, blkaddr);
+	return dev_write_block(inode, blkaddr, whint);
 }
 
 /*
@@ -1005,7 +1005,7 @@ int get_device_info(int i)
 #endif
 
 	if (!c.sparse_mode) {
-		if (dev->zoned_model == F2FS_ZONED_HM && c.func == FSCK)
+		if (dev->zoned_model == F2FS_ZONED_HM)
 			flags |= O_DSYNC;
 
 		if (S_ISBLK(stat_buf->st_mode) &&
diff --git a/lib/libf2fs_io.c b/lib/libf2fs_io.c
index f39367a..520ae03 100644
--- a/lib/libf2fs_io.c
+++ b/lib/libf2fs_io.c
@@ -34,6 +34,11 @@
 #include <linux/hdreg.h>
 #endif
 
+#ifndef F_SET_RW_HINT
+#define F_LINUX_SPECIFIC_BASE 	1024
+#define F_SET_RW_HINT		(F_LINUX_SPECIFIC_BASE + 12)
+#endif
+
 #include <stdbool.h>
 #include <assert.h>
 #include <inttypes.h>
@@ -553,11 +558,87 @@ int dev_readahead(__u64 offset, size_t UNUSED(len))
 	return 0;
 #endif
 }
+/*
+ * Copied from fs/f2fs/segment.c
+ */
+/*
+ * This returns write hints for each segment type. This hints will be
+ * passed down to block layer as below by default.
+ *
+ * User                  F2FS                     Block
+ * ----                  ----                     -----
+ *                       META                     WRITE_LIFE_NONE|REQ_META
+ *                       HOT_NODE                 WRITE_LIFE_NONE
+ *                       WARM_NODE                WRITE_LIFE_MEDIUM
+ *                       COLD_NODE                WRITE_LIFE_LONG
+ * ioctl(COLD)           COLD_DATA                WRITE_LIFE_EXTREME
+ * extension list        "                        "
+ *
+ * -- buffered io
+ *                       COLD_DATA                WRITE_LIFE_EXTREME
+ *                       HOT_DATA                 WRITE_LIFE_SHORT
+ *                       WARM_DATA                WRITE_LIFE_NOT_SET
+ *
+ * -- direct io
+ * WRITE_LIFE_EXTREME    COLD_DATA                WRITE_LIFE_EXTREME
+ * WRITE_LIFE_SHORT      HOT_DATA                 WRITE_LIFE_SHORT
+ * WRITE_LIFE_NOT_SET    WARM_DATA                WRITE_LIFE_NOT_SET
+ * WRITE_LIFE_NONE       "                        WRITE_LIFE_NONE
+ * WRITE_LIFE_MEDIUM     "                        WRITE_LIFE_MEDIUM
+ * WRITE_LIFE_LONG       "                        WRITE_LIFE_LONG
+ */
+enum rw_hint f2fs_io_type_to_rw_hint(int seg_type)
+{
+	switch (seg_type) {
+	case CURSEG_WARM_DATA:
+		return WRITE_LIFE_NOT_SET;
+	case CURSEG_HOT_DATA:
+		return WRITE_LIFE_SHORT;
+	case CURSEG_COLD_DATA:
+		return WRITE_LIFE_EXTREME;
+	case CURSEG_WARM_NODE:
+		return WRITE_LIFE_MEDIUM;
+	case CURSEG_HOT_NODE:
+		return WRITE_LIFE_NONE;
+	case CURSEG_COLD_NODE:
+		return WRITE_LIFE_LONG;
+	default:
+		return WRITE_LIFE_NONE;
+	}
+}
 
-int dev_write(void *buf, __u64 offset, size_t len)
+static int __dev_write(void *buf, __u64 offset, size_t len, enum rw_hint whint)
 {
 	int fd;
 
+	fd = __get_device_fd(&offset);
+	if (fd < 0)
+		return fd;
+
+	if (lseek(fd, (off_t)offset, SEEK_SET) < 0)
+		return -1;
+
+#if ! defined(__MINGW32__)
+	if (c.need_whint && (c.whint != whint)) {
+		u64 hint = whint;
+		int ret;
+
+		ret = fcntl(fd, F_SET_RW_HINT, &hint);
+		if (ret != -1)
+			c.whint = whint;
+	}
+#endif
+
+	if (write(fd, buf, len) < 0)
+		return -1;
+
+	c.need_fsync = true;
+
+	return 0;
+}
+
+int dev_write(void *buf, __u64 offset, size_t len, enum rw_hint whint)
+{
 	if (c.dry_run)
 		return 0;
 
@@ -572,21 +653,12 @@ int dev_write(void *buf, __u64 offset, size_t len)
 	if (dcache_update_cache(buf, offset, len) < 0)
 		return -1;
 
-	fd = __get_device_fd(&offset);
-	if (fd < 0)
-		return fd;
-
-	if (lseek(fd, (off_t)offset, SEEK_SET) < 0)
-		return -1;
-	if (write(fd, buf, len) < 0)
-		return -1;
-	c.need_fsync = true;
-	return 0;
+	return __dev_write(buf, offset, len, whint);
 }
 
-int dev_write_block(void *buf, __u64 blk_addr)
+int dev_write_block(void *buf, __u64 blk_addr, enum rw_hint whint)
 {
-	return dev_write(buf, blk_addr << F2FS_BLKSIZE_BITS, F2FS_BLKSIZE);
+	return dev_write(buf, blk_addr << F2FS_BLKSIZE_BITS, F2FS_BLKSIZE, whint);
 }
 
 int dev_write_dump(void *buf, __u64 offset, size_t len)
@@ -608,32 +680,22 @@ int dev_write_symlink(char *buf, size_t len)
 }
 #endif
 
-int dev_fill(void *buf, __u64 offset, size_t len)
+int dev_fill(void *buf, __u64 offset, size_t len, enum rw_hint whint)
 {
-	int fd;
-
 	if (c.sparse_mode)
 		return sparse_write_zeroed_blk(offset / F2FS_BLKSIZE,
 						len / F2FS_BLKSIZE);
 
-	fd = __get_device_fd(&offset);
-	if (fd < 0)
-		return fd;
-
 	/* Only allow fill to zero */
 	if (*((__u8*)buf))
 		return -1;
-	if (lseek(fd, (off_t)offset, SEEK_SET) < 0)
-		return -1;
-	if (write(fd, buf, len) < 0)
-		return -1;
-	c.need_fsync = true;
-	return 0;
+
+	return __dev_write(buf, offset, len, whint);
 }
 
-int dev_fill_block(void *buf, __u64 blk_addr)
+int dev_fill_block(void *buf, __u64 blk_addr, enum rw_hint whint)
 {
-	return dev_fill(buf, blk_addr << F2FS_BLKSIZE_BITS, F2FS_BLKSIZE);
+	return dev_fill(buf, blk_addr << F2FS_BLKSIZE_BITS, F2FS_BLKSIZE, whint);
 }
 
 int dev_read_block(void *buf, __u64 blk_addr)
diff --git a/man/defrag.f2fs.8 b/man/defrag.f2fs.8
index 34113de..fcbe3bc 100644
--- a/man/defrag.f2fs.8
+++ b/man/defrag.f2fs.8
@@ -18,6 +18,9 @@ defrag.f2fs \- relocate blocks in a given area to the specified region
 .I target block address
 ]
 [
+.B \-H
+]
+[
 .B \-i
 .I direction
 ]
@@ -53,6 +56,9 @@ Specify the number of blocks to move.
 .BI \-t " target block address"
 Specify the destination block address.
 .TP
+.BI \-H
+Specify support write hint.
+.TP
 .BI \-i " direction"
 Set the direction to left. If it is not set, the direction becomes right
 by default.
diff --git a/man/f2fs_io.8 b/man/f2fs_io.8
index b9c9dc8..2ff22f7 100644
--- a/man/f2fs_io.8
+++ b/man/f2fs_io.8
@@ -11,16 +11,22 @@ administrative purposes.
 \fBset_verity\fR \fI[file]\fR
 Set the verity flags associated with the specified file.
 .TP
+\fBfsync\fR \fI[file]\fR
+fsync given the file.
+.TP
+\fBfdatasync\fR \fI[file]\fR
+fdatasync given the file.
+.TP
 \fBgetflags\fR \fI[file]\fR
 Get the flags associated with the specified file.
 .TP
 \fBsetflags\fR \fI[flag] [file]\fR
 Set an f2fs file on specified file.  The flag can be casefold,
-compression, and nocompression.
+compression, nocompression, immutable, and nocow.
 .TP
 \fBclearflags\fR \fI[flag] [file]\fR
-Clear the specified flag on the target file, which can be compression
-and nocompression.
+Clear the specified flag on the target file, which can be compression,
+ nocompression, immutable, and nocow.
 .TP
 \fBshutdown\fR \fIshutdown filesystem\fR
 Freeze and stop all IOs for the file system mounted on
diff --git a/man/fsck.f2fs.8 b/man/fsck.f2fs.8
index aff4ff2..e39a846 100644
--- a/man/fsck.f2fs.8
+++ b/man/fsck.f2fs.8
@@ -14,6 +14,9 @@ fsck.f2fs \- check a Linux F2FS file system
 .I enable force fix
 ]
 [
+.B \-H
+]
+[
 .B \-M
 .I show file map
 ]
@@ -48,6 +51,9 @@ module. It is disabled by default.
 .BI \-f " enable force fix"
 Enable to fix all the inconsistency in the partition.
 .TP
+.BI \-H
+Specify support write hint.
+.TP
 .BI \-M " show files map"
 Enable to show all the filenames and inode numbers stored in the image
 .TP
diff --git a/man/mkfs.f2fs.8 b/man/mkfs.f2fs.8
index 1f0c724..8b3b0cc 100644
--- a/man/mkfs.f2fs.8
+++ b/man/mkfs.f2fs.8
@@ -31,6 +31,9 @@ mkfs.f2fs \- create an F2FS file system
 .I default-options
 ]
 [
+.B \-H
+]
+[
 .B \-i
 ]
 [
@@ -119,7 +122,7 @@ block size matches the page size.
 The default value is 4096.
 .TP
 .BI \-c " device-list"
-Build f2fs with these additional comma separated devices, so that the user can
+Build f2fs with these additional devices, so that the user can
 see all the devices as one big volume.
 Supports up to 7 devices except meta device.
 .TP
@@ -152,6 +155,9 @@ The following values are supported:
 Use default options for Android having "-d1 -f -w 4096 -R 0:0 -O encrypt -O project_quota,extra_attr,{quota} -O verity".
 .RE
 .TP
+.BI \-H
+Specify support write hint.
+.TP
 .BI \-i
 Enable extended node bitmap.
 .TP
diff --git a/man/resize.f2fs.8 b/man/resize.f2fs.8
index 3288760..d41ad79 100644
--- a/man/resize.f2fs.8
+++ b/man/resize.f2fs.8
@@ -18,6 +18,9 @@ resize.f2fs \- resize filesystem size
 .I overprovision-ratio-percentage
 ]
 [
+.B \-H
+]
+[
 .B \-i
 ]
 [
@@ -53,6 +56,9 @@ Specify the percentage of the volume that will be used as overprovision area.
 This area is hidden to users, and utilized by F2FS cleaner. If not specified, the
 best number will be assigned automatically according to the partition size.
 .TP
+.BI \-H
+Specify support write hint.
+.TP
 .BI \-i
 Enable extended node bitmap.
 .TP
diff --git a/mkfs/f2fs_format.c b/mkfs/f2fs_format.c
index 247a836..6635eed 100644
--- a/mkfs/f2fs_format.c
+++ b/mkfs/f2fs_format.c
@@ -13,6 +13,7 @@
 #include <unistd.h>
 #include <f2fs_fs.h>
 #include <assert.h>
+#include <stdbool.h>
 
 #ifdef HAVE_SYS_STAT_H
 #include <sys/stat.h>
@@ -39,10 +40,62 @@ struct f2fs_super_block raw_sb;
 struct f2fs_super_block *sb = &raw_sb;
 struct f2fs_checkpoint *cp;
 
+static inline bool device_is_aliased(unsigned int dev_num)
+{
+	if (dev_num >= c.ndevs)
+		return false;
+	return c.devices[dev_num].alias_filename != NULL;
+}
+
+static inline unsigned int target_device_index(uint64_t blkaddr)
+{
+	int i;
+
+	for (i = 0; i < c.ndevs; i++)
+		if (c.devices[i].start_blkaddr <= blkaddr &&
+				c.devices[i].end_blkaddr >= blkaddr)
+			return i;
+	return 0;
+}
+
+#define GET_SEGNO(blk_addr) ((blk_addr - get_sb(main_blkaddr)) / \
+				c.blks_per_seg)
+#define START_BLOCK(segno) (segno * c.blks_per_seg + get_sb(main_blkaddr))
+
 /* Return first segment number of each area */
-#define prev_zone(cur)		(c.cur_seg[cur] - c.segs_per_zone)
-#define next_zone(cur)		(c.cur_seg[cur] + c.segs_per_zone)
-#define last_zone(cur)		((cur - 1) * c.segs_per_zone)
+static inline uint32_t next_zone(int seg_type)
+{
+	uint32_t next_seg = c.cur_seg[seg_type] + c.segs_per_zone;
+	uint64_t next_blkaddr = START_BLOCK(next_seg);
+	int dev_num;
+
+	dev_num = target_device_index(next_blkaddr);
+	if (!device_is_aliased(dev_num))
+		return GET_SEGNO(next_blkaddr);
+
+	while (dev_num < c.ndevs && device_is_aliased(dev_num))
+		dev_num++;
+
+	return GET_SEGNO(c.devices[dev_num - 1].end_blkaddr + 1);
+}
+
+static inline uint32_t last_zone(uint32_t total_zone)
+{
+	uint32_t last_seg = (total_zone - 1) * c.segs_per_zone;
+	uint64_t last_blkaddr = START_BLOCK(last_seg);
+	int dev_num;
+
+	dev_num = target_device_index(last_blkaddr);
+	if (!device_is_aliased(dev_num))
+		return GET_SEGNO(last_blkaddr);
+
+	while (dev_num > 0 && device_is_aliased(dev_num))
+		dev_num--;
+
+	return GET_SEGNO(c.devices[dev_num + 1].start_blkaddr) -
+		c.segs_per_zone;
+}
+
 #define last_section(cur)	(cur + (c.secs_per_zone - 1) * c.segs_per_sec)
 
 /* Return time fixed by the user or current time by default */
@@ -213,6 +266,7 @@ static int f2fs_prepare_super_block(void)
 	uint32_t log_sectorsize, log_sectors_per_block;
 	uint32_t log_blocksize, log_blks_per_seg;
 	uint32_t segment_size_bytes, zone_size_bytes;
+	uint32_t alignment_bytes;
 	uint32_t sit_segments, nat_segments;
 	uint32_t blocks_for_sit, blocks_for_nat, blocks_for_ssa;
 	uint32_t total_valid_blks_available;
@@ -220,7 +274,7 @@ static int f2fs_prepare_super_block(void)
 	uint64_t total_meta_zones, total_meta_segments;
 	uint32_t sit_bitmap_size, max_sit_bitmap_size;
 	uint32_t max_nat_bitmap_size, max_nat_segments;
-	uint32_t total_zones, avail_zones;
+	uint32_t total_zones, avail_zones = 0;
 	enum quota_type qtype;
 	int i;
 
@@ -252,10 +306,12 @@ static int f2fs_prepare_super_block(void)
 
 	set_sb(block_count, c.total_sectors >> log_sectors_per_block);
 
+	alignment_bytes = c.zoned_mode && c.ndevs > 1 ? segment_size_bytes : zone_size_bytes;
+
 	zone_align_start_offset =
 		((uint64_t) c.start_sector * DEFAULT_SECTOR_SIZE +
-		2 * F2FS_BLKSIZE + zone_size_bytes - 1) /
-		zone_size_bytes * zone_size_bytes -
+		2 * F2FS_BLKSIZE + alignment_bytes  - 1) /
+		alignment_bytes  * alignment_bytes  -
 		(uint64_t) c.start_sector * DEFAULT_SECTOR_SIZE;
 
 	if (c.feature & F2FS_FEATURE_RO)
@@ -274,7 +330,8 @@ static int f2fs_prepare_super_block(void)
 
 	if (c.zoned_mode && c.ndevs > 1)
 		zone_align_start_offset +=
-			(c.devices[0].total_sectors * c.sector_size) % zone_size_bytes;
+			(c.devices[0].total_sectors * c.sector_size -
+			 zone_align_start_offset) % zone_size_bytes;
 
 	set_sb(segment0_blkaddr, zone_align_start_offset / blk_size_bytes);
 	sb->cp_blkaddr = sb->segment0_blkaddr;
@@ -314,6 +371,16 @@ static int f2fs_prepare_super_block(void)
 			c.devices[i].end_blkaddr = c.devices[i].start_blkaddr +
 					c.devices[i].total_segments *
 					c.blks_per_seg - 1;
+			if (device_is_aliased(i)) {
+				if (c.devices[i].zoned_model ==
+						F2FS_ZONED_HM) {
+					MSG(1, "\tError: do not support "
+					"device aliasing for device[%d]\n", i);
+					return -1;
+				}
+				c.aliased_segments +=
+					c.devices[i].total_segments;
+			}
 		}
 		if (c.ndevs > 1) {
 			strncpy((char *)sb->devs[i].path, c.devices[i].path, MAX_PATH_LEN);
@@ -531,10 +598,16 @@ static int f2fs_prepare_super_block(void)
 	if (c.feature & F2FS_FEATURE_LOST_FOUND)
 		c.lpf_ino = c.next_free_nid++;
 
+	if (c.aliased_devices) {
+		c.first_alias_ino = c.next_free_nid;
+		c.next_free_nid += c.aliased_devices;
+		avail_zones += c.aliased_segments / c.segs_per_zone;
+	}
+
 	if (c.feature & F2FS_FEATURE_RO)
-		avail_zones = 2;
+		avail_zones += 2;
 	else
-		avail_zones = 6;
+		avail_zones += 6;
 
 	if (total_zones <= avail_zones) {
 		MSG(1, "\tError: %d zones: Need more zones "
@@ -640,7 +713,7 @@ static int f2fs_init_sit_area(void)
 
 	DBG(1, "\tFilling sit area at offset 0x%08"PRIx64"\n", sit_seg_addr);
 	for (index = 0; index < (get_sb(segment_count_sit) / 2); index++) {
-		if (dev_fill(zero_buf, sit_seg_addr, seg_size)) {
+		if (dev_fill(zero_buf, sit_seg_addr, seg_size, WRITE_LIFE_NONE)) {
 			MSG(1, "\tError: While zeroing out the sit area "
 					"on disk!!!\n");
 			free(zero_buf);
@@ -674,7 +747,7 @@ static int f2fs_init_nat_area(void)
 
 	DBG(1, "\tFilling nat area at offset 0x%08"PRIx64"\n", nat_seg_addr);
 	for (index = 0; index < get_sb(segment_count_nat) / 2; index++) {
-		if (dev_fill(nat_buf, nat_seg_addr, seg_size)) {
+		if (dev_fill(nat_buf, nat_seg_addr, seg_size, WRITE_LIFE_NONE)) {
 			MSG(1, "\tError: While zeroing out the nat area "
 					"on disk!!!\n");
 			free(nat_buf);
@@ -701,6 +774,7 @@ static int f2fs_write_check_point_pack(void)
 	char *sum_compact, *sum_compact_p;
 	struct f2fs_summary *sum_entry;
 	unsigned short vblocks;
+	uint32_t used_segments = c.aliased_segments;
 	int ret = -1;
 
 	cp = calloc(F2FS_BLKSIZE, 1);
@@ -752,9 +826,14 @@ static int f2fs_write_check_point_pack(void)
 	}
 
 	set_cp(cur_node_blkoff[0], c.curseg_offset[CURSEG_HOT_NODE]);
+	set_cp(cur_node_blkoff[2], c.curseg_offset[CURSEG_COLD_NODE]);
 	set_cp(cur_data_blkoff[0], c.curseg_offset[CURSEG_HOT_DATA]);
+	set_cp(cur_data_blkoff[2], c.curseg_offset[CURSEG_COLD_DATA]);
 	set_cp(valid_block_count, c.curseg_offset[CURSEG_HOT_NODE] +
-					c.curseg_offset[CURSEG_HOT_DATA]);
+			c.curseg_offset[CURSEG_HOT_DATA] +
+			c.curseg_offset[CURSEG_COLD_NODE] +
+			c.curseg_offset[CURSEG_COLD_DATA] +
+			c.aliased_segments * c.blks_per_seg);
 	set_cp(rsvd_segment_count, c.reserved_segments);
 
 	/*
@@ -801,15 +880,16 @@ static int f2fs_write_check_point_pack(void)
 					c.reserved_segments);
 
 	/* main segments - reserved segments - (node + data segments) */
-	if (c.feature & F2FS_FEATURE_RO) {
-		set_cp(free_segment_count, f2fs_get_usable_segments(sb) - 2);
-		set_cp(user_block_count, ((get_cp(free_segment_count) + 2 -
-			get_cp(overprov_segment_count)) * c.blks_per_seg));
-	} else {
-		set_cp(free_segment_count, f2fs_get_usable_segments(sb) - 6);
-		set_cp(user_block_count, ((get_cp(free_segment_count) + 6 -
-			get_cp(overprov_segment_count)) * c.blks_per_seg));
-	}
+	if (c.feature & F2FS_FEATURE_RO)
+		used_segments += 2;
+	else
+		used_segments += 6;
+
+	set_cp(user_block_count, (f2fs_get_usable_segments(sb) -
+			get_cp(overprov_segment_count)) * c.blks_per_seg);
+	set_cp(free_segment_count, f2fs_get_usable_segments(sb) -
+			used_segments);
+
 	/* cp page (2), data summaries (1), node summaries (3) */
 	set_cp(cp_pack_total_block_count, 6 + get_sb(cp_payload));
 	flags = CP_UMOUNT_FLAG | CP_COMPACT_SUM_FLAG;
@@ -825,8 +905,10 @@ static int f2fs_write_check_point_pack(void)
 
 	set_cp(ckpt_flags, flags);
 	set_cp(cp_pack_start_sum, 1 + get_sb(cp_payload));
-	set_cp(valid_node_count, c.curseg_offset[CURSEG_HOT_NODE]);
-	set_cp(valid_inode_count, c.curseg_offset[CURSEG_HOT_NODE]);
+	set_cp(valid_node_count, c.curseg_offset[CURSEG_HOT_NODE] +
+			c.curseg_offset[CURSEG_COLD_NODE]);
+	set_cp(valid_inode_count, c.curseg_offset[CURSEG_HOT_NODE] +
+			c.curseg_offset[CURSEG_COLD_NODE]);
 	set_cp(next_free_nid, c.next_free_nid);
 	set_cp(sit_ver_bitmap_bytesize, ((get_sb(segment_count_sit) / 2) <<
 			get_sb(log_blocks_per_seg)) / 8);
@@ -855,14 +937,14 @@ static int f2fs_write_check_point_pack(void)
 
 	DBG(1, "\tWriting main segments, cp at offset 0x%08"PRIx64"\n",
 						cp_seg_blk);
-	if (dev_write_block(cp, cp_seg_blk)) {
+	if (dev_write_block(cp, cp_seg_blk, WRITE_LIFE_NONE)) {
 		MSG(1, "\tError: While writing the cp to disk!!!\n");
 		goto free_cp_payload;
 	}
 
 	for (i = 0; i < get_sb(cp_payload); i++) {
 		cp_seg_blk++;
-		if (dev_fill_block(cp_payload, cp_seg_blk)) {
+		if (dev_fill_block(cp_payload, cp_seg_blk, WRITE_LIFE_NONE)) {
 			MSG(1, "\tError: While zeroing out the sit bitmap area "
 					"on disk!!!\n");
 			goto free_cp_payload;
@@ -943,7 +1025,7 @@ static int f2fs_write_check_point_pack(void)
 	cp_seg_blk++;
 	DBG(1, "\tWriting Segment summary for HOT/WARM/COLD_DATA, at offset 0x%08"PRIx64"\n",
 			cp_seg_blk);
-	if (dev_write_block(sum_compact, cp_seg_blk)) {
+	if (dev_write_block(sum_compact, cp_seg_blk, WRITE_LIFE_NONE)) {
 		MSG(1, "\tError: While writing the sum_blk to disk!!!\n");
 		goto free_cp_payload;
 	}
@@ -957,7 +1039,7 @@ static int f2fs_write_check_point_pack(void)
 	cp_seg_blk++;
 	DBG(1, "\tWriting Segment summary for HOT_NODE, at offset 0x%08"PRIx64"\n",
 			cp_seg_blk);
-	if (dev_write_block(sum, cp_seg_blk)) {
+	if (dev_write_block(sum, cp_seg_blk, WRITE_LIFE_NONE)) {
 		MSG(1, "\tError: While writing the sum_blk to disk!!!\n");
 		goto free_cp_payload;
 	}
@@ -969,18 +1051,21 @@ static int f2fs_write_check_point_pack(void)
 	cp_seg_blk++;
 	DBG(1, "\tWriting Segment summary for WARM_NODE, at offset 0x%08"PRIx64"\n",
 			cp_seg_blk);
-	if (dev_write_block(sum, cp_seg_blk)) {
+	if (dev_write_block(sum, cp_seg_blk, WRITE_LIFE_NONE)) {
 		MSG(1, "\tError: While writing the sum_blk to disk!!!\n");
 		goto free_cp_payload;
 	}
 
-	/* Fill segment summary for COLD_NODE to zero. */
+	/* Prepare and write Segment summary for COLD_NODE */
 	memset(sum, 0, F2FS_BLKSIZE);
 	SET_SUM_TYPE(sum, SUM_TYPE_NODE);
+	memcpy(sum->entries, c.sum[CURSEG_COLD_NODE],
+			sizeof(struct f2fs_summary) * MAX_CACHE_SUMS);
+
 	cp_seg_blk++;
 	DBG(1, "\tWriting Segment summary for COLD_NODE, at offset 0x%08"PRIx64"\n",
 			cp_seg_blk);
-	if (dev_write_block(sum, cp_seg_blk)) {
+	if (dev_write_block(sum, cp_seg_blk, WRITE_LIFE_NONE)) {
 		MSG(1, "\tError: While writing the sum_blk to disk!!!\n");
 		goto free_cp_payload;
 	}
@@ -988,7 +1073,7 @@ static int f2fs_write_check_point_pack(void)
 	/* cp page2 */
 	cp_seg_blk++;
 	DBG(1, "\tWriting cp page2, at offset 0x%08"PRIx64"\n", cp_seg_blk);
-	if (dev_write_block(cp, cp_seg_blk)) {
+	if (dev_write_block(cp, cp_seg_blk, WRITE_LIFE_NONE)) {
 		MSG(1, "\tError: While writing the cp to disk!!!\n");
 		goto free_cp_payload;
 	}
@@ -1011,7 +1096,8 @@ static int f2fs_write_check_point_pack(void)
 
 		for (i = 0; i < nat_bits_blocks; i++) {
 			if (dev_write_block(nat_bits + i *
-						F2FS_BLKSIZE, cp_seg_blk + i)) {
+						F2FS_BLKSIZE, cp_seg_blk + i,
+						WRITE_LIFE_NONE)) {
 				MSG(1, "\tError: write NAT bits to disk!!!\n");
 				goto free_cp_payload;
 			}
@@ -1029,14 +1115,14 @@ static int f2fs_write_check_point_pack(void)
 	cp_seg_blk = get_sb(segment0_blkaddr) + c.blks_per_seg;
 	DBG(1, "\tWriting cp page 1 of checkpoint pack 2, at offset 0x%08"PRIx64"\n",
 				cp_seg_blk);
-	if (dev_write_block(cp, cp_seg_blk)) {
+	if (dev_write_block(cp, cp_seg_blk, WRITE_LIFE_NONE)) {
 		MSG(1, "\tError: While writing the cp to disk!!!\n");
 		goto free_cp_payload;
 	}
 
 	for (i = 0; i < get_sb(cp_payload); i++) {
 		cp_seg_blk++;
-		if (dev_fill_block(cp_payload, cp_seg_blk)) {
+		if (dev_fill_block(cp_payload, cp_seg_blk, WRITE_LIFE_NONE)) {
 			MSG(1, "\tError: While zeroing out the sit bitmap area "
 					"on disk!!!\n");
 			goto free_cp_payload;
@@ -1048,7 +1134,7 @@ static int f2fs_write_check_point_pack(void)
 					get_sb(cp_payload) - 1);
 	DBG(1, "\tWriting cp page 2 of checkpoint pack 2, at offset 0x%08"PRIx64"\n",
 				cp_seg_blk);
-	if (dev_write_block(cp, cp_seg_blk)) {
+	if (dev_write_block(cp, cp_seg_blk, WRITE_LIFE_NONE)) {
 		MSG(1, "\tError: While writing the cp to disk!!!\n");
 		goto free_cp_payload;
 	}
@@ -1082,7 +1168,7 @@ static int f2fs_write_super_block(void)
 	memcpy(zero_buff + F2FS_SUPER_OFFSET, sb, sizeof(*sb));
 	DBG(1, "\tWriting super block, at offset 0x%08x\n", 0);
 	for (index = 0; index < 2; index++) {
-		if (dev_write_block(zero_buff, index)) {
+		if (dev_write_block(zero_buff, index, WRITE_LIFE_NONE)) {
 			MSG(1, "\tError: While while writing super_blk "
 					"on disk!!! index : %d\n", index);
 			free(zero_buff);
@@ -1135,7 +1221,8 @@ static int f2fs_discard_obsolete_dnode(void)
 		memset(raw_node, 0, F2FS_BLKSIZE);
 
 		DBG(1, "\tDiscard dnode, at offset 0x%08"PRIx64"\n", offset);
-		if (dev_write_block(raw_node, offset)) {
+		if (dev_write_block(raw_node, offset,
+				    f2fs_io_type_to_rw_hint(CURSEG_WARM_NODE))) {
 			MSG(1, "\tError: While discarding direct node!!!\n");
 			free(raw_node);
 			return -1;
@@ -1209,10 +1296,40 @@ void update_summary_entry(int curseg_type, nid_t nid,
 	sum->ofs_in_node = cpu_to_le16(ofs_in_node);
 }
 
+static void add_dentry(struct f2fs_dentry_block *dent_blk, unsigned int *didx,
+		const char *name, uint32_t ino, u8 type)
+{
+	int len = strlen(name);
+	f2fs_hash_t hash;
+
+	if (name[0] == '.' && (len == 1 || (len == 2 && name[1] == '.')))
+		hash = 0;
+	else
+		hash = f2fs_dentry_hash(0, 0, (unsigned char *)name, len);
+
+	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, *didx).hash_code = cpu_to_le32(hash);
+	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, *didx).ino = cpu_to_le32(ino);
+	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, *didx).name_len = cpu_to_le16(len);
+	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, *didx).file_type = type;
+
+	while (len > F2FS_SLOT_LEN) {
+		memcpy(F2FS_DENTRY_BLOCK_FILENAME(dent_blk, *didx), name,
+				F2FS_SLOT_LEN);
+		test_and_set_bit_le(*didx, dent_blk->dentry_bitmap);
+		len -= (int)F2FS_SLOT_LEN;
+		name += F2FS_SLOT_LEN;
+		(*didx)++;
+	}
+	memcpy(F2FS_DENTRY_BLOCK_FILENAME(dent_blk, *didx), name, len);
+	test_and_set_bit_le(*didx, dent_blk->dentry_bitmap);
+	(*didx)++;
+}
+
 static block_t f2fs_add_default_dentry_root(void)
 {
 	struct f2fs_dentry_block *dent_blk = NULL;
 	block_t data_blkaddr;
+	unsigned int didx = 0;
 
 	dent_blk = calloc(F2FS_BLKSIZE, 1);
 	if(dent_blk == NULL) {
@@ -1220,43 +1337,33 @@ static block_t f2fs_add_default_dentry_root(void)
 		return 0;
 	}
 
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 0).hash_code = 0;
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 0).ino = sb->root_ino;
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 0).name_len = cpu_to_le16(1);
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 0).file_type = F2FS_FT_DIR;
-	memcpy(F2FS_DENTRY_BLOCK_FILENAME(dent_blk, 0), ".", 1);
-
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 1).hash_code = 0;
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 1).ino = sb->root_ino;
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 1).name_len = cpu_to_le16(2);
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 1).file_type = F2FS_FT_DIR;
-	memcpy(F2FS_DENTRY_BLOCK_FILENAME(dent_blk, 1), "..", 2);
-
-	/* bitmap for . and .. */
-	test_and_set_bit_le(0, dent_blk->dentry_bitmap);
-	test_and_set_bit_le(1, dent_blk->dentry_bitmap);
+	add_dentry(dent_blk, &didx, ".",
+			le32_to_cpu(sb->root_ino), F2FS_FT_DIR);
+	add_dentry(dent_blk, &didx, "..",
+			le32_to_cpu(sb->root_ino), F2FS_FT_DIR);
 
-	if (c.lpf_ino) {
-		int len = strlen(LPF);
-		f2fs_hash_t hash = f2fs_dentry_hash(0, 0, (unsigned char *)LPF, len);
+	if (c.lpf_ino)
+		add_dentry(dent_blk, &didx, LPF, c.lpf_ino, F2FS_FT_DIR);
 
-		F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 2).hash_code = cpu_to_le32(hash);
-		F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 2).ino = cpu_to_le32(c.lpf_ino);
-		F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 2).name_len = cpu_to_le16(len);
-		F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 2).file_type = F2FS_FT_DIR;
-		memcpy(F2FS_DENTRY_BLOCK_FILENAME(dent_blk, 2), LPF, F2FS_SLOT_LEN);
+	if (c.aliased_devices) {
+		int i, dev_off = 0;
 
-		memcpy(F2FS_DENTRY_BLOCK_FILENAME(dent_blk, 3), &LPF[F2FS_SLOT_LEN],
-				len - F2FS_SLOT_LEN);
+		for (i = 1; i < c.ndevs; i++) {
+			if (!device_is_aliased(i))
+				continue;
 
-		test_and_set_bit_le(2, dent_blk->dentry_bitmap);
-		test_and_set_bit_le(3, dent_blk->dentry_bitmap);
+			add_dentry(dent_blk, &didx, c.devices[i].alias_filename,
+					c.first_alias_ino + dev_off,
+					F2FS_FT_REG_FILE);
+			dev_off++;
+		}
 	}
 
 	data_blkaddr = alloc_next_free_block(CURSEG_HOT_DATA);
 
 	DBG(1, "\tWriting default dentry root, at offset 0x%x\n", data_blkaddr);
-	if (dev_write_block(dent_blk, data_blkaddr)) {
+	if (dev_write_block(dent_blk, data_blkaddr,
+			    f2fs_io_type_to_rw_hint(CURSEG_HOT_DATA))) {
 		MSG(1, "\tError: While writing the dentry_blk to disk!!!\n");
 		free(dent_blk);
 		return 0;
@@ -1301,7 +1408,8 @@ static int f2fs_write_root_inode(void)
 	F2FS_NODE_FOOTER(raw_node)->next_blkaddr = cpu_to_le32(node_blkaddr + 1);
 
 	DBG(1, "\tWriting root inode (hot node), offset 0x%x\n", node_blkaddr);
-	if (write_inode(raw_node, node_blkaddr) < 0) {
+	if (write_inode(raw_node, node_blkaddr,
+			f2fs_io_type_to_rw_hint(CURSEG_HOT_NODE)) < 0) {
 		MSG(1, "\tError: While writing the raw_node to disk!!!\n");
 		free(raw_node);
 		return -1;
@@ -1323,6 +1431,7 @@ static int f2fs_write_default_quota(int qtype, __le32 raw_id)
 	struct v2_disk_dqinfo ddqinfo;
 	struct v2r1_disk_dqblk dqblk;
 	block_t blkaddr;
+	uint64_t icnt = 1, bcnt = 1;
 	int i;
 
 	if (filebuf == NULL) {
@@ -1358,16 +1467,18 @@ static int f2fs_write_default_quota(int qtype, __le32 raw_id)
 	dqblk.dqb_pad = cpu_to_le32(0);
 	dqblk.dqb_ihardlimit = cpu_to_le64(0);
 	dqblk.dqb_isoftlimit = cpu_to_le64(0);
-	if (c.lpf_ino)
-		dqblk.dqb_curinodes = cpu_to_le64(2);
-	else
-		dqblk.dqb_curinodes = cpu_to_le64(1);
+	if (c.lpf_ino) {
+		icnt++;
+		bcnt++;
+	}
+	if (c.aliased_devices) {
+		icnt += c.aliased_devices;
+		bcnt += c.aliased_segments * c.blks_per_seg;
+	}
+	dqblk.dqb_curinodes = cpu_to_le64(icnt);
 	dqblk.dqb_bhardlimit = cpu_to_le64(0);
 	dqblk.dqb_bsoftlimit = cpu_to_le64(0);
-	if (c.lpf_ino)
-		dqblk.dqb_curspace = cpu_to_le64(F2FS_BLKSIZE * 2);
-	else
-		dqblk.dqb_curspace = cpu_to_le64(F2FS_BLKSIZE);
+	dqblk.dqb_curspace = cpu_to_le64(F2FS_BLKSIZE * bcnt);
 	dqblk.dqb_btime = cpu_to_le64(0);
 	dqblk.dqb_itime = cpu_to_le64(0);
 
@@ -1377,7 +1488,8 @@ static int f2fs_write_default_quota(int qtype, __le32 raw_id)
 	for (i = 0; i < QUOTA_DATA; i++) {
 		blkaddr = alloc_next_free_block(CURSEG_HOT_DATA);
 
-		if (dev_write_block(filebuf + i * F2FS_BLKSIZE, blkaddr)) {
+		if (dev_write_block(filebuf + i * F2FS_BLKSIZE, blkaddr,
+				    f2fs_io_type_to_rw_hint(CURSEG_HOT_DATA))) {
 			MSG(1, "\tError: While writing the quota_blk to disk!!!\n");
 			free(filebuf);
 			return 0;
@@ -1439,7 +1551,8 @@ static int f2fs_write_qf_inode(int qtype)
 					cpu_to_le32(data_blkaddr + i);
 
 	DBG(1, "\tWriting quota inode (hot node), offset 0x%x\n", node_blkaddr);
-	if (write_inode(raw_node, node_blkaddr) < 0) {
+	if (write_inode(raw_node, node_blkaddr,
+			f2fs_io_type_to_rw_hint(CURSEG_HOT_NODE)) < 0) {
 		MSG(1, "\tError: While writing the raw_node to disk!!!\n");
 		free(raw_node);
 		return -1;
@@ -1476,7 +1589,7 @@ static int f2fs_update_nat_default(void)
 
 	DBG(1, "\tWriting nat root, at offset 0x%08"PRIx64"\n",
 					nat_seg_blk_offset);
-	if (dev_write_block(nat_blk, nat_seg_blk_offset)) {
+	if (dev_write_block(nat_blk, nat_seg_blk_offset, WRITE_LIFE_NONE)) {
 		MSG(1, "\tError: While writing the nat_blk set0 to disk!\n");
 		free(nat_blk);
 		return -1;
@@ -1490,6 +1603,7 @@ static block_t f2fs_add_default_dentry_lpf(void)
 {
 	struct f2fs_dentry_block *dent_blk;
 	block_t data_blkaddr;
+	unsigned int didx = 0;
 
 	dent_blk = calloc(F2FS_BLKSIZE, 1);
 	if (dent_blk == NULL) {
@@ -1497,26 +1611,15 @@ static block_t f2fs_add_default_dentry_lpf(void)
 		return 0;
 	}
 
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 0).hash_code = 0;
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 0).ino = cpu_to_le32(c.lpf_ino);
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 0).name_len = cpu_to_le16(1);
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 0).file_type = F2FS_FT_DIR;
-	memcpy(F2FS_DENTRY_BLOCK_FILENAME(dent_blk, 0), ".", 1);
-
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 1).hash_code = 0;
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 1).ino = sb->root_ino;
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 1).name_len = cpu_to_le16(2);
-	F2FS_DENTRY_BLOCK_DENTRY(dent_blk, 1).file_type = F2FS_FT_DIR;
-	memcpy(F2FS_DENTRY_BLOCK_FILENAME(dent_blk, 1), "..", 2);
-
-	test_and_set_bit_le(0, dent_blk->dentry_bitmap);
-	test_and_set_bit_le(1, dent_blk->dentry_bitmap);
+	add_dentry(dent_blk, &didx, ".", c.lpf_ino, F2FS_FT_DIR);
+	add_dentry(dent_blk, &didx, "..", c.lpf_ino, F2FS_FT_DIR);
 
 	data_blkaddr = alloc_next_free_block(CURSEG_HOT_DATA);
 
 	DBG(1, "\tWriting default dentry lost+found, at offset 0x%x\n",
 							data_blkaddr);
-	if (dev_write_block(dent_blk, data_blkaddr)) {
+	if (dev_write_block(dent_blk, data_blkaddr,
+			    f2fs_io_type_to_rw_hint(CURSEG_HOT_DATA))) {
 		MSG(1, "\tError While writing the dentry_blk to disk!!!\n");
 		free(dent_blk);
 		return 0;
@@ -1546,8 +1649,8 @@ static int f2fs_write_lpf_inode(void)
 
 	f2fs_init_inode(sb, raw_node, c.lpf_ino, mkfs_time, 0x41c0);
 
-	raw_node->i.i_pino = le32_to_cpu(sb->root_ino);
-	raw_node->i.i_namelen = le32_to_cpu(strlen(LPF));
+	raw_node->i.i_pino = sb->root_ino;
+	raw_node->i.i_namelen = cpu_to_le32(strlen(LPF));
 	memcpy(raw_node->i.i_name, LPF, strlen(LPF));
 
 	node_blkaddr = alloc_next_free_block(CURSEG_HOT_NODE);
@@ -1563,7 +1666,8 @@ static int f2fs_write_lpf_inode(void)
 
 	DBG(1, "\tWriting lost+found inode (hot node), offset 0x%x\n",
 								node_blkaddr);
-	if (write_inode(raw_node, node_blkaddr) < 0) {
+	if (write_inode(raw_node, node_blkaddr,
+			f2fs_io_type_to_rw_hint(CURSEG_HOT_NODE)) < 0) {
 		MSG(1, "\tError: While writing the raw_node to disk!!!\n");
 		err = -1;
 		goto exit;
@@ -1578,6 +1682,105 @@ exit:
 	return err;
 }
 
+static void allocate_blocks_for_aliased_device(struct f2fs_node *raw_node,
+		unsigned int dev_num)
+{
+	uint32_t start_segno = (c.devices[dev_num].start_blkaddr -
+			get_sb(main_blkaddr)) / c.blks_per_seg;
+	uint32_t end_segno = (c.devices[dev_num].end_blkaddr -
+			get_sb(main_blkaddr) + 1) / c.blks_per_seg;
+	uint32_t segno;
+	uint64_t blkcnt;
+	struct f2fs_sit_block *sit_blk = calloc(F2FS_BLKSIZE, 1);
+
+	ASSERT(sit_blk);
+
+	for (segno = start_segno; segno < end_segno; segno++) {
+		struct f2fs_sit_entry *sit;
+		uint64_t sit_blk_addr = get_sb(sit_blkaddr) +
+			(segno / SIT_ENTRY_PER_BLOCK);
+
+		ASSERT(dev_read_block(sit_blk, sit_blk_addr) >= 0);
+		sit = &sit_blk->entries[segno % SIT_ENTRY_PER_BLOCK];
+		memset(&sit->valid_map, 0xFF, SIT_VBLOCK_MAP_SIZE);
+		sit->vblocks = cpu_to_le16((CURSEG_COLD_DATA <<
+					SIT_VBLOCKS_SHIFT) | c.blks_per_seg);
+		sit->mtime = cpu_to_le64(mkfs_time);
+		ASSERT(dev_write_block(sit_blk, sit_blk_addr,
+			f2fs_io_type_to_rw_hint(CURSEG_COLD_DATA)) >= 0);
+	}
+
+	blkcnt = (end_segno - start_segno) * c.blks_per_seg;
+	raw_node->i.i_size = cpu_to_le64(blkcnt << get_sb(log_blocksize));
+	raw_node->i.i_blocks = cpu_to_le64(blkcnt + 1);
+
+	raw_node->i.i_ext.fofs = cpu_to_le32(0);
+	raw_node->i.i_ext.blk_addr =
+		cpu_to_le32(c.devices[dev_num].start_blkaddr);
+	raw_node->i.i_ext.len = cpu_to_le32(blkcnt);
+
+	free(sit_blk);
+}
+
+static int f2fs_write_alias_inodes(void)
+{
+	struct f2fs_node *raw_node;
+	block_t node_blkaddr;
+	int err = 0;
+	unsigned int i, dev_off = 0;
+
+	ASSERT(c.aliased_devices);
+
+	raw_node = calloc(F2FS_BLKSIZE, 1);
+	if (raw_node == NULL) {
+		MSG(1, "\tError: Calloc Failed for raw_node!!!\n");
+		return -1;
+	}
+
+	for (i = 1; i < c.ndevs; i++) {
+		const char *filename;
+		nid_t ino;
+
+		if (!device_is_aliased(i))
+			continue;
+
+		ino = c.first_alias_ino + dev_off;
+		dev_off++;
+		f2fs_init_inode(sb, raw_node, ino, mkfs_time, 0x81c0);
+
+		raw_node->i.i_flags = cpu_to_le32(F2FS_DEVICE_ALIAS_FL);
+		raw_node->i.i_inline = F2FS_PIN_FILE;
+		raw_node->i.i_pino = sb->root_ino;
+		filename = c.devices[i].alias_filename;
+		raw_node->i.i_namelen = cpu_to_le32(strlen(filename));
+		memcpy(raw_node->i.i_name, filename, strlen(filename));
+
+		node_blkaddr = alloc_next_free_block(CURSEG_COLD_NODE);
+		F2FS_NODE_FOOTER(raw_node)->next_blkaddr =
+			cpu_to_le32(node_blkaddr + 1);
+
+		allocate_blocks_for_aliased_device(raw_node, i);
+
+		DBG(1, "\tWriting aliased device inode (cold node), "
+				"offset 0x%x\n", node_blkaddr);
+		if (write_inode(raw_node, node_blkaddr,
+			    f2fs_io_type_to_rw_hint(CURSEG_COLD_NODE)) < 0) {
+			MSG(1, "\tError: While writing the raw_node to "
+					"disk!!!\n");
+			err = -1;
+			goto exit;
+		}
+
+		update_nat_journal(ino, node_blkaddr);
+		update_sit_journal(CURSEG_COLD_NODE);
+		update_summary_entry(CURSEG_COLD_NODE, ino, 0);
+	}
+
+exit:
+	free(raw_node);
+	return err;
+}
+
 static int f2fs_create_root_dir(void)
 {
 	enum quota_type qtype;
@@ -1607,6 +1810,15 @@ static int f2fs_create_root_dir(void)
 		}
 	}
 
+	if (c.aliased_devices) {
+		err = f2fs_write_alias_inodes();
+		if (err < 0) {
+			MSG(1, "\tError: Failed to write aliased device "
+				"inodes!!!\n");
+			goto exit;
+		}
+	}
+
 #ifndef WITH_ANDROID
 	err = f2fs_discard_obsolete_dnode();
 	if (err < 0) {
diff --git a/mkfs/f2fs_format_main.c b/mkfs/f2fs_format_main.c
index c98e73c..9407f5b 100644
--- a/mkfs/f2fs_format_main.c
+++ b/mkfs/f2fs_format_main.c
@@ -50,12 +50,13 @@ static void mkfs_usage()
 	MSG(0, "\nUsage: mkfs.f2fs [options] device [sectors]\n");
 	MSG(0, "[options]:\n");
 	MSG(0, "  -b filesystem block size [default:4096]\n");
-	MSG(0, "  -c device1[,device2,...] up to 7 additional devices, except meta device\n");
+	MSG(0, "  -c [device_name[@alias_filename]] up to 7 additional devices, except meta device\n");
 	MSG(0, "  -d debug level [default:0]\n");
 	MSG(0, "  -e [cold file ext list] e.g. \"mp3,gif,mov\"\n");
 	MSG(0, "  -E [hot file ext list] e.g. \"db\"\n");
 	MSG(0, "  -f force overwrite of the existing filesystem\n");
 	MSG(0, "  -g add default options\n");
+	MSG(0, "  -H support write hint\n");
 	MSG(0, "  -i extended node bitmap, node ratio is 20%% by default\n");
 	MSG(0, "  -l label\n");
 	MSG(0, "  -U uuid\n");
@@ -105,6 +106,9 @@ static void f2fs_show_info()
 
 	if (c.feature & F2FS_FEATURE_COMPRESSION)
 		MSG(0, "Info: Enable Compression\n");
+
+	if (c.feature & F2FS_FEATURE_DEVICE_ALIAS)
+		MSG(0, "Info: Enable device aliasing\n");
 }
 
 #if defined(ANDROID_TARGET) && defined(HAVE_SYS_UTSNAME_H)
@@ -173,7 +177,7 @@ static void add_default_options(void)
 
 static void f2fs_parse_options(int argc, char *argv[])
 {
-	static const char *option_string = "qa:b:c:C:d:e:E:g:hil:mo:O:rR:s:S:z:t:T:U:Vfw:Z:";
+	static const char *option_string = "qa:b:c:C:d:e:E:g:hHil:mo:O:rR:s:S:z:t:T:U:Vfw:Z:";
 	static const struct option long_opts[] = {
 		{ .name = "help", .has_arg = 0, .flag = NULL, .val = 'h' },
 		{ .name = NULL, .has_arg = 0, .flag = NULL, .val = 0 }
@@ -181,6 +185,7 @@ static void f2fs_parse_options(int argc, char *argv[])
 	int32_t option=0;
 	int val;
 	char *token;
+	int dev_num;
 
 	while ((option = getopt_long(argc,argv,option_string,long_opts,NULL)) != EOF) {
 		switch (option) {
@@ -200,17 +205,41 @@ static void f2fs_parse_options(int argc, char *argv[])
 			}
 			break;
 		case 'c':
-			if (c.ndevs >= MAX_DEVICES) {
+			dev_num = c.ndevs;
+
+			if (dev_num >= MAX_DEVICES) {
 				MSG(0, "Error: Too many devices\n");
 				mkfs_usage();
 			}
 
-			if (strlen(optarg) > MAX_PATH_LEN) {
-				MSG(0, "Error: device path should be less than "
-					"%d characters\n", MAX_PATH_LEN);
+			token = strtok(optarg, "@");
+			if (strlen(token) > MAX_PATH_LEN) {
+				MSG(0, "Error: device path should be equal or "
+					"less than %d characters\n",
+					MAX_PATH_LEN);
 				mkfs_usage();
 			}
-			c.devices[c.ndevs++].path = strdup(optarg);
+			c.devices[dev_num].path = strdup(token);
+			token = strtok(NULL, "");
+			if (token) {
+				if (strlen(token) > MAX_PATH_LEN) {
+					MSG(0, "Error: alias_filename should "
+						"be equal or less than %d "
+						"characters\n", MAX_PATH_LEN);
+					mkfs_usage();
+				}
+				if (strchr(token, '/')) {
+					MSG(0, "Error: alias_filename has "
+						"invalid '/' character\n");
+					mkfs_usage();
+				}
+				c.devices[dev_num].alias_filename =
+					strdup(token);
+				if (!c.aliased_devices)
+					c.feature |= F2FS_FEATURE_DEVICE_ALIAS;
+				c.aliased_devices++;
+			}
+			c.ndevs++;
 			break;
 		case 'd':
 			c.dbg_lv = atoi(optarg);
@@ -228,6 +257,10 @@ static void f2fs_parse_options(int argc, char *argv[])
 		case 'h':
 			mkfs_usage();
 			break;
+		case 'H':
+			c.need_whint = true;
+			c.whint = WRITE_LIFE_NOT_SET;
+			break;
 		case 'i':
 			c.large_nat_bitmap = 1;
 			break;
@@ -475,7 +508,7 @@ int main(int argc, char *argv[])
 		}
 		/* wipe out other FS magics mostly first 4MB space */
 		for (i = 0; i < 1024; i++)
-			if (dev_fill_block(zero_buf, i))
+			if (dev_fill_block(zero_buf, i, WRITE_LIFE_NONE))
 				break;
 		free(zero_buf);
 		if (i != 1024) {
diff --git a/mkfs/f2fs_format_utils.c b/mkfs/f2fs_format_utils.c
index 1c2003e..1a9746a 100644
--- a/mkfs/f2fs_format_utils.c
+++ b/mkfs/f2fs_format_utils.c
@@ -48,6 +48,11 @@ static int trim_device(int i)
 	uint64_t bytes = dev->total_sectors * dev->sector_size;
 	int fd = dev->fd;
 
+	if (dev->alias_filename) {
+		MSG(0, "Info: [%s] Skip Discarding as aliased\n", dev->path);
+		return 0;
+	}
+
 	stat_buf = malloc(sizeof(struct stat));
 	if (stat_buf == NULL) {
 		MSG(1, "\tError: Malloc Failed for trim_stat_buf!!!\n");
diff --git a/tools/f2fs_io/f2fs_io.c b/tools/f2fs_io/f2fs_io.c
index 94f0adf..fa01f8f 100644
--- a/tools/f2fs_io/f2fs_io.c
+++ b/tools/f2fs_io/f2fs_io.c
@@ -174,6 +174,30 @@ static void do_fsync(int argc, char **argv, const struct cmd_desc *cmd)
 	exit(0);
 }
 
+#define fdatasync_desc "fdatasync"
+#define fdatasync_help						\
+"f2fs_io fdatasync [file]\n\n"					\
+"fdatasync given the file\n"					\
+
+static void do_fdatasync(int argc, char **argv, const struct cmd_desc *cmd)
+{
+	int fd;
+
+	if (argc != 2) {
+		fputs("Excess arguments\n\n", stderr);
+		fputs(cmd->cmd_help, stderr);
+		exit(1);
+	}
+
+	fd = xopen(argv[1], O_WRONLY, 0);
+
+	if (fdatasync(fd) != 0)
+		die_errno("fdatasync failed");
+
+	printf("fdatasync a file\n");
+	exit(0);
+}
+
 #define set_verity_desc "Set fs-verity"
 #define set_verity_help					\
 "f2fs_io set_verity [file]\n\n"				\
@@ -185,7 +209,7 @@ static void do_set_verity(int argc, char **argv, const struct cmd_desc *cmd)
 	struct fsverity_enable_arg args = {.version = 1};
 
 	args.hash_algorithm = FS_VERITY_HASH_ALG_SHA256;
-	args.block_size = 4096;
+	args.block_size = F2FS_DEFAULT_BLKSIZE;
 
 	if (argc != 2) {
 		fputs("Excess arguments\n\n", stderr);
@@ -294,7 +318,8 @@ static void do_getflags(int argc, char **argv, const struct cmd_desc *cmd)
 "  casefold\n"							\
 "  compression\n"						\
 "  nocompression\n"						\
-"  noimmutable\n"
+"  immutable\n"							\
+"  nocow\n"
 
 static void do_setflags(int argc, char **argv, const struct cmd_desc *cmd)
 {
@@ -320,8 +345,10 @@ static void do_setflags(int argc, char **argv, const struct cmd_desc *cmd)
 		flag |= FS_COMPR_FL;
 	else if (!strcmp(argv[1], "nocompression"))
 		flag |= FS_NOCOMP_FL;
-	else if (!strcmp(argv[1], "noimmutable"))
-		flag &= ~FS_IMMUTABLE_FL;
+	else if (!strcmp(argv[1], "immutable"))
+		flag |= FS_IMMUTABLE_FL;
+	else if (!strcmp(argv[1], "nocow"))
+		flag |= FS_NOCOW_FL;
 
 	ret = ioctl(fd, F2FS_IOC_SETFLAGS, &flag);
 	printf("set a flag on %s ret=%d, flags=%s\n", argv[2], ret, argv[1]);
@@ -335,6 +362,8 @@ static void do_setflags(int argc, char **argv, const struct cmd_desc *cmd)
 "flag can be\n"							\
 "  compression\n"						\
 "  nocompression\n"						\
+"  immutable\n"							\
+"  nocow\n"
 
 static void do_clearflags(int argc, char **argv, const struct cmd_desc *cmd)
 {
@@ -358,6 +387,10 @@ static void do_clearflags(int argc, char **argv, const struct cmd_desc *cmd)
 		flag &= ~FS_COMPR_FL;
 	else if (!strcmp(argv[1], "nocompression"))
 		flag &= ~FS_NOCOMP_FL;
+	else if (!strcmp(argv[1], "immutable"))
+		flag &= ~FS_IMMUTABLE_FL;
+	else if (!strcmp(argv[1], "nocow"))
+		flag &= ~FS_NOCOW_FL;
 
 	ret = ioctl(fd, F2FS_IOC_SETFLAGS, &flag);
 	printf("clear a flag on %s ret=%d, flags=%s\n", argv[2], ret, argv[1]);
@@ -626,11 +659,11 @@ static void do_write_with_advice(int argc, char **argv,
 	if (bs > 1024)
 		die("Too big chunk size - limit: 4MB");
 
-	buf_size = bs * 4096;
+	buf_size = bs * F2FS_DEFAULT_BLKSIZE;
 
 	offset = atoi(argv[2]) * buf_size;
 
-	buf = aligned_xalloc(4096, buf_size);
+	buf = aligned_xalloc(F2FS_DEFAULT_BLKSIZE, buf_size);
 	count = atoi(argv[3]);
 
 	if (!strcmp(argv[4], "zero"))
@@ -809,12 +842,15 @@ static void do_write_advice(int argc, char **argv, const struct cmd_desc *cmd)
 
 #define read_desc "read data from file"
 #define read_help					\
-"f2fs_io read [chunk_size in 4kb] [offset in chunk_size] [count] [IO] [print_nbytes] [file_path]\n\n"	\
+"f2fs_io read [chunk_size in 4kb] [offset in chunk_size] [count] [IO] [advice] [print_nbytes] [file_path]\n\n"	\
 "Read data in file_path and print nbytes\n"		\
 "IO can be\n"						\
 "  buffered : buffered IO\n"				\
 "  dio      : direct IO\n"				\
 "  mmap     : mmap IO\n"				\
+"advice can be\n"					\
+" 1 : set sequential|willneed\n"			\
+" 0 : none\n"						\
 
 static void do_read(int argc, char **argv, const struct cmd_desc *cmd)
 {
@@ -827,22 +863,22 @@ static void do_read(int argc, char **argv, const struct cmd_desc *cmd)
 	u64 total_time = 0;
 	int flags = 0;
 	int do_mmap = 0;
-	int fd;
+	int fd, advice;
 
-	if (argc != 7) {
+	if (argc != 8) {
 		fputs("Excess arguments\n\n", stderr);
 		fputs(cmd->cmd_help, stderr);
 		exit(1);
 	}
 
 	bs = atoi(argv[1]);
-	if (bs > 1024)
-		die("Too big chunk size - limit: 4MB");
-	buf_size = bs * 4096;
+	if (bs > 256 * 1024)
+		die("Too big chunk size - limit: 1GB");
+	buf_size = bs * F2FS_DEFAULT_BLKSIZE;
 
 	offset = atoi(argv[2]) * buf_size;
 
-	buf = aligned_xalloc(4096, buf_size);
+	buf = aligned_xalloc(F2FS_DEFAULT_BLKSIZE, buf_size);
 
 	count = atoi(argv[3]);
 	if (!strcmp(argv[4], "dio"))
@@ -852,13 +888,24 @@ static void do_read(int argc, char **argv, const struct cmd_desc *cmd)
 	else if (strcmp(argv[4], "buffered"))
 		die("Wrong IO type");
 
-	print_bytes = atoi(argv[5]);
+	print_bytes = atoi(argv[6]);
 	if (print_bytes > buf_size)
 		die("Print_nbytes should be less then chunk_size in kb");
 
 	print_buf = xmalloc(print_bytes);
 
-	fd = xopen(argv[6], O_RDONLY | flags, 0);
+	fd = xopen(argv[7], O_RDONLY | flags, 0);
+
+	advice = atoi(argv[5]);
+	if (advice) {
+		if (posix_fadvise(fd, 0, F2FS_DEFAULT_BLKSIZE,
+				POSIX_FADV_SEQUENTIAL) != 0)
+			die_errno("fadvise failed");
+		if (posix_fadvise(fd, 0, F2FS_DEFAULT_BLKSIZE,
+				POSIX_FADV_WILLNEED) != 0)
+			die_errno("fadvise failed");
+		printf("fadvise SEQUENTIAL|WILLNEED to a file: %s\n", argv[7]);
+	}
 
 	total_time = get_current_us();
 	if (do_mmap) {
@@ -888,8 +935,9 @@ static void do_read(int argc, char **argv, const struct cmd_desc *cmd)
 		read_cnt = count * buf_size;
 		memcpy(print_buf, data, print_bytes);
 	}
-	printf("Read %"PRIu64" bytes total_time = %"PRIu64" us, print %u bytes:\n",
-		read_cnt, get_current_us() - total_time, print_bytes);
+	printf("Read %"PRIu64" bytes total_time = %"PRIu64" us, BW = %.Lf MB/s print %u bytes:\n",
+		read_cnt, get_current_us() - total_time,
+		((long double)read_cnt / (get_current_us() - total_time)), print_bytes);
 	printf("%08"PRIx64" : ", offset);
 	for (i = 1; i <= print_bytes; i++) {
 		printf("%02x", print_buf[i - 1]);
@@ -904,24 +952,31 @@ static void do_read(int argc, char **argv, const struct cmd_desc *cmd)
 
 #define randread_desc "random read data from file"
 #define randread_help					\
-"f2fs_io randread [chunk_size in 4kb] [count] [IO] [file_path]\n\n"	\
+"f2fs_io randread [chunk_size in 4kb] [count] [IO] [advise] [file_path]\n\n"	\
 "Do random read data in file_path\n"		\
 "IO can be\n"						\
 "  buffered : buffered IO\n"				\
 "  dio      : direct IO\n"				\
+"  mmap     : mmap IO\n"				\
+"advice can be\n"					\
+" 1 : set random|willneed\n"				\
+" 0 : none\n"						\
 
 static void do_randread(int argc, char **argv, const struct cmd_desc *cmd)
 {
 	u64 buf_size = 0, ret = 0, read_cnt = 0;
 	u64 idx, end_idx, aligned_size;
 	char *buf = NULL;
-	unsigned bs, count, i;
+	char *data;
+	unsigned bs, count, i, j;
+	u64 total_time = 0, elapsed_time = 0;
 	int flags = 0;
-	int fd;
+	int do_mmap = 0;
+	int fd, advice;
 	time_t t;
 	struct stat stbuf;
 
-	if (argc != 5) {
+	if (argc != 6) {
 		fputs("Excess arguments\n\n", stderr);
 		fputs(cmd->cmd_help, stderr);
 		exit(1);
@@ -930,38 +985,69 @@ static void do_randread(int argc, char **argv, const struct cmd_desc *cmd)
 	bs = atoi(argv[1]);
 	if (bs > 1024)
 		die("Too big chunk size - limit: 4MB");
-	buf_size = bs * 4096;
+	buf_size = bs * F2FS_DEFAULT_BLKSIZE;
 
-	buf = aligned_xalloc(4096, buf_size);
+	buf = aligned_xalloc(F2FS_DEFAULT_BLKSIZE, buf_size);
 
 	count = atoi(argv[2]);
 	if (!strcmp(argv[3], "dio"))
 		flags |= O_DIRECT;
+	else if (!strcmp(argv[3], "mmap"))
+		do_mmap = 1;
 	else if (strcmp(argv[3], "buffered"))
 		die("Wrong IO type");
 
-	fd = xopen(argv[4], O_RDONLY | flags, 0);
+	fd = xopen(argv[5], O_RDONLY | flags, 0);
+
+	advice = atoi(argv[4]);
+	if (advice) {
+		if (posix_fadvise(fd, 0, stbuf.st_size, POSIX_FADV_RANDOM) != 0)
+			die_errno("fadvise failed");
+		if (posix_fadvise(fd, 0, 4096, POSIX_FADV_WILLNEED) != 0)
+			die_errno("fadvise failed");
+		printf("fadvise RANDOM|WILLNEED to a file: %s\n", argv[5]);
+	}
 
 	if (fstat(fd, &stbuf) != 0)
 		die_errno("fstat of source file failed");
 
-	aligned_size = (u64)stbuf.st_size & ~((u64)(4096 - 1));
+	aligned_size = (u64)stbuf.st_size & ~((u64)(F2FS_DEFAULT_BLKSIZE - 1));
 	if (aligned_size < buf_size)
 		die("File is too small to random read");
-	end_idx = (u64)(aligned_size - buf_size) / (u64)4096 + 1;
+	end_idx = (u64)(aligned_size - buf_size) / (u64)F2FS_DEFAULT_BLKSIZE + 1;
+
+	if (do_mmap) {
+		data = mmap(NULL, stbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
+		if (data == MAP_FAILED)
+			die("Mmap failed");
+		if (madvise((void *)data, stbuf.st_size, MADV_RANDOM) != 0)
+			die_errno("madvise failed");
+	}
 
 	srand((unsigned) time(&t));
 
+	total_time = get_current_us();
+
 	for (i = 0; i < count; i++) {
 		idx = rand() % end_idx;
 
-		ret = pread(fd, buf, buf_size, 4096 * idx);
-		if (ret != buf_size)
-			break;
-
-		read_cnt += ret;
+		if (!do_mmap) {
+			ret = pread(fd, buf, buf_size, 4096 * idx);
+			if (ret != buf_size)
+				break;
+		} else {
+			for (j = 0; j < bs; j++)
+				*buf = data[4096 * (idx + j)];
+		}
+		read_cnt += buf_size;
 	}
-	printf("Read %"PRIu64" bytes\n", read_cnt);
+	elapsed_time = get_current_us() - total_time;
+
+	printf("Read %"PRIu64" bytes total_time = %"PRIu64" us, avg. latency = %.Lf us, IOPs= %.Lf, BW = %.Lf MB/s\n",
+		read_cnt, elapsed_time,
+		(long double)elapsed_time / count,
+		(long double)count * 1000 * 1000 / elapsed_time,
+		(long double)read_cnt / elapsed_time);
 	exit(0);
 }
 
@@ -985,15 +1071,16 @@ static void do_fiemap(int argc, char **argv, const struct cmd_desc *cmd)
 	}
 
 	memset(fm, 0, sizeof(struct fiemap));
-	start = (u64)atoi(argv[1]) * F2FS_BLKSIZE;
-	length = (u64)atoi(argv[2]) * F2FS_BLKSIZE;
+	start = (u64)atoi(argv[1]) * F2FS_DEFAULT_BLKSIZE;
+	length = (u64)atoi(argv[2]) * F2FS_DEFAULT_BLKSIZE;
 	fm->fm_start = start;
 	fm->fm_length = length;
 
 	fd = xopen(argv[3], O_RDONLY | O_LARGEFILE, 0);
 
 	printf("Fiemap: offset = %"PRIu64" len = %"PRIu64"\n",
-				start / F2FS_BLKSIZE, length / F2FS_BLKSIZE);
+				start / F2FS_DEFAULT_BLKSIZE,
+				length / F2FS_DEFAULT_BLKSIZE);
 	if (ioctl(fd, FS_IOC_FIEMAP, fm) < 0)
 		die_errno("FIEMAP failed");
 
@@ -1173,9 +1260,9 @@ static void do_copy(int argc, char **argv, const struct cmd_desc *cmd)
 		if (ret < 0)
 			die_errno("sendfile failed");
 	} else {
-		char *buf = aligned_xalloc(4096, 4096);
+		char *buf = aligned_xalloc(F2FS_DEFAULT_BLKSIZE, F2FS_DEFAULT_BLKSIZE);
 
-		while ((ret = xread(src_fd, buf, 4096)) > 0)
+		while ((ret = xread(src_fd, buf, F2FS_DEFAULT_BLKSIZE)) > 0)
 			full_write(dst_fd, buf, ret);
 		free(buf);
 	}
@@ -1808,6 +1895,7 @@ static void do_help(int argc, char **argv, const struct cmd_desc *cmd);
 const struct cmd_desc cmd_list[] = {
 	_CMD(help),
 	CMD(fsync),
+	CMD(fdatasync),
 	CMD(set_verity),
 	CMD(getflags),
 	CMD(setflags),
diff --git a/tools/f2fs_io/f2fs_io.h b/tools/f2fs_io/f2fs_io.h
index e55db5f..14c9dc1 100644
--- a/tools/f2fs_io/f2fs_io.h
+++ b/tools/f2fs_io/f2fs_io.h
@@ -48,7 +48,7 @@ typedef u16	__be16;
 typedef u32	__be32;
 #endif
 
-#define F2FS_BLKSIZE	4096
+#define F2FS_DEFAULT_BLKSIZE	4096
 #define NEW_ADDR	0xFFFFFFFF
 
 #ifndef FS_IOC_GETFLAGS
```

