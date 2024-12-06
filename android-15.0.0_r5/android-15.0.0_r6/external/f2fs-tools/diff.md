```diff
diff --git a/Android.bp b/Android.bp
index 1ef0bda..82df238 100644
--- a/Android.bp
+++ b/Android.bp
@@ -47,6 +47,7 @@ cc_defaults {
         "-DF2FS_TOOLS_VERSION=\"1.16.0\"",
         "-DF2FS_TOOLS_DATE=\"2023-04-11\"",
         "-DWITH_ANDROID",
+        "-D_FILE_OFFSET_BITS=64",
         "-Wall",
         "-Werror",
         "-Wno-macro-redefined",
@@ -208,24 +209,52 @@ cc_binary_host {
     stl: "libc++_static",
 }
 
+cc_defaults {
+    name: "fsck.f2fs_defaults",
+    defaults: [
+        "f2fs-tools-defaults",
+        "fsck_main_src_files",
+    ],
+    cflags: ["-DWITH_RESIZE", "-DWITH_DEFRAG", "-DWITH_DUMP"],
+    srcs: ["fsck/fsck.c", "fsck/resize.c", "fsck/defrag.c"],
+}
+
 cc_binary {
     name: "fsck.f2fs",
     defaults: [
         "f2fs-tools-defaults",
         "fsck_main_src_files",
+        "fsck.f2fs_defaults",
     ],
     host_supported: true,
     vendor_available: true,
     recovery_available: true,
-    cflags: ["-DWITH_RESIZE", "-DWITH_DEFRAG", "-DWITH_DUMP"],
-    srcs: ["fsck/fsck.c", "fsck/resize.c", "fsck/defrag.c"],
+    symlinks: ["resize.f2fs", "defrag.f2fs", "dump.f2fs"],
+    vendor_ramdisk_available: true,
     shared_libs: [
         "libext2_uuid",
         "libsparse",
         "libbase",
     ],
-    symlinks: ["resize.f2fs", "defrag.f2fs", "dump.f2fs"],
-    vendor_ramdisk_available: true,
+    bootstrap: true,
+}
+
+cc_binary {
+    name: "fsck.f2fs_ramdisk",
+    stem: "fsck.f2fs",
+    defaults: [
+        "f2fs-tools-defaults",
+        "fsck_main_src_files",
+        "fsck.f2fs_defaults",
+    ],
+    static_executable: true,
+    ramdisk: true,
+    static_libs: [
+        "libbase",
+        "libext2_uuid",
+        "libsparse",
+        "libz",
+    ],
 }
 
 cc_binary {
diff --git a/METADATA b/METADATA
index ea3542f..b35d533 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/f2fs-tools
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "f2fs-tools"
 description: "F2FS filesystem tools"
@@ -8,13 +8,13 @@ third_party {
   license_type: RESTRICTED
   last_upgrade_date {
     year: 2024
-    month: 5
-    day: 24
+    month: 8
+    day: 16
   }
   homepage: "https://git.kernel.org/pub/scm/linux/kernel/git/jaegeuk/f2fs-tools.git/"
   identifier {
     type: "Git"
     value: "https://git.kernel.org/pub/scm/linux/kernel/git/jaegeuk/f2fs-tools.git"
-    version: "c1a97862b05d8a736ad8719939395c61bd71c982"
+    version: "b9a68f381b3447b8df10102757a34431cc2b2eb6"
   }
 }
diff --git a/fsck/Makefile.am b/fsck/Makefile.am
index 40d31b8..ea3b26a 100644
--- a/fsck/Makefile.am
+++ b/fsck/Makefile.am
@@ -4,11 +4,12 @@ AM_CPPFLAGS = ${libuuid_CFLAGS} -I$(top_srcdir)/include
 AM_CFLAGS = -Wall -D_FILE_OFFSET_BITS=64
 sbin_PROGRAMS = fsck.f2fs
 noinst_HEADERS = common.h dict.h dqblk_v2.h f2fs.h fsck.h node.h quotaio.h \
-		quotaio_tree.h quotaio_v2.h xattr.h compress.h
+		quotaio_tree.h quotaio_v2.h xattr.h compress.h inject.h
 include_HEADERS = $(top_srcdir)/include/quota.h
 fsck_f2fs_SOURCES = main.c fsck.c dump.c mount.c defrag.c resize.c \
 		node.c segment.c dir.c sload.c xattr.c compress.c \
-		dict.c mkquota.c quotaio.c quotaio_tree.c quotaio_v2.c
+		dict.c mkquota.c quotaio.c quotaio_tree.c quotaio_v2.c \
+		inject.c
 fsck_f2fs_LDADD = ${libselinux_LIBS} ${libuuid_LIBS} \
 	${liblzo2_LIBS} ${liblz4_LIBS} ${libwinpthread_LIBS} \
 	$(top_builddir)/lib/libf2fs.la
@@ -19,3 +20,4 @@ install-data-hook:
 	ln -sf fsck.f2fs $(DESTDIR)/$(sbindir)/resize.f2fs
 	ln -sf fsck.f2fs $(DESTDIR)/$(sbindir)/sload.f2fs
 	ln -sf fsck.f2fs $(DESTDIR)/$(sbindir)/f2fslabel
+	ln -sf fsck.f2fs $(DESTDIR)/$(sbindir)/inject.f2fs
diff --git a/fsck/dump.c b/fsck/dump.c
index 90e3e0e..448c0ef 100644
--- a/fsck/dump.c
+++ b/fsck/dump.c
@@ -21,7 +21,7 @@
 #endif
 #include <locale.h>
 
-#define BUF_SZ	80
+#define BUF_SZ	128
 
 /* current extent info */
 struct extent_info dump_extent;
@@ -38,6 +38,7 @@ void nat_dump(struct f2fs_sb_info *sbi, nid_t start_nat, nid_t end_nat)
 {
 	struct f2fs_nat_block *nat_block;
 	struct f2fs_node *node_block;
+	struct node_footer *footer;
 	nid_t nid;
 	pgoff_t block_addr;
 	char buf[BUF_SZ];
@@ -47,6 +48,7 @@ void nat_dump(struct f2fs_sb_info *sbi, nid_t start_nat, nid_t end_nat)
 	ASSERT(nat_block);
 	node_block = (struct f2fs_node *)calloc(F2FS_BLKSIZE, 1);
 	ASSERT(node_block);
+	footer = F2FS_NODE_FOOTER(node_block);
 
 	fd = open("dump_nat", O_CREAT|O_WRONLY|O_TRUNC, 0666);
 	ASSERT(fd >= 0);
@@ -54,6 +56,7 @@ void nat_dump(struct f2fs_sb_info *sbi, nid_t start_nat, nid_t end_nat)
 	for (nid = start_nat; nid < end_nat; nid++) {
 		struct f2fs_nat_entry raw_nat;
 		struct node_info ni;
+		int len;
 		if(nid == 0 || nid == F2FS_NODE_INO(sbi) ||
 					nid == F2FS_META_INO(sbi))
 			continue;
@@ -66,15 +69,15 @@ void nat_dump(struct f2fs_sb_info *sbi, nid_t start_nat, nid_t end_nat)
 			ret = dev_read_block(node_block, ni.blk_addr);
 			ASSERT(ret >= 0);
 			if (ni.blk_addr != 0x0) {
-				memset(buf, 0, BUF_SZ);
-				snprintf(buf, BUF_SZ,
+				len = snprintf(buf, BUF_SZ,
 					"nid:%5u\tino:%5u\toffset:%5u"
-					"\tblkaddr:%10u\tpack:%d\n",
+					"\tblkaddr:%10u\tpack:%d"
+					"\tcp_ver:0x%" PRIx64 "\n",
 					ni.nid, ni.ino,
-					le32_to_cpu(F2FS_NODE_FOOTER(node_block)->flag) >>
-						OFFSET_BIT_SHIFT,
-					ni.blk_addr, pack);
-				ret = write(fd, buf, strlen(buf));
+					le32_to_cpu(footer->flag) >> OFFSET_BIT_SHIFT,
+					ni.blk_addr, pack,
+					le64_to_cpu(footer->cp_ver));
+				ret = write(fd, buf, len);
 				ASSERT(ret >= 0);
 			}
 		} else {
@@ -87,15 +90,15 @@ void nat_dump(struct f2fs_sb_info *sbi, nid_t start_nat, nid_t end_nat)
 
 			ret = dev_read_block(node_block, ni.blk_addr);
 			ASSERT(ret >= 0);
-			memset(buf, 0, BUF_SZ);
-			snprintf(buf, BUF_SZ,
+			len = snprintf(buf, BUF_SZ,
 				"nid:%5u\tino:%5u\toffset:%5u"
-				"\tblkaddr:%10u\tpack:%d\n",
+				"\tblkaddr:%10u\tpack:%d"
+				"\tcp_ver:0x%" PRIx64 "\n",
 				ni.nid, ni.ino,
-				le32_to_cpu(F2FS_NODE_FOOTER(node_block)->flag) >>
-					OFFSET_BIT_SHIFT,
-				ni.blk_addr, pack);
-			ret = write(fd, buf, strlen(buf));
+				le32_to_cpu(footer->flag) >> OFFSET_BIT_SHIFT,
+				ni.blk_addr, pack,
+				le64_to_cpu(footer->cp_ver));
+			ret = write(fd, buf, len);
 			ASSERT(ret >= 0);
 		}
 	}
@@ -253,20 +256,27 @@ static void dump_folder_contents(struct f2fs_sb_info *sbi, u8 *bitmap,
 {
 	int i;
 	int name_len;
+	char name[F2FS_NAME_LEN + 1] = {0};
 
 	for (i = 0; i < max; i++) {
 		if (test_bit_le(i, bitmap) == 0)
 			continue;
 		name_len = le16_to_cpu(dentry[i].name_len);
+		if (name_len == 0 || name_len > F2FS_NAME_LEN) {
+			MSG(c.force, "Wrong name info\n\n");
+			ASSERT(name_len == 0 || name_len > F2FS_NAME_LEN);
+		}
 		if (name_len == 1 && filenames[i][0] == '.')
 			continue;
 		if (name_len == 2 && filenames[i][0] == '.' && filenames[i][1] == '.')
 			continue;
-		dump_node(sbi, le32_to_cpu(dentry[i].ino), 1, NULL, 0, 1);
+		strncpy(name, (const char *)filenames[i], name_len);
+		name[name_len] = 0;
+		dump_node(sbi, le32_to_cpu(dentry[i].ino), 1, NULL, 0, 1, name);
 	}
 }
 
-static void dump_data_blk(struct f2fs_sb_info *sbi, __u64 offset, u32 blkaddr, bool is_folder)
+static void dump_data_blk(struct f2fs_sb_info *sbi, __u64 offset, u32 blkaddr, int type)
 {
 	char buf[F2FS_BLKSIZE];
 
@@ -307,11 +317,15 @@ static void dump_data_blk(struct f2fs_sb_info *sbi, __u64 offset, u32 blkaddr, b
 		ASSERT(ret >= 0);
 	}
 
-	if (is_folder) {
+	if (S_ISDIR(type)) {
 		struct f2fs_dentry_block *d = (struct f2fs_dentry_block *) buf;
 
 		dump_folder_contents(sbi, d->dentry_bitmap, F2FS_DENTRY_BLOCK_DENTRIES(d),
 					F2FS_DENTRY_BLOCK_FILENAMES(d), NR_DENTRY_IN_BLOCK);
+#if !defined(__MINGW32__)
+	} if (S_ISLNK(type)) {
+		dev_write_symlink(buf, c.dump_sym_target_len);
+#endif
 	} else {
 		/* write blkaddr */
 		dev_write_dump(buf, offset, F2FS_BLKSIZE);
@@ -319,7 +333,7 @@ static void dump_data_blk(struct f2fs_sb_info *sbi, __u64 offset, u32 blkaddr, b
 }
 
 static void dump_node_blk(struct f2fs_sb_info *sbi, int ntype,
-				u32 nid, u32 addr_per_block, u64 *ofs, int is_dir)
+				u32 nid, u32 addr_per_block, u64 *ofs, int type)
 {
 	struct node_info ni;
 	struct f2fs_node *node_blk;
@@ -356,20 +370,20 @@ static void dump_node_blk(struct f2fs_sb_info *sbi, int ntype,
 		switch (ntype) {
 		case TYPE_DIRECT_NODE:
 			dump_data_blk(sbi, *ofs * F2FS_BLKSIZE,
-					le32_to_cpu(node_blk->dn.addr[i]), is_dir);
+					le32_to_cpu(node_blk->dn.addr[i]), type);
 			(*ofs)++;
 			break;
 		case TYPE_INDIRECT_NODE:
 			dump_node_blk(sbi, TYPE_DIRECT_NODE,
 					le32_to_cpu(node_blk->in.nid[i]),
 					addr_per_block,
-					ofs, is_dir);
+					ofs, type);
 			break;
 		case TYPE_DOUBLE_INDIRECT_NODE:
 			dump_node_blk(sbi, TYPE_INDIRECT_NODE,
 					le32_to_cpu(node_blk->in.nid[i]),
 					addr_per_block,
-					ofs, is_dir);
+					ofs, type);
 			break;
 		}
 	}
@@ -377,7 +391,7 @@ static void dump_node_blk(struct f2fs_sb_info *sbi, int ntype,
 }
 
 #ifdef HAVE_FSETXATTR
-static void dump_xattr(struct f2fs_sb_info *sbi, struct f2fs_node *node_blk, int is_dir)
+static void dump_xattr(struct f2fs_sb_info *sbi, struct f2fs_node *node_blk, int type)
 {
 	void *xattr;
 	void *last_base_addr;
@@ -431,19 +445,26 @@ static void dump_xattr(struct f2fs_sb_info *sbi, struct f2fs_node *node_blk, int
 
 		DBG(1, "fd %d xattr_name %s\n", c.dump_fd, xattr_name);
 #if defined(__linux__)
-		if (is_dir) {
+		if (S_ISDIR(type)) {
 			ret = setxattr(".", xattr_name, value,
 							le16_to_cpu(ent->e_value_size), 0);
+		} if (S_ISLNK(type) && c.preserve_symlinks) {
+			ret = lsetxattr(c.dump_symlink, xattr_name, value,
+							le16_to_cpu(ent->e_value_size), 0);
 		} else {
 			ret = fsetxattr(c.dump_fd, xattr_name, value,
 							le16_to_cpu(ent->e_value_size), 0);
 		}
 
 #elif defined(__APPLE__)
-		if (is_dir) {
+		if (S_ISDIR(type)) {
 			ret = setxattr(".", xattr_name, value,
 					le16_to_cpu(ent->e_value_size), 0,
 					XATTR_CREATE);
+		} if (S_ISLNK(type) && c.preserve_symlinks) {
+			ret = lsetxattr(c.dump_symlink, xattr_name, value,
+					le16_to_cpu(ent->e_value_size), 0,
+					XATTR_CREATE);
 		} else {
 			ret = fsetxattr(c.dump_fd, xattr_name, value,
 					le16_to_cpu(ent->e_value_size), 0,
@@ -473,14 +494,21 @@ static int dump_inode_blk(struct f2fs_sb_info *sbi, u32 nid,
 	u32 i = 0;
 	u64 ofs = 0;
 	u32 addr_per_block;
-	bool is_dir = S_ISDIR(le16_to_cpu(node_blk->i.i_mode));
+	u16 type = le16_to_cpu(node_blk->i.i_mode);
 	int ret = 0;
 
 	if ((node_blk->i.i_inline & F2FS_INLINE_DATA)) {
 		DBG(3, "ino[0x%x] has inline data!\n", nid);
 		/* recover from inline data */
-		dev_write_dump(((unsigned char *)node_blk) + INLINE_DATA_OFFSET,
+#if !defined(__MINGW32__)
+		if (S_ISLNK(type) && c.preserve_symlinks) {
+			dev_write_symlink(inline_data_addr(node_blk), c.dump_sym_target_len);
+		} else
+#endif
+		{
+			dev_write_dump(inline_data_addr(node_blk),
 						0, MAX_INLINE_DATA(node_blk));
+		}
 		ret = -1;
 		goto dump_xattr;
 	}
@@ -504,7 +532,7 @@ static int dump_inode_blk(struct f2fs_sb_info *sbi, u32 nid,
 	/* check data blocks in inode */
 	for (i = 0; i < ADDRS_PER_INODE(&node_blk->i); i++, ofs++)
 		dump_data_blk(sbi, ofs * F2FS_BLKSIZE, le32_to_cpu(
-			node_blk->i.i_addr[get_extra_isize(node_blk) + i]), is_dir);
+			node_blk->i.i_addr[get_extra_isize(node_blk) + i]), type);
 
 	/* check node blocks in inode */
 	for (i = 0; i < 5; i++) {
@@ -513,26 +541,26 @@ static int dump_inode_blk(struct f2fs_sb_info *sbi, u32 nid,
 					le32_to_cpu(F2FS_INODE_I_NID(&node_blk->i, i)),
 					addr_per_block,
 					&ofs,
-					is_dir);
+					type);
 		else if (i == 2 || i == 3)
 			dump_node_blk(sbi, TYPE_INDIRECT_NODE,
 					le32_to_cpu(F2FS_INODE_I_NID(&node_blk->i, i)),
 					addr_per_block,
 					&ofs,
-					is_dir);
+					type);
 		else if (i == 4)
 			dump_node_blk(sbi, TYPE_DOUBLE_INDIRECT_NODE,
 					le32_to_cpu(F2FS_INODE_I_NID(&node_blk->i, i)),
 					addr_per_block,
 					&ofs,
-					is_dir);
+					type);
 		else
 			ASSERT(0);
 	}
 	/* last block in extent cache */
 	print_extent(true);
 dump_xattr:
-	dump_xattr(sbi, node_blk, is_dir);
+	dump_xattr(sbi, node_blk, type);
 	return ret;
 }
 
@@ -555,6 +583,23 @@ static void dump_file(struct f2fs_sb_info *sbi, struct node_info *ni,
 	close(c.dump_fd);
 }
 
+static void dump_link(struct f2fs_sb_info *sbi, struct node_info *ni,
+				struct f2fs_node *node_blk, char *name)
+{
+#if defined(__MINGW32__)
+	dump_file(sbi, ni, node_blk, name);
+#else
+	struct f2fs_inode *inode = &node_blk->i;
+	int len = le64_to_cpu(inode->i_size);
+
+	if (!c.preserve_symlinks)
+		return dump_file(sbi, ni, node_blk, name);
+	c.dump_symlink = name;
+	c.dump_sym_target_len = len + 1;
+	dump_inode_blk(sbi, ni->ino, node_blk);
+#endif
+}
+
 static void dump_folder(struct f2fs_sb_info *sbi, struct node_info *ni,
 				struct f2fs_node *node_blk, char *path, int is_root)
 {
@@ -580,18 +625,24 @@ static void dump_folder(struct f2fs_sb_info *sbi, struct node_info *ni,
 
 static int dump_filesystem(struct f2fs_sb_info *sbi, struct node_info *ni,
 				struct f2fs_node *node_blk, int force, char *base_path,
-				bool is_base, bool allow_folder)
+				bool is_base, bool allow_folder, char *dirent_name)
 {
 	struct f2fs_inode *inode = &node_blk->i;
 	u32 imode = le16_to_cpu(inode->i_mode);
-	u32 namelen = le32_to_cpu(inode->i_namelen);
-	char name[F2FS_NAME_LEN + 1] = {0};
+	u32 ilinks = le32_to_cpu(inode->i_links);
+	u32 i_namelen = le32_to_cpu(inode->i_namelen);
+	char i_name[F2FS_NAME_LEN + 1] = {0};
+	char *name = NULL;
 	char path[1024] = {0};
 	char ans[255] = {0};
 	int is_encrypted = file_is_encrypt(inode);
 	int is_root = sbi->root_ino_num == ni->nid;
 	int ret;
 
+	if (!S_ISDIR(imode) && ilinks != 1) {
+		MSG(force, "Warning: Hard link detected. Dumped files may be duplicated\n");
+	}
+
 	if (is_encrypted) {
 		MSG(force, "File is encrypted\n");
 		return -1;
@@ -601,10 +652,14 @@ static int dump_filesystem(struct f2fs_sb_info *sbi, struct node_info *ni,
 		MSG(force, "Not a valid file type\n\n");
 		return -1;
 	}
-	if (!is_root && (namelen == 0 || namelen > F2FS_NAME_LEN)) {
+	if (!is_root && !dirent_name && (i_namelen == 0 || i_namelen > F2FS_NAME_LEN)) {
 		MSG(force, "Wrong name info\n\n");
 		return -1;
 	}
+	if (le32_to_cpu(inode->i_flags) & F2FS_NODUMP_FL) {
+		MSG(force, "File has nodump flag\n\n");
+		return -1;
+	}
 	base_path = base_path ?: "./lost_found";
 	if (force)
 		goto dump;
@@ -614,7 +669,7 @@ static int dump_filesystem(struct f2fs_sb_info *sbi, struct node_info *ni,
 		return dump_inode_blk(sbi, ni->ino, node_blk);
 
 	printf("Do you want to dump this %s into %s/? [Y/N] ",
-			S_ISREG(imode) || S_ISLNK(imode) ? "file" : "folder",
+			S_ISDIR(imode) ? "folder" : "file",
 			base_path);
 	ret = scanf("%s", ans);
 	ASSERT(ret >= 0);
@@ -635,23 +690,34 @@ dump:
 
 		/* make a file */
 		if (!is_root) {
-			strncpy(name, (const char *)inode->i_name, namelen);
-			name[namelen] = 0;
+			/* The i_name name may be out of date. Prefer dirent_name */
+			if (dirent_name) {
+				name = dirent_name;
+			} else  {
+				strncpy(i_name, (const char *)inode->i_name, i_namelen);
+				i_name[i_namelen] = 0;
+				name = i_name;
+			}
 		}
 
-		if (S_ISREG(imode) || S_ISLNK(imode)) {
+		if (S_ISREG(imode)) {
 			dump_file(sbi, ni, node_blk, name);
-		} else {
+		} else if (S_ISDIR(imode)) {
 			dump_folder(sbi, ni, node_blk, name, is_root);
+		} else {
+			dump_link(sbi, ni, node_blk, name);
 		}
 
 #if !defined(__MINGW32__)
 		/* fix up mode/owner */
 		if (c.preserve_perms) {
-			if (is_root)
+			if (is_root) {
+				name = i_name;
 				strncpy(name, ".", 2);
-			ASSERT(chmod(name, imode) == 0);
-			ASSERT(chown(name, inode->i_uid, inode->i_gid) == 0);
+			}
+			if (!S_ISLNK(imode))
+				ASSERT(chmod(name, imode) == 0);
+			ASSERT(lchown(name, inode->i_uid, inode->i_gid) == 0);
 		}
 #endif
 		if (is_base)
@@ -660,7 +726,7 @@ dump:
 	return 0;
 }
 
-static bool is_sit_bitmap_set(struct f2fs_sb_info *sbi, u32 blk_addr)
+bool is_sit_bitmap_set(struct f2fs_sb_info *sbi, u32 blk_addr)
 {
 	struct seg_entry *se;
 	u32 offset;
@@ -705,7 +771,7 @@ void dump_node_scan_disk(struct f2fs_sb_info *sbi, nid_t nid)
 	free(node_blk);
 }
 
-int dump_node(struct f2fs_sb_info *sbi, nid_t nid, int force, char *base_path, int base, int allow_folder)
+int dump_node(struct f2fs_sb_info *sbi, nid_t nid, int force, char *base_path, int base, int allow_folder, char *dirent_name)
 {
 	struct node_info ni;
 	struct f2fs_node *node_blk;
@@ -740,7 +806,7 @@ int dump_node(struct f2fs_sb_info *sbi, nid_t nid, int force, char *base_path, i
 			print_node_info(sbi, node_blk, force);
 
 		if (ni.ino == ni.nid)
-			ret = dump_filesystem(sbi, &ni, node_blk, force, base_path, base, allow_folder);
+			ret = dump_filesystem(sbi, &ni, node_blk, force, base_path, base, allow_folder, dirent_name);
 	} else {
 		print_node_info(sbi, node_blk, force);
 		MSG(force, "Invalid (i)node block\n\n");
diff --git a/fsck/fsck.c b/fsck/fsck.c
index 7400dcf..a18bee9 100644
--- a/fsck/fsck.c
+++ b/fsck/fsck.c
@@ -633,18 +633,6 @@ err:
 	return -EINVAL;
 }
 
-static bool is_sit_bitmap_set(struct f2fs_sb_info *sbi, u32 blk_addr)
-{
-	struct seg_entry *se;
-	u32 offset;
-
-	se = get_seg_entry(sbi, GET_SEGNO(sbi, blk_addr));
-	offset = OFFSET_IN_SEG(sbi, blk_addr);
-
-	return f2fs_test_bit(offset,
-			(const char *)se->cur_valid_map) != 0;
-}
-
 int fsck_chk_root_inode(struct f2fs_sb_info *sbi)
 {
 	struct f2fs_node *node_blk;
@@ -924,14 +912,14 @@ void fsck_chk_inode_blk(struct f2fs_sb_info *sbi, u32 nid,
 		 * the node tree.  Thus, it must be fixed unconditionally
 		 * in the memory (node_blk).
 		 */
-		node_blk->i.i_flags &= ~cpu_to_le32(F2FS_COMPR_FL);
+		i_flags &= ~F2FS_COMPR_FL;
 		compressed = false;
 		if (c.fix_on) {
 			need_fix = 1;
 			FIX_MSG("[0x%x] i_flags=0x%x -> 0x%x",
-					nid, i_flags, node_blk->i.i_flags);
+					nid, node_blk->i.i_flags, i_flags);
 		}
-		i_flags &= ~F2FS_COMPR_FL;
+		node_blk->i.i_flags = cpu_to_le32(i_flags);
 	}
 check_next:
 	memset(&child, 0, sizeof(child));
@@ -1057,7 +1045,8 @@ check_next:
 		ASSERT_MSG("[0x%x] unexpected casefold flag", nid);
 		if (c.fix_on) {
 			FIX_MSG("ino[0x%x] clear casefold flag", nid);
-			node_blk->i.i_flags &= ~cpu_to_le32(F2FS_CASEFOLD_FL);
+			i_flags &= ~F2FS_CASEFOLD_FL;
+			node_blk->i.i_flags = cpu_to_le32(i_flags);
 			need_fix = 1;
 		}
 	}
@@ -1093,10 +1082,7 @@ check_next:
 			}
 		}
 		if (!(node_blk->i.i_inline & F2FS_DATA_EXIST)) {
-			char buf[MAX_INLINE_DATA(node_blk)];
-			memset(buf, 0, MAX_INLINE_DATA(node_blk));
-
-			if (memcmp(buf, inline_data_addr(node_blk),
+			if (!is_zeroed(inline_data_addr(node_blk),
 						MAX_INLINE_DATA(node_blk))) {
 				ASSERT_MSG("[0x%x] junk inline data", nid);
 				if (c.fix_on) {
@@ -1651,7 +1637,7 @@ static void print_dentry(struct f2fs_sb_info *sbi, __u8 *name,
 			d = d->next;
 		}
 		printf("/%s", new);
-		if (dump_node(sbi, le32_to_cpu(dentry[idx].ino), 0, NULL, 0, 0))
+		if (dump_node(sbi, le32_to_cpu(dentry[idx].ino), 0, NULL, 0, 0, NULL))
 			printf("\33[2K\r");
 	} else {
 		for (i = 1; i < depth; i++)
@@ -3366,7 +3352,7 @@ static void fix_wp_sit_alignment(struct f2fs_sb_info *sbi)
 		if (!c.devices[i].path)
 			break;
 		if (c.devices[i].zoned_model != F2FS_ZONED_HM)
-			break;
+			continue;
 
 		wpd.dev_index = i;
 		if (f2fs_report_zones(i, chk_and_fix_wp_with_sit, &wpd)) {
@@ -3632,7 +3618,7 @@ int fsck_verify(struct f2fs_sb_info *sbi)
 		if (!strcasecmp(ans, "y")) {
 			for (i = 0; i < fsck->nr_nat_entries; i++) {
 				if (f2fs_test_bit(i, fsck->nat_area_bitmap))
-					dump_node(sbi, i, 1, NULL, 1, 0);
+					dump_node(sbi, i, 1, NULL, 1, 0, NULL);
 			}
 		}
 	}
@@ -3676,13 +3662,13 @@ int fsck_verify(struct f2fs_sb_info *sbi)
 			write_checkpoints(sbi);
 		}
 
-		if (c.abnormal_stop)
+		if (c.invalid_sb & SB_ABNORMAL_STOP)
 			memset(sb->s_stop_reason, 0, MAX_STOP_REASON);
 
-		if (c.fs_errors)
+		if (c.invalid_sb & SB_FS_ERRORS)
 			memset(sb->s_errors, 0, MAX_F2FS_ERRORS);
 
-		if (c.abnormal_stop || c.fs_errors)
+		if (c.invalid_sb & SB_NEED_FIX)
 			update_superblock(sb, SB_MASK_ALL);
 
 		/* to return FSCK_ERROR_CORRECTED */
diff --git a/fsck/fsck.h b/fsck/fsck.h
index 6cac926..a8f187e 100644
--- a/fsck/fsck.h
+++ b/fsck/fsck.h
@@ -236,12 +236,15 @@ extern int find_next_free_block(struct f2fs_sb_info *, u64 *, int, int, bool);
 extern void duplicate_checkpoint(struct f2fs_sb_info *);
 extern void write_checkpoint(struct f2fs_sb_info *);
 extern void write_checkpoints(struct f2fs_sb_info *);
+extern void write_raw_cp_blocks(struct f2fs_sb_info *sbi,
+			struct f2fs_checkpoint *cp, int which);
 extern void update_superblock(struct f2fs_super_block *, int);
 extern void update_data_blkaddr(struct f2fs_sb_info *, nid_t, u16, block_t,
 			struct f2fs_node *);
 extern void update_nat_blkaddr(struct f2fs_sb_info *, nid_t, nid_t, block_t);
 
 extern void print_raw_sb_info(struct f2fs_super_block *);
+extern void print_ckpt_info(struct f2fs_sb_info *);
 extern bool is_checkpoint_stop(struct f2fs_super_block *, bool);
 extern bool is_inconsistent_error(struct f2fs_super_block *);
 extern pgoff_t current_nat_addr(struct f2fs_sb_info *, nid_t, int *);
@@ -277,11 +280,11 @@ struct dump_option {
 extern void nat_dump(struct f2fs_sb_info *, nid_t, nid_t);
 extern void sit_dump(struct f2fs_sb_info *, unsigned int, unsigned int);
 extern void ssa_dump(struct f2fs_sb_info *, int, int);
-extern int dump_node(struct f2fs_sb_info *, nid_t, int, char *, int, int);
+extern int dump_node(struct f2fs_sb_info *, nid_t, int, char *, int, int, char *);
 extern int dump_info_from_blkaddr(struct f2fs_sb_info *, u32);
 extern unsigned int start_bidx_of_node(unsigned int, struct f2fs_node *);
 extern void dump_node_scan_disk(struct f2fs_sb_info *sbi, nid_t nid);
-
+extern bool is_sit_bitmap_set(struct f2fs_sb_info *sbi, u32 blk_addr);
 
 /* defrag.c */
 int f2fs_defragment(struct f2fs_sb_info *, u64, u64, u64, int);
@@ -353,4 +356,7 @@ int update_inode(struct f2fs_sb_info *sbi, struct f2fs_node *inode,
 int flush_nat_journal_entries(struct f2fs_sb_info *sbi);
 int flush_sit_journal_entries(struct f2fs_sb_info *sbi);
 
+/* main.c */
+int is_digits(char *optarg);
+
 #endif /* _FSCK_H_ */
diff --git a/fsck/inject.c b/fsck/inject.c
new file mode 100644
index 0000000..9dc085f
--- /dev/null
+++ b/fsck/inject.c
@@ -0,0 +1,924 @@
+/**
+ * inject.c
+ *
+ * Copyright (c) 2024 OPPO Mobile Comm Corp., Ltd.
+ *             http://www.oppo.com/
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ */
+
+#include <getopt.h>
+#include "inject.h"
+
+static void print_raw_nat_entry_info(struct f2fs_nat_entry *ne)
+{
+	if (!c.dbg_lv)
+		return;
+
+	DISP_u8(ne, version);
+	DISP_u32(ne, ino);
+	DISP_u32(ne, block_addr);
+}
+
+static void print_raw_sit_entry_info(struct f2fs_sit_entry *se)
+{
+	int i;
+
+	if (!c.dbg_lv)
+		return;
+
+	DISP_u16(se, vblocks);
+	if (c.layout)
+		printf("%-30s ", "valid_map:");
+	else
+		printf("%-30s\t\t[", "valid_map");
+	for (i = 0; i < SIT_VBLOCK_MAP_SIZE; i++)
+		printf("%02x", se->valid_map[i]);
+	if (c.layout)
+		printf("\n");
+	else
+		printf("]\n");
+	DISP_u64(se, mtime);
+}
+
+static void print_raw_sum_entry_info(struct f2fs_summary *sum)
+{
+	if (!c.dbg_lv)
+		return;
+
+	DISP_u32(sum, nid);
+	DISP_u8(sum, version);
+	DISP_u16(sum, ofs_in_node);
+}
+
+static void print_sum_footer_info(struct summary_footer *footer)
+{
+	if (!c.dbg_lv)
+		return;
+
+	DISP_u8(footer, entry_type);
+	DISP_u32(footer, check_sum);
+}
+
+static void print_node_footer_info(struct node_footer *footer)
+{
+	if (!c.dbg_lv)
+		return;
+
+	DISP_u32(footer, nid);
+	DISP_u32(footer, ino);
+	DISP_u32(footer, flag);
+	DISP_u64(footer, cp_ver);
+	DISP_u32(footer, next_blkaddr);
+}
+
+void inject_usage(void)
+{
+	MSG(0, "\nUsage: inject.f2fs [options] device\n");
+	MSG(0, "[options]:\n");
+	MSG(0, "  -d debug level [default:0]\n");
+	MSG(0, "  -V print the version number and exit\n");
+	MSG(0, "  --mb <member name> which member is injected in a struct\n");
+	MSG(0, "  --val <new value> new value to set\n");
+	MSG(0, "  --str <new string> new string to set\n");
+	MSG(0, "  --idx <slot index> which slot is injected in an array\n");
+	MSG(0, "  --nid <nid> which nid is injected\n");
+	MSG(0, "  --blk <blkaddr> which blkaddr is injected\n");
+	MSG(0, "  --sb <0|1|2> --mb <name> [--idx <index>] --val/str <value/string> inject superblock\n");
+	MSG(0, "  --cp <0|1|2> --mb <name> [--idx <index>] --val <value> inject checkpoint\n");
+	MSG(0, "  --nat <0|1|2> --mb <name> --nid <nid> --val <value> inject nat entry\n");
+	MSG(0, "  --sit <0|1|2> --mb <name> --blk <blk> [--idx <index>] --val <value> inject sit entry\n");
+	MSG(0, "  --ssa --mb <name> --blk <blk> [--idx <index>] --val <value> inject summary entry\n");
+	MSG(0, "  --node --mb <name> --nid <nid> [--idx <index>] --val <value> inject node\n");
+	MSG(0, "  --dry-run do not really inject\n");
+
+	exit(1);
+}
+
+static void inject_sb_usage(void)
+{
+	MSG(0, "inject.f2fs --sb <0|1|2> --mb <name> [--idx <index>] --val/str <value/string>\n");
+	MSG(0, "[sb]:\n");
+	MSG(0, "  0: auto select the first super block\n");
+	MSG(0, "  1: select the first super block\n");
+	MSG(0, "  2: select the second super block\n");
+	MSG(0, "[mb]:\n");
+	MSG(0, "  magic: inject magic number\n");
+	MSG(0, "  s_stop_reason: inject s_stop_reason array selected by --idx <index>\n");
+	MSG(0, "  s_errors: inject s_errors array selected by --idx <index>\n");
+	MSG(0, "  devs.path: inject path in devs array selected by --idx <index> specified by --str <string>\n");
+}
+
+static void inject_cp_usage(void)
+{
+	MSG(0, "inject.f2fs --cp <0|1|2> --mb <name> [--idx <index>] --val <value> inject checkpoint\n");
+	MSG(0, "[cp]:\n");
+	MSG(0, "  0: auto select the current cp pack\n");
+	MSG(0, "  1: select the first cp pack\n");
+	MSG(0, "  2: select the second cp pack\n");
+	MSG(0, "[mb]:\n");
+	MSG(0, "  checkpoint_ver: inject checkpoint_ver\n");
+	MSG(0, "  ckpt_flags: inject ckpt_flags\n");
+	MSG(0, "  cur_node_segno: inject cur_node_segno array selected by --idx <index>\n");
+	MSG(0, "  cur_node_blkoff: inject cur_node_blkoff array selected by --idx <index>\n");
+	MSG(0, "  cur_data_segno: inject cur_data_segno array selected by --idx <index>\n");
+	MSG(0, "  cur_data_blkoff: inject cur_data_blkoff array selected by --idx <index>\n");
+}
+
+static void inject_nat_usage(void)
+{
+	MSG(0, "inject.f2fs --nat <0|1|2> --mb <name> --nid <nid> --val <value> inject nat entry\n");
+	MSG(0, "[nat]:\n");
+	MSG(0, "  0: auto select the current nat pack\n");
+	MSG(0, "  1: select the first nat pack\n");
+	MSG(0, "  2: select the second nat pack\n");
+	MSG(0, "[mb]:\n");
+	MSG(0, "  version: inject nat entry version\n");
+	MSG(0, "  ino: inject nat entry ino\n");
+	MSG(0, "  block_addr: inject nat entry block_addr\n");
+}
+
+static void inject_sit_usage(void)
+{
+	MSG(0, "inject.f2fs --sit <0|1|2> --mb <name> --blk <blk> [--idx <index>] --val <value> inject sit entry\n");
+	MSG(0, "[sit]:\n");
+	MSG(0, "  0: auto select the current sit pack\n");
+	MSG(0, "  1: select the first sit pack\n");
+	MSG(0, "  2: select the second sit pack\n");
+	MSG(0, "[mb]:\n");
+	MSG(0, "  vblocks: inject sit entry vblocks\n");
+	MSG(0, "  valid_map: inject sit entry valid_map\n");
+	MSG(0, "  mtime: inject sit entry mtime\n");
+}
+
+static void inject_ssa_usage(void)
+{
+	MSG(0, "inject.f2fs --ssa --mb <name> --blk <blk> [--idx <index>] --val <value> inject summary entry\n");
+	MSG(0, "[mb]:\n");
+	MSG(0, "  entry_type: inject summary block footer entry_type\n");
+	MSG(0, "  check_sum: inject summary block footer check_sum\n");
+	MSG(0, "  nid: inject summary entry nid selected by --idx <index\n");
+	MSG(0, "  version: inject summary entry version selected by --idx <index\n");
+	MSG(0, "  ofs_in_node: inject summary entry ofs_in_node selected by --idx <index\n");
+}
+
+static void inject_node_usage(void)
+{
+	MSG(0, "inject.f2fs --node --mb <name> --nid <nid> [--idx <index>] --val <value> inject node\n");
+	MSG(0, "[mb]:\n");
+	MSG(0, "  nid: inject node footer nid\n");
+	MSG(0, "  ino: inject node footer ino\n");
+	MSG(0, "  flag: inject node footer flag\n");
+	MSG(0, "  cp_ver: inject node footer cp_ver\n");
+	MSG(0, "  next_blkaddr: inject node footer next_blkaddr\n");
+	MSG(0, "  i_mode: inject inode i_mode\n");
+	MSG(0, "  i_advise: inject inode i_advise\n");
+	MSG(0, "  i_inline: inject inode i_inline\n");
+	MSG(0, "  i_links: inject inode i_links\n");
+	MSG(0, "  i_size: inject inode i_size\n");
+	MSG(0, "  i_blocks: inject inode i_blocks\n");
+	MSG(0, "  i_extra_isize: inject inode i_extra_isize\n");
+	MSG(0, "  i_inode_checksum: inject inode i_inode_checksum\n");
+	MSG(0, "  i_addr: inject inode i_addr array selected by --idx <index>\n");
+	MSG(0, "  i_nid: inject inode i_nid array selected by --idx <index>\n");
+	MSG(0, "  addr: inject {in}direct node nid/addr array selected by --idx <index>\n");
+}
+
+int inject_parse_options(int argc, char *argv[], struct inject_option *opt)
+{
+	int o = 0;
+	const char *pack[] = {"auto", "1", "2"};
+	const char *option_string = "d:Vh";
+	char *endptr;
+	struct option long_opt[] = {
+		{"dry-run", no_argument, 0, 1},
+		{"mb", required_argument, 0, 2},
+		{"idx", required_argument, 0, 3},
+		{"val", required_argument, 0, 4},
+		{"str", required_argument, 0, 5},
+		{"sb", required_argument, 0, 6},
+		{"cp", required_argument, 0, 7},
+		{"nat", required_argument, 0, 8},
+		{"nid", required_argument, 0, 9},
+		{"sit", required_argument, 0, 10},
+		{"blk", required_argument, 0, 11},
+		{"ssa", no_argument, 0, 12},
+		{"node", no_argument, 0, 13},
+		{0, 0, 0, 0}
+	};
+
+	while ((o = getopt_long(argc, argv, option_string,
+				long_opt, NULL)) != EOF) {
+		long nid, blk;
+
+		switch (o) {
+		case 1:
+			c.dry_run = 1;
+			MSG(0, "Info: Dry run\n");
+			break;
+		case 2:
+			opt->mb = optarg;
+			MSG(0, "Info: inject member %s\n", optarg);
+			break;
+		case 3:
+			if (!is_digits(optarg))
+				return EWRONG_OPT;
+			opt->idx = atoi(optarg);
+			MSG(0, "Info: inject slot index %d\n", opt->idx);
+			break;
+		case 4:
+			opt->val = strtoll(optarg, &endptr, 0);
+			if (opt->val == LLONG_MAX || opt->val == LLONG_MIN ||
+			    *endptr != '\0')
+				return -ERANGE;
+			MSG(0, "Info: inject value %lld : 0x%llx\n", opt->val,
+			    (unsigned long long)opt->val);
+			break;
+		case 5:
+			opt->str = strdup(optarg);
+			if (!opt->str)
+				return -ENOMEM;
+			MSG(0, "Info: inject string %s\n", opt->str);
+			break;
+		case 6:
+			if (!is_digits(optarg))
+				return EWRONG_OPT;
+			opt->sb = atoi(optarg);
+			if (opt->sb < 0 || opt->sb > 2)
+				return -ERANGE;
+			MSG(0, "Info: inject sb %s\n", pack[opt->sb]);
+			break;
+		case 7:
+			if (!is_digits(optarg))
+				return EWRONG_OPT;
+			opt->cp = atoi(optarg);
+			if (opt->cp < 0 || opt->cp > 2)
+				return -ERANGE;
+			MSG(0, "Info: inject cp pack %s\n", pack[opt->cp]);
+			break;
+		case 8:
+			if (!is_digits(optarg))
+				return EWRONG_OPT;
+			opt->nat = atoi(optarg);
+			if (opt->nat < 0 || opt->nat > 2)
+				return -ERANGE;
+			MSG(0, "Info: inject nat pack %s\n", pack[opt->nat]);
+			break;
+		case 9:
+			nid = strtol(optarg, &endptr, 0);
+			if (nid >= UINT_MAX || nid < 0 ||
+			    *endptr != '\0')
+				return -ERANGE;
+			opt->nid = nid;
+			MSG(0, "Info: inject nid %u : 0x%x\n", opt->nid, opt->nid);
+			break;
+		case 10:
+			if (!is_digits(optarg))
+				return EWRONG_OPT;
+			opt->sit = atoi(optarg);
+			if (opt->sit < 0 || opt->sit > 2)
+				return -ERANGE;
+			MSG(0, "Info: inject sit pack %s\n", pack[opt->sit]);
+			break;
+		case 11:
+			blk = strtol(optarg, &endptr, 0);
+			if (blk >= UINT_MAX || blk < 0 ||
+			    *endptr != '\0')
+				return -ERANGE;
+			opt->blk = blk;
+			MSG(0, "Info: inject blkaddr %u : 0x%x\n", opt->blk, opt->blk);
+			break;
+		case 12:
+			opt->ssa = true;
+			MSG(0, "Info: inject ssa\n");
+			break;
+		case 13:
+			opt->node = true;
+			MSG(0, "Info: inject node\n");
+			break;
+		case 'd':
+			if (optarg[0] == '-' || !is_digits(optarg))
+				return EWRONG_OPT;
+			c.dbg_lv = atoi(optarg);
+			MSG(0, "Info: Debug level = %d\n", c.dbg_lv);
+			break;
+		case 'V':
+			show_version("inject.f2fs");
+			exit(0);
+		case 'h':
+		default:
+			if (opt->sb >= 0) {
+				inject_sb_usage();
+				exit(0);
+			} else if (opt->cp >= 0) {
+				inject_cp_usage();
+				exit(0);
+			} else if (opt->nat >= 0) {
+				inject_nat_usage();
+				exit(0);
+			} else if (opt->sit >= 0) {
+				inject_sit_usage();
+				exit(0);
+			} else if (opt->ssa) {
+				inject_ssa_usage();
+				exit(0);
+			} else if (opt->node) {
+				inject_node_usage();
+				exit(0);
+			}
+			return EUNKNOWN_OPT;
+		}
+	}
+
+	return 0;
+}
+
+static int inject_sb(struct f2fs_sb_info *sbi, struct inject_option *opt)
+{
+	struct f2fs_super_block *sb;
+	char *buf;
+	int ret;
+
+	buf = calloc(1, F2FS_BLKSIZE);
+	ASSERT(buf != NULL);
+
+	if (opt->sb == 0)
+		opt->sb = 1;
+
+	ret = dev_read_block(buf, opt->sb == 1 ? SB0_ADDR : SB1_ADDR);
+	ASSERT(ret >= 0);
+
+	sb = (struct f2fs_super_block *)(buf + F2FS_SUPER_OFFSET);
+
+	if (!strcmp(opt->mb, "magic")) {
+		MSG(0, "Info: inject magic of sb %d: 0x%x -> 0x%x\n",
+		    opt->sb, get_sb(magic), (u32)opt->val);
+		set_sb(magic, (u32)opt->val);
+	} else if (!strcmp(opt->mb, "s_stop_reason")) {
+		if (opt->idx >= MAX_STOP_REASON) {
+			ERR_MSG("invalid index %u of sb->s_stop_reason[]\n",
+				opt->idx);
+			ret = -EINVAL;
+			goto out;
+		}
+		MSG(0, "Info: inject s_stop_reason[%d] of sb %d: %d -> %d\n",
+		    opt->idx, opt->sb, sb->s_stop_reason[opt->idx],
+		    (u8)opt->val);
+		sb->s_stop_reason[opt->idx] = (u8)opt->val;
+	} else if (!strcmp(opt->mb, "s_errors")) {
+		if (opt->idx >= MAX_F2FS_ERRORS) {
+			ERR_MSG("invalid index %u of sb->s_errors[]\n",
+				opt->idx);
+			ret = -EINVAL;
+			goto out;
+		}
+		MSG(0, "Info: inject s_errors[%d] of sb %d: %x -> %x\n",
+		    opt->idx, opt->sb, sb->s_errors[opt->idx], (u8)opt->val);
+		sb->s_errors[opt->idx] = (u8)opt->val;
+	} else if (!strcmp(opt->mb, "devs.path")) {
+		if (opt->idx >= MAX_DEVICES) {
+			ERR_MSG("invalid index %u of sb->devs[]\n", opt->idx);
+			ret = -EINVAL;
+			goto out;
+		}
+		if (strlen(opt->str) >= MAX_PATH_LEN) {
+			ERR_MSG("invalid length of option str\n");
+			ret = -EINVAL;
+			goto out;
+		}
+		MSG(0, "Info: inject devs[%d].path of sb %d: %s -> %s\n",
+		    opt->idx, opt->sb, (char *)sb->devs[opt->idx].path, opt->str);
+		strcpy((char *)sb->devs[opt->idx].path, opt->str);
+	} else {
+		ERR_MSG("unknown or unsupported member \"%s\"\n", opt->mb);
+		ret = -EINVAL;
+		goto out;
+	}
+
+	print_raw_sb_info(sb);
+	update_superblock(sb, SB_MASK((u32)opt->sb - 1));
+
+out:
+	free(buf);
+	free(opt->str);
+	return ret;
+}
+
+static int inject_cp(struct f2fs_sb_info *sbi, struct inject_option *opt)
+{
+	struct f2fs_checkpoint *cp, *cur_cp = F2FS_CKPT(sbi);
+	char *buf = NULL;
+	int ret = 0;
+
+	if (opt->cp == 0)
+		opt->cp = sbi->cur_cp;
+
+	if (opt->cp != sbi->cur_cp) {
+		struct f2fs_super_block *sb = sbi->raw_super;
+		block_t cp_addr;
+
+		buf = calloc(1, F2FS_BLKSIZE);
+		ASSERT(buf != NULL);
+
+		cp_addr = get_sb(cp_blkaddr);
+		if (opt->cp == 2)
+			cp_addr += 1 << get_sb(log_blocks_per_seg);
+		ret = dev_read_block(buf, cp_addr);
+		ASSERT(ret >= 0);
+
+		cp = (struct f2fs_checkpoint *)buf;
+		sbi->ckpt = cp;
+		sbi->cur_cp = opt->cp;
+	} else {
+		cp = cur_cp;
+	}
+
+	if (!strcmp(opt->mb, "checkpoint_ver")) {
+		MSG(0, "Info: inject checkpoint_ver of cp %d: 0x%llx -> 0x%"PRIx64"\n",
+		    opt->cp, get_cp(checkpoint_ver), (u64)opt->val);
+		set_cp(checkpoint_ver, (u64)opt->val);
+	} else if (!strcmp(opt->mb, "ckpt_flags")) {
+		MSG(0, "Info: inject ckpt_flags of cp %d: 0x%x -> 0x%x\n",
+		    opt->cp, get_cp(ckpt_flags), (u32)opt->val);
+		set_cp(ckpt_flags, (u32)opt->val);
+	} else if (!strcmp(opt->mb, "cur_node_segno")) {
+		if (opt->idx >= MAX_ACTIVE_NODE_LOGS) {
+			ERR_MSG("invalid index %u of cp->cur_node_segno[]\n",
+				opt->idx);
+			ret = -EINVAL;
+			goto out;
+		}
+		MSG(0, "Info: inject cur_node_segno[%d] of cp %d: 0x%x -> 0x%x\n",
+		    opt->idx, opt->cp, get_cp(cur_node_segno[opt->idx]),
+		    (u32)opt->val);
+		set_cp(cur_node_segno[opt->idx], (u32)opt->val);
+	} else if (!strcmp(opt->mb, "cur_node_blkoff")) {
+		if (opt->idx >= MAX_ACTIVE_NODE_LOGS) {
+			ERR_MSG("invalid index %u of cp->cur_node_blkoff[]\n",
+				opt->idx);
+			ret = -EINVAL;
+			goto out;
+		}
+		MSG(0, "Info: inject cur_node_blkoff[%d] of cp %d: 0x%x -> 0x%x\n",
+		    opt->idx, opt->cp, get_cp(cur_node_blkoff[opt->idx]),
+		    (u16)opt->val);
+		set_cp(cur_node_blkoff[opt->idx], (u16)opt->val);
+	} else if (!strcmp(opt->mb, "cur_data_segno")) {
+		if (opt->idx >= MAX_ACTIVE_DATA_LOGS) {
+			ERR_MSG("invalid index %u of cp->cur_data_segno[]\n",
+				opt->idx);
+			ret = -EINVAL;
+			goto out;
+		}
+		MSG(0, "Info: inject cur_data_segno[%d] of cp %d: 0x%x -> 0x%x\n",
+		    opt->idx, opt->cp, get_cp(cur_data_segno[opt->idx]),
+		    (u32)opt->val);
+		set_cp(cur_data_segno[opt->idx], (u32)opt->val);
+	} else if (!strcmp(opt->mb, "cur_data_blkoff")) {
+		if (opt->idx >= MAX_ACTIVE_DATA_LOGS) {
+			ERR_MSG("invalid index %u of cp->cur_data_blkoff[]\n",
+				opt->idx);
+			ret = -EINVAL;
+			goto out;
+		}
+		MSG(0, "Info: inject cur_data_blkoff[%d] of cp %d: 0x%x -> 0x%x\n",
+		    opt->idx, opt->cp, get_cp(cur_data_blkoff[opt->idx]),
+		    (u16)opt->val);
+		set_cp(cur_data_blkoff[opt->idx], (u16)opt->val);
+	} else {
+		ERR_MSG("unknown or unsupported member \"%s\"\n", opt->mb);
+		ret = -EINVAL;
+		goto out;
+	}
+
+	print_ckpt_info(sbi);
+	write_raw_cp_blocks(sbi, cp, opt->cp);
+
+out:
+	free(buf);
+	sbi->ckpt = cur_cp;
+	return ret;
+}
+
+static int inject_nat(struct f2fs_sb_info *sbi, struct inject_option *opt)
+{
+	struct f2fs_nm_info *nm_i = NM_I(sbi);
+	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
+	struct f2fs_nat_block *nat_blk;
+	struct f2fs_nat_entry *ne;
+	block_t blk_addr;
+	unsigned int offs;
+	bool is_set;
+	int ret;
+
+	if (!IS_VALID_NID(sbi, opt->nid)) {
+		ERR_MSG("Invalid nid %u range [%u:%"PRIu64"]\n", opt->nid, 0,
+			NAT_ENTRY_PER_BLOCK *
+			((get_sb(segment_count_nat) << 1) <<
+			 sbi->log_blocks_per_seg));
+		return -EINVAL;
+	}
+
+	nat_blk = calloc(F2FS_BLKSIZE, 1);
+	ASSERT(nat_blk);
+
+	/* change NAT version bitmap temporarily to select specified pack */
+	is_set = f2fs_test_bit(opt->nid, nm_i->nat_bitmap);
+	if (opt->nat == 0) {
+		opt->nat = is_set ? 2 : 1;
+	} else {
+		if (opt->nat == 1)
+			f2fs_clear_bit(opt->nid, nm_i->nat_bitmap);
+		else
+			f2fs_set_bit(opt->nid, nm_i->nat_bitmap);
+	}
+
+	blk_addr = current_nat_addr(sbi, opt->nid, NULL);
+
+	ret = dev_read_block(nat_blk, blk_addr);
+	ASSERT(ret >= 0);
+
+	offs = opt->nid % NAT_ENTRY_PER_BLOCK;
+	ne = &nat_blk->entries[offs];
+
+	if (!strcmp(opt->mb, "version")) {
+		MSG(0, "Info: inject nat entry version of nid %u "
+		    "in pack %d: %d -> %d\n", opt->nid, opt->nat,
+		    ne->version, (u8)opt->val);
+		ne->version = (u8)opt->val;
+	} else if (!strcmp(opt->mb, "ino")) {
+		MSG(0, "Info: inject nat entry ino of nid %u "
+		    "in pack %d: %d -> %d\n", opt->nid, opt->nat,
+		    le32_to_cpu(ne->ino), (nid_t)opt->val);
+		ne->ino = cpu_to_le32((nid_t)opt->val);
+	} else if (!strcmp(opt->mb, "block_addr")) {
+		MSG(0, "Info: inject nat entry block_addr of nid %u "
+		    "in pack %d: 0x%x -> 0x%x\n", opt->nid, opt->nat,
+		    le32_to_cpu(ne->block_addr), (block_t)opt->val);
+		ne->block_addr = cpu_to_le32((block_t)opt->val);
+	} else {
+		ERR_MSG("unknown or unsupported member \"%s\"\n", opt->mb);
+		free(nat_blk);
+		return -EINVAL;
+	}
+	print_raw_nat_entry_info(ne);
+
+	ret = dev_write_block(nat_blk, blk_addr);
+	ASSERT(ret >= 0);
+	/* restore NAT version bitmap */
+	if (is_set)
+		f2fs_set_bit(opt->nid, nm_i->nat_bitmap);
+	else
+		f2fs_clear_bit(opt->nid, nm_i->nat_bitmap);
+
+	free(nat_blk);
+	return ret;
+}
+
+static int inject_sit(struct f2fs_sb_info *sbi, struct inject_option *opt)
+{
+	struct sit_info *sit_i = SIT_I(sbi);
+	struct f2fs_sit_block *sit_blk;
+	struct f2fs_sit_entry *sit;
+	unsigned int segno, offs;
+	bool is_set;
+
+	if (!f2fs_is_valid_blkaddr(sbi, opt->blk, DATA_GENERIC)) {
+		ERR_MSG("Invalid blkaddr 0x%x (valid range [0x%x:0x%lx])\n",
+			opt->blk, SM_I(sbi)->main_blkaddr,
+			(unsigned long)le64_to_cpu(F2FS_RAW_SUPER(sbi)->block_count));
+		return -EINVAL;
+	}
+
+	sit_blk = calloc(F2FS_BLKSIZE, 1);
+	ASSERT(sit_blk);
+
+	segno = GET_SEGNO(sbi, opt->blk);
+	/* change SIT version bitmap temporarily to select specified pack */
+	is_set = f2fs_test_bit(segno, sit_i->sit_bitmap);
+	if (opt->sit == 0) {
+		opt->sit = is_set ? 2 : 1;
+	} else {
+		if (opt->sit == 1)
+			f2fs_clear_bit(segno, sit_i->sit_bitmap);
+		else
+			f2fs_set_bit(segno, sit_i->sit_bitmap);
+	}
+	get_current_sit_page(sbi, segno, sit_blk);
+	offs = SIT_ENTRY_OFFSET(sit_i, segno);
+	sit = &sit_blk->entries[offs];
+
+	if (!strcmp(opt->mb, "vblocks")) {
+		MSG(0, "Info: inject sit entry vblocks of block 0x%x "
+		    "in pack %d: %u -> %u\n", opt->blk, opt->sit,
+		    le16_to_cpu(sit->vblocks), (u16)opt->val);
+		sit->vblocks = cpu_to_le16((u16)opt->val);
+	} else if (!strcmp(opt->mb, "valid_map")) {
+		if (opt->idx == -1) {
+			MSG(0, "Info: auto idx = %u\n", offs);
+			opt->idx = offs;
+		}
+		if (opt->idx >= SIT_VBLOCK_MAP_SIZE) {
+			ERR_MSG("invalid idx %u of valid_map[]\n", opt->idx);
+			free(sit_blk);
+			return -ERANGE;
+		}
+		MSG(0, "Info: inject sit entry valid_map[%d] of block 0x%x "
+		    "in pack %d: 0x%02x -> 0x%02x\n", opt->idx, opt->blk,
+		    opt->sit, sit->valid_map[opt->idx], (u8)opt->val);
+		sit->valid_map[opt->idx] = (u8)opt->val;
+	} else if (!strcmp(opt->mb, "mtime")) {
+		MSG(0, "Info: inject sit entry mtime of block 0x%x "
+		    "in pack %d: %"PRIu64" -> %"PRIu64"\n", opt->blk, opt->sit,
+		    le64_to_cpu(sit->mtime), (u64)opt->val);
+		sit->mtime = cpu_to_le64((u64)opt->val);
+	} else {
+		ERR_MSG("unknown or unsupported member \"%s\"\n", opt->mb);
+		free(sit_blk);
+		return -EINVAL;
+	}
+	print_raw_sit_entry_info(sit);
+
+	rewrite_current_sit_page(sbi, segno, sit_blk);
+	/* restore SIT version bitmap */
+	if (is_set)
+		f2fs_set_bit(segno, sit_i->sit_bitmap);
+	else
+		f2fs_clear_bit(segno, sit_i->sit_bitmap);
+
+	free(sit_blk);
+	return 0;
+}
+
+static int inject_ssa(struct f2fs_sb_info *sbi, struct inject_option *opt)
+{
+	struct f2fs_summary_block *sum_blk;
+	struct summary_footer *footer;
+	struct f2fs_summary *sum;
+	u32 segno, offset;
+	block_t ssa_blkaddr;
+	int type;
+	int ret;
+
+	if (!f2fs_is_valid_blkaddr(sbi, opt->blk, DATA_GENERIC)) {
+		ERR_MSG("Invalid blkaddr %#x (valid range [%#x:%#lx])\n",
+			opt->blk, SM_I(sbi)->main_blkaddr,
+			(unsigned long)le64_to_cpu(F2FS_RAW_SUPER(sbi)->block_count));
+		return -ERANGE;
+	}
+
+	segno = GET_SEGNO(sbi, opt->blk);
+	offset = OFFSET_IN_SEG(sbi, opt->blk);
+
+	sum_blk = get_sum_block(sbi, segno, &type);
+	sum = &sum_blk->entries[offset];
+	footer = F2FS_SUMMARY_BLOCK_FOOTER(sum_blk);
+
+	if (!strcmp(opt->mb, "entry_type")) {
+		MSG(0, "Info: inject summary block footer entry_type of "
+		    "block 0x%x: %d -> %d\n", opt->blk, footer->entry_type,
+		    (unsigned char)opt->val);
+		footer->entry_type = (unsigned char)opt->val;
+	} else 	if (!strcmp(opt->mb, "check_sum")) {
+		MSG(0, "Info: inject summary block footer check_sum of "
+		    "block 0x%x: 0x%x -> 0x%x\n", opt->blk,
+		    le32_to_cpu(footer->check_sum), (u32)opt->val);
+		footer->check_sum = cpu_to_le32((u32)opt->val);
+	} else {
+		if (opt->idx == -1) {
+			MSG(0, "Info: auto idx = %u\n", offset);
+			opt->idx = offset;
+		}
+		if (opt->idx >= ENTRIES_IN_SUM) {
+			ERR_MSG("invalid idx %u of entries[]\n", opt->idx);
+			ret = -EINVAL;
+			goto out;
+		}
+		sum = &sum_blk->entries[opt->idx];
+		if (!strcmp(opt->mb, "nid")) {
+			MSG(0, "Info: inject summary entry nid of "
+			    "block 0x%x: 0x%x -> 0x%x\n", opt->blk,
+			    le32_to_cpu(sum->nid), (u32)opt->val);
+			sum->nid = cpu_to_le32((u32)opt->val);
+		} else if (!strcmp(opt->mb, "version")) {
+			MSG(0, "Info: inject summary entry version of "
+			    "block 0x%x: %d -> %d\n", opt->blk,
+			    sum->version, (u8)opt->val);
+			sum->version = (u8)opt->val;
+		} else if (!strcmp(opt->mb, "ofs_in_node")) {
+			MSG(0, "Info: inject summary entry ofs_in_node of "
+			    "block 0x%x: %d -> %d\n", opt->blk,
+			    sum->ofs_in_node, (u16)opt->val);
+			sum->ofs_in_node = cpu_to_le16((u16)opt->val);
+		} else {
+			ERR_MSG("unknown or unsupported member \"%s\"\n", opt->mb);
+			ret = -EINVAL;
+			goto out;
+		}
+
+		print_raw_sum_entry_info(sum);
+	}
+
+	print_sum_footer_info(footer);
+
+	ssa_blkaddr = GET_SUM_BLKADDR(sbi, segno);
+	ret = dev_write_block(sum_blk, ssa_blkaddr);
+	ASSERT(ret >= 0);
+
+out:
+	if (type == SEG_TYPE_NODE || type == SEG_TYPE_DATA ||
+	    type == SEG_TYPE_MAX)
+		free(sum_blk);
+	return ret;
+}
+
+static int inject_inode(struct f2fs_sb_info *sbi, struct f2fs_node *node,
+			struct inject_option *opt)
+{
+	struct f2fs_inode *inode = &node->i;
+
+	if (!strcmp(opt->mb, "i_mode")) {
+		MSG(0, "Info: inject inode i_mode of nid %u: 0x%x -> 0x%x\n",
+		    opt->nid, le16_to_cpu(inode->i_mode), (u16)opt->val);
+		inode->i_mode = cpu_to_le16((u16)opt->val);
+	} else if (!strcmp(opt->mb, "i_advise")) {
+		MSG(0, "Info: inject inode i_advise of nid %u: 0x%x -> 0x%x\n",
+		    opt->nid, inode->i_advise, (u8)opt->val);
+		inode->i_advise = (u8)opt->val;
+	} else if (!strcmp(opt->mb, "i_inline")) {
+		MSG(0, "Info: inject inode i_inline of nid %u: 0x%x -> 0x%x\n",
+		    opt->nid, inode->i_inline, (u8)opt->val);
+		inode->i_inline = (u8)opt->val;
+	} else if (!strcmp(opt->mb, "i_links")) {
+		MSG(0, "Info: inject inode i_links of nid %u: %u -> %u\n",
+		    opt->nid, le32_to_cpu(inode->i_links), (u32)opt->val);
+		inode->i_links = cpu_to_le32((u32)opt->val);
+	} else if (!strcmp(opt->mb, "i_size")) {
+		MSG(0, "Info: inject inode i_size of nid %u: %"PRIu64" -> %"PRIu64"\n",
+		    opt->nid, le64_to_cpu(inode->i_size), (u64)opt->val);
+		inode->i_size = cpu_to_le64((u64)opt->val);
+	} else if (!strcmp(opt->mb, "i_blocks")) {
+		MSG(0, "Info: inject inode i_blocks of nid %u: %"PRIu64" -> %"PRIu64"\n",
+		    opt->nid, le64_to_cpu(inode->i_blocks), (u64)opt->val);
+		inode->i_blocks = cpu_to_le64((u64)opt->val);
+	} else if (!strcmp(opt->mb, "i_extra_isize")) {
+		/* do not care if F2FS_EXTRA_ATTR is enabled */
+		MSG(0, "Info: inject inode i_extra_isize of nid %u: %d -> %d\n",
+		    opt->nid, le16_to_cpu(inode->i_extra_isize), (u16)opt->val);
+		inode->i_extra_isize = cpu_to_le16((u16)opt->val);
+	} else if (!strcmp(opt->mb, "i_inode_checksum")) {
+		MSG(0, "Info: inject inode i_inode_checksum of nid %u: "
+		    "0x%x -> 0x%x\n", opt->nid,
+		    le32_to_cpu(inode->i_inode_checksum), (u32)opt->val);
+		inode->i_inode_checksum = cpu_to_le32((u32)opt->val);
+	} else if (!strcmp(opt->mb, "i_addr")) {
+		/* do not care if it is inline data */
+		if (opt->idx >= DEF_ADDRS_PER_INODE) {
+			ERR_MSG("invalid index %u of i_addr[]\n", opt->idx);
+			return -EINVAL;
+		}
+		MSG(0, "Info: inject inode i_addr[%d] of nid %u: "
+		    "0x%x -> 0x%x\n", opt->idx, opt->nid,
+		    le32_to_cpu(inode->i_addr[opt->idx]), (u32)opt->val);
+		inode->i_addr[opt->idx] = cpu_to_le32((block_t)opt->val);
+	} else if (!strcmp(opt->mb, "i_nid")) {
+		if (opt->idx >= 5) {
+			ERR_MSG("invalid index %u of i_nid[]\n", opt->idx);
+			return -EINVAL;
+		}
+		MSG(0, "Info: inject inode i_nid[%d] of nid %u: "
+		    "0x%x -> 0x%x\n", opt->idx, opt->nid,
+		    le32_to_cpu(F2FS_INODE_I_NID(inode, opt->idx)),
+		    (u32)opt->val);
+		F2FS_INODE_I_NID(inode, opt->idx) = cpu_to_le32((nid_t)opt->val);
+	} else {
+		ERR_MSG("unknown or unsupported member \"%s\"\n", opt->mb);
+		return -EINVAL;
+	}
+
+	if (c.dbg_lv > 0)
+		print_node_info(sbi, node, 1);
+
+	return 0;
+}
+
+static int inject_index_node(struct f2fs_sb_info *sbi, struct f2fs_node *node,
+			     struct inject_option *opt)
+{
+	struct direct_node *dn = &node->dn;
+
+	if (strcmp(opt->mb, "addr")) {
+		ERR_MSG("unknown or unsupported member \"%s\"\n", opt->mb);
+		return -EINVAL;
+	}
+
+	if (opt->idx >= DEF_ADDRS_PER_BLOCK) {
+		ERR_MSG("invalid index %u of nid/addr[]\n", opt->idx);
+		return -EINVAL;
+	}
+
+	MSG(0, "Info: inject node nid/addr[%d] of nid %u: 0x%x -> 0x%x\n",
+	    opt->idx, opt->nid, le32_to_cpu(dn->addr[opt->idx]),
+	    (block_t)opt->val);
+	dn->addr[opt->idx] = cpu_to_le32((block_t)opt->val);
+
+	if (c.dbg_lv > 0)
+		print_node_info(sbi, node, 1);
+
+	return 0;
+}
+
+static int inject_node(struct f2fs_sb_info *sbi, struct inject_option *opt)
+{
+	struct f2fs_super_block *sb = sbi->raw_super;
+	struct node_info ni;
+	struct f2fs_node *node_blk;
+	struct node_footer *footer;
+	int ret;
+
+	if (!IS_VALID_NID(sbi, opt->nid)) {
+		ERR_MSG("Invalid nid %u range [%u:%"PRIu64"]\n", opt->nid, 0,
+			NAT_ENTRY_PER_BLOCK *
+			((get_sb(segment_count_nat) << 1) <<
+			 sbi->log_blocks_per_seg));
+		return -EINVAL;
+	}
+
+	node_blk = calloc(F2FS_BLKSIZE, 1);
+	ASSERT(node_blk);
+
+	get_node_info(sbi, opt->nid, &ni);
+	ret = dev_read_block(node_blk, ni.blk_addr);
+	ASSERT(ret >= 0);
+	footer = F2FS_NODE_FOOTER(node_blk);
+
+	if (!strcmp(opt->mb, "nid")) {
+		MSG(0, "Info: inject node footer nid of nid %u: %u -> %u\n",
+		    opt->nid, le32_to_cpu(footer->nid), (u32)opt->val);
+		footer->nid = cpu_to_le32((u32)opt->val);
+	} else if (!strcmp(opt->mb, "ino")) {
+		MSG(0, "Info: inject node footer ino of nid %u: %u -> %u\n",
+		    opt->nid, le32_to_cpu(footer->ino), (u32)opt->val);
+		footer->ino = cpu_to_le32((u32)opt->val);
+	} else if (!strcmp(opt->mb, "flag")) {
+		MSG(0, "Info: inject node footer flag of nid %u: "
+		    "0x%x -> 0x%x\n", opt->nid, le32_to_cpu(footer->flag),
+		    (u32)opt->val);
+		footer->flag = cpu_to_le32((u32)opt->val);
+	} else if (!strcmp(opt->mb, "cp_ver")) {
+		MSG(0, "Info: inject node footer cp_ver of nid %u: "
+		    "0x%"PRIx64" -> 0x%"PRIx64"\n", opt->nid, le64_to_cpu(footer->cp_ver),
+		    (u64)opt->val);
+		footer->cp_ver = cpu_to_le64((u64)opt->val);
+	} else if (!strcmp(opt->mb, "next_blkaddr")) {
+		MSG(0, "Info: inject node footer next_blkaddr of nid %u: "
+		    "0x%x -> 0x%x\n", opt->nid,
+		    le32_to_cpu(footer->next_blkaddr), (u32)opt->val);
+		footer->next_blkaddr = cpu_to_le32((u32)opt->val);
+	} else if (ni.nid == ni.ino) {
+		ret = inject_inode(sbi, node_blk, opt);
+	} else {
+		ret = inject_index_node(sbi, node_blk, opt);
+	}
+	if (ret)
+		goto out;
+
+	print_node_footer_info(footer);
+
+	/*
+	 * if i_inode_checksum is injected, should call update_block() to
+	 * avoid recalculate inode checksum
+	 */
+	if (ni.nid == ni.ino && strcmp(opt->mb, "i_inode_checksum"))
+		ret = update_inode(sbi, node_blk, &ni.blk_addr);
+	else
+		ret = update_block(sbi, node_blk, &ni.blk_addr, NULL);
+	ASSERT(ret >= 0);
+
+out:
+	free(node_blk);
+	return ret;
+}
+
+int do_inject(struct f2fs_sb_info *sbi)
+{
+	struct inject_option *opt = (struct inject_option *)c.private;
+	int ret = -EINVAL;
+
+	if (opt->sb >= 0)
+		ret = inject_sb(sbi, opt);
+	else if (opt->cp >= 0)
+		ret = inject_cp(sbi, opt);
+	else if (opt->nat >= 0)
+		ret = inject_nat(sbi, opt);
+	else if (opt->sit >= 0)
+		ret = inject_sit(sbi, opt);
+	else if (opt->ssa)
+		ret = inject_ssa(sbi, opt);
+	else if (opt->node)
+		ret = inject_node(sbi, opt);
+
+	return ret;
+}
diff --git a/fsck/inject.h b/fsck/inject.h
new file mode 100644
index 0000000..9b14c31
--- /dev/null
+++ b/fsck/inject.h
@@ -0,0 +1,40 @@
+/**
+ * inject.h
+ *
+ * Copyright (c) 2024 OPPO Mobile Comm Corp., Ltd.
+ *             http://www.oppo.com/
+ *
+ * This program is free software; you can redistribute it and/or modify
+ * it under the terms of the GNU General Public License version 2 as
+ * published by the Free Software Foundation.
+ */
+
+#ifndef _INJECT_H_
+#define _INJECT_H_
+
+#include <stdio.h>
+#include <stdint.h>
+#include <limits.h>
+
+#include "f2fs_fs.h"
+#include "fsck.h"
+
+struct inject_option {
+	const char *mb;		/* member name */
+	unsigned int idx;	/* slot index */
+	long long val;		/* new value */
+	char *str;		/* new string */
+	nid_t nid;
+	block_t blk;
+	int sb;			/* which sb */
+	int cp;			/* which cp */
+	int nat;		/* which nat pack */
+	int sit;		/* which sit pack */
+	bool ssa;
+	bool node;
+};
+
+void inject_usage(void);
+int inject_parse_options(int argc, char *argv[], struct inject_option *inject_opt);
+int do_inject(struct f2fs_sb_info *sbi);
+#endif
diff --git a/fsck/main.c b/fsck/main.c
index 6edc902..8881936 100644
--- a/fsck/main.c
+++ b/fsck/main.c
@@ -29,6 +29,15 @@
 #include <stdbool.h>
 #include "quotaio.h"
 #include "compress.h"
+#ifdef WITH_INJECT
+#include "inject.h"
+#else
+static void inject_usage(void)
+{
+	MSG(0, "\ninject.f2fs not supported\n");
+	exit(1);
+}
+#endif
 
 struct f2fs_fsck gfsck;
 
@@ -97,6 +106,12 @@ void dump_usage()
 	MSG(0, "  -S sparse_mode\n");
 	MSG(0, "  -a [SSA dump segno from #1~#2 (decimal), for all 0~-1]\n");
 	MSG(0, "  -b blk_addr (in 4KB)\n");
+	MSG(0, "  -r dump out from the root inode\n");
+	MSG(0, "  -f do not prompt before dumping\n");
+	MSG(0, "  -y alias for -f\n");
+	MSG(0, "  -o dump inodes to the given path\n");
+	MSG(0, "  -P preserve mode/owner/group for dumped inode\n");
+	MSG(0, "  -L Preserves symlinks. Otherwise symlinks are dumped as regular files.\n");
 	MSG(0, "  -V print the version number and exit\n");
 
 	exit(1);
@@ -166,7 +181,7 @@ void label_usage()
 	exit(1);
 }
 
-static int is_digits(char *optarg)
+int is_digits(char *optarg)
 {
 	unsigned int i;
 
@@ -190,6 +205,8 @@ static void error_out(char *prog)
 		sload_usage();
 	else if (!strcmp("f2fslabel", prog))
 		label_usage();
+	else if (!strcmp("inject.f2fs", prog))
+		inject_usage();
 	else
 		MSG(0, "\nWrong program.\n");
 }
@@ -384,7 +401,7 @@ void f2fs_parse_options(int argc, char *argv[])
 		}
 	} else if (!strcmp("dump.f2fs", prog)) {
 #ifdef WITH_DUMP
-		const char *option_string = "d:fi:I:n:Mo:Prs:Sa:b:Vy";
+		const char *option_string = "d:fi:I:n:LMo:Prs:Sa:b:Vy";
 		static struct dump_option dump_opt = {
 			.nid = 0,	/* default root ino */
 			.start_nat = -1,
@@ -474,6 +491,14 @@ void f2fs_parse_options(int argc, char *argv[])
 				err = EWRONG_OPT;
 #else
 				c.preserve_perms = 1;
+#endif
+				break;
+			case 'L':
+#if defined(__MINGW32__)
+				MSG(0, "-L not supported for Windows\n");
+				err = EWRONG_OPT;
+#else
+				c.preserve_symlinks = 1;
 #endif
 				break;
 			case 'V':
@@ -804,6 +829,25 @@ void f2fs_parse_options(int argc, char *argv[])
 			c.vol_label = NULL;
 		}
 #endif /* WITH_LABEL */
+	} else if (!strcmp("inject.f2fs", prog)) {
+#ifdef WITH_INJECT
+		static struct inject_option inject_opt = {
+			.sb = -1,
+			.cp = -1,
+			.nat = -1,
+			.sit = -1,
+			.idx = -1,
+			.nid = -1,
+		};
+
+		err = inject_parse_options(argc, argv, &inject_opt);
+		if (err < 0) {
+			err = EWRONG_OPT;
+		}
+
+		c.func = INJECT;
+		c.private = &inject_opt;
+#endif /* WITH_INJECT */
 	}
 
 	if (err == NOERROR) {
@@ -952,7 +996,7 @@ static void do_dump(struct f2fs_sb_info *sbi)
 	if (opt->blk_addr != -1)
 		dump_info_from_blkaddr(sbi, opt->blk_addr);
 	if (opt->nid)
-		dump_node(sbi, opt->nid, c.force, opt->base_path, 1, 1);
+		dump_node(sbi, opt->nid, c.force, opt->base_path, 1, 1, NULL);
 	if (opt->scan_nid)
 		dump_node_scan_disk(sbi, opt->scan_nid);
 
@@ -1224,6 +1268,12 @@ fsck_again:
 		if (do_label(sbi))
 			goto out_err;
 		break;
+#endif
+#ifdef WITH_INJECT
+	case INJECT:
+		if (do_inject(sbi))
+			goto out_err;
+		break;
 #endif
 	default:
 		ERR_MSG("Wrong program name\n");
diff --git a/fsck/mount.c b/fsck/mount.c
index 8524335..dab0611 100644
--- a/fsck/mount.c
+++ b/fsck/mount.c
@@ -469,6 +469,7 @@ void print_raw_sb_info(struct f2fs_super_block *sb)
 	char uuid[40];
 	char encrypt_pw_salt[40];
 #endif
+	int i;
 
 	if (c.layout)
 		goto printout;
@@ -537,6 +538,13 @@ printout:
 	DISP_raw_str("%-.36s", encrypt_pw_salt);
 #endif
 
+	for (i = 0; i < MAX_DEVICES; i++) {
+		if (!sb->devs[i].path[0])
+			break;
+		DISP_str("%s", sb, devs[i].path);
+		DISP_u32(sb, devs[i].total_segments);
+	}
+
 	DISP_u32(sb, qf_ino[USRQUOTA]);
 	DISP_u32(sb, qf_ino[GRPQUOTA]);
 	DISP_u32(sb, qf_ino[PRJQUOTA]);
@@ -693,7 +701,7 @@ void print_sb_stop_reason(struct f2fs_super_block *sb)
 	u8 *reason = sb->s_stop_reason;
 	int i;
 
-	if (!c.force_stop)
+	if (!(c.invalid_sb & SB_FORCE_STOP))
 		return;
 
 	MSG(0, "Info: checkpoint stop reason: ");
@@ -731,7 +739,7 @@ void print_sb_errors(struct f2fs_super_block *sb)
 	u8 *errors = sb->s_errors;
 	int i;
 
-	if (!c.fs_errors)
+	if (!(c.invalid_sb & SB_FS_ERRORS))
 		return;
 
 	MSG(0, "Info: fs errors: ");
@@ -1163,9 +1171,12 @@ int validate_super_block(struct f2fs_sb_info *sbi, enum SB_ADDR sb_addr)
 				VERSION_NAME_LEN);
 		get_kernel_version(c.init_version);
 
-		c.force_stop = is_checkpoint_stop(sbi->raw_super, false);
-		c.abnormal_stop = is_checkpoint_stop(sbi->raw_super, true);
-		c.fs_errors = is_inconsistent_error(sbi->raw_super);
+		if (is_checkpoint_stop(sbi->raw_super, false))
+			c.invalid_sb |= SB_FORCE_STOP;
+		if (is_checkpoint_stop(sbi->raw_super, true))
+			c.invalid_sb |= SB_ABNORMAL_STOP;
+		if (is_inconsistent_error(sbi->raw_super))
+			c.invalid_sb |= SB_FS_ERRORS;
 
 		MSG(0, "Info: MKFS version\n  \"%s\"\n", c.init_version);
 		MSG(0, "Info: FSCK version\n  from \"%s\"\n    to \"%s\"\n",
@@ -1178,6 +1189,7 @@ int validate_super_block(struct f2fs_sb_info *sbi, enum SB_ADDR sb_addr)
 
 	free(sbi->raw_super);
 	sbi->raw_super = NULL;
+	c.invalid_sb |= SB_INVALID;
 	MSG(0, "\tCan't find a valid F2FS superblock at 0x%x\n", sb_addr);
 
 	return -EINVAL;
@@ -1212,7 +1224,7 @@ int init_sb_info(struct f2fs_sb_info *sbi)
 			c.devices[i].path = strdup((char *)sb->devs[i].path);
 			if (get_device_info(i))
 				ASSERT(0);
-		} else {
+		} else if (c.func != INJECT) {
 			ASSERT(!strcmp((char *)sb->devs[i].path,
 						(char *)c.devices[i].path));
 		}
@@ -1448,7 +1460,7 @@ static int f2fs_should_proceed(struct f2fs_super_block *sb, u32 flag)
 		if (flag & CP_FSCK_FLAG ||
 			flag & CP_DISABLED_FLAG ||
 			flag & CP_QUOTA_NEED_FSCK_FLAG ||
-			c.abnormal_stop || c.fs_errors ||
+			c.invalid_sb & SB_NEED_FIX ||
 			(exist_qf_ino(sb) && (flag & CP_ERROR_FLAG))) {
 			c.fix_on = 1;
 		} else if (!c.preen_mode) {
@@ -3426,6 +3438,32 @@ void write_checkpoints(struct f2fs_sb_info *sbi)
 	write_checkpoint(sbi);
 }
 
+void write_raw_cp_blocks(struct f2fs_sb_info *sbi,
+			 struct f2fs_checkpoint *cp, int which)
+{
+	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
+	uint32_t crc;
+	block_t cp_blkaddr;
+	int ret;
+
+	crc = f2fs_checkpoint_chksum(cp);
+	*((__le32 *)((unsigned char *)cp + get_cp(checksum_offset))) =
+							cpu_to_le32(crc);
+
+	cp_blkaddr = get_sb(cp_blkaddr);
+	if (which == 2)
+		cp_blkaddr += 1 << get_sb(log_blocks_per_seg);
+
+	/* write the first cp block in this CP pack */
+	ret = dev_write_block(cp, cp_blkaddr);
+	ASSERT(ret >= 0);
+
+	/* write the second cp block in this CP pack */
+	cp_blkaddr += get_cp(cp_pack_total_block_count) - 1;
+	ret = dev_write_block(cp, cp_blkaddr);
+	ASSERT(ret >= 0);
+}
+
 void build_nat_area_bitmap(struct f2fs_sb_info *sbi)
 {
 	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_HOT_DATA);
@@ -4018,7 +4056,7 @@ int f2fs_do_mount(struct f2fs_sb_info *sbi)
 	}
 	cp = F2FS_CKPT(sbi);
 
-	if (c.func != FSCK && c.func != DUMP &&
+	if (c.func != FSCK && c.func != DUMP && c.func != INJECT &&
 		!is_set_ckpt_flags(F2FS_CKPT(sbi), CP_UMOUNT_FLAG)) {
 		ERR_MSG("Mount unclean image to replay log first\n");
 		return -1;
diff --git a/fsck/node.c b/fsck/node.c
index 7ee29ac..632151a 100644
--- a/fsck/node.c
+++ b/fsck/node.c
@@ -62,7 +62,7 @@ int f2fs_rebuild_qf_inode(struct f2fs_sb_info *sbi, int qtype)
 
 	raw_node->i.i_size = cpu_to_le64(1024 * 6);
 	raw_node->i.i_blocks = cpu_to_le64(1);
-	raw_node->i.i_flags = F2FS_NOATIME_FL | F2FS_IMMUTABLE_FL;
+	raw_node->i.i_flags = cpu_to_le32(F2FS_NOATIME_FL | F2FS_IMMUTABLE_FL);
 
 	if (is_set_ckpt_flags(ckpt, CP_CRC_RECOVERY_FLAG))
 		cp_ver |= (cur_cp_crc(ckpt) << 32);
diff --git a/include/android_config.h b/include/android_config.h
index 05b686e..9c8b163 100644
--- a/include/android_config.h
+++ b/include/android_config.h
@@ -13,6 +13,7 @@
 #define HAVE_LINUX_XATTR_H 1
 #define HAVE_LINUX_FS_H 1
 #define HAVE_LINUX_FIEMAP_H 1
+#define HAVE_LINUX_VERITY_H 1
 #define HAVE_MNTENT_H 1
 #define HAVE_STDLIB_H 1
 #define HAVE_STRING_H 1
diff --git a/include/f2fs_fs.h b/include/f2fs_fs.h
index 870a6e4..15a1c82 100644
--- a/include/f2fs_fs.h
+++ b/include/f2fs_fs.h
@@ -45,6 +45,7 @@
 #define WITH_RESIZE
 #define WITH_SLOAD
 #define WITH_LABEL
+#define WITH_INJECT
 #endif
 
 #include <inttypes.h>
@@ -427,6 +428,7 @@ enum f2fs_config_func {
 	RESIZE,
 	SLOAD,
 	LABEL,
+	INJECT,
 };
 
 enum default_set {
@@ -659,9 +661,11 @@ enum {
 /*
  * On-disk inode flags (f2fs_inode::i_flags)
  */
+#define F2FS_COMPR_FL			0x00000004 /* Compress file */
+#define F2FS_NODUMP_FL			0x00000040 /* do not dump file */
 #define F2FS_IMMUTABLE_FL		0x00000010 /* Immutable file */
 #define F2FS_NOATIME_FL			0x00000080 /* do not update atime */
-
+#define F2FS_CASEFOLD_FL		0x40000000 /* Casefolded file */
 
 #define F2FS_ENC_UTF8_12_1	1
 #define F2FS_ENC_STRICT_MODE_FL	(1 << 0)
@@ -925,10 +929,10 @@ static_assert(sizeof(struct node_footer) == 24, "");
 				- sizeof(struct node_footer)) / sizeof(__le32))
 #define CUR_ADDRS_PER_INODE(inode)	(DEF_ADDRS_PER_INODE - \
 					__get_extra_isize(inode))
-#define ADDRS_PER_INODE(i)	addrs_per_inode(i)
+#define ADDRS_PER_INODE(i)	addrs_per_page(i, true)
 /* Address Pointers in a Direct Block */
 #define DEF_ADDRS_PER_BLOCK ((F2FS_BLKSIZE - sizeof(struct node_footer)) / sizeof(__le32))
-#define ADDRS_PER_BLOCK(i)	addrs_per_block(i)
+#define ADDRS_PER_BLOCK(i)	addrs_per_page(i, false)
 /* Node IDs in an Indirect Block */
 #define NIDS_PER_BLOCK    ((F2FS_BLKSIZE - sizeof(struct node_footer)) / sizeof(__le32))
 
@@ -984,9 +988,7 @@ static_assert(sizeof(struct node_footer) == 24, "");
 
 #define file_is_encrypt(fi)      ((fi)->i_advise & FADVISE_ENCRYPT_BIT)
 #define file_enc_name(fi)        ((fi)->i_advise & FADVISE_ENC_NAME_BIT)
-
-#define F2FS_CASEFOLD_FL	0x40000000 /* Casefolded file */
-#define IS_CASEFOLDED(dir)     ((dir)->i_flags & F2FS_CASEFOLD_FL)
+#define IS_CASEFOLDED(dir)     ((dir)->i_flags & cpu_to_le32(F2FS_CASEFOLD_FL))
 
 /*
  * fsck i_compr_blocks counting helper
@@ -1003,10 +1005,6 @@ struct f2fs_compr_blk_cnt {
 };
 #define CHEADER_PGOFS_NONE ((u32)-(1 << MAX_COMPRESS_LOG_SIZE))
 
-/*
- * inode flags
- */
-#define F2FS_COMPR_FL		0x00000004 /* Compress file */
 /*
  * On disk layout is
  * struct f2fs_inode
@@ -1443,6 +1441,13 @@ enum {
 	SSR
 };
 
+/* invalid sb types */
+#define SB_FORCE_STOP		0x1	/* s_stop_reason is set */
+#define SB_ABNORMAL_STOP	0x2	/* s_stop_reason is set except shutdown */
+#define SB_FS_ERRORS		0x4	/* s_erros is set */
+#define SB_INVALID		0x8	/* sb is invalid */
+#define SB_NEED_FIX (SB_ABNORMAL_STOP | SB_FS_ERRORS | SB_INVALID)
+
 #define MAX_CACHE_SUMS			8
 
 struct f2fs_configuration {
@@ -1478,6 +1483,8 @@ struct f2fs_configuration {
 	uint16_t s_encoding_flags;
 	int32_t kd;
 	int32_t dump_fd;
+	char *dump_symlink;
+	int dump_sym_target_len;
 	struct device_info devices[MAX_DEVICES];
 	int ndevs;
 	char *extension_list[2];
@@ -1494,9 +1501,7 @@ struct f2fs_configuration {
 	int force;
 	int defset;
 	int bug_on;
-	int force_stop;
-	int abnormal_stop;
-	int fs_errors;
+	unsigned int invalid_sb;
 	int bug_nat_bits;
 	bool quota_fixed;
 	int alloc_failed;
@@ -1540,7 +1545,10 @@ struct f2fs_configuration {
 	struct selinux_opt seopt_file[8];
 	int nr_opt;
 #endif
+
+	/* dump parameters */
 	int preserve_perms;
+	int preserve_symlinks;
 
 	/* resize parameters */
 	int safe_resize;
@@ -1569,8 +1577,7 @@ struct f2fs_configuration {
 extern int utf8_to_utf16(char *, const char *, size_t, size_t);
 extern int utf16_to_utf8(char *, const char *, size_t, size_t);
 extern int log_base_2(uint32_t);
-extern unsigned int addrs_per_inode(struct f2fs_inode *);
-extern unsigned int addrs_per_block(struct f2fs_inode *);
+extern unsigned int addrs_per_page(struct f2fs_inode *, bool);
 extern unsigned int f2fs_max_file_offset(struct f2fs_inode *);
 extern __u32 f2fs_inode_chksum(struct f2fs_node *);
 extern __u32 f2fs_checkpoint_chksum(struct f2fs_checkpoint *);
@@ -1614,6 +1621,9 @@ extern int dev_readahead(__u64, size_t UNUSED(len));
 extern int dev_write(void *, __u64, size_t);
 extern int dev_write_block(void *, __u64);
 extern int dev_write_dump(void *, __u64, size_t);
+#if !defined(__MINGW32__)
+extern int dev_write_symlink(char *, size_t);
+#endif
 /* All bytes in the buffer must be 0 use dev_fill(). */
 extern int dev_fill(void *, __u64, size_t);
 extern int dev_fill_block(void *, __u64);
@@ -1732,6 +1742,8 @@ blk_zone_cond_str(struct blk_zone *blkz)
  * Handle kernel zone capacity support
  */
 #define blk_zone_empty(z)	(blk_zone_cond(z) == BLK_ZONE_COND_EMPTY)
+#define blk_zone_open(z)	(blk_zone_cond(z) == BLK_ZONE_COND_IMP_OPEN ||	\
+				 blk_zone_cond(z) == BLK_ZONE_COND_EXP_OPEN)
 #define blk_zone_sector(z)	(z)->start
 #define blk_zone_length(z)	(z)->len
 #define blk_zone_wp_sector(z)	(z)->wp
diff --git a/lib/libf2fs.c b/lib/libf2fs.c
index 1cfbf31..1e0f422 100644
--- a/lib/libf2fs.c
+++ b/lib/libf2fs.c
@@ -516,9 +516,10 @@ opaque_seq:
 	return __f2fs_dentry_hash(name, len);
 }
 
-unsigned int addrs_per_inode(struct f2fs_inode *i)
+unsigned int addrs_per_page(struct f2fs_inode *i, bool is_inode)
 {
-	unsigned int addrs = CUR_ADDRS_PER_INODE(i) - get_inline_xattr_addrs(i);
+	unsigned int addrs = is_inode ? CUR_ADDRS_PER_INODE(i) -
+		get_inline_xattr_addrs(i) : DEF_ADDRS_PER_BLOCK;
 
 	if (!LINUX_S_ISREG(le16_to_cpu(i->i_mode)) ||
 			!(le32_to_cpu(i->i_flags) & F2FS_COMPR_FL))
@@ -526,14 +527,6 @@ unsigned int addrs_per_inode(struct f2fs_inode *i)
 	return ALIGN_DOWN(addrs, 1 << i->i_log_cluster_size);
 }
 
-unsigned int addrs_per_block(struct f2fs_inode *i)
-{
-	if (!LINUX_S_ISREG(le16_to_cpu(i->i_mode)) ||
-			!(le32_to_cpu(i->i_flags) & F2FS_COMPR_FL))
-		return DEF_ADDRS_PER_BLOCK;
-	return ALIGN_DOWN(DEF_ADDRS_PER_BLOCK, 1 << i->i_log_cluster_size);
-}
-
 unsigned int f2fs_max_file_offset(struct f2fs_inode *i)
 {
 	if (!LINUX_S_ISREG(le16_to_cpu(i->i_mode)) ||
diff --git a/lib/libf2fs_io.c b/lib/libf2fs_io.c
index b2d6933..f39367a 100644
--- a/lib/libf2fs_io.c
+++ b/lib/libf2fs_io.c
@@ -598,6 +598,16 @@ int dev_write_dump(void *buf, __u64 offset, size_t len)
 	return 0;
 }
 
+#if !defined(__MINGW32__)
+int dev_write_symlink(char *buf, size_t len)
+{
+	buf[len] = 0;
+	if (symlink(buf, c.dump_symlink))
+		return -1;
+	return 0;
+}
+#endif
+
 int dev_fill(void *buf, __u64 offset, size_t len)
 {
 	int fd;
diff --git a/lib/libf2fs_zoned.c b/lib/libf2fs_zoned.c
index e55d098..89ba5ad 100644
--- a/lib/libf2fs_zoned.c
+++ b/lib/libf2fs_zoned.c
@@ -27,6 +27,9 @@
 #include <libgen.h>
 
 #ifdef HAVE_LINUX_BLKZONED_H
+#ifndef BLKFINISHZONE
+#define BLKFINISHZONE   _IOW(0x12, 136, struct blk_zone_range)
+#endif
 
 int get_sysfs_path(struct device_info *dev, const char *attr,
 		   char *buf, size_t buflen)
@@ -510,7 +513,7 @@ int f2fs_finish_zone(int i, void *blkzone)
 	struct blk_zone_range range;
 	int ret;
 
-	if (!blk_zone_seq(blkz) || blk_zone_empty(blkz))
+	if (!blk_zone_seq(blkz) || !blk_zone_open(blkz))
 		return 0;
 
 	/* Non empty sequential zone: finish */
@@ -519,7 +522,8 @@ int f2fs_finish_zone(int i, void *blkzone)
 	ret = ioctl(dev->fd, BLKFINISHZONE, &range);
 	if (ret != 0) {
 		ret = -errno;
-		ERR_MSG("ioctl BLKFINISHZONE failed: errno=%d\n", errno);
+		ERR_MSG("ioctl BLKFINISHZONE failed: errno=%d, status=%s\n",
+			errno, blk_zone_cond_str(blkz));
 	}
 
 	return ret;
diff --git a/man/Makefile.am b/man/Makefile.am
index 9363b82..b78344a 100644
--- a/man/Makefile.am
+++ b/man/Makefile.am
@@ -1,3 +1,3 @@
 ## Makefile.am
 
-dist_man_MANS = mkfs.f2fs.8 fsck.f2fs.8 dump.f2fs.8 defrag.f2fs.8 resize.f2fs.8 sload.f2fs.8 f2fs_io.8 f2fslabel.8
+dist_man_MANS = mkfs.f2fs.8 fsck.f2fs.8 dump.f2fs.8 defrag.f2fs.8 resize.f2fs.8 sload.f2fs.8 f2fs_io.8 f2fslabel.8 inject.f2fs.8
diff --git a/man/dump.f2fs.8 b/man/dump.f2fs.8
index 60d6783..4035d57 100644
--- a/man/dump.f2fs.8
+++ b/man/dump.f2fs.8
@@ -71,6 +71,9 @@ Dump inodes to the given path
 .BI \-P
 Preserve mode/owner/group for dumped inode
 .TP
+.BI \-L
+Preserves symlinks. Otherwise symlinks are dumped as regular files.
+.TP
 .BI \-I " inode number"
 Specify an inode number and scan full disk to dump out, include history inode block
 .TP
diff --git a/man/inject.f2fs.8 b/man/inject.f2fs.8
new file mode 100644
index 0000000..01d58ef
--- /dev/null
+++ b/man/inject.f2fs.8
@@ -0,0 +1,225 @@
+.\" Copyright (c) 2024 OPPO Mobile Comm Corp., Ltd.
+.\"
+.TH INJECT.F2FS 8
+.SH NAME
+inject.f2fs \- inject a Linux F2FS file system
+.SH SYNOPSIS
+.B inject.f2fs
+[
+.I options
+]
+.I device
+.SH DESCRIPTION
+.B inject.f2fs
+is used to modify metadata or data (directory entry) of f2fs file system
+image offline flexibly.
+.SH OPTIONS
+.TP
+.BI \-d " debug level [default:0]"
+Specify the level of debugging options.
+.TP
+.BI \-V
+Print the version number and exit.
+.TP
+.BI \-\-mb " member name"
+Specify the member name in a struct that is injected.
+.TP
+.BI \-\-val " new value"
+New value to set if \fImb\fP is a number.
+.TP
+.BI \-\-str " new string"
+New string to set if \fImb\fP is a string.
+.TP
+.BI \-\-idx " slot index"
+Specify which slot is injected if \fImb\fP is an array.
+.TP
+.BI \-\-nid " nid"
+Specify which nid is injected.
+.TP
+.BI \-\-blk " blkaddr"
+Specify which blkaddr is injected.
+.TP
+.BI \-\-sb " 0 or 1 or 2"
+Inject super block, its argument means which sb pack is injected, where 0 choses the current valid sb automatically.
+The available \fImb\fP of \fIsb\fP are:
+.RS 1.2i
+.TP
+.BI magic
+magic numbe.
+.TP
+.BI s_stop_reason
+s_stop_reason array.
+.TP
+.BI s_errors
+s_errors array.
+.TP
+.BI devs.path
+path in devs array.
+.RE
+.TP
+.BI \-\-cp " 0 or 1 or 2"
+Inject checkpoint, its argument means which cp pack is injected, where 0 choses the current valid cp automatically.
+The available \fImb\fP of \fIcp\fP are:
+.RS 1.2i
+.TP
+.BI checkpoint_ver
+checkpoint version.
+.TP
+.BI ckpt_flags
+checkpoint flags.
+.TP
+.BI cur_node_segno
+cur_node_segno array.
+.TP
+.BI cur_node_blkoff
+cur_node_blkoff array.
+.TP
+.BI cur_data_segno
+cur_data_segno array.
+.TP
+.BI cur_data_blkoff
+cur_data_blkoff array.
+.RE
+.TP
+.BI \-\-nat " 0 or 1 or 2"
+Inject nat entry specified by \fInid\fP, its argument means which nat pack is injected, where 0 choses the current valid nat automatically.
+The available \fImb\fP of \fInat\fP are:
+.RS 1.2i
+.TP
+.BI version
+nat entry version.
+.TP
+.BI ino
+nat entry ino.
+.TP
+.BI block_addr
+nat entry block_addr.
+.RE
+.TP
+.BI \-\-sit " 0 or 1 or 2"
+Inject sit entry specified by \fIblk\fP, its argument means which sit pack is injected, where 0 choses the current valid sit automatically.
+The available \fImb\fP of \fIsit\fP are:
+.RS 1.2i
+.TP
+.BI vblocks
+sit entry vblocks.
+.TP
+.BI valid_map
+sit entry valid_map.
+.TP
+.BI mtime
+sit entry mtime.
+.RE
+.TP
+.BI \-\-ssa
+Inject summary block or summary entry specified by \fIblk\fP.
+The available \fImb\fP of \fIssa\fP are:
+.RS 1.2i
+.TP
+.BI entry_type
+summary block footer entry_type.
+.TP
+.BI check_sum
+summary block footer check_sum.
+.TP
+.BI nid
+summary entry nid.
+.TP
+.BI version
+summary entry version.
+.TP
+.BI ofs_in_node
+summary entry ofs_in_node.
+.RE
+.TP
+.BI \-\-node
+Inject node block specified by \fInid\P.
+The available \fImb\fP of \fInode\fP are:
+.RS 1.2i
+.TP
+.BI nid
+node footer nid.
+.TP
+.BI ino
+node footer ino.
+.TP
+.BI flag
+node footer flag.
+.TP
+.BI cp_ver
+node footer cp_ver.
+.TP
+.BI next_blkaddr
+node footer next_blkaddr.
+.TP
+.BI i_mode
+inode i_mode.
+.TP
+.BI i_advise
+inode i_advise.
+.TP
+.BI i_inline
+inode i_inline.
+.TP
+.BI i_links
+inode i_links.
+.TP
+.BI i_size
+inode i_size.
+.TP
+.BI i_blocks
+inode i_blocks.
+.TP
+.BI i_extra_isize
+inode i_extra_isize.
+.TP
+.BI i_inode_checksum
+inode i_inode_checksum.
+.TP
+.BI i_addr
+inode i_addr array specified by \fIidx\fP.
+.TP
+.BI i_nid
+inode i_nid array specified by \fIidx\fP.
+.TP
+.BI addr
+{in}direct node nid/addr array specified by \fIidx\fP.
+.RE
+.TP
+.BI \-\-dent
+Inject dentry block or dir entry specified \fInid\fP.
+The available \fImb\fP of \fIdent\fP are:
+.RS 1.2i
+.TP
+.BI d_bitmap
+dentry block d_bitmap.
+.TP
+.BI d_hash
+dentry hash.
+.TP
+.BI d_ino
+dentry ino.
+.TP
+.BI d_ftype
+dentry ftype.
+.RE
+.TP
+.BI \-\-dry\-run
+Do not really inject.
+
+.PP
+.SH AUTHOR
+This version of
+.B inject.f2fs
+has been written by Sheng Yong <shengyong@oppo.com>.
+.SH AVAILABILITY
+.B inject.f2fs
+is available from git://git.kernel.org/pub/scm/linux/kernel/git/jaegeuk/f2fs-tools.git.
+.SH "SEE ALSO"
+.BR mkfs.f2fs(8),
+.BR fsck.f2fs(8),
+.BR dump.f2fs(8),
+.BR defrag.f2fs(8),
+.BR resize.f2fs(8),
+.BR sload.f2fs(8),
+.BR defrag.f2fs(8).
diff --git a/mkfs/f2fs_format.c b/mkfs/f2fs_format.c
index c9d335a..247a836 100644
--- a/mkfs/f2fs_format.c
+++ b/mkfs/f2fs_format.c
@@ -316,7 +316,7 @@ static int f2fs_prepare_super_block(void)
 					c.blks_per_seg - 1;
 		}
 		if (c.ndevs > 1) {
-			memcpy(sb->devs[i].path, c.devices[i].path, MAX_PATH_LEN);
+			strncpy((char *)sb->devs[i].path, c.devices[i].path, MAX_PATH_LEN);
 			sb->devs[i].total_segments =
 					cpu_to_le32(c.devices[i].total_segments);
 		}
@@ -765,10 +765,6 @@ static int f2fs_write_check_point_pack(void)
 			get_cp(rsvd_segment_count)) *
 			c.overprovision / 100);
 
-	if (!(c.conf_reserved_sections) &&
-	    get_cp(overprov_segment_count) < get_cp(rsvd_segment_count))
-		set_cp(overprov_segment_count, get_cp(rsvd_segment_count));
-
 	/*
 	 * If conf_reserved_sections has a non zero value, overprov_segment_count
 	 * is set to overprov_segment_count + rsvd_segment_count.
@@ -788,8 +784,11 @@ static int f2fs_write_check_point_pack(void)
 		set_cp(overprov_segment_count, get_cp(overprov_segment_count) +
 				get_cp(rsvd_segment_count));
 	 } else {
-		set_cp(overprov_segment_count, get_cp(overprov_segment_count) +
-				overprovision_segment_buffer(sb));
+		/*
+		 * overprov_segment_count must bigger than rsvd_segment_count.
+		 */
+		set_cp(overprov_segment_count, max(get_cp(rsvd_segment_count),
+			get_cp(overprov_segment_count)) + overprovision_segment_buffer(sb));
 	 }
 
 	if (f2fs_get_usable_segments(sb) <= get_cp(overprov_segment_count)) {
@@ -1414,7 +1413,7 @@ static int f2fs_write_qf_inode(int qtype)
 
 	raw_node->i.i_size = cpu_to_le64(1024 * 6);
 	raw_node->i.i_blocks = cpu_to_le64(1 + QUOTA_DATA);
-	raw_node->i.i_flags = F2FS_NOATIME_FL | F2FS_IMMUTABLE_FL;
+	raw_node->i.i_flags = cpu_to_le32(F2FS_NOATIME_FL | F2FS_IMMUTABLE_FL);
 
 	node_blkaddr = alloc_next_free_block(CURSEG_HOT_NODE);
 	F2FS_NODE_FOOTER(raw_node)->next_blkaddr = cpu_to_le32(node_blkaddr + 1);
diff --git a/tools/f2fs_io/Android.bp b/tools/f2fs_io/Android.bp
index c89438f..b6b946b 100644
--- a/tools/f2fs_io/Android.bp
+++ b/tools/f2fs_io/Android.bp
@@ -13,7 +13,8 @@ package {
 cc_defaults {
     name: "f2fs-io-defaults",
     cflags: [
-        "-Wno-unused-function"
+        "-D_FILE_OFFSET_BITS=64",
+        "-Wno-unused-function",
     ],
     include_dirs: [
        "external/f2fs-tools/include/",
diff --git a/tools/f2fs_io/f2fs_io.c b/tools/f2fs_io/f2fs_io.c
index a7b593a..94f0adf 100644
--- a/tools/f2fs_io/f2fs_io.c
+++ b/tools/f2fs_io/f2fs_io.c
@@ -182,16 +182,19 @@ static void do_fsync(int argc, char **argv, const struct cmd_desc *cmd)
 static void do_set_verity(int argc, char **argv, const struct cmd_desc *cmd)
 {
 	int ret, fd;
+	struct fsverity_enable_arg args = {.version = 1};
+
+	args.hash_algorithm = FS_VERITY_HASH_ALG_SHA256;
+	args.block_size = 4096;
 
 	if (argc != 2) {
 		fputs("Excess arguments\n\n", stderr);
 		fputs(cmd->cmd_help, stderr);
 		exit(1);
 	}
+	fd = open(argv[1], O_RDONLY);
 
-	fd = open(argv[1], O_RDWR);
-
-	ret = ioctl(fd, FS_IOC_ENABLE_VERITY);
+	ret = ioctl(fd, FS_IOC_ENABLE_VERITY, &args);
 	if (ret < 0) {
 		perror("FS_IOC_ENABLE_VERITY");
 		exit(1);
@@ -539,7 +542,7 @@ static void do_fallocate(int argc, char **argv, const struct cmd_desc *cmd)
 	if (!strcmp(argv[0], "1"))
 		mode |= FALLOC_FL_KEEP_SIZE;
 
-	offset = atoi(argv[1]);
+	offset = atoll(argv[1]);
 	length = atoll(argv[2]);
 
 	fd = xopen(argv[3], O_RDWR, 0);
@@ -867,8 +870,15 @@ static void do_read(int argc, char **argv, const struct cmd_desc *cmd)
 	if (!do_mmap) {
 		for (i = 0; i < count; i++) {
 			ret = pread(fd, buf, buf_size, offset + buf_size * i);
-			if (ret != buf_size)
+			if (ret != buf_size) {
+				printf("pread expected: %"PRIu64", readed: %"PRIu64"\n",
+						buf_size, ret);
+				if (ret > 0) {
+					read_cnt += ret;
+					memcpy(print_buf, buf, print_bytes);
+				}
 				break;
+			}
 
 			read_cnt += ret;
 			if (i == 0)
@@ -957,7 +967,7 @@ static void do_randread(int argc, char **argv, const struct cmd_desc *cmd)
 
 #define fiemap_desc "get block address in file"
 #define fiemap_help					\
-"f2fs_io fiemap [offset in 4kb] [count] [file_path]\n\n"\
+"f2fs_io fiemap [offset in 4kb] [count in 4kb] [file_path]\n\n"\
 
 #if defined(HAVE_LINUX_FIEMAP_H) && defined(HAVE_LINUX_FS_H)
 static void do_fiemap(int argc, char **argv, const struct cmd_desc *cmd)
@@ -1546,9 +1556,9 @@ static void do_move_range(int argc, char **argv, const struct cmd_desc *cmd)
 
 	fd = xopen(argv[1], O_RDWR, 0);
 	range.dst_fd = xopen(argv[2], O_RDWR | O_CREAT, 0644);
-	range.pos_in = atoi(argv[3]);
-	range.pos_out = atoi(argv[4]);
-	range.len = atoi(argv[5]);
+	range.pos_in = atoll(argv[3]);
+	range.pos_out = atoll(argv[4]);
+	range.len = atoll(argv[5]);
 
 	ret = ioctl(fd, F2FS_IOC_MOVE_RANGE, &range);
 	if (ret < 0)
@@ -1726,7 +1736,7 @@ static void do_lseek(int argc, char **argv, const struct cmd_desc *cmd)
 		exit(1);
 	}
 
-	offset = atoi(argv[2]);
+	offset = atoll(argv[2]);
 
 	if (!strcmp(argv[1], "set"))
 		whence = SEEK_SET;
@@ -1746,7 +1756,7 @@ static void do_lseek(int argc, char **argv, const struct cmd_desc *cmd)
 	ret = lseek(fd, offset, whence);
 	if (ret < 0)
 		die_errno("lseek failed");
-	printf("returned offset=%ld\n", ret);
+	printf("returned offset=%lld\n", (long long)ret);
 	exit(0);
 }
 
diff --git a/tools/f2fs_io/f2fs_io.h b/tools/f2fs_io/f2fs_io.h
index b5c82f5..e55db5f 100644
--- a/tools/f2fs_io/f2fs_io.h
+++ b/tools/f2fs_io/f2fs_io.h
@@ -16,6 +16,9 @@
 #ifdef HAVE_LINUX_FS_H
 #include <linux/fs.h>
 #endif
+#ifdef HAVE_LINUX_VERITY_H
+#include <linux/fsverity.h>
+#endif
 
 #include <sys/types.h>
 
@@ -136,8 +139,21 @@ struct fscrypt_get_policy_ex_arg {
 #define F2FS_IOC_GET_ENCRYPTION_POLICY	FS_IOC_GET_ENCRYPTION_POLICY
 #define F2FS_IOC_GET_ENCRYPTION_PWSALT	FS_IOC_GET_ENCRYPTION_PWSALT
 
-#define FS_IOC_ENABLE_VERITY		_IO('f', 133)
-
+#ifndef FS_IOC_ENABLE_VERITY
+#define FS_IOC_ENABLE_VERITY    _IOW('f', 133, struct fsverity_enable_arg)
+#define FS_VERITY_HASH_ALG_SHA256       1
+struct fsverity_enable_arg {
+	__u32 version;
+	__u32 hash_algorithm;
+	__u32 block_size;
+	__u32 salt_size;
+	__u64 salt_ptr;
+	__u32 sig_size;
+	__u32 __reserved1;
+	__u64 sig_ptr;
+	__u64 __reserved2[11];
+};
+#endif
 /*
  * Inode flags
  */
```

