```diff
diff --git a/METADATA b/METADATA
index fc95632..c994a5a 100644
--- a/METADATA
+++ b/METADATA
@@ -1,17 +1,17 @@
 name: "fsck_msdos"
-description:
-    "This is the FreeBSD fsck_msdosfs."
-
+description: "This is the FreeBSD fsck_msdosfs."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/freebsd/freebsd/tree/master/sbin/fsck_msdosfs"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 1
+    day: 14
   }
-  url {
-    type: GIT
-    value: "https://github.com/freebsd/freebsd.git"
+  identifier {
+    type: "Archive"
+    value: "https://github.com/freebsd/freebsd-src/archive/refs/tags/release/14.2.0.tar.gz"
   }
-  version: "b60894b10adb071a8dc2b6fea5f9867c24bc9c47"
-  last_upgrade_date { year: 2020 month: 1 day: 13 }
-  license_type: NOTICE
+  version: "release/14.2.0"
+
+
 }
diff --git a/OWNERS b/OWNERS
index bb6f42d..ce6b8e3 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 enh@google.com
 delphij@google.com
 jsharkey@android.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/boot.c b/boot.c
index 887312e..f916094 100644
--- a/boot.c
+++ b/boot.c
@@ -1,5 +1,5 @@
 /*-
- * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
+ * SPDX-License-Identifier: BSD-2-Clause
  *
  * Copyright (C) 1995, 1997 Wolfgang Solfrank
  * Copyright (c) 1995 Martin Husemann
@@ -29,8 +29,6 @@
 #include <sys/cdefs.h>
 #ifndef lint
 __RCSID("$NetBSD: boot.c,v 1.22 2020/01/11 16:29:07 christos Exp $");
-static const char rcsid[] =
-  "$FreeBSD$";
 #endif /* not lint */
 
 #include <sys/param.h>
diff --git a/check.c b/check.c
index c164316..f672a2a 100644
--- a/check.c
+++ b/check.c
@@ -1,5 +1,5 @@
 /*-
- * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
+ * SPDX-License-Identifier: BSD-2-Clause
  *
  * Copyright (C) 1995, 1996, 1997 Wolfgang Solfrank
  * Copyright (c) 1995 Martin Husemann
@@ -29,8 +29,6 @@
 #include <sys/cdefs.h>
 #ifndef lint
 __RCSID("$NetBSD: check.c,v 1.14 2006/06/05 16:51:18 christos Exp $");
-static const char rcsid[] =
-  "$FreeBSD$";
 #endif /* not lint */
 
 #ifdef HAVE_LIBUTIL_H
@@ -186,10 +184,8 @@ checkfilesys(const char *fname)
 	free(fat);
 	close(dosfs);
 
-	if (mod & (FSFATMOD|FSDIRMOD)){
+	if (mod & (FSFATMOD|FSDIRMOD))
 		pwarn("\n***** FILE SYSTEM WAS MODIFIED *****\n");
-		return 4;
-	}
 
 	return ret;
 }
diff --git a/dir.c b/dir.c
index dbe4e0c..19516d8 100644
--- a/dir.c
+++ b/dir.c
@@ -1,5 +1,5 @@
 /*-
- * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
+ * SPDX-License-Identifier: BSD-2-Clause
  *
  * Copyright (c) 2019 Google LLC
  * Copyright (C) 1995, 1996, 1997 Wolfgang Solfrank
@@ -32,8 +32,6 @@
 #include <sys/cdefs.h>
 #ifndef lint
 __RCSID("$NetBSD: dir.c,v 1.20 2006/06/05 16:51:18 christos Exp $");
-static const char rcsid[] =
-  "$FreeBSD$";
 #endif /* not lint */
 
 #include <assert.h>
@@ -997,7 +995,7 @@ readDosDirSection(struct fat_descriptor *fat, struct dosDirEntry *dir)
 				n->next = pendingDirectories;
 				n->dir = d;
 				pendingDirectories = n;
-			} else {
+			} else if (!(mod & FSERROR)) {
 				mod |= k = checksize(fat, p, &dirent);
 				if (k & FSDIRMOD)
 					mod |= THISMOD;
diff --git a/dosfs.h b/dosfs.h
index d89a086..a8da745 100644
--- a/dosfs.h
+++ b/dosfs.h
@@ -1,5 +1,5 @@
 /*-
- * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
+ * SPDX-License-Identifier: BSD-2-Clause
  *
  * Copyright (C) 1995, 1996, 1997 Wolfgang Solfrank
  * Copyright (c) 1995 Martin Husemann
@@ -26,7 +26,6 @@
  * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
  * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *	$NetBSD: dosfs.h,v 1.4 1997/01/03 14:32:48 ws Exp $
- * $FreeBSD$
  */
 
 #ifndef DOSFS_H
diff --git a/ext.h b/ext.h
index 532e840..d0f4dd6 100644
--- a/ext.h
+++ b/ext.h
@@ -1,5 +1,5 @@
 /*-
- * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
+ * SPDX-License-Identifier: BSD-2-Clause
  *
  * Copyright (C) 1995, 1996, 1997 Wolfgang Solfrank
  * Copyright (c) 1995 Martin Husemann
@@ -24,7 +24,6 @@
  * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
  * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *	$NetBSD: ext.h,v 1.6 2000/04/25 23:02:51 jdolecek Exp $
- * $FreeBSD$
  */
 
 #ifndef EXT_H
diff --git a/fat.c b/fat.c
index e35e2f2..567bfcd 100644
--- a/fat.c
+++ b/fat.c
@@ -30,8 +30,6 @@
 #include <sys/cdefs.h>
 #ifndef lint
 __RCSID("$NetBSD: fat.c,v 1.18 2006/06/05 16:51:18 christos Exp $");
-static const char rcsid[] =
-  "$FreeBSD$";
 #endif /* not lint */
 
 #include <sys/endian.h>
diff --git a/fstab.h b/fstab.h
new file mode 100644
index 0000000..e61bb7c
--- /dev/null
+++ b/fstab.h
@@ -0,0 +1,79 @@
+/*-
+ * SPDX-License-Identifier: BSD-3-Clause
+ *
+ * Copyright (c) 1980, 1993
+ *	The Regents of the University of California.  All rights reserved.
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ * 1. Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ * 2. Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in the
+ *    documentation and/or other materials provided with the distribution.
+ * 3. Neither the name of the University nor the names of its contributors
+ *    may be used to endorse or promote products derived from this software
+ *    without specific prior written permission.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
+ * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
+ * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
+ * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
+ * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+ * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
+ * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
+ * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ *
+ *	@(#)fstab.h	8.1 (Berkeley) 6/2/93
+ */
+
+#ifndef _FSTAB_H_
+#define _FSTAB_H_
+
+/*
+ * File system table, see fstab(5).
+ *
+ * Used by dump, mount, umount, swapon, fsck, df, ...
+ *
+ * For ufs fs_spec field is the block special name.  Programs that want to
+ * use the character special name must create that name by prepending a 'r'
+ * after the right most slash.  Quota files are always named "quotas", so
+ * if type is "rq", then use concatenation of fs_file and "quotas" to locate
+ * quota file.
+ */
+#define	_PATH_FSTAB	"/etc/fstab"
+#define	FSTAB		"/etc/fstab"	/* deprecated */
+
+#define	FSTAB_RW	"rw"		/* read/write device */
+#define	FSTAB_RQ	"rq"		/* read/write with quotas */
+#define	FSTAB_RO	"ro"		/* read-only device */
+#define	FSTAB_SW	"sw"		/* swap device */
+#define	FSTAB_XX	"xx"		/* ignore totally */
+
+struct fstab {
+	char	*fs_spec;		/* block special device name */
+	char	*fs_file;		/* file system path prefix */
+	char	*fs_vfstype;		/* File system type, ufs, nfs */
+	char	*fs_mntops;		/* Mount options ala -o */
+	char	*fs_type;		/* FSTAB_* from fs_mntops */
+	int	fs_freq;		/* dump frequency, in days */
+	int	fs_passno;		/* pass number on parallel fsck */
+};
+
+#include <sys/cdefs.h>
+
+__BEGIN_DECLS
+struct fstab *getfsent(void);
+struct fstab *getfsspec(const char *);
+struct fstab *getfsfile(const char *);
+int setfsent(void);
+void endfsent(void);
+void setfstab(const char *);
+const char *getfstab(void);
+__END_DECLS
+
+#endif /* !_FSTAB_H_ */
diff --git a/fsutil.c b/fsutil.c
index 0fb0613..45fb1de 100644
--- a/fsutil.c
+++ b/fsutil.c
@@ -35,17 +35,12 @@
 #ifndef lint
 __RCSID("$NetBSD: fsutil.c,v 1.15 2006/06/05 16:52:05 christos Exp $");
 #endif /* not lint */
-__FBSDID("$FreeBSD$");
-
 #include <sys/param.h>
 #include <sys/stat.h>
 #include <sys/mount.h>
 
 #include <err.h>
-#include <errno.h>
-#ifndef __ANDROID__
 #include <fstab.h>
-#endif
 #include <paths.h>
 #include <stdarg.h>
 #include <stdio.h>
@@ -59,6 +54,44 @@ static int preen = 0;
 
 static void vmsg(int, const char *, va_list) __printflike(2, 0);
 
+/*
+ * The getfsopt() function checks whether an option is present in
+ * an fstab(5) fs_mntops entry. There are six possible cases:
+ *
+ * fs_mntops  getfsopt  result
+ *  rw,foo       foo    true
+ *  rw,nofoo    nofoo   true
+ *  rw,nofoo     foo    false
+ *  rw,foo      nofoo   false
+ *  rw           foo    false
+ *  rw          nofoo   false
+ *
+ * This function should be part of and documented in getfsent(3).
+ */
+int
+getfsopt(struct fstab *fs, const char *option)
+{
+	int negative, found;
+	char *opt, *optbuf;
+
+	if (option[0] == 'n' && option[1] == 'o') {
+		negative = 1;
+		option += 2;
+	} else
+		negative = 0;
+	optbuf = strdup(fs->fs_mntops);
+	found = 0;
+	for (opt = optbuf; (opt = strtok(opt, ",")) != NULL; opt = NULL) {
+		if (opt[0] == 'n' && opt[1] == 'o') {
+			if (!strcasecmp(opt + 2, option))
+				found = negative;
+		} else if (!strcasecmp(opt, option))
+			found = !negative;
+	}
+	free(optbuf);
+	return (found);
+}
+
 void
 setcdevname(const char *cd, int pr)
 {
@@ -165,7 +198,6 @@ getmntpt(const char *name)
 	char *dev_name;
 	struct statfs *mntbuf, *statfsp;
 	int i, mntsize, isdev;
-
 	if (stat(name, &devstat) != 0)
 		return (NULL);
 	if (S_ISCHR(devstat.st_mode) || S_ISBLK(devstat.st_mode))
diff --git a/fsutil.h b/fsutil.h
index 21e3649..794963f 100644
--- a/fsutil.h
+++ b/fsutil.h
@@ -24,14 +24,16 @@
  * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
  * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
- *
- * $FreeBSD$
  */
 
 #ifdef __ANDROID__
 #define    __dead2     __attribute__((__noreturn__))
 #endif
 
+struct fstab;
+int checkfstab(int, int (*)(struct fstab *), 
+    int (*) (const char *, const char *, const char *, const char *, pid_t *));
+int getfsopt(struct fstab *, const char *);
 void pfatal(const char *, ...) __printflike(1, 2);
 void pwarn(const char *, ...) __printflike(1, 2);
 void perr(const char *, ...) __printflike(1, 2);
@@ -39,20 +41,13 @@ void panic(const char *, ...) __dead2 __printflike(1, 2);
 const char *devcheck(const char *);
 const char *cdevname(void);
 void setcdevname(const char *, int);
-struct statfs *getmntpt(const char *);
 void *emalloc(size_t);
 void *erealloc(void *, size_t);
 char *estrdup(const char *);
 
-#ifndef __ANDROID__
 #define	CHECK_PREEN	0x0001
 #define	CHECK_VERBOSE	0x0002
 #define	CHECK_DEBUG	0x0004
 #define	CHECK_BACKGRD	0x0008
 #define	DO_BACKGRD	0x0010
 #define	CHECK_CLEAN	0x0020
-
-struct fstab;
-int checkfstab(int, int (*)(struct fstab *),
-    int (*) (const char *, const char *, const char *, const char *, pid_t *));
-#endif
diff --git a/main.c b/main.c
index de54cd1..0713189 100644
--- a/main.c
+++ b/main.c
@@ -29,8 +29,6 @@
 #include <sys/cdefs.h>
 #ifndef lint
 __RCSID("$NetBSD: main.c,v 1.10 1997/10/01 02:18:14 enami Exp $");
-static const char rcsid[] =
-  "$FreeBSD$";
 #endif /* not lint */
 
 #include <stdlib.h>
```

