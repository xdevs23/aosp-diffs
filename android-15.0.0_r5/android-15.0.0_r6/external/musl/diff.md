```diff
diff --git a/Android.bp b/Android.bp
index f31e1c72..49f66dda 100644
--- a/Android.bp
+++ b/Android.bp
@@ -213,12 +213,12 @@ cc_library_headers {
     export_header_lib_headers: [
         "libc_musl_arch_headers",
         "libc_musl_public_headers",
-        "libc_llndk_headers",
+        "libc_uapi_headers",
     ],
     header_libs: [
         "libc_musl_arch_headers",
         "libc_musl_public_headers",
-        "libc_llndk_headers",
+        "libc_uapi_headers",
     ],
 }
 
@@ -242,10 +242,10 @@ cc_library {
     export_header_lib_headers: [
         "libc_musl_arch_headers",
         "libc_musl_public_headers",
-        "libc_llndk_headers",
+        "libc_uapi_headers",
     ],
     header_libs: [
-        "libc_llndk_headers",
+        "libc_uapi_headers",
     ],
 }
 
@@ -273,10 +273,10 @@ cc_library_static {
     export_header_lib_headers: [
         "libc_musl_arch_headers",
         "libc_musl_public_headers",
-        "libc_llndk_headers",
+        "libc_uapi_headers",
     ],
     header_libs: [
-        "libc_llndk_headers",
+        "libc_uapi_headers",
     ],
 }
 
diff --git a/arch/aarch64/bits/posix.h b/arch/aarch64/bits/posix.h
deleted file mode 100644
index c37b94c1..00000000
--- a/arch/aarch64/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_LP64_OFF64  1
-#define _POSIX_V7_LP64_OFF64  1
diff --git a/arch/aarch64/bits/reg.h b/arch/aarch64/bits/reg.h
deleted file mode 100644
index 2633f39d..00000000
--- a/arch/aarch64/bits/reg.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#undef __WORDSIZE
-#define __WORDSIZE 64
diff --git a/arch/aarch64/bits/stat.h b/arch/aarch64/bits/stat.h
deleted file mode 100644
index b7f4221b..00000000
--- a/arch/aarch64/bits/stat.h
+++ /dev/null
@@ -1,18 +0,0 @@
-struct stat {
-	dev_t st_dev;
-	ino_t st_ino;
-	mode_t st_mode;
-	nlink_t st_nlink;
-	uid_t st_uid;
-	gid_t st_gid;
-	dev_t st_rdev;
-	unsigned long __pad;
-	off_t st_size;
-	blksize_t st_blksize;
-	int __pad2;
-	blkcnt_t st_blocks;
-	struct timespec st_atim;
-	struct timespec st_mtim;
-	struct timespec st_ctim;
-	unsigned __unused[2];
-};
diff --git a/arch/aarch64/bits/stdint.h b/arch/aarch64/bits/stdint.h
deleted file mode 100644
index 1bb147f2..00000000
--- a/arch/aarch64/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT64_MIN
-#define INTPTR_MAX      INT64_MAX
-#define UINTPTR_MAX     UINT64_MAX
-#define PTRDIFF_MIN     INT64_MIN
-#define PTRDIFF_MAX     INT64_MAX
-#define SIZE_MAX        UINT64_MAX
diff --git a/arch/arm/bits/posix.h b/arch/arm/bits/posix.h
deleted file mode 100644
index 30a38714..00000000
--- a/arch/arm/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_ILP32_OFFBIG  1
-#define _POSIX_V7_ILP32_OFFBIG  1
diff --git a/arch/arm/bits/reg.h b/arch/arm/bits/reg.h
deleted file mode 100644
index 0c7bffca..00000000
--- a/arch/arm/bits/reg.h
+++ /dev/null
@@ -1,3 +0,0 @@
-#undef __WORDSIZE
-#define __WORDSIZE 32
-/* FIXME */
diff --git a/arch/generic/bits/reg.h b/arch/generic/bits/reg.h
new file mode 100644
index 00000000..e69de29b
diff --git a/arch/riscv32/bits/stat.h b/arch/generic/bits/stat.h
similarity index 100%
rename from arch/riscv32/bits/stat.h
rename to arch/generic/bits/stat.h
diff --git a/arch/arm/bits/stdint.h b/arch/generic/bits/stdint.h
similarity index 68%
rename from arch/arm/bits/stdint.h
rename to arch/generic/bits/stdint.h
index d1b27121..86489187 100644
--- a/arch/arm/bits/stdint.h
+++ b/arch/generic/bits/stdint.h
@@ -12,9 +12,18 @@ typedef uint32_t uint_fast32_t;
 #define UINT_FAST16_MAX UINT32_MAX
 #define UINT_FAST32_MAX UINT32_MAX
 
+#if __LONG_MAX == 0x7fffffffL
 #define INTPTR_MIN      INT32_MIN
 #define INTPTR_MAX      INT32_MAX
 #define UINTPTR_MAX     UINT32_MAX
 #define PTRDIFF_MIN     INT32_MIN
 #define PTRDIFF_MAX     INT32_MAX
 #define SIZE_MAX        UINT32_MAX
+#else
+#define INTPTR_MIN      INT64_MIN
+#define INTPTR_MAX      INT64_MAX
+#define UINTPTR_MAX     UINT64_MAX
+#define PTRDIFF_MIN     INT64_MIN
+#define PTRDIFF_MAX     INT64_MAX
+#define SIZE_MAX        UINT64_MAX
+#endif
diff --git a/arch/i386/bits/posix.h b/arch/i386/bits/posix.h
deleted file mode 100644
index 30a38714..00000000
--- a/arch/i386/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_ILP32_OFFBIG  1
-#define _POSIX_V7_ILP32_OFFBIG  1
diff --git a/arch/i386/bits/reg.h b/arch/i386/bits/reg.h
index 8bc2582d..7dfe8250 100644
--- a/arch/i386/bits/reg.h
+++ b/arch/i386/bits/reg.h
@@ -1,5 +1,3 @@
-#undef __WORDSIZE
-#define __WORDSIZE 32
 #define EBX 0
 #define ECX 1
 #define EDX 2
diff --git a/arch/i386/bits/stdint.h b/arch/i386/bits/stdint.h
deleted file mode 100644
index d1b27121..00000000
--- a/arch/i386/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT32_MIN
-#define INTPTR_MAX      INT32_MAX
-#define UINTPTR_MAX     UINT32_MAX
-#define PTRDIFF_MIN     INT32_MIN
-#define PTRDIFF_MAX     INT32_MAX
-#define SIZE_MAX        UINT32_MAX
diff --git a/arch/loongarch64/bits/posix.h b/arch/loongarch64/bits/posix.h
deleted file mode 100644
index 8068ce98..00000000
--- a/arch/loongarch64/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_LP64_OFF64 1
-#define _POSIX_V7_LP64_OFF64 1
diff --git a/arch/loongarch64/bits/reg.h b/arch/loongarch64/bits/reg.h
deleted file mode 100644
index 2633f39d..00000000
--- a/arch/loongarch64/bits/reg.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#undef __WORDSIZE
-#define __WORDSIZE 64
diff --git a/arch/loongarch64/bits/stat.h b/arch/loongarch64/bits/stat.h
deleted file mode 100644
index b7f4221b..00000000
--- a/arch/loongarch64/bits/stat.h
+++ /dev/null
@@ -1,18 +0,0 @@
-struct stat {
-	dev_t st_dev;
-	ino_t st_ino;
-	mode_t st_mode;
-	nlink_t st_nlink;
-	uid_t st_uid;
-	gid_t st_gid;
-	dev_t st_rdev;
-	unsigned long __pad;
-	off_t st_size;
-	blksize_t st_blksize;
-	int __pad2;
-	blkcnt_t st_blocks;
-	struct timespec st_atim;
-	struct timespec st_mtim;
-	struct timespec st_ctim;
-	unsigned __unused[2];
-};
diff --git a/arch/loongarch64/bits/stdint.h b/arch/loongarch64/bits/stdint.h
deleted file mode 100644
index 1bb147f2..00000000
--- a/arch/loongarch64/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT64_MIN
-#define INTPTR_MAX      INT64_MAX
-#define UINTPTR_MAX     UINT64_MAX
-#define PTRDIFF_MIN     INT64_MIN
-#define PTRDIFF_MAX     INT64_MAX
-#define SIZE_MAX        UINT64_MAX
diff --git a/arch/m68k/bits/posix.h b/arch/m68k/bits/posix.h
deleted file mode 100644
index 30a38714..00000000
--- a/arch/m68k/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_ILP32_OFFBIG  1
-#define _POSIX_V7_ILP32_OFFBIG  1
diff --git a/arch/m68k/bits/reg.h b/arch/m68k/bits/reg.h
index 99201f70..fedc4f9f 100644
--- a/arch/m68k/bits/reg.h
+++ b/arch/m68k/bits/reg.h
@@ -1,5 +1,3 @@
-#undef __WORDSIZE
-#define __WORDSIZE 32
 #define PT_D1 0
 #define PT_D2 1
 #define PT_D3 2
diff --git a/arch/m68k/bits/stdint.h b/arch/m68k/bits/stdint.h
deleted file mode 100644
index d1b27121..00000000
--- a/arch/m68k/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT32_MIN
-#define INTPTR_MAX      INT32_MAX
-#define UINTPTR_MAX     UINT32_MAX
-#define PTRDIFF_MIN     INT32_MIN
-#define PTRDIFF_MAX     INT32_MAX
-#define SIZE_MAX        UINT32_MAX
diff --git a/arch/microblaze/bits/posix.h b/arch/microblaze/bits/posix.h
deleted file mode 100644
index 30a38714..00000000
--- a/arch/microblaze/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_ILP32_OFFBIG  1
-#define _POSIX_V7_ILP32_OFFBIG  1
diff --git a/arch/microblaze/bits/reg.h b/arch/microblaze/bits/reg.h
deleted file mode 100644
index 0c7bffca..00000000
--- a/arch/microblaze/bits/reg.h
+++ /dev/null
@@ -1,3 +0,0 @@
-#undef __WORDSIZE
-#define __WORDSIZE 32
-/* FIXME */
diff --git a/arch/microblaze/bits/stdint.h b/arch/microblaze/bits/stdint.h
deleted file mode 100644
index d1b27121..00000000
--- a/arch/microblaze/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT32_MIN
-#define INTPTR_MAX      INT32_MAX
-#define UINTPTR_MAX     UINT32_MAX
-#define PTRDIFF_MIN     INT32_MIN
-#define PTRDIFF_MAX     INT32_MAX
-#define SIZE_MAX        UINT32_MAX
diff --git a/arch/mips/bits/posix.h b/arch/mips/bits/posix.h
deleted file mode 100644
index 30a38714..00000000
--- a/arch/mips/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_ILP32_OFFBIG  1
-#define _POSIX_V7_ILP32_OFFBIG  1
diff --git a/arch/mips/bits/reg.h b/arch/mips/bits/reg.h
index 0c370987..2611b632 100644
--- a/arch/mips/bits/reg.h
+++ b/arch/mips/bits/reg.h
@@ -1,6 +1,3 @@
-#undef __WORDSIZE
-#define __WORDSIZE 32
-
 #define EF_R0 6
 #define EF_R1 7
 #define EF_R2 8
diff --git a/arch/mips/bits/stdint.h b/arch/mips/bits/stdint.h
deleted file mode 100644
index d1b27121..00000000
--- a/arch/mips/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT32_MIN
-#define INTPTR_MAX      INT32_MAX
-#define UINTPTR_MAX     UINT32_MAX
-#define PTRDIFF_MIN     INT32_MIN
-#define PTRDIFF_MAX     INT32_MAX
-#define SIZE_MAX        UINT32_MAX
diff --git a/arch/mips64/bits/posix.h b/arch/mips64/bits/posix.h
deleted file mode 100644
index acf42944..00000000
--- a/arch/mips64/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_LP64_OFFBIG 1
-#define _POSIX_V7_LP64_OFFBIG 1
diff --git a/arch/mips64/bits/reg.h b/arch/mips64/bits/reg.h
index a3f63acc..16178dd3 100644
--- a/arch/mips64/bits/reg.h
+++ b/arch/mips64/bits/reg.h
@@ -1,6 +1,3 @@
-#undef __WORDSIZE
-#define __WORDSIZE 64
-
 #define EF_R0 0
 #define EF_R1 1
 #define EF_R2 2
diff --git a/arch/mips64/bits/stdint.h b/arch/mips64/bits/stdint.h
deleted file mode 100644
index 1bb147f2..00000000
--- a/arch/mips64/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT64_MIN
-#define INTPTR_MAX      INT64_MAX
-#define UINTPTR_MAX     UINT64_MAX
-#define PTRDIFF_MIN     INT64_MIN
-#define PTRDIFF_MAX     INT64_MAX
-#define SIZE_MAX        UINT64_MAX
diff --git a/arch/mipsn32/bits/posix.h b/arch/mipsn32/bits/posix.h
deleted file mode 100644
index 30a38714..00000000
--- a/arch/mipsn32/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_ILP32_OFFBIG  1
-#define _POSIX_V7_ILP32_OFFBIG  1
diff --git a/arch/mipsn32/bits/reg.h b/arch/mipsn32/bits/reg.h
index a3f63acc..16178dd3 100644
--- a/arch/mipsn32/bits/reg.h
+++ b/arch/mipsn32/bits/reg.h
@@ -1,6 +1,3 @@
-#undef __WORDSIZE
-#define __WORDSIZE 64
-
 #define EF_R0 0
 #define EF_R1 1
 #define EF_R2 2
diff --git a/arch/mipsn32/bits/stdint.h b/arch/mipsn32/bits/stdint.h
deleted file mode 100644
index d1b27121..00000000
--- a/arch/mipsn32/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT32_MIN
-#define INTPTR_MAX      INT32_MAX
-#define UINTPTR_MAX     UINT32_MAX
-#define PTRDIFF_MIN     INT32_MIN
-#define PTRDIFF_MAX     INT32_MAX
-#define SIZE_MAX        UINT32_MAX
diff --git a/arch/or1k/bits/posix.h b/arch/or1k/bits/posix.h
deleted file mode 100644
index 30a38714..00000000
--- a/arch/or1k/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_ILP32_OFFBIG  1
-#define _POSIX_V7_ILP32_OFFBIG  1
diff --git a/arch/or1k/bits/reg.h b/arch/or1k/bits/reg.h
deleted file mode 100644
index 0c7bffca..00000000
--- a/arch/or1k/bits/reg.h
+++ /dev/null
@@ -1,3 +0,0 @@
-#undef __WORDSIZE
-#define __WORDSIZE 32
-/* FIXME */
diff --git a/arch/or1k/bits/stdint.h b/arch/or1k/bits/stdint.h
deleted file mode 100644
index d1b27121..00000000
--- a/arch/or1k/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT32_MIN
-#define INTPTR_MAX      INT32_MAX
-#define UINTPTR_MAX     UINT32_MAX
-#define PTRDIFF_MIN     INT32_MIN
-#define PTRDIFF_MAX     INT32_MAX
-#define SIZE_MAX        UINT32_MAX
diff --git a/arch/powerpc/bits/posix.h b/arch/powerpc/bits/posix.h
deleted file mode 100644
index 30a38714..00000000
--- a/arch/powerpc/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_ILP32_OFFBIG  1
-#define _POSIX_V7_ILP32_OFFBIG  1
diff --git a/arch/powerpc/bits/reg.h b/arch/powerpc/bits/reg.h
deleted file mode 100644
index 0c7bffca..00000000
--- a/arch/powerpc/bits/reg.h
+++ /dev/null
@@ -1,3 +0,0 @@
-#undef __WORDSIZE
-#define __WORDSIZE 32
-/* FIXME */
diff --git a/arch/powerpc/bits/stdint.h b/arch/powerpc/bits/stdint.h
deleted file mode 100644
index d1b27121..00000000
--- a/arch/powerpc/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT32_MIN
-#define INTPTR_MAX      INT32_MAX
-#define UINTPTR_MAX     UINT32_MAX
-#define PTRDIFF_MIN     INT32_MIN
-#define PTRDIFF_MAX     INT32_MAX
-#define SIZE_MAX        UINT32_MAX
diff --git a/arch/powerpc64/bits/posix.h b/arch/powerpc64/bits/posix.h
deleted file mode 100644
index c37b94c1..00000000
--- a/arch/powerpc64/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_LP64_OFF64  1
-#define _POSIX_V7_LP64_OFF64  1
diff --git a/arch/powerpc64/bits/reg.h b/arch/powerpc64/bits/reg.h
deleted file mode 100644
index 49382c8f..00000000
--- a/arch/powerpc64/bits/reg.h
+++ /dev/null
@@ -1,3 +0,0 @@
-#undef __WORDSIZE
-#define __WORDSIZE 64
-/* FIXME */
diff --git a/arch/powerpc64/bits/stdint.h b/arch/powerpc64/bits/stdint.h
deleted file mode 100644
index 1bb147f2..00000000
--- a/arch/powerpc64/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT64_MIN
-#define INTPTR_MAX      INT64_MAX
-#define UINTPTR_MAX     UINT64_MAX
-#define PTRDIFF_MIN     INT64_MIN
-#define PTRDIFF_MAX     INT64_MAX
-#define SIZE_MAX        UINT64_MAX
diff --git a/arch/riscv32/bits/posix.h b/arch/riscv32/bits/posix.h
deleted file mode 100644
index 8897d37d..00000000
--- a/arch/riscv32/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_ILP32_OFFBIG 1
-#define _POSIX_V7_ILP32_OFFBIG 1
diff --git a/arch/riscv32/bits/reg.h b/arch/riscv32/bits/reg.h
deleted file mode 100644
index 0192a293..00000000
--- a/arch/riscv32/bits/reg.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#undef __WORDSIZE
-#define __WORDSIZE 32
diff --git a/arch/riscv32/bits/signal.h b/arch/riscv32/bits/signal.h
index 271e7da6..50b66ec9 100644
--- a/arch/riscv32/bits/signal.h
+++ b/arch/riscv32/bits/signal.h
@@ -19,7 +19,7 @@ struct __riscv_mc_d_ext_state {
 };
 
 struct __riscv_mc_q_ext_state {
-	unsigned long long __f[64] __attribute__((aligned(16)));
+	unsigned long long __f[64] __attribute__((__aligned__(16)));
 	unsigned int __fcsr;
 	unsigned int __reserved[3];
 };
diff --git a/arch/riscv32/bits/stdint.h b/arch/riscv32/bits/stdint.h
deleted file mode 100644
index d1b27121..00000000
--- a/arch/riscv32/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT32_MIN
-#define INTPTR_MAX      INT32_MAX
-#define UINTPTR_MAX     UINT32_MAX
-#define PTRDIFF_MIN     INT32_MIN
-#define PTRDIFF_MAX     INT32_MAX
-#define SIZE_MAX        UINT32_MAX
diff --git a/arch/riscv64/bits/posix.h b/arch/riscv64/bits/posix.h
deleted file mode 100644
index 8068ce98..00000000
--- a/arch/riscv64/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_LP64_OFF64 1
-#define _POSIX_V7_LP64_OFF64 1
diff --git a/arch/riscv64/bits/reg.h b/arch/riscv64/bits/reg.h
deleted file mode 100644
index 2633f39d..00000000
--- a/arch/riscv64/bits/reg.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#undef __WORDSIZE
-#define __WORDSIZE 64
diff --git a/arch/riscv64/bits/signal.h b/arch/riscv64/bits/signal.h
index 6a53feb7..56f8fe17 100644
--- a/arch/riscv64/bits/signal.h
+++ b/arch/riscv64/bits/signal.h
@@ -19,7 +19,7 @@ struct __riscv_mc_d_ext_state {
 };
 
 struct __riscv_mc_q_ext_state {
-	unsigned long long __f[64] __attribute__((aligned(16)));
+	unsigned long long __f[64] __attribute__((__aligned__(16)));
 	unsigned int __fcsr;
 	unsigned int __reserved[3];
 };
diff --git a/arch/riscv64/bits/stat.h b/arch/riscv64/bits/stat.h
deleted file mode 100644
index b7f4221b..00000000
--- a/arch/riscv64/bits/stat.h
+++ /dev/null
@@ -1,18 +0,0 @@
-struct stat {
-	dev_t st_dev;
-	ino_t st_ino;
-	mode_t st_mode;
-	nlink_t st_nlink;
-	uid_t st_uid;
-	gid_t st_gid;
-	dev_t st_rdev;
-	unsigned long __pad;
-	off_t st_size;
-	blksize_t st_blksize;
-	int __pad2;
-	blkcnt_t st_blocks;
-	struct timespec st_atim;
-	struct timespec st_mtim;
-	struct timespec st_ctim;
-	unsigned __unused[2];
-};
diff --git a/arch/riscv64/bits/stdint.h b/arch/riscv64/bits/stdint.h
deleted file mode 100644
index 1bb147f2..00000000
--- a/arch/riscv64/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT64_MIN
-#define INTPTR_MAX      INT64_MAX
-#define UINTPTR_MAX     UINT64_MAX
-#define PTRDIFF_MIN     INT64_MIN
-#define PTRDIFF_MAX     INT64_MAX
-#define SIZE_MAX        UINT64_MAX
diff --git a/arch/s390x/bits/posix.h b/arch/s390x/bits/posix.h
deleted file mode 100644
index c37b94c1..00000000
--- a/arch/s390x/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_LP64_OFF64  1
-#define _POSIX_V7_LP64_OFF64  1
diff --git a/arch/s390x/bits/reg.h b/arch/s390x/bits/reg.h
deleted file mode 100644
index 2633f39d..00000000
--- a/arch/s390x/bits/reg.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#undef __WORDSIZE
-#define __WORDSIZE 64
diff --git a/arch/s390x/bits/stdint.h b/arch/s390x/bits/stdint.h
deleted file mode 100644
index 1bb147f2..00000000
--- a/arch/s390x/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT64_MIN
-#define INTPTR_MAX      INT64_MAX
-#define UINTPTR_MAX     UINT64_MAX
-#define PTRDIFF_MIN     INT64_MIN
-#define PTRDIFF_MAX     INT64_MAX
-#define SIZE_MAX        UINT64_MAX
diff --git a/arch/s390x/bits/user.h b/arch/s390x/bits/user.h
index ff3f0483..47f94f20 100644
--- a/arch/s390x/bits/user.h
+++ b/arch/s390x/bits/user.h
@@ -1,6 +1,3 @@
-#undef __WORDSIZE
-#define __WORDSIZE 64
-
 typedef union {
 	double d;
 	float f;
diff --git a/arch/sh/bits/posix.h b/arch/sh/bits/posix.h
deleted file mode 100644
index 30a38714..00000000
--- a/arch/sh/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_ILP32_OFFBIG  1
-#define _POSIX_V7_ILP32_OFFBIG  1
diff --git a/arch/sh/bits/stdint.h b/arch/sh/bits/stdint.h
deleted file mode 100644
index d1b27121..00000000
--- a/arch/sh/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT32_MIN
-#define INTPTR_MAX      INT32_MAX
-#define UINTPTR_MAX     UINT32_MAX
-#define PTRDIFF_MIN     INT32_MIN
-#define PTRDIFF_MAX     INT32_MAX
-#define SIZE_MAX        UINT32_MAX
diff --git a/arch/sh/bits/user.h b/arch/sh/bits/user.h
index 07fe843b..b6ba16ed 100644
--- a/arch/sh/bits/user.h
+++ b/arch/sh/bits/user.h
@@ -1,6 +1,3 @@
-#undef __WORDSIZE
-#define __WORDSIZE 32
-
 #define REG_REG0	 0
 #define REG_REG15	15
 #define REG_PC		16
diff --git a/arch/x32/bits/posix.h b/arch/x32/bits/posix.h
deleted file mode 100644
index 30a38714..00000000
--- a/arch/x32/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_ILP32_OFFBIG  1
-#define _POSIX_V7_ILP32_OFFBIG  1
diff --git a/arch/x32/bits/reg.h b/arch/x32/bits/reg.h
index 5faaef1a..6e54abcf 100644
--- a/arch/x32/bits/reg.h
+++ b/arch/x32/bits/reg.h
@@ -1,5 +1,3 @@
-#undef __WORDSIZE
-#define __WORDSIZE 32
 #define R15    0
 #define R14    1
 #define R13    2
diff --git a/arch/x32/bits/stdint.h b/arch/x32/bits/stdint.h
deleted file mode 100644
index d1b27121..00000000
--- a/arch/x32/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT32_MIN
-#define INTPTR_MAX      INT32_MAX
-#define UINTPTR_MAX     UINT32_MAX
-#define PTRDIFF_MIN     INT32_MIN
-#define PTRDIFF_MAX     INT32_MAX
-#define SIZE_MAX        UINT32_MAX
diff --git a/arch/x32/bits/user.h b/arch/x32/bits/user.h
index eac82a14..b328edf9 100644
--- a/arch/x32/bits/user.h
+++ b/arch/x32/bits/user.h
@@ -1,6 +1,3 @@
-#undef __WORDSIZE
-#define __WORDSIZE 32
-
 typedef struct user_fpregs_struct {
 	uint16_t cwd, swd, ftw, fop;
 	uint64_t rip, rdp;
diff --git a/arch/x86_64/bits/posix.h b/arch/x86_64/bits/posix.h
deleted file mode 100644
index c37b94c1..00000000
--- a/arch/x86_64/bits/posix.h
+++ /dev/null
@@ -1,2 +0,0 @@
-#define _POSIX_V6_LP64_OFF64  1
-#define _POSIX_V7_LP64_OFF64  1
diff --git a/arch/x86_64/bits/reg.h b/arch/x86_64/bits/reg.h
index a4df04ce..6e54abcf 100644
--- a/arch/x86_64/bits/reg.h
+++ b/arch/x86_64/bits/reg.h
@@ -1,5 +1,3 @@
-#undef __WORDSIZE
-#define __WORDSIZE 64
 #define R15    0
 #define R14    1
 #define R13    2
diff --git a/arch/x86_64/bits/stdint.h b/arch/x86_64/bits/stdint.h
deleted file mode 100644
index 1bb147f2..00000000
--- a/arch/x86_64/bits/stdint.h
+++ /dev/null
@@ -1,20 +0,0 @@
-typedef int32_t int_fast16_t;
-typedef int32_t int_fast32_t;
-typedef uint32_t uint_fast16_t;
-typedef uint32_t uint_fast32_t;
-
-#define INT_FAST16_MIN  INT32_MIN
-#define INT_FAST32_MIN  INT32_MIN
-
-#define INT_FAST16_MAX  INT32_MAX
-#define INT_FAST32_MAX  INT32_MAX
-
-#define UINT_FAST16_MAX UINT32_MAX
-#define UINT_FAST32_MAX UINT32_MAX
-
-#define INTPTR_MIN      INT64_MIN
-#define INTPTR_MAX      INT64_MAX
-#define UINTPTR_MAX     UINT64_MAX
-#define PTRDIFF_MIN     INT64_MIN
-#define PTRDIFF_MAX     INT64_MAX
-#define SIZE_MAX        UINT64_MAX
diff --git a/arch/x86_64/bits/user.h b/arch/x86_64/bits/user.h
index 4073cc06..b328edf9 100644
--- a/arch/x86_64/bits/user.h
+++ b/arch/x86_64/bits/user.h
@@ -1,6 +1,3 @@
-#undef __WORDSIZE
-#define __WORDSIZE 64
-
 typedef struct user_fpregs_struct {
 	uint16_t cwd, swd, ftw, fop;
 	uint64_t rip, rdp;
diff --git a/crt/aarch64/crti.s b/crt/aarch64/crti.s
index 775df0ac..3776fa64 100644
--- a/crt/aarch64/crti.s
+++ b/crt/aarch64/crti.s
@@ -1,6 +1,7 @@
 .section .init
 .global _init
 .type _init,%function
+.align 2
 _init:
 	stp x29,x30,[sp,-16]!
 	mov x29,sp
@@ -8,6 +9,7 @@ _init:
 .section .fini
 .global _fini
 .type _fini,%function
+.align 2
 _fini:
 	stp x29,x30,[sp,-16]!
 	mov x29,sp
diff --git a/include/dirent.h b/include/dirent.h
index 2d8fffb2..7fa60e06 100644
--- a/include/dirent.h
+++ b/include/dirent.h
@@ -9,14 +9,23 @@ extern "C" {
 
 #define __NEED_ino_t
 #define __NEED_off_t
-#if defined(_BSD_SOURCE) || defined(_GNU_SOURCE)
 #define __NEED_size_t
-#endif
+#define __NEED_ssize_t
 
 #include <bits/alltypes.h>
 
 #include <bits/dirent.h>
 
+typedef unsigned short reclen_t;
+
+struct posix_dent {
+	ino_t d_ino;
+	off_t d_off;
+	reclen_t d_reclen;
+	unsigned char d_type;
+	char d_name[];
+};
+
 typedef struct __dirstream DIR;
 
 #define d_fileno d_ino
@@ -29,6 +38,8 @@ int            readdir_r(DIR *__restrict, struct dirent *__restrict, struct dire
 void           rewinddir(DIR *);
 int            dirfd(DIR *);
 
+ssize_t posix_getdents(int, void *, size_t, int);
+
 int alphasort(const struct dirent **, const struct dirent **);
 int scandir(const char *, struct dirent ***, int (*)(const struct dirent *), int (*)(const struct dirent **, const struct dirent **));
 
@@ -37,7 +48,6 @@ void           seekdir(DIR *, long);
 long           telldir(DIR *);
 #endif
 
-#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
 #define DT_UNKNOWN 0
 #define DT_FIFO 1
 #define DT_CHR 2
@@ -47,6 +57,8 @@ long           telldir(DIR *);
 #define DT_LNK 10
 #define DT_SOCK 12
 #define DT_WHT 14
+
+#if defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
 #define IFTODT(x) ((x)>>12 & 017)
 #define DTTOIF(x) ((x)<<12)
 int getdents(int, struct dirent *, size_t);
diff --git a/include/stdio.h b/include/stdio.h
index cb858618..4ea4c170 100644
--- a/include/stdio.h
+++ b/include/stdio.h
@@ -158,6 +158,13 @@ char *ctermid(char *);
 #define L_ctermid 20
 #endif
 
+#if defined(_GNU_SOURCE)
+#define RENAME_NOREPLACE (1 << 0)
+#define RENAME_EXCHANGE  (1 << 1)
+#define RENAME_WHITEOUT  (1 << 2)
+
+int renameat2(int, const char *, int, const char *, unsigned);
+#endif
 
 #if defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) \
  || defined(_BSD_SOURCE)
diff --git a/include/sys/epoll.h b/include/sys/epoll.h
index ac81a841..5f975c4a 100644
--- a/include/sys/epoll.h
+++ b/include/sys/epoll.h
@@ -7,6 +7,7 @@ extern "C" {
 
 #include <stdint.h>
 #include <sys/types.h>
+#include <sys/ioctl.h>
 #include <fcntl.h>
 
 #define __NEED_sigset_t
@@ -54,6 +55,17 @@ __attribute__ ((__packed__))
 #endif
 ;
 
+struct epoll_params {
+	uint32_t busy_poll_usecs;
+	uint16_t busy_poll_budget;
+	uint8_t prefer_busy_poll;
+
+	uint8_t __pad;
+};
+
+#define EPOLL_IOC_TYPE 0x8A
+#define EPIOCSPARAMS _IOW(EPOLL_IOC_TYPE, 0x01, struct epoll_params)
+#define EPIOCGPARAMS _IOR(EPOLL_IOC_TYPE, 0x02, struct epoll_params)
 
 int epoll_create(int);
 int epoll_create1(int);
diff --git a/include/sys/reg.h b/include/sys/reg.h
index b47452d0..0272e137 100644
--- a/include/sys/reg.h
+++ b/include/sys/reg.h
@@ -4,6 +4,15 @@
 #include <limits.h>
 #include <unistd.h>
 
+#include <bits/alltypes.h>
+
+#undef __WORDSIZE
+#if __LONG_MAX == 0x7fffffffL
+#define __WORDSIZE 32
+#else
+#define __WORDSIZE 64
+#endif
+
 #include <bits/reg.h>
 
 #endif
diff --git a/include/sys/stat.h b/include/sys/stat.h
index 6690192d..57d640d7 100644
--- a/include/sys/stat.h
+++ b/include/sys/stat.h
@@ -121,6 +121,16 @@ int lchmod(const char *, mode_t);
 #define STATX_BTIME 0x800U
 #define STATX_ALL 0xfffU
 
+#define STATX_ATTR_COMPRESSED 0x4
+#define STATX_ATTR_IMMUTABLE 0x10
+#define STATX_ATTR_APPEND 0x20
+#define STATX_ATTR_NODUMP 0x40
+#define STATX_ATTR_ENCRYPTED 0x800
+#define STATX_ATTR_AUTOMOUNT 0x1000
+#define STATX_ATTR_MOUNT_ROOT 0x2000
+#define STATX_ATTR_VERITY 0x100000
+#define STATX_ATTR_DAX 0x200000
+
 struct statx_timestamp {
 	int64_t tv_sec;
 	uint32_t tv_nsec, __pad;
diff --git a/include/sys/uio.h b/include/sys/uio.h
index 8b5e3de7..5e99c7fa 100644
--- a/include/sys/uio.h
+++ b/include/sys/uio.h
@@ -46,6 +46,7 @@ ssize_t pwritev2 (int, const struct iovec *, int, off_t, int);
 #define RWF_SYNC 0x00000004
 #define RWF_NOWAIT 0x00000008
 #define RWF_APPEND 0x00000010
+#define RWF_NOAPPEND 0x00000020
 #endif
 
 #ifdef __cplusplus
diff --git a/include/sys/user.h b/include/sys/user.h
index 96a03400..511caba3 100644
--- a/include/sys/user.h
+++ b/include/sys/user.h
@@ -8,6 +8,15 @@ extern "C" {
 #include <stdint.h>
 #include <unistd.h>
 
+#include <bits/alltypes.h>
+
+#undef __WORDSIZE
+#if __LONG_MAX == 0x7fffffffL
+#define __WORDSIZE 32
+#else
+#define __WORDSIZE 64
+#endif
+
 #include <bits/user.h>
 
 #ifdef __cplusplus
diff --git a/include/syslog.h b/include/syslog.h
index 5b4d2964..57599e07 100644
--- a/include/syslog.h
+++ b/include/syslog.h
@@ -18,7 +18,7 @@ extern "C" {
 
 #define LOG_PRIMASK 7
 #define LOG_PRI(p) ((p)&LOG_PRIMASK)
-#define	LOG_MAKEPRI(f, p) (((f)<<3)|(p))
+#define	LOG_MAKEPRI(f, p) ((f)|(p))
 
 #define LOG_MASK(p) (1<<(p))
 #define LOG_UPTO(p) ((1<<((p)+1))-1)
diff --git a/include/unistd.h b/include/unistd.h
index 5bc7f798..42b0e82b 100644
--- a/include/unistd.h
+++ b/include/unistd.h
@@ -257,7 +257,13 @@ pid_t gettid(void);
 
 #define _POSIX2_C_BIND          _POSIX_VERSION
 
-#include <bits/posix.h>
+#if __LONG_MAX == 0x7fffffffL
+#define _POSIX_V6_ILP32_OFFBIG  1
+#define _POSIX_V7_ILP32_OFFBIG  1
+#else
+#define _POSIX_V6_LP64_OFF64  1
+#define _POSIX_V7_LP64_OFF64  1
+#endif
 
 
 
diff --git a/ldso/dynlink.c b/ldso/dynlink.c
index e3eae3d5..5b5363c2 100644
--- a/ldso/dynlink.c
+++ b/ldso/dynlink.c
@@ -21,15 +21,17 @@
 #include <sys/membarrier.h>
 #include "pthread_impl.h"
 #include "fork_impl.h"
+#include "libc.h"
 #include "dynlink.h"
 
 static size_t ldso_page_size;
-#ifndef PAGE_SIZE
+/* libc.h may have defined a macro for dynamic PAGE_SIZE already, but
+ * PAGESIZE is only defined if it's constant for the arch. */
+#ifndef PAGESIZE
+#undef PAGE_SIZE
 #define PAGE_SIZE ldso_page_size
 #endif
 
-#include "libc.h"
-
 #define STRINGIFY(x) __STRINGIFY(x)
 #define __STRINGIFY(x) #x
 
@@ -366,19 +368,14 @@ static struct symdef get_lfs64(const char *name)
 		"pwritev\0readdir\0scandir\0sendfile\0setrlimit\0"
 		"stat\0statfs\0statvfs\0tmpfile\0truncate\0versionsort\0"
 		"__fxstat\0__fxstatat\0__lxstat\0__xstat\0";
-	size_t l;
-	char buf[16];
-	for (l=0; name[l]; l++) {
-		if (l >= sizeof buf) goto nomatch;
-		buf[l] = name[l];
-	}
 	if (!strcmp(name, "readdir64_r"))
 		return find_sym(&ldso, "readdir_r", 1);
-	if (l<2 || name[l-2]!='6' || name[l-1]!='4')
+	size_t l = strnlen(name, 18);
+	if (l<2 || name[l-2]!='6' || name[l-1]!='4' || name[l])
 		goto nomatch;
-	buf[l-=2] = 0;
 	for (p=lfs64_list; *p; p++) {
-		if (!strcmp(buf, p)) return find_sym(&ldso, buf, 1);
+		if (!strncmp(name, p, l-2) && !p[l-2])
+			return find_sym(&ldso, p, 1);
 		while (*p) p++;
 	}
 nomatch:
@@ -907,20 +904,20 @@ static int path_open_library(const char *name, const char *s, char *buf, size_t
 		if (snprintf(buf, buf_size, "%.*s/%s", (int)l, p, name) < buf_size) {
 			fd = open(buf, O_RDONLY|O_CLOEXEC);
 			if (fd < 0) {
-				switch (errno) {
-				case ENOENT:
-				case ENOTDIR:
-				case EACCES:
-				case ENAMETOOLONG:
+			switch (errno) {
+			case ENOENT:
+			case ENOTDIR:
+			case EACCES:
+			case ENAMETOOLONG:
 					/* Keep searching in path list. */
 					continue;
-				default:
+			default:
 					/* Any negative value but -1 will
 					 * inhibit further path search in
 					 * load_library. */
-					return -2;
-				}
+				return -2;
 			}
+		}
 			Ehdr eh;
 			ssize_t n = pread(fd, &eh, sizeof eh, 0);
 			/* If the elf file is invalid return -2 to inhibit
diff --git a/sources.bp b/sources.bp
index 1d61870d..873b2a7f 100644
--- a/sources.bp
+++ b/sources.bp
@@ -143,6 +143,7 @@ cc_defaults {
         "src/dirent/dirfd.c",
         "src/dirent/fdopendir.c",
         "src/dirent/opendir.c",
+        "src/dirent/posix_getdents.c",
         "src/dirent/readdir.c",
         "src/dirent/readdir_r.c",
         "src/dirent/rewinddir.c",
@@ -260,6 +261,7 @@ cc_defaults {
         "src/linux/readahead.c",
         "src/linux/reboot.c",
         "src/linux/remap_file_pages.c",
+        "src/linux/renameat2.c",
         "src/linux/sbrk.c",
         "src/linux/sendfile.c",
         "src/linux/setfsgid.c",
diff --git a/src/complex/cacosh.c b/src/complex/cacosh.c
index 76127f75..55b857ce 100644
--- a/src/complex/cacosh.c
+++ b/src/complex/cacosh.c
@@ -1,6 +1,6 @@
 #include "complex_impl.h"
 
-/* acosh(z) = i acos(z) */
+/* acosh(z) = ±i acos(z) */
 
 double complex cacosh(double complex z)
 {
diff --git a/src/dirent/posix_getdents.c b/src/dirent/posix_getdents.c
new file mode 100644
index 00000000..26c16ac6
--- /dev/null
+++ b/src/dirent/posix_getdents.c
@@ -0,0 +1,11 @@
+#include <dirent.h>
+#include <limits.h>
+#include <errno.h>
+#include "syscall.h"
+
+ssize_t posix_getdents(int fd, void *buf, size_t len, int flags)
+{
+	if (flags) return __syscall_ret(-EOPNOTSUPP);
+	if (len>INT_MAX) len = INT_MAX;
+	return syscall(SYS_getdents, fd, buf, len);
+}
diff --git a/src/internal/atomic.h b/src/internal/atomic.h
index 5207c632..a61b77b5 100644
--- a/src/internal/atomic.h
+++ b/src/internal/atomic.h
@@ -194,7 +194,7 @@ static inline void a_store(volatile int *p, int v)
 
 #ifndef a_barrier
 #define a_barrier a_barrier
-static void a_barrier()
+static inline void a_barrier()
 {
 	volatile int tmp = 0;
 	a_cas(&tmp, 0, 0);
diff --git a/src/legacy/getusershell.c b/src/legacy/getusershell.c
index 5fecdec2..1c5d98ec 100644
--- a/src/legacy/getusershell.c
+++ b/src/legacy/getusershell.c
@@ -25,8 +25,10 @@ char *getusershell(void)
 	ssize_t l;
 	if (!f) setusershell();
 	if (!f) return 0;
-	l = getline(&line, &linesize, f);
-	if (l <= 0) return 0;
+	do {
+		l = getline(&line, &linesize, f);
+		if (l <= 0) return 0;
+	} while (line[0] == '#' || line[0] == '\n');
 	if (line[l-1]=='\n') line[l-1]=0;
 	return line;
 }
diff --git a/src/linux/renameat2.c b/src/linux/renameat2.c
new file mode 100644
index 00000000..b8060388
--- /dev/null
+++ b/src/linux/renameat2.c
@@ -0,0 +1,11 @@
+#define _GNU_SOURCE
+#include <stdio.h>
+#include "syscall.h"
+
+int renameat2(int oldfd, const char *old, int newfd, const char *new, unsigned flags)
+{
+#ifdef SYS_renameat
+	if (!flags) return syscall(SYS_renameat, oldfd, old, newfd, new);
+#endif
+	return syscall(SYS_renameat2, oldfd, old, newfd, new, flags);
+}
diff --git a/src/locale/iconv.c b/src/locale/iconv.c
index 175def1c..7fb2e1ef 100644
--- a/src/locale/iconv.c
+++ b/src/locale/iconv.c
@@ -52,7 +52,7 @@ static const unsigned char charmaps[] =
 "shiftjis\0sjis\0cp932\0\0\321"
 "iso2022jp\0\0\322"
 "gb18030\0\0\330"
-"gbk\0\0\331"
+"gbk\0cp936\0windows936\0\0\331"
 "gb2312\0\0\332"
 "big5\0bigfive\0cp950\0big5hkscs\0\0\340"
 "euckr\0ksc5601\0ksx1001\0cp949\0\0\350"
@@ -340,6 +340,7 @@ size_t iconv(iconv_t cd, char **restrict in, size_t *restrict inb, char **restri
 				c++;
 				d -= 159;
 			}
+			if (c>=84) goto ilseq;
 			c = jis0208[c][d];
 			if (!c) goto ilseq;
 			break;
@@ -403,6 +404,10 @@ size_t iconv(iconv_t cd, char **restrict in, size_t *restrict inb, char **restri
 			if (c < 128) break;
 			if (c < 0xa1) goto ilseq;
 		case GBK:
+			if (c == 128) {
+				c = 0x20ac;
+				break;
+			}
 		case GB18030:
 			if (c < 128) break;
 			c -= 0x81;
diff --git a/src/math/fma.c b/src/math/fma.c
index 0c6f90c9..adfadca8 100644
--- a/src/math/fma.c
+++ b/src/math/fma.c
@@ -53,7 +53,7 @@ double fma(double x, double y, double z)
 		return x*y + z;
 	if (nz.e >= ZEROINFNAN) {
 		if (nz.e > ZEROINFNAN) /* z==0 */
-			return x*y + z;
+			return x*y;
 		return z;
 	}
 
diff --git a/src/misc/initgroups.c b/src/misc/initgroups.c
index 922a9581..101f5c7b 100644
--- a/src/misc/initgroups.c
+++ b/src/misc/initgroups.c
@@ -1,11 +1,29 @@
 #define _GNU_SOURCE
 #include <grp.h>
 #include <limits.h>
+#include <stdlib.h>
 
 int initgroups(const char *user, gid_t gid)
 {
-	gid_t groups[NGROUPS_MAX];
-	int count = NGROUPS_MAX;
-	if (getgrouplist(user, gid, groups, &count) < 0) return -1;
-	return setgroups(count, groups);
+	gid_t buf[32], *groups = buf;
+	int count = sizeof buf / sizeof *buf, prev_count = count;
+	while (getgrouplist(user, gid, groups, &count) < 0) {
+		if (groups != buf) free(groups);
+
+		/* Return if failure isn't buffer size */
+		if (count <= prev_count)
+			return -1;
+
+		/* Always increase by at least 50% to limit to
+		 * logarithmically many retries on TOCTOU races. */
+		if (count < prev_count + (prev_count>>1))
+			count = prev_count + (prev_count>>1);
+
+		groups = calloc(count, sizeof *groups);
+		if (!groups) return -1;
+		prev_count = count;
+	}
+	int ret = setgroups(count, groups);
+	if (groups != buf) free(groups);
+	return ret;
 }
diff --git a/src/network/inet_ntop.c b/src/network/inet_ntop.c
index 4bfef2c5..f442f47d 100644
--- a/src/network/inet_ntop.c
+++ b/src/network/inet_ntop.c
@@ -34,7 +34,12 @@ const char *inet_ntop(int af, const void *restrict a0, char *restrict s, socklen
 		for (i=best=0, max=2; buf[i]; i++) {
 			if (i && buf[i] != ':') continue;
 			j = strspn(buf+i, ":0");
-			if (j>max) best=i, max=j;
+			/* The leading sequence of zeros (best==0) is
+			 * disadvantaged compared to sequences elsewhere
+			 * as it doesn't have a leading colon. One extra
+			 * character is required for another sequence to
+			 * beat it fairly. */
+			if (j>max+(best==0)) best=i, max=j;
 		}
 		if (max>3) {
 			buf[best] = buf[best+1] = ':';
diff --git a/src/signal/siglongjmp.c b/src/signal/siglongjmp.c
index bc317acc..53789b23 100644
--- a/src/signal/siglongjmp.c
+++ b/src/signal/siglongjmp.c
@@ -5,5 +5,10 @@
 
 _Noreturn void siglongjmp(sigjmp_buf buf, int ret)
 {
+	/* If sigsetjmp was called with nonzero savemask flag, the address
+	 * longjmp will return to is inside of sigsetjmp. The signal mask
+	 * will then be restored in the returned-to context instead of here,
+	 * which matters if the context we are returning from may not have
+	 * sufficient stack space for signal delivery. */
 	longjmp(buf, ret);
 }
diff --git a/src/stdio/vfprintf.c b/src/stdio/vfprintf.c
index 497c5e19..360d723a 100644
--- a/src/stdio/vfprintf.c
+++ b/src/stdio/vfprintf.c
@@ -166,7 +166,8 @@ static char *fmt_u(uintmax_t x, char *s)
 {
 	unsigned long y;
 	for (   ; x>ULONG_MAX; x/=10) *--s = '0' + x%10;
-	for (y=x;           y; y/=10) *--s = '0' + y%10;
+	for (y=x;       y>=10; y/=10) *--s = '0' + y%10;
+	if (y) *--s = '0' + y;
 	return s;
 }
 
@@ -211,18 +212,11 @@ static int fmt_fp(FILE *f, long double y, int w, int p, int fl, int t)
 	if (y) e2--;
 
 	if ((t|32)=='a') {
-		long double round = 8.0;
-		int re;
-
 		if (t&32) prefix += 9;
 		pl += 2;
 
-		if (p<0 || p>=LDBL_MANT_DIG/4-1) re=0;
-		else re=LDBL_MANT_DIG/4-1-p;
-
-		if (re) {
-			round *= 1<<(LDBL_MANT_DIG%4);
-			while (re--) round*=16;
+		if (p>=0 && p<(LDBL_MANT_DIG-1+3)/4) {
+			double round = scalbn(1, LDBL_MANT_DIG-1-(p*4));
 			if (*prefix=='-') {
 				y=-y;
 				y-=round;
diff --git a/src/time/strptime.c b/src/time/strptime.c
index c54a0d8c..b1147242 100644
--- a/src/time/strptime.c
+++ b/src/time/strptime.c
@@ -59,6 +59,22 @@ char *strptime(const char *restrict s, const char *restrict f, struct tm *restri
 			s = strptime(s, "%m/%d/%y", tm);
 			if (!s) return 0;
 			break;
+		case 'F':
+			/* Use temp buffer to implement the odd requirement
+			 * that entire field be width-limited but the year
+			 * subfield not itself be limited. */
+			i = 0;
+			char tmp[20];
+			if (*s == '-' || *s == '+') tmp[i++] = *s++;
+			while (*s=='0' && isdigit(s[1])) s++;
+			for (; *s && i<(size_t)w && i+1<sizeof tmp; i++) {
+				tmp[i] = *s++;
+			}
+			tmp[i] = 0;
+			char *p = strptime(tmp, "%12Y-%m-%d", tm);
+			if (!p) return 0;
+			s -= tmp+i-p;
+			break;
 		case 'H':
 			dest = &tm->tm_hour;
 			min = 0;
@@ -114,6 +130,13 @@ char *strptime(const char *restrict s, const char *restrict f, struct tm *restri
 			s = strptime(s, "%H:%M", tm);
 			if (!s) return 0;
 			break;
+		case 's':
+			/* Parse only. Effect on tm is unspecified
+			 * and presently no effect is implemented.. */
+			if (*s == '-') s++;
+			if (!isdigit(*s)) return 0;
+			while (isdigit(*s)) s++;
+			break;
 		case 'S':
 			dest = &tm->tm_sec;
 			min = 0;
@@ -125,11 +148,30 @@ char *strptime(const char *restrict s, const char *restrict f, struct tm *restri
 			break;
 		case 'U':
 		case 'W':
-			/* Throw away result, for now. (FIXME?) */
+			/* Throw away result of %U, %V, %W, %g, and %G. Effect
+			 * is unspecified and there is no clear right choice. */
 			dest = &dummy;
 			min = 0;
 			range = 54;
 			goto numeric_range;
+		case 'V':
+			dest = &dummy;
+			min = 1;
+			range = 53;
+			goto numeric_range;
+		case 'g':
+			dest = &dummy;
+			w = 2;
+			goto numeric_digits;
+		case 'G':
+			dest = &dummy;
+			if (w<0) w=4;
+			goto numeric_digits;
+		case 'u':
+			dest = &tm->tm_wday;
+			min = 1;
+			range = 7;
+			goto numeric_range;
 		case 'w':
 			dest = &tm->tm_wday;
 			min = 0;
@@ -154,6 +196,28 @@ char *strptime(const char *restrict s, const char *restrict f, struct tm *restri
 			adj = 1900;
 			want_century = 0;
 			goto numeric_digits;
+		case 'z':
+			if (*s == '+') neg = 0;
+			else if (*s == '-') neg = 1;
+			else return 0;
+			for (i=0; i<4; i++) if (!isdigit(s[1+i])) return 0;
+			tm->__tm_gmtoff = (s[1]-'0')*36000+(s[2]-'0')*3600
+				+ (s[3]-'0')*600 + (s[4]-'0')*60;
+			if (neg) tm->__tm_gmtoff = -tm->__tm_gmtoff;
+			s += 5;
+			break;
+		case 'Z':
+			if (!strncmp(s, tzname[0], len = strlen(tzname[0]))) {
+				tm->tm_isdst = 0;
+				s += len;
+			} else if (!strncmp(s, tzname[1], len=strlen(tzname[1]))) {
+				tm->tm_isdst = 1;
+				s += len;
+			} else {
+				/* FIXME: is this supposed to be an error? */
+				while ((*s|32)-'a' <= 'z'-'a') s++;
+			}
+			break;
 		case '%':
 			if (*s++ != '%') return 0;
 			break;
diff --git a/src/unistd/pwrite.c b/src/unistd/pwrite.c
index 869b69f0..a008b3ec 100644
--- a/src/unistd/pwrite.c
+++ b/src/unistd/pwrite.c
@@ -1,7 +1,18 @@
+#define _GNU_SOURCE
 #include <unistd.h>
+#include <sys/uio.h>
+#include <fcntl.h>
 #include "syscall.h"
 
 ssize_t pwrite(int fd, const void *buf, size_t size, off_t ofs)
 {
+	if (ofs == -1) ofs--;
+	int r = __syscall_cp(SYS_pwritev2, fd,
+		(&(struct iovec){ .iov_base = (void *)buf, .iov_len = size }),
+		1, (long)(ofs), (long)(ofs>>32), RWF_NOAPPEND);
+	if (r != -EOPNOTSUPP && r != -ENOSYS)
+		return __syscall_ret(r);
+	if (fcntl(fd, F_GETFL) & O_APPEND)
+		return __syscall_ret(-EOPNOTSUPP);
 	return syscall_cp(SYS_pwrite, fd, buf, size, __SYSCALL_LL_PRW(ofs));
 }
diff --git a/src/unistd/pwritev.c b/src/unistd/pwritev.c
index becf9deb..44a53d85 100644
--- a/src/unistd/pwritev.c
+++ b/src/unistd/pwritev.c
@@ -1,10 +1,18 @@
-#define _BSD_SOURCE
+#define _GNU_SOURCE
 #include <sys/uio.h>
 #include <unistd.h>
+#include <fcntl.h>
 #include "syscall.h"
 
 ssize_t pwritev(int fd, const struct iovec *iov, int count, off_t ofs)
 {
+	if (ofs == -1) ofs--;
+	int r = __syscall_cp(SYS_pwritev2, fd, iov, count,
+		(long)(ofs), (long)(ofs>>32), RWF_NOAPPEND);
+	if (r != -EOPNOTSUPP && r != -ENOSYS)
+		return __syscall_ret(r);
+	if (fcntl(fd, F_GETFL) & O_APPEND)
+		return __syscall_ret(-EOPNOTSUPP);
 	return syscall_cp(SYS_pwritev, fd, iov, count,
 		(long)(ofs), (long)(ofs>>32));
 }
```

