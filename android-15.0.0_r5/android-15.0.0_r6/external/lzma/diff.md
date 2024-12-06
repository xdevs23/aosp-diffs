```diff
diff --git a/Android.bp b/Android.bp
index 752a8f9..828650c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -81,15 +81,6 @@ cc_library {
         "C/XzIn.c",
     ],
 
-    arch: {
-        arm: {
-            cflags: ["-march=armv8-a+crypto"],
-        },
-        arm64: {
-            cflags: ["-march=armv8-a+crypto"],
-        },
-    },
-
     target: {
         linux_bionic: {
             enabled: true,
diff --git a/Asm/x86/LzFindOpt.asm b/Asm/x86/LzFindOpt.asm
index 42e10bd..94c5c76 100644
--- a/Asm/x86/LzFindOpt.asm
+++ b/Asm/x86/LzFindOpt.asm
@@ -1,5 +1,5 @@
 ; LzFindOpt.asm -- ASM version of GetMatchesSpecN_2() function
-; 2021-07-21: Igor Pavlov : Public domain
+; 2024-06-18: Igor Pavlov : Public domain
 ;
 
 ifndef x64
@@ -11,10 +11,31 @@ include 7zAsm.asm
 
 MY_ASM_START
 
-_TEXT$LZFINDOPT SEGMENT ALIGN(64) 'CODE'
+ifndef Z7_LZ_FIND_OPT_ASM_USE_SEGMENT
+if (IS_LINUX gt 0)
+  Z7_LZ_FIND_OPT_ASM_USE_SEGMENT equ 1
+else
+  Z7_LZ_FIND_OPT_ASM_USE_SEGMENT equ 1
+endif
+endif
 
+ifdef Z7_LZ_FIND_OPT_ASM_USE_SEGMENT
+_TEXT$LZFINDOPT SEGMENT ALIGN(64) 'CODE'
 MY_ALIGN macro num:req
         align  num
+        ; align  16
+endm
+else
+MY_ALIGN macro num:req
+        ; We expect that ".text" is aligned for 16-bytes.
+        ; So we don't need large alignment inside our function.
+        align  16
+endm
+endif
+
+
+MY_ALIGN_16 macro
+        MY_ALIGN 16
 endm
 
 MY_ALIGN_32 macro
@@ -136,7 +157,11 @@ COPY_VAR_64 macro dest_var, src_var
 endm
 
 
+ifdef Z7_LZ_FIND_OPT_ASM_USE_SEGMENT
 ; MY_ALIGN_64
+else
+  MY_ALIGN_16
+endif
 MY_PROC GetMatchesSpecN_2, 13
 MY_PUSH_PRESERVED_ABI_REGS
         mov     r0, RSP
@@ -508,6 +533,8 @@ fin:
 MY_POP_PRESERVED_ABI_REGS
 MY_ENDP
 
+ifdef Z7_LZ_FIND_OPT_ASM_USE_SEGMENT
 _TEXT$LZFINDOPT ENDS
+endif
 
 end
diff --git a/Asm/x86/LzmaDecOpt.asm b/Asm/x86/LzmaDecOpt.asm
index f2818e7..7c568df 100644
--- a/Asm/x86/LzmaDecOpt.asm
+++ b/Asm/x86/LzmaDecOpt.asm
@@ -1,5 +1,5 @@
 ; LzmaDecOpt.asm -- ASM version of LzmaDec_DecodeReal_3() function
-; 2021-02-23: Igor Pavlov : Public domain
+; 2024-06-18: Igor Pavlov : Public domain
 ;
 ; 3 - is the code compatibility version of LzmaDec_DecodeReal_*()
 ; function for check at link time.
@@ -17,11 +17,41 @@ include 7zAsm.asm
 
 MY_ASM_START
 
-_TEXT$LZMADECOPT SEGMENT ALIGN(64) 'CODE'
+; if Z7_LZMA_DEC_OPT_ASM_USE_SEGMENT is     defined, we use additional SEGMENT with 64-byte alignment.
+; if Z7_LZMA_DEC_OPT_ASM_USE_SEGMENT is not defined, we use default SEGMENT (where default 16-byte alignment of segment is expected).
+; The performance is almost identical in our tests.
+; But the performance can depend from position of lzmadec code inside instruction cache
+; or micro-op cache line (depending from low address bits in 32-byte/64-byte cache lines).
+; And 64-byte alignment provides a more consistent speed regardless
+; of the code's position in the executable.
+; But also it's possible that code without Z7_LZMA_DEC_OPT_ASM_USE_SEGMENT can be
+; slightly faster than 64-bytes aligned code in some cases, if offset of lzmadec
+; code in 64-byte block after compilation provides better speed by some reason.
+; Note that Z7_LZMA_DEC_OPT_ASM_USE_SEGMENT adds an extra section to the ELF file.
+; If you don't want to get that extra section, do not define Z7_LZMA_DEC_OPT_ASM_USE_SEGMENT.
+
+ifndef Z7_LZMA_DEC_OPT_ASM_USE_SEGMENT
+if (IS_LINUX gt 0)
+  Z7_LZMA_DEC_OPT_ASM_USE_SEGMENT equ 1
+else
+  Z7_LZMA_DEC_OPT_ASM_USE_SEGMENT equ 1
+endif
+endif
 
+ifdef Z7_LZMA_DEC_OPT_ASM_USE_SEGMENT
+_TEXT$LZMADECOPT SEGMENT ALIGN(64) 'CODE'
 MY_ALIGN macro num:req
         align  num
+        ; align  16
 endm
+else
+MY_ALIGN macro num:req
+        ; We expect that ".text" is aligned for 16-bytes.
+        ; So we don't need large alignment inside out function.
+        align  16
+endm
+endif
+
 
 MY_ALIGN_16 macro
         MY_ALIGN 16
@@ -610,7 +640,11 @@ PARAM_lzma      equ REG_ABI_PARAM_0
 PARAM_limit     equ REG_ABI_PARAM_1
 PARAM_bufLimit  equ REG_ABI_PARAM_2
 
+ifdef Z7_LZMA_DEC_OPT_ASM_USE_SEGMENT
 ; MY_ALIGN_64
+else
+  MY_ALIGN_16
+endif
 MY_PROC LzmaDec_DecodeReal_3, 3
 MY_PUSH_PRESERVED_ABI_REGS
 
@@ -1298,6 +1332,8 @@ fin:
 MY_POP_PRESERVED_ABI_REGS
 MY_ENDP
 
+ifdef Z7_LZMA_DEC_OPT_ASM_USE_SEGMENT
 _TEXT$LZMADECOPT ENDS
+endif
 
 end
diff --git a/Asm/x86/Sha1Opt.asm b/Asm/x86/Sha1Opt.asm
index 3495fd1..0b63aeb 100644
--- a/Asm/x86/Sha1Opt.asm
+++ b/Asm/x86/Sha1Opt.asm
@@ -1,5 +1,5 @@
 ; Sha1Opt.asm -- SHA-1 optimized code for SHA-1 x86 hardware instructions
-; 2021-03-10 : Igor Pavlov : Public domain
+; 2024-06-16 : Igor Pavlov : Public domain
 
 include 7zAsm.asm
 
@@ -20,7 +20,7 @@ MY_ASM_START
 
 
 
-CONST   SEGMENT
+CONST   SEGMENT READONLY
 
 align 16
 Reverse_Endian_Mask db 15,14,13,12, 11,10,9,8, 7,6,5,4, 3,2,1,0
diff --git a/Asm/x86/Sha256Opt.asm b/Asm/x86/Sha256Opt.asm
index 3e9f6ed..bc2f9da 100644
--- a/Asm/x86/Sha256Opt.asm
+++ b/Asm/x86/Sha256Opt.asm
@@ -1,5 +1,5 @@
 ; Sha256Opt.asm -- SHA-256 optimized code for SHA-256 x86 hardware instructions
-; 2022-04-17 : Igor Pavlov : Public domain
+; 2024-06-16 : Igor Pavlov : Public domain
 
 include 7zAsm.asm
 
@@ -20,7 +20,7 @@ endif
 EXTRN   K_CONST:xmmword
 @
 
-CONST   SEGMENT
+CONST   SEGMENT READONLY
 
 align 16
 Reverse_Endian_Mask db 3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12
diff --git a/C/7zVersion.h b/C/7zVersion.h
index 72b915a..1ddef80 100644
--- a/C/7zVersion.h
+++ b/C/7zVersion.h
@@ -1,7 +1,7 @@
 #define MY_VER_MAJOR 24
-#define MY_VER_MINOR 05
+#define MY_VER_MINOR 8
 #define MY_VER_BUILD 0
-#define MY_VERSION_NUMBERS "24.05"
+#define MY_VERSION_NUMBERS "24.08"
 #define MY_VERSION MY_VERSION_NUMBERS
 
 #ifdef MY_CPU_NAME
@@ -10,7 +10,7 @@
   #define MY_VERSION_CPU MY_VERSION
 #endif
 
-#define MY_DATE "2024-05-14"
+#define MY_DATE "2024-08-11"
 #undef MY_COPYRIGHT
 #undef MY_VERSION_COPYRIGHT_DATE
 #define MY_AUTHOR_NAME "Igor Pavlov"
diff --git a/C/Blake2s.c b/C/Blake2s.c
index 459e76b..abb907d 100644
--- a/C/Blake2s.c
+++ b/C/Blake2s.c
@@ -1,5 +1,5 @@
 /* Blake2s.c -- BLAKE2sp Hash
-2024-01-29 : Igor Pavlov : Public domain
+2024-05-18 : Igor Pavlov : Public domain
 2015-2019 : Samuel Neves : original code : CC0 1.0 Universal (CC0 1.0). */
 
 #include "Precomp.h"
@@ -12,6 +12,17 @@
 #include "Compiler.h"
 #include "CpuArch.h"
 
+/*
+  if defined(__AVX512F__) && defined(__AVX512VL__)
+  {
+    we define Z7_BLAKE2S_USE_AVX512_ALWAYS,
+    but the compiler can use avx512 for any code.
+  }
+  else if defined(Z7_BLAKE2S_USE_AVX512_ALWAYS)
+    { we use avx512 only for sse* and avx* branches of code. }
+*/
+// #define Z7_BLAKE2S_USE_AVX512_ALWAYS // for debug
+
 #if defined(__SSE2__)
     #define Z7_BLAKE2S_USE_VECTORS
 #elif defined(MY_CPU_X86_OR_AMD64)
@@ -59,6 +70,9 @@
 #endif // SSSE3
 
 #if defined(__GNUC__) || defined(__clang__)
+#if defined(Z7_BLAKE2S_USE_AVX512_ALWAYS) && !(defined(__AVX512F__) && defined(__AVX512VL__))
+    #define BLAKE2S_ATTRIB_128BIT  __attribute__((__target__("avx512vl,avx512f")))
+#else
   #if defined(Z7_BLAKE2S_USE_SSE41)
     #define BLAKE2S_ATTRIB_128BIT  __attribute__((__target__("sse4.1")))
   #elif defined(Z7_BLAKE2S_USE_SSSE3)
@@ -67,6 +81,7 @@
     #define BLAKE2S_ATTRIB_128BIT  __attribute__((__target__("sse2")))
   #endif
 #endif
+#endif
 
 
 #if defined(__AVX2__)
@@ -77,7 +92,11 @@
       || defined(Z7_LLVM_CLANG_VERSION) && (Z7_LLVM_CLANG_VERSION >= 30100)
     #define Z7_BLAKE2S_USE_AVX2
     #ifdef Z7_BLAKE2S_USE_AVX2
+#if defined(Z7_BLAKE2S_USE_AVX512_ALWAYS) && !(defined(__AVX512F__) && defined(__AVX512VL__))
+      #define BLAKE2S_ATTRIB_AVX2  __attribute__((__target__("avx512vl,avx512f")))
+#else
       #define BLAKE2S_ATTRIB_AVX2  __attribute__((__target__("avx2")))
+#endif
     #endif
   #elif  defined(Z7_MSC_VER_ORIGINAL) && (Z7_MSC_VER_ORIGINAL >= 1800) \
       || defined(__INTEL_COMPILER) && (__INTEL_COMPILER >= 1400)
@@ -107,7 +126,9 @@
 
 #if defined(__AVX512F__) && defined(__AVX512VL__)
    // && defined(Z7_MSC_VER_ORIGINAL) && (Z7_MSC_VER_ORIGINAL > 1930)
+  #ifndef Z7_BLAKE2S_USE_AVX512_ALWAYS
   #define Z7_BLAKE2S_USE_AVX512_ALWAYS
+  #endif
   // #pragma message ("=== Blake2s AVX512")
 #endif
 
@@ -1164,7 +1185,9 @@ Blake2sp_Final_V128_Fast(UInt32 *states)
 #if 1 && defined(Z7_BLAKE2S_USE_AVX512_ALWAYS)
   #define MM256_ROR_EPI32  _mm256_ror_epi32
   #define Z7_MM256_ROR_EPI32_IS_SUPPORTED
+#ifdef Z7_BLAKE2S_USE_AVX2_WAY2
   #define LOAD_ROTATE_CONSTS_256
+#endif
 #else
 #ifdef Z7_BLAKE2S_USE_AVX2_WAY_SLOW
 #ifdef Z7_BLAKE2S_USE_AVX2_WAY2
@@ -2549,9 +2572,11 @@ void z7_Black2sp_Prepare(void)
 
 #if defined(MY_CPU_X86_OR_AMD64)
     #if defined(Z7_BLAKE2S_USE_AVX512_ALWAYS)
+      // optional check
+      #if 0 || !(defined(__AVX512F__) && defined(__AVX512VL__))
       if (CPU_IsSupported_AVX512F_AVX512VL())
-    #endif
-    #if defined(Z7_BLAKE2S_USE_SSE41)
+      #endif
+    #elif defined(Z7_BLAKE2S_USE_SSE41)
       if (CPU_IsSupported_SSE41())
     #elif defined(Z7_BLAKE2S_USE_SSSE3)
       if (CPU_IsSupported_SSSE3())
@@ -2584,12 +2609,14 @@ void z7_Black2sp_Prepare(void)
 
 #ifdef Z7_BLAKE2S_USE_AVX2
 #if defined(MY_CPU_X86_OR_AMD64)
-    if (
-    #if 0 && defined(Z7_BLAKE2S_USE_AVX512_ALWAYS)
-        CPU_IsSupported_AVX512F_AVX512VL() &&
+    
+    #if defined(Z7_BLAKE2S_USE_AVX512_ALWAYS)
+      #if 0
+        if (CPU_IsSupported_AVX512F_AVX512VL())
+      #endif
+    #else
+        if (CPU_IsSupported_AVX2())
     #endif
-        CPU_IsSupported_AVX2()
-        )
 #endif
     {
     // #pragma message ("=== Blake2s AVX2")
diff --git a/C/CpuArch.c b/C/CpuArch.c
index d51b38a..e792f39 100644
--- a/C/CpuArch.c
+++ b/C/CpuArch.c
@@ -1,5 +1,5 @@
 /* CpuArch.c -- CPU specific code
-2024-03-02 : Igor Pavlov : Public domain */
+2024-07-04 : Igor Pavlov : Public domain */
 
 #include "Precomp.h"
 
@@ -638,7 +638,7 @@ BoolInt CPU_IsSupported_AVX(void)
 
   {
     const UInt32 bm = (UInt32)x86_xgetbv_0(MY_XCR_XFEATURE_ENABLED_MASK);
-    // printf("\n=== XGetBV=%d\n", bm);
+    // printf("\n=== XGetBV=0x%x\n", bm);
     return 1
         & (BoolInt)(bm >> 1)  // SSE state is supported (set by OS) for storing/restoring
         & (BoolInt)(bm >> 2); // AVX state is supported (set by OS) for storing/restoring
@@ -662,8 +662,7 @@ BoolInt CPU_IsSupported_AVX2(void)
   }
 }
 
-/*
-// fix it:
+#if 0
 BoolInt CPU_IsSupported_AVX512F_AVX512VL(void)
 {
   if (!CPU_IsSupported_AVX())
@@ -672,14 +671,25 @@ BoolInt CPU_IsSupported_AVX512F_AVX512VL(void)
     return False;
   {
     UInt32 d[4];
+    BoolInt v;
     z7_x86_cpuid(d, 7);
     // printf("\ncpuid(7): ebx=%8x ecx=%8x\n", d[1], d[2]);
+    v = 1
+      & (BoolInt)(d[1] >> 16)  // avx512f
+      & (BoolInt)(d[1] >> 31); // avx512vl
+    if (!v)
+      return False;
+  }
+  {
+    const UInt32 bm = (UInt32)x86_xgetbv_0(MY_XCR_XFEATURE_ENABLED_MASK);
+    // printf("\n=== XGetBV=0x%x\n", bm);
     return 1
-      & (BoolInt)(d[1] >> 16)  // avx512-f
-      & (BoolInt)(d[1] >> 31); // avx512-Vl
+        & (BoolInt)(bm >> 5)  // OPMASK
+        & (BoolInt)(bm >> 6)  // ZMM upper 256-bit
+        & (BoolInt)(bm >> 7); // ZMM16 ... ZMM31
   }
 }
-*/
+#endif
 
 BoolInt CPU_IsSupported_VAES_AVX2(void)
 {
@@ -838,7 +848,11 @@ static unsigned long MY_getauxval(int aux)
 
   #define MY_HWCAP_CHECK_FUNC(name) \
   BoolInt CPU_IsSupported_ ## name(void) { return 0; }
+#if defined(__ARM_NEON)
+  BoolInt CPU_IsSupported_NEON(void) { return True; }
+#else
   MY_HWCAP_CHECK_FUNC(NEON)
+#endif
 
 #endif // USE_HWCAP
 
diff --git a/C/CpuArch.h b/C/CpuArch.h
index dfc68f1..683cfaa 100644
--- a/C/CpuArch.h
+++ b/C/CpuArch.h
@@ -1,5 +1,5 @@
 /* CpuArch.h -- CPU specific code
-2024-05-13 : Igor Pavlov : Public domain */
+2024-06-17 : Igor Pavlov : Public domain */
 
 #ifndef ZIP7_INC_CPU_ARCH_H
 #define ZIP7_INC_CPU_ARCH_H
@@ -370,12 +370,12 @@ MY_CPU_64BIT means that processor can work with 64-bit registers.
 #define Z7_CPU_FAST_BSWAP_SUPPORTED
 
 /* GCC can generate slow code that calls function for __builtin_bswap32() for:
-     - GCC for RISCV, if Zbb extension is not used.
+     - GCC for RISCV, if Zbb/XTHeadBb extension is not used.
      - GCC for SPARC.
    The code from CLANG for SPARC also is not fastest.
    So we don't define Z7_CPU_FAST_BSWAP_SUPPORTED in some cases.
 */
-#elif (!defined(MY_CPU_RISCV) || defined (__riscv_zbb)) \
+#elif (!defined(MY_CPU_RISCV) || defined (__riscv_zbb) || defined(__riscv_xtheadbb)) \
     && !defined(MY_CPU_SPARC) \
     && ( \
        (defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))) \
@@ -564,6 +564,7 @@ problem-4 : performace:
 #define SetBe32a(p, v)   { *(UInt32 *)(void *)(p) = (v); }
 #define SetBe16a(p, v)   { *(UInt16 *)(void *)(p) = (v); }
 
+#define GetUi64a(p)      GetUi64(p)
 #define GetUi32a(p)      GetUi32(p)
 #define GetUi16a(p)      GetUi16(p)
 #define SetUi32a(p, v)   SetUi32(p, v)
@@ -571,6 +572,7 @@ problem-4 : performace:
 
 #elif defined(MY_CPU_LE)
 
+#define GetUi64a(p)      (*(const UInt64 *)(const void *)(p))
 #define GetUi32a(p)      (*(const UInt32 *)(const void *)(p))
 #define GetUi16a(p)      (*(const UInt16 *)(const void *)(p))
 #define SetUi32a(p, v)   { *(UInt32 *)(void *)(p) = (v); }
@@ -607,7 +609,7 @@ UInt32 Z7_FASTCALL z7_x86_cpuid_GetMaxFunc(void);
 BoolInt CPU_IsSupported_AES(void);
 BoolInt CPU_IsSupported_AVX(void);
 BoolInt CPU_IsSupported_AVX2(void);
-// BoolInt CPU_IsSupported_AVX512F_AVX512VL(void);
+BoolInt CPU_IsSupported_AVX512F_AVX512VL(void);
 BoolInt CPU_IsSupported_VAES_AVX2(void);
 BoolInt CPU_IsSupported_CMOV(void);
 BoolInt CPU_IsSupported_SSE(void);
diff --git a/C/ZstdDec.c b/C/ZstdDec.c
index ecf6d22..6ad47eb 100644
--- a/C/ZstdDec.c
+++ b/C/ZstdDec.c
@@ -1,5 +1,5 @@
 /* ZstdDec.c -- Zstd Decoder
-2024-01-21 : the code was developed by Igor Pavlov, using Zstandard format
+2024-06-18 : the code was developed by Igor Pavlov, using Zstandard format
              specification and original zstd decoder code as reference code.
 original zstd decoder code: Copyright (c) Facebook, Inc. All rights reserved.
 This source code is licensed under BSD 3-Clause License.
@@ -1308,8 +1308,10 @@ FSE_Decode_SeqTable(CFseRecord * const table,
   in->len--;
   {
     const Byte *ptr = in->ptr;
-    const Byte sym = ptr[0];
+    const unsigned sym = ptr[0];
     in->ptr = ptr + 1;
+    if (sym >= numSymbolsMax)
+      return SZ_ERROR_DATA;
     table[0] = (FastInt32)sym
       #if defined(Z7_ZSTD_DEC_USE_ML_PLUS3)
         + (numSymbolsMax == NUM_ML_SYMBOLS ? MATCH_LEN_MIN : 0)
@@ -2507,6 +2509,7 @@ SRes ZstdDec1_DecodeBlock(CZstdDec1 *p,
     if (vars.numSeqs == 0)
     {
       p->winPos += numLits;
+      UPDATE_TOTAL_OUT(p, numLits)
       return SZ_OK;
     }
   }
@@ -3310,11 +3313,11 @@ static SRes ZstdDec_DecodeBlock(CZstdDec * const p, CZstdDecState * const ds,
         {
           const SizeT xxh64_winPos = p->decoder.winPos - ZstdDec_GET_UNPROCESSED_XXH64_SIZE(p);
           p->decoder.winPos += outCur;
+          UPDATE_TOTAL_OUT(&p->decoder, outCur)
           p->contentProcessed += outCur;
           ZstdDec_Update_XXH(p, xxh64_winPos);
         }
         // ds->winPos = p->decoder.winPos;  // the caller does it instead. for debug:
-        UPDATE_TOTAL_OUT(&p->decoder, outCur)
         ds->outProcessed += outCur;
         if (p->blockSize -= (UInt32)outCur)
         {
diff --git a/CPP/7zip/7zip_gcc.mak b/CPP/7zip/7zip_gcc.mak
index f6a044f..45c9ab3 100644
--- a/CPP/7zip/7zip_gcc.mak
+++ b/CPP/7zip/7zip_gcc.mak
@@ -220,6 +220,9 @@ endif
 
 all: $(O) $(PROGPATH) $(STATIC_TARGET)
 
+# we need $(O) as order-only-prerequisites:
+$(OBJS): | $(O)
+
 $(O):
 	$(MY_MKDIR) $(O)
 
diff --git a/CPP/7zip/Archive/7z/7zUpdate.cpp b/CPP/7zip/Archive/7z/7zUpdate.cpp
index d374a00..c8c5d26 100644
--- a/CPP/7zip/Archive/7z/7zUpdate.cpp
+++ b/CPP/7zip/Archive/7z/7zUpdate.cpp
@@ -219,6 +219,14 @@ static int Parse_EXE(const Byte *buf, size_t size, CFilterMode *filterMode)
 }
 
 
+/*
+  Filters don't improve the compression ratio for relocatable object files (".o").
+  But we can get compression ratio gain, if we compress object
+  files and executables in same solid block.
+  So we use filters for relocatable object files (".o"):
+*/
+// #define Z7_7Z_CREATE_ARC_DISABLE_FILTER_FOR_OBJ
+
 /* ---------- ELF ---------- */
 
 #define ELF_SIG 0x464C457F
@@ -258,6 +266,12 @@ static int Parse_ELF(const Byte *buf, size_t size, CFilterMode *filterMode)
     default: return 0;
   }
 
+#ifdef Z7_7Z_CREATE_ARC_DISABLE_FILTER_FOR_OBJ
+#define ELF_ET_REL  1
+  if (Get16(buf + 0x10, be) == ELF_ET_REL)
+    return 0;
+#endif
+
   switch (Get16(buf + 0x12, be))
   {
     case 3:
@@ -318,6 +332,12 @@ static unsigned Parse_MACH(const Byte *buf, size_t size, CFilterMode *filterMode
     default: return 0;
   }
 
+#ifdef Z7_7Z_CREATE_ARC_DISABLE_FILTER_FOR_OBJ
+#define MACH_TYPE_OBJECT 1
+  if (Get32(buf + 0xC, be) == MACH_TYPE_OBJECT)
+      return 0;
+#endif
+
   switch (Get32(buf + 4, be))
   {
     case MACH_MACHINE_386:
diff --git a/CPP/7zip/Archive/ElfHandler.cpp b/CPP/7zip/Archive/ElfHandler.cpp
index e31b4ae..df22995 100644
--- a/CPP/7zip/Archive/ElfHandler.cpp
+++ b/CPP/7zip/Archive/ElfHandler.cpp
@@ -17,11 +17,13 @@
 
 #include "../Compress/CopyCoder.h"
 
+// #define Z7_ELF_SHOW_DETAILS
+
 using namespace NWindows;
 
-static UInt16 Get16(const Byte *p, bool be) { if (be) return GetBe16(p); return GetUi16(p); }
-static UInt32 Get32(const Byte *p, bool be) { if (be) return GetBe32(p); return GetUi32(p); }
-static UInt64 Get64(const Byte *p, bool be) { if (be) return GetBe64(p); return GetUi64(p); }
+static UInt16 Get16(const Byte *p, bool be) { if (be) return GetBe16a(p); return GetUi16a(p); }
+static UInt32 Get32(const Byte *p, bool be) { if (be) return GetBe32a(p); return GetUi32a(p); }
+static UInt64 Get64(const Byte *p, bool be) { if (be) return GetBe64a(p); return GetUi64a(p); }
 
 #define G16(offs, v) v = Get16(p + (offs), be)
 #define G32(offs, v) v = Get32(p + (offs), be)
@@ -31,14 +33,51 @@ namespace NArchive {
 namespace NElf {
 
 /*
-   ELF Structure for most files (real order can be different):
-   Header
-   Program (segment) header table (used at runtime)
-     Segment1 (Section ... Section)
-     Segment2
-     ...
-     SegmentN
-   Section header table (the data for linking and relocation)
+ELF Structure example:
+{
+  Header
+  Program header table (is used at runtime) (list of segment metadata records)
+  {
+    Segment (Read)
+      Segment : PT_PHDR : header table itself
+      Segment : PT_INTERP
+      Segment : PT_NOTE
+      .rela.dyn (RELA, ALLOC)
+    Segment (Execute/Read)
+      .text section (PROGBITS, SHF_ALLOC | SHF_EXECINSTR)
+    Segment (Read)
+      .rodata (PROGBITS, SHF_ALLOC | SHF_WRITE)
+      Segment : PT_GNU_EH_FRAME
+        .eh_frame_hdr
+      .eh_frame
+      .gcc_except_table
+    ...
+    Segment (Write/Read) (VaSize > Size)
+      Segment (Read) : PT_GNU_RELRO
+      Segment (Write/Read)
+      .data
+      .bss (Size == 0) (VSize != 0)
+  }
+  .comment (VA == 0)
+  .shstrtab (VA == 0)
+  Section header table (the data for linking and relocation)
+}
+
+  Last top level segment contains .bss section that requires additional VA space.
+  So (VaSize > Size) for that segment.
+
+  Segments can be unsorted (by offset) in table.
+  Top level segments has Type=PT_LOAD : "Loadable segment".
+  Top level segments usually are aligned for page size (4 KB).
+  Another segments (non PT_LOAD segments) are inside PT_LOAD segments.
+
+  (VA-offset == 0) is possible for some sections and segments at the beginning of file.
+  (VA-offset == 4KB*N) for most sections and segments where (Size != 0),
+  (VA-offset != 4KB*N) for .bss section (last section), because (Size == 0),
+    and that section is not mapped from image file.
+  Some files contain additional "virtual" 4 KB page in VA space after
+  end of data of top level segments (PT_LOAD) before new top level segments.
+  So (VA-offset) value can increase by 4 KB step.
 */
 
 #define ELF_CLASS_32 1
@@ -47,14 +86,14 @@ namespace NElf {
 #define ELF_DATA_2LSB 1
 #define ELF_DATA_2MSB 2
 
-static const UInt32 kHeaderSize32 = 0x34;
-static const UInt32 kHeaderSize64 = 0x40;
+static const unsigned kHeaderSize32 = 0x34;
+static const unsigned kHeaderSize64 = 0x40;
 
-static const UInt32 kSegmentSize32 = 0x20;
-static const UInt32 kSegmentSize64 = 0x38;
+static const unsigned kSegmentSize32 = 0x20;
+static const unsigned kSegmentSize64 = 0x38;
 
-static const UInt32 kSectionSize32 = 0x28;
-static const UInt32 kSectionSize64 = 0x40;
+static const unsigned kSectionSize32 = 0x28;
+static const unsigned kSectionSize64 = 0x40;
 
 struct CHeader
 {
@@ -78,9 +117,9 @@ struct CHeader
   UInt16 NumSections;
   UInt16 NamesSectIndex;
 
-  bool Parse(const Byte *buf);
+  bool Parse(const Byte *p);
 
-  UInt64 GetHeadersSize() const { return (UInt64)HeaderSize +
+  UInt32 GetHeadersSize() const { return (UInt32)HeaderSize +
       (UInt32)NumSegments * SegmentEntrySize +
       (UInt32)NumSections * SectionEntrySize; }
 };
@@ -104,7 +143,7 @@ bool CHeader::Parse(const Byte *p)
   if (p[6] != 1) // Version
     return false;
   Os = p[7];
-  AbiVer = p[8];
+  // AbiVer = p[8];
   for (int i = 9; i < 16; i++)
     if (p[i] != 0)
       return false;
@@ -117,16 +156,21 @@ bool CHeader::Parse(const Byte *p)
   if (Mode64)
   {
     // G64(0x18, EntryVa);
-    G64(0x20, ProgOffset);
+    G64(0x20, ProgOffset); // == kHeaderSize64 == 0x40 usually
     G64(0x28, SectOffset);
     p += 0x30;
+    // we expect that fields are aligned
+    if (ProgOffset & 7) return false;
+    if (SectOffset & 7) return false;
   }
   else
   {
     // G32(0x18, EntryVa);
-    G32(0x1C, ProgOffset);
+    G32(0x1C, ProgOffset); // == kHeaderSize32 == 0x34 usually
     G32(0x20, SectOffset);
     p += 0x24;
+    if (ProgOffset & 3) return false;
+    if (SectOffset & 3) return false;
   }
 
   G32(0, Flags);
@@ -140,21 +184,20 @@ bool CHeader::Parse(const Byte *p)
   G16(12, NumSections);
   G16(14, NamesSectIndex);
 
-  if (ProgOffset < HeaderSize && (ProgOffset != 0 || NumSegments != 0)) return false;
-  if (SectOffset < HeaderSize && (SectOffset != 0 || NumSections != 0)) return false;
+  if (ProgOffset < HeaderSize && (ProgOffset || NumSegments)) return false;
+  if (SectOffset < HeaderSize && (SectOffset || NumSections)) return false;
 
-  if (SegmentEntrySize == 0) { if (NumSegments != 0) return false; }
+  if (SegmentEntrySize == 0) { if (NumSegments) return false; }
   else if (SegmentEntrySize != (Mode64 ? kSegmentSize64 : kSegmentSize32)) return false;
 
-  if (SectionEntrySize == 0) { if (NumSections != 0) return false; }
+  if (SectionEntrySize == 0) { if (NumSections) return false; }
   else if (SectionEntrySize != (Mode64 ? kSectionSize64 : kSectionSize32)) return false;
 
   return true;
 }
 
-// The program header table itself.
 
-#define PT_PHDR 6
+#define PT_PHDR 6  // The program header table itself.
 #define PT_GNU_STACK 0x6474e551
 
 static const CUInt32PCharPair g_SegnmentTypes[] =
@@ -186,16 +229,18 @@ struct CSegment
   UInt32 Flags;
   UInt64 Offset;
   UInt64 Va;
-  // UInt64 Pa;
-  UInt64 Size;
-  UInt64 VSize;
-  UInt64 Align;
-
+  UInt64 Size;  // size in file
+  UInt64 VSize; // size in memory
+#ifdef Z7_ELF_SHOW_DETAILS
+  UInt64 Pa;    // usually == Va, or == 0
+  UInt64 Align; // if (Align != 0), condition must be met:
+                //   (VSize % Align == Offset % Alig)
+#endif
   void UpdateTotalSize(UInt64 &totalSize)
   {
-    UInt64 t = Offset + Size;
+    const UInt64 t = Offset + Size;
     if (totalSize < t)
-      totalSize = t;
+        totalSize = t;
   }
   void Parse(const Byte *p, bool mode64, bool be);
 };
@@ -208,20 +253,24 @@ void CSegment::Parse(const Byte *p, bool mode64, bool be)
     G32(4, Flags);
     G64(8, Offset);
     G64(0x10, Va);
-    // G64(0x18, Pa);
     G64(0x20, Size);
     G64(0x28, VSize);
+#ifdef Z7_ELF_SHOW_DETAILS
+    G64(0x18, Pa);
     G64(0x30, Align);
+#endif
   }
   else
   {
     G32(4, Offset);
     G32(8, Va);
-    // G32(0x0C, Pa);
     G32(0x10, Size);
     G32(0x14, VSize);
     G32(0x18, Flags);
+#ifdef Z7_ELF_SHOW_DETAILS
+    G32(0x0C, Pa);
     G32(0x1C, Align);
+#endif
   }
 }
 
@@ -290,6 +339,8 @@ static const CUInt32PCharPair g_SectTypes[] =
   { 0x70000005, "ARM_OVERLAYSECTION" }
 };
 
+
+// SHF_ flags
 static const CUInt32PCharPair g_SectionFlags[] =
 {
   { 0, "WRITE" },
@@ -303,7 +354,7 @@ static const CUInt32PCharPair g_SectionFlags[] =
   { 8, "OS_NONCONFORMING" },
   { 9, "GROUP" },
   { 10, "TLS" },
-  { 11, "CP_SECTION" },
+  { 11, "COMPRESSED" },
   { 12, "DP_SECTION" },
   { 13, "XCORE_SHF_CP_SECTION" },
   { 28, "64_LARGE" },
@@ -326,9 +377,9 @@ struct CSection
 
   void UpdateTotalSize(UInt64 &totalSize)
   {
-    UInt64 t = Offset + GetSize();
+    const UInt64 t = Offset + GetSize();
     if (totalSize < t)
-      totalSize = t;
+        totalSize = t;
   }
   bool Parse(const Byte *p, bool mode64, bool be);
 };
@@ -412,7 +463,7 @@ static const char * const g_Machines[] =
   , "TRW RH-32"
   , "Motorola RCE"
   , "ARM"
-  , "Alpha"
+  , "Alpha-STD"
   , "Hitachi SH"
   , "SPARC-V9"
   , "Siemens Tricore"
@@ -577,8 +628,9 @@ static const char * const g_Machines[] =
 static const CUInt32PCharPair g_MachinePairs[] =
 {
   { 243, "RISC-V" },
-  { 47787, "Xilinx MicroBlaze" }
-  // { 0x9026, "Alpha" }
+  { 258, "LoongArch" },
+  { 0x9026, "Alpha" },  // EM_ALPHA_EXP, obsolete, (used by NetBSD/alpha) (written in the absence of an ABI)
+  { 0xbaab, "Xilinx MicroBlaze" }
 };
 
 static const CUInt32PCharPair g_OS[] =
@@ -600,6 +652,8 @@ static const CUInt32PCharPair g_OS[] =
   { 14, "HP NSK" },
   { 15, "AROS" },
   { 16, "FenixOS" },
+  { 17, "CloudABI" },
+  { 18, "OpenVOS" },
   { 64, "Bare-metal TMS320C6000" },
   { 65, "Linux TMS320C6000" },
   { 97, "ARM" },
@@ -693,23 +747,27 @@ public:
 void CHandler::GetSectionName(UInt32 index, NCOM::CPropVariant &prop, bool showNULL) const
 {
   if (index >= _sections.Size())
-    return;
-  const CSection &section = _sections[index];
-  const UInt32 offset = section.Name;
-  if (index == SHN_UNDEF /* && section.Type == SHT_NULL && offset == 0 */)
+    prop = index; // it's possible for some file, but maybe it's ERROR case
+  else
   {
-    if (showNULL)
-      prop = "NULL";
-    return;
-  }
-  const Byte *p = _namesData;
-  size_t size = _namesData.Size();
-  for (size_t i = offset; i < size; i++)
-    if (p[i] == 0)
+    const CSection &section = _sections[index];
+    const UInt32 offset = section.Name;
+    if (index == SHN_UNDEF /* && section.Type == SHT_NULL && offset == 0 */)
     {
-      prop = (const char *)(p + offset);
+      if (showNULL)
+        prop = "NULL";
       return;
     }
+    const Byte *p = _namesData;
+    const size_t size = _namesData.Size();
+    for (size_t i = offset; i < size; i++)
+      if (p[i] == 0)
+      {
+        prop = (const char *)(p + offset);
+        return;
+      }
+    prop = "ERROR";
+  }
 }
 
 static const Byte kArcProps[] =
@@ -726,7 +784,14 @@ static const Byte kArcProps[] =
 enum
 {
   kpidLinkSection = kpidUserDefined,
-  kpidInfoSection
+  kpidInfoSection,
+  kpidEntrySize
+#ifdef Z7_ELF_SHOW_DETAILS
+  // , kpidAlign
+  , kpidPa
+  , kpidDelta
+  , kpidOffsetEnd
+#endif
 };
 
 static const CStatProp kProps[] =
@@ -738,6 +803,14 @@ static const CStatProp kProps[] =
   { NULL, kpidVa, VT_UI8 },
   { NULL, kpidType, VT_BSTR },
   { NULL, kpidCharacts, VT_BSTR }
+#ifdef Z7_ELF_SHOW_DETAILS
+  // , { "Align", kpidAlign, VT_UI8 }
+  , { NULL, kpidClusterSize, VT_UI8 }
+  , { "PA", kpidPa, VT_UI8 }
+  , { "End offset", kpidOffsetEnd, VT_UI8 }
+  , { "Delta (VA-Offset)", kpidDelta, VT_UI8 }
+#endif
+  , { "Entry Size", kpidEntrySize, VT_UI8}
   , { "Link Section", kpidLinkSection, VT_BSTR}
   , { "Info Section", kpidInfoSection, VT_BSTR}
 };
@@ -769,7 +842,7 @@ Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
       if (s.IsEmpty())
         s = TypePairToString(g_MachinePairs, Z7_ARRAY_SIZE(g_MachinePairs), _header.Machine);
       UInt32 flags = _header.Flags;
-      if (flags != 0)
+      if (flags)
       {
         s.Add_Space();
         if (_header.Machine == k_Machine_ARM)
@@ -781,18 +854,16 @@ Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
         else if (_header.Machine == k_Machine_MIPS)
         {
           const UInt32 ver = flags >> 28;
-          s += "v";
+          s.Add_Char('v');
           s.Add_UInt32(ver);
-          flags &= (((UInt32)1 << 28) - 1);
-
-          UInt32 abi = (flags >> 12) & 7;
-          if (abi != 0)
+          flags &= ((UInt32)1 << 28) - 1;
+          const UInt32 abi = (flags >> 12) & 7;
+          if (abi)
           {
             s += " ABI:";
             s.Add_UInt32(abi);
           }
           flags &= ~((UInt32)7 << 12);
-          
           s.Add_Space();
           s += FlagsToString(g_MIPS_Flags, Z7_ARRAY_SIZE(g_MIPS_Flags), flags);
         }
@@ -813,6 +884,31 @@ Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
           flags &= ~(UInt32)6;
           s += FlagsToString(g_RISCV_Flags, Z7_ARRAY_SIZE(g_RISCV_Flags), flags);
         }
+#if 0
+#define k_Machine_LOONGARCH 258
+        else if (_header.Machine == k_Machine_LOONGARCH)
+        {
+          s += "ABI:";
+          s.Add_UInt32((flags >> 6) & 3);
+          s.Add_Dot();
+          s.Add_UInt32((flags >> 3) & 7);
+          s.Add_Dot();
+#if 1
+          s.Add_UInt32(flags & 7);
+#else
+          static const char k_LoongArch_Float_Type[8] = { '0', 's', 'f', 'd', '4' ,'5', '6', '7' };
+          s.Add_Char(k_LoongArch_Float_Type[flags & 7]);
+#endif
+          flags &= ~(UInt32)0xff;
+          if (flags)
+          {
+            s.Add_Colon();
+            char sz[16];
+            ConvertUInt32ToHex(flags, sz);
+            s += sz;
+          }
+        }
+#endif
         else
         {
           char sz[16];
@@ -827,13 +923,39 @@ Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
     case kpidHostOS: PAIR_TO_PROP(g_OS, _header.Os, prop); break;
     case kpidCharacts: TYPE_TO_PROP(g_Types, _header.Type, prop); break;
     case kpidComment:
+    {
+      AString s;
       if (_stackFlags_Defined)
       {
-        AString s ("STACK: ");
+        s += "STACK: ";
         s += FlagsToString(g_SegmentFlags, Z7_ARRAY_SIZE(g_SegmentFlags), _stackFlags);
-        prop = s;
+        s.Add_LF();
+        /*
+        if (_header.EntryVa)
+        {
+          s += "Entry point: 0x";
+          char temp[16 + 4];
+          ConvertUInt64ToHex(_header.EntryVa, temp);
+          s += temp;
+          s.Add_LF();
+        }
+        */
+      }
+      if (_header.NumSegments)
+      {
+        s += "Segments: ";
+        s.Add_UInt32(_header.NumSegments);
+        s.Add_LF();
       }
+      if (_header.NumSections)
+      {
+        s += "Sections: ";
+        s.Add_UInt32(_header.NumSections);
+        s.Add_LF();
+      }
+      prop = s;
       break;
+    }
     case kpidExtension:
     {
       const char *s = NULL;
@@ -878,12 +1000,17 @@ Z7_COM7F_IMF(CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT *val
       }
       case kpidOffset: prop = item.Offset; break;
       case kpidVa: prop = item.Va; break;
+#ifdef Z7_ELF_SHOW_DETAILS
+      case kpidDelta: if (item.Va) { prop = item.Va - item.Offset; } break;
+      case kpidOffsetEnd: prop = item.Offset + item.Size; break;
+      case kpidPa: prop = item.Pa; break;
+      case kpidClusterSize: prop = item.Align; break;
+#endif
       case kpidSize:
       case kpidPackSize: prop = (UInt64)item.Size; break;
       case kpidVirtualSize: prop = (UInt64)item.VSize; break;
       case kpidType: PAIR_TO_PROP(g_SegnmentTypes, item.Type, prop); break;
       case kpidCharacts: FLAGS_TO_PROP(g_SegmentFlags, item.Flags, prop); break;
-        
     }
   }
   else
@@ -895,13 +1022,19 @@ Z7_COM7F_IMF(CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT *val
       case kpidPath: GetSectionName(index, prop, true); break;
       case kpidOffset: prop = item.Offset; break;
       case kpidVa: prop = item.Va; break;
+#ifdef Z7_ELF_SHOW_DETAILS
+      case kpidDelta: if (item.Va) { prop = item.Va - item.Offset; } break;
+      case kpidOffsetEnd: prop = item.Offset + item.GetSize(); break;
+#endif
       case kpidSize:
       case kpidPackSize: prop = (UInt64)(item.Type == SHT_NOBITS ? 0 : item.VSize); break;
       case kpidVirtualSize: prop = item.GetSize(); break;
       case kpidType: PAIR_TO_PROP(g_SectTypes, item.Type, prop); break;
       case kpidCharacts: FLAGS_TO_PROP(g_SectionFlags, (UInt32)item.Flags, prop); break;
+      // case kpidAlign: prop = item.Align; break;
       case kpidLinkSection: GetSectionName(item.Link, prop, false); break;
       case kpidInfoSection: GetSectionName(item.Info, prop, false); break;
+      case kpidEntrySize: prop = (UInt64)item.EntSize; break;
     }
   }
   prop.Detach(value);
@@ -911,42 +1044,46 @@ Z7_COM7F_IMF(CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT *val
 
 HRESULT CHandler::Open2(IInStream *stream)
 {
-  const UInt32 kStartSize = kHeaderSize64;
-  Byte h[kStartSize];
-  RINOK(ReadStream_FALSE(stream, h, kStartSize))
-  if (h[0] != 0x7F || h[1] != 'E' || h[2] != 'L' || h[3] != 'F')
-    return S_FALSE;
-  if (!_header.Parse(h))
-    return S_FALSE;
+  {
+    const UInt32 kStartSize = kHeaderSize64;
+    UInt64 h64[kStartSize / 8];
+    RINOK(ReadStream_FALSE(stream, h64, kStartSize))
+    const Byte *h = (const Byte *)(const void *)h64;
+    if (GetUi32a(h) != 0x464c457f)
+      return S_FALSE;
+    if (!_header.Parse(h))
+      return S_FALSE;
+  }
 
   _totalSize = _header.HeaderSize;
 
   bool addSegments = false;
   bool addSections = false;
-
-  if (_header.NumSections > 1)
+  // first section usually is NULL (with zero offsets and zero sizes).
+  if (_header.NumSegments == 0 || _header.NumSections > 1)
     addSections = true;
   else
     addSegments = true;
+#ifdef Z7_ELF_SHOW_DETAILS
+  addSections = true;
+  addSegments = true;
+#endif
 
-  if (_header.NumSegments != 0)
+  if (_header.NumSegments)
   {
     if (_header.ProgOffset > (UInt64)1 << 60) return S_FALSE;
     RINOK(InStream_SeekSet(stream, _header.ProgOffset))
     const size_t size = (size_t)_header.SegmentEntrySize * _header.NumSegments;
-    
     CByteArr buf(size);
-    
     RINOK(ReadStream_FALSE(stream, buf, size))
-    
-    const UInt64 total = _header.ProgOffset + size;
-    if (_totalSize < total)
-      _totalSize = total;
-
-    const Byte *p = buf;
-    
+    {
+      const UInt64 total = _header.ProgOffset + size;
+      if (_totalSize < total)
+          _totalSize = total;
+    }
     if (addSegments)
       _segments.ClearAndReserve(_header.NumSegments);
+    const Byte *p = buf;
     for (unsigned i = 0; i < _header.NumSegments; i++, p += _header.SegmentEntrySize)
     {
       CSegment seg;
@@ -957,29 +1094,29 @@ HRESULT CHandler::Open2(IInStream *stream)
         _stackFlags = seg.Flags;
         _stackFlags_Defined = true;
       }
-      if (addSegments && seg.Type != PT_PHDR)
+      if (addSegments
+          // we don't show program header table segment
+          && seg.Type != PT_PHDR
+          )
         _segments.AddInReserved(seg);
     }
   }
 
-  if (_header.NumSections != 0)
+  if (_header.NumSections)
   {
     if (_header.SectOffset > (UInt64)1 << 60) return S_FALSE;
     RINOK(InStream_SeekSet(stream, _header.SectOffset))
-    size_t size = (size_t)_header.SectionEntrySize * _header.NumSections;
-    
+    const size_t size = (size_t)_header.SectionEntrySize * _header.NumSections;
     CByteArr buf(size);
-    
     RINOK(ReadStream_FALSE(stream, buf, size))
-
-    UInt64 total = _header.SectOffset + size;
-    if (_totalSize < total)
-      _totalSize = total;
-
-    const Byte *p = buf;
-    
+    {
+      const UInt64 total = _header.SectOffset + size;
+      if (_totalSize < total)
+          _totalSize = total;
+    }
     if (addSections)
       _sections.ClearAndReserve(_header.NumSections);
+    const Byte *p = buf;
     for (unsigned i = 0; i < _header.NumSections; i++, p += _header.SectionEntrySize)
     {
       CSection sect;
@@ -1000,18 +1137,17 @@ HRESULT CHandler::Open2(IInStream *stream)
     {
       const CSection &sect = _sections[_header.NamesSectIndex];
       const UInt64 size = sect.GetSize();
-      if (size != 0
-        && size < ((UInt64)1 << 31)
-        && (Int64)sect.Offset >= 0)
+      if (size && size < ((UInt64)1 << 31)
+          && (Int64)sect.Offset >= 0)
       {
         _namesData.Alloc((size_t)size);
         RINOK(InStream_SeekSet(stream, sect.Offset))
         RINOK(ReadStream_FALSE(stream, _namesData, (size_t)size))
       }
     }
-    
     /*
-    // we will not delete NULL sections, since we have links to section via indexes
+    // we cannot delete "NULL" sections,
+    // because we have links to sections array via indexes
     for (int i = _sections.Size() - 1; i >= 0; i--)
       if (_sections[i].Type == SHT_NULL)
         _items.Delete(i);
@@ -1080,7 +1216,7 @@ Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 numItems,
   }
   RINOK(extractCallback->SetTotal(totalSize))
 
-  UInt64 currentTotalSize = 0;
+  totalSize = 0;
   UInt64 currentItemSize;
   
   CMyComPtr2_Create<ICompressCoder, NCompress::CCopyCoder> copyCoder;
@@ -1089,9 +1225,9 @@ Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 numItems,
   CMyComPtr2_Create<ISequentialInStream, CLimitedSequentialInStream> inStream;
   inStream->SetStream(_inStream);
 
-  for (i = 0;; i++, currentTotalSize += currentItemSize)
+  for (i = 0;; i++, totalSize += currentItemSize)
   {
-    lps->InSize = lps->OutSize = currentTotalSize;
+    lps->InSize = lps->OutSize = totalSize;
     RINOK(lps->SetCur())
     if (i >= numItems)
       break;
diff --git a/CPP/7zip/Archive/GptHandler.cpp b/CPP/7zip/Archive/GptHandler.cpp
index 23a1db6..4c291c4 100644
--- a/CPP/7zip/Archive/GptHandler.cpp
+++ b/CPP/7zip/Archive/GptHandler.cpp
@@ -111,6 +111,12 @@ static const CPartType kPartTypes[] =
 
   { 0x0FC63DAF, NULL, "Linux Data" },
   { 0x0657FD6D, NULL, "Linux Swap" },
+  { 0x44479540, NULL, "Linux root (x86)" },
+  { 0x4F68BCE3, NULL, "Linux root (x86-64)" },
+  { 0x69DAD710, NULL, "Linux root (ARM)" },
+  { 0xB921B045, NULL, "Linux root (ARM64)" },
+  { 0x993D8D3D, NULL, "Linux root (IA-64)" },
+  
 
   { 0x83BD6B9D, NULL, "FreeBSD Boot" },
   { 0x516E7CB4, NULL, "FreeBSD Data" },
diff --git a/CPP/7zip/Archive/LzhHandler.cpp b/CPP/7zip/Archive/LzhHandler.cpp
index adfe59d..8959300 100644
--- a/CPP/7zip/Archive/LzhHandler.cpp
+++ b/CPP/7zip/Archive/LzhHandler.cpp
@@ -473,8 +473,8 @@ Z7_COM7F_IMF(CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT *val
       break;
     }
     case kpidIsDir:  prop = item.IsDir(); break;
-    case kpidSize:   prop = item.Size; break;
-    case kpidPackSize:  prop = item.PackSize; break;
+    case kpidSize:   prop = (UInt64)item.Size; break;
+    case kpidPackSize:  prop = (UInt64)item.PackSize; break;
     case kpidCRC:  prop = (UInt32)item.CRC; break;
     case kpidHostOS:  PAIR_TO_PROP(g_OsPairs, item.OsId, prop); break;
     case kpidMTime:
diff --git a/CPP/7zip/Archive/PeHandler.cpp b/CPP/7zip/Archive/PeHandler.cpp
index 0cab820..8a0ff05 100644
--- a/CPP/7zip/Archive/PeHandler.cpp
+++ b/CPP/7zip/Archive/PeHandler.cpp
@@ -180,9 +180,32 @@ struct CDirLink
   }
 };
 
+
+// IMAGE_DIRECTORY_ENTRY_*
+static const char * const g_Dir_Names[] =
+{
+    "EXPORT"
+  , "IMPORT"
+  , "RESOURCE"
+  , "EXCEPTION"
+  , "SECURITY"
+  , "BASERELOC"
+  , "DEBUG"
+  , "ARCHITECTURE" // "COPYRIGHT"
+  , "GLOBALPTR"
+  , "TLS"
+  , "LOAD_CONFIG"
+  , "BOUND_IMPORT"
+  , "IAT"
+  , "DELAY_IMPORT"
+  , "COM_DESCRIPTOR"
+};
+
 enum
 {
+  kDirLink_EXCEPTION = 3,
   kDirLink_Certificate = 4,
+  kDirLink_BASERELOC = 5,
   kDirLink_Debug = 6
 };
 
@@ -229,7 +252,7 @@ struct COptHeader
   UInt32 UninitDataSize;
   
   // UInt32 AddressOfEntryPoint;
-  // UInt32 BaseOfCode;
+  // UInt32 BaseOfCode; //  VA(.text) == 0x1000 in most cases
   // UInt32 BaseOfData32;
   UInt64 ImageBase;
 
@@ -273,6 +296,7 @@ struct COptHeader
   }
 };
 
+// size is 16-bit
 bool COptHeader::Parse(const Byte *p, UInt32 size)
 {
   if (size < k_OptHeader32_Size_MIN)
@@ -334,14 +358,18 @@ bool COptHeader::Parse(const Byte *p, UInt32 size)
     pos = 92;
   }
 
-  G32(pos, NumDirItems);
-  if (NumDirItems > (1 << 16))
+  UInt32 numDirItems;
+  G32(pos, numDirItems);
+  NumDirItems = numDirItems;
+  if (numDirItems > (1 << 13))
     return false;
   pos += 4;
-  if (pos + 8 * NumDirItems > size)
+  if (pos + 8 * numDirItems > size)
     return false;
   memset((void *)DirItems, 0, sizeof(DirItems));
-  for (UInt32 i = 0; i < NumDirItems && i < kNumDirItemsMax; i++)
+  if (numDirItems > kNumDirItemsMax)
+      numDirItems = kNumDirItemsMax;
+  for (UInt32 i = 0; i < numDirItems; i++)
     DirItems[i].Parse(p + pos + i * 8);
   return true;
 }
@@ -352,27 +380,41 @@ struct CSection
 {
   AString Name;
 
+  UInt32 ExtractSize;
   UInt32 VSize;
   UInt32 Va;
   UInt32 PSize;
   UInt32 Pa;
   UInt32 Flags;
   UInt32 Time;
-  // UInt16 NumRelocs;
+  // UInt16 NumRelocs; // is set to zero for executable images
   bool IsRealSect;
   bool IsDebug;
   bool IsAdditionalSection;
 
-  CSection(): IsRealSect(false), IsDebug(false), IsAdditionalSection(false) {}
+  CSection():
+    ExtractSize(0),
+    IsRealSect(false),
+    IsDebug(false),
+    IsAdditionalSection(false)
+    // , NumRelocs(0)
+    {}
 
-  UInt32 GetSizeExtract() const { return PSize; }
-  UInt32 GetSizeMin() const { return MyMin(PSize, VSize); }
+  void Set_Size_for_all(UInt32 size)
+  {
+    PSize = VSize = ExtractSize = size;
+  }
+
+  UInt32 GetSize_Extract() const
+  {
+    return ExtractSize;
+  }
 
   void UpdateTotalSize(UInt32 &totalSize) const
   {
-    UInt32 t = Pa + PSize;
+    const UInt32 t = Pa + PSize;
     if (totalSize < t)
-      totalSize = t;
+        totalSize = t;
   }
   
   void Parse(const Byte *p);
@@ -380,8 +422,8 @@ struct CSection
   int Compare(const CSection &s) const
   {
     RINOZ(MyCompare(Pa, s.Pa))
-    UInt32 size1 = GetSizeExtract();
-    UInt32 size2 = s.GetSizeExtract();
+    const UInt32 size1 = GetSize_Extract();
+    const UInt32 size2 = s.GetSize_Extract();
     return MyCompare(size1, size2);
   }
 };
@@ -402,6 +444,10 @@ void CSection::Parse(const Byte *p)
   G32(20, Pa);
   // G16(32, NumRelocs);
   G32(36, Flags);
+  // v24.08: we extract only useful data (without extra padding bytes).
+  // VSize == 0 is not expected, but we support that case too.
+  // return (VSize && VSize < PSize) ? VSize : PSize;
+  ExtractSize = (VSize && VSize < PSize) ? VSize : PSize;
 }
 
 
@@ -508,6 +554,7 @@ static const CUInt32PCharPair g_MachinePairs[] =
   { 0x01D3, "AM33" },
   { 0x01F0, "PPC" },
   { 0x01F1, "PPC-FP" },
+  { 0x01F2, "PPC-BE" },
   { 0x0200, "IA-64" },
   { 0x0266, "MIPS-16" },
   { 0x0284, "Alpha-64" },
@@ -830,11 +877,11 @@ enum
   kpidStackReserve,
   kpidStackCommit,
   kpidHeapReserve,
-  kpidHeapCommit,
-  kpidImageBase
-  // kpidAddressOfEntryPoint,
-  // kpidBaseOfCode,
-  // kpidBaseOfData32,
+  kpidHeapCommit
+  // , kpidImageBase
+  // , kpidAddressOfEntryPoint
+  // , kpidBaseOfCode
+  // , kpidBaseOfData32
 };
 
 static const CStatProp kArcProps[] =
@@ -864,14 +911,16 @@ static const CStatProp kArcProps[] =
   { "Stack Commit", kpidStackCommit, VT_UI8},
   { "Heap Reserve", kpidHeapReserve, VT_UI8},
   { "Heap Commit", kpidHeapCommit, VT_UI8},
-  { "Image Base", kpidImageBase, VT_UI8},
-  { NULL, kpidComment, VT_BSTR},
+  { NULL, kpidVa, VT_UI8 }, // "Image Base", kpidImageBase, VT_UI8
+  { NULL, kpidComment, VT_BSTR}
   
-  // { "Address Of Entry Point", kpidAddressOfEntryPoint, VT_UI8},
-  // { "Base Of Code", kpidBaseOfCode, VT_UI8},
-  // { "Base Of Data", kpidBaseOfData32, VT_UI8},
+  // , { "Address Of Entry Point", kpidAddressOfEntryPoint, VT_UI8}
+  // , { "Base Of Code", kpidBaseOfCode, VT_UI8}
+  // , { "Base Of Data", kpidBaseOfData32, VT_UI8}
 };
 
+// #define kpid_NumRelocs 250
+
 static const Byte kProps[] =
 {
   kpidPath,
@@ -880,7 +929,8 @@ static const Byte kProps[] =
   kpidVirtualSize,
   kpidCharacts,
   kpidOffset,
-  kpidVa,
+  kpidVa
+  // , kpid_NumRelocs
 };
 
 IMP_IInArchive_Props
@@ -899,7 +949,42 @@ Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
   switch (propID)
   {
     case kpidPhySize: prop = _totalSize; break;
-    case kpidComment: if (!_versionFullString.IsEmpty()) prop = _versionFullString; break;
+    case kpidComment:
+    {
+      UString s (_versionFullString);
+      s.Add_LF();
+      s += "Data Directories: ";
+      s.Add_UInt32(_optHeader.NumDirItems);
+      s.Add_LF();
+      s.Add_Char('{');
+      s.Add_LF();
+      for (unsigned i = 0; i < _optHeader.NumDirItems
+          && i < Z7_ARRAY_SIZE(_optHeader.DirItems); i++)
+      {
+        const CDirLink &di = _optHeader.DirItems[i];
+        if (di.Va == 0 && di.Size == 0)
+          continue;
+        s += "index=";
+        s.Add_UInt32(i);
+
+        if (i < Z7_ARRAY_SIZE(g_Dir_Names))
+        {
+          s += " name=";
+          s += g_Dir_Names[i];
+        }
+        s += " VA=0x";
+        char temp[16];
+        ConvertUInt32ToHex(di.Va, temp);
+        s += temp;
+        s += " Size=";
+        s.Add_UInt32(di.Size);
+        s.Add_LF();
+      }
+      s.Add_Char('}');
+      s.Add_LF();
+      prop = s;
+      break;
+    }
     case kpidShortComment:
       if (!_versionShortString.IsEmpty())
         prop = _versionShortString;
@@ -969,8 +1054,7 @@ Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
     case kpidStackCommit: prop = _optHeader.StackCommit; break;
     case kpidHeapReserve: prop = _optHeader.HeapReserve; break;
     case kpidHeapCommit: prop = _optHeader.HeapCommit; break;
-
-    case kpidImageBase: prop = _optHeader.ImageBase; break;
+    case kpidVa: prop = _optHeader.ImageBase; break; // kpidImageBase:
     // case kpidAddressOfEntryPoint: prop = _optHeader.AddressOfEntryPoint; break;
     // case kpidBaseOfCode: prop = _optHeader.BaseOfCode; break;
     // case kpidBaseOfData32: if (!_optHeader.Is64Bit()) prop = _optHeader.BaseOfData32; break;
@@ -1130,7 +1214,8 @@ Z7_COM7F_IMF(CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT *val
         prop = MultiByteToUnicodeString(s);
         break;
       }
-      case kpidSize: prop = (UInt64)item.PSize; break;
+      case kpidSize: prop = (UInt64)item.GetSize_Extract(); break;
+      // case kpid_NumRelocs: prop = (UInt32)item.NumRelocs; break;
       case kpidPackSize: prop = (UInt64)item.PSize; break;
       case kpidVirtualSize: prop = (UInt64)item.VSize; break;
       case kpidOffset: prop = item.Pa; break;
@@ -1229,7 +1314,7 @@ HRESULT CHandler::LoadDebugSections(IInStream *stream, bool &thereIsSection)
       sect.Time = de.Time;
       sect.Va = de.Va;
       sect.Pa = de.Pa;
-      sect.PSize = sect.VSize = de.Size;
+      sect.Set_Size_for_all(de.Size);
     }
     buf += kEntrySize;
   }
@@ -1757,7 +1842,7 @@ static void CopyToUString(const Byte *p, UString &s)
 {
   for (;;)
   {
-    wchar_t c = (wchar_t)Get16(p);
+    const wchar_t c = (wchar_t)Get16(p);
     p += 2;
     if (c == 0)
       return;
@@ -1765,6 +1850,16 @@ static void CopyToUString(const Byte *p, UString &s)
   }
 }
 
+static void CopyToUString_ByLen16(const Byte *p, unsigned numChars16, UString &s)
+{
+  for (; numChars16; numChars16--)
+  {
+    const wchar_t c = (wchar_t)Get16(p);
+    p += 2;
+    s += c;
+  }
+}
+
 static bool CompareWStrStrings(const Byte *p, const char *s)
 {
   unsigned pos = 0;
@@ -1783,7 +1878,7 @@ struct CVersionBlock
 {
   UInt32 TotalLen;
   UInt32 ValueLen;
-  bool IsTextValue;
+  unsigned IsTextValue;
   unsigned StrSize;
 
   bool Parse(const Byte *p, UInt32 size);
@@ -1802,6 +1897,23 @@ static int Get_Utf16Str_Len_InBytes(const Byte *p, size_t size)
   }
 }
 
+static int Get_Utf16Str_Len_InBytes_AllowNonZeroTail(const Byte *p, size_t size)
+{
+  unsigned pos = 0;
+  for (;;)
+  {
+    if (pos + 1 >= size)
+    {
+      if (pos == size)
+        return (int)pos;
+      return -1;
+    }
+    if (Get16(p + pos) == 0)
+      return (int)pos;
+    pos += 2;
+  }
+}
+
 static const unsigned k_ResoureBlockHeader_Size = 6;
 
 bool CVersionBlock::Parse(const Byte *p, UInt32 size)
@@ -1812,14 +1924,12 @@ bool CVersionBlock::Parse(const Byte *p, UInt32 size)
   ValueLen = Get16(p + 2);
   if (TotalLen < k_ResoureBlockHeader_Size || TotalLen > size)
     return false;
-  switch (Get16(p + 4))
-  {
-    case 0: IsTextValue = false; break;
-    case 1: IsTextValue = true; break;
-    default: return false;
-  }
+  IsTextValue = Get16(p + 4);
+  if (IsTextValue > 1)
+    return false;
   StrSize = 0;
-  const int t = Get_Utf16Str_Len_InBytes(p + k_ResoureBlockHeader_Size, TotalLen - k_ResoureBlockHeader_Size);
+  const int t = Get_Utf16Str_Len_InBytes(p + k_ResoureBlockHeader_Size,
+      TotalLen - k_ResoureBlockHeader_Size);
   if (t < 0)
     return false;
   StrSize = (unsigned)t;
@@ -1859,7 +1969,7 @@ static bool ParseVersion(const Byte *p, UInt32 size, CTextFile &f, CObjectVector
     // if (size != vb.TotalLen) return false;
     */
     if (size > vb.TotalLen)
-      size = vb.TotalLen;
+        size = vb.TotalLen;
     CMy_VS_FIXEDFILEINFO FixedFileInfo;
     if (!FixedFileInfo.Parse(p + pos))
       return false;
@@ -1880,7 +1990,7 @@ static bool ParseVersion(const Byte *p, UInt32 size, CTextFile &f, CObjectVector
       return false;
     if (vb.ValueLen != 0)
       return false;
-    UInt32 endPos = pos + vb.TotalLen;
+    const UInt32 endPos = pos + vb.TotalLen;
     pos += k_ResoureBlockHeader_Size;
     
     f.AddSpaces(2);
@@ -1901,7 +2011,7 @@ static bool ParseVersion(const Byte *p, UInt32 size, CTextFile &f, CObjectVector
         CVersionBlock vb2;
         if (!vb2.Parse(p + pos, endPos - pos))
           return false;
-        UInt32 endPos2 = pos + vb2.TotalLen;
+        const UInt32 endPos2 = pos + vb2.TotalLen;
         if (vb2.IsTextValue)
           return false;
         pos += k_ResoureBlockHeader_Size;
@@ -1919,9 +2029,9 @@ static bool ParseVersion(const Byte *p, UInt32 size, CTextFile &f, CObjectVector
         UInt32 num = (vb2.ValueLen >> 2);
         for (; num != 0; num--, pos += 4)
         {
-          UInt32 dw = Get32(p + pos);
-          UInt32 lang = LOWORD(dw);
-          UInt32 codePage = HIWORD(dw);
+          const UInt32 dw = Get32(p + pos);
+          const UInt32 lang = LOWORD(dw);
+          const UInt32 codePage = HIWORD(dw);
 
           f.AddString(", ");
           PrintHex(f, lang);
@@ -1936,7 +2046,6 @@ static bool ParseVersion(const Byte *p, UInt32 size, CTextFile &f, CObjectVector
       if (!CompareWStrStrings(p + pos, "StringFileInfo"))
         return false;
       pos += vb.StrSize + 2;
-  
       for (;;)
       {
         pos += (4 - pos) & 3;
@@ -1945,7 +2054,7 @@ static bool ParseVersion(const Byte *p, UInt32 size, CTextFile &f, CObjectVector
         CVersionBlock vb2;
         if (!vb2.Parse(p + pos, endPos - pos))
           return false;
-        UInt32 endPos2 = pos + vb2.TotalLen;
+        const UInt32 endPos2 = pos + vb2.TotalLen;
         if (vb2.ValueLen != 0)
           return false;
         pos += k_ResoureBlockHeader_Size;
@@ -1967,9 +2076,8 @@ static bool ParseVersion(const Byte *p, UInt32 size, CTextFile &f, CObjectVector
           CVersionBlock vb3;
           if (!vb3.Parse(p + pos, endPos2 - pos))
             return false;
-          // ValueLen sometimes is a number of characters (not bytes)?
-          // So we don't use it.
-          UInt32 endPos3 = pos + vb3.TotalLen;
+          // ValueLen is a number of 16-bit characters (usually it includes zero tail character).
+          const UInt32 endPos3 = pos + vb3.TotalLen;
           pos += k_ResoureBlockHeader_Size;
 
           // we don't write string if it's not text
@@ -1984,26 +2092,35 @@ static bool ParseVersion(const Byte *p, UInt32 size, CTextFile &f, CObjectVector
             pos += vb3.StrSize + 2;
 
             pos += (4 - pos) & 3;
-            if (vb3.ValueLen > 0 && pos + 2 <= endPos3)
+            if (vb3.ValueLen != 0 && pos /* + 2 */ <= endPos3)
             {
               f.AddChar(',');
               f.AddSpaces((34 - (int)vb3.StrSize) / 2);
-              const int sLen = Get_Utf16Str_Len_InBytes(p + pos, endPos3 - pos);
+              // vb3.TotalLen for some PE files (not from msvc) doesn't include tail zero at the end of Value string.
+              // we allow that minor error.
+              const int sLen = Get_Utf16Str_Len_InBytes_AllowNonZeroTail(p + pos, endPos3 - pos);
               if (sLen < 0)
                 return false;
+              /*
+              if (vb3.ValueLen - 1 != (unsigned)sLen / 2 &&
+                  vb3.ValueLen     != (unsigned)sLen / 2)
+                return false;
+              */
               AddParamString(f, p + pos, (unsigned)sLen);
-              CopyToUString(p + pos, value);
-              pos += (unsigned)sLen + 2;
+              CopyToUString_ByLen16(p + pos, (unsigned)sLen / 2, value);
+              // pos += (unsigned)sLen + 2;
             }
             AddToUniqueUStringVector(keys, key, value);
           }
           pos = endPos3;
           f.NewLine();
         }
+        pos = endPos2;
         f.CloseBlock(4);
       }
     }
     f.CloseBlock(2);
+    pos = endPos;
   }
 
   f.CloseBlock(0);
@@ -2218,7 +2335,7 @@ HRESULT CHandler::OpenResources(unsigned sectionIndex, IInStream *stream, IArchi
 
       if (sect2.PSize != 0)
       {
-        sect2.VSize = sect2.PSize;
+        sect2.ExtractSize = sect2.VSize = sect2.PSize;
         sect2.Name = ".rsrc_1";
         sect2.Time = 0;
         sect2.IsAdditionalSection = true;
@@ -2337,6 +2454,20 @@ HRESULT CHandler::Open2(IInStream *stream, IArchiveOpenCallback *callback)
     CSection &sect = _sections.AddNew();
     sect.Parse(buffer + pos);
     sect.IsRealSect = true;
+    if (sect.Name.IsEqualTo(".reloc"))
+    {
+      const CDirLink &dl = _optHeader.DirItems[kDirLink_BASERELOC];
+      if (dl.Va == sect.Va &&
+          dl.Size <= sect.PSize)
+        sect.ExtractSize = dl.Size;
+    }
+    else if (sect.Name.IsEqualTo(".pdata"))
+    {
+      const CDirLink &dl = _optHeader.DirItems[kDirLink_EXCEPTION];
+      if (dl.Va == sect.Va &&
+          dl.Size <= sect.PSize)
+        sect.ExtractSize = dl.Size;
+    }
     
     /* PE pre-file in .hxs file has errors:
          PSize of resource is larger than real size.
@@ -2390,7 +2521,7 @@ HRESULT CHandler::Open2(IInStream *stream, IArchiveOpenCallback *callback)
     sect.Name = "CERTIFICATE";
     sect.Va = 0;
     sect.Pa = certLink.Va;
-    sect.PSize = sect.VSize = certLink.Size;
+    sect.Set_Size_for_all(certLink.Size);
     sect.UpdateTotalSize(_totalSize);
   }
 
@@ -2448,7 +2579,7 @@ HRESULT CHandler::Open2(IInStream *stream, IArchiveOpenCallback *callback)
     sect.Name = "COFF_SYMBOLS";
     sect.Va = 0;
     sect.Pa = _header.PointerToSymbolTable;
-    sect.PSize = sect.VSize = size;
+    sect.Set_Size_for_all(size);
     sect.UpdateTotalSize(_totalSize);
   }
 
@@ -2464,11 +2595,11 @@ HRESULT CHandler::Open2(IInStream *stream, IArchiveOpenCallback *callback)
       {
         CSection &s2 = _sections.AddNew();
         s2.Pa = s2.Va = limit;
-        s2.PSize = s2.VSize = s.Pa - limit;
+        s2.Set_Size_for_all(s.Pa - limit);
         s2.IsAdditionalSection = true;
-        s2.Name = '[';
+        s2.Name.Add_Char('[');
         s2.Name.Add_UInt32(num++);
-        s2.Name += ']';
+        s2.Name.Add_Char(']');
         limit = s.Pa;
       }
       UInt32 next = s.Pa + s.PSize;
@@ -2700,29 +2831,26 @@ Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 numItems,
     else if (mixItem.ResourceIndex >= 0)
       size = _items[mixItem.ResourceIndex].GetSize();
     else
-      size = _sections[mixItem.SectionIndex].GetSizeExtract();
+      size = _sections[mixItem.SectionIndex].GetSize_Extract();
     totalSize += size;
   }
-  extractCallback->SetTotal(totalSize);
-
-  UInt64 currentTotalSize = 0;
-  UInt64 currentItemSize;
-  
-  NCompress::CCopyCoder *copyCoderSpec = new NCompress::CCopyCoder();
-  CMyComPtr<ICompressCoder> copyCoder = copyCoderSpec;
+  RINOK(extractCallback->SetTotal(totalSize))
 
-  CLocalProgress *lps = new CLocalProgress;
-  CMyComPtr<ICompressProgressInfo> progress = lps;
+  CMyComPtr2_Create<ICompressCoder, NCompress::CCopyCoder> copyCoder;
+  CMyComPtr2_Create<ICompressProgressInfo, CLocalProgress> lps;
   lps->Init(extractCallback, false);
+  CMyComPtr2_Create<ISequentialInStream, CLimitedSequentialInStream> inStream;
+  inStream->SetStream(_stream);
 
-  CLimitedSequentialInStream *streamSpec = new CLimitedSequentialInStream;
-  CMyComPtr<ISequentialInStream> inStream(streamSpec);
-  streamSpec->SetStream(_stream);
-
-  for (i = 0; i < numItems; i++, currentTotalSize += currentItemSize)
+  totalSize = 0;
+  UInt64 currentItemSize;
+  
+  for (i = 0;; i++, totalSize += currentItemSize)
   {
-    lps->InSize = lps->OutSize = currentTotalSize;
+    lps->InSize = lps->OutSize = totalSize;
     RINOK(lps->SetCur())
+    if (i >= numItems)
+      break;
     const Int32 askMode = testMode ?
         NExtract::NAskMode::kTest :
         NExtract::NAskMode::kExtract;
@@ -2776,15 +2904,15 @@ Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 numItems,
     }
     else
     {
-      currentItemSize = sect.GetSizeExtract();
+      currentItemSize = sect.GetSize_Extract();
       if (!testMode && !outStream)
         continue;
       
       RINOK(extractCallback->PrepareOperation(askMode))
       RINOK(InStream_SeekSet(_stream, sect.Pa))
-      streamSpec->Init(currentItemSize);
-      RINOK(copyCoder->Code(inStream, outStream, NULL, NULL, progress))
-      isOk = (copyCoderSpec->TotalSize == currentItemSize);
+      inStream->Init(currentItemSize);
+      RINOK(copyCoder.Interface()->Code(inStream, outStream, NULL, NULL, lps))
+      isOk = (copyCoder->TotalSize == currentItemSize);
     }
     
     outStream.Release();
@@ -2804,7 +2932,7 @@ Z7_COM7F_IMF(CHandler::GetStream(UInt32 index, ISequentialInStream **stream))
   const CMixItem &mixItem = _mixItems[index];
   const CSection &sect = _sections[mixItem.SectionIndex];
   if (mixItem.IsSectionItem())
-    return CreateLimitedInStream(_stream, sect.Pa, sect.PSize, stream);
+    return CreateLimitedInStream(_stream, sect.Pa, sect.GetSize_Extract(), stream);
 
   CBufInStream *inStreamSpec = new CBufInStream;
   CMyComPtr<ISequentialInStream> streamTemp = inStreamSpec;
@@ -2964,7 +3092,7 @@ bool CHeader::Parse(const Byte *p)
   G32(12, BaseOfCode);
   G64(16, ImageBase);
   */
-  for (int i = 0; i < 2; i++)
+  for (unsigned i = 0; i < 2; i++)
   {
     CDataDir &dd = DataDir[i];
     dd.Parse(p + 24 + i * 8);
@@ -2997,6 +3125,7 @@ struct CSection
 {
   Byte Name[NPe::kNameSize];
 
+  UInt32 ExtractSize;
   UInt32 VSize;
   UInt32 Va;
   UInt32 PSize;
@@ -3013,6 +3142,7 @@ struct CSection
     G32(20, Pa);
     // G32(p + 32, NumRelocs);
     G32(36, Flags);
+    ExtractSize = (VSize && VSize < PSize) ? VSize : PSize;
   }
 
   bool Check() const
@@ -3022,11 +3152,16 @@ struct CSection
         PSize <= ((UInt32)1 << 30);
   }
 
+  UInt32 GetSize_Extract() const
+  {
+    return ExtractSize;
+  }
+
   void UpdateTotalSize(UInt32 &totalSize)
   {
-    UInt32 t = Pa + PSize;
-    if (t > totalSize)
-      totalSize = t;
+    const UInt32 t = Pa + PSize;
+    if (totalSize < t)
+        totalSize = t;
   }
 };
 
@@ -3050,6 +3185,7 @@ static const Byte kProps[] =
 {
   kpidPath,
   kpidSize,
+  kpidPackSize,
   kpidVirtualSize,
   kpidCharacts,
   kpidOffset,
@@ -3108,7 +3244,7 @@ Z7_COM7F_IMF(CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT *val
         prop = MultiByteToUnicodeString(name);
         break;
       }
-      case kpidSize:
+      case kpidSize: prop = (UInt64)item.GetSize_Extract(); break;
       case kpidPackSize: prop = (UInt64)item.PSize; break;
       case kpidVirtualSize: prop = (UInt64)item.VSize; break;
       case kpidOffset: prop = item.Pa; break;
@@ -3168,13 +3304,13 @@ Z7_COM7F_IMF(CHandler::Open(IInStream *inStream,
 {
   COM_TRY_BEGIN
   Close();
-  try
+  // try
   {
     if (Open2(inStream) != S_OK)
       return S_FALSE;
     _stream = inStream;
   }
-  catch(...) { return S_FALSE; }
+  // catch(...) { return S_FALSE; }
   return S_OK;
   COM_TRY_END
 }
@@ -3205,26 +3341,25 @@ Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 numItems,
   UInt64 totalSize = 0;
   UInt32 i;
   for (i = 0; i < numItems; i++)
-    totalSize += _items[allFilesMode ? i : indices[i]].PSize;
-  extractCallback->SetTotal(totalSize);
-
-  UInt64 currentTotalSize = 0;
-  
-  NCompress::CCopyCoder *copyCoderSpec = new NCompress::CCopyCoder();
-  CMyComPtr<ICompressCoder> copyCoder = copyCoderSpec;
+    totalSize += _items[allFilesMode ? i : indices[i]].GetSize_Extract();
+  RINOK(extractCallback->SetTotal(totalSize))
 
-  CLocalProgress *lps = new CLocalProgress;
-  CMyComPtr<ICompressProgressInfo> progress = lps;
+  CMyComPtr2_Create<ICompressCoder, NCompress::CCopyCoder> copyCoder;
+  CMyComPtr2_Create<ICompressProgressInfo, CLocalProgress> lps;
   lps->Init(extractCallback, false);
+  CMyComPtr2_Create<ISequentialInStream, CLimitedSequentialInStream> inStream;
+  inStream->SetStream(_stream);
 
-  CLimitedSequentialInStream *streamSpec = new CLimitedSequentialInStream;
-  CMyComPtr<ISequentialInStream> inStream(streamSpec);
-  streamSpec->SetStream(_stream);
+  totalSize = 0;
 
-  for (i = 0; i < numItems; i++)
+  for (i = 0;; i++)
   {
-    lps->InSize = lps->OutSize = currentTotalSize;
+    lps->InSize = lps->OutSize = totalSize;
     RINOK(lps->SetCur())
+    if (i >= numItems)
+      break;
+    int opRes;
+    {
     CMyComPtr<ISequentialOutStream> realOutStream;
     const Int32 askMode = testMode ?
         NExtract::NAskMode::kTest :
@@ -3232,21 +3367,22 @@ Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 numItems,
     const UInt32 index = allFilesMode ? i : indices[i];
     const CSection &item = _items[index];
     RINOK(extractCallback->GetStream(index, &realOutStream, askMode))
-    currentTotalSize += item.PSize;
+    const UInt32 size = item.GetSize_Extract();
+    totalSize += size;
     
     if (!testMode && !realOutStream)
       continue;
     RINOK(extractCallback->PrepareOperation(askMode))
-    int res = NExtract::NOperationResult::kDataError;
-
     RINOK(InStream_SeekSet(_stream, item.Pa))
-    streamSpec->Init(item.PSize);
-    RINOK(copyCoder->Code(inStream, realOutStream, NULL, NULL, progress))
-    if (copyCoderSpec->TotalSize == item.PSize)
-      res = NExtract::NOperationResult::kOK;
+    inStream->Init(size);
+    RINOK(copyCoder.Interface()->Code(inStream, realOutStream, NULL, NULL, lps))
 
-    realOutStream.Release();
-    RINOK(extractCallback->SetOperationResult(res))
+      opRes = (copyCoder->TotalSize == size) ?
+          NExtract::NOperationResult::kOK : (copyCoder->TotalSize < size) ?
+          NExtract::NOperationResult::kUnexpectedEnd :
+          NExtract::NOperationResult::kDataError;
+    }
+    RINOK(extractCallback->SetOperationResult(opRes))
   }
   return S_OK;
   COM_TRY_END
@@ -3256,7 +3392,7 @@ Z7_COM7F_IMF(CHandler::GetStream(UInt32 index, ISequentialInStream **stream))
 {
   COM_TRY_BEGIN
   const CSection &item = _items[index];
-  return CreateLimitedInStream(_stream, item.Pa, item.PSize, stream);
+  return CreateLimitedInStream(_stream, item.Pa, item.GetSize_Extract(), stream);
   COM_TRY_END
 }
 
diff --git a/CPP/7zip/Archive/QcowHandler.cpp b/CPP/7zip/Archive/QcowHandler.cpp
index 5a80daa..b072880 100644
--- a/CPP/7zip/Archive/QcowHandler.cpp
+++ b/CPP/7zip/Archive/QcowHandler.cpp
@@ -11,6 +11,7 @@
 #include "../../Common/MyBuffer2.h"
 
 #include "../../Windows/PropVariant.h"
+#include "../../Windows/PropVariantUtils.h"
 
 #include "../Common/RegisterArc.h"
 #include "../Common/StreamObjects.h"
@@ -20,8 +21,8 @@
 
 #include "HandlerCont.h"
 
-#define Get32(p) GetBe32(p)
-#define Get64(p) GetBe64(p)
+#define Get32(p) GetBe32a(p)
+#define Get64(p) GetBe64a(p)
 
 using namespace NWindows;
 
@@ -32,9 +33,9 @@ static const Byte k_Signature[] =  { 'Q', 'F', 'I', 0xFB, 0, 0, 0 };
 
 /*
 VA to PA maps:
-  high bits (L1) :              : in L1 Table : the reference to L1 Table
-  mid bits  (L2) : _numMidBits  : in L2 Table : the reference to cluster
-  low bits       : _clusterBits
+  high bits (L1) :              : index in L1 (_dir) : _dir[high_index] points to Table.
+  mid bits  (L2) : _numMidBits  : index in Table, Table[index] points to cluster start offset in arc file.
+  low bits       : _clusterBits : offset inside cluster.
 */
 
 Z7_class_CHandler_final: public CHandlerImg
@@ -49,30 +50,27 @@ Z7_class_CHandler_final: public CHandlerImg
 
   CObjArray2<UInt32> _dir;
   CAlignedBuffer _table;
-  UInt64 _cacheCluster;
   CByteBuffer _cache;
   CByteBuffer _cacheCompressed;
+  UInt64 _cacheCluster;
 
   UInt64 _comprPos;
   size_t _comprSize;
 
-  UInt64 _phySize;
-
-  CBufInStream *_bufInStreamSpec;
-  CMyComPtr<ISequentialInStream> _bufInStream;
-
-  CBufPtrSeqOutStream *_bufOutStreamSpec;
-  CMyComPtr<ISequentialOutStream> _bufOutStream;
-
-  NCompress::NDeflate::NDecoder::CCOMCoder *_deflateDecoderSpec;
-  CMyComPtr<ICompressCoder> _deflateDecoder;
-
-  bool _needDeflate;
+  bool _needCompression;
   bool _isArc;
   bool _unsupported;
+  Byte _compressionType;
+
+  UInt64 _phySize;
+
+  CMyComPtr2<ISequentialInStream, CBufInStream> _bufInStream;
+  CMyComPtr2<ISequentialOutStream, CBufPtrSeqOutStream> _bufOutStream;
+  CMyComPtr2<ICompressCoder, NCompress::NDeflate::NDecoder::CCOMCoder> _deflateDecoder;
 
   UInt32 _version;
   UInt32 _cryptMethod;
+  UInt64 _incompatFlags;
   
   HRESULT Seek2(UInt64 offset)
   {
@@ -96,13 +94,11 @@ Z7_COM7F_IMF(CHandler::Read(void *data, UInt32 size, UInt32 *processedSize))
 {
   if (processedSize)
     *processedSize = 0;
-
   // printf("\nRead _virtPos = %6d  size = %6d\n", (UInt32)_virtPos, size);
-
   if (_virtPos >= _size)
     return S_OK;
   {
-    UInt64 rem = _size - _virtPos;
+    const UInt64 rem = _size - _virtPos;
     if (size > rem)
       size = (UInt32)rem;
     if (size == 0)
@@ -115,47 +111,43 @@ Z7_COM7F_IMF(CHandler::Read(void *data, UInt32 size, UInt32 *processedSize))
     const size_t clusterSize = (size_t)1 << _clusterBits;
     const size_t lowBits = (size_t)_virtPos & (clusterSize - 1);
     {
-      size_t rem = clusterSize - lowBits;
+      const size_t rem = clusterSize - lowBits;
       if (size > rem)
         size = (UInt32)rem;
     }
-
     if (cluster == _cacheCluster)
     {
       memcpy(data, _cache + lowBits, size);
       break;
     }
-    
+   
     const UInt64 high = cluster >> _numMidBits;
  
     if (high < _dir.Size())
     {
-      const UInt32 tabl = _dir[(unsigned)high];
-    
+      const UInt32 tabl = _dir[(size_t)high];
       if (tabl != kEmptyDirItem)
       {
-        const Byte *buffer = _table + ((size_t)tabl << (_numMidBits + 3));
         const size_t midBits = (size_t)cluster & (((size_t)1 << _numMidBits) - 1);
-        const Byte *p = (const Byte *)buffer + (midBits << 3);
+        const Byte *p = _table + ((((size_t)tabl << _numMidBits) + midBits) << 3);
         UInt64 v = Get64(p);
         
-        if (v != 0)
+        if (v)
         {
-          if ((v & _compressedFlag) != 0)
+          if (v & _compressedFlag)
           {
             if (_version <= 1)
               return E_FAIL;
-
             /*
-            the example of table record for 12-bit clusters (4KB uncompressed).
-             2 bits : isCompressed status
-             4 bits : num_sectors_minus1; packSize = (num_sectors_minus1 + 1) * 512;
-                      it uses one additional bit over unpacked cluster_bits
-            49 bits : offset of 512-sector
-             9 bits : offset in 512-sector
+            the example of table record for 12-bit clusters (4KB uncompressed):
+              2 bits : isCompressed status
+              (4 == _clusterBits - 8) bits : (num_sectors - 1)
+                  packSize = num_sectors * 512;
+                  it uses one additional bit over unpacked cluster_bits.
+              (49 == 61 - _clusterBits) bits : offset of 512-byte sector
+              9 bits : offset in 512-byte sector
             */
-
-            const unsigned numOffsetBits = (62 - (_clusterBits - 9 + 1));
+            const unsigned numOffsetBits = 62 - (_clusterBits - 8);
             const UInt64 offset = v & (((UInt64)1 << 62) - 1);
             const size_t dataSize = ((size_t)(offset >> numOffsetBits) + 1) << 9;
             UInt64 sectorOffset = offset & (((UInt64)1 << numOffsetBits) - (1 << 9));
@@ -167,7 +159,7 @@ Z7_COM7F_IMF(CHandler::Read(void *data, UInt32 size, UInt32 *processedSize))
 
             if (sectorOffset >= _comprPos && offset2inCache < _comprSize)
             {
-              if (offset2inCache != 0)
+              if (offset2inCache)
               {
                 _comprSize -= (size_t)offset2inCache;
                 memmove(_cacheCompressed, _cacheCompressed + (size_t)offset2inCache, _comprSize);
@@ -193,39 +185,34 @@ Z7_COM7F_IMF(CHandler::Read(void *data, UInt32 size, UInt32 *processedSize))
               const size_t dataSize3 = dataSize - _comprSize;
               size_t dataSize2 = dataSize3;
               // printf("\n\n=======\nReadStream = %6d _comprPos = %6d \n", (UInt32)dataSize2, (UInt32)_comprPos);
-              RINOK(ReadStream(Stream, _cacheCompressed + _comprSize, &dataSize2))
+              const HRESULT hres = ReadStream(Stream, _cacheCompressed + _comprSize, &dataSize2);
               _posInArc += dataSize2;
+              RINOK(hres)
               if (dataSize2 != dataSize3)
                 return E_FAIL;
               _comprSize += dataSize2;
             }
             
             const size_t kSectorMask = (1 << 9) - 1;
-            const size_t offsetInSector = ((size_t)offset & kSectorMask);
-            _bufInStreamSpec->Init(_cacheCompressed + offsetInSector, dataSize - offsetInSector);
-            
+            const size_t offsetInSector = (size_t)offset & kSectorMask;
+            _bufInStream->Init(_cacheCompressed + offsetInSector, dataSize - offsetInSector);
             _cacheCluster = (UInt64)(Int64)-1;
             if (_cache.Size() < clusterSize)
               return E_FAIL;
-            _bufOutStreamSpec->Init(_cache, clusterSize);
-            
+            _bufOutStream->Init(_cache, clusterSize);
             // Do we need to use smaller block than clusterSize for last cluster?
             const UInt64 blockSize64 = clusterSize;
-            HRESULT res = _deflateDecoder->Code(_bufInStream, _bufOutStream, NULL, &blockSize64, NULL);
-
+            HRESULT res = _deflateDecoder.Interface()->Code(_bufInStream, _bufOutStream, NULL, &blockSize64, NULL);
             /*
             if (_bufOutStreamSpec->GetPos() != clusterSize)
               memset(_cache + _bufOutStreamSpec->GetPos(), 0, clusterSize - _bufOutStreamSpec->GetPos());
             */
-
             if (res == S_OK)
-              if (!_deflateDecoderSpec->IsFinished()
-                  || _bufOutStreamSpec->GetPos() != clusterSize)
+              if (!_deflateDecoder->IsFinished()
+                  || _bufOutStream->GetPos() != clusterSize)
                 res = S_FALSE;
-
             RINOK(res)
             _cacheCluster = cluster;
-            
             continue;
             /*
             memcpy(data, _cache + lowBits, size);
@@ -233,17 +220,17 @@ Z7_COM7F_IMF(CHandler::Read(void *data, UInt32 size, UInt32 *processedSize))
             */
           }
 
-          // version 3 support zero clusters
+          // version_3 supports zero clusters
           if (((UInt32)v & 511) != 1)
           {
-            v &= (_compressedFlag - 1);
+            v &= _compressedFlag - 1;
             v += lowBits;
             if (v != _posInArc)
             {
               // printf("\n%12I64x\n", v - _posInArc);
               RINOK(Seek2(v))
             }
-            HRESULT res = Stream->Read(data, size, &size);
+            const HRESULT res = Stream->Read(data, size, &size);
             _posInArc += size;
             _virtPos += size;
             if (processedSize)
@@ -274,13 +261,25 @@ static const Byte kProps[] =
 static const Byte kArcProps[] =
 {
   kpidClusterSize,
+  kpidSectorSize, // actually we need variable to show table size
+  kpidHeadersSize,
   kpidUnpackVer,
-  kpidMethod
+  kpidMethod,
+  kpidCharacts
 };
 
 IMP_IInArchive_Props
 IMP_IInArchive_ArcProps
 
+static const CUInt32PCharPair g_IncompatFlags_Characts[] =
+{
+  {  0, "Dirty" },
+  {  1, "Corrupt" },
+  {  2, "External_Data_File" },
+  {  3, "Compression" },
+  {  4, "Extended_L2" }
+};
+
 Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
 {
   COM_TRY_BEGIN
@@ -290,28 +289,54 @@ Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
   {
     case kpidMainSubfile: prop = (UInt32)0; break;
     case kpidClusterSize: prop = (UInt32)1 << _clusterBits; break;
-    case kpidPhySize: if (_phySize != 0) prop = _phySize; break;
+    case kpidSectorSize: prop = (UInt32)1 << (_numMidBits + 3); break;
+    case kpidHeadersSize: prop = _table.Size() + (UInt64)_dir.Size() * 8; break;
+    case kpidPhySize: if (_phySize) prop = _phySize; break;
     case kpidUnpackVer: prop = _version; break;
-
+    case kpidCharacts:
+    {
+      if (_incompatFlags)
+      {
+        AString s ("incompatible: ");
+        // we need to show also high 32-bits.
+        s += FlagsToString(g_IncompatFlags_Characts,
+            Z7_ARRAY_SIZE(g_IncompatFlags_Characts), (UInt32)_incompatFlags);
+        prop = s;
+      }
+      break;
+    }
     case kpidMethod:
     {
       AString s;
 
-      if (_needDeflate)
-        s = "Deflate";
+      if (_compressionType)
+      {
+        if (_compressionType == 1)
+          s += "ZSTD";
+        else
+        {
+          s += "Compression:";
+          s.Add_UInt32(_compressionType);
+        }
+      }
+      else if (_needCompression)
+        s.Add_OptSpaced("Deflate");
 
-      if (_cryptMethod != 0)
+      if (_cryptMethod)
       {
         s.Add_Space_if_NotEmpty();
         if (_cryptMethod == 1)
           s += "AES";
+        if (_cryptMethod == 2)
+          s += "LUKS";
         else
+        {
+          s += "Encryption:";
           s.Add_UInt32(_cryptMethod);
+        }
       }
-      
       if (!s.IsEmpty())
         prop = s;
-
       break;
     }
 
@@ -321,9 +346,9 @@ Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
       if (!_isArc) v |= kpv_ErrorFlags_IsNotArc;
       if (_unsupported) v |= kpv_ErrorFlags_UnsupportedMethod;
       // if (_headerError) v |= kpv_ErrorFlags_HeadersError;
-      if (!Stream && v == 0 && _isArc)
+      if (!Stream && v == 0)
         v = kpv_ErrorFlags_HeadersError;
-      if (v != 0)
+      if (v)
         prop = v;
       break;
     }
@@ -355,76 +380,91 @@ Z7_COM7F_IMF(CHandler::GetProperty(UInt32 /* index */, PROPID propID, PROPVARIAN
 
 HRESULT CHandler::Open2(IInStream *stream, IArchiveOpenCallback *openCallback)
 {
-  const unsigned kHeaderSize = 18 * 4;
-  Byte buf[kHeaderSize];
-  RINOK(ReadStream_FALSE(stream, buf, kHeaderSize))
-
-  if (memcmp(buf, k_Signature, 4) != 0)
+  UInt64 buf64[0x70 / 8];
+  RINOK(ReadStream_FALSE(stream, buf64, sizeof(buf64)))
+  const void *buf = (const void *)buf64;
+  // signature: { 'Q', 'F', 'I', 0xFB }
+  if (*(const UInt32 *)buf != Z7_CONV_BE_TO_NATIVE_CONST32(0x514649fb))
     return S_FALSE;
-
-  _version = Get32(buf + 4);
+  _version = Get32((const Byte *)(const void *)buf64 + 4);
   if (_version < 1 || _version > 3)
     return S_FALSE;
   
-  const UInt64 backOffset = Get64(buf + 8);
-  // UInt32 backSize = Get32(buf + 0x10);
-  
-  UInt64 l1Offset;
-  UInt32 l1Size;
+  const UInt64 k_UncompressedSize_MAX = (UInt64)1 << 60;
+  const UInt64 k_CompressedSize_MAX   = (UInt64)1 << 60;
+
+  _size = Get64((const Byte *)(const void *)buf64 + 0x18);
+  if (_size > k_UncompressedSize_MAX)
+    return S_FALSE;
+  size_t l1Size;
+  UInt32 headerSize;
 
   if (_version == 1)
   {
-    // _mTime = Get32(buf + 0x14); // is unused im most images
-    _size = Get64(buf + 0x18);
-    _clusterBits = buf[0x20];
-    _numMidBits = buf[0x21];
+    // _mTime = Get32((const Byte *)(const void *)buf64 + 0x14); // is unused in most images
+    _clusterBits = ((const Byte *)(const void *)buf64)[0x20];
+    _numMidBits  = ((const Byte *)(const void *)buf64)[0x21];
     if (_clusterBits < 9 || _clusterBits > 30)
       return S_FALSE;
     if (_numMidBits < 1 || _numMidBits > 28)
       return S_FALSE;
-    _cryptMethod = Get32(buf + 0x24);
-    l1Offset = Get64(buf + 0x28);
-    if (l1Offset < 0x30)
-      return S_FALSE;
-    const unsigned numBits2 = (_clusterBits + _numMidBits);
+    _cryptMethod = Get32((const Byte *)(const void *)buf64 + 0x24);
+    const unsigned numBits2 = _clusterBits + _numMidBits;
     const UInt64 l1Size64 = (_size + (((UInt64)1 << numBits2) - 1)) >> numBits2;
     if (l1Size64 > ((UInt32)1 << 31))
       return S_FALSE;
-    l1Size = (UInt32)l1Size64;
+    l1Size = (size_t)l1Size64;
+    headerSize = 0x30;
   }
   else
   {
-    _clusterBits = Get32(buf + 0x14);
+    _clusterBits = Get32((const Byte *)(const void *)buf64 + 0x14);
     if (_clusterBits < 9 || _clusterBits > 30)
       return S_FALSE;
     _numMidBits = _clusterBits - 3;
-    _size = Get64(buf + 0x18);
-    _cryptMethod = Get32(buf + 0x20);
-    l1Size = Get32(buf + 0x24);
-    l1Offset = Get64(buf + 0x28); // must be aligned for cluster
-    
-    const UInt64 refOffset = Get64(buf + 0x30); // must be aligned for cluster
-    const UInt32 refClusters = Get32(buf + 0x38);
-    
-    // UInt32 numSnapshots = Get32(buf + 0x3C);
-    // UInt64 snapshotsOffset = Get64(buf + 0x40); // must be aligned for cluster
+    _cryptMethod = Get32((const Byte *)(const void *)buf64 + 0x20);
+    l1Size = Get32((const Byte *)(const void *)buf64 + 0x24);
+    headerSize = 0x48;
+    if (_version >= 3)
+    {
+      _incompatFlags = Get64((const Byte *)(const void *)buf64 + 0x48);
+      // const UInt64 CompatFlags    = Get64((const Byte *)(const void *)buf64 + 0x50);
+      // const UInt64 AutoClearFlags = Get64((const Byte *)(const void *)buf64 + 0x58);
+      // const UInt32 RefCountOrder = Get32((const Byte *)(const void *)buf64 + 0x60);
+      headerSize = 0x68;
+      const UInt32 headerSize2  = Get32((const Byte *)(const void *)buf64 + 0x64);
+      if (headerSize2 > (1u << 30))
+        return S_FALSE;
+      if (headerSize < headerSize2)
+          headerSize = headerSize2;
+      if (headerSize2 >= 0x68 + 1)
+        _compressionType = ((const Byte *)(const void *)buf64)[0x68];
+    }
+
+    const UInt64 refOffset = Get64((const Byte *)(const void *)buf64 + 0x30); // must be aligned for cluster
+    const UInt32 refClusters = Get32((const Byte *)(const void *)buf64 + 0x38);
+    // UInt32 numSnapshots = Get32((const Byte *)(const void *)buf64 + 0x3C);
+    // UInt64 snapshotsOffset = Get64((const Byte *)(const void *)buf64 + 0x40); // must be aligned for cluster
     /*
-    if (numSnapshots != 0)
+    if (numSnapshots)
       return S_FALSE;
     */
-
-    if (refClusters != 0)
+    if (refClusters)
     {
-      const size_t numBytes = refClusters << _clusterBits;
+      if (refOffset > k_CompressedSize_MAX)
+        return S_FALSE;
+      const UInt64 numBytes = (UInt64)refClusters << _clusterBits;
+      const UInt64 end = refOffset + numBytes;
+      if (end > k_CompressedSize_MAX)
+        return S_FALSE;
       /*
       CByteBuffer refs;
       refs.Alloc(numBytes);
       RINOK(InStream_SeekSet(stream, refOffset))
       RINOK(ReadStream_FALSE(stream, refs, numBytes));
       */
-      const UInt64 end = refOffset + numBytes;
       if (_phySize < end)
-        _phySize = end;
+          _phySize = end;
       /*
       for (size_t i = 0; i < numBytes; i += 2)
       {
@@ -436,48 +476,76 @@ HRESULT CHandler::Open2(IInStream *stream, IArchiveOpenCallback *openCallback)
     }
   }
 
-  _isArc = true;
+  const UInt64 l1Offset = Get64((const Byte *)(const void *)buf64 + 0x28); // must be aligned for cluster ?
+  if (l1Offset < headerSize || l1Offset > k_CompressedSize_MAX)
+    return S_FALSE;
+  if (_phySize < headerSize)
+      _phySize = headerSize;
 
-  if (backOffset != 0)
+  _isArc = true;
   {
-    _unsupported = true;
-    return S_FALSE;
+    const UInt64 backOffset = Get64((const Byte *)(const void *)buf64 + 8);
+    // UInt32 backSize = Get32((const Byte *)(const void *)buf64 + 0x10);
+    if (backOffset)
+    {
+      _unsupported = true;
+      return S_FALSE;
+    }
   }
 
-  const size_t clusterSize = (size_t)1 << _clusterBits;
+  UInt64 fileSize = 0;
+  RINOK(InStream_GetSize_SeekToBegin(stream, fileSize))
 
-  CByteBuffer table;
+  const size_t clusterSize = (size_t)1 << _clusterBits;
+  const size_t t1SizeBytes = (size_t)l1Size << 3;
   {
-    const size_t t1SizeBytes = (size_t)l1Size << 3;
-    if ((t1SizeBytes >> 3) != l1Size)
+    const UInt64 end = l1Offset + t1SizeBytes;
+    if (end > k_CompressedSize_MAX)
       return S_FALSE;
-    table.Alloc(t1SizeBytes);
-    RINOK(InStream_SeekSet(stream, l1Offset))
-    RINOK(ReadStream_FALSE(stream, table, t1SizeBytes))
-    
-    {
-      UInt64 end = l1Offset + t1SizeBytes;
-      // we need to uses align end for empty qcow files
-      end = (end + clusterSize - 1) >> _clusterBits << _clusterBits;
-      if (_phySize < end)
+    // we need to use align end for empty qcow files
+    // some files has no cluster alignment padding at the end
+    // but has sector alignment
+    // end = (end + clusterSize - 1) >> _clusterBits << _clusterBits;
+    if (_phySize < end)
         _phySize = end;
+    if (end > fileSize)
+      return S_FALSE;
+    if (_phySize < fileSize)
+    {
+      const UInt64 end2 = (end + 511) & ~(UInt64)511;
+      if (end2 == fileSize)
+        _phySize = end2;
     }
   }
+  CObjArray<UInt64> table64(l1Size);
+  {
+    // if ((t1SizeBytes >> 3) != l1Size) return S_FALSE;
+    RINOK(InStream_SeekSet(stream, l1Offset))
+    RINOK(ReadStream_FALSE(stream, table64, t1SizeBytes))
+  }
 
   _compressedFlag = (_version <= 1) ? ((UInt64)1 << 63) : ((UInt64)1 << 62);
   const UInt64 offsetMask = _compressedFlag - 1;
+  const size_t midSize = (size_t)1 << (_numMidBits + 3);
+  size_t numTables = 0;
+  size_t i;
 
-  UInt32 numTables = 0;
-  UInt32 i;
-  
   for (i = 0; i < l1Size; i++)
   {
-    const UInt64 v = Get64((const Byte *)table + (size_t)i * 8) & offsetMask;
-    if (v != 0)
-      numTables++;
+    const UInt64 v = Get64(table64 + (size_t)i) & offsetMask;
+    if (!v)
+      continue;
+    numTables++;
+    const UInt64 end = v + midSize;
+    if (end > k_CompressedSize_MAX)
+      return S_FALSE;
+    if (_phySize < end)
+        _phySize = end;
+    if (end > fileSize)
+      return S_FALSE;
   }
 
-  if (numTables != 0)
+  if (numTables)
   {
     const size_t size = (size_t)numTables << (_numMidBits + 3);
     if (size >> (_numMidBits + 3) != numTables)
@@ -485,48 +553,38 @@ HRESULT CHandler::Open2(IInStream *stream, IArchiveOpenCallback *openCallback)
     _table.Alloc(size);
     if (!_table.IsAllocated())
       return E_OUTOFMEMORY;
+    if (openCallback)
+    {
+      const UInt64 totalBytes = size;
+      RINOK(openCallback->SetTotal(NULL, &totalBytes))
+    }
   }
 
-  _dir.SetSize(l1Size);
+  _dir.SetSize((unsigned)l1Size);
 
   UInt32 curTable = 0;
 
-  if (openCallback)
-  {
-    const UInt64 totalBytes = (UInt64)numTables << (_numMidBits + 3);
-    RINOK(openCallback->SetTotal(NULL, &totalBytes))
-  }
-
   for (i = 0; i < l1Size; i++)
   {
     Byte *buf2;
-    const size_t midSize = (size_t)1 << (_numMidBits + 3);
-   
     {
-      const UInt64 v = Get64((const Byte *)table + (size_t)i * 8) & offsetMask;
+      const UInt64 v = Get64(table64 + (size_t)i) & offsetMask;
       if (v == 0)
       {
         _dir[i] = kEmptyDirItem;
         continue;
       }
-
       _dir[i] = curTable;
-      const size_t tableOffset = ((size_t)curTable << (_numMidBits + 3));
+      const size_t tableOffset = (size_t)curTable << (_numMidBits + 3);
       buf2 = (Byte *)_table + tableOffset;
       curTable++;
-
       if (openCallback && (tableOffset & 0xFFFFF) == 0)
       {
         const UInt64 numBytes = tableOffset;
         RINOK(openCallback->SetCompleted(NULL, &numBytes))
       }
-      
       RINOK(InStream_SeekSet(stream, v))
       RINOK(ReadStream_FALSE(stream, buf2, midSize))
-
-      const UInt64 end = v + midSize;
-      if (_phySize < end)
-        _phySize = end;
     }
 
     for (size_t k = 0; k < midSize; k += 8)
@@ -537,33 +595,30 @@ HRESULT CHandler::Open2(IInStream *stream, IArchiveOpenCallback *openCallback)
       UInt64 offset = v & offsetMask;
       size_t dataSize = clusterSize;
       
-      if ((v & _compressedFlag) != 0)
+      if (v & _compressedFlag)
       {
         if (_version <= 1)
         {
-          unsigned numOffsetBits = (63 - _clusterBits);
+          const unsigned numOffsetBits = 63 - _clusterBits;
           dataSize = ((size_t)(offset >> numOffsetBits) + 1) << 9;
           offset &= ((UInt64)1 << numOffsetBits) - 1;
-          dataSize = 0;
-          // offset >>= 9;
-          // offset <<= 9;
+          dataSize = 0; // why ?
+          // offset &= ~(((UInt64)1 << 9) - 1);
         }
         else
         {
-          unsigned numOffsetBits = (62 - (_clusterBits - 8));
+          const unsigned numOffsetBits = 62 - (_clusterBits - 8);
           dataSize = ((size_t)(offset >> numOffsetBits) + 1) << 9;
-          offset &= ((UInt64)1 << numOffsetBits) - 1;
-          offset >>= 9;
-          offset <<= 9;
+          offset &= ((UInt64)1 << numOffsetBits) - (1 << 9);
         }
-        _needDeflate = true;
+        _needCompression = true;
       }
       else
       {
-        UInt32 low = (UInt32)v & 511;
-        if (low != 0)
+        const UInt32 low = (UInt32)v & 511;
+        if (low)
         {
-          // version 3 support zero clusters
+          // version_3 supports zero clusters
           if (_version < 3 || low != 1)
           {
             _unsupported = true;
@@ -574,17 +629,18 @@ HRESULT CHandler::Open2(IInStream *stream, IArchiveOpenCallback *openCallback)
       
       const UInt64 end = offset + dataSize;
       if (_phySize < end)
-        _phySize = end;
+          _phySize = end;
     }
   }
 
   if (curTable != numTables)
     return E_FAIL;
 
-  if (_cryptMethod != 0)
+  if (_cryptMethod)
     _unsupported = true;
-
-  if (_needDeflate && _version <= 1) // that case was not implemented
+  if (_needCompression && _version <= 1) // that case was not implemented
+    _unsupported = true;
+  if (_compressionType)
     _unsupported = true;
 
   Stream = stream;
@@ -596,16 +652,21 @@ Z7_COM7F_IMF(CHandler::Close())
 {
   _table.Free();
   _dir.Free();
+  // _cache.Free();
+  // _cacheCompressed.Free();
   _phySize = 0;
 
   _cacheCluster = (UInt64)(Int64)-1;
   _comprPos = 0;
   _comprSize = 0;
-  _needDeflate = false;
 
+  _needCompression = false;
   _isArc = false;
   _unsupported = false;
 
+  _compressionType = 0;
+  _incompatFlags = 0;
+
   // CHandlerImg:
   Clear_HandlerImg_Vars();
   Stream.Release();
@@ -617,39 +678,20 @@ Z7_COM7F_IMF(CHandler::GetStream(UInt32 /* index */, ISequentialInStream **strea
 {
   COM_TRY_BEGIN
   *stream = NULL;
-
-  if (_unsupported)
+  if (_unsupported || !Stream)
     return S_FALSE;
-
-  if (_needDeflate)
+  if (_needCompression)
   {
-    if (_version <= 1)
+    if (_version <= 1 || _compressionType)
       return S_FALSE;
-
-    if (!_bufInStream)
-    {
-      _bufInStreamSpec = new CBufInStream;
-      _bufInStream = _bufInStreamSpec;
-    }
-    
-    if (!_bufOutStream)
-    {
-      _bufOutStreamSpec = new CBufPtrSeqOutStream();
-      _bufOutStream = _bufOutStreamSpec;
-    }
-
-    if (!_deflateDecoder)
-    {
-      _deflateDecoderSpec = new NCompress::NDeflate::NDecoder::CCOMCoder();
-      _deflateDecoder = _deflateDecoderSpec;
-      _deflateDecoderSpec->Set_NeedFinishInput(true);
-    }
-    
+    _bufInStream.Create_if_Empty();
+    _bufOutStream.Create_if_Empty();
+    _deflateDecoder.Create_if_Empty();
+    _deflateDecoder->Set_NeedFinishInput(true);
     const size_t clusterSize = (size_t)1 << _clusterBits;
     _cache.AllocAtLeast(clusterSize);
     _cacheCompressed.AllocAtLeast(clusterSize * 2);
   }
-    
   CMyComPtr<ISequentialInStream> streamTemp = this;
   RINOK(InitAndSeek())
   *stream = streamTemp.Detach();
diff --git a/CPP/7zip/Archive/Rar/Rar5Handler.cpp b/CPP/7zip/Archive/Rar/Rar5Handler.cpp
index b786f3e..34615c2 100644
--- a/CPP/7zip/Archive/Rar/Rar5Handler.cpp
+++ b/CPP/7zip/Archive/Rar/Rar5Handler.cpp
@@ -1456,7 +1456,7 @@ Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
             }
             if (arcInfo->Locator.Is_Recovery())
             {
-              s += "Recovery:";
+              s.Add_OptSpaced("Recovery:");
               s.Add_UInt64(arcInfo->Locator.Recovery);
             }
           }
diff --git a/CPP/7zip/Archive/UefiHandler.cpp b/CPP/7zip/Archive/UefiHandler.cpp
index 9462e97..b224cdf 100644
--- a/CPP/7zip/Archive/UefiHandler.cpp
+++ b/CPP/7zip/Archive/UefiHandler.cpp
@@ -1579,6 +1579,8 @@ HRESULT CHandler::OpenCapsule(IInStream *stream)
        || _h.CapsuleImageSize < _h.HeaderSize
        || _h.OffsetToCapsuleBody < _h.HeaderSize
        || _h.OffsetToCapsuleBody > _h.CapsuleImageSize
+       || _h.CapsuleImageSize > (1u << 30) // to reduce false detection
+       || _h.HeaderSize > (1u << 28) // to reduce false detection
       )
     return S_FALSE;
   _phySize = _h.CapsuleImageSize;
@@ -1587,7 +1589,7 @@ HRESULT CHandler::OpenCapsule(IInStream *stream)
       _h.OffsetToSplitInformation != 0 )
     return E_NOTIMPL;
 
-  unsigned bufIndex = AddBuf(_h.CapsuleImageSize);
+  const unsigned bufIndex = AddBuf(_h.CapsuleImageSize);
   CByteBuffer &buf0 = _bufs[bufIndex];
   memcpy(buf0, buf, kHeaderSize);
   ReadStream_FALSE(stream, buf0 + kHeaderSize, _h.CapsuleImageSize - kHeaderSize);
diff --git a/CPP/7zip/Archive/Zip/ZipUpdate.cpp b/CPP/7zip/Archive/Zip/ZipUpdate.cpp
index b2742b7..bc047b7 100644
--- a/CPP/7zip/Archive/Zip/ZipUpdate.cpp
+++ b/CPP/7zip/Archive/Zip/ZipUpdate.cpp
@@ -1755,16 +1755,17 @@ HRESULT CCacheOutStream::FlushFromCache(size_t size)
   PRF(printf("\n-- CCacheOutStream::FlushFromCache %u\n", (unsigned)size));
   if (_hres != S_OK)
     return _hres;
-  if (size == 0 || _cachedSize == 0)
+  if (size > _cachedSize)
+      size = _cachedSize;
+  // (size <= _cachedSize)
+  if (size == 0)
     return S_OK;
   RINOK(SeekPhy(_cachedPos))
   for (;;)
   {
     // (_phyPos == _cachedPos)
     const size_t pos = (size_t)_cachedPos & kCacheMask;
-    size_t cur = kCacheSize - pos;
-    cur = MyMin(cur, _cachedSize);
-    cur = MyMin(cur, size);
+    const size_t cur = MyMin(kCacheSize - pos, size);
     _hres = SetRestriction_ForWrite(cur);
     RINOK(_hres)
     PRF(printf("\n-- CCacheOutStream::WriteFromCache _phyPos = 0x%x, size = %d\n", (unsigned)_phyPos, (unsigned)cur));
@@ -1776,7 +1777,7 @@ HRESULT CCacheOutStream::FlushFromCache(size_t size)
     _cachedPos += cur;
     _cachedSize -= cur;
     size -= cur;
-    if (size == 0 || _cachedSize == 0)
+    if (size == 0)
       return S_OK;
   }
 }
@@ -1964,7 +1965,11 @@ Z7_COM7F_IMF(CCacheOutStream::SetSize(UInt64 newSize))
       // so we reduce cache
       _cachedSize = (size_t)offset;
       if (_phySize <= newSize)
-        return S_OK; // _phySize will be restored later after cache flush
+      {
+        // _phySize will be restored later after cache flush
+        _virtSize = newSize;
+        return S_OK;
+      }
       // (_phySize > newSize)
       // so we must reduce phyStream size to (newSize) or to (_cachedPos)
       // newPhySize = _cachedPos; // optional reduce to _cachedPos
diff --git a/CPP/7zip/Bundles/Alone/afxres.h b/CPP/7zip/Bundles/Alone/afxres.h
deleted file mode 100644
index c2fadd4..0000000
--- a/CPP/7zip/Bundles/Alone/afxres.h
+++ /dev/null
@@ -1 +0,0 @@
-#include <winresrc.h>
diff --git a/CPP/7zip/Bundles/SFXCon/SfxCon.cpp b/CPP/7zip/Bundles/SFXCon/SfxCon.cpp
index cfce24d..aac4e28 100644
--- a/CPP/7zip/Bundles/SFXCon/SfxCon.cpp
+++ b/CPP/7zip/Bundles/SFXCon/SfxCon.cpp
@@ -422,7 +422,7 @@ int Main2(
     {
       CExtractCallbackConsole *ecs = new CExtractCallbackConsole;
       CMyComPtr<IFolderArchiveExtractCallback> extractCallback = ecs;
-      ecs->Init(g_StdStream, &g_StdErr, g_StdStream);
+      ecs->Init(g_StdStream, &g_StdErr, g_StdStream, false);
 
       #ifndef Z7_NO_CRYPTO
       ecs->PasswordIsDefined = passwordEnabled;
diff --git a/CPP/7zip/Compress/DllExports2Compress.cpp b/CPP/7zip/Compress/DllExports2Compress.cpp
index a6ff690..f3b862d 100644
--- a/CPP/7zip/Compress/DllExports2Compress.cpp
+++ b/CPP/7zip/Compress/DllExports2Compress.cpp
@@ -8,6 +8,15 @@
 
 #include "../Common/RegisterCodec.h"
 
+extern "C"
+BOOL WINAPI DllMain(
+  #ifdef UNDER_CE
+  HANDLE
+  #else
+  HINSTANCE
+  #endif
+  /* hInstance */, DWORD /* dwReason */, LPVOID /*lpReserved*/);
+
 extern "C"
 BOOL WINAPI DllMain(
   #ifdef UNDER_CE
@@ -22,6 +31,7 @@ BOOL WINAPI DllMain(
 
 STDAPI CreateCoder(const GUID *clsid, const GUID *iid, void **outObject);
 
+STDAPI CreateObject(const GUID *clsid, const GUID *iid, void **outObject);
 STDAPI CreateObject(const GUID *clsid, const GUID *iid, void **outObject)
 {
   return CreateCoder(clsid, iid, outObject);
diff --git a/CPP/7zip/Compress/LzmsDecoder.cpp b/CPP/7zip/Compress/LzmsDecoder.cpp
index 0f6d475..353798a 100644
--- a/CPP/7zip/Compress/LzmsDecoder.cpp
+++ b/CPP/7zip/Compress/LzmsDecoder.cpp
@@ -196,29 +196,17 @@ static void x86_Filter(Byte *data, UInt32 size, Int32 *history)
     
     const Byte b = p[0];
     
-    if (b == 0x48)
+    if ((b & 0x80) == 0) // REX (0x48 or 0x4c)
     {
-      if (p[1] == 0x8B)
+      const unsigned b2 = p[2] - 0x5; // [RIP + disp32]
+      if (b2 & 0x7)
+        continue;
+      if (p[1] != 0x8d) // LEA
       {
-        if ((p[2] & 0xF7) != 0x5)
+        if (p[1] != 0x8b || b != 0x48 || (b2 & 0xf7))
           continue;
         // MOV RAX / RCX, [RIP + disp32]
       }
-      else if (p[1] == 0x8D) // LEA
-      {
-        if ((p[2] & 0x7) != 0x5)
-          continue;
-        // LEA R**, []
-      }
-      else
-        continue;
-      codeLen = 3;
-    }
-    else if (b == 0x4C)
-    {
-      if (p[1] != 0x8D || (p[2] & 0x7) != 0x5)
-        continue;
-      // LEA R*, []
       codeLen = 3;
     }
     else if (b == 0xE8)
diff --git a/CPP/7zip/UI/Common/ArchiveCommandLine.cpp b/CPP/7zip/UI/Common/ArchiveCommandLine.cpp
index f35433b..556b25a 100644
--- a/CPP/7zip/UI/Common/ArchiveCommandLine.cpp
+++ b/CPP/7zip/UI/Common/ArchiveCommandLine.cpp
@@ -1039,6 +1039,9 @@ void CArcCmdLineParser::Parse1(const UStringVector &commandStrings,
   options.TechMode = parser[NKey::kTechMode].ThereIs;
   options.ShowTime = parser[NKey::kShowTime].ThereIs;
 
+  if (parser[NKey::kDisablePercents].ThereIs)
+    options.DisablePercents = true;
+
   if (parser[NKey::kDisablePercents].ThereIs
       || options.StdOutMode
       || !options.IsStdOutTerminal)
diff --git a/CPP/7zip/UI/Common/ArchiveCommandLine.h b/CPP/7zip/UI/Common/ArchiveCommandLine.h
index acee63c..d17ec5a 100644
--- a/CPP/7zip/UI/Common/ArchiveCommandLine.h
+++ b/CPP/7zip/UI/Common/ArchiveCommandLine.h
@@ -60,6 +60,8 @@ struct CArcCmdLineOptions
   bool StdInMode;
   bool StdOutMode;
   bool EnableHeaders;
+  bool DisablePercents;
+
 
   bool YesToAll;
   bool ShowDialog;
@@ -132,6 +134,7 @@ struct CArcCmdLineOptions
       StdOutMode(false),
 
       EnableHeaders(false),
+      DisablePercents(false),
       
       YesToAll(false),
       ShowDialog(false),
diff --git a/CPP/7zip/UI/Common/Bench.cpp b/CPP/7zip/UI/Common/Bench.cpp
index 87a2df4..e1ca846 100644
--- a/CPP/7zip/UI/Common/Bench.cpp
+++ b/CPP/7zip/UI/Common/Bench.cpp
@@ -3713,7 +3713,7 @@ HRESULT Bench(
   }
   */
   
-  bool ramSize_Defined = NSystem::GetRamSize(ramSize);
+  const bool ramSize_Defined = NSystem::GetRamSize(ramSize);
 
   UInt32 numThreadsSpecified = numCPUs;
   bool needSetComplexity = false;
@@ -4002,16 +4002,29 @@ HRESULT Bench(
     }
   }
 
-  if (numThreadsSpecified >= 2)
   if (printCallback || freqCallback)
+  for (unsigned test = 0; test < 3; test++)
   {
+    if (numThreadsSpecified < 2)
+    {
+      // if (test == 1)
+      break;
+    }
+    if (test == 2 && numThreadsSpecified <= numCPUs)
+      break;
     if (printCallback)
       printCallback->NewLine();
 
-    /* it can show incorrect frequency for HT threads.
-       so we reduce freq test to (numCPUs / 2) */
+    /* it can show incorrect frequency for HT threads. */
 
-    UInt32 numThreads = (numThreadsSpecified >= numCPUs / 2 ? numCPUs / 2 : numThreadsSpecified);
+    UInt32 numThreads = numThreadsSpecified;
+    if (test < 2)
+    {
+      if (numThreads >= numCPUs)
+        numThreads = numCPUs;
+      if (test == 0)
+        numThreads /= 2;
+    }
     if (numThreads < 1)
       numThreads = 1;
    
diff --git a/CPP/7zip/UI/Common/PropIDUtils.cpp b/CPP/7zip/UI/Common/PropIDUtils.cpp
index 0b1357f..d73680b 100644
--- a/CPP/7zip/UI/Common/PropIDUtils.cpp
+++ b/CPP/7zip/UI/Common/PropIDUtils.cpp
@@ -21,8 +21,8 @@
 
 using namespace NWindows;
 
-static const unsigned kNumWinAtrribFlags = 21;
-static const char g_WinAttribChars[kNumWinAtrribFlags + 1] = "RHS8DAdNTsLCOIEV.X.PU";
+static const unsigned kNumWinAtrribFlags = 30;
+static const char g_WinAttribChars[kNumWinAtrribFlags + 1] = "RHS8DAdNTsLCOIEVvX.PU.M......B";
 
 /*
 FILE_ATTRIBUTE_
@@ -48,8 +48,9 @@ FILE_ATTRIBUTE_
 18 RECALL_ON_OPEN or EA
 19 PINNED
 20 UNPINNED
-21 STRICTLY_SEQUENTIAL
+21 STRICTLY_SEQUENTIAL  (10.0.16267)
 22 RECALL_ON_DATA_ACCESS
+29 STRICTLY_SEQUENTIAL  (10.0.17134+) (SMR Blob)
 */
 
 
@@ -107,10 +108,10 @@ void ConvertWinAttribToString(char *s, UInt32 wa) throw()
 
   for (unsigned i = 0; i < kNumWinAtrribFlags; i++)
   {
-    UInt32 flag = (1 << i);
-    if ((wa & flag) != 0)
+    const UInt32 flag = (UInt32)1 << i;
+    if (wa & flag)
     {
-      char c = g_WinAttribChars[i];
+      const char c = g_WinAttribChars[i];
       if (c != '.')
       {
         wa &= ~flag;
diff --git a/CPP/7zip/UI/Common/Update.cpp b/CPP/7zip/UI/Common/Update.cpp
index 978630e..ed48605 100644
--- a/CPP/7zip/UI/Common/Update.cpp
+++ b/CPP/7zip/UI/Common/Update.cpp
@@ -1606,7 +1606,23 @@ HRESULT UpdateArchive(
       
       if (!MyMoveFile(tempPath, us2fs(arcPath)))
       {
-        errorInfo.SetFromLastError("cannot move the file", tempPath);
+        errorInfo.SystemError = ::GetLastError();
+        errorInfo.Message = "cannot move the file";
+        if (errorInfo.SystemError == ERROR_INVALID_PARAMETER)
+        {
+          NFind::CFileInfo fi;
+          if (fi.Find(tempPath) &&
+              fi.Size > (UInt32)(Int32)-1)
+          {
+            // bool isFsDetected = false;
+            // if (NSystem::Is_File_LimitedBy_4GB(us2fs(arcPath), isFsDetected) || !isFsDetected)
+            {
+              errorInfo.Message.Add_LF();
+              errorInfo.Message += "Archive file size exceeds 4 GB";
+            }
+          }
+        }
+        errorInfo.FileNames.Add(tempPath);
         errorInfo.FileNames.Add(us2fs(arcPath));
         return errorInfo.Get_HRESULT_Error();
       }
diff --git a/CPP/7zip/UI/Console/ExtractCallbackConsole.cpp b/CPP/7zip/UI/Console/ExtractCallbackConsole.cpp
index 66d7123..f59d4c1 100644
--- a/CPP/7zip/UI/Console/ExtractCallbackConsole.cpp
+++ b/CPP/7zip/UI/Console/ExtractCallbackConsole.cpp
@@ -343,7 +343,7 @@ Z7_COM7F_IMF(CExtractCallbackConsole::PrepareOperation(const wchar_t *name, Int3
     default: s = "???"; requiredLevel = 2;
   }
 
-  bool show2 = (LogLevel >= requiredLevel && _so);
+  const bool show2 = (LogLevel >= requiredLevel && _so);
 
   if (show2)
   {
@@ -373,6 +373,7 @@ Z7_COM7F_IMF(CExtractCallbackConsole::PrepareOperation(const wchar_t *name, Int3
  
     if (NeedFlush)
       _so->Flush();
+    // _so->Flush();  // for debug only
   }
 
   if (NeedPercents())
@@ -923,11 +924,11 @@ HRESULT CExtractCallbackConsole::ExtractResult(HRESULT result)
   }
   else
   {
-    NumArcsWithError++;
+    // we don't update NumArcsWithError, if error is not related to archive data.
     if (result == E_ABORT
-        || result == HRESULT_FROM_WIN32(ERROR_DISK_FULL)
-        )
+        || result == HRESULT_FROM_WIN32(ERROR_DISK_FULL))
       return result;
+    NumArcsWithError++; 
     
     if (_se)
     {
diff --git a/CPP/7zip/UI/Console/ExtractCallbackConsole.h b/CPP/7zip/UI/Console/ExtractCallbackConsole.h
index 8db80e7..4e45348 100644
--- a/CPP/7zip/UI/Console/ExtractCallbackConsole.h
+++ b/CPP/7zip/UI/Console/ExtractCallbackConsole.h
@@ -44,7 +44,7 @@ class CExtractScanConsole Z7_final: public IDirItemsCallback
 
   // CErrorPathCodes2 ScanErrors;
 
-  bool NeedPercents() const { return _percent._so != NULL; }
+  bool NeedPercents() const { return _percent._so && !_percent.DisablePrint; }
   
   void ClosePercentsAndFlush()
   {
@@ -56,11 +56,16 @@ class CExtractScanConsole Z7_final: public IDirItemsCallback
 
 public:
 
-  void Init(CStdOutStream *outStream, CStdOutStream *errorStream, CStdOutStream *percentStream)
+  void Init(
+      CStdOutStream *outStream,
+      CStdOutStream *errorStream,
+      CStdOutStream *percentStream,
+      bool disablePercents)
   {
     _so = outStream;
     _se = errorStream;
     _percent._so = percentStream;
+    _percent.DisablePrint = disablePercents;
   }
   
   void SetWindowWidth(unsigned width) { _percent.MaxLen = width - 1; }
@@ -177,9 +182,13 @@ public:
 
   void SetWindowWidth(unsigned width) { _percent.MaxLen = width - 1; }
 
-  void Init(CStdOutStream *outStream, CStdOutStream *errorStream, CStdOutStream *percentStream)
+  void Init(
+      CStdOutStream *outStream,
+      CStdOutStream *errorStream,
+      CStdOutStream *percentStream,
+      bool disablePercents)
   {
-    COpenCallbackConsole::Init(outStream, errorStream, percentStream);
+    COpenCallbackConsole::Init(outStream, errorStream, percentStream, disablePercents);
 
     NumTryArcs = 0;
     
diff --git a/CPP/7zip/UI/Console/List.cpp b/CPP/7zip/UI/Console/List.cpp
index 3f33dac..874caef 100644
--- a/CPP/7zip/UI/Console/List.cpp
+++ b/CPP/7zip/UI/Console/List.cpp
@@ -1155,7 +1155,7 @@ HRESULT ListArchives(
     CArchiveLink arcLink;
 
     COpenCallbackConsole openCallback;
-    openCallback.Init(&g_StdOut, g_ErrStream, NULL);
+    openCallback.Init(&g_StdOut, g_ErrStream, NULL, listOptions.DisablePercents);
 
     #ifndef Z7_NO_CRYPTO
 
diff --git a/CPP/7zip/UI/Console/List.h b/CPP/7zip/UI/Console/List.h
index 4969c3e..d87f512 100644
--- a/CPP/7zip/UI/Console/List.h
+++ b/CPP/7zip/UI/Console/List.h
@@ -11,10 +11,12 @@ struct CListOptions
 {
   bool ExcludeDirItems;
   bool ExcludeFileItems;
+  bool DisablePercents;
 
   CListOptions():
     ExcludeDirItems(false),
-    ExcludeFileItems(false)
+    ExcludeFileItems(false),
+    DisablePercents(false)
     {}
 };
 
diff --git a/CPP/7zip/UI/Console/Main.cpp b/CPP/7zip/UI/Console/Main.cpp
index 854e110..dabd696 100644
--- a/CPP/7zip/UI/Console/Main.cpp
+++ b/CPP/7zip/UI/Console/Main.cpp
@@ -1280,7 +1280,9 @@ int Main2(
     {
       CExtractScanConsole scan;
       
-      scan.Init(options.EnableHeaders ? g_StdStream : NULL, g_ErrStream, percentsStream);
+      scan.Init(options.EnableHeaders ? g_StdStream : NULL,
+          g_ErrStream, percentsStream,
+          options.DisablePercents);
       scan.SetWindowWidth(consoleWidth);
 
       if (g_StdStream && options.EnableHeaders)
@@ -1330,7 +1332,7 @@ int Main2(
       ecs->Password = options.Password;
       #endif
 
-      ecs->Init(g_StdStream, g_ErrStream, percentsStream);
+      ecs->Init(g_StdStream, g_ErrStream, percentsStream, options.DisablePercents);
       ecs->MultiArcMode = (ArchivePathsSorted.Size() > 1);
 
       ecs->LogLevel = options.LogLevel;
@@ -1494,6 +1496,7 @@ int Main2(
       CListOptions lo;
       lo.ExcludeDirItems = options.Censor.ExcludeDirItems;
       lo.ExcludeFileItems = options.Censor.ExcludeFileItems;
+      lo.DisablePercents = options.DisablePercents;
 
       hresultMain = ListArchives(
           lo,
@@ -1538,7 +1541,7 @@ int Main2(
       uo.SfxModule = kDefaultSfxModule;
 
     COpenCallbackConsole openCallback;
-    openCallback.Init(g_StdStream, g_ErrStream, percentsStream);
+    openCallback.Init(g_StdStream, g_ErrStream, percentsStream, options.DisablePercents);
 
     #ifndef Z7_NO_CRYPTO
     bool passwordIsDefined =
@@ -1563,7 +1566,7 @@ int Main2(
     callback.StdOutMode = uo.StdOutMode;
     callback.Init(
       // NULL,
-      g_StdStream, g_ErrStream, percentsStream);
+      g_StdStream, g_ErrStream, percentsStream, options.DisablePercents);
 
     CUpdateErrorInfo errorInfo;
 
@@ -1598,7 +1601,7 @@ int Main2(
     if (percentsStream)
       callback.SetWindowWidth(consoleWidth);
   
-    callback.Init(g_StdStream, g_ErrStream, percentsStream);
+    callback.Init(g_StdStream, g_ErrStream, percentsStream, options.DisablePercents);
     callback.PrintHeaders = options.EnableHeaders;
     callback.PrintFields = options.ListFields;
 
diff --git a/CPP/7zip/UI/Console/MainAr.cpp b/CPP/7zip/UI/Console/MainAr.cpp
index dca05a8..602ab64 100644
--- a/CPP/7zip/UI/Console/MainAr.cpp
+++ b/CPP/7zip/UI/Console/MainAr.cpp
@@ -63,7 +63,10 @@ static inline bool CheckIsa()
   {
     // some compilers (e2k) support SSE/AVX, but cpuid() can be unavailable or return lower isa support
 #ifdef MY_CPU_X86_OR_AMD64
-    #if defined(__AVX2__)
+    #if 0 && (defined(__AVX512F__) && defined(__AVX512VL__))
+      if (!CPU_IsSupported_AVX512F_AVX512VL())
+        return false;
+    #elif defined(__AVX2__)
       if (!CPU_IsSupported_AVX2())
         return false;
     #elif defined(__AVX__)
diff --git a/CPP/7zip/UI/Console/OpenCallbackConsole.h b/CPP/7zip/UI/Console/OpenCallbackConsole.h
index c5b4b45..5e7c19c 100644
--- a/CPP/7zip/UI/Console/OpenCallbackConsole.h
+++ b/CPP/7zip/UI/Console/OpenCallbackConsole.h
@@ -22,7 +22,7 @@ protected:
   bool _totalFilesDefined;
   // bool _totalBytesDefined;
 
-  bool NeedPercents() const { return _percent._so != NULL; }
+  bool NeedPercents() const { return _percent._so && !_percent.DisablePrint; }
 
 public:
 
@@ -49,11 +49,16 @@ public:
 
   virtual ~COpenCallbackConsole() {}
   
-  void Init(CStdOutStream *outStream, CStdOutStream *errorStream, CStdOutStream *percentStream)
+  void Init(
+      CStdOutStream *outStream,
+      CStdOutStream *errorStream,
+      CStdOutStream *percentStream,
+      bool disablePercents)
   {
     _so = outStream;
     _se = errorStream;
     _percent._so = percentStream;
+    _percent.DisablePrint = disablePercents;
   }
 
   Z7_IFACE_IMP(IOpenCallbackUI)
diff --git a/CPP/7zip/UI/Console/PercentPrinter.cpp b/CPP/7zip/UI/Console/PercentPrinter.cpp
index 1e3cfce..cfdab03 100644
--- a/CPP/7zip/UI/Console/PercentPrinter.cpp
+++ b/CPP/7zip/UI/Console/PercentPrinter.cpp
@@ -88,6 +88,8 @@ void CPercentPrinter::GetPercents()
 
 void CPercentPrinter::Print()
 {
+  if (DisablePrint)
+    return;
   DWORD tick = 0;
   if (_tickStep != 0)
     tick = GetTickCount();
diff --git a/CPP/7zip/UI/Console/PercentPrinter.h b/CPP/7zip/UI/Console/PercentPrinter.h
index 4debb3b..46988a5 100644
--- a/CPP/7zip/UI/Console/PercentPrinter.h
+++ b/CPP/7zip/UI/Console/PercentPrinter.h
@@ -43,12 +43,14 @@ class CPercentPrinter: public CPercentPrinterState
 public:
   CStdOutStream *_so;
 
+  bool DisablePrint;
   bool NeedFlush;
   unsigned MaxLen;
   
   CPercentPrinter(UInt32 tickStep = 200):
       _tickStep(tickStep),
       _prevTick(0),
+      DisablePrint(false),
       NeedFlush(true),
       MaxLen(80 - 1)
   {}
diff --git a/CPP/7zip/UI/Console/UpdateCallbackConsole.h b/CPP/7zip/UI/Console/UpdateCallbackConsole.h
index b6c1be4..276edba 100644
--- a/CPP/7zip/UI/Console/UpdateCallbackConsole.h
+++ b/CPP/7zip/UI/Console/UpdateCallbackConsole.h
@@ -64,13 +64,18 @@ public:
   
   void SetWindowWidth(unsigned width) { _percent.MaxLen = width - 1; }
 
-  void Init(CStdOutStream *outStream, CStdOutStream *errorStream, CStdOutStream *percentStream)
+  void Init(
+      CStdOutStream *outStream,
+      CStdOutStream *errorStream,
+      CStdOutStream *percentStream,
+      bool disablePercents)
   {
     FailedFiles.Clear();
 
     _so = outStream;
     _se = errorStream;
     _percent._so = percentStream;
+    _percent.DisablePrint = disablePercents;
   }
 
   void ClosePercents2()
diff --git a/CPP/7zip/UI/Explorer/ContextMenu.cpp b/CPP/7zip/UI/Explorer/ContextMenu.cpp
index d79bab1..fab3493 100644
--- a/CPP/7zip/UI/Explorer/ContextMenu.cpp
+++ b/CPP/7zip/UI/Explorer/ContextMenu.cpp
@@ -534,7 +534,8 @@ bool FindExt(const char *p, const UString &name, CStringFinder &finder);
 bool FindExt(const char *p, const UString &name, CStringFinder &finder)
 {
   const int dotPos = name.ReverseFind_Dot();
-  if (dotPos < 0 || dotPos == (int)name.Len() - 1)
+  int len = (int)name.Len() - (dotPos + 1);
+  if (len == 0 || len > 32 || dotPos < 0)
     return false;
   return finder.FindWord_In_LowCaseAsciiList_NoCase(p, name.Ptr(dotPos + 1));
 }
diff --git a/CPP/7zip/UI/FileManager/AltStreamsFolder.cpp b/CPP/7zip/UI/FileManager/AltStreamsFolder.cpp
index 446f6de..685ac70 100644
--- a/CPP/7zip/UI/FileManager/AltStreamsFolder.cpp
+++ b/CPP/7zip/UI/FileManager/AltStreamsFolder.cpp
@@ -387,8 +387,8 @@ Z7_COM7F_IMF(CAltStreamsFolder::WasChanged(Int32 *wasChanged))
       return S_OK;
     }
 
-    DWORD waitResult = ::WaitForSingleObject(_findChangeNotification, 0);
-    bool wasChangedLoc = (waitResult == WAIT_OBJECT_0);
+    const DWORD waitResult = ::WaitForSingleObject(_findChangeNotification, 0);
+    const bool wasChangedLoc = (waitResult == WAIT_OBJECT_0);
     if (wasChangedLoc)
     {
       _findChangeNotification.FindNext();
@@ -666,16 +666,10 @@ Z7_COM7F_IMF(CAltStreamsFolder::SetProperty(UInt32 /* index */, PROPID /* propID
 Z7_COM7F_IMF(CAltStreamsFolder::GetSystemIconIndex(UInt32 index, Int32 *iconIndex))
 {
   const CAltStream &ss = Streams[index];
-  *iconIndex = 0;
-  int iconIndexTemp;
-  if (GetRealIconIndex(_pathPrefix + us2fs(ss.Name),
-    0 // fi.Attrib
-    , iconIndexTemp) != 0)
-  {
-    *iconIndex = iconIndexTemp;
-    return S_OK;
-  }
-  return GetLastError_noZero_HRESULT();
+  return Shell_GetFileInfo_SysIconIndex_for_Path_return_HRESULT(
+      _pathPrefix + us2fs(ss.Name),
+      FILE_ATTRIBUTE_ARCHIVE,
+      iconIndex);
 }
 
 /*
diff --git a/CPP/7zip/UI/FileManager/App.cpp b/CPP/7zip/UI/FileManager/App.cpp
index d049fc9..06c2e8b 100644
--- a/CPP/7zip/UI/FileManager/App.cpp
+++ b/CPP/7zip/UI/FileManager/App.cpp
@@ -782,6 +782,7 @@ void CApp::OnCopy(bool move, bool copyToSame, unsigned srcPanelIndex)
   if (useSrcPanel)
   {
     CCopyToOptions options;
+    // options.src_Is_IO_FS_Folder = useFullItemPaths;
     options.folder = useTemp ? fs2us(tempDirPrefix) : destPath;
     options.moveMode = move;
     options.includeAltStreams = true;
diff --git a/CPP/7zip/UI/FileManager/BrowseDialog.cpp b/CPP/7zip/UI/FileManager/BrowseDialog.cpp
index 6464ed8..b12d8e8 100644
--- a/CPP/7zip/UI/FileManager/BrowseDialog.cpp
+++ b/CPP/7zip/UI/FileManager/BrowseDialog.cpp
@@ -208,8 +208,8 @@ bool CBrowseDialog::OnInit()
       _filterCombo.SetCurSel(FilterIndex);
   }
 
-  _list.SetImageList(GetSysImageList(true), LVSIL_SMALL);
-  _list.SetImageList(GetSysImageList(false), LVSIL_NORMAL);
+  _list.SetImageList(Shell_Get_SysImageList_smallIcons(true), LVSIL_SMALL);
+  _list.SetImageList(Shell_Get_SysImageList_smallIcons(false), LVSIL_NORMAL);
 
   _list.InsertColumn(0, LangString(IDS_PROP_NAME), 100);
   _list.InsertColumn(1, LangString(IDS_PROP_MTIME), 100);
@@ -690,19 +690,21 @@ HRESULT CBrowseDialog::Reload(const UString &pathPrefix, const UString &selected
     #ifndef UNDER_CE
     if (isDrive)
     {
-      if (GetRealIconIndex(fi.Name + FCHAR_PATH_SEPARATOR, FILE_ATTRIBUTE_DIRECTORY, item.iImage) == 0)
-        item.iImage = 0;
+      item.iImage = Shell_GetFileInfo_SysIconIndex_for_Path(
+          fi.Name + FCHAR_PATH_SEPARATOR,
+          FILE_ATTRIBUTE_DIRECTORY);
     }
     else
     #endif
       item.iImage = _extToIconMap.GetIconIndex(fi.Attrib, fullPath);
     if (item.iImage < 0)
-      item.iImage = 0;
+        item.iImage = 0;
     _list.InsertItem(&item);
     wchar_t s[64];
     {
       s[0] = 0;
-      ConvertUtcFileTimeToString(fi.MTime, s,
+      if (!FILETIME_IsZero(fi.MTime))
+        ConvertUtcFileTimeToString(fi.MTime, s,
             #ifndef UNDER_CE
               kTimestampPrintLevel_MIN
             #else
diff --git a/CPP/7zip/UI/FileManager/BrowseDialog2.cpp b/CPP/7zip/UI/FileManager/BrowseDialog2.cpp
index 59f7527..ee98ab4 100644
--- a/CPP/7zip/UI/FileManager/BrowseDialog2.cpp
+++ b/CPP/7zip/UI/FileManager/BrowseDialog2.cpp
@@ -356,8 +356,8 @@ bool CBrowseDialog2::OnInit()
 #endif
   }
 
-  _list.SetImageList(GetSysImageList(true), LVSIL_SMALL);
-  _list.SetImageList(GetSysImageList(false), LVSIL_NORMAL);
+  _list.SetImageList(Shell_Get_SysImageList_smallIcons(true), LVSIL_SMALL);
+  _list.SetImageList(Shell_Get_SysImageList_smallIcons(false), LVSIL_NORMAL);
 
   unsigned columnIndex = 0;
   _list.InsertColumn(columnIndex++, LangString(IDS_PROP_NAME), 100);
@@ -939,7 +939,8 @@ void CBrowseDialog2::OnDelete(/* bool toRecycleBin */)
       s.Add_LF();
       s += s2;
     }
-    if (::MessageBoxW((HWND)*this, s, LangString(titleID), MB_OKCANCEL | MB_ICONQUESTION) != IDOK)
+    if (::MessageBoxW((HWND)*this, s, LangString(titleID),
+        MB_YESNOCANCEL | MB_ICONQUESTION) != IDYES)
       return;
   }
 
@@ -1638,15 +1639,15 @@ HRESULT CBrowseDialog2::Reload(const UString &pathPrefix, const UStringVector &s
     #ifndef UNDER_CE
     if (isDrive)
     {
-      if (GetRealIconIndex(fi.Name + FCHAR_PATH_SEPARATOR, FILE_ATTRIBUTE_DIRECTORY, item.iImage) == 0)
-        item.iImage = 0;
+      item.iImage = Shell_GetFileInfo_SysIconIndex_for_Path(
+          fi.Name + FCHAR_PATH_SEPARATOR,
+          FILE_ATTRIBUTE_DIRECTORY);
     }
     else
     #endif
       item.iImage = _extToIconMap.GetIconIndex(fi.Attrib, fullPath);
     if (item.iImage < 0)
-      item.iImage = 0;
-
+        item.iImage = 0;
     _list.InsertItem(&item);
     wchar_t s[64];
     {
@@ -1661,7 +1662,6 @@ HRESULT CBrowseDialog2::Reload(const UString &pathPrefix, const UStringVector &s
               );
       _list.SetSubItem(index, subItem++, s);
     }
-
     {
       s[0] = 0;
       Browse_ConvertSizeToString(bi, s);
diff --git a/CPP/7zip/UI/FileManager/ExtractCallback.cpp b/CPP/7zip/UI/FileManager/ExtractCallback.cpp
index 093534b..6ec6065 100644
--- a/CPP/7zip/UI/FileManager/ExtractCallback.cpp
+++ b/CPP/7zip/UI/FileManager/ExtractCallback.cpp
@@ -206,13 +206,15 @@ Z7_COM7F_IMF(CExtractCallbackImp::AskOverwrite(
 {
   COverwriteDialog dialog;
 
-  dialog.OldFileInfo.SetTime(existTime);
-  dialog.OldFileInfo.SetSize(existSize);
-  dialog.OldFileInfo.Name = existName;
-
-  dialog.NewFileInfo.SetTime(newTime);
-  dialog.NewFileInfo.SetSize(newSize);
-  dialog.NewFileInfo.Name = newName;
+  dialog.OldFileInfo.SetTime2(existTime);
+  dialog.OldFileInfo.SetSize2(existSize);
+  dialog.OldFileInfo.Path = existName;
+  dialog.OldFileInfo.Is_FileSystemFile = true;
+
+  dialog.NewFileInfo.SetTime2(newTime);
+  dialog.NewFileInfo.SetSize2(newSize);
+  dialog.NewFileInfo.Path = newName;
+  dialog.NewFileInfo.Is_FileSystemFile = Src_Is_IO_FS_Folder;
   
   ProgressDialog->WaitCreating();
   INT_PTR writeAnswer = dialog.Create(*ProgressDialog);
diff --git a/CPP/7zip/UI/FileManager/ExtractCallback.h b/CPP/7zip/UI/FileManager/ExtractCallback.h
index daef5ec..5c459aa 100644
--- a/CPP/7zip/UI/FileManager/ExtractCallback.h
+++ b/CPP/7zip/UI/FileManager/ExtractCallback.h
@@ -224,6 +224,8 @@ public:
   bool ProcessAltStreams;
   bool StreamMode;
   bool ThereAreMessageErrors;
+  bool Src_Is_IO_FS_Folder;
+
 #ifndef Z7_NO_CRYPTO
   bool PasswordIsDefined;
   bool PasswordWasAsked;
@@ -286,6 +288,8 @@ public:
     , MultiArcMode(false)
     , ProcessAltStreams(true)
     , StreamMode(false)
+    , ThereAreMessageErrors(false)
+    , Src_Is_IO_FS_Folder(false)
 #ifndef Z7_NO_CRYPTO
     , PasswordIsDefined(false)
     , PasswordWasAsked(false)
diff --git a/CPP/7zip/UI/FileManager/FSDrives.cpp b/CPP/7zip/UI/FileManager/FSDrives.cpp
index 19d0814..70354c7 100644
--- a/CPP/7zip/UI/FileManager/FSDrives.cpp
+++ b/CPP/7zip/UI/FileManager/FSDrives.cpp
@@ -45,7 +45,8 @@ struct CPhysTempBuffer
   ~CPhysTempBuffer() { MidFree(buffer); }
 };
 
-static HRESULT CopyFileSpec(CFSTR fromPath, CFSTR toPath, bool writeToDisk, UInt64 fileSize,
+static HRESULT CopyFileSpec(CFSTR fromPath, CFSTR toPath,
+    bool writeToDisk, UInt64 fileSize,
     UInt32 bufferSize, UInt64 progressStart, IProgress *progress)
 {
   NIO::CInFile inFile;
@@ -74,9 +75,11 @@ static HRESULT CopyFileSpec(CFSTR fromPath, CFSTR toPath, bool writeToDisk, UInt
  
   for (UInt64 pos = 0; pos < fileSize;)
   {
-    UInt64 progressCur = progressStart + pos;
-    RINOK(progress->SetCompleted(&progressCur))
-    UInt64 rem = fileSize - pos;
+    {
+      const UInt64 progressCur = progressStart + pos;
+      RINOK(progress->SetCompleted(&progressCur))
+    }
+    const UInt64 rem = fileSize - pos;
     UInt32 curSize = (UInt32)MyMin(rem, (UInt64)bufferSize);
     UInt32 processedSize;
     if (!inFile.Read(tempBuffer.buffer, curSize, processedSize))
@@ -91,7 +94,6 @@ static HRESULT CopyFileSpec(CFSTR fromPath, CFSTR toPath, bool writeToDisk, UInt
       if (curSize > bufferSize)
         return E_FAIL;
     }
-
     if (!outFile.Write(tempBuffer.buffer, curSize, processedSize))
       return GetLastError_noZero_HRESULT();
     if (curSize != processedSize)
@@ -135,9 +137,7 @@ Z7_COM7F_IMF(CFSDrives::LoadItems())
   FOR_VECTOR (i, driveStrings)
   {
     CDriveInfo di;
-
     const FString &driveName = driveStrings[i];
-
     di.FullSystemName = driveName;
     if (!driveName.IsEmpty())
       di.Name.SetFrom(driveName, driveName.Len() - 1);
@@ -183,25 +183,24 @@ Z7_COM7F_IMF(CFSDrives::LoadItems())
     {
       FString name ("PhysicalDrive");
       name.Add_UInt32(n);
-      
       FString fullPath (kVolPrefix);
       fullPath += name;
-
       CFileInfo fi;
       if (!fi.Find(fullPath))
         continue;
 
       CDriveInfo di;
       di.Name = name;
-      di.FullSystemName = fullPath;
+      // if (_volumeMode == true) we use CDriveInfo::FullSystemName only in GetSystemIconIndex().
+      // And we need name without "\\\\.\\" prefix in GetSystemIconIndex().
+      // So we don't set di.FullSystemName = fullPath;
+      di.FullSystemName = name;
       di.ClusterSize = 0;
       di.DriveSize = fi.Size;
       di.FreeSpace = 0;
       di.DriveType = 0;
-
       di.IsPhysicalDrive = true;
       di.KnownSize = true;
-      
       _drives.Add(di);
     }
   }
@@ -217,7 +216,7 @@ Z7_COM7F_IMF(CFSDrives::GetNumberOfItems(UInt32 *numItems))
 
 Z7_COM7F_IMF(CFSDrives::GetProperty(UInt32 itemIndex, PROPID propID, PROPVARIANT *value))
 {
-  if (itemIndex >= (UInt32)_drives.Size())
+  if (itemIndex >= _drives.Size())
     return E_INVALIDARG;
   NCOM::CPropVariant prop;
   const CDriveInfo &di = _drives[itemIndex];
@@ -268,7 +267,7 @@ HRESULT CFSDrives::BindToFolderSpec(CFSTR name, IFolderFolder **resultFolder)
 Z7_COM7F_IMF(CFSDrives::BindToFolder(UInt32 index, IFolderFolder **resultFolder))
 {
   *resultFolder = NULL;
-  if (index >= (UInt32)_drives.Size())
+  if (index >= _drives.Size())
     return E_INVALIDARG;
   const CDriveInfo &di = _drives[index];
   /*
@@ -322,17 +321,14 @@ Z7_COM7F_IMF(CFSDrives::GetFolderProperty(PROPID propID, PROPVARIANT *value))
 
 Z7_COM7F_IMF(CFSDrives::GetSystemIconIndex(UInt32 index, Int32 *iconIndex))
 {
-  *iconIndex = 0;
+  *iconIndex = -1;
   const CDriveInfo &di = _drives[index];
-  if (di.IsPhysicalDrive)
-    return S_OK;
-  int iconIndexTemp;
-  if (GetRealIconIndex(di.FullSystemName, 0, iconIndexTemp) != 0)
-  {
-    *iconIndex = iconIndexTemp;
-    return S_OK;
-  }
-  return GetLastError_noZero_HRESULT();
+  return Shell_GetFileInfo_SysIconIndex_for_Path_return_HRESULT(
+      di.FullSystemName,
+      _volumeMode ?
+          FILE_ATTRIBUTE_ARCHIVE:
+          FILE_ATTRIBUTE_DIRECTORY,
+      iconIndex);
 }
 
 void CFSDrives::AddExt(FString &s, unsigned index) const
@@ -393,10 +389,8 @@ Z7_COM7F_IMF(CFSDrives::CopyTo(Int32 moveMode, const UInt32 *indices, UInt32 num
 {
   if (numItems == 0)
     return S_OK;
-  
   if (moveMode)
     return E_NOTIMPL;
-
   if (!_volumeMode)
     return E_NOTIMPL;
 
@@ -411,12 +405,12 @@ Z7_COM7F_IMF(CFSDrives::CopyTo(Int32 moveMode, const UInt32 *indices, UInt32 num
   RINOK(callback->SetTotal(totalSize))
   RINOK(callback->SetNumFiles(numItems))
   
-  FString destPath = us2fs(path);
+  const FString destPath = us2fs(path);
   if (destPath.IsEmpty())
     return E_INVALIDARG;
 
-  bool isAltDest = NName::IsAltPathPrefix(destPath);
-  bool isDirectPath = (!isAltDest && !IsPathSepar(destPath.Back()));
+  const bool isAltDest = NName::IsAltPathPrefix(destPath);
+  const bool isDirectPath = (!isAltDest && !IsPathSepar(destPath.Back()));
   
   if (isDirectPath)
   {
@@ -428,7 +422,7 @@ Z7_COM7F_IMF(CFSDrives::CopyTo(Int32 moveMode, const UInt32 *indices, UInt32 num
   RINOK(callback->SetCompleted(&completedSize))
   for (i = 0; i < numItems; i++)
   {
-    unsigned index = indices[i];
+    const unsigned index = indices[i];
     const CDriveInfo &di = _drives[index];
     FString destPath2 = destPath;
 
@@ -443,7 +437,7 @@ Z7_COM7F_IMF(CFSDrives::CopyTo(Int32 moveMode, const UInt32 *indices, UInt32 num
       destPath2 += destName;
     }
     
-    FString srcPath = di.GetDeviceFileIoName();
+    const FString srcPath = di.GetDeviceFileIoName();
 
     UInt64 fileSize = 0;
     if (GetFileSize(index, fileSize) != S_OK)
diff --git a/CPP/7zip/UI/FileManager/FSFolder.cpp b/CPP/7zip/UI/FileManager/FSFolder.cpp
index 26a2ccf..7956d86 100644
--- a/CPP/7zip/UI/FileManager/FSFolder.cpp
+++ b/CPP/7zip/UI/FileManager/FSFolder.cpp
@@ -535,7 +535,7 @@ Z7_COM7F_IMF(CFSFolder::GetProperty(UInt32 index, PROPID propID, PROPVARIANT *va
 {
   NCOM::CPropVariant prop;
   /*
-  if (index >= (UInt32)Files.Size())
+  if (index >= Files.Size())
   {
     CAltStream &ss = Streams[index - Files.Size()];
     CDirItem &fi = Files[ss.Parent];
@@ -561,7 +561,7 @@ Z7_COM7F_IMF(CFSFolder::GetProperty(UInt32 index, PROPID propID, PROPVARIANT *va
       case kpidComment: break;
       default: index = ss.Parent;
     }
-    if (index >= (UInt32)Files.Size())
+    if (index >= Files.Size())
     {
       prop.Detach(value);
       return S_OK;
@@ -716,8 +716,8 @@ Z7_COM7F_IMF2(Int32, CFSFolder::CompareItems(UInt32 index1, UInt32 index2, PROPI
   /*
   const CAltStream *ss1 = NULL;
   const CAltStream *ss2 = NULL;
-  if (index1 >= (UInt32)Files.Size()) { ss1 = &Streams[index1 - Files.Size()]; index1 = ss1->Parent; }
-  if (index2 >= (UInt32)Files.Size()) { ss2 = &Streams[index2 - Files.Size()]; index2 = ss2->Parent; }
+  if (index1 >= Files.Size()) { ss1 = &Streams[index1 - Files.Size()]; index1 = ss1->Parent; }
+  if (index2 >= Files.Size()) { ss2 = &Streams[index2 - Files.Size()]; index2 = ss2->Parent; }
   */
   CDirItem &fi1 = Files[index1];
   CDirItem &fi2 = Files[index2];
@@ -1034,7 +1034,7 @@ Z7_COM7F_IMF(CFSFolder::GetItemFullSize(UInt32 index, PROPVARIANT *value, IProgr
 
 Z7_COM7F_IMF(CFSFolder::CalcItemFullSize(UInt32 index, IProgress *progress))
 {
-  if (index >= (UInt32)Files.Size())
+  if (index >= Files.Size())
     return S_OK;
   CDirItem &fi = Files[index];
   if (!fi.IsDir())
@@ -1080,7 +1080,7 @@ Z7_COM7F_IMF(CFSFolder::CreateFile(const wchar_t *name, IProgress * /* progress
 
 Z7_COM7F_IMF(CFSFolder::Rename(UInt32 index, const wchar_t *newName, IProgress * /* progress */))
 {
-  if (index >= (UInt32)Files.Size())
+  if (index >= Files.Size())
     return E_NOTIMPL;
   const CDirItem &fi = Files[index];
   // FString prefix;
@@ -1103,9 +1103,9 @@ Z7_COM7F_IMF(CFSFolder::Delete(const UInt32 *indices, UInt32 numItems,IProgress
     UInt32 index = indices[i];
     bool result = true;
     /*
-    if (index >= (UInt32)Files.Size())
+    if (index >= Files.Size())
     {
-      const CAltStream &ss = Streams[index - (UInt32)Files.Size()];
+      const CAltStream &ss = Streams[index - Files.Size()];
       if (prevDeletedFileIndex != ss.Parent)
       {
         const CDirItem &fi = Files[ss.Parent];
@@ -1134,7 +1134,7 @@ Z7_COM7F_IMF(CFSFolder::Delete(const UInt32 *indices, UInt32 numItems,IProgress
 Z7_COM7F_IMF(CFSFolder::SetProperty(UInt32 index, PROPID propID,
     const PROPVARIANT *value, IProgress * /* progress */))
 {
-  if (index >= (UInt32)Files.Size())
+  if (index >= Files.Size())
     return E_INVALIDARG;
   CDirItem &fi = Files[index];
   if (fi.Parent >= 0)
@@ -1172,17 +1172,12 @@ Z7_COM7F_IMF(CFSFolder::SetProperty(UInt32 index, PROPID propID,
 
 Z7_COM7F_IMF(CFSFolder::GetSystemIconIndex(UInt32 index, Int32 *iconIndex))
 {
-  if (index >= (UInt32)Files.Size())
+  *iconIndex = -1;
+  if (index >= Files.Size())
     return E_INVALIDARG;
   const CDirItem &fi = Files[index];
-  *iconIndex = 0;
-  int iconIndexTemp;
-  if (GetRealIconIndex(_path + GetRelPath(fi), fi.Attrib, iconIndexTemp) != 0)
-  {
-    *iconIndex = iconIndexTemp;
-    return S_OK;
-  }
-  return GetLastError_noZero_HRESULT();
+  return Shell_GetFileInfo_SysIconIndex_for_Path_return_HRESULT(
+      _path + GetRelPath(fi), fi.Attrib, iconIndex);
 }
 
 Z7_COM7F_IMF(CFSFolder::SetFlatMode(Int32 flatMode))
diff --git a/CPP/7zip/UI/FileManager/FSFolder.h b/CPP/7zip/UI/FileManager/FSFolder.h
index fe8538a..e2edf5f 100644
--- a/CPP/7zip/UI/FileManager/FSFolder.h
+++ b/CPP/7zip/UI/FileManager/FSFolder.h
@@ -22,11 +22,11 @@ class CFSFolder;
 
 struct CDirItem: public NWindows::NFile::NFind::CFileInfo
 {
-  #ifndef UNDER_CE
+#ifndef UNDER_CE
   UInt64 PackSize;
-  #endif
+#endif
 
-  #ifdef FS_SHOW_LINKS_INFO
+#ifdef FS_SHOW_LINKS_INFO
   FILETIME ChangeTime;
   UInt64 FileIndex;
   UInt32 NumLinks;
@@ -34,22 +34,21 @@ struct CDirItem: public NWindows::NFile::NFind::CFileInfo
   bool FileInfo_WasRequested;
   bool ChangeTime_Defined;
   bool ChangeTime_WasRequested;
-  #endif
+#endif
 
-  #ifndef UNDER_CE
+#ifndef UNDER_CE
   bool PackSize_Defined;
-  #endif
+#endif
 
   bool FolderStat_Defined;
+  int Parent;
 
-  #ifndef UNDER_CE
+#ifndef UNDER_CE
   CByteBuffer Reparse;
-  #endif
+#endif
   
   UInt64 NumFolders;
   UInt64 NumFiles;
-  
-  int Parent;
 };
 
 /*
@@ -126,20 +125,18 @@ class CFSFolder Z7_final:
   Z7_IFACE_COM7_IMP(IFolderSetFlatMode)
   // Z7_IFACE_COM7_IMP(IFolderSetShowNtfsStreamsMode)
 
-private:
+  bool _flatMode;
+  bool _commentsAreLoaded;
+  // bool _scanAltStreams;
+
   FString _path;
-  
   CObjectVector<CDirItem> Files;
   FStringVector Folders;
   // CObjectVector<CAltStream> Streams;
   // CMyComPtr<IFolderFolder> _parentFolder;
 
-  bool _commentsAreLoaded;
   CPairsStorage _comments;
 
-  // bool _scanAltStreams;
-  bool _flatMode;
-
   #ifdef _WIN32
   NWindows::NFile::NFind::CFindChangeNotification _findChangeNotification;
   #endif
@@ -163,9 +160,11 @@ public:
   HRESULT InitToRoot() { return Init((FString) FSTRING_PATH_SEPARATOR /* , NULL */); }
   #endif
 
-  CFSFolder() : _flatMode(false)
+  CFSFolder():
+    _flatMode(false),
+    _commentsAreLoaded(false)
     // , _scanAltStreams(false)
-  {}
+    {}
 
   void GetFullPath(const CDirItem &item, FString &path) const
   {
diff --git a/CPP/7zip/UI/FileManager/FSFolderCopy.cpp b/CPP/7zip/UI/FileManager/FSFolderCopy.cpp
index 67499fc..3582be0 100644
--- a/CPP/7zip/UI/FileManager/FSFolderCopy.cpp
+++ b/CPP/7zip/UI/FileManager/FSFolderCopy.cpp
@@ -515,8 +515,22 @@ static HRESULT CopyFile_Ask(
       RINOK(state.ProgressInfo.ProgressResult)
       if (!res)
       {
+        const DWORD errorCode = GetLastError();
+        UString errorMessage = NError::MyFormatMessage(Return_LastError_or_FAIL());
+        if (errorCode == ERROR_INVALID_PARAMETER)
+        {
+          NFind::CFileInfo fi;
+          if (fi.Find(srcPath) &&
+              fi.Size > (UInt32)(Int32)-1)
+          {
+            // bool isFsDetected = false;
+            // if (NSystem::Is_File_LimitedBy_4GB(destPathNew, isFsDetected) || !isFsDetected)
+              errorMessage += " File size exceeds 4 GB";
+          }
+        }
+
         // GetLastError() is ERROR_REQUEST_ABORTED in case of PROGRESS_CANCEL.
-        RINOK(SendMessageError(state.Callback, GetLastErrorMessage(), destPathNew))
+        RINOK(SendMessageError(state.Callback, errorMessage, destPathNew))
         return E_ABORT;
       }
       state.ProgressInfo.StartPos += state.ProgressInfo.FileSize;
diff --git a/CPP/7zip/UI/FileManager/NetFolder.cpp b/CPP/7zip/UI/FileManager/NetFolder.cpp
index 879f1db..e91e67f 100644
--- a/CPP/7zip/UI/FileManager/NetFolder.cpp
+++ b/CPP/7zip/UI/FileManager/NetFolder.cpp
@@ -254,28 +254,23 @@ Z7_COM7F_IMF(CNetFolder::GetFolderProperty(PROPID propID, PROPVARIANT *value))
 
 Z7_COM7F_IMF(CNetFolder::GetSystemIconIndex(UInt32 index, Int32 *iconIndex))
 {
-  if (index >= (UInt32)_items.Size())
+  *iconIndex = -1;
+  if (index >= _items.Size())
     return E_INVALIDARG;
-  *iconIndex = 0;
   const CResourceW &resource = _items[index];
-  int iconIndexTemp;
   if (resource.DisplayType == RESOURCEDISPLAYTYPE_SERVER ||
       resource.Usage == RESOURCEUSAGE_CONNECTABLE)
   {
-    if (GetRealIconIndex(us2fs(resource.RemoteName), 0, iconIndexTemp))
-    {
-      *iconIndex = iconIndexTemp;
-      return S_OK;
-    }
+    return Shell_GetFileInfo_SysIconIndex_for_Path_return_HRESULT(
+        us2fs(resource.RemoteName), FILE_ATTRIBUTE_DIRECTORY, iconIndex);
   }
   else
   {
-    if (GetRealIconIndex(FTEXT(""), FILE_ATTRIBUTE_DIRECTORY, iconIndexTemp))
-    {
-      *iconIndex = iconIndexTemp;
-      return S_OK;
-    }
-    // *anIconIndex = GetRealIconIndex(0, L"\\\\HOME");
+#if 0
+    return S_FALSE;
+#else
+    return Shell_GetFileInfo_SysIconIndex_for_Path_return_HRESULT(
+        FTEXT("__DIR__"), FILE_ATTRIBUTE_DIRECTORY, iconIndex);
+#endif
   }
-  return GetLastError_noZero_HRESULT();
 }
diff --git a/CPP/7zip/UI/FileManager/OverwriteDialog.cpp b/CPP/7zip/UI/FileManager/OverwriteDialog.cpp
index f63277a..b15c702 100644
--- a/CPP/7zip/UI/FileManager/OverwriteDialog.cpp
+++ b/CPP/7zip/UI/FileManager/OverwriteDialog.cpp
@@ -2,8 +2,10 @@
 
 #include "StdAfx.h"
 
+#include "../../../Common/IntToString.h"
 #include "../../../Common/StringConvert.h"
 
+#include "../../../Windows/FileFind.h"
 #include "../../../Windows/PropVariantConv.h"
 #include "../../../Windows/ResourceString.h"
 
@@ -29,12 +31,16 @@ static const UInt32 kLangIDs[] =
 };
 #endif
 
-static const unsigned kCurrentFileNameSizeLimit = 82;
-static const unsigned kCurrentFileNameSizeLimit2 = 30;
+static const unsigned kCurrentFileNameSizeLimit = 72;
 
 void COverwriteDialog::ReduceString(UString &s)
 {
-  unsigned size = _isBig ? kCurrentFileNameSizeLimit : kCurrentFileNameSizeLimit2;
+  const unsigned size =
+#ifdef UNDER_CE
+      !_isBig ? 30 : // kCurrentFileNameSizeLimit2
+#endif
+      kCurrentFileNameSizeLimit;
+
   if (s.Len() > size)
   {
     s.Delete(size / 2, s.Len() - size);
@@ -42,66 +48,201 @@ void COverwriteDialog::ReduceString(UString &s)
   }
   if (!s.IsEmpty() && s.Back() == ' ')
   {
-    // s += (wchar_t)(0x2423);
+    // s += (wchar_t)(0x2423); // visible space
     s.InsertAtFront(L'\"');
-    s += L'\"';
+    s.Add_Char('\"');
   }
 }
 
-void COverwriteDialog::SetFileInfoControl(unsigned textID, unsigned iconID,
-    const NOverwriteDialog::CFileInfo &fileInfo)
+
+void COverwriteDialog::SetItemIcon(unsigned iconID, HICON hIcon)
+{
+  NControl::CStatic staticContol;
+  staticContol.Attach(GetItem(iconID));
+  hIcon = staticContol.SetIcon(hIcon);
+  if (hIcon)
+    DestroyIcon(hIcon);
+}
+
+void AddSizeValue(UString &s, UInt64 value);
+void AddSizeValue(UString &s, UInt64 value)
 {
-  UString sizeString;
-  if (fileInfo.SizeIsDefined)
-    sizeString = MyFormatNew(IDS_FILE_SIZE, NumberToString(fileInfo.Size));
-
-  const UString &fileName = fileInfo.Name;
-  int slashPos = fileName.ReverseFind_PathSepar();
-  UString s1 = fileName.Left((unsigned)(slashPos + 1));
-  UString s2 = fileName.Ptr((unsigned)(slashPos + 1));
-
-  ReduceString(s1);
-  ReduceString(s2);
-  
-  UString s = s1;
-  s.Add_LF();
-  s += s2;
-  s.Add_LF();
-  s += sizeString;
-  s.Add_LF();
-
-  if (fileInfo.TimeIsDefined)
   {
-    AddLangString(s, IDS_PROP_MTIME);
-    s += ": ";
-    char t[64];
-    ConvertUtcFileTimeToString(fileInfo.Time, t);
-    s += t;
+    wchar_t sz[32];
+    ConvertUInt64ToString(value, sz);
+    s += MyFormatNew(IDS_FILE_SIZE, sz);
   }
+  if (value >= (1 << 10))
+  {
+    char c;
+          if (value >= ((UInt64)10 << 30)) { value >>= 30; c = 'G'; }
+    else  if (value >=         (10 << 20)) { value >>= 20; c = 'M'; }
+    else                                   { value >>= 10; c = 'K'; }
+    s += " : ";
+    s.Add_UInt64(value);
+    s.Add_Space();
+    s.Add_Char(c);
+    s += "iB";
+  }
+}
 
-  NControl::CDialogChildControl control;
-  control.Init(*this, textID);
-  control.SetText(s);
 
-  SHFILEINFO shellFileInfo;
-  if (::SHGetFileInfo(
-      GetSystemString(fileInfo.Name), FILE_ATTRIBUTE_NORMAL, &shellFileInfo,
-      sizeof(shellFileInfo), SHGFI_ICON | SHGFI_USEFILEATTRIBUTES | SHGFI_LARGEICON))
+void COverwriteDialog::SetFileInfoControl(
+    const NOverwriteDialog::CFileInfo &fileInfo,
+    unsigned textID,
+    unsigned iconID,
+    unsigned iconID_2)
+{
+  {
+    const UString &path = fileInfo.Path;
+    const int slashPos = path.ReverseFind_PathSepar();
+    UString s = path.Left((unsigned)(slashPos + 1));
+    ReduceString(s);
+    s.Add_LF();
+    {
+      UString s2 = path.Ptr((unsigned)(slashPos + 1));
+      ReduceString(s2);
+      s += s2;
+    }
+    s.Add_LF();
+    if (fileInfo.Size_IsDefined)
+      AddSizeValue(s, fileInfo.Size);
+    s.Add_LF();
+    if (fileInfo.Time_IsDefined)
+    {
+      AddLangString(s, IDS_PROP_MTIME);
+      s += ": ";
+      char t[64];
+      ConvertUtcFileTimeToString(fileInfo.Time, t);
+      s += t;
+    }
+    SetItemText(textID, s);
+  }
+/*
+  SHGetFileInfo():
+    DOCs: If uFlags does not contain SHGFI_EXETYPE or SHGFI_SYSICONINDEX,
+          the return value is nonzero if successful, or zero otherwise.
+    We don't use SHGFI_EXETYPE or SHGFI_SYSICONINDEX here.
+  win10: we call with SHGFI_ICON flag set.
+    it returns 0: if error : (shFileInfo::*) members are not set.
+    it returns non_0, if successful, and retrieve:
+      { shFileInfo.hIcon != NULL : the handle to icon (must be destroyed by our code)
+        shFileInfo.iIcon is index of the icon image within the system image list.
+      }
+  Note:
+    If we send path to ".exe" file,
+    SHGFI_USEFILEATTRIBUTES flag is ignored, and it tries to open file.
+    and return icon from that exe file.
+    So we still need to reduce path, if want to get raw icon of exe file.
+    
+  if (name.Len() >= MAX_PATH))
+  {
+    it can return:
+      return 0.
+      return 1 and:
+        { shFileInfo.hIcon != NULL : is some default icon for file
+          shFileInfo.iIcon == 0
+        }
+    return results (0 or 1) can depend from:
+      - unicode/non-unicode
+      - (SHGFI_USEFILEATTRIBUTES) flag
+      - exact file extension (.exe).
+  }
+*/
+  int iconIndex = -1;
+  for (unsigned i = 0; i < 2; i++)
   {
-    NControl::CStatic staticContol;
-    staticContol.Attach(GetItem(iconID));
-    staticContol.SetIcon(shellFileInfo.hIcon);
+    CSysString name = GetSystemString(fileInfo.Path);
+    if (i != 0)
+    {
+      if (!fileInfo.Is_FileSystemFile)
+        break;
+      if (name.Len() < 4 ||
+          (!StringsAreEqualNoCase_Ascii(name.RightPtr(4), ".exe") &&
+           !StringsAreEqualNoCase_Ascii(name.RightPtr(4), ".ico")))
+        break;
+      // if path for ".exe" file is long, it returns default icon (shFileInfo.iIcon == 0).
+      // We don't want to show that default icon.
+      // But we will check for default icon later instead of MAX_PATH check here.
+      // if (name.Len() >= MAX_PATH) break; // optional
+    }
+    else
+    {
+      // we need only file extension with dot
+      const int separ = name.ReverseFind_PathSepar();
+      name.DeleteFrontal((unsigned)(separ + 1));
+      // if (name.Len() >= MAX_PATH)
+      {
+        const int dot = name.ReverseFind_Dot();
+        if (dot >= 0)
+          name.DeleteFrontal((unsigned)dot);
+        // else name.Empty(); to set default name below
+      }
+      // name.Empty(); // for debug
+    }
+
+    if (name.IsEmpty())
+    {
+      // If we send empty name, SHGetFileInfo() returns some strange icon.
+      // So we use common dummy name without extension,
+      // and SHGetFileInfo() will return default icon (iIcon == 0)
+      name = "__file__";
+    }
+
+    DWORD attrib = FILE_ATTRIBUTE_ARCHIVE;
+    if (fileInfo.Is_FileSystemFile)
+    {
+      NFile::NFind::CFileInfo fi;
+      if (fi.Find(us2fs(fileInfo.Path)) && !fi.IsAltStream && !fi.IsDir())
+        attrib = fi.Attrib;
+    }
+
+    SHFILEINFO shFileInfo;
+    // ZeroMemory(&shFileInfo, sizeof(shFileInfo)); // optional
+    shFileInfo.hIcon = NULL; // optional
+    shFileInfo.iIcon = -1;   // optional
+    // memset(&shFileInfo, 1, sizeof(shFileInfo)); // for debug
+    const DWORD_PTR res = ::SHGetFileInfo(name, attrib,
+        &shFileInfo, sizeof(shFileInfo),
+        SHGFI_ICON | SHGFI_LARGEICON | SHGFI_SHELLICONSIZE |
+        // (i == 0 ? SHGFI_USEFILEATTRIBUTES : 0)
+        SHGFI_USEFILEATTRIBUTES
+        // we use SHGFI_USEFILEATTRIBUTES for second icon, because
+        // it still returns real icon from exe files
+        );
+    if (res && shFileInfo.hIcon)
+    {
+      // we don't show second icon, if icon index (iIcon) is same
+      // as first icon index of first shown icon (exe file without icon)
+      if (   shFileInfo.iIcon >= 0
+          && shFileInfo.iIcon != iconIndex
+          && (shFileInfo.iIcon != 0 || i == 0)) // we don't want default icon for second icon
+      {
+        iconIndex = shFileInfo.iIcon;
+        SetItemIcon(i == 0 ? iconID : iconID_2, shFileInfo.hIcon);
+      }
+      else
+        DestroyIcon(shFileInfo.hIcon);
+    }
   }
 }
 
+
+
 bool COverwriteDialog::OnInit()
 {
   #ifdef Z7_LANG
   LangSetWindowText(*this, IDD_OVERWRITE);
   LangSetDlgItems(*this, kLangIDs, Z7_ARRAY_SIZE(kLangIDs));
   #endif
-  SetFileInfoControl(IDT_OVERWRITE_OLD_FILE_SIZE_TIME, IDI_OVERWRITE_OLD_FILE, OldFileInfo);
-  SetFileInfoControl(IDT_OVERWRITE_NEW_FILE_SIZE_TIME, IDI_OVERWRITE_NEW_FILE, NewFileInfo);
+  SetFileInfoControl(OldFileInfo,
+      IDT_OVERWRITE_OLD_FILE_SIZE_TIME,
+      IDI_OVERWRITE_OLD_FILE,
+      IDI_OVERWRITE_OLD_FILE_2);
+  SetFileInfoControl(NewFileInfo,
+      IDT_OVERWRITE_NEW_FILE_SIZE_TIME,
+      IDI_OVERWRITE_NEW_FILE,
+      IDI_OVERWRITE_NEW_FILE_2);
   NormalizePosition();
 
   if (!ShowExtraButtons)
@@ -122,6 +263,15 @@ bool COverwriteDialog::OnInit()
   return CModalDialog::OnInit();
 }
 
+bool COverwriteDialog::OnDestroy()
+{
+  SetItemIcon(IDI_OVERWRITE_OLD_FILE, NULL);
+  SetItemIcon(IDI_OVERWRITE_OLD_FILE_2, NULL);
+  SetItemIcon(IDI_OVERWRITE_NEW_FILE, NULL);
+  SetItemIcon(IDI_OVERWRITE_NEW_FILE_2, NULL);
+  return false; // we return (false) to perform default dialog operation
+}
+
 bool COverwriteDialog::OnButtonClicked(unsigned buttonID, HWND buttonHWND)
 {
   switch (buttonID)
diff --git a/CPP/7zip/UI/FileManager/OverwriteDialog.h b/CPP/7zip/UI/FileManager/OverwriteDialog.h
index a9ca991..9f0801d 100644
--- a/CPP/7zip/UI/FileManager/OverwriteDialog.h
+++ b/CPP/7zip/UI/FileManager/OverwriteDialog.h
@@ -12,68 +12,78 @@ namespace NOverwriteDialog
 {
   struct CFileInfo
   {
-    bool SizeIsDefined;
-    bool TimeIsDefined;
+    bool Size_IsDefined;
+    bool Time_IsDefined;
+    bool Is_FileSystemFile;
     UInt64 Size;
     FILETIME Time;
-    UString Name;
+    UString Path;
+
+    void SetTime(const FILETIME &t)
+    {
+      Time = t;
+      Time_IsDefined = true;
+    }
     
-    void SetTime(const FILETIME *t)
+    void SetTime2(const FILETIME *t)
     {
       if (!t)
-        TimeIsDefined = false;
+        Time_IsDefined = false;
       else
-      {
-        TimeIsDefined = true;
-        Time = *t;
-      }
+        SetTime(*t);
     }
 
     void SetSize(UInt64 size)
     {
-      SizeIsDefined = true;
       Size = size;
+      Size_IsDefined = true;
     }
 
-    void SetSize(const UInt64 *size)
+    void SetSize2(const UInt64 *size)
     {
       if (!size)
-        SizeIsDefined = false;
+        Size_IsDefined = false;
       else
         SetSize(*size);
     }
+
+    CFileInfo():
+      Size_IsDefined(false),
+      Time_IsDefined(false),
+      Is_FileSystemFile(false)
+      {}
   };
 }
 
 class COverwriteDialog: public NWindows::NControl::CModalDialog
 {
+#ifdef UNDER_CE
   bool _isBig;
+#endif
 
-  void SetFileInfoControl(unsigned textID, unsigned iconID, const NOverwriteDialog::CFileInfo &fileInfo);
+  void SetItemIcon(unsigned iconID, HICON hIcon);
+  void SetFileInfoControl(const NOverwriteDialog::CFileInfo &fileInfo, unsigned textID, unsigned iconID, unsigned iconID_2);
   virtual bool OnInit() Z7_override;
+  virtual bool OnDestroy() Z7_override;
   virtual bool OnButtonClicked(unsigned buttonID, HWND buttonHWND) Z7_override;
   void ReduceString(UString &s);
 
 public:
   bool ShowExtraButtons;
   bool DefaultButton_is_NO;
-
+  NOverwriteDialog::CFileInfo OldFileInfo;
+  NOverwriteDialog::CFileInfo NewFileInfo;
 
   COverwriteDialog(): ShowExtraButtons(true), DefaultButton_is_NO(false) {}
 
   INT_PTR Create(HWND parent = NULL)
   {
+#ifdef UNDER_CE
     BIG_DIALOG_SIZE(280, 200);
-    #ifdef UNDER_CE
     _isBig = isBig;
-    #else
-    _isBig = true;
-    #endif
+#endif
     return CModalDialog::Create(SIZED_DIALOG(IDD_OVERWRITE), parent);
   }
-
-  NOverwriteDialog::CFileInfo OldFileInfo;
-  NOverwriteDialog::CFileInfo NewFileInfo;
 };
 
 #endif
diff --git a/CPP/7zip/UI/FileManager/OverwriteDialog.rc b/CPP/7zip/UI/FileManager/OverwriteDialog.rc
index 29f9912..112d5d8 100644
--- a/CPP/7zip/UI/FileManager/OverwriteDialog.rc
+++ b/CPP/7zip/UI/FileManager/OverwriteDialog.rc
@@ -1,7 +1,7 @@
 #include "OverwriteDialogRes.h"
 #include "../../GuiCommon.rc"
 
-#define xc 280
+#define xc 340
 #define yc 200
 
 #undef iconSize
@@ -25,11 +25,13 @@ BEGIN
   LTEXT  "Would you like to replace the existing file", IDT_OVERWRITE_QUESTION_BEGIN, m, 28, xc, 8
   
   ICON   "", IDI_OVERWRITE_OLD_FILE,             m,  44, iconSize, iconSize
+  ICON   "", IDI_OVERWRITE_OLD_FILE_2,           m,  44 + iconSize, iconSize, iconSize
   LTEXT  "", IDT_OVERWRITE_OLD_FILE_SIZE_TIME,   x,  44, fx, fy, SS_NOPREFIX
   
   LTEXT  "with this one?", IDT_OVERWRITE_QUESTION_END, m,  98, xc, 8
 
   ICON   "", IDI_OVERWRITE_NEW_FILE,             m, 114, iconSize, iconSize
+  ICON   "", IDI_OVERWRITE_NEW_FILE_2,           m, 114 + iconSize, iconSize, iconSize
   LTEXT  "", IDT_OVERWRITE_NEW_FILE_SIZE_TIME,   x, 114, fx, fy, SS_NOPREFIX
   
   PUSHBUTTON  "&Yes",         IDYES,             bx3, by2, bxs, bys
diff --git a/CPP/7zip/UI/FileManager/OverwriteDialogRes.h b/CPP/7zip/UI/FileManager/OverwriteDialogRes.h
index b480ba1..24beb33 100644
--- a/CPP/7zip/UI/FileManager/OverwriteDialogRes.h
+++ b/CPP/7zip/UI/FileManager/OverwriteDialogRes.h
@@ -11,7 +11,9 @@
 #define IDB_NO_TO_ALL                  441
 
 #define IDI_OVERWRITE_OLD_FILE             100
-#define IDI_OVERWRITE_NEW_FILE             101
-
+#define IDI_OVERWRITE_OLD_FILE_2           101
 #define IDT_OVERWRITE_OLD_FILE_SIZE_TIME   102
-#define IDT_OVERWRITE_NEW_FILE_SIZE_TIME   103
+
+#define IDI_OVERWRITE_NEW_FILE             110
+#define IDI_OVERWRITE_NEW_FILE_2           111
+#define IDT_OVERWRITE_NEW_FILE_SIZE_TIME   112
diff --git a/CPP/7zip/UI/FileManager/Panel.cpp b/CPP/7zip/UI/FileManager/Panel.cpp
index cdb5ba4..f3fb38e 100644
--- a/CPP/7zip/UI/FileManager/Panel.cpp
+++ b/CPP/7zip/UI/FileManager/Panel.cpp
@@ -420,8 +420,8 @@ bool CPanel::OnCreate(CREATESTRUCT * /* createStruct */)
   _listView._panel = this;
   _listView.SetWindowProc();
 
-  _listView.SetImageList(GetSysImageList(true), LVSIL_SMALL);
-  _listView.SetImageList(GetSysImageList(false), LVSIL_NORMAL);
+  _listView.SetImageList(Shell_Get_SysImageList_smallIcons(true), LVSIL_SMALL);
+  _listView.SetImageList(Shell_Get_SysImageList_smallIcons(false), LVSIL_NORMAL);
 
   // _exStyle |= LVS_EX_HEADERDRAGDROP;
   // DWORD extendedStyle = _listView.GetExtendedListViewStyle();
@@ -506,17 +506,15 @@ bool CPanel::OnCreate(CREATESTRUCT * /* createStruct */)
       #endif
       , NULL,
     WS_BORDER | WS_VISIBLE |WS_CHILD | CBS_DROPDOWN | CBS_AUTOHSCROLL,
-      0, 0, 100, 520,
+      0, 0, 100, 620,
       (_headerReBar ? _headerToolBar : (HWND)*this),
       (HMENU)(UINT_PTR)(_comboBoxID),
       g_hInstance, NULL);
-  #ifndef UNDER_CE
-  _headerComboBox.SetUnicodeFormat(true);
-
-  _headerComboBox.SetImageList(GetSysImageList(true));
 
+#ifndef UNDER_CE
+  _headerComboBox.SetUnicodeFormat(true);
+  _headerComboBox.SetImageList(Shell_Get_SysImageList_smallIcons(true));
   _headerComboBox.SetExtendedStyle(CBES_EX_PATHWORDBREAKPROC, CBES_EX_PATHWORDBREAKPROC);
-
   /*
   _headerComboBox.SetUserDataLongPtr(LONG_PTR(&_headerComboBox));
   _headerComboBox._panel = this;
@@ -525,9 +523,7 @@ bool CPanel::OnCreate(CREATESTRUCT * /* createStruct */)
       LONG_PTR(ComboBoxSubclassProc));
   */
   _comboBoxEdit.Attach(_headerComboBox.GetEditControl());
-
   // _comboBoxEdit.SendMessage(CCM_SETUNICODEFORMAT, (WPARAM)(BOOL)TRUE, 0);
-
   _comboBoxEdit.SetUserDataLongPtr(LONG_PTR(&_comboBoxEdit));
   _comboBoxEdit._panel = this;
    #ifndef _UNICODE
@@ -538,8 +534,7 @@ bool CPanel::OnCreate(CREATESTRUCT * /* createStruct */)
    #endif
      _comboBoxEdit._origWindowProc =
       (WNDPROC)_comboBoxEdit.SetLongPtr(GWLP_WNDPROC, LONG_PTR(ComboBoxEditSubclassProc));
-
-  #endif
+#endif
 
   if (_headerReBar)
   {
diff --git a/CPP/7zip/UI/FileManager/Panel.h b/CPP/7zip/UI/FileManager/Panel.h
index 5cbc35d..1b708f7 100644
--- a/CPP/7zip/UI/FileManager/Panel.h
+++ b/CPP/7zip/UI/FileManager/Panel.h
@@ -147,11 +147,11 @@ public:
 struct CTempFileInfo
 {
   UInt32 FileIndex;  // index of file in folder
+  bool NeedDelete;
   UString RelPath;   // Relative path of file from Folder
   FString FolderPath;
   FString FilePath;
   NWindows::NFile::NFind::CFileInfo FileInfo;
-  bool NeedDelete;
 
   CTempFileInfo(): FileIndex((UInt32)(Int32)-1), NeedDelete(false) {}
   void DeleteDirAndFile() const
@@ -171,15 +171,15 @@ struct CTempFileInfo
 
 struct CFolderLink: public CTempFileInfo
 {
+  bool IsVirtual;
+  bool UsePassword;
   NWindows::NDLL::CLibrary Library;
   CMyComPtr<IFolderFolder> ParentFolder; // can be NULL, if parent is FS folder (in _parentFolders[0])
   UString ParentFolderPath; // including tail slash (doesn't include paths parts of parent in next level)
-  bool UsePassword;
   UString Password;
-  bool IsVirtual;
 
   UString VirtualPath; // without tail slash
-  CFolderLink(): UsePassword(false), IsVirtual(false) {}
+  CFolderLink(): IsVirtual(false), UsePassword(false) {}
 
   bool WasChanged(const NWindows::NFile::NFind::CFileInfo &newFileInfo) const
   {
@@ -310,7 +310,7 @@ struct COpenResult
 
 class CPanel Z7_final: public NWindows::NControl::CWindow2
 {
-  CExtToIconMap _extToIconMap;
+  // CExtToIconMap _extToIconMap;
   UINT _baseID;
   unsigned _comboBoxID;
   UINT _statusBarID;
@@ -324,7 +324,7 @@ class CPanel Z7_final: public NWindows::NControl::CWindow2
   virtual void OnDestroy() Z7_override;
   virtual bool OnNotify(UINT controlID, LPNMHDR lParam, LRESULT &result) Z7_override;
 
-  void AddComboBoxItem(const UString &name, int iconIndex, int indent, bool addToList);
+  void AddComboBoxItem(const UString &name, int iconIndex, unsigned indent, bool addToList);
 
   bool OnComboBoxCommand(UINT code, LPARAM param, LRESULT &result);
   
@@ -355,7 +355,7 @@ public:
   HWND _mainWindow;
   CPanelCallback *_panelCallback;
 
-  void SysIconsWereChanged() { _extToIconMap.Clear(); }
+  // void SysIconsWereChanged() { _extToIconMap.Clear(); }
 
   void DeleteItems(bool toRecycleBin);
   void CreateFolder();
diff --git a/CPP/7zip/UI/FileManager/PanelCopy.cpp b/CPP/7zip/UI/FileManager/PanelCopy.cpp
index 40a347f..36a0f6d 100644
--- a/CPP/7zip/UI/FileManager/PanelCopy.cpp
+++ b/CPP/7zip/UI/FileManager/PanelCopy.cpp
@@ -189,7 +189,9 @@ HRESULT CPanel::CopyTo(CCopyToOptions &options,
 
   extracter.ExtractCallbackSpec = new CExtractCallbackImp;
   extracter.ExtractCallback = extracter.ExtractCallbackSpec;
-
+  extracter.ExtractCallbackSpec->Src_Is_IO_FS_Folder =
+      IsFSFolder() || IsAltStreamsFolder();
+      // options.src_Is_IO_FS_Folder;
   extracter.options = &options;
   extracter.ExtractCallbackSpec->ProgressDialog = &extracter;
   extracter.CompressingMode = false;
diff --git a/CPP/7zip/UI/FileManager/PanelFolderChange.cpp b/CPP/7zip/UI/FileManager/PanelFolderChange.cpp
index 406e304..c34cb74 100644
--- a/CPP/7zip/UI/FileManager/PanelFolderChange.cpp
+++ b/CPP/7zip/UI/FileManager/PanelFolderChange.cpp
@@ -368,14 +368,41 @@ void CPanel::LoadFullPath()
     _currentFolderPrefix += GetFolderPath(_folder);
 }
 
-static int GetRealIconIndex(CFSTR path, DWORD attributes)
+
+
+static int GetRealIconIndex_for_DirPath(CFSTR path, DWORD attrib)
 {
+  attrib |= FILE_ATTRIBUTE_DIRECTORY; // optional
   int index = -1;
-  if (GetRealIconIndex(path, attributes, index) != 0)
-    return index;
-  return -1;
+  if (Shell_GetFileInfo_SysIconIndex_for_Path_attrib_iconIndexRef(path, attrib, index))
+    if (index >= 0)
+      return index;
+  return g_Ext_to_Icon_Map.GetIconIndex_DIR(attrib);
+}
+
+
+extern UString RootFolder_GetName_Computer(int &iconIndex);
+extern UString RootFolder_GetName_Network(int &iconIndex);
+extern UString RootFolder_GetName_Documents(int &iconIndex);
+
+
+static int Find_FileExtension_DotPos_in_path(const wchar_t *path)
+{
+  int dotPos = -1;
+  unsigned i;
+  for (i = 0;; i++)
+  {
+    const wchar_t c = path[i];
+    if (c == 0)
+      return dotPos;
+    if (c == '.')
+      dotPos = (int)i;
+    else if (IS_PATH_SEPAR(c) || c == ':')
+      dotPos = -1;
+  }
 }
 
+
 void CPanel::LoadFullPathAndShow()
 {
   LoadFullPath();
@@ -387,30 +414,97 @@ void CPanel::LoadFullPathAndShow()
 
   COMBOBOXEXITEM item;
   item.mask = 0;
+  item.iImage = -1;
 
   UString path = _currentFolderPrefix;
-  if (path.Len() >
-      #ifdef _WIN32
-      3
-      #else
-      1
-      #endif
-      && IS_PATH_SEPAR(path.Back()))
-    path.DeleteBack();
-
-  DWORD attrib = FILE_ATTRIBUTE_DIRECTORY;
-
-  // GetRealIconIndex is slow for direct DVD/UDF path. So we use dummy path
-  if (path.IsPrefixedBy(L"\\\\.\\"))
-    path = "_TestFolder_";
-  else
+  // path = "\\\\.\\PhysicalDrive1\\"; // for debug
+  // path = "\\\\.\\y:\\"; // for debug
+  if (!path.IsEmpty())
   {
-    CFileInfo fi;
-    if (fi.Find(us2fs(path)))
-      attrib = fi.Attrib;
+    const unsigned rootPrefixSize = NName::GetRootPrefixSize(path);
+    if (rootPrefixSize == 0 && path[0] != '\\')
+    {
+      int iconIndex = -1;
+      UString name_Computer = RootFolder_GetName_Computer(iconIndex);
+      name_Computer.Add_PathSepar();
+      if (path == name_Computer
+          || path == L"\\\\?\\")
+        item.iImage = iconIndex;
+      else
+      {
+        UString name = RootFolder_GetName_Network(iconIndex);
+        name.Add_PathSepar();
+        if (path == name)
+          item.iImage = iconIndex;
+      }
+    }
+
+    if (item.iImage < 0)
+    {
+      if (rootPrefixSize == 0 || rootPrefixSize == path.Len())
+      {
+        DWORD attrib = FILE_ATTRIBUTE_DIRECTORY;
+        CFileInfo info;
+        if (info.Find(us2fs(path)))
+          attrib = info.Attrib;
+        NName::If_IsSuperPath_RemoveSuperPrefix(path);
+        item.iImage = GetRealIconIndex_for_DirPath(us2fs(path), attrib);
+      }
+      else if (rootPrefixSize == NName::kDevicePathPrefixSize
+          && NName::IsDevicePath(us2fs(path.Left(path.Len() - 1))))
+      {
+        if (path.IsPrefixedBy_Ascii_NoCase("\\\\.\\"))
+          path.DeleteFrontal(4);
+        if (path.Len() > 3) // is not "c:\\"
+        {
+          // PhysicalDrive
+          if (path.Back() == '\\')
+            path.DeleteBack();
+        }
+        item.iImage = Shell_GetFileInfo_SysIconIndex_for_Path(us2fs(path), FILE_ATTRIBUTE_ARCHIVE);
+      }
+      else
+      {
+        if (path.Back() == '\\')
+          path.DeleteBack();
+        bool need_Fs_Check = true;
+        bool is_File = false;
+        if (!_parentFolders.IsEmpty())
+        {
+          const CFolderLink &link = _parentFolders.Back();
+          if (link.VirtualPath == path)
+          {
+            is_File = true;
+            if (_parentFolders.Size() != 1)
+              need_Fs_Check = false;
+          }
+          else
+            need_Fs_Check = false;
+        }
+        if (need_Fs_Check)
+        {
+          CFileInfo info;
+          const bool finded = info.Find(us2fs(path));
+          DWORD attrib = FILE_ATTRIBUTE_DIRECTORY;
+          if (finded)
+            attrib = info.Attrib;
+          item.iImage = Shell_GetFileInfo_SysIconIndex_for_Path(us2fs(path), attrib);
+        }
+        if (item.iImage <= 0 && is_File)
+        {
+          int dotPos = Find_FileExtension_DotPos_in_path(path);
+          if (dotPos < 0)
+            dotPos = (int)path.Len();
+          item.iImage = g_Ext_to_Icon_Map.GetIconIndex(FILE_ATTRIBUTE_ARCHIVE, path.Ptr(dotPos));
+        }
+      }
+    }
   }
-  item.iImage = GetRealIconIndex(us2fs(path), attrib);
 
+  if (item.iImage < 0)
+    item.iImage = g_Ext_to_Icon_Map.GetIconIndex_DIR();
+  // if (item.iImage < 0) item.iImage = 0;
+  // item.iImage = -1; // for debug
   if (item.iImage >= 0)
   {
     item.iSelectedImage = item.iImage;
@@ -495,13 +589,13 @@ bool CPanel::OnNotifyComboBoxEndEdit(PNMCBEENDEDIT info, LRESULT &result)
 }
 #endif
 
-void CPanel::AddComboBoxItem(const UString &name, int iconIndex, int indent, bool addToList)
+void CPanel::AddComboBoxItem(const UString &name, int iconIndex, unsigned indent, bool addToList)
 {
   #ifdef UNDER_CE
 
   UString s;
   iconIndex = iconIndex;
-  for (int i = 0; i < indent; i++)
+  for (unsigned i = 0; i < indent; i++)
     s += "  ";
   _headerComboBox.AddString(s + name);
   
@@ -509,23 +603,26 @@ void CPanel::AddComboBoxItem(const UString &name, int iconIndex, int indent, boo
   
   COMBOBOXEXITEMW item;
   item.mask = CBEIF_TEXT | CBEIF_INDENT;
+  if (iconIndex < 0)
+    iconIndex = g_Ext_to_Icon_Map.GetIconIndex_DIR();
   item.iSelectedImage = item.iImage = iconIndex;
   if (iconIndex >= 0)
     item.mask |= (CBEIF_IMAGE | CBEIF_SELECTEDIMAGE);
   item.iItem = -1;
-  item.iIndent = indent;
+  item.iIndent = (int)indent;
   item.pszText = name.Ptr_non_const();
   _headerComboBox.InsertItem(&item);
   
   #endif
 
   if (addToList)
-    ComboBoxPaths.Add(name);
+  {
+    UString s = name;
+    s.Add_PathSepar();
+    ComboBoxPaths.Add(s);
+  }
 }
 
-extern UString RootFolder_GetName_Computer(int &iconIndex);
-extern UString RootFolder_GetName_Network(int &iconIndex);
-extern UString RootFolder_GetName_Documents(int &iconIndex);
 
 bool CPanel::OnComboBoxCommand(UINT code, LPARAM /* param */, LRESULT &result)
 {
@@ -537,56 +634,168 @@ bool CPanel::OnComboBoxCommand(UINT code, LPARAM /* param */, LRESULT &result)
       ComboBoxPaths.Clear();
       _headerComboBox.ResetContent();
       
-      unsigned i;
+      UString sumPath;
       UStringVector pathParts;
-      
-      SplitPathToParts(_currentFolderPrefix, pathParts);
-      UString sumPass;
-      if (!pathParts.IsEmpty())
-        pathParts.DeleteBack();
-      for (i = 0; i < pathParts.Size(); i++)
+      unsigned indent = 0;
       {
-        const UString name = pathParts[i];
-        sumPass += name;
-        sumPass.Add_PathSepar();
-        CFileInfo info;
-        DWORD attrib = FILE_ATTRIBUTE_DIRECTORY;
-        if (info.Find(us2fs(sumPass)))
-          attrib = info.Attrib;
-        AddComboBoxItem(
-            name.IsEmpty() ? L"\\" : name,
-            GetRealIconIndex(us2fs(sumPass), attrib),
-            (int)i, // iIndent
-            false); // addToList
-        ComboBoxPaths.Add(sumPass);
+        UString path = _currentFolderPrefix;
+        // path = L"\\\\.\\y:\\"; // for debug
+        UString prefix0;
+        if (path.IsPrefixedBy_Ascii_NoCase("\\\\"))
+        {
+          const int separ = FindCharPosInString(path.Ptr(2), '\\');
+          if (separ > 0
+            && (separ > 1 || path[2] != '.')) // "\\\\.\\" will be processed later
+          {
+            const UString s = path.Left(2 + separ);
+            prefix0 = s;
+            prefix0.Add_PathSepar();
+            AddComboBoxItem(s,
+                GetRealIconIndex_for_DirPath(us2fs(prefix0), FILE_ATTRIBUTE_DIRECTORY),
+                indent++,
+                false); // addToList
+            ComboBoxPaths.Add(prefix0);
+          }
+        }
+        
+        unsigned rootPrefixSize = NName::GetRootPrefixSize(path);
+
+        sumPath = path;
+        
+        if (rootPrefixSize <= prefix0.Len())
+        {
+          rootPrefixSize = prefix0.Len();
+          sumPath.DeleteFrom(rootPrefixSize);
+        }
+        else
+        {
+          // rootPrefixSize > prefix0.Len()
+          sumPath.DeleteFrom(rootPrefixSize);
+          
+          CFileInfo info;
+          DWORD attrib = FILE_ATTRIBUTE_DIRECTORY;
+          if (info.Find(us2fs(sumPath)) && info.IsDir())
+            attrib = info.Attrib;
+          UString s = sumPath.Ptr(prefix0.Len());
+          if (!s.IsEmpty())
+          {
+            const wchar_t c = s.Back();
+            if (IS_PATH_SEPAR(c))
+              s.DeleteBack();
+          }
+          UString path_for_icon = sumPath;
+          NName::If_IsSuperPath_RemoveSuperPrefix(path_for_icon);
+          
+          AddComboBoxItem(s,
+              GetRealIconIndex_for_DirPath(us2fs(path_for_icon), attrib),
+              indent++,
+              false); // addToList
+          ComboBoxPaths.Add(sumPath);
+        }
+          
+        path.DeleteFrontal(rootPrefixSize);
+        SplitPathToParts(path, pathParts);
       }
 
-      #ifndef UNDER_CE
+      // it's expected that pathParts.Back() is empty, because _currentFolderPrefix has PathSeparator.
+      unsigned next_Arc_index = 0;
+      int iconIndex_Computer;
+      const UString name_Computer = RootFolder_GetName_Computer(iconIndex_Computer);
 
-      int iconIndex;
-      UString name;
-      name = RootFolder_GetName_Documents(iconIndex);
-      AddComboBoxItem(name, iconIndex, 0, true);
+      // const bool is_devicePrefix = (sumPath == L"\\\\.\\");
 
-      name = RootFolder_GetName_Computer(iconIndex);
-      AddComboBoxItem(name, iconIndex, 0, true);
-        
-      FStringVector driveStrings;
-      MyGetLogicalDriveStrings(driveStrings);
-      for (i = 0; i < driveStrings.Size(); i++)
+      if (pathParts.Size() > 1)
+      if (!sumPath.IsEmpty()
+          || pathParts.Size() != 2
+          || pathParts[0] != name_Computer)
+      for (unsigned i = 0; i + 1 < pathParts.Size(); i++)
       {
-        FString s = driveStrings[i];
-        ComboBoxPaths.Add(fs2us(s));
-        int iconIndex2 = GetRealIconIndex(s, 0);
-        if (s.Len() > 0 && s.Back() == FCHAR_PATH_SEPARATOR)
-          s.DeleteBack();
-        AddComboBoxItem(fs2us(s), iconIndex2, 1, false);
+        UString name = pathParts[i];
+        sumPath += name;
+
+        bool isRootDir_inLink = false;
+        if (next_Arc_index < _parentFolders.Size())
+        {
+          const CFolderLink &link = _parentFolders[next_Arc_index];
+          if (link.VirtualPath == sumPath)
+          {
+            isRootDir_inLink = true;
+            next_Arc_index++;
+          }
+        }
+        
+        int iconIndex = -1;
+        DWORD attrib = isRootDir_inLink ?
+            FILE_ATTRIBUTE_ARCHIVE:
+            FILE_ATTRIBUTE_DIRECTORY;
+        if (next_Arc_index == 0
+            || (next_Arc_index == 1 && isRootDir_inLink))
+        {
+          if (i == 0 && NName::IsDevicePath(us2fs(sumPath)))
+          {
+            UString path = name;
+            path.Add_PathSepar();
+            attrib = FILE_ATTRIBUTE_ARCHIVE;
+              // FILE_ATTRIBUTE_DIRECTORY;
+          }
+          else
+          {
+            CFileInfo info;
+            if (info.Find(us2fs(sumPath)))
+              attrib = info.Attrib;
+          }
+          iconIndex = Shell_GetFileInfo_SysIconIndex_for_Path(us2fs(sumPath), attrib);
+        }
+        
+        if (iconIndex < 0)
+          iconIndex = g_Ext_to_Icon_Map.GetIconIndex(attrib, name);
+        // iconIndex = -1; // for debug
+        if (iconIndex < 0 && isRootDir_inLink)
+          iconIndex = 0; // default file
+
+        sumPath.Add_PathSepar();
+
+        ComboBoxPaths.Add(sumPath);
+        if (name.IsEmpty())
+          name.Add_PathSepar();
+        AddComboBoxItem(name, iconIndex, indent++,
+            false); // addToList
       }
 
-      name = RootFolder_GetName_Network(iconIndex);
-      AddComboBoxItem(name, iconIndex, 0, true);
+#ifndef UNDER_CE
 
-      #endif
+      {
+        int iconIndex;
+        const UString name = RootFolder_GetName_Documents(iconIndex);
+        // iconIndex = -1; // for debug
+        AddComboBoxItem(name, iconIndex, 0, true);
+      }
+      AddComboBoxItem(name_Computer, iconIndex_Computer, 0, true);
+      {
+        FStringVector driveStrings;
+        MyGetLogicalDriveStrings(driveStrings);
+        FOR_VECTOR (i, driveStrings)
+        {
+          FString s = driveStrings[i];
+          ComboBoxPaths.Add(fs2us(s));
+          int iconIndex2 = GetRealIconIndex_for_DirPath(s, FILE_ATTRIBUTE_DIRECTORY);
+          if (!s.IsEmpty())
+          {
+            const FChar c = s.Back();
+            if (IS_PATH_SEPAR(c))
+              s.DeleteBack();
+          }
+          // iconIndex2 = -1; // for debug
+          AddComboBoxItem(fs2us(s), iconIndex2, 1, false);
+        }
+      }
+      {
+        int iconIndex;
+        const UString name = RootFolder_GetName_Network(iconIndex);
+        AddComboBoxItem(name, iconIndex, 0, true);
+      }
+
+#endif
     
       return false;
     }
@@ -596,10 +805,10 @@ bool CPanel::OnComboBoxCommand(UINT code, LPARAM /* param */, LRESULT &result)
       int index = _headerComboBox.GetCurSel();
       if (index >= 0)
       {
-        UString pass = ComboBoxPaths[index];
+        const UString path = ComboBoxPaths[index];
         _headerComboBox.SetCurSel(-1);
-        // _headerComboBox.SetText(pass); // it's fix for seclecting by mouse.
-        if (BindToPathAndRefresh(pass) == S_OK)
+        // _headerComboBox.SetText(pass); // it's fix for selecting by mouse.
+        if (BindToPathAndRefresh(path) == S_OK)
         {
           PostMsg(kSetFocusToListView);
           #ifdef UNDER_CE
diff --git a/CPP/7zip/UI/FileManager/PanelItemOpen.cpp b/CPP/7zip/UI/FileManager/PanelItemOpen.cpp
index f4ee3f3..244a962 100644
--- a/CPP/7zip/UI/FileManager/PanelItemOpen.cpp
+++ b/CPP/7zip/UI/FileManager/PanelItemOpen.cpp
@@ -609,7 +609,7 @@ HRESULT CPanel::OpenParentArchiveFolder()
     if (folderLink.WasChanged(newFileInfo))
     {
       UString message = MyFormatNew(IDS_WANT_UPDATE_MODIFIED_FILE, folderLink.RelPath);
-      if (::MessageBoxW((HWND)*this, message, L"7-Zip", MB_OKCANCEL | MB_ICONQUESTION) == IDOK)
+      if (::MessageBoxW((HWND)*this, message, L"7-Zip", MB_YESNOCANCEL | MB_ICONQUESTION) == IDYES)
       {
         if (OnOpenItemChanged(folderLink.FileIndex, fs2us(folderLink.FilePath),
             folderLinkPrev.UsePassword, folderLinkPrev.Password) != S_OK)
@@ -1249,7 +1249,7 @@ static THREAD_FUNC_DECL MyThreadFunction(void *param)
         }
         {
           const UString message = MyFormatNew(IDS_WANT_UPDATE_MODIFIED_FILE, tpi->RelPath);
-          if (::MessageBoxW(g_HWND, message, L"7-Zip", MB_OKCANCEL | MB_ICONQUESTION) == IDOK)
+          if (::MessageBoxW(g_HWND, message, L"7-Zip", MB_YESNOCANCEL | MB_ICONQUESTION) == IDYES)
           {
             // DEBUG_PRINT_NUM("SendMessage", GetCurrentThreadId());
             if (SendMessage(tpi->Window, kOpenItemChanged, 0, (LONG_PTR)tpi.get()) != 1)
diff --git a/CPP/7zip/UI/FileManager/PanelItems.cpp b/CPP/7zip/UI/FileManager/PanelItems.cpp
index 2335fc0..544e9bf 100644
--- a/CPP/7zip/UI/FileManager/PanelItems.cpp
+++ b/CPP/7zip/UI/FileManager/PanelItems.cpp
@@ -583,8 +583,13 @@ HRESULT CPanel::RefreshListCtrl(const CSelectedState &state)
   int cursorIndex = -1;
 
   CMyComPtr<IFolderGetSystemIconIndex> folderGetSystemIconIndex;
+#if 1 // 0 : for debug local icons loading
   if (!Is_Slow_Icon_Folder() || _showRealFileIcons)
     _folder.QueryInterface(IID_IFolderGetSystemIconIndex, &folderGetSystemIconIndex);
+#endif
+
+  const bool isFSDrivesFolder = IsFSDrivesFolder();
+  const bool isArcFolder = IsArcFolder();
 
   if (!IsFSFolder())
   {
@@ -631,10 +636,11 @@ HRESULT CPanel::RefreshListCtrl(const CSelectedState &state)
     #else
     item.pszText = LPSTR_TEXTCALLBACKW;
     #endif
-    const UInt32 attrib = FILE_ATTRIBUTE_DIRECTORY;
-    item.iImage = _extToIconMap.GetIconIndex(attrib, itemName);
+    // const UInt32 attrib = FILE_ATTRIBUTE_DIRECTORY;
+    item.iImage = g_Ext_to_Icon_Map.GetIconIndex_DIR();
+        // g_Ext_to_Icon_Map.GetIconIndex(attrib, itemName);
     if (item.iImage < 0)
-      item.iImage = 0;
+        item.iImage = 0;
     if (_listView.InsertItem(&item) == -1)
       return E_FAIL;
     listViewItemCount++;
@@ -755,11 +761,52 @@ HRESULT CPanel::RefreshListCtrl(const CSelectedState &state)
     }
 
     bool defined = false;
+    item.iImage = -1;
   
     if (folderGetSystemIconIndex)
     {
-      folderGetSystemIconIndex->GetSystemIconIndex(i, &item.iImage);
-      defined = (item.iImage > 0);
+      const HRESULT res = folderGetSystemIconIndex->GetSystemIconIndex(i, &item.iImage);
+      if (res == S_OK)
+      {
+        // item.iImage = -1; // for debug
+        defined = (item.iImage > 0);
+#if 0 // 0: can be slower: 2 attempts for some paths.
+      // 1: faster, but we can get default icon for some cases (where non default icon is possible)
+
+        if (item.iImage == 0)
+        {
+          // (item.iImage == 0) means default icon.
+          // But (item.iImage == 0) also can be returned for exe/ico files,
+          // if filePath is LONG PATH (path_len() >= MAX_PATH).
+          // Also we want to show split icon (.001) for any split extension: 001 002 003.
+          // Are there another cases for (item.iImage == 0) for files with known extensions?
+          // We don't want to do second attempt to request icon,
+          // if it also will return (item.iImage == 0).
+
+          int dotPos = -1;
+          for (unsigned k = 0;; k++)
+          {
+            const wchar_t c = name[k];
+            if (c == 0)
+              break;
+            if (c == '.')
+              dotPos = (int)i;
+            // we don't need IS_PATH_SEPAR check, because we have only (fileName) doesn't include path prefix.
+            // if (IS_PATH_SEPAR(c) || c == ':') dotPos = -1;
+          }
+          defined = true;
+          if (dotPos >= 0)
+          {
+#if 0
+            const wchar_t *ext = name + dotPos;
+            if (StringsAreEqualNoCase_Ascii(ext, ".exe") ||
+                StringsAreEqualNoCase_Ascii(ext, ".ico"))
+#endif
+              defined = false;
+          }
+        }
+#endif
+      }
     }
 
     if (!defined)
@@ -769,26 +816,37 @@ HRESULT CPanel::RefreshListCtrl(const CSelectedState &state)
         NCOM::CPropVariant prop;
         RINOK(_folder->GetProperty(i, kpidAttrib, &prop))
         if (prop.vt == VT_UI4)
+        {
           attrib = prop.ulVal;
+          if (isArcFolder)
+          {
+            // if attrib (high 16-bits) is supposed from posix,
+            // we keep only low bits (basic Windows attrib flags):
+            if (attrib & 0xF0000000)
+              attrib &= 0x3FFF;
+          }
+        }
       }
       if (IsItem_Folder(i))
         attrib |= FILE_ATTRIBUTE_DIRECTORY;
-
-      if (_currentFolderPrefix.IsEmpty())
-      {
-        int iconIndexTemp;
-        GetRealIconIndex(us2fs((UString)name) + FCHAR_PATH_SEPARATOR, attrib, iconIndexTemp);
-        item.iImage = iconIndexTemp;
-      }
       else
+        attrib &= ~(UInt32)FILE_ATTRIBUTE_DIRECTORY;
+
+      item.iImage = -1;
+      if (isFSDrivesFolder)
       {
-        item.iImage = _extToIconMap.GetIconIndex(attrib, name);
+        FString fs (us2fs((UString)name));
+        fs.Add_PathSepar();
+        item.iImage = Shell_GetFileInfo_SysIconIndex_for_Path(fs, attrib);
+        // item.iImage = 0; // for debug
       }
+      if (item.iImage < 0) // <= 0 check?
+        item.iImage = g_Ext_to_Icon_Map.GetIconIndex(attrib, name);
     }
     
+    // item.iImage = -1; // for debug
     if (item.iImage < 0)
-      item.iImage = 0;
-
+        item.iImage = 0; // default image
     if (_listView.InsertItem(&item) == -1)
       return E_FAIL;
     listViewItemCount++;
@@ -858,8 +916,8 @@ HRESULT CPanel::RefreshListCtrl(const CSelectedState &state)
   sprintf(s,
       // "attribMap = %5d, extMap = %5d, "
       "delete = %5d, load = %5d, list = %5d, sort = %5d, end = %5d",
-      // _extToIconMap._attribMap.Size(),
-      // _extToIconMap._extMap.Size(),
+      // g_Ext_to_Icon_Map._attribMap.Size(),
+      // g_Ext_to_Icon_Map._extMap.Size(),
       tickCount1 - tickCount0,
       tickCount2 - tickCount1,
       tickCount3 - tickCount2,
diff --git a/CPP/7zip/UI/FileManager/PanelOperations.cpp b/CPP/7zip/UI/FileManager/PanelOperations.cpp
index 6c2cea1..af313ff 100644
--- a/CPP/7zip/UI/FileManager/PanelOperations.cpp
+++ b/CPP/7zip/UI/FileManager/PanelOperations.cpp
@@ -244,7 +244,8 @@ Z7_DIAGNOSTIC_IGNORE_CAST_FUNCTION
     messageID = IDS_WANT_TO_DELETE_ITEMS;
     messageParam = NumberToString(indices.Size());
   }
-  if (::MessageBoxW(GetParent(), MyFormatNew(messageID, messageParam), LangString(titleID), MB_OKCANCEL | MB_ICONQUESTION) != IDOK)
+  if (::MessageBoxW(GetParent(), MyFormatNew(messageID, messageParam), LangString(titleID),
+      MB_YESNOCANCEL | MB_ICONQUESTION) != IDYES)
     return;
 
   CDisableNotify disableNotify(*this);
diff --git a/CPP/7zip/UI/FileManager/RootFolder.cpp b/CPP/7zip/UI/FileManager/RootFolder.cpp
index 606fb7f..192f660 100644
--- a/CPP/7zip/UI/FileManager/RootFolder.cpp
+++ b/CPP/7zip/UI/FileManager/RootFolder.cpp
@@ -54,9 +54,9 @@ UString RootFolder_GetName_Computer(int &iconIndex);
 UString RootFolder_GetName_Computer(int &iconIndex)
 {
   #ifdef USE_WIN_PATHS
-  iconIndex = GetIconIndexForCSIDL(CSIDL_DRIVES);
+  iconIndex = Shell_GetFileInfo_SysIconIndex_for_CSIDL(CSIDL_DRIVES);
   #else
-  GetRealIconIndex(FSTRING_PATH_SEPARATOR, FILE_ATTRIBUTE_DIRECTORY, iconIndex);
+  iconIndex = Shell_GetFileInfo_SysIconIndex_for_Path(FSTRING_PATH_SEPARATOR, FILE_ATTRIBUTE_DIRECTORY);
   #endif
   return LangString(IDS_COMPUTER);
 }
@@ -64,14 +64,14 @@ UString RootFolder_GetName_Computer(int &iconIndex)
 UString RootFolder_GetName_Network(int &iconIndex);
 UString RootFolder_GetName_Network(int &iconIndex)
 {
-  iconIndex = GetIconIndexForCSIDL(CSIDL_NETWORK);
+  iconIndex = Shell_GetFileInfo_SysIconIndex_for_CSIDL(CSIDL_NETWORK);
   return LangString(IDS_NETWORK);
 }
 
 UString RootFolder_GetName_Documents(int &iconIndex);
 UString RootFolder_GetName_Documents(int &iconIndex)
 {
-  iconIndex = GetIconIndexForCSIDL(CSIDL_PERSONAL);
+  iconIndex = Shell_GetFileInfo_SysIconIndex_for_CSIDL(CSIDL_PERSONAL);
   return LangString(IDS_DOCUMENTS);
 }
 
@@ -96,7 +96,7 @@ void CRootFolder::Init()
   _names[ROOT_INDEX_DOCUMENTS] = RootFolder_GetName_Documents(_iconIndices[ROOT_INDEX_DOCUMENTS]);
   _names[ROOT_INDEX_NETWORK] = RootFolder_GetName_Network(_iconIndices[ROOT_INDEX_NETWORK]);
   _names[ROOT_INDEX_VOLUMES] = kVolPrefix;
-  _iconIndices[ROOT_INDEX_VOLUMES] = GetIconIndexForCSIDL(CSIDL_DRIVES);
+  _iconIndices[ROOT_INDEX_VOLUMES] = Shell_GetFileInfo_SysIconIndex_for_CSIDL(CSIDL_DRIVES);
   #endif
 }
 
diff --git a/CPP/7zip/UI/FileManager/SysIconUtils.cpp b/CPP/7zip/UI/FileManager/SysIconUtils.cpp
index c893ea9..406c9e1 100644
--- a/CPP/7zip/UI/FileManager/SysIconUtils.cpp
+++ b/CPP/7zip/UI/FileManager/SysIconUtils.cpp
@@ -20,16 +20,19 @@
 extern bool g_IsNT;
 #endif
 
-int GetIconIndexForCSIDL(int csidl)
+CExtToIconMap g_Ext_to_Icon_Map;
+
+int Shell_GetFileInfo_SysIconIndex_for_CSIDL(int csidl)
 {
   LPITEMIDLIST pidl = NULL;
   SHGetSpecialFolderLocation(NULL, csidl, &pidl);
   if (pidl)
   {
-    SHFILEINFO shellInfo;
-    shellInfo.iIcon = 0;
-    const DWORD_PTR res = SHGetFileInfo((LPCTSTR)(const void *)(pidl), FILE_ATTRIBUTE_NORMAL,
-        &shellInfo, sizeof(shellInfo),
+    SHFILEINFO shFileInfo;
+    shFileInfo.iIcon = -1;
+    const DWORD_PTR res = SHGetFileInfo((LPCTSTR)(const void *)(pidl),
+        FILE_ATTRIBUTE_DIRECTORY,
+        &shFileInfo, sizeof(shFileInfo),
         SHGFI_PIDL | SHGFI_SYSICONINDEX);
     /*
     IMalloc *pMalloc;
@@ -43,9 +46,9 @@ int GetIconIndexForCSIDL(int csidl)
     // we use OLE2.dll function here
     CoTaskMemFree(pidl);
     if (res)
-      return shellInfo.iIcon;
+      return shFileInfo.iIcon;
   }
-  return 0;
+  return -1;
 }
 
 #ifndef _UNICODE
@@ -60,69 +63,111 @@ static struct C_SHGetFileInfo_Init
        f_SHGetFileInfoW = Z7_GET_PROC_ADDRESS(
     Func_SHGetFileInfoW, ::GetModuleHandleW(L"shell32.dll"),
         "SHGetFileInfoW");
+    // f_SHGetFileInfoW = NULL; // for debug
   }
 } g_SHGetFileInfo_Init;
 #endif
 
+#ifdef _UNICODE
+#define My_SHGetFileInfoW SHGetFileInfoW
+#else
 static DWORD_PTR My_SHGetFileInfoW(LPCWSTR pszPath, DWORD attrib, SHFILEINFOW *psfi, UINT cbFileInfo, UINT uFlags)
 {
-  #ifdef _UNICODE
-  return SHGetFileInfo
-  #else
   if (!g_SHGetFileInfo_Init.f_SHGetFileInfoW)
     return 0;
-  return g_SHGetFileInfo_Init.f_SHGetFileInfoW
-  #endif
-  (pszPath, attrib, psfi, cbFileInfo, uFlags);
+  return g_SHGetFileInfo_Init.f_SHGetFileInfoW(pszPath, attrib, psfi, cbFileInfo, uFlags);
 }
+#endif
 
-DWORD_PTR GetRealIconIndex(CFSTR path, DWORD attrib, int &iconIndex)
+DWORD_PTR Shell_GetFileInfo_SysIconIndex_for_Path_attrib_iconIndexRef(
+    CFSTR path, DWORD attrib, int &iconIndex)
 {
-  #ifndef _UNICODE
-  if (!g_IsNT)
+#ifndef _UNICODE
+  if (!g_IsNT || !g_SHGetFileInfo_Init.f_SHGetFileInfoW)
   {
-    SHFILEINFO shellInfo;
-    const DWORD_PTR res = ::SHGetFileInfo(fs2fas(path), FILE_ATTRIBUTE_NORMAL | attrib, &shellInfo,
-      sizeof(shellInfo), SHGFI_USEFILEATTRIBUTES | SHGFI_SYSICONINDEX);
-    iconIndex = shellInfo.iIcon;
+    SHFILEINFO shFileInfo;
+    // ZeroMemory(&shFileInfo, sizeof(shFileInfo));
+    shFileInfo.iIcon = -1;   // optional
+    const DWORD_PTR res = ::SHGetFileInfo(fs2fas(path),
+        attrib ? attrib : FILE_ATTRIBUTE_ARCHIVE,
+        &shFileInfo, sizeof(shFileInfo),
+        SHGFI_USEFILEATTRIBUTES | SHGFI_SYSICONINDEX);
+    iconIndex = shFileInfo.iIcon;
     return res;
   }
   else
-  #endif
+#endif
   {
-    SHFILEINFOW shellInfo;
-    const DWORD_PTR res = ::My_SHGetFileInfoW(fs2us(path), FILE_ATTRIBUTE_NORMAL | attrib, &shellInfo,
-      sizeof(shellInfo), SHGFI_USEFILEATTRIBUTES | SHGFI_SYSICONINDEX);
-    iconIndex = shellInfo.iIcon;
+    SHFILEINFOW shFileInfo;
+    // ZeroMemory(&shFileInfo, sizeof(shFileInfo));
+    shFileInfo.iIcon = -1;   // optional
+    const DWORD_PTR res = ::My_SHGetFileInfoW(fs2us(path),
+        attrib ? attrib : FILE_ATTRIBUTE_ARCHIVE,
+        &shFileInfo, sizeof(shFileInfo),
+        SHGFI_USEFILEATTRIBUTES | SHGFI_SYSICONINDEX);
+    // (shFileInfo.iIcon == 0) returned for unknown extensions and files without extension
+    iconIndex = shFileInfo.iIcon;
+    // we use SHGFI_USEFILEATTRIBUTES, and
+    //   (res != 0) is expected for main cases, even if there are no such file.
+    //   (res == 0) for path with kSuperPrefix \\?\
+    // Also SHGFI_USEFILEATTRIBUTES still returns icon inside exe.
+    // So we can use SHGFI_USEFILEATTRIBUTES for any case.
+    // UString temp = fs2us(path); // for debug
+    // UString tempName = temp.Ptr(temp.ReverseFind_PathSepar() + 1); // for debug
+    // iconIndex = -1; // for debug
     return res;
   }
 }
 
+int Shell_GetFileInfo_SysIconIndex_for_Path(CFSTR path, DWORD attrib)
+{
+  int iconIndex = -1;
+  if (!Shell_GetFileInfo_SysIconIndex_for_Path_attrib_iconIndexRef(
+      path, attrib, iconIndex))
+    iconIndex = -1;
+  return iconIndex;
+}
+
+
+HRESULT Shell_GetFileInfo_SysIconIndex_for_Path_return_HRESULT(
+    CFSTR path, DWORD attrib, Int32 *iconIndex)
+{
+  *iconIndex = -1;
+  int iconIndexTemp;
+  if (Shell_GetFileInfo_SysIconIndex_for_Path_attrib_iconIndexRef(
+      path, attrib, iconIndexTemp))
+  {
+    *iconIndex = iconIndexTemp;
+    return S_OK;
+  }
+  return GetLastError_noZero_HRESULT();
+}
+
 /*
-DWORD_PTR GetRealIconIndex(const UString &fileName, DWORD attrib, int &iconIndex, UString *typeName)
+DWORD_PTR Shell_GetFileInfo_SysIconIndex_for_Path(const UString &fileName, DWORD attrib, int &iconIndex, UString *typeName)
 {
   #ifndef _UNICODE
   if (!g_IsNT)
   {
-    SHFILEINFO shellInfo;
-    shellInfo.szTypeName[0] = 0;
-    DWORD_PTR res = ::SHGetFileInfoA(GetSystemString(fileName), FILE_ATTRIBUTE_NORMAL | attrib, &shellInfo,
-        sizeof(shellInfo), SHGFI_USEFILEATTRIBUTES | SHGFI_SYSICONINDEX | SHGFI_TYPENAME);
+    SHFILEINFO shFileInfo;
+    shFileInfo.szTypeName[0] = 0;
+    DWORD_PTR res = ::SHGetFileInfoA(GetSystemString(fileName), FILE_ATTRIBUTE_ARCHIVE | attrib, &shFileInfo,
+        sizeof(shFileInfo), SHGFI_USEFILEATTRIBUTES | SHGFI_SYSICONINDEX | SHGFI_TYPENAME);
     if (typeName)
-      *typeName = GetUnicodeString(shellInfo.szTypeName);
-    iconIndex = shellInfo.iIcon;
+      *typeName = GetUnicodeString(shFileInfo.szTypeName);
+    iconIndex = shFileInfo.iIcon;
     return res;
   }
   else
   #endif
   {
-    SHFILEINFOW shellInfo;
-    shellInfo.szTypeName[0] = 0;
-    DWORD_PTR res = ::My_SHGetFileInfoW(fileName, FILE_ATTRIBUTE_NORMAL | attrib, &shellInfo,
-        sizeof(shellInfo), SHGFI_USEFILEATTRIBUTES | SHGFI_SYSICONINDEX | SHGFI_TYPENAME);
+    SHFILEINFOW shFileInfo;
+    shFileInfo.szTypeName[0] = 0;
+    DWORD_PTR res = ::My_SHGetFileInfoW(fileName, FILE_ATTRIBUTE_ARCHIVE | attrib, &shFileInfo,
+        sizeof(shFileInfo), SHGFI_USEFILEATTRIBUTES | SHGFI_SYSICONINDEX | SHGFI_TYPENAME);
     if (typeName)
-      *typeName = shellInfo.szTypeName;
-    iconIndex = shellInfo.iIcon;
+      *typeName = shFileInfo.szTypeName;
+    iconIndex = shFileInfo.iIcon;
     return res;
   }
 }
@@ -164,6 +209,9 @@ static int FindInSorted_Ext(const CObjectVector<CExtIconPair> &vect, const wchar
   return -1;
 }
 
+
+// bool DoItemAlwaysStart(const UString &name);
+
 int CExtToIconMap::GetIconIndex(DWORD attrib, const wchar_t *fileName /*, UString *typeName */)
 {
   int dotPos = -1;
@@ -175,6 +223,8 @@ int CExtToIconMap::GetIconIndex(DWORD attrib, const wchar_t *fileName /*, UStrin
       break;
     if (c == '.')
       dotPos = (int)i;
+    // we don't need IS_PATH_SEPAR check, because (fileName) doesn't include path prefix.
+    // if (IS_PATH_SEPAR(c) || c == ':') dotPos = -1;
   }
 
   /*
@@ -187,8 +237,11 @@ int CExtToIconMap::GetIconIndex(DWORD attrib, const wchar_t *fileName /*, UStrin
   }
   */
 
-  if ((attrib & FILE_ATTRIBUTE_DIRECTORY) != 0 || dotPos < 0)
+  if ((attrib & FILE_ATTRIBUTE_DIRECTORY) || dotPos < 0)
+  for (unsigned k = 0;; k++)
   {
+    if (k >= 2)
+      return -1;
     unsigned insertPos = 0;
     const int index = FindInSorted_Attrib(_attribMap, attrib, insertPos);
     if (index >= 0)
@@ -197,33 +250,43 @@ int CExtToIconMap::GetIconIndex(DWORD attrib, const wchar_t *fileName /*, UStrin
       return _attribMap[(unsigned)index].IconIndex;
     }
     CAttribIconPair pair;
-    GetRealIconIndex(
+    pair.IconIndex = Shell_GetFileInfo_SysIconIndex_for_Path(
         #ifdef UNDER_CE
         FTEXT("\\")
         #endif
         FTEXT("__DIR__")
-        , attrib, pair.IconIndex
+        , attrib
         // , pair.TypeName
         );
-
-    /*
-    char s[256];
-    sprintf(s, "i = %3d, attr = %7x", _attribMap.Size(), attrib);
-    OutputDebugStringA(s);
-    */
-
-    pair.Attrib = attrib;
-    _attribMap.Insert(insertPos, pair);
-    // if (typeName) *typeName = pair.TypeName;
-    return pair.IconIndex;
+    if (_attribMap.Size() < (1u << 16) // we limit cache size
+       || attrib < (1u << 15)) // we want to put all items with basic attribs to cache
+    {
+      /*
+      char s[256];
+      sprintf(s, "i = %3d, attr = %7x", _attribMap.Size(), attrib);
+      OutputDebugStringA(s);
+      */
+      pair.Attrib = attrib;
+      _attribMap.Insert(insertPos, pair);
+      // if (typeName) *typeName = pair.TypeName;
+      return pair.IconIndex;
+    }
+    if (pair.IconIndex >= 0)
+      return pair.IconIndex;
+    attrib = (attrib & FILE_ATTRIBUTE_DIRECTORY) ?
+        FILE_ATTRIBUTE_DIRECTORY :
+        FILE_ATTRIBUTE_ARCHIVE;
   }
 
+  CObjectVector<CExtIconPair> &map =
+      (attrib & FILE_ATTRIBUTE_COMPRESSED) ?
+          _extMap_Compressed : _extMap_Normal;
   const wchar_t *ext = fileName + dotPos + 1;
   unsigned insertPos = 0;
-  const int index = FindInSorted_Ext(_extMap, ext, insertPos);
+  const int index = FindInSorted_Ext(map, ext, insertPos);
   if (index >= 0)
   {
-    const CExtIconPair &pa = _extMap[index];
+    const CExtIconPair &pa = map[index];
     // if (typeName) *typeName = pa.TypeName;
     return pa.IconIndex;
   }
@@ -238,14 +301,14 @@ int CExtToIconMap::GetIconIndex(DWORD attrib, const wchar_t *fileName /*, UStrin
   }
   if (i != 0 && ext[i] == 0)
   {
-    // GetRealIconIndex is too slow for big number of split extensions: .001, .002, .003
+    // Shell_GetFileInfo_SysIconIndex_for_Path is too slow for big number of split extensions: .001, .002, .003
     if (!SplitIconIndex_Defined)
     {
-      GetRealIconIndex(
+      Shell_GetFileInfo_SysIconIndex_for_Path_attrib_iconIndexRef(
           #ifdef UNDER_CE
           FTEXT("\\")
           #endif
-          FTEXT("__FILE__.001"), 0, SplitIconIndex);
+          FTEXT("__FILE__.001"), FILE_ATTRIBUTE_ARCHIVE, SplitIconIndex);
       SplitIconIndex_Defined = true;
     }
     return SplitIconIndex;
@@ -253,27 +316,36 @@ int CExtToIconMap::GetIconIndex(DWORD attrib, const wchar_t *fileName /*, UStrin
 
   CExtIconPair pair;
   pair.Ext = ext;
-  GetRealIconIndex(us2fs(fileName + dotPos), attrib, pair.IconIndex);
-  _extMap.Insert(insertPos, pair);
+  pair.IconIndex = Shell_GetFileInfo_SysIconIndex_for_Path(
+      us2fs(fileName + dotPos),
+      attrib & FILE_ATTRIBUTE_COMPRESSED ?
+          FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_COMPRESSED:
+          FILE_ATTRIBUTE_ARCHIVE);
+  if (map.Size() < (1u << 16)  // we limit cache size
+      // || DoItemAlwaysStart(fileName + dotPos) // we want some popular extensions in cache
+      )
+    map.Insert(insertPos, pair);
   // if (typeName) *typeName = pair.TypeName;
   return pair.IconIndex;
 }
 
-/*
-int CExtToIconMap::GetIconIndex(DWORD attrib, const UString &fileName)
-{
-  return GetIconIndex(attrib, fileName, NULL);
-}
-*/
 
-HIMAGELIST GetSysImageList(bool smallIcons)
+HIMAGELIST Shell_Get_SysImageList_smallIcons(bool smallIcons)
 {
-  SHFILEINFO shellInfo;
-  return (HIMAGELIST)SHGetFileInfo(TEXT(""),
-      FILE_ATTRIBUTE_NORMAL |
+  SHFILEINFO shFileInfo;
+  // shFileInfo.hIcon = NULL; // optional
+  const DWORD_PTR res = SHGetFileInfo(TEXT(""),
+      /* FILE_ATTRIBUTE_ARCHIVE | */
       FILE_ATTRIBUTE_DIRECTORY,
-      &shellInfo, sizeof(shellInfo),
+      &shFileInfo, sizeof(shFileInfo),
       SHGFI_USEFILEATTRIBUTES |
       SHGFI_SYSICONINDEX |
-      (smallIcons ? SHGFI_SMALLICON : SHGFI_ICON));
+      (smallIcons ? SHGFI_SMALLICON : SHGFI_LARGEICON));
+#if 0
+  // (shFileInfo.hIcon == NULL), because we don't use SHGFI_ICON.
+  // so DestroyIcon() is not required
+  if (res && shFileInfo.hIcon) // unexpected
+    DestroyIcon(shFileInfo.hIcon);
+#endif
+  return (HIMAGELIST)res;
 }
diff --git a/CPP/7zip/UI/FileManager/SysIconUtils.h b/CPP/7zip/UI/FileManager/SysIconUtils.h
index 1d34ef6..975ce25 100644
--- a/CPP/7zip/UI/FileManager/SysIconUtils.h
+++ b/CPP/7zip/UI/FileManager/SysIconUtils.h
@@ -14,7 +14,6 @@ struct CExtIconPair
   UString Ext;
   int IconIndex;
   // UString TypeName;
-
   // int Compare(const CExtIconPair &a) const { return MyStringCompareNoCase(Ext, a.Ext); }
 };
 
@@ -23,15 +22,15 @@ struct CAttribIconPair
   DWORD Attrib;
   int IconIndex;
   // UString TypeName;
-
   // int Compare(const CAttribIconPair &a) const { return Ext.Compare(a.Ext); }
 };
 
-class CExtToIconMap
+
+struct CExtToIconMap
 {
-public:
   CRecordVector<CAttribIconPair> _attribMap;
-  CObjectVector<CExtIconPair> _extMap;
+  CObjectVector<CExtIconPair> _extMap_Normal;
+  CObjectVector<CExtIconPair> _extMap_Compressed;
   int SplitIconIndex;
   int SplitIconIndex_Defined;
   
@@ -40,16 +39,27 @@ public:
   void Clear()
   {
     SplitIconIndex_Defined = false;
-    _extMap.Clear();
+    _extMap_Normal.Clear();
+    _extMap_Compressed.Clear();
     _attribMap.Clear();
   }
+  int GetIconIndex_DIR(DWORD attrib = FILE_ATTRIBUTE_DIRECTORY)
+  {
+    return GetIconIndex(attrib, L"__DIR__");
+  }
   int GetIconIndex(DWORD attrib, const wchar_t *fileName /* , UString *typeName */);
-  // int GetIconIndex(DWORD attrib, const UString &fileName);
 };
 
-DWORD_PTR GetRealIconIndex(CFSTR path, DWORD attrib, int &iconIndex);
-int GetIconIndexForCSIDL(int csidl);
+extern CExtToIconMap g_Ext_to_Icon_Map;
+
+DWORD_PTR Shell_GetFileInfo_SysIconIndex_for_Path_attrib_iconIndexRef(
+    CFSTR path, DWORD attrib, int &iconIndex);
+HRESULT Shell_GetFileInfo_SysIconIndex_for_Path_return_HRESULT(
+    CFSTR path, DWORD attrib, Int32 *iconIndex);
+int Shell_GetFileInfo_SysIconIndex_for_Path(CFSTR path, DWORD attrib);
+
+int Shell_GetFileInfo_SysIconIndex_for_CSIDL(int csidl);
 
-HIMAGELIST GetSysImageList(bool smallIcons);
+HIMAGELIST Shell_Get_SysImageList_smallIcons(bool smallIcons);
 
 #endif
diff --git a/CPP/7zip/UI/FileManager/VerCtrl.cpp b/CPP/7zip/UI/FileManager/VerCtrl.cpp
index f1353b8..c1ca643 100644
--- a/CPP/7zip/UI/FileManager/VerCtrl.cpp
+++ b/CPP/7zip/UI/FileManager/VerCtrl.cpp
@@ -387,13 +387,13 @@ void CApp::VerCtrl(unsigned id)
         */
         COverwriteDialog dialog;
         
-        dialog.OldFileInfo.SetTime(&fdi.Info.ftLastWriteTime);
+        dialog.OldFileInfo.SetTime(fdi.Info.ftLastWriteTime);
         dialog.OldFileInfo.SetSize(fdi.GetSize());
-        dialog.OldFileInfo.Name = fs2us(path);
+        dialog.OldFileInfo.Path = fs2us(path);
         
-        dialog.NewFileInfo.SetTime(&fdi2.Info.ftLastWriteTime);
+        dialog.NewFileInfo.SetTime(fdi2.Info.ftLastWriteTime);
         dialog.NewFileInfo.SetSize(fdi2.GetSize());
-        dialog.NewFileInfo.Name = fs2us(path2);
+        dialog.NewFileInfo.Path = fs2us(path2);
 
         dialog.ShowExtraButtons = false;
         dialog.DefaultButton_is_NO = true;
diff --git a/CPP/7zip/UI/GUI/HashGUI.cpp b/CPP/7zip/UI/GUI/HashGUI.cpp
index b96e413..231bab5 100644
--- a/CPP/7zip/UI/GUI/HashGUI.cpp
+++ b/CPP/7zip/UI/GUI/HashGUI.cpp
@@ -66,28 +66,6 @@ void AddValuePair(CPropNameValPairs &pairs, UINT resourceID, UInt64 value)
 }
 
 
-void AddSizeValue(UString &s, UInt64 value)
-{
-  {
-    wchar_t sz[32];
-    ConvertUInt64ToString(value, sz);
-    s += MyFormatNew(IDS_FILE_SIZE, sz);
-  }
-  if (value >= (1 << 10))
-  {
-    char c;
-          if (value >= ((UInt64)10 << 30)) { value >>= 30; c = 'G'; }
-    else  if (value >=         (10 << 20)) { value >>= 20; c = 'M'; }
-    else                                   { value >>= 10; c = 'K'; }
-    
-    s += " (";
-    s.Add_UInt64(value);
-    s.Add_Space();
-    s += (wchar_t)c;
-    s += "iB)";
-  }
-}
-
 void AddSizeValuePair(CPropNameValPairs &pairs, UINT resourceID, UInt64 value)
 {
   CProperty &pair = pairs.AddNew();
diff --git a/CPP/Windows/FileSystem.cpp b/CPP/Windows/FileSystem.cpp
index d11f02e..b402306 100644
--- a/CPP/Windows/FileSystem.cpp
+++ b/CPP/Windows/FileSystem.cpp
@@ -157,6 +157,31 @@ bool MyGetDiskFreeSpace(CFSTR rootPath, UInt64 &clusterSize, UInt64 &totalSize,
 
 #endif
 
+/*
+bool Is_File_LimitedBy_4GB(CFSTR _path, bool &isFsDetected)
+{
+  isFsDetected = false;
+  FString path (_path);
+  path.DeleteFrom(NName::GetRootPrefixSize(path));
+  // GetVolumeInformation supports super paths.
+  // NName::If_IsSuperPath_RemoveSuperPrefix(path);
+  if (!path.IsEmpty())
+  {
+    DWORD volumeSerialNumber, maximumComponentLength, fileSystemFlags;
+    UString volName, fileSystemName;
+    if (MyGetVolumeInformation(path, volName,
+        &volumeSerialNumber, &maximumComponentLength, &fileSystemFlags,
+        fileSystemName))
+    {
+      isFsDetected = true;
+      if (fileSystemName.IsPrefixedBy_Ascii_NoCase("fat"))
+        return true;
+    }
+  }
+  return false;
+}
+*/
+
 }}}
 
 #endif
diff --git a/CPP/Windows/SystemInfo.cpp b/CPP/Windows/SystemInfo.cpp
index d23e84b..cfc6a90 100644
--- a/CPP/Windows/SystemInfo.cpp
+++ b/CPP/Windows/SystemInfo.cpp
@@ -5,6 +5,7 @@
 #include "../../C/CpuArch.h"
 
 #include "../Common/IntToString.h"
+#include "../Common/StringConvert.h"
 
 #ifdef _WIN32
 
@@ -511,8 +512,6 @@ void GetSysInfo(AString &s1, AString &s2)
 }
 
 
-void GetCpuName(AString &s);
-
 static void AddBracedString(AString &dest, AString &src)
 {
   if (!src.IsEmpty())
@@ -554,9 +553,7 @@ void CCpuName::Fill()
   #ifdef MY_CPU_X86_OR_AMD64
   {
     #if !defined(MY_CPU_AMD64)
-    if (!z7_x86_cpuid_GetMaxFunc())
-      s += "x86";
-    else
+    if (z7_x86_cpuid_GetMaxFunc())
     #endif
     {
       x86cpuid_to_String(s);
@@ -583,43 +580,26 @@ void CCpuName::Fill()
   #endif
 
 
-  if (s.IsEmpty())
-  {
-    #ifdef MY_CPU_LE
-      s += "LE";
-    #elif defined(MY_CPU_BE)
-      s += "BE";
-    #endif
-  }
-  
-  #ifdef __APPLE__
-  {
-    AString s2;
-    UInt32 v = 0;
-    if (z7_sysctlbyname_Get_UInt32("machdep.cpu.core_count", &v) == 0)
-    {
-      s2.Add_UInt32(v);
-      s2 += 'C';
-    }
-    if (z7_sysctlbyname_Get_UInt32("machdep.cpu.thread_count", &v) == 0)
-    {
-      s2.Add_UInt32(v);
-      s2 += 'T';
-    }
-    if (!s2.IsEmpty())
-    {
-      s.Add_Space_if_NotEmpty();
-      s += s2;
-    }
-  }
-  #endif
-
-  
-  #ifdef _WIN32
+#ifdef _WIN32
   {
     NRegistry::CKey key;
     if (key.Open(HKEY_LOCAL_MACHINE, TEXT("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"), KEY_READ) == ERROR_SUCCESS)
     {
+      // s.Empty(); // for debug
+      {
+        CSysString name;
+        if (s.IsEmpty())
+        if (key.QueryValue(TEXT("ProcessorNameString"), name) == ERROR_SUCCESS)
+        {
+          s += GetAnsiString(name);
+        }
+        if (key.QueryValue(TEXT("Identifier"), name) == ERROR_SUCCESS)
+        {
+          if (!Revision.IsEmpty())
+            Revision += " : ";
+          Revision += GetAnsiString(name);
+        }
+      }
       LONG res[2];
       CByteBuffer bufs[2];
       {
@@ -627,8 +607,9 @@ void CCpuName::Fill()
         {
           UInt32 size = 0;
           res[i] = key.QueryValue(i == 0 ?
-            TEXT("Previous Update Revision") :
-            TEXT("Update Revision"), bufs[i], size);
+              TEXT("Previous Update Revision") :
+              TEXT("Update Revision"),
+              bufs[i], size);
           if (res[i] == ERROR_SUCCESS)
             if (size != bufs[i].Size())
               res[i] = ERROR_SUCCESS + 1;
@@ -657,8 +638,36 @@ void CCpuName::Fill()
       }
     }
   }
-  #endif
+#endif
 
+  if (s.IsEmpty())
+  {
+    #ifdef MY_CPU_NAME
+      s += MY_CPU_NAME;
+    #endif
+  }
+  
+  #ifdef __APPLE__
+  {
+    AString s2;
+    UInt32 v = 0;
+    if (z7_sysctlbyname_Get_UInt32("machdep.cpu.core_count", &v) == 0)
+    {
+      s2.Add_UInt32(v);
+      s2.Add_Char('C');
+    }
+    if (z7_sysctlbyname_Get_UInt32("machdep.cpu.thread_count", &v) == 0)
+    {
+      s2.Add_UInt32(v);
+      s2.Add_Char('T');
+    }
+    if (!s2.IsEmpty())
+    {
+      s.Add_Space_if_NotEmpty();
+      s += s2;
+    }
+  }
+  #endif
 
   #ifdef Z7_LARGE_PAGES
   Add_LargePages_String(LargePages);
@@ -900,7 +909,7 @@ void GetSystemInfoText(AString &sRes)
     }
     {
       AString s;
-      GetCpuName(s);
+      GetCpuName_MultiLine(s);
       if (!s.IsEmpty())
       {
         sRes += s;
@@ -923,18 +932,6 @@ void GetSystemInfoText(AString &sRes)
 }
 
 
-void GetCpuName(AString &s);
-void GetCpuName(AString &s)
-{
-  CCpuName cpuName;
-  cpuName.Fill();
-  s = cpuName.CpuName;
-  AString s2;
-  cpuName.Get_Revision_Microcode_LargePages(s2);
-  s.Add_OptSpaced(s2);
-}
-
-
 void GetCpuName_MultiLine(AString &s);
 void GetCpuName_MultiLine(AString &s)
 {
diff --git a/DOC/7zip.wxs b/DOC/7zip.wxs
index 7705d16..f41b393 100644
--- a/DOC/7zip.wxs
+++ b/DOC/7zip.wxs
@@ -1,7 +1,7 @@
 <?xml version="1.0"?>
 
 <?define VerMajor = "24" ?>
-<?define VerMinor = "05" ?>
+<?define VerMinor = "08" ?>
 <?define VerBuild = "00" ?>
 <?define MmVer = "$(var.VerMajor).$(var.VerMinor)" ?>
 <?define MmHex = "$(var.VerMajor)$(var.VerMinor)" ?>
diff --git a/DOC/lzma.txt b/DOC/lzma.txt
index 0d9863c..166bc3b 100644
--- a/DOC/lzma.txt
+++ b/DOC/lzma.txt
@@ -1,6 +1,6 @@
 LZMA compression
 ----------------
-Version: 24.05
+Version: 24.07
 
 This file describes LZMA encoding and decoding functions written in C language.
 
diff --git a/DOC/readme.txt b/DOC/readme.txt
index a33af83..6d04c5a 100644
--- a/DOC/readme.txt
+++ b/DOC/readme.txt
@@ -1,4 +1,4 @@
-7-Zip 24.05 Sources
+7-Zip 24.07 Sources
 -------------------
 
 7-Zip is a file archiver for Windows. 
diff --git a/DOC/src-history.txt b/DOC/src-history.txt
index 1f29322..1653c07 100644
--- a/DOC/src-history.txt
+++ b/DOC/src-history.txt
@@ -1,6 +1,32 @@
 HISTORY of the 7-Zip source code
 --------------------------------
 
+24.08          2024-08-11
+-------------------------
+- The bug in 7-Zip 24.00-24.07 was fixed:
+  For creating a zip archive: 7-Zip could write extra zero bytes after the end of the archive,
+  if a file included to archive cannot be compressed to a size smaller than original.
+  The created zip archive is correct except for the useless zero bytes after the end of the archive.
+  When unpacking such a zip archive, 7-Zip displays a warning:
+    "WARNING: There are data after the end of archive".
+- Some bugs were fixed.
+
+
+24.07          2024-06-19
+-------------------------
+- Changes in files:
+    Asm/x86/Sha256Opt.asm
+    Asm/x86/Sha1Opt.asm
+  Now it uses "READONLY" flag for constant array segment.
+  It fixes an issue where ".rodata" section in 7-Zip for x86/x64 Linux had a "WRITE" attribute.
+- The bug was fixed: 7-Zip could crash for some incorrect ZSTD archives.
+
+
+24.06          2024-05-26
+-------------------------
+- The bug was fixed: 7-Zip could not unpack some ZSTD archives.
+ 
+
 24.05          2024-05-14
 -------------------------
 - New switch -myv={MMNN} to set decoder compatibility version for 7z archive creating.
diff --git a/METADATA b/METADATA
index 150f965..cdff02b 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/lzma
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "lzma"
 description: "LZMA is default and general compression method of 7z format."
@@ -8,13 +8,13 @@ third_party {
   license_type: UNENCUMBERED
   last_upgrade_date {
     year: 2024
-    month: 5
-    day: 23
+    month: 9
+    day: 5
   }
   homepage: "https://7-zip.org/"
   identifier {
     type: "Archive"
-    value: "https://github.com/ip7z/7zip/archive/24.05.tar.gz"
-    version: "24.05"
+    value: "https://github.com/ip7z/7zip/archive/24.08.tar.gz"
+    version: "24.08"
   }
 }
```

