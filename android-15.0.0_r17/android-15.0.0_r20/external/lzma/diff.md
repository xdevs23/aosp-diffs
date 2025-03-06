```diff
diff --git a/C/7zDec.c b/C/7zDec.c
index c9b4064..520cbfd 100644
--- a/C/7zDec.c
+++ b/C/7zDec.c
@@ -1,5 +1,5 @@
 /* 7zDec.c -- Decoding from 7z folder
-2024-03-01 : Igor Pavlov : Public domain */
+: Igor Pavlov : Public domain */
 
 #include "Precomp.h"
 
@@ -312,8 +312,9 @@ static BoolInt IS_MAIN_METHOD(UInt32 m)
     case k_PPMD:
   #endif
       return True;
+    default:
+      return False;
   }
-  return False;
 }
 
 static BoolInt IS_SUPPORTED_CODER(const CSzCoderInfo *c)
diff --git a/C/7zVersion.h b/C/7zVersion.h
index 1ddef80..e82ba0b 100644
--- a/C/7zVersion.h
+++ b/C/7zVersion.h
@@ -1,7 +1,7 @@
 #define MY_VER_MAJOR 24
-#define MY_VER_MINOR 8
+#define MY_VER_MINOR 9
 #define MY_VER_BUILD 0
-#define MY_VERSION_NUMBERS "24.08"
+#define MY_VERSION_NUMBERS "24.09"
 #define MY_VERSION MY_VERSION_NUMBERS
 
 #ifdef MY_CPU_NAME
@@ -10,7 +10,7 @@
   #define MY_VERSION_CPU MY_VERSION
 #endif
 
-#define MY_DATE "2024-08-11"
+#define MY_DATE "2024-11-29"
 #undef MY_COPYRIGHT
 #undef MY_VERSION_COPYRIGHT_DATE
 #define MY_AUTHOR_NAME "Igor Pavlov"
diff --git a/C/AesOpt.c b/C/AesOpt.c
index 58769ea..b281807 100644
--- a/C/AesOpt.c
+++ b/C/AesOpt.c
@@ -1,5 +1,5 @@
 /* AesOpt.c -- AES optimized code for x86 AES hardware instructions
-2024-03-01 : Igor Pavlov : Public domain */
+Igor Pavlov : Public domain */
 
 #include "Precomp.h"
 
@@ -80,19 +80,39 @@ AES_FUNC_START (name)
 
 #define MM_XOR( dest, src)    MM_OP(_mm_xor_si128,    dest, src)
 
+#if 1
+// use aligned SSE load/store for data.
+// It is required for our Aes functions, that data is aligned for 16-bytes.
+// So we can use this branch of code.
+// and compiler can use fused load-op SSE instructions:
+//   xorps xmm0, XMMWORD PTR [rdx]
+#define LOAD_128(pp)        (*(__m128i *)(void *)(pp))
+#define STORE_128(pp, _v)    *(__m128i *)(void *)(pp) = _v
+// use aligned SSE load/store for data. Alternative code with direct access
+// #define LOAD_128(pp)        _mm_load_si128(pp)
+// #define STORE_128(pp, _v)   _mm_store_si128(pp, _v)
+#else
+// use unaligned load/store for data: movdqu XMMWORD PTR [rdx]
+#define LOAD_128(pp)        _mm_loadu_si128(pp)
+#define STORE_128(pp, _v)   _mm_storeu_si128(pp, _v)
+#endif
+
 AES_FUNC_START2 (AesCbc_Encode_HW)
 {
+  if (numBlocks == 0)
+    return;
+  {
   __m128i *p = (__m128i *)(void *)ivAes;
   __m128i *data = (__m128i *)(void *)data8;
   __m128i m = *p;
   const __m128i k0 = p[2];
   const __m128i k1 = p[3];
   const UInt32 numRounds2 = *(const UInt32 *)(p + 1) - 1;
-  for (; numBlocks != 0; numBlocks--, data++)
+  do
   {
     UInt32 r = numRounds2;
     const __m128i *w = p + 4;
-    __m128i temp = *data;
+    __m128i temp = LOAD_128(data);
     MM_XOR (temp, k0)
     MM_XOR (m, temp)
     MM_OP_m (_mm_aesenc_si128, k1)
@@ -104,9 +124,12 @@ AES_FUNC_START2 (AesCbc_Encode_HW)
     }
     while (--r);
     MM_OP_m (_mm_aesenclast_si128, w[0])
-    *data = m;
+    STORE_128(data, m);
+    data++;
   }
+  while (--numBlocks);
   *p = m;
+  }
 }
 
 
@@ -139,12 +162,12 @@ AES_FUNC_START2 (AesCbc_Encode_HW)
 
 #define WOP(op)  op (m0, 0)  WOP_M1(op)
 
-
 #define DECLARE_VAR(reg, ii)  __m128i reg;
-#define LOAD_data(  reg, ii)  reg = data[ii];
-#define STORE_data( reg, ii)  data[ii] = reg;
+#define LOAD_data_ii(ii)      LOAD_128(data + (ii))
+#define LOAD_data(  reg, ii)  reg = LOAD_data_ii(ii);
+#define STORE_data( reg, ii)  STORE_128(data + (ii), reg);
 #if (NUM_WAYS > 1)
-#define XOR_data_M1(reg, ii)  MM_XOR (reg, data[ii- 1])
+#define XOR_data_M1(reg, ii)  MM_XOR (reg, LOAD_128(data + (ii- 1)))
 #endif
 
 #define MM_OP_key(op, reg)  MM_OP(op, reg, key);
@@ -156,25 +179,22 @@ AES_FUNC_START2 (AesCbc_Encode_HW)
 #define AES_XOR(      reg, ii)   MM_OP_key (_mm_xor_si128,        reg)
 
 #define CTR_START(reg, ii)  MM_OP (_mm_add_epi64, ctr, one)  reg = ctr;
-#define CTR_END(  reg, ii)  MM_XOR (data[ii], reg)
-
+#define CTR_END(  reg, ii)  STORE_128(data + (ii), _mm_xor_si128(reg, \
+                            LOAD_128 (data + (ii))));
 #define WOP_KEY(op, n) { \
     const __m128i key = w[n]; \
-    WOP(op); }
-
+    WOP(op) }
 
 #define WIDE_LOOP_START  \
     dataEnd = data + numBlocks;  \
     if (numBlocks >= NUM_WAYS)  \
     { dataEnd -= NUM_WAYS; do {  \
 
-
 #define WIDE_LOOP_END  \
     data += NUM_WAYS;  \
     } while (data <= dataEnd);  \
     dataEnd += NUM_WAYS; }  \
 
-
 #define SINGLE_LOOP  \
     for (; data < dataEnd; data++)
 
@@ -184,54 +204,73 @@ AES_FUNC_START2 (AesCbc_Encode_HW)
 
 #define AVX_XOR(dest, src)    MM_OP(_mm256_xor_si256, dest, src)
 #define AVX_DECLARE_VAR(reg, ii)  __m256i reg;
-#define AVX_LOAD_data(  reg, ii)  reg = ((const __m256i *)(const void *)data)[ii];
-#define AVX_STORE_data( reg, ii)  ((__m256i *)(void *)data)[ii] = reg;
+
+#if 1
+// use unaligned AVX load/store for data.
+// It is required for our Aes functions, that data is aligned for 16-bytes.
+// But we need 32-bytes reading.
+// So we use intrinsics for unaligned AVX load/store.
+// notes for _mm256_storeu_si256:
+// msvc2022: uses vmovdqu and keeps the order of instruction sequence.
+// new gcc11 uses vmovdqu
+// old gcc9 could use pair of instructions:
+//   vmovups        %xmm7, -224(%rax)
+//   vextracti128   $0x1, %ymm7, -208(%rax)
+#define AVX_LOAD(p)         _mm256_loadu_si256((const __m256i *)(const void *)(p))
+#define AVX_STORE(p, _v)    _mm256_storeu_si256((__m256i *)(void *)(p), _v);
+#else
+// use aligned AVX load/store for data.
+// for debug: we can use this branch, if we are sure that data is aligned for 32-bytes.
+// msvc2022 uses vmovdqu still
+// gcc      uses vmovdqa (that requires 32-bytes alignment)
+#define AVX_LOAD(p)         (*(const __m256i *)(const void *)(p))
+#define AVX_STORE(p, _v)    (*(__m256i *)(void *)(p)) = _v;
+#endif
+
+#define AVX_LOAD_data(  reg, ii)  reg = AVX_LOAD((const __m256i *)(const void *)data + (ii));
+#define AVX_STORE_data( reg, ii)  AVX_STORE((__m256i *)(void *)data + (ii), reg)
 /*
-AVX_XOR_data_M1() needs unaligned memory load
-if (we don't use _mm256_loadu_si256() here)
-{
-  Most compilers with enabled optimizations generate fused AVX (LOAD + OP)
-  instruction that can load unaligned data.
-  But GCC and CLANG without -O2 or -O1 optimizations can generate separated
-  LOAD-ALIGNED (vmovdqa) instruction that will fail on execution.
-}
-Note: some compilers generate more instructions, if we use _mm256_loadu_si256() here.
-v23.02: we use _mm256_loadu_si256() here, because we need compatibility with any compiler.
+AVX_XOR_data_M1() needs unaligned memory load, even if (data)
+is aligned for 256-bits, because we read 32-bytes chunk that
+crosses (data) position: from (data - 16bytes) to (data + 16bytes).
 */
-#define AVX_XOR_data_M1(reg, ii)  AVX_XOR (reg, _mm256_loadu_si256(&(((const __m256i *)(const void *)(data - 1))[ii])))
-// for debug only: the following code will fail on execution, if compiled by some compilers:
-// #define AVX_XOR_data_M1(reg, ii)  AVX_XOR (reg, (((const __m256i *)(const void *)(data - 1))[ii]))
+#define AVX_XOR_data_M1(reg, ii)  AVX_XOR (reg, _mm256_loadu_si256((const __m256i *)(const void *)(data - 1) + (ii)))
 
 #define AVX_AES_DEC(      reg, ii)   MM_OP_key (_mm256_aesdec_epi128,     reg)
 #define AVX_AES_DEC_LAST( reg, ii)   MM_OP_key (_mm256_aesdeclast_epi128, reg)
 #define AVX_AES_ENC(      reg, ii)   MM_OP_key (_mm256_aesenc_epi128,     reg)
 #define AVX_AES_ENC_LAST( reg, ii)   MM_OP_key (_mm256_aesenclast_epi128, reg)
 #define AVX_AES_XOR(      reg, ii)   MM_OP_key (_mm256_xor_si256,         reg)
-#define AVX_CTR_START(reg, ii)  MM_OP (_mm256_add_epi64, ctr2, two)  reg = _mm256_xor_si256(ctr2, key);
-#define AVX_CTR_END(  reg, ii)  AVX_XOR (((__m256i *)(void *)data)[ii], reg)
+#define AVX_CTR_START(reg, ii)  \
+    MM_OP (_mm256_add_epi64, ctr2, two) \
+    reg = _mm256_xor_si256(ctr2, key);
+
+#define AVX_CTR_END(reg, ii)  \
+    AVX_STORE((__m256i *)(void *)data + (ii), _mm256_xor_si256(reg, \
+    AVX_LOAD ((__m256i *)(void *)data + (ii))));
+
 #define AVX_WOP_KEY(op, n) { \
     const __m256i key = w[n]; \
-    WOP(op); }
+    WOP(op) }
 
 #define NUM_AES_KEYS_MAX 15
 
 #define WIDE_LOOP_START_AVX(OP)  \
     dataEnd = data + numBlocks;  \
     if (numBlocks >= NUM_WAYS * 2)  \
-    { __m256i keys[NUM_AES_KEYS_MAX]; \
-    UInt32 ii; \
-    OP \
-    for (ii = 0; ii < numRounds; ii++) \
-      keys[ii] = _mm256_broadcastsi128_si256(p[ii]); \
-    dataEnd -= NUM_WAYS * 2; do {  \
-
+    { __m256i keys[NUM_AES_KEYS_MAX];  \
+      OP  \
+      { UInt32 ii; for (ii = 0; ii < numRounds; ii++)  \
+        keys[ii] = _mm256_broadcastsi128_si256(p[ii]); }  \
+      dataEnd -= NUM_WAYS * 2; \
+      do {  \
 
 #define WIDE_LOOP_END_AVX(OP)  \
-    data += NUM_WAYS * 2;  \
-    } while (data <= dataEnd);  \
-    dataEnd += NUM_WAYS * 2;  \
-    OP  \
-    _mm256_zeroupper();  \
+        data += NUM_WAYS * 2;  \
+      } while (data <= dataEnd);  \
+      dataEnd += NUM_WAYS * 2;  \
+      OP  \
+      _mm256_zeroupper();  \
     }  \
 
 /* MSVC for x86: If we don't call _mm256_zeroupper(), and -arch:IA32 is not specified,
@@ -246,21 +285,20 @@ AES_FUNC_START2 (AesCbc_Decode_HW)
   __m128i *p = (__m128i *)(void *)ivAes;
   __m128i *data = (__m128i *)(void *)data8;
   __m128i iv = *p;
-  const __m128i *wStart = p + *(const UInt32 *)(p + 1) * 2 + 2 - 1;
+  const __m128i * const wStart = p + (size_t)*(const UInt32 *)(p + 1) * 2 + 2 - 1;
   const __m128i *dataEnd;
   p += 2;
   
   WIDE_LOOP_START
   {
     const __m128i *w = wStart;
-    
     WOP (DECLARE_VAR)
     WOP (LOAD_data)
     WOP_KEY (AES_XOR, 1)
-
     do
     {
       WOP_KEY (AES_DEC, 0)
+
       w--;
     }
     while (w != p);
@@ -268,7 +306,7 @@ AES_FUNC_START2 (AesCbc_Decode_HW)
 
     MM_XOR (m0, iv)
     WOP_M1 (XOR_data_M1)
-    iv = data[NUM_WAYS - 1];
+    LOAD_data(iv, NUM_WAYS - 1)
     WOP (STORE_data)
   }
   WIDE_LOOP_END
@@ -276,7 +314,8 @@ AES_FUNC_START2 (AesCbc_Decode_HW)
   SINGLE_LOOP
   {
     const __m128i *w = wStart - 1;
-    __m128i m = _mm_xor_si128 (w[2], *data);
+    __m128i m = _mm_xor_si128 (w[2], LOAD_data_ii(0));
+    
     do
     {
       MM_OP_m (_mm_aesdec_si128, w[1])
@@ -286,10 +325,9 @@ AES_FUNC_START2 (AesCbc_Decode_HW)
     while (w != p);
     MM_OP_m (_mm_aesdec_si128,     w[1])
     MM_OP_m (_mm_aesdeclast_si128, w[0])
-
     MM_XOR (m, iv)
-    iv = *data;
-    *data = m;
+    LOAD_data(iv, 0)
+    STORE_data(m, 0)
   }
   
   p[-2] = iv;
@@ -301,9 +339,9 @@ AES_FUNC_START2 (AesCtr_Code_HW)
   __m128i *p = (__m128i *)(void *)ivAes;
   __m128i *data = (__m128i *)(void *)data8;
   __m128i ctr = *p;
-  UInt32 numRoundsMinus2 = *(const UInt32 *)(p + 1) * 2 - 1;
+  const UInt32 numRoundsMinus2 = *(const UInt32 *)(p + 1) * 2 - 1;
   const __m128i *dataEnd;
-  __m128i one = _mm_cvtsi32_si128(1);
+  const __m128i one = _mm_cvtsi32_si128(1);
 
   p += 2;
   
@@ -322,7 +360,6 @@ AES_FUNC_START2 (AesCtr_Code_HW)
     }
     while (--r);
     WOP_KEY (AES_ENC_LAST, 0)
-   
     WOP (CTR_END)
   }
   WIDE_LOOP_END
@@ -344,7 +381,7 @@ AES_FUNC_START2 (AesCtr_Code_HW)
     while (--numRounds2);
     MM_OP_m (_mm_aesenc_si128,     w[0])
     MM_OP_m (_mm_aesenclast_si128, w[1])
-    MM_XOR (*data, m)
+    CTR_END (m, 0)
   }
   
   p[-2] = ctr;
@@ -421,7 +458,7 @@ VAES_FUNC_START2 (AesCbc_Decode_HW_256)
   __m128i *data = (__m128i *)(void *)data8;
   __m128i iv = *p;
   const __m128i *dataEnd;
-  UInt32 numRounds = *(const UInt32 *)(p + 1) * 2 + 1;
+  const UInt32 numRounds = *(const UInt32 *)(p + 1) * 2 + 1;
   p += 2;
   
   WIDE_LOOP_START_AVX(;)
@@ -440,17 +477,17 @@ VAES_FUNC_START2 (AesCbc_Decode_HW_256)
     while (w != keys);
     AVX_WOP_KEY (AVX_AES_DEC_LAST, 0)
 
-    AVX_XOR (m0, _mm256_setr_m128i(iv, data[0]))
+    AVX_XOR (m0, _mm256_setr_m128i(iv, LOAD_data_ii(0)))
     WOP_M1 (AVX_XOR_data_M1)
-    iv = data[NUM_WAYS * 2 - 1];
+    LOAD_data (iv, NUM_WAYS * 2 - 1)
     WOP (AVX_STORE_data)
   }
   WIDE_LOOP_END_AVX(;)
 
   SINGLE_LOOP
   {
-    const __m128i *w = p + *(const UInt32 *)(p + 1 - 2) * 2 + 1 - 3;
-    __m128i m = _mm_xor_si128 (w[2], *data);
+    const __m128i *w = p - 2 + (size_t)*(const UInt32 *)(p + 1 - 2) * 2;
+    __m128i m = _mm_xor_si128 (w[2], LOAD_data_ii(0));
     do
     {
       MM_OP_m (_mm_aesdec_si128, w[1])
@@ -462,8 +499,8 @@ VAES_FUNC_START2 (AesCbc_Decode_HW_256)
     MM_OP_m (_mm_aesdeclast_si128, w[0])
 
     MM_XOR (m, iv)
-    iv = *data;
-    *data = m;
+    LOAD_data(iv, 0)
+    STORE_data(m, 0)
   }
   
   p[-2] = iv;
@@ -493,9 +530,9 @@ VAES_FUNC_START2 (AesCtr_Code_HW_256)
   __m128i *p = (__m128i *)(void *)ivAes;
   __m128i *data = (__m128i *)(void *)data8;
   __m128i ctr = *p;
-  UInt32 numRounds = *(const UInt32 *)(p + 1) * 2 + 1;
+  const UInt32 numRounds = *(const UInt32 *)(p + 1) * 2 + 1;
   const __m128i *dataEnd;
-  __m128i one = _mm_cvtsi32_si128(1);
+  const __m128i one = _mm_cvtsi32_si128(1);
   __m256i ctr2, two;
   p += 2;
   
@@ -536,7 +573,7 @@ VAES_FUNC_START2 (AesCtr_Code_HW_256)
     while (--numRounds2);
     MM_OP_m (_mm_aesenc_si128,     w[0])
     MM_OP_m (_mm_aesenclast_si128, w[1])
-    MM_XOR (*data, m)
+    CTR_END (m, 0)
   }
 
   p[-2] = ctr;
@@ -731,9 +768,14 @@ AES_FUNC_START (name)
 
 AES_FUNC_START2 (AesCbc_Encode_HW)
 {
-  v128 * const p = (v128*)(void*)ivAes;
-  v128 *data = (v128*)(void*)data8;
+  if (numBlocks == 0)
+    return;
+  {
+  v128 * const p = (v128 *)(void *)ivAes;
+  v128 *data = (v128 *)(void *)data8;
   v128 m = *p;
+  const UInt32 numRounds2 = *(const UInt32 *)(p + 1);
+  const v128 *w = p + (size_t)numRounds2 * 2;
   const v128 k0 = p[2];
   const v128 k1 = p[3];
   const v128 k2 = p[4];
@@ -744,11 +786,14 @@ AES_FUNC_START2 (AesCbc_Encode_HW)
   const v128 k7 = p[9];
   const v128 k8 = p[10];
   const v128 k9 = p[11];
-  const UInt32 numRounds2 = *(const UInt32 *)(p + 1);
-  const v128 *w = p + ((size_t)numRounds2 * 2);
+  const v128 k_z4 = w[-2];
+  const v128 k_z3 = w[-1];
+  const v128 k_z2 = w[0];
   const v128 k_z1 = w[1];
   const v128 k_z0 = w[2];
-  for (; numBlocks != 0; numBlocks--, data++)
+  // we don't use optimization veorq_u8(*data, k_z0) that can reduce one cycle,
+  // because gcc/clang compilers are not good for that optimization.
+  do
   {
     MM_XOR_m (*data)
     AES_E_MC_m (k0)
@@ -757,24 +802,26 @@ AES_FUNC_START2 (AesCbc_Encode_HW)
     AES_E_MC_m (k3)
     AES_E_MC_m (k4)
     AES_E_MC_m (k5)
-    AES_E_MC_m (k6)
-    AES_E_MC_m (k7)
-    AES_E_MC_m (k8)
     if (numRounds2 >= 6)
     {
-      AES_E_MC_m (k9)
-      AES_E_MC_m (p[12])
+      AES_E_MC_m (k6)
+      AES_E_MC_m (k7)
       if (numRounds2 != 6)
       {
-        AES_E_MC_m (p[13])
-        AES_E_MC_m (p[14])
+        AES_E_MC_m (k8)
+        AES_E_MC_m (k9)
       }
     }
-    AES_E_m  (k_z1)
-    MM_XOR_m (k_z0)
-    *data = m;
+    AES_E_MC_m (k_z4)
+    AES_E_MC_m (k_z3)
+    AES_E_MC_m (k_z2)
+    AES_E_m    (k_z1)
+    MM_XOR_m   (k_z0)
+    *data++ = m;
   }
+  while (--numBlocks);
   *p = m;
+  }
 }
 
 
@@ -834,10 +881,10 @@ AES_FUNC_START2 (AesCbc_Encode_HW)
 
 AES_FUNC_START2 (AesCbc_Decode_HW)
 {
-  v128 *p = (v128*)(void*)ivAes;
-  v128 *data = (v128*)(void*)data8;
+  v128 *p = (v128 *)(void *)ivAes;
+  v128 *data = (v128 *)(void *)data8;
   v128 iv = *p;
-  const v128 *wStart = p + ((size_t)*(const UInt32 *)(p + 1)) * 2;
+  const v128 * const wStart = p + (size_t)*(const UInt32 *)(p + 1) * 2;
   const v128 *dataEnd;
   p += 2;
   
@@ -858,7 +905,7 @@ AES_FUNC_START2 (AesCbc_Decode_HW)
     WOP_KEY (AES_XOR, 0)
     MM_XOR (m0, iv)
     WOP_M1 (XOR_data_M1)
-    iv = data[NUM_WAYS - 1];
+    LOAD_data(iv, NUM_WAYS - 1)
     WOP (STORE_data)
   }
   WIDE_LOOP_END
@@ -866,7 +913,7 @@ AES_FUNC_START2 (AesCbc_Decode_HW)
   SINGLE_LOOP
   {
     const v128 *w = wStart;
-    v128 m = *data;
+    v128 m;  LOAD_data(m, 0)
     AES_D_IMC_m (w[2])
     do
     {
@@ -878,8 +925,8 @@ AES_FUNC_START2 (AesCbc_Decode_HW)
     AES_D_m  (w[1])
     MM_XOR_m (w[0])
     MM_XOR_m (iv)
-    iv = *data;
-    *data = m;
+    LOAD_data(iv, 0)
+    STORE_data(m, 0)
   }
   
   p[-2] = iv;
@@ -888,19 +935,17 @@ AES_FUNC_START2 (AesCbc_Decode_HW)
 
 AES_FUNC_START2 (AesCtr_Code_HW)
 {
-  v128 *p = (v128*)(void*)ivAes;
-  v128 *data = (v128*)(void*)data8;
+  v128 *p = (v128 *)(void *)ivAes;
+  v128 *data = (v128 *)(void *)data8;
   uint64x2_t ctr = vreinterpretq_u64_u8(*p);
-  const v128 *wEnd = p + ((size_t)*(const UInt32 *)(p + 1)) * 2;
+  const v128 * const wEnd = p + (size_t)*(const UInt32 *)(p + 1) * 2;
   const v128 *dataEnd;
-  uint64x2_t one = vdupq_n_u64(0);
-
 // the bug in clang:
 // __builtin_neon_vsetq_lane_i64(__s0, (int8x16_t)__s1, __p2);
 #if defined(__clang__) && (__clang_major__ <= 9)
 #pragma GCC diagnostic ignored "-Wvector-conversion"
 #endif
-  one = vsetq_lane_u64(1, one, 0);
+  const uint64x2_t one = vsetq_lane_u64(1, vdupq_n_u64(0), 0);
   p += 2;
   
   WIDE_LOOP_START
diff --git a/C/CpuArch.c b/C/CpuArch.c
index e792f39..6e02551 100644
--- a/C/CpuArch.c
+++ b/C/CpuArch.c
@@ -1,5 +1,5 @@
 /* CpuArch.c -- CPU specific code
-2024-07-04 : Igor Pavlov : Public domain */
+Igor Pavlov : Public domain */
 
 #include "Precomp.h"
 
@@ -17,7 +17,7 @@
 /*
   cpuid instruction supports (subFunction) parameter in ECX,
   that is used only with some specific (function) parameter values.
-  But we always use only (subFunction==0).
+  most functions use only (subFunction==0).
 */
 /*
   __cpuid(): MSVC and GCC/CLANG use same function/macro name
@@ -49,43 +49,49 @@
 #if defined(MY_CPU_AMD64) && defined(__PIC__) \
     && ((defined (__GNUC__) && (__GNUC__ < 5)) || defined(__clang__))
 
-#define x86_cpuid_MACRO(p, func) { \
+  /* "=&r" selects free register. It can select even rbx, if that register is free.
+     "=&D" for (RDI) also works, but the code can be larger with "=&D"
+     "2"(subFun) : 2 is (zero-based) index in the output constraint list "=c" (ECX). */
+
+#define x86_cpuid_MACRO_2(p, func, subFunc) { \
   __asm__ __volatile__ ( \
     ASM_LN   "mov     %%rbx, %q1"  \
     ASM_LN   "cpuid"               \
     ASM_LN   "xchg    %%rbx, %q1"  \
-    : "=a" ((p)[0]), "=&r" ((p)[1]), "=c" ((p)[2]), "=d" ((p)[3]) : "0" (func), "2"(0)); }
-
-  /* "=&r" selects free register. It can select even rbx, if that register is free.
-     "=&D" for (RDI) also works, but the code can be larger with "=&D"
-     "2"(0) means (subFunction = 0),
-     2 is (zero-based) index in the output constraint list "=c" (ECX). */
+    : "=a" ((p)[0]), "=&r" ((p)[1]), "=c" ((p)[2]), "=d" ((p)[3]) : "0" (func), "2"(subFunc)); }
 
 #elif defined(MY_CPU_X86) && defined(__PIC__) \
     && ((defined (__GNUC__) && (__GNUC__ < 5)) || defined(__clang__))
 
-#define x86_cpuid_MACRO(p, func) { \
+#define x86_cpuid_MACRO_2(p, func, subFunc) { \
   __asm__ __volatile__ ( \
     ASM_LN   "mov     %%ebx, %k1"  \
     ASM_LN   "cpuid"               \
     ASM_LN   "xchg    %%ebx, %k1"  \
-    : "=a" ((p)[0]), "=&r" ((p)[1]), "=c" ((p)[2]), "=d" ((p)[3]) : "0" (func), "2"(0)); }
+    : "=a" ((p)[0]), "=&r" ((p)[1]), "=c" ((p)[2]), "=d" ((p)[3]) : "0" (func), "2"(subFunc)); }
 
 #else
 
-#define x86_cpuid_MACRO(p, func) { \
+#define x86_cpuid_MACRO_2(p, func, subFunc) { \
   __asm__ __volatile__ ( \
     ASM_LN   "cpuid"               \
-    : "=a" ((p)[0]), "=b" ((p)[1]), "=c" ((p)[2]), "=d" ((p)[3]) : "0" (func), "2"(0)); }
+    : "=a" ((p)[0]), "=b" ((p)[1]), "=c" ((p)[2]), "=d" ((p)[3]) : "0" (func), "2"(subFunc)); }
 
 #endif
 
+#define x86_cpuid_MACRO(p, func)  x86_cpuid_MACRO_2(p, func, 0)
 
 void Z7_FASTCALL z7_x86_cpuid(UInt32 p[4], UInt32 func)
 {
   x86_cpuid_MACRO(p, func)
 }
 
+static
+void Z7_FASTCALL z7_x86_cpuid_subFunc(UInt32 p[4], UInt32 func, UInt32 subFunc)
+{
+  x86_cpuid_MACRO_2(p, func, subFunc)
+}
+
 
 Z7_NO_INLINE
 UInt32 Z7_FASTCALL z7_x86_cpuid_GetMaxFunc(void)
@@ -205,11 +211,39 @@ void __declspec(naked) Z7_FASTCALL z7_x86_cpuid(UInt32 p[4], UInt32 func)
   __asm   ret     0
 }
 
+static
+void __declspec(naked) Z7_FASTCALL z7_x86_cpuid_subFunc(UInt32 p[4], UInt32 func, UInt32 subFunc)
+{
+  UNUSED_VAR(p)
+  UNUSED_VAR(func)
+  UNUSED_VAR(subFunc)
+  __asm   push    ebx
+  __asm   push    edi
+  __asm   mov     edi, ecx    // p
+  __asm   mov     eax, edx    // func
+  __asm   mov     ecx, [esp + 12]  // subFunc
+  __asm   cpuid
+  __asm   mov     [edi     ], eax
+  __asm   mov     [edi +  4], ebx
+  __asm   mov     [edi +  8], ecx
+  __asm   mov     [edi + 12], edx
+  __asm   pop     edi
+  __asm   pop     ebx
+  __asm   ret     4
+}
+
 #else // MY_CPU_AMD64
 
     #if _MSC_VER >= 1600
       #include <intrin.h>
       #define MY_cpuidex  __cpuidex
+
+static
+void Z7_FASTCALL z7_x86_cpuid_subFunc(UInt32 p[4], UInt32 func, UInt32 subFunc)
+{
+  __cpuidex((int *)p, func, subFunc);
+}
+
     #else
 /*
  __cpuid (func == (0 or 7)) requires subfunction number in ECX.
@@ -219,7 +253,7 @@ void __declspec(naked) Z7_FASTCALL z7_x86_cpuid(UInt32 p[4], UInt32 func)
  We still can use __cpuid for low (func) values that don't require ECX,
  but __cpuid() in old MSVC will be incorrect for some func values: (func == 7).
  So here we use the hack for old MSVC to send (subFunction) in ECX register to cpuid instruction,
- where ECX value is first parameter for FASTCALL / NO_INLINE func,
+ where ECX value is first parameter for FASTCALL / NO_INLINE func.
  So the caller of MY_cpuidex_HACK() sets ECX as subFunction, and
  old MSVC for __cpuid() doesn't change ECX and cpuid instruction gets (subFunction) value.
  
@@ -233,6 +267,11 @@ Z7_NO_INLINE void Z7_FASTCALL MY_cpuidex_HACK(Int32 subFunction, Int32 func, Int
 }
       #define MY_cpuidex(info, func, func2)  MY_cpuidex_HACK(func2, func, info)
       #pragma message("======== MY_cpuidex_HACK WAS USED ========")
+static
+void Z7_FASTCALL z7_x86_cpuid_subFunc(UInt32 p[4], UInt32 func, UInt32 subFunc)
+{
+  MY_cpuidex_HACK(subFunc, func, (Int32 *)p);
+}
     #endif // _MSC_VER >= 1600
 
 #if !defined(MY_CPU_AMD64)
@@ -445,6 +484,23 @@ BoolInt CPU_IsSupported_SHA(void)
   }
 }
 
+
+BoolInt CPU_IsSupported_SHA512(void)
+{
+  if (!CPU_IsSupported_AVX2()) return False; // maybe CPU_IsSupported_AVX() is enough here
+
+  if (z7_x86_cpuid_GetMaxFunc() < 7)
+    return False;
+  {
+    UInt32 d[4];
+    z7_x86_cpuid_subFunc(d, 7, 0);
+    if (d[0] < 1) // d[0] - is max supported subleaf value
+      return False;
+    z7_x86_cpuid_subFunc(d, 7, 1);
+    return (BoolInt)(d[0]) & 1;
+  }
+}
+
 /*
 MSVC: _xgetbv() intrinsic is available since VS2010SP1.
    MSVC also defines (_XCR_XFEATURE_ENABLED_MASK) macro in
@@ -776,6 +832,18 @@ BoolInt CPU_IsSupported_NEON(void)
   return z7_sysctlbyname_Get_BoolInt("hw.optional.neon");
 }
 
+BoolInt CPU_IsSupported_SHA512(void)
+{
+  return z7_sysctlbyname_Get_BoolInt("hw.optional.armv8_2_sha512");
+}
+
+/*
+BoolInt CPU_IsSupported_SHA3(void)
+{
+  return z7_sysctlbyname_Get_BoolInt("hw.optional.armv8_2_sha3");
+}
+*/
+
 #ifdef MY_CPU_ARM64
 #define APPLE_CRYPTO_SUPPORT_VAL 1
 #else
@@ -860,6 +928,19 @@ MY_HWCAP_CHECK_FUNC (CRC32)
 MY_HWCAP_CHECK_FUNC (SHA1)
 MY_HWCAP_CHECK_FUNC (SHA2)
 MY_HWCAP_CHECK_FUNC (AES)
+#ifdef MY_CPU_ARM64
+// <hwcap.h> supports HWCAP_SHA512 and HWCAP_SHA3 since 2017.
+// we define them here, if they are not defined
+#ifndef HWCAP_SHA3
+// #define HWCAP_SHA3    (1 << 17)
+#endif
+#ifndef HWCAP_SHA512
+// #pragma message("=== HWCAP_SHA512 define === ")
+#define HWCAP_SHA512  (1 << 21)
+#endif
+MY_HWCAP_CHECK_FUNC (SHA512)
+// MY_HWCAP_CHECK_FUNC (SHA3)
+#endif
 
 #endif // __APPLE__
 #endif // _WIN32
diff --git a/C/CpuArch.h b/C/CpuArch.h
index 683cfaa..a6297ea 100644
--- a/C/CpuArch.h
+++ b/C/CpuArch.h
@@ -1,5 +1,5 @@
 /* CpuArch.h -- CPU specific code
-2024-06-17 : Igor Pavlov : Public domain */
+Igor Pavlov : Public domain */
 
 #ifndef ZIP7_INC_CPU_ARCH_H
 #define ZIP7_INC_CPU_ARCH_H
@@ -509,11 +509,19 @@ problem-4 : performace:
 
 #if defined(MY_CPU_LE_UNALIGN) && defined(Z7_CPU_FAST_BSWAP_SUPPORTED)
 
+#if 0
+// Z7_BSWAP16 can be slow for x86-msvc
+#define GetBe16_to32(p)  (Z7_BSWAP16 (*(const UInt16 *)(const void *)(p)))
+#else
+#define GetBe16_to32(p)  (Z7_BSWAP32 (*(const UInt16 *)(const void *)(p)) >> 16)
+#endif
+
 #define GetBe32(p)  Z7_BSWAP32 (*(const UInt32 *)(const void *)(p))
 #define SetBe32(p, v) { (*(UInt32 *)(void *)(p)) = Z7_BSWAP32(v); }
 
 #if defined(MY_CPU_LE_UNALIGN_64)
 #define GetBe64(p)  Z7_BSWAP64 (*(const UInt64 *)(const void *)(p))
+#define SetBe64(p, v) { (*(UInt64 *)(void *)(p)) = Z7_BSWAP64(v); }
 #endif
 
 #else
@@ -536,11 +544,27 @@ problem-4 : performace:
 #define GetBe64(p) (((UInt64)GetBe32(p) << 32) | GetBe32(((const Byte *)(p)) + 4))
 #endif
 
+#ifndef SetBe64
+#define SetBe64(p, v) { Byte *_ppp_ = (Byte *)(p); UInt64 _vvv_ = (v); \
+    _ppp_[0] = (Byte)(_vvv_ >> 56); \
+    _ppp_[1] = (Byte)(_vvv_ >> 48); \
+    _ppp_[2] = (Byte)(_vvv_ >> 40); \
+    _ppp_[3] = (Byte)(_vvv_ >> 32); \
+    _ppp_[4] = (Byte)(_vvv_ >> 24); \
+    _ppp_[5] = (Byte)(_vvv_ >> 16); \
+    _ppp_[6] = (Byte)(_vvv_ >> 8); \
+    _ppp_[7] = (Byte)_vvv_; }
+#endif
+
 #ifndef GetBe16
+#ifdef GetBe16_to32
+#define GetBe16(p) ( (UInt16) GetBe16_to32(p))
+#else
 #define GetBe16(p) ( (UInt16) ( \
     ((UInt16)((const Byte *)(p))[0] << 8) | \
              ((const Byte *)(p))[1] ))
 #endif
+#endif
 
 
 #if defined(MY_CPU_BE)
@@ -589,6 +613,11 @@ problem-4 : performace:
 #endif
 
 
+#ifndef GetBe16_to32
+#define GetBe16_to32(p) GetBe16(p)
+#endif
+
+
 #if defined(MY_CPU_X86_OR_AMD64) \
   || defined(MY_CPU_ARM_OR_ARM64) \
   || defined(MY_CPU_PPC_OR_PPC64)
@@ -617,6 +646,7 @@ BoolInt CPU_IsSupported_SSE2(void);
 BoolInt CPU_IsSupported_SSSE3(void);
 BoolInt CPU_IsSupported_SSE41(void);
 BoolInt CPU_IsSupported_SHA(void);
+BoolInt CPU_IsSupported_SHA512(void);
 BoolInt CPU_IsSupported_PageGB(void);
 
 #elif defined(MY_CPU_ARM_OR_ARM64)
@@ -634,6 +664,7 @@ BoolInt CPU_IsSupported_SHA1(void);
 BoolInt CPU_IsSupported_SHA2(void);
 BoolInt CPU_IsSupported_AES(void);
 #endif
+BoolInt CPU_IsSupported_SHA512(void);
 
 #endif
 
diff --git a/C/LzmaEnc.c b/C/LzmaEnc.c
index 37b2787..088b78f 100644
--- a/C/LzmaEnc.c
+++ b/C/LzmaEnc.c
@@ -1,5 +1,5 @@
 /* LzmaEnc.c -- LZMA Encoder
-2024-01-24: Igor Pavlov : Public domain */
+Igor Pavlov : Public domain */
 
 #include "Precomp.h"
 
@@ -72,11 +72,11 @@ void LzmaEncProps_Normalize(CLzmaEncProps *p)
   p->level = level;
   
   if (p->dictSize == 0)
-    p->dictSize =
-      ( level <= 3 ? ((UInt32)1 << (level * 2 + 16)) :
-      ( level <= 6 ? ((UInt32)1 << (level + 19)) :
-      ( level <= 7 ? ((UInt32)1 << 25) : ((UInt32)1 << 26)
-      )));
+    p->dictSize = (unsigned)level <= 4 ?
+        (UInt32)1 << (level * 2 + 16) :
+        (unsigned)level <= sizeof(size_t) / 2 + 4 ?
+          (UInt32)1 << (level + 20) :
+          (UInt32)1 << (sizeof(size_t) / 2 + 24);
 
   if (p->dictSize > p->reduceSize)
   {
@@ -92,8 +92,8 @@ void LzmaEncProps_Normalize(CLzmaEncProps *p)
   if (p->lp < 0) p->lp = 0;
   if (p->pb < 0) p->pb = 2;
 
-  if (p->algo < 0) p->algo = (level < 5 ? 0 : 1);
-  if (p->fb < 0) p->fb = (level < 7 ? 32 : 64);
+  if (p->algo < 0) p->algo = (unsigned)level < 5 ? 0 : 1;
+  if (p->fb < 0) p->fb = (unsigned)level < 7 ? 32 : 64;
   if (p->btMode < 0) p->btMode = (p->algo == 0 ? 0 : 1);
   if (p->numHashBytes < 0) p->numHashBytes = (p->btMode ? 4 : 5);
   if (p->mc == 0) p->mc = (16 + ((unsigned)p->fb >> 1)) >> (p->btMode ? 0 : 1);
diff --git a/C/Md5.c b/C/Md5.c
new file mode 100644
index 0000000..1b745d7
--- /dev/null
+++ b/C/Md5.c
@@ -0,0 +1,206 @@
+/* Md5.c -- MD5 Hash
+: Igor Pavlov : Public domain
+This code is based on Colin Plumb's public domain md5.c code */
+
+#include "Precomp.h"
+
+#include <string.h>
+
+#include "Md5.h"
+#include "RotateDefs.h"
+#include "CpuArch.h"
+
+#define MD5_UPDATE_BLOCKS(p) Md5_UpdateBlocks
+
+Z7_NO_INLINE
+void Md5_Init(CMd5 *p)
+{
+  p->count = 0;
+  p->state[0] = 0x67452301;
+  p->state[1] = 0xefcdab89;
+  p->state[2] = 0x98badcfe;
+  p->state[3] = 0x10325476;
+}
+
+#if 0 && !defined(MY_CPU_LE_UNALIGN)
+// optional optimization for Big-endian processors or processors without unaligned access:
+// it is intended to reduce the number of complex LE32 memory reading from 64 to 16.
+// But some compilers (sparc, armt) are better without this optimization.
+#define Z7_MD5_USE_DATA32_ARRAY
+#endif
+
+#define LOAD_DATA(i)  GetUi32((const UInt32 *)(const void *)data + (i))
+
+#ifdef Z7_MD5_USE_DATA32_ARRAY
+#define D(i)  data32[i]
+#else
+#define D(i)  LOAD_DATA(i)
+#endif
+
+#define F1(x, y, z)   (z ^ (x & (y ^ z)))
+#define F2(x, y, z)   F1(z, x, y)
+#define F3(x, y, z)   (x ^ y ^ z)
+#define F4(x, y, z)   (y ^ (x | ~z))
+
+#define R1(i, f, start, step, w, x, y, z, s, k) \
+    w += D((start + step * (i)) % 16) + k; \
+    w += f(x, y, z); \
+    w = rotlFixed(w, s) + x; \
+
+#define R4(i4,  f, start, step, s0,s1,s2,s3, k0,k1,k2,k3) \
+    R1 (i4*4+0, f, start, step, a,b,c,d, s0, k0) \
+    R1 (i4*4+1, f, start, step, d,a,b,c, s1, k1) \
+    R1 (i4*4+2, f, start, step, c,d,a,b, s2, k2) \
+    R1 (i4*4+3, f, start, step, b,c,d,a, s3, k3) \
+
+#define R16(f, start, step, s0,s1,s2,s3, k00,k01,k02,k03, k10,k11,k12,k13, k20,k21,k22,k23, k30,k31,k32,k33)  \
+    R4 (0,  f, start, step, s0,s1,s2,s3, k00,k01,k02,k03) \
+    R4 (1,  f, start, step, s0,s1,s2,s3, k10,k11,k12,k13) \
+    R4 (2,  f, start, step, s0,s1,s2,s3, k20,k21,k22,k23) \
+    R4 (3,  f, start, step, s0,s1,s2,s3, k30,k31,k32,k33) \
+
+static
+Z7_NO_INLINE
+void Z7_FASTCALL Md5_UpdateBlocks(UInt32 state[4], const Byte *data, size_t numBlocks)
+{
+  UInt32 a, b, c, d;
+  // if (numBlocks == 0) return;
+  a = state[0];
+  b = state[1];
+  c = state[2];
+  d = state[3];
+  do
+  {
+#ifdef Z7_MD5_USE_DATA32_ARRAY
+    UInt32 data32[MD5_NUM_BLOCK_WORDS];
+    {
+#define LOAD_data32_x4(i) { \
+      data32[i    ] = LOAD_DATA(i    ); \
+      data32[i + 1] = LOAD_DATA(i + 1); \
+      data32[i + 2] = LOAD_DATA(i + 2); \
+      data32[i + 3] = LOAD_DATA(i + 3); }
+#if 1
+      LOAD_data32_x4 (0 * 4)
+      LOAD_data32_x4 (1 * 4)
+      LOAD_data32_x4 (2 * 4)
+      LOAD_data32_x4 (3 * 4)
+#else
+      unsigned i;
+      for (i = 0; i < MD5_NUM_BLOCK_WORDS; i += 4)
+      {
+        LOAD_data32_x4(i)
+      }
+#endif
+    }
+#endif
+
+    R16 (F1, 0, 1,  7,12,17,22, 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
+                                0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
+                                0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
+                                0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821)
+    R16 (F2, 1, 5,  5, 9,14,20, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
+                                0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
+                                0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
+                                0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a)
+    R16 (F3, 5, 3,  4,11,16,23, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
+                                0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
+                                0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
+                                0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665)
+    R16 (F4, 0, 7,  6,10,15,21, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
+                                0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
+                                0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
+                                0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391)
+
+    a += state[0];
+    b += state[1];
+    c += state[2];
+    d += state[3];
+    
+    state[0] = a;
+    state[1] = b;
+    state[2] = c;
+    state[3] = d;
+    
+    data += MD5_BLOCK_SIZE;
+  }
+  while (--numBlocks);
+}
+
+
+#define Md5_UpdateBlock(p) MD5_UPDATE_BLOCKS(p)(p->state, p->buffer, 1)
+
+void Md5_Update(CMd5 *p, const Byte *data, size_t size)
+{
+  if (size == 0)
+    return;
+  {
+    const unsigned pos = (unsigned)p->count & (MD5_BLOCK_SIZE - 1);
+    const unsigned num = MD5_BLOCK_SIZE - pos;
+    p->count += size;
+    if (num > size)
+    {
+      memcpy(p->buffer + pos, data, size);
+      return;
+    }
+    if (pos != 0)
+    {
+      size -= num;
+      memcpy(p->buffer + pos, data, num);
+      data += num;
+      Md5_UpdateBlock(p);
+    }
+  }
+  {
+    const size_t numBlocks = size >> 6;
+    if (numBlocks)
+    MD5_UPDATE_BLOCKS(p)(p->state, data, numBlocks);
+    size &= MD5_BLOCK_SIZE - 1;
+    if (size == 0)
+      return;
+    data += (numBlocks << 6);
+    memcpy(p->buffer, data, size);
+  }
+}
+
+
+void Md5_Final(CMd5 *p, Byte *digest)
+{
+  unsigned pos = (unsigned)p->count & (MD5_BLOCK_SIZE - 1);
+  p->buffer[pos++] = 0x80;
+  if (pos > (MD5_BLOCK_SIZE - 4 * 2))
+  {
+    while (pos != MD5_BLOCK_SIZE) { p->buffer[pos++] = 0; }
+    // memset(&p->buf.buffer[pos], 0, MD5_BLOCK_SIZE - pos);
+    Md5_UpdateBlock(p);
+    pos = 0;
+  }
+  memset(&p->buffer[pos], 0, (MD5_BLOCK_SIZE - 4 * 2) - pos);
+  {
+    const UInt64 numBits = p->count << 3;
+#if defined(MY_CPU_LE_UNALIGN)
+    SetUi64 (p->buffer + MD5_BLOCK_SIZE - 4 * 2, numBits)
+#else
+    SetUi32a(p->buffer + MD5_BLOCK_SIZE - 4 * 2, (UInt32)(numBits))
+    SetUi32a(p->buffer + MD5_BLOCK_SIZE - 4 * 1, (UInt32)(numBits >> 32))
+#endif
+  }
+  Md5_UpdateBlock(p);
+
+  SetUi32(digest,      p->state[0])
+  SetUi32(digest + 4,  p->state[1])
+  SetUi32(digest + 8,  p->state[2])
+  SetUi32(digest + 12, p->state[3])
+  
+  Md5_Init(p);
+}
+
+#undef R1
+#undef R4
+#undef R16
+#undef D
+#undef LOAD_DATA
+#undef LOAD_data32_x4
+#undef F1
+#undef F2
+#undef F3
+#undef F4
diff --git a/C/Md5.h b/C/Md5.h
new file mode 100644
index 0000000..49c0741
--- /dev/null
+++ b/C/Md5.h
@@ -0,0 +1,34 @@
+/* Md5.h -- MD5 Hash
+: Igor Pavlov : Public domain */
+
+#ifndef ZIP7_INC_MD5_H
+#define ZIP7_INC_MD5_H
+
+#include "7zTypes.h"
+
+EXTERN_C_BEGIN
+
+#define MD5_NUM_BLOCK_WORDS  16
+#define MD5_NUM_DIGEST_WORDS  4
+
+#define MD5_BLOCK_SIZE   (MD5_NUM_BLOCK_WORDS * 4)
+#define MD5_DIGEST_SIZE  (MD5_NUM_DIGEST_WORDS * 4)
+
+typedef struct
+{
+  UInt64 count;
+  UInt64 _pad_1;
+  // we want 16-bytes alignment here
+  UInt32 state[MD5_NUM_DIGEST_WORDS];
+  UInt64 _pad_2[4];
+  // we want 64-bytes alignment here
+  Byte buffer[MD5_BLOCK_SIZE];
+} CMd5;
+
+void Md5_Init(CMd5 *p);
+void Md5_Update(CMd5 *p, const Byte *data, size_t size);
+void Md5_Final(CMd5 *p, Byte *digest);
+
+EXTERN_C_END
+
+#endif
diff --git a/C/Sha1.c b/C/Sha1.c
index 4c92892..4ca21d7 100644
--- a/C/Sha1.c
+++ b/C/Sha1.c
@@ -1,18 +1,14 @@
 /* Sha1.c -- SHA-1 Hash
-2024-03-01 : Igor Pavlov : Public domain
+: Igor Pavlov : Public domain
 This code is based on public domain code of Steve Reid from Wei Dai's Crypto++ library. */
 
 #include "Precomp.h"
 
 #include <string.h>
 
-#include "CpuArch.h"
-#include "RotateDefs.h"
 #include "Sha1.h"
-
-#if defined(_MSC_VER) && (_MSC_VER < 1900)
-// #define USE_MY_MM
-#endif
+#include "RotateDefs.h"
+#include "CpuArch.h"
 
 #ifdef MY_CPU_X86_OR_AMD64
   #if   defined(Z7_LLVM_CLANG_VERSION)  && (Z7_LLVM_CLANG_VERSION  >= 30800) \
@@ -56,7 +52,7 @@ void Z7_FASTCALL Sha1_UpdateBlocks(UInt32 state[5], const Byte *data, size_t num
   static SHA1_FUNC_UPDATE_BLOCKS g_SHA1_FUNC_UPDATE_BLOCKS = Sha1_UpdateBlocks;
   static SHA1_FUNC_UPDATE_BLOCKS g_SHA1_FUNC_UPDATE_BLOCKS_HW;
 
-  #define SHA1_UPDATE_BLOCKS(p) p->func_UpdateBlocks
+  #define SHA1_UPDATE_BLOCKS(p) p->v.vars.func_UpdateBlocks
 #else
   #define SHA1_UPDATE_BLOCKS(p) Sha1_UpdateBlocks
 #endif
@@ -85,7 +81,7 @@ BoolInt Sha1_SetFunction(CSha1 *p, unsigned algo)
       return False;
   #endif
 
-  p->func_UpdateBlocks = func;
+  p->v.vars.func_UpdateBlocks = func;
   return True;
 }
 
@@ -225,7 +221,7 @@ BoolInt Sha1_SetFunction(CSha1 *p, unsigned algo)
 
 void Sha1_InitState(CSha1 *p)
 {
-  p->count = 0;
+  p->v.vars.count = 0;
   p->state[0] = 0x67452301;
   p->state[1] = 0xEFCDAB89;
   p->state[2] = 0x98BADCFE;
@@ -235,7 +231,7 @@ void Sha1_InitState(CSha1 *p)
 
 void Sha1_Init(CSha1 *p)
 {
-  p->func_UpdateBlocks =
+  p->v.vars.func_UpdateBlocks =
   #ifdef Z7_COMPILER_SHA1_SUPPORTED
       g_SHA1_FUNC_UPDATE_BLOCKS;
   #else
@@ -250,7 +246,7 @@ void Z7_FASTCALL Sha1_UpdateBlocks(UInt32 state[5], const Byte *data, size_t num
 {
   UInt32 a, b, c, d, e;
   UInt32 W[kNumW];
-  // if (numBlocks != 0x1264378347) return;
+
   if (numBlocks == 0)
     return;
 
@@ -283,7 +279,7 @@ void Z7_FASTCALL Sha1_UpdateBlocks(UInt32 state[5], const Byte *data, size_t num
   state[3] = d;
   state[4] = e;
 
-  data += 64;
+  data += SHA1_BLOCK_SIZE;
   }
   while (--numBlocks);
 }
@@ -295,20 +291,15 @@ void Sha1_Update(CSha1 *p, const Byte *data, size_t size)
 {
   if (size == 0)
     return;
-
   {
-    unsigned pos = (unsigned)p->count & 0x3F;
-    unsigned num;
-    
-    p->count += size;
-    
-    num = 64 - pos;
+    const unsigned pos = (unsigned)p->v.vars.count & (SHA1_BLOCK_SIZE - 1);
+    const unsigned num = SHA1_BLOCK_SIZE - pos;
+    p->v.vars.count += size;
     if (num > size)
     {
       memcpy(p->buffer + pos, data, size);
       return;
     }
-    
     if (pos != 0)
     {
       size -= num;
@@ -318,9 +309,10 @@ void Sha1_Update(CSha1 *p, const Byte *data, size_t size)
     }
   }
   {
-    size_t numBlocks = size >> 6;
+    const size_t numBlocks = size >> 6;
+    // if (numBlocks)
     SHA1_UPDATE_BLOCKS(p)(p->state, data, numBlocks);
-    size &= 0x3F;
+    size &= SHA1_BLOCK_SIZE - 1;
     if (size == 0)
       return;
     data += (numBlocks << 6);
@@ -331,42 +323,21 @@ void Sha1_Update(CSha1 *p, const Byte *data, size_t size)
 
 void Sha1_Final(CSha1 *p, Byte *digest)
 {
-  unsigned pos = (unsigned)p->count & 0x3F;
-  
-
+  unsigned pos = (unsigned)p->v.vars.count & (SHA1_BLOCK_SIZE - 1);
   p->buffer[pos++] = 0x80;
-  
-  if (pos > (64 - 8))
+  if (pos > (SHA1_BLOCK_SIZE - 4 * 2))
   {
-    while (pos != 64) { p->buffer[pos++] = 0; }
-    // memset(&p->buf.buffer[pos], 0, 64 - pos);
+    while (pos != SHA1_BLOCK_SIZE) { p->buffer[pos++] = 0; }
+    // memset(&p->buf.buffer[pos], 0, SHA1_BLOCK_SIZE - pos);
     Sha1_UpdateBlock(p);
     pos = 0;
   }
-
-  /*
-  if (pos & 3)
-  {
-    p->buffer[pos] = 0;
-    p->buffer[pos + 1] = 0;
-    p->buffer[pos + 2] = 0;
-    pos += 3;
-    pos &= ~3;
-  }
-  {
-    for (; pos < 64 - 8; pos += 4)
-      *(UInt32 *)(&p->buffer[pos]) = 0;
-  }
-  */
-
-  memset(&p->buffer[pos], 0, (64 - 8) - pos);
-
+  memset(&p->buffer[pos], 0, (SHA1_BLOCK_SIZE - 4 * 2) - pos);
   {
-    const UInt64 numBits = (p->count << 3);
-    SetBe32(p->buffer + 64 - 8, (UInt32)(numBits >> 32))
-    SetBe32(p->buffer + 64 - 4, (UInt32)(numBits))
+    const UInt64 numBits = p->v.vars.count << 3;
+    SetBe32(p->buffer + SHA1_BLOCK_SIZE - 4 * 2, (UInt32)(numBits >> 32))
+    SetBe32(p->buffer + SHA1_BLOCK_SIZE - 4 * 1, (UInt32)(numBits))
   }
-  
   Sha1_UpdateBlock(p);
 
   SetBe32(digest,      p->state[0])
@@ -375,16 +346,13 @@ void Sha1_Final(CSha1 *p, Byte *digest)
   SetBe32(digest + 12, p->state[3])
   SetBe32(digest + 16, p->state[4])
   
-
-
-
   Sha1_InitState(p);
 }
 
 
 void Sha1_PrepareBlock(const CSha1 *p, Byte *block, unsigned size)
 {
-  const UInt64 numBits = (p->count + size) << 3;
+  const UInt64 numBits = (p->v.vars.count + size) << 3;
   SetBe32(&((UInt32 *)(void *)block)[SHA1_NUM_BLOCK_WORDS - 2], (UInt32)(numBits >> 32))
   SetBe32(&((UInt32 *)(void *)block)[SHA1_NUM_BLOCK_WORDS - 1], (UInt32)(numBits))
   // SetBe32((UInt32 *)(block + size), 0x80000000);
@@ -420,57 +388,32 @@ void Sha1_GetBlockDigest(const CSha1 *p, const Byte *data, Byte *destDigest)
 
 void Sha1Prepare(void)
 {
-  #ifdef Z7_COMPILER_SHA1_SUPPORTED
+#ifdef Z7_COMPILER_SHA1_SUPPORTED
   SHA1_FUNC_UPDATE_BLOCKS f, f_hw;
   f = Sha1_UpdateBlocks;
   f_hw = NULL;
-  #ifdef MY_CPU_X86_OR_AMD64
-  #ifndef USE_MY_MM
+#ifdef MY_CPU_X86_OR_AMD64
   if (CPU_IsSupported_SHA()
       && CPU_IsSupported_SSSE3()
-      // && CPU_IsSupported_SSE41()
       )
-  #endif
-  #else
+#else
   if (CPU_IsSupported_SHA1())
-  #endif
+#endif
   {
     // printf("\n========== HW SHA1 ======== \n");
-    #if 0 && defined(MY_CPU_ARM_OR_ARM64) && defined(_MSC_VER)
+#if 1 && defined(MY_CPU_ARM_OR_ARM64) && defined(Z7_MSC_VER_ORIGINAL) && (_MSC_FULL_VER < 192930037)
     /* there was bug in MSVC compiler for ARM64 -O2 before version VS2019 16.10 (19.29.30037).
-       It generated incorrect SHA-1 code.
-       21.03 : we test sha1-hardware code at runtime initialization */
-
-      #pragma message("== SHA1 code: MSC compiler : failure-check code was inserted")
-
-      UInt32 state[5] = { 0, 1, 2, 3, 4 } ;
-      Byte data[64];
-      unsigned i;
-      for (i = 0; i < sizeof(data); i += 2)
-      {
-        data[i    ] = (Byte)(i);
-        data[i + 1] = (Byte)(i + 1);
-      }
-
-      Sha1_UpdateBlocks_HW(state, data, sizeof(data) / 64);
-    
-      if (   state[0] != 0x9acd7297
-          || state[1] != 0x4624d898
-          || state[2] != 0x0bf079f0
-          || state[3] != 0x031e61b3
-          || state[4] != 0x8323fe20)
-      {
-        // printf("\n========== SHA-1 hardware version failure ======== \n");
-      }
-      else
-    #endif
+       It generated incorrect SHA-1 code. */
+      #pragma message("== SHA1 code can work incorrectly with this compiler")
+      #error Stop_Compiling_MSC_Compiler_BUG_SHA1
+#endif
       {
         f = f_hw = Sha1_UpdateBlocks_HW;
       }
   }
   g_SHA1_FUNC_UPDATE_BLOCKS    = f;
   g_SHA1_FUNC_UPDATE_BLOCKS_HW = f_hw;
-  #endif
+#endif
 }
 
 #undef kNumW
diff --git a/C/Sha1.h b/C/Sha1.h
index fecd9d3..529be4d 100644
--- a/C/Sha1.h
+++ b/C/Sha1.h
@@ -1,5 +1,5 @@
 /* Sha1.h -- SHA-1 Hash
-2023-04-02 : Igor Pavlov : Public domain */
+: Igor Pavlov : Public domain */
 
 #ifndef ZIP7_INC_SHA1_H
 #define ZIP7_INC_SHA1_H
@@ -14,6 +14,9 @@ EXTERN_C_BEGIN
 #define SHA1_BLOCK_SIZE   (SHA1_NUM_BLOCK_WORDS * 4)
 #define SHA1_DIGEST_SIZE  (SHA1_NUM_DIGEST_WORDS * 4)
 
+
+
+
 typedef void (Z7_FASTCALL *SHA1_FUNC_UPDATE_BLOCKS)(UInt32 state[5], const Byte *data, size_t numBlocks);
 
 /*
@@ -32,9 +35,16 @@ typedef void (Z7_FASTCALL *SHA1_FUNC_UPDATE_BLOCKS)(UInt32 state[5], const Byte
 
 typedef struct
 {
-  SHA1_FUNC_UPDATE_BLOCKS func_UpdateBlocks;
-  UInt64 count;
-  UInt64 _pad_2[2];
+  union
+  {
+    struct
+    {
+      SHA1_FUNC_UPDATE_BLOCKS func_UpdateBlocks;
+      UInt64 count;
+    } vars;
+    UInt64 _pad_64bit[4];
+    void *_pad_align_ptr[2];
+  } v;
   UInt32 state[SHA1_NUM_DIGEST_WORDS];
   UInt32 _pad_3[3];
   Byte buffer[SHA1_BLOCK_SIZE];
diff --git a/C/Sha1Opt.c b/C/Sha1Opt.c
index 4e835f1..8738b94 100644
--- a/C/Sha1Opt.c
+++ b/C/Sha1Opt.c
@@ -1,18 +1,11 @@
 /* Sha1Opt.c -- SHA-1 optimized code for SHA-1 hardware instructions
-2024-03-01 : Igor Pavlov : Public domain */
+: Igor Pavlov : Public domain */
 
 #include "Precomp.h"
 #include "Compiler.h"
 #include "CpuArch.h"
 
-#if defined(_MSC_VER)
-#if (_MSC_VER < 1900) && (_MSC_VER >= 1200)
-// #define USE_MY_MM
-#endif
-#endif
-
 // #define Z7_USE_HW_SHA_STUB // for debug
-
 #ifdef MY_CPU_X86_OR_AMD64
   #if defined(__INTEL_COMPILER) && (__INTEL_COMPILER >= 1600) // fix that check
       #define USE_HW_SHA
@@ -20,19 +13,14 @@
      || defined(Z7_APPLE_CLANG_VERSION) && (Z7_APPLE_CLANG_VERSION >= 50100) \
      || defined(Z7_GCC_VERSION)         && (Z7_GCC_VERSION         >= 40900)
       #define USE_HW_SHA
-      #if !defined(_INTEL_COMPILER)
+      #if !defined(__INTEL_COMPILER)
       // icc defines __GNUC__, but icc doesn't support __attribute__(__target__)
       #if !defined(__SHA__) || !defined(__SSSE3__)
         #define ATTRIB_SHA __attribute__((__target__("sha,ssse3")))
       #endif
       #endif
   #elif defined(_MSC_VER)
-    #ifdef USE_MY_MM
-      #define USE_VER_MIN 1300
-    #else
-      #define USE_VER_MIN 1900
-    #endif
-    #if (_MSC_VER >= USE_VER_MIN)
+    #if (_MSC_VER >= 1900)
       #define USE_HW_SHA
     #else
       #define Z7_USE_HW_SHA_STUB
@@ -47,23 +35,20 @@
 
 // #pragma message("Sha1 HW")
 
+
+
+
 // sse/sse2/ssse3:
 #include <tmmintrin.h>
 // sha*:
 #include <immintrin.h>
 
 #if defined (__clang__) && defined(_MSC_VER)
-  // #if !defined(__SSSE3__)
-  // #endif
   #if !defined(__SHA__)
     #include <shaintrin.h>
   #endif
 #else
 
-#ifdef USE_MY_MM
-#include "My_mm.h"
-#endif
-
 #endif
 
 /*
@@ -84,7 +69,6 @@ SHA:
   _mm_sha1*
 */
 
-
 #define XOR_SI128(dest, src)      dest = _mm_xor_si128(dest, src);
 #define SHUFFLE_EPI8(dest, mask)  dest = _mm_shuffle_epi8(dest, mask);
 #define SHUFFLE_EPI32(dest, mask) dest = _mm_shuffle_epi32(dest, mask);
@@ -99,11 +83,12 @@ SHA:
 #define SHA1_MSG1(dest, src)      dest = _mm_sha1msg1_epu32(dest, src);
 #define SHA1_MSG2(dest, src)      dest = _mm_sha1msg2_epu32(dest, src);
 
-
 #define LOAD_SHUFFLE(m, k) \
     m = _mm_loadu_si128((const __m128i *)(const void *)(data + (k) * 16)); \
     SHUFFLE_EPI8(m, mask) \
 
+#define NNN(m0, m1, m2, m3)
+
 #define SM1(m0, m1, m2, m3) \
     SHA1_MSG1(m0, m1) \
 
@@ -116,35 +101,19 @@ SHA:
     SM1(m0, m1, m2, m3) \
     SHA1_MSG2(m3, m2) \
 
-#define NNN(m0, m1, m2, m3)
-
-
-
-
-
-
-
-
-
-
-
-
-
-
-
-
-
-#define R4(k, e0, e1, m0, m1, m2, m3, OP) \
+#define R4(k, m0, m1, m2, m3, e0, e1, OP) \
     e1 = abcd; \
     SHA1_RND4(abcd, e0, (k) / 5) \
     SHA1_NEXTE(e1, m1) \
     OP(m0, m1, m2, m3) \
 
+
+
 #define R16(k, mx, OP0, OP1, OP2, OP3) \
-    R4 ( (k)*4+0, e0,e1, m0,m1,m2,m3, OP0 ) \
-    R4 ( (k)*4+1, e1,e0, m1,m2,m3,m0, OP1 ) \
-    R4 ( (k)*4+2, e0,e1, m2,m3,m0,m1, OP2 ) \
-    R4 ( (k)*4+3, e1,e0, m3,mx,m1,m2, OP3 ) \
+    R4 ( (k)*4+0, m0,m1,m2,m3, e0,e1, OP0 ) \
+    R4 ( (k)*4+1, m1,m2,m3,m0, e1,e0, OP1 ) \
+    R4 ( (k)*4+2, m2,m3,m0,m1, e0,e1, OP2 ) \
+    R4 ( (k)*4+3, m3,mx,m1,m2, e1,e0, OP3 ) \
 
 #define PREPARE_STATE \
     SHUFFLE_EPI32 (abcd, 0x1B) \
@@ -162,8 +131,9 @@ void Z7_FASTCALL Sha1_UpdateBlocks_HW(UInt32 state[5], const Byte *data, size_t
 {
   const __m128i mask = _mm_set_epi32(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f);
 
-  __m128i abcd, e0;
   
+  __m128i abcd, e0;
+
   if (numBlocks == 0)
     return;
   
@@ -204,7 +174,7 @@ void Z7_FASTCALL Sha1_UpdateBlocks_HW(UInt32 state[5], const Byte *data, size_t
   PREPARE_STATE
 
   _mm_storeu_si128((__m128i *) (void *) state, abcd);
-  *(state+4) = (UInt32)_mm_cvtsi128_si32(e0);
+  *(state + 4) = (UInt32)_mm_cvtsi128_si32(e0);
 }
 
 #endif // USE_HW_SHA
@@ -262,22 +232,10 @@ void Z7_FASTCALL Sha1_UpdateBlocks_HW(UInt32 state[5], const Byte *data, size_t
   #define _ARM_USE_NEW_NEON_INTRINSICS
 #endif
 
-
-
-
-
 #if defined(Z7_MSC_VER_ORIGINAL) && defined(MY_CPU_ARM64)
 #include <arm64_neon.h>
 #else
 
-
-
-
-
-
-
-
-
 #if defined(__clang__) && __clang_major__ < 16
 #if !defined(__ARM_FEATURE_SHA2) && \
     !defined(__ARM_FEATURE_CRYPTO)
@@ -329,26 +287,37 @@ typedef uint32x4_t v128;
 #endif
 
 #ifdef MY_CPU_BE
-  #define MY_rev32_for_LE(x)
+  #define MY_rev32_for_LE(x) x
 #else
-  #define MY_rev32_for_LE(x) x = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(x)))
+  #define MY_rev32_for_LE(x) vrev32q_u8(x)
 #endif
 
-#define LOAD_128(_p)      (*(const v128 *)(const void *)(_p))
-#define STORE_128(_p, _v) *(v128 *)(void *)(_p) = (_v)
+#define LOAD_128_32(_p)       vld1q_u32(_p)
+#define LOAD_128_8(_p)        vld1q_u8 (_p)
+#define STORE_128_32(_p, _v)  vst1q_u32(_p, _v)
 
 #define LOAD_SHUFFLE(m, k) \
-    m = LOAD_128((data + (k) * 16)); \
-    MY_rev32_for_LE(m); \
-
-#define SU0(dest, src2, src3) dest = vsha1su0q_u32(dest, src2, src3)
-#define SU1(dest, src)        dest = vsha1su1q_u32(dest, src)
+    m = vreinterpretq_u32_u8( \
+        MY_rev32_for_LE( \
+        LOAD_128_8(data + (k) * 16))); \
+
+#define N0(dest, src2, src3)
+#define N1(dest, src)
+#define U0(dest, src2, src3)  dest = vsha1su0q_u32(dest, src2, src3);
+#define U1(dest, src)         dest = vsha1su1q_u32(dest, src);
 #define C(e)                  abcd = vsha1cq_u32(abcd, e, t)
 #define P(e)                  abcd = vsha1pq_u32(abcd, e, t)
 #define M(e)                  abcd = vsha1mq_u32(abcd, e, t)
 #define H(e)                  e = vsha1h_u32(vgetq_lane_u32(abcd, 0))
 #define T(m, c)               t = vaddq_u32(m, c)
 
+#define R16(d0,d1,d2,d3, f0,z0, f1,z1, f2,z2, f3,z3, w0,w1,w2,w3) \
+    T(m0, d0);  f0(m3, m0, m1)  z0(m2, m1)  H(e1);  w0(e0); \
+    T(m1, d1);  f1(m0, m1, m2)  z1(m3, m2)  H(e0);  w1(e1); \
+    T(m2, d2);  f2(m1, m2, m3)  z2(m0, m3)  H(e1);  w2(e0); \
+    T(m3, d3);  f3(m2, m3, m0)  z3(m1, m0)  H(e0);  w3(e1); \
+
+
 void Z7_FASTCALL Sha1_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_t numBlocks);
 #ifdef ATTRIB_SHA
 ATTRIB_SHA
@@ -367,7 +336,7 @@ void Z7_FASTCALL Sha1_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_t
   c2 = vdupq_n_u32(0x8f1bbcdc);
   c3 = vdupq_n_u32(0xca62c1d6);
 
-  abcd = LOAD_128(&state[0]);
+  abcd = LOAD_128_32(&state[0]);
   e0 = state[4];
   
   do
@@ -385,26 +354,11 @@ void Z7_FASTCALL Sha1_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_t
     LOAD_SHUFFLE (m2, 2)
     LOAD_SHUFFLE (m3, 3)
                      
-    T(m0, c0);                                  H(e1); C(e0);
-    T(m1, c0);  SU0(m0, m1, m2);                H(e0); C(e1);
-    T(m2, c0);  SU0(m1, m2, m3);  SU1(m0, m3);  H(e1); C(e0);
-    T(m3, c0);  SU0(m2, m3, m0);  SU1(m1, m0);  H(e0); C(e1);
-    T(m0, c0);  SU0(m3, m0, m1);  SU1(m2, m1);  H(e1); C(e0);
-    T(m1, c1);  SU0(m0, m1, m2);  SU1(m3, m2);  H(e0); P(e1);
-    T(m2, c1);  SU0(m1, m2, m3);  SU1(m0, m3);  H(e1); P(e0);
-    T(m3, c1);  SU0(m2, m3, m0);  SU1(m1, m0);  H(e0); P(e1);
-    T(m0, c1);  SU0(m3, m0, m1);  SU1(m2, m1);  H(e1); P(e0);
-    T(m1, c1);  SU0(m0, m1, m2);  SU1(m3, m2);  H(e0); P(e1);
-    T(m2, c2);  SU0(m1, m2, m3);  SU1(m0, m3);  H(e1); M(e0);
-    T(m3, c2);  SU0(m2, m3, m0);  SU1(m1, m0);  H(e0); M(e1);
-    T(m0, c2);  SU0(m3, m0, m1);  SU1(m2, m1);  H(e1); M(e0);
-    T(m1, c2);  SU0(m0, m1, m2);  SU1(m3, m2);  H(e0); M(e1);
-    T(m2, c2);  SU0(m1, m2, m3);  SU1(m0, m3);  H(e1); M(e0);
-    T(m3, c3);  SU0(m2, m3, m0);  SU1(m1, m0);  H(e0); P(e1);
-    T(m0, c3);  SU0(m3, m0, m1);  SU1(m2, m1);  H(e1); P(e0);
-    T(m1, c3);                    SU1(m3, m2);  H(e0); P(e1);
-    T(m2, c3);                                  H(e1); P(e0);
-    T(m3, c3);                                  H(e0); P(e1);
+    R16 ( c0,c0,c0,c0, N0,N1, U0,N1, U0,U1, U0,U1, C,C,C,C )
+    R16 ( c0,c1,c1,c1, U0,U1, U0,U1, U0,U1, U0,U1, C,P,P,P )
+    R16 ( c1,c1,c2,c2, U0,U1, U0,U1, U0,U1, U0,U1, P,P,M,M )
+    R16 ( c2,c2,c2,c3, U0,U1, U0,U1, U0,U1, U0,U1, M,M,M,P )
+    R16 ( c3,c3,c3,c3, U0,U1, N0,U1, N0,N1, N0,N1, P,P,P,P )
                                                                                                                      
     abcd = vaddq_u32(abcd, abcd_save);
     e0 += e0_save;
@@ -413,7 +367,7 @@ void Z7_FASTCALL Sha1_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_t
   }
   while (--numBlocks);
 
-  STORE_128(&state[0], abcd);
+  STORE_128_32(&state[0], abcd);
   state[4] = e0;
 }
 
@@ -421,13 +375,9 @@ void Z7_FASTCALL Sha1_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_t
 
 #endif // MY_CPU_ARM_OR_ARM64
 
-
 #if !defined(USE_HW_SHA) && defined(Z7_USE_HW_SHA_STUB)
 // #error Stop_Compiling_UNSUPPORTED_SHA
 // #include <stdlib.h>
-
-
-
 // #include "Sha1.h"
 // #if defined(_MSC_VER)
 #pragma message("Sha1   HW-SW stub was used")
@@ -447,8 +397,10 @@ void Z7_FASTCALL Sha1_UpdateBlocks_HW(UInt32 state[5], const Byte *data, size_t
 }
 #endif
 
-#undef SU0
-#undef SU1
+#undef U0
+#undef U1
+#undef N0
+#undef N1
 #undef C
 #undef P
 #undef M
diff --git a/C/Sha256.c b/C/Sha256.c
index 14d3be9..ea7ed8e 100644
--- a/C/Sha256.c
+++ b/C/Sha256.c
@@ -1,18 +1,14 @@
 /* Sha256.c -- SHA-256 Hash
-2024-03-01 : Igor Pavlov : Public domain
+: Igor Pavlov : Public domain
 This code is based on public domain code from Wei Dai's Crypto++ library. */
 
 #include "Precomp.h"
 
 #include <string.h>
 
-#include "CpuArch.h"
-#include "RotateDefs.h"
 #include "Sha256.h"
-
-#if defined(_MSC_VER) && (_MSC_VER < 1900)
-// #define USE_MY_MM
-#endif
+#include "RotateDefs.h"
+#include "CpuArch.h"
 
 #ifdef MY_CPU_X86_OR_AMD64
   #if   defined(Z7_LLVM_CLANG_VERSION)  && (Z7_LLVM_CLANG_VERSION  >= 30800) \
@@ -56,7 +52,7 @@ void Z7_FASTCALL Sha256_UpdateBlocks(UInt32 state[8], const Byte *data, size_t n
   static SHA256_FUNC_UPDATE_BLOCKS g_SHA256_FUNC_UPDATE_BLOCKS = Sha256_UpdateBlocks;
   static SHA256_FUNC_UPDATE_BLOCKS g_SHA256_FUNC_UPDATE_BLOCKS_HW;
 
-  #define SHA256_UPDATE_BLOCKS(p) p->func_UpdateBlocks
+  #define SHA256_UPDATE_BLOCKS(p) p->v.vars.func_UpdateBlocks
 #else
   #define SHA256_UPDATE_BLOCKS(p) Sha256_UpdateBlocks
 #endif
@@ -85,7 +81,7 @@ BoolInt Sha256_SetFunction(CSha256 *p, unsigned algo)
       return False;
   #endif
 
-  p->func_UpdateBlocks = func;
+  p->v.vars.func_UpdateBlocks = func;
   return True;
 }
 
@@ -111,7 +107,7 @@ BoolInt Sha256_SetFunction(CSha256 *p, unsigned algo)
 
 void Sha256_InitState(CSha256 *p)
 {
-  p->count = 0;
+  p->v.vars.count = 0;
   p->state[0] = 0x6a09e667;
   p->state[1] = 0xbb67ae85;
   p->state[2] = 0x3c6ef372;
@@ -122,9 +118,16 @@ void Sha256_InitState(CSha256 *p)
   p->state[7] = 0x5be0cd19;
 }
 
+
+
+
+
+
+
+
 void Sha256_Init(CSha256 *p)
 {
-  p->func_UpdateBlocks =
+  p->v.vars.func_UpdateBlocks =
   #ifdef Z7_COMPILER_SHA256_SUPPORTED
       g_SHA256_FUNC_UPDATE_BLOCKS;
   #else
@@ -133,10 +136,10 @@ void Sha256_Init(CSha256 *p)
   Sha256_InitState(p);
 }
 
-#define S0(x) (rotrFixed(x, 2) ^ rotrFixed(x,13) ^ rotrFixed(x, 22))
-#define S1(x) (rotrFixed(x, 6) ^ rotrFixed(x,11) ^ rotrFixed(x, 25))
+#define S0(x) (rotrFixed(x, 2) ^ rotrFixed(x,13) ^ rotrFixed(x,22))
+#define S1(x) (rotrFixed(x, 6) ^ rotrFixed(x,11) ^ rotrFixed(x,25))
 #define s0(x) (rotrFixed(x, 7) ^ rotrFixed(x,18) ^ (x >> 3))
-#define s1(x) (rotrFixed(x,17) ^ rotrFixed(x,19) ^ (x >> 10))
+#define s1(x) (rotrFixed(x,17) ^ rotrFixed(x,19) ^ (x >>10))
 
 #define Ch(x,y,z) (z^(x&(y^z)))
 #define Maj(x,y,z) ((x&y)|(z&(x|y)))
@@ -224,12 +227,10 @@ void Sha256_Init(CSha256 *p)
 
 #endif
 
-// static
-extern MY_ALIGN(64)
-const UInt32 SHA256_K_ARRAY[64];
 
-MY_ALIGN(64)
-const UInt32 SHA256_K_ARRAY[64] = {
+extern
+MY_ALIGN(64) const UInt32 SHA256_K_ARRAY[64];
+MY_ALIGN(64) const UInt32 SHA256_K_ARRAY[64] = {
   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
   0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
@@ -248,27 +249,29 @@ const UInt32 SHA256_K_ARRAY[64] = {
   0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
 };
 
-#define K SHA256_K_ARRAY
 
 
+
+
+#define K SHA256_K_ARRAY
+
 Z7_NO_INLINE
 void Z7_FASTCALL Sha256_UpdateBlocks(UInt32 state[8], const Byte *data, size_t numBlocks)
 {
   UInt32 W
-  #ifdef Z7_SHA256_BIG_W
+#ifdef Z7_SHA256_BIG_W
       [64];
-  #else
+#else
       [16];
-  #endif
-
+#endif
   unsigned j;
-
   UInt32 a,b,c,d,e,f,g,h;
-
-  #if !defined(Z7_SHA256_UNROLL) || (STEP_MAIN <= 4) || (STEP_PRE <= 4)
+#if !defined(Z7_SHA256_UNROLL) || (STEP_MAIN <= 4) || (STEP_PRE <= 4)
   UInt32 tmp;
-  #endif
+#endif
   
+  if (numBlocks == 0) return;
+
   a = state[0];
   b = state[1];
   c = state[2];
@@ -278,7 +281,7 @@ void Z7_FASTCALL Sha256_UpdateBlocks(UInt32 state[8], const Byte *data, size_t n
   g = state[6];
   h = state[7];
 
-  while (numBlocks)
+  do
   {
 
   for (j = 0; j < 16; j += STEP_PRE)
@@ -352,19 +355,11 @@ void Z7_FASTCALL Sha256_UpdateBlocks(UInt32 state[8], const Byte *data, size_t n
   g += state[6]; state[6] = g;
   h += state[7]; state[7] = h;
 
-  data += 64;
-  numBlocks--;
+  data += SHA256_BLOCK_SIZE;
   }
-
-  /* Wipe variables */
-  /* memset(W, 0, sizeof(W)); */
+  while (--numBlocks);
 }
 
-#undef S0
-#undef S1
-#undef s0
-#undef s1
-#undef K
 
 #define Sha256_UpdateBlock(p) SHA256_UPDATE_BLOCKS(p)(p->state, p->buffer, 1)
 
@@ -372,20 +367,15 @@ void Sha256_Update(CSha256 *p, const Byte *data, size_t size)
 {
   if (size == 0)
     return;
-
   {
-    unsigned pos = (unsigned)p->count & 0x3F;
-    unsigned num;
-    
-    p->count += size;
-    
-    num = 64 - pos;
+    const unsigned pos = (unsigned)p->v.vars.count & (SHA256_BLOCK_SIZE - 1);
+    const unsigned num = SHA256_BLOCK_SIZE - pos;
+    p->v.vars.count += size;
     if (num > size)
     {
       memcpy(p->buffer + pos, data, size);
       return;
     }
-    
     if (pos != 0)
     {
       size -= num;
@@ -395,9 +385,10 @@ void Sha256_Update(CSha256 *p, const Byte *data, size_t size)
     }
   }
   {
-    size_t numBlocks = size >> 6;
+    const size_t numBlocks = size >> 6;
+    // if (numBlocks)
     SHA256_UPDATE_BLOCKS(p)(p->state, data, numBlocks);
-    size &= 0x3F;
+    size &= SHA256_BLOCK_SIZE - 1;
     if (size == 0)
       return;
     data += (numBlocks << 6);
@@ -408,82 +399,69 @@ void Sha256_Update(CSha256 *p, const Byte *data, size_t size)
 
 void Sha256_Final(CSha256 *p, Byte *digest)
 {
-  unsigned pos = (unsigned)p->count & 0x3F;
-  unsigned i;
-  
+  unsigned pos = (unsigned)p->v.vars.count & (SHA256_BLOCK_SIZE - 1);
   p->buffer[pos++] = 0x80;
-  
-  if (pos > (64 - 8))
+  if (pos > (SHA256_BLOCK_SIZE - 4 * 2))
   {
-    while (pos != 64) { p->buffer[pos++] = 0; }
-    // memset(&p->buf.buffer[pos], 0, 64 - pos);
+    while (pos != SHA256_BLOCK_SIZE) { p->buffer[pos++] = 0; }
+    // memset(&p->buf.buffer[pos], 0, SHA256_BLOCK_SIZE - pos);
     Sha256_UpdateBlock(p);
     pos = 0;
   }
-
-  /*
-  if (pos & 3)
+  memset(&p->buffer[pos], 0, (SHA256_BLOCK_SIZE - 4 * 2) - pos);
   {
-    p->buffer[pos] = 0;
-    p->buffer[pos + 1] = 0;
-    p->buffer[pos + 2] = 0;
-    pos += 3;
-    pos &= ~3;
+    const UInt64 numBits = p->v.vars.count << 3;
+    SetBe32(p->buffer + SHA256_BLOCK_SIZE - 4 * 2, (UInt32)(numBits >> 32))
+    SetBe32(p->buffer + SHA256_BLOCK_SIZE - 4 * 1, (UInt32)(numBits))
   }
+  Sha256_UpdateBlock(p);
+#if 1 && defined(MY_CPU_BE)
+  memcpy(digest, p->state, SHA256_DIGEST_SIZE);
+#else
   {
-    for (; pos < 64 - 8; pos += 4)
-      *(UInt32 *)(&p->buffer[pos]) = 0;
+    unsigned i;
+    for (i = 0; i < 8; i += 2)
+    {
+      const UInt32 v0 = p->state[i];
+      const UInt32 v1 = p->state[(size_t)i + 1];
+      SetBe32(digest    , v0)
+      SetBe32(digest + 4, v1)
+      digest += 4 * 2;
+    }
   }
-  */
 
-  memset(&p->buffer[pos], 0, (64 - 8) - pos);
 
-  {
-    UInt64 numBits = (p->count << 3);
-    SetBe32(p->buffer + 64 - 8, (UInt32)(numBits >> 32))
-    SetBe32(p->buffer + 64 - 4, (UInt32)(numBits))
-  }
-  
-  Sha256_UpdateBlock(p);
 
-  for (i = 0; i < 8; i += 2)
-  {
-    UInt32 v0 = p->state[i];
-    UInt32 v1 = p->state[(size_t)i + 1];
-    SetBe32(digest    , v0)
-    SetBe32(digest + 4, v1)
-    digest += 8;
-  }
-  
+
+#endif
   Sha256_InitState(p);
 }
 
 
 void Sha256Prepare(void)
 {
-  #ifdef Z7_COMPILER_SHA256_SUPPORTED
+#ifdef Z7_COMPILER_SHA256_SUPPORTED
   SHA256_FUNC_UPDATE_BLOCKS f, f_hw;
   f = Sha256_UpdateBlocks;
   f_hw = NULL;
-  #ifdef MY_CPU_X86_OR_AMD64
-  #ifndef USE_MY_MM
+#ifdef MY_CPU_X86_OR_AMD64
   if (CPU_IsSupported_SHA()
       && CPU_IsSupported_SSSE3()
-      // && CPU_IsSupported_SSE41()
       )
-  #endif
-  #else
+#else
   if (CPU_IsSupported_SHA2())
-  #endif
+#endif
   {
     // printf("\n========== HW SHA256 ======== \n");
     f = f_hw = Sha256_UpdateBlocks_HW;
   }
   g_SHA256_FUNC_UPDATE_BLOCKS    = f;
   g_SHA256_FUNC_UPDATE_BLOCKS_HW = f_hw;
-  #endif
+#endif
 }
 
+#undef U64C
+#undef K
 #undef S0
 #undef S1
 #undef s0
diff --git a/C/Sha256.h b/C/Sha256.h
index 9e04223..75329cd 100644
--- a/C/Sha256.h
+++ b/C/Sha256.h
@@ -1,5 +1,5 @@
 /* Sha256.h -- SHA-256 Hash
-2023-04-02 : Igor Pavlov : Public domain */
+: Igor Pavlov : Public domain */
 
 #ifndef ZIP7_INC_SHA256_H
 #define ZIP7_INC_SHA256_H
@@ -14,6 +14,9 @@ EXTERN_C_BEGIN
 #define SHA256_BLOCK_SIZE   (SHA256_NUM_BLOCK_WORDS * 4)
 #define SHA256_DIGEST_SIZE  (SHA256_NUM_DIGEST_WORDS * 4)
 
+
+
+
 typedef void (Z7_FASTCALL *SHA256_FUNC_UPDATE_BLOCKS)(UInt32 state[8], const Byte *data, size_t numBlocks);
 
 /*
@@ -32,9 +35,16 @@ typedef void (Z7_FASTCALL *SHA256_FUNC_UPDATE_BLOCKS)(UInt32 state[8], const Byt
 
 typedef struct
 {
-  SHA256_FUNC_UPDATE_BLOCKS func_UpdateBlocks;
-  UInt64 count;
-  UInt64 _pad_2[2];
+  union
+  {
+    struct
+    {
+      SHA256_FUNC_UPDATE_BLOCKS func_UpdateBlocks;
+      UInt64 count;
+    } vars;
+    UInt64 _pad_64bit[4];
+    void *_pad_align_ptr[2];
+  } v;
   UInt32 state[SHA256_NUM_DIGEST_WORDS];
 
   Byte buffer[SHA256_BLOCK_SIZE];
diff --git a/C/Sha256Opt.c b/C/Sha256Opt.c
index eb38166..1c6b50f 100644
--- a/C/Sha256Opt.c
+++ b/C/Sha256Opt.c
@@ -1,18 +1,11 @@
 /* Sha256Opt.c -- SHA-256 optimized code for SHA-256 hardware instructions
-2024-03-01 : Igor Pavlov : Public domain */
+: Igor Pavlov : Public domain */
 
 #include "Precomp.h"
 #include "Compiler.h"
 #include "CpuArch.h"
 
-#if defined(_MSC_VER)
-#if (_MSC_VER < 1900) && (_MSC_VER >= 1200)
-// #define USE_MY_MM
-#endif
-#endif
-
 // #define Z7_USE_HW_SHA_STUB // for debug
-
 #ifdef MY_CPU_X86_OR_AMD64
   #if defined(__INTEL_COMPILER) && (__INTEL_COMPILER >= 1600) // fix that check
       #define USE_HW_SHA
@@ -20,19 +13,14 @@
      || defined(Z7_APPLE_CLANG_VERSION) && (Z7_APPLE_CLANG_VERSION >= 50100) \
      || defined(Z7_GCC_VERSION)         && (Z7_GCC_VERSION         >= 40900)
       #define USE_HW_SHA
-      #if !defined(_INTEL_COMPILER)
+      #if !defined(__INTEL_COMPILER)
       // icc defines __GNUC__, but icc doesn't support __attribute__(__target__)
       #if !defined(__SHA__) || !defined(__SSSE3__)
         #define ATTRIB_SHA __attribute__((__target__("sha,ssse3")))
       #endif
       #endif
   #elif defined(_MSC_VER)
-    #ifdef USE_MY_MM
-      #define USE_VER_MIN 1300
-    #else
-      #define USE_VER_MIN 1900
-    #endif
-    #if (_MSC_VER >= USE_VER_MIN)
+    #if (_MSC_VER >= 1900)
       #define USE_HW_SHA
     #else
       #define Z7_USE_HW_SHA_STUB
@@ -47,23 +35,20 @@
 
 // #pragma message("Sha256 HW")
 
+
+
+
 // sse/sse2/ssse3:
 #include <tmmintrin.h>
 // sha*:
 #include <immintrin.h>
 
 #if defined (__clang__) && defined(_MSC_VER)
-  // #if !defined(__SSSE3__)
-  // #endif
   #if !defined(__SHA__)
     #include <shaintrin.h>
   #endif
 #else
 
-#ifdef USE_MY_MM
-#include "My_mm.h"
-#endif
-
 #endif
 
 /*
@@ -91,60 +76,44 @@ SHA:
 extern
 MY_ALIGN(64)
 const UInt32 SHA256_K_ARRAY[64];
-
 #define K SHA256_K_ARRAY
 
 
 #define ADD_EPI32(dest, src)      dest = _mm_add_epi32(dest, src);
 #define SHA256_MSG1(dest, src)    dest = _mm_sha256msg1_epu32(dest, src);
-#define SHA25G_MSG2(dest, src)    dest = _mm_sha256msg2_epu32(dest, src);
-
+#define SHA256_MSG2(dest, src)    dest = _mm_sha256msg2_epu32(dest, src);
 
 #define LOAD_SHUFFLE(m, k) \
     m = _mm_loadu_si128((const __m128i *)(const void *)(data + (k) * 16)); \
     m = _mm_shuffle_epi8(m, mask); \
 
-#define SM1(g0, g1, g2, g3) \
-    SHA256_MSG1(g3, g0); \
+#define NNN(m0, m1, m2, m3)
 
-#define SM2(g0, g1, g2, g3) \
-    tmp = _mm_alignr_epi8(g1, g0, 4); \
-    ADD_EPI32(g2, tmp) \
-    SHA25G_MSG2(g2, g1); \
-
-// #define LS0(k, g0, g1, g2, g3) LOAD_SHUFFLE(g0, k)
-// #define LS1(k, g0, g1, g2, g3) LOAD_SHUFFLE(g1, k+1)
-
-
-#define NNN(g0, g1, g2, g3)
+#define SM1(m1, m2, m3, m0) \
+    SHA256_MSG1(m0, m1); \
 
+#define SM2(m2, m3, m0, m1) \
+    ADD_EPI32(m0, _mm_alignr_epi8(m3, m2, 4)) \
+    SHA256_MSG2(m0, m3); \
 
 #define RND2(t0, t1) \
     t0 = _mm_sha256rnds2_epu32(t0, t1, msg);
 
-#define RND2_0(m, k) \
-    msg = _mm_add_epi32(m, *(const __m128i *) (const void *) &K[(k) * 4]); \
-    RND2(state0, state1); \
-    msg = _mm_shuffle_epi32(msg, 0x0E); \
 
 
-#define RND2_1 \
+#define R4(k, m0, m1, m2, m3, OP0, OP1) \
+    msg = _mm_add_epi32(m0, *(const __m128i *) (const void *) &K[(k) * 4]); \
+    RND2(state0, state1); \
+    msg = _mm_shuffle_epi32(msg, 0x0E); \
+    OP0(m0, m1, m2, m3) \
     RND2(state1, state0); \
-
-
-// We use scheme with 3 rounds ahead for SHA256_MSG1 / 2 rounds ahead for SHA256_MSG2
-
-#define R4(k, g0, g1, g2, g3, OP0, OP1) \
-    RND2_0(g0, k) \
-    OP0(g0, g1, g2, g3) \
-    RND2_1 \
-    OP1(g0, g1, g2, g3) \
+    OP1(m0, m1, m2, m3) \
 
 #define R16(k, OP0, OP1, OP2, OP3, OP4, OP5, OP6, OP7) \
-    R4 ( (k)*4+0,        m0,m1,m2,m3, OP0, OP1 ) \
-    R4 ( (k)*4+1,        m1,m2,m3,m0, OP2, OP3 ) \
-    R4 ( (k)*4+2,        m2,m3,m0,m1, OP4, OP5 ) \
-    R4 ( (k)*4+3,        m3,m0,m1,m2, OP6, OP7 ) \
+    R4 ( (k)*4+0, m0,m1,m2,m3, OP0, OP1 ) \
+    R4 ( (k)*4+1, m1,m2,m3,m0, OP2, OP3 ) \
+    R4 ( (k)*4+2, m2,m3,m0,m1, OP4, OP5 ) \
+    R4 ( (k)*4+3, m3,m0,m1,m2, OP6, OP7 ) \
 
 #define PREPARE_STATE \
     tmp    = _mm_shuffle_epi32(state0, 0x1B); /* abcd */ \
@@ -161,8 +130,9 @@ ATTRIB_SHA
 void Z7_FASTCALL Sha256_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_t numBlocks)
 {
   const __m128i mask = _mm_set_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203);
-  __m128i tmp;
-  __m128i state0, state1;
+   
+  
+  __m128i tmp, state0, state1;
 
   if (numBlocks == 0)
     return;
@@ -262,22 +232,10 @@ void Z7_FASTCALL Sha256_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_
   #define _ARM_USE_NEW_NEON_INTRINSICS
 #endif
 
-
-
-
-
 #if defined(Z7_MSC_VER_ORIGINAL) && defined(MY_CPU_ARM64)
 #include <arm64_neon.h>
 #else
 
-
-
-
-
-
-
-
-
 #if defined(__clang__) && __clang_major__ < 16
 #if !defined(__ARM_FEATURE_SHA2) && \
     !defined(__ARM_FEATURE_CRYPTO)
@@ -324,41 +282,70 @@ typedef uint32x4_t v128;
 // typedef __n128 v128; // MSVC
 
 #ifdef MY_CPU_BE
-  #define MY_rev32_for_LE(x)
+  #define MY_rev32_for_LE(x) x
 #else
-  #define MY_rev32_for_LE(x) x = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(x)))
+  #define MY_rev32_for_LE(x) vrev32q_u8(x)
 #endif
 
-#define LOAD_128(_p)      (*(const v128 *)(const void *)(_p))
-#define STORE_128(_p, _v) *(v128 *)(void *)(_p) = (_v)
+#if 1 // 0 for debug
+// for arm32: it works slower by some reason than direct code
+/*
+for arm32 it generates:
+MSVC-2022, GCC-9:
+    vld1.32 {d18,d19}, [r10]
+    vst1.32 {d4,d5}, [r3]
+    vld1.8  {d20-d21}, [r4]
+there is no align hint (like [r10:128]).  So instruction allows unaligned access
+*/
+#define LOAD_128_32(_p)       vld1q_u32(_p)
+#define LOAD_128_8(_p)        vld1q_u8 (_p)
+#define STORE_128_32(_p, _v)  vst1q_u32(_p, _v)
+#else
+/*
+for arm32:
+MSVC-2022:
+    vldm r10,{d18,d19}
+    vstm r3,{d4,d5}
+    does it require strict alignment?
+GCC-9:
+    vld1.64 {d30-d31}, [r0:64]
+    vldr  d28, [r0, #16]
+    vldr  d29, [r0, #24]
+    vst1.64 {d30-d31}, [r0:64]
+    vstr  d28, [r0, #16]
+    vstr  d29, [r0, #24]
+there is hint [r0:64], so does it requires 64-bit alignment.
+*/
+#define LOAD_128_32(_p)       (*(const v128 *)(const void *)(_p))
+#define LOAD_128_8(_p)        vreinterpretq_u8_u32(*(const v128 *)(const void *)(_p))
+#define STORE_128_32(_p, _v)  *(v128 *)(void *)(_p) = (_v)
+#endif
 
 #define LOAD_SHUFFLE(m, k) \
-    m = LOAD_128((data + (k) * 16)); \
-    MY_rev32_for_LE(m); \
+    m = vreinterpretq_u32_u8( \
+        MY_rev32_for_LE( \
+        LOAD_128_8(data + (k) * 16))); \
 
 // K array must be aligned for 16-bytes at least.
 extern
 MY_ALIGN(64)
 const UInt32 SHA256_K_ARRAY[64];
-
 #define K SHA256_K_ARRAY
 
-
 #define SHA256_SU0(dest, src)        dest = vsha256su0q_u32(dest, src);
-#define SHA25G_SU1(dest, src2, src3) dest = vsha256su1q_u32(dest, src2, src3);
+#define SHA256_SU1(dest, src2, src3) dest = vsha256su1q_u32(dest, src2, src3);
 
-#define SM1(g0, g1, g2, g3)  SHA256_SU0(g3, g0)
-#define SM2(g0, g1, g2, g3)  SHA25G_SU1(g2, g0, g1)
-#define NNN(g0, g1, g2, g3)
+#define SM1(m0, m1, m2, m3)  SHA256_SU0(m3, m0)
+#define SM2(m0, m1, m2, m3)  SHA256_SU1(m2, m0, m1)
+#define NNN(m0, m1, m2, m3)
 
-
-#define R4(k, g0, g1, g2, g3, OP0, OP1) \
-    msg = vaddq_u32(g0, *(const v128 *) (const void *) &K[(k) * 4]); \
+#define R4(k, m0, m1, m2, m3, OP0, OP1) \
+    msg = vaddq_u32(m0, *(const v128 *) (const void *) &K[(k) * 4]); \
     tmp = state0; \
     state0 = vsha256hq_u32( state0, state1, msg ); \
     state1 = vsha256h2q_u32( state1, tmp, msg ); \
-    OP0(g0, g1, g2, g3); \
-    OP1(g0, g1, g2, g3); \
+    OP0(m0, m1, m2, m3); \
+    OP1(m0, m1, m2, m3); \
 
 
 #define R16(k, OP0, OP1, OP2, OP3, OP4, OP5, OP6, OP7) \
@@ -379,8 +366,8 @@ void Z7_FASTCALL Sha256_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_
   if (numBlocks == 0)
     return;
 
-  state0 = LOAD_128(&state[0]);
-  state1 = LOAD_128(&state[4]);
+  state0 = LOAD_128_32(&state[0]);
+  state1 = LOAD_128_32(&state[4]);
   
   do
   {
@@ -408,8 +395,8 @@ void Z7_FASTCALL Sha256_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_
   }
   while (--numBlocks);
 
-  STORE_128(&state[0], state0);
-  STORE_128(&state[4], state1);
+  STORE_128_32(&state[0], state0);
+  STORE_128_32(&state[4], state1);
 }
 
 #endif // USE_HW_SHA
@@ -443,13 +430,10 @@ void Z7_FASTCALL Sha256_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_
 #endif
 
 
-
 #undef K
 #undef RND2
-#undef RND2_0
-#undef RND2_1
-
 #undef MY_rev32_for_LE
+
 #undef NNN
 #undef LOAD_128
 #undef STORE_128
@@ -457,7 +441,7 @@ void Z7_FASTCALL Sha256_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_
 #undef SM1
 #undef SM2
 
-#undef NNN
+
 #undef R4
 #undef R16
 #undef PREPARE_STATE
diff --git a/C/Sha3.c b/C/Sha3.c
new file mode 100644
index 0000000..be972d6
--- /dev/null
+++ b/C/Sha3.c
@@ -0,0 +1,359 @@
+/* Sha3.c -- SHA-3 Hash
+: Igor Pavlov : Public domain
+This code is based on public domain code from Wei Dai's Crypto++ library. */
+
+#include "Precomp.h"
+
+#include <string.h>
+
+#include "Sha3.h"
+#include "RotateDefs.h"
+#include "CpuArch.h"
+
+#define U64C(x) UINT64_CONST(x)
+
+static
+MY_ALIGN(64)
+const UInt64 SHA3_K_ARRAY[24] =
+{
+  U64C(0x0000000000000001), U64C(0x0000000000008082),
+  U64C(0x800000000000808a), U64C(0x8000000080008000),
+  U64C(0x000000000000808b), U64C(0x0000000080000001),
+  U64C(0x8000000080008081), U64C(0x8000000000008009),
+  U64C(0x000000000000008a), U64C(0x0000000000000088),
+  U64C(0x0000000080008009), U64C(0x000000008000000a),
+  U64C(0x000000008000808b), U64C(0x800000000000008b),
+  U64C(0x8000000000008089), U64C(0x8000000000008003),
+  U64C(0x8000000000008002), U64C(0x8000000000000080),
+  U64C(0x000000000000800a), U64C(0x800000008000000a),
+  U64C(0x8000000080008081), U64C(0x8000000000008080),
+  U64C(0x0000000080000001), U64C(0x8000000080008008)
+};
+
+void Sha3_Init(CSha3 *p)
+{
+  p->count = 0;
+  memset(p->state, 0, sizeof(p->state));
+}
+
+#define GET_state(i, a)   UInt64 a = state[i];
+#define SET_state(i, a)   state[i] = a;
+
+#define LS_5(M, i, a0,a1,a2,a3,a4) \
+        M ((i) * 5    , a0) \
+        M ((i) * 5 + 1, a1) \
+        M ((i) * 5 + 2, a2) \
+        M ((i) * 5 + 3, a3) \
+        M ((i) * 5 + 4, a4) \
+
+#define LS_25(M) \
+        LS_5 (M, 0, a50, a51, a52, a53, a54) \
+        LS_5 (M, 1, a60, a61, a62, a63, a64) \
+        LS_5 (M, 2, a70, a71, a72, a73, a74) \
+        LS_5 (M, 3, a80, a81, a82, a83, a84) \
+        LS_5 (M, 4, a90, a91, a92, a93, a94) \
+
+
+#define XOR_1(i, a0) \
+        a0 ^= GetUi64(data + (i) * 8); \
+
+#define XOR_4(i, a0,a1,a2,a3) \
+        XOR_1 ((i)    , a0); \
+        XOR_1 ((i) + 1, a1); \
+        XOR_1 ((i) + 2, a2); \
+        XOR_1 ((i) + 3, a3); \
+
+#define D(d,b1,b2) \
+        d = b1 ^ Z7_ROTL64(b2, 1);
+
+#define D5 \
+        D (d0, c4, c1) \
+        D (d1, c0, c2) \
+        D (d2, c1, c3) \
+        D (d3, c2, c4) \
+        D (d4, c3, c0) \
+
+#define C0(c,a,d) \
+        c = a ^ d; \
+
+#define C(c,a,d,k) \
+        c = a ^ d; \
+        c = Z7_ROTL64(c, k); \
+
+#define E4(e1,e2,e3,e4) \
+        e1 = c1 ^ (~c2 & c3); \
+        e2 = c2 ^ (~c3 & c4); \
+        e3 = c3 ^ (~c4 & c0); \
+        e4 = c4 ^ (~c0 & c1); \
+
+#define CK(   v0,w0,    \
+              v1,w1,k1, \
+              v2,w2,k2, \
+              v3,w3,k3, \
+              v4,w4,k4, e0,e1,e2,e3,e4, keccak_c) \
+        C0(c0,v0,w0)    \
+        C (c1,v1,w1,k1) \
+        C (c2,v2,w2,k2) \
+        C (c3,v3,w3,k3) \
+        C (c4,v4,w4,k4) \
+        e0 = c0 ^ (~c1 & c2) ^ keccak_c; \
+        E4(e1,e2,e3,e4) \
+
+#define CE(   v0,w0,k0, \
+              v1,w1,k1, \
+              v2,w2,k2, \
+              v3,w3,k3, \
+              v4,w4,k4, e0,e1,e2,e3,e4) \
+        C (c0,v0,w0,k0) \
+        C (c1,v1,w1,k1) \
+        C (c2,v2,w2,k2) \
+        C (c3,v3,w3,k3) \
+        C (c4,v4,w4,k4) \
+        e0 = c0 ^ (~c1 & c2); \
+        E4(e1,e2,e3,e4) \
+
+// numBlocks != 0
+static
+Z7_NO_INLINE
+void Z7_FASTCALL Sha3_UpdateBlocks(UInt64 state[SHA3_NUM_STATE_WORDS],
+    const Byte *data, size_t numBlocks, size_t blockSize)
+{
+  LS_25 (GET_state)
+
+  do
+  {
+    unsigned round;
+                              XOR_4 ( 0, a50, a51, a52, a53)
+                              XOR_4 ( 4, a54, a60, a61, a62)
+                              XOR_1 ( 8, a63)
+    if (blockSize > 8 *  9) { XOR_4 ( 9, a64, a70, a71, a72)  // sha3-384
+    if (blockSize > 8 * 13) { XOR_4 (13, a73, a74, a80, a81)  // sha3-256
+    if (blockSize > 8 * 17) { XOR_1 (17, a82)                 // sha3-224
+    if (blockSize > 8 * 18) { XOR_1 (18, a83)                 // shake128
+                              XOR_1 (19, a84)
+                              XOR_1 (20, a90) }}}}
+    data += blockSize;
+
+    for (round = 0; round < 24; round += 2)
+    {
+      UInt64 c0, c1, c2, c3, c4;
+      UInt64 d0, d1, d2, d3, d4;
+      UInt64 e50, e51, e52, e53, e54;
+      UInt64 e60, e61, e62, e63, e64;
+      UInt64 e70, e71, e72, e73, e74;
+      UInt64 e80, e81, e82, e83, e84;
+      UInt64 e90, e91, e92, e93, e94;
+
+      c0 = a50^a60^a70^a80^a90;
+      c1 = a51^a61^a71^a81^a91;
+      c2 = a52^a62^a72^a82^a92;
+      c3 = a53^a63^a73^a83^a93;
+      c4 = a54^a64^a74^a84^a94;
+      D5
+      CK( a50, d0,
+          a61, d1, 44,
+          a72, d2, 43,
+          a83, d3, 21,
+          a94, d4, 14, e50, e51, e52, e53, e54, SHA3_K_ARRAY[round])
+      CE( a53, d3, 28,
+          a64, d4, 20,
+          a70, d0,  3,
+          a81, d1, 45,
+          a92, d2, 61, e60, e61, e62, e63, e64)
+      CE( a51, d1,  1,
+          a62, d2,  6,
+          a73, d3, 25,
+          a84, d4,  8,
+          a90, d0, 18, e70, e71, e72, e73, e74)
+      CE( a54, d4, 27,
+          a60, d0, 36,
+          a71, d1, 10,
+          a82, d2, 15,
+          a93, d3, 56, e80, e81, e82, e83, e84)
+      CE( a52, d2, 62,
+          a63, d3, 55,
+          a74, d4, 39,
+          a80, d0, 41,
+          a91, d1,  2, e90, e91, e92, e93, e94)
+      
+      // ---------- ROUND + 1 ----------
+
+      c0 = e50^e60^e70^e80^e90;
+      c1 = e51^e61^e71^e81^e91;
+      c2 = e52^e62^e72^e82^e92;
+      c3 = e53^e63^e73^e83^e93;
+      c4 = e54^e64^e74^e84^e94;
+      D5
+      CK( e50, d0,
+          e61, d1, 44,
+          e72, d2, 43,
+          e83, d3, 21,
+          e94, d4, 14, a50, a51, a52, a53, a54, SHA3_K_ARRAY[(size_t)round + 1])
+      CE( e53, d3, 28,
+          e64, d4, 20,
+          e70, d0,  3,
+          e81, d1, 45,
+          e92, d2, 61, a60, a61, a62, a63, a64)
+      CE( e51, d1,  1,
+          e62, d2,  6,
+          e73, d3, 25,
+          e84, d4,  8,
+          e90, d0, 18, a70, a71, a72, a73, a74)
+      CE (e54, d4, 27,
+          e60, d0, 36,
+          e71, d1, 10,
+          e82, d2, 15,
+          e93, d3, 56, a80, a81, a82, a83, a84)
+      CE (e52, d2, 62,
+          e63, d3, 55,
+          e74, d4, 39,
+          e80, d0, 41,
+          e91, d1,  2, a90, a91, a92, a93, a94)
+    }
+  }
+  while (--numBlocks);
+
+  LS_25 (SET_state)
+}
+
+
+#define Sha3_UpdateBlock(p) \
+        Sha3_UpdateBlocks(p->state, p->buffer, 1, p->blockSize)
+
+void Sha3_Update(CSha3 *p, const Byte *data, size_t size)
+{
+/*
+  for (;;)
+  {
+    if (size == 0)
+      return;
+    unsigned cur = p->blockSize - p->count;
+    if (cur > size)
+      cur = (unsigned)size;
+    size -= cur;
+    unsigned pos = p->count;
+    p->count = pos + cur;
+    while (pos & 7)
+    {
+      if (cur == 0)
+        return;
+      Byte *pb = &(((Byte *)p->state)[pos]);
+      *pb = (Byte)(*pb ^ *data++);
+      cur--;
+      pos++;
+    }
+    if (cur >= 8)
+    {
+      do
+      {
+        *(UInt64 *)(void *)&(((Byte *)p->state)[pos]) ^= GetUi64(data);
+        data += 8;
+        pos += 8;
+        cur -= 8;
+      }
+      while (cur >= 8);
+    }
+    if (pos != p->blockSize)
+    {
+      if (cur)
+      {
+        Byte *pb = &(((Byte *)p->state)[pos]);
+        do
+        {
+          *pb = (Byte)(*pb ^ *data++);
+          pb++;
+        }
+        while (--cur);
+      }
+      return;
+    }
+    Sha3_UpdateBlock(p->state);
+    p->count = 0;
+  }
+*/
+  if (size == 0)
+    return;
+  {
+    const unsigned pos = p->count;
+    const unsigned num = p->blockSize - pos;
+    if (num > size)
+    {
+      p->count = pos + (unsigned)size;
+      memcpy(p->buffer + pos, data, size);
+      return;
+    }
+    if (pos != 0)
+    {
+      size -= num;
+      memcpy(p->buffer + pos, data, num);
+      data += num;
+      Sha3_UpdateBlock(p);
+    }
+  }
+  if (size >= p->blockSize)
+  {
+    const size_t numBlocks = size / p->blockSize;
+    const Byte *dataOld = data;
+    data += numBlocks * p->blockSize;
+    size = (size_t)(dataOld + size - data);
+    Sha3_UpdateBlocks(p->state, dataOld, numBlocks, p->blockSize);
+  }
+  p->count = (unsigned)size;
+  if (size)
+    memcpy(p->buffer, data, size);
+}
+
+
+// we support only (digestSize % 4 == 0) cases
+void Sha3_Final(CSha3 *p, Byte *digest, unsigned digestSize, unsigned shake)
+{
+  memset(p->buffer + p->count, 0, p->blockSize - p->count);
+  // we write bits markers from low to higher in current byte:
+  //   - if sha-3 : 2 bits : 0,1
+  //   - if shake : 4 bits : 1111
+  // then we write bit 1 to same byte.
+  // And we write bit 1 to highest bit of last byte of block.
+  p->buffer[p->count] = (Byte)(shake ? 0x1f : 0x06);
+  // we need xor operation (^= 0x80) here because we must write 0x80 bit
+  // to same byte as (0x1f : 0x06), if (p->count == p->blockSize - 1) !!!
+  p->buffer[p->blockSize - 1] ^= 0x80;
+/*
+  ((Byte *)p->state)[p->count] ^= (Byte)(shake ? 0x1f : 0x06);
+  ((Byte *)p->state)[p->blockSize - 1] ^= 0x80;
+*/
+  Sha3_UpdateBlock(p);
+#if 1 && defined(MY_CPU_LE)
+  memcpy(digest, p->state, digestSize);
+#else
+  {
+    const unsigned numWords = digestSize >> 3;
+    unsigned i;
+    for (i = 0; i < numWords; i++)
+    {
+      const UInt64 v = p->state[i];
+      SetUi64(digest, v)
+      digest += 8;
+    }
+    if (digestSize & 4) // for SHA3-224
+    {
+      const UInt32 v = (UInt32)p->state[numWords];
+      SetUi32(digest, v)
+    }
+  }
+#endif
+  Sha3_Init(p);
+}
+
+#undef GET_state
+#undef SET_state
+#undef LS_5
+#undef LS_25
+#undef XOR_1
+#undef XOR_4
+#undef D
+#undef D5
+#undef C0
+#undef C
+#undef E4
+#undef CK
+#undef CE
diff --git a/C/Sha3.h b/C/Sha3.h
new file mode 100644
index 0000000..c5909c9
--- /dev/null
+++ b/C/Sha3.h
@@ -0,0 +1,36 @@
+/* Sha3.h -- SHA-3 Hash
+: Igor Pavlov : Public domain */
+
+#ifndef ZIP7_INC_MD5_H
+#define ZIP7_INC_MD5_H
+
+#include "7zTypes.h"
+
+EXTERN_C_BEGIN
+
+#define SHA3_NUM_STATE_WORDS  25
+
+#define SHA3_BLOCK_SIZE_FROM_DIGEST_SIZE(digestSize) \
+    (SHA3_NUM_STATE_WORDS * 8 - (digestSize) * 2)
+
+typedef struct
+{
+  UInt32 count;     // < blockSize
+  UInt32 blockSize; // <= SHA3_NUM_STATE_WORDS * 8
+  UInt64 _pad1[3];
+  // we want 32-bytes alignment here
+  UInt64 state[SHA3_NUM_STATE_WORDS];
+  UInt64 _pad2[3];
+  // we want 64-bytes alignment here
+  Byte buffer[SHA3_NUM_STATE_WORDS * 8]; // last bytes will be unused with predefined blockSize values
+} CSha3;
+
+#define Sha3_SET_blockSize(p, blockSize) { (p)->blockSize = (blockSize); }
+
+void Sha3_Init(CSha3 *p);
+void Sha3_Update(CSha3 *p, const Byte *data, size_t size);
+void Sha3_Final(CSha3 *p, Byte *digest, unsigned digestSize, unsigned shake);
+
+EXTERN_C_END
+
+#endif
diff --git a/C/Sha512.c b/C/Sha512.c
new file mode 100644
index 0000000..04827d6
--- /dev/null
+++ b/C/Sha512.c
@@ -0,0 +1,618 @@
+/* Sha512.c -- SHA-512 Hash
+: Igor Pavlov : Public domain
+This code is based on public domain code from Wei Dai's Crypto++ library. */
+
+#include "Precomp.h"
+
+#include <string.h>
+
+#include "Sha512.h"
+#include "RotateDefs.h"
+#include "CpuArch.h"
+
+#ifdef MY_CPU_X86_OR_AMD64
+  #if   defined(Z7_LLVM_CLANG_VERSION)  && (Z7_LLVM_CLANG_VERSION  >= 170001) \
+     || defined(Z7_APPLE_CLANG_VERSION) && (Z7_APPLE_CLANG_VERSION >= 170001) \
+     || defined(Z7_GCC_VERSION)         && (Z7_GCC_VERSION         >= 140000) \
+     || defined(__INTEL_COMPILER) && (__INTEL_COMPILER >= 2400) && (__INTEL_COMPILER <= 9900) \
+     || defined(_MSC_VER) && (_MSC_VER >= 1940)
+      #define Z7_COMPILER_SHA512_SUPPORTED
+  #endif
+#elif defined(MY_CPU_ARM64) && defined(MY_CPU_LE)
+  #if defined(__ARM_FEATURE_SHA512)
+    #define Z7_COMPILER_SHA512_SUPPORTED
+  #else
+    #if (defined(Z7_CLANG_VERSION) && (Z7_CLANG_VERSION >= 130000) \
+           || defined(__GNUC__) && (__GNUC__ >= 9) \
+        ) \
+      || defined(Z7_MSC_VER_ORIGINAL) && (_MSC_VER >= 1940) // fix it
+      #define Z7_COMPILER_SHA512_SUPPORTED
+    #endif
+  #endif
+#endif
+
+
+
+
+
+
+
+
+
+
+
+
+
+
+void Z7_FASTCALL Sha512_UpdateBlocks(UInt64 state[8], const Byte *data, size_t numBlocks);
+
+#ifdef Z7_COMPILER_SHA512_SUPPORTED
+  void Z7_FASTCALL Sha512_UpdateBlocks_HW(UInt64 state[8], const Byte *data, size_t numBlocks);
+
+  static SHA512_FUNC_UPDATE_BLOCKS g_SHA512_FUNC_UPDATE_BLOCKS = Sha512_UpdateBlocks;
+  static SHA512_FUNC_UPDATE_BLOCKS g_SHA512_FUNC_UPDATE_BLOCKS_HW;
+
+  #define SHA512_UPDATE_BLOCKS(p) p->v.vars.func_UpdateBlocks
+#else
+  #define SHA512_UPDATE_BLOCKS(p) Sha512_UpdateBlocks
+#endif
+
+
+BoolInt Sha512_SetFunction(CSha512 *p, unsigned algo)
+{
+  SHA512_FUNC_UPDATE_BLOCKS func = Sha512_UpdateBlocks;
+  
+  #ifdef Z7_COMPILER_SHA512_SUPPORTED
+    if (algo != SHA512_ALGO_SW)
+    {
+      if (algo == SHA512_ALGO_DEFAULT)
+        func = g_SHA512_FUNC_UPDATE_BLOCKS;
+      else
+      {
+        if (algo != SHA512_ALGO_HW)
+          return False;
+        func = g_SHA512_FUNC_UPDATE_BLOCKS_HW;
+        if (!func)
+          return False;
+      }
+    }
+  #else
+    if (algo > 1)
+      return False;
+  #endif
+
+  p->v.vars.func_UpdateBlocks = func;
+  return True;
+}
+
+
+/* define it for speed optimization */
+
+#if 0 // 1 for size optimization
+  #define STEP_PRE 1
+  #define STEP_MAIN 1
+#else
+  #define STEP_PRE 2
+  #define STEP_MAIN 4
+  // #define Z7_SHA512_UNROLL
+#endif
+
+#undef Z7_SHA512_BIG_W
+#if STEP_MAIN != 16
+  #define Z7_SHA512_BIG_W
+#endif
+
+
+#define U64C(x) UINT64_CONST(x)
+
+static MY_ALIGN(64) const UInt64 SHA512_INIT_ARRAYS[4][8] = {
+{ U64C(0x8c3d37c819544da2), U64C(0x73e1996689dcd4d6), U64C(0x1dfab7ae32ff9c82), U64C(0x679dd514582f9fcf),
+  U64C(0x0f6d2b697bd44da8), U64C(0x77e36f7304c48942), U64C(0x3f9d85a86a1d36c8), U64C(0x1112e6ad91d692a1)
+},
+{ U64C(0x22312194fc2bf72c), U64C(0x9f555fa3c84c64c2), U64C(0x2393b86b6f53b151), U64C(0x963877195940eabd),
+  U64C(0x96283ee2a88effe3), U64C(0xbe5e1e2553863992), U64C(0x2b0199fc2c85b8aa), U64C(0x0eb72ddc81c52ca2)
+},
+{ U64C(0xcbbb9d5dc1059ed8), U64C(0x629a292a367cd507), U64C(0x9159015a3070dd17), U64C(0x152fecd8f70e5939),
+  U64C(0x67332667ffc00b31), U64C(0x8eb44a8768581511), U64C(0xdb0c2e0d64f98fa7), U64C(0x47b5481dbefa4fa4)
+},
+{ U64C(0x6a09e667f3bcc908), U64C(0xbb67ae8584caa73b), U64C(0x3c6ef372fe94f82b), U64C(0xa54ff53a5f1d36f1),
+  U64C(0x510e527fade682d1), U64C(0x9b05688c2b3e6c1f), U64C(0x1f83d9abfb41bd6b), U64C(0x5be0cd19137e2179)
+}};
+
+void Sha512_InitState(CSha512 *p, unsigned digestSize)
+{
+  p->v.vars.count = 0;
+  memcpy(p->state, SHA512_INIT_ARRAYS[(size_t)(digestSize >> 4) - 1], sizeof(p->state));
+}
+
+void Sha512_Init(CSha512 *p, unsigned digestSize)
+{
+  p->v.vars.func_UpdateBlocks =
+  #ifdef Z7_COMPILER_SHA512_SUPPORTED
+      g_SHA512_FUNC_UPDATE_BLOCKS;
+  #else
+      NULL;
+  #endif
+  Sha512_InitState(p, digestSize);
+}
+
+#define S0(x) (Z7_ROTR64(x,28) ^ Z7_ROTR64(x,34) ^ Z7_ROTR64(x,39))
+#define S1(x) (Z7_ROTR64(x,14) ^ Z7_ROTR64(x,18) ^ Z7_ROTR64(x,41))
+#define s0(x) (Z7_ROTR64(x, 1) ^ Z7_ROTR64(x, 8) ^ (x >> 7))
+#define s1(x) (Z7_ROTR64(x,19) ^ Z7_ROTR64(x,61) ^ (x >> 6))
+
+#define Ch(x,y,z) (z^(x&(y^z)))
+#define Maj(x,y,z) ((x&y)|(z&(x|y)))
+
+
+#define W_PRE(i) (W[(i) + (size_t)(j)] = GetBe64(data + ((size_t)(j) + i) * 8))
+
+#define blk2_main(j, i)  s1(w(j, (i)-2)) + w(j, (i)-7) + s0(w(j, (i)-15))
+
+#ifdef Z7_SHA512_BIG_W
+    // we use +i instead of +(i) to change the order to solve CLANG compiler warning for signed/unsigned.
+    #define w(j, i)     W[(size_t)(j) + i]
+    #define blk2(j, i)  (w(j, i) = w(j, (i)-16) + blk2_main(j, i))
+#else
+    #if STEP_MAIN == 16
+        #define w(j, i)  W[(i) & 15]
+    #else
+        #define w(j, i)  W[((size_t)(j) + (i)) & 15]
+    #endif
+    #define blk2(j, i)  (w(j, i) += blk2_main(j, i))
+#endif
+
+#define W_MAIN(i)  blk2(j, i)
+
+
+#define T1(wx, i) \
+    tmp = h + S1(e) + Ch(e,f,g) + K[(i)+(size_t)(j)] + wx(i); \
+    h = g; \
+    g = f; \
+    f = e; \
+    e = d + tmp; \
+    tmp += S0(a) + Maj(a, b, c); \
+    d = c; \
+    c = b; \
+    b = a; \
+    a = tmp; \
+
+#define R1_PRE(i)  T1( W_PRE, i)
+#define R1_MAIN(i) T1( W_MAIN, i)
+
+#if (!defined(Z7_SHA512_UNROLL) || STEP_MAIN < 8) && (STEP_MAIN >= 4)
+#define R2_MAIN(i) \
+    R1_MAIN(i) \
+    R1_MAIN(i + 1) \
+
+#endif
+
+
+
+#if defined(Z7_SHA512_UNROLL) && STEP_MAIN >= 8
+
+#define T4( a,b,c,d,e,f,g,h, wx, i) \
+    h += S1(e) + Ch(e,f,g) + K[(i)+(size_t)(j)] + wx(i); \
+    tmp = h; \
+    h += d; \
+    d = tmp + S0(a) + Maj(a, b, c); \
+
+#define R4( wx, i) \
+    T4 ( a,b,c,d,e,f,g,h, wx, (i  )); \
+    T4 ( d,a,b,c,h,e,f,g, wx, (i+1)); \
+    T4 ( c,d,a,b,g,h,e,f, wx, (i+2)); \
+    T4 ( b,c,d,a,f,g,h,e, wx, (i+3)); \
+
+#define R4_PRE(i)  R4( W_PRE, i)
+#define R4_MAIN(i) R4( W_MAIN, i)
+
+
+#define T8( a,b,c,d,e,f,g,h, wx, i) \
+    h += S1(e) + Ch(e,f,g) + K[(i)+(size_t)(j)] + wx(i); \
+    d += h; \
+    h += S0(a) + Maj(a, b, c); \
+
+#define R8( wx, i) \
+    T8 ( a,b,c,d,e,f,g,h, wx, i  ); \
+    T8 ( h,a,b,c,d,e,f,g, wx, i+1); \
+    T8 ( g,h,a,b,c,d,e,f, wx, i+2); \
+    T8 ( f,g,h,a,b,c,d,e, wx, i+3); \
+    T8 ( e,f,g,h,a,b,c,d, wx, i+4); \
+    T8 ( d,e,f,g,h,a,b,c, wx, i+5); \
+    T8 ( c,d,e,f,g,h,a,b, wx, i+6); \
+    T8 ( b,c,d,e,f,g,h,a, wx, i+7); \
+
+#define R8_PRE(i)  R8( W_PRE, i)
+#define R8_MAIN(i) R8( W_MAIN, i)
+
+#endif
+
+
+extern
+MY_ALIGN(64) const UInt64 SHA512_K_ARRAY[80];
+MY_ALIGN(64) const UInt64 SHA512_K_ARRAY[80] = {
+  U64C(0x428a2f98d728ae22), U64C(0x7137449123ef65cd), U64C(0xb5c0fbcfec4d3b2f), U64C(0xe9b5dba58189dbbc),
+  U64C(0x3956c25bf348b538), U64C(0x59f111f1b605d019), U64C(0x923f82a4af194f9b), U64C(0xab1c5ed5da6d8118),
+  U64C(0xd807aa98a3030242), U64C(0x12835b0145706fbe), U64C(0x243185be4ee4b28c), U64C(0x550c7dc3d5ffb4e2),
+  U64C(0x72be5d74f27b896f), U64C(0x80deb1fe3b1696b1), U64C(0x9bdc06a725c71235), U64C(0xc19bf174cf692694),
+  U64C(0xe49b69c19ef14ad2), U64C(0xefbe4786384f25e3), U64C(0x0fc19dc68b8cd5b5), U64C(0x240ca1cc77ac9c65),
+  U64C(0x2de92c6f592b0275), U64C(0x4a7484aa6ea6e483), U64C(0x5cb0a9dcbd41fbd4), U64C(0x76f988da831153b5),
+  U64C(0x983e5152ee66dfab), U64C(0xa831c66d2db43210), U64C(0xb00327c898fb213f), U64C(0xbf597fc7beef0ee4),
+  U64C(0xc6e00bf33da88fc2), U64C(0xd5a79147930aa725), U64C(0x06ca6351e003826f), U64C(0x142929670a0e6e70),
+  U64C(0x27b70a8546d22ffc), U64C(0x2e1b21385c26c926), U64C(0x4d2c6dfc5ac42aed), U64C(0x53380d139d95b3df),
+  U64C(0x650a73548baf63de), U64C(0x766a0abb3c77b2a8), U64C(0x81c2c92e47edaee6), U64C(0x92722c851482353b),
+  U64C(0xa2bfe8a14cf10364), U64C(0xa81a664bbc423001), U64C(0xc24b8b70d0f89791), U64C(0xc76c51a30654be30),
+  U64C(0xd192e819d6ef5218), U64C(0xd69906245565a910), U64C(0xf40e35855771202a), U64C(0x106aa07032bbd1b8),
+  U64C(0x19a4c116b8d2d0c8), U64C(0x1e376c085141ab53), U64C(0x2748774cdf8eeb99), U64C(0x34b0bcb5e19b48a8),
+  U64C(0x391c0cb3c5c95a63), U64C(0x4ed8aa4ae3418acb), U64C(0x5b9cca4f7763e373), U64C(0x682e6ff3d6b2b8a3),
+  U64C(0x748f82ee5defb2fc), U64C(0x78a5636f43172f60), U64C(0x84c87814a1f0ab72), U64C(0x8cc702081a6439ec),
+  U64C(0x90befffa23631e28), U64C(0xa4506cebde82bde9), U64C(0xbef9a3f7b2c67915), U64C(0xc67178f2e372532b),
+  U64C(0xca273eceea26619c), U64C(0xd186b8c721c0c207), U64C(0xeada7dd6cde0eb1e), U64C(0xf57d4f7fee6ed178),
+  U64C(0x06f067aa72176fba), U64C(0x0a637dc5a2c898a6), U64C(0x113f9804bef90dae), U64C(0x1b710b35131c471b),
+  U64C(0x28db77f523047d84), U64C(0x32caab7b40c72493), U64C(0x3c9ebe0a15c9bebc), U64C(0x431d67c49c100d4c),
+  U64C(0x4cc5d4becb3e42b6), U64C(0x597f299cfc657e2a), U64C(0x5fcb6fab3ad6faec), U64C(0x6c44198c4a475817)
+};
+
+#define K SHA512_K_ARRAY
+
+Z7_NO_INLINE
+void Z7_FASTCALL Sha512_UpdateBlocks(UInt64 state[8], const Byte *data, size_t numBlocks)
+{
+  UInt64 W
+#ifdef Z7_SHA512_BIG_W
+      [80];
+#else
+      [16];
+#endif
+  unsigned j;
+  UInt64 a,b,c,d,e,f,g,h;
+#if !defined(Z7_SHA512_UNROLL) || (STEP_MAIN <= 4) || (STEP_PRE <= 4)
+  UInt64 tmp;
+#endif
+
+  if (numBlocks == 0) return;
+  
+  a = state[0];
+  b = state[1];
+  c = state[2];
+  d = state[3];
+  e = state[4];
+  f = state[5];
+  g = state[6];
+  h = state[7];
+
+  do
+  {
+
+  for (j = 0; j < 16; j += STEP_PRE)
+  {
+    #if STEP_PRE > 4
+
+      #if STEP_PRE < 8
+      R4_PRE(0);
+      #else
+      R8_PRE(0);
+      #if STEP_PRE == 16
+      R8_PRE(8);
+      #endif
+      #endif
+
+    #else
+
+      R1_PRE(0)
+      #if STEP_PRE >= 2
+      R1_PRE(1)
+      #if STEP_PRE >= 4
+      R1_PRE(2)
+      R1_PRE(3)
+      #endif
+      #endif
+    
+    #endif
+  }
+
+  for (j = 16; j < 80; j += STEP_MAIN)
+  {
+    #if defined(Z7_SHA512_UNROLL) && STEP_MAIN >= 8
+
+      #if STEP_MAIN < 8
+      R4_MAIN(0)
+      #else
+      R8_MAIN(0)
+      #if STEP_MAIN == 16
+      R8_MAIN(8)
+      #endif
+      #endif
+
+    #else
+      
+      R1_MAIN(0)
+      #if STEP_MAIN >= 2
+      R1_MAIN(1)
+      #if STEP_MAIN >= 4
+      R2_MAIN(2)
+      #if STEP_MAIN >= 8
+      R2_MAIN(4)
+      R2_MAIN(6)
+      #if STEP_MAIN >= 16
+      R2_MAIN(8)
+      R2_MAIN(10)
+      R2_MAIN(12)
+      R2_MAIN(14)
+      #endif
+      #endif
+      #endif
+      #endif
+    #endif
+  }
+
+  a += state[0]; state[0] = a;
+  b += state[1]; state[1] = b;
+  c += state[2]; state[2] = c;
+  d += state[3]; state[3] = d;
+  e += state[4]; state[4] = e;
+  f += state[5]; state[5] = f;
+  g += state[6]; state[6] = g;
+  h += state[7]; state[7] = h;
+
+  data += SHA512_BLOCK_SIZE;
+  }
+  while (--numBlocks);
+}
+
+
+#define Sha512_UpdateBlock(p) SHA512_UPDATE_BLOCKS(p)(p->state, p->buffer, 1)
+
+void Sha512_Update(CSha512 *p, const Byte *data, size_t size)
+{
+  if (size == 0)
+    return;
+  {
+    const unsigned pos = (unsigned)p->v.vars.count & (SHA512_BLOCK_SIZE - 1);
+    const unsigned num = SHA512_BLOCK_SIZE - pos;
+    p->v.vars.count += size;
+    if (num > size)
+    {
+      memcpy(p->buffer + pos, data, size);
+      return;
+    }
+    if (pos != 0)
+    {
+      size -= num;
+      memcpy(p->buffer + pos, data, num);
+      data += num;
+      Sha512_UpdateBlock(p);
+    }
+  }
+  {
+    const size_t numBlocks = size >> 7;
+    // if (numBlocks)
+    SHA512_UPDATE_BLOCKS(p)(p->state, data, numBlocks);
+    size &= SHA512_BLOCK_SIZE - 1;
+    if (size == 0)
+      return;
+    data += (numBlocks << 7);
+    memcpy(p->buffer, data, size);
+  }
+}
+
+
+void Sha512_Final(CSha512 *p, Byte *digest, unsigned digestSize)
+{
+  unsigned pos = (unsigned)p->v.vars.count & (SHA512_BLOCK_SIZE - 1);
+  p->buffer[pos++] = 0x80;
+  if (pos > (SHA512_BLOCK_SIZE - 8 * 2))
+  {
+    while (pos != SHA512_BLOCK_SIZE) { p->buffer[pos++] = 0; }
+    // memset(&p->buf.buffer[pos], 0, SHA512_BLOCK_SIZE - pos);
+    Sha512_UpdateBlock(p);
+    pos = 0;
+  }
+  memset(&p->buffer[pos], 0, (SHA512_BLOCK_SIZE - 8 * 2) - pos);
+  {
+    const UInt64 numBits = p->v.vars.count << 3;
+    SetBe64(p->buffer + SHA512_BLOCK_SIZE - 8 * 2, 0) // = (p->v.vars.count >> (64 - 3)); (high 64-bits)
+    SetBe64(p->buffer + SHA512_BLOCK_SIZE - 8 * 1, numBits)
+  }
+  Sha512_UpdateBlock(p);
+#if 1 && defined(MY_CPU_BE)
+  memcpy(digest, p->state, digestSize);
+#else
+  {
+    const unsigned numWords = digestSize >> 3;
+    unsigned i;
+    for (i = 0; i < numWords; i++)
+    {
+      const UInt64 v = p->state[i];
+      SetBe64(digest, v)
+      digest += 8;
+    }
+    if (digestSize & 4) // digestSize == SHA512_224_DIGEST_SIZE
+    {
+      const UInt32 v = (UInt32)((p->state[numWords]) >> 32);
+      SetBe32(digest, v)
+    }
+  }
+#endif
+  Sha512_InitState(p, digestSize);
+}
+
+
+
+
+#if defined(_WIN32) && defined(Z7_COMPILER_SHA512_SUPPORTED) \
+    && defined(MY_CPU_ARM64)  // we can disable this check to debug in x64
+
+#if 1  // 0 for debug
+
+#include "7zWindows.h"
+// #include <stdio.h>
+#if 0 && defined(MY_CPU_X86_OR_AMD64)
+#include <intrin.h> // for debug : for __ud2()
+#endif
+
+BoolInt CPU_IsSupported_SHA512(void)
+{
+#if defined(MY_CPU_ARM64)
+  // we have no SHA512 flag for IsProcessorFeaturePresent() still.
+  if (!CPU_IsSupported_CRYPTO())
+    return False;
+#endif
+  // printf("\nCPU_IsSupported_SHA512\n");
+  {
+    // we can't read ID_AA64ISAR0_EL1 register from application.
+    // but ID_AA64ISAR0_EL1 register is mapped to "CP 4030" registry value.
+    HKEY key = NULL;
+    LONG res = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
+        TEXT("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"),
+        0, KEY_READ, &key);
+    if (res != ERROR_SUCCESS)
+      return False;
+    {
+      DWORD type = 0;
+      DWORD count = sizeof(UInt64);
+      UInt64 val = 0;
+      res = RegQueryValueEx(key, TEXT("CP 4030"), NULL,
+          &type, (LPBYTE)&val, &count);
+      RegCloseKey(key);
+      if (res != ERROR_SUCCESS
+          || type != REG_QWORD
+          || count != sizeof(UInt64)
+          || ((unsigned)(val >> 12) & 0xf) != 2)
+        return False;
+      // we parse SHA2 field of ID_AA64ISAR0_EL1 register:
+      //   0 : No SHA2 instructions implemented
+      //   1 : SHA256 implemented
+      //   2 : SHA256 and SHA512 implemented
+    }
+  }
+
+
+#if 1  // 0 for debug to disable SHA512 PROBE code
+
+/*
+----- SHA512 PROBE -----
+
+We suppose that "CP 4030" registry reading is enough.
+But we use additional SHA512 PROBE code, because
+we can catch exception here, and we don't catch exceptions,
+if we call Sha512 functions from main code.
+
+NOTE: arm64 PROBE code doesn't work, if we call it via Wine in linux-arm64.
+The program just stops.
+Also x64 version of PROBE code doesn't work, if we run it via Intel SDE emulator
+without SHA512 support (-skl switch),
+The program stops, and we have message from SDE:
+  TID 0 SDE-ERROR: Executed instruction not valid for specified chip (SKYLAKE): vsha512msg1
+But we still want to catch that exception instead of process stopping.
+Does this PROBE code work in native Windows-arm64 (with/without sha512 hw instructions)?
+Are there any ways to fix the problems with arm64-wine and x64-SDE cases?
+*/
+
+  // printf("\n========== CPU_IsSupported_SHA512 PROBE ========\n");
+  {
+#ifdef __clang_major__
+  #pragma GCC diagnostic ignored "-Wlanguage-extension-token"
+#endif
+    __try
+    {
+#if 0 // 1 : for debug (reduced version to detect sha512)
+      const uint64x2_t a = vdupq_n_u64(1);
+      const uint64x2_t b = vsha512hq_u64(a, a, a);
+      if ((UInt32)vgetq_lane_u64(b, 0) == 0x11800002)
+        return True;
+#else
+      MY_ALIGN(16)
+      UInt64 temp[SHA512_NUM_DIGEST_WORDS + SHA512_NUM_BLOCK_WORDS];
+      memset(temp, 0x5a, sizeof(temp));
+#if 0 && defined(MY_CPU_X86_OR_AMD64)
+      __ud2(); // for debug : that exception is not problem for SDE
+#endif
+#if 1
+      Sha512_UpdateBlocks_HW(temp,
+          (const Byte *)(const void *)(temp + SHA512_NUM_DIGEST_WORDS), 1);
+      // printf("\n==== t = %x\n", (UInt32)temp[0]);
+      if ((UInt32)temp[0] == 0xa33cfdf7)
+      {
+        // printf("\n=== PROBE SHA512: SHA512 supported\n");
+        return True;
+      }
+#endif
+#endif
+    }
+    __except (EXCEPTION_EXECUTE_HANDLER)
+    {
+      // printf("\n==== CPU_IsSupported_SHA512 EXCEPTION_EXECUTE_HANDLER\n");
+    }
+  }
+  return False;
+#else
+  // without SHA512 PROBE code
+  return True;
+#endif
+
+}
+
+#else
+
+BoolInt CPU_IsSupported_SHA512(void)
+{
+  return False;
+}
+
+#endif
+#endif // WIN32 arm64
+
+
+void Sha512Prepare(void)
+{
+#ifdef Z7_COMPILER_SHA512_SUPPORTED
+  SHA512_FUNC_UPDATE_BLOCKS f, f_hw;
+  f = Sha512_UpdateBlocks;
+  f_hw = NULL;
+#ifdef MY_CPU_X86_OR_AMD64
+  if (CPU_IsSupported_SHA512()
+      && CPU_IsSupported_AVX2()
+      )
+#else
+  if (CPU_IsSupported_SHA512())
+#endif
+  {
+    // printf("\n========== HW SHA512 ======== \n");
+    f = f_hw = Sha512_UpdateBlocks_HW;
+  }
+  g_SHA512_FUNC_UPDATE_BLOCKS    = f;
+  g_SHA512_FUNC_UPDATE_BLOCKS_HW = f_hw;
+#endif
+}
+
+
+#undef K
+#undef S0
+#undef S1
+#undef s0
+#undef s1
+#undef Ch
+#undef Maj
+#undef W_MAIN
+#undef W_PRE
+#undef w
+#undef blk2_main
+#undef blk2
+#undef T1
+#undef T4
+#undef T8
+#undef R1_PRE
+#undef R1_MAIN
+#undef R2_MAIN
+#undef R4
+#undef R4_PRE
+#undef R4_MAIN
+#undef R8
+#undef R8_PRE
+#undef R8_MAIN
+#undef STEP_PRE
+#undef STEP_MAIN
+#undef Z7_SHA512_BIG_W
+#undef Z7_SHA512_UNROLL
+#undef Z7_COMPILER_SHA512_SUPPORTED
diff --git a/C/Sha512.h b/C/Sha512.h
new file mode 100644
index 0000000..1f3a4d1
--- /dev/null
+++ b/C/Sha512.h
@@ -0,0 +1,86 @@
+/* Sha512.h -- SHA-512 Hash
+: Igor Pavlov : Public domain */
+
+#ifndef ZIP7_INC_SHA512_H
+#define ZIP7_INC_SHA512_H
+
+#include "7zTypes.h"
+
+EXTERN_C_BEGIN
+
+#define SHA512_NUM_BLOCK_WORDS  16
+#define SHA512_NUM_DIGEST_WORDS  8
+
+#define SHA512_BLOCK_SIZE   (SHA512_NUM_BLOCK_WORDS * 8)
+#define SHA512_DIGEST_SIZE  (SHA512_NUM_DIGEST_WORDS * 8)
+#define SHA512_224_DIGEST_SIZE  (224 / 8)
+#define SHA512_256_DIGEST_SIZE  (256 / 8)
+#define SHA512_384_DIGEST_SIZE  (384 / 8)
+
+typedef void (Z7_FASTCALL *SHA512_FUNC_UPDATE_BLOCKS)(UInt64 state[8], const Byte *data, size_t numBlocks);
+
+/*
+  if (the system supports different SHA512 code implementations)
+  {
+    (CSha512::func_UpdateBlocks) will be used
+    (CSha512::func_UpdateBlocks) can be set by
+       Sha512_Init()        - to default (fastest)
+       Sha512_SetFunction() - to any algo
+  }
+  else
+  {
+    (CSha512::func_UpdateBlocks) is ignored.
+  }
+*/
+
+typedef struct
+{
+  union
+  {
+    struct
+    {
+      SHA512_FUNC_UPDATE_BLOCKS func_UpdateBlocks;
+      UInt64 count;
+    } vars;
+    UInt64 _pad_64bit[8];
+    void *_pad_align_ptr[2];
+  } v;
+  UInt64 state[SHA512_NUM_DIGEST_WORDS];
+  
+  Byte buffer[SHA512_BLOCK_SIZE];
+} CSha512;
+
+
+#define SHA512_ALGO_DEFAULT 0
+#define SHA512_ALGO_SW      1
+#define SHA512_ALGO_HW      2
+
+/*
+Sha512_SetFunction()
+return:
+  0 - (algo) value is not supported, and func_UpdateBlocks was not changed
+  1 - func_UpdateBlocks was set according (algo) value.
+*/
+
+BoolInt Sha512_SetFunction(CSha512 *p, unsigned algo);
+// we support only these (digestSize) values: 224/8, 256/8, 384/8, 512/8
+void Sha512_InitState(CSha512 *p, unsigned digestSize);
+void Sha512_Init(CSha512 *p, unsigned digestSize);
+void Sha512_Update(CSha512 *p, const Byte *data, size_t size);
+void Sha512_Final(CSha512 *p, Byte *digest, unsigned digestSize);
+
+
+
+
+// void Z7_FASTCALL Sha512_UpdateBlocks(UInt64 state[8], const Byte *data, size_t numBlocks);
+
+/*
+call Sha512Prepare() once at program start.
+It prepares all supported implementations, and detects the fastest implementation.
+*/
+
+void Sha512Prepare(void);
+
+EXTERN_C_END
+
+#endif
diff --git a/C/Sha512Opt.c b/C/Sha512Opt.c
new file mode 100644
index 0000000..3a13868
--- /dev/null
+++ b/C/Sha512Opt.c
@@ -0,0 +1,395 @@
+/* Sha512Opt.c -- SHA-512 optimized code for SHA-512 hardware instructions
+: Igor Pavlov : Public domain */
+
+#include "Precomp.h"
+#include "Compiler.h"
+#include "CpuArch.h"
+
+// #define Z7_USE_HW_SHA_STUB // for debug
+#ifdef MY_CPU_X86_OR_AMD64
+  #if defined(__INTEL_COMPILER) && (__INTEL_COMPILER >= 2400) && (__INTEL_COMPILER <= 9900) // fix it
+      #define USE_HW_SHA
+  #elif defined(Z7_LLVM_CLANG_VERSION)  && (Z7_LLVM_CLANG_VERSION  >= 170001) \
+     || defined(Z7_APPLE_CLANG_VERSION) && (Z7_APPLE_CLANG_VERSION >= 170001) \
+     || defined(Z7_GCC_VERSION)         && (Z7_GCC_VERSION         >= 140000)
+      #define USE_HW_SHA
+      #if !defined(__INTEL_COMPILER)
+      // icc defines __GNUC__, but icc doesn't support __attribute__(__target__)
+      #if !defined(__SHA512__) || !defined(__AVX2__)
+        #define ATTRIB_SHA512 __attribute__((__target__("sha512,avx2")))
+      #endif
+      #endif
+  #elif defined(Z7_MSC_VER_ORIGINAL)
+    #if (_MSC_VER >= 1940)
+      #define USE_HW_SHA
+    #else
+      // #define Z7_USE_HW_SHA_STUB
+    #endif
+  #endif
+// #endif // MY_CPU_X86_OR_AMD64
+#ifndef USE_HW_SHA
+  // #define Z7_USE_HW_SHA_STUB // for debug
+#endif
+
+#ifdef USE_HW_SHA
+
+// #pragma message("Sha512 HW")
+
+#include <immintrin.h>
+
+#if defined (__clang__) && defined(_MSC_VER)
+  #if !defined(__AVX__)
+    #include <avxintrin.h>
+  #endif
+  #if !defined(__AVX2__)
+    #include <avx2intrin.h>
+  #endif
+  #if !defined(__SHA512__)
+    #include <sha512intrin.h>
+  #endif
+#else
+
+#endif
+
+/*
+SHA512 uses:
+AVX:
+  _mm256_loadu_si256  (vmovdqu)
+  _mm256_storeu_si256
+  _mm256_set_epi32    (unused)
+AVX2:
+  _mm256_add_epi64     : vpaddq
+  _mm256_shuffle_epi8  : vpshufb
+  _mm256_shuffle_epi32 : pshufd
+  _mm256_blend_epi32   : vpblendd
+  _mm256_permute4x64_epi64 : vpermq     : 3c
+  _mm256_permute2x128_si256: vperm2i128 : 3c
+  _mm256_extracti128_si256 : vextracti128  : 3c
+SHA512:
+  _mm256_sha512*
+*/
+
+// K array must be aligned for 32-bytes at least.
+// The compiler can look align attribute and selects
+//  vmovdqu - for code without align attribute
+//  vmovdqa - for code with    align attribute
+extern
+MY_ALIGN(64)
+const UInt64 SHA512_K_ARRAY[80];
+#define K SHA512_K_ARRAY
+
+
+#define ADD_EPI64(dest, src)      dest = _mm256_add_epi64(dest, src);
+#define SHA512_MSG1(dest, src)    dest = _mm256_sha512msg1_epi64(dest, _mm256_extracti128_si256(src, 0));
+#define SHA512_MSG2(dest, src)    dest = _mm256_sha512msg2_epi64(dest, src);
+
+#define LOAD_SHUFFLE(m, k) \
+    m = _mm256_loadu_si256((const __m256i *)(const void *)(data + (k) * 32)); \
+    m = _mm256_shuffle_epi8(m, mask); \
+
+#define NNN(m0, m1, m2, m3)
+
+#define SM1(m1, m2, m3, m0) \
+    SHA512_MSG1(m0, m1); \
+            
+#define SM2(m2, m3, m0, m1) \
+    ADD_EPI64(m0, _mm256_permute4x64_epi64(_mm256_blend_epi32(m2, m3, 3), 0x39)); \
+    SHA512_MSG2(m0, m3); \
+
+#define RND2(t0, t1, lane) \
+    t0 = _mm256_sha512rnds2_epi64(t0, t1, _mm256_extracti128_si256(msg, lane));
+
+
+
+#define R4(k, m0, m1, m2, m3, OP0, OP1) \
+    msg = _mm256_add_epi64(m0, *(const __m256i *) (const void *) &K[(k) * 4]); \
+    RND2(state0, state1, 0);  OP0(m0, m1, m2, m3) \
+    RND2(state1, state0, 1);  OP1(m0, m1, m2, m3) \
+
+
+
+
+#define R16(k, OP0, OP1, OP2, OP3, OP4, OP5, OP6, OP7) \
+    R4 ( (k)*4+0, m0,m1,m2,m3, OP0, OP1 ) \
+    R4 ( (k)*4+1, m1,m2,m3,m0, OP2, OP3 ) \
+    R4 ( (k)*4+2, m2,m3,m0,m1, OP4, OP5 ) \
+    R4 ( (k)*4+3, m3,m0,m1,m2, OP6, OP7 ) \
+
+#define PREPARE_STATE \
+    state0 = _mm256_shuffle_epi32(state0, 0x4e);              /* cdab */ \
+    state1 = _mm256_shuffle_epi32(state1, 0x4e);              /* ghef */ \
+    tmp = state0; \
+    state0 = _mm256_permute2x128_si256(state0, state1, 0x13); /* cdgh */ \
+    state1 = _mm256_permute2x128_si256(tmp,    state1, 2);    /* abef */ \
+
+
+void Z7_FASTCALL Sha512_UpdateBlocks_HW(UInt64 state[8], const Byte *data, size_t numBlocks);
+#ifdef ATTRIB_SHA512
+ATTRIB_SHA512
+#endif
+void Z7_FASTCALL Sha512_UpdateBlocks_HW(UInt64 state[8], const Byte *data, size_t numBlocks)
+{
+  const __m256i mask = _mm256_set_epi32(
+      0x08090a0b,0x0c0d0e0f, 0x00010203,0x04050607,
+      0x08090a0b,0x0c0d0e0f, 0x00010203,0x04050607);
+  __m256i tmp, state0, state1;
+
+  if (numBlocks == 0)
+    return;
+
+  state0 = _mm256_loadu_si256((const __m256i *) (const void *) &state[0]);
+  state1 = _mm256_loadu_si256((const __m256i *) (const void *) &state[4]);
+  
+  PREPARE_STATE
+
+  do
+  {
+    __m256i state0_save, state1_save;
+    __m256i m0, m1, m2, m3;
+    __m256i msg;
+    // #define msg tmp
+
+    state0_save = state0;
+    state1_save = state1;
+    
+    LOAD_SHUFFLE (m0, 0)
+    LOAD_SHUFFLE (m1, 1)
+    LOAD_SHUFFLE (m2, 2)
+    LOAD_SHUFFLE (m3, 3)
+
+
+
+    R16 ( 0, NNN, NNN, SM1, NNN, SM1, SM2, SM1, SM2 )
+    R16 ( 1, SM1, SM2, SM1, SM2, SM1, SM2, SM1, SM2 )
+    R16 ( 2, SM1, SM2, SM1, SM2, SM1, SM2, SM1, SM2 )
+    R16 ( 3, SM1, SM2, SM1, SM2, SM1, SM2, SM1, SM2 )
+    R16 ( 4, SM1, SM2, NNN, SM2, NNN, NNN, NNN, NNN )
+    ADD_EPI64(state0, state0_save)
+    ADD_EPI64(state1, state1_save)
+    
+    data += 128;
+  }
+  while (--numBlocks);
+
+  PREPARE_STATE
+
+  _mm256_storeu_si256((__m256i *) (void *) &state[0], state0);
+  _mm256_storeu_si256((__m256i *) (void *) &state[4], state1);
+}
+
+#endif // USE_HW_SHA
+
+// gcc 8.5 also supports sha512, but we need also support in assembler that is called by gcc
+#elif defined(MY_CPU_ARM64) && defined(MY_CPU_LE)
+  
+  #if defined(__ARM_FEATURE_SHA512)
+    #define USE_HW_SHA
+  #else
+    #if (defined(Z7_CLANG_VERSION) && (Z7_CLANG_VERSION >= 130000) \
+           || defined(__GNUC__) && (__GNUC__ >= 9) \
+          ) \
+      || defined(Z7_MSC_VER_ORIGINAL) && (_MSC_VER >= 1940) // fix it
+      #define USE_HW_SHA
+    #endif
+  #endif
+
+#ifdef USE_HW_SHA
+
+// #pragma message("=== Sha512 HW === ")
+
+
+#if defined(__clang__) || defined(__GNUC__)
+#if !defined(__ARM_FEATURE_SHA512)
+// #pragma message("=== we define SHA3 ATTRIB_SHA512 === ")
+#if defined(__clang__)
+    #define ATTRIB_SHA512 __attribute__((__target__("sha3"))) // "armv8.2-a,sha3"
+#else
+    #define ATTRIB_SHA512 __attribute__((__target__("arch=armv8.2-a+sha3")))
+#endif
+#endif
+#endif
+
+
+#if defined(Z7_MSC_VER_ORIGINAL)
+#include <arm64_neon.h>
+#else
+
+#if defined(__clang__) && __clang_major__ < 16
+#if !defined(__ARM_FEATURE_SHA512)
+// #pragma message("=== we set __ARM_FEATURE_SHA512 1 === ")
+    Z7_DIAGNOSTIC_IGNORE_BEGIN_RESERVED_MACRO_IDENTIFIER
+    #define Z7_ARM_FEATURE_SHA512_WAS_SET 1
+    #define __ARM_FEATURE_SHA512 1
+    Z7_DIAGNOSTIC_IGNORE_END_RESERVED_MACRO_IDENTIFIER
+#endif
+#endif // clang
+
+#include <arm_neon.h>
+
+#if defined(Z7_ARM_FEATURE_SHA512_WAS_SET) && \
+    defined(__ARM_FEATURE_SHA512)
+    Z7_DIAGNOSTIC_IGNORE_BEGIN_RESERVED_MACRO_IDENTIFIER
+    #undef __ARM_FEATURE_SHA512
+    #undef Z7_ARM_FEATURE_SHA512_WAS_SET
+    Z7_DIAGNOSTIC_IGNORE_END_RESERVED_MACRO_IDENTIFIER
+// #pragma message("=== we undefine __ARM_FEATURE_CRYPTO === ")
+#endif
+
+#endif // Z7_MSC_VER_ORIGINAL
+
+typedef uint64x2_t v128_64;
+// typedef __n128 v128_64; // MSVC
+
+#ifdef MY_CPU_BE
+  #define MY_rev64_for_LE(x) x
+#else
+  #define MY_rev64_for_LE(x) vrev64q_u8(x)
+#endif
+
+#define LOAD_128_64(_p)       vld1q_u64(_p)
+#define LOAD_128_8(_p)        vld1q_u8 (_p)
+#define STORE_128_64(_p, _v)  vst1q_u64(_p, _v)
+
+#define LOAD_SHUFFLE(m, k) \
+    m = vreinterpretq_u64_u8( \
+        MY_rev64_for_LE( \
+        LOAD_128_8(data + (k) * 16))); \
+
+// K array must be aligned for 16-bytes at least.
+extern
+MY_ALIGN(64)
+const UInt64 SHA512_K_ARRAY[80];
+#define K SHA512_K_ARRAY
+
+#define NN(m0, m1, m4, m5, m7)
+#define SM(m0, m1, m4, m5, m7) \
+    m0 = vsha512su1q_u64(vsha512su0q_u64(m0, m1), m7, vextq_u64(m4, m5, 1));
+
+#define R2(k, m0,m1,m2,m3,m4,m5,m6,m7, a0,a1,a2,a3, OP) \
+    OP(m0, m1, m4, m5, m7) \
+    t = vaddq_u64(m0, vld1q_u64(k)); \
+    t = vaddq_u64(vextq_u64(t, t, 1), a3); \
+    t = vsha512hq_u64(t, vextq_u64(a2, a3, 1), vextq_u64(a1, a2, 1)); \
+    a3 = vsha512h2q_u64(t, a1, a0); \
+    a1 = vaddq_u64(a1, t); \
+
+#define R8(k,     m0,m1,m2,m3,m4,m5,m6,m7, OP) \
+    R2 ( (k)+0*2, m0,m1,m2,m3,m4,m5,m6,m7, a0,a1,a2,a3, OP ) \
+    R2 ( (k)+1*2, m1,m2,m3,m4,m5,m6,m7,m0, a3,a0,a1,a2, OP ) \
+    R2 ( (k)+2*2, m2,m3,m4,m5,m6,m7,m0,m1, a2,a3,a0,a1, OP ) \
+    R2 ( (k)+3*2, m3,m4,m5,m6,m7,m0,m1,m2, a1,a2,a3,a0, OP ) \
+
+#define R16(k, OP) \
+    R8 ( (k)+0*2, m0,m1,m2,m3,m4,m5,m6,m7, OP ) \
+    R8 ( (k)+4*2, m4,m5,m6,m7,m0,m1,m2,m3, OP ) \
+
+
+void Z7_FASTCALL Sha512_UpdateBlocks_HW(UInt64 state[8], const Byte *data, size_t numBlocks);
+#ifdef ATTRIB_SHA512
+ATTRIB_SHA512
+#endif
+void Z7_FASTCALL Sha512_UpdateBlocks_HW(UInt64 state[8], const Byte *data, size_t numBlocks)
+{
+  v128_64 a0, a1, a2, a3;
+
+  if (numBlocks == 0)
+    return;
+  a0 = LOAD_128_64(&state[0]);
+  a1 = LOAD_128_64(&state[2]);
+  a2 = LOAD_128_64(&state[4]);
+  a3 = LOAD_128_64(&state[6]);
+  do
+  {
+    v128_64 a0_save, a1_save, a2_save, a3_save;
+    v128_64 m0, m1, m2, m3, m4, m5, m6, m7;
+    v128_64 t;
+    unsigned i;
+    const UInt64 *k_ptr;
+    
+    LOAD_SHUFFLE (m0, 0)
+    LOAD_SHUFFLE (m1, 1)
+    LOAD_SHUFFLE (m2, 2)
+    LOAD_SHUFFLE (m3, 3)
+    LOAD_SHUFFLE (m4, 4)
+    LOAD_SHUFFLE (m5, 5)
+    LOAD_SHUFFLE (m6, 6)
+    LOAD_SHUFFLE (m7, 7)
+
+    a0_save = a0;
+    a1_save = a1;
+    a2_save = a2;
+    a3_save = a3;
+    
+    R16 ( K, NN )
+    k_ptr = K + 16;
+    for (i = 0; i < 4; i++)
+    {
+      R16 ( k_ptr, SM )
+      k_ptr += 16;
+    }
+    
+    a0 = vaddq_u64(a0, a0_save);
+    a1 = vaddq_u64(a1, a1_save);
+    a2 = vaddq_u64(a2, a2_save);
+    a3 = vaddq_u64(a3, a3_save);
+
+    data += 128;
+  }
+  while (--numBlocks);
+
+  STORE_128_64(&state[0], a0);
+  STORE_128_64(&state[2], a1);
+  STORE_128_64(&state[4], a2);
+  STORE_128_64(&state[6], a3);
+}
+
+#endif // USE_HW_SHA
+
+#endif // MY_CPU_ARM_OR_ARM64
+
+
+#if !defined(USE_HW_SHA) && defined(Z7_USE_HW_SHA_STUB)
+// #error Stop_Compiling_UNSUPPORTED_SHA
+// #include <stdlib.h>
+// We can compile this file with another C compiler,
+// or we can compile asm version.
+// So we can generate real code instead of this stub function.
+// #include "Sha512.h"
+// #if defined(_MSC_VER)
+#pragma message("Sha512 HW-SW stub was used")
+// #endif
+void Z7_FASTCALL Sha512_UpdateBlocks   (UInt64 state[8], const Byte *data, size_t numBlocks);
+void Z7_FASTCALL Sha512_UpdateBlocks_HW(UInt64 state[8], const Byte *data, size_t numBlocks);
+void Z7_FASTCALL Sha512_UpdateBlocks_HW(UInt64 state[8], const Byte *data, size_t numBlocks)
+{
+  Sha512_UpdateBlocks(state, data, numBlocks);
+  /*
+  UNUSED_VAR(state);
+  UNUSED_VAR(data);
+  UNUSED_VAR(numBlocks);
+  exit(1);
+  return;
+  */
+}
+#endif
+
+
+#undef K
+#undef RND2
+#undef MY_rev64_for_LE
+#undef NN
+#undef NNN
+#undef LOAD_128
+#undef STORE_128
+#undef LOAD_SHUFFLE
+#undef SM1
+#undef SM2
+#undef SM
+#undef R2
+#undef R4
+#undef R16
+#undef PREPARE_STATE
+#undef USE_HW_SHA
+#undef ATTRIB_SHA512
+#undef USE_VER_MIN
+#undef Z7_USE_HW_SHA_STUB
diff --git a/CPP/7zip/7zip_gcc.mak b/CPP/7zip/7zip_gcc.mak
index 45c9ab3..bcb06a0 100644
--- a/CPP/7zip/7zip_gcc.mak
+++ b/CPP/7zip/7zip_gcc.mak
@@ -302,6 +302,8 @@ $O/ListFileUtils.o: ../../../Common/ListFileUtils.cpp
 	$(CXX) $(CXXFLAGS) $<
 $O/LzFindPrepare.o: ../../../Common/LzFindPrepare.cpp
 	$(CXX) $(CXXFLAGS) $<
+$O/Md5Reg.o: ../../../Common/Md5Reg.cpp
+	$(CXX) $(CXXFLAGS) $<
 $O/MyMap.o: ../../../Common/MyMap.cpp
 	$(CXX) $(CXXFLAGS) $<
 $O/MyString.o: ../../../Common/MyString.cpp
@@ -326,6 +328,12 @@ $O/Sha256Prepare.o: ../../../Common/Sha256Prepare.cpp
 	$(CXX) $(CXXFLAGS) $<
 $O/Sha256Reg.o: ../../../Common/Sha256Reg.cpp
 	$(CXX) $(CXXFLAGS) $<
+$O/Sha3Reg.o: ../../../Common/Sha3Reg.cpp
+	$(CXX) $(CXXFLAGS) $<
+$O/Sha512Prepare.o: ../../../Common/Sha512Prepare.cpp
+	$(CXX) $(CXXFLAGS) $<
+$O/Sha512Reg.o: ../../../Common/Sha512Reg.cpp
+	$(CXX) $(CXXFLAGS) $<
 $O/StdInStream.o: ../../../Common/StdInStream.cpp
 	$(CXX) $(CXXFLAGS) $<
 $O/StdOutStream.o: ../../../Common/StdOutStream.cpp
@@ -1207,6 +1215,8 @@ $O/Lzma2Enc.o: ../../../../C/Lzma2Enc.c
 	$(CC) $(CFLAGS) $<
 $O/LzmaLib.o: ../../../../C/LzmaLib.c
 	$(CC) $(CFLAGS) $<
+$O/Md5.o: ../../../../C/Md5.c
+	$(CC) $(CFLAGS) $<
 $O/MtCoder.o: ../../../../C/MtCoder.c
 	$(CC) $(CFLAGS) $<
 $O/MtDec.o: ../../../../C/MtDec.c
@@ -1229,6 +1239,12 @@ $O/Sha1.o: ../../../../C/Sha1.c
 	$(CC) $(CFLAGS) $<
 $O/Sha256.o: ../../../../C/Sha256.c
 	$(CC) $(CFLAGS) $<
+$O/Sha3.o: ../../../../C/Sha3.c
+	$(CC) $(CFLAGS) $<
+$O/Sha512.o: ../../../../C/Sha512.c
+	$(CC) $(CFLAGS) $<
+$O/Sha512Opt.o: ../../../../C/Sha512Opt.c
+	$(CC) $(CFLAGS) $<
 $O/Sort.o: ../../../../C/Sort.c
 	$(CC) $(CFLAGS) $<
 $O/SwapBytes.o: ../../../../C/SwapBytes.c
diff --git a/CPP/7zip/Archive/ApmHandler.cpp b/CPP/7zip/Archive/ApmHandler.cpp
index 56d9b6e..e88d2fe 100644
--- a/CPP/7zip/Archive/ApmHandler.cpp
+++ b/CPP/7zip/Archive/ApmHandler.cpp
@@ -6,7 +6,6 @@
 
 #include "../../Common/ComTry.h"
 
-#include "../../Windows/PropVariant.h"
 #include "../../Windows/PropVariantUtils.h"
 
 #include "../Common/RegisterArc.h"
@@ -14,8 +13,7 @@
 
 #include "HandlerCont.h"
 
-// #define Get16(p) GetBe16(p)
-#define Get32(p) GetBe32(p)
+#define Get32(p) GetBe32a(p)
 
 using namespace NWindows;
 
@@ -41,8 +39,8 @@ static const CUInt32PCharPair k_Flags[] =
   { 5, "WRITABLE" },
   { 6, "OS_PIC_CODE" },
   // { 7, "OS_SPECIFIC_2" }, // "Unused"
-  // { 8, "ChainCompatible" }, // "OS_SPECIFIC_1"
-  // { 9, "RealDeviceDriver" },
+  { 8, "ChainCompatible" }, // "OS_SPECIFIC_1"
+  { 9, "RealDeviceDriver" },
   // { 10, "CanChainToNext" },
   { 30, "MOUNTED_AT_STARTUP" },
   { 31, "STARTUP" }
@@ -74,16 +72,16 @@ struct CItem
   bool Is_Valid_and_Allocated() const
     { return (Flags & (DPME_FLAGS_VALID | DPME_FLAGS_ALLOCATED)) != 0; }
 
-  bool Parse(const Byte *p, UInt32 &numBlocksInMap)
+  bool Parse(const UInt32 *p32, UInt32 &numBlocksInMap)
   {
-    numBlocksInMap = Get32(p + 4);
-    StartBlock = Get32(p + 8);
-    NumBlocks = Get32(p + 0xc);
-    Flags = Get32(p + 0x58);
-    memcpy(Name, p + 0x10, k_Str_Size);
-    memcpy(Type, p + 0x30, k_Str_Size);
-    if (GetUi32(p) != 0x4d50) // "PM"
+    if (GetUi32a(p32) != 0x4d50) // "PM"
       return false;
+    numBlocksInMap = Get32(p32 + 4 / 4);
+    StartBlock = Get32(p32 + 8 / 4);
+    NumBlocks = Get32(p32 + 0xc / 4);
+    Flags = Get32(p32 + 0x58 / 4);
+    memcpy(Name, p32 + 0x10 / 4, k_Str_Size);
+    memcpy(Type, p32 + 0x30 / 4, k_Str_Size);
     /*
     DataStartBlock = Get32(p + 0x50);
     NumDataBlocks = Get32(p + 0x54);
@@ -96,7 +94,7 @@ struct CItem
     if (Get32(p + 0x70) != 0)
       return false;
     BootChecksum = Get32(p + 0x74);
-    memcpy(Processor, p + 0x78, 16);
+    memcpy(Processor, p32 + 0x78 / 4, 16);
     */
     return true;
   }
@@ -109,9 +107,9 @@ Z7_class_CHandler_final: public CHandlerCont
 
   CRecordVector<CItem> _items;
   unsigned _blockSizeLog;
-  UInt32 _numBlocks;
-  UInt64 _phySize;
   bool _isArc;
+  // UInt32 _numBlocks;
+  UInt64 _phySize;
 
   UInt64 BlocksToBytes(UInt32 i) const { return (UInt64)i << _blockSizeLog; }
 
@@ -132,11 +130,11 @@ API_FUNC_static_IsArc IsArc_Apm(const Byte *p, size_t size)
 {
   if (size < kSectorSize)
     return k_IsArc_Res_NEED_MORE;
-  if (GetUi64(p + 8) != 0)
+  if (GetUi32(p + 12) != 0)
     return k_IsArc_Res_NO;
   UInt32 v = GetUi32(p); // we read as little-endian
-  v ^= (kSig0 | (unsigned)kSig1 << 8);
-  if ((v & ~((UInt32)0xf << 17)))
+  v ^= kSig0 | (unsigned)kSig1 << 8;
+  if (v & ~((UInt32)0xf << 17))
     return k_IsArc_Res_NO;
   if ((0x116u >> (v >> 17)) & 1)
     return k_IsArc_Res_YES;
@@ -149,55 +147,103 @@ Z7_COM7F_IMF(CHandler::Open(IInStream *stream, const UInt64 *, IArchiveOpenCallb
   COM_TRY_BEGIN
   Close();
 
-  Byte buf[kSectorSize];
-  unsigned numSectors_in_Cluster;
+  UInt32 buf32[kSectorSize / 4];
+  unsigned numPadSectors, blockSizeLog_from_Header;
   {
-    RINOK(ReadStream_FALSE(stream, buf, kSectorSize))
-    if (GetUi64(buf + 8) != 0)
+    // Driver Descriptor Map (DDM)
+    RINOK(ReadStream_FALSE(stream, buf32, kSectorSize))
+    //  8: UInt16 sbDevType : =0 (usually), =1 in Apple Mac OS X 10.3.0 iso
+    // 10: UInt16 sbDevId   : =0 (usually), =1 in Apple Mac OS X 10.3.0 iso
+    // 12: UInt32 sbData    : =0
+    if (buf32[3] != 0)
       return S_FALSE;
-    UInt32 v = GetUi32(buf); // we read as little-endian
-    v ^= (kSig0 | (unsigned)kSig1 << 8);
-    if ((v & ~((UInt32)0xf << 17)))
+    UInt32 v = GetUi32a(buf32); // we read as little-endian
+    v ^= kSig0 | (unsigned)kSig1 << 8;
+    if (v & ~((UInt32)0xf << 17))
       return S_FALSE;
     v >>= 16;
     if (v == 0)
       return S_FALSE;
     if (v & (v - 1))
       return S_FALSE;
-    const unsigned a = (0x30210u >> v) & 3;
-    // a = 0; // for debug
-    numSectors_in_Cluster = 1u << a;
-    _blockSizeLog = 9 + a;
+    // v == { 16,8,4,2 } : block size (x256 bytes)
+    const unsigned a =
+#if 1
+        (0x30210u >> v) & 3;
+#else
+        0; // for debug : hardcoded switch to 512-bytes mode
+#endif
+    numPadSectors = (1u << a) - 1;
+    _blockSizeLog = blockSizeLog_from_Header = 9 + a;
   }
 
-  UInt32 numBlocks = Get32(buf + 4);
-  _numBlocks = numBlocks;
-
+/*
+  some APMs (that are ".iso" macOS installation files) contain
+    (blockSizeLog == 11) in DDM header,
+  and contain 2 overlapping maps:
+    1) map for  512-bytes-step
+    2) map for 2048-bytes-step
+   512-bytes-step map is correct.
+  2048-bytes-step map can be incorrect in some cases.
+
+  macos 8 / OSX DP2 iso:
+    There is shared "hfs" item in both maps.
+    And correct (offset/size) values for "hfs" partition
+    can be calculated only in 512-bytes mode (ignoring blockSizeLog == 11).
+    But some records (Macintosh.Apple_Driver*_)
+    can be correct on both modes: 512-bytes mode / 2048-bytes-step.
+  
+  macos 921 ppc / Apple Mac OS X 10.3.0 iso:
+    Both maps are correct.
+    If we use 512-bytes-step, each 4th item is (Apple_Void) with zero size.
+    And these zero size (Apple_Void) items will be first items in 2048-bytes-step map.
+*/
+
+// we define Z7_APM_SWITCH_TO_512_BYTES, because
+// we want to support old MACOS APMs that contain correct value only
+// for 512-bytes-step mode
+#define Z7_APM_SWITCH_TO_512_BYTES
+
+  const UInt32 numBlocks_from_Header = Get32(buf32 + 1);
+  UInt32 numBlocks = 0;
   {
-    for (unsigned k = numSectors_in_Cluster; --k != 0;)
+    for (unsigned k = 0; k < numPadSectors; k++)
     {
-      RINOK(ReadStream_FALSE(stream, buf, kSectorSize))
+      RINOK(ReadStream_FALSE(stream, buf32, kSectorSize))
+#ifdef Z7_APM_SWITCH_TO_512_BYTES
+      if (k == 0)
+      {
+        if (GetUi32a(buf32) == 0x4d50        // "PM"
+            // && (Get32(buf32 + 0x58 / 4) & 1) // Flags::VALID
+            // some old APMs don't use VALID flag for Apple_partition_map item
+            && Get32(buf32 + 8 / 4) == 1)    // StartBlock
+        {
+          // we switch the mode to 512-bytes-step map reading:
+          numPadSectors = 0;
+          _blockSizeLog = 9;
+          break;
+        }
+      }
+#endif
     }
   }
 
-  UInt32 numBlocksInMap = 0;
-  
   for (unsigned i = 0;;)
   {
-    RINOK(ReadStream_FALSE(stream, buf, kSectorSize))
+#ifdef Z7_APM_SWITCH_TO_512_BYTES
+    if (i != 0 || _blockSizeLog == blockSizeLog_from_Header)
+#endif
+    {
+      RINOK(ReadStream_FALSE(stream, buf32, kSectorSize))
+    }
  
     CItem item;
-    
-    UInt32 numBlocksInMap2 = 0;
-    if (!item.Parse(buf, numBlocksInMap2))
+    UInt32 numBlocksInMap = 0;
+    if (!item.Parse(buf32, numBlocksInMap))
       return S_FALSE;
-    if (i == 0)
-    {
-      numBlocksInMap = numBlocksInMap2;
-      if (numBlocksInMap > (1 << 8) || numBlocksInMap == 0)
-        return S_FALSE;
-    }
-    else if (numBlocksInMap2 != numBlocksInMap)
+    // v24.09: we don't check that all entries have same (numBlocksInMap) values,
+    // because some APMs have different (numBlocksInMap) values, if (Apple_Void) is used.
+    if (numBlocksInMap > (1 << 8) || numBlocksInMap <= i)
       return S_FALSE;
 
     const UInt32 finish = item.StartBlock + item.NumBlocks;
@@ -207,15 +253,19 @@ Z7_COM7F_IMF(CHandler::Open(IInStream *stream, const UInt64 *, IArchiveOpenCallb
         numBlocks = finish;
     
     _items.Add(item);
-    for (unsigned k = numSectors_in_Cluster; --k != 0;)
+    if (numPadSectors != 0)
     {
-      RINOK(ReadStream_FALSE(stream, buf, kSectorSize))
+      RINOK(stream->Seek(numPadSectors << 9, STREAM_SEEK_CUR, NULL))
     }
     if (++i == numBlocksInMap)
       break;
   }
   
   _phySize = BlocksToBytes(numBlocks);
+  // _numBlocks = numBlocks;
+  const UInt64 physSize = (UInt64)numBlocks_from_Header << blockSizeLog_from_Header;
+  if (_phySize < physSize)
+      _phySize = physSize;
   _isArc = true;
   _stream = stream;
 
@@ -240,22 +290,21 @@ static const Byte kProps[] =
   kpidSize,
   kpidOffset,
   kpidCharacts
+  // , kpidCpu
 };
 
 static const Byte kArcProps[] =
 {
-  kpidClusterSize,
-  kpidNumBlocks
+  kpidClusterSize
+  // , kpidNumBlocks
 };
 
 IMP_IInArchive_Props
 IMP_IInArchive_ArcProps
 
-static AString GetString(const char *s)
+static void GetString(AString &dest, const char *src)
 {
-  AString res;
-  res.SetFrom_CalcLen(s, k_Str_Size);
-  return res;
+  dest.SetFrom_CalcLen(src, k_Str_Size);
 }
 
 Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
@@ -272,7 +321,8 @@ Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
         const CItem &item = _items[i];
         if (!item.Is_Valid_and_Allocated())
           continue;
-        AString s (GetString(item.Type));
+        AString s;
+        GetString(s, item.Type);
         if (NDmg::Is_Apple_FS_Or_Unknown(s))
         {
           if (mainIndex != -1)
@@ -289,7 +339,7 @@ Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
     }
     case kpidClusterSize: prop = (UInt32)1 << _blockSizeLog; break;
     case kpidPhySize: prop = _phySize; break;
-    case kpidNumBlocks: prop = _numBlocks; break;
+    // case kpidNumBlocks: prop = _numBlocks; break;
 
     case kpidErrorFlags:
     {
@@ -319,10 +369,12 @@ Z7_COM7F_IMF(CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT *val
   {
     case kpidPath:
     {
-      AString s (GetString(item.Name));
+      AString s;
+      GetString(s, item.Name);
       if (s.IsEmpty())
         s.Add_UInt32(index);
-      AString type (GetString(item.Type));
+      AString type;
+      GetString(type, item.Type);
       {
         const char *ext = NDmg::Find_Apple_FS_Ext(type);
         if (ext)
@@ -336,6 +388,16 @@ Z7_COM7F_IMF(CHandler::GetProperty(UInt32 index, PROPID propID, PROPVARIANT *val
       prop = s;
       break;
     }
+/*
+    case kpidCpu:
+    {
+      AString s;
+      s.SetFrom_CalcLen(item.Processor, sizeof(item.Processor));
+      if (!s.IsEmpty())
+        prop = s;
+      break;
+    }
+*/
     case kpidSize:
     case kpidPackSize:
       prop = BlocksToBytes(item.NumBlocks);
diff --git a/CPP/7zip/Archive/Common/HandlerOut.h b/CPP/7zip/Archive/Common/HandlerOut.h
index cfba46e..9340e1b 100644
--- a/CPP/7zip/Archive/Common/HandlerOut.h
+++ b/CPP/7zip/Archive/Common/HandlerOut.h
@@ -22,7 +22,7 @@ protected:
     _numThreads_WasForced = false;
     #endif
 
-    UInt64 memAvail = (UInt64)(sizeof(size_t)) << 28;
+    size_t memAvail = (size_t)sizeof(size_t) << 28;
     _memAvail = memAvail;
     _memUsage_Compress = memAvail;
     _memUsage_Decompress = memAvail;
@@ -55,7 +55,7 @@ public:
   bool _memUsage_WasSet;
   UInt64 _memUsage_Compress;
   UInt64 _memUsage_Decompress;
-  UInt64 _memAvail;
+  size_t _memAvail;
 
   bool SetCommonProperty(const UString &name, const PROPVARIANT &value, HRESULT &hres);
 
diff --git a/CPP/7zip/Archive/HfsHandler.cpp b/CPP/7zip/Archive/HfsHandler.cpp
index 4049fbc..46e0239 100644
--- a/CPP/7zip/Archive/HfsHandler.cpp
+++ b/CPP/7zip/Archive/HfsHandler.cpp
@@ -25,6 +25,9 @@
 #define Get32(p) GetBe32(p)
 #define Get64(p) GetBe64(p)
 
+#define Get16a(p) GetBe16a(p)
+#define Get32a(p) GetBe32a(p)
+
 namespace NArchive {
 namespace NHfs {
 
@@ -104,23 +107,21 @@ UInt32 CFork::Calc_NumBlocks_from_Extents() const
 {
   UInt32 num = 0;
   FOR_VECTOR (i, Extents)
-  {
     num += Extents[i].NumBlocks;
-  }
   return num;
 }
 
 bool CFork::Check_NumBlocks() const
 {
-  UInt32 num = 0;
+  UInt32 num = NumBlocks;
   FOR_VECTOR (i, Extents)
   {
-    UInt32 next = num + Extents[i].NumBlocks;
-    if (next < num)
+    const UInt32 cur = Extents[i].NumBlocks;
+    if (num < cur)
       return false;
-    num = next;
+    num -= cur;
   }
-  return num == NumBlocks;
+  return num == 0;
 }
 
 struct CIdIndexPair
@@ -175,7 +176,7 @@ static int Find_in_IdExtents(const CObjectVector<CIdExtents> &items, UInt32 id)
 
 bool CFork::Upgrade(const CObjectVector<CIdExtents> &items, UInt32 id)
 {
-  int index = Find_in_IdExtents(items, id);
+  const int index = Find_in_IdExtents(items, id);
   if (index < 0)
     return true;
   const CIdExtents &item = items[index];
@@ -188,8 +189,13 @@ bool CFork::Upgrade(const CObjectVector<CIdExtents> &items, UInt32 id)
 
 struct CVolHeader
 {
-  Byte Header[2];
-  UInt16 Version;
+  unsigned BlockSizeLog;
+  UInt32 NumFiles;
+  UInt32 NumFolders;
+  UInt32 NumBlocks;
+  UInt32 NumFreeBlocks;
+
+  bool Is_Hsfx_ver5;
   // UInt32 Attr;
   // UInt32 LastMountedVersion;
   // UInt32 JournalInfoBlock;
@@ -199,19 +205,13 @@ struct CVolHeader
   // UInt32 BackupTime;
   // UInt32 CheckedTime;
   
-  UInt32 NumFiles;
-  UInt32 NumFolders;
-  unsigned BlockSizeLog;
-  UInt32 NumBlocks;
-  UInt32 NumFreeBlocks;
-
   // UInt32 WriteCount;
   // UInt32 FinderInfo[8];
   // UInt64 VolID;
 
   UInt64 GetPhySize() const { return (UInt64)NumBlocks << BlockSizeLog; }
   UInt64 GetFreeSize() const { return (UInt64)NumFreeBlocks << BlockSizeLog; }
-  bool IsHfsX() const { return Version > 4; }
+  bool IsHfsX() const { return Is_Hsfx_ver5; }
 };
 
 inline void HfsTimeToFileTime(UInt32 hfsTime, FILETIME &ft)
@@ -463,18 +463,18 @@ public:
   bool UnsupportedFeature;
   bool ThereAreAltStreams;
   // bool CaseSensetive;
+  UInt32 MethodsMask;
   UString ResFileName;
 
   UInt64 SpecOffset;
-  UInt64 PhySize;
+  // UInt64 PhySize;
   UInt64 PhySize2;
   UInt64 ArcFileSize;
-  UInt32 MethodsMask;
 
   void Clear()
   {
     SpecOffset = 0;
-    PhySize = 0;
+    // PhySize = 0;
     PhySize2 = 0;
     ArcFileSize = 0;
     MethodsMask = 0;
@@ -596,7 +596,7 @@ HRESULT CDatabase::ReadFile(const CFork &fork, CByteBuffer &buf, IInStream *inSt
 {
   if (fork.NumBlocks >= Header.NumBlocks)
     return S_FALSE;
-  if ((ArcFileSize >> Header.BlockSizeLog) + 1 < fork.NumBlocks)
+  if (((ArcFileSize - SpecOffset) >> Header.BlockSizeLog) + 1 < fork.NumBlocks)
     return S_FALSE;
 
   const size_t totalSize = (size_t)fork.NumBlocks << Header.BlockSizeLog;
@@ -1328,28 +1328,26 @@ HRESULT CDatabase::LoadCatalog(const CFork &fork, const CObjectVector<CIdExtents
   return S_OK;
 }
 
-static const unsigned kHeaderPadSize = (1 << 10);
+static const unsigned kHeaderPadSize = 1 << 10;
 static const unsigned kMainHeaderSize = 512;
 static const unsigned kHfsHeaderSize = kHeaderPadSize + kMainHeaderSize;
 
+static const unsigned k_Signature_LE16_HFS_BD = 'B' + ((unsigned)'D' << 8);
+static const unsigned k_Signature_LE16_HPLUS  = 'H' + ((unsigned)'+' << 8);
+static const UInt32   k_Signature_LE32_HFSP_VER4 = 'H' + ((UInt32)'+' << 8) + ((UInt32)4 << 24);
+static const UInt32   k_Signature_LE32_HFSX_VER5 = 'H' + ((UInt32)'X' << 8) + ((UInt32)5 << 24);
+
 API_FUNC_static_IsArc IsArc_HFS(const Byte *p, size_t size)
 {
   if (size < kHfsHeaderSize)
     return k_IsArc_Res_NEED_MORE;
   p += kHeaderPadSize;
-  if (p[0] == 'B' && p[1] == 'D')
-  {
-    if (p[0x7C] != 'H' || p[0x7C + 1] != '+')
-      return k_IsArc_Res_NO;
-  }
-  else
-  {
-    if (p[0] != 'H' || (p[1] != '+' && p[1] != 'X'))
-      return k_IsArc_Res_NO;
-    UInt32 version = Get16(p + 2);
-    if (version < 4 || version > 5)
-      return k_IsArc_Res_NO;
-  }
+  const UInt32 sig = GetUi32(p);
+  if (sig != k_Signature_LE32_HFSP_VER4)
+  if (sig != k_Signature_LE32_HFSX_VER5)
+  if ((UInt16)sig != k_Signature_LE16_HFS_BD
+      || GetUi16(p + 0x7c) != k_Signature_LE16_HPLUS)
+    return k_IsArc_Res_NO;
   return k_IsArc_Res_YES;
 }
 }
@@ -1357,30 +1355,42 @@ API_FUNC_static_IsArc IsArc_HFS(const Byte *p, size_t size)
 HRESULT CDatabase::Open2(IInStream *inStream, IArchiveOpenCallback *progress)
 {
   Clear();
-  Byte buf[kHfsHeaderSize];
-  RINOK(ReadStream_FALSE(inStream, buf, kHfsHeaderSize))
-  {
-    for (unsigned i = 0; i < kHeaderPadSize; i++)
-      if (buf[i] != 0)
-        return S_FALSE;
-  }
-  const Byte *p = buf + kHeaderPadSize;
+  UInt32 buf32[kHfsHeaderSize / 4];
+  RINOK(ReadStream_FALSE(inStream, buf32, kHfsHeaderSize))
+  const Byte *p = (const Byte *)buf32 + kHeaderPadSize;
   CVolHeader &h = Header;
 
-  h.Header[0] = p[0];
-  h.Header[1] = p[1];
-
-  if (p[0] == 'B' && p[1] == 'D')
+  if (GetUi16a(p) == k_Signature_LE16_HFS_BD)
   {
     /*
     It's header for old HFS format.
     We don't support old HFS format, but we support
-    special HFS volume that contains embedded HFS+ volume
+    special HFS volume that contains embedded HFS+ volume.
+    HFS MDB : Master directory block
+    HFS VIB : Volume information block
+    some old images contain boot data with "LK" signature at start of buf32.
     */
-
-    if (p[0x7C] != 'H' || p[0x7C + 1] != '+')
+#if 1
+    // here we check first bytes of archive,
+    // because start data can contain signature of some another
+    // archive type that could have priority over HFS.
+    const void *buf_ptr = (const void *)buf32;
+    const unsigned sig = GetUi16a(buf_ptr);
+    if (sig != 'L' + ((unsigned)'K' << 8))
+    {
+      // some old HFS (non HFS+) files have no "LK" signature,
+      // but have non-zero data after 2 first bytes in start 1 KiB.
+      if (sig != 0)
+        return S_FALSE;
+/*
+      for (unsigned i = 0; i < kHeaderPadSize / 4; i++)
+        if (buf32[i] != 0)
+          return S_FALSE;
+*/
+    }
+#endif
+    if (GetUi16a(p + 0x7c) != k_Signature_LE16_HPLUS) // signature of embedded HFS+ volume
       return S_FALSE;
-
     /*
     h.CTime = Get32(p + 0x2);
     h.MTime = Get32(p + 0x6);
@@ -1399,80 +1409,104 @@ HRESULT CDatabase::Open2(IInStream *inStream, IArchiveOpenCallback *progress)
     h.NumFreeBlocks = Get16(p + 0x22);
     */
     
-    UInt32 blockSize = Get32(p + 0x14);
-    
-    {
-      unsigned i;
-      for (i = 9; ((UInt32)1 << i) != blockSize; i++)
-        if (i == 31)
-          return S_FALSE;
-      h.BlockSizeLog = i;
-    }
-    
-    h.NumBlocks = Get16(p + 0x12);
+    // v24.09: blockSize in old HFS image can be non-power of 2.
+    const UInt32 blockSize = Get32a(p + 0x14); // drAlBlkSiz
+    if (blockSize == 0 || (blockSize & 0x1ff))
+      return S_FALSE;
+    const unsigned numBlocks = Get16a(p + 0x12); // drNmAlBlks
+    // UInt16 drFreeBks = Get16a(p + 0x22); // number of unused allocation blocks
     /*
-    we suppose that it has the follwing layout
+    we suppose that it has the following layout:
     {
-      start block with header
-      [h.NumBlocks]
-      end block with header
+      start data with header
+      blocks[h.NumBlocks]
+      end data with header (probably size_of_footer <= blockSize).
     }
     */
-    PhySize2 = ((UInt64)h.NumBlocks + 2) << h.BlockSizeLog;
-
-    UInt32 startBlock = Get16(p + 0x7C + 2);
-    UInt32 blockCount = Get16(p + 0x7C + 4);
-    SpecOffset = (UInt64)(1 + startBlock) << h.BlockSizeLog;
-    UInt64 phy = SpecOffset + ((UInt64)blockCount << h.BlockSizeLog);
+    // PhySize2 = ((UInt64)numBlocks + 2) * blockSize;
+    const unsigned sector_of_FirstBlock = Get16a(p + 0x1c); // drAlBlSt : first allocation block in volume
+    const UInt32 startBlock = Get16a(p + 0x7c + 2);
+    const UInt32 blockCount = Get16a(p + 0x7c + 4);
+    SpecOffset = (UInt32)sector_of_FirstBlock << 9; // it's 32-bit here
+    PhySize2 = SpecOffset + (UInt64)numBlocks * blockSize;
+    SpecOffset += (UInt64)startBlock * blockSize;
+    // before v24.09: // SpecOffset = (UInt64)(1 + startBlock) * blockSize;
+    const UInt64 phy = SpecOffset + (UInt64)blockCount * blockSize;
     if (PhySize2 < phy)
-      PhySize2 = phy;
+        PhySize2 = phy;
+    UInt32 tail = 1 << 10; // at least 1 KiB tail (for footer MDB) is expected.
+    if (tail < blockSize)
+        tail = blockSize;
+    RINOK(InStream_GetSize_SeekToEnd(inStream, ArcFileSize))
+    if (ArcFileSize > PhySize2 &&
+        ArcFileSize - PhySize2 <= tail)
+    {
+      // data after blocks[h.NumBlocks] must contain another copy of MDB.
+      // In example where blockSize is not power of 2, we have
+      //   (ArcFileSize - PhySize2) < blockSize.
+      // We suppose that data after blocks[h.NumBlocks] is part of HFS archive.
+      // Maybe we should scan for footer MDB data (in last 1 KiB)?
+      PhySize2 = ArcFileSize;
+    }
     RINOK(InStream_SeekSet(inStream, SpecOffset))
-    RINOK(ReadStream_FALSE(inStream, buf, kHfsHeaderSize))
+    RINOK(ReadStream_FALSE(inStream, buf32, kHfsHeaderSize))
   }
 
-  if (p[0] != 'H' || (p[1] != '+' && p[1] != 'X'))
-    return S_FALSE;
-  h.Version = Get16(p + 2);
-  if (h.Version < 4 || h.Version > 5)
-    return S_FALSE;
-
-  // h.Attr = Get32(p + 4);
-  // h.LastMountedVersion = Get32(p + 8);
-  // h.JournalInfoBlock = Get32(p + 0xC);
-
-  h.CTime = Get32(p + 0x10);
-  h.MTime = Get32(p + 0x14);
-  // h.BackupTime = Get32(p + 0x18);
-  // h.CheckedTime = Get32(p + 0x1C);
-
-  h.NumFiles = Get32(p + 0x20);
-  h.NumFolders = Get32(p + 0x24);
-  
-  if (h.NumFolders > ((UInt32)1 << 29) ||
-      h.NumFiles > ((UInt32)1 << 30))
-    return S_FALSE;
-
-  RINOK(InStream_GetSize_SeekToEnd(inStream, ArcFileSize))
-
-  if (progress)
+  // HFS+ / HFSX volume header (starting from offset==1024):
   {
-    const UInt64 numFiles = (UInt64)h.NumFiles + h.NumFolders + 1;
-    RINOK(progress->SetTotal(&numFiles, NULL))
+    // v24.09: we use strict condition test for pair signature(Version):
+    // H+(4), HX(5):
+    const UInt32 sig = GetUi32a(p);
+    // h.Version = Get16(p + 2);
+    h.Is_Hsfx_ver5 = false;
+    if (sig != k_Signature_LE32_HFSP_VER4)
+    {
+      if (sig != k_Signature_LE32_HFSX_VER5)
+        return S_FALSE;
+      h.Is_Hsfx_ver5 = true;
+    }
   }
-
-  UInt32 blockSize = Get32(p + 0x28);
-
   {
+    const UInt32 blockSize = Get32a(p + 0x28);
     unsigned i;
     for (i = 9; ((UInt32)1 << i) != blockSize; i++)
       if (i == 31)
         return S_FALSE;
     h.BlockSizeLog = i;
   }
+#if 1
+  // HFS Plus DOCs: The first 1024 bytes are reserved for use as boot blocks
+  // v24.09: we don't check starting 1 KiB before old (HFS MDB) block ("BD" signture) .
+  //     but we still check starting 1 KiB before HFS+ / HFSX volume header.
+  // are there HFS+ / HFSX images with non-zero data in this reserved area?
+  {
+    for (unsigned i = 0; i < kHeaderPadSize / 4; i++)
+      if (buf32[i] != 0)
+        return S_FALSE;
+  }
+#endif
+  // h.Attr = Get32a(p + 4);
+  // h.LastMountedVersion = Get32a(p + 8);
+  // h.JournalInfoBlock = Get32a(p + 0xC);
+  h.CTime = Get32a(p + 0x10);
+  h.MTime = Get32a(p + 0x14);
+  // h.BackupTime = Get32a(p + 0x18);
+  // h.CheckedTime = Get32a(p + 0x1C);
+  h.NumFiles = Get32a(p + 0x20);
+  h.NumFolders = Get32a(p + 0x24);
+  if (h.NumFolders > ((UInt32)1 << 29) ||
+      h.NumFiles > ((UInt32)1 << 30))
+    return S_FALSE;
 
-  h.NumBlocks = Get32(p + 0x2C);
-  h.NumFreeBlocks = Get32(p + 0x30);
+  RINOK(InStream_GetSize_SeekToEnd(inStream, ArcFileSize))
+  if (progress)
+  {
+    const UInt64 numFiles = (UInt64)h.NumFiles + h.NumFolders + 1;
+    RINOK(progress->SetTotal(&numFiles, NULL))
+  }
 
+  h.NumBlocks = Get32a(p + 0x2C);
+  h.NumFreeBlocks = Get32a(p + 0x30);
   /*
   h.NextCalatlogNodeID = Get32(p + 0x40);
   h.WriteCount = Get32(p + 0x44);
@@ -1495,7 +1529,7 @@ HRESULT CDatabase::Open2(IInStream *inStream, IArchiveOpenCallback *progress)
     HeadersError = true;
   else
   {
-    HRESULT res = LoadExtentFile(extentsFork, inStream, overflowExtents);
+    const HRESULT res = LoadExtentFile(extentsFork, inStream, overflowExtents);
     if (res == S_FALSE)
       HeadersError = true;
     else if (res != S_OK)
@@ -1515,7 +1549,7 @@ HRESULT CDatabase::Open2(IInStream *inStream, IArchiveOpenCallback *progress)
   
   RINOK(LoadCatalog(catalogFork, overflowExtents, inStream, progress))
 
-  PhySize = Header.GetPhySize();
+  // PhySize = Header.GetPhySize();
   return S_OK;
 }
 
@@ -1591,7 +1625,7 @@ Z7_COM7F_IMF(CHandler::GetArchiveProperty(PROPID propID, PROPVARIANT *value))
     case kpidCharacts: MethodsMaskToProp(MethodsMask, prop); break;
     case kpidPhySize:
     {
-      UInt64 v = SpecOffset + PhySize;
+      UInt64 v = SpecOffset + Header.GetPhySize(); // PhySize;
       if (v < PhySize2)
         v = PhySize2;
       prop = v;
@@ -2529,7 +2563,7 @@ HRESULT CHandler::GetForkStream(const CFork &fork, ISequentialInStream **stream)
         return S_FALSE;
     }
     CSeekExtent se;
-    se.Phy = (UInt64)e.Pos << Header.BlockSizeLog;
+    se.Phy = SpecOffset + ((UInt64)e.Pos << Header.BlockSizeLog);
     se.Virt = virt;
     virt += cur;
     rem -= cur;
@@ -2540,7 +2574,7 @@ HRESULT CHandler::GetForkStream(const CFork &fork, ISequentialInStream **stream)
     return S_FALSE;
   
   CSeekExtent se;
-  se.Phy = 0;
+  se.Phy = 0; // = SpecOffset ?
   se.Virt = virt;
   extentStream->Extents.Add(se);
   extentStream->Stream = _stream;
diff --git a/CPP/7zip/Archive/LpHandler.cpp b/CPP/7zip/Archive/LpHandler.cpp
index c1a76b4..926b654 100644
--- a/CPP/7zip/Archive/LpHandler.cpp
+++ b/CPP/7zip/Archive/LpHandler.cpp
@@ -460,9 +460,11 @@ struct LpMetadataHeader
 
 static bool CheckSha256(const Byte *data, size_t size, const Byte *checksum)
 {
+  MY_ALIGN (16)
   CSha256 sha;
   Sha256_Init(&sha);
   Sha256_Update(&sha, data, size);
+  MY_ALIGN (16)
   Byte calced[32];
   Sha256_Final(&sha, calced);
   return memcmp(checksum, calced, 32) == 0;
@@ -470,6 +472,7 @@ static bool CheckSha256(const Byte *data, size_t size, const Byte *checksum)
 
 static bool CheckSha256_csOffset(Byte *data, size_t size, unsigned hashOffset)
 {
+  MY_ALIGN (4)
   Byte checksum[32];
   Byte *shaData = &data[hashOffset];
   memcpy(checksum, shaData, 32);
@@ -528,6 +531,7 @@ HRESULT CHandler::Open2(IInStream *stream)
 {
   RINOK(InStream_SeekSet(stream, LP_PARTITION_RESERVED_BYTES))
   {
+    MY_ALIGN (4)
     Byte buf[k_Geometry_Size];
     RINOK(ReadStream_FALSE(stream, buf, k_Geometry_Size))
     if (memcmp(buf, k_Signature, k_SignatureSize) != 0)
diff --git a/CPP/7zip/Archive/Rar/Rar5Handler.cpp b/CPP/7zip/Archive/Rar/Rar5Handler.cpp
index 34615c2..7d75aae 100644
--- a/CPP/7zip/Archive/Rar/Rar5Handler.cpp
+++ b/CPP/7zip/Archive/Rar/Rar5Handler.cpp
@@ -658,6 +658,9 @@ HRESULT CInArchive::ReadBlockHeader(CHeader &h)
     RINOK(ReadStream_Check(_buf, AES_BLOCK_SIZE * 2))
     memcpy(m_CryptoDecoder->_iv, _buf, AES_BLOCK_SIZE);
     RINOK(m_CryptoDecoder->Init())
+    // we call RAR5_AES_Filter with:
+    //   data_ptr  == aligned_ptr + 16
+    //   data_size == 16
     if (m_CryptoDecoder->Filter(_buf + AES_BLOCK_SIZE, AES_BLOCK_SIZE) != AES_BLOCK_SIZE)
       return E_FAIL;
     memcpy(buf, _buf + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
@@ -689,10 +692,14 @@ HRESULT CInArchive::ReadBlockHeader(CHeader &h)
       return E_OUTOFMEMORY;
     memcpy(_buf, buf, filled);
     const size_t rem = size - filled;
+    // if (m_CryptoMode), we add AES_BLOCK_SIZE here, because _iv is not included to size.
     AddToSeekValue(size + (m_CryptoMode ? AES_BLOCK_SIZE : 0));
     RINOK(ReadStream_Check(_buf + filled, rem))
     if (m_CryptoMode)
     {
+      // we call RAR5_AES_Filter with:
+      //   data_ptr  == aligned_ptr + 16
+      //   (rem) can be big
       if (m_CryptoDecoder->Filter(_buf + filled, (UInt32)rem) != rem)
         return E_FAIL;
 #if 1
@@ -1065,7 +1072,8 @@ HRESULT CUnpacker::Create(DECL_EXTERNAL_CODECS_LOC_VARS
 
     CMyComPtr<ICompressSetDecoderProperties2> csdp;
     RINOK(lzCoder.QueryInterface(IID_ICompressSetDecoderProperties2, &csdp))
-
+    if (!csdp)
+      return E_NOTIMPL;
     const unsigned ver = item.Get_AlgoVersion_HuffRev();
     if (ver > 1)
       return E_NOTIMPL;
@@ -3343,9 +3351,9 @@ Z7_COM7F_IMF(CHandler::SetProperties(const wchar_t * const *names, const PROPVAR
     }
     else if (name.IsPrefixedBy_Ascii_NoCase("memx"))
     {
-      UInt64 memAvail;
+      size_t memAvail;
       if (!NWindows::NSystem::GetRamSize(memAvail))
-        memAvail = (UInt64)(sizeof(size_t)) << 28;
+        memAvail = (size_t)sizeof(size_t) << 28;
       UInt64 v;
       if (!ParseSizeString(name.Ptr(4), prop, memAvail, v))
         return E_INVALIDARG;
diff --git a/CPP/7zip/Archive/XarHandler.cpp b/CPP/7zip/Archive/XarHandler.cpp
index 5112a16..6ef8941 100644
--- a/CPP/7zip/Archive/XarHandler.cpp
+++ b/CPP/7zip/Archive/XarHandler.cpp
@@ -3,6 +3,7 @@
 #include "StdAfx.h"
 
 #include "../../../C/Sha256.h"
+#include "../../../C/Sha512.h"
 #include "../../../C/CpuArch.h"
 
 #include "../../Common/ComTry.h"
@@ -41,22 +42,33 @@ Z7_CLASS_IMP_NOQIB_1(
   CInStreamWithSha256
   , ISequentialInStream
 )
+  bool _sha512Mode;
   CMyComPtr<ISequentialInStream> _stream;
-  CAlignedBuffer1 _sha;
+  CAlignedBuffer1 _sha256;
+  CAlignedBuffer1 _sha512;
   UInt64 _size;
 
-  CSha256 *Sha() { return (CSha256 *)(void *)(Byte *)_sha; }
+  CSha256 *Sha256() { return (CSha256 *)(void *)(Byte *)_sha256; }
+  CSha512 *Sha512() { return (CSha512 *)(void *)(Byte *)_sha512; }
 public:
-  CInStreamWithSha256(): _sha(sizeof(CSha256)) {}
+  CInStreamWithSha256():
+      _sha256(sizeof(CSha256)),
+      _sha512(sizeof(CSha512))
+      {}
   void SetStream(ISequentialInStream *stream) { _stream = stream;  }
-  void Init()
+  void Init(bool sha512Mode)
   {
+    _sha512Mode = sha512Mode;
     _size = 0;
-    Sha256_Init(Sha());
+    if (sha512Mode)
+      Sha512_Init(Sha512(), SHA512_DIGEST_SIZE);
+    else
+      Sha256_Init(Sha256());
   }
   void ReleaseStream() { _stream.Release(); }
   UInt64 GetSize() const { return _size; }
-  void Final(Byte *digest) { Sha256_Final(Sha(), digest); }
+  void Final256(Byte *digest) { Sha256_Final(Sha256(), digest); }
+  void Final512(Byte *digest) { Sha512_Final(Sha512(), digest, SHA512_DIGEST_SIZE); }
 };
 
 Z7_COM7F_IMF(CInStreamWithSha256::Read(void *data, UInt32 size, UInt32 *processedSize))
@@ -64,7 +76,10 @@ Z7_COM7F_IMF(CInStreamWithSha256::Read(void *data, UInt32 size, UInt32 *processe
   UInt32 realProcessedSize;
   const HRESULT result = _stream->Read(data, size, &realProcessedSize);
   _size += realProcessedSize;
-  Sha256_Update(Sha(), (const Byte *)data, realProcessedSize);
+  if (_sha512Mode)
+    Sha512_Update(Sha512(), (const Byte *)data, realProcessedSize);
+  else
+    Sha256_Update(Sha256(), (const Byte *)data, realProcessedSize);
   if (processedSize)
     *processedSize = realProcessedSize;
   return result;
@@ -75,25 +90,33 @@ Z7_CLASS_IMP_NOQIB_1(
   COutStreamWithSha256
   , ISequentialOutStream
 )
-  // bool _calculate;
+  bool _sha512Mode;
   CMyComPtr<ISequentialOutStream> _stream;
-  CAlignedBuffer1 _sha;
+  CAlignedBuffer1 _sha256;
+  CAlignedBuffer1 _sha512;
   UInt64 _size;
 
-  CSha256 *Sha() { return (CSha256 *)(void *)(Byte *)_sha; }
+  CSha256 *Sha256() { return (CSha256 *)(void *)(Byte *)_sha256; }
+  CSha512 *Sha512() { return (CSha512 *)(void *)(Byte *)_sha512; }
 public:
-  COutStreamWithSha256(): _sha(sizeof(CSha256)) {}
+  COutStreamWithSha256():
+      _sha256(sizeof(CSha256)),
+      _sha512(sizeof(CSha512))
+      {}
   void SetStream(ISequentialOutStream *stream) { _stream = stream; }
   void ReleaseStream() { _stream.Release(); }
-  void Init(/* bool calculate = true */ )
+  void Init(bool sha512Mode)
   {
-    // _calculate = calculate;
+    _sha512Mode = sha512Mode;
     _size = 0;
-    Sha256_Init(Sha());
+    if (sha512Mode)
+      Sha512_Init(Sha512(), SHA512_DIGEST_SIZE);
+    else
+      Sha256_Init(Sha256());
   }
-  void InitSha256() { Sha256_Init(Sha()); }
   UInt64 GetSize() const { return _size; }
-  void Final(Byte *digest) { Sha256_Final(Sha(), digest); }
+  void Final256(Byte *digest) { Sha256_Final(Sha256(), digest); }
+  void Final512(Byte *digest) { Sha512_Final(Sha512(), digest, SHA512_DIGEST_SIZE); }
 };
 
 Z7_COM7F_IMF(COutStreamWithSha256::Write(const void *data, UInt32 size, UInt32 *processedSize))
@@ -102,7 +125,10 @@ Z7_COM7F_IMF(COutStreamWithSha256::Write(const void *data, UInt32 size, UInt32 *
   if (_stream)
     result = _stream->Write(data, size, &size);
   // if (_calculate)
-  Sha256_Update(Sha(), (const Byte *)data, size);
+  if (_sha512Mode)
+    Sha512_Update(Sha512(), (const Byte *)data, size);
+  else
+    Sha256_Update(Sha256(), (const Byte *)data, size);
   _size += size;
   if (processedSize)
     *processedSize = size;
@@ -521,10 +547,11 @@ void CInStreamWithHash::SetStreamAndInit(ISequentialInStream *stream, int algo)
     inStreamSha1->Init();
     stream = inStreamSha1;
   }
-  else if (algo == XAR_CKSUM_SHA256)
+  else if (algo == XAR_CKSUM_SHA256
+        || algo == XAR_CKSUM_SHA512)
   {
     inStreamSha256->SetStream(stream);
-    inStreamSha256->Init();
+    inStreamSha256->Init(algo == XAR_CKSUM_SHA512);
     stream = inStreamSha256;
   }
   inStreamLim->SetStream(stream);
@@ -542,7 +569,14 @@ bool CInStreamWithHash::CheckHash(int algo, const Byte *digest_from_arc) const
   else if (algo == XAR_CKSUM_SHA256)
   {
     Byte digest[SHA256_DIGEST_SIZE];
-    inStreamSha256->Final(digest);
+    inStreamSha256->Final256(digest);
+    if (memcmp(digest, digest_from_arc, sizeof(digest)) != 0)
+      return false;
+  }
+  else if (algo == XAR_CKSUM_SHA512)
+  {
+    Byte digest[SHA512_DIGEST_SIZE];
+    inStreamSha256->Final512(digest);
     if (memcmp(digest, digest_from_arc, sizeof(digest)) != 0)
       return false;
   }
@@ -1151,11 +1185,12 @@ Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 numItems,
           outStreamSha1->SetStream(realOutStream);
           outStreamSha1->Init();
         }
-        else if (checksum_method == XAR_CKSUM_SHA256)
+        else if (checksum_method == XAR_CKSUM_SHA256
+              || checksum_method == XAR_CKSUM_SHA512)
         {
           outStreamLim->SetStream(outStreamSha256);
           outStreamSha256->SetStream(realOutStream);
-          outStreamSha256->Init();
+          outStreamSha256->Init(checksum_method == XAR_CKSUM_SHA512);
         }
         else
           outStreamLim->SetStream(realOutStream);
@@ -1209,8 +1244,15 @@ Z7_COM7F_IMF(CHandler::Extract(const UInt32 *indices, UInt32 numItems,
             else if (checksum_method == XAR_CKSUM_SHA256)
             {
               Byte digest[SHA256_DIGEST_SIZE];
-              outStreamSha256->Final(digest);
-              if (memcmp(digest, item.extracted_checksum.Data, SHA256_DIGEST_SIZE) != 0)
+              outStreamSha256->Final256(digest);
+              if (memcmp(digest, item.extracted_checksum.Data, sizeof(digest)) != 0)
+                opRes = NExtract::NOperationResult::kCRCError;
+            }
+            else if (checksum_method == XAR_CKSUM_SHA512)
+            {
+              Byte digest[SHA512_DIGEST_SIZE];
+              outStreamSha256->Final512(digest);
+              if (memcmp(digest, item.extracted_checksum.Data, sizeof(digest)) != 0)
                 opRes = NExtract::NOperationResult::kCRCError;
             }
             if (opRes == NExtract::NOperationResult::kOK)
diff --git a/CPP/7zip/Archive/XzHandler.cpp b/CPP/7zip/Archive/XzHandler.cpp
index 7ced4e1..907376c 100644
--- a/CPP/7zip/Archive/XzHandler.cpp
+++ b/CPP/7zip/Archive/XzHandler.cpp
@@ -967,9 +967,9 @@ Z7_COM7F_IMF(CHandler::GetStream(UInt32 index, ISequentialInStream **stream))
       || _maxBlocksSize != (size_t)_maxBlocksSize)
     return S_FALSE;
 
-  UInt64 memSize;
+  size_t memSize;
   if (!NSystem::GetRamSize(memSize))
-    memSize = (UInt64)(sizeof(size_t)) << 28;
+    memSize = (size_t)sizeof(size_t) << 28;
   {
     if (_maxBlocksSize > memSize / 4)
       return S_FALSE;
diff --git a/CPP/7zip/Bundles/Format7zF/Arc.mak b/CPP/7zip/Bundles/Format7zF/Arc.mak
index 3d8a430..7166ab3 100644
--- a/CPP/7zip/Bundles/Format7zF/Arc.mak
+++ b/CPP/7zip/Bundles/Format7zF/Arc.mak
@@ -4,6 +4,7 @@ COMMON_OBJS = \
   $O\DynLimBuf.obj \
   $O\IntToString.obj \
   $O\LzFindPrepare.obj \
+  $O\Md5Reg.obj \
   $O\MyMap.obj \
   $O\MyString.obj \
   $O\MyVector.obj \
@@ -11,6 +12,9 @@ COMMON_OBJS = \
   $O\NewHandler.obj \
   $O\Sha1Reg.obj \
   $O\Sha256Reg.obj \
+  $O\Sha3Reg.obj \
+  $O\Sha512Reg.obj \
+  $O\Sha512Prepare.obj \
   $O\StringConvert.obj \
   $O\StringToInt.obj \
   $O\UTFConvert.obj \
@@ -274,6 +278,7 @@ C_OBJS = \
   $O\Lzma2Enc.obj \
   $O\LzmaDec.obj \
   $O\LzmaEnc.obj \
+  $O\Md5.obj \
   $O\MtCoder.obj \
   $O\MtDec.obj \
   $O\Ppmd7.obj \
@@ -283,6 +288,9 @@ C_OBJS = \
   $O\Ppmd8.obj \
   $O\Ppmd8Dec.obj \
   $O\Ppmd8Enc.obj \
+  $O\Sha3.obj \
+  $O\Sha512.obj \
+  $O\Sha512Opt.obj \
   $O\Sort.obj \
   $O\SwapBytes.obj \
   $O\Threads.obj \
diff --git a/CPP/7zip/Bundles/Format7zF/Arc_gcc.mak b/CPP/7zip/Bundles/Format7zF/Arc_gcc.mak
index ff5a3f9..746aaff 100644
--- a/CPP/7zip/Bundles/Format7zF/Arc_gcc.mak
+++ b/CPP/7zip/Bundles/Format7zF/Arc_gcc.mak
@@ -45,6 +45,7 @@ COMMON_OBJS = \
   $O/DynLimBuf.o \
   $O/IntToString.o \
   $O/LzFindPrepare.o \
+  $O/Md5Reg.o \
   $O/MyMap.o \
   $O/MyString.o \
   $O/MyVector.o \
@@ -54,6 +55,9 @@ COMMON_OBJS = \
   $O/Sha1Reg.o \
   $O/Sha256Prepare.o \
   $O/Sha256Reg.o \
+  $O/Sha3Reg.o \
+  $O/Sha512Prepare.o \
+  $O/Sha512Reg.o \
   $O/StringConvert.o \
   $O/StringToInt.o \
   $O/UTFConvert.o \
@@ -337,6 +341,7 @@ C_OBJS = \
   $O/Lzma2Enc.o \
   $O/LzmaDec.o \
   $O/LzmaEnc.o \
+  $O/Md5.o \
   $O/MtCoder.o \
   $O/MtDec.o \
   $O/Ppmd7.o \
@@ -350,6 +355,9 @@ C_OBJS = \
   $O/Sha1Opt.o \
   $O/Sha256.o \
   $O/Sha256Opt.o \
+  $O/Sha3.o \
+  $O/Sha512.o \
+  $O/Sha512Opt.o \
   $O/Sort.o \
   $O/SwapBytes.o \
   $O/Xxh64.o \
diff --git a/CPP/7zip/Bundles/Format7zF/Format7z.dsp b/CPP/7zip/Bundles/Format7zF/Format7z.dsp
index 6e28288..0bf976c 100644
--- a/CPP/7zip/Bundles/Format7zF/Format7z.dsp
+++ b/CPP/7zip/Bundles/Format7zF/Format7z.dsp
@@ -287,6 +287,10 @@ SOURCE=..\..\..\Common\LzFindPrepare.cpp
 # End Source File
 # Begin Source File
 
+SOURCE=..\..\..\Common\Md5Reg.cpp
+# End Source File
+# Begin Source File
+
 SOURCE=..\..\..\Common\MyBuffer.h
 # End Source File
 # Begin Source File
@@ -383,6 +387,18 @@ SOURCE=..\..\..\Common\Sha256Reg.cpp
 # End Source File
 # Begin Source File
 
+SOURCE=..\..\..\Common\Sha3Reg.cpp
+# End Source File
+# Begin Source File
+
+SOURCE=..\..\..\Common\Sha512Prepare.cpp
+# End Source File
+# Begin Source File
+
+SOURCE=..\..\..\Common\Sha512Reg.cpp
+# End Source File
+# Begin Source File
+
 SOURCE=..\..\..\Common\StringConvert.cpp
 # End Source File
 # Begin Source File
@@ -2029,6 +2045,26 @@ SOURCE=..\..\..\..\C\LzmaEnc.h
 # End Source File
 # Begin Source File
 
+SOURCE=..\..\..\..\C\Md5.c
+
+!IF  "$(CFG)" == "7z - Win32 Release"
+
+# ADD CPP /O2
+# SUBTRACT CPP /YX /Yc /Yu
+
+!ELSEIF  "$(CFG)" == "7z - Win32 Debug"
+
+# SUBTRACT CPP /YX /Yc /Yu
+
+!ENDIF 
+
+# End Source File
+# Begin Source File
+
+SOURCE=..\..\..\..\C\Md5.h
+# End Source File
+# Begin Source File
+
 SOURCE=..\..\..\..\C\MtCoder.c
 # SUBTRACT CPP /YX /Yc /Yu
 # End Source File
@@ -2230,6 +2266,62 @@ SOURCE=..\..\..\..\C\Sha256.h
 # End Source File
 # Begin Source File
 
+SOURCE=..\..\..\..\C\Sha3.c
+
+!IF  "$(CFG)" == "7z - Win32 Release"
+
+# ADD CPP /O2
+# SUBTRACT CPP /YX /Yc /Yu
+
+!ELSEIF  "$(CFG)" == "7z - Win32 Debug"
+
+# SUBTRACT CPP /YX /Yc /Yu
+
+!ENDIF 
+
+# End Source File
+# Begin Source File
+
+SOURCE=..\..\..\..\C\Sha3.h
+# End Source File
+# Begin Source File
+
+SOURCE=..\..\..\..\C\Sha512.c
+
+!IF  "$(CFG)" == "7z - Win32 Release"
+
+# ADD CPP /O2
+# SUBTRACT CPP /YX /Yc /Yu
+
+!ELSEIF  "$(CFG)" == "7z - Win32 Debug"
+
+# SUBTRACT CPP /YX /Yc /Yu
+
+!ENDIF 
+
+# End Source File
+# Begin Source File
+
+SOURCE=..\..\..\..\C\Sha512.h
+# End Source File
+# Begin Source File
+
+SOURCE=..\..\..\..\C\Sha512Opt.c
+
+!IF  "$(CFG)" == "7z - Win32 Release"
+
+# ADD CPP /O2
+# SUBTRACT CPP /YX /Yc /Yu
+
+!ELSEIF  "$(CFG)" == "7z - Win32 Debug"
+
+# SUBTRACT CPP /YX /Yc /Yu
+
+!ENDIF 
+
+# End Source File
+# Begin Source File
+
 SOURCE=..\..\..\..\C\Sort.c
 
 !IF  "$(CFG)" == "7z - Win32 Release"
diff --git a/CPP/7zip/Bundles/LzmaCon/LzmaAlone.cpp b/CPP/7zip/Bundles/LzmaCon/LzmaAlone.cpp
index b4bd2de..e43e8b1 100644
--- a/CPP/7zip/Bundles/LzmaCon/LzmaAlone.cpp
+++ b/CPP/7zip/Bundles/LzmaCon/LzmaAlone.cpp
@@ -59,13 +59,13 @@ static const char * const kHelpString =
     "  b : Benchmark\n"
     "<switches>\n"
     "  -a{N}  : set compression mode : [0, 1] : default = 1 (max)\n"
-    "  -d{N}  : set dictionary size : [12, 30] : default = 24 (16 MiB)\n"
+    "  -d{N}  : set dictionary size : [12, 31] : default = 24 (16 MiB)\n"
     "  -fb{N} : set number of fast bytes : [5, 273] : default = 128\n"
     "  -mc{N} : set number of cycles for match finder\n"
     "  -lc{N} : set number of literal context bits : [0, 8] : default = 3\n"
     "  -lp{N} : set number of literal pos bits : [0, 4] : default = 0\n"
     "  -pb{N} : set number of pos bits : [0, 4] : default = 2\n"
-    "  -mf{M} : set match finder: [hc4, bt2, bt3, bt4] : default = bt4\n"
+    "  -mf{M} : set match finder: [hc4, hc5, bt2, bt3, bt4, bt5] : default = bt4\n"
     "  -mt{N} : set number of CPU threads\n"
     "  -eos   : write end of stream marker\n"
     "  -si    : read data from stdin\n"
@@ -372,8 +372,8 @@ static int main2(int numArgs, const char *args[])
     return 0;
   }
 
-  bool stdInMode = parser[NKey::kStdIn].ThereIs;
-  bool stdOutMode = parser[NKey::kStdOut].ThereIs;
+  const bool stdInMode = parser[NKey::kStdIn].ThereIs;
+  const bool stdOutMode = parser[NKey::kStdOut].ThereIs;
 
   if (!stdOutMode)
     PrintTitle();
@@ -394,7 +394,16 @@ static int main2(int numArgs, const char *args[])
     UInt32 dictLog;
     const UString &s = parser[NKey::kDict].PostStrings[0];
     dictLog = GetNumber(s);
-    dict = 1 << dictLog;
+    if (dictLog >= 32)
+      throw "unsupported dictionary size";
+    // we only want to use dictionary sizes that are powers of 2,
+    // because 7-zip only recognizes such dictionary sizes in the lzma header.#if 0
+#if 0
+    if (dictLog == 32)
+      dict = (UInt32)3840 << 20;
+    else
+#endif
+    dict = (UInt32)1 << dictLog;
     dictDefined = true;
     AddProp(props2, "d", s);
   }
@@ -522,7 +531,7 @@ static int main2(int numArgs, const char *args[])
 
   if (encodeMode && !dictDefined)
   {
-    dict = 1 << kDictSizeLog;
+    dict = (UInt32)1 << kDictSizeLog;
     if (fileSizeDefined)
     {
       unsigned i;
diff --git a/CPP/7zip/Common/CreateCoder.cpp b/CPP/7zip/Common/CreateCoder.cpp
index bf7b04e..93113a0 100644
--- a/CPP/7zip/Common/CreateCoder.cpp
+++ b/CPP/7zip/Common/CreateCoder.cpp
@@ -35,7 +35,7 @@ void RegisterCodec(const CCodecInfo *codecInfo) throw()
     g_Codecs[g_NumCodecs++] = codecInfo;
 }
 
-static const unsigned kNumHashersMax = 16;
+static const unsigned kNumHashersMax = 32;
 extern
 unsigned g_NumHashers;
 unsigned g_NumHashers = 0;
diff --git a/CPP/7zip/Common/MethodProps.h b/CPP/7zip/Common/MethodProps.h
index 3c332d6..a52f4bc 100644
--- a/CPP/7zip/Common/MethodProps.h
+++ b/CPP/7zip/Common/MethodProps.h
@@ -125,7 +125,7 @@ public:
 
   UInt32 Get_Lzma_Algo() const
   {
-    int i = FindProp(NCoderPropID::kAlgorithm);
+    const int i = FindProp(NCoderPropID::kAlgorithm);
     if (i >= 0)
     {
       const NWindows::NCOM::CPropVariant &val = Props[(unsigned)i].Value;
@@ -141,11 +141,11 @@ public:
     if (Get_DicSize(v))
       return v;
     const unsigned level = GetLevel();
-    const UInt32 dictSize =
-        ( level <= 3 ? ((UInt32)1 << (level * 2 + 16)) :
-        ( level <= 6 ? ((UInt32)1 << (level + 19)) :
-        ( level <= 7 ? ((UInt32)1 << 25) : ((UInt32)1 << 26)
-        )));
+    const UInt32 dictSize = level <= 4 ?
+        (UInt32)1 << (level * 2 + 16) :
+        level <= sizeof(size_t) / 2 + 4 ?
+          (UInt32)1 << (level + 20) :
+          (UInt32)1 << (sizeof(size_t) / 2 + 24);
     return dictSize;
   }
 
diff --git a/CPP/7zip/Crypto/Rar5Aes.cpp b/CPP/7zip/Crypto/Rar5Aes.cpp
index 26c6100..34ea4ff 100644
--- a/CPP/7zip/Crypto/Rar5Aes.cpp
+++ b/CPP/7zip/Crypto/Rar5Aes.cpp
@@ -8,16 +8,17 @@
 #include "../../Windows/Synchronization.h"
 #endif
 
-#include "Rar5Aes.h"
 #include "HmacSha256.h"
+#include "Rar5Aes.h"
+
+#define MY_ALIGN_FOR_SHA256  MY_ALIGN(16)
 
 namespace NCrypto {
 namespace NRar5 {
 
 static const unsigned kNumIterationsLog_Max = 24;
-
-static const unsigned kPswCheckCsumSize = 4;
-static const unsigned kCheckSize = kPswCheckSize + kPswCheckCsumSize;
+static const unsigned kPswCheckCsumSize32 = 1;
+static const unsigned kCheckSize32 = kPswCheckSize32 + kPswCheckCsumSize32;
 
 CKey::CKey():
     _needCalc(true),
@@ -27,15 +28,29 @@ CKey::CKey():
     _salt[i] = 0;
 }
 
+CKey::~CKey()
+{
+  Wipe();
+}
+
+void CKey::Wipe()
+{
+  _password.Wipe();
+  Z7_memset_0_ARRAY(_salt);
+  // Z7_memset_0_ARRAY(_key32);
+  // Z7_memset_0_ARRAY(_check_Calced32);
+  // Z7_memset_0_ARRAY(_hashKey32);
+  CKeyBase::Wipe();
+}
+
 CDecoder::CDecoder(): CAesCbcDecoder(kAesKeySize) {}
 
 static unsigned ReadVarInt(const Byte *p, unsigned maxSize, UInt64 *val)
 {
   *val = 0;
-
   for (unsigned i = 0; i < maxSize && i < 10;)
   {
-    Byte b = p[i];
+    const Byte b = p[i];
     *val |= (UInt64)(b & 0x7F) << (7 * i);
     i++;
     if ((b & 0x80) == 0)
@@ -64,7 +79,7 @@ HRESULT CDecoder::SetDecoderProps(const Byte *p, unsigned size, bool includeIV,
   size -= num;
 
   bool isCheck = IsThereCheck();
-  if (size != 1 + kSaltSize + (includeIV ? AES_BLOCK_SIZE : 0) + (unsigned)(isCheck ? kCheckSize : 0))
+  if (size != 1 + kSaltSize + (includeIV ? AES_BLOCK_SIZE : 0) + (unsigned)(isCheck ? kCheckSize32 * 4 : 0))
     return E_NOTIMPL;
 
   if (_numIterationsLog != p[0])
@@ -93,19 +108,21 @@ HRESULT CDecoder::SetDecoderProps(const Byte *p, unsigned size, bool includeIV,
   
   if (isCheck)
   {
-    memcpy(_check, p, kPswCheckSize);
+    memcpy(_check32, p, sizeof(_check32));
+    MY_ALIGN_FOR_SHA256
     CSha256 sha;
+    MY_ALIGN_FOR_SHA256
     Byte digest[SHA256_DIGEST_SIZE];
     Sha256_Init(&sha);
-    Sha256_Update(&sha, _check, kPswCheckSize);
+    Sha256_Update(&sha, (const Byte *)_check32, sizeof(_check32));
     Sha256_Final(&sha, digest);
-    _canCheck = (memcmp(digest, p + kPswCheckSize, kPswCheckCsumSize) == 0);
+    _canCheck = (memcmp(digest, p + sizeof(_check32), kPswCheckCsumSize32 * 4) == 0);
     if (_canCheck && isService)
     {
       // There was bug in RAR 5.21- : PswCheck field in service records ("QO") contained zeros.
       // so we disable password checking for such bad records.
       _canCheck = false;
-      for (unsigned i = 0; i < kPswCheckSize; i++)
+      for (unsigned i = 0; i < kPswCheckSize32 * 4; i++)
         if (p[i] != 0)
         {
           _canCheck = true;
@@ -132,7 +149,7 @@ void CDecoder::SetPassword(const Byte *data, size_t size)
 Z7_COM7F_IMF(CDecoder::Init())
 {
   CalcKey_and_CheckPassword();
-  RINOK(SetKey(_key, kAesKeySize))
+  RINOK(SetKey((const Byte *)_key32, kAesKeySize))
   RINOK(SetInitVector(_iv, AES_BLOCK_SIZE))
   return CAesCoder::Init();
 }
@@ -140,27 +157,27 @@ Z7_COM7F_IMF(CDecoder::Init())
 
 UInt32 CDecoder::Hmac_Convert_Crc32(UInt32 crc) const
 {
-  MY_ALIGN (16)
+  MY_ALIGN_FOR_SHA256
   NSha256::CHmac ctx;
-  ctx.SetKey(_hashKey, NSha256::kDigestSize);
+  ctx.SetKey((const Byte *)_hashKey32, NSha256::kDigestSize);
   UInt32 v;
-  SetUi32(&v, crc)
+  SetUi32a(&v, crc)
   ctx.Update((const Byte *)&v, 4);
-  MY_ALIGN (16)
+  MY_ALIGN_FOR_SHA256
   UInt32 h[SHA256_NUM_DIGEST_WORDS];
   ctx.Final((Byte *)h);
   crc = 0;
   for (unsigned i = 0; i < SHA256_NUM_DIGEST_WORDS; i++)
-    crc ^= (UInt32)GetUi32(h + i);
+    crc ^= (UInt32)GetUi32a(h + i);
   return crc;
 }
 
 
 void CDecoder::Hmac_Convert_32Bytes(Byte *data) const
 {
-  MY_ALIGN (16)
+  MY_ALIGN_FOR_SHA256
   NSha256::CHmac ctx;
-  ctx.SetKey(_hashKey, NSha256::kDigestSize);
+  ctx.SetKey((const Byte *)_hashKey32, NSha256::kDigestSize);
   ctx.Update(data, NSha256::kDigestSize);
   ctx.Final(data);
 }
@@ -190,30 +207,31 @@ bool CDecoder::CalcKey_and_CheckPassword()
     
     if (_needCalc)
     {
-      Byte pswCheck[SHA256_DIGEST_SIZE];
-
+      MY_ALIGN_FOR_SHA256
+      UInt32 pswCheck[SHA256_NUM_DIGEST_WORDS];
       {
         // Pbkdf HMAC-SHA-256
-
-        MY_ALIGN (16)
+        MY_ALIGN_FOR_SHA256
         NSha256::CHmac baseCtx;
         baseCtx.SetKey(_password, _password.Size());
-        
-        NSha256::CHmac ctx = baseCtx;
+        MY_ALIGN_FOR_SHA256
+        NSha256::CHmac ctx;
+        ctx = baseCtx;
         ctx.Update(_salt, sizeof(_salt));
         
-        MY_ALIGN (16)
-        Byte u[NSha256::kDigestSize];
-        MY_ALIGN (16)
-        Byte key[NSha256::kDigestSize];
+        MY_ALIGN_FOR_SHA256
+        UInt32 u[SHA256_NUM_DIGEST_WORDS];
+        MY_ALIGN_FOR_SHA256
+        UInt32 key[SHA256_NUM_DIGEST_WORDS];
         
-        u[0] = 0;
-        u[1] = 0;
-        u[2] = 0;
-        u[3] = 1;
+        // u[0] = 0;
+        // u[1] = 0;
+        // u[2] = 0;
+        // u[3] = 1;
+        SetUi32a(u, 0x1000000)
         
-        ctx.Update(u, 4);
-        ctx.Final(u);
+        ctx.Update((const Byte *)(const void *)u, 4);
+        ctx.Final((Byte *)(void *)u);
         
         memcpy(key, u, NSha256::kDigestSize);
         
@@ -221,35 +239,24 @@ bool CDecoder::CalcKey_and_CheckPassword()
         
         for (unsigned i = 0; i < 3; i++)
         {
-          UInt32 j = numIterations;
-          
-          for (; j != 0; j--)
+          for (; numIterations != 0; numIterations--)
           {
             ctx = baseCtx;
-            ctx.Update(u, NSha256::kDigestSize);
-            ctx.Final(u);
-            for (unsigned s = 0; s < NSha256::kDigestSize; s++)
+            ctx.Update((const Byte *)(const void *)u, NSha256::kDigestSize);
+            ctx.Final((Byte *)(void *)u);
+            for (unsigned s = 0; s < Z7_ARRAY_SIZE(u); s++)
               key[s] ^= u[s];
           }
           
           // RAR uses additional iterations for additional keys
-          memcpy((i == 0 ? _key : (i == 1 ? _hashKey : pswCheck)), key, NSha256::kDigestSize);
+          memcpy(i == 0 ? _key32 : i == 1 ? _hashKey32 : pswCheck,
+              key, NSha256::kDigestSize);
           numIterations = 16;
         }
       }
-
-      {
-        unsigned i;
-       
-        for (i = 0; i < kPswCheckSize; i++)
-          _check_Calced[i] = pswCheck[i];
-      
-        for (i = kPswCheckSize; i < SHA256_DIGEST_SIZE; i++)
-          _check_Calced[i & (kPswCheckSize - 1)] ^= pswCheck[i];
-      }
-
+     _check_Calced32[0] = pswCheck[0] ^ pswCheck[2] ^ pswCheck[4] ^ pswCheck[6];
+     _check_Calced32[1] = pswCheck[1] ^ pswCheck[3] ^ pswCheck[5] ^ pswCheck[7];
       _needCalc = false;
-      
       {
         MT_LOCK
         g_Key = *this;
@@ -258,7 +265,7 @@ bool CDecoder::CalcKey_and_CheckPassword()
   }
   
   if (IsThereCheck() && _canCheck)
-    return (memcmp(_check_Calced, _check, kPswCheckSize) == 0);
+    return memcmp(_check_Calced32, _check32, sizeof(_check32)) == 0;
   return true;
 }
 
diff --git a/CPP/7zip/Crypto/Rar5Aes.h b/CPP/7zip/Crypto/Rar5Aes.h
index 3cd7992..c6059aa 100644
--- a/CPP/7zip/Crypto/Rar5Aes.h
+++ b/CPP/7zip/Crypto/Rar5Aes.h
@@ -13,7 +13,7 @@ namespace NCrypto {
 namespace NRar5 {
 
 const unsigned kSaltSize = 16;
-const unsigned kPswCheckSize = 8;
+const unsigned kPswCheckSize32 = 2;
 const unsigned kAesKeySize = 32;
 
 namespace NCryptoFlags
@@ -22,48 +22,47 @@ namespace NCryptoFlags
   const unsigned kUseMAC   = 1 << 1;
 }
 
-struct CKey
+struct CKeyBase
 {
-  bool _needCalc;
+protected:
+  UInt32 _key32[kAesKeySize / 4];
+  UInt32 _hashKey32[SHA256_NUM_DIGEST_WORDS];
+  UInt32 _check_Calced32[kPswCheckSize32];
 
-  unsigned _numIterationsLog;
-  Byte _salt[kSaltSize];
-  CByteBuffer _password;
+  void Wipe()
+  {
+    memset(this, 0, sizeof(*this));
+  }
   
-  Byte _key[kAesKeySize];
-  Byte _check_Calced[kPswCheckSize];
-  Byte _hashKey[SHA256_DIGEST_SIZE];
-
-  void CopyCalcedKeysFrom(const CKey &k)
+  void CopyCalcedKeysFrom(const CKeyBase &k)
   {
-    memcpy(_key, k._key, sizeof(_key));
-    memcpy(_check_Calced, k._check_Calced, sizeof(_check_Calced));
-    memcpy(_hashKey, k._hashKey, sizeof(_hashKey));
+    *this = k;
   }
+};
 
+struct CKey: public CKeyBase
+{
+  CByteBuffer _password;
+  bool _needCalc;
+  unsigned _numIterationsLog;
+  Byte _salt[kSaltSize];
+  
   bool IsKeyEqualTo(const CKey &key)
   {
-    return (_numIterationsLog == key._numIterationsLog
+    return _numIterationsLog == key._numIterationsLog
         && memcmp(_salt, key._salt, sizeof(_salt)) == 0
-        && _password == key._password);
+        && _password == key._password;
   }
-  
-  CKey();
 
-  void Wipe()
-  {
-    _password.Wipe();
-    Z7_memset_0_ARRAY(_salt);
-    Z7_memset_0_ARRAY(_key);
-    Z7_memset_0_ARRAY(_check_Calced);
-    Z7_memset_0_ARRAY(_hashKey);
-  }
+  CKey();
+  ~CKey();
+  
+  void Wipe();
 
 #ifdef Z7_CPP_IS_SUPPORTED_default
   // CKey(const CKey &) = default;
   CKey& operator =(const CKey &) = default;
 #endif
-  ~CKey() { Wipe(); }
 };
 
 
@@ -71,11 +70,11 @@ class CDecoder Z7_final:
   public CAesCbcDecoder,
   public CKey
 {
-  Byte _check[kPswCheckSize];
+  UInt32 _check32[kPswCheckSize32];
   bool _canCheck;
   UInt64 Flags;
 
-  bool IsThereCheck() const { return ((Flags & NCryptoFlags::kPswCheck) != 0); }
+  bool IsThereCheck() const { return (Flags & NCryptoFlags::kPswCheck) != 0; }
 public:
   Byte _iv[AES_BLOCK_SIZE];
   
diff --git a/CPP/7zip/Crypto/RarAes.cpp b/CPP/7zip/Crypto/RarAes.cpp
index 878ea3a..e63f82c 100644
--- a/CPP/7zip/Crypto/RarAes.cpp
+++ b/CPP/7zip/Crypto/RarAes.cpp
@@ -111,7 +111,8 @@ static void UpdatePswDataSha1(Byte *data)
   
   for (i = 16; i < 80; i++)
   {
-    WW(i) = rotlFixed(WW((i)-3) ^ WW((i)-8) ^ WW((i)-14) ^ WW((i)-16), 1);
+    const UInt32 t = WW((i)-3) ^ WW((i)-8) ^ WW((i)-14) ^ WW((i)-16);
+    WW(i) = rotlFixed(t, 1);
   }
   
   for (i = 0; i < SHA1_NUM_BLOCK_WORDS; i++)
@@ -128,6 +129,7 @@ void CDecoder::CalcKey()
 
   const unsigned kSaltSize = 8;
   
+  MY_ALIGN (16)
   Byte buf[kPasswordLen_Bytes_MAX + kSaltSize];
   
   if (_password.Size() != 0)
@@ -148,7 +150,7 @@ void CDecoder::CalcKey()
   MY_ALIGN (16)
   Byte digest[NSha1::kDigestSize];
   // rar reverts hash for sha.
-  const UInt32 kNumRounds = ((UInt32)1 << 18);
+  const UInt32 kNumRounds = (UInt32)1 << 18;
   UInt32 pos = 0;
   UInt32 i;
   for (i = 0; i < kNumRounds; i++)
@@ -171,8 +173,14 @@ void CDecoder::CalcKey()
       }
     }
     pos += (UInt32)rawSize;
+#if 1
+    UInt32 pswNum;
+    SetUi32a(&pswNum, i)
+    sha.Update((const Byte *)&pswNum, 3);
+#else
     Byte pswNum[3] = { (Byte)i, (Byte)(i >> 8), (Byte)(i >> 16) };
     sha.Update(pswNum, 3);
+#endif
     pos += 3;
     if (i % (kNumRounds / 16) == 0)
     {
diff --git a/CPP/7zip/Crypto/ZipStrong.cpp b/CPP/7zip/Crypto/ZipStrong.cpp
index 59698d8..c4e8311 100644
--- a/CPP/7zip/Crypto/ZipStrong.cpp
+++ b/CPP/7zip/Crypto/ZipStrong.cpp
@@ -24,30 +24,31 @@ static const UInt16 kAES128 = 0x660E;
   if (method != AES && method != 3DES), probably we need another code.
 */
 
-static void DeriveKey2(const Byte *digest, Byte c, Byte *dest)
+static void DeriveKey2(const UInt32 *digest32, Byte c, UInt32 *dest32)
 {
+  const unsigned kBufSize = 64;
   MY_ALIGN (16)
-  Byte buf[64];
-  memset(buf, c, 64);
-  for (unsigned i = 0; i < NSha1::kDigestSize; i++)
-    buf[i] ^= digest[i];
+  UInt32 buf32[kBufSize / 4];
+  memset(buf32, c, kBufSize);
+  for (unsigned i = 0; i < NSha1::kNumDigestWords; i++)
+    buf32[i] ^= digest32[i];
   MY_ALIGN (16)
   NSha1::CContext sha;
   sha.Init();
-  sha.Update(buf, 64);
-  sha.Final(dest);
+  sha.Update((const Byte *)buf32, kBufSize);
+  sha.Final((Byte *)dest32);
 }
  
 static void DeriveKey(NSha1::CContext &sha, Byte *key)
 {
   MY_ALIGN (16)
-  Byte digest[NSha1::kDigestSize];
-  sha.Final(digest);
+  UInt32 digest32[NSha1::kNumDigestWords];
+  sha.Final((Byte *)digest32);
   MY_ALIGN (16)
-  Byte temp[NSha1::kDigestSize * 2];
-  DeriveKey2(digest, 0x36, temp);
-  DeriveKey2(digest, 0x5C, temp + NSha1::kDigestSize);
-  memcpy(key, temp, 32);
+  UInt32 temp32[NSha1::kNumDigestWords * 2];
+  DeriveKey2(digest32, 0x36, temp32);
+  DeriveKey2(digest32, 0x5C, temp32 + NSha1::kNumDigestWords);
+  memcpy(key, temp32, 32);
 }
 
 void CKeyInfo::SetPassword(const Byte *data, UInt32 size)
@@ -122,24 +123,24 @@ HRESULT CDecoder::Init_and_CheckPassword(bool &passwOK)
   passwOK = false;
   if (_remSize < 16)
     return E_NOTIMPL;
-  Byte *p = _bufAligned;
-  const unsigned format = GetUi16(p);
+  Byte * const p = _bufAligned;
+  const unsigned format = GetUi16a(p);
   if (format != 3)
     return E_NOTIMPL;
-  unsigned algId = GetUi16(p + 2);
+  unsigned algId = GetUi16a(p + 2);
   if (algId < kAES128)
     return E_NOTIMPL;
   algId -= kAES128;
   if (algId > 2)
     return E_NOTIMPL;
-  const unsigned bitLen = GetUi16(p + 4);
-  const unsigned flags = GetUi16(p + 6);
+  const unsigned bitLen = GetUi16a(p + 4);
+  const unsigned flags = GetUi16a(p + 6);
   if (algId * 64 + 128 != bitLen)
     return E_NOTIMPL;
   _key.KeySize = 16 + algId * 8;
   const bool cert = ((flags & 2) != 0);
 
-  if ((flags & 0x4000) != 0)
+  if (flags & 0x4000)
   {
     // Use 3DES for rd data
     return E_NOTIMPL;
@@ -155,7 +156,7 @@ HRESULT CDecoder::Init_and_CheckPassword(bool &passwOK)
       return E_NOTIMPL;
   }
 
-  UInt32 rdSize = GetUi16(p + 8);
+  UInt32 rdSize = GetUi16a(p + 8);
 
   if (rdSize + 16 > _remSize)
     return E_NOTIMPL;
@@ -174,7 +175,7 @@ HRESULT CDecoder::Init_and_CheckPassword(bool &passwOK)
     // PKCS7 padding
     if (rdSize < kPadSize)
       return E_NOTIMPL;
-    if ((rdSize & (kPadSize - 1)) != 0)
+    if (rdSize & (kPadSize - 1))
       return E_NOTIMPL;
   }
 
diff --git a/CPP/7zip/GuiCommon.rc b/CPP/7zip/GuiCommon.rc
index 95654b6..bf8ad8b 100644
--- a/CPP/7zip/GuiCommon.rc
+++ b/CPP/7zip/GuiCommon.rc
@@ -115,5 +115,5 @@ LANGUAGE LANG_ENGLISH, SUBLANG_ENGLISH_US
       _x + _xSize, _y, 8, 12  // these values are unused
 
 
-#define OPTIONS_PAGE_XC_SIZE 280
+#define OPTIONS_PAGE_XC_SIZE 300
 #define OPTIONS_PAGE_YC_SIZE 280
diff --git a/CPP/7zip/Guid.txt b/CPP/7zip/Guid.txt
index abbaf20..fbae89c 100644
--- a/CPP/7zip/Guid.txt
+++ b/CPP/7zip/Guid.txt
@@ -20,6 +20,8 @@
   10  IFolderArchiveUpdateCallback2
   11  IFolderScanProgress
   12  IFolderSetZoneIdMode
+  13  IFolderSetZoneIdFile
+  14  IFolderArchiveUpdateCallback_MoveArc
   
   20  IFileExtractCallback.h::IGetProp
   30  IFileExtractCallback.h::IFolderExtractToStreamCallback (old)
diff --git a/CPP/7zip/UI/Agent/Agent.cpp b/CPP/7zip/UI/Agent/Agent.cpp
index eb77f25..46b740a 100644
--- a/CPP/7zip/UI/Agent/Agent.cpp
+++ b/CPP/7zip/UI/Agent/Agent.cpp
@@ -1516,6 +1516,8 @@ Z7_COM7F_IMF(CAgentFolder::Extract(const UInt32 *indices,
     if (_zoneMode != NExtract::NZoneIdMode::kNone)
     {
       ReadZoneFile_Of_BaseFile(us2fs(_agentSpec->_archiveFilePath), extractCallbackSpec->ZoneBuf);
+      if (_zoneBuf.Size() != 0)
+        extractCallbackSpec->ZoneBuf = _zoneBuf;
     }
   #endif
 
diff --git a/CPP/7zip/UI/Agent/Agent.h b/CPP/7zip/UI/Agent/Agent.h
index ea81aa8..a63e459 100644
--- a/CPP/7zip/UI/Agent/Agent.h
+++ b/CPP/7zip/UI/Agent/Agent.h
@@ -60,6 +60,7 @@ class CAgentFolder Z7_final:
   public IArchiveFolderInternal,
   public IInArchiveGetStream,
   public IFolderSetZoneIdMode,
+  public IFolderSetZoneIdFile,
   public IFolderOperations,
   public IFolderSetFlatMode,
   public CMyUnknownImp
@@ -75,6 +76,7 @@ class CAgentFolder Z7_final:
     Z7_COM_QI_ENTRY(IArchiveFolderInternal)
     Z7_COM_QI_ENTRY(IInArchiveGetStream)
     Z7_COM_QI_ENTRY(IFolderSetZoneIdMode)
+    Z7_COM_QI_ENTRY(IFolderSetZoneIdFile)
     Z7_COM_QI_ENTRY(IFolderOperations)
     Z7_COM_QI_ENTRY(IFolderSetFlatMode)
   Z7_COM_QI_END
@@ -91,6 +93,7 @@ class CAgentFolder Z7_final:
   Z7_IFACE_COM7_IMP(IArchiveFolderInternal)
   Z7_IFACE_COM7_IMP(IInArchiveGetStream)
   Z7_IFACE_COM7_IMP(IFolderSetZoneIdMode)
+  Z7_IFACE_COM7_IMP(IFolderSetZoneIdFile)
   Z7_IFACE_COM7_IMP(IFolderOperations)
   Z7_IFACE_COM7_IMP(IFolderSetFlatMode)
 
@@ -106,11 +109,11 @@ public:
   int CompareItems2(UInt32 index1, UInt32 index2, PROPID propID, Int32 propIsRaw);
 
   CAgentFolder():
-      _proxyDirIndex(0),
       _isAltStreamFolder(false),
       _flatMode(false),
-      _loadAltStreams(false) // _loadAltStreams alt streams works in flat mode, but we don't use it now
-      , _zoneMode(NExtract::NZoneIdMode::kNone)
+      _loadAltStreams(false), // _loadAltStreams alt streams works in flat mode, but we don't use it now
+      _proxyDirIndex(0),
+      _zoneMode(NExtract::NZoneIdMode::kNone)
       /* , _replaceAltStreamCharsMode(0) */
       {}
 
@@ -145,21 +148,23 @@ public:
   UString GetFullPrefix(UInt32 index) const; // relative too root folder of archive
 
 public:
+  bool _isAltStreamFolder;
+  bool _flatMode;
+  bool _loadAltStreams; // in Flat mode
   const CProxyArc *_proxy;
   const CProxyArc2 *_proxy2;
   unsigned _proxyDirIndex;
-  bool _isAltStreamFolder;
+  NExtract::NZoneIdMode::EEnum _zoneMode;
+  CByteBuffer _zoneBuf;
+  // Int32 _replaceAltStreamCharsMode;
   // CMyComPtr<IFolderFolder> _parentFolder;
   CMyComPtr<IInFolderArchive> _agent;
   CAgent *_agentSpec;
-
   CRecordVector<CProxyItem> _items;
-  bool _flatMode;
-  bool _loadAltStreams; // in Flat mode
-  // Int32 _replaceAltStreamCharsMode;
-  NExtract::NZoneIdMode::EEnum _zoneMode;
 };
 
+
+
 class CAgent Z7_final:
   public IInFolderArchive,
   public IFolderArcProps,
@@ -213,22 +218,22 @@ public:
   CProxyArc2 *_proxy2;
   CArchiveLink _archiveLink;
 
-  bool ThereIsPathProp;
-  // bool ThereIsAltStreamProp;
-
   UString ArchiveType;
 
   FStringVector _names;
   FString _folderPrefix; // for new files from disk
 
-  bool _updatePathPrefix_is_AltFolder;
   UString _updatePathPrefix;
   CAgentFolder *_agentFolder;
 
-  UString _archiveFilePath;
+  UString _archiveFilePath; // it can be path of non-existing file if file is virtual
+  
   DWORD _attrib;
+  bool _updatePathPrefix_is_AltFolder;
+  bool ThereIsPathProp;
   bool _isDeviceFile;
   bool _isHashHandler;
+  
   FString _hashBaseFolderPrefix;
 
  #ifndef Z7_EXTRACT_ONLY
diff --git a/CPP/7zip/UI/Agent/ArchiveFolder.cpp b/CPP/7zip/UI/Agent/ArchiveFolder.cpp
index 89b20dc..eea681c 100644
--- a/CPP/7zip/UI/Agent/ArchiveFolder.cpp
+++ b/CPP/7zip/UI/Agent/ArchiveFolder.cpp
@@ -22,6 +22,12 @@ Z7_COM7F_IMF(CAgentFolder::SetZoneIdMode(NExtract::NZoneIdMode::EEnum zoneMode))
   return S_OK;
 }
 
+Z7_COM7F_IMF(CAgentFolder::SetZoneIdFile(const Byte *data, UInt32 size))
+{
+  _zoneBuf.CopyFrom(data, size);
+  return S_OK;
+}
+
 
 Z7_COM7F_IMF(CAgentFolder::CopyTo(Int32 moveMode, const UInt32 *indices, UInt32 numItems,
     Int32 includeAltStreams, Int32 replaceAltStreamCharsMode,
diff --git a/CPP/7zip/UI/Agent/ArchiveFolderOut.cpp b/CPP/7zip/UI/Agent/ArchiveFolderOut.cpp
index 0189224..1da6601 100644
--- a/CPP/7zip/UI/Agent/ArchiveFolderOut.cpp
+++ b/CPP/7zip/UI/Agent/ArchiveFolderOut.cpp
@@ -62,6 +62,33 @@ static bool Delete_EmptyFolder_And_EmptySubFolders(const FString &path)
   return RemoveDir(path);
 }
 
+
+
+struct C_CopyFileProgress_to_FolderCallback_MoveArc Z7_final:
+  public ICopyFileProgress
+{
+  IFolderArchiveUpdateCallback_MoveArc *Callback;
+  HRESULT CallbackResult;
+
+  virtual DWORD CopyFileProgress(UInt64 total, UInt64 current) Z7_override
+  {
+    HRESULT res = Callback->MoveArc_Progress(total, current);
+    CallbackResult = res;
+    // we can ignore E_ABORT here, because we update archive,
+    // and we want to get correct archive after updating
+    if (res == E_ABORT)
+      res = S_OK;
+    return res == S_OK ? PROGRESS_CONTINUE : PROGRESS_CANCEL;
+  }
+
+  C_CopyFileProgress_to_FolderCallback_MoveArc(
+      IFolderArchiveUpdateCallback_MoveArc *callback) :
+    Callback(callback),
+    CallbackResult(S_OK)
+    {}
+};
+
+
 HRESULT CAgentFolder::CommonUpdateOperation(
     AGENT_OP operation,
     bool moveMode,
@@ -159,8 +186,51 @@ HRESULT CAgentFolder::CommonUpdateOperation(
   // now: we reopen archive after close
 
   // m_FolderItem = NULL;
+  _items.Clear();
+  _proxyDirIndex = k_Proxy_RootDirIndex;
+
+  CMyComPtr<IFolderArchiveUpdateCallback_MoveArc> updateCallback_MoveArc;
+  if (progress)
+    progress->QueryInterface(IID_IFolderArchiveUpdateCallback_MoveArc, (void **)&updateCallback_MoveArc);
   
-  const HRESULT res = tempFile.MoveToOriginal(true);
+  HRESULT res;
+  if (updateCallback_MoveArc)
+  {
+    const FString &tempFilePath = tempFile.Get_TempFilePath();
+    UInt64 totalSize = 0;
+    {
+      NFind::CFileInfo fi;
+      if (fi.Find(tempFilePath))
+        totalSize = fi.Size;
+    }
+    RINOK(updateCallback_MoveArc->MoveArc_Start(
+        fs2us(tempFilePath),
+        fs2us(tempFile.Get_OriginalFilePath()),
+        totalSize,
+        1)) // updateMode
+
+    C_CopyFileProgress_to_FolderCallback_MoveArc prox(updateCallback_MoveArc);
+    res = tempFile.MoveToOriginal(
+        true, // deleteOriginal
+        &prox);
+    if (res == S_OK)
+    {
+      res = updateCallback_MoveArc->MoveArc_Finish();
+      // we don't return after E_ABORT here, because
+      // we want to reopen new archive still.
+    }
+    else if (prox.CallbackResult != S_OK)
+      res = prox.CallbackResult;
+
+    // if updating callback returned E_ABORT,
+    // then openCallback still can return E_ABORT also.
+    // So ReOpen() will return with E_ABORT.
+    // But we want to open archive still.
+    // And Before_ArcReopen() call will clear user break status in that case.
+    RINOK(updateCallback_MoveArc->Before_ArcReopen())
+  }
+  else
+    res = tempFile.MoveToOriginal(true); // deleteOriginal
 
   // RINOK(res);
   if (res == S_OK)
@@ -189,10 +259,10 @@ HRESULT CAgentFolder::CommonUpdateOperation(
   }
    
   // CAgent::ReOpen() deletes _proxy and _proxy2
-  _items.Clear();
+  // _items.Clear();
   _proxy = NULL;
   _proxy2 = NULL;
-  _proxyDirIndex = k_Proxy_RootDirIndex;
+  // _proxyDirIndex = k_Proxy_RootDirIndex;
   _isAltStreamFolder = false;
   
   
diff --git a/CPP/7zip/UI/Agent/IFolderArchive.h b/CPP/7zip/UI/Agent/IFolderArchive.h
index 55f1423..12b900f 100644
--- a/CPP/7zip/UI/Agent/IFolderArchive.h
+++ b/CPP/7zip/UI/Agent/IFolderArchive.h
@@ -103,5 +103,21 @@ Z7_IFACE_CONSTR_FOLDERARC(IFolderScanProgress, 0x11)
 
 Z7_IFACE_CONSTR_FOLDERARC(IFolderSetZoneIdMode, 0x12)
 
+#define Z7_IFACEM_IFolderSetZoneIdFile(x) \
+  x(SetZoneIdFile(const Byte *data, UInt32 size)) \
+
+Z7_IFACE_CONSTR_FOLDERARC(IFolderSetZoneIdFile, 0x13)
+
+
+// if the caller calls Before_ArcReopen(), the callee must
+// clear user break status, because the caller want to open archive still.
+#define Z7_IFACEM_IFolderArchiveUpdateCallback_MoveArc(x) \
+  x(MoveArc_Start(const wchar_t *srcTempPath, const wchar_t *destFinalPath, UInt64 size, Int32 updateMode)) \
+  x(MoveArc_Progress(UInt64 totalSize, UInt64 currentSize)) \
+  x(MoveArc_Finish()) \
+  x(Before_ArcReopen()) \
+
+Z7_IFACE_CONSTR_FOLDERARC(IFolderArchiveUpdateCallback_MoveArc, 0x14)
+
 Z7_PURE_INTERFACES_END
 #endif
diff --git a/CPP/7zip/UI/Client7z/makefile.gcc b/CPP/7zip/UI/Client7z/makefile.gcc
index 3f97205..fe27011 100644
--- a/CPP/7zip/UI/Client7z/makefile.gcc
+++ b/CPP/7zip/UI/Client7z/makefile.gcc
@@ -57,8 +57,11 @@ WIN_OBJS = \
 7ZIP_COMMON_OBJS = \
   $O/FileStreams.o \
 
+C_OBJS = \
+  $O/Alloc.o \
 
 OBJS = \
+  $(C_OBJS) \
   $(COMMON_OBJS) \
   $(WIN_OBJS) \
   $(SYS_OBJS) \
diff --git a/CPP/7zip/UI/Common/ArchiveExtractCallback.cpp b/CPP/7zip/UI/Common/ArchiveExtractCallback.cpp
index 2d32694..67ea29c 100644
--- a/CPP/7zip/UI/Common/ArchiveExtractCallback.cpp
+++ b/CPP/7zip/UI/Common/ArchiveExtractCallback.cpp
@@ -140,21 +140,25 @@ static bool FindExt2(const char *p, const UString &name)
 }
 
 
-static const FChar * const k_ZoneId_StreamName = FTEXT(":Zone.Identifier");
+static const char * const k_ZoneId_StreamName_With_Colon_Prefix = ":Zone.Identifier";
 
-void ReadZoneFile_Of_BaseFile(CFSTR fileName2, CByteBuffer &buf)
+bool Is_ZoneId_StreamName(const wchar_t *s)
 {
-  FString fileName (fileName2);
-  fileName += k_ZoneId_StreamName;
+  return StringsAreEqualNoCase_Ascii(s, k_ZoneId_StreamName_With_Colon_Prefix + 1);
+}
 
+void ReadZoneFile_Of_BaseFile(CFSTR fileName, CByteBuffer &buf)
+{
   buf.Free();
+  FString path (fileName);
+  path += k_ZoneId_StreamName_With_Colon_Prefix;
   NIO::CInFile file;
-  if (!file.Open(fileName))
+  if (!file.Open(path))
     return;
   UInt64 fileSize;
   if (!file.GetLength(fileSize))
     return;
-  if (fileSize == 0 || fileSize >= ((UInt32)1 << 16))
+  if (fileSize == 0 || fileSize >= (1u << 15))
     return;
   buf.Alloc((size_t)fileSize);
   size_t processed;
@@ -166,7 +170,7 @@ void ReadZoneFile_Of_BaseFile(CFSTR fileName2, CByteBuffer &buf)
 bool WriteZoneFile_To_BaseFile(CFSTR fileName, const CByteBuffer &buf)
 {
   FString path (fileName);
-  path += k_ZoneId_StreamName;
+  path += k_ZoneId_StreamName_With_Colon_Prefix;
   NIO::COutFile file;
   if (!file.Create_ALWAYS(path))
     return false;
@@ -275,16 +279,13 @@ HRESULT CArchiveExtractCallback::PrepareHardLinks(const CRecordVector<UInt32> *r
 
 
 CArchiveExtractCallback::CArchiveExtractCallback():
-    _arc(NULL),
-    Write_CTime(true),
-    Write_ATime(true),
-    Write_MTime(true),
+    // Write_CTime(true),
+    // Write_ATime(true),
+    // Write_MTime(true),
     Is_elimPrefix_Mode(false),
+    _arc(NULL),
     _multiArchives(false)
 {
-  LocalProgressSpec = new CLocalProgress();
-  _localProgress = LocalProgressSpec;
-
   #ifdef Z7_USE_SECURITY_CODE
   _saclEnabled = InitLocalPrivileges();
   #endif
@@ -293,9 +294,9 @@ CArchiveExtractCallback::CArchiveExtractCallback():
 
 void CArchiveExtractCallback::InitBeforeNewArchive()
 {
- #if defined(_WIN32) && !defined(UNDER_CE)
+#if defined(_WIN32) && !defined(UNDER_CE) && !defined(Z7_SFX)
   ZoneBuf.Free();
- #endif
+#endif
 }
 
 void CArchiveExtractCallback::Init(
@@ -322,27 +323,20 @@ void CArchiveExtractCallback::Init(
 
   _ntOptions = ntOptions;
   _wildcardCensor = wildcardCensor;
-
   _stdOutMode = stdOutMode;
   _testMode = testMode;
-  
-  // _progressTotal = 0;
-  // _progressTotal_Defined = false;
-  
   _packTotal = packSize;
   _progressTotal = packSize;
-  _progressTotal_Defined = true;
-
+  // _progressTotal = 0;
+  // _progressTotal_Defined = false;
+  // _progressTotal_Defined = true;
   _extractCallback2 = extractCallback2;
-  
   /*
   _compressProgress.Release();
   _extractCallback2.QueryInterface(IID_ICompressProgressInfo, &_compressProgress);
-  
   _callbackMessage.Release();
   _extractCallback2.QueryInterface(IID_IArchiveExtractCallbackMessage2, &_callbackMessage);
   */
-  
   _folderArchiveExtractCallback2.Release();
   _extractCallback2.QueryInterface(IID_IFolderArchiveExtractCallback2, &_folderArchiveExtractCallback2);
 
@@ -390,7 +384,7 @@ Z7_COM7F_IMF(CArchiveExtractCallback::SetTotal(UInt64 size))
 {
   COM_TRY_BEGIN
   _progressTotal = size;
-  _progressTotal_Defined = true;
+  // _progressTotal_Defined = true;
   if (!_multiArchives && _extractCallback2)
     return _extractCallback2->SetTotal(size);
   return S_OK;
@@ -430,7 +424,7 @@ Z7_COM7F_IMF(CArchiveExtractCallback::SetCompleted(const UInt64 *completeValue))
   if (_multiArchives)
   {
     packCur = LocalProgressSpec->InSize;
-    if (completeValue && _progressTotal_Defined)
+    if (completeValue /* && _progressTotal_Defined */)
       packCur += MyMultDiv64(*completeValue, _progressTotal, _packTotal);
     completeValue = &packCur;
   }
@@ -443,7 +437,7 @@ Z7_COM7F_IMF(CArchiveExtractCallback::SetCompleted(const UInt64 *completeValue))
 Z7_COM7F_IMF(CArchiveExtractCallback::SetRatioInfo(const UInt64 *inSize, const UInt64 *outSize))
 {
   COM_TRY_BEGIN
-  return _localProgress->SetRatioInfo(inSize, outSize);
+  return LocalProgressSpec.Interface()->SetRatioInfo(inSize, outSize);
   COM_TRY_END
 }
 
@@ -582,13 +576,23 @@ HRESULT CArchiveExtractCallback::SendMessageError2(HRESULT errorCode, const char
 
 #ifndef Z7_SFX
 
+Z7_CLASS_IMP_COM_1(
+  CGetProp
+  , IGetProp
+)
+public:
+  UInt32 IndexInArc;
+  const CArc *Arc;
+  // UString BaseName; // relative path
+};
+
 Z7_COM7F_IMF(CGetProp::GetProp(PROPID propID, PROPVARIANT *value))
 {
   /*
-  if (propID == kpidName)
+  if (propID == kpidBaseName)
   {
     COM_TRY_BEGIN
-    NCOM::CPropVariant prop = Name;
+    NCOM::CPropVariant prop = BaseName;
     prop.Detach(value);
     return S_OK;
     COM_TRY_END
@@ -1087,7 +1091,7 @@ void CArchiveExtractCallback::GetFiTimesCAM(CFiTimesCAM &pt)
   pt.ATime_Defined = false;
   pt.MTime_Defined = false;
 
-  if (Write_MTime)
+  // if (Write_MTime)
   {
     if (_fi.MTime.Def)
     {
@@ -1101,13 +1105,13 @@ void CArchiveExtractCallback::GetFiTimesCAM(CFiTimesCAM &pt)
     }
   }
 
-  if (Write_CTime && _fi.CTime.Def)
+  if (/* Write_CTime && */ _fi.CTime.Def)
   {
     _fi.CTime.Write_To_FiTime(pt.CTime);
     pt.CTime_Defined = true;
   }
 
-  if (Write_ATime && _fi.ATime.Def)
+  if (/* Write_ATime && */ _fi.ATime.Def)
   {
     _fi.ATime.Write_To_FiTime(pt.ATime);
     pt.ATime_Defined = true;
@@ -1302,7 +1306,7 @@ HRESULT CArchiveExtractCallback::CheckExistFile(FString &fullProcessedPath, bool
   {
     #if defined(_WIN32) && !defined(UNDER_CE)
     // we need to clear READ-ONLY of parent before creating alt stream
-    int colonPos = NName::FindAltStreamColon(fullProcessedPath);
+    const int colonPos = NName::FindAltStreamColon(fullProcessedPath);
     if (colonPos >= 0 && fullProcessedPath[(unsigned)colonPos + 1] != 0)
     {
       FString parentFsPath (fullProcessedPath);
@@ -1311,7 +1315,11 @@ HRESULT CArchiveExtractCallback::CheckExistFile(FString &fullProcessedPath, bool
       if (parentFi.Find(parentFsPath))
       {
         if (parentFi.IsReadOnly())
+        {
+          _altStream_NeedRestore_Attrib_for_parentFsPath = parentFsPath;
+          _altStream_NeedRestore_AttribVal = parentFi.Attrib;
           SetFileAttrib(parentFsPath, parentFi.Attrib & ~(DWORD)FILE_ATTRIBUTE_READONLY);
+        }
       }
     }
     #endif // defined(_WIN32) && !defined(UNDER_CE)
@@ -1607,37 +1615,37 @@ Z7_COM7F_IMF(CArchiveExtractCallback::GetStream(UInt32 index, ISequentialOutStre
   _bufPtrSeqOutStream.Release();
 
   _encrypted = false;
-  _position = 0;
   _isSplit = false;
-  
-  _curSize = 0;
   _curSize_Defined = false;
   _fileLength_WasSet = false;
-  _fileLength_that_WasSet = 0;
-  _index = index;
-
-  _diskFilePath.Empty();
-
   _isRenamed = false;
-  
   // _fi.Clear();
-
+ _extractMode = false;
   // _is_SymLink_in_Data = false;
   _is_SymLink_in_Data_Linux = false;
-  
   _needSetAttrib = false;
   _isSymLinkCreated = false;
   _itemFailure = false;
-
   _some_pathParts_wereRemoved = false;
   // _op_WasReported = false;
 
+  _position = 0;
+  _curSize = 0;
+  _fileLength_that_WasSet = 0;
+  _index = index;
+
+#if defined(_WIN32) && !defined(UNDER_CE)
+  _altStream_NeedRestore_AttribVal = 0;
+  _altStream_NeedRestore_Attrib_for_parentFsPath.Empty();
+#endif
+
+  _diskFilePath.Empty();
+
   #ifdef SUPPORT_LINKS
   // _copyFile_Path.Empty();
   _link.Clear();
   #endif
 
-  _extractMode = false;
 
   switch (askExtractMode)
   {
@@ -1692,6 +1700,19 @@ Z7_COM7F_IMF(CArchiveExtractCallback::GetStream(UInt32 index, ISequentialOutStre
       return S_OK;
   }
 
+#if defined(_WIN32) && !defined(UNDER_CE) && !defined(Z7_SFX)
+  if (askExtractMode == NArchive::NExtract::NAskMode::kExtract
+      && !_testMode
+      && _item.IsAltStream
+      && ZoneBuf.Size() != 0
+      && Is_ZoneId_StreamName(_item.AltStreamName))
+    if (ZoneMode != NExtract::NZoneIdMode::kOffice
+        || _item.PathParts.IsEmpty()
+        || FindExt2(kOfficeExtensions, _item.PathParts.Back()))
+      return S_OK;
+#endif
+
+
   #ifndef Z7_SFX
   if (_use_baseParentFolder_mode)
   {
@@ -1810,15 +1831,11 @@ Z7_COM7F_IMF(CArchiveExtractCallback::GetStream(UInt32 index, ISequentialOutStre
 
   if (ExtractToStreamCallback)
   {
-    if (!GetProp)
-    {
-      GetProp_Spec = new CGetProp;
-      GetProp = GetProp_Spec;
-    }
-    GetProp_Spec->Arc = _arc;
-    GetProp_Spec->IndexInArc = index;
+    CMyComPtr2_Create<IGetProp, CGetProp> GetProp;
+    GetProp->Arc = _arc;
+    GetProp->IndexInArc = index;
     UString name (MakePathFromParts(pathParts));
-    
+    // GetProp->BaseName = name;
     #ifdef SUPPORT_ALT_STREAMS
     if (_item.IsAltStream)
     {
@@ -1984,6 +2001,15 @@ HRESULT CArchiveExtractCallback::CloseFile()
 
   RINOK(_outFileStreamSpec->Close())
   _outFileStream.Release();
+
+#if defined(_WIN32) && !defined(UNDER_CE)
+  if (!_altStream_NeedRestore_Attrib_for_parentFsPath.IsEmpty())
+  {
+    SetFileAttrib(_altStream_NeedRestore_Attrib_for_parentFsPath, _altStream_NeedRestore_AttribVal);
+    _altStream_NeedRestore_Attrib_for_parentFsPath.Empty();
+  }
+#endif
+
   return hres;
 }
 
diff --git a/CPP/7zip/UI/Common/ArchiveExtractCallback.h b/CPP/7zip/UI/Common/ArchiveExtractCallback.h
index 7eb2f67..f3ee01c 100644
--- a/CPP/7zip/UI/Common/ArchiveExtractCallback.h
+++ b/CPP/7zip/UI/Common/ArchiveExtractCallback.h
@@ -90,25 +90,10 @@ struct CExtractNtOptions
   }
 };
 
-#ifndef Z7_SFX
-
-Z7_CLASS_IMP_COM_1(
-  CGetProp
-  , IGetProp
-)
-public:
-  UInt32 IndexInArc;
-  const CArc *Arc;
-  // UString Name; // relative path
-};
-
-#endif
 
 #ifndef Z7_SFX
 #ifndef UNDER_CE
-
 #define SUPPORT_LINKS
-
 #endif
 #endif
 
@@ -282,46 +267,44 @@ class CArchiveExtractCallback Z7_final:
   Z7_IFACE_COM7_IMP(IArchiveRequestMemoryUseCallback)
 #endif
 
+  // bool Write_CTime;
+  // bool Write_ATime;
+  // bool Write_MTime;
+  bool _stdOutMode;
+  bool _testMode;
+  bool _removePartsForAltStreams;
+public:
+  bool Is_elimPrefix_Mode;
+private:
+
   const CArc *_arc;
   CExtractNtOptions _ntOptions;
 
+  bool _encrypted;
   bool _isSplit;
+  bool _curSize_Defined;
+  bool _fileLength_WasSet;
 
+  bool _isRenamed;
   bool _extractMode;
-
-  bool Write_CTime;
-  bool Write_ATime;
-  bool Write_MTime;
-  bool _keepAndReplaceEmptyDirPrefixes; // replace them to "_";
-
-  bool _encrypted;
-
   // bool _is_SymLink_in_Data;
   bool _is_SymLink_in_Data_Linux; // false = WIN32, true = LINUX
-
   bool _needSetAttrib;
   bool _isSymLinkCreated;
   bool _itemFailure;
-
   bool _some_pathParts_wereRemoved;
-public:
-  bool Is_elimPrefix_Mode;
-
-private:
-  bool _curSize_Defined;
-  bool _fileLength_WasSet;
-
-  bool _removePartsForAltStreams;
 
-  bool _stdOutMode;
-  bool _testMode;
   bool _multiArchives;
+  bool _keepAndReplaceEmptyDirPrefixes; // replace them to "_";
+#if defined(_WIN32) && !defined(UNDER_CE) && !defined(Z7_SFX)
+  bool _saclEnabled;
+#endif
 
   NExtract::NPathMode::EEnum _pathMode;
   NExtract::NOverwriteMode::EEnum _overwriteMode;
 
-  const NWildcard::CCensorNode *_wildcardCensor; // we need wildcard for single pass mode (stdin)
   CMyComPtr<IFolderArchiveExtractCallback> _extractCallback2;
+  const NWildcard::CCensorNode *_wildcardCensor; // we need wildcard for single pass mode (stdin)
   // CMyComPtr<ICompressProgressInfo> _compressProgress;
   // CMyComPtr<IArchiveExtractCallbackMessage2> _callbackMessage;
   CMyComPtr<IFolderArchiveExtractCallback2> _folderArchiveExtractCallback2;
@@ -333,15 +316,12 @@ private:
   #ifndef Z7_SFX
 
   CMyComPtr<IFolderExtractToStreamCallback> ExtractToStreamCallback;
-  CGetProp *GetProp_Spec;
-  CMyComPtr<IGetProp> GetProp;
   CMyComPtr<IArchiveRequestMemoryUseCallback> _requestMemoryUseCallback;
   
   #endif
 
   CReadArcItem _item;
   FString _diskFilePath;
-  UInt64 _position;
 
   struct CProcessedFileInfo
   {
@@ -387,9 +367,17 @@ private:
     }
   } _fi;
 
-  UInt32 _index;
+  UInt64 _position;
   UInt64 _curSize;
   UInt64 _fileLength_that_WasSet;
+  UInt32 _index;
+
+// #ifdef SUPPORT_ALT_STREAMS
+#if defined(_WIN32) && !defined(UNDER_CE)
+  DWORD _altStream_NeedRestore_AttribVal;
+  FString _altStream_NeedRestore_Attrib_for_parentFsPath;
+#endif
+// #endif
 
   COutFileStream *_outFileStreamSpec;
   CMyComPtr<ISequentialOutStream> _outFileStream;
@@ -398,9 +386,7 @@ private:
   CBufPtrSeqOutStream *_bufPtrSeqOutStream_Spec;
   CMyComPtr<ISequentialOutStream> _bufPtrSeqOutStream;
 
-
  #ifndef Z7_SFX
-  
   COutStreamWithHash *_hashStreamSpec;
   CMyComPtr<ISequentialOutStream> _hashStream;
   bool _hashStreamWasUsed;
@@ -411,11 +397,9 @@ private:
 
   UStringVector _removePathParts;
 
-  CMyComPtr<ICompressProgressInfo> _localProgress;
   UInt64 _packTotal;
-  
   UInt64 _progressTotal;
-  bool _progressTotal_Defined;
+  // bool _progressTotal_Defined;
 
   CObjectVector<CDirPathTime> _extractedFolders;
   
@@ -423,10 +407,6 @@ private:
   // CObjectVector<NWindows::NFile::NDir::CDelayedSymLink> _delayedSymLinks;
   #endif
 
-  #if defined(_WIN32) && !defined(UNDER_CE) && !defined(Z7_SFX)
-  bool _saclEnabled;
-  #endif
-
   void CreateComplexDirectory(const UStringVector &dirPathParts, FString &fullPath);
   HRESULT GetTime(UInt32 index, PROPID propID, CArcTime &ft);
   HRESULT GetUnpackSize();
@@ -441,13 +421,12 @@ public:
   HRESULT SendMessageError_with_LastError(const char *message, const FString &path);
   HRESULT SendMessageError2(HRESULT errorCode, const char *message, const FString &path1, const FString &path2);
 
-public:
-  #if defined(_WIN32) && !defined(UNDER_CE)
+#if defined(_WIN32) && !defined(UNDER_CE) && !defined(Z7_SFX)
   NExtract::NZoneIdMode::EEnum ZoneMode;
   CByteBuffer ZoneBuf;
-  #endif
+#endif
 
-  CLocalProgress *LocalProgressSpec;
+  CMyComPtr2_Create<ICompressProgressInfo, CLocalProgress> LocalProgressSpec;
 
   UInt64 NumFolders;
   UInt64 NumFiles;
@@ -468,11 +447,11 @@ public:
     _multiArchives = multiArchives;
     _pathMode = pathMode;
     _overwriteMode = overwriteMode;
-   #if defined(_WIN32) && !defined(UNDER_CE)
+#if defined(_WIN32) && !defined(UNDER_CE) && !defined(Z7_SFX)
      ZoneMode = zoneMode;
-   #else
+#else
      UNUSED_VAR(zoneMode)
-   #endif
+#endif
     _keepAndReplaceEmptyDirPrefixes = keepAndReplaceEmptyDirPrefixes;
     NumFolders = NumFiles = NumAltStreams = UnpackSize = AltStreams_UnpackSize = 0;
   }
@@ -551,7 +530,6 @@ private:
   void GetFiTimesCAM(CFiTimesCAM &pt);
   void CreateFolders();
   
-  bool _isRenamed;
   HRESULT CheckExistFile(FString &fullProcessedPath, bool &needExit);
   HRESULT GetExtractStream(CMyComPtr<ISequentialOutStream> &outStreamLoc, bool &needExit);
   HRESULT GetItem(UInt32 index);
@@ -599,7 +577,8 @@ struct CArchiveExtractCallback_Closer
 
 bool CensorNode_CheckPath(const NWildcard::CCensorNode &node, const CReadArcItem &item);
 
-void ReadZoneFile_Of_BaseFile(CFSTR fileName2, CByteBuffer &buf);
+bool Is_ZoneId_StreamName(const wchar_t *s);
+void ReadZoneFile_Of_BaseFile(CFSTR fileName, CByteBuffer &buf);
 bool WriteZoneFile_To_BaseFile(CFSTR fileName, const CByteBuffer &buf);
 
 #endif
diff --git a/CPP/7zip/UI/Common/Bench.cpp b/CPP/7zip/UI/Common/Bench.cpp
index e1ca846..05d66aa 100644
--- a/CPP/7zip/UI/Common/Bench.cpp
+++ b/CPP/7zip/UI/Common/Bench.cpp
@@ -2298,6 +2298,28 @@ HRESULT CCrcInfo_Base::Generate(const Byte *data, size_t size)
 }
 
 
+#if 1
+#define HashUpdate(hf, data, size)  hf->Update(data, size)
+#else
+// for debug:
+static void HashUpdate(IHasher *hf, const void *data, UInt32 size)
+{
+  for (;;)
+  {
+    if (size == 0)
+      return;
+    UInt32 size2 = (size * 0x85EBCA87) % size / 8;
+    // UInt32 size2 = size / 2;
+    if (size2 == 0)
+      size2 = 1;
+    hf->Update(data, size2);
+    data = (const void *)((const Byte *)data + size2);
+    size -= size2;
+  }
+}
+#endif
+
+
 HRESULT CCrcInfo_Base::CrcProcess(UInt64 numIterations,
     const UInt32 *checkSum, IHasher *hf,
     IBenchPrintCallback *callback)
@@ -2328,7 +2350,7 @@ HRESULT CCrcInfo_Base::CrcProcess(UInt64 numIterations,
       const size_t rem = size - pos;
       const UInt32 kStep = ((UInt32)1 << 31);
       const UInt32 curSize = (rem < kStep) ? (UInt32)rem : kStep;
-      hf->Update(buf + pos, curSize);
+      HashUpdate(hf, buf + pos, curSize);
       pos += curSize;
     }
     while (pos != size);
@@ -2742,14 +2764,20 @@ static const CBenchHash g_Hash[] =
   {  2,   128 *ARM_CRC_MUL, 0x21e207bb, "CRC32:32" },
   {  2,    64 *ARM_CRC_MUL, 0x21e207bb, "CRC32:64" },
   { 10,   256, 0x41b901d1, "CRC64" },
-  { 10,    64, 0x43eac94f, "XXH64" },
-  
-  { 10, 5100,       0x7913ba03, "SHA256:1" },
-  {  2, CMPLX((32 * 4 + 1) * 4 + 4), 0x7913ba03, "SHA256:2" },
-  
-  { 10, 2340,       0xff769021, "SHA1:1" },
+  {  5,    64, 0x43eac94f, "XXH64" },
+  {  2,  2340, 0x3398a904, "MD5" },
+  { 10,  2340,                       0xff769021, "SHA1:1" },
   {  2, CMPLX((20 * 6 + 1) * 4 + 4), 0xff769021, "SHA1:2" },
-  
+  { 10,  5100,                       0x7913ba03, "SHA256:1" },
+  {  2, CMPLX((32 * 4 + 1) * 4 + 4), 0x7913ba03, "SHA256:2" },
+  {  5,  3200,                       0xe7aeb394, "SHA512:1" },
+  {  2, CMPLX((40 * 4 + 1) * 4 + 4), 0xe7aeb394, "SHA512:2" },
+  // { 10, 3428,       0x1cc99b18, "SHAKE128" },
+  // { 10, 4235,       0x74eaddc3, "SHAKE256" },
+  // { 10, 4000,       0xdf3e6863, "SHA3-224" },
+  {  5, 4200,       0xcecac10d, "SHA3-256" },
+  // { 10, 5538,       0x4e5d9163, "SHA3-384" },
+  // { 10, 8000,       0x96a58289, "SHA3-512" },
   {  2,  4096, 0x85189d02, "BLAKE2sp:1" },
   {  2,  1024, 0x85189d02, "BLAKE2sp:2" }, // sse2-way4-fast
   {  2,   512, 0x85189d02, "BLAKE2sp:3" }  // avx2-way8-fast
@@ -3687,7 +3715,7 @@ HRESULT Bench(
     return E_FAIL;
 
   UInt32 numCPUs = 1;
-  UInt64 ramSize = (UInt64)(sizeof(size_t)) << 29;
+  size_t ramSize = (size_t)sizeof(size_t) << 29;
 
   NSystem::CProcessAffinity threadsInfo;
   threadsInfo.InitST();
@@ -4580,6 +4608,8 @@ HRESULT Bench(
 
   if (!dictIsDefined && !onlyHashBench)
   {
+    // we use dicSizeLog and dicSizeLog_Main for data size.
+    // also we use it to reduce dictionary size of LZMA encoder via NCoderPropID::kReduceSize.
     const unsigned dicSizeLog_Main = (totalBenchMode ? 24 : 25);
     unsigned dicSizeLog = dicSizeLog_Main;
     
diff --git a/CPP/7zip/UI/Common/EnumDirItems.cpp b/CPP/7zip/UI/Common/EnumDirItems.cpp
index 0758547..11643ae 100644
--- a/CPP/7zip/UI/Common/EnumDirItems.cpp
+++ b/CPP/7zip/UI/Common/EnumDirItems.cpp
@@ -671,7 +671,7 @@ static HRESULT EnumerateForItem(
   }
   
   #if defined(_WIN32)
-  if (needAltStreams && dirItems.ScanAltStreams)
+  if (needAltStreams && dirItems.ScanAltStreams && !fi.IsAltStream)
   {
     RINOK(EnumerateAltStreams(fi, curNode, phyParent, logParent,
         phyPrefix + fi.Name,    // with (fi.Name)
@@ -929,7 +929,7 @@ static HRESULT EnumerateDirItems(
         }
         
         #if defined(_WIN32)
-        if (needAltStreams && dirItems.ScanAltStreams)
+        if (needAltStreams && dirItems.ScanAltStreams && !fi.IsAltStream)
         {
           UStringVector pathParts;
           pathParts.Add(fs2us(fi.Name));
diff --git a/CPP/7zip/UI/Common/HashCalc.cpp b/CPP/7zip/UI/Common/HashCalc.cpp
index f3d65ef..9caac36 100644
--- a/CPP/7zip/UI/Common/HashCalc.cpp
+++ b/CPP/7zip/UI/Common/HashCalc.cpp
@@ -773,13 +773,21 @@ static const char * const k_CsumMethodNames[] =
 {
     "sha256"
   , "sha224"
-//  , "sha512/224"
-//  , "sha512/256"
-  , "sha512"
+//  , "sha512-224"
+//  , "sha512-256"
   , "sha384"
+  , "sha512"
+//  , "sha3-224"
+  , "sha3-256"
+//  , "sha3-384"
+//  , "sha3-512"
+//  , "shake128"
+//  , "shake256"
   , "sha1"
   , "md5"
+  , "blake2sp"
   , "blake2b"
+  , "xxh64"
   , "crc64"
   , "crc32"
   , "cksum"
@@ -2076,11 +2084,27 @@ void Codecs_AddHashArcHandler(CCodecs *codecs)
   
     // ubuntu uses "SHA256SUMS" file
     item.AddExts(UString (
-        "sha256 sha512 sha224 sha384 sha1 sha md5"
-        // "b2sum"
+        "sha256"
+        " sha512"
+        " sha384"
+        " sha224"
+        // " sha512-224"
+        // " sha512-256"
+        // " sha3-224"
+        " sha3-256"
+        // " sha3-384"
+        // " sha3-512"
+        // " shake128"
+        // " shake256"
+        " sha1"
+        " sha"
+        " md5"
+        " blake2sp"
+        " xxh64"
         " crc32 crc64"
         " asc"
         " cksum"
+        // " b2sum"
         ),
         UString());
 
diff --git a/CPP/7zip/UI/Common/TempFiles.cpp b/CPP/7zip/UI/Common/TempFiles.cpp
index 2f86838..ad16e36 100644
--- a/CPP/7zip/UI/Common/TempFiles.cpp
+++ b/CPP/7zip/UI/Common/TempFiles.cpp
@@ -13,7 +13,8 @@ void CTempFiles::Clear()
 {
   while (!Paths.IsEmpty())
   {
-    NDir::DeleteFileAlways(Paths.Back());
+    if (NeedDeleteFiles)
+      NDir::DeleteFileAlways(Paths.Back());
     Paths.DeleteBack();
   }
 }
diff --git a/CPP/7zip/UI/Common/TempFiles.h b/CPP/7zip/UI/Common/TempFiles.h
index dd4ac20..83c741f 100644
--- a/CPP/7zip/UI/Common/TempFiles.h
+++ b/CPP/7zip/UI/Common/TempFiles.h
@@ -10,6 +10,9 @@ class CTempFiles
   void Clear();
 public:
   FStringVector Paths;
+  bool NeedDeleteFiles;
+
+  CTempFiles(): NeedDeleteFiles(true) {}
   ~CTempFiles() { Clear(); }
 };
 
diff --git a/CPP/7zip/UI/Common/Update.cpp b/CPP/7zip/UI/Common/Update.cpp
index ed48605..b959a3c 100644
--- a/CPP/7zip/UI/Common/Update.cpp
+++ b/CPP/7zip/UI/Common/Update.cpp
@@ -1096,6 +1096,30 @@ typedef Z7_WIN_MAPISENDMAILW FAR *Z7_WIN_LPMAPISENDMAILW;
 #endif // _WIN32
 
 
+struct C_CopyFileProgress_to_IUpdateCallbackUI2 Z7_final:
+  public ICopyFileProgress
+{
+  IUpdateCallbackUI2 *Callback;
+  HRESULT CallbackResult;
+  // bool Disable_Break;
+
+  virtual DWORD CopyFileProgress(UInt64 total, UInt64 current) Z7_override
+  {
+    const HRESULT res = Callback->MoveArc_Progress(total, current);
+    CallbackResult = res;
+    // if (Disable_Break && res == E_ABORT) res = S_OK;
+    return res == S_OK ? PROGRESS_CONTINUE : PROGRESS_CANCEL;
+  }
+
+  C_CopyFileProgress_to_IUpdateCallbackUI2(
+      IUpdateCallbackUI2 *callback) :
+    Callback(callback),
+    CallbackResult(S_OK)
+    // , Disable_Break(false)
+    {}
+};
+
+
 HRESULT UpdateArchive(
     CCodecs *codecs,
     const CObjectVector<COpenType> &types,
@@ -1311,7 +1335,7 @@ HRESULT UpdateArchive(
       return E_NOTIMPL;
   }
 
-  bool thereIsInArchive = arcLink.IsOpen;
+  const bool thereIsInArchive = arcLink.IsOpen;
   if (!thereIsInArchive && renameMode)
     return E_FAIL;
   
@@ -1588,7 +1612,14 @@ HRESULT UpdateArchive(
   multiStreams.DisableDeletion();
   RINOK(multiStreams.Destruct())
 
-  tempFiles.Paths.Clear();
+  // here we disable deleting of temp archives.
+  // note: archive moving can fail, or it can be interrupted,
+  // if we move new temp update from another volume.
+  // And we still want to keep temp archive in that case,
+  // because we will have deleted original archive.
+  tempFiles.NeedDeleteFiles = false;
+  // tempFiles.Paths.Clear();
+
   if (createTempFile)
   {
     try
@@ -1603,16 +1634,29 @@ HRESULT UpdateArchive(
         if (!DeleteFileAlways(us2fs(arcPath)))
           return errorInfo.SetFromLastError("cannot delete the file", us2fs(arcPath));
       }
-      
-      if (!MyMoveFile(tempPath, us2fs(arcPath)))
+
+      UInt64 totalArcSize = 0;
+      {
+        NFind::CFileInfo fi;
+        if (fi.Find(tempPath))
+          totalArcSize = fi.Size;
+      }
+      RINOK(callback->MoveArc_Start(fs2us(tempPath), arcPath,
+          totalArcSize, BoolToInt(thereIsInArchive)))
+
+      C_CopyFileProgress_to_IUpdateCallbackUI2 prox(callback);
+      // if we update archive, we have removed original archive.
+      // So if we break archive moving, we will have only temporary archive.
+      // We can disable breaking here:
+      // prox.Disable_Break = thereIsInArchive;
+
+      if (!MyMoveFile_with_Progress(tempPath, us2fs(arcPath), &prox))
       {
         errorInfo.SystemError = ::GetLastError();
         errorInfo.Message = "cannot move the file";
         if (errorInfo.SystemError == ERROR_INVALID_PARAMETER)
         {
-          NFind::CFileInfo fi;
-          if (fi.Find(tempPath) &&
-              fi.Size > (UInt32)(Int32)-1)
+          if (totalArcSize > (UInt32)(Int32)-1)
           {
             // bool isFsDetected = false;
             // if (NSystem::Is_File_LimitedBy_4GB(us2fs(arcPath), isFsDetected) || !isFsDetected)
@@ -1622,10 +1666,20 @@ HRESULT UpdateArchive(
             }
           }
         }
+        // if there was no input archive, and we have operation breaking.
+        // then we can remove temporary archive, because we still have original uncompressed files.
+        if (!thereIsInArchive
+            && prox.CallbackResult == E_ABORT)
+          tempFiles.NeedDeleteFiles = true;
         errorInfo.FileNames.Add(tempPath);
         errorInfo.FileNames.Add(us2fs(arcPath));
+        RINOK(prox.CallbackResult)
         return errorInfo.Get_HRESULT_Error();
       }
+
+      // MoveArc_Finish() can return delayed user break (E_ABORT) status,
+      // if callback callee ignored interruption to finish archive creation operation.
+      RINOK(callback->MoveArc_Finish())
       
       /*
       if (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_READONLY))
diff --git a/CPP/7zip/UI/Common/Update.h b/CPP/7zip/UI/Common/Update.h
index a9459ff..216339a 100644
--- a/CPP/7zip/UI/Common/Update.h
+++ b/CPP/7zip/UI/Common/Update.h
@@ -12,8 +12,6 @@
 #include "UpdateAction.h"
 #include "UpdateCallback.h"
 
-#include "DirItem.h"
-
 enum EArcNameMode
 {
   k_ArcNameMode_Smart,
@@ -195,6 +193,9 @@ Z7_PURE_INTERFACES_BEGIN
   virtual HRESULT FinishArchive(const CFinishArchiveStat &st) x \
   virtual HRESULT DeletingAfterArchiving(const FString &path, bool isDir) x \
   virtual HRESULT FinishDeletingAfterArchiving() x \
+  virtual HRESULT MoveArc_Start(const wchar_t *srcTempPath, const wchar_t *destFinalPath, UInt64 size, Int32 updateMode) x \
+  virtual HRESULT MoveArc_Progress(UInt64 total, UInt64 current) x \
+  virtual HRESULT MoveArc_Finish() x \
 
 DECLARE_INTERFACE(IUpdateCallbackUI2):
     public IUpdateCallbackUI,
diff --git a/CPP/7zip/UI/Common/WorkDir.cpp b/CPP/7zip/UI/Common/WorkDir.cpp
index cfec635..a492967 100644
--- a/CPP/7zip/UI/Common/WorkDir.cpp
+++ b/CPP/7zip/UI/Common/WorkDir.cpp
@@ -63,24 +63,22 @@ HRESULT CWorkDirTempFile::CreateTempFile(const FString &originalPath)
   NWorkDir::CInfo workDirInfo;
   workDirInfo.Load();
   FString namePart;
-  const FString workDir = GetWorkDir(workDirInfo, originalPath, namePart);
-  CreateComplexDir(workDir);
+  FString path = GetWorkDir(workDirInfo, originalPath, namePart);
+  CreateComplexDir(path);
+  path += namePart;
   _outStreamSpec = new COutFileStream;
   OutStream = _outStreamSpec;
-  if (!_tempFile.Create(workDir + namePart, &_outStreamSpec->File))
-  {
+  if (!_tempFile.Create(path, &_outStreamSpec->File))
     return GetLastError_noZero_HRESULT();
-  }
   _originalPath = originalPath;
   return S_OK;
 }
 
-HRESULT CWorkDirTempFile::MoveToOriginal(bool deleteOriginal)
+HRESULT CWorkDirTempFile::MoveToOriginal(bool deleteOriginal,
+    NWindows::NFile::NDir::ICopyFileProgress *progress)
 {
   OutStream.Release();
-  if (!_tempFile.MoveTo(_originalPath, deleteOriginal))
-  {
+  if (!_tempFile.MoveTo(_originalPath, deleteOriginal, progress))
     return GetLastError_noZero_HRESULT();
-  }
   return S_OK;
 }
diff --git a/CPP/7zip/UI/Common/WorkDir.h b/CPP/7zip/UI/Common/WorkDir.h
index d32ab9d..fed8c4a 100644
--- a/CPP/7zip/UI/Common/WorkDir.h
+++ b/CPP/7zip/UI/Common/WorkDir.h
@@ -11,7 +11,7 @@
 
 FString GetWorkDir(const NWorkDir::CInfo &workDirInfo, const FString &path, FString &fileName);
 
-class CWorkDirTempFile
+class CWorkDirTempFile  MY_UNCOPYABLE
 {
   FString _originalPath;
   NWindows::NFile::NDir::CTempFile _tempFile;
@@ -19,8 +19,12 @@ class CWorkDirTempFile
 public:
   CMyComPtr<IOutStream> OutStream;
 
+  const FString &Get_OriginalFilePath() const { return _originalPath; }
+  const FString &Get_TempFilePath() const { return _tempFile.GetPath(); }
+
   HRESULT CreateTempFile(const FString &originalPath);
-  HRESULT MoveToOriginal(bool deleteOriginal);
+  HRESULT MoveToOriginal(bool deleteOriginal,
+      NWindows::NFile::NDir::ICopyFileProgress *progress = NULL);
 };
 
 #endif
diff --git a/CPP/7zip/UI/Common/ZipRegistry.cpp b/CPP/7zip/UI/Common/ZipRegistry.cpp
index 73c56cf..936b888 100644
--- a/CPP/7zip/UI/Common/ZipRegistry.cpp
+++ b/CPP/7zip/UI/Common/ZipRegistry.cpp
@@ -45,8 +45,8 @@ static void Key_Set_UInt32(CKey &key, LPCTSTR name, UInt32 value)
 
 static void Key_Get_UInt32(CKey &key, LPCTSTR name, UInt32 &value)
 {
-  if (key.QueryValue(name, value) != ERROR_SUCCESS)
-    value = (UInt32)(Int32)-1;
+  value = (UInt32)(Int32)-1;
+  key.GetValue_UInt32_IfOk(name, value);
 }
 
 
@@ -59,7 +59,7 @@ static void Key_Set_BoolPair(CKey &key, LPCTSTR name, const CBoolPair &b)
 static void Key_Set_bool_if_Changed(CKey &key, LPCTSTR name, bool val)
 {
   bool oldVal = false;
-  if (key.GetValue_IfOk(name, oldVal) == ERROR_SUCCESS)
+  if (key.GetValue_bool_IfOk(name, oldVal) == ERROR_SUCCESS)
     if (val == oldVal)
       return;
   key.SetValue(name, val);
@@ -76,13 +76,13 @@ static void Key_Set_BoolPair_Delete_IfNotDef(CKey &key, LPCTSTR name, const CBoo
 static void Key_Get_BoolPair(CKey &key, LPCTSTR name, CBoolPair &b)
 {
   b.Val = false;
-  b.Def = (key.GetValue_IfOk(name, b.Val) == ERROR_SUCCESS);
+  b.Def = (key.GetValue_bool_IfOk(name, b.Val) == ERROR_SUCCESS);
 }
 
 static void Key_Get_BoolPair_true(CKey &key, LPCTSTR name, CBoolPair &b)
 {
   b.Val = true;
-  b.Def = (key.GetValue_IfOk(name, b.Val) == ERROR_SUCCESS);
+  b.Def = (key.GetValue_bool_IfOk(name, b.Val) == ERROR_SUCCESS);
 }
 
 namespace NExtract
@@ -155,12 +155,12 @@ void CInfo::Load()
   
   key.GetValue_Strings(kPathHistory, Paths);
   UInt32 v;
-  if (key.QueryValue(kExtractMode, v) == ERROR_SUCCESS && v <= NPathMode::kAbsPaths)
+  if (key.GetValue_UInt32_IfOk(kExtractMode, v) == ERROR_SUCCESS && v <= NPathMode::kAbsPaths)
   {
     PathMode = (NPathMode::EEnum)v;
     PathMode_Force = true;
   }
-  if (key.QueryValue(kOverwriteMode, v) == ERROR_SUCCESS && v <= NOverwriteMode::kRenameExisting)
+  if (key.GetValue_UInt32_IfOk(kOverwriteMode, v) == ERROR_SUCCESS && v <= NOverwriteMode::kRenameExisting)
   {
     OverwriteMode = (NOverwriteMode::EEnum)v;
     OverwriteMode_Force = true;
@@ -181,7 +181,7 @@ bool Read_ShowPassword()
   bool showPassword = false;
   if (OpenMainKey(key, kKeyName) != ERROR_SUCCESS)
     return showPassword;
-  key.GetValue_IfOk(kShowPassword, showPassword);
+  key.GetValue_bool_IfOk(kShowPassword, showPassword);
   return showPassword;
 }
 
@@ -189,13 +189,10 @@ UInt32 Read_LimitGB()
 {
   CS_LOCK
   CKey key;
+  UInt32 v = (UInt32)(Int32)-1;
   if (OpenMainKey(key, kKeyName) == ERROR_SUCCESS)
-  {
-    UInt32 v;
-    if (key.QueryValue(kMemLimit, v) == ERROR_SUCCESS)
-      return v;
-  }
-  return (UInt32)(Int32)-1;
+    key.GetValue_UInt32_IfOk(kMemLimit, v);
+  return v;
 }
 
 }
@@ -371,9 +368,9 @@ void CInfo::Load()
   UString a;
   if (key.QueryValue(kArchiver, a) == ERROR_SUCCESS)
     ArcType = a;
-  key.GetValue_IfOk(kLevel, Level);
-  key.GetValue_IfOk(kShowPassword, ShowPassword);
-  key.GetValue_IfOk(kEncryptHeaders, EncryptHeaders);
+  key.GetValue_UInt32_IfOk(kLevel, Level);
+  key.GetValue_bool_IfOk(kShowPassword, ShowPassword);
+  key.GetValue_bool_IfOk(kEncryptHeaders, EncryptHeaders);
 }
 
 
@@ -517,7 +514,7 @@ void CInfo::Load()
     return;
 
   UInt32 dirType;
-  if (key.QueryValue(kWorkDirType, dirType) != ERROR_SUCCESS)
+  if (key.GetValue_UInt32_IfOk(kWorkDirType, dirType) != ERROR_SUCCESS)
     return;
   switch (dirType)
   {
@@ -535,7 +532,7 @@ void CInfo::Load()
     if (Mode == NMode::kSpecified)
       Mode = NMode::kSystem;
   }
-  key.GetValue_IfOk(kTempRemovableOnly, ForRemovableOnly);
+  key.GetValue_bool_IfOk(kTempRemovableOnly, ForRemovableOnly);
 }
 
 }
@@ -598,5 +595,5 @@ void CContextMenuInfo::Load()
 
   Key_Get_UInt32(key, kWriteZoneId, WriteZone);
 
-  Flags_Def = (key.GetValue_IfOk(kContextMenu, Flags) == ERROR_SUCCESS);
+  Flags_Def = (key.GetValue_UInt32_IfOk(kContextMenu, Flags) == ERROR_SUCCESS);
 }
diff --git a/CPP/7zip/UI/Console/ConsoleClose.cpp b/CPP/7zip/UI/Console/ConsoleClose.cpp
index 9e4c040..a184ffb 100644
--- a/CPP/7zip/UI/Console/ConsoleClose.cpp
+++ b/CPP/7zip/UI/Console/ConsoleClose.cpp
@@ -16,7 +16,7 @@
 namespace NConsoleClose {
 
 unsigned g_BreakCounter = 0;
-static const unsigned kBreakAbortThreshold = 2;
+static const unsigned kBreakAbortThreshold = 3;
 
 #ifdef _WIN32
 
@@ -28,8 +28,7 @@ static BOOL WINAPI HandlerRoutine(DWORD ctrlType)
     return TRUE;
   }
 
-  g_BreakCounter++;
-  if (g_BreakCounter < kBreakAbortThreshold)
+  if (++g_BreakCounter < kBreakAbortThreshold)
     return TRUE;
   return FALSE;
   /*
@@ -47,7 +46,7 @@ static BOOL WINAPI HandlerRoutine(DWORD ctrlType)
 CCtrlHandlerSetter::CCtrlHandlerSetter()
 {
   if (!SetConsoleCtrlHandler(HandlerRoutine, TRUE))
-    throw "SetConsoleCtrlHandler fails";
+    throw 1019; // "SetConsoleCtrlHandler fails";
 }
 
 CCtrlHandlerSetter::~CCtrlHandlerSetter()
@@ -63,8 +62,7 @@ CCtrlHandlerSetter::~CCtrlHandlerSetter()
 
 static void HandlerRoutine(int)
 {
-  g_BreakCounter++;
-  if (g_BreakCounter < kBreakAbortThreshold)
+  if (++g_BreakCounter < kBreakAbortThreshold)
     return;
   exit(EXIT_FAILURE);
 }
diff --git a/CPP/7zip/UI/Console/ConsoleClose.h b/CPP/7zip/UI/Console/ConsoleClose.h
index 25c5d0c..b0d99b4 100644
--- a/CPP/7zip/UI/Console/ConsoleClose.h
+++ b/CPP/7zip/UI/Console/ConsoleClose.h
@@ -5,7 +5,7 @@
 
 namespace NConsoleClose {
 
-class CCtrlBreakException {};
+// class CCtrlBreakException {};
 
 #ifdef UNDER_CE
 
diff --git a/CPP/7zip/UI/Console/ExtractCallbackConsole.cpp b/CPP/7zip/UI/Console/ExtractCallbackConsole.cpp
index f59d4c1..b127631 100644
--- a/CPP/7zip/UI/Console/ExtractCallbackConsole.cpp
+++ b/CPP/7zip/UI/Console/ExtractCallbackConsole.cpp
@@ -928,7 +928,7 @@ HRESULT CExtractCallbackConsole::ExtractResult(HRESULT result)
     if (result == E_ABORT
         || result == HRESULT_FROM_WIN32(ERROR_DISK_FULL))
       return result;
-    NumArcsWithError++; 
+    NumArcsWithError++;
     
     if (_se)
     {
diff --git a/CPP/7zip/UI/Console/MainAr.cpp b/CPP/7zip/UI/Console/MainAr.cpp
index 602ab64..490950b 100644
--- a/CPP/7zip/UI/Console/MainAr.cpp
+++ b/CPP/7zip/UI/Console/MainAr.cpp
@@ -140,11 +140,13 @@ int Z7_CDECL main
     PrintError(kMemoryExceptionMessage);
     return (NExitCode::kMemoryError);
   }
+/*
   catch(const NConsoleClose::CCtrlBreakException &)
   {
     PrintError(kUserBreakMessage);
     return (NExitCode::kUserBreak);
   }
+*/
   catch(const CMessagePathException &e)
   {
     PrintError(kException_CmdLine_Error_Message);
diff --git a/CPP/7zip/UI/Console/PercentPrinter.h b/CPP/7zip/UI/Console/PercentPrinter.h
index 46988a5..379aa1b 100644
--- a/CPP/7zip/UI/Console/PercentPrinter.h
+++ b/CPP/7zip/UI/Console/PercentPrinter.h
@@ -26,6 +26,13 @@ struct CPercentPrinterState
 
 class CPercentPrinter: public CPercentPrinterState
 {
+public:
+  CStdOutStream *_so;
+  bool DisablePrint;
+  bool NeedFlush;
+  unsigned MaxLen;
+  
+private:
   UInt32 _tickStep;
   DWORD _prevTick;
 
@@ -41,18 +48,13 @@ class CPercentPrinter: public CPercentPrinterState
   void GetPercents();
 
 public:
-  CStdOutStream *_so;
-
-  bool DisablePrint;
-  bool NeedFlush;
-  unsigned MaxLen;
   
   CPercentPrinter(UInt32 tickStep = 200):
-      _tickStep(tickStep),
-      _prevTick(0),
       DisablePrint(false),
       NeedFlush(true),
-      MaxLen(80 - 1)
+      MaxLen(80 - 1),
+      _tickStep(tickStep),
+      _prevTick(0)
   {}
 
   ~CPercentPrinter();
diff --git a/CPP/7zip/UI/Console/UpdateCallbackConsole.cpp b/CPP/7zip/UI/Console/UpdateCallbackConsole.cpp
index 3e79645..5185d5c 100644
--- a/CPP/7zip/UI/Console/UpdateCallbackConsole.cpp
+++ b/CPP/7zip/UI/Console/UpdateCallbackConsole.cpp
@@ -361,6 +361,119 @@ HRESULT CUpdateCallbackConsole::WriteSfx(const wchar_t *name, UInt64 size)
 }
 
 
+
+HRESULT CUpdateCallbackConsole::MoveArc_UpdateStatus()
+{
+  if (NeedPercents())
+  {
+    AString &s = _percent.Command;
+    s = " : ";
+    s.Add_UInt64(_arcMoving_percents);
+    s.Add_Char('%');
+    const bool totalDefined = (_arcMoving_total != 0 && _arcMoving_total != (UInt64)(Int64)-1);
+    if (_arcMoving_current != 0 || totalDefined)
+    {
+      s += " : ";
+      s.Add_UInt64(_arcMoving_current >> 20);
+      s += " MiB";
+    }
+    if (totalDefined)
+    {
+      s += " / ";
+      s.Add_UInt64((_arcMoving_total + ((1 << 20) - 1)) >> 20);
+      s += " MiB";
+    }
+    s += " : temporary archive moving ...";
+    _percent.Print();
+  }
+
+  // we ignore single Ctrl-C, if (_arcMoving_updateMode) mode
+  // because we want to get good final archive instead of temp archive.
+  if (NConsoleClose::g_BreakCounter == 1 && _arcMoving_updateMode)
+    return S_OK;
+  return CheckBreak();
+}
+
+
+HRESULT CUpdateCallbackConsole::MoveArc_Start(
+    const wchar_t *srcTempPath, const wchar_t *destFinalPath,
+    UInt64 size, Int32 updateMode)
+{
+#if 0 // 1 : for debug
+  if (LogLevel > 0 && _so)
+  {
+    ClosePercents_for_so();
+    *_so << "Temporary archive moving:" << endl;
+    _tempU = srcTempPath;
+    _so->Normalize_UString_Path(_tempU);
+    _so->PrintUString(_tempU, _tempA);
+    *_so << endl;
+    _tempU = destFinalPath;
+    _so->Normalize_UString_Path(_tempU);
+    _so->PrintUString(_tempU, _tempA);
+    *_so << endl;
+  }
+#else
+  UNUSED_VAR(srcTempPath)
+  UNUSED_VAR(destFinalPath)
+#endif
+
+  _arcMoving_updateMode = updateMode;
+  _arcMoving_total = size;
+  _arcMoving_current = 0;
+  _arcMoving_percents = 0;
+  return MoveArc_UpdateStatus();
+}
+
+
+HRESULT CUpdateCallbackConsole::MoveArc_Progress(UInt64 totalSize, UInt64 currentSize)
+{
+#if 0 // 1 : for debug
+  if (_so)
+  {
+    ClosePercents_for_so();
+    *_so << totalSize << " : " << currentSize << endl;
+  }
+#endif
+
+  UInt64 percents = 0;
+  if (totalSize != 0)
+  {
+    if (totalSize < ((UInt64)1 << 57))
+      percents = currentSize * 100 / totalSize;
+    else
+      percents = currentSize / (totalSize / 100);
+  }
+
+#ifdef _WIN32
+  // Sleep(300); // for debug
+#endif
+  // totalSize = (UInt64)(Int64)-1; // for debug
+
+  if (percents == _arcMoving_percents)
+    return CheckBreak();
+  _arcMoving_current = currentSize;
+  _arcMoving_total = totalSize;
+  _arcMoving_percents = percents;
+  return MoveArc_UpdateStatus();
+}
+
+
+HRESULT CUpdateCallbackConsole::MoveArc_Finish()
+{
+  // _arcMoving_percents = 0;
+  if (NeedPercents())
+  {
+    _percent.Command.Empty();
+    _percent.Print();
+  }
+  // it can return delayed user break (E_ABORT) status,
+  // if it ignored single CTRL+C in MoveArc_Progress().
+  return CheckBreak();
+}
+
+
+
 HRESULT CUpdateCallbackConsole::DeletingAfterArchiving(const FString &path, bool /* isDir */)
 {
   if (LogLevel > 0 && _so)
diff --git a/CPP/7zip/UI/Console/UpdateCallbackConsole.h b/CPP/7zip/UI/Console/UpdateCallbackConsole.h
index 276edba..a386371 100644
--- a/CPP/7zip/UI/Console/UpdateCallbackConsole.h
+++ b/CPP/7zip/UI/Console/UpdateCallbackConsole.h
@@ -29,30 +29,31 @@ struct CErrorPathCodes
 
 class CCallbackConsoleBase
 {
-protected:
-  CPercentPrinter _percent;
+  void CommonError(const FString &path, DWORD systemError, bool isWarning);
 
+protected:
   CStdOutStream *_so;
   CStdOutStream *_se;
 
-  void CommonError(const FString &path, DWORD systemError, bool isWarning);
-  // void CommonError(const char *message);
-
   HRESULT ScanError_Base(const FString &path, DWORD systemError);
   HRESULT OpenFileError_Base(const FString &name, DWORD systemError);
   HRESULT ReadingFileError_Base(const FString &name, DWORD systemError);
 
 public:
-  bool NeedPercents() const { return _percent._so != NULL; }
-
   bool StdOutMode;
-
   bool NeedFlush;
   unsigned PercentsNameLevel;
   unsigned LogLevel;
 
+protected:
   AString _tempA;
   UString _tempU;
+  CPercentPrinter _percent;
+
+public:
+  CErrorPathCodes FailedFiles;
+  CErrorPathCodes ScanErrors;
+  UInt64 NumNonOpenFiles;
 
   CCallbackConsoleBase():
       StdOutMode(false),
@@ -62,6 +63,7 @@ public:
       NumNonOpenFiles(0)
       {}
   
+  bool NeedPercents() const { return _percent._so != NULL; }
   void SetWindowWidth(unsigned width) { _percent.MaxLen = width - 1; }
 
   void Init(
@@ -90,10 +92,6 @@ public:
       _percent.ClosePrint(false);
   }
 
-  CErrorPathCodes FailedFiles;
-  CErrorPathCodes ScanErrors;
-  UInt64 NumNonOpenFiles;
-
   HRESULT PrintProgress(const wchar_t *name, bool isDir, const char *command, bool showInLog);
 
   // void PrintInfoLine(const UString &s);
@@ -109,6 +107,14 @@ class CUpdateCallbackConsole Z7_final:
   Z7_IFACE_IMP(IUpdateCallbackUI)
   Z7_IFACE_IMP(IDirItemsCallback)
   Z7_IFACE_IMP(IUpdateCallbackUI2)
+
+  HRESULT MoveArc_UpdateStatus();
+
+  UInt64 _arcMoving_total;
+  UInt64 _arcMoving_current;
+  UInt64 _arcMoving_percents;
+  Int32  _arcMoving_updateMode;
+
 public:
   bool DeleteMessageWasShown;
 
@@ -119,7 +125,11 @@ public:
   #endif
 
   CUpdateCallbackConsole():
-      DeleteMessageWasShown(false)
+        _arcMoving_total(0)
+      , _arcMoving_current(0)
+      , _arcMoving_percents(0)
+      , _arcMoving_updateMode(0)
+      , DeleteMessageWasShown(false)
       #ifndef Z7_NO_CRYPTO
       , PasswordIsDefined(false)
       , AskPassword(false)
diff --git a/CPP/7zip/UI/Explorer/ContextMenu.cpp b/CPP/7zip/UI/Explorer/ContextMenu.cpp
index fab3493..0630d78 100644
--- a/CPP/7zip/UI/Explorer/ContextMenu.cpp
+++ b/CPP/7zip/UI/Explorer/ContextMenu.cpp
@@ -295,9 +295,13 @@ static const CHashCommand g_HashCommands[] =
 {
   { CZipContextMenu::kHash_CRC32,  "CRC-32",  "CRC32" },
   { CZipContextMenu::kHash_CRC64,  "CRC-64",  "CRC64" },
-  { CZipContextMenu::kHash_XXH64,  "XXH64",    "XXH64" },
+  { CZipContextMenu::kHash_XXH64,  "XXH64",   "XXH64" },
+  { CZipContextMenu::kHash_MD5,    "MD5",     "MD5" },
   { CZipContextMenu::kHash_SHA1,   "SHA-1",   "SHA1" },
   { CZipContextMenu::kHash_SHA256, "SHA-256", "SHA256" },
+  { CZipContextMenu::kHash_SHA384, "SHA-384", "SHA384" },
+  { CZipContextMenu::kHash_SHA512, "SHA-512", "SHA512" },
+  { CZipContextMenu::kHash_SHA3_256, "SHA3-256", "SHA3-256" },
   { CZipContextMenu::kHash_BLAKE2SP, "BLAKE2sp", "BLAKE2sp" },
   { CZipContextMenu::kHash_All,    "*",       "*" },
   { CZipContextMenu::kHash_Generate_SHA256, "SHA-256 -> file.sha256", "SHA256" },
@@ -1338,8 +1342,12 @@ HRESULT CZipContextMenu::InvokeCommandCommon(const CCommandMapItem &cmi)
       case kHash_CRC32:
       case kHash_CRC64:
       case kHash_XXH64:
+      case kHash_MD5:
       case kHash_SHA1:
       case kHash_SHA256:
+      case kHash_SHA384:
+      case kHash_SHA512:
+      case kHash_SHA3_256:
       case kHash_BLAKE2SP:
       case kHash_All:
       case kHash_Generate_SHA256:
diff --git a/CPP/7zip/UI/Explorer/ContextMenu.h b/CPP/7zip/UI/Explorer/ContextMenu.h
index a68ba9d..2759967 100644
--- a/CPP/7zip/UI/Explorer/ContextMenu.h
+++ b/CPP/7zip/UI/Explorer/ContextMenu.h
@@ -88,8 +88,12 @@ public:
     kHash_CRC32,
     kHash_CRC64,
     kHash_XXH64,
+    kHash_MD5,
     kHash_SHA1,
     kHash_SHA256,
+    kHash_SHA384,
+    kHash_SHA512,
+    kHash_SHA3_256,
     kHash_BLAKE2SP,
     kHash_All,
     kHash_Generate_SHA256,
diff --git a/CPP/7zip/UI/Far/Far.cpp b/CPP/7zip/UI/Far/Far.cpp
index 211dde8..962af97 100644
--- a/CPP/7zip/UI/Far/Far.cpp
+++ b/CPP/7zip/UI/Far/Far.cpp
@@ -116,15 +116,16 @@ Z7_CLASS_IMP_COM_3(
   // DWORD m_StartTickValue;
   bool m_MessageBoxIsShown;
 
-  CProgressBox _progressBox;
-
   bool _numFilesTotalDefined;
   bool _numBytesTotalDefined;
-
 public:
   bool PasswordIsDefined;
   UString Password;
 
+private:
+  CProgressBox _progressBox;
+public:
+
   COpenArchiveCallback()
     {}
   
diff --git a/CPP/7zip/UI/Far/FarUtils.cpp b/CPP/7zip/UI/Far/FarUtils.cpp
index ed61ccc..3c33d8e 100644
--- a/CPP/7zip/UI/Far/FarUtils.cpp
+++ b/CPP/7zip/UI/Far/FarUtils.cpp
@@ -281,7 +281,7 @@ UInt32 CStartupInfo::QueryRegKeyValue(HKEY parentKey, const char *keyName,
     return valueDefault;
   
   UInt32 value;
-  if (regKey.QueryValue(valueName, value) != ERROR_SUCCESS)
+  if (regKey.GetValue_UInt32_IfOk(valueName, value) != ERROR_SUCCESS)
     return valueDefault;
   
   return value;
@@ -295,7 +295,7 @@ bool CStartupInfo::QueryRegKeyValue(HKEY parentKey, const char *keyName,
     return valueDefault;
   
   bool value;
-  if (regKey.QueryValue(valueName, value) != ERROR_SUCCESS)
+  if (regKey.GetValue_bool_IfOk(valueName, value) != ERROR_SUCCESS)
     return valueDefault;
   
   return value;
diff --git a/CPP/7zip/UI/Far/ProgressBox.h b/CPP/7zip/UI/Far/ProgressBox.h
index 6e8b487..f6b36c4 100644
--- a/CPP/7zip/UI/Far/ProgressBox.h
+++ b/CPP/7zip/UI/Far/ProgressBox.h
@@ -45,7 +45,12 @@ class CProgressBox: public CPercentPrinterState
   DWORD _prevElapsedSec;
 
   bool _wasPrinted;
+public:
+  bool UseBytesForPercents;
+  DWORD StartTick;
+  unsigned MaxLen;
 
+private:
   UString _tempU;
   UString _name1U;
   UString _name2U;
@@ -64,15 +69,12 @@ class CProgressBox: public CPercentPrinterState
   void ReduceString(const UString &src, AString &dest);
 
 public:
-  DWORD StartTick;
-  bool UseBytesForPercents;
-  unsigned MaxLen;
 
   CProgressBox(UInt32 tickStep = 200):
       _tickStep(tickStep),
       _prevTick(0),
-      StartTick(0),
       UseBytesForPercents(true),
+      StartTick(0),
       MaxLen(60)
     {}
 
diff --git a/CPP/7zip/UI/Far/UpdateCallbackFar.cpp b/CPP/7zip/UI/Far/UpdateCallbackFar.cpp
index 94f0a47..16702d3 100644
--- a/CPP/7zip/UI/Far/UpdateCallbackFar.cpp
+++ b/CPP/7zip/UI/Far/UpdateCallbackFar.cpp
@@ -210,6 +210,96 @@ Z7_COM7F_IMF(CUpdateCallback100Imp::ReportUpdateOperation(UInt32 op, const wchar
 }
 
 
+HRESULT CUpdateCallback100Imp::MoveArc_UpdateStatus()
+{
+  MT_LOCK
+
+  if (_percent)
+  {
+    AString s;
+    s.Add_UInt64(_arcMoving_percents);
+    // status.Add_Space();
+    s.Add_Char('%');
+    const bool totalDefined = (_arcMoving_total != 0 && _arcMoving_total != (UInt64)(Int64)-1);
+    if (_arcMoving_current != 0 || totalDefined)
+    {
+      s += " : ";
+      s.Add_UInt64(_arcMoving_current >> 20);
+      s += " MiB";
+    }
+    if (totalDefined)
+    {
+      s += " / ";
+      s.Add_UInt64((_arcMoving_total + ((1 << 20) - 1)) >> 20);
+      s += " MiB";
+    }
+    s += " : temporary archive moving ...";
+    _percent->Command =  s;
+    _percent->Print();
+  }
+
+  return CheckBreak2();
+}
+
+
+Z7_COM7F_IMF(CUpdateCallback100Imp::MoveArc_Start(const wchar_t *srcTempPath, const wchar_t * /* destFinalPath */ , UInt64 size, Int32 /* updateMode */))
+{
+  MT_LOCK
+
+  _arcMoving_total = size;
+  _arcMoving_current = 0;
+  _arcMoving_percents = 0;
+  // _arcMoving_updateMode = updateMode;
+  // _name2 = fs2us(destFinalPath);
+  if (_percent)
+    _percent->FileName = srcTempPath;
+  return MoveArc_UpdateStatus();
+}
+
+Z7_COM7F_IMF(CUpdateCallback100Imp::MoveArc_Progress(UInt64 totalSize, UInt64 currentSize))
+{
+  UInt64 percents = 0;
+  if (totalSize != 0)
+  {
+    if (totalSize < ((UInt64)1 << 57))
+      percents = currentSize * 100 / totalSize;
+    else
+      percents = currentSize / (totalSize / 100);
+  }
+
+#ifdef _WIN32
+  // Sleep(300); // for debug
+#endif
+  if (percents == _arcMoving_percents)
+    return CheckBreak2();
+  _arcMoving_total = totalSize;
+  _arcMoving_current = currentSize;
+  _arcMoving_percents = percents;
+  // if (_arcMoving_percents > 100) return E_FAIL;
+  return MoveArc_UpdateStatus();
+}
+
+
+Z7_COM7F_IMF(CUpdateCallback100Imp::MoveArc_Finish())
+{
+  // _arcMoving_percents = 0;
+  if (_percent)
+  {
+    _percent->Command.Empty();
+    _percent->FileName.Empty();
+    _percent->Print();
+  }
+  return CheckBreak2();
+}
+
+
+Z7_COM7F_IMF(CUpdateCallback100Imp::Before_ArcReopen())
+{
+  // fixme: we can use Clear_Stop_Status() here
+  return CheckBreak2();
+}
+
+
 extern HRESULT GetPassword(UString &password);
 
 Z7_COM7F_IMF(CUpdateCallback100Imp::CryptoGetTextPassword(BSTR *password))
diff --git a/CPP/7zip/UI/Far/UpdateCallbackFar.h b/CPP/7zip/UI/Far/UpdateCallbackFar.h
index 4ec5eed..8d2c8b8 100644
--- a/CPP/7zip/UI/Far/UpdateCallbackFar.h
+++ b/CPP/7zip/UI/Far/UpdateCallbackFar.h
@@ -11,10 +11,11 @@
 
 #include "ProgressBox.h"
 
-Z7_CLASS_IMP_COM_6(
+Z7_CLASS_IMP_COM_7(
   CUpdateCallback100Imp
   , IFolderArchiveUpdateCallback
   , IFolderArchiveUpdateCallback2
+  , IFolderArchiveUpdateCallback_MoveArc
   , IFolderScanProgress
   , ICryptoGetTextPassword2
   , ICryptoGetTextPassword
@@ -25,6 +26,15 @@ Z7_CLASS_IMP_COM_6(
   // CMyComPtr<IInFolderArchive> _archiveHandler;
   CProgressBox *_percent;
   // UInt64 _total;
+
+  HRESULT MoveArc_UpdateStatus();
+
+private:
+  UInt64 _arcMoving_total;
+  UInt64 _arcMoving_current;
+  UInt64 _arcMoving_percents;
+  // Int32  _arcMoving_updateMode;
+
 public:
   bool PasswordIsDefined;
   UString Password;
@@ -38,6 +48,10 @@ public:
     _percent = progressBox;
     PasswordIsDefined = false;
     Password.Empty();
+    _arcMoving_total = 0;
+    _arcMoving_current = 0;
+    _arcMoving_percents = 0;
+    //  _arcMoving_updateMode = 0;
   }
 };
 
diff --git a/CPP/7zip/UI/FileManager/App.cpp b/CPP/7zip/UI/FileManager/App.cpp
index 06c2e8b..5b7d616 100644
--- a/CPP/7zip/UI/FileManager/App.cpp
+++ b/CPP/7zip/UI/FileManager/App.cpp
@@ -402,11 +402,17 @@ void CApp::Save()
   // Save_ShowDeleted(ShowDeletedFiles);
 }
 
-void CApp::Release()
+void CApp::ReleaseApp()
 {
+  // 24.09: ReleasePanel() will stop panel timer processing.
+  // but we want to stop timer processing for all panels
+  // before ReleasePanel() calling.
+  unsigned i;
+  for (i = 0; i < kNumPanelsMax; i++)
+    Panels[i].Disable_Processing_Timer_Notify_StatusBar();
   // It's for unloading COM dll's: don't change it.
-  for (unsigned i = 0; i < kNumPanelsMax; i++)
-    Panels[i].Release();
+  for (i = 0; i < kNumPanelsMax; i++)
+    Panels[i].ReleasePanel();
 }
 
 // reduces path to part that exists on disk (or root prefix of path)
@@ -644,7 +650,7 @@ void CApp::OnCopy(bool move, bool copyToSame, unsigned srcPanelIndex)
     destPath += correctName;
 
     #if defined(_WIN32) && !defined(UNDER_CE)
-    if (destPath.Len() > 0 && destPath[0] == '\\')
+    if (destPath.Len() != 0 && destPath[0] == '\\')
       if (destPath.Len() == 1 || destPath[1] != '\\')
       {
         srcPanel.MessageBox_Error_UnsupportOperation();
diff --git a/CPP/7zip/UI/FileManager/App.h b/CPP/7zip/UI/FileManager/App.h
index 1e20532..cf74d6a 100644
--- a/CPP/7zip/UI/FileManager/App.h
+++ b/CPP/7zip/UI/FileManager/App.h
@@ -109,7 +109,7 @@ public:
   HRESULT Create(HWND hwnd, const UString &mainPath, const UString &arcFormat, int xSizes[2], bool needOpenArc, COpenResult &openRes);
   void Read();
   void Save();
-  void Release();
+  void ReleaseApp();
 
   // void SetFocus(int panelIndex) { Panels[panelIndex].SetFocusToList(); }
   void SetFocusToLastItem() { Panels[LastFocusedPanel].SetFocusToLastRememberedItem(); }
diff --git a/CPP/7zip/UI/FileManager/ExtractCallback.cpp b/CPP/7zip/UI/FileManager/ExtractCallback.cpp
index 6ec6065..da25969 100644
--- a/CPP/7zip/UI/FileManager/ExtractCallback.cpp
+++ b/CPP/7zip/UI/FileManager/ExtractCallback.cpp
@@ -2,7 +2,6 @@
 
 #include "StdAfx.h"
 
-
 #include "../../../Common/ComTry.h"
 #include "../../../Common/IntToString.h"
 #include "../../../Common/Lang.h"
@@ -27,11 +26,11 @@
 #include "ExtractCallback.h"
 #include "FormatUtils.h"
 #include "LangUtils.h"
+#include "MemDialog.h"
 #include "OverwriteDialog.h"
 #ifndef Z7_NO_CRYPTO
 #include "PasswordDialog.h"
 #endif
-#include "MemDialog.h"
 #include "PropertyName.h"
 
 using namespace NWindows;
@@ -44,9 +43,9 @@ CExtractCallbackImp::~CExtractCallbackImp() {}
 
 void CExtractCallbackImp::Init()
 {
-  _lang_Extracting = LangString(IDS_PROGRESS_EXTRACTING);
-  _lang_Testing = LangString(IDS_PROGRESS_TESTING);
-  _lang_Skipping = LangString(IDS_PROGRESS_SKIPPING);
+  LangString(IDS_PROGRESS_EXTRACTING, _lang_Extracting);
+  LangString(IDS_PROGRESS_TESTING, _lang_Testing);
+  LangString(IDS_PROGRESS_SKIPPING, _lang_Skipping);
   _lang_Reading = "Reading";
 
   NumArchiveErrors = 0;
@@ -107,19 +106,19 @@ HRESULT CExtractCallbackImp::Open_SetTotal(const UInt64 *files, const UInt64 *by
   {
     if (files)
     {
-      _totalFilesDefined = true;
+      _totalFiles_Defined = true;
       // res = ProgressDialog->Sync.Set_NumFilesTotal(*files);
     }
     else
-      _totalFilesDefined = false;
+      _totalFiles_Defined = false;
 
     if (bytes)
     {
-      _totalBytesDefined = true;
+      _totalBytes_Defined = true;
       ProgressDialog->Sync.Set_NumBytesTotal(*bytes);
     }
     else
-      _totalBytesDefined = false;
+      _totalBytes_Defined = false;
   }
 
   return res;
@@ -217,7 +216,7 @@ Z7_COM7F_IMF(CExtractCallbackImp::AskOverwrite(
   dialog.NewFileInfo.Is_FileSystemFile = Src_Is_IO_FS_Folder;
   
   ProgressDialog->WaitCreating();
-  INT_PTR writeAnswer = dialog.Create(*ProgressDialog);
+  const INT_PTR writeAnswer = dialog.Create(*ProgressDialog);
   
   switch (writeAnswer)
   {
@@ -478,10 +477,10 @@ UString GetOpenArcErrorMessage(UInt32 errorFlags)
 
   for (unsigned i = 0; i < Z7_ARRAY_SIZE(k_ErrorFlagsIds); i++)
   {
-    UInt32 f = ((UInt32)1 << i);
+    const UInt32 f = (UInt32)1 << i;
     if ((errorFlags & f) == 0)
       continue;
-    UInt32 id = k_ErrorFlagsIds[i];
+    const UInt32 id = k_ErrorFlagsIds[i];
     UString m = LangString(id);
     if (m.IsEmpty())
       continue;
@@ -512,8 +511,8 @@ UString GetOpenArcErrorMessage(UInt32 errorFlags)
 
 static void ErrorInfo_Print(UString &s, const CArcErrorInfo &er)
 {
-  UInt32 errorFlags = er.GetErrorFlags();
-  UInt32 warningFlags = er.GetWarningFlags();
+  const UInt32 errorFlags = er.GetErrorFlags();
+  const UInt32 warningFlags = er.GetWarningFlags();
 
   if (errorFlags != 0)
     AddNewLineString(s, GetOpenArcErrorMessage(errorFlags));
@@ -524,7 +523,7 @@ static void ErrorInfo_Print(UString &s, const CArcErrorInfo &er)
   if (warningFlags != 0)
   {
     s += GetNameOfProperty(kpidWarningFlags, L"Warnings");
-    s += ":";
+    s.Add_Colon();
     s.Add_LF();
     AddNewLineString(s, GetOpenArcErrorMessage(warningFlags));
   }
@@ -852,34 +851,35 @@ Z7_COM7F_IMF(CExtractCallbackImp::GetStream7(const wchar_t *name,
   _newVirtFileWasAdded = false;
   _hashStream_WasUsed = false;
   _needUpdateStat = false;
+  _isFolder = IntToBool(isDir);
+  _curSize_Defined = false;
+  _curSize = 0;
 
   if (_hashStream)
     _hashStream->ReleaseStream();
 
-  GetItemBoolProp(getProp, kpidIsAltStream, _isAltStream);
-
-  if (!ProcessAltStreams && _isAltStream)
-    return S_OK;
-
   _filePath = name;
-  _isFolder = IntToBool(isDir);
-  _curSize = 0;
-  _curSize_Defined = false;
 
   UInt64 size = 0;
-  bool sizeDefined;
+  bool size_Defined;
   {
     NCOM::CPropVariant prop;
     RINOK(getProp->GetProp(kpidSize, &prop))
-    sizeDefined = ConvertPropVariantToUInt64(prop, size);
+    size_Defined = ConvertPropVariantToUInt64(prop, size);
   }
-
-  if (sizeDefined)
+  if (size_Defined)
   {
     _curSize = size;
     _curSize_Defined = true;
   }
 
+  GetItemBoolProp(getProp, kpidIsAltStream, _isAltStream);
+  if (!ProcessAltStreams && _isAltStream)
+    return S_OK;
+
+  if (isDir) // we don't support dir items extraction in this code
+    return S_OK;
+
   if (askExtractMode != NArchive::NExtract::NAskMode::kExtract &&
       askExtractMode != NArchive::NExtract::NAskMode::kTest)
     return S_OK;
@@ -890,40 +890,64 @@ Z7_COM7F_IMF(CExtractCallbackImp::GetStream7(const wchar_t *name,
   
   if (VirtFileSystem && askExtractMode == NArchive::NExtract::NAskMode::kExtract)
   {
-    CVirtFile &file = VirtFileSystemSpec->AddNewFile();
+    if (!VirtFileSystemSpec->Files.IsEmpty())
+      VirtFileSystemSpec->MaxTotalAllocSize -= VirtFileSystemSpec->Files.Back().Data.Size();
+    CVirtFile &file = VirtFileSystemSpec->Files.AddNew();
     _newVirtFileWasAdded = true;
-    file.Name = name;
-    file.IsDir = IntToBool(isDir);
+    // file.IsDir = _isFolder;
     file.IsAltStream = _isAltStream;
-    file.Size = 0;
+    file.WrittenSize = 0;
+    file.ExpectedSize = 0;
+    if (size_Defined)
+      file.ExpectedSize = size;
 
-    RINOK(GetTime(getProp, kpidCTime, file.CTime, file.CTimeDefined))
-    RINOK(GetTime(getProp, kpidATime, file.ATime, file.ATimeDefined))
-    RINOK(GetTime(getProp, kpidMTime, file.MTime, file.MTimeDefined))
+    if (VirtFileSystemSpec->Index_of_MainExtractedFile_in_Files < 0)
+      if (!file.IsAltStream || VirtFileSystemSpec->IsAltStreamFile)
+        VirtFileSystemSpec->Index_of_MainExtractedFile_in_Files =
+            (int)(VirtFileSystemSpec->Files.Size() - 1);
 
-    NCOM::CPropVariant prop;
-    RINOK(getProp->GetProp(kpidAttrib, &prop))
-    if (prop.vt == VT_UI4)
+    /* if we open only AltStream, then (name) contains only name without "fileName:" prefix */
+    file.BaseName = name;
+
+    if (file.IsAltStream
+        && !VirtFileSystemSpec->IsAltStreamFile
+        && file.BaseName.IsPrefixedBy_NoCase(VirtFileSystemSpec->FileName))
     {
-      file.Attrib = prop.ulVal;
-      file.AttribDefined = true;
+      const unsigned colonPos = VirtFileSystemSpec->FileName.Len();
+      if (file.BaseName[colonPos] == ':')
+      {
+        file.ColonWasUsed = true;
+        file.AltStreamName = name + (size_t)colonPos + 1;
+        file.BaseName.DeleteFrom(colonPos);
+        if (Is_ZoneId_StreamName(file.AltStreamName))
+        {
+          if (VirtFileSystemSpec->Index_of_ZoneBuf_AltStream_in_Files < 0)
+            VirtFileSystemSpec->Index_of_ZoneBuf_AltStream_in_Files =
+              (int)(VirtFileSystemSpec->Files.Size() - 1);
+        }
+      }
+    }
+    RINOK(GetTime(getProp, kpidCTime, file.CTime, file.CTime_Defined))
+    RINOK(GetTime(getProp, kpidATime, file.ATime, file.ATime_Defined))
+    RINOK(GetTime(getProp, kpidMTime, file.MTime, file.MTime_Defined))
+    {
+      NCOM::CPropVariant prop;
+      RINOK(getProp->GetProp(kpidAttrib, &prop))
+      if (prop.vt == VT_UI4)
+      {
+        file.Attrib = prop.ulVal;
+        file.Attrib_Defined = true;
+      }
     }
-    // else if (isDir) file.Attrib = FILE_ATTRIBUTE_DIRECTORY;
-
-    file.ExpectedSize = 0;
-    if (sizeDefined)
-      file.ExpectedSize = size;
     outStreamLoc = VirtFileSystem;
   }
 
   if (_hashStream)
   {
-    {
-      _hashStream->SetStream(outStreamLoc);
-      outStreamLoc = _hashStream;
-      _hashStream->Init(true);
-      _hashStream_WasUsed = true;
-    }
+    _hashStream->SetStream(outStreamLoc);
+    outStreamLoc = _hashStream;
+    _hashStream->Init(true);
+    _hashStream_WasUsed = true;
   }
 
   if (outStreamLoc)
@@ -1077,10 +1101,10 @@ Z7_COM7F_IMF(CExtractCallbackImp::RequestMemoryUse(
     // if (indexType == NArchive::NEventIndexType::kNoIndex)
     if ((flags & NRequestMemoryUseFlags::k_SkipArc_IsExpected) ||
         (flags & NRequestMemoryUseFlags::k_Report_SkipArc))
-      s += LangString(IDS_MSG_ARC_UNPACKING_WAS_SKIPPED);
+      AddLangString(s, IDS_MSG_ARC_UNPACKING_WAS_SKIPPED);
 /*
     else
-      s += LangString(IDS_MSG_ARC_FILES_UNPACKING_WAS_SKIPPED);
+      AddLangString(, IDS_MSG_ARC_FILES_UNPACKING_WAS_SKIPPED);
 */
     AddError_Message_ShowArcPath(s);
   }
@@ -1093,88 +1117,154 @@ Z7_COM7F_IMF(CExtractCallbackImp::RequestMemoryUse(
 }
 
 
-
-// static const UInt32 kBlockSize = ((UInt32)1 << 31);
-
 Z7_COM7F_IMF(CVirtFileSystem::Write(const void *data, UInt32 size, UInt32 *processedSize))
 {
   if (processedSize)
     *processedSize = 0;
   if (size == 0)
     return S_OK;
-  if (!_fileMode)
+  if (!_wasSwitchedToFsMode)
   {
     CVirtFile &file = Files.Back();
-    size_t rem = file.Data.Size() - (size_t)file.Size;
+    const size_t rem = file.Data.Size() - file.WrittenSize;
     bool useMem = true;
     if (rem < size)
     {
       UInt64 b = 0;
       if (file.Data.Size() == 0)
         b = file.ExpectedSize;
-      UInt64 a = file.Size + size;
+      UInt64 a = (UInt64)file.WrittenSize + size;
       if (b < a)
         b = a;
       a = (UInt64)file.Data.Size() * 2;
       if (b < a)
         b = a;
       useMem = false;
-      const size_t b_sizet = (size_t)b;
-      if (b == b_sizet && b <= MaxTotalAllocSize)
-        useMem = file.Data.ReAlloc_KeepData(b_sizet, (size_t)file.Size);
+      if (b <= MaxTotalAllocSize)
+        useMem = file.Data.ReAlloc_KeepData((size_t)b, file.WrittenSize);
     }
+
+#if 0 // 1 for debug : FLUSHING TO FS
+    useMem = false;
+#endif
+
     if (useMem)
     {
-      memcpy(file.Data + file.Size, data, size);
-      file.Size += size;
+      memcpy(file.Data + file.WrittenSize, data, size);
+      file.WrittenSize += size;
       if (processedSize)
         *processedSize = (UInt32)size;
       return S_OK;
     }
-    _fileMode = true;
+    _wasSwitchedToFsMode = true;
+  }
+  
+  if (!_newVirtFileStream_IsReadyToWrite) // we check for _newVirtFileStream_IsReadyToWrite to optimize execution
+  {
+    RINOK(FlushToDisk(false))
   }
-  RINOK(FlushToDisk(false))
-  return _outFileStream.Interface()->Write(data, size, processedSize);
+
+  if (_needWriteToRealFile)
+    return _outFileStream.Interface()->Write(data, size, processedSize);
+  if (processedSize)
+    *processedSize = size;
+  return S_OK;
 }
 
 
 HRESULT CVirtFileSystem::FlushToDisk(bool closeLast)
 {
-  _outFileStream.Create_if_Empty();
   while (_numFlushed < Files.Size())
   {
-    const CVirtFile &file = Files[_numFlushed];
-    const FString path = DirPrefix + us2fs(Get_Correct_FsFile_Name(file.Name));
-    if (!_fileIsOpen)
+    CVirtFile &file = Files[_numFlushed];
+    const FString basePath = DirPrefix + us2fs(Get_Correct_FsFile_Name(file.BaseName));
+    FString path = basePath;
+
+    if (file.ColonWasUsed)
     {
-      if (!_outFileStream->Create_NEW(path))
+      if (ZoneBuf.Size() != 0
+          && Is_ZoneId_StreamName(file.AltStreamName))
       {
-        // do we need to release stream here?
-        // _outFileStream.Release();
-        return E_FAIL;
-        // MessageBoxMyError(UString("Can't create file ") + fs2us(tempFilePath));
+        // it's expected that
+        // CArchiveExtractCallback::GetStream() have excluded
+        // ZoneId alt stream from extraction already.
+        // But we exclude alt stream extraction here too.
+        _numFlushed++;
+        continue;
       }
-      _fileIsOpen = true;
-      RINOK(WriteStream(_outFileStream, file.Data, (size_t)file.Size))
+      path.Add_Colon();
+      path += us2fs(Get_Correct_FsFile_Name(file.AltStreamName));
     }
+
+    if (!_newVirtFileStream_IsReadyToWrite)
+    {
+      if (file.ColonWasUsed)
+      {
+        NFind::CFileInfo parentFi;
+        if (parentFi.Find(basePath)
+            && parentFi.IsReadOnly())
+        {
+          _altStream_NeedRestore_Attrib_bool = true;
+          _altStream_NeedRestore_AttribVal = parentFi.Attrib;
+          NDir::SetFileAttrib(basePath, parentFi.Attrib & ~(DWORD)FILE_ATTRIBUTE_READONLY);
+        }
+      }
+      _outFileStream.Create_if_Empty();
+      _needWriteToRealFile = _outFileStream->Create_NEW(path);
+      if (!_needWriteToRealFile)
+      {
+        if (!file.ColonWasUsed)
+          return GetLastError_noZero_HRESULT(); // it's main file and we can't ignore such error.
+        // (file.ColonWasUsed == true)
+        // So it's additional alt stream.
+        // And we ignore file creation error for additional alt stream.
+        // ShowErrorMessage(UString("Can't create file ") + fs2us(path));
+      }
+      _newVirtFileStream_IsReadyToWrite = true;
+      // _openFilePath = path;
+      HRESULT hres = S_OK;
+      if (_needWriteToRealFile)
+        hres = WriteStream(_outFileStream, file.Data, file.WrittenSize);
+      // we free allocated memory buffer after data flushing:
+      file.WrittenSize = 0;
+      file.Data.Free();
+      RINOK(hres)
+    }
+    
     if (_numFlushed == Files.Size() - 1 && !closeLast)
       break;
-    if (file.CTimeDefined ||
-        file.ATimeDefined ||
-        file.MTimeDefined)
-      _outFileStream->SetTime(
-          file.CTimeDefined ? &file.CTime : NULL,
-          file.ATimeDefined ? &file.ATime : NULL,
-          file.MTimeDefined ? &file.MTime : NULL);
-    _outFileStream->Close();
+    
+    if (_needWriteToRealFile)
+    {
+      if (file.CTime_Defined ||
+          file.ATime_Defined ||
+          file.MTime_Defined)
+        _outFileStream->SetTime(
+          file.CTime_Defined ? &file.CTime : NULL,
+          file.ATime_Defined ? &file.ATime : NULL,
+          file.MTime_Defined ? &file.MTime : NULL);
+      _outFileStream->Close();
+    }
+    
     _numFlushed++;
-    _fileIsOpen = false;
+    _newVirtFileStream_IsReadyToWrite = false;
 
-    if (ZoneBuf.Size() != 0)
-      WriteZoneFile_To_BaseFile(path, ZoneBuf);
-
-    if (file.AttribDefined)
-      NDir::SetFileAttrib_PosixHighDetect(path, file.Attrib);
+    if (_needWriteToRealFile)
+    {
+      if (!file.ColonWasUsed
+          && ZoneBuf.Size() != 0)
+        WriteZoneFile_To_BaseFile(path, ZoneBuf);
+      if (file.Attrib_Defined)
+        NDir::SetFileAttrib_PosixHighDetect(path, file.Attrib);
+      // _openFilePath.Empty();
+      _needWriteToRealFile = false;
+    }
+      
+    if (_altStream_NeedRestore_Attrib_bool)
+    {
+      _altStream_NeedRestore_Attrib_bool = false;
+      NDir::SetFileAttrib(basePath, _altStream_NeedRestore_AttribVal);
+    }
   }
   return S_OK;
 }
diff --git a/CPP/7zip/UI/FileManager/ExtractCallback.h b/CPP/7zip/UI/FileManager/ExtractCallback.h
index 5c459aa..8b4dcb3 100644
--- a/CPP/7zip/UI/FileManager/ExtractCallback.h
+++ b/CPP/7zip/UI/FileManager/ExtractCallback.h
@@ -25,10 +25,6 @@
 
 #include "ProgressDialog2.h"
 
-#ifdef Z7_LANG
-// #include "LangUtils.h"
-#endif
-
 #ifndef Z7_SFX
 
 class CGrowBuf
@@ -39,12 +35,24 @@ class CGrowBuf
   Z7_CLASS_NO_COPY(CGrowBuf)
 
 public:
+  void Free()
+  {
+    MyFree(_items);
+    _items = NULL;
+    _size = 0;
+  }
+
+  // newSize >= keepSize
   bool ReAlloc_KeepData(size_t newSize, size_t keepSize)
   {
-    void *buf = MyAlloc(newSize);
-    if (!buf)
-      return false;
-    if (keepSize != 0)
+    void *buf = NULL;
+    if (newSize)
+    {
+      buf = MyAlloc(newSize);
+      if (!buf)
+        return false;
+    }
+    if (keepSize)
       memcpy(buf, _items, keepSize);
     MyFree(_items);
     _items = (Byte *)buf;
@@ -60,23 +68,27 @@ public:
   size_t Size() const { return _size; }
 };
 
+
 struct CVirtFile
 {
   CGrowBuf Data;
   
-  UInt64 Size; // real size
-  UInt64 ExpectedSize; // the size from props request. 0 if unknown
-
-  UString Name;
-
-  bool CTimeDefined;
-  bool ATimeDefined;
-  bool MTimeDefined;
-  bool AttribDefined;
+  UInt64 ExpectedSize; // size from props request. 0 if unknown
+  size_t WrittenSize;  // size of written data in (Data) buffer
+                       //   use (WrittenSize) only if (CVirtFileSystem::_newVirtFileStream_IsReadyToWrite == false)
+  UString BaseName;    // original name of file inside archive,
+                       // It's not path. So any path separators
+                       // should be treated as part of name (or as incorrect chars)
+  UString AltStreamName;
+
+  bool CTime_Defined;
+  bool ATime_Defined;
+  bool MTime_Defined;
+  bool Attrib_Defined;
   
-  bool IsDir;
+  // bool IsDir;
   bool IsAltStream;
-  
+  bool ColonWasUsed;
   DWORD Attrib;
 
   FILETIME CTime;
@@ -84,82 +96,82 @@ struct CVirtFile
   FILETIME MTime;
 
   CVirtFile():
-    CTimeDefined(false),
-    ATimeDefined(false),
-    MTimeDefined(false),
-    AttribDefined(false),
-    IsDir(false),
-    IsAltStream(false) {}
+    CTime_Defined(false),
+    ATime_Defined(false),
+    MTime_Defined(false),
+    Attrib_Defined(false),
+    // IsDir(false),
+    IsAltStream(false),
+    ColonWasUsed(false)
+    {}
 };
 
 
+/*
+  We use CVirtFileSystem only for single file extraction:
+  It supports the following cases and names:
+     - "fileName" : single file
+     - "fileName" item (main base file) and additional "fileName:altStream" items
+     - "altStream" : single item without "fileName:" prefix.
+  If file is flushed to disk, it uses Get_Correct_FsFile_Name(name).
+*/
+ 
 Z7_CLASS_IMP_NOQIB_1(
   CVirtFileSystem,
   ISequentialOutStream
 )
-  UInt64 _totalAllocSize;
-
-  size_t _pos;
   unsigned _numFlushed;
-  bool _fileIsOpen;
-  bool _fileMode;
+public:
+  bool IsAltStreamFile; // in:
+      // = true,  if extracting file is alt stream without "fileName:" prefix.
+      // = false, if extracting file is normal file, but additional
+      //          alt streams "fileName:altStream" items are possible.
+private:
+  bool _newVirtFileStream_IsReadyToWrite;    // it can non real file (if can't open alt stream)
+  bool _needWriteToRealFile;  // we need real writing to open file.
+  bool _wasSwitchedToFsMode;
+  bool _altStream_NeedRestore_Attrib_bool;
+  DWORD _altStream_NeedRestore_AttribVal;
+
   CMyComPtr2<ISequentialOutStream, COutFileStream> _outFileStream;
 public:
   CObjectVector<CVirtFile> Files;
-  UInt64 MaxTotalAllocSize;
-  FString DirPrefix;
+  size_t MaxTotalAllocSize; // remain size, including Files.Back()
+  FString DirPrefix; // files will be flushed to this FS directory.
+  UString FileName; // name of file that will be extracted.
+                    // it can be name of alt stream without "fileName:" prefix, if (IsAltStreamFile == trye).
+                    // we use that name to detect altStream part in "FileName:altStream".
   CByteBuffer ZoneBuf;
+  int Index_of_MainExtractedFile_in_Files; // out: index in Files. == -1, if expected file was not extracted
+  int Index_of_ZoneBuf_AltStream_in_Files; // out: index in Files. == -1, if no zonbuf alt stream
+  
 
-
-  CVirtFile &AddNewFile()
+  CVirtFileSystem()
   {
-    if (!Files.IsEmpty())
-    {
-      MaxTotalAllocSize -= Files.Back().Data.Size();
-    }
-    return Files.AddNew();
+    _numFlushed = 0;
+    IsAltStreamFile = false;
+    _newVirtFileStream_IsReadyToWrite = false;
+    _needWriteToRealFile = false;
+    _wasSwitchedToFsMode = false;
+    _altStream_NeedRestore_Attrib_bool = false;
+    MaxTotalAllocSize = (size_t)0 - 1;
+    Index_of_MainExtractedFile_in_Files = -1;
+    Index_of_ZoneBuf_AltStream_in_Files = -1;
   }
+
+  bool WasStreamFlushedToFS() const { return _wasSwitchedToFsMode; }
+
   HRESULT CloseMemFile()
   {
-    if (_fileMode)
-    {
-      return FlushToDisk(true);
-    }
+    if (_wasSwitchedToFsMode)
+      return FlushToDisk(true); // closeLast
     CVirtFile &file = Files.Back();
-    if (file.Data.Size() != file.Size)
-    {
-      file.Data.ReAlloc_KeepData((size_t)file.Size, (size_t)file.Size);
-    }
+    if (file.Data.Size() != file.WrittenSize)
+      file.Data.ReAlloc_KeepData(file.WrittenSize, file.WrittenSize);
     return S_OK;
   }
 
-  bool IsStreamInMem() const
-  {
-    if (_fileMode)
-      return false;
-    if (Files.Size() < 1 || /* Files[0].IsAltStream || */ Files[0].IsDir)
-      return false;
-    return true;
-  }
-
-  size_t GetMemStreamWrittenSize() const { return _pos; }
-
-  CVirtFileSystem():
-    MaxTotalAllocSize((UInt64)0 - 1)
-    {}
-
-  void Init()
-  {
-    _totalAllocSize = 0;
-    _fileMode = false;
-    _pos = 0;
-    _numFlushed = 0;
-    _fileIsOpen = false;
-  }
-
-  HRESULT CloseFile(const FString &path);
   HRESULT FlushToDisk(bool closeLast);
-  size_t GetPos() const { return _pos; }
 };
 
 #endif
@@ -217,12 +229,12 @@ class CExtractCallbackImp Z7_final:
 
   bool _needWriteArchivePath;
   bool _isFolder;
-  bool _totalFilesDefined;
-  bool _totalBytesDefined;
+  bool _totalFiles_Defined;
+  bool _totalBytes_Defined;
 public:
   bool MultiArcMode;
   bool ProcessAltStreams;
-  bool StreamMode;
+  bool StreamMode; // set to true, if you want the callee to call GetStream7()
   bool ThereAreMessageErrors;
   bool Src_Is_IO_FS_Folder;
 
@@ -246,9 +258,17 @@ private:
   bool _skipArc;
 #endif
 
+public:
+  bool YesToAll;
+  bool TestMode;
+
+  UInt32 NumArchiveErrors;
+  NExtract::NOverwriteMode::EEnum OverwriteMode;
+
+private:
   UString _currentArchivePath;
   UString _currentFilePath;
-  UString _filePath;
+  UString _filePath;  // virtual path than will be sent via IFolderExtractToStreamCallback
 
 #ifndef Z7_SFX
   UInt64 _curSize;
@@ -266,12 +286,6 @@ public:
   UInt64 NumFiles;
 #endif
 
-  UInt32 NumArchiveErrors;
-  NExtract::NOverwriteMode::EEnum OverwriteMode;
-
-  bool YesToAll;
-  bool TestMode;
-
 #ifndef Z7_NO_CRYPTO
   UString Password;
 #endif
@@ -283,8 +297,8 @@ public:
   UString _lang_Empty;
 
   CExtractCallbackImp():
-      _totalFilesDefined(false)
-    , _totalBytesDefined(false)
+      _totalFiles_Defined(false)
+    , _totalBytes_Defined(false)
     , MultiArcMode(false)
     , ProcessAltStreams(true)
     , StreamMode(false)
@@ -297,11 +311,13 @@ public:
 #ifndef Z7_SFX
     , _remember(false)
     , _skipArc(false)
-    , _hashCalc(NULL)
 #endif
-    , OverwriteMode(NExtract::NOverwriteMode::kAsk)
     , YesToAll(false)
     , TestMode(false)
+    , OverwriteMode(NExtract::NOverwriteMode::kAsk)
+#ifndef Z7_SFX
+    , _hashCalc(NULL)
+#endif
     {}
    
   ~CExtractCallbackImp();
diff --git a/CPP/7zip/UI/FileManager/FM.cpp b/CPP/7zip/UI/FileManager/FM.cpp
index fe4f2bd..7310802 100644
--- a/CPP/7zip/UI/FileManager/FM.cpp
+++ b/CPP/7zip/UI/FileManager/FM.cpp
@@ -63,8 +63,8 @@ bool g_LargePagesMode = false;
 static bool g_Maximized = false;
 
 extern
-UInt64 g_RAM_Size;
-UInt64 g_RAM_Size;
+size_t g_RAM_Size;
+size_t g_RAM_Size;
 
 #ifdef _WIN32
 extern
@@ -1025,8 +1025,11 @@ LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
       break;
     }
 
-    case WM_DESTROY:
+    case WM_CLOSE:
     {
+      // why do we use WA_INACTIVE here ?
+      SendMessage(hWnd, WM_ACTIVATE, MAKEWPARAM(WA_INACTIVE, 0), (LPARAM)hWnd);
+      g_ExitEventLauncher.Exit(false);
       // ::DragAcceptFiles(hWnd, FALSE);
       RevokeDragDrop(hWnd);
       g_App._dropTarget.Release();
@@ -1034,12 +1037,18 @@ LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
       if (g_WindowWasCreated)
         g_App.Save();
     
-      g_App.Release();
+      g_App.ReleaseApp();
       
       if (g_WindowWasCreated)
         SaveWindowInfo(hWnd);
 
       g_ExitEventLauncher.Exit(true);
+      // default DefWindowProc will call DestroyWindow / WM_DESTROY
+      break;
+    }
+
+    case WM_DESTROY:
+    {
       PostQuitMessage(0);
       break;
     }
diff --git a/CPP/7zip/UI/FileManager/MemDialog.cpp b/CPP/7zip/UI/FileManager/MemDialog.cpp
index 1ba717e..5d26d3a 100644
--- a/CPP/7zip/UI/FileManager/MemDialog.cpp
+++ b/CPP/7zip/UI/FileManager/MemDialog.cpp
@@ -55,13 +55,13 @@ static void AddSize_GB(UString &s, UInt32 size_GB, UInt32 id)
   AddLangString(s, id);
 }
 
-void CMemDialog::AddInfoMessage_To_String(UString &s, UInt64 *ramSize_GB)
+void CMemDialog::AddInfoMessage_To_String(UString &s, const UInt32 *ramSize_GB)
 {
   AddLangString(s, IDS_MEM_REQUIRES_BIG_MEM);
   AddSize_GB(s, Required_GB, IDS_MEM_REQUIRED_MEM_SIZE);
   AddSize_GB(s, Limit_GB, IDS_MEM_CURRENT_MEM_LIMIT);
   if (ramSize_GB)
-    AddSize_GB(s, (UInt32)*ramSize_GB, IDS_MEM_RAM_SIZE);
+    AddSize_GB(s, *ramSize_GB, IDS_MEM_RAM_SIZE);
   if (!FilePath.IsEmpty())
   {
     s.Add_LF();
@@ -88,11 +88,11 @@ bool CMemDialog::OnInit()
 
   // m_Action.Attach(GetItem(IDC_MEM_ACTION));
 
-  UInt64 ramSize = (UInt64)sizeof(size_t) << 29;
+  size_t ramSize = (size_t)sizeof(size_t) << 29;
   const bool ramSize_defined = NWindows::NSystem::GetRamSize(ramSize);
   // ramSize *= 10; // for debug
 
-  UInt64 ramSize_GB = (ramSize + (1u << 29)) >> 30;
+  UInt32 ramSize_GB = (UInt32)(((UInt64)ramSize + (1u << 29)) >> 30);
   if (ramSize_GB == 0)
     ramSize_GB = 1;
 
@@ -121,7 +121,7 @@ bool CMemDialog::OnInit()
     if (ramSize_defined)
     {
       s += " / ";
-      s.Add_UInt64(ramSize_GB);
+      s.Add_UInt32(ramSize_GB);
       s += " GB (RAM)";
     }
     SetItemText(IDT_MEM_GB, s);
diff --git a/CPP/7zip/UI/FileManager/MemDialog.h b/CPP/7zip/UI/FileManager/MemDialog.h
index 79de658..67f6b33 100644
--- a/CPP/7zip/UI/FileManager/MemDialog.h
+++ b/CPP/7zip/UI/FileManager/MemDialog.h
@@ -30,7 +30,7 @@ public:
   UString ArcPath;
   UString FilePath;
 
-  void AddInfoMessage_To_String(UString &s, UInt64 *ramSize_GB = NULL);
+  void AddInfoMessage_To_String(UString &s, const UInt32 *ramSize_GB = NULL);
   
   CMemDialog():
     NeedSave(false),
diff --git a/CPP/7zip/UI/FileManager/MyLoadMenu.cpp b/CPP/7zip/UI/FileManager/MyLoadMenu.cpp
index 51b8648..f190929 100644
--- a/CPP/7zip/UI/FileManager/MyLoadMenu.cpp
+++ b/CPP/7zip/UI/FileManager/MyLoadMenu.cpp
@@ -764,8 +764,12 @@ bool ExecuteFileCommand(unsigned id)
     case IDM_CRC32: g_App.CalculateCrc("CRC32"); break;
     case IDM_CRC64: g_App.CalculateCrc("CRC64"); break;
     case IDM_XXH64: g_App.CalculateCrc("XXH64"); break;
+    case IDM_MD5: g_App.CalculateCrc("MD5"); break;
     case IDM_SHA1: g_App.CalculateCrc("SHA1"); break;
     case IDM_SHA256: g_App.CalculateCrc("SHA256"); break;
+    case IDM_SHA384: g_App.CalculateCrc("SHA384"); break;
+    case IDM_SHA512: g_App.CalculateCrc("SHA512"); break;
+    case IDM_SHA3_256: g_App.CalculateCrc("SHA3-256"); break;
     case IDM_BLAKE2SP: g_App.CalculateCrc("BLAKE2sp"); break;
     
     case IDM_DIFF: g_App.DiffFiles(); break;
@@ -807,8 +811,8 @@ bool OnMenuCommand(HWND hWnd, unsigned id)
   {
     // File
     case IDCLOSE:
-      SendMessage(hWnd, WM_ACTIVATE, MAKEWPARAM(WA_INACTIVE, 0), (LPARAM)hWnd);
-      g_ExitEventLauncher.Exit(false);
+      // SendMessage(hWnd, WM_ACTIVATE, MAKEWPARAM(WA_INACTIVE, 0), (LPARAM)hWnd);
+      // g_ExitEventLauncher.Exit(false);
       SendMessage(hWnd, WM_CLOSE, 0, 0);
       break;
     
diff --git a/CPP/7zip/UI/FileManager/OpenCallback.cpp b/CPP/7zip/UI/FileManager/OpenCallback.cpp
index 5b6df50..e3cb2ec 100644
--- a/CPP/7zip/UI/FileManager/OpenCallback.cpp
+++ b/CPP/7zip/UI/FileManager/OpenCallback.cpp
@@ -27,7 +27,7 @@ HRESULT COpenArchiveCallback::Open_SetTotal(const UInt64 *numFiles, const UInt64
     ProgressDialog.Sync.Set_NumFilesTotal(numFiles ? *numFiles : (UInt64)(Int64)-1);
     // if (numFiles)
     {
-      ProgressDialog.Sync.Set_BytesProgressMode(numFiles == NULL);
+      ProgressDialog.Sync.Set_FilesProgressMode(numFiles != NULL);
     }
     if (numBytes)
       ProgressDialog.Sync.Set_NumBytesTotal(*numBytes);
diff --git a/CPP/7zip/UI/FileManager/Panel.cpp b/CPP/7zip/UI/FileManager/Panel.cpp
index f3fb38e..84bd88c 100644
--- a/CPP/7zip/UI/FileManager/Panel.cpp
+++ b/CPP/7zip/UI/FileManager/Panel.cpp
@@ -7,8 +7,8 @@
 #include "../../../Common/IntToString.h"
 #include "../../../Common/StringConvert.h"
 
-#include "../../../Windows/FileName.h"
 #include "../../../Windows/ErrorMsg.h"
+#include "../../../Windows/FileName.h"
 #include "../../../Windows/PropVariant.h"
 #include "../../../Windows/Thread.h"
 
@@ -49,8 +49,9 @@ static DWORD kStyles[4] = { LVS_ICON, LVS_SMALLICON, LVS_LIST, LVS_REPORT };
 
 extern HINSTANCE g_hInstance;
 
-void CPanel::Release()
+void CPanel::ReleasePanel()
 {
+  Disable_Processing_Timer_Notify_StatusBar();
   // It's for unloading COM dll's: don't change it.
   CloseOpenFolders();
   _sevenZipContextMenu.Release();
@@ -893,7 +894,7 @@ void CPanel::SetListViewMode(UInt32 index)
 void CPanel::ChangeFlatMode()
 {
   _flatMode = !_flatMode;
-  if (_parentFolders.Size() > 0)
+  if (!_parentFolders.IsEmpty())
     _flatModeForArc = _flatMode;
   else
     _flatModeForDisk = _flatMode;
@@ -904,7 +905,7 @@ void CPanel::ChangeFlatMode()
 void CPanel::Change_ShowNtfsStrems_Mode()
 {
   _showNtfsStrems_Mode = !_showNtfsStrems_Mode;
-  if (_parentFolders.Size() > 0)
+  if (!_parentFolders.IsEmpty())
     _showNtfsStrems_ModeForArc = _showNtfsStrems_Mode;
   else
     _showNtfsStrems_ModeForDisk = _showNtfsStrems_Mode;
@@ -1006,7 +1007,7 @@ void CPanel::GetFilePaths(const CRecordVector<UInt32> &operatedIndices, UStringV
 
 void CPanel::ExtractArchives()
 {
-  if (_parentFolders.Size() > 0)
+  if (!_parentFolders.IsEmpty())
   {
     _panelCallback->OnCopy(false, false);
     return;
diff --git a/CPP/7zip/UI/FileManager/Panel.h b/CPP/7zip/UI/FileManager/Panel.h
index 1b708f7..9c53048 100644
--- a/CPP/7zip/UI/FileManager/Panel.h
+++ b/CPP/7zip/UI/FileManager/Panel.h
@@ -162,32 +162,39 @@ struct CTempFileInfo
       NWindows::NFile::NDir::RemoveDir(FolderPath);
     }
   }
-  bool WasChanged(const NWindows::NFile::NFind::CFileInfo &newFileInfo) const
+  bool WasChanged_from_TempFileInfo(const NWindows::NFile::NFind::CFileInfo &newFileInfo) const
   {
     return newFileInfo.Size != FileInfo.Size ||
         CompareFileTime(&newFileInfo.MTime, &FileInfo.MTime) != 0;
   }
 };
 
+
 struct CFolderLink: public CTempFileInfo
 {
-  bool IsVirtual;
+  bool IsVirtual; // == true (if archive was open via IInStream):
+                  //    archive was open from another archive,
+                  //    archive size meets the size conditions derived from g_RAM_Size.
+                  //    VirtFileSystem was used
+                  //    archive was fully extracted to memory.
   bool UsePassword;
   NWindows::NDLL::CLibrary Library;
   CMyComPtr<IFolderFolder> ParentFolder; // can be NULL, if parent is FS folder (in _parentFolders[0])
   UString ParentFolderPath; // including tail slash (doesn't include paths parts of parent in next level)
   UString Password;
-
   UString VirtualPath; // without tail slash
-  CFolderLink(): IsVirtual(false), UsePassword(false) {}
+  CByteBuffer ZoneBuf; // ZoneBuf for virtaul stream (IsVirtual)
 
-  bool WasChanged(const NWindows::NFile::NFind::CFileInfo &newFileInfo) const
+  CFolderLink(): IsVirtual(false), UsePassword(false) {}
+  bool WasChanged_from_FolderLink(const NWindows::NFile::NFind::CFileInfo &newFileInfo) const
   {
-    return IsVirtual || CTempFileInfo::WasChanged(newFileInfo);
+    // we call it, if we have two real files.
+    // if archive was virtual, it means that we have updated that virtual to real file.
+    return IsVirtual || CTempFileInfo::WasChanged_from_TempFileInfo(newFileInfo);
   }
-
 };
 
+
 enum MyMessages
 {
   // we can use WM_USER, since we have defined new window class.
@@ -268,13 +275,14 @@ struct CCopyToOptions
 
   bool NeedRegistryZone;
   NExtract::NZoneIdMode::EEnum ZoneIdMode;
+  CByteBuffer ZoneBuf;
 
   UString folder;
 
   UStringVector hashMethods;
 
   CVirtFileSystem *VirtFileSystemSpec;
-  ISequentialOutStream *VirtFileSystem;
+  // ISequentialOutStream *VirtFileSystem;
   
   CCopyToOptions():
       streamMode(false),
@@ -285,8 +293,8 @@ struct CCopyToOptions
       showErrorMessages(false),
       NeedRegistryZone(true),
       ZoneIdMode(NExtract::NZoneIdMode::kNone),
-      VirtFileSystemSpec(NULL),
-      VirtFileSystem(NULL)
+      VirtFileSystemSpec(NULL)
+      // , VirtFileSystem(NULL)
       {}
 };
   
@@ -310,11 +318,60 @@ struct COpenResult
 
 class CPanel Z7_final: public NWindows::NControl::CWindow2
 {
+  bool _thereAre_ListView_Items;
+  // bool _virtualMode;
+  bool _enableItemChangeNotify;
+  bool _thereAreDeletedItems;
+  bool _markDeletedItems;
+  bool _dontShowMode;
+  bool _needSaveInfo;
+
+public:
+  bool PanelCreated;
+  bool _mySelectMode;
+  bool _showDots;
+  bool _showRealFileIcons;
+  bool _flatMode;
+  bool _flatModeForArc;
+  bool _flatModeForDisk;
+  bool _selectionIsDefined;
+  // bool _showNtfsStrems_Mode;
+  // bool _showNtfsStrems_ModeForDisk;
+  // bool _showNtfsStrems_ModeForArc;
+
+  bool _selectMark;
+  bool _lastFocusedIsList;
+
+  bool _processTimer;
+  bool _processNotify;
+  bool _processStatusBar;
+
+public:
+  bool _ascending;
+  PROPID _sortID;
+  // int _sortIndex;
+  Int32 _isRawSortProp;
+
+  CMyListView _listView;
+  CPanelCallback *_panelCallback;
+
+private:
+
   // CExtToIconMap _extToIconMap;
   UINT _baseID;
   unsigned _comboBoxID;
   UINT _statusBarID;
 
+public:
+  DWORD _exStyle;
+  // CUIntVector _realIndices;
+  int _timestampLevel;
+  UInt32 _listViewMode;
+  int _xSize;
+private:
+  int _startGroupSelect;
+  int _prevFocusedItem;
+
   CAppState *_appState;
 
   virtual bool OnCommand(unsigned code, unsigned itemID, LPARAM lParam, LRESULT &result) Z7_override;
@@ -351,22 +408,7 @@ class CPanel Z7_final: public NWindows::NControl::CWindow2
   bool OnCustomDraw(LPNMLVCUSTOMDRAW lplvcd, LRESULT &result);
 
 
-public:
-  HWND _mainWindow;
-  CPanelCallback *_panelCallback;
-
-  // void SysIconsWereChanged() { _extToIconMap.Clear(); }
-
-  void DeleteItems(bool toRecycleBin);
-  void CreateFolder();
-  void CreateFile();
-  bool CorrectFsPath(const UString &path, UString &result);
-  // bool IsPathForPlugin(const UString &path);
-
-private:
-
   void ChangeWindowSize(int xSize, int ySize);
- 
   HRESULT InitColumns();
   void DeleteColumn(unsigned index);
   void AddColumn(const CPropColumn &prop);
@@ -379,20 +421,13 @@ private:
   void OnInsert();
   // void OnUpWithShift();
   // void OnDownWithShift();
-public:
-  void UpdateSelection();
-  void SelectSpec(bool selectMode);
-  void SelectByType(bool selectMode);
-  void SelectAll(bool selectMode);
-  void InvertSelection();
-private:
-
   // UString GetFileType(UInt32 index);
   LRESULT SetItemText(LVITEMW &item);
-
   // CRecordVector<PROPID> m_ColumnsPropIDs;
 
 public:
+  HWND _mainWindow;
+
   NWindows::NControl::CReBar _headerReBar;
   NWindows::NControl::CToolBar _headerToolBar;
   NWindows::NControl::
@@ -405,42 +440,57 @@ public:
   UStringVector ComboBoxPaths;
   // CMyComboBox _headerComboBox;
   CMyComboBoxEdit _comboBoxEdit;
-  CMyListView _listView;
-  bool _thereAre_ListView_Items;
   NWindows::NControl::CStatusBar _statusBar;
-  bool _lastFocusedIsList;
   // NWindows::NControl::CStatusBar _statusBar2;
 
-  DWORD _exStyle;
-  bool _showDots;
-  bool _showRealFileIcons;
-  // bool _virtualMode;
-  // CUIntVector _realIndices;
-  bool _enableItemChangeNotify;
-  bool _mySelectMode;
+  CBoolVector _selectedStatusVector;
+  CSelectedState _selectedState;
 
-  int _timestampLevel;
+  UString _currentFolderPrefix;
+  
+  CObjectVector<CFolderLink> _parentFolders;
+  NWindows::NDLL::CLibrary _library;
+  
+  CMyComPtr<IFolderFolder> _folder;
+  CBoolVector _isDirVector;
+  CMyComPtr<IFolderCompare> _folderCompare;
+  CMyComPtr<IFolderGetItemName> _folderGetItemName;
+  CMyComPtr<IArchiveGetRawProps> _folderRawProps;
+  CMyComPtr<IFolderAltStreams> _folderAltStreams;
+  CMyComPtr<IFolderOperations> _folderOperations;
 
+  // for drag and drop highliting
+  int m_DropHighlighted_SelectionIndex;
+  // int m_SubFolderIndex;      // realIndex of item in m_Panel list (if drop cursor to that item)
+  UString m_DropHighlighted_SubFolderName;   // name of folder in m_Panel list (if drop cursor to that folder)
+
+  // CMyComPtr<IFolderGetSystemIconIndex> _folderGetSystemIconIndex;
+  UStringVector _fastFolders;
+
+  UString _typeIDString;
+  CListViewInfo _listViewInfo;
+  
+  CPropColumns _columns;
+  CPropColumns _visibleColumns;
+  
+  CMyComPtr<IContextMenu> _sevenZipContextMenu;
+  CMyComPtr<IContextMenu> _systemContextMenu;
+  
+  void UpdateSelection();
+  void SelectSpec(bool selectMode);
+  void SelectByType(bool selectMode);
+  void SelectAll(bool selectMode);
+  void InvertSelection();
 
   void RedrawListItems()
   {
     _listView.RedrawAllItems();
   }
-
-
-  CBoolVector _selectedStatusVector;
-
-  CSelectedState _selectedState;
-  bool _thereAreDeletedItems;
-  bool _markDeletedItems;
-
-  bool PanelCreated;
-
   void DeleteListItems()
   {
     if (_thereAre_ListView_Items)
     {
-      bool b = _enableItemChangeNotify;
+      const bool b = _enableItemChangeNotify;
       _enableItemChangeNotify = false;
       _listView.DeleteAllItems();
       _thereAre_ListView_Items = false;
@@ -448,6 +498,15 @@ public:
     }
   }
 
+  // void SysIconsWereChanged() { _extToIconMap.Clear(); }
+
+  void DeleteItems(bool toRecycleBin);
+  void CreateFolder();
+  void CreateFile();
+  bool CorrectFsPath(const UString &path, UString &result);
+  // bool IsPathForPlugin(const UString &path);
+
+
   HWND GetParent() const;
 
   UInt32 GetRealIndex(const LVITEMW &item) const
@@ -471,46 +530,8 @@ public:
     return (unsigned)param;
   }
 
-  UInt32 _listViewMode;
-  int _xSize;
-
-  bool _flatMode;
-  bool _flatModeForDisk;
-  bool _flatModeForArc;
-
-  // bool _showNtfsStrems_Mode;
-  // bool _showNtfsStrems_ModeForDisk;
-  // bool _showNtfsStrems_ModeForArc;
-
-  bool _dontShowMode;
-
-
-  UString _currentFolderPrefix;
-  
-  CObjectVector<CFolderLink> _parentFolders;
-  NWindows::NDLL::CLibrary _library;
-  
-  CMyComPtr<IFolderFolder> _folder;
-  CBoolVector _isDirVector;
-  CMyComPtr<IFolderCompare> _folderCompare;
-  CMyComPtr<IFolderGetItemName> _folderGetItemName;
-  CMyComPtr<IArchiveGetRawProps> _folderRawProps;
-  CMyComPtr<IFolderAltStreams> _folderAltStreams;
-  CMyComPtr<IFolderOperations> _folderOperations;
-
-
-  // for drag and drop highliting
-  int m_DropHighlighted_SelectionIndex;
-  // int m_SubFolderIndex;      // realIndex of item in m_Panel list (if drop cursor to that item)
-  UString m_DropHighlighted_SubFolderName;   // name of folder in m_Panel list (if drop cursor to that folder)
-
   void ReleaseFolder();
   void SetNewFolder(IFolderFolder *newFolder);
-
-  // CMyComPtr<IFolderGetSystemIconIndex> _folderGetSystemIconIndex;
-
-  UStringVector _fastFolders;
-
   void GetSelectedNames(UStringVector &selectedNames);
   void SaveSelectedState(CSelectedState &s);
   HRESULT RefreshListCtrl(const CSelectedState &s);
@@ -575,61 +596,44 @@ public:
 
   CPanel() :
       _thereAre_ListView_Items(false),
-      _exStyle(0),
-      _showDots(false),
-      _showRealFileIcons(false),
-      // _virtualMode(flase),
+      // _virtualMode(false),
       _enableItemChangeNotify(true),
-      _mySelectMode(false),
-      _timestampLevel(kTimestampPrintLevel_MIN),
-
       _thereAreDeletedItems(false),
       _markDeletedItems(true),
-      PanelCreated(false),
-
-      _listViewMode(3),
-      _xSize(300),
+      _dontShowMode(false),
+      _needSaveInfo(false),
 
+      PanelCreated(false),
+      _mySelectMode(false),
+      _showDots(false),
+      _showRealFileIcons(false),
       _flatMode(false),
-      _flatModeForDisk(false),
       _flatModeForArc(false),
-
+      _flatModeForDisk(false),
+      _selectionIsDefined(false),
       // _showNtfsStrems_Mode(false),
       // _showNtfsStrems_ModeForDisk(false),
       // _showNtfsStrems_ModeForArc(false),
 
-      _dontShowMode(false),
-
-      m_DropHighlighted_SelectionIndex(-1),
-
-      _needSaveInfo(false),
+      _exStyle(0),
+      _timestampLevel(kTimestampPrintLevel_MIN),
+      _listViewMode(3),
+      _xSize(300),
       _startGroupSelect(0),
-      _selectionIsDefined(false)
+      m_DropHighlighted_SelectionIndex(-1)
   {}
 
+  ~CPanel() Z7_DESTRUCTOR_override;
+
+  void ReleasePanel();
+
   void SetExtendedStyle()
   {
     if (_listView)
       _listView.SetExtendedListViewStyle(_exStyle);
   }
 
-
-  bool _needSaveInfo;
-  UString _typeIDString;
-  CListViewInfo _listViewInfo;
-  
-  CPropColumns _columns;
-  CPropColumns _visibleColumns;
-  
-  PROPID _sortID;
-  // int _sortIndex;
-  bool _ascending;
-  Int32 _isRawSortProp;
-
   void SetSortRawStatus();
-
-  void Release();
-  ~CPanel() Z7_DESTRUCTOR_override;
   void OnLeftClick(MY_NMLISTVIEW_NMITEMACTIVATE *itemActivate);
   bool OnRightClick(MY_NMLISTVIEW_NMITEMACTIVATE *itemActivate, LRESULT &result);
   void ShowColumnsContextMenu(int x, int y);
@@ -638,9 +642,6 @@ public:
   void OnReload(bool onTimer = false);
   bool OnContextMenu(HANDLE windowHandle, int xPos, int yPos);
 
-  CMyComPtr<IContextMenu> _sevenZipContextMenu;
-  CMyComPtr<IContextMenu> _systemContextMenu;
-  
   HRESULT CreateShellContextMenu(
       const CRecordVector<UInt32> &operatedIndices,
       CMyComPtr<IContextMenu> &systemContextMenu);
@@ -672,12 +673,6 @@ public:
   void EditCopy();
   void EditPaste();
 
-  int _startGroupSelect;
-
-  bool _selectionIsDefined;
-  bool _selectMark;
-  int _prevFocusedItem;
-
  
   // void SortItems(int index);
   void SortItemsWithPropID(PROPID propID);
@@ -751,9 +746,12 @@ public:
   bool IsThereReadOnlyFolder() const;
   bool CheckBeforeUpdate(UINT resourceID);
 
-  bool _processTimer;
-  bool _processNotify;
-  bool _processStatusBar;
+  void Disable_Processing_Timer_Notify_StatusBar()
+  {
+    _processTimer = false;
+    _processNotify = false;
+    _processStatusBar = false;
+  }
 
   class CDisableTimerProcessing
   {
@@ -926,6 +924,7 @@ public:
   void ExtractArchives();
   void TestArchives();
 
+  void Get_ZoneId_Stream_from_ParentFolders(CByteBuffer &buf);
 
   HRESULT CopyTo(CCopyToOptions &options,
       const CRecordVector<UInt32> &indices,
@@ -939,7 +938,7 @@ public:
   {
     bool usePassword = false;
     UString password;
-    if (_parentFolders.Size() > 0)
+    if (!_parentFolders.IsEmpty())
     {
       const CFolderLink &fl = _parentFolders.Back();
       usePassword = fl.UsePassword;
@@ -978,6 +977,7 @@ public:
   UString GetItemsInfoString(const CRecordVector<UInt32> &indices);
 };
 
+
 class CMyBuffer
 {
   void *_data;
@@ -994,13 +994,12 @@ public:
   ~CMyBuffer() { ::MidFree(_data); }
 };
 
-class CExitEventLauncher
+struct CExitEventLauncher
 {
-public:
   NWindows::NSynchronization::CManualResetEvent _exitEvent;
   bool _needExit;
-  CRecordVector< ::CThread > _threads;
   unsigned _numActiveThreads;
+  CRecordVector< ::CThread > _threads;
     
   CExitEventLauncher()
   {
diff --git a/CPP/7zip/UI/FileManager/PanelCopy.cpp b/CPP/7zip/UI/FileManager/PanelCopy.cpp
index 36a0f6d..d4f1db7 100644
--- a/CPP/7zip/UI/FileManager/PanelCopy.cpp
+++ b/CPP/7zip/UI/FileManager/PanelCopy.cpp
@@ -75,11 +75,21 @@ HRESULT CPanelCopyThread::ProcessVirt()
 
   if (FolderOperations)
   {
-    CMyComPtr<IFolderSetZoneIdMode> setZoneMode;
-    FolderOperations.QueryInterface(IID_IFolderSetZoneIdMode, &setZoneMode);
-    if (setZoneMode)
     {
-      RINOK(setZoneMode->SetZoneIdMode(options->ZoneIdMode))
+      CMyComPtr<IFolderSetZoneIdMode> setZoneMode;
+      FolderOperations.QueryInterface(IID_IFolderSetZoneIdMode, &setZoneMode);
+      if (setZoneMode)
+      {
+        RINOK(setZoneMode->SetZoneIdMode(options->ZoneIdMode))
+      }
+    }
+    {
+      CMyComPtr<IFolderSetZoneIdFile> setZoneFile;
+      FolderOperations.QueryInterface(IID_IFolderSetZoneIdFile, &setZoneFile);
+      if (setZoneFile)
+      {
+        RINOK(setZoneFile->SetZoneIdFile(options->ZoneBuf, (UInt32)options->ZoneBuf.Size()))
+      }
     }
   }
 
@@ -143,6 +153,32 @@ static void ThrowException_if_Error(HRESULT res)
 #endif
 */
 
+void CPanel::Get_ZoneId_Stream_from_ParentFolders(CByteBuffer &buf)
+{
+  // we suppose that ZoneId of top parent has priority over ZoneId from childs.
+  FOR_VECTOR (i, _parentFolders)
+  {
+    // _parentFolders[0] = is top level archive
+    // _parentFolders[1 ... ].isVirtual == true is possible
+    //           if extracted size meets size conditions derived from g_RAM_Size.
+    const CFolderLink &fl = _parentFolders[i];
+    if (fl.IsVirtual)
+    {
+      if (fl.ZoneBuf.Size() != 0)
+      {
+        buf = fl.ZoneBuf;
+        return;
+      }
+    }
+    else if (!fl.FilePath.IsEmpty())
+    {
+      ReadZoneFile_Of_BaseFile(fl.FilePath, buf);
+      if (buf.Size() != 0)
+        return;
+    }
+  }
+}
+
 HRESULT CPanel::CopyTo(CCopyToOptions &options,
     const CRecordVector<UInt32> &indices,
     UStringVector *messages,
@@ -157,6 +193,10 @@ HRESULT CPanel::CopyTo(CCopyToOptions &options,
       options.ZoneIdMode = (NExtract::NZoneIdMode::EEnum)(int)(Int32)ci.WriteZone;
   }
 
+  if (options.ZoneBuf.Size() == 0
+      && options.ZoneIdMode != NExtract::NZoneIdMode::kNone)
+    Get_ZoneId_Stream_from_ParentFolders(options.ZoneBuf);
+
   if (IsHashFolder())
   {
     if (!options.testMode)
@@ -205,9 +245,9 @@ HRESULT CPanel::CopyTo(CCopyToOptions &options,
     extracter.Hash.MainName = extracter.Hash.FirstFileName;
   }
 
-  if (options.VirtFileSystem)
+  if (options.VirtFileSystemSpec)
   {
-    extracter.ExtractCallbackSpec->VirtFileSystem = options.VirtFileSystem;
+    extracter.ExtractCallbackSpec->VirtFileSystem = options.VirtFileSystemSpec;
     extracter.ExtractCallbackSpec->VirtFileSystemSpec = options.VirtFileSystemSpec;
   }
   extracter.ExtractCallbackSpec->ProcessAltStreams = options.includeAltStreams;
diff --git a/CPP/7zip/UI/FileManager/PanelDrag.cpp b/CPP/7zip/UI/FileManager/PanelDrag.cpp
index 040444c..f9b0a6c 100644
--- a/CPP/7zip/UI/FileManager/PanelDrag.cpp
+++ b/CPP/7zip/UI/FileManager/PanelDrag.cpp
@@ -2614,11 +2614,11 @@ Z7_COMWF_B CDropTarget::Drop(IDataObject *dataObject, DWORD keyState,
     UString s = LangString(cmdEffect == DROPEFFECT_MOVE ?
         IDS_MOVE_TO : IDS_COPY_TO);
     s.Add_LF();
-    s += "\'";
+    // s += "\'";
     s += m_Panel->_currentFolderPrefix;
-    s += "\'";
+    // s += "\'";
     s.Add_LF();
-    s += LangString(IDS_WANT_TO_COPY_FILES);
+    AddLangString(s, IDS_WANT_TO_COPY_FILES);
     s += " ?";
     const int res = ::MessageBoxW(*m_Panel, s, title, MB_YESNOCANCEL | MB_ICONQUESTION);
     if (res != IDYES)
@@ -2954,7 +2954,7 @@ static unsigned Drag_OnContextMenu(int xPos, int yPos, UInt32 cmdFlags)
       name = MyFormatNew(name, destPath);
       */
       name.Add_Space();
-      name += LangString(IDS_CONTEXT_ARCHIVE);
+      AddLangString(name, IDS_CONTEXT_ARCHIVE);
     }
     if (cmdId == NDragMenu::k_Cancel)
       menu.AppendItem(MF_SEPARATOR, 0, (LPCTSTR)NULL);
diff --git a/CPP/7zip/UI/FileManager/PanelItemOpen.cpp b/CPP/7zip/UI/FileManager/PanelItemOpen.cpp
index 244a962..aa56ef5 100644
--- a/CPP/7zip/UI/FileManager/PanelItemOpen.cpp
+++ b/CPP/7zip/UI/FileManager/PanelItemOpen.cpp
@@ -39,7 +39,7 @@ using namespace NFile;
 using namespace NDir;
 
 extern bool g_RAM_Size_Defined;
-extern UInt64 g_RAM_Size;
+extern size_t g_RAM_Size;
 
 #ifndef _UNICODE
 extern bool g_IsNT;
@@ -606,9 +606,9 @@ HRESULT CPanel::OpenParentArchiveFolder()
   NFind::CFileInfo newFileInfo;
   if (newFileInfo.Find(folderLink.FilePath))
   {
-    if (folderLink.WasChanged(newFileInfo))
+    if (folderLink.WasChanged_from_FolderLink(newFileInfo))
     {
-      UString message = MyFormatNew(IDS_WANT_UPDATE_MODIFIED_FILE, folderLink.RelPath);
+      const UString message = MyFormatNew(IDS_WANT_UPDATE_MODIFIED_FILE, folderLink.RelPath);
       if (::MessageBoxW((HWND)*this, message, L"7-Zip", MB_YESNOCANCEL | MB_ICONQUESTION) == IDYES)
       {
         if (OnOpenItemChanged(folderLink.FileIndex, fs2us(folderLink.FilePath),
@@ -1083,13 +1083,11 @@ void CExitEventLauncher::Exit(bool hardExit)
   FOR_VECTOR (i, _threads)
   {
     ::CThread &th = _threads[i];
-    DWORD wait = (hardExit ? 100 : INFINITE);
     if (Thread_WasCreated(&th))
     {
-      DWORD waitResult = WaitForSingleObject(th, wait);
+      const DWORD waitResult = WaitForSingleObject(th, hardExit ? 100 : INFINITE);
       // Thread_Wait(&th);
-      if (waitResult == WAIT_TIMEOUT)
-        wait = 1;
+      // if (waitResult == WAIT_TIMEOUT) wait = 1;
       if (!hardExit && waitResult != WAIT_OBJECT_0)
         continue;
       Thread_Close(&th);
@@ -1107,7 +1105,7 @@ static THREAD_FUNC_DECL MyThreadFunction(void *param)
   CMyUniquePtr<CTmpProcessInfo> tpi((CTmpProcessInfo *)param);
   CChildProcesses &processes = tpi->Processes;
 
-  bool mainProcessWasSet = !processes.Handles.IsEmpty();
+  const bool mainProcessWasSet = !processes.Handles.IsEmpty();
 
   bool isComplexMode = true;
 
@@ -1195,7 +1193,7 @@ static THREAD_FUNC_DECL MyThreadFunction(void *param)
         {
           NFind::CFileInfo newFileInfo;
           if (newFileInfo.Find(tpi->FilePath))
-            if (tpi->WasChanged(newFileInfo))
+            if (tpi->WasChanged_from_TempFileInfo(newFileInfo))
               needFindProcessByPath = false;
         }
         
@@ -1235,7 +1233,7 @@ static THREAD_FUNC_DECL MyThreadFunction(void *param)
 
     if (mainProcessWasSet)
     {
-      if (tpi->WasChanged(newFileInfo))
+      if (tpi->WasChanged_from_TempFileInfo(newFileInfo))
       {
         UString m = MyFormatNew(IDS_CANNOT_UPDATE_FILE, fs2us(tpi->FilePath));
         if (tpi->ReadOnly)
@@ -1279,10 +1277,10 @@ static THREAD_FUNC_DECL MyThreadFunction(void *param)
 
   {
     NFind::CFileInfo newFileInfo;
-    
-    bool finded = newFileInfo.Find(tpi->FilePath);
-
-    if (!needCheckTimestamp || !finded || !tpi->WasChanged(newFileInfo))
+    const bool finded = newFileInfo.Find(tpi->FilePath);
+    if (!needCheckTimestamp
+        || !finded
+        || !tpi->WasChanged_from_TempFileInfo(newFileInfo))
     {
       DEBUG_PRINT("Delete Temp file");
       tpi->DeleteDirAndFile();
@@ -1534,7 +1532,7 @@ void CPanel::OpenItemInArchive(unsigned index, bool tryInternal, bool tryExterna
 
   bool usePassword = false;
   UString password;
-  if (_parentFolders.Size() > 0)
+  if (!_parentFolders.IsEmpty())
   {
     const CFolderLink &fl = _parentFolders.Back();
     usePassword = fl.UsePassword;
@@ -1547,7 +1545,7 @@ void CPanel::OpenItemInArchive(unsigned index, bool tryInternal, bool tryExterna
   #ifndef _UNICODE
   if (g_IsNT)
   #endif
-  if (_parentFolders.Size() > 0)
+  if (!_parentFolders.IsEmpty())
   {
     const CFolderLink &fl = _parentFolders.Front();
     if (!fl.IsVirtual && !fl.FilePath.IsEmpty())
@@ -1576,39 +1574,42 @@ void CPanel::OpenItemInArchive(unsigned index, bool tryInternal, bool tryExterna
   
   if (tryAsArchive)
   {
+    // actually we want to get sum: size of main file plus sizes of altStreams.
+    // but now there is no interface to get altStreams sizes.
     NCOM::CPropVariant prop;
     _folder->GetProperty(index, kpidSize, &prop);
-    UInt64 fileLimit = 1 << 22;
-    if (g_RAM_Size_Defined)
-      fileLimit = g_RAM_Size / 4;
-
+    const size_t fileLimit = g_RAM_Size_Defined ?
+        g_RAM_Size >> MyMax(_parentFolders.Size() + 1, 8u):
+        1u << 22;
     UInt64 fileSize = 0;
     if (!ConvertPropVariantToUInt64(prop, fileSize))
       fileSize = fileLimit;
-    if (fileSize <= fileLimit && fileSize > 0)
+#if 0  // 1 : for debug
+    fileLimit = 1;
+#endif
+
+    if (fileSize <= fileLimit)
     {
       options.streamMode = true;
       virtFileSystemSpec = new CVirtFileSystem;
       virtFileSystem = virtFileSystemSpec;
+      virtFileSystemSpec->FileName = name;
+      virtFileSystemSpec->IsAltStreamFile = isAltStream;
 
 #if defined(_WIN32) && !defined(UNDER_CE)
 #ifndef _UNICODE
       if (g_IsNT)
 #endif
-      if (_parentFolders.Size() > 0)
       {
-        const CFolderLink &fl = _parentFolders.Front();
-        if (!fl.IsVirtual && !fl.FilePath.IsEmpty())
-          ReadZoneFile_Of_BaseFile(fl.FilePath, virtFileSystemSpec->ZoneBuf);
+        Get_ZoneId_Stream_from_ParentFolders(virtFileSystemSpec->ZoneBuf);
+        options.ZoneBuf = virtFileSystemSpec->ZoneBuf;
       }
 #endif
 
-      // we allow additional total size for small alt streams;
-      virtFileSystemSpec->MaxTotalAllocSize = fileSize + (1 << 10);
-      
+      virtFileSystemSpec->MaxTotalAllocSize = (size_t)fileSize
+            + (1 << 16); // we allow additional total size for small alt streams.
       virtFileSystemSpec->DirPrefix = tempDirNorm;
-      virtFileSystemSpec->Init();
-      options.VirtFileSystem = virtFileSystem;
+      // options.VirtFileSystem = virtFileSystem;
       options.VirtFileSystemSpec = virtFileSystemSpec;
     }
   }
@@ -1618,7 +1619,7 @@ void CPanel::OpenItemInArchive(unsigned index, bool tryInternal, bool tryExterna
 
   const HRESULT result = CopyTo(options, indices, &messages, usePassword, password);
 
-  if (_parentFolders.Size() > 0)
+  if (!_parentFolders.IsEmpty())
   {
     CFolderLink &fl = _parentFolders.Back();
     fl.UsePassword = usePassword;
@@ -1634,34 +1635,46 @@ void CPanel::OpenItemInArchive(unsigned index, bool tryInternal, bool tryExterna
     return;
   }
 
-  if (options.VirtFileSystem)
+  if (virtFileSystemSpec && !virtFileSystemSpec->WasStreamFlushedToFS())
   {
-    if (virtFileSystemSpec->IsStreamInMem())
+    int index_in_Files = virtFileSystemSpec->Index_of_MainExtractedFile_in_Files;
+    if (index_in_Files < 0)
     {
-      const CVirtFile &file = virtFileSystemSpec->Files[0];
-
-      size_t streamSize = (size_t)file.Size;
-      CBufInStream *bufInStreamSpec = new CBufInStream;
-      CMyComPtr<IInStream> bufInStream = bufInStreamSpec;
-      bufInStreamSpec->Init(file.Data, streamSize, virtFileSystem);
-
-      HRESULT res = OpenAsArc_Msg(bufInStream, tempFileInfo, fullVirtPath, type ? type : L""
+      if (virtFileSystemSpec->Files.Size() != 1)
+      {
+        MessageBox_Error_HRESULT(E_FAIL);
+        return;
+      }
+      // it's not expected case that index was not set, but we support that case
+      index_in_Files = 0;
+    }
+    {
+      const CVirtFile &file = virtFileSystemSpec->Files[index_in_Files];
+      CMyComPtr2_Create<IInStream, CBufInStream> bufInStream;
+      bufInStream->Init(file.Data, file.WrittenSize, virtFileSystem);
+      const HRESULT res = OpenAsArc_Msg(bufInStream, tempFileInfo,
+          fullVirtPath, type ? type : L""
           // , encrypted
           // , true // showErrorMessage
           );
-
       if (res == S_OK)
       {
+        if (virtFileSystemSpec->Index_of_ZoneBuf_AltStream_in_Files >= 0
+            && !_parentFolders.IsEmpty())
+        {
+          const CVirtFile &fileZone = virtFileSystemSpec->Files[
+              virtFileSystemSpec->Index_of_ZoneBuf_AltStream_in_Files];
+          _parentFolders.Back().ZoneBuf.CopyFrom(fileZone.Data, fileZone.WrittenSize);
+        }
+
         tempDirectory.DisableDeleting();
         RefreshListCtrl();
         return;
       }
-
       if (res == E_ABORT || res != S_FALSE)
         return;
       if (!tryExternal)
         return;
-      
       tryAsArchive = false;
       if (virtFileSystemSpec->FlushToDisk(true) != S_OK)
         return;
@@ -1684,7 +1697,7 @@ void CPanel::OpenItemInArchive(unsigned index, bool tryInternal, bool tryExterna
 
   if (tryAsArchive)
   {
-    HRESULT res = OpenAsArc_Msg(NULL, tempFileInfo, fullVirtPath, type ? type : L""
+    const HRESULT res = OpenAsArc_Msg(NULL, tempFileInfo, fullVirtPath, type ? type : L""
         // , encrypted
         // , true // showErrorMessage
         );
@@ -1732,7 +1745,7 @@ void CPanel::OpenItemInArchive(unsigned index, bool tryInternal, bool tryExterna
       return;
   }
 
-  tpi->Window = (HWND)(*this);
+  tpi->Window = (HWND)*this;
   tpi->FullPathFolderPrefix = _currentFolderPrefix;
   tpi->FileIndex = index;
   tpi->RelPath = relPath;
diff --git a/CPP/7zip/UI/FileManager/PanelItems.cpp b/CPP/7zip/UI/FileManager/PanelItems.cpp
index 544e9bf..868ad22 100644
--- a/CPP/7zip/UI/FileManager/PanelItems.cpp
+++ b/CPP/7zip/UI/FileManager/PanelItems.cpp
@@ -1438,13 +1438,16 @@ void CPanel::OnTimer()
     return;
   if (!AutoRefresh_Mode)
     return;
-  CMyComPtr<IFolderWasChanged> folderWasChanged;
-  if (_folder.QueryInterface(IID_IFolderWasChanged, &folderWasChanged) != S_OK)
-    return;
-  Int32 wasChanged;
-  if (folderWasChanged->WasChanged(&wasChanged) != S_OK)
-    return;
-  if (wasChanged == 0)
+  if (!_folder) // it's unexpected case, but we use it as additional protection.
     return;
+  {
+    CMyComPtr<IFolderWasChanged> folderWasChanged;
+    _folder.QueryInterface(IID_IFolderWasChanged, &folderWasChanged);
+    if (!folderWasChanged)
+      return;
+    Int32 wasChanged;
+    if (folderWasChanged->WasChanged(&wasChanged) != S_OK || wasChanged == 0)
+      return;
+  }
   OnReload(true); // onTimer
 }
diff --git a/CPP/7zip/UI/FileManager/PanelListNotify.cpp b/CPP/7zip/UI/FileManager/PanelListNotify.cpp
index 4dbd9f6..05ab36b 100644
--- a/CPP/7zip/UI/FileManager/PanelListNotify.cpp
+++ b/CPP/7zip/UI/FileManager/PanelListNotify.cpp
@@ -785,7 +785,7 @@ void CPanel::Refresh_StatusBar()
     wchar_t selectSizeString[32];
     selectSizeString[0] = 0;
     
-    if (indices.Size() > 0)
+    if (!indices.IsEmpty())
     {
       // for (unsigned ttt = 0; ttt < 1000; ttt++) {
       UInt64 totalSize = 0;
diff --git a/CPP/7zip/UI/FileManager/PanelOperations.cpp b/CPP/7zip/UI/FileManager/PanelOperations.cpp
index af313ff..8b16224 100644
--- a/CPP/7zip/UI/FileManager/PanelOperations.cpp
+++ b/CPP/7zip/UI/FileManager/PanelOperations.cpp
@@ -80,7 +80,7 @@ HRESULT CThreadFolderOperations::DoOperation(CPanel &panel, const UString &progr
 
   UpdateCallbackSpec->Init();
 
-  if (panel._parentFolders.Size() > 0)
+  if (!panel._parentFolders.IsEmpty())
   {
     const CFolderLink &fl = panel._parentFolders.Back();
     UpdateCallbackSpec->PasswordIsDefined = fl.UsePassword;
diff --git a/CPP/7zip/UI/FileManager/ProgressDialog2.cpp b/CPP/7zip/UI/FileManager/ProgressDialog2.cpp
index 690ebec..a070a0a 100644
--- a/CPP/7zip/UI/FileManager/ProgressDialog2.cpp
+++ b/CPP/7zip/UI/FileManager/ProgressDialog2.cpp
@@ -78,8 +78,9 @@ static const UInt32 kLangIDs_Colon[] =
 #define IS_DEFINED_VAL(v)     ((v) != UNDEFINED_VAL)
 
 CProgressSync::CProgressSync():
-    _stopped(false), _paused(false),
-    _bytesProgressMode(true),
+    _stopped(false),
+    _paused(false),
+    _filesProgressMode(false),
     _isDir(false),
     _totalBytes(UNDEFINED_VAL), _completedBytes(0),
     _totalFiles(UNDEFINED_VAL), _curFiles(0),
@@ -108,6 +109,13 @@ HRESULT CProgressSync::CheckStop()
   }
 }
 
+void CProgressSync::Clear_Stop_Status()
+{
+  CRITICAL_LOCK
+  if (_stopped)
+    _stopped = false;
+}
+
 HRESULT CProgressSync::ScanProgress(UInt64 numFiles, UInt64 totalSize, const FString &fileName, bool isDir)
 {
   {
@@ -242,27 +250,27 @@ void CProgressSync::AddError_Code_Name(HRESULT systemError, const wchar_t *name)
 }
 
 CProgressDialog::CProgressDialog():
-   _timer(0),
-   CompressingMode(true),
-   MainWindow(NULL)
+    _isDir(false),
+    _wasCreated(false),
+    _needClose(false),
+    _errorsWereDisplayed(false),
+    _waitCloseByCancelButton(false),
+    _cancelWasPressed(false),
+    _inCancelMessageBox(false),
+    _externalCloseMessageWasReceived(false),
+    _background(false),
+    WaitMode(false),
+    MessagesDisplayed(false),
+    CompressingMode(true),
+    ShowCompressionInfo(true),
+    _numPostedMessages(0),
+    _numAutoSizeMessages(0),
+    _numMessages(0),
+    _timer(0),
+    IconID(-1),
+    MainWindow(NULL)
 {
-  _isDir = false;
-
-  _numMessages = 0;
-  IconID = -1;
-  MessagesDisplayed = false;
-  _wasCreated = false;
-  _needClose = false;
-  _inCancelMessageBox = false;
-  _externalCloseMessageWasReceived = false;
-  
-  _numPostedMessages = 0;
-  _numAutoSizeMessages = 0;
-  _errorsWereDisplayed = false;
-  _waitCloseByCancelButton = false;
-  _cancelWasPressed = false;
-  ShowCompressionInfo = true;
-  WaitMode = false;
+
   if (_dialogCreatedEvent.Create() != S_OK)
     throw 1334987;
   if (_createDialogEvent.Create() != S_OK)
@@ -357,8 +365,6 @@ bool CProgressDialog::OnInit()
   _filesStr_Prev.Empty();
   _filesTotStr_Prev.Empty();
 
-  _foreground = true;
-
   m_ProgressBar.Attach(GetItem(IDC_PROGRESS1));
   _messageList.Attach(GetItem(IDL_PROGRESS_MESSAGES));
   _messageList.SetUnicodeFormat();
@@ -388,9 +394,8 @@ bool CProgressDialog::OnInit()
   SetPauseText();
   SetPriorityText();
 
-  _messageList.InsertColumn(0, L"", 30);
-  _messageList.InsertColumn(1, L"", 600);
-
+  _messageList.InsertColumn(0, L"", 40);
+  _messageList.InsertColumn(1, L"", 460);
   _messageList.SetColumnWidthAuto(0);
   _messageList.SetColumnWidthAuto(1);
 
@@ -690,7 +695,7 @@ static UInt64 MyMultAndDiv(UInt64 mult1, UInt64 mult2, UInt64 divider)
 void CProgressDialog::UpdateStatInfo(bool showAll)
 {
   UInt64 total, completed, totalFiles, completedFiles, inSize, outSize;
-  bool bytesProgressMode;
+  bool filesProgressMode;
 
   bool titleFileName_Changed;
   bool curFilePath_Changed;
@@ -704,7 +709,7 @@ void CProgressDialog::UpdateStatInfo(bool showAll)
     completedFiles = Sync._curFiles;
     inSize = Sync._inSize;
     outSize = Sync._outSize;
-    bytesProgressMode = Sync._bytesProgressMode;
+    filesProgressMode = Sync._filesProgressMode;
 
     GetChangedString(Sync._titleFileName, _titleFileName, titleFileName_Changed);
     GetChangedString(Sync._filePath, _filePath, curFilePath_Changed);
@@ -719,8 +724,8 @@ void CProgressDialog::UpdateStatInfo(bool showAll)
 
   UInt32 curTime = ::GetTickCount();
 
-  const UInt64 progressTotal = bytesProgressMode ? total : totalFiles;
-  const UInt64 progressCompleted = bytesProgressMode ? completed : completedFiles;
+  const UInt64 progressTotal = filesProgressMode ? totalFiles : total;
+  const UInt64 progressCompleted = filesProgressMode ? completedFiles : completed;
   {
     if (IS_UNDEFINED_VAL(progressTotal))
     {
@@ -900,7 +905,7 @@ void CProgressDialog::UpdateStatInfo(bool showAll)
   {
     UString s = _status;
     ReduceString(s, _numReduceSymbols);
-    SetItemText(IDT_PROGRESS_STATUS, _status);
+    SetItemText(IDT_PROGRESS_STATUS, s);
   }
 
   if (curFilePath_Changed)
@@ -1086,12 +1091,10 @@ void CProgressDialog::SetTitleText()
   }
   if (IS_DEFINED_VAL(_prevPercentValue))
   {
-    char temp[32];
-    ConvertUInt64ToString(_prevPercentValue, temp);
-    s += temp;
+    s.Add_UInt64(_prevPercentValue);
     s.Add_Char('%');
   }
-  if (!_foreground)
+  if (_background)
   {
     s.Add_Space();
     s += _backgrounded_String;
@@ -1138,17 +1141,17 @@ void CProgressDialog::OnPauseButton()
 
 void CProgressDialog::SetPriorityText()
 {
-  SetItemText(IDB_PROGRESS_BACKGROUND, _foreground ?
-      _background_String :
-      _foreground_String);
+  SetItemText(IDB_PROGRESS_BACKGROUND, _background ?
+      _foreground_String :
+      _background_String);
   SetTitleText();
 }
 
 void CProgressDialog::OnPriorityButton()
 {
-  _foreground = !_foreground;
+  _background = !_background;
   #ifndef UNDER_CE
-  SetPriorityClass(GetCurrentProcess(), _foreground ? NORMAL_PRIORITY_CLASS: IDLE_PRIORITY_CLASS);
+  SetPriorityClass(GetCurrentProcess(), _background ? IDLE_PRIORITY_CLASS : NORMAL_PRIORITY_CLASS);
   #endif
   SetPriorityText();
 }
@@ -1184,12 +1187,16 @@ void CProgressDialog::AddMessage(LPCWSTR message)
   _numMessages++;
 }
 
-static unsigned GetNumDigits(UInt32 val)
+static unsigned GetNumDigits(unsigned val)
 {
-  unsigned i;
-  for (i = 0; val >= 10; i++)
+  unsigned i = 0;
+  for (;;)
+  {
+    i++;
     val /= 10;
-  return i;
+    if (val == 0)
+      return i;
+  }
 }
 
 void CProgressDialog::UpdateMessagesDialog()
@@ -1197,7 +1204,7 @@ void CProgressDialog::UpdateMessagesDialog()
   UStringVector messages;
   {
     NSynchronization::CCriticalSectionLock lock(Sync._cs);
-    unsigned num = Sync.Messages.Size();
+    const unsigned num = Sync.Messages.Size();
     if (num > _numPostedMessages)
     {
       messages.ClearAndReserve(num - _numPostedMessages);
@@ -1210,7 +1217,11 @@ void CProgressDialog::UpdateMessagesDialog()
   {
     FOR_VECTOR (i, messages)
       AddMessage(messages[i]);
-    if (_numAutoSizeMessages < 256 || GetNumDigits(_numPostedMessages) > GetNumDigits(_numAutoSizeMessages))
+    // SetColumnWidthAuto() can be slow for big number of files.
+    if (_numPostedMessages < 1000000 || _numAutoSizeMessages < 100)
+    if (_numAutoSizeMessages < 100 ||
+        GetNumDigits(_numPostedMessages) >
+        GetNumDigits(_numAutoSizeMessages))
     {
       _messageList.SetColumnWidthAuto(0);
       _messageList.SetColumnWidthAuto(1);
diff --git a/CPP/7zip/UI/FileManager/ProgressDialog2.h b/CPP/7zip/UI/FileManager/ProgressDialog2.h
index 4ca9be7..60a5ca6 100644
--- a/CPP/7zip/UI/FileManager/ProgressDialog2.h
+++ b/CPP/7zip/UI/FileManager/ProgressDialog2.h
@@ -33,9 +33,8 @@ class CProgressSync
 {
   bool _stopped;
   bool _paused;
-
 public:
-  bool _bytesProgressMode;
+  bool _filesProgressMode;
   bool _isDir;
   UInt64 _totalBytes;
   UInt64 _completedBytes;
@@ -73,13 +72,14 @@ public:
     _paused = val;
   }
   
-  void Set_BytesProgressMode(bool bytesProgressMode)
+  void Set_FilesProgressMode(bool filesProgressMode)
   {
     NWindows::NSynchronization::CCriticalSectionLock lock(_cs);
-    _bytesProgressMode = bytesProgressMode;
+    _filesProgressMode = filesProgressMode;
   }
   
   HRESULT CheckStop();
+  void Clear_Stop_Status();
   HRESULT ScanProgress(UInt64 numFiles, UInt64 totalSize, const FString &fileName, bool isDir = false);
 
   HRESULT Set_NumFilesTotal(UInt64 val);
@@ -102,12 +102,32 @@ public:
   bool ThereIsMessage() const { return !Messages.IsEmpty() || FinalMessage.ThereIsMessage(); }
 };
 
+
 class CProgressDialog: public NWindows::NControl::CModalDialog
 {
+  bool _isDir;
+  bool _wasCreated;
+  bool _needClose;
+  bool _errorsWereDisplayed;
+  bool _waitCloseByCancelButton;
+  bool _cancelWasPressed;
+  bool _inCancelMessageBox;
+  bool _externalCloseMessageWasReceived;
+  bool _background;
+public:
+  bool WaitMode;
+  bool MessagesDisplayed; // = true if user pressed OK on all messages or there are no messages.
+  bool CompressingMode;
+  bool ShowCompressionInfo;
+
+private:
+  unsigned _numPostedMessages;
+  unsigned _numAutoSizeMessages;
+  unsigned _numMessages;
+
   UString _titleFileName;
   UString _filePath;
   UString _status;
-  bool _isDir;
 
   UString _background_String;
   UString _backgrounded_String;
@@ -152,7 +172,6 @@ class CProgressDialog: public NWindows::NControl::CModalDialog
   NWindows::NControl::CProgressBar m_ProgressBar;
   NWindows::NControl::CListView _messageList;
   
-  unsigned _numMessages;
   UStringVector _messageStrings;
 
   // #ifdef __ITaskbarList3_INTERFACE_DEFINED__
@@ -175,28 +194,10 @@ class CProgressDialog: public NWindows::NControl::CModalDialog
   UString _filesStr_Prev;
   UString _filesTotStr_Prev;
 
+  unsigned _numReduceSymbols;
   unsigned _prevSpeed_MoveBits;
   UInt64 _prevSpeed;
 
-  bool _foreground;
-
-  unsigned _numReduceSymbols;
-
-  bool _wasCreated;
-  bool _needClose;
-
-  unsigned _numPostedMessages;
-  UInt32 _numAutoSizeMessages;
-
-  bool _errorsWereDisplayed;
-
-  bool _waitCloseByCancelButton;
-  bool _cancelWasPressed;
-  
-  bool _inCancelMessageBox;
-  bool _externalCloseMessageWasReceived;
-
-
   // #ifdef __ITaskbarList3_INTERFACE_DEFINED__
   void SetTaskbarProgressState(TBPFLAG tbpFlags)
   {
@@ -244,14 +245,10 @@ class CProgressDialog: public NWindows::NControl::CModalDialog
   void ShowAfterMessages(HWND wndParent);
 
   void CheckNeedClose();
+
 public:
   CProgressSync Sync;
-  bool CompressingMode;
-  bool WaitMode;
-  bool ShowCompressionInfo;
-  bool MessagesDisplayed; // = true if user pressed OK on all messages or there are no messages.
   int IconID;
-
   HWND MainWindow;
   #ifndef Z7_SFX
   UString MainTitle;
diff --git a/CPP/7zip/UI/FileManager/RegistryUtils.cpp b/CPP/7zip/UI/FileManager/RegistryUtils.cpp
index 7e61998..0284591 100644
--- a/CPP/7zip/UI/FileManager/RegistryUtils.cpp
+++ b/CPP/7zip/UI/FileManager/RegistryUtils.cpp
@@ -86,17 +86,15 @@ static bool Read7ZipOption(LPCTSTR value, bool defaultValue)
   if (key.Open(HKEY_CURRENT_USER, kCUBasePath, KEY_READ) == ERROR_SUCCESS)
   {
     bool enabled;
-    if (key.QueryValue(value, enabled) == ERROR_SUCCESS)
+    if (key.GetValue_bool_IfOk(value, enabled) == ERROR_SUCCESS)
       return enabled;
   }
   return defaultValue;
 }
 
-static void ReadOption(CKey &key, LPCTSTR value, bool &dest)
+static void ReadOption(CKey &key, LPCTSTR name, bool &dest)
 {
-  bool enabled = false;
-  if (key.QueryValue(value, enabled) == ERROR_SUCCESS)
-    dest = enabled;
+  key.GetValue_bool_IfOk(name, dest);
 }
 
 /*
diff --git a/CPP/7zip/UI/FileManager/SettingsPage.cpp b/CPP/7zip/UI/FileManager/SettingsPage.cpp
index a5117be..8b5983a 100644
--- a/CPP/7zip/UI/FileManager/SettingsPage.cpp
+++ b/CPP/7zip/UI/FileManager/SettingsPage.cpp
@@ -161,7 +161,7 @@ bool CSettingsPage::OnInit()
     needSetCur = false;
   }
   {
-    _ramSize = (UInt64)(sizeof(size_t)) << 29;
+    _ramSize = (size_t)sizeof(size_t) << 29;
     _ramSize_Defined = NSystem::GetRamSize(_ramSize);
     UString s;
     if (_ramSize_Defined)
@@ -198,10 +198,10 @@ bool CSettingsPage::OnInit()
 
 
   {
-    UInt64 ramSize = (UInt64)sizeof(size_t) << 29;
+    size_t ramSize = (size_t)sizeof(size_t) << 29;
     const bool ramSize_defined = NWindows::NSystem::GetRamSize(ramSize);
     // ramSize *= 10; // for debug
-    UInt64 ramSize_GB = (ramSize + (1u << 29)) >> 30;
+    UInt32 ramSize_GB = (UInt32)(((UInt64)ramSize + (1u << 29)) >> 30);
     if (ramSize_GB == 0)
       ramSize_GB = 1;
     UString s ("GB");
diff --git a/CPP/7zip/UI/FileManager/SysIconUtils.cpp b/CPP/7zip/UI/FileManager/SysIconUtils.cpp
index 406c9e1..72fe5e7 100644
--- a/CPP/7zip/UI/FileManager/SysIconUtils.cpp
+++ b/CPP/7zip/UI/FileManager/SysIconUtils.cpp
@@ -109,7 +109,7 @@ DWORD_PTR Shell_GetFileInfo_SysIconIndex_for_Path_attrib_iconIndexRef(
     iconIndex = shFileInfo.iIcon;
     // we use SHGFI_USEFILEATTRIBUTES, and
     //   (res != 0) is expected for main cases, even if there are no such file.
-    //   (res == 0) for path with kSuperPrefix \\?\
+    //   (res == 0) for path with kSuperPrefix "\\?\"
     // Also SHGFI_USEFILEATTRIBUTES still returns icon inside exe.
     // So we can use SHGFI_USEFILEATTRIBUTES for any case.
     // UString temp = fs2us(path); // for debug
diff --git a/CPP/7zip/UI/FileManager/UpdateCallback100.cpp b/CPP/7zip/UI/FileManager/UpdateCallback100.cpp
index 71ad710..0796eba 100644
--- a/CPP/7zip/UI/FileManager/UpdateCallback100.cpp
+++ b/CPP/7zip/UI/FileManager/UpdateCallback100.cpp
@@ -113,6 +113,29 @@ Z7_COM7F_IMF(CUpdateCallback100Imp::SetCompleted(const UInt64 * /* files */, con
   return ProgressDialog->Sync.CheckStop();
 }
 
+
+Z7_COM7F_IMF(CUpdateCallback100Imp::MoveArc_Start(const wchar_t *srcTempPath, const wchar_t *destFinalPath, UInt64 size, Int32 updateMode))
+{
+  return MoveArc_Start_Base(srcTempPath, destFinalPath, size, updateMode);
+}
+
+Z7_COM7F_IMF(CUpdateCallback100Imp::MoveArc_Progress(UInt64 totalSize, UInt64 currentSize))
+{
+  return MoveArc_Progress_Base(totalSize, currentSize);
+}
+
+Z7_COM7F_IMF(CUpdateCallback100Imp::MoveArc_Finish())
+{
+  return MoveArc_Finish_Base();
+}
+
+Z7_COM7F_IMF(CUpdateCallback100Imp::Before_ArcReopen())
+{
+  ProgressDialog->Sync.Clear_Stop_Status();
+  return S_OK;
+}
+
+
 Z7_COM7F_IMF(CUpdateCallback100Imp::CryptoGetTextPassword(BSTR *password))
 {
   *password = NULL;
diff --git a/CPP/7zip/UI/FileManager/UpdateCallback100.h b/CPP/7zip/UI/FileManager/UpdateCallback100.h
index 5d56dfb..adae94f 100644
--- a/CPP/7zip/UI/FileManager/UpdateCallback100.h
+++ b/CPP/7zip/UI/FileManager/UpdateCallback100.h
@@ -16,6 +16,7 @@
 class CUpdateCallback100Imp Z7_final:
   public IFolderArchiveUpdateCallback,
   public IFolderArchiveUpdateCallback2,
+  public IFolderArchiveUpdateCallback_MoveArc,
   public IFolderScanProgress,
   public ICryptoGetTextPassword2,
   public ICryptoGetTextPassword,
@@ -24,9 +25,10 @@ class CUpdateCallback100Imp Z7_final:
   public CUpdateCallbackGUI2,
   public CMyUnknownImp
 {
-  Z7_COM_UNKNOWN_IMP_7(
+  Z7_COM_UNKNOWN_IMP_8(
     IFolderArchiveUpdateCallback,
     IFolderArchiveUpdateCallback2,
+    IFolderArchiveUpdateCallback_MoveArc,
     IFolderScanProgress,
     ICryptoGetTextPassword2,
     ICryptoGetTextPassword,
@@ -36,6 +38,7 @@ class CUpdateCallback100Imp Z7_final:
   Z7_IFACE_COM7_IMP(IProgress)
   Z7_IFACE_COM7_IMP(IFolderArchiveUpdateCallback)
   Z7_IFACE_COM7_IMP(IFolderArchiveUpdateCallback2)
+  Z7_IFACE_COM7_IMP(IFolderArchiveUpdateCallback_MoveArc)
   Z7_IFACE_COM7_IMP(IFolderScanProgress)
   Z7_IFACE_COM7_IMP(ICryptoGetTextPassword2)
   Z7_IFACE_COM7_IMP(ICryptoGetTextPassword)
diff --git a/CPP/7zip/UI/FileManager/ViewSettings.cpp b/CPP/7zip/UI/FileManager/ViewSettings.cpp
index 3d64602..4a8f58d 100644
--- a/CPP/7zip/UI/FileManager/ViewSettings.cpp
+++ b/CPP/7zip/UI/FileManager/ViewSettings.cpp
@@ -81,15 +81,15 @@ void CListViewInfo::Read(const UString &id)
 {
   Clear();
   CByteBuffer buf;
-  UInt32 size;
   {
     NSynchronization::CCriticalSectionLock lock(g_CS);
     CKey key;
     if (key.Open(HKEY_CURRENT_USER, kCulumnsKeyName, KEY_READ) != ERROR_SUCCESS)
       return;
-    if (key.QueryValue(GetSystemString(id), buf, size) != ERROR_SUCCESS)
+    if (key.QueryValue_Binary(GetSystemString(id), buf) != ERROR_SUCCESS)
       return;
   }
+  unsigned size = (unsigned)buf.Size();
   if (size < kListViewHeaderSize)
     return;
   UInt32 version;
@@ -104,7 +104,9 @@ void CListViewInfo::Read(const UString &id)
   size -= kListViewHeaderSize;
   if (size % kColumnInfoSize != 0)
     return;
-  unsigned numItems = size / kColumnInfoSize;
+  if (size > 1000 * kColumnInfoSize)
+    return;
+  const unsigned numItems = size / kColumnInfoSize;
   Columns.ClearAndReserve(numItems);
   for (unsigned i = 0; i < numItems; i++)
   {
@@ -161,8 +163,7 @@ void CWindowInfo::Save() const
 
 static bool QueryBuf(CKey &key, LPCTSTR name, CByteBuffer &buf, UInt32 dataSize)
 {
-  UInt32 size;
-  return key.QueryValue(name, buf, size) == ERROR_SUCCESS && size == dataSize;
+  return key.QueryValue_Binary(name, buf) == ERROR_SUCCESS && buf.Size() == dataSize;
 }
 
 void CWindowInfo::Read(bool &windowPosDefined, bool &panelInfoDefined)
@@ -206,7 +207,7 @@ static bool ReadUi32Val(const TCHAR *name, UInt32 &value)
   CKey key;
   if (key.Open(HKEY_CURRENT_USER, kCUBasePath, KEY_READ) != ERROR_SUCCESS)
     return false;
-  return key.QueryValue(name, value) == ERROR_SUCCESS;
+  return key.GetValue_UInt32_IfOk(name, value) == ERROR_SUCCESS;
 }
 
 void SaveToolbarsMask(UInt32 toolbarMask)
@@ -229,7 +230,7 @@ void CListMode::Save() const
 {
   UInt32 t = 0;
   for (int i = 0; i < 2; i++)
-    t |= ((Panels[i]) & 0xFF) << (i * 8);
+    t |= (Panels[i] & 0xFF) << (i * 8);
   SaveUi32Val(kListMode, t);
 }
 
@@ -241,7 +242,7 @@ void CListMode::Read()
     return;
   for (int i = 0; i < 2; i++)
   {
-    Panels[i] = (t & 0xFF);
+    Panels[i] = t & 0xFF;
     t >>= 8;
   }
 }
diff --git a/CPP/7zip/UI/FileManager/resource.h b/CPP/7zip/UI/FileManager/resource.h
index 4e22230..36c4b53 100644
--- a/CPP/7zip/UI/FileManager/resource.h
+++ b/CPP/7zip/UI/FileManager/resource.h
@@ -25,9 +25,12 @@
 #define IDM_CRC64                103
 #define IDM_SHA1                 104
 #define IDM_SHA256               105
-#define IDM_XXH64                106
-#define IDM_BLAKE2SP             107
-
+#define IDM_SHA384               106
+#define IDM_SHA512               107
+#define IDM_SHA3_256             108
+#define IDM_XXH64                120
+#define IDM_BLAKE2SP             121
+#define IDM_MD5                  122
 
 #define IDM_FILE                 500
 #define IDM_EDIT                 501
@@ -134,7 +137,7 @@
 #define IDS_COPY_TO                     6002
 #define IDS_MOVE_TO                     6003
 #define IDS_COPYING                     6004
-#define IDS_MOVING                      6005
+// #define IDS_MOVING                      6005
 #define IDS_RENAMING                    6006
 
 #define IDS_OPERATION_IS_NOT_SUPPORTED  6008
diff --git a/CPP/7zip/UI/FileManager/resource.rc b/CPP/7zip/UI/FileManager/resource.rc
index feeeaf5..d9fc6f2 100644
--- a/CPP/7zip/UI/FileManager/resource.rc
+++ b/CPP/7zip/UI/FileManager/resource.rc
@@ -58,8 +58,12 @@ BEGIN
       MENUITEM "CRC-32",                    IDM_CRC32
       MENUITEM "CRC-64",                    IDM_CRC64
       MENUITEM "XXH64",                     IDM_XXH64
+      MENUITEM "MD5",                       IDM_MD5
       MENUITEM "SHA-1",                     IDM_SHA1
       MENUITEM "SHA-256",                   IDM_SHA256
+      MENUITEM "SHA-384",                   IDM_SHA384
+      MENUITEM "SHA-512",                   IDM_SHA512
+      MENUITEM "SHA3-256",                  IDM_SHA3_256
       MENUITEM "BLAKE2sp",                  IDM_BLAKE2SP
       MENUITEM "*",                         IDM_HASH_ALL
     END
@@ -202,7 +206,7 @@ BEGIN
   IDS_COPY_TO   "Copy to:"
   IDS_MOVE_TO   "Move to:"
   IDS_COPYING   "Copying..."
-  IDS_MOVING    "Moving..."
+//  IDS_MOVING    "Moving..."
   IDS_RENAMING  "Renaming..."
 
   IDS_OPERATION_IS_NOT_SUPPORTED  "Operation is not supported."
diff --git a/CPP/7zip/UI/FileManager/resourceGui.h b/CPP/7zip/UI/FileManager/resourceGui.h
index 848b36f..2e1bab3 100644
--- a/CPP/7zip/UI/FileManager/resourceGui.h
+++ b/CPP/7zip/UI/FileManager/resourceGui.h
@@ -6,6 +6,8 @@
 #define IDS_OPENNING                    3303
 #define IDS_SCANNING                    3304
 
+#define IDS_MOVING                      6005
+
 #define IDS_CHECKSUM_CALCULATING        7500
 #define IDS_CHECKSUM_INFORMATION        7501
 #define IDS_CHECKSUM_CRC_DATA           7502
diff --git a/CPP/7zip/UI/FileManager/resourceGui.rc b/CPP/7zip/UI/FileManager/resourceGui.rc
index 143e9f6..ad0d1f4 100644
--- a/CPP/7zip/UI/FileManager/resourceGui.rc
+++ b/CPP/7zip/UI/FileManager/resourceGui.rc
@@ -6,6 +6,8 @@ BEGIN
 
   IDS_PROGRESS_TESTING      "Testing"
 
+  IDS_MOVING    "Moving..."
+
   IDS_CHECKSUM_CALCULATING    "Checksum calculating..."
   IDS_CHECKSUM_INFORMATION    "Checksum information"
   IDS_CHECKSUM_CRC_DATA       "CRC checksum for data:"
diff --git a/CPP/7zip/UI/GUI/BenchmarkDialog.cpp b/CPP/7zip/UI/GUI/BenchmarkDialog.cpp
index 7f2edfa..ce5473a 100644
--- a/CPP/7zip/UI/GUI/BenchmarkDialog.cpp
+++ b/CPP/7zip/UI/GUI/BenchmarkDialog.cpp
@@ -61,9 +61,9 @@ struct CBenchPassResult
 {
   CTotalBenchRes Enc;
   CTotalBenchRes Dec;
-  #ifdef PRINT_ITER_TIME
+#ifdef PRINT_ITER_TIME
   DWORD Ticks;
-  #endif
+#endif
   // CBenchInfo EncInfo; // for debug
   // CBenchPassResult() {};
 };
@@ -97,21 +97,9 @@ struct CTotalBenchRes2: public CTotalBenchRes
 struct CSyncData
 {
   UInt32 NumPasses_Finished;
-
-  // UInt64 NumEncProgress; // for debug
-  // UInt64 NumDecProgress; // for debug
-  // CBenchInfo EncInfo; // for debug
-
-  CTotalBenchRes2 Enc_BenchRes_1;
-  CTotalBenchRes2 Enc_BenchRes;
-
-  CTotalBenchRes2 Dec_BenchRes_1;
-  CTotalBenchRes2 Dec_BenchRes;
-
-  #ifdef PRINT_ITER_TIME
+#ifdef PRINT_ITER_TIME
   DWORD TotalTicks;
-  #endif
-
+#endif
   int RatingVector_DeletedIndex;
   // UInt64 RatingVector_NumDeleted;
 
@@ -124,6 +112,16 @@ struct CSyncData
   bool NeedPrint_Dec;
   bool NeedPrint_Tot; // intermediate Total was updated after current pass
 
+  // UInt64 NumEncProgress; // for debug
+  // UInt64 NumDecProgress; // for debug
+  // CBenchInfo EncInfo; // for debug
+
+  CTotalBenchRes2 Enc_BenchRes_1;
+  CTotalBenchRes2 Enc_BenchRes;
+
+  CTotalBenchRes2 Dec_BenchRes_1;
+  CTotalBenchRes2 Dec_BenchRes;
+
   void Init();
 };
 
@@ -161,24 +159,18 @@ void CSyncData::Init()
 struct CBenchProgressSync
 {
   bool Exit; // GUI asks BenchThread to Exit, and BenchThread reads that variable
+  bool TextWasChanged;
+
   UInt32 NumThreads;
   UInt64 DictSize;
   UInt32 NumPasses_Limit;
   int Level;
-  
-  // must be written by benchmark thread, read by GUI thread */
-  CSyncData sd;
-  CRecordVector<CBenchPassResult> RatingVector;
-
-  NWindows::NSynchronization::CCriticalSection CS;
 
   AString Text;
-  bool TextWasChanged;
 
   /* BenchFinish_Task_HRESULT    - for result from benchmark code
      BenchFinish_Thread_HRESULT  - for Exceptions and service errors
              these arreos must be shown even if user escapes benchmark */
-
   HRESULT BenchFinish_Task_HRESULT;
   HRESULT BenchFinish_Thread_HRESULT;
 
@@ -186,6 +178,12 @@ struct CBenchProgressSync
   UString FreqString_Sync;
   UString FreqString_GUI;
 
+  // must be written by benchmark thread, read by GUI thread */
+  CRecordVector<CBenchPassResult> RatingVector;
+  CSyncData sd;
+
+  NWindows::NSynchronization::CCriticalSection CS;
+
   CBenchProgressSync()
   {
     NumPasses_Limit = 1;
@@ -258,6 +256,19 @@ struct CThreadBenchmark
 class CBenchmarkDialog:
   public NWindows::NControl::CModalDialog
 {
+  bool _finishTime_WasSet;
+  
+  bool WasStopped_in_GUI;
+  bool ExitWasAsked_in_GUI;
+  bool NeedRestart;
+
+  bool RamSize_Defined;
+
+public:
+  bool TotalMode;
+
+private:
+
   NWindows::NControl::CComboBox m_Dictionary;
   NWindows::NControl::CComboBox m_NumThreads;
   NWindows::NControl::CComboBox m_NumPasses;
@@ -266,17 +277,11 @@ class CBenchmarkDialog:
 
   UInt32 _startTime;
   UInt32 _finishTime;
-  bool _finishTime_WasSet;
-  
-  bool WasStopped_in_GUI;
-  bool ExitWasAsked_in_GUI;
-  bool NeedRestart;
 
   CMyFont _font;
 
-  UInt64 RamSize;
-  UInt64 RamSize_Limit;
-  bool RamSize_Defined;
+  size_t RamSize;
+  size_t RamSize_Limit;
 
   UInt32 NumPasses_Finished_Prev;
 
@@ -330,7 +335,6 @@ class CBenchmarkDialog:
 public:
   CBenchProgressSync Sync;
 
-  bool TotalMode;
   CObjectVector<CProperty> Props;
 
   CSysString Bench2Text;
@@ -339,11 +343,11 @@ public:
   CThreadBenchmark _threadBenchmark;
 
   CBenchmarkDialog():
-      _timer(0),
       WasStopped_in_GUI(false),
       ExitWasAsked_in_GUI(false),
       NeedRestart(false),
-      TotalMode(false)
+      TotalMode(false),
+      _timer(0)
       {}
 
   ~CBenchmarkDialog() Z7_DESTRUCTOR_override;
@@ -504,7 +508,8 @@ bool CBenchmarkDialog::OnInit()
         SetItemTextA(IDT_BENCH_SYS2, s2);
     }
     {
-      GetCpuName_MultiLine(s);
+      AString registers;
+      GetCpuName_MultiLine(s, registers);
       SetItemTextA(IDT_BENCH_CPU, s);
     }
     {
diff --git a/CPP/7zip/UI/GUI/CompressDialog.cpp b/CPP/7zip/UI/GUI/CompressDialog.cpp
index fd53062..58f863e 100644
--- a/CPP/7zip/UI/GUI/CompressDialog.cpp
+++ b/CPP/7zip/UI/GUI/CompressDialog.cpp
@@ -211,11 +211,13 @@ static const EMethodID g_ZstdMethods[] =
 };
 */
 
+/*
 static const EMethodID g_SwfcMethods[] =
 {
   kDeflate
   // kLZMA
 };
+*/
 
 static const EMethodID g_TarMethods[] =
 {
@@ -278,7 +280,8 @@ static const CFormatInfo g_Formats[] =
   },
   {
     "7z",
-    (1 << 0) | (1 << 1) | (1 << 3) | (1 << 5) | (1 << 7) | (1 << 9),
+    // (1 << 0) | (1 << 1) | (1 << 3) | (1 << 5) | (1 << 7) | (1 << 9),
+    (1 << 10) - 1,
     METHODS_PAIR(g_7zMethods),
     kFF_Filter | kFF_Solid | kFF_MultiThread | kFF_Encrypt |
     kFF_EncryptFileNames | kFF_MemUse | kFF_SFX
@@ -306,7 +309,8 @@ static const CFormatInfo g_Formats[] =
   },
   {
     "xz",
-    (1 << 1) | (1 << 3) | (1 << 5) | (1 << 7) | (1 << 9),
+    // (1 << 1) | (1 << 3) | (1 << 5) | (1 << 7) | (1 << 9),
+    (1 << 10) - 1 - (1 << 0), // store (1 << 0) is not supported
     METHODS_PAIR(g_XzMethods),
     kFF_Solid | kFF_MultiThread | kFF_MemUse
   },
@@ -321,12 +325,14 @@ static const CFormatInfo g_Formats[] =
     | kFF_MemUse
   },
   */
+/*
   {
     "Swfc",
     (1 << 1) | (1 << 3) | (1 << 5) | (1 << 7) | (1 << 9),
     METHODS_PAIR(g_SwfcMethods),
     0
   },
+*/
   {
     "Tar",
     (1 << 0),
@@ -429,22 +435,23 @@ bool CCompressDialog::OnInit()
   #endif
 
   {
-    UInt64 size = (UInt64)(sizeof(size_t)) << 29;
+    size_t size = (size_t)sizeof(size_t) << 29;
     _ramSize_Defined = NSystem::GetRamSize(size);
     // size = (UInt64)3 << 62; // for debug only;
-    _ramSize = size;
-    const UInt64 kMinUseSize = (1 << 26);
-    if (size < kMinUseSize)
-      size = kMinUseSize;
-
-    unsigned bits = sizeof(size_t) * 8;
-    if (bits == 32)
     {
-      const UInt32 limit2 = (UInt32)7 << 28;
-      if (size > limit2)
-        size = limit2;
+      // we use reduced limit for 32-bit version:
+      unsigned bits = sizeof(size_t) * 8;
+      if (bits == 32)
+      {
+        const UInt32 limit2 = (UInt32)7 << 28;
+        if (size > limit2)
+            size = limit2;
+      }
     }
-
+    _ramSize = size;
+    const size_t kMinUseSize = 1 << 26;
+    if (size < kMinUseSize)
+        size = kMinUseSize;
     _ramSize_Reduced = size;
 
     // 80% - is auto usage limit in handlers
@@ -1580,24 +1587,26 @@ void CCompressDialog::SetLevel2()
 
   for (unsigned i = 0; i < sizeof(UInt32) * 8; i++)
   {
-    const UInt32 mask = (UInt32)1 << i;
-    if ((fi.LevelsMask & mask) != 0)
+    const UInt32 mask = fi.LevelsMask >> i;
+    // if (mask == 0) break;
+    if (mask & 1)
     {
-      const UInt32 langID = g_Levels[i];
       UString s;
       s.Add_UInt32(i);
-      // if (fi.LevelsMask < (1 << (MY_ZSTD_LEVEL_MAX + 1)) - 1)
-      if (langID)
-      if (i != 0 || !isZstd)
+      if (i < Z7_ARRAY_SIZE(g_Levels))
       {
-        s += " - ";
-        s += LangString(langID);
+        const UInt32 langID = g_Levels[i];
+        // if (fi.LevelsMask < (1 << (MY_ZSTD_LEVEL_MAX + 1)) - 1)
+        if (langID)
+          if (i != 0 || !isZstd)
+          {
+            s += " - ";
+            AddLangString(s, langID);
+          }
       }
       const int index = (int)m_Level.AddString(s);
       m_Level.SetItemData(index, (LPARAM)i);
     }
-    if (fi.LevelsMask <= mask)
-      break;
   }
   SetNearestSelectComboBox(m_Level, level);
 }
@@ -1931,11 +1940,11 @@ void CCompressDialog::SetDictionary2()
     case kLZMA2:
     {
       {
-        _auto_Dict =
-            ( level <= 3 ? ((UInt32)1 << (level * 2 + 16)) :
-            ( level <= 6 ? ((UInt32)1 << (level + 19)) :
-            ( level <= 7 ? ((UInt32)1 << 25) : ((UInt32)1 << 26)
-            )));
+        _auto_Dict = level <= 4 ?
+            (UInt32)1 << (level * 2 + 16) :
+            level <= sizeof(size_t) / 2 + 4 ?
+              (UInt32)1 << (level + 20) :
+              (UInt32)1 << (sizeof(size_t) / 2 + 24);
       }
 
       // we use threshold 3.75 GiB to switch to kLzmaMaxDictSize.
diff --git a/CPP/7zip/UI/GUI/CompressDialog.h b/CPP/7zip/UI/GUI/CompressDialog.h
index c2d2699..e0f3aa5 100644
--- a/CPP/7zip/UI/GUI/CompressDialog.h
+++ b/CPP/7zip/UI/GUI/CompressDialog.h
@@ -141,6 +141,15 @@ struct CBool1
 
 class CCompressDialog: public NWindows::NControl::CModalDialog
 {
+public:
+  CBool1 SymLinks;
+  CBool1 HardLinks;
+  CBool1 AltStreams;
+  CBool1 NtSecurity;
+  CBool1 PreserveATime;
+private:
+  bool _ramSize_Defined;
+
   NWindows::NControl::CComboBox m_ArchivePath;
   NWindows::NControl::CComboBox m_Format;
   NWindows::NControl::CComboBox m_Level;
@@ -179,20 +188,13 @@ class CCompressDialog: public NWindows::NControl::CModalDialog
   UString DirPrefix;
   UString StartDirPrefix;
 
-  bool _ramSize_Defined;
-  UInt64 _ramSize;         // full RAM size avail
-  UInt64 _ramSize_Reduced; // full for 64-bit and reduced for 32-bit
+  size_t _ramSize;         // full RAM size avail
+  size_t _ramSize_Reduced; // full for 64-bit and reduced for 32-bit
   UInt64 _ramUsage_Auto;
 
 public:
   NCompression::CInfo m_RegistryInfo;
 
-  CBool1 SymLinks;
-  CBool1 HardLinks;
-  CBool1 AltStreams;
-  CBool1 NtSecurity;
-  CBool1 PreserveATime;
-
   void SetArchiveName(const UString &name);
   int FindRegistryFormat(const UString &name);
   unsigned FindRegistryFormat_Always(const UString &name);
diff --git a/CPP/7zip/UI/GUI/UpdateCallbackGUI.cpp b/CPP/7zip/UI/GUI/UpdateCallbackGUI.cpp
index 26057a7..424c6e4 100644
--- a/CPP/7zip/UI/GUI/UpdateCallbackGUI.cpp
+++ b/CPP/7zip/UI/GUI/UpdateCallbackGUI.cpp
@@ -252,6 +252,21 @@ HRESULT CUpdateCallbackGUI::DeletingAfterArchiving(const FString &path, bool isD
   return ProgressDialog->Sync.Set_Status2(_lang_Removing, fs2us(path), isDir);
 }
 
+
+HRESULT CUpdateCallbackGUI::MoveArc_Start(const wchar_t *srcTempPath, const wchar_t *destFinalPath, UInt64 totalSize, Int32 updateMode)
+{
+  return MoveArc_Start_Base(srcTempPath, destFinalPath, totalSize, updateMode);
+}
+HRESULT CUpdateCallbackGUI::MoveArc_Progress(UInt64 totalSize, UInt64 currentSize)
+{
+  return MoveArc_Progress_Base(totalSize, currentSize);
+}
+HRESULT CUpdateCallbackGUI::MoveArc_Finish()
+{
+  return MoveArc_Finish_Base();
+}
+
+
 HRESULT CUpdateCallbackGUI::StartOpenArchive(const wchar_t * /* name */)
 {
   return S_OK;
diff --git a/CPP/7zip/UI/GUI/UpdateCallbackGUI2.cpp b/CPP/7zip/UI/GUI/UpdateCallbackGUI2.cpp
index 966f57e..53fed91 100644
--- a/CPP/7zip/UI/GUI/UpdateCallbackGUI2.cpp
+++ b/CPP/7zip/UI/GUI/UpdateCallbackGUI2.cpp
@@ -8,6 +8,7 @@
 #include "resource2.h"
 #include "resource3.h"
 #include "ExtractRes.h"
+#include "../FileManager/resourceGui.h"
 
 #include "UpdateCallbackGUI.h"
 
@@ -29,7 +30,8 @@ void CUpdateCallbackGUI2::Init()
 {
   NumFiles = 0;
 
-  _lang_Removing = LangString(IDS_PROGRESS_REMOVE);
+  LangString(IDS_PROGRESS_REMOVE, _lang_Removing);
+  LangString(IDS_MOVING, _lang_Moving);
   _lang_Ops.Clear();
   for (unsigned i = 0; i < Z7_ARRAY_SIZE(k_UpdNotifyLangs); i++)
     _lang_Ops.Add(LangString(k_UpdNotifyLangs[i]));
@@ -57,3 +59,72 @@ HRESULT CUpdateCallbackGUI2::ShowAskPasswordDialog()
   PasswordIsDefined = true;
   return S_OK;
 }
+
+
+HRESULT CUpdateCallbackGUI2::MoveArc_UpdateStatus()
+{
+  UString s;
+  s.Add_UInt64(_arcMoving_percents);
+  s.Add_Char('%');
+
+  const bool totalDefined = (_arcMoving_total != 0 && _arcMoving_total != (UInt64)(Int64)-1);
+  if (totalDefined || _arcMoving_current != 0)
+  {
+    s += " : ";
+    s.Add_UInt64(_arcMoving_current >> 20);
+    s += " MiB";
+  }
+  if (totalDefined)
+  {
+    s += " / ";
+    s.Add_UInt64((_arcMoving_total + ((1 << 20) - 1)) >> 20);
+    s += " MiB";
+  }
+
+  s += " : ";
+  s += _lang_Moving;
+  s += " : ";
+  // s.Add_Char('\"');
+  s += _arcMoving_name1;
+  // s.Add_Char('\"');
+  return ProgressDialog->Sync.Set_Status2(s, _arcMoving_name2,
+      false); // isDir
+}
+
+
+HRESULT CUpdateCallbackGUI2::MoveArc_Start_Base(const wchar_t *srcTempPath, const wchar_t *destFinalPath, UInt64 totalSize, Int32 updateMode)
+{
+  _arcMoving_percents = 0;
+  _arcMoving_total = totalSize;
+  _arcMoving_current = 0;
+  _arcMoving_updateMode = updateMode;
+  _arcMoving_name1 = srcTempPath;
+  _arcMoving_name2 = destFinalPath;
+  return MoveArc_UpdateStatus();
+}
+
+
+HRESULT CUpdateCallbackGUI2::MoveArc_Progress_Base(UInt64 totalSize, UInt64 currentSize)
+{
+  _arcMoving_total = totalSize;
+  _arcMoving_current = currentSize;
+  UInt64 percents = 0;
+  if (totalSize != 0)
+  {
+    if (totalSize < ((UInt64)1 << 57))
+      percents = currentSize * 100 / totalSize;
+    else
+      percents = currentSize / (totalSize / 100);
+  }
+  if (percents == _arcMoving_percents)
+    return ProgressDialog->Sync.CheckStop();
+  // Sleep(300); // for debug
+  _arcMoving_percents = percents;
+  return MoveArc_UpdateStatus();
+}
+
+
+HRESULT CUpdateCallbackGUI2::MoveArc_Finish_Base()
+{
+  return ProgressDialog->Sync.Set_Status2(L"", L"", false);
+}
diff --git a/CPP/7zip/UI/GUI/UpdateCallbackGUI2.h b/CPP/7zip/UI/GUI/UpdateCallbackGUI2.h
index e32b602..56747ff 100644
--- a/CPP/7zip/UI/GUI/UpdateCallbackGUI2.h
+++ b/CPP/7zip/UI/GUI/UpdateCallbackGUI2.h
@@ -7,17 +7,38 @@
 
 class CUpdateCallbackGUI2
 {
-  UStringVector _lang_Ops;
-  UString _emptyString;
 public:
-  UString Password;
+  CProgressDialog *ProgressDialog;
+protected:
+  UString _arcMoving_name1;
+  UString _arcMoving_name2;
+  UInt64 _arcMoving_percents;
+  UInt64 _arcMoving_total;
+  UInt64 _arcMoving_current;
+  Int32  _arcMoving_updateMode;
+public:
   bool PasswordIsDefined;
   bool PasswordWasAsked;
   UInt64 NumFiles;
-
+  UString Password;
+protected:
+  UStringVector _lang_Ops;
   UString _lang_Removing;
+  UString _lang_Moving;
+  UString _emptyString;
+
+  HRESULT MoveArc_UpdateStatus();
+  HRESULT MoveArc_Start_Base(const wchar_t *srcTempPath, const wchar_t *destFinalPath, UInt64 /* totalSize */, Int32 updateMode);
+  HRESULT MoveArc_Progress_Base(UInt64 totalSize, UInt64 currentSize);
+  HRESULT MoveArc_Finish_Base();
+
+public:
 
   CUpdateCallbackGUI2():
+      _arcMoving_percents(0),
+      _arcMoving_total(0),
+      _arcMoving_current(0),
+      _arcMoving_updateMode(0),
       PasswordIsDefined(false),
       PasswordWasAsked(false),
       NumFiles(0)
@@ -25,8 +46,6 @@ public:
   
   void Init();
 
-  CProgressDialog *ProgressDialog;
-
   HRESULT SetOperation_Base(UInt32 notifyOp, const wchar_t *name, bool isDir);
   HRESULT ShowAskPasswordDialog();
 };
diff --git a/CPP/7zip/warn_gcc.mak b/CPP/7zip/warn_gcc.mak
index b6ed9c3..6152ab1 100644
--- a/CPP/7zip/warn_gcc.mak
+++ b/CPP/7zip/warn_gcc.mak
@@ -11,16 +11,16 @@ CFLAGS_WARN_GCC_4_8 = \
   -Wunused \
   -Wunused-macros \
 
-CFLAGS_WARN_GCC_6 = $(CFLAGS_WARN_GCC_4_8)\
+CFLAGS_WARN_GCC_5 = $(CFLAGS_WARN_GCC_4_8)\
   -Wbool-compare \
+
+CFLAGS_WARN_GCC_6 = $(CFLAGS_WARN_GCC_5)\
   -Wduplicated-cond \
 
 #  -Wno-strict-aliasing
 
-CFLAGS_WARN_GCC_9 = $(CFLAGS_WARN_GCC_6)\
-  -Waddress-of-packed-member \
+CFLAGS_WARN_GCC_7 = $(CFLAGS_WARN_GCC_6)\
   -Wbool-operation \
-  -Wcast-align=strict \
   -Wconversion \
   -Wdangling-else \
   -Wduplicated-branches \
@@ -28,8 +28,14 @@ CFLAGS_WARN_GCC_9 = $(CFLAGS_WARN_GCC_6)\
   -Wint-in-bool-context \
   -Wmaybe-uninitialized \
   -Wmisleading-indentation \
+
+CFLAGS_WARN_GCC_8 = $(CFLAGS_WARN_GCC_7)\
+  -Wcast-align=strict \
   -Wmissing-attributes
 
+CFLAGS_WARN_GCC_9 = $(CFLAGS_WARN_GCC_8)\
+  -Waddress-of-packed-member \
+
 # In C: -Wsign-conversion enabled also by -Wconversion
 #  -Wno-sign-conversion \
 
@@ -39,7 +45,10 @@ CFLAGS_WARN_GCC_PPMD_UNALIGNED = \
 
 
 CFLAGS_WARN = $(CFLAGS_WARN_GCC_4_8)
+CFLAGS_WARN = $(CFLAGS_WARN_GCC_5)
 CFLAGS_WARN = $(CFLAGS_WARN_GCC_6)
+CFLAGS_WARN = $(CFLAGS_WARN_GCC_7)
+CFLAGS_WARN = $(CFLAGS_WARN_GCC_8)
 CFLAGS_WARN = $(CFLAGS_WARN_GCC_9)
 
 # CXX_STD_FLAGS = -std=c++11
diff --git a/CPP/Common/Md5Reg.cpp b/CPP/Common/Md5Reg.cpp
new file mode 100644
index 0000000..026fd41
--- /dev/null
+++ b/CPP/Common/Md5Reg.cpp
@@ -0,0 +1,44 @@
+// Md5Reg.cpp
+
+#include "StdAfx.h"
+
+#include "../../C/Md5.h"
+
+#include "../Common/MyBuffer2.h"
+#include "../Common/MyCom.h"
+
+#include "../7zip/Common/RegisterCodec.h"
+
+Z7_CLASS_IMP_COM_1(
+  CMd5Hasher
+  , IHasher
+)
+  CAlignedBuffer1 _buf;
+public:
+  Byte _mtDummy[1 << 7];
+
+  CMd5 *Md5() { return (CMd5 *)(void *)(Byte *)_buf; }
+public:
+  CMd5Hasher():
+    _buf(sizeof(CMd5))
+  {
+    Md5_Init(Md5());
+  }
+};
+
+Z7_COM7F_IMF2(void, CMd5Hasher::Init())
+{
+  Md5_Init(Md5());
+}
+
+Z7_COM7F_IMF2(void, CMd5Hasher::Update(const void *data, UInt32 size))
+{
+  Md5_Update(Md5(), (const Byte *)data, size);
+}
+
+Z7_COM7F_IMF2(void, CMd5Hasher::Final(Byte *digest))
+{
+  Md5_Final(Md5(), digest);
+}
+
+REGISTER_HASHER(CMd5Hasher, 0x208, "MD5", MD5_DIGEST_SIZE)
diff --git a/CPP/Common/MyCom.h b/CPP/Common/MyCom.h
index a3cc3c8..7dc21ba 100644
--- a/CPP/Common/MyCom.h
+++ b/CPP/Common/MyCom.h
@@ -468,6 +468,19 @@ EXTERN_C_END
   Z7_COM_QI_ENTRY(i7) \
   )
 
+#define Z7_COM_UNKNOWN_IMP_8(i1, i2, i3, i4, i5, i6, i7, i8) \
+  Z7_COM_UNKNOWN_IMP_SPEC( \
+  Z7_COM_QI_ENTRY_UNKNOWN(i1) \
+  Z7_COM_QI_ENTRY(i1) \
+  Z7_COM_QI_ENTRY(i2) \
+  Z7_COM_QI_ENTRY(i3) \
+  Z7_COM_QI_ENTRY(i4) \
+  Z7_COM_QI_ENTRY(i5) \
+  Z7_COM_QI_ENTRY(i6) \
+  Z7_COM_QI_ENTRY(i7) \
+  Z7_COM_QI_ENTRY(i8) \
+  )
+
 
 #define Z7_IFACES_IMP_UNK_1(i1) \
   Z7_COM_UNKNOWN_IMP_1(i1) \
@@ -508,6 +521,16 @@ EXTERN_C_END
   Z7_IFACE_COM7_IMP(i5) \
   Z7_IFACE_COM7_IMP(i6) \
 
+#define Z7_IFACES_IMP_UNK_7(i1, i2, i3, i4, i5, i6, i7) \
+  Z7_COM_UNKNOWN_IMP_7(i1, i2, i3, i4, i5, i6, i7) \
+  Z7_IFACE_COM7_IMP(i1) \
+  Z7_IFACE_COM7_IMP(i2) \
+  Z7_IFACE_COM7_IMP(i3) \
+  Z7_IFACE_COM7_IMP(i4) \
+  Z7_IFACE_COM7_IMP(i5) \
+  Z7_IFACE_COM7_IMP(i6) \
+  Z7_IFACE_COM7_IMP(i7) \
+
 
 #define Z7_CLASS_IMP_COM_0(c) \
   Z7_class_final(c) : \
@@ -574,6 +597,20 @@ EXTERN_C_END
   private:
 
 
+#define Z7_CLASS_IMP_COM_7(c, i1, i2, i3, i4, i5, i6, i7) \
+  Z7_class_final(c) : \
+  public i1, \
+  public i2, \
+  public i3, \
+  public i4, \
+  public i5, \
+  public i6, \
+  public i7, \
+  public CMyUnknownImp { \
+  Z7_IFACES_IMP_UNK_7(i1, i2, i3, i4, i5, i6, i7) \
+  private:
+
+
 /*
 #define Z7_CLASS_IMP_NOQIB_0(c) \
   Z7_class_final(c) : \
diff --git a/CPP/Common/Sha3Reg.cpp b/CPP/Common/Sha3Reg.cpp
new file mode 100644
index 0000000..95db25e
--- /dev/null
+++ b/CPP/Common/Sha3Reg.cpp
@@ -0,0 +1,76 @@
+// Sha3Reg.cpp
+
+#include "StdAfx.h"
+
+#include "../../C/Sha3.h"
+
+#include "../Common/MyBuffer2.h"
+#include "../Common/MyCom.h"
+
+#include "../7zip/Common/RegisterCodec.h"
+
+Z7_CLASS_IMP_COM_1(
+  CSha3Hasher
+  , IHasher
+)
+  unsigned _digestSize;
+  bool _isShake;
+  CAlignedBuffer1 _buf;
+public:
+  Byte _mtDummy[1 << 7];
+
+  CSha3 *Sha() { return (CSha3 *)(void *)(Byte *)_buf; }
+public:
+  CSha3Hasher(unsigned digestSize, bool isShake, unsigned blockSize):
+     _digestSize(digestSize),
+     _isShake(isShake),
+    _buf(sizeof(CSha3))
+  {
+    CSha3 *p = Sha();
+    Sha3_SET_blockSize(p, blockSize)
+    Sha3_Init(Sha());
+  }
+};
+
+Z7_COM7F_IMF2(void, CSha3Hasher::Init())
+{
+  Sha3_Init(Sha());
+}
+
+Z7_COM7F_IMF2(void, CSha3Hasher::Update(const void *data, UInt32 size))
+{
+  Sha3_Update(Sha(), (const Byte *)data, size);
+}
+
+Z7_COM7F_IMF2(void, CSha3Hasher::Final(Byte *digest))
+{
+  Sha3_Final(Sha(), digest, _digestSize, _isShake);
+}
+
+Z7_COM7F_IMF2(UInt32, CSha3Hasher::GetDigestSize())
+{
+  return (UInt32)_digestSize;
+}
+
+
+#define REGISTER_SHA3_HASHER_2(cls, id, name, digestSize, isShake, digestSize_for_blockSize) \
+  namespace N ## cls { \
+  static IHasher *CreateHasherSpec() \
+    { return new CSha3Hasher(digestSize / 8, isShake, \
+        SHA3_BLOCK_SIZE_FROM_DIGEST_SIZE(digestSize_for_blockSize / 8)); } \
+  static const CHasherInfo g_HasherInfo = { CreateHasherSpec, id, name, digestSize }; \
+  struct REGISTER_HASHER_NAME(cls) { REGISTER_HASHER_NAME(cls)() { RegisterHasher(&g_HasherInfo); }}; \
+  static REGISTER_HASHER_NAME(cls) g_RegisterHasher; }
+
+#define REGISTER_SHA3_HASHER(  cls, id, name, size, isShake) \
+        REGISTER_SHA3_HASHER_2(cls, id, name, size, isShake, size)
+
+// REGISTER_SHA3_HASHER (Sha3_224_Hasher, 0x230, "SHA3-224", 224, false)
+REGISTER_SHA3_HASHER (Sha3_256_Hasher, 0x231, "SHA3-256", 256, false)
+// REGISTER_SHA3_HASHER (Sha3_386_Hasher, 0x232, "SHA3-384", 384, false)
+// REGISTER_SHA3_HASHER (Sha3_512_Hasher, 0x233, "SHA3-512", 512, false)
+// REGISTER_SHA3_HASHER (Shake128_Hasher, 0x240, "SHAKE128", 128, true)
+// REGISTER_SHA3_HASHER (Shake256_Hasher, 0x241, "SHAKE256", 256, true)
+// REGISTER_SHA3_HASHER_2 (Shake128_512_Hasher, 0x248, "SHAKE128-256", 256, true, 128) // -1344 (max)
+// REGISTER_SHA3_HASHER_2 (Shake256_512_Hasher, 0x249, "SHAKE256-512", 512, true, 256) // -1088 (max)
+// Shake supports different digestSize values for same blockSize
diff --git a/CPP/Common/Sha512Prepare.cpp b/CPP/Common/Sha512Prepare.cpp
new file mode 100644
index 0000000..e7beff5
--- /dev/null
+++ b/CPP/Common/Sha512Prepare.cpp
@@ -0,0 +1,7 @@
+// Sha512Prepare.cpp
+
+#include "StdAfx.h"
+
+#include "../../C/Sha512.h"
+
+static struct CSha512Prepare { CSha512Prepare() { Sha512Prepare(); } } g_Sha512Prepare;
diff --git a/CPP/Common/Sha512Reg.cpp b/CPP/Common/Sha512Reg.cpp
new file mode 100644
index 0000000..21df6ba
--- /dev/null
+++ b/CPP/Common/Sha512Reg.cpp
@@ -0,0 +1,83 @@
+// Sha512Reg.cpp
+
+#include "StdAfx.h"
+
+#include "../../C/Sha512.h"
+
+#include "../Common/MyBuffer2.h"
+#include "../Common/MyCom.h"
+
+#include "../7zip/Common/RegisterCodec.h"
+
+Z7_CLASS_IMP_COM_2(
+  CSha512Hasher
+  , IHasher
+  , ICompressSetCoderProperties
+)
+  unsigned _digestSize;
+  CAlignedBuffer1 _buf;
+public:
+  Byte _mtDummy[1 << 7];
+
+  CSha512 *Sha() { return (CSha512 *)(void *)(Byte *)_buf; }
+public:
+  CSha512Hasher(unsigned digestSize):
+     _digestSize(digestSize),
+    _buf(sizeof(CSha512))
+  {
+    Sha512_SetFunction(Sha(), 0);
+    Sha512_InitState(Sha(), _digestSize);
+  }
+};
+
+Z7_COM7F_IMF2(void, CSha512Hasher::Init())
+{
+  Sha512_InitState(Sha(), _digestSize);
+}
+
+Z7_COM7F_IMF2(void, CSha512Hasher::Update(const void *data, UInt32 size))
+{
+  Sha512_Update(Sha(), (const Byte *)data, size);
+}
+
+Z7_COM7F_IMF2(void, CSha512Hasher::Final(Byte *digest))
+{
+  Sha512_Final(Sha(), digest, _digestSize);
+}
+
+Z7_COM7F_IMF2(UInt32, CSha512Hasher::GetDigestSize())
+{
+  return (UInt32)_digestSize;
+}
+
+Z7_COM7F_IMF(CSha512Hasher::SetCoderProperties(const PROPID *propIDs, const PROPVARIANT *coderProps, UInt32 numProps))
+{
+  unsigned algo = 0;
+  for (UInt32 i = 0; i < numProps; i++)
+  {
+    if (propIDs[i] == NCoderPropID::kDefaultProp)
+    {
+      const PROPVARIANT &prop = coderProps[i];
+      if (prop.vt != VT_UI4)
+        return E_INVALIDARG;
+      if (prop.ulVal > 2)
+        return E_NOTIMPL;
+      algo = (unsigned)prop.ulVal;
+    }
+  }
+  if (!Sha512_SetFunction(Sha(), algo))
+    return E_NOTIMPL;
+  return S_OK;
+}
+
+#define REGISTER_SHA512_HASHER(cls, id, name, size) \
+  namespace N ## cls { \
+  static IHasher *CreateHasherSpec() { return new CSha512Hasher(size); } \
+  static const CHasherInfo g_HasherInfo = { CreateHasherSpec, id, name, size }; \
+  struct REGISTER_HASHER_NAME(cls) { REGISTER_HASHER_NAME(cls)() { RegisterHasher(&g_HasherInfo); }}; \
+  static REGISTER_HASHER_NAME(cls) g_RegisterHasher; }
+
+// REGISTER_SHA512_HASHER (Sha512_224_Hasher, 0x220, "SHA512-224", SHA512_224_DIGEST_SIZE)
+// REGISTER_SHA512_HASHER (Sha512_256_Hasher, 0x221, "SHA512-256", SHA512_256_DIGEST_SIZE)
+REGISTER_SHA512_HASHER (Sha384Hasher,      0x222, "SHA384",     SHA512_384_DIGEST_SIZE)
+REGISTER_SHA512_HASHER (Sha512Hasher,      0x223, "SHA512",     SHA512_DIGEST_SIZE)
diff --git a/CPP/Windows/FileDir.cpp b/CPP/Windows/FileDir.cpp
index dfeed82..2cb83b2 100644
--- a/CPP/Windows/FileDir.cpp
+++ b/CPP/Windows/FileDir.cpp
@@ -15,8 +15,9 @@
 #include <sys/stat.h>
 #include <sys/types.h>
 
-#include "../Common/StringConvert.h"
 #include "../Common/C_FileIO.h"
+#include "../Common/MyBuffer2.h"
+#include "../Common/StringConvert.h"
 #endif
 
 #include "FileDir.h"
@@ -222,6 +223,8 @@ bool RemoveDir(CFSTR path)
 }
 
 
+// When moving a directory, oldFile and newFile must be on the same drive.
+
 bool MyMoveFile(CFSTR oldFile, CFSTR newFile)
 {
   #ifndef _UNICODE
@@ -250,6 +253,59 @@ bool MyMoveFile(CFSTR oldFile, CFSTR newFile)
   return false;
 }
 
+#if defined(Z7_WIN32_WINNT_MIN) && Z7_WIN32_WINNT_MIN >= 0x0500
+static DWORD WINAPI CopyProgressRoutine_to_ICopyFileProgress(
+  LARGE_INTEGER TotalFileSize,          // file size
+  LARGE_INTEGER TotalBytesTransferred,  // bytes transferred
+  LARGE_INTEGER /* StreamSize */,             // bytes in stream
+  LARGE_INTEGER /* StreamBytesTransferred */, // bytes transferred for stream
+  DWORD /* dwStreamNumber */,                 // current stream
+  DWORD /* dwCallbackReason */,               // callback reason
+  HANDLE /* hSourceFile */,                   // handle to source file
+  HANDLE /* hDestinationFile */,              // handle to destination file
+  LPVOID lpData                         // from CopyFileEx
+)
+{
+  return ((ICopyFileProgress *)lpData)->CopyFileProgress(
+      (UInt64)TotalFileSize.QuadPart,
+      (UInt64)TotalBytesTransferred.QuadPart);
+}
+#endif
+
+bool MyMoveFile_with_Progress(CFSTR oldFile, CFSTR newFile,
+    ICopyFileProgress *progress)
+{
+#if defined(Z7_WIN32_WINNT_MIN) && Z7_WIN32_WINNT_MIN >= 0x0500
+#ifndef _UNICODE
+  if (g_IsNT)
+#endif
+  if (progress)
+  {
+    IF_USE_MAIN_PATH_2(oldFile, newFile)
+    {
+      if (::MoveFileWithProgressW(fs2us(oldFile), fs2us(newFile),
+          CopyProgressRoutine_to_ICopyFileProgress, progress, MOVEFILE_COPY_ALLOWED))
+        return true;
+      if (::GetLastError() == ERROR_REQUEST_ABORTED)
+        return false;
+    }
+    #ifdef Z7_LONG_PATH
+    if (USE_SUPER_PATH_2)
+    {
+      UString d1, d2;
+      if (GetSuperPaths(oldFile, newFile, d1, d2, USE_MAIN_PATH_2))
+        return BOOLToBool(::MoveFileWithProgressW(d1, d2,
+            CopyProgressRoutine_to_ICopyFileProgress, progress, MOVEFILE_COPY_ALLOWED));
+    }
+    #endif
+    return false;
+  }
+#else
+  UNUSED_VAR(progress)
+#endif
+  return MyMoveFile(oldFile, newFile);
+}
+
 #ifndef UNDER_CE
 #if !defined(Z7_WIN32_WINNT_MIN) || Z7_WIN32_WINNT_MIN < 0x0500  // Win2000
 #define Z7_USE_DYN_CreateHardLink
@@ -878,9 +934,9 @@ bool CTempFile::Remove()
   return !_mustBeDeleted;
 }
 
-bool CTempFile::MoveTo(CFSTR name, bool deleteDestBefore)
+bool CTempFile::MoveTo(CFSTR name, bool deleteDestBefore,
+    ICopyFileProgress *progress)
 {
-  // DWORD attrib = 0;
   if (deleteDestBefore)
   {
     if (NFind::DoesFileExist_Raw(name))
@@ -891,8 +947,8 @@ bool CTempFile::MoveTo(CFSTR name, bool deleteDestBefore)
     }
   }
   DisableDeleting();
-  return MyMoveFile(_path, name);
-  
+  // if (!progress) return MyMoveFile(_path, name);
+  return MyMoveFile_with_Progress(_path, name, progress);
   /*
   if (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_READONLY))
   {
@@ -941,34 +997,59 @@ bool RemoveDir(CFSTR path)
 }
 
 
-static BOOL My_CopyFile(CFSTR oldFile, CFSTR newFile)
+static BOOL My_CopyFile(CFSTR oldFile, CFSTR newFile, ICopyFileProgress *progress)
 {
-  NWindows::NFile::NIO::COutFile outFile;
-  if (!outFile.Create_NEW(newFile))
-    return FALSE;
-  
-  NWindows::NFile::NIO::CInFile inFile;
-  if (!inFile.Open(oldFile))
-    return FALSE;
-
-  char buf[1 << 14];
-
-  for (;;)
   {
-    const ssize_t num = inFile.read_part(buf, sizeof(buf));
-    if (num == 0)
-      return TRUE;
-    if (num < 0)
+    NIO::COutFile outFile;
+    if (!outFile.Create_NEW(newFile))
       return FALSE;
-    size_t processed;
-    const ssize_t num2 = outFile.write_full(buf, (size_t)num, processed);
-    if (num2 != num || processed != (size_t)num)
+    NIO::CInFile inFile;
+    if (!inFile.Open(oldFile))
       return FALSE;
+    
+    const size_t k_BufSize = 1 << 16;
+    CAlignedBuffer1 buf(k_BufSize);
+    
+    UInt64 length = 0;
+    if (progress && !inFile.GetLength(length))
+      length = 0;
+    UInt64 prev = 0;
+    UInt64 cur = 0;
+    for (;;)
+    {
+      const ssize_t num = inFile.read_part(buf, k_BufSize);
+      if (num == 0)
+        return TRUE;
+      if (num < 0)
+        break;
+      size_t processed;
+      const ssize_t num2 = outFile.write_full(buf, (size_t)num, processed);
+      if (num2 != num || processed != (size_t)num)
+        break;
+      cur += (size_t)num2;
+      if (progress && cur - prev >= (1u << 20))
+      {
+        prev = cur;
+        if (progress->CopyFileProgress(length, cur) != PROGRESS_CONTINUE)
+        {
+          errno = EINTR; // instead of WIN32::ERROR_REQUEST_ABORTED
+          break;
+        }
+      }
+    }
   }
+  // There is file IO error or process was interrupted by user.
+  // We close output file and delete it.
+  // DeleteFileAlways doesn't change errno (if successed), but we restore errno.
+  const int errno_save = errno;
+  DeleteFileAlways(newFile);
+  errno = errno_save;
+  return FALSE;
 }
 
 
-bool MyMoveFile(CFSTR oldFile, CFSTR newFile)
+bool MyMoveFile_with_Progress(CFSTR oldFile, CFSTR newFile,
+    ICopyFileProgress *progress)
 {
   int res = rename(oldFile, newFile);
   if (res == 0)
@@ -976,7 +1057,7 @@ bool MyMoveFile(CFSTR oldFile, CFSTR newFile)
   if (errno != EXDEV) // (oldFile and newFile are not on the same mounted filesystem)
     return false;
 
-  if (My_CopyFile(oldFile, newFile) == FALSE)
+  if (My_CopyFile(oldFile, newFile, progress) == FALSE)
     return false;
     
   struct stat info_file;
@@ -990,6 +1071,11 @@ bool MyMoveFile(CFSTR oldFile, CFSTR newFile)
   return (unlink(oldFile) == 0);
 }
 
+bool MyMoveFile(CFSTR oldFile, CFSTR newFile)
+{
+  return MyMoveFile_with_Progress(oldFile, newFile, NULL);
+}
+
 
 bool CreateDir(CFSTR path)
 {
diff --git a/CPP/Windows/FileDir.h b/CPP/Windows/FileDir.h
index 573ffa2..74675ee 100644
--- a/CPP/Windows/FileDir.h
+++ b/CPP/Windows/FileDir.h
@@ -41,7 +41,26 @@ int my_chown(CFSTR path, uid_t owner, gid_t group);
 bool SetFileAttrib_PosixHighDetect(CFSTR path, DWORD attrib);
 
 
+#ifndef _WIN32
+#define PROGRESS_CONTINUE   0
+#define PROGRESS_CANCEL     1
+// #define PROGRESS_STOP       2
+// #define PROGRESS_QUIET      3
+#endif
+Z7_PURE_INTERFACES_BEGIN
+DECLARE_INTERFACE(ICopyFileProgress)
+{
+  // in: total, current: include all/processed alt streams.
+  // it returns PROGRESS_CONTINUE or PROGRESS_CANCEL.
+  virtual DWORD CopyFileProgress(UInt64 total, UInt64 current) = 0;
+};
+Z7_PURE_INTERFACES_END
+
 bool MyMoveFile(CFSTR existFileName, CFSTR newFileName);
+// (progress == NULL) is allowed
+bool MyMoveFile_with_Progress(CFSTR oldFile, CFSTR newFile,
+    ICopyFileProgress *progress);
+
 
 #ifndef UNDER_CE
 bool MyCreateHardLink(CFSTR newFileName, CFSTR existFileName);
@@ -87,7 +106,9 @@ public:
   bool Create(CFSTR pathPrefix, NIO::COutFile *outFile); // pathPrefix is not folder prefix
   bool CreateRandomInTempFolder(CFSTR namePrefix, NIO::COutFile *outFile);
   bool Remove();
-  bool MoveTo(CFSTR name, bool deleteDestBefore);
+  // bool MoveTo(CFSTR name, bool deleteDestBefore);
+  bool MoveTo(CFSTR name, bool deleteDestBefore,
+      ICopyFileProgress *progress);
 };
 
 
diff --git a/CPP/Windows/FileName.cpp b/CPP/Windows/FileName.cpp
index c16b3d4..1f4a6da 100644
--- a/CPP/Windows/FileName.cpp
+++ b/CPP/Windows/FileName.cpp
@@ -278,12 +278,14 @@ bool IsAbsolutePath(const wchar_t *s) throw()
 int FindAltStreamColon(CFSTR path) throw()
 {
   unsigned i = 0;
-  if (IsDrivePath2(path))
-    i = 2;
+  if (IsSuperPath(path))
+    i = kSuperPathPrefixSize;
+  if (IsDrivePath2(path + i))
+    i += 2;
   int colonPos = -1;
   for (;; i++)
   {
-    FChar c = path[i];
+    const FChar c = path[i];
     if (c == 0)
       return colonPos;
     if (c == ':')
diff --git a/CPP/Windows/Registry.cpp b/CPP/Windows/Registry.cpp
index c8b1709..a94a50f 100644
--- a/CPP/Windows/Registry.cpp
+++ b/CPP/Windows/Registry.cpp
@@ -78,7 +78,7 @@ LONG CKey::Close() throw()
   return res;
 }
 
-// win95, win98: deletes sunkey and all its subkeys
+// win95, win98: deletes subkey and all its subkeys
 // winNT to be deleted must not have subkeys
 LONG CKey::DeleteSubKey(LPCTSTR subKeyName) throw()
 {
@@ -88,22 +88,36 @@ LONG CKey::DeleteSubKey(LPCTSTR subKeyName) throw()
 
 LONG CKey::RecurseDeleteKey(LPCTSTR subKeyName) throw()
 {
-  CKey key;
-  LONG res = key.Open(_object, subKeyName, KEY_READ | KEY_WRITE);
-  if (res != ERROR_SUCCESS)
-    return res;
-  FILETIME fileTime;
-  const UInt32 kBufSize = MAX_PATH + 1; // 256 in ATL
-  DWORD size = kBufSize;
-  TCHAR buffer[kBufSize];
-  while (RegEnumKeyEx(key._object, 0, buffer, &size, NULL, NULL, NULL, &fileTime) == ERROR_SUCCESS)
   {
-    res = key.RecurseDeleteKey(buffer);
+    CKey key;
+    LONG res = key.Open(_object, subKeyName, KEY_READ | KEY_WRITE);
     if (res != ERROR_SUCCESS)
       return res;
-    size = kBufSize;
+    FILETIME fileTime;
+    const UInt32 kBufSize = MAX_PATH + 1; // 256 in ATL
+    TCHAR buffer[kBufSize];
+    // we use loop limit here for some unexpected code failure
+    for (unsigned loop_cnt = 0; loop_cnt < (1u << 26); loop_cnt++)
+    {
+      DWORD size = kBufSize;
+      // we always request starting item (index==0) in each iteration,
+      // because we remove starting item (index==0) in each loop iteration.
+      res = RegEnumKeyEx(key._object, 0, buffer, &size, NULL, NULL, NULL, &fileTime);
+      if (res != ERROR_SUCCESS)
+      {
+        // possible return codes:
+        //   ERROR_NO_MORE_ITEMS : are no more subkeys available
+        //   ERROR_MORE_DATA     : name buffer is too small
+        // we can try to remove (subKeyName), even if there is non ERROR_NO_MORE_ITEMS error.
+        // if (res != ERROR_NO_MORE_ITEMS) return res;
+        break;
+      }
+      res = key.RecurseDeleteKey(buffer);
+      if (res != ERROR_SUCCESS)
+        return res;
+    }
+    // key.Close();
   }
-  key.Close();
   return DeleteSubKey(subKeyName);
 }
 
@@ -127,7 +141,7 @@ LONG CKey::DeleteValue(LPCWSTR name)
   MY_ASSUME(_object != NULL);
   if (g_IsNT)
     return ::RegDeleteValueW(_object, name);
-  return DeleteValue(name == 0 ? 0 : (LPCSTR)GetSystemString(name));
+  return DeleteValue(name == NULL ? NULL : (LPCSTR)GetSystemString(name));
 }
 #endif
 
@@ -143,12 +157,15 @@ LONG CKey::SetValue(LPCTSTR name, bool value) throw()
   return SetValue(name, BoolToUINT32(value));
 }
 
+
+// value must be string that is NULL terminated
 LONG CKey::SetValue(LPCTSTR name, LPCTSTR value) throw()
 {
   MYASSERT(value != NULL);
   MY_ASSUME(_object != NULL);
+  // note: RegSetValueEx supports (value == NULL), if (cbData == 0)
   return RegSetValueEx(_object, name, 0, REG_SZ,
-      (const BYTE *)value, ((DWORD)lstrlen(value) + 1) * sizeof(TCHAR));
+      (const BYTE *)value, (DWORD)(((DWORD)lstrlen(value) + 1) * sizeof(TCHAR)));
 }
 
 /*
@@ -156,7 +173,7 @@ LONG CKey::SetValue(LPCTSTR name, const CSysString &value)
 {
   MYASSERT(value != NULL);
   MY_ASSUME(_object != NULL);
-  return RegSetValueEx(_object, name, NULL, REG_SZ,
+  return RegSetValueEx(_object, name, 0, REG_SZ,
       (const BYTE *)(const TCHAR *)value, (value.Len() + 1) * sizeof(TCHAR));
 }
 */
@@ -169,9 +186,10 @@ LONG CKey::SetValue(LPCWSTR name, LPCWSTR value)
   MY_ASSUME(_object != NULL);
   if (g_IsNT)
     return RegSetValueExW(_object, name, 0, REG_SZ,
-      (const BYTE * )value, (DWORD)((wcslen(value) + 1) * sizeof(wchar_t)));
-  return SetValue(name == 0 ? 0 : (LPCSTR)GetSystemString(name),
-    value == 0 ? 0 : (LPCSTR)GetSystemString(value));
+        (const BYTE *)value, (DWORD)(((DWORD)wcslen(value) + 1) * sizeof(wchar_t)));
+  return SetValue(name == NULL ? NULL :
+        (LPCSTR)GetSystemString(name),
+        (LPCSTR)GetSystemString(value));
 }
 
 #endif
@@ -205,99 +223,137 @@ LONG CKey::SetKeyValue(LPCTSTR keyName, LPCTSTR valueName, LPCTSTR value) throw(
   return res;
 }
 
-LONG CKey::QueryValue(LPCTSTR name, UInt32 &value) throw()
-{
-  DWORD type = 0;
-  DWORD count = sizeof(DWORD);
-  LONG res = RegQueryValueEx(_object, name, NULL, &type,
-    (LPBYTE)&value, &count);
-  MYASSERT((res != ERROR_SUCCESS) || (type == REG_DWORD));
-  MYASSERT((res != ERROR_SUCCESS) || (count == sizeof(UInt32)));
-  return res;
-}
 
-LONG CKey::QueryValue(LPCTSTR name, bool &value) throw()
+LONG CKey::GetValue_UInt32_IfOk(LPCTSTR name, UInt32 &value) throw()
 {
-  UInt32 uintValue = BoolToUINT32(value);
-  LONG res = QueryValue(name, uintValue);
-  value = UINT32ToBool(uintValue);
+  DWORD type = 0;
+  DWORD count = sizeof(value);
+  UInt32 value2; // = value;
+  const LONG res = QueryValueEx(name, &type, (LPBYTE)&value2, &count);
+  if (res == ERROR_SUCCESS)
+  {
+    // ERROR_UNSUPPORTED_TYPE
+    if (count != sizeof(value) || type != REG_DWORD)
+      return ERROR_UNSUPPORTED_TYPE; // ERROR_INVALID_DATA;
+    value = value2;
+  }
   return res;
 }
 
-LONG CKey::GetValue_IfOk(LPCTSTR name, UInt32 &value) throw()
+LONG CKey::GetValue_UInt64_IfOk(LPCTSTR name, UInt64 &value) throw()
 {
-  UInt32 newVal;
-  LONG res = QueryValue(name, newVal);
+  DWORD type = 0;
+  DWORD count = sizeof(value);
+  UInt64 value2; // = value;
+  const LONG res = QueryValueEx(name, &type, (LPBYTE)&value2, &count);
   if (res == ERROR_SUCCESS)
-    value = newVal;
+  {
+    if (count != sizeof(value) || type != REG_QWORD)
+      return ERROR_UNSUPPORTED_TYPE;
+    value = value2;
+  }
   return res;
 }
 
-LONG CKey::GetValue_IfOk(LPCTSTR name, bool &value) throw()
+LONG CKey::GetValue_bool_IfOk(LPCTSTR name, bool &value) throw()
 {
-  bool newVal = false;
-  LONG res = QueryValue(name, newVal);
+  UInt32 uintValue;
+  const LONG res = GetValue_UInt32_IfOk(name, uintValue);
   if (res == ERROR_SUCCESS)
-    value = newVal;
+    value = UINT32ToBool(uintValue);
   return res;
 }
 
-LONG CKey::QueryValue(LPCTSTR name, LPTSTR value, UInt32 &count) throw()
-{
-  DWORD type = 0;
-  LONG res = RegQueryValueEx(_object, name, NULL, &type, (LPBYTE)value, (DWORD *)&count);
-  MYASSERT((res != ERROR_SUCCESS) || (type == REG_SZ) || (type == REG_MULTI_SZ) || (type == REG_EXPAND_SZ));
-  return res;
-}
+
 
 LONG CKey::QueryValue(LPCTSTR name, CSysString &value)
 {
   value.Empty();
-  DWORD type = 0;
-  DWORD curSize = 0;
-  LONG res = RegQueryValueEx(_object, name, NULL, &type, NULL, &curSize);
-  if (res != ERROR_SUCCESS && res != ERROR_MORE_DATA)
-    return res;
-  UInt32 curSize2 = curSize;
-  res = QueryValue(name, value.GetBuf(curSize), curSize2);
-  if (curSize > curSize2)
-    curSize = curSize2;
-  value.ReleaseBuf_CalcLen(curSize / sizeof(TCHAR));
+  LONG res = ERROR_SUCCESS;
+  {
+    // if we don't want multiple calls here,
+    // we can use big value (264) here.
+    // 3 is default available length in new string.
+    DWORD size_prev = 3 * sizeof(TCHAR);
+    // at least 2 attempts are required. But we use more attempts for cases,
+    // where string can be changed by anothner process
+    for (unsigned i = 0; i < 2 + 2; i++)
+    {
+      DWORD type = 0;
+      DWORD size = size_prev;
+      {
+        LPBYTE buf = (LPBYTE)value.GetBuf(size / sizeof(TCHAR));
+        res = QueryValueEx(name, &type, size == 0 ? NULL : buf, &size);
+        // if (size_prev == 0), then (res == ERROR_SUCCESS) is expected here, because we requested only size.
+      }
+      if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA)
+      {
+        if (type != REG_SZ && type != REG_EXPAND_SZ)
+        {
+          res = ERROR_UNSUPPORTED_TYPE;
+          size = 0;
+        }
+      }
+      else
+        size = 0;
+      if (size > size_prev)
+      {
+        size_prev = size;
+        size = 0;
+        res = ERROR_MORE_DATA;
+      }
+      value.ReleaseBuf_CalcLen(size / sizeof(TCHAR));
+      if (res != ERROR_MORE_DATA)
+        return res;
+    }
+  }
   return res;
 }
 
 
 #ifndef _UNICODE
 
-LONG CKey::QueryValue(LPCWSTR name, LPWSTR value, UInt32 &count)
-{
-  DWORD type = 0;
-  LONG res = RegQueryValueExW(_object, name, NULL, &type, (LPBYTE)value, (DWORD *)&count);
-  MYASSERT((res != ERROR_SUCCESS) || (type == REG_SZ) || (type == REG_MULTI_SZ) || (type == REG_EXPAND_SZ));
-  return res;
-}
-
 LONG CKey::QueryValue(LPCWSTR name, UString &value)
 {
   value.Empty();
-  DWORD type = 0;
-  DWORD curSize = 0;
-  LONG res;
+  LONG res = ERROR_SUCCESS;
   if (g_IsNT)
   {
-    res = RegQueryValueExW(_object, name, NULL, &type, NULL, &curSize);
-    if (res != ERROR_SUCCESS && res != ERROR_MORE_DATA)
-      return res;
-    UInt32 curSize2 = curSize;
-    res = QueryValue(name, value.GetBuf(curSize), curSize2);
-    if (curSize > curSize2)
-      curSize = curSize2;
-    value.ReleaseBuf_CalcLen(curSize / sizeof(wchar_t));
+    DWORD size_prev = 3 * sizeof(wchar_t);
+    for (unsigned i = 0; i < 2 + 2; i++)
+    {
+      DWORD type = 0;
+      DWORD size = size_prev;
+      {
+        LPBYTE buf = (LPBYTE)value.GetBuf(size / sizeof(wchar_t));
+        res = RegQueryValueExW(_object, name, NULL, &type,
+            size == 0 ? NULL : buf, &size);
+      }
+      if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA)
+      {
+        if (type != REG_SZ && type != REG_EXPAND_SZ)
+        {
+          res = ERROR_UNSUPPORTED_TYPE;
+          size = 0;
+        }
+      }
+      else
+        size = 0;
+      if (size > size_prev)
+      {
+        size_prev = size;
+        size = 0;
+        res = ERROR_MORE_DATA;
+      }
+      value.ReleaseBuf_CalcLen(size / sizeof(wchar_t));
+      if (res != ERROR_MORE_DATA)
+        return res;
+    }
   }
   else
   {
     AString vTemp;
-    res = QueryValue(name == 0 ? 0 : (LPCSTR)GetSystemString(name), vTemp);
+    res = QueryValue(name == NULL ? NULL : (LPCSTR)GetSystemString(name), vTemp);
     value = GetUnicodeString(vTemp);
   }
   return res;
@@ -306,26 +362,43 @@ LONG CKey::QueryValue(LPCWSTR name, UString &value)
 #endif
 
 
-LONG CKey::QueryValue(LPCTSTR name, void *value, UInt32 &count) throw()
+LONG CKey::QueryValue_Binary(LPCTSTR name, CByteBuffer &value)
 {
-  DWORD type = 0;
-  LONG res = RegQueryValueEx(_object, name, NULL, &type, (LPBYTE)value, (DWORD *)&count);
-  MYASSERT((res != ERROR_SUCCESS) || (type == REG_BINARY));
+  // value.Free();
+  DWORD size_prev = 0;
+  LONG res = ERROR_SUCCESS;
+  for (unsigned i = 0; i < 2 + 2; i++)
+  {
+    DWORD type = 0;
+    DWORD size = size_prev;
+    value.Alloc(size_prev);
+    res = QueryValueEx(name, &type, value.NonConstData(), &size);
+    // if (size_prev == 0), then (res == ERROR_SUCCESS) is expected here, because we requested only size.
+    if (res == ERROR_SUCCESS || res == ERROR_MORE_DATA)
+    {
+      if (type != REG_BINARY)
+      {
+        res = ERROR_UNSUPPORTED_TYPE;
+        size = 0;
+      }
+    }
+    else
+      size = 0;
+    if (size > size_prev)
+    {
+      size_prev = size;
+      size = 0;
+      res = ERROR_MORE_DATA;
+    }
+    if (size < value.Size())
+      value.ChangeSize_KeepData(size, size);
+    if (res != ERROR_MORE_DATA)
+      return res;
+  }
   return res;
 }
 
 
-LONG CKey::QueryValue(LPCTSTR name, CByteBuffer &value, UInt32 &dataSize)
-{
-  DWORD type = 0;
-  dataSize = 0;
-  LONG res = RegQueryValueEx(_object, name, NULL, &type, NULL, (DWORD *)&dataSize);
-  if (res != ERROR_SUCCESS && res != ERROR_MORE_DATA)
-    return res;
-  value.Alloc(dataSize);
-  return QueryValue(name, (BYTE *)value, dataSize);
-}
-
 LONG CKey::EnumKeys(CSysStringVector &keyNames)
 {
   keyNames.Clear();
@@ -334,23 +407,23 @@ LONG CKey::EnumKeys(CSysStringVector &keyNames)
   {
     const unsigned kBufSize = MAX_PATH + 1; // 256 in ATL
     FILETIME lastWriteTime;
-    UInt32 nameSize = kBufSize;
-    LONG result = ::RegEnumKeyEx(_object, index, keyName.GetBuf(kBufSize),
-        (DWORD *)&nameSize, NULL, NULL, NULL, &lastWriteTime);
+    DWORD nameSize = kBufSize;
+    const LONG res = ::RegEnumKeyEx(_object, index,
+        keyName.GetBuf(kBufSize), &nameSize,
+        NULL, NULL, NULL, &lastWriteTime);
     keyName.ReleaseBuf_CalcLen(kBufSize);
-    if (result == ERROR_NO_MORE_ITEMS)
-      break;
-    if (result != ERROR_SUCCESS)
-      return result;
+    if (res == ERROR_NO_MORE_ITEMS)
+      return ERROR_SUCCESS;
+    if (res != ERROR_SUCCESS)
+      return res;
     keyNames.Add(keyName);
   }
-  return ERROR_SUCCESS;
 }
 
+
 LONG CKey::SetValue_Strings(LPCTSTR valueName, const UStringVector &strings)
 {
   size_t numChars = 0;
-  
   unsigned i;
   
   for (i = 0; i < strings.Size(); i++)
@@ -362,10 +435,11 @@ LONG CKey::SetValue_Strings(LPCTSTR valueName, const UStringVector &strings)
   for (i = 0; i < strings.Size(); i++)
   {
     const UString &s = strings[i];
-    size_t size = s.Len() + 1;
+    const size_t size = s.Len() + 1;
     wmemcpy(buffer + pos, s, size);
     pos += size;
   }
+  // if (pos != numChars) return E_FAIL;
   return SetValue(valueName, buffer, (UInt32)numChars * sizeof(wchar_t));
 }
 
@@ -373,20 +447,18 @@ LONG CKey::GetValue_Strings(LPCTSTR valueName, UStringVector &strings)
 {
   strings.Clear();
   CByteBuffer buffer;
-  UInt32 dataSize = 0;
-  const LONG res = QueryValue(valueName, buffer, dataSize);
+  const LONG res = QueryValue_Binary(valueName, buffer);
   if (res != ERROR_SUCCESS)
     return res;
-  if (dataSize > buffer.Size())
-    return E_FAIL;
-  if (dataSize % sizeof(wchar_t) != 0)
-    return E_FAIL;
-
+  const size_t dataSize = buffer.Size();
+  if (dataSize % sizeof(wchar_t))
+    return ERROR_INVALID_DATA;
   const wchar_t *data = (const wchar_t *)(const void *)(const Byte  *)buffer;
   const size_t numChars = dataSize / sizeof(wchar_t);
+  // we can check that all names are finished
+  // if (numChars != 0 && data[numChars - 1] != 0) return ERROR_INVALID_DATA;
   size_t prev = 0;
   UString s;
-  
   for (size_t i = 0; i < numChars; i++)
   {
     if (data[i] == 0)
@@ -396,7 +468,6 @@ LONG CKey::GetValue_Strings(LPCTSTR valueName, UStringVector &strings)
       prev = i + 1;
     }
   }
-  
   return res;
 }
 
diff --git a/CPP/Windows/Registry.h b/CPP/Windows/Registry.h
index 0d3b4fc..74ee919 100644
--- a/CPP/Windows/Registry.h
+++ b/CPP/Windows/Registry.h
@@ -14,6 +14,13 @@ LONG SetValue(HKEY parentKey, LPCTSTR keyName, LPCTSTR valueName, LPCTSTR value)
 class CKey
 {
   HKEY _object;
+
+  LONG QueryValueEx(LPCTSTR lpValueName, LPDWORD lpType,
+      LPBYTE lpData, LPDWORD lpcbData)
+  {
+    return RegQueryValueEx(_object, lpValueName, NULL, lpType, lpData, lpcbData);
+  }
+
 public:
   CKey(): _object(NULL) {}
   ~CKey() { Close(); }
@@ -22,13 +29,14 @@ public:
   void Attach(HKEY key) { _object = key; }
   HKEY Detach()
   {
-    HKEY key = _object;
+    const HKEY key = _object;
     _object = NULL;
     return key;
   }
 
   LONG Create(HKEY parentKey, LPCTSTR keyName,
-      LPTSTR keyClass = REG_NONE, DWORD options = REG_OPTION_NON_VOLATILE,
+      LPTSTR keyClass = REG_NONE,
+      DWORD options = REG_OPTION_NON_VOLATILE,
       REGSAM accessMask = KEY_ALL_ACCESS,
       LPSECURITY_ATTRIBUTES securityAttributes = NULL,
       LPDWORD disposition = NULL) throw();
@@ -40,18 +48,18 @@ public:
   LONG RecurseDeleteKey(LPCTSTR subKeyName) throw();
 
   LONG DeleteValue(LPCTSTR name) throw();
-  #ifndef _UNICODE
+#ifndef _UNICODE
   LONG DeleteValue(LPCWSTR name);
-  #endif
+#endif
 
   LONG SetValue(LPCTSTR valueName, UInt32 value) throw();
   LONG SetValue(LPCTSTR valueName, bool value) throw();
   LONG SetValue(LPCTSTR valueName, LPCTSTR value) throw();
   // LONG SetValue(LPCTSTR valueName, const CSysString &value);
-  #ifndef _UNICODE
+#ifndef _UNICODE
   LONG SetValue(LPCWSTR name, LPCWSTR value);
   // LONG SetValue(LPCWSTR name, const UString &value);
-  #endif
+#endif
 
   LONG SetValue(LPCTSTR name, const void *value, UInt32 size) throw();
 
@@ -60,21 +68,25 @@ public:
 
   LONG SetKeyValue(LPCTSTR keyName, LPCTSTR valueName, LPCTSTR value) throw();
 
-  LONG QueryValue(LPCTSTR name, UInt32 &value) throw();
-  LONG QueryValue(LPCTSTR name, bool &value) throw();
-  LONG QueryValue(LPCTSTR name, LPTSTR value, UInt32 &dataSize) throw();
-  LONG QueryValue(LPCTSTR name, CSysString &value);
-
-  LONG GetValue_IfOk(LPCTSTR name, UInt32 &value) throw();
-  LONG GetValue_IfOk(LPCTSTR name, bool &value) throw();
+  // GetValue_[type]_IfOk():
+  //   if (return_result == ERROR_SUCCESS), (value) variable was read from registry
+  //   if (return_result != ERROR_SUCCESS), (value) variable was not changed
+  LONG GetValue_UInt32_IfOk(LPCTSTR name, UInt32 &value) throw();
+  LONG GetValue_UInt64_IfOk(LPCTSTR name, UInt64 &value) throw();
+  LONG GetValue_bool_IfOk(LPCTSTR name, bool &value) throw();
 
-  #ifndef _UNICODE
-  LONG QueryValue(LPCWSTR name, LPWSTR value, UInt32 &dataSize);
+  // QueryValue():
+  //   if (return_result == ERROR_SUCCESS), (value) string was read from registry
+  //   if (return_result != ERROR_SUCCESS), (value) string was cleared
+  LONG QueryValue(LPCTSTR name, CSysString &value);
+#ifndef _UNICODE
   LONG QueryValue(LPCWSTR name, UString &value);
-  #endif
+#endif
 
-  LONG QueryValue(LPCTSTR name, void *value, UInt32 &dataSize) throw();
-  LONG QueryValue(LPCTSTR name, CByteBuffer &value, UInt32 &dataSize);
+  // QueryValue_Binary():
+  //   if (return_result == ERROR_SUCCESS), (value) buffer was read from registry (BINARY data)
+  //   if (return_result != ERROR_SUCCESS), (value) buffer was cleared
+  LONG QueryValue_Binary(LPCTSTR name, CByteBuffer &value);
 
   LONG EnumKeys(CSysStringVector &keyNames);
 };
diff --git a/CPP/Windows/System.cpp b/CPP/Windows/System.cpp
index 03c8988..5fa87f3 100644
--- a/CPP/Windows/System.cpp
+++ b/CPP/Windows/System.cpp
@@ -142,9 +142,9 @@ typedef BOOL (WINAPI *Func_GlobalMemoryStatusEx)(MY_LPMEMORYSTATUSEX lpBuffer);
 #endif // !UNDER_CE
 
   
-bool GetRamSize(UInt64 &size)
+bool GetRamSize(size_t &size)
 {
-  size = (UInt64)(sizeof(size_t)) << 29;
+  size = (size_t)sizeof(size_t) << 29;
 
   #ifndef UNDER_CE
     MY_MEMORYSTATUSEX stat;
@@ -167,11 +167,23 @@ bool GetRamSize(UInt64 &size)
           "GlobalMemoryStatusEx");
       if (fn && fn(&stat))
       {
-        size = MyMin(stat.ullTotalVirtual, stat.ullTotalPhys);
+        // (MY_MEMORYSTATUSEX::ullTotalVirtual) < 4 GiB in 32-bit mode
+        size_t size2 = (size_t)0 - 1;
+        if (size2 > stat.ullTotalPhys)
+            size2 = (size_t)stat.ullTotalPhys;
+        if (size2 > stat.ullTotalVirtual)
+            size2 = (size_t)stat.ullTotalVirtual;
+        size = size2;
         return true;
       }
     #endif
   
+    // On computers with more than 4 GB of memory:
+    //   new docs  : GlobalMemoryStatus can report (-1) value to indicate an overflow.
+    //   some old docs : GlobalMemoryStatus can report (modulo 4 GiB) value.
+    //                   (for example, if 5 GB total memory, it could report 1 GB).
+    // We don't want to get (modulo 4 GiB) value.
+    // So we use GlobalMemoryStatusEx() instead.
     {
       MEMORYSTATUS stat2;
       stat2.dwLength = sizeof(stat2);
@@ -187,9 +199,11 @@ bool GetRamSize(UInt64 &size)
 // POSIX
 // #include <stdio.h>
 
-bool GetRamSize(UInt64 &size)
+bool GetRamSize(size_t &size)
 {
-  size = (UInt64)(sizeof(size_t)) << 29;
+  UInt64 size64;
+  size = (size_t)sizeof(size_t) << 29;
+  size64 = size;
 
 #if defined(__APPLE__) || defined(__DragonFly__) || \
     defined(BSD) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
@@ -215,7 +229,7 @@ bool GetRamSize(UInt64 &size)
     // we use strict check (size_sys == sizeof(val)) for returned value
     // because big-endian encoding is possible:
     if (res == 0 && size_sys == sizeof(val) && val)
-      size = val;
+      size64 = val;
     else
     {
       uint32_t val32 = 0;
@@ -223,12 +237,12 @@ bool GetRamSize(UInt64 &size)
       res = sysctl(mib, 2, &val32, &size_sys, NULL, 0);
       // printf("\n sysctl res=%d val=%llx size_sys = %d, %d\n", res, (long long int)val32, (int)size_sys, errno);
       if (res == 0 && size_sys == sizeof(val32) && val32)
-        size = val32;
+        size64 = val32;
     }
 
   #elif defined(_AIX)
     #if defined(_SC_AIX_REALMEM) // AIX
-      size = (UInt64)sysconf(_SC_AIX_REALMEM) * 1024;
+      size64 = (UInt64)sysconf(_SC_AIX_REALMEM) * 1024;
     #endif
   #elif 0 || defined(__sun)
     #if defined(_SC_PHYS_PAGES) && defined(_SC_PAGESIZE)
@@ -240,7 +254,7 @@ bool GetRamSize(UInt64 &size)
       // printf("\n_SC_PHYS_PAGES (hex) = %lx", (unsigned long)phys_pages);
       // printf("\n_SC_PAGESIZE = %lu\n", (unsigned long)page_size);
       if (phys_pages != -1 && page_size != -1)
-        size = (UInt64)(Int64)phys_pages * (UInt64)(Int64)page_size;
+        size64 = (UInt64)(Int64)phys_pages * (UInt64)(Int64)page_size;
     }
     #endif
   #elif defined(__gnu_hurd__)
@@ -253,7 +267,7 @@ bool GetRamSize(UInt64 &size)
   struct sysinfo info;
   if (::sysinfo(&info) != 0)
     return false;
-  size = (UInt64)info.mem_unit * info.totalram;
+  size64 = (UInt64)info.mem_unit * info.totalram;
   /*
   printf("\n mem_unit  = %lld", (UInt64)info.mem_unit);
   printf("\n totalram  = %lld", (UInt64)info.totalram);
@@ -262,10 +276,9 @@ bool GetRamSize(UInt64 &size)
 
   #endif
 
-  const UInt64 kLimit = (UInt64)1 << (sizeof(size_t) * 8 - 1);
-  if (size > kLimit)
-    size = kLimit;
-
+  size = (size_t)1 << (sizeof(size_t) * 8 - 1);
+  if (size > size64)
+      size = (size_t)size64;
   return true;
 }
 
diff --git a/CPP/Windows/System.h b/CPP/Windows/System.h
index b17111c..9951b8b 100644
--- a/CPP/Windows/System.h
+++ b/CPP/Windows/System.h
@@ -122,7 +122,7 @@ struct CProcessAffinity
 
 UInt32 GetNumberOfProcessors();
 
-bool GetRamSize(UInt64 &size); // returns false, if unknown ram size
+bool GetRamSize(size_t &size); // returns false, if unknown ram size
 
 unsigned long Get_File_OPEN_MAX();
 unsigned Get_File_OPEN_MAX_Reduced_for_3_tasks();
diff --git a/CPP/Windows/SystemInfo.cpp b/CPP/Windows/SystemInfo.cpp
index cfc6a90..35846e0 100644
--- a/CPP/Windows/SystemInfo.cpp
+++ b/CPP/Windows/SystemInfo.cpp
@@ -530,6 +530,28 @@ struct CCpuName
   AString Microcode;
   AString LargePages;
 
+#ifdef _WIN32
+  UInt32 MHz;
+
+#ifdef MY_CPU_ARM64
+#define Z7_SYS_INFO_SHOW_ARM64_REGS
+#endif
+#ifdef Z7_SYS_INFO_SHOW_ARM64_REGS
+  bool Arm64_ISAR0_EL1_Defined;
+  UInt64 Arm64_ISAR0_EL1;
+#endif
+#endif
+
+#ifdef _WIN32
+  CCpuName():
+      MHz(0)
+#ifdef Z7_SYS_INFO_SHOW_ARM64_REGS
+    , Arm64_ISAR0_EL1_Defined(false)
+    , Arm64_ISAR0_EL1(0)
+#endif
+    {}
+#endif
+
   void Fill();
 
   void Get_Revision_Microcode_LargePages(AString &s)
@@ -537,16 +559,46 @@ struct CCpuName
     s.Empty();
     AddBracedString(s, Revision);
     AddBracedString(s, Microcode);
-    s.Add_OptSpaced(LargePages);
+#ifdef _WIN32
+    if (MHz != 0)
+    {
+      s.Add_Space_if_NotEmpty();
+      s.Add_UInt32(MHz);
+      s += " MHz";
+    }
+#endif
+    if (!LargePages.IsEmpty())
+      s.Add_OptSpaced(LargePages);
+  }
+
+#ifdef Z7_SYS_INFO_SHOW_ARM64_REGS
+  void Get_Registers(AString &s)
+  {
+    if (Arm64_ISAR0_EL1_Defined)
+    {
+      // ID_AA64ISAR0_EL1
+      s.Add_OptSpaced("cp4030:");
+      PrintHex(s, Arm64_ISAR0_EL1);
+      {
+        const unsigned sha2 = ((unsigned)(Arm64_ISAR0_EL1 >> 12) & 0xf) - 1;
+        if (sha2 < 2)
+        {
+          s += ":SHA256";
+          if (sha2)
+            s += ":SHA512";
+        }
+      }
+    }
   }
+#endif
 };
 
 void CCpuName::Fill()
 {
-  CpuName.Empty();
-  Revision.Empty();
-  Microcode.Empty();
-  LargePages.Empty();
+  // CpuName.Empty();
+  // Revision.Empty();
+  // Microcode.Empty();
+  // LargePages.Empty();
 
   AString &s = CpuName;
 
@@ -600,21 +652,32 @@ void CCpuName::Fill()
           Revision += GetAnsiString(name);
         }
       }
+#ifdef _WIN32
+      key.GetValue_UInt32_IfOk(TEXT("~MHz"), MHz);
+#ifdef Z7_SYS_INFO_SHOW_ARM64_REGS
+/*
+mapping arm64 registers to Windows registry:
+CP 4000: MIDR_EL1
+CP 4020: ID_AA64PFR0_EL1
+CP 4021: ID_AA64PFR1_EL1
+CP 4028: ID_AA64DFR0_EL1
+CP 4029: ID_AA64DFR1_EL1
+CP 402C: ID_AA64AFR0_EL1
+CP 402D: ID_AA64AFR1_EL1
+CP 4030: ID_AA64ISAR0_EL1
+CP 4031: ID_AA64ISAR1_EL1
+CP 4038: ID_AA64MMFR0_EL1
+CP 4039: ID_AA64MMFR1_EL1
+CP 403A: ID_AA64MMFR2_EL1
+*/
+      if (key.GetValue_UInt64_IfOk(TEXT("CP 4030"), Arm64_ISAR0_EL1) == ERROR_SUCCESS)
+        Arm64_ISAR0_EL1_Defined = true;
+#endif
+#endif
       LONG res[2];
       CByteBuffer bufs[2];
-      {
-        for (unsigned i = 0; i < 2; i++)
-        {
-          UInt32 size = 0;
-          res[i] = key.QueryValue(i == 0 ?
-              TEXT("Previous Update Revision") :
-              TEXT("Update Revision"),
-              bufs[i], size);
-          if (res[i] == ERROR_SUCCESS)
-            if (size != bufs[i].Size())
-              res[i] = ERROR_SUCCESS + 1;
-        }
-      }
+      res[0] = key.QueryValue_Binary(TEXT("Previous Update Revision"), bufs[0]);
+      res[1] = key.QueryValue_Binary(TEXT("Update Revision"),          bufs[1]);
       if (res[0] == ERROR_SUCCESS || res[1] == ERROR_SUCCESS)
       {
         for (unsigned i = 0; i < 2; i++)
@@ -747,9 +810,18 @@ void AddCpuFeatures(AString &s)
     unsigned long h = MY_getauxval(AT_HWCAP);
     PrintHex(s, h);
     #ifdef MY_CPU_ARM64
+#ifndef HWCAP_SHA3
+#define HWCAP_SHA3    (1 << 17)
+#endif
+#ifndef HWCAP_SHA512
+#define HWCAP_SHA512  (1 << 21)
+// #pragma message("=== HWCAP_SHA512 define === ")
+#endif
     if (h & HWCAP_CRC32)  s += ":CRC32";
     if (h & HWCAP_SHA1)   s += ":SHA1";
     if (h & HWCAP_SHA2)   s += ":SHA2";
+    if (h & HWCAP_SHA3)   s += ":SHA3";
+    if (h & HWCAP_SHA512) s += ":SHA512";
     if (h & HWCAP_AES)    s += ":AES";
     if (h & HWCAP_ASIMD)  s += ":ASIMD";
     #elif defined(MY_CPU_ARM)
@@ -908,13 +980,18 @@ void GetSystemInfoText(AString &sRes)
       }
     }
     {
-      AString s;
-      GetCpuName_MultiLine(s);
+      AString s, registers;
+      GetCpuName_MultiLine(s, registers);
       if (!s.IsEmpty())
       {
         sRes += s;
         sRes.Add_LF();
       }
+      if (!registers.IsEmpty())
+      {
+        sRes += registers;
+        sRes.Add_LF();
+      }
     }
     /*
     #ifdef MY_CPU_X86_OR_AMD64
@@ -932,8 +1009,8 @@ void GetSystemInfoText(AString &sRes)
 }
 
 
-void GetCpuName_MultiLine(AString &s);
-void GetCpuName_MultiLine(AString &s)
+void GetCpuName_MultiLine(AString &s, AString &registers);
+void GetCpuName_MultiLine(AString &s, AString &registers)
 {
   CCpuName cpuName;
   cpuName.Fill();
@@ -945,6 +1022,10 @@ void GetCpuName_MultiLine(AString &s)
     s.Add_LF();
     s += s2;
   }
+  registers.Empty();
+#ifdef Z7_SYS_INFO_SHOW_ARM64_REGS
+  cpuName.Get_Registers(registers);
+#endif
 }
 
 
diff --git a/CPP/Windows/SystemInfo.h b/CPP/Windows/SystemInfo.h
index c2e2e3b..4601685 100644
--- a/CPP/Windows/SystemInfo.h
+++ b/CPP/Windows/SystemInfo.h
@@ -6,7 +6,7 @@
 #include "../Common/MyString.h"
 
 
-void GetCpuName_MultiLine(AString &s);
+void GetCpuName_MultiLine(AString &s, AString &registers);
 
 void GetOsInfoText(AString &sRes);
 void GetSystemInfoText(AString &s);
diff --git a/DOC/7zip.wxs b/DOC/7zip.wxs
index f41b393..867e3d1 100644
--- a/DOC/7zip.wxs
+++ b/DOC/7zip.wxs
@@ -1,7 +1,7 @@
 <?xml version="1.0"?>
 
 <?define VerMajor = "24" ?>
-<?define VerMinor = "08" ?>
+<?define VerMinor = "09" ?>
 <?define VerBuild = "00" ?>
 <?define MmVer = "$(var.VerMajor).$(var.VerMinor)" ?>
 <?define MmHex = "$(var.VerMajor)$(var.VerMinor)" ?>
diff --git a/DOC/readme.txt b/DOC/readme.txt
index 6d04c5a..ad1d842 100644
--- a/DOC/readme.txt
+++ b/DOC/readme.txt
@@ -1,4 +1,4 @@
-7-Zip 24.07 Sources
+7-Zip 24.09 Sources
 -------------------
 
 7-Zip is a file archiver for Windows. 
@@ -100,12 +100,14 @@ So if you compile the version with Assembeler code, you will get faster 7-Zip bi
 7-Zip's assembler code uses the following syntax for different platforms:
 
 1) x86 and x86-64 (AMD64): MASM syntax. 
-   There are 2 programs that supports MASM syntax in Linux.
-'    'Asmc Macro Assembler and JWasm. But JWasm now doesn't support some 
+   Now there are 3 programs that supports MASM syntax in Linux.
+'    'Asmc Macro Assembler, JWasm, and UASM. Note that JWasm now doesn't support some 
       cpu instructions used in 7-Zip.
-   So you must install Asmc Macro Assembler in Linux, if you want to compile fastest version
-   of 7-Zip  x86 and x86-64:
+   So you must install Asmc Macro Assembler in Linux or UASM, if you want to compile 
+   fastest version of 7-Zip  x86 and x86-64:
      https://github.com/nidud/asmc
+     https://github.com/Terraspace/UASM
+
 
 2) arm64: GNU assembler for ARM64 with preprocessor. 
    That systax is supported by GCC and CLANG for ARM64.
@@ -155,6 +157,13 @@ USE_JWASM=1
   Note that JWasm doesn't support AES instructions. So AES code from C version AesOpt.c 
   will be used instead of assembler code from AesOpt.asm.
 
+If you want to use UASM for x86-64 compiling, you can change 7zip_gcc.mak, 
+or send IS_X64=1 USE_ASM=1 MY_ASM="$UASM" to make command calling:
+  UASM="$PWD/GccUnixR/uasm"
+  cd "7zip-src/CPP/7zip/Bundles/Alone2"
+  make -f makefile.gcc -j IS_X64=1 USE_ASM=1 MY_ASM="$UASM"
+
+
 DISABLE_RAR=1
   removes whole RAR related code from compilation.
 
diff --git a/DOC/src-history.txt b/DOC/src-history.txt
index 1653c07..6b57694 100644
--- a/DOC/src-history.txt
+++ b/DOC/src-history.txt
@@ -1,6 +1,29 @@
 HISTORY of the 7-Zip source code
 --------------------------------
 
+24.09          2024-11-29
+-------------------------
+- The default dictionary size values for LZMA/LZMA2 compression methods were increased:
+         dictionary size   compression level
+  v24.08  v24.09  v24.09   
+          32-bit  64-bit    
+    8 MB   16 MB   16 MB   -mx4
+   16 MB   32 MB   32 MB   -mx5 : Normal
+   32 MB   64 MB   64 MB   -mx6
+   32 MB   64 MB  128 MB   -mx7 : Maximum
+   64 MB   64 MB  256 MB   -mx8
+   64 MB   64 MB  256 MB   -mx9 : Ultra
+  The default dictionary size values for 32-bit versions of LZMA/LZMA2 don't exceed 64 MB.
+- 7-Zip now can calculate the following hash checksums: SHA-512, SHA-384, SHA3-256 and MD5.
+- APM and HFS support was improved.
+- If an archive update operation uses a temporary archive folder and 
+  the archive is moved to the destination folder, 7-Zip shows the progress of moving 
+  the archive file, as this operation can take a long time if the archive is large.
+- The bug was fixed: 7-Zip File Manager didn't propagate Zone.Identifier stream
+  for extacted files from nested archives (if there is open archive inside another open archive).
+- Some bugs were fixed.
+
+
 24.08          2024-08-11
 -------------------------
 - The bug in 7-Zip 24.00-24.07 was fixed:
diff --git a/METADATA b/METADATA
index cdff02b..412aff2 100644
--- a/METADATA
+++ b/METADATA
@@ -8,13 +8,13 @@ third_party {
   license_type: UNENCUMBERED
   last_upgrade_date {
     year: 2024
-    month: 9
-    day: 5
+    month: 12
+    day: 3
   }
   homepage: "https://7-zip.org/"
   identifier {
     type: "Archive"
-    value: "https://github.com/ip7z/7zip/archive/24.08.tar.gz"
-    version: "24.08"
+    value: "https://github.com/ip7z/7zip/archive/24.09.tar.gz"
+    version: "24.09"
   }
 }
```

