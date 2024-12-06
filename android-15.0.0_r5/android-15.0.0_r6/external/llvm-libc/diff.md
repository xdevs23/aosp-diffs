```diff
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 41ae5ea..528ffec 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -1,5 +1,8 @@
 {
-  "postsubmit": [
+  "presubmit": [
+    {
+      "name": "CtsBionicTestCases"
+    },
     {
       "name": "llvmlibc_stdlib_bsearch_test",
       "options": [ { "native-test-flag": "--gtest_color=no"} ]
diff --git a/include/llvm-libc-macros/float16-macros.h b/include/llvm-libc-macros/float16-macros.h
index 9f17503..e7d8d93 100644
--- a/include/llvm-libc-macros/float16-macros.h
+++ b/include/llvm-libc-macros/float16-macros.h
@@ -10,7 +10,8 @@
 #define LLVM_LIBC_MACROS_FLOAT16_MACROS_H
 
 #if defined(__FLT16_MANT_DIG__) &&                                             \
-    (!defined(__GNUC__) || __GNUC__ >= 13 || defined(__clang__))
+    (!defined(__GNUC__) || __GNUC__ >= 13 || defined(__clang__)) &&            \
+    !defined(__arm__) && !defined(_M_ARM) && !defined(__riscv)
 #define LIBC_TYPES_HAS_FLOAT16
 #endif
 
diff --git a/include/llvm-libc-macros/limits-macros.h b/include/llvm-libc-macros/limits-macros.h
index 95f0f5f..3fab996 100644
--- a/include/llvm-libc-macros/limits-macros.h
+++ b/include/llvm-libc-macros/limits-macros.h
@@ -148,7 +148,7 @@
 #endif // INT_MAX
 
 #ifndef UINT_MAX
-#define UINT_MAX (~0U)
+#define UINT_MAX (INT_MAX * 2U + 1U)
 #endif // UINT_MAX
 
 #ifndef LONG_MAX
@@ -160,7 +160,7 @@
 #endif // LONG_MAX
 
 #ifndef ULONG_MAX
-#define ULONG_MAX (~0UL)
+#define ULONG_MAX (LONG_MAX * 2UL + 1UL)
 #endif // ULONG_MAX
 
 #ifndef LLONG_MAX
@@ -172,7 +172,7 @@
 #endif // LLONG_MAX
 
 #ifndef ULLONG_MAX
-#define ULLONG_MAX (~0ULL)
+#define ULLONG_MAX (LLONG_MAX * 2ULL + 1ULL)
 #endif // ULLONG_MAX
 
 // *_MIN macros
diff --git a/include/llvm-libc-types/jmp_buf.h b/include/llvm-libc-types/jmp_buf.h
index 29a1df9..8949be9 100644
--- a/include/llvm-libc-types/jmp_buf.h
+++ b/include/llvm-libc-types/jmp_buf.h
@@ -32,6 +32,9 @@ typedef struct {
 #elif defined(__riscv_float_abi_single)
 #error "__jmp_buf not available for your target architecture."
 #endif
+#elif defined(__arm__)
+  // r4, r5, r6, r7, r8, r9, r10, r11, r12, lr
+  long opaque[10];
 #else
 #error "__jmp_buf not available for your target architecture."
 #endif
diff --git a/include/llvm-libc-types/pthread_rwlock_t.h b/include/llvm-libc-types/pthread_rwlock_t.h
new file mode 100644
index 0000000..da49a15
--- /dev/null
+++ b/include/llvm-libc-types/pthread_rwlock_t.h
@@ -0,0 +1,26 @@
+//===-- Definition of pthread_mutex_t type --------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_TYPES_PTHREAD_RWLOCK_T_H
+#define LLVM_LIBC_TYPES_PTHREAD_RWLOCK_T_H
+
+#include "llvm-libc-types/__futex_word.h"
+#include "llvm-libc-types/pid_t.h"
+typedef struct {
+  unsigned __is_pshared : 1;
+  unsigned __preference : 1;
+  int __state;
+  pid_t __writer_tid;
+  __futex_word __wait_queue_mutex;
+  __futex_word __pending_readers;
+  __futex_word __pending_writers;
+  __futex_word __reader_serialization;
+  __futex_word __writer_serialization;
+} pthread_rwlock_t;
+
+#endif // LLVM_LIBC_TYPES_PTHREAD_RWLOCK_T_H
diff --git a/src/__support/CPP/bit.h b/src/__support/CPP/bit.h
index 8a8951a..4aea066 100644
--- a/src/__support/CPP/bit.h
+++ b/src/__support/CPP/bit.h
@@ -271,9 +271,10 @@ template <typename T>
 [[nodiscard]] LIBC_INLINE constexpr cpp::enable_if_t<cpp::is_unsigned_v<T>, int>
 popcount(T value) {
   int count = 0;
-  for (int i = 0; i != cpp::numeric_limits<T>::digits; ++i)
-    if ((value >> i) & 0x1)
-      ++count;
+  while (value) {
+    value &= value - 1;
+    ++count;
+  }
   return count;
 }
 #define ADD_SPECIALIZATION(TYPE, BUILTIN)                                      \
diff --git a/src/__support/FPUtil/BasicOperations.h b/src/__support/FPUtil/BasicOperations.h
index e5ac101..17eee7b 100644
--- a/src/__support/FPUtil/BasicOperations.h
+++ b/src/__support/FPUtil/BasicOperations.h
@@ -240,6 +240,73 @@ LIBC_INLINE int canonicalize(T &cx, const T &x) {
   return 0;
 }
 
+template <typename T>
+LIBC_INLINE cpp::enable_if_t<cpp::is_floating_point_v<T>, bool>
+totalorder(T x, T y) {
+  using FPBits = FPBits<T>;
+  FPBits x_bits(x);
+  FPBits y_bits(y);
+
+  using StorageType = typename FPBits::StorageType;
+  StorageType x_u = x_bits.uintval();
+  StorageType y_u = y_bits.uintval();
+
+  using signed_t = cpp::make_signed_t<StorageType>;
+  signed_t x_signed = static_cast<signed_t>(x_u);
+  signed_t y_signed = static_cast<signed_t>(y_u);
+
+  bool both_neg = (x_u & y_u & FPBits::SIGN_MASK) != 0;
+  return x_signed == y_signed || ((x_signed <= y_signed) != both_neg);
+}
+
+template <typename T>
+LIBC_INLINE cpp::enable_if_t<cpp::is_floating_point_v<T>, bool>
+totalordermag(T x, T y) {
+  return FPBits<T>(x).abs().uintval() <= FPBits<T>(y).abs().uintval();
+}
+
+template <typename T>
+LIBC_INLINE cpp::enable_if_t<cpp::is_floating_point_v<T>, T> getpayload(T x) {
+  using FPBits = FPBits<T>;
+  FPBits x_bits(x);
+
+  if (!x_bits.is_nan())
+    return T(-1.0);
+
+  return T(x_bits.uintval() & (FPBits::FRACTION_MASK >> 1));
+}
+
+template <bool IsSignaling, typename T>
+LIBC_INLINE cpp::enable_if_t<cpp::is_floating_point_v<T>, bool>
+setpayload(T &res, T pl) {
+  using FPBits = FPBits<T>;
+  FPBits pl_bits(pl);
+
+  // Signaling NaNs don't have the mantissa's MSB set to 1, so they need a
+  // non-zero payload to distinguish them from infinities.
+  if (!IsSignaling && pl_bits.is_zero()) {
+    res = FPBits::quiet_nan(Sign::POS).get_val();
+    return false;
+  }
+
+  int pl_exp = pl_bits.get_exponent();
+
+  if (pl_bits.is_neg() || pl_exp < 0 || pl_exp >= FPBits::FRACTION_LEN - 1 ||
+      ((pl_bits.get_mantissa() << pl_exp) & FPBits::FRACTION_MASK) != 0) {
+    res = T(0.0);
+    return true;
+  }
+
+  using StorageType = typename FPBits::StorageType;
+  StorageType v(pl_bits.get_explicit_mantissa() >> (FPBits::SIG_LEN - pl_exp));
+
+  if constexpr (IsSignaling)
+    res = FPBits::signaling_nan(Sign::POS, v).get_val();
+  else
+    res = FPBits::quiet_nan(Sign::POS, v).get_val();
+  return false;
+}
+
 } // namespace fputil
 } // namespace LIBC_NAMESPACE
 
diff --git a/src/__support/FPUtil/FMA.h b/src/__support/FPUtil/FMA.h
index c277da4..cf01a31 100644
--- a/src/__support/FPUtil/FMA.h
+++ b/src/__support/FPUtil/FMA.h
@@ -10,41 +10,29 @@
 #define LLVM_LIBC_SRC___SUPPORT_FPUTIL_FMA_H
 
 #include "src/__support/CPP/type_traits.h"
+#include "src/__support/FPUtil/generic/FMA.h"
 #include "src/__support/macros/properties/architectures.h"
 #include "src/__support/macros/properties/cpu_features.h" // LIBC_TARGET_CPU_HAS_FMA
 
-#if defined(LIBC_TARGET_CPU_HAS_FMA)
-
 namespace LIBC_NAMESPACE {
 namespace fputil {
 
-template <typename T>
-LIBC_INLINE cpp::enable_if_t<cpp::is_same_v<T, float>, T> fma(T x, T y, T z) {
-  return __builtin_fmaf(x, y, z);
+template <typename OutType, typename InType>
+LIBC_INLINE OutType fma(InType x, InType y, InType z) {
+  return generic::fma<OutType>(x, y, z);
 }
 
-template <typename T>
-LIBC_INLINE cpp::enable_if_t<cpp::is_same_v<T, double>, T> fma(T x, T y, T z) {
-  return __builtin_fma(x, y, z);
+#ifdef LIBC_TARGET_CPU_HAS_FMA
+template <> LIBC_INLINE float fma(float x, float y, float z) {
+  return __builtin_fmaf(x, y, z);
 }
 
-} // namespace fputil
-} // namespace LIBC_NAMESPACE
-
-#else
-// FMA instructions are not available
-#include "generic/FMA.h"
-
-namespace LIBC_NAMESPACE {
-namespace fputil {
-
-template <typename T> LIBC_INLINE T fma(T x, T y, T z) {
-  return generic::fma(x, y, z);
+template <> LIBC_INLINE double fma(double x, double y, double z) {
+  return __builtin_fma(x, y, z);
 }
+#endif // LIBC_TARGET_CPU_HAS_FMA
 
 } // namespace fputil
 } // namespace LIBC_NAMESPACE
 
-#endif
-
 #endif // LLVM_LIBC_SRC___SUPPORT_FPUTIL_FMA_H
diff --git a/src/__support/FPUtil/ManipulationFunctions.h b/src/__support/FPUtil/ManipulationFunctions.h
index a289c2e..97c4312 100644
--- a/src/__support/FPUtil/ManipulationFunctions.h
+++ b/src/__support/FPUtil/ManipulationFunctions.h
@@ -142,8 +142,10 @@ LIBC_INLINE constexpr T logb(T x) {
   return static_cast<T>(normal.get_unbiased_exponent());
 }
 
-template <typename T, cpp::enable_if_t<cpp::is_floating_point_v<T>, int> = 0>
-LIBC_INLINE constexpr T ldexp(T x, int exp) {
+template <typename T, typename U>
+LIBC_INLINE constexpr cpp::enable_if_t<
+    cpp::is_floating_point_v<T> && cpp::is_integral_v<U>, T>
+ldexp(T x, U exp) {
   FPBits<T> bits(x);
   if (LIBC_UNLIKELY((exp == 0) || bits.is_zero() || bits.is_inf_or_nan()))
     return x;
@@ -156,6 +158,8 @@ LIBC_INLINE constexpr T ldexp(T x, int exp) {
   // calculating the limit.
   constexpr int EXP_LIMIT =
       FPBits<T>::MAX_BIASED_EXPONENT + FPBits<T>::FRACTION_LEN + 1;
+  // Make sure that we can safely cast exp to int when not returning early.
+  static_assert(EXP_LIMIT <= INT_MAX && -EXP_LIMIT >= INT_MIN);
   if (LIBC_UNLIKELY(exp > EXP_LIMIT)) {
     int rounding_mode = quick_get_round();
     Sign sign = bits.sign();
@@ -186,7 +190,7 @@ LIBC_INLINE constexpr T ldexp(T x, int exp) {
 
   // For all other values, NormalFloat to T conversion handles it the right way.
   DyadicFloat<FPBits<T>::STORAGE_LEN> normal(bits.get_val());
-  normal.exponent += exp;
+  normal.exponent += static_cast<int>(exp);
   return static_cast<T>(normal);
 }
 
diff --git a/src/__support/FPUtil/NormalFloat.h b/src/__support/FPUtil/NormalFloat.h
index 8bc1fec..413d204 100644
--- a/src/__support/FPUtil/NormalFloat.h
+++ b/src/__support/FPUtil/NormalFloat.h
@@ -52,7 +52,7 @@ template <typename T> struct NormalFloat {
       return;
 
     unsigned normalization_shift = evaluate_normalization_shift(mantissa);
-    mantissa = mantissa << normalization_shift;
+    mantissa <<= normalization_shift;
     exponent -= normalization_shift;
   }
 
@@ -110,9 +110,11 @@ template <typename T> struct NormalFloat {
       if (shift <= FPBits<T>::FRACTION_LEN + 1) {
         // Generate a subnormal number. Might lead to loss of precision.
         // We round to nearest and round halfway cases to even.
-        const StorageType shift_out_mask = (StorageType(1) << shift) - 1;
+        const StorageType shift_out_mask =
+            static_cast<StorageType>(StorageType(1) << shift) - 1;
         const StorageType shift_out_value = mantissa & shift_out_mask;
-        const StorageType halfway_value = StorageType(1) << (shift - 1);
+        const StorageType halfway_value =
+            static_cast<StorageType>(StorageType(1) << (shift - 1));
         result.set_biased_exponent(0);
         result.set_mantissa(mantissa >> shift);
         StorageType new_mantissa = result.get_mantissa();
@@ -135,7 +137,8 @@ template <typename T> struct NormalFloat {
       }
     }
 
-    result.set_biased_exponent(exponent + FPBits<T>::EXP_BIAS);
+    result.set_biased_exponent(
+        static_cast<StorageType>(exponent + FPBits<T>::EXP_BIAS));
     result.set_mantissa(mantissa);
     return result.get_val();
   }
@@ -155,7 +158,7 @@ private:
     // Normalize subnormal numbers.
     if (bits.is_subnormal()) {
       unsigned shift = evaluate_normalization_shift(bits.get_mantissa());
-      mantissa = StorageType(bits.get_mantissa()) << shift;
+      mantissa = static_cast<StorageType>(bits.get_mantissa() << shift);
       exponent = 1 - FPBits<T>::EXP_BIAS - shift;
     } else {
       exponent = bits.get_biased_exponent() - FPBits<T>::EXP_BIAS;
diff --git a/src/__support/FPUtil/dyadic_float.h b/src/__support/FPUtil/dyadic_float.h
index 12a6922..63cb983 100644
--- a/src/__support/FPUtil/dyadic_float.h
+++ b/src/__support/FPUtil/dyadic_float.h
@@ -126,7 +126,7 @@ template <size_t Bits> struct DyadicFloat {
         shift >= MantissaType::BITS ? MantissaType(0) : mantissa >> shift;
 
     T d_hi = FPBits<T>::create_value(
-                 sign, exp_hi,
+                 sign, static_cast<output_bits_t>(exp_hi),
                  (static_cast<output_bits_t>(m_hi) & FPBits<T>::SIG_MASK) |
                      IMPLICIT_MASK)
                  .get_val();
@@ -143,25 +143,32 @@ template <size_t Bits> struct DyadicFloat {
 
     if (LIBC_UNLIKELY(exp_lo <= 0)) {
       // d_lo is denormal, but the output is normal.
-      int scale_up_exponent = 2 * PRECISION;
+      int scale_up_exponent = 1 - exp_lo;
       T scale_up_factor =
-          FPBits<T>::create_value(sign, FPBits<T>::EXP_BIAS + scale_up_exponent,
+          FPBits<T>::create_value(sign,
+                                  static_cast<output_bits_t>(
+                                      FPBits<T>::EXP_BIAS + scale_up_exponent),
                                   IMPLICIT_MASK)
               .get_val();
       T scale_down_factor =
-          FPBits<T>::create_value(sign, FPBits<T>::EXP_BIAS - scale_up_exponent,
+          FPBits<T>::create_value(sign,
+                                  static_cast<output_bits_t>(
+                                      FPBits<T>::EXP_BIAS - scale_up_exponent),
                                   IMPLICIT_MASK)
               .get_val();
 
-      d_lo = FPBits<T>::create_value(sign, exp_lo + scale_up_exponent,
-                                     IMPLICIT_MASK)
+      d_lo = FPBits<T>::create_value(
+                 sign, static_cast<output_bits_t>(exp_lo + scale_up_exponent),
+                 IMPLICIT_MASK)
                  .get_val();
 
       return multiply_add(d_lo, T(round_and_sticky), d_hi * scale_up_factor) *
              scale_down_factor;
     }
 
-    d_lo = FPBits<T>::create_value(sign, exp_lo, IMPLICIT_MASK).get_val();
+    d_lo = FPBits<T>::create_value(sign, static_cast<output_bits_t>(exp_lo),
+                                   IMPLICIT_MASK)
+               .get_val();
 
     // Still correct without FMA instructions if `d_lo` is not underflow.
     T r = multiply_add(d_lo, T(round_and_sticky), d_hi);
@@ -169,7 +176,8 @@ template <size_t Bits> struct DyadicFloat {
     if (LIBC_UNLIKELY(denorm)) {
       // Exponent before rounding is in denormal range, simply clear the
       // exponent field.
-      output_bits_t clear_exp = (output_bits_t(exp_hi) << FPBits<T>::SIG_LEN);
+      output_bits_t clear_exp = static_cast<output_bits_t>(
+          output_bits_t(exp_hi) << FPBits<T>::SIG_LEN);
       output_bits_t r_bits = FPBits<T>(r).uintval() - clear_exp;
       if (!(r_bits & FPBits<T>::EXP_MASK)) {
         // Output is denormal after rounding, clear the implicit bit for 80-bit
diff --git a/src/__support/FPUtil/generic/FMA.h b/src/__support/FPUtil/generic/FMA.h
index f403aa7..71b1507 100644
--- a/src/__support/FPUtil/generic/FMA.h
+++ b/src/__support/FPUtil/generic/FMA.h
@@ -10,19 +10,26 @@
 #define LLVM_LIBC_SRC___SUPPORT_FPUTIL_GENERIC_FMA_H
 
 #include "src/__support/CPP/bit.h"
+#include "src/__support/CPP/limits.h"
 #include "src/__support/CPP/type_traits.h"
-#include "src/__support/FPUtil/FEnvImpl.h"
 #include "src/__support/FPUtil/FPBits.h"
 #include "src/__support/FPUtil/rounding_mode.h"
+#include "src/__support/big_int.h"
 #include "src/__support/macros/attributes.h"   // LIBC_INLINE
 #include "src/__support/macros/optimization.h" // LIBC_UNLIKELY
-#include "src/__support/uint128.h"
+
+#include "hdr/fenv_macros.h"
 
 namespace LIBC_NAMESPACE {
 namespace fputil {
 namespace generic {
 
-template <typename T> LIBC_INLINE T fma(T x, T y, T z);
+template <typename OutType, typename InType>
+LIBC_INLINE cpp::enable_if_t<cpp::is_floating_point_v<OutType> &&
+                                 cpp::is_floating_point_v<InType> &&
+                                 sizeof(OutType) <= sizeof(InType),
+                             OutType>
+fma(InType x, InType y, InType z);
 
 // TODO(lntue): Implement fmaf that is correctly rounded to all rounding modes.
 // The implementation below only is only correct for the default rounding mode,
@@ -64,11 +71,10 @@ template <> LIBC_INLINE float fma<float>(float x, float y, float z) {
     // Update sticky bits if t != 0.0 and the least (52 - 23 - 1 = 28) bits are
     // zero.
     if (!t.is_zero() && ((bit_sum.get_mantissa() & 0xfff'ffffULL) == 0)) {
-      if (bit_sum.sign() != t.sign()) {
+      if (bit_sum.sign() != t.sign())
         bit_sum.set_mantissa(bit_sum.get_mantissa() + 1);
-      } else if (bit_sum.get_mantissa()) {
+      else if (bit_sum.get_mantissa())
         bit_sum.set_mantissa(bit_sum.get_mantissa() - 1);
-      }
     }
   }
 
@@ -79,12 +85,14 @@ namespace internal {
 
 // Extract the sticky bits and shift the `mantissa` to the right by
 // `shift_length`.
-LIBC_INLINE bool shift_mantissa(int shift_length, UInt128 &mant) {
-  if (shift_length >= 128) {
+template <typename T>
+LIBC_INLINE cpp::enable_if_t<is_unsigned_integral_or_big_int_v<T>, bool>
+shift_mantissa(int shift_length, T &mant) {
+  if (shift_length >= cpp::numeric_limits<T>::digits) {
     mant = 0;
     return true; // prod_mant is non-zero.
   }
-  UInt128 mask = (UInt128(1) << shift_length) - 1;
+  T mask = (T(1) << shift_length) - 1;
   bool sticky_bits = (mant & mask) != 0;
   mant >>= shift_length;
   return sticky_bits;
@@ -92,47 +100,64 @@ LIBC_INLINE bool shift_mantissa(int shift_length, UInt128 &mant) {
 
 } // namespace internal
 
-template <> LIBC_INLINE double fma<double>(double x, double y, double z) {
-  using FPBits = fputil::FPBits<double>;
-
-  if (LIBC_UNLIKELY(x == 0 || y == 0 || z == 0)) {
-    return x * y + z;
-  }
+template <typename OutType, typename InType>
+LIBC_INLINE cpp::enable_if_t<cpp::is_floating_point_v<OutType> &&
+                                 cpp::is_floating_point_v<InType> &&
+                                 sizeof(OutType) <= sizeof(InType),
+                             OutType>
+fma(InType x, InType y, InType z) {
+  using OutFPBits = fputil::FPBits<OutType>;
+  using OutStorageType = typename OutFPBits::StorageType;
+  using InFPBits = fputil::FPBits<InType>;
+  using InStorageType = typename InFPBits::StorageType;
+
+  constexpr int IN_EXPLICIT_MANT_LEN = InFPBits::FRACTION_LEN + 1;
+  constexpr size_t PROD_LEN = 2 * IN_EXPLICIT_MANT_LEN;
+  constexpr size_t TMP_RESULT_LEN = cpp::bit_ceil(PROD_LEN + 1);
+  using TmpResultType = UInt<TMP_RESULT_LEN>;
+
+  constexpr size_t EXTRA_FRACTION_LEN =
+      TMP_RESULT_LEN - 1 - OutFPBits::FRACTION_LEN;
+  constexpr TmpResultType EXTRA_FRACTION_STICKY_MASK =
+      (TmpResultType(1) << (EXTRA_FRACTION_LEN - 1)) - 1;
+
+  if (LIBC_UNLIKELY(x == 0 || y == 0 || z == 0))
+    return static_cast<OutType>(x * y + z);
 
   int x_exp = 0;
   int y_exp = 0;
   int z_exp = 0;
 
   // Normalize denormal inputs.
-  if (LIBC_UNLIKELY(FPBits(x).is_subnormal())) {
-    x_exp -= 52;
-    x *= 0x1.0p+52;
+  if (LIBC_UNLIKELY(InFPBits(x).is_subnormal())) {
+    x_exp -= InFPBits::FRACTION_LEN;
+    x *= InType(InStorageType(1) << InFPBits::FRACTION_LEN);
   }
-  if (LIBC_UNLIKELY(FPBits(y).is_subnormal())) {
-    y_exp -= 52;
-    y *= 0x1.0p+52;
+  if (LIBC_UNLIKELY(InFPBits(y).is_subnormal())) {
+    y_exp -= InFPBits::FRACTION_LEN;
+    y *= InType(InStorageType(1) << InFPBits::FRACTION_LEN);
   }
-  if (LIBC_UNLIKELY(FPBits(z).is_subnormal())) {
-    z_exp -= 52;
-    z *= 0x1.0p+52;
+  if (LIBC_UNLIKELY(InFPBits(z).is_subnormal())) {
+    z_exp -= InFPBits::FRACTION_LEN;
+    z *= InType(InStorageType(1) << InFPBits::FRACTION_LEN);
   }
 
-  FPBits x_bits(x), y_bits(y), z_bits(z);
+  InFPBits x_bits(x), y_bits(y), z_bits(z);
   const Sign z_sign = z_bits.sign();
   Sign prod_sign = (x_bits.sign() == y_bits.sign()) ? Sign::POS : Sign::NEG;
   x_exp += x_bits.get_biased_exponent();
   y_exp += y_bits.get_biased_exponent();
   z_exp += z_bits.get_biased_exponent();
 
-  if (LIBC_UNLIKELY(x_exp == FPBits::MAX_BIASED_EXPONENT ||
-                    y_exp == FPBits::MAX_BIASED_EXPONENT ||
-                    z_exp == FPBits::MAX_BIASED_EXPONENT))
-    return x * y + z;
+  if (LIBC_UNLIKELY(x_exp == InFPBits::MAX_BIASED_EXPONENT ||
+                    y_exp == InFPBits::MAX_BIASED_EXPONENT ||
+                    z_exp == InFPBits::MAX_BIASED_EXPONENT))
+    return static_cast<OutType>(x * y + z);
 
   // Extract mantissa and append hidden leading bits.
-  UInt128 x_mant = x_bits.get_explicit_mantissa();
-  UInt128 y_mant = y_bits.get_explicit_mantissa();
-  UInt128 z_mant = z_bits.get_explicit_mantissa();
+  InStorageType x_mant = x_bits.get_explicit_mantissa();
+  InStorageType y_mant = y_bits.get_explicit_mantissa();
+  TmpResultType z_mant = z_bits.get_explicit_mantissa();
 
   // If the exponent of the product x*y > the exponent of z, then no extra
   // precision beside the entire product x*y is needed.  On the other hand, when
@@ -143,22 +168,20 @@ template <> LIBC_INLINE double fma<double>(double x, double y, double z) {
   //      z :    10aa...a
   // - prod :     1bb...bb....b
   // In that case, in order to store the exact result, we need at least
-  //   (Length of prod) - (MantissaLength of z) = 2*(52 + 1) - 52 = 54.
+  //     (Length of prod) - (Fraction length of z)
+  //   = 2*(Length of input explicit mantissa) - (Fraction length of z) bits.
   // Overall, before aligning the mantissas and exponents, we can simply left-
-  // shift the mantissa of z by at least 54, and left-shift the product of x*y
-  // by (that amount - 52).  After that, it is enough to align the least
-  // significant bit, given that we keep track of the round and sticky bits
-  // after the least significant bit.
-  // We pick shifting z_mant by 64 bits so that technically we can simply use
-  // the original mantissa as high part when constructing 128-bit z_mant. So the
-  // mantissa of prod will be left-shifted by 64 - 54 = 10 initially.
-
-  UInt128 prod_mant = x_mant * y_mant << 10;
+  // shift the mantissa of z by that amount.  After that, it is enough to align
+  // the least significant bit, given that we keep track of the round and sticky
+  // bits after the least significant bit.
+
+  TmpResultType prod_mant = TmpResultType(x_mant) * y_mant;
   int prod_lsb_exp =
-      x_exp + y_exp - (FPBits::EXP_BIAS + 2 * FPBits::FRACTION_LEN + 10);
+      x_exp + y_exp - (InFPBits::EXP_BIAS + 2 * InFPBits::FRACTION_LEN);
 
-  z_mant <<= 64;
-  int z_lsb_exp = z_exp - (FPBits::FRACTION_LEN + 64);
+  constexpr int RESULT_MIN_LEN = PROD_LEN - InFPBits::FRACTION_LEN;
+  z_mant <<= RESULT_MIN_LEN;
+  int z_lsb_exp = z_exp - (InFPBits::FRACTION_LEN + RESULT_MIN_LEN);
   bool round_bit = false;
   bool sticky_bits = false;
   bool z_shifted = false;
@@ -198,46 +221,42 @@ template <> LIBC_INLINE double fma<double>(double x, double y, double z) {
     }
   }
 
-  uint64_t result = 0;
+  OutStorageType result = 0;
   int r_exp = 0; // Unbiased exponent of the result
 
+  int round_mode = fputil::quick_get_round();
+
   // Normalize the result.
   if (prod_mant != 0) {
-    uint64_t prod_hi = static_cast<uint64_t>(prod_mant >> 64);
-    int lead_zeros =
-        prod_hi ? cpp::countl_zero(prod_hi)
-                : 64 + cpp::countl_zero(static_cast<uint64_t>(prod_mant));
+    int lead_zeros = cpp::countl_zero(prod_mant);
     // Move the leading 1 to the most significant bit.
     prod_mant <<= lead_zeros;
-    // The lower 64 bits are always sticky bits after moving the leading 1 to
-    // the most significant bit.
-    sticky_bits |= (static_cast<uint64_t>(prod_mant) != 0);
-    result = static_cast<uint64_t>(prod_mant >> 64);
-    // Change prod_lsb_exp the be the exponent of the least significant bit of
-    // the result.
-    prod_lsb_exp += 64 - lead_zeros;
-    r_exp = prod_lsb_exp + 63;
+    prod_lsb_exp -= lead_zeros;
+    r_exp = prod_lsb_exp + (cpp::numeric_limits<TmpResultType>::digits - 1) -
+            InFPBits::EXP_BIAS + OutFPBits::EXP_BIAS;
 
     if (r_exp > 0) {
-      // The result is normal.  We will shift the mantissa to the right by
-      // 63 - 52 = 11 bits (from the locations of the most significant bit).
-      // Then the rounding bit will correspond the 11th bit, and the lowest
-      // 10 bits are merged into sticky bits.
-      round_bit = (result & 0x0400ULL) != 0;
-      sticky_bits |= (result & 0x03ffULL) != 0;
-      result >>= 11;
+      // The result is normal.  We will shift the mantissa to the right by the
+      // amount of extra bits compared to the length of the explicit mantissa in
+      // the output type.  The rounding bit then becomes the highest bit that is
+      // shifted out, and the following lower bits are merged into sticky bits.
+      round_bit =
+          (prod_mant & (TmpResultType(1) << (EXTRA_FRACTION_LEN - 1))) != 0;
+      sticky_bits |= (prod_mant & EXTRA_FRACTION_STICKY_MASK) != 0;
+      result = static_cast<OutStorageType>(prod_mant >> EXTRA_FRACTION_LEN);
     } else {
-      if (r_exp < -52) {
+      if (r_exp < -OutFPBits::FRACTION_LEN) {
         // The result is smaller than 1/2 of the smallest denormal number.
         sticky_bits = true; // since the result is non-zero.
         result = 0;
       } else {
         // The result is denormal.
-        uint64_t mask = 1ULL << (11 - r_exp);
-        round_bit = (result & mask) != 0;
-        sticky_bits |= (result & (mask - 1)) != 0;
-        if (r_exp > -52)
-          result >>= 12 - r_exp;
+        TmpResultType mask = TmpResultType(1) << (EXTRA_FRACTION_LEN - r_exp);
+        round_bit = (prod_mant & mask) != 0;
+        sticky_bits |= (prod_mant & (mask - 1)) != 0;
+        if (r_exp > -OutFPBits::FRACTION_LEN)
+          result = static_cast<OutStorageType>(
+              prod_mant >> (EXTRA_FRACTION_LEN + 1 - r_exp));
         else
           result = 0;
       }
@@ -245,27 +264,30 @@ template <> LIBC_INLINE double fma<double>(double x, double y, double z) {
       r_exp = 0;
     }
   } else {
-    // Return +0.0 when there is exact cancellation, i.e., x*y == -z exactly.
-    prod_sign = Sign::POS;
+    // When there is exact cancellation, i.e., x*y == -z exactly, return -0.0 if
+    // rounding downward and +0.0 for other rounding modes.
+    if (round_mode == FE_DOWNWARD)
+      prod_sign = Sign::NEG;
+    else
+      prod_sign = Sign::POS;
   }
 
   // Finalize the result.
-  int round_mode = fputil::quick_get_round();
-  if (LIBC_UNLIKELY(r_exp >= FPBits::MAX_BIASED_EXPONENT)) {
+  if (LIBC_UNLIKELY(r_exp >= OutFPBits::MAX_BIASED_EXPONENT)) {
     if ((round_mode == FE_TOWARDZERO) ||
         (round_mode == FE_UPWARD && prod_sign.is_neg()) ||
         (round_mode == FE_DOWNWARD && prod_sign.is_pos())) {
-      return FPBits::max_normal(prod_sign).get_val();
+      return OutFPBits::max_normal(prod_sign).get_val();
     }
-    return FPBits::inf(prod_sign).get_val();
+    return OutFPBits::inf(prod_sign).get_val();
   }
 
   // Remove hidden bit and append the exponent field and sign bit.
-  result = (result & FPBits::FRACTION_MASK) |
-           (static_cast<uint64_t>(r_exp) << FPBits::FRACTION_LEN);
-  if (prod_sign.is_neg()) {
-    result |= FPBits::SIGN_MASK;
-  }
+  result = static_cast<OutStorageType>(
+      (result & OutFPBits::FRACTION_MASK) |
+      (static_cast<OutStorageType>(r_exp) << OutFPBits::FRACTION_LEN));
+  if (prod_sign.is_neg())
+    result |= OutFPBits::SIGN_MASK;
 
   // Rounding.
   if (round_mode == FE_TONEAREST) {
@@ -277,7 +299,7 @@ template <> LIBC_INLINE double fma<double>(double x, double y, double z) {
       ++result;
   }
 
-  return cpp::bit_cast<double>(result);
+  return cpp::bit_cast<OutType>(result);
 }
 
 } // namespace generic
diff --git a/src/__support/FPUtil/generic/sqrt.h b/src/__support/FPUtil/generic/sqrt.h
index 7e7600b..d6e894f 100644
--- a/src/__support/FPUtil/generic/sqrt.h
+++ b/src/__support/FPUtil/generic/sqrt.h
@@ -18,6 +18,8 @@
 #include "src/__support/common.h"
 #include "src/__support/uint128.h"
 
+#include "hdr/fenv_macros.h"
+
 namespace LIBC_NAMESPACE {
 namespace fputil {
 
@@ -64,40 +66,50 @@ LIBC_INLINE void normalize<long double>(int &exponent, UInt128 &mantissa) {
 
 // Correctly rounded IEEE 754 SQRT for all rounding modes.
 // Shift-and-add algorithm.
-template <typename T>
-LIBC_INLINE cpp::enable_if_t<cpp::is_floating_point_v<T>, T> sqrt(T x) {
-
-  if constexpr (internal::SpecialLongDouble<T>::VALUE) {
+template <typename OutType, typename InType>
+LIBC_INLINE cpp::enable_if_t<cpp::is_floating_point_v<OutType> &&
+                                 cpp::is_floating_point_v<InType> &&
+                                 sizeof(OutType) <= sizeof(InType),
+                             OutType>
+sqrt(InType x) {
+  if constexpr (internal::SpecialLongDouble<OutType>::VALUE &&
+                internal::SpecialLongDouble<InType>::VALUE) {
     // Special 80-bit long double.
     return x86::sqrt(x);
   } else {
     // IEEE floating points formats.
-    using FPBits_t = typename fputil::FPBits<T>;
-    using StorageType = typename FPBits_t::StorageType;
-    constexpr StorageType ONE = StorageType(1) << FPBits_t::FRACTION_LEN;
-    constexpr auto FLT_NAN = FPBits_t::quiet_nan().get_val();
-
-    FPBits_t bits(x);
-
-    if (bits == FPBits_t::inf(Sign::POS) || bits.is_zero() || bits.is_nan()) {
+    using OutFPBits = typename fputil::FPBits<OutType>;
+    using OutStorageType = typename OutFPBits::StorageType;
+    using InFPBits = typename fputil::FPBits<InType>;
+    using InStorageType = typename InFPBits::StorageType;
+    constexpr InStorageType ONE = InStorageType(1) << InFPBits::FRACTION_LEN;
+    constexpr auto FLT_NAN = OutFPBits::quiet_nan().get_val();
+    constexpr int EXTRA_FRACTION_LEN =
+        InFPBits::FRACTION_LEN - OutFPBits::FRACTION_LEN;
+    constexpr InStorageType EXTRA_FRACTION_MASK =
+        (InStorageType(1) << EXTRA_FRACTION_LEN) - 1;
+
+    InFPBits bits(x);
+
+    if (bits == InFPBits::inf(Sign::POS) || bits.is_zero() || bits.is_nan()) {
       // sqrt(+Inf) = +Inf
       // sqrt(+0) = +0
       // sqrt(-0) = -0
       // sqrt(NaN) = NaN
       // sqrt(-NaN) = -NaN
-      return x;
+      return static_cast<OutType>(x);
     } else if (bits.is_neg()) {
       // sqrt(-Inf) = NaN
       // sqrt(-x) = NaN
       return FLT_NAN;
     } else {
       int x_exp = bits.get_exponent();
-      StorageType x_mant = bits.get_mantissa();
+      InStorageType x_mant = bits.get_mantissa();
 
       // Step 1a: Normalize denormal input and append hidden bit to the mantissa
       if (bits.is_subnormal()) {
         ++x_exp; // let x_exp be the correct exponent of ONE bit.
-        internal::normalize<T>(x_exp, x_mant);
+        internal::normalize<InType>(x_exp, x_mant);
       } else {
         x_mant |= ONE;
       }
@@ -120,12 +132,13 @@ LIBC_INLINE cpp::enable_if_t<cpp::is_floating_point_v<T>, T> sqrt(T x) {
       // So the nth digit y_n of the mantissa of sqrt(x) can be found by:
       //   y_n = 1 if 2*r(n-1) >= 2*y(n - 1) + 2^(-n-1)
       //         0 otherwise.
-      StorageType y = ONE;
-      StorageType r = x_mant - ONE;
+      InStorageType y = ONE;
+      InStorageType r = x_mant - ONE;
 
-      for (StorageType current_bit = ONE >> 1; current_bit; current_bit >>= 1) {
+      for (InStorageType current_bit = ONE >> 1; current_bit;
+           current_bit >>= 1) {
         r <<= 1;
-        StorageType tmp = (y << 1) + current_bit; // 2*y(n - 1) + 2^(-n-1)
+        InStorageType tmp = (y << 1) + current_bit; // 2*y(n - 1) + 2^(-n-1)
         if (r >= tmp) {
           r -= tmp;
           y += current_bit;
@@ -133,34 +146,91 @@ LIBC_INLINE cpp::enable_if_t<cpp::is_floating_point_v<T>, T> sqrt(T x) {
       }
 
       // We compute one more iteration in order to round correctly.
-      bool lsb = static_cast<bool>(y & 1); // Least significant bit
-      bool rb = false;                     // Round bit
+      bool lsb = (y & (InStorageType(1) << EXTRA_FRACTION_LEN)) !=
+                 0;    // Least significant bit
+      bool rb = false; // Round bit
       r <<= 2;
-      StorageType tmp = (y << 2) + 1;
+      InStorageType tmp = (y << 2) + 1;
       if (r >= tmp) {
         r -= tmp;
         rb = true;
       }
 
+      bool sticky = false;
+
+      if constexpr (EXTRA_FRACTION_LEN > 0) {
+        sticky = rb || (y & EXTRA_FRACTION_MASK) != 0;
+        rb = (y & (InStorageType(1) << (EXTRA_FRACTION_LEN - 1))) != 0;
+      }
+
       // Remove hidden bit and append the exponent field.
-      x_exp = ((x_exp >> 1) + FPBits_t::EXP_BIAS);
+      x_exp = ((x_exp >> 1) + OutFPBits::EXP_BIAS);
+
+      OutStorageType y_out = static_cast<OutStorageType>(
+          ((y - ONE) >> EXTRA_FRACTION_LEN) |
+          (static_cast<OutStorageType>(x_exp) << OutFPBits::FRACTION_LEN));
+
+      if constexpr (EXTRA_FRACTION_LEN > 0) {
+        if (x_exp >= OutFPBits::MAX_BIASED_EXPONENT) {
+          switch (quick_get_round()) {
+          case FE_TONEAREST:
+          case FE_UPWARD:
+            return OutFPBits::inf().get_val();
+          default:
+            return OutFPBits::max_normal().get_val();
+          }
+        }
+
+        if (x_exp <
+            -OutFPBits::EXP_BIAS - OutFPBits::SIG_LEN + EXTRA_FRACTION_LEN) {
+          switch (quick_get_round()) {
+          case FE_UPWARD:
+            return OutFPBits::min_subnormal().get_val();
+          default:
+            return OutType(0.0);
+          }
+        }
 
-      y = (y - ONE) |
-          (static_cast<StorageType>(x_exp) << FPBits_t::FRACTION_LEN);
+        if (x_exp <= 0) {
+          int underflow_extra_fraction_len = EXTRA_FRACTION_LEN - x_exp + 1;
+          InStorageType underflow_extra_fraction_mask =
+              (InStorageType(1) << underflow_extra_fraction_len) - 1;
+
+          rb = (y & (InStorageType(1) << (underflow_extra_fraction_len - 1))) !=
+               0;
+          OutStorageType subnormal_mant =
+              static_cast<OutStorageType>(y >> underflow_extra_fraction_len);
+          lsb = (subnormal_mant & 1) != 0;
+          sticky = sticky || (y & underflow_extra_fraction_mask) != 0;
+
+          switch (quick_get_round()) {
+          case FE_TONEAREST:
+            if (rb && (lsb || sticky))
+              ++subnormal_mant;
+            break;
+          case FE_UPWARD:
+            if (rb || sticky)
+              ++subnormal_mant;
+            break;
+          }
+
+          return cpp::bit_cast<OutType>(subnormal_mant);
+        }
+      }
 
       switch (quick_get_round()) {
       case FE_TONEAREST:
         // Round to nearest, ties to even
         if (rb && (lsb || (r != 0)))
-          ++y;
+          ++y_out;
         break;
       case FE_UPWARD:
-        if (rb || (r != 0))
-          ++y;
+        if (rb || (r != 0) || sticky)
+          ++y_out;
         break;
       }
 
-      return cpp::bit_cast<T>(y);
+      return cpp::bit_cast<OutType>(y_out);
     }
   }
 }
diff --git a/src/__support/FPUtil/multiply_add.h b/src/__support/FPUtil/multiply_add.h
index 82932da..622914e 100644
--- a/src/__support/FPUtil/multiply_add.h
+++ b/src/__support/FPUtil/multiply_add.h
@@ -45,11 +45,11 @@ namespace LIBC_NAMESPACE {
 namespace fputil {
 
 LIBC_INLINE float multiply_add(float x, float y, float z) {
-  return fma(x, y, z);
+  return fma<float>(x, y, z);
 }
 
 LIBC_INLINE double multiply_add(double x, double y, double z) {
-  return fma(x, y, z);
+  return fma<double>(x, y, z);
 }
 
 } // namespace fputil
diff --git a/src/__support/FPUtil/x86_64/FEnvImpl.h b/src/__support/FPUtil/x86_64/FEnvImpl.h
index a157b81..2aa6956 100644
--- a/src/__support/FPUtil/x86_64/FEnvImpl.h
+++ b/src/__support/FPUtil/x86_64/FEnvImpl.h
@@ -248,7 +248,7 @@ LIBC_INLINE int raise_except(int excepts) {
   // of the "Intel 64 and IA-32 Architectures Software Developer's
   // Manual, Vol 1".
 
-  // FPU status word is read for each exception seperately as the
+  // FPU status word is read for each exception separately as the
   // exception handler can potentially write to it (typically to clear
   // the corresponding exception flag). By reading it separately, we
   // ensure that the writes by the exception handler are maintained
diff --git a/src/__support/File/linux/file.cpp b/src/__support/File/linux/file.cpp
index b84da64..00ff938 100644
--- a/src/__support/File/linux/file.cpp
+++ b/src/__support/File/linux/file.cpp
@@ -8,10 +8,10 @@
 
 #include "file.h"
 
-#include "src/__support/File/file.h"
-
 #include "src/__support/CPP/new.h"
+#include "src/__support/File/file.h"
 #include "src/__support/File/linux/lseekImpl.h"
+#include "src/__support/OSUtil/fcntl.h"
 #include "src/__support/OSUtil/syscall.h" // For internal syscall function.
 #include "src/errno/libc_errno.h"         // For error macros
 
@@ -119,6 +119,60 @@ ErrorOr<File *> openfile(const char *path, const char *mode) {
   return file;
 }
 
+ErrorOr<LinuxFile *> create_file_from_fd(int fd, const char *mode) {
+  using ModeFlags = File::ModeFlags;
+  ModeFlags modeflags = File::mode_flags(mode);
+  if (modeflags == 0) {
+    return Error(EINVAL);
+  }
+
+  int fd_flags = internal::fcntl(fd, F_GETFL);
+  if (fd_flags == -1) {
+    return Error(EBADF);
+  }
+
+  using OpenMode = File::OpenMode;
+  if (((fd_flags & O_ACCMODE) == O_RDONLY &&
+       !(modeflags & static_cast<ModeFlags>(OpenMode::READ))) ||
+      ((fd_flags & O_ACCMODE) == O_WRONLY &&
+       !(modeflags & static_cast<ModeFlags>(OpenMode::WRITE)))) {
+    return Error(EINVAL);
+  }
+
+  bool do_seek = false;
+  if ((modeflags & static_cast<ModeFlags>(OpenMode::APPEND)) &&
+      !(fd_flags & O_APPEND)) {
+    do_seek = true;
+    if (internal::fcntl(fd, F_SETFL,
+                        reinterpret_cast<void *>(fd_flags | O_APPEND)) == -1) {
+      return Error(EBADF);
+    }
+  }
+
+  uint8_t *buffer;
+  {
+    AllocChecker ac;
+    buffer = new (ac) uint8_t[File::DEFAULT_BUFFER_SIZE];
+    if (!ac) {
+      return Error(ENOMEM);
+    }
+  }
+  AllocChecker ac;
+  auto *file = new (ac)
+      LinuxFile(fd, buffer, File::DEFAULT_BUFFER_SIZE, _IOFBF, true, modeflags);
+  if (!ac) {
+    return Error(ENOMEM);
+  }
+  if (do_seek) {
+    auto result = file->seek(0, SEEK_END);
+    if (!result.has_value()) {
+      free(file);
+      return Error(result.error());
+    }
+  }
+  return file;
+}
+
 int get_fileno(File *f) {
   auto *lf = reinterpret_cast<LinuxFile *>(f);
   return lf->get_fd();
diff --git a/src/__support/File/linux/file.h b/src/__support/File/linux/file.h
index 24e71b1..7d3770e 100644
--- a/src/__support/File/linux/file.h
+++ b/src/__support/File/linux/file.h
@@ -29,4 +29,7 @@ public:
   int get_fd() const { return fd; }
 };
 
+// Create a File object and associate it with a fd.
+ErrorOr<LinuxFile *> create_file_from_fd(int fd, const char *mode);
+
 } // namespace LIBC_NAMESPACE
diff --git a/src/__support/OSUtil/fcntl.h b/src/__support/OSUtil/fcntl.h
new file mode 100644
index 0000000..d934545
--- /dev/null
+++ b/src/__support/OSUtil/fcntl.h
@@ -0,0 +1,17 @@
+//===-- Implementation header of internal fcntl function ------------------===//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC___SUPPORT_OSUTIL_FCNTL_H
+#define LLVM_LIBC_SRC___SUPPORT_OSUTIL_FCNTL_H
+
+namespace LIBC_NAMESPACE::internal {
+
+int fcntl(int fd, int cmd, void *arg = nullptr);
+
+} // namespace LIBC_NAMESPACE::internal
+
+#endif // LLVM_LIBC_SRC___SUPPORT_OSUTIL_FCNTL_H
diff --git a/src/__support/OSUtil/linux/fcntl.cpp b/src/__support/OSUtil/linux/fcntl.cpp
new file mode 100644
index 0000000..b087f89
--- /dev/null
+++ b/src/__support/OSUtil/linux/fcntl.cpp
@@ -0,0 +1,94 @@
+//===-- Implementation of internal fcntl ----------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/__support/OSUtil/fcntl.h"
+
+#include "hdr/fcntl_macros.h"
+#include "hdr/types/struct_f_owner_ex.h"
+#include "hdr/types/struct_flock.h"
+#include "hdr/types/struct_flock64.h"
+#include "src/__support/OSUtil/syscall.h" // For internal syscall function.
+#include "src/__support/common.h"
+#include "src/errno/libc_errno.h"
+
+#include <stdarg.h>
+#include <sys/syscall.h> // For syscall numbers.
+
+namespace LIBC_NAMESPACE::internal {
+
+int fcntl(int fd, int cmd, void *arg) {
+  switch (cmd) {
+  case F_OFD_SETLKW: {
+    struct flock *flk = reinterpret_cast<struct flock *>(arg);
+    // convert the struct to a flock64
+    struct flock64 flk64;
+    flk64.l_type = flk->l_type;
+    flk64.l_whence = flk->l_whence;
+    flk64.l_start = flk->l_start;
+    flk64.l_len = flk->l_len;
+    flk64.l_pid = flk->l_pid;
+    // create a syscall
+    return LIBC_NAMESPACE::syscall_impl<int>(SYS_fcntl, fd, cmd, &flk64);
+  }
+  case F_OFD_GETLK:
+  case F_OFD_SETLK: {
+    struct flock *flk = reinterpret_cast<struct flock *>(arg);
+    // convert the struct to a flock64
+    struct flock64 flk64;
+    flk64.l_type = flk->l_type;
+    flk64.l_whence = flk->l_whence;
+    flk64.l_start = flk->l_start;
+    flk64.l_len = flk->l_len;
+    flk64.l_pid = flk->l_pid;
+    // create a syscall
+    int retVal = LIBC_NAMESPACE::syscall_impl<int>(SYS_fcntl, fd, cmd, &flk64);
+    // On failure, return
+    if (retVal == -1)
+      return -1;
+    // Check for overflow, i.e. the offsets are not the same when cast
+    // to off_t from off64_t.
+    if (static_cast<off_t>(flk64.l_len) != flk64.l_len ||
+        static_cast<off_t>(flk64.l_start) != flk64.l_start) {
+      libc_errno = EOVERFLOW;
+      return -1;
+    }
+    // Now copy back into flk, in case flk64 got modified
+    flk->l_type = flk64.l_type;
+    flk->l_whence = flk64.l_whence;
+    flk->l_start = static_cast<decltype(flk->l_start)>(flk64.l_start);
+    flk->l_len = static_cast<decltype(flk->l_len)>(flk64.l_len);
+    flk->l_pid = flk64.l_pid;
+    return retVal;
+  }
+  case F_GETOWN: {
+    struct f_owner_ex fex;
+    int retVal =
+        LIBC_NAMESPACE::syscall_impl<int>(SYS_fcntl, fd, F_GETOWN_EX, &fex);
+    if (retVal == -EINVAL)
+      return LIBC_NAMESPACE::syscall_impl<int>(SYS_fcntl, fd, cmd,
+                                               reinterpret_cast<void *>(arg));
+    if (static_cast<unsigned long>(retVal) <= -4096UL)
+      return fex.type == F_OWNER_PGRP ? -fex.pid : fex.pid;
+
+    libc_errno = -retVal;
+    return -1;
+  }
+  // The general case
+  default: {
+    int retVal = LIBC_NAMESPACE::syscall_impl<int>(
+        SYS_fcntl, fd, cmd, reinterpret_cast<void *>(arg));
+    if (retVal >= 0) {
+      return retVal;
+    }
+    libc_errno = -retVal;
+    return -1;
+  }
+  }
+}
+
+} // namespace LIBC_NAMESPACE::internal
diff --git a/src/__support/big_int.h b/src/__support/big_int.h
index e2061c4..5ce9541 100644
--- a/src/__support/big_int.h
+++ b/src/__support/big_int.h
@@ -299,9 +299,11 @@ LIBC_INLINE constexpr cpp::array<word, N> shift(cpp::array<word, N> array,
     if (bit_offset == 0)
       dst = part1; // no crosstalk between parts.
     else if constexpr (direction == LEFT)
-      dst = (part1 << bit_offset) | (part2 >> (WORD_BITS - bit_offset));
+      dst = static_cast<word>((part1 << bit_offset) |
+                              (part2 >> (WORD_BITS - bit_offset)));
     else
-      dst = (part1 >> bit_offset) | (part2 << (WORD_BITS - bit_offset));
+      dst = static_cast<word>((part1 >> bit_offset) |
+                              (part2 << (WORD_BITS - bit_offset)));
   }
   return out;
 }
@@ -969,7 +971,8 @@ struct WordTypeSelector : cpp::type_identity<
 #endif // LIBC_TYPES_HAS_INT64
                               > {
 };
-// Except if we request 32 bits explicitly.
+// Except if we request 16 or 32 bits explicitly.
+template <> struct WordTypeSelector<16> : cpp::type_identity<uint16_t> {};
 template <> struct WordTypeSelector<32> : cpp::type_identity<uint32_t> {};
 template <size_t Bits>
 using WordTypeSelectorT = typename WordTypeSelector<Bits>::type;
@@ -981,23 +984,18 @@ using UInt = BigInt<Bits, false, internal::WordTypeSelectorT<Bits>>;
 template <size_t Bits>
 using Int = BigInt<Bits, true, internal::WordTypeSelectorT<Bits>>;
 
-// Provides limits of U/Int<128>.
-template <> class cpp::numeric_limits<UInt<128>> {
-public:
-  LIBC_INLINE static constexpr UInt<128> max() { return UInt<128>::max(); }
-  LIBC_INLINE static constexpr UInt<128> min() { return UInt<128>::min(); }
-  // Meant to match std::numeric_limits interface.
-  // NOLINTNEXTLINE(readability-identifier-naming)
-  LIBC_INLINE_VAR static constexpr int digits = 128;
-};
-
-template <> class cpp::numeric_limits<Int<128>> {
-public:
-  LIBC_INLINE static constexpr Int<128> max() { return Int<128>::max(); }
-  LIBC_INLINE static constexpr Int<128> min() { return Int<128>::min(); }
+// Provides limits of BigInt.
+template <size_t Bits, bool Signed, typename T>
+struct cpp::numeric_limits<BigInt<Bits, Signed, T>> {
+  LIBC_INLINE static constexpr BigInt<Bits, Signed, T> max() {
+    return BigInt<Bits, Signed, T>::max();
+  }
+  LIBC_INLINE static constexpr BigInt<Bits, Signed, T> min() {
+    return BigInt<Bits, Signed, T>::min();
+  }
   // Meant to match std::numeric_limits interface.
   // NOLINTNEXTLINE(readability-identifier-naming)
-  LIBC_INLINE_VAR static constexpr int digits = 128;
+  LIBC_INLINE_VAR static constexpr int digits = Bits - Signed;
 };
 
 // type traits to determine whether a T is a BigInt.
@@ -1071,6 +1069,18 @@ template <typename T>
 using make_integral_or_big_int_signed_t =
     typename make_integral_or_big_int_signed<T>::type;
 
+// is_unsigned_integral_or_big_int
+template <typename T>
+struct is_unsigned_integral_or_big_int
+    : cpp::bool_constant<
+          cpp::is_same_v<T, make_integral_or_big_int_unsigned_t<T>>> {};
+
+template <typename T>
+// Meant to look like <type_traits> helper variable templates.
+// NOLINTNEXTLINE(readability-identifier-naming)
+LIBC_INLINE_VAR constexpr bool is_unsigned_integral_or_big_int_v =
+    is_unsigned_integral_or_big_int<T>::value;
+
 namespace cpp {
 
 // Specialization of cpp::bit_cast ('bit.h') from T to BigInt.
diff --git a/src/__support/block.h b/src/__support/block.h
new file mode 100644
index 0000000..580f20e
--- /dev/null
+++ b/src/__support/block.h
@@ -0,0 +1,484 @@
+//===-- Implementation header for a block of memory -------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC___SUPPORT_BLOCK_H
+#define LLVM_LIBC_SRC___SUPPORT_BLOCK_H
+
+#include "src/__support/CPP/algorithm.h"
+#include "src/__support/CPP/cstddef.h"
+#include "src/__support/CPP/limits.h"
+#include "src/__support/CPP/new.h"
+#include "src/__support/CPP/optional.h"
+#include "src/__support/CPP/span.h"
+#include "src/__support/CPP/type_traits.h"
+
+#include <stdint.h>
+
+namespace LIBC_NAMESPACE {
+
+namespace internal {
+// Types of corrupted blocks, and functions to crash with an error message
+// corresponding to each type.
+enum class BlockStatus {
+  VALID,
+  MISALIGNED,
+  PREV_MISMATCHED,
+  NEXT_MISMATCHED,
+};
+} // namespace internal
+
+/// Returns the value rounded down to the nearest multiple of alignment.
+LIBC_INLINE constexpr size_t align_down(size_t value, size_t alignment) {
+  // Note this shouldn't overflow since the result will always be <= value.
+  return (value / alignment) * alignment;
+}
+
+/// Returns the value rounded down to the nearest multiple of alignment.
+template <typename T>
+LIBC_INLINE constexpr T *align_down(T *value, size_t alignment) {
+  return reinterpret_cast<T *>(
+      align_down(reinterpret_cast<size_t>(value), alignment));
+}
+
+/// Returns the value rounded up to the nearest multiple of alignment.
+LIBC_INLINE constexpr size_t align_up(size_t value, size_t alignment) {
+  __builtin_add_overflow(value, alignment - 1, &value);
+  return align_down(value, alignment);
+}
+
+/// Returns the value rounded up to the nearest multiple of alignment.
+template <typename T>
+LIBC_INLINE constexpr T *align_up(T *value, size_t alignment) {
+  return reinterpret_cast<T *>(
+      align_up(reinterpret_cast<size_t>(value), alignment));
+}
+
+using ByteSpan = cpp::span<LIBC_NAMESPACE::cpp::byte>;
+using cpp::optional;
+
+/// Memory region with links to adjacent blocks.
+///
+/// The blocks do not encode their size directly. Instead, they encode offsets
+/// to the next and previous blocks using the type given by the `OffsetType`
+/// template parameter. The encoded offsets are simply the offsets divded by the
+/// minimum block alignment, `ALIGNMENT`.
+///
+/// The `ALIGNMENT` constant provided by the derived block is typically the
+/// minimum value of `alignof(OffsetType)`. Since the addressable range of a
+/// block is given by `std::numeric_limits<OffsetType>::max() *
+/// ALIGNMENT`, it may be advantageous to set a higher alignment if it allows
+/// using a smaller offset type, even if this wastes some bytes in order to
+/// align block headers.
+///
+/// Blocks will always be aligned to a `ALIGNMENT` boundary. Block sizes will
+/// always be rounded up to a multiple of `ALIGNMENT`.
+///
+/// As an example, the diagram below represents two contiguous
+/// `Block<uint32_t, 8>`s. The indices indicate byte offsets:
+///
+/// @code{.unparsed}
+/// Block 1:
+/// +---------------------+------+--------------+
+/// | Header              | Info | Usable space |
+/// +----------+----------+------+--------------+
+/// | prev     | next     |      |              |
+/// | 0......3 | 4......7 | 8..9 | 10.......280 |
+/// | 00000000 | 00000046 | 8008 |  <app data>  |
+/// +----------+----------+------+--------------+
+/// Block 2:
+/// +---------------------+------+--------------+
+/// | Header              | Info | Usable space |
+/// +----------+----------+------+--------------+
+/// | prev     | next     |      |              |
+/// | 0......3 | 4......7 | 8..9 | 10......1056 |
+/// | 00000046 | 00000106 | 2008 | f7f7....f7f7 |
+/// +----------+----------+------+--------------+
+/// @endcode
+///
+/// The overall size of the block (e.g. 280 bytes) is given by its next offset
+/// multiplied by the alignment (e.g. 0x106 * 4). Also, the next offset of a
+/// block matches the previous offset of its next block. The first block in a
+/// list is denoted by having a previous offset of `0`.
+///
+/// @tparam   OffsetType  Unsigned integral type used to encode offsets. Larger
+///                       types can address more memory, but consume greater
+///                       overhead.
+/// @tparam   kAlign      Sets the overall alignment for blocks. Minimum is
+///                       `alignof(OffsetType)` (the default). Larger values can
+///                       address more memory, but consume greater overhead.
+template <typename OffsetType = uintptr_t, size_t kAlign = alignof(OffsetType)>
+class Block {
+public:
+  using offset_type = OffsetType;
+  static_assert(cpp::is_unsigned_v<offset_type>,
+                "offset type must be unsigned");
+
+  static constexpr size_t ALIGNMENT = cpp::max(kAlign, alignof(offset_type));
+  static constexpr size_t BLOCK_OVERHEAD = align_up(sizeof(Block), ALIGNMENT);
+
+  // No copy or move.
+  Block(const Block &other) = delete;
+  Block &operator=(const Block &other) = delete;
+
+  /// Creates the first block for a given memory region.
+  static optional<Block *> init(ByteSpan region);
+
+  /// @returns  A pointer to a `Block`, given a pointer to the start of the
+  ///           usable space inside the block.
+  ///
+  /// This is the inverse of `usable_space()`.
+  ///
+  /// @warning  This method does not do any checking; passing a random
+  ///           pointer will return a non-null pointer.
+  static Block *from_usable_space(void *usable_space) {
+    auto *bytes = reinterpret_cast<cpp::byte *>(usable_space);
+    return reinterpret_cast<Block *>(bytes - BLOCK_OVERHEAD);
+  }
+  static const Block *from_usable_space(const void *usable_space) {
+    const auto *bytes = reinterpret_cast<const cpp::byte *>(usable_space);
+    return reinterpret_cast<const Block *>(bytes - BLOCK_OVERHEAD);
+  }
+
+  /// @returns The total size of the block in bytes, including the header.
+  size_t outer_size() const { return next_ * ALIGNMENT; }
+
+  /// @returns The number of usable bytes inside the block.
+  size_t inner_size() const { return outer_size() - BLOCK_OVERHEAD; }
+
+  /// @returns The number of bytes requested using AllocFirst or AllocLast.
+  size_t requested_size() const { return inner_size() - padding_; }
+
+  /// @returns A pointer to the usable space inside this block.
+  cpp::byte *usable_space() {
+    return reinterpret_cast<cpp::byte *>(this) + BLOCK_OVERHEAD;
+  }
+  const cpp::byte *usable_space() const {
+    return reinterpret_cast<const cpp::byte *>(this) + BLOCK_OVERHEAD;
+  }
+
+  /// Marks the block as free and merges it with any free neighbors.
+  ///
+  /// This method is static in order to consume and replace the given block
+  /// pointer. If neither member is free, the returned pointer will point to the
+  /// original block. Otherwise, it will point to the new, larger block created
+  /// by merging adjacent free blocks together.
+  static void free(Block *&block);
+
+  /// Attempts to split this block.
+  ///
+  /// If successful, the block will have an inner size of `new_inner_size`,
+  /// rounded up to a `ALIGNMENT` boundary. The remaining space will be
+  /// returned as a new block.
+  ///
+  /// This method may fail if the remaining space is too small to hold a new
+  /// block. If this method fails for any reason, the original block is
+  /// unmodified.
+  ///
+  /// This method is static in order to consume and replace the given block
+  /// pointer with a pointer to the new, smaller block.
+  static optional<Block *> split(Block *&block, size_t new_inner_size);
+
+  /// Merges this block with the one that comes after it.
+  ///
+  /// This method is static in order to consume and replace the given block
+  /// pointer with a pointer to the new, larger block.
+  static bool merge_next(Block *&block);
+
+  /// Fetches the block immediately after this one.
+  ///
+  /// For performance, this always returns a block pointer, even if the returned
+  /// pointer is invalid. The pointer is valid if and only if `last()` is false.
+  ///
+  /// Typically, after calling `Init` callers may save a pointer past the end of
+  /// the list using `next()`. This makes it easy to subsequently iterate over
+  /// the list:
+  /// @code{.cpp}
+  ///   auto result = Block<>::init(byte_span);
+  ///   Block<>* begin = *result;
+  ///   Block<>* end = begin->next();
+  ///   ...
+  ///   for (auto* block = begin; block != end; block = block->next()) {
+  ///     // Do something which each block.
+  ///   }
+  /// @endcode
+  Block *next() const;
+
+  /// @copydoc `next`.
+  static Block *next_block(const Block *block) {
+    return block == nullptr ? nullptr : block->next();
+  }
+
+  /// @returns The block immediately before this one, or a null pointer if this
+  /// is the first block.
+  Block *prev() const;
+
+  /// @copydoc `prev`.
+  static Block *prev_block(const Block *block) {
+    return block == nullptr ? nullptr : block->prev();
+  }
+
+  /// Returns the current alignment of a block.
+  size_t alignment() const { return used() ? info_.alignment : 1; }
+
+  /// Indicates whether the block is in use.
+  ///
+  /// @returns `true` if the block is in use or `false` if not.
+  bool used() const { return info_.used; }
+
+  /// Indicates whether this block is the last block or not (i.e. whether
+  /// `next()` points to a valid block or not). This is needed because
+  /// `next()` points to the end of this block, whether there is a valid
+  /// block there or not.
+  ///
+  /// @returns `true` is this is the last block or `false` if not.
+  bool last() const { return info_.last; }
+
+  /// Marks this block as in use.
+  void mark_used() { info_.used = 1; }
+
+  /// Marks this block as free.
+  void mark_free() { info_.used = 0; }
+
+  /// Marks this block as the last one in the chain.
+  constexpr void mark_last() { info_.last = 1; }
+
+  /// Clears the last bit from this block.
+  void clear_last() { info_.last = 1; }
+
+  /// @brief Checks if a block is valid.
+  ///
+  /// @returns `true` if and only if the following conditions are met:
+  /// * The block is aligned.
+  /// * The prev/next fields match with the previous and next blocks.
+  bool is_valid() const {
+    return check_status() == internal::BlockStatus::VALID;
+  }
+
+  constexpr Block(size_t prev_outer_size, size_t outer_size);
+
+private:
+  /// Consumes the block and returns as a span of bytes.
+  static ByteSpan as_bytes(Block *&&block);
+
+  /// Consumes the span of bytes and uses it to construct and return a block.
+  static Block *as_block(size_t prev_outer_size, ByteSpan bytes);
+
+  /// Returns a `BlockStatus` that is either VALID or indicates the reason why
+  /// the block is invalid.
+  ///
+  /// If the block is invalid at multiple points, this function will only return
+  /// one of the reasons.
+  internal::BlockStatus check_status() const;
+
+  /// Like `split`, but assumes the caller has already checked to parameters to
+  /// ensure the split will succeed.
+  static Block *split_impl(Block *&block, size_t new_inner_size);
+
+  /// Offset (in increments of the minimum alignment) from this block to the
+  /// previous block. 0 if this is the first block.
+  offset_type prev_ = 0;
+
+  /// Offset (in increments of the minimum alignment) from this block to the
+  /// next block. Valid even if this is the last block, since it equals the
+  /// size of the block.
+  offset_type next_ = 0;
+
+  /// Information about the current state of the block:
+  /// * If the `used` flag is set, the block's usable memory has been allocated
+  ///   and is being used.
+  /// * If the `last` flag is set, the block does not have a next block.
+  /// * If the `used` flag is set, the alignment represents the requested value
+  ///   when the memory was allocated, which may be less strict than the actual
+  ///   alignment.
+  struct {
+    uint16_t used : 1;
+    uint16_t last : 1;
+    uint16_t alignment : 14;
+  } info_;
+
+  /// Number of bytes allocated beyond what was requested. This will be at most
+  /// the minimum alignment, i.e. `alignof(offset_type).`
+  uint16_t padding_ = 0;
+} __attribute__((packed, aligned(kAlign)));
+
+// Public template method implementations.
+
+LIBC_INLINE ByteSpan get_aligned_subspan(ByteSpan bytes, size_t alignment) {
+  if (bytes.data() == nullptr)
+    return ByteSpan();
+
+  auto unaligned_start = reinterpret_cast<uintptr_t>(bytes.data());
+  auto aligned_start = align_up(unaligned_start, alignment);
+  auto unaligned_end = unaligned_start + bytes.size();
+  auto aligned_end = align_down(unaligned_end, alignment);
+
+  if (aligned_end <= aligned_start)
+    return ByteSpan();
+
+  return bytes.subspan(aligned_start - unaligned_start,
+                       aligned_end - aligned_start);
+}
+
+template <typename OffsetType, size_t kAlign>
+optional<Block<OffsetType, kAlign> *>
+Block<OffsetType, kAlign>::init(ByteSpan region) {
+  optional<ByteSpan> result = get_aligned_subspan(region, ALIGNMENT);
+  if (!result)
+    return {};
+
+  region = result.value();
+  if (region.size() < BLOCK_OVERHEAD)
+    return {};
+
+  if (cpp::numeric_limits<OffsetType>::max() < region.size() / ALIGNMENT)
+    return {};
+
+  Block *block = as_block(0, region);
+  block->mark_last();
+  return block;
+}
+
+template <typename OffsetType, size_t kAlign>
+void Block<OffsetType, kAlign>::free(Block *&block) {
+  if (block == nullptr)
+    return;
+
+  block->mark_free();
+  Block *prev = block->prev();
+
+  if (merge_next(prev))
+    block = prev;
+
+  merge_next(block);
+}
+
+template <typename OffsetType, size_t kAlign>
+optional<Block<OffsetType, kAlign> *>
+Block<OffsetType, kAlign>::split(Block *&block, size_t new_inner_size) {
+  if (block == nullptr)
+    return {};
+
+  if (block->used())
+    return {};
+
+  size_t old_inner_size = block->inner_size();
+  new_inner_size = align_up(new_inner_size, ALIGNMENT);
+  if (old_inner_size < new_inner_size)
+    return {};
+
+  if (old_inner_size - new_inner_size < BLOCK_OVERHEAD)
+    return {};
+
+  return split_impl(block, new_inner_size);
+}
+
+template <typename OffsetType, size_t kAlign>
+Block<OffsetType, kAlign> *
+Block<OffsetType, kAlign>::split_impl(Block *&block, size_t new_inner_size) {
+  size_t prev_outer_size = block->prev_ * ALIGNMENT;
+  size_t outer_size1 = new_inner_size + BLOCK_OVERHEAD;
+  bool is_last = block->last();
+  ByteSpan bytes = as_bytes(cpp::move(block));
+  Block *block1 = as_block(prev_outer_size, bytes.subspan(0, outer_size1));
+  Block *block2 = as_block(outer_size1, bytes.subspan(outer_size1));
+
+  if (is_last)
+    block2->mark_last();
+  else
+    block2->next()->prev_ = block2->next_;
+
+  block = cpp::move(block1);
+  return block2;
+}
+
+template <typename OffsetType, size_t kAlign>
+bool Block<OffsetType, kAlign>::merge_next(Block *&block) {
+  if (block == nullptr)
+    return false;
+
+  if (block->last())
+    return false;
+
+  Block *next = block->next();
+  if (block->used() || next->used())
+    return false;
+
+  size_t prev_outer_size = block->prev_ * ALIGNMENT;
+  bool is_last = next->last();
+  ByteSpan prev_bytes = as_bytes(cpp::move(block));
+  ByteSpan next_bytes = as_bytes(cpp::move(next));
+  size_t outer_size = prev_bytes.size() + next_bytes.size();
+  cpp::byte *merged = ::new (prev_bytes.data()) cpp::byte[outer_size];
+  block = as_block(prev_outer_size, ByteSpan(merged, outer_size));
+
+  if (is_last)
+    block->mark_last();
+  else
+    block->next()->prev_ = block->next_;
+
+  return true;
+}
+
+template <typename OffsetType, size_t kAlign>
+Block<OffsetType, kAlign> *Block<OffsetType, kAlign>::next() const {
+  uintptr_t addr =
+      last() ? 0 : reinterpret_cast<uintptr_t>(this) + outer_size();
+  return reinterpret_cast<Block *>(addr);
+}
+
+template <typename OffsetType, size_t kAlign>
+Block<OffsetType, kAlign> *Block<OffsetType, kAlign>::prev() const {
+  uintptr_t addr =
+      (prev_ == 0) ? 0
+                   : reinterpret_cast<uintptr_t>(this) - (prev_ * ALIGNMENT);
+  return reinterpret_cast<Block *>(addr);
+}
+
+// Private template method implementations.
+
+template <typename OffsetType, size_t kAlign>
+constexpr Block<OffsetType, kAlign>::Block(size_t prev_outer_size,
+                                           size_t outer_size)
+    : info_{} {
+  prev_ = prev_outer_size / ALIGNMENT;
+  next_ = outer_size / ALIGNMENT;
+  info_.used = 0;
+  info_.last = 0;
+  info_.alignment = ALIGNMENT;
+}
+
+template <typename OffsetType, size_t kAlign>
+ByteSpan Block<OffsetType, kAlign>::as_bytes(Block *&&block) {
+  size_t block_size = block->outer_size();
+  cpp::byte *bytes = new (cpp::move(block)) cpp::byte[block_size];
+  return {bytes, block_size};
+}
+
+template <typename OffsetType, size_t kAlign>
+Block<OffsetType, kAlign> *
+Block<OffsetType, kAlign>::as_block(size_t prev_outer_size, ByteSpan bytes) {
+  return ::new (bytes.data()) Block(prev_outer_size, bytes.size());
+}
+
+template <typename OffsetType, size_t kAlign>
+internal::BlockStatus Block<OffsetType, kAlign>::check_status() const {
+  if (reinterpret_cast<uintptr_t>(this) % ALIGNMENT != 0)
+    return internal::BlockStatus::MISALIGNED;
+
+  if (!last() && (this >= next() || this != next()->prev()))
+    return internal::BlockStatus::NEXT_MISMATCHED;
+
+  if (prev() && (this <= prev() || this != prev()->next()))
+    return internal::BlockStatus::PREV_MISMATCHED;
+
+  return internal::BlockStatus::VALID;
+}
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC___SUPPORT_BLOCK_H
diff --git a/src/__support/blockstore.h b/src/__support/blockstore.h
index ac0eb22..bcab750 100644
--- a/src/__support/blockstore.h
+++ b/src/__support/blockstore.h
@@ -44,7 +44,7 @@ protected:
   struct Pair {
     Block *first, *second;
   };
-  Pair get_last_blocks() {
+  LIBC_INLINE Pair get_last_blocks() {
     if (REVERSE_ORDER)
       return {current, current->next};
     Block *prev = nullptr;
@@ -55,20 +55,20 @@ protected:
     return {curr, prev};
   }
 
-  Block *get_last_block() { return get_last_blocks().first; }
+  LIBC_INLINE Block *get_last_block() { return get_last_blocks().first; }
 
 public:
-  constexpr BlockStore() = default;
-  ~BlockStore() = default;
+  LIBC_INLINE constexpr BlockStore() = default;
+  LIBC_INLINE ~BlockStore() = default;
 
   class Iterator {
     Block *block;
     size_t index;
 
   public:
-    constexpr Iterator(Block *b, size_t i) : block(b), index(i) {}
+    LIBC_INLINE constexpr Iterator(Block *b, size_t i) : block(b), index(i) {}
 
-    Iterator &operator++() {
+    LIBC_INLINE Iterator &operator++() {
       if (REVERSE_ORDER) {
         if (index == 0)
           return *this;
@@ -92,23 +92,24 @@ public:
       return *this;
     }
 
-    T &operator*() {
+    LIBC_INLINE T &operator*() {
       size_t true_index = REVERSE_ORDER ? index - 1 : index;
       return *reinterpret_cast<T *>(block->data + sizeof(T) * true_index);
     }
 
-    bool operator==(const Iterator &rhs) const {
+    LIBC_INLINE bool operator==(const Iterator &rhs) const {
       return block == rhs.block && index == rhs.index;
     }
 
-    bool operator!=(const Iterator &rhs) const {
+    LIBC_INLINE bool operator!=(const Iterator &rhs) const {
       return block != rhs.block || index != rhs.index;
     }
   };
 
-  static void destroy(BlockStore<T, BLOCK_SIZE, REVERSE_ORDER> *block_store);
+  LIBC_INLINE static void
+  destroy(BlockStore<T, BLOCK_SIZE, REVERSE_ORDER> *block_store);
 
-  T *new_obj() {
+  LIBC_INLINE T *new_obj() {
     if (fill_count == BLOCK_SIZE) {
       AllocChecker ac;
       auto new_block = new (ac) Block();
@@ -128,7 +129,7 @@ public:
     return obj;
   }
 
-  [[nodiscard]] bool push_back(const T &value) {
+  [[nodiscard]] LIBC_INLINE bool push_back(const T &value) {
     T *ptr = new_obj();
     if (ptr == nullptr)
       return false;
@@ -136,12 +137,12 @@ public:
     return true;
   }
 
-  T &back() {
+  LIBC_INLINE T &back() {
     return *reinterpret_cast<T *>(get_last_block()->data +
                                   sizeof(T) * (fill_count - 1));
   }
 
-  void pop_back() {
+  LIBC_INLINE void pop_back() {
     fill_count--;
     if (fill_count || current == &first)
       return;
@@ -159,16 +160,16 @@ public:
     fill_count = BLOCK_SIZE;
   }
 
-  bool empty() const { return current == &first && !fill_count; }
+  LIBC_INLINE bool empty() const { return current == &first && !fill_count; }
 
-  Iterator begin() {
+  LIBC_INLINE Iterator begin() {
     if (REVERSE_ORDER)
       return Iterator(current, fill_count);
     else
       return Iterator(&first, 0);
   }
 
-  Iterator end() {
+  LIBC_INLINE Iterator end() {
     if (REVERSE_ORDER)
       return Iterator(&first, 0);
     else
@@ -177,7 +178,7 @@ public:
 };
 
 template <typename T, size_t BLOCK_SIZE, bool REVERSE_ORDER>
-void BlockStore<T, BLOCK_SIZE, REVERSE_ORDER>::destroy(
+LIBC_INLINE void BlockStore<T, BLOCK_SIZE, REVERSE_ORDER>::destroy(
     BlockStore<T, BLOCK_SIZE, REVERSE_ORDER> *block_store) {
   if (REVERSE_ORDER) {
     auto current = block_store->current;
diff --git a/src/__support/fixedvector.h b/src/__support/fixedvector.h
index ddd0993..403b162 100644
--- a/src/__support/fixedvector.h
+++ b/src/__support/fixedvector.h
@@ -25,17 +25,24 @@ public:
   constexpr FixedVector() = default;
 
   using iterator = typename cpp::array<T, CAPACITY>::iterator;
-  constexpr FixedVector(iterator begin, iterator end) {
+  constexpr FixedVector(iterator begin, iterator end) : store{}, item_count{} {
     for (; begin != end; ++begin)
       push_back(*begin);
   }
 
-  constexpr FixedVector(size_t count, const T &value) {
+  using const_iterator = typename cpp::array<T, CAPACITY>::const_iterator;
+  constexpr FixedVector(const_iterator begin, const_iterator end)
+      : store{}, item_count{} {
+    for (; begin != end; ++begin)
+      push_back(*begin);
+  }
+
+  constexpr FixedVector(size_t count, const T &value) : store{}, item_count{} {
     for (size_t i = 0; i < count; ++i)
       push_back(value);
   }
 
-  bool push_back(const T &obj) {
+  constexpr bool push_back(const T &obj) {
     if (item_count == CAPACITY)
       return false;
     store[item_count] = obj;
@@ -43,27 +50,27 @@ public:
     return true;
   }
 
-  const T &back() const { return store[item_count - 1]; }
+  constexpr const T &back() const { return store[item_count - 1]; }
 
-  T &back() { return store[item_count - 1]; }
+  constexpr T &back() { return store[item_count - 1]; }
 
-  bool pop_back() {
+  constexpr bool pop_back() {
     if (item_count == 0)
       return false;
     --item_count;
     return true;
   }
 
-  T &operator[](size_t idx) { return store[idx]; }
+  constexpr T &operator[](size_t idx) { return store[idx]; }
 
-  const T &operator[](size_t idx) const { return store[idx]; }
+  constexpr const T &operator[](size_t idx) const { return store[idx]; }
 
-  bool empty() const { return item_count == 0; }
+  constexpr bool empty() const { return item_count == 0; }
 
-  size_t size() const { return item_count; }
+  constexpr size_t size() const { return item_count; }
 
   // Empties the store for all practical purposes.
-  void reset() { item_count = 0; }
+  constexpr void reset() { item_count = 0; }
 
   // This static method does not free up the resources held by |store|,
   // say by calling `free` or something similar. It just does the equivalent
diff --git a/src/__support/freelist.h b/src/__support/freelist.h
new file mode 100644
index 0000000..0641ba9
--- /dev/null
+++ b/src/__support/freelist.h
@@ -0,0 +1,190 @@
+//===-- Interface for freelist_malloc -------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC___SUPPORT_FREELIST_H
+#define LLVM_LIBC_SRC___SUPPORT_FREELIST_H
+
+#include "src/__support/CPP/array.h"
+#include "src/__support/CPP/cstddef.h"
+#include "src/__support/CPP/new.h"
+#include "src/__support/CPP/span.h"
+#include "src/__support/fixedvector.h"
+
+namespace LIBC_NAMESPACE {
+
+using cpp::span;
+
+/// Basic [freelist](https://en.wikipedia.org/wiki/Free_list) implementation
+/// for an allocator. This implementation buckets by chunk size, with a list
+/// of user-provided buckets. Each bucket is a linked list of storage chunks.
+/// Because this freelist uses the added chunks themselves as list nodes, there
+/// is a lower bound of `sizeof(FreeList.FreeListNode)` bytes for chunks which
+/// can be added to this freelist. There is also an implicit bucket for
+/// "everything else", for chunks which do not fit into a bucket.
+///
+/// Each added chunk will be added to the smallest bucket under which it fits.
+/// If it does not fit into any user-provided bucket, it will be added to the
+/// default bucket.
+///
+/// As an example, assume that the `FreeList` is configured with buckets of
+/// sizes {64, 128, 256, and 512} bytes. The internal state may look like the
+/// following:
+///
+/// @code{.unparsed}
+/// bucket[0] (64B) --> chunk[12B] --> chunk[42B] --> chunk[64B] --> NULL
+/// bucket[1] (128B) --> chunk[65B] --> chunk[72B] --> NULL
+/// bucket[2] (256B) --> NULL
+/// bucket[3] (512B) --> chunk[312B] --> chunk[512B] --> chunk[416B] --> NULL
+/// bucket[4] (implicit) --> chunk[1024B] --> chunk[513B] --> NULL
+/// @endcode
+///
+/// Note that added chunks should be aligned to a 4-byte boundary.
+template <size_t NUM_BUCKETS = 6> class FreeList {
+public:
+  // Remove copy/move ctors
+  FreeList(const FreeList &other) = delete;
+  FreeList(FreeList &&other) = delete;
+  FreeList &operator=(const FreeList &other) = delete;
+  FreeList &operator=(FreeList &&other) = delete;
+
+  /// Adds a chunk to this freelist.
+  bool add_chunk(cpp::span<cpp::byte> chunk);
+
+  /// Finds an eligible chunk for an allocation of size `size`.
+  ///
+  /// @note This returns the first allocation possible within a given bucket;
+  /// It does not currently optimize for finding the smallest chunk.
+  ///
+  /// @returns
+  /// * On success - A span representing the chunk.
+  /// * On failure (e.g. there were no chunks available for that allocation) -
+  ///   A span with a size of 0.
+  cpp::span<cpp::byte> find_chunk(size_t size) const;
+
+  /// Removes a chunk from this freelist.
+  bool remove_chunk(cpp::span<cpp::byte> chunk);
+
+  /// For a given size, find which index into chunks_ the node should be written
+  /// to.
+  constexpr size_t find_chunk_ptr_for_size(size_t size, bool non_null) const;
+
+  struct FreeListNode {
+    FreeListNode *next;
+    size_t size;
+  };
+
+  constexpr void set_freelist_node(FreeListNode &node,
+                                   cpp::span<cpp::byte> chunk);
+
+  constexpr explicit FreeList(const cpp::array<size_t, NUM_BUCKETS> &sizes)
+      : chunks_(NUM_BUCKETS + 1, 0), sizes_(sizes.begin(), sizes.end()) {}
+
+private:
+  FixedVector<FreeList::FreeListNode *, NUM_BUCKETS + 1> chunks_;
+  FixedVector<size_t, NUM_BUCKETS> sizes_;
+};
+
+template <size_t NUM_BUCKETS>
+constexpr void FreeList<NUM_BUCKETS>::set_freelist_node(FreeListNode &node,
+                                                        span<cpp::byte> chunk) {
+  // Add it to the correct list.
+  size_t chunk_ptr = find_chunk_ptr_for_size(chunk.size(), false);
+  node.size = chunk.size();
+  node.next = chunks_[chunk_ptr];
+  chunks_[chunk_ptr] = &node;
+}
+
+template <size_t NUM_BUCKETS>
+bool FreeList<NUM_BUCKETS>::add_chunk(span<cpp::byte> chunk) {
+  // Check that the size is enough to actually store what we need
+  if (chunk.size() < sizeof(FreeListNode))
+    return false;
+
+  FreeListNode *node = ::new (chunk.data()) FreeListNode;
+  set_freelist_node(*node, chunk);
+
+  return true;
+}
+
+template <size_t NUM_BUCKETS>
+span<cpp::byte> FreeList<NUM_BUCKETS>::find_chunk(size_t size) const {
+  if (size == 0)
+    return span<cpp::byte>();
+
+  size_t chunk_ptr = find_chunk_ptr_for_size(size, true);
+
+  // Check that there's data. This catches the case where we run off the
+  // end of the array
+  if (chunks_[chunk_ptr] == nullptr)
+    return span<cpp::byte>();
+
+  // Now iterate up the buckets, walking each list to find a good candidate
+  for (size_t i = chunk_ptr; i < chunks_.size(); i++) {
+    FreeListNode *node = chunks_[static_cast<unsigned short>(i)];
+
+    while (node != nullptr) {
+      if (node->size >= size)
+        return span<cpp::byte>(reinterpret_cast<cpp::byte *>(node), node->size);
+
+      node = node->next;
+    }
+  }
+
+  // If we get here, we've checked every block in every bucket. There's
+  // nothing that can support this allocation.
+  return span<cpp::byte>();
+}
+
+template <size_t NUM_BUCKETS>
+bool FreeList<NUM_BUCKETS>::remove_chunk(span<cpp::byte> chunk) {
+  size_t chunk_ptr = find_chunk_ptr_for_size(chunk.size(), true);
+
+  // Check head first.
+  if (chunks_[chunk_ptr] == nullptr)
+    return false;
+
+  FreeListNode *node = chunks_[chunk_ptr];
+  if (reinterpret_cast<cpp::byte *>(node) == chunk.data()) {
+    chunks_[chunk_ptr] = node->next;
+    return true;
+  }
+
+  // No? Walk the nodes.
+  node = chunks_[chunk_ptr];
+
+  while (node->next != nullptr) {
+    if (reinterpret_cast<cpp::byte *>(node->next) == chunk.data()) {
+      // Found it, remove this node out of the chain
+      node->next = node->next->next;
+      return true;
+    }
+
+    node = node->next;
+  }
+
+  return false;
+}
+
+template <size_t NUM_BUCKETS>
+constexpr size_t
+FreeList<NUM_BUCKETS>::find_chunk_ptr_for_size(size_t size,
+                                               bool non_null) const {
+  size_t chunk_ptr = 0;
+  for (chunk_ptr = 0u; chunk_ptr < sizes_.size(); chunk_ptr++) {
+    if (sizes_[chunk_ptr] >= size &&
+        (!non_null || chunks_[chunk_ptr] != nullptr)) {
+      break;
+    }
+  }
+
+  return chunk_ptr;
+}
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC___SUPPORT_FREELIST_H
diff --git a/src/__support/freelist_heap.h b/src/__support/freelist_heap.h
new file mode 100644
index 0000000..3569baf
--- /dev/null
+++ b/src/__support/freelist_heap.h
@@ -0,0 +1,223 @@
+//===-- Interface for freelist_heap ---------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC___SUPPORT_FREELIST_HEAP_H
+#define LLVM_LIBC_SRC___SUPPORT_FREELIST_HEAP_H
+
+#include <stddef.h>
+
+#include "block.h"
+#include "freelist.h"
+#include "src/__support/CPP/optional.h"
+#include "src/__support/CPP/span.h"
+#include "src/__support/libc_assert.h"
+#include "src/string/memory_utils/inline_memcpy.h"
+#include "src/string/memory_utils/inline_memset.h"
+
+namespace LIBC_NAMESPACE {
+
+using cpp::optional;
+using cpp::span;
+
+static constexpr cpp::array<size_t, 6> DEFAULT_BUCKETS{16,  32,  64,
+                                                       128, 256, 512};
+
+template <size_t NUM_BUCKETS = DEFAULT_BUCKETS.size()> class FreeListHeap {
+public:
+  using BlockType = Block<>;
+  using FreeListType = FreeList<NUM_BUCKETS>;
+
+  struct HeapStats {
+    size_t total_bytes;
+    size_t bytes_allocated;
+    size_t cumulative_allocated;
+    size_t cumulative_freed;
+    size_t total_allocate_calls;
+    size_t total_free_calls;
+  };
+
+  FreeListHeap(span<cpp::byte> region)
+      : FreeListHeap(&*region.begin(), &*region.end(), region.size()) {
+    auto result = BlockType::init(region);
+    BlockType *block = *result;
+    freelist_.add_chunk(block_to_span(block));
+  }
+
+  constexpr FreeListHeap(void *start, cpp::byte *end, size_t total_bytes)
+      : block_region_start_(start), block_region_end_(end),
+        freelist_(DEFAULT_BUCKETS), heap_stats_{} {
+    heap_stats_.total_bytes = total_bytes;
+  }
+
+  void *allocate(size_t size);
+  void free(void *ptr);
+  void *realloc(void *ptr, size_t size);
+  void *calloc(size_t num, size_t size);
+
+  const HeapStats &heap_stats() const { return heap_stats_; }
+  void reset_heap_stats() { heap_stats_ = {}; }
+
+  void *region_start() const { return block_region_start_; }
+  size_t region_size() const {
+    return reinterpret_cast<uintptr_t>(block_region_end_) -
+           reinterpret_cast<uintptr_t>(block_region_start_);
+  }
+
+protected:
+  constexpr void set_freelist_node(typename FreeListType::FreeListNode &node,
+                                   cpp::span<cpp::byte> chunk) {
+    freelist_.set_freelist_node(node, chunk);
+  }
+
+private:
+  span<cpp::byte> block_to_span(BlockType *block) {
+    return span<cpp::byte>(block->usable_space(), block->inner_size());
+  }
+
+  bool is_valid_ptr(void *ptr) {
+    return ptr >= block_region_start_ && ptr < block_region_end_;
+  }
+
+  void *block_region_start_;
+  void *block_region_end_;
+  FreeListType freelist_;
+  HeapStats heap_stats_;
+};
+
+template <size_t BUFF_SIZE, size_t NUM_BUCKETS = DEFAULT_BUCKETS.size()>
+struct FreeListHeapBuffer : public FreeListHeap<NUM_BUCKETS> {
+  using parent = FreeListHeap<NUM_BUCKETS>;
+  using FreeListNode = typename parent::FreeListType::FreeListNode;
+
+  constexpr FreeListHeapBuffer()
+      : FreeListHeap<NUM_BUCKETS>(&block, buffer + sizeof(buffer), BUFF_SIZE),
+        block(0, BUFF_SIZE), node{}, buffer{} {
+    block.mark_last();
+
+    cpp::span<cpp::byte> chunk(buffer, sizeof(buffer));
+    parent::set_freelist_node(node, chunk);
+  }
+
+  typename parent::BlockType block;
+  FreeListNode node;
+  cpp::byte buffer[BUFF_SIZE - sizeof(block) - sizeof(node)];
+};
+
+template <size_t NUM_BUCKETS>
+void *FreeListHeap<NUM_BUCKETS>::allocate(size_t size) {
+  // Find a chunk in the freelist. Split it if needed, then return
+  auto chunk = freelist_.find_chunk(size);
+
+  if (chunk.data() == nullptr)
+    return nullptr;
+  freelist_.remove_chunk(chunk);
+
+  BlockType *chunk_block = BlockType::from_usable_space(chunk.data());
+
+  // Split that chunk. If there's a leftover chunk, add it to the freelist
+  optional<BlockType *> result = BlockType::split(chunk_block, size);
+  if (result)
+    freelist_.add_chunk(block_to_span(*result));
+
+  chunk_block->mark_used();
+
+  heap_stats_.bytes_allocated += size;
+  heap_stats_.cumulative_allocated += size;
+  heap_stats_.total_allocate_calls += 1;
+
+  return chunk_block->usable_space();
+}
+
+template <size_t NUM_BUCKETS> void FreeListHeap<NUM_BUCKETS>::free(void *ptr) {
+  cpp::byte *bytes = static_cast<cpp::byte *>(ptr);
+
+  LIBC_ASSERT(is_valid_ptr(bytes) && "Invalid pointer");
+
+  BlockType *chunk_block = BlockType::from_usable_space(bytes);
+
+  size_t size_freed = chunk_block->inner_size();
+  LIBC_ASSERT(chunk_block->used() && "The block is not in-use");
+  chunk_block->mark_free();
+
+  // Can we combine with the left or right blocks?
+  BlockType *prev = chunk_block->prev();
+  BlockType *next = nullptr;
+
+  if (!chunk_block->last())
+    next = chunk_block->next();
+
+  if (prev != nullptr && !prev->used()) {
+    // Remove from freelist and merge
+    freelist_.remove_chunk(block_to_span(prev));
+    chunk_block = chunk_block->prev();
+    BlockType::merge_next(chunk_block);
+  }
+
+  if (next != nullptr && !next->used()) {
+    freelist_.remove_chunk(block_to_span(next));
+    BlockType::merge_next(chunk_block);
+  }
+  // Add back to the freelist
+  freelist_.add_chunk(block_to_span(chunk_block));
+
+  heap_stats_.bytes_allocated -= size_freed;
+  heap_stats_.cumulative_freed += size_freed;
+  heap_stats_.total_free_calls += 1;
+}
+
+// Follows constract of the C standard realloc() function
+// If ptr is free'd, will return nullptr.
+template <size_t NUM_BUCKETS>
+void *FreeListHeap<NUM_BUCKETS>::realloc(void *ptr, size_t size) {
+  if (size == 0) {
+    free(ptr);
+    return nullptr;
+  }
+
+  // If the pointer is nullptr, allocate a new memory.
+  if (ptr == nullptr)
+    return allocate(size);
+
+  cpp::byte *bytes = static_cast<cpp::byte *>(ptr);
+
+  if (!is_valid_ptr(bytes))
+    return nullptr;
+
+  BlockType *chunk_block = BlockType::from_usable_space(bytes);
+  if (!chunk_block->used())
+    return nullptr;
+  size_t old_size = chunk_block->inner_size();
+
+  // Do nothing and return ptr if the required memory size is smaller than
+  // the current size.
+  if (old_size >= size)
+    return ptr;
+
+  void *new_ptr = allocate(size);
+  // Don't invalidate ptr if allocate(size) fails to initilize the memory.
+  if (new_ptr == nullptr)
+    return nullptr;
+  LIBC_NAMESPACE::inline_memcpy(new_ptr, ptr, old_size);
+
+  free(ptr);
+  return new_ptr;
+}
+
+template <size_t NUM_BUCKETS>
+void *FreeListHeap<NUM_BUCKETS>::calloc(size_t num, size_t size) {
+  void *ptr = allocate(num * size);
+  if (ptr != nullptr)
+    LIBC_NAMESPACE::inline_memset(ptr, 0, num * size);
+  return ptr;
+}
+
+extern FreeListHeap<> *freelist_heap;
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC___SUPPORT_FREELIST_HEAP_H
diff --git a/src/__support/macros/attributes.h b/src/__support/macros/attributes.h
index 8637e16..c647467 100644
--- a/src/__support/macros/attributes.h
+++ b/src/__support/macros/attributes.h
@@ -19,6 +19,10 @@
 
 #include "properties/architectures.h"
 
+#ifndef __has_attribute
+#define __has_attribute(x) 0
+#endif
+
 #define LIBC_INLINE inline
 #define LIBC_INLINE_VAR inline
 #define LIBC_INLINE_ASM __asm__ __volatile__
@@ -30,4 +34,18 @@
 #define LIBC_THREAD_LOCAL thread_local
 #endif
 
+#if __cplusplus >= 202002L
+#define LIBC_CONSTINIT constinit
+#elif __has_attribute(__require_constant_initialization__)
+#define LIBC_CONSTINIT __attribute__((__require_constant_initialization__))
+#else
+#define LIBC_CONSTINIT
+#endif
+
+#if defined(__clang__) && __has_attribute(preferred_type)
+#define LIBC_PREFERED_TYPE(TYPE) [[clang::preferred_type(TYPE)]]
+#else
+#define LIBC_PREFERED_TYPE(TYPE)
+#endif
+
 #endif // LLVM_LIBC_SRC___SUPPORT_MACROS_ATTRIBUTES_H
diff --git a/src/__support/threads/linux/rwlock.h b/src/__support/threads/linux/rwlock.h
new file mode 100644
index 0000000..201fe92
--- /dev/null
+++ b/src/__support/threads/linux/rwlock.h
@@ -0,0 +1,558 @@
+//===--- Implementation of a Linux RwLock class ---------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+#ifndef LLVM_LIBC_SRC_SUPPORT_THREADS_LINUX_RWLOCK_H
+#define LLVM_LIBC_SRC_SUPPORT_THREADS_LINUX_RWLOCK_H
+
+#include "hdr/errno_macros.h"
+#include "hdr/types/pid_t.h"
+#include "src/__support/CPP/atomic.h"
+#include "src/__support/CPP/limits.h"
+#include "src/__support/CPP/optional.h"
+#include "src/__support/OSUtil/syscall.h"
+#include "src/__support/common.h"
+#include "src/__support/libc_assert.h"
+#include "src/__support/macros/attributes.h"
+#include "src/__support/macros/optimization.h"
+#include "src/__support/threads/linux/futex_utils.h"
+#include "src/__support/threads/linux/futex_word.h"
+#include "src/__support/threads/linux/raw_mutex.h"
+#include "src/__support/threads/sleep.h"
+
+#ifndef LIBC_COPT_RWLOCK_DEFAULT_SPIN_COUNT
+#define LIBC_COPT_RWLOCK_DEFAULT_SPIN_COUNT 100
+#endif
+
+#ifndef LIBC_COPT_TIMEOUT_ENSURE_MONOTONICITY
+#define LIBC_COPT_TIMEOUT_ENSURE_MONOTONICITY 1
+#warning "LIBC_COPT_TIMEOUT_ENSURE_MONOTONICITY is not defined, defaulting to 1"
+#endif
+
+#if LIBC_COPT_TIMEOUT_ENSURE_MONOTONICITY
+#include "src/__support/time/linux/monotonicity.h"
+#endif
+
+namespace LIBC_NAMESPACE {
+// Forward declaration of the RwLock class.
+class RwLock;
+// A namespace to rwlock specific utilities.
+namespace rwlock {
+// The role of the thread in the RwLock.
+enum class Role { Reader = 0, Writer = 1 };
+
+// A waiting queue to keep track of the pending readers and writers.
+class WaitingQueue final : private RawMutex {
+  /* FutexWordType raw_mutex;  (from base class) */
+
+  // Pending reader count (protected by the mutex)
+  FutexWordType pending_readers;
+  // Pending writer count (protected by the mutex)
+  FutexWordType pending_writers;
+  // Reader serialization (increases on each reader-waking operation)
+  Futex reader_serialization;
+  // Writer serialization (increases on each writer-waking operation)
+  Futex writer_serialization;
+
+public:
+  // RAII guard to lock and unlock the waiting queue.
+  class Guard {
+    WaitingQueue &queue;
+    bool is_pshared;
+
+    LIBC_INLINE Guard(WaitingQueue &queue, bool is_pshared)
+        : queue(queue), is_pshared(is_pshared) {
+      queue.lock(cpp::nullopt, is_pshared);
+    }
+
+  public:
+    LIBC_INLINE ~Guard() { queue.unlock(is_pshared); }
+    template <Role role> LIBC_INLINE FutexWordType &pending_count() {
+      if constexpr (role == Role::Reader)
+        return queue.pending_readers;
+      else
+        return queue.pending_writers;
+    }
+    template <Role role> LIBC_INLINE FutexWordType &serialization() {
+      if constexpr (role == Role::Reader)
+        return queue.reader_serialization.val;
+      else
+        return queue.writer_serialization.val;
+    }
+    friend WaitingQueue;
+  };
+
+public:
+  LIBC_INLINE constexpr WaitingQueue()
+      : RawMutex(), pending_readers(0), pending_writers(0),
+        reader_serialization(0), writer_serialization(0) {}
+
+  LIBC_INLINE Guard acquire(bool is_pshared) {
+    return Guard(*this, is_pshared);
+  }
+
+  template <Role role>
+  LIBC_INLINE long wait(FutexWordType expected,
+                        cpp::optional<Futex::Timeout> timeout,
+                        bool is_pshared) {
+    if constexpr (role == Role::Reader)
+      return reader_serialization.wait(expected, timeout, is_pshared);
+    else
+      return writer_serialization.wait(expected, timeout, is_pshared);
+  }
+
+  template <Role role> LIBC_INLINE long notify(bool is_pshared) {
+    if constexpr (role == Role::Reader)
+      return reader_serialization.notify_all(is_pshared);
+    else
+      return writer_serialization.notify_one(is_pshared);
+  }
+};
+
+// The RwState of the RwLock is stored in an integer word, consisting of the
+// following components:
+// -----------------------------------------------
+// | Range    |           Description            |
+// ===============================================
+// | 0        | Pending Reader Bit               |
+// -----------------------------------------------
+// | 1        | Pending Writer Bit               |
+// -----------------------------------------------
+// | [2, MSB) | Active Reader Count              |
+// -----------------------------------------------
+// | MSB      | Active Writer Bit                |
+// -----------------------------------------------
+class RwState {
+  // Shift amounts to access the components of the state.
+  LIBC_INLINE_VAR static constexpr int PENDING_READER_SHIFT = 0;
+  LIBC_INLINE_VAR static constexpr int PENDING_WRITER_SHIFT = 1;
+  LIBC_INLINE_VAR static constexpr int ACTIVE_READER_SHIFT = 2;
+  LIBC_INLINE_VAR static constexpr int ACTIVE_WRITER_SHIFT =
+      cpp::numeric_limits<int>::digits;
+
+  // Bitmasks to access the components of the state.
+  LIBC_INLINE_VAR static constexpr int PENDING_READER_BIT =
+      1 << PENDING_READER_SHIFT;
+  LIBC_INLINE_VAR static constexpr int PENDING_WRITER_BIT =
+      1 << PENDING_WRITER_SHIFT;
+  LIBC_INLINE_VAR static constexpr int ACTIVE_READER_COUNT_UNIT =
+      1 << ACTIVE_READER_SHIFT;
+  LIBC_INLINE_VAR static constexpr int ACTIVE_WRITER_BIT =
+      1 << ACTIVE_WRITER_SHIFT;
+  LIBC_INLINE_VAR static constexpr int PENDING_MASK =
+      PENDING_READER_BIT | PENDING_WRITER_BIT;
+
+private:
+  // We use the signed integer as the state type. It is easier
+  // to reason about the state transitions using signness.
+  int state;
+
+public:
+  // Construction and conversion functions.
+  LIBC_INLINE constexpr RwState(int state = 0) : state(state) {}
+  LIBC_INLINE constexpr operator int() const { return state; }
+
+  // Utilities to check the state of the RwLock.
+  LIBC_INLINE constexpr bool has_active_writer() const { return state < 0; }
+  LIBC_INLINE constexpr bool has_active_reader() const {
+    return state >= ACTIVE_READER_COUNT_UNIT;
+  }
+  LIBC_INLINE constexpr bool has_acitve_owner() const {
+    return has_active_reader() || has_active_writer();
+  }
+  LIBC_INLINE constexpr bool has_last_reader() const {
+    return (state >> ACTIVE_READER_SHIFT) == 1;
+  }
+  LIBC_INLINE constexpr bool has_pending_writer() const {
+    return state & PENDING_WRITER_BIT;
+  }
+  LIBC_INLINE constexpr bool has_pending() const {
+    return state & PENDING_MASK;
+  }
+
+  LIBC_INLINE constexpr RwState set_writer_bit() const {
+    return RwState(state | ACTIVE_WRITER_BIT);
+  }
+
+  // The preference parameter changes the behavior of the lock acquisition
+  // if there are both readers and writers waiting for the lock. If writers
+  // are preferred, reader acquisition will be blocked until all pending
+  // writers are served.
+  template <Role role> LIBC_INLINE bool can_acquire(Role preference) const {
+    if constexpr (role == Role::Reader) {
+      switch (preference) {
+      case Role::Reader:
+        return !has_active_writer();
+      case Role::Writer:
+        return !has_active_writer() && !has_pending_writer();
+      }
+      __builtin_unreachable();
+    } else
+      return !has_acitve_owner();
+  }
+
+  // This function check if it is possible to grow the reader count without
+  // overflowing the state.
+  LIBC_INLINE cpp::optional<RwState> try_increase_reader_count() const {
+    LIBC_ASSERT(!has_active_writer() &&
+                "try_increase_reader_count shall only be called when there "
+                "is no active writer.");
+    RwState res;
+    if (LIBC_UNLIKELY(__builtin_sadd_overflow(state, ACTIVE_READER_COUNT_UNIT,
+                                              &res.state)))
+      return cpp::nullopt;
+    return res;
+  }
+
+  // Utilities to do atomic operations on the state.
+  LIBC_INLINE static RwState fetch_sub_reader_count(cpp::Atomic<int> &target,
+                                                    cpp::MemoryOrder order) {
+    return RwState(target.fetch_sub(ACTIVE_READER_COUNT_UNIT, order));
+  }
+
+  LIBC_INLINE static RwState load(cpp::Atomic<int> &target,
+                                  cpp::MemoryOrder order) {
+    return RwState(target.load(order));
+  }
+
+  template <Role role>
+  LIBC_INLINE static RwState fetch_set_pending_bit(cpp::Atomic<int> &target,
+                                                   cpp::MemoryOrder order) {
+    if constexpr (role == Role::Reader)
+      return RwState(target.fetch_or(PENDING_READER_BIT, order));
+    else
+      return RwState(target.fetch_or(PENDING_WRITER_BIT, order));
+  }
+  template <Role role>
+  LIBC_INLINE static RwState fetch_clear_pending_bit(cpp::Atomic<int> &target,
+                                                     cpp::MemoryOrder order) {
+    if constexpr (role == Role::Reader)
+      return RwState(target.fetch_and(~PENDING_READER_BIT, order));
+    else
+      return RwState(target.fetch_and(~PENDING_WRITER_BIT, order));
+  }
+
+  LIBC_INLINE static RwState fetch_clear_active_writer(cpp::Atomic<int> &target,
+                                                       cpp::MemoryOrder order) {
+    return RwState(target.fetch_and(~ACTIVE_WRITER_BIT, order));
+  }
+
+  LIBC_INLINE bool compare_exchange_weak_with(cpp::Atomic<int> &target,
+                                              RwState desired,
+                                              cpp::MemoryOrder success_order,
+                                              cpp::MemoryOrder failure_order) {
+    return target.compare_exchange_weak(state, desired, success_order,
+                                        failure_order);
+  }
+
+  // Utilities to spin and reload the state.
+private:
+  template <class F>
+  LIBC_INLINE static RwState spin_reload_until(cpp::Atomic<int> &target,
+                                               F &&func, unsigned spin_count) {
+    for (;;) {
+      auto state = RwState::load(target, cpp::MemoryOrder::RELAXED);
+      if (func(state) || spin_count == 0)
+        return state;
+      sleep_briefly();
+      spin_count--;
+    }
+  }
+
+public:
+  template <Role role>
+  LIBC_INLINE static RwState spin_reload(cpp::Atomic<int> &target,
+                                         Role preference, unsigned spin_count) {
+    if constexpr (role == Role::Reader) {
+      // Return the reader state if either the lock is available or there is
+      // any ongoing contention.
+      return spin_reload_until(
+          target,
+          [=](RwState state) {
+            return state.can_acquire<Role::Reader>(preference) ||
+                   state.has_pending();
+          },
+          spin_count);
+    } else {
+      // Return the writer state if either the lock is available or there is
+      // any contention *between writers*. Since writers can be way less than
+      // readers, we allow them to spin more to improve the fairness.
+      return spin_reload_until(
+          target,
+          [=](RwState state) {
+            return state.can_acquire<Role::Writer>(preference) ||
+                   state.has_pending_writer();
+          },
+          spin_count);
+    }
+  }
+
+  friend class RwLockTester;
+};
+} // namespace rwlock
+
+class RwLock {
+  using RwState = rwlock::RwState;
+  using Role = rwlock::Role;
+  using WaitingQueue = rwlock::WaitingQueue;
+
+public:
+  // Return types for the lock functions.
+  // All the locking routines returning this type are marked as [[nodiscard]]
+  // because it is a common error to assume the lock success without checking
+  // the return value, which can lead to undefined behaviors or other subtle
+  // bugs that are hard to reason about.
+  enum class LockResult : int {
+    Success = 0,
+    TimedOut = ETIMEDOUT,
+    Overflow = EAGAIN, /* EAGAIN is specified in the standard for overflow. */
+    Busy = EBUSY,
+    Deadlock = EDEADLOCK,
+    PermissionDenied = EPERM,
+  };
+
+private:
+  // Whether the RwLock is shared between processes.
+  LIBC_PREFERED_TYPE(bool)
+  unsigned is_pshared : 1;
+  // Reader/Writer preference.
+  LIBC_PREFERED_TYPE(Role)
+  unsigned preference : 1;
+  // RwState to keep track of the RwLock.
+  cpp::Atomic<int> state;
+  // writer_tid is used to keep track of the thread id of the writer. Notice
+  // that TLS address is not a good idea here since it may remains the same
+  // across forked processes.
+  cpp::Atomic<pid_t> writer_tid;
+  // Waiting queue to keep track of the  readers and writers.
+  WaitingQueue queue;
+
+private:
+  // Load the bitfield preference.
+  LIBC_INLINE Role get_preference() const {
+    return static_cast<Role>(preference);
+  }
+  // TODO: use cached thread id once implemented.
+  LIBC_INLINE static pid_t gettid() { return syscall_impl<pid_t>(SYS_gettid); }
+
+  template <Role role> LIBC_INLINE LockResult try_lock(RwState &old) {
+    if constexpr (role == Role::Reader) {
+      while (LIBC_LIKELY(old.can_acquire<Role::Reader>(get_preference()))) {
+        cpp::optional<RwState> next = old.try_increase_reader_count();
+        if (!next)
+          return LockResult::Overflow;
+        if (LIBC_LIKELY(old.compare_exchange_weak_with(
+                state, *next, cpp::MemoryOrder::ACQUIRE,
+                cpp::MemoryOrder::RELAXED)))
+          return LockResult::Success;
+        // Notice that old is updated by the compare_exchange_weak_with
+        // function.
+      }
+      return LockResult::Busy;
+    } else {
+      // This while loop should terminate quickly
+      while (LIBC_LIKELY(old.can_acquire<Role::Writer>(get_preference()))) {
+        if (LIBC_LIKELY(old.compare_exchange_weak_with(
+                state, old.set_writer_bit(), cpp::MemoryOrder::ACQUIRE,
+                cpp::MemoryOrder::RELAXED))) {
+          writer_tid.store(gettid(), cpp::MemoryOrder::RELAXED);
+          return LockResult::Success;
+        }
+        // Notice that old is updated by the compare_exchange_weak_with
+        // function.
+      }
+      return LockResult::Busy;
+    }
+  }
+
+public:
+  LIBC_INLINE constexpr RwLock(Role preference = Role::Reader,
+                               bool is_pshared = false)
+      : is_pshared(is_pshared),
+        preference(static_cast<unsigned>(preference) & 1u), state(0),
+        writer_tid(0), queue() {}
+
+  [[nodiscard]]
+  LIBC_INLINE LockResult try_read_lock() {
+    RwState old = RwState::load(state, cpp::MemoryOrder::RELAXED);
+    return try_lock<Role::Reader>(old);
+  }
+  [[nodiscard]]
+  LIBC_INLINE LockResult try_write_lock() {
+    RwState old = RwState::load(state, cpp::MemoryOrder::RELAXED);
+    return try_lock<Role::Writer>(old);
+  }
+
+private:
+  template <Role role>
+  LIBC_INLINE LockResult
+  lock_slow(cpp::optional<Futex::Timeout> timeout = cpp::nullopt,
+            unsigned spin_count = LIBC_COPT_RWLOCK_DEFAULT_SPIN_COUNT) {
+    // Phase 1: deadlock detection.
+    // A deadlock happens if this is a RAW/WAW lock in the same thread.
+    if (writer_tid.load(cpp::MemoryOrder::RELAXED) == gettid())
+      return LockResult::Deadlock;
+
+#if LIBC_COPT_TIMEOUT_ENSURE_MONOTONICITY
+    // Phase 2: convert the timeout if necessary.
+    if (timeout)
+      ensure_monotonicity(*timeout);
+#endif
+
+    // Phase 3: spin to get the initial state. We ignore the timing due to
+    // spin since it should end quickly.
+    RwState old =
+        RwState::spin_reload<role>(state, get_preference(), spin_count);
+
+    // Enter the main acquisition loop.
+    for (;;) {
+      // Phase 4: if the lock can be acquired, try to acquire it.
+      LockResult result = try_lock<role>(old);
+      if (result != LockResult::Busy)
+        return result;
+
+      // Phase 5: register ourselves as a  reader.
+      int serial_number;
+      {
+        // The queue need to be protected by a mutex since the operations in
+        // this block must be executed as a whole transaction. It is possible
+        // that this lock will make the timeout imprecise, but this is the
+        // best we can do. The transaction is small and everyone should make
+        // progress rather quickly.
+        WaitingQueue::Guard guard = queue.acquire(is_pshared);
+        guard.template pending_count<role>()++;
+
+        // Use atomic operation to guarantee the total order of the operations
+        // on the state. The pending flag update should be visible to any
+        // succeeding unlock events. Or, if a unlock does happen before we
+        // sleep on the futex, we can avoid such waiting.
+        old = RwState::fetch_set_pending_bit<role>(state,
+                                                   cpp::MemoryOrder::RELAXED);
+        // no need to use atomic since it is already protected by the mutex.
+        serial_number = guard.serialization<role>();
+      }
+
+      // Phase 6: do futex wait until the lock is available or timeout is
+      // reached.
+      bool timeout_flag = false;
+      if (!old.can_acquire<role>(get_preference()))
+        timeout_flag = (queue.wait<role>(serial_number, timeout, is_pshared) ==
+                        -ETIMEDOUT);
+
+      // Phase 7: unregister ourselves as a pending reader/writer.
+      {
+        // Similarly, the unregister operation should also be an atomic
+        // transaction.
+        WaitingQueue::Guard guard = queue.acquire(is_pshared);
+        guard.pending_count<role>()--;
+        // Clear the flag if we are the last reader. The flag must be
+        // cleared otherwise operations like trylock may fail even though
+        // there is no competitors.
+        if (guard.pending_count<role>() == 0)
+          RwState::fetch_clear_pending_bit<role>(state,
+                                                 cpp::MemoryOrder::RELAXED);
+      }
+
+      // Phase 8: exit the loop is timeout is reached.
+      if (timeout_flag)
+        return LockResult::TimedOut;
+
+      // Phase 9: reload the state and retry the acquisition.
+      old = RwState::spin_reload<role>(state, get_preference(), spin_count);
+    }
+  }
+
+public:
+  [[nodiscard]]
+  LIBC_INLINE LockResult
+  read_lock(cpp::optional<Futex::Timeout> timeout = cpp::nullopt,
+            unsigned spin_count = LIBC_COPT_RWLOCK_DEFAULT_SPIN_COUNT) {
+    LockResult result = try_read_lock();
+    if (LIBC_LIKELY(result != LockResult::Busy))
+      return result;
+    return lock_slow<Role::Reader>(timeout, spin_count);
+  }
+  [[nodiscard]]
+  LIBC_INLINE LockResult
+  write_lock(cpp::optional<Futex::Timeout> timeout = cpp::nullopt,
+             unsigned spin_count = LIBC_COPT_RWLOCK_DEFAULT_SPIN_COUNT) {
+    LockResult result = try_write_lock();
+    if (LIBC_LIKELY(result != LockResult::Busy))
+      return result;
+    return lock_slow<Role::Writer>(timeout, spin_count);
+  }
+
+private:
+  // Compiler (clang 19.0) somehow decides that this function may be inlined,
+  // which leads to a larger unlock function that is infeasible to be inlined.
+  // Since notifcation routine is colder we mark it as noinline explicitly.
+  [[gnu::noinline]]
+  LIBC_INLINE void notify_pending_threads() {
+    enum class WakeTarget { Readers, Writers, None };
+    WakeTarget status;
+
+    {
+      WaitingQueue::Guard guard = queue.acquire(is_pshared);
+      if (guard.pending_count<Role::Writer>() != 0) {
+        guard.serialization<Role::Writer>()++;
+        status = WakeTarget::Writers;
+      } else if (guard.pending_count<Role::Reader>() != 0) {
+        guard.serialization<Role::Reader>()++;
+        status = WakeTarget::Readers;
+      } else
+        status = WakeTarget::None;
+    }
+
+    if (status == WakeTarget::Readers)
+      queue.notify<Role::Reader>(is_pshared);
+    else if (status == WakeTarget::Writers)
+      queue.notify<Role::Writer>(is_pshared);
+  }
+
+public:
+  [[nodiscard]]
+  LIBC_INLINE LockResult unlock() {
+    RwState old = RwState::load(state, cpp::MemoryOrder::RELAXED);
+    if (old.has_active_writer()) {
+      // The lock is held by a writer.
+      // Check if we are the owner of the lock.
+      if (writer_tid.load(cpp::MemoryOrder::RELAXED) != gettid())
+        return LockResult::PermissionDenied;
+      // clear writer tid.
+      writer_tid.store(0, cpp::MemoryOrder::RELAXED);
+      // clear the writer bit.
+      old =
+          RwState::fetch_clear_active_writer(state, cpp::MemoryOrder::RELEASE);
+      // If there is no pending readers or writers, we are done.
+      if (!old.has_pending())
+        return LockResult::Success;
+    } else if (old.has_active_reader()) {
+      // The lock is held by readers.
+      // Decrease the reader count.
+      old = RwState::fetch_sub_reader_count(state, cpp::MemoryOrder::RELEASE);
+      // If there is no pending readers or writers, we are done.
+      if (!old.has_last_reader() || !old.has_pending())
+        return LockResult::Success;
+    } else
+      return LockResult::PermissionDenied;
+
+    notify_pending_threads();
+    return LockResult::Success;
+  }
+
+  // We do not allocate any special resources for the RwLock, so this function
+  // will only check if the lock is currently held by any thread.
+  [[nodiscard]]
+  LIBC_INLINE LockResult check_for_destroy() {
+    RwState old = RwState::load(state, cpp::MemoryOrder::RELAXED);
+    if (old.has_acitve_owner())
+      return LockResult::Busy;
+    return LockResult::Success;
+  }
+};
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_SUPPORT_THREADS_LINUX_RWLOCK_H
diff --git a/src/fcntl/linux/fcntl.cpp b/src/fcntl/linux/fcntl.cpp
index 24a20fb..3875889 100644
--- a/src/fcntl/linux/fcntl.cpp
+++ b/src/fcntl/linux/fcntl.cpp
@@ -8,86 +8,20 @@
 
 #include "src/fcntl/fcntl.h"
 
-#include "hdr/fcntl_macros.h"
-#include "hdr/types/struct_f_owner_ex.h"
-#include "hdr/types/struct_flock.h"
-#include "hdr/types/struct_flock64.h"
-#include "src/__support/OSUtil/syscall.h" // For internal syscall function.
+#include "src/__support/OSUtil/fcntl.h"
 #include "src/__support/common.h"
-#include "src/errno/libc_errno.h"
 
 #include <stdarg.h>
-#include <sys/syscall.h> // For syscall numbers.
 
-// The OFD file locks require special handling for LARGEFILES
 namespace LIBC_NAMESPACE {
+
 LLVM_LIBC_FUNCTION(int, fcntl, (int fd, int cmd, ...)) {
   void *arg;
   va_list varargs;
   va_start(varargs, cmd);
   arg = va_arg(varargs, void *);
   va_end(varargs);
-
-  switch (cmd) {
-  case F_SETLKW:
-    return syscall_impl<int>(SYS_fcntl, fd, cmd, arg);
-  case F_OFD_SETLKW: {
-    struct flock *flk = reinterpret_cast<struct flock *>(arg);
-    // convert the struct to a flock64
-    struct flock64 flk64;
-    flk64.l_type = flk->l_type;
-    flk64.l_whence = flk->l_whence;
-    flk64.l_start = flk->l_start;
-    flk64.l_len = flk->l_len;
-    flk64.l_pid = flk->l_pid;
-    // create a syscall
-    return syscall_impl<int>(SYS_fcntl, fd, cmd, &flk64);
-  }
-  case F_OFD_GETLK:
-  case F_OFD_SETLK: {
-    struct flock *flk = reinterpret_cast<struct flock *>(arg);
-    // convert the struct to a flock64
-    struct flock64 flk64;
-    flk64.l_type = flk->l_type;
-    flk64.l_whence = flk->l_whence;
-    flk64.l_start = flk->l_start;
-    flk64.l_len = flk->l_len;
-    flk64.l_pid = flk->l_pid;
-    // create a syscall
-    int retVal = syscall_impl<int>(SYS_fcntl, fd, cmd, &flk64);
-    // On failure, return
-    if (retVal == -1)
-      return -1;
-    // Check for overflow, i.e. the offsets are not the same when cast
-    // to off_t from off64_t.
-    if (static_cast<off_t>(flk64.l_len) != flk64.l_len ||
-        static_cast<off_t>(flk64.l_start) != flk64.l_start) {
-      libc_errno = EOVERFLOW;
-      return -1;
-    }
-    // Now copy back into flk, in case flk64 got modified
-    flk->l_type = flk64.l_type;
-    flk->l_whence = flk64.l_whence;
-    flk->l_start = flk64.l_start;
-    flk->l_len = flk64.l_len;
-    flk->l_pid = flk64.l_pid;
-    return retVal;
-  }
-  case F_GETOWN: {
-    struct f_owner_ex fex;
-    int retVal = syscall_impl<int>(SYS_fcntl, fd, F_GETOWN_EX, &fex);
-    if (retVal == -EINVAL)
-      return syscall_impl<int>(SYS_fcntl, fd, cmd,
-                               reinterpret_cast<void *>(arg));
-    if (static_cast<unsigned long>(retVal) <= -4096UL)
-      return fex.type == F_OWNER_PGRP ? -fex.pid : fex.pid;
-
-    libc_errno = -retVal;
-    return -1;
-  }
-  // The general case
-  default:
-    return syscall_impl<int>(SYS_fcntl, fd, cmd, reinterpret_cast<void *>(arg));
-  }
+  return LIBC_NAMESPACE::internal::fcntl(fd, cmd, arg);
 }
+
 } // namespace LIBC_NAMESPACE
diff --git a/src/math/f16fmaf.h b/src/math/f16fmaf.h
new file mode 100644
index 0000000..d92cb43
--- /dev/null
+++ b/src/math/f16fmaf.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for f16fmaf -----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_F16FMAF_H
+#define LLVM_LIBC_SRC_MATH_F16FMAF_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+float16 f16fmaf(float x, float y, float z);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_F16FMAF_H
diff --git a/src/math/f16sqrtf.h b/src/math/f16sqrtf.h
new file mode 100644
index 0000000..197ebe6
--- /dev/null
+++ b/src/math/f16sqrtf.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for f16sqrtf ----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_F16SQRTF_H
+#define LLVM_LIBC_SRC_MATH_F16SQRTF_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+float16 f16sqrtf(float x);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_F16SQRTF_H
diff --git a/src/math/fmul.h b/src/math/fmul.h
new file mode 100644
index 0000000..fbc1069
--- /dev/null
+++ b/src/math/fmul.h
@@ -0,0 +1,18 @@
+//===-- Implementation header for fmul --------------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_FMUL_H
+#define LLVM_LIBC_SRC_MATH_FMUL_H
+
+namespace LIBC_NAMESPACE {
+
+float fmul(double x, double y);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_FMUL_H
diff --git a/src/math/frexpf16.h b/src/math/frexpf16.h
new file mode 100644
index 0000000..dc1898c
--- /dev/null
+++ b/src/math/frexpf16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for frexpf16 ----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_FREXPF16_H
+#define LLVM_LIBC_SRC_MATH_FREXPF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+float16 frexpf16(float16 x, int *exp);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_FREXPF16_H
diff --git a/src/math/generic/acosf.cpp b/src/math/generic/acosf.cpp
index e6e28d4..f02edec 100644
--- a/src/math/generic/acosf.cpp
+++ b/src/math/generic/acosf.cpp
@@ -113,7 +113,7 @@ LLVM_LIBC_FUNCTION(float, acosf, (float x)) {
   xbits.set_sign(Sign::POS);
   double xd = static_cast<double>(xbits.get_val());
   double u = fputil::multiply_add(-0.5, xd, 0.5);
-  double cv = 2 * fputil::sqrt(u);
+  double cv = 2 * fputil::sqrt<double>(u);
 
   double r3 = asin_eval(u);
   double r = fputil::multiply_add(cv * u, r3, cv);
diff --git a/src/math/generic/acoshf.cpp b/src/math/generic/acoshf.cpp
index a4a75a7..9422ec6 100644
--- a/src/math/generic/acoshf.cpp
+++ b/src/math/generic/acoshf.cpp
@@ -66,8 +66,8 @@ LLVM_LIBC_FUNCTION(float, acoshf, (float x)) {
 
   double x_d = static_cast<double>(x);
   // acosh(x) = log(x + sqrt(x^2 - 1))
-  return static_cast<float>(
-      log_eval(x_d + fputil::sqrt(fputil::multiply_add(x_d, x_d, -1.0))));
+  return static_cast<float>(log_eval(
+      x_d + fputil::sqrt<double>(fputil::multiply_add(x_d, x_d, -1.0))));
 }
 
 } // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/asinf.cpp b/src/math/generic/asinf.cpp
index d913333..c4afca4 100644
--- a/src/math/generic/asinf.cpp
+++ b/src/math/generic/asinf.cpp
@@ -144,7 +144,7 @@ LLVM_LIBC_FUNCTION(float, asinf, (float x)) {
   double sign = SIGN[x_sign];
   double xd = static_cast<double>(xbits.get_val());
   double u = fputil::multiply_add(-0.5, xd, 0.5);
-  double c1 = sign * (-2 * fputil::sqrt(u));
+  double c1 = sign * (-2 * fputil::sqrt<double>(u));
   double c2 = fputil::multiply_add(sign, M_MATH_PI_2, c1);
   double c3 = c1 * u;
 
diff --git a/src/math/generic/asinhf.cpp b/src/math/generic/asinhf.cpp
index 6e35178..82dc2a3 100644
--- a/src/math/generic/asinhf.cpp
+++ b/src/math/generic/asinhf.cpp
@@ -97,9 +97,9 @@ LLVM_LIBC_FUNCTION(float, asinhf, (float x)) {
 
   // asinh(x) = log(x + sqrt(x^2 + 1))
   return static_cast<float>(
-      x_sign *
-      log_eval(fputil::multiply_add(
-          x_d, x_sign, fputil::sqrt(fputil::multiply_add(x_d, x_d, 1.0)))));
+      x_sign * log_eval(fputil::multiply_add(
+                   x_d, x_sign,
+                   fputil::sqrt<double>(fputil::multiply_add(x_d, x_d, 1.0)))));
 }
 
 } // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/expm1f.cpp b/src/math/generic/expm1f.cpp
index 037e600..6b9f074 100644
--- a/src/math/generic/expm1f.cpp
+++ b/src/math/generic/expm1f.cpp
@@ -104,7 +104,7 @@ LLVM_LIBC_FUNCTION(float, expm1f, (float x)) {
         // intermediate results as it is more efficient than using an emulated
         // version of FMA.
 #if defined(LIBC_TARGET_CPU_HAS_FMA)
-      return fputil::fma(x, x, x);
+      return fputil::fma<float>(x, x, x);
 #else
       double xd = x;
       return static_cast<float>(fputil::multiply_add(xd, xd, xd));
diff --git a/src/math/generic/f16fmaf.cpp b/src/math/generic/f16fmaf.cpp
new file mode 100644
index 0000000..09f2712
--- /dev/null
+++ b/src/math/generic/f16fmaf.cpp
@@ -0,0 +1,19 @@
+//===-- Implementation of f16fmaf function --------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/f16fmaf.h"
+#include "src/__support/FPUtil/FMA.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(float16, f16fmaf, (float x, float y, float z)) {
+  return fputil::fma<float16>(x, y, z);
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/f16sqrtf.cpp b/src/math/generic/f16sqrtf.cpp
new file mode 100644
index 0000000..1f7ee2d
--- /dev/null
+++ b/src/math/generic/f16sqrtf.cpp
@@ -0,0 +1,19 @@
+//===-- Implementation of f16sqrtf function -------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/f16sqrtf.h"
+#include "src/__support/FPUtil/sqrt.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(float16, f16sqrtf, (float x)) {
+  return fputil::sqrt<float16>(x);
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/fma.cpp b/src/math/generic/fma.cpp
index e27e5ba..7937766 100644
--- a/src/math/generic/fma.cpp
+++ b/src/math/generic/fma.cpp
@@ -14,7 +14,7 @@
 namespace LIBC_NAMESPACE {
 
 LLVM_LIBC_FUNCTION(double, fma, (double x, double y, double z)) {
-  return fputil::fma(x, y, z);
+  return fputil::fma<double>(x, y, z);
 }
 
 } // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/fmaf.cpp b/src/math/generic/fmaf.cpp
index 7512b82..d367a06 100644
--- a/src/math/generic/fmaf.cpp
+++ b/src/math/generic/fmaf.cpp
@@ -14,7 +14,7 @@
 namespace LIBC_NAMESPACE {
 
 LLVM_LIBC_FUNCTION(float, fmaf, (float x, float y, float z)) {
-  return fputil::fma(x, y, z);
+  return fputil::fma<float>(x, y, z);
 }
 
 } // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/fmul.cpp b/src/math/generic/fmul.cpp
new file mode 100644
index 0000000..40af204
--- /dev/null
+++ b/src/math/generic/fmul.cpp
@@ -0,0 +1,128 @@
+//===-- Implementation of fmul function------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/fmul.h"
+#include "src/__support/CPP/bit.h"
+#include "src/__support/FPUtil/BasicOperations.h"
+#include "src/__support/FPUtil/FPBits.h"
+#include "src/__support/FPUtil/rounding_mode.h"
+#include "src/__support/common.h"
+#include "src/__support/uint128.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(float, fmul, (double x, double y)) {
+  auto x_bits = fputil::FPBits<double>(x);
+
+  auto y_bits = fputil::FPBits<double>(y);
+
+  auto output_sign = (x_bits.sign() != y_bits.sign()) ? Sign::NEG : Sign::POS;
+
+  if (LIBC_UNLIKELY(x_bits.is_inf_or_nan() || y_bits.is_inf_or_nan() ||
+                    x_bits.is_zero() || y_bits.is_zero())) {
+    if (x_bits.is_nan())
+      return static_cast<float>(x);
+    if (y_bits.is_nan())
+      return static_cast<float>(y);
+    if (x_bits.is_inf())
+      return y_bits.is_zero()
+                 ? fputil::FPBits<float>::quiet_nan().get_val()
+                 : fputil::FPBits<float>::inf(output_sign).get_val();
+    if (y_bits.is_inf())
+      return x_bits.is_zero()
+                 ? fputil::FPBits<float>::quiet_nan().get_val()
+                 : fputil::FPBits<float>::inf(output_sign).get_val();
+    // Now either x or y is zero, and the other one is finite.
+    return fputil::FPBits<float>::zero(output_sign).get_val();
+  }
+
+  uint64_t mx, my;
+
+  // Get mantissa and append the hidden bit if needed.
+  mx = x_bits.get_explicit_mantissa();
+  my = y_bits.get_explicit_mantissa();
+
+  // Get the corresponding biased exponent.
+  int ex = x_bits.get_explicit_exponent();
+  int ey = y_bits.get_explicit_exponent();
+
+  // Count the number of leading zeros of the explicit mantissas.
+  int nx = cpp::countl_zero(mx);
+  int ny = cpp::countl_zero(my);
+  // Shift the leading 1 bit to the most significant bit.
+  mx <<= nx;
+  my <<= ny;
+
+  // Adjust exponent accordingly: If x or y are normal, we will only need to
+  // shift by (exponent length + sign bit = 11 bits. If x or y are denormal, we
+  // will need to shift more than 11 bits.
+  ex -= (nx - 11);
+  ey -= (ny - 11);
+
+  UInt128 product = static_cast<UInt128>(mx) * static_cast<UInt128>(my);
+  int32_t dm1;
+  uint64_t highs, lows;
+  uint64_t g, hight, lowt;
+  uint32_t m;
+  uint32_t b;
+  int c;
+
+  highs = static_cast<uint64_t>(product >> 64);
+  c = static_cast<int>(highs >= 0x8000000000000000);
+  lows = static_cast<uint64_t>(product);
+
+  lowt = (lows != 0);
+
+  dm1 = ex + ey + c + fputil::FPBits<float>::EXP_BIAS;
+
+  int round_mode = fputil::quick_get_round();
+  if (dm1 >= 255) {
+    if ((round_mode == FE_TOWARDZERO) ||
+        (round_mode == FE_UPWARD && output_sign.is_neg()) ||
+        (round_mode == FE_DOWNWARD && output_sign.is_pos())) {
+      return fputil::FPBits<float>::max_normal(output_sign).get_val();
+    }
+    return fputil::FPBits<float>::inf().get_val();
+  } else if (dm1 <= 0) {
+
+    int m_shift = 40 + c - dm1;
+    int g_shift = m_shift - 1;
+    int h_shift = 64 - g_shift;
+    m = (m_shift >= 64) ? 0 : static_cast<uint32_t>(highs >> m_shift);
+
+    g = g_shift >= 64 ? 0 : (highs >> g_shift) & 1;
+    hight = h_shift >= 64 ? highs : (highs << h_shift) != 0;
+
+    dm1 = 0;
+  } else {
+    m = static_cast<uint32_t>(highs >> (39 + c));
+    g = (highs >> (38 + c)) & 1;
+    hight = (highs << (26 - c)) != 0;
+  }
+
+  if (round_mode == FE_TONEAREST) {
+    b = g && ((hight && lowt) || ((m & 1) != 0));
+  } else if ((output_sign.is_neg() && round_mode == FE_DOWNWARD) ||
+             (output_sign.is_pos() && round_mode == FE_UPWARD)) {
+    b = (g == 0 && (hight && lowt) == 0) ? 0 : 1;
+  } else {
+    b = 0;
+  }
+
+  uint32_t exp16 = (dm1 << 23);
+
+  uint32_t m2 = m & fputil::FPBits<float>::FRACTION_MASK;
+
+  uint32_t result = (exp16 + m2) + b;
+
+  auto result_bits = fputil::FPBits<float>(result);
+  result_bits.set_sign(output_sign);
+  return result_bits.get_val();
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/frexpf16.cpp b/src/math/generic/frexpf16.cpp
new file mode 100644
index 0000000..2d29c07
--- /dev/null
+++ b/src/math/generic/frexpf16.cpp
@@ -0,0 +1,19 @@
+//===-- Implementation of frexpf16 function -------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/frexpf16.h"
+#include "src/__support/FPUtil/ManipulationFunctions.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(float16, frexpf16, (float16 x, int *exp)) {
+  return fputil::frexp(x, *exp);
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/getpayloadf16.cpp b/src/math/generic/getpayloadf16.cpp
new file mode 100644
index 0000000..0923226
--- /dev/null
+++ b/src/math/generic/getpayloadf16.cpp
@@ -0,0 +1,19 @@
+//===-- Implementation of getpayloadf16 function --------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/getpayloadf16.h"
+#include "src/__support/FPUtil/BasicOperations.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(float16, getpayloadf16, (const float16 *x)) {
+  return fputil::getpayload(*x);
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/hypotf.cpp b/src/math/generic/hypotf.cpp
index ffbf706..b09d09a 100644
--- a/src/math/generic/hypotf.cpp
+++ b/src/math/generic/hypotf.cpp
@@ -42,7 +42,7 @@ LLVM_LIBC_FUNCTION(float, hypotf, (float x, float y)) {
   double err = (x_sq >= y_sq) ? (sum_sq - x_sq) - y_sq : (sum_sq - y_sq) - x_sq;
 
   // Take sqrt in double precision.
-  DoubleBits result(fputil::sqrt(sum_sq));
+  DoubleBits result(fputil::sqrt<double>(sum_sq));
 
   if (!DoubleBits(sum_sq).is_inf_or_nan()) {
     // Correct rounding.
diff --git a/src/math/generic/ilogbf16.cpp b/src/math/generic/ilogbf16.cpp
new file mode 100644
index 0000000..87e43f8
--- /dev/null
+++ b/src/math/generic/ilogbf16.cpp
@@ -0,0 +1,19 @@
+//===-- Implementation of ilogbf16 function -------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/ilogbf16.h"
+#include "src/__support/FPUtil/ManipulationFunctions.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(int, ilogbf16, (float16 x)) {
+  return fputil::intlogb<int>(x);
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/ldexpf16.cpp b/src/math/generic/ldexpf16.cpp
new file mode 100644
index 0000000..ed15c45
--- /dev/null
+++ b/src/math/generic/ldexpf16.cpp
@@ -0,0 +1,19 @@
+//===-- Implementation of ldexpf16 function -------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/ldexpf16.h"
+#include "src/__support/FPUtil/ManipulationFunctions.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(float16, ldexpf16, (float16 x, int exp)) {
+  return fputil::ldexp(x, exp);
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/llogbf16.cpp b/src/math/generic/llogbf16.cpp
new file mode 100644
index 0000000..b7a21b9
--- /dev/null
+++ b/src/math/generic/llogbf16.cpp
@@ -0,0 +1,19 @@
+//===-- Implementation of llogbf16 function -------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/llogbf16.h"
+#include "src/__support/FPUtil/ManipulationFunctions.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(long, llogbf16, (float16 x)) {
+  return fputil::intlogb<long>(x);
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/logbf16.cpp b/src/math/generic/logbf16.cpp
new file mode 100644
index 0000000..52eb9ac
--- /dev/null
+++ b/src/math/generic/logbf16.cpp
@@ -0,0 +1,17 @@
+//===-- Implementation of logbf16 function --------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/logbf16.h"
+#include "src/__support/FPUtil/ManipulationFunctions.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(float16, logbf16, (float16 x)) { return fputil::logb(x); }
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/modff16.cpp b/src/math/generic/modff16.cpp
new file mode 100644
index 0000000..50cc5b5
--- /dev/null
+++ b/src/math/generic/modff16.cpp
@@ -0,0 +1,19 @@
+//===-- Implementation of modff16 function --------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/modff16.h"
+#include "src/__support/FPUtil/ManipulationFunctions.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(float16, modff16, (float16 x, float16 *iptr)) {
+  return fputil::modf(x, *iptr);
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/nanf16.cpp b/src/math/generic/nanf16.cpp
new file mode 100644
index 0000000..c42cd25
--- /dev/null
+++ b/src/math/generic/nanf16.cpp
@@ -0,0 +1,23 @@
+//===-- Implementation of nanf16 function ---------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/nanf16.h"
+#include "src/__support/common.h"
+#include "src/__support/str_to_float.h"
+#include "src/errno/libc_errno.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(float16, nanf16, (const char *arg)) {
+  auto result = internal::strtonan<float16>(arg);
+  if (result.has_error())
+    libc_errno = result.error;
+  return result.value;
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/powf.cpp b/src/math/generic/powf.cpp
index 59efc3f..13c0424 100644
--- a/src/math/generic/powf.cpp
+++ b/src/math/generic/powf.cpp
@@ -562,7 +562,7 @@ LLVM_LIBC_FUNCTION(float, powf, (float x, float y)) {
       switch (y_u) {
       case 0x3f00'0000: // y = 0.5f
         // pow(x, 1/2) = sqrt(x)
-        return fputil::sqrt(x);
+        return fputil::sqrt<float>(x);
       case 0x3f80'0000: // y = 1.0f
         return x;
       case 0x4000'0000: // y = 2.0f
diff --git a/src/math/generic/range_reduction_fma.h b/src/math/generic/range_reduction_fma.h
index aee8cbb..82b4ae1 100644
--- a/src/math/generic/range_reduction_fma.h
+++ b/src/math/generic/range_reduction_fma.h
@@ -33,8 +33,8 @@ static constexpr double THIRTYTWO_OVER_PI[5] = {
 //   k = round(x * 32 / pi) and y = (x * 32 / pi) - k.
 LIBC_INLINE int64_t small_range_reduction(double x, double &y) {
   double kd = fputil::nearest_integer(x * THIRTYTWO_OVER_PI[0]);
-  y = fputil::fma(x, THIRTYTWO_OVER_PI[0], -kd);
-  y = fputil::fma(x, THIRTYTWO_OVER_PI[1], y);
+  y = fputil::fma<double>(x, THIRTYTWO_OVER_PI[0], -kd);
+  y = fputil::fma<double>(x, THIRTYTWO_OVER_PI[1], y);
   return static_cast<int64_t>(kd);
 }
 
@@ -54,12 +54,13 @@ LIBC_INLINE int64_t large_range_reduction(double x, int x_exp, double &y) {
     prod_hi.set_uintval(prod_hi.uintval() &
                         ((x_exp < 55) ? (~0xfffULL) : (~0ULL))); // |x| < 2^55
     double k_hi = fputil::nearest_integer(prod_hi.get_val());
-    double truncated_prod = fputil::fma(x, THIRTYTWO_OVER_PI[0], -k_hi);
-    double prod_lo = fputil::fma(x, THIRTYTWO_OVER_PI[1], truncated_prod);
+    double truncated_prod = fputil::fma<double>(x, THIRTYTWO_OVER_PI[0], -k_hi);
+    double prod_lo =
+        fputil::fma<double>(x, THIRTYTWO_OVER_PI[1], truncated_prod);
     double k_lo = fputil::nearest_integer(prod_lo);
-    y = fputil::fma(x, THIRTYTWO_OVER_PI[1], truncated_prod - k_lo);
-    y = fputil::fma(x, THIRTYTWO_OVER_PI[2], y);
-    y = fputil::fma(x, THIRTYTWO_OVER_PI[3], y);
+    y = fputil::fma<double>(x, THIRTYTWO_OVER_PI[1], truncated_prod - k_lo);
+    y = fputil::fma<double>(x, THIRTYTWO_OVER_PI[2], y);
+    y = fputil::fma<double>(x, THIRTYTWO_OVER_PI[3], y);
 
     return static_cast<int64_t>(k_lo);
   }
@@ -74,12 +75,12 @@ LIBC_INLINE int64_t large_range_reduction(double x, int x_exp, double &y) {
   prod_hi.set_uintval(prod_hi.uintval() &
                       ((x_exp < 110) ? (~0xfffULL) : (~0ULL))); // |x| < 2^110
   double k_hi = fputil::nearest_integer(prod_hi.get_val());
-  double truncated_prod = fputil::fma(x, THIRTYTWO_OVER_PI[1], -k_hi);
-  double prod_lo = fputil::fma(x, THIRTYTWO_OVER_PI[2], truncated_prod);
+  double truncated_prod = fputil::fma<double>(x, THIRTYTWO_OVER_PI[1], -k_hi);
+  double prod_lo = fputil::fma<double>(x, THIRTYTWO_OVER_PI[2], truncated_prod);
   double k_lo = fputil::nearest_integer(prod_lo);
-  y = fputil::fma(x, THIRTYTWO_OVER_PI[2], truncated_prod - k_lo);
-  y = fputil::fma(x, THIRTYTWO_OVER_PI[3], y);
-  y = fputil::fma(x, THIRTYTWO_OVER_PI[4], y);
+  y = fputil::fma<double>(x, THIRTYTWO_OVER_PI[2], truncated_prod - k_lo);
+  y = fputil::fma<double>(x, THIRTYTWO_OVER_PI[3], y);
+  y = fputil::fma<double>(x, THIRTYTWO_OVER_PI[4], y);
 
   return static_cast<int64_t>(k_lo);
 }
diff --git a/src/math/generic/remainderf16.cpp b/src/math/generic/remainderf16.cpp
new file mode 100644
index 0000000..3517722
--- /dev/null
+++ b/src/math/generic/remainderf16.cpp
@@ -0,0 +1,20 @@
+//===-- Implementation of remainderf16 function ---------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/remainderf16.h"
+#include "src/__support/FPUtil/DivisionAndRemainderOperations.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(float16, remainderf16, (float16 x, float16 y)) {
+  int quotient;
+  return fputil::remquo(x, y, quotient);
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/remquof128.cpp b/src/math/generic/remquof128.cpp
new file mode 100644
index 0000000..e195c7b
--- /dev/null
+++ b/src/math/generic/remquof128.cpp
@@ -0,0 +1,19 @@
+//===-- Implementation of remquof128 function -----------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/remquof128.h"
+#include "src/__support/FPUtil/DivisionAndRemainderOperations.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(float128, remquof128, (float128 x, float128 y, int *exp)) {
+  return fputil::remquo(x, y, *exp);
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/remquof16.cpp b/src/math/generic/remquof16.cpp
new file mode 100644
index 0000000..a373bfa
--- /dev/null
+++ b/src/math/generic/remquof16.cpp
@@ -0,0 +1,19 @@
+//===-- Implementation of remquof16 function ------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/remquof16.h"
+#include "src/__support/FPUtil/DivisionAndRemainderOperations.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(float16, remquof16, (float16 x, float16 y, int *exp)) {
+  return fputil::remquo(x, y, *exp);
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/scalblnf16.cpp b/src/math/generic/scalblnf16.cpp
new file mode 100644
index 0000000..844a071
--- /dev/null
+++ b/src/math/generic/scalblnf16.cpp
@@ -0,0 +1,25 @@
+//===-- Implementation of scalblnf16 function -----------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/scalblnf16.h"
+#include "src/__support/FPUtil/ManipulationFunctions.h"
+#include "src/__support/common.h"
+
+#include "hdr/float_macros.h"
+
+#if FLT_RADIX != 2
+#error "FLT_RADIX != 2 is not supported."
+#endif
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(float16, scalblnf16, (float16 x, long n)) {
+  return fputil::ldexp(x, n);
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/scalbnf16.cpp b/src/math/generic/scalbnf16.cpp
new file mode 100644
index 0000000..a42fdff
--- /dev/null
+++ b/src/math/generic/scalbnf16.cpp
@@ -0,0 +1,25 @@
+//===-- Implementation of scalbnf16 function ------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/scalbnf16.h"
+#include "src/__support/FPUtil/ManipulationFunctions.h"
+#include "src/__support/common.h"
+
+#include "hdr/float_macros.h"
+
+#if FLT_RADIX != 2
+#error "FLT_RADIX != 2 is not supported."
+#endif
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(float16, scalbnf16, (float16 x, int n)) {
+  return fputil::ldexp(x, n);
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/setpayloadf16.cpp b/src/math/generic/setpayloadf16.cpp
new file mode 100644
index 0000000..98fc239
--- /dev/null
+++ b/src/math/generic/setpayloadf16.cpp
@@ -0,0 +1,19 @@
+//===-- Implementation of setpayloadf16 function --------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/setpayloadf16.h"
+#include "src/__support/FPUtil/BasicOperations.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(int, setpayloadf16, (float16 * res, float16 pl)) {
+  return static_cast<int>(fputil::setpayload</*IsSignaling=*/false>(*res, pl));
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/setpayloadsigf16.cpp b/src/math/generic/setpayloadsigf16.cpp
new file mode 100644
index 0000000..c79620f
--- /dev/null
+++ b/src/math/generic/setpayloadsigf16.cpp
@@ -0,0 +1,19 @@
+//===-- Implementation of setpayloadsigf16 function -----------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/setpayloadsigf16.h"
+#include "src/__support/FPUtil/BasicOperations.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(int, setpayloadsigf16, (float16 * res, float16 pl)) {
+  return static_cast<int>(fputil::setpayload</*IsSignaling=*/true>(*res, pl));
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/sqrt.cpp b/src/math/generic/sqrt.cpp
index b4d0278..f33b0a2 100644
--- a/src/math/generic/sqrt.cpp
+++ b/src/math/generic/sqrt.cpp
@@ -12,6 +12,6 @@
 
 namespace LIBC_NAMESPACE {
 
-LLVM_LIBC_FUNCTION(double, sqrt, (double x)) { return fputil::sqrt(x); }
+LLVM_LIBC_FUNCTION(double, sqrt, (double x)) { return fputil::sqrt<double>(x); }
 
 } // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/sqrtf.cpp b/src/math/generic/sqrtf.cpp
index bc74252..26a53e9 100644
--- a/src/math/generic/sqrtf.cpp
+++ b/src/math/generic/sqrtf.cpp
@@ -12,6 +12,6 @@
 
 namespace LIBC_NAMESPACE {
 
-LLVM_LIBC_FUNCTION(float, sqrtf, (float x)) { return fputil::sqrt(x); }
+LLVM_LIBC_FUNCTION(float, sqrtf, (float x)) { return fputil::sqrt<float>(x); }
 
 } // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/sqrtf128.cpp b/src/math/generic/sqrtf128.cpp
index 0196c3e..70e28dd 100644
--- a/src/math/generic/sqrtf128.cpp
+++ b/src/math/generic/sqrtf128.cpp
@@ -12,6 +12,8 @@
 
 namespace LIBC_NAMESPACE {
 
-LLVM_LIBC_FUNCTION(float128, sqrtf128, (float128 x)) { return fputil::sqrt(x); }
+LLVM_LIBC_FUNCTION(float128, sqrtf128, (float128 x)) {
+  return fputil::sqrt<float128>(x);
+}
 
 } // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/sqrtl.cpp b/src/math/generic/sqrtl.cpp
index b2aaa27..9f0cc87 100644
--- a/src/math/generic/sqrtl.cpp
+++ b/src/math/generic/sqrtl.cpp
@@ -13,7 +13,7 @@
 namespace LIBC_NAMESPACE {
 
 LLVM_LIBC_FUNCTION(long double, sqrtl, (long double x)) {
-  return fputil::sqrt(x);
+  return fputil::sqrt<long double>(x);
 }
 
 } // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/totalorderf16.cpp b/src/math/generic/totalorderf16.cpp
new file mode 100644
index 0000000..e43beb3
--- /dev/null
+++ b/src/math/generic/totalorderf16.cpp
@@ -0,0 +1,19 @@
+//===-- Implementation of totalorderf16 function --------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/totalorderf16.h"
+#include "src/__support/FPUtil/BasicOperations.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(int, totalorderf16, (const float16 *x, const float16 *y)) {
+  return static_cast<int>(fputil::totalorder(*x, *y));
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/generic/totalordermagf16.cpp b/src/math/generic/totalordermagf16.cpp
new file mode 100644
index 0000000..09d04fb
--- /dev/null
+++ b/src/math/generic/totalordermagf16.cpp
@@ -0,0 +1,20 @@
+//===-- Implementation of totalordermagf16 function -----------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/math/totalordermagf16.h"
+#include "src/__support/FPUtil/BasicOperations.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(int, totalordermagf16,
+                   (const float16 *x, const float16 *y)) {
+  return static_cast<int>(fputil::totalordermag(*x, *y));
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/math/getpayloadf16.h b/src/math/getpayloadf16.h
new file mode 100644
index 0000000..1349dfd
--- /dev/null
+++ b/src/math/getpayloadf16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for getpayloadf16 -----------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_GETPAYLOADF16_H
+#define LLVM_LIBC_SRC_MATH_GETPAYLOADF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+float16 getpayloadf16(const float16 *x);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_GETPAYLOADF16_H
diff --git a/src/math/ilogbf16.h b/src/math/ilogbf16.h
new file mode 100644
index 0000000..4884a14
--- /dev/null
+++ b/src/math/ilogbf16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for ilogbf16 ----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_ILOGBF16_H
+#define LLVM_LIBC_SRC_MATH_ILOGBF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+int ilogbf16(float16 x);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_ILOGBF16_H
diff --git a/src/math/ldexpf16.h b/src/math/ldexpf16.h
new file mode 100644
index 0000000..7303610
--- /dev/null
+++ b/src/math/ldexpf16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for ldexpf16 ----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_LDEXPF16_H
+#define LLVM_LIBC_SRC_MATH_LDEXPF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+float16 ldexpf16(float16 x, int exp);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_LDEXPF16_H
diff --git a/src/math/llogbf16.h b/src/math/llogbf16.h
new file mode 100644
index 0000000..267ae41
--- /dev/null
+++ b/src/math/llogbf16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for llogbf16 ----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_LLOGBF16_H
+#define LLVM_LIBC_SRC_MATH_LLOGBF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+long llogbf16(float16 x);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_LLOGBF16_H
diff --git a/src/math/logbf16.h b/src/math/logbf16.h
new file mode 100644
index 0000000..8082e06
--- /dev/null
+++ b/src/math/logbf16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for logbf16 -----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_LOGBF16_H
+#define LLVM_LIBC_SRC_MATH_LOGBF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+float16 logbf16(float16 x);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_LOGBF16_H
diff --git a/src/math/modff16.h b/src/math/modff16.h
new file mode 100644
index 0000000..a3017c5
--- /dev/null
+++ b/src/math/modff16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for modff16 -----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_MODFF16_H
+#define LLVM_LIBC_SRC_MATH_MODFF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+float16 modff16(float16 x, float16 *iptr);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_MODFF16_H
diff --git a/src/math/nanf16.h b/src/math/nanf16.h
new file mode 100644
index 0000000..c2db4ba
--- /dev/null
+++ b/src/math/nanf16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for nanf16 ------------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_NANF16_H
+#define LLVM_LIBC_SRC_MATH_NANF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+float16 nanf16(const char *arg);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_NANF16_H
diff --git a/src/math/remainderf16.h b/src/math/remainderf16.h
new file mode 100644
index 0000000..e23eead
--- /dev/null
+++ b/src/math/remainderf16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for remainderf16 ------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_REMAINDERF16_H
+#define LLVM_LIBC_SRC_MATH_REMAINDERF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+float16 remainderf16(float16 x, float16 y);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_REMAINDERF16_H
diff --git a/src/math/remquof128.h b/src/math/remquof128.h
new file mode 100644
index 0000000..e9db1ef
--- /dev/null
+++ b/src/math/remquof128.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for remquof128 --------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_REMQUOF128_H
+#define LLVM_LIBC_SRC_MATH_REMQUOF128_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+float128 remquof128(float128 x, float128 y, int *exp);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_REMQUOF128_H
diff --git a/src/math/remquof16.h b/src/math/remquof16.h
new file mode 100644
index 0000000..fee848c
--- /dev/null
+++ b/src/math/remquof16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for remquof16 ---------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_REMQUOF16_H
+#define LLVM_LIBC_SRC_MATH_REMQUOF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+float16 remquof16(float16 x, float16 y, int *exp);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_REMQUOF16_H
diff --git a/src/math/scalblnf16.h b/src/math/scalblnf16.h
new file mode 100644
index 0000000..be93fab
--- /dev/null
+++ b/src/math/scalblnf16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for scalblnf16 --------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_SCALBLNF16_H
+#define LLVM_LIBC_SRC_MATH_SCALBLNF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+float16 scalblnf16(float16 x, long n);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_SCALBLNF16_H
diff --git a/src/math/scalbnf16.h b/src/math/scalbnf16.h
new file mode 100644
index 0000000..95e4862
--- /dev/null
+++ b/src/math/scalbnf16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for scalbnf16 ---------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_SCALBNF16_H
+#define LLVM_LIBC_SRC_MATH_SCALBNF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+float16 scalbnf16(float16 x, int n);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_SCALBNF16_H
diff --git a/src/math/setpayloadf16.h b/src/math/setpayloadf16.h
new file mode 100644
index 0000000..8705e28
--- /dev/null
+++ b/src/math/setpayloadf16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for setpayloadf16 -----------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_SETPAYLOADF16_H
+#define LLVM_LIBC_SRC_MATH_SETPAYLOADF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+int setpayloadf16(float16 *res, float16 pl);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_SETPAYLOADF16_H
diff --git a/src/math/setpayloadsigf16.h b/src/math/setpayloadsigf16.h
new file mode 100644
index 0000000..ee9bc38
--- /dev/null
+++ b/src/math/setpayloadsigf16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for setpayloadsigf16 --------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_SETPAYLOADSIGF16_H
+#define LLVM_LIBC_SRC_MATH_SETPAYLOADSIGF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+int setpayloadsigf16(float16 *res, float16 pl);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_SETPAYLOADSIGF16_H
diff --git a/src/math/totalorderf16.h b/src/math/totalorderf16.h
new file mode 100644
index 0000000..f539014
--- /dev/null
+++ b/src/math/totalorderf16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for totalorderf16 -----------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_TOTALORDERF16_H
+#define LLVM_LIBC_SRC_MATH_TOTALORDERF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+int totalorderf16(const float16 *x, const float16 *y);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_TOTALORDERF16_H
diff --git a/src/math/totalordermagf16.h b/src/math/totalordermagf16.h
new file mode 100644
index 0000000..8c6621b
--- /dev/null
+++ b/src/math/totalordermagf16.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for totalordermagf16 --------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_MATH_TOTALORDERMAGF16_H
+#define LLVM_LIBC_SRC_MATH_TOTALORDERMAGF16_H
+
+#include "src/__support/macros/properties/types.h"
+
+namespace LIBC_NAMESPACE {
+
+int totalordermagf16(const float16 *x, const float16 *y);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_MATH_TOTALORDERMAGF16_H
diff --git a/src/pthread/pthread_rwlock_destroy.cpp b/src/pthread/pthread_rwlock_destroy.cpp
new file mode 100644
index 0000000..d82bb37
--- /dev/null
+++ b/src/pthread/pthread_rwlock_destroy.cpp
@@ -0,0 +1,33 @@
+//===-- Implementation for Rwlock's destroy function ----------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/pthread/pthread_rwlock_destroy.h"
+
+#include "src/__support/common.h"
+#include "src/__support/threads/linux/rwlock.h"
+
+#include <errno.h>
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(int, pthread_rwlock_destroy, (pthread_rwlock_t * rwlock)) {
+  if (!rwlock)
+    return EINVAL;
+  auto *rw = reinterpret_cast<RwLock *>(rwlock);
+  RwLock::LockResult res = rw->check_for_destroy();
+
+  // this is currently no-op, but we still call the destructor as a symmetry
+  // to its constructor call;
+  if (res == RwLock::LockResult::Success)
+    rw->~RwLock();
+
+  return static_cast<int>(res);
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/pthread/pthread_rwlock_destroy.h b/src/pthread/pthread_rwlock_destroy.h
new file mode 100644
index 0000000..f845e80
--- /dev/null
+++ b/src/pthread/pthread_rwlock_destroy.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for Rwlock's destroy function -------*-C++-*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_DESTROY_H
+#define LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_DESTROY_H
+
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+int pthread_rwlock_destroy(pthread_rwlock_t *rwlock);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_DESTROY_H
diff --git a/src/pthread/pthread_rwlock_init.cpp b/src/pthread/pthread_rwlock_init.cpp
new file mode 100644
index 0000000..b1b58aa
--- /dev/null
+++ b/src/pthread/pthread_rwlock_init.cpp
@@ -0,0 +1,67 @@
+//===-- Linux implementation of the pthread_rwlock_init function ----------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/pthread/pthread_rwlock_init.h"
+
+#include "src/__support/CPP/new.h"
+#include "src/__support/common.h"
+#include "src/__support/libc_assert.h"
+#include "src/__support/threads/linux/rwlock.h"
+
+#include <errno.h>
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+static_assert(
+    sizeof(RwLock) == sizeof(pthread_rwlock_t) &&
+        alignof(RwLock) == alignof(pthread_rwlock_t),
+    "The public pthread_rwlock_t type must be of the same size and alignment "
+    "as the internal rwlock type.");
+
+LLVM_LIBC_FUNCTION(int, pthread_rwlock_init,
+                   (pthread_rwlock_t * rwlock,
+                    const pthread_rwlockattr_t *__restrict attr)) {
+  pthread_rwlockattr_t rwlockattr{
+      /*pshared=*/PTHREAD_PROCESS_PRIVATE,
+      /*pref*/ PTHREAD_RWLOCK_PREFER_READER_NP,
+  };
+  // POSIX does not specify this check, so we add an assertion to catch it.
+  LIBC_ASSERT(rwlock && "rwlock is null");
+  if (attr)
+    rwlockattr = *attr;
+
+  // PTHREAD_RWLOCK_PREFER_WRITER_NP is not supported.
+  rwlock::Role preference;
+  switch (rwlockattr.pref) {
+  case PTHREAD_RWLOCK_PREFER_READER_NP:
+    preference = rwlock::Role::Reader;
+    break;
+  case PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP:
+    preference = rwlock::Role::Writer;
+    break;
+  default:
+    return EINVAL;
+  }
+  bool is_pshared;
+  switch (rwlockattr.pshared) {
+  case PTHREAD_PROCESS_PRIVATE:
+    is_pshared = false;
+    break;
+  case PTHREAD_PROCESS_SHARED:
+    is_pshared = true;
+    break;
+  default:
+    return EINVAL;
+  }
+
+  new (rwlock) RwLock(preference, is_pshared);
+  return 0;
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/pthread/pthread_rwlock_init.h b/src/pthread/pthread_rwlock_init.h
new file mode 100644
index 0000000..78d2934
--- /dev/null
+++ b/src/pthread/pthread_rwlock_init.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for pthread_rwlock_init function ---*- C++-*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_INIT_H
+#define LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_INIT_H
+
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+int pthread_rwlock_init(pthread_rwlock_t *rwlock,
+                        const pthread_rwlockattr_t *__restrict attr);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_INIT_H
diff --git a/src/pthread/pthread_rwlock_rdlock.cpp b/src/pthread/pthread_rwlock_rdlock.cpp
new file mode 100644
index 0000000..e9aee5d
--- /dev/null
+++ b/src/pthread/pthread_rwlock_rdlock.cpp
@@ -0,0 +1,32 @@
+//===-- Implementation of the Rwlock's rdlock function --------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/pthread/pthread_rwlock_rdlock.h"
+
+#include "src/__support/common.h"
+#include "src/__support/threads/linux/rwlock.h"
+
+#include <errno.h>
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+static_assert(
+    sizeof(RwLock) == sizeof(pthread_rwlock_t) &&
+        alignof(RwLock) == alignof(pthread_rwlock_t),
+    "The public pthread_rwlock_t type must be of the same size and alignment "
+    "as the internal rwlock type.");
+
+LLVM_LIBC_FUNCTION(int, pthread_rwlock_rdlock, (pthread_rwlock_t * rwlock)) {
+  if (!rwlock)
+    return EINVAL;
+  RwLock *rw = reinterpret_cast<RwLock *>(rwlock);
+  return static_cast<int>(rw->read_lock());
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/pthread/pthread_rwlock_rdlock.h b/src/pthread/pthread_rwlock_rdlock.h
new file mode 100644
index 0000000..7902773
--- /dev/null
+++ b/src/pthread/pthread_rwlock_rdlock.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for Rwlock's rdlock function -------*- C++-*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_RDLOCK_H
+#define LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_RDLOCK_H
+
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_RDLOCK_H
diff --git a/src/pthread/pthread_rwlock_timedrdlock.cpp b/src/pthread/pthread_rwlock_timedrdlock.cpp
new file mode 100644
index 0000000..6ce69ea
--- /dev/null
+++ b/src/pthread/pthread_rwlock_timedrdlock.cpp
@@ -0,0 +1,49 @@
+//===-- Implementation of the Rwlock's timedrdlock function ---------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/pthread/pthread_rwlock_timedrdlock.h"
+
+#include "src/__support/common.h"
+#include "src/__support/libc_assert.h"
+#include "src/__support/macros/optimization.h"
+#include "src/__support/threads/linux/rwlock.h"
+#include "src/__support/time/linux/abs_timeout.h"
+
+#include <errno.h>
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+static_assert(
+    sizeof(RwLock) == sizeof(pthread_rwlock_t) &&
+        alignof(RwLock) == alignof(pthread_rwlock_t),
+    "The public pthread_rwlock_t type must be of the same size and alignment "
+    "as the internal rwlock type.");
+
+LLVM_LIBC_FUNCTION(int, pthread_rwlock_timedrdlock,
+                   (pthread_rwlock_t * rwlock,
+                    const struct timespec *abstime)) {
+  if (!rwlock)
+    return EINVAL;
+  RwLock *rw = reinterpret_cast<RwLock *>(rwlock);
+  LIBC_ASSERT(abstime && "timedrdlock called with a null timeout");
+  auto timeout =
+      internal::AbsTimeout::from_timespec(*abstime, /*is_realtime=*/true);
+  if (LIBC_LIKELY(timeout.has_value()))
+    return static_cast<int>(rw->read_lock(timeout.value()));
+
+  switch (timeout.error()) {
+  case internal::AbsTimeout::Error::Invalid:
+    return EINVAL;
+  case internal::AbsTimeout::Error::BeforeEpoch:
+    return ETIMEDOUT;
+  }
+  __builtin_unreachable();
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/pthread/pthread_rwlock_timedrdlock.h b/src/pthread/pthread_rwlock_timedrdlock.h
new file mode 100644
index 0000000..dfa43f2
--- /dev/null
+++ b/src/pthread/pthread_rwlock_timedrdlock.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for Rwlock's timedrdlock function --*- C++-*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_TIMEDRDLOCK_H
+#define LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_TIMEDRDLOCK_H
+
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+int pthread_rwlock_timedrdlock(pthread_rwlock_t *__restrict rwlock,
+                               const struct timespec *__restrict abs_timeout);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_TIMEDRDLOCK_H
diff --git a/src/pthread/pthread_rwlock_timedwrlock.cpp b/src/pthread/pthread_rwlock_timedwrlock.cpp
new file mode 100644
index 0000000..ad3f913
--- /dev/null
+++ b/src/pthread/pthread_rwlock_timedwrlock.cpp
@@ -0,0 +1,43 @@
+//===-- Implementation for Rwlock's timedwrlock function ------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/pthread/pthread_rwlock_timedwrlock.h"
+
+#include "src/__support/common.h"
+#include "src/__support/libc_assert.h"
+#include "src/__support/macros/optimization.h"
+#include "src/__support/threads/linux/rwlock.h"
+#include "src/__support/time/linux/abs_timeout.h"
+
+#include <errno.h>
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(int, pthread_rwlock_timedwrlock,
+                   (pthread_rwlock_t *__restrict rwlock,
+                    const struct timespec *__restrict abstime)) {
+  if (!rwlock)
+    return EINVAL;
+  RwLock *rw = reinterpret_cast<RwLock *>(rwlock);
+  LIBC_ASSERT(abstime && "timedwrlock called with a null timeout");
+  auto timeout =
+      internal::AbsTimeout::from_timespec(*abstime, /*is_realtime=*/true);
+  if (LIBC_LIKELY(timeout.has_value()))
+    return static_cast<int>(rw->write_lock(timeout.value()));
+
+  switch (timeout.error()) {
+  case internal::AbsTimeout::Error::Invalid:
+    return EINVAL;
+  case internal::AbsTimeout::Error::BeforeEpoch:
+    return ETIMEDOUT;
+  }
+  __builtin_unreachable();
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/pthread/pthread_rwlock_timedwrlock.h b/src/pthread/pthread_rwlock_timedwrlock.h
new file mode 100644
index 0000000..a39d8de
--- /dev/null
+++ b/src/pthread/pthread_rwlock_timedwrlock.h
@@ -0,0 +1,21 @@
+//===-- Implementation header for Rwlock's timedwrlock function --*- C++-*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_TIMEDWRLOCK_H
+#define LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_TIMEDWRLOCK_H
+
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+int pthread_rwlock_timedwrlock(pthread_rwlock_t *__restrict rwlock,
+                               const struct timespec *__restrict abs_timeout);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_TIMEDWRLOCK_H
diff --git a/src/pthread/pthread_rwlock_tryrdlock.cpp b/src/pthread/pthread_rwlock_tryrdlock.cpp
new file mode 100644
index 0000000..9dc1bf0
--- /dev/null
+++ b/src/pthread/pthread_rwlock_tryrdlock.cpp
@@ -0,0 +1,32 @@
+//===-- Implementation of the Rwlock's tryrdlock function -----------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/pthread/pthread_rwlock_tryrdlock.h"
+
+#include "src/__support/common.h"
+#include "src/__support/threads/linux/rwlock.h"
+
+#include <errno.h>
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+static_assert(
+    sizeof(RwLock) == sizeof(pthread_rwlock_t) &&
+        alignof(RwLock) == alignof(pthread_rwlock_t),
+    "The public pthread_rwlock_t type must be of the same size and alignment "
+    "as the internal rwlock type.");
+
+LLVM_LIBC_FUNCTION(int, pthread_rwlock_tryrdlock, (pthread_rwlock_t * rwlock)) {
+  if (!rwlock)
+    return EINVAL;
+  RwLock *rw = reinterpret_cast<RwLock *>(rwlock);
+  return static_cast<int>(rw->try_read_lock());
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/pthread/pthread_rwlock_tryrdlock.h b/src/pthread/pthread_rwlock_tryrdlock.h
new file mode 100644
index 0000000..b07ab5b
--- /dev/null
+++ b/src/pthread/pthread_rwlock_tryrdlock.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for Rwlock's tryrdlock function ----*- C++-*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_TRYRDLOCK_H
+#define LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_TRYRDLOCK_H
+
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_TRYRDLOCK_H
diff --git a/src/pthread/pthread_rwlock_trywrlock.cpp b/src/pthread/pthread_rwlock_trywrlock.cpp
new file mode 100644
index 0000000..e4ace3c
--- /dev/null
+++ b/src/pthread/pthread_rwlock_trywrlock.cpp
@@ -0,0 +1,32 @@
+//===-- Implementation for Rwlock's trywrlock function -------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/pthread/pthread_rwlock_trywrlock.h"
+
+#include "src/__support/common.h"
+#include "src/__support/threads/linux/rwlock.h"
+
+#include <errno.h>
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+static_assert(
+    sizeof(RwLock) == sizeof(pthread_rwlock_t) &&
+        alignof(RwLock) == alignof(pthread_rwlock_t),
+    "The public pthread_rwlock_t type must be of the same size and alignment "
+    "as the internal rwlock type.");
+
+LLVM_LIBC_FUNCTION(int, pthread_rwlock_trywrlock, (pthread_rwlock_t * rwlock)) {
+  if (!rwlock)
+    return EINVAL;
+  RwLock *rw = reinterpret_cast<RwLock *>(rwlock);
+  return static_cast<int>(rw->try_write_lock());
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/pthread/pthread_rwlock_trywrlock.h b/src/pthread/pthread_rwlock_trywrlock.h
new file mode 100644
index 0000000..fc146c6
--- /dev/null
+++ b/src/pthread/pthread_rwlock_trywrlock.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for Rwlock's trywrlock function ----*- C++-*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_TRYWRLOCK_H
+#define LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_TRYWRLOCK_H
+
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+int pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_TRYWRLOCK_H
diff --git a/src/pthread/pthread_rwlock_unlock.cpp b/src/pthread/pthread_rwlock_unlock.cpp
new file mode 100644
index 0000000..21cedf4
--- /dev/null
+++ b/src/pthread/pthread_rwlock_unlock.cpp
@@ -0,0 +1,26 @@
+//===-- Implementation for Rwlock's unlock function -----------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/pthread/pthread_rwlock_unlock.h"
+
+#include "src/__support/common.h"
+#include "src/__support/threads/linux/rwlock.h"
+
+#include <errno.h>
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(int, pthread_rwlock_unlock, (pthread_rwlock_t * rwlock)) {
+  if (!rwlock)
+    return EINVAL;
+  auto *rw = reinterpret_cast<RwLock *>(rwlock);
+  return static_cast<int>(rw->unlock());
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/pthread/pthread_rwlock_unlock.h b/src/pthread/pthread_rwlock_unlock.h
new file mode 100644
index 0000000..b9a72f1
--- /dev/null
+++ b/src/pthread/pthread_rwlock_unlock.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for Rwlock's unlock function -------*- C++-*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_UNLOCK_H
+#define LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_UNLOCK_H
+
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+int pthread_rwlock_unlock(pthread_rwlock_t *rwlock);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_UNLOCK_H
diff --git a/src/pthread/pthread_rwlock_wrlock.cpp b/src/pthread/pthread_rwlock_wrlock.cpp
new file mode 100644
index 0000000..5d3868a
--- /dev/null
+++ b/src/pthread/pthread_rwlock_wrlock.cpp
@@ -0,0 +1,32 @@
+//===-- Implementation for Rwlock's wrlock function -------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/pthread/pthread_rwlock_wrlock.h"
+
+#include "src/__support/common.h"
+#include "src/__support/threads/linux/rwlock.h"
+
+#include <errno.h>
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+static_assert(
+    sizeof(RwLock) == sizeof(pthread_rwlock_t) &&
+        alignof(RwLock) == alignof(pthread_rwlock_t),
+    "The public pthread_rwlock_t type must be of the same size and alignment "
+    "as the internal rwlock type.");
+
+LLVM_LIBC_FUNCTION(int, pthread_rwlock_wrlock, (pthread_rwlock_t * rwlock)) {
+  if (!rwlock)
+    return EINVAL;
+  RwLock *rw = reinterpret_cast<RwLock *>(rwlock);
+  return static_cast<int>(rw->write_lock());
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/pthread/pthread_rwlock_wrlock.h b/src/pthread/pthread_rwlock_wrlock.h
new file mode 100644
index 0000000..ba77c1f
--- /dev/null
+++ b/src/pthread/pthread_rwlock_wrlock.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for Rwlock's wrlock function -------*- C++-*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_WRLOCK_H
+#define LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_WRLOCK_H
+
+#include <pthread.h>
+
+namespace LIBC_NAMESPACE {
+
+int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_PTHREAD_PTHREAD_RWLOCK_WRLOCK_H
diff --git a/src/setjmp/arm/longjmp.cpp b/src/setjmp/arm/longjmp.cpp
new file mode 100644
index 0000000..a088b58
--- /dev/null
+++ b/src/setjmp/arm/longjmp.cpp
@@ -0,0 +1,74 @@
+
+//===-- Implementation of longjmp -----------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/setjmp/longjmp.h"
+#include "src/__support/common.h"
+
+namespace LIBC_NAMESPACE {
+
+#if defined(__thumb__) && __ARM_ARCH_ISA_THUMB == 1
+
+[[gnu::naked, gnu::target("thumb")]]
+LLVM_LIBC_FUNCTION(void, longjmp, (__jmp_buf * buf, int val)) {
+  asm(R"(
+      # Reload r4, r5, r6, r7.
+      ldmia r0!, {r4-r7}
+
+      # Reload r8, r9. They cannot appear in register lists so load them
+      # into the lower registers, then move them into place.
+      ldmia r0!, {r2-r3}
+      mov r8, r2
+      mov r9, r3
+
+      # Reload r10, r11. They cannot appear in register lists so load them
+      # into the lower registers, then move them into place.
+      ldmia r0!, {r2-r3}
+      mov r10, r2
+      mov r11, r3
+
+      # Reload sp, lr. They cannot appear in register lists so load them
+      # into the lower registers, then move them into place.
+      ldmia r0!, {r2-r3}
+      mov sp, r2
+      mov lr, r3
+
+      # return val ?: 1;
+      movs r0, r1
+      bne .Lret_val
+      movs r0, #1
+
+    .Lret_val:
+      bx lr)");
+}
+
+#else // Thumb2 or ARM
+
+// TODO(https://github.com/llvm/llvm-project/issues/94061): fp registers
+// (d0-d16)
+// TODO(https://github.com/llvm/llvm-project/issues/94062): pac+bti
+[[gnu::naked]]
+LLVM_LIBC_FUNCTION(void, longjmp, (__jmp_buf * buf, int val)) {
+  asm(R"(
+      # While sp may appear in a register list for ARM mode, it may not for
+      # Thumb2 mode. Just load the previous value of sp into r12 then move it
+      # into sp, so that this code is portable between ARM and Thumb2.
+
+      ldm r0, {r4-r12, lr}
+      mov sp, r12
+
+      # return val ?: 1;
+      movs r0, r1
+      it eq
+      moveq r0, #1
+      bx lr)");
+}
+
+#endif
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/setjmp/arm/setjmp.cpp b/src/setjmp/arm/setjmp.cpp
new file mode 100644
index 0000000..287e09c
--- /dev/null
+++ b/src/setjmp/arm/setjmp.cpp
@@ -0,0 +1,64 @@
+//===-- Implementation of setjmp ------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/__support/common.h"
+#include "src/setjmp/setjmp_impl.h"
+
+namespace LIBC_NAMESPACE {
+
+#if defined(__thumb__) && __ARM_ARCH_ISA_THUMB == 1
+
+[[gnu::naked, gnu::target("thumb")]]
+LLVM_LIBC_FUNCTION(int, setjmp, (__jmp_buf * buf)) {
+  asm(R"(
+      # Store r4, r5, r6, and r7 into buf.
+      stmia r0!, {r4-r7}
+
+      # Store r8, r9, r10, r11, sp, and lr into buf. Thumb(1) doesn't support
+      # the high registers > r7 in stmia, so move them into lower GPRs first.
+      # Thumb(1) also doesn't support using str with sp or lr, move them
+      # together with the rest.
+      mov r1, r8
+      mov r2, r9
+      mov r3, r10
+      stmia r0!, {r1-r3}
+
+      mov r1, r11
+      mov r2, sp
+      mov r3, lr
+      stmia r0!, {r1-r3}
+
+      # Return 0.
+      movs r0, #0
+      bx lr)");
+}
+
+#else // Thumb2 or ARM
+
+// TODO(https://github.com/llvm/llvm-project/issues/94061): fp registers
+// (d0-d16)
+// TODO(https://github.com/llvm/llvm-project/issues/94062): pac+bti
+[[gnu::naked]]
+LLVM_LIBC_FUNCTION(int, setjmp, (__jmp_buf * buf)) {
+  asm(R"(
+      # While sp may appear in a register list for ARM mode, it may not for
+      # Thumb2 mode. Just move it into r12 then stm that, so that this code
+      # is portable between ARM and Thumb2.
+      mov r12, sp
+
+      # Store r4, r5, r6, r7, r8, r9, r10, r11, sp, and lr into buf.
+      stm r0, {r4-r12, lr}
+
+      # Return zero.
+      mov r0, #0
+      bx lr)");
+}
+
+#endif
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/stdio/baremetal/printf.cpp b/src/stdio/baremetal/printf.cpp
index 597078b..b240371 100644
--- a/src/stdio/baremetal/printf.cpp
+++ b/src/stdio/baremetal/printf.cpp
@@ -7,6 +7,7 @@
 //===----------------------------------------------------------------------===//
 
 #include "src/stdio/printf.h"
+#include "src/__support/OSUtil/io.h"
 #include "src/__support/arg_list.h"
 #include "src/stdio/printf_core/core_structs.h"
 #include "src/stdio/printf_core/printf_main.h"
@@ -14,19 +15,12 @@
 
 #include <stdarg.h>
 
-// TODO(https://github.com/llvm/llvm-project/issues/94685) unify baremetal hooks
-
-// This is intended to be provided by the vendor.
-extern "C" size_t __llvm_libc_raw_write(const char *s, size_t size);
-
 namespace LIBC_NAMESPACE {
 
 namespace {
 
 LIBC_INLINE int raw_write_hook(cpp::string_view new_str, void *) {
-  size_t written = __llvm_libc_raw_write(new_str.data(), new_str.size());
-  if (written != new_str.size())
-    return printf_core::FILE_WRITE_ERROR;
+  write_to_stderr(new_str);
   return printf_core::WRITE_OK;
 }
 
diff --git a/src/stdio/baremetal/putchar.cpp b/src/stdio/baremetal/putchar.cpp
new file mode 100644
index 0000000..23e9745
--- /dev/null
+++ b/src/stdio/baremetal/putchar.cpp
@@ -0,0 +1,23 @@
+//===-- Baremetal Implementation of putchar -------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/stdio/putchar.h"
+#include "src/__support/CPP/string_view.h"
+#include "src/__support/OSUtil/io.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(int, putchar, (int c)) {
+  char uc = static_cast<char>(c);
+
+  write_to_stderr(cpp::string_view(&uc, 1));
+
+  return 0;
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/stdio/baremetal/vprintf.cpp b/src/stdio/baremetal/vprintf.cpp
new file mode 100644
index 0000000..cd15412
--- /dev/null
+++ b/src/stdio/baremetal/vprintf.cpp
@@ -0,0 +1,49 @@
+//===-- Implementation of vprintf -------------------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/stdio/vprintf.h"
+#include "src/__support/OSUtil/io.h"
+#include "src/__support/arg_list.h"
+#include "src/stdio/printf_core/core_structs.h"
+#include "src/stdio/printf_core/printf_main.h"
+#include "src/stdio/printf_core/writer.h"
+
+#include <stdarg.h>
+
+namespace LIBC_NAMESPACE {
+
+namespace {
+
+LIBC_INLINE int raw_write_hook(cpp::string_view new_str, void *) {
+  write_to_stderr(new_str);
+  return printf_core::WRITE_OK;
+}
+
+} // namespace
+
+LLVM_LIBC_FUNCTION(int, vprintf,
+                   (const char *__restrict format, va_list vlist)) {
+  internal::ArgList args(vlist); // This holder class allows for easier copying
+                                 // and pointer semantics, as well as handling
+                                 // destruction automatically.
+  constexpr size_t BUFF_SIZE = 1024;
+  char buffer[BUFF_SIZE];
+
+  printf_core::WriteBuffer wb(buffer, BUFF_SIZE, &raw_write_hook, nullptr);
+  printf_core::Writer writer(&wb);
+
+  int retval = printf_core::printf_main(&writer, format, args);
+
+  int flushval = wb.overflow_write("");
+  if (flushval != printf_core::WRITE_OK)
+    retval = flushval;
+
+  return retval;
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/stdio/fdopen.h b/src/stdio/fdopen.h
new file mode 100644
index 0000000..158a133
--- /dev/null
+++ b/src/stdio/fdopen.h
@@ -0,0 +1,20 @@
+//===-- Implementation header of open ---------------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_SRC_STDIO_FDOPEN_H
+#define LLVM_LIBC_SRC_STDIO_FDOPEN_H
+
+#include <stdio.h>
+
+namespace LIBC_NAMESPACE {
+
+FILE *fdopen(int fd, const char *mode);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_STDIO_FDOPEN_H
diff --git a/src/stdio/linux/fdopen.cpp b/src/stdio/linux/fdopen.cpp
new file mode 100644
index 0000000..a1d08ee
--- /dev/null
+++ b/src/stdio/linux/fdopen.cpp
@@ -0,0 +1,25 @@
+//===-- Implementation of fdopen --------------------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/stdio/fdopen.h"
+
+#include "src/__support/File/linux/file.h"
+#include "src/errno/libc_errno.h"
+
+namespace LIBC_NAMESPACE {
+
+LLVM_LIBC_FUNCTION(::FILE *, fdopen, (int fd, const char *mode)) {
+  auto result = LIBC_NAMESPACE::create_file_from_fd(fd, mode);
+  if (!result.has_value()) {
+    libc_errno = result.error();
+    return nullptr;
+  }
+  return reinterpret_cast<::FILE *>(result.value());
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/stdio/printf_core/float_dec_converter.h b/src/stdio/printf_core/float_dec_converter.h
index 666e4c9..1237db6 100644
--- a/src/stdio/printf_core/float_dec_converter.h
+++ b/src/stdio/printf_core/float_dec_converter.h
@@ -502,25 +502,22 @@ LIBC_INLINE int convert_float_decimal_typed(Writer *writer,
 
   const size_t positive_blocks = float_converter.get_positive_blocks();
 
-  if (positive_blocks >= 0) {
-    // This loop iterates through the number a block at a time until it finds a
-    // block that is not zero or it hits the decimal point. This is because all
-    // zero blocks before the first nonzero digit or the decimal point are
-    // ignored (no leading zeroes, at least at this stage).
-    int32_t i = static_cast<int32_t>(positive_blocks) - 1;
-    for (; i >= 0; --i) {
-      BlockInt digits = float_converter.get_positive_block(i);
-      if (nonzero) {
-        RET_IF_RESULT_NEGATIVE(float_writer.write_middle_block(digits));
-      } else if (digits != 0) {
-        size_t blocks_before_decimal = i;
-        float_writer.init((blocks_before_decimal * BLOCK_SIZE) +
-                              (has_decimal_point ? 1 : 0) + precision,
-                          blocks_before_decimal * BLOCK_SIZE);
-        float_writer.write_first_block(digits);
-
-        nonzero = true;
-      }
+  // This loop iterates through the number a block at a time until it finds a
+  // block that is not zero or it hits the decimal point. This is because all
+  // zero blocks before the first nonzero digit or the decimal point are
+  // ignored (no leading zeroes, at least at this stage).
+  for (int32_t i = static_cast<int32_t>(positive_blocks) - 1; i >= 0; --i) {
+    BlockInt digits = float_converter.get_positive_block(i);
+    if (nonzero) {
+      RET_IF_RESULT_NEGATIVE(float_writer.write_middle_block(digits));
+    } else if (digits != 0) {
+      size_t blocks_before_decimal = i;
+      float_writer.init((blocks_before_decimal * BLOCK_SIZE) +
+                            (has_decimal_point ? 1 : 0) + precision,
+                        blocks_before_decimal * BLOCK_SIZE);
+      float_writer.write_first_block(digits);
+
+      nonzero = true;
     }
   }
 
diff --git a/src/stdio/printf_core/float_hex_converter.h b/src/stdio/printf_core/float_hex_converter.h
index 68a4ba6..8fac36d 100644
--- a/src/stdio/printf_core/float_hex_converter.h
+++ b/src/stdio/printf_core/float_hex_converter.h
@@ -199,13 +199,13 @@ LIBC_INLINE int convert_float_hex_exp(Writer *writer,
   constexpr cpp::string_view HEXADECIMAL_POINT(".");
 
   // This is for the letter 'p' before the exponent.
-  const char exp_seperator = a + ('p' - 'a');
-  constexpr int EXP_SEPERATOR_LEN = 1;
+  const char exp_separator = a + ('p' - 'a');
+  constexpr int EXP_SEPARATOR_LEN = 1;
 
   padding = static_cast<int>(to_conv.min_width - (sign_char > 0 ? 1 : 0) -
                              PREFIX_LEN - mant_digits - trailing_zeroes -
                              static_cast<int>(has_hexadecimal_point) -
-                             EXP_SEPERATOR_LEN - (EXP_LEN - exp_cur));
+                             EXP_SEPARATOR_LEN - (EXP_LEN - exp_cur));
   if (padding < 0)
     padding = 0;
 
@@ -223,7 +223,7 @@ LIBC_INLINE int convert_float_hex_exp(Writer *writer,
       RET_IF_RESULT_NEGATIVE(writer->write({mant_buffer + 1, mant_digits - 1}));
     if (trailing_zeroes > 0)
       RET_IF_RESULT_NEGATIVE(writer->write('0', trailing_zeroes));
-    RET_IF_RESULT_NEGATIVE(writer->write(exp_seperator));
+    RET_IF_RESULT_NEGATIVE(writer->write(exp_separator));
     RET_IF_RESULT_NEGATIVE(
         writer->write({exp_buffer + exp_cur, EXP_LEN - exp_cur}));
     if (padding > 0)
@@ -247,7 +247,7 @@ LIBC_INLINE int convert_float_hex_exp(Writer *writer,
       RET_IF_RESULT_NEGATIVE(writer->write({mant_buffer + 1, mant_digits - 1}));
     if (trailing_zeroes > 0)
       RET_IF_RESULT_NEGATIVE(writer->write('0', trailing_zeroes));
-    RET_IF_RESULT_NEGATIVE(writer->write(exp_seperator));
+    RET_IF_RESULT_NEGATIVE(writer->write(exp_separator));
     RET_IF_RESULT_NEGATIVE(
         writer->write({exp_buffer + exp_cur, EXP_LEN - exp_cur}));
   }
diff --git a/src/stdio/putchar.h b/src/stdio/putchar.h
index 99a7453..e458e31 100644
--- a/src/stdio/putchar.h
+++ b/src/stdio/putchar.h
@@ -9,8 +9,6 @@
 #ifndef LLVM_LIBC_SRC_STDIO_PUTCHAR_H
 #define LLVM_LIBC_SRC_STDIO_PUTCHAR_H
 
-#include <stdio.h>
-
 namespace LIBC_NAMESPACE {
 
 int putchar(int c);
diff --git a/src/stdlib/free.h b/src/stdlib/free.h
index f802f1d..b3970fd 100644
--- a/src/stdlib/free.h
+++ b/src/stdlib/free.h
@@ -17,4 +17,4 @@ void free(void *ptr);
 
 } // namespace LIBC_NAMESPACE
 
-#endif // LLVM_LIBC_SRC_STDLIB_LDIV_H
+#endif // LLVM_LIBC_SRC_STDLIB_FREE_H
diff --git a/src/stdlib/freelist_malloc.cpp b/src/stdlib/freelist_malloc.cpp
new file mode 100644
index 0000000..4d3c42c
--- /dev/null
+++ b/src/stdlib/freelist_malloc.cpp
@@ -0,0 +1,45 @@
+//===-- Implementation for freelist_malloc --------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/__support/freelist_heap.h"
+#include "src/stdlib/calloc.h"
+#include "src/stdlib/free.h"
+#include "src/stdlib/malloc.h"
+#include "src/stdlib/realloc.h"
+
+#include <stddef.h>
+
+namespace LIBC_NAMESPACE {
+
+namespace {
+#ifdef LIBC_FREELIST_MALLOC_SIZE
+// This is set via the LIBC_CONF_FREELIST_MALLOC_BUFFER_SIZE configuration.
+constexpr size_t SIZE = LIBC_FREELIST_MALLOC_SIZE;
+#else
+#error "LIBC_FREELIST_MALLOC_SIZE was not defined for this build."
+#endif
+LIBC_CONSTINIT FreeListHeapBuffer<SIZE> freelist_heap_buffer;
+} // namespace
+
+FreeListHeap<> *freelist_heap = &freelist_heap_buffer;
+
+LLVM_LIBC_FUNCTION(void *, malloc, (size_t size)) {
+  return freelist_heap->allocate(size);
+}
+
+LLVM_LIBC_FUNCTION(void, free, (void *ptr)) { return freelist_heap->free(ptr); }
+
+LLVM_LIBC_FUNCTION(void *, calloc, (size_t num, size_t size)) {
+  return freelist_heap->calloc(num, size);
+}
+
+LLVM_LIBC_FUNCTION(void *, realloc, (void *ptr, size_t size)) {
+  return freelist_heap->realloc(ptr, size);
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/src/stdlib/realloc.h b/src/stdlib/realloc.h
new file mode 100644
index 0000000..6e025fa
--- /dev/null
+++ b/src/stdlib/realloc.h
@@ -0,0 +1,20 @@
+//===-- Implementation header for realloc -----------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include <stddef.h>
+
+#ifndef LLVM_LIBC_SRC_STDLIB_REALLOC_H
+#define LLVM_LIBC_SRC_STDLIB_REALLOC_H
+
+namespace LIBC_NAMESPACE {
+
+void *realloc(void *ptr, size_t size);
+
+} // namespace LIBC_NAMESPACE
+
+#endif // LLVM_LIBC_SRC_STDLIB_REALLOC_H
diff --git a/test/IntegrationTest/test.cpp b/test/IntegrationTest/test.cpp
index 3bdbe89..2751f31 100644
--- a/test/IntegrationTest/test.cpp
+++ b/test/IntegrationTest/test.cpp
@@ -6,9 +6,14 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "src/__support/common.h"
 #include <stddef.h>
 #include <stdint.h>
 
+#ifdef LIBC_TARGET_ARCH_IS_AARCH64
+#include "src/sys/auxv/getauxval.h"
+#endif
+
 // Integration tests rely on the following memory functions. This is because the
 // compiler code generation can emit calls to them. We want to map the external
 // entrypoint to the internal implementation of the function used for testing.
@@ -79,4 +84,12 @@ void *realloc(void *ptr, size_t s) {
 // Integration tests are linked with -nostdlib. BFD linker expects
 // __dso_handle when -nostdlib is used.
 void *__dso_handle = nullptr;
+
+#ifdef LIBC_TARGET_ARCH_IS_AARCH64
+// Due to historical reasons, libgcc on aarch64 may expect __getauxval to be
+// defined. See also https://gcc.gnu.org/pipermail/gcc-cvs/2020-June/300635.html
+unsigned long __getauxval(unsigned long id) {
+  return LIBC_NAMESPACE::getauxval(id);
+}
+#endif
 } // extern "C"
diff --git a/test/UnitTest/FPMatcher.h b/test/UnitTest/FPMatcher.h
index 26af5ce..86b8232 100644
--- a/test/UnitTest/FPMatcher.h
+++ b/test/UnitTest/FPMatcher.h
@@ -97,8 +97,10 @@ template <typename T> struct FPTest : public Test {
       LIBC_NAMESPACE::cpp::numeric_limits<StorageType>::max();                 \
   const T zero = FPBits::zero(Sign::POS).get_val();                            \
   const T neg_zero = FPBits::zero(Sign::NEG).get_val();                        \
-  const T aNaN = FPBits::quiet_nan().get_val();                                \
-  const T sNaN = FPBits::signaling_nan().get_val();                            \
+  const T aNaN = FPBits::quiet_nan(Sign::POS).get_val();                       \
+  const T neg_aNaN = FPBits::quiet_nan(Sign::NEG).get_val();                   \
+  const T sNaN = FPBits::signaling_nan(Sign::POS).get_val();                   \
+  const T neg_sNaN = FPBits::signaling_nan(Sign::NEG).get_val();               \
   const T inf = FPBits::inf(Sign::POS).get_val();                              \
   const T neg_inf = FPBits::inf(Sign::NEG).get_val();                          \
   const T min_normal = FPBits::min_normal().get_val();                         \
diff --git a/test/UnitTest/HermeticTestUtils.cpp b/test/UnitTest/HermeticTestUtils.cpp
index 349c182..ca854ad 100644
--- a/test/UnitTest/HermeticTestUtils.cpp
+++ b/test/UnitTest/HermeticTestUtils.cpp
@@ -6,9 +6,14 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "src/__support/common.h"
 #include <stddef.h>
 #include <stdint.h>
 
+#ifdef LIBC_TARGET_ARCH_IS_AARCH64
+#include "src/sys/auxv/getauxval.h"
+#endif
+
 namespace LIBC_NAMESPACE {
 
 int bcmp(const void *lhs, const void *rhs, size_t count);
@@ -19,6 +24,12 @@ void *memmove(void *dst, const void *src, size_t count);
 void *memset(void *ptr, int value, size_t count);
 int atexit(void (*func)(void));
 
+// TODO: It seems that some old test frameworks does not use
+// add_libc_hermetic_test properly. Such that they won't get correct linkage
+// against the object containing this function. We create a dummy function that
+// always returns 0 to indicate a failure.
+[[gnu::weak]] unsigned long getauxval(unsigned long id) { return 0; }
+
 } // namespace LIBC_NAMESPACE
 
 namespace {
@@ -102,6 +113,14 @@ void __cxa_pure_virtual() {
 // __dso_handle when -nostdlib is used.
 void *__dso_handle = nullptr;
 
+#ifdef LIBC_TARGET_ARCH_IS_AARCH64
+// Due to historical reasons, libgcc on aarch64 may expect __getauxval to be
+// defined. See also https://gcc.gnu.org/pipermail/gcc-cvs/2020-June/300635.html
+unsigned long __getauxval(unsigned long id) {
+  return LIBC_NAMESPACE::getauxval(id);
+}
+#endif
+
 } // extern "C"
 
 void *operator new(unsigned long size, void *ptr) { return ptr; }
diff --git a/test/integration/src/pthread/pthread_rwlock_test.cpp b/test/integration/src/pthread/pthread_rwlock_test.cpp
new file mode 100644
index 0000000..9175efe
--- /dev/null
+++ b/test/integration/src/pthread/pthread_rwlock_test.cpp
@@ -0,0 +1,478 @@
+//===-- Tests for pthread_rwlock ------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/__support/CPP/atomic.h"
+#include "src/__support/CPP/new.h"
+#include "src/__support/OSUtil/syscall.h"
+#include "src/__support/threads/linux/raw_mutex.h"
+#include "src/__support/threads/linux/rwlock.h"
+#include "src/__support/threads/sleep.h"
+#include "src/pthread/pthread_create.h"
+#include "src/pthread/pthread_join.h"
+#include "src/pthread/pthread_rwlock_destroy.h"
+#include "src/pthread/pthread_rwlock_init.h"
+#include "src/pthread/pthread_rwlock_rdlock.h"
+#include "src/pthread/pthread_rwlock_timedrdlock.h"
+#include "src/pthread/pthread_rwlock_timedwrlock.h"
+#include "src/pthread/pthread_rwlock_tryrdlock.h"
+#include "src/pthread/pthread_rwlock_trywrlock.h"
+#include "src/pthread/pthread_rwlock_unlock.h"
+#include "src/pthread/pthread_rwlock_wrlock.h"
+#include "src/pthread/pthread_rwlockattr_destroy.h"
+#include "src/pthread/pthread_rwlockattr_init.h"
+#include "src/pthread/pthread_rwlockattr_setkind_np.h"
+#include "src/pthread/pthread_rwlockattr_setpshared.h"
+#include "src/stdio/printf.h"
+#include "src/stdlib/exit.h"
+#include "src/stdlib/getenv.h"
+#include "src/sys/mman/mmap.h"
+#include "src/sys/mman/munmap.h"
+#include "src/sys/random/getrandom.h"
+#include "src/sys/wait/waitpid.h"
+#include "src/time/clock_gettime.h"
+#include "src/unistd/fork.h"
+#include "test/IntegrationTest/test.h"
+#include <errno.h>
+#include <pthread.h>
+#include <time.h>
+
+namespace LIBC_NAMESPACE::rwlock {
+class RwLockTester {
+public:
+  static constexpr int full_reader_state() {
+    return (~0) & (~RwState::PENDING_MASK) & (~RwState::ACTIVE_WRITER_BIT);
+  }
+};
+} // namespace LIBC_NAMESPACE::rwlock
+
+static void smoke_test() {
+  pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_init(&rwlock, nullptr), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_rdlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_tryrdlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_trywrlock(&rwlock), EBUSY);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_wrlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_rdlock(&rwlock), EDEADLK);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_wrlock(&rwlock), EDEADLK);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_tryrdlock(&rwlock), EBUSY);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_trywrlock(&rwlock), EBUSY);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_destroy(&rwlock), 0);
+}
+
+static void deadlock_detection_test() {
+  pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_init(&rwlock, nullptr), 0);
+  // We only detect RAW, WAW deadlocks.
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_wrlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_wrlock(&rwlock), EDEADLK);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_destroy(&rwlock), 0);
+}
+
+static void try_lock_test() {
+  pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_init(&rwlock, nullptr), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_wrlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_trywrlock(&rwlock), EBUSY);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_tryrdlock(&rwlock), EBUSY);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_tryrdlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_rdlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_tryrdlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_trywrlock(&rwlock), EBUSY);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_destroy(&rwlock), 0);
+}
+
+static void destroy_before_unlock_test() {
+  pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_init(&rwlock, nullptr), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_wrlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_destroy(&rwlock), EBUSY);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_destroy(&rwlock), 0);
+}
+
+static void nullptr_test() {
+  timespec ts = {};
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_rdlock(nullptr), EINVAL);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_wrlock(nullptr), EINVAL);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_timedrdlock(nullptr, &ts), EINVAL);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_timedwrlock(nullptr, &ts), EINVAL);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_tryrdlock(nullptr), EINVAL);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_trywrlock(nullptr), EINVAL);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(nullptr), EINVAL);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_destroy(nullptr), EINVAL);
+}
+
+// If you are a user reading this code, please do not do something like this.
+// We manually modify the internal state of the rwlock to test high reader
+// counts.
+static void high_reader_count_test() {
+  pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
+  rwlock.__state = LIBC_NAMESPACE::rwlock::RwLockTester::full_reader_state();
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_rdlock(&rwlock), EAGAIN);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_tryrdlock(&rwlock), EAGAIN);
+  // allocate 4 reader slots.
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+
+  pthread_t threads[20];
+  for (auto &i : threads)
+    ASSERT_EQ(LIBC_NAMESPACE::pthread_create(
+                  &i, nullptr,
+                  [](void *arg) -> void * {
+                    pthread_rwlock_t *rwlock =
+                        reinterpret_cast<pthread_rwlock_t *>(arg);
+                    ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_trywrlock(rwlock),
+                              EBUSY);
+                    while (LIBC_NAMESPACE::pthread_rwlock_rdlock(rwlock) ==
+                           EAGAIN)
+                      LIBC_NAMESPACE::sleep_briefly();
+                    ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(rwlock), 0);
+                    return nullptr;
+                  },
+                  &rwlock),
+              0);
+
+  for (auto &i : threads)
+    ASSERT_EQ(LIBC_NAMESPACE::pthread_join(i, nullptr), 0);
+}
+
+static void unusual_timespec_test() {
+  pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
+  timespec ts = {0, -1};
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_timedrdlock(&rwlock, &ts), EINVAL);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_timedwrlock(&rwlock, &ts), EINVAL);
+  ts.tv_nsec = 1'000'000'000;
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_timedrdlock(&rwlock, &ts), EINVAL);
+  ts.tv_nsec += 1;
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_timedwrlock(&rwlock, &ts), EINVAL);
+  ts.tv_nsec = 0;
+  ts.tv_sec = -1;
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_timedrdlock(&rwlock, &ts),
+            ETIMEDOUT);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_timedwrlock(&rwlock, &ts),
+            ETIMEDOUT);
+}
+
+static void timedlock_with_deadlock_test() {
+  pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;
+  timespec ts{};
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_rdlock(&rwlock), 0);
+  LIBC_NAMESPACE::clock_gettime(CLOCK_REALTIME, &ts);
+  ts.tv_nsec += 50'000;
+  if (ts.tv_nsec >= 1'000'000'000) {
+    ts.tv_nsec -= 1'000'000'000;
+    ts.tv_sec += 1;
+  }
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_timedwrlock(&rwlock, &ts),
+            ETIMEDOUT);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_timedrdlock(&rwlock, &ts), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  // notice that ts is already expired, but the following should still succeed.
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_tryrdlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_trywrlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_rdlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_wrlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_unlock(&rwlock), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_destroy(&rwlock), 0);
+}
+
+static void attributed_initialization_test() {
+  pthread_rwlockattr_t attr{};
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlockattr_init(&attr), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlockattr_setkind_np(
+                &attr, PTHREAD_RWLOCK_PREFER_READER_NP),
+            0);
+  {
+    pthread_rwlock_t rwlock{};
+    ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_init(&rwlock, &attr), 0);
+    ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_destroy(&rwlock), 0);
+  }
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlockattr_setkind_np(
+                &attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP),
+            0);
+  {
+    pthread_rwlock_t rwlock{};
+    ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_init(&rwlock, &attr), 0);
+    ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_destroy(&rwlock), 0);
+  }
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlockattr_setkind_np(
+                &attr, PTHREAD_RWLOCK_PREFER_WRITER_NP),
+            0);
+  {
+    pthread_rwlock_t rwlock{};
+    ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_init(&rwlock, &attr), EINVAL);
+  }
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlockattr_setkind_np(
+                &attr, PTHREAD_RWLOCK_PREFER_READER_NP),
+            0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlockattr_setpshared(
+                &attr, PTHREAD_PROCESS_PRIVATE),
+            0);
+  {
+    pthread_rwlock_t rwlock{};
+    ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_init(&rwlock, &attr), 0);
+    ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_destroy(&rwlock), 0);
+  }
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlockattr_setpshared(
+                &attr, PTHREAD_PROCESS_SHARED),
+            0);
+  {
+    pthread_rwlock_t rwlock{};
+    ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_init(&rwlock, &attr), 0);
+    ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_destroy(&rwlock), 0);
+  }
+  attr.pref = -1;
+  {
+    pthread_rwlock_t rwlock{};
+    ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_init(&rwlock, &attr), EINVAL);
+  }
+  attr.pref = PTHREAD_RWLOCK_PREFER_READER_NP;
+  attr.pshared = -1;
+  {
+    pthread_rwlock_t rwlock{};
+    ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_init(&rwlock, &attr), EINVAL);
+  }
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlockattr_destroy(&attr), 0);
+}
+
+struct SharedData {
+  pthread_rwlock_t lock;
+  int data;
+  LIBC_NAMESPACE::cpp::Atomic<int> reader_count;
+  bool writer_flag;
+  LIBC_NAMESPACE::cpp::Atomic<int> total_writer_count;
+};
+
+enum class Operation : int {
+  READ = 0,
+  WRITE = 1,
+  TIMED_READ = 2,
+  TIMED_WRITE = 3,
+  TRY_READ = 4,
+  TRY_WRITE = 5,
+  COUNT = 6
+};
+
+LIBC_NAMESPACE::RawMutex *io_mutex;
+struct ThreadGuard {
+  Operation record[64]{};
+  size_t cursor = 0;
+  void push(Operation op) { record[cursor++] = op; }
+  ~ThreadGuard() {
+    if (!LIBC_NAMESPACE::getenv("LIBC_PTHREAD_RWLOCK_TEST_VERBOSE"))
+      return;
+    pid_t pid = LIBC_NAMESPACE::syscall_impl(SYS_getpid);
+    pid_t tid = LIBC_NAMESPACE::syscall_impl(SYS_gettid);
+    io_mutex->lock(LIBC_NAMESPACE::cpp::nullopt, true);
+    LIBC_NAMESPACE::printf("process %d thread %d: ", pid, tid);
+    for (size_t i = 0; i < cursor; ++i)
+      LIBC_NAMESPACE::printf("%d ", static_cast<int>(record[i]));
+    LIBC_NAMESPACE::printf("\n");
+    io_mutex->unlock(true);
+  }
+};
+
+static void randomized_thread_operation(SharedData *data, ThreadGuard &guard) {
+  int buffer;
+  // We cannot reason about thread order anyway, let's go wild and randomize it
+  // directly using getrandom.
+  LIBC_NAMESPACE::getrandom(&buffer, sizeof(buffer), 0);
+  constexpr int TOTAL = static_cast<int>(Operation::COUNT);
+  Operation op = static_cast<Operation>(((buffer % TOTAL) + TOTAL) % TOTAL);
+  guard.push(op);
+  auto read_ops = [data]() {
+    ASSERT_FALSE(data->writer_flag);
+    data->reader_count.fetch_add(1, LIBC_NAMESPACE::cpp::MemoryOrder::RELAXED);
+    for (int i = 0; i < 10; ++i)
+      LIBC_NAMESPACE::sleep_briefly();
+    data->reader_count.fetch_sub(1, LIBC_NAMESPACE::cpp::MemoryOrder::RELAXED);
+  };
+  auto write_ops = [data]() {
+    ASSERT_FALSE(data->writer_flag);
+    data->data += 1;
+    data->writer_flag = true;
+    for (int i = 0; i < 10; ++i)
+      LIBC_NAMESPACE::sleep_briefly();
+    ASSERT_EQ(data->reader_count, 0);
+    data->writer_flag = false;
+    data->total_writer_count.fetch_add(1);
+  };
+  auto get_ts = []() {
+    timespec ts{};
+    LIBC_NAMESPACE::clock_gettime(CLOCK_REALTIME, &ts);
+    ts.tv_nsec += 5'000;
+    if (ts.tv_nsec >= 1'000'000'000) {
+      ts.tv_nsec -= 1'000'000'000;
+      ts.tv_sec += 1;
+    }
+    return ts;
+  };
+  switch (op) {
+  case Operation::READ: {
+    LIBC_NAMESPACE::pthread_rwlock_rdlock(&data->lock);
+    read_ops();
+    LIBC_NAMESPACE::pthread_rwlock_unlock(&data->lock);
+    break;
+  }
+  case Operation::WRITE: {
+    LIBC_NAMESPACE::pthread_rwlock_wrlock(&data->lock);
+    write_ops();
+    LIBC_NAMESPACE::pthread_rwlock_unlock(&data->lock);
+    break;
+  }
+  case Operation::TIMED_READ: {
+    timespec ts = get_ts();
+    if (LIBC_NAMESPACE::pthread_rwlock_timedrdlock(&data->lock, &ts) == 0) {
+      read_ops();
+      LIBC_NAMESPACE::pthread_rwlock_unlock(&data->lock);
+    }
+    break;
+  }
+  case Operation::TIMED_WRITE: {
+    timespec ts = get_ts();
+    if (LIBC_NAMESPACE::pthread_rwlock_timedwrlock(&data->lock, &ts) == 0) {
+      write_ops();
+      LIBC_NAMESPACE::pthread_rwlock_unlock(&data->lock);
+    }
+    break;
+  }
+  case Operation::TRY_READ: {
+    if (LIBC_NAMESPACE::pthread_rwlock_tryrdlock(&data->lock) == 0) {
+      read_ops();
+      LIBC_NAMESPACE::pthread_rwlock_unlock(&data->lock);
+    }
+    break;
+  }
+  case Operation::TRY_WRITE: {
+    if (LIBC_NAMESPACE::pthread_rwlock_trywrlock(&data->lock) == 0) {
+      write_ops();
+      LIBC_NAMESPACE::pthread_rwlock_unlock(&data->lock);
+    }
+    break;
+  }
+  case Operation::COUNT:
+    __builtin_trap();
+  }
+}
+
+static void
+randomized_process_operation(SharedData &data,
+                             LIBC_NAMESPACE::cpp::Atomic<int> &finish_count,
+                             int expected_count) {
+  pthread_t threads[32];
+  for (auto &i : threads)
+    ASSERT_EQ(LIBC_NAMESPACE::pthread_create(
+                  &i, nullptr,
+                  [](void *arg) -> void * {
+                    ThreadGuard guard{};
+                    for (int i = 0; i < 64; ++i)
+                      randomized_thread_operation(
+                          reinterpret_cast<SharedData *>(arg), guard);
+                    return nullptr;
+                  },
+                  &data),
+              0);
+
+  for (auto &i : threads)
+    ASSERT_EQ(LIBC_NAMESPACE::pthread_join(i, nullptr), 0);
+
+  finish_count.fetch_add(1);
+  while (finish_count.load() != expected_count)
+    LIBC_NAMESPACE::sleep_briefly();
+
+  ASSERT_EQ(data.total_writer_count.load(), data.data);
+  ASSERT_FALSE(data.writer_flag);
+  ASSERT_EQ(data.reader_count, 0);
+}
+
+static void single_process_test(int preference) {
+  SharedData data{};
+  data.data = 0;
+  data.reader_count = 0;
+  data.writer_flag = false;
+  data.total_writer_count.store(0);
+  pthread_rwlockattr_t attr{};
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlockattr_init(&attr), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlockattr_setkind_np(&attr, preference),
+            0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_init(&data.lock, nullptr), 0);
+  LIBC_NAMESPACE::cpp::Atomic<int> finish_count{0};
+  randomized_process_operation(data, finish_count, 1);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_destroy(&data.lock), 0);
+}
+
+static void multiple_process_test(int preference) {
+  struct PShared {
+    SharedData data;
+    LIBC_NAMESPACE::cpp::Atomic<int> finish_count;
+  };
+  PShared *shared_data = reinterpret_cast<PShared *>(
+      LIBC_NAMESPACE::mmap(nullptr, sizeof(PShared), PROT_READ | PROT_WRITE,
+                           MAP_SHARED | MAP_ANONYMOUS, -1, 0));
+  shared_data->data.data = 0;
+  shared_data->data.reader_count = 0;
+  shared_data->data.writer_flag = false;
+  shared_data->data.total_writer_count.store(0);
+  shared_data->finish_count.store(0);
+  pthread_rwlockattr_t attr{};
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlockattr_init(&attr), 0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlockattr_setkind_np(&attr, preference),
+            0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlockattr_setpshared(
+                &attr, PTHREAD_PROCESS_SHARED),
+            0);
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_init(&shared_data->data.lock, &attr),
+            0);
+  int pid = LIBC_NAMESPACE::fork();
+  randomized_process_operation(shared_data->data, shared_data->finish_count, 2);
+  if (pid == 0)
+    LIBC_NAMESPACE::exit(0);
+  else {
+    int status;
+    LIBC_NAMESPACE::waitpid(pid, &status, 0);
+    ASSERT_EQ(status, 0);
+  }
+  ASSERT_EQ(LIBC_NAMESPACE::pthread_rwlock_destroy(&shared_data->data.lock), 0);
+  LIBC_NAMESPACE::munmap(shared_data, sizeof(PShared));
+}
+
+TEST_MAIN() {
+  io_mutex = new (LIBC_NAMESPACE::mmap(
+      nullptr, sizeof(LIBC_NAMESPACE::RawMutex), PROT_READ | PROT_WRITE,
+      MAP_ANONYMOUS | MAP_SHARED, -1, 0)) LIBC_NAMESPACE::RawMutex();
+  smoke_test();
+  deadlock_detection_test();
+  try_lock_test();
+  destroy_before_unlock_test();
+  nullptr_test();
+  high_reader_count_test();
+  unusual_timespec_test();
+  timedlock_with_deadlock_test();
+  attributed_initialization_test();
+  single_process_test(PTHREAD_RWLOCK_PREFER_READER_NP);
+  single_process_test(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
+  multiple_process_test(PTHREAD_RWLOCK_PREFER_READER_NP);
+  multiple_process_test(PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
+  io_mutex->~RawMutex();
+  LIBC_NAMESPACE::munmap(io_mutex, sizeof(LIBC_NAMESPACE::RawMutex));
+  return 0;
+}
diff --git a/test/src/__support/FPUtil/dyadic_float_test.cpp b/test/src/__support/FPUtil/dyadic_float_test.cpp
index 809381e..3b1f9de 100644
--- a/test/src/__support/FPUtil/dyadic_float_test.cpp
+++ b/test/src/__support/FPUtil/dyadic_float_test.cpp
@@ -8,6 +8,7 @@
 
 #include "src/__support/FPUtil/dyadic_float.h"
 #include "src/__support/big_int.h"
+#include "src/__support/macros/properties/types.h"
 #include "test/UnitTest/FPMatcher.h"
 #include "test/UnitTest/Test.h"
 #include "utils/MPFRWrapper/MPFRUtils.h"
@@ -89,3 +90,6 @@ TEST(LlvmLibcDyadicFloatTest, QuickMul) {
 TEST_EDGE_RANGES(Float, float);
 TEST_EDGE_RANGES(Double, double);
 TEST_EDGE_RANGES(LongDouble, long double);
+#ifdef LIBC_TYPES_HAS_FLOAT16
+TEST_EDGE_RANGES(Float16, float16);
+#endif
diff --git a/test/src/__support/big_int_test.cpp b/test/src/__support/big_int_test.cpp
index 1c4f0ac..84cd206 100644
--- a/test/src/__support/big_int_test.cpp
+++ b/test/src/__support/big_int_test.cpp
@@ -205,6 +205,7 @@ TYPED_TEST(LlvmLibcUIntClassTest, CountBits, Types) {
   }
 }
 
+using LL_UInt16 = UInt<16>;
 using LL_UInt64 = UInt<64>;
 // We want to test UInt<128> explicitly. So, for
 // convenience, we use a sugar which does not conflict with the UInt128 type
@@ -258,6 +259,19 @@ TEST(LlvmLibcUIntClassTest, BitCastToFromNativeFloat128) {
 }
 #endif // LIBC_TYPES_HAS_FLOAT128
 
+#ifdef LIBC_TYPES_HAS_FLOAT16
+TEST(LlvmLibcUIntClassTest, BitCastToFromNativeFloat16) {
+  static_assert(cpp::is_trivially_copyable<LL_UInt16>::value);
+  static_assert(sizeof(LL_UInt16) == sizeof(float16));
+  const float16 array[] = {0, 0.1, 1};
+  for (float16 value : array) {
+    LL_UInt16 back = cpp::bit_cast<LL_UInt16>(value);
+    float16 forth = cpp::bit_cast<float16>(back);
+    EXPECT_TRUE(value == forth);
+  }
+}
+#endif // LIBC_TYPES_HAS_FLOAT16
+
 TEST(LlvmLibcUIntClassTest, BasicInit) {
   LL_UInt128 half_val(12345);
   LL_UInt128 full_val({12345, 67890});
diff --git a/test/src/__support/block_test.cpp b/test/src/__support/block_test.cpp
new file mode 100644
index 0000000..6614e4b
--- /dev/null
+++ b/test/src/__support/block_test.cpp
@@ -0,0 +1,569 @@
+//===-- Unittests for a block of memory -------------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+#include <stddef.h>
+
+#include "src/__support/CPP/array.h"
+#include "src/__support/CPP/span.h"
+#include "src/__support/block.h"
+#include "src/string/memcpy.h"
+#include "test/UnitTest/Test.h"
+
+// Block types.
+using LargeOffsetBlock = LIBC_NAMESPACE::Block<uint64_t>;
+using SmallOffsetBlock = LIBC_NAMESPACE::Block<uint16_t>;
+
+// For each of the block types above, we'd like to run the same tests since
+// they should work independently of the parameter sizes. Rather than re-writing
+// the same test for each case, let's instead create a custom test framework for
+// each test case that invokes the actual testing function for each block type.
+//
+// It's organized this way because the ASSERT/EXPECT macros only work within a
+// `Test` class due to those macros expanding to `test` methods.
+#define TEST_FOR_EACH_BLOCK_TYPE(TestCase)                                     \
+  class LlvmLibcBlockTest##TestCase : public LIBC_NAMESPACE::testing::Test {   \
+  public:                                                                      \
+    template <typename BlockType> void RunTest();                              \
+  };                                                                           \
+  TEST_F(LlvmLibcBlockTest##TestCase, TestCase) {                              \
+    RunTest<LargeOffsetBlock>();                                               \
+    RunTest<SmallOffsetBlock>();                                               \
+  }                                                                            \
+  template <typename BlockType> void LlvmLibcBlockTest##TestCase::RunTest()
+
+using LIBC_NAMESPACE::cpp::array;
+using LIBC_NAMESPACE::cpp::byte;
+using LIBC_NAMESPACE::cpp::span;
+
+TEST_FOR_EACH_BLOCK_TYPE(CanCreateSingleAlignedBlock) {
+  constexpr size_t kN = 1024;
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block = *result;
+
+  EXPECT_EQ(block->outer_size(), kN);
+  EXPECT_EQ(block->inner_size(), kN - BlockType::BLOCK_OVERHEAD);
+  EXPECT_EQ(block->prev(), static_cast<BlockType *>(nullptr));
+  EXPECT_EQ(block->next(), static_cast<BlockType *>(nullptr));
+  EXPECT_FALSE(block->used());
+  EXPECT_TRUE(block->last());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanCreateUnalignedSingleBlock) {
+  constexpr size_t kN = 1024;
+
+  // Force alignment, so we can un-force it below
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  span<byte> aligned(bytes);
+
+  auto result = BlockType::init(aligned.subspan(1));
+  EXPECT_TRUE(result.has_value());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CannotCreateTooSmallBlock) {
+  array<byte, 2> bytes;
+  auto result = BlockType::init(bytes);
+  EXPECT_FALSE(result.has_value());
+}
+
+// This test specifically checks that we cannot allocate a block with a size
+// larger than what can be held by the offset type, we don't need to test with
+// multiple block types for this particular check, so we use the normal TEST
+// macro and not the custom framework.
+TEST(LlvmLibcBlockTest, CannotCreateTooLargeBlock) {
+  using BlockType = LIBC_NAMESPACE::Block<uint8_t>;
+  constexpr size_t kN = 1024;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  EXPECT_FALSE(result.has_value());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanSplitBlock) {
+  constexpr size_t kN = 1024;
+  constexpr size_t kSplitN = 512;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  auto *block1 = *result;
+
+  result = BlockType::split(block1, kSplitN);
+  ASSERT_TRUE(result.has_value());
+
+  auto *block2 = *result;
+
+  EXPECT_EQ(block1->inner_size(), kSplitN);
+  EXPECT_EQ(block1->outer_size(), kSplitN + BlockType::BLOCK_OVERHEAD);
+  EXPECT_FALSE(block1->last());
+
+  EXPECT_EQ(block2->outer_size(), kN - kSplitN - BlockType::BLOCK_OVERHEAD);
+  EXPECT_FALSE(block2->used());
+  EXPECT_TRUE(block2->last());
+
+  EXPECT_EQ(block1->next(), block2);
+  EXPECT_EQ(block2->prev(), block1);
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanSplitBlockUnaligned) {
+  constexpr size_t kN = 1024;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block1 = *result;
+
+  // We should split at sizeof(BlockType) + kSplitN bytes. Then
+  // we need to round that up to an alignof(BlockType) boundary.
+  constexpr size_t kSplitN = 513;
+  uintptr_t split_addr = reinterpret_cast<uintptr_t>(block1) + kSplitN;
+  split_addr += alignof(BlockType) - (split_addr % alignof(BlockType));
+  uintptr_t split_len = split_addr - (uintptr_t)&bytes;
+
+  result = BlockType::split(block1, kSplitN);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block2 = *result;
+
+  EXPECT_EQ(block1->inner_size(), split_len);
+  EXPECT_EQ(block1->outer_size(), split_len + BlockType::BLOCK_OVERHEAD);
+
+  EXPECT_EQ(block2->outer_size(), kN - block1->outer_size());
+  EXPECT_FALSE(block2->used());
+
+  EXPECT_EQ(block1->next(), block2);
+  EXPECT_EQ(block2->prev(), block1);
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanSplitMidBlock) {
+  // split once, then split the original block again to ensure that the
+  // pointers get rewired properly.
+  // I.e.
+  // [[             BLOCK 1            ]]
+  // block1->split()
+  // [[       BLOCK1       ]][[ BLOCK2 ]]
+  // block1->split()
+  // [[ BLOCK1 ]][[ BLOCK3 ]][[ BLOCK2 ]]
+
+  constexpr size_t kN = 1024;
+  constexpr size_t kSplit1 = 512;
+  constexpr size_t kSplit2 = 256;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block1 = *result;
+
+  result = BlockType::split(block1, kSplit1);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block2 = *result;
+
+  result = BlockType::split(block1, kSplit2);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block3 = *result;
+
+  EXPECT_EQ(block1->next(), block3);
+  EXPECT_EQ(block3->prev(), block1);
+  EXPECT_EQ(block3->next(), block2);
+  EXPECT_EQ(block2->prev(), block3);
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CannotSplitTooSmallBlock) {
+  constexpr size_t kN = 64;
+  constexpr size_t kSplitN = kN + 1;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block = *result;
+
+  result = BlockType::split(block, kSplitN);
+  ASSERT_FALSE(result.has_value());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CannotSplitBlockWithoutHeaderSpace) {
+  constexpr size_t kN = 1024;
+  constexpr size_t kSplitN = kN - BlockType::BLOCK_OVERHEAD - 1;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block = *result;
+
+  result = BlockType::split(block, kSplitN);
+  ASSERT_FALSE(result.has_value());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CannotSplitNull) {
+  BlockType *block = nullptr;
+  auto result = BlockType::split(block, 1);
+  ASSERT_FALSE(result.has_value());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CannotMakeBlockLargerInSplit) {
+  // Ensure that we can't ask for more space than the block actually has...
+  constexpr size_t kN = 1024;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block = *result;
+
+  result = BlockType::split(block, block->inner_size() + 1);
+  ASSERT_FALSE(result.has_value());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CannotMakeSecondBlockLargerInSplit) {
+  // Ensure that the second block in split is at least of the size of header.
+  constexpr size_t kN = 1024;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block = *result;
+
+  result = BlockType::split(block, block->inner_size() -
+                                       BlockType::BLOCK_OVERHEAD + 1);
+  ASSERT_FALSE(result.has_value());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanMakeZeroSizeFirstBlock) {
+  // This block does support splitting with zero payload size.
+  constexpr size_t kN = 1024;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block = *result;
+
+  result = BlockType::split(block, 0);
+  ASSERT_TRUE(result.has_value());
+  EXPECT_EQ(block->inner_size(), static_cast<size_t>(0));
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanMakeZeroSizeSecondBlock) {
+  // Likewise, the split block can be zero-width.
+  constexpr size_t kN = 1024;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block1 = *result;
+
+  result = BlockType::split(block1,
+                            block1->inner_size() - BlockType::BLOCK_OVERHEAD);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block2 = *result;
+
+  EXPECT_EQ(block2->inner_size(), static_cast<size_t>(0));
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanMarkBlockUsed) {
+  constexpr size_t kN = 1024;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block = *result;
+
+  block->mark_used();
+  EXPECT_TRUE(block->used());
+
+  // Size should be unaffected.
+  EXPECT_EQ(block->outer_size(), kN);
+
+  block->mark_free();
+  EXPECT_FALSE(block->used());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CannotSplitUsedBlock) {
+  constexpr size_t kN = 1024;
+  constexpr size_t kSplitN = 512;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block = *result;
+
+  block->mark_used();
+  result = BlockType::split(block, kSplitN);
+  ASSERT_FALSE(result.has_value());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanMergeWithNextBlock) {
+  // Do the three way merge from "CanSplitMidBlock", and let's
+  // merge block 3 and 2
+  constexpr size_t kN = 1024;
+  constexpr size_t kSplit1 = 512;
+  constexpr size_t kSplit2 = 256;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block1 = *result;
+
+  result = BlockType::split(block1, kSplit1);
+  ASSERT_TRUE(result.has_value());
+
+  result = BlockType::split(block1, kSplit2);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block3 = *result;
+
+  EXPECT_TRUE(BlockType::merge_next(block3));
+
+  EXPECT_EQ(block1->next(), block3);
+  EXPECT_EQ(block3->prev(), block1);
+  EXPECT_EQ(block1->inner_size(), kSplit2);
+  EXPECT_EQ(block3->outer_size(), kN - block1->outer_size());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CannotMergeWithFirstOrLastBlock) {
+  constexpr size_t kN = 1024;
+  constexpr size_t kSplitN = 512;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block1 = *result;
+
+  // Do a split, just to check that the checks on next/prev are different...
+  result = BlockType::split(block1, kSplitN);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block2 = *result;
+
+  EXPECT_FALSE(BlockType::merge_next(block2));
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CannotMergeNull) {
+  BlockType *block = nullptr;
+  EXPECT_FALSE(BlockType::merge_next(block));
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CannotMergeUsedBlock) {
+  constexpr size_t kN = 1024;
+  constexpr size_t kSplitN = 512;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block = *result;
+
+  // Do a split, just to check that the checks on next/prev are different...
+  result = BlockType::split(block, kSplitN);
+  ASSERT_TRUE(result.has_value());
+
+  block->mark_used();
+  EXPECT_FALSE(BlockType::merge_next(block));
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanFreeSingleBlock) {
+  constexpr size_t kN = 1024;
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block = *result;
+
+  block->mark_used();
+  BlockType::free(block);
+  EXPECT_FALSE(block->used());
+  EXPECT_EQ(block->outer_size(), kN);
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanFreeBlockWithoutMerging) {
+  constexpr size_t kN = 1024;
+  constexpr size_t kSplit1 = 512;
+  constexpr size_t kSplit2 = 256;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block1 = *result;
+
+  result = BlockType::split(block1, kSplit1);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block2 = *result;
+
+  result = BlockType::split(block2, kSplit2);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block3 = *result;
+
+  block1->mark_used();
+  block2->mark_used();
+  block3->mark_used();
+
+  BlockType::free(block2);
+  EXPECT_FALSE(block2->used());
+  EXPECT_NE(block2->prev(), static_cast<BlockType *>(nullptr));
+  EXPECT_FALSE(block2->last());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanFreeBlockAndMergeWithPrev) {
+  constexpr size_t kN = 1024;
+  constexpr size_t kSplit1 = 512;
+  constexpr size_t kSplit2 = 256;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block1 = *result;
+
+  result = BlockType::split(block1, kSplit1);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block2 = *result;
+
+  result = BlockType::split(block2, kSplit2);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block3 = *result;
+
+  block2->mark_used();
+  block3->mark_used();
+
+  BlockType::free(block2);
+  EXPECT_FALSE(block2->used());
+  EXPECT_EQ(block2->prev(), static_cast<BlockType *>(nullptr));
+  EXPECT_FALSE(block2->last());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanFreeBlockAndMergeWithNext) {
+  constexpr size_t kN = 1024;
+  constexpr size_t kSplit1 = 512;
+  constexpr size_t kSplit2 = 256;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block1 = *result;
+
+  result = BlockType::split(block1, kSplit1);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block2 = *result;
+
+  result = BlockType::split(block2, kSplit2);
+  ASSERT_TRUE(result.has_value());
+
+  block1->mark_used();
+  block2->mark_used();
+
+  BlockType::free(block2);
+  EXPECT_FALSE(block2->used());
+  EXPECT_NE(block2->prev(), static_cast<BlockType *>(nullptr));
+  EXPECT_TRUE(block2->last());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanFreeUsedBlockAndMergeWithBoth) {
+  constexpr size_t kN = 1024;
+  constexpr size_t kSplit1 = 512;
+  constexpr size_t kSplit2 = 256;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block1 = *result;
+
+  result = BlockType::split(block1, kSplit1);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block2 = *result;
+
+  result = BlockType::split(block2, kSplit2);
+  ASSERT_TRUE(result.has_value());
+
+  block2->mark_used();
+
+  BlockType::free(block2);
+  EXPECT_FALSE(block2->used());
+  EXPECT_EQ(block2->prev(), static_cast<BlockType *>(nullptr));
+  EXPECT_TRUE(block2->last());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanCheckValidBlock) {
+  constexpr size_t kN = 1024;
+  constexpr size_t kSplit1 = 512;
+  constexpr size_t kSplit2 = 256;
+
+  alignas(BlockType::ALIGNMENT) array<byte, kN> bytes;
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block1 = *result;
+
+  result = BlockType::split(block1, kSplit1);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block2 = *result;
+
+  result = BlockType::split(block2, kSplit2);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block3 = *result;
+
+  EXPECT_TRUE(block1->is_valid());
+  EXPECT_TRUE(block2->is_valid());
+  EXPECT_TRUE(block3->is_valid());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanCheckInvalidBlock) {
+  constexpr size_t kN = 1024;
+  constexpr size_t kSplit1 = 128;
+  constexpr size_t kSplit2 = 384;
+  constexpr size_t kSplit3 = 256;
+
+  array<byte, kN> bytes{};
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block1 = *result;
+
+  result = BlockType::split(block1, kSplit1);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block2 = *result;
+
+  result = BlockType::split(block2, kSplit2);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block3 = *result;
+
+  result = BlockType::split(block3, kSplit3);
+  ASSERT_TRUE(result.has_value());
+
+  // Corrupt a Block header.
+  // This must not touch memory outside the original region, or the test may
+  // (correctly) abort when run with address sanitizer.
+  // To remain as agostic to the internals of `Block` as possible, the test
+  // copies a smaller block's header to a larger block.
+  EXPECT_TRUE(block1->is_valid());
+  EXPECT_TRUE(block2->is_valid());
+  EXPECT_TRUE(block3->is_valid());
+  auto *src = reinterpret_cast<byte *>(block1);
+  auto *dst = reinterpret_cast<byte *>(block2);
+  LIBC_NAMESPACE::memcpy(dst, src, sizeof(BlockType));
+  EXPECT_FALSE(block1->is_valid());
+  EXPECT_FALSE(block2->is_valid());
+  EXPECT_FALSE(block3->is_valid());
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanGetBlockFromUsableSpace) {
+  constexpr size_t kN = 1024;
+
+  array<byte, kN> bytes{};
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  BlockType *block1 = *result;
+
+  void *ptr = block1->usable_space();
+  BlockType *block2 = BlockType::from_usable_space(ptr);
+  EXPECT_EQ(block1, block2);
+}
+
+TEST_FOR_EACH_BLOCK_TYPE(CanGetConstBlockFromUsableSpace) {
+  constexpr size_t kN = 1024;
+
+  array<byte, kN> bytes{};
+  auto result = BlockType::init(bytes);
+  ASSERT_TRUE(result.has_value());
+  const BlockType *block1 = *result;
+
+  const void *ptr = block1->usable_space();
+  const BlockType *block2 = BlockType::from_usable_space(ptr);
+  EXPECT_EQ(block1, block2);
+}
diff --git a/test/src/__support/freelist_heap_test.cpp b/test/src/__support/freelist_heap_test.cpp
new file mode 100644
index 0000000..a35cb55
--- /dev/null
+++ b/test/src/__support/freelist_heap_test.cpp
@@ -0,0 +1,217 @@
+//===-- Unittests for freelist_heap ---------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/__support/CPP/span.h"
+#include "src/__support/freelist_heap.h"
+#include "src/string/memcmp.h"
+#include "src/string/memcpy.h"
+#include "test/UnitTest/Test.h"
+
+namespace LIBC_NAMESPACE {
+
+using LIBC_NAMESPACE::freelist_heap;
+
+// Similar to `LlvmLibcBlockTest` in block_test.cpp, we'd like to run the same
+// tests independently for different parameters. In this case, we'd like to test
+// functionality for a `FreeListHeap` and the global `freelist_heap` which was
+// constinit'd. Functionally, it should operate the same if the FreeListHeap
+// were initialized locally at runtime or at compile-time.
+//
+// Note that calls to `allocate` for each test case here don't always explicitly
+// `free` them afterwards, so when testing the global allocator, allocations
+// made in tests leak and aren't free'd. This is fine for the purposes of this
+// test file.
+#define TEST_FOR_EACH_ALLOCATOR(TestCase, BufferSize)                          \
+  class LlvmLibcFreeListHeapTest##TestCase : public testing::Test {            \
+  public:                                                                      \
+    void RunTest(FreeListHeap<> &allocator, [[maybe_unused]] size_t N);        \
+  };                                                                           \
+  TEST_F(LlvmLibcFreeListHeapTest##TestCase, TestCase) {                       \
+    alignas(FreeListHeap<>::BlockType)                                         \
+        cpp::byte buf[BufferSize] = {cpp::byte(0)};                            \
+    FreeListHeap<> allocator(buf);                                             \
+    RunTest(allocator, BufferSize);                                            \
+    RunTest(*freelist_heap, freelist_heap->region_size());                     \
+  }                                                                            \
+  void LlvmLibcFreeListHeapTest##TestCase::RunTest(FreeListHeap<> &allocator,  \
+                                                   size_t N)
+
+TEST_FOR_EACH_ALLOCATOR(CanAllocate, 2048) {
+  constexpr size_t ALLOC_SIZE = 512;
+
+  void *ptr = allocator.allocate(ALLOC_SIZE);
+
+  ASSERT_NE(ptr, static_cast<void *>(nullptr));
+  // In this case, the allocator should be returning us the start of the chunk.
+  EXPECT_EQ(ptr, static_cast<void *>(
+                     reinterpret_cast<cpp::byte *>(allocator.region_start()) +
+                     FreeListHeap<>::BlockType::BLOCK_OVERHEAD));
+}
+
+TEST_FOR_EACH_ALLOCATOR(AllocationsDontOverlap, 2048) {
+  constexpr size_t ALLOC_SIZE = 512;
+
+  void *ptr1 = allocator.allocate(ALLOC_SIZE);
+  void *ptr2 = allocator.allocate(ALLOC_SIZE);
+
+  ASSERT_NE(ptr1, static_cast<void *>(nullptr));
+  ASSERT_NE(ptr2, static_cast<void *>(nullptr));
+
+  uintptr_t ptr1_start = reinterpret_cast<uintptr_t>(ptr1);
+  uintptr_t ptr1_end = ptr1_start + ALLOC_SIZE;
+  uintptr_t ptr2_start = reinterpret_cast<uintptr_t>(ptr2);
+
+  EXPECT_GT(ptr2_start, ptr1_end);
+}
+
+TEST_FOR_EACH_ALLOCATOR(CanFreeAndRealloc, 2048) {
+  // There's not really a nice way to test that free works, apart from to try
+  // and get that value back again.
+  constexpr size_t ALLOC_SIZE = 512;
+
+  void *ptr1 = allocator.allocate(ALLOC_SIZE);
+  allocator.free(ptr1);
+  void *ptr2 = allocator.allocate(ALLOC_SIZE);
+
+  EXPECT_EQ(ptr1, ptr2);
+}
+
+TEST_FOR_EACH_ALLOCATOR(ReturnsNullWhenAllocationTooLarge, 2048) {
+  EXPECT_EQ(allocator.allocate(N), static_cast<void *>(nullptr));
+}
+
+// NOTE: This doesn't use TEST_FOR_EACH_ALLOCATOR because the first `allocate`
+// here will likely actually return a nullptr since the same global allocator
+// is used for other test cases and we don't explicitly free them.
+TEST(LlvmLibcFreeListHeap, ReturnsNullWhenFull) {
+  constexpr size_t N = 2048;
+  alignas(FreeListHeap<>::BlockType) cpp::byte buf[N] = {cpp::byte(0)};
+
+  FreeListHeap<> allocator(buf);
+
+  EXPECT_NE(allocator.allocate(N - FreeListHeap<>::BlockType::BLOCK_OVERHEAD),
+            static_cast<void *>(nullptr));
+  EXPECT_EQ(allocator.allocate(1), static_cast<void *>(nullptr));
+}
+
+TEST_FOR_EACH_ALLOCATOR(ReturnedPointersAreAligned, 2048) {
+  void *ptr1 = allocator.allocate(1);
+
+  // Should be aligned to native pointer alignment
+  uintptr_t ptr1_start = reinterpret_cast<uintptr_t>(ptr1);
+  size_t alignment = alignof(void *);
+
+  EXPECT_EQ(ptr1_start % alignment, static_cast<size_t>(0));
+
+  void *ptr2 = allocator.allocate(1);
+  uintptr_t ptr2_start = reinterpret_cast<uintptr_t>(ptr2);
+
+  EXPECT_EQ(ptr2_start % alignment, static_cast<size_t>(0));
+}
+
+TEST_FOR_EACH_ALLOCATOR(CanRealloc, 2048) {
+  constexpr size_t ALLOC_SIZE = 512;
+  constexpr size_t kNewAllocSize = 768;
+
+  void *ptr1 = allocator.allocate(ALLOC_SIZE);
+  void *ptr2 = allocator.realloc(ptr1, kNewAllocSize);
+
+  ASSERT_NE(ptr1, static_cast<void *>(nullptr));
+  ASSERT_NE(ptr2, static_cast<void *>(nullptr));
+}
+
+TEST_FOR_EACH_ALLOCATOR(ReallocHasSameContent, 2048) {
+  constexpr size_t ALLOC_SIZE = sizeof(int);
+  constexpr size_t kNewAllocSize = sizeof(int) * 2;
+  // Data inside the allocated block.
+  cpp::byte data1[ALLOC_SIZE];
+  // Data inside the reallocated block.
+  cpp::byte data2[ALLOC_SIZE];
+
+  int *ptr1 = reinterpret_cast<int *>(allocator.allocate(ALLOC_SIZE));
+  *ptr1 = 42;
+  LIBC_NAMESPACE::memcpy(data1, ptr1, ALLOC_SIZE);
+  int *ptr2 = reinterpret_cast<int *>(allocator.realloc(ptr1, kNewAllocSize));
+  LIBC_NAMESPACE::memcpy(data2, ptr2, ALLOC_SIZE);
+
+  ASSERT_NE(ptr1, static_cast<int *>(nullptr));
+  ASSERT_NE(ptr2, static_cast<int *>(nullptr));
+  // Verify that data inside the allocated and reallocated chunks are the same.
+  EXPECT_EQ(LIBC_NAMESPACE::memcmp(data1, data2, ALLOC_SIZE), 0);
+}
+
+TEST_FOR_EACH_ALLOCATOR(ReturnsNullReallocFreedPointer, 2048) {
+  constexpr size_t ALLOC_SIZE = 512;
+  constexpr size_t kNewAllocSize = 256;
+
+  void *ptr1 = allocator.allocate(ALLOC_SIZE);
+  allocator.free(ptr1);
+  void *ptr2 = allocator.realloc(ptr1, kNewAllocSize);
+
+  EXPECT_EQ(static_cast<void *>(nullptr), ptr2);
+}
+
+TEST_FOR_EACH_ALLOCATOR(ReallocSmallerSize, 2048) {
+  constexpr size_t ALLOC_SIZE = 512;
+  constexpr size_t kNewAllocSize = 256;
+
+  void *ptr1 = allocator.allocate(ALLOC_SIZE);
+  void *ptr2 = allocator.realloc(ptr1, kNewAllocSize);
+
+  // For smaller sizes, realloc will not shrink the block.
+  EXPECT_EQ(ptr1, ptr2);
+}
+
+TEST_FOR_EACH_ALLOCATOR(ReallocTooLarge, 2048) {
+  constexpr size_t ALLOC_SIZE = 512;
+  size_t kNewAllocSize = N * 2; // Large enough to fail.
+
+  void *ptr1 = allocator.allocate(ALLOC_SIZE);
+  void *ptr2 = allocator.realloc(ptr1, kNewAllocSize);
+
+  // realloc() will not invalidate the original pointer if realloc() fails
+  EXPECT_NE(static_cast<void *>(nullptr), ptr1);
+  EXPECT_EQ(static_cast<void *>(nullptr), ptr2);
+}
+
+TEST_FOR_EACH_ALLOCATOR(CanCalloc, 2048) {
+  constexpr size_t ALLOC_SIZE = 128;
+  constexpr size_t NUM = 4;
+  constexpr int size = NUM * ALLOC_SIZE;
+  constexpr cpp::byte zero{0};
+
+  cpp::byte *ptr1 =
+      reinterpret_cast<cpp::byte *>(allocator.calloc(NUM, ALLOC_SIZE));
+
+  // calloc'd content is zero.
+  for (int i = 0; i < size; i++) {
+    EXPECT_EQ(ptr1[i], zero);
+  }
+}
+
+TEST_FOR_EACH_ALLOCATOR(CanCallocWeirdSize, 2048) {
+  constexpr size_t ALLOC_SIZE = 143;
+  constexpr size_t NUM = 3;
+  constexpr int size = NUM * ALLOC_SIZE;
+  constexpr cpp::byte zero{0};
+
+  cpp::byte *ptr1 =
+      reinterpret_cast<cpp::byte *>(allocator.calloc(NUM, ALLOC_SIZE));
+
+  // calloc'd content is zero.
+  for (int i = 0; i < size; i++) {
+    EXPECT_EQ(ptr1[i], zero);
+  }
+}
+
+TEST_FOR_EACH_ALLOCATOR(CallocTooLarge, 2048) {
+  size_t ALLOC_SIZE = N + 1;
+  EXPECT_EQ(allocator.calloc(1, ALLOC_SIZE), static_cast<void *>(nullptr));
+}
+
+} // namespace LIBC_NAMESPACE
diff --git a/test/src/__support/freelist_malloc_test.cpp b/test/src/__support/freelist_malloc_test.cpp
new file mode 100644
index 0000000..989e954
--- /dev/null
+++ b/test/src/__support/freelist_malloc_test.cpp
@@ -0,0 +1,56 @@
+//===-- Unittests for freelist_malloc -------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/__support/freelist_heap.h"
+#include "src/stdlib/calloc.h"
+#include "src/stdlib/free.h"
+#include "src/stdlib/malloc.h"
+#include "test/UnitTest/Test.h"
+
+using LIBC_NAMESPACE::freelist_heap;
+
+TEST(LlvmLibcFreeListMalloc, MallocStats) {
+  constexpr size_t kAllocSize = 256;
+  constexpr size_t kCallocNum = 4;
+  constexpr size_t kCallocSize = 64;
+
+  freelist_heap->reset_heap_stats(); // Do this because other tests might've
+                                     // called the same global allocator.
+
+  void *ptr1 = LIBC_NAMESPACE::malloc(kAllocSize);
+
+  const auto &freelist_heap_stats = freelist_heap->heap_stats();
+
+  ASSERT_NE(ptr1, static_cast<void *>(nullptr));
+  EXPECT_EQ(freelist_heap_stats.bytes_allocated, kAllocSize);
+  EXPECT_EQ(freelist_heap_stats.cumulative_allocated, kAllocSize);
+  EXPECT_EQ(freelist_heap_stats.cumulative_freed, size_t(0));
+
+  LIBC_NAMESPACE::free(ptr1);
+  EXPECT_EQ(freelist_heap_stats.bytes_allocated, size_t(0));
+  EXPECT_EQ(freelist_heap_stats.cumulative_allocated, kAllocSize);
+  EXPECT_EQ(freelist_heap_stats.cumulative_freed, kAllocSize);
+
+  void *ptr2 = LIBC_NAMESPACE::calloc(kCallocNum, kCallocSize);
+  ASSERT_NE(ptr2, static_cast<void *>(nullptr));
+  EXPECT_EQ(freelist_heap_stats.bytes_allocated, kCallocNum * kCallocSize);
+  EXPECT_EQ(freelist_heap_stats.cumulative_allocated,
+            kAllocSize + kCallocNum * kCallocSize);
+  EXPECT_EQ(freelist_heap_stats.cumulative_freed, kAllocSize);
+
+  for (size_t i = 0; i < kCallocNum * kCallocSize; ++i) {
+    EXPECT_EQ(reinterpret_cast<uint8_t *>(ptr2)[i], uint8_t(0));
+  }
+
+  LIBC_NAMESPACE::free(ptr2);
+  EXPECT_EQ(freelist_heap_stats.bytes_allocated, size_t(0));
+  EXPECT_EQ(freelist_heap_stats.cumulative_allocated,
+            kAllocSize + kCallocNum * kCallocSize);
+  EXPECT_EQ(freelist_heap_stats.cumulative_freed,
+            kAllocSize + kCallocNum * kCallocSize);
+}
diff --git a/test/src/__support/freelist_test.cpp b/test/src/__support/freelist_test.cpp
new file mode 100644
index 0000000..cae0ed4
--- /dev/null
+++ b/test/src/__support/freelist_test.cpp
@@ -0,0 +1,166 @@
+//===-- Unittests for a freelist --------------------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include <stddef.h>
+
+#include "src/__support/CPP/array.h"
+#include "src/__support/CPP/span.h"
+#include "src/__support/freelist.h"
+#include "test/UnitTest/Test.h"
+
+using LIBC_NAMESPACE::FreeList;
+using LIBC_NAMESPACE::cpp::array;
+using LIBC_NAMESPACE::cpp::byte;
+using LIBC_NAMESPACE::cpp::span;
+
+static constexpr size_t SIZE = 8;
+static constexpr array<size_t, SIZE> example_sizes = {64,   128,  256,  512,
+                                                      1024, 2048, 4096, 8192};
+
+TEST(LlvmLibcFreeList, EmptyListHasNoMembers) {
+  FreeList<SIZE> list(example_sizes);
+
+  auto item = list.find_chunk(4);
+  EXPECT_EQ(item.size(), static_cast<size_t>(0));
+  item = list.find_chunk(128);
+  EXPECT_EQ(item.size(), static_cast<size_t>(0));
+}
+
+TEST(LlvmLibcFreeList, CanRetrieveAddedMember) {
+  FreeList<SIZE> list(example_sizes);
+  constexpr size_t N = 512;
+
+  byte data[N] = {byte(0)};
+
+  bool ok = list.add_chunk(span<byte>(data, N));
+  EXPECT_TRUE(ok);
+
+  auto item = list.find_chunk(N);
+  EXPECT_EQ(item.size(), N);
+  EXPECT_EQ(item.data(), data);
+}
+
+TEST(LlvmLibcFreeList, CanRetrieveAddedMemberForSmallerSize) {
+  FreeList<SIZE> list(example_sizes);
+  constexpr size_t N = 512;
+
+  byte data[N] = {byte(0)};
+
+  ASSERT_TRUE(list.add_chunk(span<byte>(data, N)));
+  auto item = list.find_chunk(N / 2);
+  EXPECT_EQ(item.size(), N);
+  EXPECT_EQ(item.data(), data);
+}
+
+TEST(LlvmLibcFreeList, CanRemoveItem) {
+  FreeList<SIZE> list(example_sizes);
+  constexpr size_t N = 512;
+
+  byte data[N] = {byte(0)};
+
+  ASSERT_TRUE(list.add_chunk(span<byte>(data, N)));
+  EXPECT_TRUE(list.remove_chunk(span<byte>(data, N)));
+
+  auto item = list.find_chunk(N);
+  EXPECT_EQ(item.size(), static_cast<size_t>(0));
+}
+
+TEST(LlvmLibcFreeList, FindReturnsSmallestChunk) {
+  FreeList<SIZE> list(example_sizes);
+  constexpr size_t kN1 = 512;
+  constexpr size_t kN2 = 1024;
+
+  byte data1[kN1] = {byte(0)};
+  byte data2[kN2] = {byte(0)};
+
+  ASSERT_TRUE(list.add_chunk(span<byte>(data1, kN1)));
+  ASSERT_TRUE(list.add_chunk(span<byte>(data2, kN2)));
+
+  auto chunk = list.find_chunk(kN1 / 2);
+  EXPECT_EQ(chunk.size(), kN1);
+  EXPECT_EQ(chunk.data(), data1);
+
+  chunk = list.find_chunk(kN1);
+  EXPECT_EQ(chunk.size(), kN1);
+  EXPECT_EQ(chunk.data(), data1);
+
+  chunk = list.find_chunk(kN1 + 1);
+  EXPECT_EQ(chunk.size(), kN2);
+  EXPECT_EQ(chunk.data(), data2);
+}
+
+TEST(LlvmLibcFreeList, FindReturnsCorrectChunkInSameBucket) {
+  // If we have two values in the same bucket, ensure that the allocation will
+  // pick an appropriately sized one.
+  FreeList<SIZE> list(example_sizes);
+  constexpr size_t kN1 = 512;
+  constexpr size_t kN2 = 257;
+
+  byte data1[kN1] = {byte(0)};
+  byte data2[kN2] = {byte(0)};
+
+  // List should now be 257 -> 512 -> NULL
+  ASSERT_TRUE(list.add_chunk(span<byte>(data1, kN1)));
+  ASSERT_TRUE(list.add_chunk(span<byte>(data2, kN2)));
+
+  auto chunk = list.find_chunk(kN2 + 1);
+  EXPECT_EQ(chunk.size(), kN1);
+}
+
+TEST(LlvmLibcFreeList, FindCanMoveUpThroughBuckets) {
+  // Ensure that finding a chunk will move up through buckets if no appropriate
+  // chunks were found in a given bucket
+  FreeList<SIZE> list(example_sizes);
+  constexpr size_t kN1 = 257;
+  constexpr size_t kN2 = 513;
+
+  byte data1[kN1] = {byte(0)};
+  byte data2[kN2] = {byte(0)};
+
+  // List should now be:
+  // bkt[3] (257 bytes up to 512 bytes) -> 257 -> NULL
+  // bkt[4] (513 bytes up to 1024 bytes) -> 513 -> NULL
+  ASSERT_TRUE(list.add_chunk(span<byte>(data1, kN1)));
+  ASSERT_TRUE(list.add_chunk(span<byte>(data2, kN2)));
+
+  // Request a 300 byte chunk. This should return the 513 byte one
+  auto chunk = list.find_chunk(kN1 + 1);
+  EXPECT_EQ(chunk.size(), kN2);
+}
+
+TEST(LlvmLibcFreeList, RemoveUnknownChunkReturnsNotFound) {
+  FreeList<SIZE> list(example_sizes);
+  constexpr size_t N = 512;
+
+  byte data[N] = {byte(0)};
+  byte data2[N] = {byte(0)};
+
+  ASSERT_TRUE(list.add_chunk(span<byte>(data, N)));
+  EXPECT_FALSE(list.remove_chunk(span<byte>(data2, N)));
+}
+
+TEST(LlvmLibcFreeList, CanStoreMultipleChunksPerBucket) {
+  FreeList<SIZE> list(example_sizes);
+  constexpr size_t N = 512;
+
+  byte data1[N] = {byte(0)};
+  byte data2[N] = {byte(0)};
+
+  ASSERT_TRUE(list.add_chunk(span<byte>(data1, N)));
+  ASSERT_TRUE(list.add_chunk(span<byte>(data2, N)));
+
+  auto chunk1 = list.find_chunk(N);
+  ASSERT_TRUE(list.remove_chunk(chunk1));
+  auto chunk2 = list.find_chunk(N);
+  ASSERT_TRUE(list.remove_chunk(chunk2));
+
+  // Ordering of the chunks doesn't matter
+  EXPECT_TRUE(chunk1.data() != chunk2.data());
+  EXPECT_TRUE(chunk1.data() == data1 || chunk1.data() == data2);
+  EXPECT_TRUE(chunk2.data() == data1 || chunk2.data() == data2);
+}
diff --git a/test/src/__support/str_to_float_comparison_test.cpp b/test/src/__support/str_to_float_comparison_test.cpp
index 19f3f86..7641c59 100644
--- a/test/src/__support/str_to_float_comparison_test.cpp
+++ b/test/src/__support/str_to_float_comparison_test.cpp
@@ -143,7 +143,7 @@ int main(int argc, char *argv[]) {
   int fails = 0;
 
   // Bitdiffs are cases where the expected result and actual result only differ
-  // by +/- the least significant bit. They are tracked seperately from larger
+  // by +/- the least significant bit. They are tracked separately from larger
   // failures since a bitdiff is most likely the result of a rounding error, and
   // splitting them off makes them easier to track down.
   int bitdiffs = 0;
diff --git a/test/src/fcntl/fcntl_test.cpp b/test/src/fcntl/fcntl_test.cpp
index c5cbb61..fc909ac 100644
--- a/test/src/fcntl/fcntl_test.cpp
+++ b/test/src/fcntl/fcntl_test.cpp
@@ -153,3 +153,13 @@ TEST(LlvmLibcFcntlTest, FcntlGetLkWrite) {
 
   ASSERT_THAT(LIBC_NAMESPACE::close(fd), Succeeds(0));
 }
+
+TEST(LlvmLibcFcntlTest, UseAfterClose) {
+  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+  constexpr const char *TEST_FILE_NAME = "testdata/fcntl_use_after_close.test";
+  auto TEST_FILE = libc_make_test_file_path(TEST_FILE_NAME);
+  int fd = LIBC_NAMESPACE::open(TEST_FILE, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU);
+  ASSERT_THAT(LIBC_NAMESPACE::close(fd), Succeeds(0));
+  ASSERT_EQ(-1, LIBC_NAMESPACE::fcntl(fd, F_GETFL));
+  ASSERT_ERRNO_EQ(EBADF);
+}
diff --git a/test/src/math/CeilTest.h b/test/src/math/CeilTest.h
index b4c3752..3af8742 100644
--- a/test/src/math/CeilTest.h
+++ b/test/src/math/CeilTest.h
@@ -6,6 +6,10 @@
 //
 //===----------------------------------------------------------------------===//
 
+#ifndef LLVM_LIBC_TEST_SRC_MATH_CEILTEST_H
+#define LLVM_LIBC_TEST_SRC_MATH_CEILTEST_H
+
+#include "src/__support/CPP/algorithm.h"
 #include "test/UnitTest/FEnvSafeTest.h"
 #include "test/UnitTest/FPMatcher.h"
 #include "test/UnitTest/Test.h"
@@ -59,18 +63,21 @@ public:
     EXPECT_FP_EQ(T(-10.0), func(T(-10.32)));
     EXPECT_FP_EQ(T(11.0), func(T(10.65)));
     EXPECT_FP_EQ(T(-10.0), func(T(-10.65)));
-    EXPECT_FP_EQ(T(1235.0), func(T(1234.38)));
-    EXPECT_FP_EQ(T(-1234.0), func(T(-1234.38)));
-    EXPECT_FP_EQ(T(1235.0), func(T(1234.96)));
-    EXPECT_FP_EQ(T(-1234.0), func(T(-1234.96)));
+    EXPECT_FP_EQ(T(124.0), func(T(123.38)));
+    EXPECT_FP_EQ(T(-123.0), func(T(-123.38)));
+    EXPECT_FP_EQ(T(124.0), func(T(123.96)));
+    EXPECT_FP_EQ(T(-123.0), func(T(-123.96)));
   }
 
   void testRange(CeilFunc func) {
-    constexpr StorageType COUNT = 100'000;
-    constexpr StorageType STEP = STORAGE_MAX / COUNT;
-    for (StorageType i = 0, v = 0; i <= COUNT; ++i, v += STEP) {
-      T x = FPBits(v).get_val();
-      if (isnan(x) || isinf(x))
+    constexpr int COUNT = 100'000;
+    constexpr StorageType STEP = LIBC_NAMESPACE::cpp::max(
+        static_cast<StorageType>(STORAGE_MAX / COUNT), StorageType(1));
+    StorageType v = 0;
+    for (int i = 0; i <= COUNT; ++i, v += STEP) {
+      FPBits xbits(v);
+      T x = xbits.get_val();
+      if (xbits.is_inf_or_nan())
         continue;
 
       ASSERT_MPFR_MATCH(mpfr::Operation::Ceil, x, func(x), 0.0);
@@ -84,3 +91,5 @@ public:
   TEST_F(LlvmLibcCeilTest, RoundedNubmers) { testRoundedNumbers(&func); }      \
   TEST_F(LlvmLibcCeilTest, Fractions) { testFractions(&func); }                \
   TEST_F(LlvmLibcCeilTest, Range) { testRange(&func); }
+
+#endif // LLVM_LIBC_TEST_SRC_MATH_CEILTEST_H
diff --git a/test/src/math/FloorTest.h b/test/src/math/FloorTest.h
index 9103a5b..cce0c73 100644
--- a/test/src/math/FloorTest.h
+++ b/test/src/math/FloorTest.h
@@ -9,6 +9,7 @@
 #ifndef LLVM_LIBC_TEST_SRC_MATH_FLOORTEST_H
 #define LLVM_LIBC_TEST_SRC_MATH_FLOORTEST_H
 
+#include "src/__support/CPP/algorithm.h"
 #include "test/UnitTest/FEnvSafeTest.h"
 #include "test/UnitTest/FPMatcher.h"
 #include "test/UnitTest/Test.h"
@@ -62,18 +63,21 @@ public:
     EXPECT_FP_EQ(T(-11.0), func(T(-10.32)));
     EXPECT_FP_EQ(T(10.0), func(T(10.65)));
     EXPECT_FP_EQ(T(-11.0), func(T(-10.65)));
-    EXPECT_FP_EQ(T(1234.0), func(T(1234.38)));
-    EXPECT_FP_EQ(T(-1235.0), func(T(-1234.38)));
-    EXPECT_FP_EQ(T(1234.0), func(T(1234.96)));
-    EXPECT_FP_EQ(T(-1235.0), func(T(-1234.96)));
+    EXPECT_FP_EQ(T(123.0), func(T(123.38)));
+    EXPECT_FP_EQ(T(-124.0), func(T(-123.38)));
+    EXPECT_FP_EQ(T(123.0), func(T(123.96)));
+    EXPECT_FP_EQ(T(-124.0), func(T(-123.96)));
   }
 
   void testRange(FloorFunc func) {
-    constexpr StorageType COUNT = 100'000;
-    constexpr StorageType STEP = STORAGE_MAX / COUNT;
-    for (StorageType i = 0, v = 0; i <= COUNT; ++i, v += STEP) {
-      T x = FPBits(v).get_val();
-      if (isnan(x) || isinf(x))
+    constexpr int COUNT = 100'000;
+    constexpr StorageType STEP = LIBC_NAMESPACE::cpp::max(
+        static_cast<StorageType>(STORAGE_MAX / COUNT), StorageType(1));
+    StorageType v = 0;
+    for (int i = 0; i <= COUNT; ++i, v += STEP) {
+      FPBits xbits(v);
+      T x = xbits.get_val();
+      if (xbits.is_inf_or_nan())
         continue;
 
       ASSERT_MPFR_MATCH(mpfr::Operation::Floor, x, func(x), 0.0);
diff --git a/test/src/math/FmaTest.h b/test/src/math/FmaTest.h
index 5a40f69..53895e7 100644
--- a/test/src/math/FmaTest.h
+++ b/test/src/math/FmaTest.h
@@ -9,7 +9,6 @@
 #ifndef LLVM_LIBC_TEST_SRC_MATH_FMATEST_H
 #define LLVM_LIBC_TEST_SRC_MATH_FMATEST_H
 
-#include "src/__support/FPUtil/FPBits.h"
 #include "src/stdlib/rand.h"
 #include "src/stdlib/srand.h"
 #include "test/UnitTest/FEnvSafeTest.h"
@@ -19,85 +18,74 @@
 
 namespace mpfr = LIBC_NAMESPACE::testing::mpfr;
 
-template <typename T>
+template <typename OutType, typename InType = OutType>
 class FmaTestTemplate : public LIBC_NAMESPACE::testing::FEnvSafeTest {
-private:
-  using Func = T (*)(T, T, T);
-  using FPBits = LIBC_NAMESPACE::fputil::FPBits<T>;
-  using StorageType = typename FPBits::StorageType;
 
-  const T min_subnormal = FPBits::min_subnormal(Sign::POS).get_val();
-  const T min_normal = FPBits::min_normal(Sign::POS).get_val();
-  const T max_normal = FPBits::max_normal(Sign::POS).get_val();
-  const T inf = FPBits::inf(Sign::POS).get_val();
-  const T neg_inf = FPBits::inf(Sign::NEG).get_val();
-  const T zero = FPBits::zero(Sign::POS).get_val();
-  const T neg_zero = FPBits::zero(Sign::NEG).get_val();
-  const T nan = FPBits::quiet_nan().get_val();
+  struct OutConstants {
+    DECLARE_SPECIAL_CONSTANTS(OutType)
+  };
 
-  static constexpr StorageType MAX_NORMAL = FPBits::max_normal().uintval();
-  static constexpr StorageType MIN_NORMAL = FPBits::min_normal().uintval();
-  static constexpr StorageType MAX_SUBNORMAL =
-      FPBits::max_subnormal().uintval();
-  static constexpr StorageType MIN_SUBNORMAL =
-      FPBits::min_subnormal().uintval();
+  struct InConstants {
+    DECLARE_SPECIAL_CONSTANTS(InType)
+  };
 
-  StorageType get_random_bit_pattern() {
-    StorageType bits{0};
-    for (StorageType i = 0; i < sizeof(StorageType) / 2; ++i) {
+  using OutFPBits = typename OutConstants::FPBits;
+  using OutStorageType = typename OutConstants::StorageType;
+  using InFPBits = typename InConstants::FPBits;
+  using InStorageType = typename InConstants::StorageType;
+
+  static constexpr OutStorageType OUT_MIN_NORMAL_U =
+      OutFPBits::min_normal().uintval();
+  static constexpr InStorageType IN_MAX_NORMAL_U =
+      InFPBits::max_normal().uintval();
+  static constexpr InStorageType IN_MIN_NORMAL_U =
+      InFPBits::min_normal().uintval();
+  static constexpr InStorageType IN_MAX_SUBNORMAL_U =
+      InFPBits::max_subnormal().uintval();
+  static constexpr InStorageType IN_MIN_SUBNORMAL_U =
+      InFPBits::min_subnormal().uintval();
+
+  OutConstants out;
+  InConstants in;
+
+  InStorageType get_random_bit_pattern() {
+    InStorageType bits{0};
+    for (InStorageType i = 0; i < sizeof(InStorageType) / 2; ++i) {
       bits = (bits << 2) + static_cast<uint16_t>(LIBC_NAMESPACE::rand());
     }
     return bits;
   }
 
 public:
-  void test_special_numbers(Func func) {
-    EXPECT_FP_EQ(func(zero, zero, zero), zero);
-    EXPECT_FP_EQ(func(zero, neg_zero, neg_zero), neg_zero);
-    EXPECT_FP_EQ(func(inf, inf, zero), inf);
-    EXPECT_FP_EQ(func(neg_inf, inf, neg_inf), neg_inf);
-    EXPECT_FP_EQ(func(inf, zero, zero), nan);
-    EXPECT_FP_EQ(func(inf, neg_inf, inf), nan);
-    EXPECT_FP_EQ(func(nan, zero, inf), nan);
-    EXPECT_FP_EQ(func(inf, neg_inf, nan), nan);
-
-    // Test underflow rounding up.
-    EXPECT_FP_EQ(func(T(0.5), min_subnormal, min_subnormal),
-                 FPBits(StorageType(2)).get_val());
-    // Test underflow rounding down.
-    T v = FPBits(MIN_NORMAL + StorageType(1)).get_val();
-    EXPECT_FP_EQ(func(T(1) / T(MIN_NORMAL << 1), v, min_normal), v);
-    // Test overflow.
-    T z = max_normal;
-    EXPECT_FP_EQ(func(T(1.75), z, -z), T(0.75) * z);
-    // Exact cancellation.
-    EXPECT_FP_EQ(func(T(3.0), T(5.0), -T(15.0)), T(0.0));
-    EXPECT_FP_EQ(func(T(-3.0), T(5.0), T(15.0)), T(0.0));
-  }
+  using FmaFunc = OutType (*)(InType, InType, InType);
 
-  void test_subnormal_range(Func func) {
-    constexpr StorageType COUNT = 100'001;
-    constexpr StorageType STEP = (MAX_SUBNORMAL - MIN_SUBNORMAL) / COUNT;
+  void test_subnormal_range(FmaFunc func) {
+    constexpr InStorageType COUNT = 100'001;
+    constexpr InStorageType STEP =
+        (IN_MAX_SUBNORMAL_U - IN_MIN_SUBNORMAL_U) / COUNT;
     LIBC_NAMESPACE::srand(1);
-    for (StorageType v = MIN_SUBNORMAL, w = MAX_SUBNORMAL;
-         v <= MAX_SUBNORMAL && w >= MIN_SUBNORMAL; v += STEP, w -= STEP) {
-      T x = FPBits(get_random_bit_pattern()).get_val(), y = FPBits(v).get_val(),
-        z = FPBits(w).get_val();
-      mpfr::TernaryInput<T> input{x, y, z};
+    for (InStorageType v = IN_MIN_SUBNORMAL_U, w = IN_MAX_SUBNORMAL_U;
+         v <= IN_MAX_SUBNORMAL_U && w >= IN_MIN_SUBNORMAL_U;
+         v += STEP, w -= STEP) {
+      InType x = InFPBits(get_random_bit_pattern()).get_val();
+      InType y = InFPBits(v).get_val();
+      InType z = InFPBits(w).get_val();
+      mpfr::TernaryInput<InType> input{x, y, z};
       ASSERT_MPFR_MATCH_ALL_ROUNDING(mpfr::Operation::Fma, input, func(x, y, z),
                                      0.5);
     }
   }
 
-  void test_normal_range(Func func) {
-    constexpr StorageType COUNT = 100'001;
-    constexpr StorageType STEP = (MAX_NORMAL - MIN_NORMAL) / COUNT;
+  void test_normal_range(FmaFunc func) {
+    constexpr InStorageType COUNT = 100'001;
+    constexpr InStorageType STEP = (IN_MAX_NORMAL_U - IN_MIN_NORMAL_U) / COUNT;
     LIBC_NAMESPACE::srand(1);
-    for (StorageType v = MIN_NORMAL, w = MAX_NORMAL;
-         v <= MAX_NORMAL && w >= MIN_NORMAL; v += STEP, w -= STEP) {
-      T x = FPBits(v).get_val(), y = FPBits(w).get_val(),
-        z = FPBits(get_random_bit_pattern()).get_val();
-      mpfr::TernaryInput<T> input{x, y, z};
+    for (InStorageType v = IN_MIN_NORMAL_U, w = IN_MAX_NORMAL_U;
+         v <= IN_MAX_NORMAL_U && w >= IN_MIN_NORMAL_U; v += STEP, w -= STEP) {
+      InType x = InFPBits(v).get_val();
+      InType y = InFPBits(w).get_val();
+      InType z = InFPBits(get_random_bit_pattern()).get_val();
+      mpfr::TernaryInput<InType> input{x, y, z};
       ASSERT_MPFR_MATCH_ALL_ROUNDING(mpfr::Operation::Fma, input, func(x, y, z),
                                      0.5);
     }
diff --git a/test/src/math/RIntTest.h b/test/src/math/RIntTest.h
index 007b504..d31bf74 100644
--- a/test/src/math/RIntTest.h
+++ b/test/src/math/RIntTest.h
@@ -9,6 +9,7 @@
 #ifndef LLVM_LIBC_TEST_SRC_MATH_RINTTEST_H
 #define LLVM_LIBC_TEST_SRC_MATH_RINTTEST_H
 
+#include "src/__support/CPP/algorithm.h"
 #include "src/__support/FPUtil/FEnvImpl.h"
 #include "src/__support/FPUtil/FPBits.h"
 #include "test/UnitTest/FEnvSafeTest.h"
@@ -18,7 +19,6 @@
 
 #include "hdr/fenv_macros.h"
 #include "hdr/math_macros.h"
-#include <stdio.h>
 
 namespace mpfr = LIBC_NAMESPACE::testing::mpfr;
 
@@ -101,8 +101,10 @@ public:
   }
 
   void testSubnormalRange(RIntFunc func) {
-    constexpr StorageType COUNT = 100'001;
-    constexpr StorageType STEP = (MAX_SUBNORMAL - MIN_SUBNORMAL) / COUNT;
+    constexpr int COUNT = 100'001;
+    constexpr StorageType STEP = LIBC_NAMESPACE::cpp::max(
+        static_cast<StorageType>((MAX_SUBNORMAL - MIN_SUBNORMAL) / COUNT),
+        StorageType(1));
     for (StorageType i = MIN_SUBNORMAL; i <= MAX_SUBNORMAL; i += STEP) {
       T x = FPBits(i).get_val();
       for (int mode : ROUNDING_MODES) {
@@ -114,15 +116,17 @@ public:
   }
 
   void testNormalRange(RIntFunc func) {
-    constexpr StorageType COUNT = 100'001;
-    constexpr StorageType STEP = (MAX_NORMAL - MIN_NORMAL) / COUNT;
+    constexpr int COUNT = 100'001;
+    constexpr StorageType STEP = LIBC_NAMESPACE::cpp::max(
+        static_cast<StorageType>((MAX_NORMAL - MIN_NORMAL) / COUNT),
+        StorageType(1));
     for (StorageType i = MIN_NORMAL; i <= MAX_NORMAL; i += STEP) {
-      T x = FPBits(i).get_val();
+      FPBits xbits(i);
+      T x = xbits.get_val();
       // In normal range on x86 platforms, the long double implicit 1 bit can be
       // zero making the numbers NaN. We will skip them.
-      if (isnan(x)) {
+      if (xbits.is_nan())
         continue;
-      }
 
       for (int mode : ROUNDING_MODES) {
         LIBC_NAMESPACE::fputil::set_round(mode);
diff --git a/test/src/math/RoundEvenTest.h b/test/src/math/RoundEvenTest.h
index d70555d..5ecda66 100644
--- a/test/src/math/RoundEvenTest.h
+++ b/test/src/math/RoundEvenTest.h
@@ -9,6 +9,7 @@
 #ifndef LLVM_LIBC_TEST_SRC_MATH_ROUNDEVENTEST_H
 #define LLVM_LIBC_TEST_SRC_MATH_ROUNDEVENTEST_H
 
+#include "src/__support/CPP/algorithm.h"
 #include "test/UnitTest/FEnvSafeTest.h"
 #include "test/UnitTest/FPMatcher.h"
 #include "test/UnitTest/Test.h"
@@ -60,22 +61,25 @@ public:
     EXPECT_FP_EQ(T(-2.0), func(T(-1.75)));
     EXPECT_FP_EQ(T(11.0), func(T(10.65)));
     EXPECT_FP_EQ(T(-11.0), func(T(-10.65)));
-    EXPECT_FP_EQ(T(1233.0), func(T(1233.25)));
-    EXPECT_FP_EQ(T(1234.0), func(T(1233.50)));
-    EXPECT_FP_EQ(T(1234.0), func(T(1233.75)));
-    EXPECT_FP_EQ(T(-1233.0), func(T(-1233.25)));
-    EXPECT_FP_EQ(T(-1234.0), func(T(-1233.50)));
-    EXPECT_FP_EQ(T(-1234.0), func(T(-1233.75)));
-    EXPECT_FP_EQ(T(1234.0), func(T(1234.50)));
-    EXPECT_FP_EQ(T(-1234.0), func(T(-1234.50)));
+    EXPECT_FP_EQ(T(123.0), func(T(123.25)));
+    EXPECT_FP_EQ(T(124.0), func(T(123.50)));
+    EXPECT_FP_EQ(T(124.0), func(T(123.75)));
+    EXPECT_FP_EQ(T(-123.0), func(T(-123.25)));
+    EXPECT_FP_EQ(T(-124.0), func(T(-123.50)));
+    EXPECT_FP_EQ(T(-124.0), func(T(-123.75)));
+    EXPECT_FP_EQ(T(124.0), func(T(124.50)));
+    EXPECT_FP_EQ(T(-124.0), func(T(-124.50)));
   }
 
   void testRange(RoundEvenFunc func) {
-    constexpr StorageType COUNT = 100'000;
-    constexpr StorageType STEP = STORAGE_MAX / COUNT;
-    for (StorageType i = 0, v = 0; i <= COUNT; ++i, v += STEP) {
-      T x = FPBits(v).get_val();
-      if (isnan(x) || isinf(x))
+    constexpr int COUNT = 100'000;
+    constexpr StorageType STEP = LIBC_NAMESPACE::cpp::max(
+        static_cast<StorageType>(STORAGE_MAX / COUNT), StorageType(1));
+    StorageType v = 0;
+    for (int i = 0; i <= COUNT; ++i, v += STEP) {
+      FPBits xbits(v);
+      T x = xbits.get_val();
+      if (xbits.is_inf_or_nan())
         continue;
 
       ASSERT_MPFR_MATCH(mpfr::Operation::RoundEven, x, func(x), 0.0);
diff --git a/test/src/math/RoundTest.h b/test/src/math/RoundTest.h
index 2a31df3..d571d5d 100644
--- a/test/src/math/RoundTest.h
+++ b/test/src/math/RoundTest.h
@@ -9,6 +9,7 @@
 #ifndef LLVM_LIBC_TEST_SRC_MATH_ROUNDTEST_H
 #define LLVM_LIBC_TEST_SRC_MATH_ROUNDTEST_H
 
+#include "src/__support/CPP/algorithm.h"
 #include "test/UnitTest/FEnvSafeTest.h"
 #include "test/UnitTest/FPMatcher.h"
 #include "test/UnitTest/Test.h"
@@ -62,18 +63,21 @@ public:
     EXPECT_FP_EQ(T(-10.0), func(T(-10.32)));
     EXPECT_FP_EQ(T(11.0), func(T(10.65)));
     EXPECT_FP_EQ(T(-11.0), func(T(-10.65)));
-    EXPECT_FP_EQ(T(1234.0), func(T(1234.38)));
-    EXPECT_FP_EQ(T(-1234.0), func(T(-1234.38)));
-    EXPECT_FP_EQ(T(1235.0), func(T(1234.96)));
-    EXPECT_FP_EQ(T(-1235.0), func(T(-1234.96)));
+    EXPECT_FP_EQ(T(123.0), func(T(123.38)));
+    EXPECT_FP_EQ(T(-123.0), func(T(-123.38)));
+    EXPECT_FP_EQ(T(124.0), func(T(123.96)));
+    EXPECT_FP_EQ(T(-124.0), func(T(-123.96)));
   }
 
   void testRange(RoundFunc func) {
-    constexpr StorageType COUNT = 100'000;
-    constexpr StorageType STEP = STORAGE_MAX / COUNT;
-    for (StorageType i = 0, v = 0; i <= COUNT; ++i, v += STEP) {
-      T x = FPBits(v).get_val();
-      if (isnan(x) || isinf(x))
+    constexpr int COUNT = 100'000;
+    constexpr StorageType STEP = LIBC_NAMESPACE::cpp::max(
+        static_cast<StorageType>(STORAGE_MAX / COUNT), StorageType(1));
+    StorageType v = 0;
+    for (int i = 0; i <= COUNT; ++i, v += STEP) {
+      FPBits xbits(v);
+      T x = xbits.get_val();
+      if (xbits.is_inf_or_nan())
         continue;
 
       ASSERT_MPFR_MATCH(mpfr::Operation::Round, x, func(x), 0.0);
diff --git a/test/src/math/RoundToIntegerTest.h b/test/src/math/RoundToIntegerTest.h
index d40e150..bb7e864 100644
--- a/test/src/math/RoundToIntegerTest.h
+++ b/test/src/math/RoundToIntegerTest.h
@@ -9,6 +9,7 @@
 #ifndef LLVM_LIBC_TEST_SRC_MATH_ROUNDTOINTEGERTEST_H
 #define LLVM_LIBC_TEST_SRC_MATH_ROUNDTOINTEGERTEST_H
 
+#include "src/__support/CPP/algorithm.h"
 #include "src/__support/FPUtil/FEnvImpl.h"
 #include "src/__support/FPUtil/FPBits.h"
 #include "test/UnitTest/FEnvSafeTest.h"
@@ -136,10 +137,13 @@ public:
       return;
 
     constexpr int EXPONENT_LIMIT = sizeof(I) * 8 - 1;
+    constexpr int BIASED_EXPONENT_LIMIT = EXPONENT_LIMIT + FPBits::EXP_BIAS;
+    if (BIASED_EXPONENT_LIMIT > FPBits::MAX_BIASED_EXPONENT)
+      return;
     // We start with 1.0 so that the implicit bit for x86 long doubles
     // is set.
     FPBits bits(F(1.0));
-    bits.set_biased_exponent(EXPONENT_LIMIT + FPBits::EXP_BIAS);
+    bits.set_biased_exponent(BIASED_EXPONENT_LIMIT);
     bits.set_sign(Sign::NEG);
     bits.set_mantissa(0);
 
@@ -200,10 +204,13 @@ public:
       return;
 
     constexpr int EXPONENT_LIMIT = sizeof(I) * 8 - 1;
+    constexpr int BIASED_EXPONENT_LIMIT = EXPONENT_LIMIT + FPBits::EXP_BIAS;
+    if (BIASED_EXPONENT_LIMIT > FPBits::MAX_BIASED_EXPONENT)
+      return;
     // We start with 1.0 so that the implicit bit for x86 long doubles
     // is set.
     FPBits bits(F(1.0));
-    bits.set_biased_exponent(EXPONENT_LIMIT + FPBits::EXP_BIAS);
+    bits.set_biased_exponent(BIASED_EXPONENT_LIMIT);
     bits.set_sign(Sign::NEG);
     bits.set_mantissa(FPBits::FRACTION_MASK);
 
@@ -226,8 +233,10 @@ public:
   }
 
   void testSubnormalRange(RoundToIntegerFunc func) {
-    constexpr StorageType COUNT = 1'000'001;
-    constexpr StorageType STEP = (MAX_SUBNORMAL - MIN_SUBNORMAL) / COUNT;
+    constexpr int COUNT = 1'000'001;
+    constexpr StorageType STEP = LIBC_NAMESPACE::cpp::max(
+        static_cast<StorageType>((MAX_SUBNORMAL - MIN_SUBNORMAL) / COUNT),
+        StorageType(1));
     for (StorageType i = MIN_SUBNORMAL; i <= MAX_SUBNORMAL; i += STEP) {
       F x = FPBits(i).get_val();
       if (x == F(0.0))
@@ -268,15 +277,17 @@ public:
     if (sizeof(I) > sizeof(long))
       return;
 
-    constexpr StorageType COUNT = 1'000'001;
-    constexpr StorageType STEP = (MAX_NORMAL - MIN_NORMAL) / COUNT;
+    constexpr int COUNT = 1'000'001;
+    constexpr StorageType STEP = LIBC_NAMESPACE::cpp::max(
+        static_cast<StorageType>((MAX_NORMAL - MIN_NORMAL) / COUNT),
+        StorageType(1));
     for (StorageType i = MIN_NORMAL; i <= MAX_NORMAL; i += STEP) {
-      F x = FPBits(i).get_val();
+      FPBits xbits(i);
+      F x = xbits.get_val();
       // In normal range on x86 platforms, the long double implicit 1 bit can be
       // zero making the numbers NaN. We will skip them.
-      if (isnan(x)) {
+      if (xbits.is_nan())
         continue;
-      }
 
       if (TestModes) {
         for (int m : ROUNDING_MODES) {
diff --git a/test/src/math/TruncTest.h b/test/src/math/TruncTest.h
index bc5b761..76c9740 100644
--- a/test/src/math/TruncTest.h
+++ b/test/src/math/TruncTest.h
@@ -9,6 +9,7 @@
 #ifndef LLVM_LIBC_TEST_SRC_MATH_TRUNCTEST_H
 #define LLVM_LIBC_TEST_SRC_MATH_TRUNCTEST_H
 
+#include "src/__support/CPP/algorithm.h"
 #include "test/UnitTest/FEnvSafeTest.h"
 #include "test/UnitTest/FPMatcher.h"
 #include "test/UnitTest/Test.h"
@@ -62,18 +63,21 @@ public:
     EXPECT_FP_EQ(T(-10.0), func(T(-10.32)));
     EXPECT_FP_EQ(T(10.0), func(T(10.65)));
     EXPECT_FP_EQ(T(-10.0), func(T(-10.65)));
-    EXPECT_FP_EQ(T(1234.0), func(T(1234.38)));
-    EXPECT_FP_EQ(T(-1234.0), func(T(-1234.38)));
-    EXPECT_FP_EQ(T(1234.0), func(T(1234.96)));
-    EXPECT_FP_EQ(T(-1234.0), func(T(-1234.96)));
+    EXPECT_FP_EQ(T(123.0), func(T(123.38)));
+    EXPECT_FP_EQ(T(-123.0), func(T(-123.38)));
+    EXPECT_FP_EQ(T(123.0), func(T(123.96)));
+    EXPECT_FP_EQ(T(-123.0), func(T(-123.96)));
   }
 
   void testRange(TruncFunc func) {
-    constexpr StorageType COUNT = 100'000;
-    constexpr StorageType STEP = STORAGE_MAX / COUNT;
-    for (StorageType i = 0, v = 0; i <= COUNT; ++i, v += STEP) {
-      T x = FPBits(v).get_val();
-      if (isnan(x) || isinf(x))
+    constexpr int COUNT = 100'000;
+    constexpr StorageType STEP = LIBC_NAMESPACE::cpp::max(
+        static_cast<StorageType>(STORAGE_MAX / COUNT), StorageType(1));
+    StorageType v = 0;
+    for (int i = 0; i <= COUNT; ++i, v += STEP) {
+      FPBits xbits(v);
+      T x = xbits.get_val();
+      if (xbits.is_inf_or_nan())
         continue;
 
       ASSERT_MPFR_MATCH(mpfr::Operation::Trunc, x, func(x), 0.0);
diff --git a/test/src/math/ceilf16_test.cpp b/test/src/math/ceilf16_test.cpp
new file mode 100644
index 0000000..a6ec922
--- /dev/null
+++ b/test/src/math/ceilf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for ceilf16 ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "CeilTest.h"
+
+#include "src/math/ceilf16.h"
+
+LIST_CEIL_TESTS(float16, LIBC_NAMESPACE::ceilf16)
diff --git a/test/src/math/exhaustive/exhaustive_test.h b/test/src/math/exhaustive/exhaustive_test.h
index c4ae382..13e2727 100644
--- a/test/src/math/exhaustive/exhaustive_test.h
+++ b/test/src/math/exhaustive/exhaustive_test.h
@@ -35,16 +35,16 @@
 //   LlvmLibcUnaryOpExhaustiveMathTest<FloatType, Op, Func>.
 namespace mpfr = LIBC_NAMESPACE::testing::mpfr;
 
-template <typename T> using UnaryOp = T(T);
+template <typename OutType, typename InType = OutType>
+using UnaryOp = OutType(InType);
 
-template <typename T, mpfr::Operation Op, UnaryOp<T> Func>
+template <typename OutType, typename InType, mpfr::Operation Op,
+          UnaryOp<OutType, InType> Func>
 struct UnaryOpChecker : public virtual LIBC_NAMESPACE::testing::Test {
-  using FloatType = T;
+  using FloatType = InType;
   using FPBits = LIBC_NAMESPACE::fputil::FPBits<FloatType>;
   using StorageType = typename FPBits::StorageType;
 
-  static constexpr UnaryOp<FloatType> *FUNC = Func;
-
   // Check in a range, return the number of failures.
   uint64_t check(StorageType start, StorageType stop,
                  mpfr::RoundingMode rounding) {
@@ -57,11 +57,11 @@ struct UnaryOpChecker : public virtual LIBC_NAMESPACE::testing::Test {
       FPBits xbits(bits);
       FloatType x = xbits.get_val();
       bool correct =
-          TEST_MPFR_MATCH_ROUNDING_SILENTLY(Op, x, FUNC(x), 0.5, rounding);
+          TEST_MPFR_MATCH_ROUNDING_SILENTLY(Op, x, Func(x), 0.5, rounding);
       failed += (!correct);
       // Uncomment to print out failed values.
       // if (!correct) {
-      //   TEST_MPFR_MATCH(Op::Operation, x, Op::func(x), 0.5, rounding);
+      //   EXPECT_MPFR_MATCH_ROUNDING(Op, x, Func(x), 0.5, rounding);
       // }
     } while (bits++ < stop);
     return failed;
@@ -169,4 +169,9 @@ struct LlvmLibcExhaustiveMathTest
 
 template <typename FloatType, mpfr::Operation Op, UnaryOp<FloatType> Func>
 using LlvmLibcUnaryOpExhaustiveMathTest =
-    LlvmLibcExhaustiveMathTest<UnaryOpChecker<FloatType, Op, Func>>;
+    LlvmLibcExhaustiveMathTest<UnaryOpChecker<FloatType, FloatType, Op, Func>>;
+
+template <typename OutType, typename InType, mpfr::Operation Op,
+          UnaryOp<OutType, InType> Func>
+using LlvmLibcUnaryNarrowingOpExhaustiveMathTest =
+    LlvmLibcExhaustiveMathTest<UnaryOpChecker<OutType, InType, Op, Func>>;
diff --git a/test/src/math/exhaustive/f16sqrtf_test.cpp b/test/src/math/exhaustive/f16sqrtf_test.cpp
new file mode 100644
index 0000000..3a42ff8
--- /dev/null
+++ b/test/src/math/exhaustive/f16sqrtf_test.cpp
@@ -0,0 +1,25 @@
+//===-- Exhaustive test for f16sqrtf --------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "exhaustive_test.h"
+#include "src/math/f16sqrtf.h"
+#include "utils/MPFRWrapper/MPFRUtils.h"
+
+namespace mpfr = LIBC_NAMESPACE::testing::mpfr;
+
+using LlvmLibcF16sqrtfExhaustiveTest =
+    LlvmLibcUnaryNarrowingOpExhaustiveMathTest<
+        float16, float, mpfr::Operation::Sqrt, LIBC_NAMESPACE::f16sqrtf>;
+
+// Range: [0, Inf];
+static constexpr uint32_t POS_START = 0x0000'0000U;
+static constexpr uint32_t POS_STOP = 0x7f80'0000U;
+
+TEST_F(LlvmLibcF16sqrtfExhaustiveTest, PostiveRange) {
+  test_full_range_all_roundings(POS_START, POS_STOP);
+}
diff --git a/test/src/math/f16fmaf_test.cpp b/test/src/math/f16fmaf_test.cpp
new file mode 100644
index 0000000..e4ca88b
--- /dev/null
+++ b/test/src/math/f16fmaf_test.cpp
@@ -0,0 +1,21 @@
+//===-- Unittests for f16fmaf ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "FmaTest.h"
+
+#include "src/math/f16fmaf.h"
+
+using LlvmLibcF16fmafTest = FmaTestTemplate<float16, float>;
+
+TEST_F(LlvmLibcF16fmafTest, SubnormalRange) {
+  test_subnormal_range(&LIBC_NAMESPACE::f16fmaf);
+}
+
+TEST_F(LlvmLibcF16fmafTest, NormalRange) {
+  test_normal_range(&LIBC_NAMESPACE::f16fmaf);
+}
diff --git a/test/src/math/floorf16_test.cpp b/test/src/math/floorf16_test.cpp
new file mode 100644
index 0000000..ca5160e
--- /dev/null
+++ b/test/src/math/floorf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for floorf16 --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "FloorTest.h"
+
+#include "src/math/floorf16.h"
+
+LIST_FLOOR_TESTS(float16, LIBC_NAMESPACE::floorf16)
diff --git a/test/src/math/fma_test.cpp b/test/src/math/fma_test.cpp
index 20224d9..dd76138 100644
--- a/test/src/math/fma_test.cpp
+++ b/test/src/math/fma_test.cpp
@@ -276,10 +276,6 @@ struct LlvmLibcFmaTest : public FmaTestTemplate<double> {
   }
 };
 
-TEST_F(LlvmLibcFmaTest, SpecialNumbers) {
-  test_special_numbers(&LIBC_NAMESPACE::fma);
-}
-
 TEST_F(LlvmLibcFmaTest, SubnormalRange) {
   test_subnormal_range(&LIBC_NAMESPACE::fma);
 }
diff --git a/test/src/math/fmaf_test.cpp b/test/src/math/fmaf_test.cpp
index b607d4a..0e498d4 100644
--- a/test/src/math/fmaf_test.cpp
+++ b/test/src/math/fmaf_test.cpp
@@ -12,10 +12,6 @@
 
 using LlvmLibcFmafTest = FmaTestTemplate<float>;
 
-TEST_F(LlvmLibcFmafTest, SpecialNumbers) {
-  test_special_numbers(&LIBC_NAMESPACE::fmaf);
-}
-
 TEST_F(LlvmLibcFmafTest, SubnormalRange) {
   test_subnormal_range(&LIBC_NAMESPACE::fmaf);
 }
diff --git a/test/src/math/llrintf16_test.cpp b/test/src/math/llrintf16_test.cpp
new file mode 100644
index 0000000..d16bd8f
--- /dev/null
+++ b/test/src/math/llrintf16_test.cpp
@@ -0,0 +1,14 @@
+//===-- Unittests for llrintf16 -------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "RoundToIntegerTest.h"
+
+#include "src/math/llrintf16.h"
+
+LIST_ROUND_TO_INTEGER_TESTS_WITH_MODES(float16, long long,
+                                       LIBC_NAMESPACE::llrintf16)
diff --git a/test/src/math/llroundf16_test.cpp b/test/src/math/llroundf16_test.cpp
new file mode 100644
index 0000000..9342b24
--- /dev/null
+++ b/test/src/math/llroundf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for llroundf16 ------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "RoundToIntegerTest.h"
+
+#include "src/math/llroundf16.h"
+
+LIST_ROUND_TO_INTEGER_TESTS(float16, long long, LIBC_NAMESPACE::llroundf16)
diff --git a/test/src/math/lrintf16_test.cpp b/test/src/math/lrintf16_test.cpp
new file mode 100644
index 0000000..28b1a1c
--- /dev/null
+++ b/test/src/math/lrintf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for lrintf16 --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "RoundToIntegerTest.h"
+
+#include "src/math/lrintf16.h"
+
+LIST_ROUND_TO_INTEGER_TESTS_WITH_MODES(float16, long, LIBC_NAMESPACE::lrintf16)
diff --git a/test/src/math/lroundf16_test.cpp b/test/src/math/lroundf16_test.cpp
new file mode 100644
index 0000000..3077134
--- /dev/null
+++ b/test/src/math/lroundf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for lroundf16 -------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "RoundToIntegerTest.h"
+
+#include "src/math/lroundf16.h"
+
+LIST_ROUND_TO_INTEGER_TESTS(float16, long, LIBC_NAMESPACE::lroundf16)
diff --git a/test/src/math/rintf16_test.cpp b/test/src/math/rintf16_test.cpp
new file mode 100644
index 0000000..2adf256
--- /dev/null
+++ b/test/src/math/rintf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for rintf16 ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "RIntTest.h"
+
+#include "src/math/rintf16.h"
+
+LIST_RINT_TESTS(float16, LIBC_NAMESPACE::rintf16)
diff --git a/test/src/math/roundevenf16_test.cpp b/test/src/math/roundevenf16_test.cpp
new file mode 100644
index 0000000..911a32c
--- /dev/null
+++ b/test/src/math/roundevenf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for roundevenf16 ----------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "RoundEvenTest.h"
+
+#include "src/math/roundevenf16.h"
+
+LIST_ROUNDEVEN_TESTS(float16, LIBC_NAMESPACE::roundevenf16)
diff --git a/test/src/math/roundf16_test.cpp b/test/src/math/roundf16_test.cpp
new file mode 100644
index 0000000..54ead85
--- /dev/null
+++ b/test/src/math/roundf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for roundf16 --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "RoundTest.h"
+
+#include "src/math/roundf16.h"
+
+LIST_ROUND_TESTS(float16, LIBC_NAMESPACE::roundf16)
diff --git a/test/src/math/smoke/FMulTest.h b/test/src/math/smoke/FMulTest.h
new file mode 100644
index 0000000..33fb82c
--- /dev/null
+++ b/test/src/math/smoke/FMulTest.h
@@ -0,0 +1,104 @@
+//===-- Utility class to test fmul[f|l] ---------------------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LLVM_LIBC_TEST_SRC_MATH_SMOKE_FMULTEST_H
+#define LLVM_LIBC_TEST_SRC_MATH_SMOKE_FMULTEST_H
+
+#include "test/UnitTest/FEnvSafeTest.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+
+template <typename T, typename R>
+class FmulTest : public LIBC_NAMESPACE::testing::FEnvSafeTest {
+
+  DECLARE_SPECIAL_CONSTANTS(T)
+
+public:
+  typedef T (*FMulFunc)(R, R);
+
+  void testMul(FMulFunc func) {
+
+    EXPECT_FP_EQ_ALL_ROUNDING(T(15.0), func(3.0, 5.0));
+    EXPECT_FP_EQ_ALL_ROUNDING(T(0x1.0p-130), func(0x1.0p1, 0x1.0p-131));
+    EXPECT_FP_EQ_ALL_ROUNDING(T(0x1.0p-127), func(0x1.0p2, 0x1.0p-129));
+    EXPECT_FP_EQ_ALL_ROUNDING(T(1.0), func(1.0, 1.0));
+
+    EXPECT_FP_EQ_ALL_ROUNDING(T(0.0), func(-0.0, -0.0));
+    EXPECT_FP_EQ_ALL_ROUNDING(T(-0.0), func(0.0, -0.0));
+    EXPECT_FP_EQ_ALL_ROUNDING(T(-0.0), func(-0.0, 0.0));
+
+    EXPECT_FP_EQ_ROUNDING_NEAREST(inf, func(0x1.0p100, 0x1.0p100));
+    EXPECT_FP_EQ_ROUNDING_UPWARD(inf, func(0x1.0p100, 0x1.0p100));
+    EXPECT_FP_EQ_ROUNDING_DOWNWARD(max_normal, func(0x1.0p100, 0x1.0p100));
+    EXPECT_FP_EQ_ROUNDING_TOWARD_ZERO(max_normal, func(0x1.0p100, 0x1.0p100));
+
+    EXPECT_FP_EQ_ROUNDING_NEAREST(
+        0x1p0, func(1.0, 1.0 + 0x1.0p-128 + 0x1.0p-149 + 0x1.0p-150));
+    EXPECT_FP_EQ_ROUNDING_DOWNWARD(
+        0x1p0, func(1.0, 1.0 + 0x1.0p-128 + 0x1.0p-149 + 0x1.0p-150));
+    EXPECT_FP_EQ_ROUNDING_TOWARD_ZERO(
+        0x1p0, func(1.0, 1.0 + 0x1.0p-128 + 0x1.0p-149 + 0x1.0p-150));
+    EXPECT_FP_EQ_ROUNDING_UPWARD(
+        0x1p0, func(1.0, 1.0 + 0x1.0p-128 + 0x1.0p-149 + 0x1.0p-150));
+
+    EXPECT_FP_EQ_ROUNDING_NEAREST(
+        0x1.0p-128f + 0x1.0p-148f,
+        func(1.0, 0x1.0p-128 + 0x1.0p-149 + 0x1.0p-150));
+    EXPECT_FP_EQ_ROUNDING_UPWARD(
+        0x1.0p-128f + 0x1.0p-148f,
+        func(1.0, 0x1.0p-128 + 0x1.0p-149 + 0x1.0p-150));
+    EXPECT_FP_EQ_ROUNDING_DOWNWARD(
+        0x1.0p-128f + 0x1.0p-149f,
+        func(1.0, 0x1.0p-128 + 0x1.0p-149 + 0x1.0p-150));
+    EXPECT_FP_EQ_ROUNDING_TOWARD_ZERO(
+        0x1.0p-128f + 0x1.0p-149f,
+        func(1.0, 0x1.0p-128 + 0x1.0p-149 + 0x1.0p-150));
+  }
+
+  void testSpecialInputs(FMulFunc func) {
+    EXPECT_FP_EQ_ALL_ROUNDING(inf, func(inf, 0x1.0p-129));
+    EXPECT_FP_EQ_ALL_ROUNDING(inf, func(0x1.0p-129, inf));
+    EXPECT_FP_EQ_ALL_ROUNDING(inf, func(inf, 2.0));
+    EXPECT_FP_EQ_ALL_ROUNDING(inf, func(3.0, inf));
+    EXPECT_FP_EQ_ALL_ROUNDING(0.0, func(0.0, 0.0));
+
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(neg_inf, aNaN));
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(aNaN, neg_inf));
+    EXPECT_FP_EQ_ALL_ROUNDING(inf, func(neg_inf, neg_inf));
+
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(0.0, neg_inf));
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(neg_inf, 0.0));
+
+    EXPECT_FP_EQ_ALL_ROUNDING(neg_inf, func(neg_inf, 1.0));
+    EXPECT_FP_EQ_ALL_ROUNDING(neg_inf, func(1.0, neg_inf));
+
+    EXPECT_FP_EQ_ALL_ROUNDING(neg_inf, func(neg_inf, 0x1.0p-129));
+    EXPECT_FP_EQ_ALL_ROUNDING(neg_inf, func(0x1.0p-129, neg_inf));
+
+    EXPECT_FP_EQ_ALL_ROUNDING(0.0, func(0.0, 0x1.0p-129));
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(inf, 0.0));
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(0.0, inf));
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(0.0, aNaN));
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(2.0, aNaN));
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(0x1.0p-129, aNaN));
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(inf, aNaN));
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(aNaN, aNaN));
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(0.0, sNaN));
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(2.0, sNaN));
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(0x1.0p-129, sNaN));
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(inf, sNaN));
+    EXPECT_FP_EQ_ALL_ROUNDING(aNaN, func(sNaN, sNaN));
+  }
+};
+
+#define LIST_FMUL_TESTS(T, R, func)                                            \
+  using LlvmLibcFmulTest = FmulTest<T, R>;                                     \
+  TEST_F(LlvmLibcFmulTest, Mul) { testMul(&func); }                            \
+  TEST_F(LlvmLibcFmulTest, NaNInf) { testSpecialInputs(&func); }
+
+#endif // LLVM_LIBC_TEST_SRC_MATH_SMOKE_FMULTEST_H
diff --git a/test/src/math/smoke/FmaTest.h b/test/src/math/smoke/FmaTest.h
index 7063ecf..f942de3 100644
--- a/test/src/math/smoke/FmaTest.h
+++ b/test/src/math/smoke/FmaTest.h
@@ -9,51 +9,103 @@
 #ifndef LLVM_LIBC_TEST_SRC_MATH_FMATEST_H
 #define LLVM_LIBC_TEST_SRC_MATH_FMATEST_H
 
-#include "src/__support/FPUtil/FPBits.h"
 #include "test/UnitTest/FEnvSafeTest.h"
 #include "test/UnitTest/FPMatcher.h"
 #include "test/UnitTest/Test.h"
 
-template <typename T>
+template <typename OutType, typename InType = OutType>
 class FmaTestTemplate : public LIBC_NAMESPACE::testing::FEnvSafeTest {
-private:
-  using Func = T (*)(T, T, T);
-  using FPBits = LIBC_NAMESPACE::fputil::FPBits<T>;
-  using StorageType = typename FPBits::StorageType;
 
-  const T inf = FPBits::inf(Sign::POS).get_val();
-  const T neg_inf = FPBits::inf(Sign::NEG).get_val();
-  const T zero = FPBits::zero(Sign::POS).get_val();
-  const T neg_zero = FPBits::zero(Sign::NEG).get_val();
-  const T nan = FPBits::quiet_nan().get_val();
+  struct OutConstants {
+    DECLARE_SPECIAL_CONSTANTS(OutType)
+  };
+
+  struct InConstants {
+    DECLARE_SPECIAL_CONSTANTS(InType)
+  };
+
+  using OutFPBits = typename OutConstants::FPBits;
+  using OutStorageType = typename OutConstants::StorageType;
+  using InFPBits = typename InConstants::FPBits;
+  using InStorageType = typename InConstants::StorageType;
+
+  static constexpr OutStorageType OUT_MIN_NORMAL_U =
+      OutFPBits::min_normal().uintval();
+  static constexpr InStorageType IN_MIN_NORMAL_U =
+      InFPBits::min_normal().uintval();
+
+  OutConstants out;
+  InConstants in;
 
 public:
-  void test_special_numbers(Func func) {
-    EXPECT_FP_EQ(func(zero, zero, zero), zero);
-    EXPECT_FP_EQ(func(zero, neg_zero, neg_zero), neg_zero);
-    EXPECT_FP_EQ(func(inf, inf, zero), inf);
-    EXPECT_FP_EQ(func(neg_inf, inf, neg_inf), neg_inf);
-    EXPECT_FP_EQ(func(inf, zero, zero), nan);
-    EXPECT_FP_EQ(func(inf, neg_inf, inf), nan);
-    EXPECT_FP_EQ(func(nan, zero, inf), nan);
-    EXPECT_FP_EQ(func(inf, neg_inf, nan), nan);
+  using FmaFunc = OutType (*)(InType, InType, InType);
+
+  void test_special_numbers(FmaFunc func) {
+    EXPECT_FP_EQ(out.zero, func(in.zero, in.zero, in.zero));
+    EXPECT_FP_EQ(out.neg_zero, func(in.zero, in.neg_zero, in.neg_zero));
+    EXPECT_FP_EQ(out.inf, func(in.inf, in.inf, in.zero));
+    EXPECT_FP_EQ(out.neg_inf, func(in.neg_inf, in.inf, in.neg_inf));
+    EXPECT_FP_EQ(out.aNaN, func(in.inf, in.zero, in.zero));
+    EXPECT_FP_EQ(out.aNaN, func(in.inf, in.neg_inf, in.inf));
+    EXPECT_FP_EQ(out.aNaN, func(in.aNaN, in.zero, in.inf));
+    EXPECT_FP_EQ(out.aNaN, func(in.inf, in.neg_inf, in.aNaN));
 
     // Test underflow rounding up.
-    EXPECT_FP_EQ(func(T(0.5), FPBits::min_subnormal().get_val(),
-                      FPBits::min_subnormal().get_val()),
-                 FPBits(StorageType(2)).get_val());
+    EXPECT_FP_EQ(OutFPBits(OutStorageType(2)).get_val(),
+                 func(OutType(0.5), out.min_denormal, out.min_denormal));
+
+    if constexpr (sizeof(OutType) < sizeof(InType)) {
+      EXPECT_FP_EQ(out.zero,
+                   func(InType(0.5), in.min_denormal, in.min_denormal));
+    }
+
     // Test underflow rounding down.
-    StorageType MIN_NORMAL = FPBits::min_normal().uintval();
-    T v = FPBits(MIN_NORMAL + StorageType(1)).get_val();
-    EXPECT_FP_EQ(
-        func(T(1) / T(MIN_NORMAL << 1), v, FPBits::min_normal().get_val()), v);
+    OutType v = OutFPBits(static_cast<OutStorageType>(OUT_MIN_NORMAL_U +
+                                                      OutStorageType(1)))
+                    .get_val();
+    EXPECT_FP_EQ(v, func(OutType(1) / OutType(OUT_MIN_NORMAL_U << 1), v,
+                         out.min_normal));
+
+    if constexpr (sizeof(OutType) < sizeof(InType)) {
+      InType v = InFPBits(static_cast<InStorageType>(IN_MIN_NORMAL_U +
+                                                     InStorageType(1)))
+                     .get_val();
+      EXPECT_FP_EQ(
+          out.min_normal,
+          func(InType(1) / InType(IN_MIN_NORMAL_U << 1), v, out.min_normal));
+    }
+
     // Test overflow.
-    T z = FPBits::max_normal().get_val();
-    EXPECT_FP_EQ(func(T(1.75), z, -z), T(0.75) * z);
+    OutType z = out.max_normal;
+    EXPECT_FP_EQ_ALL_ROUNDING(OutType(0.75) * z, func(InType(1.75), z, -z));
+
     // Exact cancellation.
-    EXPECT_FP_EQ(func(T(3.0), T(5.0), -T(15.0)), T(0.0));
-    EXPECT_FP_EQ(func(T(-3.0), T(5.0), T(15.0)), T(0.0));
+    EXPECT_FP_EQ_ROUNDING_NEAREST(
+        out.zero, func(InType(3.0), InType(5.0), InType(-15.0)));
+    EXPECT_FP_EQ_ROUNDING_UPWARD(out.zero,
+                                 func(InType(3.0), InType(5.0), InType(-15.0)));
+    EXPECT_FP_EQ_ROUNDING_TOWARD_ZERO(
+        out.zero, func(InType(3.0), InType(5.0), InType(-15.0)));
+    EXPECT_FP_EQ_ROUNDING_DOWNWARD(
+        out.neg_zero, func(InType(3.0), InType(5.0), InType(-15.0)));
+
+    EXPECT_FP_EQ_ROUNDING_NEAREST(
+        out.zero, func(InType(-3.0), InType(5.0), InType(15.0)));
+    EXPECT_FP_EQ_ROUNDING_UPWARD(out.zero,
+                                 func(InType(-3.0), InType(5.0), InType(15.0)));
+    EXPECT_FP_EQ_ROUNDING_TOWARD_ZERO(
+        out.zero, func(InType(-3.0), InType(5.0), InType(15.0)));
+    EXPECT_FP_EQ_ROUNDING_DOWNWARD(
+        out.neg_zero, func(InType(-3.0), InType(5.0), InType(15.0)));
   }
 };
 
+#define LIST_FMA_TESTS(T, func)                                                \
+  using LlvmLibcFmaTest = FmaTestTemplate<T>;                                  \
+  TEST_F(LlvmLibcFmaTest, SpecialNumbers) { test_special_numbers(&func); }
+
+#define LIST_NARROWING_FMA_TESTS(OutType, InType, func)                        \
+  using LlvmLibcFmaTest = FmaTestTemplate<OutType, InType>;                    \
+  TEST_F(LlvmLibcFmaTest, SpecialNumbers) { test_special_numbers(&func); }
+
 #endif // LLVM_LIBC_TEST_SRC_MATH_FMATEST_H
diff --git a/test/src/math/smoke/FrexpTest.h b/test/src/math/smoke/FrexpTest.h
index e9e4964..fc2313a 100644
--- a/test/src/math/smoke/FrexpTest.h
+++ b/test/src/math/smoke/FrexpTest.h
@@ -6,7 +6,6 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/__support/FPUtil/BasicOperations.h"
 #include "test/UnitTest/FEnvSafeTest.h"
 #include "test/UnitTest/FPMatcher.h"
 #include "test/UnitTest/Test.h"
diff --git a/test/src/math/smoke/GetPayloadTest.h b/test/src/math/smoke/GetPayloadTest.h
new file mode 100644
index 0000000..6e30de7
--- /dev/null
+++ b/test/src/math/smoke/GetPayloadTest.h
@@ -0,0 +1,70 @@
+//===-- Utility class to test different flavors of getpayload ---*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LIBC_TEST_SRC_MATH_SMOKE_GETPAYLOADTEST_H
+#define LIBC_TEST_SRC_MATH_SMOKE_GETPAYLOADTEST_H
+
+#include "test/UnitTest/FEnvSafeTest.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+
+template <typename T>
+class GetPayloadTestTemplate : public LIBC_NAMESPACE::testing::FEnvSafeTest {
+
+  DECLARE_SPECIAL_CONSTANTS(T)
+
+public:
+  typedef T (*GetPayloadFunc)(const T *);
+
+  T funcWrapper(GetPayloadFunc func, T x) { return func(&x); }
+
+  void testNonNaNs(GetPayloadFunc func) {
+    EXPECT_FP_EQ(T(-1.0), funcWrapper(func, T(0.0)));
+    EXPECT_FP_EQ(T(-1.0), funcWrapper(func, T(-0.0)));
+    EXPECT_FP_EQ(T(-1.0), funcWrapper(func, T(0.1)));
+    EXPECT_FP_EQ(T(-1.0), funcWrapper(func, T(-0.1)));
+    EXPECT_FP_EQ(T(-1.0), funcWrapper(func, T(123.38)));
+    EXPECT_FP_EQ(T(-1.0), funcWrapper(func, T(-123.38)));
+    EXPECT_FP_EQ(T(-1.0), funcWrapper(func, inf));
+    EXPECT_FP_EQ(T(-1.0), funcWrapper(func, neg_inf));
+  }
+
+  void testNaNs(GetPayloadFunc func) {
+    EXPECT_FP_EQ(T(0.0), funcWrapper(func, aNaN));
+    EXPECT_FP_EQ(T(0.0), funcWrapper(func, neg_aNaN));
+
+    T default_snan_payload = StorageType(1) << (FPBits::SIG_LEN - 2);
+    EXPECT_FP_EQ(default_snan_payload, funcWrapper(func, sNaN));
+    EXPECT_FP_EQ(default_snan_payload, funcWrapper(func, neg_sNaN));
+
+    T qnan_42 = FPBits::quiet_nan(Sign::POS, 0x42).get_val();
+    T neg_qnan_42 = FPBits::quiet_nan(Sign::NEG, 0x42).get_val();
+    T snan_42 = FPBits::signaling_nan(Sign::POS, 0x42).get_val();
+    T neg_snan_42 = FPBits::signaling_nan(Sign::NEG, 0x42).get_val();
+    EXPECT_FP_EQ(T(0x42.0p+0), funcWrapper(func, qnan_42));
+    EXPECT_FP_EQ(T(0x42.0p+0), funcWrapper(func, neg_qnan_42));
+    EXPECT_FP_EQ(T(0x42.0p+0), funcWrapper(func, snan_42));
+    EXPECT_FP_EQ(T(0x42.0p+0), funcWrapper(func, neg_snan_42));
+
+    T qnan_123 = FPBits::quiet_nan(Sign::POS, 0x123).get_val();
+    T neg_qnan_123 = FPBits::quiet_nan(Sign::NEG, 0x123).get_val();
+    T snan_123 = FPBits::signaling_nan(Sign::POS, 0x123).get_val();
+    T neg_snan_123 = FPBits::signaling_nan(Sign::NEG, 0x123).get_val();
+    EXPECT_FP_EQ(T(0x123.0p+0), funcWrapper(func, qnan_123));
+    EXPECT_FP_EQ(T(0x123.0p+0), funcWrapper(func, neg_qnan_123));
+    EXPECT_FP_EQ(T(0x123.0p+0), funcWrapper(func, snan_123));
+    EXPECT_FP_EQ(T(0x123.0p+0), funcWrapper(func, neg_snan_123));
+  }
+};
+
+#define LIST_GETPAYLOAD_TESTS(T, func)                                         \
+  using LlvmLibcGetPayloadTest = GetPayloadTestTemplate<T>;                    \
+  TEST_F(LlvmLibcGetPayloadTest, NonNaNs) { testNonNaNs(&func); }              \
+  TEST_F(LlvmLibcGetPayloadTest, NaNs) { testNaNs(&func); }
+
+#endif // LIBC_TEST_SRC_MATH_SMOKE_GETPAYLOADTEST_H
diff --git a/test/src/math/smoke/ILogbTest.h b/test/src/math/smoke/ILogbTest.h
index 05f906b..3315ac2 100644
--- a/test/src/math/smoke/ILogbTest.h
+++ b/test/src/math/smoke/ILogbTest.h
@@ -9,7 +9,7 @@
 #ifndef LLVM_LIBC_TEST_SRC_MATH_ILOGBTEST_H
 #define LLVM_LIBC_TEST_SRC_MATH_ILOGBTEST_H
 
-#include "src/__support/CPP/limits.h" // INT_MAX
+#include "src/__support/CPP/algorithm.h"
 #include "src/__support/FPUtil/FPBits.h"
 #include "src/__support/FPUtil/ManipulationFunctions.h"
 #include "test/UnitTest/FEnvSafeTest.h"
@@ -76,10 +76,12 @@ public:
   void test_subnormal_range(Func func) {
     constexpr StorageType MIN_SUBNORMAL = FPBits::min_subnormal().uintval();
     constexpr StorageType MAX_SUBNORMAL = FPBits::max_subnormal().uintval();
-    constexpr StorageType COUNT = 10'001;
-    constexpr StorageType STEP = (MAX_SUBNORMAL - MIN_SUBNORMAL) / COUNT;
+    constexpr int COUNT = 10'001;
+    constexpr StorageType STEP = LIBC_NAMESPACE::cpp::max(
+        static_cast<StorageType>((MAX_SUBNORMAL - MIN_SUBNORMAL) / COUNT),
+        StorageType(1));
     for (StorageType v = MIN_SUBNORMAL; v <= MAX_SUBNORMAL; v += STEP) {
-      FPBits x_bits = FPBits(v);
+      FPBits x_bits(v);
       if (x_bits.is_zero() || x_bits.is_inf_or_nan())
         continue;
 
@@ -94,10 +96,12 @@ public:
   void test_normal_range(Func func) {
     constexpr StorageType MIN_NORMAL = FPBits::min_normal().uintval();
     constexpr StorageType MAX_NORMAL = FPBits::max_normal().uintval();
-    constexpr StorageType COUNT = 10'001;
-    constexpr StorageType STEP = (MAX_NORMAL - MIN_NORMAL) / COUNT;
+    constexpr int COUNT = 10'001;
+    constexpr StorageType STEP = LIBC_NAMESPACE::cpp::max(
+        static_cast<StorageType>((MAX_NORMAL - MIN_NORMAL) / COUNT),
+        StorageType(1));
     for (StorageType v = MIN_NORMAL; v <= MAX_NORMAL; v += STEP) {
-      FPBits x_bits = FPBits(v);
+      FPBits x_bits(v);
       if (x_bits.is_zero() || x_bits.is_inf_or_nan())
         continue;
 
diff --git a/test/src/math/smoke/LdExpTest.h b/test/src/math/smoke/LdExpTest.h
index 713d305..7739bd7 100644
--- a/test/src/math/smoke/LdExpTest.h
+++ b/test/src/math/smoke/LdExpTest.h
@@ -18,7 +18,7 @@
 
 #include <stdint.h>
 
-template <typename T>
+template <typename T, typename U = int>
 class LdExpTestTemplate : public LIBC_NAMESPACE::testing::FEnvSafeTest {
   using FPBits = LIBC_NAMESPACE::fputil::FPBits<T>;
   using NormalFloat = LIBC_NAMESPACE::fputil::NormalFloat<T>;
@@ -31,13 +31,13 @@ class LdExpTestTemplate : public LIBC_NAMESPACE::testing::FEnvSafeTest {
   const T nan = FPBits::quiet_nan().get_val();
 
   // A normalized mantissa to be used with tests.
-  static constexpr StorageType MANTISSA = NormalFloat::ONE + 0x1234;
+  static constexpr StorageType MANTISSA = NormalFloat::ONE + 0x123;
 
 public:
-  typedef T (*LdExpFunc)(T, int);
+  typedef T (*LdExpFunc)(T, U);
 
   void testSpecialNumbers(LdExpFunc func) {
-    int exp_array[5] = {-INT_MAX - 1, -10, 0, 10, INT_MAX};
+    int exp_array[5] = {INT_MIN, -10, 0, 10, INT_MAX};
     for (int exp : exp_array) {
       ASSERT_FP_EQ(zero, func(zero, exp));
       ASSERT_FP_EQ(neg_zero, func(neg_zero, exp));
@@ -45,6 +45,17 @@ public:
       ASSERT_FP_EQ(neg_inf, func(neg_inf, exp));
       ASSERT_FP_EQ(nan, func(nan, exp));
     }
+
+    if constexpr (sizeof(U) < sizeof(long) || sizeof(long) == sizeof(int))
+      return;
+    long long_exp_array[4] = {LONG_MIN, INT_MIN - 1L, INT_MAX + 1L, LONG_MAX};
+    for (long exp : long_exp_array) {
+      ASSERT_FP_EQ(zero, func(zero, exp));
+      ASSERT_FP_EQ(neg_zero, func(neg_zero, exp));
+      ASSERT_FP_EQ(inf, func(inf, exp));
+      ASSERT_FP_EQ(neg_inf, func(neg_inf, exp));
+      ASSERT_FP_EQ(nan, func(nan, exp));
+    }
   }
 
   void testPowersOfTwo(LdExpFunc func) {
@@ -60,7 +71,7 @@ public:
 
   void testOverflow(LdExpFunc func) {
     NormalFloat x(Sign::POS, FPBits::MAX_BIASED_EXPONENT - 10,
-                  NormalFloat::ONE + 0xF00BA);
+                  NormalFloat::ONE + 0xFB);
     for (int32_t exp = 10; exp < 100; ++exp) {
       ASSERT_FP_EQ(inf, func(T(x), exp));
       ASSERT_FP_EQ(neg_inf, func(-T(x), exp));
@@ -95,10 +106,10 @@ public:
 
   void testNormalOperation(LdExpFunc func) {
     T val_array[] = {// Normal numbers
-                     NormalFloat(Sign::POS, 100, MANTISSA),
-                     NormalFloat(Sign::POS, -100, MANTISSA),
-                     NormalFloat(Sign::NEG, 100, MANTISSA),
-                     NormalFloat(Sign::NEG, -100, MANTISSA),
+                     NormalFloat(Sign::POS, 10, MANTISSA),
+                     NormalFloat(Sign::POS, -10, MANTISSA),
+                     NormalFloat(Sign::NEG, 10, MANTISSA),
+                     NormalFloat(Sign::NEG, -10, MANTISSA),
                      // Subnormal numbers
                      NormalFloat(Sign::POS, -FPBits::EXP_BIAS, MANTISSA),
                      NormalFloat(Sign::NEG, -FPBits::EXP_BIAS, MANTISSA)};
@@ -114,8 +125,8 @@ public:
         NormalFloat two_to_exp = NormalFloat(static_cast<T>(1.L));
         two_to_exp = two_to_exp.mul2(exp);
 
-        ASSERT_FP_EQ(func(x, exp), x * two_to_exp);
-        ASSERT_FP_EQ(func(x, -exp), x / two_to_exp);
+        ASSERT_FP_EQ(func(x, exp), x * static_cast<T>(two_to_exp));
+        ASSERT_FP_EQ(func(x, -exp), x / static_cast<T>(two_to_exp));
       }
     }
 
diff --git a/test/src/math/smoke/LogbTest.h b/test/src/math/smoke/LogbTest.h
index 4938fcf..0bb6e12 100644
--- a/test/src/math/smoke/LogbTest.h
+++ b/test/src/math/smoke/LogbTest.h
@@ -6,6 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "src/__support/CPP/algorithm.h"
 #include "src/__support/FPUtil/ManipulationFunctions.h"
 #include "test/UnitTest/FEnvSafeTest.h"
 #include "test/UnitTest/FPMatcher.h"
@@ -69,10 +70,12 @@ public:
 
   void testRange(LogbFunc func) {
     using StorageType = typename FPBits::StorageType;
-    constexpr StorageType COUNT = 100'000;
-    constexpr StorageType STEP = STORAGE_MAX / COUNT;
-    for (StorageType i = 0, v = 0; i <= COUNT; ++i, v += STEP) {
-      FPBits x_bits = FPBits(v);
+    constexpr int COUNT = 100'000;
+    constexpr StorageType STEP = LIBC_NAMESPACE::cpp::max(
+        static_cast<StorageType>(STORAGE_MAX / COUNT), StorageType(1));
+    StorageType v = 0;
+    for (int i = 0; i <= COUNT; ++i, v += STEP) {
+      FPBits x_bits(v);
       if (x_bits.is_zero() || x_bits.is_inf_or_nan())
         continue;
 
diff --git a/test/src/math/smoke/ModfTest.h b/test/src/math/smoke/ModfTest.h
index 85db2d6..6226e5d 100644
--- a/test/src/math/smoke/ModfTest.h
+++ b/test/src/math/smoke/ModfTest.h
@@ -6,6 +6,7 @@
 //
 //===----------------------------------------------------------------------===//
 
+#include "src/__support/CPP/algorithm.h"
 #include "src/__support/FPUtil/BasicOperations.h"
 #include "src/__support/FPUtil/NearestIntegerOperations.h"
 #include "test/UnitTest/FEnvSafeTest.h"
@@ -83,10 +84,12 @@ public:
   }
 
   void testRange(ModfFunc func) {
-    constexpr StorageType COUNT = 100'000;
-    constexpr StorageType STEP = STORAGE_MAX / COUNT;
-    for (StorageType i = 0, v = 0; i <= COUNT; ++i, v += STEP) {
-      FPBits x_bits = FPBits(v);
+    constexpr int COUNT = 100'000;
+    constexpr StorageType STEP = LIBC_NAMESPACE::cpp::max(
+        static_cast<StorageType>(STORAGE_MAX / COUNT), StorageType(1));
+    StorageType v = 0;
+    for (int i = 0; i <= COUNT; ++i, v += STEP) {
+      FPBits x_bits(v);
       if (x_bits.is_zero() || x_bits.is_inf_or_nan())
         continue;
 
diff --git a/test/src/math/smoke/RemQuoTest.h b/test/src/math/smoke/RemQuoTest.h
index 43eee3d..e926326 100644
--- a/test/src/math/smoke/RemQuoTest.h
+++ b/test/src/math/smoke/RemQuoTest.h
@@ -9,8 +9,6 @@
 #ifndef LLVM_LIBC_TEST_SRC_MATH_REMQUOTEST_H
 #define LLVM_LIBC_TEST_SRC_MATH_REMQUOTEST_H
 
-#include "hdr/math_macros.h"
-#include "src/__support/FPUtil/BasicOperations.h"
 #include "src/__support/FPUtil/FPBits.h"
 #include "test/UnitTest/FEnvSafeTest.h"
 #include "test/UnitTest/FPMatcher.h"
diff --git a/test/src/math/smoke/ScalbnTest.h b/test/src/math/smoke/ScalbnTest.h
index e1d035c..67ea30f 100644
--- a/test/src/math/smoke/ScalbnTest.h
+++ b/test/src/math/smoke/ScalbnTest.h
@@ -12,8 +12,8 @@
 #include "LdExpTest.h"
 #include "test/UnitTest/Test.h"
 
-#define LIST_SCALBN_TESTS(T, func)                                             \
-  using LlvmLibcScalbnTest = LdExpTestTemplate<T>;                             \
+#define LIST_SCALBN_TESTS(T, U, func)                                          \
+  using LlvmLibcScalbnTest = LdExpTestTemplate<T, U>;                          \
   TEST_F(LlvmLibcScalbnTest, SpecialNumbers) { testSpecialNumbers(&func); }    \
   TEST_F(LlvmLibcScalbnTest, PowersOfTwo) { testPowersOfTwo(&func); }          \
   TEST_F(LlvmLibcScalbnTest, OverFlow) { testOverflow(&func); }                \
diff --git a/test/src/math/smoke/SetPayloadSigTest.h b/test/src/math/smoke/SetPayloadSigTest.h
new file mode 100644
index 0000000..7ec3ac0
--- /dev/null
+++ b/test/src/math/smoke/SetPayloadSigTest.h
@@ -0,0 +1,74 @@
+//===-- Utility class to test flavors of setpayloadsig ----------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LIBC_TEST_SRC_MATH_SMOKE_SETPAYLOADSIGTEST_H
+#define LIBC_TEST_SRC_MATH_SMOKE_SETPAYLOADSIGTEST_H
+
+#include "test/UnitTest/FEnvSafeTest.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+
+template <typename T>
+class SetPayloadSigTestTemplate : public LIBC_NAMESPACE::testing::FEnvSafeTest {
+
+  DECLARE_SPECIAL_CONSTANTS(T)
+
+public:
+  typedef int (*SetPayloadSigFunc)(T *, T);
+
+  void testInvalidPayloads(SetPayloadSigFunc func) {
+    T res;
+
+    EXPECT_EQ(1, func(&res, T(aNaN)));
+    EXPECT_EQ(1, func(&res, T(neg_aNaN)));
+    EXPECT_EQ(1, func(&res, T(inf)));
+    EXPECT_EQ(1, func(&res, T(neg_inf)));
+    EXPECT_EQ(1, func(&res, T(0.0)));
+    EXPECT_EQ(1, func(&res, T(-0.0)));
+    EXPECT_EQ(1, func(&res, T(0.1)));
+    EXPECT_EQ(1, func(&res, T(-0.1)));
+    EXPECT_EQ(1, func(&res, T(-1.0)));
+    EXPECT_EQ(1, func(&res, T(0x42.1p+0)));
+    EXPECT_EQ(1, func(&res, T(-0x42.1p+0)));
+    EXPECT_EQ(1, func(&res, T(StorageType(1) << (FPBits::FRACTION_LEN - 1))));
+  }
+
+  void testValidPayloads(SetPayloadSigFunc func) {
+    T res;
+
+    EXPECT_EQ(0, func(&res, T(1.0)));
+    EXPECT_TRUE(FPBits(res).is_signaling_nan());
+    EXPECT_EQ(FPBits::signaling_nan(Sign::POS, 1).uintval(),
+              FPBits(res).uintval());
+
+    EXPECT_EQ(0, func(&res, T(0x42.0p+0)));
+    EXPECT_TRUE(FPBits(res).is_signaling_nan());
+    EXPECT_EQ(FPBits::signaling_nan(Sign::POS, 0x42).uintval(),
+              FPBits(res).uintval());
+
+    EXPECT_EQ(0, func(&res, T(0x123.0p+0)));
+    EXPECT_TRUE(FPBits(res).is_signaling_nan());
+    EXPECT_EQ(FPBits::signaling_nan(Sign::POS, 0x123).uintval(),
+              FPBits(res).uintval());
+
+    EXPECT_EQ(0, func(&res, T(FPBits::FRACTION_MASK >> 1)));
+    EXPECT_TRUE(FPBits(res).is_signaling_nan());
+    EXPECT_EQ(
+        FPBits::signaling_nan(Sign::POS, FPBits::FRACTION_MASK >> 1).uintval(),
+        FPBits(res).uintval());
+  }
+};
+
+#define LIST_SETPAYLOADSIG_TESTS(T, func)                                      \
+  using LlvmLibcSetPayloadSigTest = SetPayloadSigTestTemplate<T>;              \
+  TEST_F(LlvmLibcSetPayloadSigTest, InvalidPayloads) {                         \
+    testInvalidPayloads(&func);                                                \
+  }                                                                            \
+  TEST_F(LlvmLibcSetPayloadSigTest, ValidPayloads) { testValidPayloads(&func); }
+
+#endif // LIBC_TEST_SRC_MATH_SMOKE_SETPAYLOADSIGTEST_H
diff --git a/test/src/math/smoke/SetPayloadTest.h b/test/src/math/smoke/SetPayloadTest.h
new file mode 100644
index 0000000..4b0dacf
--- /dev/null
+++ b/test/src/math/smoke/SetPayloadTest.h
@@ -0,0 +1,75 @@
+//===-- Utility class to test different flavors of setpayload ---*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LIBC_TEST_SRC_MATH_SMOKE_SETPAYLOADTEST_H
+#define LIBC_TEST_SRC_MATH_SMOKE_SETPAYLOADTEST_H
+
+#include "test/UnitTest/FEnvSafeTest.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+
+template <typename T>
+class SetPayloadTestTemplate : public LIBC_NAMESPACE::testing::FEnvSafeTest {
+
+  DECLARE_SPECIAL_CONSTANTS(T)
+
+public:
+  typedef int (*SetPayloadFunc)(T *, T);
+
+  void testInvalidPayloads(SetPayloadFunc func) {
+    T res;
+
+    EXPECT_EQ(1, func(&res, T(aNaN)));
+    EXPECT_EQ(1, func(&res, T(neg_aNaN)));
+    EXPECT_EQ(1, func(&res, T(inf)));
+    EXPECT_EQ(1, func(&res, T(neg_inf)));
+    EXPECT_EQ(1, func(&res, T(0.1)));
+    EXPECT_EQ(1, func(&res, T(-0.1)));
+    EXPECT_EQ(1, func(&res, T(-1.0)));
+    EXPECT_EQ(1, func(&res, T(0x42.1p+0)));
+    EXPECT_EQ(1, func(&res, T(-0x42.1p+0)));
+    EXPECT_EQ(1, func(&res, T(StorageType(1) << (FPBits::FRACTION_LEN - 1))));
+  }
+
+  void testValidPayloads(SetPayloadFunc func) {
+    T res;
+
+    EXPECT_EQ(0, func(&res, T(0.0)));
+    EXPECT_TRUE(FPBits(res).is_quiet_nan());
+    EXPECT_EQ(FPBits(aNaN).uintval(), FPBits(res).uintval());
+
+    EXPECT_EQ(0, func(&res, T(1.0)));
+    EXPECT_TRUE(FPBits(res).is_quiet_nan());
+    EXPECT_EQ(FPBits::quiet_nan(Sign::POS, 1).uintval(), FPBits(res).uintval());
+
+    EXPECT_EQ(0, func(&res, T(0x42.0p+0)));
+    EXPECT_TRUE(FPBits(res).is_quiet_nan());
+    EXPECT_EQ(FPBits::quiet_nan(Sign::POS, 0x42).uintval(),
+              FPBits(res).uintval());
+
+    EXPECT_EQ(0, func(&res, T(0x123.0p+0)));
+    EXPECT_TRUE(FPBits(res).is_quiet_nan());
+    EXPECT_EQ(FPBits::quiet_nan(Sign::POS, 0x123).uintval(),
+              FPBits(res).uintval());
+
+    EXPECT_EQ(0, func(&res, T(FPBits::FRACTION_MASK >> 1)));
+    EXPECT_TRUE(FPBits(res).is_quiet_nan());
+    EXPECT_EQ(
+        FPBits::quiet_nan(Sign::POS, FPBits::FRACTION_MASK >> 1).uintval(),
+        FPBits(res).uintval());
+  }
+};
+
+#define LIST_SETPAYLOAD_TESTS(T, func)                                         \
+  using LlvmLibcSetPayloadTest = SetPayloadTestTemplate<T>;                    \
+  TEST_F(LlvmLibcSetPayloadTest, InvalidPayloads) {                            \
+    testInvalidPayloads(&func);                                                \
+  }                                                                            \
+  TEST_F(LlvmLibcSetPayloadTest, ValidPayloads) { testValidPayloads(&func); }
+
+#endif // LIBC_TEST_SRC_MATH_SMOKE_SETPAYLOADTEST_H
diff --git a/test/src/math/smoke/SqrtTest.h b/test/src/math/smoke/SqrtTest.h
index 8afacaf..ce9f2f8 100644
--- a/test/src/math/smoke/SqrtTest.h
+++ b/test/src/math/smoke/SqrtTest.h
@@ -6,37 +6,35 @@
 //
 //===----------------------------------------------------------------------===//
 
-#include "src/__support/CPP/bit.h"
 #include "test/UnitTest/FEnvSafeTest.h"
 #include "test/UnitTest/FPMatcher.h"
 #include "test/UnitTest/Test.h"
 
-#include "hdr/math_macros.h"
-
-template <typename T>
+template <typename OutType, typename InType>
 class SqrtTest : public LIBC_NAMESPACE::testing::FEnvSafeTest {
 
-  DECLARE_SPECIAL_CONSTANTS(T)
-
-  static constexpr StorageType HIDDEN_BIT =
-      StorageType(1) << LIBC_NAMESPACE::fputil::FPBits<T>::FRACTION_LEN;
+  DECLARE_SPECIAL_CONSTANTS(OutType)
 
 public:
-  typedef T (*SqrtFunc)(T);
+  typedef OutType (*SqrtFunc)(InType);
 
   void test_special_numbers(SqrtFunc func) {
     ASSERT_FP_EQ(aNaN, func(aNaN));
     ASSERT_FP_EQ(inf, func(inf));
     ASSERT_FP_EQ(aNaN, func(neg_inf));
-    ASSERT_FP_EQ(0.0, func(0.0));
-    ASSERT_FP_EQ(-0.0, func(-0.0));
-    ASSERT_FP_EQ(aNaN, func(T(-1.0)));
-    ASSERT_FP_EQ(T(1.0), func(T(1.0)));
-    ASSERT_FP_EQ(T(2.0), func(T(4.0)));
-    ASSERT_FP_EQ(T(3.0), func(T(9.0)));
+    ASSERT_FP_EQ(zero, func(zero));
+    ASSERT_FP_EQ(neg_zero, func(neg_zero));
+    ASSERT_FP_EQ(aNaN, func(InType(-1.0)));
+    ASSERT_FP_EQ(OutType(1.0), func(InType(1.0)));
+    ASSERT_FP_EQ(OutType(2.0), func(InType(4.0)));
+    ASSERT_FP_EQ(OutType(3.0), func(InType(9.0)));
   }
 };
 
 #define LIST_SQRT_TESTS(T, func)                                               \
-  using LlvmLibcSqrtTest = SqrtTest<T>;                                        \
+  using LlvmLibcSqrtTest = SqrtTest<T, T>;                                     \
+  TEST_F(LlvmLibcSqrtTest, SpecialNumbers) { test_special_numbers(&func); }
+
+#define LIST_NARROWING_SQRT_TESTS(OutType, InType, func)                       \
+  using LlvmLibcSqrtTest = SqrtTest<OutType, InType>;                          \
   TEST_F(LlvmLibcSqrtTest, SpecialNumbers) { test_special_numbers(&func); }
diff --git a/test/src/math/smoke/TotalOrderMagTest.h b/test/src/math/smoke/TotalOrderMagTest.h
new file mode 100644
index 0000000..5fe2983
--- /dev/null
+++ b/test/src/math/smoke/TotalOrderMagTest.h
@@ -0,0 +1,142 @@
+//===-- Utility class to test flavors of totalordermag ----------*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LIBC_TEST_SRC_MATH_SMOKE_TOTALORDERMAGTEST_H
+#define LIBC_TEST_SRC_MATH_SMOKE_TOTALORDERMAGTEST_H
+
+#include "test/UnitTest/FEnvSafeTest.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+
+template <typename T>
+class TotalOrderMagTestTemplate : public LIBC_NAMESPACE::testing::FEnvSafeTest {
+
+  DECLARE_SPECIAL_CONSTANTS(T)
+
+public:
+  typedef int (*TotalOrderMagFunc)(const T *, const T *);
+
+  bool funcWrapper(TotalOrderMagFunc func, T x, T y) {
+    return func(&x, &y) != 0;
+  }
+
+  void testXLesserThanY(TotalOrderMagFunc func) {
+    EXPECT_TRUE(funcWrapper(func, neg_inf, inf));
+
+    EXPECT_TRUE(funcWrapper(func, T(0.0), T(0.1)));
+    EXPECT_TRUE(funcWrapper(func, T(0.0), T(123.38)));
+
+    EXPECT_FALSE(funcWrapper(func, T(-0.1), T(0.0)));
+    EXPECT_FALSE(funcWrapper(func, T(-123.38), T(0.0)));
+
+    EXPECT_TRUE(funcWrapper(func, T(-0.1), T(0.1)));
+    EXPECT_TRUE(funcWrapper(func, T(-123.38), T(123.38)));
+  }
+
+  void testXGreaterThanY(TotalOrderMagFunc func) {
+    EXPECT_TRUE(funcWrapper(func, inf, neg_inf));
+
+    EXPECT_TRUE(funcWrapper(func, T(0.0), T(-0.1)));
+    EXPECT_TRUE(funcWrapper(func, T(0.0), T(-123.38)));
+
+    EXPECT_FALSE(funcWrapper(func, T(0.1), T(0.0)));
+    EXPECT_FALSE(funcWrapper(func, T(123.38), T(0.0)));
+
+    EXPECT_TRUE(funcWrapper(func, T(0.1), T(-0.1)));
+    EXPECT_TRUE(funcWrapper(func, T(123.38), T(-123.38)));
+  }
+
+  void testXEqualToY(TotalOrderMagFunc func) {
+    EXPECT_TRUE(funcWrapper(func, inf, inf));
+    EXPECT_TRUE(funcWrapper(func, neg_inf, neg_inf));
+
+    EXPECT_TRUE(funcWrapper(func, T(-0.0), T(0.0)));
+    EXPECT_TRUE(funcWrapper(func, T(0.0), T(-0.0)));
+
+    EXPECT_TRUE(funcWrapper(func, T(0.0), T(0.0)));
+    EXPECT_TRUE(funcWrapper(func, T(-0.0), T(-0.0)));
+    EXPECT_TRUE(funcWrapper(func, T(0.1), T(0.1)));
+    EXPECT_TRUE(funcWrapper(func, T(-0.1), T(-0.1)));
+    EXPECT_TRUE(funcWrapper(func, T(123.38), T(123.38)));
+    EXPECT_TRUE(funcWrapper(func, T(-123.38), T(-123.38)));
+  }
+
+  void testSingleNaN(TotalOrderMagFunc func) {
+    EXPECT_FALSE(funcWrapper(func, neg_aNaN, T(0.0)));
+    EXPECT_FALSE(funcWrapper(func, neg_aNaN, T(0.1)));
+    EXPECT_FALSE(funcWrapper(func, neg_aNaN, T(123.38)));
+
+    EXPECT_TRUE(funcWrapper(func, T(0.0), neg_aNaN));
+    EXPECT_TRUE(funcWrapper(func, T(0.1), neg_aNaN));
+    EXPECT_TRUE(funcWrapper(func, T(123.38), neg_aNaN));
+
+    EXPECT_TRUE(funcWrapper(func, T(0.0), aNaN));
+    EXPECT_TRUE(funcWrapper(func, T(0.1), aNaN));
+    EXPECT_TRUE(funcWrapper(func, T(123.38), aNaN));
+
+    EXPECT_FALSE(funcWrapper(func, aNaN, T(0.0)));
+    EXPECT_FALSE(funcWrapper(func, aNaN, T(0.1)));
+    EXPECT_FALSE(funcWrapper(func, aNaN, T(123.38)));
+  }
+
+  void testNaNSigns(TotalOrderMagFunc func) {
+    EXPECT_TRUE(funcWrapper(func, neg_aNaN, aNaN));
+    EXPECT_FALSE(funcWrapper(func, neg_aNaN, sNaN));
+    EXPECT_TRUE(funcWrapper(func, neg_sNaN, aNaN));
+    EXPECT_TRUE(funcWrapper(func, neg_sNaN, sNaN));
+
+    EXPECT_TRUE(funcWrapper(func, aNaN, neg_aNaN));
+    EXPECT_FALSE(funcWrapper(func, aNaN, neg_sNaN));
+    EXPECT_TRUE(funcWrapper(func, sNaN, neg_aNaN));
+    EXPECT_TRUE(funcWrapper(func, sNaN, neg_sNaN));
+  }
+
+  void testQuietVsSignalingNaN(TotalOrderMagFunc func) {
+    EXPECT_FALSE(funcWrapper(func, neg_aNaN, neg_sNaN));
+    EXPECT_TRUE(funcWrapper(func, neg_sNaN, neg_aNaN));
+    EXPECT_TRUE(funcWrapper(func, sNaN, aNaN));
+    EXPECT_FALSE(funcWrapper(func, aNaN, sNaN));
+  }
+
+  void testNaNPayloads(TotalOrderMagFunc func) {
+    T qnan_123 = FPBits::quiet_nan(Sign::POS, 0x123).get_val();
+    T neg_qnan_123 = FPBits::quiet_nan(Sign::NEG, 0x123).get_val();
+    T snan_123 = FPBits::signaling_nan(Sign::POS, 0x123).get_val();
+    T neg_snan_123 = FPBits::signaling_nan(Sign::NEG, 0x123).get_val();
+
+    EXPECT_TRUE(funcWrapper(func, aNaN, aNaN));
+    EXPECT_TRUE(funcWrapper(func, sNaN, sNaN));
+    EXPECT_TRUE(funcWrapper(func, aNaN, qnan_123));
+    EXPECT_TRUE(funcWrapper(func, sNaN, snan_123));
+    EXPECT_FALSE(funcWrapper(func, qnan_123, aNaN));
+    EXPECT_FALSE(funcWrapper(func, snan_123, sNaN));
+
+    EXPECT_TRUE(funcWrapper(func, neg_aNaN, neg_aNaN));
+    EXPECT_TRUE(funcWrapper(func, neg_sNaN, neg_sNaN));
+    EXPECT_TRUE(funcWrapper(func, neg_aNaN, neg_qnan_123));
+    EXPECT_TRUE(funcWrapper(func, neg_sNaN, neg_snan_123));
+    EXPECT_FALSE(funcWrapper(func, neg_qnan_123, neg_aNaN));
+    EXPECT_FALSE(funcWrapper(func, neg_snan_123, neg_sNaN));
+  }
+};
+
+#define LIST_TOTALORDERMAG_TESTS(T, func)                                      \
+  using LlvmLibcTotalOrderMagTest = TotalOrderMagTestTemplate<T>;              \
+  TEST_F(LlvmLibcTotalOrderMagTest, XLesserThanY) { testXLesserThanY(&func); } \
+  TEST_F(LlvmLibcTotalOrderMagTest, XGreaterThanY) {                           \
+    testXGreaterThanY(&func);                                                  \
+  }                                                                            \
+  TEST_F(LlvmLibcTotalOrderMagTest, XEqualToY) { testXEqualToY(&func); }       \
+  TEST_F(LlvmLibcTotalOrderMagTest, SingleNaN) { testSingleNaN(&func); }       \
+  TEST_F(LlvmLibcTotalOrderMagTest, NaNSigns) { testNaNSigns(&func); }         \
+  TEST_F(LlvmLibcTotalOrderMagTest, QuietVsSignalingNaN) {                     \
+    testQuietVsSignalingNaN(&func);                                            \
+  }                                                                            \
+  TEST_F(LlvmLibcTotalOrderMagTest, NaNPayloads) { testNaNPayloads(&func); }
+
+#endif // LIBC_TEST_SRC_MATH_SMOKE_TOTALORDERMAGTEST_H
diff --git a/test/src/math/smoke/TotalOrderTest.h b/test/src/math/smoke/TotalOrderTest.h
new file mode 100644
index 0000000..281b2a5
--- /dev/null
+++ b/test/src/math/smoke/TotalOrderTest.h
@@ -0,0 +1,138 @@
+//===-- Utility class to test different flavors of totalorder ---*- C++ -*-===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#ifndef LIBC_TEST_SRC_MATH_SMOKE_TOTALORDERTEST_H
+#define LIBC_TEST_SRC_MATH_SMOKE_TOTALORDERTEST_H
+
+#include "test/UnitTest/FEnvSafeTest.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+
+template <typename T>
+class TotalOrderTestTemplate : public LIBC_NAMESPACE::testing::FEnvSafeTest {
+
+  DECLARE_SPECIAL_CONSTANTS(T)
+
+public:
+  typedef int (*TotalOrderFunc)(const T *, const T *);
+
+  bool funcWrapper(TotalOrderFunc func, T x, T y) { return func(&x, &y) != 0; }
+
+  void testXLesserThanY(TotalOrderFunc func) {
+    EXPECT_TRUE(funcWrapper(func, neg_inf, inf));
+
+    EXPECT_TRUE(funcWrapper(func, T(0.0), T(0.1)));
+    EXPECT_TRUE(funcWrapper(func, T(0.0), T(123.38)));
+
+    EXPECT_TRUE(funcWrapper(func, T(-0.1), T(0.0)));
+    EXPECT_TRUE(funcWrapper(func, T(-123.38), T(0.0)));
+
+    EXPECT_TRUE(funcWrapper(func, T(-0.1), T(0.1)));
+    EXPECT_TRUE(funcWrapper(func, T(-123.38), T(123.38)));
+  }
+
+  void testXGreaterThanY(TotalOrderFunc func) {
+    EXPECT_FALSE(funcWrapper(func, inf, neg_inf));
+
+    EXPECT_FALSE(funcWrapper(func, T(0.0), T(-0.1)));
+    EXPECT_FALSE(funcWrapper(func, T(0.0), T(-123.38)));
+
+    EXPECT_FALSE(funcWrapper(func, T(0.1), T(0.0)));
+    EXPECT_FALSE(funcWrapper(func, T(123.38), T(0.0)));
+
+    EXPECT_FALSE(funcWrapper(func, T(0.1), T(-0.1)));
+    EXPECT_FALSE(funcWrapper(func, T(123.38), T(-123.38)));
+  }
+
+  void testXEqualToY(TotalOrderFunc func) {
+    EXPECT_TRUE(funcWrapper(func, inf, inf));
+    EXPECT_TRUE(funcWrapper(func, neg_inf, neg_inf));
+
+    EXPECT_TRUE(funcWrapper(func, T(-0.0), T(0.0)));
+    EXPECT_FALSE(funcWrapper(func, T(0.0), T(-0.0)));
+
+    EXPECT_TRUE(funcWrapper(func, T(0.0), T(0.0)));
+    EXPECT_TRUE(funcWrapper(func, T(-0.0), T(-0.0)));
+    EXPECT_TRUE(funcWrapper(func, T(0.1), T(0.1)));
+    EXPECT_TRUE(funcWrapper(func, T(-0.1), T(-0.1)));
+    EXPECT_TRUE(funcWrapper(func, T(123.38), T(123.38)));
+    EXPECT_TRUE(funcWrapper(func, T(-123.38), T(-123.38)));
+  }
+
+  void testSingleNaN(TotalOrderFunc func) {
+    EXPECT_TRUE(funcWrapper(func, neg_aNaN, T(0.0)));
+    EXPECT_TRUE(funcWrapper(func, neg_aNaN, T(0.1)));
+    EXPECT_TRUE(funcWrapper(func, neg_aNaN, T(123.38)));
+
+    EXPECT_FALSE(funcWrapper(func, T(0.0), neg_aNaN));
+    EXPECT_FALSE(funcWrapper(func, T(0.1), neg_aNaN));
+    EXPECT_FALSE(funcWrapper(func, T(123.38), neg_aNaN));
+
+    EXPECT_TRUE(funcWrapper(func, T(0.0), aNaN));
+    EXPECT_TRUE(funcWrapper(func, T(0.1), aNaN));
+    EXPECT_TRUE(funcWrapper(func, T(123.38), aNaN));
+
+    EXPECT_FALSE(funcWrapper(func, aNaN, T(0.0)));
+    EXPECT_FALSE(funcWrapper(func, aNaN, T(0.1)));
+    EXPECT_FALSE(funcWrapper(func, aNaN, T(123.38)));
+  }
+
+  void testNaNSigns(TotalOrderFunc func) {
+    EXPECT_TRUE(funcWrapper(func, neg_aNaN, aNaN));
+    EXPECT_TRUE(funcWrapper(func, neg_aNaN, sNaN));
+    EXPECT_TRUE(funcWrapper(func, neg_sNaN, aNaN));
+    EXPECT_TRUE(funcWrapper(func, neg_sNaN, sNaN));
+
+    EXPECT_FALSE(funcWrapper(func, aNaN, neg_aNaN));
+    EXPECT_FALSE(funcWrapper(func, aNaN, neg_sNaN));
+    EXPECT_FALSE(funcWrapper(func, sNaN, neg_aNaN));
+    EXPECT_FALSE(funcWrapper(func, sNaN, neg_sNaN));
+  }
+
+  void testQuietVsSignalingNaN(TotalOrderFunc func) {
+    EXPECT_TRUE(funcWrapper(func, neg_aNaN, neg_sNaN));
+    EXPECT_FALSE(funcWrapper(func, neg_sNaN, neg_aNaN));
+    EXPECT_TRUE(funcWrapper(func, sNaN, aNaN));
+    EXPECT_FALSE(funcWrapper(func, aNaN, sNaN));
+  }
+
+  void testNaNPayloads(TotalOrderFunc func) {
+    T qnan_123 = FPBits::quiet_nan(Sign::POS, 0x123).get_val();
+    T neg_qnan_123 = FPBits::quiet_nan(Sign::NEG, 0x123).get_val();
+    T snan_123 = FPBits::signaling_nan(Sign::POS, 0x123).get_val();
+    T neg_snan_123 = FPBits::signaling_nan(Sign::NEG, 0x123).get_val();
+
+    EXPECT_TRUE(funcWrapper(func, aNaN, aNaN));
+    EXPECT_TRUE(funcWrapper(func, sNaN, sNaN));
+    EXPECT_TRUE(funcWrapper(func, aNaN, qnan_123));
+    EXPECT_TRUE(funcWrapper(func, sNaN, snan_123));
+    EXPECT_FALSE(funcWrapper(func, qnan_123, aNaN));
+    EXPECT_FALSE(funcWrapper(func, snan_123, sNaN));
+
+    EXPECT_TRUE(funcWrapper(func, neg_aNaN, neg_aNaN));
+    EXPECT_TRUE(funcWrapper(func, neg_sNaN, neg_sNaN));
+    EXPECT_FALSE(funcWrapper(func, neg_aNaN, neg_qnan_123));
+    EXPECT_FALSE(funcWrapper(func, neg_sNaN, neg_snan_123));
+    EXPECT_TRUE(funcWrapper(func, neg_qnan_123, neg_aNaN));
+    EXPECT_TRUE(funcWrapper(func, neg_snan_123, neg_sNaN));
+  }
+};
+
+#define LIST_TOTALORDER_TESTS(T, func)                                         \
+  using LlvmLibcTotalOrderTest = TotalOrderTestTemplate<T>;                    \
+  TEST_F(LlvmLibcTotalOrderTest, XLesserThanY) { testXLesserThanY(&func); }    \
+  TEST_F(LlvmLibcTotalOrderTest, XGreaterThanY) { testXGreaterThanY(&func); }  \
+  TEST_F(LlvmLibcTotalOrderTest, XEqualToY) { testXEqualToY(&func); }          \
+  TEST_F(LlvmLibcTotalOrderTest, SingleNaN) { testSingleNaN(&func); }          \
+  TEST_F(LlvmLibcTotalOrderTest, NaNSigns) { testNaNSigns(&func); }            \
+  TEST_F(LlvmLibcTotalOrderTest, QuietVsSignalingNaN) {                        \
+    testQuietVsSignalingNaN(&func);                                            \
+  }                                                                            \
+  TEST_F(LlvmLibcTotalOrderTest, NaNPayloads) { testNaNPayloads(&func); }
+
+#endif // LIBC_TEST_SRC_MATH_SMOKE_TOTALORDERTEST_H
diff --git a/test/src/math/smoke/f16fmaf_test.cpp b/test/src/math/smoke/f16fmaf_test.cpp
new file mode 100644
index 0000000..5e3aec7
--- /dev/null
+++ b/test/src/math/smoke/f16fmaf_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for f16fmaf ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "FmaTest.h"
+
+#include "src/math/f16fmaf.h"
+
+LIST_NARROWING_FMA_TESTS(float16, float, LIBC_NAMESPACE::f16fmaf)
diff --git a/test/src/math/smoke/f16sqrtf_test.cpp b/test/src/math/smoke/f16sqrtf_test.cpp
new file mode 100644
index 0000000..36231ae
--- /dev/null
+++ b/test/src/math/smoke/f16sqrtf_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for f16sqrtf --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "SqrtTest.h"
+
+#include "src/math/f16sqrtf.h"
+
+LIST_NARROWING_SQRT_TESTS(float16, float, LIBC_NAMESPACE::f16sqrtf)
diff --git a/test/src/math/smoke/fma_test.cpp b/test/src/math/smoke/fma_test.cpp
index 4460b80..c5d802a 100644
--- a/test/src/math/smoke/fma_test.cpp
+++ b/test/src/math/smoke/fma_test.cpp
@@ -10,8 +10,4 @@
 
 #include "src/math/fma.h"
 
-using LlvmLibcFmaTest = FmaTestTemplate<double>;
-
-TEST_F(LlvmLibcFmaTest, SpecialNumbers) {
-  test_special_numbers(&LIBC_NAMESPACE::fma);
-}
+LIST_FMA_TESTS(double, LIBC_NAMESPACE::fma)
diff --git a/test/src/math/smoke/fmaf_test.cpp b/test/src/math/smoke/fmaf_test.cpp
index a645efb..09e9c50 100644
--- a/test/src/math/smoke/fmaf_test.cpp
+++ b/test/src/math/smoke/fmaf_test.cpp
@@ -10,8 +10,4 @@
 
 #include "src/math/fmaf.h"
 
-using LlvmLibcFmafTest = FmaTestTemplate<float>;
-
-TEST_F(LlvmLibcFmafTest, SpecialNumbers) {
-  test_special_numbers(&LIBC_NAMESPACE::fmaf);
-}
+LIST_FMA_TESTS(float, LIBC_NAMESPACE::fmaf)
diff --git a/test/src/math/smoke/fmul_test.cpp b/test/src/math/smoke/fmul_test.cpp
new file mode 100644
index 0000000..0eb664f
--- /dev/null
+++ b/test/src/math/smoke/fmul_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for fmul-------------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===---------------------------------------------------------------------===//
+
+#include "FMulTest.h"
+
+#include "src/math/fmul.h"
+
+LIST_FMUL_TESTS(float, double, LIBC_NAMESPACE::fmul)
diff --git a/test/src/math/smoke/frexpf16_test.cpp b/test/src/math/smoke/frexpf16_test.cpp
new file mode 100644
index 0000000..4d5492c
--- /dev/null
+++ b/test/src/math/smoke/frexpf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for frexpf16 --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "FrexpTest.h"
+
+#include "src/math/frexpf16.h"
+
+LIST_FREXP_TESTS(float16, LIBC_NAMESPACE::frexpf16);
diff --git a/test/src/math/smoke/getpayloadf16_test.cpp b/test/src/math/smoke/getpayloadf16_test.cpp
new file mode 100644
index 0000000..385b047
--- /dev/null
+++ b/test/src/math/smoke/getpayloadf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for getpayloadf16 ---------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "GetPayloadTest.h"
+
+#include "src/math/getpayloadf16.h"
+
+LIST_GETPAYLOAD_TESTS(float16, LIBC_NAMESPACE::getpayloadf16)
diff --git a/test/src/math/smoke/ilogbf16_test.cpp b/test/src/math/smoke/ilogbf16_test.cpp
new file mode 100644
index 0000000..e046709
--- /dev/null
+++ b/test/src/math/smoke/ilogbf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for ilogbf16 --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "ILogbTest.h"
+
+#include "src/math/ilogbf16.h"
+
+LIST_INTLOGB_TESTS(int, float16, LIBC_NAMESPACE::ilogbf16);
diff --git a/test/src/math/smoke/ldexpf16_test.cpp b/test/src/math/smoke/ldexpf16_test.cpp
new file mode 100644
index 0000000..ecf8f76
--- /dev/null
+++ b/test/src/math/smoke/ldexpf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for ldexpf16 --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "LdExpTest.h"
+
+#include "src/math/ldexpf16.h"
+
+LIST_LDEXP_TESTS(float16, LIBC_NAMESPACE::ldexpf16);
diff --git a/test/src/math/smoke/llogbf16_test.cpp b/test/src/math/smoke/llogbf16_test.cpp
new file mode 100644
index 0000000..8907681
--- /dev/null
+++ b/test/src/math/smoke/llogbf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for llogbf16 --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "ILogbTest.h"
+
+#include "src/math/llogbf16.h"
+
+LIST_INTLOGB_TESTS(long, float16, LIBC_NAMESPACE::llogbf16);
diff --git a/test/src/math/smoke/logbf16_test.cpp b/test/src/math/smoke/logbf16_test.cpp
new file mode 100644
index 0000000..cfc1a05
--- /dev/null
+++ b/test/src/math/smoke/logbf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for logbf16 ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "LogbTest.h"
+
+#include "src/math/logbf16.h"
+
+LIST_LOGB_TESTS(float16, LIBC_NAMESPACE::logbf16)
diff --git a/test/src/math/smoke/modff16_test.cpp b/test/src/math/smoke/modff16_test.cpp
new file mode 100644
index 0000000..7093377
--- /dev/null
+++ b/test/src/math/smoke/modff16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for modff16 ---------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "ModfTest.h"
+
+#include "src/math/modff16.h"
+
+LIST_MODF_TESTS(float16, LIBC_NAMESPACE::modff16)
diff --git a/test/src/math/smoke/nanf16_test.cpp b/test/src/math/smoke/nanf16_test.cpp
new file mode 100644
index 0000000..ec17a73
--- /dev/null
+++ b/test/src/math/smoke/nanf16_test.cpp
@@ -0,0 +1,51 @@
+//===-- Unittests for nanf16 ----------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/__support/FPUtil/FPBits.h"
+#include "src/__support/macros/sanitizer.h"
+#include "src/math/nanf16.h"
+#include "test/UnitTest/FEnvSafeTest.h"
+#include "test/UnitTest/FPMatcher.h"
+#include "test/UnitTest/Test.h"
+
+#include <signal.h>
+
+class LlvmLibcNanf16Test : public LIBC_NAMESPACE::testing::FEnvSafeTest {
+public:
+  using StorageType = LIBC_NAMESPACE::fputil::FPBits<float16>::StorageType;
+
+  void run_test(const char *input_str, StorageType bits) {
+    float16 result = LIBC_NAMESPACE::nanf16(input_str);
+    auto actual_fp = LIBC_NAMESPACE::fputil::FPBits<float16>(result);
+    auto expected_fp = LIBC_NAMESPACE::fputil::FPBits<float16>(bits);
+    EXPECT_EQ(actual_fp.uintval(), expected_fp.uintval());
+  };
+};
+
+TEST_F(LlvmLibcNanf16Test, NCharSeq) {
+  run_test("", 0x7e00);
+  run_test("123", 0x7e7b);
+  run_test("0x123", 0x7f23);
+  run_test("1a", 0x7e00);
+  run_test("1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM_",
+           0x7e00);
+  run_test("10000000000000000000000000000000000000000000000000", 0x7e00);
+}
+
+TEST_F(LlvmLibcNanf16Test, RandomString) {
+  run_test(" 1234", 0x7e00);
+  run_test("-1234", 0x7e00);
+  run_test("asd&f", 0x7e00);
+  run_test("123 ", 0x7e00);
+}
+
+#ifndef LIBC_HAVE_ADDRESS_SANITIZER
+TEST_F(LlvmLibcNanf16Test, InvalidInput) {
+  EXPECT_DEATH([] { LIBC_NAMESPACE::nanf16(nullptr); }, WITH_SIGNAL(SIGSEGV));
+}
+#endif // LIBC_HAVE_ADDRESS_SANITIZER
diff --git a/test/src/math/smoke/remquof128_test.cpp b/test/src/math/smoke/remquof128_test.cpp
new file mode 100644
index 0000000..8ef6c3b
--- /dev/null
+++ b/test/src/math/smoke/remquof128_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for remquof128 ------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "RemQuoTest.h"
+
+#include "src/math/remquof128.h"
+
+LIST_REMQUO_TESTS(float128, LIBC_NAMESPACE::remquof128)
diff --git a/test/src/math/smoke/remquof16_test.cpp b/test/src/math/smoke/remquof16_test.cpp
new file mode 100644
index 0000000..18f2aba
--- /dev/null
+++ b/test/src/math/smoke/remquof16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for remquof16 -------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "RemQuoTest.h"
+
+#include "src/math/remquof16.h"
+
+LIST_REMQUO_TESTS(float16, LIBC_NAMESPACE::remquof16)
diff --git a/test/src/math/smoke/scalblnf16_test.cpp b/test/src/math/smoke/scalblnf16_test.cpp
new file mode 100644
index 0000000..a678254
--- /dev/null
+++ b/test/src/math/smoke/scalblnf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for scalblnf16 ------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "ScalbnTest.h"
+
+#include "src/math/scalblnf16.h"
+
+LIST_SCALBN_TESTS(float16, long, LIBC_NAMESPACE::scalblnf16)
diff --git a/test/src/math/smoke/scalbn_test.cpp b/test/src/math/smoke/scalbn_test.cpp
index 413a239..86ad71b 100644
--- a/test/src/math/smoke/scalbn_test.cpp
+++ b/test/src/math/smoke/scalbn_test.cpp
@@ -10,4 +10,4 @@
 
 #include "src/math/scalbn.h"
 
-LIST_SCALBN_TESTS(double, LIBC_NAMESPACE::scalbn)
+LIST_SCALBN_TESTS(double, int, LIBC_NAMESPACE::scalbn)
diff --git a/test/src/math/smoke/scalbnf128_test.cpp b/test/src/math/smoke/scalbnf128_test.cpp
index dc259de..b42902a 100644
--- a/test/src/math/smoke/scalbnf128_test.cpp
+++ b/test/src/math/smoke/scalbnf128_test.cpp
@@ -10,4 +10,4 @@
 
 #include "src/math/scalbnf128.h"
 
-LIST_SCALBN_TESTS(float128, LIBC_NAMESPACE::scalbnf128)
+LIST_SCALBN_TESTS(float128, int, LIBC_NAMESPACE::scalbnf128)
diff --git a/test/src/math/smoke/scalbnf16_test.cpp b/test/src/math/smoke/scalbnf16_test.cpp
new file mode 100644
index 0000000..9cee0d0
--- /dev/null
+++ b/test/src/math/smoke/scalbnf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for scalbnf16 -------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "ScalbnTest.h"
+
+#include "src/math/scalbnf16.h"
+
+LIST_SCALBN_TESTS(float16, int, LIBC_NAMESPACE::scalbnf16)
diff --git a/test/src/math/smoke/scalbnf_test.cpp b/test/src/math/smoke/scalbnf_test.cpp
index e97781c..b25db4e 100644
--- a/test/src/math/smoke/scalbnf_test.cpp
+++ b/test/src/math/smoke/scalbnf_test.cpp
@@ -10,4 +10,4 @@
 
 #include "src/math/scalbnf.h"
 
-LIST_SCALBN_TESTS(float, LIBC_NAMESPACE::scalbnf)
+LIST_SCALBN_TESTS(float, int, LIBC_NAMESPACE::scalbnf)
diff --git a/test/src/math/smoke/scalbnl_test.cpp b/test/src/math/smoke/scalbnl_test.cpp
index b0e0053..838b065 100644
--- a/test/src/math/smoke/scalbnl_test.cpp
+++ b/test/src/math/smoke/scalbnl_test.cpp
@@ -10,4 +10,4 @@
 
 #include "src/math/scalbnl.h"
 
-LIST_SCALBN_TESTS(long double, LIBC_NAMESPACE::scalbnl)
+LIST_SCALBN_TESTS(long double, int, LIBC_NAMESPACE::scalbnl)
diff --git a/test/src/math/smoke/setpayloadf16_test.cpp b/test/src/math/smoke/setpayloadf16_test.cpp
new file mode 100644
index 0000000..ccf5370
--- /dev/null
+++ b/test/src/math/smoke/setpayloadf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for setpayloadf16 ---------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "SetPayloadTest.h"
+
+#include "src/math/setpayloadf16.h"
+
+LIST_SETPAYLOAD_TESTS(float16, LIBC_NAMESPACE::setpayloadf16)
diff --git a/test/src/math/smoke/setpayloadsigf16_test.cpp b/test/src/math/smoke/setpayloadsigf16_test.cpp
new file mode 100644
index 0000000..9f786e6
--- /dev/null
+++ b/test/src/math/smoke/setpayloadsigf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for setpayloadsigf16 ------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "SetPayloadSigTest.h"
+
+#include "src/math/setpayloadsigf16.h"
+
+LIST_SETPAYLOADSIG_TESTS(float16, LIBC_NAMESPACE::setpayloadsigf16)
diff --git a/test/src/math/smoke/totalorderf16_test.cpp b/test/src/math/smoke/totalorderf16_test.cpp
new file mode 100644
index 0000000..410c70c
--- /dev/null
+++ b/test/src/math/smoke/totalorderf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for totalorderf16 ---------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "TotalOrderTest.h"
+
+#include "src/math/totalorderf16.h"
+
+LIST_TOTALORDER_TESTS(float16, LIBC_NAMESPACE::totalorderf16)
diff --git a/test/src/math/smoke/totalordermagf16_test.cpp b/test/src/math/smoke/totalordermagf16_test.cpp
new file mode 100644
index 0000000..b09eb11
--- /dev/null
+++ b/test/src/math/smoke/totalordermagf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for totalordermagf16 ------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "TotalOrderMagTest.h"
+
+#include "src/math/totalordermagf16.h"
+
+LIST_TOTALORDERMAG_TESTS(float16, LIBC_NAMESPACE::totalordermagf16)
diff --git a/test/src/math/truncf16_test.cpp b/test/src/math/truncf16_test.cpp
new file mode 100644
index 0000000..832d88e
--- /dev/null
+++ b/test/src/math/truncf16_test.cpp
@@ -0,0 +1,13 @@
+//===-- Unittests for truncf16 --------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "TruncTest.h"
+
+#include "src/math/truncf16.h"
+
+LIST_TRUNC_TESTS(float16, LIBC_NAMESPACE::truncf16)
diff --git a/test/src/sched/param_and_scheduler_test.cpp b/test/src/sched/param_and_scheduler_test.cpp
index 8e81f2e..747c7e3 100644
--- a/test/src/sched/param_and_scheduler_test.cpp
+++ b/test/src/sched/param_and_scheduler_test.cpp
@@ -36,7 +36,7 @@
 
 class SchedTest : public LIBC_NAMESPACE::testing::Test {
 public:
-  void testSched(int policy, bool can_set) {
+  void testSched(int policy, bool is_mandatory) {
     LIBC_NAMESPACE::libc_errno = 0;
 
     int init_policy = LIBC_NAMESPACE::sched_getscheduler(0);
@@ -74,24 +74,26 @@ public:
 
     param.sched_priority = max_priority + 1;
     ASSERT_EQ(LIBC_NAMESPACE::sched_setscheduler(0, policy, &param), -1);
-    // A bit hard to test as depending if we are root or not we can run into
+    // A bit hard to test as depending on user privileges we can run into
     // different issues.
     ASSERT_TRUE(LIBC_NAMESPACE::libc_errno == EINVAL ||
                 LIBC_NAMESPACE::libc_errno == EPERM);
     LIBC_NAMESPACE::libc_errno = 0;
 
-    // Some sched policies require permissions, so skip
     param.sched_priority = min_priority;
-    // Success / missing permissions.
-    ASSERT_EQ(LIBC_NAMESPACE::sched_setscheduler(0, policy, &param),
-              can_set ? 0 : -1);
-    ASSERT_TRUE(can_set ? (LIBC_NAMESPACE::libc_errno == 0)
-                        : (LIBC_NAMESPACE::libc_errno == EINVAL ||
-                           LIBC_NAMESPACE::libc_errno == EPERM));
+    // Success/unsupported policy/missing permissions.
+    int setscheduler_result =
+        LIBC_NAMESPACE::sched_setscheduler(0, policy, &param);
+    ASSERT_TRUE(setscheduler_result == 0 || setscheduler_result == -1);
+    ASSERT_TRUE(
+        setscheduler_result != -1
+            ? (LIBC_NAMESPACE::libc_errno == 0)
+            : ((!is_mandatory && LIBC_NAMESPACE::libc_errno == EINVAL) ||
+               LIBC_NAMESPACE::libc_errno == EPERM));
     LIBC_NAMESPACE::libc_errno = 0;
 
     ASSERT_EQ(LIBC_NAMESPACE::sched_getscheduler(0),
-              can_set ? policy : init_policy);
+              setscheduler_result != -1 ? policy : init_policy);
     ASSERT_ERRNO_SUCCESS();
 
     // Out of bounds priority
@@ -121,17 +123,21 @@ public:
       ASSERT_ERRNO_EQ(EINVAL);
       LIBC_NAMESPACE::libc_errno = 0;
 
-      // Success / missing permissions
-      ASSERT_EQ(LIBC_NAMESPACE::sched_setparam(0, &param), can_set ? 0 : -1);
-      ASSERT_TRUE(can_set ? (LIBC_NAMESPACE::libc_errno == 0)
-                          : (LIBC_NAMESPACE::libc_errno == EINVAL ||
-                             LIBC_NAMESPACE::libc_errno == EPERM));
+      // Success/unsupported policy/missing permissions
+      int setparam_result = LIBC_NAMESPACE::sched_setparam(0, &param);
+      ASSERT_TRUE(setparam_result == 0 || setparam_result == -1);
+      ASSERT_TRUE(setparam_result != -1
+                      ? (LIBC_NAMESPACE::libc_errno == 0)
+                      : ((setscheduler_result == -1 &&
+                          LIBC_NAMESPACE::libc_errno == EINVAL) ||
+                         LIBC_NAMESPACE::libc_errno == EPERM));
       LIBC_NAMESPACE::libc_errno = 0;
 
       ASSERT_EQ(LIBC_NAMESPACE::sched_getparam(0, &param), 0);
       ASSERT_ERRNO_SUCCESS();
 
-      ASSERT_EQ(param.sched_priority, can_set ? priority : init_priority);
+      ASSERT_EQ(param.sched_priority,
+                setparam_result != -1 ? priority : init_priority);
     }
 
     // Null test
@@ -145,12 +151,12 @@ public:
   using LlvmLibcSchedTest = SchedTest;                                         \
   TEST_F(LlvmLibcSchedTest, Sched_##policy) { testSched(policy, can_set); }
 
-// Root is required to set these policies.
-LIST_SCHED_TESTS(SCHED_FIFO, LIBC_NAMESPACE::getuid() == 0)
-LIST_SCHED_TESTS(SCHED_RR, LIBC_NAMESPACE::getuid() == 0)
-
-// No root is required to set these policies.
+// Mandated by POSIX.
 LIST_SCHED_TESTS(SCHED_OTHER, true)
+LIST_SCHED_TESTS(SCHED_FIFO, true)
+LIST_SCHED_TESTS(SCHED_RR, true)
+
+// Linux extensions.
 LIST_SCHED_TESTS(SCHED_BATCH, true)
 LIST_SCHED_TESTS(SCHED_IDLE, true)
 
diff --git a/test/src/stdfix/ISqrtTest.h b/test/src/stdfix/ISqrtTest.h
index ddf292f..692488b 100644
--- a/test/src/stdfix/ISqrtTest.h
+++ b/test/src/stdfix/ISqrtTest.h
@@ -55,7 +55,7 @@ public:
       x_d += 1.0;
       ++x;
       OutType result = func(x);
-      double expected = LIBC_NAMESPACE::fputil::sqrt(x_d);
+      double expected = LIBC_NAMESPACE::fputil::sqrt<double>(x_d);
       testSpecificInput(x, result, expected, ERR);
     }
   }
diff --git a/test/src/stdfix/SqrtTest.h b/test/src/stdfix/SqrtTest.h
index 47ec129..2a8a825 100644
--- a/test/src/stdfix/SqrtTest.h
+++ b/test/src/stdfix/SqrtTest.h
@@ -49,7 +49,8 @@ public:
       T v = LIBC_NAMESPACE::cpp::bit_cast<T>(x);
       double v_d = static_cast<double>(v);
       double errors = LIBC_NAMESPACE::fputil::abs(
-          static_cast<double>(func(v)) - LIBC_NAMESPACE::fputil::sqrt(v_d));
+          static_cast<double>(func(v)) -
+          LIBC_NAMESPACE::fputil::sqrt<double>(v_d));
       if (errors > ERR) {
         // Print out the failure input and output.
         EXPECT_EQ(v, zero);
diff --git a/test/src/stdio/fdopen_test.cpp b/test/src/stdio/fdopen_test.cpp
new file mode 100644
index 0000000..ef36cff
--- /dev/null
+++ b/test/src/stdio/fdopen_test.cpp
@@ -0,0 +1,89 @@
+//===-- Unittest for fdopen -----------------------------------------------===//
+//
+// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
+// See https://llvm.org/LICENSE.txt for license information.
+// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
+//
+//===----------------------------------------------------------------------===//
+
+#include "src/stdio/fdopen.h"
+
+#include "hdr/fcntl_macros.h"
+#include "src/errno/libc_errno.h"
+#include "src/fcntl/open.h"
+#include "src/stdio/fclose.h"
+#include "src/stdio/fgets.h"
+#include "src/stdio/fputs.h"
+#include "src/unistd/close.h"
+#include "test/UnitTest/ErrnoSetterMatcher.h"
+#include "test/UnitTest/Test.h"
+
+#include <sys/stat.h> // For S_IRWXU
+
+TEST(LlvmLibcStdioFdopenTest, WriteAppendRead) {
+  using LIBC_NAMESPACE::testing::ErrnoSetterMatcher::Succeeds;
+  LIBC_NAMESPACE::libc_errno = 0;
+  constexpr const char *TEST_FILE_NAME = "testdata/write_read_append.test";
+  auto TEST_FILE = libc_make_test_file_path(TEST_FILE_NAME);
+  int fd = LIBC_NAMESPACE::open(TEST_FILE, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU);
+  auto *fp = LIBC_NAMESPACE::fdopen(fd, "w");
+  ASSERT_ERRNO_SUCCESS();
+  ASSERT_TRUE(nullptr != fp);
+  constexpr const char HELLO[] = "Hello";
+  LIBC_NAMESPACE::fputs(HELLO, fp);
+  LIBC_NAMESPACE::fclose(fp);
+  ASSERT_ERRNO_SUCCESS();
+
+  constexpr const char LLVM[] = "LLVM";
+  int fd2 = LIBC_NAMESPACE::open(TEST_FILE, O_CREAT | O_RDWR);
+  auto *fp2 = LIBC_NAMESPACE::fdopen(fd2, "a");
+  ASSERT_ERRNO_SUCCESS();
+  ASSERT_TRUE(nullptr != fp2);
+  LIBC_NAMESPACE::fputs(LLVM, fp2);
+  LIBC_NAMESPACE::fclose(fp2);
+  ASSERT_ERRNO_SUCCESS();
+
+  int fd3 = LIBC_NAMESPACE::open(TEST_FILE, O_CREAT | O_RDWR);
+  auto *fp3 = LIBC_NAMESPACE::fdopen(fd3, "r");
+  char buffer[10];
+  LIBC_NAMESPACE::fgets(buffer, sizeof(buffer), fp3);
+  ASSERT_STREQ("HelloLLVM", buffer);
+  LIBC_NAMESPACE::fclose(fp3);
+  ASSERT_ERRNO_SUCCESS();
+}
+
+TEST(LlvmLibcStdioFdopenTest, InvalidFd) {
+  LIBC_NAMESPACE::libc_errno = 0;
+  constexpr const char *TEST_FILE_NAME = "testdata/invalid_fd.test";
+  auto TEST_FILE = libc_make_test_file_path(TEST_FILE_NAME);
+  int fd = LIBC_NAMESPACE::open(TEST_FILE, O_CREAT | O_TRUNC);
+  LIBC_NAMESPACE::close(fd);
+  // With `fd` already closed, `fdopen` should fail and set the `errno` to EBADF
+  auto *fp = LIBC_NAMESPACE::fdopen(fd, "r");
+  ASSERT_ERRNO_EQ(EBADF);
+  ASSERT_TRUE(nullptr == fp);
+}
+
+TEST(LlvmLibcStdioFdopenTest, InvalidMode) {
+  LIBC_NAMESPACE::libc_errno = 0;
+  constexpr const char *TEST_FILE_NAME = "testdata/invalid_mode.test";
+  auto TEST_FILE = libc_make_test_file_path(TEST_FILE_NAME);
+  int fd = LIBC_NAMESPACE::open(TEST_FILE, O_CREAT | O_RDONLY, S_IRWXU);
+  ASSERT_ERRNO_SUCCESS();
+  ASSERT_GT(fd, 0);
+
+  // `Mode` must be one of "r", "w" or "a"
+  auto *fp = LIBC_NAMESPACE::fdopen(fd, "m+");
+  ASSERT_ERRNO_EQ(EINVAL);
+  ASSERT_TRUE(nullptr == fp);
+
+  // If the mode argument is invalid, then `fdopen` returns a nullptr and sets
+  // the `errno` to EINVAL. In this case the `mode` param can only be "r" or
+  // "r+"
+  auto *fp2 = LIBC_NAMESPACE::fdopen(fd, "w");
+  ASSERT_ERRNO_EQ(EINVAL);
+  ASSERT_TRUE(nullptr == fp2);
+  LIBC_NAMESPACE::libc_errno = 0;
+  LIBC_NAMESPACE::close(fd);
+  ASSERT_ERRNO_SUCCESS();
+}
```

