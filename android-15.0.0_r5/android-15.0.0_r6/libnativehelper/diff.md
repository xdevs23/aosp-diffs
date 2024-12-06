```diff
diff --git a/header_only_include/nativehelper/scoped_primitive_array.h b/header_only_include/nativehelper/scoped_primitive_array.h
index 16acb70..069de00 100644
--- a/header_only_include/nativehelper/scoped_primitive_array.h
+++ b/header_only_include/nativehelper/scoped_primitive_array.h
@@ -143,6 +143,64 @@ INSTANTIATE_SCOPED_PRIMITIVE_ARRAY_RW(jlong, Long);
 INSTANTIATE_SCOPED_PRIMITIVE_ARRAY_RW(jshort, Short);
 
 #undef INSTANTIATE_SCOPED_PRIMITIVE_ARRAY_RW
+
+template<typename PrimitiveType, typename ArrayType, jint ReleaseMode>
+class ScopedCriticalArray {
+    public:
+        explicit ScopedCriticalArray(JNIEnv* env)
+        : mEnv(env), mJavaArray(nullptr), mRawArray(nullptr) {}
+        ScopedCriticalArray(JNIEnv* env, ArrayType javaArray)
+        : mEnv(env), mJavaArray(javaArray), mRawArray(nullptr) {
+            if (mJavaArray == nullptr) {
+                jniThrowNullPointerException(mEnv);
+            } else {
+                mRawArray = static_cast<PrimitiveType*>(
+                    mEnv->GetPrimitiveArrayCritical(mJavaArray, nullptr));
+            }
+        }
+        ~ScopedCriticalArray() {
+            if (mRawArray) {
+                mEnv->ReleasePrimitiveArrayCritical(mJavaArray, mRawArray, ReleaseMode);
+            }
+        }
+        void reset(ArrayType javaArray) const {
+            mJavaArray = javaArray;
+            mRawArray = static_cast<PrimitiveType*>(
+                    mEnv->GetPrimitiveArrayCritical(mJavaArray, nullptr));
+        }
+        const PrimitiveType* get() const { return mRawArray; }
+        ArrayType getJavaArray() const { return mJavaArray; }
+        const PrimitiveType& operator[](size_t n) const { return mRawArray[n]; }
+        PrimitiveType* get() { return mRawArray; }
+        PrimitiveType& operator[](size_t n) { return mRawArray[n]; }
+        size_t size() const { return mEnv->GetArrayLength(mJavaArray); }
+    private:
+        JNIEnv* const mEnv;
+        mutable ArrayType mJavaArray;
+        mutable PrimitiveType* mRawArray;
+        DISALLOW_COPY_AND_ASSIGN(ScopedCriticalArray);
+};
+
+// Scoped<PrimitiveType>CriticalArray(RO/RW) provide convenient critical
+// access to Java arrays from JNI code. Usage of these should be careful, as
+// the JVM imposes significant restrictions for critical array access.
+// See https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/functions.html#GetPrimitiveArrayCritical
+// for more details about the JVM restrictions.
+#define INSTANTIATE_SCOPED_PRIMITIVE_CRITICAL_ARRAY(PRIMITIVE_TYPE, NAME) \
+    using Scoped ## NAME ## CriticalArrayRO = \
+        const ScopedCriticalArray<PRIMITIVE_TYPE, PRIMITIVE_TYPE ## Array, JNI_ABORT>; \
+    using Scoped ## NAME ## CriticalArrayRW = \
+        ScopedCriticalArray<PRIMITIVE_TYPE, PRIMITIVE_TYPE ## Array, 0>
+
+INSTANTIATE_SCOPED_PRIMITIVE_CRITICAL_ARRAY(jboolean, Boolean);
+INSTANTIATE_SCOPED_PRIMITIVE_CRITICAL_ARRAY(jbyte, Byte);
+INSTANTIATE_SCOPED_PRIMITIVE_CRITICAL_ARRAY(jchar, Char);
+INSTANTIATE_SCOPED_PRIMITIVE_CRITICAL_ARRAY(jdouble, Double);
+INSTANTIATE_SCOPED_PRIMITIVE_CRITICAL_ARRAY(jfloat, Float);
+INSTANTIATE_SCOPED_PRIMITIVE_CRITICAL_ARRAY(jint, Int);
+INSTANTIATE_SCOPED_PRIMITIVE_CRITICAL_ARRAY(jlong, Long);
+INSTANTIATE_SCOPED_PRIMITIVE_CRITICAL_ARRAY(jshort, Short);
+
+#undef INSTANTIATE_SCOPED_PRIMITIVE_CRITICAL_ARRAY
 #undef POINTER_TYPE
 #undef REFERENCE_TYPE
-
diff --git a/tests/scoped_primitive_array_test.cpp b/tests/scoped_primitive_array_test.cpp
index 6916d45..46c44a2 100644
--- a/tests/scoped_primitive_array_test.cpp
+++ b/tests/scoped_primitive_array_test.cpp
@@ -32,3 +32,18 @@ void TestCompilationRW(JNIEnv* env, jintArray array) {
     sba.size();
     sba[3] = 3;
 }
+
+void TestCompilationCriticalRO(JNIEnv* env, jfloatArray array) {
+    ScopedFloatCriticalArrayRO sfa(env, array);
+    sfa.reset(nullptr);
+    sfa.get();
+    sfa.size();
+}
+
+void TestCompilationCriticalRW(JNIEnv* env, jdoubleArray array) {
+    ScopedDoubleCriticalArrayRW sda(env, array);
+    sda.reset(nullptr);
+    sda.get();
+    sda.size();
+    sda[3] = 3.0;
+}
```

