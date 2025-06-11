```diff
diff --git a/Android.bp b/Android.bp
index 73197435..07967665 100644
--- a/Android.bp
+++ b/Android.bp
@@ -55,11 +55,10 @@ cc_defaults {
         "-Wno-overloaded-virtual",
         "-Wno-implicit-fallthrough",
         "-Wno-macro-redefined",
-        "-Wno-enum-constexpr-conversion",
     ],
 
     target: {
-        linux_glibc: {
+        host_linux: {
             cppflags: [
                 // Soong is always adding -DANDROID even for the host
                 "-UANDROID",
@@ -110,7 +109,6 @@ cc_library_shared {
 
     cflags: [
         "-DWITHOUT_SYSTEMD",
-        "-Wno-enum-constexpr-conversion",
     ],
 
     rtti: true,
diff --git a/OWNERS b/OWNERS
index 27877470..027a2421 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 ftsarev@google.com
 hrayan@google.com
 hugojacob@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/third_party/boost/Android.bp b/third_party/boost/Android.bp
index 8c19e01b..e43dfdaf 100644
--- a/third_party/boost/Android.bp
+++ b/third_party/boost/Android.bp
@@ -33,7 +33,6 @@ cc_defaults {
     "-Wall",
     "-Werror",
     "-fexceptions",
-    "-Wno-enum-constexpr-conversion",
   ],
   host_supported: true,
   rtti: true,
@@ -43,6 +42,11 @@ cc_defaults {
         "-msse4.1",
       ],
     },
+    musl:  {
+      cflags: [
+        "-msse4.1",
+      ],
+    },
   },
   vendor_available: true,
   visibility: [
diff --git a/third_party/boost/boost-1_76_0.json b/third_party/boost/boost-1_76_0.json
index 079bf151..044cc72a 100644
--- a/third_party/boost/boost-1_76_0.json
+++ b/third_party/boost/boost-1_76_0.json
@@ -16,7 +16,6 @@
         "-Wall",
         "-Werror",
         "-fexceptions",
-        "-Wno-enum-constexpr-conversion"
       ],
       "visibility": ["//external/sdv/vsomeip"]
     },
diff --git a/third_party/boost/mpl/include/boost/mpl/aux_/integral_wrapper.hpp b/third_party/boost/mpl/include/boost/mpl/aux_/integral_wrapper.hpp
index 8748fbb9..5f24b794 100644
--- a/third_party/boost/mpl/include/boost/mpl/aux_/integral_wrapper.hpp
+++ b/third_party/boost/mpl/include/boost/mpl/aux_/integral_wrapper.hpp
@@ -56,7 +56,8 @@ struct AUX_WRAPPER_NAME
 // have to #ifdef here: some compilers don't like the 'N + 1' form (MSVC),
 // while some other don't like 'value + 1' (Borland), and some don't like
 // either
-#if BOOST_WORKAROUND(__EDG_VERSION__, <= 243)
+#if BOOST_WORKAROUND(__EDG_VERSION__, <= 243) \
+    || __cplusplus >= 201103L
  private:
     BOOST_STATIC_CONSTANT(AUX_WRAPPER_VALUE_TYPE, next_value = BOOST_MPL_AUX_STATIC_CAST(AUX_WRAPPER_VALUE_TYPE, (N + 1)));
     BOOST_STATIC_CONSTANT(AUX_WRAPPER_VALUE_TYPE, prior_value = BOOST_MPL_AUX_STATIC_CAST(AUX_WRAPPER_VALUE_TYPE, (N - 1)));
```

