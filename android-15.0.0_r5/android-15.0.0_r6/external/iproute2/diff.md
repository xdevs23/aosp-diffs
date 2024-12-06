```diff
diff --git a/include/json_print.h b/include/json_print.h
index dc4d2bb3..8706f745 100644
--- a/include/json_print.h
+++ b/include/json_print.h
@@ -59,11 +59,24 @@ _PRINT_FUNC(int, int);
 _PRINT_FUNC(bool, bool);
 _PRINT_FUNC(null, const char*);
 _PRINT_FUNC(string, const char*);
-_PRINT_FUNC(uint, uint64_t);
+// ANDROID: upstream used 'uint' we rename the true function to 'uint32', see below
+#define print_color_uint32 print_color_uint
+_PRINT_FUNC(uint32, unsigned int);
 _PRINT_FUNC(hu, unsigned short);
 _PRINT_FUNC(hex, unsigned int);
 _PRINT_FUNC(0xhex, unsigned int);
 _PRINT_FUNC(lluint, unsigned long long int);
 #undef _PRINT_FUNC
 
+// ANDROID: The upstream version of iproute2 has a bug where print_uint() gets
+// called with "%u" fmt string and u64 value, which fails to generate the
+// correct behaviour on 32-bit userspace.  Detect this and autocorrect.
+#define print_uint(t,key,fmt,val) do {       \
+  if (sizeof(val) <= sizeof(unsigned int)) { \
+    print_uint32((t),(key),(fmt),(val));     \
+  } else {                                   \
+    print_lluint((t),(key),(fmt),(val));     \
+  };                                         \
+} while (0)
+
 #endif /* _JSON_PRINT_H_ */
diff --git a/lib/json_print.c b/lib/json_print.c
index aa527af6..f189a4e6 100644
--- a/lib/json_print.c
+++ b/lib/json_print.c
@@ -118,7 +118,7 @@ void close_json_array(enum output_type type, const char *str)
 	}
 _PRINT_FUNC(int, int);
 _PRINT_FUNC(hu, unsigned short);
-_PRINT_FUNC(uint, uint64_t);
+_PRINT_FUNC(uint, unsigned int);
 _PRINT_FUNC(lluint, unsigned long long int);
 #undef _PRINT_FUNC
 
```

