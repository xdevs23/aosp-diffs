```diff
diff --git a/ion.c b/ion.c
index cce583a..5ae34ad 100644
--- a/ion.c
+++ b/ion.c
@@ -39,7 +39,7 @@
 
 enum ion_version { ION_VERSION_UNKNOWN, ION_VERSION_MODERN, ION_VERSION_LEGACY };
 
-static atomic_int g_ion_version = ATOMIC_VAR_INIT(ION_VERSION_UNKNOWN);
+static atomic_int g_ion_version = ION_VERSION_UNKNOWN;
 
 int ion_is_legacy(int fd) {
     int version = atomic_load_explicit(&g_ion_version, memory_order_acquire);
```

