```diff
diff --git a/android_keymaster/android_keymaster.cpp b/android_keymaster/android_keymaster.cpp
index 0e98a0f..e5ea6ac 100644
--- a/android_keymaster/android_keymaster.cpp
+++ b/android_keymaster/android_keymaster.cpp
@@ -68,7 +68,7 @@ keymaster_error_t CheckPatchLevel(const AuthorizationSet& tee_enforced,
         if (key_patchlevel < current_patchlevel) {
             return KM_ERROR_KEY_REQUIRES_UPGRADE;
         } else if (key_patchlevel > current_patchlevel) {
-            LOG_E("Key blob invalid! key patchlevel %lu is > current patchlevel %lu",
+            LOG_E("Key blob invalid! key patchlevel %lux is > current patchlevel %lux",
                   (unsigned long)key_patchlevel, (unsigned long)current_patchlevel);
             return KM_ERROR_INVALID_KEY_BLOB;
         }
```

