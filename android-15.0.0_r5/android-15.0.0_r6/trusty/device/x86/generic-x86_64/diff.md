```diff
diff --git a/project/generic-x86_64-inc.mk b/project/generic-x86_64-inc.mk
index 2c49972..342c8f1 100644
--- a/project/generic-x86_64-inc.mk
+++ b/project/generic-x86_64-inc.mk
@@ -37,6 +37,9 @@ WITH_HKDF_RPMB_KEY ?= true
 # Always allow provisioning for emulator builds
 STATIC_SYSTEM_STATE_FLAG_PROVISIONING_ALLOWED := 1
 
+# Enable Secure Storage AIDL interface
+STORAGE_AIDL_ENABLED ?= true
+
 MODULES += \
 	trusty/kernel/lib/trusty \
 	trusty/kernel/services/apploader \
@@ -55,6 +58,7 @@ TRUSTY_BUILTIN_USER_TASKS := \
 	trusty/user/app/sample/hwaes \
 	trusty/user/app/sample/hwbcc \
 	trusty/user/app/sample/hwcrypto \
+	trusty/user/app/sample/hwcryptohal/server/app \
 	trusty/user/app/storage \
 	trusty/user/base/app/apploader \
 	trusty/user/base/app/system_state_server_static \
diff --git a/project/generic-x86_64-test-inc.mk b/project/generic-x86_64-test-inc.mk
index f4e16cc..aa675f4 100644
--- a/project/generic-x86_64-test-inc.mk
+++ b/project/generic-x86_64-test-inc.mk
@@ -16,7 +16,14 @@
 RELEASE_BUILD ?= false
 
 include project/generic-x86_64-inc.mk
+include frameworks/native/libs/binder/trusty/usertests-inc.mk
 include trusty/kernel/kerneltests-inc.mk
 include trusty/user/base/usertests-inc.mk
+include trusty/user/base/usertests-rust-inc.mk
+
+WITH_HWCRYPTO_UNITTEST := 1
+
+# Enable hwcrypto unittest keyslots and tests
+GLOBAL_USER_COMPILEFLAGS += -DWITH_HWCRYPTO_UNITTEST=$(WITH_HWCRYPTO_UNITTEST)
 
 TEST_BUILD := true
```

