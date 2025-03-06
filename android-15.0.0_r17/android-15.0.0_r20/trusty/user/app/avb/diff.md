```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..90ce1db
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_trusty_user_app_avb",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/test/rules.mk b/test/rules.mk
index aa2e382..4895704 100644
--- a/test/rules.mk
+++ b/test/rules.mk
@@ -33,4 +33,8 @@ HOST_FLAGS := -Wpointer-arith -fno-permissive \
 HOST_LIBS := \
 	stdc++ \
 
+HOST_DEPS := \
+	trusty/user/base/host/unittest \
+
+
 include make/host_test.mk
```

