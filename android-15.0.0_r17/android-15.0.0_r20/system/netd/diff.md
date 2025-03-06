```diff
diff --git a/server/Android.bp b/server/Android.bp
index f40b4c6f..e77554b0 100644
--- a/server/Android.bp
+++ b/server/Android.bp
@@ -146,13 +146,18 @@ cc_defaults {
     ],
 }
 
+vintf_fragment {
+    name: "android.system.net.netd-service.xml",
+    src: "android.system.net.netd-service.xml",
+}
+
 cc_binary {
     name: "netd",
     defaults: [
         "netd_default_sources",
     ],
     init_rc: ["netd.rc"],
-    vintf_fragments: ["android.system.net.netd-service.xml"],
+    vintf_fragment_modules: ["android.system.net.netd-service.xml"],
     required: [
         "mainline_tethering_platform_components",
     ],
diff --git a/server/XfrmController.cpp b/server/XfrmController.cpp
index e8b83da3..d2cb5674 100644
--- a/server/XfrmController.cpp
+++ b/server/XfrmController.cpp
@@ -1183,9 +1183,11 @@ netdutils::Status XfrmController::deleteSecurityAssociation(const XfrmCommonInfo
 netdutils::Status XfrmController::migrate(const XfrmMigrateInfo& record, const XfrmSocket& sock) {
     xfrm_userpolicy_id xfrm_policyid{};
     nlattr_xfrm_user_migrate xfrm_migrate{};
+    nlattr_xfrm_interface_id xfrm_if_id{};
 
     __kernel_size_t lenPolicyId = fillUserPolicyId(record, &xfrm_policyid);
     __kernel_size_t lenXfrmMigrate = fillNlAttrXfrmMigrate(record, &xfrm_migrate);
+    __kernel_size_t lenXfrmIfId = fillNlAttrXfrmIntfId(record.xfrm_if_id, &xfrm_if_id);
 
     std::vector<iovec> iov = {
             {nullptr, 0},  // reserved for the eventual addition of a NLMSG_HDR
@@ -1193,6 +1195,8 @@ netdutils::Status XfrmController::migrate(const XfrmMigrateInfo& record, const X
             {kPadBytes, NLMSG_ALIGN(lenPolicyId) - lenPolicyId},
             {&xfrm_migrate, lenXfrmMigrate},
             {kPadBytes, NLMSG_ALIGN(lenXfrmMigrate) - lenXfrmMigrate},
+            {&xfrm_if_id, lenXfrmIfId},
+            {kPadBytes, NLMSG_ALIGN(lenXfrmIfId) - lenXfrmIfId},
     };
 
     return sock.sendMessage(XFRM_MSG_MIGRATE, NETLINK_REQUEST_FLAGS, 0, &iov);
diff --git a/tests/binder_test.cpp b/tests/binder_test.cpp
index 359a28f4..ad04ed30 100644
--- a/tests/binder_test.cpp
+++ b/tests/binder_test.cpp
@@ -164,7 +164,6 @@ static const int TEST_UID6 = 99994;
 constexpr int BASE_UID = AID_USER_OFFSET * 5;
 
 static const std::string NO_SOCKET_ALLOW_RULE("! owner UID match 0-4294967294");
-static const std::string ESP_ALLOW_RULE("esp");
 
 static const in6_addr V6_ADDR = {
         {// 2001:db8:cafe::8888
diff --git a/tests/kernel_test.cpp b/tests/kernel_test.cpp
index c518f579..ce7d3cc6 100644
--- a/tests/kernel_test.cpp
+++ b/tests/kernel_test.cpp
@@ -82,8 +82,8 @@ TEST(KernelTest, TestRequireBpfUnprivDefaultOn) {
 }
 
 TEST(KernelTest, TestBpfJitAlwaysOn) {
-    // 32-bit arm & x86 kernels aren't capable of JIT-ing all of our BPF code,
-    if (bpf::isKernel32Bit()) GTEST_SKIP() << "Exempt on 32-bit kernel.";
+    if (bpf::isKernel32Bit() && !bpf::isAtLeastKernelVersion(5, 16, 0))
+        GTEST_SKIP() << "Exempt on obsolete 32-bit kernels.";
     KernelConfigVerifier configVerifier;
     ASSERT_TRUE(configVerifier.hasOption("CONFIG_BPF_JIT_ALWAYS_ON"));
 }
@@ -112,11 +112,22 @@ TEST(KernelTest, TestX86Kernel64Bit) {
     ASSERT_TRUE(bpf::isKernel64Bit());
 }
 
+// Android W requires 64-bit userspace on new 6.7+ kernels.
+TEST(KernelTest, TestUser64Bit) {
+    if (!bpf::isAtLeastKernelVersion(6, 7, 0)) GTEST_SKIP() << "Exempt on < 6.7 kernel.";
+    ASSERT_TRUE(bpf::isUserspace64bit());
+}
+
 // Android V requires 4.19+
 TEST(KernelTest, TestKernel419) {
     ASSERT_TRUE(bpf::isAtLeastKernelVersion(4, 19, 0));
 }
 
+// Android W requires 5.4+
+TEST(KernelTest, TestKernel54) {
+    ASSERT_TRUE(bpf::isAtLeastKernelVersion(5, 4, 0));
+}
+
 // RiscV is not yet supported: make it fail VTS.
 TEST(KernelTest, TestNotRiscV) {
     ASSERT_TRUE(!bpf::isRiscV());
@@ -147,6 +158,7 @@ TEST(KernelTest, TestMinRequiredLTS_5_10) { ifIsKernelThenMinLTS(5, 10, 199); }
 TEST(KernelTest, TestMinRequiredLTS_5_15) { ifIsKernelThenMinLTS(5, 15, 136); }
 TEST(KernelTest, TestMinRequiredLTS_6_1)  { ifIsKernelThenMinLTS(6, 1, 57); }
 TEST(KernelTest, TestMinRequiredLTS_6_6)  { ifIsKernelThenMinLTS(6, 6, 0); }
+TEST(KernelTest, TestMinRequiredLTS_6_12) { ifIsKernelThenMinLTS(6, 12, 0); }
 
 TEST(KernelTest, TestSupportsAcceptRaMinLft) {
     if (isGSI()) GTEST_SKIP() << "Meaningless on GSI due to ancient kernels.";
```

