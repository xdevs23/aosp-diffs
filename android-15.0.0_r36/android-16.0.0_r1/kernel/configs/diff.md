```diff
diff --git a/approved-ogki-builds.xml b/approved-ogki-builds.xml
index 489abf9..355ac54 100644
--- a/approved-ogki-builds.xml
+++ b/approved-ogki-builds.xml
@@ -13,14 +13,30 @@
         <build id="8fb7ad74cb59ca7345d355b6764226c4048ed02a1ea9189bad8e9f842b101484" bug="365490960"/>
         <build id="b1f92dda6b2c38dbea909badc91b3b28a054de94a024486964bd72f79c808c8b" bug="370105559"/>
         <build id="cfc835874474a547c5524234a8b0439745865e6237ab281096e0577d8a586c54" bug="371109120"/>
-        <build id="af3fac58e89b2d3be32c5243522b110265f663ae8bc87e4a5c033dca0a5173a4" bug="372781358"/>
-        <build id="6212eb07e3860fbc4ddb1777fdd0081720214530a7d75b04b4d6124cbc9b8eea" bug="373007513"/>
-        <build id="d87030fc2e522fd63ba51f41bd4b879a253c483ec0abce72e302a575c4616f60" bug="376306115"/>
-        <build id="e59599c75c0cd65b6f458dfa354508f4e1df2ab22c7b619700d830682dd43130" bug="376176551"/>
         <build id="497913ccdd8944275a72755194824fad0ff2f0f70e0d378163629e92cdb98799" bug="376408424"/>
-        <build id="d249c895f5879ff4cd56a996ae3c62e3db1627e48a733319098aebf079eba095" bug="380176718"/>
-        <build id="af142b33121b3916221430aa51fc79178c9556d42a3a07cad39e6bf6a16a54e3" bug="382189309"/>
-        <build id="d82fb33e858ff924ab3decb299363c10033e039ebfda60b7518e172b062ef763" bug="381189904"/>
-        <build id="3e83431b33e9e4d78c078c05dbb94a3c3d6274cdd37062f560b378c32247bc61" bug="379765216"/>
+        <build id="6f202764b32aa05443d1446cab43db339a84032d855452c8e299bf2fd9a91dbb" bug="383952401"/>
+        <build id="e8f8530224a4538b224e8fa79ba3e8b310d3a146351525b01764b9e6ca0784ce" bug="383966654"/>
+        <build id="aaa803748a256a26a6625e38e2bdade308317ff945e639fe59dda34c3b4a01fc" bug="383048167"/>
+        <build id="fa6ebabd8d222c7b7bc10ce7d9c3451de31bebbb06e8773d69cf98dded871afb" bug="381816532"/>
+        <build id="83bee47272b816d762a0eb0dfb3cc75852e4cd36e7373db3c3d197227942104a" bug="384384714"/>
+        <build id="66599cb5e6fe8ce2cd84b8adcb9e42fedde2553ee91d67aaab167867c6aa8f8b" bug="383916444"/>
+        <build id="94ce909cbb118fc3987c3bf68dd0785f7c5e756ee94018d0396b3dc30629c1e7" bug="382172291"/>
+        <build id="970aea6f1e6e236010d0f62bc30b48b8d0fee95768440d289d025565427028a4" bug="385301342"/>
+        <build id="e6f97bde41e0cad9cb3bb0a55446ad0cbea6ae4ec7224a681cbe445b9f6832d9" bug="386722337"/>
+        <build id="983d176fff5d168ba40ea6a80fe0a891214884815c2c7a326fd26f8eb8a0d6a0" bug="386715781"/>
+        <build id="98213330a1f620c53b0ff0d90ae2725fbf03168741dea3719d5ac580e6ac85fa" bug="388572729"/>
+        <build id="d594fa50bc5f94d9f89f28b8d7ac9bb2dd4ea34eb4cd860ed1899a691afd1005" bug="388618489"/>
+        <build id="f8e9d05c5e75f994454ca342c9865d60c70bab2e786bd01eb7c0b1a63c11abd7" bug="387229724"/>
+        <build id="c5357202cee01df49a4bf0cb5d3911d1923d7f3c9a10013da225a91c79176507" bug="391459863"/>
+        <build id="c6accecc14d403870fe978e50749ea81173227dfdeea7fc7cab1b62b0fa0902e" bug="395793266"/>
+        <build id="98d4d1391fb98fcdc68ef8d84d1d2ffe0958178f8f3d98cbf71003e12e322666" bug="396061988"/>
+        <build id="6e4cefcf7c0461f90bc747db044c66a8c162afe166b571d6a3a8924417de66c5" bug="397325644"/>
+        <build id="66ca657d7332d74e831dd6307bdc350cac670634c853382a48e320f317ef519f" bug="391459865"/>
+        <build id="aabbb8f067b8811d10b65ff71171fb76dbac82373baa13949ae74c0c04cdb240" bug="400616479"/>
+        <build id="f8d33b7bbb35d9dc4c8af162a6d4b7d2d79c057b3e09341bfb3db50712bcd61e" bug="400383590"/>
+        <build id="701bc6e1729b3d636279df1c4c7fc2e33540cac0b5859c457134ebe0a0affd3a" bug="402031639"/>
+        <build id="7179682dfd148a34d03406730cf389f36b9201f4ebc0d7876b85e1339713d7e5" bug="402600434"/>
+        <build id="2c89a039ebcad778d3523f409822b1e436ac54690adaa55a9de17d7e7e2e979b" bug="394515205"/>
+        <build id="a74e3a465c242228b012ceeb74e7009d65a7807c0b9995850e230fe85269cb2c" bug="404967969"/>
     </branch>
 </ogki-approved>
diff --git a/w/android-6.12/Android.bp b/b/android-6.12/Android.bp
similarity index 96%
rename from w/android-6.12/Android.bp
rename to b/android-6.12/Android.bp
index db574e2..8e1cf05 100644
--- a/w/android-6.12/Android.bp
+++ b/b/android-6.12/Android.bp
@@ -18,7 +18,7 @@ package {
 }
 
 kernel_config {
-    name: "kernel_config_w_6.12",
+    name: "kernel_config_b_6.12",
     srcs: [
         "android-base.config",
     ],
diff --git a/w/android-6.12/android-base-conditional.xml b/b/android-6.12/android-base-conditional.xml
similarity index 98%
rename from w/android-6.12/android-base-conditional.xml
rename to b/android-6.12/android-base-conditional.xml
index 400f84b..fda288b 100644
--- a/w/android-6.12/android-base-conditional.xml
+++ b/b/android-6.12/android-base-conditional.xml
@@ -13,10 +13,6 @@
 		<key>CONFIG_AEABI</key>
 		<value type="bool">y</value>
 	</config>
-	<config>
-		<key>CONFIG_CPU_SW_DOMAIN_PAN</key>
-		<value type="bool">y</value>
-	</config>
 	<config>
 		<key>CONFIG_DEVKMEM</key>
 		<value type="bool">n</value>
diff --git a/w/android-6.12/android-base.config b/b/android-6.12/android-base.config
similarity index 100%
rename from w/android-6.12/android-base.config
rename to b/android-6.12/android-base.config
diff --git a/r/android-4.14/Android.bp b/c/android-6.12/Android.bp
similarity index 81%
rename from r/android-4.14/Android.bp
rename to c/android-6.12/Android.bp
index f6089bd..0b4af03 100644
--- a/r/android-4.14/Android.bp
+++ b/c/android-6.12/Android.bp
@@ -1,4 +1,4 @@
-// Copyright (C) 2020 The Android Open Source Project
+// Copyright (C) 2025 The Android Open Source Project
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -18,13 +18,9 @@ package {
 }
 
 kernel_config {
-    name: "kernel_config_r_4.14",
+    name: "kernel_config_c_6.12",
     srcs: [
         "android-base.config",
-        "non_debuggable.config",
-    ],
-    debuggable_srcs: [
-        "android-base.config",
     ],
     meta: "android-base-conditional.xml",
 }
diff --git a/r/android-4.19/android-base-conditional.xml b/c/android-6.12/android-base-conditional.xml
similarity index 58%
rename from r/android-4.19/android-base-conditional.xml
rename to c/android-6.12/android-base-conditional.xml
index e5b8635..fda288b 100644
--- a/r/android-4.19/android-base-conditional.xml
+++ b/c/android-6.12/android-base-conditional.xml
@@ -1,4 +1,4 @@
-<kernel minlts="4.19.110" />
+<kernel minlts="6.12.0" />
 
 <!-- KEEP ALPHABETICALLY SORTED -->
 <!-- ARM base requirements -->
@@ -13,10 +13,6 @@
 		<key>CONFIG_AEABI</key>
 		<value type="bool">y</value>
 	</config>
-	<config>
-		<key>CONFIG_CPU_SW_DOMAIN_PAN</key>
-		<value type="bool">y</value>
-	</config>
 	<config>
 		<key>CONFIG_DEVKMEM</key>
 		<value type="bool">n</value>
@@ -47,6 +43,10 @@
 		<key>CONFIG_ARMV8_DEPRECATED</key>
 		<value type="bool">y</value>
 	</config>
+	<config>
+		<key>CONFIG_CFI_CLANG</key>
+		<value type="bool">y</value>
+	</config>
 	<config>
 		<key>CONFIG_COMPAT</key>
 		<value type="bool">y</value>
@@ -55,16 +55,36 @@
 		<key>CONFIG_CP15_BARRIER_EMULATION</key>
 		<value type="bool">y</value>
 	</config>
+	<config>
+		<key>CONFIG_RANDOMIZE_BASE</key>
+		<value type="bool">y</value>
+	</config>
 	<config>
 		<key>CONFIG_SETEND_EMULATION</key>
 		<value type="bool">y</value>
 	</config>
+	<config>
+		<key>CONFIG_SHADOW_CALL_STACK</key>
+		<value type="bool">y</value>
+	</config>
 	<config>
 		<key>CONFIG_SWP_EMULATION</key>
 		<value type="bool">y</value>
 	</config>
 	<config>
-		<key>CONFIG_BPF_JIT_ALWAYS_ON</key>
+		<key>CONFIG_HAVE_MOVE_PMD</key>
+		<value type="bool">y</value>
+	</config>
+	<config>
+		<key>CONFIG_HAVE_MOVE_PUD</key>
+		<value type="bool">y</value>
+	</config>
+	<config>
+		<key>CONFIG_KFENCE</key>
+		<value type="bool">y</value>
+	</config>
+	<config>
+		<key>CONFIG_USERFAULTFD</key>
 		<value type="bool">y</value>
 	</config>
 </group>
@@ -82,15 +102,45 @@
 		<value type="bool">n</value>
 	</config>
 	<config>
-		<key>CONFIG_PAGE_TABLE_ISOLATION</key>
+		<key>CONFIG_KFENCE</key>
+		<value type="bool">y</value>
+	</config>
+	<config>
+		<key>CONFIG_MITIGATION_PAGE_TABLE_ISOLATION</key>
+		<value type="bool">y</value>
+	</config>
+	<config>
+		<key>CONFIG_MITIGATION_RETPOLINE</key>
 		<value type="bool">y</value>
 	</config>
 	<config>
-		<key>CONFIG_RETPOLINE</key>
+		<key>CONFIG_HAVE_MOVE_PMD</key>
 		<value type="bool">y</value>
 	</config>
 	<config>
-		<key>CONFIG_BPF_JIT_ALWAYS_ON</key>
+		<key>CONFIG_HAVE_MOVE_PUD</key>
+		<value type="bool">y</value>
+	</config>
+	<config>
+		<key>CONFIG_RANDOMIZE_BASE</key>
+		<value type="bool">y</value>
+	</config>
+	<config>
+		<key>CONFIG_USERFAULTFD</key>
+		<value type="bool">y</value>
+	</config>
+</group>
+
+<!-- x86_64 base requirements -->
+<group>
+	<conditions>
+		<config>
+			<key>CONFIG_X86_64</key>
+			<value type="bool">y</value>
+		</config>
+	</conditions>
+	<config>
+		<key>CONFIG_CFI_CLANG</key>
 		<value type="bool">y</value>
 	</config>
 </group>
@@ -148,3 +198,35 @@
 		<value type="bool">y</value>
 	</config>
 </group>
+
+<!-- CONFIG_VMAP_STACK requirement -->
+<group>
+	<conditions>
+		<config>
+			<key>CONFIG_HAVE_ARCH_VMAP_STACK</key>
+			<value type="bool">y</value>
+		</config>
+		<config>
+			<key>CONFIG_KASAN_SW_TAGS</key>
+			<value type="bool">n</value>
+		</config>
+	</conditions>
+	<config>
+		<key>CONFIG_VMAP_STACK</key>
+		<value type="bool">y</value>
+	</config>
+</group>
+
+<!-- CONFIG_INIT_STACK_ALL_ZERO requirement -->
+<group>
+	<conditions>
+		<config>
+			<key>CONFIG_CC_HAS_AUTO_VAR_INIT_ZERO</key>
+			<value type="bool">y</value>
+		</config>
+	</conditions>
+	<config>
+		<key>CONFIG_INIT_STACK_ALL_ZERO</key>
+		<value type="bool">y</value>
+	</config>
+</group>
diff --git a/r/android-4.19/android-base.config b/c/android-6.12/android-base.config
similarity index 88%
rename from r/android-4.19/android-base.config
rename to c/android-6.12/android-base.config
index fef4c6f..1481e99 100644
--- a/r/android-4.19/android-base.config
+++ b/c/android-6.12/android-base.config
@@ -1,5 +1,6 @@
 #  KEEP ALPHABETICALLY SORTED
 # CONFIG_ANDROID_LOW_MEMORY_KILLER is not set
+# CONFIG_ANDROID_PARANOID_NETWORK is not set
 # CONFIG_BPFILTER is not set
 # CONFIG_DEVMEM is not set
 # CONFIG_FHANDLE is not set
@@ -12,30 +13,38 @@
 # CONFIG_RT_GROUP_SCHED is not set
 # CONFIG_SYSVIPC is not set
 # CONFIG_USELIB is not set
-# CONFIG_VHOST is not set
 CONFIG_ADVISE_SYSCALLS=y
 CONFIG_AIO=y
-CONFIG_ANDROID=y
-CONFIG_ANDROID_BINDER_DEVICES="binder,hwbinder,vndbinder"
 CONFIG_ANDROID_BINDER_IPC=y
 CONFIG_ANDROID_BINDERFS=y
 CONFIG_ASHMEM=y
+CONFIG_AS_IS_LLVM=y
 CONFIG_AUDIT=y
 CONFIG_BINFMT_ELF=y
 CONFIG_BINFMT_SCRIPT=y
 CONFIG_BLK_DEV_INITRD=y
 CONFIG_BLK_DEV_LOOP=y
+CONFIG_BLK_INLINE_ENCRYPTION=y
 CONFIG_BLOCK=y
 CONFIG_BPF_JIT=y
+CONFIG_BPF_JIT_ALWAYS_ON=y
 CONFIG_BPF_SYSCALL=y
+CONFIG_BUG_ON_DATA_CORRUPTION=y
+CONFIG_CC_IS_CLANG=y
 CONFIG_CGROUPS=y
 CONFIG_CGROUP_BPF=y
 CONFIG_CGROUP_CPUACCT=y
 CONFIG_CGROUP_FREEZER=y
 CONFIG_CGROUP_SCHED=y
+CONFIG_CPU_FREQ=y
+CONFIG_CPU_FREQ_STAT=y
+CONFIG_CPU_FREQ_TIMES=y
 CONFIG_CROSS_MEMORY_ATTACH=y
 CONFIG_CRYPTO_AES=y
 CONFIG_CRYPTO_CBC=y
+CONFIG_CRYPTO_CHACHA20POLY1305=y
+CONFIG_CRYPTO_CMAC=y
+CONFIG_CRYPTO_CTR=y
 CONFIG_CRYPTO_ECB=y
 CONFIG_CRYPTO_GCM=y
 CONFIG_CRYPTO_HMAC=y
@@ -44,36 +53,38 @@ CONFIG_CRYPTO_NULL=y
 CONFIG_CRYPTO_SHA1=y
 CONFIG_CRYPTO_SHA256=y
 CONFIG_CRYPTO_SHA512=y
-CONFIG_DEBUG_LIST=y
+CONFIG_CRYPTO_XCBC=y
 CONFIG_DEFAULT_SECURITY_SELINUX=y
+CONFIG_DM_DEFAULT_KEY=y
 CONFIG_DM_SNAPSHOT=y
 CONFIG_DM_VERITY=y
 CONFIG_DUMMY=y
-CONFIG_EMBEDDED=y
 CONFIG_EPOLL=y
 CONFIG_EVENTFD=y
+CONFIG_EXPERT=y
 CONFIG_FILE_LOCKING=y
 CONFIG_FS_ENCRYPTION=y
+CONFIG_FS_ENCRYPTION_INLINE_CRYPT=y
 CONFIG_FS_VERITY=y
-CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y
 CONFIG_FUSE_FS=y
 CONFIG_FUTEX=y
 CONFIG_HARDENED_USERCOPY=y
 CONFIG_HID_GENERIC=y
+CONFIG_HID_PLAYSTATION=y
+CONFIG_PLAYSTATION_FF=y
+CONFIG_HIDRAW=y
 CONFIG_HID_SONY=y
+CONFIG_SONY_FF=y
 CONFIG_HIGH_RES_TIMERS=y
+CONFIG_IFB=y
 CONFIG_IKCONFIG=y
 CONFIG_IKCONFIG_PROC=y
 CONFIG_INET6_ESP=y
 CONFIG_INET6_IPCOMP=y
-CONFIG_INET6_XFRM_MODE_TRANSPORT=y
-CONFIG_INET6_XFRM_MODE_TUNNEL=y
 CONFIG_INET=y
 CONFIG_INET_DIAG_DESTROY=y
 CONFIG_INET_ESP=y
 CONFIG_INET_UDP_DIAG=y
-CONFIG_INET_XFRM_MODE_TRANSPORT=y
-CONFIG_INET_XFRM_MODE_TUNNEL=y
 CONFIG_INOTIFY_USER=y
 CONFIG_INPUT=y
 CONFIG_INPUT_EVDEV=y
@@ -101,6 +112,7 @@ CONFIG_IP_NF_FILTER=y
 CONFIG_IP_NF_IPTABLES=y
 CONFIG_IP_NF_MANGLE=y
 CONFIG_IP_NF_MATCH_ECN=y
+CONFIG_IP_NF_MATCH_RPFILTER=y
 CONFIG_IP_NF_MATCH_TTL=y
 CONFIG_IP_NF_NAT=y
 CONFIG_IP_NF_RAW=y
@@ -110,7 +122,7 @@ CONFIG_IP_NF_TARGET_NETMAP=y
 CONFIG_IP_NF_TARGET_REDIRECT=y
 CONFIG_IP_NF_TARGET_REJECT=y
 CONFIG_JOYSTICK_XPAD=y
-CONFIG_L2TP=y
+CONFIG_LD_IS_LLD=y
 CONFIG_MAGIC_SYSRQ=y
 CONFIG_MD=y
 CONFIG_MEMBARRIER=y
@@ -159,9 +171,12 @@ CONFIG_NETFILTER_XT_TARGET_SECMARK=y
 CONFIG_NETFILTER_XT_TARGET_TCPMSS=y
 CONFIG_NETFILTER_XT_TARGET_TPROXY=y
 CONFIG_NETFILTER_XT_TARGET_TRACE=y
+CONFIG_NET_ACT_POLICE=y
+CONFIG_NET_ACT_BPF=y
 CONFIG_NET_CLS_ACT=y
 CONFIG_NET_CLS_BPF=y
 CONFIG_NET_CLS_U32=y
+CONFIG_NET_CLS_MATCHALL=y
 CONFIG_NET_EMATCH=y
 CONFIG_NET_EMATCH_U32=y
 CONFIG_NET_IPGRE_DEMUX=y
@@ -171,6 +186,7 @@ CONFIG_NET_NS=y
 CONFIG_NET_SCHED=y
 CONFIG_NET_SCH_HTB=y
 CONFIG_NET_SCH_INGRESS=y
+CONFIG_NET_SCH_TBF=y
 CONFIG_NF_CONNTRACK=y
 CONFIG_NF_CONNTRACK_AMANDA=y
 CONFIG_NF_CONNTRACK_EVENTS=y
@@ -193,12 +209,6 @@ CONFIG_NO_HZ=y
 CONFIG_PACKET=y
 CONFIG_PM_WAKELOCKS=y
 CONFIG_POSIX_TIMERS=y
-CONFIG_PPP=y
-CONFIG_PPPOL2TP=y
-CONFIG_PPP_BSDCOMP=y
-CONFIG_PPP_DEFLATE=y
-CONFIG_PPP_MPPE=y
-CONFIG_PPTP=y
 CONFIG_PREEMPT=y
 CONFIG_PROC_FS=y
 CONFIG_PROFILING=y
@@ -206,6 +216,7 @@ CONFIG_PSI=y
 CONFIG_QFMT_V2=y
 CONFIG_QUOTA=y
 CONFIG_QUOTACTL=y
+CONFIG_RD_LZ4=y
 CONFIG_RTC_CLASS=y
 CONFIG_SCHED_DEBUG=y
 CONFIG_SECCOMP=y
@@ -230,6 +241,7 @@ CONFIG_TASKSTATS=y
 CONFIG_TASK_IO_ACCOUNTING=y
 CONFIG_TASK_XACCT=y
 CONFIG_TIMERFD=y
+CONFIG_TRACE_GPU_MEM=y
 CONFIG_TTY=y
 CONFIG_TUN=y
 CONFIG_UHID=y
@@ -237,15 +249,13 @@ CONFIG_UID_SYS_STATS=y
 CONFIG_UNIX=y
 CONFIG_USB=y
 CONFIG_USB_CONFIGFS=y
-CONFIG_USB_CONFIGFS_F_ACC=y
-CONFIG_USB_CONFIGFS_F_AUDIO_SRC=y
 CONFIG_USB_CONFIGFS_F_FS=y
 CONFIG_USB_CONFIGFS_F_MIDI=y
-CONFIG_USB_CONFIGFS_UEVENT=y
 CONFIG_USB_GADGET=y
 CONFIG_USB_SUPPORT=y
 CONFIG_UTS_NS=y
 CONFIG_VETH=y
 CONFIG_XFRM_INTERFACE=y
+CONFIG_XFRM_MIGRATE=y
 CONFIG_XFRM_STATISTICS=y
 CONFIG_XFRM_USER=y
diff --git a/kernel-lifetimes.xml b/kernel-lifetimes.xml
index c2d01a5..89dafb2 100644
--- a/kernel-lifetimes.xml
+++ b/kernel-lifetimes.xml
@@ -19,6 +19,7 @@
 			<release version="5.10.205" launch="2024-03-12" eol="2024-11-01"/>
 			<release version="5.10.209" launch="2024-05-09" eol="2025-06-01"/>
 			<release version="5.10.218" launch="2024-08-12" eol="2025-09-01"/>
+			<release version="5.10.226" launch="2024-11-12" eol="2025-12-01"/>
 		</lts-versions>
 	</branch>
 
@@ -31,7 +32,7 @@
 			<release version="5.10.210" launch="2024-06-21" eol="2025-07-01"/>
 			<release version="5.10.214" launch="2024-07-24" eol="2025-08-01"/>
 			<release version="5.10.218" launch="2024-08-22" eol="2025-09-01"/>
-			<release version="5.10.223" launch="2024-09-26" eol="2025-10-01"/>
+			<release version="5.10.223" launch="2024-09-26" eol="2025-12-01"/>
 		</lts-versions>
 	</branch>
 
@@ -40,10 +41,11 @@
 			<release version="5.15.123" launch="2023-10-27" eol="2024-11-01"/>
 			<release version="5.15.137" launch="2023-12-13" eol="2024-11-01"/>
 			<release version="5.15.144" launch="2024-02-20" eol="2024-11-01"/>
-			<release version="5.15.148" launch="2024-04-27" eol="2025-05-01"/>
+			<release version="5.15.148" launch="2024-04-27" eol="2025-06-01"/>
 			<release version="5.15.149" launch="2024-06-12" eol="2025-08-01"/>
 			<release version="5.15.151" launch="2024-08-21" eol="2025-09-01"/>
-			<release version="5.15.153" launch="2024-09-25" eol="2025-09-01"/>
+			<release version="5.15.153" launch="2024-09-25" eol="2025-10-01"/>
+			<release version="5.15.167" launch="2024-11-19" eol="2025-12-01"/>
 		</lts-versions>
 	</branch>
 
@@ -53,11 +55,12 @@
 			<release version="5.15.131" launch="2023-11-24" eol="2024-11-01"/>
 			<release version="5.15.137" launch="2023-12-13" eol="2024-11-01"/>
 			<release version="5.15.144" launch="2024-02-20" eol="2024-11-01"/>
-			<release version="5.15.148" launch="2024-04-27" eol="2025-05-01"/>
+			<release version="5.15.148" launch="2024-04-27" eol="2025-06-01"/>
 			<release version="5.15.149" launch="2024-06-27" eol="2025-07-01"/>
 			<release version="5.15.153" launch="2024-07-09" eol="2025-08-01"/>
 			<release version="5.15.158" launch="2024-08-09" eol="2025-09-01"/>
 			<release version="5.15.164" launch="2024-09-10" eol="2025-10-01"/>
+			<release version="5.15.167" launch="2024-11-19" eol="2025-12-01"/>
 		</lts-versions>
 	</branch>
 
@@ -66,12 +69,13 @@
 			<release version="6.1.43" launch="2023-10-31" eol="2024-11-01"/>
 			<release version="6.1.57" launch="2023-12-15" eol="2024-11-01"/>
 			<release version="6.1.68" launch="2024-02-21" eol="2024-11-01"/>
-			<release version="6.1.75" launch="2024-04-24" eol="2025-05-01"/>
+			<release version="6.1.75" launch="2024-04-24" eol="2025-06-01"/>
 			<release version="6.1.78" launch="2024-06-20" eol="2025-07-01"/>
 			<release version="6.1.84" launch="2024-07-24" eol="2025-08-01"/>
 			<release version="6.1.90" launch="2024-08-22" eol="2025-09-01"/>
 			<release version="6.1.93" launch="2024-09-26" eol="2025-10-01"/>
 			<release version="6.1.99" launch="2024-10-09" eol="2025-11-01"/>
+			<release version="6.1.112" launch="2024-11-10" eol="2025-12-01"/>
 		</lts-versions>
 	</branch>
 
@@ -80,6 +84,11 @@
 			<release version="6.6.30" launch="2024-07-12" eol="2025-09-01"/>
 			<release version="6.6.46" launch="2024-09-16" eol="2025-10-01"/>
 			<release version="6.6.50" launch="2024-10-11" eol="2025-11-01"/>
+			<release version="6.6.56" launch="2024-11-11" eol="2025-12-01"/>
 		</lts-versions>
 	</branch>
+
+	<branch name="android16-6.12" min_android_release="16" version="6.12" launch="2024-11-17" eol="2029-07-01">
+		<no-releases reason="release not yet scheduled"/>
+	</branch>
 </kernels>
diff --git a/r/android-4.14/android-base-conditional.xml b/r/android-4.14/android-base-conditional.xml
deleted file mode 100644
index 5b56452..0000000
--- a/r/android-4.14/android-base-conditional.xml
+++ /dev/null
@@ -1,150 +0,0 @@
-<kernel minlts="4.14.180" />
-
-<!-- KEEP ALPHABETICALLY SORTED -->
-<!-- ARM base requirements -->
-<group>
-	<conditions>
-		<config>
-			<key>CONFIG_ARM</key>
-			<value type="bool">y</value>
-		</config>
-	</conditions>
-	<config>
-		<key>CONFIG_AEABI</key>
-		<value type="bool">y</value>
-	</config>
-	<config>
-		<key>CONFIG_CPU_SW_DOMAIN_PAN</key>
-		<value type="bool">y</value>
-	</config>
-	<config>
-		<key>CONFIG_DEVKMEM</key>
-		<value type="bool">n</value>
-	</config>
-	<config>
-		<key>CONFIG_OABI_COMPAT</key>
-		<value type="bool">n</value>
-	</config>
-</group>
-
-<!-- ARM64 base requirements -->
-<group>
-	<conditions>
-		<config>
-			<key>CONFIG_ARM64</key>
-			<value type="bool">y</value>
-		</config>
-	</conditions>
-	<config>
-		<key>CONFIG_ARM64_PAN</key>
-		<value type="bool">y</value>
-	</config>
-	<config>
-		<key>CONFIG_ARM64_SW_TTBR0_PAN</key>
-		<value type="bool">y</value>
-	</config>
-	<config>
-		<key>CONFIG_ARMV8_DEPRECATED</key>
-		<value type="bool">y</value>
-	</config>
-	<config>
-		<key>CONFIG_COMPAT</key>
-		<value type="bool">y</value>
-	</config>
-	<config>
-		<key>CONFIG_CP15_BARRIER_EMULATION</key>
-		<value type="bool">y</value>
-	</config>
-	<config>
-		<key>CONFIG_SETEND_EMULATION</key>
-		<value type="bool">y</value>
-	</config>
-	<config>
-		<key>CONFIG_SWP_EMULATION</key>
-		<value type="bool">y</value>
-	</config>
-	<config>
-		<key>CONFIG_BPF_JIT_ALWAYS_ON</key>
-		<value type="bool">y</value>
-	</config>
-</group>
-
-<!-- x86 base requirements -->
-<group>
-	<conditions>
-		<config>
-			<key>CONFIG_X86</key>
-			<value type="bool">y</value>
-		</config>
-	</conditions>
-	<config>
-		<key>CONFIG_DEVKMEM</key>
-		<value type="bool">n</value>
-	</config>
-	<config>
-		<key>CONFIG_PAGE_TABLE_ISOLATION</key>
-		<value type="bool">y</value>
-	</config>
-	<config>
-		<key>CONFIG_RETPOLINE</key>
-		<value type="bool">y</value>
-	</config>
-	<config>
-		<key>CONFIG_BPF_JIT_ALWAYS_ON</key>
-		<value type="bool">y</value>
-	</config>
-</group>
-
-<!-- CONFIG_ACPI || CONFIG_OF -->
-<group>
-	<conditions>
-		<config>
-			<key>CONFIG_ACPI</key>
-			<value type="bool">n</value>
-		</config>
-	</conditions>
-	<config>
-		<key>CONFIG_OF</key>
-		<value type="bool">y</value>
-	</config>
-</group>
-<group>
-	<conditions>
-		<config>
-			<key>CONFIG_OF</key>
-			<value type="bool">n</value>
-		</config>
-	</conditions>
-	<config>
-		<key>CONFIG_ACPI</key>
-		<value type="bool">y</value>
-	</config>
-</group>
-
-<!-- EXT4 requirements -->
-<group>
-	<conditions>
-		<config>
-			<key>CONFIG_EXT4_FS</key>
-			<value type="bool">y</value>
-		</config>
-	</conditions>
-	<config>
-		<key>CONFIG_EXT4_FS_POSIX_ACL</key>
-		<value type="bool">y</value>
-	</config>
-</group>
-
-<!-- F2FS requirements -->
-<group>
-	<conditions>
-		<config>
-			<key>CONFIG_F2FS_FS</key>
-			<value type="bool">y</value>
-		</config>
-	</conditions>
-	<config>
-		<key>CONFIG_F2FS_FS_POSIX_ACL</key>
-		<value type="bool">y</value>
-	</config>
-</group>
diff --git a/r/android-4.14/android-base.config b/r/android-4.14/android-base.config
deleted file mode 100644
index a126f5d..0000000
--- a/r/android-4.14/android-base.config
+++ /dev/null
@@ -1,250 +0,0 @@
-#  KEEP ALPHABETICALLY SORTED
-# CONFIG_DEVMEM is not set
-# CONFIG_FHANDLE is not set
-# CONFIG_IP6_NF_NAT is not set
-# CONFIG_MODULE_FORCE_UNLOAD is not set
-# CONFIG_NETFILTER_XT_MATCH_QTAGUID is not set
-# CONFIG_NFSD is not set
-# CONFIG_NFS_FS is not set
-# CONFIG_PM_AUTOSLEEP is not set
-# CONFIG_RT_GROUP_SCHED is not set
-# CONFIG_SYSVIPC is not set
-# CONFIG_USELIB is not set
-# CONFIG_VHOST is not set
-CONFIG_ADVISE_SYSCALLS=y
-CONFIG_AIO=y
-CONFIG_ANDROID=y
-CONFIG_ANDROID_BINDER_DEVICES="binder,hwbinder,vndbinder"
-CONFIG_ANDROID_BINDER_IPC=y
-CONFIG_ANDROID_BINDERFS=y
-CONFIG_ASHMEM=y
-CONFIG_AUDIT=y
-CONFIG_BINFMT_ELF=y
-CONFIG_BINFMT_SCRIPT=y
-CONFIG_BLK_DEV_INITRD=y
-CONFIG_BLK_DEV_LOOP=y
-CONFIG_BLOCK=y
-CONFIG_BPF_JIT=y
-CONFIG_BPF_SYSCALL=y
-CONFIG_CC_STACKPROTECTOR_STRONG=y
-CONFIG_CGROUPS=y
-CONFIG_CGROUP_BPF=y
-CONFIG_CGROUP_CPUACCT=y
-CONFIG_CGROUP_FREEZER=y
-CONFIG_CGROUP_SCHED=y
-CONFIG_CROSS_MEMORY_ATTACH=y
-CONFIG_CRYPTO_AES=y
-CONFIG_CRYPTO_CBC=y
-CONFIG_CRYPTO_ECB=y
-CONFIG_CRYPTO_GCM=y
-CONFIG_CRYPTO_HMAC=y
-CONFIG_CRYPTO_MD5=y
-CONFIG_CRYPTO_NULL=y
-CONFIG_CRYPTO_SHA1=y
-CONFIG_CRYPTO_SHA256=y
-CONFIG_CRYPTO_SHA512=y
-CONFIG_DEBUG_LIST=y
-CONFIG_DEFAULT_SECURITY_SELINUX=y
-CONFIG_DM_SNAPSHOT=y
-CONFIG_DM_VERITY=y
-CONFIG_DUMMY=y
-CONFIG_EMBEDDED=y
-CONFIG_EPOLL=y
-CONFIG_EVENTFD=y
-CONFIG_FILE_LOCKING=y
-CONFIG_FS_ENCRYPTION=y
-CONFIG_FS_VERITY=y
-CONFIG_FS_VERITY_BUILTIN_SIGNATURES=y
-CONFIG_FUSE_FS=y
-CONFIG_FUTEX=y
-CONFIG_HARDENED_USERCOPY=y
-CONFIG_HID_GENERIC=y
-CONFIG_HID_SONY=y
-CONFIG_HIGH_RES_TIMERS=y
-CONFIG_IKCONFIG=y
-CONFIG_IKCONFIG_PROC=y
-CONFIG_INET6_ESP=y
-CONFIG_INET6_IPCOMP=y
-CONFIG_INET6_XFRM_MODE_TRANSPORT=y
-CONFIG_INET6_XFRM_MODE_TUNNEL=y
-CONFIG_INET=y
-CONFIG_INET_DIAG_DESTROY=y
-CONFIG_INET_ESP=y
-CONFIG_INET_UDP_DIAG=y
-CONFIG_INET_XFRM_MODE_TRANSPORT=y
-CONFIG_INET_XFRM_MODE_TUNNEL=y
-CONFIG_INOTIFY_USER=y
-CONFIG_INPUT=y
-CONFIG_INPUT_EVDEV=y
-CONFIG_INPUT_JOYSTICK=y
-CONFIG_IP6_NF_FILTER=y
-CONFIG_IP6_NF_IPTABLES=y
-CONFIG_IP6_NF_MANGLE=y
-CONFIG_IP6_NF_MATCH_RPFILTER=y
-CONFIG_IP6_NF_RAW=y
-CONFIG_IP6_NF_TARGET_REJECT=y
-CONFIG_IPV6=y
-CONFIG_IPV6_MIP6=y
-CONFIG_IPV6_MULTIPLE_TABLES=y
-CONFIG_IPV6_OPTIMISTIC_DAD=y
-CONFIG_IPV6_ROUTER_PREF=y
-CONFIG_IPV6_ROUTE_INFO=y
-CONFIG_IPV6_VTI=y
-CONFIG_IP_ADVANCED_ROUTER=y
-CONFIG_IP_MULTICAST=y
-CONFIG_IP_MULTIPLE_TABLES=y
-CONFIG_IP_NF_ARPFILTER=y
-CONFIG_IP_NF_ARPTABLES=y
-CONFIG_IP_NF_ARP_MANGLE=y
-CONFIG_IP_NF_FILTER=y
-CONFIG_IP_NF_IPTABLES=y
-CONFIG_IP_NF_MANGLE=y
-CONFIG_IP_NF_MATCH_ECN=y
-CONFIG_IP_NF_MATCH_TTL=y
-CONFIG_IP_NF_NAT=y
-CONFIG_IP_NF_RAW=y
-CONFIG_IP_NF_SECURITY=y
-CONFIG_IP_NF_TARGET_MASQUERADE=y
-CONFIG_IP_NF_TARGET_NETMAP=y
-CONFIG_IP_NF_TARGET_REDIRECT=y
-CONFIG_IP_NF_TARGET_REJECT=y
-CONFIG_JOYSTICK_XPAD=y
-CONFIG_L2TP=y
-CONFIG_MAGIC_SYSRQ=y
-CONFIG_MD=y
-CONFIG_MEMBARRIER=y
-CONFIG_MMU=y
-CONFIG_MODULES=y
-CONFIG_MODULE_UNLOAD=y
-CONFIG_MODVERSIONS=y
-CONFIG_MULTIUSER=y
-CONFIG_NAMESPACES=y
-CONFIG_NET=y
-CONFIG_NETDEVICES=y
-CONFIG_NETFILTER=y
-CONFIG_NETFILTER_XT_MATCH_BPF=y
-CONFIG_NETFILTER_XT_MATCH_COMMENT=y
-CONFIG_NETFILTER_XT_MATCH_CONNLIMIT=y
-CONFIG_NETFILTER_XT_MATCH_CONNMARK=y
-CONFIG_NETFILTER_XT_MATCH_CONNTRACK=y
-CONFIG_NETFILTER_XT_MATCH_HASHLIMIT=y
-CONFIG_NETFILTER_XT_MATCH_HELPER=y
-CONFIG_NETFILTER_XT_MATCH_IPRANGE=y
-CONFIG_NETFILTER_XT_MATCH_LENGTH=y
-CONFIG_NETFILTER_XT_MATCH_LIMIT=y
-CONFIG_NETFILTER_XT_MATCH_MAC=y
-CONFIG_NETFILTER_XT_MATCH_MARK=y
-CONFIG_NETFILTER_XT_MATCH_OWNER=y
-CONFIG_NETFILTER_XT_MATCH_PKTTYPE=y
-CONFIG_NETFILTER_XT_MATCH_POLICY=y
-CONFIG_NETFILTER_XT_MATCH_QUOTA2=y
-CONFIG_NETFILTER_XT_MATCH_QUOTA2_LOG=y
-CONFIG_NETFILTER_XT_MATCH_QUOTA=y
-CONFIG_NETFILTER_XT_MATCH_SOCKET=y
-CONFIG_NETFILTER_XT_MATCH_STATE=y
-CONFIG_NETFILTER_XT_MATCH_STATISTIC=y
-CONFIG_NETFILTER_XT_MATCH_STRING=y
-CONFIG_NETFILTER_XT_MATCH_TIME=y
-CONFIG_NETFILTER_XT_MATCH_U32=y
-CONFIG_NETFILTER_XT_TARGET_CLASSIFY=y
-CONFIG_NETFILTER_XT_TARGET_CONNMARK=y
-CONFIG_NETFILTER_XT_TARGET_CONNSECMARK=y
-CONFIG_NETFILTER_XT_TARGET_CT=y
-CONFIG_NETFILTER_XT_TARGET_IDLETIMER=y
-CONFIG_NETFILTER_XT_TARGET_MARK=y
-CONFIG_NETFILTER_XT_TARGET_NFLOG=y
-CONFIG_NETFILTER_XT_TARGET_NFQUEUE=y
-CONFIG_NETFILTER_XT_TARGET_SECMARK=y
-CONFIG_NETFILTER_XT_TARGET_TCPMSS=y
-CONFIG_NETFILTER_XT_TARGET_TPROXY=y
-CONFIG_NETFILTER_XT_TARGET_TRACE=y
-CONFIG_NET_CLS_ACT=y
-CONFIG_NET_CLS_BPF=y
-CONFIG_NET_CLS_U32=y
-CONFIG_NET_EMATCH=y
-CONFIG_NET_EMATCH_U32=y
-CONFIG_NET_IPGRE_DEMUX=y
-CONFIG_NET_IPVTI=y
-CONFIG_NET_KEY=y
-CONFIG_NET_NS=y
-CONFIG_NET_SCHED=y
-CONFIG_NET_SCH_HTB=y
-CONFIG_NET_SCH_INGRESS=y
-CONFIG_NF_CONNTRACK=y
-CONFIG_NF_CONNTRACK_AMANDA=y
-CONFIG_NF_CONNTRACK_EVENTS=y
-CONFIG_NF_CONNTRACK_FTP=y
-CONFIG_NF_CONNTRACK_H323=y
-CONFIG_NF_CONNTRACK_IPV4=y
-CONFIG_NF_CONNTRACK_IPV6=y
-CONFIG_NF_CONNTRACK_IRC=y
-CONFIG_NF_CONNTRACK_NETBIOS_NS=y
-CONFIG_NF_CONNTRACK_PPTP=y
-CONFIG_NF_CONNTRACK_SANE=y
-CONFIG_NF_CONNTRACK_SECMARK=y
-CONFIG_NF_CONNTRACK_TFTP=y
-CONFIG_NF_CT_NETLINK=y
-CONFIG_NF_CT_PROTO_DCCP=y
-CONFIG_NF_CT_PROTO_SCTP=y
-CONFIG_NF_CT_PROTO_UDPLITE=y
-CONFIG_NF_NAT=y
-CONFIG_NF_SOCKET_IPV4=y
-CONFIG_NF_SOCKET_IPV6=y
-CONFIG_NO_HZ=y
-CONFIG_PACKET=y
-CONFIG_PM_WAKELOCKS=y
-CONFIG_POSIX_TIMERS=y
-CONFIG_PPP=y
-CONFIG_PPPOL2TP=y
-CONFIG_PPP_BSDCOMP=y
-CONFIG_PPP_DEFLATE=y
-CONFIG_PPP_MPPE=y
-CONFIG_PPTP=y
-CONFIG_PREEMPT=y
-CONFIG_PROC_FS=y
-CONFIG_PROFILING=y
-CONFIG_PSI=y
-CONFIG_QFMT_V2=y
-CONFIG_QUOTA=y
-CONFIG_QUOTACTL=y
-CONFIG_RTC_CLASS=y
-CONFIG_SCHED_DEBUG=y
-CONFIG_SECCOMP=y
-CONFIG_SECCOMP_FILTER=y
-CONFIG_SECURITY=y
-CONFIG_SECURITY_NETWORK=y
-CONFIG_SECURITY_SELINUX=y
-CONFIG_SHMEM=y
-CONFIG_SIGNALFD=y
-CONFIG_SND=y
-CONFIG_SOUND=y
-CONFIG_STAGING=y
-CONFIG_STATIC_USERMODEHELPER=y
-CONFIG_STRICT_KERNEL_RWX=y
-CONFIG_STRICT_MODULE_RWX=y
-CONFIG_SUSPEND=y
-CONFIG_SYNC_FILE=y
-CONFIG_SYSFS=y
-CONFIG_TASKSTATS=y
-CONFIG_TASK_IO_ACCOUNTING=y
-CONFIG_TASK_XACCT=y
-CONFIG_TIMERFD=y
-CONFIG_TTY=y
-CONFIG_TUN=y
-CONFIG_UHID=y
-CONFIG_UID_SYS_STATS=y
-CONFIG_UNIX=y
-CONFIG_USB=y
-CONFIG_USB_CONFIGFS=y
-CONFIG_USB_CONFIGFS_F_ACC=y
-CONFIG_USB_CONFIGFS_F_AUDIO_SRC=y
-CONFIG_USB_CONFIGFS_F_FS=y
-CONFIG_USB_CONFIGFS_F_MIDI=y
-CONFIG_USB_CONFIGFS_UEVENT=y
-CONFIG_USB_GADGET=y
-CONFIG_USB_SUPPORT=y
-CONFIG_UTS_NS=y
-CONFIG_VETH=y
-CONFIG_XFRM_INTERFACE=y
-CONFIG_XFRM_STATISTICS=y
-CONFIG_XFRM_USER=y
diff --git a/r/android-4.14/android-recommended-arm.config b/r/android-4.14/android-recommended-arm.config
deleted file mode 100644
index 1ff0342..0000000
--- a/r/android-4.14/android-recommended-arm.config
+++ /dev/null
@@ -1,6 +0,0 @@
-#  KEEP ALPHABETICALLY SORTED
-CONFIG_ARM_CRYPTO=y
-CONFIG_CRYPTO_AES_ARM_CE=y
-CONFIG_CRYPTO_SHA2_ARM_CE=y
-CONFIG_KERNEL_MODE_NEON=y
-CONFIG_NEON=y
diff --git a/r/android-4.14/android-recommended-arm64.config b/r/android-4.14/android-recommended-arm64.config
deleted file mode 100644
index 16ec836..0000000
--- a/r/android-4.14/android-recommended-arm64.config
+++ /dev/null
@@ -1,7 +0,0 @@
-#  KEEP ALPHABETICALLY SORTED
-CONFIG_ARM64_CRYPTO=y
-CONFIG_ARM64_SW_TTBR0_PAN=y
-CONFIG_CRYPTO_AES_ARM64_CE_BLK=y
-CONFIG_CRYPTO_SHA2_ARM64_CE=y
-CONFIG_RANDOMIZE_BASE=y
-CONFIG_RELOCATABLE=y
diff --git a/r/android-4.14/android-recommended-x86.config b/r/android-4.14/android-recommended-x86.config
deleted file mode 100644
index 0388b3f..0000000
--- a/r/android-4.14/android-recommended-x86.config
+++ /dev/null
@@ -1,5 +0,0 @@
-#  KEEP ALPHABETICALLY SORTED
-CONFIG_CRYPTO_AES_NI_INTEL=y
-CONFIG_CRYPTO_SHA256_SSSE3=y
-CONFIG_RANDOMIZE_BASE=y
-CONFIG_RELOCATABLE=y
diff --git a/r/android-4.14/android-recommended.config b/r/android-4.14/android-recommended.config
deleted file mode 100644
index 95b2803..0000000
--- a/r/android-4.14/android-recommended.config
+++ /dev/null
@@ -1,132 +0,0 @@
-#  KEEP ALPHABETICALLY SORTED
-# CONFIG_CORE_DUMP_DEFAULT_ELF_HEADERS is not set
-# CONFIG_INPUT_MOUSE is not set
-# CONFIG_KSM is not set
-# CONFIG_LEGACY_PTYS is not set
-# CONFIG_NF_CONNTRACK_SIP is not set
-# CONFIG_VT is not set
-CONFIG_BACKLIGHT_LCD_SUPPORT=y
-CONFIG_BLK_DEV_DM=y
-CONFIG_BLK_DEV_RAM=y
-CONFIG_BLK_DEV_RAM_SIZE=8192
-CONFIG_COMPACTION=y
-CONFIG_CONFIGFS_FS=y
-CONFIG_COREDUMP=y
-CONFIG_CPU_FREQ=y
-CONFIG_CPU_FREQ_GOV_SCHEDUTIL=y
-CONFIG_DEFAULT_USE_ENERGY_AWARE=y
-CONFIG_DM_BOW=y
-CONFIG_DM_CRYPT=y
-CONFIG_DM_UEVENT=y
-CONFIG_DM_VERITY_FEC=y
-CONFIG_DRAGONRISE_FF=y
-CONFIG_ELF_CORE=y
-CONFIG_ENABLE_DEFAULT_TRACERS=y
-CONFIG_EXT4_FS=y
-CONFIG_EXT4_FS_SECURITY=y
-CONFIG_F2FS_FS=y
-CONFIG_F2FS_FS_SECURITY=y
-CONFIG_FTRACE=y
-CONFIG_GREENASIA_FF=y
-CONFIG_HIDRAW=y
-CONFIG_HID_A4TECH=y
-CONFIG_HID_ACRUX=y
-CONFIG_HID_ACRUX_FF=y
-CONFIG_HID_APPLE=y
-CONFIG_HID_BELKIN=y
-CONFIG_HID_CHERRY=y
-CONFIG_HID_CHICONY=y
-CONFIG_HID_CYPRESS=y
-CONFIG_HID_DRAGONRISE=y
-CONFIG_HID_ELECOM=y
-CONFIG_HID_EMS_FF=y
-CONFIG_HID_EZKEY=y
-CONFIG_HID_GREENASIA=y
-CONFIG_HID_GYRATION=y
-CONFIG_HID_HOLTEK=y
-CONFIG_HID_KENSINGTON=y
-CONFIG_HID_KEYTOUCH=y
-CONFIG_HID_KYE=y
-CONFIG_HID_LCPOWER=y
-CONFIG_HID_LOGITECH=y
-CONFIG_HID_LOGITECH_DJ=y
-CONFIG_HID_MAGICMOUSE=y
-CONFIG_HID_MICROSOFT=y
-CONFIG_HID_MONTEREY=y
-CONFIG_HID_MULTITOUCH=y
-CONFIG_HID_NTRIG=y
-CONFIG_HID_ORTEK=y
-CONFIG_HID_PANTHERLORD=y
-CONFIG_HID_PETALYNX=y
-CONFIG_HID_PICOLCD=y
-CONFIG_HID_PRIMAX=y
-CONFIG_HID_PRODIKEYS=y
-CONFIG_HID_ROCCAT=y
-CONFIG_HID_SAITEK=y
-CONFIG_HID_SAMSUNG=y
-CONFIG_HID_SMARTJOYPLUS=y
-CONFIG_HID_SPEEDLINK=y
-CONFIG_HID_STEAM=y
-CONFIG_HID_SUNPLUS=y
-CONFIG_HID_THRUSTMASTER=y
-CONFIG_HID_TIVO=y
-CONFIG_HID_TOPSEED=y
-CONFIG_HID_TWINHAN=y
-CONFIG_HID_UCLOGIC=y
-CONFIG_HID_WACOM=y
-CONFIG_HID_WALTOP=y
-CONFIG_HID_WIIMOTE=y
-CONFIG_HID_ZEROPLUS=y
-CONFIG_HID_ZYDACRON=y
-CONFIG_INPUT_GPIO=y
-CONFIG_INPUT_KEYRESET=y
-CONFIG_INPUT_MISC=y
-CONFIG_INPUT_TABLET=y
-CONFIG_INPUT_UINPUT=y
-CONFIG_ION=y
-CONFIG_JOYSTICK_XPAD_FF=y
-CONFIG_JOYSTICK_XPAD_LEDS=y
-CONFIG_KALLSYMS=y
-CONFIG_KALLSYMS_ALL=y
-CONFIG_KEYS=y
-CONFIG_LOGIG940_FF=y
-CONFIG_LOGIRUMBLEPAD2_FF=y
-CONFIG_LOGITECH_FF=y
-CONFIG_MEDIA_SUPPORT=y
-CONFIG_MISC_FILESYSTEMS=y
-CONFIG_MSDOS_FS=y
-CONFIG_NET_SCH_NETEM=y
-CONFIG_OVERLAY_FS=y
-CONFIG_PANIC_TIMEOUT=5
-CONFIG_PANTHERLORD_FF=y
-CONFIG_PERF_EVENTS=y
-CONFIG_PM_DEBUG=y
-CONFIG_POWER_SUPPLY=y
-CONFIG_PSI=y
-CONFIG_PSTORE=y
-CONFIG_PSTORE_CONSOLE=y
-CONFIG_PSTORE_RAM=y
-CONFIG_REFCOUNT_FULL=y
-CONFIG_SCHEDSTATS=y
-CONFIG_SCHED_TUNE=y
-CONFIG_SDCARD_FS=y
-CONFIG_SMARTJOYPLUS_FF=y
-CONFIG_SMP=y
-CONFIG_SND=y
-CONFIG_SOUND=y
-CONFIG_STRICT_KERNEL_RWX=y
-CONFIG_TABLET_USB_ACECAD=y
-CONFIG_TABLET_USB_AIPTEK=y
-CONFIG_TABLET_USB_GTCO=y
-CONFIG_TABLET_USB_HANWANG=y
-CONFIG_TABLET_USB_KBTAB=y
-CONFIG_TASK_DELAY_ACCT=y
-CONFIG_TMPFS=y
-CONFIG_TMPFS_POSIX_ACL=y
-CONFIG_UPROBE_EVENTS=y
-CONFIG_USB_ANNOUNCE_NEW_DEVICES=y
-CONFIG_USB_EHCI_HCD=y
-CONFIG_USB_HIDDEV=y
-CONFIG_USB_RTL8152=y
-CONFIG_USB_USBNET=y
-CONFIG_VFAT_FS=y
diff --git a/r/android-4.14/non_debuggable.config b/r/android-4.14/non_debuggable.config
deleted file mode 100644
index 71b51bf..0000000
--- a/r/android-4.14/non_debuggable.config
+++ /dev/null
@@ -1,2 +0,0 @@
-#  KEEP ALPHABETICALLY SORTED
-# CONFIG_DEBUG_FS is not set
diff --git a/r/android-4.19/Android.bp b/r/android-4.19/Android.bp
deleted file mode 100644
index 9d00624..0000000
--- a/r/android-4.19/Android.bp
+++ /dev/null
@@ -1,30 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    // See: http://go/android-license-faq
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-kernel_config {
-    name: "kernel_config_r_4.19",
-    srcs: [
-        "android-base.config",
-        "non_debuggable.config",
-    ],
-    debuggable_srcs: [
-        "android-base.config",
-    ],
-    meta: "android-base-conditional.xml",
-}
diff --git a/r/android-4.19/android-recommended-arm.config b/r/android-4.19/android-recommended-arm.config
deleted file mode 100644
index 1ff0342..0000000
--- a/r/android-4.19/android-recommended-arm.config
+++ /dev/null
@@ -1,6 +0,0 @@
-#  KEEP ALPHABETICALLY SORTED
-CONFIG_ARM_CRYPTO=y
-CONFIG_CRYPTO_AES_ARM_CE=y
-CONFIG_CRYPTO_SHA2_ARM_CE=y
-CONFIG_KERNEL_MODE_NEON=y
-CONFIG_NEON=y
diff --git a/r/android-4.19/android-recommended-arm64.config b/r/android-4.19/android-recommended-arm64.config
deleted file mode 100644
index 16ec836..0000000
--- a/r/android-4.19/android-recommended-arm64.config
+++ /dev/null
@@ -1,7 +0,0 @@
-#  KEEP ALPHABETICALLY SORTED
-CONFIG_ARM64_CRYPTO=y
-CONFIG_ARM64_SW_TTBR0_PAN=y
-CONFIG_CRYPTO_AES_ARM64_CE_BLK=y
-CONFIG_CRYPTO_SHA2_ARM64_CE=y
-CONFIG_RANDOMIZE_BASE=y
-CONFIG_RELOCATABLE=y
diff --git a/r/android-4.19/android-recommended-x86.config b/r/android-4.19/android-recommended-x86.config
deleted file mode 100644
index 0388b3f..0000000
--- a/r/android-4.19/android-recommended-x86.config
+++ /dev/null
@@ -1,5 +0,0 @@
-#  KEEP ALPHABETICALLY SORTED
-CONFIG_CRYPTO_AES_NI_INTEL=y
-CONFIG_CRYPTO_SHA256_SSSE3=y
-CONFIG_RANDOMIZE_BASE=y
-CONFIG_RELOCATABLE=y
diff --git a/r/android-4.19/android-recommended.config b/r/android-4.19/android-recommended.config
deleted file mode 100644
index e47684c..0000000
--- a/r/android-4.19/android-recommended.config
+++ /dev/null
@@ -1,130 +0,0 @@
-#  KEEP ALPHABETICALLY SORTED
-# CONFIG_CORE_DUMP_DEFAULT_ELF_HEADERS is not set
-# CONFIG_INPUT_MOUSE is not set
-# CONFIG_KSM is not set
-# CONFIG_LEGACY_PTYS is not set
-# CONFIG_NF_CONNTRACK_SIP is not set
-# CONFIG_VT is not set
-CONFIG_BACKLIGHT_LCD_SUPPORT=y
-CONFIG_BLK_DEV_DM=y
-CONFIG_BLK_DEV_RAM=y
-CONFIG_BLK_DEV_RAM_SIZE=8192
-CONFIG_COMPACTION=y
-CONFIG_CONFIGFS_FS=y
-CONFIG_COREDUMP=y
-CONFIG_CPU_FREQ=y
-CONFIG_CPU_FREQ_GOV_SCHEDUTIL=y
-CONFIG_DM_BOW=y
-CONFIG_DM_CRYPT=y
-CONFIG_DM_UEVENT=y
-CONFIG_DM_VERITY_FEC=y
-CONFIG_DRAGONRISE_FF=y
-CONFIG_ELF_CORE=y
-CONFIG_ENABLE_DEFAULT_TRACERS=y
-CONFIG_ENERGY_MODEL=y
-CONFIG_EXT4_FS=y
-CONFIG_EXT4_FS_SECURITY=y
-CONFIG_F2FS_FS=y
-CONFIG_F2FS_FS_SECURITY=y
-CONFIG_FTRACE=y
-CONFIG_GREENASIA_FF=y
-CONFIG_HIDRAW=y
-CONFIG_HID_A4TECH=y
-CONFIG_HID_ACRUX=y
-CONFIG_HID_ACRUX_FF=y
-CONFIG_HID_APPLE=y
-CONFIG_HID_BELKIN=y
-CONFIG_HID_CHERRY=y
-CONFIG_HID_CHICONY=y
-CONFIG_HID_CYPRESS=y
-CONFIG_HID_DRAGONRISE=y
-CONFIG_HID_ELECOM=y
-CONFIG_HID_EMS_FF=y
-CONFIG_HID_EZKEY=y
-CONFIG_HID_GREENASIA=y
-CONFIG_HID_GYRATION=y
-CONFIG_HID_HOLTEK=y
-CONFIG_HID_KENSINGTON=y
-CONFIG_HID_KEYTOUCH=y
-CONFIG_HID_KYE=y
-CONFIG_HID_LCPOWER=y
-CONFIG_HID_LOGITECH=y
-CONFIG_HID_LOGITECH_DJ=y
-CONFIG_HID_MAGICMOUSE=y
-CONFIG_HID_MICROSOFT=y
-CONFIG_HID_MONTEREY=y
-CONFIG_HID_MULTITOUCH=y
-CONFIG_HID_NTRIG=y
-CONFIG_HID_ORTEK=y
-CONFIG_HID_PANTHERLORD=y
-CONFIG_HID_PETALYNX=y
-CONFIG_HID_PICOLCD=y
-CONFIG_HID_PRIMAX=y
-CONFIG_HID_PRODIKEYS=y
-CONFIG_HID_ROCCAT=y
-CONFIG_HID_SAITEK=y
-CONFIG_HID_SAMSUNG=y
-CONFIG_HID_SMARTJOYPLUS=y
-CONFIG_HID_SPEEDLINK=y
-CONFIG_HID_STEAM=y
-CONFIG_HID_SUNPLUS=y
-CONFIG_HID_THRUSTMASTER=y
-CONFIG_HID_TIVO=y
-CONFIG_HID_TOPSEED=y
-CONFIG_HID_TWINHAN=y
-CONFIG_HID_UCLOGIC=y
-CONFIG_HID_WACOM=y
-CONFIG_HID_WALTOP=y
-CONFIG_HID_WIIMOTE=y
-CONFIG_HID_ZEROPLUS=y
-CONFIG_HID_ZYDACRON=y
-CONFIG_INPUT_MISC=y
-CONFIG_INPUT_TABLET=y
-CONFIG_INPUT_UINPUT=y
-CONFIG_ION=y
-CONFIG_JOYSTICK_XPAD_FF=y
-CONFIG_JOYSTICK_XPAD_LEDS=y
-CONFIG_KALLSYMS=y
-CONFIG_KALLSYMS_ALL=y
-CONFIG_KEYS=y
-CONFIG_LOGIG940_FF=y
-CONFIG_LOGIRUMBLEPAD2_FF=y
-CONFIG_LOGITECH_FF=y
-CONFIG_MEDIA_SUPPORT=y
-CONFIG_MISC_FILESYSTEMS=y
-CONFIG_MSDOS_FS=y
-CONFIG_NET_SCH_NETEM=y
-CONFIG_OVERLAY_FS=y
-CONFIG_PANIC_TIMEOUT=5
-CONFIG_PANTHERLORD_FF=y
-CONFIG_PERF_EVENTS=y
-CONFIG_PM_DEBUG=y
-CONFIG_POWER_SUPPLY=y
-CONFIG_PSI=y
-CONFIG_PSTORE=y
-CONFIG_PSTORE_CONSOLE=y
-CONFIG_PSTORE_RAM=y
-CONFIG_REFCOUNT_FULL=y
-CONFIG_SCHEDSTATS=y
-CONFIG_SCHED_TUNE=y
-CONFIG_SDCARD_FS=y
-CONFIG_SMARTJOYPLUS_FF=y
-CONFIG_SMP=y
-CONFIG_SND=y
-CONFIG_SOUND=y
-CONFIG_STRICT_KERNEL_RWX=y
-CONFIG_TABLET_USB_ACECAD=y
-CONFIG_TABLET_USB_AIPTEK=y
-CONFIG_TABLET_USB_GTCO=y
-CONFIG_TABLET_USB_HANWANG=y
-CONFIG_TABLET_USB_KBTAB=y
-CONFIG_TASK_DELAY_ACCT=y
-CONFIG_TMPFS=y
-CONFIG_TMPFS_POSIX_ACL=y
-CONFIG_UPROBE_EVENTS=y
-CONFIG_USB_ANNOUNCE_NEW_DEVICES=y
-CONFIG_USB_EHCI_HCD=y
-CONFIG_USB_HIDDEV=y
-CONFIG_USB_RTL8152=y
-CONFIG_USB_USBNET=y
-CONFIG_VFAT_FS=y
diff --git a/r/android-4.19/non_debuggable.config b/r/android-4.19/non_debuggable.config
deleted file mode 100644
index 71b51bf..0000000
--- a/r/android-4.19/non_debuggable.config
+++ /dev/null
@@ -1,2 +0,0 @@
-#  KEEP ALPHABETICALLY SORTED
-# CONFIG_DEBUG_FS is not set
diff --git a/r/android-5.4/android-base-conditional.xml b/r/android-5.4/android-base-conditional.xml
index d54f670..8725cd3 100644
--- a/r/android-5.4/android-base-conditional.xml
+++ b/r/android-5.4/android-base-conditional.xml
@@ -13,10 +13,6 @@
 		<key>CONFIG_AEABI</key>
 		<value type="bool">y</value>
 	</config>
-	<config>
-		<key>CONFIG_CPU_SW_DOMAIN_PAN</key>
-		<value type="bool">y</value>
-	</config>
 	<config>
 		<key>CONFIG_DEVKMEM</key>
 		<value type="bool">n</value>
diff --git a/s/android-4.19/android-base-conditional.xml b/s/android-4.19/android-base-conditional.xml
index c7de80c..8aab2a0 100644
--- a/s/android-4.19/android-base-conditional.xml
+++ b/s/android-4.19/android-base-conditional.xml
@@ -13,10 +13,6 @@
 		<key>CONFIG_AEABI</key>
 		<value type="bool">y</value>
 	</config>
-	<config>
-		<key>CONFIG_CPU_SW_DOMAIN_PAN</key>
-		<value type="bool">y</value>
-	</config>
 	<config>
 		<key>CONFIG_DEVKMEM</key>
 		<value type="bool">n</value>
diff --git a/s/android-5.10/android-base-conditional.xml b/s/android-5.10/android-base-conditional.xml
index aae1847..4b376c5 100644
--- a/s/android-5.10/android-base-conditional.xml
+++ b/s/android-5.10/android-base-conditional.xml
@@ -13,10 +13,6 @@
 		<key>CONFIG_AEABI</key>
 		<value type="bool">y</value>
 	</config>
-	<config>
-		<key>CONFIG_CPU_SW_DOMAIN_PAN</key>
-		<value type="bool">y</value>
-	</config>
 	<config>
 		<key>CONFIG_DEVKMEM</key>
 		<value type="bool">n</value>
diff --git a/s/android-5.4/android-base-conditional.xml b/s/android-5.4/android-base-conditional.xml
index 1e62abd..560c42f 100644
--- a/s/android-5.4/android-base-conditional.xml
+++ b/s/android-5.4/android-base-conditional.xml
@@ -13,10 +13,6 @@
 		<key>CONFIG_AEABI</key>
 		<value type="bool">y</value>
 	</config>
-	<config>
-		<key>CONFIG_CPU_SW_DOMAIN_PAN</key>
-		<value type="bool">y</value>
-	</config>
 	<config>
 		<key>CONFIG_DEVKMEM</key>
 		<value type="bool">n</value>
diff --git a/t/android-5.10/android-base-conditional.xml b/t/android-5.10/android-base-conditional.xml
index db24e7f..92a3478 100644
--- a/t/android-5.10/android-base-conditional.xml
+++ b/t/android-5.10/android-base-conditional.xml
@@ -13,10 +13,6 @@
 		<key>CONFIG_AEABI</key>
 		<value type="bool">y</value>
 	</config>
-	<config>
-		<key>CONFIG_CPU_SW_DOMAIN_PAN</key>
-		<value type="bool">y</value>
-	</config>
 	<config>
 		<key>CONFIG_DEVKMEM</key>
 		<value type="bool">n</value>
diff --git a/t/android-5.15/android-base-conditional.xml b/t/android-5.15/android-base-conditional.xml
index 3e76ae6..6f40883 100644
--- a/t/android-5.15/android-base-conditional.xml
+++ b/t/android-5.15/android-base-conditional.xml
@@ -13,10 +13,6 @@
 		<key>CONFIG_AEABI</key>
 		<value type="bool">y</value>
 	</config>
-	<config>
-		<key>CONFIG_CPU_SW_DOMAIN_PAN</key>
-		<value type="bool">y</value>
-	</config>
 	<config>
 		<key>CONFIG_DEVKMEM</key>
 		<value type="bool">n</value>
diff --git a/u/android-5.15/android-base-conditional.xml b/u/android-5.15/android-base-conditional.xml
index 11d3d95..fdc6730 100644
--- a/u/android-5.15/android-base-conditional.xml
+++ b/u/android-5.15/android-base-conditional.xml
@@ -13,10 +13,6 @@
 		<key>CONFIG_AEABI</key>
 		<value type="bool">y</value>
 	</config>
-	<config>
-		<key>CONFIG_CPU_SW_DOMAIN_PAN</key>
-		<value type="bool">y</value>
-	</config>
 	<config>
 		<key>CONFIG_DEVKMEM</key>
 		<value type="bool">n</value>
diff --git a/u/android-6.1/android-base-conditional.xml b/u/android-6.1/android-base-conditional.xml
index a85563a..1ddf067 100644
--- a/u/android-6.1/android-base-conditional.xml
+++ b/u/android-6.1/android-base-conditional.xml
@@ -13,10 +13,6 @@
 		<key>CONFIG_AEABI</key>
 		<value type="bool">y</value>
 	</config>
-	<config>
-		<key>CONFIG_CPU_SW_DOMAIN_PAN</key>
-		<value type="bool">y</value>
-	</config>
 	<config>
 		<key>CONFIG_DEVKMEM</key>
 		<value type="bool">n</value>
diff --git a/v/android-6.1/android-base-conditional.xml b/v/android-6.1/android-base-conditional.xml
index ec0c9f8..93fdd99 100644
--- a/v/android-6.1/android-base-conditional.xml
+++ b/v/android-6.1/android-base-conditional.xml
@@ -13,10 +13,6 @@
 		<key>CONFIG_AEABI</key>
 		<value type="bool">y</value>
 	</config>
-	<config>
-		<key>CONFIG_CPU_SW_DOMAIN_PAN</key>
-		<value type="bool">y</value>
-	</config>
 	<config>
 		<key>CONFIG_DEVKMEM</key>
 		<value type="bool">n</value>
diff --git a/v/android-6.6/android-base-conditional.xml b/v/android-6.6/android-base-conditional.xml
index cb7cd51..6bac4a8 100644
--- a/v/android-6.6/android-base-conditional.xml
+++ b/v/android-6.6/android-base-conditional.xml
@@ -13,10 +13,6 @@
 		<key>CONFIG_AEABI</key>
 		<value type="bool">y</value>
 	</config>
-	<config>
-		<key>CONFIG_CPU_SW_DOMAIN_PAN</key>
-		<value type="bool">y</value>
-	</config>
 	<config>
 		<key>CONFIG_DEVKMEM</key>
 		<value type="bool">n</value>
diff --git a/xsd/kernelLifetimes/kernel_lifetimes.xsd b/xsd/kernelLifetimes/kernel_lifetimes.xsd
index 7f90d89..09bbe42 100644
--- a/xsd/kernelLifetimes/kernel_lifetimes.xsd
+++ b/xsd/kernelLifetimes/kernel_lifetimes.xsd
@@ -38,7 +38,7 @@
         <xs:attribute name="eol" type="xs:date" use="required"/>
     </xs:complexType>
     <xs:complexType name="no-releases">
-        <xs:attribute name="reason" type="xs:string" fixed="non-GKI kernel"/>
+        <xs:attribute name="reason" type="xs:string" use="required"/>
     </xs:complexType>
     <xs:complexType name="lts-versions">
         <xs:sequence>
diff --git a/xsd/kernelLifetimes/vts/ValidateKernelLifetimes.cpp b/xsd/kernelLifetimes/vts/ValidateKernelLifetimes.cpp
index 28d4dae..da8f5bf 100644
--- a/xsd/kernelLifetimes/vts/ValidateKernelLifetimes.cpp
+++ b/xsd/kernelLifetimes/vts/ValidateKernelLifetimes.cpp
@@ -22,7 +22,7 @@
 #include <vintf/VintfObject.h>
 #include "utility/ValidateXml.h"
 
-TEST(CheckConfig, approvedBuildValidation) {
+TEST(CheckConfig, kernelLifetimesValidation) {
     if (android::vintf::VintfObject::GetRuntimeInfo()->kernelVersion().dropMinor() <
         android::vintf::Version{4, 14}) {
         GTEST_SKIP() << "Kernel versions below 4.14 are exempt";
```

