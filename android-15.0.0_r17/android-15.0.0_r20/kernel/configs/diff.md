```diff
diff --git a/OWNERS b/OWNERS
index 8cafa08..8ae14d2 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,3 @@
 include kernel/common:android-mainline:/OWNERS
+
+per-file approved-ogki-builds.xml=gprocida@google.com,szuweilin@google.com
diff --git a/approved-ogki-builds.xml b/approved-ogki-builds.xml
index 41a3933..489abf9 100644
--- a/approved-ogki-builds.xml
+++ b/approved-ogki-builds.xml
@@ -9,5 +9,18 @@
         <build id="33c3a0275689e4e1ec425168c518bb2a19067d15134b8a378d9f559e81a158a2" bug="365040462"/>
         <build id="0141db8fab24fa166137f8ab0a22ab2f50e3cf7b582e1619713641e27604b42d" bug="365050796"/>
         <build id="cef7d3cb5e807a1290e8ebfec13d82666e7e9fea3607b9b85a1c98ad660b5db2" bug="367569362"/>
+        <build id="a9098d4801bb0adfd5ece84dd1bd602477d20e10d4c6747dea7b55318447642a" bug="365445056"/>
+        <build id="8fb7ad74cb59ca7345d355b6764226c4048ed02a1ea9189bad8e9f842b101484" bug="365490960"/>
+        <build id="b1f92dda6b2c38dbea909badc91b3b28a054de94a024486964bd72f79c808c8b" bug="370105559"/>
+        <build id="cfc835874474a547c5524234a8b0439745865e6237ab281096e0577d8a586c54" bug="371109120"/>
+        <build id="af3fac58e89b2d3be32c5243522b110265f663ae8bc87e4a5c033dca0a5173a4" bug="372781358"/>
+        <build id="6212eb07e3860fbc4ddb1777fdd0081720214530a7d75b04b4d6124cbc9b8eea" bug="373007513"/>
+        <build id="d87030fc2e522fd63ba51f41bd4b879a253c483ec0abce72e302a575c4616f60" bug="376306115"/>
+        <build id="e59599c75c0cd65b6f458dfa354508f4e1df2ab22c7b619700d830682dd43130" bug="376176551"/>
+        <build id="497913ccdd8944275a72755194824fad0ff2f0f70e0d378163629e92cdb98799" bug="376408424"/>
+        <build id="d249c895f5879ff4cd56a996ae3c62e3db1627e48a733319098aebf079eba095" bug="380176718"/>
+        <build id="af142b33121b3916221430aa51fc79178c9556d42a3a07cad39e6bf6a16a54e3" bug="382189309"/>
+        <build id="d82fb33e858ff924ab3decb299363c10033e039ebfda60b7518e172b062ef763" bug="381189904"/>
+        <build id="3e83431b33e9e4d78c078c05dbb94a3c3d6274cdd37062f560b378c32247bc61" bug="379765216"/>
     </branch>
 </ogki-approved>
diff --git a/kernel-lifetimes.xml b/kernel-lifetimes.xml
index acae814..c2d01a5 100644
--- a/kernel-lifetimes.xml
+++ b/kernel-lifetimes.xml
@@ -18,6 +18,7 @@
 			<release version="5.10.198" launch="2023-11-14" eol="2024-11-01"/>
 			<release version="5.10.205" launch="2024-03-12" eol="2024-11-01"/>
 			<release version="5.10.209" launch="2024-05-09" eol="2025-06-01"/>
+			<release version="5.10.218" launch="2024-08-12" eol="2025-09-01"/>
 		</lts-versions>
 	</branch>
 
@@ -28,6 +29,9 @@
 			<release version="5.10.205" launch="2024-02-20" eol="2024-11-01"/>
 			<release version="5.10.209" launch="2024-04-27" eol="2025-06-01"/>
 			<release version="5.10.210" launch="2024-06-21" eol="2025-07-01"/>
+			<release version="5.10.214" launch="2024-07-24" eol="2025-08-01"/>
+			<release version="5.10.218" launch="2024-08-22" eol="2025-09-01"/>
+			<release version="5.10.223" launch="2024-09-26" eol="2025-10-01"/>
 		</lts-versions>
 	</branch>
 
@@ -37,18 +41,23 @@
 			<release version="5.15.137" launch="2023-12-13" eol="2024-11-01"/>
 			<release version="5.15.144" launch="2024-02-20" eol="2024-11-01"/>
 			<release version="5.15.148" launch="2024-04-27" eol="2025-05-01"/>
-			<release version="5.15.149" launch="2024-06-12" eol="2025-07-01"/>
+			<release version="5.15.149" launch="2024-06-12" eol="2025-08-01"/>
+			<release version="5.15.151" launch="2024-08-21" eol="2025-09-01"/>
+			<release version="5.15.153" launch="2024-09-25" eol="2025-09-01"/>
 		</lts-versions>
 	</branch>
 
 	<branch name="android14-5.15" min_android_release="14" version="5.15" launch="2021-10-31" eol="2028-07-01">
 		<lts-versions>
 			<release version="5.15.123" launch="2023-10-27" eol="2024-11-01"/>
+			<release version="5.15.131" launch="2023-11-24" eol="2024-11-01"/>
 			<release version="5.15.137" launch="2023-12-13" eol="2024-11-01"/>
 			<release version="5.15.144" launch="2024-02-20" eol="2024-11-01"/>
 			<release version="5.15.148" launch="2024-04-27" eol="2025-05-01"/>
 			<release version="5.15.149" launch="2024-06-27" eol="2025-07-01"/>
 			<release version="5.15.153" launch="2024-07-09" eol="2025-08-01"/>
+			<release version="5.15.158" launch="2024-08-09" eol="2025-09-01"/>
+			<release version="5.15.164" launch="2024-09-10" eol="2025-10-01"/>
 		</lts-versions>
 	</branch>
 
@@ -59,12 +68,18 @@
 			<release version="6.1.68" launch="2024-02-21" eol="2024-11-01"/>
 			<release version="6.1.75" launch="2024-04-24" eol="2025-05-01"/>
 			<release version="6.1.78" launch="2024-06-20" eol="2025-07-01"/>
+			<release version="6.1.84" launch="2024-07-24" eol="2025-08-01"/>
+			<release version="6.1.90" launch="2024-08-22" eol="2025-09-01"/>
+			<release version="6.1.93" launch="2024-09-26" eol="2025-10-01"/>
+			<release version="6.1.99" launch="2024-10-09" eol="2025-11-01"/>
 		</lts-versions>
 	</branch>
 
 	<branch name="android15-6.6" min_android_release="15" version="6.6" launch="2023-10-29" eol="2028-07-01">
 		<lts-versions>
-			<release version="6.6.30" launch="2024-07-12" eol="2025-08-01"/>
+			<release version="6.6.30" launch="2024-07-12" eol="2025-09-01"/>
+			<release version="6.6.46" launch="2024-09-16" eol="2025-10-01"/>
+			<release version="6.6.50" launch="2024-10-11" eol="2025-11-01"/>
 		</lts-versions>
 	</branch>
 </kernels>
diff --git a/w/android-6.next/Android.bp b/w/android-6.12/Android.bp
similarity index 95%
rename from w/android-6.next/Android.bp
rename to w/android-6.12/Android.bp
index 1f9c8ae..db574e2 100644
--- a/w/android-6.next/Android.bp
+++ b/w/android-6.12/Android.bp
@@ -18,7 +18,7 @@ package {
 }
 
 kernel_config {
-    name: "kernel_config_w_6.next",
+    name: "kernel_config_w_6.12",
     srcs: [
         "android-base.config",
     ],
diff --git a/w/android-6.next/android-base-conditional.xml b/w/android-6.12/android-base-conditional.xml
similarity index 94%
rename from w/android-6.next/android-base-conditional.xml
rename to w/android-6.12/android-base-conditional.xml
index cb7cd51..400f84b 100644
--- a/w/android-6.next/android-base-conditional.xml
+++ b/w/android-6.12/android-base-conditional.xml
@@ -1,4 +1,4 @@
-<kernel minlts="6.6.0" />
+<kernel minlts="6.12.0" />
 
 <!-- KEEP ALPHABETICALLY SORTED -->
 <!-- ARM base requirements -->
@@ -75,10 +75,6 @@
 		<key>CONFIG_SWP_EMULATION</key>
 		<value type="bool">y</value>
 	</config>
-	<config>
-		<key>CONFIG_BPF_JIT_ALWAYS_ON</key>
-		<value type="bool">y</value>
-	</config>
 	<config>
 		<key>CONFIG_HAVE_MOVE_PMD</key>
 		<value type="bool">y</value>
@@ -114,11 +110,11 @@
 		<value type="bool">y</value>
 	</config>
 	<config>
-		<key>CONFIG_PAGE_TABLE_ISOLATION</key>
+		<key>CONFIG_MITIGATION_PAGE_TABLE_ISOLATION</key>
 		<value type="bool">y</value>
 	</config>
 	<config>
-		<key>CONFIG_RETPOLINE</key>
+		<key>CONFIG_MITIGATION_RETPOLINE</key>
 		<value type="bool">y</value>
 	</config>
 	<config>
@@ -151,10 +147,6 @@
 		<key>CONFIG_CFI_CLANG</key>
 		<value type="bool">y</value>
 	</config>
-	<config>
-		<key>CONFIG_BPF_JIT_ALWAYS_ON</key>
-		<value type="bool">y</value>
-	</config>
 </group>
 
 <!-- CONFIG_ACPI || CONFIG_OF -->
@@ -241,4 +233,4 @@
 		<key>CONFIG_INIT_STACK_ALL_ZERO</key>
 		<value type="bool">y</value>
 	</config>
-</group>
\ No newline at end of file
+</group>
diff --git a/w/android-6.next/android-base.config b/w/android-6.12/android-base.config
similarity index 99%
rename from w/android-6.next/android-base.config
rename to w/android-6.12/android-base.config
index b5edf77..1481e99 100644
--- a/w/android-6.next/android-base.config
+++ b/w/android-6.12/android-base.config
@@ -27,6 +27,7 @@ CONFIG_BLK_DEV_LOOP=y
 CONFIG_BLK_INLINE_ENCRYPTION=y
 CONFIG_BLOCK=y
 CONFIG_BPF_JIT=y
+CONFIG_BPF_JIT_ALWAYS_ON=y
 CONFIG_BPF_SYSCALL=y
 CONFIG_BUG_ON_DATA_CORRUPTION=y
 CONFIG_CC_IS_CLANG=y
@@ -111,6 +112,7 @@ CONFIG_IP_NF_FILTER=y
 CONFIG_IP_NF_IPTABLES=y
 CONFIG_IP_NF_MANGLE=y
 CONFIG_IP_NF_MATCH_ECN=y
+CONFIG_IP_NF_MATCH_RPFILTER=y
 CONFIG_IP_NF_MATCH_TTL=y
 CONFIG_IP_NF_NAT=y
 CONFIG_IP_NF_RAW=y
```

