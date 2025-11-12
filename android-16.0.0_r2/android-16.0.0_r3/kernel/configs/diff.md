```diff
diff --git a/approved-ogki-builds.xml b/approved-ogki-builds.xml
index 355ac54..4e2b7c8 100644
--- a/approved-ogki-builds.xml
+++ b/approved-ogki-builds.xml
@@ -38,5 +38,24 @@
         <build id="7179682dfd148a34d03406730cf389f36b9201f4ebc0d7876b85e1339713d7e5" bug="402600434"/>
         <build id="2c89a039ebcad778d3523f409822b1e436ac54690adaa55a9de17d7e7e2e979b" bug="394515205"/>
         <build id="a74e3a465c242228b012ceeb74e7009d65a7807c0b9995850e230fe85269cb2c" bug="404967969"/>
+        <build id="5f4476f17f9d4421c4486eff99b4bcf941455c30697164c8320ac57c78e2acfd" bug="405245097"/>
+        <build id="ea01f6c0ba3d61c179eef1aa0e83cdda0c5df576dfa55af0dab5d4fd44f83376" bug="407459068"/>
+        <build id="e816d75e91bc6cbedbe9c3f6b3d0f8ac80ada5261b52c5d1d98ca2d63adb418e" bug="407711482"/>
+        <build id="3f891c9cfa085e5e052c4a3993f79bfc255d3085c26afbdad39a089efc2e63c6" bug="404971164"/>
+        <build id="777c3137addaac7c0740a2d073bd26f7b2e58d15d2a6baae40d36f52251db96f" bug="409153065"/>
+        <build id="b51137d75618c8348ee6a4ec5f23442a526874c8889ed761745f9dec60449d54" bug="409475261"/>
+        <build id="b5834d0244c052f8df657b16f0ed1d5985c06e9c4e5a94b751903530e621d6fb" bug="403398885"/>
+        <build id="7c6e6b6e7364a4ffe67c2bdb408c477e782f8bfd878487e82617058dd393ed9b" bug="409704137"/>
+        <build id="95999124bdded19704c03e6671d96694c742ba56ca097067758a688cc8304b7f" bug="412262948"/>
+        <build id="553c676af4e9ec9172a5887c2658cec24aed980e5a2f7c8d431413cdb1c6ff30" bug="413159095"/>
+        <build id="c84bd7b5c1988d09971de39f74fd40fd098ffcba4cc0096be655c4670b3d7ba3" bug="415959920"/>
+        <build id="335f238fce64b114d897e97a95c806955d1ff39de2ae0bdc28d304d737a95a21" bug="417153558"/>
+        <build id="262c0ac7e2910df34dcb49b7d3c8b883d5ddf170ee2595ae5a193e6f8bf4ebcd" bug="417623531"/>
+        <build id="7e7f323950d2efa0a79679f3d7f1012fd4111b743e3f3cda2a131516b03e8c62" bug="417623530"/>
+        <build id="2b5f627191f2d729db3b3d96f8f19d67084da87df4a07e316d50cd42857ea5b3" bug="417154918"/>
+        <build id="20cb8620e2baf00b8dc2a3dbc63445256215e268be1cb8e0106fb850bbee694a" bug="418618663"/>
+        <build id="48cf025d75d3c5de486b0e1571490e1848dd549670194e6015e9ee7d786811ae" bug="419198949"/>
+        <build id="e17fb6e2f33ea6a44b669f62968a8490674a412fbd49bab826906c8e010b5939" bug="418695651"/>
+        <build id="8f5acf7da562c098d9c54ad9c32105109d31a0fa3bc08be9b7e0b6087e370091" bug="416527347"/>
     </branch>
 </ogki-approved>
diff --git a/kernel-lifetimes.xml b/kernel-lifetimes.xml
index 89dafb2..0e20d89 100644
--- a/kernel-lifetimes.xml
+++ b/kernel-lifetimes.xml
@@ -20,6 +20,7 @@
 			<release version="5.10.209" launch="2024-05-09" eol="2025-06-01"/>
 			<release version="5.10.218" launch="2024-08-12" eol="2025-09-01"/>
 			<release version="5.10.226" launch="2024-11-12" eol="2025-12-01"/>
+			<release version="5.10.233" launch="2025-02-11" eol="2026-03-01"/>
 		</lts-versions>
 	</branch>
 
@@ -32,7 +33,8 @@
 			<release version="5.10.210" launch="2024-06-21" eol="2025-07-01"/>
 			<release version="5.10.214" launch="2024-07-24" eol="2025-08-01"/>
 			<release version="5.10.218" launch="2024-08-22" eol="2025-09-01"/>
-			<release version="5.10.223" launch="2024-09-26" eol="2025-12-01"/>
+			<release version="5.10.223" launch="2024-09-26" eol="2026-02-01"/>
+			<release version="5.10.228" launch="2025-01-22" eol="2026-02-01"/>
 		</lts-versions>
 	</branch>
 
@@ -46,6 +48,7 @@
 			<release version="5.15.151" launch="2024-08-21" eol="2025-09-01"/>
 			<release version="5.15.153" launch="2024-09-25" eol="2025-10-01"/>
 			<release version="5.15.167" launch="2024-11-19" eol="2025-12-01"/>
+			<release version="5.15.170" launch="2025-01-22" eol="2026-02-01"/>
 		</lts-versions>
 	</branch>
 
@@ -61,6 +64,7 @@
 			<release version="5.15.158" launch="2024-08-09" eol="2025-09-01"/>
 			<release version="5.15.164" launch="2024-09-10" eol="2025-10-01"/>
 			<release version="5.15.167" launch="2024-11-19" eol="2025-12-01"/>
+			<release version="5.15.170" launch="2025-01-22" eol="2026-02-01"/>
 		</lts-versions>
 	</branch>
 
@@ -76,6 +80,10 @@
 			<release version="6.1.93" launch="2024-09-26" eol="2025-10-01"/>
 			<release version="6.1.99" launch="2024-10-09" eol="2025-11-01"/>
 			<release version="6.1.112" launch="2024-11-10" eol="2025-12-01"/>
+			<release version="6.1.115" launch="2024-12-13" eol="2026-01-01"/>
+			<release version="6.1.118" launch="2025-01-15" eol="2026-02-01"/>
+			<release version="6.1.124" launch="2025-02-10" eol="2026-03-01"/>
+			<release version="6.1.128" launch="2025-03-11" eol="2026-04-01"/>
 		</lts-versions>
 	</branch>
 
@@ -85,6 +93,10 @@
 			<release version="6.6.46" launch="2024-09-16" eol="2025-10-01"/>
 			<release version="6.6.50" launch="2024-10-11" eol="2025-11-01"/>
 			<release version="6.6.56" launch="2024-11-11" eol="2025-12-01"/>
+			<release version="6.6.57" launch="2024-12-24" eol="2026-01-01"/>
+			<release version="6.6.58" launch="2025-01-14" eol="2026-02-01"/>
+			<release version="6.6.66" launch="2025-02-10" eol="2026-03-01"/>
+			<release version="6.6.77" launch="2025-03-12" eol="2026-04-01"/>
 		</lts-versions>
 	</branch>
 
```

