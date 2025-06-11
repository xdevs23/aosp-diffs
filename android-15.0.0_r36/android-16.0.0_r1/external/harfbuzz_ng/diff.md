```diff
diff --git a/.ci/requirements-fonttools.txt b/.ci/requirements-fonttools.txt
index a020a2b6d..eecabbc3f 100644
--- a/.ci/requirements-fonttools.txt
+++ b/.ci/requirements-fonttools.txt
@@ -4,53 +4,55 @@
 #
 #    pip-compile --generate-hashes .ci/requirements-fonttools.in
 #
-fonttools==4.54.1 \
-    --hash=sha256:07e005dc454eee1cc60105d6a29593459a06321c21897f769a281ff2d08939f6 \
-    --hash=sha256:0a911591200114969befa7f2cb74ac148bce5a91df5645443371aba6d222e263 \
-    --hash=sha256:0d1d353ef198c422515a3e974a1e8d5b304cd54a4c2eebcae708e37cd9eeffb1 \
-    --hash=sha256:0e88e3018ac809b9662615072dcd6b84dca4c2d991c6d66e1970a112503bba7e \
-    --hash=sha256:1d152d1be65652fc65e695e5619e0aa0982295a95a9b29b52b85775243c06556 \
-    --hash=sha256:262705b1663f18c04250bd1242b0515d3bbae177bee7752be67c979b7d47f43d \
-    --hash=sha256:278913a168f90d53378c20c23b80f4e599dca62fbffae4cc620c8eed476b723e \
-    --hash=sha256:301540e89cf4ce89d462eb23a89464fef50915255ece765d10eee8b2bf9d75b2 \
-    --hash=sha256:31c32d7d4b0958600eac75eaf524b7b7cb68d3a8c196635252b7a2c30d80e986 \
-    --hash=sha256:357cacb988a18aace66e5e55fe1247f2ee706e01debc4b1a20d77400354cddeb \
-    --hash=sha256:37cddd62d83dc4f72f7c3f3c2bcf2697e89a30efb152079896544a93907733bd \
-    --hash=sha256:41bb0b250c8132b2fcac148e2e9198e62ff06f3cc472065dff839327945c5882 \
-    --hash=sha256:4aa4817f0031206e637d1e685251ac61be64d1adef111060df84fdcbc6ab6c44 \
-    --hash=sha256:4e10d2e0a12e18f4e2dd031e1bf7c3d7017be5c8dbe524d07706179f355c5dac \
-    --hash=sha256:5419771b64248484299fa77689d4f3aeed643ea6630b2ea750eeab219588ba20 \
-    --hash=sha256:54471032f7cb5fca694b5f1a0aaeba4af6e10ae989df408e0216f7fd6cdc405d \
-    --hash=sha256:58974b4987b2a71ee08ade1e7f47f410c367cdfc5a94fabd599c88165f56213a \
-    --hash=sha256:58d29b9a294573d8319f16f2f79e42428ba9b6480442fa1836e4eb89c4d9d61c \
-    --hash=sha256:5eb2474a7c5be8a5331146758debb2669bf5635c021aee00fd7c353558fc659d \
-    --hash=sha256:6e37561751b017cf5c40fce0d90fd9e8274716de327ec4ffb0df957160be3bff \
-    --hash=sha256:76ae5091547e74e7efecc3cbf8e75200bc92daaeb88e5433c5e3e95ea8ce5aa7 \
-    --hash=sha256:7965af9b67dd546e52afcf2e38641b5be956d68c425bef2158e95af11d229f10 \
-    --hash=sha256:7e3b7d44e18c085fd8c16dcc6f1ad6c61b71ff463636fcb13df7b1b818bd0c02 \
-    --hash=sha256:7ed7ee041ff7b34cc62f07545e55e1468808691dddfd315d51dd82a6b37ddef2 \
-    --hash=sha256:82834962b3d7c5ca98cb56001c33cf20eb110ecf442725dc5fdf36d16ed1ab07 \
-    --hash=sha256:8583e563df41fdecef31b793b4dd3af8a9caa03397be648945ad32717a92885b \
-    --hash=sha256:8fa92cb248e573daab8d032919623cc309c005086d743afb014c836636166f08 \
-    --hash=sha256:93d458c8a6a354dc8b48fc78d66d2a8a90b941f7fec30e94c7ad9982b1fa6bab \
-    --hash=sha256:957f669d4922f92c171ba01bef7f29410668db09f6c02111e22b2bce446f3285 \
-    --hash=sha256:9dc080e5a1c3b2656caff2ac2633d009b3a9ff7b5e93d0452f40cd76d3da3b3c \
-    --hash=sha256:9ef1b167e22709b46bf8168368b7b5d3efeaaa746c6d39661c1b4405b6352e58 \
-    --hash=sha256:a7a310c6e0471602fe3bf8efaf193d396ea561486aeaa7adc1f132e02d30c4b9 \
-    --hash=sha256:ab774fa225238986218a463f3fe151e04d8c25d7de09df7f0f5fce27b1243dbc \
-    --hash=sha256:ada215fd079e23e060157aab12eba0d66704316547f334eee9ff26f8c0d7b8ab \
-    --hash=sha256:c39287f5c8f4a0c5a55daf9eaf9ccd223ea59eed3f6d467133cc727d7b943a55 \
-    --hash=sha256:c9c563351ddc230725c4bdf7d9e1e92cbe6ae8553942bd1fb2b2ff0884e8b714 \
-    --hash=sha256:d26732ae002cc3d2ecab04897bb02ae3f11f06dd7575d1df46acd2f7c012a8d8 \
-    --hash=sha256:d3b659d1029946f4ff9b6183984578041b520ce0f8fb7078bb37ec7445806b33 \
-    --hash=sha256:dd9cc95b8d6e27d01e1e1f1fae8559ef3c02c76317da650a19047f249acd519d \
-    --hash=sha256:e4564cf40cebcb53f3dc825e85910bf54835e8a8b6880d59e5159f0f325e637e \
-    --hash=sha256:e7d82b9e56716ed32574ee106cabca80992e6bbdcf25a88d97d21f73a0aae664 \
-    --hash=sha256:e8a4b261c1ef91e7188a30571be6ad98d1c6d9fa2427244c545e2fa0a2494dd7 \
-    --hash=sha256:e96bc94c8cda58f577277d4a71f51c8e2129b8b36fd05adece6320dd3d57de8a \
-    --hash=sha256:ed2f80ca07025551636c555dec2b755dd005e2ea8fbeb99fc5cdff319b70b23b \
-    --hash=sha256:f5b8a096e649768c2f4233f947cf9737f8dbf8728b90e2771e2497c6e3d21d13 \
-    --hash=sha256:f8e953cc0bddc2beaf3a3c3b5dd9ab7554677da72dfaf46951e193c9653e515a \
-    --hash=sha256:fda582236fee135d4daeca056c8c88ec5f6f6d88a004a79b84a02547c8f57386 \
-    --hash=sha256:fdb062893fd6d47b527d39346e0c5578b7957dcea6d6a3b6794569370013d9ac
+fonttools==4.55.3 \
+    --hash=sha256:07f8288aacf0a38d174445fc78377a97fb0b83cfe352a90c9d9c1400571963c7 \
+    --hash=sha256:11e5de1ee0d95af4ae23c1a138b184b7f06e0b6abacabf1d0db41c90b03d834b \
+    --hash=sha256:1bc7ad24ff98846282eef1cbeac05d013c2154f977a79886bb943015d2b1b261 \
+    --hash=sha256:1dcc07934a2165ccdc3a5a608db56fb3c24b609658a5b340aee4ecf3ba679dc0 \
+    --hash=sha256:22f38464daa6cdb7b6aebd14ab06609328fe1e9705bb0fcc7d1e69de7109ee02 \
+    --hash=sha256:27e4ae3592e62eba83cd2c4ccd9462dcfa603ff78e09110680a5444c6925d841 \
+    --hash=sha256:3983313c2a04d6cc1fe9251f8fc647754cf49a61dac6cb1e7249ae67afaafc45 \
+    --hash=sha256:529cef2ce91dc44f8e407cc567fae6e49a1786f2fefefa73a294704c415322a4 \
+    --hash=sha256:5323a22eabddf4b24f66d26894f1229261021dacd9d29e89f7872dd8c63f0b8b \
+    --hash=sha256:54153c49913f45065c8d9e6d0c101396725c5621c8aee744719300f79771d75a \
+    --hash=sha256:546565028e244a701f73df6d8dd6be489d01617863ec0c6a42fa25bf45d43048 \
+    --hash=sha256:5480673f599ad410695ca2ddef2dfefe9df779a9a5cda89503881e503c9c7d90 \
+    --hash=sha256:5e8d657cd7326eeaba27de2740e847c6b39dde2f8d7cd7cc56f6aad404ddf0bd \
+    --hash=sha256:62d65a3022c35e404d19ca14f291c89cc5890032ff04f6c17af0bd1927299674 \
+    --hash=sha256:6314bf82c54c53c71805318fcf6786d986461622dd926d92a465199ff54b1b72 \
+    --hash=sha256:7a8aa2c5e5b8b3bcb2e4538d929f6589a5c6bdb84fd16e2ed92649fb5454f11c \
+    --hash=sha256:827e95fdbbd3e51f8b459af5ea10ecb4e30af50221ca103bea68218e9615de07 \
+    --hash=sha256:859c358ebf41db18fb72342d3080bce67c02b39e86b9fbcf1610cca14984841b \
+    --hash=sha256:86721fbc389ef5cc1e2f477019e5069e8e4421e8d9576e9c26f840dbb04678de \
+    --hash=sha256:89bdc5d88bdeec1b15af790810e267e8332d92561dce4f0748c2b95c9bdf3926 \
+    --hash=sha256:8c4491699bad88efe95772543cd49870cf756b019ad56294f6498982408ab03e \
+    --hash=sha256:8c5ec45428edaa7022f1c949a632a6f298edc7b481312fc7dc258921e9399628 \
+    --hash=sha256:8e75f12c82127486fac2d8bfbf5bf058202f54bf4f158d367e41647b972342ca \
+    --hash=sha256:a430178ad3e650e695167cb53242dae3477b35c95bef6525b074d87493c4bf29 \
+    --hash=sha256:a8c2794ded89399cc2169c4d0bf7941247b8d5932b2659e09834adfbb01589aa \
+    --hash=sha256:aca318b77f23523309eec4475d1fbbb00a6b133eb766a8bdc401faba91261abe \
+    --hash=sha256:ae3b6600565b2d80b7c05acb8e24d2b26ac407b27a3f2e078229721ba5698427 \
+    --hash=sha256:aedbeb1db64496d098e6be92b2e63b5fac4e53b1b92032dfc6988e1ea9134a4d \
+    --hash=sha256:aee3b57643827e237ff6ec6d28d9ff9766bd8b21e08cd13bff479e13d4b14765 \
+    --hash=sha256:b54baf65c52952db65df39fcd4820668d0ef4766c0ccdf32879b77f7c804d5c5 \
+    --hash=sha256:b586ab5b15b6097f2fb71cafa3c98edfd0dba1ad8027229e7b1e204a58b0e09d \
+    --hash=sha256:b8d5e8916c0970fbc0f6f1bece0063363bb5857a7f170121a4493e31c3db3314 \
+    --hash=sha256:bc5dbb4685e51235ef487e4bd501ddfc49be5aede5e40f4cefcccabc6e60fb4b \
+    --hash=sha256:bdcc9f04b36c6c20978d3f060e5323a43f6222accc4e7fcbef3f428e216d96af \
+    --hash=sha256:c3ca99e0d460eff46e033cd3992a969658c3169ffcd533e0a39c63a38beb6831 \
+    --hash=sha256:caf8230f3e10f8f5d7593eb6d252a37caf58c480b19a17e250a63dad63834cf3 \
+    --hash=sha256:cd70de1a52a8ee2d1877b6293af8a2484ac82514f10b1c67c1c5762d38073e56 \
+    --hash=sha256:cf4fe7c124aa3f4e4c1940880156e13f2f4d98170d35c749e6b4f119a872551e \
+    --hash=sha256:d342e88764fb201286d185093781bf6628bbe380a913c24adf772d901baa8276 \
+    --hash=sha256:da9da6d65cd7aa6b0f806556f4985bcbf603bf0c5c590e61b43aa3e5a0f822d0 \
+    --hash=sha256:dc5294a3d5c84226e3dbba1b6f61d7ad813a8c0238fceea4e09aa04848c3d851 \
+    --hash=sha256:dd68c87a2bfe37c5b33bcda0fba39b65a353876d3b9006fde3adae31f97b3ef5 \
+    --hash=sha256:e6e8766eeeb2de759e862004aa11a9ea3d6f6d5ec710551a88b476192b64fd54 \
+    --hash=sha256:e894b5bd60d9f473bed7a8f506515549cc194de08064d829464088d23097331b \
+    --hash=sha256:eb6ca911c4c17eb51853143624d8dc87cdcdf12a711fc38bf5bd21521e79715f \
+    --hash=sha256:ed63959d00b61959b035c7d47f9313c2c1ece090ff63afea702fe86de00dbed4 \
+    --hash=sha256:f412604ccbeee81b091b420272841e5ec5ef68967a9790e80bffd0e30b8e2977 \
+    --hash=sha256:f7d66c15ba875432a2d2fb419523f5d3d347f91f48f57b8b08a2dfc3c39b8a3f \
+    --hash=sha256:f9e736f60f4911061235603a6119e72053073a12c6d7904011df2d8fad2c0e35 \
+    --hash=sha256:fb594b5a99943042c702c550d5494bdd7577f6ef19b0bc73877c948a63184a32
     # via -r requirements-fonttools.in
diff --git a/.ci/requirements.in b/.ci/requirements.in
index ae131bdcf..0e205be9f 100644
--- a/.ci/requirements.in
+++ b/.ci/requirements.in
@@ -1,5 +1,5 @@
 -r requirements-fonttools.in
-meson==1.5.2
+meson==1.6.1
 gcovr==5.0
 ninja
 setuptools # https://github.com/harfbuzz/harfbuzz/issues/4475
diff --git a/.ci/requirements.txt b/.ci/requirements.txt
index f30ff4f51..5dff38b12 100644
--- a/.ci/requirements.txt
+++ b/.ci/requirements.txt
@@ -4,63 +4,65 @@
 #
 #    pip-compile --allow-unsafe --generate-hashes --output-file=.ci/requirements.txt .ci/requirements.in
 #
-fonttools==4.54.1 \
-    --hash=sha256:07e005dc454eee1cc60105d6a29593459a06321c21897f769a281ff2d08939f6 \
-    --hash=sha256:0a911591200114969befa7f2cb74ac148bce5a91df5645443371aba6d222e263 \
-    --hash=sha256:0d1d353ef198c422515a3e974a1e8d5b304cd54a4c2eebcae708e37cd9eeffb1 \
-    --hash=sha256:0e88e3018ac809b9662615072dcd6b84dca4c2d991c6d66e1970a112503bba7e \
-    --hash=sha256:1d152d1be65652fc65e695e5619e0aa0982295a95a9b29b52b85775243c06556 \
-    --hash=sha256:262705b1663f18c04250bd1242b0515d3bbae177bee7752be67c979b7d47f43d \
-    --hash=sha256:278913a168f90d53378c20c23b80f4e599dca62fbffae4cc620c8eed476b723e \
-    --hash=sha256:301540e89cf4ce89d462eb23a89464fef50915255ece765d10eee8b2bf9d75b2 \
-    --hash=sha256:31c32d7d4b0958600eac75eaf524b7b7cb68d3a8c196635252b7a2c30d80e986 \
-    --hash=sha256:357cacb988a18aace66e5e55fe1247f2ee706e01debc4b1a20d77400354cddeb \
-    --hash=sha256:37cddd62d83dc4f72f7c3f3c2bcf2697e89a30efb152079896544a93907733bd \
-    --hash=sha256:41bb0b250c8132b2fcac148e2e9198e62ff06f3cc472065dff839327945c5882 \
-    --hash=sha256:4aa4817f0031206e637d1e685251ac61be64d1adef111060df84fdcbc6ab6c44 \
-    --hash=sha256:4e10d2e0a12e18f4e2dd031e1bf7c3d7017be5c8dbe524d07706179f355c5dac \
-    --hash=sha256:5419771b64248484299fa77689d4f3aeed643ea6630b2ea750eeab219588ba20 \
-    --hash=sha256:54471032f7cb5fca694b5f1a0aaeba4af6e10ae989df408e0216f7fd6cdc405d \
-    --hash=sha256:58974b4987b2a71ee08ade1e7f47f410c367cdfc5a94fabd599c88165f56213a \
-    --hash=sha256:58d29b9a294573d8319f16f2f79e42428ba9b6480442fa1836e4eb89c4d9d61c \
-    --hash=sha256:5eb2474a7c5be8a5331146758debb2669bf5635c021aee00fd7c353558fc659d \
-    --hash=sha256:6e37561751b017cf5c40fce0d90fd9e8274716de327ec4ffb0df957160be3bff \
-    --hash=sha256:76ae5091547e74e7efecc3cbf8e75200bc92daaeb88e5433c5e3e95ea8ce5aa7 \
-    --hash=sha256:7965af9b67dd546e52afcf2e38641b5be956d68c425bef2158e95af11d229f10 \
-    --hash=sha256:7e3b7d44e18c085fd8c16dcc6f1ad6c61b71ff463636fcb13df7b1b818bd0c02 \
-    --hash=sha256:7ed7ee041ff7b34cc62f07545e55e1468808691dddfd315d51dd82a6b37ddef2 \
-    --hash=sha256:82834962b3d7c5ca98cb56001c33cf20eb110ecf442725dc5fdf36d16ed1ab07 \
-    --hash=sha256:8583e563df41fdecef31b793b4dd3af8a9caa03397be648945ad32717a92885b \
-    --hash=sha256:8fa92cb248e573daab8d032919623cc309c005086d743afb014c836636166f08 \
-    --hash=sha256:93d458c8a6a354dc8b48fc78d66d2a8a90b941f7fec30e94c7ad9982b1fa6bab \
-    --hash=sha256:957f669d4922f92c171ba01bef7f29410668db09f6c02111e22b2bce446f3285 \
-    --hash=sha256:9dc080e5a1c3b2656caff2ac2633d009b3a9ff7b5e93d0452f40cd76d3da3b3c \
-    --hash=sha256:9ef1b167e22709b46bf8168368b7b5d3efeaaa746c6d39661c1b4405b6352e58 \
-    --hash=sha256:a7a310c6e0471602fe3bf8efaf193d396ea561486aeaa7adc1f132e02d30c4b9 \
-    --hash=sha256:ab774fa225238986218a463f3fe151e04d8c25d7de09df7f0f5fce27b1243dbc \
-    --hash=sha256:ada215fd079e23e060157aab12eba0d66704316547f334eee9ff26f8c0d7b8ab \
-    --hash=sha256:c39287f5c8f4a0c5a55daf9eaf9ccd223ea59eed3f6d467133cc727d7b943a55 \
-    --hash=sha256:c9c563351ddc230725c4bdf7d9e1e92cbe6ae8553942bd1fb2b2ff0884e8b714 \
-    --hash=sha256:d26732ae002cc3d2ecab04897bb02ae3f11f06dd7575d1df46acd2f7c012a8d8 \
-    --hash=sha256:d3b659d1029946f4ff9b6183984578041b520ce0f8fb7078bb37ec7445806b33 \
-    --hash=sha256:dd9cc95b8d6e27d01e1e1f1fae8559ef3c02c76317da650a19047f249acd519d \
-    --hash=sha256:e4564cf40cebcb53f3dc825e85910bf54835e8a8b6880d59e5159f0f325e637e \
-    --hash=sha256:e7d82b9e56716ed32574ee106cabca80992e6bbdcf25a88d97d21f73a0aae664 \
-    --hash=sha256:e8a4b261c1ef91e7188a30571be6ad98d1c6d9fa2427244c545e2fa0a2494dd7 \
-    --hash=sha256:e96bc94c8cda58f577277d4a71f51c8e2129b8b36fd05adece6320dd3d57de8a \
-    --hash=sha256:ed2f80ca07025551636c555dec2b755dd005e2ea8fbeb99fc5cdff319b70b23b \
-    --hash=sha256:f5b8a096e649768c2f4233f947cf9737f8dbf8728b90e2771e2497c6e3d21d13 \
-    --hash=sha256:f8e953cc0bddc2beaf3a3c3b5dd9ab7554677da72dfaf46951e193c9653e515a \
-    --hash=sha256:fda582236fee135d4daeca056c8c88ec5f6f6d88a004a79b84a02547c8f57386 \
-    --hash=sha256:fdb062893fd6d47b527d39346e0c5578b7957dcea6d6a3b6794569370013d9ac
+fonttools==4.55.3 \
+    --hash=sha256:07f8288aacf0a38d174445fc78377a97fb0b83cfe352a90c9d9c1400571963c7 \
+    --hash=sha256:11e5de1ee0d95af4ae23c1a138b184b7f06e0b6abacabf1d0db41c90b03d834b \
+    --hash=sha256:1bc7ad24ff98846282eef1cbeac05d013c2154f977a79886bb943015d2b1b261 \
+    --hash=sha256:1dcc07934a2165ccdc3a5a608db56fb3c24b609658a5b340aee4ecf3ba679dc0 \
+    --hash=sha256:22f38464daa6cdb7b6aebd14ab06609328fe1e9705bb0fcc7d1e69de7109ee02 \
+    --hash=sha256:27e4ae3592e62eba83cd2c4ccd9462dcfa603ff78e09110680a5444c6925d841 \
+    --hash=sha256:3983313c2a04d6cc1fe9251f8fc647754cf49a61dac6cb1e7249ae67afaafc45 \
+    --hash=sha256:529cef2ce91dc44f8e407cc567fae6e49a1786f2fefefa73a294704c415322a4 \
+    --hash=sha256:5323a22eabddf4b24f66d26894f1229261021dacd9d29e89f7872dd8c63f0b8b \
+    --hash=sha256:54153c49913f45065c8d9e6d0c101396725c5621c8aee744719300f79771d75a \
+    --hash=sha256:546565028e244a701f73df6d8dd6be489d01617863ec0c6a42fa25bf45d43048 \
+    --hash=sha256:5480673f599ad410695ca2ddef2dfefe9df779a9a5cda89503881e503c9c7d90 \
+    --hash=sha256:5e8d657cd7326eeaba27de2740e847c6b39dde2f8d7cd7cc56f6aad404ddf0bd \
+    --hash=sha256:62d65a3022c35e404d19ca14f291c89cc5890032ff04f6c17af0bd1927299674 \
+    --hash=sha256:6314bf82c54c53c71805318fcf6786d986461622dd926d92a465199ff54b1b72 \
+    --hash=sha256:7a8aa2c5e5b8b3bcb2e4538d929f6589a5c6bdb84fd16e2ed92649fb5454f11c \
+    --hash=sha256:827e95fdbbd3e51f8b459af5ea10ecb4e30af50221ca103bea68218e9615de07 \
+    --hash=sha256:859c358ebf41db18fb72342d3080bce67c02b39e86b9fbcf1610cca14984841b \
+    --hash=sha256:86721fbc389ef5cc1e2f477019e5069e8e4421e8d9576e9c26f840dbb04678de \
+    --hash=sha256:89bdc5d88bdeec1b15af790810e267e8332d92561dce4f0748c2b95c9bdf3926 \
+    --hash=sha256:8c4491699bad88efe95772543cd49870cf756b019ad56294f6498982408ab03e \
+    --hash=sha256:8c5ec45428edaa7022f1c949a632a6f298edc7b481312fc7dc258921e9399628 \
+    --hash=sha256:8e75f12c82127486fac2d8bfbf5bf058202f54bf4f158d367e41647b972342ca \
+    --hash=sha256:a430178ad3e650e695167cb53242dae3477b35c95bef6525b074d87493c4bf29 \
+    --hash=sha256:a8c2794ded89399cc2169c4d0bf7941247b8d5932b2659e09834adfbb01589aa \
+    --hash=sha256:aca318b77f23523309eec4475d1fbbb00a6b133eb766a8bdc401faba91261abe \
+    --hash=sha256:ae3b6600565b2d80b7c05acb8e24d2b26ac407b27a3f2e078229721ba5698427 \
+    --hash=sha256:aedbeb1db64496d098e6be92b2e63b5fac4e53b1b92032dfc6988e1ea9134a4d \
+    --hash=sha256:aee3b57643827e237ff6ec6d28d9ff9766bd8b21e08cd13bff479e13d4b14765 \
+    --hash=sha256:b54baf65c52952db65df39fcd4820668d0ef4766c0ccdf32879b77f7c804d5c5 \
+    --hash=sha256:b586ab5b15b6097f2fb71cafa3c98edfd0dba1ad8027229e7b1e204a58b0e09d \
+    --hash=sha256:b8d5e8916c0970fbc0f6f1bece0063363bb5857a7f170121a4493e31c3db3314 \
+    --hash=sha256:bc5dbb4685e51235ef487e4bd501ddfc49be5aede5e40f4cefcccabc6e60fb4b \
+    --hash=sha256:bdcc9f04b36c6c20978d3f060e5323a43f6222accc4e7fcbef3f428e216d96af \
+    --hash=sha256:c3ca99e0d460eff46e033cd3992a969658c3169ffcd533e0a39c63a38beb6831 \
+    --hash=sha256:caf8230f3e10f8f5d7593eb6d252a37caf58c480b19a17e250a63dad63834cf3 \
+    --hash=sha256:cd70de1a52a8ee2d1877b6293af8a2484ac82514f10b1c67c1c5762d38073e56 \
+    --hash=sha256:cf4fe7c124aa3f4e4c1940880156e13f2f4d98170d35c749e6b4f119a872551e \
+    --hash=sha256:d342e88764fb201286d185093781bf6628bbe380a913c24adf772d901baa8276 \
+    --hash=sha256:da9da6d65cd7aa6b0f806556f4985bcbf603bf0c5c590e61b43aa3e5a0f822d0 \
+    --hash=sha256:dc5294a3d5c84226e3dbba1b6f61d7ad813a8c0238fceea4e09aa04848c3d851 \
+    --hash=sha256:dd68c87a2bfe37c5b33bcda0fba39b65a353876d3b9006fde3adae31f97b3ef5 \
+    --hash=sha256:e6e8766eeeb2de759e862004aa11a9ea3d6f6d5ec710551a88b476192b64fd54 \
+    --hash=sha256:e894b5bd60d9f473bed7a8f506515549cc194de08064d829464088d23097331b \
+    --hash=sha256:eb6ca911c4c17eb51853143624d8dc87cdcdf12a711fc38bf5bd21521e79715f \
+    --hash=sha256:ed63959d00b61959b035c7d47f9313c2c1ece090ff63afea702fe86de00dbed4 \
+    --hash=sha256:f412604ccbeee81b091b420272841e5ec5ef68967a9790e80bffd0e30b8e2977 \
+    --hash=sha256:f7d66c15ba875432a2d2fb419523f5d3d347f91f48f57b8b08a2dfc3c39b8a3f \
+    --hash=sha256:f9e736f60f4911061235603a6119e72053073a12c6d7904011df2d8fad2c0e35 \
+    --hash=sha256:fb594b5a99943042c702c550d5494bdd7577f6ef19b0bc73877c948a63184a32
     # via -r requirements-fonttools.in
 gcovr==5.0 \
     --hash=sha256:1d80264cbaadff356b3dda71b8c62b3aa803e5b3eb6d526a24932cd6660a2576 \
     --hash=sha256:8c49ebcfc5a98b56dd900c687aad0258ac86093d2f81a1417905193ab45fe69f
     # via -r requirements.in
-jinja2==3.1.4 \
-    --hash=sha256:4a3aee7acbbe7303aede8e9648d13b8bf88a429282aa6122a993f0ac800cb369 \
-    --hash=sha256:bc5dd2abb727a5319567b7a813e6a2e7318c39f4f487cfe6c89c6f9c7d25197d
+jinja2==3.1.5 \
+    --hash=sha256:8fefff8dc3034e27bb80d67c671eb8a9bc424c0ef4c0826edbff304cceff43bb \
+    --hash=sha256:aba0f4dc9ed8013c424088f68a5c226f7d6097ed89b246d7749c2ec4175c6adb
     # via gcovr
 lxml==4.9.3 \
     --hash=sha256:05186a0f1346ae12553d66df1cfce6f251589fea3ad3da4f3ef4e34b2d58c6a3 \
@@ -218,26 +220,28 @@ markupsafe==2.1.3 \
     --hash=sha256:fec21693218efe39aa7f8599346e90c705afa52c5b31ae019b2e57e8f6542bb2 \
     --hash=sha256:ffcc3f7c66b5f5b7931a5aa68fc9cecc51e685ef90282f4a82f0f5e9b704ad11
     # via jinja2
-meson==1.5.2 \
-    --hash=sha256:77706e2368a00d789c097632ccf4fc39251fba56d03e1e1b262559a3c7a08f5b \
-    --hash=sha256:f955e09ab0d71ef180ae85df65991d58ed8430323de7d77a37e11c9ea630910b
+meson==1.6.1 \
+    --hash=sha256:1eca49eb6c26d58bbee67fd3337d8ef557c0804e30a6d16bfdf269db997464de \
+    --hash=sha256:3f41f6b03df56bb76836cc33c94e1a404c3584d48b3259540794a60a21fad1f9
     # via -r requirements.in
-ninja==1.11.1.1 \
-    --hash=sha256:18302d96a5467ea98b68e1cae1ae4b4fb2b2a56a82b955193c637557c7273dbd \
-    --hash=sha256:185e0641bde601e53841525c4196278e9aaf4463758da6dd1e752c0a0f54136a \
-    --hash=sha256:376889c76d87b95b5719fdd61dd7db193aa7fd4432e5d52d2e44e4c497bdbbee \
-    --hash=sha256:3e0f9be5bb20d74d58c66cc1c414c3e6aeb45c35b0d0e41e8d739c2c0d57784f \
-    --hash=sha256:73b93c14046447c7c5cc892433d4fae65d6364bec6685411cb97a8bcf815f93a \
-    --hash=sha256:7563ce1d9fe6ed5af0b8dd9ab4a214bf4ff1f2f6fd6dc29f480981f0f8b8b249 \
-    --hash=sha256:76482ba746a2618eecf89d5253c0d1e4f1da1270d41e9f54dfbd91831b0f6885 \
-    --hash=sha256:84502ec98f02a037a169c4b0d5d86075eaf6afc55e1879003d6cab51ced2ea4b \
-    --hash=sha256:95da904130bfa02ea74ff9c0116b4ad266174fafb1c707aa50212bc7859aebf1 \
-    --hash=sha256:9d793b08dd857e38d0b6ffe9e6b7145d7c485a42dcfea04905ca0cdb6017cc3c \
-    --hash=sha256:9df724344202b83018abb45cb1efc22efd337a1496514e7e6b3b59655be85205 \
-    --hash=sha256:aad34a70ef15b12519946c5633344bc775a7656d789d9ed5fdb0d456383716ef \
-    --hash=sha256:d491fc8d89cdcb416107c349ad1e3a735d4c4af5e1cb8f5f727baca6350fdaea \
-    --hash=sha256:ecf80cf5afd09f14dcceff28cb3f11dc90fb97c999c89307aea435889cb66877 \
-    --hash=sha256:fa2ba9d74acfdfbfbcf06fad1b8282de8a7a8c481d9dee45c859a8c93fcc1082
+ninja==1.11.1.3 \
+    --hash=sha256:04d48d14ea7ba11951c156599ab526bdda575450797ff57c6fdf99b2554d09c7 \
+    --hash=sha256:114ed5c61c8474df6a69ab89097a20749b769e2c219a452cb2fadc49b0d581b0 \
+    --hash=sha256:17978ad611d8ead578d83637f5ae80c2261b033db0b493a7ce94f88623f29e1b \
+    --hash=sha256:1ad2112c2b0159ed7c4ae3731595191b1546ba62316fc40808edecd0306fefa3 \
+    --hash=sha256:2883ea46b3c5079074f56820f9989c6261fcc6fd873d914ee49010ecf283c3b2 \
+    --hash=sha256:28aea3c1c280cba95b8608d50797169f3a34280e3e9a6379b6e340f0c9eaeeb0 \
+    --hash=sha256:2b4879ea3f1169f3d855182c57dcc84d1b5048628c8b7be0d702b81882a37237 \
+    --hash=sha256:53409151da081f3c198bb0bfc220a7f4e821e022c5b7d29719adda892ddb31bb \
+    --hash=sha256:56ada5d33b8741d298836644042faddebc83ee669782d661e21563034beb5aba \
+    --hash=sha256:7fa2247fce98f683bc712562d82b22b8a0a5c000738a13147ca2d1b68c122298 \
+    --hash=sha256:8c4bdb9fd2d0c06501ae15abfd23407660e95659e384acd36e013b6dd7d8a8e4 \
+    --hash=sha256:a27e78ca71316c8654965ee94b286a98c83877bfebe2607db96897bbfe458af0 \
+    --hash=sha256:a38c6c6c8032bed68b70c3b065d944c35e9f903342875d3a3218c1607987077c \
+    --hash=sha256:a4a3b71490557e18c010cbb26bd1ea9a0c32ee67e8f105e9731515b6e0af792e \
+    --hash=sha256:b6966f83064a88a51693073eea3decd47e08c3965241e09578ef7aa3a7738329 \
+    --hash=sha256:bc3ebc8b2e47716149f3541742b5cd8e0b08f51013b825c05baca3e34854370d \
+    --hash=sha256:edfa0d2e9d7ead1635b03e40a32ad56cc8f56798b6e2e9848d8300b174897076
     # via -r requirements.in
 pygments==2.16.1 \
     --hash=sha256:13fc09fa63bc8d8671a6d247e1eb303c4b343eaee81d861f3404db2935653692 \
diff --git a/.circleci/config.yml b/.circleci/config.yml
index 45f440ffa..5eae8d26d 100644
--- a/.circleci/config.yml
+++ b/.circleci/config.yml
@@ -136,7 +136,7 @@ jobs:
       - run: |
           python3 -m venv venv
           source venv/bin/activate
-          pip3 install meson==0.60.0
+          pip3 install meson==1.6.0
           bash .ci/build-win32.sh
       - store_artifacts:
           path: harfbuzz-win32.zip
@@ -162,7 +162,7 @@ jobs:
       - run: |
           python3 -m venv venv
           source venv/bin/activate
-          pip3 install meson==0.60.0
+          pip3 install meson==1.6.0
           bash .ci/build-win64.sh
       - store_artifacts:
           path: harfbuzz-win64.zip
diff --git a/.github/workflows/linux-ci.yml b/.github/workflows/linux-ci.yml
index 5bb640445..54a001891 100644
--- a/.github/workflows/linux-ci.yml
+++ b/.github/workflows/linux-ci.yml
@@ -70,7 +70,7 @@ jobs:
     - name: Generate Coverage
       run: ninja -Cbuild coverage-xml
     - name: Upload Coverage
-      uses: codecov/codecov-action@b9fd7d16f6d7d1b5d2bec1a2887e65ceed900238 # v4.6.0
+      uses: codecov/codecov-action@7f8b4b4bde536c465e797be725718b88c5d95e0e # v5.1.1
       with:
         token: ${{ secrets.CODECOV_TOKEN }}
         file: build/meson-logs/coverage.xml
diff --git a/.github/workflows/macos-ci.yml b/.github/workflows/macos-ci.yml
index 42617a1f1..e7fd9d051 100644
--- a/.github/workflows/macos-ci.yml
+++ b/.github/workflows/macos-ci.yml
@@ -24,6 +24,7 @@ jobs:
       run: |
         export HOMEBREW_NO_AUTO_UPDATE=1
         export HOMEBREW_NO_INSTALL_CLEANUP=1
+        brew rm -f pkg-config@0.29.2
         brew install \
           cairo \
           freetype \
@@ -33,7 +34,7 @@ jobs:
           icu4c \
           meson \
           ninja \
-          pkg-config
+          pkgconf
     - name: Setup Python
       uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b # v5.3.0
       with:
@@ -61,7 +62,7 @@ jobs:
     - name: Generate Coverage
       run: ninja -Cbuild coverage-xml
     - name: Upload Coverage
-      uses: codecov/codecov-action@b9fd7d16f6d7d1b5d2bec1a2887e65ceed900238 # v4.6.0
+      uses: codecov/codecov-action@7f8b4b4bde536c465e797be725718b88c5d95e0e # v5.1.1
       with:
         token: ${{ secrets.CODECOV_TOKEN }}
         file: build/meson-logs/coverage.xml
diff --git a/.github/workflows/scorecard.yml b/.github/workflows/scorecard.yml
index 5e80cd34d..6a3627ed7 100644
--- a/.github/workflows/scorecard.yml
+++ b/.github/workflows/scorecard.yml
@@ -59,6 +59,6 @@ jobs:
 
       # Upload the results to GitHub's code scanning dashboard.
       - name: "Upload to code-scanning"
-        uses: github/codeql-action/upload-sarif@662472033e021d55d94146f66f6058822b0b39fd # v3.27.0
+        uses: github/codeql-action/upload-sarif@aa578102511db1f4524ed59b8cc2bae4f6e88195 # v3.27.6
         with:
           sarif_file: results.sarif
diff --git a/Android.bp b/Android.bp
index 35cf7d82f..1c25b6c72 100644
--- a/Android.bp
+++ b/Android.bp
@@ -117,7 +117,6 @@ cc_library {
         "src/hb-subset-instancer-iup.cc",
         "src/hb-subset-instancer-solver.cc",
         "src/hb-subset-plan.cc",
-        "src/hb-subset-repacker.cc",
         "src/hb-subset.cc",
         "src/graph/gsubgpos-context.cc",
     ],
diff --git a/CMakeLists.txt b/CMakeLists.txt
index c8e377db6..c3e568fe3 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -1,4 +1,4 @@
-cmake_minimum_required(VERSION 3.12)
+cmake_minimum_required(VERSION 3.14)
 project(harfbuzz)
 
 message(WARN "HarfBuzz has a Meson port and tries to migrate all the other build systems to it, please consider using it as we might remove our cmake port soon.")
@@ -6,20 +6,6 @@ message(WARN "HarfBuzz has a Meson port and tries to migrate all the other build
 set(CMAKE_CXX_STANDARD 11)
 set(CMAKE_CXX_STANDARD_REQUIRED ON)
 
-## Limit framework build to Xcode generator
-if (BUILD_FRAMEWORK)
-  # for a framework build on macOS, use:
-  # cmake -DBUILD_FRAMEWORK=ON -Bbuild -H. -GXcode && cmake --build build
-  if (NOT "${CMAKE_GENERATOR}" STREQUAL "Xcode")
-    message(FATAL_ERROR
-      "You should use Xcode generator with BUILD_FRAMEWORK enabled")
-  endif ()
-  set (CMAKE_OSX_ARCHITECTURES "$(ARCHS_STANDARD_32_64_BIT)")
-  set (CMAKE_MACOSX_RPATH ON)
-  set (BUILD_SHARED_LIBS ON)
-endif ()
-
-
 ## Disallow in-source builds, as CMake generated make files can collide with autotools ones
 if (NOT MSVC AND "${PROJECT_BINARY_DIR}" STREQUAL "${PROJECT_SOURCE_DIR}")
   message(FATAL_ERROR
@@ -73,6 +59,14 @@ if (HB_HAVE_INTROSPECTION)
   set (HB_HAVE_GLIB ON)
 endif ()
 
+if (APPLE)
+  option(BUILD_FRAMEWORK "Build as Apple Frameworks" OFF)
+endif ()
+if (BUILD_FRAMEWORK)
+  set (CMAKE_MACOSX_RPATH ON)
+  set (BUILD_SHARED_LIBS OFF)
+endif ()
+
 include_directories(AFTER
   ${PROJECT_SOURCE_DIR}/src
   ${PROJECT_BINARY_DIR}/src
@@ -168,7 +162,7 @@ set (subset_project_sources
      ${PROJECT_SOURCE_DIR}/src/hb-subset-plan.cc
      ${PROJECT_SOURCE_DIR}/src/hb-subset-plan.hh
      ${PROJECT_SOURCE_DIR}/src/hb-subset-plan-member-list.hh
-     ${PROJECT_SOURCE_DIR}/src/hb-subset-repacker.cc
+     ${PROJECT_SOURCE_DIR}/src/hb-subset-serialize.cc
      ${PROJECT_SOURCE_DIR}/src/hb-subset.cc
      ${PROJECT_SOURCE_DIR}/src/hb-subset.hh
      ${PROJECT_SOURCE_DIR}/src/hb-repacker.hh
@@ -219,7 +213,7 @@ set (project_headers
 )
 set (subset_project_headers
      ${PROJECT_SOURCE_DIR}/src/hb-subset.h
-     ${PROJECT_SOURCE_DIR}/src/hb-subset-repacker.h
+     ${PROJECT_SOURCE_DIR}/src/hb-subset-serialize.h
 )
 
 ## Find and include needed header folders and libraries
@@ -506,6 +500,21 @@ if (HB_HAVE_ICU)
 
   if (BUILD_SHARED_LIBS)
     set_target_properties(harfbuzz harfbuzz-icu PROPERTIES VISIBILITY_INLINES_HIDDEN TRUE)
+
+    if (BUILD_FRAMEWORK)
+      set_target_properties(harfbuzz harfbuzz-icu PROPERTIES
+        FRAMEWORK TRUE
+        FRAMEWORK_VERSION "${HB_VERSION}"
+        PUBLIC_HEADER "${project_headers}"
+        PRODUCT_BUNDLE_IDENTIFIER "harfbuzz.harfbuzz-icu"
+        XCODE_ATTRIBUTE_INSTALL_PATH "@rpath"
+        OUTPUT_NAME "harfbuzz-icu"
+        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ""
+        MACOSX_FRAMEWORK_IDENTIFIER "harfbuzz-icu"
+        MACOSX_FRAMEWORK_SHORT_VERSION_STRING "${HB_VERSION}"
+        MACOSX_FRAMEWORK_BUNDLE_VERSION "${HB_VERSION}"
+      )
+    endif ()
   endif ()
 endif ()
 
@@ -513,12 +522,27 @@ endif ()
 ## Define harfbuzz-subset library
 if (HB_BUILD_SUBSET)
   add_library(harfbuzz-subset ${subset_project_sources} ${subset_project_headers})
-  list(APPEND project_headers ${PROJECT_SOURCE_DIR}/src/hb-subset.h ${PROJECT_SOURCE_DIR}/src/hb-subset-repacker.h)
+  list(APPEND project_headers ${PROJECT_SOURCE_DIR}/src/hb-subset.h ${PROJECT_SOURCE_DIR}/src/hb-subset-serialize.h)
   add_dependencies(harfbuzz-subset harfbuzz)
   target_link_libraries(harfbuzz-subset harfbuzz ${THIRD_PARTY_LIBS})
 
   if (BUILD_SHARED_LIBS)
     set_target_properties(harfbuzz harfbuzz-subset PROPERTIES VISIBILITY_INLINES_HIDDEN TRUE)
+
+    if (BUILD_FRAMEWORK)
+      set_target_properties(harfbuzz harfbuzz-subset PROPERTIES
+        FRAMEWORK TRUE
+        FRAMEWORK_VERSION "${HB_VERSION}"
+        PUBLIC_HEADER "${project_headers}"
+        PRODUCT_BUNDLE_IDENTIFIER "harfbuzz.harfbuzz-subset"
+        XCODE_ATTRIBUTE_INSTALL_PATH "@rpath"
+        OUTPUT_NAME "harfbuzz-subset"
+        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ""
+        MACOSX_FRAMEWORK_IDENTIFIER "harfbuzz-subset"
+        MACOSX_FRAMEWORK_SHORT_VERSION_STRING "${HB_VERSION}"
+        MACOSX_FRAMEWORK_BUNDLE_VERSION "${HB_VERSION}"
+      )
+    endif ()
   endif ()
 endif ()
 
@@ -568,7 +592,22 @@ if (HB_HAVE_GOBJECT)
   target_link_libraries(harfbuzz-gobject harfbuzz ${GOBJECT_LIBRARIES} ${THIRD_PARTY_LIBS})
 
   if (BUILD_SHARED_LIBS)
-    set_target_properties(harfbuzz-gobject PROPERTIES VISIBILITY_INLINES_HIDDEN TRUE)
+    set_target_properties(harfbuzz harfbuzz-gobject PROPERTIES VISIBILITY_INLINES_HIDDEN TRUE)
+
+    if (BUILD_FRAMEWORK)
+      set_target_properties(harfbuzz-gobject PROPERTIES
+        FRAMEWORK TRUE
+        FRAMEWORK_VERSION "${HB_VERSION}"
+        PUBLIC_HEADER "${project_headers}"
+        PRODUCT_BUNDLE_IDENTIFIER "harfbuzz.harfbuzz-gobject"
+        XCODE_ATTRIBUTE_INSTALL_PATH "@rpath"
+        OUTPUT_NAME "harfbuzz-gobject"
+        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ""
+        MACOSX_FRAMEWORK_IDENTIFIER "harfbuzz-gobject"
+        MACOSX_FRAMEWORK_SHORT_VERSION_STRING "${HB_VERSION}"
+        MACOSX_FRAMEWORK_BUNDLE_VERSION "${HB_VERSION}"
+      )
+    endif ()
   endif ()
 endif ()
 
@@ -581,6 +620,21 @@ if (HB_HAVE_CAIRO)
 
   if (BUILD_SHARED_LIBS)
     set_target_properties(harfbuzz-cairo PROPERTIES VISIBILITY_INLINES_HIDDEN TRUE)
+
+    if (BUILD_FRAMEWORK)
+      set_target_properties(harfbuzz-cairo PROPERTIES
+        FRAMEWORK TRUE
+        FRAMEWORK_VERSION "${HB_VERSION}"
+        PUBLIC_HEADER "${project_headers}"
+        PRODUCT_BUNDLE_IDENTIFIER "harfbuzz.harbuzz-cairo"
+        XCODE_ATTRIBUTE_INSTALL_PATH "@rpath"
+        OUTPUT_NAME "harfbuzz-cairo"
+        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ""
+        MACOSX_FRAMEWORK_IDENTIFIER "harfbuzz-cairo"
+        MACOSX_FRAMEWORK_SHORT_VERSION_STRING "${HB_VERSION}"
+        MACOSX_FRAMEWORK_BUNDLE_VERSION "${HB_VERSION}"
+      )
+    endif ()
   endif ()
 endif()
 
@@ -719,8 +773,12 @@ if (BUILD_FRAMEWORK)
   set (CMAKE_MACOSX_RPATH ON)
   set_target_properties(harfbuzz PROPERTIES
     FRAMEWORK TRUE
+    FRAMEWORK_VERSION "${HB_VERSION}"
     PUBLIC_HEADER "${project_headers}"
+    PRODUCT_BUNDLE_IDENTIFIER "harfbuzz"
     XCODE_ATTRIBUTE_INSTALL_PATH "@rpath"
+    OUTPUT_NAME "harfbuzz"
+    XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY ""
   )
   set (MACOSX_FRAMEWORK_IDENTIFIER "harfbuzz")
   set (MACOSX_FRAMEWORK_SHORT_VERSION_STRING "${HB_VERSION}")
@@ -881,7 +939,8 @@ if (NOT SKIP_INSTALL_LIBRARIES AND NOT SKIP_INSTALL_ALL)
     ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
     LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
     RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
-    FRAMEWORK DESTINATION Library/Frameworks
+    FRAMEWORK DESTINATION Library/Frameworks 
+    COMPONENT runtime OPTIONAL
   )
   make_pkgconfig_pc_file("harfbuzz")
   install(EXPORT harfbuzzConfig
@@ -893,7 +952,8 @@ if (NOT SKIP_INSTALL_LIBRARIES AND NOT SKIP_INSTALL_ALL)
       ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
       LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
       RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
-      FRAMEWORK DESTINATION Library/Frameworks
+      FRAMEWORK DESTINATION Library/Frameworks 
+      COMPONENT runtime OPTIONAL
     )
     make_pkgconfig_pc_file("harfbuzz-icu")
   endif ()
@@ -902,13 +962,19 @@ if (NOT SKIP_INSTALL_LIBRARIES AND NOT SKIP_INSTALL_ALL)
       ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
       LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
       RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
-      FRAMEWORK DESTINATION Library/Frameworks
+      FRAMEWORK DESTINATION Library/Frameworks 
+      COMPONENT runtime OPTIONAL
     )
     make_pkgconfig_pc_file("harfbuzz-cairo")
   endif ()
   if (HB_BUILD_SUBSET)
     install(TARGETS harfbuzz-subset
+      EXPORT harfbuzz-subset
       ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
+      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
+      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
+      FRAMEWORK DESTINATION Library/Frameworks 
+      COMPONENT runtime OPTIONAL
     )
     make_pkgconfig_pc_file("harfbuzz-subset")
   endif ()
@@ -943,9 +1009,12 @@ if (NOT SKIP_INSTALL_LIBRARIES AND NOT SKIP_INSTALL_ALL)
   endif ()
   if (HB_HAVE_GOBJECT)
     install(TARGETS harfbuzz-gobject
+      EXPORT harfbuzz-gobject
       ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
       LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
       RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
+      FRAMEWORK DESTINATION ${CMAKE_INSTALL_LIBDIR} 
+      COMPONENT runtime OPTIONAL
     )
     make_pkgconfig_pc_file("harfbuzz-gobject")
     if (HB_HAVE_INTROSPECTION)
diff --git a/LICENSE b/LICENSE
index 315dd59b3..4ce592dc5 100644
--- a/LICENSE
+++ b/LICENSE
@@ -742,6 +742,10 @@ Copyright (c) 2023 David Corbett
 
 -------------------------------------------------------------------
 
+Copyright (c) 2025 David Corbett
+
+-------------------------------------------------------------------
+
 Copyright (c) Microsoft Corporation.
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
@@ -1254,6 +1258,10 @@ https://scripts.sil.org/OFL
 
 -------------------------------------------------------------------
 
+Copyright 2022 The Noto Project Authors (https://github.com/notofonts/myanmar)
+
+-------------------------------------------------------------------
+
 Copyright 2022 The Noto Project Authors (https://github.com/notofonts/oriya)
 
 -------------------------------------------------------------------
diff --git a/METADATA b/METADATA
index 1146595e2..f8b7f9464 100644
--- a/METADATA
+++ b/METADATA
@@ -9,7 +9,7 @@ third_party {
     type: GIT
     value: "https://github.com/harfbuzz/harfbuzz"
   }
-  version: "10.1.0"
+  version: "10.2.0"
   license_type: RESTRICTED
   license_note: "would be NOTICE save for GPL in:\n"
   " m4/ax_code_coverage.m4\n"
@@ -17,8 +17,8 @@ third_party {
   " culp/ligatures font with CC-BY-NC-SA licensing. Google does not want to\n"
   " host CC-BY-NC* content.\n"
   last_upgrade_date {
-    year: 2024
-    month: 11
-    day: 6
+    year: 2025
+    month: 1
+    day: 14
   }
 }
diff --git a/NEWS b/NEWS
index a2b6ebd23..ce123f2a5 100644
--- a/NEWS
+++ b/NEWS
@@ -1,3 +1,32 @@
+Overview of changes leading to 10.2.0
+Saturday, January 11, 2025
+====================================
+- Consider Unicode Variation Selectors when subsetting “cmap” table.
+- Guard hb_cairo_glyphs_from_buffer() against malformed UTF-8 strings.
+- Fix incorrect “COLR” v1 glyph scaling in hb-cairo.
+- Use locale-independent parsing of double numbers is “hb-subset” command line
+  tool.
+- Fix incorrect zeroing of advance width of base glyphs in various “Courier New”
+  font versions due to incorrect “GDEF” glyph classes.
+- Fix handling of long language codes with “HB_LEAN” configuration.
+- Update OpenType language system registry.
+- Allow all Myanmar tone marks (including visarga) in any order
+- Don’t insert U+25CC DOTTED CIRCLE before superscript/subscript digits
+- Handle Garay script as right to left script.
+- New API for serializing font tables and potentially repacking them in optimal
+  way. This was a previously experimental-only API.
+- New API for converting font variation setting from and to strings.
+- Various build fixes
+- Various subsetter and instancer fixes.
+
+- New API:
++hb_subset_serialize_link_t
++hb_subset_serialize_object_t
++hb_subset_serialize_or_fail()
++hb_subset_axis_range_from_string()
++hb_subset_axis_range_to_string()
+
+
 Overview of changes leading to 10.1.0
 Tuesday, November 5, 2024
 ====================================
diff --git a/OWNERS b/OWNERS
index 8fac92c1e..1322c09f1 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 siyamed@google.com
 nona@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/docs/harfbuzz-docs.xml b/docs/harfbuzz-docs.xml
index 164b89299..f935cea69 100644
--- a/docs/harfbuzz-docs.xml
+++ b/docs/harfbuzz-docs.xml
@@ -120,6 +120,7 @@
       <index id="api-index-full"><title>API Index</title><xi:include href="xml/api-index-full.xml"><xi:fallback /></xi:include></index>
       <index id="deprecated-api-index"><title>Index of deprecated API</title><xi:include href="xml/api-index-deprecated.xml"><xi:fallback /></xi:include></index>
 
+      <index id="api-index-10-2-0"><title>Index of new symbols in 10.2.0</title><xi:include href="xml/api-index-10.2.0.xml"><xi:fallback /></xi:include></index>
       <index id="api-index-10-1-0"><title>Index of new symbols in 10.1.0</title><xi:include href="xml/api-index-10.1.0.xml"><xi:fallback /></xi:include></index>
       <index id="api-index-10-0-0"><title>Index of new symbols in 10.0.0</title><xi:include href="xml/api-index-10.0.0.xml"><xi:fallback /></xi:include></index>
       <index id="api-index-8-5-0"><title>Index of new symbols in 8.5.0</title><xi:include href="xml/api-index-8.5.0.xml"><xi:fallback /></xi:include></index>
diff --git a/docs/harfbuzz-sections.txt b/docs/harfbuzz-sections.txt
index 4a5c06cd6..0e75e6935 100644
--- a/docs/harfbuzz-sections.txt
+++ b/docs/harfbuzz-sections.txt
@@ -801,8 +801,10 @@ hb_set_t
 <FILE>hb-shape</FILE>
 hb_shape
 hb_shape_full
-hb_shape_justify
 hb_shape_list_shapers
+<SUBSECTION Private>
+hb_shape_justify
+</SUBSECTION>
 </SECTION>
 
 <SECTION>
@@ -900,6 +902,8 @@ hb_subset_input_pin_axis_location
 hb_subset_input_pin_axis_to_default
 hb_subset_input_get_axis_range
 hb_subset_input_set_axis_range
+hb_subset_axis_range_from_string
+hb_subset_axis_range_to_string
 hb_subset_or_fail
 hb_subset_plan_create_or_fail
 hb_subset_plan_reference
@@ -915,10 +919,10 @@ hb_subset_flags_t
 hb_subset_input_t
 hb_subset_sets_t
 hb_subset_plan_t
+hb_subset_serialize_link_t
+hb_subset_serialize_object_t
+hb_subset_serialize_or_fail
 <SUBSECTION Private>
-hb_link_t
-hb_object_t
-hb_subset_repack_or_fail
 hb_subset_input_override_name_table
 </SECTION>
 
diff --git a/meson.build b/meson.build
index 5a02b3bb2..f3e43b595 100644
--- a/meson.build
+++ b/meson.build
@@ -1,6 +1,6 @@
 project('harfbuzz', 'c', 'cpp',
   meson_version: '>= 0.55.0',
-  version: '10.1.0',
+  version: '10.2.0',
   default_options: [
     'cpp_eh=none',          # Just to support msvc, we are passing -fno-exceptions also anyway
     # 'cpp_rtti=false',     # Do NOT enable, wraps inherit it and ICU needs RTTI
diff --git a/src/OT/Color/COLR/COLR.hh b/src/OT/Color/COLR/COLR.hh
index 36b509d7c..d227768d5 100644
--- a/src/OT/Color/COLR/COLR.hh
+++ b/src/OT/Color/COLR/COLR.hh
@@ -1003,7 +1003,7 @@ struct PaintTransform
   void paint_glyph (hb_paint_context_t *c) const
   {
     TRACE_PAINT (this);
-    (this+transform).paint_glyph (c);
+    (this+transform).paint_glyph (c); // This does a push_transform()
     c->recurse (this+src);
     c->funcs->pop_transform (c->data);
   }
diff --git a/src/gen-def.py b/src/gen-def.py
index 6011817bc..bc5a40137 100755
--- a/src/gen-def.py
+++ b/src/gen-def.py
@@ -20,7 +20,6 @@ if '--experimental-api' not in sys.argv:
 	# Move these to harfbuzz-sections.txt when got stable
 	experimental_symbols = \
 """hb_shape_justify
-hb_subset_repack_or_fail
 hb_subset_input_override_name_table
 """.splitlines ()
 	symbols = [x for x in symbols if x not in experimental_symbols]
diff --git a/src/gen-indic-table.py b/src/gen-indic-table.py
index 2c8abcca6..31a321a56 100755
--- a/src/gen-indic-table.py
+++ b/src/gen-indic-table.py
@@ -102,6 +102,7 @@ categories = {
     'CM',
     'Symbol',
     'CS',
+    'SMPst',
   ],
   'khmer' : [
     'VAbv',
@@ -435,6 +436,8 @@ defaults = (category_map[defaults[0]], position_map[defaults[1]], defaults[2])
 indic_data = {}
 for k, (cat, pos, block) in combined.items():
   cat = category_map[cat]
+  if cat == 'SM' and pos == 'Not_Applicable':
+    cat = 'SMPst'
   pos = position_map[pos]
   indic_data[k] = (cat, pos, block)
 
@@ -454,7 +457,7 @@ for k, (cat, pos, block) in indic_data.items():
 # Keep in sync with CONSONANT_FLAGS in the shaper
 consonant_categories = ('C', 'CS', 'Ra','CM', 'V', 'PLACEHOLDER', 'DOTTEDCIRCLE')
 matra_categories = ('M', 'MPst')
-smvd_categories = ('SM', 'VD', 'A', 'Symbol')
+smvd_categories = ('SM', 'SMPst', 'VD', 'A', 'Symbol')
 for k, (cat, pos, block) in indic_data.items():
   if cat in consonant_categories:
     pos = 'BASE_C'
@@ -530,6 +533,7 @@ short = [{
 	"Repha":		'Rf',
 	"PLACEHOLDER":		'GB',
 	"DOTTEDCIRCLE":		'DC',
+	"SMPst":		'SP',
 	"VPst":			'VR',
 	"VPre":			'VL',
 	"Robatic":		'Rt',
diff --git a/src/harfbuzz-config.cmake.in b/src/harfbuzz-config.cmake.in
index 6abe2d62d..2d990efab 100644
--- a/src/harfbuzz-config.cmake.in
+++ b/src/harfbuzz-config.cmake.in
@@ -2,6 +2,8 @@
 
 set_and_check(HARFBUZZ_INCLUDE_DIR "@PACKAGE_INCLUDE_INSTALL_DIR@")
 
+set(HARFBUZZ_VERSION "@HARFBUZZ_VERSION@")
+
 # Add the libraries.
 add_library(harfbuzz::harfbuzz @HB_LIBRARY_TYPE@ IMPORTED)
 set_target_properties(harfbuzz::harfbuzz PROPERTIES
diff --git a/src/harfbuzz-subset.cc b/src/harfbuzz-subset.cc
index 05483b14c..a0accfb33 100644
--- a/src/harfbuzz-subset.cc
+++ b/src/harfbuzz-subset.cc
@@ -58,7 +58,7 @@
 #include "hb-subset-instancer-iup.cc"
 #include "hb-subset-instancer-solver.cc"
 #include "hb-subset-plan.cc"
-#include "hb-subset-repacker.cc"
+#include "hb-subset-serialize.cc"
 #include "hb-subset.cc"
 #include "hb-ucd.cc"
 #include "hb-unicode.cc"
diff --git a/src/hb-cairo.cc b/src/hb-cairo.cc
index d8b582c49..89332d715 100644
--- a/src/hb-cairo.cc
+++ b/src/hb-cairo.cc
@@ -180,7 +180,7 @@ hb_cairo_paint_color_glyph (hb_paint_funcs_t *pfuncs HB_UNUSED,
 
   hb_position_t x_scale, y_scale;
   hb_font_get_scale (font, &x_scale, &y_scale);
-  cairo_scale (cr, x_scale, y_scale);
+  cairo_scale (cr, x_scale, -y_scale);
 
   cairo_glyph_t cairo_glyph = { glyph, 0, 0 };
   cairo_set_scaled_font (cr, c->scaled_font);
@@ -597,7 +597,9 @@ hb_cairo_render_glyph (cairo_scaled_font_t  *scaled_font,
 
   hb_position_t x_scale, y_scale;
   hb_font_get_scale (font, &x_scale, &y_scale);
-  cairo_scale (cr, +1./x_scale, -1./y_scale);
+  cairo_scale (cr,
+	       +1. / (x_scale ? x_scale : 1),
+	       -1. / (y_scale ? y_scale : 1));
 
   hb_font_draw_glyph (font, glyph, hb_cairo_draw_get_funcs (), cr);
 
@@ -628,7 +630,9 @@ hb_cairo_render_color_glyph (cairo_scaled_font_t  *scaled_font,
   hb_color_t color = HB_COLOR (0, 0, 0, 255);
   hb_position_t x_scale, y_scale;
   hb_font_get_scale (font, &x_scale, &y_scale);
-  cairo_scale (cr, +1./x_scale, -1./y_scale);
+  cairo_scale (cr,
+	       +1. / (x_scale ? x_scale : 1),
+	       -1. / (y_scale ? y_scale : 1));
 
   hb_cairo_context_t c;
   c.scaled_font = scaled_font;
@@ -1000,6 +1004,7 @@ hb_cairo_glyphs_from_buffer (hb_buffer_t *buffer,
 	    end = start + hb_glyph[i].cluster - hb_glyph[i+1].cluster;
 	  else
 	    end = (const char *) hb_utf_offset_to_pointer<hb_utf8_t> ((const uint8_t *) start,
+								      (const uint8_t *) utf8, utf8_len,
 								      (signed) (hb_glyph[i].cluster - hb_glyph[i+1].cluster));
 	  (*clusters)[cluster].num_bytes = end - start;
 	  start = end;
@@ -1020,6 +1025,7 @@ hb_cairo_glyphs_from_buffer (hb_buffer_t *buffer,
 	    end = start + hb_glyph[i].cluster - hb_glyph[i-1].cluster;
 	  else
 	    end = (const char *) hb_utf_offset_to_pointer<hb_utf8_t> ((const uint8_t *) start,
+								      (const uint8_t *) utf8, utf8_len,
 								      (signed) (hb_glyph[i].cluster - hb_glyph[i-1].cluster));
 	  (*clusters)[cluster].num_bytes = end - start;
 	  start = end;
diff --git a/src/hb-common.cc b/src/hb-common.cc
index f3d6d12f7..ead5a8a04 100644
--- a/src/hb-common.cc
+++ b/src/hb-common.cc
@@ -626,6 +626,9 @@ hb_script_get_horizontal_direction (hb_script_t script)
     /* Unicode-14.0 additions */
     case HB_SCRIPT_OLD_UYGHUR:
 
+    /* Unicode-16.0 additions */
+    case HB_SCRIPT_GARAY:
+
       return HB_DIRECTION_RTL;
 
 
diff --git a/src/hb-config.hh b/src/hb-config.hh
index 14105846a..09f669567 100644
--- a/src/hb-config.hh
+++ b/src/hb-config.hh
@@ -68,8 +68,6 @@
 #define HB_NO_FACE_COLLECT_UNICODES
 #define HB_NO_GETENV
 #define HB_NO_HINTING
-#define HB_NO_LANGUAGE_LONG
-#define HB_NO_LANGUAGE_PRIVATE_SUBTAG
 #define HB_NO_LAYOUT_FEATURE_PARAMS
 #define HB_NO_LAYOUT_COLLECT_GLYPHS
 #define HB_NO_LAYOUT_RARELY_USED
diff --git a/src/hb-coretext-font.cc b/src/hb-coretext-font.cc
index e6a02cce6..92194ea0a 100644
--- a/src/hb-coretext-font.cc
+++ b/src/hb-coretext-font.cc
@@ -34,8 +34,12 @@
 #include "hb-font.hh"
 #include "hb-machinery.hh"
 
-#if MAC_OS_X_VERSION_MIN_REQUIRED < 101100
+#if (defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 1080) \
+    || (defined(__ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__) && __ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__ < 60000) \
+    || (defined(__ENVIRONMENT_TV_OS_VERSION_MIN_REQUIRED__) && __ENVIRONMENT_TV_OS_VERSION_MIN_REQUIRED__ < 90000)
 #  define kCTFontOrientationDefault kCTFontDefaultOrientation
+#  define kCTFontOrientationHorizontal kCTFontHorizontalOrientation
+#  define kCTFontOrientationVertical kCTFontVerticalOrientation
 #endif
 
 #define MAX_GLYPHS 64u
diff --git a/src/hb-face.cc b/src/hb-face.cc
index bc0f6d90d..c7dbf7966 100644
--- a/src/hb-face.cc
+++ b/src/hb-face.cc
@@ -470,7 +470,8 @@ hb_face_is_immutable (const hb_face_t *face)
  * @tag: The #hb_tag_t of the table to query
  *
  * Fetches a reference to the specified table within
- * the specified face.
+ * the specified face. Returns an empty blob if referencing table data is not
+ * possible.
  *
  * Return value: (transfer full): A pointer to the @tag table within @face
  *
diff --git a/src/hb-ft-colr.hh b/src/hb-ft-colr.hh
index 8766a2a2c..7d8ed4a6f 100644
--- a/src/hb-ft-colr.hh
+++ b/src/hb-ft-colr.hh
@@ -547,7 +547,9 @@ hb_ft_paint_glyph_colr (hb_font_t *font,
     c.funcs->push_root_transform (c.data, font);
 
     if (is_bounded)
+     {
       c.recurse (paint);
+     }
 
     c.funcs->pop_transform (c.data);
     c.funcs->pop_clip (c.data);
diff --git a/src/hb-ft.cc b/src/hb-ft.cc
index c305df19a..7e65277d1 100644
--- a/src/hb-ft.cc
+++ b/src/hb-ft.cc
@@ -931,11 +931,15 @@ hb_ft_paint_glyph (hb_font_t *font,
   hb_lock_t lock (ft_font->lock);
   FT_Face ft_face = ft_font->ft_face;
 
+  FT_Long load_flags = ft_font->load_flags | FT_LOAD_NO_BITMAP | FT_LOAD_COLOR;
+#if (FREETYPE_MAJOR*10000 + FREETYPE_MINOR*100 + FREETYPE_PATCH) >= 21301
+  load_flags |= FT_LOAD_NO_SVG;
+#endif
+
   /* We release the lock before calling into glyph callbacks, such that
    * eg. draw API can call back into the face.*/
 
-  if (unlikely (FT_Load_Glyph (ft_face, gid,
-			       ft_font->load_flags | FT_LOAD_COLOR)))
+  if (unlikely (FT_Load_Glyph (ft_face, gid, load_flags)))
     return;
 
   if (ft_face->glyph->format == FT_GLYPH_FORMAT_OUTLINE)
diff --git a/src/hb-null.hh b/src/hb-null.hh
index 854485d3d..3588f6ab2 100644
--- a/src/hb-null.hh
+++ b/src/hb-null.hh
@@ -176,7 +176,7 @@ template <typename Type>
 static inline Type& Crap () {
   static_assert (hb_null_size (Type) <= HB_NULL_POOL_SIZE, "Increase HB_NULL_POOL_SIZE.");
   Type *obj = reinterpret_cast<Type *> (_hb_CrapPool);
-  memcpy (obj, std::addressof (Null (Type)), sizeof (*obj));
+  memcpy (reinterpret_cast<void*>(obj), std::addressof (Null (Type)), sizeof (*obj));
   return *obj;
 }
 template <typename QType>
diff --git a/src/hb-ot-cmap-table.hh b/src/hb-ot-cmap-table.hh
index 0f1edce0b..7a7a77ad5 100644
--- a/src/hb-ot-cmap-table.hh
+++ b/src/hb-ot-cmap-table.hh
@@ -1397,6 +1397,9 @@ struct CmapSubtableFormat14
     hb_vector_t<hb_pair_t<unsigned, unsigned>> obj_indices;
     for (int i = src_tbl->record.len - 1; i >= 0; i--)
     {
+      if (!unicodes->has(src_tbl->record[i].varSelector))
+        continue;
+
       hb_pair_t<unsigned, unsigned> result = src_tbl->record[i].copy (c, unicodes, glyphs_requested, glyph_map, base);
       if (result.first || result.second)
 	obj_indices.push (result);
@@ -1453,6 +1456,7 @@ struct CmapSubtableFormat14
   {
     + hb_iter (record)
     | hb_filter (hb_bool, &VariationSelectorRecord::nonDefaultUVS)
+    | hb_filter (unicodes, &VariationSelectorRecord::varSelector)
     | hb_map (&VariationSelectorRecord::nonDefaultUVS)
     | hb_map (hb_add (this))
     | hb_apply ([=] (const NonDefaultUVS& _) { _.closure_glyphs (unicodes, glyphset); })
diff --git a/src/hb-ot-layout-gsubgpos.hh b/src/hb-ot-layout-gsubgpos.hh
index 2c9056c70..966fa06c1 100644
--- a/src/hb-ot-layout-gsubgpos.hh
+++ b/src/hb-ot-layout-gsubgpos.hh
@@ -1462,6 +1462,7 @@ static inline bool ligate_input (hb_ot_apply_context_t *c,
 	unsigned int this_comp = _hb_glyph_info_get_lig_comp (&buffer->cur());
 	if (this_comp == 0)
 	  this_comp = last_num_components;
+	assert (components_so_far >= last_num_components);
 	unsigned int new_lig_comp = components_so_far - last_num_components +
 				    hb_min (this_comp, last_num_components);
 	  _hb_glyph_info_set_lig_props_for_mark (&buffer->cur(), lig_id, new_lig_comp);
@@ -1487,6 +1488,7 @@ static inline bool ligate_input (hb_ot_apply_context_t *c,
       unsigned this_comp = _hb_glyph_info_get_lig_comp (&buffer->info[i]);
       if (!this_comp) break;
 
+      assert (components_so_far >= last_num_components);
       unsigned new_lig_comp = components_so_far - last_num_components +
 			      hb_min (this_comp, last_num_components);
       _hb_glyph_info_set_lig_props_for_mark (&buffer->info[i], lig_id, new_lig_comp);
@@ -1542,6 +1544,7 @@ static bool match_lookahead (hb_ot_apply_context_t *c,
   TRACE_APPLY (nullptr);
 
   hb_ot_apply_context_t::skipping_iterator_t &skippy_iter = c->iter_context;
+  assert (start_index >= 1);
   skippy_iter.reset (start_index - 1);
   skippy_iter.set_match_func (match_func, match_data);
   skippy_iter.set_glyph_data (lookahead);
@@ -1852,6 +1855,7 @@ static inline void apply_lookup (hb_ot_apply_context_t *c,
   if (match_positions != match_positions_input)
     hb_free (match_positions);
 
+  assert (end >= 0);
   (void) buffer->move_to (end);
 }
 
diff --git a/src/hb-ot-layout.cc b/src/hb-ot-layout.cc
index 66c2eb4d8..d26f094ba 100644
--- a/src/hb-ot-layout.cc
+++ b/src/hb-ot-layout.cc
@@ -246,6 +246,18 @@ OT::GDEF::is_blocklisted (hb_blob_t *blob,
     /* sha1sum: c26e41d567ed821bed997e937bc0c41435689e85  Padauk.ttf
      *  "Padauk Regular" "Version 2.5", see https://crbug.com/681813 */
     case HB_CODEPOINT_ENCODE3 (1004, 59092, 14836):
+    /* 88d2006ca084f04af2df1954ed714a8c71e8400f  Courier New.ttf from macOS 15 */
+    case HB_CODEPOINT_ENCODE3 (588, 5078, 14418):
+    /* 608e3ebb6dd1aee521cff08eb07d500a2c59df68  Courier New Bold.ttf from macOS 15 */
+    case HB_CODEPOINT_ENCODE3 (588, 5078, 14238):
+    /* d13221044ff054efd78f1cd8631b853c3ce85676  cour.ttf from Windows 10 */
+    case HB_CODEPOINT_ENCODE3 (894, 17162, 33960):
+    /* 68ed4a22d8067fcf1622ac6f6e2f4d3a2e3ec394  courbd.ttf from Windows 10 */
+    case HB_CODEPOINT_ENCODE3 (894, 17154, 34472):
+    /* 4cdb0259c96b7fd7c103821bb8f08f7cc6b211d7  cour.ttf from Windows 8.1 */
+    case HB_CODEPOINT_ENCODE3 (816, 7868, 17052):
+    /* 920483d8a8ed37f7f0afdabbe7f679aece7c75d8  courbd.ttf from Windows 8.1 */
+    case HB_CODEPOINT_ENCODE3 (816, 7868, 17138):
       return true;
   }
   return false;
diff --git a/src/hb-ot-os2-table.hh b/src/hb-ot-os2-table.hh
index 6c9140226..c00d22b24 100644
--- a/src/hb-ot-os2-table.hh
+++ b/src/hb-ot-os2-table.hh
@@ -284,8 +284,8 @@ struct OS2
         os2_prime->usWidthClass = width_class;
     }
 
-    os2_prime->usFirstCharIndex = hb_min (0xFFFFu, c->plan->unicodes.get_min ());
-    os2_prime->usLastCharIndex  = hb_min (0xFFFFu, c->plan->unicodes.get_max ());
+    os2_prime->usFirstCharIndex = hb_min (0xFFFFu, c->plan->os2_info.min_cmap_codepoint);
+    os2_prime->usLastCharIndex  = hb_min (0xFFFFu, c->plan->os2_info.max_cmap_codepoint);
 
     if (c->plan->flags & HB_SUBSET_FLAGS_NO_PRUNE_UNICODE_RANGES)
       return_trace (true);
diff --git a/src/hb-ot-shaper-indic-machine.hh b/src/hb-ot-shaper-indic-machine.hh
index 353e32d32..6ff65c30a 100644
--- a/src/hb-ot-shaper-indic-machine.hh
+++ b/src/hb-ot-shaper-indic-machine.hh
@@ -68,6 +68,7 @@ enum indic_syllable_type_t {
 #define indic_syllable_machine_ex_Ra 15u
 #define indic_syllable_machine_ex_Repha 14u
 #define indic_syllable_machine_ex_SM 8u
+#define indic_syllable_machine_ex_SMPst 57u
 #define indic_syllable_machine_ex_Symbol 17u
 #define indic_syllable_machine_ex_V 2u
 #define indic_syllable_machine_ex_VD 9u
@@ -76,251 +77,916 @@ enum indic_syllable_type_t {
 #define indic_syllable_machine_ex_ZWNJ 5u
 
 
-#line 80 "hb-ot-shaper-indic-machine.hh"
+#line 81 "hb-ot-shaper-indic-machine.hh"
 static const unsigned char _indic_syllable_machine_trans_keys[] = {
-	8u, 8u, 4u, 13u, 5u, 13u, 5u, 13u, 13u, 13u, 4u, 13u, 4u, 13u, 4u, 13u, 
-	8u, 8u, 5u, 13u, 5u, 13u, 13u, 13u, 4u, 13u, 4u, 13u, 4u, 13u, 4u, 13u, 
-	8u, 8u, 5u, 13u, 5u, 13u, 13u, 13u, 4u, 13u, 4u, 13u, 4u, 13u, 8u, 8u, 
-	5u, 13u, 5u, 13u, 13u, 13u, 4u, 13u, 4u, 13u, 5u, 13u, 8u, 8u, 1u, 18u, 
-	3u, 16u, 3u, 16u, 4u, 16u, 1u, 15u, 5u, 9u, 5u, 9u, 9u, 9u, 5u, 9u, 
-	1u, 15u, 1u, 15u, 1u, 15u, 3u, 13u, 4u, 13u, 5u, 13u, 5u, 13u, 4u, 13u, 
-	5u, 9u, 3u, 9u, 5u, 9u, 3u, 16u, 3u, 16u, 3u, 16u, 3u, 16u, 4u, 16u, 
-	1u, 15u, 3u, 16u, 3u, 16u, 4u, 16u, 1u, 15u, 5u, 9u, 9u, 9u, 5u, 9u, 
-	1u, 15u, 1u, 15u, 3u, 13u, 4u, 13u, 5u, 13u, 5u, 13u, 4u, 13u, 5u, 9u, 
-	5u, 9u, 3u, 9u, 5u, 9u, 3u, 16u, 3u, 16u, 4u, 13u, 3u, 16u, 3u, 16u, 
-	4u, 16u, 1u, 15u, 3u, 16u, 1u, 15u, 5u, 9u, 9u, 9u, 5u, 9u, 1u, 15u, 
-	1u, 15u, 3u, 13u, 4u, 13u, 5u, 13u, 5u, 13u, 3u, 16u, 4u, 13u, 5u, 9u, 
-	5u, 9u, 3u, 9u, 5u, 9u, 3u, 16u, 4u, 13u, 4u, 13u, 3u, 16u, 3u, 16u, 
-	4u, 16u, 1u, 15u, 3u, 16u, 1u, 15u, 5u, 9u, 9u, 9u, 5u, 9u, 1u, 15u, 
-	1u, 15u, 3u, 13u, 4u, 13u, 5u, 13u, 5u, 13u, 3u, 16u, 4u, 13u, 5u, 9u, 
-	5u, 9u, 3u, 9u, 5u, 9u, 1u, 16u, 3u, 16u, 1u, 16u, 4u, 13u, 5u, 13u, 
-	5u, 13u, 9u, 9u, 5u, 9u, 1u, 15u, 3u, 9u, 5u, 9u, 5u, 9u, 9u, 9u, 
+	8u, 57u, 4u, 57u, 5u, 57u, 5u, 57u, 13u, 13u, 4u, 57u, 4u, 57u, 4u, 57u, 
+	8u, 57u, 5u, 57u, 5u, 57u, 13u, 13u, 4u, 57u, 4u, 57u, 4u, 57u, 4u, 57u, 
+	8u, 57u, 5u, 57u, 5u, 57u, 13u, 13u, 4u, 57u, 4u, 57u, 4u, 57u, 8u, 57u, 
+	5u, 57u, 5u, 57u, 13u, 13u, 4u, 57u, 4u, 57u, 5u, 57u, 8u, 57u, 1u, 57u, 
+	3u, 57u, 3u, 57u, 4u, 57u, 1u, 57u, 5u, 57u, 5u, 57u, 9u, 9u, 5u, 9u, 
+	1u, 57u, 1u, 57u, 1u, 57u, 3u, 57u, 4u, 57u, 5u, 57u, 5u, 57u, 4u, 57u, 
+	5u, 57u, 3u, 57u, 5u, 57u, 3u, 57u, 3u, 57u, 3u, 57u, 3u, 57u, 4u, 57u, 
+	1u, 57u, 3u, 57u, 3u, 57u, 4u, 57u, 1u, 57u, 5u, 57u, 9u, 9u, 5u, 9u, 
+	1u, 57u, 1u, 57u, 3u, 57u, 4u, 57u, 5u, 57u, 5u, 57u, 4u, 57u, 5u, 57u, 
+	5u, 57u, 3u, 57u, 5u, 57u, 3u, 57u, 3u, 57u, 4u, 57u, 3u, 57u, 3u, 57u, 
+	4u, 57u, 1u, 57u, 3u, 57u, 1u, 57u, 5u, 57u, 9u, 9u, 5u, 9u, 1u, 57u, 
+	1u, 57u, 3u, 57u, 4u, 57u, 5u, 57u, 5u, 57u, 3u, 57u, 4u, 57u, 5u, 57u, 
+	5u, 57u, 3u, 57u, 5u, 57u, 3u, 57u, 4u, 57u, 4u, 57u, 3u, 57u, 3u, 57u, 
+	4u, 57u, 1u, 57u, 3u, 57u, 1u, 57u, 5u, 57u, 9u, 9u, 5u, 9u, 1u, 57u, 
+	1u, 57u, 3u, 57u, 4u, 57u, 5u, 57u, 5u, 57u, 3u, 57u, 4u, 57u, 5u, 57u, 
+	5u, 57u, 3u, 57u, 5u, 57u, 1u, 57u, 3u, 57u, 1u, 57u, 4u, 57u, 5u, 57u, 
+	5u, 57u, 9u, 9u, 5u, 9u, 1u, 57u, 3u, 57u, 5u, 57u, 5u, 57u, 9u, 9u, 
 	5u, 9u, 1u, 15u, 0
 };
 
 static const char _indic_syllable_machine_key_spans[] = {
-	1, 10, 9, 9, 1, 10, 10, 10, 
-	1, 9, 9, 1, 10, 10, 10, 10, 
-	1, 9, 9, 1, 10, 10, 10, 1, 
-	9, 9, 1, 10, 10, 9, 1, 18, 
-	14, 14, 13, 15, 5, 5, 1, 5, 
-	15, 15, 15, 11, 10, 9, 9, 10, 
-	5, 7, 5, 14, 14, 14, 14, 13, 
-	15, 14, 14, 13, 15, 5, 1, 5, 
-	15, 15, 11, 10, 9, 9, 10, 5, 
-	5, 7, 5, 14, 14, 10, 14, 14, 
-	13, 15, 14, 15, 5, 1, 5, 15, 
-	15, 11, 10, 9, 9, 14, 10, 5, 
-	5, 7, 5, 14, 10, 10, 14, 14, 
-	13, 15, 14, 15, 5, 1, 5, 15, 
-	15, 11, 10, 9, 9, 14, 10, 5, 
-	5, 7, 5, 16, 14, 16, 10, 9, 
-	9, 1, 5, 15, 7, 5, 5, 1, 
+	50, 54, 53, 53, 1, 54, 54, 54, 
+	50, 53, 53, 1, 54, 54, 54, 54, 
+	50, 53, 53, 1, 54, 54, 54, 50, 
+	53, 53, 1, 54, 54, 53, 50, 57, 
+	55, 55, 54, 57, 53, 53, 1, 5, 
+	57, 57, 57, 55, 54, 53, 53, 54, 
+	53, 55, 53, 55, 55, 55, 55, 54, 
+	57, 55, 55, 54, 57, 53, 1, 5, 
+	57, 57, 55, 54, 53, 53, 54, 53, 
+	53, 55, 53, 55, 55, 54, 55, 55, 
+	54, 57, 55, 57, 53, 1, 5, 57, 
+	57, 55, 54, 53, 53, 55, 54, 53, 
+	53, 55, 53, 55, 54, 54, 55, 55, 
+	54, 57, 55, 57, 53, 1, 5, 57, 
+	57, 55, 54, 53, 53, 55, 54, 53, 
+	53, 55, 53, 57, 55, 57, 54, 53, 
+	53, 1, 5, 57, 55, 53, 53, 1, 
 	5, 15
 };
 
 static const short _indic_syllable_machine_index_offsets[] = {
-	0, 2, 13, 23, 33, 35, 46, 57, 
-	68, 70, 80, 90, 92, 103, 114, 125, 
-	136, 138, 148, 158, 160, 171, 182, 193, 
-	195, 205, 215, 217, 228, 239, 249, 251, 
-	270, 285, 300, 314, 330, 336, 342, 344, 
-	350, 366, 382, 398, 410, 421, 431, 441, 
-	452, 458, 466, 472, 487, 502, 517, 532, 
-	546, 562, 577, 592, 606, 622, 628, 630, 
-	636, 652, 668, 680, 691, 701, 711, 722, 
-	728, 734, 742, 748, 763, 778, 789, 804, 
-	819, 833, 849, 864, 880, 886, 888, 894, 
-	910, 926, 938, 949, 959, 969, 984, 995, 
-	1001, 1007, 1015, 1021, 1036, 1047, 1058, 1073, 
-	1088, 1102, 1118, 1133, 1149, 1155, 1157, 1163, 
-	1179, 1195, 1207, 1218, 1228, 1238, 1253, 1264, 
-	1270, 1276, 1284, 1290, 1307, 1322, 1339, 1350, 
-	1360, 1370, 1372, 1378, 1394, 1402, 1408, 1414, 
-	1416, 1422
+	0, 51, 106, 160, 214, 216, 271, 326, 
+	381, 432, 486, 540, 542, 597, 652, 707, 
+	762, 813, 867, 921, 923, 978, 1033, 1088, 
+	1139, 1193, 1247, 1249, 1304, 1359, 1413, 1464, 
+	1522, 1578, 1634, 1689, 1747, 1801, 1855, 1857, 
+	1863, 1921, 1979, 2037, 2093, 2148, 2202, 2256, 
+	2311, 2365, 2421, 2475, 2531, 2587, 2643, 2699, 
+	2754, 2812, 2868, 2924, 2979, 3037, 3091, 3093, 
+	3099, 3157, 3215, 3271, 3326, 3380, 3434, 3489, 
+	3543, 3597, 3653, 3707, 3763, 3819, 3874, 3930, 
+	3986, 4041, 4099, 4155, 4213, 4267, 4269, 4275, 
+	4333, 4391, 4447, 4502, 4556, 4610, 4666, 4721, 
+	4775, 4829, 4885, 4939, 4995, 5050, 5105, 5161, 
+	5217, 5272, 5330, 5386, 5444, 5498, 5500, 5506, 
+	5564, 5622, 5678, 5733, 5787, 5841, 5897, 5952, 
+	6006, 6060, 6116, 6170, 6228, 6284, 6342, 6397, 
+	6451, 6505, 6507, 6513, 6571, 6627, 6681, 6735, 
+	6737, 6743
 };
 
 static const unsigned char _indic_syllable_machine_indicies[] = {
-	1, 0, 2, 3, 3, 4, 5, 0, 
-	0, 0, 0, 4, 0, 3, 3, 4, 
-	6, 0, 0, 0, 0, 4, 0, 3, 
-	3, 4, 5, 0, 0, 0, 0, 4, 
-	0, 4, 0, 7, 3, 3, 4, 5, 
-	0, 0, 0, 0, 4, 0, 2, 3, 
-	3, 4, 5, 0, 0, 0, 8, 4, 
-	0, 10, 11, 11, 12, 13, 9, 9, 
-	9, 9, 12, 9, 14, 9, 11, 11, 
-	12, 15, 9, 9, 9, 9, 12, 9, 
-	11, 11, 12, 13, 9, 9, 9, 9, 
-	12, 9, 12, 9, 16, 11, 11, 12, 
-	13, 9, 9, 9, 9, 12, 9, 10, 
-	11, 11, 12, 13, 9, 9, 9, 17, 
-	12, 9, 10, 11, 11, 12, 13, 9, 
-	9, 9, 18, 12, 9, 20, 21, 21, 
-	22, 23, 19, 19, 19, 24, 22, 19, 
-	25, 19, 21, 21, 22, 27, 26, 26, 
-	26, 26, 22, 26, 21, 21, 22, 23, 
-	19, 19, 19, 19, 22, 19, 22, 26, 
-	20, 21, 21, 22, 23, 19, 19, 19, 
-	19, 22, 19, 28, 21, 21, 22, 23, 
-	19, 19, 19, 19, 22, 19, 30, 31, 
-	31, 32, 33, 29, 29, 29, 34, 32, 
+	1, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 1, 0, 2, 3, 3, 4, 5, 
+	0, 0, 0, 0, 4, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	5, 0, 3, 3, 4, 6, 0, 0, 
+	0, 0, 4, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 6, 0, 
+	3, 3, 4, 5, 0, 0, 0, 0, 
+	4, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 5, 0, 4, 0, 
+	7, 3, 3, 4, 5, 0, 0, 0, 
+	0, 4, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 5, 0, 2, 
+	3, 3, 4, 5, 0, 0, 0, 8, 
+	4, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 5, 0, 10, 11, 
+	11, 12, 13, 9, 9, 9, 9, 12, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 13, 9, 14, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 14, 9, 
+	11, 11, 12, 15, 9, 9, 9, 9, 
+	12, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 15, 9, 11, 11, 
+	12, 13, 9, 9, 9, 9, 12, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 13, 9, 12, 9, 16, 11, 
+	11, 12, 13, 9, 9, 9, 9, 12, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 13, 9, 10, 11, 11, 
+	12, 13, 9, 9, 9, 17, 12, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 13, 9, 10, 11, 11, 12, 
+	13, 9, 9, 9, 18, 12, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 9, 9, 9, 9, 9, 9, 9, 
+	9, 13, 9, 20, 21, 21, 22, 23, 
+	19, 19, 19, 24, 22, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	23, 19, 25, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 25, 19, 21, 21, 22, 
+	27, 26, 26, 26, 26, 22, 26, 26, 
+	26, 26, 26, 26, 26, 26, 26, 26, 
+	26, 26, 26, 26, 26, 26, 26, 26, 
+	26, 26, 26, 26, 26, 26, 26, 26, 
+	26, 26, 26, 26, 26, 26, 26, 26, 
+	26, 26, 26, 26, 26, 26, 26, 26, 
+	26, 27, 26, 21, 21, 22, 23, 19, 
+	19, 19, 19, 22, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 23, 
+	19, 22, 26, 20, 21, 21, 22, 23, 
+	19, 19, 19, 19, 22, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	23, 19, 28, 21, 21, 22, 23, 19, 
+	19, 19, 19, 22, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 19, 
+	19, 19, 19, 19, 19, 19, 19, 23, 
+	19, 30, 31, 31, 32, 33, 29, 29, 
+	29, 34, 32, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 33, 29, 
+	35, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
 	29, 35, 29, 31, 31, 32, 36, 29, 
-	29, 29, 29, 32, 29, 31, 31, 32, 
-	33, 29, 29, 29, 29, 32, 29, 32, 
+	29, 29, 29, 32, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 36, 
+	29, 31, 31, 32, 33, 29, 29, 29, 
+	29, 32, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 33, 29, 32, 
 	29, 30, 31, 31, 32, 33, 29, 29, 
-	29, 29, 32, 29, 37, 31, 31, 32, 
-	33, 29, 29, 29, 29, 32, 29, 21, 
+	29, 29, 32, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 33, 29, 
+	37, 31, 31, 32, 33, 29, 29, 29, 
+	29, 32, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 29, 29, 29, 
+	29, 29, 29, 29, 29, 33, 29, 21, 
 	21, 22, 38, 0, 0, 0, 0, 22, 
-	0, 40, 39, 42, 43, 44, 45, 46, 
-	47, 22, 23, 48, 49, 49, 24, 22, 
-	50, 51, 52, 53, 54, 41, 56, 57, 
-	58, 59, 4, 5, 60, 55, 55, 8, 
-	4, 55, 55, 61, 55, 62, 57, 63, 
-	63, 4, 5, 60, 55, 55, 55, 4, 
-	55, 55, 61, 55, 57, 63, 63, 4, 
-	5, 60, 55, 55, 55, 4, 55, 55, 
-	61, 55, 42, 55, 55, 55, 64, 65, 
-	55, 1, 60, 55, 55, 55, 55, 55, 
-	42, 55, 66, 66, 55, 1, 60, 55, 
-	60, 55, 55, 67, 60, 55, 60, 55, 
-	60, 55, 55, 55, 60, 55, 42, 55, 
-	68, 55, 66, 66, 55, 1, 60, 55, 
-	55, 55, 55, 55, 42, 55, 42, 55, 
-	55, 55, 66, 66, 55, 1, 60, 55, 
-	55, 55, 55, 55, 42, 55, 42, 55, 
-	55, 55, 66, 65, 55, 1, 60, 55, 
-	55, 55, 55, 55, 42, 55, 69, 70, 
-	71, 71, 4, 5, 60, 55, 55, 55, 
-	4, 55, 70, 71, 71, 4, 5, 60, 
-	55, 55, 55, 4, 55, 71, 71, 4, 
-	5, 60, 55, 55, 55, 4, 55, 60, 
-	55, 55, 67, 60, 55, 55, 55, 4, 
-	55, 72, 73, 73, 4, 5, 60, 55, 
-	55, 55, 4, 55, 64, 74, 55, 1, 
-	60, 55, 64, 55, 66, 66, 55, 1, 
-	60, 55, 66, 74, 55, 1, 60, 55, 
-	56, 57, 63, 63, 4, 5, 60, 55, 
-	55, 55, 4, 55, 55, 61, 55, 56, 
-	57, 58, 63, 4, 5, 60, 55, 55, 
-	8, 4, 55, 55, 61, 55, 76, 77, 
-	78, 79, 12, 13, 80, 75, 75, 18, 
-	12, 75, 75, 81, 75, 82, 77, 83, 
-	79, 12, 13, 80, 75, 75, 75, 12, 
-	75, 75, 81, 75, 77, 83, 79, 12, 
-	13, 80, 75, 75, 75, 12, 75, 75, 
-	81, 75, 84, 75, 75, 75, 85, 86, 
-	75, 14, 80, 75, 75, 75, 75, 75, 
-	84, 75, 87, 77, 88, 89, 12, 13, 
-	80, 75, 75, 17, 12, 75, 75, 81, 
-	75, 90, 77, 83, 83, 12, 13, 80, 
-	75, 75, 75, 12, 75, 75, 81, 75, 
-	77, 83, 83, 12, 13, 80, 75, 75, 
-	75, 12, 75, 75, 81, 75, 84, 75, 
-	75, 75, 91, 86, 75, 14, 80, 75, 
-	75, 75, 75, 75, 84, 75, 80, 75, 
-	75, 92, 80, 75, 80, 75, 80, 75, 
-	75, 75, 80, 75, 84, 75, 93, 75, 
-	91, 91, 75, 14, 80, 75, 75, 75, 
-	75, 75, 84, 75, 84, 75, 75, 75, 
-	91, 91, 75, 14, 80, 75, 75, 75, 
-	75, 75, 84, 75, 94, 95, 96, 96, 
-	12, 13, 80, 75, 75, 75, 12, 75, 
-	95, 96, 96, 12, 13, 80, 75, 75, 
-	75, 12, 75, 96, 96, 12, 13, 80, 
-	75, 75, 75, 12, 75, 80, 75, 75, 
-	92, 80, 75, 75, 75, 12, 75, 97, 
-	98, 98, 12, 13, 80, 75, 75, 75, 
-	12, 75, 85, 99, 75, 14, 80, 75, 
-	91, 91, 75, 14, 80, 75, 85, 75, 
-	91, 91, 75, 14, 80, 75, 91, 99, 
-	75, 14, 80, 75, 87, 77, 83, 83, 
-	12, 13, 80, 75, 75, 75, 12, 75, 
-	75, 81, 75, 87, 77, 88, 83, 12, 
-	13, 80, 75, 75, 17, 12, 75, 75, 
-	81, 75, 10, 11, 11, 12, 13, 75, 
-	75, 75, 75, 12, 75, 76, 77, 83, 
-	79, 12, 13, 80, 75, 75, 75, 12, 
-	75, 75, 81, 75, 101, 45, 102, 102, 
-	22, 23, 48, 100, 100, 100, 22, 100, 
-	100, 52, 100, 45, 102, 102, 22, 23, 
-	48, 100, 100, 100, 22, 100, 100, 52, 
-	100, 103, 100, 100, 100, 104, 105, 100, 
-	25, 48, 100, 100, 100, 100, 100, 103, 
-	100, 44, 45, 106, 107, 22, 23, 48, 
-	100, 100, 24, 22, 100, 100, 52, 100, 
-	103, 100, 100, 100, 108, 105, 100, 25, 
-	48, 100, 100, 100, 100, 100, 103, 100, 
-	48, 100, 100, 109, 48, 100, 48, 100, 
-	48, 100, 100, 100, 48, 100, 103, 100, 
-	110, 100, 108, 108, 100, 25, 48, 100, 
-	100, 100, 100, 100, 103, 100, 103, 100, 
-	100, 100, 108, 108, 100, 25, 48, 100, 
-	100, 100, 100, 100, 103, 100, 111, 112, 
-	113, 113, 22, 23, 48, 100, 100, 100, 
-	22, 100, 112, 113, 113, 22, 23, 48, 
-	100, 100, 100, 22, 100, 113, 113, 22, 
-	23, 48, 100, 100, 100, 22, 100, 48, 
-	100, 100, 109, 48, 100, 100, 100, 22, 
-	100, 44, 45, 102, 102, 22, 23, 48, 
-	100, 100, 100, 22, 100, 100, 52, 100, 
-	114, 115, 115, 22, 23, 48, 100, 100, 
-	100, 22, 100, 104, 116, 100, 25, 48, 
-	100, 108, 108, 100, 25, 48, 100, 104, 
-	100, 108, 108, 100, 25, 48, 100, 108, 
-	116, 100, 25, 48, 100, 44, 45, 106, 
-	102, 22, 23, 48, 100, 100, 24, 22, 
-	100, 100, 52, 100, 20, 21, 21, 22, 
-	23, 117, 117, 117, 24, 22, 117, 20, 
-	21, 21, 22, 23, 117, 117, 117, 117, 
-	22, 117, 119, 120, 121, 122, 32, 33, 
-	123, 118, 118, 34, 32, 118, 118, 124, 
-	118, 125, 120, 122, 122, 32, 33, 123, 
-	118, 118, 118, 32, 118, 118, 124, 118, 
-	120, 122, 122, 32, 33, 123, 118, 118, 
-	118, 32, 118, 118, 124, 118, 126, 118, 
-	118, 118, 127, 128, 118, 35, 123, 118, 
-	118, 118, 118, 118, 126, 118, 119, 120, 
-	121, 49, 32, 33, 123, 118, 118, 34, 
-	32, 118, 118, 124, 118, 126, 118, 118, 
-	118, 129, 128, 118, 35, 123, 118, 118, 
-	118, 118, 118, 126, 118, 123, 118, 118, 
-	130, 123, 118, 123, 118, 123, 118, 118, 
-	118, 123, 118, 126, 118, 131, 118, 129, 
-	129, 118, 35, 123, 118, 118, 118, 118, 
-	118, 126, 118, 126, 118, 118, 118, 129, 
-	129, 118, 35, 123, 118, 118, 118, 118, 
-	118, 126, 118, 132, 133, 134, 134, 32, 
-	33, 123, 118, 118, 118, 32, 118, 133, 
-	134, 134, 32, 33, 123, 118, 118, 118, 
-	32, 118, 134, 134, 32, 33, 123, 118, 
-	118, 118, 32, 118, 123, 118, 118, 130, 
-	123, 118, 118, 118, 32, 118, 119, 120, 
-	122, 122, 32, 33, 123, 118, 118, 118, 
-	32, 118, 118, 124, 118, 135, 136, 136, 
-	32, 33, 123, 118, 118, 118, 32, 118, 
-	127, 137, 118, 35, 123, 118, 129, 129, 
-	118, 35, 123, 118, 127, 118, 129, 129, 
-	118, 35, 123, 118, 129, 137, 118, 35, 
-	123, 118, 42, 43, 44, 45, 106, 102, 
-	22, 23, 48, 49, 49, 24, 22, 100, 
-	42, 52, 100, 56, 138, 58, 59, 4, 
-	5, 60, 55, 55, 8, 4, 55, 55, 
-	61, 55, 42, 43, 44, 45, 139, 140, 
-	22, 141, 142, 55, 49, 24, 22, 55, 
-	42, 52, 55, 20, 143, 143, 22, 141, 
-	60, 55, 55, 24, 22, 55, 60, 55, 
-	55, 67, 60, 55, 55, 55, 22, 55, 
-	142, 55, 55, 144, 142, 55, 55, 55, 
-	22, 55, 142, 55, 142, 55, 55, 55, 
-	142, 55, 42, 55, 68, 20, 143, 143, 
-	22, 141, 60, 55, 55, 55, 22, 55, 
-	42, 55, 146, 145, 147, 147, 145, 40, 
-	148, 145, 147, 147, 145, 40, 148, 145, 
-	148, 145, 145, 149, 148, 145, 148, 145, 
-	148, 145, 145, 145, 148, 145, 42, 117, 
-	117, 117, 117, 117, 117, 117, 117, 49, 
-	117, 117, 117, 117, 42, 117, 0
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 38, 0, 40, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 40, 39, 
+	42, 43, 44, 45, 46, 47, 22, 23, 
+	48, 49, 49, 24, 22, 50, 51, 52, 
+	53, 54, 41, 41, 41, 41, 41, 41, 
+	41, 41, 41, 41, 41, 41, 41, 41, 
+	41, 41, 41, 41, 41, 41, 41, 41, 
+	41, 41, 41, 41, 41, 41, 41, 41, 
+	41, 41, 41, 41, 41, 41, 41, 41, 
+	55, 41, 57, 58, 59, 60, 4, 5, 
+	61, 56, 56, 8, 4, 56, 56, 62, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	5, 56, 63, 58, 64, 64, 4, 5, 
+	61, 56, 56, 56, 4, 56, 56, 62, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	5, 56, 58, 64, 64, 4, 5, 61, 
+	56, 56, 56, 4, 56, 56, 62, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 5, 
+	56, 42, 56, 56, 56, 65, 66, 56, 
+	1, 61, 56, 56, 56, 56, 56, 42, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 1, 56, 67, 67, 56, 1, 61, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 1, 
+	56, 61, 56, 56, 68, 61, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 68, 56, 61, 
+	56, 61, 56, 56, 56, 61, 56, 42, 
+	56, 69, 56, 67, 67, 56, 1, 61, 
+	56, 56, 56, 56, 56, 42, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 1, 
+	56, 42, 56, 56, 56, 67, 67, 56, 
+	1, 61, 56, 56, 56, 56, 56, 42, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 1, 56, 42, 56, 56, 56, 67, 
+	66, 56, 1, 61, 56, 56, 56, 56, 
+	56, 42, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 1, 56, 70, 71, 72, 
+	72, 4, 5, 61, 56, 56, 56, 4, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 5, 56, 71, 72, 72, 
+	4, 5, 61, 56, 56, 56, 4, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 5, 56, 72, 72, 4, 5, 
+	61, 56, 56, 56, 4, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	5, 56, 61, 56, 56, 68, 61, 56, 
+	56, 56, 4, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 68, 56, 
+	73, 74, 74, 4, 5, 61, 56, 56, 
+	56, 4, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 5, 56, 65, 
+	75, 56, 1, 61, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 1, 56, 65, 56, 67, 
+	67, 56, 1, 61, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 1, 56, 67, 75, 56, 
+	1, 61, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 1, 56, 57, 58, 64, 64, 4, 
+	5, 61, 56, 56, 56, 4, 56, 56, 
+	62, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 5, 56, 57, 58, 59, 64, 4, 
+	5, 61, 56, 56, 8, 4, 56, 56, 
+	62, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 5, 56, 77, 78, 79, 80, 12, 
+	13, 81, 76, 76, 18, 12, 76, 76, 
+	82, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 13, 76, 83, 78, 84, 80, 12, 
+	13, 81, 76, 76, 76, 12, 76, 76, 
+	82, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 13, 76, 78, 84, 80, 12, 13, 
+	81, 76, 76, 76, 12, 76, 76, 82, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	13, 76, 85, 76, 76, 76, 86, 87, 
+	76, 14, 81, 76, 76, 76, 76, 76, 
+	85, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 14, 76, 88, 78, 89, 90, 
+	12, 13, 81, 76, 76, 17, 12, 76, 
+	76, 82, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 13, 76, 91, 78, 84, 84, 
+	12, 13, 81, 76, 76, 76, 12, 76, 
+	76, 82, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 13, 76, 78, 84, 84, 12, 
+	13, 81, 76, 76, 76, 12, 76, 76, 
+	82, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 13, 76, 85, 76, 76, 76, 92, 
+	87, 76, 14, 81, 76, 76, 76, 76, 
+	76, 85, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 14, 76, 81, 76, 76, 
+	93, 81, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 93, 76, 81, 76, 81, 76, 76, 
+	76, 81, 76, 85, 76, 94, 76, 92, 
+	92, 76, 14, 81, 76, 76, 76, 76, 
+	76, 85, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 14, 76, 85, 76, 76, 
+	76, 92, 92, 76, 14, 81, 76, 76, 
+	76, 76, 76, 85, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 14, 76, 95, 
+	96, 97, 97, 12, 13, 81, 76, 76, 
+	76, 12, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 13, 76, 96, 
+	97, 97, 12, 13, 81, 76, 76, 76, 
+	12, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 13, 76, 97, 97, 
+	12, 13, 81, 76, 76, 76, 12, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 13, 76, 81, 76, 76, 93, 
+	81, 76, 76, 76, 12, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	93, 76, 98, 99, 99, 12, 13, 81, 
+	76, 76, 76, 12, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 13, 
+	76, 86, 100, 76, 14, 81, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 14, 76, 92, 
+	92, 76, 14, 81, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 14, 76, 86, 76, 92, 
+	92, 76, 14, 81, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 14, 76, 92, 100, 76, 
+	14, 81, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 14, 76, 88, 78, 84, 84, 12, 
+	13, 81, 76, 76, 76, 12, 76, 76, 
+	82, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 13, 76, 88, 78, 89, 84, 12, 
+	13, 81, 76, 76, 17, 12, 76, 76, 
+	82, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 13, 76, 10, 11, 11, 12, 13, 
+	76, 76, 76, 76, 12, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	13, 76, 77, 78, 84, 80, 12, 13, 
+	81, 76, 76, 76, 12, 76, 76, 82, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	76, 76, 76, 76, 76, 76, 76, 76, 
+	13, 76, 102, 45, 103, 103, 22, 23, 
+	48, 101, 101, 101, 22, 101, 101, 52, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	23, 101, 45, 103, 103, 22, 23, 48, 
+	101, 101, 101, 22, 101, 101, 52, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 23, 
+	101, 104, 101, 101, 101, 105, 106, 101, 
+	25, 48, 101, 101, 101, 101, 101, 104, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 25, 101, 44, 45, 107, 108, 22, 
+	23, 48, 101, 101, 24, 22, 101, 101, 
+	52, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 23, 101, 104, 101, 101, 101, 109, 
+	106, 101, 25, 48, 101, 101, 101, 101, 
+	101, 104, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 25, 101, 48, 101, 101, 
+	110, 48, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 110, 101, 48, 101, 48, 101, 101, 
+	101, 48, 101, 104, 101, 111, 101, 109, 
+	109, 101, 25, 48, 101, 101, 101, 101, 
+	101, 104, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 25, 101, 104, 101, 101, 
+	101, 109, 109, 101, 25, 48, 101, 101, 
+	101, 101, 101, 104, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 25, 101, 112, 
+	113, 114, 114, 22, 23, 48, 101, 101, 
+	101, 22, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 23, 101, 113, 
+	114, 114, 22, 23, 48, 101, 101, 101, 
+	22, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 23, 101, 114, 114, 
+	22, 23, 48, 101, 101, 101, 22, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 23, 101, 48, 26, 26, 110, 
+	48, 26, 26, 26, 22, 26, 26, 26, 
+	26, 26, 26, 26, 26, 26, 26, 26, 
+	26, 26, 26, 26, 26, 26, 26, 26, 
+	26, 26, 26, 26, 26, 26, 26, 26, 
+	26, 26, 26, 26, 26, 26, 26, 26, 
+	26, 26, 26, 26, 26, 26, 26, 26, 
+	110, 26, 44, 45, 103, 103, 22, 23, 
+	48, 101, 101, 101, 22, 101, 101, 52, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	23, 101, 115, 116, 116, 22, 23, 48, 
+	101, 101, 101, 22, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 23, 
+	101, 105, 117, 101, 25, 48, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 25, 101, 109, 
+	109, 101, 25, 48, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 25, 101, 105, 101, 109, 
+	109, 101, 25, 48, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 25, 101, 109, 117, 101, 
+	25, 48, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 25, 101, 44, 45, 107, 103, 22, 
+	23, 48, 101, 101, 24, 22, 101, 101, 
+	52, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 23, 101, 20, 21, 21, 22, 23, 
+	118, 118, 118, 24, 22, 118, 118, 118, 
+	118, 118, 118, 118, 118, 118, 118, 118, 
+	118, 118, 118, 118, 118, 118, 118, 118, 
+	118, 118, 118, 118, 118, 118, 118, 118, 
+	118, 118, 118, 118, 118, 118, 118, 118, 
+	118, 118, 118, 118, 118, 118, 118, 118, 
+	23, 118, 20, 21, 21, 22, 23, 118, 
+	118, 118, 118, 22, 118, 118, 118, 118, 
+	118, 118, 118, 118, 118, 118, 118, 118, 
+	118, 118, 118, 118, 118, 118, 118, 118, 
+	118, 118, 118, 118, 118, 118, 118, 118, 
+	118, 118, 118, 118, 118, 118, 118, 118, 
+	118, 118, 118, 118, 118, 118, 118, 23, 
+	118, 120, 121, 122, 123, 32, 33, 124, 
+	119, 119, 34, 32, 119, 119, 125, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 33, 
+	119, 126, 121, 123, 123, 32, 33, 124, 
+	119, 119, 119, 32, 119, 119, 125, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 33, 
+	119, 121, 123, 123, 32, 33, 124, 119, 
+	119, 119, 32, 119, 119, 125, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 33, 119, 
+	127, 119, 119, 119, 128, 129, 119, 35, 
+	124, 119, 119, 119, 119, 119, 127, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	35, 119, 120, 121, 122, 49, 32, 33, 
+	124, 119, 119, 34, 32, 119, 119, 125, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	33, 119, 127, 119, 119, 119, 130, 129, 
+	119, 35, 124, 119, 119, 119, 119, 119, 
+	127, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 35, 119, 124, 119, 119, 131, 
+	124, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	131, 119, 124, 119, 124, 119, 119, 119, 
+	124, 119, 127, 119, 132, 119, 130, 130, 
+	119, 35, 124, 119, 119, 119, 119, 119, 
+	127, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 35, 119, 127, 119, 119, 119, 
+	130, 130, 119, 35, 124, 119, 119, 119, 
+	119, 119, 127, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 35, 119, 133, 134, 
+	135, 135, 32, 33, 124, 119, 119, 119, 
+	32, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 33, 119, 134, 135, 
+	135, 32, 33, 124, 119, 119, 119, 32, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 33, 119, 135, 135, 32, 
+	33, 124, 119, 119, 119, 32, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 33, 119, 124, 119, 119, 131, 124, 
+	119, 119, 119, 32, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 131, 
+	119, 120, 121, 123, 123, 32, 33, 124, 
+	119, 119, 119, 32, 119, 119, 125, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 33, 
+	119, 136, 137, 137, 32, 33, 124, 119, 
+	119, 119, 32, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 33, 119, 
+	128, 138, 119, 35, 124, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 35, 119, 130, 130, 
+	119, 35, 124, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 35, 119, 128, 119, 130, 130, 
+	119, 35, 124, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 35, 119, 130, 138, 119, 35, 
+	124, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	119, 119, 119, 119, 119, 119, 119, 119, 
+	35, 119, 42, 43, 44, 45, 107, 103, 
+	22, 23, 48, 49, 49, 24, 22, 101, 
+	42, 52, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 101, 101, 101, 101, 101, 101, 
+	101, 101, 23, 101, 57, 139, 59, 60, 
+	4, 5, 61, 56, 56, 8, 4, 56, 
+	56, 62, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 5, 56, 42, 43, 44, 45, 
+	140, 141, 22, 142, 143, 56, 49, 24, 
+	22, 56, 42, 52, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 142, 56, 20, 144, 
+	144, 22, 142, 61, 56, 56, 24, 22, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 142, 56, 61, 56, 56, 
+	68, 61, 56, 56, 56, 22, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 68, 56, 143, 56, 56, 145, 143, 
+	56, 56, 56, 22, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 145, 
+	56, 143, 56, 143, 56, 56, 56, 143, 
+	56, 42, 56, 69, 20, 144, 144, 22, 
+	142, 61, 56, 56, 56, 22, 56, 42, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 56, 56, 56, 56, 56, 56, 56, 
+	56, 142, 56, 147, 146, 148, 148, 146, 
+	40, 149, 146, 146, 146, 146, 146, 146, 
+	146, 146, 146, 146, 146, 146, 146, 146, 
+	146, 146, 146, 146, 146, 146, 146, 146, 
+	146, 146, 146, 146, 146, 146, 146, 146, 
+	146, 146, 146, 146, 146, 146, 146, 146, 
+	146, 146, 146, 146, 146, 146, 146, 146, 
+	146, 40, 146, 148, 148, 146, 40, 149, 
+	146, 146, 146, 146, 146, 146, 146, 146, 
+	146, 146, 146, 146, 146, 146, 146, 146, 
+	146, 146, 146, 146, 146, 146, 146, 146, 
+	146, 146, 146, 146, 146, 146, 146, 146, 
+	146, 146, 146, 146, 146, 146, 146, 146, 
+	146, 146, 146, 146, 146, 146, 146, 40, 
+	146, 149, 146, 146, 150, 149, 146, 146, 
+	146, 146, 146, 146, 146, 146, 146, 146, 
+	146, 146, 146, 146, 146, 146, 146, 146, 
+	146, 146, 146, 146, 146, 146, 146, 146, 
+	146, 146, 146, 146, 146, 146, 146, 146, 
+	146, 146, 146, 146, 146, 146, 146, 146, 
+	146, 146, 146, 146, 146, 150, 146, 149, 
+	146, 149, 146, 146, 146, 149, 146, 42, 
+	118, 118, 118, 118, 118, 118, 118, 118, 
+	49, 118, 118, 118, 118, 42, 118, 0
 };
 
 static const unsigned char _indic_syllable_machine_trans_targs[] = {
@@ -330,41 +996,41 @@ static const unsigned char _indic_syllable_machine_trans_targs[] = {
 	93, 84, 31, 19, 98, 31, 107, 24, 
 	113, 116, 117, 108, 26, 122, 127, 31, 
 	134, 31, 32, 53, 79, 81, 100, 101, 
-	85, 102, 123, 124, 94, 132, 137, 31, 
-	33, 35, 6, 52, 38, 47, 34, 1, 
-	36, 40, 0, 39, 41, 44, 45, 3, 
-	48, 5, 49, 31, 54, 56, 14, 77, 
-	62, 70, 55, 7, 57, 72, 64, 58, 
-	13, 76, 59, 8, 63, 65, 67, 68, 
-	10, 71, 12, 73, 31, 80, 20, 82, 
-	96, 87, 15, 99, 16, 86, 88, 90, 
-	91, 18, 95, 21, 97, 31, 31, 103, 
-	105, 22, 27, 109, 118, 104, 106, 120, 
-	111, 23, 110, 112, 114, 115, 25, 119, 
-	28, 121, 125, 126, 131, 128, 129, 29, 
-	130, 31, 133, 30, 135, 136
+	85, 102, 123, 124, 94, 132, 137, 92, 
+	31, 33, 35, 6, 52, 38, 47, 34, 
+	1, 36, 40, 0, 39, 41, 44, 45, 
+	3, 48, 5, 49, 31, 54, 56, 14, 
+	77, 62, 70, 55, 7, 57, 72, 64, 
+	58, 13, 76, 59, 8, 63, 65, 67, 
+	68, 10, 71, 12, 73, 31, 80, 20, 
+	82, 96, 87, 15, 99, 16, 86, 88, 
+	90, 91, 18, 95, 21, 97, 31, 31, 
+	103, 105, 22, 27, 109, 118, 104, 106, 
+	120, 111, 23, 110, 112, 114, 115, 25, 
+	119, 28, 121, 125, 126, 131, 128, 129, 
+	29, 130, 31, 133, 30, 135, 136
 };
 
 static const char _indic_syllable_machine_trans_actions[] = {
 	1, 0, 2, 0, 2, 0, 0, 2, 
 	2, 3, 2, 0, 2, 0, 0, 0, 
-	2, 2, 2, 4, 2, 0, 5, 0, 
+	2, 2, 2, 4, 2, 0, 5, 5, 
 	5, 0, 6, 0, 2, 7, 2, 0, 
 	2, 0, 2, 0, 0, 2, 0, 8, 
 	0, 11, 2, 2, 5, 0, 12, 12, 
 	0, 2, 5, 2, 5, 2, 0, 13, 
-	2, 0, 0, 2, 0, 2, 2, 0, 
-	2, 2, 0, 0, 2, 2, 2, 0, 
-	0, 0, 2, 14, 2, 0, 0, 2, 
-	0, 2, 2, 0, 2, 2, 2, 2, 
+	14, 2, 0, 0, 2, 0, 2, 2, 
 	0, 2, 2, 0, 0, 2, 2, 2, 
-	0, 0, 0, 2, 15, 5, 0, 5, 
-	2, 2, 0, 5, 0, 0, 2, 5, 
-	5, 0, 0, 0, 2, 16, 17, 2, 
-	0, 0, 0, 0, 2, 2, 2, 2, 
-	2, 0, 0, 2, 2, 2, 0, 0, 
-	0, 2, 0, 18, 18, 0, 0, 0, 
-	0, 19, 2, 0, 0, 0
+	0, 0, 0, 2, 15, 2, 0, 0, 
+	2, 0, 2, 2, 0, 2, 2, 2, 
+	2, 0, 2, 2, 0, 0, 2, 2, 
+	2, 0, 0, 0, 2, 16, 5, 0, 
+	5, 2, 2, 0, 5, 0, 0, 2, 
+	5, 5, 0, 0, 0, 2, 17, 18, 
+	2, 0, 0, 0, 0, 2, 2, 2, 
+	2, 2, 0, 0, 2, 2, 2, 0, 
+	0, 0, 2, 0, 19, 19, 0, 0, 
+	0, 0, 20, 2, 0, 0, 0
 };
 
 static const char _indic_syllable_machine_to_state_actions[] = {
@@ -414,20 +1080,20 @@ static const short _indic_syllable_machine_eof_trans[] = {
 	10, 10, 10, 10, 10, 10, 10, 20, 
 	20, 27, 20, 27, 20, 20, 30, 30, 
 	30, 30, 30, 30, 30, 1, 40, 0, 
-	56, 56, 56, 56, 56, 56, 56, 56, 
-	56, 56, 56, 56, 56, 56, 56, 56, 
-	56, 56, 56, 56, 56, 76, 76, 76, 
-	76, 76, 76, 76, 76, 76, 76, 76, 
-	76, 76, 76, 76, 76, 76, 76, 76, 
-	76, 76, 76, 76, 76, 76, 76, 101, 
-	101, 101, 101, 101, 101, 101, 101, 101, 
-	101, 101, 101, 101, 101, 101, 101, 101, 
-	101, 101, 101, 101, 118, 118, 119, 119, 
-	119, 119, 119, 119, 119, 119, 119, 119, 
-	119, 119, 119, 119, 119, 119, 119, 119, 
-	119, 119, 119, 101, 56, 56, 56, 56, 
-	56, 56, 56, 56, 146, 146, 146, 146, 
-	146, 118
+	57, 57, 57, 57, 57, 57, 57, 57, 
+	57, 57, 57, 57, 57, 57, 57, 57, 
+	57, 57, 57, 57, 57, 77, 77, 77, 
+	77, 77, 77, 77, 77, 77, 77, 77, 
+	77, 77, 77, 77, 77, 77, 77, 77, 
+	77, 77, 77, 77, 77, 77, 77, 102, 
+	102, 102, 102, 102, 102, 102, 102, 102, 
+	102, 102, 102, 102, 27, 102, 102, 102, 
+	102, 102, 102, 102, 119, 119, 120, 120, 
+	120, 120, 120, 120, 120, 120, 120, 120, 
+	120, 120, 120, 120, 120, 120, 120, 120, 
+	120, 120, 120, 102, 57, 57, 57, 57, 
+	57, 57, 57, 57, 147, 147, 147, 147, 
+	147, 119
 };
 
 static const int indic_syllable_machine_start = 31;
@@ -441,7 +1107,7 @@ static const int indic_syllable_machine_en_main = 31;
 
 
 
-#line 118 "hb-ot-shaper-indic-machine.rl"
+#line 121 "hb-ot-shaper-indic-machine.rl"
 
 
 #define found_syllable(syllable_type) \
@@ -460,7 +1126,7 @@ find_syllables_indic (hb_buffer_t *buffer)
   int cs;
   hb_glyph_info_t *info = buffer->info;
   
-#line 464 "hb-ot-shaper-indic-machine.hh"
+#line 1130 "hb-ot-shaper-indic-machine.hh"
 	{
 	cs = indic_syllable_machine_start;
 	ts = 0;
@@ -468,7 +1134,7 @@ find_syllables_indic (hb_buffer_t *buffer)
 	act = 0;
 	}
 
-#line 138 "hb-ot-shaper-indic-machine.rl"
+#line 141 "hb-ot-shaper-indic-machine.rl"
 
 
   p = 0;
@@ -476,7 +1142,7 @@ find_syllables_indic (hb_buffer_t *buffer)
 
   unsigned int syllable_serial = 1;
   
-#line 480 "hb-ot-shaper-indic-machine.hh"
+#line 1146 "hb-ot-shaper-indic-machine.hh"
 	{
 	int _slen;
 	int _trans;
@@ -490,7 +1156,7 @@ _resume:
 #line 1 "NONE"
 	{ts = p;}
 	break;
-#line 494 "hb-ot-shaper-indic-machine.hh"
+#line 1160 "hb-ot-shaper-indic-machine.hh"
 	}
 
 	_keys = _indic_syllable_machine_trans_keys + (cs<<1);
@@ -513,51 +1179,51 @@ _eof_trans:
 	{te = p+1;}
 	break;
 	case 11:
-#line 114 "hb-ot-shaper-indic-machine.rl"
+#line 117 "hb-ot-shaper-indic-machine.rl"
 	{te = p+1;{ found_syllable (indic_non_indic_cluster); }}
 	break;
-	case 13:
-#line 109 "hb-ot-shaper-indic-machine.rl"
+	case 14:
+#line 111 "hb-ot-shaper-indic-machine.rl"
 	{te = p;p--;{ found_syllable (indic_consonant_syllable); }}
 	break;
-	case 14:
-#line 110 "hb-ot-shaper-indic-machine.rl"
+	case 15:
+#line 112 "hb-ot-shaper-indic-machine.rl"
 	{te = p;p--;{ found_syllable (indic_vowel_syllable); }}
 	break;
-	case 17:
-#line 111 "hb-ot-shaper-indic-machine.rl"
+	case 18:
+#line 113 "hb-ot-shaper-indic-machine.rl"
 	{te = p;p--;{ found_syllable (indic_standalone_cluster); }}
 	break;
-	case 19:
-#line 112 "hb-ot-shaper-indic-machine.rl"
+	case 20:
+#line 114 "hb-ot-shaper-indic-machine.rl"
 	{te = p;p--;{ found_syllable (indic_symbol_cluster); }}
 	break;
-	case 15:
-#line 113 "hb-ot-shaper-indic-machine.rl"
+	case 16:
+#line 116 "hb-ot-shaper-indic-machine.rl"
 	{te = p;p--;{ found_syllable (indic_broken_cluster); buffer->scratch_flags |= HB_BUFFER_SCRATCH_FLAG_HAS_BROKEN_SYLLABLE; }}
 	break;
-	case 16:
-#line 114 "hb-ot-shaper-indic-machine.rl"
+	case 17:
+#line 117 "hb-ot-shaper-indic-machine.rl"
 	{te = p;p--;{ found_syllable (indic_non_indic_cluster); }}
 	break;
 	case 1:
-#line 109 "hb-ot-shaper-indic-machine.rl"
+#line 111 "hb-ot-shaper-indic-machine.rl"
 	{{p = ((te))-1;}{ found_syllable (indic_consonant_syllable); }}
 	break;
 	case 3:
-#line 110 "hb-ot-shaper-indic-machine.rl"
+#line 112 "hb-ot-shaper-indic-machine.rl"
 	{{p = ((te))-1;}{ found_syllable (indic_vowel_syllable); }}
 	break;
 	case 7:
-#line 111 "hb-ot-shaper-indic-machine.rl"
+#line 113 "hb-ot-shaper-indic-machine.rl"
 	{{p = ((te))-1;}{ found_syllable (indic_standalone_cluster); }}
 	break;
 	case 8:
-#line 112 "hb-ot-shaper-indic-machine.rl"
+#line 114 "hb-ot-shaper-indic-machine.rl"
 	{{p = ((te))-1;}{ found_syllable (indic_symbol_cluster); }}
 	break;
 	case 4:
-#line 113 "hb-ot-shaper-indic-machine.rl"
+#line 116 "hb-ot-shaper-indic-machine.rl"
 	{{p = ((te))-1;}{ found_syllable (indic_broken_cluster); buffer->scratch_flags |= HB_BUFFER_SCRATCH_FLAG_HAS_BROKEN_SYLLABLE; }}
 	break;
 	case 6:
@@ -567,33 +1233,42 @@ _eof_trans:
 	{{p = ((te))-1;} found_syllable (indic_consonant_syllable); }
 	break;
 	case 5:
-	{{p = ((te))-1;} found_syllable (indic_broken_cluster); buffer->scratch_flags |= HB_BUFFER_SCRATCH_FLAG_HAS_BROKEN_SYLLABLE; }
+	{{p = ((te))-1;} found_syllable (indic_non_indic_cluster); }
 	break;
 	case 6:
+	{{p = ((te))-1;} found_syllable (indic_broken_cluster); buffer->scratch_flags |= HB_BUFFER_SCRATCH_FLAG_HAS_BROKEN_SYLLABLE; }
+	break;
+	case 7:
 	{{p = ((te))-1;} found_syllable (indic_non_indic_cluster); }
 	break;
 	}
 	}
 	break;
-	case 18:
+	case 19:
 #line 1 "NONE"
 	{te = p+1;}
-#line 109 "hb-ot-shaper-indic-machine.rl"
+#line 111 "hb-ot-shaper-indic-machine.rl"
 	{act = 1;}
 	break;
-	case 5:
+	case 13:
 #line 1 "NONE"
 	{te = p+1;}
-#line 113 "hb-ot-shaper-indic-machine.rl"
+#line 115 "hb-ot-shaper-indic-machine.rl"
 	{act = 5;}
 	break;
-	case 12:
+	case 5:
 #line 1 "NONE"
 	{te = p+1;}
-#line 114 "hb-ot-shaper-indic-machine.rl"
+#line 116 "hb-ot-shaper-indic-machine.rl"
 	{act = 6;}
 	break;
-#line 597 "hb-ot-shaper-indic-machine.hh"
+	case 12:
+#line 1 "NONE"
+	{te = p+1;}
+#line 117 "hb-ot-shaper-indic-machine.rl"
+	{act = 7;}
+	break;
+#line 1272 "hb-ot-shaper-indic-machine.hh"
 	}
 
 _again:
@@ -602,7 +1277,7 @@ _again:
 #line 1 "NONE"
 	{ts = 0;}
 	break;
-#line 606 "hb-ot-shaper-indic-machine.hh"
+#line 1281 "hb-ot-shaper-indic-machine.hh"
 	}
 
 	if ( ++p != pe )
@@ -618,7 +1293,7 @@ _again:
 
 	}
 
-#line 146 "hb-ot-shaper-indic-machine.rl"
+#line 149 "hb-ot-shaper-indic-machine.rl"
 
 }
 
diff --git a/src/hb-ot-shaper-indic-machine.rl b/src/hb-ot-shaper-indic-machine.rl
index f568a8462..138b35f04 100644
--- a/src/hb-ot-shaper-indic-machine.rl
+++ b/src/hb-ot-shaper-indic-machine.rl
@@ -80,17 +80,19 @@ export Ra    = 15;
 export CM    = 16;
 export Symbol= 17;
 export CS    = 18;
+export SMPst = 57;
 
 
 c = (C | Ra);			# is_consonant
 n = ((ZWNJ?.RS)? (N.N?)?);	# is_consonant_modifier
 z = ZWJ|ZWNJ;			# is_joiner
 reph = (Ra H | Repha);		# possible reph
+sm = SM | SMPst;
 
 cn = c.ZWJ?.n?;
 symbol = Symbol.N?;
-matra_group = z*.(M | SM? MPst).N?.H?;
-syllable_tail = (z?.SM.SM?.ZWNJ?)? (A | VD)*;
+matra_group = z*.(M | sm? MPst).N?.H?;
+syllable_tail = (z?.sm.sm?.ZWNJ?)? (A | VD)*;
 halant_group = (z?.H.(ZWJ.N?)?);
 final_halant_group = halant_group | H.ZWNJ;
 medial_group = CM?;
@@ -110,6 +112,7 @@ main := |*
 	vowel_syllable		=> { found_syllable (indic_vowel_syllable); };
 	standalone_cluster	=> { found_syllable (indic_standalone_cluster); };
 	symbol_cluster		=> { found_syllable (indic_symbol_cluster); };
+	SMPst			=> { found_syllable (indic_non_indic_cluster); };
 	broken_cluster		=> { found_syllable (indic_broken_cluster); buffer->scratch_flags |= HB_BUFFER_SCRATCH_FLAG_HAS_BROKEN_SYLLABLE; };
 	other			=> { found_syllable (indic_non_indic_cluster); };
 *|;
diff --git a/src/hb-ot-shaper-indic-table.cc b/src/hb-ot-shaper-indic-table.cc
index adea32efd..b87c53085 100644
--- a/src/hb-ot-shaper-indic-table.cc
+++ b/src/hb-ot-shaper-indic-table.cc
@@ -48,6 +48,7 @@
 #define OT_CM I_Cat(CM)
 #define OT_Symbol I_Cat(Symbol)
 #define OT_CS I_Cat(CS)
+#define OT_SMPst I_Cat(SMPst)
 /* khmer */
 #define OT_VAbv K_Cat(VAbv)
 #define OT_VBlw K_Cat(VBlw)
@@ -94,7 +95,8 @@ static_assert (OT_VPst == M_Cat(VPst), "");
 #define _OT_R    OT_Ra           /*  14 chars; Ra */
 #define _OT_Rf   OT_Repha        /*   1 chars; Repha */
 #define _OT_Rt   OT_Robatic      /*   3 chars; Robatic */
-#define _OT_SM   OT_SM           /*  56 chars; SM */
+#define _OT_SM   OT_SM           /*  50 chars; SM */
+#define _OT_SP   OT_SMPst        /*   6 chars; SMPst */
 #define _OT_S    OT_Symbol       /*  22 chars; Symbol */
 #define _OT_V    OT_V            /* 172 chars; V */
 #define _OT_VA   OT_VAbv         /*  18 chars; VAbv */
@@ -145,7 +147,7 @@ static const uint16_t indic_table[] = {
 
   /* Latin-1 Supplement */
 
-  /* 00B0 */  _(X,X),  _(X,X),_(SM,SM),_(SM,SM),  _(X,X),  _(X,X),  _(X,X),  _(X,X),
+  /* 00B0 */  _(X,X),  _(X,X),_(SP,SM),_(SP,SM),  _(X,X),  _(X,X),  _(X,X),  _(X,X),
   /* 00B8 */  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),
   /* 00C0 */  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),
   /* 00C8 */  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),
@@ -398,9 +400,9 @@ static const uint16_t indic_table[] = {
 
   /* Superscripts and Subscripts */
 
-  /* 2070 */  _(X,X),  _(X,X),  _(X,X),  _(X,X),_(SM,SM),  _(X,X),  _(X,X),  _(X,X),
+  /* 2070 */  _(X,X),  _(X,X),  _(X,X),  _(X,X),_(SP,SM),  _(X,X),  _(X,X),  _(X,X),
   /* 2078 */  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),  _(X,X),
-  /* 2080 */  _(X,X),  _(X,X),_(SM,SM),_(SM,SM),_(SM,SM),  _(X,X),  _(X,X),  _(X,X),
+  /* 2080 */  _(X,X),  _(X,X),_(SP,SM),_(SP,SM),_(SP,SM),  _(X,X),  _(X,X),  _(X,X),
 
 #define indic_offset_0x25f8u 1592
 
@@ -540,6 +542,7 @@ hb_indic_get_categories (hb_codepoint_t u)
 #undef _OT_Rf
 #undef _OT_Rt
 #undef _OT_SM
+#undef _OT_SP
 #undef _OT_S
 #undef _OT_V
 #undef _OT_VA
diff --git a/src/hb-ot-shaper-myanmar-machine.hh b/src/hb-ot-shaper-myanmar-machine.hh
index f7b456b11..4b8da586d 100644
--- a/src/hb-ot-shaper-myanmar-machine.hh
+++ b/src/hb-ot-shaper-myanmar-machine.hh
@@ -68,6 +68,7 @@ enum myanmar_syllable_type_t {
 #define myanmar_syllable_machine_ex_PT 39u
 #define myanmar_syllable_machine_ex_Ra 15u
 #define myanmar_syllable_machine_ex_SM 8u
+#define myanmar_syllable_machine_ex_SMPst 57u
 #define myanmar_syllable_machine_ex_VAbv 20u
 #define myanmar_syllable_machine_ex_VBlw 21u
 #define myanmar_syllable_machine_ex_VPre 22u
@@ -77,35 +78,35 @@ enum myanmar_syllable_type_t {
 #define myanmar_syllable_machine_ex_ZWNJ 5u
 
 
-#line 81 "hb-ot-shaper-myanmar-machine.hh"
+#line 82 "hb-ot-shaper-myanmar-machine.hh"
 static const unsigned char _myanmar_syllable_machine_trans_keys[] = {
-	1u, 41u, 3u, 41u, 5u, 39u, 5u, 8u, 3u, 41u, 3u, 39u, 3u, 39u, 5u, 39u, 
-	5u, 39u, 3u, 39u, 3u, 39u, 3u, 41u, 5u, 39u, 1u, 15u, 3u, 39u, 3u, 39u, 
-	3u, 40u, 3u, 39u, 3u, 41u, 3u, 41u, 3u, 39u, 3u, 41u, 3u, 41u, 3u, 41u, 
-	3u, 41u, 3u, 41u, 5u, 39u, 5u, 8u, 3u, 41u, 3u, 39u, 3u, 39u, 5u, 39u, 
-	5u, 39u, 3u, 39u, 3u, 39u, 3u, 41u, 5u, 39u, 1u, 15u, 3u, 41u, 3u, 39u, 
-	3u, 39u, 3u, 40u, 3u, 39u, 3u, 41u, 3u, 41u, 3u, 39u, 3u, 41u, 3u, 41u, 
-	3u, 41u, 3u, 41u, 3u, 41u, 3u, 41u, 3u, 41u, 1u, 41u, 1u, 15u, 0
+	1u, 57u, 3u, 57u, 5u, 57u, 5u, 57u, 3u, 57u, 5u, 57u, 3u, 57u, 3u, 57u, 
+	3u, 57u, 3u, 57u, 3u, 57u, 5u, 57u, 1u, 15u, 3u, 57u, 3u, 57u, 3u, 57u, 
+	3u, 57u, 3u, 57u, 3u, 57u, 3u, 57u, 3u, 57u, 3u, 57u, 3u, 57u, 3u, 57u, 
+	3u, 57u, 5u, 57u, 5u, 57u, 3u, 57u, 5u, 57u, 3u, 57u, 3u, 57u, 3u, 57u, 
+	3u, 57u, 3u, 57u, 5u, 57u, 1u, 15u, 3u, 57u, 3u, 57u, 3u, 57u, 3u, 57u, 
+	3u, 57u, 3u, 57u, 3u, 57u, 3u, 57u, 3u, 57u, 3u, 57u, 3u, 57u, 3u, 57u, 
+	3u, 57u, 3u, 57u, 3u, 57u, 1u, 57u, 1u, 15u, 0
 };
 
 static const char _myanmar_syllable_machine_key_spans[] = {
-	41, 39, 35, 4, 39, 37, 37, 35, 
-	35, 37, 37, 39, 35, 15, 37, 37, 
-	38, 37, 39, 39, 37, 39, 39, 39, 
-	39, 39, 35, 4, 39, 37, 37, 35, 
-	35, 37, 37, 39, 35, 15, 39, 37, 
-	37, 38, 37, 39, 39, 37, 39, 39, 
-	39, 39, 39, 39, 39, 41, 15
+	57, 55, 53, 53, 55, 53, 55, 55, 
+	55, 55, 55, 53, 15, 55, 55, 55, 
+	55, 55, 55, 55, 55, 55, 55, 55, 
+	55, 53, 53, 55, 53, 55, 55, 55, 
+	55, 55, 53, 15, 55, 55, 55, 55, 
+	55, 55, 55, 55, 55, 55, 55, 55, 
+	55, 55, 55, 57, 15
 };
 
 static const short _myanmar_syllable_machine_index_offsets[] = {
-	0, 42, 82, 118, 123, 163, 201, 239, 
-	275, 311, 349, 387, 427, 463, 479, 517, 
-	555, 594, 632, 672, 712, 750, 790, 830, 
-	870, 910, 950, 986, 991, 1031, 1069, 1107, 
-	1143, 1179, 1217, 1255, 1295, 1331, 1347, 1387, 
-	1425, 1463, 1502, 1540, 1580, 1620, 1658, 1698, 
-	1738, 1778, 1818, 1858, 1898, 1938, 1980
+	0, 58, 114, 168, 222, 278, 332, 388, 
+	444, 500, 556, 612, 666, 682, 738, 794, 
+	850, 906, 962, 1018, 1074, 1130, 1186, 1242, 
+	1298, 1354, 1408, 1462, 1518, 1572, 1628, 1684, 
+	1740, 1796, 1852, 1906, 1922, 1978, 2034, 2090, 
+	2146, 2202, 2258, 2314, 2370, 2426, 2482, 2538, 
+	2594, 2650, 2706, 2762, 2820
 };
 
 static const char _myanmar_syllable_machine_indicies[] = {
@@ -114,273 +115,378 @@ static const char _myanmar_syllable_machine_indicies[] = {
 	0, 8, 0, 9, 10, 11, 12, 0, 
 	0, 0, 0, 0, 0, 0, 0, 13, 
 	0, 0, 14, 15, 16, 17, 18, 19, 
-	20, 0, 22, 23, 24, 24, 21, 25, 
-	26, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 27, 28, 29, 30, 21, 
-	21, 21, 21, 21, 21, 21, 21, 31, 
-	21, 21, 32, 33, 34, 35, 36, 37, 
-	38, 21, 24, 24, 21, 25, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 30, 21, 21, 21, 
-	21, 21, 21, 21, 21, 39, 21, 21, 
-	21, 21, 21, 21, 36, 21, 24, 24, 
-	21, 25, 21, 22, 21, 24, 24, 21, 
-	25, 26, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 40, 21, 21, 30, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	41, 21, 21, 42, 21, 21, 21, 36, 
-	21, 41, 21, 22, 21, 24, 24, 21, 
-	25, 26, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 30, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 36, 
-	21, 43, 21, 24, 24, 21, 25, 36, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 44, 21, 
-	21, 21, 21, 21, 21, 36, 21, 24, 
-	24, 21, 25, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 44, 21, 21, 21, 21, 21, 
-	21, 36, 21, 24, 24, 21, 25, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 36, 21, 22, 
-	21, 24, 24, 21, 25, 26, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	40, 21, 21, 30, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 36, 21, 22, 21, 24, 
-	24, 21, 25, 26, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 40, 21, 
-	21, 30, 21, 21, 21, 21, 21, 21, 
-	21, 21, 41, 21, 21, 21, 21, 21, 
-	21, 36, 21, 22, 21, 24, 24, 21, 
-	25, 26, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 40, 21, 21, 30, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	41, 21, 21, 21, 21, 21, 21, 36, 
-	21, 41, 21, 24, 24, 21, 25, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 30, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 36, 21, 1, 
-	1, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 1, 21, 22, 
-	21, 24, 24, 21, 25, 26, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	27, 28, 21, 30, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 36, 21, 22, 21, 24, 
-	24, 21, 25, 26, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 28, 
-	21, 30, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 36, 21, 22, 21, 24, 24, 21, 
-	25, 26, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 27, 28, 29, 30, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 36, 
-	45, 21, 22, 21, 24, 24, 21, 25, 
-	26, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 27, 28, 29, 30, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 36, 21, 
-	22, 21, 24, 24, 21, 25, 26, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 27, 28, 29, 30, 21, 21, 21, 
-	21, 21, 21, 21, 21, 31, 21, 21, 
-	32, 33, 34, 35, 36, 21, 38, 21, 
-	22, 21, 24, 24, 21, 25, 26, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 27, 28, 29, 30, 21, 21, 21, 
-	21, 21, 21, 21, 21, 45, 21, 21, 
-	21, 21, 21, 21, 36, 21, 38, 21, 
-	22, 21, 24, 24, 21, 25, 26, 21, 
-	21, 21, 21, 21, 21, 21, 21, 21, 
-	21, 27, 28, 29, 30, 21, 21, 21, 
-	21, 21, 21, 21, 21, 45, 21, 21, 
-	21, 21, 21, 21, 36, 21, 22, 21, 
-	24, 24, 21, 25, 26, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 27, 
-	28, 29, 30, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 32, 21, 
-	34, 21, 36, 21, 38, 21, 22, 21, 
-	24, 24, 21, 25, 26, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 27, 
-	28, 29, 30, 21, 21, 21, 21, 21, 
-	21, 21, 21, 45, 21, 21, 32, 21, 
-	21, 21, 36, 21, 38, 21, 22, 21, 
-	24, 24, 21, 25, 26, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 27, 
-	28, 29, 30, 21, 21, 21, 21, 21, 
-	21, 21, 21, 46, 21, 21, 32, 33, 
-	34, 21, 36, 21, 38, 21, 22, 21, 
-	24, 24, 21, 25, 26, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 27, 
-	28, 29, 30, 21, 21, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 32, 33, 
-	34, 21, 36, 21, 38, 21, 22, 23, 
-	24, 24, 21, 25, 26, 21, 21, 21, 
-	21, 21, 21, 21, 21, 21, 21, 27, 
-	28, 29, 30, 21, 21, 21, 21, 21, 
-	21, 21, 21, 31, 21, 21, 32, 33, 
-	34, 35, 36, 21, 38, 21, 48, 48, 
+	20, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	21, 0, 23, 24, 25, 25, 22, 26, 
+	27, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 28, 29, 30, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 32, 
+	22, 22, 33, 34, 35, 36, 37, 38, 
+	39, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 25, 25, 22, 26, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 31, 22, 22, 22, 
+	22, 22, 22, 22, 22, 40, 22, 22, 
+	22, 22, 22, 22, 37, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 26, 22, 
+	25, 25, 22, 26, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 37, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 26, 22, 41, 22, 
+	25, 25, 22, 26, 37, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 26, 22, 22, 22, 22, 
+	22, 22, 37, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 26, 22, 25, 25, 
+	22, 26, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 26, 22, 22, 22, 22, 22, 22, 
+	37, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 26, 22, 23, 22, 25, 25, 
+	22, 26, 27, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 42, 22, 22, 
+	31, 22, 22, 22, 22, 22, 22, 22, 
+	22, 43, 22, 22, 44, 22, 22, 22, 
+	37, 22, 43, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 26, 22, 23, 22, 25, 25, 
+	22, 26, 27, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	31, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	37, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 26, 22, 23, 22, 25, 25, 
+	22, 26, 27, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 42, 22, 22, 
+	31, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	37, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 26, 22, 23, 22, 25, 25, 
+	22, 26, 27, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 42, 22, 22, 
+	31, 22, 22, 22, 22, 22, 22, 22, 
+	22, 43, 22, 22, 22, 22, 22, 22, 
+	37, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 26, 22, 23, 22, 25, 25, 
+	22, 26, 27, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 42, 22, 22, 
+	31, 22, 22, 22, 22, 22, 22, 22, 
+	22, 43, 22, 22, 22, 22, 22, 22, 
+	37, 22, 43, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 26, 22, 25, 25, 22, 26, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 37, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 1, 1, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	1, 22, 23, 22, 25, 25, 22, 26, 
+	27, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 28, 29, 22, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 37, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 23, 22, 25, 25, 22, 26, 
+	27, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 29, 22, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 37, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 23, 22, 25, 25, 22, 26, 
+	27, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 28, 29, 30, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 37, 45, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 23, 22, 25, 25, 22, 26, 
+	27, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 28, 29, 30, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 37, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 23, 22, 25, 25, 22, 26, 
+	27, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 28, 29, 30, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 32, 
+	22, 22, 33, 34, 35, 36, 37, 22, 
+	39, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 23, 22, 25, 25, 22, 26, 
+	27, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 28, 29, 30, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 45, 
+	22, 22, 22, 22, 22, 22, 37, 22, 
+	39, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 23, 22, 25, 25, 22, 26, 
+	27, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 28, 29, 30, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 45, 
+	22, 22, 22, 22, 22, 22, 37, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 23, 22, 25, 25, 22, 26, 
+	27, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 28, 29, 30, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 33, 22, 35, 22, 37, 22, 
+	39, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 23, 22, 25, 25, 22, 26, 
+	27, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 28, 29, 30, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 45, 
+	22, 22, 33, 22, 22, 22, 37, 22, 
+	39, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 23, 22, 25, 25, 22, 26, 
+	27, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 28, 29, 30, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 46, 
+	22, 22, 33, 34, 35, 22, 37, 22, 
+	39, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 23, 22, 25, 25, 22, 26, 
+	27, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 28, 29, 30, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 33, 34, 35, 22, 37, 22, 
+	39, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 23, 24, 25, 25, 22, 26, 
+	27, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 28, 29, 30, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 32, 
+	22, 22, 33, 34, 35, 36, 37, 22, 
+	39, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 48, 48, 47, 5, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 12, 47, 47, 47, 
+	47, 47, 47, 47, 47, 49, 47, 47, 
+	47, 47, 47, 47, 18, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 5, 47, 
+	48, 48, 50, 5, 50, 50, 50, 50, 
+	50, 50, 50, 50, 50, 50, 50, 50, 
+	50, 50, 50, 50, 50, 50, 50, 50, 
+	50, 50, 50, 50, 50, 50, 50, 50, 
+	50, 50, 18, 50, 50, 50, 50, 50, 
+	50, 50, 50, 50, 50, 50, 50, 50, 
+	50, 50, 50, 50, 5, 50, 51, 47, 
+	48, 48, 47, 5, 18, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 5, 47, 47, 47, 47, 
+	47, 47, 18, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 5, 47, 48, 48, 
 	47, 5, 47, 47, 47, 47, 47, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	47, 5, 47, 47, 47, 47, 47, 47, 
+	18, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 5, 47, 2, 47, 48, 48, 
+	47, 5, 6, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 52, 47, 47, 
+	12, 47, 47, 47, 47, 47, 47, 47, 
+	47, 53, 47, 47, 54, 47, 47, 47, 
+	18, 47, 53, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 5, 47, 2, 47, 48, 48, 
+	47, 5, 6, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	12, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	18, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 5, 47, 2, 47, 48, 48, 
+	47, 5, 6, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 52, 47, 47, 
+	12, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	18, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 5, 47, 2, 47, 48, 48, 
+	47, 5, 6, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 52, 47, 47, 
+	12, 47, 47, 47, 47, 47, 47, 47, 
+	47, 53, 47, 47, 47, 47, 47, 47, 
+	18, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 5, 47, 2, 47, 48, 48, 
+	47, 5, 6, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 52, 47, 47, 
 	12, 47, 47, 47, 47, 47, 47, 47, 
-	47, 49, 47, 47, 47, 47, 47, 47, 
-	18, 47, 48, 48, 47, 5, 47, 2, 
-	47, 48, 48, 47, 5, 6, 47, 47, 
+	47, 53, 47, 47, 47, 47, 47, 47, 
+	18, 47, 53, 47, 47, 47, 47, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	50, 47, 47, 12, 47, 47, 47, 47, 
-	47, 47, 47, 47, 51, 47, 47, 52, 
-	47, 47, 47, 18, 47, 51, 47, 2, 
-	47, 48, 48, 47, 5, 6, 47, 47, 
+	47, 47, 5, 47, 48, 48, 47, 5, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	47, 47, 47, 12, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 12, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	47, 47, 47, 18, 47, 53, 47, 48, 
-	48, 47, 5, 18, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 18, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	47, 47, 54, 47, 47, 47, 47, 47, 
-	47, 18, 47, 48, 48, 47, 5, 47, 
+	5, 47, 55, 55, 47, 47, 47, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
+	55, 47, 2, 3, 48, 48, 47, 5, 
+	6, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 9, 10, 11, 12, 47, 
+	47, 47, 47, 47, 47, 47, 47, 13, 
+	47, 47, 14, 15, 16, 17, 18, 19, 
+	20, 47, 47, 47, 47, 47, 47, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	47, 47, 47, 47, 47, 47, 54, 47, 
-	47, 47, 47, 47, 47, 18, 47, 48, 
-	48, 47, 5, 47, 47, 47, 47, 47, 
+	5, 47, 2, 47, 48, 48, 47, 5, 
+	6, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 9, 10, 47, 12, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 18, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	47, 18, 47, 2, 47, 48, 48, 47, 
-	5, 6, 47, 47, 47, 47, 47, 47, 
-	47, 47, 47, 47, 50, 47, 47, 12, 
+	5, 47, 2, 47, 48, 48, 47, 5, 
+	6, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 10, 47, 12, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	47, 47, 47, 47, 47, 47, 47, 18, 
-	47, 2, 47, 48, 48, 47, 5, 6, 
+	47, 47, 47, 47, 47, 47, 18, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	47, 47, 50, 47, 47, 12, 47, 47, 
-	47, 47, 47, 47, 47, 47, 51, 47, 
-	47, 47, 47, 47, 47, 18, 47, 2, 
-	47, 48, 48, 47, 5, 6, 47, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	50, 47, 47, 12, 47, 47, 47, 47, 
-	47, 47, 47, 47, 51, 47, 47, 47, 
-	47, 47, 47, 18, 47, 51, 47, 48, 
-	48, 47, 5, 47, 47, 47, 47, 47, 
+	5, 47, 2, 47, 48, 48, 47, 5, 
+	6, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 9, 10, 11, 12, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	47, 12, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 18, 56, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	47, 18, 47, 55, 55, 47, 47, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	47, 55, 47, 2, 3, 48, 48, 47, 
-	5, 6, 47, 47, 47, 47, 47, 47, 
-	47, 47, 47, 47, 9, 10, 11, 12, 
+	5, 47, 2, 47, 48, 48, 47, 5, 
+	6, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 9, 10, 11, 12, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	13, 47, 47, 14, 15, 16, 17, 18, 
-	19, 20, 47, 2, 47, 48, 48, 47, 
-	5, 6, 47, 47, 47, 47, 47, 47, 
-	47, 47, 47, 47, 9, 10, 47, 12, 
+	47, 47, 47, 47, 47, 47, 18, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	47, 47, 47, 47, 47, 47, 47, 18, 
-	47, 2, 47, 48, 48, 47, 5, 6, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	47, 47, 47, 10, 47, 12, 47, 47, 
+	5, 47, 2, 47, 48, 48, 47, 5, 
+	6, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 9, 10, 11, 12, 47, 
+	47, 47, 47, 47, 47, 47, 47, 13, 
+	47, 47, 14, 15, 16, 17, 18, 47, 
+	20, 47, 47, 47, 47, 47, 47, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	47, 47, 47, 47, 47, 18, 47, 2, 
-	47, 48, 48, 47, 5, 6, 47, 47, 
+	5, 47, 2, 47, 48, 48, 47, 5, 
+	6, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 9, 10, 11, 12, 47, 
+	47, 47, 47, 47, 47, 47, 47, 56, 
+	47, 47, 47, 47, 47, 47, 18, 47, 
+	20, 47, 47, 47, 47, 47, 47, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	9, 10, 11, 12, 47, 47, 47, 47, 
+	5, 47, 2, 47, 48, 48, 47, 5, 
+	6, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 9, 10, 11, 12, 47, 
+	47, 47, 47, 47, 47, 47, 47, 56, 
+	47, 47, 47, 47, 47, 47, 18, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	47, 47, 47, 18, 56, 47, 2, 47, 
-	48, 48, 47, 5, 6, 47, 47, 47, 
-	47, 47, 47, 47, 47, 47, 47, 9, 
-	10, 11, 12, 47, 47, 47, 47, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
-	47, 47, 18, 47, 2, 47, 48, 48, 
-	47, 5, 6, 47, 47, 47, 47, 47, 
-	47, 47, 47, 47, 47, 9, 10, 11, 
-	12, 47, 47, 47, 47, 47, 47, 47, 
-	47, 13, 47, 47, 14, 15, 16, 17, 
-	18, 47, 20, 47, 2, 47, 48, 48, 
-	47, 5, 6, 47, 47, 47, 47, 47, 
-	47, 47, 47, 47, 47, 9, 10, 11, 
-	12, 47, 47, 47, 47, 47, 47, 47, 
-	47, 56, 47, 47, 47, 47, 47, 47, 
-	18, 47, 20, 47, 2, 47, 48, 48, 
-	47, 5, 6, 47, 47, 47, 47, 47, 
-	47, 47, 47, 47, 47, 9, 10, 11, 
-	12, 47, 47, 47, 47, 47, 47, 47, 
-	47, 56, 47, 47, 47, 47, 47, 47, 
-	18, 47, 2, 47, 48, 48, 47, 5, 
+	5, 47, 2, 47, 48, 48, 47, 5, 
 	6, 47, 47, 47, 47, 47, 47, 47, 
 	47, 47, 47, 9, 10, 11, 12, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
 	47, 47, 14, 47, 16, 47, 18, 47, 
-	20, 47, 2, 47, 48, 48, 47, 5, 
+	20, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	5, 47, 2, 47, 48, 48, 47, 5, 
 	6, 47, 47, 47, 47, 47, 47, 47, 
 	47, 47, 47, 9, 10, 11, 12, 47, 
 	47, 47, 47, 47, 47, 47, 47, 56, 
 	47, 47, 14, 47, 47, 47, 18, 47, 
-	20, 47, 2, 47, 48, 48, 47, 5, 
+	20, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	5, 47, 2, 47, 48, 48, 47, 5, 
 	6, 47, 47, 47, 47, 47, 47, 47, 
 	47, 47, 47, 9, 10, 11, 12, 47, 
 	47, 47, 47, 47, 47, 47, 47, 57, 
 	47, 47, 14, 15, 16, 47, 18, 47, 
-	20, 47, 2, 47, 48, 48, 47, 5, 
+	20, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	5, 47, 2, 47, 48, 48, 47, 5, 
 	6, 47, 47, 47, 47, 47, 47, 47, 
 	47, 47, 47, 9, 10, 11, 12, 47, 
 	47, 47, 47, 47, 47, 47, 47, 47, 
 	47, 47, 14, 15, 16, 47, 18, 47, 
-	20, 47, 2, 3, 48, 48, 47, 5, 
+	20, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	5, 47, 2, 3, 48, 48, 47, 5, 
 	6, 47, 47, 47, 47, 47, 47, 47, 
 	47, 47, 47, 9, 10, 11, 12, 47, 
 	47, 47, 47, 47, 47, 47, 47, 13, 
 	47, 47, 14, 15, 16, 17, 18, 47, 
-	20, 47, 22, 23, 24, 24, 21, 25, 
-	26, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 27, 28, 29, 30, 21, 
-	21, 21, 21, 21, 21, 21, 21, 58, 
-	21, 21, 32, 33, 34, 35, 36, 37, 
-	38, 21, 22, 59, 24, 24, 21, 25, 
-	26, 21, 21, 21, 21, 21, 21, 21, 
-	21, 21, 21, 27, 28, 29, 30, 21, 
-	21, 21, 21, 21, 21, 21, 21, 31, 
-	21, 21, 32, 33, 34, 35, 36, 21, 
-	38, 21, 1, 1, 2, 3, 48, 48, 
+	20, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	5, 47, 23, 24, 25, 25, 22, 26, 
+	27, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 28, 29, 30, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 58, 
+	22, 22, 33, 34, 35, 36, 37, 38, 
+	39, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 23, 59, 25, 25, 22, 26, 
+	27, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 28, 29, 30, 31, 22, 
+	22, 22, 22, 22, 22, 22, 22, 32, 
+	22, 22, 33, 34, 35, 36, 37, 22, 
+	39, 22, 22, 22, 22, 22, 22, 22, 
+	22, 22, 22, 22, 22, 22, 22, 22, 
+	26, 22, 1, 1, 2, 3, 48, 48, 
 	47, 5, 6, 1, 1, 47, 47, 47, 
 	1, 47, 47, 47, 47, 9, 10, 11, 
 	12, 47, 47, 47, 47, 47, 47, 47, 
 	47, 13, 47, 47, 14, 15, 16, 17, 
-	18, 19, 20, 47, 1, 1, 60, 60, 
+	18, 19, 20, 47, 47, 47, 47, 47, 
+	47, 47, 47, 47, 47, 47, 47, 47, 
+	47, 47, 5, 47, 1, 1, 60, 60, 
 	60, 60, 60, 60, 60, 1, 1, 60, 
 	60, 60, 1, 60, 0
 };
 
 static const char _myanmar_syllable_machine_trans_targs[] = {
-	0, 1, 26, 37, 0, 27, 29, 51, 
-	54, 39, 40, 41, 28, 43, 44, 46, 
-	47, 48, 30, 50, 45, 0, 2, 13, 
-	0, 3, 5, 14, 15, 16, 4, 18, 
-	19, 21, 22, 23, 6, 25, 20, 12, 
-	9, 10, 11, 7, 8, 17, 24, 0, 
-	0, 36, 33, 34, 35, 31, 32, 38, 
-	42, 49, 52, 53, 0
+	0, 1, 25, 35, 0, 26, 30, 49, 
+	52, 37, 38, 39, 29, 41, 42, 44, 
+	45, 46, 27, 48, 43, 26, 0, 2, 
+	12, 0, 3, 7, 13, 14, 15, 6, 
+	17, 18, 20, 21, 22, 4, 24, 19, 
+	11, 5, 8, 9, 10, 16, 23, 0, 
+	0, 34, 0, 28, 31, 32, 33, 36, 
+	40, 47, 50, 51, 0
 };
 
 static const char _myanmar_syllable_machine_trans_actions[] = {
-	3, 0, 0, 0, 4, 0, 0, 0, 
+	3, 0, 0, 0, 4, 5, 0, 0, 
 	0, 0, 0, 0, 0, 0, 0, 0, 
-	0, 0, 0, 0, 0, 5, 0, 0, 
-	6, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 6, 7, 0, 
+	0, 8, 0, 0, 0, 0, 0, 0, 
 	0, 0, 0, 0, 0, 0, 0, 0, 
-	0, 0, 0, 0, 0, 0, 0, 7, 
-	8, 0, 0, 0, 0, 0, 0, 0, 
-	0, 0, 0, 0, 9
+	0, 0, 0, 0, 0, 0, 0, 9, 
+	10, 0, 11, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 12
 };
 
 static const char _myanmar_syllable_machine_to_state_actions[] = {
@@ -390,7 +496,7 @@ static const char _myanmar_syllable_machine_to_state_actions[] = {
 	0, 0, 0, 0, 0, 0, 0, 0, 
 	0, 0, 0, 0, 0, 0, 0, 0, 
 	0, 0, 0, 0, 0, 0, 0, 0, 
-	0, 0, 0, 0, 0, 0, 0
+	0, 0, 0, 0, 0
 };
 
 static const char _myanmar_syllable_machine_from_state_actions[] = {
@@ -400,17 +506,17 @@ static const char _myanmar_syllable_machine_from_state_actions[] = {
 	0, 0, 0, 0, 0, 0, 0, 0, 
 	0, 0, 0, 0, 0, 0, 0, 0, 
 	0, 0, 0, 0, 0, 0, 0, 0, 
-	0, 0, 0, 0, 0, 0, 0
+	0, 0, 0, 0, 0
 };
 
 static const short _myanmar_syllable_machine_eof_trans[] = {
-	0, 22, 22, 22, 22, 22, 22, 22, 
-	22, 22, 22, 22, 22, 22, 22, 22, 
-	22, 22, 22, 22, 22, 22, 22, 22, 
-	22, 22, 48, 48, 48, 48, 48, 48, 
+	0, 23, 23, 23, 23, 23, 23, 23, 
+	23, 23, 23, 23, 23, 23, 23, 23, 
+	23, 23, 23, 23, 23, 23, 23, 23, 
+	23, 48, 51, 48, 48, 48, 48, 48, 
 	48, 48, 48, 48, 48, 48, 48, 48, 
 	48, 48, 48, 48, 48, 48, 48, 48, 
-	48, 48, 48, 22, 22, 48, 61
+	48, 23, 23, 48, 61
 };
 
 static const int myanmar_syllable_machine_start = 0;
@@ -424,7 +530,7 @@ static const int myanmar_syllable_machine_en_main = 0;
 
 
 
-#line 117 "hb-ot-shaper-myanmar-machine.rl"
+#line 118 "hb-ot-shaper-myanmar-machine.rl"
 
 
 #define found_syllable(syllable_type) \
@@ -443,7 +549,7 @@ find_syllables_myanmar (hb_buffer_t *buffer)
   int cs;
   hb_glyph_info_t *info = buffer->info;
   
-#line 447 "hb-ot-shaper-myanmar-machine.hh"
+#line 553 "hb-ot-shaper-myanmar-machine.hh"
 	{
 	cs = myanmar_syllable_machine_start;
 	ts = 0;
@@ -451,7 +557,7 @@ find_syllables_myanmar (hb_buffer_t *buffer)
 	act = 0;
 	}
 
-#line 137 "hb-ot-shaper-myanmar-machine.rl"
+#line 138 "hb-ot-shaper-myanmar-machine.rl"
 
 
   p = 0;
@@ -459,7 +565,7 @@ find_syllables_myanmar (hb_buffer_t *buffer)
 
   unsigned int syllable_serial = 1;
   
-#line 463 "hb-ot-shaper-myanmar-machine.hh"
+#line 569 "hb-ot-shaper-myanmar-machine.hh"
 	{
 	int _slen;
 	int _trans;
@@ -473,7 +579,7 @@ _resume:
 #line 1 "NONE"
 	{ts = p;}
 	break;
-#line 477 "hb-ot-shaper-myanmar-machine.hh"
+#line 583 "hb-ot-shaper-myanmar-machine.hh"
 	}
 
 	_keys = _myanmar_syllable_machine_trans_keys + (cs<<1);
@@ -491,35 +597,59 @@ _eof_trans:
 		goto _again;
 
 	switch ( _myanmar_syllable_machine_trans_actions[_trans] ) {
-	case 6:
-#line 110 "hb-ot-shaper-myanmar-machine.rl"
+	case 8:
+#line 111 "hb-ot-shaper-myanmar-machine.rl"
 	{te = p+1;{ found_syllable (myanmar_consonant_syllable); }}
 	break;
 	case 4:
-#line 111 "hb-ot-shaper-myanmar-machine.rl"
+#line 112 "hb-ot-shaper-myanmar-machine.rl"
 	{te = p+1;{ found_syllable (myanmar_non_myanmar_cluster); }}
 	break;
-	case 8:
-#line 112 "hb-ot-shaper-myanmar-machine.rl"
+	case 10:
+#line 113 "hb-ot-shaper-myanmar-machine.rl"
 	{te = p+1;{ found_syllable (myanmar_broken_cluster); buffer->scratch_flags |= HB_BUFFER_SCRATCH_FLAG_HAS_BROKEN_SYLLABLE; }}
 	break;
 	case 3:
-#line 113 "hb-ot-shaper-myanmar-machine.rl"
+#line 114 "hb-ot-shaper-myanmar-machine.rl"
 	{te = p+1;{ found_syllable (myanmar_non_myanmar_cluster); }}
 	break;
-	case 5:
-#line 110 "hb-ot-shaper-myanmar-machine.rl"
-	{te = p;p--;{ found_syllable (myanmar_consonant_syllable); }}
-	break;
 	case 7:
-#line 112 "hb-ot-shaper-myanmar-machine.rl"
-	{te = p;p--;{ found_syllable (myanmar_broken_cluster); buffer->scratch_flags |= HB_BUFFER_SCRATCH_FLAG_HAS_BROKEN_SYLLABLE; }}
+#line 111 "hb-ot-shaper-myanmar-machine.rl"
+	{te = p;p--;{ found_syllable (myanmar_consonant_syllable); }}
 	break;
 	case 9:
 #line 113 "hb-ot-shaper-myanmar-machine.rl"
+	{te = p;p--;{ found_syllable (myanmar_broken_cluster); buffer->scratch_flags |= HB_BUFFER_SCRATCH_FLAG_HAS_BROKEN_SYLLABLE; }}
+	break;
+	case 12:
+#line 114 "hb-ot-shaper-myanmar-machine.rl"
 	{te = p;p--;{ found_syllable (myanmar_non_myanmar_cluster); }}
 	break;
-#line 523 "hb-ot-shaper-myanmar-machine.hh"
+	case 11:
+#line 1 "NONE"
+	{	switch( act ) {
+	case 2:
+	{{p = ((te))-1;} found_syllable (myanmar_non_myanmar_cluster); }
+	break;
+	case 3:
+	{{p = ((te))-1;} found_syllable (myanmar_broken_cluster); buffer->scratch_flags |= HB_BUFFER_SCRATCH_FLAG_HAS_BROKEN_SYLLABLE; }
+	break;
+	}
+	}
+	break;
+	case 6:
+#line 1 "NONE"
+	{te = p+1;}
+#line 112 "hb-ot-shaper-myanmar-machine.rl"
+	{act = 2;}
+	break;
+	case 5:
+#line 1 "NONE"
+	{te = p+1;}
+#line 113 "hb-ot-shaper-myanmar-machine.rl"
+	{act = 3;}
+	break;
+#line 653 "hb-ot-shaper-myanmar-machine.hh"
 	}
 
 _again:
@@ -528,7 +658,7 @@ _again:
 #line 1 "NONE"
 	{ts = 0;}
 	break;
-#line 532 "hb-ot-shaper-myanmar-machine.hh"
+#line 662 "hb-ot-shaper-myanmar-machine.hh"
 	}
 
 	if ( ++p != pe )
@@ -544,7 +674,7 @@ _again:
 
 	}
 
-#line 145 "hb-ot-shaper-myanmar-machine.rl"
+#line 146 "hb-ot-shaper-myanmar-machine.rl"
 
 }
 
diff --git a/src/hb-ot-shaper-myanmar-machine.rl b/src/hb-ot-shaper-myanmar-machine.rl
index e8d1e788c..0b7a95997 100644
--- a/src/hb-ot-shaper-myanmar-machine.rl
+++ b/src/hb-ot-shaper-myanmar-machine.rl
@@ -72,6 +72,7 @@ export DOTTEDCIRCLE = 11;
 export A    = 9;
 export Ra   = 15;
 export CS   = 18;
+export SMPst= 57;
 
 export VAbv = 20;
 export VBlw = 21;
@@ -91,15 +92,15 @@ export ML   = 41;	# Medial Mon La
 
 j = ZWJ|ZWNJ;			# Joiners
 k = (Ra As H);			# Kinzi
-
+sm = SM | SMPst;
 c = C|Ra;			# is_consonant
 
 medial_group = MY? As? MR? ((MW MH? ML? | MH ML? | ML) As?)?;
 main_vowel_group = (VPre.VS?)* VAbv* VBlw* A* (DB As?)?;
 post_vowel_group = VPst MH? ML? As* VAbv* A* (DB As?)?;
-pwo_tone_group = PT A* DB? As?;
+tone_group = sm | PT A* DB? As?;
 
-complex_syllable_tail = As* medial_group main_vowel_group post_vowel_group* pwo_tone_group* SM* j?;
+complex_syllable_tail = As* medial_group main_vowel_group post_vowel_group* tone_group* j?;
 syllable_tail = (H (c|IV).VS?)* (H | complex_syllable_tail);
 
 consonant_syllable =	(k|CS)? (c|IV|GB|DOTTEDCIRCLE).VS? syllable_tail;
@@ -108,7 +109,7 @@ other =			any;
 
 main := |*
 	consonant_syllable	=> { found_syllable (myanmar_consonant_syllable); };
-	j			=> { found_syllable (myanmar_non_myanmar_cluster); };
+	j | SMPst		=> { found_syllable (myanmar_non_myanmar_cluster); };
 	broken_cluster		=> { found_syllable (myanmar_broken_cluster); buffer->scratch_flags |= HB_BUFFER_SCRATCH_FLAG_HAS_BROKEN_SYLLABLE; };
 	other			=> { found_syllable (myanmar_non_myanmar_cluster); };
 *|;
diff --git a/src/hb-ot-shaper-use-machine.hh b/src/hb-ot-shaper-use-machine.hh
index e9da28d45..65b6adc36 100644
--- a/src/hb-ot-shaper-use-machine.hh
+++ b/src/hb-ot-shaper-use-machine.hh
@@ -166,556 +166,556 @@ static const unsigned char _use_syllable_machine_indicies[] = {
 	19, 20, 21, 8, 22, 23, 24, 25, 
 	5, 26, 27, 28, 5, 29, 30, 31, 
 	32, 33, 34, 35, 32, 1, 5, 36, 
-	5, 37, 5, 5, 35, 5, 39, 40, 
-	38, 41, 38, 38, 38, 38, 38, 38, 
-	38, 42, 43, 44, 45, 46, 47, 48, 
-	49, 50, 39, 51, 52, 53, 54, 38, 
-	55, 56, 57, 38, 58, 59, 38, 60, 
-	61, 62, 63, 60, 38, 38, 38, 38, 
-	64, 38, 38, 63, 38, 39, 40, 38, 
-	41, 38, 38, 38, 38, 38, 38, 38, 
-	42, 43, 44, 45, 46, 47, 48, 49, 
-	50, 39, 51, 52, 53, 54, 38, 55, 
-	56, 57, 38, 38, 38, 38, 60, 61, 
-	62, 63, 60, 38, 38, 38, 38, 64, 
-	38, 38, 63, 38, 39, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 41, 38, 38, 38, 38, 38, 38, 
-	38, 38, 43, 44, 45, 46, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	55, 56, 57, 38, 38, 38, 38, 38, 
-	61, 62, 63, 65, 38, 38, 38, 38, 
-	43, 38, 41, 38, 38, 38, 38, 38, 
-	38, 38, 38, 43, 44, 45, 46, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 55, 56, 57, 38, 38, 38, 38, 
-	38, 61, 62, 63, 65, 38, 41, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	44, 45, 46, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 61, 62, 63, 
-	38, 41, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 45, 46, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	61, 62, 63, 38, 41, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	46, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 61, 62, 63, 38, 41, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 61, 62, 
-	38, 41, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 62, 38, 41, 38, 41, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 44, 
-	45, 46, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 55, 56, 57, 38, 
-	38, 38, 38, 38, 61, 62, 63, 65, 
-	38, 41, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 44, 45, 46, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 56, 57, 38, 38, 38, 38, 38, 
-	61, 62, 63, 65, 38, 41, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 44, 
-	45, 46, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 57, 38, 
-	38, 38, 38, 38, 61, 62, 63, 65, 
-	38, 66, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 41, 38, 
-	41, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 44, 45, 46, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 61, 
-	62, 63, 65, 38, 41, 38, 38, 38, 
-	38, 38, 38, 38, 42, 43, 44, 45, 
-	46, 38, 38, 38, 38, 38, 38, 52, 
-	53, 54, 38, 55, 56, 57, 38, 38, 
-	38, 38, 38, 61, 62, 63, 65, 38, 
-	38, 38, 38, 43, 38, 41, 38, 38, 
-	38, 38, 38, 38, 38, 38, 43, 44, 
-	45, 46, 38, 38, 38, 38, 38, 38, 
-	52, 53, 54, 38, 55, 56, 57, 38, 
-	38, 38, 38, 38, 61, 62, 63, 65, 
-	38, 38, 38, 38, 43, 38, 41, 38, 
-	38, 38, 38, 38, 38, 38, 38, 43, 
-	44, 45, 46, 38, 38, 38, 38, 38, 
-	38, 38, 53, 54, 38, 55, 56, 57, 
-	38, 38, 38, 38, 38, 61, 62, 63, 
-	65, 38, 38, 38, 38, 43, 38, 41, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	43, 44, 45, 46, 38, 38, 38, 38, 
-	38, 38, 38, 38, 54, 38, 55, 56, 
-	57, 38, 38, 38, 38, 38, 61, 62, 
-	63, 65, 38, 38, 38, 38, 43, 38, 
-	67, 38, 41, 38, 38, 38, 38, 38, 
-	38, 38, 42, 43, 44, 45, 46, 38, 
-	48, 49, 38, 38, 38, 52, 53, 54, 
-	38, 55, 56, 57, 38, 38, 38, 38, 
-	38, 61, 62, 63, 65, 38, 38, 38, 
-	38, 43, 38, 41, 38, 38, 38, 38, 
-	38, 38, 38, 38, 43, 44, 45, 46, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 55, 56, 57, 38, 38, 38, 
-	38, 38, 61, 62, 63, 65, 38, 38, 
-	38, 38, 43, 38, 67, 38, 41, 38, 
-	38, 38, 38, 38, 38, 38, 42, 43, 
-	44, 45, 46, 38, 38, 49, 38, 38, 
-	38, 52, 53, 54, 38, 55, 56, 57, 
-	38, 38, 38, 38, 38, 61, 62, 63, 
-	65, 38, 38, 38, 38, 43, 38, 67, 
-	38, 41, 38, 38, 38, 38, 38, 38, 
-	38, 42, 43, 44, 45, 46, 38, 38, 
-	38, 38, 38, 38, 52, 53, 54, 38, 
-	55, 56, 57, 38, 38, 38, 38, 38, 
-	61, 62, 63, 65, 38, 38, 38, 38, 
-	43, 38, 67, 38, 41, 38, 38, 38, 
-	38, 38, 38, 38, 42, 43, 44, 45, 
-	46, 47, 48, 49, 38, 38, 38, 52, 
-	53, 54, 38, 55, 56, 57, 38, 38, 
-	38, 38, 38, 61, 62, 63, 65, 38, 
-	38, 38, 38, 43, 38, 39, 40, 38, 
-	41, 38, 38, 38, 38, 38, 38, 38, 
-	42, 43, 44, 45, 46, 47, 48, 49, 
-	50, 38, 51, 52, 53, 54, 38, 55, 
-	56, 57, 38, 38, 38, 38, 60, 61, 
-	62, 63, 60, 38, 38, 38, 38, 64, 
-	38, 38, 63, 38, 39, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 41, 38, 39, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	41, 38, 38, 38, 38, 38, 38, 38, 
-	38, 43, 44, 45, 46, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 55, 
-	56, 57, 38, 38, 38, 38, 38, 61, 
-	62, 63, 65, 38, 41, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 58, 
-	59, 38, 41, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 38, 38, 
-	38, 38, 38, 38, 38, 38, 59, 38, 
-	4, 69, 68, 70, 68, 68, 68, 68, 
-	68, 68, 68, 71, 72, 73, 74, 75, 
-	76, 77, 78, 79, 4, 80, 81, 82, 
-	83, 68, 84, 85, 86, 68, 68, 68, 
-	68, 87, 88, 89, 90, 91, 68, 68, 
-	68, 68, 92, 68, 68, 93, 68, 4, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 70, 68, 68, 68, 
-	68, 68, 68, 68, 68, 72, 73, 74, 
-	75, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 84, 85, 86, 68, 68, 
-	68, 68, 68, 88, 89, 90, 94, 68, 
-	68, 68, 68, 72, 68, 70, 68, 68, 
-	68, 68, 68, 68, 68, 68, 72, 73, 
-	74, 75, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 84, 85, 86, 68, 
-	68, 68, 68, 68, 88, 89, 90, 94, 
-	68, 70, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 73, 74, 75, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	88, 89, 90, 68, 70, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 74, 
-	75, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 88, 89, 90, 68, 70, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 75, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 88, 89, 
-	90, 68, 70, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 88, 89, 68, 70, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 89, 68, 70, 68, 
-	70, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 73, 74, 75, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 84, 
-	85, 86, 68, 68, 68, 68, 68, 88, 
-	89, 90, 94, 68, 70, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 73, 74, 
-	75, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 85, 86, 68, 68, 
-	68, 68, 68, 88, 89, 90, 94, 68, 
-	70, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 73, 74, 75, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 86, 68, 68, 68, 68, 68, 88, 
-	89, 90, 94, 68, 96, 95, 95, 95, 
-	95, 95, 95, 95, 95, 95, 95, 95, 
-	95, 97, 95, 70, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 73, 74, 75, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 88, 89, 90, 94, 68, 70, 
-	68, 68, 68, 68, 68, 68, 68, 71, 
-	72, 73, 74, 75, 68, 68, 68, 68, 
-	68, 68, 81, 82, 83, 68, 84, 85, 
-	86, 68, 68, 68, 68, 68, 88, 89, 
-	90, 94, 68, 68, 68, 68, 72, 68, 
-	70, 68, 68, 68, 68, 68, 68, 68, 
-	68, 72, 73, 74, 75, 68, 68, 68, 
-	68, 68, 68, 81, 82, 83, 68, 84, 
-	85, 86, 68, 68, 68, 68, 68, 88, 
-	89, 90, 94, 68, 68, 68, 68, 72, 
-	68, 70, 68, 68, 68, 68, 68, 68, 
-	68, 68, 72, 73, 74, 75, 68, 68, 
-	68, 68, 68, 68, 68, 82, 83, 68, 
-	84, 85, 86, 68, 68, 68, 68, 68, 
-	88, 89, 90, 94, 68, 68, 68, 68, 
-	72, 68, 70, 68, 68, 68, 68, 68, 
-	68, 68, 68, 72, 73, 74, 75, 68, 
-	68, 68, 68, 68, 68, 68, 68, 83, 
-	68, 84, 85, 86, 68, 68, 68, 68, 
-	68, 88, 89, 90, 94, 68, 68, 68, 
-	68, 72, 68, 98, 68, 70, 68, 68, 
-	68, 68, 68, 68, 68, 71, 72, 73, 
-	74, 75, 68, 77, 78, 68, 68, 68, 
-	81, 82, 83, 68, 84, 85, 86, 68, 
-	68, 68, 68, 68, 88, 89, 90, 94, 
-	68, 68, 68, 68, 72, 68, 70, 68, 
-	68, 68, 68, 68, 68, 68, 68, 72, 
-	73, 74, 75, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 84, 85, 86, 
-	68, 68, 68, 68, 68, 88, 89, 90, 
-	94, 68, 68, 68, 68, 72, 68, 98, 
-	68, 70, 68, 68, 68, 68, 68, 68, 
-	68, 71, 72, 73, 74, 75, 68, 68, 
-	78, 68, 68, 68, 81, 82, 83, 68, 
-	84, 85, 86, 68, 68, 68, 68, 68, 
-	88, 89, 90, 94, 68, 68, 68, 68, 
-	72, 68, 98, 68, 70, 68, 68, 68, 
-	68, 68, 68, 68, 71, 72, 73, 74, 
-	75, 68, 68, 68, 68, 68, 68, 81, 
-	82, 83, 68, 84, 85, 86, 68, 68, 
-	68, 68, 68, 88, 89, 90, 94, 68, 
-	68, 68, 68, 72, 68, 98, 68, 70, 
-	68, 68, 68, 68, 68, 68, 68, 71, 
-	72, 73, 74, 75, 76, 77, 78, 68, 
-	68, 68, 81, 82, 83, 68, 84, 85, 
-	86, 68, 68, 68, 68, 68, 88, 89, 
-	90, 94, 68, 68, 68, 68, 72, 68, 
-	4, 69, 68, 70, 68, 68, 68, 68, 
-	68, 68, 68, 71, 72, 73, 74, 75, 
-	76, 77, 78, 79, 68, 80, 81, 82, 
-	83, 68, 84, 85, 86, 68, 68, 68, 
-	68, 87, 88, 89, 90, 91, 68, 68, 
-	68, 68, 92, 68, 68, 93, 68, 4, 
-	99, 99, 99, 99, 99, 99, 99, 99, 
-	99, 99, 99, 99, 100, 99, 4, 95, 
-	95, 95, 95, 95, 95, 95, 95, 95, 
-	95, 95, 95, 97, 95, 4, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 70, 68, 68, 68, 68, 68, 
-	68, 68, 68, 72, 73, 74, 75, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 84, 85, 86, 68, 68, 68, 68, 
-	68, 88, 89, 90, 94, 68, 100, 99, 
-	102, 103, 101, 6, 104, 104, 104, 104, 
-	104, 104, 104, 104, 104, 105, 104, 106, 
-	107, 68, 70, 68, 68, 68, 68, 68, 
-	68, 68, 108, 109, 110, 111, 112, 113, 
-	114, 115, 116, 106, 117, 118, 119, 120, 
-	68, 121, 122, 123, 68, 58, 59, 68, 
-	124, 125, 126, 127, 128, 68, 68, 68, 
-	68, 129, 68, 68, 130, 68, 106, 107, 
-	68, 70, 68, 68, 68, 68, 68, 68, 
-	68, 108, 109, 110, 111, 112, 113, 114, 
-	115, 116, 106, 117, 118, 119, 120, 68, 
-	121, 122, 123, 68, 68, 68, 68, 124, 
-	125, 126, 127, 128, 68, 68, 68, 68, 
-	129, 68, 68, 130, 68, 106, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 70, 68, 68, 68, 68, 68, 
-	68, 68, 68, 109, 110, 111, 112, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 121, 122, 123, 68, 68, 68, 68, 
-	68, 125, 126, 127, 131, 68, 68, 68, 
-	68, 109, 68, 70, 68, 68, 68, 68, 
-	68, 68, 68, 68, 109, 110, 111, 112, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 121, 122, 123, 68, 68, 68, 
-	68, 68, 125, 126, 127, 131, 68, 70, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 110, 111, 112, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 125, 126, 
-	127, 68, 70, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 111, 112, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 125, 126, 127, 68, 70, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 112, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 125, 126, 127, 68, 
-	70, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 125, 
-	126, 68, 70, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 126, 68, 70, 68, 70, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	110, 111, 112, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 121, 122, 123, 
-	68, 68, 68, 68, 68, 125, 126, 127, 
-	131, 68, 70, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 110, 111, 112, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 122, 123, 68, 68, 68, 68, 
-	68, 125, 126, 127, 131, 68, 70, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	110, 111, 112, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 123, 
-	68, 68, 68, 68, 68, 125, 126, 127, 
-	131, 68, 132, 95, 95, 95, 95, 95, 
-	95, 95, 95, 95, 95, 95, 95, 97, 
-	95, 70, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 110, 111, 112, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	125, 126, 127, 131, 68, 70, 68, 68, 
-	68, 68, 68, 68, 68, 108, 109, 110, 
-	111, 112, 68, 68, 68, 68, 68, 68, 
-	118, 119, 120, 68, 121, 122, 123, 68, 
-	68, 68, 68, 68, 125, 126, 127, 131, 
-	68, 68, 68, 68, 109, 68, 70, 68, 
-	68, 68, 68, 68, 68, 68, 68, 109, 
-	110, 111, 112, 68, 68, 68, 68, 68, 
-	68, 118, 119, 120, 68, 121, 122, 123, 
-	68, 68, 68, 68, 68, 125, 126, 127, 
-	131, 68, 68, 68, 68, 109, 68, 70, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	109, 110, 111, 112, 68, 68, 68, 68, 
-	68, 68, 68, 119, 120, 68, 121, 122, 
-	123, 68, 68, 68, 68, 68, 125, 126, 
-	127, 131, 68, 68, 68, 68, 109, 68, 
-	70, 68, 68, 68, 68, 68, 68, 68, 
-	68, 109, 110, 111, 112, 68, 68, 68, 
-	68, 68, 68, 68, 68, 120, 68, 121, 
-	122, 123, 68, 68, 68, 68, 68, 125, 
-	126, 127, 131, 68, 68, 68, 68, 109, 
-	68, 133, 68, 70, 68, 68, 68, 68, 
-	68, 68, 68, 108, 109, 110, 111, 112, 
-	68, 114, 115, 68, 68, 68, 118, 119, 
-	120, 68, 121, 122, 123, 68, 68, 68, 
-	68, 68, 125, 126, 127, 131, 68, 68, 
-	68, 68, 109, 68, 70, 68, 68, 68, 
-	68, 68, 68, 68, 68, 109, 110, 111, 
-	112, 68, 68, 68, 68, 68, 68, 68, 
-	68, 68, 68, 121, 122, 123, 68, 68, 
-	68, 68, 68, 125, 126, 127, 131, 68, 
-	68, 68, 68, 109, 68, 133, 68, 70, 
-	68, 68, 68, 68, 68, 68, 68, 108, 
-	109, 110, 111, 112, 68, 68, 115, 68, 
-	68, 68, 118, 119, 120, 68, 121, 122, 
-	123, 68, 68, 68, 68, 68, 125, 126, 
-	127, 131, 68, 68, 68, 68, 109, 68, 
-	133, 68, 70, 68, 68, 68, 68, 68, 
-	68, 68, 108, 109, 110, 111, 112, 68, 
-	68, 68, 68, 68, 68, 118, 119, 120, 
-	68, 121, 122, 123, 68, 68, 68, 68, 
-	68, 125, 126, 127, 131, 68, 68, 68, 
-	68, 109, 68, 133, 68, 70, 68, 68, 
-	68, 68, 68, 68, 68, 108, 109, 110, 
-	111, 112, 113, 114, 115, 68, 68, 68, 
-	118, 119, 120, 68, 121, 122, 123, 68, 
-	68, 68, 68, 68, 125, 126, 127, 131, 
-	68, 68, 68, 68, 109, 68, 106, 107, 
-	68, 70, 68, 68, 68, 68, 68, 68, 
-	68, 108, 109, 110, 111, 112, 113, 114, 
-	115, 116, 68, 117, 118, 119, 120, 68, 
-	121, 122, 123, 68, 68, 68, 68, 124, 
-	125, 126, 127, 128, 68, 68, 68, 68, 
-	129, 68, 68, 130, 68, 106, 99, 99, 
-	99, 99, 99, 99, 99, 99, 99, 99, 
-	99, 99, 100, 99, 106, 95, 95, 95, 
-	95, 95, 95, 95, 95, 95, 95, 95, 
-	95, 97, 95, 106, 68, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 68, 
-	70, 68, 68, 68, 68, 68, 68, 68, 
-	68, 109, 110, 111, 112, 68, 68, 68, 
-	68, 68, 68, 68, 68, 68, 68, 121, 
-	122, 123, 68, 68, 68, 68, 68, 125, 
-	126, 127, 131, 68, 100, 99, 8, 9, 
-	134, 11, 134, 134, 134, 134, 134, 134, 
-	134, 13, 14, 15, 16, 17, 18, 19, 
-	20, 21, 8, 22, 23, 24, 25, 134, 
-	26, 27, 28, 134, 134, 134, 134, 32, 
-	33, 34, 35, 32, 134, 134, 134, 134, 
-	37, 134, 134, 35, 134, 8, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 11, 134, 134, 134, 134, 134, 
-	134, 134, 134, 14, 15, 16, 17, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 26, 27, 28, 134, 134, 134, 134, 
-	134, 33, 34, 35, 135, 134, 134, 134, 
-	134, 14, 134, 11, 134, 134, 134, 134, 
-	134, 134, 134, 134, 14, 15, 16, 17, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 26, 27, 28, 134, 134, 134, 
-	134, 134, 33, 34, 35, 135, 134, 11, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 15, 16, 17, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 33, 34, 
-	35, 134, 11, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 16, 17, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 33, 34, 35, 134, 11, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 17, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 33, 34, 35, 134, 
-	11, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 33, 
-	34, 134, 11, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 34, 134, 11, 134, 11, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	15, 16, 17, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 26, 27, 28, 
-	134, 134, 134, 134, 134, 33, 34, 35, 
-	135, 134, 11, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 15, 16, 17, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 27, 28, 134, 134, 134, 134, 
-	134, 33, 34, 35, 135, 134, 11, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	15, 16, 17, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 28, 
-	134, 134, 134, 134, 134, 33, 34, 35, 
-	135, 134, 136, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 11, 
-	134, 11, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 15, 16, 17, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	33, 34, 35, 135, 134, 11, 134, 134, 
-	134, 134, 134, 134, 134, 13, 14, 15, 
-	16, 17, 134, 134, 134, 134, 134, 134, 
-	23, 24, 25, 134, 26, 27, 28, 134, 
-	134, 134, 134, 134, 33, 34, 35, 135, 
-	134, 134, 134, 134, 14, 134, 11, 134, 
-	134, 134, 134, 134, 134, 134, 134, 14, 
-	15, 16, 17, 134, 134, 134, 134, 134, 
-	134, 23, 24, 25, 134, 26, 27, 28, 
-	134, 134, 134, 134, 134, 33, 34, 35, 
-	135, 134, 134, 134, 134, 14, 134, 11, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	14, 15, 16, 17, 134, 134, 134, 134, 
-	134, 134, 134, 24, 25, 134, 26, 27, 
-	28, 134, 134, 134, 134, 134, 33, 34, 
-	35, 135, 134, 134, 134, 134, 14, 134, 
-	11, 134, 134, 134, 134, 134, 134, 134, 
-	134, 14, 15, 16, 17, 134, 134, 134, 
-	134, 134, 134, 134, 134, 25, 134, 26, 
-	27, 28, 134, 134, 134, 134, 134, 33, 
-	34, 35, 135, 134, 134, 134, 134, 14, 
-	134, 137, 134, 11, 134, 134, 134, 134, 
-	134, 134, 134, 13, 14, 15, 16, 17, 
-	134, 19, 20, 134, 134, 134, 23, 24, 
-	25, 134, 26, 27, 28, 134, 134, 134, 
-	134, 134, 33, 34, 35, 135, 134, 134, 
-	134, 134, 14, 134, 11, 134, 134, 134, 
-	134, 134, 134, 134, 134, 14, 15, 16, 
-	17, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 26, 27, 28, 134, 134, 
-	134, 134, 134, 33, 34, 35, 135, 134, 
-	134, 134, 134, 14, 134, 137, 134, 11, 
-	134, 134, 134, 134, 134, 134, 134, 13, 
-	14, 15, 16, 17, 134, 134, 20, 134, 
-	134, 134, 23, 24, 25, 134, 26, 27, 
-	28, 134, 134, 134, 134, 134, 33, 34, 
-	35, 135, 134, 134, 134, 134, 14, 134, 
-	137, 134, 11, 134, 134, 134, 134, 134, 
-	134, 134, 13, 14, 15, 16, 17, 134, 
-	134, 134, 134, 134, 134, 23, 24, 25, 
-	134, 26, 27, 28, 134, 134, 134, 134, 
-	134, 33, 34, 35, 135, 134, 134, 134, 
-	134, 14, 134, 137, 134, 11, 134, 134, 
-	134, 134, 134, 134, 134, 13, 14, 15, 
-	16, 17, 18, 19, 20, 134, 134, 134, 
-	23, 24, 25, 134, 26, 27, 28, 134, 
-	134, 134, 134, 134, 33, 34, 35, 135, 
-	134, 134, 134, 134, 14, 134, 8, 9, 
-	134, 11, 134, 134, 134, 134, 134, 134, 
-	134, 13, 14, 15, 16, 17, 18, 19, 
-	20, 21, 134, 22, 23, 24, 25, 134, 
-	26, 27, 28, 134, 134, 134, 134, 32, 
-	33, 34, 35, 32, 134, 134, 134, 134, 
-	37, 134, 134, 35, 134, 8, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 11, 134, 8, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 11, 134, 134, 134, 134, 134, 134, 
-	134, 134, 14, 15, 16, 17, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	26, 27, 28, 134, 134, 134, 134, 134, 
-	33, 34, 35, 135, 134, 138, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 11, 
-	134, 10, 11, 134, 4, 134, 134, 134, 
-	4, 134, 134, 134, 134, 134, 8, 9, 
-	10, 11, 134, 134, 134, 134, 134, 134, 
-	134, 13, 14, 15, 16, 17, 18, 19, 
-	20, 21, 8, 22, 23, 24, 25, 134, 
-	26, 27, 28, 134, 29, 30, 134, 32, 
-	33, 34, 35, 32, 134, 134, 134, 134, 
-	37, 134, 134, 35, 134, 11, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	29, 30, 134, 11, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 134, 
-	134, 134, 134, 134, 134, 134, 134, 30, 
-	134, 4, 139, 139, 139, 4, 139, 141, 
-	140, 140, 140, 140, 140, 140, 140, 140, 
-	140, 140, 140, 140, 140, 140, 140, 140, 
-	140, 140, 140, 140, 140, 140, 140, 140, 
-	140, 140, 140, 140, 140, 140, 140, 140, 
-	140, 140, 140, 142, 140, 143, 140, 143, 
-	144, 140, 141, 140, 140, 140, 140, 140, 
-	140, 140, 140, 140, 140, 140, 140, 140, 
-	140, 140, 140, 140, 140, 140, 140, 140, 
-	140, 140, 140, 140, 140, 140, 140, 140, 
-	140, 140, 140, 140, 140, 1, 142, 142, 
-	140, 141, 140, 140, 140, 140, 140, 140, 
-	140, 140, 140, 140, 140, 140, 140, 140, 
-	140, 140, 140, 140, 140, 140, 140, 140, 
-	140, 140, 140, 140, 140, 140, 140, 140, 
-	140, 140, 140, 140, 140, 142, 140, 143, 
-	140, 141, 140, 140, 140, 140, 140, 140, 
-	140, 140, 140, 140, 140, 140, 140, 140, 
-	140, 140, 140, 140, 140, 140, 140, 140, 
-	140, 140, 140, 140, 140, 140, 140, 140, 
-	140, 140, 140, 140, 140, 142, 140, 143, 
-	140, 143, 140, 39, 40, 38, 41, 38, 
-	38, 38, 38, 38, 38, 38, 42, 43, 
-	44, 45, 46, 47, 48, 49, 50, 39, 
-	51, 52, 53, 54, 38, 55, 56, 57, 
-	38, 58, 59, 38, 60, 61, 62, 63, 
-	60, 1, 38, 2, 38, 64, 38, 38, 
-	63, 38, 0
+	5, 37, 5, 5, 38, 5, 40, 41, 
+	39, 42, 39, 39, 39, 39, 39, 39, 
+	39, 43, 44, 45, 46, 47, 48, 49, 
+	50, 51, 40, 52, 53, 54, 55, 39, 
+	56, 57, 58, 39, 59, 60, 39, 61, 
+	62, 63, 64, 61, 39, 39, 39, 39, 
+	65, 39, 39, 64, 39, 40, 41, 39, 
+	42, 39, 39, 39, 39, 39, 39, 39, 
+	43, 44, 45, 46, 47, 48, 49, 50, 
+	51, 40, 52, 53, 54, 55, 39, 56, 
+	57, 58, 39, 39, 39, 39, 61, 62, 
+	63, 64, 61, 39, 39, 39, 39, 65, 
+	39, 39, 64, 39, 40, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 42, 39, 39, 39, 39, 39, 39, 
+	39, 39, 44, 45, 46, 47, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	56, 57, 58, 39, 39, 39, 39, 39, 
+	62, 63, 64, 66, 39, 39, 39, 39, 
+	44, 39, 42, 39, 39, 39, 39, 39, 
+	39, 39, 39, 44, 45, 46, 47, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 56, 57, 58, 39, 39, 39, 39, 
+	39, 62, 63, 64, 66, 39, 42, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	45, 46, 47, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 62, 63, 64, 
+	39, 42, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 46, 47, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	62, 63, 64, 39, 42, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	47, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 62, 63, 64, 39, 42, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 62, 63, 
+	39, 42, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 63, 39, 42, 39, 42, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 45, 
+	46, 47, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 56, 57, 58, 39, 
+	39, 39, 39, 39, 62, 63, 64, 66, 
+	39, 42, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 45, 46, 47, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 57, 58, 39, 39, 39, 39, 39, 
+	62, 63, 64, 66, 39, 42, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 45, 
+	46, 47, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 58, 39, 
+	39, 39, 39, 39, 62, 63, 64, 66, 
+	39, 67, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 42, 39, 
+	42, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 45, 46, 47, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 62, 
+	63, 64, 66, 39, 42, 39, 39, 39, 
+	39, 39, 39, 39, 43, 44, 45, 46, 
+	47, 39, 39, 39, 39, 39, 39, 53, 
+	54, 55, 39, 56, 57, 58, 39, 39, 
+	39, 39, 39, 62, 63, 64, 66, 39, 
+	39, 39, 39, 44, 39, 42, 39, 39, 
+	39, 39, 39, 39, 39, 39, 44, 45, 
+	46, 47, 39, 39, 39, 39, 39, 39, 
+	53, 54, 55, 39, 56, 57, 58, 39, 
+	39, 39, 39, 39, 62, 63, 64, 66, 
+	39, 39, 39, 39, 44, 39, 42, 39, 
+	39, 39, 39, 39, 39, 39, 39, 44, 
+	45, 46, 47, 39, 39, 39, 39, 39, 
+	39, 39, 54, 55, 39, 56, 57, 58, 
+	39, 39, 39, 39, 39, 62, 63, 64, 
+	66, 39, 39, 39, 39, 44, 39, 42, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	44, 45, 46, 47, 39, 39, 39, 39, 
+	39, 39, 39, 39, 55, 39, 56, 57, 
+	58, 39, 39, 39, 39, 39, 62, 63, 
+	64, 66, 39, 39, 39, 39, 44, 39, 
+	68, 39, 42, 39, 39, 39, 39, 39, 
+	39, 39, 43, 44, 45, 46, 47, 39, 
+	49, 50, 39, 39, 39, 53, 54, 55, 
+	39, 56, 57, 58, 39, 39, 39, 39, 
+	39, 62, 63, 64, 66, 39, 39, 39, 
+	39, 44, 39, 42, 39, 39, 39, 39, 
+	39, 39, 39, 39, 44, 45, 46, 47, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 56, 57, 58, 39, 39, 39, 
+	39, 39, 62, 63, 64, 66, 39, 39, 
+	39, 39, 44, 39, 68, 39, 42, 39, 
+	39, 39, 39, 39, 39, 39, 43, 44, 
+	45, 46, 47, 39, 39, 50, 39, 39, 
+	39, 53, 54, 55, 39, 56, 57, 58, 
+	39, 39, 39, 39, 39, 62, 63, 64, 
+	66, 39, 39, 39, 39, 44, 39, 68, 
+	39, 42, 39, 39, 39, 39, 39, 39, 
+	39, 43, 44, 45, 46, 47, 39, 39, 
+	39, 39, 39, 39, 53, 54, 55, 39, 
+	56, 57, 58, 39, 39, 39, 39, 39, 
+	62, 63, 64, 66, 39, 39, 39, 39, 
+	44, 39, 68, 39, 42, 39, 39, 39, 
+	39, 39, 39, 39, 43, 44, 45, 46, 
+	47, 48, 49, 50, 39, 39, 39, 53, 
+	54, 55, 39, 56, 57, 58, 39, 39, 
+	39, 39, 39, 62, 63, 64, 66, 39, 
+	39, 39, 39, 44, 39, 40, 41, 39, 
+	42, 39, 39, 39, 39, 39, 39, 39, 
+	43, 44, 45, 46, 47, 48, 49, 50, 
+	51, 39, 52, 53, 54, 55, 39, 56, 
+	57, 58, 39, 39, 39, 39, 61, 62, 
+	63, 64, 61, 39, 39, 39, 39, 65, 
+	39, 39, 64, 39, 40, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 42, 39, 40, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	42, 39, 39, 39, 39, 39, 39, 39, 
+	39, 44, 45, 46, 47, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 56, 
+	57, 58, 39, 39, 39, 39, 39, 62, 
+	63, 64, 66, 39, 42, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 59, 
+	60, 39, 42, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 39, 39, 
+	39, 39, 39, 39, 39, 39, 60, 39, 
+	4, 70, 69, 71, 69, 69, 69, 69, 
+	69, 69, 69, 72, 73, 74, 75, 76, 
+	77, 78, 79, 80, 4, 81, 82, 83, 
+	84, 69, 85, 86, 87, 69, 69, 69, 
+	69, 88, 89, 90, 91, 92, 69, 69, 
+	69, 69, 93, 69, 69, 94, 69, 4, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 71, 69, 69, 69, 
+	69, 69, 69, 69, 69, 73, 74, 75, 
+	76, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 85, 86, 87, 69, 69, 
+	69, 69, 69, 89, 90, 91, 95, 69, 
+	69, 69, 69, 73, 69, 71, 69, 69, 
+	69, 69, 69, 69, 69, 69, 73, 74, 
+	75, 76, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 85, 86, 87, 69, 
+	69, 69, 69, 69, 89, 90, 91, 95, 
+	69, 71, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 74, 75, 76, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	89, 90, 91, 69, 71, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 75, 
+	76, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 89, 90, 91, 69, 71, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 76, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 89, 90, 
+	91, 69, 71, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 89, 90, 69, 71, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 90, 69, 71, 69, 
+	71, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 74, 75, 76, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 85, 
+	86, 87, 69, 69, 69, 69, 69, 89, 
+	90, 91, 95, 69, 71, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 74, 75, 
+	76, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 86, 87, 69, 69, 
+	69, 69, 69, 89, 90, 91, 95, 69, 
+	71, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 74, 75, 76, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 87, 69, 69, 69, 69, 69, 89, 
+	90, 91, 95, 69, 97, 96, 96, 96, 
+	96, 96, 96, 96, 96, 96, 96, 96, 
+	96, 98, 96, 71, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 74, 75, 76, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 89, 90, 91, 95, 69, 71, 
+	69, 69, 69, 69, 69, 69, 69, 72, 
+	73, 74, 75, 76, 69, 69, 69, 69, 
+	69, 69, 82, 83, 84, 69, 85, 86, 
+	87, 69, 69, 69, 69, 69, 89, 90, 
+	91, 95, 69, 69, 69, 69, 73, 69, 
+	71, 69, 69, 69, 69, 69, 69, 69, 
+	69, 73, 74, 75, 76, 69, 69, 69, 
+	69, 69, 69, 82, 83, 84, 69, 85, 
+	86, 87, 69, 69, 69, 69, 69, 89, 
+	90, 91, 95, 69, 69, 69, 69, 73, 
+	69, 71, 69, 69, 69, 69, 69, 69, 
+	69, 69, 73, 74, 75, 76, 69, 69, 
+	69, 69, 69, 69, 69, 83, 84, 69, 
+	85, 86, 87, 69, 69, 69, 69, 69, 
+	89, 90, 91, 95, 69, 69, 69, 69, 
+	73, 69, 71, 69, 69, 69, 69, 69, 
+	69, 69, 69, 73, 74, 75, 76, 69, 
+	69, 69, 69, 69, 69, 69, 69, 84, 
+	69, 85, 86, 87, 69, 69, 69, 69, 
+	69, 89, 90, 91, 95, 69, 69, 69, 
+	69, 73, 69, 99, 69, 71, 69, 69, 
+	69, 69, 69, 69, 69, 72, 73, 74, 
+	75, 76, 69, 78, 79, 69, 69, 69, 
+	82, 83, 84, 69, 85, 86, 87, 69, 
+	69, 69, 69, 69, 89, 90, 91, 95, 
+	69, 69, 69, 69, 73, 69, 71, 69, 
+	69, 69, 69, 69, 69, 69, 69, 73, 
+	74, 75, 76, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 85, 86, 87, 
+	69, 69, 69, 69, 69, 89, 90, 91, 
+	95, 69, 69, 69, 69, 73, 69, 99, 
+	69, 71, 69, 69, 69, 69, 69, 69, 
+	69, 72, 73, 74, 75, 76, 69, 69, 
+	79, 69, 69, 69, 82, 83, 84, 69, 
+	85, 86, 87, 69, 69, 69, 69, 69, 
+	89, 90, 91, 95, 69, 69, 69, 69, 
+	73, 69, 99, 69, 71, 69, 69, 69, 
+	69, 69, 69, 69, 72, 73, 74, 75, 
+	76, 69, 69, 69, 69, 69, 69, 82, 
+	83, 84, 69, 85, 86, 87, 69, 69, 
+	69, 69, 69, 89, 90, 91, 95, 69, 
+	69, 69, 69, 73, 69, 99, 69, 71, 
+	69, 69, 69, 69, 69, 69, 69, 72, 
+	73, 74, 75, 76, 77, 78, 79, 69, 
+	69, 69, 82, 83, 84, 69, 85, 86, 
+	87, 69, 69, 69, 69, 69, 89, 90, 
+	91, 95, 69, 69, 69, 69, 73, 69, 
+	4, 70, 69, 71, 69, 69, 69, 69, 
+	69, 69, 69, 72, 73, 74, 75, 76, 
+	77, 78, 79, 80, 69, 81, 82, 83, 
+	84, 69, 85, 86, 87, 69, 69, 69, 
+	69, 88, 89, 90, 91, 92, 69, 69, 
+	69, 69, 93, 69, 69, 94, 69, 4, 
+	100, 100, 100, 100, 100, 100, 100, 100, 
+	100, 100, 100, 100, 101, 100, 4, 96, 
+	96, 96, 96, 96, 96, 96, 96, 96, 
+	96, 96, 96, 98, 96, 4, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 71, 69, 69, 69, 69, 69, 
+	69, 69, 69, 73, 74, 75, 76, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 85, 86, 87, 69, 69, 69, 69, 
+	69, 89, 90, 91, 95, 69, 101, 100, 
+	103, 104, 102, 6, 105, 105, 105, 105, 
+	105, 105, 105, 105, 105, 106, 105, 107, 
+	108, 69, 71, 69, 69, 69, 69, 69, 
+	69, 69, 109, 110, 111, 112, 113, 114, 
+	115, 116, 117, 107, 118, 119, 120, 121, 
+	69, 122, 123, 124, 69, 59, 60, 69, 
+	125, 126, 127, 128, 129, 69, 69, 69, 
+	69, 130, 69, 69, 131, 69, 107, 108, 
+	69, 71, 69, 69, 69, 69, 69, 69, 
+	69, 109, 110, 111, 112, 113, 114, 115, 
+	116, 117, 107, 118, 119, 120, 121, 69, 
+	122, 123, 124, 69, 69, 69, 69, 125, 
+	126, 127, 128, 129, 69, 69, 69, 69, 
+	130, 69, 69, 131, 69, 107, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 71, 69, 69, 69, 69, 69, 
+	69, 69, 69, 110, 111, 112, 113, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 122, 123, 124, 69, 69, 69, 69, 
+	69, 126, 127, 128, 132, 69, 69, 69, 
+	69, 110, 69, 71, 69, 69, 69, 69, 
+	69, 69, 69, 69, 110, 111, 112, 113, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 122, 123, 124, 69, 69, 69, 
+	69, 69, 126, 127, 128, 132, 69, 71, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 111, 112, 113, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 126, 127, 
+	128, 69, 71, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 112, 113, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 126, 127, 128, 69, 71, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 113, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 126, 127, 128, 69, 
+	71, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 126, 
+	127, 69, 71, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 127, 69, 71, 69, 71, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	111, 112, 113, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 122, 123, 124, 
+	69, 69, 69, 69, 69, 126, 127, 128, 
+	132, 69, 71, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 111, 112, 113, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 123, 124, 69, 69, 69, 69, 
+	69, 126, 127, 128, 132, 69, 71, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	111, 112, 113, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 124, 
+	69, 69, 69, 69, 69, 126, 127, 128, 
+	132, 69, 133, 96, 96, 96, 96, 96, 
+	96, 96, 96, 96, 96, 96, 96, 98, 
+	96, 71, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 111, 112, 113, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	126, 127, 128, 132, 69, 71, 69, 69, 
+	69, 69, 69, 69, 69, 109, 110, 111, 
+	112, 113, 69, 69, 69, 69, 69, 69, 
+	119, 120, 121, 69, 122, 123, 124, 69, 
+	69, 69, 69, 69, 126, 127, 128, 132, 
+	69, 69, 69, 69, 110, 69, 71, 69, 
+	69, 69, 69, 69, 69, 69, 69, 110, 
+	111, 112, 113, 69, 69, 69, 69, 69, 
+	69, 119, 120, 121, 69, 122, 123, 124, 
+	69, 69, 69, 69, 69, 126, 127, 128, 
+	132, 69, 69, 69, 69, 110, 69, 71, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	110, 111, 112, 113, 69, 69, 69, 69, 
+	69, 69, 69, 120, 121, 69, 122, 123, 
+	124, 69, 69, 69, 69, 69, 126, 127, 
+	128, 132, 69, 69, 69, 69, 110, 69, 
+	71, 69, 69, 69, 69, 69, 69, 69, 
+	69, 110, 111, 112, 113, 69, 69, 69, 
+	69, 69, 69, 69, 69, 121, 69, 122, 
+	123, 124, 69, 69, 69, 69, 69, 126, 
+	127, 128, 132, 69, 69, 69, 69, 110, 
+	69, 134, 69, 71, 69, 69, 69, 69, 
+	69, 69, 69, 109, 110, 111, 112, 113, 
+	69, 115, 116, 69, 69, 69, 119, 120, 
+	121, 69, 122, 123, 124, 69, 69, 69, 
+	69, 69, 126, 127, 128, 132, 69, 69, 
+	69, 69, 110, 69, 71, 69, 69, 69, 
+	69, 69, 69, 69, 69, 110, 111, 112, 
+	113, 69, 69, 69, 69, 69, 69, 69, 
+	69, 69, 69, 122, 123, 124, 69, 69, 
+	69, 69, 69, 126, 127, 128, 132, 69, 
+	69, 69, 69, 110, 69, 134, 69, 71, 
+	69, 69, 69, 69, 69, 69, 69, 109, 
+	110, 111, 112, 113, 69, 69, 116, 69, 
+	69, 69, 119, 120, 121, 69, 122, 123, 
+	124, 69, 69, 69, 69, 69, 126, 127, 
+	128, 132, 69, 69, 69, 69, 110, 69, 
+	134, 69, 71, 69, 69, 69, 69, 69, 
+	69, 69, 109, 110, 111, 112, 113, 69, 
+	69, 69, 69, 69, 69, 119, 120, 121, 
+	69, 122, 123, 124, 69, 69, 69, 69, 
+	69, 126, 127, 128, 132, 69, 69, 69, 
+	69, 110, 69, 134, 69, 71, 69, 69, 
+	69, 69, 69, 69, 69, 109, 110, 111, 
+	112, 113, 114, 115, 116, 69, 69, 69, 
+	119, 120, 121, 69, 122, 123, 124, 69, 
+	69, 69, 69, 69, 126, 127, 128, 132, 
+	69, 69, 69, 69, 110, 69, 107, 108, 
+	69, 71, 69, 69, 69, 69, 69, 69, 
+	69, 109, 110, 111, 112, 113, 114, 115, 
+	116, 117, 69, 118, 119, 120, 121, 69, 
+	122, 123, 124, 69, 69, 69, 69, 125, 
+	126, 127, 128, 129, 69, 69, 69, 69, 
+	130, 69, 69, 131, 69, 107, 100, 100, 
+	100, 100, 100, 100, 100, 100, 100, 100, 
+	100, 100, 101, 100, 107, 96, 96, 96, 
+	96, 96, 96, 96, 96, 96, 96, 96, 
+	96, 98, 96, 107, 69, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 69, 
+	71, 69, 69, 69, 69, 69, 69, 69, 
+	69, 110, 111, 112, 113, 69, 69, 69, 
+	69, 69, 69, 69, 69, 69, 69, 122, 
+	123, 124, 69, 69, 69, 69, 69, 126, 
+	127, 128, 132, 69, 101, 100, 8, 9, 
+	135, 11, 135, 135, 135, 135, 135, 135, 
+	135, 13, 14, 15, 16, 17, 18, 19, 
+	20, 21, 8, 22, 23, 24, 25, 135, 
+	26, 27, 28, 135, 135, 135, 135, 32, 
+	33, 34, 38, 32, 135, 135, 135, 135, 
+	37, 135, 135, 38, 135, 8, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 11, 135, 135, 135, 135, 135, 
+	135, 135, 135, 14, 15, 16, 17, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 26, 27, 28, 135, 135, 135, 135, 
+	135, 33, 34, 38, 136, 135, 135, 135, 
+	135, 14, 135, 11, 135, 135, 135, 135, 
+	135, 135, 135, 135, 14, 15, 16, 17, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 26, 27, 28, 135, 135, 135, 
+	135, 135, 33, 34, 38, 136, 135, 11, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 15, 16, 17, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 33, 34, 
+	38, 135, 11, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 16, 17, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 33, 34, 38, 135, 11, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 17, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 33, 34, 38, 135, 
+	11, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 33, 
+	34, 135, 11, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 34, 135, 11, 137, 11, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	15, 16, 17, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 26, 27, 28, 
+	135, 135, 135, 135, 135, 33, 34, 38, 
+	136, 135, 11, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 15, 16, 17, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 27, 28, 135, 135, 135, 135, 
+	135, 33, 34, 38, 136, 135, 11, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	15, 16, 17, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 28, 
+	135, 135, 135, 135, 135, 33, 34, 38, 
+	136, 135, 138, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 11, 
+	135, 11, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 15, 16, 17, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	33, 34, 38, 136, 135, 11, 135, 135, 
+	135, 135, 135, 135, 135, 13, 14, 15, 
+	16, 17, 135, 135, 135, 135, 135, 135, 
+	23, 24, 25, 135, 26, 27, 28, 135, 
+	135, 135, 135, 135, 33, 34, 38, 136, 
+	135, 135, 135, 135, 14, 135, 11, 135, 
+	135, 135, 135, 135, 135, 135, 135, 14, 
+	15, 16, 17, 135, 135, 135, 135, 135, 
+	135, 23, 24, 25, 135, 26, 27, 28, 
+	135, 135, 135, 135, 135, 33, 34, 38, 
+	136, 135, 135, 135, 135, 14, 135, 11, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	14, 15, 16, 17, 135, 135, 135, 135, 
+	135, 135, 135, 24, 25, 135, 26, 27, 
+	28, 135, 135, 135, 135, 135, 33, 34, 
+	38, 136, 135, 135, 135, 135, 14, 135, 
+	11, 135, 135, 135, 135, 135, 135, 135, 
+	135, 14, 15, 16, 17, 135, 135, 135, 
+	135, 135, 135, 135, 135, 25, 135, 26, 
+	27, 28, 135, 135, 135, 135, 135, 33, 
+	34, 38, 136, 135, 135, 135, 135, 14, 
+	135, 139, 135, 11, 135, 135, 135, 135, 
+	135, 135, 135, 13, 14, 15, 16, 17, 
+	135, 19, 20, 135, 135, 135, 23, 24, 
+	25, 135, 26, 27, 28, 135, 135, 135, 
+	135, 135, 33, 34, 38, 136, 135, 135, 
+	135, 135, 14, 135, 11, 135, 135, 135, 
+	135, 135, 135, 135, 135, 14, 15, 16, 
+	17, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 26, 27, 28, 135, 135, 
+	135, 135, 135, 33, 34, 38, 136, 135, 
+	135, 135, 135, 14, 135, 139, 135, 11, 
+	135, 135, 135, 135, 135, 135, 135, 13, 
+	14, 15, 16, 17, 135, 135, 20, 135, 
+	135, 135, 23, 24, 25, 135, 26, 27, 
+	28, 135, 135, 135, 135, 135, 33, 34, 
+	38, 136, 135, 135, 135, 135, 14, 135, 
+	139, 135, 11, 135, 135, 135, 135, 135, 
+	135, 135, 13, 14, 15, 16, 17, 135, 
+	135, 135, 135, 135, 135, 23, 24, 25, 
+	135, 26, 27, 28, 135, 135, 135, 135, 
+	135, 33, 34, 38, 136, 135, 135, 135, 
+	135, 14, 135, 139, 135, 11, 135, 135, 
+	135, 135, 135, 135, 135, 13, 14, 15, 
+	16, 17, 18, 19, 20, 135, 135, 135, 
+	23, 24, 25, 135, 26, 27, 28, 135, 
+	135, 135, 135, 135, 33, 34, 38, 136, 
+	135, 135, 135, 135, 14, 135, 8, 9, 
+	135, 11, 135, 135, 135, 135, 135, 135, 
+	135, 13, 14, 15, 16, 17, 18, 19, 
+	20, 21, 135, 22, 23, 24, 25, 135, 
+	26, 27, 28, 135, 135, 135, 135, 32, 
+	33, 34, 38, 32, 135, 135, 135, 135, 
+	37, 135, 135, 38, 135, 8, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 11, 135, 8, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 11, 135, 135, 135, 135, 135, 135, 
+	135, 135, 14, 15, 16, 17, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	26, 27, 28, 135, 135, 135, 135, 135, 
+	33, 34, 38, 136, 135, 140, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 11, 
+	135, 10, 11, 135, 4, 135, 135, 135, 
+	4, 135, 135, 135, 135, 135, 8, 9, 
+	10, 11, 135, 135, 135, 135, 135, 135, 
+	135, 13, 14, 15, 16, 17, 18, 19, 
+	20, 21, 8, 22, 23, 24, 25, 135, 
+	26, 27, 28, 135, 29, 30, 135, 32, 
+	33, 34, 38, 32, 135, 135, 135, 135, 
+	37, 135, 135, 38, 135, 11, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	29, 30, 135, 11, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 135, 
+	135, 135, 135, 135, 135, 135, 135, 30, 
+	135, 4, 141, 141, 141, 4, 141, 143, 
+	142, 142, 142, 142, 142, 142, 142, 142, 
+	142, 142, 142, 142, 142, 142, 142, 142, 
+	142, 142, 142, 142, 142, 142, 142, 142, 
+	142, 142, 142, 142, 142, 142, 142, 142, 
+	142, 142, 142, 144, 142, 145, 142, 145, 
+	146, 142, 143, 142, 142, 142, 142, 142, 
+	142, 142, 142, 142, 142, 142, 142, 142, 
+	142, 142, 142, 142, 142, 142, 142, 142, 
+	142, 142, 142, 142, 142, 142, 142, 142, 
+	142, 142, 142, 142, 142, 1, 144, 144, 
+	142, 143, 142, 142, 142, 142, 142, 142, 
+	142, 142, 142, 142, 142, 142, 142, 142, 
+	142, 142, 142, 142, 142, 142, 142, 142, 
+	142, 142, 142, 142, 142, 142, 142, 142, 
+	142, 142, 142, 142, 142, 144, 142, 145, 
+	142, 143, 142, 142, 142, 142, 142, 142, 
+	142, 142, 142, 142, 142, 142, 142, 142, 
+	142, 142, 142, 142, 142, 142, 142, 142, 
+	142, 142, 142, 142, 142, 142, 142, 142, 
+	142, 142, 142, 142, 142, 144, 142, 145, 
+	142, 145, 142, 40, 41, 39, 42, 39, 
+	39, 39, 39, 39, 39, 39, 43, 44, 
+	45, 46, 47, 48, 49, 50, 51, 40, 
+	52, 53, 54, 55, 39, 56, 57, 58, 
+	39, 59, 60, 39, 61, 62, 63, 64, 
+	61, 1, 39, 2, 39, 65, 39, 39, 
+	64, 39, 0
 };
 
 static const char _use_syllable_machine_trans_targs[] = {
@@ -723,21 +723,21 @@ static const char _use_syllable_machine_trans_targs[] = {
 	90, 91, 116, 1, 118, 104, 92, 93, 
 	94, 95, 108, 110, 111, 112, 113, 105, 
 	106, 107, 99, 100, 101, 119, 120, 121, 
-	114, 96, 97, 98, 126, 115, 1, 3, 
-	4, 1, 17, 5, 6, 7, 8, 21, 
-	23, 24, 25, 26, 18, 19, 20, 12, 
-	13, 14, 29, 30, 27, 9, 10, 11, 
-	28, 15, 16, 22, 1, 32, 1, 45, 
-	33, 34, 35, 36, 49, 51, 52, 53, 
-	54, 46, 47, 48, 40, 41, 42, 55, 
-	37, 38, 39, 56, 57, 58, 43, 1, 
-	44, 1, 50, 1, 1, 1, 60, 1, 
-	1, 1, 62, 63, 76, 64, 65, 66, 
-	67, 80, 82, 83, 84, 85, 77, 78, 
-	79, 71, 72, 73, 86, 68, 69, 70, 
-	87, 88, 89, 74, 75, 81, 1, 102, 
-	103, 109, 117, 1, 1, 1, 123, 124, 
-	125
+	114, 96, 97, 98, 126, 115, 98, 1, 
+	3, 4, 1, 17, 5, 6, 7, 8, 
+	21, 23, 24, 25, 26, 18, 19, 20, 
+	12, 13, 14, 29, 30, 27, 9, 10, 
+	11, 28, 15, 16, 22, 1, 32, 1, 
+	45, 33, 34, 35, 36, 49, 51, 52, 
+	53, 54, 46, 47, 48, 40, 41, 42, 
+	55, 37, 38, 39, 56, 57, 58, 43, 
+	1, 44, 1, 50, 1, 1, 1, 60, 
+	1, 1, 1, 62, 63, 76, 64, 65, 
+	66, 67, 80, 82, 83, 84, 85, 77, 
+	78, 79, 71, 72, 73, 86, 68, 69, 
+	70, 87, 88, 89, 74, 75, 81, 1, 
+	102, 1, 103, 109, 117, 1, 1, 1, 
+	123, 124, 125
 };
 
 static const char _use_syllable_machine_trans_actions[] = {
@@ -745,21 +745,21 @@ static const char _use_syllable_machine_trans_actions[] = {
 	0, 0, 0, 5, 0, 0, 0, 0, 
 	0, 0, 0, 0, 0, 0, 0, 0, 
 	0, 0, 0, 0, 0, 0, 0, 0, 
-	0, 0, 0, 0, 6, 0, 7, 0, 
-	0, 8, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 6, 7, 0, 8, 9, 
+	0, 0, 10, 0, 0, 0, 0, 0, 
 	0, 0, 0, 0, 0, 0, 0, 0, 
 	0, 0, 0, 0, 0, 0, 0, 0, 
-	0, 0, 0, 0, 9, 0, 10, 0, 
+	0, 0, 0, 0, 0, 11, 0, 12, 
 	0, 0, 0, 0, 0, 0, 0, 0, 
 	0, 0, 0, 0, 0, 0, 0, 0, 
-	0, 0, 0, 0, 0, 0, 0, 11, 
-	0, 12, 0, 13, 14, 15, 0, 16, 
-	17, 18, 0, 0, 0, 0, 0, 0, 
 	0, 0, 0, 0, 0, 0, 0, 0, 
+	13, 0, 14, 0, 15, 16, 17, 0, 
+	18, 19, 20, 0, 0, 0, 0, 0, 
 	0, 0, 0, 0, 0, 0, 0, 0, 
-	0, 0, 0, 0, 0, 0, 19, 0, 
-	0, 0, 0, 20, 21, 22, 0, 0, 
-	0
+	0, 0, 0, 0, 0, 0, 0, 0, 
+	0, 0, 0, 0, 0, 0, 0, 21, 
+	0, 22, 0, 0, 0, 23, 24, 25, 
+	0, 0, 0
 };
 
 static const char _use_syllable_machine_to_state_actions[] = {
@@ -801,22 +801,22 @@ static const char _use_syllable_machine_from_state_actions[] = {
 };
 
 static const short _use_syllable_machine_eof_trans[] = {
-	1, 0, 39, 39, 39, 39, 39, 39, 
-	39, 39, 39, 39, 39, 39, 39, 39, 
-	39, 39, 39, 39, 39, 39, 39, 39, 
-	39, 39, 39, 39, 39, 39, 39, 69, 
-	69, 69, 69, 69, 69, 69, 69, 69, 
-	69, 69, 69, 96, 69, 69, 69, 69, 
-	69, 69, 69, 69, 69, 69, 69, 100, 
-	96, 69, 100, 102, 105, 69, 69, 69, 
-	69, 69, 69, 69, 69, 69, 69, 69, 
-	69, 69, 96, 69, 69, 69, 69, 69, 
-	69, 69, 69, 69, 69, 69, 100, 96, 
-	69, 100, 135, 135, 135, 135, 135, 135, 
-	135, 135, 135, 135, 135, 135, 135, 135, 
-	135, 135, 135, 135, 135, 135, 135, 135, 
-	135, 135, 135, 135, 135, 135, 135, 135, 
-	135, 140, 141, 141, 141, 141, 39
+	1, 0, 40, 40, 40, 40, 40, 40, 
+	40, 40, 40, 40, 40, 40, 40, 40, 
+	40, 40, 40, 40, 40, 40, 40, 40, 
+	40, 40, 40, 40, 40, 40, 40, 70, 
+	70, 70, 70, 70, 70, 70, 70, 70, 
+	70, 70, 70, 97, 70, 70, 70, 70, 
+	70, 70, 70, 70, 70, 70, 70, 101, 
+	97, 70, 101, 103, 106, 70, 70, 70, 
+	70, 70, 70, 70, 70, 70, 70, 70, 
+	70, 70, 97, 70, 70, 70, 70, 70, 
+	70, 70, 70, 70, 70, 70, 101, 97, 
+	70, 101, 136, 136, 136, 136, 136, 136, 
+	136, 136, 138, 136, 136, 136, 136, 136, 
+	136, 136, 136, 136, 136, 136, 136, 136, 
+	136, 136, 136, 136, 136, 136, 136, 136, 
+	136, 142, 143, 143, 143, 143, 40
 };
 
 static const int use_syllable_machine_start = 1;
@@ -830,7 +830,7 @@ static const int use_syllable_machine_en_main = 1;
 
 
 
-#line 185 "hb-ot-shaper-use-machine.rl"
+#line 186 "hb-ot-shaper-use-machine.rl"
 
 
 #define found_syllable(syllable_type) \
@@ -937,7 +937,7 @@ find_syllables_use (hb_buffer_t *buffer)
 	act = 0;
 	}
 
-#line 285 "hb-ot-shaper-use-machine.rl"
+#line 286 "hb-ot-shaper-use-machine.rl"
 
 
   unsigned int syllable_serial = 1;
@@ -974,87 +974,111 @@ _eof_trans:
 		goto _again;
 
 	switch ( _use_syllable_machine_trans_actions[_trans] ) {
-	case 6:
+	case 7:
 #line 1 "NONE"
 	{te = p+1;}
 	break;
-	case 14:
+	case 16:
 #line 173 "hb-ot-shaper-use-machine.rl"
 	{te = p+1;{ found_syllable (use_virama_terminated_cluster); }}
 	break;
-	case 12:
+	case 14:
 #line 174 "hb-ot-shaper-use-machine.rl"
 	{te = p+1;{ found_syllable (use_sakot_terminated_cluster); }}
 	break;
-	case 10:
+	case 12:
 #line 175 "hb-ot-shaper-use-machine.rl"
 	{te = p+1;{ found_syllable (use_standard_cluster); }}
 	break;
-	case 18:
+	case 20:
 #line 176 "hb-ot-shaper-use-machine.rl"
 	{te = p+1;{ found_syllable (use_number_joiner_terminated_cluster); }}
 	break;
-	case 16:
+	case 18:
 #line 177 "hb-ot-shaper-use-machine.rl"
 	{te = p+1;{ found_syllable (use_numeral_cluster); }}
 	break;
-	case 8:
+	case 10:
 #line 178 "hb-ot-shaper-use-machine.rl"
 	{te = p+1;{ found_syllable (use_symbol_cluster); }}
 	break;
-	case 22:
+	case 25:
 #line 179 "hb-ot-shaper-use-machine.rl"
 	{te = p+1;{ found_syllable (use_hieroglyph_cluster); }}
 	break;
 	case 5:
-#line 180 "hb-ot-shaper-use-machine.rl"
+#line 181 "hb-ot-shaper-use-machine.rl"
 	{te = p+1;{ found_syllable (use_broken_cluster); buffer->scratch_flags |= HB_BUFFER_SCRATCH_FLAG_HAS_BROKEN_SYLLABLE; }}
 	break;
 	case 4:
-#line 181 "hb-ot-shaper-use-machine.rl"
+#line 182 "hb-ot-shaper-use-machine.rl"
 	{te = p+1;{ found_syllable (use_non_cluster); }}
 	break;
-	case 13:
+	case 15:
 #line 173 "hb-ot-shaper-use-machine.rl"
 	{te = p;p--;{ found_syllable (use_virama_terminated_cluster); }}
 	break;
-	case 11:
+	case 13:
 #line 174 "hb-ot-shaper-use-machine.rl"
 	{te = p;p--;{ found_syllable (use_sakot_terminated_cluster); }}
 	break;
-	case 9:
+	case 11:
 #line 175 "hb-ot-shaper-use-machine.rl"
 	{te = p;p--;{ found_syllable (use_standard_cluster); }}
 	break;
-	case 17:
+	case 19:
 #line 176 "hb-ot-shaper-use-machine.rl"
 	{te = p;p--;{ found_syllable (use_number_joiner_terminated_cluster); }}
 	break;
-	case 15:
+	case 17:
 #line 177 "hb-ot-shaper-use-machine.rl"
 	{te = p;p--;{ found_syllable (use_numeral_cluster); }}
 	break;
-	case 7:
+	case 9:
 #line 178 "hb-ot-shaper-use-machine.rl"
 	{te = p;p--;{ found_syllable (use_symbol_cluster); }}
 	break;
-	case 21:
+	case 24:
 #line 179 "hb-ot-shaper-use-machine.rl"
 	{te = p;p--;{ found_syllable (use_hieroglyph_cluster); }}
 	break;
-	case 19:
-#line 180 "hb-ot-shaper-use-machine.rl"
+	case 21:
+#line 181 "hb-ot-shaper-use-machine.rl"
 	{te = p;p--;{ found_syllable (use_broken_cluster); buffer->scratch_flags |= HB_BUFFER_SCRATCH_FLAG_HAS_BROKEN_SYLLABLE; }}
 	break;
-	case 20:
-#line 181 "hb-ot-shaper-use-machine.rl"
+	case 23:
+#line 182 "hb-ot-shaper-use-machine.rl"
 	{te = p;p--;{ found_syllable (use_non_cluster); }}
 	break;
 	case 1:
 #line 178 "hb-ot-shaper-use-machine.rl"
 	{{p = ((te))-1;}{ found_syllable (use_symbol_cluster); }}
 	break;
-#line 1058 "hb-ot-shaper-use-machine.hh"
+	case 22:
+#line 1 "NONE"
+	{	switch( act ) {
+	case 8:
+	{{p = ((te))-1;} found_syllable (use_non_cluster); }
+	break;
+	case 9:
+	{{p = ((te))-1;} found_syllable (use_broken_cluster); buffer->scratch_flags |= HB_BUFFER_SCRATCH_FLAG_HAS_BROKEN_SYLLABLE; }
+	break;
+	}
+	}
+	break;
+	case 6:
+#line 1 "NONE"
+	{te = p+1;}
+#line 180 "hb-ot-shaper-use-machine.rl"
+	{act = 8;}
+	break;
+	case 8:
+#line 1 "NONE"
+	{te = p+1;}
+#line 181 "hb-ot-shaper-use-machine.rl"
+	{act = 9;}
+	break;
+#line 1082 "hb-ot-shaper-use-machine.hh"
 	}
 
 _again:
@@ -1063,7 +1087,7 @@ _again:
 #line 1 "NONE"
 	{ts = 0;}
 	break;
-#line 1067 "hb-ot-shaper-use-machine.hh"
+#line 1091 "hb-ot-shaper-use-machine.hh"
 	}
 
 	if ( ++p != pe )
@@ -1079,7 +1103,7 @@ _again:
 
 	}
 
-#line 290 "hb-ot-shaper-use-machine.rl"
+#line 291 "hb-ot-shaper-use-machine.rl"
 
 }
 
diff --git a/src/hb-ot-shaper-use-machine.rl b/src/hb-ot-shaper-use-machine.rl
index f5a2091a3..4460e35e6 100644
--- a/src/hb-ot-shaper-use-machine.rl
+++ b/src/hb-ot-shaper-use-machine.rl
@@ -177,6 +177,7 @@ main := |*
 	numeral_cluster ZWNJ?			=> { found_syllable (use_numeral_cluster); };
 	symbol_cluster ZWNJ?			=> { found_syllable (use_symbol_cluster); };
 	hieroglyph_cluster ZWNJ?		=> { found_syllable (use_hieroglyph_cluster); };
+	FMPst					=> { found_syllable (use_non_cluster); };
 	broken_cluster ZWNJ?			=> { found_syllable (use_broken_cluster); buffer->scratch_flags |= HB_BUFFER_SCRATCH_FLAG_HAS_BROKEN_SYLLABLE; };
 	other					=> { found_syllable (use_non_cluster); };
 *|;
diff --git a/src/hb-ot-tag-table.hh b/src/hb-ot-tag-table.hh
index 66ba9f1b0..26eb34f5c 100644
--- a/src/hb-ot-tag-table.hh
+++ b/src/hb-ot-tag-table.hh
@@ -6,8 +6,8 @@
  *
  * on files with these headers:
  *
- * <meta name="updated_at" content="2024-07-07 12:57 AM" />
- * File-Date: 2024-06-14
+ * <meta name="updated_at" content="2024-12-05 07:13 PM" />
+ * File-Date: 2024-11-19
  */
 
 #ifndef HB_OT_TAG_TABLE_HH
@@ -830,6 +830,7 @@ static const LangTag ot_languages3[] = {
   {HB_TAG('k','f','x',' '),	HB_TAG('K','U','L',' ')},	/* Kullu Pahari -> Kulvi */
   {HB_TAG('k','f','y',' '),	HB_TAG('K','M','N',' ')},	/* Kumaoni */
   {HB_TAG('k','g','e',' '),	HB_TAG_NONE	       },	/* Komering != Khutsuri Georgian */
+/*{HB_TAG('k','g','f',' '),	HB_TAG('K','G','F',' ')},*/	/* Kube */
   {HB_TAG('k','h','a',' '),	HB_TAG('K','S','I',' ')},	/* Khasi */
   {HB_TAG('k','h','b',' '),	HB_TAG('X','B','D',' ')},	/* Lü */
   {HB_TAG('k','h','k',' '),	HB_TAG('M','N','G',' ')},	/* Halh Mongolian -> Mongolian */
@@ -855,6 +856,7 @@ static const LangTag ot_languages3[] = {
   {HB_TAG('k','l','m',' '),	HB_TAG_NONE	       },	/* Migum != Kalmyk */
   {HB_TAG('k','l','n',' '),	HB_TAG('K','A','L',' ')},	/* Kalenjin [macrolanguage] */
   {HB_TAG('k','m','b',' '),	HB_TAG('M','B','N',' ')},	/* Kimbundu -> Mbundu */
+/*{HB_TAG('k','m','g',' '),	HB_TAG('K','M','G',' ')},*/	/* Kâte */
   {HB_TAG('k','m','n',' '),	HB_TAG_NONE	       },	/* Awtuw != Kumaoni */
   {HB_TAG('k','m','o',' '),	HB_TAG_NONE	       },	/* Kwoma != Komo */
   {HB_TAG('k','m','r',' '),	HB_TAG('K','U','R',' ')},	/* Northern Kurdish -> Kurdish */
@@ -898,6 +900,7 @@ static const LangTag ot_languages3[] = {
   {HB_TAG('k','s','i',' '),	HB_TAG_NONE	       },	/* Krisa != Khasi */
   {HB_TAG('k','s','m',' '),	HB_TAG_NONE	       },	/* Kumba != Kildin Sami */
   {HB_TAG('k','s','s',' '),	HB_TAG('K','I','S',' ')},	/* Southern Kisi -> Kisii */
+/*{HB_TAG('k','s','u',' '),	HB_TAG('K','S','U',' ')},*/	/* Khamyang */
   {HB_TAG('k','s','w',' '),	HB_TAG('K','S','W',' ')},	/* S’gaw Karen */
   {HB_TAG('k','s','w',' '),	HB_TAG('K','R','N',' ')},	/* S'gaw Karen -> Karen */
   {HB_TAG('k','t','b',' '),	HB_TAG('K','E','B',' ')},	/* Kambaata -> Kebena */
@@ -911,6 +914,7 @@ static const LangTag ot_languages3[] = {
   {HB_TAG('k','u','y',' '),	HB_TAG_NONE	       },	/* Kuuku-Ya'u != Kuy */
   {HB_TAG('k','v','b',' '),	HB_TAG('M','L','Y',' ')},	/* Kubu -> Malay */
   {HB_TAG('k','v','l',' '),	HB_TAG('K','R','N',' ')},	/* Kayaw -> Karen */
+  {HB_TAG('k','v','q',' '),	HB_TAG('K','V','Q',' ')},	/* Geba Karen */
   {HB_TAG('k','v','q',' '),	HB_TAG('K','R','N',' ')},	/* Geba Karen -> Karen */
   {HB_TAG('k','v','r',' '),	HB_TAG('M','L','Y',' ')},	/* Kerinci -> Malay */
   {HB_TAG('k','v','t',' '),	HB_TAG('K','R','N',' ')},	/* Lahta Karen -> Karen */
@@ -1146,6 +1150,7 @@ static const LangTag ot_languages3[] = {
   {HB_TAG('n','o','d',' '),	HB_TAG('N','T','A',' ')},	/* Northern Thai -> Northern Tai */
 /*{HB_TAG('n','o','e',' '),	HB_TAG('N','O','E',' ')},*/	/* Nimadi */
 /*{HB_TAG('n','o','g',' '),	HB_TAG('N','O','G',' ')},*/	/* Nogai */
+/*{HB_TAG('n','o','p',' '),	HB_TAG('N','O','P',' ')},*/	/* Numanggang */
 /*{HB_TAG('n','o','v',' '),	HB_TAG('N','O','V',' ')},*/	/* Novial */
   {HB_TAG('n','p','i',' '),	HB_TAG('N','E','P',' ')},	/* Nepali */
   {HB_TAG('n','p','l',' '),	HB_TAG('N','A','H',' ')},	/* Southeastern Puebla Nahuatl -> Nahuatl */
@@ -1156,6 +1161,7 @@ static const LangTag ot_languages3[] = {
   {HB_TAG('n','s','u',' '),	HB_TAG('N','A','H',' ')},	/* Sierra Negra Nahuatl -> Nahuatl */
   {HB_TAG('n','t','o',' '),	HB_TAG_NONE	       },	/* Ntomba != Esperanto */
   {HB_TAG('n','u','e',' '),	HB_TAG('B','A','D','0')},	/* Ngundu -> Banda */
+/*{HB_TAG('n','u','k',' '),	HB_TAG('N','U','K',' ')},*/	/* Nuu-chah-nulth */
   {HB_TAG('n','u','u',' '),	HB_TAG('B','A','D','0')},	/* Ngbundu -> Banda */
   {HB_TAG('n','u','z',' '),	HB_TAG('N','A','H',' ')},	/* Tlamacazapa Nahuatl -> Nahuatl */
   {HB_TAG('n','w','e',' '),	HB_TAG('B','M','L',' ')},	/* Ngwe -> Bamileke */
@@ -1399,8 +1405,10 @@ static const LangTag ot_languages3[] = {
   {HB_TAG('s','i','z',' '),	HB_TAG('B','B','R',' ')},	/* Siwi -> Berber */
 /*{HB_TAG('s','j','a',' '),	HB_TAG('S','J','A',' ')},*/	/* Epena */
   {HB_TAG('s','j','d',' '),	HB_TAG('K','S','M',' ')},	/* Kildin Sami */
+/*{HB_TAG('s','j','e',' '),	HB_TAG('S','J','E',' ')},*/	/* Pite Sami */
   {HB_TAG('s','j','o',' '),	HB_TAG('S','I','B',' ')},	/* Xibe -> Sibe */
   {HB_TAG('s','j','s',' '),	HB_TAG('B','B','R',' ')},	/* Senhaja De Srair -> Berber */
+/*{HB_TAG('s','j','u',' '),	HB_TAG('S','J','U',' ')},*/	/* Ume Sami */
   {HB_TAG('s','k','g',' '),	HB_TAG('M','L','G',' ')},	/* Sakalava Malagasy -> Malagasy */
   {HB_TAG('s','k','r',' '),	HB_TAG('S','R','K',' ')},	/* Saraiki */
   {HB_TAG('s','k','s',' '),	HB_TAG_NONE	       },	/* Maia != Skolt Sami */
@@ -1461,6 +1469,7 @@ static const LangTag ot_languages3[] = {
   {HB_TAG('t','a','q',' '),	HB_TAG('B','B','R',' ')},	/* Tamasheq -> Berber */
   {HB_TAG('t','a','s',' '),	HB_TAG('C','P','P',' ')},	/* Tay Boi -> Creoles */
   {HB_TAG('t','a','u',' '),	HB_TAG('A','T','H',' ')},	/* Upper Tanana -> Athapaskan */
+/*{HB_TAG('t','b','v',' '),	HB_TAG('T','B','V',' ')},*/	/* Tobo */
   {HB_TAG('t','c','b',' '),	HB_TAG('A','T','H',' ')},	/* Tanacross -> Athapaskan */
   {HB_TAG('t','c','e',' '),	HB_TAG('A','T','H',' ')},	/* Southern Tutchone -> Athapaskan */
   {HB_TAG('t','c','h',' '),	HB_TAG('C','P','P',' ')},	/* Turks And Caicos Creole English -> Creoles */
@@ -1623,7 +1632,7 @@ static const LangTag ot_languages3[] = {
   {HB_TAG('y','b','a',' '),	HB_TAG_NONE	       },	/* Yala != Yoruba */
   {HB_TAG('y','b','b',' '),	HB_TAG('B','M','L',' ')},	/* Yemba -> Bamileke */
   {HB_TAG('y','b','d',' '),	HB_TAG('A','R','K',' ')},	/* Yangbye (retired code) -> Rakhine */
-  {HB_TAG('y','c','r',' '),	HB_TAG_NONE	       },	/* Yilan Creole != Y-Cree */
+  {HB_TAG('y','c','r',' '),	HB_TAG('C','P','P',' ')},	/* Yilan Creole -> Creoles */
   {HB_TAG('y','d','d',' '),	HB_TAG('J','I','I',' ')},	/* Eastern Yiddish -> Yiddish */
 /*{HB_TAG('y','g','p',' '),	HB_TAG('Y','G','P',' ')},*/	/* Gepo */
   {HB_TAG('y','i','h',' '),	HB_TAG('J','I','I',' ')},	/* Western Yiddish -> Yiddish */
diff --git a/src/hb-ot-var-common.hh b/src/hb-ot-var-common.hh
index efbbfb25d..3ab58ae30 100644
--- a/src/hb-ot-var-common.hh
+++ b/src/hb-ot-var-common.hh
@@ -885,9 +885,9 @@ struct TupleVariationData
      * no need to do find_shared_points () again */
     hb_vector_t<char> *shared_points_bytes = nullptr;
 
-    /* total compiled byte size as TupleVariationData format, initialized to its
-     * min_size: 4 */
-    unsigned compiled_byte_size = 4;
+    /* total compiled byte size as TupleVariationData format, initialized to 0 */
+    unsigned compiled_byte_size = 0;
+    bool needs_padding = false;
 
     /* for gvar iup delta optimization: whether this is a composite glyph */
     bool is_composite = false;
@@ -1219,12 +1219,21 @@ struct TupleVariationData
     bool compile_bytes (const hb_map_t& axes_index_map,
                         const hb_map_t& axes_old_index_tag_map,
                         bool use_shared_points,
+                        bool is_gvar = false,
                         const hb_hashmap_t<const hb_vector_t<char>*, unsigned>* shared_tuples_idx_map = nullptr)
     {
+      // return true for empty glyph
+      if (!tuple_vars)
+        return true;
+
       // compile points set and store data in hashmap
       if (!compile_all_point_sets ())
         return false;
 
+      /* total compiled byte size as TupleVariationData format, initialized to its
+       * min_size: 4 */
+      compiled_byte_size += 4;
+
       if (use_shared_points)
       {
         find_shared_points ();
@@ -1253,6 +1262,13 @@ struct TupleVariationData
           return false;
         compiled_byte_size += tuple.compiled_tuple_header.length + points_data_length + tuple.compiled_deltas.length;
       }
+
+      if (is_gvar && (compiled_byte_size % 2))
+      {
+        needs_padding = true;
+        compiled_byte_size += 1;
+      }
+
       return true;
     }
 
@@ -1295,7 +1311,7 @@ struct TupleVariationData
       }
 
       /* padding for gvar */
-      if (is_gvar && (compiled_byte_size % 2))
+      if (is_gvar && needs_padding)
       {
         HBUINT8 pad;
         pad = 0;
diff --git a/src/hb-ot-var-gvar-table.hh b/src/hb-ot-var-gvar-table.hh
index b021a00f6..96cc2e887 100644
--- a/src/hb-ot-var-gvar-table.hh
+++ b/src/hb-ot-var-gvar-table.hh
@@ -140,6 +140,7 @@ struct glyph_variations_t
     for (tuple_variations_t& vars: glyph_variations)
       if (!vars.compile_bytes (axes_index_map, axes_old_index_tag_map,
                                true, /* use shared points*/
+                               true,
                                &shared_tuples_idx_map))
         return false;
 
diff --git a/src/hb-paint.h b/src/hb-paint.h
index b0cd384e2..d8896a523 100644
--- a/src/hb-paint.h
+++ b/src/hb-paint.h
@@ -146,7 +146,7 @@ typedef void (*hb_paint_pop_transform_func_t) (hb_paint_funcs_t *funcs,
  *
  * A virtual method for the #hb_paint_funcs_t to render a color glyph by glyph index.
  *
- * Return value: %true if the glyph was painted, %false otherwise.
+ * Return value: `true` if the glyph was painted, `false` otherwise.
  *
  * Since: 8.2.0
  */
diff --git a/src/hb-sanitize.hh b/src/hb-sanitize.hh
index 408649c76..199165a1e 100644
--- a/src/hb-sanitize.hh
+++ b/src/hb-sanitize.hh
@@ -72,8 +72,8 @@
  *
  * === The sanitize() contract ===
  *
- * The sanitize() method of each object type shall return true if it's safe to
- * call other methods of the object, and %false otherwise.
+ * The sanitize() method of each object type shall return `true` if it's safe to
+ * call other methods of the object, and `false` otherwise.
  *
  * Note that what sanitize() checks for might align with what the specification
  * describes as valid table data, but does not have to be.  In particular, we
diff --git a/src/hb-serialize.hh b/src/hb-serialize.hh
index e988451eb..f066d0e31 100644
--- a/src/hb-serialize.hh
+++ b/src/hb-serialize.hh
@@ -36,9 +36,7 @@
 #include "hb-map.hh"
 #include "hb-pool.hh"
 
-#ifdef HB_EXPERIMENTAL_API
-#include "hb-subset-repacker.h"
-#endif
+#include "hb-subset-serialize.h"
 
 /*
  * Serialize
@@ -75,8 +73,7 @@ struct hb_serialize_context_t
 
     object_t () = default;
 
-#ifdef HB_EXPERIMENTAL_API
-    object_t (const hb_object_t &o)
+    object_t (const hb_subset_serialize_object_t &o)
     {
       head = o.head;
       tail = o.tail;
@@ -89,7 +86,6 @@ struct hb_serialize_context_t
       for (unsigned i = 0; i < o.num_virtual_links; i++)
         virtual_links.push (o.virtual_links[i]);
     }
-#endif
 
     bool add_virtual_link (objidx_t objidx)
     {
@@ -148,8 +144,7 @@ struct hb_serialize_context_t
 
       link_t () = default;
 
-#ifdef HB_EXPERIMENTAL_API
-      link_t (const hb_link_t &o)
+      link_t (const hb_subset_serialize_link_t &o)
       {
         width = o.width;
         is_signed = 0;
@@ -158,7 +153,6 @@ struct hb_serialize_context_t
         bias = 0;
         objidx = o.objidx;
       }
-#endif
 
       HB_INTERNAL static int cmp (const void* a, const void* b)
       {
@@ -400,6 +394,7 @@ struct hb_serialize_context_t
       {
         merge_virtual_links (obj, objidx);
 	obj->fini ();
+        object_pool.release (obj);
 	return objidx;
       }
     }
@@ -463,9 +458,11 @@ struct hb_serialize_context_t
     while (packed.length > 1 &&
 	   packed.tail ()->head < tail)
     {
-      packed_map.del (packed.tail ());
-      assert (!packed.tail ()->next);
-      packed.tail ()->fini ();
+      object_t *obj = packed.tail ();
+      packed_map.del (obj);
+      assert (!obj->next);
+      obj->fini ();
+      object_pool.release (obj);
       packed.pop ();
     }
     if (packed.length > 1)
diff --git a/src/hb-shape.h b/src/hb-shape.h
index d4d4fdfd2..b09bf0587 100644
--- a/src/hb-shape.h
+++ b/src/hb-shape.h
@@ -53,6 +53,7 @@ hb_shape_full (hb_font_t          *font,
 	       unsigned int        num_features,
 	       const char * const *shaper_list);
 
+#ifdef HB_EXPERIMENTAL_API
 HB_EXTERN hb_bool_t
 hb_shape_justify (hb_font_t          *font,
 		  hb_buffer_t        *buffer,
@@ -64,6 +65,7 @@ hb_shape_justify (hb_font_t          *font,
 		  float              *advance, /* IN/OUT */
 		  hb_tag_t           *var_tag, /* OUT */
 		  float              *var_value /* OUT */);
+#endif
 
 HB_EXTERN const char **
 hb_shape_list_shapers (void);
diff --git a/src/hb-subset-input.cc b/src/hb-subset-input.cc
index b874949df..2f0b54f47 100644
--- a/src/hb-subset-input.cc
+++ b/src/hb-subset-input.cc
@@ -534,7 +534,6 @@ hb_subset_input_pin_axis_location (hb_subset_input_t  *input,
  *
  * Note: input min value can not be bigger than input max value. If the input
  * default value is not within the new min/max range, it'll be clamped.
- * Note: currently it supports gvar and cvar tables only.
  *
  * Return value: `true` if success, `false` otherwise
  *
@@ -597,6 +596,144 @@ hb_subset_input_get_axis_range (hb_subset_input_t  *input,
   *axis_max_value = triple->maximum;
   return true;
 }
+
+/**
+ * hb_subset_axis_range_from_string:
+ * @str: a string to parse
+ * @len: length of @str, or -1 if str is NULL terminated
+ * @axis_min_value: (out): the axis min value to initialize with the parsed value
+ * @axis_max_value: (out): the axis max value to initialize with the parsed value
+ * @axis_def_value: (out): the axis default value to initialize with the parse
+ * value
+ *
+ * Parses a string into a subset axis range(min, def, max).
+ * Axis positions string is in the format of min:def:max or min:max
+ * When parsing axis positions, empty values as meaning the existing value for that part
+ * E.g: :300:500
+ * Specifies min = existing, def = 300, max = 500
+ * In the output axis_range, if a value should be set to it's default value,
+ * then it will be set to NaN
+ *
+ * Return value:
+ * `true` if @str is successfully parsed, `false` otherwise
+ *
+ * Since: 10.2.0
+ */
+HB_EXTERN hb_bool_t
+hb_subset_axis_range_from_string (const char *str, int len,
+                                  float *axis_min_value,
+                                  float *axis_max_value,
+                                  float *axis_def_value)
+{
+  if (len < 0)
+    len = strlen (str);
+
+  const char *end = str + len;
+  const char* part = strpbrk (str, ":");
+  if (!part)
+  {
+    // Single value.
+    if (strcmp (str, "drop") == 0)
+    {
+      *axis_min_value = NAN;
+      *axis_def_value = NAN;
+      *axis_max_value = NAN;
+      return true;
+    }
+
+    double v;
+    if (!hb_parse_double (&str, end, &v)) return false;
+
+    *axis_min_value = v;
+    *axis_def_value = v;
+    *axis_max_value = v;
+    return true;
+  }
+
+  float values[3];
+  int count = 0;
+  for (int i = 0; i < 3; i++) {
+    count++;
+    if (!*str || part == str)
+    {
+      values[i] = NAN;
+
+      if (part == NULL) break;
+      str = part + 1;
+      part = strpbrk (str, ":");
+      continue;
+    }
+
+    double v;
+    if (!hb_parse_double (&str, part, &v)) return false;
+    values[i] = v;
+
+    if (part == NULL) break;
+    str = part + 1;
+    part = strpbrk (str, ":");
+  }
+
+  if (count == 2)
+  {
+    *axis_min_value = values[0];
+    *axis_def_value = NAN;
+    *axis_max_value = values[1];
+    return true;
+  }
+  else if (count == 3)
+  {
+    *axis_min_value = values[0];
+    *axis_def_value = values[1];
+    *axis_max_value = values[2];
+    return true;
+  }
+  return false;
+}
+
+/**
+ * hb_subset_axis_range_to_string:
+ * @input: a #hb_subset_input_t object.
+ * @axis_tag: an axis to convert
+ * @buf: (array length=size) (out caller-allocates): output string
+ * @size: the allocated size of @buf
+ *
+ * Converts an axis range into a `NULL`-terminated string in the format
+ * understood by hb_subset_axis_range_from_string(). The client in responsible for
+ * allocating big enough size for @buf, 128 bytes is more than enough.
+ *
+ * Since: 10.2.0
+ */
+HB_EXTERN void
+hb_subset_axis_range_to_string (hb_subset_input_t *input,
+                                hb_tag_t axis_tag,
+                                char *buf, unsigned size)
+{
+  if (unlikely (!size)) return;
+  Triple* triple;
+  if (!input->axes_location.has(axis_tag, &triple)) {
+    return;
+  }
+
+  char s[128];
+  unsigned len = 0;
+
+  hb_locale_t clocale HB_UNUSED;
+  hb_locale_t oldlocale HB_UNUSED;
+  oldlocale = hb_uselocale (clocale = newlocale (LC_ALL_MASK, "C", NULL));
+  len += hb_max (0, snprintf (s, ARRAY_LENGTH (s) - len, "%g", (double) triple->minimum));
+  s[len++] = ':';
+
+  len += hb_max (0, snprintf (s + len, ARRAY_LENGTH (s) - len, "%g", (double) triple->middle));
+  s[len++] = ':';
+
+  len += hb_max (0, snprintf (s + len, ARRAY_LENGTH (s) - len, "%g", (double) triple->maximum));
+  (void) hb_uselocale (((void) freelocale (clocale), oldlocale));
+
+  assert (len < ARRAY_LENGTH (s));
+  len = hb_min (len, size - 1);
+  hb_memcpy (buf, s, len);
+  buf[len] = '\0';
+}
 #endif
 
 /**
diff --git a/src/hb-subset-plan.cc b/src/hb-subset-plan.cc
index 59020dbe8..c88fd75a5 100644
--- a/src/hb-subset-plan.cc
+++ b/src/hb-subset-plan.cc
@@ -678,7 +678,8 @@ _populate_unicodes_to_retain (const hb_set_t *unicodes,
                               hb_subset_plan_t *plan)
 {
   OT::cmap::accelerator_t cmap (plan->source);
-  unsigned size_threshold = plan->source->get_num_glyphs ();
+  unsigned size_threshold = plan->source->get_num_glyphs ();  
+
   if (glyphs->is_empty () && unicodes->get_population () < size_threshold)
   {
 
@@ -797,6 +798,21 @@ _populate_unicodes_to_retain (const hb_set_t *unicodes,
     plan->unicodes.add_sorted_array (&arr.arrayZ->first, arr.length, sizeof (*arr.arrayZ));
     plan->_glyphset_gsub.add_array (&arr.arrayZ->second, arr.length, sizeof (*arr.arrayZ));
   }
+
+  // Variation selectors don't have glyphs associated with them in the cmap so they will have been filtered out above
+  // but should still be retained. Add them back here.
+
+  // However, the min and max codepoints for OS/2 should be calculated without considering variation selectors,
+  // so record those first.
+  plan->os2_info.min_cmap_codepoint = plan->unicodes.get_min();
+  plan->os2_info.max_cmap_codepoint = plan->unicodes.get_max();
+  
+  hb_set_t variation_selectors_to_retain;
+  cmap.collect_variation_selectors(&variation_selectors_to_retain);
+  + variation_selectors_to_retain.iter()
+  | hb_filter(unicodes)
+  | hb_sink(&plan->unicodes)
+  ;
 }
 
 static unsigned
diff --git a/src/hb-subset-plan.hh b/src/hb-subset-plan.hh
index 19a9fa691..fe80c08bc 100644
--- a/src/hb-subset-plan.hh
+++ b/src/hb-subset-plan.hh
@@ -41,6 +41,13 @@ namespace OT {
 struct Feature;
 }
 
+struct os2_info_t {
+  hb_codepoint_t min_cmap_codepoint;
+  hb_codepoint_t max_cmap_codepoint;
+};
+
+typedef struct os2_info_t os2_info_t;
+
 struct head_maxp_info_t
 {
   head_maxp_info_t ()
@@ -180,6 +187,8 @@ struct hb_subset_plan_t
   //recalculated head/maxp table info after instancing
   mutable head_maxp_info_t head_maxp_info;
 
+  os2_info_t os2_info;
+
   const hb_subset_accelerator_t* accelerator;
   hb_subset_accelerator_t* inprogress_accelerator;
 
diff --git a/src/hb-subset-repacker.h b/src/hb-subset-repacker.h
deleted file mode 100644
index 245cf6076..000000000
--- a/src/hb-subset-repacker.h
+++ /dev/null
@@ -1,81 +0,0 @@
-/*
- * Copyright © 2022  Google, Inc.
- *
- *  This is part of HarfBuzz, a text shaping library.
- *
- * Permission is hereby granted, without written agreement and without
- * license or royalty fees, to use, copy, modify, and distribute this
- * software and its documentation for any purpose, provided that the
- * above copyright notice and the following two paragraphs appear in
- * all copies of this software.
- *
- * IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE TO ANY PARTY FOR
- * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
- * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN
- * IF THE COPYRIGHT HOLDER HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
- * DAMAGE.
- *
- * THE COPYRIGHT HOLDER SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING,
- * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
- * FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
- * ON AN "AS IS" BASIS, AND THE COPYRIGHT HOLDER HAS NO OBLIGATION TO
- * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
- *
- */
-
-#ifndef HB_SUBSET_REPACKER_H
-#define HB_SUBSET_REPACKER_H
-
-#include "hb.h"
-
-HB_BEGIN_DECLS
-
-#ifdef HB_EXPERIMENTAL_API
-/*
- * struct hb_link_t
- * width:    offsetSize in bytes
- * position: position of the offset field in bytes
- * from beginning of subtable
- * objidx:   index of subtable
- */
-struct hb_link_t
-{
-  unsigned width;
-  unsigned position;
-  unsigned objidx;
-};
-
-typedef struct hb_link_t hb_link_t;
-
-/*
- * struct hb_object_t
- * head:    start of object data
- * tail:    end of object data
- * num_real_links:    num of offset field in the object
- * real_links:        pointer to array of offset info
- * num_virtual_links: num of objects that must be packed
- * after current object in the final serialized order
- * virtual_links:     array of virtual link info
- */
-struct hb_object_t
-{
-  char *head;
-  char *tail;
-  unsigned num_real_links;
-  hb_link_t *real_links;
-  unsigned num_virtual_links;
-  hb_link_t *virtual_links;
-};
-
-typedef struct hb_object_t hb_object_t;
-
-HB_EXTERN hb_blob_t*
-hb_subset_repack_or_fail (hb_tag_t table_tag,
-                          hb_object_t* hb_objects,
-                          unsigned num_hb_objs);
-
-#endif
-
-HB_END_DECLS
-
-#endif /* HB_SUBSET_REPACKER_H */
diff --git a/src/hb-subset-repacker.cc b/src/hb-subset-serialize.cc
similarity index 68%
rename from src/hb-subset-repacker.cc
rename to src/hb-subset-serialize.cc
index 6a29b35be..dc7613654 100644
--- a/src/hb-subset-repacker.cc
+++ b/src/hb-subset-serialize.cc
@@ -22,37 +22,36 @@
  * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
  *
  */
-#include "hb-repacker.hh"
 
-#ifdef HB_EXPERIMENTAL_API
+#include "hb.hh"
+
+#include "hb-subset-serialize.h"
+#include "hb-repacker.hh"
 
 /**
- * hb_subset_repack_or_fail:
+ * hb_subset_serialize_or_fail:
  * @table_tag: tag of the table being packed, needed to allow table specific optimizations.
- * @hb_objects: raw array of struct hb_object_t, which provides
+ * @hb_objects: raw array of struct hb_subset_serialize_object_t, which provides
  * object graph info
- * @num_hb_objs: number of hb_object_t in the hb_objects array.
+ * @num_hb_objs: number of hb_subset_serialize_object_t in the hb_objects array.
  *
- * Given the input object graph info, repack a table to eliminate
- * offset overflows. A nullptr is returned if the repacking attempt fails.
+ * Given the input object graph info, repack a table to eliminate offset overflows and
+ * serialize it into a continuous array of bytes. A nullptr is returned if the serializing attempt fails.
  * Table specific optimizations (eg. extension promotion in GSUB/GPOS) may be performed.
  * Passing HB_TAG_NONE will disable table specific optimizations.
  *
- * XSince: EXPERIMENTAL
+ * Since: 10.2.0
  **/
-hb_blob_t* hb_subset_repack_or_fail (hb_tag_t table_tag,
-                                     hb_object_t* hb_objects,
-                                     unsigned num_hb_objs)
+HB_EXTERN hb_blob_t *
+hb_subset_serialize_or_fail (hb_tag_t                      table_tag,
+                             hb_subset_serialize_object_t *hb_objects,
+                             unsigned                      num_hb_objs)
 {
-  hb_vector_t<const hb_object_t *> packed;
+  hb_vector_t<const hb_subset_serialize_object_t *> packed;
   packed.alloc (num_hb_objs + 1);
   packed.push (nullptr);
   for (unsigned i = 0 ; i < num_hb_objs ; i++)
     packed.push (&(hb_objects[i]));
 
-  return hb_resolve_overflows (packed,
-                               table_tag,
-                               20,
-                               true);
+  return hb_resolve_overflows (packed, table_tag, 20, true);
 }
-#endif
diff --git a/src/hb-subset-serialize.h b/src/hb-subset-serialize.h
new file mode 100644
index 000000000..9035d4ced
--- /dev/null
+++ b/src/hb-subset-serialize.h
@@ -0,0 +1,83 @@
+/*
+ * Copyright © 2022  Google, Inc.
+ *
+ *  This is part of HarfBuzz, a text shaping library.
+ *
+ * Permission is hereby granted, without written agreement and without
+ * license or royalty fees, to use, copy, modify, and distribute this
+ * software and its documentation for any purpose, provided that the
+ * above copyright notice and the following two paragraphs appear in
+ * all copies of this software.
+ *
+ * IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE TO ANY PARTY FOR
+ * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
+ * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN
+ * IF THE COPYRIGHT HOLDER HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
+ * DAMAGE.
+ *
+ * THE COPYRIGHT HOLDER SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING,
+ * BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
+ * FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
+ * ON AN "AS IS" BASIS, AND THE COPYRIGHT HOLDER HAS NO OBLIGATION TO
+ * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
+ *
+ */
+
+#ifndef HB_SUBSET_SERIALIZE_H
+#define HB_SUBSET_SERIALIZE_H
+
+#include "hb.h"
+
+HB_BEGIN_DECLS
+
+/**
+ * hb_subset_serialize_link_t:
+ * @width: offsetSize in bytes
+ * @position: position of the offset field in bytes from
+ *            beginning of subtable
+ * @objidx: index of subtable
+ *
+ * Represents a link between two objects in the object graph
+ * to be serialized.
+ *
+ * Since: 10.2.0
+ */
+typedef struct hb_subset_serialize_link_t {
+  unsigned int width;
+  unsigned int position;
+  unsigned int objidx;
+} hb_subset_serialize_link_t;
+
+/**
+ * hb_subset_serialize_object_t:
+ * @head: start of object data
+ * @tail: end of object data
+ * @num_real_links: number of offset field in the object
+ * @real_links: array of offset info
+ * @num_virtual_links: number of objects that must be packed
+ *                     after current object in the final
+ *                     serialized order
+ * @virtual_links: array of virtual link info
+ *
+ * Represents an object in the object graph to be serialized.
+ *
+ * Since: 10.2.0
+ */
+typedef struct hb_subset_serialize_object_t {
+  char *head;
+  char *tail;
+  unsigned int num_real_links;
+  hb_subset_serialize_link_t *real_links;
+  unsigned int num_virtual_links;
+  hb_subset_serialize_link_t *virtual_links;
+} hb_subset_serialize_object_t;
+
+HB_EXTERN hb_blob_t *
+hb_subset_serialize_or_fail (hb_tag_t                      table_tag,
+                             hb_subset_serialize_object_t *hb_objects,
+                             unsigned                      num_hb_objs);
+
+
+HB_END_DECLS
+
+#endif /* HB_SUBSET_SERIALIZE_H */
diff --git a/src/hb-subset.cc b/src/hb-subset.cc
index 7cea9f183..4e96c9853 100644
--- a/src/hb-subset.cc
+++ b/src/hb-subset.cc
@@ -295,7 +295,7 @@ _try_subset (const TableType *table,
   DEBUG_MSG (SUBSET, nullptr, "OT::%c%c%c%c ran out of room; reallocating to %u bytes.",
              HB_UNTAG (c->table_tag), buf_size);
 
-  if (unlikely (buf_size > c->source_blob->length * 16 ||
+  if (unlikely (buf_size > c->source_blob->length * 256 ||
 		!buf->alloc (buf_size, true)))
   {
     DEBUG_MSG (SUBSET, nullptr, "OT::%c%c%c%c failed to reallocate %u bytes.",
diff --git a/src/hb-subset.h b/src/hb-subset.h
index 365c21a63..71276c7a6 100644
--- a/src/hb-subset.h
+++ b/src/hb-subset.h
@@ -203,6 +203,18 @@ hb_subset_input_set_axis_range (hb_subset_input_t  *input,
 				float               axis_max_value,
 				float               axis_def_value);
 
+HB_EXTERN hb_bool_t
+hb_subset_axis_range_from_string (const char *str, int len,
+				  float *axis_min_value,
+				  float *axis_max_value,
+				  float *axis_def_value);
+
+HB_EXTERN void
+hb_subset_axis_range_to_string (hb_subset_input_t *input,
+				hb_tag_t axis_tag,
+				char *buf,
+				unsigned size);
+
 #ifdef HB_EXPERIMENTAL_API
 HB_EXTERN hb_bool_t
 hb_subset_input_override_name_table (hb_subset_input_t  *input,
diff --git a/src/hb-utf.hh b/src/hb-utf.hh
index 1120bd1cc..6db9bf2fd 100644
--- a/src/hb-utf.hh
+++ b/src/hb-utf.hh
@@ -458,19 +458,21 @@ struct hb_ascii_t
 template <typename utf_t>
 static inline const typename utf_t::codepoint_t *
 hb_utf_offset_to_pointer (const typename utf_t::codepoint_t *start,
+			  const typename utf_t::codepoint_t *text,
+			  unsigned text_len,
 			  signed offset)
 {
   hb_codepoint_t unicode;
 
   while (offset-- > 0)
     start = utf_t::next (start,
-			 start + utf_t::max_len,
+			 text + text_len,
 			 &unicode,
 			 HB_BUFFER_REPLACEMENT_CODEPOINT_DEFAULT);
 
   while (offset++ < 0)
     start = utf_t::prev (start,
-			 start - utf_t::max_len,
+			 text,
 			 &unicode,
 			 HB_BUFFER_REPLACEMENT_CODEPOINT_DEFAULT);
 
diff --git a/src/hb-version.h b/src/hb-version.h
index 1083bc9c9..8e767cba2 100644
--- a/src/hb-version.h
+++ b/src/hb-version.h
@@ -47,7 +47,7 @@ HB_BEGIN_DECLS
  *
  * The minor component of the library version available at compile-time.
  */
-#define HB_VERSION_MINOR 1
+#define HB_VERSION_MINOR 2
 /**
  * HB_VERSION_MICRO:
  *
@@ -60,7 +60,7 @@ HB_BEGIN_DECLS
  *
  * A string literal containing the library version available at compile-time.
  */
-#define HB_VERSION_STRING "10.1.0"
+#define HB_VERSION_STRING "10.2.0"
 
 /**
  * HB_VERSION_ATLEAST:
diff --git a/src/meson.build b/src/meson.build
index 5ca15d90e..b9daabf01 100644
--- a/src/meson.build
+++ b/src/meson.build
@@ -383,7 +383,7 @@ hb_subset_sources = files(
   'hb-subset-plan.cc',
   'hb-subset-plan.hh',
   'hb-subset-plan-member-list.hh',
-  'hb-subset-repacker.cc',
+  'hb-subset-serialize.cc',
   'graph/gsubgpos-context.cc',
   'graph/gsubgpos-context.hh',
   'graph/gsubgpos-graph.hh',
@@ -398,7 +398,7 @@ hb_subset_sources = files(
 
 hb_subset_headers = files(
   'hb-subset.h',
-  'hb-subset-repacker.h'
+  'hb-subset-serialize.h'
 )
 
 hb_gobject_sources = files(
@@ -875,6 +875,7 @@ endmacro()
 cmake_config.set('PACKAGE_CMAKE_INSTALL_INCLUDEDIR', '${PACKAGE_PREFIX_DIR}/@0@'.format(cmake_install_includedir))
 cmake_config.set('PACKAGE_CMAKE_INSTALL_LIBDIR', '${PACKAGE_PREFIX_DIR}/@0@'.format(cmake_install_libdir))
 cmake_config.set('PACKAGE_INCLUDE_INSTALL_DIR', '${PACKAGE_PREFIX_DIR}/@0@/@1@'.format(cmake_install_includedir, meson.project_name()))
+cmake_config.set('HARFBUZZ_VERSION', meson.project_version())
 cmake_config.set('HB_HAVE_GOBJECT', have_gobject ? 'YES' : 'NO')
 cmake_config.set('HB_LIBRARY_TYPE', get_option('default_library') == 'static' ? 'STATIC' : 'SHARED')
 
diff --git a/subprojects/cairo.wrap b/subprojects/cairo.wrap
index 36e8043a2..edd7cf8d5 100644
--- a/subprojects/cairo.wrap
+++ b/subprojects/cairo.wrap
@@ -1,8 +1,10 @@
-[wrap-git]
-directory=cairo
-url=https://gitlab.freedesktop.org/cairo/cairo.git
-depth=1
-revision=1.17.8
+[wrap-file]
+directory = cairo-1.18.2
+source_url = https://www.cairographics.org/releases/cairo-1.18.2.tar.xz
+source_filename = cairo-1.18.2.tar.xz
+source_hash = a62b9bb42425e844cc3d6ddde043ff39dbabedd1542eba57a2eb79f85889d45a
+source_fallback_url = https://github.com/mesonbuild/wrapdb/releases/download/cairo_1.18.2-1/cairo-1.18.2.tar.xz
+wrapdb_version = 1.18.2-1
 
 [provide]
-dependency_names = cairo
+dependency_names = cairo, cairo-gobject
diff --git a/subprojects/freetype2.wrap b/subprojects/freetype2.wrap
index fe325d84e..acad6f487 100644
--- a/subprojects/freetype2.wrap
+++ b/subprojects/freetype2.wrap
@@ -1,9 +1,10 @@
 [wrap-file]
-directory = freetype-2.13.0
-source_url = https://download.savannah.gnu.org/releases/freetype/freetype-2.13.0.tar.xz
-source_fallback_url = https://github.com/mesonbuild/wrapdb/releases/download/freetype2_2.13.0-1/freetype-2.13.0.tar.xz
-source_filename = freetype-2.13.0.tar.xz
-source_hash = 5ee23abd047636c24b2d43c6625dcafc66661d1aca64dec9e0d05df29592624c
+directory = freetype-2.13.3
+source_url = https://download.savannah.gnu.org/releases/freetype/freetype-2.13.3.tar.xz
+source_fallback_url = https://github.com/mesonbuild/wrapdb/releases/download/freetype2_2.13.3-1/freetype-2.13.3.tar.xz
+source_filename = freetype-2.13.3.tar.xz
+source_hash = 0550350666d427c74daeb85d5ac7bb353acba5f76956395995311a9c6f063289
+wrapdb_version = 2.13.3-1
 
 [provide]
 freetype2 = freetype_dep
diff --git a/subprojects/glib.wrap b/subprojects/glib.wrap
index 2ea0dbff2..3fded5413 100644
--- a/subprojects/glib.wrap
+++ b/subprojects/glib.wrap
@@ -1,10 +1,10 @@
 [wrap-file]
-directory = glib-2.74.4
-source_url = https://download.gnome.org/sources/glib/2.74/glib-2.74.4.tar.xz
-source_fallback_url = https://ftp.acc.umu.se/pub/gnome/sources/glib/2.74/glib-2.74.4.tar.xz
-source_filename = glib-2.74.4.tar.xz
-source_hash = 0e82da5ea129b4444227c7e4a9e598f7288d1994bf63f129c44b90cfd2432172
-wrapdb_version = 2.74.4-1
+directory = glib-2.82.2
+source_url = https://download.gnome.org/sources/glib/2.82/glib-2.82.2.tar.xz
+source_fallback_url = https://github.com/mesonbuild/wrapdb/releases/download/glib_2.82.2-1/glib-2.82.2.tar.xz
+source_filename = glib-2.82.2.tar.xz
+source_hash = ab45f5a323048b1659ee0fbda5cecd94b099ab3e4b9abf26ae06aeb3e781fd63
+wrapdb_version = 2.82.2-1
 
 [provide]
 dependency_names = gthread-2.0, gobject-2.0, gmodule-no-export-2.0, gmodule-export-2.0, gmodule-2.0, glib-2.0, gio-2.0, gio-windows-2.0, gio-unix-2.0
diff --git a/subprojects/google-benchmark.wrap b/subprojects/google-benchmark.wrap
index 6205cd7f7..91ff9528d 100644
--- a/subprojects/google-benchmark.wrap
+++ b/subprojects/google-benchmark.wrap
@@ -1,12 +1,14 @@
 [wrap-file]
-directory = benchmark-1.7.1
-source_url = https://github.com/google/benchmark/archive/refs/tags/v1.7.1.tar.gz
-source_filename = benchmark-1.7.1.tar.gz
-source_hash = 6430e4092653380d9dc4ccb45a1e2dc9259d581f4866dc0759713126056bc1d7
-patch_filename = google-benchmark_1.7.1-1_patch.zip
-patch_url = https://wrapdb.mesonbuild.com/v2/google-benchmark_1.7.1-1/get_patch
-patch_hash = 9c6694328ac971cd781aa67c45c64291c087f118e23b75946f52670caacf49b7
-wrapdb_version = 1.7.1-1
+directory = benchmark-1.8.4
+source_url = https://github.com/google/benchmark/archive/refs/tags/v1.8.4.tar.gz
+source_filename = benchmark-1.8.4.tar.gz
+source_hash = 3e7059b6b11fb1bbe28e33e02519398ca94c1818874ebed18e504dc6f709be45
+patch_filename = google-benchmark_1.8.4-1_patch.zip
+patch_url = https://wrapdb.mesonbuild.com/v2/google-benchmark_1.8.4-1/get_patch
+patch_hash = 77cdae534fe12b6783c1267de3673d3462b229054519034710d581b419e73cca
+source_fallback_url = https://github.com/mesonbuild/wrapdb/releases/download/google-benchmark_1.8.4-1/benchmark-1.8.4.tar.gz
+wrapdb_version = 1.8.4-1
 
 [provide]
 benchmark = google_benchmark_dep
+benchmark-main = google_benchmark_main_dep
diff --git a/test/api/test-subset-cmap.c b/test/api/test-subset-cmap.c
index e16400ea5..9aef6f8d4 100644
--- a/test/api/test-subset-cmap.c
+++ b/test/api/test-subset-cmap.c
@@ -145,6 +145,7 @@ test_subset_cmap_noto_color_emoji_noop (void)
   hb_set_add (codepoints, 0xAE);
   hb_set_add (codepoints, 0x2049);
   hb_set_add (codepoints, 0x20E3);
+  hb_set_add (codepoints, 0xfe0f);
   face_subset = hb_subset_test_create_subset (face, hb_subset_test_create_input (codepoints));
   hb_set_destroy (codepoints);
 
@@ -165,6 +166,7 @@ test_subset_cmap_noto_color_emoji_non_consecutive_glyphs (void)
   hb_set_add (codepoints, 0x38);
   hb_set_add (codepoints, 0xAE);
   hb_set_add (codepoints, 0x2049);
+  hb_set_add (codepoints, 0xfe0f);
   face_subset = hb_subset_test_create_subset (face, hb_subset_test_create_input (codepoints));
   hb_set_destroy (codepoints);
 
diff --git a/test/api/test-subset-repacker.c b/test/api/test-subset-repacker.c
index d1779b69c..6eeae4ed2 100644
--- a/test/api/test-subset-repacker.c
+++ b/test/api/test-subset-repacker.c
@@ -26,15 +26,14 @@
 #include "hb-test.h"
 #include "hb-subset-test.h"
 
-#ifdef HB_EXPERIMENTAL_API
-#include "hb-subset-repacker.h"
+#include "hb-subset-serialize.h"
 
 char test_gsub_data[106] = "\x0\x1\x0\x0\x0\xa\x0\x1e\x0\x2c\x0\x1\x6c\x61\x74\x6e\x0\x8\x0\x4\x0\x0\x0\x0\xff\xff\x0\x1\x0\x0\x0\x1\x74\x65\x73\x74\x0\x8\x0\x0\x0\x1\x0\x1\x0\x2\x0\x2a\x0\x6\x0\x5\x0\x0\x0\x1\x0\x8\x0\x1\x0\x8\x0\x1\x0\xe\x0\x1\x0\x1\x0\x1\x0\x1\x0\x4\x0\x2\x0\x1\x0\x2\x0\x1\x0\x0\x0\x1\x0\x0\x0\x1\x0\x8\x0\x1\x0\x6\x0\x1\x0\x1\x0\x1\x0\x2";
 
 static void
 test_hb_repack_with_cy_struct (void)
 {
-  hb_object_t *hb_objs = calloc (15, sizeof (hb_object_t));
+  hb_subset_serialize_object_t *hb_objs = calloc (15, sizeof (hb_subset_serialize_object_t));
 
   hb_objs[0].head = &(test_gsub_data[100]);
   hb_objs[0].tail = &(test_gsub_data[105]) + 1;
@@ -47,7 +46,7 @@ test_hb_repack_with_cy_struct (void)
   hb_objs[1].tail = &(test_gsub_data[100]);
   hb_objs[1].num_real_links = 1;
   hb_objs[1].num_virtual_links = 0;
-  hb_objs[1].real_links = malloc (sizeof (hb_link_t));
+  hb_objs[1].real_links = malloc (sizeof (hb_subset_serialize_link_t));
   hb_objs[1].real_links[0].width = 2;
   hb_objs[1].real_links[0].position = 2;
   hb_objs[1].real_links[0].objidx = 1;
@@ -58,7 +57,7 @@ test_hb_repack_with_cy_struct (void)
   hb_objs[2].tail = &(test_gsub_data[94]);
   hb_objs[2].num_real_links = 1;
   hb_objs[2].num_virtual_links = 0;
-  hb_objs[2].real_links = malloc (sizeof (hb_link_t));
+  hb_objs[2].real_links = malloc (sizeof (hb_subset_serialize_link_t));
   hb_objs[2].real_links[0].width = 2;
   hb_objs[2].real_links[0].position = 6;
   hb_objs[2].real_links[0].objidx = 2;
@@ -75,7 +74,7 @@ test_hb_repack_with_cy_struct (void)
   hb_objs[4].tail = &(test_gsub_data[76]);
   hb_objs[4].num_real_links = 1;
   hb_objs[4].num_virtual_links = 0;
-  hb_objs[4].real_links = malloc (sizeof (hb_link_t));
+  hb_objs[4].real_links = malloc (sizeof (hb_subset_serialize_link_t));
   hb_objs[4].real_links[0].width = 2;
   hb_objs[4].real_links[0].position = 2;
   hb_objs[4].real_links[0].objidx = 4;
@@ -92,7 +91,7 @@ test_hb_repack_with_cy_struct (void)
   hb_objs[6].tail = &(test_gsub_data[66]);
   hb_objs[6].num_real_links = 2;
   hb_objs[6].num_virtual_links = 0;
-  hb_objs[6].real_links = calloc (2, sizeof (hb_link_t));
+  hb_objs[6].real_links = calloc (2, sizeof (hb_subset_serialize_link_t));
   hb_objs[6].real_links[0].width = 2;
   hb_objs[6].real_links[0].position = 6;
   hb_objs[6].real_links[0].objidx = 5;
@@ -105,7 +104,7 @@ test_hb_repack_with_cy_struct (void)
   hb_objs[7].tail = &(test_gsub_data[58]);
   hb_objs[7].num_real_links = 1;
   hb_objs[7].num_virtual_links = 0;
-  hb_objs[7].real_links = malloc (sizeof (hb_link_t));
+  hb_objs[7].real_links = malloc (sizeof (hb_subset_serialize_link_t));
   hb_objs[7].real_links[0].width = 2;
   hb_objs[7].real_links[0].position = 6;
   hb_objs[7].real_links[0].objidx = 7;
@@ -115,7 +114,7 @@ test_hb_repack_with_cy_struct (void)
   hb_objs[8].tail = &(test_gsub_data[50]);
   hb_objs[8].num_real_links = 2;
   hb_objs[8].num_virtual_links = 0;
-  hb_objs[8].real_links = calloc (2, sizeof (hb_link_t));
+  hb_objs[8].real_links = calloc (2, sizeof (hb_subset_serialize_link_t));
   hb_objs[8].real_links[0].width = 2;
   hb_objs[8].real_links[0].position = 2;
   hb_objs[8].real_links[0].objidx = 3;
@@ -135,7 +134,7 @@ test_hb_repack_with_cy_struct (void)
   hb_objs[10].tail = &(test_gsub_data[38]);
   hb_objs[10].num_real_links = 1;
   hb_objs[10].num_virtual_links = 0;
-  hb_objs[10].real_links = malloc (sizeof (hb_link_t));
+  hb_objs[10].real_links = malloc (sizeof (hb_subset_serialize_link_t));
   hb_objs[10].real_links[0].width = 2;
   hb_objs[10].real_links[0].position = 6;
   hb_objs[10].real_links[0].objidx = 10;
@@ -152,7 +151,7 @@ test_hb_repack_with_cy_struct (void)
   hb_objs[12].tail = &(test_gsub_data[22]);
   hb_objs[12].num_real_links = 1;
   hb_objs[12].num_virtual_links = 0;
-  hb_objs[12].real_links = malloc (sizeof (hb_link_t));
+  hb_objs[12].real_links = malloc (sizeof (hb_subset_serialize_link_t));
   hb_objs[12].real_links[0].width = 2;
   hb_objs[12].real_links[0].position = 0;
   hb_objs[12].real_links[0].objidx = 12;
@@ -162,7 +161,7 @@ test_hb_repack_with_cy_struct (void)
   hb_objs[13].tail = &(test_gsub_data[18]);
   hb_objs[13].num_real_links = 1;
   hb_objs[13].num_virtual_links = 0;
-  hb_objs[13].real_links = malloc (sizeof (hb_link_t));
+  hb_objs[13].real_links = malloc (sizeof (hb_subset_serialize_link_t));
   hb_objs[13].real_links[0].width = 2;
   hb_objs[13].real_links[0].position = 6;
   hb_objs[13].real_links[0].objidx = 13;
@@ -172,7 +171,7 @@ test_hb_repack_with_cy_struct (void)
   hb_objs[14].tail = &(test_gsub_data[10]);
   hb_objs[14].num_real_links = 3;
   hb_objs[14].num_virtual_links = 0;
-  hb_objs[14].real_links = calloc (3, sizeof (hb_link_t));
+  hb_objs[14].real_links = calloc (3, sizeof (hb_subset_serialize_link_t));
   hb_objs[14].real_links[0].width = 2;
   hb_objs[14].real_links[0].position = 8;
   hb_objs[14].real_links[0].objidx = 9;
@@ -184,7 +183,7 @@ test_hb_repack_with_cy_struct (void)
   hb_objs[14].real_links[2].objidx = 14;
   hb_objs[14].virtual_links = NULL;
 
-  hb_blob_t *result = hb_subset_repack_or_fail (HB_TAG_NONE, hb_objs, 15);
+  hb_blob_t *result = hb_subset_serialize_or_fail (HB_TAG_NONE, hb_objs, 15);
 
   hb_face_t *face_expected = hb_test_open_font_file ("fonts/repacker_expected.otf");
   hb_blob_t *expected_blob = hb_face_reference_table (face_expected, HB_TAG ('G','S','U','B'));
@@ -217,9 +216,3 @@ main (int argc, char **argv)
 
   return hb_test_run();
 }
-#else
-int main (int argc HB_UNUSED, char **argv HB_UNUSED)
-{
-  return 0;
-}
-#endif
diff --git a/test/fuzzing/hb-repacker-fuzzer.cc b/test/fuzzing/hb-repacker-fuzzer.cc
index 0b06fd2af..f7caeee0f 100644
--- a/test/fuzzing/hb-repacker-fuzzer.cc
+++ b/test/fuzzing/hb-repacker-fuzzer.cc
@@ -5,7 +5,7 @@
 #include <string.h>
 #include <assert.h>
 
-#include "hb-subset-repacker.h"
+#include "hb-subset-serialize.h"
 
 typedef struct
 {
@@ -42,7 +42,7 @@ bool read(const uint8_t** data, size_t* size, T* out)
   return true;
 }
 
-void cleanup (hb_object_t* objects, uint16_t num_objects)
+void cleanup (hb_subset_serialize_object_t* objects, uint16_t num_objects)
 {
   for (uint32_t i = 0; i < num_objects; i++)
   {
@@ -51,7 +51,7 @@ void cleanup (hb_object_t* objects, uint16_t num_objects)
   }
 }
 
-void add_links_to_objects (hb_object_t* objects, uint16_t num_objects,
+void add_links_to_objects (hb_subset_serialize_object_t* objects, uint16_t num_objects,
                            link_t* links, uint16_t num_links)
 {
   unsigned* link_count = (unsigned*) calloc (num_objects, sizeof (unsigned));
@@ -65,7 +65,7 @@ void add_links_to_objects (hb_object_t* objects, uint16_t num_objects,
   for (uint32_t i = 0; i < num_objects; i++)
   {
     objects[i].num_real_links = link_count[i];
-    objects[i].real_links = (hb_link_t*) calloc (link_count[i], sizeof (hb_link_t));
+    objects[i].real_links = (hb_subset_serialize_link_t*) calloc (link_count[i], sizeof (hb_subset_serialize_link_t));
     objects[i].num_virtual_links = 0;
     objects[i].virtual_links = nullptr;
   }
@@ -74,7 +74,7 @@ void add_links_to_objects (hb_object_t* objects, uint16_t num_objects,
   {
     uint16_t parent_idx = links[i].parent;
     uint16_t child_idx = links[i].child + 1; // All indices are shifted by 1 by the null object.
-    hb_link_t* link = &(objects[parent_idx].real_links[link_count[parent_idx] - 1]);
+    hb_subset_serialize_link_t* link = &(objects[parent_idx].real_links[link_count[parent_idx] - 1]);
 
     link->width = links[i].width;
     link->position = links[i].position;
@@ -91,7 +91,7 @@ extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
   alloc_state = _fuzzing_alloc_state (data, size);
 
   uint16_t num_objects = 0;
-  hb_object_t* objects = nullptr;
+  hb_subset_serialize_object_t* objects = nullptr;
 
   uint16_t num_real_links = 0;
   link_t* links = nullptr;
@@ -100,7 +100,7 @@ extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
   if (!read<hb_tag_t> (&data, &size, &table_tag)) goto end;
   if (!read<uint16_t> (&data, &size, &num_objects)) goto end;
 
-  objects = (hb_object_t*) calloc (num_objects, sizeof (hb_object_t));
+  objects = (hb_subset_serialize_object_t*) calloc (num_objects, sizeof (hb_subset_serialize_object_t));
   for (uint32_t i = 0; i < num_objects; i++)
   {
     uint16_t blob_size;
@@ -129,9 +129,9 @@ extern "C" int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
   add_links_to_objects (objects, num_objects,
                         links, num_real_links);
 
-  hb_blob_destroy (hb_subset_repack_or_fail (table_tag,
-                                             objects,
-                                             num_objects));
+  hb_blob_destroy (hb_subset_serialize_or_fail (table_tag,
+                                                objects,
+                                                num_objects));
 
 end:
   if (objects)
diff --git a/test/fuzzing/meson.build b/test/fuzzing/meson.build
index d38ca8f9f..fce6d625a 100644
--- a/test/fuzzing/meson.build
+++ b/test/fuzzing/meson.build
@@ -3,12 +3,9 @@ tests = [
   'hb-subset-fuzzer.cc',
   'hb-set-fuzzer.cc',
   'hb-draw-fuzzer.cc',
+  'hb-repacker-fuzzer.cc',
 ]
 
-if get_option('experimental_api')
-  tests += 'hb-repacker-fuzzer.cc'
-endif
-
 foreach file_name : tests
   test_name = file_name.split('.')[0]
 
@@ -63,19 +60,19 @@ test('subset_fuzzer', find_program('run-subset-fuzzer-tests.py'),
   suite: ['fuzzing', 'slow'],
 )
 
-if get_option('experimental_api')
-  test('repacker_fuzzer', find_program('run-repacker-fuzzer-tests.py'),
-    args: [
-      hb_repacker_fuzzer_exe,
-    ],
-    # as the tests are ran concurrently let's raise acceptable time here
-    # ideally better to break and let meson handles them in parallel
-    timeout: 300,
-    workdir: meson.current_build_dir() / '..' / '..',
-    env: env,
-    suite: ['fuzzing', 'slow'],
-  )
-endif
+
+test('repacker_fuzzer', find_program('run-repacker-fuzzer-tests.py'),
+  args: [
+    hb_repacker_fuzzer_exe,
+  ],
+  # as the tests are ran concurrently let's raise acceptable time here
+  # ideally better to break and let meson handles them in parallel
+  timeout: 300,
+  workdir: meson.current_build_dir() / '..' / '..',
+  env: env,
+  suite: ['fuzzing', 'slow'],
+)
+
 
 test('draw_fuzzer', find_program('run-draw-fuzzer-tests.py'),
   args: [
diff --git a/test/shape/data/in-house/fonts/65d1b9099cfb3191931d8d6112d7a03d979d579f.ttf b/test/shape/data/in-house/fonts/65d1b9099cfb3191931d8d6112d7a03d979d579f.ttf
new file mode 100644
index 000000000..cb04a5fca
Binary files /dev/null and b/test/shape/data/in-house/fonts/65d1b9099cfb3191931d8d6112d7a03d979d579f.ttf differ
diff --git a/test/shape/data/in-house/fonts/f4ba5a767ef56a40133844507efb98fee5635e71.ttf b/test/shape/data/in-house/fonts/f4ba5a767ef56a40133844507efb98fee5635e71.ttf
new file mode 100644
index 000000000..646e2d33c
Binary files /dev/null and b/test/shape/data/in-house/fonts/f4ba5a767ef56a40133844507efb98fee5635e71.ttf differ
diff --git a/test/shape/data/in-house/tests/indic-syllable.tests b/test/shape/data/in-house/tests/indic-syllable.tests
index cc5c882f8..84526d9cd 100644
--- a/test/shape/data/in-house/tests/indic-syllable.tests
+++ b/test/shape/data/in-house/tests/indic-syllable.tests
@@ -12,3 +12,4 @@
 ../fonts/b3075ca42b27dde7341c2d0ae16703c5b6640df0.ttf;;U+0B2C,U+0B3E,U+0B55;[uni0B2C=0+641|uni0B3E=0+253|uni0B55=0+0]
 ../fonts/e2b17207c4b7ad78d843e1b0c4d00b09398a1137.ttf;;U+0BAA,U+0BAA,U+0BCD;[pa-tamil=0+778|pa-tamil.001=1+778|pulli-tamil=1@-385,0+0]
 ../fonts/41071178fbce4956d151f50967af458dbf555f7b.ttf;;U+0926,U+093F,U+0938,U+0902,U+092C,U+0930;[isigndeva=0+266|dadeva=0+541|sadeva=2+709|anusvaradeva=2@0,-1+0|badeva=4+537|radeva=5+436]
+../fonts/65d1b9099cfb3191931d8d6112d7a03d979d579f.ttf;;U+00B2,U+0B95;[uni00B2=0+500|uni0B95=1+500]
diff --git a/test/shape/data/in-house/tests/macos.tests b/test/shape/data/in-house/tests/macos.tests
index 803abbd9c..247a2ffb6 100644
--- a/test/shape/data/in-house/tests/macos.tests
+++ b/test/shape/data/in-house/tests/macos.tests
@@ -166,3 +166,5 @@
 /System/Library/Fonts/GeezaPro.ttc@fec826d69594ad925665f93252d8b20daf6b0879;--font-funcs ot;U+0631,U+0628;[u0628.beh=1+1415|u0631.reh=0@-202,0+700]
 /System/Library/Fonts/GeezaPro.ttc@fec826d69594ad925665f93252d8b20daf6b0879;--font-funcs ot;U+0628,U+064F;[u064f.damma=0@250,-250+250|u0628.beh=0@-250,0+1165]
 /System/Library/Fonts/GeezaPro.ttc@fec826d69594ad925665f93252d8b20daf6b0879;--font-funcs ot;U+0644,U+064E,U+0645,U+064E,U+0651,U+0627;[u0627.final.alef=5+647|u064e.fatha=0@-80,160+-80|u064e_u0651.shaddaFatha=0@490,250+490|u0644_u0645.initial.lamMeem=0@-410,0+415]
+/System/Library/Fonts/Supplemental/Courier New.ttf@88d2006ca084f04af2df1954ed714a8c71e8400f;;U+0181,U+0182,U+0183,U+0184,U+0185,U+0186,U+0187,U+0188,U+03FD,U+0674;[uni0181=0+1229|uni0182=1+1229|uni0183=2+1229|uni0184=3+1229|uni0185=4+1229|uni0186=5+1229|uni0187=6+1229|uni0188=7+1229|uni03FD=8+1229|afii57543=9+1229]
+/System/Library/Fonts/Supplemental/Courier New Bold.ttf@608e3ebb6dd1aee521cff08eb07d500a2c59df68;;U+0181,U+0182,U+0183,U+0184,U+0185,U+0186,U+0187,U+0188,U+03FD,U+0674;[uni0181=0+1229|uni0182=1+1229|uni0183=2+1229|uni0184=3+1229|uni0185=4+1229|uni0186=5+1229|uni0187=6+1229|uni0188=7+1229|uni03FD=8+1229|afii57543=9+1229]
diff --git a/test/shape/data/in-house/tests/myanmar-syllable.tests b/test/shape/data/in-house/tests/myanmar-syllable.tests
index 65a4b0b06..e2dc726d3 100644
--- a/test/shape/data/in-house/tests/myanmar-syllable.tests
+++ b/test/shape/data/in-house/tests/myanmar-syllable.tests
@@ -1 +1,3 @@
 ../fonts/af3086380b743099c54a3b11b96766039ea62fcd.ttf;--no-glyph-names;U+101D,U+FE00,U+1031,U+FE00,U+1031,U+FE00;[6=0+465|6=0+465|5=0+502]
+../fonts/f4ba5a767ef56a40133844507efb98fee5635e71.ttf;;U+1000,U+1032,U+1038,U+1069;[ka=0+1124|_ai=0@-27,20+0|visarga=0+346|tone1_wpk=0+423]
+../fonts/65d1b9099cfb3191931d8d6112d7a03d979d579f.ttf;;U+00B2,U+1000;[uni00B2=0+500|uni1000=1+500]
diff --git a/test/shape/data/in-house/tests/use-syllable.tests b/test/shape/data/in-house/tests/use-syllable.tests
index 3586a46a5..2d134244a 100644
--- a/test/shape/data/in-house/tests/use-syllable.tests
+++ b/test/shape/data/in-house/tests/use-syllable.tests
@@ -24,3 +24,4 @@
 ../fonts/2a670df15b73a5dc75a5cc491bde5ac93c5077dc.ttf;;U+11124,U+2060,U+11127;[u11124=0+514|uni25CC=1+547|u11127=1+0]
 ../fonts/a56745bac8449d0ad94918b2bb5930716ba02fe3.ttf;;U+1142C,U+11442,U+200C,U+1142E;[u1142C=0+547|u11442=0+0|u1142E=3+547]
 ../fonts/d0430ea499348c420946f6abc2efc84fdf8f00e3.ttf;;U+1142C,U+11442,U+1140E,U+1145E;[u1140E=0+736|u1142C_u11442=0+0|u1145E=0+0]
+../fonts/65d1b9099cfb3191931d8d6112d7a03d979d579f.ttf;;U+00B2,U+11315;[uni00B2=0+500|u11315=1+500]
diff --git a/test/shape/hb_test_tools.py b/test/shape/hb_test_tools.py
index 682b919b6..4b4614626 100644
--- a/test/shape/hb_test_tools.py
+++ b/test/shape/hb_test_tools.py
@@ -1,6 +1,6 @@
 #!/usr/bin/env python3
 
-import sys, os, re, difflib, unicodedata, errno, cgi, itertools
+import sys, os, re, difflib, unicodedata, errno, html, itertools
 from itertools import *
 
 diff_symbols = "-+=*&^%$#@!~/"
@@ -45,7 +45,7 @@ class ColorFormatter:
 		def end_color ():
 			return '</span>'
 		@staticmethod
-		def escape (s): return cgi.escape (s)
+		def escape (s): return html.escape (s)
 		@staticmethod
 		def newline (): return '<br/>\n'
 
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.default.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints-retain-gids.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.drop-hints.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.default.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints-retain-gids.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.drop-hints.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.gap.retain-gids.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.default.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints-retain-gids.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.drop-hints.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.index_format3.retain-gids.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.default.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints-retain-gids.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.drop-hints.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.multiple_size_tables.retain-gids.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.38,39,AE,2049,38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.38,39,AE,2049,38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.0038,0039,00AE,2049,0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.38,AE,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.0038,00AE,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.38,AE,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.0038,00AE,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.38,2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.0038,2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.38,2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.0038,2049,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.38,20E3.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.0038,20E3,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.38,20E3.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.0038,20E3,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.39.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.0039,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.39.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.0039,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.AE.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.00AE,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.AE.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.00AE,FE0F.ttf
diff --git a/test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.2049.ttf b/test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.2049,FE0F.ttf
similarity index 100%
rename from test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.2049.ttf
rename to test/subset/data/expected/cbdt/NotoColorEmoji.subset.retain-gids.2049,FE0F.ttf
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E02,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E02,4E03,E0100.otf
new file mode 100644
index 000000000..6f417f274
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E02,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E02,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E02,4E03.otf
index 6f417f274..ea3760076 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E02,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E02,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E03,E0100.otf
new file mode 100644
index 000000000..4f3902b39
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E03.otf
index 4f3902b39..546e84c5d 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E05,4E07,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E05,4E07,E0100.otf
new file mode 100644
index 000000000..22d8b57f0
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E05,4E07,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E05,4E07.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E05,4E07.otf
index 22d8b57f0..343bfb529 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E05,4E07.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E00,4E05,4E07.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E02,4E03,4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E02,4E03,4E08,E0100.otf
new file mode 100644
index 000000000..e80e29023
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E02,4E03,4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E02,4E03,4E08.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E02,4E03,4E08.otf
index e80e29023..17e0c4df4 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E02,4E03,4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E02,4E03,4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E02,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E02,E0100.otf
new file mode 100644
index 000000000..21efe7a1f
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E02,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E03,E0100.otf
new file mode 100644
index 000000000..6b68f7008
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E03.otf
index 6b68f7008..1b2836fe6 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E05,4E07,4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E05,4E07,4E08,4E09,E0100.otf
new file mode 100644
index 000000000..2877b3c50
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E05,4E07,4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E05,4E07,4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E05,4E07,4E08,4E09.otf
index 2877b3c50..bf5999fe2 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E05,4E07,4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E05,4E07,4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E08,4E09,E0100.otf
new file mode 100644
index 000000000..69bcaaffb
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E08,4E09.otf
index 69bcaaffb..ebb87e53e 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E08,E0100.otf
new file mode 100644
index 000000000..a1c08be66
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E08.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E08.otf
index a1c08be66..ee603c920 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints-retain-gids.4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E02,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E02,4E03,E0100.otf
new file mode 100644
index 000000000..041218728
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E02,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E02,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E02,4E03.otf
index 041218728..a47bfd0a3 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E02,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E02,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E03,E0100.otf
new file mode 100644
index 000000000..03ad26dab
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E03.otf
index 03ad26dab..f05d066e7 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E05,4E07,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E05,4E07,E0100.otf
new file mode 100644
index 000000000..1b995fee4
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E05,4E07,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E05,4E07.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E05,4E07.otf
index 1b995fee4..760884c80 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E05,4E07.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E00,4E05,4E07.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E02,4E03,4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E02,4E03,4E08,E0100.otf
new file mode 100644
index 000000000..543fec5f2
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E02,4E03,4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E02,4E03,4E08.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E02,4E03,4E08.otf
index 543fec5f2..679dad271 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E02,4E03,4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E02,4E03,4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E02,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E02,E0100.otf
new file mode 100644
index 000000000..ff9f70cdb
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E02,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E03,E0100.otf
new file mode 100644
index 000000000..877c1915c
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E03.otf
index 877c1915c..b5ee80f3e 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E05,4E07,4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E05,4E07,4E08,4E09,E0100.otf
new file mode 100644
index 000000000..8a91fe0eb
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E05,4E07,4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E05,4E07,4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E05,4E07,4E08,4E09.otf
index 8a91fe0eb..f89d1d4ef 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E05,4E07,4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E05,4E07,4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E08,4E09,E0100.otf
new file mode 100644
index 000000000..c125b7032
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E08,4E09.otf
index c125b7032..8b575b7d7 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E08,E0100.otf
new file mode 100644
index 000000000..0eb2f9e72
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E08.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E08.otf
index 0eb2f9e72..ec21a0aff 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-drop-hints.4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E02,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E02,4E03,E0100.otf
new file mode 100644
index 000000000..fbe79dfcf
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E02,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E02,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E02,4E03.otf
index fbe79dfcf..7800d1aa5 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E02,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E02,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E03,E0100.otf
new file mode 100644
index 000000000..2e0edaf9d
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E03.otf
index 2e0edaf9d..ef28ff2ab 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E05,4E07,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E05,4E07,E0100.otf
new file mode 100644
index 000000000..ec0fad37b
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E05,4E07,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E05,4E07.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E05,4E07.otf
index ec0fad37b..a53b19e34 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E05,4E07.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E00,4E05,4E07.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E02,4E03,4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E02,4E03,4E08,E0100.otf
new file mode 100644
index 000000000..3767814ce
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E02,4E03,4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E02,4E03,4E08.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E02,4E03,4E08.otf
index 3767814ce..0842d509c 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E02,4E03,4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E02,4E03,4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E02,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E02,E0100.otf
new file mode 100644
index 000000000..87059e214
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E02,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E03,E0100.otf
new file mode 100644
index 000000000..a99addafb
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E03.otf
index a99addafb..4bf741c40 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E05,4E07,4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E05,4E07,4E08,4E09,E0100.otf
new file mode 100644
index 000000000..d4b390860
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E05,4E07,4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E05,4E07,4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E05,4E07,4E08,4E09.otf
index d4b390860..2b973b88a 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E05,4E07,4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E05,4E07,4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E08,4E09,E0100.otf
new file mode 100644
index 000000000..a1f9def1a
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E08,4E09.otf
index a1f9def1a..ad15a18a7 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E08,E0100.otf
new file mode 100644
index 000000000..ca9512af1
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E08.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E08.otf
index ca9512af1..9f420180e 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-gids.4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E02,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E02,4E03,E0100.otf
new file mode 100644
index 000000000..07f7b2582
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E02,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E02,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E02,4E03.otf
index 07f7b2582..671c4ba3d 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E02,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E02,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E03,E0100.otf
new file mode 100644
index 000000000..c491db487
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E03.otf
index c491db487..703d60c90 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E05,4E07,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E05,4E07,E0100.otf
new file mode 100644
index 000000000..3f35b1999
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E05,4E07,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E05,4E07.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E05,4E07.otf
index 3f35b1999..6d7ded1ec 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E05,4E07.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E00,4E05,4E07.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E02,4E03,4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E02,4E03,4E08,E0100.otf
new file mode 100644
index 000000000..a26347d49
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E02,4E03,4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E02,4E03,4E08.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E02,4E03,4E08.otf
index a26347d49..5e6d5865a 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E02,4E03,4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E02,4E03,4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E02,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E02,E0100.otf
new file mode 100644
index 000000000..d0d6613e3
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E02,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E03,E0100.otf
new file mode 100644
index 000000000..fbf89373e
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E03.otf
index fbf89373e..3e50a7171 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E05,4E07,4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E05,4E07,4E08,4E09,E0100.otf
new file mode 100644
index 000000000..fc7f26b13
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E05,4E07,4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E05,4E07,4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E05,4E07,4E08,4E09.otf
index fc7f26b13..cdb017254 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E05,4E07,4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E05,4E07,4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E08,4E09,E0100.otf
new file mode 100644
index 000000000..8b41561f9
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E08,4E09.otf
index 8b41561f9..1be0ab786 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E08,E0100.otf
new file mode 100644
index 000000000..391218f34
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E08.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E08.otf
index 391218f34..0c044012e 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-name-ids.4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E02,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E02,4E03,E0100.otf
new file mode 100644
index 000000000..4a212017f
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E02,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E02,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E02,4E03.otf
index 4a212017f..5e513cc1b 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E02,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E02,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E03,E0100.otf
new file mode 100644
index 000000000..bec789b5e
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E03.otf
index bec789b5e..bbab3254d 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E05,4E07,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E05,4E07,E0100.otf
new file mode 100644
index 000000000..cacbb74f0
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E05,4E07,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E05,4E07.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E05,4E07.otf
index cacbb74f0..0f521cf11 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E05,4E07.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E00,4E05,4E07.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E02,4E03,4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E02,4E03,4E08,E0100.otf
new file mode 100644
index 000000000..09a8c3fe7
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E02,4E03,4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E02,4E03,4E08.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E02,4E03,4E08.otf
index 09a8c3fe7..ed8243af2 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E02,4E03,4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E02,4E03,4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E02,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E02,E0100.otf
new file mode 100644
index 000000000..eaca75c91
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E02,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E03,E0100.otf
new file mode 100644
index 000000000..f0a95ebb8
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E03.otf
index f0a95ebb8..1c9bcf70c 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E05,4E07,4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E05,4E07,4E08,4E09,E0100.otf
new file mode 100644
index 000000000..2701ca193
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E05,4E07,4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E05,4E07,4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E05,4E07,4E08,4E09.otf
index 2701ca193..f9d7e1a68 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E05,4E07,4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E05,4E07,4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E08,4E09,E0100.otf
new file mode 100644
index 000000000..18a48b64e
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E08,4E09.otf
index 18a48b64e..e56b81b97 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E08,E0100.otf
new file mode 100644
index 000000000..fcd8c4f65
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E08.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E08.otf
index fcd8c4f65..5956517c1 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline-retain-gids.4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E02,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E02,4E03,E0100.otf
new file mode 100644
index 000000000..8bb85a642
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E02,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E02,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E02,4E03.otf
index 8bb85a642..7c9667a1c 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E02,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E02,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E03,E0100.otf
new file mode 100644
index 000000000..137f1651d
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E03.otf
index 137f1651d..3edfd175c 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E05,4E07,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E05,4E07,E0100.otf
new file mode 100644
index 000000000..1b2dfdfb9
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E05,4E07,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E05,4E07.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E05,4E07.otf
index 1b2dfdfb9..318a6968f 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E05,4E07.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E00,4E05,4E07.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E02,4E03,4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E02,4E03,4E08,E0100.otf
new file mode 100644
index 000000000..4dee16901
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E02,4E03,4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E02,4E03,4E08.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E02,4E03,4E08.otf
index 4dee16901..6d9999d08 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E02,4E03,4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E02,4E03,4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E02,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E02,E0100.otf
new file mode 100644
index 000000000..775a67c93
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E02,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E03,E0100.otf
new file mode 100644
index 000000000..fcf87259a
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E03.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E03.otf
index fcf87259a..b4df95889 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E05,4E07,4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E05,4E07,4E08,4E09,E0100.otf
new file mode 100644
index 000000000..0248360e6
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E05,4E07,4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E05,4E07,4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E05,4E07,4E08,4E09.otf
index 0248360e6..30c9a1df4 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E05,4E07,4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E05,4E07,4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E08,4E09,E0100.otf
new file mode 100644
index 000000000..649feae14
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E08,4E09.otf
index 649feae14..69bec2437 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E08,E0100.otf
new file mode 100644
index 000000000..8010c0f04
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E08.otf b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E08.otf
index 8010c0f04..8552571b2 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font1.notdef-outline.4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E02,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E02,4E03,E0100.otf
new file mode 100644
index 000000000..a1720189a
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E02,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E02,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E02,4E03.otf
index a1720189a..ccdc0cf47 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E02,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E02,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E03,E0100.otf
new file mode 100644
index 000000000..59ba9b2da
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E03.otf
index 59ba9b2da..0faf9d721 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E05,4E07,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E05,4E07,E0100.otf
new file mode 100644
index 000000000..ed110b9d9
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E05,4E07,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E05,4E07.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E05,4E07.otf
index ed110b9d9..9f54caba9 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E05,4E07.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E00,4E05,4E07.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E02,4E03,4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E02,4E03,4E08,E0100.otf
new file mode 100644
index 000000000..996713e60
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E02,4E03,4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E02,4E03,4E08.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E02,4E03,4E08.otf
index 996713e60..75e538c13 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E02,4E03,4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E02,4E03,4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E02,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E02,E0100.otf
new file mode 100644
index 000000000..dda36155d
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E02,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E03,E0100.otf
new file mode 100644
index 000000000..8f0e542f3
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E03.otf
index 8f0e542f3..f5e32265d 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E05,4E07,4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E05,4E07,4E08,4E09,E0100.otf
new file mode 100644
index 000000000..9247f615f
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E05,4E07,4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E05,4E07,4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E05,4E07,4E08,4E09.otf
index 9247f615f..5de4bc5c5 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E05,4E07,4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E05,4E07,4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E08,4E09,E0100.otf
new file mode 100644
index 000000000..91bdcdd05
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E08,4E09.otf
index 91bdcdd05..b9fd93fc5 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E08,E0100.otf
new file mode 100644
index 000000000..6d4ea8f84
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E08.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E08.otf
index 6d4ea8f84..c78826108 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints-retain-gids.4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E02,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E02,4E03,E0100.otf
new file mode 100644
index 000000000..a0a8321b2
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E02,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E02,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E02,4E03.otf
index a0a8321b2..e8847725f 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E02,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E02,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E03,E0100.otf
new file mode 100644
index 000000000..8897d7486
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E03.otf
index 8897d7486..2d5269a2a 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E05,4E07,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E05,4E07,E0100.otf
new file mode 100644
index 000000000..717f255f2
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E05,4E07,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E05,4E07.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E05,4E07.otf
index 717f255f2..d2b75bc1d 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E05,4E07.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E00,4E05,4E07.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E02,4E03,4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E02,4E03,4E08,E0100.otf
new file mode 100644
index 000000000..c90f248c3
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E02,4E03,4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E02,4E03,4E08.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E02,4E03,4E08.otf
index c90f248c3..d4f848ed5 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E02,4E03,4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E02,4E03,4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E02,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E02,E0100.otf
new file mode 100644
index 000000000..f364d0eba
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E02,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E03,E0100.otf
new file mode 100644
index 000000000..d2e491549
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E03.otf
index d2e491549..5c8fdcba5 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E05,4E07,4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E05,4E07,4E08,4E09,E0100.otf
new file mode 100644
index 000000000..eaa29437f
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E05,4E07,4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E05,4E07,4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E05,4E07,4E08,4E09.otf
index eaa29437f..62de2b140 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E05,4E07,4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E05,4E07,4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E08,4E09,E0100.otf
new file mode 100644
index 000000000..7bb0772c2
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E08,4E09.otf
index 7bb0772c2..c064f2eec 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E08,E0100.otf
new file mode 100644
index 000000000..c19070087
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E08.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E08.otf
index c19070087..4ce17301c 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-drop-hints.4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E02,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E02,4E03,E0100.otf
new file mode 100644
index 000000000..d9d7645c3
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E02,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E02,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E02,4E03.otf
index d9d7645c3..9abbcc1ce 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E02,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E02,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E03,E0100.otf
new file mode 100644
index 000000000..46195031c
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E03.otf
index 46195031c..d0d477434 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E05,4E07,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E05,4E07,E0100.otf
new file mode 100644
index 000000000..eaab0aac9
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E05,4E07,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E05,4E07.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E05,4E07.otf
index eaab0aac9..8d8430e8f 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E05,4E07.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E00,4E05,4E07.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E02,4E03,4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E02,4E03,4E08,E0100.otf
new file mode 100644
index 000000000..1e00ded7a
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E02,4E03,4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E02,4E03,4E08.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E02,4E03,4E08.otf
index 1e00ded7a..46db924cd 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E02,4E03,4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E02,4E03,4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E02,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E02,E0100.otf
new file mode 100644
index 000000000..986c80ecf
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E02,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E03,E0100.otf
new file mode 100644
index 000000000..dd00dfb4b
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E03.otf
index dd00dfb4b..14c87cb5a 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E05,4E07,4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E05,4E07,4E08,4E09,E0100.otf
new file mode 100644
index 000000000..1eac8ee70
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E05,4E07,4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E05,4E07,4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E05,4E07,4E08,4E09.otf
index 1eac8ee70..65d412653 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E05,4E07,4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E05,4E07,4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E08,4E09,E0100.otf
new file mode 100644
index 000000000..e4ec6621d
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E08,4E09.otf
index e4ec6621d..5422b936d 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E08,E0100.otf
new file mode 100644
index 000000000..a1ac1e98e
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E08.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E08.otf
index a1ac1e98e..5f92be899 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-gids.4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E02,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E02,4E03,E0100.otf
new file mode 100644
index 000000000..21b6f7d3d
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E02,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E02,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E02,4E03.otf
index 21b6f7d3d..7a59c5fb4 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E02,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E02,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E03,E0100.otf
new file mode 100644
index 000000000..ed3e4eb2d
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E03.otf
index ed3e4eb2d..ff5f02952 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E05,4E07,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E05,4E07,E0100.otf
new file mode 100644
index 000000000..9d591eb87
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E05,4E07,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E05,4E07.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E05,4E07.otf
index 9d591eb87..0146a0003 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E05,4E07.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E00,4E05,4E07.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E02,4E03,4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E02,4E03,4E08,E0100.otf
new file mode 100644
index 000000000..19fdddbf7
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E02,4E03,4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E02,4E03,4E08.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E02,4E03,4E08.otf
index 19fdddbf7..83b7d25b5 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E02,4E03,4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E02,4E03,4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E02,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E02,E0100.otf
new file mode 100644
index 000000000..ab18162ce
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E02,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E03,E0100.otf
new file mode 100644
index 000000000..206579586
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E03.otf
index 206579586..b2df0657e 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E05,4E07,4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E05,4E07,4E08,4E09,E0100.otf
new file mode 100644
index 000000000..dc14f3875
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E05,4E07,4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E05,4E07,4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E05,4E07,4E08,4E09.otf
index dc14f3875..48d907b8a 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E05,4E07,4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E05,4E07,4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E08,4E09,E0100.otf
new file mode 100644
index 000000000..bebffae65
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E08,4E09.otf
index bebffae65..1b3b01386 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E08,E0100.otf
new file mode 100644
index 000000000..317e87647
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E08.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E08.otf
index 317e87647..9b7da18b8 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-name-ids.4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E02,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E02,4E03,E0100.otf
new file mode 100644
index 000000000..7b3046a75
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E02,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E02,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E02,4E03.otf
index 7b3046a75..2b1abd61c 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E02,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E02,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E03,E0100.otf
new file mode 100644
index 000000000..82efd78a7
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E03.otf
index 82efd78a7..8d126f8ef 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E05,4E07,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E05,4E07,E0100.otf
new file mode 100644
index 000000000..fba35b019
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E05,4E07,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E05,4E07.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E05,4E07.otf
index fba35b019..e57c0cc45 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E05,4E07.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E00,4E05,4E07.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E02,4E03,4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E02,4E03,4E08,E0100.otf
new file mode 100644
index 000000000..6669184f2
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E02,4E03,4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E02,4E03,4E08.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E02,4E03,4E08.otf
index 6669184f2..cc81a2c65 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E02,4E03,4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E02,4E03,4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E02,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E02,E0100.otf
new file mode 100644
index 000000000..b23afcecb
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E02,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E03,E0100.otf
new file mode 100644
index 000000000..6e2a5228d
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E03.otf
index 6e2a5228d..d9e56ef3f 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E05,4E07,4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E05,4E07,4E08,4E09,E0100.otf
new file mode 100644
index 000000000..b9a1ed1f7
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E05,4E07,4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E05,4E07,4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E05,4E07,4E08,4E09.otf
index b9a1ed1f7..a8563fefd 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E05,4E07,4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E05,4E07,4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E08,4E09,E0100.otf
new file mode 100644
index 000000000..d48a5e1e9
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E08,4E09.otf
index d48a5e1e9..ef0fe90dd 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E08,E0100.otf
new file mode 100644
index 000000000..40c22d2cb
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E08.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E08.otf
index 40c22d2cb..b8061dafc 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline-retain-gids.4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E02,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E02,4E03,E0100.otf
new file mode 100644
index 000000000..1ad2629ee
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E02,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E02,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E02,4E03.otf
index 1ad2629ee..3d7c8fa19 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E02,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E02,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E03,E0100.otf
new file mode 100644
index 000000000..0925800e9
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E03.otf
index 0925800e9..56f6079d2 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E05,4E07,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E05,4E07,E0100.otf
new file mode 100644
index 000000000..1ed837bb7
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E05,4E07,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E05,4E07.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E05,4E07.otf
index 1ed837bb7..0cc701f2c 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E05,4E07.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E00,4E05,4E07.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E02,4E03,4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E02,4E03,4E08,E0100.otf
new file mode 100644
index 000000000..778a2d66e
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E02,4E03,4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E02,4E03,4E08.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E02,4E03,4E08.otf
index 778a2d66e..8ad67b020 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E02,4E03,4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E02,4E03,4E08.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E02,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E02,E0100.otf
new file mode 100644
index 000000000..698901170
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E02,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E03,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E03,E0100.otf
new file mode 100644
index 000000000..c6aeacd1b
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E03,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E03.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E03.otf
index c6aeacd1b..c8f9b74a0 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E03.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E03.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E05,4E07,4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E05,4E07,4E08,4E09,E0100.otf
new file mode 100644
index 000000000..cd02fda86
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E05,4E07,4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E05,4E07,4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E05,4E07,4E08,4E09.otf
index cd02fda86..87892c6a6 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E05,4E07,4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E05,4E07,4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E08,4E09,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E08,4E09,E0100.otf
new file mode 100644
index 000000000..13148c83b
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E08,4E09,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E08,4E09.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E08,4E09.otf
index 13148c83b..b34218b7f 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E08,4E09.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E08,4E09.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E08,E0100.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E08,E0100.otf
new file mode 100644
index 000000000..546ce3418
Binary files /dev/null and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E08,E0100.otf differ
diff --git a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E08.otf b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E08.otf
index 546ce3418..5e123d430 100644
Binary files a/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E08.otf and b/test/subset/data/expected/cmap14/cmap14_font2.notdef-outline.4E08.otf differ
diff --git a/test/subset/data/expected/instantiate_gvar_padding/googlesansflex_subset.default.all.ROND=100.0,slnt=0.0,wdth=150.0,wght=500.0.iup_optimize.ttf b/test/subset/data/expected/instantiate_gvar_padding/googlesansflex_subset.default.all.ROND=100.0,slnt=0.0,wdth=150.0,wght=500.0.iup_optimize.ttf
new file mode 100644
index 000000000..b3bdca5f9
Binary files /dev/null and b/test/subset/data/expected/instantiate_gvar_padding/googlesansflex_subset.default.all.ROND=100.0,slnt=0.0,wdth=150.0,wght=500.0.iup_optimize.ttf differ
diff --git a/test/subset/data/expected/instantiate_gvar_padding/googlesansflex_subset.default.all.ROND=100.0,slnt=0.0,wdth=150.0,wght=500.0.ttf b/test/subset/data/expected/instantiate_gvar_padding/googlesansflex_subset.default.all.ROND=100.0,slnt=0.0,wdth=150.0,wght=500.0.ttf
new file mode 100644
index 000000000..0f88afd97
Binary files /dev/null and b/test/subset/data/expected/instantiate_gvar_padding/googlesansflex_subset.default.all.ROND=100.0,slnt=0.0,wdth=150.0,wght=500.0.ttf differ
diff --git a/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test-retain-gids.53A9,53F1.otf b/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test-retain-gids.53A9,53F1.otf
index 87ada2618..743a2f2f3 100644
Binary files a/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test-retain-gids.53A9,53F1.otf and b/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test-retain-gids.53A9,53F1.otf differ
diff --git a/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test-retain-gids.53A9.otf b/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test-retain-gids.53A9.otf
index 42464f352..456c7e26a 100644
Binary files a/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test-retain-gids.53A9.otf and b/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test-retain-gids.53A9.otf differ
diff --git a/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test-retain-gids.53F1.otf b/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test-retain-gids.53F1.otf
index 009db72e8..f390a6cd0 100644
Binary files a/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test-retain-gids.53F1.otf and b/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test-retain-gids.53F1.otf differ
diff --git a/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test.53A9,53F1.otf b/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test.53A9,53F1.otf
index 1a4f65f8d..59eccd61d 100644
Binary files a/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test.53A9,53F1.otf and b/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test.53A9,53F1.otf differ
diff --git a/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test.53A9.otf b/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test.53A9.otf
index c1cd42ccc..38e3d8ad8 100644
Binary files a/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test.53A9.otf and b/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test.53A9.otf differ
diff --git a/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test.53F1.otf b/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test.53F1.otf
index 688005a05..bd8c7115a 100644
Binary files a/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test.53F1.otf and b/test/subset/data/expected/layout.gsub3/gsub_alternate_substitution.layout-test.53F1.otf differ
diff --git a/test/subset/data/fonts/googlesansflex_subset.ttf b/test/subset/data/fonts/googlesansflex_subset.ttf
new file mode 100644
index 000000000..e6d670ce8
Binary files /dev/null and b/test/subset/data/fonts/googlesansflex_subset.ttf differ
diff --git a/test/subset/data/tests/cbdt.tests b/test/subset/data/tests/cbdt.tests
index 5e74fef73..15e58779b 100644
--- a/test/subset/data/tests/cbdt.tests
+++ b/test/subset/data/tests/cbdt.tests
@@ -11,10 +11,10 @@ drop-hints-retain-gids.txt
 retain-gids.txt
 
 SUBSETS:
-89®⁉8⃣
-8®⁉
-8⁉
-®
-9
-⁉
-8⃣
+U+0038,U+0039,U+00AE,U+2049,U+0038,U+20E3,U+FE0F
+U+0038,U+00AE,U+2049,U+FE0F
+U+0038,U+2049,U+FE0F
+U+00AE,U+FE0F
+U+0039,U+FE0F
+U+2049,U+FE0F
+U+0038,U+20E3,U+FE0F
diff --git a/test/subset/data/tests/cmap14.tests b/test/subset/data/tests/cmap14.tests
index abfec32d9..5165f1c14 100644
--- a/test/subset/data/tests/cmap14.tests
+++ b/test/subset/data/tests/cmap14.tests
@@ -11,13 +11,22 @@ notdef-outline-name-ids.txt
 notdef-outline-gids.txt
 
 SUBSETS:
-一丂七
-丂
-七
-一七
-一丅万
-丅万丈三
-丈
-丈三
-丂七丈
+U+4E00,U+4E02,U+4E03
+U+4E02
+U+4E03
+U+4E00,U+4E03
+U+4E00,U+4E05,U+4E07
+U+4E05,U+4E07,U+4E08,U+4E09
+U+4E08
+U+4E08,U+4E09
+U+4E02,U+4E03,U+4E08
 *
+U+4E00,U+4E02,U+4E03,U+E0100
+U+4E02,U+E0100
+U+4E03,U+E0100
+U+4E00,U+4E03,U+E0100
+U+4E00,U+4E05,U+4E07,U+E0100
+U+4E05,U+4E07,U+4E08,U+4E09,U+E0100
+U+4E08,U+E0100
+U+4E08,U+4E09,U+E0100
+U+4E02,U+4E03,U+4E08,U+E0100
diff --git a/test/subset/data/tests/instantiate_gvar_padding.tests b/test/subset/data/tests/instantiate_gvar_padding.tests
new file mode 100644
index 000000000..f02f692db
--- /dev/null
+++ b/test/subset/data/tests/instantiate_gvar_padding.tests
@@ -0,0 +1,15 @@
+FONTS:
+googlesansflex_subset.ttf
+
+PROFILES:
+default.txt
+
+SUBSETS:
+*
+
+INSTANCES:
+ROND=100.0,slnt=0.0,wdth=150.0,wght=500.0
+
+IUP_OPTIONS:
+Yes
+No
diff --git a/test/subset/data/tests/layout.gsub3.tests b/test/subset/data/tests/layout.gsub3.tests
index 35d02fb22..065457bdf 100644
--- a/test/subset/data/tests/layout.gsub3.tests
+++ b/test/subset/data/tests/layout.gsub3.tests
@@ -10,3 +10,7 @@ SUBSETS:
 叱
 厩叱
 *
+
+# TODO temporary until diff with fonttools on FDSelect format is fixed.
+OPTIONS:
+no_fonttools
diff --git a/test/subset/meson.build b/test/subset/meson.build
index b35489329..dffba6463 100644
--- a/test/subset/meson.build
+++ b/test/subset/meson.build
@@ -79,6 +79,7 @@ tests = [
   'sync_vmetrics',
   'empty_region_vardata',
   'colrv1_partial_instance',
+  'instantiate_gvar_padding',
 ]
 
 if get_option('experimental_api')
diff --git a/util/helper-cairo.hh b/util/helper-cairo.hh
index a457f1024..b6ef80677 100644
--- a/util/helper-cairo.hh
+++ b/util/helper-cairo.hh
@@ -156,6 +156,18 @@ helper_cairo_create_scaled_font (const font_options_t *font_opts,
 							       &font_matrix,
 							       &ctm,
 							       font_options);
+  if (cairo_scaled_font_status (scaled_font) == CAIRO_STATUS_INVALID_MATRIX)
+  {
+    // Set font matrix to 0, which *does* work with cairo_scaled_font_create()
+    font_matrix.xx = font_matrix.yy = 0;
+    font_matrix.xy = font_matrix.yx = 0;
+    font_matrix.x0 = font_matrix.y0 = 0;
+    scaled_font = cairo_scaled_font_create (cairo_face,
+					    &font_matrix,
+					    &ctm,
+					    font_options);
+
+  }
 
   cairo_font_options_destroy (font_options);
   cairo_font_face_destroy (cairo_face);
diff --git a/util/helper-subset.hh b/util/helper-subset.hh
index a050d713d..91d5f7b54 100644
--- a/util/helper-subset.hh
+++ b/util/helper-subset.hh
@@ -34,92 +34,6 @@
 
 #ifndef HB_NO_VAR
 
-// Parses an axis position string and sets min, default, and max to
-// the requested values. If a value should be set to it's default value
-// then it will be set to NaN.
-static gboolean
-parse_axis_position(const char* s,
-                    float* min,
-                    float* def,
-                    float* max,
-                    gboolean* drop,
-                    GError **error)
-{
-  const char* part = strpbrk(s, ":");
-  *drop = false;
-  if (!part) {
-    // Single value.
-    if (strcmp (s, "drop") == 0)
-    {
-      *min = NAN;
-      *def = NAN;
-      *max = NAN;
-      *drop = true;
-      return true;
-    }
-
-    errno = 0;
-    char *p;
-    float axis_value = strtof (s, &p);
-    if (errno || s == p)
-    {
-      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
-                   "Failed parsing axis value at: '%s'", s);
-      return false;
-    }
-
-    *min = axis_value;
-    *def = axis_value;
-    *max = axis_value;
-    return true;
-  }
-
-
-  float values[3];
-  int count = 0;
-  for (int i = 0; i < 3; i++) {
-    errno = 0;
-    count++;
-    if (!*s || part == s) {
-      values[i] = NAN;
-
-      if (part == NULL) break;
-      s = part + 1;
-      part = strpbrk(s, ":");
-      continue;
-    }
-
-    char *pend;
-    values[i] = strtof (s, &pend);
-    if (errno || s == pend || (part && pend != part))
-    {
-      g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
-                   "Failed parsing axis value at: '%s'", s);
-      return false;
-    }
-
-    if (part == NULL) break;
-    s = pend + 1;
-    part = strpbrk(s, ":");
-  }
-
-  if (count == 2) {
-    *min = values[0];
-    *def = NAN;
-    *max = values[1];
-    return true;
-  } else if (count == 3) {
-    *min = values[0];
-    *def = values[1];
-    *max = values[2];
-    return true;
-  }
-
-  g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
-                   "Failed parsing axis value at: '%s'", s);
-  return false;
-}
-
 static gboolean
 parse_instancing_spec (const char *arg,
                        hb_face_t* face,
@@ -168,13 +82,7 @@ parse_instancing_spec (const char *arg,
       return false;
     }
 
-    gboolean drop;
-    float min, def, max;
-    if (!parse_axis_position(s, &min, &def, &max, &drop, error))
-      return false;
-
-    if (drop)
-    {
+    if (strcmp (s, "drop") == 0) {
       if (!hb_subset_input_pin_axis_to_default (input,
                                                 face,
                                                 axis_tag))
@@ -185,18 +93,9 @@ parse_instancing_spec (const char *arg,
       }
       continue;
     }
-
-    if (min == def && def == max) {
-      if (!hb_subset_input_pin_axis_location (input,
-                                              face, axis_tag,
-                                              def))
-      {
-        g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
-                     "Cannot pin axis: '%c%c%c%c', not present in fvar", HB_UNTAG (axis_tag));
-        return false;
-      }
-      continue;
-    }
+    float min, def, max;
+    if (!hb_subset_axis_range_from_string(s, -1, &min, &max, &def))
+      return false;
 
     if (!hb_subset_input_set_axis_range (input,
                                          face, axis_tag,
@@ -207,10 +106,6 @@ parse_instancing_spec (const char *arg,
       return false;
     }
     continue;
-
-    g_set_error (error, G_OPTION_ERROR, G_OPTION_ERROR_BAD_VALUE,
-                 "Partial instancing is not supported.");
-    return false;
   }
 
   return true;
```

