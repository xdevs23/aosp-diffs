```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..bf62142
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_trusty_user_app_authmgr",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/LICENSE b/LICENSE
new file mode 100644
index 0000000..57bc88a
--- /dev/null
+++ b/LICENSE
@@ -0,0 +1,202 @@
+                                 Apache License
+                           Version 2.0, January 2004
+                        http://www.apache.org/licenses/
+
+   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
+
+   1. Definitions.
+
+      "License" shall mean the terms and conditions for use, reproduction,
+      and distribution as defined by Sections 1 through 9 of this document.
+
+      "Licensor" shall mean the copyright owner or entity authorized by
+      the copyright owner that is granting the License.
+
+      "Legal Entity" shall mean the union of the acting entity and all
+      other entities that control, are controlled by, or are under common
+      control with that entity. For the purposes of this definition,
+      "control" means (i) the power, direct or indirect, to cause the
+      direction or management of such entity, whether by contract or
+      otherwise, or (ii) ownership of fifty percent (50%) or more of the
+      outstanding shares, or (iii) beneficial ownership of such entity.
+
+      "You" (or "Your") shall mean an individual or Legal Entity
+      exercising permissions granted by this License.
+
+      "Source" form shall mean the preferred form for making modifications,
+      including but not limited to software source code, documentation
+      source, and configuration files.
+
+      "Object" form shall mean any form resulting from mechanical
+      transformation or translation of a Source form, including but
+      not limited to compiled object code, generated documentation,
+      and conversions to other media types.
+
+      "Work" shall mean the work of authorship, whether in Source or
+      Object form, made available under the License, as indicated by a
+      copyright notice that is included in or attached to the work
+      (an example is provided in the Appendix below).
+
+      "Derivative Works" shall mean any work, whether in Source or Object
+      form, that is based on (or derived from) the Work and for which the
+      editorial revisions, annotations, elaborations, or other modifications
+      represent, as a whole, an original work of authorship. For the purposes
+      of this License, Derivative Works shall not include works that remain
+      separable from, or merely link (or bind by name) to the interfaces of,
+      the Work and Derivative Works thereof.
+
+      "Contribution" shall mean any work of authorship, including
+      the original version of the Work and any modifications or additions
+      to that Work or Derivative Works thereof, that is intentionally
+      submitted to Licensor for inclusion in the Work by the copyright owner
+      or by an individual or Legal Entity authorized to submit on behalf of
+      the copyright owner. For the purposes of this definition, "submitted"
+      means any form of electronic, verbal, or written communication sent
+      to the Licensor or its representatives, including but not limited to
+      communication on electronic mailing lists, source code control systems,
+      and issue tracking systems that are managed by, or on behalf of, the
+      Licensor for the purpose of discussing and improving the Work, but
+      excluding communication that is conspicuously marked or otherwise
+      designated in writing by the copyright owner as "Not a Contribution."
+
+      "Contributor" shall mean Licensor and any individual or Legal Entity
+      on behalf of whom a Contribution has been received by Licensor and
+      subsequently incorporated within the Work.
+
+   2. Grant of Copyright License. Subject to the terms and conditions of
+      this License, each Contributor hereby grants to You a perpetual,
+      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
+      copyright license to reproduce, prepare Derivative Works of,
+      publicly display, publicly perform, sublicense, and distribute the
+      Work and such Derivative Works in Source or Object form.
+
+   3. Grant of Patent License. Subject to the terms and conditions of
+      this License, each Contributor hereby grants to You a perpetual,
+      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
+      (except as stated in this section) patent license to make, have made,
+      use, offer to sell, sell, import, and otherwise transfer the Work,
+      where such license applies only to those patent claims licensable
+      by such Contributor that are necessarily infringed by their
+      Contribution(s) alone or by combination of their Contribution(s)
+      with the Work to which such Contribution(s) was submitted. If You
+      institute patent litigation against any entity (including a
+      cross-claim or counterclaim in a lawsuit) alleging that the Work
+      or a Contribution incorporated within the Work constitutes direct
+      or contributory patent infringement, then any patent licenses
+      granted to You under this License for that Work shall terminate
+      as of the date such litigation is filed.
+
+   4. Redistribution. You may reproduce and distribute copies of the
+      Work or Derivative Works thereof in any medium, with or without
+      modifications, and in Source or Object form, provided that You
+      meet the following conditions:
+
+      (a) You must give any other recipients of the Work or
+          Derivative Works a copy of this License; and
+
+      (b) You must cause any modified files to carry prominent notices
+          stating that You changed the files; and
+
+      (c) You must retain, in the Source form of any Derivative Works
+          that You distribute, all copyright, patent, trademark, and
+          attribution notices from the Source form of the Work,
+          excluding those notices that do not pertain to any part of
+          the Derivative Works; and
+
+      (d) If the Work includes a "NOTICE" text file as part of its
+          distribution, then any Derivative Works that You distribute must
+          include a readable copy of the attribution notices contained
+          within such NOTICE file, excluding those notices that do not
+          pertain to any part of the Derivative Works, in at least one
+          of the following places: within a NOTICE text file distributed
+          as part of the Derivative Works; within the Source form or
+          documentation, if provided along with the Derivative Works; or,
+          within a display generated by the Derivative Works, if and
+          wherever such third-party notices normally appear. The contents
+          of the NOTICE file are for informational purposes only and
+          do not modify the License. You may add Your own attribution
+          notices within Derivative Works that You distribute, alongside
+          or as an addendum to the NOTICE text from the Work, provided
+          that such additional attribution notices cannot be construed
+          as modifying the License.
+
+      You may add Your own copyright statement to Your modifications and
+      may provide additional or different license terms and conditions
+      for use, reproduction, or distribution of Your modifications, or
+      for any such Derivative Works as a whole, provided Your use,
+      reproduction, and distribution of the Work otherwise complies with
+      the conditions stated in this License.
+
+   5. Submission of Contributions. Unless You explicitly state otherwise,
+      any Contribution intentionally submitted for inclusion in the Work
+      by You to the Licensor shall be under the terms and conditions of
+      this License, without any additional terms or conditions.
+      Notwithstanding the above, nothing herein shall supersede or modify
+      the terms of any separate license agreement you may have executed
+      with Licensor regarding such Contributions.
+
+   6. Trademarks. This License does not grant permission to use the trade
+      names, trademarks, service marks, or product names of the Licensor,
+      except as required for reasonable and customary use in describing the
+      origin of the Work and reproducing the content of the NOTICE file.
+
+   7. Disclaimer of Warranty. Unless required by applicable law or
+      agreed to in writing, Licensor provides the Work (and each
+      Contributor provides its Contributions) on an "AS IS" BASIS,
+      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
+      implied, including, without limitation, any warranties or conditions
+      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
+      PARTICULAR PURPOSE. You are solely responsible for determining the
+      appropriateness of using or redistributing the Work and assume any
+      risks associated with Your exercise of permissions under this License.
+
+   8. Limitation of Liability. In no event and under no legal theory,
+      whether in tort (including negligence), contract, or otherwise,
+      unless required by applicable law (such as deliberate and grossly
+      negligent acts) or agreed to in writing, shall any Contributor be
+      liable to You for damages, including any direct, indirect, special,
+      incidental, or consequential damages of any character arising as a
+      result of this License or out of the use or inability to use the
+      Work (including but not limited to damages for loss of goodwill,
+      work stoppage, computer failure or malfunction, or any and all
+      other commercial damages or losses), even if such Contributor
+      has been advised of the possibility of such damages.
+
+   9. Accepting Warranty or Additional Liability. While redistributing
+      the Work or Derivative Works thereof, You may choose to offer,
+      and charge a fee for, acceptance of support, warranty, indemnity,
+      or other liability obligations and/or rights consistent with this
+      License. However, in accepting such obligations, You may act only
+      on Your own behalf and on Your sole responsibility, not on behalf
+      of any other Contributor, and only if You agree to indemnify,
+      defend, and hold each Contributor harmless for any liability
+      incurred by, or claims asserted against, such Contributor by reason
+      of your accepting any such warranty or additional liability.
+
+   END OF TERMS AND CONDITIONS
+
+   APPENDIX: How to apply the Apache License to your work.
+
+      To apply the Apache License to your work, attach the following
+      boilerplate notice, with the fields enclosed by brackets "[]"
+      replaced with your own identifying information. (Don't include
+      the brackets!)  The text should be enclosed in the appropriate
+      comment syntax for the file format. We also recommend that a
+      file or class name and description of purpose be included on the
+      same "printed page" as the copyright notice for easier
+      identification within third-party archives.
+
+   Copyright [yyyy] [name of copyright owner]
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+   you may not use this file except in compliance with the License.
+   You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+   Unless required by applicable law or agreed to in writing, software
+   distributed under the License is distributed on an "AS IS" BASIS,
+   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+   See the License for the specific language governing permissions and
+   limitations under the License.
+
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
new file mode 100644
index 0000000..319feb4
--- /dev/null
+++ b/PREUPLOAD.cfg
@@ -0,0 +1,10 @@
+[Builtin Hooks]
+clang_format = true
+commit_msg_bug_field = true
+commit_msg_changeid_field = true
+rustfmt = true
+
+[Builtin Hooks Options]
+clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
+rustfmt = --config-path=rustfmt.toml
+
diff --git a/authmgr-be/.clang-format b/authmgr-be/.clang-format
new file mode 100644
index 0000000..5c86e69
--- /dev/null
+++ b/authmgr-be/.clang-format
@@ -0,0 +1,25 @@
+# Trusty Style
+# This is a Google-derived style with 4-space indent and a few quirks for
+# systems code.
+BasedOnStyle: Chromium
+
+# 4-space indent, no tabs.
+IndentWidth: 4
+UseTab: Never
+TabWidth: 4
+
+# Double indent arguments when none of them are on the first line.
+ContinuationIndentWidth: 8
+ConstructorInitializerIndentWidth: 8
+
+# Don't indent public/private/protected.
+# It's a little more common to do a half indent, but folks didn't like that.
+AccessModifierOffset: -4
+
+# Don't indent case labels.
+IndentCaseLabels: false
+
+# Don't break strings to make it easier to grep for error messages.
+# Note: this can result in lines that exceed the column limit.
+BreakStringLiterals: false
+
diff --git a/authmgr-be/LICENSE b/authmgr-be/LICENSE
new file mode 100644
index 0000000..57bc88a
--- /dev/null
+++ b/authmgr-be/LICENSE
@@ -0,0 +1,202 @@
+                                 Apache License
+                           Version 2.0, January 2004
+                        http://www.apache.org/licenses/
+
+   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
+
+   1. Definitions.
+
+      "License" shall mean the terms and conditions for use, reproduction,
+      and distribution as defined by Sections 1 through 9 of this document.
+
+      "Licensor" shall mean the copyright owner or entity authorized by
+      the copyright owner that is granting the License.
+
+      "Legal Entity" shall mean the union of the acting entity and all
+      other entities that control, are controlled by, or are under common
+      control with that entity. For the purposes of this definition,
+      "control" means (i) the power, direct or indirect, to cause the
+      direction or management of such entity, whether by contract or
+      otherwise, or (ii) ownership of fifty percent (50%) or more of the
+      outstanding shares, or (iii) beneficial ownership of such entity.
+
+      "You" (or "Your") shall mean an individual or Legal Entity
+      exercising permissions granted by this License.
+
+      "Source" form shall mean the preferred form for making modifications,
+      including but not limited to software source code, documentation
+      source, and configuration files.
+
+      "Object" form shall mean any form resulting from mechanical
+      transformation or translation of a Source form, including but
+      not limited to compiled object code, generated documentation,
+      and conversions to other media types.
+
+      "Work" shall mean the work of authorship, whether in Source or
+      Object form, made available under the License, as indicated by a
+      copyright notice that is included in or attached to the work
+      (an example is provided in the Appendix below).
+
+      "Derivative Works" shall mean any work, whether in Source or Object
+      form, that is based on (or derived from) the Work and for which the
+      editorial revisions, annotations, elaborations, or other modifications
+      represent, as a whole, an original work of authorship. For the purposes
+      of this License, Derivative Works shall not include works that remain
+      separable from, or merely link (or bind by name) to the interfaces of,
+      the Work and Derivative Works thereof.
+
+      "Contribution" shall mean any work of authorship, including
+      the original version of the Work and any modifications or additions
+      to that Work or Derivative Works thereof, that is intentionally
+      submitted to Licensor for inclusion in the Work by the copyright owner
+      or by an individual or Legal Entity authorized to submit on behalf of
+      the copyright owner. For the purposes of this definition, "submitted"
+      means any form of electronic, verbal, or written communication sent
+      to the Licensor or its representatives, including but not limited to
+      communication on electronic mailing lists, source code control systems,
+      and issue tracking systems that are managed by, or on behalf of, the
+      Licensor for the purpose of discussing and improving the Work, but
+      excluding communication that is conspicuously marked or otherwise
+      designated in writing by the copyright owner as "Not a Contribution."
+
+      "Contributor" shall mean Licensor and any individual or Legal Entity
+      on behalf of whom a Contribution has been received by Licensor and
+      subsequently incorporated within the Work.
+
+   2. Grant of Copyright License. Subject to the terms and conditions of
+      this License, each Contributor hereby grants to You a perpetual,
+      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
+      copyright license to reproduce, prepare Derivative Works of,
+      publicly display, publicly perform, sublicense, and distribute the
+      Work and such Derivative Works in Source or Object form.
+
+   3. Grant of Patent License. Subject to the terms and conditions of
+      this License, each Contributor hereby grants to You a perpetual,
+      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
+      (except as stated in this section) patent license to make, have made,
+      use, offer to sell, sell, import, and otherwise transfer the Work,
+      where such license applies only to those patent claims licensable
+      by such Contributor that are necessarily infringed by their
+      Contribution(s) alone or by combination of their Contribution(s)
+      with the Work to which such Contribution(s) was submitted. If You
+      institute patent litigation against any entity (including a
+      cross-claim or counterclaim in a lawsuit) alleging that the Work
+      or a Contribution incorporated within the Work constitutes direct
+      or contributory patent infringement, then any patent licenses
+      granted to You under this License for that Work shall terminate
+      as of the date such litigation is filed.
+
+   4. Redistribution. You may reproduce and distribute copies of the
+      Work or Derivative Works thereof in any medium, with or without
+      modifications, and in Source or Object form, provided that You
+      meet the following conditions:
+
+      (a) You must give any other recipients of the Work or
+          Derivative Works a copy of this License; and
+
+      (b) You must cause any modified files to carry prominent notices
+          stating that You changed the files; and
+
+      (c) You must retain, in the Source form of any Derivative Works
+          that You distribute, all copyright, patent, trademark, and
+          attribution notices from the Source form of the Work,
+          excluding those notices that do not pertain to any part of
+          the Derivative Works; and
+
+      (d) If the Work includes a "NOTICE" text file as part of its
+          distribution, then any Derivative Works that You distribute must
+          include a readable copy of the attribution notices contained
+          within such NOTICE file, excluding those notices that do not
+          pertain to any part of the Derivative Works, in at least one
+          of the following places: within a NOTICE text file distributed
+          as part of the Derivative Works; within the Source form or
+          documentation, if provided along with the Derivative Works; or,
+          within a display generated by the Derivative Works, if and
+          wherever such third-party notices normally appear. The contents
+          of the NOTICE file are for informational purposes only and
+          do not modify the License. You may add Your own attribution
+          notices within Derivative Works that You distribute, alongside
+          or as an addendum to the NOTICE text from the Work, provided
+          that such additional attribution notices cannot be construed
+          as modifying the License.
+
+      You may add Your own copyright statement to Your modifications and
+      may provide additional or different license terms and conditions
+      for use, reproduction, or distribution of Your modifications, or
+      for any such Derivative Works as a whole, provided Your use,
+      reproduction, and distribution of the Work otherwise complies with
+      the conditions stated in this License.
+
+   5. Submission of Contributions. Unless You explicitly state otherwise,
+      any Contribution intentionally submitted for inclusion in the Work
+      by You to the Licensor shall be under the terms and conditions of
+      this License, without any additional terms or conditions.
+      Notwithstanding the above, nothing herein shall supersede or modify
+      the terms of any separate license agreement you may have executed
+      with Licensor regarding such Contributions.
+
+   6. Trademarks. This License does not grant permission to use the trade
+      names, trademarks, service marks, or product names of the Licensor,
+      except as required for reasonable and customary use in describing the
+      origin of the Work and reproducing the content of the NOTICE file.
+
+   7. Disclaimer of Warranty. Unless required by applicable law or
+      agreed to in writing, Licensor provides the Work (and each
+      Contributor provides its Contributions) on an "AS IS" BASIS,
+      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
+      implied, including, without limitation, any warranties or conditions
+      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
+      PARTICULAR PURPOSE. You are solely responsible for determining the
+      appropriateness of using or redistributing the Work and assume any
+      risks associated with Your exercise of permissions under this License.
+
+   8. Limitation of Liability. In no event and under no legal theory,
+      whether in tort (including negligence), contract, or otherwise,
+      unless required by applicable law (such as deliberate and grossly
+      negligent acts) or agreed to in writing, shall any Contributor be
+      liable to You for damages, including any direct, indirect, special,
+      incidental, or consequential damages of any character arising as a
+      result of this License or out of the use or inability to use the
+      Work (including but not limited to damages for loss of goodwill,
+      work stoppage, computer failure or malfunction, or any and all
+      other commercial damages or losses), even if such Contributor
+      has been advised of the possibility of such damages.
+
+   9. Accepting Warranty or Additional Liability. While redistributing
+      the Work or Derivative Works thereof, You may choose to offer,
+      and charge a fee for, acceptance of support, warranty, indemnity,
+      or other liability obligations and/or rights consistent with this
+      License. However, in accepting such obligations, You may act only
+      on Your own behalf and on Your sole responsibility, not on behalf
+      of any other Contributor, and only if You agree to indemnify,
+      defend, and hold each Contributor harmless for any liability
+      incurred by, or claims asserted against, such Contributor by reason
+      of your accepting any such warranty or additional liability.
+
+   END OF TERMS AND CONDITIONS
+
+   APPENDIX: How to apply the Apache License to your work.
+
+      To apply the Apache License to your work, attach the following
+      boilerplate notice, with the fields enclosed by brackets "[]"
+      replaced with your own identifying information. (Don't include
+      the brackets!)  The text should be enclosed in the appropriate
+      comment syntax for the file format. We also recommend that a
+      file or class name and description of purpose be included on the
+      same "printed page" as the copyright notice for easier
+      identification within third-party archives.
+
+   Copyright [yyyy] [name of copyright owner]
+
+   Licensed under the Apache License, Version 2.0 (the "License");
+   you may not use this file except in compliance with the License.
+   You may obtain a copy of the License at
+
+       http://www.apache.org/licenses/LICENSE-2.0
+
+   Unless required by applicable law or agreed to in writing, software
+   distributed under the License is distributed on an "AS IS" BASIS,
+   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+   See the License for the specific language governing permissions and
+   limitations under the License.
+
diff --git a/authmgr-be/PREUPLOAD.cfg b/authmgr-be/PREUPLOAD.cfg
new file mode 100644
index 0000000..319feb4
--- /dev/null
+++ b/authmgr-be/PREUPLOAD.cfg
@@ -0,0 +1,10 @@
+[Builtin Hooks]
+clang_format = true
+commit_msg_bug_field = true
+commit_msg_changeid_field = true
+rustfmt = true
+
+[Builtin Hooks Options]
+clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
+rustfmt = --config-path=rustfmt.toml
+
diff --git a/authmgr-be/app/main.rs b/authmgr-be/app/main.rs
new file mode 100644
index 0000000..a1560a0
--- /dev/null
+++ b/authmgr-be/app/main.rs
@@ -0,0 +1,36 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+//! Entrypoint to the AuthMgr BE Trusted App
+
+use authmgr_be_lib::server::main_loop;
+use log::debug;
+
+fn log_formatter(record: &log::Record) -> String {
+    // line number should be present, so keeping it simple by just returning a 0.
+    let line = record.line().unwrap_or(0);
+    let file = record.file().unwrap_or("unknown file");
+    format!("{}: {}:{} {}\n", record.level(), file, line, record.args())
+}
+
+fn main() {
+    let config = trusty_log::TrustyLoggerConfig::default()
+        .with_min_level(log::Level::Info)
+        .format(&log_formatter);
+    trusty_log::init_with_config(config);
+    debug!("starting AuthMgr BE...");
+    main_loop().expect("AuthMgr BE service quits unexpectedly.");
+}
diff --git a/authmgr-be/app/manifest.json b/authmgr-be/app/manifest.json
new file mode 100644
index 0000000..4efb0b4
--- /dev/null
+++ b/authmgr-be/app/manifest.json
@@ -0,0 +1,6 @@
+{
+    "app_name": "authmgr_be_app",
+    "uuid": "f4768956-62d9-4904-9512-86df360d8d50",
+    "min_heap": 114688,
+    "min_stack": 32768
+}
\ No newline at end of file
diff --git a/authmgr-be/app/rules.mk b/authmgr-be/app/rules.mk
new file mode 100644
index 0000000..0196676
--- /dev/null
+++ b/authmgr-be/app/rules.mk
@@ -0,0 +1,36 @@
+# Copyright (C) 2025 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/main.rs \
+
+MODULE_CRATE_NAME := authmgr_be_app
+
+MODULE_LIBRARY_DEPS += \
+	trusty/user/app/authmgr/authmgr-be/lib \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/trusty-sys \
+	trusty/user/base/lib/trusty-std \
+	$(call FIND_CRATE,log) \
+	trusty/user/base/lib/trusty-log \
+
+MODULE_RUST_USE_CLIPPY := true
+
+include make/trusted_app.mk
\ No newline at end of file
diff --git a/authmgr-be/lib/manifest.json b/authmgr-be/lib/manifest.json
new file mode 100644
index 0000000..42d1e01
--- /dev/null
+++ b/authmgr-be/lib/manifest.json
@@ -0,0 +1,6 @@
+{
+    "app_name": "authmgr_be_lib",
+    "uuid": "1c966e25-7729-4122-8fb6-ccd2b612430c",
+    "min_heap": 114688,
+    "min_stack": 32768
+}
\ No newline at end of file
diff --git a/authmgr-be/lib/rules.mk b/authmgr-be/lib/rules.mk
new file mode 100644
index 0000000..2aed10f
--- /dev/null
+++ b/authmgr-be/lib/rules.mk
@@ -0,0 +1,55 @@
+# Copyright (C) 2025 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/src/lib.rs \
+
+MODULE_CRATE_NAME := authmgr_be_lib
+
+MODULE_LIBRARY_DEPS += \
+	frameworks/native/libs/binder/trusty/rust \
+	frameworks/native/libs/binder/trusty/rust/binder_rpc_server \
+	frameworks/native/libs/binder/trusty/rust/rpcbinder \
+	trusty/user/base/interface/authmgr/rust \
+	trusty/user/app/sample/rust-hello-world-trusted-hal/aidl \
+	trusty/user/base/interface/authmgr-handover/aidl \
+	trusty/user/base/lib/authgraph-rust/boringssl \
+	trusty/user/base/lib/authgraph-rust/core \
+	trusty/user/base/lib/authgraph-rust/tests \
+	trusty/user/base/lib/authmgr-be-rust \
+	trusty/user/base/lib/authmgr-be-impl-rust \
+	trusty/user/base/lib/authmgr-common-rust \
+	trusty/user/base/lib/authmgr-common-util-rust \
+	trusty/user/base/lib/secretkeeper/dice_policy \
+	trusty/user/base/lib/secretkeeper/dice-policy-builder \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/trusty-log \
+	trusty/user/base/lib/trusty-std \
+	trusty/user/base/lib/trusty-sys \
+	$(call FIND_CRATE,coset) \
+	$(call FIND_CRATE,log) \
+	$(call FIND_CRATE,vm-memory) \
+
+MODULE_RUST_TESTS := true
+
+MODULE_RUST_USE_CLIPPY := true
+
+include make/library.mk
\ No newline at end of file
diff --git a/authmgr-be/lib/src/authorization_service.rs b/authmgr-be/lib/src/authorization_service.rs
new file mode 100644
index 0000000..70c1021
--- /dev/null
+++ b/authmgr-be/lib/src/authorization_service.rs
@@ -0,0 +1,343 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+//! The implementation of the `IAuthMgrAuthorization` AIDL interface.
+//#![allow(dead_code)]
+use android_hardware_security_see_authmgr::aidl::android::hardware::security::see::authmgr::{
+    DiceLeafArtifacts::DiceLeafArtifacts,
+    DicePolicy::DicePolicy,
+    ExplicitKeyDiceCertChain::ExplicitKeyDiceCertChain,
+    IAuthMgrAuthorization::{BnAuthMgrAuthorization, IAuthMgrAuthorization},
+    SignedConnectionRequest::SignedConnectionRequest,
+};
+use android_hardware_security_see_authmgr::binder;
+use authgraph_core::key::{CertChain, InstanceIdentifier};
+use authmgr_be::{
+    am_err,
+    authorization::AuthMgrBE,
+    data_structures::{AuthenticatedConnectionState, MemoryLimits},
+    error::{Error, ErrorCode},
+    traits::{Device, RawConnection, RpcConnection},
+};
+use authmgr_be_impl::mock_storage::MockPersistentStorage;
+use authmgr_common::signed_connection_request::{
+    TransportID, TEMP_AUTHMGR_BE_TRANSPORT_ID, TEMP_AUTHMGR_FE_TRANSPORT_ID,
+};
+use authmgr_handover_aidl::aidl::android::trusty::handover::ITrustedServicesHandover::ITrustedServicesHandover;
+use binder::ParcelFileDescriptor;
+use binder::SpIBinder;
+use binder::Strong;
+use log::error;
+use rpcbinder::{FileDescriptorTransportMode, RpcSession};
+use std::ffi::CStr;
+use std::os::fd::FromRawFd;
+use std::os::fd::OwnedFd;
+use std::sync::Arc;
+use std::sync::Mutex;
+use tipc::Handle;
+
+// TODO: b/400118241. Construct the handover service's port from the given service name.
+// For now, hardcode the port for the handover service of the HelloWorld TA.
+const HANDOVER_SERVICE_PORT: &CStr = c"com.android.trusty.rust.handover.hello.service.V1";
+
+/// Represents a per-session RPC binder object which implements the `IAuthMgrAuthorization`
+/// interface. This encapsulates the connection information as well as the global state of the
+/// AuthMgr Authorization service.
+/// `global_state` is shared across the all the binder RPC root objects of
+///  `AuthMgrAuthorizationRPCService` and the AuthMgr main service of this TA.
+/// `connection_information` is shared across multiple binder RPC sessions of the samme connection.
+/// Therefore, we are not locking both mutexes together. In the usage of both mutexes (which is
+/// in the below implementation of `AuthMgrAuthorizationRPCService`, the locks on them should be
+/// grabbed in the same order as they are ordered in the struct below.
+pub struct AuthMgrAuthorizationRPCService {
+    global_state: Arc<Mutex<AuthMgrGlobalState>>,
+    connection_information: Arc<Mutex<RpcConnectionInformation>>,
+}
+
+impl binder::Interface for AuthMgrAuthorizationRPCService {}
+
+impl AuthMgrAuthorizationRPCService {
+    // TODO: b/392905377. Expect transport id (i.e. VM-ID) to be passed into this method
+    pub fn new_authorization_session(
+        global_state: Arc<Mutex<AuthMgrGlobalState>>,
+    ) -> Option<SpIBinder> {
+        let connection_information =
+            RpcConnectionInformation::new(TEMP_AUTHMGR_FE_TRANSPORT_ID, None);
+        let authmgr_authorization = AuthMgrAuthorizationRPCService {
+            global_state,
+            connection_information: Arc::new(Mutex::new(connection_information)),
+        };
+        Some(
+            BnAuthMgrAuthorization::new_binder(
+                authmgr_authorization,
+                binder::BinderFeatures::default(),
+            )
+            .as_binder(),
+        )
+    }
+}
+
+impl Drop for AuthMgrAuthorizationRPCService {
+    fn drop(&mut self) {
+        let mut global_state = self.global_state.lock().unwrap();
+        let mut connection_info = self.connection_information.lock().unwrap();
+        let _ = global_state
+            .authmgr_core
+            .clear_cache_upon_main_connection_close(&mut *connection_info)
+            .map_err(|e| {
+                error!("Failed to clear cache: {:?}", e);
+                errcode_to_binder_err(e.0)
+            });
+    }
+}
+
+impl IAuthMgrAuthorization for AuthMgrAuthorizationRPCService {
+    fn initAuthentication(
+        &self,
+        dice_cert_chain: &ExplicitKeyDiceCertChain,
+        instance_id: Option<&[u8]>,
+    ) -> binder::Result<[u8; 32]> {
+        let mut global_state = self.global_state.lock().unwrap();
+        let connection_info = self.connection_information.lock().unwrap();
+        global_state
+            .authmgr_core
+            .init_authentication(&*connection_info, &dice_cert_chain.diceCertChain, instance_id)
+            .map_err(|e| {
+                error!("Failed step 1 of phase 1: {:?}", e);
+                errcode_to_binder_err(e.0)
+            })
+    }
+
+    fn completeAuthentication(
+        &self,
+        signed_response: &SignedConnectionRequest,
+        dice_policy: &DicePolicy,
+    ) -> binder::Result<()> {
+        let mut global_state = self.global_state.lock().unwrap();
+        let mut connection_info = self.connection_information.lock().unwrap();
+        global_state
+            .authmgr_core
+            .complete_authentication(
+                &mut *connection_info,
+                &signed_response.signedConnectionRequest,
+                &dice_policy.dicePolicy,
+            )
+            .map_err(|e| {
+                error!("Failed step 2 of phase 1: {:?}", e);
+                errcode_to_binder_err(e.0)
+            })
+    }
+
+    fn authorizeAndConnectClientToTrustedService(
+        &self,
+        client_id: &[u8],
+        service_name: &str,
+        token: &[u8; 32],
+        client_dice_artifacts: &DiceLeafArtifacts,
+    ) -> binder::Result<()> {
+        let mut global_state = self.global_state.lock().unwrap();
+        let mut connection_info = self.connection_information.lock().unwrap();
+        global_state
+            .authmgr_core
+            .authorize_and_connect_client_to_trusted_service(
+                &mut *connection_info,
+                client_id,
+                service_name,
+                *token,
+                &client_dice_artifacts.diceLeaf.diceChainEntry,
+                &client_dice_artifacts.diceLeafPolicy.dicePolicy,
+            )
+            .map_err(|e| {
+                error!("Failed step 2 of phase 1: {:?}", e);
+                errcode_to_binder_err(e.0)
+            })
+    }
+}
+
+/// Convert an AuthMgr ErrorCode into a binder error.
+pub fn errcode_to_binder_err(err: ErrorCode) -> binder::Status {
+    // Translate the internal errors for `Unimplemented` and `InternalError` to their counterparts
+    // in binder errors
+    match err {
+        ErrorCode::Unimplemented => {
+            binder::Status::new_exception(binder::ExceptionCode::UNSUPPORTED_OPERATION, None)
+        }
+        ErrorCode::InternalError => {
+            binder::Status::new_exception(binder::ExceptionCode::SERVICE_SPECIFIC, None)
+        }
+        _ => binder::Status::new_service_specific_error(err as i32, None),
+    }
+}
+
+/// The global state that needs to be maintained by the AuthMgr service.
+pub struct AuthMgrGlobalState {
+    pub authmgr_core: AuthMgrBE,
+}
+
+impl AuthMgrGlobalState {
+    pub fn new() -> Result<Self, Error> {
+        // TODO: Here we use the default constants in the reference implementation. These should be
+        // adjusted appropriately.
+        let memory_limits = MemoryLimits::default();
+
+        let authmgr_core = AuthMgrBE::new(
+            authmgr_be_impl::crypto_trait_impls(),
+            Box::new(DeviceInformation::new()?),
+            Box::new(MockPersistentStorage::new()),
+            memory_limits,
+        )?;
+
+        Ok(AuthMgrGlobalState { authmgr_core })
+    }
+}
+
+pub struct RpcConnectionInformation {
+    transport_id: TransportID,
+    connection_state: Option<AuthenticatedConnectionState>,
+}
+
+impl RpcConnectionInformation {
+    /// Constructor
+    pub fn new(
+        transport_id: TransportID,
+        connection_state: Option<AuthenticatedConnectionState>,
+    ) -> Self {
+        RpcConnectionInformation { transport_id, connection_state }
+    }
+}
+
+impl RpcConnection for RpcConnectionInformation {
+    fn get_peer_transport_id(&self) -> Result<TransportID, Error> {
+        Ok(self.transport_id)
+    }
+
+    fn store_authenticated_state(
+        &mut self,
+        connection_state: AuthenticatedConnectionState,
+    ) -> Result<(), Error> {
+        self.connection_state = Some(connection_state);
+        Ok(())
+    }
+
+    fn get_authenticated_state(&self) -> Result<Option<&AuthenticatedConnectionState>, Error> {
+        Ok(self.connection_state.as_ref())
+    }
+
+    fn get_mutable_authenticated_state(
+        &mut self,
+    ) -> Result<Option<&mut AuthenticatedConnectionState>, Error> {
+        Ok((self.connection_state).as_mut())
+    }
+
+    fn remove_authenticated_state(&mut self) -> Result<(), Error> {
+        self.connection_state = None;
+        Ok(())
+    }
+}
+
+pub struct RawConnectionInformation {
+    // Raw file descriptor
+    handle: Handle,
+    peer_transport_id: TransportID,
+}
+
+impl RawConnectionInformation {
+    /// Constructor
+    pub fn new(handle: Handle, peer_transport_id: TransportID) -> Self {
+        RawConnectionInformation { handle, peer_transport_id }
+    }
+}
+
+impl RawConnection for RawConnectionInformation {
+    fn get_peer_transport_id(&self) -> Result<TransportID, Error> {
+        Ok(self.peer_transport_id)
+    }
+
+    fn into_raw_fd(self: Box<Self>) -> i32 {
+        let fd = self.handle.as_raw_fd();
+        // Prevent the destructor of the handle from being called
+        core::mem::forget(self.handle);
+        fd
+    }
+}
+
+#[derive(Default)]
+struct DeviceInformation;
+
+impl DeviceInformation {
+    fn new() -> Result<Self, Error> {
+        Ok(Self)
+    }
+}
+
+impl Device for DeviceInformation {
+    fn get_self_transport_id(&self) -> Result<TransportID, Error> {
+        // TODO: b/392905377. This is temporary, until we can integrate the transport ID from FFA.
+        Ok(TEMP_AUTHMGR_BE_TRANSPORT_ID)
+    }
+
+    fn is_persistent_instance(&self, _instance_id: &InstanceIdentifier) -> Result<bool, Error> {
+        // TODO: 399707150
+        // In the scope of Android 16, we support only persistent instances created in the factory.
+        // Therefore, we can simply return true here.
+        Ok(true)
+    }
+
+    fn handover_client_connection(
+        &self,
+        _service_name: &str,
+        client_seq_number: i32,
+        client_conn_handle: Box<dyn RawConnection>,
+        _is_persistent: bool,
+    ) -> Result<(), Error> {
+        // TODO: b/400118241.
+        // Currently we have the port of the hand over service hardcoded to that of the example TA.
+        // Instead the AuthMgr should construct the appropriate hand over service port based on the
+        // input `service_name`.
+        // TODO: We may be able to retrieve an already setup RPC session to a trusted service from
+        // the cache
+        let rpc_session = RpcSession::new();
+        rpc_session.set_file_descriptor_transport_mode(FileDescriptorTransportMode::Trusty);
+        let rpc_session: Strong<dyn ITrustedServicesHandover> =
+            rpc_session.setup_trusty_client(HANDOVER_SERVICE_PORT).map_err(|_e| {
+                am_err!(
+                    ConnectionHandoverFailed,
+                    "Failed to setup connection to the handover service."
+                )
+            })?;
+
+        let raw_fd: i32 = client_conn_handle.into_raw_fd();
+        // SAFETY: As specified in the definition of the `RawConnection` trait (in system/see/
+        // authmgr/authmgr-be/src/traits.rs), `RawConnection` trait object should have the ownership
+        // of the underlying file descriptor. Therefore, the `raw_fd` passed into the `from_raw_fd`
+        // is an owned file descriptor.
+        let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
+        let fd = ParcelFileDescriptor::new(owned_fd);
+        rpc_session.handoverConnection(&fd, client_seq_number).map_err(|_e| {
+            am_err!(ConnectionHandoverFailed, "Failed to handover the connection.")
+        })?;
+        Ok(())
+    }
+
+    fn is_persistent_instance_creation_allowed(
+        &self,
+        _instance_id: &InstanceIdentifier,
+        _dice_chain: &CertChain,
+    ) -> Result<bool, Error> {
+        // TODO: b/400116782. Check the system state and return true if the device is in factory
+        Ok(true)
+    }
+}
diff --git a/authmgr-be/lib/src/lib.rs b/authmgr-be/lib/src/lib.rs
new file mode 100644
index 0000000..6125d87
--- /dev/null
+++ b/authmgr-be/lib/src/lib.rs
@@ -0,0 +1,22 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+//! Entry point to the AuthMgr BE TA library
+
+mod authorization_service;
+pub mod server;
+#[cfg(test)]
+mod tests;
diff --git a/authmgr-be/lib/src/server.rs b/authmgr-be/lib/src/server.rs
new file mode 100644
index 0000000..6aa8879
--- /dev/null
+++ b/authmgr-be/lib/src/server.rs
@@ -0,0 +1,327 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+//! AuthMgr BE server
+use crate::authorization_service::{
+    AuthMgrAuthorizationRPCService, AuthMgrGlobalState, RawConnectionInformation,
+};
+use authmgr_common::{
+    signed_connection_request::TEMP_AUTHMGR_FE_TRANSPORT_ID, CMD_RAW, CMD_RPC, TOKEN_LENGTH,
+};
+use log::{debug, error};
+use rpcbinder::{RpcServer, RpcServerConnection};
+use std::ffi::CStr;
+use std::sync::Mutex;
+use std::sync::{Arc, Weak};
+use tipc::raw::{EventLoop, HandleSetWrapper};
+use tipc::{
+    ConnectResult, Deserialize, Handle, MessageResult, PortCfg, Serialize, Serializer, TipcError,
+    UnbufferedService, Uuid,
+};
+use trusty_std::alloc::TryAllocFrom;
+
+/// Port for the AuthMgr main service
+pub(crate) const AUTHMGR_SERVICE_PORT: &CStr = c"com.android.trusty.rust.authmgr.V1";
+
+/// Maximum message size.
+/// TODO: determine the size
+const MAX_MSG_SIZE: usize = 4000;
+
+/// Represents the main AuthMgr service encapsulating the global state which is also shared with the
+/// `AuthMgrAuthorizationRPCService`.
+pub struct AuthMgrService {
+    global_state: Arc<Mutex<AuthMgrGlobalState>>,
+    rpc_service: Arc<RpcServer>,
+    handle_set: Weak<HandleSetWrapper<AuthMgrServices>>,
+}
+
+impl AuthMgrService {
+    fn new(
+        global_state: Arc<Mutex<AuthMgrGlobalState>>,
+        rpc_service: Arc<RpcServer>,
+        handle_set: Weak<HandleSetWrapper<AuthMgrServices>>,
+    ) -> Self {
+        AuthMgrService { global_state, rpc_service, handle_set }
+    }
+}
+
+// SAFETY: Out of the three fields of `AuthMgrService`:
+// `AuthMgrGlobalState` and `HandleSetWrapper` are heap allocated in the main_loop() of this TA and
+// therefore, are not bound to any particular thread.
+// `RpcServer` implements (unsafe) `Send`.
+unsafe impl Send for AuthMgrService {}
+
+pub struct AuthMgrConnection {
+    uuid: Uuid,
+    // In on_connect, we do not know whether this is a connection request for the RPC binder service
+    // or a raw connection request. Until the first message arrives, we mark the connection as
+    // pending_to_be_routed = true
+    pending_to_be_routed: Arc<Mutex<bool>>,
+}
+
+pub struct AuthMgrMessage(pub Vec<u8>);
+
+impl Deserialize for AuthMgrMessage {
+    type Error = TipcError;
+    const MAX_SERIALIZED_SIZE: usize = MAX_MSG_SIZE;
+
+    fn deserialize(bytes: &[u8], _handles: &mut [Option<Handle>]) -> Result<Self, TipcError> {
+        Ok(AuthMgrMessage(Vec::try_alloc_from(bytes)?))
+    }
+}
+
+impl<'s> Serialize<'s> for AuthMgrMessage {
+    fn serialize<'a: 's, S: Serializer<'s>>(
+        &'a self,
+        serializer: &mut S,
+    ) -> Result<S::Ok, S::Error> {
+        serializer.serialize_bytes(self.0.as_slice())
+    }
+}
+
+impl UnbufferedService for AuthMgrService {
+    type Connection = AuthMgrConnection;
+
+    fn on_connect(
+        &self,
+        _port: &PortCfg,
+        handle: &Handle,
+        peer: &Uuid,
+    ) -> Result<ConnectResult<Self::Connection>, TipcError> {
+        debug!("Accepted AthMgr BE connection from uuid: {:?}, handle: {:?}", peer, handle);
+        Ok(ConnectResult::Accept(AuthMgrConnection {
+            uuid: peer.clone(),
+            pending_to_be_routed: Arc::new(Mutex::new(true)),
+        }))
+    }
+
+    fn on_message(
+        &self,
+        connection: &Self::Connection,
+        handle: &Handle,
+        _buffer: &mut [u8],
+    ) -> Result<MessageResult, TipcError> {
+        let mut connection_pending_to_be_routed = connection.pending_to_be_routed.lock().unwrap();
+        debug!(
+            "AuthMgr BE received a message from uuid: {:?} for a pending_to_be_routed: {:?}, handle: {:?}.",
+            connection.uuid,
+            connection_pending_to_be_routed,
+            handle
+        );
+        if *connection_pending_to_be_routed {
+            let mut temp_buffer = [0u8; MAX_MSG_SIZE];
+            let msg: AuthMgrMessage = handle.recv(&mut temp_buffer)?;
+            if msg.0.is_empty() {
+                error!("Expected a command byte, got an empty payload.");
+                return Err(TipcError::InvalidData);
+            }
+            match msg.0[0] {
+                CMD_RAW => {
+                    debug!("It's a request for a new raw connection.");
+                    if msg.0.len() != TOKEN_LENGTH + 1 {
+                        error!(
+                            "Expected a token of length: {:?}, got a payload of size: {:?}.",
+                            TOKEN_LENGTH,
+                            msg.0.len()
+                        );
+                        return Err(TipcError::InvalidData);
+                    }
+                    let token: [u8; TOKEN_LENGTH] =
+                        (msg.0[1..TOKEN_LENGTH + 1]).try_into().map_err(|e| {
+                            error!("Failed to read the token: {:?}", e);
+                            TipcError::InvalidData
+                        })?;
+                    let client_connection = RawConnectionInformation::new(
+                        handle.try_clone()?,
+                        // TODO: b/392905377. This is temporary, until the VM-ID is available.
+                        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+                    );
+                    let mut global_state = self.global_state.lock().unwrap();
+                    global_state
+                        .authmgr_core
+                        .init_connection_for_client(Box::new(client_connection), token)
+                        .map_err(|e| {
+                            error!("Failed to call init_connection_for_client: {:?}", e);
+                            TipcError::UnknownError
+                        })?;
+                    *connection_pending_to_be_routed = false;
+                    // Close the handle registered in the handle set
+                    Ok(MessageResult::CloseConnection)
+                }
+                CMD_RPC => {
+                    debug!("It's a request for a RPC binder connection.");
+                    let authmgr_service_port_cfg = PortCfg::new_raw(AUTHMGR_SERVICE_PORT.into())
+                        .allow_ta_connect()
+                        .allow_ns_connect();
+                    let rpc_connection = match self.rpc_service.on_connect(
+                        &authmgr_service_port_cfg,
+                        handle,
+                        &connection.uuid,
+                    )? {
+                        ConnectResult::Accept(conn) => conn,
+                        ConnectResult::CloseConnection => {
+                            return Ok(MessageResult::CloseConnection)
+                        }
+                    };
+                    debug!("AuthMgr RPC service.on_connect returned. Adding to the handle set.");
+                    self.handle_set.upgrade().ok_or(TipcError::InvalidData)?.add_connection(
+                        AuthMgrServicesConnection::RpcService(rpc_connection),
+                        handle.try_clone()?,
+                        Arc::new(AuthMgrServices::RpcService(Arc::clone(&self.rpc_service))),
+                    )?;
+                    *connection_pending_to_be_routed = false;
+                    // Close the handle registered in the handle set
+                    Ok(MessageResult::CloseConnection)
+                }
+                _ => {
+                    error!("Unknown command.");
+                    Err(TipcError::InvalidData)
+                }
+            }
+        } else {
+            error!(
+                "No messages are expected on the same connection
+                    after the initial command byte is sent."
+            );
+            Err(TipcError::InvalidData)
+        }
+    }
+    // TODO: implement on_disconnect
+}
+
+enum AuthMgrServices {
+    InitService(Arc<AuthMgrService>),
+    RpcService(Arc<RpcServer>),
+}
+
+enum AuthMgrServicesConnection {
+    InitService(AuthMgrConnection),
+    RpcService(RpcServerConnection),
+}
+
+impl From<AuthMgrConnection> for AuthMgrServicesConnection {
+    fn from(v: AuthMgrConnection) -> AuthMgrServicesConnection {
+        AuthMgrServicesConnection::InitService(v)
+    }
+}
+
+impl From<RpcServerConnection> for AuthMgrServicesConnection {
+    fn from(v: RpcServerConnection) -> AuthMgrServicesConnection {
+        AuthMgrServicesConnection::RpcService(v)
+    }
+}
+
+impl<'a> TryFrom<&'a AuthMgrServicesConnection> for &'a AuthMgrConnection {
+    type Error = TipcError;
+    fn try_from(v: &'a AuthMgrServicesConnection) -> Result<&'a AuthMgrConnection, Self::Error> {
+        match v {
+            AuthMgrServicesConnection::InitService(amgr_conn) => Ok(amgr_conn),
+            _ => Err(TipcError::InvalidData),
+        }
+    }
+}
+
+impl<'a> TryFrom<&'a AuthMgrServicesConnection> for &'a RpcServerConnection {
+    type Error = TipcError;
+    fn try_from(v: &'a AuthMgrServicesConnection) -> Result<&'a RpcServerConnection, Self::Error> {
+        match v {
+            AuthMgrServicesConnection::RpcService(rpc_conn) => Ok(rpc_conn),
+            _ => Err(TipcError::InvalidData),
+        }
+    }
+}
+
+impl UnbufferedService for AuthMgrServices {
+    type Connection = AuthMgrServicesConnection;
+
+    fn on_connect(
+        &self,
+        port: &PortCfg,
+        handle: &Handle,
+        peer: &Uuid,
+    ) -> Result<ConnectResult<Self::Connection>, TipcError> {
+        match self {
+            AuthMgrServices::InitService(authmgr_service) => {
+                match authmgr_service.on_connect(port, handle, peer) {
+                    Ok(conn_result) => match conn_result {
+                        ConnectResult::Accept(conn) => Ok(ConnectResult::Accept(conn.into())),
+                        ConnectResult::CloseConnection => Ok(ConnectResult::CloseConnection),
+                    },
+                    Err(e) => Err(e),
+                }
+            }
+
+            AuthMgrServices::RpcService(authmgr_rpc_service) => {
+                match authmgr_rpc_service.on_connect(port, handle, peer) {
+                    Ok(conn_result) => match conn_result {
+                        ConnectResult::Accept(conn) => Ok(ConnectResult::Accept(conn.into())),
+                        ConnectResult::CloseConnection => Ok(ConnectResult::CloseConnection),
+                    },
+                    Err(e) => Err(e),
+                }
+            }
+        }
+    }
+
+    fn on_message(
+        &self,
+        connection: &Self::Connection,
+        handle: &Handle,
+        buffer: &mut [u8],
+    ) -> Result<MessageResult, TipcError> {
+        match self {
+            AuthMgrServices::InitService(authmgr_service) => authmgr_service.on_message(
+                connection.try_into().map_err(|_| TipcError::InvalidData)?,
+                handle,
+                buffer,
+            ),
+            AuthMgrServices::RpcService(authmgr_rpc_service) => authmgr_rpc_service.on_message(
+                connection.try_into().map_err(|_| TipcError::InvalidData)?,
+                handle,
+                buffer,
+            ),
+        }
+    }
+}
+
+pub fn main_loop() -> Result<(), TipcError> {
+    let handle_set_wrapper = Arc::new(HandleSetWrapper::<AuthMgrServices>::new()?);
+    let global_state = AuthMgrGlobalState::new().map_err(|e| {
+        error!("Could not create AuthMgr global state due to: {:?}", e);
+        TipcError::UnknownError
+    })?;
+    let global_state = Arc::new(Mutex::new(global_state));
+    let gs_clone = Arc::clone(&global_state);
+    let authmgr_service_port_cfg =
+        PortCfg::new_raw(AUTHMGR_SERVICE_PORT.into()).allow_ta_connect().allow_ns_connect();
+
+    let cb_per_session = move |_uuid| {
+        AuthMgrAuthorizationRPCService::new_authorization_session(Arc::clone(&global_state))
+    };
+    let authmgr_authorization_rpc_server = RpcServer::new_per_session(cb_per_session);
+    let authmgr_service = AuthMgrService::new(
+        gs_clone,
+        Arc::new(authmgr_authorization_rpc_server),
+        Arc::downgrade(&handle_set_wrapper),
+    );
+
+    let _port_wrapper = handle_set_wrapper.add_port(
+        &authmgr_service_port_cfg,
+        Arc::new(AuthMgrServices::InitService(Arc::new(authmgr_service))),
+    )?;
+    let event_loop = EventLoop::new(handle_set_wrapper.clone());
+    event_loop.run()
+}
diff --git a/authmgr-be/lib/src/tests.rs b/authmgr-be/lib/src/tests.rs
new file mode 100644
index 0000000..b598832
--- /dev/null
+++ b/authmgr-be/lib/src/tests.rs
@@ -0,0 +1,1015 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+//! Unit tests for AuthMgr BE
+use crate::server::{AuthMgrMessage, AUTHMGR_SERVICE_PORT};
+use alloc::vec::Vec;
+use android_hardware_security_see_authmgr::aidl::android::hardware::security::see::authmgr::{
+    DiceChainEntry::DiceChainEntry as AidlDiceChainEntry, DiceLeafArtifacts::DiceLeafArtifacts,
+    DicePolicy::DicePolicy, Error::Error, ExplicitKeyDiceCertChain::ExplicitKeyDiceCertChain,
+    IAuthMgrAuthorization::IAuthMgrAuthorization, SignedConnectionRequest::SignedConnectionRequest,
+};
+use authgraph_boringssl::{BoringEcDsa, BoringRng};
+use authgraph_core::key::{CertChain, DiceChainEntry};
+use authgraph_core::traits::Rng;
+use authgraph_core_test::{
+    create_dice_cert_chain_for_guest_os, create_dice_leaf_cert, SAMPLE_INSTANCE_HASH,
+};
+use authmgr_common::{
+    signed_connection_request::{
+        ConnectionRequest, TEMP_AUTHMGR_BE_TRANSPORT_ID, TEMP_AUTHMGR_FE_TRANSPORT_ID,
+    },
+    CMD_RAW, CMD_RPC, TOKEN_LENGTH,
+};
+use authmgr_common_util::{
+    get_constraint_spec_for_static_trusty_ta, get_constraints_spec_for_trusty_vm,
+    policy_for_dice_node,
+};
+use binder::Strong;
+use coset::CborSerializable;
+use hello_world_trusted_aidl::aidl::android::trusty::trustedhal::IHelloWorld::IHelloWorld;
+use rpcbinder::RpcSession;
+use test::assert_ok;
+use tipc::{Deserialize, Handle, Serialize, Serializer, TipcError};
+use trusty_std::alloc::TryAllocFrom;
+
+test::init!();
+
+#[test]
+fn test_authmgr_connection() {
+    assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+}
+
+#[test]
+fn test_authmgr_rpc_command() {
+    // Test the AuthMgr Init Service by sending just CMD_RPC over the connection, expect success.
+
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+}
+
+#[test]
+fn test_authmgr_rpc_command_with_session_setup() {
+    // Test the AuthMgr Init Service by sending CMD_RPC over the connection and then setting
+    // up session, expect success.
+
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let _rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+}
+
+#[test]
+fn test_authmgr_init_auth_ok() {
+    // Test the IAuthMgrAuthorization AIDL interface - initAuthentication, expect success.
+    // Connect and send message indicating the intent to connect to the RPC service
+
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
+    let (_signing_key, _cdi_values, cert_chain) =
+        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+    let result_init_auth = rpc_session
+        .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain }, None);
+    let _challenge: [u8; TOKEN_LENGTH] =
+        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+}
+
+#[test]
+fn test_authmgr_init_auth_with_invalid_dice_chain() {
+    // Test the IAuthMgrAuthorization AIDL interface - initAuthentication with an invalid
+    // DICE chain, expect error.
+    // Connect and send message indicating the intent to connect to the RPC service
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+
+    let result_init_auth = rpc_session
+        .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: Vec::<u8>::new() }, None);
+    assert!(result_init_auth.is_err());
+    assert_eq!(
+        result_init_auth.err().unwrap().service_specific_error(),
+        Error::INVALID_DICE_CERT_CHAIN.0
+    );
+}
+
+#[test]
+fn test_authmgr_init_auth_no_instance_id() {
+    // Test the IAuthMgrAuthorization AIDL interface - initAuthentication with no instance id,
+    // expect error.
+    // Connect and send message indicating the intent to connect to the RPC service
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a test DICE chain (with CDI secrets for signing) without instance hash
+    let (_signing_key, _cdi_values, cert_chain) = create_dice_cert_chain_for_guest_os(None, 1);
+    let result_init_auth = rpc_session
+        .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain }, None);
+    // Expect error because the instance hash is neither in the DICE chain nor provided externally
+    assert!(result_init_auth.is_err());
+    assert_eq!(
+        result_init_auth.err().unwrap().service_specific_error(),
+        Error::INVALID_INSTANCE_IDENTIFIER.0
+    );
+}
+
+#[test]
+fn test_authmgr_duplicate_init_auth_with_same_vm_id() {
+    // Test the IAuthMgrAuthorization AIDL interface - with two calls to initAuthentication, from
+    // the same transport id (i.e. VM-ID), expect error.
+    // Connect and send message indicating the intent to connect to the RPC service
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
+    let (_signing_key, _cdi_values, cert_chain) =
+        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+    let result_init_auth = rpc_session
+        .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain.clone() }, None);
+    let _challenge: [u8; TOKEN_LENGTH] =
+        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+
+    let result_init_auth2 = rpc_session
+        .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain }, None);
+    assert!(result_init_auth2.is_err());
+    assert_eq!(
+        result_init_auth2.err().unwrap().service_specific_error(),
+        Error::AUTHENTICATION_ALREADY_STARTED.0
+    );
+}
+
+#[test]
+fn test_authmgr_duplicate_init_auth_with_same_vm_id_after_cache_cleanup() {
+    // Test the IAuthMgrAuthorization AIDL interface - with two calls to initAuthentication, from
+    // the same transport id (i.e. VM-ID), but after cache cleanup triggered by closing the initial
+    // connection, expect success.
+    // Connect and send message indicating the intent to connect to the RPC service
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
+    let (_signing_key, _cdi_values, cert_chain) =
+        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+    let result_init_auth = rpc_session
+        .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain.clone() }, None);
+    let _challenge: [u8; TOKEN_LENGTH] =
+        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+    // Drop the first connection to trigger cache cleanup
+    core::mem::drop(conn_rpc);
+
+    // Setup a new connection
+    let conn_rpc_2 =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    assert_ok!(conn_rpc_2.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb_authmgr_2 = || {
+        let fd = conn_rpc_2.as_raw_fd();
+        Some(fd)
+    };
+
+    // Setup RPC connection to the AuthMgr service and execute step 1 of phase 1
+    let rpc_session_2 = RpcSession::new();
+    let rpc_session_2: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session_2.setup_preconnected_client(cb_authmgr_2),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+
+    let result_init_auth2 = rpc_session_2
+        .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain }, None);
+    let _challenge: [u8; TOKEN_LENGTH] = assert_ok!(result_init_auth2);
+}
+
+#[test]
+fn test_authmgr_complete_auth_ok() {
+    // Test the IAuthMgrAuthorization AIDL interface - completeAuthentication, expect success.
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
+    let (signing_key, _cdi_values, cert_chain_bytes) =
+        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+    let result_init_auth = rpc_session.initAuthentication(
+        &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
+        None,
+    );
+    let challenge: [u8; TOKEN_LENGTH] =
+        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+
+    let cert_chain =
+        assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
+    // Build the connection request to be signed
+    let conn_req = ConnectionRequest::new_for_ffa_transport(
+        challenge,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    // Sign the connection request with the DICE CDI secrets
+    let ecdsa = BoringEcDsa;
+    let verify_key = assert_ok!(cert_chain.validate(&ecdsa), "Failed to validate the cert chain");
+    let signing_algorithm = verify_key.get_cose_sign_algorithm();
+    let signature = assert_ok!(
+        conn_req.sign(&signing_key, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+    // Create a DICE policy
+    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let policy = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
+        "Failed to building policy for pvm"
+    );
+
+    // ****** Invoke step 2 of phase 1 of the protocol ******
+    let result_complete_auth = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy.to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    assert_ok!(result_complete_auth);
+}
+
+#[test]
+fn test_authmgr_duplicate_init_auth_on_authenticated_connection() {
+    // Test the IAuthMgrAuthorization AIDL interface - with two calls to initAuthentication, over
+    // an already authenticated connection, expect error.
+    // Connect and send message indicating the intent to connect to the RPC service
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
+    let (signing_key, _cdi_values, cert_chain_bytes) =
+        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+    let result_init_auth = rpc_session.initAuthentication(
+        &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
+        None,
+    );
+    let challenge: [u8; TOKEN_LENGTH] =
+        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+
+    let cert_chain =
+        assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
+    // Build the connection request to be signed
+    let conn_req = ConnectionRequest::new_for_ffa_transport(
+        challenge,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    // Sign the connection request with the DICE CDI secrets
+    let ecdsa = BoringEcDsa;
+    let verify_key = assert_ok!(cert_chain.validate(&ecdsa), "Failed to validate the cert chain");
+    let signing_algorithm = verify_key.get_cose_sign_algorithm();
+    let signature = assert_ok!(
+        conn_req.sign(&signing_key, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+    // Create a DICE policy
+    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let policy = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
+        "Failed to building policy for pvm"
+    );
+
+    // ****** Invoke step 2 of phase 1 of the protocol ******
+    let result_complete_auth = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy.to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    assert_ok!(result_complete_auth);
+
+    // ******* Invoke step 1 of phase 1 of the protocol over the same connection ********
+    let result_init_auth2 = rpc_session
+        .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes }, None);
+    assert!(result_init_auth2.is_err());
+    assert_eq!(
+        result_init_auth2.err().unwrap().service_specific_error(),
+        Error::INSTANCE_ALREADY_AUTHENTICATED.0
+    );
+}
+
+#[test]
+fn test_authmgr_duplicate_init_auth_with_same_instance_id_of_authenticatd_vm_on_new_connection() {
+    // Test the IAuthMgrAuthorization AIDL interface - with two calls to initAuthentication, using
+    // the same instance id of an authenticated pvm, over a new connection, expect error.
+    // Connect and send message indicating the intent to connect to the RPC service
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
+    let (signing_key, _cdi_values, cert_chain_bytes) =
+        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+    let result_init_auth = rpc_session.initAuthentication(
+        &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
+        None,
+    );
+    let challenge: [u8; TOKEN_LENGTH] =
+        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+
+    let cert_chain =
+        assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
+    // Build the connection request to be signed
+    let conn_req = ConnectionRequest::new_for_ffa_transport(
+        challenge,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    // Sign the connection request with the DICE CDI secrets
+    let ecdsa = BoringEcDsa;
+    let verify_key = assert_ok!(cert_chain.validate(&ecdsa), "Failed to validate the cert chain");
+    let signing_algorithm = verify_key.get_cose_sign_algorithm();
+    let signature = assert_ok!(
+        conn_req.sign(&signing_key, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+    // Create a DICE policy
+    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let policy = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
+        "Failed to building policy for pvm"
+    );
+
+    // ****** Invoke step 2 of phase 1 of the protocol ******
+    let result_complete_auth = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy.to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    assert_ok!(result_complete_auth);
+
+    // ******* Invoke step 1 of phase 1 of the protocol over a different connection ********
+    let conn_rpc_2 = assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT));
+    assert_ok!(conn_rpc_2.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb_authmgr_2 = || {
+        let fd = conn_rpc_2.as_raw_fd();
+        Some(fd)
+    };
+
+    // Setup RPC connection to the AuthMgr service and execute step 1 of phase 1
+    let rpc_session_2 = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session_2.setup_preconnected_client(cb_authmgr_2),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+
+    let result_init_auth2 = rpc_session
+        .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes }, None);
+    assert!(result_init_auth2.is_err());
+    assert_eq!(
+        result_init_auth2.err().unwrap().service_specific_error(),
+        Error::INSTANCE_ALREADY_AUTHENTICATED.0
+    );
+}
+
+#[test]
+fn test_authmgr_duplicate_init_auth_with_diff_instance_ids_same_vm_id_of_authenticatd_vm_on_new_connection(
+) {
+    // Test the IAuthMgrAuthorization AIDL interface - with two calls to initAuthentication, using
+    // different instance ids, but the same vm-id of an authenticated pvm, over a new connection,
+    // expect error.
+    // Connect and send message indicating the intent to connect to the RPC service
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
+    let (signing_key, _cdi_values, cert_chain_bytes) =
+        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+    let result_init_auth = rpc_session.initAuthentication(
+        &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
+        None,
+    );
+    let challenge: [u8; TOKEN_LENGTH] =
+        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+
+    let cert_chain =
+        assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
+    // Build the connection request to be signed
+    let conn_req = ConnectionRequest::new_for_ffa_transport(
+        challenge,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    // Sign the connection request with the DICE CDI secrets
+    let ecdsa = BoringEcDsa;
+    let verify_key = assert_ok!(cert_chain.validate(&ecdsa), "Failed to validate the cert chain");
+    let signing_algorithm = verify_key.get_cose_sign_algorithm();
+    let signature = assert_ok!(
+        conn_req.sign(&signing_key, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+    // Create a DICE policy
+    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let policy = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
+        "Failed to building policy for pvm"
+    );
+
+    // ****** Invoke step 2 of phase 1 of the protocol ******
+    let result_complete_auth = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy.to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    assert_ok!(result_complete_auth);
+
+    // Create a DICE chain with a different instance hash
+    pub const DIFF_INSTANCE_HASH: [u8; 64] = [
+        0x5b, 0x3f, 0xc9, 0x6b, 0xe3, 0x95, 0x59, 0x40, 0x21, 0x09, 0x9c, 0xf3, 0xcd, 0xc7, 0xa4,
+        0x2a, 0x7d, 0x7e, 0xf5, 0x8e, 0xd6, 0x4d, 0x82, 0x25, 0x1a, 0x51, 0x27, 0x9d, 0x55, 0x8a,
+        0xe9, 0x90, 0xf5, 0x8e, 0xd6, 0x4d, 0x84, 0x25, 0x1a, 0x51, 0x27, 0x9d, 0x5b, 0x3f, 0xc9,
+        0x6a, 0xe3, 0x95, 0x59, 0x40, 0x21, 0x09, 0x3d, 0xf3, 0xcd, 0xc7, 0xa4, 0x2a, 0x7d, 0x7e,
+        0xf5, 0x8e, 0xf5, 0x8e,
+    ];
+    let (_signing_key_2, _cdi_values_2, cert_chain_bytes_2) =
+        create_dice_cert_chain_for_guest_os(Some(DIFF_INSTANCE_HASH), 1);
+
+    // ******* Invoke step 1 of phase 1 of the protocol over a different connection ********
+    let conn_rpc_2 = assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT));
+    assert_ok!(conn_rpc_2.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb_authmgr_2 = || {
+        let fd = conn_rpc_2.as_raw_fd();
+        Some(fd)
+    };
+
+    // Setup RPC connection to the AuthMgr service and execute step 1 of phase 1
+    let rpc_session_2 = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session_2.setup_preconnected_client(cb_authmgr_2),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+
+    let result_init_auth2 = rpc_session
+        .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes_2 }, None);
+    assert!(result_init_auth2.is_err());
+    assert_eq!(
+        result_init_auth2.err().unwrap().service_specific_error(),
+        Error::INSTANCE_ALREADY_AUTHENTICATED.0
+    );
+}
+
+#[test]
+fn test_authmgr_raw_command_without_authentication() {
+    // Test the AuthMgr Init Service by sending CMD_RAW over the connection, which should result in
+    // an error and connection close at the service side because the previous steps of the protocol
+    // have not been performed yet. The only way we can assert that this results in an error in the
+    // service is by waiting for `recv` on the connection and trying to send another command and
+    // asserting that it fails.
+    let conn_raw =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+
+    let mut token = [0u8; TOKEN_LENGTH];
+    let boring_rng = BoringRng;
+    boring_rng.fill_bytes(&mut token);
+    let mut msg = Vec::<u8>::new();
+    msg.push(CMD_RAW);
+    msg.extend_from_slice(&token);
+    let cmd_raw = AuthMgrMessage(msg);
+    assert_ok!(conn_raw.send(&cmd_raw));
+
+    pub struct AuthMgrMessage(pub Vec<u8>);
+
+    impl Deserialize for AuthMgrMessage {
+        type Error = TipcError;
+        const MAX_SERIALIZED_SIZE: usize = 4000;
+
+        fn deserialize(bytes: &[u8], _handles: &mut [Option<Handle>]) -> Result<Self, TipcError> {
+            Ok(AuthMgrMessage(Vec::try_alloc_from(bytes)?))
+        }
+    }
+
+    impl<'s> Serialize<'s> for AuthMgrMessage {
+        fn serialize<'a: 's, S: Serializer<'s>>(
+            &'a self,
+            serializer: &mut S,
+        ) -> Result<S::Ok, S::Error> {
+            serializer.serialize_bytes(self.0.as_slice())
+        }
+    }
+
+    let mut buf = [0u8; 1];
+    let _resul: Result<AuthMgrMessage, TipcError> = conn_raw.recv(&mut buf);
+
+    let result2 = conn_raw.send(&cmd_raw);
+    assert!(result2.is_err());
+}
+
+#[test]
+fn test_authmgr_complete_auth_without_init_auth() {
+    // Test IAuthMgrAuthorization AIDL interface - by invoking completeAuthentication without
+    // invoking initAuthentication before - expect error
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    let result_complete_auth = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: Vec::new() },
+        &DicePolicy { dicePolicy: Vec::new() },
+    );
+    assert!(result_complete_auth.is_err());
+    assert_eq!(
+        result_complete_auth.err().unwrap().service_specific_error(),
+        Error::AUTHENTICATION_NOT_STARTED.0
+    );
+}
+
+#[test]
+fn test_authmgr_duplicate_complete_auth_on_the_same_connection() {
+    // Test IAuthMgrAuthorization AIDL interface - by invoking completeAuthentication on an alerady
+    // authenticated connection.
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
+    let (signing_key, _cdi_values, cert_chain_bytes) =
+        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+    let result_init_auth = rpc_session.initAuthentication(
+        &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
+        None,
+    );
+    let challenge: [u8; TOKEN_LENGTH] =
+        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+
+    let cert_chain =
+        assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
+    // Build the connection request to be signed
+    let conn_req = ConnectionRequest::new_for_ffa_transport(
+        challenge,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    // Sign the connection request with the DICE CDI secrets
+    let ecdsa = BoringEcDsa;
+    let verify_key = assert_ok!(cert_chain.validate(&ecdsa), "Failed to validate the cert chain");
+    let signing_algorithm = verify_key.get_cose_sign_algorithm();
+    let signature = assert_ok!(
+        conn_req.sign(&signing_key, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+    // Create a DICE policy
+    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let policy = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
+        "Failed to building policy for pvm"
+    );
+
+    // ****** Invoke step 2 of phase 1 of the protocol ******
+    let result_complete_auth = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature.clone() },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy.clone().to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    assert_ok!(result_complete_auth);
+
+    let result_complete_auth2 = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy.to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    assert!(result_complete_auth2.is_err());
+    assert_eq!(
+        result_complete_auth2.err().unwrap().service_specific_error(),
+        Error::INSTANCE_ALREADY_AUTHENTICATED.0
+    );
+}
+
+#[test]
+fn test_authmgr_duplicate_complete_auth_on_new_connection() {
+    // Test the IAuthMgrAuthorization AIDL interface - by invoking completeAuthentication from
+    // an authenticated pvm, over a new connection, expect error.
+    // Connect and send message indicating the intent to connect to the RPC service
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
+    let (signing_key, _cdi_values, cert_chain_bytes) =
+        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+    let result_init_auth = rpc_session.initAuthentication(
+        &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
+        None,
+    );
+    let challenge: [u8; TOKEN_LENGTH] =
+        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+
+    let cert_chain =
+        assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
+    // Build the connection request to be signed
+    let conn_req = ConnectionRequest::new_for_ffa_transport(
+        challenge,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    // Sign the connection request with the DICE CDI secrets
+    let ecdsa = BoringEcDsa;
+    let verify_key = assert_ok!(cert_chain.validate(&ecdsa), "Failed to validate the cert chain");
+    let signing_algorithm = verify_key.get_cose_sign_algorithm();
+    let signature = assert_ok!(
+        conn_req.sign(&signing_key, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+    // Create a DICE policy
+    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let policy = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
+        "Failed to building policy for pvm"
+    );
+
+    // ****** Invoke step 2 of phase 1 of the protocol ******
+    let result_complete_auth = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature.clone() },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy.clone().to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    assert_ok!(result_complete_auth);
+
+    // ******* Invoke step 2 of phase 1 of the protocol over a different connection ********
+    let conn_rpc_2 = assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT));
+    assert_ok!(conn_rpc_2.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb_authmgr_2 = || {
+        let fd = conn_rpc_2.as_raw_fd();
+        Some(fd)
+    };
+
+    // Setup RPC connection to the AuthMgr service and execute step 1 of phase 1
+    let rpc_session_2 = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session_2.setup_preconnected_client(cb_authmgr_2),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+
+    let result_complete_auth_2 = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy.to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    assert!(result_complete_auth_2.is_err());
+    assert_eq!(
+        result_complete_auth_2.err().unwrap().service_specific_error(),
+        Error::INSTANCE_ALREADY_AUTHENTICATED.0
+    );
+}
+
+#[test]
+fn test_authmgr_duplicate_complete_auth_after_cache_cleanup() {
+    // Test the IAuthMgrAuthorization AIDL interface - with two attempts for phase 1, from
+    // the same transport id (i.e. VM-ID), but after cache cleanup triggered by closing the initial
+    // connection, expect success.
+    // Connect and send message indicating the intent to connect to the RPC service
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
+    let (signing_key, _cdi_values, cert_chain_bytes) =
+        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+    let result_init_auth = rpc_session.initAuthentication(
+        &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
+        None,
+    );
+    let challenge: [u8; TOKEN_LENGTH] =
+        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+
+    let cert_chain =
+        assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
+    // Build the connection request to be signed
+    let conn_req = ConnectionRequest::new_for_ffa_transport(
+        challenge,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    // Sign the connection request with the DICE CDI secrets
+    let ecdsa = BoringEcDsa;
+    let verify_key = assert_ok!(cert_chain.validate(&ecdsa), "Failed to validate the cert chain");
+    let signing_algorithm = verify_key.get_cose_sign_algorithm();
+    let signature = assert_ok!(
+        conn_req.sign(&signing_key, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+    // Create a DICE policy
+    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let policy = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
+        "Failed to building policy for pvm"
+    );
+
+    // ****** Invoke step 2 of phase 1 of the protocol ******
+    let result_complete_auth = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy.clone().to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    assert_ok!(result_complete_auth);
+
+    // Drop the first connection to trigger cache cleanup
+    core::mem::drop(conn_rpc);
+
+    // Setup a new connection
+    let conn_rpc_2 =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    assert_ok!(conn_rpc_2.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb_authmgr_2 = || {
+        let fd = conn_rpc_2.as_raw_fd();
+        Some(fd)
+    };
+
+    // Setup RPC connection to the AuthMgr service and execute step 1 of phase 1
+    let rpc_session_2 = RpcSession::new();
+    let rpc_session_2: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session_2.setup_preconnected_client(cb_authmgr_2),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+
+    let result_init_auth_2 = rpc_session_2
+        .initAuthentication(&ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes }, None);
+    let challenge_2: [u8; TOKEN_LENGTH] = assert_ok!(result_init_auth_2);
+
+    // Build the connection request to be signed
+    let conn_req_2 = ConnectionRequest::new_for_ffa_transport(
+        challenge_2,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    let signature_2 = assert_ok!(
+        conn_req_2.sign(&signing_key, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+
+    let result_complete_auth_2 = rpc_session_2.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature_2 },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy.to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    assert_ok!(result_complete_auth_2);
+}
+
+#[test]
+fn authmgr_full_protocol_happy_path() {
+    // Connect to the TA and send message indicating the intent to connect to the binder RPC service
+    let conn_rpc =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to connect to AuthMgr BE.");
+    let cmd_rpc = AuthMgrMessage(vec![CMD_RPC]);
+    assert_ok!(conn_rpc.send(&cmd_rpc), "Failed to send the command requesting RPC service.");
+    let cb = || {
+        let fd = conn_rpc.as_raw_fd();
+        Some(fd)
+    };
+    let rpc_session = RpcSession::new();
+    let rpc_session: Strong<dyn IAuthMgrAuthorization> = assert_ok!(
+        rpc_session.setup_preconnected_client(cb),
+        "Failed to setup pre-connected client for the authmgr rpc service."
+    );
+    // Create a test DICE chain (with CDI secrets for signing) with an instance hash in vm_entry
+    let (signing_key, cdi_values, cert_chain_bytes) =
+        create_dice_cert_chain_for_guest_os(Some(SAMPLE_INSTANCE_HASH), 1);
+    let result_init_auth = rpc_session.initAuthentication(
+        &ExplicitKeyDiceCertChain { diceCertChain: cert_chain_bytes.clone() },
+        None,
+    );
+    let challenge: [u8; TOKEN_LENGTH] =
+        assert_ok!(result_init_auth, "Failed to invoke initAuthentication.");
+
+    let cert_chain =
+        assert_ok!(CertChain::from_slice(&cert_chain_bytes), "Failed to decode the cert chain");
+    // Build the connection request to be signed
+    let conn_req = ConnectionRequest::new_for_ffa_transport(
+        challenge,
+        TEMP_AUTHMGR_FE_TRANSPORT_ID,
+        TEMP_AUTHMGR_BE_TRANSPORT_ID,
+    );
+    // Sign the connection request with the DICE CDI secrets
+    let ecdsa = BoringEcDsa;
+    let verify_key = assert_ok!(cert_chain.validate(&ecdsa), "Failed to validate the cert chain");
+    let signing_algorithm = verify_key.get_cose_sign_algorithm();
+    let signature = assert_ok!(
+        conn_req.sign(&signing_key, &ecdsa, signing_algorithm),
+        "Failed to sign connection request"
+    );
+    // Create a DICE policy
+    let constraint_spec = get_constraints_spec_for_trusty_vm();
+    let policy = assert_ok!(
+        dice_policy_builder::policy_for_dice_chain(&cert_chain_bytes, constraint_spec),
+        "Failed to building policy for pvm"
+    );
+
+    // ****** Invoke step 2 of phase 1 of the protocol ******
+    let result_complete_auth = rpc_session.completeAuthentication(
+        &SignedConnectionRequest { signedConnectionRequest: signature },
+        &DicePolicy {
+            dicePolicy: assert_ok!(policy.to_vec(), "Failed to encode DICE policy for pvm"),
+        },
+    );
+    assert_ok!(result_complete_auth);
+
+    // Connect to the TA and send a message indicating the intent establish a raw connection and
+    // send a token
+    let conn_raw =
+        assert_ok!(Handle::connect(AUTHMGR_SERVICE_PORT), "Failed to setup a raw connection");
+    let mut token = [0u8; TOKEN_LENGTH];
+    let boring_rng = BoringRng;
+    boring_rng.fill_bytes(&mut token);
+    let mut msg = Vec::<u8>::new();
+    msg.push(CMD_RAW);
+    msg.extend_from_slice(&token);
+    let cmd_raw = AuthMgrMessage(msg);
+    assert_ok!(conn_raw.send(&cmd_raw));
+
+    // ****** Execute phase 2 of the AuthMgr protocol ******
+    // Create DICE certificate and a DICE policy for the client
+    let leaf_cert_bytes = create_dice_leaf_cert(cdi_values, "keymint", 1);
+    let client_constraint_spec_km = get_constraint_spec_for_static_trusty_ta();
+    let leaf_cert =
+        assert_ok!(DiceChainEntry::from_slice(&leaf_cert_bytes), "Failed to decode leaf cert");
+    let client_policy = assert_ok!(
+        policy_for_dice_node(&leaf_cert, client_constraint_spec_km),
+        "Failed to create policy for leaf cert"
+    );
+    let result_client_authz = rpc_session.authorizeAndConnectClientToTrustedService(
+        &[],
+        "HelloService",
+        &token,
+        &DiceLeafArtifacts {
+            diceLeaf: AidlDiceChainEntry { diceChainEntry: leaf_cert_bytes },
+            diceLeafPolicy: DicePolicy {
+                dicePolicy: assert_ok!(
+                    client_policy.to_vec(),
+                    "Failed to encode client dice policy."
+                ),
+            },
+        },
+    );
+    assert_ok!(result_client_authz);
+
+    // Simulate the client connecting to the IHelloWorld example trusted service over the raw
+    // connection authorized via AuthMgr protocol execution above
+    let cb_trusted_hal = || {
+        let fd = conn_raw.as_raw_fd();
+        Some(fd)
+    };
+
+    let trusted_service_rpc_session = RpcSession::new();
+    let trusted_service_rpc_session: Strong<dyn IHelloWorld> = assert_ok!(
+        trusted_service_rpc_session.setup_preconnected_client(cb_trusted_hal),
+        "Failed to setup pre-connected client for the trusted service."
+    );
+    let result = assert_ok!(trusted_service_rpc_session.sayHello("Test."));
+    assert_eq!("Hello Test.", result);
+}
diff --git a/authmgr-be/rustfmt.toml b/authmgr-be/rustfmt.toml
new file mode 100644
index 0000000..cefaa42
--- /dev/null
+++ b/authmgr-be/rustfmt.toml
@@ -0,0 +1,5 @@
+# Android Format Style
+
+edition = "2021"
+use_small_heuristics = "Max"
+newline_style = "Unix"
diff --git a/authmgr-fe/accessor.rs b/authmgr-fe/accessor.rs
new file mode 100644
index 0000000..f171596
--- /dev/null
+++ b/authmgr-fe/accessor.rs
@@ -0,0 +1,87 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+use binder::{BinderFeatures, Interface, ParcelFileDescriptor, Status, StatusCode};
+use std::ffi::CStr;
+use std::os::fd::{FromRawFd, OwnedFd};
+use tipc::Uuid;
+use trusty_binder_accessor::aidl::trusty::os::ITrustyAccessor::{
+    BnTrustyAccessor, ITrustyAccessor, ERROR_FAILED_TO_CREATE_SOCKET,
+};
+
+pub enum SecurityConfig {
+    // The accessor will resolve connections using the AuthMgr protocol.
+    Secure,
+    // The accessor will not perform any authentication or authorization,
+    // but simply establish a connection to the target port.
+    Insecure { target_port: &'static CStr },
+}
+
+pub struct AuthMgrAccessor {
+    service_name: &'static str,
+    security_config: SecurityConfig,
+    _uuid: Uuid,
+}
+
+impl AuthMgrAccessor {
+    pub fn new_binder(
+        service_name: &'static str,
+        security_config: SecurityConfig,
+        _uuid: Uuid,
+    ) -> binder::Strong<dyn ITrustyAccessor> {
+        let accessor = AuthMgrAccessor { service_name, security_config, _uuid };
+        BnTrustyAccessor::new_binder(accessor, BinderFeatures::default())
+    }
+}
+
+impl ITrustyAccessor for AuthMgrAccessor {
+    fn addConnection(&self) -> Result<ParcelFileDescriptor, Status> {
+        match self.security_config {
+            SecurityConfig::Secure => unimplemented!(),
+            SecurityConfig::Insecure { target_port } => add_insecure_connection(target_port),
+        }
+    }
+
+    fn getInstanceName(&self) -> Result<String, Status> {
+        let mut out_name = String::new();
+        out_name.try_reserve_exact(self.service_name.len()).map_err(|_| StatusCode::NO_MEMORY)?;
+        out_name.push_str(self.service_name);
+
+        Ok(out_name)
+    }
+}
+
+impl Interface for AuthMgrAccessor {}
+
+fn add_insecure_connection(port: &CStr) -> Result<ParcelFileDescriptor, Status> {
+    let handle = tipc::Handle::connect(port).map_err(|_| {
+        binder::Status::new_service_specific_error(
+            ERROR_FAILED_TO_CREATE_SOCKET,
+            Some(c"AuthMgrAccessor failed to connect to port"),
+        )
+    })?;
+
+    // TODO: b/395847127 - clean this up once we have Handle::into_raw_fd
+    let fd = handle.as_raw_fd();
+    // Do not close this fd. We're passing ownership of it
+    // to ParcelFileDescriptor.
+    core::mem::forget(handle);
+    // SAFETY: The fd is open since it was obtained from a successful call to
+    // tipc::Handle::connect. The fd is suitable for transferring ownership because we've leaked
+    // the original handle to ensure it isn't dropped.
+    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
+    Ok(ParcelFileDescriptor::new(owned_fd))
+}
diff --git a/authmgr-fe/app/main.rs b/authmgr-fe/app/main.rs
new file mode 100644
index 0000000..8f7f0ca
--- /dev/null
+++ b/authmgr-fe/app/main.rs
@@ -0,0 +1,24 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+use log::info;
+
+fn main() {
+    trusty_log::init();
+    info!("Hello from AuthMgr-FE!");
+
+    authmgr_fe::init_and_start_loop().expect("AuthMgr-FE should not exit");
+}
diff --git a/authmgr-fe/app/manifest.json b/authmgr-fe/app/manifest.json
new file mode 100644
index 0000000..569b9ba
--- /dev/null
+++ b/authmgr-fe/app/manifest.json
@@ -0,0 +1,6 @@
+{
+    "app_name": "authmgr_fe_app",
+    "uuid": "9b3c1e9e-1808-4b98-8fa9-8592dff3a337",
+    "min_heap": 16384,
+    "min_stack": 8192
+}
diff --git a/authmgr-fe/app/rules.mk b/authmgr-fe/app/rules.mk
new file mode 100644
index 0000000..8b110e9
--- /dev/null
+++ b/authmgr-fe/app/rules.mk
@@ -0,0 +1,33 @@
+# Copyright (C) 2025 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/main.rs \
+
+MODULE_CRATE_NAME := authmgr_fe_app
+
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,log) \
+	trusty/user/app/authmgr/authmgr-fe \
+	trusty/user/base/interface/binder_accessor \
+	trusty/user/base/lib/trusty-log \
+
+include make/trusted_app.mk
diff --git a/authmgr-fe/lib.rs b/authmgr-fe/lib.rs
new file mode 100644
index 0000000..b4487fd
--- /dev/null
+++ b/authmgr-fe/lib.rs
@@ -0,0 +1,109 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+mod accessor;
+
+use alloc::rc::Rc;
+use rpcbinder::RpcServer;
+use std::ffi::CStr;
+use tipc::{service_dispatcher, Manager, PortCfg};
+
+pub use accessor::{AuthMgrAccessor, SecurityConfig};
+
+const SECURE_STORAGE_SERVICE_NAME: &str =
+    "android.hardware.security.see.storage.ISecureStorage/default";
+const SECURE_STORAGE_TARGET_PORT: &CStr = c"com.android.hardware.security.see.storage";
+const HWKEY_SERVICE_NAME: &str = "android.hardware.security.see.hwcrypto.IHwCryptoKey/default";
+const HWKEY_TARGET_PORT: &CStr = c"com.android.trusty.rust.hwcryptohal.V1";
+
+const PORT_COUNT: usize = 2;
+const CONNECTION_COUNT: usize = 6;
+
+type AuthMgrAccessorService = rpcbinder::RpcServer;
+
+service_dispatcher! {
+    pub enum AuthMgrFeDispatcher {
+        AuthMgrAccessorService,
+    }
+}
+
+fn add_server_to_authmgr_dispatcher(
+    dispatcher: &mut AuthMgrFeDispatcher<PORT_COUNT>,
+    service_name: &'static str,
+    target_port: &'static CStr,
+) {
+    let accessor_server = RpcServer::new_per_session(move |uuid| {
+        Some(
+            AuthMgrAccessor::new_binder(service_name, get_security_config(target_port), uuid)
+                .as_binder(),
+        )
+    });
+    let serving_port = service_manager::service_name_to_trusty_port(service_name)
+        .expect("Port name to be derivable from service name");
+    let service_cfg =
+        PortCfg::new(serving_port).expect("Service port should be valid").allow_ta_connect();
+
+    dispatcher
+        .add_service(Rc::new(accessor_server), service_cfg)
+        .expect("RPC service should add to dispatcher");
+}
+
+#[cfg(feature = "authmgrfe_mode_insecure")]
+fn get_security_config(target_port: &'static CStr) -> SecurityConfig {
+    log::warn!("Using authmgr-fe SecurityConfig::Insecure - no authentication or authorization for trusted services.");
+    SecurityConfig::Insecure { target_port }
+}
+
+#[cfg(not(feature = "authmgrfe_mode_insecure"))]
+fn get_security_config(_target_port: &'static CStr) -> SecurityConfig {
+    log::info!("Using authmgr-fe SecurityConfig::Secure.");
+    SecurityConfig::Secure
+}
+
+pub fn init_and_start_loop() -> tipc::Result<()> {
+    let mut dispatcher =
+        AuthMgrFeDispatcher::<PORT_COUNT>::new().expect("Dispatcher creation should not fail");
+
+    add_server_to_authmgr_dispatcher(
+        &mut dispatcher,
+        SECURE_STORAGE_SERVICE_NAME,
+        SECURE_STORAGE_TARGET_PORT,
+    );
+    add_server_to_authmgr_dispatcher(&mut dispatcher, HWKEY_SERVICE_NAME, HWKEY_TARGET_PORT);
+
+    Manager::<_, _, PORT_COUNT, CONNECTION_COUNT>::new_with_dispatcher(dispatcher, [])
+        .expect("Service manager should be created")
+        .run_event_loop()
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+    use binder::IBinder;
+    use test::*;
+    use service_manager::*;
+    use android_hardware_security_see_storage::aidl::android::hardware::security::see::storage::ISecureStorage::ISecureStorage;
+
+    test::init!();
+
+    #[test]
+    fn test_get_secure_storage_binder() {
+        let ss: Result<binder::Strong<dyn ISecureStorage>, binder::StatusCode> =
+            wait_for_interface(SECURE_STORAGE_SERVICE_NAME);
+
+        assert_ok!(ss.expect("secure storage interface to be resolved").as_binder().ping_binder());
+    }
+}
diff --git a/authmgr-fe/manifest.json b/authmgr-fe/manifest.json
new file mode 100644
index 0000000..89d59ba
--- /dev/null
+++ b/authmgr-fe/manifest.json
@@ -0,0 +1,9 @@
+{
+    "app_name": "authmgr_fe_tests",
+    "uuid": "2b5d904d-a589-44db-9f0d-72de76729736",
+    "min_heap": 16384,
+    "min_stack": 16384,
+    "mgmt_flags": {
+        "non_critical_app": true
+    }
+}
diff --git a/authmgr-fe/rules.mk b/authmgr-fe/rules.mk
new file mode 100644
index 0000000..a7a7728
--- /dev/null
+++ b/authmgr-fe/rules.mk
@@ -0,0 +1,50 @@
+# Copyright (C) 2025 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/lib.rs \
+
+MODULE_CRATE_NAME := authmgr_fe
+
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,log) \
+	frameworks/native/libs/binder/trusty/rust \
+	frameworks/native/libs/binder/trusty/rust/rpcbinder \
+	trusty/user/base/interface/binder_accessor \
+	trusty/user/base/interface/secure_storage/rust \
+	trusty/user/base/lib/service_manager/client \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/trusty-log \
+	trusty/user/base/lib/trusty-std \
+
+
+ifeq (true,$(call TOBOOL,$(AUTHMGRFE_MODE_INSECURE)))
+
+MODULE_RUSTFLAGS += \
+	--cfg 'feature="authmgrfe_mode_insecure"' \
+
+endif
+
+
+MODULE_RUST_TESTS := true
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+include make/library.mk
diff --git a/rustfmt.toml b/rustfmt.toml
new file mode 100644
index 0000000..cefaa42
--- /dev/null
+++ b/rustfmt.toml
@@ -0,0 +1,5 @@
+# Android Format Style
+
+edition = "2021"
+use_small_heuristics = "Max"
+newline_style = "Unix"
```

