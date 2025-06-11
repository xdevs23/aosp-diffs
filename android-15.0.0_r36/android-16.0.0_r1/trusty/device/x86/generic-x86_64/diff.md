```diff
diff --git a/project/vm-x86_64-security-inc.mk b/project/vm-x86_64-security-inc.mk
new file mode 100644
index 0000000..3e0aaf8
--- /dev/null
+++ b/project/vm-x86_64-security-inc.mk
@@ -0,0 +1,40 @@
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
+include project/generic-x86_64-inc.mk
+
+#
+# overwrite list of TAs
+#
+TRUSTY_VM_INCLUDE_KEYMINT ?= true
+TRUSTY_VM_INCLUDE_GATEKEEPER ?= true
+
+# compiled from source
+TRUSTY_BUILTIN_USER_TASKS := \
+	trusty/user/app/gatekeeper \
+	trusty/user/app/keymint/app \
+	trusty/user/base/app/device_tree \
+
+ifeq (true,$(call TOBOOL,$(USER_COVERAGE_ENABLED)))
+TRUSTY_ALL_USER_TASKS += \
+	trusty/user/base/app/coverage \
+
+endif
+
+ifeq (true,$(call TOBOOL,$(UNITTEST_COVERAGE_ENABLED)))
+TRUSTY_ALL_USER_TASKS += \
+	trusty/user/base/app/line-coverage \
+
+endif
diff --git a/project/vm-x86_64-security-placeholder-trusted-hal-inc.mk b/project/vm-x86_64-security-placeholder-trusted-hal-inc.mk
new file mode 100644
index 0000000..cc62695
--- /dev/null
+++ b/project/vm-x86_64-security-placeholder-trusted-hal-inc.mk
@@ -0,0 +1,44 @@
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
+#
+# complement with the placeholder trusted hals
+#
+WITH_FAKE_HWRNG ?= true
+WITH_FAKE_HWKEY ?= true
+WITH_FAKE_KEYBOX ?= true
+
+# Derive RPMB key using HKDF
+WITH_HKDF_RPMB_KEY ?= true
+
+STORAGE_ENABLE_ERROR_REPORTING ?= true
+STORAGE_AIDL_ENABLED ?= true
+TRUSTY_VM_INCLUDE_SECURE_STORAGE_HAL ?= true
+
+KEYMINT_TRUSTY_VM ?= nonsecure
+
+include project/vm-x86_64-security-inc.mk
+
+TRUSTY_BUILTIN_USER_TASKS += \
+	trusty/user/app/authmgr/authmgr-be/app \
+	trusty/user/app/sample/hwaes \
+	trusty/user/app/sample/hwbcc \
+	trusty/user/app/sample/hwcrypto \
+	trusty/user/app/sample/hwcryptohal/server/app \
+	trusty/user/app/sample/hwwsk \
+	trusty/user/app/sample/rust-hello-world-trusted-hal/app \
+	trusty/user/app/storage \
+	trusty/user/base/app/metrics \
+	trusty/user/base/app/system_state_server_static \
diff --git a/project/vm-x86_64-security-placeholder-trusted-hal-user.mk b/project/vm-x86_64-security-placeholder-trusted-hal-user.mk
new file mode 100644
index 0000000..d43c16a
--- /dev/null
+++ b/project/vm-x86_64-security-placeholder-trusted-hal-user.mk
@@ -0,0 +1,16 @@
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
+include project/vm-x86_64-security-placeholder-trusted-hal-inc.mk
diff --git a/project/vm-x86_64-security-placeholder-trusted-hal-userdebug.mk b/project/vm-x86_64-security-placeholder-trusted-hal-userdebug.mk
new file mode 100644
index 0000000..2460c26
--- /dev/null
+++ b/project/vm-x86_64-security-placeholder-trusted-hal-userdebug.mk
@@ -0,0 +1,24 @@
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
+# debug build
+DEBUG ?= 2
+UBSAN_ENABLED ?= true
+RELEASE_BUILD ?= false
+
+# If SYMTAB_ENABLED is true: do not strip symbols from the resulting app binary
+SYMTAB_ENABLED ?= true
+
+include project/vm-x86_64-security-placeholder-trusted-hal-inc.mk
diff --git a/project/vm-x86_64-security-user.mk b/project/vm-x86_64-security-user.mk
new file mode 100644
index 0000000..fdfc6ad
--- /dev/null
+++ b/project/vm-x86_64-security-user.mk
@@ -0,0 +1,16 @@
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
+include project/vm-x86_64-security-inc.mk
diff --git a/project/vm-x86_64-security-userdebug.mk b/project/vm-x86_64-security-userdebug.mk
new file mode 100644
index 0000000..a4c6249
--- /dev/null
+++ b/project/vm-x86_64-security-userdebug.mk
@@ -0,0 +1,24 @@
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
+# debug build
+DEBUG ?= 2
+UBSAN_ENABLED ?= true
+RELEASE_BUILD ?= false
+
+# If SYMTAB_ENABLED is true: do not strip symbols from the resulting app binary
+SYMTAB_ENABLED ?= true
+
+include project/vm-x86_64-security-inc.mk
diff --git a/project/vm-x86_64-test-inc.mk b/project/vm-x86_64-test-inc.mk
new file mode 100644
index 0000000..be376d5
--- /dev/null
+++ b/project/vm-x86_64-test-inc.mk
@@ -0,0 +1,56 @@
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
+WITH_FAKE_HWRNG ?= false
+WITH_FAKE_HWKEY ?= false
+WITH_FAKE_KEYBOX ?= false
+
+include project/generic-x86_64-inc.mk
+
+#
+# overwrite list of TAs
+#
+
+# the test-vm does not include any TAs by default
+# (except for the test TAs that are included by virt-test-inc.mk)
+#
+# tests in Trusty are mostly declared as TRUSTY_LOADABLE_USER_TESTS,
+# they also are included by default as builtin apps
+# (unless the top-level makefile initializes TRUSTY_BUILTIN_USER_TESTS,
+#  see documentation in trusty/kernel/app/trusty/user-tasks.mk)
+#
+# for virt payload, loadable TAs are generally not applicable
+# (apploader interface is not a stable ABI yet).
+# So apploader should generally be disabled.
+#
+# the Trusty build system however makes it complicated to disable
+# apploader service while still declaring tests as loadable.
+# as a short-term workaround, the test-vm will include apploader service
+# TODO(b/) evolve `trusty/kernel/app/trusty/user-tasks.mk` to support
+# disabling apploader service and rebalancing loadable test as builtin tests
+TRUSTY_BUILTIN_USER_TASKS := \
+	trusty/user/base/app/apploader \
+
+ifeq (true,$(call TOBOOL,$(USER_COVERAGE_ENABLED)))
+TRUSTY_ALL_USER_TASKS += \
+	trusty/user/base/app/coverage \
+
+endif
+
+ifeq (true,$(call TOBOOL,$(UNITTEST_COVERAGE_ENABLED)))
+TRUSTY_ALL_USER_TASKS += \
+	trusty/user/base/app/line-coverage \
+
+endif
diff --git a/project/vm-x86_64-test-placeholder-trusted-hal-inc.mk b/project/vm-x86_64-test-placeholder-trusted-hal-inc.mk
new file mode 100644
index 0000000..785d5d6
--- /dev/null
+++ b/project/vm-x86_64-test-placeholder-trusted-hal-inc.mk
@@ -0,0 +1,42 @@
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
+#
+# complement with the placeholder trusted hals
+#
+WITH_FAKE_HWRNG ?= true
+WITH_FAKE_HWKEY ?= true
+WITH_FAKE_KEYBOX ?= true
+
+# Derive RPMB key using HKDF
+WITH_HKDF_RPMB_KEY ?= true
+
+STORAGE_ENABLE_ERROR_REPORTING ?= true
+STORAGE_AIDL_ENABLED ?= true
+TRUSTY_VM_INCLUDE_SECURE_STORAGE_HAL ?= true
+
+include project/vm-x86_64-test-inc.mk
+
+TRUSTY_BUILTIN_USER_TASKS += \
+	trusty/user/app/authmgr/authmgr-be/app \
+	trusty/user/app/sample/hwaes \
+	trusty/user/app/sample/hwbcc \
+	trusty/user/app/sample/hwcrypto \
+	trusty/user/app/sample/hwcryptohal/server/app \
+	trusty/user/app/sample/hwwsk \
+	trusty/user/app/sample/rust-hello-world-trusted-hal/app \
+	trusty/user/app/storage \
+	trusty/user/base/app/metrics \
+	trusty/user/base/app/system_state_server_static \
diff --git a/project/vm-x86_64-test-placeholder-trusted-hal-user.mk b/project/vm-x86_64-test-placeholder-trusted-hal-user.mk
new file mode 100644
index 0000000..38209b1
--- /dev/null
+++ b/project/vm-x86_64-test-placeholder-trusted-hal-user.mk
@@ -0,0 +1,16 @@
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
+include project/vm-x86_64-test-placeholder-trusted-hal-inc.mk
diff --git a/project/vm-x86_64-test-placeholder-trusted-hal-userdebug.mk b/project/vm-x86_64-test-placeholder-trusted-hal-userdebug.mk
new file mode 100644
index 0000000..ff29962
--- /dev/null
+++ b/project/vm-x86_64-test-placeholder-trusted-hal-userdebug.mk
@@ -0,0 +1,24 @@
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
+# debug build
+DEBUG ?= 2
+UBSAN_ENABLED ?= true
+RELEASE_BUILD ?= false
+
+# If SYMTAB_ENABLED is true: do not strip symbols from the resulting app binary
+SYMTAB_ENABLED ?= true
+
+include project/vm-x86_64-test-placeholder-trusted-hal-inc.mk
diff --git a/project/vm-x86_64-test-user.mk b/project/vm-x86_64-test-user.mk
new file mode 100644
index 0000000..509c6eb
--- /dev/null
+++ b/project/vm-x86_64-test-user.mk
@@ -0,0 +1,16 @@
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
+include project/vm-x86_64-test-inc.mk
diff --git a/project/vm-x86_64-test-userdebug.mk b/project/vm-x86_64-test-userdebug.mk
new file mode 100644
index 0000000..cff5d45
--- /dev/null
+++ b/project/vm-x86_64-test-userdebug.mk
@@ -0,0 +1,24 @@
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
+# debug build
+DEBUG ?= 2
+UBSAN_ENABLED ?= true
+RELEASE_BUILD ?= false
+
+# If SYMTAB_ENABLED is true: do not strip symbols from the resulting app binary
+SYMTAB_ENABLED ?= true
+
+include project/vm-x86_64-test-inc.mk
diff --git a/project/vm-x86_64-test_os-inc.mk b/project/vm-x86_64-test_os-inc.mk
new file mode 100644
index 0000000..4010758
--- /dev/null
+++ b/project/vm-x86_64-test_os-inc.mk
@@ -0,0 +1,56 @@
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
+WITH_FAKE_HWRNG ?= false
+WITH_FAKE_HWKEY ?= false
+WITH_FAKE_KEYBOX ?= false
+
+include project/generic-x86_64-test-inc.mk
+
+#
+# overwrite list of TAs
+#
+
+# the test-vm does not include any TAs by default
+# (except for the test TAs that are included by virt-test-inc.mk)
+#
+# tests in Trusty are mostly declared as TRUSTY_LOADABLE_USER_TESTS,
+# they also are included by default as builtin apps
+# (unless the top-level makefile initializes TRUSTY_BUILTIN_USER_TESTS,
+#  see documentation in trusty/kernel/app/trusty/user-tasks.mk)
+#
+# for virt payload, loadable TAs are generally not applicable
+# (apploader interface is not a stable ABI yet).
+# So apploader should generally be disabled.
+#
+# the Trusty build system however makes it complicated to disable
+# apploader service while still declaring tests as loadable.
+# as a short-term workaround, the test-vm will include apploader service
+# TODO(b/) evolve `trusty/kernel/app/trusty/user-tasks.mk` to support
+# disabling apploader service and rebalancing loadable test as builtin tests
+TRUSTY_BUILTIN_USER_TASKS := \
+	trusty/user/base/app/apploader \
+
+ifeq (true,$(call TOBOOL,$(USER_COVERAGE_ENABLED)))
+TRUSTY_ALL_USER_TASKS += \
+	trusty/user/base/app/coverage \
+
+endif
+
+ifeq (true,$(call TOBOOL,$(UNITTEST_COVERAGE_ENABLED)))
+TRUSTY_ALL_USER_TASKS += \
+	trusty/user/base/app/line-coverage \
+
+endif
diff --git a/project/vm-x86_64-test_os-user.mk b/project/vm-x86_64-test_os-user.mk
new file mode 100644
index 0000000..6176085
--- /dev/null
+++ b/project/vm-x86_64-test_os-user.mk
@@ -0,0 +1,16 @@
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
+include project/vm-x86_64-test_os-inc.mk
diff --git a/project/vm-x86_64-test_os-userdebug.mk b/project/vm-x86_64-test_os-userdebug.mk
new file mode 100644
index 0000000..01bb82b
--- /dev/null
+++ b/project/vm-x86_64-test_os-userdebug.mk
@@ -0,0 +1,24 @@
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
+# debug build
+DEBUG ?= 2
+UBSAN_ENABLED ?= true
+RELEASE_BUILD ?= false
+
+# If SYMTAB_ENABLED is true: do not strip symbols from the resulting app binary
+SYMTAB_ENABLED ?= true
+
+include project/vm-x86_64-test_os-inc.mk
diff --git a/project/vm-x86_64-virt-inc.mk b/project/vm-x86_64-virt-inc.mk
new file mode 100644
index 0000000..bad5ac6
--- /dev/null
+++ b/project/vm-x86_64-virt-inc.mk
@@ -0,0 +1,30 @@
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
+# release build
+DEBUG ?= 1
+UBSAN_ENABLED ?= false
+RELEASE_BUILD ?= true
+SYMTAB_ENABLED ?= false
+
+# no placeholder hals by default
+WITH_FAKE_HWRNG ?= false
+WITH_FAKE_HWKEY ?= false
+WITH_FAKE_KEYBOX ?= false
+
+USE_SYSTEM_BINDER := true
+
+include project/generic-x86_64-inc.mk
+
diff --git a/project/vm-x86_64-virt-test-inc.mk b/project/vm-x86_64-virt-test-inc.mk
new file mode 100644
index 0000000..1c291f8
--- /dev/null
+++ b/project/vm-x86_64-virt-test-inc.mk
@@ -0,0 +1,18 @@
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
+include project/generic-x86_64-virt-inc.mk
+include project/generic-x86_64_test-inc.mk
+
```

