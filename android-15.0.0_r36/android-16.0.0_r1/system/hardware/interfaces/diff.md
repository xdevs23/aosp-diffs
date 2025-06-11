```diff
diff --git a/keystore2/aidl/Android.bp b/keystore2/aidl/Android.bp
index 31853ee..9119489 100644
--- a/keystore2/aidl/Android.bp
+++ b/keystore2/aidl/Android.bp
@@ -54,9 +54,13 @@ aidl_interface {
             version: "4",
             imports: ["android.hardware.security.keymint-V3"],
         },
+        {
+            version: "5",
+            imports: ["android.hardware.security.keymint-V4"],
+        },
 
     ],
-    frozen: false,
+    frozen: true,
 
 }
 
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/.hash b/keystore2/aidl/aidl_api/android.system.keystore2/5/.hash
new file mode 100644
index 0000000..9832228
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/.hash
@@ -0,0 +1 @@
+98d815116c190250e9e5a1d9182cea8126fd0e97
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/AuthenticatorSpec.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/AuthenticatorSpec.aidl
new file mode 100644
index 0000000..49a3b2c
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/AuthenticatorSpec.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright 2020, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.keystore2;
+/* @hide */
+@VintfStability
+parcelable AuthenticatorSpec {
+  android.hardware.security.keymint.HardwareAuthenticatorType authenticatorType = android.hardware.security.keymint.HardwareAuthenticatorType.NONE;
+  long authenticatorId;
+}
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/Authorization.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/Authorization.aidl
new file mode 100644
index 0000000..3efeb68
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/Authorization.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright 2020, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.keystore2;
+/* @hide */
+@VintfStability
+parcelable Authorization {
+  android.hardware.security.keymint.SecurityLevel securityLevel = android.hardware.security.keymint.SecurityLevel.SOFTWARE;
+  android.hardware.security.keymint.KeyParameter keyParameter;
+}
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/CreateOperationResponse.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/CreateOperationResponse.aidl
new file mode 100644
index 0000000..e37facb
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/CreateOperationResponse.aidl
@@ -0,0 +1,42 @@
+/*
+ * Copyright 2020, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.keystore2;
+/* @hide */
+@VintfStability
+parcelable CreateOperationResponse {
+  android.system.keystore2.IKeystoreOperation iOperation;
+  @nullable android.system.keystore2.OperationChallenge operationChallenge;
+  @nullable android.system.keystore2.KeyParameters parameters;
+  @nullable byte[] upgradedBlob;
+}
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/Domain.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/Domain.aidl
new file mode 100644
index 0000000..4fd54aa
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/Domain.aidl
@@ -0,0 +1,43 @@
+/*
+ * Copyright 2020, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.keystore2;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum Domain {
+  APP = 0,
+  GRANT = 1,
+  SELINUX = 2,
+  BLOB = 3,
+  KEY_ID = 4,
+}
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/EphemeralStorageKeyResponse.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/EphemeralStorageKeyResponse.aidl
new file mode 100644
index 0000000..963af7b
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/EphemeralStorageKeyResponse.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright 2021, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.keystore2;
+/* @hide */
+@VintfStability
+parcelable EphemeralStorageKeyResponse {
+  byte[] ephemeralKey;
+  @nullable byte[] upgradedBlob;
+}
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/IKeystoreOperation.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/IKeystoreOperation.aidl
new file mode 100644
index 0000000..df911cd
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/IKeystoreOperation.aidl
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.keystore2;
+/* @hide */
+@SensitiveData @VintfStability
+interface IKeystoreOperation {
+  void updateAad(in byte[] aadInput);
+  @nullable byte[] update(in byte[] input);
+  @nullable byte[] finish(in @nullable byte[] input, in @nullable byte[] signature);
+  void abort();
+}
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/IKeystoreSecurityLevel.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/IKeystoreSecurityLevel.aidl
new file mode 100644
index 0000000..4b2eab4
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/IKeystoreSecurityLevel.aidl
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.keystore2;
+/* @hide */
+@SensitiveData @VintfStability
+interface IKeystoreSecurityLevel {
+  android.system.keystore2.CreateOperationResponse createOperation(in android.system.keystore2.KeyDescriptor key, in android.hardware.security.keymint.KeyParameter[] operationParameters, in boolean forced);
+  android.system.keystore2.KeyMetadata generateKey(in android.system.keystore2.KeyDescriptor key, in @nullable android.system.keystore2.KeyDescriptor attestationKey, in android.hardware.security.keymint.KeyParameter[] params, in int flags, in byte[] entropy);
+  android.system.keystore2.KeyMetadata importKey(in android.system.keystore2.KeyDescriptor key, in @nullable android.system.keystore2.KeyDescriptor attestationKey, in android.hardware.security.keymint.KeyParameter[] params, in int flags, in byte[] keyData);
+  android.system.keystore2.KeyMetadata importWrappedKey(in android.system.keystore2.KeyDescriptor key, in android.system.keystore2.KeyDescriptor wrappingKey, in @nullable byte[] maskingKey, in android.hardware.security.keymint.KeyParameter[] params, in android.system.keystore2.AuthenticatorSpec[] authenticators);
+  android.system.keystore2.EphemeralStorageKeyResponse convertStorageKeyToEphemeral(in android.system.keystore2.KeyDescriptor storageKey);
+  void deleteKey(in android.system.keystore2.KeyDescriptor key);
+  const int KEY_FLAG_AUTH_BOUND_WITHOUT_CRYPTOGRAPHIC_LSKF_BINDING = 0x1;
+}
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/IKeystoreService.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/IKeystoreService.aidl
new file mode 100644
index 0000000..0c292c8
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/IKeystoreService.aidl
@@ -0,0 +1,51 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.keystore2;
+/* @hide */
+@VintfStability
+interface IKeystoreService {
+  android.system.keystore2.IKeystoreSecurityLevel getSecurityLevel(in android.hardware.security.keymint.SecurityLevel securityLevel);
+  android.system.keystore2.KeyEntryResponse getKeyEntry(in android.system.keystore2.KeyDescriptor key);
+  void updateSubcomponent(in android.system.keystore2.KeyDescriptor key, in @nullable byte[] publicCert, in @nullable byte[] certificateChain);
+  /**
+   * @deprecated use listEntriesBatched instead.
+   */
+  android.system.keystore2.KeyDescriptor[] listEntries(in android.system.keystore2.Domain domain, in long nspace);
+  void deleteKey(in android.system.keystore2.KeyDescriptor key);
+  android.system.keystore2.KeyDescriptor grant(in android.system.keystore2.KeyDescriptor key, in int granteeUid, in int accessVector);
+  void ungrant(in android.system.keystore2.KeyDescriptor key, in int granteeUid);
+  int getNumberOfEntries(in android.system.keystore2.Domain domain, in long nspace);
+  android.system.keystore2.KeyDescriptor[] listEntriesBatched(in android.system.keystore2.Domain domain, in long nspace, in @nullable String startingPastAlias);
+  byte[] getSupplementaryAttestationInfo(in android.hardware.security.keymint.Tag tag);
+}
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/KeyDescriptor.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/KeyDescriptor.aidl
new file mode 100644
index 0000000..79478aa
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/KeyDescriptor.aidl
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.keystore2;
+/* @hide */
+@RustDerive(Clone=true, Eq=true, Ord=true, PartialEq=true, PartialOrd=true) @VintfStability
+parcelable KeyDescriptor {
+  android.system.keystore2.Domain domain = android.system.keystore2.Domain.APP;
+  long nspace;
+  @nullable String alias;
+  @nullable byte[] blob;
+}
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/KeyEntryResponse.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/KeyEntryResponse.aidl
new file mode 100644
index 0000000..ea313b3
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/KeyEntryResponse.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright 2020, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.keystore2;
+/* @hide */
+@VintfStability
+parcelable KeyEntryResponse {
+  @nullable android.system.keystore2.IKeystoreSecurityLevel iSecurityLevel;
+  android.system.keystore2.KeyMetadata metadata;
+}
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/KeyMetadata.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/KeyMetadata.aidl
new file mode 100644
index 0000000..fef4531
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/KeyMetadata.aidl
@@ -0,0 +1,44 @@
+/*
+ * Copyright 2020, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.keystore2;
+/* @hide */
+@VintfStability
+parcelable KeyMetadata {
+  android.system.keystore2.KeyDescriptor key;
+  android.hardware.security.keymint.SecurityLevel keySecurityLevel = android.hardware.security.keymint.SecurityLevel.SOFTWARE;
+  android.system.keystore2.Authorization[] authorizations;
+  @nullable byte[] certificate;
+  @nullable byte[] certificateChain;
+  long modificationTimeMs;
+}
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/KeyParameters.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/KeyParameters.aidl
new file mode 100644
index 0000000..f9c836a
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/KeyParameters.aidl
@@ -0,0 +1,39 @@
+/*
+ * Copyright 2020, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.keystore2;
+/* @hide */
+@VintfStability
+parcelable KeyParameters {
+  android.hardware.security.keymint.KeyParameter[] keyParameter;
+}
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/KeyPermission.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/KeyPermission.aidl
new file mode 100644
index 0000000..3009fb6
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/KeyPermission.aidl
@@ -0,0 +1,51 @@
+/*
+ * Copyright 2020, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.keystore2;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum KeyPermission {
+  NONE = 0,
+  DELETE = 0x1,
+  GEN_UNIQUE_ID = 0x2,
+  GET_INFO = 0x4,
+  GRANT = 0x8,
+  MANAGE_BLOB = 0x10,
+  REBIND = 0x20,
+  REQ_FORCED_OP = 0x40,
+  UPDATE = 0x80,
+  USE = 0x100,
+  USE_DEV_ID = 0x200,
+  USE_NO_LSKF_BINDING = 0x400,
+  CONVERT_STORAGE_KEY_TO_EPHEMERAL = 0x800,
+}
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/OperationChallenge.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/OperationChallenge.aidl
new file mode 100644
index 0000000..0a079fb
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/OperationChallenge.aidl
@@ -0,0 +1,39 @@
+/*
+ * Copyright 2020, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.keystore2;
+/* @hide */
+@VintfStability
+parcelable OperationChallenge {
+  long challenge;
+}
diff --git a/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/ResponseCode.aidl b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/ResponseCode.aidl
new file mode 100644
index 0000000..51dddf0
--- /dev/null
+++ b/keystore2/aidl/aidl_api/android.system.keystore2/5/android/system/keystore2/ResponseCode.aidl
@@ -0,0 +1,59 @@
+/*
+ * Copyright 2020, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.keystore2;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum ResponseCode {
+  LOCKED = 2,
+  UNINITIALIZED = 3,
+  SYSTEM_ERROR = 4,
+  PERMISSION_DENIED = 6,
+  KEY_NOT_FOUND = 7,
+  VALUE_CORRUPTED = 8,
+  KEY_PERMANENTLY_INVALIDATED = 17,
+  BACKEND_BUSY = 18,
+  OPERATION_BUSY = 19,
+  INVALID_ARGUMENT = 20,
+  TOO_MUCH_DATA = 21,
+  /**
+   * @deprecated replaced by other OUT_OF_KEYS_* errors below
+   */
+  OUT_OF_KEYS = 22,
+  OUT_OF_KEYS_REQUIRES_SYSTEM_UPGRADE = 23,
+  OUT_OF_KEYS_PENDING_INTERNET_CONNECTIVITY = 24,
+  OUT_OF_KEYS_TRANSIENT_ERROR = 25,
+  OUT_OF_KEYS_PERMANENT_ERROR = 26,
+  GET_ATTESTATION_APPLICATION_ID_FAILED = 27,
+  INFO_NOT_AVAILABLE = 28,
+}
diff --git a/keystore2/aidl/android/system/keystore2/IKeystoreService.aidl b/keystore2/aidl/android/system/keystore2/IKeystoreService.aidl
index 666985c..886047d 100644
--- a/keystore2/aidl/android/system/keystore2/IKeystoreService.aidl
+++ b/keystore2/aidl/android/system/keystore2/IKeystoreService.aidl
@@ -255,7 +255,9 @@ interface IKeystoreService {
      *
      * o Tag::MODULE_HASH: returns the DER-encoded structure corresponding to the `Modules` schema
      *   described in the KeyMint HAL's KeyCreationResult.aidl. The SHA-256 hash of this encoded
-     *   structure is what's included with the tag in attestations.
+     *   structure is what's included with the tag in attestations. To ensure the returned encoded
+     *   structure is the one attested to, clients should verify its SHA-256 hash matches the one
+     *   in the attestation. Note that the returned structure can vary between boots.
      *
      * ## Error conditions
      * `ResponseCode::INVALID_ARGUMENT` if `tag` is not specified in the list above.
diff --git a/media/Android.bp b/media/Android.bp
index 500dbd6..87b6bc7 100644
--- a/media/Android.bp
+++ b/media/Android.bp
@@ -121,7 +121,7 @@ aidl_interface {
             min_sdk_version: "29",
             apex_available: [
                 "//apex_available:platform",
-                "com.android.btservices",
+                "com.android.bt",
             ],
         },
         rust: {
@@ -141,11 +141,15 @@ aidl_interface {
             version: "3",
             imports: [],
         },
+        {
+            version: "4",
+            imports: [],
+        },
 
         // IMPORTANT: Update latest_android_media_audio_common_types every time
         // you add the latest frozen version to versions_with_info
     ],
-    frozen: false,
+    frozen: true,
 
 }
 
@@ -276,9 +280,13 @@ aidl_interface {
             version: "2",
             imports: ["android.media.audio.common.types-V3"],
         },
+        {
+            version: "3",
+            imports: ["android.media.audio.common.types-V4"],
+        },
 
     ],
-    frozen: false,
+    frozen: true,
 
 }
 
@@ -386,7 +394,14 @@ aidl_interface {
     imports: [
         latest_android_media_audio_common_types,
     ],
-    frozen: false,
+    frozen: true,
+    versions_with_info: [
+        {
+            version: "1",
+            imports: ["android.media.audio.common.types-V4"],
+        },
+    ],
+
 }
 
 // Note: This should always be one version ahead of the last frozen version
diff --git a/media/aidl/android/media/audio/common/AudioChannelLayout.aidl b/media/aidl/android/media/audio/common/AudioChannelLayout.aidl
index 409e964..6f94823 100644
--- a/media/aidl/android/media/audio/common/AudioChannelLayout.aidl
+++ b/media/aidl/android/media/audio/common/AudioChannelLayout.aidl
@@ -153,11 +153,12 @@ union AudioChannelLayout {
             LAYOUT_7POINT1POINT4 | CHANNEL_FRONT_WIDE_LEFT | CHANNEL_FRONT_WIDE_RIGHT;
     const int LAYOUT_9POINT1POINT6 =
             LAYOUT_9POINT1POINT4 | CHANNEL_TOP_SIDE_LEFT | CHANNEL_TOP_SIDE_RIGHT;
-    const int LAYOUT_13POINT_360RA = CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT | CHANNEL_FRONT_CENTER
+    const int LAYOUT_13POINT0 = CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT | CHANNEL_FRONT_CENTER
             | CHANNEL_SIDE_LEFT | CHANNEL_SIDE_RIGHT | CHANNEL_TOP_FRONT_LEFT
             | CHANNEL_TOP_FRONT_RIGHT | CHANNEL_TOP_FRONT_CENTER | CHANNEL_TOP_BACK_LEFT
             | CHANNEL_TOP_BACK_RIGHT | CHANNEL_BOTTOM_FRONT_LEFT | CHANNEL_BOTTOM_FRONT_RIGHT
             | CHANNEL_BOTTOM_FRONT_CENTER;
+    const int LAYOUT_13POINT_360RA = LAYOUT_13POINT0;
     const int LAYOUT_22POINT2 = LAYOUT_7POINT1POINT4 | CHANNEL_FRONT_LEFT_OF_CENTER
             | CHANNEL_FRONT_RIGHT_OF_CENTER | CHANNEL_BACK_CENTER | CHANNEL_TOP_CENTER
             | CHANNEL_TOP_FRONT_CENTER | CHANNEL_TOP_BACK_CENTER | CHANNEL_TOP_SIDE_LEFT
diff --git a/media/aidl/android/media/audio/common/AudioPlaybackRate.aidl b/media/aidl/android/media/audio/common/AudioPlaybackRate.aidl
index 3dd474f..45921d5 100644
--- a/media/aidl/android/media/audio/common/AudioPlaybackRate.aidl
+++ b/media/aidl/android/media/audio/common/AudioPlaybackRate.aidl
@@ -71,9 +71,15 @@ parcelable AudioPlaybackRate {
         SYS_RESERVED_CUT_REPEAT = -1,
         /** Reserved for use by the framework. */
         SYS_RESERVED_DEFAULT = 0,
-        /** Play silence for parameter values that are out of range. */
+        /**
+         * If possible, play silence for parameter values that are out of range,
+         * otherwise return an error (same as 'FAIL' would return).
+         */
         MUTE = 1,
-        /** Return an error while trying to set the parameters. */
+        /**
+         * Always return an error while trying to set the parameters that are
+         * out of range.
+         */
         FAIL = 2,
     }
     /**
diff --git a/media/aidl_api/android.media.audio.common.types/4/.hash b/media/aidl_api/android.media.audio.common.types/4/.hash
new file mode 100644
index 0000000..21938ff
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/.hash
@@ -0,0 +1 @@
+af71e6ae2c6861fc2b09bb477e7285e6777cd41c
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioAttributes.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioAttributes.aidl
new file mode 100644
index 0000000..d52cbe5
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioAttributes.aidl
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioAttributes {
+  android.media.audio.common.AudioContentType contentType = android.media.audio.common.AudioContentType.UNKNOWN;
+  android.media.audio.common.AudioUsage usage = android.media.audio.common.AudioUsage.UNKNOWN;
+  android.media.audio.common.AudioSource source = android.media.audio.common.AudioSource.DEFAULT;
+  int flags = android.media.audio.common.AudioFlag.NONE /* 0 */;
+  @utf8InCpp String[] tags;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioChannelLayout.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioChannelLayout.aidl
new file mode 100644
index 0000000..c833f1c
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioChannelLayout.aidl
@@ -0,0 +1,135 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @SuppressWarnings(value={"redundant-name"}) @VintfStability
+union AudioChannelLayout {
+  int none = 0;
+  int invalid = 0;
+  int indexMask;
+  int layoutMask;
+  int voiceMask;
+  const int INDEX_MASK_1 = ((1 << 1) - 1) /* 1 */;
+  const int INDEX_MASK_2 = ((1 << 2) - 1) /* 3 */;
+  const int INDEX_MASK_3 = ((1 << 3) - 1) /* 7 */;
+  const int INDEX_MASK_4 = ((1 << 4) - 1) /* 15 */;
+  const int INDEX_MASK_5 = ((1 << 5) - 1) /* 31 */;
+  const int INDEX_MASK_6 = ((1 << 6) - 1) /* 63 */;
+  const int INDEX_MASK_7 = ((1 << 7) - 1) /* 127 */;
+  const int INDEX_MASK_8 = ((1 << 8) - 1) /* 255 */;
+  const int INDEX_MASK_9 = ((1 << 9) - 1) /* 511 */;
+  const int INDEX_MASK_10 = ((1 << 10) - 1) /* 1023 */;
+  const int INDEX_MASK_11 = ((1 << 11) - 1) /* 2047 */;
+  const int INDEX_MASK_12 = ((1 << 12) - 1) /* 4095 */;
+  const int INDEX_MASK_13 = ((1 << 13) - 1) /* 8191 */;
+  const int INDEX_MASK_14 = ((1 << 14) - 1) /* 16383 */;
+  const int INDEX_MASK_15 = ((1 << 15) - 1) /* 32767 */;
+  const int INDEX_MASK_16 = ((1 << 16) - 1) /* 65535 */;
+  const int INDEX_MASK_17 = ((1 << 17) - 1) /* 131071 */;
+  const int INDEX_MASK_18 = ((1 << 18) - 1) /* 262143 */;
+  const int INDEX_MASK_19 = ((1 << 19) - 1) /* 524287 */;
+  const int INDEX_MASK_20 = ((1 << 20) - 1) /* 1048575 */;
+  const int INDEX_MASK_21 = ((1 << 21) - 1) /* 2097151 */;
+  const int INDEX_MASK_22 = ((1 << 22) - 1) /* 4194303 */;
+  const int INDEX_MASK_23 = ((1 << 23) - 1) /* 8388607 */;
+  const int INDEX_MASK_24 = ((1 << 24) - 1) /* 16777215 */;
+  const int LAYOUT_MONO = CHANNEL_FRONT_LEFT /* 1 */;
+  const int LAYOUT_STEREO = (CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) /* 3 */;
+  const int LAYOUT_2POINT1 = ((CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) | CHANNEL_LOW_FREQUENCY) /* 11 */;
+  const int LAYOUT_TRI = ((CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) | CHANNEL_FRONT_CENTER) /* 7 */;
+  const int LAYOUT_TRI_BACK = ((CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) | CHANNEL_BACK_CENTER) /* 259 */;
+  const int LAYOUT_3POINT1 = (((CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) | CHANNEL_FRONT_CENTER) | CHANNEL_LOW_FREQUENCY) /* 15 */;
+  const int LAYOUT_2POINT0POINT2 = (((CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) | CHANNEL_TOP_SIDE_LEFT) | CHANNEL_TOP_SIDE_RIGHT) /* 786435 */;
+  const int LAYOUT_2POINT1POINT2 = (LAYOUT_2POINT0POINT2 | CHANNEL_LOW_FREQUENCY) /* 786443 */;
+  const int LAYOUT_3POINT0POINT2 = ((((CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) | CHANNEL_FRONT_CENTER) | CHANNEL_TOP_SIDE_LEFT) | CHANNEL_TOP_SIDE_RIGHT) /* 786439 */;
+  const int LAYOUT_3POINT1POINT2 = (LAYOUT_3POINT0POINT2 | CHANNEL_LOW_FREQUENCY) /* 786447 */;
+  const int LAYOUT_QUAD = (((CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) | CHANNEL_BACK_LEFT) | CHANNEL_BACK_RIGHT) /* 51 */;
+  const int LAYOUT_QUAD_SIDE = (((CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) | CHANNEL_SIDE_LEFT) | CHANNEL_SIDE_RIGHT) /* 1539 */;
+  const int LAYOUT_SURROUND = (((CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) | CHANNEL_FRONT_CENTER) | CHANNEL_BACK_CENTER) /* 263 */;
+  const int LAYOUT_PENTA = (LAYOUT_QUAD | CHANNEL_FRONT_CENTER) /* 55 */;
+  const int LAYOUT_5POINT1 = (((((CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) | CHANNEL_FRONT_CENTER) | CHANNEL_LOW_FREQUENCY) | CHANNEL_BACK_LEFT) | CHANNEL_BACK_RIGHT) /* 63 */;
+  const int LAYOUT_5POINT1_SIDE = (((((CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) | CHANNEL_FRONT_CENTER) | CHANNEL_LOW_FREQUENCY) | CHANNEL_SIDE_LEFT) | CHANNEL_SIDE_RIGHT) /* 1551 */;
+  const int LAYOUT_5POINT1POINT2 = ((LAYOUT_5POINT1 | CHANNEL_TOP_SIDE_LEFT) | CHANNEL_TOP_SIDE_RIGHT) /* 786495 */;
+  const int LAYOUT_5POINT1POINT4 = ((((LAYOUT_5POINT1 | CHANNEL_TOP_FRONT_LEFT) | CHANNEL_TOP_FRONT_RIGHT) | CHANNEL_TOP_BACK_LEFT) | CHANNEL_TOP_BACK_RIGHT) /* 184383 */;
+  const int LAYOUT_6POINT1 = ((((((CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) | CHANNEL_FRONT_CENTER) | CHANNEL_LOW_FREQUENCY) | CHANNEL_BACK_LEFT) | CHANNEL_BACK_RIGHT) | CHANNEL_BACK_CENTER) /* 319 */;
+  const int LAYOUT_7POINT1 = ((LAYOUT_5POINT1 | CHANNEL_SIDE_LEFT) | CHANNEL_SIDE_RIGHT) /* 1599 */;
+  const int LAYOUT_7POINT1POINT2 = ((LAYOUT_7POINT1 | CHANNEL_TOP_SIDE_LEFT) | CHANNEL_TOP_SIDE_RIGHT) /* 788031 */;
+  const int LAYOUT_7POINT1POINT4 = ((((LAYOUT_7POINT1 | CHANNEL_TOP_FRONT_LEFT) | CHANNEL_TOP_FRONT_RIGHT) | CHANNEL_TOP_BACK_LEFT) | CHANNEL_TOP_BACK_RIGHT) /* 185919 */;
+  const int LAYOUT_9POINT1POINT4 = ((LAYOUT_7POINT1POINT4 | CHANNEL_FRONT_WIDE_LEFT) | CHANNEL_FRONT_WIDE_RIGHT) /* 50517567 */;
+  const int LAYOUT_9POINT1POINT6 = ((LAYOUT_9POINT1POINT4 | CHANNEL_TOP_SIDE_LEFT) | CHANNEL_TOP_SIDE_RIGHT) /* 51303999 */;
+  const int LAYOUT_13POINT0 = ((((((((((((CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) | CHANNEL_FRONT_CENTER) | CHANNEL_SIDE_LEFT) | CHANNEL_SIDE_RIGHT) | CHANNEL_TOP_FRONT_LEFT) | CHANNEL_TOP_FRONT_RIGHT) | CHANNEL_TOP_FRONT_CENTER) | CHANNEL_TOP_BACK_LEFT) | CHANNEL_TOP_BACK_RIGHT) | CHANNEL_BOTTOM_FRONT_LEFT) | CHANNEL_BOTTOM_FRONT_RIGHT) | CHANNEL_BOTTOM_FRONT_CENTER) /* 7534087 */;
+  const int LAYOUT_13POINT_360RA = LAYOUT_13POINT0 /* 7534087 */;
+  const int LAYOUT_22POINT2 = ((((((((((((LAYOUT_7POINT1POINT4 | CHANNEL_FRONT_LEFT_OF_CENTER) | CHANNEL_FRONT_RIGHT_OF_CENTER) | CHANNEL_BACK_CENTER) | CHANNEL_TOP_CENTER) | CHANNEL_TOP_FRONT_CENTER) | CHANNEL_TOP_BACK_CENTER) | CHANNEL_TOP_SIDE_LEFT) | CHANNEL_TOP_SIDE_RIGHT) | CHANNEL_BOTTOM_FRONT_LEFT) | CHANNEL_BOTTOM_FRONT_RIGHT) | CHANNEL_BOTTOM_FRONT_CENTER) | CHANNEL_LOW_FREQUENCY_2) /* 16777215 */;
+  const int LAYOUT_MONO_HAPTIC_A = (LAYOUT_MONO | CHANNEL_HAPTIC_A) /* 1073741825 */;
+  const int LAYOUT_STEREO_HAPTIC_A = (LAYOUT_STEREO | CHANNEL_HAPTIC_A) /* 1073741827 */;
+  const int LAYOUT_HAPTIC_AB = (CHANNEL_HAPTIC_A | CHANNEL_HAPTIC_B) /* 1610612736 */;
+  const int LAYOUT_MONO_HAPTIC_AB = (LAYOUT_MONO | LAYOUT_HAPTIC_AB) /* 1610612737 */;
+  const int LAYOUT_STEREO_HAPTIC_AB = (LAYOUT_STEREO | LAYOUT_HAPTIC_AB) /* 1610612739 */;
+  const int LAYOUT_FRONT_BACK = (CHANNEL_FRONT_CENTER | CHANNEL_BACK_CENTER) /* 260 */;
+  const int INTERLEAVE_LEFT = 0;
+  const int INTERLEAVE_RIGHT = 1;
+  const int CHANNEL_FRONT_LEFT = (1 << 0) /* 1 */;
+  const int CHANNEL_FRONT_RIGHT = (1 << 1) /* 2 */;
+  const int CHANNEL_FRONT_CENTER = (1 << 2) /* 4 */;
+  const int CHANNEL_LOW_FREQUENCY = (1 << 3) /* 8 */;
+  const int CHANNEL_BACK_LEFT = (1 << 4) /* 16 */;
+  const int CHANNEL_BACK_RIGHT = (1 << 5) /* 32 */;
+  const int CHANNEL_FRONT_LEFT_OF_CENTER = (1 << 6) /* 64 */;
+  const int CHANNEL_FRONT_RIGHT_OF_CENTER = (1 << 7) /* 128 */;
+  const int CHANNEL_BACK_CENTER = (1 << 8) /* 256 */;
+  const int CHANNEL_SIDE_LEFT = (1 << 9) /* 512 */;
+  const int CHANNEL_SIDE_RIGHT = (1 << 10) /* 1024 */;
+  const int CHANNEL_TOP_CENTER = (1 << 11) /* 2048 */;
+  const int CHANNEL_TOP_FRONT_LEFT = (1 << 12) /* 4096 */;
+  const int CHANNEL_TOP_FRONT_CENTER = (1 << 13) /* 8192 */;
+  const int CHANNEL_TOP_FRONT_RIGHT = (1 << 14) /* 16384 */;
+  const int CHANNEL_TOP_BACK_LEFT = (1 << 15) /* 32768 */;
+  const int CHANNEL_TOP_BACK_CENTER = (1 << 16) /* 65536 */;
+  const int CHANNEL_TOP_BACK_RIGHT = (1 << 17) /* 131072 */;
+  const int CHANNEL_TOP_SIDE_LEFT = (1 << 18) /* 262144 */;
+  const int CHANNEL_TOP_SIDE_RIGHT = (1 << 19) /* 524288 */;
+  const int CHANNEL_BOTTOM_FRONT_LEFT = (1 << 20) /* 1048576 */;
+  const int CHANNEL_BOTTOM_FRONT_CENTER = (1 << 21) /* 2097152 */;
+  const int CHANNEL_BOTTOM_FRONT_RIGHT = (1 << 22) /* 4194304 */;
+  const int CHANNEL_LOW_FREQUENCY_2 = (1 << 23) /* 8388608 */;
+  const int CHANNEL_FRONT_WIDE_LEFT = (1 << 24) /* 16777216 */;
+  const int CHANNEL_FRONT_WIDE_RIGHT = (1 << 25) /* 33554432 */;
+  const int CHANNEL_HAPTIC_B = (1 << 29) /* 536870912 */;
+  const int CHANNEL_HAPTIC_A = (1 << 30) /* 1073741824 */;
+  const int VOICE_UPLINK_MONO = CHANNEL_VOICE_UPLINK /* 16384 */;
+  const int VOICE_DNLINK_MONO = CHANNEL_VOICE_DNLINK /* 32768 */;
+  const int VOICE_CALL_MONO = (CHANNEL_VOICE_UPLINK | CHANNEL_VOICE_DNLINK) /* 49152 */;
+  const int CHANNEL_VOICE_UPLINK = 0x4000;
+  const int CHANNEL_VOICE_DNLINK = 0x8000;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioConfig.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioConfig.aidl
new file mode 100644
index 0000000..6b8686c
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioConfig.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioConfig {
+  android.media.audio.common.AudioConfigBase base;
+  android.media.audio.common.AudioOffloadInfo offloadInfo;
+  long frameCount;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioConfigBase.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioConfigBase.aidl
new file mode 100644
index 0000000..f3e716b
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioConfigBase.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioConfigBase {
+  int sampleRate;
+  android.media.audio.common.AudioChannelLayout channelMask;
+  android.media.audio.common.AudioFormatDescription format;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioContentType.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioContentType.aidl
new file mode 100644
index 0000000..f9ac614
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioContentType.aidl
@@ -0,0 +1,44 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum AudioContentType {
+  UNKNOWN = 0,
+  SPEECH = 1,
+  MUSIC = 2,
+  MOVIE = 3,
+  SONIFICATION = 4,
+  ULTRASOUND = 1997,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioDevice.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioDevice.aidl
new file mode 100644
index 0000000..fb5cb62
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioDevice.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioDevice {
+  android.media.audio.common.AudioDeviceDescription type;
+  android.media.audio.common.AudioDeviceAddress address;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioDeviceAddress.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioDeviceAddress.aidl
new file mode 100644
index 0000000..905d3aa
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioDeviceAddress.aidl
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+union AudioDeviceAddress {
+  @utf8InCpp String id;
+  byte[] mac;
+  byte[] ipv4;
+  int[] ipv6;
+  int[] alsa;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioDeviceDescription.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioDeviceDescription.aidl
new file mode 100644
index 0000000..d1bcfed
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioDeviceDescription.aidl
@@ -0,0 +1,56 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioDeviceDescription {
+  android.media.audio.common.AudioDeviceType type = android.media.audio.common.AudioDeviceType.NONE;
+  @utf8InCpp String connection;
+  const @utf8InCpp String CONNECTION_ANALOG = "analog";
+  const @utf8InCpp String CONNECTION_BT_A2DP = "bt-a2dp";
+  const @utf8InCpp String CONNECTION_BT_LE = "bt-le";
+  const @utf8InCpp String CONNECTION_BT_SCO = "bt-sco";
+  /**
+   * @deprecated Bus devices are attached, and must be represented using `{IN|OUT}_BUS` type + empty connection. Bus connection. Mostly used in automotive scenarios.
+   */
+  const @utf8InCpp String CONNECTION_BUS = "bus";
+  const @utf8InCpp String CONNECTION_HDMI = "hdmi";
+  const @utf8InCpp String CONNECTION_HDMI_ARC = "hdmi-arc";
+  const @utf8InCpp String CONNECTION_HDMI_EARC = "hdmi-earc";
+  const @utf8InCpp String CONNECTION_IP_V4 = "ip-v4";
+  const @utf8InCpp String CONNECTION_SPDIF = "spdif";
+  const @utf8InCpp String CONNECTION_WIRELESS = "wireless";
+  const @utf8InCpp String CONNECTION_USB = "usb";
+  const @utf8InCpp String CONNECTION_VIRTUAL = "virtual";
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioDeviceType.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioDeviceType.aidl
new file mode 100644
index 0000000..f31a707
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioDeviceType.aidl
@@ -0,0 +1,74 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @SuppressWarnings(value={"redundant-name"}) @VintfStability
+enum AudioDeviceType {
+  NONE = 0,
+  IN_DEFAULT = 1,
+  IN_ACCESSORY = 2,
+  IN_AFE_PROXY = 3,
+  IN_DEVICE = 4,
+  IN_ECHO_REFERENCE = 5,
+  IN_FM_TUNER = 6,
+  IN_HEADSET = 7,
+  IN_LOOPBACK = 8,
+  IN_MICROPHONE = 9,
+  IN_MICROPHONE_BACK = 10,
+  IN_SUBMIX = 11,
+  IN_TELEPHONY_RX = 12,
+  IN_TV_TUNER = 13,
+  IN_DOCK = 14,
+  IN_BUS = IN_DEVICE /* 4 */,
+  OUT_DEFAULT = 129,
+  OUT_ACCESSORY = 130,
+  OUT_AFE_PROXY = 131,
+  OUT_CARKIT = 132,
+  OUT_DEVICE = 133,
+  OUT_ECHO_CANCELLER = 134,
+  OUT_FM = 135,
+  OUT_HEADPHONE = 136,
+  OUT_HEADSET = 137,
+  OUT_HEARING_AID = 138,
+  OUT_LINE_AUX = 139,
+  OUT_SPEAKER = 140,
+  OUT_SPEAKER_EARPIECE = 141,
+  OUT_SPEAKER_SAFE = 142,
+  OUT_SUBMIX = 143,
+  OUT_TELEPHONY_TX = 144,
+  OUT_DOCK = 145,
+  OUT_BROADCAST = 146,
+  OUT_BUS = OUT_DEVICE /* 133 */,
+  OUT_MULTICHANNEL_GROUP = 147,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioDualMonoMode.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioDualMonoMode.aidl
new file mode 100644
index 0000000..77773f0
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioDualMonoMode.aidl
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum AudioDualMonoMode {
+  OFF = 0,
+  LR = 1,
+  LL = 2,
+  RR = 3,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioEncapsulationMetadataType.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioEncapsulationMetadataType.aidl
new file mode 100644
index 0000000..0ee0dbb
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioEncapsulationMetadataType.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum AudioEncapsulationMetadataType {
+  NONE = 0,
+  FRAMEWORK_TUNER = 1,
+  DVB_AD_DESCRIPTOR = 2,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioEncapsulationMode.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioEncapsulationMode.aidl
new file mode 100644
index 0000000..0747dba
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioEncapsulationMode.aidl
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="byte") @VintfStability
+enum AudioEncapsulationMode {
+  INVALID = (-1) /* -1 */,
+  NONE = 0,
+  ELEMENTARY_STREAM = 1,
+  HANDLE = 2,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioEncapsulationType.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioEncapsulationType.aidl
new file mode 100644
index 0000000..ed58fcf
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioEncapsulationType.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum AudioEncapsulationType {
+  NONE = 0,
+  IEC61937 = 1,
+  PCM = 2,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioFlag.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioFlag.aidl
new file mode 100644
index 0000000..1c8cbf5
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioFlag.aidl
@@ -0,0 +1,55 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum AudioFlag {
+  NONE = 0x0,
+  AUDIBILITY_ENFORCED = (0x1 << 0) /* 1 */,
+  SCO = (0x1 << 2) /* 4 */,
+  BEACON = (0x1 << 3) /* 8 */,
+  HW_AV_SYNC = (0x1 << 4) /* 16 */,
+  HW_HOTWORD = (0x1 << 5) /* 32 */,
+  BYPASS_INTERRUPTION_POLICY = (0x1 << 6) /* 64 */,
+  BYPASS_MUTE = (0x1 << 7) /* 128 */,
+  LOW_LATENCY = (0x1 << 8) /* 256 */,
+  DEEP_BUFFER = (0x1 << 9) /* 512 */,
+  NO_MEDIA_PROJECTION = (0x1 << 10) /* 1024 */,
+  MUTE_HAPTIC = (0x1 << 11) /* 2048 */,
+  NO_SYSTEM_CAPTURE = (0x1 << 12) /* 4096 */,
+  CAPTURE_PRIVATE = (0x1 << 13) /* 8192 */,
+  CONTENT_SPATIALIZED = (0x1 << 14) /* 16384 */,
+  NEVER_SPATIALIZE = (0x1 << 15) /* 32768 */,
+  CALL_REDIRECTION = (0x1 << 16) /* 65536 */,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioFormatDescription.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioFormatDescription.aidl
new file mode 100644
index 0000000..58c75eb
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioFormatDescription.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioFormatDescription {
+  android.media.audio.common.AudioFormatType type = android.media.audio.common.AudioFormatType.DEFAULT;
+  android.media.audio.common.PcmType pcm = android.media.audio.common.PcmType.DEFAULT;
+  @utf8InCpp String encoding;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioFormatType.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioFormatType.aidl
new file mode 100644
index 0000000..e60794f
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioFormatType.aidl
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="byte") @VintfStability
+enum AudioFormatType {
+  DEFAULT = 0,
+  NON_PCM = DEFAULT /* 0 */,
+  PCM = 1,
+  SYS_RESERVED_INVALID = (-1) /* -1 */,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioGain.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioGain.aidl
new file mode 100644
index 0000000..adc5b67
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioGain.aidl
@@ -0,0 +1,47 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioGain {
+  int mode;
+  android.media.audio.common.AudioChannelLayout channelMask;
+  int minValue;
+  int maxValue;
+  int defaultValue;
+  int stepValue;
+  int minRampMs;
+  int maxRampMs;
+  boolean useForVolume;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioGainConfig.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioGainConfig.aidl
new file mode 100644
index 0000000..01877c7
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioGainConfig.aidl
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioGainConfig {
+  int index;
+  int mode;
+  android.media.audio.common.AudioChannelLayout channelMask;
+  int[] values;
+  int rampDurationMs;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioGainMode.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioGainMode.aidl
new file mode 100644
index 0000000..fddc20c
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioGainMode.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="byte") @VintfStability
+enum AudioGainMode {
+  JOINT = 0,
+  CHANNELS = 1,
+  RAMP = 2,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalAttributesGroup.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalAttributesGroup.aidl
new file mode 100644
index 0000000..1062bdb
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalAttributesGroup.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioHalAttributesGroup {
+  android.media.audio.common.AudioStreamType streamType = android.media.audio.common.AudioStreamType.INVALID;
+  @utf8InCpp String volumeGroupName;
+  android.media.audio.common.AudioAttributes[] attributes;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapConfiguration.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapConfiguration.aidl
new file mode 100644
index 0000000..255b10a
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapConfiguration.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioHalCapConfiguration {
+  @utf8InCpp String name;
+  android.media.audio.common.AudioHalCapRule rule;
+  android.media.audio.common.AudioHalCapParameter[] parameterSettings;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapCriterion.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapCriterion.aidl
new file mode 100644
index 0000000..3b00031
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapCriterion.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioHalCapCriterion {
+  @utf8InCpp String name;
+  @utf8InCpp String criterionTypeName;
+  @utf8InCpp String defaultLiteralValue;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapCriterionType.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapCriterionType.aidl
new file mode 100644
index 0000000..1245761
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapCriterionType.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioHalCapCriterionType {
+  @utf8InCpp String name;
+  boolean isInclusive;
+  @utf8InCpp String[] values;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapCriterionV2.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapCriterionV2.aidl
new file mode 100644
index 0000000..b5ceee3
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapCriterionV2.aidl
@@ -0,0 +1,71 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@VintfStability
+union AudioHalCapCriterionV2 {
+  android.media.audio.common.AudioHalCapCriterionV2.AvailableDevices availableInputDevices;
+  android.media.audio.common.AudioHalCapCriterionV2.AvailableDevices availableOutputDevices;
+  android.media.audio.common.AudioHalCapCriterionV2.AvailableDevicesAddresses availableInputDevicesAddresses;
+  android.media.audio.common.AudioHalCapCriterionV2.AvailableDevicesAddresses availableOutputDevicesAddresses;
+  android.media.audio.common.AudioHalCapCriterionV2.TelephonyMode telephonyMode;
+  android.media.audio.common.AudioHalCapCriterionV2.ForceConfigForUse forceConfigForUse;
+  @Backing(type="byte") @VintfStability
+  enum LogicalDisjunction {
+    EXCLUSIVE = 0,
+    INCLUSIVE,
+  }
+  @VintfStability
+  parcelable ForceConfigForUse {
+    android.media.audio.common.AudioPolicyForceUse[] values;
+    android.media.audio.common.AudioPolicyForceUse defaultValue;
+    android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction logic = android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction.EXCLUSIVE;
+  }
+  @VintfStability
+  parcelable TelephonyMode {
+    android.media.audio.common.AudioMode[] values;
+    android.media.audio.common.AudioMode defaultValue = android.media.audio.common.AudioMode.NORMAL;
+    android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction logic = android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction.EXCLUSIVE;
+  }
+  @VintfStability
+  parcelable AvailableDevices {
+    android.media.audio.common.AudioDeviceDescription[] values;
+    android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction logic = android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction.INCLUSIVE;
+  }
+  @VintfStability
+  parcelable AvailableDevicesAddresses {
+    android.media.audio.common.AudioDeviceAddress[] values;
+    android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction logic = android.media.audio.common.AudioHalCapCriterionV2.LogicalDisjunction.INCLUSIVE;
+  }
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapDomain.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapDomain.aidl
new file mode 100644
index 0000000..9c20abe
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapDomain.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioHalCapDomain {
+  @utf8InCpp String name;
+  android.media.audio.common.AudioHalCapConfiguration[] configurations;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapParameter.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapParameter.aidl
new file mode 100644
index 0000000..c0b1a72
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapParameter.aidl
@@ -0,0 +1,64 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@VintfStability
+union AudioHalCapParameter {
+  android.media.audio.common.AudioHalCapParameter.StrategyDevice selectedStrategyDevice;
+  android.media.audio.common.AudioHalCapParameter.InputSourceDevice selectedInputSourceDevice;
+  android.media.audio.common.AudioHalCapParameter.StrategyDeviceAddress strategyDeviceAddress;
+  android.media.audio.common.AudioHalCapParameter.StreamVolumeProfile streamVolumeProfile;
+  @VintfStability
+  parcelable StrategyDevice {
+    android.media.audio.common.AudioDeviceDescription device;
+    int id = android.media.audio.common.AudioProductStrategyType.SYS_RESERVED_NONE /* -1 */;
+    boolean isSelected;
+  }
+  @VintfStability
+  parcelable InputSourceDevice {
+    android.media.audio.common.AudioDeviceDescription device;
+    android.media.audio.common.AudioSource inputSource = android.media.audio.common.AudioSource.DEFAULT;
+    boolean isSelected;
+  }
+  @VintfStability
+  parcelable StrategyDeviceAddress {
+    android.media.audio.common.AudioDeviceAddress deviceAddress;
+    int id = android.media.audio.common.AudioProductStrategyType.SYS_RESERVED_NONE /* -1 */;
+  }
+  @VintfStability
+  parcelable StreamVolumeProfile {
+    android.media.audio.common.AudioStreamType stream = android.media.audio.common.AudioStreamType.INVALID;
+    android.media.audio.common.AudioStreamType profile = android.media.audio.common.AudioStreamType.INVALID;
+  }
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapRule.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapRule.aidl
new file mode 100644
index 0000000..e106050
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalCapRule.aidl
@@ -0,0 +1,60 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioHalCapRule {
+  android.media.audio.common.AudioHalCapRule.CompoundRule compoundRule = android.media.audio.common.AudioHalCapRule.CompoundRule.INVALID;
+  android.media.audio.common.AudioHalCapRule.CriterionRule[] criterionRules;
+  android.media.audio.common.AudioHalCapRule[] nestedRules;
+  @VintfStability
+  enum CompoundRule {
+    INVALID = 0,
+    ANY,
+    ALL,
+  }
+  @VintfStability
+  enum MatchingRule {
+    INVALID = (-1) /* -1 */,
+    IS = 0,
+    IS_NOT,
+    INCLUDES,
+    EXCLUDES,
+  }
+  @VintfStability
+  parcelable CriterionRule {
+    android.media.audio.common.AudioHalCapRule.MatchingRule matchingRule = android.media.audio.common.AudioHalCapRule.MatchingRule.INVALID;
+    android.media.audio.common.AudioHalCapCriterionV2 criterionAndValue;
+  }
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalEngineConfig.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalEngineConfig.aidl
new file mode 100644
index 0000000..bc856da
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalEngineConfig.aidl
@@ -0,0 +1,49 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioHalEngineConfig {
+  int defaultProductStrategyId = android.media.audio.common.AudioProductStrategyType.SYS_RESERVED_NONE /* -1 */;
+  android.media.audio.common.AudioHalProductStrategy[] productStrategies;
+  android.media.audio.common.AudioHalVolumeGroup[] volumeGroups;
+  @nullable android.media.audio.common.AudioHalEngineConfig.CapSpecificConfig capSpecificConfig;
+  @VintfStability
+  parcelable CapSpecificConfig {
+    android.media.audio.common.AudioHalCapCriterion[] criteria;
+    android.media.audio.common.AudioHalCapCriterionType[] criterionTypes;
+    @nullable android.media.audio.common.AudioHalCapCriterionV2[] criteriaV2;
+    @nullable android.media.audio.common.AudioHalCapDomain[] domains;
+  }
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalProductStrategy.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalProductStrategy.aidl
new file mode 100644
index 0000000..9878e37
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalProductStrategy.aidl
@@ -0,0 +1,47 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @SuppressWarnings(value={"redundant-name"}) @VintfStability
+parcelable AudioHalProductStrategy {
+  int id = android.media.audio.common.AudioProductStrategyType.SYS_RESERVED_NONE /* -1 */;
+  android.media.audio.common.AudioHalAttributesGroup[] attributesGroups;
+  @nullable @utf8InCpp String name;
+  int zoneId = android.media.audio.common.AudioHalProductStrategy.ZoneId.DEFAULT /* 0 */;
+  const int VENDOR_STRATEGY_ID_START = 1000;
+  @Backing(type="int") @VintfStability
+  enum ZoneId {
+    DEFAULT = 0,
+  }
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalVolumeCurve.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalVolumeCurve.aidl
new file mode 100644
index 0000000..bcc7324
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalVolumeCurve.aidl
@@ -0,0 +1,55 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioHalVolumeCurve {
+  android.media.audio.common.AudioHalVolumeCurve.DeviceCategory deviceCategory = android.media.audio.common.AudioHalVolumeCurve.DeviceCategory.SPEAKER;
+  android.media.audio.common.AudioHalVolumeCurve.CurvePoint[] curvePoints;
+  @Backing(type="byte") @VintfStability
+  enum DeviceCategory {
+    HEADSET = 0,
+    SPEAKER = 1,
+    EARPIECE = 2,
+    EXT_MEDIA = 3,
+    HEARING_AID = 4,
+  }
+  @VintfStability
+  parcelable CurvePoint {
+    byte index;
+    int attenuationMb;
+    const byte MIN_INDEX = 0;
+    const byte MAX_INDEX = 100;
+  }
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalVolumeGroup.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalVolumeGroup.aidl
new file mode 100644
index 0000000..f741e69
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioHalVolumeGroup.aidl
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @SuppressWarnings(value={"redundant-name"}) @VintfStability
+parcelable AudioHalVolumeGroup {
+  @utf8InCpp String name;
+  int minIndex;
+  int maxIndex;
+  android.media.audio.common.AudioHalVolumeCurve[] volumeCurves;
+  const int INDEX_DEFERRED_TO_AUDIO_SERVICE = (-1) /* -1 */;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioInputFlags.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioInputFlags.aidl
new file mode 100644
index 0000000..e6a57e9
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioInputFlags.aidl
@@ -0,0 +1,49 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum AudioInputFlags {
+  FAST = 0,
+  HW_HOTWORD = 1,
+  RAW = 2,
+  SYNC = 3,
+  MMAP_NOIRQ = 4,
+  VOIP_TX = 5,
+  HW_AV_SYNC = 6,
+  DIRECT = 7,
+  ULTRASOUND = 8,
+  HOTWORD_TAP = 9,
+  HW_LOOKBACK = 10,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioIoFlags.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioIoFlags.aidl
new file mode 100644
index 0000000..4a46725
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioIoFlags.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+union AudioIoFlags {
+  int input;
+  int output;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioLatencyMode.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioLatencyMode.aidl
new file mode 100644
index 0000000..f6949d2
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioLatencyMode.aidl
@@ -0,0 +1,42 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="byte") @SuppressWarnings(value={"redundant-name"}) @VintfStability
+enum AudioLatencyMode {
+  FREE = 0,
+  LOW = 1,
+  DYNAMIC_SPATIAL_AUDIO_SOFTWARE = 2,
+  DYNAMIC_SPATIAL_AUDIO_HARDWARE = 3,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioMMapPolicy.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioMMapPolicy.aidl
new file mode 100644
index 0000000..98bf0e5
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioMMapPolicy.aidl
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum AudioMMapPolicy {
+  UNSPECIFIED = 0,
+  NEVER = 1,
+  AUTO = 2,
+  ALWAYS = 3,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioMMapPolicyInfo.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioMMapPolicyInfo.aidl
new file mode 100644
index 0000000..7c4f75e
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioMMapPolicyInfo.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioMMapPolicyInfo {
+  android.media.audio.common.AudioDevice device;
+  android.media.audio.common.AudioMMapPolicy mmapPolicy = android.media.audio.common.AudioMMapPolicy.UNSPECIFIED;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioMMapPolicyType.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioMMapPolicyType.aidl
new file mode 100644
index 0000000..efe8826
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioMMapPolicyType.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum AudioMMapPolicyType {
+  DEFAULT = 1,
+  EXCLUSIVE = 2,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioMode.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioMode.aidl
new file mode 100644
index 0000000..1b4cdc4
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioMode.aidl
@@ -0,0 +1,47 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum AudioMode {
+  SYS_RESERVED_INVALID = (-2) /* -2 */,
+  SYS_RESERVED_CURRENT = (-1) /* -1 */,
+  NORMAL = 0,
+  RINGTONE = 1,
+  IN_CALL = 2,
+  IN_COMMUNICATION = 3,
+  CALL_SCREEN = 4,
+  SYS_RESERVED_CALL_REDIRECT = 5,
+  SYS_RESERVED_COMMUNICATION_REDIRECT = 6,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioOffloadInfo.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioOffloadInfo.aidl
new file mode 100644
index 0000000..40bd53b
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioOffloadInfo.aidl
@@ -0,0 +1,50 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioOffloadInfo {
+  android.media.audio.common.AudioConfigBase base;
+  android.media.audio.common.AudioStreamType streamType = android.media.audio.common.AudioStreamType.INVALID;
+  int bitRatePerSecond;
+  long durationUs;
+  boolean hasVideo;
+  boolean isStreaming;
+  int bitWidth = 16;
+  int offloadBufferSize;
+  android.media.audio.common.AudioUsage usage = android.media.audio.common.AudioUsage.INVALID;
+  android.media.audio.common.AudioEncapsulationMode encapsulationMode = android.media.audio.common.AudioEncapsulationMode.INVALID;
+  int contentId;
+  int syncId;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioOutputFlags.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioOutputFlags.aidl
new file mode 100644
index 0000000..268e635
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioOutputFlags.aidl
@@ -0,0 +1,57 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum AudioOutputFlags {
+  DIRECT = 0,
+  PRIMARY = 1,
+  FAST = 2,
+  DEEP_BUFFER = 3,
+  COMPRESS_OFFLOAD = 4,
+  NON_BLOCKING = 5,
+  HW_AV_SYNC = 6,
+  TTS = 7,
+  RAW = 8,
+  SYNC = 9,
+  IEC958_NONAUDIO = 10,
+  DIRECT_PCM = 11,
+  MMAP_NOIRQ = 12,
+  VOIP_RX = 13,
+  INCALL_MUSIC = 14,
+  GAPLESS_OFFLOAD = 15,
+  SPATIALIZER = 16,
+  ULTRASOUND = 17,
+  BIT_PERFECT = 18,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPlaybackRate.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPlaybackRate.aidl
new file mode 100644
index 0000000..310b2af
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPlaybackRate.aidl
@@ -0,0 +1,54 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioPlaybackRate {
+  float speed;
+  float pitch;
+  android.media.audio.common.AudioPlaybackRate.TimestretchMode timestretchMode = android.media.audio.common.AudioPlaybackRate.TimestretchMode.DEFAULT;
+  android.media.audio.common.AudioPlaybackRate.TimestretchFallbackMode fallbackMode = android.media.audio.common.AudioPlaybackRate.TimestretchFallbackMode.SYS_RESERVED_DEFAULT;
+  @Backing(type="int") @VintfStability
+  enum TimestretchMode {
+    DEFAULT = 0,
+    VOICE = 1,
+  }
+  @Backing(type="int") @VintfStability
+  enum TimestretchFallbackMode {
+    SYS_RESERVED_CUT_REPEAT = (-1) /* -1 */,
+    SYS_RESERVED_DEFAULT = 0,
+    MUTE = 1,
+    FAIL = 2,
+  }
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPolicyForceUse.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPolicyForceUse.aidl
new file mode 100644
index 0000000..eb883e9
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPolicyForceUse.aidl
@@ -0,0 +1,81 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@SuppressWarnings(value={"redundant-name"}) @VintfStability
+union AudioPolicyForceUse {
+  android.media.audio.common.AudioPolicyForceUse.MediaDeviceCategory forMedia = android.media.audio.common.AudioPolicyForceUse.MediaDeviceCategory.NONE;
+  android.media.audio.common.AudioPolicyForceUse.CommunicationDeviceCategory forCommunication = android.media.audio.common.AudioPolicyForceUse.CommunicationDeviceCategory.NONE;
+  android.media.audio.common.AudioPolicyForceUse.CommunicationDeviceCategory forRecord = android.media.audio.common.AudioPolicyForceUse.CommunicationDeviceCategory.NONE;
+  android.media.audio.common.AudioPolicyForceUse.CommunicationDeviceCategory forVibrateRinging = android.media.audio.common.AudioPolicyForceUse.CommunicationDeviceCategory.NONE;
+  android.media.audio.common.AudioPolicyForceUse.DockType dock = android.media.audio.common.AudioPolicyForceUse.DockType.NONE;
+  boolean systemSounds = false;
+  boolean hdmiSystemAudio = false;
+  android.media.audio.common.AudioPolicyForceUse.EncodedSurroundConfig encodedSurround = android.media.audio.common.AudioPolicyForceUse.EncodedSurroundConfig.UNSPECIFIED;
+  @Backing(type="byte") @VintfStability
+  enum CommunicationDeviceCategory {
+    NONE = 0,
+    SPEAKER,
+    BT_SCO,
+    BT_BLE,
+    WIRED_ACCESSORY,
+  }
+  @Backing(type="byte") @VintfStability
+  enum MediaDeviceCategory {
+    NONE = 0,
+    SPEAKER,
+    HEADPHONES,
+    BT_A2DP,
+    ANALOG_DOCK,
+    DIGITAL_DOCK,
+    WIRED_ACCESSORY,
+    NO_BT_A2DP,
+  }
+  @Backing(type="byte") @VintfStability
+  enum DockType {
+    NONE = 0,
+    BT_CAR_DOCK,
+    BT_DESK_DOCK,
+    ANALOG_DOCK,
+    DIGITAL_DOCK,
+    WIRED_ACCESSORY,
+  }
+  @Backing(type="byte") @VintfStability
+  enum EncodedSurroundConfig {
+    UNSPECIFIED = 0,
+    NEVER,
+    ALWAYS,
+    MANUAL,
+  }
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPort.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPort.aidl
new file mode 100644
index 0000000..970bbc0
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPort.aidl
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioPort {
+  int id;
+  @utf8InCpp String name;
+  android.media.audio.common.AudioProfile[] profiles;
+  android.media.audio.common.AudioIoFlags flags;
+  android.media.audio.common.ExtraAudioDescriptor[] extraAudioDescriptors;
+  android.media.audio.common.AudioGain[] gains;
+  android.media.audio.common.AudioPortExt ext;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPortConfig.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPortConfig.aidl
new file mode 100644
index 0000000..18e6406
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPortConfig.aidl
@@ -0,0 +1,46 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioPortConfig {
+  int id;
+  int portId;
+  @nullable android.media.audio.common.Int sampleRate;
+  @nullable android.media.audio.common.AudioChannelLayout channelMask;
+  @nullable android.media.audio.common.AudioFormatDescription format;
+  @nullable android.media.audio.common.AudioGainConfig gain;
+  @nullable android.media.audio.common.AudioIoFlags flags;
+  android.media.audio.common.AudioPortExt ext;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPortDeviceExt.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPortDeviceExt.aidl
new file mode 100644
index 0000000..2b3e72c
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPortDeviceExt.aidl
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @SuppressWarnings(value={"redundant-name"}) @VintfStability
+parcelable AudioPortDeviceExt {
+  android.media.audio.common.AudioDevice device;
+  int flags;
+  android.media.audio.common.AudioFormatDescription[] encodedFormats;
+  int encapsulationModes;
+  int encapsulationMetadataTypes;
+  @nullable android.media.audio.common.AudioChannelLayout speakerLayout;
+  const int FLAG_INDEX_DEFAULT_DEVICE = 0;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPortExt.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPortExt.aidl
new file mode 100644
index 0000000..af9d9c4
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPortExt.aidl
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+union AudioPortExt {
+  boolean unspecified;
+  android.media.audio.common.AudioPortDeviceExt device;
+  android.media.audio.common.AudioPortMixExt mix;
+  int session;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPortMixExt.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPortMixExt.aidl
new file mode 100644
index 0000000..5b74c0d
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPortMixExt.aidl
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioPortMixExt {
+  int handle;
+  android.media.audio.common.AudioPortMixExtUseCase usecase;
+  int maxOpenStreamCount;
+  int maxActiveStreamCount;
+  int recommendedMuteDurationMs;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPortMixExtUseCase.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPortMixExtUseCase.aidl
new file mode 100644
index 0000000..e9acb40
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioPortMixExtUseCase.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+union AudioPortMixExtUseCase {
+  boolean unspecified;
+  android.media.audio.common.AudioStreamType stream;
+  android.media.audio.common.AudioSource source;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioProductStrategyType.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioProductStrategyType.aidl
new file mode 100644
index 0000000..ba59d40
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioProductStrategyType.aidl
@@ -0,0 +1,49 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="byte") @VintfStability
+enum AudioProductStrategyType {
+  SYS_RESERVED_NONE = (-1) /* -1 */,
+  MEDIA = 0,
+  PHONE = 1,
+  SONIFICATION = 2,
+  SONIFICATION_RESPECTFUL = 3,
+  DTMF = 4,
+  ENFORCED_AUDIBLE = 5,
+  TRANSMITTED_THROUGH_SPEAKER = 6,
+  ACCESSIBILITY = 7,
+  SYS_RESERVED_REROUTING = 8,
+  SYS_RESERVED_CALL_ASSISTANT = 9,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioProfile.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioProfile.aidl
new file mode 100644
index 0000000..134cdd9
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioProfile.aidl
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioProfile {
+  @utf8InCpp String name;
+  android.media.audio.common.AudioFormatDescription format;
+  android.media.audio.common.AudioChannelLayout[] channelMasks;
+  int[] sampleRates;
+  android.media.audio.common.AudioEncapsulationType encapsulationType = android.media.audio.common.AudioEncapsulationType.NONE;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioSource.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioSource.aidl
new file mode 100644
index 0000000..522adeb
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioSource.aidl
@@ -0,0 +1,54 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum AudioSource {
+  SYS_RESERVED_INVALID = (-1) /* -1 */,
+  DEFAULT = 0,
+  MIC = 1,
+  VOICE_UPLINK = 2,
+  VOICE_DOWNLINK = 3,
+  VOICE_CALL = 4,
+  CAMCORDER = 5,
+  VOICE_RECOGNITION = 6,
+  VOICE_COMMUNICATION = 7,
+  REMOTE_SUBMIX = 8,
+  UNPROCESSED = 9,
+  VOICE_PERFORMANCE = 10,
+  ECHO_REFERENCE = 1997,
+  FM_TUNER = 1998,
+  HOTWORD = 1999,
+  ULTRASOUND = 2000,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioStandard.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioStandard.aidl
new file mode 100644
index 0000000..704d340
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioStandard.aidl
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum AudioStandard {
+  NONE = 0,
+  EDID = 1,
+  SADB = 2,
+  VSADB = 3,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioStreamType.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioStreamType.aidl
new file mode 100644
index 0000000..aa170b7
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioStreamType.aidl
@@ -0,0 +1,55 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum AudioStreamType {
+  INVALID = (-2) /* -2 */,
+  SYS_RESERVED_DEFAULT = (-1) /* -1 */,
+  VOICE_CALL = 0,
+  SYSTEM = 1,
+  RING = 2,
+  MUSIC = 3,
+  ALARM = 4,
+  NOTIFICATION = 5,
+  BLUETOOTH_SCO = 6,
+  ENFORCED_AUDIBLE = 7,
+  DTMF = 8,
+  TTS = 9,
+  ACCESSIBILITY = 10,
+  ASSISTANT = 11,
+  SYS_RESERVED_REROUTING = 12,
+  SYS_RESERVED_PATCH = 13,
+  CALL_ASSISTANT = 14,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioUsage.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioUsage.aidl
new file mode 100644
index 0000000..3074b9d
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioUsage.aidl
@@ -0,0 +1,62 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum AudioUsage {
+  INVALID = (-1) /* -1 */,
+  UNKNOWN = 0,
+  MEDIA = 1,
+  VOICE_COMMUNICATION = 2,
+  VOICE_COMMUNICATION_SIGNALLING = 3,
+  ALARM = 4,
+  NOTIFICATION = 5,
+  NOTIFICATION_TELEPHONY_RINGTONE = 6,
+  SYS_RESERVED_NOTIFICATION_COMMUNICATION_REQUEST = 7,
+  SYS_RESERVED_NOTIFICATION_COMMUNICATION_INSTANT = 8,
+  SYS_RESERVED_NOTIFICATION_COMMUNICATION_DELAYED = 9,
+  NOTIFICATION_EVENT = 10,
+  ASSISTANCE_ACCESSIBILITY = 11,
+  ASSISTANCE_NAVIGATION_GUIDANCE = 12,
+  ASSISTANCE_SONIFICATION = 13,
+  GAME = 14,
+  VIRTUAL_SOURCE = 15,
+  ASSISTANT = 16,
+  CALL_ASSISTANT = 17,
+  EMERGENCY = 1000,
+  SAFETY = 1001,
+  VEHICLE_STATUS = 1002,
+  ANNOUNCEMENT = 1003,
+  SPEAKER_CLEANUP = 1004,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioUuid.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioUuid.aidl
new file mode 100644
index 0000000..af307da
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioUuid.aidl
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable AudioUuid {
+  int timeLow;
+  int timeMid;
+  int timeHiAndVersion;
+  int clockSeq;
+  byte[] node;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioVolumeGroupChangeEvent.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioVolumeGroupChangeEvent.aidl
new file mode 100644
index 0000000..3a2bc5b
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/AudioVolumeGroupChangeEvent.aidl
@@ -0,0 +1,56 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @SuppressWarnings(value={"redundant-name"}) @VintfStability
+parcelable AudioVolumeGroupChangeEvent {
+  int groupId;
+  int volumeIndex;
+  boolean muted;
+  int flags;
+  const int VOLUME_FLAG_SHOW_UI = (1 << 0) /* 1 */;
+  const int VOLUME_FLAG_ALLOW_RINGER_MODES = (1 << 1) /* 2 */;
+  const int VOLUME_FLAG_PLAY_SOUND = (1 << 2) /* 4 */;
+  const int VOLUME_FLAG_REMOVE_SOUND_AND_VIBRATE = (1 << 3) /* 8 */;
+  const int VOLUME_FLAG_VIBRATE = (1 << 4) /* 16 */;
+  const int VOLUME_FLAG_FIXED_VOLUME = (1 << 5) /* 32 */;
+  const int VOLUME_FLAG_BLUETOOTH_ABS_VOLUME = (1 << 6) /* 64 */;
+  const int VOLUME_FLAG_SHOW_SILENT_HINT = (1 << 7) /* 128 */;
+  const int VOLUME_FLAG_HDMI_SYSTEM_AUDIO_VOLUME = (1 << 8) /* 256 */;
+  const int VOLUME_FLAG_ACTIVE_MEDIA_ONLY = (1 << 9) /* 512 */;
+  const int VOLUME_FLAG_SHOW_UI_WARNINGS = (1 << 10) /* 1024 */;
+  const int VOLUME_FLAG_SHOW_VIBRATE_HINT = (1 << 11) /* 2048 */;
+  const int VOLUME_FLAG_FROM_KEY = (1 << 12) /* 4096 */;
+  const int VOLUME_FLAG_ABSOLUTE_VOLUME = (1 << 13) /* 8192 */;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Boolean.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Boolean.aidl
new file mode 100644
index 0000000..bc996e4
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Boolean.aidl
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Boolean {
+  boolean value;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Byte.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Byte.aidl
new file mode 100644
index 0000000..604e74d
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Byte.aidl
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Byte {
+  byte value;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Double.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Double.aidl
new file mode 100644
index 0000000..a525629
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Double.aidl
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Double {
+  double value;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/ExtraAudioDescriptor.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/ExtraAudioDescriptor.aidl
new file mode 100644
index 0000000..2ae2405
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/ExtraAudioDescriptor.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable ExtraAudioDescriptor {
+  android.media.audio.common.AudioStandard standard = android.media.audio.common.AudioStandard.NONE;
+  byte[] audioDescriptor;
+  android.media.audio.common.AudioEncapsulationType encapsulationType = android.media.audio.common.AudioEncapsulationType.NONE;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Float.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Float.aidl
new file mode 100644
index 0000000..af98eab
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Float.aidl
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Float {
+  float value;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/HeadTracking.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/HeadTracking.aidl
new file mode 100644
index 0000000..39518cd
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/HeadTracking.aidl
@@ -0,0 +1,57 @@
+/*
+ * Copyright 2023 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable HeadTracking {
+  /* @hide */
+  @Backing(type="byte")
+  enum Mode {
+    OTHER = 0,
+    DISABLED = 1,
+    RELATIVE_WORLD = 2,
+    RELATIVE_SCREEN = 3,
+  }
+  /* @hide */
+  @Backing(type="byte")
+  enum ConnectionMode {
+    FRAMEWORK_PROCESSED = 0,
+    DIRECT_TO_SENSOR_SW = 1,
+    DIRECT_TO_SENSOR_TUNNEL = 2,
+  }
+  /* @hide */
+  union SensorData {
+    float[6] headToStage = {0f, 0f, 0f, 0f, 0f, 0f};
+  }
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Int.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Int.aidl
new file mode 100644
index 0000000..b0d3c49
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Int.aidl
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Int {
+  int value;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Long.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Long.aidl
new file mode 100644
index 0000000..e403dd3
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Long.aidl
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Long {
+  long value;
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/MicrophoneDynamicInfo.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/MicrophoneDynamicInfo.aidl
new file mode 100644
index 0000000..f0a9b8b
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/MicrophoneDynamicInfo.aidl
@@ -0,0 +1,46 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable MicrophoneDynamicInfo {
+  @utf8InCpp String id;
+  android.media.audio.common.MicrophoneDynamicInfo.ChannelMapping[] channelMapping;
+  @Backing(type="int") @VintfStability
+  enum ChannelMapping {
+    UNUSED = 0,
+    DIRECT = 1,
+    PROCESSED = 2,
+  }
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/MicrophoneInfo.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/MicrophoneInfo.aidl
new file mode 100644
index 0000000..d23031e
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/MicrophoneInfo.aidl
@@ -0,0 +1,83 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable MicrophoneInfo {
+  @utf8InCpp String id;
+  android.media.audio.common.AudioDevice device;
+  android.media.audio.common.MicrophoneInfo.Location location = android.media.audio.common.MicrophoneInfo.Location.UNKNOWN;
+  int group = GROUP_UNKNOWN /* -1 */;
+  int indexInTheGroup = INDEX_IN_THE_GROUP_UNKNOWN /* -1 */;
+  @nullable android.media.audio.common.MicrophoneInfo.Sensitivity sensitivity;
+  android.media.audio.common.MicrophoneInfo.Directionality directionality = android.media.audio.common.MicrophoneInfo.Directionality.UNKNOWN;
+  android.media.audio.common.MicrophoneInfo.FrequencyResponsePoint[] frequencyResponse;
+  @nullable android.media.audio.common.MicrophoneInfo.Coordinate position;
+  @nullable android.media.audio.common.MicrophoneInfo.Coordinate orientation;
+  const int GROUP_UNKNOWN = (-1) /* -1 */;
+  const int INDEX_IN_THE_GROUP_UNKNOWN = (-1) /* -1 */;
+  @Backing(type="int") @VintfStability
+  enum Location {
+    UNKNOWN = 0,
+    MAINBODY = 1,
+    MAINBODY_MOVABLE = 2,
+    PERIPHERAL = 3,
+  }
+  @VintfStability
+  parcelable Sensitivity {
+    float leveldBFS;
+    float maxSpldB;
+    float minSpldB;
+  }
+  @Backing(type="int") @VintfStability
+  enum Directionality {
+    UNKNOWN = 0,
+    OMNI = 1,
+    BI_DIRECTIONAL = 2,
+    CARDIOID = 3,
+    HYPER_CARDIOID = 4,
+    SUPER_CARDIOID = 5,
+  }
+  @VintfStability
+  parcelable FrequencyResponsePoint {
+    float frequencyHz;
+    float leveldB;
+  }
+  @VintfStability
+  parcelable Coordinate {
+    float x;
+    float y;
+    float z;
+  }
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/PcmType.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/PcmType.aidl
new file mode 100644
index 0000000..fbe3aea
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/PcmType.aidl
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@Backing(type="byte") @VintfStability
+enum PcmType {
+  DEFAULT = 0,
+  UINT_8_BIT = DEFAULT /* 0 */,
+  INT_16_BIT = 1,
+  INT_32_BIT = 2,
+  FIXED_Q_8_24 = 3,
+  FLOAT_32_BIT = 4,
+  INT_24_BIT = 5,
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Spatialization.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Spatialization.aidl
new file mode 100644
index 0000000..d916c8c
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Spatialization.aidl
@@ -0,0 +1,51 @@
+/*
+ * Copyright 2023 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Spatialization {
+  /* @hide */
+  @Backing(type="byte")
+  enum Level {
+    NONE = 0,
+    MULTICHANNEL = 1,
+    BED_PLUS_OBJECTS = 2,
+  }
+  /* @hide */
+  @Backing(type="byte")
+  enum Mode {
+    BINAURAL = 0,
+    TRANSAURAL = 1,
+  }
+}
diff --git a/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Void.aidl b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Void.aidl
new file mode 100644
index 0000000..2e8afd4
--- /dev/null
+++ b/media/aidl_api/android.media.audio.common.types/4/android/media/audio/common/Void.aidl
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.common;
+/* @hide */
+@FixedSize @JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Void {
+}
diff --git a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioChannelLayout.aidl b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioChannelLayout.aidl
index 33596ea..c833f1c 100644
--- a/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioChannelLayout.aidl
+++ b/media/aidl_api/android.media.audio.common.types/current/android/media/audio/common/AudioChannelLayout.aidl
@@ -88,7 +88,8 @@ union AudioChannelLayout {
   const int LAYOUT_7POINT1POINT4 = ((((LAYOUT_7POINT1 | CHANNEL_TOP_FRONT_LEFT) | CHANNEL_TOP_FRONT_RIGHT) | CHANNEL_TOP_BACK_LEFT) | CHANNEL_TOP_BACK_RIGHT) /* 185919 */;
   const int LAYOUT_9POINT1POINT4 = ((LAYOUT_7POINT1POINT4 | CHANNEL_FRONT_WIDE_LEFT) | CHANNEL_FRONT_WIDE_RIGHT) /* 50517567 */;
   const int LAYOUT_9POINT1POINT6 = ((LAYOUT_9POINT1POINT4 | CHANNEL_TOP_SIDE_LEFT) | CHANNEL_TOP_SIDE_RIGHT) /* 51303999 */;
-  const int LAYOUT_13POINT_360RA = ((((((((((((CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) | CHANNEL_FRONT_CENTER) | CHANNEL_SIDE_LEFT) | CHANNEL_SIDE_RIGHT) | CHANNEL_TOP_FRONT_LEFT) | CHANNEL_TOP_FRONT_RIGHT) | CHANNEL_TOP_FRONT_CENTER) | CHANNEL_TOP_BACK_LEFT) | CHANNEL_TOP_BACK_RIGHT) | CHANNEL_BOTTOM_FRONT_LEFT) | CHANNEL_BOTTOM_FRONT_RIGHT) | CHANNEL_BOTTOM_FRONT_CENTER) /* 7534087 */;
+  const int LAYOUT_13POINT0 = ((((((((((((CHANNEL_FRONT_LEFT | CHANNEL_FRONT_RIGHT) | CHANNEL_FRONT_CENTER) | CHANNEL_SIDE_LEFT) | CHANNEL_SIDE_RIGHT) | CHANNEL_TOP_FRONT_LEFT) | CHANNEL_TOP_FRONT_RIGHT) | CHANNEL_TOP_FRONT_CENTER) | CHANNEL_TOP_BACK_LEFT) | CHANNEL_TOP_BACK_RIGHT) | CHANNEL_BOTTOM_FRONT_LEFT) | CHANNEL_BOTTOM_FRONT_RIGHT) | CHANNEL_BOTTOM_FRONT_CENTER) /* 7534087 */;
+  const int LAYOUT_13POINT_360RA = LAYOUT_13POINT0 /* 7534087 */;
   const int LAYOUT_22POINT2 = ((((((((((((LAYOUT_7POINT1POINT4 | CHANNEL_FRONT_LEFT_OF_CENTER) | CHANNEL_FRONT_RIGHT_OF_CENTER) | CHANNEL_BACK_CENTER) | CHANNEL_TOP_CENTER) | CHANNEL_TOP_FRONT_CENTER) | CHANNEL_TOP_BACK_CENTER) | CHANNEL_TOP_SIDE_LEFT) | CHANNEL_TOP_SIDE_RIGHT) | CHANNEL_BOTTOM_FRONT_LEFT) | CHANNEL_BOTTOM_FRONT_RIGHT) | CHANNEL_BOTTOM_FRONT_CENTER) | CHANNEL_LOW_FREQUENCY_2) /* 16777215 */;
   const int LAYOUT_MONO_HAPTIC_A = (LAYOUT_MONO | CHANNEL_HAPTIC_A) /* 1073741825 */;
   const int LAYOUT_STEREO_HAPTIC_A = (LAYOUT_STEREO | CHANNEL_HAPTIC_A) /* 1073741827 */;
diff --git a/media/aidl_api/android.media.audio.eraser.types/1/.hash b/media/aidl_api/android.media.audio.eraser.types/1/.hash
new file mode 100644
index 0000000..62758f5
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/1/.hash
@@ -0,0 +1 @@
+d0f24b98624bc07be92c5dc38302f967c522ff14
diff --git a/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/Capability.aidl b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/Capability.aidl
new file mode 100644
index 0000000..a415a42
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/Capability.aidl
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Capability {
+  int[] sampleRates;
+  android.media.audio.common.AudioChannelLayout[] channelLayouts;
+  android.media.audio.eraser.Mode[] modes;
+  android.media.audio.eraser.SeparatorCapability separator;
+  android.media.audio.eraser.ClassifierCapability classifier;
+  android.media.audio.eraser.RemixerCapability remixer;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/Classification.aidl b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/Classification.aidl
new file mode 100644
index 0000000..f90f1c1
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/Classification.aidl
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Classification {
+  android.media.audio.eraser.SoundClassification classification = android.media.audio.eraser.SoundClassification.HUMAN;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/ClassificationConfig.aidl b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/ClassificationConfig.aidl
new file mode 100644
index 0000000..763352d
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/ClassificationConfig.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable ClassificationConfig {
+  android.media.audio.eraser.Classification[] classifications;
+  float confidenceThreshold = 0f;
+  float gainFactor = 1f;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/ClassificationMetadata.aidl b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/ClassificationMetadata.aidl
new file mode 100644
index 0000000..cfdbe5b
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/ClassificationMetadata.aidl
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable ClassificationMetadata {
+  float confidenceScore;
+  android.media.audio.eraser.Classification classification;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/ClassificationMetadataList.aidl b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/ClassificationMetadataList.aidl
new file mode 100644
index 0000000..36cef59
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/ClassificationMetadataList.aidl
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable ClassificationMetadataList {
+  int timeMs;
+  android.media.audio.eraser.ClassificationMetadata[] metadatas;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/ClassifierCapability.aidl b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/ClassifierCapability.aidl
new file mode 100644
index 0000000..fadf920
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/ClassifierCapability.aidl
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable ClassifierCapability {
+  int windowSizeMs;
+  android.media.audio.eraser.Classification[] supportedClassifications;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/Configuration.aidl b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/Configuration.aidl
new file mode 100644
index 0000000..8da4032
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/Configuration.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Configuration {
+  android.media.audio.eraser.Mode mode = android.media.audio.eraser.Mode.ERASER;
+  android.media.audio.eraser.ClassificationConfig[] classificationConfigs;
+  int maxClassificationMetadata = 5;
+  @nullable android.media.audio.eraser.IEraserCallback callback;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/IEraserCallback.aidl b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/IEraserCallback.aidl
new file mode 100644
index 0000000..8d53405
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/IEraserCallback.aidl
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@VintfStability
+interface IEraserCallback {
+  oneway void onClassifierUpdate(in int soundSourceId, in android.media.audio.eraser.ClassificationMetadataList metadata);
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/Mode.aidl b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/Mode.aidl
new file mode 100644
index 0000000..916b314
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/Mode.aidl
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@Backing(type="byte") @JavaDerive(equals=true, toString=true) @VintfStability
+enum Mode {
+  ERASER,
+  CLASSIFIER,
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/RemixerCapability.aidl b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/RemixerCapability.aidl
new file mode 100644
index 0000000..82707b1
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/RemixerCapability.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable RemixerCapability {
+  boolean supported;
+  float minGainFactor = 0f;
+  float maxGainFactor = 1f;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/SeparatorCapability.aidl b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/SeparatorCapability.aidl
new file mode 100644
index 0000000..2e983ac
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/SeparatorCapability.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable SeparatorCapability {
+  boolean supported;
+  int maxSoundSources = 4;
+  const int MIN_SOUND_SOURCE_SUPPORTED = 2;
+}
diff --git a/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/SoundClassification.aidl b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/SoundClassification.aidl
new file mode 100644
index 0000000..e5483b4
--- /dev/null
+++ b/media/aidl_api/android.media.audio.eraser.types/1/android/media/audio/eraser/SoundClassification.aidl
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.audio.eraser;
+@Backing(type="int") @JavaDerive(equals=true, toString=true) @VintfStability
+enum SoundClassification {
+  HUMAN,
+  ANIMAL,
+  NATURE,
+  MUSIC,
+  THINGS,
+  AMBIGUOUS,
+  ENVIRONMENT,
+  VENDOR_EXTENSION,
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/.hash b/media/aidl_api/android.media.soundtrigger.types/3/.hash
new file mode 100644
index 0000000..4e2c77c
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/.hash
@@ -0,0 +1 @@
+4659b1a13cfc886bed9b5d1a4545ed3a25e00843
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/AudioCapabilities.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/AudioCapabilities.aidl
new file mode 100644
index 0000000..47119b9
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/AudioCapabilities.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum AudioCapabilities {
+  ECHO_CANCELLATION = (1 << 0) /* 1 */,
+  NOISE_SUPPRESSION = (1 << 1) /* 2 */,
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/ConfidenceLevel.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/ConfidenceLevel.aidl
new file mode 100644
index 0000000..5127a11
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/ConfidenceLevel.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable ConfidenceLevel {
+  int userId;
+  int levelPercent;
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/ModelParameter.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/ModelParameter.aidl
new file mode 100644
index 0000000..bcfe93d
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/ModelParameter.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum ModelParameter {
+  INVALID = (-1) /* -1 */,
+  THRESHOLD_FACTOR = 0,
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/ModelParameterRange.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/ModelParameterRange.aidl
new file mode 100644
index 0000000..f29b728
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/ModelParameterRange.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable ModelParameterRange {
+  int minInclusive;
+  int maxInclusive;
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/Phrase.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/Phrase.aidl
new file mode 100644
index 0000000..11029ba
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/Phrase.aidl
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Phrase {
+  int id;
+  int recognitionModes;
+  int[] users;
+  String locale;
+  String text;
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/PhraseRecognitionEvent.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/PhraseRecognitionEvent.aidl
new file mode 100644
index 0000000..b75d1b8
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/PhraseRecognitionEvent.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable PhraseRecognitionEvent {
+  android.media.soundtrigger.RecognitionEvent common;
+  android.media.soundtrigger.PhraseRecognitionExtra[] phraseExtras;
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/PhraseRecognitionExtra.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/PhraseRecognitionExtra.aidl
new file mode 100644
index 0000000..e417c69
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/PhraseRecognitionExtra.aidl
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable PhraseRecognitionExtra {
+  int id;
+  int recognitionModes;
+  int confidenceLevel;
+  android.media.soundtrigger.ConfidenceLevel[] levels;
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/PhraseSoundModel.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/PhraseSoundModel.aidl
new file mode 100644
index 0000000..b4b3854
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/PhraseSoundModel.aidl
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable PhraseSoundModel {
+  android.media.soundtrigger.SoundModel common;
+  android.media.soundtrigger.Phrase[] phrases;
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/Properties.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/Properties.aidl
new file mode 100644
index 0000000..068db52
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/Properties.aidl
@@ -0,0 +1,53 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable Properties {
+  String implementor;
+  String description;
+  int version;
+  String uuid;
+  String supportedModelArch;
+  int maxSoundModels;
+  int maxKeyPhrases;
+  int maxUsers;
+  int recognitionModes;
+  boolean captureTransition;
+  int maxBufferMs;
+  boolean concurrentCapture;
+  boolean triggerInEvent;
+  int powerConsumptionMw;
+  int audioCapabilities;
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/RecognitionConfig.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/RecognitionConfig.aidl
new file mode 100644
index 0000000..63cd2cb
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/RecognitionConfig.aidl
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable RecognitionConfig {
+  boolean captureRequested;
+  android.media.soundtrigger.PhraseRecognitionExtra[] phraseRecognitionExtras;
+  int audioCapabilities;
+  byte[] data;
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/RecognitionEvent.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/RecognitionEvent.aidl
new file mode 100644
index 0000000..0209602
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/RecognitionEvent.aidl
@@ -0,0 +1,47 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable RecognitionEvent {
+  android.media.soundtrigger.RecognitionStatus status = android.media.soundtrigger.RecognitionStatus.INVALID;
+  android.media.soundtrigger.SoundModelType type = android.media.soundtrigger.SoundModelType.INVALID;
+  boolean captureAvailable;
+  int captureDelayMs;
+  int capturePreambleMs;
+  boolean triggerInData;
+  @nullable android.media.audio.common.AudioConfig audioConfig;
+  byte[] data;
+  boolean recognitionStillActive;
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/RecognitionMode.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/RecognitionMode.aidl
new file mode 100644
index 0000000..1899a33
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/RecognitionMode.aidl
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum RecognitionMode {
+  VOICE_TRIGGER = 0x1,
+  USER_IDENTIFICATION = 0x2,
+  USER_AUTHENTICATION = 0x4,
+  GENERIC_TRIGGER = 0x8,
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/RecognitionStatus.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/RecognitionStatus.aidl
new file mode 100644
index 0000000..8101ffd
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/RecognitionStatus.aidl
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum RecognitionStatus {
+  INVALID = (-1) /* -1 */,
+  SUCCESS = 0,
+  ABORTED = 1,
+  FAILURE = 2,
+  FORCED = 3,
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/SoundModel.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/SoundModel.aidl
new file mode 100644
index 0000000..fe38264
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/SoundModel.aidl
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@JavaDerive(equals=true, toString=true) @VintfStability
+parcelable SoundModel {
+  android.media.soundtrigger.SoundModelType type = android.media.soundtrigger.SoundModelType.INVALID;
+  String uuid;
+  String vendorUuid;
+  @nullable ParcelFileDescriptor data;
+  int dataSize;
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/SoundModelType.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/SoundModelType.aidl
new file mode 100644
index 0000000..c0927a5
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/SoundModelType.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum SoundModelType {
+  INVALID = (-1) /* -1 */,
+  KEYPHRASE = 0,
+  GENERIC = 1,
+}
diff --git a/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/Status.aidl b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/Status.aidl
new file mode 100644
index 0000000..4cd4c8e
--- /dev/null
+++ b/media/aidl_api/android.media.soundtrigger.types/3/android/media/soundtrigger/Status.aidl
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.media.soundtrigger;
+/* @hide */
+@Backing(type="int") @VintfStability
+enum Status {
+  INVALID = (-1) /* -1 */,
+  SUCCESS = 0,
+  RESOURCE_CONTENTION = 1,
+  OPERATION_NOT_SUPPORTED = 2,
+  TEMPORARY_PERMISSION_DENIED = 3,
+  DEAD_OBJECT = 4,
+  INTERNAL_ERROR = 5,
+}
diff --git a/suspend/OWNERS b/suspend/OWNERS
index b278c1c..c80f587 100644
--- a/suspend/OWNERS
+++ b/suspend/OWNERS
@@ -1,5 +1,8 @@
 # Bug component: 30545
-krossmo@google.com
-santoscordon@google.com
+krossmo@google.com #{LAST_RESORT_SUGGESTION}
+santoscordon@google.com #{LAST_RESORT_SUGGESTION}
+
+# For any queries regarding the suspend service, please reach out to the
+# following people.
 vilasbhat@google.com
 kaleshsingh@google.com
diff --git a/suspend/aidl/Android.bp b/suspend/aidl/Android.bp
index 97e0694..599107b 100644
--- a/suspend/aidl/Android.bp
+++ b/suspend/aidl/Android.bp
@@ -29,7 +29,7 @@ aidl_interface {
         ndk: {
             apex_available: [
                 "//apex_available:platform",
-                "com.android.btservices",
+                "com.android.bt",
             ],
             min_sdk_version: "30",
         },
@@ -60,7 +60,7 @@ aidl_interface {
             apex_available: [
                 "//apex_available:platform",
                 "com.android.uwb",
-                "com.android.btservices",
+                "com.android.bt",
             ],
             min_sdk_version: "30",
         },
diff --git a/vold/Android.bp b/vold/Android.bp
index c53ae65..f2d167a 100644
--- a/vold/Android.bp
+++ b/vold/Android.bp
@@ -26,5 +26,12 @@ aidl_interface {
             enabled: true,
         },
     },
-    frozen: false,
+    frozen: true,
+    versions_with_info: [
+        {
+            version: "1",
+            imports: [],
+        },
+    ],
+
 }
diff --git a/vold/aidl_api/android.system.vold/1/.hash b/vold/aidl_api/android.system.vold/1/.hash
new file mode 100644
index 0000000..9ddffeb
--- /dev/null
+++ b/vold/aidl_api/android.system.vold/1/.hash
@@ -0,0 +1 @@
+354cd0fab35bc265a0ecc951ca7737604b164a0d
diff --git a/vold/aidl_api/android.system.vold/1/android/system/vold/CheckpointingState.aidl b/vold/aidl_api/android.system.vold/1/android/system/vold/CheckpointingState.aidl
new file mode 100644
index 0000000..040b40e
--- /dev/null
+++ b/vold/aidl_api/android.system.vold/1/android/system/vold/CheckpointingState.aidl
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.vold;
+@VintfStability
+enum CheckpointingState {
+  POSSIBLE_CHECKPOINTING,
+  CHECKPOINTING_COMPLETE,
+}
diff --git a/vold/aidl_api/android.system.vold/1/android/system/vold/IVold.aidl b/vold/aidl_api/android.system.vold/1/android/system/vold/IVold.aidl
new file mode 100644
index 0000000..85bcd3b
--- /dev/null
+++ b/vold/aidl_api/android.system.vold/1/android/system/vold/IVold.aidl
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.vold;
+@VintfStability
+interface IVold {
+  android.system.vold.CheckpointingState registerCheckpointListener(android.system.vold.IVoldCheckpointListener listener);
+}
diff --git a/vold/aidl_api/android.system.vold/1/android/system/vold/IVoldCheckpointListener.aidl b/vold/aidl_api/android.system.vold/1/android/system/vold/IVoldCheckpointListener.aidl
new file mode 100644
index 0000000..434fbd2
--- /dev/null
+++ b/vold/aidl_api/android.system.vold/1/android/system/vold/IVoldCheckpointListener.aidl
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.system.vold;
+@VintfStability
+interface IVoldCheckpointListener {
+  oneway void onCheckpointingComplete();
+}
diff --git a/vold/vts/Android.bp b/vold/vts/Android.bp
new file mode 100644
index 0000000..37e1ab8
--- /dev/null
+++ b/vold/vts/Android.bp
@@ -0,0 +1,24 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_test {
+    name: "VtsHalVendorVoldTest",
+    defaults: [
+        "VtsHalTargetTestDefaults",
+        "use_libaidlvintf_gtest_helper_static",
+    ],
+    srcs: ["VtsHalVendorVoldTest.cpp"],
+    static_libs: [
+        "android.system.vold-V1-cpp",
+    ],
+    shared_libs: [
+        "libbinder",
+        "libbase",
+        "libutils",
+    ],
+    test_suites: [
+        "general-tests",
+        "vts",
+    ],
+}
diff --git a/vold/vts/VtsHalVendorVoldTest.cpp b/vold/vts/VtsHalVendorVoldTest.cpp
new file mode 100644
index 0000000..9e15878
--- /dev/null
+++ b/vold/vts/VtsHalVendorVoldTest.cpp
@@ -0,0 +1,76 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+#define LOG_TAG "vold_aidl_hal_test"
+
+#include <aidl/Gtest.h>
+#include <aidl/Vintf.h>
+#include <android/system/vold/BnVoldCheckpointListener.h>
+#include <android/system/vold/CheckpointingState.h>
+#include <android/system/vold/IVold.h>
+#include <binder/IServiceManager.h>
+#include <gtest/gtest.h>
+#include <utils/String16.h>
+
+using ::android::defaultServiceManager;
+using ::android::sp;
+using ::android::String16;
+using ::android::binder::Status;
+using ::android::system::vold::BnVoldCheckpointListener;
+using ::android::system::vold::CheckpointingState;
+using ::android::system::vold::IVold;
+
+class VoldAidlTest : public ::testing::TestWithParam<std::string> {
+   public:
+    sp<IVold> vold_;
+
+    void SetUp() final {
+        auto manager = defaultServiceManager();
+        auto name = GetParam();
+        auto binder = manager->waitForService(String16(name.data(), name.size()));
+        vold_ = IVold::asInterface(binder);
+    }
+
+    void TearDown() final {}
+};
+
+class TestListener : public BnVoldCheckpointListener {
+   public:
+    Status onCheckpointingComplete() final {
+        ++called_;
+        return Status::ok();
+    }
+
+    int timesCalled() { return called_; }
+
+   private:
+    int called_ = 0;
+};
+
+TEST_P(VoldAidlTest, PostBootAddListener) {
+    auto listener = sp<TestListener>::make();
+
+    CheckpointingState state;
+    Status ret = vold_->registerCheckpointListener(listener, &state);
+    ASSERT_EQ(ret.isOk(), true);
+    EXPECT_EQ(state, CheckpointingState::CHECKPOINTING_COMPLETE);
+    EXPECT_EQ(listener->timesCalled(), 0);
+}
+
+GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(VoldAidlTest);
+INSTANTIATE_TEST_SUITE_P(PerInstance, VoldAidlTest,
+                         testing::ValuesIn(::android::getAidlHalInstanceNames(IVold::descriptor)),
+                         android::PrintInstanceNameToString);
diff --git a/wifi/keystore/1.0/default/OWNERS b/wifi/keystore/1.0/default/OWNERS
index c7e30be..afcfb8b 100644
--- a/wifi/keystore/1.0/default/OWNERS
+++ b/wifi/keystore/1.0/default/OWNERS
@@ -1,2 +1 @@
 haishalom@google.com
-etancohen@google.com
diff --git a/wifi/keystore/1.0/vts/OWNERS b/wifi/keystore/1.0/vts/OWNERS
index c7e30be..afcfb8b 100644
--- a/wifi/keystore/1.0/vts/OWNERS
+++ b/wifi/keystore/1.0/vts/OWNERS
@@ -1,2 +1 @@
 haishalom@google.com
-etancohen@google.com
diff --git a/wifi/keystore/1.0/vts/functional/OWNERS b/wifi/keystore/1.0/vts/functional/OWNERS
index 3f5fd4a..c36df84 100644
--- a/wifi/keystore/1.0/vts/functional/OWNERS
+++ b/wifi/keystore/1.0/vts/functional/OWNERS
@@ -1,3 +1,2 @@
 # Bug component: 189335
 haishalom@google.com
-etancohen@google.com
```

