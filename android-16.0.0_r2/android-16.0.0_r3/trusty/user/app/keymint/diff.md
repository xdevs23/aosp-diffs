```diff
diff --git a/vm/commservice/aidl/Android.bp b/vm/commservice/aidl/Android.bp
new file mode 100644
index 0000000..8fe2381
--- /dev/null
+++ b/vm/commservice/aidl/Android.bp
@@ -0,0 +1,18 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+aidl_interface {
+    name: "android.keymint.trusty.commservice",
+    srcs: ["android/keymint/trusty/commservice/*.aidl"],
+    unstable: true,
+    backend: {
+        rust: {
+            enabled: true,
+            apex_available: [
+                "//apex_available:anyapex",
+                "//apex_available:platform",
+            ],
+        },
+    },
+}
diff --git a/vm/commservice/aidl/android/keymint/trusty/commservice/ICommService.aidl b/vm/commservice/aidl/android/keymint/trusty/commservice/ICommService.aidl
new file mode 100644
index 0000000..43aac39
--- /dev/null
+++ b/vm/commservice/aidl/android/keymint/trusty/commservice/ICommService.aidl
@@ -0,0 +1,25 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+package android.keymint.trusty.commservice;
+
+/**
+ * This is the service exposed by Trusty VM to the host.
+ */
+interface ICommService {
+    /* send byte buffer, receive byte buffer */
+    byte[] execute_transact(in byte[] request);
+}
diff --git a/vm/commservice/aidl/rules.mk b/vm/commservice/aidl/rules.mk
new file mode 100644
index 0000000..1433f09
--- /dev/null
+++ b/vm/commservice/aidl/rules.mk
@@ -0,0 +1,32 @@
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
+MODULE_CRATE_NAME := android_keymint_trusty_commservice
+
+MODULE_AIDL_LANGUAGE := rust
+
+MODULE_AIDL_PACKAGE := android/keymint/trusty/commservice
+
+MODULE_AIDL_INCLUDES := \
+	-I $(LOCAL_DIR) \
+
+MODULE_AIDLS := \
+    $(LOCAL_DIR)/$(MODULE_AIDL_PACKAGE)/ICommService.aidl
+
+include make/aidl.mk
diff --git a/vm/commservice/app/manifest.json b/vm/commservice/app/manifest.json
new file mode 100644
index 0000000..9394e55
--- /dev/null
+++ b/vm/commservice/app/manifest.json
@@ -0,0 +1,6 @@
+{
+    "app_name": "keymint_commservice_trusted_app",
+    "uuid": "f199e0c1-0826-4b83-88b3-ea68a5821bff",
+    "min_heap": 118784,
+    "min_stack": 65536
+}
diff --git a/vm/commservice/app/rules.mk b/vm/commservice/app/rules.mk
new file mode 100644
index 0000000..be985ec
--- /dev/null
+++ b/vm/commservice/app/rules.mk
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
+LOCAL_DIR := $(GET_LOCAL_DIR)
+
+MODULE := $(LOCAL_DIR)
+
+MANIFEST := $(LOCAL_DIR)/manifest.json
+
+MODULE_SRCS += \
+	$(LOCAL_DIR)/src/main.rs \
+
+MODULE_CRATE_NAME := keymint_commservice_trusted_app
+
+MODULE_LIBRARY_DEPS += \
+	$(call FIND_CRATE,log) \
+	frameworks/native/libs/binder/trusty/rust/rpcbinder \
+	trusty/user/app/keymint/vm/commservice/aidl \
+	trusty/user/base/lib/tipc/rust \
+	trusty/user/base/lib/trusty-log \
+
+include make/trusted_app.mk
diff --git a/vm/commservice/app/src/commservice.rs b/vm/commservice/app/src/commservice.rs
new file mode 100644
index 0000000..0665ea9
--- /dev/null
+++ b/vm/commservice/app/src/commservice.rs
@@ -0,0 +1,138 @@
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
+//! This module groups the ICommService binder, exposed within the KeyMint VM,
+//! which serves as the communication channel between the KeyMint VM and the
+//! host.
+
+use android_keymint_trusty_commservice::aidl::android::keymint::trusty::commservice::ICommService::{
+    BnCommService, ICommService,
+};
+use android_keymint_trusty_commservice::binder;
+use alloc::vec::Vec;
+use alloc::rc::Rc;
+use core::ffi::CStr;
+use log::info;
+use tipc::{service_dispatcher, wrap_service, Manager, PortCfg, TipcError};
+use rpcbinder::RpcServer;
+
+const KEYMINT_COMMSERVICE_PORT: &str = "com.android.trusty.keymint.commservice";
+const KEYMINT_PORT: &CStr = c"com.android.trusty.keymint";
+
+/// Constants to indicate whether or not to include/expect more messages when splitting and then
+/// assembling the large responses sent from the TA to the HAL.
+const NEXT_MESSAGE_SIGNAL_TRUE: u8 = 0b00000001u8;
+
+/// KeyMint ICommService binder.
+pub struct KeymintTrustyComm;
+
+impl binder::Interface for KeymintTrustyComm {}
+
+impl KeymintTrustyComm {
+    /// Creates a new KeymintTrustyComm binder.
+    pub fn new_binder() -> binder::Strong<dyn ICommService> {
+        let keymint_comm = KeymintTrustyComm;
+        BnCommService::new_binder(keymint_comm, binder::BinderFeatures::default())
+    }
+}
+
+impl ICommService for KeymintTrustyComm {
+    #[allow(dependency_on_unit_never_type_fallback)]
+    fn execute_transact(&self, req_data: &[u8]) -> binder::Result<Vec<u8>> {
+        let handle = tipc::Handle::connect(KEYMINT_PORT).map_err(|e| {
+            binder::Status::new_exception_str(
+                binder::ExceptionCode::TRANSACTION_FAILED,
+                Some(format!("failed to connect to Trusty port: {KEYMINT_PORT:?}. {e:?}")),
+            )
+        })?;
+        handle.send(&req_data).map_err(|e| {
+            binder::Status::new_exception_str(
+                binder::ExceptionCode::TRANSACTION_FAILED,
+                Some(format!("failed to send the request via tipc channel:{e:?}")),
+            )
+        })?;
+        let mut expect_more_msgs = true;
+        let mut full_rsp = Vec::new();
+        let mut recv_buf = Vec::new();
+        while expect_more_msgs {
+            recv_buf.clear();
+            handle.recv(&mut recv_buf).map_err(|e| {
+                binder::Status::new_exception_str(
+                    binder::ExceptionCode::TRANSACTION_FAILED,
+                    Some(format!("failed to receive the response via tipc channel: {e:?}")),
+                )
+            })?;
+            let current_rsp_content;
+            (expect_more_msgs, current_rsp_content) = extract_rsp(&recv_buf)?;
+            full_rsp.try_reserve(current_rsp_content.len()).map_err(|_| {
+                binder::Status::new_exception_str(
+                    binder::ExceptionCode::TRANSACTION_FAILED,
+                    Some(format!("failed to reserve memory for the response")),
+                )
+            })?;
+            full_rsp.extend_from_slice(current_rsp_content);
+        }
+        Ok(full_rsp)
+    }
+}
+
+wrap_service!(CommService(RpcServer: UnbufferedService));
+
+service_dispatcher! {
+    enum KmCommServices {
+        CommService,
+    }
+}
+
+pub fn main_loop() -> Result<(), TipcError> {
+    info!("Hello from KeyMint CommService TA!");
+    let service = KeymintTrustyComm::new_binder();
+    let direct_rpc_server = RpcServer::new(service.as_binder());
+    let direct = CommService(direct_rpc_server);
+
+    let cfg = PortCfg::new(KEYMINT_COMMSERVICE_PORT)
+        .expect("failed to create port config")
+        .allow_ta_connect()
+        .allow_ns_connect();
+
+    let mut dispatcher = KmCommServices::<1>::new().expect("dispatcher creation failed");
+    dispatcher
+        .add_service(Rc::new(direct), cfg)
+        .expect("failed to add direct KeymintCommService to dispatcher");
+    Manager::<_, _, 1, 1>::new_with_dispatcher(dispatcher, [])
+        .expect("Manager could not be created")
+        .run_event_loop()
+}
+
+/// A helper method to be used in the [`execute`] method above, in order to handle
+/// responses received from the TA, especially those which are larger than the capacity of the
+/// channel between the HAL and the TA.
+/// This inspects the message, checks the first byte to see if the response arrives in multiple
+/// messages. A boolean indicating whether or not to wait for the next message and the
+/// response content (with the first byte stripped off) are returned to
+/// the HAL service . Implementation of this method must be in sync with its counterpart
+/// in the `kmr-ta` crate.
+///
+/// TODO(b/376340041): Remove duplication of this method in host.
+fn extract_rsp(rsp: &[u8]) -> binder::Result<(bool, &[u8])> {
+    if rsp.len() < 2 {
+        return Err(binder::Status::new_exception_str(
+            binder::ExceptionCode::ILLEGAL_ARGUMENT,
+            Some("message is too small to extract the response data".to_string()),
+        ));
+    }
+    Ok((rsp[0] == NEXT_MESSAGE_SIGNAL_TRUE, &rsp[1..]))
+}
diff --git a/vm/commservice/app/src/main.rs b/vm/commservice/app/src/main.rs
new file mode 100644
index 0000000..e175e35
--- /dev/null
+++ b/vm/commservice/app/src/main.rs
@@ -0,0 +1,26 @@
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
+//! Trusty KeyMint CommService TA
+
+mod commservice;
+
+use crate::commservice::main_loop;
+
+fn main() {
+    trusty_log::init();
+    main_loop().expect("KeyMint CommService TA quits unexpectedly.");
+}
```

