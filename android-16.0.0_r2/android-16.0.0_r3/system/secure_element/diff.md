```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..f6eac73
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,17 @@
+// Copyright 2024, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_team: "trendy_team_android_hardware_backed_security",
+}
diff --git a/omapi/Android.bp b/omapi/Android.bp
index bedb4e7..cb40644 100644
--- a/omapi/Android.bp
+++ b/omapi/Android.bp
@@ -17,13 +17,25 @@ rust_defaults {
     crate_name: "se_service",
     srcs: ["src/lib.rs"],
     rustlibs: [
+        "android.hardware.secure_element-V1-rust",
+        "libandroid_logger",
+        "libanyhow",
+        "libbinder_rs",
+        "libbssl_crypto",
         "libhex",
+        "libitertools",
         "liblog_rust",
-        "libthiserror",
+        "libmockall",
+        "libserde_xml_rs",
+        "libserde",
         "libstrum",
-        "libitertools",
+        "libthiserror",
+        "libzeroize",
     ],
     proc_macros: ["libstrum_macros"],
+    // The "log_sensitive_data" feature enables detailed debug tracing.  This is useful but
+    // verbose and may log sensitive data, so enable it only for developer builds.
+    //features: ["log_sensitive_data"],
 }
 
 rust_library {
@@ -39,4 +51,17 @@ rust_test {
     rustlibs: [
         "libgoogletest_rust",
     ],
+    proc_macros: ["libmockall_derive"],
+    require_root: true,
+}
+
+rust_test {
+    name: "libse_service_test_disallow_unknown_tags",
+    defaults: ["libse_service_defaults"],
+    test_suites: ["general-tests"],
+    auto_gen_config: true,
+    rustlibs: [
+        "libgoogletest_rust",
+    ],
+    features: ["disallow_unknown_ara_tags"],
 }
diff --git a/omapi/src/access_enforcer.rs b/omapi/src/access_enforcer.rs
new file mode 100644
index 0000000..fd53151
--- /dev/null
+++ b/omapi/src/access_enforcer.rs
@@ -0,0 +1,315 @@
+// Copyright 2024, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! This module defines the [`AccessEnforcer`] type, which implements a GlobalPlatform
+//! AcesssControlEnforcer (ACE). It is responsible for enforcing applet access control,
+//! restricting which device apps can communicate with which applets.
+//!
+//! The [`AccessEnforcer`] must communicate with the SE for which it enforces access, to retrieve
+//! access rules.  For it to do that, the caller must provide a reference to a [`Terminal`].
+
+use crate::{
+    ara::{
+        tlv::{self, Parseable, Tag},
+        ApduAccessRule, AppletId, DeviceAppId, Rule, RuleCache,
+    },
+    system_services::{ClientId, SeSecurityProfile},
+    terminal::{ApduResponse, ChannelId, SendSelectOnClose, Terminal},
+    utils::{binder_exception, create_exception_status, TraceResultExt},
+};
+use binder::{
+    ExceptionCode::{ILLEGAL_ARGUMENT, ILLEGAL_STATE, SECURITY},
+    Result,
+};
+use log::{debug, error, info, trace};
+
+#[cfg(test)]
+mod test;
+
+/// [`CONFIGURABLE_LE`] is the Le value to use in GET_ALL, GET_NEXT and GET_REFRESH_TAG commands.
+/// It's available to be customized by OEMs if their device or modem has problems with Le = 0x00.
+pub(crate) const CONFIGURABLE_LE: u8 = 0x00;
+
+/// AID of ARA-[M|D] applet.
+pub const ARA_M_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C, 0x00];
+
+// APDU to get the ARA refresh tag.
+pub const GET_REFRESH_TAG_APDU: &[u8] = &[0x80, 0xCA, 0xDF, 0x20, CONFIGURABLE_LE];
+
+// APDU to get the ARA rule data.
+pub const GET_ALL_APDU: &[u8] = &[0x80, 0xCA, 0xFF, 0x40, CONFIGURABLE_LE];
+
+// APDU to get the next chunk of ARA rule data, in the event the data was too large to be returned
+// in the response to the [`GET_ALL`] APDU.
+pub const GET_NEXT_APDU: &[u8] = &[0x80, 0xCA, 0xFF, 0x60, CONFIGURABLE_LE];
+
+#[derive(Clone, Debug)]
+struct CacheState {
+    rules: RuleCache,
+    refresh_tag: Option<RefreshTagDo>,
+    platform_rules: Vec<Rule>,
+}
+
+impl CacheState {
+    fn new(platform_rules: Vec<Rule>) -> Self {
+        CacheState {
+            rules: RuleCache::new(platform_rules.clone()),
+            refresh_tag: None,
+            platform_rules,
+        }
+    }
+
+    /// Update cache, reading rules from the SE if the refresh tag has changed.
+    fn update(&mut self, terminal: &Terminal, channel_id: ChannelId) -> Result<()> {
+        let se_refresh_tag = read_refresh_tag(terminal, channel_id).trace("Refresh tag").ok();
+
+        if self.refresh_tag.is_some() && se_refresh_tag == self.refresh_tag {
+            info!("Refresh tag {:?} unchanged. Using cached access rules.", se_refresh_tag);
+            return Ok(());
+        } else if se_refresh_tag.is_none() {
+            error!("Refresh tag could not be retrieved.")
+        } else {
+            info!("Refresh tag {:?} changed to {:?}.", self.refresh_tag, se_refresh_tag);
+        }
+
+        match read_rule_data(terminal, channel_id, self.platform_rules.clone()) {
+            Ok(rules) => {
+                self.rules = rules;
+                self.refresh_tag = se_refresh_tag;
+                Ok(())
+            }
+            Err(e) => {
+                error!("Error reading ARA rule data: {e}");
+                self.reset();
+                Err(e)
+            }
+        }
+    }
+
+    /// Reset the cache.
+    fn reset(&mut self) {
+        self.rules = RuleCache::new(self.platform_rules.iter().cloned());
+        self.refresh_tag = None;
+    }
+}
+
+#[derive(Clone, Debug)]
+pub struct AccessEnforcer {
+    rule_cache: CacheState,
+    security_profile: SeSecurityProfile,
+}
+
+impl AccessEnforcer {
+    pub fn new(security_profile: SeSecurityProfile, platform_rules: Vec<Rule>) -> Self {
+        AccessEnforcer { rule_cache: CacheState::new(platform_rules), security_profile }
+    }
+
+    /// Update the cached rules if necessary.  Returns [`Err`] if there was a problem
+    /// communicating with the SE.
+    ///
+    /// Note that even if the rules haven't changed, this function is moderately expensive because
+    /// it opens a logical channel and sends an APDU to the SE to get the refresh tag.
+    ///
+    /// Does nothing if the security profile indicates we're not using ARA.
+    pub fn update_rule_cache(&mut self, terminal: &mut Terminal) -> Result<()> {
+        if !self.security_profile.use_ara_applet {
+            info!("Ignoring ARA rule update request because platform is not using ARA.");
+            return Ok(());
+        }
+
+        debug!("Opening logical channel for ARA-M applet.");
+        match terminal.open_logical_channel(Self::get_aid(), 0x00) {
+            Ok(Some(channel_id)) => {
+                trace!("Opened {channel_id}");
+                let result = self.rule_cache.update(terminal, channel_id);
+                let _ = terminal.close_channel(channel_id, SendSelectOnClose(false));
+                result
+            }
+            Ok(None) => {
+                error!("Unable to open SE channel to get ARA rules.");
+                self.rule_cache.reset();
+                Ok(())
+            }
+            Err(e) => {
+                error!("Unable to open SE channel to get ARA rules: {e}.");
+                self.rule_cache.reset();
+                Err(e)
+            }
+        }
+    }
+
+    /// Clear the rule cache, removing any rules retrieved from the ARA applet and resetting the
+    /// refresh tag to force re-reading.
+    pub fn reset(&mut self) {
+        self.rule_cache.reset()
+    }
+
+    /// Get APDU access policy for the specified AID, for the current caller.
+    pub fn get_policy(&self, aid: &[u8], client_id: &ClientId) -> Result<ApduAccessRule> {
+        if self.security_profile.full_access {
+            return Ok(ApduAccessRule::Always);
+        }
+
+        let app_id = client_id_to_app_id(client_id);
+        let applet_id = AppletId::new(aid);
+
+        let policy = self.rule_cache.rules.get_apdu_rule(&app_id, &applet_id);
+        if *policy == ApduAccessRule::Never {
+            debug!("Access denied for AID {} with caller info {client_id}", hex::encode(aid));
+            binder_exception(SECURITY, "APDU access disallowed by policy")
+        } else {
+            Ok(policy.clone())
+        }
+    }
+
+    /// Determine if the caller should receive NFC events for the specified [`ClientId`]s.
+    pub fn is_nfc_event_allowed(
+        &self,
+        aid: Option<&[u8]>,
+        client_ids: &[ClientId],
+    ) -> Result<Vec<bool>> {
+        let aid = AppletId::new(aid.unwrap_or_default());
+        let rules = &self.rule_cache.rules;
+        Ok(client_ids
+            .iter()
+            .map(|client_id| rules.check_nfc(&client_id_to_app_id(client_id), &aid))
+            .collect())
+    }
+
+    pub fn have_applet_rules(&self) -> bool {
+        self.rule_cache.refresh_tag.is_some()
+    }
+
+    const fn get_aid() -> &'static [u8] {
+        ARA_M_AID
+    }
+}
+
+/// Convert a [`ClientId`] provided by the system to the [`DeviceAppId`] format required by the
+/// ARA rule engine.
+fn client_id_to_app_id(caller_id: &ClientId) -> DeviceAppId {
+    match caller_id {
+        ClientId::PackageInfo(package_infos) => DeviceAppId::new_apk(
+            package_infos.iter().flat_map(|info| info.sha256s.iter().cloned()).collect(),
+            package_infos.iter().flat_map(|info| info.sha1s.iter().cloned()).collect(),
+            package_infos.iter().map(|info| info.package_name.clone()).collect(),
+        ),
+        ClientId::Uuids(uuids) => DeviceAppId::new_system_component(uuids.clone()),
+    }
+}
+
+fn read_refresh_tag(terminal: &Terminal, channel_id: ChannelId) -> Result<RefreshTagDo> {
+    debug!("Reading ARA refresh tag.");
+    let privileged_caller = false;
+    let response = terminal.transmit(channel_id, GET_REFRESH_TAG_APDU, privileged_caller)?;
+    check_status(&response, "Reading refresh tag")?;
+    RefreshTagDo::from_ber(response.risky_data())
+}
+
+fn check_status(response: &ApduResponse, context: &str) -> Result<()> {
+    if response.successful() {
+        Ok(())
+    } else {
+        binder_exception(
+            ILLEGAL_STATE,
+            &format!(
+                "{context}: Unsuccessful APDU response: {}",
+                hex::encode(response.non_zeroizing_status())
+            ),
+        )
+    }
+}
+
+fn read_rule_data(
+    terminal: &Terminal,
+    channel_id: ChannelId,
+    platform_rules: Vec<Rule>,
+) -> Result<RuleCache> {
+    info!("Reading ARA rules.");
+    let privileged_caller = false;
+    let mut response = terminal.transmit(channel_id, GET_ALL_APDU, privileged_caller)?;
+    check_status(&response, "GET ALL")?;
+
+    let (hdr, data) = tlv::Header::parse(response.risky_data()).map_err(|_| {
+        create_exception_status(ILLEGAL_STATE, "Failed to parse ALL-REF-AR-DO header")
+    })?;
+
+    // May not have gotten all of the data in one request.
+    let additional_data_needed = hdr.len().saturating_sub(data.len());
+    let rule_data_needed = response.data_len() + additional_data_needed;
+
+    while response.data_len() < rule_data_needed {
+        trace!("Reading additional data, need {}", rule_data_needed - response.data_len());
+
+        let get_next_response = terminal.transmit(channel_id, GET_NEXT_APDU, privileged_caller)?;
+        check_status(&get_next_response, "GET NEXT")?;
+
+        trace!("Read {} additional bytes", get_next_response.data_len());
+        response.extend(get_next_response);
+    }
+
+    trace!("Got ARA rule data: {}", hex::encode(response.risky_data()));
+    let (tlv, unused_data) = tlv::parse(response.risky_data()).map_err(|e| {
+        create_exception_status(ILLEGAL_ARGUMENT, &format!("Error parsing ARA rule BER: {e:?}"))
+    })?;
+
+    if !unused_data.is_empty() {
+        error!("Got {} extra bytes of rule data", unused_data.len());
+    }
+    trace!("Parsed ARA rule TLV objects: {tlv:#?}");
+
+    let ara_rules = RuleCache::tlv_to_rules(tlv).map_err(|e| {
+        create_exception_status(ILLEGAL_ARGUMENT, &format!("Error validating ARA rules {e:?}"))
+    })?;
+    Ok(RuleCache::new(ara_rules.into_iter().chain(platform_rules.clone())))
+}
+
+#[derive(Clone, Copy, PartialEq)]
+pub(crate) struct RefreshTagDo([u8; 8]);
+
+impl std::fmt::Debug for RefreshTagDo {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        write!(f, "RefreshTagDo({})", hex::encode(self.0))
+    }
+}
+
+impl RefreshTagDo {
+    fn from_ber(data: &[u8]) -> Result<Self> {
+        let (obj, _) = tlv::parse(data).map_err(|e| {
+            create_exception_status(
+                ILLEGAL_STATE,
+                &format!("Failed to parse RefreshTagDo {}: {e}", hex::encode(data)),
+            )
+        })?;
+        Self::from_tlv(&obj)
+    }
+
+    fn from_tlv(tlv_obj: &tlv::Object) -> Result<Self> {
+        trace!("RefreshTagDo: {tlv_obj:?}");
+        if *tlv_obj.tag() != Tag::ResponseRefreshTagDo {
+            return binder_exception(ILLEGAL_STATE, &format!("Got {tlv_obj:?} from GET REFRESH"));
+        }
+
+        match tlv_obj.value() {
+            tlv::Value::Primitive(data) => (*data)
+                .try_into()
+                .map(Self)
+                .map_err(|_| create_exception_status(ILLEGAL_STATE, "Invalid")),
+            _ => binder_exception(
+                ILLEGAL_STATE,
+                &format!("Invalid content {} in ResponseRefreshTagDo", tlv_obj.value()),
+            ),
+        }
+    }
+}
diff --git a/omapi/src/access_enforcer/test.rs b/omapi/src/access_enforcer/test.rs
new file mode 100644
index 0000000..4f8b340
--- /dev/null
+++ b/omapi/src/access_enforcer/test.rs
@@ -0,0 +1,322 @@
+// Copyright 2025, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! This module defines the [`AccessEnforcer`] type, which implements a GlobalPlatform
+//! AcesssControlEnforcer (ACE). It is responsible for enforcing applet access control,
+//! restricting which device apps can communicate with which applets.
+//!
+//! The [`AccessEnforcer`] must communicate with the SE for which it enforces access, to retrieve
+//! access rules.  For it to do that, the caller must provide a reference to a [`Terminal`].
+
+use super::*;
+use crate::{
+    ara::{
+        tlv::{Object, Value},
+        Sha1DigestOrUuid,
+    },
+    terminal::Apdu,
+};
+use android_hardware_secure_element::aidl::android::hardware::secure_element::{
+    ISecureElement::{BnSecureElement, ISecureElement, MockISecureElement},
+    LogicalChannelResponse::LogicalChannelResponse,
+};
+use binder::{BinderFeatures, ExceptionCode, Strong};
+use bssl_crypto::digest::Sha256;
+use googletest::{prelude::*, test as gtest, Result};
+use mockall::{predicate as mp, Sequence};
+
+fn init() {
+    android_logger::init_once(
+        android_logger::Config::default()
+            .with_tag("se_service_access_enforcer_test")
+            .with_max_level(log::LevelFilter::Trace)
+            .with_log_buffer(android_logger::LogId::System)
+            .format(|buf, record| {
+                writeln!(
+                    buf,
+                    "{}:{} - {}",
+                    record.file().unwrap_or("unknown"),
+                    record.line().unwrap_or(0),
+                    record.args()
+                )
+            }),
+    );
+}
+
+#[gtest]
+fn create() -> Result<()> {
+    init();
+
+    let security_profile = SeSecurityProfile { use_ara_applet: true, full_access: false };
+    let platform_rules = vec![];
+    let ae = AccessEnforcer::new(security_profile, platform_rules);
+
+    assert_that!(ae.security_profile.use_ara_applet, eq(true));
+    assert_that!(ae.security_profile.full_access, eq(false));
+
+    Ok(())
+}
+
+#[gtest]
+fn test_default_deny() -> Result<()> {
+    init();
+
+    let security_profile = SeSecurityProfile { use_ara_applet: true, full_access: false };
+    let platform_rules = vec![];
+    let ae = AccessEnforcer::new(security_profile, platform_rules);
+
+    let aid = [0; 5];
+    let client_id = ClientId::Uuids(vec![Sha1DigestOrUuid([0; 20])]);
+    assert_that!(
+        ae.get_policy(&aid, &client_id),
+        err(predicate(binder_status(SECURITY, "APDU access disallowed by policy")))
+    );
+
+    Ok(())
+}
+
+#[gtest]
+fn test_full_access() -> Result<()> {
+    init();
+
+    let security_profile = SeSecurityProfile { use_ara_applet: true, full_access: true };
+    let platform_rules = vec![];
+    let ae = AccessEnforcer::new(security_profile, platform_rules);
+
+    // Any AID is accessible.
+    let client_id = ClientId::Uuids(vec![Sha1DigestOrUuid([0; 20])]);
+    assert_that!(ae.get_policy(&[0; 5], &client_id), ok(eq(&ApduAccessRule::Always)));
+    assert_that!(ae.get_policy(&[1; 5], &client_id), ok(eq(&ApduAccessRule::Always)));
+    assert_that!(ae.get_policy(&[2; 5], &client_id), ok(eq(&ApduAccessRule::Always)));
+    assert_that!(ae.get_policy(&[3; 5], &client_id), ok(eq(&ApduAccessRule::Always)));
+
+    Ok(())
+}
+
+/// The [`AccessEnforcer`] should use platform rules without attempting to retrieve rules from
+/// ARA-M, if the platform rules satisfy the request.
+#[gtest]
+fn test_platform_rule() -> Result<()> {
+    init();
+
+    let aid1 = [0; 5];
+    let aid2 = [1; 5];
+    let uuid = [0; 20];
+    let client_id = ClientId::Uuids(vec![Sha1DigestOrUuid([0; 20])]);
+
+    let security_profile = SeSecurityProfile { use_ara_applet: true, full_access: false };
+    let platform_rules = vec![Rule::from_tlv(build_allow_rule(&aid1, &uuid)).unwrap()];
+    let mut ae = AccessEnforcer::new(security_profile, platform_rules);
+
+    assert_that!(ae.get_policy(&aid1, &client_id), ok(eq(&ApduAccessRule::Always)));
+    assert_that!(
+        ae.get_policy(&aid2, &client_id),
+        err(predicate(binder_status(SECURITY, "APDU access disallowed by policy")))
+    );
+
+    // Test that resetting the enforcer cache doesn't lose platform rules.
+    ae.rule_cache.reset();
+    assert_that!(ae.get_policy(&aid1, &client_id), ok(eq(&ApduAccessRule::Always)));
+    assert_that!(
+        ae.get_policy(&aid2, &client_id),
+        err(predicate(binder_status(SECURITY, "APDU access disallowed by policy")))
+    );
+
+    Ok(())
+}
+
+#[gtest]
+fn test_update_rule_cache() -> Result<()> {
+    init();
+
+    // Mock SE setup is extensive.  The SE has to respond to multiple requests to get the ARA-M
+    // rule data, further complicated by the fact that we want to test the refresh tag
+    // functionality, so we'll need to read rule data twice.
+    //
+    // We'll return two sets of rules, and two corresponding refresh tag values.  The first rule
+    // set authorizes the all-zeros UUID, the second adds authorization for the all-ones UUID.
+    // The client is the all-ones UUID.
+    let se_hal = mock_se(|mock| {
+        let mut seq = Sequence::new();
+
+        let first_rule_set_data = build_rule_set(vec![build_allow_rule(
+            /* aid */ &[0; 5], /* uuid */ &[0; 20],
+        )])
+        .to_ber();
+        let first_refresh_tag = Object::new(
+            Tag::ResponseRefreshTagDo,
+            Value::Primitive(&Sha256::hash(&first_rule_set_data)[..8]),
+        )
+        .to_ber();
+
+        let second_rule_set_data = build_rule_set(vec![
+            build_allow_rule(/* aid */ &[0; 5], /* uuid */ &[1; 20]),
+            build_allow_rule(/* aid */ &[0; 5], /* uuid */ &[1; 20]),
+        ])
+        .to_ber();
+        let second_refresh_tag = Object::new(
+            Tag::ResponseRefreshTagDo,
+            Value::Primitive(&Sha256::hash(&second_rule_set_data)[..8]),
+        )
+        .to_ber();
+
+        // First update request.  Since the AccessEnforcer has no rule data, this will include a
+        // ruleset retrieval.  To test the chunk reassembly reature, break the data into chunks.
+        let mut rule_chunks = first_rule_set_data.chunks(10);
+
+        expect_open_channel(mock, &mut seq, ARA_M_AID);
+        expect_transmit(mock, &mut seq, GET_REFRESH_TAG_APDU, &first_refresh_tag);
+        expect_transmit(mock, &mut seq, GET_ALL_APDU, rule_chunks.next().unwrap());
+        rule_chunks.for_each(|chunk| {
+            expect_transmit(mock, &mut seq, GET_NEXT_APDU, chunk);
+        });
+        expect_close_channel(mock, &mut seq);
+
+        // Another update request.  We return the same tag, which doesn't provoke ruleset retrieval.
+        expect_open_channel(mock, &mut seq, ARA_M_AID);
+        expect_transmit(mock, &mut seq, GET_REFRESH_TAG_APDU, &first_refresh_tag);
+        expect_close_channel(mock, &mut seq);
+
+        // A third update request, this time returning a different tag, provoking ruleset retrieval.
+        // This time we'll return the whole ruleset in one response.
+        expect_open_channel(mock, &mut seq, ARA_M_AID);
+        expect_transmit(mock, &mut seq, GET_REFRESH_TAG_APDU, &second_refresh_tag);
+        expect_transmit(mock, &mut seq, GET_ALL_APDU, &second_rule_set_data);
+        expect_close_channel(mock, &mut seq);
+    });
+
+    let security_profile = SeSecurityProfile { use_ara_applet: true, full_access: false };
+    let platform_rules = vec![];
+    let mut ae = AccessEnforcer::new(security_profile, platform_rules);
+
+    let mut terminal = Terminal::new("se_name", se_hal)?;
+    terminal.set_connected(true);
+
+    let client_id = ClientId::Uuids(vec![Sha1DigestOrUuid([1; 20])]);
+
+    // We haven't yet read data from ARA-M, so access should be denied.
+    let aid = [0; 5];
+    assert_that!(
+        ae.get_policy(&aid, &client_id),
+        err(predicate(binder_status(SECURITY, "APDU access disallowed by policy")))
+    );
+
+    // Read from ARA-M.  The first rule set authorizes the all-zeros UUID but the client is the
+    // all-ones UUID.
+    ae.update_rule_cache(&mut terminal)?;
+    assert_that!(
+        ae.get_policy(&aid, &client_id),
+        err(predicate(binder_status(SECURITY, "APDU access disallowed by policy")))
+    );
+
+    // The second update gets the same refresh tag, so no change in policy.
+    ae.update_rule_cache(&mut terminal)?;
+    assert_that!(
+        ae.get_policy(&aid, &client_id),
+        err(predicate(binder_status(SECURITY, "APDU access disallowed by policy")))
+    );
+
+    // The third update returns a different refresh tag, provoking a re-read of a new policy that
+    // also authorizes the all-ones UUID.
+    ae.update_rule_cache(&mut terminal)?;
+    assert_that!(ae.get_policy(&aid, &client_id), ok(eq(&ApduAccessRule::Always)));
+
+    // Resetting the enforcer cache should lose the ARA rules.
+    ae.rule_cache.reset();
+    assert_that!(
+        ae.get_policy(&aid, &client_id),
+        err(predicate(binder_status(SECURITY, "APDU access disallowed by policy")))
+    );
+
+    Ok(())
+}
+
+fn build_rule_set(objects: Vec<Object>) -> Object {
+    Object::new(Tag::ResponseAllRefArDo, Value::Constructed(objects))
+}
+
+fn build_allow_rule<'a>(aid: &'a [u8], uuid: &'a [u8]) -> Object<'a> {
+    Object::new(
+        Tag::RefArDo,
+        Value::Constructed(vec![
+            Object::new(
+                Tag::RefDo,
+                Value::Constructed(vec![
+                    // Match AID [0; 5].
+                    Object::new(Tag::AidRefDoSpecificApplet, Value::Primitive(aid)),
+                    // Match UUID [0; 20].
+                    Object::new(Tag::DeviceAppIdRefDo, Value::Primitive(uuid)),
+                ]),
+            ),
+            Object::new(
+                Tag::ArDo,
+                Value::Constructed(vec![
+                    // Always allow APDUs
+                    Object::new(Tag::ApduArDo, Value::Primitive(&[1])),
+                ]),
+            ),
+        ]),
+    )
+}
+
+fn expect_transmit(
+    mock: &mut MockISecureElement,
+    seq: &mut Sequence,
+    apdu: &[u8],
+    response: &[u8],
+) {
+    let response = [response, &[0x90, 0x00][..]].concat();
+    mock.expect_transmit()
+        .times(1)
+        .in_sequence(seq)
+        .with(mp::eq(set_channel(1, apdu)))
+        .return_once(move |_| Ok(response));
+}
+
+fn expect_close_channel(mock: &mut MockISecureElement, seq: &mut Sequence) {
+    // Close channel
+    mock.expect_closeChannel().times(1).in_sequence(seq).with(mp::eq(1)).returning(|_| Ok(()));
+}
+
+fn expect_open_channel(mock: &mut MockISecureElement, seq: &mut Sequence, aid: &[u8]) {
+    let aid = aid.to_vec();
+    mock.expect_openLogicalChannel()
+        .times(1)
+        .in_sequence(seq)
+        .with(mp::eq(aid), mp::eq(0))
+        .returning(|_, _| Ok(LogicalChannelResponse { channelNumber: 1, selectResponse: vec![] }));
+}
+
+fn mock_se(expectations: impl FnOnce(&mut MockISecureElement)) -> Strong<dyn ISecureElement> {
+    let mut se_mock = MockISecureElement::new();
+    expectations(&mut se_mock);
+
+    BnSecureElement::new_binder(se_mock, BinderFeatures::default())
+}
+
+fn binder_status(
+    code: ExceptionCode,
+    description: &str,
+) -> impl Fn(&'_ binder::Status) -> bool + use<'_> {
+    let description = description.to_owned();
+    move |s: &binder::Status| {
+        s.exception_code() == code && s.get_description().contains(&description)
+    }
+}
+
+fn set_channel(channel: i8, apdu: &[u8]) -> Vec<u8> {
+    let apdu =
+        Apdu::new(apdu, Some(ChannelId(channel))).expect("We shouldn't be using invalid APDUs");
+    apdu.0.clone()
+}
diff --git a/omapi/src/ara.rs b/omapi/src/ara.rs
index afc30ed..a1f210d 100644
--- a/omapi/src/ara.rs
+++ b/omapi/src/ara.rs
@@ -16,5 +16,13 @@
 //! Control](https://globalplatform.org/wp-content/uploads/2024/08/GPD_SE_Access_Control_v1.1.0.10_PublicRvw.pdf)
 //! Access Control Enforcer (ACE).
 
-#[allow(dead_code)] // TODO: remove when client code is added.
-mod tlv;
+pub mod tlv;
+
+#[allow(dead_code)] // TODO: Remove when client code is added.
+mod rules;
+#[allow(dead_code)] // TODO: Remove when client code is added.
+mod xml;
+
+pub use rules::{
+    ApduAccessRule, AppletId, DeviceAppId, Rule, RuleCache, Sha1DigestOrUuid, Sha256Digest,
+};
diff --git a/omapi/src/ara/rules.rs b/omapi/src/ara/rules.rs
new file mode 100644
index 0000000..a7cd664
--- /dev/null
+++ b/omapi/src/ara/rules.rs
@@ -0,0 +1,996 @@
+// Copyright 2024, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! Implementation of the rules engine of a Global Platform Access Control Enforcer.  See
+//!
+//! https://globalplatform.org/wp-content/uploads/2024/08/GPD_SE_Access_Control_v1.1.0.10_PublicRvw.pdf
+//!
+//! and
+//!
+//! https://globalplatform.org/wp-content/uploads/2018/06/GPD_Device_API_Access_Control_v1.0_PublicRelease.pdf
+//!
+//! The comments in this file reference those documents as ARA-M and ARA-D, respectively.
+//!
+//! Parse errors are reported as strings, generally using [`anyhow::bail`], because it's expected
+//! that the only useful thing that can be done with errors is to log them so humans can examine
+//! and repair the rules.
+
+use super::{tlv, xml};
+use anyhow::{anyhow, bail, ensure, Context, Result};
+use itertools::{izip, Itertools};
+use log::{info, trace};
+use std::{
+    array::TryFromSliceError,
+    cmp::Ordering,
+    collections::{btree_map::Entry, BTreeMap, BTreeSet},
+};
+
+#[cfg(test)]
+mod test;
+
+pub const SHA1_OR_UUID_LEN: usize = 20;
+pub const SHA256_LEN: usize = 32;
+pub const APDU_HEADER_LEN: usize = 4;
+/// An APDU filter set consists of two byte arrays the same length as an APDU header.  One is a
+/// mask that is bitwise ANDed with the header and the other is a pattern that is compared with
+/// the mask result.
+pub const APDU_FILTER_SET_LEN: usize = 2 * APDU_HEADER_LEN;
+
+#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
+pub struct Sha256Digest(pub [u8; SHA256_LEN]);
+
+#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
+pub struct Sha1DigestOrUuid(pub [u8; SHA1_OR_UUID_LEN]);
+
+/// [`DeviceAppId`] identifes the client that wishes to use the Secure element.  Clients may be
+/// APKs, which are identified by their certificate hashes (SHA-256 or SHA-1) and, optionally,
+/// package names, or they may be system components, which are identified by a UUID.
+///
+/// Note that [`DeviceAppId`] is filled out by the system when it identifies the caller.  Compare
+/// to [`DeviceAppIdRef`] and [`DeviceAppPkgRef`], the ARA rule structures that are matched
+/// against [`DeviceAppId`].
+#[derive(PartialEq)]
+pub enum DeviceAppId {
+    Apk {
+        /// SHA-256 hashes of all of the APK's signing certificates.
+        sha256s: Vec<Sha256Digest>,
+        /// SHA-1 hashes of all of the APK's signing certificates.
+        sha1s: Vec<Sha1DigestOrUuid>,
+        /// APK package names.  Note that although a client has a single package name, shared UIDs
+        /// make it impossible to identify which package is the caller, so all are checked.
+        package_names: Vec<String>,
+    },
+    SystemComponent {
+        /// UUIDs of the system component.  Components should probably have only one UUID, but the
+        /// UUID mapping file format does not prevent mapping a uid to multiple UUIDs, so we allow
+        /// for more than one.
+        uuids: Vec<Sha1DigestOrUuid>,
+    },
+}
+
+impl DeviceAppId {
+    /// Construct a [`DeviceAppId`] for an APK with the provided hashes, UUIDs and package names.
+    pub fn new_apk(
+        sha256s: Vec<Sha256Digest>,
+        sha1s: Vec<Sha1DigestOrUuid>,
+        package_names: Vec<String>,
+    ) -> Self {
+        DeviceAppId::Apk { sha256s, sha1s, package_names }
+    }
+
+    /// Construct a [`DeviceAppId`] for a system component with the provided UUIDs.
+    pub fn new_system_component(uuids: Vec<Sha1DigestOrUuid>) -> Self {
+        DeviceAppId::SystemComponent { uuids }
+    }
+}
+
+impl std::fmt::Debug for DeviceAppId {
+    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        match self {
+            DeviceAppId::Apk { sha256s, sha1s, package_names } => {
+                write!(
+                formatter,
+                "DeviceAppId: Apk {{ Sha1CertHashes: [{}], Sha256CertHashes [{}], PackageNames [{}] }} ",
+                sha1s.iter().map(hex::encode).join(", "),
+                sha256s.iter().map(hex::encode).join(", "),
+                package_names.iter().join(", "),
+            )
+            }
+            DeviceAppId::SystemComponent { uuids } => {
+                write!(
+                    formatter,
+                    "DeviceAppId: SystemComponent: {{ UUIDs: [{}] }}",
+                    uuids.iter().map(hex::encode).join(", "),
+                )
+            }
+        }
+    }
+}
+
+/// AppletId identifies a target applet, either by AID (applet ID) or by specifying the SE
+/// channel's default.
+///
+/// Note that the library doesn't know which applet is default, it just determines whether the
+/// rules allow whichever applet is the default (the one implicitly selected by opening a channel
+/// to the applet without specifying an AID) to be accessed by the specified app.
+#[derive(Debug, PartialEq, Clone)]
+pub enum AppletId<'a> {
+    /// Specifies an applet by AID; references the bytes of the AID value.
+    Aid(&'a [u8]),
+    /// Specifies that the default-selected applet is being used.
+    DefaultApplet,
+}
+
+impl<'a> AppletId<'a> {
+    pub fn new(aid: &'a [u8]) -> Self {
+        if aid.is_empty() {
+            AppletId::DefaultApplet
+        } else {
+            AppletId::Aid(aid)
+        }
+    }
+}
+
+/// ARA rules are ranked by specificity, and are evaluated strictly in the order defined by this
+/// enum, "Carrier" first.  The reason for the naming is that "Least" to "Highest" are the
+/// priorities defined in the first ARA-M document, and "Carrier" represents the even higher,
+/// carrier-only priority level defined by ARA-D.
+#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
+enum RuleSpecificity {
+    /// Specifies device app & package name
+    Carrier,
+    /// Specifies AID and device app
+    Highest,
+    /// Specifies AID, matches any device app
+    High,
+    /// Matches any AID, specifies device app
+    Low,
+    /// Matches any AID and any device app
+    Least,
+}
+
+/// Collection of ARA rules, which can be queried to check access permissionss.
+///
+/// Corresponds to Response-ALL-REF-DO.  See ARA-M page 35.
+#[derive(Debug, Clone)]
+pub struct RuleCache {
+    /// ARA rules to be applied.  Will be checked in the order they're found in the vector, which
+    /// means they must be ordered correctly when the [`RuleCache`] is created.
+    rules: Vec<Rule>,
+}
+
+impl RuleCache {
+    /// This method constructs a [`RuleCache`] from an iterator over [`Rule`]s, but it does some
+    /// extra work to implement meta-rules that would be applied at evaluation time, i.e.  when
+    /// trying to compute access for an AID and app.  By doing some extra work now we can
+    /// pre-compute the result of the meta-rules so the work doesn't have to be done during
+    /// evaluation. We do the following:
+    ///
+    /// 1.  Access merging.  The specification requires that if multiple rules match a request,
+    ///     the strictest of their access specifications win.  But because of the hierarchical way
+    ///     the rules are evaluated, the only way two (or more) rules can match a request is if
+    ///     they have the same match criteria, i.e. specify the same AID and App.  We handle this
+    ///     by finding such redundant rules and pre-merging them.  The result is that there is
+    ///     only one rule for any match criteria pair (AID and app).
+    ///
+    /// 2.  AID shadowing.  The specification requires that if an app-wildcard rule (specific AID,
+    ///     but any app) matches a request, but there is some fully-specific rule (specifies AID
+    ///     and app) that references the same AID but a different app, the engine should deny the
+    ///     request.  We handle this by finding any app-wildcard rules that are "shadowed" by
+    ///     specific rules and setting their access to NEVER.
+    ///
+    /// 3.  App shadowing.  The specification requires that if a fully generic rule (any AID, any
+    ///     app) matches a request, but there exists an AID wildcard rule (any AID, specific app)
+    ///     that matches a different app, the engine must return NEVER, which is the same thing it
+    ///     returns if no rules match.  Therefore, if there are any AID wildcard rules, we discard
+    ///     any fully-generic rules.
+    ///
+    /// 4.  Priority hierarchy.  Rules must be applied in strict priority order (based on
+    ///     specificity/genericity).  We handle this by sorting the rules by
+    ///     [`MatchCriteria::cmp`], which is defined to produce the correct order.  Sorting is
+    ///     provided by the [`BTreeMap`].
+    ///
+    /// By applying these optimizations now, we don't have to bother with these meta-rules at
+    /// evaluation time.  We can just apply the rules sequentially, taking the first match.
+    pub fn new<I>(rules_iter: I) -> Self
+    where
+        I: IntoIterator<Item = Rule>,
+    {
+        let mut rules = construct_merged_rule_map(rules_iter);
+        handle_aid_shadowing_rule(&mut rules);
+        handle_app_shadowing(&mut rules);
+        RuleCache { rules: rules.into_iter().map(Rule::from_tuple).collect() }
+    }
+
+    /// Convert parsed-TLV object containing rules to a [`Vec<Rule>`], preparatory to creating a
+    /// [`RuleCache`] (perhaps containing rules from multiple sources).
+    pub fn tlv_to_rules(tlv: tlv::Object) -> Result<Vec<Rule>> {
+        ensure!(*tlv.tag() == tlv::Tag::ResponseAllRefArDo);
+        let value = tlv.get_content();
+        match value {
+            tlv::Value::Empty => Ok(Vec::new()),
+            tlv::Value::Constructed(vec) => {
+                vec.into_iter().filter(is_known_tag).map(Rule::from_tlv).collect()
+            }
+            tlv::Value::Primitive(_) => {
+                bail!("Invalid RuleCache content {}", value)
+            }
+        }
+    }
+
+    /// Returns the APDU access restrictions for the specified device app and AID.  To check the
+    /// default-selected applet specify [`AppletId::DefaultApplet`] for `aid`.
+    pub fn get_apdu_rule(&self, app: &DeviceAppId, aid: &AppletId) -> &ApduAccessRule {
+        trace!("Checking APDU access to {aid:02x?} for {app:?}");
+        &self.get_rules(app, aid).apdu
+    }
+
+    /// Check whether the specified app should be notified about NFC events related to the
+    /// specified applet.  To check the default-selected applet specify
+    /// [`AppletId::DefaultApplet`] for `aid`.
+    pub fn check_nfc(&self, app: &DeviceAppId, aid: &AppletId) -> bool {
+        trace!("Checking NFC access to {aid:02x?} for {app:?}");
+        self.get_rules(app, aid).nfc == NfcAccessRule::Always
+    }
+
+    /// Returns the access rules, both APDU and NFC, for the specified device app and AID.  To
+    /// check the default-selected applet specify [`AppletId::DefaultApplet`] for `applet`.
+    fn get_rules(&self, app: &DeviceAppId, aid: &AppletId) -> &AccessRules {
+        self.rules
+            .iter()
+            .find_map(|rule| rule.criteria.matches(app, aid).then_some(&rule.access))
+            .unwrap_or(&AccessRules::NEVER)
+    }
+
+    #[cfg(test)]
+    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
+        Ok(Self::new(Self::tlv_to_rules(tlv)?))
+    }
+
+    #[cfg(test)]
+    fn check_apdu(&self, app: &DeviceAppId, aid: &AppletId, apdu_header: &ApduHeader) -> bool {
+        self.get_apdu_rule(app, aid).allow_apdu(apdu_header)
+    }
+}
+
+/// Merge rules from an iterator into a map.  "Merge" means that where two [`Rule`]s have the same
+/// [`MatchCriteria`], their [`AccessRules`]s are merged.
+fn construct_merged_rule_map<I>(rules: I) -> BTreeMap<MatchCriteria, AccessRules>
+where
+    I: IntoIterator<Item = Rule>,
+{
+    let mut map = BTreeMap::new();
+    for rule in rules {
+        match map.entry(rule.criteria) {
+            Entry::Vacant(entry) => {
+                entry.insert(rule.access);
+            }
+            Entry::Occupied(mut entry) => entry.get_mut().merge(rule.access),
+        }
+    }
+    map
+}
+
+/// Handle AID shadowing by setting [`AccessRules::NEVER`] for any app-wildcard rule (i.e.
+/// [`RuleSpecificity::High`]) with an AID that is mentioned in a fully-specified (i.e.
+/// [`RuleSpecificity::Highest`] rule.
+fn handle_aid_shadowing_rule(rules: &mut BTreeMap<MatchCriteria, AccessRules>) {
+    let mut shadowing_aids = BTreeSet::new();
+    for (criteria, _) in rules.iter() {
+        if criteria.specificity() == RuleSpecificity::Highest {
+            shadowing_aids.insert(criteria.aid_ref.clone());
+        }
+    }
+
+    for (criteria, access) in rules.iter_mut() {
+        if criteria.specificity() == RuleSpecificity::High
+            && shadowing_aids.contains(&criteria.aid_ref)
+        {
+            *access = AccessRules::NEVER;
+        }
+    }
+}
+
+/// Handle app shadowing by removing any fully-generic rules ([`RuleSpecificity::Least`]) if any
+/// AID-wildcard ([`RuleSpecificity::Low`]) rules exist.
+///
+/// We search in reverse order because [`Iterator::any`] short-circuits and
+/// [`RuleSpecificity::Low`] rules are towards the end of the rule set. Minor efficiency tweak.
+fn handle_app_shadowing(rules: &mut BTreeMap<MatchCriteria, AccessRules>) {
+    if rules.iter().rev().any(|(criteria, _)| criteria.specificity() == RuleSpecificity::Low) {
+        rules.retain(|criteria, _| criteria.specificity() != RuleSpecificity::Least);
+    };
+}
+
+/// An access rule, specifying the conditions of match and the access permissions/restrictions to
+/// be applied.
+///
+/// Corresponds to REF-AR-DO.  See ARA-M page 68.
+#[derive(Debug, Clone, PartialEq)]
+pub struct Rule {
+    criteria: MatchCriteria,
+    access: AccessRules,
+}
+
+impl Rule {
+    fn from_tuple(tuple: (MatchCriteria, AccessRules)) -> Self {
+        let (criteria, access) = tuple;
+        Self { criteria, access }
+    }
+
+    /// Create a [`Rule`] from a [`tlv::Object`].  Returns [`Err`] if the object does not contain
+    /// a valid REF-AR-DO structure.
+    pub(crate) fn from_tlv(tlv: tlv::Object) -> Result<Rule> {
+        ensure!(*tlv.tag() == tlv::Tag::RefArDo);
+        let value = tlv.get_content();
+        let tlv::Value::Constructed(vec) = value else {
+            bail!("Invalid RefArDo content {}", value);
+        };
+        Self::from_tlv_vec(vec).context("Parsing RefArDo")
+    }
+
+    /// Create a [`Rule`] from an [`xml::RefArDo`].  Returns [`Err`] if the object does not
+    /// contain a valid REF-AR-DO structure.
+    fn from_xml(ref_ar_do: xml::RefArDo) -> Result<Rule> {
+        let criteria = MatchCriteria::from_xml(ref_ar_do.get_match_criteria())?;
+        let access = AccessRules::from_xml(ref_ar_do.get_apdu_access())?;
+        Ok(Rule { criteria, access })
+    }
+
+    /// Create a [`Rule`] from a vector containing a REF-DO and AR-DO [`tlv::Object`]s.  Returns
+    /// [`Err`] if the objects are not well-formed.
+    fn from_tlv_vec(vec: Vec<tlv::Object<'_>>) -> Result<Rule> {
+        let mut access = None;
+        let mut criteria = None;
+
+        for tlv in vec.into_iter().filter(is_known_tag) {
+            match tlv.tag() {
+                tlv::Tag::RefDo => {
+                    ensure!(access.is_none(), "Found ArDo before RefDo");
+                    ensure!(criteria.is_none(), "Found multiple RefDo");
+                    criteria = Some(MatchCriteria::from_tlv(tlv).context("Parsing RefDo")?);
+                }
+                tlv::Tag::ArDo => {
+                    ensure!(access.is_none(), "Found multiple ArDo");
+                    access = Some(AccessRules::from_tlv(tlv).context("Parsing ArDo")?);
+                }
+                tag => bail!("Invalid tag {:?}", tag),
+            }
+        }
+
+        let criteria = criteria.ok_or_else(|| anyhow!("Missing RefDo"))?;
+        let access = access.ok_or_else(|| anyhow!("Missing ArDo"))?;
+
+        Ok(Rule { criteria, access })
+    }
+}
+
+/// Defines the conditions for access.
+///
+/// The order in which rules are applied depends on their match criteria.  This type implements
+/// [`Ord`] so sorted rules are in the order the specification requires them to be evaluated.
+///
+/// Corresponds to REF-DO.  See ARA-M page 68 and page ARA-D page 41.
+#[derive(Clone, Debug, PartialEq, Eq)]
+struct MatchCriteria {
+    aid_ref: AppletRef,
+    hash_ref: DeviceAppIdRef,
+    pkg_ref: Option<DeviceAppPkgRef>,
+}
+
+impl MatchCriteria {
+    /// Create [`MatchCriteria`] from [`tlv::Object`].
+    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
+        ensure!(*tlv.tag() == tlv::Tag::RefDo);
+        match tlv.get_content() {
+            tlv::Value::Constructed(vec) => Self::from_tlv_vec(vec),
+            other => bail!("Invalid RefDo content {}", other),
+        }
+    }
+
+    /// Create [`MatchCriteria`] from [`xml::RefDo`].
+    fn from_xml(ref_do: &xml::RefDo) -> Result<MatchCriteria> {
+        Ok(MatchCriteria {
+            aid_ref: AppletRef::from_xml(ref_do.get_aid_ref())?,
+            hash_ref: DeviceAppIdRef::from_xml(ref_do.get_app_id())?,
+            pkg_ref: None,
+        })
+    }
+
+    /// Create [`MatchCriteria`] from a vector containing one of:
+    ///
+    /// 1. AID-REF-DO || DeviceAppID-REF-DO
+    /// 2. DeviceAppID-REF-DO
+    /// 3. DeviceAppID-REF-DO || PKG-REF-DO
+    ///
+    /// (|| represents concatenation).
+    ///
+    /// Case 1 represents an ARA-M  rule.  Cases 2 and 3 are ARA-D rules and apply to all applets;
+    /// carriers apps have "device" access, i.e. access to the entire SE (though the SE will apply
+    /// its own security constraints).  This means that if we don't find an AID-REF-DO, we set
+    /// [`MatchCriteria::aid_ref`] to [`AppletRef::Carrier`].
+    fn from_tlv_vec(vec: Vec<tlv::Object>) -> Result<Self> {
+        ensure!(!vec.is_empty(), "Found empty REF-DO");
+
+        let mut pkg_ref = None;
+        let mut hash_ref = None;
+        let mut aid_ref = AppletRef::Carrier;
+
+        for (pos, entry) in vec.into_iter().filter(is_known_tag).enumerate() {
+            ensure!(pos < 2, "Found {} components in REF-DO", pos + 1);
+            match entry.tag() {
+                tlv::Tag::DeviceAppIdRefDo => {
+                    hash_ref = {
+                        ensure!(hash_ref.is_none());
+                        Some(DeviceAppIdRef::from_tlv(entry)?)
+                    }
+                }
+                tlv::Tag::PkgRefDo => {
+                    ensure!(pos == 1, "PKG-REF-DO found in position {pos}");
+                    ensure!(hash_ref.is_some(), "PKG-REF-DO not preceded by DeviceAppID-REF-DO");
+                    pkg_ref = Some(DeviceAppPkgRef::from_tlv(entry)?)
+                }
+                tlv::Tag::AidRefDoSpecificApplet | tlv::Tag::AidRefDoImplicit => {
+                    ensure!(pos == 0, "AID-REF-DO found in position {pos}");
+                    aid_ref = AppletRef::from_tlv(entry)?
+                }
+                _ => bail!("Invalid tag {} in REF-DO", entry.tag()),
+            }
+        }
+
+        Ok(Self {
+            aid_ref,
+            hash_ref: hash_ref.ok_or_else(|| anyhow!("No DeviceAppId-REF-DO in REF-DO"))?,
+            pkg_ref,
+        })
+    }
+
+    /// Returns true iff these MatchCriteria match the supplied app ID and applet ID.
+    fn matches(&self, app_id: &DeviceAppId, aid: &AppletId) -> bool {
+        self.aid_ref.matches(aid)
+            && self.hash_ref.matches(app_id)
+            && self.pkg_ref.as_ref().map_or(true, |p| p.matches(app_id))
+    }
+
+    /// Calculate the specificity-derived priority of a rule from the booleans indicating whether
+    /// the rule specifies a specific AID and/or [`super::DeviceAppId`].  See the priority table
+    /// on ARA-M page 27.
+    fn specificity(&self) -> RuleSpecificity {
+        if self.aid_ref == AppletRef::Carrier {
+            return RuleSpecificity::Carrier;
+        }
+
+        let explicit_aid = self.aid_ref != AppletRef::AllApplets;
+        let explicit_app = self.hash_ref != DeviceAppIdRef::AllApplications;
+        match (explicit_aid, explicit_app) {
+            (true, true) => RuleSpecificity::Highest,
+            (true, false) => RuleSpecificity::High,
+            (false, true) => RuleSpecificity::Low,
+            (false, false) => RuleSpecificity::Least,
+        }
+    }
+}
+
+impl PartialOrd for MatchCriteria {
+    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
+        Some(self.cmp(other))
+    }
+}
+
+impl Ord for MatchCriteria {
+    fn cmp(&self, other: &Self) -> Ordering {
+        self.specificity()
+            .cmp(&other.specificity())
+            .then(self.hash_ref.cmp(&other.hash_ref))
+            .then(self.pkg_ref.cmp(&other.pkg_ref))
+            .then(self.aid_ref.cmp(&other.aid_ref))
+    }
+}
+
+/// Defines the AID matching condition for a [`Rule`].
+///
+/// Mostly corresponds to AID-REF-DO.  See ARA-M page 66.
+///
+/// The "Carrier" variant is needed for ARA-D integration.  It is used in the case of an ARA-D
+/// rule which doesn't specify AID because carriers have access to all applets.  In that sense
+/// it's similar to the "AllApplets" wildcard case, except that Carrier rules are higher in
+/// priority and not subject to shadowing rules.
+#[derive(PartialEq, Clone, Eq, PartialOrd, Ord)]
+enum AppletRef {
+    AllApplets,
+    DefaultApplet,
+    SpecificApplet(Vec<u8>),
+    Carrier,
+}
+
+impl AppletRef {
+    /// Create a new instance from a [`tlv::Object`].
+    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
+        match tlv.tag() {
+            tlv::Tag::AidRefDoSpecificApplet => match tlv.value() {
+                tlv::Value::Empty => Ok(Self::AllApplets),
+                tlv::Value::Primitive(bytes) => Ok(Self::SpecificApplet(bytes.to_vec())),
+                tlv::Value::Constructed(_) => bail!("Found invalid content in AidRefDo"),
+            },
+            tlv::Tag::AidRefDoImplicit => match tlv.value() {
+                tlv::Value::Empty => Ok(Self::DefaultApplet),
+                _ => {
+                    bail!("Unexpected content {} in AidRefDoImplicit", tlv.value());
+                }
+            },
+            other => bail!("Found unexpected {other:?}, where AidRefDo expected."),
+        }
+    }
+
+    /// Create a new instance from an [`xml::AidRefDo`].
+    fn from_xml(aid_ref_do: &xml::AidRefDo) -> Result<Self> {
+        let aid = aid_ref_do.get_aid();
+        let aid_ref = match aid.len() {
+            0 => Self::AllApplets,
+            _ => Self::SpecificApplet(aid.to_vec()),
+        };
+        Ok(aid_ref)
+    }
+
+    /// Returns true iff the supplied [`AppletId`] matches [`self`]`.
+    fn matches(&self, applet_id: &AppletId) -> bool {
+        match self {
+            AppletRef::AllApplets | AppletRef::Carrier => true,
+            AppletRef::DefaultApplet => *applet_id == AppletId::DefaultApplet,
+            AppletRef::SpecificApplet(aid) => *applet_id == AppletId::Aid(aid),
+        }
+    }
+}
+
+impl std::fmt::Debug for AppletRef {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        match self {
+            Self::Carrier => write!(f, "Carrier"),
+            Self::AllApplets => write!(f, "AllApplets"),
+            Self::DefaultApplet => write!(f, "DefaultApplet"),
+            Self::SpecificApplet(arg0) => write!(f, "SpecificApplet({})", hex::encode(arg0)),
+        }
+    }
+}
+
+/// Defines the device app ID matching condition for a [`Rule`].
+///
+/// Corresponds to DeviceAppID-REF-DO.  See ARA-M page 67 and ARA-D page 40.
+///
+/// The reason we have a "Sha1OrUuid" variant, rather than two separate variants for SHA-1 and
+/// UUID values is because it is impossible to distinguish which of those is meant by a 20-byte
+/// value in the encoded rule.
+///
+/// Note that the order of the first two variants is important.  Rules are ordered by
+/// MatchCriteria, which are ordered first by priority, then by DeviceAppIdRef, specifically to
+/// ensure that SHA-256 IDs are tested before SHA1/UUID IDs, so [`DeviceAppIdRef::Sha256`]
+/// instances must be less than (come before in sorting order) [`DeviceAppIdRef::Sha1OrUuid`]
+/// instances.  The relative position of [`DeviceAppIdRef::AllApplications`] instances doesn't
+/// matter.
+#[derive(PartialEq, Clone, Eq, PartialOrd, Ord, Debug)]
+enum DeviceAppIdRef {
+    Sha256(Sha256Digest),
+    Sha1OrUuid(Sha1DigestOrUuid),
+    AllApplications,
+}
+
+impl DeviceAppIdRef {
+    /// Create a new instance from a [`tlv::Object`].
+    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
+        ensure!(*tlv.tag() == tlv::Tag::DeviceAppIdRefDo);
+
+        let app_id_ref = match tlv.value() {
+            tlv::Value::Empty => Self::AllApplications,
+            tlv::Value::Primitive(data) => match data.len() {
+                SHA1_OR_UUID_LEN => Self::Sha1OrUuid((*data).try_into()?),
+                SHA256_LEN => Self::Sha256((*data).try_into()?),
+                _ => bail!("Invalid DeviceAppId content length"),
+            },
+            tlv::Value::Constructed(_) => {
+                bail!("Invalid content {} found in DeviceAppIdRefDo", tlv.value())
+            }
+        };
+
+        Ok(app_id_ref)
+    }
+
+    /// Create a new instance from a [`xml::DeviceAppIdRefDo`].
+    fn from_xml(deviceappid_ref_do: &xml::DeviceAppIdRefDo) -> Result<Self> {
+        let bytes = deviceappid_ref_do.get_app_id();
+        match bytes.len() {
+            0 => Ok(Self::AllApplications),
+            SHA1_OR_UUID_LEN => Ok(Self::Sha1OrUuid(bytes.try_into()?)),
+            SHA256_LEN => Ok(Self::Sha256(bytes.try_into()?)),
+            _ => unreachable!(),
+        }
+    }
+
+    /// Returns true iff the supplied [`DeviceAppId`] matches self.
+    fn matches(&self, app_id: &DeviceAppId) -> bool {
+        match app_id {
+            DeviceAppId::Apk { sha256s, sha1s, package_names: _ } => match self {
+                DeviceAppIdRef::Sha256(sha256) => sha256s.iter().contains(&sha256),
+                DeviceAppIdRef::Sha1OrUuid(sha1) => sha1s.iter().contains(&sha1),
+                DeviceAppIdRef::AllApplications => true,
+            },
+            DeviceAppId::SystemComponent { uuids } => match self {
+                DeviceAppIdRef::Sha256(_) => false,
+                DeviceAppIdRef::Sha1OrUuid(uuid) => uuids.iter().contains(&uuid),
+                DeviceAppIdRef::AllApplications => true,
+            },
+        }
+    }
+}
+
+/// Defines an app ID matching condition based on package name.
+///
+/// This is an ARA-D feature, not an ARA-M feature. See ARA-D page 41.
+#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
+pub struct DeviceAppPkgRef(String);
+
+impl DeviceAppPkgRef {
+    /// Create a new instance from a [`tlv::Object`].
+    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
+        ensure!(*tlv.tag() == tlv::Tag::PkgRefDo);
+        match tlv.value() {
+            tlv::Value::Primitive(data) => Ok(DeviceAppPkgRef(ascii_bytes_to_string(data)?)),
+            value => bail!("Invalid content {} found in PkgRefDo", value),
+        }
+    }
+
+    fn matches(&self, app_id: &DeviceAppId) -> bool {
+        match app_id {
+            DeviceAppId::Apk { sha1s: _, sha256s: _, package_names } => {
+                package_names.iter().any(|p| *p == self.0)
+            }
+            DeviceAppId::SystemComponent { uuids: _ } => false,
+        }
+    }
+}
+
+fn ascii_bytes_to_string(bytes: &[u8]) -> Result<String> {
+    if let Ok(utf8_str) = std::str::from_utf8(bytes) {
+        if utf8_str.is_ascii() {
+            return Ok(utf8_str.to_owned());
+        }
+    }
+    bail!("Non-ASCII content in bytes.")
+}
+
+/// Defines the conditions for access.
+///
+/// Corresponds to AR-DO, see ARA-M page 69.
+#[derive(Debug, Clone, PartialEq)]
+pub struct AccessRules {
+    apdu: ApduAccessRule,
+    nfc: NfcAccessRule,
+}
+
+impl AccessRules {
+    // It's convenient to have a static [`NEVER`] rule, so we can return references to it.
+    const NEVER: AccessRules =
+        AccessRules { apdu: ApduAccessRule::Never, nfc: NfcAccessRule::Never };
+
+    /// Create [`AccessRules`] from a [`tlv::Object`].
+    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
+        ensure!(*tlv.tag() == tlv::Tag::ArDo);
+        match tlv.get_content() {
+            tlv::Value::Constructed(vec) => Self::from_tlv_vec(vec),
+            content => bail!("Invalid content {content} in ArDo"),
+        }
+    }
+
+    /// Create [`AccessRules`] from a vector of APDU-AR-DO and NFC-AR-DO objects.
+    fn from_tlv_vec(obj_vec: Vec<tlv::Object<'_>>) -> Result<Self> {
+        let mut apdu = None;
+        let mut nfc = None;
+
+        for object in obj_vec.into_iter().filter(is_known_tag) {
+            match object.tag() {
+                tlv::Tag::ApduArDo => {
+                    ensure!(apdu.is_none(), "Found multiple ApduArDo instances in ArDo");
+                    ensure!(nfc.is_none(), "Found ApduArDo instance after NfcArDo");
+                    apdu =
+                        Some(ApduAccessRule::from_tlv(object).context("Invalid ApduArDo in ArDo")?)
+                }
+                tlv::Tag::NfcArDo => {
+                    ensure!(nfc.is_none(), "Found multiple NfcArDo instances in ArDo");
+                    nfc = Some(NfcAccessRule::from_tlv(object).context("Invalid NfcArDo in ArDo")?)
+                }
+                _ => bail!("Invalid tag {} in ArDo content", object.tag()),
+            }
+        }
+
+        let (apdu, nfc) = handle_partial_ardo(apdu, nfc)?;
+        Ok(AccessRules { apdu, nfc })
+    }
+
+    fn from_xml(ar_do: &xml::ArDo) -> Result<Self> {
+        let apdu = ApduAccessRule::from_data(ar_do.get_apdu_access())?;
+        let (apdu, nfc) = handle_partial_ardo(Some(apdu), None)?;
+        Ok(AccessRules { apdu, nfc })
+    }
+    fn merge(&mut self, other: Self) {
+        self.apdu.merge(other.apdu);
+        self.nfc.merge(other.nfc);
+    }
+}
+
+fn handle_partial_ardo(
+    apdu: Option<ApduAccessRule>,
+    nfc: Option<NfcAccessRule>,
+) -> Result<(ApduAccessRule, NfcAccessRule)> {
+    // This translation table implements the logic described in ARA-M Annex G, page 128.  It
+    // handles the cases where one of APDU/NFC is not present in the rule.
+    let (apdu, nfc) = match (apdu, nfc) {
+        (Some(apdu), Some(nfc)) => (apdu, nfc),
+        (Some(ApduAccessRule::Never), None) => (ApduAccessRule::Never, NfcAccessRule::Never),
+        (Some(apdu), None) => (apdu, NfcAccessRule::Always),
+        (None, Some(nfc)) => (ApduAccessRule::Never, nfc),
+        (None, None) => bail!("Empty ArDo."),
+    };
+    Ok((apdu, nfc))
+}
+
+pub struct ApduHeader([u8; APDU_HEADER_LEN]);
+
+impl From<[u8; 4]> for ApduHeader {
+    fn from(array: [u8; 4]) -> Self {
+        ApduHeader(array)
+    }
+}
+
+/// Defines access permissions for APDU access.
+///
+/// Corresponds to APDU-AR-DO (pg. 70).
+#[derive(PartialEq, Debug, Clone)]
+pub enum ApduAccessRule {
+    /// APDU access is always allowed.
+    Always,
+    /// APDU access is allowed only if it matches one of the APDU filters.
+    PartialAllow(ApduFilterSet),
+    /// APDU access is never allowed.
+    Never,
+}
+
+impl ApduAccessRule {
+    /// Returns true if the specified APDU meets the access criteria.
+    pub fn allow_apdu(&self, apdu_header: &ApduHeader) -> bool {
+        match self {
+            ApduAccessRule::Always => true,
+            ApduAccessRule::Never => false,
+            ApduAccessRule::PartialAllow(filter_set) => filter_set.allow(apdu_header),
+        }
+    }
+
+    /// Create a new instance from a [`tlv::Object`].
+    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
+        ensure!(*tlv.tag() == tlv::Tag::ApduArDo);
+        match tlv.value() {
+            tlv::Value::Primitive(data) => Self::from_data(data),
+            _ => bail!("Invalid content {} in ApduArDo", tlv.value()),
+        }
+    }
+
+    /// Create [`ApduAccessRule`] from a buffer containing the content of an APDU-AR-DO object.
+    fn from_data(data: &[u8]) -> Result<Self> {
+        Ok(match data.len() {
+            1 => match data[0] {
+                0 => Self::Never,
+                1 => Self::Always,
+                _ => bail!("Invalid data byte {} in ApduArDo", data[0]),
+            },
+            0 => bail!("No data in ApduArDo"),
+            _ => Self::PartialAllow(
+                ApduFilterSet::from_data(data).context("Invalid ApduFilters in ApduArDo")?,
+            ),
+        })
+    }
+
+    /// Merge other into self, always taking the stricter rule.
+    fn merge(&mut self, other: Self) {
+        // Take ownership of the contents of `self`.
+        let mut this = ApduAccessRule::Always;
+        std::mem::swap(self, &mut this);
+
+        *self = match this {
+            ApduAccessRule::Never => ApduAccessRule::Never,
+            ApduAccessRule::Always => other,
+            ApduAccessRule::PartialAllow(mut this_set) => match other {
+                ApduAccessRule::Never => ApduAccessRule::Never,
+                ApduAccessRule::Always => ApduAccessRule::PartialAllow(this_set),
+                ApduAccessRule::PartialAllow(mut other_set) => {
+                    this_set.0.append(&mut other_set.0);
+                    this_set.0.sort_unstable();
+                    this_set.0.dedup();
+                    ApduAccessRule::PartialAllow(this_set)
+                }
+            },
+        };
+    }
+}
+
+/// Defines the set of allowed APDUs.  Call [`ApduFilterSet::allow`] to determine whether
+/// a given APDU should be permitted.
+#[derive(PartialEq, Debug, Clone)]
+pub struct ApduFilterSet(Vec<ApduFilter>);
+
+impl ApduFilterSet {
+    /// Create new ApduFilterSet from provided data.  Will return Err if data buffer is empty or
+    /// not a multiple of 8 bytes in length.
+    fn from_data(data: &[u8]) -> Result<Self> {
+        ensure!(
+            !data.is_empty() && data.len() % APDU_FILTER_SET_LEN == 0,
+            "Invalid data in ApduFilterSet {data:?}"
+        );
+        let mut filters: Vec<ApduFilter> =
+            data.chunks_exact(APDU_FILTER_SET_LEN).map(ApduFilter::from_data).collect();
+        filters.sort_unstable(); // Ensure that filter sets with the same contents compare Equal.
+        Ok(ApduFilterSet(filters))
+    }
+
+    /// Returns true if the specified APDU header meets the filter requirements and should be
+    /// allowed to be sent to the SE.
+    fn allow(&self, apdu_header: &ApduHeader) -> bool {
+        self.0.iter().any(|filter| filter.allow_apdu(apdu_header))
+    }
+}
+
+/// Defines a set of allowed APDUs.
+///
+/// Each of [`ApduFilter::allowed`] and [`ApduFilter::mask`] are four bytes, corresponding to the
+/// CLA, INS, P1 and P2 bytes of an APDU.  [`ApduFilter::mask`] is bitwise ANDed with the APDU to
+/// be tested and the result is compared with [`ApduFilter::allowed`].  If they match, the APDU is
+/// allowed.
+///
+/// See definition of APDU-AR-DO (pg. 70).
+#[derive(PartialEq, Clone, PartialOrd, Ord, Eq)]
+struct ApduFilter {
+    allowed: [u8; APDU_HEADER_LEN],
+    mask: [u8; APDU_HEADER_LEN],
+}
+
+impl ApduFilter {
+    /// Create new ApduFilter from provided data.  Will panic if data buffer is not 8 bytes.
+    fn from_data(data: &[u8]) -> ApduFilter {
+        let data: &[u8; APDU_FILTER_SET_LEN] =
+            data.try_into().expect("ApduFilter called with incorrect data length");
+        ApduFilter {
+            allowed: data[..APDU_HEADER_LEN].try_into().unwrap(),
+            mask: data[APDU_HEADER_LEN..].try_into().unwrap(),
+        }
+    }
+
+    /// Return true if the provided APDU header is allowed according to this rule.
+    fn allow_apdu(&self, apdu: &ApduHeader) -> bool {
+        // Check if masked value is allowed at each position (CLA, INS, P1, P2).
+        izip!(apdu.0, self.mask, self.allowed).all(|(apdu, mask, allow)| apdu & mask == allow)
+    }
+}
+
+impl std::fmt::Debug for ApduFilter {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        write!(
+            f,
+            "ApduFilter: allowed {} mask {}",
+            hex::encode(self.allowed),
+            hex::encode(self.mask)
+        )
+    }
+}
+
+/// Defines an NFC access rule.
+///
+/// Corresponds to NFC-AR-DO (pg. 71).
+#[derive(Clone, Copy, Debug, PartialEq)]
+enum NfcAccessRule {
+    Always,
+    Never,
+}
+
+impl NfcAccessRule {
+    /// Create [`NfcAccessRule`] from a [`tlv::Object`].
+    fn from_tlv(tlv: tlv::Object) -> Result<Self> {
+        ensure!(*tlv.tag() == tlv::Tag::NfcArDo);
+        match tlv.value() {
+            tlv::Value::Primitive(data) => Self::from_data(data),
+            _ => bail!("Invalid content {} in NfcArDo", tlv.value()),
+        }
+    }
+
+    /// Create [`NfcAccessRule`] from a buffer containing the content of an NFC-AR-DO object.
+    fn from_data(data: &[u8]) -> Result<Self> {
+        ensure!(data.len() == 1, "Invalid data length in NfcArDo {}", hex::encode(data));
+        match data[0] {
+            0 => Ok(Self::Never),
+            1 => Ok(Self::Always),
+            _ => bail!("Invalid data in NfcArDo {}", hex::encode(data)),
+        }
+    }
+
+    /// Merge the other access rule into self, taking the more restrictive.
+    fn merge(&mut self, other: Self) {
+        match self {
+            NfcAccessRule::Always => *self = other,
+            NfcAccessRule::Never => {}
+        }
+    }
+}
+
+/// Determine if the referenced object contains a known tag.
+fn is_known_tag(tlv: &tlv::Object) -> bool {
+    if cfg!(feature = "disallow_unknown_ara_tags") {
+        // If we're disallowing unknown ARA tags, this function just claims all tags as known,
+        // allowing the rest of the code to see the unknown tags and emit errors.
+        true
+    } else {
+        let known = !matches!(tlv.tag(), tlv::Tag::Unknown(_));
+        if !known {
+            info!("Ignoring tag {:?}", tlv.tag());
+        }
+        known
+    }
+}
+
+impl From<[u8; SHA256_LEN]> for Sha256Digest {
+    fn from(value: [u8; SHA256_LEN]) -> Self {
+        Sha256Digest(value)
+    }
+}
+
+impl TryFrom<&[u8]> for Sha256Digest {
+    type Error = TryFromSliceError;
+
+    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
+        Ok(Self(value.try_into()?))
+    }
+}
+
+impl AsRef<[u8]> for Sha256Digest {
+    fn as_ref(&self) -> &[u8] {
+        &self.0
+    }
+}
+
+impl std::fmt::Debug for Sha256Digest {
+    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        write!(formatter, "SHA-256 digest: [{}] ", hex::encode(self.0))
+    }
+}
+
+impl From<[u8; SHA1_OR_UUID_LEN]> for Sha1DigestOrUuid {
+    fn from(value: [u8; SHA1_OR_UUID_LEN]) -> Self {
+        Sha1DigestOrUuid(value)
+    }
+}
+
+impl TryFrom<&[u8]> for Sha1DigestOrUuid {
+    type Error = TryFromSliceError;
+
+    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
+        Ok(Self(value.try_into()?))
+    }
+}
+
+impl AsRef<[u8]> for Sha1DigestOrUuid {
+    fn as_ref(&self) -> &[u8] {
+        &self.0
+    }
+}
+
+impl std::fmt::Debug for Sha1DigestOrUuid {
+    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        write!(formatter, "SHA-1 digest or UUID: [{}] ", hex::encode(self.0))
+    }
+}
diff --git a/omapi/src/ara/rules/test.rs b/omapi/src/ara/rules/test.rs
new file mode 100644
index 0000000..9b99ea3
--- /dev/null
+++ b/omapi/src/ara/rules/test.rs
@@ -0,0 +1,1711 @@
+// Copyright 2024, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+use anyhow::Result;
+use log::trace;
+
+use super::tlv::{Object, Tag, Value};
+use super::*;
+use crate::test_utils::init;
+use googletest::prelude::*;
+use googletest::test as gtest;
+
+#[gtest]
+fn test_apdu_access_rule_merging() -> Result<()> {
+    init();
+
+    let values = [
+        ApduAccessRule::Always,
+        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&[0, 1, 2, 3, 4, 5, 6, 7])?),
+        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&[8, 9, 10, 11, 12, 13, 14, 15])?),
+        ApduAccessRule::Never,
+    ];
+
+    fn is_at_least_as_restrictive(a: &ApduAccessRule, b: &ApduAccessRule) -> bool {
+        match (a, b) {
+            // Never is maximally-restrictive.
+            (ApduAccessRule::Never, _) => true,
+            // Always is as restrictive as Always
+            (ApduAccessRule::Always, ApduAccessRule::Always) => true,
+            // But always is less restrictive than anything else
+            (ApduAccessRule::Always, _) => false,
+            // PartialAllow is less restrictive than Never
+            (ApduAccessRule::PartialAllow(_), ApduAccessRule::Never) => false,
+            // PartialAllow is more restrictive than Always
+            (ApduAccessRule::PartialAllow(_), ApduAccessRule::Always) => true,
+            (ApduAccessRule::PartialAllow(a_set), ApduAccessRule::PartialAllow(b_set)) => {
+                // If `b_set` is a subset of `a_set`, then `a_set` is more restrictive, so we
+                // just test if all elements of `b_set` are in `a_set`.
+                b_set.0.iter().all(|f| a_set.0.contains(f))
+            }
+        }
+    }
+
+    // For all combinations, check that merging produces rule that is at least as restrictive.
+    for (a, b) in values.iter().cartesian_product(values.iter()) {
+        let mut merged = a.clone();
+        merged.merge(b.clone());
+
+        assert!(is_at_least_as_restrictive(&merged, a), "A: {a:?}\nB: {b:?}\nM: {merged:?}\n");
+        assert!(is_at_least_as_restrictive(&merged, b), "A: {a:?}\nB: {b:?}\nM: {merged:?}\n");
+    }
+
+    Ok(())
+}
+
+#[test]
+fn test_apdu_access_rule_partial_allow_merging() -> Result<()> {
+    init();
+
+    // The merge of two distinct PartialAllows is different; it combines the filters.
+    let mut rule =
+        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&[0, 1, 2, 3, 4, 5, 6, 7])?);
+    rule.merge(ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&[7, 6, 5, 4, 3, 2, 1, 0])?));
+    if let ApduAccessRule::PartialAllow(filter) = rule {
+        assert!(
+            filter == ApduFilterSet::from_data(&[7, 6, 5, 4, 3, 2, 1, 0, 0, 1, 2, 3, 4, 5, 6, 7,])?
+        )
+    } else {
+        panic!("Merger must be a PartialAllow");
+    }
+
+    Ok(())
+}
+
+#[test]
+fn test_nfc_access_rule_merging() {
+    init();
+
+    let mut rule = NfcAccessRule::Always;
+    rule.merge(NfcAccessRule::Never);
+    assert_eq!(rule, NfcAccessRule::Never);
+
+    let mut rule = NfcAccessRule::Never;
+    rule.merge(NfcAccessRule::Always);
+    assert!(rule == NfcAccessRule::Never);
+
+    let mut rule = NfcAccessRule::Never;
+    rule.merge(NfcAccessRule::Never);
+    assert!(rule == NfcAccessRule::Never);
+
+    let mut rule = NfcAccessRule::Always;
+    rule.merge(NfcAccessRule::Always);
+    assert!(rule == NfcAccessRule::Always);
+}
+
+#[test]
+fn test_apdu_filter() -> Result<()> {
+    init();
+
+    let reject_filter = ApduFilter::from_data(&[
+        0x01, 0x02, 0x03, 0x04, // Allowed
+        0x00, 0x00, 0x00, 0x00, // Mask
+    ]);
+    let accept_filter = ApduFilter::from_data(&[
+        0x01, 0x02, 0x03, 0x04, // Allowed
+        0xFF, 0xFF, 0xFF, 0xFF, // Mask
+    ]);
+    let almost_accept_filter = ApduFilter::from_data(&[
+        0x01, 0x02, 0x03, 0x04, // Allowed
+        0xFF, 0xFF, 0x01, 0xFF, // Mask
+    ]);
+
+    let test_apdu = [0x01, 0x02, 0x03, 0x04].into();
+
+    assert!(!reject_filter.allow_apdu(&test_apdu));
+    assert!(accept_filter.allow_apdu(&test_apdu));
+    assert!(!almost_accept_filter.allow_apdu(&test_apdu));
+
+    Ok(())
+}
+
+#[test]
+fn test_apdu_filter_set() -> Result<()> {
+    init();
+
+    let filter_set = ApduFilterSet::from_data(&[
+        0x01, 0x02, 0x03, 0x04, // Allowed 1
+        0x00, 0x00, 0x00, 0x00, // Mask 1
+        0x01, 0x02, 0x03, 0x04, // Allowed 2
+        0xFF, 0xFF, 0xFF, 0xFF, // Mask 2
+    ])?;
+
+    // This test APDU should be rejected by first, allowed by second, so allowed.
+    let test_apdu = [0x01, 0x02, 0x03, 0x04].into();
+    assert!(filter_set.allow(&test_apdu));
+
+    // To confirm:
+    assert!(!filter_set.0[0].allow_apdu(&test_apdu));
+    assert!(filter_set.0[1].allow_apdu(&test_apdu));
+
+    // This test APDU should be allowed by neither, so rejected.
+    let test_apdu = [0x02, 0x02, 0x03, 0x04].into();
+    assert!(!filter_set.allow(&test_apdu));
+
+    Ok(())
+}
+
+#[gtest]
+fn test_invalid_apdu_filter_set() -> Result<()> {
+    init();
+
+    assert_that!(
+        ApduFilterSet::from_data(&[]).unwrap_err().to_string(),
+        contains_substring("Invalid data in ApduFilterSet []")
+    );
+
+    assert_that!(
+        ApduFilterSet::from_data(&[0x01]).unwrap_err().to_string(),
+        contains_substring("Invalid data in ApduFilterSet [1]")
+    );
+
+    Ok(())
+}
+
+#[gtest]
+fn test_invalid_access_rules() -> Result<()> {
+    init();
+
+    fn expect_fail(tlv: Object, want_err: &str) {
+        let err = AccessRules::from_tlv(tlv).unwrap_err();
+        assert!(err.to_string().contains(want_err));
+    }
+
+    // Invalid entry tag
+    expect_fail(
+        Object::new(
+            Tag::ArDo,
+            Value::Constructed(vec![Object::new(Tag::ArDo, Value::Primitive(&[0x01]))]),
+        ),
+        "Invalid tag",
+    );
+
+    // Invalid outer content
+    expect_fail(Object::new(Tag::ArDo, Value::Empty), "Invalid content Empty");
+    expect_fail(Object::new(Tag::ArDo, Value::Primitive(&[])), "Invalid content Primitive");
+    expect_fail(Object::new(Tag::ArDo, Value::Constructed(Vec::new())), "Empty ArDo");
+
+    expect_fail(
+        Object::new(
+            Tag::ArDo,
+            Value::Constructed(vec![
+                Object::new(Tag::ApduArDo, Value::Primitive(&[0x00])),
+                Object::new(Tag::PkgRefDo, Value::Empty),
+            ]),
+        ),
+        "Invalid tag PkgRefDo",
+    );
+
+    let contains_unknown = AccessRules::from_tlv(Object::new(
+        Tag::ArDo,
+        Value::Constructed(vec![
+            Object::new(Tag::ApduArDo, Value::Primitive(&[0x00])),
+            Object::new(Tag::new(&[0x00]), Value::Empty),
+            Object::new(Tag::NfcArDo, Value::Primitive(&[0x00])),
+        ]),
+    ));
+
+    if cfg!(feature = "disallow_unknown_ara_tags") {
+        expect_that!(
+            contains_unknown.unwrap_err().to_string(),
+            contains_substring("Invalid tag Unknown")
+        );
+    } else {
+        assert!(contains_unknown.is_ok(), "Got unexpected error {contains_unknown:?}");
+    }
+
+    Ok(())
+}
+
+#[test]
+fn test_invalid_apdu_rule() -> Result<()> {
+    init();
+
+    // Wrong content types
+    assert!(ApduAccessRule::from_tlv(Object::new(Tag::ApduArDo, Value::Empty))
+        .unwrap_err()
+        .to_string()
+        .contains("Invalid content Empty"));
+    assert!(ApduAccessRule::from_tlv(Object::new(Tag::ApduArDo, Value::Constructed(vec![])))
+        .unwrap_err()
+        .to_string()
+        .contains("Invalid content Constructed"));
+
+    // Can't be empty
+    assert!(ApduAccessRule::from_tlv(Object::new(Tag::ApduArDo, Value::Primitive(&[])))
+        .unwrap_err()
+        .to_string()
+        .contains("No data"));
+
+    // Invalid single-byte value:
+    assert!(ApduAccessRule::from_tlv(Object::new(Tag::ApduArDo, Value::Primitive(&[2])))
+        .unwrap_err()
+        .to_string()
+        .contains("Invalid data byte"));
+
+    // Invalid filter
+    assert!(ApduAccessRule::from_tlv(Object::new(Tag::ApduArDo, Value::Primitive(&[2, 3])))
+        .unwrap_err()
+        .to_string()
+        .contains("Invalid ApduFilters"));
+
+    Ok(())
+}
+
+#[test]
+fn test_invalid_nfc_rule() -> Result<()> {
+    init();
+
+    // Wrong content types
+    assert!(NfcAccessRule::from_tlv(Object::new(Tag::NfcArDo, Value::Empty))
+        .unwrap_err()
+        .to_string()
+        .contains("Invalid content Empty"));
+
+    assert!(NfcAccessRule::from_tlv(Object::new(Tag::NfcArDo, Value::Constructed(vec![])))
+        .unwrap_err()
+        .to_string()
+        .contains("Invalid content Constructed"));
+
+    // Data must be a single byte
+    assert!(NfcAccessRule::from_tlv(Object::new(Tag::NfcArDo, Value::Primitive(&[])))
+        .unwrap_err()
+        .to_string()
+        .contains("Invalid data"));
+    assert!(NfcAccessRule::from_tlv(Object::new(Tag::NfcArDo, Value::Primitive(&[1, 1])))
+        .unwrap_err()
+        .to_string()
+        .contains("Invalid data"));
+
+    // Invalid value (valid values are 0 and 1)
+    assert!(NfcAccessRule::from_tlv(Object::new(Tag::NfcArDo, Value::Primitive(&[3])))
+        .unwrap_err()
+        .to_string()
+        .contains("Invalid data"));
+
+    Ok(())
+}
+
+#[test]
+fn test_invalid_device_app_ref() -> Result<()> {
+    init();
+
+    // Invalid content type
+    assert!(DeviceAppIdRef::from_tlv(Object::new(
+        Tag::DeviceAppIdRefDo,
+        Value::Constructed(vec![])
+    ))
+    .unwrap_err()
+    .to_string()
+    .contains("Invalid content Constructed"));
+
+    // Invalid content data length (must be 20 or 32 bytes)
+    assert!(DeviceAppIdRef::from_tlv(Object::new(Tag::DeviceAppIdRefDo, Value::Primitive(&[])))
+        .unwrap_err()
+        .to_string()
+        .contains("Invalid DeviceAppId content length"));
+    assert!(DeviceAppIdRef::from_tlv(Object::new(
+        Tag::DeviceAppIdRefDo,
+        Value::Primitive(&[1; 5])
+    ))
+    .unwrap_err()
+    .to_string()
+    .contains("Invalid DeviceAppId content length"));
+
+    Ok(())
+}
+
+#[gtest]
+fn test_invalid_match_criteria_structure() -> Result<()> {
+    init();
+
+    // Missing AID and app
+    expect_that!(
+        MatchCriteria::from_tlv(Object::new(Tag::RefDo, Value::Constructed(vec![])))
+            .unwrap_err()
+            .to_string(),
+        contains_substring("Found empty REF-DO")
+    );
+
+    // Missing app
+    expect_that!(
+        MatchCriteria::from_tlv(Object::new(
+            Tag::RefDo,
+            Value::Constructed(vec![Object::new(Tag::AidRefDoImplicit, Value::Empty)]),
+        ))
+        .unwrap_err()
+        .to_string(),
+        contains_substring("No DeviceAppId-REF-DO")
+    );
+
+    // Extra entry
+    expect_that!(
+        MatchCriteria::from_tlv(Object::new(
+            Tag::RefDo,
+            Value::Constructed(vec![
+                Object::new(Tag::AidRefDoImplicit, Value::Empty),
+                Object::new(Tag::DeviceAppIdRefDo, Value::Empty),
+                Object::new(Tag::DeviceAppIdRefDo, Value::Empty)
+            ]),
+        ))
+        .unwrap_err()
+        .to_string(),
+        contains_substring("Found 3 components")
+    );
+
+    // AID and DeviceAppID out of order
+    expect_that!(
+        MatchCriteria::from_tlv(Object::new(
+            Tag::RefDo,
+            Value::Constructed(vec![
+                Object::new(Tag::DeviceAppIdRefDo, Value::Empty),
+                Object::new(Tag::AidRefDoImplicit, Value::Empty),
+            ])
+        ))
+        .unwrap_err()
+        .to_string(),
+        contains_substring("AID-REF-DO found in position 1")
+    );
+
+    // AID and PKG-REF
+    expect_that!(
+        MatchCriteria::from_tlv(Object::new(
+            Tag::RefDo,
+            Value::Constructed(vec![
+                Object::new(Tag::AidRefDoImplicit, Value::Empty),
+                Object::new(Tag::PkgRefDo, Value::Empty),
+            ])
+        ))
+        .unwrap_err()
+        .to_string(),
+        contains_substring("PKG-REF-DO not preceded by DeviceAppID")
+    );
+
+    // Invalid content type
+    let e = MatchCriteria::from_tlv(Object::new(Tag::RefDo, Value::Primitive(&[])))
+        .unwrap_err()
+        .to_string();
+    assert!(e.contains("Invalid RefDo content Primitive"), "{e}");
+    expect_that!(
+        MatchCriteria::from_tlv(Object::new(Tag::RefDo, Value::Empty)).unwrap_err().to_string(),
+        contains_substring("Invalid RefDo content Empty")
+    );
+
+    let contains_unknown = MatchCriteria::from_tlv(Object::new(
+        Tag::RefDo,
+        Value::Constructed(vec![
+            Object::new(Tag::AidRefDoImplicit, Value::Empty),
+            Object::new(Tag::new(&[0x00]), Value::Empty),
+            Object::new(Tag::DeviceAppIdRefDo, Value::Empty),
+        ]),
+    ));
+
+    if cfg!(feature = "disallow_unknown_ara_tags") {
+        expect_that!(
+            contains_unknown.unwrap_err().to_string(),
+            contains_substring("Invalid tag Unknown")
+        )
+    } else {
+        assert!(contains_unknown.is_ok(), "Got unexpected error {contains_unknown:?}");
+    }
+
+    Ok(())
+}
+
+#[test]
+fn test_invalid_applet_ref() -> Result<()> {
+    init();
+
+    // Default applet ref with invalid content
+    assert_that!(
+        AppletRef::from_tlv(Object::new(Tag::AidRefDoImplicit, Value::Primitive(&[])))
+            .unwrap_err()
+            .to_string(),
+        contains_substring("Unexpected content Primitive")
+    );
+    assert_that!(
+        AppletRef::from_tlv(Object::new(Tag::AidRefDoImplicit, Value::Constructed(vec![])))
+            .unwrap_err()
+            .to_string(),
+        contains_substring("Unexpected content Constructed")
+    );
+
+    // AID ref with invalid content
+    assert!(AppletRef::from_tlv(Object::new(
+        Tag::AidRefDoSpecificApplet,
+        Value::Constructed(vec![])
+    ))
+    .unwrap_err()
+    .to_string()
+    .contains("Found invalid content"));
+
+    // Wrong tag
+    assert_that!(
+        AppletRef::from_tlv(Object::new(Tag::ArDo, Value::Empty)).unwrap_err().to_string(),
+        contains_substring("Found unexpected ArDo")
+    );
+
+    Ok(())
+}
+
+#[test]
+fn test_empty_rule_set() -> Result<()> {
+    init();
+
+    let tlv = Object::new(Tag::ResponseAllRefArDo, Value::Empty);
+
+    let rule_set = RuleCache::from_tlv(tlv)?;
+    assert!(rule_set.rules.is_empty());
+
+    assert_eq!(
+        *rule_set.get_apdu_rule(
+            &DeviceAppId::new_apk(vec![[0; 32].into()], vec![], vec![]),
+            &AppletId::new(&[])
+        ),
+        ApduAccessRule::Never
+    );
+
+    Ok(())
+}
+
+#[gtest]
+fn test_unknown_in_rule_set() -> Result<()> {
+    let tlv = rule_set(vec![Object::new(Tag::new(&[0x00]), Value::Empty)]);
+
+    if cfg!(feature = "disallow_unknown_ara_tags") {
+        expect_that!(
+            RuleCache::from_tlv(tlv).unwrap_err().root_cause().to_string(),
+            contains_substring("Unknown")
+        );
+    } else {
+        expect_that!(RuleCache::from_tlv(tlv), ok(anything()));
+    }
+
+    Ok(())
+}
+
+#[test]
+fn test_access_rule_translation_nfc_defaults() -> Result<()> {
+    init();
+
+    // APDU NEVER, no NFC -> NFC NEVER
+    assert_eq!(
+        AccessRules::from_tlv(access_rule(apdu_access_never(), no_rule()))?.nfc,
+        NfcAccessRule::Never
+    );
+
+    // APDU ALWAYS, no NFC -> NFC ALWAYS
+    assert_eq!(
+        AccessRules::from_tlv(access_rule(apdu_access_always(), no_rule()))?.nfc,
+        NfcAccessRule::Always
+    );
+
+    // APDU FILTER, no NFC -> NFC ALWAYS
+    assert_eq!(
+        AccessRules::from_tlv(access_rule(apdu_access_filtered(&[0; 8]), no_rule()))?.nfc,
+        NfcAccessRule::Always
+    );
+
+    Ok(())
+}
+
+#[test]
+fn test_access_rule_translation_apdu_defaults() -> Result<()> {
+    init();
+
+    // no APDU, NFC NEVER -> APDU NEVER
+    assert_eq!(
+        AccessRules::from_tlv(access_rule(no_rule(), nfc_access_never()))?.apdu,
+        ApduAccessRule::Never
+    );
+
+    // no APDU, NFC ALWAYS -> APDU NEVER
+    assert_eq!(
+        AccessRules::from_tlv(access_rule(no_rule(), nfc_access_always()))?.apdu,
+        ApduAccessRule::Never
+    );
+
+    Ok(())
+}
+
+#[test]
+fn test_zen_rule_set() -> Result<()> {
+    init();
+
+    let app0 = &DeviceAppId::new_apk(vec![[0; 32].into()], vec![], vec![]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![[1; 20].into()], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+    let app3 = &DeviceAppId::new_apk(vec![[3; 32].into()], vec![], vec![]);
+    let app4 = &DeviceAppId::new_apk(vec![[4; 32].into()], vec![], vec!["the_package".to_owned()]);
+    let app5 = &DeviceAppId::new_system_component(vec![[5; 20].into()]);
+
+    let applet0 = &AppletId::new(&[0; 5]);
+    let applet1 = &AppletId::new(&[1; 5]);
+    let applet2 = &AppletId::new(&[2; 5]);
+    let applet3 = &AppletId::new(&[3; 5]);
+    let applet4 = &AppletId::new(&[4; 5]);
+    let applet5 = &AppletId::new(&[5; 5]);
+
+    let tlv_rule_set = rule_set(vec![
+        // Allow all apps to access applet0
+        rule(
+            matcher(match_aid(applet0), match_any_app()),
+            access_rule(apdu_access_always(), nfc_access_always()),
+        ),
+        // Allow app0 to access default-selected app.
+        rule(
+            matcher(match_default_applet(), match_app_sha256(app0)),
+            access_rule(apdu_access_always(), nfc_access_always()),
+        ),
+        // Allow app1 (specified with Sha1 hash) to get NFC events for applet1
+        rule(
+            matcher(match_aid(applet1), match_app_sha1(app1)),
+            access_rule(apdu_access_never(), nfc_access_always()),
+        ),
+        // Allow app1 (specified with Sha256 hash) to send INS 0xA0 to applet2
+        rule(
+            matcher(match_aid(applet2), match_app_sha256(app1)),
+            access_rule(
+                apdu_access_filtered(&[
+                    0x00, 0xA0, 0x00, 0x00, // allow
+                    0x00, 0xFF, 0x00, 0x00, // mask
+                ]),
+                nfc_access_always(),
+            ),
+        ),
+        // Another app1/applet2 rule, permissive on APDU and deny on NFC. This shouldn't change
+        // the APDU filtering above (because filtering is stricter), but should change the NfC
+        // always to never.
+        rule(
+            matcher(match_aid(applet2), match_app_sha256(app1)),
+            access_rule(apdu_access_always(), nfc_access_never()),
+        ),
+        // Allow app3 APDU access to everything, no NFC rule.
+        rule(
+            matcher(match_any_aid(), match_app_sha256(app3)),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        // Allow all apps to access applet4
+        rule(
+            matcher(match_aid(applet4), match_any_app()),
+            access_rule(apdu_access_always(), nfc_access_always()),
+        ),
+        // But also define a rule for app0 access to applet4.  This "shadows" the previous rule,
+        // preventing any app other than app0 (and app4, due to carrier access rules, see below)
+        // from using applet4.
+        rule(
+            matcher(match_aid(applet4), match_app_sha256(app0)),
+            access_rule(apdu_access_always(), nfc_access_never()),
+        ),
+        // Allow app 4 carrier-privileged access, but only with right package name.  Note that
+        // carrier rules do not participate in shadowing, so app4 also has access to applet4.
+        rule(match_carrier(app4), access_rule(apdu_access_always(), nfc_access_always())),
+        // Allow app 5, a system component, access to applet2, but APDU only, no NFC.
+        rule(
+            matcher(match_aid(applet2), match_uuid(app5)),
+            access_rule(apdu_access_always(), nfc_access_never()),
+        ),
+    ]);
+
+    let rules = RuleCache::from_tlv(tlv_rule_set)?;
+
+    trace!("Zen RuleSet: {rules:#?}");
+
+    // App0 has access to default-selected applet and applet4
+    let test_app = &app0;
+    assert_eq!(*rules.get_apdu_rule(test_app, applet0), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, applet0));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet1), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet1));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet2), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet2));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet3), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet3));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet4), ApduAccessRule::Always);
+    assert!(!rules.check_nfc(test_app, applet4));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet5), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet5));
+    assert_eq!(*rules.get_apdu_rule(test_app, &AppletId::DefaultApplet), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, &AppletId::DefaultApplet));
+
+    // App1 can also get applet1 NFC events and send INS 0xA0 APDUs to applet2
+    let test_app = &app1;
+    assert_eq!(*rules.get_apdu_rule(test_app, applet0), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, applet0));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet1), ApduAccessRule::Never);
+    assert!(rules.check_nfc(test_app, applet1));
+    assert!(rules.check_apdu(test_app, applet2, &[0x00, 0xA0, 0x01, 0x05].into()));
+    assert!(rules.check_apdu(test_app, applet2, &[0x0F, 0xA0, 0x02, 0x09].into()));
+    assert!(!rules.check_apdu(test_app, applet2, &[0x00, 0xA1, 0x01, 0x05].into()));
+    assert!(!rules.check_nfc(test_app, applet2));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet3), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet3));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet4), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet4));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet5), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet5));
+    assert_eq!(*rules.get_apdu_rule(test_app, &AppletId::DefaultApplet), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, &AppletId::DefaultApplet));
+
+    // App2 has no special access, should be denied everything except applet0 (which is
+    // open-access).
+    let test_app = &app2;
+    assert_eq!(*rules.get_apdu_rule(test_app, applet0), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, applet0));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet1), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet1));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet2), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet2));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet3), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet3));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet4), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet4));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet5), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet5));
+    assert_eq!(*rules.get_apdu_rule(test_app, &AppletId::DefaultApplet), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, &AppletId::DefaultApplet));
+
+    // App3 has APDU access to everything; NFC access is default for the APDU ALWAYS case,
+    // which per Annex G is ALWAYS.
+    let test_app = &app3;
+    assert_eq!(*rules.get_apdu_rule(test_app, applet0), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, applet0));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet1), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, applet1));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet2), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, applet2));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet3), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, applet3));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet4), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet4));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet5), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, applet5));
+    assert_eq!(*rules.get_apdu_rule(test_app, &AppletId::DefaultApplet), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, &AppletId::DefaultApplet));
+
+    // App4 has carrier access (meaning access to everything), with the correct package name.
+    let test_app = &app4;
+    assert_eq!(*rules.get_apdu_rule(test_app, applet0), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, applet0));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet1), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, applet1));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet2), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, applet2));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet3), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, applet3));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet4), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, applet4));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet5), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, applet5));
+    assert_eq!(*rules.get_apdu_rule(test_app, &AppletId::DefaultApplet), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, &AppletId::DefaultApplet));
+
+    // App5 has access to applet4, APDU only, and applet0, which is open access.
+    let test_app = &app5;
+    assert_eq!(*rules.get_apdu_rule(test_app, applet0), ApduAccessRule::Always);
+    assert!(rules.check_nfc(test_app, applet0));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet1), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet1));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet2), ApduAccessRule::Always);
+    assert!(!rules.check_nfc(test_app, applet2));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet3), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet3));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet4), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet4));
+    assert_eq!(*rules.get_apdu_rule(test_app, applet5), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, applet5));
+    assert_eq!(*rules.get_apdu_rule(test_app, &AppletId::DefaultApplet), ApduAccessRule::Never);
+    assert!(!rules.check_nfc(test_app, &AppletId::DefaultApplet));
+
+    Ok(())
+}
+
+#[test]
+fn test_highest_sha256_masks_sha1() -> Result<()> {
+    init();
+
+    let applet = AppletId::Aid(&[0; 5]);
+    check_sha_256_masks_sha1(applet.clone(), match_aid(&applet))
+}
+
+#[test]
+fn test_wildcard_aid_sha256_masks_sha1() -> Result<()> {
+    init();
+
+    let applet = AppletId::Aid(&[0; 5]);
+    check_sha_256_masks_sha1(applet, match_any_aid())
+}
+
+fn check_sha_256_masks_sha1(
+    applet: AppletId<'_>,
+    applet_matcher: Object,
+) -> std::result::Result<(), anyhow::Error> {
+    let app = DeviceAppId::new_apk(vec![[0; 32].into()], vec![[1; 20].into()], vec![]);
+
+    // Define a couple of APDU "filters".  We won't use these to filter APDUs, they're just
+    // handy ways to identify matched rules by which filter the rule contains.
+    let filter0 = [0; 8];
+    let filter1 = [1; 8];
+
+    let sha1_rule_w_filter_0 = rule(
+        matcher(applet_matcher.clone(), match_app_sha1(&app)),
+        access_rule(apdu_access_filtered(&filter0), nfc_access_always()),
+    );
+
+    let sha256_rule_w_filter_1 = rule(
+        matcher(applet_matcher.clone(), match_app_sha256(&app)),
+        access_rule(apdu_access_filtered(&filter1), nfc_access_never()),
+    );
+
+    // With only the sha1 rule, we should get filter0 & NFC allowed
+    let rules = RuleCache::from_tlv(rule_set(vec![sha1_rule_w_filter_0.clone()]))?;
+    assert_eq!(
+        *rules.get_apdu_rule(&app, &applet),
+        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter0)?)
+    );
+    assert!(rules.check_nfc(&app, &applet),);
+
+    // With only the sha256 rule, we should get filter1 & NFC denied
+    let rules = RuleCache::from_tlv(rule_set(vec![sha256_rule_w_filter_1.clone()]))?;
+    assert_eq!(
+        *rules.get_apdu_rule(&app, &applet),
+        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter1)?)
+    );
+    assert!(!rules.check_nfc(&app, &applet),);
+
+    // With both sha1 and sha256 rules, we should again get the sha256 rule content.
+    let rules = RuleCache::from_tlv(rule_set(vec![
+        sha256_rule_w_filter_1.clone(),
+        sha1_rule_w_filter_0.clone(),
+    ]))?;
+    assert_eq!(
+        *rules.get_apdu_rule(&app, &applet),
+        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter1)?)
+    );
+    assert!(!rules.check_nfc(&app, &applet),);
+
+    // Rule order shouldn't matter
+    let rules = RuleCache::from_tlv(rule_set(vec![
+        sha1_rule_w_filter_0.clone(),
+        sha256_rule_w_filter_1.clone(),
+    ]))?;
+    assert_eq!(
+        *rules.get_apdu_rule(&app, &applet),
+        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter1)?)
+    );
+    assert!(!rules.check_nfc(&app, &applet),);
+
+    Ok(())
+}
+
+#[test]
+fn test_low_rules_mask_least_rules() -> Result<()> {
+    init();
+
+    let app1 = DeviceAppId::new_apk(vec![[0; 32].into()], vec![], vec![]);
+    let app2 = DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    assert_ne!(app1, app2);
+
+    // Define a couple of APDU "filters".  We won't use these to filter APDUs, they're just
+    // handy ways to identify matched rules by which filter the rule contains.
+    let filter0 = [0; 8];
+    let filter1 = [1; 8];
+
+    let low_rule = rule(
+        matcher(match_any_aid(), match_app_sha256(&app1)),
+        access_rule(apdu_access_filtered(&filter0), nfc_access_never()),
+    );
+
+    let least_rule = rule(
+        matcher(match_any_aid(), match_any_app()),
+        access_rule(apdu_access_filtered(&filter1), nfc_access_never()),
+    );
+
+    let applet = AppletId::Aid(&[0; 5]);
+
+    // With only the low rule, we should get filter0 for app1 and NEVER for app2.
+    let rules = RuleCache::from_tlv(rule_set(vec![low_rule.clone()]))?;
+    assert_eq!(
+        *rules.get_apdu_rule(&app1, &applet),
+        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter0)?)
+    );
+    assert_eq!(*rules.get_apdu_rule(&app2, &applet), ApduAccessRule::Never,);
+
+    // With only the least rule, we should get filter1 for both apps.
+    let rules = RuleCache::from_tlv(rule_set(vec![least_rule.clone()]))?;
+    assert_eq!(
+        *rules.get_apdu_rule(&app1, &applet),
+        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter1)?)
+    );
+    assert_eq!(
+        *rules.get_apdu_rule(&app2, &applet),
+        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter1)?)
+    );
+
+    // With both rules, we should get filter1 for app1, but NEVER for app2, because the low
+    // rule masks the least rule, making it inapplicable.
+    // With only the least rule, we should get filter1 for both apps.
+    let rules = RuleCache::from_tlv(rule_set(vec![least_rule.clone(), low_rule.clone()]))?;
+    assert_eq!(
+        *rules.get_apdu_rule(&app1, &applet),
+        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter0)?)
+    );
+    assert_eq!(*rules.get_apdu_rule(&app2, &applet), ApduAccessRule::Never);
+
+    // Rule order doesn't matter.
+    let rules = RuleCache::from_tlv(rule_set(vec![low_rule.clone(), least_rule.clone()]))?;
+    assert_eq!(
+        *rules.get_apdu_rule(&app1, &applet),
+        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&filter0)?)
+    );
+    assert_eq!(*rules.get_apdu_rule(&app2, &applet), ApduAccessRule::Never);
+
+    Ok(())
+}
+
+#[test]
+fn test_invalid_rule_set() -> Result<()> {
+    init();
+
+    // Wrong tag
+    assert_that!(
+        RuleCache::from_tlv(Object::new(Tag::ArDo, Value::Empty))
+            .unwrap_err()
+            .root_cause()
+            .to_string(),
+        contains_substring("ArDo vs ResponseAllRefArDo")
+    );
+
+    // Wrong content type
+    assert_that!(
+        RuleCache::from_tlv(Object::new(Tag::ResponseAllRefArDo, Value::Primitive(&[])))
+            .unwrap_err()
+            .root_cause()
+            .to_string(),
+        contains_substring("Invalid RuleCache content Primitive")
+    );
+
+    Ok(())
+}
+
+#[gtest]
+fn test_invalid_rule() -> Result<()> {
+    init();
+
+    // Wrong content type
+    expect_that!(
+        Rule::from_tlv(Object::new(Tag::RefArDo, Value::Empty)).unwrap_err().to_string(),
+        contains_substring("Invalid RefArDo content Empty")
+    );
+    expect_that!(
+        Rule::from_tlv(Object::new(Tag::RefArDo, Value::Primitive(&[]))).unwrap_err().to_string(),
+        contains_substring("Invalid RefArDo content Primitive")
+    );
+
+    // Missing match criteria
+    expect_that!(
+        Rule::from_tlv(Object::new(Tag::RefArDo, Value::Constructed(vec![])))
+            .unwrap_err()
+            .root_cause()
+            .to_string(),
+        contains_substring("Missing RefDo")
+    );
+
+    // Missing access rules
+    expect_that!(
+        Rule::from_tlv(Object::new(
+            Tag::RefArDo,
+            Value::Constructed(vec![matcher(match_any_aid(), match_any_app())])
+        ))
+        .unwrap_err()
+        .root_cause()
+        .to_string(),
+        contains_substring("Missing ArDo")
+    );
+
+    // Extra entry
+    expect_that!(
+        Rule::from_tlv(Object::new(
+            Tag::RefArDo,
+            Value::Constructed(vec![
+                matcher(match_any_aid(), match_any_app()),
+                access_rule(apdu_access_always(), nfc_access_always()),
+                access_rule(apdu_access_always(), nfc_access_always()),
+            ])
+        ))
+        .unwrap_err()
+        .root_cause()
+        .to_string(),
+        contains_substring("Found multiple")
+    );
+
+    // Unknown tag
+    let contains_unknown = Rule::from_tlv(Object::new(
+        Tag::RefArDo,
+        Value::Constructed(vec![
+            matcher(match_any_aid(), match_any_app()),
+            Object::new(Tag::new(&[0x00]), Value::Empty),
+            access_rule(apdu_access_always(), nfc_access_always()),
+        ]),
+    ));
+
+    if cfg!(feature = "disallow_unknown_ara_tags") {
+        expect_that!(
+            contains_unknown.unwrap_err().root_cause().to_string(),
+            contains_substring("Invalid tag Unknown")
+        );
+    } else {
+        assert!(contains_unknown.is_ok(), "Got unexpected error {contains_unknown:?}");
+    }
+
+    Ok(())
+}
+
+// Test case from page 106
+#[test]
+fn test_gp_doc_test_case_1() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![rule(
+        matcher(match_aid(applet1), match_app_sha256(app1)),
+        access_rule(apdu_access_always(), no_rule()),
+    )]))?;
+    trace!("{rules:?}");
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
+    // Doc doesn't say what NFC access should be.
+
+    assert!(rules.check_apdu(app1, applet1, &[0; 4].into()));
+    assert!(!rules.check_apdu(app1, applet2, &[0; 4].into()));
+
+    Ok(())
+}
+
+// Test case from page 106
+#[test]
+fn test_gp_doc_test_case_2() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app1)),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app2)),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+    ]))?;
+    trace!("{rules:?}");
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);
+
+    Ok(())
+}
+
+// Test case on page 106
+#[test]
+fn test_gp_doc_test_case_3() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![rule(
+        matcher(match_aid(applet1), match_app_sha256(app1)),
+        access_rule(apdu_access_never(), no_rule()),
+    )]))?;
+    trace!("{rules:?}");
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);
+
+    Ok(())
+}
+
+// Test case on page 106
+#[test]
+fn test_gp_doc_test_case_4() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app1)),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app1)),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+    ]))?;
+    trace!("{rules:?}");
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);
+
+    Ok(())
+}
+
+// Test case on page 106
+#[test]
+fn test_gp_doc_test_case_5() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![rule(
+        matcher(match_aid(applet1), match_app_sha256(app1)),
+        access_rule(apdu_access_filtered(&[1; 8]), no_rule()),
+    )]))?;
+    trace!("{rules:?}");
+
+    assert_eq!(
+        *rules.get_apdu_rule(app1, applet1),
+        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&[1; 8])?)
+    );
+    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);
+
+    Ok(())
+}
+
+// Test case on page 106
+#[test]
+fn test_gp_doc_test_case_6() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let applet3 = &AppletId::Aid(&[3]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app2)),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet2), match_app_sha256(app2)),
+            access_rule(apdu_access_filtered(&[1; 8]), no_rule()),
+        ),
+        rule(
+            matcher(match_any_aid(), match_app_sha256(app2)),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+    ]))?;
+    trace!("{rules:#?}");
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
+    assert_eq!(
+        *rules.get_apdu_rule(app2, applet2),
+        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&[1; 8])?)
+    );
+    assert_eq!(*rules.get_apdu_rule(app1, applet3), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet3), ApduAccessRule::Always);
+
+    Ok(())
+}
+
+// Test case on page 106
+#[gtest]
+fn test_gp_doc_test_case_7() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app1)),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app2)),
+            access_rule(apdu_access_filtered(&[1; 8]), no_rule()),
+        ),
+    ]))?;
+    trace!("{rules:?}");
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
+    assert_eq!(
+        *rules.get_apdu_rule(app2, applet1),
+        ApduAccessRule::PartialAllow(ApduFilterSet::from_data(&[1; 8])?)
+    );
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);
+
+    Ok(())
+}
+
+// Test case on page 107
+#[gtest]
+fn test_gp_doc_test_case_9() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app1)),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet1), match_any_app()),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+    ]))?;
+    trace!("{rules:?}");
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);
+
+    Ok(())
+}
+
+// Test case on page 107
+#[gtest]
+fn test_gp_doc_test_case_10() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app1)),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet1), match_any_app()),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+    ]))?;
+    trace!("{rules:?}");
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);
+
+    Ok(())
+}
+
+// Test case on page 107
+#[gtest]
+fn test_gp_doc_test_case_11() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app1)),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet1), match_any_app()),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+    ]))?;
+    trace!("{rules:?}");
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);
+
+    Ok(())
+}
+
+// Test case on page 107
+#[test]
+fn test_gp_doc_test_case_12() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app1)),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet1), match_any_app()),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+    ]))?;
+    trace!("{rules:?}");
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);
+
+    Ok(())
+}
+
+// Test case on page 107
+#[gtest]
+fn test_gp_doc_test_case_13() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![rule(
+        matcher(match_any_aid(), match_any_app()),
+        access_rule(apdu_access_always(), no_rule()),
+    )]))?;
+    trace!("{rules:?}");
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Always);
+
+    Ok(())
+}
+
+// Test case on page 107
+#[gtest]
+fn test_gp_doc_test_case_14() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app1)),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet1), match_any_app()),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+    ]))?;
+    trace!("{rules:?}");
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);
+
+    Ok(())
+}
+
+// Test case on page 108
+#[test]
+fn test_gp_doc_test_case_15() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let applet3 = &AppletId::Aid(&[3]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![
+        rule(
+            matcher(match_aid(applet1), match_any_app()),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet2), match_any_app()),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        rule(
+            matcher(match_any_aid(), match_any_app()),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+    ]))?;
+    trace!("{rules:?}");
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app1, applet3), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet3), ApduAccessRule::Never);
+
+    Ok(())
+}
+
+// Test case on page 108
+#[gtest]
+fn test_gp_doc_test_case_16() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let applet3 = &AppletId::Aid(&[3]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app1)),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet1), match_any_app()),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet2), match_app_sha256(app1)),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet2), match_any_app()),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+        rule(
+            matcher(match_any_aid(), match_app_sha256(app1)),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+        rule(
+            matcher(match_any_aid(), match_any_app()),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+    ]))?;
+    trace!("{rules:?}");
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app1, applet3), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet3), ApduAccessRule::Never);
+
+    Ok(())
+}
+
+// Test case on page 108
+#[gtest]
+fn test_gp_doc_test_case_17() -> Result<()> {
+    init();
+
+    let applet1 = &AppletId::Aid(&[1]);
+    let applet2 = &AppletId::Aid(&[2]);
+    let applet3 = &AppletId::Aid(&[3]);
+    let app1 = &DeviceAppId::new_apk(vec![[1; 32].into()], vec![], vec![]);
+    let app2 = &DeviceAppId::new_apk(vec![[2; 32].into()], vec![], vec![]);
+    let app3 = &DeviceAppId::new_apk(vec![[3; 32].into()], vec![], vec![]);
+    let app4 = &DeviceAppId::new_apk(vec![[4; 32].into()], vec![], vec![]);
+
+    let rules = RuleCache::from_tlv(rule_set(vec![
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app1)),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app2)),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet1), match_app_sha256(app3)),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet1), match_any_app()),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet2), match_app_sha256(app1)),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet2), match_app_sha256(app2)),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet2), match_app_sha256(app3)),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(applet2), match_any_app()),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        rule(
+            matcher(match_any_aid(), match_app_sha256(app1)),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        rule(
+            matcher(match_any_aid(), match_app_sha256(app2)),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        rule(
+            matcher(match_any_aid(), match_app_sha256(app3)),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        rule(
+            matcher(match_any_aid(), match_any_app()),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+    ]))?;
+    trace!("{rules:?}");
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app2, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app3, applet1), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app4, applet1), ApduAccessRule::Never);
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet2), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app2, applet2), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app3, applet2), ApduAccessRule::Never);
+    assert_eq!(*rules.get_apdu_rule(app4, applet2), ApduAccessRule::Never);
+
+    assert_eq!(*rules.get_apdu_rule(app1, applet3), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app2, applet3), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app3, applet3), ApduAccessRule::Always);
+    assert_eq!(*rules.get_apdu_rule(app4, applet3), ApduAccessRule::Never);
+
+    Ok(())
+}
+
+#[gtest]
+fn text_xml_rules() -> Result<()> {
+    init();
+
+    let text = r#"
+    <rules>
+      <ref_ar_do>
+        <ref_do>
+          <aid_ref_do>
+            A00000015141434C00
+          </aid_ref_do>
+          <deviceappid_ref_do>
+            00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
+          </deviceappid_ref_do>
+        </ref_do>
+        <ar_do>
+          <apdu_ar_do>
+            01
+          </apdu_ar_do>
+        </ar_do>
+      </ref_ar_do>
+      <ref_ar_do>
+        <ref_do>
+          <aid_ref_do>
+            A000000BCDEF
+          </aid_ref_do>
+          <deviceappid_ref_do/>
+        </ref_do>
+        <ar_do>
+          <apdu_ar_do>
+            00
+          </apdu_ar_do>
+        </ar_do>
+      </ref_ar_do>
+    </rules>"#;
+
+    let xml_rules = xml::parse_xml_rules(text.as_bytes())?
+        .ref_ar_do
+        .into_iter()
+        .map(Rule::from_xml)
+        .collect::<Result<Vec<_>>>()?;
+
+    // Create the same rules with [`tlv::Object`]s, so we can verify the constructed [`Rule`]
+    // objects are the same.
+    let aid1 = AppletId::new(&[0xA0, 0x00, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C, 0x00]);
+    let aid2 = AppletId::new(&[0xA0, 0x00, 0x00, 0x0B, 0xCD, 0xEF]);
+    let app = DeviceAppId::Apk {
+        sha1s: vec![],
+        sha256s: vec![Sha256Digest([
+            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
+            0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
+            0xCC, 0xDD, 0xEE, 0xFF,
+        ])],
+        package_names: vec![],
+    };
+
+    let tlv = vec![
+        rule(
+            matcher(match_aid(&aid1), match_app_sha256(&app)),
+            access_rule(apdu_access_always(), no_rule()),
+        ),
+        rule(
+            matcher(match_aid(&aid2), match_any_app()),
+            access_rule(apdu_access_never(), no_rule()),
+        ),
+    ];
+
+    let tlv_rules = tlv.into_iter().map(Rule::from_tlv).collect::<Result<Vec<_>>>()?;
+
+    assert_that!(xml_rules, eq(&tlv_rules));
+
+    Ok(())
+}
+
+pub fn match_any_aid() -> Object<'static> {
+    Object::new(Tag::AidRefDoSpecificApplet, Value::Empty)
+}
+
+pub fn match_aid<'a>(applet: &'a AppletId) -> Object<'a> {
+    match applet {
+        AppletId::Aid(aid) => Object::new(Tag::AidRefDoSpecificApplet, Value::Primitive(aid)),
+        AppletId::DefaultApplet => Object::new(Tag::AidRefDoImplicit, Value::Empty),
+    }
+}
+
+pub fn match_default_applet() -> Object<'static> {
+    Object::new(Tag::AidRefDoImplicit, Value::Empty)
+}
+
+pub fn match_any_app() -> Object<'static> {
+    Object::new(Tag::DeviceAppIdRefDo, Value::Empty)
+}
+
+pub fn match_app_sha256(app: &DeviceAppId) -> Object<'_> {
+    match app {
+        DeviceAppId::Apk { sha256s, sha1s: _, package_names: _ } => {
+            Object::new(Tag::DeviceAppIdRefDo, Value::Primitive(&sha256s[0].0))
+        }
+        DeviceAppId::SystemComponent { uuids: _ } => unreachable!(),
+    }
+}
+
+pub fn match_package(pkg_name: &str) -> Object<'_> {
+    Object::new(Tag::PkgRefDo, Value::Primitive(pkg_name.as_bytes()))
+}
+
+pub fn match_app_sha1(app: &DeviceAppId) -> Object {
+    match app {
+        DeviceAppId::Apk { sha256s: _, sha1s, package_names: _ } => {
+            Object::new(Tag::DeviceAppIdRefDo, Value::Primitive(&sha1s[0].0))
+        }
+        DeviceAppId::SystemComponent { uuids: _ } => unreachable!(),
+    }
+}
+
+pub fn match_uuid(app: &DeviceAppId) -> Object {
+    match app {
+        DeviceAppId::Apk { sha256s: _, sha1s: _, package_names: _ } => unreachable!(),
+        DeviceAppId::SystemComponent { uuids } => {
+            Object::new(Tag::DeviceAppIdRefDo, Value::Primitive(&uuids[0].0))
+        }
+    }
+}
+
+pub fn matcher<'a>(aid_ref: Object<'a>, app_ref: Object<'a>) -> Object<'a> {
+    Object::new(Tag::RefDo, Value::Constructed(vec![aid_ref, app_ref]))
+}
+
+pub fn match_carrier(app: &DeviceAppId) -> Object<'_> {
+    let mut vec = vec![match_app_sha256(app)];
+    match app {
+        DeviceAppId::Apk { sha256s: _, sha1s: _, package_names } => {
+            vec.push(match_package(&package_names[0]))
+        }
+        DeviceAppId::SystemComponent { uuids: _ } => unreachable!(),
+    }
+    Object::new(Tag::RefDo, Value::Constructed(vec))
+}
+
+pub fn apdu_access_never() -> Option<Object<'static>> {
+    Some(Object::new(Tag::ApduArDo, Value::Primitive(&[0x00])))
+}
+
+pub fn apdu_access_filtered(filters: &[u8]) -> Option<Object> {
+    Some(Object::new(Tag::ApduArDo, Value::Primitive(filters)))
+}
+
+pub fn apdu_access_always() -> Option<Object<'static>> {
+    Some(Object::new(Tag::ApduArDo, Value::Primitive(&[0x01])))
+}
+
+pub fn nfc_access_never() -> Option<Object<'static>> {
+    Some(Object::new(Tag::NfcArDo, Value::Primitive(&[0x00])))
+}
+
+pub fn nfc_access_always() -> Option<Object<'static>> {
+    Some(Object::new(Tag::NfcArDo, Value::Primitive(&[0x01])))
+}
+
+pub fn no_rule<'a>() -> Option<Object<'a>> {
+    None
+}
+
+pub fn access_rule<'a>(apdu_rule: Option<Object<'a>>, nfc_rule: Option<Object<'a>>) -> Object<'a> {
+    let mut vec = Vec::new();
+    if let Some(apdu_rule) = apdu_rule {
+        vec.push(apdu_rule);
+    }
+    if let Some(nfc_rule) = nfc_rule {
+        vec.push(nfc_rule);
+    }
+
+    Object::new(Tag::ArDo, Value::Constructed(vec))
+}
+
+pub fn rule<'a>(matcher: Object<'a>, access_rule: Object<'a>) -> Object<'a> {
+    Object::new(Tag::RefArDo, Value::Constructed(vec![matcher, access_rule]))
+}
+
+pub fn rule_set(rules: Vec<Object<'_>>) -> Object<'_> {
+    match rules.len() {
+        0 => Object::new(Tag::ResponseAllRefArDo, Value::Empty),
+        _ => Object::new(Tag::ResponseAllRefArDo, Value::Constructed(rules)),
+    }
+}
diff --git a/omapi/src/ara/tlv.rs b/omapi/src/ara/tlv.rs
index c966b5e..053d774 100644
--- a/omapi/src/ara/tlv.rs
+++ b/omapi/src/ara/tlv.rs
@@ -20,11 +20,13 @@
 //! parse TLV-DER, and diagnose and report non-canonical encodings.  The ARA rule set is TLV-BER
 //! encoded, not TLV-DER, because canonicalization is not required.
 
+use std::fmt;
+
 use strum_macros::{Display, EnumIter};
 use thiserror::Error;
 
 /// Trait that defines a common interface for parsing things from bytes.
-trait Parseable<'a>: 'a + Sized {
+pub trait Parseable<'a>: 'a + Sized {
     fn parse(input: &'a [u8]) -> Result<(Self, &'a [u8]), TlvParseError>;
 }
 
@@ -65,6 +67,17 @@ impl<'a> Object<'a> {
     pub fn get_content(self) -> Value<'a> {
         self.value
     }
+
+    #[cfg(test)]
+    /// Generate BER encoding of [`self`].
+    pub fn to_ber(&self) -> Vec<u8> {
+        let value_ber = self.value.to_ber();
+
+        let mut ber = self.tag.bytes().to_vec();
+        ber.extend(Asn1Length(value_ber.len()).to_ber());
+        ber.extend(value_ber);
+        ber
+    }
 }
 
 impl<'a> Parseable<'a> for Object<'a> {
@@ -87,7 +100,7 @@ impl<'a> Parseable<'a> for Object<'a> {
 /// was empty, [`Value::Constructed`], meaning the value consists of a set of zero or more
 /// contained TLV objects, or [`Value::Primitive`], meaning the value does not contain other TLV
 /// objects, but only some primitive content.  Primitive content is provided only as a byte array.
-#[derive(Display, Debug, Clone, PartialEq)]
+#[derive(Display, Clone, PartialEq)]
 pub enum Value<'a> {
     Empty,
     Primitive(&'a [u8]),
@@ -108,13 +121,48 @@ impl<'a> Value<'a> {
 
         Ok((header.tag, value, &input[header.length.0..]))
     }
+
+    #[cfg(test)]
+    fn to_ber(&self) -> Vec<u8> {
+        match self {
+            Value::Empty => vec![],
+            Value::Primitive(data) => data.to_vec(),
+            Value::Constructed(objects) => {
+                objects.iter().map(Object::to_ber).collect::<Vec<_>>().concat()
+            }
+        }
+    }
+}
+
+impl fmt::Debug for Value<'_> {
+    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
+        if fmt.alternate() {
+            match self {
+                Value::Empty => write!(fmt, "Empty"),
+                Value::Primitive(data) => write!(fmt, "Primitive (0x{})", hex::encode(data)),
+                Value::Constructed(objects) => write!(fmt, "Constructed ({objects:#?})"),
+            }
+        } else {
+            match self {
+                Value::Empty => write!(fmt, "[]"),
+                Value::Primitive(data) => write!(fmt, "[{}]", hex::encode(data)),
+                Value::Constructed(objects) => write!(fmt, "{objects:?}"),
+            }
+        }
+    }
 }
 
-struct Header {
+pub struct Header {
     tag: Tag,
     length: Asn1Length,
 }
 
+impl Header {
+    pub fn len(&self) -> usize {
+        self.length.0
+    }
+}
+
 impl Parseable<'_> for Header {
     fn parse(input: &[u8]) -> Result<(Self, &[u8]), TlvParseError> {
         let (tag, remainder) = Tag::parse(input)?;
@@ -140,6 +188,23 @@ impl Parseable<'_> for Asn1Length {
     }
 }
 
+#[cfg(test)]
+impl Asn1Length {
+    fn to_ber(&self) -> Vec<u8> {
+        match self.0 {
+            0..128 => vec![self.0 as u8],
+            128.. => {
+                // We don't need to canonicalize, but we'll do it anyway.
+                let be_bytes = self.0.to_be_bytes().to_vec();
+                let be_bytes = be_bytes.into_iter().skip_while(|b| *b == 0).collect::<Vec<u8>>();
+                let mut result = vec![be_bytes.len() as u8 | 0x80];
+                result.extend_from_slice(&be_bytes);
+                result
+            }
+        }
+    }
+}
+
 /// The set of supported tags.  Additional tags can be added if needed, though unknown tags are
 /// handled cleanly as [`Tag::Unknown`].
 #[derive(Display, Debug, Clone, EnumIter, PartialEq)]
diff --git a/omapi/src/ara/xml.rs b/omapi/src/ara/xml.rs
new file mode 100644
index 0000000..3d0327e
--- /dev/null
+++ b/omapi/src/ara/xml.rs
@@ -0,0 +1,739 @@
+// Copyright 2024, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! This module extracts ARA rules from XML. No formal schema is defined, but the structure
+//! mirrors the TLV structure and an example should make it clear. See the GP SE Access control
+//! specification.
+//!
+//! Example:
+//!
+//! ```xml
+//! <rules>
+//!   <ref-ar-do>         <!-- Each ref-ar-do contains a single rule. -->
+//!     <ref-do>          <!-- First part of a rule is the match criteria, ref-do -->
+//!       <aid-ref-do>    <!-- Match an AID -->
+//!         A00000015141434C00   <!-- AIDs are hex-encoded.  Empty means "all" -->
+//!       </aid-ref-do>
+//!       <deviceappid-ref-do>   <!-- Match a device app hash, 0, 20 or 32 bytes, in hex.
+//!                                   0 bytes means "any app", 20 bytes is a SHA-1 hash or
+//!                                   UUID, 32 bytes is a SHA-256 hash. -->
+//!         00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
+//!       </deviceappid-ref-do>
+//!     </ref-do>
+//!     <ar-do>           <!-- Second part of a rule is the access specification, ar-do -->
+//!       <apdu-ar-do>    <!-- APDU access specification -->
+//!         01            <!-- Content is hex-encoded 0, 1 or filter value. -->
+//!       </apdu-ar-do>
+//!     </ar-do>
+//!   </ref-ar-do>
+//! </rules>
+//! ```
+
+use std::io::{BufReader, Read};
+
+use hex::FromHex;
+use serde::{Deserialize, Deserializer};
+use serde_xml_rs::from_reader;
+use thiserror::Error;
+
+use super::rules::{SHA1_OR_UUID_LEN, SHA256_LEN};
+
+#[derive(Error, Debug)]
+pub enum AraXmlError {
+    #[error("Error parsing XML: {0}")]
+    XmlError(#[from] serde_xml_rs::Error),
+
+    #[error("Error decoding hex: {0}")]
+    HexError(#[from] hex::FromHexError),
+}
+
+/// Parse ARA rules from XML content in the provided [`Read`] object (e.g. a [`std::fs::File`]).
+pub fn parse_xml_rules<R: Read>(reader: R) -> Result<Rules, serde_xml_rs::Error> {
+    from_reader(BufReader::new(reader))
+}
+
+#[derive(Debug, Deserialize)]
+pub struct Rules {
+    #[serde(default)]
+    pub ref_ar_do: Vec<RefArDo>,
+}
+
+#[derive(Debug, Deserialize)]
+pub struct RefArDo {
+    ref_do: RefDo,
+    ar_do: ArDo,
+}
+
+impl RefArDo {
+    pub fn get_match_criteria(&self) -> &RefDo {
+        &self.ref_do
+    }
+
+    pub fn get_apdu_access(&self) -> &ArDo {
+        &self.ar_do
+    }
+}
+
+#[derive(Debug, Deserialize)]
+pub struct RefDo {
+    aid_ref_do: AidRefDo,
+    deviceappid_ref_do: DeviceAppIdRefDo,
+}
+
+impl RefDo {
+    pub fn get_aid_ref(&self) -> &AidRefDo {
+        &self.aid_ref_do
+    }
+
+    pub fn get_app_id(&self) -> &DeviceAppIdRefDo {
+        &self.deviceappid_ref_do
+    }
+}
+
+#[derive(Debug, Deserialize)]
+pub struct AidRefDo(#[serde(deserialize_with = "dehex_aid_ref_do")] Vec<u8>);
+
+fn dehex_aid_ref_do<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
+    let bytes = deserializer.deserialize_str(HexStrVisitor(" of len 0,5..=16"))?;
+    match bytes.len() {
+        0 | 5..=16 => Ok(bytes),
+        _ => Err(serde::de::Error::custom(hex::FromHexError::InvalidStringLength)),
+    }
+}
+
+impl AidRefDo {
+    pub fn get_aid(&self) -> &[u8] {
+        &self.0
+    }
+}
+
+#[derive(Debug, Deserialize)]
+pub struct DeviceAppIdRefDo(#[serde(deserialize_with = "dehex_app_id_ref_do")] Vec<u8>);
+
+fn dehex_app_id_ref_do<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
+    let bytes = deserializer.deserialize_str(HexStrVisitor(" of len 0|20|32"))?;
+    match bytes.len() {
+        0 | SHA1_OR_UUID_LEN | SHA256_LEN => Ok(bytes),
+        _ => Err(serde::de::Error::custom(hex::FromHexError::InvalidStringLength)),
+    }
+}
+
+impl DeviceAppIdRefDo {
+    pub fn get_app_id(&self) -> &[u8] {
+        &self.0
+    }
+}
+
+#[derive(Debug, Deserialize)]
+pub struct ArDo {
+    apdu_ar_do: ApduArDo,
+}
+
+impl ArDo {
+    pub(crate) fn get_apdu_access(&self) -> &[u8] {
+        &self.apdu_ar_do.0
+    }
+}
+
+#[derive(Debug, Deserialize)]
+struct ApduArDo(#[serde(deserialize_with = "dehex_apdu_ar_do")] Vec<u8>);
+
+fn dehex_apdu_ar_do<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
+    deserializer.deserialize_str(HexStrVisitor(""))
+}
+
+struct HexStrVisitor(&'static str);
+
+impl serde::de::Visitor<'_> for HexStrVisitor {
+    type Value = Vec<u8>;
+
+    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
+        write!(f, "a hex encoded string{}", self.0)
+    }
+
+    fn visit_str<E: serde::de::Error>(self, data: &str) -> Result<Self::Value, E> {
+        FromHex::from_hex(data).map_err(serde::de::Error::custom)
+    }
+}
+
+#[cfg(test)]
+mod test {
+    use super::*;
+    use googletest::prelude::*;
+    use googletest::test as gtest;
+
+    #[cfg(not(feature = "notandroid"))]
+    fn init() {
+        android_logger::init_once(
+            android_logger::Config::default()
+                .with_tag("se_service_xml_rules_test")
+                .with_max_level(log::LevelFilter::Trace)
+                .with_log_buffer(android_logger::LogId::System)
+                .format(|buf, record| {
+                    writeln!(
+                        buf,
+                        "{}:{} - {}",
+                        record.file().unwrap_or("unknown"),
+                        record.line().unwrap_or(0),
+                        record.args()
+                    )
+                }),
+        );
+    }
+
+    #[cfg(feature = "notandroid")]
+    fn init() {
+        let _ = env_logger::builder().is_test(true).try_init();
+    }
+
+    #[gtest]
+    fn happy() -> Result<()> {
+        init();
+
+        let text = r#"
+        <rules>
+          <ref_ar_do>
+            <ref_do>
+              <aid_ref_do>
+                A00000015141434C00
+              </aid_ref_do>
+              <deviceappid_ref_do>
+                00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
+              </deviceappid_ref_do>
+            </ref_do>
+            <ar_do>
+              <apdu_ar_do>
+                01
+              </apdu_ar_do>
+            </ar_do>
+          </ref_ar_do>
+          <ref_ar_do>
+            <ref_do>
+              <aid_ref_do>
+                A000000BCDEF
+              </aid_ref_do>
+              <deviceappid_ref_do/>
+            </ref_do>
+            <ar_do>
+              <apdu_ar_do>
+                00
+              </apdu_ar_do>
+            </ar_do>
+          </ref_ar_do>
+        </rules>"#;
+
+        let rules = parse_xml_rules(text.as_bytes())?.ref_ar_do;
+
+        expect_eq!(rules.len(), 2);
+        let ref_do = &rules[0].ref_do;
+        expect_eq!(ref_do.aid_ref_do.0, [0xA0, 0x00, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C, 0x00]);
+        expect_eq!(
+            ref_do.deviceappid_ref_do.0,
+            [
+                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
+                0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
+                0xCC, 0xDD, 0xEE, 0xFF
+            ]
+        );
+
+        let ar_do = rules[0].get_apdu_access();
+        expect_eq!(ar_do.get_apdu_access(), &[0x01]);
+
+        let ref_do = &rules[1].ref_do;
+        expect_eq!(ref_do.aid_ref_do.0, [0xA0, 0x00, 0x00, 0x0B, 0xCD, 0xEF]);
+        expect_true!(ref_do.deviceappid_ref_do.0.is_empty());
+
+        let ar_do = &rules[1].get_apdu_access();
+        expect_eq!(ar_do.get_apdu_access(), &[0x00]);
+
+        Ok(())
+    }
+
+    #[gtest]
+    fn empty_rules() -> Result<()> {
+        init();
+
+        let text = r#"
+        <rules>
+        </rules>"#;
+
+        let rules = parse_xml_rules(text.as_bytes())?;
+        expect_eq!(rules.ref_ar_do.len(), 0);
+
+        Ok(())
+    }
+
+    // This test exposes a misfeature in serde_xml_rs, that there is no way to specify that XML
+    // objects must appear in the correct order.  It would be better to be strict about this, but
+    // since we're not, at least we can test the incorrect behavior to be sure it doesn't change.
+    #[gtest]
+    fn out_of_order() -> Result<()> {
+        init();
+
+        let text = r#"
+        <rules>
+          <ref_ar_do>
+            <ar_do>
+              <apdu_ar_do>
+                01
+              </apdu_ar_do>
+            </ar_do>
+            <ref_do>
+              <aid_ref_do>
+                A00000015141434C00
+              </aid_ref_do>
+              <deviceappid_ref_do>
+                00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
+              </deviceappid_ref_do>
+            </ref_do>
+          </ref_ar_do>
+        </rules>"#;
+
+        let rules = parse_xml_rules(text.as_bytes())?.ref_ar_do;
+
+        expect_eq!(rules.len(), 1);
+        let ref_do = &rules[0].ref_do;
+        expect_eq!(ref_do.aid_ref_do.0, [0xA0, 0x00, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C, 0x00]);
+        expect_eq!(
+            ref_do.deviceappid_ref_do.0,
+            [
+                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
+                0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
+                0xCC, 0xDD, 0xEE, 0xFF
+            ]
+        );
+
+        let ar_do = &rules[0].ar_do;
+        expect_eq!(ar_do.apdu_ar_do.0, [0x01]);
+
+        Ok(())
+    }
+
+    // Similar to out of order fields, serde_xml_rs does not emit any diagnostics when parsing XML
+    // that contains unknown XML objects.  This test ensures that this (mis)behavior isn't
+    // inadvertently broken.
+    #[gtest]
+    fn unknown_tag() -> Result<()> {
+        init();
+
+        let text = r#"
+        <rules>
+        <unknown/>
+        <ref_ar_do>
+            <ref_do>
+              <aid_ref_do>
+                A00000015141434C00
+              </aid_ref_do>
+              <unknown/>
+              <deviceappid_ref_do>
+                00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
+              </deviceappid_ref_do>
+            </ref_do>
+            <ar_do>
+              <apdu_ar_do>
+                01
+              </apdu_ar_do>
+            </ar_do>
+          </ref_ar_do>
+        </rules>"#;
+
+        let rules = parse_xml_rules(text.as_bytes())?.ref_ar_do;
+
+        expect_eq!(rules.len(), 1);
+        let ref_do = &rules[0].ref_do;
+        expect_eq!(ref_do.aid_ref_do.0, [0xA0, 0x00, 0x00, 0x01, 0x51, 0x41, 0x43, 0x4C, 0x00]);
+        expect_eq!(
+            ref_do.deviceappid_ref_do.0,
+            [
+                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
+                0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
+                0xCC, 0xDD, 0xEE, 0xFF
+            ]
+        );
+
+        let ar_do = &rules[0].ar_do;
+        expect_eq!(ar_do.apdu_ar_do.0, [0x01]);
+
+        Ok(())
+    }
+
+    #[gtest]
+    fn invalid_hex_aid() -> Result<()> {
+        init();
+
+        let invalid_hex_aid = r#"
+        <rules>
+          <ref_ar_do>
+            <ref_do>
+              <aid_ref_do>
+                INVALIDHEX
+              </aid_ref_do>
+              <deviceappid_ref_do>
+                00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
+              </deviceappid_ref_do>
+            </ref_do>
+            <ar_do>
+              <apdu_ar_do>
+                01
+              </apdu_ar_do>
+            </ar_do>
+          </ref_ar_do>
+        </rules>"#;
+
+        expect_that!(
+            parse_xml_rules(invalid_hex_aid.as_bytes()).unwrap_err().to_string(),
+            contains_substring("Invalid character 'I'")
+        );
+
+        Ok(())
+    }
+
+    #[gtest]
+    fn invalid_hex_app_id() -> Result<()> {
+        init();
+
+        let invalid_hex_app_id = r#"
+        <rules>
+          <ref_ar_do>
+            <ref_do>
+              <aid_ref_do>
+                A00000015141434C00
+              </aid_ref_do>
+              <deviceappid_ref_do>
+                INVALIDHEX
+              </deviceappid_ref_do>
+            </ref_do>
+            <ar_do>
+              <apdu_ar_do>
+                01
+              </apdu_ar_do>
+            </ar_do>
+          </ref_ar_do>
+        </rules>"#;
+
+        expect_that!(
+            parse_xml_rules(invalid_hex_app_id.as_bytes()).unwrap_err().to_string(),
+            contains_substring("Invalid character 'I'")
+        );
+
+        Ok(())
+    }
+
+    #[gtest]
+    fn odd_length_aid() -> Result<()> {
+        init();
+
+        let odd_length_aid = r#"
+        <rules>
+          <ref_ar_do>
+            <ref_do>
+              <aid_ref_do>
+                A00000015141434C0
+              </aid_ref_do>
+              <deviceappid_ref_do>
+                00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
+              </deviceappid_ref_do>
+            </ref_do>
+            <ar_do>
+              <apdu_ar_do>
+                01
+              </apdu_ar_do>
+            </ar_do>
+          </ref_ar_do>
+        </rules>"#;
+
+        expect_that!(
+            parse_xml_rules(odd_length_aid.as_bytes()).unwrap_err().to_string(),
+            contains_substring("Odd number of digits")
+        );
+
+        Ok(())
+    }
+
+    #[gtest]
+    fn odd_length_app_id() -> Result<()> {
+        init();
+
+        let odd_length_app_id = r#"
+        <rules>
+          <ref_ar_do>
+            <ref_do>
+              <aid_ref_do>
+                A00000015141434C04
+              </aid_ref_do>
+              <deviceappid_ref_do>
+                00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEF
+              </deviceappid_ref_do>
+            </ref_do>
+            <ar_do>
+              <apdu_ar_do>
+                01
+              </apdu_ar_do>
+            </ar_do>
+          </ref_ar_do>
+        </rules>"#;
+
+        expect_that!(
+            parse_xml_rules(odd_length_app_id.as_bytes()).unwrap_err().to_string(),
+            contains_substring("Odd number of digits")
+        );
+
+        Ok(())
+    }
+
+    #[gtest]
+    fn too_short_aid() -> Result<()> {
+        let too_short_aid = r#"
+        <rules>
+          <ref_ar_do>
+            <ref_do>
+              <aid_ref_do>
+                01020304
+              </aid_ref_do>
+              <deviceappid_ref_do>
+                00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
+              </deviceappid_ref_do>
+            </ref_do>
+            <ar_do>
+              <apdu_ar_do>
+                01
+              </apdu_ar_do>
+            </ar_do>
+          </ref_ar_do>
+        </rules>"#;
+
+        expect_that!(
+            parse_xml_rules(too_short_aid.as_bytes()).unwrap_err().to_string(),
+            contains_substring("Invalid string length")
+        );
+
+        Ok(())
+    }
+
+    #[gtest]
+    fn too_long_aid() -> Result<()> {
+        let too_long_aid = r#"
+        <rules>
+          <ref_ar_do>
+            <ref_do>
+              <aid_ref_do>
+                000102030405060708090a0b0c0d0e0f10
+              </aid_ref_do>
+              <deviceappid_ref_do>
+                00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
+              </deviceappid_ref_do>
+            </ref_do>
+            <ar_do>
+              <apdu_ar_do>
+                01
+              </apdu_ar_do>
+            </ar_do>
+          </ref_ar_do>
+        </rules>"#;
+
+        expect_that!(
+            parse_xml_rules(too_long_aid.as_bytes()).unwrap_err().to_string(),
+            contains_substring("Invalid string length")
+        );
+
+        Ok(())
+    }
+
+    #[gtest]
+    fn invalid_length_app_id() -> Result<()> {
+        init();
+
+        let prefix = r#"
+        <rules>
+          <ref_ar_do>
+            <ref_do>
+              <aid_ref_do>
+                A00000015141434C0F
+              </aid_ref_do>
+              <deviceappid_ref_do>"#;
+
+        let suffix = r#"
+              </deviceappid_ref_do>
+            </ref_do>
+            <ar_do>
+              <apdu_ar_do>
+                01
+              </apdu_ar_do>
+            </ar_do>
+          </ref_ar_do>
+        </rules>"#;
+
+        for aid_len in (0..40).step_by(2) {
+            let aid = "FF".repeat(aid_len);
+            let xml = format!("{prefix}{aid}{suffix}");
+
+            match aid_len {
+                0 | SHA1_OR_UUID_LEN | SHA256_LEN => {
+                    let rules = parse_xml_rules(xml.as_bytes())
+                        .unwrap_or_else(|e| panic!("Failed with {e} for aid_len {aid_len}"))
+                        .ref_ar_do;
+                    expect_that!(
+                        rules[0].get_match_criteria().get_app_id().get_app_id(),
+                        len(eq(aid_len)),
+                        "{aid_len} should be valid",
+                    );
+                }
+                _ => {
+                    expect_that!(
+                        parse_xml_rules(xml.as_bytes()).unwrap_err().to_string(),
+                        contains_substring("Invalid string length"),
+                        "Test failed for {aid_len}"
+                    );
+                }
+            }
+        }
+
+        Ok(())
+    }
+
+    #[gtest]
+    fn missing_aid_ref() -> Result<()> {
+        init();
+
+        let text = r#"
+        <rules>
+          <ref_ar_do>
+            <ref_do>
+              <deviceappid_ref_do>
+                00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
+              </deviceappid_ref_do>
+            </ref_do>
+            <ar_do>
+              <apdu_ar_do>
+                01
+              </apdu_ar_do>
+            </ar_do>
+          </ref_ar_do>
+        </rules>"#;
+
+        expect_that!(
+            parse_xml_rules(text.as_bytes()).unwrap_err(),
+            matches_pattern!(serde_xml_rs::Error::Custom {
+                field: contains_substring("missing field `aid_ref_do`")
+            })
+        );
+
+        Ok(())
+    }
+
+    #[gtest]
+    fn missing_device_app_ref() -> Result<()> {
+        let text = r#"
+        <rules>
+          <ref_ar_do>
+            <ref_do>
+              <aid_ref_do>
+                A00000015141434C00
+              </aid_ref_do>
+            </ref_do>
+            <ar_do>
+              <apdu_ar_do>
+                01
+              </apdu_ar_do>
+            </ar_do>
+          </ref_ar_do>
+        </rules>"#;
+
+        expect_that!(
+            parse_xml_rules(text.as_bytes()).unwrap_err(),
+            matches_pattern!(serde_xml_rs::Error::Custom {
+                field: contains_substring("missing field `deviceappid_ref_do`")
+            })
+        );
+
+        Ok(())
+    }
+
+    #[gtest]
+    fn missing_ref_do() -> Result<()> {
+        let text = r#"
+        <rules>
+          <ref_ar_do>
+            <ar_do>
+              <apdu_ar_do>
+                01
+              </apdu_ar_do>
+            </ar_do>
+          </ref_ar_do>
+        </rules>"#;
+
+        expect_that!(
+            parse_xml_rules(text.as_bytes()).unwrap_err(),
+            matches_pattern!(serde_xml_rs::Error::Custom {
+                field: contains_substring("missing field `ref_do`")
+            })
+        );
+
+        Ok(())
+    }
+
+    #[gtest]
+    fn missing_apdu_ar_do() -> Result<()> {
+        let text = r#"
+        <rules>
+          <ref_ar_do>
+            <ref_do>
+              <aid_ref_do>
+                A00000015141434C00
+              </aid_ref_do>
+              <deviceappid_ref_do>
+                00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
+              </deviceappid_ref_do>
+            </ref_do>
+            <ar_do>
+            </ar_do>
+          </ref_ar_do>
+        </rules>"#;
+
+        expect_that!(
+            parse_xml_rules(text.as_bytes()).unwrap_err(),
+            matches_pattern!(serde_xml_rs::Error::Custom {
+                field: contains_substring("missing field `apdu_ar_do`")
+            })
+        );
+
+        Ok(())
+    }
+
+    #[gtest]
+    fn missing_ar_do() -> Result<()> {
+        let text = r#"
+        <rules>
+          <ref_ar_do>
+            <ref_do>
+              <aid_ref_do>
+                A00000015141434C00
+              </aid_ref_do>
+              <deviceappid_ref_do>
+                00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
+              </deviceappid_ref_do>
+            </ref_do>
+          </ref_ar_do>
+        </rules>"#;
+
+        expect_that!(
+            parse_xml_rules(text.as_bytes()).unwrap_err(),
+            matches_pattern!(serde_xml_rs::Error::Custom {
+                field: contains_substring("missing field `ar_do`")
+            })
+        );
+
+        Ok(())
+    }
+}
diff --git a/omapi/src/lib.rs b/omapi/src/lib.rs
index c5dcb6e..d3fee44 100644
--- a/omapi/src/lib.rs
+++ b/omapi/src/lib.rs
@@ -16,4 +16,14 @@
 
 #![deny(missing_docs)]
 
-pub mod ara;
+mod access_enforcer;
+mod ara;
+#[expect(dead_code)] // TODO: Remove when client code is added.
+mod reader;
+#[expect(dead_code)] // TODO: Remove when client code is added.
+mod system_services;
+mod terminal;
+mod utils;
+
+#[cfg(test)]
+mod test_utils;
diff --git a/omapi/src/reader.rs b/omapi/src/reader.rs
new file mode 100644
index 0000000..cfc4627
--- /dev/null
+++ b/omapi/src/reader.rs
@@ -0,0 +1,356 @@
+// Copyright 2025, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! [`Reader`] provides access to an underlying [`Terminal`], with session management and access
+//! control enforcement.
+
+use crate::{
+    access_enforcer::AccessEnforcer,
+    ara::ApduAccessRule,
+    system_services::{SystemServices, WaitForReader},
+    terminal::{ApduResponse, ChannelId, SendSelectOnClose, Terminal},
+    utils::{binder_exception, service_specific_exception,
+        ServiceSpecificException::{IoError, SecureElementNotPresent}
+     },
+};
+use android_hardware_secure_element::aidl::android::hardware::secure_element::ISecureElementCallback::{
+    BnSecureElementCallback, ISecureElementCallback};
+use binder::{BinderFeatures, ExceptionCode::{SERVICE_SPECIFIC, ILLEGAL_STATE}, Result, Status, Strong};
+use log::{debug, error, info, trace};
+use std::{
+    collections::HashMap,
+    sync::{Arc, Mutex},
+};
+
+#[cfg(test)]
+mod test;
+
+#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
+pub struct SessionId(pub u64);
+
+enum ChannelType {
+    Basic,
+    Logical,
+}
+
+/// Reader owns and provides access to an underlying SE [`Terminal`], and is responsible for
+/// managing client sessions and checking access control rules for applications trying to use the
+/// SE.
+#[derive(Debug)]
+pub struct Reader {
+    terminal: Terminal,
+    access_enforcer: AccessEnforcer,
+    system_services: Arc<dyn SystemServices>,
+    sessions: HashMap<SessionId, Vec<ChannelId>>,
+    session_id_counter: u64,
+}
+
+impl Reader {
+    pub fn new_arc(
+        name: &str,
+        wait: WaitForReader,
+        system_services: Arc<dyn SystemServices>,
+    ) -> Result<Arc<Mutex<Self>>> {
+        let se_hal = system_services.get_se_hal(name, wait)?;
+        let security_profile = system_services.get_security_profile();
+        let platform_rules = system_services.get_platform_rules(name)?;
+
+        let terminal = Terminal::new(name, se_hal.clone())?;
+        let access_enforcer = AccessEnforcer::new(security_profile, platform_rules);
+
+        let reader_arc = Arc::new(Mutex::new(Self {
+            terminal,
+            access_enforcer,
+            system_services,
+            sessions: HashMap::new(),
+            session_id_counter: 0,
+        }));
+
+        // The call to [`ISecureElement::init()`] might invoke the callback synchronously (but
+        // usually won't).  As such, the lock on `reader_arc` must not be held for the call, to
+        // prevent deadlock/double-lock.
+        debug!("Initializing SE {name}");
+        let reader_arc_clone = reader_arc.clone();
+        let se_callback = SeHalCallback::new_native_binder(move |state: bool, reason: &str| {
+            reader_arc_clone.lock().unwrap().on_state_change(state, reason)
+        });
+        se_hal.init(&se_callback)?;
+        debug!("SE {name} initialized, callback established");
+
+        Ok(reader_arc)
+    }
+
+    pub fn is_nfc_event_allowed(
+        &self,
+        aid: Option<&[u8]>,
+        package_names: &[String],
+        user_id: i32,
+    ) -> Result<Vec<bool>> {
+        let client_ids =
+            self.system_services.get_client_ids_for_packages(package_names, user_id)?;
+        self.access_enforcer.is_nfc_event_allowed(aid, &client_ids)
+    }
+
+    pub fn is_secure_element_present(&self) -> Result<bool> {
+        self.terminal.is_secure_element_present()
+    }
+
+    pub fn get_atr(&self) -> Result<Option<Vec<u8>>> {
+        self.terminal.answer_to_reset()
+    }
+
+    pub fn open_session(&mut self) -> Result<SessionId> {
+        if !self.terminal.is_secure_element_present()? {
+            service_specific_exception(SecureElementNotPresent, "Secure Element is not present.")?
+        }
+
+        let session_id = SessionId(self.session_id_counter);
+        self.sessions.insert(session_id, Vec::new());
+        self.session_id_counter += 1;
+
+        trace!("Opened {session_id:?}");
+        Ok(session_id)
+    }
+
+    pub fn open_basic_channel(
+        &mut self,
+        session_id: SessionId,
+        aid: &[u8],
+        p2: i8,
+    ) -> Result<(Option<ChannelId>, ApduAccessRule)> {
+        self.open_channel_internal(ChannelType::Basic, session_id, aid, p2)
+            .inspect_err(|err| self.close_on_ioerror(err))
+    }
+
+    pub fn open_logical_channel(
+        &mut self,
+        session_id: SessionId,
+        aid: &[u8],
+        p2: i8,
+    ) -> Result<(Option<ChannelId>, ApduAccessRule)> {
+        self.open_channel_internal(ChannelType::Logical, session_id, aid, p2)
+            .inspect_err(|err| self.close_on_ioerror(err))
+    }
+
+    /// Get the response returned by the SELECT command sent when the specified channel was
+    /// opened, if any.
+    pub fn select_response(&self, channel_id: ChannelId) -> Option<&[u8]> {
+        self.terminal.select_response(channel_id)
+    }
+
+    /// Transmit the specified `apdu` on the specified channel.  If `privileged_caller` is true,
+    /// privileged APDUs will be allowed.
+    pub fn transmit_on_channel(
+        &mut self,
+        channel_id: ChannelId,
+        apdu: &[u8],
+        privileged_caller: bool,
+    ) -> Result<ApduResponse> {
+        self.terminal
+            .transmit(channel_id, apdu, privileged_caller)
+            .inspect_err(|e| self.close_on_ioerror(e))
+    }
+
+    /// Close the specified channel, first selecting the default applet if the channel is
+    /// [`ChannelId::BASIC`] and `send_select` is `true`.
+    pub fn close_channel(
+        &mut self,
+        channel_id: ChannelId,
+        send_select: SendSelectOnClose,
+    ) -> Result<()> {
+        self.sessions
+            .iter_mut()
+            .for_each(|(_, channel_ids)| channel_ids.retain(|id| *id != channel_id));
+        self.terminal.close_channel(channel_id, send_select)
+    }
+
+    /// Close all open channels on the specified session.  If the [`ChannelId::BASIC`] channel is
+    /// open and `send_select` is `true`, the default applet will be selected.
+    pub fn close_session_channels(&mut self, id: SessionId, send_select: SendSelectOnClose) {
+        let mut tmp = Vec::new();
+        if let Some(channel_ids) = self.sessions.get_mut(&id) {
+            std::mem::swap(channel_ids, &mut tmp);
+            self.close_channel_ids(tmp, send_select);
+        } else {
+            error!("Attempted to close channels for closed {id:?}");
+        }
+    }
+
+    /// Close the specified session, and implicitly close all of the open channels on that
+    /// session, first selecting the default applet if the channel is [`ChannelId::BASIC`] and
+    /// `send_select` is `true`.
+    pub fn close_session(&mut self, id: SessionId, send_select: SendSelectOnClose) {
+        trace!("Closing {id:?}");
+        if let Some(channel_ids) = self.sessions.remove(&id) {
+            self.close_channel_ids(channel_ids, send_select);
+        } else {
+            debug!("Attempted to close closed {id:?}");
+        }
+    }
+
+    /// Close all sessions, and implicitly close all of the open channels, first selecting the
+    /// default applet if the channel is [`ChannelId::BASIC`] and `send_select` is `true`.
+    pub fn close_sessions(&mut self, send_select: SendSelectOnClose) {
+        self.terminal.close_channels(send_select);
+        self.sessions.drain().for_each(|(id, _)| trace!("Closed {id:?}"));
+    }
+
+    /// Return true iff the specified channel is closed.
+    pub fn is_channel_closed(&mut self, channel_id: ChannelId) -> bool {
+        self.terminal.channel_closed(channel_id)
+    }
+
+    /// Returns true iff the specified session has been closed.
+    pub fn is_session_closed(&self, session_id: SessionId) -> bool {
+        !self.sessions.contains_key(&session_id)
+    }
+
+    pub fn reset(&self) -> bool {
+        // TODO: Find out whether this needs to clean up sessions/channels.
+        self.terminal.reset()
+    }
+
+    fn open_channel_internal(
+        &mut self,
+        channel_type: ChannelType,
+        session_id: SessionId,
+        aid: &[u8],
+        p2: i8,
+    ) -> Result<(Option<ChannelId>, ApduAccessRule)> {
+        let policy = self.get_access_policy(aid)?;
+        let channel_id = match channel_type {
+            ChannelType::Basic => self.terminal.open_basic_channel(aid, p2)?,
+            ChannelType::Logical => self.terminal.open_logical_channel(aid, p2)?,
+        };
+
+        if let Some(channel_id) = channel_id {
+            let Some(session) = self.sessions.get_mut(&session_id) else {
+                return binder_exception(ILLEGAL_STATE, &format!("{session_id:?} is closed."));
+            };
+            session.push(channel_id);
+        }
+
+        Ok((channel_id, policy))
+    }
+
+    fn close_channel_ids(&mut self, channel_ids: Vec<ChannelId>, send_select: SendSelectOnClose) {
+        // sorted()/rev() is used so we close the basic channel last.
+        itertools::sorted(channel_ids).rev().for_each(|id| {
+            let _ = self.terminal.close_channel(id, send_select);
+        });
+    }
+
+    fn on_state_change(&mut self, connected: bool, debug_reason: &str) {
+        info!("on_state_change: connected: {connected} reason: {debug_reason}");
+
+        self.terminal.set_connected(connected);
+
+        // The Java OMAPI service starts the process of initializing the access enforcer here,
+        // reading rules from the ARA applet.  We instead defer reading of rules to the first app
+        // that tries to talk to the SE which isn't authorized by platform rules.  This is because
+        // the first apps that try to use the SE are probably authorized by platform rules and
+        // there's no reason to make the SE busy and block them while the ARA rules are read.
+        //
+        // Note that the Java service doesn't even start running until the first app tries to use
+        // it, meaning the first such app always has to wait for rules to be read so this
+        // difference in strategy won't impose any surprising latency on existing clients.
+
+        info!("Reader {} state change, resetting ACE", self.terminal.name());
+        self.access_enforcer.reset();
+    }
+
+    fn get_access_policy(&mut self, aid: &[u8]) -> Result<ApduAccessRule> {
+        let client_id = self.system_services.get_client_id()?;
+
+        // Special case:  If we haven't read the applet rules yet but the platform rules allow
+        // the access, use that result without waiting to read ARA rules.
+        if !self.access_enforcer.have_applet_rules() {
+            trace!("No applet rules, checking platform rules.");
+            if let Ok(policy) = self.access_enforcer.get_policy(aid, &client_id) {
+                trace!("Platform rules allowed");
+                return Ok(policy.clone());
+            }
+            trace!("Platform rules didn't allow");
+        }
+
+        // Normal case: Update the rule cache before retrieving policy.
+        self.update_rules()?;
+        self.access_enforcer.get_policy(aid, &client_id)
+    }
+
+    /// Update the rule cache.    In most cases this is relatively quick, requiring one APDU
+    /// exchange to check that the refresh tag has not changed.  If the rules have changed, it
+    /// will take longer.
+    fn update_rules(&mut self) -> Result<()> {
+        // The AccessEnforcer copy is a workaround for the borrow checker's conservatism.  It
+        // won't let us borrow both reader.terminal and reader.access_enforcer at the same time
+        // because that would be two mutable borrows of (parts of) reader.  Instead, we clone
+        // reader.access_enforcer, update the new copy, then move it into reader.  This isn't
+        // terribly efficient.
+        let mut access_enforcer = self.access_enforcer.clone();
+        access_enforcer.update_rule_cache(&mut self.terminal)?;
+        self.access_enforcer = access_enforcer;
+        Ok(())
+    }
+
+    #[cfg(test)]
+    pub fn get_open_sessions(&self) -> HashMap<SessionId, Vec<ChannelId>> {
+        self.sessions.clone()
+    }
+
+    fn close_on_ioerror(&mut self, err: &Status) {
+        if err.exception_code() == SERVICE_SPECIFIC
+            && err.service_specific_error() == IoError as i32
+        {
+            error!("Got IOERROR from SE, closing all sessions.");
+            self.close_sessions(SendSelectOnClose(false));
+        }
+    }
+}
+
+impl Drop for Reader {
+    fn drop(&mut self) {
+        trace!("Reader dropped, closing sessions");
+        self.close_sessions(SendSelectOnClose(false));
+    }
+}
+
+#[derive(Debug)]
+struct SeHalCallback<F>
+where
+    F: Fn(bool, &str) + Send + Sync + 'static,
+{
+    callback: F,
+}
+
+impl<F> SeHalCallback<F>
+where
+    F: Fn(bool, &str) + Send + Sync + 'static,
+{
+    fn new_native_binder(callback: F) -> Strong<dyn ISecureElementCallback> {
+        BnSecureElementCallback::new_binder(SeHalCallback { callback }, BinderFeatures::default())
+    }
+}
+
+impl<F> binder::Interface for SeHalCallback<F> where F: Fn(bool, &str) + Send + Sync + 'static {}
+
+impl<F> ISecureElementCallback for SeHalCallback<F>
+where
+    F: Fn(bool, &str) + Send + Sync + 'static,
+{
+    fn onStateChange(&self, connected: bool, debug_reason: &str) -> Result<()> {
+        (self.callback)(connected, debug_reason);
+        Ok(())
+    }
+}
diff --git a/omapi/src/reader/test.rs b/omapi/src/reader/test.rs
new file mode 100644
index 0000000..2e7ac88
--- /dev/null
+++ b/omapi/src/reader/test.rs
@@ -0,0 +1,236 @@
+// Copyright 2025, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! Testing of [`Reader`] is minimal because nearly all of its functionality is provided by
+//! sub-components which have their own tests.  Integration testing is provided at a higher level.
+
+use super::*;
+use crate::{
+    ara::Rule,
+    system_services::{ClientId, MockSystemServices, SeSecurityProfile},
+    test_utils::init,
+    utils::ServiceSpecificException,
+};
+use android_hardware_secure_element::aidl::android::hardware::secure_element::{
+    ISecureElement::{BnSecureElement, ISecureElement, MockISecureElement},
+    LogicalChannelResponse::LogicalChannelResponse,
+};
+use binder::ExceptionCode;
+use googletest::{prelude::*, test as gtest, Result};
+
+const DEFAULT_AID: &[u8] = &[];
+const TEST_P2: i8 = 0x00;
+
+#[gtest]
+fn create_reader() -> Result<()> {
+    init();
+
+    let se_binder = mock_se(|_mock| {});
+    let system_services = mock_system_services(
+        Ok(se_binder),
+        SeSecurityProfile { use_ara_applet: true, full_access: false },
+        /* platform_rules */ Ok(vec![]),
+        |_mock| {},
+    );
+    let _reader = Reader::new_arc("se_name", WaitForReader(false), system_services)?;
+
+    Ok(())
+}
+
+#[gtest]
+fn open_and_close_sessions() -> Result<()> {
+    init();
+
+    let se_binder = mock_se(|mock| {
+        mock.expect_isCardPresent().times(3).returning(|| Ok(true));
+    });
+    let system_services = mock_system_services(
+        Ok(se_binder),
+        SeSecurityProfile { use_ara_applet: true, full_access: false },
+        /* platform_rules */ Ok(vec![]),
+        |_mock| {},
+    );
+    let reader_arc = Reader::new_arc("se_name", WaitForReader(false), system_services)?;
+    let mut reader = reader_arc.lock().unwrap();
+    let session1 = reader.open_session()?;
+    let session2 = reader.open_session()?;
+    let session3 = reader.open_session()?;
+
+    assert_that!(reader.is_session_closed(session1), eq(false));
+    assert_that!(reader.is_session_closed(session2), eq(false));
+    assert_that!(reader.is_session_closed(session3), eq(false));
+    assert_that!(reader.is_session_closed(session1), eq(false));
+
+    reader.close_session(session1, SendSelectOnClose(true));
+
+    assert_that!(reader.is_session_closed(session1), eq(true));
+    assert_that!(reader.is_session_closed(session2), eq(false));
+
+    reader.close_sessions(SendSelectOnClose(true));
+
+    assert_that!(reader.is_session_closed(session1), eq(true));
+    assert_that!(reader.is_session_closed(session2), eq(true));
+    assert_that!(reader.is_session_closed(session3), eq(true));
+
+    Ok(())
+}
+
+/// [`Reader`] should close all sessions if the ARA-M read returns an I/O error.
+#[gtest]
+fn close_on_ara_io_error() -> Result<()> {
+    init();
+
+    let se_binder = mock_se(|mock| {
+        mock.expect_isCardPresent().times(2).returning(|| Ok(true));
+        mock.expect_openLogicalChannel().times(1).returning(|_, _| {
+            service_specific_exception(ServiceSpecificException::IoError, "I/O error")
+        });
+    });
+
+    let system_services = mock_system_services(
+        Ok(se_binder),
+        SeSecurityProfile { use_ara_applet: true, full_access: false },
+        /* platform_rules */ Ok(vec![]),
+        |mock| {
+            mock.expect_get_client_id().returning(|| Ok(ClientId::PackageInfo(vec![])));
+        },
+    );
+
+    let reader_arc = Reader::new_arc("se_name", WaitForReader(false), system_services)?;
+    let mut reader = reader_arc.lock().unwrap();
+    let session1 = reader.open_session()?;
+    let session2 = reader.open_session()?;
+
+    let err = reader.open_logical_channel(session1, DEFAULT_AID, TEST_P2).unwrap_err();
+    assert_that!(err.exception_code(), eq(ExceptionCode::SERVICE_SPECIFIC));
+    assert_that!(err.service_specific_error(), eq(ServiceSpecificException::IoError as i32));
+
+    assert_that!(reader.is_session_closed(session1), eq(true));
+    assert_that!(reader.is_session_closed(session2), eq(true));
+
+    Ok(())
+}
+
+/// [`Reader`] should close all sessions if opening a session returns an I/O error.
+#[gtest]
+fn close_on_open_session_io_error() -> Result<()> {
+    init();
+
+    let se_binder = mock_se(|mock| {
+        mock.expect_isCardPresent().times(2).returning(|| Ok(true));
+        mock.expect_openLogicalChannel().times(1).returning(|_, _| {
+            service_specific_exception(ServiceSpecificException::IoError, "I/O error")
+        });
+    });
+
+    let system_services = mock_system_services(
+        Ok(se_binder),
+        // Full access security profile, to avoid triggering an ARA-M read.
+        SeSecurityProfile { use_ara_applet: false, full_access: true },
+        /* platform_rules */ Ok(vec![]),
+        |mock| {
+            mock.expect_get_client_id().returning(|| Ok(ClientId::PackageInfo(vec![])));
+        },
+    );
+
+    let reader_arc = Reader::new_arc("se_name", WaitForReader(false), system_services)?;
+    let mut reader = reader_arc.lock().unwrap();
+    let session1 = reader.open_session()?;
+    let session2 = reader.open_session()?;
+
+    let err = reader.open_logical_channel(session1, DEFAULT_AID, TEST_P2).unwrap_err();
+    assert_that!(err.exception_code(), eq(ExceptionCode::SERVICE_SPECIFIC));
+    assert_that!(err.service_specific_error(), eq(ServiceSpecificException::IoError as i32));
+
+    assert_that!(reader.is_session_closed(session1), eq(true));
+    assert_that!(reader.is_session_closed(session2), eq(true));
+
+    Ok(())
+}
+
+/// [`Reader`] should close all sessions if transmitting an APDU returns an IO error.
+#[gtest]
+fn close_on_transmit_io_error() -> Result<()> {
+    init();
+
+    let se_binder = mock_se(|mock| {
+        mock.expect_isCardPresent().times(2).returning(|| Ok(true));
+        mock.expect_openLogicalChannel().times(1).returning(|_, _| {
+            Ok(LogicalChannelResponse { channelNumber: 1, selectResponse: vec![] })
+        });
+        mock.expect_transmit().returning(|_| {
+            service_specific_exception(ServiceSpecificException::IoError, "I/O error")
+        });
+        mock.expect_closeChannel().returning(|_| Ok(()));
+    });
+
+    let system_services = mock_system_services(
+        Ok(se_binder),
+        // Full access security profile, to avoid triggering an ARA-M read.
+        SeSecurityProfile { use_ara_applet: false, full_access: true },
+        /* platform_rules */ Ok(vec![]),
+        |mock| {
+            mock.expect_get_client_id().returning(|| Ok(ClientId::PackageInfo(vec![])));
+        },
+    );
+
+    let reader_arc = Reader::new_arc("se_name", WaitForReader(false), system_services)?;
+    let mut reader = reader_arc.lock().unwrap();
+    let session1 = reader.open_session()?;
+    let session2 = reader.open_session()?;
+
+    let (Some(channel_id), _policy) =
+        reader.open_logical_channel(session1, DEFAULT_AID, TEST_P2)?
+    else {
+        panic!("Should get a channel ID")
+    };
+
+    let privileged_caller = false;
+    let err = reader
+        .transmit_on_channel(channel_id, &[0x00, 0x00, 0x00, 0x00], privileged_caller)
+        .unwrap_err();
+    assert_that!(err.exception_code(), eq(ExceptionCode::SERVICE_SPECIFIC));
+    assert_that!(err.service_specific_error(), eq(ServiceSpecificException::IoError as i32));
+
+    assert_that!(reader.is_session_closed(session1), eq(true));
+    assert_that!(reader.is_session_closed(session2), eq(true));
+
+    Ok(())
+}
+
+fn mock_se(expectations: impl FnOnce(&mut MockISecureElement)) -> Strong<dyn ISecureElement> {
+    let mut se_mock = MockISecureElement::new();
+    se_mock.expect_init().returning(|callback| {
+        callback.onStateChange(/* connected */ true, /* reason */ "connected")
+    });
+
+    expectations(&mut se_mock);
+
+    BnSecureElement::new_binder(se_mock, BinderFeatures::default())
+}
+
+fn mock_system_services(
+    se_hal: binder::Result<Strong<dyn ISecureElement>>,
+    security_profile: SeSecurityProfile,
+    platform_rules: binder::Result<Vec<Rule>>,
+    expectations: impl FnOnce(&mut MockSystemServices),
+) -> Arc<dyn SystemServices> {
+    let mut mock_services = MockSystemServices::new();
+    mock_services.expect_get_se_hal().return_once(move |_, _| se_hal);
+    mock_services.expect_get_security_profile().return_once(move || security_profile);
+    mock_services.expect_get_platform_rules().return_once(move |_| platform_rules);
+    expectations(&mut mock_services);
+
+    Arc::new(mock_services)
+}
diff --git a/omapi/src/system_services.rs b/omapi/src/system_services.rs
new file mode 100644
index 0000000..12a5a98
--- /dev/null
+++ b/omapi/src/system_services.rs
@@ -0,0 +1,120 @@
+// Copyright 2024, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! This module defines a trait that provides information from the system.
+
+pub use crate::ara::{Rule, Sha1DigestOrUuid, Sha256Digest};
+use android_hardware_secure_element::aidl::android::hardware::secure_element::ISecureElement::ISecureElement;
+use binder::{Result, Strong};
+use bssl_crypto::digest::{InsecureSha1, Sha256};
+use itertools::Itertools;
+use std::fmt::Display;
+
+/// Newtype to specify whether to wait for an SE HAL service to become available.
+pub struct WaitForReader(pub bool);
+
+/// Trait that provides access to system services needed by libse_service.
+#[mockall::automock]
+pub trait SystemServices: std::fmt::Debug + Send + Sync {
+    /// Returns an SE HAL binder object for the specified SE name.  If `wait` is true, will wait
+    /// until the SE HAL is available (potentially waiting forever).
+    fn get_se_hal(&self, se_name: &str, wait: WaitForReader) -> Result<Strong<dyn ISecureElement>>;
+
+    /// Returns the UUID(s) and certificate hash(es) of the calling device application.
+    fn get_client_id(&self) -> Result<ClientId>;
+
+    /// Returns [`ClientId`]s for teach of the provided set of package names, for the specified user ID.
+    fn get_client_ids_for_packages(
+        &self,
+        package_names: &[String],
+        user_id: i32,
+    ) -> Result<Vec<ClientId>>;
+
+    /// Returns the platform security configuration.
+    fn get_security_profile(&self) -> SeSecurityProfile;
+
+    /// Returns the platform security rules for the specified SE
+    fn get_platform_rules(&self, se_name: &str) -> Result<Vec<Rule>>;
+}
+
+#[derive(Debug, Clone, Copy)]
+/// [`SeSecurityProfile`] defines overall policy for access control to SE applets.  In general,
+/// policy is default-deny.  That is, if there isn't some policy that allows an app to access an
+/// applet, it may not.
+pub struct SeSecurityProfile {
+    /// If true, rules are read from the ARA applet and may provide access.
+    pub use_ara_applet: bool,
+    /// If true, all access is allowed.
+    pub full_access: bool,
+}
+
+/// Android package information bundle, used to describe a caller.
+pub struct PackageInfo {
+    /// Package name.
+    pub package_name: String,
+    /// SHA1 hashes of APK signing certificates.
+    pub sha1s: Vec<Sha1DigestOrUuid>,
+    /// SHA256 hashes of APK signing certificates.
+    pub sha256s: Vec<Sha256Digest>,
+}
+
+impl Display for PackageInfo {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        write!(
+            f,
+            "package_name: {}, sha1s: [{}], sha256s: [{}]",
+            self.package_name,
+            self.sha1s.iter().map(hex::encode).join(", "),
+            self.sha256s.iter().map(hex::encode).join(", ")
+        )
+    }
+}
+
+impl PackageInfo {
+    /// Create package info by hashing a set of certificates.
+    pub fn new<I>(package_name: String, cert_iter: I) -> Self
+    where
+        I: Iterator<Item = Vec<u8>>,
+    {
+        let (sha1s, sha256s) = cert_iter
+            .map(|cert| ({ InsecureSha1::hash(&cert).into() }, { Sha256::hash(&cert).into() }))
+            .unzip();
+        PackageInfo { package_name, sha1s, sha256s }
+    }
+}
+
+/// Enum that describes the way OMAPI callers may be identified for access control.
+pub enum ClientId {
+    /// Caller identity expressed as a set of Android package information bundles.
+    PackageInfo(Vec<PackageInfo>),
+    /// Caller identity expressed as UUIDs.
+    Uuids(Vec<Sha1DigestOrUuid>),
+}
+
+impl Display for ClientId {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        match self {
+            ClientId::PackageInfo(package_infos) => {
+                write!(
+                    f,
+                    "package_info:\n{}",
+                    package_infos.iter().map(PackageInfo::to_string).join("\n"),
+                )
+            }
+            ClientId::Uuids(uuids) => {
+                write!(f, "system_uuid: [{}]", uuids.iter().map(hex::encode).join("\n"))
+            }
+        }
+    }
+}
diff --git a/omapi/src/terminal.rs b/omapi/src/terminal.rs
new file mode 100644
index 0000000..8dc502b
--- /dev/null
+++ b/omapi/src/terminal.rs
@@ -0,0 +1,880 @@
+// Copyright 2024, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! This module provides a [`Terminal`] type that wraps an [`ISecureElement`], which represents a
+//! secure element reader (or "terminal").  The name "Terminal" is used instead of "Reader" to
+//! allow distinction between this hardware interface and a higher-level interface that will be
+//! used by applications.
+
+#[cfg(test)]
+mod test;
+
+use crate::{
+    sensitive,
+    utils::{
+        binder_exception, service_specific_exception, ServiceSpecificException::*, TraceResultExt,
+    },
+};
+use android_hardware_secure_element::aidl::android::hardware::secure_element::ISecureElement as HwSe;
+use android_hardware_secure_element::aidl::android::hardware::secure_element::ISecureElement::ISecureElement;
+use binder::{
+    ExceptionCode::{
+        ILLEGAL_ARGUMENT, ILLEGAL_STATE, SECURITY, SERVICE_SPECIFIC, UNSUPPORTED_OPERATION,
+    },
+    Result, Status, Strong,
+};
+use log::{debug, error, trace, warn};
+use std::{collections::HashMap, fmt::Display};
+use zeroize::{Zeroize, ZeroizeOnDrop};
+
+/// Newtype for `bool` that indicates whether the [`Terminal`] should re-select the default applet
+/// when the basic channel is closed.
+#[derive(Clone, Copy)]
+pub struct SendSelectOnClose(pub bool);
+
+const SELECT_DEFAULT_APDU: [u8; 4] = [0x00, 0xA4, 0x04, 0x00];
+const WRONG_LE_SW1: StatusByte = StatusByte(0x6C);
+const BYTES_TO_RECEIVE_SW1: StatusByte = StatusByte(0x61);
+const SUCCESS_STATUS: [u8; 2] = [0x90, 0x00];
+
+/// [`ChannelId`] is a newtype that identifies an SE channel.
+#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
+pub struct ChannelId(pub i8);
+
+impl Display for ChannelId {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        write!(f, "{self:?}")
+    }
+}
+
+impl ChannelId {
+    /// ID of the "basic" channel.
+    pub const BASIC: ChannelId = ChannelId(0);
+
+    /// Returns `true` iff [`self`] references the basic, non-supplementary channel.
+    pub fn is_basic(&self) -> bool {
+        *self == Self::BASIC
+    }
+}
+
+#[derive(Clone, Debug, PartialEq)]
+struct SelectResponse(pub Vec<u8>);
+
+impl Display for SelectResponse {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        write!(f, "SelectResponse({})", hex::encode(&self.0))
+    }
+}
+
+/// [`Terminal`] provides access to SE reader hardware, either an embedded SE or an SE reader
+/// (e.g. SIM card slot) with an (optionally) inserted reader.
+#[derive(Debug)]
+pub struct Terminal {
+    /// System name of this reader.
+    name: String,
+
+    /// Proxy of the underlying SE HAL instance, the binder service that communicates with the
+    /// actual hardware.
+    se_hal: Strong<dyn ISecureElement>,
+
+    /// `true` if the SE HAL is connected to the SE.  May be false if the SE is a SIM which has been
+    /// removed from the device or if the SE HAL is not yet initialized.
+    is_connected: bool,
+
+    /// True if the basic channel was opened without specifying an AID.  Not meaningful if the
+    /// basic channel is not yet open.
+    is_default_app_selected_on_basic_channel: bool,
+
+    /// Open channels.
+    channels: HashMap<ChannelId, SelectResponse>,
+}
+
+impl Terminal {
+    /// Create a [`Terminal`] object that provides access to the SE reader referenced by `se_hal`.
+    pub fn new(name: &str, se_hal: Strong<dyn ISecureElement>) -> Result<Terminal> {
+        Ok(Terminal {
+            name: name.to_owned(),
+            se_hal,
+            is_connected: false,
+            is_default_app_selected_on_basic_channel: true,
+            channels: HashMap::new(),
+        })
+    }
+
+    /// Returns the name of the SE.
+    pub fn name(&self) -> &str {
+        &self.name
+    }
+
+    /// Returns true iff the SE is present in the terminal (i.e. the SIM is inserted).
+    pub fn is_secure_element_present(&self) -> Result<bool> {
+        self.se_hal.isCardPresent()
+    }
+
+    /// Reset the SE.
+    pub fn reset(&self) -> bool {
+        if let Err(e) = self.se_hal.reset() {
+            error!("Got error {e} resetting SE {}.", self.name);
+            // The Java implementation doesn't propagate the error, so we don't either.
+            false
+        } else {
+            true
+        }
+    }
+
+    /// Returns the answer to reset (ATR) message returned by the SE when it was last reset.
+    pub fn answer_to_reset(&self) -> Result<Option<Vec<u8>>> {
+        if !self.is_connected {
+            return Ok(None);
+        }
+
+        let atr = self.se_hal.getAtr()?;
+        debug!("ATR: [{}]", hex::encode(&atr));
+
+        let have_atr = !atr.is_empty();
+        Ok(have_atr.then_some(atr))
+    }
+
+    /// Open the basic channel, selecting the specified AID (may be empty) and P2 value.
+    pub fn open_basic_channel(&mut self, aid: &[u8], p2: i8) -> Result<Option<ChannelId>> {
+        trace!("open_basic_channel() {} P2 = 0x{p2:02x}", hex::encode(aid));
+
+        if !self.channel_closed(ChannelId::BASIC) {
+            error!("Basic channel in use");
+            return Ok(None);
+        }
+        self.check_channel_open_requirements(p2, aid)?;
+
+        if aid.is_empty() && !self.is_default_app_selected_on_basic_channel {
+            error!("Default application is not selected, AID required");
+            return Ok(None);
+        }
+
+        let select_response = match self.se_hal.openBasicChannel(aid, p2) {
+            Ok(response) => SelectResponse(response),
+            Err(status) => return convert_hw_exception(status),
+        };
+
+        if !aid.is_empty() {
+            self.is_default_app_selected_on_basic_channel = false
+        };
+
+        self.channels.insert(ChannelId::BASIC, select_response);
+        Ok(Some(ChannelId::BASIC))
+    }
+
+    /// Open a logical channel, selecting the specified AID (may be empty) and P2 value.
+    pub fn open_logical_channel(&mut self, aid: &[u8], p2: i8) -> Result<Option<ChannelId>> {
+        trace!("open_logical_channel() {} P2 = 0x{p2:02x}", hex::encode(aid));
+
+        self.check_channel_open_requirements(p2, aid)?;
+
+        let response = match self.se_hal.openLogicalChannel(aid, p2) {
+            Ok(response) => response,
+            Err(status) => return convert_hw_exception(status),
+        };
+
+        if response.channelNumber <= 0 {
+            // This logic is odd, but it's what the Java implementation does.  If the SE for some
+            // reason returns an invalid channel ID, we don't throw an exception we return None,
+            // which translated to `null` in Java.
+            //
+            // TODO: See if this actually makes sense for some reason.
+            error!("Invalid logical channel {} received from SE", response.channelNumber);
+            return Ok(None);
+        }
+
+        let channel_id = ChannelId(response.channelNumber);
+        self.channels.insert(channel_id, SelectResponse(response.selectResponse));
+        Ok(Some(channel_id))
+    }
+
+    /// Get the response returned by the SELECT command sent when the specified channel was
+    /// opened, if any.
+    pub fn select_response(&self, channel_id: ChannelId) -> Option<&[u8]> {
+        self.channels.get(&channel_id).map(|select_response| &select_response.0[..])
+    }
+
+    /// Close the specified channel, optionally selecting the default applet if channel is
+    /// `ChannelId::BASIC`.
+    pub fn close_channel(&mut self, id: ChannelId, send_select: SendSelectOnClose) -> Result<()> {
+        if self.channels.remove(&id).is_none() {
+            error!("Got request to close already-closed {id}");
+            return Ok(());
+        }
+        self.close_channel_internal(id, send_select)
+    }
+
+    /// Returns true iff the specified channel is closed.
+    pub fn channel_closed(&self, channel_id: ChannelId) -> bool {
+        !self.channels.contains_key(&channel_id)
+    }
+
+    /// SECURITY NOTE: APDU and response contents may be sensitive, so any copies must be zeroized
+    /// and the content must not be logged, except with [`sensitive!`], which is disabled except
+    /// sometimes on local developer builds.
+    ///
+    /// This method needs to copy the APDU to modify the CLA byte, so it puts the copy into an
+    /// [`Apdu`] instance, which zeroizes on drop and does not implement [`Clone`].  This method
+    /// does not copy the response data, just passes it through.
+    pub fn transmit(&self, id: ChannelId, apdu: &[u8], priv_caller: bool) -> Result<ApduResponse> {
+        if self.channel_closed(id) {
+            return binder_exception(ILLEGAL_STATE, &format!("Channel {id} is closed"));
+        }
+
+        let apdu = Apdu::new(apdu, Some(id))?;
+        apdu.check_disallowed_iso_commands(priv_caller)?;
+
+        self.transmit_and_get_response(apdu)
+    }
+
+    /// Change SE connection state
+    pub fn set_connected(&mut self, connected: bool) {
+        if connected == self.is_connected {
+            // I don't think we can get here, but just in case we get duplicate connection
+            // requests, don't do anything.
+            warn!("Got informed of a successful SE connection, but the SE is already connected.");
+            return;
+        }
+
+        self.close_channels(SendSelectOnClose(false));
+
+        self.is_connected = connected;
+        if connected {
+            self.is_default_app_selected_on_basic_channel = true;
+        }
+    }
+
+    /// SECURITY NOTE:  APDU and response contents may be sensitive, so any copies must be
+    /// zeroized and the content must not be logged, except with [`trace!`], which is normaly
+    /// disabled.
+    ///
+    /// This method does not copy APDU or response.
+    fn transmit_and_get_response(&self, mut apdu: Apdu) -> Result<ApduResponse> {
+        if !self.is_connected {
+            return service_specific_exception(IoError, "Secure Element is not connected");
+        }
+
+        let mut response = self.send_apdu(&apdu)?;
+
+        if response.incorrect_le() {
+            sensitive!("Wrong Le field, re-sending with correct value {:?}", response.sw2());
+            apdu.set_le(response.sw2());
+            return self.transmit_and_get_response(apdu).trace("transmit (corrected Le)");
+        }
+
+        while response.get_data_required() {
+            sensitive!("Response chaining requested, getting {:?}", response.sw2());
+            let get_data_apdu = response.create_get_data_command(apdu.cla());
+            response.extend(self.send_apdu(&get_data_apdu)?);
+        }
+
+        Ok(response)
+    }
+
+    /// SECURITY NOTE:  APDU and response contents may be sensitive, so any copies must be
+    /// zeroized and the content must not be logged, except with [`trace!`], which is disabled.
+    fn send_apdu(&self, apdu: &Apdu) -> Result<ApduResponse> {
+        sensitive!("Transmitting: {apdu:?}");
+        ApduResponse::new(self.se_hal.transmit(&apdu.0)?).sensitive("transmit")
+    }
+
+    /// Close all open channels on the [`Terminal`]
+    pub fn close_channels(&mut self, send_select: SendSelectOnClose) {
+        for channel_id in self.channels.drain().map(|(id, _)| id).collect::<Vec<_>>() {
+            let _ = self.close_channel_internal(channel_id, send_select);
+        }
+    }
+
+    fn close_channel_internal(
+        &mut self,
+        id: ChannelId,
+        send_select: SendSelectOnClose,
+    ) -> Result<()> {
+        trace!("Closing {id}.");
+
+        if !self.is_connected {
+            debug!("Can't actually close {id}, reader isn't connected.");
+            return Ok(());
+        }
+
+        if send_select.0 && id.is_basic() {
+            let apdu = Apdu::create_select_default_on_basic();
+
+            if let Err(e) = self.transmit_and_get_response(apdu) {
+                error!("Error trying to select default applet on basic channel during close: {e}");
+            } else {
+                self.is_default_app_selected_on_basic_channel = true;
+            }
+        }
+
+        if let Err(e) = self.se_hal.closeChannel(id.0) {
+            // Don't return errors caused by closing the basic channel.
+            //
+            // TODO: Figure out why we don't return them (other than the Java implementation
+            // doesn't).
+            if !id.is_basic() {
+                error!("Error closing channel {}: {e}.", id.0);
+                return Err(e);
+            }
+        }
+
+        trace!("Closed {id}");
+        Ok(())
+    }
+
+    fn check_channel_open_requirements(&mut self, p2: i8, aid: &[u8]) -> Result<()> {
+        self.check_connected()?;
+        validate_p2(p2)?;
+        validate_aid(aid)?;
+        Ok(())
+    }
+
+    fn check_connected(&mut self) -> Result<()> {
+        if !self.is_connected {
+            return service_specific_exception(
+                SecureElementNotConnected,
+                "Secure Element is not connected",
+            );
+        };
+        Ok(())
+    }
+}
+
+/// [`StatusByte`] is a newtype for APDU response status bytes.  It exists so it can derive
+/// [`ZeroizeOnDrop`].  It's unclear if there are any situations in which status bytes are
+/// sensitive, but better safe than sorry.
+///
+/// SECURITY NOTE:  APDU and response contents may be sensitive, so any copies must be zeroized
+/// and the content must not be logged, except with [`sensitive!`].  To help ensure this,
+/// [`StatusByte`]'s implementation of [`std::fmt::Debug`] is a no-op when sensitive data logging
+/// is not enabled, and [`std::fmt::Display`] is not implemented.
+#[derive(Clone, ZeroizeOnDrop, PartialEq)]
+pub(crate) struct StatusByte(u8);
+
+impl std::fmt::Debug for StatusByte {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        // This conditional shouldn't be necessary, since code should always use [`sensitive`] to
+        // trace APDU response data, but this helps protect against mistakes.
+        if cfg!(any(feature = "log_sensitive_data", test)) {
+            return write!(f, "{:#04X?}", self.0);
+        }
+        Ok(())
+    }
+}
+
+/// [`ApduResponse`]is a newtype for APDU response contents.  It exists primarily so it can derive
+/// [`ZeroizeOnDrop`].
+///
+/// SECURITY NOTE:  APDU and response contents may be sensitive, so any copies must be zeroized
+/// and the content must not be logged, except with [`sensitive!`].  To help ensure this,
+/// [`ApduResponse`]'s implementation of [`std::fmt::Debug`] is a no-op when sensitive data
+/// logging is not enabled, and [`std::fmt::Display`] is not implemented.
+#[derive(Clone, ZeroizeOnDrop, PartialEq)]
+pub(crate) struct ApduResponse(Vec<u8>);
+
+impl std::fmt::Debug for ApduResponse {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        // This conditional shouldn't be necessary, since code should always use [`sensitive`] to
+        // trace APDU response data, but this helps protect against mistakes.
+        if cfg!(any(feature = "log_sensitive_data", test)) {
+            return write!(f, "{}", hex::encode(&self.0));
+        }
+        Ok(())
+    }
+}
+
+impl ApduResponse {
+    pub fn new(data: Vec<u8>) -> Result<Self> {
+        if data.len() < 2 {
+            return service_specific_exception(IoError, "Error in transmit(), too-short response");
+        }
+        Ok(Self(data))
+    }
+
+    /// Extend this response by appending the contents of `additional`.  The status word of `self`
+    /// is discarded and the result has the status word from `additional`.
+    ///
+    /// SECURITY NOTE:  The implementation of this method is a little tricky, because we need to
+    /// ensure we don't leave any copies of the data around in the heap.  So we can't use
+    /// `self.0.resize()`, nor can we pass `additional.0` to `Vec::append`, since that would
+    /// probably "move" the contents out of `additional.0` by copying them, leaving `additional.0`
+    /// empty so [`ZeroizeOnDrop`] does nothing.
+    pub fn extend(&mut self, additional: ApduResponse) {
+        if self.0.capacity() >= self.data_len() + additional.0.len() {
+            self.0.pop();
+            self.0.pop();
+            self.0.extend_from_slice(&additional.0);
+        } else {
+            let mut tmp = Vec::with_capacity(self.data_len() + additional.0.len());
+            tmp.extend_from_slice(self.risky_data());
+            tmp.extend_from_slice(&additional.0[..]);
+            std::mem::swap(&mut tmp, &mut self.0);
+            tmp.zeroize();
+        }
+    }
+
+    pub fn data_len(&self) -> usize {
+        self.0.len() - 2
+    }
+
+    pub fn successful(&self) -> bool {
+        self.0[self.0.len() - 2..] == SUCCESS_STATUS
+    }
+
+    /// Get a reference to the data portion of the response, as a slice.  This is labeled "risky"
+    /// because the caller must take care not to copy the slice content, unless the caller knows
+    /// that the content is not sensitive, or takes care to zeroize any copies.
+    pub fn risky_data(&self) -> &[u8] {
+        &self.0[..self.0.len() - 2]
+    }
+
+    /// Get a copy of the status portion of the response, as an array.  The caller must take care
+    /// zeroize the copy, unless the caller knows it is not sensitive.
+    pub fn non_zeroizing_status(&self) -> [u8; 2] {
+        self.0[self.0.len() - 2..].try_into().unwrap()
+    }
+
+    fn sw1(&self) -> StatusByte {
+        StatusByte(self.0[self.0.len() - 2])
+    }
+
+    fn sw2(&self) -> StatusByte {
+        StatusByte(self.0[self.0.len() - 1])
+    }
+
+    fn incorrect_le(&self) -> bool {
+        self.sw1() == WRONG_LE_SW1
+    }
+
+    fn get_data_required(&self) -> bool {
+        self.sw1() == BYTES_TO_RECEIVE_SW1
+    }
+
+    fn create_get_data_command(&self, cla: u8) -> Apdu {
+        Apdu(vec![cla, 0xC0, 0x00, 0x00, self.sw2().0])
+    }
+}
+
+/*
+ *  APDU header structure constants
+ */
+
+/// CLA -- Class byte.  Indicates whether the APDU is a standard ISO command, whether and what
+/// sort of secure messaging is used, and what logical channel is in use.
+const OFFSET_CLA: usize = 0;
+
+/// INS -- Instruction byte.  Indicates what operation is being requested.
+const OFFSET_INS: usize = OFFSET_CLA + 1;
+
+/// P1 -- First parameter byte.  0x00 if unused.
+const OFFSET_P1: usize = OFFSET_INS + 1;
+
+/// P2 -- Second parameter byte. 0x00 if unused.
+const OFFSET_P2: usize = OFFSET_P1 + 1;
+
+/// Length of APDU header
+const APDU_HEADER_LEN: usize = OFFSET_P2 + 1;
+
+/// [`Apdu`] is a newtype for APDU contents.  It exists primarily so it can derive
+/// [`ZeroizeOnDrop`].
+///
+/// Apdu creation validates the structure of the APDU, including its length, which must be at
+/// least 4-7 bytes (depending on their content).
+///
+/// SECURITY NOTE:  APDU and response contents may be sensitive, so any copies must be zeroized
+/// and the content must not be logged, except with [`sensitive!`].  To help ensure this,
+/// [`Apdu`]'s implementation of [`std::fmt::Debug`] is a no-op when sensitive data logging is not
+/// enabled, and [`std::fmt::Display`] is not implemented.
+#[derive(Clone, ZeroizeOnDrop)]
+pub(crate) struct Apdu(pub(crate) Vec<u8>);
+
+impl std::fmt::Debug for Apdu {
+    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
+        // This conditional shouldn't be necessary, since code should always use [`sensitive`] to
+        // trace Apdus, but this helps protect against mistakes.
+        if cfg!(any(feature = "log_sensitive_data", test)) {
+            write!(f, "{}", hex::encode(&self.0))
+        } else {
+            write!(f, "APDU elided for security")
+        }
+    }
+}
+
+impl Apdu {
+    /// Create a new [`Apdu`] from an APDU buffer, validating its structure and optionally
+    /// updating it to use a specified channel.
+    pub(crate) fn new(apdu: &[u8], channel_id_opt: Option<ChannelId>) -> Result<Self> {
+        check_apdu_structure(apdu)?;
+
+        if ApduClassType::new(apdu[OFFSET_CLA]) == ApduClassType::ReservedForProtocolSelection {
+            // Perhaps we should also reject `ApduClassType::Reserved`, but the Java OMAPI
+            // implementation doesn't.
+            binder_exception(ILLEGAL_ARGUMENT, &format!("Invalid CLA ({:#04X})", apdu[OFFSET_CLA]))
+        } else if (apdu[OFFSET_INS] & 0xF0) == 0x60 || (apdu[OFFSET_INS] & 0xF0) == 0x90 {
+            // ISO 7816-4 says that odd-valued INS bytes and INS bytes of the form 0x6_ and 0x9_
+            // are all invalid, but the Java OMAPI implementation doesn't reject odd-valued INS
+            // bytes, so we don't either.
+            binder_exception(ILLEGAL_ARGUMENT, &format!("Invalid INS {:#04X}", apdu[OFFSET_INS]))
+        } else {
+            let mut apdu = Self(apdu.to_vec());
+
+            if let Some(channel) = channel_id_opt {
+                apdu.set_channel(channel)?;
+            }
+
+            Ok(apdu)
+        }
+    }
+
+    /// Create a SELECT APDU that selects the default AID on the BASIC channel.
+    pub fn create_select_default_on_basic() -> Self {
+        let mut apdu = Self(SELECT_DEFAULT_APDU.to_vec());
+        apdu.set_channel(ChannelId::BASIC).expect("Can't fail");
+        apdu
+    }
+
+    /// Returns true if this APDU uses secure messaging, as indicated by the class byte.
+    fn uses_secure_messaging(&self) -> bool {
+        SecureMessagingConfiguration::new(self.cla())
+            != SecureMessagingConfiguration::NoneOrNonStandard
+    }
+
+    /// Returns true if this APDU uses Global Platform secure messaging, as indicated by the class
+    /// byte.
+    fn uses_gp_secure_messaging(&self) -> bool {
+        SecureMessagingConfiguration::new(self.cla())
+            == SecureMessagingConfiguration::GlobalPlatform
+    }
+
+    /// Update the CLA byte to specify the channel ID, with correct interindustry class byte
+    /// coding.  See Global Platform Card Specification 2.3.1, 11.1.4.
+    fn set_channel(&mut self, id: ChannelId) -> Result<()> {
+        let mut new_cla = self.cla();
+        match id.0 {
+            0..4 => {
+                // Clear bit 7 to indicate first interindustry class byte coding
+                new_cla &= 0xBC;
+
+                // Encode `id` into bits 0 and 1.
+                new_cla |= id.0 as u8
+            }
+            4..20 => {
+                // Set bit 7 to indicate further interindustry class byte coding
+                new_cla |= 0x40;
+
+                // Set bit 6 if using secure messaging
+                let first_interindustry_coding = self.cla() & 0x40 == 0;
+                if first_interindustry_coding && self.uses_secure_messaging() {
+                    new_cla |= 0x20
+                }
+
+                // Encode to `id - 4` into low-order nibble.
+                new_cla = (new_cla & 0xF0) | (id.0 as u8 - 4)
+            }
+            _ => return binder_exception(ILLEGAL_ARGUMENT, &format!("Invalid {id}")),
+        };
+
+        self.0[OFFSET_CLA] = new_cla;
+
+        Ok(())
+    }
+
+    /// Update the last byte of the APDU.
+    fn set_le(&mut self, value: StatusByte) {
+        self.0.pop();
+        self.0.push(value.0);
+    }
+
+    /// Get class byte
+    fn cla(&self) -> u8 {
+        self.0[OFFSET_CLA]
+    }
+
+    /// Get instruction byte.
+    fn ins(&self) -> u8 {
+        self.0[OFFSET_INS]
+    }
+
+    /// Get p1 byte.
+    fn p1(&self) -> u8 {
+        self.0[OFFSET_P1]
+    }
+
+    /// Get the APDU type indicated by the class byte.
+    fn get_cla_type(&self) -> ApduClassType {
+        ApduClassType::new(self.cla())
+    }
+
+    /// Returns true iff the APDU is an ISO command, as indicated by the class byte.
+    fn is_iso_command_class(&self) -> bool {
+        let cla_type = self.get_cla_type();
+
+        // It seems like we should only consider ISO 7816 CLA types to be ISO commands, but the
+        // Java OMAPI implementation also allows CLA values in the reserved space.  This is likely
+        // a bug, but we do the same for compatibility.
+        //
+        // TODO: Research why this is.
+        cla_type == ApduClassType::Iso7816Command || cla_type == ApduClassType::Reserved
+    }
+
+    /// Returns [`Err`] if this APDU is a disallowed command.  `privileged_caller` indicates
+    /// whether the caller is allowed to perform some ISO commands.
+    fn check_disallowed_iso_commands(&self, privileged_caller: bool) -> Result<()> {
+        // TODO: Research why not disallow SM.
+        if self.is_iso_command_class() && !self.uses_gp_secure_messaging() {
+            match self.ins() {
+                0x70 => binder_exception(SECURITY, "MANAGE CHANNEL command not allowed."),
+                0xA4 => {
+                    if self.p1() == 0x04 && !privileged_caller {
+                        binder_exception(SECURITY, "SELECT by DF name command not allowed.")
+                    } else {
+                        Ok(())
+                    }
+                }
+                _ => Ok(()),
+            }
+        } else {
+            Ok(())
+        }
+    }
+}
+
+/// This function validates the structure of the passed-in APDU buffer.  Conceptually, the APDU
+/// structure is very simple:
+///
+/// * Class byte, CLA
+/// * Instruction byte, INS
+/// * Parameter byte, P1
+/// * Parameter byte, P2
+/// * Command data length, Lc
+/// * Command data bytes
+/// * Length expected, Le
+///
+/// The first four bytes (CLA, INS, P1, P2) are called the "header".
+///
+/// However, either or both of the Lc and Le fields may be omitted, and they may be one byte
+/// (called "short") or two bytes (called "extended").  The Lc and Le fields are omitted to
+/// indicate they have the value zero, and MUST be omitted if their value is zero.
+///
+/// Validating the structure is mostly about checking that the command data length, Lc,
+/// corresponds to the amount of command data present, but all of the optional and length-varying
+/// fields make this a little complicated.
+///
+/// The IS0 7816 documentation categorizes APDUs into four cases, based on the presence/absence of
+/// Lc and Le:
+///
+/// * Case 1: No Lc and no Le.
+/// * Case 2: No Lc but Le is present (non-zero).
+/// * Case 3: Lc is present (non-zero), but no Le.
+/// * Case 4: Lc and Le are both present (and non-zero)
+///
+/// Cases 2, 3 and 4 are further subdivided into "short" and "extended" cases, 2S, 2E, 3S, 3E, 4S
+/// and 4E, depending on whether Lc and Le are encoded in one byte or two.
+fn check_apdu_structure(apdu_data: &[u8]) -> Result<()> {
+    if apdu_data.len() < APDU_HEADER_LEN {
+        return binder_exception(
+            ILLEGAL_ARGUMENT,
+            &format!("Too-short APDU (length: {}).", apdu_data.len()),
+        );
+    }
+
+    // Skip header
+    let data = &apdu_data[APDU_HEADER_LEN..];
+
+    if data.is_empty() {
+        // Case 1, No Lc, no Le.
+        Ok(())
+    } else if data.len() == 1 {
+        // Case 2S, No Lc, Le present.
+        Ok(())
+    } else if data[0] != 0 {
+        // B1 != 0 indicates short (one-byte) Lc/Le, i.e. case 3S or 4S.
+        check_apdu_structure_short(data)
+    } else {
+        // B1 == 0 indicates extended (two-byte) Lc/Le, i.e. case 2E, 3E, or 4E
+
+        // Skip B1; it's not used in Lc in the extended cases
+        let data = &data[1..];
+        check_apdu_structure_extended(data)
+    }
+}
+
+/// Check APDU structure, cases 3S and 4S
+fn check_apdu_structure_short(data: &[u8]) -> Result<()> {
+    // The format of the data should be:
+    //
+    // 1 byte: Lc
+    // Lc bytes: data
+    // 0 or 1 byte: Le
+
+    let lc = data[0] as usize;
+
+    // Skip past Lc
+    let data = &data[1..];
+
+    if data.len() == lc {
+        // Case 3S, Lc present, no Le
+        Ok(())
+    } else if data.len() == lc + 1 {
+        // Case 4S, Lc and Le both present
+        Ok(())
+    } else {
+        binder_exception(
+            ILLEGAL_ARGUMENT,
+            &format!("Invalid APDU: Lc is {lc} but is followed by {} byte(s).", data.len()),
+        )
+    }
+}
+
+// Check APDU structure, cases 2E, 3E and 4E.
+fn check_apdu_structure_extended(data: &[u8]) -> Result<()> {
+    // The format of the data should be:
+    //
+    //     2 bytes: Lc
+    //     Lc bytes: command data
+    //     0 or 2 bytes: Le
+
+    if data.len() < size_of::<u16>() {
+        return binder_exception(
+            ILLEGAL_ARGUMENT,
+            &format!("Invalid extended APDU: Need 2 bytes for Lc, found {}.", data.len()),
+        );
+    }
+
+    if data.len() == size_of::<u16>() {
+        // Case 2E, No Lc, two-byte Le present.
+        return Ok(());
+    }
+
+    // Have command data, get length.
+    let mut lc = u16::from_be_bytes(data[..size_of::<u16>()].try_into().unwrap()) as usize;
+    if lc == 0 {
+        lc = 65536;
+    }
+
+    // Skip past Lc
+    let data = &data[size_of::<u16>()..];
+
+    if data.len() == lc {
+        // Case 3E, two-byte Lc present, No Le
+        Ok(())
+    } else if data.len() == (lc + size_of::<u16>()) {
+        // Case 4E, two-byte Lc and two-byte Le both present.
+        Ok(())
+    } else {
+        binder_exception(
+            ILLEGAL_ARGUMENT,
+            &format!(
+                "Invalid extended APDU: Lc is {lc} but is followed by {} byte(s).",
+                data.len()
+            ),
+        )
+    }
+}
+
+/// This enum categorizes the CLA byte value, which categorizes the APDU command.
+#[derive(Debug, PartialEq)]
+enum ApduClassType {
+    /// Command defined by ISO 7816.
+    Iso7816Command,
+    /// Reserved for future use by ISO committee.
+    Reserved,
+    /// Command defined by Global Platform
+    GlobalPlatform,
+    /// APDU command and response use proprietary structure and coding.
+    ProprietaryStructureAndCoding,
+    /// Class reserved for protocol selection.
+    ReservedForProtocolSelection,
+}
+
+impl ApduClassType {
+    fn new(cla: u8) -> Self {
+        match cla {
+            0x00..0x10 => Self::Iso7816Command,
+            0x10..0x80 => Self::Reserved,
+            0x80..0xD0 => Self::GlobalPlatform,
+            0xD0..0xFF => Self::ProprietaryStructureAndCoding,
+            0xFF => Self::ReservedForProtocolSelection,
+        }
+    }
+}
+
+/// This enum categorizes the secure messaging being used, as specified by the CLA byte.
+#[derive(Debug, PartialEq)]
+enum SecureMessagingConfiguration {
+    /// No secure messaging or no indication.
+    NoneOrNonStandard,
+    /// Proprietary secure messaging used.
+    GlobalPlatform,
+    /// Header is included in standard secure messaging.
+    HeaderNotAuthenticated,
+    /// Header is not included in standard secure messaging.
+    HeaderAuthenticated,
+}
+
+impl SecureMessagingConfiguration {
+    fn new(cla: u8) -> Self {
+        match ApduClassType::new(cla) {
+            ApduClassType::Iso7816Command | ApduClassType::GlobalPlatform => {
+                match (cla & 0x0F) >> 2 {
+                    0 => Self::NoneOrNonStandard,
+                    1 => Self::GlobalPlatform,
+                    2 => Self::HeaderNotAuthenticated,
+                    3 => Self::HeaderAuthenticated,
+                    _ => unreachable!(),
+                }
+            }
+            _ => Self::NoneOrNonStandard,
+        }
+    }
+}
+
+fn convert_hw_exception(status: Status) -> Result<Option<ChannelId>> {
+    debug!("Got error {status:?} from SE");
+    if status.exception_code() == SERVICE_SPECIFIC {
+        match status.service_specific_error() {
+            HwSe::CHANNEL_NOT_AVAILABLE => Ok(None),
+            HwSe::UNSUPPORTED_OPERATION => binder_exception(
+                UNSUPPORTED_OPERATION,
+                "Unsupported operation when opening channel",
+            ),
+            HwSe::IOERROR => service_specific_exception(IoError, "I/O error when opening channel"),
+            HwSe::NO_SUCH_ELEMENT_ERROR => {
+                service_specific_exception(NoSuchElement, "No such element when opening channel")
+            }
+            other => {
+                error!("Unknown service-specific error {other} when opening channel");
+                Err(status)
+            }
+        }
+    } else {
+        error!("Unexpected binder error {:?}", status.exception_code());
+        Err(status)
+    }
+}
+
+fn validate_aid(aid: &[u8]) -> Result<()> {
+    match aid.len() {
+        0 | 5..=16 => Ok(()),
+        _ => binder_exception(ILLEGAL_ARGUMENT, "AID out of range"),
+    }
+}
+
+fn validate_p2(p2: i8) -> Result<()> {
+    match p2 {
+        0x00 | 0x04 | 0x08 | 0x0C => Ok(()),
+        other => binder_exception(ILLEGAL_ARGUMENT, &format!("p2 not supported: 0x{other:02x}")),
+    }
+}
diff --git a/omapi/src/terminal/test.rs b/omapi/src/terminal/test.rs
new file mode 100644
index 0000000..5ad084f
--- /dev/null
+++ b/omapi/src/terminal/test.rs
@@ -0,0 +1,511 @@
+use super::*;
+use crate::{test_utils::init, utils::create_exception_status};
+use android_hardware_secure_element::aidl::android::hardware::secure_element::{
+    ISecureElement::{BnSecureElement, MockISecureElement},
+    LogicalChannelResponse::LogicalChannelResponse,
+};
+use binder::{BinderFeatures, ExceptionCode};
+use googletest::prelude::*;
+use googletest::test as gtest;
+use googletest::Result;
+use mockall::{predicate as mp, Sequence};
+
+#[gtest]
+fn create_terminal() -> Result<()> {
+    init();
+
+    let se_binder = build_mock_se(|_mock_se| {});
+    let terminal = Terminal::new("se_name", se_binder)?;
+
+    assert_that!(terminal.name(), eq("se_name"));
+    assert!(!terminal.is_connected);
+    assert!(terminal.is_default_app_selected_on_basic_channel);
+    assert!(terminal.channels.is_empty());
+
+    Ok(())
+}
+
+#[gtest]
+fn get_answer_to_reset() -> Result<()> {
+    init();
+
+    let se_binder = build_mock_se(|mock_se| {
+        mock_se.expect_getAtr().times(1).return_once(|| Ok("Hello".as_bytes().to_vec()));
+    });
+    let mut terminal = Terminal::new("se_name", se_binder.clone())?;
+
+    // Can't get ATR until connected.
+    assert_that!(terminal.answer_to_reset()?, none());
+
+    terminal.set_connected(true);
+
+    assert_that!(terminal.answer_to_reset()?, some(eq("Hello".as_bytes())));
+
+    Ok(())
+}
+
+#[gtest]
+fn open_basic_channel() -> Result<()> {
+    init();
+
+    let se_binder = build_mock_se(|mock_se| {
+        mock_se
+            .expect_openBasicChannel()
+            .with(mp::eq([]), mp::eq(0x00))
+            .return_once(|_, _| Ok("ats".as_bytes().to_vec()));
+        expect_default_select(mock_se);
+        mock_se.expect_closeChannel().with(mp::eq(0)).returning(|_| Ok(()));
+    });
+    let mut terminal = Terminal::new("se_name", se_binder.clone())?;
+
+    let err = terminal.open_basic_channel(&[], 0x00).unwrap_err();
+    assert_eq!(err.exception_code(), ExceptionCode::SERVICE_SPECIFIC);
+    assert!(err.get_description().contains("Secure Element is not connected"));
+
+    terminal.set_connected(true);
+
+    let channel_id = terminal.open_basic_channel(&[], 0x00)?.expect("Should not be None");
+    assert!(channel_id.is_basic());
+    assert_that!(terminal.select_response(channel_id).unwrap(), eq("ats".as_bytes()));
+    assert!(!terminal.channel_closed(channel_id));
+
+    terminal.close_channel(channel_id, SendSelectOnClose(false))?;
+    assert!(terminal.channel_closed(channel_id));
+
+    Ok(())
+}
+
+#[gtest]
+fn open_basic_channel_invalid_p2() -> Result<()> {
+    init();
+
+    let se_binder = build_mock_se(|mock_se| {
+        // openBasicChannel (and therefore closeChannel) is only called for the valid p2 values.
+        mock_se.expect_openBasicChannel().times(4).returning(|_, _| Ok("ats".as_bytes().to_vec()));
+        mock_se.expect_closeChannel().times(4).with(mp::eq(0)).returning(|_| Ok(()));
+    });
+    let mut terminal = Terminal::new("se_name", se_binder)?;
+    terminal.set_connected(true);
+
+    for p2 in 0x00_u8..=0xFF_u8 {
+        let open_result = terminal.open_basic_channel(&[], p2 as i8);
+        match p2 {
+            0x00 | 0x04 | 0x08 | 0x0C => {
+                let channel_id = open_result
+                    .expect("No error expected for {p2}")
+                    .expect("Some value expected for {p2}");
+                assert!(channel_id.is_basic(), "Should be basic channel for {p2}");
+                assert!(terminal.is_default_app_selected_on_basic_channel);
+                terminal.close_channel(channel_id, SendSelectOnClose(false))?;
+            }
+            p2 => {
+                assert_that!(
+                    open_result
+                        .expect_err(&format!("P2 value {p2} should not be supported."))
+                        .to_string(),
+                    contains_substring("p2 not supported")
+                );
+            }
+        }
+    }
+
+    Ok(())
+}
+
+#[gtest]
+fn open_basic_channel_invalid_aid() -> Result<()> {
+    init();
+
+    let se_binder = build_mock_se(|mock_se| {
+        // openBasicChannel (and therefore closeChannel) is only called for the valid AIDs.
+        mock_se.expect_openBasicChannel().times(13).returning(|_, _| Ok("ats".as_bytes().to_vec()));
+        mock_se.expect_closeChannel().times(13).with(mp::eq(0)).returning(|_| Ok(()));
+    });
+    let mut terminal = Terminal::new("se_name", se_binder)?;
+    terminal.set_connected(true);
+
+    for aid_len in 0..20 {
+        let aid = vec![0; aid_len];
+        let open_result = terminal.open_basic_channel(&aid, 0x00);
+
+        match aid_len {
+            0x00 | 5..=16 => {
+                let channel_id = open_result
+                    .expect("No error expected for {aid_len}")
+                    .expect("Some value expected for {aid_len}");
+                assert!(channel_id.is_basic(), "Should be basic channel for {aid_len}",);
+                assert!(
+                    terminal.is_default_app_selected_on_basic_channel == (aid_len == 0),
+                    "Default applet selection incorrect for {aid_len}"
+                );
+                terminal.close_channel(channel_id, SendSelectOnClose(false))?;
+            }
+            aid_len => {
+                assert_that!(
+                    open_result
+                        .expect_err("AID length {aid_len} should not be supported.")
+                        .to_string(),
+                    contains_substring("AID out of range"),
+                    "Wrong error for {aid_len}"
+                );
+            }
+        }
+    }
+
+    Ok(())
+}
+
+#[gtest]
+fn reopen_basic_channel() -> Result<()> {
+    init();
+
+    let se_binder = build_mock_se(|mock_se| {
+        mock_se.expect_openBasicChannel().times(1).returning(|_, _| Ok("ats".as_bytes().to_vec()));
+    });
+    let mut terminal = Terminal::new("se_name", se_binder)?;
+    terminal.set_connected(true);
+
+    // First attempt works.
+    let channel_id = terminal.open_basic_channel(&[], 0x00)?;
+    assert!(channel_id.expect("Should not be None").is_basic());
+
+    // Second time returns None because the channel is already open.
+    let channel_id = terminal.open_basic_channel(&[], 0x00)?;
+    assert!(channel_id.is_none());
+
+    Ok(())
+}
+
+#[gtest]
+fn open_logical_channel() -> Result<()> {
+    init();
+
+    let se_binder = build_mock_se(|mock_se| {
+        mock_se.expect_openLogicalChannel().times(1).returning(|_, _| {
+            Ok(LogicalChannelResponse {
+                channelNumber: 1,
+                selectResponse: "ats".as_bytes().to_vec(),
+            })
+        });
+        mock_se.expect_closeChannel().with(mp::eq(1)).returning(|_| Ok(()));
+    });
+    let mut terminal = Terminal::new("se_name", se_binder)?;
+    terminal.set_connected(true);
+
+    let channel_id = terminal.open_logical_channel(&[], 0x00)?.expect("Should not be None");
+    assert!(!channel_id.is_basic());
+    assert_that!(channel_id, eq(ChannelId(1)));
+    assert_that!(terminal.select_response(channel_id).unwrap(), eq("ats".as_bytes()));
+    assert!(!terminal.channel_closed(channel_id));
+
+    terminal.close_channel(channel_id, SendSelectOnClose(false))?;
+    assert!(terminal.channel_closed(channel_id));
+
+    Ok(())
+}
+
+#[gtest]
+fn transmit_apdu() -> Result<()> {
+    init();
+
+    let se_binder = build_mock_se(|mock_se| {
+        mock_se.expect_openLogicalChannel().times(1).returning(|_, _| {
+            Ok(LogicalChannelResponse {
+                channelNumber: 1,
+                selectResponse: "ats".as_bytes().to_vec(),
+            })
+        });
+        mock_se.expect_transmit().with(mp::eq([1, 0, 0, 0])).returning(|_| Ok(vec![0x90, 0x00]));
+    });
+
+    let mut terminal = Terminal::new("se_name", se_binder)?;
+    terminal.set_connected(true);
+
+    let channel_id = terminal.open_logical_channel(&[], 0x00)?.unwrap();
+    let response = terminal.transmit(channel_id, &[0x00, 0x00, 0x00, 0x00], false)?;
+    assert_that!(response, eq(&ApduResponse(vec![0x90, 00])));
+
+    Ok(())
+}
+
+#[gtest]
+fn transmit_on_closed_channel() -> Result<()> {
+    init();
+
+    let se_binder = build_mock_se(|mock_se| {
+        mock_se.expect_openLogicalChannel().times(1).returning(|_, _| {
+            Ok(LogicalChannelResponse {
+                channelNumber: 1,
+                selectResponse: "ats".as_bytes().to_vec(),
+            })
+        });
+        mock_se.expect_closeChannel().with(mp::eq(1)).returning(|_| Ok(()));
+    });
+
+    let mut terminal = Terminal::new("se_name", se_binder)?;
+    terminal.set_connected(true);
+
+    let channel_id = terminal.open_logical_channel(&[], 0x00)?.unwrap();
+    terminal.close_channel(channel_id, SendSelectOnClose(false))?;
+
+    let err = terminal.transmit(channel_id, &[0x00, 0x00, 0x00, 0x00, 0x00], false).unwrap_err();
+    assert_that!(err.to_string(), contains_substring("ChannelId(1) is closed"));
+
+    Ok(())
+}
+
+#[gtest]
+fn invalid_apdus() -> Result<()> {
+    init();
+
+    let se_binder = build_mock_se(|mock_se| {
+        mock_se.expect_openLogicalChannel().times(1).returning(|_, _| {
+            Ok(LogicalChannelResponse {
+                channelNumber: 1,
+                selectResponse: "ats".as_bytes().to_vec(),
+            })
+        });
+        mock_se.expect_transmit().returning(|_| Ok(vec![0x90, 0x00]));
+    });
+
+    let mut terminal = Terminal::new("se_name", se_binder)?;
+    terminal.set_connected(true);
+    let channel_id = terminal.open_logical_channel(&[], 0x00)?.unwrap();
+
+    // Lambdas to reduce repetition.
+    let expect_fail = |apdu: &[u8], expected_code: ExceptionCode, expected_err: &str| {
+        expect_that!(
+            terminal.transmit(channel_id, apdu, false),
+            err(predicate(binder_status(expected_code, expected_err))),
+            "APDU {} should have failed with {}",
+            hex::encode(apdu),
+            create_exception_status(expected_code, expected_err)
+        );
+    };
+    let expect_success = |apdu: &[u8]| {
+        expect_that!(
+            terminal.transmit(channel_id, apdu, false),
+            ok(eq(&ApduResponse(vec![0x90, 0x00]))),
+            "APDU {} should have succeeded",
+            hex::encode(apdu)
+        );
+    };
+
+    expect_fail(&[0x00, 0x00, 0x00], ILLEGAL_ARGUMENT, "Too-short APDU");
+    expect_fail(&[0xFF, 0x00, 0x00, 0x00], ILLEGAL_ARGUMENT, "Invalid CLA (0xFF)");
+
+    // Invalid INS (with ISO CLA and P2 == 0x04)
+    for ins in 0..0xFF_u8 {
+        let apdu = &[0x00, ins, 0x04, 0x00];
+
+        match ins {
+            0xA4 => expect_fail(apdu, SECURITY, "SELECT by DF name command not allowed"),
+            0x70 => expect_fail(apdu, SECURITY, "MANAGE CHANNEL command not allowed."),
+            _ => match ins & 0xF0 {
+                0x60 | 0x90 => {
+                    expect_fail(apdu, ILLEGAL_ARGUMENT, &format!("Invalid INS {ins:#04X}"))
+                }
+                _ => expect_success(apdu),
+            },
+        }
+    }
+
+    // Verify that INS 0xA4 (SELECT DF) is allowed for non-privileged callers if P1 is not 0x04
+    // (select by name)
+    expect_success(&[0x00, 0xA4, 0x00, 0x00]);
+
+    // Verify that INS 0xA4 with P1 0x04 is allowed for non-privileged callers with non-ISO CLA
+    expect_success(&[0x80, 0xA4, 0x04, 0x00]);
+
+    // Verify that privileged callers are allowed to use INS 0xA4 with P1 0x04
+    expect_that!(
+        terminal.transmit(channel_id, &[0x00, 0xA4, 0x04, 0x00], true),
+        ok(eq(&ApduResponse(vec![0x90, 0x00])))
+    );
+
+    // Verify that INS 0x70 (manage channel) is allowed with non-ISO CLA
+    expect_success(&[0x80, 0x70, 0x00, 0x00]);
+
+    // Case 3S error; Not enough command bytes (Lc == 0x02, only one data byte).
+    expect_fail(
+        &[0x00, 0x00, 0x00, 0x00, 0x02, 0xFF],
+        ILLEGAL_ARGUMENT,
+        "Lc is 2 but is followed by 1 byte(s).",
+    );
+
+    // Case 3E error; Not enough command bytes (Lc == 0x02, only one data byte).
+    expect_fail(
+        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF],
+        ILLEGAL_ARGUMENT,
+        "Lc is 2 but is followed by 1 byte(s).",
+    );
+
+    // Case 3S/4S error; Too many command bytes (Lc = 1, two data bytes)
+    expect_fail(
+        &[0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0x01],
+        ILLEGAL_ARGUMENT,
+        "Lc is 1 but is followed by 3 byte(s).",
+    );
+
+    // Case 3S/4E error; Too many command bytes (Lc = 1, two data bytes)
+    expect_fail(
+        &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0x00, 0x00],
+        ILLEGAL_ARGUMENT,
+        "Lc is 1 but is followed by 4 byte(s)",
+    );
+
+    // Verify that extended Lc goes up to 2^16 == 65536, not 2^16 - 1, as you'd usually expect.
+    // 65536 is represented by 0x0000 in the Lc field.
+    expect_success(
+        &[
+            &[0x00, 0x00, 0x00, 0x00, 0x00][..], // header w/B1 == 0 indicates extended
+            &[0x00, 0x00][..],                   // 0x0000 means Lc = 65536
+            &[0x00; 65536][..],                  // 65536 bytes of data.
+        ]
+        .concat(),
+    );
+
+    // One less byte of command data should fail
+    expect_fail(
+        &[
+            &[0x00, 0x00, 0x00, 0x00, 0x00][..], // header w/B1 == 0 indicates extended
+            &[0x00, 0x00][..],                   // 0x0000 means Lc = 65536
+            &[0x00; 65535][..],                  // 65536 - 1 bytes of data.
+        ]
+        .concat(),
+        ILLEGAL_ARGUMENT,
+        "Lc is 65536 but is followed by 65535 byte(s)",
+    );
+
+    Ok(())
+}
+
+#[gtest]
+fn handle_le_correction() -> Result<()> {
+    init();
+
+    let mut seq = Sequence::new();
+    let se_binder = build_mock_se(|mock_se| {
+        mock_se.expect_openLogicalChannel().times(1).in_sequence(&mut seq).returning(|_, _| {
+            Ok(LogicalChannelResponse {
+                channelNumber: 1,
+                selectResponse: "ats".as_bytes().to_vec(),
+            })
+        });
+
+        // First APDU has Le 0, but SE will respond saying it should be two.
+        mock_se
+            .expect_transmit()
+            .with(mp::eq([0x01, 0x00, 0x00, 0x00, /* Le */ 0x00]))
+            .times(1)
+            .in_sequence(&mut seq)
+            // Return SW1 0x6C, indicating Le should be corrected, and SW2 to indicate correct
+            // value, in this case 2.
+            .returning(|_| Ok(vec![0x6C, 0x02]));
+
+        // Automatic resend should adjust the Le and return success with two bytes of data.
+        mock_se
+            .expect_transmit()
+            .with(mp::eq([0x01, 0x00, 0x00, 0x00, /* Le */ 0x02]))
+            .times(1)
+            .in_sequence(&mut seq)
+            .returning(|_| Ok(vec![0x00, 0x00, 0x90, 0x00]));
+    });
+
+    let mut terminal = Terminal::new("se_name", se_binder)?;
+    terminal.set_connected(true);
+
+    let channel_id = terminal.open_logical_channel(&[], 0x00)?.unwrap();
+    // Although there will actually be two APDUs sent, the initial one and the corrected one, as
+    // far as the client knows, there's just one successful APDU.
+    let response =
+        terminal.transmit(channel_id, &[0x00, 0x00, 0x00, 0x00, /* Le */ 0x00], false)?;
+    assert_that!(response, eq(&ApduResponse(vec![0x00, 0x00, 0x90, 0x00])));
+
+    Ok(())
+}
+
+#[gtest]
+fn handle_response_chaining() -> Result<()> {
+    init();
+
+    let mut seq = Sequence::new();
+    let se_binder = build_mock_se(|mock_se| {
+        mock_se.expect_openLogicalChannel().times(1).in_sequence(&mut seq).returning(|_, _| {
+            Ok(LogicalChannelResponse {
+                channelNumber: 1,
+                selectResponse: "ats".as_bytes().to_vec(),
+            })
+        });
+        // First APDU has Le 0x10, but SE will respond with only the first four bytes and send
+        // status words indicating that GET DATA should be used to get the rest.
+        mock_se
+            .expect_transmit()
+            .with(mp::eq([0x01, 0x00, 0x00, 0x00, /* Le */ 0x10]))
+            .times(1)
+            .in_sequence(&mut seq)
+            // Return SW1 0x61, indicating that not all data was returned and SW 0x0C, indicating
+            // that 8 more bytes need to be retrieved
+            .returning(|_| Ok(vec![0x01, 0x02, 0x03, 0x04, 0x61, 0x0C]));
+        // Second APDU will be GET DATA, requesting 0x0C bytes.  Only return 4 and indicate
+        // another GET DATA is needed.
+        mock_se
+            .expect_transmit()
+            .with(mp::eq([0x01, 0xC0, 0x00, 0x00, /* Le */ 0x0C]))
+            .times(1)
+            .in_sequence(&mut seq)
+            .returning(|_| Ok(vec![0x05, 0x06, 0x07, 0x08, 0x61, 0x08]));
+        // Third APDU will be GET DATA, requesting 0x08 bytes.  Only return 4 and indicate another
+        // GET DATA is needed.
+        mock_se
+            .expect_transmit()
+            .with(mp::eq([0x01, 0xC0, 0x00, 0x00, /* Le */ 0x08]))
+            .times(1)
+            .in_sequence(&mut seq)
+            .returning(|_| Ok(vec![0x09, 0x0A, 0x0B, 0x0C, 0x61, 0x04]));
+        // Fourth and final APDU will be GET DATA, requesting 0x04 (12) bytes.  Return them and
+        // indicate success.
+        mock_se
+            .expect_transmit()
+            .with(mp::eq([0x01, 0xC0, 0x00, 0x00, /* Le */ 0x04]))
+            .times(1)
+            .in_sequence(&mut seq)
+            .returning(|_| Ok(vec![0x0D, 0x0E, 0x0F, 0x10, 0x90, 0x00]));
+    });
+
+    let mut terminal = Terminal::new("se_name", se_binder)?;
+    terminal.set_connected(true);
+
+    let channel_id = terminal.open_logical_channel(&[], 0x00)?.unwrap();
+    // Although four APDUs are exchanged, to the client it appears there was only one, and it
+    // returned all 0x10 bytes of data.
+    let response =
+        terminal.transmit(channel_id, &[0x00, 0x00, 0x00, 0x00, /* Le */ 0x10], false)?;
+    assert_that!(
+        response,
+        eq(&ApduResponse(vec![
+            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
+            0x0F, 0x10, 0x90, 0x00
+        ]))
+    );
+
+    Ok(())
+}
+
+fn build_mock_se(expectations: impl FnOnce(&mut MockISecureElement)) -> Strong<dyn ISecureElement> {
+    let mut se_mock = MockISecureElement::new();
+    expectations(&mut se_mock);
+
+    BnSecureElement::new_binder(se_mock, BinderFeatures::default())
+}
+
+fn expect_default_select(mock_se: &mut MockISecureElement) {
+    mock_se.expect_transmit().with(mp::eq(SELECT_DEFAULT_APDU)).returning(|_| Ok(vec![0x90, 0x00]));
+}
+
+fn binder_status(code: ExceptionCode, description: &str) -> impl Fn(&'_ binder::Status) -> bool {
+    let description = description.to_owned();
+    move |s: &binder::Status| {
+        s.exception_code() == code && s.get_description().contains(&description)
+    }
+}
diff --git a/omapi/src/test_utils.rs b/omapi/src/test_utils.rs
new file mode 100644
index 0000000..23a7cf9
--- /dev/null
+++ b/omapi/src/test_utils.rs
@@ -0,0 +1,33 @@
+// Copyright 2025, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! Utility functions used only in tests.
+
+pub fn init() {
+    android_logger::init_once(
+        android_logger::Config::default()
+            .with_tag("se_service_rules_test")
+            .with_max_level(log::LevelFilter::Trace)
+            .with_log_buffer(android_logger::LogId::System)
+            .format(|buf, record| {
+                writeln!(
+                    buf,
+                    "{}:{} - {}",
+                    record.file().unwrap_or("unknown"),
+                    record.line().unwrap_or(0),
+                    record.args()
+                )
+            }),
+    );
+}
diff --git a/omapi/src/utils.rs b/omapi/src/utils.rs
new file mode 100644
index 0000000..64837c6
--- /dev/null
+++ b/omapi/src/utils.rs
@@ -0,0 +1,144 @@
+// Copyright 2024, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! Utility functions and types, notably tools for creating binder exceptions and easy tracing of
+//! return values.
+
+use crate::{
+    access_enforcer::RefreshTagDo,
+    terminal::{Apdu, ApduResponse},
+};
+use binder::{self, ExceptionCode, Result};
+use std::error::Error;
+
+/// SE service errors
+pub enum ServiceSpecificException {
+    /// IO error communicating with SE.
+    IoError = 1,
+    /// No such Secure Element is configured.
+    NoSuchElement = 2,
+    /// Secure Element is not present (e.g. SIM is not inserted).
+    SecureElementNotPresent = 3,
+    /// Secure Element is not connected.
+    SecureElementNotConnected = 4,
+}
+
+/// Create a [`binder::Result`] containing a service-specific exception.
+pub fn service_specific_exception<T>(error: ServiceSpecificException, message: &str) -> Result<T> {
+    Err(binder::Status::new_service_specific_error_str(error as i32, Some(message)))
+}
+
+/// Create a [`binder::Result`]` containing an error with the specified [`ExceptionCode`] and
+/// message.
+pub fn binder_exception<T>(exception_code: ExceptionCode, message: &str) -> Result<T> {
+    Err(create_exception_status(exception_code, message))
+}
+
+/// Create a [`binder::Status`] with the specified [`ExceptionCode`] and message. Wrap in [`Err`]
+/// to create a [`binder::Result`] (or use [`binder_exception`]).
+pub fn create_exception_status(exception_code: ExceptionCode, message: &str) -> binder::Status {
+    binder::Status::new_exception_str(exception_code, Some(message))
+}
+
+/// The [`sensitive`] macro is used for logging sensitive data.  It logs at
+/// [`log::LevelFilter::Trace`], but only if sensitive logging is allowed, either because the
+/// "log_sensitive_data" feature is enabled or because we're building in a test configuration.
+#[macro_export]
+macro_rules! sensitive {
+    ($fmt:expr $(, $args:expr)* ) => {
+        #[cfg(any(feature = "log_sensitive_data", test))]
+            trace!($fmt $(, $args)*);
+        }
+    }
+
+/// An object that provides a string for tracing.
+trait Traceable {
+    fn trace_string(&self) -> String;
+}
+
+impl Traceable for Vec<u8> {
+    fn trace_string(&self) -> String {
+        hex::encode(self)
+    }
+}
+
+impl<T> Traceable for Option<T>
+where
+    T: Traceable,
+{
+    fn trace_string(&self) -> String {
+        match self {
+            Some(value) => format!("Some({})", value.trace_string()),
+            None => "None".to_string(),
+        }
+    }
+}
+
+macro_rules! trace_debug {
+    ($t:ty) => {
+        impl Traceable for $t {
+            fn trace_string(&self) -> String {
+                format!("{self:?}")
+            }
+        }
+    };
+}
+
+trace_debug!(Apdu);
+trace_debug!(ApduResponse);
+trace_debug!(RefreshTagDo);
+
+/// Provide an easy way to trace [`Traceable`] values that are about to be returned.  That is,
+/// supposing `result` is [`Traceable`] and is being returned from a function:
+///
+/// ```
+/// result.trace("context")
+/// ```
+///
+/// will output `result` in a trace message, then return it.  Likewise `sensitive()` can be used
+/// to trace a sensitive value, but only if sensitive logging is allowed.
+pub trait TraceResultExt {
+    /// Trace self, adding context string, and returns self, for additional processing.
+    fn trace(self, context: &str) -> Self;
+
+    /// Trace self as above, but only if feature `log_sensitive_data` is enabled, or if this is a
+    /// test build.  In other builds, do nothing.
+    fn sensitive(self, context: &str) -> Self
+    where
+        Self: std::marker::Sized,
+    {
+        if cfg!(any(feature = "log_sensitive_data", test)) {
+            Self::trace(self, context)
+        } else {
+            self
+        }
+    }
+}
+
+impl<T, E> TraceResultExt for std::result::Result<T, E>
+where
+    T: Traceable,
+    E: Error,
+{
+    fn trace(self, context: &str) -> Self {
+        log::trace!(
+            "{context} result: {}",
+            match self.as_ref() {
+                Ok(v) => format!("Ok({})", v.trace_string()),
+                Err(e) => format!("Err({e})"),
+            }
+        );
+        self
+    }
+}
```

