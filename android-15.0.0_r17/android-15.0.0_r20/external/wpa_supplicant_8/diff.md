```diff
diff --git a/Android.bp b/Android.bp
index 068630ba..a083f89e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -64,3 +64,40 @@ filegroup {
         "src/wps/http_server.c",
     ],
 }
+
+filegroup {
+    name: "wpa_supplicant_macsec_extra_driver_srcs",
+    srcs: [
+        "src/drivers/driver_macsec_linux.c",
+        "src/drivers/driver_wired_common.c",
+    ],
+}
+
+filegroup {
+    name: "hs20_client_srcs",
+    srcs: [
+        "hs20/client/est.c",
+        "hs20/client/oma_dm_client.c",
+        "hs20/client/osu_client.c",
+        "hs20/client/spp_client.c",
+        "src/common/wpa_ctrl.c",
+        "src/common/wpa_helpers.c",
+        "src/crypto/crypto_internal.c",
+        "src/crypto/md5-internal.c",
+        "src/crypto/sha1-internal.c",
+        "src/crypto/sha256-internal.c",
+        "src/crypto/tls_openssl_ocsp.c",
+        "src/utils/base64.c",
+        "src/utils/browser-wpadebug.c",
+        "src/utils/common.c",
+        "src/utils/eloop.c",
+        "src/utils/http_curl.c",
+        "src/utils/os_unix.c",
+        "src/utils/wpa_debug.c",
+        "src/utils/wpabuf.c",
+        "src/utils/xml-utils.c",
+        "src/utils/xml_libxml2.c",
+        "src/wps/http_server.c",
+        "src/wps/httpread.c",
+    ],
+}
diff --git a/Android.mk b/Android.mk
index bb8326cb..ca7a6206 100644
--- a/Android.mk
+++ b/Android.mk
@@ -1,5 +1,6 @@
 S_LOCAL_PATH := $(call my-dir)
 
+ifdef FORCE_USE_ANDROIDMK_FOR_WPA
 ifneq ($(filter VER_0_8_X VER_2_1_DEVEL,$(WPA_SUPPLICANT_VERSION)),)
 # The order of the 2 Android.mks does matter!
 # TODO: Clean up the Android.mks, reset all the temporary variables at the
@@ -13,3 +14,4 @@ include $(S_LOCAL_PATH)/hs20/client/Android.mk
 endif #End of Check for platform version
 endif #End of Check for target build variant
 endif
+endif
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
new file mode 100644
index 00000000..321bab6f
--- /dev/null
+++ b/PREUPLOAD.cfg
@@ -0,0 +1,2 @@
+[Builtin Hooks]
+bpfmt = true
diff --git a/TEST_MAPPING b/TEST_MAPPING
new file mode 100644
index 00000000..e9ea3dd7
--- /dev/null
+++ b/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+    "postsubmit": [
+        {
+            "name": "libhostapd_aidl_bp_unittest"
+        }
+    ]
+}
diff --git a/hostapd/Android.bp b/hostapd/Android.bp
index 8b79dd57..4f76a302 100644
--- a/hostapd/Android.bp
+++ b/hostapd/Android.bp
@@ -355,3 +355,352 @@ filegroup {
         "src/utils/wpa_debug.c",
     ],
 }
+
+prebuilt_etc {
+    name: "android.hardware.wifi.hostapd.xml.prebuilt",
+    src: "android.hardware.wifi.hostapd.xml",
+    relative_install_path: "vintf",
+    installable: false,
+}
+
+// For converting the default to soong
+cc_defaults {
+    name: "hostapd_driver_srcs_default",
+    srcs: [
+        "src/drivers/driver_nl80211.c",
+        "src/drivers/driver_nl80211_android.c",
+        "src/drivers/driver_nl80211_capa.c",
+        "src/drivers/driver_nl80211_event.c",
+        "src/drivers/driver_nl80211_monitor.c",
+        "src/drivers/driver_nl80211_scan.c",
+        "src/drivers/linux_ioctl.c",
+        "src/drivers/netlink.c",
+        "src/drivers/rfkill.c",
+        "src/utils/radiotap.c",
+    ],
+}
+
+cc_defaults {
+    name: "hostapd_driver_cflags_default",
+    cflags: [
+        "-DCONFIG_DRIVER_NL80211",
+    ] + select(soong_config_variable("wpa_supplicant_8", "board_wlan_device"), {
+        "bcmdhd": ["-DCONFIG_DRIVER_NL80211_BRCM"],
+        "synadhd": ["-DCONFIG_DRIVER_NL80211_SYNA"],
+        default: ["-DCONFIG_DRIVER_NL80211_QCA"],
+    }),
+}
+
+soong_config_module_type {
+    name: "hostapd_cc_defaults_type",
+    module_type: "cc_defaults",
+    config_namespace: "wpa_supplicant_8",
+    value_variables: [
+        "platform_version",
+    ],
+    properties: ["cflags"],
+}
+
+// Hostap related module share the same CFLAGS
+hostapd_cc_defaults_type {
+    name: "hostapd_cflags_default",
+    cflags: [
+        "-DWPA_IGNORE_CONFIG_ERRORS",
+        "-DANDROID_LOG_NAME=\"hostapd\"",
+        "-Wall",
+        "-Werror",
+        "-Wno-unused-parameter",
+        "-Wno-unused-variable",
+        "-Wno-macro-redefined",
+        "-DANDROID_P2P",
+        "-DCONFIG_CTRL_IFACE_CLIENT_DIR=\"/data/vendor/wifi/hostapd/sockets\"",
+        "-DCONFIG_CTRL_IFACE_DIR=\"/data/vendor/wifi/hostapd/ctrl\"",
+        "-DCONFIG_HOSTAPD_CLI_HISTORY_DIR=\"/data/vendor/wifi/hostapd\"",
+        "-DHOSTAPD",
+        "-DHOSTAPD_DUMP_STATE",
+        "-DCONFIG_NO_RADIUS",
+        "-DCONFIG_NO_ACCOUNTING",
+        "-DCONFIG_CTRL_IFACE",
+        "-DCONFIG_CTRL_IFACE_UNIX",
+        "-DCONFIG_SAE",
+        "-DCONFIG_IEEE80211AC",
+        "-DCONFIG_WEP",
+        "-DCONFIG_WPS",
+        "-DEAP_SERVER_WSC",
+        "-DCONFIG_DPP",
+        "-DEAP_SERVER_IDENTITY",
+        "-DEAP_SERVER",
+        "-DPKCS12_FUNCS",
+        "-DCRYPTO_RSA_OAEP_SHA256",
+        "-DTLS_DEFAULT_CIPHERS=\"DEFAULT:!EXP:!LOW\"",
+        "-DCONFIG_SHA256",
+        "-DCONFIG_SHA384",
+        "-DCONFIG_SHA512",
+        "-DCONFIG_ECC",
+        "-DCONFIG_NO_RANDOM_POOL",
+        "-DCONFIG_IPV6",
+        "-DCONFIG_JSON",
+        "-DNEED_AP_MLME",
+        "-DCONFIG_INTERWORKING",
+        "-DCONFIG_ACS",
+        "-DCONFIG_ANDROID_LOG",
+        "-DCONFIG_CTRL_IFACE_AIDL",
+    ] + select(soong_config_variable("wpa_supplicant_8", "hostapd_use_stub_lib"), {
+        true: ["-DANDROID_LIB_STUB"],
+        default: [],
+    }) + select(soong_config_variable("wpa_supplicant_8", "hostapd_11ax"), {
+        true: ["-DCONFIG_IEEE80211AX"],
+        default: [],
+    }) + select(soong_config_variable("wpa_supplicant_8", "board_hostapd_config_80211w_mfp_optional"), {
+        true: ["-DENABLE_HOSTAPD_CONFIG_80211W_MFP_OPTIONAL"],
+        default: [],
+    }) + select(soong_config_variable("wpa_supplicant_8", "board_hostapd_private_lib_event"), {
+        true: ["-DANDROID_LIB_EVENT"],
+        default: [],
+    }),
+    arch: {
+        arm: {
+            cflags: [
+                "-mabi=aapcs-linux",
+            ],
+        },
+    },
+    defaults: [
+        "hostapd_driver_cflags_default",
+    ],
+    soong_config_variables: {
+        platform_version: {
+            cflags: ["-DVERSION_STR_POSTFIX=\"-%s\""],
+        },
+    },
+    enabled: select(soong_config_variable("wpa_supplicant_8", "wpa_build_hostapd"), {
+        true: true,
+        default: false,
+    }),
+}
+
+cc_defaults {
+    name: "hostapd_includes_default",
+    local_include_dirs: [
+        ".",
+        "src",
+        "src/utils",
+    ],
+    include_dirs: [
+        // There's an if condition for external/libnl but current code base should always have this.
+        "external/libnl/include",
+        "system/security/keystore/include",
+    ],
+}
+
+cc_defaults {
+    name: "hostapd_srcs_default",
+    srcs: [
+        "main.c",
+        "config_file.c",
+        "src/ap/hostapd.c",
+        "src/ap/wpa_auth_glue.c",
+        "src/ap/drv_callbacks.c",
+        "src/ap/ap_drv_ops.c",
+        "src/ap/utils.c",
+        "src/ap/authsrv.c",
+        "src/ap/ieee802_1x.c",
+        "src/ap/ap_config.c",
+        "src/ap/eap_user_db.c",
+        "src/ap/ieee802_11_auth.c",
+        "src/ap/sta_info.c",
+        "src/ap/wpa_auth.c",
+        "src/ap/tkip_countermeasures.c",
+        "src/ap/ap_mlme.c",
+        "src/ap/wpa_auth_ie.c",
+        "src/ap/preauth_auth.c",
+        "src/ap/pmksa_cache_auth.c",
+        "src/ap/ieee802_11_shared.c",
+        "src/ap/beacon.c",
+        "src/ap/bss_load.c",
+        "src/ap/neighbor_db.c",
+        "src/ap/rrm.c",
+        "src/drivers/drivers.c",
+        "src/utils/eloop.c",
+        "src/utils/common.c",
+        "src/utils/wpa_debug.c",
+        "src/utils/wpabuf.c",
+        "src/utils/os_unix.c",
+        "src/utils/ip_addr.c",
+        "src/utils/crc32.c",
+        "src/common/ieee802_11_common.c",
+        "src/common/wpa_common.c",
+        "src/common/hw_features_common.c",
+        "src/common/ptksa_cache.c",
+        "src/eapol_auth/eapol_auth_sm.c",
+        "src/eapol_auth/eapol_auth_dump.c",
+        "src/ap/vlan_init.c",
+        "src/ap/vlan_ifconfig.c",
+        "src/ap/vlan.c",
+        "src/common/ctrl_iface_common.c",
+        "ctrl_iface.c",
+        "src/ap/ctrl_iface_ap.c",
+        "src/common/sae.c",
+        "src/l2_packet/l2_packet_none.c",
+        "src/utils/uuid.c",
+        "src/ap/wps_hostapd.c",
+        "src/eap_server/eap_server_wsc.c",
+        "src/eap_common/eap_wsc_common.c",
+        "src/wps/wps.c",
+        "src/wps/wps_common.c",
+        "src/wps/wps_attr_parse.c",
+        "src/wps/wps_attr_build.c",
+        "src/wps/wps_attr_process.c",
+        "src/wps/wps_dev_attr.c",
+        "src/wps/wps_enrollee.c",
+        "src/wps/wps_registrar.c",
+        "src/common/dpp.c",
+        "src/common/dpp_auth.c",
+        "src/common/dpp_backup.c",
+        "src/common/dpp_crypto.c",
+        "src/common/dpp_pkex.c",
+        "src/common/dpp_reconfig.c",
+        "src/common/dpp_tcp.c",
+        "src/ap/dpp_hostapd.c",
+        "src/ap/gas_query_ap.c",
+        "eap_register.c",
+        "src/eap_server/eap_server.c",
+        "src/eap_common/eap_common.c",
+        "src/eap_server/eap_server_methods.c",
+        "src/eap_server/eap_server_identity.c",
+        "src/common/dragonfly.c",
+        "src/crypto/crypto_openssl.c",
+        "src/crypto/tls_none.c",
+        "src/crypto/aes-siv.c",
+        "src/crypto/aes-ctr.c",
+        "src/crypto/sha1-prf.c",
+        "src/crypto/sha256-prf.c",
+        "src/crypto/sha256-tlsprf.c",
+        "src/crypto/sha256-kdf.c",
+        "src/crypto/sha384-kdf.c",
+        "src/crypto/sha512-kdf.c",
+        "src/crypto/sha384-prf.c",
+        "src/crypto/sha512-prf.c",
+        "src/tls/asn1.c",
+        "src/crypto/dh_groups.c",
+        "src/utils/base64.c",
+        "src/utils/json.c",
+        "src/ap/wmm.c",
+        "src/ap/ap_list.c",
+        "src/ap/comeback_token.c",
+        "src/pasn/pasn_common.c",
+        "src/pasn/pasn_responder.c",
+        "src/ap/ieee802_11.c",
+        "src/ap/hw_features.c",
+        "src/ap/dfs.c",
+        "src/ap/ieee802_11_ht.c",
+        "src/ap/ieee802_11_vht.c",
+        "src/common/gas.c",
+        "src/ap/gas_serv.c",
+        "src/drivers/driver_common.c",
+        "src/ap/acs.c",
+    ] + select(soong_config_variable("wpa_supplicant_8", "hostapd_11ax"), {
+        true: ["src/ap/ieee802_11_he.c"],
+        default: [],
+    }),
+    defaults: [
+        "hostapd_driver_srcs_default",
+    ],
+}
+
+cc_binary {
+    name: "hostapd_cli",
+    proprietary: true,
+    srcs: [
+        "hostapd_cli.c",
+        "src/common/cli.c",
+        "src/common/wpa_ctrl.c",
+        "src/utils/common.c",
+        "src/utils/edit.c",
+        "src/utils/eloop.c",
+        "src/utils/os_unix.c",
+        "src/utils/wpa_debug.c",
+    ],
+    shared_libs: [
+        "libc",
+        "libcutils",
+        "liblog",
+    ],
+    defaults: [
+        "hostapd_cflags_default",
+        "hostapd_includes_default",
+    ],
+}
+
+soong_config_module_type {
+    name: "hostapd_cc_binary",
+    module_type: "cc_binary",
+    config_namespace: "wpa_supplicant_8",
+    value_variables: [
+        "board_hostapd_private_lib",
+    ],
+    properties: ["static_libs"],
+}
+
+hostapd_cc_binary {
+    name: "hostapd",
+    proprietary: true,
+    relative_install_path: "hw",
+    //vintf_fragments: ["android.hardware.wifi.hostapd.xml"],
+    required: [
+        "android.hardware.wifi.hostapd.xml",
+    ],
+    static_libs: [
+        "libhostapd_aidl",
+    ],
+    shared_libs: [
+        "libc",
+        "libcutils",
+        "liblog",
+        "libcrypto",
+        "libssl",
+        "libnl",
+        "android.hardware.wifi.hostapd-V3-ndk",
+        "android.hardware.wifi.common-V2-ndk",
+        "libbase",
+        "libutils",
+        "libbinder_ndk",
+    ],
+    init_rc: ["hostapd.android.rc"],
+    defaults: [
+        "hostapd_srcs_default",
+        "hostapd_cflags_default",
+        "hostapd_includes_default",
+    ],
+    soong_config_variables: {
+        board_hostapd_private_lib: {
+            static_libs: ["%s"],
+        },
+    },
+}
+
+cc_library_static {
+    name: "libhostapd_aidl",
+    soc_specific: true,
+    srcs: [
+        "aidl/aidl.cpp",
+        "aidl/hostapd.cpp",
+    ],
+    shared_libs: [
+        "android.hardware.wifi.hostapd-V3-ndk",
+        "android.hardware.wifi.common-V2-ndk",
+        "libbinder_ndk",
+        "libbase",
+        "libutils",
+        "liblog",
+    ],
+    export_include_dirs: ["aidl"],
+    cppflags: [
+        "-Wall",
+        "-Werror",
+    ],
+    defaults: [
+        "hostapd_cflags_default",
+        "hostapd_includes_default",
+    ],
+}
diff --git a/hostapd/Android.mk b/hostapd/Android.mk
index d5d11907..680c572e 100644
--- a/hostapd/Android.mk
+++ b/hostapd/Android.mk
@@ -1209,7 +1209,7 @@ endif
 endif
 ifeq ($(HOSTAPD_USE_AIDL), y)
 LOCAL_SHARED_LIBRARIES += android.hardware.wifi.hostapd-V3-ndk
-LOCAL_SHARED_LIBRARIES += android.hardware.wifi.common-V1-ndk
+LOCAL_SHARED_LIBRARIES += android.hardware.wifi.common-V2-ndk
 LOCAL_SHARED_LIBRARIES += libbase libutils
 LOCAL_SHARED_LIBRARIES += libbinder_ndk
 LOCAL_STATIC_LIBRARIES += libhostapd_aidl
@@ -1264,7 +1264,7 @@ LOCAL_SRC_FILES := \
     aidl/hostapd.cpp
 LOCAL_SHARED_LIBRARIES := \
     android.hardware.wifi.hostapd-V3-ndk \
-    android.hardware.wifi.common-V1-ndk \
+    android.hardware.wifi.common-V2-ndk \
     libbinder_ndk \
     libbase \
     libutils \
diff --git a/hostapd/aidl/hostapd.cpp b/hostapd/aidl/hostapd.cpp
index afb4147f..12d0d9e7 100644
--- a/hostapd/aidl/hostapd.cpp
+++ b/hostapd/aidl/hostapd.cpp
@@ -35,6 +35,11 @@ extern "C"
 #include "drivers/linux_ioctl.h"
 }
 
+
+#ifdef ANDROID_HOSTAPD_UNITTEST
+#include "tests/unittest_overrides.h"
+#endif
+
 // The AIDL implementation for hostapd creates a hostapd.conf dynamically for
 // each interface. This file can then be used to hook onto the normal config
 // file parsing logic in hostapd code.  Helps us to avoid duplication of code
@@ -43,9 +48,78 @@ extern "C"
 namespace {
 constexpr char kConfFileNameFmt[] = "/data/vendor/wifi/hostapd/hostapd_%s.conf";
 
+/**
+ * To add an overlay file, add
+ *
+ * PRODUCT_COPY_FILES += \
+ *   <your/path/here>/hostapd_unmetered_overlay.conf:/vendor/etc/wifi/hostapd_unmetered_overlay.conf
+ *
+ * to the build file for your device, with the <your/path/here> being the path to your overlay in
+ * your repo. See the resolveVendorConfPath function in this file for more specifics on where this
+ * overlay file will wind up on your device.
+ *
+ * This overlay may configure any of the parameters listed in kOverlayableKeys. The kOverlayableKeys
+ * list is subject to change over time, as certain parameters may be added as APIs instead in the
+ * future.
+ *
+ * Example of what an overlay file might look like:
+ * $> cat hostapd_unmetered_overlay.conf
+ * dtim_period=2
+ * ap_max_inactivity=300
+ *
+ * Anything added to this overlay will be prepended to the hostapd.conf for unmetered (typically
+ * local only hotspots) interfaces.
+ */
+constexpr char kUnmeteredIfaceOverlayPath[] = "/etc/wifi/hostapd_unmetered_overlay.conf";
+
+/**
+ * Allow-list of hostapd.conf parameters (keys) that can be set via overlay.
+ *
+ * If introducing new APIs, be sure to remove keys from this list that would otherwise be
+ * controlled by the new API. This way we can avoid conflicting settings.
+ * Please file an FR to add new keys to this list.
+ */
+static const std::set<std::string> kOverlayableKeys = {
+	"ap_max_inactivity",
+	"assocresp_elements"
+	"beacon_int",
+	"disassoc_low_ack",
+	"dtim_period",
+	"fragm_threshold",
+	"max_listen_interval",
+	"max_num_sta",
+	"rts_threshold",
+	"skip_inactivity_poll",
+	"uapsd_advertisement_enabled",
+	"wmm_enabled",
+	"wmm_ac_vo_aifs",
+	"wmm_ac_vo_cwmin",
+	"wmm_ac_vo_cwmax",
+	"wmm_ac_vo_txop_limit",
+	"wmm_ac_vo_acm",
+	"wmm_ac_vi_aifs",
+	"wmm_ac_vi_cwmin",
+	"wmm_ac_vi_cwmax",
+	"wmm_ac_vi_txop_limit",
+	"wmm_ac_vi_acm",
+	"wmm_ac_bk_cwmin"
+	"wmm_ac_bk_cwmax"
+	"wmm_ac_bk_aifs",
+	"wmm_ac_bk_txop_limit",
+	"wmm_ac_bk_acm",
+	"wmm_ac_be_aifs",
+	"wmm_ac_be_cwmin",
+	"wmm_ac_be_cwmax",
+	"wmm_ac_be_txop_limit",
+	"wmm_ac_be_acm",
+};
+
 using android::base::RemoveFileIfExists;
 using android::base::StringPrintf;
+#ifndef ANDROID_HOSTAPD_UNITTEST
+using android::base::ReadFileToString;
 using android::base::WriteStringToFile;
+#endif
 using aidl::android::hardware::wifi::hostapd::BandMask;
 using aidl::android::hardware::wifi::hostapd::ChannelBandwidth;
 using aidl::android::hardware::wifi::hostapd::ChannelParams;
@@ -79,6 +153,12 @@ inline int32_t isAidlClientVersionAtLeast(int32_t expected_version)
 	return expected_version <= aidl_client_version;
 }
 
+inline int32_t areAidlServiceAndClientAtLeastVersion(int32_t expected_version)
+{
+	return isAidlServiceVersionAtLeast(expected_version)
+		&& isAidlClientVersionAtLeast(expected_version);
+}
+
 #define MAX_PORTS 1024
 bool GetInterfacesInBridge(std::string br_name,
                            std::vector<std::string>* interfaces) {
@@ -119,11 +199,42 @@ bool GetInterfacesInBridge(std::string br_name,
 	return true;
 }
 
+std::string resolveVendorConfPath(const std::string& conf_path)
+{
+#if defined(__ANDROID_APEX__)
+	// returns "/apex/<apexname>" + conf_path
+	std::string path = android::base::GetExecutablePath();
+	return path.substr(0, path.find_first_of('/', strlen("/apex/"))) + conf_path;
+#else
+	return std::string("/vendor") + conf_path;
+#endif
+}
+
+void logHostapdConfigError(int error, const std::string& file_path) {
+	wpa_printf(MSG_ERROR, "Cannot read/write hostapd config %s, error: %s", file_path.c_str(),
+			strerror(error));
+	struct stat st;
+	int result = stat(file_path.c_str(), &st);
+	if (result == 0) {
+		wpa_printf(MSG_ERROR, "hostapd config file uid: %d, gid: %d, mode: %d",st.st_uid,
+				st.st_gid, st.st_mode);
+	} else {
+		wpa_printf(MSG_ERROR, "Error calling stat() on hostapd config file: %s",
+				strerror(errno));
+	}
+}
+
 std::string WriteHostapdConfig(
-    const std::string& interface_name, const std::string& config)
+    const std::string& instance_name, const std::string& config,
+    const std::string br_name, const bool usesMlo)
 {
+	std::string conf_name_as_string = instance_name;
+	if (usesMlo) {
+		conf_name_as_string = StringPrintf(
+				"%s-%s", br_name.c_str(), instance_name.c_str());
+	}
 	const std::string file_path =
-	    StringPrintf(kConfFileNameFmt, interface_name.c_str());
+		StringPrintf(kConfFileNameFmt, conf_name_as_string.c_str());
 	if (WriteStringToFile(
 		config, file_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP,
 		getuid(), getgid())) {
@@ -131,21 +242,7 @@ std::string WriteHostapdConfig(
 	}
 	// Diagnose failure
 	int error = errno;
-	wpa_printf(
-		MSG_ERROR, "Cannot write hostapd config to %s, error: %s",
-		file_path.c_str(), strerror(error));
-	struct stat st;
-	int result = stat(file_path.c_str(), &st);
-	if (result == 0) {
-		wpa_printf(
-			MSG_ERROR, "hostapd config file uid: %d, gid: %d, mode: %d",
-			st.st_uid, st.st_gid, st.st_mode);
-	} else {
-		wpa_printf(
-			MSG_ERROR,
-			"Error calling stat() on hostapd config file: %s",
-			strerror(errno));
-	}
+	logHostapdConfigError(errno, file_path);
 	return "";
 }
 
@@ -339,6 +436,14 @@ std::string getInterfaceMacAddress(const std::string& if_name)
 	return mac_addr;
 }
 
+std::string trimWhitespace(const std::string& str) {
+	size_t pos = 0;
+	size_t len = str.size();
+	for (pos; pos < str.size() && std::isspace(str[pos]); ++pos){}
+	for (len; len - 1 > 0 && std::isspace(str[len-1]); --len){}
+	return str.substr(pos, len);
+}
+
 std::string CreateHostapdConfig(
 	const IfaceParams& iface_params,
 	const ChannelParams& channelParams,
@@ -587,17 +692,25 @@ std::string CreateHostapdConfig(
 #ifdef CONFIG_IEEE80211BE
 	if (iface_params.hwModeParams.enable80211BE && !is_60Ghz_used) {
 		eht_params_as_string = "ieee80211be=1\n";
-		if (isAidlServiceVersionAtLeast(2) && isAidlClientVersionAtLeast(2)) {
-			std::string interface_mac_addr = getInterfaceMacAddress(iface_params.name);
+		if (areAidlServiceAndClientAtLeastVersion(2)) {
+			std::string interface_mac_addr = getInterfaceMacAddress(
+					iface_params.usesMlo ? br_name : iface_params.name);
 			if (interface_mac_addr.empty()) {
 				wpa_printf(MSG_ERROR,
 				    "Unable to set interface mac address as bssid for 11BE SAP");
 				return "";
 			}
-			eht_params_as_string += StringPrintf(
-				"bssid=%s\n"
-				"mld_ap=1",
-				interface_mac_addr.c_str());
+            if (iface_params.usesMlo) {
+                eht_params_as_string += StringPrintf(
+                    "mld_addr=%s\n"
+                    "mld_ap=1",
+                    interface_mac_addr.c_str());
+            } else {
+                eht_params_as_string += StringPrintf(
+                    "bssid=%s\n"
+                    "mld_ap=1",
+                    interface_mac_addr.c_str());
+            }
 		}
 		/* TODO set eht_su_beamformer, eht_su_beamformee, eht_mu_beamformer */
 	} else {
@@ -714,7 +827,7 @@ std::string CreateHostapdConfig(
 #endif /* CONFIG_INTERWORKING */
 
 	std::string bridge_as_string;
-	if (!br_name.empty()) {
+	if (!br_name.empty() && !iface_params.usesMlo) {
 		bridge_as_string = StringPrintf("bridge=%s", br_name.c_str());
 	}
 
@@ -736,10 +849,33 @@ std::string CreateHostapdConfig(
 			"owe_transition_ifname=%s", owe_transition_ifname.c_str());
 	}
 
+	std::string ap_isolation_as_string = StringPrintf("ap_isolate=%s",
+			isAidlServiceVersionAtLeast(3) && nw_params.isClientIsolationEnabled ?
+			"1" : "0");
+
+	// Overlay for LOHS (unmetered SoftAP)
+	std::string overlay_path = resolveVendorConfPath(kUnmeteredIfaceOverlayPath);
+	std::string overlay_string;
+	if (!nw_params.isMetered
+			&& 0 == access(overlay_path.c_str(), R_OK)
+			&& !ReadFileToString(overlay_path, &overlay_string)) {
+		logHostapdConfigError(errno, overlay_path);
+		return "";
+	}
+	std::string sanitized_overlay = "";
+	std::istringstream overlay_stream(overlay_string);
+	for (std::string line; std::getline(overlay_stream, line);) {
+		std::string overlay_key = trimWhitespace(line.substr(0, line.find("=")));
+		if (kOverlayableKeys.contains(overlay_key)) {
+			sanitized_overlay.append(line + "\n");
+		}
+	}
+
 	return StringPrintf(
+		"%s\n"
 		"interface=%s\n"
 		"driver=nl80211\n"
-		"ctrl_interface=/data/vendor/wifi/hostapd/ctrl\n"
+		"ctrl_interface=/data/vendor/wifi/hostapd/ctrl_%s\n"
 		// ssid2 signals to hostapd that the value is not a literal value
 		// for use as a SSID.  In this case, we're giving it a hex
 		// std::string and hostapd needs to expect that.
@@ -761,8 +897,12 @@ std::string CreateHostapdConfig(
 		"%s\n"
 		"%s\n"
 		"%s\n"
+		"%s\n"
 		"%s\n",
-		iface_params.name.c_str(), ssid_as_string.c_str(),
+		sanitized_overlay.c_str(),
+		iface_params.usesMlo ? br_name.c_str() : iface_params.name.c_str(),
+		iface_params.name.c_str(),
+		ssid_as_string.c_str(),
 		channel_config_as_string.c_str(),
 		iface_params.hwModeParams.enable80211N ? 1 : 0,
 		iface_params.hwModeParams.enable80211AC ? 1 : 0,
@@ -778,7 +918,8 @@ std::string CreateHostapdConfig(
 		owe_transition_ifname_as_string.c_str(),
 		enable_edmg_as_string.c_str(),
 		edmg_channel_as_string.c_str(),
-		vendor_elements_as_string.c_str());
+		vendor_elements_as_string.c_str(),
+		ap_isolation_as_string.c_str());
 }
 
 Generation getGeneration(hostapd_hw_modes *current_mode)
@@ -839,23 +980,39 @@ ChannelBandwidth getChannelBandwidth(struct hostapd_config *iconf)
 	}
 }
 
+std::optional<struct sta_info*> getStaInfoByMacAddr(const struct hostapd_data* iface_hapd,
+		const u8 *mac_addr) {
+	if (iface_hapd == nullptr || mac_addr == nullptr){
+		wpa_printf(MSG_ERROR, "nullptr passsed to getStaInfoByMacAddr!");
+		return std::nullopt;
+	}
+
+	for (struct sta_info* sta_ptr = iface_hapd->sta_list; sta_ptr; sta_ptr = sta_ptr->next) {
+		int res;
+		res = memcmp(sta_ptr->addr, mac_addr, ETH_ALEN);
+		if (res == 0) {
+			return sta_ptr;
+		}
+	}
+	return std::nullopt;
+}
+
 bool forceStaDisconnection(struct hostapd_data* hapd,
 			   const std::vector<uint8_t>& client_address,
 			   const uint16_t reason_code) {
-	struct sta_info *sta;
 	if (client_address.size() != ETH_ALEN) {
 		return false;
 	}
-	for (sta = hapd->sta_list; sta; sta = sta->next) {
-		int res;
-		res = memcmp(sta->addr, client_address.data(), ETH_ALEN);
-		if (res == 0) {
-			wpa_printf(MSG_INFO, "Force client:" MACSTR " disconnect with reason: %d",
-			    MAC2STR(client_address.data()), reason_code);
-			ap_sta_disconnect(hapd, sta, sta->addr, reason_code);
-			return true;
-		}
+
+	auto sta_ptr_optional = getStaInfoByMacAddr(hapd, client_address.data());
+	if (sta_ptr_optional.has_value()) {
+		wpa_printf(MSG_INFO, "Force client:" MACSTR " disconnect with reason: %d",
+				MAC2STR(client_address.data()), reason_code);
+		ap_sta_disconnect(hapd, sta_ptr_optional.value(), sta_ptr_optional.value()->addr,
+				reason_code);
+		return true;
 	}
+
 	return false;
 }
 
@@ -979,6 +1136,12 @@ Hostapd::Hostapd(struct hapd_interfaces* interfaces)
 	return setDebugParamsInternal(level);
 }
 
+::ndk::ScopedAStatus Hostapd::removeLinkFromMultipleLinkBridgedApIface(
+        const std::string& iface_name, const std::string& linkIdentity)
+{
+	return removeLinkFromMultipleLinkBridgedApIfaceInternal(iface_name, linkIdentity);
+}
+
 ::ndk::ScopedAStatus Hostapd::addAccessPointInternal(
 	const IfaceParams& iface_params,
 	const NetworkParams& nw_params)
@@ -1011,35 +1174,58 @@ std::vector<uint8_t>  generateRandomOweSsid()
 	return vssid;
 }
 
+
+// Both of bridged dual APs and MLO AP will be treated as concurrenct APs.
+// -----------------------------------------
+//                  | br_name     |  instance#1 | instance#2 |
+// ___________________________________________________________
+// bridged dual APs | ap_br_wlanX |   wlan X    |   wlanY    |
+// ___________________________________________________________
+// MLO AP           | wlanX       |     0       |     1      |
+// ___________________________________________________________
+// Both will be added in br_interfaces_[$br_name] and use instance's name
+// to be iface_params_new.name to create single Access point.
 ::ndk::ScopedAStatus Hostapd::addConcurrentAccessPoints(
 	const IfaceParams& iface_params, const NetworkParams& nw_params)
 {
 	int channelParamsListSize = iface_params.channelParams.size();
 	// Get available interfaces in bridge
-	std::vector<std::string> managed_interfaces;
-	std::string br_name = StringPrintf(
-		"%s", iface_params.name.c_str());
-	if (!GetInterfacesInBridge(br_name, &managed_interfaces)) {
+	std::vector<std::string> managed_instances;
+	std::string br_name = StringPrintf("%s", iface_params.name.c_str());
+	if (iface_params.usesMlo) {
+		// MLO AP is using link id as instance.
+		for (std::size_t i = 0; i < iface_params.instanceIdentities->size(); i++) {
+			managed_instances.push_back(iface_params.instanceIdentities->at(i)->c_str());
+		}
+	} else {
+		if (!GetInterfacesInBridge(br_name, &managed_instances)) {
+			return createStatusWithMsg(HostapdStatusCode::FAILURE_UNKNOWN,
+					"Get interfaces in bridge failed.");
+		}
+	}
+	// Either bridged AP or MLO AP should have two instances.
+	if (managed_instances.size() < channelParamsListSize) {
 		return createStatusWithMsg(HostapdStatusCode::FAILURE_UNKNOWN,
-			"Get interfaces in bridge failed.");
+				"Available interfaces less than requested bands");
 	}
-	if (managed_interfaces.size() < channelParamsListSize) {
+
+	if (iface_params.usesMlo
+				&& nw_params.encryptionType == EncryptionType::WPA3_OWE_TRANSITION) {
 		return createStatusWithMsg(HostapdStatusCode::FAILURE_UNKNOWN,
-			"Available interfaces less than requested bands");
+				"Invalid encryptionType (OWE transition) for MLO SAP.");
 	}
 	// start BSS on specified bands
 	for (std::size_t i = 0; i < channelParamsListSize; i ++) {
 		IfaceParams iface_params_new = iface_params;
 		NetworkParams nw_params_new = nw_params;
-		iface_params_new.name = managed_interfaces[i];
-
 		std::string owe_transition_ifname = "";
+		iface_params_new.name = managed_instances[i];
 		if (nw_params.encryptionType == EncryptionType::WPA3_OWE_TRANSITION) {
 			if (i == 0 && i+1 < channelParamsListSize) {
-				owe_transition_ifname = managed_interfaces[i+1];
+				owe_transition_ifname = managed_instances[i+1];
 				nw_params_new.encryptionType = EncryptionType::NONE;
 			} else {
-				owe_transition_ifname = managed_interfaces[0];
+				owe_transition_ifname = managed_instances[0];
 				nw_params_new.isHidden = true;
 				nw_params_new.ssid = generateRandomOweSsid();
 			}
@@ -1050,15 +1236,61 @@ std::vector<uint8_t>  generateRandomOweSsid()
 		    br_name, owe_transition_ifname);
 		if (!status.isOk()) {
 			wpa_printf(MSG_ERROR, "Failed to addAccessPoint %s",
-				   managed_interfaces[i].c_str());
+				   managed_instances[i].c_str());
 			return status;
 		}
 	}
+
+	if (iface_params.usesMlo) {
+		std::size_t i = 0;
+		std::size_t j = 0;
+		for (i = 0; i < interfaces_->count; i++) {
+			struct hostapd_iface *iface = interfaces_->iface[i];
+
+			for (j = 0; j < iface->num_bss; j++) {
+				struct hostapd_data *iface_hapd = iface->bss[j];
+				if (hostapd_enable_iface(iface_hapd->iface) < 0) {
+					wpa_printf(
+					MSG_ERROR, "Enabling interface %s failed on %zu",
+						iface_params.name.c_str(), i);
+					return createStatus(HostapdStatusCode::FAILURE_UNKNOWN);
+				}
+			}
+		}
+    }
 	// Save bridge interface info
-	br_interfaces_[br_name] = managed_interfaces;
+	br_interfaces_[br_name] = managed_instances;
 	return ndk::ScopedAStatus::ok();
 }
 
+struct hostapd_data * hostapd_get_iface_by_link_id(struct hapd_interfaces *interfaces,
+					const size_t link_id)
+{
+#ifdef CONFIG_IEEE80211BE
+	size_t i, j;
+
+	for (i = 0; i < interfaces->count; i++) {
+		struct hostapd_iface *iface = interfaces->iface[i];
+
+		for (j = 0; j < iface->num_bss; j++) {
+			struct hostapd_data *hapd = iface->bss[j];
+
+			if (link_id == hapd->mld_link_id)
+				return hapd;
+		}
+	}
+#endif
+	return NULL;
+}
+
+// Both of bridged dual APs and MLO AP will be treated as concurrenct APs.
+// -----------------------------------------
+//                  | br_name                 |  iface_params.name
+// _______________________________________________________________
+// bridged dual APs | bridged interface name  |  interface name
+// _______________________________________________________________
+// MLO AP           | AP interface name       |  mld link id as instance name
+// _______________________________________________________________
 ::ndk::ScopedAStatus Hostapd::addSingleAccessPoint(
 	const IfaceParams& iface_params,
 	const ChannelParams& channelParams,
@@ -1066,10 +1298,19 @@ std::vector<uint8_t>  generateRandomOweSsid()
 	const std::string br_name,
 	const std::string owe_transition_ifname)
 {
-	if (hostapd_get_iface(interfaces_, iface_params.name.c_str())) {
+	if (iface_params.usesMlo) { // the mlo case, iface name is instance name which is mld_link_id
+		if (hostapd_get_iface_by_link_id(interfaces_, (size_t) iface_params.name.c_str())) {
+			wpa_printf(
+				MSG_ERROR, "Instance link id %s already present",
+				iface_params.name.c_str());
+			return createStatus(HostapdStatusCode::FAILURE_IFACE_EXISTS);
+		}
+	}
+	if (hostapd_get_iface(interfaces_,
+			iface_params.usesMlo ? br_name.c_str() : iface_params.name.c_str())) {
 		wpa_printf(
-			MSG_ERROR, "Interface %s already present",
-			iface_params.name.c_str());
+			MSG_ERROR, "Instance interface %s already present",
+			iface_params.usesMlo ? br_name.c_str() : iface_params.name.c_str());
 		return createStatus(HostapdStatusCode::FAILURE_IFACE_EXISTS);
 	}
 	const auto conf_params = CreateHostapdConfig(iface_params, channelParams, nw_params,
@@ -1079,26 +1320,46 @@ std::vector<uint8_t>  generateRandomOweSsid()
 		return createStatus(HostapdStatusCode::FAILURE_ARGS_INVALID);
 	}
 	const auto conf_file_path =
-		WriteHostapdConfig(iface_params.name, conf_params);
+		WriteHostapdConfig(iface_params.name, conf_params, br_name, iface_params.usesMlo);
 	if (conf_file_path.empty()) {
 		wpa_printf(MSG_ERROR, "Failed to write config file");
 		return createStatus(HostapdStatusCode::FAILURE_UNKNOWN);
 	}
 	std::string add_iface_param_str = StringPrintf(
-		"%s config=%s", iface_params.name.c_str(),
+		"%s config=%s", iface_params.usesMlo ? br_name.c_str(): iface_params.name.c_str(),
 		conf_file_path.c_str());
 	std::vector<char> add_iface_param_vec(
 		add_iface_param_str.begin(), add_iface_param_str.end() + 1);
 	if (hostapd_add_iface(interfaces_, add_iface_param_vec.data()) < 0) {
 		wpa_printf(
-			MSG_ERROR, "Adding interface %s failed",
+			MSG_ERROR, "Adding hostapd iface %s failed",
 			add_iface_param_str.c_str());
 		return createStatus(HostapdStatusCode::FAILURE_UNKNOWN);
 	}
-	struct hostapd_data* iface_hapd =
-	    hostapd_get_iface(interfaces_, iface_params.name.c_str());
+
+	// find the iface and set up callback.
+	struct hostapd_data* iface_hapd = iface_params.usesMlo ?
+		hostapd_get_iface_by_link_id(interfaces_, (size_t) iface_params.name.c_str()) :
+		hostapd_get_iface(interfaces_, iface_params.name.c_str());
 	WPA_ASSERT(iface_hapd != nullptr && iface_hapd->iface != nullptr);
+	if (iface_params.usesMlo) {
+		memcmp(iface_hapd->conf->iface, br_name.c_str(), br_name.size());
+	}
+
+	// Callback discrepancy between bridged dual APs and MLO AP
+	// Note: Only bridged dual APs will have "iface_hapd->conf->bridge" and
+	// Only MLO AP will have "iface_hapd->mld_link_id"
 	// Register the setup complete callbacks
+	// -----------------------------------------
+	//                    |   bridged dual APs     | bridged single link MLO | MLO SAP
+	// _________________________________________________________________________________________
+	// hapd->conf->bridge | bridged interface name |  bridged interface nam  | N/A
+	// _________________________________________________________________________________________
+	// hapd->conf->iface  | AP interface name      |  AP interface name      | AP interface name
+	// _________________________________________________________________________________________
+	// hapd->mld_link_id  | 0 (default value)      |      link id (0)        | link id (0 or 1)
+	// _________________________________________________________________________________________
+	// hapd->mld_ap       |         0              |            1            |     1
 	on_setup_complete_internal_callback =
 		[this](struct hostapd_data* iface_hapd) {
 			wpa_printf(
@@ -1107,11 +1368,18 @@ std::vector<uint8_t>  generateRandomOweSsid()
 			if (iface_hapd->iface->state == HAPD_IFACE_DISABLED) {
 				// Invoke the failure callback on all registered
 				// clients.
+				std::string instanceName = iface_hapd->conf->iface;
+#ifdef CONFIG_IEEE80211BE
+				if (iface_hapd->conf->mld_ap
+						&& strlen(iface_hapd->conf->bridge) == 0) {
+					instanceName = std::to_string(iface_hapd->mld_link_id);
+				}
+#endif
 				for (const auto& callback : callbacks_) {
 					auto status = callback->onFailure(
 						strlen(iface_hapd->conf->bridge) > 0 ?
 						iface_hapd->conf->bridge : iface_hapd->conf->iface,
-							    iface_hapd->conf->iface);
+							    instanceName);
 					if (!status.isOk()) {
 						wpa_printf(MSG_ERROR, "Failed to invoke onFailure");
 					}
@@ -1129,9 +1397,25 @@ std::vector<uint8_t>  generateRandomOweSsid()
 		ClientInfo info;
 		info.ifaceName = strlen(iface_hapd->conf->bridge) > 0 ?
 			iface_hapd->conf->bridge : iface_hapd->conf->iface;
-		info.apIfaceInstance = iface_hapd->conf->iface;
+		std::string instanceName = iface_hapd->conf->iface;
+#ifdef CONFIG_IEEE80211BE
+		if (iface_hapd->conf->mld_ap
+				&& strlen(iface_hapd->conf->bridge) == 0) {
+			instanceName = std::to_string(iface_hapd->mld_link_id);
+		}
+#endif
+		info.apIfaceInstance = instanceName;
 		info.clientAddress.assign(mac_addr, mac_addr + ETH_ALEN);
 		info.isConnected = authorized;
+		if(isAidlServiceVersionAtLeast(3) && !authorized) {
+			u16 disconnect_reason_code = WLAN_REASON_UNSPECIFIED;
+			auto sta_ptr_optional = getStaInfoByMacAddr(iface_hapd, mac_addr);
+			if (sta_ptr_optional.has_value()){
+				disconnect_reason_code = sta_ptr_optional.value()->deauth_reason;
+			}
+			info.disconnectReasonCode =
+					static_cast<common::DeauthenticationReasonCode>(disconnect_reason_code);
+		}
 		for (const auto &callback : callbacks_) {
 			auto status = callback->onConnectedClientsChanged(info);
 			if (!status.isOk()) {
@@ -1150,10 +1434,16 @@ std::vector<uint8_t>  generateRandomOweSsid()
 					strlen(AP_EVENT_ENABLED)) == 0 ||
 			os_strncmp(txt, WPA_EVENT_CHANNEL_SWITCH,
 					strlen(WPA_EVENT_CHANNEL_SWITCH)) == 0) {
+			std::string instanceName = iface_hapd->conf->iface;
+#ifdef CONFIG_IEEE80211BE
+			if (iface_hapd->conf->mld_ap && strlen(iface_hapd->conf->bridge) == 0) {
+				instanceName = std::to_string(iface_hapd->mld_link_id);
+			}
+#endif
 			ApInfo info;
 			info.ifaceName = strlen(iface_hapd->conf->bridge) > 0 ?
 				iface_hapd->conf->bridge : iface_hapd->conf->iface,
-			info.apIfaceInstance = iface_hapd->conf->iface;
+			info.apIfaceInstance = instanceName;
 			info.freqMhz = iface_hapd->iface->freq;
 			info.channelBandwidth = getChannelBandwidth(iface_hapd->iconf);
 			info.generation = getGeneration(iface_hapd->iface->current_mode);
@@ -1169,11 +1459,18 @@ std::vector<uint8_t>  generateRandomOweSsid()
 		} else if (os_strncmp(txt, AP_EVENT_DISABLED, strlen(AP_EVENT_DISABLED)) == 0
                            || os_strncmp(txt, INTERFACE_DISABLED, strlen(INTERFACE_DISABLED)) == 0)
 		{
+			std::string instanceName = iface_hapd->conf->iface;
+#ifdef CONFIG_IEEE80211BE
+			if (iface_hapd->conf->mld_ap && strlen(iface_hapd->conf->bridge) == 0) {
+				instanceName = std::to_string(iface_hapd->mld_link_id);
+			}
+#endif
 			// Invoke the failure callback on all registered clients.
 			for (const auto& callback : callbacks_) {
-				auto status = callback->onFailure(strlen(iface_hapd->conf->bridge) > 0 ?
+				auto status =
+					callback->onFailure(strlen(iface_hapd->conf->bridge) > 0 ?
 					iface_hapd->conf->bridge : iface_hapd->conf->iface,
-						    iface_hapd->conf->iface);
+						instanceName);
 				if (!status.isOk()) {
 					wpa_printf(MSG_ERROR, "Failed to invoke onFailure");
 				}
@@ -1188,7 +1485,8 @@ std::vector<uint8_t>  generateRandomOweSsid()
 	iface_hapd->sta_authorized_cb_ctx = iface_hapd;
 	wpa_msg_register_aidl_cb(onAsyncWpaEventCb);
 
-	if (hostapd_enable_iface(iface_hapd->iface) < 0) {
+	// Multi-link MLO should enable iface after both links have been set.
+	if (!iface_params.usesMlo && hostapd_enable_iface(iface_hapd->iface) < 0) {
 		wpa_printf(
 			MSG_ERROR, "Enabling interface %s failed",
 			iface_params.name.c_str());
@@ -1288,6 +1586,23 @@ std::vector<uint8_t>  generateRandomOweSsid()
 	return ndk::ScopedAStatus::ok();
 }
 
+::ndk::ScopedAStatus Hostapd::removeLinkFromMultipleLinkBridgedApIfaceInternal(
+const std::string& iface_name, const std::string& linkIdentity)
+{
+	if (!hostapd_get_iface(interfaces_, iface_name.c_str())) {
+		wpa_printf(MSG_ERROR, "Interface %s doesn't exist", iface_name.c_str());
+		return createStatus(HostapdStatusCode::FAILURE_IFACE_UNKNOWN);
+	}
+	struct hostapd_data* iface_hapd =
+		hostapd_get_iface_by_link_id(interfaces_, (size_t) linkIdentity.c_str());
+	if (iface_hapd) {
+		if (0 == hostapd_link_remove(iface_hapd, 1)) {
+			return ndk::ScopedAStatus::ok();
+		}
+	}
+	return createStatus(HostapdStatusCode::FAILURE_ARGS_INVALID);
+}
+
 }  // namespace hostapd
 }  // namespace wifi
 }  // namespace hardware
diff --git a/hostapd/aidl/hostapd.h b/hostapd/aidl/hostapd.h
index ffdbd8e9..ba47810a 100644
--- a/hostapd/aidl/hostapd.h
+++ b/hostapd/aidl/hostapd.h
@@ -55,6 +55,8 @@ public:
 	    const std::vector<uint8_t>& client_address,
 	    Ieee80211ReasonCode reason_code) override;
 	::ndk::ScopedAStatus setDebugParams(DebugLevel level) override;
+	::ndk::ScopedAStatus removeLinkFromMultipleLinkBridgedApIface(
+		const std::string& iface_name, const std::string& linkIdentity) override;
 private:
 	// Corresponding worker functions for the AIDL methods.
 	::ndk::ScopedAStatus addAccessPointInternal(
@@ -77,7 +79,8 @@ private:
 	    const std::vector<uint8_t>& client_address,
 	    Ieee80211ReasonCode reason_code);
 	::ndk::ScopedAStatus setDebugParamsInternal(DebugLevel level);
-
+	::ndk::ScopedAStatus removeLinkFromMultipleLinkBridgedApIfaceInternal(
+		const std::string& iface_name, const std::string& linkIdentity);
 	// Raw pointer to the global structure maintained by the core.
 	struct hapd_interfaces* interfaces_;
 	// Callbacks registered.
diff --git a/hostapd/aidl/tests/Android.bp b/hostapd/aidl/tests/Android.bp
new file mode 100644
index 00000000..51444d23
--- /dev/null
+++ b/hostapd/aidl/tests/Android.bp
@@ -0,0 +1,56 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_team: "trendy_team_fwk_wifi_hal",
+    default_applicable_licenses: [
+        "external_wpa_supplicant_8_license",
+        "external_wpa_supplicant_8_hostapd_license",
+    ],
+}
+
+cc_test {
+    name: "libhostapd_aidl_bp_unittest",
+    defaults: [
+        "hostapd_cflags_defaults",
+    ],
+    require_root: true,
+    soc_specific: true,
+    srcs: [
+        "unittests.cpp",
+    ],
+    shared_libs: [
+        "android.hardware.wifi.hostapd-V3-ndk",
+        "libbinder_ndk",
+        "libbase",
+        "libutils",
+        "liblog",
+    ],
+    static_libs: [
+        "libgtest",
+    ],
+    header_libs: [
+        "hostapd_headers",
+        "libhostapd_aidl_headers",
+    ],
+    cppflags: [
+        "-DANDROID_HOSTAPD_UNITTEST",
+    ],
+    test_options: {
+        unit_test: true,
+    },
+    test_suites: [
+        "general-tests",
+    ],
+}
diff --git a/hostapd/aidl/tests/unittest_overrides.h b/hostapd/aidl/tests/unittest_overrides.h
new file mode 100644
index 00000000..a5be1781
--- /dev/null
+++ b/hostapd/aidl/tests/unittest_overrides.h
@@ -0,0 +1,91 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+
+#pragma once
+
+#include <android-base/logging.h>
+
+static ::android::base::LogSeverity wpa_to_android_level(int level)
+{
+	if (level == MSG_ERROR)
+		return ::android::base::ERROR;
+	if (level == MSG_WARNING)
+		return ::android::base::WARNING;
+	if (level == MSG_INFO)
+		return ::android::base::INFO;
+	return ::android::base::DEBUG;
+}
+
+// don't use hostapd's wpa_printf for unit testing. It won't compile otherwise
+void wpa_printf(int level, const char *fmt, ...) {
+	va_list ap;
+	va_start(ap, fmt);
+	LOG(wpa_to_android_level(level)) << ::android::base::StringPrintf(fmt, ap);
+	va_end(ap);
+}
+
+static int hostapd_unittest_stat_ret = 0;
+int stat(const char* pathname, struct stat* stabuf) {
+	if (hostapd_unittest_stat_ret != 0) {
+		errno = EINVAL;
+	}
+	return hostapd_unittest_stat_ret;
+}
+
+static int hostapd_unittest_accessRet = 0;
+int access(const char* pathname, int mode) {
+	if (hostapd_unittest_accessRet != 0) {
+		errno = EINVAL;
+	}
+	return hostapd_unittest_accessRet;
+}
+
+
+// You can inspect the string here to see what we tried to write to a file
+static std::string hostapd_unittest_config_output = "";
+static bool hostapd_unittest_WriteStringToFileRet = true;
+bool WriteStringToFile(const std::string& content, const std::string& path, mode_t mode,
+		uid_t owner, gid_t group) {
+	if (!hostapd_unittest_WriteStringToFileRet) {
+		errno = EINVAL;
+	} else {
+		hostapd_unittest_config_output = content;
+	}
+	return hostapd_unittest_WriteStringToFileRet;
+}
+
+// You can simulate a file having content with this string
+static std::string hostapd_unittest_overlay_content = "";
+static bool hostapd_unittest_ReadFileToStringRet = true;
+bool ReadFileToString(const std::string& path, std::string* content) {
+	*content = hostapd_unittest_overlay_content;
+	LOG(INFO) << "*content = " << *content;
+	return hostapd_unittest_ReadFileToStringRet;
+}
+
+/**
+ * We can simulate I/O operations failing by re-defining the calls.
+ *
+ * By default, all files are empty, and all calls succeed.
+ */
+void resetOverrides() {
+	hostapd_unittest_stat_ret = 0;
+	hostapd_unittest_WriteStringToFileRet = true;
+	hostapd_unittest_config_output = "";
+	hostapd_unittest_accessRet = 0;
+	hostapd_unittest_overlay_content = "";
+	hostapd_unittest_ReadFileToStringRet = true;
+}
diff --git a/hostapd/aidl/tests/unittests.cpp b/hostapd/aidl/tests/unittests.cpp
new file mode 100644
index 00000000..696e1239
--- /dev/null
+++ b/hostapd/aidl/tests/unittests.cpp
@@ -0,0 +1,246 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+
+#include <cstring>
+
+#include <gtest/gtest.h>
+#include "../hostapd.cpp"
+
+namespace aidl::android::hardware::wifi::hostapd {
+unsigned char kTestSsid[] = {0x31, 0x32, 0x33, 0x61, 0x62, 0x63, 0x64};
+
+class HostapdConfigTest : public testing::Test {
+	protected:
+	void SetUp() override {
+		resetOverrides();
+
+		mIface_params = {
+			.name = "wlan42",
+			.hwModeParams = {
+				.enable80211N = true,
+				.enable80211AC = false,
+				.enable80211AX = false,
+				.enable6GhzBand = false,
+				.enableHeSingleUserBeamformer = false,
+				.enableHeSingleUserBeamformee = false,
+				.enableHeMultiUserBeamformer = false,
+				.enableHeTargetWakeTime = false,
+				.enableEdmg = false,
+				.enable80211BE = false,
+				.maximumChannelBandwidth = ChannelBandwidth::BANDWIDTH_AUTO,
+			},
+			.channelParams = {},  // not used in config creation
+			.vendorData = {},  // not used in config creation
+			.instanceIdentities = {},  // not used in config creation
+			.usesMlo = false,
+		};
+		mChannel_params = {
+			.bandMask = BandMask::BAND_2_GHZ,
+			.acsChannelFreqRangesMhz = {},
+			.enableAcs = false,
+			.acsShouldExcludeDfs = false,
+			.channel = 6,
+		};
+		mNetwork_params = {
+			.ssid =  std::vector<uint8_t>(kTestSsid, kTestSsid + sizeof(kTestSsid)),
+			.isHidden = false,
+			.encryptionType = EncryptionType::WPA2,
+			.passphrase = "verysecurewowe",
+			.isMetered = true,  // default for tethered softap, change to false for lohs.
+			.vendorElements = {},
+		};
+	}
+
+	std::string mWlan42_tethered_config = "\ninterface=wlan42\n"
+		"driver=nl80211\n"
+		"ctrl_interface=/data/vendor/wifi/hostapd/ctrl_wlan42\n"
+		"ssid2=31323361626364\n"
+		"channel=6\n"
+		"op_class=83\n"
+		"ieee80211n=1\n"
+		"ieee80211ac=0\n\n\n"
+		"hw_mode=g\n\n"
+		"ignore_broadcast_ssid=0\n"
+		"wowlan_triggers=any\n"
+		"interworking=1\n"
+		"access_network_type=2\n\n"
+		"wpa=2\n"
+		"rsn_pairwise=CCMP\n"
+		"wpa_passphrase=verysecurewowe\n\n\n\n\n\n"
+		"ap_isolate=0\n";
+
+	std::string mWlan42_lohs_config = "dtim_period=2   \n"
+		"   ap_max_inactivity=300\n"
+		"skip_inactivity_poll = 1\n\n"
+		"interface=wlan42\n"
+		"driver=nl80211\n"
+		"ctrl_interface=/data/vendor/wifi/hostapd/ctrl_wlan42\n"
+		"ssid2=31323361626364\n"
+		"channel=6\n"
+		"op_class=83\n"
+		"ieee80211n=1\n"
+		"ieee80211ac=0\n\n\n"
+		"hw_mode=g\n\n"
+		"ignore_broadcast_ssid=0\n"
+		"wowlan_triggers=any\n"
+		"interworking=0\n\n"
+		"wpa=2\n"
+		"rsn_pairwise=CCMP\n"
+		"wpa_passphrase=verysecurewowe\n\n\n\n\n\n"
+		"ap_isolate=0\n";
+
+	std::string mWlan42_lohs_config_no_overlay = "\ninterface=wlan42\n"
+		"driver=nl80211\n"
+		"ctrl_interface=/data/vendor/wifi/hostapd/ctrl_wlan42\n"
+		"ssid2=31323361626364\n"
+		"channel=6\n"
+		"op_class=83\n"
+		"ieee80211n=1\n"
+		"ieee80211ac=0\n\n\n"
+		"hw_mode=g\n\n"
+		"ignore_broadcast_ssid=0\n"
+		"wowlan_triggers=any\n"
+		"interworking=0\n\n"
+		"wpa=2\n"
+		"rsn_pairwise=CCMP\n"
+		"wpa_passphrase=verysecurewowe\n\n\n\n\n\n"
+		"ap_isolate=0\n";
+
+	IfaceParams mIface_params;
+	ChannelParams mChannel_params;
+	NetworkParams mNetwork_params;
+	std::string mBr_name = "";
+	std::string mOwe_transition_ifname = "";
+};
+
+/**
+ * Null hostapd_data* and null mac address (u8*)
+ * There's an || check on these that should return nullopt
+ */
+TEST(getStaInfoByMacAddrTest, NullArguments) {
+	EXPECT_EQ(std::nullopt, getStaInfoByMacAddr(nullptr, nullptr));
+}
+
+
+/**
+ * We pass valid arguments to get past the nullptr check, but hostapd_data->sta_list is nullptr.
+ * Don't loop through the sta_info* list, just return nullopt.
+ */
+TEST(getStaInfoByMacAddrTest, NullStaList) {
+	struct hostapd_data iface_hapd = {};
+	u8 mac_addr[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xD0, 0x0D};
+	EXPECT_EQ(std::nullopt, getStaInfoByMacAddr(&iface_hapd, mac_addr));
+}
+
+/**
+ * Mac doesn't match, and we hit the end of the sta_info list.
+ * Don't run over the end of the list and return nullopt.
+ */
+TEST(getStaInfoByMacAddrTest, NoMatchingMac) {
+	struct hostapd_data iface_hapd = {};
+	struct sta_info sta0 = {};
+	struct sta_info sta1 = {};
+	struct sta_info sta2 = {};
+	iface_hapd.sta_list = &sta0;
+	sta0.next = &sta1;
+	sta1.next = &sta2;
+	u8 mac_addr[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xD0, 0x0D};
+	EXPECT_EQ(std::nullopt, getStaInfoByMacAddr(&iface_hapd, mac_addr));
+}
+
+/**
+ * There is a matching address and we return it.
+ */
+TEST(getStaInfoByMacAddrTest, MatchingMac) {
+	struct hostapd_data iface_hapd = {};
+	struct sta_info sta0 = {};
+	struct sta_info sta1 = {};
+	struct sta_info sta2 = {};
+	iface_hapd.sta_list = &sta0;
+	sta0.next = &sta1;
+	sta1.next = &sta2;
+	u8 sta0_addr[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xD0, 0x0C};  // off by 1 bit
+	std::memcpy(sta0.addr, sta0_addr, ETH_ALEN);
+	u8 sta1_addr[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xD0, 0x0D};
+	std::memcpy(sta1.addr, sta1_addr, ETH_ALEN);
+	u8 mac_addr[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xD0, 0x0D};
+	auto sta_ptr_optional = getStaInfoByMacAddr(&iface_hapd, mac_addr);
+	EXPECT_TRUE(sta_ptr_optional.has_value());
+	EXPECT_EQ(0, std::memcmp(sta_ptr_optional.value()->addr, sta1_addr, ETH_ALEN));
+}
+
+
+TEST_F(HostapdConfigTest, tetheredApConfig) {
+	// instance name, config string, br_name, usesMlo
+	std::string config_path = WriteHostapdConfig("wlan42", mWlan42_tethered_config, "", false);
+	std::string expected_path = "/data/vendor/wifi/hostapd/hostapd_wlan42.conf";
+	EXPECT_EQ(expected_path, config_path);
+	EXPECT_EQ(mWlan42_tethered_config, hostapd_unittest_config_output);
+}
+
+TEST_F(HostapdConfigTest, tetheredApConfigStatFails) {
+	hostapd_unittest_WriteStringToFileRet = false;
+	hostapd_unittest_stat_ret = -1;
+	// instance name, config string, br_name, usesMlo
+	std::string config_path = WriteHostapdConfig("wlan42", mWlan42_tethered_config, "", false);
+	std::string expected_path = "";
+	EXPECT_EQ(expected_path, config_path);
+}
+
+TEST_F(HostapdConfigTest, tetheredApConfigWriteFails) {
+	hostapd_unittest_WriteStringToFileRet = false;
+	// instance name, config string, br_name, usesMlo
+	std::string config_path = WriteHostapdConfig("wlan42", mWlan42_tethered_config, "", false);
+	std::string expected_path = "";
+	EXPECT_EQ(expected_path, config_path);
+}
+
+TEST_F(HostapdConfigTest, tetheredAp) {
+	std::string config_string = CreateHostapdConfig(mIface_params, mChannel_params, mNetwork_params,
+			mBr_name, mOwe_transition_ifname);
+	EXPECT_EQ(mWlan42_tethered_config, config_string);
+}
+
+TEST_F(HostapdConfigTest, lohsAp) {
+	mNetwork_params.isMetered = false;
+	hostapd_unittest_overlay_content =
+			"invalid_key=this_should_not_be_here\n"
+			"dtim_period=2   \n"
+			"   ap_max_inactivity=300\n"
+			"another_invalid_key_dtim_period=-10000\n"
+			"skip_inactivity_poll = 1";
+	std::string config_string = CreateHostapdConfig(mIface_params, mChannel_params, mNetwork_params,
+			mBr_name, mOwe_transition_ifname);
+	EXPECT_EQ(mWlan42_lohs_config, config_string);
+}
+
+TEST_F(HostapdConfigTest, lohsApAccessFails) {
+	mNetwork_params.isMetered = false;
+	hostapd_unittest_accessRet = -1;
+	std::string config_string = CreateHostapdConfig(mIface_params, mChannel_params, mNetwork_params,
+			mBr_name, mOwe_transition_ifname);
+	EXPECT_EQ(mWlan42_lohs_config_no_overlay, config_string);
+}
+
+TEST_F(HostapdConfigTest, lohsApReadFails) {
+	mNetwork_params.isMetered = false;
+	hostapd_unittest_ReadFileToStringRet = false;
+	std::string config_string = CreateHostapdConfig(mIface_params, mChannel_params, mNetwork_params,
+			mBr_name, mOwe_transition_ifname);
+	EXPECT_EQ("", config_string);
+}
+
+}  // namespace aidl::android::hardware::wifi::hostapd
diff --git a/hostapd/config_file.c b/hostapd/config_file.c
index 1d2bdb87..9470cae8 100644
--- a/hostapd/config_file.c
+++ b/hostapd/config_file.c
@@ -2436,6 +2436,31 @@ static int get_u16(const char *pos, int line, u16 *ret_val)
 #endif /* CONFIG_IEEE80211BE */
 
 
+#ifdef CONFIG_TESTING_OPTIONS
+static bool get_hexstream(const char *val, struct wpabuf **var,
+			  const char *name, int line)
+{
+	struct wpabuf *tmp;
+	size_t len = os_strlen(val) / 2;
+
+	tmp = wpabuf_alloc(len);
+	if (!tmp)
+		return false;
+
+	if (hexstr2bin(val, wpabuf_put(tmp, len), len)) {
+		wpabuf_free(tmp);
+		wpa_printf(MSG_ERROR, "Line %d: Invalid %s '%s'",
+			   line, name, val);
+		return false;
+	}
+
+	wpabuf_free(*var);
+	*var = tmp;
+	return true;
+}
+#endif /* CONFIG_TESTING_OPTIONS */
+
+
 static int hostapd_config_fill(struct hostapd_config *conf,
 			       struct hostapd_bss_config *bss,
 			       const char *buf, char *pos, int line)
@@ -3244,6 +3269,8 @@ static int hostapd_config_fill(struct hostapd_config *conf,
 		os_free(bss->rsn_preauth_interfaces);
 		bss->rsn_preauth_interfaces = os_strdup(pos);
 #endif /* CONFIG_RSN_PREAUTH */
+	} else if (os_strcmp(buf, "rsn_override_omit_rsnxe") == 0) {
+		bss->rsn_override_omit_rsnxe = atoi(pos);
 	} else if (os_strcmp(buf, "peerkey") == 0) {
 		wpa_printf(MSG_INFO,
 			   "Line %d: Obsolete peerkey parameter ignored", line);
@@ -4502,23 +4529,29 @@ static int hostapd_config_fill(struct hostapd_config *conf,
 			bss->radio_measurements[0] |=
 				WLAN_RRM_CAPS_NEIGHBOR_REPORT;
 	} else if (os_strcmp(buf, "own_ie_override") == 0) {
-		struct wpabuf *tmp;
-		size_t len = os_strlen(pos) / 2;
-
-		tmp = wpabuf_alloc(len);
-		if (!tmp)
+		if (!get_hexstream(pos, &bss->own_ie_override,
+				   "own_ie_override", line))
 			return 1;
-
-		if (hexstr2bin(pos, wpabuf_put(tmp, len), len)) {
-			wpabuf_free(tmp);
-			wpa_printf(MSG_ERROR,
-				   "Line %d: Invalid own_ie_override '%s'",
-				   line, pos);
+	} else if (os_strcmp(buf, "rsne_override") == 0) {
+		if (!get_hexstream(pos, &bss->rsne_override,
+				   "rsne_override", line))
+			return 1;
+	} else if (os_strcmp(buf, "rsnoe_override") == 0) {
+		if (!get_hexstream(pos, &bss->rsnoe_override,
+				   "rsnoe_override", line))
+			return 1;
+	} else if (os_strcmp(buf, "rsno2e_override") == 0) {
+		if (!get_hexstream(pos, &bss->rsno2e_override,
+				   "rsno2e_override", line))
+			return 1;
+	} else if (os_strcmp(buf, "rsnxe_override") == 0) {
+		if (!get_hexstream(pos, &bss->rsnxe_override,
+				   "rsnxe_override", line))
+			return 1;
+	} else if (os_strcmp(buf, "rsnxoe_override") == 0) {
+		if (!get_hexstream(pos, &bss->rsnxoe_override,
+				   "rsnxoe_override", line))
 			return 1;
-		}
-
-		wpabuf_free(bss->own_ie_override);
-		bss->own_ie_override = tmp;
 	} else if (os_strcmp(buf, "sae_reflection_attack") == 0) {
 		bss->sae_reflection_attack = atoi(pos);
 	} else if (os_strcmp(buf, "sae_commit_status") == 0) {
@@ -4584,6 +4617,8 @@ static int hostapd_config_fill(struct hostapd_config *conf,
 			return 1;
 	} else if (os_strcmp(buf, "eapol_m3_no_encrypt") == 0) {
 		bss->eapol_m3_no_encrypt = atoi(pos);
+	} else if (os_strcmp(buf, "eapol_key_reserved_random") == 0) {
+		bss->eapol_key_reserved_random = atoi(pos);
 	} else if (os_strcmp(buf, "test_assoc_comeback_type") == 0) {
 		bss->test_assoc_comeback_type = atoi(pos);
 	} else if (os_strcmp(buf, "presp_elements") == 0) {
diff --git a/hostapd/ctrl_iface.c b/hostapd/ctrl_iface.c
index 8e2b8bd5..ea19ba73 100644
--- a/hostapd/ctrl_iface.c
+++ b/hostapd/ctrl_iface.c
@@ -2458,6 +2458,31 @@ static int hostapd_ctrl_register_frame(struct hostapd_data *hapd,
 
 
 #ifdef NEED_AP_MLME
+
+static bool
+hostapd_ctrl_is_freq_in_cmode(struct hostapd_hw_modes *mode,
+			      struct hostapd_multi_hw_info *current_hw_info,
+			      int freq)
+{
+	struct hostapd_channel_data *chan;
+	int i;
+
+	for (i = 0; i < mode->num_channels; i++) {
+		chan = &mode->channels[i];
+
+		if (chan->flag & HOSTAPD_CHAN_DISABLED)
+			continue;
+
+		if (!chan_in_current_hw_info(current_hw_info, chan))
+			continue;
+
+		if (chan->freq == freq)
+			return true;
+	}
+	return false;
+}
+
+
 static int hostapd_ctrl_check_freq_params(struct hostapd_freq_params *params,
 					  u16 punct_bitmap)
 {
@@ -2672,6 +2697,15 @@ static int hostapd_ctrl_iface_chan_switch(struct hostapd_iface *iface,
 		settings.link_id = iface->bss[0]->mld_link_id;
 #endif /* CONFIG_IEEE80211BE */
 
+	if (iface->num_hw_features > 1 &&
+	    !hostapd_ctrl_is_freq_in_cmode(iface->current_mode,
+					   iface->current_hw_info,
+					   settings.freq_params.freq)) {
+		wpa_printf(MSG_INFO,
+			   "chanswitch: Invalid frequency settings provided for multi band phy");
+		return -1;
+	}
+
 	ret = hostapd_ctrl_check_freq_params(&settings.freq_params,
 					     settings.punct_bitmap);
 	if (ret) {
@@ -2739,6 +2773,12 @@ static int hostapd_ctrl_iface_chan_switch(struct hostapd_iface *iface,
 		return 0;
 	}
 
+	if (iface->cac_started) {
+		wpa_printf(MSG_DEBUG,
+			   "CAC is in progress - switching channel without CSA");
+		return hostapd_force_channel_switch(iface, &settings);
+	}
+
 	for (i = 0; i < iface->num_bss; i++) {
 
 		/* Save CHAN_SWITCH VHT, HE, and EHT config */
@@ -3709,6 +3749,7 @@ static int hostapd_ctrl_nan_publish(struct hostapd_data *hapd, char *cmd,
 	struct wpabuf *ssi = NULL;
 	int ret = -1;
 	enum nan_service_protocol_type srv_proto_type = 0;
+	bool p2p = false;
 
 	os_memset(&params, 0, sizeof(params));
 	/* USD shall use both solicited and unsolicited transmissions */
@@ -3742,6 +3783,11 @@ static int hostapd_ctrl_nan_publish(struct hostapd_data *hapd, char *cmd,
 			continue;
 		}
 
+		if (os_strcmp(token, "p2p=1") == 0) {
+			p2p = true;
+			continue;
+		}
+
 		if (os_strcmp(token, "solicited=0") == 0) {
 			params.solicited = false;
 			continue;
@@ -3763,7 +3809,7 @@ static int hostapd_ctrl_nan_publish(struct hostapd_data *hapd, char *cmd,
 	}
 
 	publish_id = hostapd_nan_usd_publish(hapd, service_name, srv_proto_type,
-					     ssi, &params);
+					     ssi, &params, p2p);
 	if (publish_id > 0)
 		ret = os_snprintf(buf, buflen, "%d", publish_id);
 fail:
@@ -3846,6 +3892,7 @@ static int hostapd_ctrl_nan_subscribe(struct hostapd_data *hapd, char *cmd,
 	struct wpabuf *ssi = NULL;
 	int ret = -1;
 	enum nan_service_protocol_type srv_proto_type = 0;
+	bool p2p = false;
 
 	os_memset(&params, 0, sizeof(params));
 
@@ -3879,6 +3926,11 @@ static int hostapd_ctrl_nan_subscribe(struct hostapd_data *hapd, char *cmd,
 			continue;
 		}
 
+		if (os_strcmp(token, "p2p=1") == 0) {
+			p2p = true;
+			continue;
+		}
+
 		wpa_printf(MSG_INFO,
 			   "CTRL: Invalid NAN_SUBSCRIBE parameter: %s",
 			   token);
@@ -3887,7 +3939,7 @@ static int hostapd_ctrl_nan_subscribe(struct hostapd_data *hapd, char *cmd,
 
 	subscribe_id = hostapd_nan_usd_subscribe(hapd, service_name,
 						 srv_proto_type, ssi,
-						 &params);
+						 &params, p2p);
 	if (subscribe_id > 0)
 		ret = os_snprintf(buf, buflen, "%d", subscribe_id);
 fail:
@@ -4686,23 +4738,360 @@ done:
 }
 
 
+#ifdef CONFIG_IEEE80211BE
+#ifndef CONFIG_CTRL_IFACE_UDP
+
+static int hostapd_mld_ctrl_iface_receive_process(struct hostapd_mld *mld,
+						  char *buf, char *reply,
+						  size_t reply_size,
+						  struct sockaddr_storage *from,
+						  socklen_t fromlen)
+{
+	struct hostapd_data *link_hapd, *link_itr;
+	int reply_len = -1, link_id = -1;
+	char *cmd;
+	bool found = false;
+
+	os_memcpy(reply, "OK\n", 3);
+	reply_len = 3;
+
+	cmd = buf;
+
+	/* Check whether the link ID is provided in the command */
+	if (os_strncmp(cmd, "LINKID ", 7) == 0) {
+		cmd += 7;
+		link_id = atoi(cmd);
+		if (link_id < 0 || link_id >= 15) {
+			os_memcpy(reply, "INVALID LINK ID\n", 16);
+			reply_len = 16;
+			goto out;
+		}
+
+		cmd = os_strchr(cmd, ' ');
+		if (!cmd)
+			goto out;
+		cmd++;
+	}
+	if (link_id >= 0) {
+		link_hapd = mld->fbss;
+		if (!link_hapd) {
+			os_memcpy(reply, "NO LINKS ACTIVE\n", 16);
+			reply_len = 16;
+			goto out;
+		}
+
+		for_each_mld_link(link_itr, link_hapd) {
+			if (link_itr->mld_link_id == link_id) {
+				found = true;
+				break;
+			}
+		}
+
+		if (!found)
+			goto out;
+
+		link_hapd = link_itr;
+	} else {
+		link_hapd = mld->fbss;
+	}
+
+	if (os_strcmp(cmd, "PING") == 0) {
+		os_memcpy(reply, "PONG\n", 5);
+		reply_len = 5;
+	} else if (os_strcmp(cmd, "ATTACH") == 0) {
+		if (ctrl_iface_attach(&mld->ctrl_dst, from, fromlen, NULL))
+			reply_len = -1;
+	} else if (os_strncmp(cmd, "ATTACH ", 7) == 0) {
+		if (ctrl_iface_attach(&mld->ctrl_dst, from, fromlen, cmd + 7))
+			reply_len = -1;
+	} else if (os_strcmp(cmd, "DETACH") == 0) {
+		if (ctrl_iface_detach(&mld->ctrl_dst, from, fromlen))
+			reply_len = -1;
+	} else {
+		if (link_id == -1)
+			wpa_printf(MSG_DEBUG,
+				   "Link ID not provided, using the first link BSS (if available)");
+
+		if (!link_hapd)
+			reply_len = -1;
+		else
+			reply_len =
+				hostapd_ctrl_iface_receive_process(
+					link_hapd, cmd, reply, reply_size,
+					from, fromlen);
+	}
+
+out:
+	if (reply_len < 0) {
+		os_memcpy(reply, "FAIL\n", 5);
+		reply_len = 5;
+	}
+
+	return reply_len;
+}
+
+
+static void hostapd_mld_ctrl_iface_receive(int sock, void *eloop_ctx,
+					   void *sock_ctx)
+{
+	struct hostapd_mld *mld = eloop_ctx;
+	char buf[4096];
+	int res;
+	struct sockaddr_storage from;
+	socklen_t fromlen = sizeof(from);
+	char *reply, *pos = buf;
+	const size_t reply_size = 4096;
+	int reply_len;
+	int level = MSG_DEBUG;
+
+	res = recvfrom(sock, buf, sizeof(buf) - 1, 0,
+		       (struct sockaddr *) &from, &fromlen);
+	if (res < 0) {
+		wpa_printf(MSG_ERROR, "recvfrom(mld ctrl_iface): %s",
+			   strerror(errno));
+		return;
+	}
+	buf[res] = '\0';
+
+	reply = os_malloc(reply_size);
+	if (!reply) {
+		if (sendto(sock, "FAIL\n", 5, 0, (struct sockaddr *) &from,
+			   fromlen) < 0) {
+			wpa_printf(MSG_DEBUG, "MLD CTRL: sendto failed: %s",
+				   strerror(errno));
+		}
+		return;
+	}
+
+	if (os_strcmp(pos, "PING") == 0)
+		level = MSG_EXCESSIVE;
+
+	wpa_hexdump_ascii(level, "RX MLD ctrl_iface", pos, res);
+
+	reply_len = hostapd_mld_ctrl_iface_receive_process(mld, pos,
+							   reply, reply_size,
+							   &from, fromlen);
+
+	if (sendto(sock, reply, reply_len, 0, (struct sockaddr *) &from,
+		   fromlen) < 0) {
+		wpa_printf(MSG_DEBUG, "MLD CTRL: sendto failed: %s",
+			   strerror(errno));
+	}
+	os_free(reply);
+}
+
+
+static char * hostapd_mld_ctrl_iface_path(struct hostapd_mld *mld)
+{
+	size_t len;
+	char *buf;
+	int ret;
+
+	if (!mld->ctrl_interface)
+		return NULL;
+
+	len = os_strlen(mld->ctrl_interface) + os_strlen(mld->name) + 2;
+
+	buf = os_malloc(len);
+	if (!buf)
+		return NULL;
+
+	ret = os_snprintf(buf, len, "%s/%s", mld->ctrl_interface, mld->name);
+	if (os_snprintf_error(len, ret)) {
+		os_free(buf);
+		return NULL;
+	}
+
+	return buf;
+}
+
+#endif /* !CONFIG_CTRL_IFACE_UDP */
+
+
+int hostapd_mld_ctrl_iface_init(struct hostapd_mld *mld)
+{
+#ifndef CONFIG_CTRL_IFACE_UDP
+	struct sockaddr_un addr;
+	int s = -1;
+	char *fname = NULL;
+
+	if (!mld)
+		return -1;
+
+	if (mld->ctrl_sock > -1) {
+		wpa_printf(MSG_DEBUG, "MLD %s ctrl_iface already exists!",
+			   mld->name);
+		return 0;
+	}
+
+	dl_list_init(&mld->ctrl_dst);
+
+	if (!mld->ctrl_interface)
+		return 0;
+
+	if (mkdir(mld->ctrl_interface, S_IRWXU | S_IRWXG) < 0) {
+		if (errno == EEXIST) {
+			wpa_printf(MSG_DEBUG,
+				   "Using existing control interface directory.");
+		} else {
+			wpa_printf(MSG_ERROR, "mkdir[ctrl_interface]: %s",
+				   strerror(errno));
+			goto fail;
+		}
+	}
+
+	if (os_strlen(mld->ctrl_interface) + 1 + os_strlen(mld->name) >=
+	    sizeof(addr.sun_path))
+		goto fail;
+
+	s = socket(PF_UNIX, SOCK_DGRAM, 0);
+	if (s < 0) {
+		wpa_printf(MSG_ERROR, "socket(PF_UNIX): %s", strerror(errno));
+		goto fail;
+	}
+
+	os_memset(&addr, 0, sizeof(addr));
+#ifdef __FreeBSD__
+	addr.sun_len = sizeof(addr);
+#endif /* __FreeBSD__ */
+	addr.sun_family = AF_UNIX;
+
+	fname = hostapd_mld_ctrl_iface_path(mld);
+	if (!fname)
+		goto fail;
+
+	os_strlcpy(addr.sun_path, fname, sizeof(addr.sun_path));
+
+	wpa_printf(MSG_DEBUG, "Setting up MLD %s ctrl_iface", mld->name);
+
+	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
+		wpa_printf(MSG_DEBUG, "ctrl_iface bind(PF_UNIX) failed: %s",
+			   strerror(errno));
+		if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
+			wpa_printf(MSG_DEBUG, "ctrl_iface exists, but does not allow connections - assuming it was left over from forced program termination");
+			if (unlink(fname) < 0) {
+				wpa_printf(MSG_ERROR,
+					   "Could not unlink existing ctrl_iface socket '%s': %s",
+					   fname, strerror(errno));
+				goto fail;
+			}
+			if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) <
+			    0) {
+				wpa_printf(MSG_ERROR,
+					   "hostapd-ctrl-iface: bind(PF_UNIX): %s",
+					   strerror(errno));
+				goto fail;
+			}
+			wpa_printf(MSG_DEBUG,
+				   "Successfully replaced leftover ctrl_iface socket '%s'",
+				   fname);
+		} else {
+			wpa_printf(MSG_INFO,
+				   "ctrl_iface exists and seems to be in use - cannot override it");
+			wpa_printf(MSG_INFO,
+				   "Delete '%s' manually if it is not used anymore", fname);
+			os_free(fname);
+			fname = NULL;
+			goto fail;
+		}
+	}
+
+	if (chmod(fname, S_IRWXU | S_IRWXG) < 0) {
+		wpa_printf(MSG_ERROR, "chmod[ctrl_interface/ifname]: %s",
+			   strerror(errno));
+		goto fail;
+	}
+	os_free(fname);
+
+	mld->ctrl_sock = s;
+
+	if (eloop_register_read_sock(s, hostapd_mld_ctrl_iface_receive, mld,
+				     NULL) < 0)
+		return -1;
+
+	return 0;
+
+fail:
+	if (s >= 0)
+		close(s);
+	if (fname) {
+		unlink(fname);
+		os_free(fname);
+	}
+	return -1;
+#endif /* !CONFIG_CTRL_IFACE_UDP */
+	return 0;
+}
+
+
+void hostapd_mld_ctrl_iface_deinit(struct hostapd_mld *mld)
+{
+#ifndef CONFIG_CTRL_IFACE_UDP
+	struct wpa_ctrl_dst *dst, *prev;
+
+	if (mld->ctrl_sock > -1) {
+		char *fname;
+
+		eloop_unregister_read_sock(mld->ctrl_sock);
+		close(mld->ctrl_sock);
+		mld->ctrl_sock = -1;
+
+		fname = hostapd_mld_ctrl_iface_path(mld);
+		if (fname) {
+			unlink(fname);
+			os_free(fname);
+		}
+
+		if (mld->ctrl_interface &&
+		    rmdir(mld->ctrl_interface) < 0) {
+			if (errno == ENOTEMPTY) {
+				wpa_printf(MSG_DEBUG,
+					   "MLD control interface directory not empty - leaving it behind");
+			} else {
+				wpa_printf(MSG_ERROR,
+					   "rmdir[ctrl_interface=%s]: %s",
+					   mld->ctrl_interface,
+					   strerror(errno));
+			}
+		}
+	}
+
+	dl_list_for_each_safe(dst, prev, &mld->ctrl_dst, struct wpa_ctrl_dst,
+			      list)
+		os_free(dst);
+#endif /* !CONFIG_CTRL_IFACE_UDP */
+
+	os_free(mld->ctrl_interface);
+}
+
+#endif /* CONFIG_IEEE80211BE */
+
+
 #ifndef CONFIG_CTRL_IFACE_UDP
 static char * hostapd_ctrl_iface_path(struct hostapd_data *hapd)
 {
 	char *buf;
 	size_t len;
+	const char *ctrl_sock_iface;
+
+#ifdef CONFIG_IEEE80211BE
+	ctrl_sock_iface = hapd->ctrl_sock_iface;
+#else /* CONFIG_IEEE80211BE */
+	ctrl_sock_iface = hapd->conf->iface;
+#endif /* CONFIG_IEEE80211BE */
 
 	if (hapd->conf->ctrl_interface == NULL)
 		return NULL;
 
 	len = os_strlen(hapd->conf->ctrl_interface) +
-		os_strlen(hapd->conf->iface) + 2;
+		os_strlen(ctrl_sock_iface) + 2;
+
 	buf = os_malloc(len);
 	if (buf == NULL)
 		return NULL;
 
 	os_snprintf(buf, len, "%s/%s",
-		    hapd->conf->ctrl_interface, hapd->conf->iface);
+		    hapd->conf->ctrl_interface, ctrl_sock_iface);
 	buf[len - 1] = '\0';
 	return buf;
 }
@@ -4818,6 +5207,7 @@ fail:
 	struct sockaddr_un addr;
 	int s = -1;
 	char *fname = NULL;
+	size_t iflen;
 
 	if (hapd->ctrl_sock > -1) {
 		wpa_printf(MSG_DEBUG, "ctrl_iface already exists!");
@@ -4872,8 +5262,13 @@ fail:
 	}
 #endif /* ANDROID */
 
+#ifdef CONFIG_IEEE80211BE
+	iflen = os_strlen(hapd->ctrl_sock_iface);
+#else /* CONFIG_IEEE80211BE */
+	iflen = os_strlen(hapd->conf->iface);
+#endif /* CONFIG_IEEE80211BE */
 	if (os_strlen(hapd->conf->ctrl_interface) + 1 +
-	    os_strlen(hapd->conf->iface) >= sizeof(addr.sun_path))
+	    iflen >= sizeof(addr.sun_path))
 		goto fail;
 
 	s = socket(PF_UNIX, SOCK_DGRAM, 0);
diff --git a/hostapd/ctrl_iface.h b/hostapd/ctrl_iface.h
index 3341a66b..6ce209d2 100644
--- a/hostapd/ctrl_iface.h
+++ b/hostapd/ctrl_iface.h
@@ -14,6 +14,8 @@ int hostapd_ctrl_iface_init(struct hostapd_data *hapd);
 void hostapd_ctrl_iface_deinit(struct hostapd_data *hapd);
 int hostapd_global_ctrl_iface_init(struct hapd_interfaces *interface);
 void hostapd_global_ctrl_iface_deinit(struct hapd_interfaces *interface);
+int hostapd_mld_ctrl_iface_init(struct hostapd_mld *mld);
+void hostapd_mld_ctrl_iface_deinit(struct hostapd_mld *mld);
 #else /* CONFIG_NO_CTRL_IFACE */
 static inline int hostapd_ctrl_iface_init(struct hostapd_data *hapd)
 {
diff --git a/hostapd/hostapd.conf b/hostapd/hostapd.conf
index 24f39865..93524cf5 100644
--- a/hostapd/hostapd.conf
+++ b/hostapd/hostapd.conf
@@ -2333,6 +2333,15 @@ own_ip_addr=127.0.0.1
 #rsn_override_pairwise_2
 #rsn_override_mfp_2
 #
+# The RSNXE is normally included if any of the extended RSN capabilities is
+# enabled/supported. When using RSN overriding, a separate RSNXOE is included
+# and it may be more interoperable to omit the RSNXE completely. This
+# configuration parameter can be used to do that.
+# 0 = Include the RSNXE if any extended RSN capability is enabled/supported
+#     (default).
+# 1 = Do not include the RSNXE.
+#rsn_override_omit_rsnxe=0
+#
 # Example configuration for WPA2-Personal/PMF-optional in RSNE and
 # WPA3-Personal/PMF-required/MLO in override elements
 #wpa_key_mgmt=WPA-PSK
diff --git a/hostapd/hostapd_cli.c b/hostapd/hostapd_cli.c
index eb8a3835..57702d93 100644
--- a/hostapd/hostapd_cli.c
+++ b/hostapd/hostapd_cli.c
@@ -54,7 +54,11 @@ static void usage(void)
 	fprintf(stderr, "%s\n", hostapd_cli_version);
 	fprintf(stderr,
 		"\n"
-		"usage: hostapd_cli [-p<path>] [-i<ifname>] [-hvBr] "
+		"usage: hostapd_cli [-p<path>] [-i<ifname>] "
+#ifdef CONFIG_IEEE80211BE
+		"[-l<link_id>] "
+#endif /* CONFIG_IEEE80211BE */
+		"[-hvBr] "
 		"[-a<path>] \\\n"
 		"                   [-P<pid file>] [-G<ping interval>] [command..]\n"
 		"\n"
@@ -74,7 +78,11 @@ static void usage(void)
 		"   -B           run a daemon in the background\n"
 		"   -i<ifname>   Interface to listen on (default: first "
 		"interface found in the\n"
-		"                socket path)\n\n");
+		"                socket path)\n"
+#ifdef CONFIG_IEEE80211BE
+		"   -l<link_id>  Link ID of the interface in case of Multi-Link Operation\n"
+#endif /* CONFIG_IEEE80211BE */
+		"\n");
 	print_help(stderr, NULL);
 }
 
@@ -2212,12 +2220,15 @@ int main(int argc, char *argv[])
 	int c;
 	int daemonize = 0;
 	int reconnect = 0;
+#ifdef CONFIG_IEEE80211BE
+	int link_id = -1;
+#endif /* CONFIG_IEEE80211BE */
 
 	if (os_program_init())
 		return -1;
 
 	for (;;) {
-		c = getopt(argc, argv, "a:BhG:i:p:P:rs:v");
+		c = getopt(argc, argv, "a:BhG:i:l:p:P:rs:v");
 		if (c < 0)
 			break;
 		switch (c) {
@@ -2252,6 +2263,11 @@ int main(int argc, char *argv[])
 		case 's':
 			client_socket_dir = optarg;
 			break;
+#ifdef CONFIG_IEEE80211BE
+		case 'l':
+			link_id = atoi(optarg);
+			break;
+#endif /* CONFIG_IEEE80211BE */
 		default:
 			usage();
 			return -1;
@@ -2285,6 +2301,24 @@ int main(int argc, char *argv[])
 				closedir(dir);
 			}
 		}
+
+#ifdef CONFIG_IEEE80211BE
+		if (link_id >= 0 && ctrl_ifname) {
+			int ret;
+			char buf[300];
+
+			ret = os_snprintf(buf, sizeof(buf), "%s_%s%d",
+					  ctrl_ifname, WPA_CTRL_IFACE_LINK_NAME,
+					  link_id);
+			if (os_snprintf_error(sizeof(buf), ret))
+				return -1;
+
+			os_free(ctrl_ifname);
+			ctrl_ifname = os_strdup(buf);
+			link_id = -1;
+		}
+#endif /* CONFIG_IEEE80211BE */
+
 		hostapd_cli_reconnect(ctrl_ifname);
 		if (ctrl_conn) {
 			if (warning_displayed)
diff --git a/hostapd/main.c b/hostapd/main.c
index 640a1694..50b9f04f 100644
--- a/hostapd/main.c
+++ b/hostapd/main.c
@@ -193,7 +193,6 @@ static int hostapd_driver_init(struct hostapd_iface *iface)
 			os_memcpy(hapd->own_addr, b, ETH_ALEN);
 		}
 
-		hostapd_mld_add_link(hapd);
 		wpa_printf(MSG_DEBUG,
 			   "Setup of non first link (%d) BSS of MLD %s",
 			   hapd->mld_link_id, hapd->conf->iface);
@@ -280,7 +279,6 @@ static int hostapd_driver_init(struct hostapd_iface *iface)
 		else
 			os_memcpy(hapd->own_addr, b, ETH_ALEN);
 
-		hostapd_mld_add_link(hapd);
 		wpa_printf(MSG_DEBUG, "Setup of first link (%d) BSS of MLD %s",
 			   hapd->mld_link_id, hapd->conf->iface);
 	}
@@ -340,8 +338,14 @@ setup_mld:
 			   hapd->mld_link_id, MAC2STR(hapd->mld->mld_addr),
 			   MAC2STR(hapd->own_addr));
 
-		hostapd_drv_link_add(hapd, hapd->mld_link_id,
-				     hapd->own_addr);
+		if (hostapd_drv_link_add(hapd, hapd->mld_link_id,
+					 hapd->own_addr)) {
+			wpa_printf(MSG_ERROR,
+				   "MLD: Failed to add link %d in MLD %s",
+				   hapd->mld_link_id, hapd->conf->iface);
+			return -1;
+		}
+		hostapd_mld_add_link(hapd);
 	}
 #endif /* CONFIG_IEEE80211BE */
 
@@ -757,6 +761,7 @@ static void hostapd_global_cleanup_mld(struct hapd_interfaces *interfaces)
 		if (!interfaces->mld[i])
 			continue;
 
+		interfaces->mld_ctrl_iface_deinit(interfaces->mld[i]);
 		os_free(interfaces->mld[i]);
 		interfaces->mld[i] = NULL;
 	}
@@ -802,6 +807,10 @@ int main(int argc, char *argv[])
 	interfaces.global_iface_path = NULL;
 	interfaces.global_iface_name = NULL;
 	interfaces.global_ctrl_sock = -1;
+#ifdef CONFIG_IEEE80211BE
+	interfaces.mld_ctrl_iface_init = hostapd_mld_ctrl_iface_init;
+	interfaces.mld_ctrl_iface_deinit = hostapd_mld_ctrl_iface_deinit;
+#endif /* CONFIG_IEEE80211BE */
 	dl_list_init(&interfaces.global_ctrl_dst);
 #ifdef CONFIG_ETH_P_OUI
 	dl_list_init(&interfaces.eth_p_oui);
diff --git a/hs20/client/Android.bp b/hs20/client/Android.bp
new file mode 100644
index 00000000..3c8383c5
--- /dev/null
+++ b/hs20/client/Android.bp
@@ -0,0 +1,61 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    // See: http://go/android-license-faq
+    default_applicable_licenses: [
+        "external_wpa_supplicant_8_license",
+    ],
+}
+
+cc_binary {
+    name: "hs20-osu-client",
+    vendor: true,
+    srcs: [
+        ":hs20_client_srcs",
+    ],
+    shared_libs: [
+        "libc",
+        "libcrypto",
+        "libcurl",
+        "libcutils",
+        "liblog",
+        "libssl",
+        "libxml2",
+    ],
+    cflags: [
+        "-DCONFIG_CTRL_IFACE",
+        "-DCONFIG_CTRL_IFACE_UNIX",
+        "-DCONFIG_CTRL_IFACE_CLIENT_DIR=\"/data/misc/wifi/sockets\"",
+        "-DCONFIG_DEBUG_FILE",
+        "-DEAP_TLS_OPENSSL",
+        "-Wno-unused-parameter",
+        "-DCONFIG_ANDROID_LOG",
+        "-DANDROID_LOG_NAME=\"hs20-osu-client\"",
+    ],
+    local_include_dirs: [
+        ".",
+    ],
+    include_dirs: [
+        "external/curl/include",
+        "external/libxml2/include",
+        "external/wpa_supplicant_8/src",
+        "external/wpa_supplicant_8/src/common",
+        "external/wpa_supplicant_8/src/utils",
+    ],
+    defaults: [
+        "wpa_supplicant_cflags_default",
+    ],
+}
diff --git a/src/ap/ap_config.c b/src/ap/ap_config.c
index a5a821b4..c8fbb6ad 100644
--- a/src/ap/ap_config.c
+++ b/src/ap/ap_config.c
@@ -493,6 +493,8 @@ int hostapd_setup_sae_pt(struct hostapd_bss_config *conf)
 #ifdef CONFIG_SAE
 	struct hostapd_ssid *ssid = &conf->ssid;
 	struct sae_password_entry *pw;
+	int *groups = conf->sae_groups;
+	int default_groups[] = { 19, 0, 0 };
 
 	if ((conf->sae_pwe == SAE_PWE_HUNT_AND_PECK &&
 	     !hostapd_sae_pw_id_in_use(conf) &&
@@ -506,11 +508,18 @@ int hostapd_setup_sae_pt(struct hostapd_bss_config *conf)
 			      conf->rsn_override_key_mgmt_2))
 		return 0; /* PT not needed */
 
+	if (!groups) {
+		groups = default_groups;
+		if (wpa_key_mgmt_sae_ext_key(conf->wpa_key_mgmt |
+					     conf->rsn_override_key_mgmt |
+					     conf->rsn_override_key_mgmt_2))
+			default_groups[1] = 20;
+	}
+
 	sae_deinit_pt(ssid->pt);
 	ssid->pt = NULL;
 	if (ssid->wpa_passphrase) {
-		ssid->pt = sae_derive_pt(conf->sae_groups, ssid->ssid,
-					 ssid->ssid_len,
+		ssid->pt = sae_derive_pt(groups, ssid->ssid, ssid->ssid_len,
 					 (const u8 *) ssid->wpa_passphrase,
 					 os_strlen(ssid->wpa_passphrase),
 					 NULL);
@@ -520,8 +529,7 @@ int hostapd_setup_sae_pt(struct hostapd_bss_config *conf)
 
 	for (pw = conf->sae_passwords; pw; pw = pw->next) {
 		sae_deinit_pt(pw->pt);
-		pw->pt = sae_derive_pt(conf->sae_groups, ssid->ssid,
-				       ssid->ssid_len,
+		pw->pt = sae_derive_pt(groups, ssid->ssid, ssid->ssid_len,
 				       (const u8 *) pw->password,
 				       os_strlen(pw->password),
 				       pw->identifier);
@@ -966,6 +974,11 @@ void hostapd_config_free_bss(struct hostapd_bss_config *conf)
 
 #ifdef CONFIG_TESTING_OPTIONS
 	wpabuf_free(conf->own_ie_override);
+	wpabuf_free(conf->rsne_override);
+	wpabuf_free(conf->rsnoe_override);
+	wpabuf_free(conf->rsno2e_override);
+	wpabuf_free(conf->rsnxe_override);
+	wpabuf_free(conf->rsnxoe_override);
 	wpabuf_free(conf->sae_commit_override);
 	wpabuf_free(conf->rsne_override_eapol);
 	wpabuf_free(conf->rsnxe_override_eapol);
diff --git a/src/ap/ap_config.h b/src/ap/ap_config.h
index 1a4c912f..55f3b64c 100644
--- a/src/ap/ap_config.h
+++ b/src/ap/ap_config.h
@@ -396,6 +396,8 @@ struct hostapd_bss_config {
 	int rsn_preauth;
 	char *rsn_preauth_interfaces;
 
+	int rsn_override_omit_rsnxe;
+
 #ifdef CONFIG_IEEE80211R_AP
 	/* IEEE 802.11r - Fast BSS Transition */
 	u8 mobility_domain[MOBILITY_DOMAIN_ID_LEN];
@@ -694,6 +696,11 @@ struct hostapd_bss_config {
 	u8 bss_load_test[5];
 	u8 bss_load_test_set;
 	struct wpabuf *own_ie_override;
+	struct wpabuf *rsne_override;
+	struct wpabuf *rsnoe_override;
+	struct wpabuf *rsno2e_override;
+	struct wpabuf *rsnxe_override;
+	struct wpabuf *rsnxoe_override;
 	int sae_reflection_attack;
 	int sae_commit_status;
 	int sae_pk_omit;
@@ -718,6 +725,7 @@ struct hostapd_bss_config {
 	struct wpabuf *eapol_m1_elements;
 	struct wpabuf *eapol_m3_elements;
 	bool eapol_m3_no_encrypt;
+	bool eapol_key_reserved_random;
 	int test_assoc_comeback_type;
 	struct wpabuf *presp_elements;
 
diff --git a/src/ap/ap_drv_ops.c b/src/ap/ap_drv_ops.c
index c4734911..92dbc165 100644
--- a/src/ap/ap_drv_ops.c
+++ b/src/ap/ap_drv_ops.c
@@ -1250,3 +1250,14 @@ int hostapd_drv_set_secure_ranging_ctx(struct hostapd_data *hapd,
 	return hapd->driver->set_secure_ranging_ctx(hapd->drv_priv, &params);
 }
 #endif /* CONFIG_PASN */
+
+
+struct hostapd_multi_hw_info *
+hostapd_get_multi_hw_info(struct hostapd_data *hapd,
+			  unsigned int *num_multi_hws)
+{
+	if (!hapd->driver || !hapd->driver->get_multi_hw_info)
+		return NULL;
+
+	return hapd->driver->get_multi_hw_info(hapd->drv_priv, num_multi_hws);
+}
diff --git a/src/ap/ap_drv_ops.h b/src/ap/ap_drv_ops.h
index d7e79c84..6b7f02a1 100644
--- a/src/ap/ap_drv_ops.h
+++ b/src/ap/ap_drv_ops.h
@@ -478,4 +478,8 @@ static inline int hostapd_drv_link_sta_remove(struct hostapd_data *hapd,
 
 #endif /* CONFIG_IEEE80211BE */
 
+struct hostapd_multi_hw_info *
+hostapd_get_multi_hw_info(struct hostapd_data *hapd,
+			  unsigned int *num_multi_hws);
+
 #endif /* AP_DRV_OPS */
diff --git a/src/ap/beacon.c b/src/ap/beacon.c
index f8ce8103..2e3d9046 100644
--- a/src/ap/beacon.c
+++ b/src/ap/beacon.c
@@ -514,6 +514,35 @@ static u8 * hostapd_eid_ecsa(struct hostapd_data *hapd, u8 *eid)
 }
 
 
+static u8 * hostapd_eid_max_cs_time(struct hostapd_data *hapd, u8 *eid)
+{
+#ifdef CONFIG_IEEE80211BE
+	u32 switch_time;
+
+	/* Add Max Channel Switch Time element only if this AP is affiliated
+	 * with an AP MLD and channel switch is in process. */
+	if (!hapd->conf->mld_ap || !hapd->cs_freq_params.channel)
+		return eid;
+
+	/* Switch time is basically time between CSA count 1 and CSA count
+	 * 0 (1 beacon interval) + time for interface restart + time to
+	 * send a Beacon frame in the new channel (1 beacon interval).
+	 *
+	 * TODO: Use dynamic interface restart time. For now, assume 1 sec.
+	 */
+	switch_time = USEC_TO_TU(1000 * 1000) + 2 * hapd->iconf->beacon_int;
+
+	*eid++ = WLAN_EID_EXTENSION;
+	*eid++ = 4;
+	*eid++ = WLAN_EID_EXT_MAX_CHANNEL_SWITCH_TIME;
+	WPA_PUT_LE24(eid, switch_time);
+	eid += 3;
+#endif /* CONFIG_IEEE80211BE */
+
+	return eid;
+}
+
+
 static u8 * hostapd_eid_supported_op_classes(struct hostapd_data *hapd, u8 *eid)
 {
 	u8 op_class, channel;
@@ -676,7 +705,6 @@ struct probe_resp_params {
 	bool is_p2p;
 
 	/* Generated IEs will be included inside an ML element */
-	bool is_ml_sta_info;
 	struct hostapd_data *mld_ap;
 	struct mld_info *mld_info;
 
@@ -698,7 +726,7 @@ static void hostapd_free_probe_resp_params(struct probe_resp_params *params)
 #ifdef CONFIG_IEEE80211BE
 	if (!params)
 		return;
-	ap_sta_free_sta_profile(params->mld_info);
+
 	os_free(params->mld_info);
 	params->mld_info = NULL;
 #endif /* CONFIG_IEEE80211BE */
@@ -737,17 +765,21 @@ static size_t hostapd_probe_resp_elems_len(struct hostapd_data *hapd,
 
 #ifdef CONFIG_IEEE80211BE
 	if (hapd->iconf->ieee80211be && !hapd->conf->disable_11be) {
+		struct hostapd_data *ml_elem_ap =
+			params->mld_ap ? params->mld_ap : hapd;
+
 		buflen += hostapd_eid_eht_capab_len(hapd, IEEE80211_MODE_AP);
 		buflen += 3 + sizeof(struct ieee80211_eht_operation);
 		if (hapd->iconf->punct_bitmap)
 			buflen += EHT_OPER_DISABLED_SUBCHAN_BITMAP_SIZE;
 
-		if (!params->is_ml_sta_info && hapd->conf->mld_ap) {
-			struct hostapd_data *ml_elem_ap =
-				params->mld_ap ? params->mld_ap : hapd;
-
+		if (ml_elem_ap->conf->mld_ap) {
 			buflen += hostapd_eid_eht_ml_beacon_len(
 				ml_elem_ap, params->mld_info, !!params->mld_ap);
+
+			/* For Max Channel Switch Time element during channel
+			 * switch */
+			buflen += 6;
 		}
 	}
 #endif /* CONFIG_IEEE80211BE */
@@ -755,9 +787,7 @@ static size_t hostapd_probe_resp_elems_len(struct hostapd_data *hapd,
 	buflen += hostapd_eid_mbssid_len(hapd, WLAN_FC_STYPE_PROBE_RESP, NULL,
 					 params->known_bss,
 					 params->known_bss_len, NULL);
-	if (!params->is_ml_sta_info)
-		buflen += hostapd_eid_rnr_len(hapd, WLAN_FC_STYPE_PROBE_RESP,
-					      true);
+	buflen += hostapd_eid_rnr_len(hapd, WLAN_FC_STYPE_PROBE_RESP, true);
 	buflen += hostapd_mbo_ie_len(hapd);
 	buflen += hostapd_eid_owe_trans_len(hapd);
 	buflen += hostapd_eid_dpp_cc_len(hapd);
@@ -778,13 +808,11 @@ static u8 * hostapd_probe_resp_fill_elems(struct hostapd_data *hapd,
 
 	epos = pos + len;
 
-	if (!params->is_ml_sta_info) {
-		*pos++ = WLAN_EID_SSID;
-		*pos++ = hapd->conf->ssid.ssid_len;
-		os_memcpy(pos, hapd->conf->ssid.ssid,
-			  hapd->conf->ssid.ssid_len);
-		pos += hapd->conf->ssid.ssid_len;
-	}
+	*pos++ = WLAN_EID_SSID;
+	*pos++ = hapd->conf->ssid.ssid_len;
+	os_memcpy(pos, hapd->conf->ssid.ssid,
+		  hapd->conf->ssid.ssid_len);
+	pos += hapd->conf->ssid.ssid_len;
 
 	/* Supported rates */
 	pos = hostapd_eid_supp_rates(hapd, pos);
@@ -797,18 +825,13 @@ static u8 * hostapd_probe_resp_fill_elems(struct hostapd_data *hapd,
 	/* Power Constraint element */
 	pos = hostapd_eid_pwr_constraint(hapd, pos);
 
-	/*
-	 * CSA IE
-	 * TODO: This should be included inside the ML sta profile
-	 */
-	if (!params->is_ml_sta_info) {
-		csa_pos = hostapd_eid_csa(hapd, pos);
-		if (csa_pos != pos)
-			params->csa_pos = csa_pos - 1;
-		else
-			params->csa_pos = NULL;
-		pos = csa_pos;
-	}
+	/* CSA element */
+	csa_pos = hostapd_eid_csa(hapd, pos);
+	if (csa_pos != pos)
+		params->csa_pos = csa_pos - 1;
+	else
+		params->csa_pos = NULL;
+	pos = csa_pos;
 
 	/* ERP Information element */
 	pos = hostapd_eid_erp_info(hapd, pos);
@@ -824,18 +847,13 @@ static u8 * hostapd_probe_resp_fill_elems(struct hostapd_data *hapd,
 	pos = hostapd_eid_rm_enabled_capab(hapd, pos, epos - pos);
 	pos = hostapd_get_mde(hapd, pos, epos - pos);
 
-	/*
-	 * eCSA IE
-	 * TODO: This should be included inside the ML sta profile
-	 */
-	if (!params->is_ml_sta_info) {
-		csa_pos = hostapd_eid_ecsa(hapd, pos);
-		if (csa_pos != pos)
-			params->ecsa_pos = csa_pos - 1;
-		else
-			params->ecsa_pos = NULL;
-		pos = csa_pos;
-	}
+	/* eCSA element */
+	csa_pos = hostapd_eid_ecsa(hapd, pos);
+	if (csa_pos != pos)
+		params->ecsa_pos = csa_pos - 1;
+	else
+		params->ecsa_pos = NULL;
+	pos = csa_pos;
 
 	pos = hostapd_eid_supported_op_classes(hapd, pos);
 	pos = hostapd_eid_ht_capabilities(hapd, pos);
@@ -877,12 +895,14 @@ static u8 * hostapd_probe_resp_fill_elems(struct hostapd_data *hapd,
 		pos = hostapd_eid_txpower_envelope(hapd, pos);
 #endif /* CONFIG_IEEE80211AX */
 
-	pos = hostapd_eid_wb_chsw_wrapper(hapd, pos);
+	pos = hostapd_eid_chsw_wrapper(hapd, pos);
 
-	if (!params->is_ml_sta_info)
-		pos = hostapd_eid_rnr(hapd, pos, WLAN_FC_STYPE_PROBE_RESP,
-				      true);
+	pos = hostapd_eid_rnr(hapd, pos, WLAN_FC_STYPE_PROBE_RESP, true);
 	pos = hostapd_eid_fils_indic(hapd, pos, 0);
+
+	/* Max Channel Switch Time element */
+	pos = hostapd_eid_max_cs_time(hapd, pos);
+
 	pos = hostapd_get_rsnxe(hapd, pos, epos - pos);
 
 #ifdef CONFIG_IEEE80211AX
@@ -1039,7 +1059,6 @@ static void hostapd_fill_probe_resp_ml_params(struct hostapd_data *hapd,
 					      const struct ieee80211_mgmt *mgmt,
 					      int mld_id, u16 links)
 {
-	struct probe_resp_params sta_info_params;
 	struct hostapd_data *link;
 
 	params->mld_ap = NULL;
@@ -1053,10 +1072,7 @@ static void hostapd_fill_probe_resp_ml_params(struct hostapd_data *hapd,
 
 	for_each_mld_link(link, hapd) {
 		struct mld_link_info *link_info;
-		size_t buflen;
 		u8 mld_link_id = link->mld_link_id;
-		u8 *epos;
-		u8 buf[EHT_ML_MAX_STA_PROF_LEN];
 
 		/*
 		 * Set mld_ap iff the ML probe request explicitly
@@ -1076,49 +1092,12 @@ static void hostapd_fill_probe_resp_ml_params(struct hostapd_data *hapd,
 			continue;
 
 		link_info = &params->mld_info->links[mld_link_id];
-
-		sta_info_params.req = params->req;
-		sta_info_params.is_p2p = false;
-		sta_info_params.is_ml_sta_info = true;
-		sta_info_params.mld_ap = NULL;
-		sta_info_params.mld_info = NULL;
-
-		buflen = MAX_PROBERESP_LEN;
-		buflen += hostapd_probe_resp_elems_len(link, &sta_info_params);
-
-		if (buflen > EHT_ML_MAX_STA_PROF_LEN) {
-			wpa_printf(MSG_DEBUG,
-				   "MLD: Not including link %d in ML probe response (%zu bytes is too long)",
-				   mld_link_id, buflen);
-			goto fail;
-		}
-
-		/*
-		 * NOTE: This does not properly handle inheritance and
-		 * various other things.
-		 */
-		link_info->valid = true;
-		epos = buf;
-
-		/* Capabilities is the only fixed parameter */
-		WPA_PUT_LE16(epos, hostapd_own_capab_info(hapd));
-		epos += 2;
-
-		epos = hostapd_probe_resp_fill_elems(
-			link, &sta_info_params, epos,
-			EHT_ML_MAX_STA_PROF_LEN - 2);
-		link_info->resp_sta_profile_len = epos - buf;
-		os_free(link_info->resp_sta_profile);
-		link_info->resp_sta_profile = os_memdup(
-			buf, link_info->resp_sta_profile_len);
-		if (!link_info->resp_sta_profile)
-			link_info->resp_sta_profile_len = 0;
-		os_memcpy(link_info->local_addr, link->own_addr, ETH_ALEN);
+		os_memcpy(link_info, &hapd->partner_links[mld_link_id],
+			  sizeof(hapd->partner_links[mld_link_id]));
 
 		wpa_printf(MSG_DEBUG,
-			   "MLD: ML probe response includes link sta info for %d: %u bytes (estimate %zu)",
-			   mld_link_id, link_info->resp_sta_profile_len,
-			   buflen);
+			   "MLD: ML probe response includes link STA info for %d: %u bytes",
+			   mld_link_id, link_info->resp_sta_profile_len);
 	}
 
 	if (mld_id != -1 && !params->mld_ap) {
@@ -1685,7 +1664,6 @@ void handle_probe_req(struct hostapd_data *hapd,
 	params.is_p2p = !!elems.p2p;
 	params.known_bss = elems.mbssid_known_bss;
 	params.known_bss_len = elems.mbssid_known_bss_len;
-	params.is_ml_sta_info = false;
 
 	hostapd_gen_probe_resp(hapd, &params);
 
@@ -1766,7 +1744,6 @@ static u8 * hostapd_probe_resp_offloads(struct hostapd_data *hapd,
 	params.is_p2p = false;
 	params.known_bss = NULL;
 	params.known_bss_len = 0;
-	params.is_ml_sta_info = false;
 	params.mld_ap = NULL;
 	params.mld_info = NULL;
 
@@ -1810,7 +1787,6 @@ u8 * hostapd_unsol_bcast_probe_resp(struct hostapd_data *hapd,
 	probe_params.is_p2p = false;
 	probe_params.known_bss = NULL;
 	probe_params.known_bss_len = 0;
-	probe_params.is_ml_sta_info = false;
 	probe_params.mld_ap = NULL;
 	probe_params.mld_info = NULL;
 
@@ -2188,7 +2164,7 @@ int ieee802_11_build_ap_params(struct hostapd_data *hapd,
 
 #ifdef NEED_AP_MLME
 #define BEACON_HEAD_BUF_SIZE 256
-#define BEACON_TAIL_BUF_SIZE 512
+#define BEACON_TAIL_BUF_SIZE 1500
 	head = os_zalloc(BEACON_HEAD_BUF_SIZE);
 	tail_len = BEACON_TAIL_BUF_SIZE;
 #ifdef CONFIG_WPS
@@ -2227,8 +2203,13 @@ int ieee802_11_build_ap_params(struct hostapd_data *hapd,
 		 * long based on the common info and number of per
 		 * station profiles. For now use 256.
 		 */
-		if (hapd->conf->mld_ap)
+		if (hapd->conf->mld_ap) {
 			tail_len += 256;
+
+			/* for Max Channel Switch Time element during channel
+			 * switch */
+			tail_len += 6;
+		}
 	}
 #endif /* CONFIG_IEEE80211BE */
 
@@ -2372,10 +2353,14 @@ int ieee802_11_build_ap_params(struct hostapd_data *hapd,
 		tailpos = hostapd_eid_txpower_envelope(hapd, tailpos);
 #endif /* CONFIG_IEEE80211AX */
 
-	tailpos = hostapd_eid_wb_chsw_wrapper(hapd, tailpos);
+	tailpos = hostapd_eid_chsw_wrapper(hapd, tailpos);
 
 	tailpos = hostapd_eid_rnr(hapd, tailpos, WLAN_FC_STYPE_BEACON, true);
 	tailpos = hostapd_eid_fils_indic(hapd, tailpos, 0);
+
+	/* Max Channel Switch Time element */
+	tailpos = hostapd_eid_max_cs_time(hapd, tailpos);
+
 	tailpos = hostapd_get_rsnxe(hapd, tailpos, tailend - tailpos);
 	tailpos = hostapd_eid_mbssid_config(hapd, tailpos,
 					    params->mbssid_elem_count);
@@ -2775,12 +2760,438 @@ void ieee802_11_set_beacon_per_bss_only(struct hostapd_data *hapd)
 }
 
 
+#ifdef CONFIG_IEEE80211BE
+
+static int hostapd_get_probe_resp_tmpl(struct hostapd_data *hapd,
+				       struct probe_resp_params *params,
+				       bool is_ml_sta_info)
+{
+	os_memset(params, 0, sizeof(*params));
+	hostapd_gen_probe_resp(hapd, params);
+	if (!params->resp)
+		return -1;
+
+	/* The caller takes care of freeing params->resp. */
+	return 0;
+}
+
+
+static bool is_restricted_eid_in_sta_profile(u8 eid, bool tx_vap)
+{
+	switch (eid) {
+	case WLAN_EID_TIM:
+	case WLAN_EID_BSS_MAX_IDLE_PERIOD:
+	case WLAN_EID_MULTIPLE_BSSID:
+	case WLAN_EID_REDUCED_NEIGHBOR_REPORT:
+	case WLAN_EID_NEIGHBOR_REPORT:
+		return true;
+	case WLAN_EID_SSID:
+		/* SSID is not restricted for non-transmitted BSSID */
+		return tx_vap;
+	default:
+		return false;
+	}
+}
+
+
+static bool is_restricted_ext_eid_in_sta_profile(u8 ext_id)
+{
+	switch (ext_id) {
+	case WLAN_EID_EXT_MULTI_LINK:
+		return true;
+	default:
+		return false;
+	}
+}
+
+
+/* Create the link STA profiles based on inheritance from the reporting
+ * profile.
+ *
+ * NOTE: The same function is used for length calculation as well as filling
+ * data in the given buffer. This avoids risk of not updating the length
+ * function but filling function or vice versa.
+ */
+static size_t hostapd_add_sta_profile(struct ieee80211_mgmt *link_fdata,
+				      size_t link_data_len,
+				      struct ieee80211_mgmt *own_fdata,
+				      size_t own_data_len,
+				      u8 *sta_profile, bool tx_vap)
+{
+	const struct element *link_elem;
+	size_t sta_profile_len = 0;
+	const u8 *link_elem_data;
+	u8 link_ele_len;
+	u8 *link_data;
+	const struct element *own_elem;
+	u8 link_eid, own_eid, own_ele_len;
+	const u8 *own_elem_data;
+	u8 *own_data;
+	bool is_ext;
+	bool ie_found;
+	u8 non_inherit_ele_ext_list[256] = { 0 };
+	u8 non_inherit_ele_ext_list_len = 0;
+	u8 non_inherit_ele_list[256] = { 0 };
+	u8 non_inherit_ele_list_len = 0;
+	u8 num_link_elem_vendor_ies = 0, num_own_elem_vendor_ies = 0;
+	bool add_vendor_ies = false, is_identical_vendor_ies = true;
+	/* The bitmap of parsed EIDs. There are 256 EIDs and ext EIDs, so 32
+	 * bytes to store the bitmaps. */
+	u8 parsed_eid_bmap[32] = { 0 }, parsed_ext_eid_bmap[32] = { 0 };
+	/* extra len used in the logic includes the element id and len */
+	u8 extra_len = 2;
+
+	/* Include len for capab info */
+	sta_profile_len += sizeof(le16);
+	if (sta_profile) {
+		os_memcpy(sta_profile, &link_fdata->u.probe_resp.capab_info,
+			  sizeof(le16));
+		sta_profile += sizeof(le16);
+	}
+
+	own_data = own_fdata->u.probe_resp.variable;
+	link_data = link_fdata->u.probe_resp.variable;
+
+	/* The below logic takes the reporting BSS data and reported BSS data
+	 * and performs intersection to build the STA profile of the reported
+	 * BSS. Certain elements are not added to the STA profile as
+	 * recommended in standard. Matching element information in the
+	 * reporting BSS profile are ignored in the STA profile. Remaining
+	 * elements pertaining to the STA profile are appended at the end. */
+	for_each_element(own_elem, own_data, own_data_len) {
+		is_ext = false;
+		ie_found = false;
+
+		/* Pick one of own elements and get its EID and length */
+		own_elem_data = own_elem->data;
+		own_ele_len = own_elem->datalen;
+
+		if (own_elem->id == WLAN_EID_EXTENSION) {
+			is_ext = true;
+			own_eid = *(own_elem_data);
+			if (is_restricted_ext_eid_in_sta_profile(own_eid))
+				continue;
+		} else {
+			own_eid = own_elem->id;
+			if (is_restricted_eid_in_sta_profile(own_eid, tx_vap))
+				continue;
+		}
+
+		for_each_element(link_elem, link_data, link_data_len) {
+			/* If the element type mismatches, do not consider
+			 * this link element for comparison. */
+			if ((link_elem->id == WLAN_EID_EXTENSION &&
+			     !is_ext) ||
+			    (is_ext && link_elem->id != WLAN_EID_EXTENSION))
+				continue;
+
+			/* Comparison can be done so get the link element and
+			 * its EID and length. */
+			link_elem_data = link_elem->data;
+			link_ele_len = link_elem->datalen;
+
+			if (link_elem->id == WLAN_EID_EXTENSION)
+				link_eid = *(link_elem_data);
+			else
+				link_eid = link_elem->id;
+
+			/* Ignore if EID does not match */
+			if (own_eid != link_eid)
+				continue;
+
+			ie_found = true;
+
+			/* Ignore if the contents is identical. */
+			if (own_ele_len == link_ele_len &&
+			    os_memcmp(own_elem->data, link_elem->data,
+				      own_ele_len) == 0) {
+				if (own_eid == WLAN_EID_VENDOR_SPECIFIC) {
+					is_identical_vendor_ies = true;
+					num_own_elem_vendor_ies++;
+				}
+				continue;
+			}
+
+			/* No need to include this non-matching Vendor Specific
+			 * element explicitly at this point. */
+			if (own_eid == WLAN_EID_VENDOR_SPECIFIC) {
+				is_identical_vendor_ies = false;
+				continue;
+			}
+
+			/* This element is present in the reported profile
+			 * as well as present in the reporting profile.
+			 * However, there is a mismatch in the contents and
+			 * hence, include this in the per STA profile. */
+			sta_profile_len += link_ele_len + extra_len;
+			if (sta_profile) {
+				os_memcpy(sta_profile,
+					  link_elem->data - extra_len,
+					  link_ele_len + extra_len);
+				sta_profile += link_ele_len + extra_len;
+			}
+
+			/* Update the parsed EIDs bitmap */
+			if (is_ext)
+				parsed_ext_eid_bmap[own_eid / 8] |=
+					BIT(own_eid % 8);
+			else
+				parsed_eid_bmap[own_eid / 8] |=
+					BIT(own_eid % 8);
+			break;
+		}
+
+		/* We found at least one Vendor Specific element in reporting
+		 * link which is not same (or present) in the reported link. We
+		 * need to include all Vendor Specific elements from the
+		 * reported link. */
+		if (!is_identical_vendor_ies)
+			add_vendor_ies = true;
+
+		/* This is a unique element in the reporting profile which is
+		 * not present in the reported profile. Update the
+		 * non-inheritance list. */
+		if (!ie_found) {
+			u8 idx;
+
+			if (is_ext) {
+				idx = non_inherit_ele_ext_list_len++;
+				non_inherit_ele_ext_list[idx] = own_eid;
+			} else {
+				idx = non_inherit_ele_list_len++;
+				non_inherit_ele_list[idx] = own_eid;
+			}
+		}
+	}
+
+	/* Parse the remaining elements in the reported profile */
+	for_each_element(link_elem, link_data, link_data_len) {
+		link_elem_data = link_elem->data;
+		link_ele_len = link_elem->datalen;
+
+		/* No need to check this Vendor Specific element at this point.
+		 * Just take the count and continue. */
+		if (link_elem->id == WLAN_EID_VENDOR_SPECIFIC) {
+			num_link_elem_vendor_ies++;
+			continue;
+		}
+
+		if (link_elem->id == WLAN_EID_EXTENSION) {
+			link_eid = *(link_elem_data);
+
+			if ((parsed_ext_eid_bmap[link_eid / 8] &
+			     BIT(link_eid % 8)) ||
+			    is_restricted_ext_eid_in_sta_profile(link_eid))
+				continue;
+		} else {
+			link_eid = link_elem->id;
+
+			if ((parsed_eid_bmap[link_eid / 8] &
+			     BIT(link_eid % 8)) ||
+			    is_restricted_eid_in_sta_profile(link_eid, tx_vap))
+				continue;
+		}
+
+		sta_profile_len += link_ele_len + extra_len;
+		if (sta_profile) {
+			os_memcpy(sta_profile, link_elem_data - extra_len,
+				  link_ele_len + extra_len);
+			sta_profile += link_ele_len + extra_len;
+		}
+	}
+
+	/* Handle Vendor Specific elements
+	 * Add all the Vendor Specific elements of the reported link if
+	 *  a. There is at least one non-matching Vendor Specific element, or
+	 *  b. The number of Vendor Specific elements in reporting and reported
+	 *     link is not same. */
+	if (add_vendor_ies ||
+	    num_own_elem_vendor_ies != num_link_elem_vendor_ies) {
+		for_each_element(link_elem, link_data, link_data_len) {
+			link_elem_data = link_elem->data;
+			link_ele_len = link_elem->datalen;
+
+			if (link_elem->id != WLAN_EID_VENDOR_SPECIFIC)
+				continue;
+
+			sta_profile_len += link_ele_len + extra_len;
+			if (sta_profile) {
+				os_memcpy(sta_profile,
+					  link_elem_data - extra_len,
+					  link_ele_len + extra_len);
+				sta_profile += link_ele_len + extra_len;
+			}
+		}
+	}
+
+	/* Handle non-inheritance
+	 * Non-Inheritance element:
+	 *      Element ID Ext: 1 octet
+	 *	Length: 1 octet
+	 *	Ext tag number: 1 octet
+	 *	Length of Elements ID list: 1 octet
+	 *	Elements ID list: variable
+	 *      Length of Elements ID Extension list: 1 octet
+	 *	Elements ID extensions list: variable
+	 */
+	if (non_inherit_ele_list_len || non_inherit_ele_ext_list_len)
+		sta_profile_len += 3 + 2 + non_inherit_ele_list_len +
+			non_inherit_ele_ext_list_len;
+
+	if (sta_profile &&
+	    (non_inherit_ele_list_len || non_inherit_ele_ext_list_len)) {
+		*sta_profile++ = WLAN_EID_EXTENSION;
+		*sta_profile++ = non_inherit_ele_list_len +
+			non_inherit_ele_ext_list_len + 3;
+		*sta_profile++ = WLAN_EID_EXT_NON_INHERITANCE;
+		*sta_profile++ = non_inherit_ele_list_len;
+		os_memcpy(sta_profile, non_inherit_ele_list,
+			  non_inherit_ele_list_len);
+		sta_profile += non_inherit_ele_list_len;
+		*sta_profile++ = non_inherit_ele_ext_list_len;
+		os_memcpy(sta_profile, non_inherit_ele_ext_list,
+			  non_inherit_ele_ext_list_len);
+		sta_profile += non_inherit_ele_ext_list_len;
+	}
+
+	return sta_profile_len;
+}
+
+
+static u8 * hostapd_gen_sta_profile(struct ieee80211_mgmt *link_data,
+				    size_t link_data_len,
+				    struct ieee80211_mgmt *own_data,
+				    size_t own_data_len,
+				    size_t *sta_profile_len, bool tx_vap)
+{
+	u8 *sta_profile;
+
+	/* Get the length first */
+	*sta_profile_len = hostapd_add_sta_profile(link_data, link_data_len,
+						   own_data, own_data_len,
+						   NULL, tx_vap);
+	if (!(*sta_profile_len) || *sta_profile_len > EHT_ML_MAX_STA_PROF_LEN)
+		return NULL;
+
+	sta_profile = os_zalloc(*sta_profile_len);
+	if (!sta_profile)
+		return NULL;
+
+	/* Now fill in the data */
+	hostapd_add_sta_profile(link_data, link_data_len, own_data,
+				own_data_len, sta_profile, tx_vap);
+
+	/* The caller takes care of freeing the returned sta_profile */
+	return sta_profile;
+}
+
+
+static void hostapd_gen_per_sta_profiles(struct hostapd_data *hapd)
+{
+	bool tx_vap = hapd == hostapd_mbssid_get_tx_bss(hapd);
+	size_t link_data_len, sta_profile_len;
+	size_t own_data_len;
+	struct probe_resp_params link_params;
+	struct probe_resp_params own_params;
+	struct ieee80211_mgmt *link_data;
+	struct ieee80211_mgmt *own_data;
+	struct mld_link_info *link_info;
+	struct hostapd_data *link_bss;
+	u8 link_id, *sta_profile;
+
+	if (!hapd->conf->mld_ap)
+		return;
+
+	wpa_printf(MSG_DEBUG, "MLD: Generating per STA profiles for MLD %s",
+		   hapd->conf->iface);
+
+	wpa_printf(MSG_DEBUG, "MLD: Reporting link %d", hapd->mld_link_id);
+
+	/* Generate a Probe Response template for self */
+	if (hostapd_get_probe_resp_tmpl(hapd, &own_params, false)) {
+		wpa_printf(MSG_ERROR,
+			   "MLD: Error in building per STA profiles");
+		return;
+	}
+
+	own_data = own_params.resp;
+	own_data_len = own_params.resp_len;
+
+	/* Consider the length of the variable fields */
+	own_data_len -= offsetof(struct ieee80211_mgmt, u.probe_resp.variable);
+
+	for_each_mld_link(link_bss, hapd) {
+		if (link_bss == hapd || !link_bss->started)
+			continue;
+
+		link_id = link_bss->mld_link_id;
+		if (link_id >= MAX_NUM_MLD_LINKS)
+			continue;
+
+		sta_profile = NULL;
+		sta_profile_len = 0;
+
+		/* Generate a Probe Response frame template for partner link */
+		if (hostapd_get_probe_resp_tmpl(link_bss, &link_params, true)) {
+			wpa_printf(MSG_ERROR,
+				   "MLD: Could not get link STA probe response template for link %d",
+				   link_id);
+			continue;
+		}
+
+		link_data = link_params.resp;
+		link_data_len = link_params.resp_len;
+
+		/* Consider length of the variable fields */
+		link_data_len -= offsetof(struct ieee80211_mgmt,
+					  u.probe_resp.variable);
+
+		sta_profile = hostapd_gen_sta_profile(link_data, link_data_len,
+						      own_data, own_data_len,
+						      &sta_profile_len, tx_vap);
+		if (!sta_profile) {
+			wpa_printf(MSG_ERROR,
+				   "MLD: Could not generate link STA profile for link %d",
+				   link_id);
+			continue;
+		}
+
+		link_info = &hapd->partner_links[link_id];
+		link_info->valid = true;
+
+		os_free(link_info->resp_sta_profile);
+		link_info->resp_sta_profile_len = sta_profile_len;
+
+		link_info->resp_sta_profile = os_memdup(sta_profile,
+							sta_profile_len);
+		if (!link_info->resp_sta_profile)
+			link_info->resp_sta_profile_len = 0;
+
+		os_memcpy(link_info->local_addr, link_bss->own_addr, ETH_ALEN);
+
+		wpa_printf(MSG_DEBUG,
+			   "MLD: Reported link STA info for %d: %u bytes",
+			   link_id, link_info->resp_sta_profile_len);
+
+		os_free(sta_profile);
+		os_free(link_params.resp);
+	}
+
+	os_free(own_params.resp);
+}
+
+#endif /* CONFIG_IEEE80211BE */
+
+
 int ieee802_11_set_beacon(struct hostapd_data *hapd)
 {
 	struct hostapd_iface *iface = hapd->iface;
 	int ret;
 	size_t i, j;
 	bool is_6g, hapd_mld = false;
+#ifdef CONFIG_IEEE80211BE
+	struct hostapd_data *link_bss;
+#endif /* CONFIG_IEEE80211BE */
 
 	ret = __ieee802_11_set_beacon(hapd);
 	if (ret != 0)
@@ -2821,6 +3232,15 @@ int ieee802_11_set_beacon(struct hostapd_data *hapd)
 		}
 	}
 
+#ifdef CONFIG_IEEE80211BE
+	if (!hapd_mld)
+		return 0;
+
+	/* Generate per STA profiles for each affiliated APs */
+	for_each_mld_link(link_bss, hapd)
+		hostapd_gen_per_sta_profiles(link_bss);
+#endif /* CONFIG_IEEE80211BE */
+
 	return 0;
 }
 
diff --git a/src/ap/ctrl_iface_ap.c b/src/ap/ctrl_iface_ap.c
index d4d73de1..b93a5d21 100644
--- a/src/ap/ctrl_iface_ap.c
+++ b/src/ap/ctrl_iface_ap.c
@@ -661,15 +661,18 @@ int hostapd_ctrl_iface_deauthenticate(struct hostapd_data *hapd,
 	}
 #endif /* CONFIG_P2P_MANAGER */
 
-	if (os_strstr(txtaddr, " tx=0"))
+	sta = ap_get_sta(hapd, addr);
+	if (os_strstr(txtaddr, " tx=0")) {
 		hostapd_drv_sta_remove(hapd, addr);
-	else
+		if (sta)
+			ap_free_sta(hapd, sta);
+	} else {
 		hostapd_drv_sta_deauth(hapd, addr, reason);
-	sta = ap_get_sta(hapd, addr);
-	if (sta)
-		ap_sta_deauthenticate(hapd, sta, reason);
-	else if (addr[0] == 0xff)
-		hostapd_free_stas(hapd);
+		if (sta)
+			ap_sta_deauthenticate(hapd, sta, reason);
+		else if (addr[0] == 0xff)
+			hostapd_free_stas(hapd);
+	}
 
 	return 0;
 }
@@ -723,15 +726,18 @@ int hostapd_ctrl_iface_disassociate(struct hostapd_data *hapd,
 	}
 #endif /* CONFIG_P2P_MANAGER */
 
-	if (os_strstr(txtaddr, " tx=0"))
+	sta = ap_get_sta(hapd, addr);
+	if (os_strstr(txtaddr, " tx=0")) {
 		hostapd_drv_sta_remove(hapd, addr);
-	else
+		if (sta)
+			ap_free_sta(hapd, sta);
+	} else {
 		hostapd_drv_sta_disassoc(hapd, addr, reason);
-	sta = ap_get_sta(hapd, addr);
-	if (sta)
-		ap_sta_disassociate(hapd, sta, reason);
-	else if (addr[0] == 0xff)
-		hostapd_free_stas(hapd);
+		if (sta)
+			ap_sta_disassociate(hapd, sta, reason);
+		else if (addr[0] == 0xff)
+			hostapd_free_stas(hapd);
+	}
 
 	return 0;
 }
@@ -1137,8 +1143,9 @@ int hostapd_parse_csa_settings(const char *pos,
 	SET_CSA_SETTING_EXT(punct_bitmap);
 	settings->freq_params.ht_enabled = !!os_strstr(pos, " ht");
 	settings->freq_params.vht_enabled = !!os_strstr(pos, " vht");
-	settings->freq_params.he_enabled = !!os_strstr(pos, " he");
 	settings->freq_params.eht_enabled = !!os_strstr(pos, " eht");
+	settings->freq_params.he_enabled = !!os_strstr(pos, " he") ||
+		settings->freq_params.eht_enabled;
 	settings->block_tx = !!os_strstr(pos, " blocktx");
 #undef SET_CSA_SETTING
 #undef SET_CSA_SETTING_EXT
diff --git a/src/ap/dfs.c b/src/ap/dfs.c
index af9dc16f..0cac194b 100644
--- a/src/ap/dfs.c
+++ b/src/ap/dfs.c
@@ -253,6 +253,13 @@ static int dfs_find_channel(struct hostapd_iface *iface,
 	for (i = 0; i < mode->num_channels; i++) {
 		chan = &mode->channels[i];
 
+		if (!chan_in_current_hw_info(iface->current_hw_info, chan)) {
+			wpa_printf(MSG_DEBUG,
+				   "DFS: channel %d (%d) is not under current hardware index",
+				   chan->freq, chan->chan);
+			continue;
+		}
+
 		/* Skip HT40/VHT incompatible channels */
 		if (iface->conf->ieee80211n &&
 		    iface->conf->secondary_channel &&
diff --git a/src/ap/drv_callbacks.c b/src/ap/drv_callbacks.c
index 233984f7..05adc411 100644
--- a/src/ap/drv_callbacks.c
+++ b/src/ap/drv_callbacks.c
@@ -73,6 +73,8 @@ void hostapd_notify_assoc_fils_finish(struct hostapd_data *hapd,
 	p = hostapd_eid_assoc_fils_session(sta->wpa_sm, p,
 					   elems.fils_session,
 					   sta->fils_hlp_resp);
+	if (!p)
+		return;
 
 	reply_res = hostapd_sta_assoc(hapd, sta->addr,
 				      sta->fils_pending_assoc_is_reassoc,
@@ -248,6 +250,52 @@ out:
 #endif /* CONFIG_IEEE80211BE */
 
 
+#if defined(HOSTAPD) || defined(CONFIG_IEEE80211BE)
+static struct hostapd_data * hostapd_find_by_sta(struct hostapd_iface *iface,
+						 const u8 *src, bool rsn,
+						 struct sta_info **sta_ret)
+{
+	struct hostapd_data *hapd;
+	struct sta_info *sta;
+	unsigned int j;
+
+	if (sta_ret)
+		*sta_ret = NULL;
+
+	for (j = 0; j < iface->num_bss; j++) {
+		hapd = iface->bss[j];
+		sta = ap_get_sta(hapd, src);
+		if (sta && (sta->flags & WLAN_STA_ASSOC) &&
+		    (!rsn || sta->wpa_sm)) {
+			if (sta_ret)
+				*sta_ret = sta;
+			return hapd;
+		}
+#ifdef CONFIG_IEEE80211BE
+		if (hapd->conf->mld_ap) {
+			struct hostapd_data *p_hapd;
+
+			for_each_mld_link(p_hapd, hapd) {
+				if (p_hapd == hapd)
+					continue;
+
+				sta = ap_get_sta(p_hapd, src);
+				if (sta && (sta->flags & WLAN_STA_ASSOC) &&
+				    (!rsn || sta->wpa_sm)) {
+					if (sta_ret)
+						*sta_ret = sta;
+					return p_hapd;
+				}
+			}
+		}
+#endif /* CONFIG_IEEE80211BE */
+	}
+
+	return NULL;
+}
+#endif /* HOSTAPD || CONFIG_IEEE80211BE */
+
+
 int hostapd_notif_assoc(struct hostapd_data *hapd, const u8 *addr,
 			const u8 *req_ies, size_t req_ies_len,
 			const u8 *resp_ies, size_t resp_ies_len,
@@ -513,10 +561,8 @@ int hostapd_notif_assoc(struct hostapd_data *hapd, const u8 *addr,
 				   "Failed to initialize WPA state machine");
 			return -1;
 		}
-		wpa_auth_set_rsn_override(sta->wpa_sm,
-					  elems.rsne_override != NULL);
-		wpa_auth_set_rsn_override_2(sta->wpa_sm,
-					    elems.rsne_override_2 != NULL);
+		wpa_auth_set_rsn_selection(sta->wpa_sm, elems.rsn_selection,
+					   elems.rsn_selection_len);
 #ifdef CONFIG_IEEE80211BE
 		if (ap_sta_is_mld(hapd, sta)) {
 			wpa_printf(MSG_DEBUG,
@@ -777,6 +823,9 @@ skip_wpa_check:
 		p = hostapd_eid_assoc_fils_session(sta->wpa_sm, p,
 						   elems.fils_session,
 						   sta->fils_hlp_resp);
+		if (!p)
+			goto fail;
+
 		wpa_hexdump(MSG_DEBUG, "FILS Assoc Resp BUF (IEs)",
 			    buf, p - buf);
 	}
@@ -1041,6 +1090,20 @@ legacy:
 void hostapd_event_sta_low_ack(struct hostapd_data *hapd, const u8 *addr)
 {
 	struct sta_info *sta = ap_get_sta(hapd, addr);
+#ifdef CONFIG_IEEE80211BE
+	struct hostapd_data *orig_hapd = hapd;
+
+	if (!sta && hapd->conf->mld_ap) {
+		hapd = hostapd_find_by_sta(hapd->iface, addr, true, &sta);
+		if (!hapd) {
+			wpa_printf(MSG_DEBUG,
+				   "No partner link BSS found for STA " MACSTR
+				   " - fallback to received context",
+				   MAC2STR(addr));
+			hapd = orig_hapd;
+		}
+	}
+#endif /* CONFIG_IEEE80211BE */
 
 	if (!sta || !hapd->conf->disassoc_low_ack || sta->agreed_to_steer)
 		return;
@@ -1983,50 +2046,6 @@ static int hostapd_event_new_sta(struct hostapd_data *hapd, const u8 *addr)
 }
 
 
-static struct hostapd_data * hostapd_find_by_sta(struct hostapd_iface *iface,
-						 const u8 *src, bool rsn,
-						 struct sta_info **sta_ret)
-{
-	struct hostapd_data *hapd;
-	struct sta_info *sta;
-	unsigned int j;
-
-	if (sta_ret)
-		*sta_ret = NULL;
-
-	for (j = 0; j < iface->num_bss; j++) {
-		hapd = iface->bss[j];
-		sta = ap_get_sta(hapd, src);
-		if (sta && (sta->flags & WLAN_STA_ASSOC) &&
-		    (!rsn || sta->wpa_sm)) {
-			if (sta_ret)
-				*sta_ret = sta;
-			return hapd;
-		}
-#ifdef CONFIG_IEEE80211BE
-		if (hapd->conf->mld_ap) {
-			struct hostapd_data *p_hapd;
-
-			for_each_mld_link(p_hapd, hapd) {
-				if (p_hapd == hapd)
-					continue;
-
-				sta = ap_get_sta(p_hapd, src);
-				if (sta && (sta->flags & WLAN_STA_ASSOC) &&
-				    (!rsn || sta->wpa_sm)) {
-					if (sta_ret)
-						*sta_ret = sta;
-					return p_hapd;
-				}
-			}
-		}
-#endif /* CONFIG_IEEE80211BE */
-	}
-
-	return NULL;
-}
-
-
 static void hostapd_event_eapol_rx(struct hostapd_data *hapd, const u8 *src,
 				   const u8 *data, size_t data_len,
 				   enum frame_encryption encrypted,
@@ -2416,6 +2435,88 @@ static void hostapd_event_color_change(struct hostapd_data *hapd, bool success)
 #endif  /* CONFIG_IEEE80211AX */
 
 
+static void hostapd_iface_enable(struct hostapd_data *hapd)
+{
+	wpa_msg(hapd->msg_ctx, MSG_INFO, INTERFACE_ENABLED);
+	if (hapd->disabled && hapd->started) {
+		hapd->disabled = 0;
+		/*
+		 * Try to re-enable interface if the driver stopped it
+		 * when the interface got disabled.
+		 */
+		if (hapd->wpa_auth)
+			wpa_auth_reconfig_group_keys(hapd->wpa_auth);
+		else
+			hostapd_reconfig_encryption(hapd);
+		hapd->reenable_beacon = 1;
+		ieee802_11_set_beacon(hapd);
+#ifdef NEED_AP_MLME
+	} else if (hapd->disabled && hapd->iface->cac_started) {
+		wpa_printf(MSG_DEBUG, "DFS: restarting pending CAC");
+		hostapd_handle_dfs(hapd->iface);
+#endif /* NEED_AP_MLME */
+	}
+}
+
+
+static void hostapd_iface_disable(struct hostapd_data *hapd)
+{
+	hostapd_free_stas(hapd);
+	wpa_msg(hapd->msg_ctx, MSG_INFO, INTERFACE_DISABLED);
+	hapd->disabled = 1;
+}
+
+
+#ifdef CONFIG_IEEE80211BE
+
+static void hostapd_mld_iface_enable(struct hostapd_data *hapd)
+{
+	struct hostapd_data *first_link, *link_bss;
+
+	first_link = hostapd_mld_is_first_bss(hapd) ? hapd :
+		hostapd_mld_get_first_bss(hapd);
+
+	/* Links have been removed. Re-add all links and enable them, but
+	 * enable the first link BSS before doing that. */
+	if (hostapd_drv_link_add(first_link, first_link->mld_link_id,
+				 first_link->own_addr)) {
+		wpa_printf(MSG_ERROR, "MLD: Failed to re-add link %d in MLD %s",
+			   first_link->mld_link_id, first_link->conf->iface);
+		return;
+	}
+
+	hostapd_iface_enable(first_link);
+
+	/* Add other affiliated links */
+	for_each_mld_link(link_bss, first_link) {
+		if (link_bss == first_link)
+			continue;
+
+		if (hostapd_drv_link_add(link_bss, link_bss->mld_link_id,
+					 link_bss->own_addr)) {
+			wpa_printf(MSG_ERROR,
+				   "MLD: Failed to re-add link %d in MLD %s",
+				   link_bss->mld_link_id,
+				   link_bss->conf->iface);
+			continue;
+		}
+
+		hostapd_iface_enable(link_bss);
+	}
+}
+
+
+static void hostapd_mld_iface_disable(struct hostapd_data *hapd)
+{
+	struct hostapd_data *link_bss;
+
+	for_each_mld_link(link_bss, hapd)
+		hostapd_iface_disable(link_bss);
+}
+
+#endif /* CONFIG_IEEE80211BE */
+
+
 void wpa_supplicant_event(void *ctx, enum wpa_event_type event,
 			  union wpa_event_data *data)
 {
@@ -2693,30 +2794,22 @@ void wpa_supplicant_event(void *ctx, enum wpa_event_type event,
 		break;
 #endif /* NEED_AP_MLME */
 	case EVENT_INTERFACE_ENABLED:
-		wpa_msg(hapd->msg_ctx, MSG_INFO, INTERFACE_ENABLED);
-		if (hapd->disabled && hapd->started) {
-			hapd->disabled = 0;
-			/*
-			 * Try to re-enable interface if the driver stopped it
-			 * when the interface got disabled.
-			 */
-			if (hapd->wpa_auth)
-				wpa_auth_reconfig_group_keys(hapd->wpa_auth);
-			else
-				hostapd_reconfig_encryption(hapd);
-			hapd->reenable_beacon = 1;
-			ieee802_11_set_beacon(hapd);
-#ifdef NEED_AP_MLME
-		} else if (hapd->disabled && hapd->iface->cac_started) {
-			wpa_printf(MSG_DEBUG, "DFS: restarting pending CAC");
-			hostapd_handle_dfs(hapd->iface);
-#endif /* NEED_AP_MLME */
+#ifdef CONFIG_IEEE80211BE
+		if (hapd->conf->mld_ap) {
+			hostapd_mld_iface_enable(hapd);
+			break;
 		}
+#endif /* CONFIG_IEEE80211BE */
+		hostapd_iface_enable(hapd);
 		break;
 	case EVENT_INTERFACE_DISABLED:
-		hostapd_free_stas(hapd);
-		wpa_msg(hapd->msg_ctx, MSG_INFO, INTERFACE_DISABLED);
-		hapd->disabled = 1;
+#ifdef CONFIG_IEEE80211BE
+		if (hapd->conf->mld_ap) {
+			hostapd_mld_iface_disable(hapd);
+			break;
+		}
+#endif /* CONFIG_IEEE80211BE */
+		hostapd_iface_disable(hapd);
 		break;
 #ifdef CONFIG_ACS
 	case EVENT_ACS_CHANNEL_SELECTED:
@@ -2769,6 +2862,13 @@ void wpa_supplicant_event(void *ctx, enum wpa_event_type event,
 		hostapd_event_color_change(hapd, true);
 		break;
 #endif /* CONFIG_IEEE80211AX */
+#ifdef CONFIG_IEEE80211BE
+	case EVENT_MLD_INTERFACE_FREED:
+		wpa_printf(MSG_DEBUG, "MLD: Interface %s freed",
+			   hapd->conf->iface);
+		hostapd_mld_interface_freed(hapd);
+		break;
+#endif /* CONFIG_IEEE80211BE */
 	default:
 		wpa_printf(MSG_DEBUG, "Unknown event %d", event);
 		break;
diff --git a/src/ap/hostapd.c b/src/ap/hostapd.c
index a05de030..7d924893 100644
--- a/src/ap/hostapd.c
+++ b/src/ap/hostapd.c
@@ -400,8 +400,6 @@ static int hostapd_broadcast_wep_set(struct hostapd_data *hapd)
 #ifdef CONFIG_IEEE80211BE
 #ifdef CONFIG_TESTING_OPTIONS
 
-#define TU_TO_USEC(_val) ((_val) * 1024)
-
 static void hostapd_link_remove_timeout_handler(void *eloop_data,
 						void *user_ctx)
 {
@@ -440,6 +438,8 @@ int hostapd_link_remove(struct hostapd_data *hapd, u32 count)
 
 	hapd->eht_mld_link_removal_count = count;
 	hapd->eht_mld_bss_param_change++;
+	if (hapd->eht_mld_bss_param_change == 255)
+		hapd->eht_mld_bss_param_change = 0;
 
 	eloop_register_timeout(0, TU_TO_USEC(hapd->iconf->beacon_int),
 			       hostapd_link_remove_timeout_handler,
@@ -620,9 +620,19 @@ void hostapd_free_hapd_data(struct hostapd_data *hapd)
 static void hostapd_bss_link_deinit(struct hostapd_data *hapd)
 {
 #ifdef CONFIG_IEEE80211BE
+	int i;
+
 	if (!hapd->conf || !hapd->conf->mld_ap)
 		return;
 
+	/* Free per STA profiles */
+	for (i = 0; i < MAX_NUM_MLD_LINKS; i++) {
+		os_free(hapd->partner_links[i].resp_sta_profile);
+		os_memset(&hapd->partner_links[i], 0,
+			  sizeof(hapd->partner_links[i]));
+	}
+
+	/* Put all freeing logic above this */
 	if (!hapd->mld->num_links)
 		return;
 
@@ -702,6 +712,9 @@ void hostapd_cleanup_iface_partial(struct hostapd_iface *iface)
 	ap_list_deinit(iface);
 	sta_track_deinit(iface);
 	airtime_policy_update_deinit(iface);
+	hostapd_free_multi_hw_info(iface->multi_hw_info);
+	iface->multi_hw_info = NULL;
+	iface->current_hw_info = NULL;
 }
 
 
@@ -1440,7 +1453,6 @@ static int hostapd_setup_bss(struct hostapd_data *hapd, int first,
 			if (h_hapd) {
 				hapd->drv_priv = h_hapd->drv_priv;
 				hapd->interface_added = h_hapd->interface_added;
-				hostapd_mld_add_link(hapd);
 				wpa_printf(MSG_DEBUG,
 					   "Setup of non first link (%d) BSS of MLD %s",
 					   hapd->mld_link_id, hapd->conf->iface);
@@ -1471,7 +1483,6 @@ static int hostapd_setup_bss(struct hostapd_data *hapd, int first,
 				   hapd->mld_link_id, hapd->conf->iface);
 			os_memcpy(hapd->mld->mld_addr, hapd->own_addr,
 				  ETH_ALEN);
-			hostapd_mld_add_link(hapd);
 		}
 #endif /* CONFIG_IEEE80211BE */
 	}
@@ -1486,8 +1497,13 @@ setup_mld:
 			   MAC2STR(hapd->own_addr));
 
 		if (hostapd_drv_link_add(hapd, hapd->mld_link_id,
-					 hapd->own_addr))
+					 hapd->own_addr)) {
+			wpa_printf(MSG_ERROR,
+				   "MLD: Failed to add link %d in MLD %s",
+				   hapd->mld_link_id, hapd->conf->iface);
 			return -1;
+		}
+		hostapd_mld_add_link(hapd);
 	}
 #endif /* CONFIG_IEEE80211BE */
 
@@ -1808,12 +1824,36 @@ int hostapd_set_acl(struct hostapd_data *hapd)
 }
 
 
+static int hostapd_set_ctrl_sock_iface(struct hostapd_data *hapd)
+{
+#ifdef CONFIG_IEEE80211BE
+	int ret;
+
+	if (hapd->conf->mld_ap) {
+		ret = os_snprintf(hapd->ctrl_sock_iface,
+				  sizeof(hapd->ctrl_sock_iface), "%s_%s%d",
+				  hapd->conf->iface, WPA_CTRL_IFACE_LINK_NAME,
+				  hapd->mld_link_id);
+		if (os_snprintf_error(sizeof(hapd->ctrl_sock_iface), ret))
+			return -1;
+	} else {
+		os_strlcpy(hapd->ctrl_sock_iface, hapd->conf->iface,
+			   sizeof(hapd->ctrl_sock_iface));
+	}
+#endif /* CONFIG_IEEE80211BE */
+	return 0;
+}
+
+
 static int start_ctrl_iface_bss(struct hostapd_data *hapd)
 {
 	if (!hapd->iface->interfaces ||
 	    !hapd->iface->interfaces->ctrl_iface_init)
 		return 0;
 
+	if (hostapd_set_ctrl_sock_iface(hapd))
+		return -1;
+
 	if (hapd->iface->interfaces->ctrl_iface_init(hapd)) {
 		wpa_printf(MSG_ERROR,
 			   "Failed to setup control interface for %s",
@@ -1834,6 +1874,10 @@ static int start_ctrl_iface(struct hostapd_iface *iface)
 
 	for (i = 0; i < iface->num_bss; i++) {
 		struct hostapd_data *hapd = iface->bss[i];
+
+		if (hostapd_set_ctrl_sock_iface(hapd))
+			return -1;
+
 		if (iface->interfaces->ctrl_iface_init(hapd)) {
 			wpa_printf(MSG_ERROR,
 				   "Failed to setup control interface for %s",
@@ -2492,6 +2536,12 @@ static int hostapd_setup_interface_complete_sync(struct hostapd_iface *iface,
 			   hostapd_hw_mode_txt(iface->conf->hw_mode),
 			   iface->conf->channel, iface->freq);
 
+		if (hostapd_set_current_hw_info(iface, iface->freq)) {
+			wpa_printf(MSG_ERROR,
+				   "Failed to set current hardware info");
+			goto fail;
+		}
+
 #ifdef NEED_AP_MLME
 		/* Handle DFS only if it is not offloaded to the driver */
 		if (!(iface->drv_flags & WPA_DRIVER_FLAGS_DFS_OFFLOAD)) {
@@ -3065,9 +3115,17 @@ static void hostapd_bss_setup_multi_link(struct hostapd_data *hapd,
 
 	os_strlcpy(mld->name, conf->iface, sizeof(conf->iface));
 	dl_list_init(&mld->links);
+	mld->ctrl_sock = -1;
+	if (hapd->conf->ctrl_interface)
+		mld->ctrl_interface = os_strdup(hapd->conf->ctrl_interface);
 
 	wpa_printf(MSG_DEBUG, "AP MLD %s created", mld->name);
 
+	/* Initialize MLD control interfaces early to allow external monitoring
+	 * of link setup operations. */
+	if (interfaces->mld_ctrl_iface_init(mld))
+		goto fail;
+
 	hapd->mld = mld;
 	hostapd_mld_ref_inc(mld);
 	hostapd_bss_alloc_link_id(hapd);
@@ -3127,6 +3185,8 @@ static void hostapd_cleanup_unused_mlds(struct hapd_interfaces *interfaces)
 		if (!remove && !forced_remove)
 			continue;
 
+		interfaces->mld_ctrl_iface_deinit(mld);
+
 		wpa_printf(MSG_DEBUG, "AP MLD %s: Freed%s", mld->name,
 			   forced_remove ? " (forced)" : "");
 		os_free(mld);
@@ -3387,8 +3447,10 @@ static void hostapd_cleanup_driver(const struct wpa_driver_ops *driver,
 		driver->hapd_deinit(drv_priv);
 	} else if (hostapd_mld_is_first_bss(iface->bss[0]) &&
 		   driver->is_drv_shared &&
-		   !driver->is_drv_shared(drv_priv, iface->bss[0])) {
+		   !driver->is_drv_shared(drv_priv,
+					  iface->bss[0]->mld_link_id)) {
 		driver->hapd_deinit(drv_priv);
+		hostapd_mld_interface_freed(iface->bss[0]);
 	} else if (hostapd_if_link_remove(iface->bss[0],
 					  WPA_IF_AP_BSS,
 					  iface->bss[0]->conf->iface,
@@ -4501,6 +4563,42 @@ int hostapd_switch_channel(struct hostapd_data *hapd,
 }
 
 
+int hostapd_force_channel_switch(struct hostapd_iface *iface,
+				 struct csa_settings *settings)
+{
+	int ret = 0;
+
+	if (!settings->freq_params.channel) {
+		/* Check if the new channel is supported */
+		settings->freq_params.channel = hostapd_hw_get_channel(
+			iface->bss[0], settings->freq_params.freq);
+		if (!settings->freq_params.channel)
+			return -1;
+	}
+
+	ret = hostapd_disable_iface(iface);
+	if (ret) {
+		wpa_printf(MSG_DEBUG, "Failed to disable the interface");
+		return ret;
+	}
+
+	hostapd_chan_switch_config(iface->bss[0], &settings->freq_params);
+	ret = hostapd_change_config_freq(iface->bss[0], iface->conf,
+					 &settings->freq_params, NULL);
+	if (ret) {
+		wpa_printf(MSG_DEBUG,
+			   "Failed to set the new channel in config");
+		return ret;
+	}
+
+	ret = hostapd_enable_iface(iface);
+	if (ret)
+		wpa_printf(MSG_DEBUG, "Failed to enable the interface");
+
+	return ret;
+}
+
+
 void
 hostapd_switch_channel_fallback(struct hostapd_iface *iface,
 				const struct hostapd_freq_params *freq_params)
@@ -4932,6 +5030,18 @@ struct hostapd_data * hostapd_mld_get_first_bss(struct hostapd_data *hapd)
 	return mld->fbss;
 }
 
+
+void hostapd_mld_interface_freed(struct hostapd_data *hapd)
+{
+	struct hostapd_data *link_bss = NULL;
+
+	if (!hapd || !hapd->conf->mld_ap)
+		return;
+
+	for_each_mld_link(link_bss, hapd)
+		link_bss->drv_priv = NULL;
+}
+
 #endif /* CONFIG_IEEE80211BE */
 
 
diff --git a/src/ap/hostapd.h b/src/ap/hostapd.h
index 85122d48..5d91d855 100644
--- a/src/ap/hostapd.h
+++ b/src/ap/hostapd.h
@@ -97,6 +97,8 @@ struct hapd_interfaces {
 #ifdef CONFIG_IEEE80211BE
 	struct hostapd_mld **mld;
 	size_t mld_count;
+	int (*mld_ctrl_iface_init)(struct hostapd_mld *mld);
+	void (*mld_ctrl_iface_deinit)(struct hostapd_mld *mld);
 #endif /* CONFIG_IEEE80211BE */
 };
 
@@ -167,6 +169,21 @@ struct hostapd_sae_commit_queue {
 	u8 msg[];
 };
 
+struct mld_link_info {
+	u8 valid:1;
+	u8 nstr_bitmap_len:2;
+	u8 local_addr[ETH_ALEN];
+	u8 peer_addr[ETH_ALEN];
+
+	u8 nstr_bitmap[2];
+
+	u16 capability;
+
+	u16 status;
+	u16 resp_sta_profile_len;
+	u8 *resp_sta_profile;
+};
+
 /**
  * struct hostapd_data - hostapd per-BSS data structure
  */
@@ -476,6 +493,14 @@ struct hostapd_data {
 	struct hostapd_mld *mld;
 	struct dl_list link;
 	u8 mld_link_id;
+
+	/* Cached partner info for ML probe response */
+	struct mld_link_info partner_links[MAX_NUM_MLD_LINKS];
+
+	/* 5 characters for "_link", up to 2 characters for <link ID>, so in
+	 * total, additional 7 characters required. */
+	char ctrl_sock_iface[IFNAMSIZ + 7 + 1];
+
 #ifdef CONFIG_TESTING_OPTIONS
 	u8 eht_mld_link_removal_count;
 #endif /* CONFIG_TESTING_OPTIONS */
@@ -529,6 +554,10 @@ struct hostapd_mld {
 
 	struct hostapd_data *fbss;
 	struct dl_list links; /* List head of all affiliated links */
+
+	int ctrl_sock;
+	struct dl_list ctrl_dst;
+	char *ctrl_interface; /* Directory for UNIX domain sockets */
 };
 
 #define HOSTAPD_MLD_MAX_REF_COUNT      0xFF
@@ -713,6 +742,10 @@ struct hostapd_iface {
 	bool is_no_ir;
 
 	bool is_ch_switch_dfs; /* Channel switch from ACS to DFS */
+
+	struct hostapd_multi_hw_info *multi_hw_info;
+	unsigned int num_multi_hws;
+	struct hostapd_multi_hw_info *current_hw_info;
 };
 
 /* hostapd.c */
@@ -755,6 +788,8 @@ void hostapd_chan_switch_config(struct hostapd_data *hapd,
 				struct hostapd_freq_params *freq_params);
 int hostapd_switch_channel(struct hostapd_data *hapd,
 			   struct csa_settings *settings);
+int hostapd_force_channel_switch(struct hostapd_iface *iface,
+				 struct csa_settings *settings);
 void
 hostapd_switch_channel_fallback(struct hostapd_iface *iface,
 				const struct hostapd_freq_params *freq_params);
@@ -833,6 +868,7 @@ int hostapd_fill_cca_settings(struct hostapd_data *hapd,
 #ifdef CONFIG_IEEE80211BE
 
 bool hostapd_mld_is_first_bss(struct hostapd_data *hapd);
+void hostapd_mld_interface_freed(struct hostapd_data *hapd);
 
 #define for_each_mld_link(partner, self) \
 	dl_list_for_each(partner, &self->mld->links, struct hostapd_data, link)
diff --git a/src/ap/hw_features.c b/src/ap/hw_features.c
index c4556603..02d67593 100644
--- a/src/ap/hw_features.c
+++ b/src/ap/hw_features.c
@@ -76,12 +76,15 @@ int hostapd_get_hw_features(struct hostapd_iface *iface)
 {
 	struct hostapd_data *hapd = iface->bss[0];
 	int i, j;
+	unsigned int k;
 	u16 num_modes, flags;
 	struct hostapd_hw_modes *modes;
 	u8 dfs_domain;
 	enum hostapd_hw_mode mode = HOSTAPD_MODE_IEEE80211ANY;
 	bool is_6ghz = false;
 	bool orig_mode_valid = false;
+	struct hostapd_multi_hw_info *multi_hw_info;
+	unsigned int num_multi_hws;
 
 	if (hostapd_drv_none(hapd))
 		return -1;
@@ -168,6 +171,25 @@ int hostapd_get_hw_features(struct hostapd_iface *iface)
 			   __func__);
 	}
 
+	multi_hw_info = hostapd_get_multi_hw_info(hapd, &num_multi_hws);
+	if (!multi_hw_info)
+		return 0;
+
+	hostapd_free_multi_hw_info(iface->multi_hw_info);
+	iface->multi_hw_info = multi_hw_info;
+	iface->num_multi_hws = num_multi_hws;
+
+	wpa_printf(MSG_DEBUG, "Multiple underlying hardwares info:");
+
+	for (k = 0; k < num_multi_hws; k++) {
+		struct hostapd_multi_hw_info *hw_info = &multi_hw_info[k];
+
+		wpa_printf(MSG_DEBUG,
+			   "  %d. hw_idx=%u, frequency range: %d-%d MHz",
+			   k + 1, hw_info->hw_idx, hw_info->start_freq,
+			   hw_info->end_freq);
+	}
+
 	return 0;
 }
 
@@ -1391,3 +1413,34 @@ int hostapd_hw_skip_mode(struct hostapd_iface *iface,
 	}
 	return 0;
 }
+
+
+void hostapd_free_multi_hw_info(struct hostapd_multi_hw_info *multi_hw_info)
+{
+	os_free(multi_hw_info);
+}
+
+
+int hostapd_set_current_hw_info(struct hostapd_iface *iface, int oper_freq)
+{
+	struct hostapd_multi_hw_info *hw_info;
+	unsigned int i;
+
+	if (!iface->num_multi_hws)
+		return 0;
+
+	for (i = 0; i < iface->num_multi_hws; i++) {
+		hw_info = &iface->multi_hw_info[i];
+
+		if (hw_info->start_freq <= oper_freq &&
+		    hw_info->end_freq >= oper_freq) {
+			iface->current_hw_info = hw_info;
+			wpa_printf(MSG_DEBUG,
+				   "Mode: Selected underlying hardware: hw_idx=%u",
+				   iface->current_hw_info->hw_idx);
+			return 0;
+		}
+	}
+
+	return -1;
+}
diff --git a/src/ap/hw_features.h b/src/ap/hw_features.h
index c682c6d2..73663d0a 100644
--- a/src/ap/hw_features.h
+++ b/src/ap/hw_features.h
@@ -30,6 +30,8 @@ void hostapd_stop_setup_timers(struct hostapd_iface *iface);
 int hostapd_hw_skip_mode(struct hostapd_iface *iface,
 			 struct hostapd_hw_modes *mode);
 int hostapd_determine_mode(struct hostapd_iface *iface);
+void hostapd_free_multi_hw_info(struct hostapd_multi_hw_info *multi_hw_info);
+int hostapd_set_current_hw_info(struct hostapd_iface *iface, int oper_freq);
 #else /* NEED_AP_MLME */
 static inline void
 hostapd_free_hw_features(struct hostapd_hw_modes *hw_features,
@@ -103,6 +105,16 @@ static inline int hostapd_determine_mode(struct hostapd_iface *iface)
 	return 0;
 }
 
+static inline
+void hostapd_free_multi_hw_info(struct hostapd_multi_hw_info *multi_hw_info)
+{
+}
+
+static inline int hostapd_set_current_hw_info(struct hostapd_iface *iface,
+					      u32 oper_freq)
+{
+	return 0;
+}
 #endif /* NEED_AP_MLME */
 
 #endif /* HW_FEATURES_H */
diff --git a/src/ap/ieee802_11.c b/src/ap/ieee802_11.c
index 1cd76ca7..d4552f2f 100644
--- a/src/ap/ieee802_11.c
+++ b/src/ap/ieee802_11.c
@@ -1173,16 +1173,23 @@ static int sae_sm_step(struct hostapd_data *hapd, struct sta_info *sta,
 static void sae_pick_next_group(struct hostapd_data *hapd, struct sta_info *sta)
 {
 	struct sae_data *sae = sta->sae;
-	int i, *groups = hapd->conf->sae_groups;
-	int default_groups[] = { 19, 0 };
+	struct hostapd_bss_config *conf = hapd->conf;
+	int i, *groups = conf->sae_groups;
+	int default_groups[] = { 19, 0, 0 };
 
 	if (sae->state != SAE_COMMITTED)
 		return;
 
 	wpa_printf(MSG_DEBUG, "SAE: Previously selected group: %d", sae->group);
 
-	if (!groups)
+	if (!groups) {
 		groups = default_groups;
+		if (wpa_key_mgmt_sae_ext_key(conf->wpa_key_mgmt |
+					     conf->rsn_override_key_mgmt |
+					     conf->rsn_override_key_mgmt_2))
+			default_groups[1] = 20;
+	}
+
 	for (i = 0; groups[i] > 0; i++) {
 		if (sae->group == groups[i])
 			break;
@@ -1247,12 +1254,18 @@ static int sae_status_success(struct hostapd_data *hapd, u16 status_code)
 
 static int sae_is_group_enabled(struct hostapd_data *hapd, int group)
 {
-	int *groups = hapd->conf->sae_groups;
-	int default_groups[] = { 19, 0 };
+	struct hostapd_bss_config *conf = hapd->conf;
+	int *groups = conf->sae_groups;
+	int default_groups[] = { 19, 0, 0 };
 	int i;
 
-	if (!groups)
+	if (!groups) {
 		groups = default_groups;
+		if (wpa_key_mgmt_sae_ext_key(conf->wpa_key_mgmt |
+					     conf->rsn_override_key_mgmt |
+					     conf->rsn_override_key_mgmt_2))
+			default_groups[1] = 20;
+	}
 
 	for (i = 0; groups[i] > 0; i++) {
 		if (groups[i] == group)
@@ -1309,14 +1322,20 @@ static void handle_auth_sae(struct hostapd_data *hapd, struct sta_info *sta,
 {
 	int resp = WLAN_STATUS_SUCCESS;
 	struct wpabuf *data = NULL;
-	int *groups = hapd->conf->sae_groups;
-	int default_groups[] = { 19, 0 };
+	struct hostapd_bss_config *conf = hapd->conf;
+	int *groups = conf->sae_groups;
+	int default_groups[] = { 19, 0, 0 };
 	const u8 *pos, *end;
 	int sta_removed = 0;
 	bool success_status;
 
-	if (!groups)
+	if (!groups) {
 		groups = default_groups;
+		if (wpa_key_mgmt_sae_ext_key(conf->wpa_key_mgmt |
+					     conf->rsn_override_key_mgmt |
+					     conf->rsn_override_key_mgmt_2))
+			default_groups[1] = 20;
+	}
 
 #ifdef CONFIG_TESTING_OPTIONS
 	if (hapd->conf->sae_reflection_attack && auth_transaction == 1) {
@@ -1609,12 +1628,12 @@ reply:
 		    !data && end - pos >= 2)
 			data = wpabuf_alloc_copy(pos, 2);
 
-		sae_sme_send_external_auth_status(hapd, sta, resp);
 		send_auth_reply(hapd, sta, sta->addr,
 				WLAN_AUTH_SAE,
 				auth_transaction, resp,
 				data ? wpabuf_head(data) : (u8 *) "",
 				data ? wpabuf_len(data) : 0, "auth-sae");
+		sae_sme_send_external_auth_status(hapd, sta, resp);
 		if (sta->sae && sta->sae->tmp && sta->sae->tmp->pw_id &&
 		    resp == WLAN_STATUS_UNKNOWN_PASSWORD_IDENTIFIER &&
 		    auth_transaction == 1) {
@@ -1935,6 +1954,8 @@ void handle_auth_fils(struct hostapd_data *hapd, struct sta_info *sta,
 		goto fail;
 	}
 
+	wpa_auth_set_rsn_selection(sta->wpa_sm, elems.rsn_selection,
+				   elems.rsn_selection_len);
 	res = wpa_validate_wpa_ie(hapd->wpa_auth, sta->wpa_sm,
 				  hapd->iface->freq,
 				  elems.rsn_ie - 2, elems.rsn_ie_len + 2,
@@ -1945,9 +1966,6 @@ void handle_auth_fils(struct hostapd_data *hapd, struct sta_info *sta,
 	if (resp != WLAN_STATUS_SUCCESS)
 		goto fail;
 
-	wpa_auth_set_rsn_override(sta->wpa_sm, elems.rsne_override != NULL);
-	wpa_auth_set_rsn_override_2(sta->wpa_sm, elems.rsne_override_2 != NULL);
-
 	if (!elems.fils_nonce) {
 		wpa_printf(MSG_DEBUG, "FILS: No FILS Nonce field");
 		resp = WLAN_STATUS_UNSPECIFIED_FAILURE;
@@ -2463,7 +2481,8 @@ static void pasn_fils_auth_resp(struct hostapd_data *hapd,
 			      wpabuf_head(pasn->secret),
 			      wpabuf_len(pasn->secret),
 			      pasn_get_ptk(sta->pasn), pasn_get_akmp(sta->pasn),
-			      pasn_get_cipher(sta->pasn), sta->pasn->kdk_len);
+			      pasn_get_cipher(sta->pasn), sta->pasn->kdk_len,
+			      sta->pasn->kek_len);
 	if (ret) {
 		wpa_printf(MSG_DEBUG, "PASN: FILS: Failed to derive PTK");
 		goto fail;
@@ -2832,7 +2851,7 @@ static void handle_auth_pasn(struct hostapd_data *hapd, struct sta_info *sta,
 
 		hapd_pasn_update_params(hapd, sta, mgmt, len);
 		if (handle_auth_pasn_1(sta->pasn, hapd->own_addr,
-				       sta->addr, mgmt, len) < 0)
+				       sta->addr, mgmt, len, false) < 0)
 			ap_free_sta(hapd, sta);
 	} else if (trans_seq == 3) {
 		if (!sta->pasn) {
@@ -4134,10 +4153,8 @@ static int __check_assoc_ies(struct hostapd_data *hapd, struct sta_info *sta,
 #endif /* CONFIG_IEEE80211BE */
 
 		wpa_auth_set_auth_alg(sta->wpa_sm, sta->auth_alg);
-		wpa_auth_set_rsn_override(sta->wpa_sm,
-					  elems->rsne_override != NULL);
-		wpa_auth_set_rsn_override_2(sta->wpa_sm,
-					    elems->rsne_override_2 != NULL);
+		wpa_auth_set_rsn_selection(sta->wpa_sm, elems->rsn_selection,
+					   elems->rsn_selection_len);
 		res = wpa_validate_wpa_ie(hapd->wpa_auth, sta->wpa_sm,
 					  hapd->iface->freq,
 					  wpa_ie, wpa_ie_len,
@@ -4998,7 +5015,8 @@ static u16 send_assoc_resp(struct hostapd_data *hapd, struct sta_info *sta,
 #endif /* CONFIG_IEEE80211AX */
 
 	p = hostapd_eid_ext_capab(hapd, p, false);
-	p = hostapd_eid_bss_max_idle_period(hapd, p, sta->max_idle_period);
+	p = hostapd_eid_bss_max_idle_period(hapd, p,
+					    sta ? sta->max_idle_period : 0);
 	if (sta && sta->qos_map_enabled)
 		p = hostapd_eid_qos_map_set(hapd, p);
 
@@ -7230,16 +7248,11 @@ u8 * hostapd_eid_txpower_envelope(struct hostapd_data *hapd, u8 *eid)
 }
 
 
-u8 * hostapd_eid_wb_chsw_wrapper(struct hostapd_data *hapd, u8 *eid)
+/* Wide Bandwidth Channel Switch subelement */
+static u8 * hostapd_eid_wb_channel_switch(struct hostapd_data *hapd, u8 *eid,
+					  u8 chan1, u8 chan2)
 {
-	u8 bw, chan1 = 0, chan2 = 0;
-	int freq1;
-
-	if (!hapd->cs_freq_params.channel ||
-	    (!hapd->cs_freq_params.vht_enabled &&
-	     !hapd->cs_freq_params.he_enabled &&
-	     !hapd->cs_freq_params.eht_enabled))
-		return eid;
+	u8 bw;
 
 	/* bandwidth: 0: 40, 1: 80, 160, 80+80, 4: 320 as per
 	 * IEEE P802.11-REVme/D4.0, 9.4.2.159 and Table 9-314. */
@@ -7261,20 +7274,6 @@ u8 * hostapd_eid_wb_chsw_wrapper(struct hostapd_data *hapd, u8 *eid)
 		return eid;
 	}
 
-	freq1 = hapd->cs_freq_params.center_freq1 ?
-		hapd->cs_freq_params.center_freq1 :
-		hapd->cs_freq_params.freq;
-	if (ieee80211_freq_to_chan(freq1, &chan1) !=
-	    HOSTAPD_MODE_IEEE80211A)
-		return eid;
-
-	if (hapd->cs_freq_params.center_freq2 &&
-	    ieee80211_freq_to_chan(hapd->cs_freq_params.center_freq2,
-				   &chan2) != HOSTAPD_MODE_IEEE80211A)
-		return eid;
-
-	*eid++ = WLAN_EID_CHANNEL_SWITCH_WRAPPER;
-	*eid++ = 5; /* Length of Channel Switch Wrapper */
 	*eid++ = WLAN_EID_WIDE_BW_CHSWITCH;
 	*eid++ = 3; /* Length of Wide Bandwidth Channel Switch element */
 	*eid++ = bw; /* New Channel Width */
@@ -7300,6 +7299,118 @@ u8 * hostapd_eid_wb_chsw_wrapper(struct hostapd_data *hapd, u8 *eid)
 }
 
 
+#ifdef CONFIG_IEEE80211BE
+/* Bandwidth Indication element that is also used as the Bandwidth Indication
+ * For Channel Switch subelement within a Channel Switch Wrapper element. */
+static u8 * hostapd_eid_bw_indication(struct hostapd_data *hapd, u8 *eid,
+				      u8 chan1, u8 chan2)
+{
+	u16 punct_bitmap = hostapd_get_punct_bitmap(hapd);
+	struct ieee80211_bw_ind_element *bw_ind_elem;
+	size_t elen = 3;
+
+	if (hapd->cs_freq_params.bandwidth <= 160 && !punct_bitmap)
+		return eid;
+
+	if (punct_bitmap)
+		elen += EHT_OPER_DISABLED_SUBCHAN_BITMAP_SIZE;
+
+	*eid++ = WLAN_EID_EXTENSION;
+	*eid++ = 1 + elen;
+	*eid++ = WLAN_EID_EXT_BANDWIDTH_INDICATION;
+
+	bw_ind_elem = (struct ieee80211_bw_ind_element *) eid;
+	os_memset(bw_ind_elem, 0, sizeof(struct ieee80211_bw_ind_element));
+
+	switch (hapd->cs_freq_params.bandwidth) {
+	case 320:
+		bw_ind_elem->bw_ind_info.control |= BW_IND_CHANNEL_WIDTH_320MHZ;
+		chan2 = chan1;
+		if (hapd->cs_freq_params.channel < chan1)
+			chan1 -= 16;
+		else
+			chan1 += 16;
+		break;
+	case 160:
+		bw_ind_elem->bw_ind_info.control |= BW_IND_CHANNEL_WIDTH_160MHZ;
+		chan2 = chan1;
+		if (hapd->cs_freq_params.channel < chan1)
+			chan1 -= 8;
+		else
+			chan1 += 8;
+		break;
+	case 80:
+		bw_ind_elem->bw_ind_info.control |= BW_IND_CHANNEL_WIDTH_80MHZ;
+		break;
+	case 40:
+		if (hapd->cs_freq_params.sec_channel_offset == 1)
+			bw_ind_elem->bw_ind_info.control |=
+				BW_IND_CHANNEL_WIDTH_40MHZ;
+		else
+			bw_ind_elem->bw_ind_info.control |=
+				BW_IND_CHANNEL_WIDTH_20MHZ;
+		break;
+	default:
+		bw_ind_elem->bw_ind_info.control |= BW_IND_CHANNEL_WIDTH_20MHZ;
+		break;
+	}
+
+	bw_ind_elem->bw_ind_info.ccfs0 = chan1;
+	bw_ind_elem->bw_ind_info.ccfs1 = chan2;
+
+	if (punct_bitmap) {
+		bw_ind_elem->bw_ind_params |=
+			BW_IND_PARAMETER_DISABLED_SUBCHAN_BITMAP_PRESENT;
+		bw_ind_elem->bw_ind_info.disabled_chan_bitmap =
+			host_to_le16(punct_bitmap);
+	}
+
+	return eid + elen;
+}
+#endif /* CONFIG_IEEE80211BE */
+
+
+u8 * hostapd_eid_chsw_wrapper(struct hostapd_data *hapd, u8 *eid)
+{
+	u8 chan1 = 0, chan2 = 0;
+	u8 *eid_len_offset;
+	int freq1;
+
+	if (!hapd->cs_freq_params.channel ||
+	    (!hapd->cs_freq_params.vht_enabled &&
+	     !hapd->cs_freq_params.he_enabled &&
+	     !hapd->cs_freq_params.eht_enabled))
+		return eid;
+
+	freq1 = hapd->cs_freq_params.center_freq1 ?
+		hapd->cs_freq_params.center_freq1 :
+		hapd->cs_freq_params.freq;
+	if (ieee80211_freq_to_chan(freq1, &chan1) !=
+	    HOSTAPD_MODE_IEEE80211A)
+		return eid;
+
+	if (hapd->cs_freq_params.center_freq2 &&
+	    ieee80211_freq_to_chan(hapd->cs_freq_params.center_freq2,
+				   &chan2) != HOSTAPD_MODE_IEEE80211A)
+		return eid;
+
+	*eid++ = WLAN_EID_CHANNEL_SWITCH_WRAPPER;
+	eid_len_offset = eid++; /* Length of Channel Switch Wrapper element */
+
+	eid = hostapd_eid_wb_channel_switch(hapd, eid, chan1, chan2);
+
+#ifdef CONFIG_IEEE80211BE
+	if (hapd->iconf->ieee80211be && !hapd->conf->disable_11be) {
+		/* Bandwidth Indication For Channel Switch subelement */
+		eid = hostapd_eid_bw_indication(hapd, eid, chan1, chan2);
+	}
+#endif /* CONFIG_IEEE80211BE */
+
+	*eid_len_offset = (eid - eid_len_offset) - 1;
+	return eid;
+}
+
+
 static size_t hostapd_eid_nr_db_len(struct hostapd_data *hapd,
 				    size_t *current_len)
 {
diff --git a/src/ap/ieee802_11.h b/src/ap/ieee802_11.h
index dd4995f3..abf48ab6 100644
--- a/src/ap/ieee802_11.h
+++ b/src/ap/ieee802_11.h
@@ -63,7 +63,7 @@ u8 * hostapd_eid_ht_operation(struct hostapd_data *hapd, u8 *eid);
 u8 * hostapd_eid_vht_capabilities(struct hostapd_data *hapd, u8 *eid, u32 nsts);
 u8 * hostapd_eid_vht_operation(struct hostapd_data *hapd, u8 *eid);
 u8 * hostapd_eid_vendor_vht(struct hostapd_data *hapd, u8 *eid);
-u8 * hostapd_eid_wb_chsw_wrapper(struct hostapd_data *hapd, u8 *eid);
+u8 * hostapd_eid_chsw_wrapper(struct hostapd_data *hapd, u8 *eid);
 u8 * hostapd_eid_txpower_envelope(struct hostapd_data *hapd, u8 *eid);
 u8 * hostapd_eid_he_capab(struct hostapd_data *hapd, u8 *eid,
 			  enum ieee80211_op_mode opmode);
diff --git a/src/ap/ieee802_11_eht.c b/src/ap/ieee802_11_eht.c
index afb2e168..aea69ab2 100644
--- a/src/ap/ieee802_11_eht.c
+++ b/src/ap/ieee802_11_eht.c
@@ -871,6 +871,8 @@ sae_commit_skip_fixed_fields(const struct ieee80211_mgmt *mgmt, size_t len,
 
 	wpa_printf(MSG_DEBUG, "EHT: SAE scalar length is %zu", prime_len);
 
+	if (len - 2 < prime_len * (ec ? 3 : 2))
+		goto truncated;
 	/* scalar */
 	pos += prime_len;
 
@@ -882,6 +884,7 @@ sae_commit_skip_fixed_fields(const struct ieee80211_mgmt *mgmt, size_t len,
 	}
 
 	if (pos - mgmt->u.auth.variable > (int) len) {
+	truncated:
 		wpa_printf(MSG_DEBUG,
 			   "EHT: Too short SAE commit Authentication frame");
 		return NULL;
@@ -905,16 +908,38 @@ sae_confirm_skip_fixed_fields(struct hostapd_data *hapd,
 		return pos;
 
 	/* send confirm integer */
+	if (len < 2)
+		goto truncated;
 	pos += 2;
 
 	/*
 	 * At this stage we should already have an MLD station and actually SA
-	 * will be replaced with the MLD MAC address by the driver.
+	 * will be replaced with the MLD MAC address by the driver. However,
+	 * there is at least a theoretical race condition in a case where the
+	 * peer sends the SAE confirm message quickly enough for the driver
+	 * translation mechanism to not be available to update the SAE confirm
+	 * message addresses. Work around that by searching for the STA entry
+	 * using the link address of the non-AP MLD if no match is found based
+	 * on the MLD MAC address.
 	 */
 	sta = ap_get_sta(hapd, mgmt->sa);
 	if (!sta) {
 		wpa_printf(MSG_DEBUG, "SAE: No MLD STA for SAE confirm");
-		return NULL;
+		for (sta = hapd->sta_list; sta; sta = sta->next) {
+			int link_id = hapd->mld_link_id;
+
+			if (!sta->mld_info.mld_sta ||
+			    sta->mld_info.links[link_id].valid ||
+			    !ether_addr_equal(
+				    mgmt->sa,
+				    sta->mld_info.links[link_id].peer_addr))
+				continue;
+			wpa_printf(MSG_DEBUG,
+				   "SAE: Found MLD STA for SAE confirm based on link address");
+			break;
+		}
+		if (!sta)
+			return NULL;
 	}
 
 	if (!sta->sae || sta->sae->state < SAE_COMMITTED || !sta->sae->tmp) {
@@ -929,9 +954,12 @@ sae_confirm_skip_fixed_fields(struct hostapd_data *hapd,
 	wpa_printf(MSG_DEBUG, "SAE: confirm: kck_len=%zu",
 		   sta->sae->tmp->kck_len);
 
+	if (len - 2 < sta->sae->tmp->kck_len)
+		goto truncated;
 	pos += sta->sae->tmp->kck_len;
 
 	if (pos - mgmt->u.auth.variable > (int) len) {
+	truncated:
 		wpa_printf(MSG_DEBUG,
 			   "EHT: Too short SAE confirm Authentication frame");
 		return NULL;
diff --git a/src/ap/ieee802_11_ht.c b/src/ap/ieee802_11_ht.c
index f90f1254..4c39e407 100644
--- a/src/ap/ieee802_11_ht.c
+++ b/src/ap/ieee802_11_ht.c
@@ -79,6 +79,51 @@ u8 * hostapd_eid_ht_capabilities(struct hostapd_data *hapd, u8 *eid)
 }
 
 
+static void set_ht_param(struct hostapd_data *hapd,
+			 struct ieee80211_ht_operation *oper)
+{
+	int secondary_channel = hapd->iconf->secondary_channel;
+#ifdef CONFIG_IEEE80211BE
+	enum oper_chan_width chwidth = hostapd_get_oper_chwidth(hapd->iconf);
+	u16 bw = 0, punct_bitmap = hostapd_get_punct_bitmap(hapd);
+	u8 offset, chan_bit_pos;
+
+	switch (chwidth) {
+	case CONF_OPER_CHWIDTH_80MHZ:
+		bw = 80;
+		offset = 6;
+		break;
+	case CONF_OPER_CHWIDTH_160MHZ:
+		bw = 160;
+		offset = 14;
+		break;
+	case CONF_OPER_CHWIDTH_320MHZ:
+		bw = 320;
+		offset = 30;
+		break;
+	default:
+		goto no_update;
+	}
+
+	chan_bit_pos = (hapd->iconf->channel -
+			hostapd_get_oper_centr_freq_seg0_idx(hapd->iconf) +
+			offset) / 4;
+	/* Check if secondary channel is punctured */
+	if (bw >= 80 && punct_bitmap && secondary_channel &&
+	    (punct_bitmap & BIT(chan_bit_pos + secondary_channel)))
+		return; /* Do not indicate punctured secondary channel for HT */
+no_update:
+#endif /* CONFIG_IEEE80211BE */
+
+	if (secondary_channel == 1)
+		oper->ht_param |= HT_INFO_HT_PARAM_SECONDARY_CHNL_ABOVE |
+			HT_INFO_HT_PARAM_STA_CHNL_WIDTH;
+	if (secondary_channel == -1)
+		oper->ht_param |= HT_INFO_HT_PARAM_SECONDARY_CHNL_BELOW |
+			HT_INFO_HT_PARAM_STA_CHNL_WIDTH;
+}
+
+
 u8 * hostapd_eid_ht_operation(struct hostapd_data *hapd, u8 *eid)
 {
 	struct ieee80211_ht_operation *oper;
@@ -96,12 +141,7 @@ u8 * hostapd_eid_ht_operation(struct hostapd_data *hapd, u8 *eid)
 
 	oper->primary_chan = hapd->iconf->channel;
 	oper->operation_mode = host_to_le16(hapd->iface->ht_op_mode);
-	if (hapd->iconf->secondary_channel == 1)
-		oper->ht_param |= HT_INFO_HT_PARAM_SECONDARY_CHNL_ABOVE |
-			HT_INFO_HT_PARAM_STA_CHNL_WIDTH;
-	if (hapd->iconf->secondary_channel == -1)
-		oper->ht_param |= HT_INFO_HT_PARAM_SECONDARY_CHNL_BELOW |
-			HT_INFO_HT_PARAM_STA_CHNL_WIDTH;
+	set_ht_param(hapd, oper);
 
 	pos += sizeof(*oper);
 
diff --git a/src/ap/nan_usd_ap.c b/src/ap/nan_usd_ap.c
index 52a967a4..570abfce 100644
--- a/src/ap/nan_usd_ap.c
+++ b/src/ap/nan_usd_ap.c
@@ -158,7 +158,7 @@ int hostapd_nan_usd_init(struct hostapd_data *hapd)
 	cb.subscribe_terminated = hostapd_nan_de_subscribe_terminated;
 	cb.receive = hostapd_nan_de_receive;
 
-	hapd->nan_de = nan_de_init(hapd->own_addr, true, &cb);
+	hapd->nan_de = nan_de_init(hapd->own_addr, false, true, &cb);
 	if (!hapd->nan_de)
 		return -1;
 	return 0;
@@ -192,7 +192,7 @@ void hostapd_nan_usd_flush(struct hostapd_data *hapd)
 int hostapd_nan_usd_publish(struct hostapd_data *hapd, const char *service_name,
 			    enum nan_service_protocol_type srv_proto_type,
 			    const struct wpabuf *ssi,
-			    struct nan_publish_params *params)
+			    struct nan_publish_params *params, bool p2p)
 {
 	int publish_id;
 	struct wpabuf *elems = NULL;
@@ -201,7 +201,7 @@ int hostapd_nan_usd_publish(struct hostapd_data *hapd, const char *service_name,
 		return -1;
 
 	publish_id = nan_de_publish(hapd->nan_de, service_name, srv_proto_type,
-				    ssi, elems, params);
+				    ssi, elems, params, p2p);
 	wpabuf_free(elems);
 	return publish_id;
 }
@@ -231,7 +231,7 @@ int hostapd_nan_usd_subscribe(struct hostapd_data *hapd,
 			      const char *service_name,
 			      enum nan_service_protocol_type srv_proto_type,
 			      const struct wpabuf *ssi,
-			      struct nan_subscribe_params *params)
+			      struct nan_subscribe_params *params, bool p2p)
 {
 	int subscribe_id;
 	struct wpabuf *elems = NULL;
@@ -240,7 +240,7 @@ int hostapd_nan_usd_subscribe(struct hostapd_data *hapd,
 		return -1;
 
 	subscribe_id = nan_de_subscribe(hapd->nan_de, service_name,
-					srv_proto_type, ssi, elems, params);
+					srv_proto_type, ssi, elems, params, p2p);
 	wpabuf_free(elems);
 	return subscribe_id;
 }
diff --git a/src/ap/nan_usd_ap.h b/src/ap/nan_usd_ap.h
index 58ff5fc4..0571643c 100644
--- a/src/ap/nan_usd_ap.h
+++ b/src/ap/nan_usd_ap.h
@@ -21,7 +21,7 @@ void hostapd_nan_usd_flush(struct hostapd_data *hapd);
 int hostapd_nan_usd_publish(struct hostapd_data *hapd, const char *service_name,
 			    enum nan_service_protocol_type srv_proto_type,
 			    const struct wpabuf *ssi,
-			    struct nan_publish_params *params);
+			    struct nan_publish_params *params, bool p2p);
 void hostapd_nan_usd_cancel_publish(struct hostapd_data *hapd, int publish_id);
 int hostapd_nan_usd_update_publish(struct hostapd_data *hapd, int publish_id,
 				   const struct wpabuf *ssi);
@@ -29,7 +29,7 @@ int hostapd_nan_usd_subscribe(struct hostapd_data *hapd,
 			      const char *service_name,
 			      enum nan_service_protocol_type srv_proto_type,
 			      const struct wpabuf *ssi,
-			      struct nan_subscribe_params *params);
+			      struct nan_subscribe_params *params, bool p2p);
 void hostapd_nan_usd_cancel_subscribe(struct hostapd_data *hapd,
 				      int subscribe_id);
 int hostapd_nan_usd_transmit(struct hostapd_data *hapd, int handle,
diff --git a/src/ap/sta_info.c b/src/ap/sta_info.c
index 13613dba..aa7e156a 100644
--- a/src/ap/sta_info.c
+++ b/src/ap/sta_info.c
@@ -1625,6 +1625,7 @@ void ap_sta_disconnect(struct hostapd_data *hapd, struct sta_info *sta,
 
 	if (sta == NULL)
 		return;
+	sta->deauth_reason = reason;
 	ap_sta_set_authorized(hapd, sta, 0);
 	sta->flags &= ~(WLAN_STA_AUTH | WLAN_STA_ASSOC);
 	hostapd_set_sta_flags(hapd, sta);
@@ -1654,7 +1655,6 @@ void ap_sta_disconnect(struct hostapd_data *hapd, struct sta_info *sta,
 		return;
 	}
 
-	sta->deauth_reason = reason;
 	sta->flags |= WLAN_STA_PENDING_DEAUTH_CB;
 	eloop_cancel_timeout(ap_sta_deauth_cb_timeout, hapd, sta);
 	eloop_register_timeout(hapd->iface->drv_flags &
diff --git a/src/ap/sta_info.h b/src/ap/sta_info.h
index 84629358..5b01c1e6 100644
--- a/src/ap/sta_info.h
+++ b/src/ap/sta_info.h
@@ -81,20 +81,7 @@ struct mld_info {
 		u16 mld_capa;
 	} common_info;
 
-	struct mld_link_info {
-		u8 valid:1;
-		u8 nstr_bitmap_len:2;
-		u8 local_addr[ETH_ALEN];
-		u8 peer_addr[ETH_ALEN];
-
-		u8 nstr_bitmap[2];
-
-		u16 capability;
-
-		u16 status;
-		u16 resp_sta_profile_len;
-		u8 *resp_sta_profile;
-	} links[MAX_NUM_MLD_LINKS];
+	struct mld_link_info links[MAX_NUM_MLD_LINKS];
 };
 
 struct sta_info {
diff --git a/src/ap/wpa_auth.c b/src/ap/wpa_auth.c
index bbf41d30..3af3404a 100644
--- a/src/ap/wpa_auth.c
+++ b/src/ap/wpa_auth.c
@@ -112,10 +112,7 @@ static void wpa_gkeydone_sta(struct wpa_state_machine *sm)
 	int link_id;
 #endif /* CONFIG_IEEE80211BE */
 
-	if (!sm->wpa_auth)
-		return;
-
-	sm->wpa_auth->group->GKeyDoneStations--;
+	sm->group->GKeyDoneStations--;
 	sm->GUpdateStationKeys = false;
 
 #ifdef CONFIG_IEEE80211BE
@@ -889,9 +886,6 @@ void wpa_deinit(struct wpa_authenticator *wpa_auth)
 
 
 	os_free(wpa_auth->wpa_ie);
-	os_free(wpa_auth->rsne_override);
-	os_free(wpa_auth->rsne_override_2);
-	os_free(wpa_auth->rsnxe_override);
 
 	group = wpa_auth->group;
 	while (group) {
@@ -1053,6 +1047,7 @@ static void wpa_free_sta_sm(struct wpa_state_machine *sm)
 	os_free(sm->last_rx_eapol_key);
 	os_free(sm->wpa_ie);
 	os_free(sm->rsnxe);
+	os_free(sm->rsn_selection);
 #ifdef CONFIG_IEEE80211BE
 	for_each_sm_auth(sm, link_id) {
 		wpa_group_put(sm->mld_links[link_id].wpa_auth,
@@ -1893,7 +1888,8 @@ void wpa_receive(struct wpa_authenticator *wpa_auth,
 	sm->EAPOLKeyReceived = true;
 	sm->EAPOLKeyPairwise = !!(key_info & WPA_KEY_INFO_KEY_TYPE);
 	sm->EAPOLKeyRequest = !!(key_info & WPA_KEY_INFO_REQUEST);
-	os_memcpy(sm->SNonce, key->key_nonce, WPA_NONCE_LEN);
+	if (msg == PAIRWISE_2)
+		os_memcpy(sm->SNonce, key->key_nonce, WPA_NONCE_LEN);
 	wpa_sm_step(sm);
 
 out:
@@ -2071,6 +2067,11 @@ void __wpa_send_eapol(struct wpa_authenticator *wpa_auth,
 	if (key_rsc)
 		os_memcpy(key->key_rsc, key_rsc, WPA_KEY_RSC_LEN);
 
+#ifdef CONFIG_TESTING_OPTIONS
+	if (conf->eapol_key_reserved_random)
+		random_get_bytes(key->key_id, sizeof(key->key_id));
+#endif /* CONFIG_TESTING_OPTIONS */
+
 	if (kde && !encr) {
 		os_memcpy(key_data, kde, kde_len);
 		WPA_PUT_BE16(key_mic + mic_len, kde_len);
@@ -3926,6 +3927,34 @@ SM_STATE(WPA_PTK, PTKCALCNEGOTIATING)
 		goto out;
 	}
 #endif /* CONFIG_IEEE80211R_AP */
+
+	/* Verify RSN Selection element for RSN overriding */
+	if ((wpa_auth->conf.rsn_override_key_mgmt ||
+	     wpa_auth->conf.rsn_override_key_mgmt_2) &&
+	    ((rsn_is_snonce_cookie(sm->SNonce) && !kde.rsn_selection) ||
+	     (!rsn_is_snonce_cookie(sm->SNonce) && kde.rsn_selection) ||
+	     (sm->rsn_selection && !kde.rsn_selection) ||
+	     (!sm->rsn_selection && kde.rsn_selection) ||
+	     (sm->rsn_selection && kde.rsn_selection &&
+	      (sm->rsn_selection_len != kde.rsn_selection_len ||
+	       os_memcmp(sm->rsn_selection, kde.rsn_selection,
+			 sm->rsn_selection_len) != 0)))) {
+		wpa_auth_logger(wpa_auth, wpa_auth_get_spa(sm), LOGGER_INFO,
+				"RSN Selection element from (Re)AssocReq did not match the one in EAPOL-Key msg 2/4");
+		wpa_printf(MSG_DEBUG,
+			   "SNonce cookie for RSN overriding %sused",
+			   rsn_is_snonce_cookie(sm->SNonce) ? "" : "not ");
+		wpa_hexdump(MSG_DEBUG, "RSN Selection in AssocReq",
+			    sm->rsn_selection, sm->rsn_selection_len);
+		wpa_hexdump(MSG_DEBUG, "RSN Selection in EAPOL-Key msg 2/4",
+			    kde.rsn_selection, kde.rsn_selection_len);
+		/* MLME-DEAUTHENTICATE.request */
+		wpa_sta_disconnect(wpa_auth, sm->addr,
+				   WLAN_REASON_PREV_AUTH_NOT_VALID);
+		goto out;
+
+	}
+
 #ifdef CONFIG_P2P
 	if (kde.ip_addr_req && kde.ip_addr_req[0] &&
 	    wpa_auth->ip_pool && WPA_GET_BE32(sm->ip_addr) == 0) {
@@ -4189,7 +4218,8 @@ static u8 * replace_ie(const char *name, const u8 *old_buf, size_t *len, u8 eid,
 
 void wpa_auth_ml_get_key_info(struct wpa_authenticator *a,
 			      struct wpa_auth_ml_link_key_info *info,
-			      bool mgmt_frame_prot, bool beacon_prot)
+			      bool mgmt_frame_prot, bool beacon_prot,
+			      bool rekey)
 {
 	struct wpa_group *gsm = a->group;
 	u8 rsc[WPA_KEY_RSC_LEN];
@@ -4202,7 +4232,7 @@ void wpa_auth_ml_get_key_info(struct wpa_authenticator *a,
 	info->gtk = gsm->GTK[gsm->GN - 1];
 	info->gtk_len = gsm->GTK_len;
 
-	if (wpa_auth_get_seqnum(a, NULL, gsm->GN, rsc) < 0)
+	if (rekey || wpa_auth_get_seqnum(a, NULL, gsm->GN, rsc) < 0)
 		os_memset(info->pn, 0, sizeof(info->pn));
 	else
 		os_memcpy(info->pn, rsc, sizeof(info->pn));
@@ -4214,7 +4244,7 @@ void wpa_auth_ml_get_key_info(struct wpa_authenticator *a,
 	info->igtk = gsm->IGTK[gsm->GN_igtk - 4];
 	info->igtk_len = wpa_cipher_key_len(a->conf.group_mgmt_cipher);
 
-	if (wpa_auth_get_seqnum(a, NULL, gsm->GN_igtk, rsc) < 0)
+	if (rekey || wpa_auth_get_seqnum(a, NULL, gsm->GN_igtk, rsc) < 0)
 		os_memset(info->ipn, 0, sizeof(info->ipn));
 	else
 		os_memcpy(info->ipn, rsc, sizeof(info->ipn));
@@ -4230,7 +4260,7 @@ void wpa_auth_ml_get_key_info(struct wpa_authenticator *a,
 	info->bigtkidx = gsm->GN_bigtk;
 	info->bigtk = gsm->BIGTK[gsm->GN_bigtk - 6];
 
-	if (wpa_auth_get_seqnum(a, NULL, gsm->GN_bigtk, rsc) < 0)
+	if (rekey || wpa_auth_get_seqnum(a, NULL, gsm->GN_bigtk, rsc) < 0)
 		os_memset(info->bipn, 0, sizeof(info->bipn));
 	else
 		os_memcpy(info->bipn, rsc, sizeof(info->bipn));
@@ -4238,12 +4268,13 @@ void wpa_auth_ml_get_key_info(struct wpa_authenticator *a,
 
 
 static void wpa_auth_get_ml_key_info(struct wpa_authenticator *wpa_auth,
-				     struct wpa_auth_ml_key_info *info)
+				     struct wpa_auth_ml_key_info *info,
+				     bool rekey)
 {
 	if (!wpa_auth->cb->get_ml_key_info)
 		return;
 
-	wpa_auth->cb->get_ml_key_info(wpa_auth->cb_ctx, info);
+	wpa_auth->cb->get_ml_key_info(wpa_auth->cb_ctx, info, rekey);
 }
 
 
@@ -4300,6 +4331,7 @@ static u8 * wpa_auth_ml_group_kdes(struct wpa_state_machine *sm, u8 *pos)
 	struct wpa_auth_ml_key_info ml_key_info;
 	unsigned int i, link_id;
 	u8 *start = pos;
+	bool rekey = sm->wpa_ptk_group_state == WPA_PTK_GROUP_REKEYNEGOTIATING;
 
 	/* First fetch the key information from all the authenticators */
 	os_memset(&ml_key_info, 0, sizeof(ml_key_info));
@@ -4319,7 +4351,7 @@ static u8 * wpa_auth_ml_group_kdes(struct wpa_state_machine *sm, u8 *pos)
 		ml_key_info.links[i++].link_id = link_id;
 	}
 
-	wpa_auth_get_ml_key_info(sm->wpa_auth, &ml_key_info);
+	wpa_auth_get_ml_key_info(sm->wpa_auth, &ml_key_info, rekey);
 
 	/* Add MLO GTK KDEs */
 	for (i = 0, link_id = 0; link_id < MAX_NUM_MLD_LINKS; link_id++) {
@@ -4458,34 +4490,47 @@ static size_t wpa_auth_ml_kdes_len(struct wpa_state_machine *sm)
 	/* For the MAC Address KDE */
 	kde_len = 2 + RSN_SELECTOR_LEN + ETH_ALEN;
 
-	/* MLO Link KDE for each link */
+	/* MLO Link KDE and RSN Override Link KDE for each link */
 	for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; link_id++) {
 		struct wpa_authenticator *wpa_auth;
-		const u8 *ie, *ieo;
+		const u8 *ie;
 
 		wpa_auth = wpa_get_link_auth(sm->wpa_auth, link_id);
 		if (!wpa_auth)
 			continue;
 
+		/* MLO Link KDE */
 		kde_len += 2 + RSN_SELECTOR_LEN + 1 + ETH_ALEN;
+
 		ie = get_ie(wpa_auth->wpa_ie, wpa_auth->wpa_ie_len,
 			    WLAN_EID_RSN);
-		ieo = get_vendor_ie(wpa_auth->wpa_ie, wpa_auth->wpa_ie_len,
-				    sm->rsn_override_2 ?
-				    RSNE_OVERRIDE_2_IE_VENDOR_TYPE :
-				    RSNE_OVERRIDE_IE_VENDOR_TYPE);
-		if ((sm->rsn_override || sm->rsn_override_2) && ieo)
-			kde_len += 2 + ieo[1 - 4];
-		else
+		if (ie)
 			kde_len += 2 + ie[1];
 
 		ie = get_ie(wpa_auth->wpa_ie, wpa_auth->wpa_ie_len,
 			    WLAN_EID_RSNX);
-		ieo = get_vendor_ie(wpa_auth->wpa_ie, wpa_auth->wpa_ie_len,
-				    RSNXE_OVERRIDE_IE_VENDOR_TYPE);
-		if ((sm->rsn_override || sm->rsn_override_2) && ieo)
-			kde_len += 2 + ieo[1] - 4;
-		else if (ie)
+		if (ie)
+			kde_len += 2 + ie[1];
+
+		if (!rsn_is_snonce_cookie(sm->SNonce))
+			continue;
+
+		/* RSN Override Link KDE */
+		kde_len += 2 + RSN_SELECTOR_LEN + 1;
+
+		ie = get_vendor_ie(wpa_auth->wpa_ie, wpa_auth->wpa_ie_len,
+				   RSNE_OVERRIDE_IE_VENDOR_TYPE);
+		if (ie)
+			kde_len += 2 + ie[1];
+
+		ie = get_vendor_ie(wpa_auth->wpa_ie, wpa_auth->wpa_ie_len,
+				   RSNE_OVERRIDE_2_IE_VENDOR_TYPE);
+		if (ie)
+			kde_len += 2 + ie[1];
+
+		ie = get_vendor_ie(wpa_auth->wpa_ie, wpa_auth->wpa_ie_len,
+				   RSNXE_OVERRIDE_IE_VENDOR_TYPE);
+		if (ie)
 			kde_len += 2 + ie[1];
 	}
 
@@ -4511,8 +4556,9 @@ static u8 * wpa_auth_ml_kdes(struct wpa_state_machine *sm, u8 *pos)
 
 	for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; link_id++) {
 		struct wpa_authenticator *wpa_auth;
-		const u8 *rsne, *rsnxe, *rsneo, *rsnxeo;
-		size_t rsne_len, rsnxe_len;
+		const u8 *rsne, *rsnxe, *rsnoe, *rsno2e, *rsnxoe;
+		size_t rsne_len, rsnxe_len, rsnoe_len, rsno2e_len, rsnxoe_len;
+		size_t kde_len;
 
 		wpa_auth = wpa_get_link_auth(sm->wpa_auth, link_id);
 		if (!wpa_auth)
@@ -4521,30 +4567,17 @@ static u8 * wpa_auth_ml_kdes(struct wpa_state_machine *sm, u8 *pos)
 		rsne = get_ie(wpa_auth->wpa_ie, wpa_auth->wpa_ie_len,
 			     WLAN_EID_RSN);
 		rsne_len = rsne ? 2 + rsne[1] : 0;
-		rsneo = get_vendor_ie(wpa_auth->wpa_ie, wpa_auth->wpa_ie_len,
-				      sm->rsn_override_2 ?
-				      RSNE_OVERRIDE_2_IE_VENDOR_TYPE :
-				      RSNE_OVERRIDE_IE_VENDOR_TYPE);
-		if ((sm->rsn_override || sm->rsn_override_2) && rsneo)
-			rsne_len = 2 + rsneo[1] - 4;
-		else
-			rsneo = NULL;
 
 		rsnxe = get_ie(wpa_auth->wpa_ie, wpa_auth->wpa_ie_len,
 			       WLAN_EID_RSNX);
 		rsnxe_len = rsnxe ? 2 + rsnxe[1] : 0;
-		rsnxeo = get_vendor_ie(wpa_auth->wpa_ie, wpa_auth->wpa_ie_len,
-				       RSNXE_OVERRIDE_IE_VENDOR_TYPE);
-		if ((sm->rsn_override || sm->rsn_override_2) && rsnxeo)
-			rsnxe_len = 2 + rsnxeo[1] - 4;
-		else
-			rsnxeo = NULL;
 
 		wpa_printf(MSG_DEBUG,
 			   "RSN: MLO Link: link=%u, len=%zu", link_id,
 			   RSN_SELECTOR_LEN + 1 + ETH_ALEN +
 			   rsne_len + rsnxe_len);
 
+		/* MLO Link KDE */
 		*pos++ = WLAN_EID_VENDOR_SPECIFIC;
 		*pos++ = RSN_SELECTOR_LEN + 1 + ETH_ALEN +
 			rsne_len + rsnxe_len;
@@ -4564,31 +4597,71 @@ static u8 * wpa_auth_ml_kdes(struct wpa_state_machine *sm, u8 *pos)
 		pos += ETH_ALEN;
 
 		if (rsne_len) {
-			if (rsneo) {
-				*pos++ = WLAN_EID_RSN;
-				*pos++ = rsneo[1] - 4;
-				os_memcpy(pos, &rsneo[2 + 4], rsneo[1] - 4);
-				pos += rsneo[1] - 4;
-			} else {
-				os_memcpy(pos, rsne, rsne_len);
-				pos += rsne_len;
-			}
+			os_memcpy(pos, rsne, rsne_len);
+			pos += rsne_len;
 		}
 
 		if (rsnxe_len) {
-			if (rsnxeo) {
-				*pos++ = WLAN_EID_RSNX;
-				*pos++ = rsnxeo[1] - 4;
-				os_memcpy(pos, &rsnxeo[2 + 4], rsnxeo[1] - 4);
-				pos += rsnxeo[1] - 4;
-			} else {
-				os_memcpy(pos, rsnxe, rsnxe_len);
-				pos += rsnxe_len;
-			}
+			os_memcpy(pos, rsnxe, rsnxe_len);
+			pos += rsnxe_len;
+		}
+
+		if (!rsn_is_snonce_cookie(sm->SNonce))
+			continue;
+
+		rsnoe = get_vendor_ie(wpa_auth->wpa_ie, wpa_auth->wpa_ie_len,
+				      RSNE_OVERRIDE_IE_VENDOR_TYPE);
+		rsnoe_len = rsnoe ? 2 + rsnoe[1] : 0;
+
+		rsno2e = get_vendor_ie(wpa_auth->wpa_ie, wpa_auth->wpa_ie_len,
+				       RSNE_OVERRIDE_2_IE_VENDOR_TYPE);
+		rsno2e_len = rsno2e ? 2 + rsno2e[1] : 0;
+
+		rsnxoe = get_vendor_ie(wpa_auth->wpa_ie, wpa_auth->wpa_ie_len,
+				       RSNXE_OVERRIDE_IE_VENDOR_TYPE);
+		rsnxoe_len = rsnxoe ? 2 + rsnxoe[1] : 0;
+
+		wpa_printf(MSG_DEBUG,
+			   "RSN: RSN Override Link KDE: link=%u, len=%zu",
+			   link_id, RSN_SELECTOR_LEN + rsnoe_len + rsno2e_len +
+			   rsnxoe_len);
+
+		/* RSN Override Link KDE */
+		*pos++ = WLAN_EID_VENDOR_SPECIFIC;
+		kde_len = RSN_SELECTOR_LEN + 1 + rsnoe_len + rsno2e_len +
+			rsnxoe_len;
+		if (kde_len > 255) {
+			wpa_printf(MSG_ERROR,
+				   "RSN: RSNOE/RSNO2E/RSNXOE too long (KDE length %zu) to fit in RSN Override Link KDE for link %u",
+				   kde_len, link_id);
+			return NULL;
+		}
+		*pos++ = kde_len;
+
+		RSN_SELECTOR_PUT(pos, WFA_KEY_DATA_RSN_OVERRIDE_LINK);
+		pos += RSN_SELECTOR_LEN;
+
+		*pos++ = link_id;
+
+		if (rsnoe_len) {
+			os_memcpy(pos, rsnoe, rsnoe_len);
+			pos += rsnoe_len;
+		}
+
+		if (rsno2e_len) {
+			os_memcpy(pos, rsno2e, rsno2e_len);
+			pos += rsno2e_len;
+		}
+
+		if (rsnxoe_len) {
+			os_memcpy(pos, rsnxoe, rsnxoe_len);
+			pos += rsnxoe_len;
 		}
 	}
 
-	wpa_printf(MSG_DEBUG, "RSN: MLO Link KDE len = %ld", pos - start);
+	wpa_printf(MSG_DEBUG,
+		   "RSN: MLO Link KDEs and RSN Override Link KDEs len = %ld",
+		   pos - start);
 	pos = wpa_auth_ml_group_kdes(sm, pos);
 #endif /* CONFIG_IEEE80211BE */
 
@@ -4644,77 +4717,36 @@ SM_STATE(WPA_PTK, PTKINITNEGOTIATING)
 			wpa_ie = wpa_ie + wpa_ie[1] + 2;
 		wpa_ie_len = wpa_ie[1] + 2;
 	}
-	if ((sm->rsn_override &&
-	     get_vendor_ie(wpa_ie, wpa_ie_len, RSNE_OVERRIDE_IE_VENDOR_TYPE)) ||
-	    (sm->rsn_override_2 &&
-	     get_vendor_ie(wpa_ie, wpa_ie_len,
-			   RSNE_OVERRIDE_2_IE_VENDOR_TYPE))) {
-		const u8 *mde, *fte, *tie, *tie2 = NULL;
-		const u8 *override_rsne = NULL, *override_rsnxe = NULL;
-		const struct element *elem;
+	if ((conf->rsn_override_key_mgmt || conf->rsn_override_key_mgmt_2) &&
+	    !rsn_is_snonce_cookie(sm->SNonce)) {
+		u8 *ie;
+		size_t ie_len;
+		u32 ids[] = {
+			RSNE_OVERRIDE_IE_VENDOR_TYPE,
+			RSNE_OVERRIDE_2_IE_VENDOR_TYPE,
+			RSNXE_OVERRIDE_IE_VENDOR_TYPE,
+			0
+		};
+		int i;
 
 		wpa_printf(MSG_DEBUG,
-			   "RSN: Use RSNE/RSNXE override element contents");
-		mde = get_ie(wpa_ie, wpa_ie_len, WLAN_EID_MOBILITY_DOMAIN);
-		fte = get_ie(wpa_ie, wpa_ie_len, WLAN_EID_FAST_BSS_TRANSITION);
-		tie = get_ie(wpa_ie, wpa_ie_len, WLAN_EID_TIMEOUT_INTERVAL);
-		if (tie) {
-			const u8 *next = tie + 2 + tie[1];
-
-			tie2 = get_ie(next, wpa_ie + wpa_ie_len - next,
-				      WLAN_EID_TIMEOUT_INTERVAL);
-		}
-		for_each_element_id(elem, WLAN_EID_VENDOR_SPECIFIC,
-				    wpa_ie, wpa_ie_len) {
-			if (elem->datalen >= 4) {
-				if (WPA_GET_BE32(elem->data) ==
-				    (sm->rsn_override_2 ?
-				     RSNE_OVERRIDE_2_IE_VENDOR_TYPE :
-				     RSNE_OVERRIDE_IE_VENDOR_TYPE))
-					override_rsne = &elem->id;
-				if (WPA_GET_BE32(elem->data) ==
-				    RSNXE_OVERRIDE_IE_VENDOR_TYPE)
-					override_rsnxe = &elem->id;
-			}
-		}
+			   "RSN: Remove RSNE/RSNXE override elements");
 		wpa_hexdump(MSG_DEBUG, "EAPOL-Key msg 3/4 IEs before edits",
 			    wpa_ie, wpa_ie_len);
-		wpa_ie_buf3 = os_malloc(wpa_ie_len);
+		wpa_ie_buf3 = os_memdup(wpa_ie, wpa_ie_len);
 		if (!wpa_ie_buf3)
 			goto done;
-		pos = wpa_ie_buf3;
-		if (override_rsne) {
-			*pos++ = WLAN_EID_RSN;
-			*pos++ = override_rsne[1] - 4;
-			os_memcpy(pos, &override_rsne[2 + 4],
-				  override_rsne[1] - 4);
-			pos += override_rsne[1] - 4;
-		}
-		if (mde) {
-			os_memcpy(pos, mde, 2 + mde[1]);
-			pos += 2 + mde[1];
-		}
-		if (fte) {
-			os_memcpy(pos, fte, 2 + fte[1]);
-			pos += 2 + fte[1];
-		}
-		if (tie) {
-			os_memcpy(pos, tie, 2 + tie[1]);
-			pos += 2 + tie[1];
-		}
-		if (tie2) {
-			os_memcpy(pos, tie2, 2 + tie2[1]);
-			pos += 2 + tie2[1];
-		}
-		if (override_rsnxe) {
-			*pos++ = WLAN_EID_RSNX;
-			*pos++ = override_rsnxe[1] - 4;
-			os_memcpy(pos, &override_rsnxe[2 + 4],
-				  override_rsnxe[1] - 4);
-			pos += override_rsnxe[1] - 4;
-		}
 		wpa_ie = wpa_ie_buf3;
-		wpa_ie_len = pos - wpa_ie_buf3;
+
+		for (i = 0; ids[i]; i++) {
+			ie = (u8 *) get_vendor_ie(wpa_ie, wpa_ie_len, ids[i]);
+			if (ie) {
+				ie_len = 2 + ie[1];
+				os_memmove(ie, ie + ie_len,
+					   wpa_ie_len - (ie + ie_len - wpa_ie));
+				wpa_ie_len -= ie_len;
+			}
+		}
 		wpa_hexdump(MSG_DEBUG, "EAPOL-Key msg 3/4 IEs after edits",
 			    wpa_ie, wpa_ie_len);
 	}
@@ -4957,6 +4989,10 @@ SM_STATE(WPA_PTK, PTKINITNEGOTIATING)
 #endif /* CONFIG_DPP2 */
 
 	pos = wpa_auth_ml_kdes(sm, pos);
+	if (!pos) {
+		wpa_printf(MSG_ERROR, "RSN: Failed to add MLO KDEs");
+		goto done;
+	}
 
 	if (sm->ssid_protection) {
 		*pos++ = WLAN_EID_SSID;
@@ -5601,11 +5637,38 @@ static void wpa_group_gtk_init(struct wpa_authenticator *wpa_auth,
 
 static int wpa_group_update_sta(struct wpa_state_machine *sm, void *ctx)
 {
-	if (ctx != NULL && ctx != sm->group)
+	struct wpa_authenticator *wpa_auth = sm->wpa_auth;
+	struct wpa_group *group = sm->group;
+#ifdef CONFIG_IEEE80211BE
+	int link_id;
+
+	for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; link_id++) {
+		if (!sm->mld_links[link_id].valid)
+			continue;
+		if (sm->mld_links[link_id].wpa_auth &&
+		    sm->mld_links[link_id].wpa_auth->group == ctx) {
+			group = sm->mld_links[link_id].wpa_auth->group;
+			wpa_auth = sm->mld_links[link_id].wpa_auth;
+			break;
+		}
+	}
+#endif /* CONFIG_IEEE80211BE */
+
+	if (ctx && ctx != group)
 		return 0;
 
+#ifdef CONFIG_IEEE80211BE
+	/* For ML STA, run rekey on the association link and send G1 with keys
+	 * for all links. This is based on assumption that MLD level
+	 * Authenticator updates group keys on all affiliated links in one shot
+	 * and not independently or concurrently for separate links. */
+	if (sm->mld_assoc_link_id >= 0 &&
+	    sm->mld_assoc_link_id != wpa_auth->link_id)
+		return 0;
+#endif /* CONFIG_IEEE80211BE */
+
 	if (sm->wpa_ptk_state != WPA_PTK_PTKINITDONE) {
-		wpa_auth_logger(sm->wpa_auth, wpa_auth_get_spa(sm),
+		wpa_auth_logger(wpa_auth, wpa_auth_get_spa(sm),
 				LOGGER_DEBUG,
 				"Not in PTKINITDONE; skip Group Key update");
 		sm->GUpdateStationKeys = false;
@@ -5617,7 +5680,7 @@ static int wpa_group_update_sta(struct wpa_state_machine *sm, void *ctx)
 		 * Since we clear the GKeyDoneStations before the loop, the
 		 * station needs to be counted here anyway.
 		 */
-		wpa_auth_logger(sm->wpa_auth, wpa_auth_get_spa(sm),
+		wpa_auth_logger(wpa_auth, wpa_auth_get_spa(sm),
 				LOGGER_DEBUG,
 				"GUpdateStationKeys was already set when marking station for GTK rekeying");
 	}
@@ -5627,6 +5690,11 @@ static int wpa_group_update_sta(struct wpa_state_machine *sm, void *ctx)
 		return 0;
 
 	sm->group->GKeyDoneStations++;
+#ifdef CONFIG_IEEE80211BE
+	for_each_sm_auth(sm, link_id)
+		sm->mld_links[link_id].wpa_auth->group->GKeyDoneStations++;
+#endif /* CONFIG_IEEE80211BE */
+
 	sm->GUpdateStationKeys = true;
 
 	wpa_sm_step(sm);
@@ -6939,17 +7007,27 @@ void wpa_auth_set_auth_alg(struct wpa_state_machine *sm, u16 auth_alg)
 }
 
 
-void wpa_auth_set_rsn_override(struct wpa_state_machine *sm, bool val)
+void wpa_auth_set_rsn_selection(struct wpa_state_machine *sm, const u8 *ie,
+				size_t len)
 {
-	if (sm)
-		sm->rsn_override = val;
-}
-
-
-void wpa_auth_set_rsn_override_2(struct wpa_state_machine *sm, bool val)
-{
-	if (sm)
-		sm->rsn_override_2 = val;
+	if (!sm)
+		return;
+	os_free(sm->rsn_selection);
+	sm->rsn_selection = NULL;
+	sm->rsn_selection_len = 0;
+	sm->rsn_override = false;
+	sm->rsn_override_2 = false;
+	if (ie) {
+		if (len >=  1) {
+			if (ie[0] == RSN_SELECTION_RSNE_OVERRIDE)
+				sm->rsn_override = true;
+			else if (ie[0] == RSN_SELECTION_RSNE_OVERRIDE_2)
+				sm->rsn_override_2 = true;
+		}
+		sm->rsn_selection = os_memdup(ie, len);
+		if (sm->rsn_selection)
+			sm->rsn_selection_len = len;
+	}
 }
 
 
diff --git a/src/ap/wpa_auth.h b/src/ap/wpa_auth.h
index 86cb4e85..0b692ada 100644
--- a/src/ap/wpa_auth.h
+++ b/src/ap/wpa_auth.h
@@ -17,7 +17,7 @@
 struct vlan_description;
 struct mld_info;
 
-#define MAX_OWN_IE_OVERRIDE 256
+#define MAX_OWN_IE_OVERRIDE 257
 
 #ifdef _MSC_VER
 #pragma pack(push, 1)
@@ -230,6 +230,21 @@ struct wpa_auth_config {
 	double corrupt_gtk_rekey_mic_probability;
 	u8 own_ie_override[MAX_OWN_IE_OVERRIDE];
 	size_t own_ie_override_len;
+	bool rsne_override_set;
+	u8 rsne_override[MAX_OWN_IE_OVERRIDE];
+	size_t rsne_override_len;
+	bool rsnoe_override_set;
+	u8 rsnoe_override[MAX_OWN_IE_OVERRIDE];
+	size_t rsnoe_override_len;
+	bool rsno2e_override_set;
+	u8 rsno2e_override[MAX_OWN_IE_OVERRIDE];
+	size_t rsno2e_override_len;
+	bool rsnxe_override_set;
+	u8 rsnxe_override[MAX_OWN_IE_OVERRIDE];
+	size_t rsnxe_override_len;
+	bool rsnxoe_override_set;
+	u8 rsnxoe_override[MAX_OWN_IE_OVERRIDE];
+	size_t rsnxoe_override_len;
 	u8 rsne_override_eapol[MAX_OWN_IE_OVERRIDE];
 	size_t rsne_override_eapol_len;
 	u8 rsnxe_override_eapol[MAX_OWN_IE_OVERRIDE];
@@ -253,6 +268,7 @@ struct wpa_auth_config {
 	struct wpabuf *eapol_m1_elements;
 	struct wpabuf *eapol_m3_elements;
 	bool eapol_m3_no_encrypt;
+	bool eapol_key_reserved_random;
 #endif /* CONFIG_TESTING_OPTIONS */
 	unsigned int oci_freq_override_eapol_m3;
 	unsigned int oci_freq_override_eapol_g1;
@@ -303,6 +319,8 @@ struct wpa_auth_config {
 #endif /* CONFIG_IEEE80211BE */
 
 	bool ssid_protection;
+
+	int rsn_override_omit_rsnxe;
 };
 
 typedef enum {
@@ -408,7 +426,8 @@ struct wpa_auth_callbacks {
 			       size_t ltf_keyseed_len);
 #endif /* CONFIG_PASN */
 #ifdef CONFIG_IEEE80211BE
-	int (*get_ml_key_info)(void *ctx, struct wpa_auth_ml_key_info *info);
+	int (*get_ml_key_info)(void *ctx, struct wpa_auth_ml_key_info *info,
+			       bool rekey);
 #endif /* CONFIG_IEEE80211BE */
 	int (*get_drv_flags)(void *ctx, u64 *drv_flags, u64 *drv_flags2);
 };
@@ -613,8 +632,8 @@ u8 * wpa_auth_write_assoc_resp_fils(struct wpa_state_machine *sm,
 bool wpa_auth_write_fd_rsn_info(struct wpa_authenticator *wpa_auth,
 				u8 *fd_rsn_info);
 void wpa_auth_set_auth_alg(struct wpa_state_machine *sm, u16 auth_alg);
-void wpa_auth_set_rsn_override(struct wpa_state_machine *sm, bool val);
-void wpa_auth_set_rsn_override_2(struct wpa_state_machine *sm, bool val);
+void wpa_auth_set_rsn_selection(struct wpa_state_machine *sm, const u8 *ie,
+				size_t len);
 void wpa_auth_set_dpp_z(struct wpa_state_machine *sm, const struct wpabuf *z);
 void wpa_auth_set_ssid_protection(struct wpa_state_machine *sm, bool val);
 void wpa_auth_set_transition_disable(struct wpa_authenticator *wpa_auth,
@@ -658,7 +677,8 @@ void wpa_auth_set_ml_info(struct wpa_state_machine *sm,
 			  u8 mld_assoc_link_id, struct mld_info *info);
 void wpa_auth_ml_get_key_info(struct wpa_authenticator *a,
 			      struct wpa_auth_ml_link_key_info *info,
-			      bool mgmt_frame_prot, bool beacon_prot);
+			      bool mgmt_frame_prot, bool beacon_prot,
+			      bool rekey);
 
 void wpa_release_link_auth_ref(struct wpa_state_machine *sm,
 			       int release_link_id);
diff --git a/src/ap/wpa_auth_glue.c b/src/ap/wpa_auth_glue.c
index e88644fe..2323a599 100644
--- a/src/ap/wpa_auth_glue.c
+++ b/src/ap/wpa_auth_glue.c
@@ -132,6 +132,46 @@ static void hostapd_wpa_auth_conf(struct hostapd_bss_config *conf,
 			  wpabuf_head(conf->own_ie_override),
 			  wconf->own_ie_override_len);
 	}
+	if (conf->rsne_override &&
+	    wpabuf_len(conf->rsne_override) <= MAX_OWN_IE_OVERRIDE) {
+		wconf->rsne_override_len = wpabuf_len(conf->rsne_override);
+		os_memcpy(wconf->rsne_override,
+			  wpabuf_head(conf->rsne_override),
+			  wconf->rsne_override_len);
+		wconf->rsne_override_set = true;
+	}
+	if (conf->rsnoe_override &&
+	    wpabuf_len(conf->rsnoe_override) <= MAX_OWN_IE_OVERRIDE) {
+		wconf->rsnoe_override_len = wpabuf_len(conf->rsnoe_override);
+		os_memcpy(wconf->rsnoe_override,
+			  wpabuf_head(conf->rsnoe_override),
+			  wconf->rsnoe_override_len);
+		wconf->rsnoe_override_set = true;
+	}
+	if (conf->rsno2e_override &&
+	    wpabuf_len(conf->rsno2e_override) <= MAX_OWN_IE_OVERRIDE) {
+		wconf->rsno2e_override_len = wpabuf_len(conf->rsno2e_override);
+		os_memcpy(wconf->rsno2e_override,
+			  wpabuf_head(conf->rsno2e_override),
+			  wconf->rsno2e_override_len);
+		wconf->rsno2e_override_set = true;
+	}
+	if (conf->rsnxe_override &&
+	    wpabuf_len(conf->rsnxe_override) <= MAX_OWN_IE_OVERRIDE) {
+		wconf->rsnxe_override_len = wpabuf_len(conf->rsnxe_override);
+		os_memcpy(wconf->rsnxe_override,
+			  wpabuf_head(conf->rsnxe_override),
+			  wconf->rsnxe_override_len);
+		wconf->rsnxe_override_set = true;
+	}
+	if (conf->rsnxoe_override &&
+	    wpabuf_len(conf->rsnxoe_override) <= MAX_OWN_IE_OVERRIDE) {
+		wconf->rsnxoe_override_len = wpabuf_len(conf->rsnxoe_override);
+		os_memcpy(wconf->rsnxoe_override,
+			  wpabuf_head(conf->rsnxoe_override),
+			  wconf->rsnxoe_override_len);
+		wconf->rsnxoe_override_set = true;
+	}
 	if (conf->rsne_override_eapol &&
 	    wpabuf_len(conf->rsne_override_eapol) <= MAX_OWN_IE_OVERRIDE) {
 		wconf->rsne_override_eapol_set = 1;
@@ -199,6 +239,7 @@ static void hostapd_wpa_auth_conf(struct hostapd_bss_config *conf,
 	if (conf->eapol_m3_elements)
 		wconf->eapol_m3_elements = wpabuf_dup(conf->eapol_m3_elements);
 	wconf->eapol_m3_no_encrypt = conf->eapol_m3_no_encrypt;
+	wconf->eapol_key_reserved_random = conf->eapol_key_reserved_random;
 #endif /* CONFIG_TESTING_OPTIONS */
 #ifdef CONFIG_P2P
 	os_memcpy(wconf->ip_addr_go, conf->ip_addr_go, 4);
@@ -237,6 +278,8 @@ static void hostapd_wpa_auth_conf(struct hostapd_bss_config *conf,
 	wconf->no_disconnect_on_group_keyerror =
 		conf->bss_max_idle && conf->ap_max_inactivity &&
 		conf->no_disconnect_on_group_keyerror;
+
+	wconf->rsn_override_omit_rsnxe = conf->rsn_override_omit_rsnxe;
 }
 
 
@@ -1547,7 +1590,8 @@ static int hostapd_set_ltf_keyseed(void *ctx, const u8 *peer_addr,
 #ifdef CONFIG_IEEE80211BE
 
 static int hostapd_wpa_auth_get_ml_key_info(void *ctx,
-					    struct wpa_auth_ml_key_info *info)
+					    struct wpa_auth_ml_key_info *info,
+					    bool rekey)
 {
 	struct hostapd_data *hapd = ctx;
 	unsigned int i;
@@ -1571,7 +1615,8 @@ static int hostapd_wpa_auth_get_ml_key_info(void *ctx,
 			wpa_auth_ml_get_key_info(hapd->wpa_auth,
 						 &info->links[i],
 						 info->mgmt_frame_prot,
-						 info->beacon_prot);
+						 info->beacon_prot,
+						 rekey);
 			continue;
 		}
 
@@ -1582,7 +1627,8 @@ static int hostapd_wpa_auth_get_ml_key_info(void *ctx,
 			wpa_auth_ml_get_key_info(bss->wpa_auth,
 						 &info->links[i],
 						 info->mgmt_frame_prot,
-						 info->beacon_prot);
+						 info->beacon_prot,
+						 rekey);
 			link_bss_found = true;
 			break;
 		}
diff --git a/src/ap/wpa_auth_i.h b/src/ap/wpa_auth_i.h
index 29988c27..cb902e42 100644
--- a/src/ap/wpa_auth_i.h
+++ b/src/ap/wpa_auth_i.h
@@ -111,6 +111,8 @@ struct wpa_state_machine {
 	size_t wpa_ie_len;
 	u8 *rsnxe;
 	size_t rsnxe_len;
+	u8 *rsn_selection;
+	size_t rsn_selection_len;
 
 	enum {
 		WPA_VERSION_NO_WPA = 0 /* WPA not used */,
@@ -251,9 +253,6 @@ struct wpa_authenticator {
 
 	u8 *wpa_ie;
 	size_t wpa_ie_len;
-	u8 *rsne_override; /* RSNE with overridden payload */
-	u8 *rsne_override_2; /* RSNE with overridden (2) payload */
-	u8 *rsnxe_override; /* RSNXE with overridden payload */
 
 	u8 addr[ETH_ALEN];
 
diff --git a/src/ap/wpa_auth_ie.c b/src/ap/wpa_auth_ie.c
index f4f9cc8a..43d9c1d3 100644
--- a/src/ap/wpa_auth_ie.c
+++ b/src/ap/wpa_auth_ie.c
@@ -547,15 +547,20 @@ static int wpa_write_rsnxe_override(struct wpa_auth_config *conf, u8 *buf,
 				    size_t len)
 {
 	u8 *pos = buf;
-	u16 capab;
+	u32 capab, tmp;
 	size_t flen;
 
 	capab = rsnxe_capab(conf, conf->rsn_override_key_mgmt |
 			    conf->rsn_override_key_mgmt_2);
 
-	flen = (capab & 0xff00) ? 2 : 1;
 	if (!capab)
 		return 0; /* no supported extended RSN capabilities */
+	tmp = capab;
+	flen = 0;
+	while (tmp) {
+		flen++;
+		tmp >>= 8;
+	}
 	if (len < 2 + flen)
 		return -1;
 	capab |= flen - 1; /* bit 0-3 = Field length (n - 1) */
@@ -565,10 +570,10 @@ static int wpa_write_rsnxe_override(struct wpa_auth_config *conf, u8 *buf,
 	WPA_PUT_BE32(pos, RSNXE_OVERRIDE_IE_VENDOR_TYPE);
 	pos += 4;
 
-	*pos++ = capab & 0x00ff;
-	capab >>= 8;
-	if (capab)
-		*pos++ = capab;
+	while (capab) {
+		*pos++ = capab & 0xff;
+		capab >>= 8;
+	}
 
 	return pos - buf;
 }
@@ -627,7 +632,7 @@ static u8 * wpa_write_osen(struct wpa_auth_config *conf, u8 *eid)
 
 int wpa_auth_gen_wpa_ie(struct wpa_authenticator *wpa_auth)
 {
-	u8 *pos, buf[256];
+	u8 *pos, buf[1500];
 	int res;
 
 #ifdef CONFIG_TESTING_OPTIONS
@@ -653,17 +658,54 @@ int wpa_auth_gen_wpa_ie(struct wpa_authenticator *wpa_auth)
 		pos = wpa_write_osen(&wpa_auth->conf, pos);
 	}
 	if (wpa_auth->conf.wpa & WPA_PROTO_RSN) {
+#ifdef CONFIG_TESTING_OPTIONS
+		if (wpa_auth->conf.rsne_override_set) {
+			wpa_hexdump(MSG_DEBUG,
+				    "RSN: Forced own RSNE for testing",
+				    wpa_auth->conf.rsne_override,
+				    wpa_auth->conf.rsne_override_len);
+			if (sizeof(buf) - (pos - buf) <
+			    wpa_auth->conf.rsne_override_len)
+				return -1;
+			os_memcpy(pos, wpa_auth->conf.rsne_override,
+				  wpa_auth->conf.rsne_override_len);
+			pos += wpa_auth->conf.rsne_override_len;
+			goto rsnxe;
+		}
+#endif /* CONFIG_TESTING_OPTIONS */
 		res = wpa_write_rsn_ie(&wpa_auth->conf,
 				       pos, buf + sizeof(buf) - pos, NULL);
 		if (res < 0)
 			return res;
 		pos += res;
-		res = wpa_write_rsnxe(&wpa_auth->conf, pos,
-				      buf + sizeof(buf) - pos);
+#ifdef CONFIG_TESTING_OPTIONS
+	rsnxe:
+		if (wpa_auth->conf.rsnxe_override_set) {
+			wpa_hexdump(MSG_DEBUG,
+				    "RSN: Forced own RSNXE for testing",
+				    wpa_auth->conf.rsnxe_override,
+				    wpa_auth->conf.rsnxe_override_len);
+			if (sizeof(buf) - (pos - buf) <
+			    wpa_auth->conf.rsnxe_override_len)
+				return -1;
+			os_memcpy(pos, wpa_auth->conf.rsnxe_override,
+				  wpa_auth->conf.rsnxe_override_len);
+			pos += wpa_auth->conf.rsnxe_override_len;
+			goto fte;
+		}
+#endif /* CONFIG_TESTING_OPTIONS */
+		if (wpa_auth->conf.rsn_override_omit_rsnxe)
+			res = 0;
+		else
+			res = wpa_write_rsnxe(&wpa_auth->conf, pos,
+					      buf + sizeof(buf) - pos);
 		if (res < 0)
 			return res;
 		pos += res;
 	}
+#ifdef CONFIG_TESTING_OPTIONS
+fte:
+#endif /* CONFIG_TESTING_OPTIONS */
 #ifdef CONFIG_IEEE80211R_AP
 	if (wpa_key_mgmt_ft(wpa_auth->conf.wpa_key_mgmt)) {
 		res = wpa_write_mdie(&wpa_auth->conf, pos,
@@ -682,30 +724,85 @@ int wpa_auth_gen_wpa_ie(struct wpa_authenticator *wpa_auth)
 	}
 	if ((wpa_auth->conf.wpa & WPA_PROTO_RSN) &&
 	    wpa_auth->conf.rsn_override_key_mgmt) {
+#ifdef CONFIG_TESTING_OPTIONS
+		if (wpa_auth->conf.rsnoe_override_set) {
+			wpa_hexdump(MSG_DEBUG,
+				    "RSN: Forced own RSNOE for testing",
+				    wpa_auth->conf.rsnoe_override,
+				    wpa_auth->conf.rsnoe_override_len);
+			if (sizeof(buf) - (pos - buf) <
+			    wpa_auth->conf.rsnoe_override_len)
+				return -1;
+			os_memcpy(pos, wpa_auth->conf.rsnoe_override,
+				  wpa_auth->conf.rsnoe_override_len);
+			pos += wpa_auth->conf.rsnoe_override_len;
+			goto rsno2e;
+		}
+#endif /* CONFIG_TESTING_OPTIONS */
 		res = wpa_write_rsne_override(&wpa_auth->conf,
 					      pos, buf + sizeof(buf) - pos);
 		if (res < 0)
 			return res;
 		pos += res;
 	}
+#ifdef CONFIG_TESTING_OPTIONS
+rsno2e:
+#endif /* CONFIG_TESTING_OPTIONS */
 	if ((wpa_auth->conf.wpa & WPA_PROTO_RSN) &&
 	    wpa_auth->conf.rsn_override_key_mgmt_2) {
+#ifdef CONFIG_TESTING_OPTIONS
+		if (wpa_auth->conf.rsno2e_override_set) {
+			wpa_hexdump(MSG_DEBUG,
+				    "RSN: Forced own RSNO2E for testing",
+				    wpa_auth->conf.rsno2e_override,
+				    wpa_auth->conf.rsno2e_override_len);
+			if (sizeof(buf) - (pos - buf) <
+			    wpa_auth->conf.rsno2e_override_len)
+				return -1;
+			os_memcpy(pos, wpa_auth->conf.rsno2e_override,
+				  wpa_auth->conf.rsno2e_override_len);
+			pos += wpa_auth->conf.rsno2e_override_len;
+			goto rsnxoe;
+		}
+#endif /* CONFIG_TESTING_OPTIONS */
 		res = wpa_write_rsne_override_2(&wpa_auth->conf, pos,
 						buf + sizeof(buf) - pos);
 		if (res < 0)
 			return res;
 		pos += res;
 	}
+#ifdef CONFIG_TESTING_OPTIONS
+rsnxoe:
+#endif /* CONFIG_TESTING_OPTIONS */
 	if ((wpa_auth->conf.wpa & WPA_PROTO_RSN) &&
 	    (wpa_auth->conf.rsn_override_key_mgmt ||
 	     wpa_auth->conf.rsn_override_key_mgmt_2)) {
+#ifdef CONFIG_TESTING_OPTIONS
+		if (wpa_auth->conf.rsnxoe_override_set) {
+			wpa_hexdump(MSG_DEBUG,
+				    "RSN: Forced own RSNXOE for testing",
+				    wpa_auth->conf.rsnxoe_override,
+				    wpa_auth->conf.rsnxoe_override_len);
+			if (sizeof(buf) - (pos - buf) <
+			    wpa_auth->conf.rsnxoe_override_len)
+				return -1;
+			os_memcpy(pos, wpa_auth->conf.rsnxoe_override,
+				  wpa_auth->conf.rsnxoe_override_len);
+			pos += wpa_auth->conf.rsnxoe_override_len;
+			goto done;
+		}
+#endif /* CONFIG_TESTING_OPTIONS */
 		res = wpa_write_rsnxe_override(&wpa_auth->conf, pos,
 					       buf + sizeof(buf) - pos);
 		if (res < 0)
 			return res;
 		pos += res;
 	}
+#ifdef CONFIG_TESTING_OPTIONS
+done:
+#endif /* CONFIG_TESTING_OPTIONS */
 
+	wpa_hexdump(MSG_DEBUG, "RSN: Own IEs", buf, pos - buf);
 	os_free(wpa_auth->wpa_ie);
 	wpa_auth->wpa_ie = os_malloc(pos - buf);
 	if (wpa_auth->wpa_ie == NULL)
@@ -713,59 +810,6 @@ int wpa_auth_gen_wpa_ie(struct wpa_authenticator *wpa_auth)
 	os_memcpy(wpa_auth->wpa_ie, buf, pos - buf);
 	wpa_auth->wpa_ie_len = pos - buf;
 
-	if ((wpa_auth->conf.wpa & WPA_PROTO_RSN) &&
-	    wpa_auth->conf.rsn_override_key_mgmt) {
-		res = wpa_write_rsne_override(&wpa_auth->conf, buf,
-					      sizeof(buf));
-		if (res < 0)
-			return res;
-		os_free(wpa_auth->rsne_override);
-		wpa_auth->rsne_override = os_malloc(res - 4);
-		if (!wpa_auth->rsne_override)
-			return -1;
-		pos = wpa_auth->rsne_override;
-		*pos++ = WLAN_EID_RSN;
-		*pos++ = res - 2 - 4;
-		os_memcpy(pos, &buf[2 + 4], res - 2 - 4);
-	}
-
-	if ((wpa_auth->conf.wpa & WPA_PROTO_RSN) &&
-	    wpa_auth->conf.rsn_override_key_mgmt_2) {
-		res = wpa_write_rsne_override_2(&wpa_auth->conf, buf,
-						sizeof(buf));
-		if (res < 0)
-			return res;
-		os_free(wpa_auth->rsne_override_2);
-		wpa_auth->rsne_override_2 = os_malloc(res - 4);
-		if (!wpa_auth->rsne_override_2)
-			return -1;
-		pos = wpa_auth->rsne_override_2;
-		*pos++ = WLAN_EID_RSN;
-		*pos++ = res - 2 - 4;
-		os_memcpy(pos, &buf[2 + 4], res - 2 - 4);
-	}
-
-	if ((wpa_auth->conf.wpa & WPA_PROTO_RSN) &&
-	    (wpa_auth->conf.rsn_override_key_mgmt ||
-	     wpa_auth->conf.rsn_override_key_mgmt_2)) {
-		res = wpa_write_rsnxe_override(&wpa_auth->conf, buf,
-					       sizeof(buf));
-		if (res < 0)
-			return res;
-		os_free(wpa_auth->rsnxe_override);
-		if (res == 0) {
-			wpa_auth->rsnxe_override = NULL;
-			return 0;
-		}
-		wpa_auth->rsnxe_override = os_malloc(res - 4);
-		if (!wpa_auth->rsnxe_override)
-			return -1;
-		pos = wpa_auth->rsnxe_override;
-		*pos++ = WLAN_EID_RSNX;
-		*pos++ = res - 2 - 4;
-		os_memcpy(pos, &buf[2 + 4], res - 2 - 4);
-	}
-
 	return 0;
 }
 
@@ -970,9 +1014,13 @@ wpa_validate_wpa_ie(struct wpa_authenticator *wpa_auth,
 		return WPA_INVALID_GROUP;
 	}
 
-	key_mgmt = data.key_mgmt & (wpa_auth->conf.wpa_key_mgmt |
-				    wpa_auth->conf.rsn_override_key_mgmt |
-				    wpa_auth->conf.rsn_override_key_mgmt_2);
+	if (sm->rsn_override_2)
+		key_mgmt = data.key_mgmt &
+			wpa_auth->conf.rsn_override_key_mgmt_2;
+	else if (sm->rsn_override)
+		key_mgmt = data.key_mgmt & wpa_auth->conf.rsn_override_key_mgmt;
+	else
+		key_mgmt = data.key_mgmt & wpa_auth->conf.wpa_key_mgmt;
 	if (!key_mgmt) {
 		wpa_printf(MSG_DEBUG, "Invalid WPA key mgmt (0x%x) from "
 			   MACSTR, data.key_mgmt, MAC2STR(sm->addr));
@@ -1041,11 +1089,14 @@ wpa_validate_wpa_ie(struct wpa_authenticator *wpa_auth,
 	else
 		sm->wpa_key_mgmt = WPA_KEY_MGMT_PSK;
 
-	if (version == WPA_PROTO_RSN)
+	if (version == WPA_PROTO_RSN && sm->rsn_override_2)
+		ciphers = data.pairwise_cipher &
+			wpa_auth->conf.rsn_override_pairwise_2;
+	else if (version == WPA_PROTO_RSN && sm->rsn_override)
 		ciphers = data.pairwise_cipher &
-			(wpa_auth->conf.rsn_pairwise |
-			 wpa_auth->conf.rsn_override_pairwise |
-			 wpa_auth->conf.rsn_override_pairwise_2);
+			wpa_auth->conf.rsn_override_pairwise;
+	else if (version == WPA_PROTO_RSN)
+		ciphers = data.pairwise_cipher & wpa_auth->conf.rsn_pairwise;
 	else
 		ciphers = data.pairwise_cipher & wpa_auth->conf.wpa_pairwise;
 	if (!ciphers) {
diff --git a/src/common/common_module_tests.c b/src/common/common_module_tests.c
index a95ae36d..5763c51f 100644
--- a/src/common/common_module_tests.c
+++ b/src/common/common_module_tests.c
@@ -651,7 +651,7 @@ static int pasn_test_pasn_auth(void)
 			      spa_addr, bssid,
 			      dhss, sizeof(dhss),
 			      &ptk, WPA_KEY_MGMT_PASN, WPA_CIPHER_CCMP,
-			      WPA_KDK_MAX_LEN);
+			      WPA_KDK_MAX_LEN, 0);
 
 	if (ret)
 		return ret;
diff --git a/src/common/defs.h b/src/common/defs.h
index 48d5d3c9..754c4e4c 100644
--- a/src/common/defs.h
+++ b/src/common/defs.h
@@ -537,4 +537,9 @@ enum sae_pwe {
 	SAE_PWE_NOT_SET = 4,
 };
 
+#define USEC_80211_TU 1024
+
+#define USEC_TO_TU(m) ((m) / USEC_80211_TU)
+#define TU_TO_USEC(m) ((m) * USEC_80211_TU)
+
 #endif /* DEFS_H */
diff --git a/src/common/dpp.c b/src/common/dpp.c
index 02c32dc7..46f2551e 100644
--- a/src/common/dpp.c
+++ b/src/common/dpp.c
@@ -1035,6 +1035,10 @@ struct wpabuf * dpp_build_conf_req_helper(struct dpp_authentication *auth,
 		json_value_sep(json);
 		json_add_string(json, "pkcs10", csr);
 	}
+#ifdef CONFIG_DPP3
+	json_value_sep(json);
+	json_add_int(json, "capabilities", DPP_ENROLLEE_CAPAB_SAE_PW_ID);
+#endif /* CONFIG_DPP3 */
 	if (extra_name && extra_value && extra_name[0] && extra_value[0]) {
 		json_value_sep(json);
 		wpabuf_printf(json, "\"%s\":%s", extra_name, extra_value);
@@ -1139,8 +1143,18 @@ int dpp_configuration_valid(const struct dpp_configuration *conf)
 		return 0;
 	if (dpp_akm_psk(conf->akm) && !conf->passphrase && !conf->psk_set)
 		return 0;
+	if (dpp_akm_psk(conf->akm) && conf->passphrase) {
+		size_t len = os_strlen(conf->passphrase);
+
+		if (len > 63 || len < 8)
+			return 0;
+	}
 	if (dpp_akm_sae(conf->akm) && !conf->passphrase)
 		return 0;
+#ifdef CONFIG_DPP3
+	if (conf->idpass && (!conf->passphrase || !dpp_akm_sae(conf->akm)))
+		return 0;
+#endif /* CONFIG_DPP3 */
 	return 1;
 }
 
@@ -1150,6 +1164,9 @@ void dpp_configuration_free(struct dpp_configuration *conf)
 	if (!conf)
 		return;
 	str_clear_free(conf->passphrase);
+#ifdef CONFIG_DPP3
+	os_free(conf->idpass);
+#endif /* CONFIG_DPP3 */
 	os_free(conf->group_id);
 	os_free(conf->csrattrs);
 	os_free(conf->extra_name);
@@ -1228,14 +1245,28 @@ static int dpp_configuration_parse_helper(struct dpp_authentication *auth,
 		end = os_strchr(pos, ' ');
 		pass_len = end ? (size_t) (end - pos) : os_strlen(pos);
 		pass_len /= 2;
-		if (pass_len > 63 || pass_len < 8)
-			goto fail;
 		conf->passphrase = os_zalloc(pass_len + 1);
 		if (!conf->passphrase ||
 		    hexstr2bin(pos, (u8 *) conf->passphrase, pass_len) < 0)
 			goto fail;
 	}
 
+#ifdef CONFIG_DPP3
+	pos = os_strstr(cmd, " idpass=");
+	if (pos) {
+		size_t idpass_len;
+
+		pos += 8;
+		end = os_strchr(pos, ' ');
+		idpass_len = end ? (size_t) (end - pos) : os_strlen(pos);
+		idpass_len /= 2;
+		conf->idpass = os_zalloc(idpass_len + 1);
+		if (!conf->idpass ||
+		    hexstr2bin(pos, (u8 *) conf->idpass, idpass_len) < 0)
+			goto fail;
+	}
+#endif /* CONFIG_DPP3 */
+
 	pos = os_strstr(cmd, " psk=");
 	if (pos) {
 		pos += 5;
@@ -1595,6 +1626,13 @@ static void dpp_build_legacy_cred_params(struct wpabuf *buf,
 	if (conf->passphrase && os_strlen(conf->passphrase) < 64) {
 		json_add_string_escape(buf, "pass", conf->passphrase,
 				       os_strlen(conf->passphrase));
+#ifdef CONFIG_DPP3
+		if (conf->idpass) {
+			json_value_sep(buf);
+			json_add_string_escape(buf, "idpass", conf->idpass,
+					       os_strlen(conf->idpass));
+		}
+#endif /* CONFIG_DPP3 */
 	} else if (conf->psk_set) {
 		char psk[2 * sizeof(conf->psk) + 1];
 
@@ -1917,6 +1955,16 @@ dpp_build_conf_obj_legacy(struct dpp_authentication *auth,
 	const char *akm_str;
 	size_t len = 1000;
 
+
+#ifdef CONFIG_DPP3
+	if (conf->idpass &&
+	    !(auth->enrollee_capabilities & DPP_ENROLLEE_CAPAB_SAE_PW_ID)) {
+		wpa_printf(MSG_DEBUG,
+			   "DPP: Enrollee does not support SAE Password Identifier - cannot generate config object");
+		return NULL;
+	}
+#endif /* CONFIG_DPP3 */
+
 	if (conf->extra_name && conf->extra_value)
 		len += 10 + os_strlen(conf->extra_name) +
 			os_strlen(conf->extra_value);
@@ -2540,6 +2588,18 @@ dpp_conf_req_rx(struct dpp_authentication *auth, const u8 *attr_start,
 cont:
 #endif /* CONFIG_DPP2 */
 
+#ifdef CONFIG_DPP3
+	token = json_get_member(root, "capabilities");
+	if (token && token->type == JSON_NUMBER) {
+		wpa_printf(MSG_DEBUG, "DPP: capabilities = 0x%x",
+			   token->number);
+		wpa_msg(auth->msg_ctx, MSG_INFO,
+			DPP_EVENT_ENROLLEE_CAPABILITY "%d",
+			token->number);
+		auth->enrollee_capabilities = token->number;
+	}
+#endif /* CONFIG_DPP3 */
+
 	resp = dpp_build_conf_resp(auth, e_nonce, e_nonce_len, netrole,
 				   cert_req);
 
@@ -2563,13 +2623,25 @@ static int dpp_parse_cred_legacy(struct dpp_config_obj *conf,
 
 	if (pass && pass->type == JSON_STRING) {
 		size_t len = os_strlen(pass->string);
+#ifdef CONFIG_DPP3
+		struct json_token *saepi = json_get_member(cred, "idpass");
+#endif /* CONFIG_DPP3 */
 
 		wpa_hexdump_ascii_key(MSG_DEBUG, "DPP: Legacy passphrase",
 				      pass->string, len);
-		if (len < 8 || len > 63)
+		if (dpp_akm_psk(conf->akm) && (len < 8 || len > 63)) {
+			wpa_printf(MSG_DEBUG,
+				   "DPP: Unexpected pass length %zu for a config object that includes PSK",
+				   len);
 			return -1;
+		}
 		os_strlcpy(conf->passphrase, pass->string,
 			   sizeof(conf->passphrase));
+#ifdef CONFIG_DPP3
+		if (saepi && saepi->type == JSON_STRING)
+			os_strlcpy(conf->password_id, saepi->string,
+				   sizeof(conf->password_id));
+#endif /* CONFIG_DPP3 */
 	} else if (psk_hex && psk_hex->type == JSON_STRING) {
 		if (dpp_akm_sae(conf->akm) && !dpp_akm_psk(conf->akm)) {
 			wpa_printf(MSG_DEBUG,
diff --git a/src/common/dpp.h b/src/common/dpp.h
index 86f8478c..f9af506c 100644
--- a/src/common/dpp.h
+++ b/src/common/dpp.h
@@ -134,6 +134,9 @@ enum dpp_connector_key {
 #define DPP_MAX_SHARED_SECRET_LEN 66
 #define DPP_CP_LEN 64
 
+/* DPP Configuration Request - Enrollee Capabilities */
+#define DPP_ENROLLEE_CAPAB_SAE_PW_ID BIT(0)
+
 struct dpp_curve_params {
 	const char *name;
 	size_t hash_len;
@@ -260,6 +263,7 @@ struct dpp_configuration {
 
 	/* For legacy configuration */
 	char *passphrase;
+	char *idpass;
 	u8 psk[32];
 	int psk_set;
 
@@ -359,6 +363,9 @@ struct dpp_authentication {
 		u8 ssid_len;
 		int ssid_charset;
 		char passphrase[64];
+#ifdef CONFIG_DPP3
+		char password_id[64];
+#endif /* CONFIG_DPP3 */
 		u8 psk[PMK_LEN];
 		int psk_set;
 		enum dpp_akm akm;
@@ -396,6 +403,7 @@ struct dpp_authentication {
 	char *e_name;
 	char *e_mud_url;
 	int *e_band_support;
+	unsigned int enrollee_capabilities;
 #ifdef CONFIG_TESTING_OPTIONS
 	char *config_obj_override;
 	char *discovery_override;
diff --git a/src/common/hw_features_common.c b/src/common/hw_features_common.c
index 2c47bf81..bffb4407 100644
--- a/src/common/hw_features_common.c
+++ b/src/common/hw_features_common.c
@@ -1033,3 +1033,18 @@ bool is_punct_bitmap_valid(u16 bw, u16 pri_ch_bit_pos, u16 punct_bitmap)
 
 	return false;
 }
+
+
+bool chan_in_current_hw_info(struct hostapd_multi_hw_info *current_hw_info,
+			     struct hostapd_channel_data *chan)
+{
+	/* Assuming that if current_hw_info is not set full
+	 * iface->current_mode->channels[] can be used to scan for channels,
+	 * hence we return true.
+	 */
+	if (!current_hw_info)
+		return true;
+
+	return current_hw_info->start_freq <= chan->freq &&
+		current_hw_info->end_freq >= chan->freq;
+}
diff --git a/src/common/hw_features_common.h b/src/common/hw_features_common.h
index e791c33f..80e33adf 100644
--- a/src/common/hw_features_common.h
+++ b/src/common/hw_features_common.h
@@ -58,5 +58,7 @@ int chan_bw_allowed(const struct hostapd_channel_data *chan, u32 bw,
 		    int ht40_plus, int pri);
 int chan_pri_allowed(const struct hostapd_channel_data *chan);
 bool is_punct_bitmap_valid(u16 bw, u16 pri_ch_bit_pos, u16 punct_bitmap);
+bool chan_in_current_hw_info(struct hostapd_multi_hw_info *current_hw_info,
+			     struct hostapd_channel_data *chan);
 
 #endif /* HW_FEATURES_COMMON_H */
diff --git a/src/common/ieee802_11_common.c b/src/common/ieee802_11_common.c
index 10f9c4a6..c9b2d37c 100644
--- a/src/common/ieee802_11_common.c
+++ b/src/common/ieee802_11_common.c
@@ -148,6 +148,20 @@ static int ieee802_11_parse_vendor_specific(const u8 *pos, size_t elen,
 			elems->rsne_override_2 = pos;
 			elems->rsne_override_2_len = elen;
 			break;
+		case WFA_RSN_SELECTION_OUI_TYPE:
+			if (elen < 4 + 1) {
+				wpa_printf(MSG_DEBUG,
+					   "Too short RSN Selection element ignored");
+				return -1;
+			}
+			elems->rsn_selection = pos + 4;
+			elems->rsn_selection_len = elen - 4;
+			break;
+		case P2P2_OUI_TYPE:
+			/* Wi-Fi Alliance - P2P2 IE */
+			elems->p2p2_ie = pos;
+			elems->p2p2_ie_len = elen;
+			break;
 		default:
 			wpa_printf(MSG_MSGDUMP, "Unknown WFA "
 				   "information element ignored "
@@ -407,6 +421,10 @@ static int ieee802_11_parse_extension(const u8 *pos, size_t elen,
 		elems->mbssid_known_bss = pos;
 		elems->mbssid_known_bss_len = elen;
 		break;
+	case WLAN_EID_EXT_PASN_ENCRYPTED_DATA:
+		elems->pasn_encrypted_data = pos;
+		elems->pasn_encrypted_data_len = elen;
+		break;
 	default:
 		if (show_errors) {
 			wpa_printf(MSG_MSGDUMP,
diff --git a/src/common/ieee802_11_common.h b/src/common/ieee802_11_common.h
index 17e0822a..62090ce8 100644
--- a/src/common/ieee802_11_common.h
+++ b/src/common/ieee802_11_common.h
@@ -65,6 +65,8 @@ struct ieee802_11_elems {
 	const u8 *vendor_ht_cap;
 	const u8 *vendor_vht;
 	const u8 *p2p;
+	const u8 *p2p2_ie;
+	const u8 *pasn_encrypted_data;
 	const u8 *wfd;
 	const u8 *link_id;
 	const u8 *interworking;
@@ -118,6 +120,7 @@ struct ieee802_11_elems {
 	const u8 *mbssid;
 	const u8 *rsne_override;
 	const u8 *rsne_override_2;
+	const u8 *rsn_selection;
 
 	u8 ssid_len;
 	u8 supp_rates_len;
@@ -138,6 +141,8 @@ struct ieee802_11_elems {
 	u8 vendor_ht_cap_len;
 	u8 vendor_vht_len;
 	u8 p2p_len;
+	u8 p2p2_ie_len;
+	u8 pasn_encrypted_data_len;
 	u8 wfd_len;
 	u8 interworking_len;
 	u8 qos_map_set_len;
@@ -183,6 +188,7 @@ struct ieee802_11_elems {
 	u8 mbssid_len;
 	size_t rsne_override_len;
 	size_t rsne_override_2_len;
+	size_t rsn_selection_len;
 
 	struct mb_ies_info mb_ies;
 
diff --git a/src/common/ieee802_11_defs.h b/src/common/ieee802_11_defs.h
index 4cc6e41b..7ce75915 100644
--- a/src/common/ieee802_11_defs.h
+++ b/src/common/ieee802_11_defs.h
@@ -504,6 +504,7 @@
 #define WLAN_EID_EXT_HE_MU_EDCA_PARAMS 38
 #define WLAN_EID_EXT_SPATIAL_REUSE 39
 #define WLAN_EID_EXT_COLOR_CHANGE_ANNOUNCEMENT 42
+#define WLAN_EID_EXT_MAX_CHANNEL_SWITCH_TIME 52
 #define WLAN_EID_EXT_OCV_OCI 54
 #define WLAN_EID_EXT_MULTIPLE_BSSID_CONFIGURATION 55
 #define WLAN_EID_EXT_NON_INHERITANCE 56
@@ -524,6 +525,8 @@
 #define WLAN_EID_EXT_MULTI_LINK_TRAFFIC_INDICATION 110
 #define WLAN_EID_EXT_QOS_CHARACTERISTICS 113
 #define WLAN_EID_EXT_AKM_SUITE_SELECTOR 114
+#define WLAN_EID_EXT_BANDWIDTH_INDICATION 135
+#define WLAN_EID_EXT_PASN_ENCRYPTED_DATA 140
 
 /* Extended Capabilities field */
 #define WLAN_EXT_CAPAB_20_40_COEX 0
@@ -1431,6 +1434,7 @@ struct ieee80211_ampe_ie {
 #define WPS_IE_VENDOR_TYPE 0x0050f204
 #define OUI_WFA 0x506f9a
 #define P2P_IE_VENDOR_TYPE 0x506f9a09
+#define P2P2_IE_VENDOR_TYPE 0x506f9a28
 #define WFD_IE_VENDOR_TYPE 0x506f9a0a
 #define WFD_OUI_TYPE 10
 #define HS20_IE_VENDOR_TYPE 0x506f9a10
@@ -1455,9 +1459,11 @@ struct ieee80211_ampe_ie {
 #define WFA_RSNE_OVERRIDE_OUI_TYPE 0x29
 #define WFA_RSNE_OVERRIDE_2_OUI_TYPE 0x2a
 #define WFA_RSNXE_OVERRIDE_OUI_TYPE 0x2b
+#define WFA_RSN_SELECTION_OUI_TYPE 0x2c
 #define RSNE_OVERRIDE_IE_VENDOR_TYPE 0x506f9a29
 #define RSNE_OVERRIDE_2_IE_VENDOR_TYPE 0x506f9a2a
 #define RSNXE_OVERRIDE_IE_VENDOR_TYPE 0x506f9a2b
+#define RSN_SELECTION_IE_VENDOR_TYPE 0x506f9a2c
 
 #define MULTI_AP_SUB_ELEM_TYPE 0x06
 #define MULTI_AP_PROFILE_SUB_ELEM_TYPE 0x07
@@ -1722,6 +1728,7 @@ enum mbo_transition_reject_reason {
 /* Wi-Fi Direct (P2P) */
 
 #define P2P_OUI_TYPE 9
+#define P2P2_OUI_TYPE 0x28
 
 enum p2p_attr_id {
 	P2P_ATTR_STATUS = 0,
@@ -1752,6 +1759,13 @@ enum p2p_attr_id {
 	P2P_ATTR_SESSION_ID = 26,
 	P2P_ATTR_FEATURE_CAPABILITY = 27,
 	P2P_ATTR_PERSISTENT_GROUP = 28,
+	P2P_ATTR_CAPABILITY_EXTENSION = 29,
+	P2P_ATTR_WLAN_AP_INFORMATION = 30,
+	P2P_ATTR_DEVICE_IDENTITY_KEY = 31,
+	P2P_ATTR_DEVICE_IDENTITY_RESOLUTION = 32,
+	P2P_ATTR_PAIRING_AND_BOOTSTRAPPING = 33,
+	P2P_ATTR_PASSWORD = 34,
+	P2P_ATTR_ACTION_FRAME_WRAPPER = 35,
 	P2P_ATTR_VENDOR_SPECIFIC = 221
 };
 
@@ -1776,6 +1790,31 @@ enum p2p_attr_id {
 #define P2P_GROUP_CAPAB_GROUP_FORMATION BIT(6)
 #define P2P_GROUP_CAPAB_IP_ADDR_ALLOCATION BIT(7)
 
+/* P2P Capability Extension attribute - Capability info */
+#define P2P_PCEA_LEN_MASK (BIT(0) | BIT(1) | BIT(2) | BIT(3))
+#define P2P_PCEA_6GHZ BIT(4)
+#define P2P_PCEA_REG_INFO BIT(5)
+#define P2P_PCEA_DFS_OWNER BIT(6)
+#define P2P_PCEA_CLI_REQ_CS BIT(7)
+#define P2P_PCEA_PAIRING_CAPABLE BIT(8)
+#define P2P_PCEA_PAIRING_SETUP_ENABLED BIT(9)
+#define P2P_PCEA_PMK_CACHING BIT(10)
+#define P2P_PCEA_PASN_TYPE BIT(11)
+#define P2P_PCEA_TWT_POWER_MGMT BIT(12)
+
+/* P2P Pairing Bootstrapping Method attribute - Bootstrapping Method */
+#define P2P_PBMA_OPPORTUNISTIC       BIT(0)
+#define P2P_PBMA_PIN_CODE_DISPLAY    BIT(1)
+#define P2P_PBMA_PASSPHRASE_DISPLAY  BIT(2)
+#define P2P_PBMA_QR_DISPLAY          BIT(3)
+#define P2P_PBMA_NFC_TAG             BIT(4)
+#define P2P_PBMA_PIN_CODE_KEYPAD     BIT(5)
+#define P2P_PBMA_PASSPHRASE_KEYPAD   BIT(6)
+#define P2P_PBMA_QR_SCAN             BIT(7)
+#define P2P_PBMA_NFC_READER          BIT(8)
+#define P2P_PBMA_SERVICE_MANAGED     BIT(14)
+#define P2P_PBMA_HANDSHAKE_SKIP      BIT(15)
+
 /* P2PS Coordination Protocol Transport Bitmap */
 #define P2PS_FEATURE_CAPAB_UDP_TRANSPORT BIT(0)
 #define P2PS_FEATURE_CAPAB_MAC_TRANSPORT BIT(1)
@@ -1807,6 +1846,7 @@ enum p2p_status_code {
 	P2P_SC_FAIL_INCOMPATIBLE_PROV_METHOD = 10,
 	P2P_SC_FAIL_REJECTED_BY_USER = 11,
 	P2P_SC_SUCCESS_DEFERRED = 12,
+	P2P_SC_COMEBACK = 13,
 };
 
 enum p2p_role_indication {
@@ -2904,6 +2944,33 @@ enum ieee80211_eht_ml_sub_elem {
 	EHT_ML_SUB_ELEM_FRAGMENT = 254,
 };
 
+/* IEEE P802.11be/D7.0, 9.4.2.329 (Bandwidth Indication element) defines the
+ * Bandwidth Indication Information field to have the same definition as the
+ * EHT Operation Information field in the EHT Operation element.
+ */
+struct ieee80211_bw_ind_info {
+	u8 control; /* B0..B2: Channel Width */
+	u8 ccfs0;
+	u8 ccfs1;
+	le16 disabled_chan_bitmap; /* 0 or 2 octets */
+} STRUCT_PACKED;
+
+/* Control subfield: Channel Width subfield; see Table 9-417e (Channel width,
+ * CCFS0, and CCFS1 subfields) in IEEE P802.11be/D7.0. */
+#define BW_IND_CHANNEL_WIDTH_20MHZ	EHT_OPER_CHANNEL_WIDTH_20MHZ
+#define BW_IND_CHANNEL_WIDTH_40MHZ	EHT_OPER_CHANNEL_WIDTH_40MHZ
+#define BW_IND_CHANNEL_WIDTH_80MHZ	EHT_OPER_CHANNEL_WIDTH_80MHZ
+#define BW_IND_CHANNEL_WIDTH_160MHZ	EHT_OPER_CHANNEL_WIDTH_160MHZ
+#define BW_IND_CHANNEL_WIDTH_320MHZ	EHT_OPER_CHANNEL_WIDTH_320MHZ
+
+/* IEEE P802.11be/D7.0, 9.4.2.329 (Bandwidth Indication element) */
+struct ieee80211_bw_ind_element {
+	u8 bw_ind_params; /* Bandwidth Indication Parameters */
+	struct ieee80211_bw_ind_info bw_ind_info; /* 3 or 5 octets */
+} STRUCT_PACKED;
+
+#define BW_IND_PARAMETER_DISABLED_SUBCHAN_BITMAP_PRESENT       BIT(1)
+
 /* IEEE P802.11ay/D4.0, 9.4.2.251 - EDMG Operation element */
 #define EDMG_BSS_OPERATING_CHANNELS_OFFSET	6
 #define EDMG_OPERATING_CHANNEL_WIDTH_OFFSET	7
diff --git a/src/common/nan_de.c b/src/common/nan_de.c
index 12fad311..acde4f3b 100644
--- a/src/common/nan_de.c
+++ b/src/common/nan_de.c
@@ -58,10 +58,12 @@ struct nan_de_service {
 	struct os_reltime next_publish_state;
 	struct os_reltime next_publish_chan;
 	unsigned int next_publish_duration;
+	bool is_p2p;
 };
 
 struct nan_de {
 	u8 nmi[ETH_ALEN];
+	bool offload;
 	bool ap;
 	struct nan_callbacks cb;
 
@@ -77,7 +79,7 @@ struct nan_de {
 };
 
 
-struct nan_de * nan_de_init(const u8 *nmi, bool ap,
+struct nan_de * nan_de_init(const u8 *nmi, bool offload, bool ap,
 			    const struct nan_callbacks *cb)
 {
 	struct nan_de *de;
@@ -87,6 +89,7 @@ struct nan_de * nan_de_init(const u8 *nmi, bool ap,
 		return NULL;
 
 	os_memcpy(de->nmi, nmi, ETH_ALEN);
+	de->offload = offload;
 	de->ap = ap;
 	os_memcpy(&de->cb, cb, sizeof(*cb));
 
@@ -590,7 +593,7 @@ static void nan_de_timer(void *eloop_ctx, void *timeout_ctx)
 		if (srv_next >= 0 && (next == -1 || srv_next < next))
 			next = srv_next;
 
-		if (srv_next == 0 && !started &&
+		if (srv_next == 0 && !started && !de->offload &&
 		    de->listen_freq == 0 && de->ext_listen_freq == 0 &&
 		    de->tx_wait_end_freq == 0 &&
 		    nan_de_next_multicast(de, srv, &now) == 0) {
@@ -598,7 +601,7 @@ static void nan_de_timer(void *eloop_ctx, void *timeout_ctx)
 			nan_de_tx_multicast(de, srv, 0);
 		}
 
-		if (!started && de->cb.listen &&
+		if (!started && !de->offload && de->cb.listen &&
 		    de->listen_freq == 0 && de->ext_listen_freq == 0 &&
 		    de->tx_wait_end_freq == 0 &&
 		    ((srv->type == NAN_DE_PUBLISH &&
@@ -774,6 +777,34 @@ static void nan_de_get_sdea(const u8 *buf, size_t len, u8 instance_id,
 }
 
 
+static void nan_de_process_elem_container(struct nan_de *de, const u8 *buf,
+					  size_t len, const u8 *peer_addr,
+					  unsigned int freq, bool p2p)
+{
+	const u8 *elem;
+	u16 elem_len;
+
+	elem = nan_de_get_attr(buf, len, NAN_ATTR_ELEM_CONTAINER, 0);
+	if (!elem)
+		return;
+
+	elem++;
+	elem_len = WPA_GET_LE16(elem);
+	elem += 2;
+	/* Skip the attribute if there is not enough froom for an element. */
+	if (elem_len < 1 + 2)
+		return;
+
+	/* Skip Map ID */
+	elem++;
+	elem_len--;
+
+	if (p2p && de->cb.process_p2p_usd_elems)
+		de->cb.process_p2p_usd_elems(de->cb.ctx, elem, elem_len,
+					     peer_addr, freq);
+}
+
+
 static void nan_de_rx_publish(struct nan_de *de, struct nan_de_service *srv,
 			      const u8 *peer_addr, u8 instance_id,
 			      u8 req_instance_id, u16 sdea_control,
@@ -787,13 +818,13 @@ static void nan_de_rx_publish(struct nan_de *de, struct nan_de_service *srv,
 		nan_de_run_timer(de);
 	}
 
-	if (srv->subscribe.active && req_instance_id == 0) {
+	if (!de->offload && srv->subscribe.active && req_instance_id == 0) {
 		/* Active subscriber replies with a Subscribe message if it
 		 * received a matching unsolicited Publish message. */
 		nan_de_tx_multicast(de, srv, instance_id);
 	}
 
-	if (!srv->subscribe.active && req_instance_id == 0) {
+	if (!de->offload && !srv->subscribe.active && req_instance_id == 0) {
 		/* Passive subscriber replies with a Follow-up message without
 		 * Service Specific Info field if it received a matching
 		 * unsolicited Publish message. */
@@ -873,6 +904,9 @@ static void nan_de_rx_subscribe(struct nan_de *de, struct nan_de_service *srv,
 		return;
 	}
 
+	if (de->offload)
+		goto offload;
+
 	/* Reply with a solicited Publish message */
 	/* Service Descriptor attribute */
 	sda_len = NAN_SERVICE_ID_LEN + 1 + 1 + 1;
@@ -939,6 +973,7 @@ static void nan_de_rx_subscribe(struct nan_de *de, struct nan_de_service *srv,
 
 	nan_de_pause_state(srv, peer_addr, instance_id);
 
+offload:
 	if (!srv->publish.disable_events && de->cb.replied)
 		de->cb.replied(de->cb.ctx, srv->id, peer_addr, instance_id,
 			       srv_proto_type, ssi, ssi_len);
@@ -1094,6 +1129,8 @@ static void nan_de_rx_sda(struct nan_de *de, const u8 *peer_addr,
 				wpa_hexdump(MSG_MSGDUMP, "NAN: ssi",
 					    ssi, ssi_len);
 			}
+			nan_de_process_elem_container(de, buf, len, peer_addr,
+						      freq, srv->is_p2p);
 		}
 
 		switch (type) {
@@ -1196,10 +1233,23 @@ static int nan_de_derive_service_id(struct nan_de_service *srv)
 }
 
 
+const u8 * nan_de_get_service_id(struct nan_de *de, int id)
+{
+	struct nan_de_service *srv;
+
+	if (id < 1 || id > NAN_DE_MAX_SERVICE)
+		return NULL;
+	srv = de->service[id - 1];
+	if (!srv)
+		return NULL;
+	return srv->service_id;
+}
+
+
 int nan_de_publish(struct nan_de *de, const char *service_name,
 		   enum nan_service_protocol_type srv_proto_type,
 		   const struct wpabuf *ssi, const struct wpabuf *elems,
-		   struct nan_publish_params *params)
+		   struct nan_publish_params *params, bool p2p)
 {
 	int publish_id;
 	struct nan_de_service *srv;
@@ -1261,6 +1311,7 @@ int nan_de_publish(struct nan_de *de, const char *service_name,
 	wpa_printf(MSG_DEBUG, "NAN: Assigned new publish handle %d for %s",
 		   publish_id, service_name);
 	srv->id = publish_id;
+	srv->is_p2p = p2p;
 	nan_de_add_srv(de, srv);
 	nan_de_run_timer(de);
 	return publish_id;
@@ -1312,7 +1363,7 @@ int nan_de_update_publish(struct nan_de *de, int publish_id,
 int nan_de_subscribe(struct nan_de *de, const char *service_name,
 		     enum nan_service_protocol_type srv_proto_type,
 		     const struct wpabuf *ssi, const struct wpabuf *elems,
-		     struct nan_subscribe_params *params)
+		     struct nan_subscribe_params *params, bool p2p)
 {
 	int subscribe_id;
 	struct nan_de_service *srv;
@@ -1337,6 +1388,17 @@ int nan_de_subscribe(struct nan_de *de, const char *service_name,
 	if (nan_de_derive_service_id(srv) < 0)
 		goto fail;
 	os_memcpy(&srv->subscribe, params, sizeof(*params));
+
+	if (params->freq_list) {
+		size_t len;
+
+		len = (int_array_len(params->freq_list) + 1) * sizeof(int);
+		srv->freq_list = os_memdup(params->freq_list, len);
+		if (!srv->freq_list)
+			goto fail;
+	}
+	srv->subscribe.freq_list = NULL;
+
 	srv->srv_proto_type = srv_proto_type;
 	if (ssi) {
 		srv->ssi = wpabuf_dup(ssi);
@@ -1352,6 +1414,7 @@ int nan_de_subscribe(struct nan_de *de, const char *service_name,
 	wpa_printf(MSG_DEBUG, "NAN: Assigned new subscribe handle %d for %s",
 		   subscribe_id, service_name);
 	srv->id = subscribe_id;
+	srv->is_p2p = p2p;
 	nan_de_add_srv(de, srv);
 	nan_de_run_timer(de);
 	return subscribe_id;
diff --git a/src/common/nan_de.h b/src/common/nan_de.h
index 62235064..f369a572 100644
--- a/src/common/nan_de.h
+++ b/src/common/nan_de.h
@@ -53,9 +53,13 @@ struct nan_callbacks {
 	void (*receive)(void *ctx, int id, int peer_instance_id,
 			const u8 *ssi, size_t ssi_len,
 			const u8 *peer_addr);
+
+	void (*process_p2p_usd_elems)(void *ctx, const u8 *buf,
+				      u16 buf_len, const u8 *peer_addr,
+				      unsigned int freq);
 };
 
-struct nan_de * nan_de_init(const u8 *nmi, bool ap,
+struct nan_de * nan_de_init(const u8 *nmi, bool offload, bool ap,
 			    const struct nan_callbacks *cb);
 void nan_de_flush(struct nan_de *de);
 void nan_de_deinit(struct nan_de *de);
@@ -68,6 +72,7 @@ void nan_de_tx_wait_ended(struct nan_de *de);
 
 void nan_de_rx_sdf(struct nan_de *de, const u8 *peer_addr, unsigned int freq,
 		   const u8 *buf, size_t len);
+const u8 * nan_de_get_service_id(struct nan_de *de, int id);
 
 struct nan_publish_params {
 	/* configuration_parameters */
@@ -105,7 +110,7 @@ struct nan_publish_params {
 int nan_de_publish(struct nan_de *de, const char *service_name,
 		   enum nan_service_protocol_type srv_proto_type,
 		   const struct wpabuf *ssi, const struct wpabuf *elems,
-		   struct nan_publish_params *params);
+		   struct nan_publish_params *params, bool p2p);
 
 void nan_de_cancel_publish(struct nan_de *de, int publish_id);
 
@@ -124,6 +129,9 @@ struct nan_subscribe_params {
 	/* Selected frequency */
 	unsigned int freq;
 
+	/* Multi-channel frequencies (publishChannelList) */
+	const int *freq_list;
+
 	/* Query period in ms; 0 = use default */
 	unsigned int query_period;
 };
@@ -132,7 +140,7 @@ struct nan_subscribe_params {
 int nan_de_subscribe(struct nan_de *de, const char *service_name,
 		     enum nan_service_protocol_type srv_proto_type,
 		     const struct wpabuf *ssi, const struct wpabuf *elems,
-		     struct nan_subscribe_params *params);
+		     struct nan_subscribe_params *params, bool p2p);
 
 void nan_de_cancel_subscribe(struct nan_de *de, int subscribe_id);
 
diff --git a/src/common/qca-vendor.h b/src/common/qca-vendor.h
index 5dab120d..ddf19662 100644
--- a/src/common/qca-vendor.h
+++ b/src/common/qca-vendor.h
@@ -230,7 +230,8 @@ enum qca_radiotap_vendor_ids {
  *
  * @QCA_NL80211_VENDOR_SUBCMD_GET_FEATURES: Command to get the features
  *	supported by the driver. enum qca_wlan_vendor_features defines
- *	the possible features.
+ *	the possible features that are encoded in
+ *	QCA_WLAN_VENDOR_ATTR_FEATURE_FLAGS.
  *
  * @QCA_NL80211_VENDOR_SUBCMD_DFS_OFFLOAD_CAC_STARTED: Event used by driver,
  *	which supports DFS offloading, to indicate a channel availability check
@@ -1132,6 +1133,39 @@ enum qca_radiotap_vendor_ids {
  *	Uses the attributes defined in
  *	enum qca_wlan_vendor_attr_tdls_disc_rsp_ext.
  *
+ * @QCA_NL80211_VENDOR_SUBCMD_AUDIO_TRANSPORT_SWITCH: This vendor subcommand is
+ *	used to configure and indicate the audio transport switch in both
+ *	command and event paths. This is used when two or more audio transports
+ *	(e.g., WLAN and Bluetooth) are available between peers.
+ *
+ *	If the driver needs to perform operations like scan, connection,
+ *	roaming, RoC, etc. and AP concurrency policy is set to either
+ *	QCA_WLAN_CONCURRENT_AP_POLICY_GAMING_AUDIO or
+ *	QCA_WLAN_CONCURRENT_AP_POLICY_LOSSLESS_AUDIO_STREAMING, the driver sends
+ *	audio transport switch event to userspace. Userspace application upon
+ *	receiving the event, can try to switch to the requested audio transport.
+ *	The userspace uses this command to send the status of transport
+ *	switching (either confirm or reject) to the driver using this
+ *	subcommand. The driver continues with the pending operation either upon
+ *	receiving the command from userspace or after waiting for a timeout from
+ *	sending the event to userspace. The driver can request userspace to
+ *	switch to WLAN upon availability of WLAN audio transport once after the
+ *	concurrent operations are completed.
+ *
+ *	Userspace can also request audio transport switch from non-WLAN to WLAN
+ *	using this subcommand to the driver. The driver can accept or reject
+ *	depending on other concurrent operations in progress. The driver returns
+ *	success if it can allow audio transport when it receives the command or
+ *	appropriate kernel error code otherwise. Userspace indicates the audio
+ *	transport switch from WLAN to non-WLAN using this subcommand and the
+ *	driver can do other concurrent operations without needing to send any
+ *	event to userspace. This subcommand is used by userspace only when the
+ *	driver advertises support for
+ *	QCA_WLAN_VENDOR_FEATURE_ENHANCED_AUDIO_EXPERIENCE_OVER_WLAN.
+ *
+ *	The attributes used with this command are defined in enum
+ *	qca_wlan_vendor_attr_audio_transport_switch.
+ *
  * @QCA_NL80211_VENDOR_SUBCMD_TX_LATENCY: This vendor subcommand is used to
  *	configure, retrieve, and report per-link transmit latency statistics.
  *
@@ -1237,6 +1271,33 @@ enum qca_radiotap_vendor_ids {
  *
  *	The attributes used with this command are defined in
  *	enum qca_wlan_vendor_attr_usd.
+ *
+ * @QCA_NL80211_VENDOR_SUBCMD_CONNECT_EXT: This is an extension to
+ *	%NL80211_CMD_CONNECT command. Userspace can use this to indicate
+ *	additional information to be considered for the subsequent
+ *	(re)association request attempts with %NL80211_CMD_CONNECT. The
+ *	additional information sent with this command is applicable for the
+ *	entire duration of the connection established with %NL80211_CMD_CONNECT,
+ *	including the roams triggered by the driver internally due to other
+ *	vendor interfaces, driver internal logic, and BTM requests from the
+ *	connected AP.
+ *
+ *	The attributes used with this command are defined in
+ *	enum qca_wlan_vendor_attr_connect_ext.
+ *
+ * @QCA_NL80211_VENDOR_SUBCMD_SET_P2P_MODE: Vendor subcommand to configure
+ *	Wi-Fi Direct mode. This command sets the configuration through
+ *	the attributes defined in the enum qca_wlan_vendor_attr_set_p2p_mode.
+ *	It is applicable for P2P Group Owner only. This command is used before
+ *	starting the GO.
+ *
+ * @QCA_NL80211_VENDOR_SUBCMD_CHAN_USAGE_REQ: Vendor subcommand to request
+ *	transmission of a channel usage request. It carries channel usage
+ *	information for BSSs that are not infrastructure BSSs or an off channel
+ *	TDLS direct link.
+ *
+ *	The attributes used with this command are defined in
+ *	enum qca_wlan_vendor_attr_chan_usage_req.
  */
 enum qca_nl80211_vendor_subcmds {
 	QCA_NL80211_VENDOR_SUBCMD_UNSPEC = 0,
@@ -1452,7 +1513,7 @@ enum qca_nl80211_vendor_subcmds {
 	QCA_NL80211_VENDOR_SUBCMD_TID_TO_LINK_MAP = 229,
 	QCA_NL80211_VENDOR_SUBCMD_LINK_RECONFIG = 230,
 	QCA_NL80211_VENDOR_SUBCMD_TDLS_DISC_RSP_EXT = 231,
-	/* 232 - reserved for QCA */
+	QCA_NL80211_VENDOR_SUBCMD_AUDIO_TRANSPORT_SWITCH = 232,
 	QCA_NL80211_VENDOR_SUBCMD_TX_LATENCY = 233,
 	/* 234 - reserved for QCA */
 	QCA_NL80211_VENDOR_SUBCMD_SDWF_PHY_OPS = 235,
@@ -1470,6 +1531,9 @@ enum qca_nl80211_vendor_subcmds {
 	QCA_NL80211_VENDOR_SUBCMD_ASYNC_STATS_POLICY = 247,
 	QCA_NL80211_VENDOR_SUBCMD_CLASSIFIED_FLOW_REPORT = 248,
 	QCA_NL80211_VENDOR_SUBCMD_USD = 249,
+	QCA_NL80211_VENDOR_SUBCMD_CONNECT_EXT = 250,
+	QCA_NL80211_VENDOR_SUBCMD_SET_P2P_MODE = 251,
+	QCA_NL80211_VENDOR_SUBCMD_CHAN_USAGE_REQ = 252,
 };
 
 /* Compatibility defines for previously used subcmd names.
@@ -1496,7 +1560,11 @@ enum qca_wlan_vendor_attr {
 	 */
 	QCA_WLAN_VENDOR_ATTR_ROAMING_POLICY = 5,
 	QCA_WLAN_VENDOR_ATTR_MAC_ADDR = 6,
-	/* used by QCA_NL80211_VENDOR_SUBCMD_GET_FEATURES */
+	/* Feature flags contained in a byte array. The feature flags are
+	 * identified by their bit index (see &enum qca_wlan_vendor_features)
+	 * with the first byte being the least significant one and the last one
+	 * being the most significant one. Used by
+	 * QCA_NL80211_VENDOR_SUBCMD_GET_FEATURES. */
 	QCA_WLAN_VENDOR_ATTR_FEATURE_FLAGS = 7,
 	QCA_WLAN_VENDOR_ATTR_TEST = 8,
 	/* used by QCA_NL80211_VENDOR_SUBCMD_GET_FEATURES */
@@ -2193,31 +2261,15 @@ enum qca_wlan_vendor_acs_hw_mode {
  *	in AP mode supports TWT responder mode in HT and VHT modes.
  *
  * @QCA_WLAN_VENDOR_FEATURE_RSN_OVERRIDE_STA: Flag indicates that the device
- *	supports RSNE/RSNXE overriding in STA mode.
- *
- *	For SME offload to the driver case:
- *	- Supplicant should enable RSNO element use only when the driver
- *	  indicates this feature flag.
- *	- The driver should enable RSNO element use with the supplicant selected
- *	  BSS only when the supplicant sends an RSNO element with an empty
- *	  payload in the connect request elements buffer in NL80211_CMD_CONNECT.
- *
- *	For BSS selection offload to the driver case:
- *	- Supplicant should enable RSNO element use only when the driver
- *	  indicates this feature flag.
- *	- Supplicant should always send RSNO elements in the connect request
- *	  elements buffer in NL80211_CMD_CONNECT irrespective of whether RSNO
- *	  elements are supported by the BSS that the supplicant selected
- *	- The driver should enable RSNO element use only when the supplicant
- *	  sends an RSNO element with an empty payload in connect request
- *	  elements in NL80211_CMD_CONNECT.
- *	- The driver should remove RSNO elements from the connect request
- *	  elements while preparing the (Re)Association Request frame elements
- *	  if the driver selects a different BSS which is not advertising RSNO
- *	  elements.
- *
- *	If both SME and BSS selection offload to the driver, BSS selection
- *	offload to the driver case rules shall be applied.
+ *	supports RSNE/RSNXE overriding in STA mode. Supplicant should enable
+ *	RSN overriding elements use only when the driver indicates this feature
+ *	flag. For BSS selection offload to the driver case, the driver shall
+ *	strip/modify the RSN Selection element indicated in connect request
+ *	elements or add that element if none was provided based on the BSS
+ *	selected by the driver.
+ *
+ * @QCA_WLAN_VENDOR_FEATURE_NAN_USD_OFFLOAD: Flag indicates that the driver
+ *	supports Unsynchronized Service Discovery to be offloaded to it.
  *
  * @NUM_QCA_WLAN_VENDOR_FEATURES: Number of assigned feature bits
  */
@@ -2248,6 +2300,7 @@ enum qca_wlan_vendor_features {
 	QCA_WLAN_VENDOR_FEATURE_ENHANCED_AUDIO_EXPERIENCE_OVER_WLAN = 23,
 	QCA_WLAN_VENDOR_FEATURE_HT_VHT_TWT_RESPONDER = 24,
 	QCA_WLAN_VENDOR_FEATURE_RSN_OVERRIDE_STA = 25,
+	QCA_WLAN_VENDOR_FEATURE_NAN_USD_OFFLOAD = 26,
 	NUM_QCA_WLAN_VENDOR_FEATURES /* keep last */
 };
 
@@ -2667,6 +2720,9 @@ enum qca_wlan_vendor_scan_priority {
  *	when AP is operating as MLD to specify which link is requesting the
  *	scan or which link the scan result is for. No need of this attribute
  *	in other cases.
+ * @QCA_WLAN_VENDOR_ATTR_SCAN_SKIP_CHANNEL_RECENCY_PERIOD: Optional (u32). Skip
+ *	scanning channels which are scanned recently within configured time
+ *	(in ms).
  */
 enum qca_wlan_vendor_attr_scan {
 	QCA_WLAN_VENDOR_ATTR_SCAN_INVALID_PARAM = 0,
@@ -2685,6 +2741,7 @@ enum qca_wlan_vendor_attr_scan {
 	QCA_WLAN_VENDOR_ATTR_SCAN_PRIORITY = 13,
 	QCA_WLAN_VENDOR_ATTR_SCAN_PAD = 14,
 	QCA_WLAN_VENDOR_ATTR_SCAN_LINK_ID = 15,
+	QCA_WLAN_VENDOR_ATTR_SCAN_SKIP_CHANNEL_RECENCY_PERIOD = 16,
 	QCA_WLAN_VENDOR_ATTR_SCAN_AFTER_LAST,
 	QCA_WLAN_VENDOR_ATTR_SCAN_MAX =
 	QCA_WLAN_VENDOR_ATTR_SCAN_AFTER_LAST - 1
@@ -3686,6 +3743,17 @@ enum qca_wlan_vendor_attr_config {
 	 */
 	QCA_WLAN_VENDOR_ATTR_CONFIG_FOLLOW_AP_PREFERENCE_FOR_CNDS_SELECT = 121,
 
+	/* 16-bit unsigned value to configure P2P GO beacon interval in TUs.
+	 * This attribute is used to update the P2P GO beacon interval
+	 * dynamically.
+	 *
+	 * Updating the beacon interval while the GO continues operating the BSS
+	 * will likely interoperability issues and is not recommended to be
+	 * used. All the values should be multiples of the minimum used value to
+	 * minimize risk of issues.
+	 */
+	QCA_WLAN_VENDOR_ATTR_CONFIG_P2P_GO_BEACON_INTERVAL = 122,
+
 	/* keep last */
 	QCA_WLAN_VENDOR_ATTR_CONFIG_AFTER_LAST,
 	QCA_WLAN_VENDOR_ATTR_CONFIG_MAX =
@@ -7457,6 +7525,10 @@ enum qca_wlan_vendor_attr_external_acs_event {
 	 * for External ACS
 	 */
 	QCA_WLAN_VENDOR_ATTR_EXTERNAL_ACS_EVENT_AFC_CAPABILITY = 15,
+	/* Link ID attibute (u8) is used to identify a specific link affiliated
+	 * to an AP MLD.
+	 */
+	QCA_WLAN_VENDOR_ATTR_EXTERNAL_ACS_EVENT_LINK_ID = 16,
 
 	/* keep last */
 	QCA_WLAN_VENDOR_ATTR_EXTERNAL_ACS_EVENT_LAST,
@@ -10398,6 +10470,26 @@ enum qca_wlan_vendor_attr_wifi_test_config {
 	 */
 	QCA_WLAN_VENDOR_ATTR_WIFI_TEST_CONFIG_EHT_SCS_TRAFFIC_SUPPORT = 73,
 
+	/* 8-bit unsigned value to disable or not disable the channel switch
+	 * initiation in P2P GO mode.
+	 * 0 - Not-disable, 1 - Disable
+	 *
+	 * This attribute is used for testing purposes.
+	 */
+	QCA_WLAN_VENDOR_ATTR_WIFI_TEST_CONFIG_DISABLE_CHAN_SWITCH_INITIATION = 74,
+
+	/* 8-bit unsigned value. This indicates number of random PMKIDs to be
+	 * added in the RSNE of the (Re)Association request frames. This is
+	 * exclusively used for the scenarios where the device is used as a test
+	 * bed device with special functionality and not recommended for
+	 * production. Default value is zero. If the user space configures a
+	 * non-zero value, that remains in use until the driver is unloaded or
+	 * the user space resets the value to zero.
+	 *
+	 * This attribute is used for testing purposes.
+	 */
+	QCA_WLAN_VENDOR_ATTR_WIFI_TEST_CONFIG_RSNE_ADD_RANDOM_PMKIDS = 75,
+
 	/* keep last */
 	QCA_WLAN_VENDOR_ATTR_WIFI_TEST_CONFIG_AFTER_LAST,
 	QCA_WLAN_VENDOR_ATTR_WIFI_TEST_CONFIG_MAX =
@@ -10695,7 +10787,8 @@ enum qca_wlan_twt_setup_state {
  * TWT (Target Wake Time) setup request. These attributes are sent as part of
  * %QCA_WLAN_VENDOR_ATTR_WIFI_TEST_CONFIG_TWT_SETUP and
  * %QCA_NL80211_VENDOR_SUBCMD_WIFI_TEST_CONFIGURATION. Also used by
- * attributes through %QCA_NL80211_VENDOR_SUBCMD_CONFIG_TWT.
+ * attributes through %QCA_NL80211_VENDOR_SUBCMD_CONFIG_TWT and
+ * %QCA_NL80211_VENDOR_SUBCMD_CHAN_USAGE_REQ.
  *
  * @QCA_WLAN_VENDOR_ATTR_TWT_SETUP_BCAST: Flag attribute.
  * Disable (flag attribute not present) - Individual TWT
@@ -12451,6 +12544,12 @@ enum qca_wlan_vendor_attr_add_sta_node_params {
 	 */
 	QCA_WLAN_VENDOR_ATTR_ADD_STA_NODE_IS_ML = 3,
 
+	/*
+	 * This is u8 attribute used to identify a specific link affiliated
+	 * to an AP MLD.
+	 */
+	QCA_WLAN_VENDOR_ATTR_ADD_STA_NODE_LINK_ID = 4,
+
 	/* keep last */
 	QCA_WLAN_VENDOR_ATTR_ADD_STA_NODE_PARAM_AFTER_LAST,
 	QCA_WLAN_VENDOR_ATTR_ADD_STA_NODE_PARAM_MAX =
@@ -18047,4 +18146,238 @@ enum qca_wlan_vendor_attr_usd {
 	QCA_WLAN_VENDOR_ATTR_USD_AFTER_LAST - 1,
 };
 
+/**
+ * enum qca_wlan_audio_transport_switch_type - Represents the possible transport
+ * switch types.
+ *
+ * @QCA_WLAN_AUDIO_TRANSPORT_SWITCH_TYPE_NON_WLAN: Request to route audio data
+ * via non-WLAN transport (e.g., Bluetooth).
+ *
+ * @QCA_WLAN_AUDIO_TRANSPORT_SWITCH_TYPE_WLAN: Request to route audio data via
+ * WLAN transport.
+ */
+enum qca_wlan_audio_transport_switch_type {
+	QCA_WLAN_AUDIO_TRANSPORT_SWITCH_TYPE_NON_WLAN = 0,
+	QCA_WLAN_AUDIO_TRANSPORT_SWITCH_TYPE_WLAN = 1,
+};
+
+/**
+ * enum qca_wlan_audio_transport_switch_status - Represents the status of audio
+ * transport switch request.
+ *
+ * @QCA_WLAN_AUDIO_TRANSPORT_SWITCH_STATUS_REJECTED: Request to switch transport
+ * has been rejected. For example, when transport switch is requested from WLAN
+ * to non-WLAN transport, user space modules and peers would evaluate the switch
+ * request and may not be ready for switch and hence switch to non-WLAN
+ * transport gets rejected.
+ *
+ * @QCA_WLAN_AUDIO_TRANSPORT_SWITCH_STATUS_COMPLETED: Request to switch
+ * transport has been completed. This is sent only in the command path. For
+ * example, when the driver had requested for audio transport switch and
+ * userspace modules as well as peers are ready for the switch, userspace module
+ * switches the transport and sends the subcommand with status completed to the
+ * driver.
+ */
+enum qca_wlan_audio_transport_switch_status {
+	QCA_WLAN_AUDIO_TRANSPORT_SWITCH_STATUS_REJECTED = 0,
+	QCA_WLAN_AUDIO_TRANSPORT_SWITCH_STATUS_COMPLETED = 1,
+};
+
+/**
+ * enum qca_wlan_audio_transport_switch_reason - Represents the reason of audio
+ * transport switch request.
+ *
+ * @QCA_WLAN_AUDIO_TRANSPORT_SWITCH_REASON_TERMINATING: Requester transport is
+ * terminating. After this indication, requester module may not be available to
+ * process further request on its transport. For example, to handle a high
+ * priority concurrent interface, WLAN transport needs to terminate and hence
+ * indicates switch to a non-WLAN transport with reason terminating. User space
+ * modules switch to non-WLAN immediately without waiting for further
+ * confirmation.
+ */
+enum qca_wlan_audio_transport_switch_reason {
+	QCA_WLAN_AUDIO_TRANSPORT_SWITCH_REASON_TERMINATING = 0,
+};
+
+/**
+ * enum qca_wlan_vendor_attr_audio_transport_switch - Attributes used by
+ * %QCA_NL80211_VENDOR_SUBCMD_AUDIO_TRANSPORT_SWITCH vendor command.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_AUDIO_TRANSPORT_SWITCH_TYPE: u8 attribute. Indicates
+ * the transport switch type from one of the values in enum
+ * qca_wlan_audio_transport_switch_type. This is mandatory attribute in both
+ * command and event path. This attribute is included in both requests and
+ * responses.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_AUDIO_TRANSPORT_SWITCH_STATUS: u8 attribute. Indicates
+ * the transport switch status from one of the values in enum
+ * qca_wlan_audio_transport_switch_status. This is optional attribute and used
+ * in both command and event path. This attribute must not be included in
+ * requests.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_AUDIO_TRANSPORT_SWITCH_REASON: u8 attribute. Indicates
+ * the transport switch reason from one of the values in enum
+ * qca_wlan_audio_transport_switch_reason. This is optional attribute and used
+ * in both command and event path.
+ */
+enum qca_wlan_vendor_attr_audio_transport_switch {
+	QCA_WLAN_VENDOR_ATTR_AUDIO_TRANSPORT_SWITCH_INVALID = 0,
+	QCA_WLAN_VENDOR_ATTR_AUDIO_TRANSPORT_SWITCH_TYPE = 1,
+	QCA_WLAN_VENDOR_ATTR_AUDIO_TRANSPORT_SWITCH_STATUS = 2,
+	QCA_WLAN_VENDOR_ATTR_AUDIO_TRANSPORT_SWITCH_REASON = 3,
+
+	/* keep last */
+	QCA_WLAN_VENDOR_ATTR_AUDIO_TRANSPORT_SWITCH_AFTER_LAST,
+	QCA_WLAN_VENDOR_ATTR_AUDIO_TRANSPORT_SWITCH_MAX =
+	QCA_WLAN_VENDOR_ATTR_AUDIO_TRANSPORT_SWITCH_AFTER_LAST - 1,
+};
+
+
+/**
+ * enum qca_wlan_connect_ext_features - Feature flags for
+ * %QCA_WLAN_VENDOR_ATTR_CONNECT_EXT_FEATURES
+ *
+ * @QCA_CONNECT_EXT_FEATURE_RSNO: Flag attribute. This indicates supplicant
+ * support for RSN overriding. The driver shall enable RSN overriding in the
+ * (re)association attempts only if this flag is indicated. This functionality
+ * is available only when the driver indicates support for
+ * @QCA_WLAN_VENDOR_FEATURE_RSN_OVERRIDE_STA.
+ *
+ * @NUM_QCA_WLAN_VENDOR_FEATURES: Number of assigned feature bits.
+ */
+enum qca_wlan_connect_ext_features {
+	QCA_CONNECT_EXT_FEATURE_RSNO	= 0,
+	NUM_QCA_CONNECT_EXT_FEATURES /* keep last */
+};
+
+/* enum qca_wlan_vendor_attr_connect_ext: Attributes used by vendor command
+ * %QCA_NL80211_VENDOR_SUBCMD_CONNECT_EXT.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_CONNECT_EXT_FEATURES: Feature flags contained in a byte
+ * array. The feature flags are identified by their bit index (see &enum
+ * qca_wlan_connect_ext_features) with the first byte being the least
+ * significant one and the last one being the most significant one.
+ */
+enum qca_wlan_vendor_attr_connect_ext {
+	QCA_WLAN_VENDOR_ATTR_CONNECT_EXT_INVALID = 0,
+	QCA_WLAN_VENDOR_ATTR_CONNECT_EXT_FEATURES = 1,
+
+	QCA_WLAN_VENDOR_ATTR_CONNECT_EXT_AFTER_LAST,
+	QCA_WLAN_VENDOR_ATTR_CONNECT_EXT_MAX =
+	QCA_WLAN_VENDOR_ATTR_CONNECT_EXT_AFTER_LAST - 1,
+};
+
+/**
+ * enum qca_wlan_vendor_p2p_mode - Defines the values used with
+ * %QCA_WLAN_VENDOR_ATTR_SET_P2P_MODE_CONFIG.
+ *
+ * @QCA_P2P_MODE_WFD_R1: Wi-Fi Direct R1 only.
+ * @QCA_P2P_MODE_WFD_R2: Wi-Fi Direct R2 only.
+ * @QCA_P2P_MODE_WFD_PCC: P2P Connection Compatibility Mode which supports both
+ * Wi-Fi Direct R1 and R2.
+ */
+enum qca_wlan_vendor_p2p_mode {
+	QCA_P2P_MODE_WFD_R1	= 0,
+	QCA_P2P_MODE_WFD_R2	= 1,
+	QCA_P2P_MODE_WFD_PCC	= 2,
+};
+
+/* enum qca_wlan_vendor_attr_set_p2p_mode: Attributes used by vendor command
+ * %QCA_NL80211_VENDOR_SUBCMD_SET_P2P_MODE.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_SET_P2P_MODE_CONFIG: u8 attribute. Sets the P2P device
+ * mode. The values used are defined in enum qca_wlan_vendor_p2p_mode.
+ * This configuration is valid until the interface is brought up next time after
+ * this configuration and the driver shall use this configuration only when the
+ * interface is brought up in NL80211_IFTYPE_P2P_GO mode.
+ * When this parameter has not been set, the interface is brought up with
+ * Wi-Fi Direct R1 only configuration by default.
+ */
+enum qca_wlan_vendor_attr_set_p2p_mode {
+	QCA_WLAN_VENDOR_ATTR_SET_P2P_MODE_INVALID = 0,
+	QCA_WLAN_VENDOR_ATTR_SET_P2P_MODE_CONFIG = 1,
+
+	QCA_WLAN_VENDOR_ATTR_SET_P2P_MODE_AFTER_LAST,
+	QCA_WLAN_VENDOR_ATTR_SET_P2P_MODE_MAX =
+	QCA_WLAN_VENDOR_ATTR_SET_P2P_MODE_AFTER_LAST - 1,
+};
+
+/**
+ * enum qca_wlan_vendor_attr_chan_usage_req_chan_list: Attributes used inside
+ * nested attributes %QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_CHAN_LIST.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_CHAN_LIST_CHAN: u8 attribute. Indicates
+ * the channel number of the channel list entry.
+ * @QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_CHAN_LIST_OP_CLASS: u8 attribute.
+ * Indicates the operating class of the channel list entry.
+ */
+enum qca_wlan_vendor_attr_chan_usage_req_chan_list {
+	QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_CHAN_LIST_INVALID = 0,
+	QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_CHAN_LIST_CHAN = 1,
+	QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_CHAN_LIST_OP_CLASS = 2,
+
+	QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_CHAN_LIST_AFTER_LAST,
+	QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_CHAN_LIST_MAX =
+	QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_CHAN_LIST_AFTER_LAST - 1,
+};
+
+/**
+ * enum qca_wlan_vendor_attr_chan_usage_req_mode: Defines the values used
+ * with %QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_MODE.
+ *
+ * @QCA_CHAN_USAGE_MODE_UNAVAILABILITY_INDICATION: Mode set by STA to indicate
+ * the AP about its unavailability during a peer-to-peer TWT agreement.
+ *
+ * @QCA_CHAN_USAGE_MODE_CHANNEL_SWITCH_REQ: Mode set by the STA that is in a
+ * channel-usage-aidable BSS to request a channel switch. Other Channel Usage
+ * elements are not required. Optional HT/VHT/HE Capabilities are present.
+ */
+enum qca_wlan_vendor_attr_chan_usage_req_mode {
+	QCA_CHAN_USAGE_MODE_UNAVAILABILITY_INDICATION = 3,
+	QCA_CHAN_USAGE_MODE_CHANNEL_SWITCH_REQ = 4,
+};
+
+/**
+ * enum qca_wlan_vendor_attr_chan_usage_req: Attributes used by vendor command
+ * %QCA_NL80211_VENDOR_SUBCMD_CHAN_USAGE_REQ.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_MODE: Required u8 attribute. Identifies
+ * the usage of the channel list entry provided in the channel usage request.
+ * Channel switch request and unavailability channel usage modes are
+ * configured on a STA/P2P Client.
+ * See enum qca_wlan_vendor_attr_chan_usage_req_mode for attribute values.
+ * See IEEE P802.11-REVme/D7.0, 9.4.2.84, Table 9-268 for more information.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_CHAN_LIST: Required array of nested
+ * attributes containing channel usage parameters.
+ * Required when channel usage mode is Channel-usage-aidable BSS channel
+ * switch request.
+ * See enum qca_wlan_vendor_attr_req_chan_list for nested attributes.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_UNAVAILABILITY_CONFIG_PARAMS: Nested
+ * attribute representing the parameters configured for unavailability
+ * indication. Required when channel usage mode is unavailability indication.
+ *
+ * Below attributes from enum qca_wlan_vendor_attr_twt_setup are used inside
+ * this nested attribute:
+ * %QCA_WLAN_VENDOR_ATTR_TWT_SETUP_RESPONDER_PM_MODE,
+ * %QCA_WLAN_VENDOR_ATTR_TWT_SETUP_REQ_TYPE,
+ * %QCA_WLAN_VENDOR_ATTR_TWT_SETUP_TRIGGER,
+ * %QCA_WLAN_VENDOR_ATTR_TWT_SETUP_FLOW_TYPE,
+ * %QCA_WLAN_VENDOR_ATTR_TWT_SETUP_WAKE_INTVL_EXP,
+ * %QCA_WLAN_VENDOR_ATTR_TWT_SETUP_PROTECTION,
+ * %QCA_WLAN_VENDOR_ATTR_TWT_SETUP_WAKE_DURATION,
+ * %QCA_WLAN_VENDOR_ATTR_TWT_SETUP_WAKE_INTVL_MANTISSA.
+ */
+enum qca_wlan_vendor_attr_chan_usage_req {
+	QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_INVALID = 0,
+	QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_MODE = 1,
+	QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_CHAN_LIST = 2,
+	QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_UNAVAILABILITY_CONFIG_PARAMS = 3,
+
+	QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_AFTER_LAST,
+	QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_MAX =
+	QCA_WLAN_VENDOR_ATTR_CHAN_USAGE_REQ_AFTER_LAST - 1,
+};
+
 #endif /* QCA_VENDOR_H */
diff --git a/src/common/wpa_common.c b/src/common/wpa_common.c
index 8eb4a1da..a8c7c416 100644
--- a/src/common/wpa_common.c
+++ b/src/common/wpa_common.c
@@ -1456,15 +1456,18 @@ bool pasn_use_sha384(int akmp, int cipher)
  * @akmp: Negotiated AKM
  * @cipher: Negotiated pairwise cipher
  * @kdk_len: the length in octets that should be derived for HTLK. Can be zero.
+ * @kek_len: The length in octets that should be derived for KEK. Can be zero.
  * Returns: 0 on success, -1 on failure
  */
 int pasn_pmk_to_ptk(const u8 *pmk, size_t pmk_len,
 		    const u8 *spa, const u8 *bssid,
 		    const u8 *dhss, size_t dhss_len,
 		    struct wpa_ptk *ptk, int akmp, int cipher,
-		    size_t kdk_len)
+		    size_t kdk_len, size_t kek_len)
 {
-	u8 tmp[WPA_KCK_MAX_LEN + WPA_TK_MAX_LEN + WPA_KDK_MAX_LEN];
+	u8 tmp[WPA_KCK_MAX_LEN + WPA_KEK_MAX_LEN + WPA_TK_MAX_LEN +
+	       WPA_KDK_MAX_LEN];
+	const u8 *pos;
 	u8 *data;
 	size_t data_len, ptk_len;
 	int ret = -1;
@@ -1499,7 +1502,7 @@ int pasn_pmk_to_ptk(const u8 *pmk, size_t pmk_len,
 	ptk->kck_len = WPA_PASN_KCK_LEN;
 	ptk->tk_len = wpa_cipher_key_len(cipher);
 	ptk->kdk_len = kdk_len;
-	ptk->kek_len = 0;
+	ptk->kek_len = kek_len;
 	ptk->kek2_len = 0;
 	ptk->kck2_len = 0;
 
@@ -1510,7 +1513,7 @@ int pasn_pmk_to_ptk(const u8 *pmk, size_t pmk_len,
 		goto err;
 	}
 
-	ptk_len = ptk->kck_len + ptk->tk_len + ptk->kdk_len;
+	ptk_len = ptk->kck_len + ptk->tk_len + ptk->kdk_len + ptk->kek_len;
 	if (ptk_len > sizeof(tmp))
 		goto err;
 
@@ -1538,13 +1541,21 @@ int pasn_pmk_to_ptk(const u8 *pmk, size_t pmk_len,
 
 	os_memcpy(ptk->kck, tmp, WPA_PASN_KCK_LEN);
 	wpa_hexdump_key(MSG_DEBUG, "PASN: KCK:", ptk->kck, WPA_PASN_KCK_LEN);
+	pos = &tmp[WPA_PASN_KCK_LEN];
 
-	os_memcpy(ptk->tk, tmp + WPA_PASN_KCK_LEN, ptk->tk_len);
+	if (kek_len) {
+		os_memcpy(ptk->kek, pos, kek_len);
+		wpa_hexdump_key(MSG_DEBUG, "PASN: KEK:",
+				ptk->kek, ptk->kek_len);
+		pos += kek_len;
+	}
+
+	os_memcpy(ptk->tk, pos, ptk->tk_len);
 	wpa_hexdump_key(MSG_DEBUG, "PASN: TK:", ptk->tk, ptk->tk_len);
+	pos += ptk->tk_len;
 
 	if (kdk_len) {
-		os_memcpy(ptk->kdk, tmp + WPA_PASN_KCK_LEN + ptk->tk_len,
-			  ptk->kdk_len);
+		os_memcpy(ptk->kdk, pos, ptk->kdk_len);
 		wpa_hexdump_key(MSG_DEBUG, "PASN: KDK:",
 				ptk->kdk, ptk->kdk_len);
 	}
@@ -3448,7 +3459,7 @@ static int wpa_parse_generic(const u8 *pos, struct wpa_eapol_ie_parse *ie)
 	const u8 *p;
 	size_t left;
 	u8 link_id;
-	char title[50];
+	char title[100];
 	int ret;
 
 	if (len == 0)
@@ -3629,6 +3640,57 @@ static int wpa_parse_generic(const u8 *pos, struct wpa_eapol_ie_parse *ie)
 		return 0;
 	}
 
+	if (left >= 1 && selector == WFA_KEY_DATA_RSN_OVERRIDE_LINK) {
+		link_id = p[0];
+		if (link_id >= MAX_NUM_MLD_LINKS)
+			return 2;
+
+		ie->rsn_override_link[link_id] = p;
+		ie->rsn_override_link_len[link_id] = left;
+		ret = os_snprintf(title, sizeof(title),
+				  "RSN: Link ID %u - RSN Override Link KDE in EAPOL-Key",
+				  link_id);
+		if (!os_snprintf_error(sizeof(title), ret))
+			wpa_hexdump(MSG_DEBUG, title, pos, dlen);
+		return 0;
+	}
+
+	if (selector == RSNE_OVERRIDE_IE_VENDOR_TYPE) {
+		ie->rsne_override = pos;
+		ie->rsne_override_len = dlen;
+		wpa_hexdump(MSG_DEBUG,
+			    "RSN: RSNE Override element in EAPOL-Key",
+			    ie->rsne_override, ie->rsne_override_len);
+		return 0;
+	}
+
+	if (selector == RSNE_OVERRIDE_2_IE_VENDOR_TYPE) {
+		ie->rsne_override_2 = pos;
+		ie->rsne_override_2_len = dlen;
+		wpa_hexdump(MSG_DEBUG,
+			    "RSN: RSNE Override 2 element in EAPOL-Key",
+			    ie->rsne_override_2, ie->rsne_override_2_len);
+		return 0;
+	}
+
+	if (selector == RSNXE_OVERRIDE_IE_VENDOR_TYPE) {
+		ie->rsnxe_override = pos;
+		ie->rsnxe_override_len = dlen;
+		wpa_hexdump(MSG_DEBUG,
+			    "RSN: RSNXE Override element in EAPOL-Key",
+			    ie->rsnxe_override, ie->rsnxe_override_len);
+		return 0;
+	}
+
+	if (selector == RSN_SELECTION_IE_VENDOR_TYPE) {
+		ie->rsn_selection = p;
+		ie->rsn_selection_len = left;
+		wpa_hexdump(MSG_DEBUG,
+			    "RSN: RSN Selection element in EAPOL-Key",
+			    ie->rsn_selection, ie->rsn_selection_len);
+		return 0;
+	}
+
 	return 2;
 }
 
@@ -4268,3 +4330,24 @@ int wpa_pasn_add_extra_ies(struct wpabuf *buf, const u8 *extra_ies, size_t len)
 }
 
 #endif /* CONFIG_PASN */
+
+
+void rsn_set_snonce_cookie(u8 *snonce)
+{
+	u8 *pos;
+
+	pos = snonce + WPA_NONCE_LEN - 6;
+	WPA_PUT_BE24(pos, OUI_WFA);
+	pos += 3;
+	WPA_PUT_BE24(pos, 0x000029);
+}
+
+
+bool rsn_is_snonce_cookie(const u8 *snonce)
+{
+	const u8 *pos;
+
+	pos = snonce + WPA_NONCE_LEN - 6;
+	return WPA_GET_BE24(pos) == OUI_WFA &&
+		WPA_GET_BE24(pos + 3) == 0x000029;
+}
diff --git a/src/common/wpa_common.h b/src/common/wpa_common.h
index 1e313684..e608d3cb 100644
--- a/src/common/wpa_common.h
+++ b/src/common/wpa_common.h
@@ -144,6 +144,7 @@ WPA_CIPHER_BIP_CMAC_256)
 #define WFA_KEY_DATA_IP_ADDR_ALLOC RSN_SELECTOR(0x50, 0x6f, 0x9a, 5)
 #define WFA_KEY_DATA_TRANSITION_DISABLE RSN_SELECTOR(0x50, 0x6f, 0x9a, 0x20)
 #define WFA_KEY_DATA_DPP RSN_SELECTOR(0x50, 0x6f, 0x9a, 0x21)
+#define WFA_KEY_DATA_RSN_OVERRIDE_LINK RSN_SELECTOR(0x50, 0x6f, 0x9a, 0x2d)
 
 #define WPA_OUI_TYPE RSN_SELECTOR(0x00, 0x50, 0xf2, 1)
 
@@ -643,6 +644,14 @@ struct wpa_pasn_params_data {
 #define WPA_PASN_PUBKEY_COMPRESSED_1 0x03
 #define WPA_PASN_PUBKEY_UNCOMPRESSED 0x04
 
+/* WPA3 specification - RSN Selection element */
+enum rsn_selection_variant {
+	RSN_SELECTION_RSNE = 0,
+	RSN_SELECTION_RSNE_OVERRIDE = 1,
+	RSN_SELECTION_RSNE_OVERRIDE_2 = 2,
+};
+
+
 int wpa_ft_parse_ies(const u8 *ies, size_t ies_len, struct wpa_ft_ies *parse,
 		     int key_mgmt, bool reassoc_resp);
 void wpa_ft_parse_ies_free(struct wpa_ft_ies *parse);
@@ -704,6 +713,14 @@ struct wpa_eapol_ie_parse {
 	u16 aid;
 	const u8 *wmm;
 	size_t wmm_len;
+	const u8 *rsn_selection;
+	size_t rsn_selection_len;
+	const u8 *rsne_override;
+	size_t rsne_override_len;
+	const u8 *rsne_override_2;
+	size_t rsne_override_2_len;
+	const u8 *rsnxe_override;
+	size_t rsnxe_override_len;
 	u16 valid_mlo_gtks; /* bitmap of valid link GTK KDEs */
 	const u8 *mlo_gtk[MAX_NUM_MLD_LINKS];
 	size_t mlo_gtk_len[MAX_NUM_MLD_LINKS];
@@ -716,6 +733,8 @@ struct wpa_eapol_ie_parse {
 	u16 valid_mlo_links; /* bitmap of valid MLO link KDEs */
 	const u8 *mlo_link[MAX_NUM_MLD_LINKS];
 	size_t mlo_link_len[MAX_NUM_MLD_LINKS];
+	const u8 *rsn_override_link[MAX_NUM_MLD_LINKS];
+	size_t rsn_override_link_len[MAX_NUM_MLD_LINKS];
 };
 
 int wpa_parse_kde_ies(const u8 *buf, size_t len, struct wpa_eapol_ie_parse *ie);
@@ -751,7 +770,7 @@ int pasn_pmk_to_ptk(const u8 *pmk, size_t pmk_len,
 		    const u8 *spa, const u8 *bssid,
 		    const u8 *dhss, size_t dhss_len,
 		    struct wpa_ptk *ptk, int akmp, int cipher,
-		    size_t kdk_len);
+		    size_t kdk_len, size_t kek_len);
 
 u8 pasn_mic_len(int akmp, int cipher);
 
@@ -787,4 +806,7 @@ int wpa_pasn_parse_parameter_ie(const u8 *data, u8 len, bool from_ap,
 void wpa_pasn_add_rsnxe(struct wpabuf *buf, u16 capab);
 int wpa_pasn_add_extra_ies(struct wpabuf *buf, const u8 *extra_ies, size_t len);
 
+void rsn_set_snonce_cookie(u8 *snonce);
+bool rsn_is_snonce_cookie(const u8 *snonce);
+
 #endif /* WPA_COMMON_H */
diff --git a/src/common/wpa_ctrl.h b/src/common/wpa_ctrl.h
index f6142501..2ea8ab31 100644
--- a/src/common/wpa_ctrl.h
+++ b/src/common/wpa_ctrl.h
@@ -13,6 +13,8 @@
 extern "C" {
 #endif
 
+#define WPA_CTRL_IFACE_LINK_NAME	"link"
+
 /* wpa_supplicant control interface - fixed message prefixes */
 
 /** Interactive request for identity/password/pin */
@@ -204,6 +206,7 @@ extern "C" {
 #define DPP_EVENT_CONFOBJ_SSID "DPP-CONFOBJ-SSID "
 #define DPP_EVENT_CONFOBJ_SSID_CHARSET "DPP-CONFOBJ-SSID-CHARSET "
 #define DPP_EVENT_CONFOBJ_PASS "DPP-CONFOBJ-PASS "
+#define DPP_EVENT_CONFOBJ_IDPASS "DPP-CONFOBJ-IDPASS "
 #define DPP_EVENT_CONFOBJ_PSK "DPP-CONFOBJ-PSK "
 #define DPP_EVENT_CONNECTOR "DPP-CONNECTOR "
 #define DPP_EVENT_C_SIGN_KEY "DPP-C-SIGN-KEY "
@@ -225,6 +228,7 @@ extern "C" {
 #define DPP_EVENT_CHIRP_STOPPED "DPP-CHIRP-STOPPED "
 #define DPP_EVENT_MUD_URL "DPP-MUD-URL "
 #define DPP_EVENT_BAND_SUPPORT "DPP-BAND-SUPPORT "
+#define DPP_EVENT_ENROLLEE_CAPABILITY "DPP-ENROLLEE-CAPABILITY "
 #define DPP_EVENT_CSR "DPP-CSR "
 #define DPP_EVENT_CHIRP_RX "DPP-CHIRP-RX "
 #define DPP_EVENT_CONF_NEEDED "DPP-CONF-NEEDED "
@@ -304,6 +308,10 @@ extern "C" {
 #define P2P_EVENT_P2PS_PROVISION_START "P2PS-PROV-START "
 #define P2P_EVENT_P2PS_PROVISION_DONE "P2PS-PROV-DONE "
 
+#define P2P_EVENT_BOOTSTRAP_REQUEST "P2P-BOOTSTRAP-REQUEST "
+#define P2P_EVENT_BOOTSTRAP_SUCCESS "P2P-BOOTSTRAP-SUCCESS "
+#define P2P_EVENT_BOOTSTRAP_FAILURE "P2P-BOOTSTRAP-FAILURE "
+
 #define INTERWORKING_AP "INTERWORKING-AP "
 #define INTERWORKING_EXCLUDED "INTERWORKING-BLACKLISTED "
 #define INTERWORKING_NO_MATCH "INTERWORKING-NO-MATCH "
diff --git a/src/crypto/tls_openssl.c b/src/crypto/tls_openssl.c
index f5d734d4..d8499330 100644
--- a/src/crypto/tls_openssl.c
+++ b/src/crypto/tls_openssl.c
@@ -1290,8 +1290,9 @@ static int tls_is_pin_error(unsigned int err)
 #endif /* OPENSSL_NO_ENGINE */
 
 
-#ifdef ANDROID
-/* EVP_PKEY_from_keystore comes from system/security/keystore-engine. */
+// Imported from system/security/keystore-engine. This method
+// is not used by the mainline supplicant.
+#if defined(ANDROID) && !defined(MAINLINE_SUPPLICANT)
 EVP_PKEY * EVP_PKEY_from_keystore(const char *key_id);
 #endif /* ANDROID */
 
@@ -1299,7 +1300,7 @@ static int tls_engine_init(struct tls_connection *conn, const char *engine_id,
 			   const char *pin, const char *key_id,
 			   const char *cert_id, const char *ca_cert_id)
 {
-#if defined(ANDROID) && defined(OPENSSL_IS_BORINGSSL)
+#if defined(ANDROID) && !defined(MAINLINE_SUPPLICANT) && defined(OPENSSL_IS_BORINGSSL)
 #if !defined(OPENSSL_NO_ENGINE)
 #error "This code depends on OPENSSL_NO_ENGINE being defined by BoringSSL."
 #endif
@@ -1307,6 +1308,7 @@ static int tls_engine_init(struct tls_connection *conn, const char *engine_id,
 		return TLS_SET_PARAMS_ENGINE_PRV_INIT_FAILED;
 	conn->engine = NULL;
 	conn->private_key = EVP_PKEY_from_keystore(key_id);
+
 	if (!conn->private_key) {
 		wpa_printf(MSG_ERROR,
 			   "ENGINE: cannot load private key with id '%s' [%s]",
diff --git a/src/drivers/driver.h b/src/drivers/driver.h
index 8be40123..765ea59c 100644
--- a/src/drivers/driver.h
+++ b/src/drivers/driver.h
@@ -22,11 +22,15 @@
 #include "common/defs.h"
 #include "common/ieee802_11_defs.h"
 #include "common/wpa_common.h"
+#include "common/nan.h"
 #ifdef CONFIG_MACSEC
 #include "pae/ieee802_1x_kay.h"
 #endif /* CONFIG_MACSEC */
 #include "utils/list.h"
 
+struct nan_subscribe_params;
+struct nan_publish_params;
+
 #define HOSTAPD_CHAN_DISABLED 0x00000001
 #define HOSTAPD_CHAN_NO_IR 0x00000002
 #define HOSTAPD_CHAN_RADAR 0x00000008
@@ -317,6 +321,27 @@ struct hostapd_hw_modes {
 };
 
 
+/**
+ * struct hostapd_multi_hw_info: Supported multiple underlying hardware info
+ */
+struct hostapd_multi_hw_info {
+	/**
+	 * hw_idx - Hardware index
+	 */
+	u8 hw_idx;
+
+	/**
+	 * start_freq - Frequency range start in MHz
+	 */
+	int start_freq;
+
+	/**
+	 * end_freq - Frequency range end in MHz
+	 */
+	int end_freq;
+};
+
+
 #define IEEE80211_CAP_ESS	0x0001
 #define IEEE80211_CAP_IBSS	0x0002
 #define IEEE80211_CAP_PRIVACY	0x0010
@@ -1370,6 +1395,12 @@ struct wpa_driver_associate_params {
 	 * mld_params - MLD association parameters
 	 */
 	struct wpa_driver_mld_params mld_params;
+
+
+	/**
+	 * rsn_overriding - wpa_supplicant RSN overriding support
+	 */
+	bool rsn_overriding;
 };
 
 enum hide_ssid {
@@ -2339,6 +2370,8 @@ struct wpa_driver_capa {
 #define WPA_DRIVER_FLAGS2_HT_VHT_TWT_RESPONDER	0x0000000000200000ULL
 /** Driver supports RSN override elements */
 #define WPA_DRIVER_FLAGS2_RSN_OVERRIDE_STA	0x0000000000400000ULL
+/** Driver supports NAN offload */
+#define WPA_DRIVER_FLAGS2_NAN_OFFLOAD		0x0000000000800000ULL
 	u64 flags2;
 
 #define FULL_AP_CLIENT_STATE_SUPP(drv_flags) \
@@ -5206,15 +5239,19 @@ struct wpa_driver_ops {
 	/**
 	 * is_drv_shared - Check whether the driver interface is shared
 	 * @priv: Private driver interface data from init()
-	 * @bss_ctx: BSS context for %WPA_IF_AP_BSS interfaces
+	 * @link_id: Link ID to match
+	 * Returns: true if it is being used or else false.
 	 *
 	 * Checks whether the driver interface is being used by other partner
 	 * BSS(s) or not. This is used to decide whether the driver interface
 	 * needs to be deinitilized when one interface is getting deinitialized.
 	 *
-	 * Returns: true if it is being used or else false.
+	 * NOTE: @link_id will be used only when there is only one BSS
+	 * present and if that single link is active. In that case, the
+	 * link ID is matched with the active link_id to decide whether the
+	 * driver interface is being used by other partner BSS(s).
 	 */
-	bool (*is_drv_shared)(void *priv, void *bss_ctx);
+	bool (*is_drv_shared)(void *priv, int link_id);
 
 	/**
 	 * link_sta_remove - Remove a link STA from an MLD STA
@@ -5225,11 +5262,94 @@ struct wpa_driver_ops {
 	 */
 	int (*link_sta_remove)(void *priv, u8 link_id, const u8 *addr);
 
+	/**
+	 * nan_flush - Flush all NAN offload services
+	 * @priv: Private driver interface data
+	 * Returns: 0 on success, negative value on failure
+	 */
+	int (*nan_flush)(void *priv);
+
+	/**
+	 * nan_publish - NAN offload for Publish()
+	 * @priv: Private driver interface data
+	 * @src: Source P2P device addr
+	 * @publish_id: Publish instance to add
+	 * @service_name: Service name
+	 * @service_id: Service ID (6 octet value derived from service name)
+	 * @srv_proto_type: Service protocol type
+	 * @ssi: Service specific information or %NULL
+	 * @elems: Information elements for Element Container attribute or %NULL
+	 * @params: Configuration parameters
+	 * Returns: 0 on success, negative value on failure
+	 */
+	int (*nan_publish)(void *priv, const u8 *src, int publish_id,
+			   const char *service_name, const u8 *service_id,
+			   enum nan_service_protocol_type srv_proto_type,
+			   const struct wpabuf *ssi, const struct wpabuf *elems,
+			   struct nan_publish_params *params);
+
+	/**
+	 * nan_cancel_publish - NAN offload for CancelPublish()
+	 * @priv: Private driver interface data
+	 * @publish_id: Publish instance to cancel
+	 * Returns: 0 on success, negative value on failure
+	 */
+	int (*nan_cancel_publish)(void *priv, int publish_id);
+
+	/**
+	 * nan_update_publish - NAN offload for UpdatePublish()
+	 * @priv: Private driver interface data
+	 * @ssi: Service specific information or %NULL
+	 * Returns: 0 on success, negative value on failure
+	 */
+	int (*nan_update_publish)(void *priv, int publish_id,
+				  const struct wpabuf *ssi);
+
+	/**
+	 * nan_subscribe - NAN offload for Subscribe()
+	 * @priv: Private driver interface data
+	 * @src: Source P2P device addr
+	 * @subscribe_id: Subscribe instance to add
+	 * @service_name: Service name
+	 * @service_id: Service ID (6 octet value derived from service name)
+	 * @srv_proto_type: Service protocol type
+	 * @ssi: Service specific information or %NULL
+	 * @elems: Information elements for Element Container attribute or %NULL
+	 * @params: Configuration parameters
+	 * Returns: 0 on success, negative value on failure
+	 */
+	int (*nan_subscribe)(void *priv, const u8 *src, int subscribe_id,
+			     const char *service_name, const u8 *service_id,
+			     enum nan_service_protocol_type srv_proto_type,
+			     const struct wpabuf *ssi,
+			     const struct wpabuf *elems,
+			     struct nan_subscribe_params *params);
+
+	/**
+	 * nan_cancel_subscribe - NAN offload for CancelSubscribe()
+	 * @priv: Private driver interface data
+	 * @subscribe_id: Subscribe instance to cancel
+	 * Returns: 0 on success, negative value on failure
+	 */
+	int (*nan_cancel_subscribe)(void *priv, int subscribe_id);
+
 #ifdef CONFIG_TESTING_OPTIONS
 	int (*register_frame)(void *priv, u16 type,
 			      const u8 *match, size_t match_len,
 			      bool multicast);
 #endif /* CONFIG_TESTING_OPTIONS */
+
+	/**
+	 * get_multi_hw_info - Get multiple underlying hardware information
+	 *		       (hardware IDx and supported frequency range)
+	 * @priv: Private driver interface data
+	 * @num_multi_hws: Variable for returning the number of returned
+	 *	hardware info data
+	 * Returns: Pointer to allocated multiple hardware data on success
+	 * or %NULL on failure. Caller is responsible for freeing this.
+	 */
+	struct hostapd_multi_hw_info *
+	(*get_multi_hw_info)(void *priv, unsigned int *num_multi_hws);
 };
 
 /**
@@ -5857,6 +5977,11 @@ enum wpa_event_type {
 	 * EVENT_LINK_RECONFIG - Notification that AP links removed
 	 */
 	EVENT_LINK_RECONFIG,
+
+	/**
+	 * EVENT_MLD_INTERFACE_FREED - Notification of AP MLD interface removal
+	 */
+	EVENT_MLD_INTERFACE_FREED,
 };
 
 
diff --git a/src/drivers/driver_common.c b/src/drivers/driver_common.c
index 9bc5a731..9589183d 100644
--- a/src/drivers/driver_common.c
+++ b/src/drivers/driver_common.c
@@ -100,6 +100,7 @@ const char * event_to_string(enum wpa_event_type event)
 	E2S(LINK_CH_SWITCH_STARTED);
 	E2S(TID_LINK_MAP);
 	E2S(LINK_RECONFIG);
+	E2S(MLD_INTERFACE_FREED);
 	}
 
 	return "UNKNOWN";
diff --git a/src/drivers/driver_macsec_linux.c b/src/drivers/driver_macsec_linux.c
index c8671549..fad47a29 100644
--- a/src/drivers/driver_macsec_linux.c
+++ b/src/drivers/driver_macsec_linux.c
@@ -19,6 +19,7 @@
 #include <netlink/route/link.h>
 #include <netlink/route/link/macsec.h>
 #include <linux/if_macsec.h>
+#include <linux/version.h>
 #include <inttypes.h>
 
 #include "utils/common.h"
@@ -32,7 +33,8 @@
 
 #define UNUSED_SCI 0xffffffffffffffff
 
-#if LIBNL_VER_NUM >= LIBNL_VER(3, 6)
+#if (LIBNL_VER_NUM >= LIBNL_VER(3, 6) && \
+     LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
 #define LIBNL_HAS_OFFLOAD
 #endif
 
diff --git a/src/drivers/driver_nl80211.c b/src/drivers/driver_nl80211.c
index b2b909e1..5890ac6f 100644
--- a/src/drivers/driver_nl80211.c
+++ b/src/drivers/driver_nl80211.c
@@ -30,6 +30,8 @@
 #include "common/ieee802_11_defs.h"
 #include "common/ieee802_11_common.h"
 #include "common/wpa_common.h"
+#include "common/nan.h"
+#include "common/nan_de.h"
 #include "crypto/sha256.h"
 #include "crypto/sha384.h"
 #include "netlink.h"
@@ -3089,7 +3091,7 @@ static int wpa_driver_nl80211_del_beacon(struct i802_bss *bss,
 	struct wpa_driver_nl80211_data *drv = bss->drv;
 	struct i802_link *link = nl80211_get_link(bss, link_id);
 
-	if (!link->beacon_set)
+	if (!link || !link->beacon_set)
 		return 0;
 
 	wpa_printf(MSG_DEBUG, "nl80211: Remove beacon (ifindex=%d)",
@@ -3157,9 +3159,6 @@ static void wpa_driver_nl80211_deinit(struct i802_bss *bss)
 				   bss->ifname, bss->brname, strerror(errno));
 	}
 
-	if (drv->rtnl_sk)
-		nl_socket_free(drv->rtnl_sk);
-
 	if (bss->added_bridge) {
 		if (linux_set_iface_flags(drv->global->ioctl_sock, bss->brname,
 					  0) < 0)
@@ -3179,6 +3178,9 @@ static void wpa_driver_nl80211_deinit(struct i802_bss *bss)
 		nl80211_remove_links(bss);
 	}
 
+	if (drv->rtnl_sk)
+		nl_socket_free(drv->rtnl_sk);
+
 	if (drv->eapol_sock >= 0) {
 		eloop_unregister_read_sock(drv->eapol_sock);
 		close(drv->eapol_sock);
@@ -3195,7 +3197,7 @@ static void wpa_driver_nl80211_deinit(struct i802_bss *bss)
 	eloop_cancel_timeout(wpa_driver_nl80211_send_rfkill, drv, drv->ctx);
 	rfkill_deinit(drv->rfkill);
 
-	eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv, drv->ctx);
+	eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv, bss->ctx);
 
 	if (!drv->start_iface_up)
 		(void) i802_set_iface_flags(bss, 0);
@@ -4272,6 +4274,22 @@ struct i802_link * nl80211_get_link(struct i802_bss *bss, s8 link_id)
 }
 
 
+u8 nl80211_get_link_id_from_link(struct i802_bss *bss, struct i802_link *link)
+{
+	u8 link_id;
+
+	if (link == bss->flink)
+		return 0;
+
+	for_each_link(bss->valid_links, link_id) {
+		if (&bss->links[link_id] == link)
+			return link_id;
+	}
+
+	return 0;
+}
+
+
 static void nl80211_link_set_freq(struct i802_bss *bss, s8 link_id, int freq)
 {
 	struct i802_link *link = nl80211_get_link(bss, link_id);
@@ -5930,13 +5948,15 @@ fail:
 }
 
 
-static void rtnl_neigh_delete_fdb_entry(struct i802_bss *bss, const u8 *addr)
+static void rtnl_neigh_delete_fdb_entry(struct i802_bss *bss, const u8 *addr,
+					bool is_bridge)
 {
 	struct wpa_driver_nl80211_data *drv = bss->drv;
 	struct ndmsg nhdr = {
 		.ndm_state = NUD_PERMANENT,
-		.ndm_ifindex = bss->ifindex,
+		.ndm_ifindex = is_bridge ? bss->br_ifindex : bss->ifindex,
 		.ndm_family = AF_BRIDGE,
+		.ndm_type = is_bridge ? NTF_SELF : 0,
 	};
 	struct nl_msg *msg;
 	int err;
@@ -5953,11 +5973,61 @@ static void rtnl_neigh_delete_fdb_entry(struct i802_bss *bss, const u8 *addr)
 	err = nl_wait_for_ack(drv->rtnl_sk);
 	if (err < 0) {
 		wpa_printf(MSG_DEBUG, "nl80211: bridge FDB entry delete for "
-			   MACSTR " ifindex=%d failed: %s", MAC2STR(addr),
-			   bss->ifindex, nl_geterror(err));
+			   MACSTR " ifindex=%d ifname %s failed: %s",
+			   MAC2STR(addr),
+			   is_bridge ? bss->br_ifindex : bss->ifindex,
+			   is_bridge ? bss->brname : bss->ifname,
+			   nl_geterror(err));
+	} else {
+		wpa_printf(MSG_DEBUG, "nl80211: deleted bridge FDB entry "
+			   MACSTR " from %s",
+			   MAC2STR(addr),
+			   is_bridge ? bss->brname : bss->ifname);
+	}
+
+errout:
+	nlmsg_free(msg);
+}
+
+
+static void rtnl_neigh_add_fdb_entry(struct i802_bss *bss, const u8 *addr,
+				     bool is_bridge)
+{
+	struct wpa_driver_nl80211_data *drv = bss->drv;
+	struct ndmsg nhdr = {
+		.ndm_state = NUD_PERMANENT,
+		.ndm_ifindex = is_bridge ? bss->br_ifindex : bss->ifindex,
+		.ndm_family = AF_BRIDGE,
+		/* TODO: remove this check if this flag needs to be used,
+		 * for other interfaces type.
+		 */
+		.ndm_flags = is_bridge ? NTF_SELF : 0,
+	};
+	struct nl_msg *msg;
+	int err;
+
+	msg = nlmsg_alloc_simple(RTM_NEWNEIGH, NLM_F_CREATE);
+	if (!msg)
+		return;
+
+	if (nlmsg_append(msg, &nhdr, sizeof(nhdr), NLMSG_ALIGNTO) < 0 ||
+	    nla_put(msg, NDA_LLADDR, ETH_ALEN, (void *) addr) ||
+	    nl_send_auto_complete(drv->rtnl_sk, msg) < 0)
+		goto errout;
+
+	err = nl_wait_for_ack(drv->rtnl_sk);
+	if (err < 0) {
+		wpa_printf(MSG_DEBUG, "nl80211: bridge FDB entry addition for "
+			   MACSTR " ifindex=%d ifname %s failed: %s",
+			   MAC2STR(addr),
+			   is_bridge ? bss->br_ifindex : bss->ifindex,
+			   is_bridge ? bss->brname : bss->ifname,
+			   nl_geterror(err));
 	} else {
-		wpa_printf(MSG_DEBUG, "nl80211: deleted bridge FDB entry for "
-			   MACSTR, MAC2STR(addr));
+		wpa_printf(MSG_DEBUG, "nl80211: added bridge FDB entry " MACSTR
+			   " to %s",
+			   MAC2STR(addr),
+			   is_bridge ? bss->brname : bss->ifname);
 	}
 
 errout:
@@ -5992,7 +6062,7 @@ static int wpa_driver_nl80211_sta_remove(struct i802_bss *bss, const u8 *addr,
 		   bss->ifname, MAC2STR(addr), ret, strerror(-ret));
 
 	if (drv->rtnl_sk)
-		rtnl_neigh_delete_fdb_entry(bss, addr);
+		rtnl_neigh_delete_fdb_entry(bss, addr, false);
 
 	if (ret == -ENOENT)
 		return 0;
@@ -7151,6 +7221,60 @@ static int nl80211_connect_common(struct wpa_driver_nl80211_data *drv,
 }
 
 
+#ifdef CONFIG_DRIVER_NL80211_QCA
+static void connect_ext_feature_set(u8 *features,
+				    enum qca_wlan_connect_ext_features idx)
+{
+	u8 *idx_byte = &features[idx / 8];
+
+	*idx_byte |= BIT(idx % 8);
+}
+#endif /* CONFIG_DRIVER_NL80211_QCA */
+
+
+static int nl80211_connect_ext(struct wpa_driver_nl80211_data *drv,
+			       struct wpa_driver_associate_params *params)
+{
+#ifdef CONFIG_DRIVER_NL80211_QCA
+	struct nl_msg *msg;
+	struct nlattr *attr;
+	u8 features[(NUM_QCA_CONNECT_EXT_FEATURES + 7) / 8] = {};
+
+	if (!drv->connect_ext_vendor_cmd_avail)
+		return -1;
+
+	wpa_printf(MSG_DEBUG, "nl80211: Connect_ext (ifindex=%d)",
+		   drv->ifindex);
+
+	if (!(msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR)) ||
+	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
+	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
+			QCA_NL80211_VENDOR_SUBCMD_CONNECT_EXT))
+		goto fail;
+
+	attr = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
+	if (!attr)
+		goto fail;
+
+	if (params->rsn_overriding) {
+		wpa_printf(MSG_DEBUG, "- RSN overriding");
+		connect_ext_feature_set(features, QCA_CONNECT_EXT_FEATURE_RSNO);
+	}
+
+	if (nla_put(msg, QCA_WLAN_VENDOR_ATTR_CONNECT_EXT_FEATURES,
+		    sizeof(features), features))
+		goto fail;
+
+	nla_nest_end(msg, attr);
+
+	return send_and_recv_cmd(drv, msg);
+fail:
+	nlmsg_free(msg);
+#endif /* CONFIG_DRIVER_NL80211_QCA */
+	return -1;
+}
+
+
 static int wpa_driver_nl80211_try_connect(
 	struct wpa_driver_nl80211_data *drv,
 	struct wpa_driver_associate_params *params,
@@ -7172,6 +7296,7 @@ static int wpa_driver_nl80211_try_connect(
 	}
 #endif /* CONFIG_DRIVER_NL80211_QCA */
 
+	nl80211_connect_ext(drv, params);
 	wpa_printf(MSG_DEBUG, "nl80211: Connect (ifindex=%d)", drv->ifindex);
 	msg = nl80211_drv_msg(drv, 0, NL80211_CMD_CONNECT);
 	if (!msg)
@@ -8508,6 +8633,7 @@ static int i802_set_wds_sta(void *priv, const u8 *addr, int aid, int val,
 	struct wpa_driver_nl80211_data *drv = bss->drv;
 	char name[IFNAMSIZ + 1];
 	union wpa_event_data event;
+	bool add_br = false;
 	int ret;
 
 	ret = os_snprintf(name, sizeof(name), "%s.sta%d", bss->ifname, aid);
@@ -8529,10 +8655,9 @@ static int i802_set_wds_sta(void *priv, const u8 *addr, int aid, int val,
 						 bss->addr, 1, NULL, NULL, 0) <
 			    0)
 				return -1;
-			if (bridge_ifname &&
-			    linux_br_add_if(drv->global->ioctl_sock,
-					    bridge_ifname, name) < 0)
-				return -1;
+
+			if (bridge_ifname)
+				add_br = true;
 
 			os_memset(&event, 0, sizeof(event));
 			event.wds_sta_interface.sta_addr = addr;
@@ -8546,6 +8671,12 @@ static int i802_set_wds_sta(void *priv, const u8 *addr, int aid, int val,
 			wpa_printf(MSG_ERROR, "nl80211: Failed to set WDS STA "
 				   "interface %s up", name);
 		}
+
+		if (add_br &&
+		    linux_br_add_if(drv->global->ioctl_sock,
+				    bridge_ifname, name) < 0)
+			return -1;
+
 		return i802_set_sta_vlan(priv, addr, name, 0,
 					 NL80211_DRV_LINK_ID_NA);
 	} else {
@@ -9532,13 +9663,14 @@ fail:
 }
 
 
-static int nl80211_remove_link(struct i802_bss *bss, int link_id)
+int nl80211_remove_link(struct i802_bss *bss, int link_id)
 {
 	struct wpa_driver_nl80211_data *drv = bss->drv;
 	struct i802_link *link;
 	struct nl_msg *msg;
 	size_t i;
 	int ret;
+	u8 link_addr[ETH_ALEN];
 
 	wpa_printf(MSG_DEBUG, "nl80211: Remove link (ifindex=%d link_id=%u)",
 		   bss->ifindex, link_id);
@@ -9553,6 +9685,7 @@ static int nl80211_remove_link(struct i802_bss *bss, int link_id)
 
 	wpa_driver_nl80211_del_beacon(bss, link_id);
 
+	os_memcpy(link_addr, link->addr, ETH_ALEN);
 	/* First remove the link locally */
 	bss->valid_links &= ~BIT(link_id);
 	os_memset(link->addr, 0, ETH_ALEN);
@@ -9590,6 +9723,9 @@ static int nl80211_remove_link(struct i802_bss *bss, int link_id)
 			   "nl80211: remove link (%d) failed. ret=%d (%s)",
 			   link_id, ret, strerror(-ret));
 
+	if (drv->rtnl_sk)
+		rtnl_neigh_delete_fdb_entry(bss, link_addr, true);
+
 	return ret;
 }
 
@@ -10342,6 +10478,8 @@ static int wpa_driver_nl80211_get_survey(void *priv, unsigned int freq)
 	int err;
 	union wpa_event_data data;
 	struct survey_results *survey_results;
+	void *ctx = (bss->scan_link && bss->scan_link->ctx) ?
+		bss->scan_link->ctx : bss->ctx;
 
 	os_memset(&data, 0, sizeof(data));
 	survey_results = &data.survey_results;
@@ -10364,7 +10502,7 @@ static int wpa_driver_nl80211_get_survey(void *priv, unsigned int freq)
 	if (err)
 		wpa_printf(MSG_ERROR, "nl80211: Failed to process survey data");
 	else
-		wpa_supplicant_event(drv->ctx, EVENT_SURVEY, &data);
+		wpa_supplicant_event(ctx, EVENT_SURVEY, &data);
 
 	clean_survey_results(survey_results);
 	return err;
@@ -10837,6 +10975,7 @@ static int driver_nl80211_link_remove(void *priv, enum wpa_driver_if_type type,
 {
 	struct i802_bss *bss = priv;
 	struct wpa_driver_nl80211_data *drv = bss->drv;
+	int ret;
 
 	if (type != WPA_IF_AP_BSS ||
 	    !nl80211_link_valid(bss->valid_links, link_id))
@@ -10856,18 +10995,25 @@ static int driver_nl80211_link_remove(void *priv, enum wpa_driver_if_type type,
 	if (!bss->valid_links) {
 		wpa_printf(MSG_DEBUG,
 			   "nl80211: No more links remaining, so remove interface");
-		return wpa_driver_nl80211_if_remove(bss, type, ifname);
+		ret = wpa_driver_nl80211_if_remove(bss, type, ifname);
+		if (ret)
+			return ret;
+
+		/* Notify that the MLD interface is removed */
+		wpa_supplicant_event(bss->ctx, EVENT_MLD_INTERFACE_FREED, NULL);
 	}
 
 	return 0;
 }
 
 
-static bool nl80211_is_drv_shared(void *priv, void *bss_ctx)
+static bool nl80211_is_drv_shared(void *priv, int link_id)
 {
 	struct i802_bss *bss = priv;
 	struct wpa_driver_nl80211_data *drv = bss->drv;
-	unsigned int num_bss = 0;
+	unsigned int num_bss = 0, num_links = 0;
+	bool self = false;
+	u8 i;
 
 	/* If any other BSS exist, someone else is using this since at this
 	 * time, we would have removed all BSSs created by this driver and only
@@ -10882,13 +11028,23 @@ static bool nl80211_is_drv_shared(void *priv, void *bss_ctx)
 	/* This is the only BSS present */
 	bss = priv;
 
-	/* If only one/no link is there no one is sharing */
-	if (bss->valid_links <= 1)
+	for_each_link(bss->valid_links, i) {
+		num_links++;
+		if (i == link_id)
+			self = true;
+	}
+
+	/* More than one links means some one is still sharing */
+	if (num_links > 1)
+		return true;
+
+	/* Even if only one link is there, it should match the given
+	 * link ID to assert that no one else is sharing. */
+	if (num_links == 1 && self)
 		return false;
 
-	/* More than one link means someone is still using. To check if
-	 * only 1 bit is set, power of 2 condition can be checked. */
-	if (!(bss->valid_links & (bss->valid_links - 1)))
+	/* No links are active means no one is sharing */
+	if (num_links == 0)
 		return false;
 
 	return true;
@@ -12623,7 +12779,7 @@ static int add_acs_ch_list(struct nl_msg *msg, const int *freq_list)
 }
 
 
-static int add_acs_freq_list(struct nl_msg *msg, const int *freq_list)
+static int add_freq_list(struct nl_msg *msg, int attr, const int *freq_list)
 {
 	int i, len, ret;
 	u32 *freqs;
@@ -12636,8 +12792,7 @@ static int add_acs_freq_list(struct nl_msg *msg, const int *freq_list)
 		return -1;
 	for (i = 0; i < len; i++)
 		freqs[i] = freq_list[i];
-	ret = nla_put(msg, QCA_WLAN_VENDOR_ATTR_ACS_FREQ_LIST,
-		      sizeof(u32) * len, freqs);
+	ret = nla_put(msg, attr, sizeof(u32) * len, freqs);
 	os_free(freqs);
 	return ret;
 }
@@ -12672,7 +12827,8 @@ static int nl80211_qca_do_acs(struct wpa_driver_nl80211_data *drv,
 	    nla_put_u16(msg, QCA_WLAN_VENDOR_ATTR_ACS_CHWIDTH,
 			params->ch_width) ||
 	    add_acs_ch_list(msg, params->freq_list) ||
-	    add_acs_freq_list(msg, params->freq_list) ||
+	    add_freq_list(msg, QCA_WLAN_VENDOR_ATTR_ACS_FREQ_LIST,
+			  params->freq_list) ||
 	    (params->edmg_enabled &&
 	     nla_put_flag(msg, QCA_WLAN_VENDOR_ATTR_ACS_EDMG_ENABLED)) ||
 	    (params->link_id != NL80211_DRV_LINK_ID_NA &&
@@ -13559,6 +13715,315 @@ fail:
 
 #endif /* CONFIG_PASN */
 
+#ifdef CONFIG_NAN_USD
+
+static int nl80211_nan_flush(void *priv)
+{
+	struct i802_bss *bss = priv;
+	struct wpa_driver_nl80211_data *drv = bss->drv;
+	struct nl_msg *msg;
+	struct nlattr *container;
+	int ret;
+
+	wpa_printf(MSG_DEBUG, "nl80211: NAN USD flush");
+
+	msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR);
+	if (!msg ||
+	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
+	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
+			QCA_NL80211_VENDOR_SUBCMD_USD))
+		goto fail;
+
+	container = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
+	if (!container ||
+	    nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_USD_OP_TYPE,
+		       QCA_WLAN_VENDOR_USD_OP_TYPE_FLUSH))
+		goto fail;
+
+	nla_nest_end(msg, container);
+
+	ret = send_and_recv_cmd(drv, msg);
+	if (ret) {
+		wpa_printf(MSG_ERROR,
+			   "nl80211: Failed to send NAN USD flush");
+		goto fail;
+	}
+	return 0;
+
+fail:
+	nlmsg_free(msg);
+	return -1;
+}
+
+
+static int nl80211_nan_publish(void *priv, const u8 *src, int publish_id,
+			       const char *service_name, const u8 *service_id,
+			       enum nan_service_protocol_type srv_proto_type,
+			       const struct wpabuf *ssi,
+			       const struct wpabuf *elems,
+			       struct nan_publish_params *params)
+{
+	struct i802_bss *bss = priv;
+	struct wpa_driver_nl80211_data *drv = bss->drv;
+	struct nl_msg *msg;
+	struct nlattr *container, *attr;
+	int ret;
+
+	wpa_printf(MSG_DEBUG,
+		   "nl80211: Start NAN USD publish: default freq=%u, ttl=%u",
+		   params->freq, params->ttl);
+	wpa_hexdump_buf(MSG_MSGDUMP, "nl80211: USD elements", elems);
+
+	msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR);
+	if (!msg ||
+	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
+	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
+			QCA_NL80211_VENDOR_SUBCMD_USD))
+		goto fail;
+
+	container = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
+	if (!container)
+		goto fail;
+
+	if (nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_USD_OP_TYPE,
+		       QCA_WLAN_VENDOR_USD_OP_TYPE_PUBLISH) ||
+	    nla_put(msg, QCA_WLAN_VENDOR_ATTR_USD_SRC_ADDR, ETH_ALEN, src) ||
+	    nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_USD_INSTANCE_ID, publish_id) ||
+	    nla_put(msg, QCA_WLAN_VENDOR_ATTR_USD_SERVICE_ID,
+		    NAN_SERVICE_ID_LEN, service_id) ||
+	    nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_USD_SERVICE_PROTOCOL_TYPE,
+		       srv_proto_type) ||
+	    nla_put_u16(msg, QCA_WLAN_VENDOR_ATTR_USD_TTL, params->ttl) ||
+	    nla_put(msg, QCA_WLAN_VENDOR_ATTR_USD_ELEMENT_CONTAINER,
+		    wpabuf_len(elems), wpabuf_head(elems)) ||
+	    (ssi && nla_put(msg, QCA_WLAN_VENDOR_ATTR_USD_SSI,
+			    wpabuf_len(ssi), wpabuf_head(ssi))))
+		goto fail;
+
+	attr = nla_nest_start(msg, QCA_WLAN_VENDOR_ATTR_USD_CHAN_CONFIG);
+	if (!attr)
+		goto fail;
+	if (nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_USD_CHAN_CONFIG_DEFAULT_FREQ,
+			params->freq) ||
+	    add_freq_list(msg, QCA_WLAN_VENDOR_ATTR_USD_CHAN_CONFIG_FREQ_LIST,
+			  params->freq_list))
+	nla_nest_end(msg, attr);
+
+	nla_nest_end(msg, container);
+	ret = send_and_recv_cmd(drv, msg);
+	if (ret) {
+		wpa_printf(MSG_ERROR,
+			   "nl80211: Failed to send NAN USD publish");
+		goto fail;
+	}
+	return 0;
+
+fail:
+	nlmsg_free(msg);
+	return -1;
+}
+
+
+static int nl80211_nan_cancel_publish(void *priv, int publish_id)
+{
+	struct i802_bss *bss = priv;
+	struct wpa_driver_nl80211_data *drv = bss->drv;
+	struct nl_msg *msg;
+	struct nlattr *container;
+	int ret;
+
+	wpa_printf(MSG_DEBUG, "nl80211: NAN USD cancel publish");
+
+	msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR);
+	if (!msg ||
+	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
+	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
+			QCA_NL80211_VENDOR_SUBCMD_USD))
+		goto fail;
+
+	container = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
+	if (!container)
+		goto fail;
+
+	if (nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_USD_OP_TYPE,
+		       QCA_WLAN_VENDOR_USD_OP_TYPE_CANCEL_PUBLISH) ||
+	    nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_USD_INSTANCE_ID,
+		       publish_id))
+		goto fail;
+
+	nla_nest_end(msg, container);
+
+	ret = send_and_recv_cmd(drv, msg);
+	if (ret) {
+		wpa_printf(MSG_ERROR,
+			   "nl80211: Failed to send NAN USD cancel publish");
+		goto fail;
+	}
+	return 0;
+
+fail:
+	nlmsg_free(msg);
+	return -1;
+}
+
+
+static int nl80211_nan_update_publish(void *priv, int publish_id,
+				      const struct wpabuf *ssi)
+{
+	struct i802_bss *bss = priv;
+	struct wpa_driver_nl80211_data *drv = bss->drv;
+	struct nl_msg *msg;
+	struct nlattr *container;
+	int ret;
+
+	wpa_printf(MSG_DEBUG, "nl80211: NAN USD update publish: id=%d",
+		   publish_id);
+
+	msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR);
+	if (!msg ||
+	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
+	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
+			QCA_NL80211_VENDOR_SUBCMD_USD))
+		goto fail;
+
+	container = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
+	if (!container)
+		goto fail;
+
+	if (nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_USD_OP_TYPE,
+		       QCA_WLAN_VENDOR_USD_OP_TYPE_UPDATE_PUBLISH) ||
+	    nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_USD_INSTANCE_ID,
+		       publish_id) ||
+	    (ssi && nla_put(msg, QCA_WLAN_VENDOR_ATTR_USD_SSI,
+			    wpabuf_len(ssi), wpabuf_head(ssi))))
+		goto fail;
+
+	nla_nest_end(msg, container);
+	ret = send_and_recv_cmd(drv, msg);
+	if (ret) {
+		wpa_printf(MSG_ERROR,
+			   "nl80211: Failed to send NAN USD update publish");
+		goto fail;
+	}
+	return 0;
+
+fail:
+	nlmsg_free(msg);
+	return -1;
+}
+
+
+static int nl80211_nan_subscribe(void *priv, const u8 *src, int subscribe_id,
+				 const char *service_name, const u8 *service_id,
+				 enum nan_service_protocol_type srv_proto_type,
+				 const struct wpabuf *ssi,
+				 const struct wpabuf *elems,
+				 struct nan_subscribe_params *params)
+{
+	struct i802_bss *bss = priv;
+	struct wpa_driver_nl80211_data *drv = bss->drv;
+	struct nl_msg *msg;
+	struct nlattr *container, *attr;
+	int ret;
+
+	wpa_printf(MSG_DEBUG,
+		   "nl80211: Start NAN USD subscribe: freq=%u, ttl=%u",
+		   params->freq, params->ttl);
+	wpa_hexdump_buf(MSG_MSGDUMP, "nl80211: USD elements", elems);
+
+	msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR);
+	if (!msg ||
+	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
+	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
+			QCA_NL80211_VENDOR_SUBCMD_USD))
+		goto fail;
+
+	container = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
+	if (!container)
+		goto fail;
+
+	if (nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_USD_OP_TYPE,
+		       QCA_WLAN_VENDOR_USD_OP_TYPE_SUBSCRIBE) ||
+	    nla_put(msg, QCA_WLAN_VENDOR_ATTR_USD_SRC_ADDR, ETH_ALEN, src) ||
+	    nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_USD_INSTANCE_ID,
+		       subscribe_id) ||
+	    nla_put(msg, QCA_WLAN_VENDOR_ATTR_USD_SERVICE_ID,
+		    NAN_SERVICE_ID_LEN, service_id) ||
+	    nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_USD_SERVICE_PROTOCOL_TYPE,
+		       srv_proto_type) ||
+	    nla_put_u16(msg, QCA_WLAN_VENDOR_ATTR_USD_TTL, params->ttl) ||
+	    nla_put(msg, QCA_WLAN_VENDOR_ATTR_USD_ELEMENT_CONTAINER,
+		    wpabuf_len(elems), wpabuf_head(elems)) ||
+	    (ssi && nla_put(msg, QCA_WLAN_VENDOR_ATTR_USD_SSI,
+			    wpabuf_len(ssi), wpabuf_head(ssi))))
+		goto fail;
+
+	attr = nla_nest_start(msg, QCA_WLAN_VENDOR_ATTR_USD_CHAN_CONFIG);
+	if (!attr ||
+	    nla_put_u32(msg, QCA_WLAN_VENDOR_ATTR_USD_CHAN_CONFIG_DEFAULT_FREQ,
+			params->freq) ||
+	    add_freq_list(msg, QCA_WLAN_VENDOR_ATTR_USD_CHAN_CONFIG_FREQ_LIST,
+			  params->freq_list))
+		goto fail;
+	nla_nest_end(msg, attr);
+
+	nla_nest_end(msg, container);
+	ret = send_and_recv_cmd(drv, msg);
+	if (ret) {
+		wpa_printf(MSG_ERROR,
+			   "nl80211: Failed to send NAN USD subscribe");
+		goto fail;
+	}
+	return 0;
+
+fail:
+	nlmsg_free(msg);
+	return -1;
+}
+
+
+static int nl80211_nan_cancel_subscribe(void *priv, int subscribe_id)
+{
+	struct i802_bss *bss = priv;
+	struct wpa_driver_nl80211_data *drv = bss->drv;
+	struct nl_msg *msg;
+	struct nlattr *container;
+	int ret;
+
+	wpa_printf(MSG_DEBUG, "nl80211: NAN USD cancel subscribe");
+
+	msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR);
+	if (!msg ||
+	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
+	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
+			QCA_NL80211_VENDOR_SUBCMD_USD))
+		goto fail;
+
+	container = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
+	if (!container ||
+	    nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_USD_OP_TYPE,
+		       QCA_WLAN_VENDOR_USD_OP_TYPE_CANCEL_SUBSCRIBE) ||
+	    nla_put_u8(msg, QCA_WLAN_VENDOR_ATTR_USD_INSTANCE_ID,
+		       subscribe_id))
+		goto fail;
+
+	nla_nest_end(msg, container);
+
+	ret = send_and_recv_cmd(drv, msg);
+	if (ret) {
+		wpa_printf(MSG_ERROR,
+			   "nl80211: Failed to send NAN USD cancel subscribe");
+		goto fail;
+	}
+	return 0;
+
+fail:
+	nlmsg_free(msg);
+	return -1;
+}
+
+#endif /* CONFIG_NAN_USD */
+
 #endif /* CONFIG_DRIVER_NL80211_QCA */
 
 
@@ -14091,6 +14556,10 @@ static int nl80211_link_add(void *priv, u8 link_id, const u8 *addr,
 
 	wpa_printf(MSG_DEBUG, "nl80211: MLD: valid_links=0x%04x on %s",
 		   bss->valid_links, bss->ifname);
+
+	if (drv->rtnl_sk)
+		rtnl_neigh_add_fdb_entry(bss, addr, true);
+
 	return 0;
 }
 
@@ -14170,6 +14639,15 @@ static int testing_nl80211_radio_disable(void *priv, int disabled)
 #endif /* CONFIG_TESTING_OPTIONS */
 
 
+static struct hostapd_multi_hw_info *
+wpa_driver_get_multi_hw_info(void *priv, unsigned int *num_multi_hws)
+{
+	struct i802_bss *bss = priv;
+
+	return nl80211_get_multi_hw_info(bss, num_multi_hws);
+}
+
+
 const struct wpa_driver_ops wpa_driver_nl80211_ops = {
 	.name = "nl80211",
 	.desc = "Linux nl80211/cfg80211",
@@ -14306,6 +14784,14 @@ const struct wpa_driver_ops wpa_driver_nl80211_ops = {
 	.send_pasn_resp = nl80211_send_pasn_resp,
 	.set_secure_ranging_ctx = nl80211_set_secure_ranging_ctx,
 #endif /* CONFIG_PASN */
+#ifdef CONFIG_NAN_USD
+	.nan_flush = nl80211_nan_flush,
+	.nan_publish = nl80211_nan_publish,
+	.nan_cancel_publish = nl80211_nan_cancel_publish,
+	.nan_update_publish = nl80211_nan_update_publish,
+	.nan_subscribe = nl80211_nan_subscribe,
+	.nan_cancel_subscribe = nl80211_nan_cancel_subscribe,
+#endif /* CONFIG_NAN_USD */
 #endif /* CONFIG_DRIVER_NL80211_QCA */
 	.do_acs = nl80211_do_acs,
 	.configure_data_frame_filters = nl80211_configure_data_frame_filters,
@@ -14328,4 +14814,5 @@ const struct wpa_driver_ops wpa_driver_nl80211_ops = {
 	.register_frame = testing_nl80211_register_frame,
 	.radio_disable = testing_nl80211_radio_disable,
 #endif /* CONFIG_TESTING_OPTIONS */
+	.get_multi_hw_info = wpa_driver_get_multi_hw_info,
 };
diff --git a/src/drivers/driver_nl80211.h b/src/drivers/driver_nl80211.h
index d2c1ffa2..bf1bf4e6 100644
--- a/src/drivers/driver_nl80211.h
+++ b/src/drivers/driver_nl80211.h
@@ -67,7 +67,7 @@ struct i802_bss {
 
 	u16 valid_links;
 	struct i802_link links[MAX_NUM_MLD_LINKS];
-	struct i802_link *flink;
+	struct i802_link *flink, *scan_link;
 
 	int ifindex;
 	int br_ifindex;
@@ -200,6 +200,7 @@ struct wpa_driver_nl80211_data {
 	unsigned int secure_ranging_ctx_vendor_cmd_avail:1;
 	unsigned int puncturing:1;
 	unsigned int qca_ap_allowed_freqs:1;
+	unsigned int connect_ext_vendor_cmd_avail:1;
 
 	u32 ignore_next_local_disconnect;
 	u32 ignore_next_local_deauth;
@@ -370,6 +371,8 @@ const char * nl80211_iftype_str(enum nl80211_iftype mode);
 
 void nl80211_restore_ap_mode(struct i802_bss *bss);
 struct i802_link * nl80211_get_link(struct i802_bss *bss, s8 link_id);
+u8 nl80211_get_link_id_from_link(struct i802_bss *bss, struct i802_link *link);
+int nl80211_remove_link(struct i802_bss *bss, int link_id);
 
 static inline bool nl80211_link_valid(u16 links, s8 link_id)
 {
@@ -427,5 +430,7 @@ int wpa_driver_nl80211_abort_scan(void *priv, u64 scan_cookie);
 int wpa_driver_nl80211_vendor_scan(struct i802_bss *bss,
 				   struct wpa_driver_scan_params *params);
 int nl80211_set_default_scan_ies(void *priv, const u8 *ies, size_t ies_len);
+struct hostapd_multi_hw_info *
+nl80211_get_multi_hw_info(struct i802_bss *bss, unsigned int *num_multi_hws);
 
 #endif /* DRIVER_NL80211_H */
diff --git a/src/drivers/driver_nl80211_capa.c b/src/drivers/driver_nl80211_capa.c
index ebf69dc1..58fb71dd 100644
--- a/src/drivers/driver_nl80211_capa.c
+++ b/src/drivers/driver_nl80211_capa.c
@@ -1119,6 +1119,9 @@ static int wiphy_info_handler(struct nl_msg *msg, void *arg)
 				case QCA_NL80211_VENDOR_SUBCMD_SECURE_RANGING_CONTEXT:
 					drv->secure_ranging_ctx_vendor_cmd_avail = 1;
 					break;
+				case QCA_NL80211_VENDOR_SUBCMD_CONNECT_EXT:
+					drv->connect_ext_vendor_cmd_avail = 1;
+					break;
 #endif /* CONFIG_DRIVER_NL80211_QCA */
 				}
 #if defined(CONFIG_DRIVER_NL80211_BRCM) || defined(CONFIG_DRIVER_NL80211_SYNA)
@@ -1457,6 +1460,8 @@ static void qca_nl80211_get_features(struct wpa_driver_nl80211_data *drv)
 			   "The driver supports RSN overriding in STA mode");
 		drv->capa.flags2 |= WPA_DRIVER_FLAGS2_RSN_OVERRIDE_STA;
 	}
+	if (check_feature(QCA_WLAN_VENDOR_FEATURE_NAN_USD_OFFLOAD, &info))
+		drv->capa.flags2 |= WPA_DRIVER_FLAGS2_NAN_OFFLOAD;
 
 	os_free(info.flags);
 }
@@ -2745,3 +2750,132 @@ nl80211_get_hw_feature_data(void *priv, u16 *num_modes, u16 *flags,
 
 	return NULL;
 }
+
+
+static int phy_multi_hw_info_parse(struct hostapd_multi_hw_info *hw_info,
+				   struct nlattr *radio_attr)
+{
+	struct nlattr *tb_freq[NL80211_WIPHY_RADIO_FREQ_ATTR_MAX + 1];
+	int start_freq, end_freq;
+
+	switch (nla_type(radio_attr)) {
+	case NL80211_WIPHY_RADIO_ATTR_INDEX:
+		hw_info->hw_idx = nla_get_u32(radio_attr);
+		return NL_OK;
+	case NL80211_WIPHY_RADIO_ATTR_FREQ_RANGE:
+		if (nla_parse_nested(tb_freq, NL80211_WIPHY_RADIO_FREQ_ATTR_MAX,
+				     radio_attr, NULL) ||
+		    !tb_freq[NL80211_WIPHY_RADIO_FREQ_ATTR_START] ||
+		    !tb_freq[NL80211_WIPHY_RADIO_FREQ_ATTR_END])
+			return NL_STOP;
+
+		start_freq = nla_get_u32(
+			tb_freq[NL80211_WIPHY_RADIO_FREQ_ATTR_START]);
+		end_freq = nla_get_u32(
+			tb_freq[NL80211_WIPHY_RADIO_FREQ_ATTR_END]);
+
+		/* Convert to MHz and store */
+		hw_info->start_freq = start_freq / 1000;
+		hw_info->end_freq = end_freq / 1000;
+		return NL_OK;
+	default:
+		return NL_OK;
+	}
+}
+
+
+struct phy_multi_hw_info_arg {
+	bool failed;
+	unsigned int *num_multi_hws;
+	struct hostapd_multi_hw_info *multi_hws;
+};
+
+
+static int phy_multi_hw_info_handler(struct nl_msg *msg, void *arg)
+{
+	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
+	struct phy_multi_hw_info_arg *multi_hw_info = arg;
+	struct hostapd_multi_hw_info *multi_hws, hw_info;
+	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
+	struct nlattr *nl_hw, *radio_attr;
+	int rem_hw, rem_radio_prop, res;
+
+	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
+		  genlmsg_attrlen(gnlh, 0), NULL);
+
+	if (!tb_msg[NL80211_ATTR_WIPHY_RADIOS])
+		return NL_SKIP;
+
+	*multi_hw_info->num_multi_hws = 0;
+
+	nla_for_each_nested(nl_hw, tb_msg[NL80211_ATTR_WIPHY_RADIOS], rem_hw) {
+		os_memset(&hw_info, 0, sizeof(hw_info));
+
+		nla_for_each_nested(radio_attr, nl_hw, rem_radio_prop) {
+			res = phy_multi_hw_info_parse(&hw_info, radio_attr);
+			if (res != NL_OK)
+				goto out;
+		}
+
+		if (hw_info.start_freq == 0 || hw_info.end_freq == 0)
+			goto out;
+
+		multi_hws = os_realloc_array(multi_hw_info->multi_hws,
+					     *multi_hw_info->num_multi_hws + 1,
+					     sizeof(*multi_hws));
+		if (!multi_hws)
+			goto out;
+
+		multi_hw_info->multi_hws = multi_hws;
+		os_memcpy(&multi_hws[*(multi_hw_info->num_multi_hws)],
+			  &hw_info, sizeof(struct hostapd_multi_hw_info));
+		*(multi_hw_info->num_multi_hws) += 1;
+	}
+
+	return NL_OK;
+out:
+	multi_hw_info->failed = true;
+	return NL_STOP;
+}
+
+
+struct hostapd_multi_hw_info *
+nl80211_get_multi_hw_info(struct i802_bss *bss, unsigned int *num_multi_hws)
+{
+	u32 feat;
+	struct wpa_driver_nl80211_data *drv = bss->drv;
+	int nl_flags = 0;
+	struct nl_msg *msg;
+	struct phy_multi_hw_info_arg result = {
+		.failed = false,
+		.num_multi_hws = num_multi_hws,
+		.multi_hws = NULL,
+	};
+
+	*num_multi_hws = 0;
+
+	if (!drv->has_capability || !(drv->capa.flags2 & WPA_DRIVER_FLAGS2_MLO))
+		return NULL;
+
+	feat = get_nl80211_protocol_features(drv);
+	if (feat & NL80211_PROTOCOL_FEATURE_SPLIT_WIPHY_DUMP)
+		nl_flags = NLM_F_DUMP;
+	if (!(msg = nl80211_cmd_msg(bss, nl_flags, NL80211_CMD_GET_WIPHY)) ||
+	    nla_put_flag(msg, NL80211_ATTR_SPLIT_WIPHY_DUMP)) {
+		nlmsg_free(msg);
+		return NULL;
+	}
+
+	if (send_and_recv_resp(drv, msg, phy_multi_hw_info_handler,
+			       &result) == 0) {
+		if (result.failed) {
+			os_free(result.multi_hws);
+			*num_multi_hws = 0;
+			return NULL;
+		}
+
+		return result.multi_hws;
+	}
+
+	return NULL;
+}
diff --git a/src/drivers/driver_nl80211_event.c b/src/drivers/driver_nl80211_event.c
index d3814409..d3017013 100644
--- a/src/drivers/driver_nl80211_event.c
+++ b/src/drivers/driver_nl80211_event.c
@@ -185,6 +185,7 @@ static const char * nl80211_command_to_string(enum nl80211_commands cmd)
 	C2S(NL80211_CMD_REMOVE_LINK_STA)
 	C2S(NL80211_CMD_SET_HW_TIMESTAMP)
 	C2S(NL80211_CMD_LINKS_REMOVED)
+	C2S(NL80211_CMD_SET_TID_TO_LINK_MAPPING)
 	C2S(__NL80211_CMD_AFTER_LAST)
 	}
 #undef C2S
@@ -1204,9 +1205,6 @@ static void mlme_event_ch_switch(struct wpa_driver_nl80211_data *drv,
 	int chan_offset = 0;
 	int ifidx;
 
-	wpa_printf(MSG_DEBUG, "nl80211: Channel switch%s event",
-		   finished ? "" : " started");
-
 	if (!freq)
 		return;
 
@@ -1218,6 +1216,9 @@ static void mlme_event_ch_switch(struct wpa_driver_nl80211_data *drv,
 		return;
 	}
 
+	wpa_printf(MSG_DEBUG, "nl80211: Channel switch%s event for %s",
+		   finished ? "" : " started", bss->ifname);
+
 	if (type) {
 		enum nl80211_channel_type ch_type = nla_get_u32(type);
 
@@ -1260,10 +1261,13 @@ static void mlme_event_ch_switch(struct wpa_driver_nl80211_data *drv,
 	if (cf2)
 		data.ch_switch.cf2 = nla_get_u32(cf2);
 
-	if (link)
+	if (link) {
 		data.ch_switch.link_id = nla_get_u8(link);
-	else
+		wpa_printf(MSG_DEBUG, "nl80211: Link ID: %d",
+			   data.ch_switch.link_id);
+	} else {
 		data.ch_switch.link_id = NL80211_DRV_LINK_ID_NA;
+	}
 
 	if (finished) {
 		if (data.ch_switch.link_id != NL80211_DRV_LINK_ID_NA) {
@@ -1300,6 +1304,14 @@ static void mlme_event_ch_switch(struct wpa_driver_nl80211_data *drv,
 			return;
 	}
 
+	if (link && is_ap_interface(drv->nlmode) &&
+	    !nl80211_link_valid(bss->valid_links, data.ch_switch.link_id)) {
+		wpa_printf(MSG_WARNING,
+			   "nl80211: Unknown link ID (%d) for channel switch (%s), ignoring",
+			   data.ch_switch.link_id, bss->ifname);
+		return;
+	}
+
 	drv->assoc_freq = data.ch_switch.freq;
 
 	wpa_supplicant_event(bss->ctx, finished ?
@@ -1965,9 +1977,10 @@ static void mlme_event_dh_event(struct wpa_driver_nl80211_data *drv,
 }
 
 
-static void send_scan_event(struct wpa_driver_nl80211_data *drv, int aborted,
+static void send_scan_event(struct i802_bss *bss, int aborted,
 			    struct nlattr *tb[], int external_scan)
 {
+	struct wpa_driver_nl80211_data *drv = bss->drv;
 	union wpa_event_data event;
 	struct nlattr *nl;
 	int rem;
@@ -1975,6 +1988,8 @@ static void send_scan_event(struct wpa_driver_nl80211_data *drv, int aborted,
 #define MAX_REPORT_FREQS 110
 	int freqs[MAX_REPORT_FREQS];
 	int num_freqs = 0;
+	struct i802_link *mld_link;
+	void *ctx = bss->ctx;
 
 	if (!external_scan && drv->scan_for_auth) {
 		drv->scan_for_auth = 0;
@@ -2038,13 +2053,30 @@ static void send_scan_event(struct wpa_driver_nl80211_data *drv, int aborted,
 			  ETH_ALEN);
 	}
 
-	wpa_supplicant_event(drv->ctx, EVENT_SCAN_RESULTS, &event);
+	/* Need to pass to the correct link ctx during AP MLD operation */
+	if (is_ap_interface(drv->nlmode)) {
+		mld_link = bss->scan_link;
+		if (!mld_link) {
+			wpa_printf(MSG_DEBUG,
+				   "nl80211: Scan event on unknown link");
+		} else if (mld_link->ctx) {
+			u8 link_id = nl80211_get_link_id_from_link(bss,
+								   mld_link);
+
+			wpa_printf(MSG_DEBUG,
+				   "nl80211: Scan event for link_id %d",
+				   link_id);
+			ctx = mld_link->ctx;
+		}
+	}
+
+	wpa_supplicant_event(ctx, EVENT_SCAN_RESULTS, &event);
 }
 
 
-static void nl80211_cqm_event(struct wpa_driver_nl80211_data *drv,
-			      struct nlattr *tb[])
+static void nl80211_cqm_event(struct i802_bss *bss, struct nlattr *tb[])
 {
+	struct wpa_driver_nl80211_data *drv = bss->drv;
 	static struct nla_policy cqm_policy[NL80211_ATTR_CQM_MAX + 1] = {
 		[NL80211_ATTR_CQM_RSSI_THOLD] = { .type = NLA_U32 },
 		[NL80211_ATTR_CQM_RSSI_HYST] = { .type = NLA_U8 },
@@ -2079,7 +2111,7 @@ static void nl80211_cqm_event(struct wpa_driver_nl80211_data *drv,
 		wpa_printf(MSG_DEBUG, "nl80211: Packet loss event for " MACSTR
 			   " (num_packets %u)",
 			   MAC2STR(ed.low_ack.addr), ed.low_ack.num_packets);
-		wpa_supplicant_event(drv->ctx, EVENT_STATION_LOW_ACK, &ed);
+		wpa_supplicant_event(bss->ctx, EVENT_STATION_LOW_ACK, &ed);
 		return;
 	}
 
@@ -2411,10 +2443,33 @@ static void nl80211_tdls_oper_event(struct wpa_driver_nl80211_data *drv,
 }
 
 
-static void nl80211_stop_ap(struct wpa_driver_nl80211_data *drv,
-			    struct nlattr **tb)
+static void nl80211_stop_ap(struct i802_bss *bss, struct nlattr **tb)
 {
-	wpa_supplicant_event(drv->ctx, EVENT_INTERFACE_UNAVAILABLE, NULL);
+	struct i802_link *mld_link = NULL;
+	void *ctx = bss->ctx;
+	int link_id = -1;
+
+	if (tb[NL80211_ATTR_MLO_LINK_ID]) {
+		link_id = nla_get_u8(tb[NL80211_ATTR_MLO_LINK_ID]);
+		if (!nl80211_link_valid(bss->valid_links, link_id)) {
+			wpa_printf(MSG_DEBUG,
+				   "nl80211: Ignoring STOP_AP event for invalid link ID %d (valid: 0x%04x)",
+				   link_id, bss->valid_links);
+			return;
+		}
+
+		mld_link = nl80211_get_link(bss, link_id);
+		wpa_printf(MSG_DEBUG,
+			   "nl80211: STOP_AP event on link %d", link_id);
+		ctx = mld_link->ctx;
+
+		/* The driver would have already deleted the link and this call
+		 * will return an error. Ignore that since nl80211_remove_link()
+		 * is called here only to update the bss->links[] state. */
+		nl80211_remove_link(bss, link_id);
+	}
+
+	wpa_supplicant_event(ctx, EVENT_INTERFACE_UNAVAILABLE, NULL);
 }
 
 
@@ -3054,7 +3109,7 @@ static void qca_nl80211_scan_done_event(struct wpa_driver_nl80211_data *drv,
 			drv->scan_state = SCAN_ABORTED;
 
 		eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv,
-				     drv->ctx);
+				     drv->first_bss->ctx);
 		drv->vendor_scan_cookie = 0;
 		drv->last_scan_cmd = 0;
 	}
@@ -3893,7 +3948,7 @@ static void do_process_drv_event(struct i802_bss *bss, int cmd,
 
 	switch (cmd) {
 	case NL80211_CMD_TRIGGER_SCAN:
-		wpa_dbg(drv->ctx, MSG_DEBUG, "nl80211: Scan trigger");
+		wpa_dbg(bss->ctx, MSG_DEBUG, "nl80211: Scan trigger");
 		drv->scan_state = SCAN_STARTED;
 		if (drv->scan_for_auth) {
 			/*
@@ -3905,40 +3960,40 @@ static void do_process_drv_event(struct i802_bss *bss, int cmd,
 			wpa_printf(MSG_DEBUG, "nl80211: Do not indicate scan-start event due to internal scan_for_auth");
 			break;
 		}
-		wpa_supplicant_event(drv->ctx, EVENT_SCAN_STARTED, NULL);
+		wpa_supplicant_event(bss->ctx, EVENT_SCAN_STARTED, NULL);
 		break;
 	case NL80211_CMD_START_SCHED_SCAN:
-		wpa_dbg(drv->ctx, MSG_DEBUG, "nl80211: Sched scan started");
+		wpa_dbg(bss->ctx, MSG_DEBUG, "nl80211: Sched scan started");
 		drv->scan_state = SCHED_SCAN_STARTED;
 		break;
 	case NL80211_CMD_SCHED_SCAN_STOPPED:
-		wpa_dbg(drv->ctx, MSG_DEBUG, "nl80211: Sched scan stopped");
+		wpa_dbg(bss->ctx, MSG_DEBUG, "nl80211: Sched scan stopped");
 		drv->scan_state = SCHED_SCAN_STOPPED;
-		wpa_supplicant_event(drv->ctx, EVENT_SCHED_SCAN_STOPPED, NULL);
+		wpa_supplicant_event(bss->ctx, EVENT_SCHED_SCAN_STOPPED, NULL);
 		break;
 	case NL80211_CMD_NEW_SCAN_RESULTS:
-		wpa_dbg(drv->ctx, MSG_DEBUG,
+		wpa_dbg(bss->ctx, MSG_DEBUG,
 			"nl80211: New scan results available");
 		if (drv->last_scan_cmd != NL80211_CMD_VENDOR)
 			drv->scan_state = SCAN_COMPLETED;
 		drv->scan_complete_events = 1;
 		if (drv->last_scan_cmd == NL80211_CMD_TRIGGER_SCAN) {
 			eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout,
-					     drv, drv->ctx);
+					     drv, bss->ctx);
 			drv->last_scan_cmd = 0;
 		} else {
 			external_scan_event = 1;
 		}
-		send_scan_event(drv, 0, tb, external_scan_event);
+		send_scan_event(bss, 0, tb, external_scan_event);
 		break;
 	case NL80211_CMD_SCHED_SCAN_RESULTS:
-		wpa_dbg(drv->ctx, MSG_DEBUG,
+		wpa_dbg(bss->ctx, MSG_DEBUG,
 			"nl80211: New sched scan results available");
 		drv->scan_state = SCHED_SCAN_RESULTS;
-		send_scan_event(drv, 0, tb, 0);
+		send_scan_event(bss, 0, tb, 0);
 		break;
 	case NL80211_CMD_SCAN_ABORTED:
-		wpa_dbg(drv->ctx, MSG_DEBUG, "nl80211: Scan aborted");
+		wpa_dbg(bss->ctx, MSG_DEBUG, "nl80211: Scan aborted");
 		if (drv->last_scan_cmd != NL80211_CMD_VENDOR)
 			drv->scan_state = SCAN_ABORTED;
 		if (drv->last_scan_cmd == NL80211_CMD_TRIGGER_SCAN) {
@@ -3947,12 +4002,12 @@ static void do_process_drv_event(struct i802_bss *bss, int cmd,
 			 * order not to make wpa_supplicant stop its scanning.
 			 */
 			eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout,
-					     drv, drv->ctx);
+					     drv, bss->ctx);
 			drv->last_scan_cmd = 0;
 		} else {
 			external_scan_event = 1;
 		}
-		send_scan_event(drv, 1, tb, external_scan_event);
+		send_scan_event(bss, 1, tb, external_scan_event);
 		break;
 	case NL80211_CMD_AUTHENTICATE:
 	case NL80211_CMD_ASSOCIATE:
@@ -4030,7 +4085,7 @@ static void do_process_drv_event(struct i802_bss *bss, int cmd,
 		mlme_event_remain_on_channel(drv, 1, tb);
 		break;
 	case NL80211_CMD_NOTIFY_CQM:
-		nl80211_cqm_event(drv, tb);
+		nl80211_cqm_event(bss, tb);
 		break;
 	case NL80211_CMD_REG_CHANGE:
 	case NL80211_CMD_WIPHY_REG_CHANGE:
@@ -4067,7 +4122,7 @@ static void do_process_drv_event(struct i802_bss *bss, int cmd,
 		nl80211_radar_event(drv, tb);
 		break;
 	case NL80211_CMD_STOP_AP:
-		nl80211_stop_ap(drv, tb);
+		nl80211_stop_ap(bss, tb);
 		break;
 	case NL80211_CMD_VENDOR:
 		nl80211_vendor_event(drv, tb);
@@ -4201,7 +4256,16 @@ int process_global_event(struct nl_msg *msg, void *arg)
 			     wdev_id == bss->wdev_id)) {
 				processed = true;
 				do_process_drv_event(bss, gnlh->cmd, tb);
-				if (!wiphy_idx_set)
+				/* There are two types of events that may need
+				 * to be delivered to multiple interfaces:
+				 * 1. Events for a wiphy, as it can have
+				 * multiple interfaces.
+				 * 2. "Global" events, like
+				 * NL80211_CMD_REG_CHANGE.
+				 *
+				 * Terminate early only if the event is directed
+				 * to a specific interface or wdev. */
+				if (ifidx != -1 || wdev_id_set)
 					return NL_SKIP;
 				/* The driver instance could have been removed,
 				 * e.g., due to NL80211_CMD_RADAR_DETECT event,
diff --git a/src/drivers/driver_nl80211_scan.c b/src/drivers/driver_nl80211_scan.c
index b055e684..d0ed7ad9 100644
--- a/src/drivers/driver_nl80211_scan.c
+++ b/src/drivers/driver_nl80211_scan.c
@@ -153,6 +153,7 @@ fail:
 void wpa_driver_nl80211_scan_timeout(void *eloop_ctx, void *timeout_ctx)
 {
 	struct wpa_driver_nl80211_data *drv = eloop_ctx;
+	struct i802_bss *bss;
 
 	wpa_printf(MSG_DEBUG, "nl80211: Scan timeout - try to abort it");
 #ifdef CONFIG_DRIVER_NL80211_QCA
@@ -160,14 +161,27 @@ void wpa_driver_nl80211_scan_timeout(void *eloop_ctx, void *timeout_ctx)
 	    nl80211_abort_vendor_scan(drv, drv->vendor_scan_cookie) == 0)
 		return;
 #endif /* CONFIG_DRIVER_NL80211_QCA */
+
+	for (bss = drv->first_bss; bss; bss = bss->next) {
+		if (bss->scan_link)
+			break;
+	}
+
+	if (!bss) {
+		wpa_printf(MSG_DEBUG, "nl80211: Failed to find scan BSS");
+		return;
+	}
+
 	if (!drv->vendor_scan_cookie &&
-	    nl80211_abort_scan(drv->first_bss) == 0)
+	    nl80211_abort_scan(bss) == 0) {
+		bss->scan_link = NULL;
 		return;
+	}
 
 	wpa_printf(MSG_DEBUG, "nl80211: Failed to abort scan");
 
 	if (drv->ap_scan_as_station != NL80211_IFTYPE_UNSPECIFIED)
-		nl80211_restore_ap_mode(drv->first_bss);
+		nl80211_restore_ap_mode(bss);
 
 	wpa_printf(MSG_DEBUG, "nl80211: Try to get scan results");
 	wpa_supplicant_event(timeout_ctx, EVENT_SCAN_RESULTS, NULL);
@@ -347,7 +361,7 @@ int wpa_driver_nl80211_scan(struct i802_bss *bss,
 	int ret = -1, timeout;
 	struct nl_msg *msg = NULL;
 
-	wpa_dbg(drv->ctx, MSG_DEBUG, "nl80211: scan request");
+	wpa_dbg(bss->ctx, MSG_DEBUG, "nl80211: scan request");
 	drv->scan_for_auth = 0;
 
 	if (TEST_FAIL())
@@ -402,6 +416,40 @@ int wpa_driver_nl80211_scan(struct i802_bss *bss,
 		wpa_printf(MSG_DEBUG, "nl80211: Scan trigger failed: ret=%d "
 			   "(%s)", ret, strerror(-ret));
 		if (drv->hostapd && is_ap_interface(drv->nlmode)) {
+#ifdef CONFIG_IEEE80211BE
+			/* For multi link BSS, retry scan if any other links
+			 * are busy scanning. */
+			if (ret == -EBUSY &&
+			    nl80211_link_valid(bss->valid_links,
+					       params->link_id)) {
+				struct i802_bss *link_bss;
+				u8 link_id;
+
+				wpa_printf(MSG_DEBUG,
+					   "nl80211: Scan trigger on multi link BSS failed (requested link=%d on interface %s)",
+					   params->link_id, bss->ifname);
+
+				for (link_bss = drv->first_bss; link_bss;
+				     link_bss = link_bss->next) {
+					if (link_bss->scan_link)
+						break;
+				}
+
+				if (!link_bss) {
+					wpa_printf(MSG_DEBUG,
+						   "nl80211: BSS information already running scan not available");
+					goto fail;
+				}
+
+				link_id = nl80211_get_link_id_from_link(
+					link_bss, link_bss->scan_link);
+				wpa_printf(MSG_DEBUG,
+					   "nl80211: Scan already running on interface %s link %d",
+					   link_bss->ifname, link_id);
+				goto fail;
+			}
+#endif /* CONFIG_IEEE80211BE */
+
 			/*
 			 * mac80211 does not allow scan requests in AP mode, so
 			 * try to do this in station mode.
@@ -435,11 +483,20 @@ int wpa_driver_nl80211_scan(struct i802_bss *bss,
 	}
 	wpa_printf(MSG_DEBUG, "Scan requested (ret=%d) - scan timeout %d "
 		   "seconds", ret, timeout);
-	eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv, drv->ctx);
+	eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv, bss->ctx);
 	eloop_register_timeout(timeout, 0, wpa_driver_nl80211_scan_timeout,
-			       drv, drv->ctx);
+			       drv, bss->ctx);
 	drv->last_scan_cmd = NL80211_CMD_TRIGGER_SCAN;
 
+	bss->scan_link = bss->flink;
+	if (is_ap_interface(drv->nlmode) &&
+	    nl80211_link_valid(bss->valid_links, params->link_id)) {
+		wpa_dbg(bss->ctx, MSG_DEBUG,
+			"nl80211: Scan requested for link %d",
+			params->link_id);
+		bss->scan_link = nl80211_get_link(bss, params->link_id);
+	}
+
 fail:
 	nlmsg_free(msg);
 	return ret;
@@ -1294,9 +1351,9 @@ int wpa_driver_nl80211_vendor_scan(struct i802_bss *bss,
 	wpa_printf(MSG_DEBUG,
 		   "nl80211: Vendor scan requested (ret=%d) - scan timeout 30 seconds, scan cookie:0x%llx",
 		   ret, (long long unsigned int) cookie);
-	eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv, drv->ctx);
+	eloop_cancel_timeout(wpa_driver_nl80211_scan_timeout, drv, bss->ctx);
 	eloop_register_timeout(30, 0, wpa_driver_nl80211_scan_timeout,
-			       drv, drv->ctx);
+			       drv, bss->ctx);
 	drv->last_scan_cmd = NL80211_CMD_VENDOR;
 
 fail:
diff --git a/src/drivers/nl80211_copy.h b/src/drivers/nl80211_copy.h
index dced2c49..f97f5adc 100644
--- a/src/drivers/nl80211_copy.h
+++ b/src/drivers/nl80211_copy.h
@@ -11,7 +11,7 @@
  * Copyright 2008 Jouni Malinen <jouni.malinen@atheros.com>
  * Copyright 2008 Colin McCabe <colin@cozybit.com>
  * Copyright 2015-2017	Intel Deutschland GmbH
- * Copyright (C) 2018-2023 Intel Corporation
+ * Copyright (C) 2018-2024 Intel Corporation
  *
  * Permission to use, copy, modify, and/or distribute this software for any
  * purpose with or without fee is hereby granted, provided that the above
@@ -72,7 +72,7 @@
  * For drivers supporting TDLS with external setup (WIPHY_FLAG_SUPPORTS_TDLS
  * and WIPHY_FLAG_TDLS_EXTERNAL_SETUP), the station lifetime is as follows:
  *  - a setup station entry is added, not yet authorized, without any rate
- *    or capability information, this just exists to avoid race conditions
+ *    or capability information; this just exists to avoid race conditions
  *  - when the TDLS setup is done, a single NL80211_CMD_SET_STATION is valid
  *    to add rate and capability information to the station and at the same
  *    time mark it authorized.
@@ -87,7 +87,7 @@
  * DOC: Frame transmission/registration support
  *
  * Frame transmission and registration support exists to allow userspace
- * management entities such as wpa_supplicant react to management frames
+ * management entities such as wpa_supplicant to react to management frames
  * that are not being handled by the kernel. This includes, for example,
  * certain classes of action frames that cannot be handled in the kernel
  * for various reasons.
@@ -113,7 +113,7 @@
  *
  * Frame transmission allows userspace to send for example the required
  * responses to action frames. It is subject to some sanity checking,
- * but many frames can be transmitted. When a frame was transmitted, its
+ * but many frames can be transmitted. When a frame is transmitted, its
  * status is indicated to the sending socket.
  *
  * For more technical details, see the corresponding command descriptions
@@ -123,7 +123,7 @@
 /**
  * DOC: Virtual interface / concurrency capabilities
  *
- * Some devices are able to operate with virtual MACs, they can have
+ * Some devices are able to operate with virtual MACs; they can have
  * more than one virtual interface. The capability handling for this
  * is a bit complex though, as there may be a number of restrictions
  * on the types of concurrency that are supported.
@@ -135,7 +135,7 @@
  * Once concurrency is desired, more attributes must be observed:
  * To start with, since some interface types are purely managed in
  * software, like the AP-VLAN type in mac80211 for example, there's
- * an additional list of these, they can be added at any time and
+ * an additional list of these; they can be added at any time and
  * are only restricted by some semantic restrictions (e.g. AP-VLAN
  * cannot be added without a corresponding AP interface). This list
  * is exported in the %NL80211_ATTR_SOFTWARE_IFTYPES attribute.
@@ -164,7 +164,7 @@
  * Packet coalesce feature helps to reduce number of received interrupts
  * to host by buffering these packets in firmware/hardware for some
  * predefined time. Received interrupt will be generated when one of the
- * following events occur.
+ * following events occurs.
  * a) Expiration of hardware timer whose expiration time is set to maximum
  * coalescing delay of matching coalesce rule.
  * b) Coalescing buffer in hardware reaches its limit.
@@ -174,7 +174,7 @@
  * rule.
  * a) Maximum coalescing delay
  * b) List of packet patterns which needs to be matched
- * c) Condition for coalescence. pattern 'match' or 'no match'
+ * c) Condition for coalescence: pattern 'match' or 'no match'
  * Multiple such rules can be created.
  */
 
@@ -213,7 +213,7 @@
 /**
  * DOC: FILS shared key authentication offload
  *
- * FILS shared key authentication offload can be advertized by drivers by
+ * FILS shared key authentication offload can be advertised by drivers by
  * setting @NL80211_EXT_FEATURE_FILS_SK_OFFLOAD flag. The drivers that support
  * FILS shared key authentication offload should be able to construct the
  * authentication and association frames for FILS shared key authentication and
@@ -239,7 +239,7 @@
  * The PMKSA can be maintained in userspace persistently so that it can be used
  * later after reboots or wifi turn off/on also.
  *
- * %NL80211_ATTR_FILS_CACHE_ID is the cache identifier advertized by a FILS
+ * %NL80211_ATTR_FILS_CACHE_ID is the cache identifier advertised by a FILS
  * capable AP supporting PMK caching. It specifies the scope within which the
  * PMKSAs are cached in an ESS. %NL80211_CMD_SET_PMKSA and
  * %NL80211_CMD_DEL_PMKSA are enhanced to allow support for PMKSA caching based
@@ -290,12 +290,12 @@
  * If the configuration needs to be applied for specific peer then the MAC
  * address of the peer needs to be passed in %NL80211_ATTR_MAC, otherwise the
  * configuration will be applied for all the connected peers in the vif except
- * any peers that have peer specific configuration for the TID by default; if
- * the %NL80211_TID_CONFIG_ATTR_OVERRIDE flag is set, peer specific values
+ * any peers that have peer-specific configuration for the TID by default; if
+ * the %NL80211_TID_CONFIG_ATTR_OVERRIDE flag is set, peer-specific values
  * will be overwritten.
  *
- * All this configuration is valid only for STA's current connection
- * i.e. the configuration will be reset to default when the STA connects back
+ * All this configuration is valid only for STA's current connection,
+ * i.e., the configuration will be reset to default when the STA connects back
  * after disconnection/roaming, and this configuration will be cleared when
  * the interface goes down.
  */
@@ -413,8 +413,8 @@
  *	are like for %NL80211_CMD_SET_BEACON, and additionally parameters that
  *	do not change are used, these include %NL80211_ATTR_BEACON_INTERVAL,
  *	%NL80211_ATTR_DTIM_PERIOD, %NL80211_ATTR_SSID,
- *	%NL80211_ATTR_HIDDEN_SSID, %NL80211_ATTR_CIPHERS_PAIRWISE,
- *	%NL80211_ATTR_CIPHER_GROUP, %NL80211_ATTR_WPA_VERSIONS,
+ *	%NL80211_ATTR_HIDDEN_SSID, %NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
+ *	%NL80211_ATTR_CIPHER_SUITE_GROUP, %NL80211_ATTR_WPA_VERSIONS,
  *	%NL80211_ATTR_AKM_SUITES, %NL80211_ATTR_PRIVACY,
  *	%NL80211_ATTR_AUTH_TYPE, %NL80211_ATTR_INACTIVITY_TIMEOUT,
  *	%NL80211_ATTR_ACL_POLICY and %NL80211_ATTR_MAC_ADDRS.
@@ -438,23 +438,19 @@
  *	%NL80211_ATTR_REASON_CODE can optionally be used to specify which type
  *	of disconnection indication should be sent to the station
  *	(Deauthentication or Disassociation frame and reason code for that
- *	frame).
+ *	frame). %NL80211_ATTR_MLO_LINK_ID can be used optionally to remove
+ *	stations connected and using at least that link as one of its links.
  *
  * @NL80211_CMD_GET_MPATH: Get mesh path attributes for mesh path to
- * 	destination %NL80211_ATTR_MAC on the interface identified by
- * 	%NL80211_ATTR_IFINDEX.
+ *	destination %NL80211_ATTR_MAC on the interface identified by
+ *	%NL80211_ATTR_IFINDEX.
  * @NL80211_CMD_SET_MPATH:  Set mesh path attributes for mesh path to
- * 	destination %NL80211_ATTR_MAC on the interface identified by
- * 	%NL80211_ATTR_IFINDEX.
+ *	destination %NL80211_ATTR_MAC on the interface identified by
+ *	%NL80211_ATTR_IFINDEX.
  * @NL80211_CMD_NEW_MPATH: Create a new mesh path for the destination given by
  *	%NL80211_ATTR_MAC via %NL80211_ATTR_MPATH_NEXT_HOP.
  * @NL80211_CMD_DEL_MPATH: Delete a mesh path to the destination given by
  *	%NL80211_ATTR_MAC.
- * @NL80211_CMD_NEW_PATH: Add a mesh path with given attributes to the
- *	interface identified by %NL80211_ATTR_IFINDEX.
- * @NL80211_CMD_DEL_PATH: Remove a mesh path identified by %NL80211_ATTR_MAC
- *	or, if no MAC address given, all mesh paths, on the interface identified
- *	by %NL80211_ATTR_IFINDEX.
  * @NL80211_CMD_SET_BSS: Set BSS attributes for BSS identified by
  *	%NL80211_ATTR_IFINDEX.
  *
@@ -475,15 +471,15 @@
  *	after being queried by the kernel. CRDA replies by sending a regulatory
  *	domain structure which consists of %NL80211_ATTR_REG_ALPHA set to our
  *	current alpha2 if it found a match. It also provides
- * 	NL80211_ATTR_REG_RULE_FLAGS, and a set of regulatory rules. Each
- * 	regulatory rule is a nested set of attributes  given by
- * 	%NL80211_ATTR_REG_RULE_FREQ_[START|END] and
- * 	%NL80211_ATTR_FREQ_RANGE_MAX_BW with an attached power rule given by
- * 	%NL80211_ATTR_REG_RULE_POWER_MAX_ANT_GAIN and
- * 	%NL80211_ATTR_REG_RULE_POWER_MAX_EIRP.
+ *	NL80211_ATTR_REG_RULE_FLAGS, and a set of regulatory rules. Each
+ *	regulatory rule is a nested set of attributes  given by
+ *	%NL80211_ATTR_REG_RULE_FREQ_[START|END] and
+ *	%NL80211_ATTR_FREQ_RANGE_MAX_BW with an attached power rule given by
+ *	%NL80211_ATTR_REG_RULE_POWER_MAX_ANT_GAIN and
+ *	%NL80211_ATTR_REG_RULE_POWER_MAX_EIRP.
  * @NL80211_CMD_REQ_SET_REG: ask the wireless core to set the regulatory domain
- * 	to the specified ISO/IEC 3166-1 alpha2 country code. The core will
- * 	store this as a valid request and then query userspace for it.
+ *	to the specified ISO/IEC 3166-1 alpha2 country code. The core will
+ *	store this as a valid request and then query userspace for it.
  *
  * @NL80211_CMD_GET_MESH_CONFIG: Get mesh networking properties for the
  *	interface identified by %NL80211_ATTR_IFINDEX
@@ -521,7 +517,7 @@
  *	%NL80211_ATTR_SCHED_SCAN_PLANS. If %NL80211_ATTR_SCHED_SCAN_PLANS is
  *	not specified and only %NL80211_ATTR_SCHED_SCAN_INTERVAL is specified,
  *	scheduled scan will run in an infinite loop with the specified interval.
- *	These attributes are mutually exculsive,
+ *	These attributes are mutually exclusive,
  *	i.e. NL80211_ATTR_SCHED_SCAN_INTERVAL must not be passed if
  *	NL80211_ATTR_SCHED_SCAN_PLANS is defined.
  *	If for some reason scheduled scan is aborted by the driver, all scan
@@ -552,7 +548,7 @@
  *	%NL80211_CMD_STOP_SCHED_SCAN command is received or when the interface
  *	is brought down while a scheduled scan was running.
  *
- * @NL80211_CMD_GET_SURVEY: get survey resuls, e.g. channel occupation
+ * @NL80211_CMD_GET_SURVEY: get survey results, e.g. channel occupation
  *      or noise level
  * @NL80211_CMD_NEW_SURVEY_RESULTS: survey data notification (as a reply to
  *	NL80211_CMD_GET_SURVEY and on the "scan" multicast group)
@@ -563,40 +559,41 @@
  *	using %NL80211_ATTR_SSID, %NL80211_ATTR_FILS_CACHE_ID,
  *	%NL80211_ATTR_PMKID, and %NL80211_ATTR_PMK in case of FILS
  *	authentication where %NL80211_ATTR_FILS_CACHE_ID is the identifier
- *	advertized by a FILS capable AP identifying the scope of PMKSA in an
+ *	advertised by a FILS capable AP identifying the scope of PMKSA in an
  *	ESS.
  * @NL80211_CMD_DEL_PMKSA: Delete a PMKSA cache entry, using %NL80211_ATTR_MAC
  *	(for the BSSID) and %NL80211_ATTR_PMKID or using %NL80211_ATTR_SSID,
  *	%NL80211_ATTR_FILS_CACHE_ID, and %NL80211_ATTR_PMKID in case of FILS
- *	authentication.
+ *	authentication. Additionally in case of SAE offload and OWE offloads
+ *	PMKSA entry can be deleted using %NL80211_ATTR_SSID.
  * @NL80211_CMD_FLUSH_PMKSA: Flush all PMKSA cache entries.
  *
  * @NL80211_CMD_REG_CHANGE: indicates to userspace the regulatory domain
- * 	has been changed and provides details of the request information
- * 	that caused the change such as who initiated the regulatory request
- * 	(%NL80211_ATTR_REG_INITIATOR), the wiphy_idx
- * 	(%NL80211_ATTR_REG_ALPHA2) on which the request was made from if
- * 	the initiator was %NL80211_REGDOM_SET_BY_COUNTRY_IE or
- * 	%NL80211_REGDOM_SET_BY_DRIVER, the type of regulatory domain
- * 	set (%NL80211_ATTR_REG_TYPE), if the type of regulatory domain is
- * 	%NL80211_REG_TYPE_COUNTRY the alpha2 to which we have moved on
- * 	to (%NL80211_ATTR_REG_ALPHA2).
+ *	has been changed and provides details of the request information
+ *	that caused the change such as who initiated the regulatory request
+ *	(%NL80211_ATTR_REG_INITIATOR), the wiphy_idx
+ *	(%NL80211_ATTR_REG_ALPHA2) on which the request was made from if
+ *	the initiator was %NL80211_REGDOM_SET_BY_COUNTRY_IE or
+ *	%NL80211_REGDOM_SET_BY_DRIVER, the type of regulatory domain
+ *	set (%NL80211_ATTR_REG_TYPE), if the type of regulatory domain is
+ *	%NL80211_REG_TYPE_COUNTRY the alpha2 to which we have moved on
+ *	to (%NL80211_ATTR_REG_ALPHA2).
  * @NL80211_CMD_REG_BEACON_HINT: indicates to userspace that an AP beacon
- * 	has been found while world roaming thus enabling active scan or
- * 	any mode of operation that initiates TX (beacons) on a channel
- * 	where we would not have been able to do either before. As an example
- * 	if you are world roaming (regulatory domain set to world or if your
- * 	driver is using a custom world roaming regulatory domain) and while
- * 	doing a passive scan on the 5 GHz band you find an AP there (if not
- * 	on a DFS channel) you will now be able to actively scan for that AP
- * 	or use AP mode on your card on that same channel. Note that this will
- * 	never be used for channels 1-11 on the 2 GHz band as they are always
- * 	enabled world wide. This beacon hint is only sent if your device had
- * 	either disabled active scanning or beaconing on a channel. We send to
- * 	userspace the wiphy on which we removed a restriction from
- * 	(%NL80211_ATTR_WIPHY) and the channel on which this occurred
- * 	before (%NL80211_ATTR_FREQ_BEFORE) and after (%NL80211_ATTR_FREQ_AFTER)
- * 	the beacon hint was processed.
+ *	has been found while world roaming thus enabling active scan or
+ *	any mode of operation that initiates TX (beacons) on a channel
+ *	where we would not have been able to do either before. As an example
+ *	if you are world roaming (regulatory domain set to world or if your
+ *	driver is using a custom world roaming regulatory domain) and while
+ *	doing a passive scan on the 5 GHz band you find an AP there (if not
+ *	on a DFS channel) you will now be able to actively scan for that AP
+ *	or use AP mode on your card on that same channel. Note that this will
+ *	never be used for channels 1-11 on the 2 GHz band as they are always
+ *	enabled world wide. This beacon hint is only sent if your device had
+ *	either disabled active scanning or beaconing on a channel. We send to
+ *	userspace the wiphy on which we removed a restriction from
+ *	(%NL80211_ATTR_WIPHY) and the channel on which this occurred
+ *	before (%NL80211_ATTR_FREQ_BEFORE) and after (%NL80211_ATTR_FREQ_AFTER)
+ *	the beacon hint was processed.
  *
  * @NL80211_CMD_AUTHENTICATE: authentication request and notification.
  *	This command is used both as a command (request to authenticate) and
@@ -607,7 +604,7 @@
  *	BSSID in case of station mode). %NL80211_ATTR_SSID is used to specify
  *	the SSID (mainly for association, but is included in authentication
  *	request, too, to help BSS selection. %NL80211_ATTR_WIPHY_FREQ +
- *	%NL80211_ATTR_WIPHY_FREQ_OFFSET is used to specify the frequence of the
+ *	%NL80211_ATTR_WIPHY_FREQ_OFFSET is used to specify the frequency of the
  *	channel in MHz. %NL80211_ATTR_AUTH_TYPE is used to specify the
  *	authentication type. %NL80211_ATTR_IE is used to define IEs
  *	(VendorSpecificInfo, but also including RSN IE and FT IEs) to be added
@@ -816,7 +813,7 @@
  *	reached.
  * @NL80211_CMD_SET_CHANNEL: Set the channel (using %NL80211_ATTR_WIPHY_FREQ
  *	and the attributes determining channel width) the given interface
- *	(identifed by %NL80211_ATTR_IFINDEX) shall operate on.
+ *	(identified by %NL80211_ATTR_IFINDEX) shall operate on.
  *	In case multiple channels are supported by the device, the mechanism
  *	with which it switches channels is implementation-defined.
  *	When a monitor interface is given, it can only switch channel while
@@ -888,7 +885,7 @@
  *	inform userspace of the new replay counter.
  *
  * @NL80211_CMD_PMKSA_CANDIDATE: This is used as an event to inform userspace
- *	of PMKSA caching dandidates.
+ *	of PMKSA caching candidates.
  *
  * @NL80211_CMD_TDLS_OPER: Perform a high-level TDLS command (e.g. link setup).
  *	In addition, this can be used as an event to request userspace to take
@@ -924,7 +921,7 @@
  *
  * @NL80211_CMD_PROBE_CLIENT: Probe an associated station on an AP interface
  *	by sending a null data frame to it and reporting when the frame is
- *	acknowleged. This is used to allow timing out inactive clients. Uses
+ *	acknowledged. This is used to allow timing out inactive clients. Uses
  *	%NL80211_ATTR_IFINDEX and %NL80211_ATTR_MAC. The command returns a
  *	direct reply with an %NL80211_ATTR_COOKIE that is later used to match
  *	up the event with the request. The event includes the same data and
@@ -1118,7 +1115,7 @@
  *	current configuration is not changed.  If it is present but
  *	set to zero, the configuration is changed to don't-care
  *	(i.e. the device can decide what to do).
- * @NL80211_CMD_NAN_FUNC_MATCH: Notification sent when a match is reported.
+ * @NL80211_CMD_NAN_MATCH: Notification sent when a match is reported.
  *	This will contain a %NL80211_ATTR_NAN_MATCH nested attribute and
  *	%NL80211_ATTR_COOKIE.
  *
@@ -1135,11 +1132,15 @@
  * @NL80211_CMD_DEL_PMK: For offloaded 4-Way handshake, delete the previously
  *	configured PMK for the authenticator address identified by
  *	%NL80211_ATTR_MAC.
- * @NL80211_CMD_PORT_AUTHORIZED: An event that indicates an 802.1X FT roam was
- *	completed successfully. Drivers that support 4 way handshake offload
- *	should send this event after indicating 802.1X FT assocation with
- *	%NL80211_CMD_ROAM. If the 4 way handshake failed %NL80211_CMD_DISCONNECT
- *	should be indicated instead.
+ * @NL80211_CMD_PORT_AUTHORIZED: An event that indicates port is authorized and
+ *	open for regular data traffic. For STA/P2P-client, this event is sent
+ *	with AP MAC address and for AP/P2P-GO, the event carries the STA/P2P-
+ *	client MAC address.
+ *	Drivers that support 4 way handshake offload should send this event for
+ *	STA/P2P-client after successful 4-way HS or after 802.1X FT following
+ *	NL80211_CMD_CONNECT or NL80211_CMD_ROAM. Drivers using AP/P2P-GO 4-way
+ *	handshake offload should send this event on successful completion of
+ *	4-way handshake with the peer (STA/P2P-client).
  * @NL80211_CMD_CONTROL_PORT_FRAME: Control Port (e.g. PAE) frame TX request
  *	and RX notification.  This command is used both as a request to transmit
  *	a control port frame and as a notification that a control port frame
@@ -1323,6 +1324,11 @@
  *	Multi-Link reconfiguration. %NL80211_ATTR_MLO_LINKS is used to provide
  *	information about the removed STA MLD setup links.
  *
+ * @NL80211_CMD_SET_TID_TO_LINK_MAPPING: Set the TID to Link Mapping for a
+ *      non-AP MLD station. The %NL80211_ATTR_MLO_TTLM_DLINK and
+ *      %NL80211_ATTR_MLO_TTLM_ULINK attributes are used to specify the
+ *      TID to Link mapping for downlink/uplink traffic.
+ *
  * @NL80211_CMD_MAX: highest used command number
  * @__NL80211_CMD_AFTER_LAST: internal use
  */
@@ -1578,6 +1584,8 @@ enum nl80211_commands {
 
 	NL80211_CMD_LINKS_REMOVED,
 
+	NL80211_CMD_SET_TID_TO_LINK_MAPPING,
+
 	/* add new commands above here */
 
 	/* used to define NL80211_CMD_MAX below */
@@ -1702,21 +1710,21 @@ enum nl80211_commands {
  *	(see &enum nl80211_plink_action).
  * @NL80211_ATTR_MPATH_NEXT_HOP: MAC address of the next hop for a mesh path.
  * @NL80211_ATTR_MPATH_INFO: information about a mesh_path, part of mesh path
- * 	info given for %NL80211_CMD_GET_MPATH, nested attribute described at
+ *	info given for %NL80211_CMD_GET_MPATH, nested attribute described at
  *	&enum nl80211_mpath_info.
  *
  * @NL80211_ATTR_MNTR_FLAGS: flags, nested element with NLA_FLAG attributes of
  *      &enum nl80211_mntr_flags.
  *
  * @NL80211_ATTR_REG_ALPHA2: an ISO-3166-alpha2 country code for which the
- * 	current regulatory domain should be set to or is already set to.
- * 	For example, 'CR', for Costa Rica. This attribute is used by the kernel
- * 	to query the CRDA to retrieve one regulatory domain. This attribute can
- * 	also be used by userspace to query the kernel for the currently set
- * 	regulatory domain. We chose an alpha2 as that is also used by the
- * 	IEEE-802.11 country information element to identify a country.
- * 	Users can also simply ask the wireless core to set regulatory domain
- * 	to a specific alpha2.
+ *	current regulatory domain should be set to or is already set to.
+ *	For example, 'CR', for Costa Rica. This attribute is used by the kernel
+ *	to query the CRDA to retrieve one regulatory domain. This attribute can
+ *	also be used by userspace to query the kernel for the currently set
+ *	regulatory domain. We chose an alpha2 as that is also used by the
+ *	IEEE-802.11 country information element to identify a country.
+ *	Users can also simply ask the wireless core to set regulatory domain
+ *	to a specific alpha2.
  * @NL80211_ATTR_REG_RULES: a nested array of regulatory domain regulatory
  *	rules.
  *
@@ -1759,9 +1767,9 @@ enum nl80211_commands {
  * @NL80211_ATTR_BSS: scan result BSS
  *
  * @NL80211_ATTR_REG_INITIATOR: indicates who requested the regulatory domain
- * 	currently in effect. This could be any of the %NL80211_REGDOM_SET_BY_*
+ *	currently in effect. This could be any of the %NL80211_REGDOM_SET_BY_*
  * @NL80211_ATTR_REG_TYPE: indicates the type of the regulatory domain currently
- * 	set. This can be one of the nl80211_reg_type (%NL80211_REGDOM_TYPE_*)
+ *	set. This can be one of the nl80211_reg_type (%NL80211_REGDOM_TYPE_*)
  *
  * @NL80211_ATTR_SUPPORTED_COMMANDS: wiphy attribute that specifies
  *	an array of command numbers (i.e. a mapping index to command number)
@@ -1780,15 +1788,15 @@ enum nl80211_commands {
  *	a u32
  *
  * @NL80211_ATTR_FREQ_BEFORE: A channel which has suffered a regulatory change
- * 	due to considerations from a beacon hint. This attribute reflects
- * 	the state of the channel _before_ the beacon hint processing. This
- * 	attributes consists of a nested attribute containing
- * 	NL80211_FREQUENCY_ATTR_*
+ *	due to considerations from a beacon hint. This attribute reflects
+ *	the state of the channel _before_ the beacon hint processing. This
+ *	attributes consists of a nested attribute containing
+ *	NL80211_FREQUENCY_ATTR_*
  * @NL80211_ATTR_FREQ_AFTER: A channel which has suffered a regulatory change
- * 	due to considerations from a beacon hint. This attribute reflects
- * 	the state of the channel _after_ the beacon hint processing. This
- * 	attributes consists of a nested attribute containing
- * 	NL80211_FREQUENCY_ATTR_*
+ *	due to considerations from a beacon hint. This attribute reflects
+ *	the state of the channel _after_ the beacon hint processing. This
+ *	attributes consists of a nested attribute containing
+ *	NL80211_FREQUENCY_ATTR_*
  *
  * @NL80211_ATTR_CIPHER_SUITES: a set of u32 values indicating the supported
  *	cipher suites
@@ -1835,7 +1843,7 @@ enum nl80211_commands {
  *	using %CMD_CONTROL_PORT_FRAME.  If control port routing over NL80211 is
  *	to be used then userspace must also use the %NL80211_ATTR_SOCKET_OWNER
  *	flag. When used with %NL80211_ATTR_CONTROL_PORT_NO_PREAUTH, pre-auth
- *	frames are not forwared over the control port.
+ *	frames are not forwarded over the control port.
  *
  * @NL80211_ATTR_TESTDATA: Testmode data blob, passed through to the driver.
  *	We recommend using nested, driver-specific attributes within this.
@@ -1849,12 +1857,6 @@ enum nl80211_commands {
  *	that protected APs should be used. This is also used with NEW_BEACON to
  *	indicate that the BSS is to use protection.
  *
- * @NL80211_ATTR_CIPHERS_PAIRWISE: Used with CONNECT, ASSOCIATE, and NEW_BEACON
- *	to indicate which unicast key ciphers will be used with the connection
- *	(an array of u32).
- * @NL80211_ATTR_CIPHER_GROUP: Used with CONNECT, ASSOCIATE, and NEW_BEACON to
- *	indicate which group key cipher will be used with the connection (a
- *	u32).
  * @NL80211_ATTR_WPA_VERSIONS: Used with CONNECT, ASSOCIATE, and NEW_BEACON to
  *	indicate which WPA version(s) the AP we want to associate with is using
  *	(a u32 with flags from &enum nl80211_wpa_versions).
@@ -1885,6 +1887,7 @@ enum nl80211_commands {
  *	with %NL80211_KEY_* sub-attributes
  *
  * @NL80211_ATTR_PID: Process ID of a network namespace.
+ * @NL80211_ATTR_NETNS_FD: File descriptor of a network namespace.
  *
  * @NL80211_ATTR_GENERATION: Used to indicate consistent snapshots for
  *	dumps. This number increases whenever the object list being
@@ -1939,6 +1942,7 @@ enum nl80211_commands {
  *
  * @NL80211_ATTR_ACK: Flag attribute indicating that the frame was
  *	acknowledged by the recipient.
+ * @NL80211_ATTR_ACK_SIGNAL: Station's ack signal strength (s32)
  *
  * @NL80211_ATTR_PS_STATE: powersave state, using &enum nl80211_ps_state values.
  *
@@ -1972,10 +1976,10 @@ enum nl80211_commands {
  *	bit. Depending on which antennas are selected in the bitmap, 802.11n
  *	drivers can derive which chainmasks to use (if all antennas belonging to
  *	a particular chain are disabled this chain should be disabled) and if
- *	a chain has diversity antennas wether diversity should be used or not.
+ *	a chain has diversity antennas whether diversity should be used or not.
  *	HT capabilities (STBC, TX Beamforming, Antenna selection) can be
  *	derived from the available chains after applying the antenna mask.
- *	Non-802.11n drivers can derive wether to use diversity or not.
+ *	Non-802.11n drivers can derive whether to use diversity or not.
  *	Drivers may reject configurations or RX/TX mask combinations they cannot
  *	support by returning -EINVAL.
  *
@@ -2048,6 +2052,10 @@ enum nl80211_commands {
  * @NL80211_ATTR_INTERFACE_COMBINATIONS: Nested attribute listing the supported
  *	interface combinations. In each nested item, it contains attributes
  *	defined in &enum nl80211_if_combination_attrs.
+ *	If the wiphy uses multiple radios (@NL80211_ATTR_WIPHY_RADIOS is set),
+ *	this attribute contains the interface combinations of the first radio.
+ *	See @NL80211_ATTR_WIPHY_INTERFACE_COMBINATIONS for the global wiphy
+ *	combinations for the sum of all radios.
  * @NL80211_ATTR_SOFTWARE_IFTYPES: Nested attribute (just like
  *	%NL80211_ATTR_SUPPORTED_IFTYPES) containing the interface types that
  *	are managed in software: interfaces of these types aren't subject to
@@ -2136,6 +2144,9 @@ enum nl80211_commands {
  * @NL80211_ATTR_DISABLE_HE: Force HE capable interfaces to disable
  *      this feature during association. This is a flag attribute.
  *	Currently only supported in mac80211 drivers.
+ * @NL80211_ATTR_DISABLE_EHT: Force EHT capable interfaces to disable
+ *      this feature during association. This is a flag attribute.
+ *	Currently only supported in mac80211 drivers.
  * @NL80211_ATTR_HT_CAPABILITY_MASK: Specify which bits of the
  *      ATTR_HT_CAPABILITY to which attention should be paid.
  *      Currently, only mac80211 NICs support this feature.
@@ -2145,6 +2156,12 @@ enum nl80211_commands {
  *      All values are treated as suggestions and may be ignored
  *      by the driver as required.  The actual values may be seen in
  *      the station debugfs ht_caps file.
+ * @NL80211_ATTR_VHT_CAPABILITY_MASK: Specify which bits of the
+ *      ATTR_VHT_CAPABILITY to which attention should be paid.
+ *      Currently, only mac80211 NICs support this feature.
+ *      All values are treated as suggestions and may be ignored
+ *      by the driver as required.  The actual values may be seen in
+ *      the station debugfs vht_caps file.
  *
  * @NL80211_ATTR_DFS_REGION: region for regulatory rules which this country
  *    abides to when initiating radiation on DFS channels. A country maps
@@ -2403,7 +2420,7 @@ enum nl80211_commands {
  *	scheduled scan is started.  Or the delay before a WoWLAN
  *	net-detect scan is started, counting from the moment the
  *	system is suspended.  This value is a u32, in seconds.
-
+ *
  * @NL80211_ATTR_REG_INDOOR: flag attribute, if set indicates that the device
  *      is operating in an indoor environment.
  *
@@ -2545,7 +2562,7 @@ enum nl80211_commands {
  *	from successful FILS authentication and is used with
  *	%NL80211_CMD_CONNECT.
  *
- * @NL80211_ATTR_FILS_CACHE_ID: A 2-octet identifier advertized by a FILS AP
+ * @NL80211_ATTR_FILS_CACHE_ID: A 2-octet identifier advertised by a FILS AP
  *	identifying the scope of PMKSAs. This is used with
  *	@NL80211_CMD_SET_PMKSA and @NL80211_CMD_DEL_PMKSA.
  *
@@ -2826,6 +2843,31 @@ enum nl80211_commands {
  * @NL80211_ATTR_MLO_LINK_DISABLED: Flag attribute indicating that the link is
  *	disabled.
  *
+ * @NL80211_ATTR_BSS_DUMP_INCLUDE_USE_DATA: Include BSS usage data, i.e.
+ *	include BSSes that can only be used in restricted scenarios and/or
+ *	cannot be used at all.
+ *
+ * @NL80211_ATTR_MLO_TTLM_DLINK: Binary attribute specifying the downlink TID to
+ *      link mapping. The length is 8 * sizeof(u16). For each TID the link
+ *      mapping is as defined in section 9.4.2.314 (TID-To-Link Mapping element)
+ *      in Draft P802.11be_D4.0.
+ * @NL80211_ATTR_MLO_TTLM_ULINK: Binary attribute specifying the uplink TID to
+ *      link mapping. The length is 8 * sizeof(u16). For each TID the link
+ *      mapping is as defined in section 9.4.2.314 (TID-To-Link Mapping element)
+ *      in Draft P802.11be_D4.0.
+ *
+ * @NL80211_ATTR_ASSOC_SPP_AMSDU: flag attribute used with
+ *	%NL80211_CMD_ASSOCIATE indicating the SPP A-MSDUs
+ *	are used on this connection
+ *
+ * @NL80211_ATTR_WIPHY_RADIOS: Nested attribute describing physical radios
+ *	belonging to this wiphy. See &enum nl80211_wiphy_radio_attrs.
+ *
+ * @NL80211_ATTR_WIPHY_INTERFACE_COMBINATIONS: Nested attribute listing the
+ *	supported interface combinations for all radios combined. In each
+ *	nested item, it contains attributes defined in
+ *	&enum nl80211_if_combination_attrs.
+ *
  * @NUM_NL80211_ATTR: total number of nl80211_attrs available
  * @NL80211_ATTR_MAX: highest attribute number currently defined
  * @__NL80211_ATTR_AFTER_LAST: internal use
@@ -3364,6 +3406,16 @@ enum nl80211_attrs {
 
 	NL80211_ATTR_MLO_LINK_DISABLED,
 
+	NL80211_ATTR_BSS_DUMP_INCLUDE_USE_DATA,
+
+	NL80211_ATTR_MLO_TTLM_DLINK,
+	NL80211_ATTR_MLO_TTLM_ULINK,
+
+	NL80211_ATTR_ASSOC_SPP_AMSDU,
+
+	NL80211_ATTR_WIPHY_RADIOS,
+	NL80211_ATTR_WIPHY_INTERFACE_COMBINATIONS,
+
 	/* add attributes here, update the policy in nl80211.c */
 
 	__NL80211_ATTR_AFTER_LAST,
@@ -3504,6 +3556,7 @@ enum nl80211_iftype {
  * @NL80211_STA_FLAG_ASSOCIATED: station is associated; used with drivers
  *	that support %NL80211_FEATURE_FULL_AP_CLIENT_STATE to transition a
  *	previously added station into associated state
+ * @NL80211_STA_FLAG_SPP_AMSDU: station supports SPP A-MSDUs
  * @NL80211_STA_FLAG_MAX: highest station flag number currently defined
  * @__NL80211_STA_FLAG_AFTER_LAST: internal use
  */
@@ -3516,6 +3569,7 @@ enum nl80211_sta_flags {
 	NL80211_STA_FLAG_AUTHENTICATED,
 	NL80211_STA_FLAG_TDLS_PEER,
 	NL80211_STA_FLAG_ASSOCIATED,
+	NL80211_STA_FLAG_SPP_AMSDU,
 
 	/* keep last */
 	__NL80211_STA_FLAG_AFTER_LAST,
@@ -3526,7 +3580,7 @@ enum nl80211_sta_flags {
  * enum nl80211_sta_p2p_ps_status - station support of P2P PS
  *
  * @NL80211_P2P_PS_UNSUPPORTED: station doesn't support P2P PS mechanism
- * @@NL80211_P2P_PS_SUPPORTED: station supports P2P PS mechanism
+ * @NL80211_P2P_PS_SUPPORTED: station supports P2P PS mechanism
  * @NUM_NL80211_P2P_PS_STATUS: number of values
  */
 enum nl80211_sta_p2p_ps_status {
@@ -3564,9 +3618,9 @@ enum nl80211_he_gi {
 
 /**
  * enum nl80211_he_ltf - HE long training field
- * @NL80211_RATE_INFO_HE_1xLTF: 3.2 usec
- * @NL80211_RATE_INFO_HE_2xLTF: 6.4 usec
- * @NL80211_RATE_INFO_HE_4xLTF: 12.8 usec
+ * @NL80211_RATE_INFO_HE_1XLTF: 3.2 usec
+ * @NL80211_RATE_INFO_HE_2XLTF: 6.4 usec
+ * @NL80211_RATE_INFO_HE_4XLTF: 12.8 usec
  */
 enum nl80211_he_ltf {
 	NL80211_RATE_INFO_HE_1XLTF,
@@ -3681,7 +3735,7 @@ enum nl80211_eht_ru_alloc {
  * @NL80211_RATE_INFO_HE_GI: HE guard interval identifier
  *	(u8, see &enum nl80211_he_gi)
  * @NL80211_RATE_INFO_HE_DCM: HE DCM value (u8, 0/1)
- * @NL80211_RATE_INFO_RU_ALLOC: HE RU allocation, if not present then
+ * @NL80211_RATE_INFO_HE_RU_ALLOC: HE RU allocation, if not present then
  *	non-OFDMA was used (u8, see &enum nl80211_he_ru_alloc)
  * @NL80211_RATE_INFO_320_MHZ_WIDTH: 320 MHz bitrate
  * @NL80211_RATE_INFO_EHT_MCS: EHT MCS index (u8, 0-15)
@@ -3784,7 +3838,7 @@ enum nl80211_sta_bss_param {
  *	(u64, to this station)
  * @NL80211_STA_INFO_SIGNAL: signal strength of last received PPDU (u8, dBm)
  * @NL80211_STA_INFO_TX_BITRATE: current unicast tx rate, nested attribute
- * 	containing info as possible, see &enum nl80211_rate_info
+ *	containing info as possible, see &enum nl80211_rate_info
  * @NL80211_STA_INFO_RX_PACKETS: total received packet (MSDUs and MMPDUs)
  *	(u32, from this station)
  * @NL80211_STA_INFO_TX_PACKETS: total transmitted packets (MSDUs and MMPDUs)
@@ -3813,8 +3867,8 @@ enum nl80211_sta_bss_param {
  *	Contains a nested array of signal strength attributes (u8, dBm)
  * @NL80211_STA_INFO_CHAIN_SIGNAL_AVG: per-chain signal strength average
  *	Same format as NL80211_STA_INFO_CHAIN_SIGNAL.
- * @NL80211_STA_EXPECTED_THROUGHPUT: expected throughput considering also the
- *	802.11 header (u32, kbps)
+ * @NL80211_STA_INFO_EXPECTED_THROUGHPUT: expected throughput considering also
+ *	the 802.11 header (u32, kbps)
  * @NL80211_STA_INFO_RX_DROP_MISC: RX packets dropped for unspecified reasons
  *	(u64)
  * @NL80211_STA_INFO_BEACON_RX: number of beacons received from this peer (u64)
@@ -4000,7 +4054,7 @@ enum nl80211_mpath_flags {
  * @NL80211_MPATH_INFO_METRIC: metric (cost) of this mesh path
  * @NL80211_MPATH_INFO_EXPTIME: expiration time for the path, in msec from now
  * @NL80211_MPATH_INFO_FLAGS: mesh path flags, enumerated in
- * 	&enum nl80211_mpath_flags;
+ *	&enum nl80211_mpath_flags;
  * @NL80211_MPATH_INFO_DISCOVERY_TIMEOUT: total path discovery timeout, in msec
  * @NL80211_MPATH_INFO_DISCOVERY_RETRIES: mesh path discovery retries
  * @NL80211_MPATH_INFO_HOP_COUNT: hop count to destination
@@ -4140,7 +4194,7 @@ enum nl80211_band_attr {
  * @NL80211_WMMR_CW_MAX: Maximum contention window slot.
  * @NL80211_WMMR_AIFSN: Arbitration Inter Frame Space.
  * @NL80211_WMMR_TXOP: Maximum allowed tx operation time.
- * @nl80211_WMMR_MAX: highest possible wmm rule.
+ * @NL80211_WMMR_MAX: highest possible wmm rule.
  * @__NL80211_WMMR_LAST: Internal use.
  */
 enum nl80211_wmm_rule {
@@ -4162,15 +4216,16 @@ enum nl80211_wmm_rule {
  * @NL80211_FREQUENCY_ATTR_DISABLED: Channel is disabled in current
  *	regulatory domain.
  * @NL80211_FREQUENCY_ATTR_NO_IR: no mechanisms that initiate radiation
- * 	are permitted on this channel, this includes sending probe
- * 	requests, or modes of operation that require beaconing.
+ *	are permitted on this channel, this includes sending probe
+ *	requests, or modes of operation that require beaconing.
+ * @__NL80211_FREQUENCY_ATTR_NO_IBSS: obsolete, same as _NO_IR
  * @NL80211_FREQUENCY_ATTR_RADAR: Radar detection is mandatory
  *	on this channel in current regulatory domain.
  * @NL80211_FREQUENCY_ATTR_MAX_TX_POWER: Maximum transmission power in mBm
  *	(100 * dBm).
  * @NL80211_FREQUENCY_ATTR_DFS_STATE: current state for DFS
  *	(enum nl80211_dfs_state)
- * @NL80211_FREQUENCY_ATTR_DFS_TIME: time in miliseconds for how long
+ * @NL80211_FREQUENCY_ATTR_DFS_TIME: time in milliseconds for how long
  *	this channel is in this DFS state.
  * @NL80211_FREQUENCY_ATTR_NO_HT40_MINUS: HT40- isn't possible with this
  *	channel as the control channel
@@ -4226,6 +4281,19 @@ enum nl80211_wmm_rule {
  *	in current regulatory domain.
  * @NL80211_FREQUENCY_ATTR_PSD: Power spectral density (in dBm) that
  *	is allowed on this channel in current regulatory domain.
+ * @NL80211_FREQUENCY_ATTR_DFS_CONCURRENT: Operation on this channel is
+ *	allowed for peer-to-peer or adhoc communication under the control
+ *	of a DFS master which operates on the same channel (FCC-594280 D01
+ *	Section B.3). Should be used together with %NL80211_RRF_DFS only.
+ * @NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT: Client connection to VLP AP
+ *	not allowed using this channel
+ * @NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT: Client connection to AFC AP
+ *	not allowed using this channel
+ * @NL80211_FREQUENCY_ATTR_CAN_MONITOR: This channel can be used in monitor
+ *	mode despite other (regulatory) restrictions, even if the channel is
+ *	otherwise completely disabled.
+ * @NL80211_FREQUENCY_ATTR_ALLOW_6GHZ_VLP_AP: This channel can be used for a
+ *	very low power (VLP) AP, despite being NO_IR.
  * @NL80211_FREQUENCY_ATTR_MAX: highest frequency attribute number
  *	currently defined
  * @__NL80211_FREQUENCY_ATTR_AFTER_LAST: internal use
@@ -4265,6 +4333,11 @@ enum nl80211_frequency_attr {
 	NL80211_FREQUENCY_ATTR_NO_320MHZ,
 	NL80211_FREQUENCY_ATTR_NO_EHT,
 	NL80211_FREQUENCY_ATTR_PSD,
+	NL80211_FREQUENCY_ATTR_DFS_CONCURRENT,
+	NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT,
+	NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT,
+	NL80211_FREQUENCY_ATTR_CAN_MONITOR,
+	NL80211_FREQUENCY_ATTR_ALLOW_6GHZ_VLP_AP,
 
 	/* keep last */
 	__NL80211_FREQUENCY_ATTR_AFTER_LAST,
@@ -4277,6 +4350,10 @@ enum nl80211_frequency_attr {
 #define NL80211_FREQUENCY_ATTR_NO_IR		NL80211_FREQUENCY_ATTR_NO_IR
 #define NL80211_FREQUENCY_ATTR_GO_CONCURRENT \
 					NL80211_FREQUENCY_ATTR_IR_CONCURRENT
+#define NL80211_FREQUENCY_ATTR_NO_UHB_VLP_CLIENT \
+	NL80211_FREQUENCY_ATTR_NO_6GHZ_VLP_CLIENT
+#define NL80211_FREQUENCY_ATTR_NO_UHB_AFC_CLIENT \
+	NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT
 
 /**
  * enum nl80211_bitrate_attr - bitrate attributes
@@ -4299,16 +4376,16 @@ enum nl80211_bitrate_attr {
 };
 
 /**
- * enum nl80211_initiator - Indicates the initiator of a reg domain request
+ * enum nl80211_reg_initiator - Indicates the initiator of a reg domain request
  * @NL80211_REGDOM_SET_BY_CORE: Core queried CRDA for a dynamic world
- * 	regulatory domain.
+ *	regulatory domain.
  * @NL80211_REGDOM_SET_BY_USER: User asked the wireless core to set the
- * 	regulatory domain.
+ *	regulatory domain.
  * @NL80211_REGDOM_SET_BY_DRIVER: a wireless drivers has hinted to the
- * 	wireless core it thinks its knows the regulatory domain we should be in.
+ *	wireless core it thinks its knows the regulatory domain we should be in.
  * @NL80211_REGDOM_SET_BY_COUNTRY_IE: the wireless core has received an
- * 	802.11 country information element with regulatory information it
- * 	thinks we should consider. cfg80211 only processes the country
+ *	802.11 country information element with regulatory information it
+ *	thinks we should consider. cfg80211 only processes the country
  *	code from the IE, and relies on the regulatory domain information
  *	structure passed by userspace (CRDA) from our wireless-regdb.
  *	If a channel is enabled but the country code indicates it should
@@ -4327,11 +4404,11 @@ enum nl80211_reg_initiator {
  *	to a specific country. When this is set you can count on the
  *	ISO / IEC 3166 alpha2 country code being valid.
  * @NL80211_REGDOM_TYPE_WORLD: the regulatory set domain is the world regulatory
- * 	domain.
+ *	domain.
  * @NL80211_REGDOM_TYPE_CUSTOM_WORLD: the regulatory domain set is a custom
- * 	driver specific world regulatory domain. These do not apply system-wide
- * 	and are only applicable to the individual devices which have requested
- * 	them to be applied.
+ *	driver specific world regulatory domain. These do not apply system-wide
+ *	and are only applicable to the individual devices which have requested
+ *	them to be applied.
  * @NL80211_REGDOM_TYPE_INTERSECTION: the regulatory domain set is the product
  *	of an intersection between two regulatory domains -- the previously
  *	set regulatory domain on the system and the last accepted regulatory
@@ -4348,21 +4425,21 @@ enum nl80211_reg_type {
  * enum nl80211_reg_rule_attr - regulatory rule attributes
  * @__NL80211_REG_RULE_ATTR_INVALID: attribute number 0 is reserved
  * @NL80211_ATTR_REG_RULE_FLAGS: a set of flags which specify additional
- * 	considerations for a given frequency range. These are the
- * 	&enum nl80211_reg_rule_flags.
+ *	considerations for a given frequency range. These are the
+ *	&enum nl80211_reg_rule_flags.
  * @NL80211_ATTR_FREQ_RANGE_START: starting frequencry for the regulatory
- * 	rule in KHz. This is not a center of frequency but an actual regulatory
- * 	band edge.
+ *	rule in KHz. This is not a center of frequency but an actual regulatory
+ *	band edge.
  * @NL80211_ATTR_FREQ_RANGE_END: ending frequency for the regulatory rule
- * 	in KHz. This is not a center a frequency but an actual regulatory
- * 	band edge.
+ *	in KHz. This is not a center a frequency but an actual regulatory
+ *	band edge.
  * @NL80211_ATTR_FREQ_RANGE_MAX_BW: maximum allowed bandwidth for this
  *	frequency range, in KHz.
  * @NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN: the maximum allowed antenna gain
- * 	for a given frequency range. The value is in mBi (100 * dBi).
- * 	If you don't have one then don't send this.
+ *	for a given frequency range. The value is in mBi (100 * dBi).
+ *	If you don't have one then don't send this.
  * @NL80211_ATTR_POWER_RULE_MAX_EIRP: the maximum allowed EIRP for
- * 	a given frequency range. The value is in mBm (100 * dBm).
+ *	a given frequency range. The value is in mBm (100 * dBm).
  * @NL80211_ATTR_DFS_CAC_TIME: DFS CAC time in milliseconds.
  *	If not present or 0 default CAC time will be used.
  * @NL80211_ATTR_POWER_RULE_PSD: power spectral density (in dBm).
@@ -4414,14 +4491,7 @@ enum nl80211_reg_rule_attr {
  *	value as specified by &struct nl80211_bss_select_rssi_adjust.
  * @NL80211_SCHED_SCAN_MATCH_ATTR_BSSID: BSSID to be used for matching
  *	(this cannot be used together with SSID).
- * @NL80211_SCHED_SCAN_MATCH_PER_BAND_RSSI: Nested attribute that carries the
- *	band specific minimum rssi thresholds for the bands defined in
- *	enum nl80211_band. The minimum rssi threshold value(s32) specific to a
- *	band shall be encapsulated in attribute with type value equals to one
- *	of the NL80211_BAND_* defined in enum nl80211_band. For example, the
- *	minimum rssi threshold value for 2.4GHZ band shall be encapsulated
- *	within an attribute of type NL80211_BAND_2GHZ. And one or more of such
- *	attributes will be nested within this attribute.
+ * @NL80211_SCHED_SCAN_MATCH_PER_BAND_RSSI: Obsolete
  * @NL80211_SCHED_SCAN_MATCH_ATTR_MAX: highest scheduled scan filter
  *	attribute number currently defined
  * @__NL80211_SCHED_SCAN_MATCH_ATTR_AFTER_LAST: internal use
@@ -4434,7 +4504,7 @@ enum nl80211_sched_scan_match_attr {
 	NL80211_SCHED_SCAN_MATCH_ATTR_RELATIVE_RSSI,
 	NL80211_SCHED_SCAN_MATCH_ATTR_RSSI_ADJUST,
 	NL80211_SCHED_SCAN_MATCH_ATTR_BSSID,
-	NL80211_SCHED_SCAN_MATCH_PER_BAND_RSSI,
+	NL80211_SCHED_SCAN_MATCH_PER_BAND_RSSI, /* obsolete */
 
 	/* keep last */
 	__NL80211_SCHED_SCAN_MATCH_ATTR_AFTER_LAST,
@@ -4456,8 +4526,9 @@ enum nl80211_sched_scan_match_attr {
  * @NL80211_RRF_PTP_ONLY: this is only for Point To Point links
  * @NL80211_RRF_PTMP_ONLY: this is only for Point To Multi Point links
  * @NL80211_RRF_NO_IR: no mechanisms that initiate radiation are allowed,
- * 	this includes probe requests or modes of operation that require
- * 	beaconing.
+ *	this includes probe requests or modes of operation that require
+ *	beaconing.
+ * @__NL80211_RRF_NO_IBSS: obsolete, same as NO_IR
  * @NL80211_RRF_AUTO_BW: maximum available bandwidth should be calculated
  *	base on contiguous rules and wider channels will be allowed to cross
  *	multiple contiguous/overlapping frequency ranges.
@@ -4470,6 +4541,14 @@ enum nl80211_sched_scan_match_attr {
  * @NL80211_RRF_NO_320MHZ: 320MHz operation not allowed
  * @NL80211_RRF_NO_EHT: EHT operation not allowed
  * @NL80211_RRF_PSD: Ruleset has power spectral density value
+ * @NL80211_RRF_DFS_CONCURRENT: Operation on this channel is allowed for
+ *	peer-to-peer or adhoc communication under the control of a DFS master
+ *	which operates on the same channel (FCC-594280 D01 Section B.3).
+ *	Should be used together with %NL80211_RRF_DFS only.
+ * @NL80211_RRF_NO_6GHZ_VLP_CLIENT: Client connection to VLP AP not allowed
+ * @NL80211_RRF_NO_6GHZ_AFC_CLIENT: Client connection to AFC AP not allowed
+ * @NL80211_RRF_ALLOW_6GHZ_VLP_AP: Very low power (VLP) AP can be permitted
+ *	despite NO_IR configuration.
  */
 enum nl80211_reg_rule_flags {
 	NL80211_RRF_NO_OFDM		= 1<<0,
@@ -4491,6 +4570,10 @@ enum nl80211_reg_rule_flags {
 	NL80211_RRF_NO_320MHZ		= 1<<18,
 	NL80211_RRF_NO_EHT		= 1<<19,
 	NL80211_RRF_PSD			= 1<<20,
+	NL80211_RRF_DFS_CONCURRENT	= 1<<21,
+	NL80211_RRF_NO_6GHZ_VLP_CLIENT	= 1<<22,
+	NL80211_RRF_NO_6GHZ_AFC_CLIENT	= 1<<23,
+	NL80211_RRF_ALLOW_6GHZ_VLP_AP	= 1<<24,
 };
 
 #define NL80211_RRF_PASSIVE_SCAN	NL80211_RRF_NO_IR
@@ -4499,6 +4582,8 @@ enum nl80211_reg_rule_flags {
 #define NL80211_RRF_NO_HT40		(NL80211_RRF_NO_HT40MINUS |\
 					 NL80211_RRF_NO_HT40PLUS)
 #define NL80211_RRF_GO_CONCURRENT	NL80211_RRF_IR_CONCURRENT
+#define NL80211_RRF_NO_UHB_VLP_CLIENT	NL80211_RRF_NO_6GHZ_VLP_CLIENT
+#define NL80211_RRF_NO_UHB_AFC_CLIENT	NL80211_RRF_NO_6GHZ_AFC_CLIENT
 
 /* For backport compatibility with older userspace */
 #define NL80211_RRF_NO_IR_ALL		(NL80211_RRF_NO_IR | __NL80211_RRF_NO_IBSS)
@@ -4645,8 +4730,8 @@ enum nl80211_mntr_flags {
  *	alternate between Active and Doze states, but may not wake up
  *	for neighbor's beacons.
  *
- * @__NL80211_MESH_POWER_AFTER_LAST - internal use
- * @NL80211_MESH_POWER_MAX - highest possible power save level
+ * @__NL80211_MESH_POWER_AFTER_LAST: internal use
+ * @NL80211_MESH_POWER_MAX: highest possible power save level
  */
 
 enum nl80211_mesh_power_mode {
@@ -5027,6 +5112,36 @@ enum nl80211_bss_scan_width {
 	NL80211_BSS_CHAN_WIDTH_2,
 };
 
+/**
+ * enum nl80211_bss_use_for - bitmap indicating possible BSS use
+ * @NL80211_BSS_USE_FOR_NORMAL: Use this BSS for normal "connection",
+ *	including IBSS/MBSS depending on the type.
+ * @NL80211_BSS_USE_FOR_MLD_LINK: This BSS can be used as a link in an
+ *	MLO connection. Note that for an MLO connection, all links including
+ *	the assoc link must have this flag set, and the assoc link must
+ *	additionally have %NL80211_BSS_USE_FOR_NORMAL set.
+ */
+enum nl80211_bss_use_for {
+	NL80211_BSS_USE_FOR_NORMAL = 1 << 0,
+	NL80211_BSS_USE_FOR_MLD_LINK = 1 << 1,
+};
+
+/**
+ * enum nl80211_bss_cannot_use_reasons - reason(s) connection to a
+ *	BSS isn't possible
+ * @NL80211_BSS_CANNOT_USE_NSTR_NONPRIMARY: NSTR nonprimary links aren't
+ *	supported by the device, and this BSS entry represents one.
+ * @NL80211_BSS_CANNOT_USE_6GHZ_PWR_MISMATCH: STA is not supporting
+ *	the AP power type (SP, VLP, AP) that the AP uses.
+ */
+enum nl80211_bss_cannot_use_reasons {
+	NL80211_BSS_CANNOT_USE_NSTR_NONPRIMARY	= 1 << 0,
+	NL80211_BSS_CANNOT_USE_6GHZ_PWR_MISMATCH	= 1 << 1,
+};
+
+#define NL80211_BSS_CANNOT_USE_UHB_PWR_MISMATCH \
+	NL80211_BSS_CANNOT_USE_6GHZ_PWR_MISMATCH
+
 /**
  * enum nl80211_bss - netlink attributes for a BSS
  *
@@ -5079,6 +5194,14 @@ enum nl80211_bss_scan_width {
  * @NL80211_BSS_FREQUENCY_OFFSET: frequency offset in KHz
  * @NL80211_BSS_MLO_LINK_ID: MLO link ID of the BSS (u8).
  * @NL80211_BSS_MLD_ADDR: MLD address of this BSS if connected to it.
+ * @NL80211_BSS_USE_FOR: u32 bitmap attribute indicating what the BSS can be
+ *	used for, see &enum nl80211_bss_use_for.
+ * @NL80211_BSS_CANNOT_USE_REASONS: Indicates the reason that this BSS cannot
+ *	be used for all or some of the possible uses by the device reporting it,
+ *	even though its presence was detected.
+ *	This is a u64 attribute containing a bitmap of values from
+ *	&enum nl80211_cannot_use_reasons, note that the attribute may be missing
+ *	if no reasons are specified.
  * @__NL80211_BSS_AFTER_LAST: internal
  * @NL80211_BSS_MAX: highest BSS attribute
  */
@@ -5106,6 +5229,8 @@ enum nl80211_bss {
 	NL80211_BSS_FREQUENCY_OFFSET,
 	NL80211_BSS_MLO_LINK_ID,
 	NL80211_BSS_MLD_ADDR,
+	NL80211_BSS_USE_FOR,
+	NL80211_BSS_CANNOT_USE_REASONS,
 
 	/* keep last */
 	__NL80211_BSS_AFTER_LAST,
@@ -5454,7 +5579,7 @@ enum nl80211_tx_rate_setting {
  *	(%NL80211_TID_CONFIG_ATTR_TIDS, %NL80211_TID_CONFIG_ATTR_OVERRIDE).
  * @NL80211_TID_CONFIG_ATTR_PEER_SUPP: same as the previous per-vif one, but
  *	per peer instead.
- * @NL80211_TID_CONFIG_ATTR_OVERRIDE: flag attribue, if set indicates
+ * @NL80211_TID_CONFIG_ATTR_OVERRIDE: flag attribute, if set indicates
  *	that the new configuration overrides all previous peer
  *	configurations, otherwise previous peer specific configurations
  *	should be left untouched.
@@ -5626,7 +5751,7 @@ struct nl80211_pattern_support {
  *	"TCP connection wakeup" for more details. This is a nested attribute
  *	containing the exact information for establishing and keeping alive
  *	the TCP connection.
- * @NL80211_WOWLAN_TRIG_TCP_WAKEUP_MATCH: For wakeup reporting only, the
+ * @NL80211_WOWLAN_TRIG_WAKEUP_TCP_MATCH: For wakeup reporting only, the
  *	wakeup packet was received on the TCP connection
  * @NL80211_WOWLAN_TRIG_WAKEUP_TCP_CONNLOST: For wakeup reporting only, the
  *	TCP connection was lost or failed to be established
@@ -5655,6 +5780,8 @@ struct nl80211_pattern_support {
  *	%NL80211_ATTR_SCAN_FREQUENCIES contains more than one
  *	frequency, it means that the match occurred in more than one
  *	channel.
+ * @NL80211_WOWLAN_TRIG_UNPROTECTED_DEAUTH_DISASSOC: For wakeup reporting only.
+ *	Wake up happened due to unprotected deauth or disassoc frame in MFP.
  * @NUM_NL80211_WOWLAN_TRIG: number of wake on wireless triggers
  * @MAX_NL80211_WOWLAN_TRIG: highest wowlan trigger attribute number
  *
@@ -5682,6 +5809,7 @@ enum nl80211_wowlan_triggers {
 	NL80211_WOWLAN_TRIG_WAKEUP_TCP_NOMORETOKENS,
 	NL80211_WOWLAN_TRIG_NET_DETECT,
 	NL80211_WOWLAN_TRIG_NET_DETECT_RESULTS,
+	NL80211_WOWLAN_TRIG_UNPROTECTED_DEAUTH_DISASSOC,
 
 	/* keep last */
 	NUM_NL80211_WOWLAN_TRIG,
@@ -5837,7 +5965,7 @@ enum nl80211_attr_coalesce_rule {
 
 /**
  * enum nl80211_coalesce_condition - coalesce rule conditions
- * @NL80211_COALESCE_CONDITION_MATCH: coalaesce Rx packets when patterns
+ * @NL80211_COALESCE_CONDITION_MATCH: coalesce Rx packets when patterns
  *	in a rule are matched.
  * @NL80211_COALESCE_CONDITION_NO_MATCH: coalesce Rx packets when patterns
  *	in a rule are not matched.
@@ -5936,7 +6064,7 @@ enum nl80211_if_combination_attrs {
  * enum nl80211_plink_state - state of a mesh peer link finite state machine
  *
  * @NL80211_PLINK_LISTEN: initial state, considered the implicit
- *	state of non existent mesh peer links
+ *	state of non-existent mesh peer links
  * @NL80211_PLINK_OPN_SNT: mesh plink open frame has been sent to
  *	this mesh peer
  * @NL80211_PLINK_OPN_RCVD: mesh plink open frame has been received
@@ -5972,7 +6100,7 @@ enum nl80211_plink_state {
  * @NL80211_PLINK_ACTION_BLOCK: block traffic from this mesh peer
  * @NUM_NL80211_PLINK_ACTIONS: number of possible actions
  */
-enum plink_actions {
+enum nl80211_plink_action {
 	NL80211_PLINK_ACTION_NO_ACTION,
 	NL80211_PLINK_ACTION_OPEN,
 	NL80211_PLINK_ACTION_BLOCK,
@@ -6229,7 +6357,7 @@ enum nl80211_feature_flags {
  *	request to use RRM (see %NL80211_ATTR_USE_RRM) with
  *	%NL80211_CMD_ASSOCIATE and %NL80211_CMD_CONNECT requests, which will set
  *	the ASSOC_REQ_USE_RRM flag in the association request even if
- *	NL80211_FEATURE_QUIET is not advertized.
+ *	NL80211_FEATURE_QUIET is not advertised.
  * @NL80211_EXT_FEATURE_MU_MIMO_AIR_SNIFFER: This device supports MU-MIMO air
  *	sniffer which means that it can be configured to hear packets from
  *	certain groups which can be configured by the
@@ -6241,13 +6369,15 @@ enum nl80211_feature_flags {
  *	the BSS that the interface that requested the scan is connected to
  *	(if available).
  * @NL80211_EXT_FEATURE_BSS_PARENT_TSF: Per BSS, this driver reports the
- *	time the last beacon/probe was received. The time is the TSF of the
- *	BSS that the interface that requested the scan is connected to
- *	(if available).
+ *	time the last beacon/probe was received. For a non-MLO connection, the
+ *	time is the TSF of the BSS that the interface that requested the scan is
+ *	connected to (if available). For an MLO connection, the time is the TSF
+ *	of the BSS corresponding with link ID specified in the scan request (if
+ *	specified).
  * @NL80211_EXT_FEATURE_SET_SCAN_DWELL: This driver supports configuration of
  *	channel dwell time.
  * @NL80211_EXT_FEATURE_BEACON_RATE_LEGACY: Driver supports beacon rate
- *	configuration (AP/mesh), supporting a legacy (non HT/VHT) rate.
+ *	configuration (AP/mesh), supporting a legacy (non-HT/VHT) rate.
  * @NL80211_EXT_FEATURE_BEACON_RATE_HT: Driver supports beacon rate
  *	configuration (AP/mesh) with HT rates.
  * @NL80211_EXT_FEATURE_BEACON_RATE_VHT: Driver supports beacon rate
@@ -6297,6 +6427,7 @@ enum nl80211_feature_flags {
  *	receiving control port frames over nl80211 instead of the netdevice.
  * @NL80211_EXT_FEATURE_ACK_SIGNAL_SUPPORT: This driver/device supports
  *	(average) ACK signal strength reporting.
+ * @NL80211_EXT_FEATURE_DATA_ACK_SIGNAL_SUPPORT: Backward-compatible ID
  * @NL80211_EXT_FEATURE_TXQS: Driver supports FQ-CoDel-enabled intermediate
  *      TXQs.
  * @NL80211_EXT_FEATURE_SCAN_RANDOM_SN: Driver/device supports randomizing the
@@ -6321,8 +6452,7 @@ enum nl80211_feature_flags {
  * @NL80211_EXT_FEATURE_AP_PMKSA_CACHING: Driver/device supports PMKSA caching
  *	(set/del PMKSA operations) in AP mode.
  *
- * @NL80211_EXT_FEATURE_SCHED_SCAN_BAND_SPECIFIC_RSSI_THOLD: Driver supports
- *	filtering of sched scan results using band specific RSSI thresholds.
+ * @NL80211_EXT_FEATURE_SCHED_SCAN_BAND_SPECIFIC_RSSI_THOLD: Obsolete
  *
  * @NL80211_EXT_FEATURE_STA_TX_PWR: This driver supports controlling tx power
  *	to a station.
@@ -6426,6 +6556,16 @@ enum nl80211_feature_flags {
  * @NL80211_EXT_FEATURE_OWE_OFFLOAD_AP: Driver/Device wants to do OWE DH IE
  *	handling in AP mode.
  *
+ * @NL80211_EXT_FEATURE_DFS_CONCURRENT: The device supports peer-to-peer or
+ *	ad hoc operation on DFS channels under the control of a concurrent
+ *	DFS master on the same channel as described in FCC-594280 D01
+ *	(Section B.3). This, for example, allows P2P GO and P2P clients to
+ *	operate on DFS channels as long as there's a concurrent BSS connection.
+ *
+ * @NL80211_EXT_FEATURE_SPP_AMSDU_SUPPORT: The driver has support for SPP
+ *	(signaling and payload protected) A-MSDUs and this shall be advertised
+ *	in the RSNXE.
+ *
  * @NUM_NL80211_EXT_FEATURES: number of extended features.
  * @MAX_NL80211_EXT_FEATURES: highest extended feature index.
  */
@@ -6467,7 +6607,7 @@ enum nl80211_ext_feature_index {
 	NL80211_EXT_FEATURE_ENABLE_FTM_RESPONDER,
 	NL80211_EXT_FEATURE_AIRTIME_FAIRNESS,
 	NL80211_EXT_FEATURE_AP_PMKSA_CACHING,
-	NL80211_EXT_FEATURE_SCHED_SCAN_BAND_SPECIFIC_RSSI_THOLD,
+	NL80211_EXT_FEATURE_SCHED_SCAN_BAND_SPECIFIC_RSSI_THOLD, /* obsolete */
 	NL80211_EXT_FEATURE_EXT_KEY_ID,
 	NL80211_EXT_FEATURE_STA_TX_PWR,
 	NL80211_EXT_FEATURE_SAE_OFFLOAD,
@@ -6499,6 +6639,8 @@ enum nl80211_ext_feature_index {
 	NL80211_EXT_FEATURE_AUTH_AND_DEAUTH_RANDOM_TA,
 	NL80211_EXT_FEATURE_OWE_OFFLOAD,
 	NL80211_EXT_FEATURE_OWE_OFFLOAD_AP,
+	NL80211_EXT_FEATURE_DFS_CONCURRENT,
+	NL80211_EXT_FEATURE_SPP_AMSDU_SUPPORT,
 
 	/* add new features before the definition below */
 	NUM_NL80211_EXT_FEATURES,
@@ -6583,7 +6725,7 @@ enum nl80211_timeout_reason {
  *	request parameters IE in the probe request
  * @NL80211_SCAN_FLAG_ACCEPT_BCAST_PROBE_RESP: accept broadcast probe responses
  * @NL80211_SCAN_FLAG_OCE_PROBE_REQ_HIGH_TX_RATE: send probe request frames at
- *	rate of at least 5.5M. In case non OCE AP is discovered in the channel,
+ *	rate of at least 5.5M. In case non-OCE AP is discovered in the channel,
  *	only the first probe req in the channel will be sent in high rate.
  * @NL80211_SCAN_FLAG_OCE_PROBE_REQ_DEFERRAL_SUPPRESSION: allow probe request
  *	tx deferral (dot11FILSProbeDelay shall be set to 15ms)
@@ -6619,7 +6761,7 @@ enum nl80211_timeout_reason {
  *	received on the 2.4/5 GHz channels to actively scan only the 6GHz
  *	channels on which APs are expected to be found. Note that when not set,
  *	the scan logic would scan all 6GHz channels, but since transmission of
- *	probe requests on non PSC channels is limited, it is highly likely that
+ *	probe requests on non-PSC channels is limited, it is highly likely that
  *	these channels would passively be scanned. Also note that when the flag
  *	is set, in addition to the colocated APs, PSC channels would also be
  *	scanned if the user space has asked for it.
@@ -6669,6 +6811,8 @@ enum nl80211_acl_policy {
  * @NL80211_SMPS_STATIC: static SMPS (use a single antenna)
  * @NL80211_SMPS_DYNAMIC: dynamic smps (start with a single antenna and
  *	turn on other antennas after CTS/RTS).
+ * @__NL80211_SMPS_AFTER_LAST: internal
+ * @NL80211_SMPS_MAX: highest used enumeration
  */
 enum nl80211_smps_mode {
 	NL80211_SMPS_OFF,
@@ -6890,6 +7034,8 @@ enum nl80211_bss_select_attr {
  * @NL80211_NAN_FUNC_PUBLISH: function is publish
  * @NL80211_NAN_FUNC_SUBSCRIBE: function is subscribe
  * @NL80211_NAN_FUNC_FOLLOW_UP: function is follow-up
+ * @__NL80211_NAN_FUNC_TYPE_AFTER_LAST: internal use
+ * @NL80211_NAN_FUNC_MAX_TYPE: internal use
  */
 enum nl80211_nan_function_type {
 	NL80211_NAN_FUNC_PUBLISH,
@@ -6951,7 +7097,7 @@ enum nl80211_nan_func_term_reason {
  *	The instance ID for the follow up Service Discovery Frame. This is u8.
  * @NL80211_NAN_FUNC_FOLLOW_UP_REQ_ID: relevant if the function's type
  *	is follow up. This is a u8.
- *	The requestor instance ID for the follow up Service Discovery Frame.
+ *	The requester instance ID for the follow up Service Discovery Frame.
  * @NL80211_NAN_FUNC_FOLLOW_UP_DEST: the MAC address of the recipient of the
  *	follow up Service Discovery Frame. This is a binary attribute.
  * @NL80211_NAN_FUNC_CLOSE_RANGE: is this function limited for devices in a
@@ -7050,7 +7196,7 @@ enum nl80211_nan_match_attributes {
 };
 
 /**
- * nl80211_external_auth_action - Action to perform with external
+ * enum nl80211_external_auth_action - Action to perform with external
  *     authentication request. Used by NL80211_ATTR_EXTERNAL_AUTH_ACTION.
  * @NL80211_EXTERNAL_AUTH_START: Start the authentication.
  * @NL80211_EXTERNAL_AUTH_ABORT: Abort the ongoing authentication.
@@ -7068,7 +7214,7 @@ enum nl80211_external_auth_action {
  * @NL80211_FTM_RESP_ATTR_LCI: The content of Measurement Report Element
  *	(9.4.2.22 in 802.11-2016) with type 8 - LCI (9.4.2.22.10),
  *	i.e. starting with the measurement token
- * @NL80211_FTM_RESP_ATTR_CIVIC: The content of Measurement Report Element
+ * @NL80211_FTM_RESP_ATTR_CIVICLOC: The content of Measurement Report Element
  *	(9.4.2.22 in 802.11-2016) with type 11 - Civic (Section 9.4.2.22.13),
  *	i.e. starting with the measurement token
  * @__NL80211_FTM_RESP_ATTR_LAST: Internal
@@ -7341,7 +7487,7 @@ enum nl80211_peer_measurement_attrs {
  * @NL80211_PMSR_FTM_CAPA_ATTR_TRIGGER_BASED: flag attribute indicating if
  *	trigger based ranging measurement is supported
  * @NL80211_PMSR_FTM_CAPA_ATTR_NON_TRIGGER_BASED: flag attribute indicating
- *	if non trigger based ranging measurement is supported
+ *	if non-trigger-based ranging measurement is supported
  *
  * @NUM_NL80211_PMSR_FTM_CAPA_ATTR: internal
  * @NL80211_PMSR_FTM_CAPA_ATTR_MAX: highest attribute number
@@ -7395,7 +7541,7 @@ enum nl80211_peer_measurement_ftm_capa {
  *      if neither %NL80211_PMSR_FTM_REQ_ATTR_TRIGGER_BASED nor
  *	%NL80211_PMSR_FTM_REQ_ATTR_NON_TRIGGER_BASED is set, EDCA based
  *	ranging will be used.
- * @NL80211_PMSR_FTM_REQ_ATTR_NON_TRIGGER_BASED: request non trigger based
+ * @NL80211_PMSR_FTM_REQ_ATTR_NON_TRIGGER_BASED: request non-trigger-based
  *	ranging measurement (flag)
  *	This attribute and %NL80211_PMSR_FTM_REQ_ATTR_TRIGGER_BASED are
  *	mutually exclusive.
@@ -7473,7 +7619,7 @@ enum nl80211_peer_measurement_ftm_failure_reasons {
  * @NL80211_PMSR_FTM_RESP_ATTR_NUM_FTMR_ATTEMPTS: number of FTM Request frames
  *	transmitted (u32, optional)
  * @NL80211_PMSR_FTM_RESP_ATTR_NUM_FTMR_SUCCESSES: number of FTM Request frames
- *	that were acknowleged (u32, optional)
+ *	that were acknowledged (u32, optional)
  * @NL80211_PMSR_FTM_RESP_ATTR_BUSY_RETRY_TIME: retry time received from the
  *	busy peer (u32, seconds)
  * @NL80211_PMSR_FTM_RESP_ATTR_NUM_BURSTS_EXP: actual number of bursts exponent
@@ -7711,6 +7857,7 @@ enum nl80211_sae_pwe_mechanism {
  *
  * @NL80211_SAR_TYPE_POWER: power limitation specified in 0.25dBm unit
  *
+ * @NUM_NL80211_SAR_TYPE: internal
  */
 enum nl80211_sar_type {
 	NL80211_SAR_TYPE_POWER,
@@ -7724,6 +7871,8 @@ enum nl80211_sar_type {
 /**
  * enum nl80211_sar_attrs - Attributes for SAR spec
  *
+ * @__NL80211_SAR_ATTR_INVALID: Invalid
+ *
  * @NL80211_SAR_ATTR_TYPE: the SAR type as defined in &enum nl80211_sar_type.
  *
  * @NL80211_SAR_ATTR_SPECS: Nested array of SAR power
@@ -7755,6 +7904,8 @@ enum nl80211_sar_attrs {
 /**
  * enum nl80211_sar_specs_attrs - Attributes for SAR power limit specs
  *
+ * @__NL80211_SAR_ATTR_SPECS_INVALID: Invalid
+ *
  * @NL80211_SAR_ATTR_SPECS_POWER: Required (s32)value to specify the actual
  *	power limit value in units of 0.25 dBm if type is
  *	NL80211_SAR_TYPE_POWER. (i.e., a value of 44 represents 11 dBm).
@@ -7869,4 +8020,54 @@ enum nl80211_ap_settings_flags {
 	NL80211_AP_SETTINGS_SA_QUERY_OFFLOAD_SUPPORT	= 1 << 1,
 };
 
+/**
+ * enum nl80211_wiphy_radio_attrs - wiphy radio attributes
+ *
+ * @__NL80211_WIPHY_RADIO_ATTR_INVALID: Invalid
+ *
+ * @NL80211_WIPHY_RADIO_ATTR_INDEX: Index of this radio (u32)
+ * @NL80211_WIPHY_RADIO_ATTR_FREQ_RANGE: Frequency range supported by this
+ *	radio. Attribute may be present multiple times.
+ * @NL80211_WIPHY_RADIO_ATTR_INTERFACE_COMBINATION: Supported interface
+ *	combination for this radio. Attribute may be present multiple times
+ *	and contains attributes defined in &enum nl80211_if_combination_attrs.
+ *
+ * @__NL80211_WIPHY_RADIO_ATTR_LAST: Internal
+ * @NL80211_WIPHY_RADIO_ATTR_MAX: Highest attribute
+ */
+enum nl80211_wiphy_radio_attrs {
+	__NL80211_WIPHY_RADIO_ATTR_INVALID,
+
+	NL80211_WIPHY_RADIO_ATTR_INDEX,
+	NL80211_WIPHY_RADIO_ATTR_FREQ_RANGE,
+	NL80211_WIPHY_RADIO_ATTR_INTERFACE_COMBINATION,
+
+	/* keep last */
+	__NL80211_WIPHY_RADIO_ATTR_LAST,
+	NL80211_WIPHY_RADIO_ATTR_MAX = __NL80211_WIPHY_RADIO_ATTR_LAST - 1,
+};
+
+/**
+ * enum nl80211_wiphy_radio_freq_range - wiphy radio frequency range
+ *
+ * @__NL80211_WIPHY_RADIO_FREQ_ATTR_INVALID: Invalid
+ *
+ * @NL80211_WIPHY_RADIO_FREQ_ATTR_START: Frequency range start (u32).
+ *	The unit is kHz.
+ * @NL80211_WIPHY_RADIO_FREQ_ATTR_END: Frequency range end (u32).
+ *	The unit is kHz.
+ *
+ * @__NL80211_WIPHY_RADIO_FREQ_ATTR_LAST: Internal
+ * @NL80211_WIPHY_RADIO_FREQ_ATTR_MAX: Highest attribute
+ */
+enum nl80211_wiphy_radio_freq_range {
+	__NL80211_WIPHY_RADIO_FREQ_ATTR_INVALID,
+
+	NL80211_WIPHY_RADIO_FREQ_ATTR_START,
+	NL80211_WIPHY_RADIO_FREQ_ATTR_END,
+
+	__NL80211_WIPHY_RADIO_FREQ_ATTR_LAST,
+	NL80211_WIPHY_RADIO_FREQ_ATTR_MAX = __NL80211_WIPHY_RADIO_FREQ_ATTR_LAST - 1,
+};
+
 #endif /* __LINUX_NL80211_H */
diff --git a/src/fst/fst_session.c b/src/fst/fst_session.c
index 49886ffa..f8de9a10 100644
--- a/src/fst/fst_session.c
+++ b/src/fst/fst_session.c
@@ -18,11 +18,6 @@
 #include "fst/fst_ctrl_defs.h"
 #endif /* CONFIG_FST_TEST */
 
-#define US_80211_TU 1024
-
-#define US_TO_TU(m) ((m) * / US_80211_TU)
-#define TU_TO_US(m) ((m) * US_80211_TU)
-
 #define FST_LLT_SWITCH_IMMEDIATELY 0
 
 #define fst_printf_session(s, level, format, ...) \
@@ -182,7 +177,8 @@ static void fst_session_timeout_handler(void *eloop_data, void *user_ctx)
 static void fst_session_stt_arm(struct fst_session *s)
 {
 	/* Action frames sometimes get delayed. Use relaxed timeout (2*) */
-	eloop_register_timeout(0, 2 * TU_TO_US(FST_DEFAULT_SESSION_TIMEOUT_TU),
+	eloop_register_timeout(0,
+			       2 * TU_TO_USEC(FST_DEFAULT_SESSION_TIMEOUT_TU),
 			       fst_session_timeout_handler, NULL, s);
 	s->stt_armed = true;
 }
diff --git a/src/p2p/p2p.c b/src/p2p/p2p.c
index df7cb7fe..f3742ea5 100644
--- a/src/p2p/p2p.c
+++ b/src/p2p/p2p.c
@@ -14,9 +14,13 @@
 #include "common/defs.h"
 #include "common/ieee802_11_defs.h"
 #include "common/ieee802_11_common.h"
+#include "common/wpa_common.h"
 #include "common/wpa_ctrl.h"
+#include "common/sae.h"
 #include "crypto/sha256.h"
+#include "crypto/sha384.h"
 #include "crypto/crypto.h"
+#include "pasn/pasn_common.h"
 #include "wps/wps_i.h"
 #include "p2p_i.h"
 #include "p2p.h"
@@ -957,6 +961,7 @@ static void p2p_device_free(struct p2p_data *p2p, struct p2p_device *dev)
 		dev->info.wps_vendor_ext[i] = NULL;
 	}
 
+	os_free(dev->bootstrap_params);
 	wpabuf_free(dev->info.wfd_subelems);
 	wpabuf_free(dev->info.vendor_elems);
 	wpabuf_free(dev->go_neg_conf);
@@ -1602,7 +1607,8 @@ int p2p_connect(struct p2p_data *p2p, const u8 *peer_addr,
 		int go_intent, const u8 *own_interface_addr,
 		unsigned int force_freq, int persistent_group,
 		const u8 *force_ssid, size_t force_ssid_len,
-		int pd_before_go_neg, unsigned int pref_freq, u16 oob_pw_id)
+		int pd_before_go_neg, unsigned int pref_freq, u16 oob_pw_id,
+		bool p2p2, u16 bootstrap, const char *password)
 {
 	struct p2p_device *dev;
 
@@ -1686,6 +1692,10 @@ int p2p_connect(struct p2p_data *p2p, const u8 *peer_addr,
 
 	dev->wps_method = wps_method;
 	dev->oob_pw_id = oob_pw_id;
+	dev->p2p2 = p2p2;
+	dev->req_bootstrap_method = bootstrap;
+	if (password && os_strlen(password) < sizeof(dev->password))
+		os_strlcpy(dev->password, password, sizeof(dev->password));
 	dev->status = P2P_SC_SUCCESS;
 
 	if (p2p->p2p_scan_running) {
@@ -1704,7 +1714,8 @@ int p2p_authorize(struct p2p_data *p2p, const u8 *peer_addr,
 		  int go_intent, const u8 *own_interface_addr,
 		  unsigned int force_freq, int persistent_group,
 		  const u8 *force_ssid, size_t force_ssid_len,
-		  unsigned int pref_freq, u16 oob_pw_id)
+		  unsigned int pref_freq, u16 oob_pw_id, u16 bootstrap,
+		  const char *password)
 {
 	struct p2p_device *dev;
 
@@ -1738,6 +1749,10 @@ int p2p_authorize(struct p2p_data *p2p, const u8 *peer_addr,
 	dev->flags &= ~P2P_DEV_USER_REJECTED;
 	dev->go_neg_req_sent = 0;
 	dev->go_state = UNKNOWN_GO;
+	dev->req_bootstrap_method = bootstrap;
+
+	if (password && os_strlen(password) < sizeof(dev->password))
+		os_strlcpy(dev->password, password, sizeof(dev->password));
 	p2p_set_dev_persistent(dev, persistent_group);
 	p2p->go_intent = go_intent;
 	os_memcpy(p2p->intended_addr, own_interface_addr, ETH_ALEN);
@@ -1916,26 +1931,25 @@ static void p2p_rx_p2p_action(struct p2p_data *p2p, const u8 *sa,
 
 	switch (data[0]) {
 	case P2P_GO_NEG_REQ:
-		p2p_process_go_neg_req(p2p, sa, data + 1, len - 1, rx_freq);
+		p2p_handle_go_neg_req(p2p, sa, data + 1, len - 1, rx_freq);
 		break;
 	case P2P_GO_NEG_RESP:
-		p2p_process_go_neg_resp(p2p, sa, data + 1, len - 1, rx_freq);
+		p2p_handle_go_neg_resp(p2p, sa, data + 1, len - 1, rx_freq);
 		break;
 	case P2P_GO_NEG_CONF:
-		p2p_process_go_neg_conf(p2p, sa, data + 1, len - 1);
+		p2p_handle_go_neg_conf(p2p, sa, data + 1, len - 1, false);
 		break;
 	case P2P_INVITATION_REQ:
-		p2p_process_invitation_req(p2p, sa, data + 1, len - 1,
-					   rx_freq);
+		p2p_handle_invitation_req(p2p, sa, data + 1, len - 1, rx_freq);
 		break;
 	case P2P_INVITATION_RESP:
 		p2p_process_invitation_resp(p2p, sa, data + 1, len - 1);
 		break;
 	case P2P_PROV_DISC_REQ:
-		p2p_process_prov_disc_req(p2p, sa, data + 1, len - 1, rx_freq);
+		p2p_handle_prov_disc_req(p2p, sa, data + 1, len - 1, rx_freq);
 		break;
 	case P2P_PROV_DISC_RESP:
-		p2p_process_prov_disc_resp(p2p, sa, data + 1, len - 1);
+		p2p_handle_prov_disc_resp(p2p, sa, data + 1, len - 1, rx_freq);
 		break;
 	case P2P_DEV_DISC_REQ:
 		p2p_process_dev_disc_req(p2p, sa, data + 1, len - 1, rx_freq);
@@ -2984,6 +2998,52 @@ bool is_p2p_dfs_chan_enabled(struct p2p_data *p2p)
 }
 
 
+static void p2p_pairing_info_deinit(struct p2p_data *p2p)
+{
+#ifdef CONFIG_PASN
+	pasn_initiator_pmksa_cache_deinit(p2p->initiator_pmksa);
+	pasn_responder_pmksa_cache_deinit(p2p->responder_pmksa);
+#endif /* CONFIG_PASN */
+	os_free(p2p->pairing_info);
+}
+
+
+static int p2p_pairing_info_init(struct p2p_data *p2p)
+{
+	struct p2p_pairing_info *pairing_info;
+
+	if (p2p->cfg->pairing_config.dik_len > DEVICE_IDENTITY_KEY_MAX_LEN)
+		return -1;
+
+	pairing_info = os_zalloc(sizeof(struct p2p_pairing_info));
+	if (!pairing_info)
+		return -1;
+
+	pairing_info->enable_pairing_setup =
+		p2p->cfg->pairing_config.enable_pairing_setup;
+	pairing_info->enable_pairing_cache =
+		p2p->cfg->pairing_config.enable_pairing_cache;
+	pairing_info->supported_bootstrap =
+		p2p->cfg->pairing_config.bootstrap_methods;
+
+	pairing_info->dev_ik.cipher_version =
+		p2p->cfg->pairing_config.dik_cipher;
+	pairing_info->dev_ik.dik_len = p2p->cfg->pairing_config.dik_len;
+	os_memcpy(pairing_info->dev_ik.dik_data,
+		  p2p->cfg->pairing_config.dik_data,
+		  p2p->cfg->pairing_config.dik_len);
+
+	p2p_pairing_info_deinit(p2p);
+	p2p->pairing_info = pairing_info;
+#ifdef CONFIG_PASN
+	p2p->initiator_pmksa = pasn_initiator_pmksa_cache_init();
+	p2p->responder_pmksa = pasn_responder_pmksa_cache_init();
+#endif /* CONFIG_PASN */
+
+	return 0;
+}
+
+
 struct p2p_data * p2p_init(const struct p2p_config *cfg)
 {
 	struct p2p_data *p2p;
@@ -3039,6 +3099,10 @@ struct p2p_data * p2p_init(const struct p2p_config *cfg)
 	p2p->go_timeout = 100;
 	p2p->client_timeout = 20;
 	p2p->num_p2p_sd_queries = 0;
+	/* Default comeback after one second */
+	if (!p2p->cfg->comeback_after)
+		p2p->cfg->comeback_after = 977; /* TUs */
+	p2p_pairing_info_init(p2p);
 
 	p2p_dbg(p2p, "initialized");
 	p2p_channels_dump(p2p, "channels", &p2p->cfg->channels);
@@ -3082,6 +3146,7 @@ void p2p_deinit(struct p2p_data *p2p)
 	p2p_remove_wps_vendor_extensions(p2p);
 	os_free(p2p->no_go_freq.range);
 	p2p_service_flush_asp(p2p);
+	p2p_pairing_info_deinit(p2p);
 
 	os_free(p2p);
 }
@@ -3415,7 +3480,7 @@ static void p2p_retry_pd(struct p2p_data *p2p)
 		if (!ether_addr_equal(p2p->pending_pd_devaddr,
 				      dev->info.p2p_device_addr))
 			continue;
-		if (!dev->req_config_methods)
+		if (!dev->req_config_methods && !dev->req_bootstrap_method)
 			continue;
 
 		p2p_dbg(p2p, "Send pending Provision Discovery Request to "
@@ -4933,8 +4998,13 @@ int p2p_get_interface_addr(struct p2p_data *p2p, const u8 *dev_addr,
 			   u8 *iface_addr)
 {
 	struct p2p_device *dev = p2p_get_device(p2p, dev_addr);
-	if (dev == NULL || is_zero_ether_addr(dev->interface_addr))
+
+	if (!dev || is_zero_ether_addr(dev->interface_addr)) {
+		p2p_dbg(p2p,
+			"P2P: Failed to get interface address from device addr "
+			MACSTR, MAC2STR(dev_addr));
 		return -1;
+	}
 	os_memcpy(iface_addr, dev->interface_addr, ETH_ALEN);
 	return 0;
 }
@@ -4944,8 +5014,13 @@ int p2p_get_dev_addr(struct p2p_data *p2p, const u8 *iface_addr,
 			   u8 *dev_addr)
 {
 	struct p2p_device *dev = p2p_get_device_interface(p2p, iface_addr);
-	if (dev == NULL)
+
+	if (!dev) {
+		p2p_dbg(p2p,
+			"P2P: Failed to get device address from interface address "
+			MACSTR, MAC2STR(iface_addr));
 		return -1;
+	}
 	os_memcpy(dev_addr, dev->info.p2p_device_addr, ETH_ALEN);
 	return 0;
 }
@@ -5704,3 +5779,184 @@ void set_p2p_allow_6ghz(struct p2p_data *p2p, bool value)
 {
 	p2p->allow_6ghz = value;
 }
+
+
+static int p2p_derive_nonce_tag(struct p2p_data *p2p)
+{
+	u8 dira_nonce[DEVICE_IDENTITY_NONCE_LEN];
+	u8 dira_tag[DEVICE_MAX_HASH_LEN];
+	u8 data[DIR_STR_LEN + DEVICE_IDENTITY_NONCE_LEN + ETH_ALEN];
+	struct p2p_id_key *dev_ik;
+
+	dev_ik = &p2p->pairing_info->dev_ik;
+
+	if (dev_ik->cipher_version != DIRA_CIPHER_VERSION_128) {
+		wpa_printf(MSG_INFO,
+			   "P2P: Unsupported DIRA Cipher version = %d",
+			   dev_ik->cipher_version);
+		return -1;
+	}
+
+	if (dev_ik->dik_len != DEVICE_IDENTITY_KEY_LEN) {
+		wpa_printf(MSG_INFO, "P2P: Invalid DIK length = %zu",
+			   dev_ik->dik_len);
+		return -1;
+	}
+
+	os_memset(data, 0, sizeof(data));
+
+	if (os_get_random(dira_nonce, DEVICE_IDENTITY_NONCE_LEN) < 0) {
+		wpa_printf(MSG_ERROR, "P2P: Failed to generate DIRA nonce");
+		return -1;
+	}
+
+	/* Tag = Truncate-64(HMAC-SHA-256(DevIK,
+	 *                                "DIR" || P2P Device Address || Nonce))
+	 */
+	os_memcpy(data, "DIR", DIR_STR_LEN);
+	os_memcpy(&data[DIR_STR_LEN], p2p->cfg->dev_addr, ETH_ALEN);
+	os_memcpy(&data[DIR_STR_LEN + ETH_ALEN], dira_nonce,
+		  DEVICE_IDENTITY_NONCE_LEN);
+
+	if (hmac_sha256(dev_ik->dik_data, dev_ik->dik_len, data, sizeof(data),
+			dira_tag) < 0) {
+		wpa_printf(MSG_ERROR, "P2P: Could not derive DIRA tag");
+		return -1;
+	}
+
+	dev_ik->dira_nonce_len = DEVICE_IDENTITY_NONCE_LEN;
+	os_memcpy(dev_ik->dira_nonce, dira_nonce, DEVICE_IDENTITY_NONCE_LEN);
+	dev_ik->dira_tag_len = DEVICE_IDENTITY_TAG_LEN;
+	os_memcpy(dev_ik->dira_tag, dira_tag, DEVICE_IDENTITY_TAG_LEN);
+
+	wpa_hexdump_key(MSG_DEBUG, "P2P: DIK", dev_ik->dik_data,
+			dev_ik->dik_len);
+	wpa_hexdump_key(MSG_DEBUG, "P2P: DIRA-NONCE", dev_ik->dira_nonce,
+			dev_ik->dira_nonce_len);
+	wpa_hexdump_key(MSG_DEBUG, "P2P: DIRA-TAG", dev_ik->dira_tag,
+			dev_ik->dira_tag_len);
+	return 0;
+}
+
+
+struct wpabuf * p2p_usd_elems(struct p2p_data *p2p)
+{
+	struct wpabuf *buf;
+	u8 *len;
+	u8 group_capab;
+
+	buf = wpabuf_alloc(1000);
+	if (!buf)
+		return NULL;
+
+	len = p2p_buf_add_ie_hdr(buf);
+
+	/* P2P Capability attribute */
+	group_capab = 0;
+	if (p2p->num_groups) {
+		group_capab |= P2P_GROUP_CAPAB_GROUP_OWNER;
+		if ((p2p->dev_capab & P2P_DEV_CAPAB_CONCURRENT_OPER) &&
+		    (p2p->dev_capab & P2P_DEV_CAPAB_INFRA_MANAGED) &&
+		    p2p->cross_connect)
+			group_capab |= P2P_GROUP_CAPAB_CROSS_CONN;
+	}
+	if (p2p->cfg->p2p_intra_bss)
+		group_capab |= P2P_GROUP_CAPAB_INTRA_BSS_DIST;
+	p2p_buf_add_capability(buf, p2p->dev_capab &
+			       ~P2P_DEV_CAPAB_CLIENT_DISCOVERABILITY,
+			       group_capab);
+
+	/* P2P Device Info attribute */
+	p2p_buf_add_device_info(buf, p2p, NULL);
+
+	p2p_buf_update_ie_hdr(buf, len);
+
+	len = p2p_buf_add_p2p2_ie_hdr(buf);
+
+	/* P2P Capability Extension attribute */
+	p2p_buf_add_pcea(buf, p2p);
+
+	/* P2P Pairing Bootstrapping Method attribute */
+	p2p_buf_add_pbma(buf, p2p->cfg->pairing_config.bootstrap_methods, NULL,
+			 0, 0);
+
+	/* P2P Device Identity Resolution attribute */
+	if (p2p->pairing_info &&
+	    p2p->cfg->pairing_config.pairing_capable &&
+	    p2p->cfg->pairing_config.enable_pairing_cache &&
+	    p2p->cfg->pairing_config.enable_pairing_verification &&
+	    p2p_derive_nonce_tag(p2p) == 0)
+		p2p_buf_add_dira(buf, p2p);
+
+	p2p_buf_update_ie_hdr(buf, len);
+
+	return buf;
+}
+
+
+void p2p_process_usd_elems(struct p2p_data *p2p, const u8 *ies, u16 ies_len,
+			   const u8 *peer_addr, unsigned int freq)
+{
+	struct p2p_device *dev;
+	struct p2p_message msg;
+	const u8 *p2p_dev_addr;
+
+	os_memset(&msg, 0, sizeof(msg));
+	if (p2p_parse_ies(ies, ies_len, &msg)) {
+		p2p_dbg(p2p, "Failed to parse P2P IE for a device entry");
+		p2p_parse_free(&msg);
+		return;
+	}
+	if (msg.p2p_device_addr)
+		p2p_dev_addr = msg.p2p_device_addr;
+	else
+		p2p_dev_addr = peer_addr;
+
+	dev = p2p_create_device(p2p, p2p_dev_addr);
+	if (!dev) {
+		p2p_parse_free(&msg);
+		p2p_dbg(p2p, "Failed to add a peer P2P Device");
+		return;
+	}
+
+	dev->p2p2 = true;
+	/* Reset info from old IEs */
+	dev->info.reg_info = 0;
+	os_memset(&dev->info.pairing_config, 0,
+		  sizeof(struct p2p_pairing_config));
+
+	os_get_reltime(&dev->last_seen);
+	dev->listen_freq = freq;
+	dev->oper_freq = freq;
+
+	if (msg.capability) {
+		/*
+		 * P2P Client Discoverability bit is reserved in all frames
+		 * that use this function, so do not change its value here.
+		 */
+		dev->info.dev_capab &= P2P_DEV_CAPAB_CLIENT_DISCOVERABILITY;
+		dev->info.dev_capab |= msg.capability[0] &
+			~P2P_DEV_CAPAB_CLIENT_DISCOVERABILITY;
+		dev->info.group_capab = msg.capability[1];
+	}
+
+	if (msg.pcea_info && msg.pcea_info_len >= 2)
+		p2p_process_pcea(p2p, &msg, dev);
+
+	if (msg.pbma_info && msg.pbma_info_len == 2)
+		dev->info.pairing_config.bootstrap_methods =
+			WPA_GET_LE16(msg.pbma_info);
+
+	if (!ether_addr_equal(peer_addr, p2p_dev_addr))
+		os_memcpy(dev->interface_addr, peer_addr, ETH_ALEN);
+
+	p2p_dbg(p2p, "Updated device entry based on USD frame: " MACSTR
+		" dev_capab=0x%x group_capab=0x%x listen_freq=%d",
+		MAC2STR(dev->info.p2p_device_addr), dev->info.dev_capab,
+		dev->info.group_capab, dev->listen_freq);
+
+	p2p->cfg->dev_found(p2p->cfg->cb_ctx, dev->info.p2p_device_addr,
+			    &dev->info, !(dev->flags & P2P_DEV_REPORTED_ONCE));
+
+	p2p_parse_free(&msg);
+}
diff --git a/src/p2p/p2p.h b/src/p2p/p2p.h
index 77841285..5b5c7dd4 100644
--- a/src/p2p/p2p.h
+++ b/src/p2p/p2p.h
@@ -12,6 +12,16 @@
 #include "common/ieee802_11_defs.h"
 #include "wps/wps.h"
 
+#define DEVICE_IDENTITY_KEY_MAX_LEN 64
+#define DEVICE_IDENTITY_KEY_LEN 16
+#define DEVICE_IDENTITY_TAG_LEN 8
+#define DEVICE_IDENTITY_NONCE_LEN 8
+#define DEVICE_MAX_HASH_LEN 32
+#define DIR_STR_LEN 3
+
+/* DIRA Cipher versions */
+#define DIRA_CIPHER_VERSION_128 0
+
 struct weighted_pcl;
 
 /* P2P ASP Setup Capability */
@@ -320,6 +330,50 @@ enum p2p_scan_type {
 
 #define P2P_MAX_WPS_VENDOR_EXT 10
 
+/**
+ * struct p2p_pairing_config - P2P pairing configuration
+ */
+struct p2p_pairing_config {
+	/**
+	 * Pairing capable
+	 */
+	bool pairing_capable;
+
+	/**
+	 * Enable P2P pairing setup
+	 */
+	bool enable_pairing_setup;
+
+	/**
+	 * Enable pairing cache to allow verification
+	 */
+	bool enable_pairing_cache;
+
+	/**
+	 * Enable P2P pairing verification with cached NIK/NPK
+	 */
+	bool enable_pairing_verification;
+
+	/**
+	 * P2P bootstrapping methods supported
+	 */
+	u16 bootstrap_methods;
+
+	/**
+	 * Bitmap of supported PASN types
+	 */
+	u8 pasn_type;
+
+	/* Cipher version type */
+	int dik_cipher;
+
+	/* Buffer to hold the DevIK */
+	u8 dik_data[DEVICE_IDENTITY_KEY_MAX_LEN];
+
+	/* Length of DevIK in octets */
+	size_t dik_len;
+};
+
 /**
  * struct p2p_peer_info - P2P peer information
  */
@@ -411,6 +465,21 @@ struct p2p_peer_info {
 	 * p2ps_instance - P2PS Application Service Info
 	 */
 	struct wpabuf *p2ps_instance;
+
+	/**
+	 * pcea_cap_info - Capability info in PCEA
+	 */
+	u16 pcea_cap_info;
+
+	/**
+	 * The regulatory info encoding for operation in 6 GHz band
+	 */
+	u8 reg_info;
+
+	/**
+	 * p2p_pairing_config - P2P pairing configuration
+	 */
+	struct p2p_pairing_config pairing_config;
 };
 
 enum p2p_prov_disc_status {
@@ -594,6 +663,33 @@ struct p2p_config {
 	 */
 	unsigned int passphrase_len;
 
+	/**
+	 * p2p_pairing_config - P2P pairing configuration
+	 */
+	struct p2p_pairing_config pairing_config;
+
+	/**
+	 * reg_info - Regulatory info encoding for operation in 6 GHz band
+	 */
+	u8 reg_info;
+
+	/**
+	 * dfs_owner - Enable P2P GO to act as DFS Owner
+	 */
+	bool dfs_owner;
+
+	/**
+	 * twt_power_mgmt - Enable TWT based power management for P2P
+	 */
+	bool twt_power_mgmt;
+
+	/**
+	 * comeback_after - Bootstrap request unauthorized for peer
+	 *
+	 * Ask to come back after this many TUs.
+	 */
+	u16 comeback_after;
+
 	/**
 	 * cb_ctx - Context to use with callback functions
 	 */
@@ -1089,7 +1185,8 @@ struct p2p_config {
 	 * When P2PS provisioning completes (successfully or not) we must
 	 * transmit all of the results to the upper layers.
 	 */
-	void (*p2ps_prov_complete)(void *ctx, u8 status, const u8 *dev,
+	void (*p2ps_prov_complete)(void *ctx, enum p2p_status_code status,
+				   const u8 *dev,
 				   const u8 *adv_mac, const u8 *ses_mac,
 				   const u8 *grp_mac, u32 adv_id, u32 ses_id,
 				   u8 conncap, int passwd_id,
@@ -1141,6 +1238,44 @@ struct p2p_config {
 	int (*get_pref_freq_list)(void *ctx, int go,
 				  unsigned int *len,
 				  struct weighted_pcl *freq_list);
+
+	/**
+	 * register_bootstrap_comeback - Register timeout to initiate bootstrap
+	 *	comeback request
+	 * @ctx: Callback context from cb_ctx
+	 * @addr: P2P Device Address to which comeback request is to be sent
+	 * @comeback_after: Time in TUs after which comeback request is sent
+	 *
+	 * This function can be used to send comeback request after given
+	 * timeout.
+	 */
+	void (*register_bootstrap_comeback)(void *ctx, const u8 *addr,
+					    u16 comeback_after);
+
+	/**
+	 * bootstrap_req_rx - Indicate bootstrap request from a P2P peer
+	 * @ctx: Callback context from cb_ctx
+	 * @addr: P2P device address from which bootstrap request was received
+	 * @bootstrap_method: Bootstrapping method request by the peer device
+	 *
+	 * This function can be used to notify that bootstrap request is
+	 * received from a P2P peer.
+	 */
+	void (*bootstrap_req_rx)(void *ctx, const u8 *addr,
+				 u16 bootstrap_method);
+
+	/**
+	 * bootstrap_completed - Indicate bootstrapping completed with P2P peer
+	 * @ctx: Callback context from cb_ctx
+	 * @addr: P2P device address with which bootstrapping is completed
+	 * @status: P2P Status Code of bootstrapping handshake
+	 * @freq: Frequency in which bootstrapping is done
+	 *
+	 * This function can be used to notify the status of bootstrapping
+	 * handshake.
+	 */
+	void (*bootstrap_completed)(void *ctx, const u8 *addr,
+				    enum p2p_status_code status, int freq);
 };
 
 
@@ -1324,6 +1459,10 @@ void p2p_stop_listen(struct p2p_data *p2p);
  *	formation
  * @pref_freq: Preferred operating frequency in MHz or 0 (this is only used if
  *	force_freq == 0)
+ * @oob_pw_id: OOB password identifier
+ * @p2p2: Device supports P2P2 features
+ * @bootstrap: Bootstrapping method requested for P2P2 provision discovery
+ * @password: P2P2 pairing password or %NULL for opportunistic method
  * Returns: 0 on success, -1 on failure
  */
 int p2p_connect(struct p2p_data *p2p, const u8 *peer_addr,
@@ -1331,7 +1470,8 @@ int p2p_connect(struct p2p_data *p2p, const u8 *peer_addr,
 		int go_intent, const u8 *own_interface_addr,
 		unsigned int force_freq, int persistent_group,
 		const u8 *force_ssid, size_t force_ssid_len,
-		int pd_before_go_neg, unsigned int pref_freq, u16 oob_pw_id);
+		int pd_before_go_neg, unsigned int pref_freq, u16 oob_pw_id,
+		bool p2p2, u16 bootstrap, const char *password);
 
 /**
  * p2p_authorize - Authorize P2P group formation (GO negotiation)
@@ -1349,6 +1489,9 @@ int p2p_connect(struct p2p_data *p2p, const u8 *peer_addr,
  * @force_ssid_len: Length of $force_ssid buffer
  * @pref_freq: Preferred operating frequency in MHz or 0 (this is only used if
  *	force_freq == 0)
+ * @oob_pw_id: OOB password identifier
+ * @bootstrap: Bootstrapping method requested for P2P2 provision discovery
+ * @password: P2P2 pairing password or %NULL for opportunistic method
  * Returns: 0 on success, -1 on failure
  *
  * This is like p2p_connect(), but the actual group negotiation is not
@@ -1359,7 +1502,8 @@ int p2p_authorize(struct p2p_data *p2p, const u8 *peer_addr,
 		  int go_intent, const u8 *own_interface_addr,
 		  unsigned int force_freq, int persistent_group,
 		  const u8 *force_ssid, size_t force_ssid_len,
-		  unsigned int pref_freq, u16 oob_pw_id);
+		  unsigned int pref_freq, u16 oob_pw_id, u16 bootstrap,
+		  const char *password);
 
 /**
  * p2p_reject - Reject peer device (explicitly block connection attempts)
@@ -2435,5 +2579,8 @@ bool is_p2p_allow_6ghz(struct p2p_data *p2p);
 void set_p2p_allow_6ghz(struct p2p_data *p2p, bool value);
 int p2p_remove_6ghz_channels(struct weighted_pcl *pref_freq_list, int size);
 int p2p_channel_to_freq(int op_class, int channel);
+struct wpabuf * p2p_usd_elems(struct p2p_data *p2p);
+void p2p_process_usd_elems(struct p2p_data *p2p, const u8 *ies, u16 ies_len,
+			   const u8 *peer_addr, unsigned int freq);
 
 #endif /* P2P_H */
diff --git a/src/p2p/p2p_build.c b/src/p2p/p2p_build.c
index e4f40fe8..ddadd34b 100644
--- a/src/p2p/p2p_build.c
+++ b/src/p2p/p2p_build.c
@@ -55,11 +55,24 @@ u8 * p2p_buf_add_ie_hdr(struct wpabuf *buf)
 
 void p2p_buf_update_ie_hdr(struct wpabuf *buf, u8 *len)
 {
-	/* Update P2P IE Length */
+	/* Update P2P/P2P2 IE Length */
 	*len = (u8 *) wpabuf_put(buf, 0) - len - 1;
 }
 
 
+u8 * p2p_buf_add_p2p2_ie_hdr(struct wpabuf *buf)
+{
+	u8 *len;
+
+	/* P2P2 IE header */
+	wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC);
+	len = wpabuf_put(buf, 1); /* IE length to be filled */
+	wpabuf_put_be32(buf, P2P2_IE_VENDOR_TYPE);
+	wpa_printf(MSG_DEBUG, "P2P: * P2P2 IE header");
+	return len;
+}
+
+
 void p2p_buf_add_capability(struct wpabuf *buf, u8 dev_capab, u8 group_capab)
 {
 	/* P2P Capability */
@@ -709,6 +722,111 @@ void p2p_buf_add_persistent_group_info(struct wpabuf *buf, const u8 *dev_addr,
 }
 
 
+void p2p_buf_add_pcea(struct wpabuf *buf, struct p2p_data *p2p)
+{
+	u8 *len;
+	u16 capability_info = 0;
+
+	/* P2P Capability Extension */
+	wpabuf_put_u8(buf, P2P_ATTR_CAPABILITY_EXTENSION);
+	/* Length to be filled */
+	len = wpabuf_put(buf, 2);
+
+	if (!p2p->cfg->p2p_6ghz_disable)
+		capability_info |= P2P_PCEA_6GHZ;
+
+	if (p2p->cfg->reg_info)
+		capability_info |= P2P_PCEA_REG_INFO;
+
+	if (p2p->cfg->dfs_owner)
+		capability_info |= P2P_PCEA_DFS_OWNER;
+
+	if (p2p->cfg->pairing_config.pairing_capable)
+		capability_info |= P2P_PCEA_PAIRING_CAPABLE;
+
+	if (p2p->cfg->pairing_config.enable_pairing_setup)
+		capability_info |= P2P_PCEA_PAIRING_SETUP_ENABLED;
+
+	if (p2p->cfg->pairing_config.enable_pairing_cache)
+		capability_info |= P2P_PCEA_PMK_CACHING;
+
+	if (p2p->cfg->pairing_config.pasn_type)
+		capability_info |= P2P_PCEA_PASN_TYPE;
+
+	if (p2p->cfg->twt_power_mgmt)
+		capability_info |= P2P_PCEA_TWT_POWER_MGMT;
+
+	/* Field length is (n-1), n in octets */
+	capability_info |= (2 - 1) & P2P_PCEA_LEN_MASK;
+	wpabuf_put_le16(buf, capability_info);
+
+	if (capability_info & P2P_PCEA_REG_INFO)
+		wpabuf_put_u8(buf, p2p->cfg->reg_info);
+
+	if (capability_info & P2P_PCEA_PASN_TYPE)
+		wpabuf_put_u8(buf, p2p->cfg->pairing_config.pasn_type);
+
+	/* Update attribute length */
+	WPA_PUT_LE16(len, (u8 *) wpabuf_put(buf, 0) - len - 2);
+
+	wpa_printf(MSG_DEBUG, "P2P: * Capability Extension info=0x%x",
+		   capability_info);
+}
+
+
+void p2p_buf_add_pbma(struct wpabuf *buf, u16 bootstrap, const u8 *cookie,
+		      size_t cookie_len, int comeback_after)
+{
+	u8 *len;
+
+	/* P2P Pairing and Bootstrapping methods */
+	wpabuf_put_u8(buf, P2P_ATTR_PAIRING_AND_BOOTSTRAPPING);
+	/* Length to be filled */
+	len = wpabuf_put(buf, 2);
+
+	if (cookie && cookie_len) {
+		if (comeback_after)
+			wpabuf_put_le16(buf, comeback_after);
+		wpabuf_put_u8(buf, cookie_len);
+		wpabuf_put_data(buf, cookie, cookie_len);
+	}
+	wpabuf_put_le16(buf, bootstrap);
+
+	/* Update attribute length */
+	WPA_PUT_LE16(len, (u8 *) wpabuf_put(buf, 0) - len - 2);
+
+	wpa_printf(MSG_DEBUG, "P2P: * Bootstrapping method=0x%x",
+		   bootstrap);
+}
+
+
+void p2p_buf_add_dira(struct wpabuf *buf, struct p2p_data *p2p)
+{
+	u8 *len;
+	struct p2p_id_key *dev_ik;
+
+	if (!p2p->cfg->pairing_config.pairing_capable ||
+	    !p2p->cfg->pairing_config.enable_pairing_cache ||
+	    !p2p->cfg->pairing_config.enable_pairing_verification)
+		return;
+
+	dev_ik = &p2p->pairing_info->dev_ik;
+	/* P2P DIRA */
+	wpabuf_put_u8(buf, P2P_ATTR_DEVICE_IDENTITY_RESOLUTION);
+	/* Length to be filled */
+	len = wpabuf_put(buf, 2);
+
+	wpabuf_put_u8(buf, dev_ik->cipher_version);
+	wpabuf_put_data(buf, dev_ik->dira_nonce, dev_ik->dira_nonce_len);
+	wpabuf_put_data(buf, dev_ik->dira_tag, dev_ik->dira_tag_len);
+
+	/* Update attribute length */
+	WPA_PUT_LE16(len, (u8 *) wpabuf_put(buf, 0) - len - 2);
+
+	wpa_printf(MSG_DEBUG, "P2P: * DIRA");
+}
+
+
 static int p2p_add_wps_string(struct wpabuf *buf, enum wps_attribute attr,
 			      const char *val)
 {
@@ -839,3 +957,37 @@ int p2p_build_wps_ie(struct p2p_data *p2p, struct wpabuf *buf, int pw_id,
 
 	return 0;
 }
+
+
+struct wpabuf * p2p_encaps_ie(const struct wpabuf *subelems, u32 ie_type)
+{
+	struct wpabuf *ie;
+	const u8 *pos, *end;
+	size_t len;
+
+	if (!subelems)
+		return NULL;
+
+	len = wpabuf_len(subelems) + 1000;
+
+	ie = wpabuf_alloc(len);
+	if (!ie)
+		return NULL;
+
+	pos = wpabuf_head(subelems);
+	end = pos + wpabuf_len(subelems);
+
+	while (end > pos) {
+		size_t frag_len = end - pos;
+
+		if (frag_len > 251)
+			frag_len = 251;
+		wpabuf_put_u8(ie, WLAN_EID_VENDOR_SPECIFIC);
+		wpabuf_put_u8(ie, 4 + frag_len);
+		wpabuf_put_be32(ie, ie_type);
+		wpabuf_put_data(ie, pos, frag_len);
+		pos += frag_len;
+	}
+
+	return ie;
+}
diff --git a/src/p2p/p2p_go_neg.c b/src/p2p/p2p_go_neg.c
index 30901b34..ac6bbf75 100644
--- a/src/p2p/p2p_go_neg.c
+++ b/src/p2p/p2p_go_neg.c
@@ -135,11 +135,11 @@ static const char * p2p_wps_method_str(enum p2p_wps_method wps_method)
 }
 
 
-static struct wpabuf * p2p_build_go_neg_req(struct p2p_data *p2p,
-					    struct p2p_device *peer)
+struct wpabuf * p2p_build_go_neg_req(struct p2p_data *p2p,
+				     struct p2p_device *peer)
 {
 	struct wpabuf *buf;
-	u8 *len;
+	struct wpabuf *subelems;
 	u8 group_capab;
 	size_t extra = 0;
 	u16 pw_id;
@@ -159,7 +159,12 @@ static struct wpabuf * p2p_build_go_neg_req(struct p2p_data *p2p,
 
 	p2p_buf_add_public_action_hdr(buf, P2P_GO_NEG_REQ, peer->dialog_token);
 
-	len = p2p_buf_add_ie_hdr(buf);
+	subelems = wpabuf_alloc(500);
+	if (!subelems) {
+		wpabuf_free(buf);
+		return NULL;
+	}
+
 	group_capab = 0;
 	if (peer->flags & P2P_DEV_PREFER_PERSISTENT_GROUP) {
 		group_capab |= P2P_GROUP_CAPAB_PERSISTENT_GROUP;
@@ -170,17 +175,20 @@ static struct wpabuf * p2p_build_go_neg_req(struct p2p_data *p2p,
 		group_capab |= P2P_GROUP_CAPAB_CROSS_CONN;
 	if (p2p->cfg->p2p_intra_bss)
 		group_capab |= P2P_GROUP_CAPAB_INTRA_BSS_DIST;
-	p2p_buf_add_capability(buf, p2p->dev_capab &
+	p2p_buf_add_capability(subelems, p2p->dev_capab &
 			       ~P2P_DEV_CAPAB_CLIENT_DISCOVERABILITY,
 			       group_capab);
-	p2p_buf_add_go_intent(buf, (p2p->go_intent << 1) | peer->tie_breaker);
-	p2p_buf_add_config_timeout(buf, p2p->go_timeout, p2p->client_timeout);
-	p2p_buf_add_listen_channel(buf, p2p->cfg->country, p2p->cfg->reg_class,
+	p2p_buf_add_go_intent(subelems,
+			      (p2p->go_intent << 1) | peer->tie_breaker);
+	p2p_buf_add_config_timeout(subelems, p2p->go_timeout,
+				   p2p->client_timeout);
+	p2p_buf_add_listen_channel(subelems, p2p->cfg->country,
+				   p2p->cfg->reg_class,
 				   p2p->cfg->channel);
 	if (p2p->ext_listen_interval)
-		p2p_buf_add_ext_listen_timing(buf, p2p->ext_listen_period,
+		p2p_buf_add_ext_listen_timing(subelems, p2p->ext_listen_period,
 					      p2p->ext_listen_interval);
-	p2p_buf_add_intended_addr(buf, p2p->intended_addr);
+	p2p_buf_add_intended_addr(subelems, p2p->intended_addr);
 	is_6ghz_capab = is_p2p_6ghz_capable(p2p) &&
 		p2p_is_peer_6ghz_capab(p2p, peer->info.p2p_device_addr);
 	if (p2p->num_pref_freq) {
@@ -191,16 +199,15 @@ static struct wpabuf * p2p_build_go_neg_req(struct p2p_data *p2p,
 					p2p->num_pref_freq, &pref_chanlist, go);
 		p2p_channels_dump(p2p, "channel list after filtering",
 				  &pref_chanlist);
-		p2p_buf_add_channel_list(buf, p2p->cfg->country,
+		p2p_buf_add_channel_list(subelems, p2p->cfg->country,
 					 &pref_chanlist, is_6ghz_capab);
 	} else {
-		p2p_buf_add_channel_list(buf, p2p->cfg->country,
+		p2p_buf_add_channel_list(subelems, p2p->cfg->country,
 					 &p2p->channels, is_6ghz_capab);
 	}
-	p2p_buf_add_device_info(buf, p2p, peer);
-	p2p_buf_add_operating_channel(buf, p2p->cfg->country,
+	p2p_buf_add_device_info(subelems, p2p, peer);
+	p2p_buf_add_operating_channel(subelems, p2p->cfg->country,
 				      p2p->op_reg_class, p2p->op_channel);
-	p2p_buf_update_ie_hdr(buf, len);
 
 	p2p_buf_add_pref_channel_list(buf, p2p->pref_freq_list,
 				      p2p->num_pref_freq);
@@ -209,8 +216,9 @@ static struct wpabuf * p2p_build_go_neg_req(struct p2p_data *p2p,
 	pw_id = p2p_wps_method_pw_id(peer->wps_method);
 	if (peer->oob_pw_id)
 		pw_id = peer->oob_pw_id;
-	if (p2p_build_wps_ie(p2p, buf, pw_id, 0) < 0) {
+	if (!peer->p2p2 && p2p_build_wps_ie(p2p, buf, pw_id, 0) < 0) {
 		p2p_dbg(p2p, "Failed to build WPS IE for GO Negotiation Request");
+		wpabuf_free(subelems);
 		wpabuf_free(buf);
 		return NULL;
 	}
@@ -223,6 +231,8 @@ static struct wpabuf * p2p_build_go_neg_req(struct p2p_data *p2p,
 	if (p2p->vendor_elem && p2p->vendor_elem[VENDOR_ELEM_P2P_GO_NEG_REQ])
 		wpabuf_put_buf(buf, p2p->vendor_elem[VENDOR_ELEM_P2P_GO_NEG_REQ]);
 
+	buf = wpabuf_concat(buf, p2p_encaps_ie(subelems, P2P_IE_VENDOR_TYPE));
+	wpabuf_free(subelems);
 	return buf;
 }
 
@@ -244,6 +254,8 @@ int p2p_connect_send(struct p2p_data *p2p, struct p2p_device *dev)
 			config_method = WPS_CONFIG_PUSHBUTTON;
 		else if (dev->wps_method == WPS_P2PS)
 			config_method = WPS_CONFIG_P2PS;
+		else if (dev->p2p2 && dev->req_bootstrap_method)
+			config_method = WPS_NOT_READY;
 		else
 			return -1;
 		return p2p_prov_disc_req(p2p, dev->info.p2p_device_addr,
@@ -291,7 +303,7 @@ static struct wpabuf * p2p_build_go_neg_resp(struct p2p_data *p2p,
 					     u8 tie_breaker)
 {
 	struct wpabuf *buf;
-	u8 *len;
+	struct wpabuf *subelems;
 	u8 group_capab;
 	size_t extra = 0;
 	u16 pw_id;
@@ -314,8 +326,13 @@ static struct wpabuf * p2p_build_go_neg_resp(struct p2p_data *p2p,
 
 	p2p_buf_add_public_action_hdr(buf, P2P_GO_NEG_RESP, dialog_token);
 
-	len = p2p_buf_add_ie_hdr(buf);
-	p2p_buf_add_status(buf, status);
+	subelems = wpabuf_alloc(500);
+	if (!subelems) {
+		wpabuf_free(buf);
+		return NULL;
+	}
+
+	p2p_buf_add_status(subelems, status);
 	group_capab = 0;
 	if (peer && peer->go_state == LOCAL_GO) {
 		if (peer->flags & P2P_DEV_PREFER_PERSISTENT_GROUP) {
@@ -329,24 +346,26 @@ static struct wpabuf * p2p_build_go_neg_resp(struct p2p_data *p2p,
 		if (p2p->cfg->p2p_intra_bss)
 			group_capab |= P2P_GROUP_CAPAB_INTRA_BSS_DIST;
 	}
-	p2p_buf_add_capability(buf, p2p->dev_capab &
+	p2p_buf_add_capability(subelems, p2p->dev_capab &
 			       ~P2P_DEV_CAPAB_CLIENT_DISCOVERABILITY,
 			       group_capab);
-	p2p_buf_add_go_intent(buf, (p2p->go_intent << 1) | tie_breaker);
-	p2p_buf_add_config_timeout(buf, p2p->go_timeout, p2p->client_timeout);
+	p2p_buf_add_go_intent(subelems, (p2p->go_intent << 1) | tie_breaker);
+	p2p_buf_add_config_timeout(subelems, p2p->go_timeout,
+				   p2p->client_timeout);
 	if (p2p->override_pref_op_class) {
 		p2p_dbg(p2p, "Override operating channel preference");
-		p2p_buf_add_operating_channel(buf, p2p->cfg->country,
+		p2p_buf_add_operating_channel(subelems, p2p->cfg->country,
 					      p2p->override_pref_op_class,
 					      p2p->override_pref_channel);
 	} else if (peer && peer->go_state == REMOTE_GO && !p2p->num_pref_freq) {
 		p2p_dbg(p2p, "Omit Operating Channel attribute");
 	} else {
-		p2p_buf_add_operating_channel(buf, p2p->cfg->country,
+		p2p_buf_add_operating_channel(subelems, p2p->cfg->country,
 					      p2p->op_reg_class,
 					      p2p->op_channel);
 	}
-	p2p_buf_add_intended_addr(buf, p2p->intended_addr);
+	p2p_buf_add_intended_addr(subelems, p2p->intended_addr);
+
 	if (p2p->num_pref_freq) {
 		bool go = (peer && peer->go_state == LOCAL_GO) ||
 			p2p->go_intent == 15;
@@ -360,12 +379,12 @@ static struct wpabuf * p2p_build_go_neg_resp(struct p2p_data *p2p,
 				  p2p->allow_6ghz);
 	}
 	if (status || peer == NULL) {
-		p2p_buf_add_channel_list(buf, p2p->cfg->country,
+		p2p_buf_add_channel_list(subelems, p2p->cfg->country,
 					 &pref_chanlist, false);
 	} else if (peer->go_state == REMOTE_GO) {
 		is_6ghz_capab = is_p2p_6ghz_capable(p2p) &&
 			p2p_is_peer_6ghz_capab(p2p, peer->info.p2p_device_addr);
-		p2p_buf_add_channel_list(buf, p2p->cfg->country,
+		p2p_buf_add_channel_list(subelems, p2p->cfg->country,
 					 &pref_chanlist, is_6ghz_capab);
 	} else {
 		struct p2p_channels res;
@@ -374,22 +393,22 @@ static struct wpabuf * p2p_build_go_neg_resp(struct p2p_data *p2p,
 			p2p_is_peer_6ghz_capab(p2p, peer->info.p2p_device_addr);
 		p2p_channels_intersect(&pref_chanlist, &peer->channels,
 				       &res);
-		p2p_buf_add_channel_list(buf, p2p->cfg->country, &res,
-				       is_6ghz_capab);
+		p2p_buf_add_channel_list(subelems, p2p->cfg->country, &res,
+					 is_6ghz_capab);
 	}
-	p2p_buf_add_device_info(buf, p2p, peer);
+	p2p_buf_add_device_info(subelems, p2p, peer);
 	if (peer && peer->go_state == LOCAL_GO) {
-		p2p_buf_add_group_id(buf, p2p->cfg->dev_addr, p2p->ssid,
+		p2p_buf_add_group_id(subelems, p2p->cfg->dev_addr, p2p->ssid,
 				     p2p->ssid_len);
 	}
-	p2p_buf_update_ie_hdr(buf, len);
 
 	/* WPS IE with Device Password ID attribute */
 	pw_id = p2p_wps_method_pw_id(peer ? peer->wps_method : WPS_NOT_READY);
 	if (peer && peer->oob_pw_id)
 		pw_id = peer->oob_pw_id;
-	if (p2p_build_wps_ie(p2p, buf, pw_id, 0) < 0) {
+	if (peer && !peer->p2p2 && p2p_build_wps_ie(p2p, buf, pw_id, 0) < 0) {
 		p2p_dbg(p2p, "Failed to build WPS IE for GO Negotiation Response");
+		wpabuf_free(subelems);
 		wpabuf_free(buf);
 		return NULL;
 	}
@@ -402,6 +421,8 @@ static struct wpabuf * p2p_build_go_neg_resp(struct p2p_data *p2p,
 	if (p2p->vendor_elem && p2p->vendor_elem[VENDOR_ELEM_P2P_GO_NEG_RESP])
 		wpabuf_put_buf(buf, p2p->vendor_elem[VENDOR_ELEM_P2P_GO_NEG_RESP]);
 
+	buf = wpabuf_concat(buf, p2p_encaps_ie(subelems, P2P_IE_VENDOR_TYPE));
+	wpabuf_free(subelems);
 	return buf;
 }
 
@@ -799,21 +820,21 @@ void p2p_check_pref_chan(struct p2p_data *p2p, int go,
 }
 
 
-void p2p_process_go_neg_req(struct p2p_data *p2p, const u8 *sa,
-			    const u8 *data, size_t len, int rx_freq)
+struct wpabuf * p2p_process_go_neg_req(struct p2p_data *p2p, const u8 *sa,
+				       const u8 *data, size_t len, int rx_freq,
+				       bool p2p2)
 {
 	struct p2p_device *dev = NULL;
 	struct wpabuf *resp;
 	struct p2p_message msg;
 	u8 status = P2P_SC_FAIL_INVALID_PARAMS;
 	int tie_breaker = 0;
-	int freq;
 
 	p2p_dbg(p2p, "Received GO Negotiation Request from " MACSTR "(freq=%d)",
 		MAC2STR(sa), rx_freq);
 
 	if (p2p_parse(data, len, &msg))
-		return;
+		return NULL;
 
 	if (!msg.capability) {
 		p2p_dbg(p2p, "Mandatory Capability attribute missing from GO Negotiation Request");
@@ -888,7 +909,7 @@ void p2p_process_go_neg_req(struct p2p_data *p2p, const u8 *sa,
 			p2p->cfg->send_action_done(p2p->cfg->cb_ctx);
 			p2p_go_neg_failed(p2p, *msg.status);
 			p2p_parse_free(&msg);
-			return;
+			return NULL;
 		}
 		goto fail;
 	}
@@ -920,7 +941,7 @@ void p2p_process_go_neg_req(struct p2p_data *p2p, const u8 *sa,
 		p2p_dbg(p2p, "User has rejected this peer");
 		status = P2P_SC_FAIL_REJECTED_BY_USER;
 	} else if (dev == NULL ||
-		   (dev->wps_method == WPS_NOT_READY &&
+		   (dev->wps_method == WPS_NOT_READY && !p2p2 &&
 		    (p2p->authorized_oob_dev_pw_id == 0 ||
 		     p2p->authorized_oob_dev_pw_id !=
 		     msg.dev_password_id))) {
@@ -966,7 +987,7 @@ void p2p_process_go_neg_req(struct p2p_data *p2p, const u8 *sa,
 		    os_memcmp(sa, p2p->cfg->dev_addr, ETH_ALEN) > 0) {
 			p2p_dbg(p2p, "Do not reply since peer has higher address and GO Neg Request already sent");
 			p2p_parse_free(&msg);
-			return;
+			return NULL;
 		}
 
 		if (dev->go_neg_req_sent &&
@@ -974,7 +995,7 @@ void p2p_process_go_neg_req(struct p2p_data *p2p, const u8 *sa,
 			p2p_dbg(p2p,
 				"Do not reply since peer is waiting for us to start a new GO Negotiation and GO Neg Request already sent");
 			p2p_parse_free(&msg);
-			return;
+			return NULL;
 		}
 
 		go = p2p_go_det(p2p->go_intent, *msg.go_intent);
@@ -991,6 +1012,9 @@ void p2p_process_go_neg_req(struct p2p_data *p2p, const u8 *sa,
 			goto fail;
 		}
 
+		if (p2p2)
+			goto skip;
+
 		switch (msg.dev_password_id) {
 		case DEV_PW_REGISTRAR_SPECIFIED:
 			p2p_dbg(p2p, "PIN from peer Display");
@@ -1058,6 +1082,7 @@ void p2p_process_go_neg_req(struct p2p_data *p2p, const u8 *sa,
 			goto fail;
 		}
 
+skip:
 		if (go && p2p_go_select_channel(p2p, dev, &status) < 0)
 			goto fail;
 
@@ -1097,18 +1122,8 @@ fail:
 				     !tie_breaker);
 	p2p_parse_free(&msg);
 	if (resp == NULL)
-		return;
-	p2p_dbg(p2p, "Sending GO Negotiation Response");
-	if (rx_freq > 0)
-		freq = rx_freq;
-	else
-		freq = p2p_channel_to_freq(p2p->cfg->reg_class,
-					   p2p->cfg->channel);
-	if (freq < 0) {
-		p2p_dbg(p2p, "Unknown regulatory class/channel");
-		wpabuf_free(resp);
-		return;
-	}
+		return NULL;
+
 	if (status == P2P_SC_SUCCESS) {
 		p2p->pending_action_state = P2P_PENDING_GO_NEG_RESPONSE;
 		dev->flags |= P2P_DEV_WAIT_GO_NEG_CONFIRM;
@@ -1126,6 +1141,33 @@ fail:
 	} else
 		p2p->pending_action_state =
 			P2P_PENDING_GO_NEG_RESPONSE_FAILURE;
+	return resp;
+}
+
+
+void p2p_handle_go_neg_req(struct p2p_data *p2p, const u8 *sa, const u8 *data,
+			   size_t len, int rx_freq)
+{
+	int freq;
+	struct wpabuf *resp;
+
+	resp = p2p_process_go_neg_req(p2p, sa, data, len, rx_freq, false);
+	if (!resp)
+		return;
+
+	p2p_dbg(p2p, "Sending GO Negotiation Response");
+
+	if (rx_freq > 0)
+		freq = rx_freq;
+	else
+		freq = p2p_channel_to_freq(p2p->cfg->reg_class,
+					   p2p->cfg->channel);
+	if (freq < 0) {
+		p2p_dbg(p2p, "Unknown regulatory class/channel");
+		wpabuf_free(resp);
+		return;
+	}
+
 	if (p2p_send_action(p2p, freq, sa, p2p->cfg->dev_addr,
 			    p2p->cfg->dev_addr,
 			    wpabuf_head(resp), wpabuf_len(resp), 100) < 0) {
@@ -1142,7 +1184,7 @@ static struct wpabuf * p2p_build_go_neg_conf(struct p2p_data *p2p,
 					     const u8 *resp_chan, int go)
 {
 	struct wpabuf *buf;
-	u8 *len;
+	struct wpabuf *subelems;
 	struct p2p_channels res;
 	u8 group_capab;
 	size_t extra = 0;
@@ -1164,8 +1206,13 @@ static struct wpabuf * p2p_build_go_neg_conf(struct p2p_data *p2p,
 
 	p2p_buf_add_public_action_hdr(buf, P2P_GO_NEG_CONF, dialog_token);
 
-	len = p2p_buf_add_ie_hdr(buf);
-	p2p_buf_add_status(buf, status);
+	subelems = wpabuf_alloc(500);
+	if (!subelems) {
+		wpabuf_free(buf);
+		return NULL;
+	}
+
+	p2p_buf_add_status(subelems, status);
 	group_capab = 0;
 	if (peer->go_state == LOCAL_GO) {
 		if (peer->flags & P2P_DEV_PREFER_PERSISTENT_GROUP) {
@@ -1179,25 +1226,26 @@ static struct wpabuf * p2p_build_go_neg_conf(struct p2p_data *p2p,
 		if (p2p->cfg->p2p_intra_bss)
 			group_capab |= P2P_GROUP_CAPAB_INTRA_BSS_DIST;
 	}
-	p2p_buf_add_capability(buf, p2p->dev_capab &
+	p2p_buf_add_capability(subelems, p2p->dev_capab &
 			       ~P2P_DEV_CAPAB_CLIENT_DISCOVERABILITY,
 			       group_capab);
 	if (go || resp_chan == NULL)
-		p2p_buf_add_operating_channel(buf, p2p->cfg->country,
+		p2p_buf_add_operating_channel(subelems, p2p->cfg->country,
 					      p2p->op_reg_class,
 					      p2p->op_channel);
 	else
-		p2p_buf_add_operating_channel(buf, (const char *) resp_chan,
+		p2p_buf_add_operating_channel(subelems,
+					      (const char *) resp_chan,
 					      resp_chan[3], resp_chan[4]);
 	p2p_channels_intersect(&p2p->channels, &peer->channels, &res);
 	is_6ghz_capab = is_p2p_6ghz_capable(p2p) &&
 		p2p_is_peer_6ghz_capab(p2p, peer->info.p2p_device_addr);
-	p2p_buf_add_channel_list(buf, p2p->cfg->country, &res, is_6ghz_capab);
+	p2p_buf_add_channel_list(subelems, p2p->cfg->country, &res,
+				 is_6ghz_capab);
 	if (go) {
-		p2p_buf_add_group_id(buf, p2p->cfg->dev_addr, p2p->ssid,
+		p2p_buf_add_group_id(subelems, p2p->cfg->dev_addr, p2p->ssid,
 				     p2p->ssid_len);
 	}
-	p2p_buf_update_ie_hdr(buf, len);
 
 #ifdef CONFIG_WIFI_DISPLAY
 	if (p2p->wfd_ie_go_neg)
@@ -1207,36 +1255,40 @@ static struct wpabuf * p2p_build_go_neg_conf(struct p2p_data *p2p,
 	if (p2p->vendor_elem && p2p->vendor_elem[VENDOR_ELEM_P2P_GO_NEG_CONF])
 		wpabuf_put_buf(buf, p2p->vendor_elem[VENDOR_ELEM_P2P_GO_NEG_CONF]);
 
+	buf = wpabuf_concat(buf, p2p_encaps_ie(subelems, P2P_IE_VENDOR_TYPE));
+	wpabuf_free(subelems);
 	return buf;
 }
 
 
-void p2p_process_go_neg_resp(struct p2p_data *p2p, const u8 *sa,
-			     const u8 *data, size_t len, int rx_freq)
+struct wpabuf * p2p_process_go_neg_resp(struct p2p_data *p2p, const u8 *sa,
+					const u8 *data, size_t len,
+					int rx_freq, bool p2p2)
 {
 	struct p2p_device *dev;
 	int go = -1;
 	struct p2p_message msg;
 	u8 status = P2P_SC_SUCCESS;
 	int freq;
+	struct wpabuf *conf = NULL;
 
 	p2p_dbg(p2p, "Received GO Negotiation Response from " MACSTR
 		" (freq=%d)", MAC2STR(sa), rx_freq);
 	dev = p2p_get_device(p2p, sa);
-	if (dev == NULL || dev->wps_method == WPS_NOT_READY ||
+	if (dev == NULL || (!p2p2 && dev->wps_method == WPS_NOT_READY) ||
 	    dev != p2p->go_neg_peer) {
 		p2p_dbg(p2p, "Not ready for GO negotiation with " MACSTR,
 			MAC2STR(sa));
-		return;
+		return NULL;
 	}
 
 	if (p2p_parse(data, len, &msg))
-		return;
+		return NULL;
 
 	if (!(dev->flags & P2P_DEV_WAIT_GO_NEG_RESPONSE)) {
 		p2p_dbg(p2p, "Was not expecting GO Negotiation Response - ignore");
 		p2p_parse_free(&msg);
-		return;
+		return NULL;
 	}
 	dev->flags &= ~P2P_DEV_WAIT_GO_NEG_RESPONSE;
 	p2p_update_peer_6ghz_capab(dev, &msg);
@@ -1245,7 +1297,7 @@ void p2p_process_go_neg_resp(struct p2p_data *p2p, const u8 *sa,
 		p2p_dbg(p2p, "Unexpected Dialog Token %u (expected %u)",
 			msg.dialog_token, dev->dialog_token);
 		p2p_parse_free(&msg);
-		return;
+		return NULL;
 	}
 
 	if (!msg.status) {
@@ -1274,7 +1326,7 @@ void p2p_process_go_neg_resp(struct p2p_data *p2p, const u8 *sa,
 		}
 		p2p->cfg->send_action_done(p2p->cfg->cb_ctx);
 		p2p_parse_free(&msg);
-		return;
+		return NULL;
 	}
 
 	if (!msg.capability) {
@@ -1375,6 +1427,9 @@ void p2p_process_go_neg_resp(struct p2p_data *p2p, const u8 *sa,
 	} else
 		dev->oper_freq = 0;
 
+	if (p2p2)
+		goto skip;
+
 	switch (msg.dev_password_id) {
 	case DEV_PW_REGISTRAR_SPECIFIED:
 		p2p_dbg(p2p, "PIN from peer Display");
@@ -1430,6 +1485,7 @@ void p2p_process_go_neg_resp(struct p2p_data *p2p, const u8 *sa,
 		goto fail;
 	}
 
+skip:
 	if (go && p2p_go_select_channel(p2p, dev, &status) < 0)
 		goto fail;
 
@@ -1454,8 +1510,10 @@ fail:
 						 go);
 	p2p_parse_free(&msg);
 	if (dev->go_neg_conf == NULL)
-		return;
-	p2p_dbg(p2p, "Sending GO Negotiation Confirm");
+		return NULL;
+
+	conf = wpabuf_dup(dev->go_neg_conf);
+
 	if (status == P2P_SC_SUCCESS) {
 		p2p->pending_action_state = P2P_PENDING_GO_NEG_CONFIRM;
 		dev->go_state = go ? LOCAL_GO : REMOTE_GO;
@@ -1469,7 +1527,39 @@ fail:
 	dev->go_neg_conf_freq = freq;
 	dev->go_neg_conf_sent = 0;
 
-	if (p2p_send_action(p2p, freq, sa, p2p->cfg->dev_addr, sa,
+	if (status != P2P_SC_SUCCESS) {
+		p2p_dbg(p2p, "GO Negotiation failed");
+		dev->status = status;
+	}
+
+	return conf;
+}
+
+
+void p2p_handle_go_neg_resp(struct p2p_data *p2p, const u8 *sa, const u8 *data,
+			    size_t len, int rx_freq)
+{
+	int freq;
+	struct p2p_device *dev;
+	struct wpabuf *conf;
+
+	conf = p2p_process_go_neg_resp(p2p, sa, data, len, rx_freq, false);
+	if (!conf)
+		return;
+	wpabuf_free(conf);
+
+	dev = p2p_get_device(p2p, sa);
+	if (!dev)
+		return;
+
+	p2p_dbg(p2p, "Sending GO Negotiation Confirm");
+	if (rx_freq > 0)
+		freq = rx_freq;
+	else
+		freq = dev->listen_freq;
+
+	if (dev->go_neg_conf &&
+	    p2p_send_action(p2p, freq, sa, p2p->cfg->dev_addr, sa,
 			    wpabuf_head(dev->go_neg_conf),
 			    wpabuf_len(dev->go_neg_conf), 50) < 0) {
 		p2p_dbg(p2p, "Failed to send Action frame");
@@ -1477,15 +1567,14 @@ fail:
 		p2p->cfg->send_action_done(p2p->cfg->cb_ctx);
 	} else
 		dev->go_neg_conf_sent++;
-	if (status != P2P_SC_SUCCESS) {
-		p2p_dbg(p2p, "GO Negotiation failed");
-		p2p_go_neg_failed(p2p, status);
-	}
+
+	if (dev->status != P2P_SC_SUCCESS)
+		p2p_go_neg_failed(p2p, dev->status);
 }
 
 
-void p2p_process_go_neg_conf(struct p2p_data *p2p, const u8 *sa,
-			     const u8 *data, size_t len)
+void p2p_handle_go_neg_conf(struct p2p_data *p2p, const u8 *sa,
+			    const u8 *data, size_t len, bool p2p2)
 {
 	struct p2p_device *dev;
 	struct p2p_message msg;
@@ -1493,7 +1582,7 @@ void p2p_process_go_neg_conf(struct p2p_data *p2p, const u8 *sa,
 	p2p_dbg(p2p, "Received GO Negotiation Confirm from " MACSTR,
 		MAC2STR(sa));
 	dev = p2p_get_device(p2p, sa);
-	if (dev == NULL || dev->wps_method == WPS_NOT_READY ||
+	if (dev == NULL || (!p2p2 && dev->wps_method == WPS_NOT_READY) ||
 	    dev != p2p->go_neg_peer) {
 		p2p_dbg(p2p, "Not ready for GO negotiation with " MACSTR,
 			MAC2STR(sa));
diff --git a/src/p2p/p2p_i.h b/src/p2p/p2p_i.h
index 5239ee4e..808bb966 100644
--- a/src/p2p/p2p_i.h
+++ b/src/p2p/p2p_i.h
@@ -37,6 +37,26 @@ enum p2p_go_state {
 	REMOTE_GO
 };
 
+/**
+ * struct bootstrap_params - P2P Device bootstrap request parameters
+ */
+struct p2p_bootstrap_params {
+	/* Bootstrap method */
+	u16 bootstrap_method;
+
+	/* Status code */
+	enum p2p_status_code status;
+
+	/* Cookie for comeback */
+	u8 cookie[50];
+
+	/* Cookie length */
+	size_t cookie_len;
+
+	/* Comeback time in TUs after which receiver is requested to retry */
+	int comeback_after;
+};
+
 /**
  * struct p2p_device - P2P Device data (internal to P2P module)
  */
@@ -151,6 +171,18 @@ struct p2p_device {
 
 	int sd_pending_bcast_queries;
 	bool support_6ghz;
+
+	/* Supports P2P2 */
+	bool p2p2;
+
+	/* Requested bootstrap method */
+	u16 req_bootstrap_method;
+
+	/* Bootstrap parameters received from peer */
+	struct p2p_bootstrap_params *bootstrap_params;
+
+	/* Password for P2P2 GO negotiation */
+	char password[100];
 };
 
 struct p2p_sd_query {
@@ -161,6 +193,39 @@ struct p2p_sd_query {
 	struct wpabuf *tlvs;
 };
 
+/* P2P Device Identity Key parameters */
+struct p2p_id_key {
+	/* AKMP used for DevIK derviation */
+	int akmp;
+	/* Cipher version type */
+	int cipher_version;
+	/* Buffer to hold the DevIK */
+	u8 dik_data[DEVICE_IDENTITY_KEY_MAX_LEN];
+	/* Length of DevIK */
+	size_t dik_len;
+	/* Nonce used in DIRA attribute */
+	u8 dira_nonce[DEVICE_IDENTITY_NONCE_LEN];
+	/* Length of nonce */
+	size_t dira_nonce_len;
+	/* Tag computed for nonce using NIK */
+	u8 dira_tag[DEVICE_IDENTITY_TAG_LEN];
+	/* Length of tag in octets */
+	size_t dira_tag_len;
+};
+
+struct p2p_pairing_info {
+	/* P2P device own address */
+	u8 own_addr[ETH_ALEN];
+	/* device capability to enable pairing setup */
+	bool enable_pairing_setup;
+	/* device capability to enable pairing cache */
+	bool enable_pairing_cache;
+	/* device supported bootstrapping */
+	u16 supported_bootstrap;
+	/* P2P Device Identity Key info */
+	struct p2p_id_key dev_ik;
+};
+
 /**
  * struct p2p_data - P2P module data (internal to P2P module)
  */
@@ -565,6 +630,13 @@ struct p2p_data {
 	bool p2p_6ghz_capable;
 	bool include_6ghz;
 	bool allow_6ghz;
+
+	struct p2p_pairing_info *pairing_info;
+
+	/* Pairing initiator PMKSA cache */
+	struct rsn_pmksa_cache *initiator_pmksa;
+	/* Pairing responder PMKSA cache */
+	struct rsn_pmksa_cache *responder_pmksa;
 };
 
 /**
@@ -572,6 +644,7 @@ struct p2p_data {
  */
 struct p2p_message {
 	struct wpabuf *p2p_attributes;
+	struct wpabuf *p2p2_attributes;
 	struct wpabuf *wps_attributes;
 	struct wpabuf *wfd_subelems;
 
@@ -670,6 +743,21 @@ struct p2p_message {
 
 	const u8 *pref_freq_list;
 	size_t pref_freq_list_len;
+
+	const u8 *pcea_info;
+	size_t pcea_info_len;
+
+	const u8 *pbma_info;
+	size_t pbma_info_len;
+
+	const u8 *action_frame_wrapper;
+	size_t action_frame_wrapper_len;
+
+	const u8 *dira;
+	size_t dira_len;
+
+	const u8 *wlan_ap_info;
+	size_t wlan_ap_info_len;
 };
 
 
@@ -759,6 +847,7 @@ void p2p_buf_add_action_hdr(struct wpabuf *buf, u8 subtype, u8 dialog_token);
 void p2p_buf_add_public_action_hdr(struct wpabuf *buf, u8 subtype,
 				   u8 dialog_token);
 u8 * p2p_buf_add_ie_hdr(struct wpabuf *buf);
+u8 * p2p_buf_add_p2p2_ie_hdr(struct wpabuf *buf);
 void p2p_buf_add_status(struct wpabuf *buf, u8 status);
 void p2p_buf_add_device_info(struct wpabuf *buf, struct p2p_data *p2p,
 			     struct p2p_device *peer);
@@ -799,11 +888,16 @@ void p2p_buf_add_feature_capability(struct wpabuf *buf, u16 len,
 				    const u8 *mask);
 void p2p_buf_add_persistent_group_info(struct wpabuf *buf, const u8 *dev_addr,
 				       const u8 *ssid, size_t ssid_len);
+void p2p_buf_add_pcea(struct wpabuf *buf, struct p2p_data *p2p);
+void p2p_buf_add_pbma(struct wpabuf *buf, u16 bootstrap, const u8 *cookie,
+		      size_t cookie_len, int comeback_after);
+void p2p_buf_add_dira(struct wpabuf *buf, struct p2p_data *p2p);
 int p2p_build_wps_ie(struct p2p_data *p2p, struct wpabuf *buf, int pw_id,
 		     int all_attr);
 void p2p_buf_add_pref_channel_list(struct wpabuf *buf,
 				   const struct weighted_pcl *pref_freq_list,
 				   unsigned int size);
+struct wpabuf * p2p_encaps_ie(const struct wpabuf *subelems, u32 ie_type);
 
 /* p2p_sd.c */
 struct p2p_sd_query * p2p_pending_sd_req(struct p2p_data *p2p,
@@ -820,15 +914,23 @@ void p2p_rx_gas_comeback_resp(struct p2p_data *p2p, const u8 *sa,
 int p2p_start_sd(struct p2p_data *p2p, struct p2p_device *dev);
 
 /* p2p_go_neg.c */
+struct wpabuf * p2p_build_go_neg_req(struct p2p_data *p2p,
+				     struct p2p_device *peer);
 int p2p_peer_channels_check(struct p2p_data *p2p, struct p2p_channels *own,
 			    struct p2p_device *dev,
 			    const u8 *channel_list, size_t channel_list_len);
-void p2p_process_go_neg_req(struct p2p_data *p2p, const u8 *sa,
-			    const u8 *data, size_t len, int rx_freq);
-void p2p_process_go_neg_resp(struct p2p_data *p2p, const u8 *sa,
-			     const u8 *data, size_t len, int rx_freq);
-void p2p_process_go_neg_conf(struct p2p_data *p2p, const u8 *sa,
-			     const u8 *data, size_t len);
+void p2p_handle_go_neg_req(struct p2p_data *p2p, const u8 *sa, const u8 *data,
+			   size_t len, int rx_freq);
+void p2p_handle_go_neg_resp(struct p2p_data *p2p, const u8 *sa, const u8 *data,
+			    size_t len, int rx_freq);
+void p2p_handle_go_neg_conf(struct p2p_data *p2p, const u8 *sa, const u8 *data,
+			    size_t len, bool p2p2);
+struct wpabuf * p2p_process_go_neg_req(struct p2p_data *p2p, const u8 *sa,
+				       const u8 *data, size_t len, int rx_freq,
+				       bool p2p2);
+struct wpabuf * p2p_process_go_neg_resp(struct p2p_data *p2p, const u8 *sa,
+					const u8 *data, size_t len,
+					int rx_freq, bool p2p2);
 int p2p_connect_send(struct p2p_data *p2p, struct p2p_device *dev);
 u16 p2p_wps_method_pw_id(enum p2p_wps_method wps_method);
 void p2p_reselect_channel(struct p2p_data *p2p,
@@ -837,18 +939,25 @@ void p2p_check_pref_chan(struct p2p_data *p2p, int go,
 			 struct p2p_device *dev, struct p2p_message *msg);
 
 /* p2p_pd.c */
-void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
+void p2p_handle_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
+			      const u8 *data, size_t len, int rx_freq);
+void p2p_handle_prov_disc_resp(struct p2p_data *p2p, const u8 *sa,
 			       const u8 *data, size_t len, int rx_freq);
-void p2p_process_prov_disc_resp(struct p2p_data *p2p, const u8 *sa,
-				const u8 *data, size_t len);
 int p2p_send_prov_disc_req(struct p2p_data *p2p, struct p2p_device *dev,
 			   int join, int force_freq);
 void p2p_reset_pending_pd(struct p2p_data *p2p);
 void p2ps_prov_free(struct p2p_data *p2p);
+void p2p_process_pcea(struct p2p_data *p2p, struct p2p_message *msg,
+		      struct p2p_device *dev);
 
 /* p2p_invitation.c */
-void p2p_process_invitation_req(struct p2p_data *p2p, const u8 *sa,
-				const u8 *data, size_t len, int rx_freq);
+void p2p_handle_invitation_req(struct p2p_data *p2p, const u8 *sa,
+			       const u8 *data, size_t len, int rx_freq);
+void p2p_handle_invitation_resp(struct p2p_data *p2p, const u8 *sa,
+				const u8 *data, size_t len);
+struct wpabuf * p2p_process_invitation_req(struct p2p_data *p2p, const u8 *sa,
+					   const u8 *data, size_t len,
+					   int rx_freq);
 void p2p_process_invitation_resp(struct p2p_data *p2p, const u8 *sa,
 				 const u8 *data, size_t len);
 int p2p_invite_send(struct p2p_data *p2p, struct p2p_device *dev,
diff --git a/src/p2p/p2p_invitation.c b/src/p2p/p2p_invitation.c
index 70a7f6fa..3fd66c23 100644
--- a/src/p2p/p2p_invitation.c
+++ b/src/p2p/p2p_invitation.c
@@ -181,14 +181,14 @@ static struct wpabuf * p2p_build_invitation_resp(struct p2p_data *p2p,
 }
 
 
-void p2p_process_invitation_req(struct p2p_data *p2p, const u8 *sa,
-				const u8 *data, size_t len, int rx_freq)
+struct wpabuf * p2p_process_invitation_req(struct p2p_data *p2p, const u8 *sa,
+					   const u8 *data, size_t len,
+					   int rx_freq)
 {
 	struct p2p_device *dev;
 	struct p2p_message msg;
 	struct wpabuf *resp = NULL;
 	u8 status = P2P_SC_FAIL_INFO_CURRENTLY_UNAVAILABLE;
-	int freq;
 	int go = 0;
 	u8 group_bssid[ETH_ALEN], *bssid;
 	int op_freq = 0;
@@ -202,7 +202,7 @@ void p2p_process_invitation_req(struct p2p_data *p2p, const u8 *sa,
 		MAC2STR(sa), rx_freq);
 
 	if (p2p_parse(data, len, &msg))
-		return;
+		return NULL;
 
 	dev = p2p_get_device(p2p, sa);
 	if (dev == NULL || (dev->flags & P2P_DEV_PROBE_REQ_ONLY)) {
@@ -388,19 +388,6 @@ fail:
 	resp = p2p_build_invitation_resp(p2p, dev, msg.dialog_token, status,
 					 bssid, reg_class, channel, channels);
 
-	if (resp == NULL)
-		goto out;
-
-	if (rx_freq > 0)
-		freq = rx_freq;
-	else
-		freq = p2p_channel_to_freq(p2p->cfg->reg_class,
-					   p2p->cfg->channel);
-	if (freq < 0) {
-		p2p_dbg(p2p, "Unknown regulatory class/channel");
-		goto out;
-	}
-
 	/*
 	 * Store copy of invitation data to be used when processing TX status
 	 * callback for the Acton frame.
@@ -424,6 +411,28 @@ fail:
 	}
 	p2p->inv_status = status;
 	p2p->inv_op_freq = op_freq;
+	p2p_parse_free(&msg);
+	return resp;
+}
+
+
+void p2p_handle_invitation_req(struct p2p_data *p2p, const u8 *sa,
+			       const u8 *data, size_t len, int rx_freq)
+{
+	int freq;
+	struct wpabuf *resp;
+
+	resp = p2p_process_invitation_req(p2p, sa, data, len, rx_freq);
+	if (!resp)
+		return;
+
+	if (rx_freq > 0)
+		freq = rx_freq;
+	else
+		freq = p2p_channel_to_freq(p2p->cfg->reg_class,
+					   p2p->cfg->channel);
+	if (freq < 0)
+		p2p_dbg(p2p, "Unknown regulatory class/channel");
 
 	p2p->pending_action_state = P2P_PENDING_INVITATION_RESPONSE;
 	if (p2p_send_action(p2p, freq, sa, p2p->cfg->dev_addr,
@@ -432,9 +441,7 @@ fail:
 		p2p_dbg(p2p, "Failed to send Action frame");
 	}
 
-out:
 	wpabuf_free(resp);
-	p2p_parse_free(&msg);
 }
 
 
diff --git a/src/p2p/p2p_parse.c b/src/p2p/p2p_parse.c
index 07d6ca02..cd3332d6 100644
--- a/src/p2p/p2p_parse.c
+++ b/src/p2p/p2p_parse.c
@@ -417,6 +417,60 @@ static int p2p_parse_attribute(u8 id, const u8 *data, u16 len,
 					msg->persistent_ssid_len));
 		break;
 	}
+	case P2P_ATTR_CAPABILITY_EXTENSION:
+		if (len < 2) {
+			wpa_printf(MSG_DEBUG, "P2P: Too short PCEA (length %d)",
+				   len);
+			return -1;
+		}
+		msg->pcea_info = data;
+		msg->pcea_info_len = len;
+		wpa_printf(MSG_DEBUG, "P2P: * PCEA (length=%u)", len);
+		break;
+	case P2P_ATTR_PAIRING_AND_BOOTSTRAPPING:
+		if (len < 1) {
+			wpa_printf(MSG_DEBUG, "P2P: Too short PBMA (length %d)",
+				   len);
+			return -1;
+		}
+		msg->pbma_info = data;
+		msg->pbma_info_len = len;
+		wpa_printf(MSG_DEBUG, "P2P: * PBMA (length=%u)", len);
+		break;
+	case P2P_ATTR_ACTION_FRAME_WRAPPER:
+		if (len < 2) {
+			wpa_printf(MSG_DEBUG,
+				   "P2P: Too short Action Frame Wrapper attribute (length %d)",
+				   len);
+			return -1;
+		}
+		msg->action_frame_wrapper = data;
+		msg->action_frame_wrapper_len = len;
+		wpa_printf(MSG_DEBUG, "P2P: * Action frame wrapper (length=%u)",
+			   len);
+		break;
+	case P2P_ATTR_DEVICE_IDENTITY_RESOLUTION:
+		if (len < 1) {
+			wpa_printf(MSG_DEBUG, "P2P: Too short DIRA (length %d)",
+				   len);
+			return -1;
+		}
+		msg->dira = data;
+		msg->dira_len = len;
+		wpa_printf(MSG_DEBUG, "P2P: * DIRA (length=%u)", len);
+		break;
+	case P2P_ATTR_WLAN_AP_INFORMATION:
+		/* One or more AP Info fields (each being 12 octets) is required
+		 * to be included. */
+		if (len < 12) {
+			wpa_printf(MSG_DEBUG,
+				   "P2P: Too short WLAN AP info (length %d)",
+				   len);
+			return -1;
+		}
+		msg->wlan_ap_info = data;
+		msg->wlan_ap_info_len = len;
+		break;
 	default:
 		wpa_printf(MSG_DEBUG, "P2P: Skipped unknown attribute %d "
 			   "(length %d)", id, len);
@@ -573,6 +627,18 @@ int p2p_parse_ies(const u8 *data, size_t len, struct p2p_message *msg)
 		return -1;
 	}
 
+	msg->p2p2_attributes = ieee802_11_vendor_ie_concat(data, len,
+							   P2P2_IE_VENDOR_TYPE);
+	if (msg->p2p2_attributes &&
+	    p2p_parse_p2p_ie(msg->p2p2_attributes, msg)) {
+		wpa_printf(MSG_DEBUG, "P2P: Failed to parse P2P2 IE data");
+		if (msg->p2p2_attributes)
+			wpa_hexdump_buf(MSG_MSGDUMP, "P2P: P2P2 IE data",
+					msg->p2p2_attributes);
+		p2p_parse_free(msg);
+		return -1;
+	}
+
 #ifdef CONFIG_WIFI_DISPLAY
 	if (elems.wfd) {
 		msg->wfd_subelems = ieee802_11_vendor_ie_concat(
@@ -647,6 +713,8 @@ void p2p_parse_free(struct p2p_message *msg)
 {
 	wpabuf_free(msg->p2p_attributes);
 	msg->p2p_attributes = NULL;
+	wpabuf_free(msg->p2p2_attributes);
+	msg->p2p2_attributes = NULL;
 	wpabuf_free(msg->wps_attributes);
 	msg->wps_attributes = NULL;
 #ifdef CONFIG_WIFI_DISPLAY
diff --git a/src/p2p/p2p_pd.c b/src/p2p/p2p_pd.c
index 542521ed..fb203131 100644
--- a/src/p2p/p2p_pd.c
+++ b/src/p2p/p2p_pd.c
@@ -181,6 +181,64 @@ static void p2ps_add_pd_req_attrs(struct p2p_data *p2p, struct p2p_device *dev,
 }
 
 
+static struct wpabuf * p2p_build_prov_disc_bootstrap_req(struct p2p_data *p2p,
+							 struct p2p_device *dev)
+{
+	struct wpabuf *buf;
+	u8 *len;
+	size_t cookie_len = 0;
+	const u8 *cookie = NULL;
+	u8 dialog_token = dev->dialog_token;
+	u8 group_capab;
+
+	buf = wpabuf_alloc(1000);
+	if (!buf)
+		return NULL;
+
+	p2p_dbg(p2p, "P2P2: Building bootstrapping PD Request");
+	p2p_buf_add_public_action_hdr(buf, P2P_PROV_DISC_REQ, dialog_token);
+
+	len = p2p_buf_add_ie_hdr(buf);
+
+	group_capab = 0;
+
+	if (p2p->num_groups) {
+		group_capab |= P2P_GROUP_CAPAB_GROUP_OWNER;
+		if ((p2p->dev_capab & P2P_DEV_CAPAB_CONCURRENT_OPER) &&
+		    (p2p->dev_capab & P2P_DEV_CAPAB_INFRA_MANAGED) &&
+		    p2p->cross_connect)
+			group_capab |= P2P_GROUP_CAPAB_CROSS_CONN;
+	}
+	if (p2p->cfg->p2p_intra_bss)
+		group_capab |= P2P_GROUP_CAPAB_INTRA_BSS_DIST;
+
+	p2p_buf_add_capability(buf, p2p->dev_capab &
+			       ~P2P_DEV_CAPAB_CLIENT_DISCOVERABILITY,
+			       group_capab);
+	p2p_buf_add_device_info(buf, p2p, NULL);
+
+	if (dev->bootstrap_params) {
+		cookie = dev->bootstrap_params->cookie;
+		cookie_len = dev->bootstrap_params->cookie_len;
+
+		if (dev->bootstrap_params->status == P2P_SC_COMEBACK)
+			p2p_buf_add_status(buf, dev->bootstrap_params->status);
+	}
+
+	p2p_buf_update_ie_hdr(buf, len);
+
+	len = p2p_buf_add_p2p2_ie_hdr(buf);
+
+	p2p_buf_add_pcea(buf, p2p);
+	p2p_buf_add_pbma(buf, dev->req_bootstrap_method, cookie, cookie_len, 0);
+
+	p2p_buf_update_ie_hdr(buf, len);
+
+	wpa_printf(MSG_DEBUG, "P2P2: Added PCEA and PBMA in PD Request");
+	return buf;
+}
+
+
 static struct wpabuf * p2p_build_prov_disc_req(struct p2p_data *p2p,
 					       struct p2p_device *dev,
 					       int join)
@@ -249,6 +307,42 @@ static struct wpabuf * p2p_build_prov_disc_req(struct p2p_data *p2p,
 }
 
 
+static struct wpabuf *
+p2p_build_prov_disc_bootstrap_resp(struct p2p_data *p2p, struct p2p_device *dev,
+				   u8 dialog_token, enum p2p_status_code status)
+{
+	struct wpabuf *buf;
+	u8 *cookie = NULL;
+	size_t cookie_len = 0;
+	int comeback_after = 0;
+	u8 *len;
+
+	buf = wpabuf_alloc(1000);
+	if (!buf)
+		return NULL;
+
+	p2p_dbg(p2p, "P2P2: Building boostrapping PD Response");
+	if (status == P2P_SC_COMEBACK && dev->bootstrap_params) {
+		cookie = dev->bootstrap_params->cookie;
+		cookie_len = dev->bootstrap_params->cookie_len;
+		comeback_after = dev->bootstrap_params->comeback_after;
+	}
+
+	p2p_buf_add_public_action_hdr(buf, P2P_PROV_DISC_RESP, dialog_token);
+
+	len = p2p_buf_add_p2p2_ie_hdr(buf);
+
+	p2p_buf_add_status(buf, status);
+	p2p_buf_add_pcea(buf, p2p);
+	p2p_buf_add_pbma(buf, dev->req_bootstrap_method, cookie, cookie_len,
+			 comeback_after);
+
+	p2p_buf_update_ie_hdr(buf, len);
+
+	return buf;
+}
+
+
 static struct wpabuf * p2p_build_prov_disc_resp(struct p2p_data *p2p,
 						struct p2p_device *dev,
 						u8 dialog_token,
@@ -563,10 +657,232 @@ do { \
 }
 
 
-void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
-			       const u8 *data, size_t len, int rx_freq)
+void p2p_process_pcea(struct p2p_data *p2p, struct p2p_message *msg,
+		      struct p2p_device *dev)
+{
+	const u8 *pos, *end;
+	u8 cap_info_len;
+
+	if (!p2p || !dev || !msg || !msg->pcea_info)
+		return;
+
+	pos = msg->pcea_info;
+	end = pos + msg->pcea_info_len;
+	dev->info.pcea_cap_info = WPA_GET_LE16(pos);
+	cap_info_len = dev->info.pcea_cap_info & P2P_PCEA_LEN_MASK;
+
+	/* Field length is (n-1), n in octets */
+	if (end - pos < cap_info_len + 1)
+		return;
+	pos += cap_info_len + 1;
+
+	if (dev->info.pcea_cap_info & P2P_PCEA_6GHZ)
+		dev->support_6ghz = true;
+
+	if (dev->info.pcea_cap_info & P2P_PCEA_REG_INFO) {
+		if (end - pos < 1) {
+			p2p_dbg(p2p, "Truncated PCEA");
+			return;
+		}
+		dev->info.reg_info = *pos++;
+	}
+
+	if (dev->info.pcea_cap_info & P2P_PCEA_PASN_TYPE) {
+		if (end - pos < 1) {
+			p2p_dbg(p2p, "Truncated PCEA");
+			return;
+		}
+		dev->info.pairing_config.pasn_type = *pos++;
+	}
+
+	if (dev->info.pcea_cap_info & P2P_PCEA_PAIRING_CAPABLE)
+		dev->info.pairing_config.pairing_capable = true;
+
+	if (dev->info.pcea_cap_info & P2P_PCEA_PAIRING_SETUP_ENABLED)
+		dev->info.pairing_config.enable_pairing_setup = true;
+
+	if (dev->info.pcea_cap_info & P2P_PCEA_PMK_CACHING) {
+		dev->info.pairing_config.enable_pairing_cache = true;
+		dev->info.pairing_config.enable_pairing_verification = true;
+	}
+}
+
+
+static void p2p_process_prov_disc_bootstrap_req(struct p2p_data *p2p,
+						struct p2p_message *msg,
+						const u8 *sa, const u8 *data,
+						size_t len, int rx_freq)
+{
+	struct p2p_device *dev;
+	int freq;
+	struct wpabuf *resp;
+	u16 bootstrap;
+	size_t cookie_len = 0;
+	const u8 *pos, *cookie;
+	enum p2p_status_code status = P2P_SC_FAIL_INVALID_PARAMS;
+
+	p2p_dbg(p2p, "Received Provision Discovery Request from " MACSTR
+		" with bootstrapping Attribute (freq=%d)",
+		MAC2STR(sa), rx_freq);
+
+	dev = p2p_get_device(p2p, sa);
+	if (!dev) {
+		p2p_dbg(p2p, "Provision Discovery Request from unknown peer "
+			MACSTR, MAC2STR(sa));
+
+		if (p2p_add_device(p2p, sa, rx_freq, NULL, 0, data, len, 0)) {
+			p2p_dbg(p2p,
+				"Provision Discovery Request add device failed "
+				MACSTR, MAC2STR(sa));
+			return;
+		}
+
+		dev = p2p_get_device(p2p, sa);
+		if (!dev) {
+			p2p_dbg(p2p,
+				"Provision Discovery device not found "
+				MACSTR, MAC2STR(sa));
+			return;
+		}
+	}
+	dev->p2p2 = true;
+
+	if (p2p->send_action_in_progress) {
+		p2p_dbg(p2p, "Dropping retry frame as response TX pending");
+		return;
+	}
+
+	p2p_update_peer_6ghz_capab(dev, msg);
+
+	if (msg->pcea_info && msg->pcea_info_len >= 2)
+		p2p_process_pcea(p2p, msg, dev);
+
+	pos = msg->pbma_info;
+
+	if (msg->pbma_info_len > 2 && msg->status &&
+	    *msg->status == P2P_SC_COMEBACK) {
+		/* PBMA comeback request */
+		cookie_len = *pos++;
+		if (msg->pbma_info_len < 1 + cookie_len) {
+			p2p_dbg(p2p, "Truncated PBMA");
+			return;
+		}
+		cookie = pos;
+
+		if (!dev->bootstrap_params ||
+		    dev->bootstrap_params->cookie_len != cookie_len ||
+		    os_memcmp(cookie, dev->bootstrap_params->cookie,
+			      cookie_len) != 0) {
+			status = P2P_SC_FAIL_REJECTED_BY_USER;
+			goto out;
+		}
+
+		bootstrap = dev->bootstrap_params->bootstrap_method;
+
+		if (!dev->req_bootstrap_method) {
+			status = P2P_SC_COMEBACK;
+			if (p2p->cfg->bootstrap_req_rx)
+				p2p->cfg->bootstrap_req_rx(p2p->cfg->cb_ctx,
+							   sa, bootstrap);
+			goto out;
+		}
+	} else {
+		/* PBMA request */
+		bootstrap = WPA_GET_LE16(pos);
+
+		os_free(dev->bootstrap_params);
+		dev->bootstrap_params = NULL;
+
+		if (!dev->req_bootstrap_method) {
+			dev->bootstrap_params =
+				os_zalloc(sizeof(struct p2p_bootstrap_params));
+			if (!dev->bootstrap_params)
+				return;
+			dev->bootstrap_params->bootstrap_method = bootstrap;
+			dev->bootstrap_params->cookie_len = 4;
+			if (os_get_random(dev->bootstrap_params->cookie,
+					  dev->bootstrap_params->cookie_len) <
+			    0) {
+				os_free(dev->bootstrap_params);
+				dev->bootstrap_params = NULL;
+				return;
+			}
+			dev->bootstrap_params->comeback_after =
+				p2p->cfg->comeback_after;
+			status = P2P_SC_COMEBACK;
+			if (p2p->cfg->bootstrap_req_rx)
+				p2p->cfg->bootstrap_req_rx(p2p->cfg->cb_ctx,
+							   sa, bootstrap);
+			goto out;
+		}
+	}
+
+	if (bootstrap == P2P_PBMA_PIN_CODE_DISPLAY &&
+	    dev->req_bootstrap_method == P2P_PBMA_PIN_CODE_KEYPAD)
+		status = P2P_SC_SUCCESS;
+	else if (bootstrap == P2P_PBMA_PIN_CODE_KEYPAD &&
+		 dev->req_bootstrap_method == P2P_PBMA_PIN_CODE_DISPLAY)
+		status = P2P_SC_SUCCESS;
+	else if (bootstrap == P2P_PBMA_PASSPHRASE_DISPLAY &&
+		 dev->req_bootstrap_method == P2P_PBMA_PASSPHRASE_KEYPAD)
+		status = P2P_SC_SUCCESS;
+	else if (bootstrap == P2P_PBMA_PASSPHRASE_KEYPAD &&
+		 dev->req_bootstrap_method == P2P_PBMA_PASSPHRASE_DISPLAY)
+		status = P2P_SC_SUCCESS;
+	else if (bootstrap == P2P_PBMA_NFC_TAG &&
+		 dev->req_bootstrap_method == P2P_PBMA_NFC_READER)
+		status = P2P_SC_SUCCESS;
+	else if (bootstrap == P2P_PBMA_NFC_READER &&
+		 dev->req_bootstrap_method == P2P_PBMA_NFC_TAG)
+		status = P2P_SC_SUCCESS;
+	else if (bootstrap == P2P_PBMA_QR_DISPLAY &&
+		 dev->req_bootstrap_method == P2P_PBMA_QR_SCAN)
+		status = P2P_SC_SUCCESS;
+	else if (bootstrap == P2P_PBMA_QR_SCAN &&
+		 dev->req_bootstrap_method == P2P_PBMA_QR_DISPLAY)
+		status = P2P_SC_SUCCESS;
+	else if (bootstrap == P2P_PBMA_OPPORTUNISTIC &&
+		 dev->req_bootstrap_method == P2P_PBMA_OPPORTUNISTIC)
+		status = P2P_SC_SUCCESS;
+	else
+		status = P2P_SC_FAIL_INVALID_PARAMS;
+
+	wpa_printf(MSG_ERROR, "Bootstrap received %d", bootstrap);
+
+out:
+	/* Send PD Bootstrapping Response for the PD Request */
+	resp = p2p_build_prov_disc_bootstrap_resp(p2p, dev, msg->dialog_token,
+						  status);
+	if (!resp)
+		return;
+
+	p2p_dbg(p2p, "Sending Provision Discovery Bootstrap Response");
+	if (rx_freq > 0)
+		freq = rx_freq;
+	else
+		freq = p2p_channel_to_freq(p2p->cfg->reg_class,
+					   p2p->cfg->channel);
+	if (freq < 0) {
+		p2p_dbg(p2p, "Unknown operating class/channel");
+		wpabuf_free(resp);
+		return;
+	}
+	p2p->pending_action_state = P2P_PENDING_PD_RESPONSE;
+	if (p2p_send_action(p2p, freq, sa, p2p->cfg->dev_addr,
+			    p2p->cfg->dev_addr, wpabuf_head(resp),
+			    wpabuf_len(resp), 50) < 0)
+		p2p_dbg(p2p, "Failed to send Action frame");
+	else
+		p2p->send_action_in_progress = 1;
+
+	wpabuf_free(resp);
+}
+
+
+static void p2p_process_prov_disc_req(struct p2p_data *p2p,
+				      struct p2p_message *msg, const u8 *sa,
+				      const u8 *data, size_t len, int rx_freq)
 {
-	struct p2p_message msg;
 	struct p2p_device *dev;
 	int freq;
 	enum p2p_status_code reject = P2P_SC_FAIL_INCOMPATIBLE_PARAMS;
@@ -587,21 +903,17 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 	u8 remote_conncap;
 	u16 method;
 
-	if (p2p_parse(data, len, &msg))
-		return;
-
 	p2p_dbg(p2p, "Received Provision Discovery Request from " MACSTR
 		" with config methods 0x%x (freq=%d)",
-		MAC2STR(sa), msg.wps_config_methods, rx_freq);
-	group_mac = msg.intended_addr;
+		MAC2STR(sa), msg->wps_config_methods, rx_freq);
+	group_mac = msg->intended_addr;
 
 	dev = p2p_get_device(p2p, sa);
 	if (dev == NULL || (dev->flags & P2P_DEV_PROBE_REQ_ONLY)) {
 		p2p_dbg(p2p, "Provision Discovery Request from unknown peer "
 			MACSTR, MAC2STR(sa));
 
-		if (p2p_add_device(p2p, sa, rx_freq, NULL, 0, data + 1, len - 1,
-				   0)) {
+		if (p2p_add_device(p2p, sa, rx_freq, NULL, 0, data, len, 0)) {
 			p2p_dbg(p2p, "Provision Discovery Request add device failed "
 				MACSTR, MAC2STR(sa));
 			goto out;
@@ -614,29 +926,29 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 				MACSTR, MAC2STR(sa));
 			goto out;
 		}
-	} else if (msg.wfd_subelems) {
+	} else if (msg->wfd_subelems) {
 		wpabuf_free(dev->info.wfd_subelems);
-		dev->info.wfd_subelems = wpabuf_dup(msg.wfd_subelems);
+		dev->info.wfd_subelems = wpabuf_dup(msg->wfd_subelems);
 	}
 
-	p2p_update_peer_6ghz_capab(dev, &msg);
+	p2p_update_peer_6ghz_capab(dev, msg);
 
-	if (!msg.adv_id) {
+	if (!msg->adv_id) {
 		allowed_config_methods |= WPS_CONFIG_PUSHBUTTON;
-		if (!(msg.wps_config_methods & allowed_config_methods)) {
+		if (!(msg->wps_config_methods & allowed_config_methods)) {
 			p2p_dbg(p2p,
 				"Unsupported Config Methods in Provision Discovery Request");
 			goto out;
 		}
 
 		/* Legacy (non-P2PS) - Unknown groups allowed for P2PS */
-		if (msg.group_id) {
+		if (msg->group_id) {
 			size_t i;
 
 			for (i = 0; i < p2p->num_groups; i++) {
 				if (p2p_group_is_group_id_match(
 					    p2p->groups[i],
-					    msg.group_id, msg.group_id_len))
+					    msg->group_id, msg->group_id_len))
 					break;
 			}
 			if (i == p2p->num_groups) {
@@ -652,29 +964,29 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 		 * Set adv_id here, so in case of an error, a P2PS PD Response
 		 * will be sent.
 		 */
-		adv_id = WPA_GET_LE32(msg.adv_id);
-		if (p2ps_validate_pd_req(p2p, &msg, sa) < 0) {
+		adv_id = WPA_GET_LE32(msg->adv_id);
+		if (p2ps_validate_pd_req(p2p, msg, sa) < 0) {
 			reject = P2P_SC_FAIL_INVALID_PARAMS;
 			goto out;
 		}
 
-		req_fcap = (struct p2ps_feature_capab *) msg.feature_cap;
+		req_fcap = (struct p2ps_feature_capab *) msg->feature_cap;
 
-		os_memcpy(session_mac, msg.session_mac, ETH_ALEN);
-		os_memcpy(adv_mac, msg.adv_mac, ETH_ALEN);
+		os_memcpy(session_mac, msg->session_mac, ETH_ALEN);
+		os_memcpy(adv_mac, msg->adv_mac, ETH_ALEN);
 
-		session_id = WPA_GET_LE32(msg.session_id);
+		session_id = WPA_GET_LE32(msg->session_id);
 
-		if (msg.conn_cap)
-			conncap = *msg.conn_cap;
+		if (msg->conn_cap)
+			conncap = *msg->conn_cap;
 
 		/*
 		 * We need to verify a P2PS config methog in an initial PD
 		 * request or in a follow-on PD request with the status
 		 * SUCCESS_DEFERRED.
 		 */
-		if ((!msg.status || *msg.status == P2P_SC_SUCCESS_DEFERRED) &&
-		    !(msg.wps_config_methods & allowed_config_methods)) {
+		if ((!msg->status || *msg->status == P2P_SC_SUCCESS_DEFERRED) &&
+		    !(msg->wps_config_methods & allowed_config_methods)) {
 			p2p_dbg(p2p,
 				"Unsupported Config Methods in Provision Discovery Request");
 			goto out;
@@ -690,18 +1002,18 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 			P2P_DEV_PD_PEER_KEYPAD |
 			P2P_DEV_PD_PEER_P2PS);
 
-	if (msg.wps_config_methods & WPS_CONFIG_DISPLAY) {
+	if (msg->wps_config_methods & WPS_CONFIG_DISPLAY) {
 		p2p_dbg(p2p, "Peer " MACSTR
 			" requested us to show a PIN on display", MAC2STR(sa));
 		dev->flags |= P2P_DEV_PD_PEER_KEYPAD;
 		passwd_id = DEV_PW_USER_SPECIFIED;
-	} else if (msg.wps_config_methods & WPS_CONFIG_KEYPAD) {
+	} else if (msg->wps_config_methods & WPS_CONFIG_KEYPAD) {
 		p2p_dbg(p2p, "Peer " MACSTR
 			" requested us to write its PIN using keypad",
 			MAC2STR(sa));
 		dev->flags |= P2P_DEV_PD_PEER_DISPLAY;
 		passwd_id = DEV_PW_REGISTRAR_SPECIFIED;
-	} else if (msg.wps_config_methods & WPS_CONFIG_P2PS) {
+	} else if (msg->wps_config_methods & WPS_CONFIG_P2PS) {
 		p2p_dbg(p2p, "Peer " MACSTR " requesting P2PS PIN",
 			MAC2STR(sa));
 		dev->flags |= P2P_DEV_PD_PEER_P2PS;
@@ -712,8 +1024,8 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 	if (p2p->cfg->remove_stale_groups) {
 		p2p->cfg->remove_stale_groups(
 			p2p->cfg->cb_ctx, dev->info.p2p_device_addr,
-			msg.persistent_dev,
-			msg.persistent_ssid, msg.persistent_ssid_len);
+			msg->persistent_dev,
+			msg->persistent_ssid, msg->persistent_ssid_len);
 	}
 
 	reject = P2P_SC_SUCCESS;
@@ -722,15 +1034,15 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 	 * End of a legacy P2P PD Request processing, from this point continue
 	 * with P2PS one.
 	 */
-	if (!msg.adv_id)
+	if (!msg->adv_id)
 		goto out;
 
 	remote_conncap = conncap;
 
-	if (!msg.status) {
+	if (!msg->status) {
 		unsigned int forced_freq, pref_freq;
 
-		if (!ether_addr_equal(p2p->cfg->dev_addr, msg.adv_mac)) {
+		if (!ether_addr_equal(p2p->cfg->dev_addr, msg->adv_mac)) {
 			p2p_dbg(p2p,
 				"P2PS PD adv mac does not match the local one");
 			reject = P2P_SC_FAIL_INCOMPATIBLE_PARAMS;
@@ -767,12 +1079,12 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 				"Incompatible P2PS feature capability CPT bitmask");
 			reject = P2P_SC_FAIL_INCOMPATIBLE_PARAMS;
 		} else if (p2ps_adv->config_methods &&
-			   !(msg.wps_config_methods &
+			   !(msg->wps_config_methods &
 			     p2ps_adv->config_methods)) {
 			p2p_dbg(p2p,
 				"Unsupported config methods in Provision Discovery Request (own=0x%x peer=0x%x)",
 				p2ps_adv->config_methods,
-				msg.wps_config_methods);
+				msg->wps_config_methods);
 			reject = P2P_SC_FAIL_INCOMPATIBLE_PARAMS;
 		} else if (!p2ps_adv->state) {
 			p2p_dbg(p2p, "P2PS state unavailable");
@@ -782,24 +1094,24 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 			reject = P2P_SC_FAIL_INCOMPATIBLE_PARAMS;
 		}
 
-		if (msg.wps_config_methods & WPS_CONFIG_KEYPAD) {
+		if (msg->wps_config_methods & WPS_CONFIG_KEYPAD) {
 			p2p_dbg(p2p, "Keypad - always defer");
 			auto_accept = 0;
 		}
 
 		if ((remote_conncap & (P2PS_SETUP_NEW | P2PS_SETUP_CLIENT) ||
-		     msg.persistent_dev) && conncap != P2PS_SETUP_NEW &&
-		    msg.channel_list && msg.channel_list_len &&
+		     msg->persistent_dev) && conncap != P2PS_SETUP_NEW &&
+		    msg->channel_list && msg->channel_list_len &&
 		    p2p_peer_channels_check(p2p, &p2p->channels, dev,
-					    msg.channel_list,
-					    msg.channel_list_len) < 0) {
+					    msg->channel_list,
+					    msg->channel_list_len) < 0) {
 			p2p_dbg(p2p,
 				"No common channels - force deferred flow");
 			auto_accept = 0;
 		}
 
 		if (((remote_conncap & P2PS_SETUP_GROUP_OWNER) ||
-		     msg.persistent_dev) && msg.operating_channel) {
+		     msg->persistent_dev) && msg->operating_channel) {
 			struct p2p_channels intersect;
 
 			/*
@@ -810,15 +1122,15 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 			 */
 			if (dev->channels.reg_classes == 0 ||
 			    !p2p_channels_includes(&dev->channels,
-						   msg.operating_channel[3],
-						   msg.operating_channel[4])) {
+						   msg->operating_channel[3],
+						   msg->operating_channel[4])) {
 				struct p2p_channels *ch = &dev->channels;
 
 				os_memset(ch, 0, sizeof(*ch));
 				ch->reg_class[0].reg_class =
-					msg.operating_channel[3];
+					msg->operating_channel[3];
 				ch->reg_class[0].channel[0] =
-					msg.operating_channel[4];
+					msg->operating_channel[4];
 				ch->reg_class[0].channels = 1;
 				ch->reg_classes = 1;
 			}
@@ -837,7 +1149,7 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 			struct p2ps_provision *tmp;
 
 			if (p2ps_setup_p2ps_prov(p2p, adv_id, session_id,
-						 msg.wps_config_methods,
+						 msg->wps_config_methods,
 						 session_mac, adv_mac) < 0) {
 				reject = P2P_SC_FAIL_UNABLE_TO_ACCOMMODATE;
 				goto out;
@@ -859,7 +1171,7 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 		}
 	}
 
-	if (!msg.status && !auto_accept &&
+	if (!msg->status && !auto_accept &&
 	    (!p2p->p2ps_prov || p2p->p2ps_prov->adv_id != adv_id)) {
 		struct p2ps_provision *tmp;
 
@@ -869,7 +1181,7 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 		}
 
 		if (p2ps_setup_p2ps_prov(p2p, adv_id, session_id,
-					 msg.wps_config_methods,
+					 msg->wps_config_methods,
 					 session_mac, adv_mac) < 0) {
 			reject = P2P_SC_FAIL_UNABLE_TO_ACCOMMODATE;
 			goto out;
@@ -880,26 +1192,26 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 	}
 
 	/* Not a P2PS Follow-on PD */
-	if (!msg.status)
+	if (!msg->status)
 		goto out;
 
-	if (*msg.status && *msg.status != P2P_SC_SUCCESS_DEFERRED) {
-		reject = *msg.status;
+	if (*msg->status && *msg->status != P2P_SC_SUCCESS_DEFERRED) {
+		reject = *msg->status;
 		goto out;
 	}
 
-	if (*msg.status != P2P_SC_SUCCESS_DEFERRED || !p2p->p2ps_prov)
+	if (*msg->status != P2P_SC_SUCCESS_DEFERRED || !p2p->p2ps_prov)
 		goto out;
 
 	if (p2p->p2ps_prov->adv_id != adv_id ||
-	    !ether_addr_equal(p2p->p2ps_prov->adv_mac, msg.adv_mac)) {
+	    !ether_addr_equal(p2p->p2ps_prov->adv_mac, msg->adv_mac)) {
 		p2p_dbg(p2p,
 			"P2PS Follow-on PD with mismatch Advertisement ID/MAC");
 		goto out;
 	}
 
 	if (p2p->p2ps_prov->session_id != session_id ||
-	    !ether_addr_equal(p2p->p2ps_prov->session_mac, msg.session_mac)) {
+	    !ether_addr_equal(p2p->p2ps_prov->session_mac, msg->session_mac)) {
 		p2p_dbg(p2p, "P2PS Follow-on PD with mismatch Session ID/MAC");
 		goto out;
 	}
@@ -930,7 +1242,7 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 	else if (method & WPS_CONFIG_KEYPAD)
 		method = WPS_CONFIG_DISPLAY;
 
-	if (!conncap || !(msg.wps_config_methods & method)) {
+	if (!conncap || !(msg->wps_config_methods & method)) {
 		/*
 		 * Reject this "Deferred Accept*
 		 * if incompatible conncap or method
@@ -941,11 +1253,11 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 			"Incompatible P2PS feature capability CPT bitmask");
 		reject = P2P_SC_FAIL_INCOMPATIBLE_PARAMS;
 	} else if ((remote_conncap & (P2PS_SETUP_NEW | P2PS_SETUP_CLIENT) ||
-		    msg.persistent_dev) && conncap != P2PS_SETUP_NEW &&
-		   msg.channel_list && msg.channel_list_len &&
+		    msg->persistent_dev) && conncap != P2PS_SETUP_NEW &&
+		   msg->channel_list && msg->channel_list_len &&
 		   p2p_peer_channels_check(p2p, &p2p->channels, dev,
-					   msg.channel_list,
-					   msg.channel_list_len) < 0) {
+					   msg->channel_list,
+					   msg->channel_list_len) < 0) {
 		p2p_dbg(p2p,
 			"No common channels in Follow-On Provision Discovery Request");
 		reject = P2P_SC_FAIL_NO_COMMON_CHANNELS;
@@ -957,10 +1269,10 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 	if (reject == P2P_SC_SUCCESS || reject == P2P_SC_SUCCESS_DEFERRED) {
 		u8 tmp;
 
-		if (msg.operating_channel)
+		if (msg->operating_channel)
 			dev->oper_freq =
-				p2p_channel_to_freq(msg.operating_channel[3],
-						    msg.operating_channel[4]);
+				p2p_channel_to_freq(msg->operating_channel[3],
+						    msg->operating_channel[4]);
 
 		if ((conncap & P2PS_SETUP_GROUP_OWNER) &&
 		    p2p_go_select_channel(p2p, dev, &tmp) < 0)
@@ -973,7 +1285,7 @@ void p2p_process_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
 out:
 	if (reject == P2P_SC_SUCCESS ||
 	    reject == P2P_SC_FAIL_INFO_CURRENTLY_UNAVAILABLE)
-		config_methods = msg.wps_config_methods;
+		config_methods = msg->wps_config_methods;
 	else
 		config_methods = 0;
 
@@ -981,18 +1293,18 @@ out:
 	 * Send PD Response for an initial PD Request or for follow-on
 	 * PD Request with P2P_SC_SUCCESS_DEFERRED status.
 	 */
-	if (!msg.status || *msg.status == P2P_SC_SUCCESS_DEFERRED) {
-		resp = p2p_build_prov_disc_resp(p2p, dev, msg.dialog_token,
+	if (!msg->status || *msg->status == P2P_SC_SUCCESS_DEFERRED) {
+		resp = p2p_build_prov_disc_resp(p2p, dev, msg->dialog_token,
 						reject, config_methods, adv_id,
-						msg.group_id, msg.group_id_len,
-						msg.persistent_ssid,
-						msg.persistent_ssid_len,
+						msg->group_id,
+						msg->group_id_len,
+						msg->persistent_ssid,
+						msg->persistent_ssid_len,
 						(const u8 *) &resp_fcap,
 						sizeof(resp_fcap));
-		if (!resp) {
-			p2p_parse_free(&msg);
+		if (!resp)
 			return;
-		}
+
 		p2p_dbg(p2p, "Sending Provision Discovery Response");
 		if (rx_freq > 0)
 			freq = rx_freq;
@@ -1002,7 +1314,6 @@ out:
 		if (freq < 0) {
 			p2p_dbg(p2p, "Unknown regulatory class/channel");
 			wpabuf_free(resp);
-			p2p_parse_free(&msg);
 			return;
 		}
 		p2p->pending_action_state = P2P_PENDING_PD_RESPONSE;
@@ -1017,10 +1328,8 @@ out:
 		wpabuf_free(resp);
 	}
 
-	if (!dev) {
-		p2p_parse_free(&msg);
+	if (!dev)
 		return;
-	}
 
 	freq = 0;
 	if (reject == P2P_SC_SUCCESS && conncap == P2PS_SETUP_GROUP_OWNER) {
@@ -1032,17 +1341,17 @@ out:
 
 	if (!p2p->cfg->p2ps_prov_complete) {
 		/* Don't emit anything */
-	} else if (msg.status && *msg.status != P2P_SC_SUCCESS &&
-		   *msg.status != P2P_SC_SUCCESS_DEFERRED) {
-		reject = *msg.status;
+	} else if (msg->status && *msg->status != P2P_SC_SUCCESS &&
+		   *msg->status != P2P_SC_SUCCESS_DEFERRED) {
+		reject = *msg->status;
 		p2p->cfg->p2ps_prov_complete(p2p->cfg->cb_ctx, reject,
 					     sa, adv_mac, session_mac,
 					     NULL, adv_id, session_id,
-					     0, 0, msg.persistent_ssid,
-					     msg.persistent_ssid_len,
+					     0, 0, msg->persistent_ssid,
+					     msg->persistent_ssid_len,
 					     0, 0, NULL, NULL, 0, freq,
 					     NULL, 0);
-	} else if (msg.status && *msg.status == P2P_SC_SUCCESS_DEFERRED &&
+	} else if (msg->status && *msg->status == P2P_SC_SUCCESS_DEFERRED &&
 		   p2p->p2ps_prov) {
 		p2p->p2ps_prov->status = reject;
 		p2p->p2ps_prov->conncap = conncap;
@@ -1052,77 +1361,77 @@ out:
 						     sa, adv_mac, session_mac,
 						     NULL, adv_id,
 						     session_id, conncap, 0,
-						     msg.persistent_ssid,
-						     msg.persistent_ssid_len, 0,
-						     0, NULL, NULL, 0, freq,
+						     msg->persistent_ssid,
+						     msg->persistent_ssid_len,
+						     0, 0, NULL, NULL, 0, freq,
 						     NULL, 0);
 		else
 			p2p->cfg->p2ps_prov_complete(p2p->cfg->cb_ctx,
-						     *msg.status,
+						     *msg->status,
 						     sa, adv_mac, session_mac,
 						     group_mac, adv_id,
 						     session_id, conncap,
 						     passwd_id,
-						     msg.persistent_ssid,
-						     msg.persistent_ssid_len, 0,
-						     0, NULL,
+						     msg->persistent_ssid,
+						     msg->persistent_ssid_len,
+						     0, 0, NULL,
 						     (const u8 *) &resp_fcap,
 						     sizeof(resp_fcap), freq,
 						     NULL, 0);
-	} else if (msg.status && p2p->p2ps_prov) {
+	} else if (msg->status && p2p->p2ps_prov) {
 		p2p->p2ps_prov->status = P2P_SC_SUCCESS;
-		p2p->cfg->p2ps_prov_complete(p2p->cfg->cb_ctx, *msg.status, sa,
+		p2p->cfg->p2ps_prov_complete(p2p->cfg->cb_ctx, *msg->status, sa,
 					     adv_mac, session_mac, group_mac,
 					     adv_id, session_id, conncap,
 					     passwd_id,
-					     msg.persistent_ssid,
-					     msg.persistent_ssid_len,
+					     msg->persistent_ssid,
+					     msg->persistent_ssid_len,
 					     0, 0, NULL,
 					     (const u8 *) &resp_fcap,
 					     sizeof(resp_fcap), freq, NULL, 0);
-	} else if (msg.status) {
+	} else if (msg->status) {
 	} else if (auto_accept && reject == P2P_SC_SUCCESS) {
 		p2p->cfg->p2ps_prov_complete(p2p->cfg->cb_ctx, P2P_SC_SUCCESS,
 					     sa, adv_mac, session_mac,
 					     group_mac, adv_id, session_id,
 					     conncap, passwd_id,
-					     msg.persistent_ssid,
-					     msg.persistent_ssid_len,
+					     msg->persistent_ssid,
+					     msg->persistent_ssid_len,
 					     0, 0, NULL,
 					     (const u8 *) &resp_fcap,
 					     sizeof(resp_fcap), freq,
-					     msg.group_id ?
-					     msg.group_id + ETH_ALEN : NULL,
-					     msg.group_id ?
-					     msg.group_id_len - ETH_ALEN : 0);
+					     msg->group_id ?
+					     msg->group_id + ETH_ALEN : NULL,
+					     msg->group_id ?
+					     msg->group_id_len - ETH_ALEN : 0);
 	} else if (reject == P2P_SC_FAIL_INFO_CURRENTLY_UNAVAILABLE &&
-		   (!msg.session_info || !msg.session_info_len)) {
-		p2p->p2ps_prov->method = msg.wps_config_methods;
+		   (!msg->session_info || !msg->session_info_len)) {
+		p2p->p2ps_prov->method = msg->wps_config_methods;
 
 		p2p->cfg->p2ps_prov_complete(p2p->cfg->cb_ctx, P2P_SC_SUCCESS,
 					     sa, adv_mac, session_mac,
 					     group_mac, adv_id, session_id,
 					     conncap, passwd_id,
-					     msg.persistent_ssid,
-					     msg.persistent_ssid_len,
+					     msg->persistent_ssid,
+					     msg->persistent_ssid_len,
 					     0, 1, NULL,
 					     (const u8 *) &resp_fcap,
 					     sizeof(resp_fcap), freq, NULL, 0);
 	} else if (reject == P2P_SC_FAIL_INFO_CURRENTLY_UNAVAILABLE) {
-		size_t buf_len = msg.session_info_len;
+		size_t buf_len = msg->session_info_len;
 		char *buf = os_malloc(2 * buf_len + 1);
 
 		if (buf) {
-			p2p->p2ps_prov->method = msg.wps_config_methods;
+			p2p->p2ps_prov->method = msg->wps_config_methods;
 
-			utf8_escape((char *) msg.session_info, buf_len,
+			utf8_escape((char *) msg->session_info, buf_len,
 				    buf, 2 * buf_len + 1);
 
 			p2p->cfg->p2ps_prov_complete(
 				p2p->cfg->cb_ctx, P2P_SC_SUCCESS, sa,
 				adv_mac, session_mac, group_mac, adv_id,
 				session_id, conncap, passwd_id,
-				msg.persistent_ssid, msg.persistent_ssid_len,
+				msg->persistent_ssid, msg->persistent_ssid_len,
 				0, 1, buf,
 				(const u8 *) &resp_fcap, sizeof(resp_fcap),
 				freq, NULL, 0);
@@ -1150,29 +1459,30 @@ out:
 	 *    seeker: KEYPAD, response status: SUCCESS
 	 */
 	if (p2p->cfg->prov_disc_req &&
-	    ((reject == P2P_SC_SUCCESS && !msg.adv_id) ||
-	     (!msg.status &&
+	    ((reject == P2P_SC_SUCCESS && !msg->adv_id) ||
+	     (!msg->status &&
 	     (reject == P2P_SC_SUCCESS ||
 	      reject == P2P_SC_FAIL_INFO_CURRENTLY_UNAVAILABLE) &&
 	      passwd_id == DEV_PW_USER_SPECIFIED) ||
-	     (!msg.status &&
+	     (!msg->status &&
 	      reject == P2P_SC_FAIL_INFO_CURRENTLY_UNAVAILABLE &&
 	      passwd_id == DEV_PW_REGISTRAR_SPECIFIED) ||
 	     (reject == P2P_SC_SUCCESS &&
-	      msg.status && *msg.status == P2P_SC_SUCCESS_DEFERRED &&
+	      msg->status && *msg->status == P2P_SC_SUCCESS_DEFERRED &&
 	       passwd_id == DEV_PW_REGISTRAR_SPECIFIED))) {
 		const u8 *dev_addr = sa;
 
-		if (msg.p2p_device_addr)
-			dev_addr = msg.p2p_device_addr;
+		if (msg->p2p_device_addr)
+			dev_addr = msg->p2p_device_addr;
 		p2p->cfg->prov_disc_req(p2p->cfg->cb_ctx, sa,
-					msg.wps_config_methods,
-					dev_addr, msg.pri_dev_type,
-					msg.device_name, msg.config_methods,
-					msg.capability ? msg.capability[0] : 0,
-					msg.capability ? msg.capability[1] :
+					msg->wps_config_methods,
+					dev_addr, msg->pri_dev_type,
+					msg->device_name, msg->config_methods,
+					msg->capability ? msg->capability[0] :
+					0,
+					msg->capability ? msg->capability[1] :
 					0,
-					msg.group_id, msg.group_id_len);
+					msg->group_id, msg->group_id_len);
 	}
 
 	if (reject != P2P_SC_FAIL_INFO_CURRENTLY_UNAVAILABLE)
@@ -1197,10 +1507,28 @@ out:
 			break;
 		}
 
-		if (msg.intended_addr)
-			os_memcpy(dev->interface_addr, msg.intended_addr,
+		if (msg->intended_addr)
+			os_memcpy(dev->interface_addr, msg->intended_addr,
 				  ETH_ALEN);
 	}
+}
+
+
+void p2p_handle_prov_disc_req(struct p2p_data *p2p, const u8 *sa,
+			      const u8 *data, size_t len, int rx_freq)
+{
+	struct p2p_message msg;
+
+	if (p2p_parse(data, len, &msg))
+		return;
+
+	if (msg.pcea_info && msg.pbma_info)
+		p2p_process_prov_disc_bootstrap_req(p2p, &msg, sa, data + 1,
+						    len - 1, rx_freq);
+	else
+		p2p_process_prov_disc_req(p2p, &msg, sa, data + 1, len - 1,
+					  rx_freq);
+
 	p2p_parse_free(&msg);
 }
 
@@ -1303,13 +1631,102 @@ static int p2p_validate_p2ps_pd_resp(struct p2p_data *p2p,
 }
 
 
-void p2p_process_prov_disc_resp(struct p2p_data *p2p, const u8 *sa,
-				const u8 *data, size_t len)
+static void p2p_process_prov_disc_bootstrap_resp(struct p2p_data *p2p,
+						 struct p2p_message *msg,
+						 const u8 *sa, const u8 *data,
+						 size_t len, int rx_freq)
+{
+	struct p2p_device *dev;
+	enum p2p_status_code status = P2P_SC_SUCCESS;
+	size_t cookie_len = 0;
+	const u8 *pos, *cookie;
+	u16 comeback_after;
+
+	/* Parse the P2P status present */
+	if (msg->status)
+		status = *msg->status;
+
+	p2p_dbg(p2p, "Received Provision Discovery Bootstrap Response from "
+		MACSTR, MAC2STR(sa));
+
+	dev = p2p_get_device(p2p, sa);
+	if (!dev || !dev->req_bootstrap_method) {
+		p2p_dbg(p2p, "Ignore Provision Discovery Response from " MACSTR
+			" with no pending request", MAC2STR(sa));
+		return;
+	}
+
+	p2p_update_peer_6ghz_capab(dev, msg);
+
+	if (dev->dialog_token != msg->dialog_token) {
+		p2p_dbg(p2p,
+			"Ignore Provision Discovery Response with unexpected Dialog Token %u (expected %u)",
+			msg->dialog_token, dev->dialog_token);
+		return;
+	}
+
+	if (p2p->pending_action_state == P2P_PENDING_PD) {
+		os_memset(p2p->pending_pd_devaddr, 0, ETH_ALEN);
+		p2p->pending_action_state = P2P_NO_PENDING_ACTION;
+	}
+
+	os_free(dev->bootstrap_params);
+	dev->bootstrap_params = NULL;
+
+	/* If the response is from the peer to whom a user initiated request
+	 * was sent earlier, we reset that state information here. */
+	if (p2p->user_initiated_pd &&
+	    ether_addr_equal(p2p->pending_pd_devaddr, sa))
+		p2p_reset_pending_pd(p2p);
+
+	if (status == P2P_SC_COMEBACK) {
+		/* PBMA comeback response */
+		pos = msg->pbma_info;
+		if (msg->pbma_info_len < 2 + 1)
+			return;
+		comeback_after = WPA_GET_LE16(pos);
+		pos += 2;
+		cookie_len = *pos++;
+		if (msg->pbma_info_len < 2 + 1 + cookie_len) {
+			p2p_dbg(p2p, "Truncated PBMA");
+			return;
+		}
+		cookie = pos;
+
+		dev->bootstrap_params =
+			os_zalloc(sizeof(struct p2p_bootstrap_params));
+		if (!dev->bootstrap_params)
+			return;
+		dev->bootstrap_params->cookie_len = cookie_len;
+		os_memcpy(dev->bootstrap_params->cookie, cookie, cookie_len);
+		dev->bootstrap_params->comeback_after = comeback_after;
+		dev->bootstrap_params->bootstrap_method =
+						dev->req_bootstrap_method;
+		dev->bootstrap_params->status = status;
+
+		p2p->cfg->register_bootstrap_comeback(p2p->cfg->cb_ctx, sa,
+						      comeback_after);
+		p2p->cfg->send_action_done(p2p->cfg->cb_ctx);
+		return;
+	}
+
+	p2p->cfg->send_action_done(p2p->cfg->cb_ctx);
+	if (dev->flags & P2P_DEV_PD_BEFORE_GO_NEG)
+		dev->flags &= ~P2P_DEV_PD_BEFORE_GO_NEG;
+
+	if (p2p->cfg->bootstrap_completed)
+		p2p->cfg->bootstrap_completed(p2p->cfg->cb_ctx, sa, status,
+					      rx_freq);
+}
+
+
+static void p2p_process_prov_disc_resp(struct p2p_data *p2p,
+				       struct p2p_message *msg, const u8 *sa,
+				       const u8 *data, size_t len)
 {
-	struct p2p_message msg;
 	struct p2p_device *dev;
 	u16 report_config_methods = 0, req_config_methods;
-	u8 status = P2P_SC_SUCCESS;
+	enum p2p_status_code status = P2P_SC_SUCCESS;
 	u32 adv_id = 0;
 	u8 conncap = P2PS_SETUP_NEW;
 	u8 adv_mac[ETH_ALEN];
@@ -1317,30 +1734,25 @@ void p2p_process_prov_disc_resp(struct p2p_data *p2p, const u8 *sa,
 	int passwd_id = DEV_PW_DEFAULT;
 	int p2ps_seeker;
 
-	if (p2p_parse(data, len, &msg))
+	if (p2p->p2ps_prov && p2p_validate_p2ps_pd_resp(p2p, msg))
 		return;
 
-	if (p2p->p2ps_prov && p2p_validate_p2ps_pd_resp(p2p, &msg)) {
-		p2p_parse_free(&msg);
-		return;
-	}
-
 	/* Parse the P2PS members present */
-	if (msg.status)
-		status = *msg.status;
+	if (msg->status)
+		status = *msg->status;
 
-	group_mac = msg.intended_addr;
+	group_mac = msg->intended_addr;
 
-	if (msg.adv_mac)
-		os_memcpy(adv_mac, msg.adv_mac, ETH_ALEN);
+	if (msg->adv_mac)
+		os_memcpy(adv_mac, msg->adv_mac, ETH_ALEN);
 	else
 		os_memset(adv_mac, 0, ETH_ALEN);
 
-	if (msg.adv_id)
-		adv_id = WPA_GET_LE32(msg.adv_id);
+	if (msg->adv_id)
+		adv_id = WPA_GET_LE32(msg->adv_id);
 
-	if (msg.conn_cap) {
-		conncap = *msg.conn_cap;
+	if (msg->conn_cap) {
+		conncap = *msg->conn_cap;
 
 		/* Switch bits to local relative */
 		switch (conncap) {
@@ -1355,25 +1767,23 @@ void p2p_process_prov_disc_resp(struct p2p_data *p2p, const u8 *sa,
 
 	p2p_dbg(p2p, "Received Provision Discovery Response from " MACSTR
 		" with config methods 0x%x",
-		MAC2STR(sa), msg.wps_config_methods);
+		MAC2STR(sa), msg->wps_config_methods);
 
 	dev = p2p_get_device(p2p, sa);
 	if (dev == NULL || !dev->req_config_methods) {
 		p2p_dbg(p2p, "Ignore Provision Discovery Response from " MACSTR
 			" with no pending request", MAC2STR(sa));
-		p2p_parse_free(&msg);
 		return;
-	} else if (msg.wfd_subelems) {
+	} else if (msg->wfd_subelems) {
 		wpabuf_free(dev->info.wfd_subelems);
-		dev->info.wfd_subelems = wpabuf_dup(msg.wfd_subelems);
+		dev->info.wfd_subelems = wpabuf_dup(msg->wfd_subelems);
 	}
 
-	p2p_update_peer_6ghz_capab(dev, &msg);
+	p2p_update_peer_6ghz_capab(dev, msg);
 
-	if (dev->dialog_token != msg.dialog_token) {
+	if (dev->dialog_token != msg->dialog_token) {
 		p2p_dbg(p2p, "Ignore Provision Discovery Response with unexpected Dialog Token %u (expected %u)",
-			msg.dialog_token, dev->dialog_token);
-		p2p_parse_free(&msg);
+			msg->dialog_token, dev->dialog_token);
 		return;
 	}
 
@@ -1398,14 +1808,13 @@ void p2p_process_prov_disc_resp(struct p2p_data *p2p, const u8 *sa,
 	    ether_addr_equal(p2p->pending_pd_devaddr, sa))
 		p2p_reset_pending_pd(p2p);
 
-	if (msg.wps_config_methods != req_config_methods) {
+	if (msg->wps_config_methods != req_config_methods) {
 		p2p_dbg(p2p, "Peer rejected our Provision Discovery Request (received config_methods 0x%x expected 0x%x",
-			msg.wps_config_methods, req_config_methods);
+			msg->wps_config_methods, req_config_methods);
 		if (p2p->cfg->prov_disc_fail)
 			p2p->cfg->prov_disc_fail(p2p->cfg->cb_ctx, sa,
 						 P2P_PROV_DISC_REJECTED,
 						 adv_id, adv_mac, NULL);
-		p2p_parse_free(&msg);
 		p2ps_prov_free(p2p);
 		goto out;
 	}
@@ -1419,13 +1828,13 @@ void p2p_process_prov_disc_resp(struct p2p_data *p2p, const u8 *sa,
 			" accepted to show a PIN on display", MAC2STR(sa));
 		dev->flags |= P2P_DEV_PD_PEER_DISPLAY;
 		passwd_id = DEV_PW_REGISTRAR_SPECIFIED;
-	} else if (msg.wps_config_methods & WPS_CONFIG_KEYPAD) {
+	} else if (msg->wps_config_methods & WPS_CONFIG_KEYPAD) {
 		p2p_dbg(p2p, "Peer " MACSTR
 			" accepted to write our PIN using keypad",
 			MAC2STR(sa));
 		dev->flags |= P2P_DEV_PD_PEER_KEYPAD;
 		passwd_id = DEV_PW_USER_SPECIFIED;
-	} else if (msg.wps_config_methods & WPS_CONFIG_P2PS) {
+	} else if (msg->wps_config_methods & WPS_CONFIG_P2PS) {
 		p2p_dbg(p2p, "Peer " MACSTR " accepted P2PS PIN",
 			MAC2STR(sa));
 		dev->flags |= P2P_DEV_PD_PEER_P2PS;
@@ -1444,23 +1853,23 @@ void p2p_process_prov_disc_resp(struct p2p_data *p2p, const u8 *sa,
 		 * fails the flow would continue, although it would probably
 		 * fail. Same is true for the operating channel.
 		 */
-		if (msg.channel_list && msg.channel_list_len &&
+		if (msg->channel_list && msg->channel_list_len &&
 		    p2p_peer_channels_check(p2p, &p2p->channels, dev,
-					    msg.channel_list,
-					    msg.channel_list_len) < 0)
+					    msg->channel_list,
+					    msg->channel_list_len) < 0)
 			p2p_dbg(p2p, "P2PS PD Response - no common channels");
 
-		if (msg.operating_channel) {
+		if (msg->operating_channel) {
 			if (p2p_channels_includes(&p2p->channels,
-						  msg.operating_channel[3],
-						  msg.operating_channel[4]) &&
+						  msg->operating_channel[3],
+						  msg->operating_channel[4]) &&
 			    p2p_channels_includes(&dev->channels,
-						  msg.operating_channel[3],
-						  msg.operating_channel[4])) {
+						  msg->operating_channel[3],
+						  msg->operating_channel[4])) {
 				dev->oper_freq =
 					p2p_channel_to_freq(
-						msg.operating_channel[3],
-						msg.operating_channel[4]);
+						msg->operating_channel[3],
+						msg->operating_channel[4]);
 			} else {
 				p2p_dbg(p2p,
 					"P2PS PD Response - invalid operating channel");
@@ -1492,11 +1901,12 @@ void p2p_process_prov_disc_resp(struct p2p_data *p2p, const u8 *sa,
 				p2p->cfg->cb_ctx, status, sa, adv_mac,
 				p2p->p2ps_prov->session_mac,
 				group_mac, adv_id, p2p->p2ps_prov->session_id,
-				conncap, passwd_id, msg.persistent_ssid,
-				msg.persistent_ssid_len, 1, 0, NULL,
-				msg.feature_cap, msg.feature_cap_len, freq,
-				msg.group_id ? msg.group_id + ETH_ALEN : NULL,
-				msg.group_id ? msg.group_id_len - ETH_ALEN : 0);
+				conncap, passwd_id, msg->persistent_ssid,
+				msg->persistent_ssid_len, 1, 0, NULL,
+				msg->feature_cap, msg->feature_cap_len, freq,
+				msg->group_id ? msg->group_id + ETH_ALEN : NULL,
+				msg->group_id ? msg->group_id_len - ETH_ALEN :
+				0);
 		}
 		p2ps_prov_free(p2p);
 	} else if (status != P2P_SC_SUCCESS &&
@@ -1518,16 +1928,15 @@ void p2p_process_prov_disc_resp(struct p2p_data *p2p, const u8 *sa,
 						      NULL, NULL, 0);
 		}
 
-		if (msg.session_info && msg.session_info_len) {
-			size_t info_len = msg.session_info_len;
+		if (msg->session_info && msg->session_info_len) {
+			size_t info_len = msg->session_info_len;
 			char *deferred_sess_resp = os_malloc(2 * info_len + 1);
 
 			if (!deferred_sess_resp) {
-				p2p_parse_free(&msg);
 				p2ps_prov_free(p2p);
 				goto out;
 			}
-			utf8_escape((char *) msg.session_info, info_len,
+			utf8_escape((char *) msg->session_info, info_len,
 				    deferred_sess_resp, 2 * info_len + 1);
 
 			if (p2p->cfg->prov_disc_fail)
@@ -1549,17 +1958,14 @@ void p2p_process_prov_disc_resp(struct p2p_data *p2p, const u8 *sa,
 			p2p->cfg->prov_disc_fail(p2p->cfg->cb_ctx, sa,
 						 P2P_PROV_DISC_REJECTED,
 						 adv_id, adv_mac, NULL);
-		p2p_parse_free(&msg);
 		p2ps_prov_free(p2p);
 		goto out;
 	}
 
 	/* Store the provisioning info */
-	dev->wps_prov_info = msg.wps_config_methods;
-	if (msg.intended_addr)
-		os_memcpy(dev->interface_addr, msg.intended_addr, ETH_ALEN);
-
-	p2p_parse_free(&msg);
+	dev->wps_prov_info = msg->wps_config_methods;
+	if (msg->intended_addr)
+		os_memcpy(dev->interface_addr, msg->intended_addr, ETH_ALEN);
 
 out:
 	dev->req_config_methods = 0;
@@ -1603,6 +2009,24 @@ out:
 }
 
 
+void p2p_handle_prov_disc_resp(struct p2p_data *p2p, const u8 *sa,
+			       const u8 *data, size_t len, int rx_freq)
+{
+	struct p2p_message msg;
+
+	if (p2p_parse(data, len, &msg))
+		return;
+
+	if (msg.pcea_info && msg.pbma_info)
+		p2p_process_prov_disc_bootstrap_resp(p2p, &msg, sa, data + 1,
+						     len - 1, rx_freq);
+	else
+		p2p_process_prov_disc_resp(p2p, &msg, sa, data + 1, len - 1);
+
+	p2p_parse_free(&msg);
+}
+
+
 int p2p_send_prov_disc_req(struct p2p_data *p2p, struct p2p_device *dev,
 			   int join, int force_freq)
 {
@@ -1632,7 +2056,7 @@ int p2p_send_prov_disc_req(struct p2p_data *p2p, struct p2p_device *dev,
 		/* TODO: use device discoverability request through GO */
 	}
 
-	if (p2p->p2ps_prov) {
+	if (!dev->p2p2 && p2p->p2ps_prov) {
 		if (p2p->p2ps_prov->status == P2P_SC_SUCCESS_DEFERRED) {
 			if (p2p->p2ps_prov->method == WPS_CONFIG_DISPLAY)
 				dev->req_config_methods = WPS_CONFIG_KEYPAD;
@@ -1662,7 +2086,11 @@ int p2p_send_prov_disc_req(struct p2p_data *p2p, struct p2p_device *dev,
 			return -1;
 	}
 
-	req = p2p_build_prov_disc_req(p2p, dev, join);
+	if (dev->p2p2)
+		req = p2p_build_prov_disc_bootstrap_req(p2p, dev);
+	else
+		req = p2p_build_prov_disc_req(p2p, dev, join);
+
 	if (req == NULL)
 		return -1;
 
@@ -1701,13 +2129,22 @@ int p2p_prov_disc_req(struct p2p_data *p2p, const u8 *peer_addr,
 		return -1;
 	}
 
+	if (dev->p2p2 && dev->req_bootstrap_method) {
+		p2p_dbg(p2p, "Provision Discovery Request with " MACSTR
+			" (bootstrap methods 0x%x)",
+			MAC2STR(peer_addr), dev->req_bootstrap_method);
+		goto out;
+	}
+
 	p2p_dbg(p2p, "Provision Discovery Request with " MACSTR
 		" (config methods 0x%x)",
 		MAC2STR(peer_addr), config_methods);
+
 	if (config_methods == 0 && !p2ps_prov) {
 		os_free(p2ps_prov);
 		return -1;
 	}
+	dev->req_config_methods = config_methods;
 
 	if (p2ps_prov && p2ps_prov->status == P2P_SC_SUCCESS_DEFERRED &&
 	    p2p->p2ps_prov) {
@@ -1715,12 +2152,12 @@ int p2p_prov_disc_req(struct p2p_data *p2p, const u8 *peer_addr,
 		p2ps_prov->method = p2p->p2ps_prov->method;
 	}
 
+out:
 	/* Reset provisioning info */
 	dev->wps_prov_info = 0;
 	p2ps_prov_free(p2p);
 	p2p->p2ps_prov = p2ps_prov;
 
-	dev->req_config_methods = config_methods;
 	if (join)
 		dev->flags |= P2P_DEV_PD_FOR_JOIN;
 	else
@@ -1729,8 +2166,7 @@ int p2p_prov_disc_req(struct p2p_data *p2p, const u8 *peer_addr,
 	if (p2p->state != P2P_IDLE && p2p->state != P2P_SEARCH &&
 	    p2p->state != P2P_LISTEN_ONLY) {
 		p2p_dbg(p2p, "Busy with other operations; postpone Provision Discovery Request with "
-			MACSTR " (config methods 0x%x)",
-			MAC2STR(peer_addr), config_methods);
+			MACSTR, MAC2STR(peer_addr));
 		return 0;
 	}
 
diff --git a/src/pasn/pasn_common.c b/src/pasn/pasn_common.c
index e2c66813..25e44a19 100644
--- a/src/pasn/pasn_common.c
+++ b/src/pasn/pasn_common.c
@@ -28,6 +28,9 @@ struct pasn_data * pasn_data_init(void)
 
 void pasn_data_deinit(struct pasn_data *pasn)
 {
+	if (!pasn)
+		return;
+	os_free(pasn->rsnxe_ie);
 	bin_clear_free(pasn, sizeof(struct pasn_data));
 }
 
@@ -157,7 +160,7 @@ void pasn_set_rsnxe_ie(struct pasn_data *pasn, const u8 *rsnxe_ie)
 {
 	if (!pasn || !rsnxe_ie)
 		return;
-	pasn->rsnxe_ie = rsnxe_ie;
+	pasn->rsnxe_ie = os_memdup(rsnxe_ie, 2 + rsnxe_ie[1]);
 }
 
 
@@ -192,6 +195,14 @@ int pasn_set_extra_ies(struct pasn_data *pasn, const u8 *extra_ies,
 }
 
 
+void pasn_set_noauth(struct pasn_data *pasn, bool noauth)
+{
+	if (!pasn)
+		return;
+	pasn->noauth = noauth;
+}
+
+
 int pasn_get_akmp(struct pasn_data *pasn)
 {
 	if (!pasn)
diff --git a/src/pasn/pasn_common.h b/src/pasn/pasn_common.h
index 36710c2b..7b7c7379 100644
--- a/src/pasn/pasn_common.h
+++ b/src/pasn/pasn_common.h
@@ -54,7 +54,7 @@ struct pasn_data {
 	int wpa_key_mgmt;
 	int rsn_pairwise;
 	u16 rsnxe_capab;
-	const u8 *rsnxe_ie;
+	u8 *rsnxe_ie;
 	bool custom_pmkid_valid;
 	u8 custom_pmkid[PMKID_LEN];
 
@@ -66,6 +66,7 @@ struct pasn_data {
 	size_t extra_ies_len;
 
 	/* External modules do not access below variables */
+	size_t kek_len;
 	u16 group;
 	bool secure_ltf;
 	int freq;
@@ -174,7 +175,8 @@ int wpa_pasn_auth_tx_status(struct pasn_data *pasn,
 /* Responder */
 int handle_auth_pasn_1(struct pasn_data *pasn,
 		       const u8 *own_addr, const u8 *peer_addr,
-		       const struct ieee80211_mgmt *mgmt, size_t len);
+		       const struct ieee80211_mgmt *mgmt, size_t len,
+		       bool reject);
 int handle_auth_pasn_3(struct pasn_data *pasn, const u8 *own_addr,
 		       const u8 *peer_addr,
 		       const struct ieee80211_mgmt *mgmt, size_t len);
@@ -205,8 +207,20 @@ void pasn_set_initiator_pmksa(struct pasn_data *pasn,
 void pasn_set_responder_pmksa(struct pasn_data *pasn,
 			      struct rsn_pmksa_cache *pmksa);
 int pasn_set_pt(struct pasn_data *pasn, struct sae_pt *pt);
+struct rsn_pmksa_cache * pasn_initiator_pmksa_cache_init(void);
+void pasn_initiator_pmksa_cache_deinit(struct rsn_pmksa_cache *pmksa);
+int pasn_initiator_pmksa_cache_add(struct rsn_pmksa_cache *pmksa,
+				   const u8 *own_addr, const u8 *bssid, u8 *pmk,
+				   size_t pmk_len, u8 *pmkid);
+int pasn_initiator_pmksa_cache_get(struct rsn_pmksa_cache *pmksa,
+				   const u8 *bssid, u8 *pmkid, u8 *pmk,
+				   size_t *pmk_len);
+void pasn_initiator_pmksa_cache_remove(struct rsn_pmksa_cache *pmksa,
+				       const u8 *bssid);
+void pasn_initiator_pmksa_cache_flush(struct rsn_pmksa_cache *pmksa);
 
 /* Responder */
+void pasn_set_noauth(struct pasn_data *pasn, bool noauth);
 void pasn_set_password(struct pasn_data *pasn, const char *password);
 void pasn_set_wpa_key_mgmt(struct pasn_data *pasn, int key_mgmt);
 void pasn_set_rsn_pairwise(struct pasn_data *pasn, int rsn_pairwise);
@@ -215,6 +229,17 @@ void pasn_set_rsnxe_ie(struct pasn_data *pasn, const u8 *rsnxe_ie);
 void pasn_set_custom_pmkid(struct pasn_data *pasn, const u8 *pmkid);
 int pasn_set_extra_ies(struct pasn_data *pasn, const u8 *extra_ies,
 		       size_t extra_ies_len);
+struct rsn_pmksa_cache * pasn_responder_pmksa_cache_init(void);
+void pasn_responder_pmksa_cache_deinit(struct rsn_pmksa_cache *pmksa);
+int pasn_responder_pmksa_cache_add(struct rsn_pmksa_cache *pmksa,
+				   const u8 *own_addr, const u8 *bssid, u8 *pmk,
+				   size_t pmk_len, u8 *pmkid);
+int pasn_responder_pmksa_cache_get(struct rsn_pmksa_cache *pmksa,
+				   const u8 *bssid, u8 *pmkid, u8 *pmk,
+				   size_t *pmk_len);
+void pasn_responder_pmksa_cache_remove(struct rsn_pmksa_cache *pmksa,
+				       const u8 *bssid);
+void pasn_responder_pmksa_cache_flush(struct rsn_pmksa_cache *pmksa);
 
 int pasn_get_akmp(struct pasn_data *pasn);
 int pasn_get_cipher(struct pasn_data *pasn);
diff --git a/src/pasn/pasn_initiator.c b/src/pasn/pasn_initiator.c
index d273067b..ce1055b1 100644
--- a/src/pasn/pasn_initiator.c
+++ b/src/pasn/pasn_initiator.c
@@ -26,6 +26,65 @@
 #include "pasn_common.h"
 
 
+struct rsn_pmksa_cache * pasn_initiator_pmksa_cache_init(void)
+{
+	return pmksa_cache_init(NULL, NULL, NULL, NULL, NULL);
+}
+
+
+void pasn_initiator_pmksa_cache_deinit(struct rsn_pmksa_cache *pmksa)
+{
+	return pmksa_cache_deinit(pmksa);
+}
+
+
+int pasn_initiator_pmksa_cache_add(struct rsn_pmksa_cache *pmksa,
+				   const u8 *own_addr, const u8 *bssid, u8 *pmk,
+				   size_t pmk_len, u8 *pmkid)
+{
+	if (pmksa_cache_add(pmksa, pmk, pmk_len, pmkid, NULL, 0, bssid,
+			    own_addr, NULL, WPA_KEY_MGMT_SAE, 0))
+		return 0;
+	return -1;
+}
+
+
+void pasn_initiator_pmksa_cache_remove(struct rsn_pmksa_cache *pmksa,
+				       const u8 *bssid)
+{
+	struct rsn_pmksa_cache_entry *entry;
+
+	entry = pmksa_cache_get(pmksa, bssid, NULL, NULL, NULL, 0);
+	if (!entry)
+		return;
+
+	pmksa_cache_remove(pmksa, entry);
+}
+
+
+int pasn_initiator_pmksa_cache_get(struct rsn_pmksa_cache *pmksa,
+				   const u8 *bssid, u8 *pmkid, u8 *pmk,
+				   size_t *pmk_len)
+{
+	struct rsn_pmksa_cache_entry *entry;
+
+	entry = pmksa_cache_get(pmksa, bssid, NULL, NULL, NULL, 0);
+	if (entry) {
+		os_memcpy(pmkid, entry->pmkid, PMKID_LEN);
+		os_memcpy(pmk, entry->pmk, entry->pmk_len);
+		*pmk_len = entry->pmk_len;
+		return 0;
+	}
+	return -1;
+}
+
+
+void pasn_initiator_pmksa_cache_flush(struct rsn_pmksa_cache *pmksa)
+{
+	return pmksa_cache_flush(pmksa, NULL, NULL, 0, false);
+}
+
+
 void pasn_set_initiator_pmksa(struct pasn_data *pasn,
 			      struct rsn_pmksa_cache *pmksa)
 {
@@ -587,7 +646,10 @@ static struct wpabuf * wpas_pasn_build_auth_1(struct pasn_data *pasn,
 	if (wpa_pasn_add_wrapped_data(buf, wrapped_data_buf) < 0)
 		goto fail;
 
-	wpa_pasn_add_rsnxe(buf, pasn->rsnxe_capab);
+	if (pasn->rsnxe_ie)
+		wpabuf_put_data(buf, pasn->rsnxe_ie, 2 + pasn->rsnxe_ie[1]);
+	else
+		wpa_pasn_add_rsnxe(buf, pasn->rsnxe_capab);
 
 	wpa_pasn_add_extra_ies(buf, pasn->extra_ies, pasn->extra_ies_len);
 
@@ -747,6 +809,7 @@ void wpa_pasn_reset(struct pasn_data *pasn)
 	pasn->derive_kdk = false;
 	pasn->rsn_ie = NULL;
 	pasn->rsn_ie_len = 0;
+	os_free(pasn->rsnxe_ie);
 	pasn->rsnxe_ie = NULL;
 	pasn->custom_pmkid_valid = false;
 
@@ -1233,7 +1296,7 @@ int wpa_pasn_auth_rx(struct pasn_data *pasn, const u8 *data, size_t len,
 			      pasn->own_addr, pasn->peer_addr,
 			      wpabuf_head(secret), wpabuf_len(secret),
 			      &pasn->ptk, pasn->akmp, pasn->cipher,
-			      pasn->kdk_len);
+			      pasn->kdk_len, pasn->kek_len);
 	if (ret) {
 		wpa_printf(MSG_DEBUG, "PASN: Failed to derive PTK");
 		goto fail;
diff --git a/src/pasn/pasn_responder.c b/src/pasn/pasn_responder.c
index b9913649..e344898d 100644
--- a/src/pasn/pasn_responder.c
+++ b/src/pasn/pasn_responder.c
@@ -26,6 +26,65 @@
 #include "pasn_common.h"
 
 
+struct rsn_pmksa_cache * pasn_responder_pmksa_cache_init(void)
+{
+	return pmksa_cache_auth_init(NULL, NULL);
+}
+
+
+void pasn_responder_pmksa_cache_deinit(struct rsn_pmksa_cache *pmksa)
+{
+	return pmksa_cache_auth_deinit(pmksa);
+}
+
+
+int pasn_responder_pmksa_cache_add(struct rsn_pmksa_cache *pmksa,
+				   const u8 *own_addr, const u8 *bssid, u8 *pmk,
+				   size_t pmk_len, u8 *pmkid)
+{
+	if (pmksa_cache_auth_add(pmksa, pmk, pmk_len, pmkid, NULL, 0, own_addr,
+				 bssid, 0, NULL, WPA_KEY_MGMT_SAE))
+		return 0;
+	return -1;
+}
+
+
+int pasn_responder_pmksa_cache_get(struct rsn_pmksa_cache *pmksa,
+				   const u8 *bssid, u8 *pmkid, u8 *pmk,
+				   size_t *pmk_len)
+{
+	struct rsn_pmksa_cache_entry *entry;
+
+	entry = pmksa_cache_auth_get(pmksa, bssid, NULL);
+	if (entry) {
+		os_memcpy(pmkid, entry->pmkid, PMKID_LEN);
+		os_memcpy(pmk, entry->pmk, entry->pmk_len);
+		*pmk_len = entry->pmk_len;
+		return 0;
+	}
+	return -1;
+}
+
+
+void pasn_responder_pmksa_cache_remove(struct rsn_pmksa_cache *pmksa,
+				       const u8 *bssid)
+{
+	struct rsn_pmksa_cache_entry *entry;
+
+	entry = pmksa_cache_auth_get(pmksa, bssid, NULL);
+	if (!entry)
+		return;
+
+	pmksa_cache_free_entry(pmksa, entry);
+}
+
+
+void pasn_responder_pmksa_cache_flush(struct rsn_pmksa_cache *pmksa)
+{
+	return pmksa_cache_auth_flush(pmksa);
+}
+
+
 void pasn_set_responder_pmksa(struct pasn_data *pasn,
 			      struct rsn_pmksa_cache *pmksa)
 {
@@ -349,7 +408,7 @@ pasn_derive_keys(struct pasn_data *pasn,
 	ret = pasn_pmk_to_ptk(pmk, pmk_len, peer_addr, own_addr,
 			      wpabuf_head(secret), wpabuf_len(secret),
 			      &pasn->ptk, pasn->akmp,
-			      pasn->cipher, pasn->kdk_len);
+			      pasn->cipher, pasn->kdk_len, pasn->kek_len);
 	if (ret) {
 		wpa_printf(MSG_DEBUG, "PASN: Failed to derive PTK");
 		return -1;
@@ -414,7 +473,7 @@ static void handle_auth_pasn_comeback(struct pasn_data *pasn,
 		   "PASN: comeback: STA=" MACSTR, MAC2STR(peer_addr));
 
 	ret = pasn->send_mgmt(pasn->cb_ctx, wpabuf_head_u8(buf),
-			      wpabuf_len(buf), 0, 0, 0);
+			      wpabuf_len(buf), 0, pasn->freq, 0);
 	if (ret)
 		wpa_printf(MSG_INFO, "PASN: Failed to send comeback frame 2");
 
@@ -579,7 +638,7 @@ done:
 		   MAC2STR(peer_addr));
 
 	ret = pasn->send_mgmt(pasn->cb_ctx, wpabuf_head_u8(buf),
-			      wpabuf_len(buf), 0, 0, 0);
+			      wpabuf_len(buf), 0, pasn->freq, 0);
 	if (ret)
 		wpa_printf(MSG_INFO, "send_auth_reply: Send failed");
 
@@ -597,7 +656,8 @@ fail:
 
 int handle_auth_pasn_1(struct pasn_data *pasn,
 		       const u8 *own_addr, const u8 *peer_addr,
-		       const struct ieee80211_mgmt *mgmt, size_t len)
+		       const struct ieee80211_mgmt *mgmt, size_t len,
+		       bool reject)
 {
 	struct ieee802_11_elems elems;
 	struct wpa_ie_data rsn_data;
@@ -616,6 +676,12 @@ int handle_auth_pasn_1(struct pasn_data *pasn,
 	if (!groups)
 		groups = default_groups;
 
+	if (reject) {
+		wpa_printf(MSG_DEBUG, "PASN: Received Rejection");
+		status = WLAN_STATUS_UNSPECIFIED_FAILURE;
+		goto send_resp;
+	}
+
 	if (ieee802_11_parse_elems(mgmt->u.auth.variable,
 				   len - offsetof(struct ieee80211_mgmt,
 						  u.auth.variable),
diff --git a/src/rsn_supp/wpa.c b/src/rsn_supp/wpa.c
index 935a1aa3..d145da0e 100644
--- a/src/rsn_supp/wpa.c
+++ b/src/rsn_supp/wpa.c
@@ -532,7 +532,7 @@ int wpa_supplicant_send_2_of_4(struct wpa_sm *sm, const unsigned char *dst,
 	size_t mic_len, hdrlen, rlen, extra_len = 0;
 	struct wpa_eapol_key *reply;
 	u8 *rbuf, *key_mic;
-	u8 *rsn_ie_buf = NULL;
+	u8 *rsn_ie_buf = NULL, *buf2 = NULL;
 	u16 key_info;
 #ifdef CONFIG_TESTING_OPTIONS
 	size_t pad_len = 0;
@@ -582,6 +582,37 @@ int wpa_supplicant_send_2_of_4(struct wpa_sm *sm, const unsigned char *dst,
 	}
 #endif /* CONFIG_IEEE80211R */
 
+	if (sm->rsn_override != RSN_OVERRIDE_NOT_USED) {
+		u8 *pos;
+
+		buf2 = os_malloc(wpa_ie_len + 2 + 4 + 1);
+		if (!buf2) {
+			os_free(rsn_ie_buf);
+			return -1;
+		}
+		os_memcpy(buf2, wpa_ie, wpa_ie_len);
+		pos = buf2 + wpa_ie_len;
+		*pos++ = WLAN_EID_VENDOR_SPECIFIC;
+		*pos++ = 4 + 1;
+		WPA_PUT_BE32(pos, RSN_SELECTION_IE_VENDOR_TYPE);
+		pos += 4;
+		if (sm->rsn_override == RSN_OVERRIDE_RSNE) {
+			*pos++ = RSN_SELECTION_RSNE;
+		} else if (sm->rsn_override == RSN_OVERRIDE_RSNE_OVERRIDE) {
+			*pos++ = RSN_SELECTION_RSNE_OVERRIDE;
+		} else if (sm->rsn_override == RSN_OVERRIDE_RSNE_OVERRIDE_2) {
+			*pos++ = RSN_SELECTION_RSNE_OVERRIDE_2;
+		} else {
+			os_free(rsn_ie_buf);
+			os_free(buf2);
+			return -1;
+		}
+
+		wpa_ie = buf2;
+		wpa_ie_len += 2 + 4 + 1;
+
+	}
+
 	wpa_hexdump(MSG_DEBUG, "WPA: WPA IE for msg 2/4", wpa_ie, wpa_ie_len);
 
 #ifdef CONFIG_TESTING_OPTIONS
@@ -602,6 +633,7 @@ int wpa_supplicant_send_2_of_4(struct wpa_sm *sm, const unsigned char *dst,
 				  &rlen, (void *) &reply);
 	if (rbuf == NULL) {
 		os_free(rsn_ie_buf);
+		os_free(buf2);
 		return -1;
 	}
 
@@ -634,6 +666,7 @@ int wpa_supplicant_send_2_of_4(struct wpa_sm *sm, const unsigned char *dst,
 	WPA_PUT_BE16(key_mic + mic_len, wpa_ie_len + extra_len);
 	os_memcpy(key_mic + mic_len + 2, wpa_ie, wpa_ie_len); /* Key Data */
 	os_free(rsn_ie_buf);
+	os_free(buf2);
 #ifdef CONFIG_TESTING_OPTIONS
 	if (sm->test_eapol_m2_elems) {
 		os_memcpy(key_mic + mic_len + 2 + wpa_ie_len,
@@ -991,6 +1024,8 @@ static void wpa_supplicant_process_1_of_4(struct wpa_sm *sm,
 				"WPA: Failed to get random data for SNonce");
 			goto failed;
 		}
+		if (wpa_sm_rsn_overriding_supported(sm))
+			rsn_set_snonce_cookie(sm->snonce);
 		sm->renew_snonce = 0;
 		wpa_hexdump(MSG_DEBUG, "WPA: Renewed SNonce",
 			    sm->snonce, WPA_NONCE_LEN);
@@ -2194,6 +2229,68 @@ static int wpa_supplicant_validate_ie(struct wpa_sm *sm,
 		return -1;
 	}
 
+	if (sm->proto == WPA_PROTO_RSN && wpa_sm_rsn_overriding_supported(sm)) {
+		if ((sm->ap_rsne_override && !ie->rsne_override) ||
+		    (!sm->ap_rsne_override && ie->rsne_override) ||
+		    (sm->ap_rsne_override && ie->rsne_override &&
+		     (sm->ap_rsne_override_len != ie->rsne_override_len ||
+		      os_memcmp(sm->ap_rsne_override, ie->rsne_override,
+				sm->ap_rsne_override_len) != 0))) {
+			wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
+				"RSN: RSNE Override element mismatch between Beacon/ProbeResp and EAPOL-Key msg 3/4");
+			wpa_hexdump(MSG_INFO,
+				    "RSNE Override element in Beacon/ProbeResp",
+				    sm->ap_rsne_override,
+				    sm->ap_rsne_override_len);
+			wpa_hexdump(MSG_INFO,
+				    "RSNE Override element in EAPOL-Key msg 3/4",
+				    ie->rsne_override, ie->rsne_override_len);
+			wpa_sm_deauthenticate(sm,
+					      WLAN_REASON_IE_IN_4WAY_DIFFERS);
+			return -1;
+		}
+
+		if ((sm->ap_rsne_override_2 && !ie->rsne_override_2) ||
+		    (!sm->ap_rsne_override_2 && ie->rsne_override_2) ||
+		    (sm->ap_rsne_override_2 && ie->rsne_override_2 &&
+		     (sm->ap_rsne_override_2_len != ie->rsne_override_2_len ||
+		      os_memcmp(sm->ap_rsne_override_2, ie->rsne_override_2,
+				sm->ap_rsne_override_2_len) != 0))) {
+			wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
+				"RSN: RSNE Override 2 element mismatch between Beacon/ProbeResp and EAPOL-Key msg 3/4");
+			wpa_hexdump(MSG_INFO,
+				    "RSNE Override 2 element in Beacon/ProbeResp",
+				    sm->ap_rsne_override_2,
+				    sm->ap_rsne_override_2_len);
+			wpa_hexdump(MSG_INFO,
+				    "RSNE Override 2 element in EAPOL-Key msg 3/4",
+				    ie->rsne_override_2, ie->rsne_override_2_len);
+			wpa_sm_deauthenticate(sm,
+					      WLAN_REASON_IE_IN_4WAY_DIFFERS);
+			return -1;
+		}
+
+		if ((sm->ap_rsnxe_override && !ie->rsnxe_override) ||
+		    (!sm->ap_rsnxe_override && ie->rsnxe_override) ||
+		    (sm->ap_rsnxe_override && ie->rsnxe_override &&
+		     (sm->ap_rsnxe_override_len != ie->rsnxe_override_len ||
+		      os_memcmp(sm->ap_rsnxe_override, ie->rsnxe_override,
+				sm->ap_rsnxe_override_len) != 0))) {
+			wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
+				"RSN: RSNXE Override element mismatch between Beacon/ProbeResp and EAPOL-Key msg 3/4");
+			wpa_hexdump(MSG_INFO,
+				    "RSNXE Override element in Beacon/ProbeResp",
+				    sm->ap_rsnxe_override,
+				    sm->ap_rsnxe_override_len);
+			wpa_hexdump(MSG_INFO,
+				    "RSNXE Override element in EAPOL-Key msg 3/4",
+				    ie->rsnxe_override, ie->rsnxe_override_len);
+			wpa_sm_deauthenticate(sm,
+					      WLAN_REASON_IE_IN_4WAY_DIFFERS);
+			return -1;
+		}
+	}
+
 #ifdef CONFIG_IEEE80211R
 	if (wpa_key_mgmt_ft(sm->key_mgmt) &&
 	    wpa_supplicant_validate_ie_ft(sm, src_addr, ie) < 0)
@@ -2340,10 +2437,14 @@ int wpa_supplicant_send_4_of_4(struct wpa_sm *sm, const unsigned char *dst,
 
 static int wpa_supplicant_validate_link_kde(struct wpa_sm *sm, u8 link_id,
 					    const u8 *link_kde,
-					    size_t link_kde_len)
+					    size_t link_kde_len,
+					    const u8 *rsn_override_link_kde,
+					    size_t rsn_override_link_kde_len)
 {
-	size_t rsne_len = 0, rsnxe_len = 0;
-	const u8 *rsne = NULL, *rsnxe = NULL;
+	size_t rsne_len = 0, rsnxe_len = 0, rsnoe_len = 0, rsno2e_len = 0,
+		rsnxoe_len = 0;
+	const u8 *rsne = NULL, *rsnxe = NULL, *rsnoe = NULL, *rsno2e = NULL,
+		*rsnxoe = NULL;
 
 	if (!link_kde ||
 	    link_kde_len < RSN_MLO_LINK_KDE_LINK_MAC_INDEX + ETH_ALEN) {
@@ -2404,14 +2505,14 @@ static int wpa_supplicant_validate_link_kde(struct wpa_sm *sm, u8 link_id,
 			       sm->mlo.links[link_id].ap_rsne_len,
 			       rsne, rsne_len)) {
 		wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
-			"RSN MLO: IE in 3/4 msg does not match with IE in Beacon/ProbeResp for link ID %u",
+			"RSN MLO: RSNE in 3/4 msg does not match with IE in Beacon/ProbeResp for link ID %u",
 			link_id);
 		wpa_hexdump(MSG_INFO, "RSNE in Beacon/ProbeResp",
 			    sm->mlo.links[link_id].ap_rsne,
 			    sm->mlo.links[link_id].ap_rsne_len);
 		wpa_hexdump(MSG_INFO, "RSNE in EAPOL-Key msg 3/4",
 			    rsne, rsne_len);
-		return -1;
+		goto fail;
 	}
 
 	if ((sm->mlo.links[link_id].ap_rsnxe && !rsnxe) ||
@@ -2428,11 +2529,89 @@ static int wpa_supplicant_validate_link_kde(struct wpa_sm *sm, u8 link_id,
 			    sm->mlo.links[link_id].ap_rsnxe_len);
 		wpa_hexdump(MSG_INFO, "RSNXE in EAPOL-Key msg 3/4",
 			    rsnxe, rsnxe_len);
-		wpa_sm_deauthenticate(sm, WLAN_REASON_IE_IN_4WAY_DIFFERS);
-		return -1;
+		goto fail;
+	}
+
+	if (!wpa_sm_rsn_overriding_supported(sm))
+		return 0;
+
+	if (rsn_override_link_kde) {
+		rsnoe = get_vendor_ie(rsn_override_link_kde + 1,
+				      rsn_override_link_kde_len - 1,
+				      RSNE_OVERRIDE_IE_VENDOR_TYPE);
+		if (rsnoe)
+			rsnoe_len = 2 + rsnoe[1];
+
+		rsno2e = get_vendor_ie(rsn_override_link_kde + 1,
+				       rsn_override_link_kde_len - 1,
+				       RSNE_OVERRIDE_2_IE_VENDOR_TYPE);
+		if (rsno2e)
+			rsno2e_len = 2 + rsno2e[1];
+
+		rsnxoe = get_vendor_ie(rsn_override_link_kde + 1,
+				       rsn_override_link_kde_len - 1,
+				       RSNXE_OVERRIDE_IE_VENDOR_TYPE);
+		if (rsnxoe)
+			rsnxoe_len = 2 + rsnxoe[1];
+	}
+
+	if ((sm->mlo.links[link_id].ap_rsnoe && !rsnoe) ||
+	    (!sm->mlo.links[link_id].ap_rsnoe && rsnoe) ||
+	    (sm->mlo.links[link_id].ap_rsnoe && rsnoe &&
+	     wpa_compare_rsn_ie(wpa_key_mgmt_ft(sm->key_mgmt),
+				sm->mlo.links[link_id].ap_rsnoe,
+				sm->mlo.links[link_id].ap_rsnoe_len,
+				rsnoe, rsnoe_len))) {
+		wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
+			"RSN MLO: RSNOE in 3/4 msg does not match with IE in Beacon/ProbeResp for link ID %u",
+			link_id);
+		wpa_hexdump(MSG_INFO, "RSNOE in Beacon/ProbeResp",
+			    sm->mlo.links[link_id].ap_rsnoe,
+			    sm->mlo.links[link_id].ap_rsnoe_len);
+		wpa_hexdump(MSG_INFO, "RSNOE in EAPOL-Key msg 3/4",
+			    rsnoe, rsnoe_len);
+		goto fail;
+	}
+
+	if ((sm->mlo.links[link_id].ap_rsno2e && !rsno2e) ||
+	    (!sm->mlo.links[link_id].ap_rsno2e && rsno2e) ||
+	    (sm->mlo.links[link_id].ap_rsno2e && rsno2e &&
+	     wpa_compare_rsn_ie(wpa_key_mgmt_ft(sm->key_mgmt),
+				sm->mlo.links[link_id].ap_rsno2e,
+				sm->mlo.links[link_id].ap_rsno2e_len,
+				rsno2e, rsno2e_len))) {
+		wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
+			"RSN MLO: RSNO2E in 3/4 msg does not match with IE in Beacon/ProbeResp for link ID %u",
+			link_id);
+		wpa_hexdump(MSG_INFO, "RSNO2E in Beacon/ProbeResp",
+			    sm->mlo.links[link_id].ap_rsno2e,
+			    sm->mlo.links[link_id].ap_rsno2e_len);
+		wpa_hexdump(MSG_INFO, "RSNOE in EAPOL-Key msg 3/4",
+			    rsno2e, rsno2e_len);
+		goto fail;
+	}
+
+	if ((sm->mlo.links[link_id].ap_rsnxoe && !rsnxoe) ||
+	    (!sm->mlo.links[link_id].ap_rsnxoe && rsnxoe) ||
+	    (sm->mlo.links[link_id].ap_rsnxoe && rsnxoe &&
+	     (sm->mlo.links[link_id].ap_rsnxoe_len != rsnxoe_len ||
+	      os_memcmp(sm->mlo.links[link_id].ap_rsnxoe, rsnxoe,
+			sm->mlo.links[link_id].ap_rsnxoe_len) != 0))) {
+		wpa_msg(sm->ctx->msg_ctx, MSG_INFO,
+			"RSN MLO: RSNXOE mismatch between Beacon/ProbeResp and EAPOL-Key msg 3/4 for link ID %u",
+			link_id);
+		wpa_hexdump(MSG_INFO, "RSNXOE in Beacon/ProbeResp",
+			    sm->mlo.links[link_id].ap_rsnxoe,
+			    sm->mlo.links[link_id].ap_rsnxoe_len);
+		wpa_hexdump(MSG_INFO, "RSNXOE in EAPOL-Key msg 3/4",
+			    rsnxoe, rsnxoe_len);
+		goto fail;
 	}
 
 	return 0;
+fail:
+	wpa_sm_deauthenticate(sm, WLAN_REASON_IE_IN_4WAY_DIFFERS);
+	return -1;
 }
 
 
@@ -2600,8 +2779,10 @@ static void wpa_supplicant_process_3_of_4(struct wpa_sm *sm,
 		if (!(sm->mlo.req_links & BIT(i)))
 			continue;
 
-		if (wpa_supplicant_validate_link_kde(sm, i, ie.mlo_link[i],
-						     ie.mlo_link_len[i]) < 0)
+		if (wpa_supplicant_validate_link_kde(
+			    sm, i, ie.mlo_link[i], ie.mlo_link_len[i],
+			    ie.rsn_override_link[i],
+			    ie.rsn_override_link_len[i]) < 0)
 			goto failed;
 
 		if (!(sm->mlo.valid_links & BIT(i)))
@@ -4174,9 +4355,15 @@ void wpa_sm_deinit(struct wpa_sm *sm)
 	os_free(sm->ap_wpa_ie);
 	os_free(sm->ap_rsn_ie);
 	os_free(sm->ap_rsnxe);
+	os_free(sm->ap_rsne_override);
+	os_free(sm->ap_rsne_override_2);
+	os_free(sm->ap_rsnxe_override);
 	for (i = 0; i < MAX_NUM_MLD_LINKS; i++) {
 		os_free(sm->mlo.links[i].ap_rsne);
 		os_free(sm->mlo.links[i].ap_rsnxe);
+		os_free(sm->mlo.links[i].ap_rsnoe);
+		os_free(sm->mlo.links[i].ap_rsno2e);
+		os_free(sm->mlo.links[i].ap_rsnxoe);
 	}
 	wpa_sm_drop_sa(sm);
 	os_free(sm->ctx);
@@ -4551,27 +4738,12 @@ int wpa_sm_set_mlo_params(struct wpa_sm *sm, const struct wpa_sm_mlo *mlo)
 		} else {
 			wpa_hexdump_link(MSG_DEBUG, i, "RSN: Set AP RSNE",
 					 ie, len);
-			if (ie[0] == WLAN_EID_VENDOR_SPECIFIC && len > 2 + 4) {
-				sm->mlo.links[i].ap_rsne = os_malloc(len - 4);
-				if (!sm->mlo.links[i].ap_rsne)
-					return -1;
-				sm->mlo.links[i].ap_rsne[0] = WLAN_EID_RSN;
-				sm->mlo.links[i].ap_rsne[1] = len - 2 - 4;
-				os_memcpy(&sm->mlo.links[i].ap_rsne[2],
-					  ie + 2 + 4, len - 2 - 4);
-				sm->mlo.links[i].ap_rsne_len = len - 4;
-				wpa_hexdump(MSG_DEBUG,
-					    "RSN: Converted RSNE override to RSNE",
-					    sm->mlo.links[i].ap_rsne,
-					    sm->mlo.links[i].ap_rsne_len);
-			} else {
-				sm->mlo.links[i].ap_rsne = os_memdup(ie, len);
-				if (!sm->mlo.links[i].ap_rsne) {
-					sm->mlo.links[i].ap_rsne_len = 0;
-					return -1;
-				}
-				sm->mlo.links[i].ap_rsne_len = len;
+			sm->mlo.links[i].ap_rsne = os_memdup(ie, len);
+			if (!sm->mlo.links[i].ap_rsne) {
+				sm->mlo.links[i].ap_rsne_len = 0;
+				return -1;
 			}
+			sm->mlo.links[i].ap_rsne_len = len;
 		}
 
 		ie = mlo->links[i].ap_rsnxe;
@@ -4587,27 +4759,75 @@ int wpa_sm_set_mlo_params(struct wpa_sm *sm, const struct wpa_sm_mlo *mlo)
 		} else {
 			wpa_hexdump_link(MSG_DEBUG, i, "RSN: Set AP RSNXE", ie,
 					 len);
-			if (ie[0] == WLAN_EID_VENDOR_SPECIFIC && len > 2 + 4) {
-				sm->mlo.links[i].ap_rsnxe = os_malloc(len - 4);
-				if (!sm->mlo.links[i].ap_rsnxe)
-					return -1;
-				sm->mlo.links[i].ap_rsnxe[0] = WLAN_EID_RSNX;
-				sm->mlo.links[i].ap_rsnxe[1] = len - 2 - 4;
-				os_memcpy(&sm->mlo.links[i].ap_rsnxe[2],
-					  ie + 2 + 4, len - 2 - 4);
-				sm->mlo.links[i].ap_rsnxe_len = len - 4;
-				wpa_hexdump(MSG_DEBUG,
-					    "RSN: Converted RSNXE override to RSNXE",
-					    sm->mlo.links[i].ap_rsnxe,
-					    sm->mlo.links[i].ap_rsnxe_len);
-			} else {
-				sm->mlo.links[i].ap_rsnxe = os_memdup(ie, len);
-				if (!sm->mlo.links[i].ap_rsnxe) {
-					sm->mlo.links[i].ap_rsnxe_len = 0;
-					return -1;
-				}
-				sm->mlo.links[i].ap_rsnxe_len = len;
+			sm->mlo.links[i].ap_rsnxe = os_memdup(ie, len);
+			if (!sm->mlo.links[i].ap_rsnxe) {
+				sm->mlo.links[i].ap_rsnxe_len = 0;
+				return -1;
+			}
+			sm->mlo.links[i].ap_rsnxe_len = len;
+		}
+
+		ie = mlo->links[i].ap_rsnoe;
+		len = mlo->links[i].ap_rsnoe_len;
+		os_free(sm->mlo.links[i].ap_rsnoe);
+		if (!ie || len == 0) {
+			if (sm->mlo.links[i].ap_rsnoe)
+				wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
+					"RSN: Clearing MLO link[%u] AP RSNOE",
+					i);
+			sm->mlo.links[i].ap_rsnoe = NULL;
+			sm->mlo.links[i].ap_rsnoe_len = 0;
+		} else {
+			wpa_hexdump_link(MSG_DEBUG, i, "RSN: Set AP RSNOE",
+					 ie, len);
+			sm->mlo.links[i].ap_rsnoe = os_memdup(ie, len);
+			if (!sm->mlo.links[i].ap_rsnoe) {
+				sm->mlo.links[i].ap_rsnoe_len = 0;
+				return -1;
+			}
+			sm->mlo.links[i].ap_rsnoe_len = len;
+		}
+
+		ie = mlo->links[i].ap_rsno2e;
+		len = mlo->links[i].ap_rsno2e_len;
+		os_free(sm->mlo.links[i].ap_rsno2e);
+		if (!ie || len == 0) {
+			if (sm->mlo.links[i].ap_rsno2e)
+				wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
+					"RSN: Clearing MLO link[%u] AP RSNO2E",
+					i);
+			sm->mlo.links[i].ap_rsno2e = NULL;
+			sm->mlo.links[i].ap_rsno2e_len = 0;
+		} else {
+			wpa_hexdump_link(MSG_DEBUG, i, "RSN: Set AP RSNO2E",
+					 ie, len);
+			sm->mlo.links[i].ap_rsno2e = os_memdup(ie, len);
+			if (!sm->mlo.links[i].ap_rsno2e) {
+				sm->mlo.links[i].ap_rsno2e_len = 0;
+				return -1;
 			}
+			sm->mlo.links[i].ap_rsno2e_len = len;
+		}
+
+		ie = mlo->links[i].ap_rsnxoe;
+		len = mlo->links[i].ap_rsnxoe_len;
+		os_free(sm->mlo.links[i].ap_rsnxoe);
+		if (!ie || len == 0) {
+			if (sm->mlo.links[i].ap_rsnxoe)
+				wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
+					"RSN: Clearing MLO link[%u] AP RSNXOE",
+					i);
+			sm->mlo.links[i].ap_rsnxoe = NULL;
+			sm->mlo.links[i].ap_rsnxoe_len = 0;
+		} else {
+			wpa_hexdump_link(MSG_DEBUG, i, "RSN: Set AP RSNXOE",
+					 ie, len);
+			sm->mlo.links[i].ap_rsnxoe = os_memdup(ie, len);
+			if (!sm->mlo.links[i].ap_rsnxoe) {
+				sm->mlo.links[i].ap_rsnxoe_len = 0;
+				return -1;
+			}
+			sm->mlo.links[i].ap_rsnxoe_len = len;
 		}
 	}
 
@@ -4768,6 +4988,12 @@ int wpa_sm_set_param(struct wpa_sm *sm, enum wpa_sm_conf_params param,
 	case WPA_PARAM_SSID_PROTECTION:
 		sm->ssid_protection = value;
 		break;
+	case WPA_PARAM_RSN_OVERRIDE:
+		sm->rsn_override = value;
+		break;
+	case WPA_PARAM_RSN_OVERRIDE_SUPPORT:
+		sm->rsn_override_support = value;
+		break;
 	default:
 		break;
 	}
@@ -4776,6 +5002,23 @@ int wpa_sm_set_param(struct wpa_sm *sm, enum wpa_sm_conf_params param,
 }
 
 
+static const u8 * wpa_sm_get_ap_rsne(struct wpa_sm *sm, size_t *len)
+{
+	if (sm->rsn_override == RSN_OVERRIDE_RSNE_OVERRIDE) {
+		*len = sm->ap_rsne_override_len;
+		return sm->ap_rsne_override;
+	}
+
+	if (sm->rsn_override == RSN_OVERRIDE_RSNE_OVERRIDE_2) {
+		*len = sm->ap_rsne_override_2_len;
+		return sm->ap_rsne_override_2;
+	}
+
+	*len = sm->ap_rsn_ie_len;
+	return sm->ap_rsn_ie;
+}
+
+
 /**
  * wpa_sm_get_status - Get WPA state machine
  * @sm: Pointer to WPA state machine data from wpa_sm_init()
@@ -4793,6 +5036,10 @@ int wpa_sm_get_status(struct wpa_sm *sm, char *buf, size_t buflen,
 {
 	char *pos = buf, *end = buf + buflen;
 	int ret;
+	const u8 *rsne;
+	size_t rsne_len;
+
+	rsne = wpa_sm_get_ap_rsne(sm, &rsne_len);
 
 	ret = os_snprintf(pos, end - pos,
 			  "pairwise_cipher=%s\n"
@@ -4814,10 +5061,10 @@ int wpa_sm_get_status(struct wpa_sm *sm, char *buf, size_t buflen,
 	}
 #endif /* CONFIG_DPP2 */
 
-	if (sm->mfp != NO_MGMT_FRAME_PROTECTION && sm->ap_rsn_ie) {
+	if (sm->mfp != NO_MGMT_FRAME_PROTECTION && rsne) {
 		struct wpa_ie_data rsn;
-		if (wpa_parse_wpa_ie_rsn(sm->ap_rsn_ie, sm->ap_rsn_ie_len, &rsn)
-		    >= 0 &&
+
+		if (wpa_parse_wpa_ie_rsn(rsne, rsne_len, &rsn) >= 0 &&
 		    rsn.capabilities & (WPA_CAPABILITY_MFPR |
 					WPA_CAPABILITY_MFPC)) {
 			ret = os_snprintf(pos, end - pos, "pmf=%d\n"
@@ -4839,11 +5086,15 @@ int wpa_sm_get_status(struct wpa_sm *sm, char *buf, size_t buflen,
 int wpa_sm_pmf_enabled(struct wpa_sm *sm)
 {
 	struct wpa_ie_data rsn;
+	const u8 *rsne;
+	size_t rsne_len;
+
+	rsne = wpa_sm_get_ap_rsne(sm, &rsne_len);
 
-	if (sm->mfp == NO_MGMT_FRAME_PROTECTION || !sm->ap_rsn_ie)
+	if (sm->mfp == NO_MGMT_FRAME_PROTECTION || !rsne)
 		return 0;
 
-	if (wpa_parse_wpa_ie_rsn(sm->ap_rsn_ie, sm->ap_rsn_ie_len, &rsn) >= 0 &&
+	if (wpa_parse_wpa_ie_rsn(rsne, rsne_len, &rsn) >= 0 &&
 	    rsn.capabilities & (WPA_CAPABILITY_MFPR | WPA_CAPABILITY_MFPC))
 		return 1;
 
@@ -4851,6 +5102,17 @@ int wpa_sm_pmf_enabled(struct wpa_sm *sm)
 }
 
 
+bool wpa_sm_rsn_overriding_supported(struct wpa_sm *sm)
+{
+	const u8 *rsne;
+	size_t rsne_len;
+
+	rsne = wpa_sm_get_ap_rsne(sm, &rsne_len);
+
+	return sm->rsn_override_support && rsne;
+}
+
+
 int wpa_sm_ext_key_id(struct wpa_sm *sm)
 {
 	return sm ? sm->ext_key_id : 0;
@@ -4866,12 +5128,14 @@ int wpa_sm_ext_key_id_active(struct wpa_sm *sm)
 int wpa_sm_ocv_enabled(struct wpa_sm *sm)
 {
 	struct wpa_ie_data rsn;
+	const u8 *rsne;
+	size_t rsne_len;
 
-	if (!sm->ocv || !sm->ap_rsn_ie)
+	rsne = wpa_sm_get_ap_rsne(sm, &rsne_len);
+	if (!sm->ocv || !rsne)
 		return 0;
 
-	return wpa_parse_wpa_ie_rsn(sm->ap_rsn_ie, sm->ap_rsn_ie_len,
-				    &rsn) >= 0 &&
+	return wpa_parse_wpa_ie_rsn(rsne, rsne_len, &rsn) >= 0 &&
 		(rsn.capabilities & WPA_CAPABILITY_OCVC);
 }
 
@@ -5108,24 +5372,11 @@ int wpa_sm_set_ap_rsn_ie(struct wpa_sm *sm, const u8 *ie, size_t len)
 		sm->ap_rsn_ie_len = 0;
 	} else {
 		wpa_hexdump(MSG_DEBUG, "WPA: set AP RSN IE", ie, len);
-		if (ie[0] == WLAN_EID_VENDOR_SPECIFIC && len > 2 + 4) {
-			sm->ap_rsn_ie = os_malloc(len - 4);
-			if (!sm->ap_rsn_ie)
-				return -1;
-			sm->ap_rsn_ie[0] = WLAN_EID_RSN;
-			sm->ap_rsn_ie[1] = len - 2 - 4;
-			os_memcpy(&sm->ap_rsn_ie[2], ie + 2 + 4, len - 2 - 4);
-			sm->ap_rsn_ie_len = len - 4;
-			wpa_hexdump(MSG_DEBUG,
-				    "RSN: Converted RSNE override to RSNE",
-				    sm->ap_rsn_ie, sm->ap_rsn_ie_len);
-		} else {
-			sm->ap_rsn_ie = os_memdup(ie, len);
-			if (sm->ap_rsn_ie == NULL)
-				return -1;
+		sm->ap_rsn_ie = os_memdup(ie, len);
+		if (sm->ap_rsn_ie == NULL)
+			return -1;
 
-			sm->ap_rsn_ie_len = len;
-		}
+		sm->ap_rsn_ie_len = len;
 	}
 
 	return 0;
@@ -5154,24 +5405,86 @@ int wpa_sm_set_ap_rsnxe(struct wpa_sm *sm, const u8 *ie, size_t len)
 		sm->ap_rsnxe_len = 0;
 	} else {
 		wpa_hexdump(MSG_DEBUG, "WPA: set AP RSNXE", ie, len);
-		if (ie[0] == WLAN_EID_VENDOR_SPECIFIC && len > 2 + 4) {
-			sm->ap_rsnxe = os_malloc(len - 4);
-			if (!sm->ap_rsnxe)
-				return -1;
-			sm->ap_rsnxe[0] = WLAN_EID_RSNX;
-			sm->ap_rsnxe[1] = len - 2 - 4;
-			os_memcpy(&sm->ap_rsnxe[2], ie + 2 + 4, len - 2 - 4);
-			sm->ap_rsnxe_len = len - 4;
-			wpa_hexdump(MSG_DEBUG,
-				    "RSN: Converted RSNXE override to RSNXE",
-				    sm->ap_rsnxe, sm->ap_rsnxe_len);
-		} else {
-			sm->ap_rsnxe = os_memdup(ie, len);
-			if (!sm->ap_rsnxe)
-				return -1;
+		sm->ap_rsnxe = os_memdup(ie, len);
+		if (!sm->ap_rsnxe)
+			return -1;
 
-			sm->ap_rsnxe_len = len;
-		}
+		sm->ap_rsnxe_len = len;
+	}
+
+	return 0;
+}
+
+
+int wpa_sm_set_ap_rsne_override(struct wpa_sm *sm, const u8 *ie, size_t len)
+{
+	if (!sm)
+		return -1;
+
+	os_free(sm->ap_rsne_override);
+	if (!ie || len == 0) {
+		wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
+			"RSN: Clearing AP RSNE Override element");
+		sm->ap_rsne_override = NULL;
+		sm->ap_rsne_override_len = 0;
+	} else {
+		wpa_hexdump(MSG_DEBUG, "RSN: Set AP RSNE Override element",
+			    ie, len);
+		sm->ap_rsne_override = os_memdup(ie, len);
+		if (!sm->ap_rsne_override)
+			return -1;
+
+		sm->ap_rsne_override_len = len;
+	}
+
+	return 0;
+}
+
+
+int wpa_sm_set_ap_rsne_override_2(struct wpa_sm *sm, const u8 *ie, size_t len)
+{
+	if (!sm)
+		return -1;
+
+	os_free(sm->ap_rsne_override_2);
+	if (!ie || len == 0) {
+		wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
+			"RSN: Clearing AP RSNE Override 2 element");
+		sm->ap_rsne_override_2 = NULL;
+		sm->ap_rsne_override_2_len = 0;
+	} else {
+		wpa_hexdump(MSG_DEBUG, "RSN: Set AP RSNE Override 2 element",
+			    ie, len);
+		sm->ap_rsne_override_2 = os_memdup(ie, len);
+		if (!sm->ap_rsne_override_2)
+			return -1;
+
+		sm->ap_rsne_override_2_len = len;
+	}
+
+	return 0;
+}
+
+
+int wpa_sm_set_ap_rsnxe_override(struct wpa_sm *sm, const u8 *ie, size_t len)
+{
+	if (!sm)
+		return -1;
+
+	os_free(sm->ap_rsnxe_override);
+	if (!ie || len == 0) {
+		wpa_dbg(sm->ctx->msg_ctx, MSG_DEBUG,
+			"RSN: Clearing AP RSNXE Override element");
+		sm->ap_rsnxe_override = NULL;
+		sm->ap_rsnxe_override_len = 0;
+	} else {
+		wpa_hexdump(MSG_DEBUG, "RSN: Set AP RSNXE Override element",
+			    ie, len);
+		sm->ap_rsnxe_override = os_memdup(ie, len);
+		if (!sm->ap_rsnxe_override)
+			return -1;
+
+		sm->ap_rsnxe_override_len = len;
 	}
 
 	return 0;
diff --git a/src/rsn_supp/wpa.h b/src/rsn_supp/wpa.h
index 231e0881..ca64d8fb 100644
--- a/src/rsn_supp/wpa.h
+++ b/src/rsn_supp/wpa.h
@@ -137,6 +137,15 @@ enum wpa_sm_conf_params {
 	WPA_PARAM_ENCRYPT_EAPOL_M4,
 	WPA_PARAM_FT_PREPEND_PMKID,
 	WPA_PARAM_SSID_PROTECTION,
+	WPA_PARAM_RSN_OVERRIDE,
+	WPA_PARAM_RSN_OVERRIDE_SUPPORT,
+};
+
+enum wpa_rsn_override {
+	RSN_OVERRIDE_NOT_USED,
+	RSN_OVERRIDE_RSNE,
+	RSN_OVERRIDE_RSNE_OVERRIDE,
+	RSN_OVERRIDE_RSNE_OVERRIDE_2,
 };
 
 struct rsn_supp_config {
@@ -160,8 +169,9 @@ struct rsn_supp_config {
 struct wpa_sm_link {
 	u8 addr[ETH_ALEN];
 	u8 bssid[ETH_ALEN];
-	u8 *ap_rsne, *ap_rsnxe;
-	size_t ap_rsne_len, ap_rsnxe_len;
+	u8 *ap_rsne, *ap_rsnxe, *ap_rsnoe, *ap_rsno2e, *ap_rsnxoe;
+	size_t ap_rsne_len, ap_rsnxe_len, ap_rsnoe_len, ap_rsno2e_len,
+		ap_rsnxoe_len;;
 	struct wpa_gtk gtk;
 	struct wpa_gtk gtk_wnm_sleep;
 	struct wpa_igtk igtk;
@@ -204,6 +214,9 @@ int wpa_sm_set_assoc_rsnxe(struct wpa_sm *sm, const u8 *ie, size_t len);
 int wpa_sm_set_ap_wpa_ie(struct wpa_sm *sm, const u8 *ie, size_t len);
 int wpa_sm_set_ap_rsn_ie(struct wpa_sm *sm, const u8 *ie, size_t len);
 int wpa_sm_set_ap_rsnxe(struct wpa_sm *sm, const u8 *ie, size_t len);
+int wpa_sm_set_ap_rsne_override(struct wpa_sm *sm, const u8 *ie, size_t len);
+int wpa_sm_set_ap_rsne_override_2(struct wpa_sm *sm, const u8 *ie, size_t len);
+int wpa_sm_set_ap_rsnxe_override(struct wpa_sm *sm, const u8 *ie, size_t len);
 int wpa_sm_get_mib(struct wpa_sm *sm, char *buf, size_t buflen);
 
 int wpa_sm_set_param(struct wpa_sm *sm, enum wpa_sm_conf_params param,
@@ -353,6 +366,24 @@ static inline int wpa_sm_set_ap_rsnxe(struct wpa_sm *sm, const u8 *ie,
 	return -1;
 }
 
+static inline int wpa_sm_set_ap_rsne_override(struct wpa_sm *sm, const u8 *ie,
+					      size_t len)
+{
+	return -1;
+}
+
+static inline int wpa_sm_set_ap_rsne_override_2(struct wpa_sm *sm, const u8 *ie,
+						size_t len)
+{
+	return -1;
+}
+
+static inline int wpa_sm_set_ap_rsnxe_override(struct wpa_sm *sm, const u8 *ie,
+					       size_t len)
+{
+	return -1;
+}
+
 static inline int wpa_sm_get_mib(struct wpa_sm *sm, char *buf, size_t buflen)
 {
 	return 0;
diff --git a/src/rsn_supp/wpa_i.h b/src/rsn_supp/wpa_i.h
index d7e78051..ef26b248 100644
--- a/src/rsn_supp/wpa_i.h
+++ b/src/rsn_supp/wpa_i.h
@@ -120,6 +120,9 @@ struct wpa_sm {
 	size_t assoc_rsnxe_len;
 	u8 *ap_wpa_ie, *ap_rsn_ie, *ap_rsnxe;
 	size_t ap_wpa_ie_len, ap_rsn_ie_len, ap_rsnxe_len;
+	u8 *ap_rsne_override, *ap_rsne_override_2, *ap_rsnxe_override;
+	size_t ap_rsne_override_len, ap_rsne_override_2_len,
+		ap_rsnxe_override_len;
 
 #ifdef CONFIG_TDLS
 	struct wpa_tdls_peer *tdls;
@@ -229,6 +232,9 @@ struct wpa_sm {
 	bool wmm_enabled;
 	bool driver_bss_selection;
 	bool ft_prepend_pmkid;
+
+	bool rsn_override_support;
+	enum wpa_rsn_override rsn_override;
 };
 
 
@@ -542,5 +548,6 @@ int wpa_derive_ptk_ft(struct wpa_sm *sm, const unsigned char *src_addr,
 
 void wpa_tdls_assoc(struct wpa_sm *sm);
 void wpa_tdls_disassoc(struct wpa_sm *sm);
+bool wpa_sm_rsn_overriding_supported(struct wpa_sm *sm);
 
 #endif /* WPA_I_H */
diff --git a/wpa_supplicant/Android.bp b/wpa_supplicant/Android.bp
index 8c50031f..5361289c 100644
--- a/wpa_supplicant/Android.bp
+++ b/wpa_supplicant/Android.bp
@@ -57,6 +57,31 @@ cc_library_headers {
     soc_specific: true,
 }
 
+cc_library_headers {
+    name: "wpa_supplicant_headers_mainline",
+    export_include_dirs: [
+        ".",
+        "src",
+        "src/common",
+        "src/drivers",
+        "src/eap_common",
+        "src/eapol_supp",
+        "src/eap_peer",
+        "src/eap_server",
+        "src/l2_packet",
+        "src/radius",
+        "src/rsn_supp",
+        "src/tls",
+        "src/utils",
+        "src/wps",
+    ],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.wifi",
+    ],
+    min_sdk_version: "30",
+}
+
 filegroup {
     name: "wpa_supplicant_template.conf",
     srcs: ["wpa_supplicant_template.conf"],
@@ -129,7 +154,6 @@ cc_defaults {
         "-DCONFIG_NO_RADIUS",
         "-DCONFIG_NO_RADIUS",
         "-DCONFIG_NO_RANDOM_POOL",
-        "-DCONFIG_NO_ROAMING",
         "-DCONFIG_NO_VLAN",
         "-DCONFIG_OFFCHANNEL",
         "-DCONFIG_OWE",
@@ -161,6 +185,7 @@ cc_defaults {
         "-DEAP_MSCHAPv2",
         "-DEAP_OTP",
         "-DEAP_PEAP",
+        "-DCONFIG_PTKSA_CACHE",
         "-DEAP_PWD",
         "-DEAP_SERVER",
         "-DEAP_SERVER_IDENTITY",
@@ -199,6 +224,21 @@ cc_defaults {
             any @ driver: ["-D" + driver],
             // Flag is optional, so no default value provided.
             default: [],
+        }) +
+        select(soong_config_variable("wpa_supplicant", "roaming"), {
+            true: [],
+            default: ["-DCONFIG_NO_ROAMING"],
+        }) +
+        select(soong_config_variable("wpa_supplicant", "pasn"), {
+            false: [],
+            default: ["-DCONFIG_PASN"],
+        }) +
+        select(soong_config_variable("wpa_supplicant", "bgscan_simple"), {
+            true: [
+                "-DCONFIG_BGSCAN",
+                "-DCONFIG_BGSCAN_SIMPLE",
+            ],
+            default: [],
         }),
     // Similar to suppressing clang compiler warnings, here we
     // suppress clang-tidy warnings to reduce noises in Android build.log.
@@ -264,7 +304,6 @@ filegroup {
         "src/ap/ap_drv_ops.c",
         "src/ap/ap_list.c",
         "src/ap/comeback_token.c",
-        "src/pasn/pasn_responder.c",
         "src/ap/ap_mlme.c",
         "src/ap/authsrv.c",
         "src/ap/beacon.c",
@@ -432,7 +471,24 @@ filegroup {
         "wpas_glue.c",
         "wpa_supplicant.c",
         "wps_supplicant.c",
-    ],
+    ] +
+        select(soong_config_variable("wpa_supplicant", "bgscan_simple"), {
+            true: [
+                "bgscan.c",
+                "bgscan_simple.c",
+            ],
+            default: [],
+        }) +
+        select(soong_config_variable("wpa_supplicant", "pasn"), {
+            false: [],
+            default: [
+                "pasn_supplicant.c",
+                "src/pasn/pasn_initiator.c",
+                "src/pasn/pasn_responder.c",
+                "src/pasn/pasn_common.c",
+            ],
+        }),
+
 }
 
 // Generated by building wpa_cli and printing LOCAL_SRC_FILES
@@ -467,3 +523,960 @@ cc_library_headers {
     ],
     soc_specific: true,
 }
+
+cc_library {
+    name: "libpasn",
+    vendor: true,
+    cflags: [
+        "-DANDROID_LOG_NAME=\"libpasn\"",
+        "-DANDROID_P2P",
+        "-DCONFIG_ACS",
+        "-DCONFIG_ANDROID_LOG",
+        "-DCONFIG_AP",
+        "-DCONFIG_BACKEND_FILE",
+        "-DCONFIG_CTRL_IFACE",
+        "-DCONFIG_CTRL_IFACE_CLIENT_DIR=\"/data/vendor/wifi/wpa/sockets\"",
+        "-DCONFIG_CTRL_IFACE_DIR=\"/data/vendor/wifi/wpa/sockets\"",
+        "-DCONFIG_CTRL_IFACE_AIDL",
+        "-DCONFIG_CTRL_IFACE_UNIX",
+        "-DCONFIG_DPP",
+        "-DCONFIG_DPP2",
+        "-DCONFIG_DRIVER_NL80211",
+        "-DCONFIG_ECC",
+        "-DCONFIG_ERP",
+        "-DCONFIG_FILS",
+        "-DCONFIG_GAS",
+        "-DCONFIG_GAS_SERVER",
+        "-DCONFIG_AIDL",
+        "-DCONFIG_HMAC_SHA256_KDF",
+        "-DCONFIG_HMAC_SHA384_KDF",
+        "-DCONFIG_HMAC_SHA512_KDF",
+        "-DCONFIG_HS20",
+        "-DCONFIG_IEEE80211AC",
+        "-DCONFIG_IEEE80211R",
+        "-DCONFIG_INTERWORKING",
+        "-DCONFIG_IPV6",
+        "-DCONFIG_JSON",
+        "-DCONFIG_MBO",
+        "-DCONFIG_NO_ACCOUNTING",
+        "-DCONFIG_NO_RADIUS",
+        "-DCONFIG_NO_RADIUS",
+        "-DCONFIG_NO_RANDOM_POOL",
+        "-DCONFIG_NO_ROAMING",
+        "-DCONFIG_NO_VLAN",
+        "-DCONFIG_OFFCHANNEL",
+        "-DCONFIG_OWE",
+        "-DCONFIG_P2P",
+        "-DCONFIG_SAE",
+        "-DCONFIG_SAE_PK",
+        "-DCONFIG_SHA256",
+        "-DCONFIG_SHA384",
+        "-DCONFIG_SHA512",
+        "-DCONFIG_SMARTCARD",
+        "-DCONFIG_SME",
+        "-DCONFIG_SUITEB",
+        "-DCONFIG_SUITEB192",
+        "-DCONFIG_TDLS",
+        "-DCONFIG_WEP",
+        "-DCONFIG_WIFI_DISPLAY",
+        "-DCONFIG_WNM",
+        "-DCONFIG_WPA_CLI_HISTORY_DIR=\"/data/vendor/wifi/wpa\"",
+        "-DCONFIG_WPS",
+        "-DCONFIG_WPS_ER",
+        "-DCONFIG_WPS_NFC",
+        "-DCONFIG_WPS_OOB",
+        "-DCONFIG_WPS_UPNP",
+        "-DEAP_AKA",
+        "-DEAP_AKA_PRIME",
+        "-DEAP_GTC",
+        "-DEAP_LEAP",
+        "-DEAP_MD5",
+        "-DEAP_MSCHAPv2",
+        "-DEAP_OTP",
+        "-DEAP_PEAP",
+        "-DCONFIG_PASN",
+        "-DCONFIG_PTKSA_CACHE",
+        "-DEAP_PWD",
+        "-DEAP_SERVER",
+        "-DEAP_SERVER_IDENTITY",
+        "-DEAP_SERVER_WSC",
+        "-DEAP_SIM",
+        "-DEAP_TLS",
+        "-DEAP_TLS_OPENSSL",
+        "-DEAP_TTLS",
+        "-DEAP_WSC",
+        "-DIEEE8021X_EAPOL",
+        "-DNEED_AP_MLME",
+        "-DPKCS12_FUNCS",
+        "-DTLS_DEFAULT_CIPHERS=\"DEFAULT:!EXP:!LOW\"",
+        "-DWPA_IGNORE_CONFIG_ERRORS",
+        "-Wall",
+        "-Werror",
+        "-Wno-error=sometimes-uninitialized",
+        "-Wno-incompatible-pointer-types",
+        "-Wno-incompatible-pointer-types-discards-qualifiers",
+        "-Wno-macro-redefined",
+        "-Wno-parentheses-equality",
+        "-Wno-sign-compare",
+        "-Wno-unused-function",
+        "-Wno-unused-parameter",
+        "-Wno-unused-variable",
+    ],
+    product_variables: {
+        debuggable: {
+            cflags: ["-DLOG_NDEBUG=0"],
+        },
+    },
+    local_include_dirs: [
+        ".",
+        "src",
+        "src/common",
+        "src/drivers",
+        "src/eap_common",
+        "src/eapol_supp",
+        "src/eap_peer",
+        "src/eap_server",
+        "src/l2_packet",
+        "src/radius",
+        "src/rsn_supp",
+        "src/tls",
+        "src/utils",
+        "src/wps",
+    ],
+    srcs: [
+        "src/utils/eloop.c",
+        "src/utils/wpa_debug.c",
+        "src/utils/wpabuf.c",
+        "src/utils/os_unix.c",
+        "src/utils/config.c",
+        "src/utils/common.c",
+        "src/utils/base64.c",
+        "src/common/sae.c",
+        "src/common/sae_pk.c",
+        "src/common/wpa_common.c",
+        "src/common/ieee802_11_common.c",
+        "src/common/dragonfly.c",
+        "src/common/ptksa_cache.c",
+        "src/rsn_supp/pmksa_cache.c",
+        "src/rsn_supp/wpa_ie.c",
+        "src/ap/comeback_token.c",
+        "src/ap/pmksa_cache_auth.c",
+        "src/eap_common/eap_common.c",
+        "src/eap_common/chap.c",
+        "src/eap_peer/eap.c",
+        "src/eap_peer/eap_methods.c",
+        "src/eapol_supp/eapol_supp_sm.c",
+        "src/crypto/crypto_openssl.c",
+        "src/crypto/tls_openssl.c",
+        "src/crypto/tls_openssl_ocsp.c",
+        "src/crypto/sha256-tlsprf.c",
+        "src/crypto/sha512-prf.c",
+        "src/crypto/sha384-prf.c",
+        "src/crypto/sha256-prf.c",
+        "src/crypto/sha512-kdf.c",
+        "src/crypto/sha384-kdf.c",
+        "src/crypto/sha256-kdf.c",
+        "src/crypto/dh_groups.c",
+        "src/crypto/aes-siv.c",
+        "src/crypto/aes-ctr.c",
+        "src/crypto/sha1-prf.c",
+        "src/crypto/sha1-tlsprf.c",
+        "src/pasn/pasn_initiator.c",
+        "src/pasn/pasn_responder.c",
+        "src/pasn/pasn_common.c",
+    ],
+    shared_libs: [
+        "libc",
+        "libcutils",
+        "liblog",
+        "libcrypto",
+        "libssl",
+        "libkeystore-engine-wifi-hidl",
+    ],
+    sanitize: {
+        misc_undefined: [
+            "unsigned-integer-overflow",
+            "signed-integer-overflow",
+        ],
+        cfi: true,
+    },
+}
+
+// For converting the default to soong
+cc_defaults {
+    name: "wpa_supplicant_driver_srcs_default",
+    srcs: [
+        "src/drivers/driver_nl80211.c",
+        "src/drivers/driver_nl80211_android.c",
+        "src/drivers/driver_nl80211_capa.c",
+        "src/drivers/driver_nl80211_event.c",
+        "src/drivers/driver_nl80211_monitor.c",
+        "src/drivers/driver_nl80211_scan.c",
+        "src/drivers/linux_ioctl.c",
+        "src/drivers/netlink.c",
+        "src/drivers/rfkill.c",
+        "src/utils/radiotap.c",
+    ],
+}
+
+cc_defaults {
+    name: "wpa_supplicant_driver_cflags_default",
+    cflags: [
+        "-DCONFIG_DRIVER_NL80211",
+        // Because the original Android.mk will call hostapd's Android.mk first and it
+        // will make the flag share with wpa_supplicant, keep the original logic in hostapd.
+    ] + select(soong_config_variable("wpa_supplicant_8", "board_wlan_device"), {
+        "bcmdhd": ["-DCONFIG_DRIVER_NL80211_BRCM"],
+        "synadhd": ["-DCONFIG_DRIVER_NL80211_SYNA"],
+        "qcwcn": ["-DCONFIG_DRIVER_NL80211_QCA"],
+        default: ["-DCONFIG_DRIVER_NL80211_QCA"],
+    }),
+}
+
+cc_defaults {
+    name: "wpa_supplicant_includes_default",
+    local_include_dirs: [
+        ".",
+        "src",
+        "src/common",
+        "src/drivers",
+        "src/eap_common",
+        "src/eap_peer",
+        "src/eap_server",
+        "src/eapol_supp",
+        "src/l2_packet",
+        "src/pasn",
+        "src/radius",
+        "src/rsn_supp",
+        "src/tls",
+        "src/utils",
+        "src/wps",
+    ],
+    include_dirs: [
+        // There's an if condition for external/libnl but current code base should always have this.
+        "external/libnl/include",
+        "system/security/keystore/include",
+    ],
+}
+
+soong_config_module_type {
+    name: "wpa_supplicant_cc_defaults_type",
+    module_type: "cc_defaults",
+    config_namespace: "wpa_supplicant_8",
+    value_variables: [
+        "platform_version",
+    ],
+    properties: ["cflags"],
+}
+
+// Hostap related module share the same CFLAGS
+wpa_supplicant_cc_defaults_type {
+    name: "wpa_supplicant_no_aidl_cflags_default",
+    cflags: [
+        "-DANDROID_LOG_NAME=\"wpa_supplicant\"",
+        "-DANDROID_P2P",
+        "-DCONFIG_ACS",
+        "-DCONFIG_ANDROID_LOG",
+        "-DCONFIG_AP",
+        "-DCONFIG_BACKEND_FILE",
+        "-DCONFIG_CTRL_IFACE",
+        "-DCONFIG_CTRL_IFACE_CLIENT_DIR=\"/data/vendor/wifi/wpa/sockets\"",
+        "-DCONFIG_CTRL_IFACE_DIR=\"/data/vendor/wifi/wpa/sockets\"",
+        "-DCONFIG_CTRL_IFACE_UNIX",
+        "-DCONFIG_DPP",
+        "-DCONFIG_DPP2",
+        "-DCONFIG_DRIVER_NL80211",
+        "-DCONFIG_DRIVER_NL80211_QCA",
+        "-DCONFIG_ECC",
+        "-DCONFIG_ERP",
+        "-DCONFIG_FILS",
+        "-DCONFIG_GAS",
+        "-DCONFIG_GAS_SERVER",
+        "-DCONFIG_HMAC_SHA256_KDF",
+        "-DCONFIG_HMAC_SHA384_KDF",
+        "-DCONFIG_HMAC_SHA512_KDF",
+        "-DCONFIG_HS20",
+        "-DCONFIG_IEEE80211AC",
+        "-DCONFIG_IEEE80211R",
+        "-DCONFIG_INTERWORKING",
+        "-DCONFIG_IPV6",
+        "-DCONFIG_JSON",
+        "-DCONFIG_MBO",
+        "-DCONFIG_NO_ACCOUNTING",
+        "-DCONFIG_NO_RADIUS",
+        "-DCONFIG_NO_RADIUS",
+        "-DCONFIG_NO_RANDOM_POOL",
+        "-DCONFIG_NO_ROAMING",
+        "-DCONFIG_NO_VLAN",
+        "-DCONFIG_OFFCHANNEL",
+        "-DCONFIG_OWE",
+        "-DCONFIG_P2P",
+        "-DCONFIG_PASN",
+        "-DCONFIG_PTKSA_CACHE",
+        "-DCONFIG_SAE",
+        "-DCONFIG_SAE_PK",
+        "-DCONFIG_SHA256",
+        "-DCONFIG_SHA384",
+        "-DCONFIG_SHA512",
+        "-DCONFIG_SMARTCARD",
+        "-DCONFIG_SME",
+        "-DCONFIG_SUITEB",
+        "-DCONFIG_SUITEB192",
+        "-DCONFIG_TDLS",
+        "-DCONFIG_WEP",
+        "-DCONFIG_WIFI_DISPLAY",
+        "-DCONFIG_WNM",
+        "-DCONFIG_WPA_CLI_HISTORY_DIR=\"/data/vendor/wifi/wpa\"",
+        "-DCONFIG_WPS",
+        "-DCONFIG_WPS_ER",
+        "-DCONFIG_WPS_NFC",
+        "-DCONFIG_WPS_OOB",
+        "-DCONFIG_WPS_UPNP",
+        "-DCRYPTO_RSA_OAEP_SHA256",
+        "-DEAP_AKA",
+        "-DEAP_AKA_PRIME",
+        "-DEAP_GTC",
+        "-DEAP_LEAP",
+        "-DEAP_MD5",
+        "-DEAP_MSCHAPv2",
+        "-DEAP_OTP",
+        "-DEAP_PEAP",
+        "-DEAP_PWD",
+        "-DEAP_SERVER",
+        "-DEAP_SERVER_IDENTITY",
+        "-DEAP_SERVER_WSC",
+        "-DEAP_SIM",
+        "-DEAP_TLS",
+        "-DEAP_TLSV1_3",
+        "-DEAP_TLS_OPENSSL",
+        "-DEAP_TTLS",
+        "-DEAP_WSC",
+        "-DIEEE8021X_EAPOL",
+        "-DNEED_AP_MLME",
+        "-DPKCS12_FUNCS",
+        "-DTLS_DEFAULT_CIPHERS=\"DEFAULT:!EXP:!LOW\"",
+        "-DWPA_IGNORE_CONFIG_ERRORS",
+        "-Wall",
+        "-Werror",
+        "-Wno-error=sometimes-uninitialized",
+        "-Wno-incompatible-pointer-types",
+        "-Wno-incompatible-pointer-types-discards-qualifiers",
+        "-Wno-macro-redefined",
+        "-Wno-parentheses-equality",
+        "-Wno-sign-compare",
+        "-Wno-unused-function",
+        "-Wno-unused-parameter",
+        "-Wno-unused-variable",
+    ] + select(soong_config_variable("wpa_supplicant_8", "wpa_supplicant_use_stub_lib"), {
+        true: ["-DANDROID_LIB_STUB"],
+        default: [],
+    }) + select(soong_config_variable("wpa_supplicant_8", "board_hostapd_config_80211w_mfp_optional"), {
+        true: ["-DENABLE_HOSTAPD_CONFIG_80211W_MFP_OPTIONAL"],
+        default: [],
+    }) + select(soong_config_variable("wpa_supplicant_8", "board_wpa_supplicant_private_lib_event"), {
+        true: ["-DANDROID_LIB_EVENT"],
+        default: [],
+    }) + select(soong_config_variable("wpa_supplicant_8", "wifi_priv_cmd_update_mbo_cell_status"), {
+        true: ["-DENABLE_PRIV_CMD_UPDATE_MBO_CELL_STATUS"],
+        default: [],
+    }) + select(soong_config_variable("wpa_supplicant_8", "hostapd_11ax"), {
+        true: ["-DCONFIG_IEEE80211AX"],
+        default: [],
+    }) + select(soong_config_variable("wpa_supplicant_8", "wifi_brcm_open_source_multi_akm"), {
+        true: ["-DWIFI_BRCM_OPEN_SOURCE_MULTI_AKM"],
+        default: [],
+    }),
+    arch: {
+        arm: {
+            cflags: [
+                "-mabi=aapcs-linux",
+            ],
+        },
+    },
+    defaults: [
+        "wpa_supplicant_driver_cflags_default",
+    ],
+    soong_config_variables: {
+        platform_version: {
+            cflags: ["-DVERSION_STR_POSTFIX=\"-%s\""],
+        },
+    },
+}
+
+cc_defaults {
+    name: "wpa_supplicant_cflags_default",
+    cflags: [
+        "-DCONFIG_AIDL",
+        "-DCONFIG_CTRL_IFACE_AIDL",
+    ],
+    defaults: [
+        "wpa_supplicant_no_aidl_cflags_default",
+    ],
+}
+
+wpa_supplicant_cc_defaults_type {
+    name: "wpa_supplicant_mainline_cflags_default",
+    cflags: [
+        "-DANDROID_LIB_STUB",
+        "-DANDROID_LOG_NAME=\"mainline_supplicant\"",
+        "-DCONFIG_ANDROID_LOG",
+        "-DCONFIG_BACKEND_FILE",
+        "-DCONFIG_CTRL_IFACE",
+        "-DCONFIG_CTRL_IFACE_UNIX",
+        "-DCONFIG_DRIVER_NL80211",
+        "-DCONFIG_NO_ACCOUNTING",
+        "-DCONFIG_NO_CONFIG_BLOBS",
+        "-DCONFIG_NO_CONFIG_WRITE",
+        "-DCONFIG_NO_RADIUS",
+        "-DCONFIG_NO_RANDOM_POOL",
+        "-DCONFIG_NO_ROAMING",
+        "-DCONFIG_NO_ROBUST_AV",
+        "-DCONFIG_NO_RRM",
+        "-DCONFIG_NO_SCAN_PROCESSING",
+        "-DCONFIG_NO_TKIP",
+        "-DCONFIG_NO_VLAN",
+        "-DCONFIG_NO_WMM_AC",
+        "-DCONFIG_NO_WPA",
+        "-DCONFIG_NO_WPA_PASSPHRASE",
+        "-DCONFIG_OFFCHANNEL",
+        "-DMAINLINE_SUPPLICANT",
+        "-DOPENSSL_NO_ENGINE",
+        "-DWPA_IGNORE_CONFIG_ERRORS",
+        "-Wall",
+        "-Werror",
+        "-Wno-error=sometimes-uninitialized",
+        "-Wno-incompatible-pointer-types",
+        "-Wno-incompatible-pointer-types-discards-qualifiers",
+        "-Wno-macro-redefined",
+        "-Wno-parentheses-equality",
+        "-Wno-sign-compare",
+        "-Wno-unused-function",
+        "-Wno-unused-parameter",
+        "-Wno-unused-variable",
+    ],
+}
+
+cc_defaults {
+    name: "wpa_supplicant_srcs_default",
+    srcs: [
+        "ap.c",
+        "bss.c",
+        "bssid_ignore.c",
+        "config.c",
+        "config_file.c",
+        "ctrl_iface.c",
+        "ctrl_iface_unix.c",
+        "dpp_supplicant.c",
+        "eap_register.c",
+        "events.c",
+        "gas_query.c",
+        "hs20_supplicant.c",
+        "interworking.c",
+        "main.c",
+        "mbo.c",
+        "notify.c",
+        "offchannel.c",
+        "op_classes.c",
+        "p2p_supplicant.c",
+        "p2p_supplicant_sd.c",
+        "pasn_supplicant.c",
+        "robust_av.c",
+        "rrm.c",
+        "scan.c",
+        "sme.c",
+        "twt.c",
+        "wifi_display.c",
+        "wmm_ac.c",
+        "wnm_sta.c",
+        "wpa_supplicant.c",
+        "wpas_glue.c",
+        "wps_supplicant.c",
+        "src/ap/acs.c",
+        "src/ap/ap_config.c",
+        "src/ap/ap_drv_ops.c",
+        "src/ap/ap_list.c",
+        "src/ap/ap_mlme.c",
+        "src/ap/authsrv.c",
+        "src/ap/beacon.c",
+        "src/ap/bss_load.c",
+        "src/ap/comeback_token.c",
+        "src/ap/ctrl_iface_ap.c",
+        "src/ap/dfs.c",
+        "src/ap/dpp_hostapd.c",
+        "src/ap/drv_callbacks.c",
+        "src/ap/eap_user_db.c",
+        "src/ap/fils_hlp.c",
+        "src/ap/gas_query_ap.c",
+        "src/ap/gas_serv.c",
+        "src/ap/hostapd.c",
+        "src/ap/hs20.c",
+        "src/ap/hw_features.c",
+        "src/ap/ieee802_11.c",
+        "src/ap/ieee802_11_auth.c",
+        "src/ap/ieee802_11_ht.c",
+        "src/ap/ieee802_11_shared.c",
+        "src/ap/ieee802_11_vht.c",
+        "src/ap/ieee802_1x.c",
+        "src/ap/mbo_ap.c",
+        "src/ap/neighbor_db.c",
+        "src/ap/p2p_hostapd.c",
+        "src/ap/pmksa_cache_auth.c",
+        "src/ap/rrm.c",
+        "src/ap/sta_info.c",
+        "src/ap/tkip_countermeasures.c",
+        "src/ap/utils.c",
+        "src/ap/wmm.c",
+        "src/ap/wpa_auth.c",
+        "src/ap/wpa_auth_glue.c",
+        "src/ap/wpa_auth_ie.c",
+        "src/ap/wps_hostapd.c",
+        "src/common/ctrl_iface_common.c",
+        "src/common/dpp.c",
+        "src/common/dpp_auth.c",
+        "src/common/dpp_backup.c",
+        "src/common/dpp_crypto.c",
+        "src/common/dpp_pkex.c",
+        "src/common/dpp_reconfig.c",
+        "src/common/dpp_tcp.c",
+        "src/common/dragonfly.c",
+        "src/common/gas.c",
+        "src/common/gas_server.c",
+        "src/common/hw_features_common.c",
+        "src/common/ieee802_11_common.c",
+        "src/common/ptksa_cache.c",
+        "src/common/sae.c",
+        "src/common/sae_pk.c",
+        "src/common/wpa_common.c",
+        "src/crypto/aes-ctr.c",
+        "src/crypto/aes-siv.c",
+        "src/crypto/crypto_openssl.c",
+        "src/crypto/dh_groups.c",
+        "src/crypto/fips_prf_openssl.c",
+        "src/crypto/ms_funcs.c",
+        "src/crypto/sha1-prf.c",
+        "src/crypto/sha1-tlsprf.c",
+        "src/crypto/sha256-kdf.c",
+        "src/crypto/sha256-prf.c",
+        "src/crypto/sha256-tlsprf.c",
+        "src/crypto/sha384-kdf.c",
+        "src/crypto/sha384-prf.c",
+        "src/crypto/sha512-kdf.c",
+        "src/crypto/sha512-prf.c",
+        "src/crypto/tls_openssl.c",
+        "src/crypto/tls_openssl_ocsp.c",
+        "src/drivers/driver_common.c",
+        "src/drivers/driver_nl80211.c",
+        "src/drivers/driver_nl80211_android.c",
+        "src/drivers/driver_nl80211_capa.c",
+        "src/drivers/driver_nl80211_event.c",
+        "src/drivers/driver_nl80211_monitor.c",
+        "src/drivers/driver_nl80211_scan.c",
+        "src/drivers/drivers.c",
+        "src/drivers/linux_ioctl.c",
+        "src/drivers/netlink.c",
+        "src/drivers/rfkill.c",
+        "src/eap_common/chap.c",
+        "src/eap_common/eap_common.c",
+        "src/eap_common/eap_peap_common.c",
+        "src/eap_common/eap_pwd_common.c",
+        "src/eap_common/eap_sim_common.c",
+        "src/eap_common/eap_wsc_common.c",
+        "src/eap_peer/eap.c",
+        "src/eap_peer/eap_aka.c",
+        "src/eap_peer/eap_gtc.c",
+        "src/eap_peer/eap_leap.c",
+        "src/eap_peer/eap_md5.c",
+        "src/eap_peer/eap_methods.c",
+        "src/eap_peer/eap_mschapv2.c",
+        "src/eap_peer/eap_otp.c",
+        "src/eap_peer/eap_peap.c",
+        "src/eap_peer/eap_pwd.c",
+        "src/eap_peer/eap_sim.c",
+        "src/eap_peer/eap_tls.c",
+        "src/eap_peer/eap_tls_common.c",
+        "src/eap_peer/eap_ttls.c",
+        "src/eap_peer/eap_wsc.c",
+        "src/eap_peer/mschapv2.c",
+        "src/eap_server/eap_server.c",
+        "src/eap_server/eap_server_identity.c",
+        "src/eap_server/eap_server_methods.c",
+        "src/eap_server/eap_server_wsc.c",
+        "src/eapol_auth/eapol_auth_sm.c",
+        "src/eapol_supp/eapol_supp_sm.c",
+        "src/l2_packet/l2_packet_linux.c",
+        "src/p2p/p2p.c",
+        "src/p2p/p2p_build.c",
+        "src/p2p/p2p_dev_disc.c",
+        "src/p2p/p2p_go_neg.c",
+        "src/p2p/p2p_group.c",
+        "src/p2p/p2p_invitation.c",
+        "src/p2p/p2p_parse.c",
+        "src/p2p/p2p_pd.c",
+        "src/p2p/p2p_sd.c",
+        "src/p2p/p2p_utils.c",
+        "src/pasn/pasn_common.c",
+        "src/pasn/pasn_initiator.c",
+        "src/pasn/pasn_responder.c",
+        "src/rsn_supp/pmksa_cache.c",
+        "src/rsn_supp/preauth.c",
+        "src/rsn_supp/tdls.c",
+        "src/rsn_supp/wpa.c",
+        "src/rsn_supp/wpa_ft.c",
+        "src/rsn_supp/wpa_ie.c",
+        "src/tls/asn1.c",
+        "src/utils/base64.c",
+        "src/utils/bitfield.c",
+        "src/utils/common.c",
+        "src/utils/config.c",
+        "src/utils/crc32.c",
+        "src/utils/eloop.c",
+        "src/utils/ip_addr.c",
+        "src/utils/json.c",
+        "src/utils/os_unix.c",
+        "src/utils/radiotap.c",
+        "src/utils/uuid.c",
+        "src/utils/wpa_debug.c",
+        "src/utils/wpabuf.c",
+        "src/wps/http_client.c",
+        "src/wps/http_server.c",
+        "src/wps/httpread.c",
+        "src/wps/ndef.c",
+        "src/wps/upnp_xml.c",
+        "src/wps/wps.c",
+        "src/wps/wps_attr_build.c",
+        "src/wps/wps_attr_parse.c",
+        "src/wps/wps_attr_process.c",
+        "src/wps/wps_common.c",
+        "src/wps/wps_dev_attr.c",
+        "src/wps/wps_enrollee.c",
+        "src/wps/wps_er.c",
+        "src/wps/wps_er_ssdp.c",
+        "src/wps/wps_registrar.c",
+        "src/wps/wps_upnp.c",
+        "src/wps/wps_upnp_ap.c",
+        "src/wps/wps_upnp_event.c",
+        "src/wps/wps_upnp_ssdp.c",
+        "src/wps/wps_upnp_web.c",
+    ] + select(soong_config_variable("wpa_supplicant_8", "hostapd_11ax"), {
+        true: ["src/ap/ieee802_11_he.c"],
+        default: [],
+    }),
+    defaults: [
+        "wpa_supplicant_driver_srcs_default",
+    ],
+}
+
+cc_defaults {
+    name: "wpa_supplicant_mainline_srcs_default",
+    srcs: [
+        "bss.c",
+        "bssid_ignore.c",
+        "config.c",
+        "config_file.c",
+        "ctrl_iface.c",
+        "ctrl_iface_unix.c",
+        "eap_register.c",
+        "events.c",
+        "main.c",
+        "notify.c",
+        "offchannel.c",
+        "op_classes.c",
+        "rrm.c",
+        "scan.c",
+        "wpa_supplicant.c",
+        "wpas_glue.c",
+        "src/common/ctrl_iface_common.c",
+        "src/common/hw_features_common.c",
+        "src/common/ieee802_11_common.c",
+        "src/common/ptksa_cache.c",
+        "src/common/wpa_common.c",
+        "src/crypto/crypto_openssl.c",
+        "src/crypto/tls_none.c",
+        "src/drivers/driver_common.c",
+        "src/drivers/driver_nl80211.c",
+        "src/drivers/driver_nl80211_android.c",
+        "src/drivers/driver_nl80211_capa.c",
+        "src/drivers/driver_nl80211_event.c",
+        "src/drivers/driver_nl80211_monitor.c",
+        "src/drivers/driver_nl80211_scan.c",
+        "src/drivers/drivers.c",
+        "src/drivers/linux_ioctl.c",
+        "src/drivers/netlink.c",
+        "src/drivers/rfkill.c",
+        "src/l2_packet/l2_packet_linux.c",
+        "src/rsn_supp/pmksa_cache.c",
+        "src/utils/base64.c",
+        "src/utils/bitfield.c",
+        "src/utils/common.c",
+        "src/utils/config.c",
+        "src/utils/crc32.c",
+        "src/utils/eloop.c",
+        "src/utils/ip_addr.c",
+        "src/utils/os_unix.c",
+        "src/utils/radiotap.c",
+        "src/utils/wpa_debug.c",
+        "src/utils/wpabuf.c",
+    ],
+    defaults: [
+        "wpa_supplicant_driver_srcs_default",
+    ],
+}
+
+cc_binary {
+    name: "wpa_cli",
+    proprietary: true,
+    srcs: [
+        "wpa_cli.c",
+        "src/common/cli.c",
+        "src/common/wpa_ctrl.c",
+        "src/utils/common.c",
+        "src/utils/edit.c",
+        "src/utils/eloop.c",
+        "src/utils/os_unix.c",
+        "src/utils/wpa_debug.c",
+    ],
+    shared_libs: [
+        "libcutils",
+        "liblog",
+    ],
+    defaults: [
+        "wpa_supplicant_cflags_default",
+        "wpa_supplicant_includes_default",
+    ],
+}
+
+soong_config_module_type {
+    name: "wpa_supplicant_cc_binary",
+    module_type: "cc_binary",
+    config_namespace: "wpa_supplicant_8",
+    value_variables: [
+        "board_wpa_supplicant_private_lib",
+    ],
+    bool_variables: [
+        "wifi_hidl_unified_supplicant_service_rc_entry",
+    ],
+    properties: [
+        "init_rc",
+        "static_libs",
+    ],
+}
+
+wpa_supplicant_cc_binary {
+    name: "wpa_supplicant",
+    proprietary: true,
+    relative_install_path: "hw",
+    // vintf_fragments: wpa_supplicant only
+    // vintf_fragments: ["aidl/android.hardware.wifi.supplicant.xml"],
+    required: [
+        "android.hardware.wifi.supplicant.xml",
+    ],
+    // wpa_supplicant only
+    static_libs: [
+        "libwpa_aidl",
+    ],
+    shared_libs: [
+        // Share between wpa_supplicant and wpa_supplicant_macsec
+        "libc",
+        "libcrypto",
+        "libcutils",
+        "libkeystore-engine-wifi-hidl",
+        "liblog",
+        "libnl",
+        "libssl",
+    ] + [
+        // wpa_supplicant only
+        "android.hardware.wifi.supplicant-V4-ndk",
+        "android.system.keystore2-V1-ndk",
+        "libbase",
+        "libbinder_ndk",
+        "libutils",
+    ],
+    defaults: [
+        "wpa_supplicant_srcs_default",
+        "wpa_supplicant_cflags_default",
+        "wpa_supplicant_includes_default",
+    ],
+    soong_config_variables: {
+        board_wpa_supplicant_private_lib: {
+            static_libs: ["%s"],
+        },
+        // init_rc: wpa_supplicant only
+        wifi_hidl_unified_supplicant_service_rc_entry: {
+            init_rc: ["aidl/vendor/android.hardware.wifi.supplicant-service.rc"],
+        },
+    },
+}
+
+wpa_supplicant_cc_binary {
+    name: "wpa_supplicant_macsec",
+    proprietary: true,
+    relative_install_path: "hw",
+    srcs: [
+        // wpa_supplicant_macsec only
+        ":wpa_supplicant_macsec_extra_driver_srcs",
+        "wpas_kay.c",
+        "src/ap/wpa_auth_kay.c",
+        "src/pae/ieee802_1x_cp.c",
+        "src/pae/ieee802_1x_kay.c",
+        "src/pae/ieee802_1x_key.c",
+        "src/pae/ieee802_1x_secy_ops.c",
+        "src/pae/aidl/aidl_psk.cpp",
+    ],
+    shared_libs: [
+        // Share between wpa_supplicant and wpa_supplicant_macsec
+        "libc",
+        "libcrypto",
+        "libcutils",
+        "libkeystore-engine-wifi-hidl",
+        "liblog",
+        "libnl",
+        "libssl",
+    ] + [
+        // wpa_supplicant_macsec only
+        "android.hardware.macsec-V1-ndk",
+        "libbinder_ndk",
+    ],
+    cflags: [
+        "-DCONFIG_AIDL_MACSEC_PSK_METHODS",
+        "-DCONFIG_DRIVER_MACSEC_LINUX",
+        "-DCONFIG_MACSEC",
+    ],
+    local_include_dirs: [
+        // wpa_supplicant_macsec only
+        "aidl",
+    ],
+    defaults: [
+        "wpa_supplicant_srcs_default",
+        "wpa_supplicant_includes_default",
+        "wpa_supplicant_no_aidl_cflags_default",
+    ],
+    soong_config_variables: {
+        board_wpa_supplicant_private_lib: {
+            static_libs: ["%s"],
+        },
+    },
+}
+
+wpa_supplicant_cc_binary {
+    name: "wpa_supplicant_mainline",
+    shared_libs: [
+        "android.system.wifi.mainline_supplicant-ndk",
+        "libbase",
+        "libbinder_ndk",
+        "libc",
+        "libcrypto",
+        "libcutils_sockets",
+        "liblog",
+        "libnl",
+        "libssl",
+    ],
+    static_libs: [
+        "mainline_supplicant_aidl_bp",
+    ],
+    defaults: [
+        "wpa_supplicant_mainline_srcs_default",
+        "wpa_supplicant_includes_default",
+        "wpa_supplicant_mainline_cflags_default",
+    ],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.wifi",
+    ],
+    min_sdk_version: "30",
+}
+
+cc_library_shared {
+    name: "libwpa_client",
+    proprietary: true,
+    srcs: [
+        "src/common/wpa_ctrl.c",
+        "src/utils/os_unix.c",
+    ],
+    shared_libs: [
+        "libc",
+        "libcutils",
+        "liblog",
+    ],
+    defaults: [
+        "wpa_supplicant_cflags_default",
+        "wpa_supplicant_includes_default",
+    ],
+}
+
+cc_fuzz {
+    name: "mainline_supplicant_service_fuzzer",
+    team: "trendy_team_fwk_wifi_hal",
+    srcs: [
+        "aidl/mainline/fuzzers/mainline_supplicant_service_fuzzer.cpp",
+    ],
+    defaults: [
+        "fuzzer_disable_leaks",
+        "service_fuzzer_defaults",
+        "wpa_supplicant_includes_default",
+        "wpa_supplicant_mainline_cflags_default",
+        "wpa_supplicant_mainline_srcs_default",
+    ],
+    shared_libs: [
+        "android.system.wifi.mainline_supplicant-ndk",
+        "libbase",
+        "libbinder_ndk",
+        "libc",
+        "libcrypto",
+        "libcutils_sockets",
+        "liblog",
+        "libnl",
+        "libssl",
+    ],
+    static_libs: [
+        "mainline_supplicant_aidl_bp",
+    ],
+    cflags: [
+        "-DSUPPLICANT_SERVICE_FUZZER",
+    ],
+    fuzz_config: {
+        triage_assignee: "android-wifi-team@google.com",
+    },
+    proto: {
+        type: "lite",
+        static: true,
+    },
+}
+
+//## Aidl service library ###
+//#######################
+cc_library_static {
+    name: "libwpa_aidl",
+    vendor: true,
+    cppflags: [
+        "-Wall",
+        "-Werror",
+        "-Wno-unused-parameter",
+        "-Wno-unused-private-field",
+        "-Wno-unused-variable",
+    ],
+    srcs: [
+        "aidl/vendor/aidl.cpp",
+        "aidl/vendor/aidl_manager.cpp",
+        "aidl/vendor/certificate_utils.cpp",
+        "aidl/vendor/iface_config_utils.cpp",
+        "aidl/vendor/p2p_iface.cpp",
+        "aidl/vendor/p2p_network.cpp",
+        "aidl/vendor/sta_iface.cpp",
+        "aidl/vendor/sta_network.cpp",
+        "aidl/vendor/supplicant.cpp",
+    ],
+    shared_libs: [
+        "android.hardware.wifi.supplicant-V4-ndk",
+        "android.system.keystore2-V1-ndk",
+        "libbinder_ndk",
+        "libbase",
+        "libutils",
+        "liblog",
+        "libssl",
+    ],
+    export_include_dirs: ["aidl"],
+    defaults: [
+        "wpa_supplicant_cflags_default",
+        "wpa_supplicant_includes_default",
+    ],
+}
diff --git a/wpa_supplicant/Android.mk b/wpa_supplicant/Android.mk
index f36b0744..581d9071 100644
--- a/wpa_supplicant/Android.mk
+++ b/wpa_supplicant/Android.mk
@@ -18,7 +18,11 @@ ifeq ($(BOARD_WLAN_DEVICE), qcwcn)
   CONFIG_DRIVER_NL80211_QCA=y
 endif
 
-include $(LOCAL_PATH)/android.config
+ifneq ($(SUPPLICANT_CUSTOM_DEF_CONFIG_FILE_PATH),)
+  include $(SUPPLICANT_CUSTOM_DEF_CONFIG_FILE_PATH)
+else
+  include $(LOCAL_PATH)/android.config
+endif
 
 # To ignore possible wrong network configurations
 L_CFLAGS = -DWPA_IGNORE_CONFIG_ERRORS
@@ -2117,21 +2121,3 @@ LOCAL_EXPORT_C_INCLUDE_DIRS := \
     $(LOCAL_PATH)/aidl
 include $(BUILD_STATIC_LIBRARY)
 endif # WPA_SUPPLICANT_USE_AIDL == y
-
-ifeq ($(CONFIG_PASN), y)
-include $(CLEAR_VARS)
-LOCAL_MODULE = libpasn
-LOCAL_LICENSE_KINDS := SPDX-license-identifier-BSD SPDX-license-identifier-BSD-3-Clause SPDX-license-identifier-ISC legacy_unencumbered
-LOCAL_LICENSE_CONDITIONS := notice unencumbered
-LOCAL_NOTICE_FILE := $(LOCAL_PATH)/../LICENSE
-LOCAL_VENDOR_MODULE := true
-LOCAL_CFLAGS = $(L_CFLAGS)
-LOCAL_SRC_FILES = $(PASNOBJS)
-LOCAL_C_INCLUDES = $(INCLUDES)
-LOCAL_SHARED_LIBRARIES := libc libcutils liblog
-ifeq ($(CONFIG_TLS), openssl)
-LOCAL_SHARED_LIBRARIES += libcrypto libssl libkeystore-wifi-hidl
-LOCAL_SHARED_LIBRARIES += libkeystore-engine-wifi-hidl
-endif
-include $(BUILD_SHARED_LIBRARY)
-endif # CONFIG_PASN == y
diff --git a/wpa_supplicant/aidl/mainline/Android.bp b/wpa_supplicant/aidl/mainline/Android.bp
new file mode 100644
index 00000000..a2f5370e
--- /dev/null
+++ b/wpa_supplicant/aidl/mainline/Android.bp
@@ -0,0 +1,67 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+cc_library_headers {
+    name: "mainline_supplicant_aidl_headers",
+    export_include_dirs: ["."],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.wifi",
+    ],
+    min_sdk_version: "30",
+}
+
+cc_library_static {
+    name: "mainline_supplicant_aidl_bp",
+    srcs: ["*.cpp"],
+    shared_libs: [
+        "android.system.wifi.mainline_supplicant-ndk",
+        "libbase",
+        "libbinder_ndk",
+    ],
+    cppflags: [
+        "-Wall",
+        "-Werror",
+        "-Wno-unused-parameter",
+        "-Wno-unused-private-field",
+        "-Wno-unused-variable",
+    ],
+    header_libs: [
+        // Shared headers with vendor supplicant
+        "libwpa_shared_aidl_headers_mainline",
+        // Mainline supplicant headers
+        "mainline_supplicant_aidl_headers",
+        // Core supplicant headers
+        "wpa_supplicant_headers_mainline",
+    ],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.wifi",
+    ],
+    min_sdk_version: "30",
+}
+
+prebuilt_etc {
+    name: "mainline_supplicant_rc",
+    src: "config/mainline_supplicant.rc",
+    filename: "mainline_supplicant.rc",
+    installable: false,
+}
+
+prebuilt_etc {
+    name: "mainline_supplicant_conf",
+    src: "config/mainline_supplicant.conf",
+    filename: "mainline_supplicant.conf",
+    installable: false,
+}
diff --git a/wpa_supplicant/aidl/mainline/config/mainline_supplicant.conf b/wpa_supplicant/aidl/mainline/config/mainline_supplicant.conf
new file mode 100644
index 00000000..57eb0598
--- /dev/null
+++ b/wpa_supplicant/aidl/mainline/config/mainline_supplicant.conf
@@ -0,0 +1,2 @@
+ctrl_interface=/data/misc/wifi/mainline_supplicant/sockets
+p2p_disabled=1
diff --git a/wpa_supplicant/aidl/mainline/config/mainline_supplicant.rc b/wpa_supplicant/aidl/mainline/config/mainline_supplicant.rc
new file mode 100644
index 00000000..8c436c60
--- /dev/null
+++ b/wpa_supplicant/aidl/mainline/config/mainline_supplicant.rc
@@ -0,0 +1,9 @@
+service wpa_supplicant_mainline /apex/com.android.wifi/bin/wpa_supplicant_mainline \
+    -O/data/misc/wifi/mainline_supplicant/sockets -dd \
+    -g@android:wpa_wlan0
+    interface aidl wifi_mainline_supplicant
+    class main
+    user root
+    socket wpa_wlan0 dgram 660 wifi wifi
+    disabled
+    oneshot
diff --git a/wpa_supplicant/aidl/mainline/fuzzers/mainline_supplicant_service_fuzzer.cpp b/wpa_supplicant/aidl/mainline/fuzzers/mainline_supplicant_service_fuzzer.cpp
new file mode 100644
index 00000000..23b16adc
--- /dev/null
+++ b/wpa_supplicant/aidl/mainline/fuzzers/mainline_supplicant_service_fuzzer.cpp
@@ -0,0 +1,46 @@
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
+#include <android/binder_interface_utils.h>
+#include <fuzzbinder/libbinder_ndk_driver.h>
+
+#include "aidl/mainline/mainline_supplicant.h"
+
+extern "C"
+{
+#include "utils/common.h"
+#include "utils/includes.h"
+#include "utils/wpa_debug.h"
+#include "wpa_supplicant_i.h"
+}
+
+using namespace android;
+using ndk::SharedRefBase;
+
+extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
+    struct wpa_params params;
+    os_memset(&params, 0, sizeof(params));
+    params.wpa_debug_level = MSG_INFO;
+
+    struct wpa_global *global = wpa_supplicant_init(&params);
+    if (global == NULL) {
+        return 1;
+    }
+
+    std::shared_ptr<MainlineSupplicant> service = SharedRefBase::make<MainlineSupplicant>(global);
+    fuzzService(service->asBinder().get(), FuzzedDataProvider(data, size));
+    return 0;
+}
diff --git a/wpa_supplicant/aidl/mainline/mainline_supplicant.cpp b/wpa_supplicant/aidl/mainline/mainline_supplicant.cpp
new file mode 100644
index 00000000..dd2babeb
--- /dev/null
+++ b/wpa_supplicant/aidl/mainline/mainline_supplicant.cpp
@@ -0,0 +1,85 @@
+/*
+ * WPA Supplicant - Mainline supplicant AIDL implementation
+ * Copyright (c) 2024, Google Inc. All rights reserved.
+ *
+ * This software may be distributed under the terms of the BSD license.
+ * See README for more details.
+ */
+
+#include "aidl/shared/shared_utils.h"
+#include "mainline_supplicant.h"
+#include "utils.h"
+
+using ::ndk::ScopedAStatus;
+
+const std::string kConfigFilePath = "/apex/com.android.wifi/etc/mainline_supplicant.conf";
+
+MainlineSupplicant::MainlineSupplicant(struct wpa_global* global) {
+    wpa_global_ = global;
+}
+
+ndk::ScopedAStatus MainlineSupplicant::addUsdInterface(const std::string& ifaceName) {
+    if (ifaceName.empty()) {
+        wpa_printf(MSG_ERROR, "Empty iface name provided");
+        return createStatus(SupplicantStatusCode::FAILURE_ARGS_INVALID);
+    }
+
+    if (active_usd_ifaces_.find(ifaceName) != active_usd_ifaces_.end()) {
+        wpa_printf(MSG_INFO, "Interface %s already exists", ifaceName.c_str());
+        return ndk::ScopedAStatus::ok();
+    }
+
+    if (ensureConfigFileExistsAtPath(kConfigFilePath) != 0) {
+        wpa_printf(MSG_ERROR, "Unable to find config file at %s", kConfigFilePath.c_str());
+        return createStatusWithMsg(
+            SupplicantStatusCode::FAILURE_UNKNOWN, "Config file does not exist");
+    }
+
+    struct wpa_interface iface_params = {};
+    iface_params.driver = kIfaceDriverName;
+    iface_params.ifname = ifaceName.c_str();
+    iface_params.confname = kConfigFilePath.c_str();
+
+    struct wpa_supplicant* wpa_s = wpa_supplicant_add_iface(wpa_global_, &iface_params, NULL);
+    if (!wpa_s) {
+        wpa_printf(MSG_ERROR, "Unable to add interface %s", ifaceName.c_str());
+        return createStatus(SupplicantStatusCode::FAILURE_UNKNOWN);
+    }
+
+    wpa_printf(MSG_INFO, "Interface %s was added successfully", ifaceName.c_str());
+    active_usd_ifaces_.insert(ifaceName);
+    return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus MainlineSupplicant::removeUsdInterface(const std::string& ifaceName) {
+    if (ifaceName.empty()) {
+        wpa_printf(MSG_ERROR, "Empty iface name provided");
+        return createStatus(SupplicantStatusCode::FAILURE_ARGS_INVALID);
+    }
+
+    if (active_usd_ifaces_.find(ifaceName) == active_usd_ifaces_.end()) {
+        wpa_printf(MSG_ERROR, "Interface %s does not exist", ifaceName.c_str());
+        return createStatus(SupplicantStatusCode::FAILURE_IFACE_UNKNOWN);
+    }
+
+    struct wpa_supplicant* wpa_s =
+        wpa_supplicant_get_iface(wpa_global_, ifaceName.c_str());
+    if (!wpa_s) {
+        wpa_printf(MSG_ERROR, "Interface %s does not exist", ifaceName.c_str());
+        return createStatus(SupplicantStatusCode::FAILURE_IFACE_UNKNOWN);
+    }
+    if (wpa_supplicant_remove_iface(wpa_global_, wpa_s, 0)) {
+        wpa_printf(MSG_ERROR, "Unable to remove interface %s", ifaceName.c_str());
+        return createStatus(SupplicantStatusCode::FAILURE_UNKNOWN);
+    }
+
+    wpa_printf(MSG_INFO, "Interface %s was removed successfully", ifaceName.c_str());
+    active_usd_ifaces_.erase(ifaceName);
+    return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus MainlineSupplicant::terminate() {
+    wpa_printf(MSG_INFO, "Terminating...");
+    wpa_supplicant_terminate_proc(wpa_global_);
+    return ndk::ScopedAStatus::ok();
+}
diff --git a/wpa_supplicant/aidl/mainline/mainline_supplicant.h b/wpa_supplicant/aidl/mainline/mainline_supplicant.h
new file mode 100644
index 00000000..38a355fb
--- /dev/null
+++ b/wpa_supplicant/aidl/mainline/mainline_supplicant.h
@@ -0,0 +1,43 @@
+/*
+ * WPA Supplicant - Mainline supplicant AIDL implementation
+ * Copyright (c) 2024, Google Inc. All rights reserved.
+ *
+ * This software may be distributed under the terms of the BSD license.
+ * See README for more details.
+ */
+
+#ifndef MAINLINE_SUPPLICANT_IMPL_H
+#define MAINLINE_SUPPLICANT_IMPL_H
+
+#include <set>
+
+#include <aidl/android/system/wifi/mainline_supplicant/BnMainlineSupplicant.h>
+#include <aidl/android/system/wifi/mainline_supplicant/SupplicantStatusCode.h>
+
+extern "C"
+{
+#include "utils/common.h"
+#include "utils/includes.h"
+#include "utils/wpa_debug.h"
+#include "wpa_supplicant_i.h"
+#include "scan.h"
+}
+
+using ::aidl::android::system::wifi::mainline_supplicant::BnMainlineSupplicant;
+using ::aidl::android::system::wifi::mainline_supplicant::SupplicantStatusCode;
+
+class MainlineSupplicant : public BnMainlineSupplicant {
+    public:
+        MainlineSupplicant(struct wpa_global* global);
+        ndk::ScopedAStatus addUsdInterface(const std::string& ifaceName);
+        ndk::ScopedAStatus removeUsdInterface(const std::string& ifaceName);
+        ndk::ScopedAStatus terminate();
+
+    private:
+        // Raw pointer to the global structure maintained by the core
+        struct wpa_global* wpa_global_;
+        // Names of all active USD interfaces
+        std::set<std::string> active_usd_ifaces_;
+};
+
+#endif  // MAINLINE_SUPPLICANT_IMPL_H
diff --git a/wpa_supplicant/aidl/mainline/service.cpp b/wpa_supplicant/aidl/mainline/service.cpp
new file mode 100644
index 00000000..da343eac
--- /dev/null
+++ b/wpa_supplicant/aidl/mainline/service.cpp
@@ -0,0 +1,91 @@
+/*
+ * WPA Supplicant - Mainline supplicant service
+ * Copyright (c) 2024, Google Inc. All rights reserved.
+ *
+ * This software may be distributed under the terms of the BSD license.
+ * See README for more details.
+ */
+
+#include <android/binder_manager.h>
+#include <android/binder_process.h>
+
+#include "mainline_supplicant.h"
+
+extern "C"
+{
+#include "aidl_i.h"
+#include "service.h"
+#include "utils/common.h"
+#include "utils/eloop.h"
+#include "utils/includes.h"
+#include "utils/wpa_debug.h"
+}
+
+using ::ndk::SharedRefBase;
+
+/* Handler for requests to the service */
+void aidl_sock_handler(int /* sock */, void * /* eloop_ctx */, void * /* sock_ctx */) {
+    // Suppress warning, since this service is only available after Android V
+    if (__builtin_available(android __ANDROID_API_V__, *)) {
+        ABinderProcess_handlePolledCommands();
+    }
+}
+
+bool register_service(struct wpa_global *global) {
+    wpa_printf(MSG_INFO, "Registering as a lazy service");
+    std::string service_name = "wifi_mainline_supplicant";
+    std::shared_ptr<MainlineSupplicant> service = SharedRefBase::make<MainlineSupplicant>(global);
+
+    // Suppress warning, since this service is only available after Android V
+    if (__builtin_available(android __ANDROID_API_V__, *)) {
+        int status =
+            AServiceManager_registerLazyService(service->asBinder().get(), service_name.c_str());
+        if (status != EX_NONE) {
+            wpa_printf(MSG_ERROR, "Registration failed with status %d", status);
+        }
+        return status == EX_NONE;
+    }
+    return false;
+}
+
+struct wpas_aidl_priv *mainline_aidl_init(struct wpa_global *global) {
+    wpa_printf(MSG_INFO, "Initializing the mainline supplicant service");
+    struct wpas_aidl_priv *priv = (wpas_aidl_priv *)os_zalloc(sizeof(*priv));
+    if (!priv) {
+        wpa_printf(MSG_ERROR, "Unable to allocate the global AIDL object");
+        return NULL;
+    }
+    priv->global = global;
+
+    // Suppress warning, since this service is only available after Android V
+    if (__builtin_available(android __ANDROID_API_V__, *)) {
+        ABinderProcess_setupPolling(&priv->aidl_fd);
+    }
+    if (priv->aidl_fd < 0) {
+        wpa_printf(MSG_ERROR, "Unable to set up polling");
+        mainline_aidl_deinit(priv);
+        return NULL;
+    }
+
+    if (eloop_register_read_sock(priv->aidl_fd, aidl_sock_handler, global, priv) < 0) {
+        wpa_printf(MSG_ERROR, "Unable to register eloop read socket");
+        mainline_aidl_deinit(priv);
+        return NULL;
+    }
+
+    if (!register_service(global)) {
+        wpa_printf(MSG_ERROR, "Unable to register service");
+        mainline_aidl_deinit(priv);
+        return NULL;
+    }
+
+    wpa_printf(MSG_INFO, "AIDL setup is complete");
+    return priv;
+}
+
+void mainline_aidl_deinit(struct wpas_aidl_priv *priv) {
+    if (!priv) return;
+    wpa_printf(MSG_INFO, "Deiniting the mainline supplicant service");
+    eloop_unregister_read_sock(priv->aidl_fd);
+    os_free(priv);
+}
diff --git a/wpa_supplicant/aidl/mainline/service.h b/wpa_supplicant/aidl/mainline/service.h
new file mode 100644
index 00000000..6d213e7e
--- /dev/null
+++ b/wpa_supplicant/aidl/mainline/service.h
@@ -0,0 +1,27 @@
+/*
+ * WPA Supplicant - Mainline supplicant service
+ * Copyright (c) 2024, Google Inc. All rights reserved.
+ *
+ * This software may be distributed under the terms of the BSD license.
+ * See README for more details.
+ */
+
+#ifndef MAINLINE_SUPPLICANT_SERVICE_H
+#define MAINLINE_SUPPLICANT_SERVICE_H
+
+#ifdef _cplusplus
+extern "C"
+{
+#endif  // _cplusplus
+
+struct wpas_aidl_priv;
+struct wpa_global;
+
+struct wpas_aidl_priv *mainline_aidl_init(struct wpa_global *global);
+void mainline_aidl_deinit(struct wpas_aidl_priv *priv);
+
+#ifdef _cplusplus
+}
+#endif  // _cplusplus
+
+#endif  // MAINLINE_SUPPLICANT_SERVICE_H
diff --git a/wpa_supplicant/aidl/mainline/utils.h b/wpa_supplicant/aidl/mainline/utils.h
new file mode 100644
index 00000000..703b9eef
--- /dev/null
+++ b/wpa_supplicant/aidl/mainline/utils.h
@@ -0,0 +1,25 @@
+/*
+ * WPA Supplicant - Utilities for the mainline supplicant
+ * Copyright (c) 2024, Google Inc. All rights reserved.
+ *
+ * This software may be distributed under the terms of the BSD license.
+ * See README for more details.
+ */
+
+#ifndef MAINLINE_SUPPLICANT_UTILS_H
+#define MAINLINE_SUPPLICANT_UTILS_H
+
+#include <aidl/android/system/wifi/mainline_supplicant/SupplicantStatusCode.h>
+
+inline ndk::ScopedAStatus createStatus(SupplicantStatusCode statusCode) {
+	return ndk::ScopedAStatus::fromServiceSpecificError(
+		static_cast<int32_t>(statusCode));
+}
+
+inline ndk::ScopedAStatus createStatusWithMsg(
+	    SupplicantStatusCode statusCode, std::string msg) {
+	return ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(
+		static_cast<int32_t>(statusCode), msg.c_str());
+}
+
+#endif // MAINLINE_SUPPLICANT_UTILS_H
diff --git a/wpa_supplicant/aidl/shared/Android.bp b/wpa_supplicant/aidl/shared/Android.bp
new file mode 100644
index 00000000..25cb5fa5
--- /dev/null
+++ b/wpa_supplicant/aidl/shared/Android.bp
@@ -0,0 +1,29 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+cc_library_headers {
+    name: "libwpa_shared_aidl_headers_vendor",
+    export_include_dirs: ["."],
+    soc_specific: true,
+}
+
+cc_library_headers {
+    name: "libwpa_shared_aidl_headers_mainline",
+    export_include_dirs: ["."],
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.wifi",
+    ],
+    min_sdk_version: "30",
+}
diff --git a/wpa_supplicant/aidl/aidl_i.h b/wpa_supplicant/aidl/shared/aidl_i.h
similarity index 100%
rename from wpa_supplicant/aidl/aidl_i.h
rename to wpa_supplicant/aidl/shared/aidl_i.h
diff --git a/wpa_supplicant/aidl/shared/shared_utils.h b/wpa_supplicant/aidl/shared/shared_utils.h
new file mode 100644
index 00000000..97676f4f
--- /dev/null
+++ b/wpa_supplicant/aidl/shared/shared_utils.h
@@ -0,0 +1,49 @@
+/*
+ * WPA Supplicant - Shared utility functions and constants
+ * Copyright (c) 2024, Google Inc. All rights reserved.
+ *
+ * This software may be distributed under the terms of the BSD license.
+ * See README for more details.
+ */
+
+#ifndef SHARED_UTILS_H
+#define SHARED_UTILS_H
+
+#include <android-base/file.h>
+#include <fcntl.h>
+
+extern "C"
+{
+#include "utils/common.h"
+}
+
+constexpr char kIfaceDriverName[] = "nl80211";
+constexpr mode_t kConfigFileMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
+
+/**
+ * Ensure that the config file at |config_file_path| exists.
+ * Returns 0 on success, or errno otherwise.
+ */
+int ensureConfigFileExistsAtPath(const std::string& config_file_path) {
+    int ret = access(config_file_path.c_str(), R_OK);
+    if (ret == 0) {
+        return 0;
+    }
+    if (errno == EACCES) {
+        ret = chmod(config_file_path.c_str(), kConfigFileMode);
+        if (ret == 0) {
+            return 0;
+        } else {
+            wpa_printf(
+                MSG_ERROR, "Cannot set RW to %s. Errno: %s",
+                config_file_path.c_str(), strerror(errno));
+        }
+    } else if (errno != ENOENT) {
+        wpa_printf(
+            MSG_ERROR, "Cannot access %s. Errno: %s",
+            config_file_path.c_str(), strerror(errno));
+    }
+    return errno;
+}
+
+#endif // SHARED_UTILS_H
diff --git a/wpa_supplicant/aidl/.clang-format b/wpa_supplicant/aidl/vendor/.clang-format
similarity index 100%
rename from wpa_supplicant/aidl/.clang-format
rename to wpa_supplicant/aidl/vendor/.clang-format
diff --git a/wpa_supplicant/aidl/Android.bp b/wpa_supplicant/aidl/vendor/Android.bp
similarity index 91%
rename from wpa_supplicant/aidl/Android.bp
rename to wpa_supplicant/aidl/vendor/Android.bp
index a2ce7e87..a972dd6c 100644
--- a/wpa_supplicant/aidl/Android.bp
+++ b/wpa_supplicant/aidl/vendor/Android.bp
@@ -56,6 +56,7 @@ cc_library_static {
     header_libs: [
         "wpa_supplicant_headers",
         "libwpa_aidl_headers",
+        "libwpa_shared_aidl_headers_vendor",
     ],
 }
 
@@ -83,3 +84,10 @@ libwpa_aidl_cflags_cc_defaults {
         },
     },
 }
+
+prebuilt_etc {
+    name: "android.hardware.wifi.supplicant.xml.prebuilt",
+    src: "android.hardware.wifi.supplicant.xml",
+    relative_install_path: "vintf",
+    installable: false,
+}
diff --git a/wpa_supplicant/aidl/aidl.cpp b/wpa_supplicant/aidl/vendor/aidl.cpp
similarity index 99%
rename from wpa_supplicant/aidl/aidl.cpp
rename to wpa_supplicant/aidl/vendor/aidl.cpp
index d1cf8913..a0446fe6 100644
--- a/wpa_supplicant/aidl/aidl.cpp
+++ b/wpa_supplicant/aidl/vendor/aidl.cpp
@@ -14,7 +14,7 @@
 extern "C"
 {
 #include "aidl.h"
-#include "aidl_i.h"
+#include "aidl/shared/aidl_i.h"
 #include "utils/common.h"
 #include "utils/eloop.h"
 #include "utils/includes.h"
diff --git a/wpa_supplicant/aidl/aidl.h b/wpa_supplicant/aidl/vendor/aidl.h
similarity index 98%
rename from wpa_supplicant/aidl/aidl.h
rename to wpa_supplicant/aidl/vendor/aidl.h
index eb1426ac..71620f4e 100644
--- a/wpa_supplicant/aidl/aidl.h
+++ b/wpa_supplicant/aidl/vendor/aidl.h
@@ -110,8 +110,10 @@ extern "C"
 	void wpas_aidl_notify_dpp_config_received(struct wpa_supplicant *wpa_s,
 		struct wpa_ssid *ssid, bool conn_status_requested);
 	void wpas_aidl_notify_dpp_config_sent(struct wpa_supplicant *wpa_s);
+#ifdef CONFIG_DPP
 	void wpas_aidl_notify_dpp_connection_status_sent(struct wpa_supplicant *wpa_s,
 		enum dpp_status_error result);
+#endif /* CONFIG_DPP */
 	void wpas_aidl_notify_dpp_auth_success(struct wpa_supplicant *wpa_s);
 	void wpas_aidl_notify_dpp_resp_pending(struct wpa_supplicant *wpa_s);
 	void wpas_aidl_notify_dpp_not_compatible(struct wpa_supplicant *wpa_s);
@@ -124,9 +126,11 @@ extern "C"
 	void wpas_aidl_notify_dpp_config_sent_wait_response(struct wpa_supplicant *wpa_s);
 	void wpas_aidl_notify_dpp_config_accepted(struct wpa_supplicant *wpa_s);
 	void wpas_aidl_notify_dpp_config_rejected(struct wpa_supplicant *wpa_s);
+#ifdef CONFIG_DPP
 	void wpas_aidl_notify_dpp_conn_status(struct wpa_supplicant *wpa_s,
 		enum dpp_status_error status, const char *ssid,
 		const char *channel_list, unsigned short band_list[], int size);
+#endif /* CONFIG_DPP */
 	void wpas_aidl_notify_pmk_cache_added(
 		struct wpa_supplicant *wpas, struct rsn_pmksa_cache_entry *pmksa_entry);
 	void wpas_aidl_notify_bss_tm_status(struct wpa_supplicant *wpa_s);
@@ -274,9 +278,11 @@ static void wpas_aidl_notify_dpp_config_received(struct wpa_supplicant *wpa_s,
 {}
 static void wpas_aidl_notify_dpp_config_sent(struct wpa_supplicant *wpa_s)
 {}
+#ifdef CONFIG_DPP
 static void wpas_aidl_notify_dpp_connection_status_sent(struct wpa_supplicant *wpa_s,
 	enum dpp_status_error result)
 {}
+#endif /* CONFIG_DPP */
 static void wpas_aidl_notify_dpp_auth_success(struct wpa_supplicant *wpa_s)
 {}
 static void wpas_aidl_notify_dpp_resp_pending(struct wpa_supplicant *wpa_s)
@@ -301,10 +307,12 @@ static void wpas_aidl_notify_dpp_config_accepted(struct wpa_supplicant *wpa_s)
 {}
 static void wpas_aidl_notify_dpp_config_rejected(struct wpa_supplicant *wpa_s)
 {}
+#ifdef CONFIG_DPP
 static void wpas_aidl_notify_dpp_conn_status(struct wpa_supplicant *wpa_s,
 			enum dpp_status_error status, const char *ssid,
 			const char *channel_list, unsigned short band_list[], int size)
 {}
+#endif /* CONFIG_DPP */
 static void wpas_aidl_notify_pmk_cache_added(struct wpa_supplicant *wpas,
 						 struct rsn_pmksa_cache_entry *pmksa_entry)
 {}
diff --git a/wpa_supplicant/aidl/aidl_manager.cpp b/wpa_supplicant/aidl/vendor/aidl_manager.cpp
similarity index 96%
rename from wpa_supplicant/aidl/aidl_manager.cpp
rename to wpa_supplicant/aidl/vendor/aidl_manager.cpp
index 707299df..177f4789 100644
--- a/wpa_supplicant/aidl/aidl_manager.cpp
+++ b/wpa_supplicant/aidl/vendor/aidl_manager.cpp
@@ -425,6 +425,12 @@ int32_t AidlManager::isAidlClientVersionAtLeast(int32_t expected_version)
 	return expected_version <= aidl_client_version;
 }
 
+int32_t AidlManager::areAidlServiceAndClientAtLeastVersion(int32_t expected_version)
+{
+	return isAidlServiceVersionAtLeast(expected_version)
+		&& isAidlClientVersionAtLeast(expected_version);
+}
+
 int AidlManager::registerAidlService(struct wpa_global *global)
 {
 	// Create the main aidl service object and register it.
@@ -1356,7 +1362,7 @@ void AidlManager::notifyP2pDeviceFound(
 			std::back_inserter(aidl_vendor_elems));
 	}
 
-	if (isAidlServiceVersionAtLeast(3) && isAidlClientVersionAtLeast(3)) {
+	if (areAidlServiceAndClientAtLeastVersion(3)) {
 		P2pDeviceFoundEventParams params;
 		params.srcAddress = macAddrToArray(addr);
 		params.p2pDeviceAddress = macAddrToArray(info->p2p_device_addr);
@@ -1368,6 +1374,10 @@ void AidlManager::notifyP2pDeviceFound(
 		params.wfdDeviceInfo = aidl_peer_wfd_device_info;
 		params.wfdR2DeviceInfo = aidl_peer_wfd_r2_device_info;
 		params.vendorElemBytes = aidl_vendor_elems;
+		if (areAidlServiceAndClientAtLeastVersion(4)) {
+			// TODO Fill the field when supplicant implementation is ready
+			params.pairingBootstrappingMethods = 0;
+		}
 		callWithEachP2pIfaceCallback(
 			misc_utils::charBufToString(wpa_s->ifname),
 			std::bind(
@@ -1529,6 +1539,10 @@ void AidlManager::notifyP2pGroupStarted(
 			   params.p2pClientIpInfo.ipAddressMask,
 			   params.p2pClientIpInfo.ipAddressGo);
         }
+	if (areAidlServiceAndClientAtLeastVersion(4)) {
+		// TODO Fill the field when supplicant implementation is ready
+		params.keyMgmtMask = 0;
+	}
 	callWithEachP2pIfaceCallback(
 		misc_utils::charBufToString(wpa_s->ifname),
 		std::bind(&ISupplicantP2pIfaceCallback::onGroupStartedWithParams,
@@ -1619,7 +1633,7 @@ void AidlManager::notifyP2pProvisionDiscovery(
 	}
 	bool aidl_is_request = (request == 1);
 
-	if (isAidlServiceVersionAtLeast(3) && isAidlClientVersionAtLeast(3)) {
+	if (areAidlServiceAndClientAtLeastVersion(3)) {
 		P2pProvisionDiscoveryCompletedEventParams params;
 		params.p2pDeviceAddress =  macAddrToArray(dev_addr);
 		params.isRequest = aidl_is_request;
@@ -1665,6 +1679,75 @@ void AidlManager::notifyP2pSdResponse(
 		byteArrToVec(tlvs, tlvs_len)));
 }
 
+void AidlManager::notifyUsdBasedServiceDiscoveryResult(
+	struct wpa_supplicant *wpa_s, const u8 *peer_addr, int subscribe_id,
+	int peer_publish_id, int srv_proto_type, const u8 *ssi, size_t ssi_len)
+{
+	// TODO define the reason and map to AIDL defenition.
+	if (!wpa_s)
+		return;
+
+	if (p2p_iface_object_map_.find(wpa_s->ifname) ==
+		p2p_iface_object_map_.end())
+		return;
+
+	if (!areAidlServiceAndClientAtLeastVersion(4)) {
+	      return;
+	}
+	// TODO Fill the fields when supplicant implementation is ready
+	P2pUsdBasedServiceDiscoveryResultParams params;
+
+	callWithEachP2pIfaceCallback(
+		misc_utils::charBufToString(wpa_s->ifname),
+		std::bind(
+		&ISupplicantP2pIfaceCallback::onUsdBasedServiceDiscoveryResult,
+		std::placeholders::_1, params));
+}
+
+void AidlManager::notifyUsdBasedServiceDiscoveryTerminated(
+	struct wpa_supplicant *wpa_s, int subscribe_id, int reason)
+{
+	// TODO define the reason and map to AIDL defenition.
+	if (!wpa_s)
+		return;
+
+	if (p2p_iface_object_map_.find(wpa_s->ifname) ==
+		p2p_iface_object_map_.end())
+		return;
+
+	if (!areAidlServiceAndClientAtLeastVersion(4)) {
+	      return;
+	}
+
+	callWithEachP2pIfaceCallback(
+		misc_utils::charBufToString(wpa_s->ifname),
+		std::bind(
+		&ISupplicantP2pIfaceCallback::onUsdBasedServiceDiscoveryTerminated,
+		std::placeholders::_1, subscribe_id, UsdTerminateReasonCode::UNKNOWN));
+}
+
+void AidlManager::notifyUsdBasedServiceAdvertisementTerminated(
+	struct wpa_supplicant *wpa_s, int publish_id, int reason)
+{
+	// TODO define the reason and map to AIDL defenition.
+	if (!wpa_s)
+		return;
+
+	if (p2p_iface_object_map_.find(wpa_s->ifname) ==
+		p2p_iface_object_map_.end())
+		return;
+
+	if (!areAidlServiceAndClientAtLeastVersion(4)) {
+	      return;
+	}
+
+	callWithEachP2pIfaceCallback(
+		misc_utils::charBufToString(wpa_s->ifname),
+		std::bind(
+		&ISupplicantP2pIfaceCallback::onUsdBasedServiceAdvertisementTerminated,
+		std::placeholders::_1, publish_id, UsdTerminateReasonCode::UNKNOWN));
+}
+
 void AidlManager::notifyApStaAuthorized(
 	struct wpa_supplicant *wpa_group_s, const u8 *sta, const u8 *p2p_dev_addr,
 	const u8 *ip)
@@ -1675,7 +1758,7 @@ void AidlManager::notifyApStaAuthorized(
 	if (!wpa_s)
 		return;
 
-	if (isAidlServiceVersionAtLeast(3) && isAidlClientVersionAtLeast(3)) {
+	if (areAidlServiceAndClientAtLeastVersion(3)) {
 		P2pPeerClientJoinedEventParams params;
 		params.groupInterfaceName = misc_utils::charBufToString(wpa_group_s->ifname);
 		params.clientInterfaceAddress = macAddrToArray(sta);
@@ -1686,6 +1769,10 @@ void AidlManager::notifyApStaAuthorized(
 			os_memcpy(&aidl_ip, &ip[0], 4);
 		}
 		params.clientIpAddress = aidl_ip;
+		if (areAidlServiceAndClientAtLeastVersion(4)) {
+			// TODO Fill the field when supplicant implementation is ready
+			params.keyMgmtMask = 0;
+		}
 		callWithEachP2pIfaceCallback(
 			misc_utils::charBufToString(wpa_s->ifname),
 			std::bind(
@@ -1711,7 +1798,7 @@ void AidlManager::notifyApStaDeauthorized(
 	if (!wpa_s)
 		return;
 
-	if (isAidlServiceVersionAtLeast(3) && isAidlClientVersionAtLeast(3)) {
+	if (areAidlServiceAndClientAtLeastVersion(3)) {
 		P2pPeerClientDisconnectedEventParams params;
 		params.groupInterfaceName = misc_utils::charBufToString(wpa_group_s->ifname);
 		params.clientInterfaceAddress = macAddrToArray(sta);
@@ -2060,7 +2147,7 @@ uint32_t getBssTmDataAssocRetryDelayMs(struct wpa_supplicant *wpa_s)
 
 	if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_DISASSOC_IMMINENT) {
 		// number of tbtts to milliseconds
-		duration_ms = wpa_s->wnm_dissoc_timer * beacon_int * 128 / 125;
+		duration_ms = wpa_s->wnm_disassoc_timer * beacon_int * 128 / 125;
 	}
 	if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED) {
 		//wnm_bss_termination_duration contains 12 bytes of BSS
diff --git a/wpa_supplicant/aidl/aidl_manager.h b/wpa_supplicant/aidl/vendor/aidl_manager.h
similarity index 98%
rename from wpa_supplicant/aidl/aidl_manager.h
rename to wpa_supplicant/aidl/vendor/aidl_manager.h
index b3dfa822..46a40aa2 100644
--- a/wpa_supplicant/aidl/aidl_manager.h
+++ b/wpa_supplicant/aidl/vendor/aidl_manager.h
@@ -120,6 +120,15 @@ public:
 	void notifyP2pSdResponse(
 		struct wpa_supplicant *wpa_s, const u8 *sa, u16 update_indic,
 		const u8 *tlvs, size_t tlvs_len);
+	void notifyUsdBasedServiceDiscoveryResult(
+		struct wpa_supplicant *wpa_s, const u8 *peer_addr, int subscribe_id,
+		int peer_publish_id, int srv_proto_type, const u8 *ssi, size_t ssi_len);
+	void notifyUsdBasedServiceDiscoveryTerminated(
+		struct wpa_supplicant *wpa_s, int subscribe_id,
+		int reason);
+	void notifyUsdBasedServiceAdvertisementTerminated(
+		struct wpa_supplicant *wpa_s, int publish_id,
+		int reason);
 	void notifyApStaAuthorized(
 		struct wpa_supplicant *wpa_s, const u8 *sta,
 		const u8 *p2p_dev_addr, const u8 *ip);
@@ -173,6 +182,7 @@ public:
 	// Methods called from aidl objects.
 	int32_t isAidlServiceVersionAtLeast(int32_t expected_version);
 	int32_t isAidlClientVersionAtLeast(int32_t expected_version);
+	int32_t areAidlServiceAndClientAtLeastVersion(int32_t expected_version);
 	void notifyExtRadioWorkStart(struct wpa_supplicant *wpa_s, uint32_t id);
 	void notifyExtRadioWorkTimeout(
 		struct wpa_supplicant *wpa_s, uint32_t id);
diff --git a/wpa_supplicant/aidl/aidl_return_util.h b/wpa_supplicant/aidl/vendor/aidl_return_util.h
similarity index 100%
rename from wpa_supplicant/aidl/aidl_return_util.h
rename to wpa_supplicant/aidl/vendor/aidl_return_util.h
diff --git a/wpa_supplicant/aidl/android.hardware.wifi.supplicant-service.rc b/wpa_supplicant/aidl/vendor/android.hardware.wifi.supplicant-service.rc
similarity index 100%
rename from wpa_supplicant/aidl/android.hardware.wifi.supplicant-service.rc
rename to wpa_supplicant/aidl/vendor/android.hardware.wifi.supplicant-service.rc
diff --git a/wpa_supplicant/aidl/android.hardware.wifi.supplicant.xml b/wpa_supplicant/aidl/vendor/android.hardware.wifi.supplicant.xml
similarity index 100%
rename from wpa_supplicant/aidl/android.hardware.wifi.supplicant.xml
rename to wpa_supplicant/aidl/vendor/android.hardware.wifi.supplicant.xml
diff --git a/wpa_supplicant/aidl/certificate_utils.cpp b/wpa_supplicant/aidl/vendor/certificate_utils.cpp
similarity index 100%
rename from wpa_supplicant/aidl/certificate_utils.cpp
rename to wpa_supplicant/aidl/vendor/certificate_utils.cpp
diff --git a/wpa_supplicant/aidl/certificate_utils.h b/wpa_supplicant/aidl/vendor/certificate_utils.h
similarity index 100%
rename from wpa_supplicant/aidl/certificate_utils.h
rename to wpa_supplicant/aidl/vendor/certificate_utils.h
diff --git a/wpa_supplicant/aidl/iface_config_utils.cpp b/wpa_supplicant/aidl/vendor/iface_config_utils.cpp
similarity index 100%
rename from wpa_supplicant/aidl/iface_config_utils.cpp
rename to wpa_supplicant/aidl/vendor/iface_config_utils.cpp
diff --git a/wpa_supplicant/aidl/iface_config_utils.h b/wpa_supplicant/aidl/vendor/iface_config_utils.h
similarity index 100%
rename from wpa_supplicant/aidl/iface_config_utils.h
rename to wpa_supplicant/aidl/vendor/iface_config_utils.h
diff --git a/wpa_supplicant/aidl/misc_utils.h b/wpa_supplicant/aidl/vendor/misc_utils.h
similarity index 100%
rename from wpa_supplicant/aidl/misc_utils.h
rename to wpa_supplicant/aidl/vendor/misc_utils.h
diff --git a/wpa_supplicant/aidl/p2p_iface.cpp b/wpa_supplicant/aidl/vendor/p2p_iface.cpp
similarity index 93%
rename from wpa_supplicant/aidl/p2p_iface.cpp
rename to wpa_supplicant/aidl/vendor/p2p_iface.cpp
index 7afc8a13..b1cd1cd1 100644
--- a/wpa_supplicant/aidl/p2p_iface.cpp
+++ b/wpa_supplicant/aidl/vendor/p2p_iface.cpp
@@ -29,6 +29,7 @@ namespace {
 const char kConfigMethodStrPbc[] = "pbc";
 const char kConfigMethodStrDisplay[] = "display";
 const char kConfigMethodStrKeypad[] = "keypad";
+const char kConfigMethodStrNone[] = "none";
 constexpr char kSetMiracastMode[] = "MIRACAST ";
 constexpr uint8_t kWfdDeviceInfoSubelemId = 0;
 constexpr uint8_t kWfdR2DeviceInfoSubelemId = 11;
@@ -853,6 +854,79 @@ ndk::ScopedAStatus P2pIface::addGroup(
 		this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
 		&P2pIface::createGroupOwnerInternal, in_groupOwnerInfo);
 }
+
+::ndk::ScopedAStatus P2pIface::getFeatureSet(int64_t* _aidl_return)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
+		&P2pIface::getFeatureSetInternal, _aidl_return);
+}
+
+::ndk::ScopedAStatus P2pIface::startUsdBasedServiceDiscovery(
+		const P2pUsdBasedServiceDiscoveryConfig& in_serviceDiscoveryConfig,
+		int32_t* _aidl_return)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
+		&P2pIface::startUsdBasedServiceDiscoveryInternal, _aidl_return,
+		in_serviceDiscoveryConfig);
+}
+
+::ndk::ScopedAStatus P2pIface::stopUsdBasedServiceDiscovery(int32_t in_sessionId)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
+		&P2pIface::stopUsdBasedServiceDiscoveryInternal, in_sessionId);
+}
+
+::ndk::ScopedAStatus P2pIface::startUsdBasedServiceAdvertisement(
+		const P2pUsdBasedServiceAdvertisementConfig& in_serviceAdvertisementConfig,
+		int32_t* _aidl_return)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
+		&P2pIface::startUsdBasedServiceAdvertisementInternal, _aidl_return,
+		in_serviceAdvertisementConfig);
+}
+
+::ndk::ScopedAStatus P2pIface::stopUsdBasedServiceAdvertisement(int32_t in_sessionId)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
+		&P2pIface::stopUsdBasedServiceAdvertisementInternal, in_sessionId);
+}
+
+::ndk::ScopedAStatus P2pIface::provisionDiscoveryWithParams(
+		const P2pProvisionDiscoveryParams& in_params)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
+		&P2pIface::provisionDiscoveryWithParamsInternal, in_params);
+}
+
+::ndk::ScopedAStatus P2pIface::getDirInfo(P2pDirInfo* _aidl_return)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
+		&P2pIface::getDirInfoInternal, _aidl_return);
+}
+
+::ndk::ScopedAStatus P2pIface::validateDirInfo(const P2pDirInfo& in_dirInfo,
+		int32_t* _aidl_return)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
+		&P2pIface::validateDirInfoInternal, _aidl_return, in_dirInfo);
+}
+
+::ndk::ScopedAStatus P2pIface::reinvokePersistentGroup(
+		const P2pReinvokePersistentGroupParams& in_reinvokeGroupParams)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_IFACE_INVALID,
+		&P2pIface::reinvokePersistentGroupInternal, in_reinvokeGroupParams);
+}
+
 std::pair<std::string, ndk::ScopedAStatus> P2pIface::getNameInternal()
 {
 	return {ifname_, ndk::ScopedAStatus::ok()};
@@ -1051,6 +1125,9 @@ std::pair<std::string, ndk::ScopedAStatus> P2pIface::connectInternal(
 	case WpsProvisionMethod::KEYPAD:
 		wps_method = WPS_PIN_KEYPAD;
 		break;
+	case WpsProvisionMethod::NONE:
+		wps_method = WPS_NOT_READY;
+		break;
 	}
 	int he = wpa_s->conf->p2p_go_he;
 	int vht = wpa_s->conf->p2p_go_vht;
@@ -1061,7 +1138,8 @@ std::pair<std::string, ndk::ScopedAStatus> P2pIface::connectInternal(
 	int new_pin = wpas_p2p_connect(
 		wpa_s, peer_address.data(), pin, wps_method, persistent, false,
 		join_existing_group, false, go_intent_signed, 0, 0, -1, false, ht40,
-		vht, CONF_OPER_CHWIDTH_USE_HT, he, edmg, nullptr, 0, is6GhzAllowed(wpa_s));
+		vht, CONF_OPER_CHWIDTH_USE_HT, he, edmg, nullptr, 0, is6GhzAllowed(wpa_s),
+		false, 0, NULL);
 	if (new_pin < 0) {
 		return {"", createStatus(SupplicantStatusCode::FAILURE_UNKNOWN)};
 	}
@@ -1107,6 +1185,10 @@ ndk::ScopedAStatus P2pIface::provisionDiscoveryInternal(
 	case WpsProvisionMethod::KEYPAD:
 		config_method_str = kConfigMethodStrKeypad;
 		break;
+	// TODO Handle pairing bootstrapping method when supplicant implementation is ready
+	case WpsProvisionMethod::NONE:
+		config_method_str = kConfigMethodStrNone;
+		break;
 	}
 	if (wpas_p2p_prov_disc(
 		wpa_s, peer_address.data(), config_method_str,
@@ -1943,6 +2025,70 @@ ndk::ScopedAStatus P2pIface::createGroupOwnerInternal(
 		groupOwnerInfo.persistent, groupOwnerInfo.persistentNetworkId);
 }
 
+std::pair<int64_t, ndk::ScopedAStatus> P2pIface::getFeatureSetInternal()
+{
+	// TODO Fill the field when supplicant implementation is ready
+	return {0, ndk::ScopedAStatus::ok()};
+}
+
+std::pair<uint32_t, ndk::ScopedAStatus>
+P2pIface::startUsdBasedServiceDiscoveryInternal(
+	const P2pUsdBasedServiceDiscoveryConfig& serviceDiscoveryConfig)
+{
+	// TODO Fill the field when supplicant implementation is ready
+	return {0, ndk::ScopedAStatus::ok()};
+}
+
+ndk::ScopedAStatus P2pIface::stopUsdBasedServiceDiscoveryInternal(
+	uint32_t sessionId)
+{
+	// TODO Fill the field when supplicant implementation is ready
+	return ndk::ScopedAStatus::ok();
+}
+
+std::pair<uint32_t, ndk::ScopedAStatus>
+P2pIface::startUsdBasedServiceAdvertisementInternal(
+	const P2pUsdBasedServiceAdvertisementConfig& serviceAdvertisementConfig)
+{
+	// TODO Fill the field when supplicant implementation is ready
+	return {0, ndk::ScopedAStatus::ok()};
+}
+
+ndk::ScopedAStatus P2pIface::stopUsdBasedServiceAdvertisementInternal(
+	uint32_t sessionId)
+{
+	// TODO Fill the field when supplicant implementation is ready
+	return ndk::ScopedAStatus::ok();
+}
+
+ndk::ScopedAStatus P2pIface::provisionDiscoveryWithParamsInternal(
+	const P2pProvisionDiscoveryParams& params)
+{
+	// TODO Fill the field when supplicant implementation is ready
+	return ndk::ScopedAStatus::ok();
+}
+
+std::pair<P2pDirInfo, ndk::ScopedAStatus> P2pIface::getDirInfoInternal()
+{
+	// TODO Fill the field when supplicant implementation is ready
+	P2pDirInfo dirInfo = {};
+	return {dirInfo, ndk::ScopedAStatus::ok()};
+}
+
+std::pair<int32_t, ndk::ScopedAStatus> P2pIface::validateDirInfoInternal(
+	const P2pDirInfo& dirInfo)
+{
+	// TODO Fill the field when supplicant implementation is ready
+	return {0, ndk::ScopedAStatus::ok()};
+}
+
+ndk::ScopedAStatus P2pIface::reinvokePersistentGroupInternal(
+	const P2pReinvokePersistentGroupParams& reinvokeGroupParams)
+{
+	// TODO Fill the field when supplicant implementation is ready
+	return ndk::ScopedAStatus::ok();
+}
+
 /**
  * Retrieve the underlying |wpa_supplicant| struct
  * pointer for this iface.
diff --git a/wpa_supplicant/aidl/p2p_iface.h b/wpa_supplicant/aidl/vendor/p2p_iface.h
similarity index 89%
rename from wpa_supplicant/aidl/p2p_iface.h
rename to wpa_supplicant/aidl/vendor/p2p_iface.h
index 98556d13..545a6c92 100644
--- a/wpa_supplicant/aidl/p2p_iface.h
+++ b/wpa_supplicant/aidl/vendor/p2p_iface.h
@@ -184,6 +184,22 @@ public:
 		const P2pAddGroupConfigurationParams& in_groupConfigurationParams) override;
 	::ndk::ScopedAStatus createGroupOwner(
 		const P2pCreateGroupOwnerInfo& in_groupOwnerInfo) override;
+	::ndk::ScopedAStatus getFeatureSet(int64_t* _aidl_return) override;
+	::ndk::ScopedAStatus startUsdBasedServiceDiscovery(
+		const P2pUsdBasedServiceDiscoveryConfig& in_serviceDiscoveryConfig,
+		int32_t* _aidl_return) override;
+	::ndk::ScopedAStatus stopUsdBasedServiceDiscovery(int32_t in_sessionId) override;
+	::ndk::ScopedAStatus startUsdBasedServiceAdvertisement(
+		const P2pUsdBasedServiceAdvertisementConfig& in_serviceAdvertisementConfig,
+		int32_t* _aidl_return) override;
+	::ndk::ScopedAStatus stopUsdBasedServiceAdvertisement(int32_t in_sessionId) override;
+	::ndk::ScopedAStatus provisionDiscoveryWithParams(
+		const P2pProvisionDiscoveryParams& in_params) override;
+	::ndk::ScopedAStatus getDirInfo(P2pDirInfo* _aidl_return) override;
+	::ndk::ScopedAStatus validateDirInfo(const P2pDirInfo &in_dirInfo,
+		int32_t* _aidl_return) override;
+	::ndk::ScopedAStatus reinvokePersistentGroup(
+		const P2pReinvokePersistentGroupParams& in_reinvokeGroupParams) override;
 
 
 private:
@@ -316,6 +332,20 @@ private:
 		const P2pAddGroupConfigurationParams& groupConfigurationParams);
 	ndk::ScopedAStatus createGroupOwnerInternal(
 		const P2pCreateGroupOwnerInfo& groupOwnerInfo);
+	std::pair<int64_t, ndk::ScopedAStatus> getFeatureSetInternal();
+	std::pair<uint32_t, ndk::ScopedAStatus> startUsdBasedServiceDiscoveryInternal(
+		const P2pUsdBasedServiceDiscoveryConfig& serviceDiscoveryConfig);
+	::ndk::ScopedAStatus stopUsdBasedServiceDiscoveryInternal(uint32_t sessionId);
+	std::pair<uint32_t, ndk::ScopedAStatus> startUsdBasedServiceAdvertisementInternal(
+		const P2pUsdBasedServiceAdvertisementConfig& serviceAdvertisementConfig);
+	::ndk::ScopedAStatus stopUsdBasedServiceAdvertisementInternal(uint32_t sessionId);
+	::ndk::ScopedAStatus provisionDiscoveryWithParamsInternal(
+		const P2pProvisionDiscoveryParams& params);
+	std::pair<P2pDirInfo, ndk::ScopedAStatus> getDirInfoInternal();
+	std::pair<int32_t, ndk::ScopedAStatus> validateDirInfoInternal(
+		const P2pDirInfo& dirInfo);
+	::ndk::ScopedAStatus reinvokePersistentGroupInternal(
+		const P2pReinvokePersistentGroupParams& reinvokeGroupParams);
 
 	struct wpa_supplicant* retrieveIfacePtr();
 	struct wpa_supplicant* retrieveGroupIfacePtr(
diff --git a/wpa_supplicant/aidl/p2p_network.cpp b/wpa_supplicant/aidl/vendor/p2p_network.cpp
similarity index 100%
rename from wpa_supplicant/aidl/p2p_network.cpp
rename to wpa_supplicant/aidl/vendor/p2p_network.cpp
diff --git a/wpa_supplicant/aidl/p2p_network.h b/wpa_supplicant/aidl/vendor/p2p_network.h
similarity index 100%
rename from wpa_supplicant/aidl/p2p_network.h
rename to wpa_supplicant/aidl/vendor/p2p_network.h
diff --git a/wpa_supplicant/aidl/sta_iface.cpp b/wpa_supplicant/aidl/vendor/sta_iface.cpp
similarity index 95%
rename from wpa_supplicant/aidl/sta_iface.cpp
rename to wpa_supplicant/aidl/vendor/sta_iface.cpp
index 3880a1d9..1a6ae081 100644
--- a/wpa_supplicant/aidl/sta_iface.cpp
+++ b/wpa_supplicant/aidl/vendor/sta_iface.cpp
@@ -38,23 +38,10 @@ using aidl::android::hardware::wifi::supplicant::KeyMgmtMask;
 using aidl::android::hardware::wifi::supplicant::LegacyMode;
 using aidl::android::hardware::wifi::supplicant::RxFilterType;
 using aidl::android::hardware::wifi::supplicant::SupplicantStatusCode;
+using aidl::android::hardware::wifi::supplicant::WifiChannelWidthInMhz;
 using aidl::android::hardware::wifi::supplicant::WifiTechnology;
 using aidl::android::hardware::wifi::supplicant::misc_utils::createStatus;
 
-// Enum definition copied from the Vendor HAL interface.
-// See android.hardware.wifi.WifiChannelWidthInMhz
-enum WifiChannelWidthInMhz {
-  WIDTH_20	= 0,
-  WIDTH_40	= 1,
-  WIDTH_80	= 2,
-  WIDTH_160   = 3,
-  WIDTH_80P80 = 4,
-  WIDTH_5	 = 5,
-  WIDTH_10	= 6,
-  WIDTH_320	= 7,
-  WIDTH_INVALID = -1
-};
-
 constexpr uint32_t kMaxAnqpElems = 100;
 constexpr char kGetMacAddress[] = "MACADDR";
 constexpr char kStartRxFilter[] = "RXFILTER-START";
@@ -856,6 +843,58 @@ bool StaIface::isValid()
 		&StaIface::disableMscsInternal);
 }
 
+::ndk::ScopedAStatus StaIface::getUsdCapabilities(UsdCapabilities* _aidl_return)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_UNKNOWN,
+		&StaIface::getUsdCapabilitiesInternal, _aidl_return);
+}
+
+::ndk::ScopedAStatus StaIface::startUsdPublish(int32_t in_cmdId,
+	const UsdPublishConfig& in_usdPublishConfig)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_UNKNOWN,
+		&StaIface::startUsdPublishInternal, in_usdPublishConfig);
+}
+
+::ndk::ScopedAStatus StaIface::startUsdSubscribe(int32_t in_cmdId,
+	const UsdSubscribeConfig& in_usdSubscribeConfig)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_UNKNOWN,
+		&StaIface::startUsdSubscribeInternal, in_usdSubscribeConfig);
+}
+
+::ndk::ScopedAStatus StaIface::updateUsdPublish(int32_t in_publishId,
+	const std::vector<uint8_t>& in_serviceSpecificInfo)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_UNKNOWN,
+		&StaIface::updateUsdPublishInternal, in_publishId, in_serviceSpecificInfo);
+}
+
+::ndk::ScopedAStatus StaIface::cancelUsdPublish(int32_t in_publishId)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_UNKNOWN,
+		&StaIface::cancelUsdPublishInternal, in_publishId);
+}
+
+::ndk::ScopedAStatus StaIface::cancelUsdSubscribe(int32_t in_subscribeId)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_UNKNOWN,
+		&StaIface::cancelUsdSubscribeInternal, in_subscribeId);
+}
+
+::ndk::ScopedAStatus StaIface::sendUsdMessage(const UsdMessageInfo& in_messageInfo)
+{
+	return validateAndCall(
+		this, SupplicantStatusCode::FAILURE_UNKNOWN,
+		&StaIface::sendUsdMessageInternal, in_messageInfo);
+}
+
 std::pair<std::string, ndk::ScopedAStatus> StaIface::getNameInternal()
 {
 	return {ifname_, ndk::ScopedAStatus::ok()};
@@ -1851,32 +1890,32 @@ StaIface::getConnectionCapabilitiesInternal()
 			capa.technology = WifiTechnology::LEGACY;
 			if (wpas_freq_to_band(wpa_s->assoc_freq) == BAND_2_4_GHZ) {
 				capa.legacyMode = (wpa_s->connection_11b_only) ? LegacyMode::B_MODE
-						: LegacyMode::G_MODE; 
+						: LegacyMode::G_MODE;
 			} else {
 				capa.legacyMode = LegacyMode::A_MODE;
 			}
 		}
 		switch (wpa_s->connection_channel_bandwidth) {
 		case CHAN_WIDTH_20:
-			capa.channelBandwidth = WifiChannelWidthInMhz::WIDTH_20;
+			capa.channelBandwidth = static_cast<int32_t>(WifiChannelWidthInMhz::WIDTH_20);
 			break;
 		case CHAN_WIDTH_40:
-			capa.channelBandwidth = WifiChannelWidthInMhz::WIDTH_40;
+			capa.channelBandwidth = static_cast<int32_t>(WifiChannelWidthInMhz::WIDTH_40);
 			break;
 		case CHAN_WIDTH_80:
-			capa.channelBandwidth = WifiChannelWidthInMhz::WIDTH_80;
+			capa.channelBandwidth = static_cast<int32_t>(WifiChannelWidthInMhz::WIDTH_80);
 			break;
 		case CHAN_WIDTH_160:
-			capa.channelBandwidth = WifiChannelWidthInMhz::WIDTH_160;
+			capa.channelBandwidth = static_cast<int32_t>(WifiChannelWidthInMhz::WIDTH_160);
 			break;
 		case CHAN_WIDTH_80P80:
-			capa.channelBandwidth = WifiChannelWidthInMhz::WIDTH_80P80;
+			capa.channelBandwidth = static_cast<int32_t>(WifiChannelWidthInMhz::WIDTH_80P80);
 			break;
 		case CHAN_WIDTH_320:
-			capa.channelBandwidth = WifiChannelWidthInMhz::WIDTH_320;
+			capa.channelBandwidth = static_cast<int32_t>(WifiChannelWidthInMhz::WIDTH_320);
 			break;
 		default:
-			capa.channelBandwidth = WifiChannelWidthInMhz::WIDTH_20;
+			capa.channelBandwidth = static_cast<int32_t>(WifiChannelWidthInMhz::WIDTH_20);
 			break;
 		}
 		capa.maxNumberRxSpatialStreams = wpa_s->connection_max_nss_rx;
@@ -1884,7 +1923,7 @@ StaIface::getConnectionCapabilitiesInternal()
 		capa.apTidToLinkMapNegotiationSupported = wpa_s->ap_t2lm_negotiation_support;
 	} else {
 		capa.technology = WifiTechnology::UNKNOWN;
-		capa.channelBandwidth = WifiChannelWidthInMhz::WIDTH_20;
+		capa.channelBandwidth = static_cast<int32_t>(WifiChannelWidthInMhz::WIDTH_20);
 		capa.maxNumberTxSpatialStreams = 1;
 		capa.maxNumberRxSpatialStreams = 1;
 		capa.legacyMode = LegacyMode::UNKNOWN;
@@ -2568,6 +2607,38 @@ StaIface::removeQosPolicyForScsInternal(const std::vector<uint8_t>& scsPolicyIds
 	return ndk::ScopedAStatus::ok();
 }
 
+std::pair<UsdCapabilities, ndk::ScopedAStatus> StaIface::getUsdCapabilitiesInternal() {
+	UsdCapabilities capabilities;
+	return {capabilities, ndk::ScopedAStatus::ok()};
+}
+
+ndk::ScopedAStatus StaIface::startUsdPublishInternal(
+		const UsdPublishConfig& usdPublishConfig) {
+	return createStatus(SupplicantStatusCode::FAILURE_UNSUPPORTED);
+}
+
+ndk::ScopedAStatus StaIface::startUsdSubscribeInternal(
+		const UsdSubscribeConfig& usdSubscribeConfig) {
+	return createStatus(SupplicantStatusCode::FAILURE_UNSUPPORTED);
+}
+
+::ndk::ScopedAStatus StaIface::updateUsdPublishInternal(int32_t publishId,
+		const std::vector<uint8_t>& serviceSpecificInfo) {
+	return createStatus(SupplicantStatusCode::FAILURE_UNSUPPORTED);
+}
+
+::ndk::ScopedAStatus StaIface::cancelUsdPublishInternal(int32_t publishId) {
+	return createStatus(SupplicantStatusCode::FAILURE_UNSUPPORTED);
+}
+
+::ndk::ScopedAStatus StaIface::cancelUsdSubscribeInternal(int32_t subscribeId) {
+	return createStatus(SupplicantStatusCode::FAILURE_UNSUPPORTED);
+}
+
+::ndk::ScopedAStatus StaIface::sendUsdMessageInternal(const UsdMessageInfo& messageInfo) {
+	return createStatus(SupplicantStatusCode::FAILURE_UNSUPPORTED);
+}
+
 /**
  * Retrieve the underlying |wpa_supplicant| struct
  * pointer for this iface.
diff --git a/wpa_supplicant/aidl/sta_iface.h b/wpa_supplicant/aidl/vendor/sta_iface.h
similarity index 92%
rename from wpa_supplicant/aidl/sta_iface.h
rename to wpa_supplicant/aidl/vendor/sta_iface.h
index b52c6b0c..6c6cfb96 100644
--- a/wpa_supplicant/aidl/sta_iface.h
+++ b/wpa_supplicant/aidl/vendor/sta_iface.h
@@ -167,6 +167,16 @@ public:
 		std::vector<QosPolicyScsRequestStatus>* _aidl_return) override;
 	::ndk::ScopedAStatus configureMscs(const MscsParams& in_params) override;
 	::ndk::ScopedAStatus disableMscs() override;
+	::ndk::ScopedAStatus getUsdCapabilities(UsdCapabilities* _aidl_return);
+	::ndk::ScopedAStatus startUsdPublish(int32_t in_cmdId,
+		const UsdPublishConfig& in_usdPublishConfig);
+	::ndk::ScopedAStatus startUsdSubscribe(int32_t in_cmdId,
+		const UsdSubscribeConfig& in_usdSubscribeConfig);
+	::ndk::ScopedAStatus updateUsdPublish(int32_t in_publishId,
+		const std::vector<uint8_t>& in_serviceSpecificInfo);
+	::ndk::ScopedAStatus cancelUsdPublish(int32_t in_publishId);
+	::ndk::ScopedAStatus cancelUsdSubscribe(int32_t in_subscribeId);
+	::ndk::ScopedAStatus sendUsdMessage(const UsdMessageInfo& in_messageInfo);
 
 private:
 	// Corresponding worker functions for the AIDL methods.
@@ -281,6 +291,14 @@ private:
 		const std::vector<uint8_t>& scsPolicyIds);
 	::ndk::ScopedAStatus configureMscsInternal(const MscsParams& params);
 	::ndk::ScopedAStatus disableMscsInternal();
+	std::pair<UsdCapabilities, ndk::ScopedAStatus> getUsdCapabilitiesInternal();
+	::ndk::ScopedAStatus startUsdPublishInternal(const UsdPublishConfig& usdPublishConfig);
+	::ndk::ScopedAStatus startUsdSubscribeInternal(const UsdSubscribeConfig& usdSubscribeConfig);
+	::ndk::ScopedAStatus updateUsdPublishInternal(int32_t publishId,
+		const std::vector<uint8_t>& serviceSpecificInfo);
+	::ndk::ScopedAStatus cancelUsdPublishInternal(int32_t publishId);
+	::ndk::ScopedAStatus cancelUsdSubscribeInternal(int32_t subscribeId);
+	::ndk::ScopedAStatus sendUsdMessageInternal(const UsdMessageInfo& messageInfo);
 
 	struct wpa_supplicant* retrieveIfacePtr();
 
diff --git a/wpa_supplicant/aidl/sta_network.cpp b/wpa_supplicant/aidl/vendor/sta_network.cpp
similarity index 100%
rename from wpa_supplicant/aidl/sta_network.cpp
rename to wpa_supplicant/aidl/vendor/sta_network.cpp
diff --git a/wpa_supplicant/aidl/sta_network.h b/wpa_supplicant/aidl/vendor/sta_network.h
similarity index 100%
rename from wpa_supplicant/aidl/sta_network.h
rename to wpa_supplicant/aidl/vendor/sta_network.h
diff --git a/wpa_supplicant/aidl/supplicant.cpp b/wpa_supplicant/aidl/vendor/supplicant.cpp
similarity index 97%
rename from wpa_supplicant/aidl/supplicant.cpp
rename to wpa_supplicant/aidl/vendor/supplicant.cpp
index ae1943fd..0cb23423 100644
--- a/wpa_supplicant/aidl/supplicant.cpp
+++ b/wpa_supplicant/aidl/vendor/supplicant.cpp
@@ -12,6 +12,8 @@
 #include "supplicant.h"
 #include "p2p_iface.h"
 
+#include "aidl/shared/shared_utils.h"
+
 #include <android-base/file.h>
 #include <fcntl.h>
 #include <sys/stat.h>
@@ -22,8 +24,6 @@ namespace {
 // Note: This may differ for other OEM's. So, modify this accordingly.
 // When wpa_supplicant is in its APEX, overlay/template configurations should be
 // loaded from the same APEX.
-constexpr char kIfaceDriverName[] = "nl80211";
-
 constexpr char kStaIfaceConfPath[] =
 	"/data/vendor/wifi/wpa/wpa_supplicant.conf";
 constexpr char kStaIfaceConfOverlayPath[] =
@@ -42,7 +42,6 @@ constexpr char kVendorTemplateConfPath[] =
 
 constexpr char kOldStaIfaceConfPath[] = "/data/misc/wifi/wpa_supplicant.conf";
 constexpr char kOldP2pIfaceConfPath[] = "/data/misc/wifi/p2p_supplicant.conf";
-constexpr mode_t kConfigFileMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
 
 std::string resolveVendorConfPath(const std::string& conf_path)
 {
@@ -114,26 +113,15 @@ int ensureConfigFileExists(
 	const std::string& config_file_path,
 	const std::string& old_config_file_path)
 {
-	int ret = access(config_file_path.c_str(), R_OK | W_OK);
+	// Check if config file already exists at |config_file_path|
+	int ret = ensureConfigFileExistsAtPath(config_file_path);
 	if (ret == 0) {
+		wpa_printf(MSG_INFO, "Config file already exists at %s", config_file_path.c_str());
 		return 0;
-	}
-	if (errno == EACCES) {
-		ret = chmod(config_file_path.c_str(), kConfigFileMode);
-		if (ret == 0) {
-			return 0;
-		} else {
-			wpa_printf(
-				MSG_ERROR, "Cannot set RW to %s. Errno: %s",
-				config_file_path.c_str(), strerror(errno));
-			return -1;
-		}
-	} else if (errno != ENOENT) {
-		wpa_printf(
-			MSG_ERROR, "Cannot acces %s. Errno: %s",
-			config_file_path.c_str(), strerror(errno));
+	} else if (ret != ENOENT) {
 		return -1;
 	}
+
 	ret = copyFileIfItExists(old_config_file_path, config_file_path);
 	if (ret == 0) {
 		wpa_printf(
@@ -145,6 +133,7 @@ int ensureConfigFileExists(
 		unlink(config_file_path.c_str());
 		return -1;
 	}
+
 	std::string vendor_template_conf_path = resolveVendorConfPath(kVendorTemplateConfPath);
 	ret = copyFileIfItExists(vendor_template_conf_path, config_file_path);
 	if (ret == 0) {
@@ -156,6 +145,7 @@ int ensureConfigFileExists(
 		unlink(config_file_path.c_str());
 		return -1;
 	}
+
 	ret = copyFileIfItExists(kSystemTemplateConfPath, config_file_path);
 	if (ret == 0) {
 		wpa_printf(
@@ -166,6 +156,7 @@ int ensureConfigFileExists(
 		unlink(config_file_path.c_str());
 		return -1;
 	}
+
 	// Did not create the conf file.
 	return -1;
 }
diff --git a/wpa_supplicant/aidl/supplicant.h b/wpa_supplicant/aidl/vendor/supplicant.h
similarity index 100%
rename from wpa_supplicant/aidl/supplicant.h
rename to wpa_supplicant/aidl/vendor/supplicant.h
diff --git a/wpa_supplicant/bgscan_learn.c b/wpa_supplicant/bgscan_learn.c
index cab4ae2a..bc9f3240 100644
--- a/wpa_supplicant/bgscan_learn.c
+++ b/wpa_supplicant/bgscan_learn.c
@@ -280,6 +280,11 @@ static void bgscan_learn_timeout(void *eloop_ctx, void *timeout_ctx)
 	params.num_ssids = 1;
 	params.ssids[0].ssid = data->ssid->ssid;
 	params.ssids[0].ssid_len = data->ssid->ssid_len;
+
+	/* Add OWE transition mode SSID of the current network */
+	wpa_add_owe_scan_ssid(wpa_s, &params, data->ssid,
+			      wpa_s->max_scan_ssids - params.num_ssids);
+
 	if (data->ssid->scan_freq)
 		params.freqs = data->ssid->scan_freq;
 	else {
diff --git a/wpa_supplicant/bgscan_simple.c b/wpa_supplicant/bgscan_simple.c
index a90cf86e..d9aaa634 100644
--- a/wpa_supplicant/bgscan_simple.c
+++ b/wpa_supplicant/bgscan_simple.c
@@ -89,6 +89,10 @@ static void bgscan_simple_timeout(void *eloop_ctx, void *timeout_ctx)
 	params.ssids[0].ssid_len = data->ssid->ssid_len;
 	params.freqs = data->ssid->scan_freq;
 
+	/* Add OWE transition mode SSID of the current network */
+	wpa_add_owe_scan_ssid(wpa_s, &params, data->ssid,
+			      wpa_s->max_scan_ssids - params.num_ssids);
+
 	/*
 	 * A more advanced bgscan module would learn about most like channels
 	 * over time and request scans only for some channels (probing others
diff --git a/wpa_supplicant/bss.c b/wpa_supplicant/bss.c
index cf94d4be..39de8bac 100644
--- a/wpa_supplicant/bss.c
+++ b/wpa_supplicant/bss.c
@@ -273,6 +273,57 @@ struct wpa_bss * wpa_bss_get(struct wpa_supplicant *wpa_s, const u8 *bssid,
 	return NULL;
 }
 
+/**
+ * wpa_bss_get_connection - Fetch a BSS table entry based on BSSID and SSID.
+ * @wpa_s: Pointer to wpa_supplicant data
+ * @bssid: BSSID, or %NULL to match any BSSID
+ * @ssid: SSID
+ * @ssid_len: Length of @ssid
+ * Returns: Pointer to the BSS entry or %NULL if not found
+ *
+ * This function is similar to wpa_bss_get() but it will also return OWE
+ * transition mode encrypted networks for which transition-element matches
+ * @ssid.
+ */
+struct wpa_bss * wpa_bss_get_connection(struct wpa_supplicant *wpa_s,
+					const u8 *bssid,
+					const u8 *ssid, size_t ssid_len)
+{
+	struct wpa_bss *bss;
+#ifdef CONFIG_OWE
+	const u8 *owe, *owe_bssid, *owe_ssid;
+	size_t owe_ssid_len;
+#endif /* CONFIG_OWE */
+
+	if (bssid && !wpa_supplicant_filter_bssid_match(wpa_s, bssid))
+		return NULL;
+	dl_list_for_each(bss, &wpa_s->bss, struct wpa_bss, list) {
+		if (bssid && !ether_addr_equal(bss->bssid, bssid))
+			continue;
+
+		if (bss->ssid_len == ssid_len &&
+		    os_memcmp(bss->ssid, ssid, ssid_len) == 0)
+			return bss;
+
+#ifdef CONFIG_OWE
+		/* Check if OWE transition mode element is present and matches
+		 * the SSID */
+		owe = wpa_bss_get_vendor_ie(bss, OWE_IE_VENDOR_TYPE);
+		if (!owe)
+			continue;
+
+		if (wpas_get_owe_trans_network(owe, &owe_bssid, &owe_ssid,
+					       &owe_ssid_len))
+			continue;
+
+		if (owe_ssid_len == ssid_len &&
+		    os_memcmp(owe_ssid, ssid, ssid_len) == 0)
+			return bss;
+#endif /* CONFIG_OWE */
+	}
+	return NULL;
+}
+
 
 void calculate_update_time(const struct os_reltime *fetch_time,
 			   unsigned int age_ms,
diff --git a/wpa_supplicant/bss.h b/wpa_supplicant/bss.h
index 508129c3..31688fa5 100644
--- a/wpa_supplicant/bss.h
+++ b/wpa_supplicant/bss.h
@@ -165,6 +165,9 @@ void wpa_bss_flush(struct wpa_supplicant *wpa_s);
 void wpa_bss_flush_by_age(struct wpa_supplicant *wpa_s, int age);
 struct wpa_bss * wpa_bss_get(struct wpa_supplicant *wpa_s, const u8 *bssid,
 			     const u8 *ssid, size_t ssid_len);
+struct wpa_bss * wpa_bss_get_connection(struct wpa_supplicant *wpa_s,
+					const u8 *bssid,
+					const u8 *ssid, size_t ssid_len);
 struct wpa_bss * wpa_bss_get_bssid(struct wpa_supplicant *wpa_s,
 				   const u8 *bssid);
 struct wpa_bss * wpa_bss_get_bssid_latest(struct wpa_supplicant *wpa_s,
diff --git a/wpa_supplicant/config.c b/wpa_supplicant/config.c
index 0f98f778..5b084788 100644
--- a/wpa_supplicant/config.c
+++ b/wpa_supplicant/config.c
@@ -3096,6 +3096,7 @@ void wpa_config_free(struct wpa_config *config)
 	os_free(config->dpp_mud_url);
 	os_free(config->dpp_extra_conf_req_name);
 	os_free(config->dpp_extra_conf_req_value);
+	wpabuf_free(config->dik);
 
 	os_free(config);
 }
@@ -5496,6 +5497,8 @@ static const struct global_parse_data global_fields[] = {
 	{ INT(p2p_interface_random_mac_addr), 0 },
 	{ INT(p2p_6ghz_disable), 0 },
 	{ INT(p2p_dfs_chan_enable), 0 },
+	{ INT(dik_cipher), 0},
+	{ BIN(dik), 0 },
 #endif /* CONFIG_P2P */
 	{ FUNC(country), CFG_CHANGED_COUNTRY },
 	{ INT(bss_max_count), 0 },
diff --git a/wpa_supplicant/config.h b/wpa_supplicant/config.h
index 7ea43a66..12817867 100644
--- a/wpa_supplicant/config.h
+++ b/wpa_supplicant/config.h
@@ -1843,6 +1843,12 @@ struct wpa_config {
 
 	int mld_force_single_link;
 #endif /* CONFIG_TESTING_OPTIONS */
+
+	/* Cipher version type */
+	int dik_cipher;
+
+	/* DevIK */
+	struct wpabuf *dik;
 };
 
 
diff --git a/wpa_supplicant/config_file.c b/wpa_supplicant/config_file.c
index fa829eba..53614ae0 100644
--- a/wpa_supplicant/config_file.c
+++ b/wpa_supplicant/config_file.c
@@ -1634,7 +1634,11 @@ static void wpa_config_write_global(FILE *f, struct wpa_config *config)
 			MAC2STR(config->mld_connect_bssid_pref));
 #endif /* CONFIG_TESTING_OPTIONS */
 	if (config->ft_prepend_pmkid)
-		fprintf(f, "ft_prepend_pmkid=%d", config->ft_prepend_pmkid);
+		fprintf(f, "ft_prepend_pmkid=%d\n", config->ft_prepend_pmkid);
+	if (config->dik) {
+		fprintf(f, "dik_cipher=%d\n", config->dik_cipher);
+		write_global_bin(f, "dik", config->dik);
+	}
 }
 
 #endif /* CONFIG_NO_CONFIG_WRITE */
diff --git a/wpa_supplicant/ctrl_iface.c b/wpa_supplicant/ctrl_iface.c
index d245531c..a8fc9625 100644
--- a/wpa_supplicant/ctrl_iface.c
+++ b/wpa_supplicant/ctrl_iface.c
@@ -6035,7 +6035,7 @@ static int wpa_supplicant_ctrl_iface_roam(struct wpa_supplicant *wpa_s,
 		return -1;
 	}
 
-	bss = wpa_bss_get(wpa_s, bssid, ssid->ssid, ssid->ssid_len);
+	bss = wpa_bss_get_connection(wpa_s, bssid, ssid->ssid, ssid->ssid_len);
 	if (!bss) {
 		wpa_printf(MSG_DEBUG, "CTRL_IFACE ROAM: Target AP not found "
 			   "from BSS table");
@@ -6376,6 +6376,10 @@ static int p2p_ctrl_connect(struct wpa_supplicant *wpa_s, char *cmd,
 	size_t group_ssid_len = 0;
 	int he;
 	bool allow_6ghz;
+	bool p2p2;
+	u16 bootstrap = 0;
+	const char *password = NULL;
+	char *token, *context = NULL;
 
 	if (!wpa_s->global->p2p_init_wpa_s)
 		return -1;
@@ -6385,10 +6389,12 @@ static int p2p_ctrl_connect(struct wpa_supplicant *wpa_s, char *cmd,
 		wpa_s = wpa_s->global->p2p_init_wpa_s;
 	}
 
-	/* <addr> <"pbc" | "pin" | PIN> [label|display|keypad|p2ps]
+	/* <addr> <"pbc" | "pin" | "pair" | PIN> [label|display|keypad|p2ps]
 	 * [persistent|persistent=<network id>]
 	 * [join] [auth] [go_intent=<0..15>] [freq=<in MHz>] [provdisc]
-	 * [ht40] [vht] [he] [edmg] [auto] [ssid=<hexdump>] */
+	 * [ht40] [vht] [he] [edmg] [auto] [ssid=<hexdump>]
+	 * [p2p2] [bstrapmethod=<value>] [password=<string>]
+	 */
 
 	if (hwaddr_aton(cmd, addr))
 		return -1;
@@ -6422,6 +6428,7 @@ static int p2p_ctrl_connect(struct wpa_supplicant *wpa_s, char *cmd,
 		vht;
 	he = (os_strstr(cmd, " he") != NULL) || wpa_s->conf->p2p_go_he;
 	edmg = (os_strstr(cmd, " edmg") != NULL) || wpa_s->conf->p2p_go_edmg;
+	p2p2 = os_strstr(pos, " p2p2") != NULL;
 
 	pos2 = os_strstr(pos, " go_intent=");
 	if (pos2) {
@@ -6477,6 +6484,8 @@ static int p2p_ctrl_connect(struct wpa_supplicant *wpa_s, char *cmd,
 		wps_method = WPS_PBC;
 	} else if (os_strstr(pos, "p2ps") != NULL) {
 		wps_method = WPS_P2PS;
+	} else if (os_strncmp(pos, "pair", 4) == 0 && p2p2) {
+		wps_method = WPS_NOT_READY;
 	} else {
 		pin = pos;
 		pos = os_strchr(pin, ' ');
@@ -6492,11 +6501,26 @@ static int p2p_ctrl_connect(struct wpa_supplicant *wpa_s, char *cmd,
 		}
 	}
 
+	pos2 = os_strstr(pos, "bstrapmethod=");
+	if (pos2) {
+		pos2 += 13;
+		bootstrap = atoi(pos2);
+		pd = true;
+	}
+
+	while ((token = str_token(pos, " ", &context))) {
+		if (os_strncmp(token, "password=", 9) == 0) {
+			password = token + 9;
+			continue;
+		}
+	}
+
 	new_pin = wpas_p2p_connect(wpa_s, addr, pin, wps_method,
 				   persistent_group, automatic, join,
 				   auth, go_intent, freq, freq2, persistent_id,
 				   pd, ht40, vht, max_oper_chwidth, he, edmg,
-				   group_ssid, group_ssid_len, allow_6ghz);
+				   group_ssid, group_ssid_len, allow_6ghz, p2p2,
+				   bootstrap, password);
 	if (new_pin == -2) {
 		os_memcpy(buf, "FAIL-CHANNEL-UNAVAILABLE\n", 25);
 		return 25;
@@ -7172,7 +7196,7 @@ static int p2p_ctrl_group_add_persistent(struct wpa_supplicant *wpa_s,
 		return -1;
 	}
 
-	return wpas_p2p_group_add_persistent(wpa_s, ssid, 0, freq, 0,
+	return wpas_p2p_group_add_persistent(wpa_s, ssid, 0, freq, freq,
 					     vht_center_freq2, ht40, vht,
 					     vht_chwidth, he, edmg,
 					     NULL, 0, 0, allow_6ghz, 0,
@@ -8650,6 +8674,7 @@ static int wpa_supplicant_driver_cmd(struct wpa_supplicant *wpa_s, char *cmd,
 	int ret;
 
 	ret = wpa_drv_driver_cmd(wpa_s, cmd, buf, buflen);
+#ifdef CONFIG_P2P
 	if (ret == 0) {
 		if (os_strncasecmp(cmd, "COUNTRY", 7) == 0) {
 			struct p2p_data *p2p = wpa_s->global->p2p;
@@ -8665,6 +8690,7 @@ static int wpa_supplicant_driver_cmd(struct wpa_supplicant *wpa_s, char *cmd,
 		if (os_snprintf_error(buflen, ret))
 			ret = -1;
 	}
+#endif /* CONFIG_P2P */
 	return ret;
 }
 #endif /* ANDROID */
@@ -12202,6 +12228,7 @@ static int wpas_ctrl_nan_publish(struct wpa_supplicant *wpa_s, char *cmd,
 	int ret = -1;
 	enum nan_service_protocol_type srv_proto_type = 0;
 	int *freq_list = NULL;
+	bool p2p = false;
 
 	os_memset(&params, 0, sizeof(params));
 	/* USD shall use both solicited and unsolicited transmissions */
@@ -12262,6 +12289,11 @@ static int wpas_ctrl_nan_publish(struct wpa_supplicant *wpa_s, char *cmd,
 			continue;
 		}
 
+		if (os_strcmp(token, "p2p=1") == 0) {
+			p2p = true;
+			continue;
+		}
+
 		if (os_strcmp(token, "solicited=0") == 0) {
 			params.solicited = false;
 			continue;
@@ -12283,7 +12315,7 @@ static int wpas_ctrl_nan_publish(struct wpa_supplicant *wpa_s, char *cmd,
 	}
 
 	publish_id = wpas_nan_usd_publish(wpa_s, service_name, srv_proto_type,
-					  ssi, &params);
+					  ssi, &params, p2p);
 	if (publish_id > 0)
 		ret = os_snprintf(buf, buflen, "%d", publish_id);
 fail:
@@ -12367,6 +12399,8 @@ static int wpas_ctrl_nan_subscribe(struct wpa_supplicant *wpa_s, char *cmd,
 	struct wpabuf *ssi = NULL;
 	int ret = -1;
 	enum nan_service_protocol_type srv_proto_type = 0;
+	int *freq_list = NULL;
+	bool p2p = false;
 
 	os_memset(&params, 0, sizeof(params));
 	params.freq = NAN_USD_DEFAULT_FREQ;
@@ -12392,6 +12426,27 @@ static int wpas_ctrl_nan_subscribe(struct wpa_supplicant *wpa_s, char *cmd,
 			continue;
 		}
 
+		if (os_strncmp(token, "freq_list=", 10) == 0) {
+			char *pos = token + 10;
+
+			if (os_strcmp(pos, "all") == 0) {
+				os_free(freq_list);
+				freq_list = wpas_nan_usd_all_freqs(wpa_s);
+				params.freq_list = freq_list;
+				continue;
+			}
+
+			while (pos && pos[0]) {
+				int_array_add_unique(&freq_list, atoi(pos));
+				pos = os_strchr(pos, ',');
+				if (pos)
+					pos++;
+			}
+
+			params.freq_list = freq_list;
+			continue;
+		}
+
 		if (os_strncmp(token, "srv_proto_type=", 15) == 0) {
 			srv_proto_type = atoi(token + 15);
 			continue;
@@ -12406,6 +12461,11 @@ static int wpas_ctrl_nan_subscribe(struct wpa_supplicant *wpa_s, char *cmd,
 			continue;
 		}
 
+		if (os_strcmp(token, "p2p=1") == 0) {
+			p2p = true;
+			continue;
+		}
+
 		wpa_printf(MSG_INFO,
 			   "CTRL: Invalid NAN_SUBSCRIBE parameter: %s",
 			   token);
@@ -12414,11 +12474,12 @@ static int wpas_ctrl_nan_subscribe(struct wpa_supplicant *wpa_s, char *cmd,
 
 	subscribe_id = wpas_nan_usd_subscribe(wpa_s, service_name,
 					      srv_proto_type, ssi,
-					      &params);
+					      &params, p2p);
 	if (subscribe_id > 0)
 		ret = os_snprintf(buf, buflen, "%d", subscribe_id);
 fail:
 	wpabuf_free(ssi);
+	os_free(freq_list);
 	return ret;
 }
 
diff --git a/wpa_supplicant/dbus/dbus_new.c b/wpa_supplicant/dbus/dbus_new.c
index 76e42ffb..5ad5bcd7 100644
--- a/wpa_supplicant/dbus/dbus_new.c
+++ b/wpa_supplicant/dbus/dbus_new.c
@@ -2396,6 +2396,10 @@ void wpas_dbus_signal_prop_changed(struct wpa_supplicant *wpa_s,
 	case WPAS_DBUS_PROP_ROAM_COMPLETE:
 		prop = "RoamComplete";
 		break;
+	case WPAS_DBUS_PROP_SCAN_IN_PROGRESS_6GHZ:
+		prop = "ScanInProgress6GHz";
+		flush = TRUE;
+		break;
 	case WPAS_DBUS_PROP_SESSION_LENGTH:
 		prop = "SessionLength";
 		break;
@@ -3983,6 +3987,12 @@ static const struct wpa_dbus_property_desc wpas_dbus_interface_properties[] = {
 	  NULL,
 	  NULL
 	},
+	{
+	  "ScanInProgress6GHz", WPAS_DBUS_NEW_IFACE_INTERFACE, "b",
+	  wpas_dbus_getter_scan_in_progress_6ghz,
+	  NULL,
+	  NULL
+	},
 	{
 	  "SessionLength", WPAS_DBUS_NEW_IFACE_INTERFACE, "u",
 	  wpas_dbus_getter_session_length,
diff --git a/wpa_supplicant/dbus/dbus_new.h b/wpa_supplicant/dbus/dbus_new.h
index 952bb422..1db5fe8a 100644
--- a/wpa_supplicant/dbus/dbus_new.h
+++ b/wpa_supplicant/dbus/dbus_new.h
@@ -36,6 +36,7 @@ enum wpas_dbus_prop {
 	WPAS_DBUS_PROP_ASSOC_STATUS_CODE,
 	WPAS_DBUS_PROP_ROAM_TIME,
 	WPAS_DBUS_PROP_ROAM_COMPLETE,
+	WPAS_DBUS_PROP_SCAN_IN_PROGRESS_6GHZ,
 	WPAS_DBUS_PROP_SESSION_LENGTH,
 	WPAS_DBUS_PROP_BSS_TM_STATUS,
 	WPAS_DBUS_PROP_MAC_ADDRESS,
diff --git a/wpa_supplicant/dbus/dbus_new_handlers.c b/wpa_supplicant/dbus/dbus_new_handlers.c
index 960b3069..52e35a77 100644
--- a/wpa_supplicant/dbus/dbus_new_handlers.c
+++ b/wpa_supplicant/dbus/dbus_new_handlers.c
@@ -3835,6 +3835,29 @@ dbus_bool_t wpas_dbus_getter_roam_complete(
 }
 
 
+/**
+ * wpas_dbus_getter_scan_in_progress_6ghz - Get whether a 6 GHz scan is in
+ * progress
+ * @iter: Pointer to incoming dbus message iter
+ * @error: Location to store error on failure
+ * @user_data: Function specific data
+ * Returns: TRUE on success, FALSE on failure
+ *
+ * Getter function for "ScanInProgress6GHz" property.
+ */
+dbus_bool_t wpas_dbus_getter_scan_in_progress_6ghz(
+	const struct wpa_dbus_property_desc *property_desc,
+	DBusMessageIter *iter, DBusError *error, void *user_data)
+{
+	struct wpa_supplicant *wpa_s = user_data;
+	dbus_bool_t scan_in_progress_6ghz = wpa_s->scan_in_progress_6ghz ?
+		TRUE : FALSE;
+
+	return wpas_dbus_simple_property_getter(iter, DBUS_TYPE_BOOLEAN,
+						&scan_in_progress_6ghz, error);
+}
+
+
 /**
  * wpas_dbus_getter_session_length - Get most recent BSS session length
  * @iter: Pointer to incoming dbus message iter
diff --git a/wpa_supplicant/dbus/dbus_new_handlers.h b/wpa_supplicant/dbus/dbus_new_handlers.h
index acd6af7f..7faf70a7 100644
--- a/wpa_supplicant/dbus/dbus_new_handlers.h
+++ b/wpa_supplicant/dbus/dbus_new_handlers.h
@@ -173,6 +173,7 @@ DECLARE_ACCESSOR(wpas_dbus_getter_auth_status_code);
 DECLARE_ACCESSOR(wpas_dbus_getter_assoc_status_code);
 DECLARE_ACCESSOR(wpas_dbus_getter_roam_time);
 DECLARE_ACCESSOR(wpas_dbus_getter_roam_complete);
+DECLARE_ACCESSOR(wpas_dbus_getter_scan_in_progress_6ghz);
 DECLARE_ACCESSOR(wpas_dbus_getter_session_length);
 DECLARE_ACCESSOR(wpas_dbus_getter_bss_tm_status);
 DECLARE_ACCESSOR(wpas_dbus_getter_bss_expire_age);
diff --git a/wpa_supplicant/dbus/dbus_new_handlers_p2p.c b/wpa_supplicant/dbus/dbus_new_handlers_p2p.c
index 418a8fd4..65bd478c 100644
--- a/wpa_supplicant/dbus/dbus_new_handlers_p2p.c
+++ b/wpa_supplicant/dbus/dbus_new_handlers_p2p.c
@@ -473,7 +473,7 @@ DBusMessage * wpas_dbus_handler_p2p_group_add(DBusMessage *message,
 		if (ssid == NULL || ssid->disabled != 2)
 			goto inv_args;
 
-		if (wpas_p2p_group_add_persistent(wpa_s, ssid, 0, freq, 0,
+		if (wpas_p2p_group_add_persistent(wpa_s, ssid, 0, freq, freq,
 						  freq2, ht40, vht,
 						  max_oper_chwidth, he, edmg,
 						  NULL, 0, 0, allow_6ghz,
@@ -706,7 +706,7 @@ DBusMessage * wpas_dbus_handler_p2p_connect(DBusMessage *message,
 	new_pin = wpas_p2p_connect(wpa_s, addr, pin, wps_method,
 				   persistent_group, 0, join, authorize_only,
 				   go_intent, freq, 0, -1, 0, 0, 0, 0, 0, 0,
-				   NULL, 0, false);
+				   NULL, 0, false, 0, 0, NULL);
 
 	if (new_pin >= 0) {
 		char npin[9];
diff --git a/wpa_supplicant/dpp_supplicant.c b/wpa_supplicant/dpp_supplicant.c
index 216224f4..1b2c756f 100644
--- a/wpa_supplicant/dpp_supplicant.c
+++ b/wpa_supplicant/dpp_supplicant.c
@@ -29,7 +29,7 @@
 #include "scan.h"
 #include "notify.h"
 #include "dpp_supplicant.h"
-#include "aidl/aidl.h"
+#include "aidl/vendor/aidl.h"
 
 
 static int wpas_dpp_listen_start(struct wpa_supplicant *wpa_s,
@@ -1433,6 +1433,17 @@ static struct wpa_ssid * wpas_dpp_add_network(struct wpa_supplicant *wpa_s,
 	os_memcpy(ssid->ssid, conf->ssid, conf->ssid_len);
 	ssid->ssid_len = conf->ssid_len;
 
+#ifdef CONFIG_DPP3
+	if (conf->akm == DPP_AKM_SAE && conf->password_id[0]) {
+		size_t len = os_strlen(conf->password_id);
+
+		ssid->sae_password_id = os_zalloc(len + 1);
+		if (!ssid->sae_password_id)
+			goto fail;
+		os_memcpy(ssid->sae_password_id, conf->password_id, len);
+	}
+#endif /* CONFIG_DPP3 */
+
 	if (conf->connector) {
 		if (dpp_akm_dpp(conf->akm)) {
 			ssid->key_mgmt = WPA_KEY_MGMT_DPP;
@@ -1490,12 +1501,17 @@ static struct wpa_ssid * wpas_dpp_add_network(struct wpa_supplicant *wpa_s,
 			ssid->ieee80211w = MGMT_FRAME_PROTECTION_OPTIONAL;
 		else
 			ssid->ieee80211w = MGMT_FRAME_PROTECTION_REQUIRED;
-		if (conf->passphrase[0]) {
+		if (conf->passphrase[0] && dpp_akm_psk(conf->akm)) {
 			if (wpa_config_set_quoted(ssid, "psk",
 						  conf->passphrase) < 0)
 				goto fail;
 			wpa_config_update_psk(ssid);
 			ssid->export_keys = 1;
+		} else if (conf->passphrase[0] && dpp_akm_sae(conf->akm)) {
+			if (wpa_config_set_quoted(ssid, "sae_password",
+						  conf->passphrase) < 0)
+				goto fail;
+			ssid->export_keys = 1;
 		} else {
 			ssid->psk_set = conf->psk_set;
 			os_memcpy(ssid->psk, conf->psk, PMK_LEN);
@@ -1709,6 +1725,12 @@ static int wpas_dpp_handle_config_obj(struct wpa_supplicant *wpa_s,
 		wpa_msg(wpa_s, MSG_INFO, DPP_EVENT_CONFOBJ_PSK "%s",
 			hex);
 	}
+#ifdef CONFIG_DPP3
+	if (conf->password_id[0]) {
+		wpa_msg(wpa_s, MSG_INFO, DPP_EVENT_CONFOBJ_IDPASS "%s",
+			conf->password_id);
+	}
+#endif /* CONFIG_DPP3 */
 	if (conf->c_sign_key) {
 		char *hex;
 		size_t hexlen;
diff --git a/wpa_supplicant/driver_i.h b/wpa_supplicant/driver_i.h
index d01b52bb..b6c7f508 100644
--- a/wpa_supplicant/driver_i.h
+++ b/wpa_supplicant/driver_i.h
@@ -9,6 +9,7 @@
 #ifndef DRIVER_I_H
 #define DRIVER_I_H
 
+#include "common/nan_de.h"
 #include "drivers/driver.h"
 
 /* driver_ops */
@@ -1175,4 +1176,75 @@ wpas_drv_get_sta_mlo_info(struct wpa_supplicant *wpa_s,
 	return wpa_s->driver->get_sta_mlo_info(wpa_s->drv_priv, mlo_info);
 }
 
+static inline int
+wpas_drv_nan_flush(struct wpa_supplicant *wpa_s)
+{
+	if (!wpa_s->driver->nan_flush)
+		return 0;
+
+	return wpa_s->driver->nan_flush(wpa_s->drv_priv);
+}
+
+static inline int
+wpas_drv_nan_publish(struct wpa_supplicant *wpa_s, const u8 *addr,
+		     int publish_id, const char *service_name,
+		     const u8 *service_id,
+		     enum nan_service_protocol_type srv_proto_type,
+		     const struct wpabuf *ssi, const struct wpabuf *elems,
+		     struct nan_publish_params *params)
+{
+	if (!wpa_s->driver->nan_publish)
+		return 0;
+
+	return wpa_s->driver->nan_publish(wpa_s->drv_priv, addr, publish_id,
+					  service_name, service_id,
+					  srv_proto_type, ssi, elems, params);
+}
+
+static inline int
+wpas_drv_nan_cancel_publish(struct wpa_supplicant *wpa_s, int publish_id)
+{
+	if (!wpa_s->driver->nan_cancel_publish)
+		return 0;
+
+	return wpa_s->driver->nan_cancel_publish(wpa_s->drv_priv, publish_id);
+}
+
+static inline int
+wpas_drv_nan_update_publish(struct wpa_supplicant *wpa_s, int publish_id,
+			    const struct wpabuf *ssi)
+{
+	if (!wpa_s->driver->nan_update_publish)
+		return 0;
+
+	return wpa_s->driver->nan_update_publish(wpa_s->drv_priv, publish_id,
+						 ssi);
+}
+
+static inline int
+wpas_drv_nan_subscribe(struct wpa_supplicant *wpa_s, const u8 *addr,
+		       int subscribe_id, const char *service_name,
+		       const u8 *service_id,
+		       enum nan_service_protocol_type srv_proto_type,
+		       const struct wpabuf *ssi, const struct wpabuf *elems,
+		       struct nan_subscribe_params *params)
+{
+	if (!wpa_s->driver->nan_subscribe)
+		return 0;
+
+	return wpa_s->driver->nan_subscribe(wpa_s->drv_priv, addr, subscribe_id,
+					    service_name, service_id,
+					    srv_proto_type, ssi, elems, params);
+}
+
+static inline int
+wpas_drv_nan_cancel_subscribe(struct wpa_supplicant *wpa_s, int subscribe_id)
+{
+	if (!wpa_s->driver->nan_cancel_subscribe)
+		return 0;
+
+	return wpa_s->driver->nan_cancel_subscribe(wpa_s->drv_priv,
+						   subscribe_id);
+}
+
 #endif /* DRIVER_I_H */
diff --git a/wpa_supplicant/events.c b/wpa_supplicant/events.c
index 09a2bbb5..2a665d7c 100644
--- a/wpa_supplicant/events.c
+++ b/wpa_supplicant/events.c
@@ -9,6 +9,7 @@
 #include "includes.h"
 
 #include "common.h"
+#include "utils/crc32.h"
 #include "eapol_supp/eapol_supp_sm.h"
 #include "rsn_supp/wpa.h"
 #include "eloop.h"
@@ -1140,30 +1141,20 @@ static void owe_trans_ssid(struct wpa_supplicant *wpa_s, struct wpa_bss *bss,
 			   const u8 **ret_ssid, size_t *ret_ssid_len)
 {
 #ifdef CONFIG_OWE
-	const u8 *owe, *pos, *end, *bssid;
-	u8 ssid_len;
+	const u8 *owe, *bssid;
 
 	owe = wpa_bss_get_vendor_ie(bss, OWE_IE_VENDOR_TYPE);
 	if (!owe || !wpa_bss_get_rsne(wpa_s, bss, NULL, false))
 		return;
 
-	pos = owe + 6;
-	end = owe + 2 + owe[1];
-
-	if (end - pos < ETH_ALEN + 1)
-		return;
-	bssid = pos;
-	pos += ETH_ALEN;
-	ssid_len = *pos++;
-	if (end - pos < ssid_len || ssid_len > SSID_MAX_LEN)
+	if (wpas_get_owe_trans_network(owe, &bssid, ret_ssid, ret_ssid_len))
 		return;
 
 	/* Match the profile SSID against the OWE transition mode SSID on the
 	 * open network. */
 	wpa_dbg(wpa_s, MSG_DEBUG, "OWE: transition mode BSSID: " MACSTR
-		" SSID: %s", MAC2STR(bssid), wpa_ssid_txt(pos, ssid_len));
-	*ret_ssid = pos;
-	*ret_ssid_len = ssid_len;
+		" SSID: %s", MAC2STR(bssid),
+		wpa_ssid_txt(*ret_ssid, *ret_ssid_len));
 
 	if (!(bss->flags & WPA_BSS_OWE_TRANSITION)) {
 		struct wpa_ssid *ssid;
@@ -1171,8 +1162,8 @@ static void owe_trans_ssid(struct wpa_supplicant *wpa_s, struct wpa_bss *bss,
 		for (ssid = wpa_s->conf->ssid; ssid; ssid = ssid->next) {
 			if (wpas_network_disabled(wpa_s, ssid))
 				continue;
-			if (ssid->ssid_len == ssid_len &&
-			    os_memcmp(ssid->ssid, pos, ssid_len) == 0) {
+			if (ssid->ssid_len == *ret_ssid_len &&
+			    os_memcmp(ssid->ssid, ret_ssid, *ret_ssid_len) == 0) {
 				/* OWE BSS in transition mode for a currently
 				 * enabled OWE network. */
 				wpa_dbg(wpa_s, MSG_DEBUG,
@@ -2411,6 +2402,78 @@ static int wpa_supplicant_need_to_roam(struct wpa_supplicant *wpa_s,
 }
 
 
+static int wpas_trigger_6ghz_scan(struct wpa_supplicant *wpa_s,
+				  union wpa_event_data *data)
+{
+	struct wpa_driver_scan_params params;
+	unsigned int j;
+
+	wpa_dbg(wpa_s, MSG_INFO, "Triggering 6GHz-only scan");
+	os_memset(&params, 0, sizeof(params));
+	params.non_coloc_6ghz = wpa_s->last_scan_non_coloc_6ghz;
+	for (j = 0; j < data->scan_info.num_ssids; j++)
+		params.ssids[j] = data->scan_info.ssids[j];
+	params.num_ssids = data->scan_info.num_ssids;
+	wpa_add_scan_freqs_list(wpa_s, HOSTAPD_MODE_IEEE80211A, &params,
+				true, false, false);
+	if (!wpa_supplicant_trigger_scan(wpa_s, &params, true, true)) {
+		wpa_s->scan_in_progress_6ghz = true;
+		wpas_notify_scan_in_progress_6ghz(wpa_s);
+		os_free(params.freqs);
+		return 1;
+	}
+	wpa_dbg(wpa_s, MSG_INFO, "Failed to trigger 6GHz-only scan");
+	os_free(params.freqs);
+	return 0;
+}
+
+
+static bool wpas_short_ssid_match(struct wpa_supplicant *wpa_s,
+				  struct wpa_scan_results *scan_res)
+{
+	size_t i;
+	struct wpa_ssid *ssid = wpa_s->current_ssid;
+	u32 current_ssid_short = ieee80211_crc32(ssid->ssid, ssid->ssid_len);
+
+	for (i = 0; i < scan_res->num; i++) {
+		struct wpa_scan_res *res = scan_res->res[i];
+		const u8 *rnr_ie, *ie_end;
+		const struct ieee80211_neighbor_ap_info *info;
+		size_t left;
+
+		rnr_ie = wpa_scan_get_ie(res, WLAN_EID_REDUCED_NEIGHBOR_REPORT);
+		if (!rnr_ie)
+			continue;
+
+		ie_end = rnr_ie + 2 + rnr_ie[1];
+		rnr_ie += 2;
+
+		left = ie_end - rnr_ie;
+		if (left < sizeof(struct ieee80211_neighbor_ap_info))
+			continue;
+
+		info = (const struct ieee80211_neighbor_ap_info *) rnr_ie;
+		if (info->tbtt_info_len < 11)
+			continue; /* short SSID not included */
+		left -= sizeof(struct ieee80211_neighbor_ap_info);
+		rnr_ie += sizeof(struct ieee80211_neighbor_ap_info);
+
+		while (left >= info->tbtt_info_len && rnr_ie + 11 <= ie_end) {
+			/* Skip TBTT offset and BSSID */
+			u32 short_ssid = WPA_GET_LE32(rnr_ie + 1 + ETH_ALEN);
+
+			if (short_ssid == current_ssid_short)
+				return true;
+
+			left -= info->tbtt_info_len;
+			rnr_ie += info->tbtt_info_len;
+		}
+	}
+
+	return false;
+}
+
+
 /*
  * Return a negative value if no scan results could be fetched or if scan
  * results should not be shared with other virtual interfaces.
@@ -2428,6 +2491,7 @@ static int _wpa_supplicant_event_scan_results(struct wpa_supplicant *wpa_s,
 	int ret = 0;
 	int ap = 0;
 	bool trigger_6ghz_scan;
+	bool short_ssid_match_found = false;
 #ifndef CONFIG_NO_RANDOM_POOL
 	size_t i, num;
 #endif /* CONFIG_NO_RANDOM_POOL */
@@ -2447,6 +2511,12 @@ static int _wpa_supplicant_event_scan_results(struct wpa_supplicant *wpa_s,
 	scan_res = wpa_supplicant_get_scan_results(wpa_s,
 						   data ? &data->scan_info :
 						   NULL, 1, NULL);
+
+	if (wpa_s->scan_in_progress_6ghz) {
+		wpa_s->scan_in_progress_6ghz = false;
+		wpas_notify_scan_in_progress_6ghz(wpa_s);
+	}
+
 	if (scan_res == NULL) {
 		if (wpa_s->conf->ap_scan == 2 || ap ||
 		    wpa_s->scan_res_handler == scan_only_handler)
@@ -2537,9 +2607,6 @@ static int _wpa_supplicant_event_scan_results(struct wpa_supplicant *wpa_s,
 		return 0;
 	}
 
-	if (wnm_scan_process(wpa_s, false) > 0)
-		goto scan_work_done;
-
 	if (sme_proc_obss_scan(wpa_s) > 0)
 		goto scan_work_done;
 
@@ -2569,10 +2636,19 @@ static int _wpa_supplicant_event_scan_results(struct wpa_supplicant *wpa_s,
 
 	wpas_wps_update_ap_info(wpa_s, scan_res);
 
+	if (wnm_scan_process(wpa_s, false) > 0)
+		goto scan_work_done;
+
 	if (wpa_s->wpa_state >= WPA_AUTHENTICATING &&
 	    wpa_s->wpa_state < WPA_COMPLETED)
 		goto scan_work_done;
 
+	if (wpa_s->current_ssid && trigger_6ghz_scan && own_request && data &&
+	    wpas_short_ssid_match(wpa_s, scan_res)) {
+		wpa_dbg(wpa_s, MSG_INFO, "Short SSID match in scan results");
+		short_ssid_match_found = true;
+	}
+
 	wpa_scan_results_free(scan_res);
 
 	if (own_request && wpa_s->scan_work) {
@@ -2599,6 +2675,9 @@ static int _wpa_supplicant_event_scan_results(struct wpa_supplicant *wpa_s,
 	if (wpa_s->supp_pbc_active && !wpas_wps_partner_link_scan_done(wpa_s))
 		return ret;
 
+	if (short_ssid_match_found && wpas_trigger_6ghz_scan(wpa_s, data) > 0)
+		return 1;
+
 	return wpas_select_network_from_last_scan(wpa_s, 1, own_request,
 						  trigger_6ghz_scan, data);
 
@@ -2613,30 +2692,6 @@ scan_work_done:
 }
 
 
-static int wpas_trigger_6ghz_scan(struct wpa_supplicant *wpa_s,
-				  union wpa_event_data *data)
-{
-	struct wpa_driver_scan_params params;
-	unsigned int j;
-
-	wpa_dbg(wpa_s, MSG_INFO, "Triggering 6GHz-only scan");
-	os_memset(&params, 0, sizeof(params));
-	params.non_coloc_6ghz = wpa_s->last_scan_non_coloc_6ghz;
-	for (j = 0; j < data->scan_info.num_ssids; j++)
-		params.ssids[j] = data->scan_info.ssids[j];
-	params.num_ssids = data->scan_info.num_ssids;
-	wpa_add_scan_freqs_list(wpa_s, HOSTAPD_MODE_IEEE80211A, &params,
-				true, !wpa_s->last_scan_non_coloc_6ghz, false);
-	if (!wpa_supplicant_trigger_scan(wpa_s, &params, true, true)) {
-		os_free(params.freqs);
-		return 1;
-	}
-	wpa_dbg(wpa_s, MSG_INFO, "Failed to trigger 6GHz-only scan");
-	os_free(params.freqs);
-	return 0;
-}
-
-
 /**
  * Select a network from the last scan
  * @wpa_s: Pointer to wpa_supplicant data
@@ -2727,7 +2782,7 @@ static int wpas_select_network_from_last_scan(struct wpa_supplicant *wpa_s,
 				wpa_supplicant_rsn_preauth_scan_results(wpa_s);
 		} else if (own_request) {
 			if (wpa_s->support_6ghz && trigger_6ghz_scan && data &&
-			    wpas_trigger_6ghz_scan(wpa_s, data) < 0)
+			    wpas_trigger_6ghz_scan(wpa_s, data) > 0)
 				return 1;
 
 			/*
@@ -3375,13 +3430,17 @@ static int wpa_supplicant_use_own_rsne_params(struct wpa_supplicant *wpa_s,
 static int wpa_supplicant_event_associnfo(struct wpa_supplicant *wpa_s,
 					  union wpa_event_data *data)
 {
-	int l, len, found = 0, found_x = 0, wpa_found, rsn_found;
-	const u8 *p;
+	int l, len, found = 0, wpa_found, rsn_found;
+#ifndef CONFIG_NO_WPA
+	int found_x = 0;
+#endif /* CONFIG_NO_WPA */
+	const u8 *p, *ie;
 	u8 bssid[ETH_ALEN];
 	bool bssid_known;
 #if defined(CONFIG_DRIVER_NL80211_BRCM) || defined(CONFIG_DRIVER_NL80211_SYNA)
-	struct wpa_ie_data ie;
+	struct wpa_ie_data wpa_ie;
 #endif /* CONFIG_DRIVER_NL80211_BRCM || CONFIG_DRIVER_NL80211_SYNA */
+	enum wpa_rsn_override rsn_override;
 
 	wpa_dbg(wpa_s, MSG_DEBUG, "Association info event");
 	wpa_s->ssid_verified = false;
@@ -3510,18 +3569,22 @@ static int wpa_supplicant_event_associnfo(struct wpa_supplicant *wpa_s,
 			wpa_find_assoc_pmkid(wpa_s,
 					     data->assoc_info.authorized);
 		}
+#ifndef CONFIG_NO_WPA
 		if (!found_x && p[0] == WLAN_EID_RSNX) {
 			if (wpa_sm_set_assoc_rsnxe(wpa_s->wpa, p, len))
 				break;
 			found_x = 1;
 		}
+#endif /* CONFIG_NO_WPA */
 		l -= len;
 		p += len;
 	}
 	if (!found && data->assoc_info.req_ies)
 		wpa_sm_set_assoc_wpa_ie(wpa_s->wpa, NULL, 0);
+#ifndef CONFIG_NO_WPA
 	if (!found_x && data->assoc_info.req_ies)
 		wpa_sm_set_assoc_rsnxe(wpa_s->wpa, NULL, 0);
+#endif /* CONFIG_NO_WPA */
 
 #if defined(CONFIG_DRIVER_NL80211_BRCM) || defined(CONFIG_DRIVER_NL80211_SYNA)
 	/* The WPA/RSN IE has been updated at this point. Since the Firmware could have roamed
@@ -3529,12 +3592,12 @@ static int wpa_supplicant_event_associnfo(struct wpa_supplicant *wpa_s,
 	 * and pairwise suites from the assoc IE passed by the driver.
 	 */
 	if (wpas_driver_bss_selection(wpa_s)) {
-		if (!(wpa_sm_parse_own_wpa_ie(wpa_s->wpa, &ie) < 0)) {
+		if (!(wpa_sm_parse_own_wpa_ie(wpa_s->wpa, &wpa_ie) < 0)) {
 			/* Check if firmware has roamed to a different security network */
-			if(wpa_s->key_mgmt != ie.key_mgmt) {
+			if(wpa_s->key_mgmt != wpa_ie.key_mgmt) {
 				wpa_dbg(wpa_s, MSG_DEBUG, "Update to AKM suite 0x%x from Assoc IE",
-					ie.key_mgmt);
-				wpa_s->key_mgmt = ie.key_mgmt;
+					wpa_ie.key_mgmt);
+				wpa_s->key_mgmt = wpa_ie.key_mgmt;
 				wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_KEY_MGMT, wpa_s->key_mgmt);
 
 				if (wpa_key_mgmt_wpa_psk_no_sae(wpa_s->key_mgmt)) {
@@ -3557,10 +3620,10 @@ static int wpa_supplicant_event_associnfo(struct wpa_supplicant *wpa_s,
 					}
 				}
 			}
-			if(wpa_s->pairwise_cipher != ie.pairwise_cipher) {
+			if(wpa_s->pairwise_cipher != wpa_ie.pairwise_cipher) {
 				wpa_dbg(wpa_s, MSG_DEBUG, "Update to pairwise cipher suite 0x%x "
-					"from Assoc IE", ie.pairwise_cipher);
-				wpa_s->pairwise_cipher = ie.pairwise_cipher;
+					"from Assoc IE", wpa_ie.pairwise_cipher);
+				wpa_s->pairwise_cipher = wpa_ie.pairwise_cipher;
 				wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_PAIRWISE,
 					wpa_s->pairwise_cipher);
 			}
@@ -3569,6 +3632,25 @@ static int wpa_supplicant_event_associnfo(struct wpa_supplicant *wpa_s,
 	}
 #endif /* CONFIG_DRIVER_NL80211_BRCM || CONFIG_DRIVER_NL80211_SYNA */
 
+	rsn_override = RSN_OVERRIDE_NOT_USED;
+	ie = get_vendor_ie(data->assoc_info.req_ies,
+			   data->assoc_info.req_ies_len,
+			   RSN_SELECTION_IE_VENDOR_TYPE);
+	if (ie && ie[1] >= 4 + 1) {
+		switch (ie[2 + 4]) {
+		case RSN_SELECTION_RSNE:
+			rsn_override = RSN_OVERRIDE_RSNE;
+			break;
+		case RSN_SELECTION_RSNE_OVERRIDE:
+			rsn_override = RSN_OVERRIDE_RSNE_OVERRIDE;
+			break;
+		case RSN_SELECTION_RSNE_OVERRIDE_2:
+			rsn_override = RSN_OVERRIDE_RSNE_OVERRIDE_2;
+			break;
+		}
+	}
+	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_RSN_OVERRIDE, rsn_override);
+
 #ifdef CONFIG_FILS
 #ifdef CONFIG_SME
 	if (wpa_s->sme.auth_alg == WPA_AUTH_ALG_FILS ||
@@ -3764,28 +3846,20 @@ no_pfs:
 			wpa_sm_set_ap_rsn_ie(wpa_s->wpa, p, len);
 		}
 
-		if (wpas_rsn_overriding(wpa_s) &&
-		    p[0] == WLAN_EID_VENDOR_SPECIFIC && p[1] >= 6 &&
-		    WPA_GET_BE32(&p[2]) == RSNE_OVERRIDE_2_IE_VENDOR_TYPE) {
-			rsn_found = 1;
-			wpa_sm_set_ap_rsn_ie(wpa_s->wpa, p, len);
-		}
+		if (p[0] == WLAN_EID_VENDOR_SPECIFIC && p[1] >= 6 &&
+		    WPA_GET_BE32(&p[2]) == RSNE_OVERRIDE_2_IE_VENDOR_TYPE)
+			wpa_sm_set_ap_rsne_override_2(wpa_s->wpa, p, len);
 
-		if (!rsn_found &&
-		    wpas_rsn_overriding(wpa_s) &&
-		    p[0] == WLAN_EID_VENDOR_SPECIFIC && p[1] >= 6 &&
-		    WPA_GET_BE32(&p[2]) == RSNE_OVERRIDE_IE_VENDOR_TYPE) {
-			rsn_found = 1;
-			wpa_sm_set_ap_rsn_ie(wpa_s->wpa, p, len);
-		}
+		if (p[0] == WLAN_EID_VENDOR_SPECIFIC && p[1] >= 6 &&
+		    WPA_GET_BE32(&p[2]) == RSNE_OVERRIDE_IE_VENDOR_TYPE)
+			wpa_sm_set_ap_rsne_override(wpa_s->wpa, p, len);
 
 		if (p[0] == WLAN_EID_RSNX && p[1] >= 1)
 			wpa_sm_set_ap_rsnxe(wpa_s->wpa, p, len);
 
-		if (wpas_rsn_overriding(wpa_s) &&
-		    p[0] == WLAN_EID_VENDOR_SPECIFIC && p[1] >= 6 &&
+		if (p[0] == WLAN_EID_VENDOR_SPECIFIC && p[1] >= 6 &&
 		    WPA_GET_BE32(&p[2]) == RSNXE_OVERRIDE_IE_VENDOR_TYPE)
-			wpa_sm_set_ap_rsnxe(wpa_s->wpa, p, len);
+			wpa_sm_set_ap_rsnxe_override(wpa_s->wpa, p, len);
 
 		l -= len;
 		p += len;
@@ -3796,6 +3870,9 @@ no_pfs:
 	if (!rsn_found && data->assoc_info.beacon_ies) {
 		wpa_sm_set_ap_rsn_ie(wpa_s->wpa, NULL, 0);
 		wpa_sm_set_ap_rsnxe(wpa_s->wpa, NULL, 0);
+		wpa_sm_set_ap_rsne_override(wpa_s->wpa, NULL, 0);
+		wpa_sm_set_ap_rsne_override_2(wpa_s->wpa, NULL, 0);
+		wpa_sm_set_ap_rsnxe_override(wpa_s->wpa, NULL, 0);
 	}
 	if (wpa_found || rsn_found)
 		wpa_s->ap_ies_from_associnfo = 1;
@@ -3831,6 +3908,7 @@ no_pfs:
 static int wpa_supplicant_assoc_update_ie(struct wpa_supplicant *wpa_s)
 {
 	const u8 *bss_wpa = NULL, *bss_rsn = NULL, *bss_rsnx = NULL;
+	const u8 *rsnoe, *rsno2e, *rsnxoe;
 
 	if (!wpa_s->current_bss || !wpa_s->current_ssid)
 		return -1;
@@ -3840,17 +3918,27 @@ static int wpa_supplicant_assoc_update_ie(struct wpa_supplicant *wpa_s)
 
 	bss_wpa = wpa_bss_get_vendor_ie(wpa_s->current_bss,
 					WPA_IE_VENDOR_TYPE);
-	bss_rsn = wpa_bss_get_rsne(wpa_s, wpa_s->current_bss, NULL,
-				   wpa_s->valid_links);
-	bss_rsnx = wpa_bss_get_rsnxe(wpa_s, wpa_s->current_bss, NULL,
-				     wpa_s->valid_links);
+	bss_rsn = wpa_bss_get_ie(wpa_s->current_bss, WLAN_EID_RSN);
+	bss_rsnx = wpa_bss_get_ie(wpa_s->current_bss, WLAN_EID_RSNX);
+	rsnoe = wpa_bss_get_vendor_ie(wpa_s->current_bss,
+				      RSNE_OVERRIDE_IE_VENDOR_TYPE);
+	rsno2e = wpa_bss_get_vendor_ie(wpa_s->current_bss,
+				       RSNE_OVERRIDE_2_IE_VENDOR_TYPE);
+	rsnxoe = wpa_bss_get_vendor_ie(wpa_s->current_bss,
+				       RSNXE_OVERRIDE_IE_VENDOR_TYPE);
 
 	if (wpa_sm_set_ap_wpa_ie(wpa_s->wpa, bss_wpa,
 				 bss_wpa ? 2 + bss_wpa[1] : 0) ||
 	    wpa_sm_set_ap_rsn_ie(wpa_s->wpa, bss_rsn,
 				 bss_rsn ? 2 + bss_rsn[1] : 0) ||
 	    wpa_sm_set_ap_rsnxe(wpa_s->wpa, bss_rsnx,
-				 bss_rsnx ? 2 + bss_rsnx[1] : 0))
+				 bss_rsnx ? 2 + bss_rsnx[1] : 0) ||
+	    wpa_sm_set_ap_rsne_override(wpa_s->wpa, rsnoe,
+					rsnoe ? 2 + rsnoe[1] : 0) ||
+	    wpa_sm_set_ap_rsne_override_2(wpa_s->wpa, rsno2e,
+					  rsno2e ? 2 + rsno2e[1] : 0) ||
+	    wpa_sm_set_ap_rsnxe_override(wpa_s->wpa, rsnxoe,
+					 rsnxoe ? 2 + rsnxoe[1] : 0))
 		return -1;
 
 	return 0;
@@ -4203,7 +4291,6 @@ static int wpa_sm_set_ml_info(struct wpa_supplicant *wpa_s)
 {
 	struct driver_sta_mlo_info drv_mlo;
 	struct wpa_sm_mlo wpa_mlo;
-	const u8 *bss_rsn = NULL, *bss_rsnx = NULL;
 	int i;
 
 	os_memset(&drv_mlo, 0, sizeof(drv_mlo));
@@ -4223,6 +4310,7 @@ static int wpa_sm_set_ml_info(struct wpa_supplicant *wpa_s)
 
 	for_each_link(drv_mlo.req_links, i) {
 		struct wpa_bss *bss;
+		const u8 *rsne, *rsnxe, *rsnoe, *rsno2e, *rsnxoe;
 
 		bss = wpa_supplicant_get_new_bss(wpa_s, drv_mlo.links[i].bssid);
 		if (!bss) {
@@ -4231,13 +4319,25 @@ static int wpa_sm_set_ml_info(struct wpa_supplicant *wpa_s)
 			return -1;
 		}
 
-		bss_rsn = wpa_bss_get_rsne(wpa_s, bss, NULL, true);
-		bss_rsnx = wpa_bss_get_rsnxe(wpa_s, bss, NULL, true);
-
-		wpa_mlo.links[i].ap_rsne = bss_rsn ? (u8 *) bss_rsn : NULL;
-		wpa_mlo.links[i].ap_rsne_len = bss_rsn ? 2 + bss_rsn[1] : 0;
-		wpa_mlo.links[i].ap_rsnxe = bss_rsnx ? (u8 *) bss_rsnx : NULL;
-		wpa_mlo.links[i].ap_rsnxe_len = bss_rsnx ? 2 + bss_rsnx[1] : 0;
+		rsne = wpa_bss_get_ie(bss, WLAN_EID_RSN);
+		rsnxe = wpa_bss_get_ie(bss, WLAN_EID_RSNX);
+		rsnoe = wpa_bss_get_vendor_ie(bss,
+					      RSNE_OVERRIDE_IE_VENDOR_TYPE);
+		rsno2e = wpa_bss_get_vendor_ie(bss,
+					       RSNE_OVERRIDE_2_IE_VENDOR_TYPE);
+		rsnxoe = wpa_bss_get_vendor_ie(bss,
+					       RSNXE_OVERRIDE_IE_VENDOR_TYPE);
+
+		wpa_mlo.links[i].ap_rsne = rsne ? (u8 *) rsne : NULL;
+		wpa_mlo.links[i].ap_rsne_len = rsne ? 2 + rsne[1] : 0;
+		wpa_mlo.links[i].ap_rsnxe = rsnxe ? (u8 *) rsnxe : NULL;
+		wpa_mlo.links[i].ap_rsnxe_len = rsnxe ? 2 + rsnxe[1] : 0;
+		wpa_mlo.links[i].ap_rsnoe = rsnoe ? (u8 *) rsnoe : NULL;
+		wpa_mlo.links[i].ap_rsnoe_len = rsnoe ? 2 + rsnoe[1] : 0;
+		wpa_mlo.links[i].ap_rsno2e = rsno2e ? (u8 *) rsno2e : NULL;
+		wpa_mlo.links[i].ap_rsno2e_len = rsno2e ? 2 + rsno2e[1] : 0;
+		wpa_mlo.links[i].ap_rsnxoe = rsnxoe ? (u8 *) rsnxoe : NULL;
+		wpa_mlo.links[i].ap_rsnxoe_len = rsnxoe ? 2 + rsnxoe[1] : 0;
 
 		os_memcpy(wpa_mlo.links[i].bssid, drv_mlo.links[i].bssid,
 			  ETH_ALEN);
@@ -6159,6 +6259,17 @@ static void wpas_link_reconfig(struct wpa_supplicant *wpa_s)
 		wpa_s->valid_links);
 }
 
+#ifdef MAINLINE_SUPPLICANT
+static bool is_event_allowlisted(enum wpa_event_type event) {
+	return event == EVENT_SCAN_STARTED ||
+	       event == EVENT_SCAN_RESULTS ||
+	       event == EVENT_RX_MGMT ||
+	       event == EVENT_REMAIN_ON_CHANNEL ||
+	       event == EVENT_CANCEL_REMAIN_ON_CHANNEL ||
+	       event == EVENT_TX_WAIT_EXPIRE;
+}
+#endif /* MAINLINE_SUPPLICANT */
+
 
 void wpa_supplicant_event(void *ctx, enum wpa_event_type event,
 			  union wpa_event_data *data)
@@ -6170,6 +6281,15 @@ void wpa_supplicant_event(void *ctx, enum wpa_event_type event,
 	int level = MSG_DEBUG;
 #endif /* CONFIG_NO_STDOUT_DEBUG */
 
+#ifdef MAINLINE_SUPPLICANT
+	if (!is_event_allowlisted(event)) {
+		wpa_dbg(wpa_s, MSG_DEBUG,
+			"Ignore event %s (%d) which is not allowlisted",
+			event_to_string(event), event);
+		return;
+	}
+#endif /* MAINLINE_SUPPLICANT */
+
 	if (wpa_s->wpa_state == WPA_INTERFACE_DISABLED &&
 	    event != EVENT_INTERFACE_ENABLED &&
 	    event != EVENT_INTERFACE_STATUS &&
diff --git a/wpa_supplicant/main.c b/wpa_supplicant/main.c
index 9229eb51..517c6bc9 100644
--- a/wpa_supplicant/main.c
+++ b/wpa_supplicant/main.c
@@ -178,7 +178,9 @@ static int wpa_supplicant_init_match(struct wpa_global *global)
 }
 #endif /* CONFIG_MATCH_IFACE */
 
-
+// Temporarily allow the fuzzer library to redefine main()
+// TODO: Remove this flag once mainline supplicant does not include this file
+#ifndef SUPPLICANT_SERVICE_FUZZER
 int main(int argc, char *argv[])
 {
 	int c, i;
@@ -409,3 +411,4 @@ out:
 
 	return exitcode;
 }
+#endif /* SUPPLICANT_SERVICE_FUZZER */
diff --git a/wpa_supplicant/nan_usd.c b/wpa_supplicant/nan_usd.c
index 657b302c..1125f950 100644
--- a/wpa_supplicant/nan_usd.c
+++ b/wpa_supplicant/nan_usd.c
@@ -13,6 +13,8 @@
 #include "wpa_supplicant_i.h"
 #include "offchannel.h"
 #include "driver_i.h"
+#include "notify.h"
+#include "p2p_supplicant.h"
 #include "nan_usd.h"
 
 
@@ -241,19 +243,10 @@ wpas_nan_de_discovery_result(void *ctx, int subscribe_id,
 			     const u8 *peer_addr, bool fsd, bool fsd_gas)
 {
 	struct wpa_supplicant *wpa_s = ctx;
-	char *ssi_hex;
 
-	ssi_hex = os_zalloc(2 * ssi_len + 1);
-	if (!ssi_hex)
-		return;
-	if (ssi)
-		wpa_snprintf_hex(ssi_hex, 2 * ssi_len + 1, ssi, ssi_len);
-	wpa_msg(wpa_s, MSG_INFO, NAN_DISCOVERY_RESULT
-		"subscribe_id=%d publish_id=%d address=" MACSTR
-		" fsd=%d fsd_gas=%d srv_proto_type=%u ssi=%s",
-		subscribe_id, peer_publish_id, MAC2STR(peer_addr),
-		fsd, fsd_gas, srv_proto_type, ssi_hex);
-	os_free(ssi_hex);
+	wpas_notify_nan_discovery_result(wpa_s, srv_proto_type, subscribe_id,
+					 peer_publish_id, peer_addr, fsd,
+					 fsd_gas, ssi, ssi_len);
 }
 
 
@@ -263,34 +256,9 @@ static void wpas_nan_de_replied(void *ctx, int publish_id, const u8 *peer_addr,
 				const u8 *ssi, size_t ssi_len)
 {
 	struct wpa_supplicant *wpa_s = ctx;
-	char *ssi_hex;
 
-	ssi_hex = os_zalloc(2 * ssi_len + 1);
-	if (!ssi_hex)
-		return;
-	if (ssi)
-		wpa_snprintf_hex(ssi_hex, 2 * ssi_len + 1, ssi, ssi_len);
-	wpa_msg(wpa_s, MSG_INFO, NAN_REPLIED
-		"publish_id=%d address=" MACSTR
-		" subscribe_id=%d srv_proto_type=%u ssi=%s",
-		publish_id, MAC2STR(peer_addr), peer_subscribe_id,
-		srv_proto_type, ssi_hex);
-	os_free(ssi_hex);
-}
-
-
-static const char * nan_reason_txt(enum nan_de_reason reason)
-{
-	switch (reason) {
-	case NAN_DE_REASON_TIMEOUT:
-		return "timeout";
-	case NAN_DE_REASON_USER_REQUEST:
-		return "user-request";
-	case NAN_DE_REASON_FAILURE:
-		return "failure";
-	}
-
-	return "unknown";
+	wpas_notify_nan_replied(wpa_s, srv_proto_type, publish_id,
+				peer_subscribe_id, peer_addr, ssi, ssi_len);
 }
 
 
@@ -299,9 +267,7 @@ static void wpas_nan_de_publish_terminated(void *ctx, int publish_id,
 {
 	struct wpa_supplicant *wpa_s = ctx;
 
-	wpa_msg(wpa_s, MSG_INFO, NAN_PUBLISH_TERMINATED
-		"publish_id=%d reason=%s",
-		publish_id, nan_reason_txt(reason));
+	wpas_notify_nan_publish_terminated(wpa_s, publish_id, reason);
 }
 
 
@@ -310,9 +276,7 @@ static void wpas_nan_de_subscribe_terminated(void *ctx, int subscribe_id,
 {
 	struct wpa_supplicant *wpa_s = ctx;
 
-	wpa_msg(wpa_s, MSG_INFO, NAN_SUBSCRIBE_TERMINATED
-		"subscribe_id=%d reason=%s",
-		subscribe_id, nan_reason_txt(reason));
+	wpas_notify_nan_subscribe_terminated(wpa_s, subscribe_id, reason);
 }
 
 
@@ -321,23 +285,28 @@ static void wpas_nan_de_receive(void *ctx, int id, int peer_instance_id,
 				const u8 *peer_addr)
 {
 	struct wpa_supplicant *wpa_s = ctx;
-	char *ssi_hex;
 
-	ssi_hex = os_zalloc(2 * ssi_len + 1);
-	if (!ssi_hex)
-		return;
-	if (ssi)
-		wpa_snprintf_hex(ssi_hex, 2 * ssi_len + 1, ssi, ssi_len);
-	wpa_msg(wpa_s, MSG_INFO, NAN_RECEIVE
-		"id=%d peer_instance_id=%d address=" MACSTR " ssi=%s",
-		id, peer_instance_id, MAC2STR(peer_addr), ssi_hex);
-	os_free(ssi_hex);
+	wpas_notify_nan_receive(wpa_s, id, peer_instance_id, peer_addr,
+				ssi, ssi_len);
 }
 
 
+#ifdef CONFIG_P2P
+static void wpas_nan_process_p2p_usd_elems(void *ctx, const u8 *buf,
+					   u16 buf_len, const u8 *peer_addr,
+					   unsigned int freq)
+{
+	struct wpa_supplicant *wpa_s = ctx;
+
+	wpas_p2p_process_usd_elems(wpa_s, buf, buf_len, peer_addr, freq);
+}
+#endif /* CONFIG_P2P */
+
+
 int wpas_nan_usd_init(struct wpa_supplicant *wpa_s)
 {
 	struct nan_callbacks cb;
+	bool offload = wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_OFFLOAD;
 
 	os_memset(&cb, 0, sizeof(cb));
 	cb.ctx = wpa_s;
@@ -348,8 +317,11 @@ int wpas_nan_usd_init(struct wpa_supplicant *wpa_s)
 	cb.publish_terminated = wpas_nan_de_publish_terminated;
 	cb.subscribe_terminated = wpas_nan_de_subscribe_terminated;
 	cb.receive = wpas_nan_de_receive;
+#ifdef CONFIG_P2P
+	cb.process_p2p_usd_elems = wpas_nan_process_p2p_usd_elems;
+#endif /* CONFIG_P2P */
 
-	wpa_s->nan_de = nan_de_init(wpa_s->own_addr, false, &cb);
+	wpa_s->nan_de = nan_de_init(wpa_s->own_addr, offload, false, &cb);
 	if (!wpa_s->nan_de)
 		return -1;
 	return 0;
@@ -377,22 +349,42 @@ void wpas_nan_usd_flush(struct wpa_supplicant *wpa_s)
 	if (!wpa_s->nan_de)
 		return;
 	nan_de_flush(wpa_s->nan_de);
+	if (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_OFFLOAD)
+		wpas_drv_nan_flush(wpa_s);
 }
 
 
 int wpas_nan_usd_publish(struct wpa_supplicant *wpa_s, const char *service_name,
 			 enum nan_service_protocol_type srv_proto_type,
 			 const struct wpabuf *ssi,
-			 struct nan_publish_params *params)
+			 struct nan_publish_params *params, bool p2p)
 {
 	int publish_id;
 	struct wpabuf *elems = NULL;
+	const u8 *addr;
 
 	if (!wpa_s->nan_de)
 		return -1;
 
+	if (p2p) {
+		elems = wpas_p2p_usd_elems(wpa_s);
+		addr = wpa_s->global->p2p_dev_addr;
+	} else {
+		addr = wpa_s->own_addr;
+	}
+
 	publish_id = nan_de_publish(wpa_s->nan_de, service_name, srv_proto_type,
-				    ssi, elems, params);
+				    ssi, elems, params, p2p);
+	if (publish_id >= 1 &&
+	    (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_OFFLOAD) &&
+	    wpas_drv_nan_publish(wpa_s, addr, publish_id, service_name,
+				 nan_de_get_service_id(wpa_s->nan_de,
+						       publish_id),
+				 srv_proto_type, ssi, elems, params) < 0) {
+		nan_de_cancel_publish(wpa_s->nan_de, publish_id);
+		publish_id = -1;
+	}
+
 	wpabuf_free(elems);
 	return publish_id;
 }
@@ -403,15 +395,23 @@ void wpas_nan_usd_cancel_publish(struct wpa_supplicant *wpa_s, int publish_id)
 	if (!wpa_s->nan_de)
 		return;
 	nan_de_cancel_publish(wpa_s->nan_de, publish_id);
+	if (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_OFFLOAD)
+		wpas_drv_nan_cancel_publish(wpa_s, publish_id);
 }
 
 
 int wpas_nan_usd_update_publish(struct wpa_supplicant *wpa_s, int publish_id,
 				const struct wpabuf *ssi)
 {
+	int ret;
+
 	if (!wpa_s->nan_de)
 		return -1;
-	return nan_de_update_publish(wpa_s->nan_de, publish_id, ssi);
+	ret = nan_de_update_publish(wpa_s->nan_de, publish_id, ssi);
+	if (ret == 0 && (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_OFFLOAD) &&
+	    wpas_drv_nan_cancel_publish(wpa_s, publish_id) < 0)
+		return -1;
+	return ret;
 }
 
 
@@ -419,16 +419,35 @@ int wpas_nan_usd_subscribe(struct wpa_supplicant *wpa_s,
 			   const char *service_name,
 			   enum nan_service_protocol_type srv_proto_type,
 			   const struct wpabuf *ssi,
-			   struct nan_subscribe_params *params)
+			   struct nan_subscribe_params *params, bool p2p)
 {
 	int subscribe_id;
 	struct wpabuf *elems = NULL;
+	const u8 *addr;
 
 	if (!wpa_s->nan_de)
 		return -1;
 
+	if (p2p) {
+		elems = wpas_p2p_usd_elems(wpa_s);
+		addr = wpa_s->global->p2p_dev_addr;
+	} else {
+		addr = wpa_s->own_addr;
+	}
+
 	subscribe_id = nan_de_subscribe(wpa_s->nan_de, service_name,
-					srv_proto_type, ssi, elems, params);
+					srv_proto_type, ssi, elems, params,
+					p2p);
+	if (subscribe_id >= 1 &&
+	    (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_OFFLOAD) &&
+	    wpas_drv_nan_subscribe(wpa_s, addr, subscribe_id, service_name,
+				   nan_de_get_service_id(wpa_s->nan_de,
+							 subscribe_id),
+				   srv_proto_type, ssi, elems, params) < 0) {
+		nan_de_cancel_subscribe(wpa_s->nan_de, subscribe_id);
+		subscribe_id = -1;
+	}
+
 	wpabuf_free(elems);
 	return subscribe_id;
 }
@@ -440,6 +459,8 @@ void wpas_nan_usd_cancel_subscribe(struct wpa_supplicant *wpa_s,
 	if (!wpa_s->nan_de)
 		return;
 	nan_de_cancel_subscribe(wpa_s->nan_de, subscribe_id);
+	if (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_OFFLOAD)
+		wpas_drv_nan_cancel_subscribe(wpa_s, subscribe_id);
 }
 
 
diff --git a/wpa_supplicant/nan_usd.h b/wpa_supplicant/nan_usd.h
index 149ac9e6..ecb4973c 100644
--- a/wpa_supplicant/nan_usd.h
+++ b/wpa_supplicant/nan_usd.h
@@ -21,7 +21,7 @@ void wpas_nan_usd_flush(struct wpa_supplicant *wpa_s);
 int wpas_nan_usd_publish(struct wpa_supplicant *wpa_s, const char *service_name,
 			 enum nan_service_protocol_type srv_proto_type,
 			 const struct wpabuf *ssi,
-			 struct nan_publish_params *params);
+			 struct nan_publish_params *params, bool p2p);
 void wpas_nan_usd_cancel_publish(struct wpa_supplicant *wpa_s, int publish_id);
 int wpas_nan_usd_update_publish(struct wpa_supplicant *wpa_s, int publish_id,
 				const struct wpabuf *ssi);
@@ -29,7 +29,7 @@ int wpas_nan_usd_subscribe(struct wpa_supplicant *wpa_s,
 			   const char *service_name,
 			   enum nan_service_protocol_type srv_proto_type,
 			   const struct wpabuf *ssi,
-			   struct nan_subscribe_params *params);
+			   struct nan_subscribe_params *params, bool p2p);
 void wpas_nan_usd_cancel_subscribe(struct wpa_supplicant *wpa_s,
 				   int subscribe_id);
 int wpas_nan_usd_transmit(struct wpa_supplicant *wpa_s, int handle,
diff --git a/wpa_supplicant/notify.c b/wpa_supplicant/notify.c
index d53ae563..2dc68b01 100644
--- a/wpa_supplicant/notify.c
+++ b/wpa_supplicant/notify.c
@@ -10,6 +10,7 @@
 
 #include "utils/common.h"
 #include "common/wpa_ctrl.h"
+#include "common/nan_de.h"
 #include "config.h"
 #include "wpa_supplicant_i.h"
 #include "wps_supplicant.h"
@@ -25,7 +26,11 @@
 #include "p2p_supplicant.h"
 #include "sme.h"
 #include "notify.h"
-#include "aidl/aidl.h"
+#include "aidl/vendor/aidl.h"
+
+#ifdef MAINLINE_SUPPLICANT
+#include "aidl/mainline/service.h"
+#endif
 
 int wpas_notify_supplicant_initialized(struct wpa_global *global)
 {
@@ -47,6 +52,12 @@ int wpas_notify_supplicant_initialized(struct wpa_global *global)
 	}
 #endif /* CONFIG_AIDL */
 
+#ifdef MAINLINE_SUPPLICANT
+	global->aidl = mainline_aidl_init(global);
+	if (!global->aidl)
+		return -1;
+#endif /* MAINLINE_SUPPLICANT */
+
 	return 0;
 }
 
@@ -62,6 +73,12 @@ void wpas_notify_supplicant_deinitialized(struct wpa_global *global)
 	if (global->aidl)
 		wpas_aidl_deinit(global->aidl);
 #endif /* CONFIG_AIDL */
+
+#ifdef MAINLINE_SUPPLICANT
+	if (global->aidl)
+		mainline_aidl_deinit(global->aidl);
+#endif /* MAINLINE_SUPPLICANT */
+
 }
 
 
@@ -210,6 +227,16 @@ void wpas_notify_roam_complete(struct wpa_supplicant *wpa_s)
 }
 
 
+void wpas_notify_scan_in_progress_6ghz(struct wpa_supplicant *wpa_s)
+{
+	if (wpa_s->p2p_mgmt)
+		return;
+
+	wpas_dbus_signal_prop_changed(wpa_s,
+				      WPAS_DBUS_PROP_SCAN_IN_PROGRESS_6GHZ);
+}
+
+
 void wpas_notify_session_length(struct wpa_supplicant *wpa_s)
 {
 	if (wpa_s->p2p_mgmt)
@@ -1195,6 +1222,7 @@ void wpas_notify_dpp_config_sent(struct wpa_supplicant *wpa_s)
 #endif /* CONFIG_DPP */
 }
 
+#ifdef CONFIG_DPP
 void wpas_notify_dpp_connection_status_sent(struct wpa_supplicant *wpa_s,
 	    enum dpp_status_error result)
 {
@@ -1205,6 +1233,7 @@ void wpas_notify_dpp_connection_status_sent(struct wpa_supplicant *wpa_s,
 	wpas_aidl_notify_dpp_connection_status_sent(wpa_s, result);
 #endif /* CONFIG_DPP2 */
 }
+#endif /* CONFIG_DPP */
 
 /* DPP Progress notifications */
 void wpas_notify_dpp_auth_success(struct wpa_supplicant *wpa_s)
@@ -1302,6 +1331,7 @@ void wpas_notify_dpp_config_accepted(struct wpa_supplicant *wpa_s)
 #endif /* CONFIG_DPP2 */
 }
 
+#ifdef CONFIG_DPP
 void wpas_notify_dpp_conn_status(struct wpa_supplicant *wpa_s,
 		enum dpp_status_error status, const char *ssid,
 		const char *channel_list, unsigned short band_list[], int size)
@@ -1310,6 +1340,7 @@ void wpas_notify_dpp_conn_status(struct wpa_supplicant *wpa_s,
 	wpas_aidl_notify_dpp_conn_status(wpa_s, status, ssid, channel_list, band_list, size);
 #endif /* CONFIG_DPP2 */
 }
+#endif /* CONFIG_DPP */
 
 void wpas_notify_dpp_config_rejected(struct wpa_supplicant *wpa_s)
 {
@@ -1457,3 +1488,105 @@ void wpas_notify_hs20_t_c_acceptance(struct wpa_supplicant *wpa_s,
 	wpas_dbus_signal_hs20_t_c_acceptance(wpa_s, url);
 #endif /* CONFIG_HS20 */
 }
+
+#ifdef CONFIG_NAN_USD
+
+void wpas_notify_nan_discovery_result(struct wpa_supplicant *wpa_s,
+				      enum nan_service_protocol_type
+				      srv_proto_type,
+				      int subscribe_id, int peer_publish_id,
+				      const u8 *peer_addr,
+				      bool fsd, bool fsd_gas,
+				      const u8 *ssi, size_t ssi_len)
+{
+	char *ssi_hex;
+
+	ssi_hex = os_zalloc(2 * ssi_len + 1);
+	if (!ssi_hex)
+		return;
+	if (ssi)
+		wpa_snprintf_hex(ssi_hex, 2 * ssi_len + 1, ssi, ssi_len);
+	wpa_msg(wpa_s, MSG_INFO, NAN_DISCOVERY_RESULT
+		"subscribe_id=%d publish_id=%d address=" MACSTR
+		" fsd=%d fsd_gas=%d srv_proto_type=%u ssi=%s",
+		subscribe_id, peer_publish_id, MAC2STR(peer_addr),
+		fsd, fsd_gas, srv_proto_type, ssi_hex);
+	os_free(ssi_hex);
+}
+
+
+void wpas_notify_nan_replied(struct wpa_supplicant *wpa_s,
+			     enum nan_service_protocol_type srv_proto_type,
+			     int publish_id, int peer_subscribe_id,
+			     const u8 *peer_addr,
+			     const u8 *ssi, size_t ssi_len)
+{
+	char *ssi_hex;
+
+	ssi_hex = os_zalloc(2 * ssi_len + 1);
+	if (!ssi_hex)
+		return;
+	if (ssi)
+		wpa_snprintf_hex(ssi_hex, 2 * ssi_len + 1, ssi, ssi_len);
+	wpa_msg(wpa_s, MSG_INFO, NAN_REPLIED
+		"publish_id=%d address=" MACSTR
+		" subscribe_id=%d srv_proto_type=%u ssi=%s",
+		publish_id, MAC2STR(peer_addr), peer_subscribe_id,
+		srv_proto_type, ssi_hex);
+	os_free(ssi_hex);
+}
+
+
+void wpas_notify_nan_receive(struct wpa_supplicant *wpa_s, int id,
+			     int peer_instance_id, const u8 *peer_addr,
+			     const u8 *ssi, size_t ssi_len)
+{
+	char *ssi_hex;
+
+	ssi_hex = os_zalloc(2 * ssi_len + 1);
+	if (!ssi_hex)
+		return;
+	if (ssi)
+		wpa_snprintf_hex(ssi_hex, 2 * ssi_len + 1, ssi, ssi_len);
+	wpa_msg(wpa_s, MSG_INFO, NAN_RECEIVE
+		"id=%d peer_instance_id=%d address=" MACSTR " ssi=%s",
+		id, peer_instance_id, MAC2STR(peer_addr), ssi_hex);
+	os_free(ssi_hex);
+}
+
+
+static const char * nan_reason_txt(enum nan_de_reason reason)
+{
+	switch (reason) {
+	case NAN_DE_REASON_TIMEOUT:
+		return "timeout";
+	case NAN_DE_REASON_USER_REQUEST:
+		return "user-request";
+	case NAN_DE_REASON_FAILURE:
+		return "failure";
+	}
+
+	return "unknown";
+}
+
+
+void wpas_notify_nan_publish_terminated(struct wpa_supplicant *wpa_s,
+					int publish_id,
+					enum nan_de_reason reason)
+{
+	wpa_msg(wpa_s, MSG_INFO, NAN_PUBLISH_TERMINATED
+		"publish_id=%d reason=%s",
+		publish_id, nan_reason_txt(reason));
+}
+
+
+void wpas_notify_nan_subscribe_terminated(struct wpa_supplicant *wpa_s,
+					  int subscribe_id,
+					  enum nan_de_reason reason)
+{
+	wpa_msg(wpa_s, MSG_INFO, NAN_SUBSCRIBE_TERMINATED
+		"subscribe_id=%d reason=%s",
+		subscribe_id, nan_reason_txt(reason));
+}
+
+#endif /* CONFIG_NAN_USD */
diff --git a/wpa_supplicant/notify.h b/wpa_supplicant/notify.h
index a5848846..4e172de3 100644
--- a/wpa_supplicant/notify.h
+++ b/wpa_supplicant/notify.h
@@ -20,6 +20,8 @@ struct wps_event_fail;
 struct tls_cert_data;
 struct wpa_cred;
 struct rsn_pmksa_cache_entry;
+enum nan_de_reason;
+enum nan_service_protocol_type;
 
 int wpas_notify_supplicant_initialized(struct wpa_global *global);
 void wpas_notify_supplicant_deinitialized(struct wpa_global *global);
@@ -35,6 +37,7 @@ void wpas_notify_assoc_status_code(struct wpa_supplicant *wpa_s, const u8 *bssid
 void wpas_notify_auth_timeout(struct wpa_supplicant *wpa_s);
 void wpas_notify_roam_time(struct wpa_supplicant *wpa_s);
 void wpas_notify_roam_complete(struct wpa_supplicant *wpa_s);
+void wpas_notify_scan_in_progress_6ghz(struct wpa_supplicant *wpa_s);
 void wpas_notify_session_length(struct wpa_supplicant *wpa_s);
 void wpas_notify_bss_tm_status(struct wpa_supplicant *wpa_s);
 void wpas_notify_network_changed(struct wpa_supplicant *wpa_s);
@@ -187,8 +190,10 @@ void wpas_notify_hs20_rx_deauth_imminent_notice(struct wpa_supplicant *wpa_s,
 void wpas_notify_dpp_config_received(struct wpa_supplicant *wpa_s,
 		struct wpa_ssid *ssid, bool conn_status_requested);
 void wpas_notify_dpp_config_sent(struct wpa_supplicant *wpa_s);
+#ifdef CONFIG_DPP
 void wpas_notify_dpp_connection_status_sent(struct wpa_supplicant *wpa_s,
 		enum dpp_status_error result);
+#endif /* CONFIG_DPP */
 void wpas_notify_dpp_auth_success(struct wpa_supplicant *wpa_s);
 void wpas_notify_dpp_resp_pending(struct wpa_supplicant *wpa_s);
 void wpas_notify_dpp_not_compatible(struct wpa_supplicant *wpa_s);
@@ -198,9 +203,11 @@ void wpas_notify_dpp_timeout(struct wpa_supplicant *wpa_s);
 void wpas_notify_dpp_auth_failure(struct wpa_supplicant *wpa_s);
 void wpas_notify_dpp_failure(struct wpa_supplicant *wpa_s);
 void wpas_notify_dpp_config_sent_wait_response(struct wpa_supplicant *wpa_s);
+#ifdef CONFIG_DPP
 void wpas_notify_dpp_conn_status(struct wpa_supplicant *wpa_s,
 		enum dpp_status_error status, const char *ssid,
 		const char *channel_list, unsigned short band_list[], int size);
+#endif /* CONFIG_DPP */
 void wpas_notify_dpp_config_accepted(struct wpa_supplicant *wpa_s);
 void wpas_notify_dpp_config_rejected(struct wpa_supplicant *wpa_s);
 void wpas_notify_transition_disable(struct wpa_supplicant *wpa_s,
@@ -234,5 +241,26 @@ void wpas_notify_mlo_info_change_reason(struct wpa_supplicant *wpa_s,
 					enum mlo_info_change_reason reason);
 void wpas_notify_hs20_t_c_acceptance(struct wpa_supplicant *wpa_s,
 				     const char *url);
+void wpas_notify_nan_discovery_result(struct wpa_supplicant *wpa_s,
+				      enum nan_service_protocol_type
+				      srv_proto_type,
+				      int subscribe_id, int peer_publish_id,
+				      const u8 *peer_addr,
+				      bool fsd, bool fsd_gas,
+				      const u8 *ssi, size_t ssi_len);
+void wpas_notify_nan_replied(struct wpa_supplicant *wpa_s,
+			     enum nan_service_protocol_type srv_proto_type,
+			     int publish_id, int peer_subscribe_id,
+			     const u8 *peer_addr,
+			     const u8 *ssi, size_t ssi_len);
+void wpas_notify_nan_receive(struct wpa_supplicant *wpa_s, int id,
+			     int peer_instance_id, const u8 *peer_addr,
+			     const u8 *ssi, size_t ssi_len);
+void wpas_notify_nan_publish_terminated(struct wpa_supplicant *wpa_s,
+					int publish_id,
+					enum nan_de_reason reason);
+void wpas_notify_nan_subscribe_terminated(struct wpa_supplicant *wpa_s,
+					  int subscribe_id,
+					  enum nan_de_reason reason);
 
 #endif /* NOTIFY_H */
diff --git a/wpa_supplicant/p2p_supplicant.c b/wpa_supplicant/p2p_supplicant.c
index 9c20ee50..768b9178 100644
--- a/wpa_supplicant/p2p_supplicant.c
+++ b/wpa_supplicant/p2p_supplicant.c
@@ -4501,7 +4501,8 @@ static void wpas_p2ps_get_feat_cap_str(char *buf, size_t buf_len,
 }
 
 
-static void wpas_p2ps_prov_complete(void *ctx, u8 status, const u8 *dev,
+static void wpas_p2ps_prov_complete(void *ctx, enum p2p_status_code status,
+				    const u8 *dev,
 				    const u8 *adv_mac, const u8 *ses_mac,
 				    const u8 *grp_mac, u32 adv_id, u32 ses_id,
 				    u8 conncap, int passwd_id,
@@ -4858,6 +4859,70 @@ static int wpas_p2p_get_pref_freq_list(void *ctx, int go,
 					  WPA_IF_P2P_CLIENT, len, freq_list);
 }
 
+
+static void wpas_p2p_send_bootstrap_comeback(void *eloop_ctx, void *timeout_ctx)
+{
+	struct wpa_supplicant *wpa_s = eloop_ctx;
+
+	wpa_printf(MSG_DEBUG, "P2P2: Send bootstrapping comeback PD Request");
+	wpas_p2p_connect(wpa_s, wpa_s->p2p_bootstrap_dev_addr, wpa_s->p2p_pin,
+			 wpa_s->p2p_wps_method, wpa_s->p2p_persistent_group, 0,
+			 0, 0, wpa_s->p2p_go_intent, wpa_s->p2p_connect_freq,
+			 wpa_s->p2p_go_vht_center_freq2,
+			 wpa_s->p2p_persistent_id,
+			 wpa_s->p2p_pd_before_go_neg,
+			 wpa_s->p2p_go_ht40,
+			 wpa_s->p2p_go_vht,
+			 wpa_s->p2p_go_max_oper_chwidth,
+			 wpa_s->p2p_go_he,
+			 wpa_s->p2p_go_edmg,
+			 NULL, 0, is_p2p_allow_6ghz(wpa_s->global->p2p),
+			 wpa_s->p2p2, wpa_s->p2p_bootstrap, NULL);
+}
+
+
+static void wpas_p2p_register_bootstrap_comeback(void *ctx, const u8 *addr,
+						 u16 comeback_after)
+{
+	unsigned int timeout_us;
+	struct wpa_supplicant *wpa_s = ctx;
+
+	timeout_us = comeback_after * 1024;
+	os_memcpy(wpa_s->p2p_bootstrap_dev_addr, addr, ETH_ALEN);
+
+	eloop_cancel_timeout(wpas_p2p_send_bootstrap_comeback, wpa_s, NULL);
+	eloop_register_timeout(0, timeout_us, wpas_p2p_send_bootstrap_comeback,
+			       wpa_s, NULL);
+}
+
+
+static void wpas_bootstrap_req_rx(void *ctx, const u8 *addr,
+				  u16 bootstrap_method)
+{
+	struct wpa_supplicant *wpa_s = ctx;
+
+	wpa_msg_global(wpa_s, MSG_INFO, P2P_EVENT_BOOTSTRAP_REQUEST MACSTR
+		       " bootstrap_method=%u", MAC2STR(addr), bootstrap_method);
+}
+
+
+static void wpas_bootstrap_completed(void *ctx, const u8 *addr,
+				     enum p2p_status_code status, int freq)
+{
+	struct wpa_supplicant *wpa_s = ctx;
+
+	if (status) {
+		wpa_msg_global(wpa_s, MSG_INFO,
+			       P2P_EVENT_BOOTSTRAP_FAILURE MACSTR " status=%d",
+			       MAC2STR(addr), status);
+	} else {
+		wpa_msg_global(wpa_s, MSG_INFO,
+			       P2P_EVENT_BOOTSTRAP_SUCCESS MACSTR " status=%d",
+			       MAC2STR(addr), status);
+	}
+}
+
+
 int wpas_p2p_mac_setup(struct wpa_supplicant *wpa_s)
 {
 	int ret = 0;
@@ -4982,6 +5047,9 @@ int wpas_p2p_init(struct wpa_global *global, struct wpa_supplicant *wpa_s)
 	p2p.get_pref_freq_list = wpas_p2p_get_pref_freq_list;
 	p2p.p2p_6ghz_disable = wpa_s->conf->p2p_6ghz_disable;
 	p2p.p2p_dfs_chan_enable = wpa_s->conf->p2p_dfs_chan_enable;
+	p2p.register_bootstrap_comeback = wpas_p2p_register_bootstrap_comeback;
+	p2p.bootstrap_req_rx = wpas_bootstrap_req_rx;
+	p2p.bootstrap_completed = wpas_bootstrap_completed;
 
 	os_memcpy(wpa_s->global->p2p_dev_addr, wpa_s->own_addr, ETH_ALEN);
 	os_memcpy(p2p.dev_addr, wpa_s->global->p2p_dev_addr, ETH_ALEN);
@@ -5097,6 +5165,34 @@ int wpas_p2p_init(struct wpa_global *global, struct wpa_supplicant *wpa_s)
 	else
 		p2p.passphrase_len = 8;
 
+	if (wpa_s->conf->dik &&
+	    wpabuf_len(wpa_s->conf->dik) <= DEVICE_IDENTITY_KEY_MAX_LEN) {
+		p2p.pairing_config.dik_cipher = wpa_s->conf->dik_cipher;
+		p2p.pairing_config.dik_len = wpabuf_len(wpa_s->conf->dik);
+		os_memcpy(p2p.pairing_config.dik_data,
+			  wpabuf_head(wpa_s->conf->dik),
+			  p2p.pairing_config.dik_len);
+	} else {
+		p2p.pairing_config.dik_cipher = DIRA_CIPHER_VERSION_128;
+		p2p.pairing_config.dik_len = DEVICE_IDENTITY_KEY_LEN;
+		if (os_get_random(p2p.pairing_config.dik_data,
+				  p2p.pairing_config.dik_len) < 0)
+			return -1;
+
+		wpa_s->conf->dik =
+			wpabuf_alloc_copy(p2p.pairing_config.dik_data,
+					  p2p.pairing_config.dik_len);
+		if (!wpa_s->conf->dik)
+			return -1;
+
+		wpa_s->conf->dik_cipher = p2p.pairing_config.dik_cipher;
+
+		if (wpa_s->conf->update_config &&
+		    wpa_config_write(wpa_s->confname, wpa_s->conf))
+			wpa_printf(MSG_DEBUG,
+				   "P2P: Failed to update configuration");
+	}
+
 	global->p2p = p2p_init(&p2p);
 	if (global->p2p == NULL)
 		return -1;
@@ -5151,6 +5247,7 @@ void wpas_p2p_deinit(struct wpa_supplicant *wpa_s)
 		wpa_s->p2p_send_action_work = NULL;
 	}
 	eloop_cancel_timeout(wpas_p2p_send_action_work_timeout, wpa_s, NULL);
+	eloop_cancel_timeout(wpas_p2p_send_bootstrap_comeback, wpa_s, NULL);
 
 	wpabuf_free(wpa_s->p2p_oob_dev_pw);
 	wpa_s->p2p_oob_dev_pw = NULL;
@@ -5233,7 +5330,8 @@ static int wpas_p2p_start_go_neg(struct wpa_supplicant *wpa_s,
 				 enum p2p_wps_method wps_method,
 				 int go_intent, const u8 *own_interface_addr,
 				 unsigned int force_freq, int persistent_group,
-				 struct wpa_ssid *ssid, unsigned int pref_freq)
+				 struct wpa_ssid *ssid, unsigned int pref_freq,
+				 bool p2p2, u16 bootstrap, const char *password)
 {
 	if (persistent_group && wpa_s->conf->persistent_reconnect)
 		persistent_group = 2;
@@ -5251,7 +5349,7 @@ static int wpas_p2p_start_go_neg(struct wpa_supplicant *wpa_s,
 			   ssid ? ssid->ssid_len : 0,
 			   wpa_s->p2p_pd_before_go_neg, pref_freq,
 			   wps_method == WPS_NFC ? wpa_s->p2p_oob_dev_pw_id :
-			   0);
+			   0, p2p2, bootstrap, password);
 }
 
 
@@ -5260,7 +5358,8 @@ static int wpas_p2p_auth_go_neg(struct wpa_supplicant *wpa_s,
 				enum p2p_wps_method wps_method,
 				int go_intent, const u8 *own_interface_addr,
 				unsigned int force_freq, int persistent_group,
-				struct wpa_ssid *ssid, unsigned int pref_freq)
+				struct wpa_ssid *ssid, unsigned int pref_freq,
+				u16 bootstrap, const char *password)
 {
 	if (persistent_group && wpa_s->conf->persistent_reconnect)
 		persistent_group = 2;
@@ -5270,7 +5369,7 @@ static int wpas_p2p_auth_go_neg(struct wpa_supplicant *wpa_s,
 			     persistent_group, ssid ? ssid->ssid : NULL,
 			     ssid ? ssid->ssid_len : 0, pref_freq,
 			     wps_method == WPS_NFC ? wpa_s->p2p_oob_dev_pw_id :
-			     0);
+			     0, bootstrap, password);
 }
 
 
@@ -5454,7 +5553,9 @@ static void wpas_p2p_scan_res_join(struct wpa_supplicant *wpa_s,
 					 wpa_s->p2p_go_he,
 					 wpa_s->p2p_go_edmg,
 					 NULL, 0,
-					 is_p2p_allow_6ghz(wpa_s->global->p2p));
+					 is_p2p_allow_6ghz(wpa_s->global->p2p),
+					 wpa_s->p2p2, wpa_s->p2p_bootstrap,
+					 NULL);
 			return;
 		}
 
@@ -5970,6 +6071,9 @@ static bool is_p2p_6ghz_supported(struct wpa_supplicant *wpa_s,
 		      HOSTAPD_MODE_IEEE80211A, true))
 		return false;
 
+	if (wpa_s->p2p2)
+		return true;
+
 	if (!p2p_wfd_enabled(wpa_s->global->p2p))
 		return false;
 	if (peer_addr && !p2p_peer_wfd_enabled(wpa_s->global->p2p, peer_addr))
@@ -6021,6 +6125,10 @@ static int wpas_p2p_check_6ghz(struct wpa_supplicant *wpa_s,
  * @group_ssid: Specific Group SSID for join or %NULL if not set
  * @group_ssid_len: Length of @group_ssid in octets
  * @allow_6ghz: Allow P2P connection on 6 GHz channels
+ * @p2p2: Whether device is in P2P R2 mode
+ * @bootstrap: Requested bootstrap method for pairing in P2P2
+ * @password: Password for pairing setup or NULL for oppurtunistic method
+ *	in P2P2
  * Returns: 0 or new PIN (if pin was %NULL) on success, -1 on unspecified
  *	failure, -2 on failure due to channel not currently available,
  *	-3 if forced channel is not supported
@@ -6032,7 +6140,8 @@ int wpas_p2p_connect(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
 		     int persistent_id, int pd, int ht40, int vht,
 		     unsigned int vht_chwidth, int he, int edmg,
 		     const u8 *group_ssid, size_t group_ssid_len,
-		     bool allow_6ghz)
+		     bool allow_6ghz, bool p2p2, u16 bootstrap,
+		     const char *password)
 {
 	int force_freq = 0, pref_freq = 0;
 	int ret = 0, res;
@@ -6052,6 +6161,8 @@ int wpas_p2p_connect(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
 			return -1;
 	}
 
+	wpa_s->p2p2 = p2p2;
+
 	if (wpas_p2p_check_6ghz(wpa_s, peer_addr, allow_6ghz, freq))
 		return -2;
 
@@ -6082,6 +6193,7 @@ int wpas_p2p_connect(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
 	wpa_s->p2p_go_max_oper_chwidth = vht_chwidth;
 	wpa_s->p2p_go_he = !!he;
 	wpa_s->p2p_go_edmg = !!edmg;
+	wpa_s->p2p_bootstrap = bootstrap;
 
 	if (pin)
 		os_strlcpy(wpa_s->p2p_pin, pin, sizeof(wpa_s->p2p_pin));
@@ -6167,14 +6279,15 @@ int wpas_p2p_connect(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
 		if (wpas_p2p_auth_go_neg(wpa_s, peer_addr, wps_method,
 					 go_intent, if_addr,
 					 force_freq, persistent_group, ssid,
-					 pref_freq) < 0)
+					 pref_freq, bootstrap, password) < 0)
 			return -1;
 		return ret;
 	}
 
 	if (wpas_p2p_start_go_neg(wpa_s, peer_addr, wps_method,
 				  go_intent, if_addr, force_freq,
-				  persistent_group, ssid, pref_freq) < 0) {
+				  persistent_group, ssid, pref_freq, p2p2,
+				  bootstrap, password) < 0) {
 		if (wpa_s->create_p2p_iface)
 			wpas_p2p_remove_pending_group_interface(wpa_s);
 		return -1;
@@ -8828,7 +8941,8 @@ static int wpas_p2p_fallback_to_go_neg(struct wpa_supplicant *wpa_s,
 			 wpa_s->p2p_go_max_oper_chwidth,
 			 wpa_s->p2p_go_he,
 			 wpa_s->p2p_go_edmg,
-			 NULL, 0, is_p2p_allow_6ghz(wpa_s->global->p2p));
+			 NULL, 0, is_p2p_allow_6ghz(wpa_s->global->p2p),
+			 wpa_s->p2p2, wpa_s->p2p_bootstrap, NULL);
 	return ret;
 }
 
@@ -9366,7 +9480,8 @@ static int wpas_p2p_nfc_join_group(struct wpa_supplicant *wpa_s,
 				-1, 0, 1, 1, wpa_s->p2p_go_max_oper_chwidth,
 				wpa_s->p2p_go_he, wpa_s->p2p_go_edmg,
 				params->go_ssid_len ? params->go_ssid : NULL,
-				params->go_ssid_len, false);
+				params->go_ssid_len, false, wpa_s->p2p2,
+				wpa_s->p2p_bootstrap, NULL);
 }
 
 
@@ -9445,7 +9560,8 @@ static int wpas_p2p_nfc_init_go_neg(struct wpa_supplicant *wpa_s,
 				forced_freq, wpa_s->p2p_go_vht_center_freq2,
 				-1, 0, 1, 1, wpa_s->p2p_go_max_oper_chwidth,
 				wpa_s->p2p_go_he, wpa_s->p2p_go_edmg,
-				NULL, 0, false);
+				NULL, 0, false, wpa_s->p2p2,
+				wpa_s->p2p_bootstrap, NULL);
 }
 
 
@@ -9462,7 +9578,8 @@ static int wpas_p2p_nfc_resp_go_neg(struct wpa_supplicant *wpa_s,
 			       forced_freq, wpa_s->p2p_go_vht_center_freq2,
 			       -1, 0, 1, 1, wpa_s->p2p_go_max_oper_chwidth,
 			       wpa_s->p2p_go_he, wpa_s->p2p_go_edmg,
-			       NULL, 0, false);
+			       NULL, 0, false, wpa_s->p2p2,
+			       wpa_s->p2p_bootstrap, NULL);
 	if (res)
 		return res;
 
@@ -10330,3 +10447,25 @@ int wpas_p2p_lo_stop(struct wpa_supplicant *wpa_s)
 	wpa_s->p2p_lo_started = 0;
 	return ret;
 }
+
+
+struct wpabuf * wpas_p2p_usd_elems(struct wpa_supplicant *wpa_s)
+{
+	struct p2p_data *p2p = wpa_s->global->p2p;
+
+	if (wpa_s->global->p2p_disabled || !p2p)
+		return NULL;
+	return p2p_usd_elems(p2p);
+}
+
+
+void wpas_p2p_process_usd_elems(struct wpa_supplicant *wpa_s, const u8 *buf,
+				u16 buf_len, const u8 *peer_addr,
+				unsigned int freq)
+{
+	struct p2p_data *p2p = wpa_s->global->p2p;
+
+	if (wpa_s->global->p2p_disabled || !p2p)
+		return;
+	p2p_process_usd_elems(p2p, buf, buf_len, peer_addr, freq);
+}
diff --git a/wpa_supplicant/p2p_supplicant.h b/wpa_supplicant/p2p_supplicant.h
index d71f7701..a0fbddce 100644
--- a/wpa_supplicant/p2p_supplicant.h
+++ b/wpa_supplicant/p2p_supplicant.h
@@ -39,7 +39,8 @@ int wpas_p2p_connect(struct wpa_supplicant *wpa_s, const u8 *peer_addr,
 		     int persistent_id, int pd, int ht40, int vht,
 		     unsigned int vht_chwidth, int he, int edmg,
 		     const u8 *group_ssid, size_t group_ssid_len,
-		     bool allow_6ghz);
+		     bool allow_6ghz, bool p2p2, u16 bootstrap,
+		     const char *password);
 int wpas_p2p_handle_frequency_conflicts(struct wpa_supplicant *wpa_s,
                                           int freq, struct wpa_ssid *ssid);
 int wpas_p2p_group_add(struct wpa_supplicant *wpa_s, int persistent_group,
@@ -178,6 +179,9 @@ int wpas_p2p_nfc_tag_enabled(struct wpa_supplicant *wpa_s, int enabled);
 void wpas_p2p_pbc_overlap_cb(void *eloop_ctx, void *timeout_ctx);
 int wpas_p2p_try_edmg_channel(struct wpa_supplicant *wpa_s,
 			      struct p2p_go_neg_results *params);
+void wpas_p2p_process_usd_elems(struct wpa_supplicant *wpa_s, const u8 *buf,
+				u16 buf_len, const u8 *peer_addr,
+				unsigned int freq);
 
 #ifdef CONFIG_P2P
 
@@ -225,6 +229,7 @@ int wpas_p2p_lo_start(struct wpa_supplicant *wpa_s, unsigned int freq,
 		      unsigned int count);
 int wpas_p2p_lo_stop(struct wpa_supplicant *wpa_s);
 int wpas_p2p_mac_setup(struct wpa_supplicant *wpa_s);
+struct wpabuf * wpas_p2p_usd_elems(struct wpa_supplicant *wpa_s);
 
 #else /* CONFIG_P2P */
 
@@ -351,6 +356,11 @@ static inline int wpas_p2p_group_remove(struct wpa_supplicant *wpa_s,
 	return 0;
 }
 
+static inline struct wpabuf * wpas_p2p_usd_elems(struct wpa_supplicant *wpa_s)
+{
+	return NULL;
+}
+
 #endif /* CONFIG_P2P */
 
 #endif /* P2P_SUPPLICANT_H */
diff --git a/wpa_supplicant/scan.c b/wpa_supplicant/scan.c
index 8b59e409..f0ab122f 100644
--- a/wpa_supplicant/scan.c
+++ b/wpa_supplicant/scan.c
@@ -940,9 +940,9 @@ static void wpa_add_scan_ssid(struct wpa_supplicant *wpa_s,
 }
 
 
-static void wpa_add_owe_scan_ssid(struct wpa_supplicant *wpa_s,
-				  struct wpa_driver_scan_params *params,
-				  struct wpa_ssid *ssid, size_t max_ssids)
+void wpa_add_owe_scan_ssid(struct wpa_supplicant *wpa_s,
+			   struct wpa_driver_scan_params *params,
+			   const struct wpa_ssid *ssid, size_t max_ssids)
 {
 #ifdef CONFIG_OWE
 	struct wpa_bss *bss;
@@ -954,8 +954,7 @@ static void wpa_add_owe_scan_ssid(struct wpa_supplicant *wpa_s,
 		   wpa_ssid_txt(ssid->ssid, ssid->ssid_len));
 
 	dl_list_for_each(bss, &wpa_s->bss, struct wpa_bss, list) {
-		const u8 *owe, *pos, *end;
-		const u8 *owe_ssid;
+		const u8 *owe, *owe_bssid, *owe_ssid;
 		size_t owe_ssid_len;
 
 		if (bss->ssid_len != ssid->ssid_len ||
@@ -966,21 +965,9 @@ static void wpa_add_owe_scan_ssid(struct wpa_supplicant *wpa_s,
 		if (!owe || owe[1] < 4)
 			continue;
 
-		pos = owe + 6;
-		end = owe + 2 + owe[1];
-
-		/* Must include BSSID and ssid_len */
-		if (end - pos < ETH_ALEN + 1)
-			return;
-
-		/* Skip BSSID */
-		pos += ETH_ALEN;
-		owe_ssid_len = *pos++;
-		owe_ssid = pos;
-
-		if ((size_t) (end - pos) < owe_ssid_len ||
-		    owe_ssid_len > SSID_MAX_LEN)
-			return;
+		if (wpas_get_owe_trans_network(owe, &owe_bssid, &owe_ssid,
+					       &owe_ssid_len))
+			continue;
 
 		wpa_printf(MSG_DEBUG,
 			   "OWE: scan_ssids: transition mode OWE ssid=%s",
diff --git a/wpa_supplicant/scan.h b/wpa_supplicant/scan.h
index d4c06c1a..7ea99928 100644
--- a/wpa_supplicant/scan.h
+++ b/wpa_supplicant/scan.h
@@ -104,5 +104,8 @@ int wpas_channel_width_rssi_bump(const u8 *ies, size_t ies_len,
 				 enum chan_width cw);
 int wpas_adjust_snr_by_chanwidth(const u8 *ies, size_t ies_len,
 				 enum chan_width max_cw, int snr);
+void wpa_add_owe_scan_ssid(struct wpa_supplicant *wpa_s,
+			   struct wpa_driver_scan_params *params,
+			   const struct wpa_ssid *ssid, size_t max_ssids);
 
 #endif /* SCAN_H */
diff --git a/wpa_supplicant/sme.c b/wpa_supplicant/sme.c
index 57c9b381..e4be388d 100644
--- a/wpa_supplicant/sme.c
+++ b/wpa_supplicant/sme.c
@@ -2471,26 +2471,46 @@ mscs_fail:
 		wpa_s->sme.assoc_req_ie_len += multi_ap_ie_len;
 	}
 
+	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_RSN_OVERRIDE_SUPPORT,
+			 wpas_rsn_overriding(wpa_s));
+	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_RSN_OVERRIDE,
+			 RSN_OVERRIDE_NOT_USED);
 	if (wpas_rsn_overriding(wpa_s) &&
 	    wpas_ap_supports_rsn_overriding(wpa_s, wpa_s->current_bss) &&
 	    wpa_s->sme.assoc_req_ie_len + 2 + 4 <=
 	    sizeof(wpa_s->sme.assoc_req_ie)) {
 		u8 *pos = wpa_s->sme.assoc_req_ie + wpa_s->sme.assoc_req_ie_len;
-		u32 type = 0;
 		const u8 *ie;
+		enum rsn_selection_variant variant = RSN_SELECTION_RSNE;
 
+		wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_RSN_OVERRIDE,
+				 RSN_OVERRIDE_RSNE);
 		ie = wpa_bss_get_rsne(wpa_s, wpa_s->current_bss, ssid,
 				      wpa_s->valid_links);
-		if (ie && ie[0] == WLAN_EID_VENDOR_SPECIFIC && ie[1] >= 4)
-			type = WPA_GET_BE32(&ie[2]);
+		if (ie && ie[0] == WLAN_EID_VENDOR_SPECIFIC && ie[1] >= 4) {
+			u32 type;
 
-		if (type) {
-			/* Indicate support for RSN overriding */
-			*pos++ = WLAN_EID_VENDOR_SPECIFIC;
-			*pos++ = 4;
-			WPA_PUT_BE32(pos, type);
-			wpa_s->sme.assoc_req_ie_len += 2 + 4;
+			type = WPA_GET_BE32(&ie[2]);
+			if (type == RSNE_OVERRIDE_IE_VENDOR_TYPE) {
+				variant = RSN_SELECTION_RSNE_OVERRIDE;
+				wpa_sm_set_param(wpa_s->wpa,
+						 WPA_PARAM_RSN_OVERRIDE,
+						 RSN_OVERRIDE_RSNE_OVERRIDE);
+			} else if (type == RSNE_OVERRIDE_2_IE_VENDOR_TYPE) {
+				variant = RSN_SELECTION_RSNE_OVERRIDE_2;
+				wpa_sm_set_param(wpa_s->wpa,
+						 WPA_PARAM_RSN_OVERRIDE,
+						 RSN_OVERRIDE_RSNE_OVERRIDE_2);
+			}
 		}
+
+		/* Indicate which RSNE variant was used */
+		*pos++ = WLAN_EID_VENDOR_SPECIFIC;
+		*pos++ = 4 + 1;
+		WPA_PUT_BE32(pos, RSN_SELECTION_IE_VENDOR_TYPE);
+		pos += 4;
+		*pos = variant;
+		wpa_s->sme.assoc_req_ie_len += 2 + 4 + 1;
 	}
 
 	params.bssid = bssid;
diff --git a/wpa_supplicant/wnm_sta.c b/wpa_supplicant/wnm_sta.c
index ea79ae6e..3bb621db 100644
--- a/wpa_supplicant/wnm_sta.c
+++ b/wpa_supplicant/wnm_sta.c
@@ -27,7 +27,6 @@
 #define MAX_TFS_IE_LEN  1024
 #define WNM_MAX_NEIGHBOR_REPORT 10
 
-#define WNM_SCAN_RESULT_AGE 2 /* 2 seconds */
 
 /* get the TFS IE from driver */
 static int ieee80211_11_get_tfs_ie(struct wpa_supplicant *wpa_s, u8 *buf,
@@ -556,7 +555,7 @@ static int wnm_nei_get_chan(struct wpa_supplicant *wpa_s, u8 op_class, u8 chan)
 	}
 
 	freq = ieee80211_chan_to_freq(country, op_class, chan);
-	if (freq <= 0 && op_class == 0) {
+	if (freq <= 0 && (op_class == 0 || op_class == 255)) {
 		/*
 		 * Some APs do not advertise correct operating class
 		 * information. Try to determine the most likely operating
@@ -740,7 +739,7 @@ static struct wpa_bss * find_better_target(struct wpa_bss *a,
 }
 
 static struct wpa_bss *
-compare_scan_neighbor_results(struct wpa_supplicant *wpa_s, os_time_t age_secs,
+compare_scan_neighbor_results(struct wpa_supplicant *wpa_s,
 			      enum mbo_transition_reject_reason *reason)
 {
 	u8 i;
@@ -761,11 +760,6 @@ compare_scan_neighbor_results(struct wpa_supplicant *wpa_s, os_time_t age_secs,
 		struct neighbor_report *nei;
 
 		nei = &wpa_s->wnm_neighbor_report_elements[i];
-		if (nei->preference_present && nei->preference == 0) {
-			wpa_printf(MSG_DEBUG, "Skip excluded BSS " MACSTR,
-				   MAC2STR(nei->bssid));
-			continue;
-		}
 
 		target = wpa_bss_get_bssid(wpa_s, nei->bssid);
 		if (!target) {
@@ -777,19 +771,6 @@ compare_scan_neighbor_results(struct wpa_supplicant *wpa_s, os_time_t age_secs,
 			continue;
 		}
 
-		if (age_secs) {
-			struct os_reltime now;
-
-			if (os_get_reltime(&now) == 0 &&
-			    os_reltime_expired(&now, &target->last_update,
-					       age_secs)) {
-				wpa_printf(MSG_DEBUG,
-					   "Candidate BSS is more than %ld seconds old",
-					   age_secs);
-				continue;
-			}
-		}
-
 		/*
 		 * TODO: Could consider allowing transition to another ESS if
 		 * PMF was enabled for the association.
@@ -1192,8 +1173,13 @@ int wnm_scan_process(struct wpa_supplicant *wpa_s, bool pre_scan_check)
 		goto send_bss_resp_fail;
 	}
 
+	if (!pre_scan_check && !wpa_s->wnm_transition_scan)
+		return 0;
+
+	wpa_s->wnm_transition_scan = false;
+
 	/* Compare the Neighbor Report and scan results */
-	bss = compare_scan_neighbor_results(wpa_s, 0, &reason);
+	bss = compare_scan_neighbor_results(wpa_s, &reason);
 
 	/*
 	 * If this is a pre-scan check, returning 0 will trigger a scan and
@@ -1235,11 +1221,19 @@ int wnm_scan_process(struct wpa_supplicant *wpa_s, bool pre_scan_check)
 	return 1;
 
 send_bss_resp_fail:
-	/* Send reject response for all the failures */
+	if (wpa_s->wnm_reply) {
+		/* If disassoc imminent is set, we must not reject */
+		if (wpa_s->wnm_mode &
+		    (WNM_BSS_TM_REQ_DISASSOC_IMMINENT |
+		     WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT)) {
+			wpa_printf(MSG_DEBUG,
+				   "WNM: Accept BTM request because disassociation imminent bit is set");
+			status = WNM_BSS_TM_ACCEPT;
+		}
 
-	if (wpa_s->wnm_reply)
 		wnm_send_bss_transition_mgmt_resp(wpa_s, status, reason,
 						  0, NULL);
+	}
 
 	wnm_btm_reset(wpa_s);
 
@@ -1376,6 +1370,63 @@ static void wnm_set_scan_freqs(struct wpa_supplicant *wpa_s)
 }
 
 
+static int wnm_parse_candidate_list(struct wpa_supplicant *wpa_s,
+				    const u8 *pos, const u8 *end,
+				    int *num_valid_candidates)
+{
+	*num_valid_candidates = 0;
+
+	while (end - pos >= 2 &&
+	       wpa_s->wnm_num_neighbor_report < WNM_MAX_NEIGHBOR_REPORT) {
+		u8 tag = *pos++;
+		u8 len = *pos++;
+
+		wpa_printf(MSG_DEBUG, "WNM: Neighbor report tag %u", tag);
+		if (len > end - pos) {
+			wpa_printf(MSG_DEBUG, "WNM: Truncated request");
+			return -1;
+		}
+		if (tag == WLAN_EID_NEIGHBOR_REPORT) {
+			struct neighbor_report *rep;
+
+			if (!wpa_s->wnm_num_neighbor_report) {
+				wpa_s->wnm_neighbor_report_elements = os_calloc(
+					WNM_MAX_NEIGHBOR_REPORT,
+					sizeof(struct neighbor_report));
+				if (!wpa_s->wnm_neighbor_report_elements)
+					return -1;
+			}
+
+			rep = &wpa_s->wnm_neighbor_report_elements[
+				wpa_s->wnm_num_neighbor_report];
+			wnm_parse_neighbor_report(wpa_s, pos, len, rep);
+			if ((wpa_s->wnm_mode &
+			     WNM_BSS_TM_REQ_DISASSOC_IMMINENT) &&
+			    ether_addr_equal(rep->bssid, wpa_s->bssid))
+				rep->disassoc_imminent = 1;
+
+			if (rep->preference_present && rep->preference)
+				*num_valid_candidates += 1;
+
+			wpa_s->wnm_num_neighbor_report++;
+#ifdef CONFIG_MBO
+			if (wpa_s->wnm_mbo_trans_reason_present &&
+			    wpa_s->wnm_num_neighbor_report == 1) {
+				rep->is_first = 1;
+				wpa_printf(MSG_DEBUG,
+					   "WNM: First transition candidate is "
+					   MACSTR, MAC2STR(rep->bssid));
+			}
+#endif /* CONFIG_MBO */
+		}
+
+		pos += len;
+	}
+
+	return 0;
+}
+
+
 static void ieee802_11_rx_bss_trans_mgmt_req(struct wpa_supplicant *wpa_s,
 					     const u8 *pos, const u8 *end,
 					     int reply)
@@ -1386,6 +1437,7 @@ static void ieee802_11_rx_bss_trans_mgmt_req(struct wpa_supplicant *wpa_s,
 	const u8 *vendor;
 #endif /* CONFIG_MBO */
 	bool disassoc_imminent;
+	int num_valid_candidates;
 
 	if (wpa_s->disable_mbo_oce || wpa_s->conf->disable_btm)
 		return;
@@ -1409,7 +1461,7 @@ static void ieee802_11_rx_bss_trans_mgmt_req(struct wpa_supplicant *wpa_s,
 
 	wpa_s->wnm_dialog_token = pos[0];
 	wpa_s->wnm_mode = pos[1];
-	wpa_s->wnm_dissoc_timer = WPA_GET_LE16(pos + 2);
+	wpa_s->wnm_disassoc_timer = WPA_GET_LE16(pos + 2);
 	wpa_s->wnm_link_removal = false;
 	valid_int = pos[4];
 	wpa_s->wnm_reply = reply;
@@ -1418,7 +1470,12 @@ static void ieee802_11_rx_bss_trans_mgmt_req(struct wpa_supplicant *wpa_s,
 		   "dialog_token=%u request_mode=0x%x "
 		   "disassoc_timer=%u validity_interval=%u",
 		   wpa_s->wnm_dialog_token, wpa_s->wnm_mode,
-		   wpa_s->wnm_dissoc_timer, valid_int);
+		   wpa_s->wnm_disassoc_timer, valid_int);
+
+	if (!wpa_s->wnm_dialog_token) {
+		wpa_printf(MSG_DEBUG, "WNM: Invalid dialog token");
+		goto reset;
+	}
 
 #if defined(CONFIG_MBO) && defined(CONFIG_TESTING_OPTIONS)
 	if (wpa_s->reject_btm_req_reason) {
@@ -1428,7 +1485,7 @@ static void ieee802_11_rx_bss_trans_mgmt_req(struct wpa_supplicant *wpa_s,
 		wnm_send_bss_transition_mgmt_resp(
 			wpa_s, wpa_s->reject_btm_req_reason,
 			MBO_TRANSITION_REJECT_REASON_UNSPECIFIED, 0, NULL);
-		return;
+		goto reset;
 	}
 #endif /* CONFIG_MBO && CONFIG_TESTING_OPTIONS */
 
@@ -1437,7 +1494,7 @@ static void ieee802_11_rx_bss_trans_mgmt_req(struct wpa_supplicant *wpa_s,
 	if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED) {
 		if (end - pos < 12) {
 			wpa_printf(MSG_DEBUG, "WNM: Too short BSS TM Request");
-			return;
+			goto reset;
 		}
 		os_memcpy(wpa_s->wnm_bss_termination_duration, pos, 12);
 		pos += 12; /* BSS Termination Duration */
@@ -1450,13 +1507,13 @@ static void ieee802_11_rx_bss_trans_mgmt_req(struct wpa_supplicant *wpa_s,
 		if (end - pos < 1) {
 			wpa_printf(MSG_DEBUG, "WNM: Invalid BSS Transition "
 				   "Management Request (URL)");
-			return;
+			goto reset;
 		}
 		url_len = *pos++;
 		if (url_len > end - pos) {
 			wpa_printf(MSG_DEBUG,
 				   "WNM: Invalid BSS Transition Management Request (URL truncated)");
-			return;
+			goto reset;
 		}
 		os_memcpy(url, pos, url_len);
 		url[url_len] = '\0';
@@ -1464,7 +1521,8 @@ static void ieee802_11_rx_bss_trans_mgmt_req(struct wpa_supplicant *wpa_s,
 
 		wpa_msg(wpa_s, MSG_INFO, ESS_DISASSOC_IMMINENT "%d %u %s",
 			wpa_sm_pmf_enabled(wpa_s->wpa),
-			wpa_s->wnm_dissoc_timer * beacon_int * 128 / 125, url);
+			wpa_s->wnm_disassoc_timer * beacon_int * 128 / 125,
+			url);
 	}
 
 #ifdef CONFIG_MBO
@@ -1505,77 +1563,34 @@ static void ieee802_11_rx_bss_trans_mgmt_req(struct wpa_supplicant *wpa_s,
 			wnm_send_bss_transition_mgmt_resp(
 				wpa_s, WNM_BSS_TM_ACCEPT, 0, 0, NULL);
 
-			return;
+			goto reset;
 		}
 
 		/* The last link is being removed (which must be the assoc link)
 		 */
 		wpa_s->wnm_link_removal = true;
-		os_memcpy(wpa_s->wnm_dissoc_addr,
+		wpa_s->wnm_disassoc_mld = false;
+		os_memcpy(wpa_s->wnm_disassoc_addr,
 			  wpa_s->links[wpa_s->mlo_assoc_link_id].bssid,
 			  ETH_ALEN);
+	} else if (wpa_s->valid_links) {
+		wpa_s->wnm_disassoc_mld = true;
+		os_memcpy(wpa_s->wnm_disassoc_addr, wpa_s->ap_mld_addr,
+			  ETH_ALEN);
 	} else {
-		os_memcpy(wpa_s->wnm_dissoc_addr, wpa_s->valid_links ?
-			  wpa_s->ap_mld_addr : wpa_s->bssid, ETH_ALEN);
+		wpa_s->wnm_disassoc_mld = false;
+		os_memcpy(wpa_s->wnm_disassoc_addr, wpa_s->bssid, ETH_ALEN);
 	}
 
-	if (disassoc_imminent) {
+	if (disassoc_imminent)
 		wpa_msg(wpa_s, MSG_INFO, "WNM: Disassociation Imminent - "
-			"Disassociation Timer %u", wpa_s->wnm_dissoc_timer);
-		if (wpa_s->wnm_dissoc_timer && !wpa_s->scanning &&
-		    (!wpa_s->current_ssid || !wpa_s->current_ssid->bssid_set)) {
-			wpa_printf(MSG_DEBUG, "Trying to find another BSS");
-			wpa_supplicant_req_scan(wpa_s, 0, 0);
-		}
-	}
+			"Disassociation Timer %u", wpa_s->wnm_disassoc_timer);
 
-	if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_PREF_CAND_LIST_INCLUDED) {
-		unsigned int valid_ms;
-
-		wpa_msg(wpa_s, MSG_INFO, "WNM: Preferred List Available");
-		wpa_s->wnm_neighbor_report_elements = os_calloc(
-			WNM_MAX_NEIGHBOR_REPORT,
-			sizeof(struct neighbor_report));
-		if (wpa_s->wnm_neighbor_report_elements == NULL)
-			return;
-
-		while (end - pos >= 2 &&
-		       wpa_s->wnm_num_neighbor_report < WNM_MAX_NEIGHBOR_REPORT)
-		{
-			u8 tag = *pos++;
-			u8 len = *pos++;
-
-			wpa_printf(MSG_DEBUG, "WNM: Neighbor report tag %u",
-				   tag);
-			if (len > end - pos) {
-				wpa_printf(MSG_DEBUG, "WNM: Truncated request");
-				return;
-			}
-			if (tag == WLAN_EID_NEIGHBOR_REPORT) {
-				struct neighbor_report *rep;
-				rep = &wpa_s->wnm_neighbor_report_elements[
-					wpa_s->wnm_num_neighbor_report];
-				wnm_parse_neighbor_report(wpa_s, pos, len, rep);
-				if ((wpa_s->wnm_mode &
-				     WNM_BSS_TM_REQ_DISASSOC_IMMINENT) &&
-				    ether_addr_equal(rep->bssid, wpa_s->bssid))
-					rep->disassoc_imminent = 1;
-
-				wpa_s->wnm_num_neighbor_report++;
-#ifdef CONFIG_MBO
-				if (wpa_s->wnm_mbo_trans_reason_present &&
-				    wpa_s->wnm_num_neighbor_report == 1) {
-					rep->is_first = 1;
-					wpa_printf(MSG_DEBUG,
-						   "WNM: First transition candidate is "
-						   MACSTR, MAC2STR(rep->bssid));
-				}
-#endif /* CONFIG_MBO */
-			}
-
-			pos += len;
-		}
+	if (wnm_parse_candidate_list(wpa_s, pos, end,
+				     &num_valid_candidates) < 0)
+		goto reset;
 
+	if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_PREF_CAND_LIST_INCLUDED) {
 		if (!wpa_s->wnm_num_neighbor_report) {
 			wpa_printf(MSG_DEBUG,
 				   "WNM: Candidate list included bit is set, but no candidates found");
@@ -1583,18 +1598,13 @@ static void ieee802_11_rx_bss_trans_mgmt_req(struct wpa_supplicant *wpa_s,
 				wpa_s, WNM_BSS_TM_REJECT_NO_SUITABLE_CANDIDATES,
 				MBO_TRANSITION_REJECT_REASON_UNSPECIFIED, 0,
 				NULL);
-			return;
+			goto reset;
 		}
+		wpa_msg(wpa_s, MSG_INFO, "WNM: Preferred List Available");
+	}
 
-		if (wpa_s->current_ssid && wpa_s->current_ssid->bssid_set) {
-			wpa_printf(MSG_DEBUG,
-				   "WNM: Configuration prevents roaming (BSSID set)");
-			wnm_send_bss_transition_mgmt_resp(
-				wpa_s, WNM_BSS_TM_REJECT_NO_SUITABLE_CANDIDATES,
-				MBO_TRANSITION_REJECT_REASON_UNSPECIFIED, 0,
-				NULL);
-			return;
-		}
+	if (wpa_s->wnm_num_neighbor_report) {
+		unsigned int valid_ms;
 
 		wnm_sort_cand_list(wpa_s);
 		wnm_dump_cand_list(wpa_s);
@@ -1602,40 +1612,12 @@ static void ieee802_11_rx_bss_trans_mgmt_req(struct wpa_supplicant *wpa_s,
 		wpa_printf(MSG_DEBUG, "WNM: Candidate list valid for %u ms",
 			   valid_ms);
 		os_get_reltime(&wpa_s->wnm_cand_valid_until);
-		wpa_s->wnm_cand_valid_until.sec += valid_ms / 1000;
-		wpa_s->wnm_cand_valid_until.usec += (valid_ms % 1000) * 1000;
-		wpa_s->wnm_cand_valid_until.sec +=
-			wpa_s->wnm_cand_valid_until.usec / 1000000;
-		wpa_s->wnm_cand_valid_until.usec %= 1000000;
-
-		/*
-		* Try fetching the latest scan results from the kernel.
-		* This can help in finding more up-to-date information should
-		* the driver have done some internal scanning operations after
-		* the last scan result update in wpa_supplicant.
-		*
-		* It is not a new scan, this does not update the last_scan
-		* timestamp nor will it expire old BSSs.
-		*/
-		wpa_supplicant_update_scan_results(wpa_s, NULL);
-		if (wnm_scan_process(wpa_s, true) > 0)
-			return;
-		wpa_printf(MSG_DEBUG,
-			   "WNM: No valid match in previous scan results - try a new scan");
-
-		wnm_set_scan_freqs(wpa_s);
-		if (wpa_s->wnm_num_neighbor_report == 1) {
-			os_memcpy(wpa_s->next_scan_bssid,
-				  wpa_s->wnm_neighbor_report_elements[0].bssid,
-				  ETH_ALEN);
-			wpa_printf(MSG_DEBUG,
-				   "WNM: Scan only for a specific BSSID since there is only a single candidate "
-				   MACSTR, MAC2STR(wpa_s->next_scan_bssid));
-		}
-		wpa_supplicant_req_scan(wpa_s, 0, 0);
-	} else if (reply) {
+		os_reltime_add_ms(&wpa_s->wnm_cand_valid_until, valid_ms);
+	} else if (!disassoc_imminent) {
 		enum bss_trans_mgmt_status_code status;
 
+		/* No candidate list and disassociation is not imminent */
+
 		if ((wpa_s->wnm_mode & WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT) ||
 		    wpa_s->wnm_link_removal)
 			status = WNM_BSS_TM_ACCEPT;
@@ -1643,10 +1625,66 @@ static void ieee802_11_rx_bss_trans_mgmt_req(struct wpa_supplicant *wpa_s,
 			wpa_msg(wpa_s, MSG_INFO, "WNM: BSS Transition Management Request did not include candidates");
 			status = WNM_BSS_TM_REJECT_UNSPECIFIED;
 		}
-		wnm_send_bss_transition_mgmt_resp(
-			wpa_s, status,
-			MBO_TRANSITION_REJECT_REASON_UNSPECIFIED, 0, NULL);
+
+		if (reply)
+			wnm_send_bss_transition_mgmt_resp(
+				wpa_s, status,
+				MBO_TRANSITION_REJECT_REASON_UNSPECIFIED, 0,
+				NULL);
+
+		goto reset;
+	}
+
+	/*
+	 * Try fetching the latest scan results from the kernel.
+	 * This can help in finding more up-to-date information should
+	 * the driver have done some internal scanning operations after
+	 * the last scan result update in wpa_supplicant.
+	 *
+	 * It is not a new scan, this does not update the last_scan
+	 * timestamp nor will it expire old BSSs.
+	 */
+	wpa_supplicant_update_scan_results(wpa_s, NULL);
+	if (wnm_scan_process(wpa_s, true) > 0)
+		return;
+	wpa_printf(MSG_DEBUG,
+		   "WNM: No valid match in previous scan results - try a new scan");
+
+	/*
+	 * If we have a fixed BSSID configured, just reject at this point.
+	 * NOTE: We could actually check if we are allowed to stay (and we do
+	 * above if we have scan results available).
+	 */
+	if (wpa_s->current_ssid && wpa_s->current_ssid->bssid_set) {
+		wpa_printf(MSG_DEBUG, "WNM: Fixed BSSID, rejecting request");
+
+		if (reply)
+			wnm_send_bss_transition_mgmt_resp(
+				wpa_s, WNM_BSS_TM_REJECT_NO_SUITABLE_CANDIDATES,
+				MBO_TRANSITION_REJECT_REASON_UNSPECIFIED, 0,
+				NULL);
+
+		goto reset;
 	}
+
+	wnm_set_scan_freqs(wpa_s);
+	if (num_valid_candidates == 1) {
+		/* Any invalid candidate was sorted to the end */
+		os_memcpy(wpa_s->next_scan_bssid,
+			  wpa_s->wnm_neighbor_report_elements[0].bssid,
+			  ETH_ALEN);
+		wpa_printf(MSG_DEBUG,
+			  "WNM: Scan only for a specific BSSID since there is only a single candidate "
+			  MACSTR, MAC2STR(wpa_s->next_scan_bssid));
+	}
+	wpa_s->wnm_transition_scan = true;
+	wpa_supplicant_req_scan(wpa_s, 0, 0);
+
+	/* Continue from scan handler */
+	return;
+
+reset:
+	wnm_btm_reset(wpa_s);
 }
 
 
@@ -2067,22 +2105,41 @@ void wnm_clear_coloc_intf_reporting(struct wpa_supplicant *wpa_s)
 
 bool wnm_is_bss_excluded(struct wpa_supplicant *wpa_s, struct wpa_bss *bss)
 {
-	if (!(wpa_s->wnm_mode & WNM_BSS_TM_REQ_DISASSOC_IMMINENT))
-		return false;
+	int i;
 
 	/*
 	 * In case disassociation imminent is set, do no try to use a BSS to
 	 * which we are connected.
 	 */
-	if (wpa_s->wnm_link_removal ||
-	    !(wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_MLO) ||
-	    is_zero_ether_addr(bss->mld_addr)) {
-		if (ether_addr_equal(bss->bssid, wpa_s->wnm_dissoc_addr))
-			return true;
-	} else {
-		if (ether_addr_equal(bss->mld_addr, wpa_s->wnm_dissoc_addr))
+	if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_DISASSOC_IMMINENT) {
+		if (!wpa_s->wnm_disassoc_mld) {
+			if (ether_addr_equal(bss->bssid,
+					     wpa_s->wnm_disassoc_addr))
+				return true;
+		} else {
+			if (ether_addr_equal(bss->mld_addr,
+					     wpa_s->wnm_disassoc_addr))
+				return true;
+		}
+	}
+
+	for (i = 0; i < wpa_s->wnm_num_neighbor_report; i++) {
+		struct neighbor_report *nei;
+
+		nei = &wpa_s->wnm_neighbor_report_elements[i];
+		if (!ether_addr_equal(nei->bssid, bss->bssid))
+			continue;
+
+		if (nei->preference_present && nei->preference == 0)
 			return true;
+
+		break;
 	}
 
+	/* If the abridged bit is set, the BSS must be a known neighbor. */
+	if ((wpa_s->wnm_mode & WNM_BSS_TM_REQ_ABRIDGED) &&
+	    wpa_s->wnm_num_neighbor_report == i)
+		return true;
+
 	return false;
 }
diff --git a/wpa_supplicant/wpa_supplicant.c b/wpa_supplicant/wpa_supplicant.c
index 15a859f5..e3ed8582 100644
--- a/wpa_supplicant/wpa_supplicant.c
+++ b/wpa_supplicant/wpa_supplicant.c
@@ -70,7 +70,7 @@
 #include "ap/ap_config.h"
 #include "ap/hostapd.h"
 #endif /* CONFIG_MESH */
-#include "aidl/aidl.h"
+#include "aidl/vendor/aidl.h"
 
 const char *const wpa_supplicant_version =
 "wpa_supplicant v" VERSION_STR "\n"
@@ -418,8 +418,13 @@ void wpa_supplicant_set_non_wpa_policy(struct wpa_supplicant *wpa_s,
 	wpa_sm_set_ap_wpa_ie(wpa_s->wpa, NULL, 0);
 	wpa_sm_set_ap_rsn_ie(wpa_s->wpa, NULL, 0);
 	wpa_sm_set_ap_rsnxe(wpa_s->wpa, NULL, 0);
+	wpa_sm_set_ap_rsne_override(wpa_s->wpa, NULL, 0);
+	wpa_sm_set_ap_rsne_override_2(wpa_s->wpa, NULL, 0);
+	wpa_sm_set_ap_rsnxe_override(wpa_s->wpa, NULL, 0);
 	wpa_sm_set_assoc_wpa_ie(wpa_s->wpa, NULL, 0);
+#ifndef CONFIG_NO_WPA
 	wpa_sm_set_assoc_rsnxe(wpa_s->wpa, NULL, 0);
+#endif /* CONFIG_NO_WPA */
 	wpa_s->rsnxe_len = 0;
 	wpa_s->pairwise_cipher = WPA_CIPHER_NONE;
 	wpa_s->group_cipher = WPA_CIPHER_NONE;
@@ -1838,12 +1843,31 @@ int wpa_supplicant_set_suites(struct wpa_supplicant *wpa_s,
 			 !!(ssid->proto & (WPA_PROTO_RSN | WPA_PROTO_OSEN)));
 
 	if (bss || !wpa_s->ap_ies_from_associnfo) {
+		const u8 *rsnoe = NULL, *rsno2e = NULL, *rsnxoe = NULL;
+
+		if (bss) {
+			bss_rsn = wpa_bss_get_ie(bss, WLAN_EID_RSN);
+			bss_rsnx = wpa_bss_get_ie(bss, WLAN_EID_RSNX);
+			rsnoe = wpa_bss_get_vendor_ie(
+				bss, RSNE_OVERRIDE_IE_VENDOR_TYPE);
+			rsno2e = wpa_bss_get_vendor_ie(
+				bss, RSNE_OVERRIDE_2_IE_VENDOR_TYPE);
+			rsnxoe = wpa_bss_get_vendor_ie(
+				bss, RSNXE_OVERRIDE_IE_VENDOR_TYPE);
+		}
+
 		if (wpa_sm_set_ap_wpa_ie(wpa_s->wpa, bss_wpa,
 					 bss_wpa ? 2 + bss_wpa[1] : 0) ||
 		    wpa_sm_set_ap_rsn_ie(wpa_s->wpa, bss_rsn,
 					 bss_rsn ? 2 + bss_rsn[1] : 0) ||
 		    wpa_sm_set_ap_rsnxe(wpa_s->wpa, bss_rsnx,
-					bss_rsnx ? 2 + bss_rsnx[1] : 0))
+					bss_rsnx ? 2 + bss_rsnx[1] : 0) ||
+		    wpa_sm_set_ap_rsne_override(wpa_s->wpa, rsnoe,
+						rsnoe ? 2 + rsnoe[1] : 0) ||
+		    wpa_sm_set_ap_rsne_override_2(wpa_s->wpa, rsno2e,
+						  rsno2e ? 2 + rsno2e[1] : 0) ||
+		    wpa_sm_set_ap_rsnxe_override(wpa_s->wpa, rsnxoe,
+						 rsnxoe ? 2 + rsnxoe[1] : 0))
 			return -1;
 	}
 
@@ -2145,6 +2169,7 @@ int wpa_supplicant_set_suites(struct wpa_supplicant *wpa_s,
 			return -1;
 		}
 
+#ifndef CONFIG_NO_WPA
 		wpa_s->rsnxe_len = sizeof(wpa_s->rsnxe);
 		if (wpa_sm_set_assoc_rsnxe_default(wpa_s->wpa, wpa_s->rsnxe,
 						   &wpa_s->rsnxe_len)) {
@@ -2152,6 +2177,7 @@ int wpa_supplicant_set_suites(struct wpa_supplicant *wpa_s,
 				"RSN: Failed to generate RSNXE");
 			return -1;
 		}
+#endif /* CONFIG_NO_WPA */
 	}
 
 	if (0) {
@@ -3968,57 +3994,48 @@ mscs_end:
 		wpa_ie_len += multi_ap_ie_len;
 	}
 
-	if (!wpas_driver_bss_selection(wpa_s) &&
-	    wpas_rsn_overriding(wpa_s) &&
+	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_RSN_OVERRIDE_SUPPORT,
+			 wpas_rsn_overriding(wpa_s));
+	wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_RSN_OVERRIDE,
+			 RSN_OVERRIDE_NOT_USED);
+	if (wpas_rsn_overriding(wpa_s) &&
 	    wpas_ap_supports_rsn_overriding(wpa_s, bss) &&
-	    wpa_ie_len + 2 + 4 <= max_wpa_ie_len) {
-		u8 *pos = wpa_ie + wpa_ie_len;
-		u32 type = 0;
+	    wpa_ie_len + 2 + 4 + 1 <= max_wpa_ie_len) {
+		u8 *pos = wpa_ie + wpa_ie_len, *start = pos;
 		const u8 *ie;
+		enum rsn_selection_variant variant = RSN_SELECTION_RSNE;
 
+		wpa_sm_set_param(wpa_s->wpa, WPA_PARAM_RSN_OVERRIDE,
+				 RSN_OVERRIDE_RSNE);
 		ie = wpa_bss_get_rsne(wpa_s, bss, ssid, wpa_s->valid_links);
-		if (ie && ie[0] == WLAN_EID_VENDOR_SPECIFIC && ie[1] >= 4)
-			type = WPA_GET_BE32(&ie[2]);
-
-		if (type) {
-			/* Indicate support for RSN overriding */
-			*pos++ = WLAN_EID_VENDOR_SPECIFIC;
-			*pos++ = 4;
-			WPA_PUT_BE32(pos, type);
-			pos += 4;
-			wpa_hexdump(MSG_MSGDUMP, "RSNE Override", wpa_ie,
-				    pos - wpa_ie);
-			wpa_ie_len += 2 + 4;
-		}
-	}
+		if (ie && ie[0] == WLAN_EID_VENDOR_SPECIFIC && ie[1] >= 4) {
+			u32 type;
 
-	if (wpas_driver_bss_selection(wpa_s) &&
-	    wpas_rsn_overriding(wpa_s)) {
-		if (wpa_ie_len + 2 + 4 <= max_wpa_ie_len) {
-			u8 *pos = wpa_ie + wpa_ie_len;
-
-			*pos++ = WLAN_EID_VENDOR_SPECIFIC;
-			*pos++ = 4;
-			WPA_PUT_BE32(pos, RSNE_OVERRIDE_IE_VENDOR_TYPE);
-			pos += 4;
-			wpa_hexdump(MSG_MSGDUMP, "RSNE Override", wpa_ie,
-				    pos - wpa_ie);
-			wpa_ie_len += 2 + 4;
+			type = WPA_GET_BE32(&ie[2]);
+			if (type == RSNE_OVERRIDE_IE_VENDOR_TYPE) {
+				variant = RSN_SELECTION_RSNE_OVERRIDE;
+				wpa_sm_set_param(wpa_s->wpa,
+						 WPA_PARAM_RSN_OVERRIDE,
+						 RSN_OVERRIDE_RSNE_OVERRIDE);
+			} else if (type == RSNE_OVERRIDE_2_IE_VENDOR_TYPE) {
+				variant = RSN_SELECTION_RSNE_OVERRIDE_2;
+				wpa_sm_set_param(wpa_s->wpa,
+						 WPA_PARAM_RSN_OVERRIDE,
+						 RSN_OVERRIDE_RSNE_OVERRIDE_2);
+			}
 		}
 
-		if (wpa_ie_len + 2 + 4 <= max_wpa_ie_len) {
-			u8 *pos = wpa_ie + wpa_ie_len;
-
-			*pos++ = WLAN_EID_VENDOR_SPECIFIC;
-			*pos++ = 4;
-			WPA_PUT_BE32(pos, RSNE_OVERRIDE_2_IE_VENDOR_TYPE);
-			pos += 4;
-			wpa_hexdump(MSG_MSGDUMP, "RSNE Override 2",
-				    wpa_ie, pos - wpa_ie);
-			wpa_ie_len += 2 + 4;
-		}
+		/* Indicate which RSNE variant was used */
+		*pos++ = WLAN_EID_VENDOR_SPECIFIC;
+		*pos++ = 4 + 1;
+		WPA_PUT_BE32(pos, RSN_SELECTION_IE_VENDOR_TYPE);
+		pos += 4;
+		*pos++ = variant;
+		wpa_hexdump(MSG_MSGDUMP, "RSN Selection", start, pos - start);
+		wpa_ie_len += pos - start;
 	}
 
+	params->rsn_overriding = wpas_rsn_overriding(wpa_s);
 	params->wpa_ie = wpa_ie;
 	params->wpa_ie_len = wpa_ie_len;
 	params->auth_alg = algs;
@@ -4283,7 +4300,9 @@ static void wpas_start_assoc_cb(struct wpa_radio_work *work, int deinit)
 	/* Starting new association, so clear the possibly used WPA IE from the
 	 * previous association. */
 	wpa_sm_set_assoc_wpa_ie(wpa_s->wpa, NULL, 0);
+#ifndef CONFIG_NO_WPA
 	wpa_sm_set_assoc_rsnxe(wpa_s->wpa, NULL, 0);
+#endif /* CONFIG_NO_WPA */
 	wpa_s->rsnxe_len = 0;
 #ifndef CONFIG_NO_ROBUST_AV
 	wpa_s->mscs_setup_done = false;
@@ -4755,8 +4774,10 @@ static void wpas_start_assoc_cb(struct wpa_radio_work *work, int deinit)
 	}
 
 	wpa_supplicant_rsn_supp_set_config(wpa_s, wpa_s->current_ssid);
+#ifndef CONFIG_NO_WPA
 	if (bss)
 		wpa_sm_set_ssid(wpa_s->wpa, bss->ssid, bss->ssid_len);
+#endif /* CONFIG_NO_WPA */
 	wpa_supplicant_initiate_eapol(wpa_s);
 	if (old_ssid != wpa_s->current_ssid)
 		wpas_notify_network_changed(wpa_s);
@@ -5511,8 +5532,8 @@ int wpa_supplicant_set_debug_params(struct wpa_global *global, int debug_level,
 static int owe_trans_ssid_match(struct wpa_supplicant *wpa_s, const u8 *bssid,
 				const u8 *entry_ssid, size_t entry_ssid_len)
 {
-	const u8 *owe, *pos, *end;
-	u8 ssid_len;
+	const u8 *owe, *owe_bssid, *owe_ssid;
+	size_t owe_ssid_len;
 	struct wpa_bss *bss;
 
 	/* Check network profile SSID aganst the SSID in the
@@ -5526,18 +5547,12 @@ static int owe_trans_ssid_match(struct wpa_supplicant *wpa_s, const u8 *bssid,
 	if (!owe)
 		return 0;
 
-	pos = owe + 6;
-	end = owe + 2 + owe[1];
-
-	if (end - pos < ETH_ALEN + 1)
-		return 0;
-	pos += ETH_ALEN;
-	ssid_len = *pos++;
-	if (end - pos < ssid_len || ssid_len > SSID_MAX_LEN)
+	if (wpas_get_owe_trans_network(owe, &owe_bssid, &owe_ssid,
+				       &owe_ssid_len))
 		return 0;
 
-	return entry_ssid_len == ssid_len &&
-		os_memcmp(pos, entry_ssid, ssid_len) == 0;
+	return entry_ssid_len == owe_ssid_len &&
+		os_memcmp(owe_ssid, entry_ssid, owe_ssid_len) == 0;
 }
 #endif /* CONFIG_OWE */
 
@@ -7517,9 +7532,11 @@ static int wpa_supplicant_init_iface(struct wpa_supplicant *wpa_s,
 #ifdef CONFIG_PASN
 	wpa_pasn_sm_set_caps(wpa_s->wpa, wpa_s->drv_flags2);
 #endif /* CONFIG_PASN */
+#ifndef CONFIG_NO_WPA
 	wpa_sm_set_driver_bss_selection(wpa_s->wpa,
 					!!(wpa_s->drv_flags &
 					   WPA_DRIVER_FLAGS_BSS_SELECTION));
+#endif /* CONFIG_NO_WPA */
 	if (wpa_s->max_remain_on_chan == 0)
 		wpa_s->max_remain_on_chan = 1000;
 
@@ -9787,3 +9804,34 @@ bool wpas_ap_supports_rsn_overriding_2(struct wpa_supplicant *wpa_s,
 
 	return false;
 }
+
+
+int wpas_get_owe_trans_network(const u8 *owe_ie, const u8 **bssid,
+			       const u8 **ssid, size_t *ssid_len)
+{
+#ifdef CONFIG_OWE
+	const u8 *pos, *end;
+	u8 ssid_len_tmp;
+
+	if (!owe_ie)
+		return -1;
+
+	pos = owe_ie + 6;
+	end = owe_ie + 2 + owe_ie[1];
+
+	if (end - pos < ETH_ALEN + 1)
+		return -1;
+	*bssid = pos;
+	pos += ETH_ALEN;
+	ssid_len_tmp = *pos++;
+	if (end - pos < ssid_len_tmp || ssid_len_tmp > SSID_MAX_LEN)
+		return -1;
+
+	*ssid = pos;
+	*ssid_len = ssid_len_tmp;
+
+	return 0;
+#else /* CONFIG_OWE */
+	return -1;
+#endif /* CONFIG_OWE */
+}
diff --git a/wpa_supplicant/wpa_supplicant_i.h b/wpa_supplicant/wpa_supplicant_i.h
index 245ac93f..84b7bd53 100644
--- a/wpa_supplicant/wpa_supplicant_i.h
+++ b/wpa_supplicant/wpa_supplicant_i.h
@@ -1135,6 +1135,7 @@ struct wpa_supplicant {
 	int pending_pd_before_join;
 	u8 pending_join_iface_addr[ETH_ALEN];
 	u8 pending_join_dev_addr[ETH_ALEN];
+	u8 p2p_bootstrap_dev_addr[ETH_ALEN];
 	int pending_join_wps_method;
 	u8 p2p_join_ssid[SSID_MAX_LEN];
 	size_t p2p_join_ssid_len;
@@ -1189,6 +1190,8 @@ struct wpa_supplicant {
 	unsigned int p2ps_method_config_any:1;
 	unsigned int p2p_cli_probe:1;
 	unsigned int p2p_go_allow_dfs:1;
+	unsigned int p2p2:1;
+	u16 p2p_bootstrap;
 	enum hostapd_hw_mode p2p_go_acs_band;
 	int p2p_persistent_go_freq;
 	int p2p_persistent_id;
@@ -1324,13 +1327,15 @@ struct wpa_supplicant {
 	u8 *mac_addr_pno;
 
 #ifdef CONFIG_WNM
+	bool wnm_transition_scan;
 	u8 wnm_dialog_token;
 	u8 wnm_reply;
 	u8 wnm_num_neighbor_report;
 	u8 wnm_mode;
 	bool wnm_link_removal;
-	u8 wnm_dissoc_addr[ETH_ALEN];
-	u16 wnm_dissoc_timer;
+	bool wnm_disassoc_mld;
+	u8 wnm_disassoc_addr[ETH_ALEN];
+	u16 wnm_disassoc_timer;
 	u8 wnm_bss_termination_duration[12];
 	struct neighbor_report *wnm_neighbor_report_elements;
 	struct os_reltime wnm_cand_valid_until;
@@ -1607,6 +1612,7 @@ struct wpa_supplicant {
 	bool wps_scan_done; /* Set upon receiving scan results event */
 	bool supp_pbc_active; /* Set for interface when PBC is triggered */
 	bool wps_overlap;
+	bool scan_in_progress_6ghz; /* Set upon a 6 GHz scan being triggered */
 
 #ifdef CONFIG_PASN
 	struct pasn_data pasn;
@@ -2057,5 +2063,7 @@ bool wpas_ap_supports_rsn_overriding(struct wpa_supplicant *wpa_s,
 				     struct wpa_bss *bss);
 bool wpas_ap_supports_rsn_overriding_2(struct wpa_supplicant *wpa_s,
 				       struct wpa_bss *bss);
+int wpas_get_owe_trans_network(const u8 *owe_ie, const u8 **bssid,
+			       const u8 **ssid, size_t *ssid_len);
 
 #endif /* WPA_SUPPLICANT_I_H */
diff --git a/wpa_supplicant/wpa_supplicant_template.conf b/wpa_supplicant/wpa_supplicant_template.conf
index 6a2fbd37..cec26c48 100644
--- a/wpa_supplicant/wpa_supplicant_template.conf
+++ b/wpa_supplicant/wpa_supplicant_template.conf
@@ -9,4 +9,3 @@ oce=1
 sae_pwe=2
 p2p_optimize_listen_chan=1
 wowlan_disconnect_on_deinit=1
-sae_pmkid_in_assoc=1
diff --git a/wpa_supplicant/wpas_glue.c b/wpa_supplicant/wpas_glue.c
index de216d29..741ac6cc 100644
--- a/wpa_supplicant/wpas_glue.c
+++ b/wpa_supplicant/wpas_glue.c
@@ -148,6 +148,7 @@ static int wpa_supplicant_eapol_send(void *ctx, int type, const u8 *buf,
 {
 	struct wpa_supplicant *wpa_s = ctx;
 	u8 *msg, *dst, bssid[ETH_ALEN];
+	struct driver_sta_mlo_info drv_mlo;
 	size_t msglen;
 	int res;
 
@@ -197,11 +198,16 @@ static int wpa_supplicant_eapol_send(void *ctx, int type, const u8 *buf,
 	if (is_zero_ether_addr(wpa_s->bssid)) {
 		wpa_printf(MSG_DEBUG, "BSSID not set when trying to send an "
 			   "EAPOL frame");
+		os_memset(&drv_mlo, 0, sizeof(drv_mlo));
 		if (wpa_drv_get_bssid(wpa_s, bssid) == 0 &&
+		    (!wpa_s->valid_links ||
+		     wpas_drv_get_sta_mlo_info(wpa_s, &drv_mlo) == 0) &&
 		    !is_zero_ether_addr(bssid)) {
-			dst = bssid;
-			wpa_printf(MSG_DEBUG, "Using current BSSID " MACSTR
+			dst = drv_mlo.valid_links ? drv_mlo.ap_mld_addr : bssid;
+			wpa_printf(MSG_DEBUG, "Using current %s " MACSTR
 				   " from the driver as the EAPOL destination",
+				   drv_mlo.valid_links ? "AP MLD MAC address" :
+				   "BSSID",
 				   MAC2STR(dst));
 		} else {
 			dst = wpa_s->last_eapol_src;
@@ -211,9 +217,10 @@ static int wpa_supplicant_eapol_send(void *ctx, int type, const u8 *buf,
 				   MAC2STR(dst));
 		}
 	} else {
-		/* BSSID was already set (from (Re)Assoc event, so use it as
-		 * the EAPOL destination. */
-		dst = wpa_s->bssid;
+		/* BSSID was already set (from (Re)Assoc event, so use BSSID or
+		 * AP MLD MAC address (in the case of MLO connection) as the
+		 * EAPOL destination. */
+		dst = wpa_s->valid_links ? wpa_s->ap_mld_addr : wpa_s->bssid;
 	}
 
 	msg = wpa_alloc_eapol(wpa_s, type, buf, len, &msglen, NULL);
@@ -441,13 +448,29 @@ static int wpa_get_beacon_ie(struct wpa_supplicant *wpa_s)
 		if (wpa_sm_set_ap_wpa_ie(wpa_s->wpa, ie, ie ? 2 + ie[1] : 0))
 			ret = -1;
 
-		ie = wpa_bss_get_rsne(wpa_s, curr, ssid, false);
+		ie = wpa_bss_get_ie(curr, WLAN_EID_RSN);
 		if (wpa_sm_set_ap_rsn_ie(wpa_s->wpa, ie, ie ? 2 + ie[1] : 0))
 			ret = -1;
 
-		ie = wpa_bss_get_rsnxe(wpa_s, curr, ssid, false);
+		ie = wpa_bss_get_ie(curr, WLAN_EID_RSNX);
 		if (wpa_sm_set_ap_rsnxe(wpa_s->wpa, ie, ie ? 2 + ie[1] : 0))
 			ret = -1;
+
+		ie = wpa_bss_get_vendor_ie(curr, RSNE_OVERRIDE_IE_VENDOR_TYPE);
+		if (wpa_sm_set_ap_rsne_override(wpa_s->wpa, ie,
+						ie ? 2 + ie[1] : 0))
+			ret = -1;
+
+		ie = wpa_bss_get_vendor_ie(curr,
+					   RSNE_OVERRIDE_2_IE_VENDOR_TYPE);
+		if (wpa_sm_set_ap_rsne_override_2(wpa_s->wpa, ie,
+						  ie ? 2 + ie[1] : 0))
+			ret = -1;
+
+		ie = wpa_bss_get_vendor_ie(curr, RSNXE_OVERRIDE_IE_VENDOR_TYPE);
+		if (wpa_sm_set_ap_rsnxe_override(wpa_s->wpa, ie,
+						 ie ? 2 + ie[1] : 0))
+			ret = -1;
 	} else {
 		ret = -1;
 	}
```

