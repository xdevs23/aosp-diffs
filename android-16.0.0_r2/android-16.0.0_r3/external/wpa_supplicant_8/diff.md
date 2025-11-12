```diff
diff --git a/apex/Android.bp b/apex/Android.bp
index 6aad837c..094c8b85 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -42,8 +42,4 @@ apex {
         "com.android.hardware.hostapd.rc",
         "wpa_supplicant.conf.prebuilt",
     ],
-    vintf_fragment_modules: [
-        "android.hardware.wifi.hostapd.xml",
-        "android.hardware.wifi.supplicant.xml",
-    ],
 }
diff --git a/hostapd/Android.bp b/hostapd/Android.bp
index 533a917d..ce589a47 100644
--- a/hostapd/Android.bp
+++ b/hostapd/Android.bp
@@ -714,6 +714,7 @@ hostapd_cc_binary {
             static_libs: ["%s"],
         },
     },
+    vintf_fragment_modules: ["android.hardware.wifi.hostapd.xml"],
 }
 
 cc_library_static {
diff --git a/hostapd/aidl/hostapd.cpp b/hostapd/aidl/hostapd.cpp
index 745fab82..a0a39538 100644
--- a/hostapd/aidl/hostapd.cpp
+++ b/hostapd/aidl/hostapd.cpp
@@ -706,16 +706,16 @@ std::string CreateHostapdConfig(
 				    "Unable to set interface mac address as bssid for 11BE SAP");
 				return "";
 			}
-            if (iface_params.usesMlo) {
-                eht_params_as_string += StringPrintf(
-                    "mld_addr=%s\n"
-                    "mld_ap=1",
-                    interface_mac_addr.c_str());
-            } else {
-                eht_params_as_string += StringPrintf(
-                    "bssid=%s\n"
-                    "mld_ap=1",
-                    interface_mac_addr.c_str());
+			if (iface_params.usesMlo) {
+				eht_params_as_string += StringPrintf(
+					"mld_addr=%s\n"
+					"mld_ap=1",
+					interface_mac_addr.c_str());
+			} else {
+				eht_params_as_string += StringPrintf(
+					"bssid=%s\n"
+					"mld_ap=1",
+					interface_mac_addr.c_str());
             }
 		}
 		/* TODO set eht_su_beamformer, eht_su_beamformee, eht_mu_beamformer */
@@ -1398,6 +1398,10 @@ struct hostapd_data * hostapd_get_iface_by_link_id(struct hapd_interfaces *inter
 	// hapd->mld_link_id  | 0 (default value)      |      link id (0)        | link id (0 or 1)
 	// _________________________________________________________________________________________
 	// hapd->mld_ap       |         0              |            1            |     1
+	// -----------------------------------------------------------------------------------------
+	// hapd->conf->bssid  |    configured          |    configured           | No configured
+	// -----------------------------------------------------------------------------------------
+	// hapd->conf->mld_addr|   No configured       |   No configured         |   configured
 	on_setup_complete_internal_callback =
 		[this](struct hostapd_data* iface_hapd) {
 			wpa_printf(
@@ -1409,7 +1413,8 @@ struct hostapd_data * hostapd_get_iface_by_link_id(struct hapd_interfaces *inter
 				std::string instanceName = iface_hapd->conf->iface;
 #ifdef CONFIG_IEEE80211BE
 				if (iface_hapd->conf->mld_ap
-						&& strlen(iface_hapd->conf->bridge) == 0) {
+						&& strlen(iface_hapd->conf->bridge) == 0
+						&& strlen((char*)(iface_hapd->conf->bssid)) == 0) {
 					instanceName = std::to_string(iface_hapd->mld_link_id);
 				}
 #endif /* CONFIG_IEEE80211BE */
@@ -1438,7 +1443,8 @@ struct hostapd_data * hostapd_get_iface_by_link_id(struct hapd_interfaces *inter
 		std::string instanceName = iface_hapd->conf->iface;
 #ifdef CONFIG_IEEE80211BE
 		if (iface_hapd->conf->mld_ap
-				&& strlen(iface_hapd->conf->bridge) == 0) {
+				&& strlen(iface_hapd->conf->bridge) == 0
+				&& strlen((char*)(iface_hapd->conf->bssid)) == 0) {
 			instanceName = std::to_string(iface_hapd->mld_link_id);
 		}
 #endif /* CONFIG_IEEE80211BE */
@@ -1474,7 +1480,9 @@ struct hostapd_data * hostapd_get_iface_by_link_id(struct hapd_interfaces *inter
 					strlen(WPA_EVENT_CHANNEL_SWITCH)) == 0) {
 			std::string instanceName = iface_hapd->conf->iface;
 #ifdef CONFIG_IEEE80211BE
-			if (iface_hapd->conf->mld_ap && strlen(iface_hapd->conf->bridge) == 0) {
+			if (iface_hapd->conf->mld_ap
+					&& strlen(iface_hapd->conf->bridge) == 0
+					&& strlen((char*)(iface_hapd->conf->bssid)) == 0) {
 				instanceName = std::to_string(iface_hapd->mld_link_id);
 			}
 #endif /* CONFIG_IEEE80211BE */
@@ -1506,7 +1514,9 @@ struct hostapd_data * hostapd_get_iface_by_link_id(struct hapd_interfaces *inter
 		{
 			std::string instanceName = iface_hapd->conf->iface;
 #ifdef CONFIG_IEEE80211BE
-			if (iface_hapd->conf->mld_ap && strlen(iface_hapd->conf->bridge) == 0) {
+			if (iface_hapd->conf->mld_ap
+					&& strlen(iface_hapd->conf->bridge) == 0
+					&& strlen((char*)(iface_hapd->conf->bssid)) == 0) {
 				instanceName = std::to_string(iface_hapd->mld_link_id);
 			}
 #endif /* CONFIG_IEEE80211BE */
diff --git a/hostapd/config_file.c b/hostapd/config_file.c
index a9310f2a..23404b69 100644
--- a/hostapd/config_file.c
+++ b/hostapd/config_file.c
@@ -4489,6 +4489,15 @@ static int hostapd_config_fill(struct hostapd_config *conf,
 			wpabuf_free(conf->lci);
 			conf->lci = NULL;
 		}
+		if (conf->lci) {
+			/* Enable LCI capability in RM Enabled Capabilities
+			 * element */
+			bss->radio_measurements[1] |=
+				WLAN_RRM_CAPS_LCI_MEASUREMENT;
+		} else {
+			bss->radio_measurements[1] &=
+				~WLAN_RRM_CAPS_LCI_MEASUREMENT;
+		}
 	} else if (os_strcmp(buf, "civic") == 0) {
 		wpabuf_free(conf->civic);
 		conf->civic = wpabuf_parse_bin(pos);
@@ -4496,6 +4505,15 @@ static int hostapd_config_fill(struct hostapd_config *conf,
 			wpabuf_free(conf->civic);
 			conf->civic = NULL;
 		}
+		if (conf->civic) {
+			/* Enable civic location capability in RM Enabled
+			 * Capabilities element */
+			bss->radio_measurements[4] |=
+				WLAN_RRM_CAPS_CIVIC_LOCATION_MEASUREMENT;
+		} else {
+			bss->radio_measurements[4] &=
+				~WLAN_RRM_CAPS_CIVIC_LOCATION_MEASUREMENT;
+		}
 	} else if (os_strcmp(buf, "rrm_neighbor_report") == 0) {
 		if (atoi(pos))
 			bss->radio_measurements[0] |=
diff --git a/hostapd/ctrl_iface.c b/hostapd/ctrl_iface.c
index e74b1c7e..35c16aa4 100644
--- a/hostapd/ctrl_iface.c
+++ b/hostapd/ctrl_iface.c
@@ -2478,7 +2478,7 @@ static int hostapd_ctrl_check_freq_params(struct hostapd_freq_params *params,
 				idx = (params->center_freq1 - 5950) / 5;
 
 			bw = center_idx_to_bw_6ghz(idx);
-			if (bw < 0 || bw > (int) ARRAY_SIZE(bw_idx) ||
+			if (bw < 0 || bw >= (int) ARRAY_SIZE(bw_idx) ||
 			    bw_idx[bw] != params->bandwidth)
 				return -1;
 		}
diff --git a/hostapd/main.c b/hostapd/main.c
index 5769fa0e..fdc5f084 100644
--- a/hostapd/main.c
+++ b/hostapd/main.c
@@ -280,7 +280,7 @@ static int hostapd_driver_init(struct hostapd_iface *iface)
 				   &hapd->drv_priv, force_ifname, if_addr,
 				   params.num_bridge && params.bridge[0] ?
 				   params.bridge[0] : NULL,
-				   0)) {
+				   1)) {
 			wpa_printf(MSG_ERROR, "Failed to add BSS (BSSID="
 				   MACSTR ")", MAC2STR(hapd->own_addr));
 			os_free(params.bridge);
diff --git a/src/ap/acs.c b/src/ap/acs.c
index f5b36d32..44d08368 100644
--- a/src/ap/acs.c
+++ b/src/ap/acs.c
@@ -54,7 +54,7 @@
  * Todo / Ideas
  * ------------
  * - implement other interference computation methods
- *   - BSS/RSSI based
+ *   - RSSI based
  *   - spectral scan based
  *   (should be possibly to hook this up with current ACS scans)
  * - add wpa_supplicant support (for P2P)
@@ -557,6 +557,9 @@ static int acs_surveys_are_sufficient(struct hostapd_iface *iface)
 
 static int acs_usable_chan(struct hostapd_channel_data *chan)
 {
+	if (chan->interference_bss_based)
+		return 1;
+
 	return !dl_list_empty(&chan->survey_list) &&
 		!(chan->flag & HOSTAPD_CHAN_DISABLED) &&
 		acs_survey_list_is_sufficient(chan);
@@ -1254,13 +1257,53 @@ static int acs_study_survey_based(struct hostapd_iface *iface)
 }
 
 
+static int acs_study_bss_based(struct hostapd_iface *iface)
+{
+	struct wpa_scan_results *scan_res;
+	int j;
+
+	wpa_printf(MSG_DEBUG, "ACS: Trying BSS-based ACS");
+
+	scan_res = hostapd_driver_get_scan_results(iface->bss[0]);
+	if (!scan_res) {
+		wpa_printf(MSG_INFO, "ACS: Scan request failed");
+		hostapd_setup_interface_complete(iface, 1);
+		return -1;
+	}
+
+	for (j = 0; j < iface->current_mode->num_channels; j++) {
+		struct hostapd_channel_data *chan;
+		unsigned int bss_on_ch = 0;
+		size_t i;
+
+		chan = &iface->current_mode->channels[j];
+		for (i = 0; i < scan_res->num; i++) {
+			struct wpa_scan_res *bss = scan_res->res[i];
+
+			if (bss->freq == chan->freq)
+				bss_on_ch++;
+		}
+
+		wpa_printf(MSG_MSGDUMP,
+			   "ACS: Interference on ch %d (%d MHz): %d",
+			   chan->chan, chan->freq, bss_on_ch);
+		chan->interference_factor = bss_on_ch;
+		chan->interference_bss_based = true;
+	}
+
+	wpa_scan_results_free(scan_res);
+	return 0;
+}
+
+
 static int acs_study_options(struct hostapd_iface *iface)
 {
 	if (acs_study_survey_based(iface) == 0)
 		return 0;
 
-	/* TODO: If no surveys are available/sufficient this is a good
-	 * place to fallback to BSS-based ACS */
+	wpa_printf(MSG_INFO, "ACS: Survey based ACS failed");
+	if (acs_study_bss_based(iface) == 0)
+		return 0;
 
 	return -1;
 }
diff --git a/src/ap/ap_config.c b/src/ap/ap_config.c
index 69550cf2..f4aab006 100644
--- a/src/ap/ap_config.c
+++ b/src/ap/ap_config.c
@@ -1200,7 +1200,7 @@ static bool hostapd_sae_pk_password_without_pk(struct hostapd_bss_config *bss)
 #endif /* CONFIG_SAE_PK */
 
 
-static bool hostapd_config_check_bss_6g(struct hostapd_bss_config *bss)
+bool hostapd_config_check_bss_6g(struct hostapd_bss_config *bss)
 {
 	if (bss->wpa != WPA_PROTO_RSN) {
 		wpa_printf(MSG_ERROR,
diff --git a/src/ap/ap_config.h b/src/ap/ap_config.h
index a587b96c..df0ca044 100644
--- a/src/ap/ap_config.h
+++ b/src/ap/ap_config.h
@@ -1401,5 +1401,6 @@ int hostapd_add_acl_maclist(struct mac_acl_entry **acl, int *num,
 			    int vlan_id, const u8 *addr);
 void hostapd_remove_acl_mac(struct mac_acl_entry **acl, int *num,
 			    const u8 *addr);
+bool hostapd_config_check_bss_6g(struct hostapd_bss_config *bss);
 
 #endif /* HOSTAPD_CONFIG_H */
diff --git a/src/ap/ap_drv_ops.c b/src/ap/ap_drv_ops.c
index d342132d..b2e930de 100644
--- a/src/ap/ap_drv_ops.c
+++ b/src/ap/ap_drv_ops.c
@@ -21,6 +21,7 @@
 #include "p2p_hostapd.h"
 #include "hs20.h"
 #include "wpa_auth.h"
+#include "hw_features.h"
 #include "ap_drv_ops.h"
 
 
@@ -788,6 +789,31 @@ int hostapd_driver_scan(struct hostapd_data *hapd,
 #ifdef CONFIG_IEEE80211BE
 	if (hapd->conf->mld_ap)
 		params->link_id = hapd->mld_link_id;
+
+	if (!hapd->iface->scan_cb && hapd->conf->mld_ap &&
+	    hapd->iface->interfaces) {
+		/* Other links may be waiting for scan results */
+		unsigned int i;
+
+		for (i = 0; i < hapd->iface->interfaces->count; i++) {
+			struct hostapd_iface *h_iface =
+				hapd->iface->interfaces->iface[i];
+			struct hostapd_data *h_hapd;
+
+			if (!h_iface || h_iface == hapd->iface ||
+			    h_iface->num_bss == 0)
+				continue;
+
+			h_hapd = h_iface->bss[0];
+
+			if (hostapd_is_ml_partner(hapd, h_hapd) &&
+			    h_hapd->iface->state == HAPD_IFACE_ACS) {
+				wpa_printf(MSG_INFO,
+					   "ACS in progress in a partner link - try to scan later");
+				return -EBUSY;
+			}
+		}
+	}
 #endif /* CONFIG_IEEE80211BE */
 
 	if (hapd->driver && hapd->driver->scan2)
@@ -1125,6 +1151,9 @@ void hostapd_get_hw_mode_any_channels(struct hostapd_data *hapd,
 {
 	int i;
 	bool is_no_ir = false;
+	bool allow_6g_acs = hostapd_config_check_bss_6g(hapd->conf) &&
+		(hapd->iface->conf->ieee80211ax ||
+		 hapd->iface->conf->ieee80211be);
 
 	for (i = 0; i < mode->num_channels; i++) {
 		struct hostapd_channel_data *chan = &mode->channels[i];
@@ -1145,8 +1174,7 @@ void hostapd_get_hw_mode_any_channels(struct hostapd_data *hapd,
 		if (is_6ghz_freq(chan->freq) &&
 		    ((hapd->iface->conf->acs_exclude_6ghz_non_psc &&
 		      !is_6ghz_psc_frequency(chan->freq)) ||
-		     (!hapd->iface->conf->ieee80211ax &&
-		      !hapd->iface->conf->ieee80211be)))
+		     !allow_6g_acs))
 			continue;
 		if ((!(chan->flag & HOSTAPD_CHAN_DISABLED) || allow_disabled) &&
 		    !(hapd->iface->conf->acs_exclude_dfs &&
diff --git a/src/ap/beacon.c b/src/ap/beacon.c
index a7d7ecd2..3bff0ae3 100644
--- a/src/ap/beacon.c
+++ b/src/ap/beacon.c
@@ -621,18 +621,24 @@ ieee802_11_build_ap_params_mbssid(struct hostapd_data *hapd,
 				 elem_count, elem_offset, NULL, 0, rnr_elem,
 				 &rnr_elem_count, rnr_elem_offset, rnr_len);
 
-	params->mbssid_tx_iface = tx_bss->conf->iface;
-	params->mbssid_index = hostapd_mbssid_get_bss_index(hapd);
-	params->mbssid_elem = elem;
-	params->mbssid_elem_len = end - elem;
-	params->mbssid_elem_count = elem_count;
-	params->mbssid_elem_offset = elem_offset;
-	params->rnr_elem = rnr_elem;
-	params->rnr_elem_len = rnr_len;
-	params->rnr_elem_count = rnr_elem_count;
-	params->rnr_elem_offset = rnr_elem_offset;
+	params->mbssid.mbssid_tx_iface = tx_bss->conf->iface;
+	params->mbssid.mbssid_index = hostapd_mbssid_get_bss_index(hapd);
+	params->mbssid.mbssid_elem = elem;
+	params->mbssid.mbssid_elem_len = end - elem;
+	params->mbssid.mbssid_elem_count = elem_count;
+	params->mbssid.mbssid_elem_offset = elem_offset;
+	params->mbssid.rnr_elem = rnr_elem;
+	params->mbssid.rnr_elem_len = rnr_len;
+	params->mbssid.rnr_elem_count = rnr_elem_count;
+	params->mbssid.rnr_elem_offset = rnr_elem_offset;
 	if (iface->conf->mbssid == ENHANCED_MBSSID_ENABLED)
-		params->ema = true;
+		params->mbssid.ema = true;
+
+	params->mbssid.mbssid_tx_iface_linkid = -1;
+#ifdef CONFIG_IEEE80211BE
+	if (tx_bss->conf->mld_ap)
+		params->mbssid.mbssid_tx_iface_linkid = tx_bss->mld_link_id;
+#endif /* CONFIG_IEEE80211BE */
 
 	return 0;
 
@@ -732,8 +738,13 @@ static void hostapd_free_probe_resp_params(struct probe_resp_params *params)
 static size_t hostapd_probe_resp_elems_len(struct hostapd_data *hapd,
 					   struct probe_resp_params *params)
 {
+#ifdef CONFIG_IEEE80211BE
+	struct hostapd_data *hapd_probed = hapd;
+#endif /* CONFIG_IEEE80211BE */
 	size_t buflen = 0;
 
+	hapd = hostapd_mbssid_get_tx_bss(hapd);
+
 #ifdef CONFIG_WPS
 	if (hapd->wps_probe_resp_ie)
 		buflen += wpabuf_len(hapd->wps_probe_resp_ie);
@@ -777,6 +788,10 @@ static size_t hostapd_probe_resp_elems_len(struct hostapd_data *hapd,
 			 * switch */
 			buflen += 6;
 		}
+
+		if (hapd_probed != hapd && hapd_probed->conf->mld_ap)
+			buflen += hostapd_eid_eht_basic_ml_len(hapd_probed,
+							       NULL, true);
 	}
 #endif /* CONFIG_IEEE80211BE */
 
@@ -799,9 +814,13 @@ static u8 * hostapd_probe_resp_fill_elems(struct hostapd_data *hapd,
 					  struct probe_resp_params *params,
 					  u8 *pos, size_t len)
 {
+#ifdef CONFIG_IEEE80211BE
+	struct hostapd_data *hapd_probed = hapd;
+#endif /* CONFIG_IEEE80211BE */
 	u8 *csa_pos;
 	u8 *epos;
 
+	hapd = hostapd_mbssid_get_tx_bss(hapd);
 	epos = pos + len;
 
 	*pos++ = WLAN_EID_SSID;
@@ -935,6 +954,10 @@ static u8 * hostapd_probe_resp_fill_elems(struct hostapd_data *hapd,
 		pos = hostapd_eid_eht_capab(hapd, pos, IEEE80211_MODE_AP);
 		pos = hostapd_eid_eht_operation(hapd, pos);
 	}
+
+	if (hapd_probed != hapd && hapd_probed->conf->mld_ap)
+		pos = hostapd_eid_eht_basic_ml_common(hapd_probed, pos, NULL,
+						      true);
 #endif /* CONFIG_IEEE80211BE */
 
 #ifdef CONFIG_IEEE80211AC
@@ -1003,6 +1026,7 @@ static u8 * hostapd_probe_resp_fill_elems(struct hostapd_data *hapd,
 static void hostapd_gen_probe_resp(struct hostapd_data *hapd,
 				   struct probe_resp_params *params)
 {
+	struct hostapd_data *hapd_probed = hapd;
 	u8 *pos;
 	size_t buflen;
 
@@ -1010,7 +1034,7 @@ static void hostapd_gen_probe_resp(struct hostapd_data *hapd,
 
 #define MAX_PROBERESP_LEN 768
 	buflen = MAX_PROBERESP_LEN;
-	buflen += hostapd_probe_resp_elems_len(hapd, params);
+	buflen += hostapd_probe_resp_elems_len(hapd_probed, params);
 	params->resp = os_zalloc(buflen);
 	if (!params->resp) {
 		params->resp_len = 0;
@@ -1040,7 +1064,7 @@ static void hostapd_gen_probe_resp(struct hostapd_data *hapd,
 	params->resp->u.probe_resp.capab_info =
 		host_to_le16(hostapd_own_capab_info(hapd));
 
-	pos = hostapd_probe_resp_fill_elems(hapd, params,
+	pos = hostapd_probe_resp_fill_elems(hapd_probed, params,
 					    params->resp->u.probe_resp.variable,
 					    buflen);
 
@@ -2323,7 +2347,7 @@ int ieee802_11_build_ap_params(struct hostapd_data *hapd,
 		}
 		complete = hapd->iconf->mbssid == MBSSID_ENABLED ||
 			(hapd->iconf->mbssid == ENHANCED_MBSSID_ENABLED &&
-			 params->mbssid_elem_count == 1);
+			 params->mbssid.mbssid_elem_count == 1);
 	}
 
 	tailpos = hostapd_eid_ext_capab(hapd, tailpos, complete);
@@ -2371,7 +2395,7 @@ int ieee802_11_build_ap_params(struct hostapd_data *hapd,
 
 	tailpos = hostapd_get_rsnxe(hapd, tailpos, tailend - tailpos);
 	tailpos = hostapd_eid_mbssid_config(hapd, tailpos,
-					    params->mbssid_elem_count);
+					    params->mbssid.mbssid_elem_count);
 
 #ifdef CONFIG_IEEE80211AX
 	if (hapd->iconf->ieee80211ax && !hapd->conf->disable_11ax) {
@@ -2617,14 +2641,14 @@ void ieee802_11_free_ap_params(struct wpa_driver_ap_params *params)
 	params->head = NULL;
 	os_free(params->proberesp);
 	params->proberesp = NULL;
-	os_free(params->mbssid_elem);
-	params->mbssid_elem = NULL;
-	os_free(params->mbssid_elem_offset);
-	params->mbssid_elem_offset = NULL;
-	os_free(params->rnr_elem);
-	params->rnr_elem = NULL;
-	os_free(params->rnr_elem_offset);
-	params->rnr_elem_offset = NULL;
+	os_free(params->mbssid.mbssid_elem);
+	params->mbssid.mbssid_elem = NULL;
+	os_free(params->mbssid.mbssid_elem_offset);
+	params->mbssid.mbssid_elem_offset = NULL;
+	os_free(params->mbssid.rnr_elem);
+	params->mbssid.rnr_elem = NULL;
+	os_free(params->mbssid.rnr_elem_offset);
+	params->mbssid.rnr_elem_offset = NULL;
 #ifdef CONFIG_FILS
 	os_free(params->fd_frame_tmpl);
 	params->fd_frame_tmpl = NULL;
@@ -3110,7 +3134,7 @@ static void hostapd_gen_per_sta_profiles(struct hostapd_data *hapd)
 	struct hostapd_data *link_bss;
 	u8 link_id, *sta_profile;
 
-	if (!hapd->conf->mld_ap)
+	if (!hapd->conf->mld_ap || !hapd->started)
 		return;
 
 	wpa_printf(MSG_DEBUG, "MLD: Generating per STA profiles for MLD %s",
diff --git a/src/ap/drv_callbacks.c b/src/ap/drv_callbacks.c
index 0b4613e7..e7adf916 100644
--- a/src/ap/drv_callbacks.c
+++ b/src/ap/drv_callbacks.c
@@ -189,7 +189,20 @@ static int hostapd_update_sta_links_status(struct hostapd_data *hapd,
 
 	/* Parse Subelements */
 	while (rem_len > 2) {
-		size_t ie_len = 2 + pos[1];
+		size_t ie_len, subelem_defrag_len;
+		int num_frag_subelems;
+
+		num_frag_subelems =
+			ieee802_11_defrag_mle_subelem(mlebuf, pos,
+						      &subelem_defrag_len);
+		if (num_frag_subelems < 0) {
+			wpa_printf(MSG_DEBUG,
+				   "MLD: Failed to parse MLE subelem");
+			break;
+		}
+
+		ie_len = 2 + subelem_defrag_len;
+		rem_len -= num_frag_subelems * 2;
 
 		if (rem_len < ie_len)
 			break;
@@ -200,13 +213,13 @@ static int hostapd_update_sta_links_status(struct hostapd_data *hapd,
 			size_t sta_profile_len;
 			u16 sta_ctrl;
 
-			if (pos[1] < BASIC_MLE_STA_CTRL_LEN + 1) {
+			if (subelem_defrag_len < BASIC_MLE_STA_CTRL_LEN + 1) {
 				wpa_printf(MSG_DEBUG,
 					   "MLO: Invalid per-STA profile IE");
 				goto next_subelem;
 			}
 
-			sta_profile_len = pos[1];
+			sta_profile_len = subelem_defrag_len;
 			sta_profile = &pos[2];
 			sta_ctrl = WPA_GET_LE16(sta_profile);
 			link_id = sta_ctrl & BASIC_MLE_STA_CTRL_LINK_ID_MASK;
diff --git a/src/ap/hostapd.c b/src/ap/hostapd.c
index 65dc14d6..7f2ebecb 100644
--- a/src/ap/hostapd.c
+++ b/src/ap/hostapd.c
@@ -558,9 +558,9 @@ void hostapd_free_hapd_data(struct hostapd_data *hapd)
 	wpabuf_free(hapd->time_adv);
 	hapd->time_adv = NULL;
 
-#ifdef CONFIG_INTERWORKING
+#if defined(CONFIG_INTERWORKING) || defined(CONFIG_DPP)
 	gas_serv_deinit(hapd);
-#endif /* CONFIG_INTERWORKING */
+#endif /* CONFIG_INTERWORKING || CONFIG_DPP */
 
 	bss_load_update_deinit(hapd);
 	ndisc_snoop_deinit(hapd);
@@ -1570,7 +1570,7 @@ setup_mld:
 
 	/*
 	 * Short SSID calculation is identical to FCS and it is defined in
-	 * IEEE P802.11-REVmd/D3.0, 9.4.2.170.3 (Calculating the Short-SSID).
+	 * IEEE Std 802.11-2024, 9.4.2.169.3 (Calculating the Short-SSID).
 	 */
 	conf->ssid.short_ssid = ieee80211_crc32(conf->ssid.ssid,
 						conf->ssid.ssid_len);
@@ -1679,12 +1679,12 @@ setup_mld:
 		return -1;
 	}
 
-#ifdef CONFIG_INTERWORKING
+#if defined(CONFIG_INTERWORKING) || defined(CONFIG_DPP)
 	if (gas_serv_init(hapd)) {
 		wpa_printf(MSG_ERROR, "GAS server initialization failed");
 		return -1;
 	}
-#endif /* CONFIG_INTERWORKING */
+#endif /* CONFIG_INTERWORKING || CONFIG_DPP */
 
 	if (conf->qos_map_set_len &&
 	    hostapd_drv_set_qos_map(hapd, conf->qos_map_set,
@@ -4256,6 +4256,14 @@ void free_beacon_data(struct beacon_data *beacon)
 	beacon->proberesp_ies = NULL;
 	os_free(beacon->assocresp_ies);
 	beacon->assocresp_ies = NULL;
+	os_free(beacon->mbssid.mbssid_elem);
+	beacon->mbssid.mbssid_elem = NULL;
+	os_free(beacon->mbssid.mbssid_elem_offset);
+	beacon->mbssid.mbssid_elem_offset = NULL;
+	os_free(beacon->mbssid.rnr_elem);
+	beacon->mbssid.rnr_elem = NULL;
+	os_free(beacon->mbssid.rnr_elem_offset);
+	beacon->mbssid.rnr_elem_offset = NULL;
 }
 
 
@@ -4264,6 +4272,10 @@ int hostapd_build_beacon_data(struct hostapd_data *hapd,
 {
 	struct wpabuf *beacon_extra, *proberesp_extra, *assocresp_extra;
 	struct wpa_driver_ap_params params;
+	struct hostapd_data *tx_bss;
+	u8 *mbssid_start_eid, *rnr_start_eid;
+	size_t size = 0;
+	int i;
 	int ret;
 
 	os_memset(beacon, 0, sizeof(*beacon));
@@ -4327,6 +4339,76 @@ int hostapd_build_beacon_data(struct hostapd_data *hapd,
 		beacon->assocresp_ies_len = wpabuf_len(assocresp_extra);
 	}
 
+	/* MBSSID element */
+	if (!params.mbssid.mbssid_elem_len)
+		goto done;
+
+	tx_bss = hostapd_mbssid_get_tx_bss(hapd);
+	beacon->mbssid.mbssid_tx_iface = tx_bss->conf->iface;
+	beacon->mbssid.mbssid_tx_iface_linkid =
+		params.mbssid.mbssid_tx_iface_linkid;
+	beacon->mbssid.mbssid_index = params.mbssid.mbssid_index;
+
+	beacon->mbssid.mbssid_elem_len = params.mbssid.mbssid_elem_len;
+	beacon->mbssid.mbssid_elem_count = params.mbssid.mbssid_elem_count;
+	if (params.mbssid.mbssid_elem) {
+		beacon->mbssid.mbssid_elem =
+			os_memdup(params.mbssid.mbssid_elem,
+				  params.mbssid.mbssid_elem_len);
+		if (!beacon->mbssid.mbssid_elem)
+			goto free_beacon;
+	}
+	beacon->mbssid.ema = params.mbssid.ema;
+
+	if (params.mbssid.mbssid_elem_offset) {
+		beacon->mbssid.mbssid_elem_offset =
+			os_calloc(beacon->mbssid.mbssid_elem_count,
+				  sizeof(u8 *));
+		if (!beacon->mbssid.mbssid_elem_offset)
+			goto free_beacon;
+
+		mbssid_start_eid = beacon->mbssid.mbssid_elem;
+		beacon->mbssid.mbssid_elem_offset[0] = mbssid_start_eid;
+		for (i = 0; i < beacon->mbssid.mbssid_elem_count - 1; i++) {
+			size = params.mbssid.mbssid_elem_offset[i + 1] -
+				params.mbssid.mbssid_elem_offset[i];
+			mbssid_start_eid = mbssid_start_eid + size;
+			beacon->mbssid.mbssid_elem_offset[i + 1] =
+				mbssid_start_eid;
+		}
+	}
+
+	/* RNR element */
+	if (!params.mbssid.rnr_elem_len)
+		goto done;
+
+	if (params.mbssid.rnr_elem) {
+		beacon->mbssid.rnr_elem = os_memdup(params.mbssid.rnr_elem,
+						    params.mbssid.rnr_elem_len);
+		if (!beacon->mbssid.rnr_elem)
+			goto free_beacon;
+	}
+
+	beacon->mbssid.rnr_elem_len = params.mbssid.rnr_elem_len;
+	beacon->mbssid.rnr_elem_count = params.mbssid.rnr_elem_count;
+	if (params.mbssid.rnr_elem_offset) {
+		beacon->mbssid.rnr_elem_offset =
+			os_calloc(beacon->mbssid.rnr_elem_count + 1,
+				  sizeof(u8 *));
+		if (!beacon->mbssid.rnr_elem_offset)
+			goto free_beacon;
+
+		rnr_start_eid = beacon->mbssid.rnr_elem;
+		beacon->mbssid.rnr_elem_offset[0] = rnr_start_eid;
+		for (i = 0; i < beacon->mbssid.rnr_elem_count - 1; i++) {
+			size = params.mbssid.rnr_elem_offset[i + 1] -
+				params.mbssid.rnr_elem_offset[i];
+			rnr_start_eid = rnr_start_eid + size;
+			beacon->mbssid.rnr_elem_offset[i + 1] = rnr_start_eid;
+		}
+	}
+
+done:
 	ret = 0;
 free_beacon:
 	/* if the function fails, the caller should not free beacon data */
diff --git a/src/ap/ieee802_11.c b/src/ap/ieee802_11.c
index 523e0a32..ef5b4d24 100644
--- a/src/ap/ieee802_11.c
+++ b/src/ap/ieee802_11.c
@@ -3377,6 +3377,12 @@ static void handle_auth(struct hostapd_data *hapd,
 	if (!sta->added_unassoc && auth_transaction == 1) {
 		ap_sta_free_sta_profile(&sta->mld_info);
 		os_memset(&sta->mld_info, 0, sizeof(sta->mld_info));
+		if ((!(sta->flags & WLAN_STA_MFP) ||
+		     !ap_sta_is_authorized(sta)) && sta->wpa_sm) {
+			wpa_auth_sta_deinit(sta->wpa_sm);
+			sta->wpa_sm = NULL;
+			clear_wpa_sm_for_each_partner_link(hapd, sta);
+		}
 
 		if (mld_sta) {
 			u8 link_id = hapd->mld_link_id;
@@ -4788,7 +4794,7 @@ static int ieee80211_ml_process_link(struct hostapd_data *hapd,
 	}
 
 	sta = ap_get_sta(hapd, origin_sta->addr);
-	if (sta) {
+	if (sta || TEST_FAIL()) {
 		wpa_printf(MSG_INFO, "MLD: link: Station already exists");
 		status = WLAN_STATUS_UNSPECIFIED_FAILURE;
 		sta = NULL;
@@ -4879,6 +4885,8 @@ out:
 
 	wpa_printf(MSG_DEBUG, "MLD: link: status=%u", status);
 	if (status != WLAN_STATUS_SUCCESS) {
+		wpa_release_link_auth_ref(origin_sta->wpa_sm,
+					  hapd->mld_link_id, true);
 		if (sta)
 			ap_free_sta(hapd, sta);
 		return -1;
@@ -4909,6 +4917,7 @@ int hostapd_process_assoc_ml_info(struct hostapd_data *hapd,
 				  bool reassoc, int tx_link_status,
 				  bool offload)
 {
+	int ret = 0;
 #ifdef CONFIG_IEEE80211BE
 	unsigned int i;
 
@@ -4950,12 +4959,12 @@ int hostapd_process_assoc_ml_info(struct hostapd_data *hapd,
 			if (ieee80211_ml_process_link(bss, sta, link,
 						      ies, ies_len, reassoc,
 						      offload))
-				return -1;
+				ret = -1;
 		}
 	}
 #endif /* CONFIG_IEEE80211BE */
 
-	return 0;
+	return ret;
 }
 
 
@@ -6478,32 +6487,6 @@ static int handle_action(struct hostapd_data *hapd,
 		       "handle_action - unknown action category %d or invalid "
 		       "frame",
 		       mgmt->u.action.category);
-	if (!is_multicast_ether_addr(mgmt->da) &&
-	    !(mgmt->u.action.category & 0x80) &&
-	    !is_multicast_ether_addr(mgmt->sa)) {
-		struct ieee80211_mgmt *resp;
-
-		/*
-		 * IEEE 802.11-REVma/D9.0 - 7.3.1.11
-		 * Return the Action frame to the source without change
-		 * except that MSB of the Category set to 1.
-		 */
-		wpa_printf(MSG_DEBUG, "IEEE 802.11: Return unknown Action "
-			   "frame back to sender");
-		resp = os_memdup(mgmt, len);
-		if (resp == NULL)
-			return 0;
-		os_memcpy(resp->da, resp->sa, ETH_ALEN);
-		os_memcpy(resp->sa, hapd->own_addr, ETH_ALEN);
-		os_memcpy(resp->bssid, hapd->own_addr, ETH_ALEN);
-		resp->u.action.category |= 0x80;
-
-		if (hostapd_drv_send_mlme(hapd, resp, len, 0, NULL, 0, 0) < 0) {
-			wpa_printf(MSG_ERROR, "IEEE 802.11: Failed to send "
-				   "Action frame");
-		}
-		os_free(resp);
-	}
 
 	return 1;
 }
@@ -7556,7 +7539,8 @@ static u8 * hostapd_eid_wb_channel_switch(struct hostapd_data *hapd, u8 *eid,
 	u8 bw;
 
 	/* bandwidth: 0: 40, 1: 80, 160, 80+80, 4 to 255 reserved as per
-	 * IEEE P802.11-REVme/D7.0, 9.4.2.159 and Table 9-316.
+	 * IEEE Std 802.11-2024, 9.4.2.156 and Table 9-316 (VHT Operation
+	 * Information subfields).
 	 */
 	switch (hapd->cs_freq_params.bandwidth) {
 	case 320:
@@ -7576,7 +7560,8 @@ static u8 * hostapd_eid_wb_channel_switch(struct hostapd_data *hapd, u8 *eid,
 		/* fallthrough */
 	case 160:
 		/* Update the CCFS0 and CCFS1 values in the element based on
-		 * IEEE P802.11-REVme/D7.0, Table 9-316
+		 * IEEE Std 802.11-2024, Table 9-316 (VHT Operation
+		 * Information subfields).
 		 */
 
 		/* CCFS1 - The channel center frequency index of the 160 MHz
@@ -7755,6 +7740,44 @@ static size_t hostapd_eid_nr_db_len(struct hostapd_data *hapd,
 }
 
 
+#ifdef CONFIG_IEEE80211BE
+static bool hostapd_mbssid_mld_match(struct hostapd_data *tx_hapd,
+				     struct hostapd_data *ml_hapd,
+				     u8 *match_idx)
+{
+	size_t bss_idx;
+
+	if (!ml_hapd->conf->mld_ap)
+		return false;
+
+	if (!tx_hapd->iconf->mbssid || tx_hapd->iface->num_bss <= 1) {
+		if (hostapd_is_ml_partner(tx_hapd, ml_hapd)) {
+			if (match_idx)
+				*match_idx = 0;
+			return true;
+		}
+
+		return false;
+	}
+
+	for (bss_idx = 0; bss_idx < tx_hapd->iface->num_bss; bss_idx++) {
+		struct hostapd_data *bss = tx_hapd->iface->bss[bss_idx];
+
+		if (!bss)
+			continue;
+
+		if (hostapd_is_ml_partner(bss, ml_hapd)) {
+			if (match_idx)
+				*match_idx = bss_idx;
+			return true;
+		}
+	}
+
+	return false;
+}
+#endif /* CONFIG_IEEE80211BE */
+
+
 struct mbssid_ie_profiles {
 	u8 start;
 	u8 end;
@@ -7763,9 +7786,9 @@ struct mbssid_ie_profiles {
 static bool hostapd_skip_rnr(size_t i, struct mbssid_ie_profiles *skip_profiles,
 			     bool ap_mld, u8 tbtt_info_len, bool mld_update,
 			     struct hostapd_data *reporting_hapd,
-			     struct hostapd_data *bss)
+			     struct hostapd_data *bss, u8 *match_idx)
 {
-	if (skip_profiles &&
+	if (!mld_update && skip_profiles &&
 	    i >= skip_profiles->start && i < skip_profiles->end)
 		return true;
 
@@ -7787,7 +7810,17 @@ static bool hostapd_skip_rnr(size_t i, struct mbssid_ie_profiles *skip_profiles,
 
 	/* If building for ML RNR and they are not ML partners, don't include.
 	 */
-	if (mld_update && !hostapd_is_ml_partner(reporting_hapd, bss))
+	if (mld_update &&
+	    !hostapd_mbssid_mld_match(reporting_hapd, bss, match_idx))
+		return true;
+
+	/* When MLD parameters are added to beacon RNR and in case of EMA
+	 * beacons we report only affiliated APs belonging to the reported
+	 * non Tx profiles and TX profile will be reported in every EMA beacon.
+	 */
+	if (mld_update && skip_profiles && match_idx &&
+	    (*match_idx < skip_profiles->start ||
+	     *match_idx >= skip_profiles->end))
 		return true;
 #endif /* CONFIG_IEEE80211BE */
 
@@ -7841,7 +7874,7 @@ repeat_rnr_len:
 
 			if (hostapd_skip_rnr(i, skip_profiles, ap_mld,
 					     tbtt_info_len, mld_update,
-					     reporting_hapd, bss))
+					     reporting_hapd, bss, NULL))
 				continue;
 
 			if (len + tbtt_info_len > 255 ||
@@ -7958,6 +7991,7 @@ static size_t hostapd_eid_rnr_colocation_len(struct hostapd_data *hapd,
 
 
 static size_t hostapd_eid_rnr_mlo_len(struct hostapd_data *hapd, u32 type,
+				      struct mbssid_ie_profiles *skip_profiles,
 				      size_t *current_len)
 {
 	size_t len = 0;
@@ -7965,7 +7999,7 @@ static size_t hostapd_eid_rnr_mlo_len(struct hostapd_data *hapd, u32 type,
 	struct hostapd_iface *iface;
 	size_t i;
 
-	if (!hapd->iface || !hapd->iface->interfaces || !hapd->conf->mld_ap)
+	if (!hapd->iface || !hapd->iface->interfaces)
 		return 0;
 
 	/* TODO: Allow for FILS/Action as well */
@@ -7980,7 +8014,8 @@ static size_t hostapd_eid_rnr_mlo_len(struct hostapd_data *hapd, u32 type,
 			continue;
 
 		len += hostapd_eid_rnr_iface_len(iface->bss[0], hapd,
-						 current_len, NULL, true);
+						 current_len, skip_profiles,
+						 true);
 	}
 #endif /* CONFIG_IEEE80211BE */
 
@@ -8024,7 +8059,8 @@ size_t hostapd_eid_rnr_len(struct hostapd_data *hapd, u32 type,
 	if (include_mld_params &&
 	    (type != WLAN_FC_STYPE_BEACON ||
 	     hapd->iconf->mbssid != ENHANCED_MBSSID_ENABLED))
-		total_len += hostapd_eid_rnr_mlo_len(hapd, type, &current_len);
+		total_len += hostapd_eid_rnr_mlo_len(hapd, type, NULL,
+						     &current_len);
 
 	return total_len;
 }
@@ -8094,7 +8130,7 @@ static bool hostapd_eid_rnr_bss(struct hostapd_data *hapd,
 {
 	struct hostapd_iface *iface = hapd->iface;
 	struct hostapd_data *bss = iface->bss[i];
-	u8 bss_param = 0;
+	u8 bss_param = 0, match_idx = 255;
 	bool ap_mld = false;
 	u8 *eid = *pos;
 
@@ -8107,7 +8143,7 @@ static bool hostapd_eid_rnr_bss(struct hostapd_data *hapd,
 		return false;
 
 	if (hostapd_skip_rnr(i, skip_profiles, ap_mld, tbtt_info_len,
-			     mld_update, reporting_hapd, bss))
+			     mld_update, reporting_hapd, bss, &match_idx))
 	    return false;
 
 	if (*len + RNR_TBTT_INFO_LEN > 255 ||
@@ -8150,22 +8186,21 @@ static bool hostapd_eid_rnr_bss(struct hostapd_data *hapd,
 #ifdef CONFIG_IEEE80211BE
 	if (ap_mld) {
 		u8 param_ch = bss->eht_mld_bss_param_change;
-		bool is_partner;
 
-		/* If BSS is not a partner of the reporting_hapd
+		/* If BSS is not a partner of the reporting_hapd or
+		 * it is one of the nontransmitted hapd,
 		 *  a) MLD ID advertised shall be 255.
 		 *  b) Link ID advertised shall be 15.
 		 *  c) BPCC advertised shall be 255 */
-		is_partner = hostapd_is_ml_partner(bss, reporting_hapd);
 		/* MLD ID */
-		*eid++ = is_partner ? hostapd_get_mld_id(bss) : 0xFF;
+		*eid++ = match_idx;
 		/* Link ID (Bit 3 to Bit 0)
 		 * BPCC (Bit 4 to Bit 7) */
-		*eid++ = is_partner ?
+		*eid++ = match_idx < 255 ?
 			bss->mld_link_id | ((param_ch & 0xF) << 4) :
 			(MAX_NUM_MLD_LINKS | 0xF0);
 		/* BPCC (Bit 3 to Bit 0) */
-		*eid = is_partner ? ((param_ch & 0xF0) >> 4) : 0x0F;
+		*eid = match_idx < 255 ? ((param_ch & 0xF0) >> 4) : 0x0F;
 #ifdef CONFIG_TESTING_OPTIONS
 		if (bss->conf->mld_indicate_disabled)
 			*eid |= RNR_TBTT_INFO_MLD_PARAM2_LINK_DISABLED;
@@ -8282,13 +8317,15 @@ static u8 * hostapd_eid_rnr_colocation(struct hostapd_data *hapd, u8 *eid,
 
 
 static u8 * hostapd_eid_rnr_mlo(struct hostapd_data *hapd, u32 type,
-				u8 *eid, size_t *current_len)
+				u8 *eid,
+				struct mbssid_ie_profiles *skip_profiles,
+				size_t *current_len)
 {
 #ifdef CONFIG_IEEE80211BE
 	struct hostapd_iface *iface;
 	size_t i;
 
-	if (!hapd->iface || !hapd->iface->interfaces || !hapd->conf->mld_ap)
+	if (!hapd->iface || !hapd->iface->interfaces)
 		return eid;
 
 	/* TODO: Allow for FILS/Action as well */
@@ -8303,7 +8340,7 @@ static u8 * hostapd_eid_rnr_mlo(struct hostapd_data *hapd, u32 type,
 			continue;
 
 		eid = hostapd_eid_rnr_iface(iface->bss[0], hapd, eid,
-					    current_len, NULL, true);
+					    current_len, skip_profiles, true);
 	}
 #endif /* CONFIG_IEEE80211BE */
 
@@ -8347,7 +8384,7 @@ u8 * hostapd_eid_rnr(struct hostapd_data *hapd, u8 *eid, u32 type,
 	if (include_mld_params &&
 	    (type != WLAN_FC_STYPE_BEACON ||
 	     hapd->iconf->mbssid != ENHANCED_MBSSID_ENABLED))
-		eid = hostapd_eid_rnr_mlo(hapd, type, eid, &current_len);
+		eid = hostapd_eid_rnr_mlo(hapd, type, eid, NULL, &current_len);
 
 	if (eid == eid_start + 2)
 		return eid_start;
@@ -8457,6 +8494,17 @@ static size_t hostapd_eid_mbssid_elem_len(struct hostapd_data *hapd,
 			nontx_profile_len += xrate_len;
 		else if (tx_xrate_len)
 			ie_count++;
+
+#ifdef CONFIG_IEEE80211BE
+		/* For ML Probe Response frame, the solicited hapd's MLE will
+		 * be in the frame body */
+		if (bss->conf->mld_ap &&
+		    (bss != hapd || frame_type != WLAN_FC_STYPE_PROBE_RESP))
+			nontx_profile_len += hostapd_eid_eht_basic_ml_len(bss,
+									  NULL,
+									  true);
+#endif /* CONFIG_IEEE80211BE */
+
 		if (ie_count)
 			nontx_profile_len += 4 + ie_count + 1;
 
@@ -8478,11 +8526,6 @@ size_t hostapd_eid_mbssid_len(struct hostapd_data *hapd, u32 frame_type,
 			      size_t known_bss_len, size_t *rnr_len)
 {
 	size_t len = 0, bss_index = 1;
-	bool ap_mld = false;
-
-#ifdef CONFIG_IEEE80211BE
-	ap_mld = hapd->conf->mld_ap;
-#endif /* CONFIG_IEEE80211BE */
 
 	if (!hapd->iconf->mbssid || hapd->iface->num_bss <= 1 ||
 	    (frame_type != WLAN_FC_STYPE_BEACON &&
@@ -8515,7 +8558,11 @@ size_t hostapd_eid_mbssid_len(struct hostapd_data *hapd, u32 frame_type,
 
 			*rnr_len += hostapd_eid_rnr_iface_len(
 				hapd, hostapd_mbssid_get_tx_bss(hapd),
-				&rnr_cur_len, &skip_profiles, ap_mld);
+				&rnr_cur_len, &skip_profiles, false);
+
+			*rnr_len += hostapd_eid_rnr_mlo_len(
+				hostapd_mbssid_get_tx_bss(hapd), frame_type,
+				&skip_profiles, &rnr_cur_len);
 		}
 	}
 
@@ -8624,6 +8671,14 @@ static u8 * hostapd_eid_mbssid_elem(struct hostapd_data *hapd, u8 *eid, u8 *end,
 			non_inherit_ie[ie_count++] = WLAN_EID_EXT_SUPP_RATES;
 		if (!rsnx && hostapd_wpa_ie(tx_bss, WLAN_EID_RSNX))
 			non_inherit_ie[ie_count++] = WLAN_EID_RSNX;
+#ifdef CONFIG_IEEE80211BE
+		/* For ML Probe Response frame, the solicited hapd's MLE will
+		 * be in the frame body */
+		if (bss->conf->mld_ap &&
+		    (bss != hapd || frame_type != WLAN_FC_STYPE_PROBE_RESP))
+			eid = hostapd_eid_eht_basic_ml_common(bss, eid, NULL,
+							      true);
+#endif /* CONFIG_IEEE80211BE */
 		if (ie_count) {
 			*eid++ = WLAN_EID_EXTENSION;
 			*eid++ = 2 + ie_count + 1;
@@ -8659,11 +8714,7 @@ u8 * hostapd_eid_mbssid(struct hostapd_data *hapd, u8 *eid, u8 *end,
 {
 	size_t bss_index = 1, cur_len = 0;
 	u8 elem_index = 0, *rnr_start_eid = rnr_eid;
-	bool add_rnr, ap_mld = false;
-
-#ifdef CONFIG_IEEE80211BE
-	ap_mld = hapd->conf->mld_ap;
-#endif /* CONFIG_IEEE80211BE */
+	bool add_rnr;
 
 	if (!hapd->iconf->mbssid || hapd->iface->num_bss <= 1 ||
 	    (frame_stype != WLAN_FC_STYPE_BEACON &&
@@ -8708,7 +8759,10 @@ u8 * hostapd_eid_mbssid(struct hostapd_data *hapd, u8 *eid, u8 *end,
 			cur_len = 0;
 			rnr_eid = hostapd_eid_rnr_iface(
 				hapd, hostapd_mbssid_get_tx_bss(hapd),
-				rnr_eid, &cur_len, &skip_profiles, ap_mld);
+				rnr_eid, &cur_len, &skip_profiles, false);
+			rnr_eid = hostapd_eid_rnr_mlo(
+				hostapd_mbssid_get_tx_bss(hapd), frame_stype,
+				rnr_eid, &skip_profiles, &cur_len);
 		}
 	}
 
diff --git a/src/ap/ieee802_11.h b/src/ap/ieee802_11.h
index 2bcc29eb..da97c25e 100644
--- a/src/ap/ieee802_11.h
+++ b/src/ap/ieee802_11.h
@@ -94,6 +94,12 @@ u8 * hostapd_eid_eht_ml_beacon(struct hostapd_data *hapd,
 			       u8 *eid, bool include_mld_id);
 u8 * hostapd_eid_eht_ml_assoc(struct hostapd_data *hapd, struct sta_info *info,
 			      u8 *eid);
+u8 * hostapd_eid_eht_basic_ml_common(struct hostapd_data *hapd,
+				     u8 *eid, struct mld_info *mld_info,
+				     bool include_mld_id);
+size_t hostapd_eid_eht_basic_ml_len(struct hostapd_data *hapd,
+				    struct sta_info *info,
+				    bool include_mld_id);
 size_t hostapd_eid_eht_ml_beacon_len(struct hostapd_data *hapd,
 				     struct mld_info *info,
 				     bool include_mld_id);
diff --git a/src/ap/ieee802_11_eht.c b/src/ap/ieee802_11_eht.c
index 0d0a0091..e2441962 100644
--- a/src/ap/ieee802_11_eht.c
+++ b/src/ap/ieee802_11_eht.c
@@ -439,9 +439,15 @@ void hostapd_get_eht_capab(struct hostapd_data *hapd,
 }
 
 
-static u8 * hostapd_eid_eht_basic_ml_common(struct hostapd_data *hapd,
-					    u8 *eid, struct mld_info *mld_info,
-					    bool include_mld_id)
+/* Beacon or a non ML Probe Response frame should include
+ * Common Info Length(1) + MLD MAC Address(6) +
+ * Link ID Info(1) + BSS Parameters Change count(1) +
+ * EML Capabilities (2) + MLD Capabilities (2)
+ */
+#define EHT_ML_COMMON_INFO_LEN 13
+u8 * hostapd_eid_eht_basic_ml_common(struct hostapd_data *hapd,
+				     u8 *eid, struct mld_info *mld_info,
+				     bool include_mld_id)
 {
 	struct wpabuf *buf;
 	u16 control;
@@ -475,7 +481,6 @@ static u8 * hostapd_eid_eht_basic_ml_common(struct hostapd_data *hapd,
 	 * BSS Parameters Change Count (1) + EML Capabilities (2) +
 	 * MLD Capabilities and Operations (2)
 	 */
-#define EHT_ML_COMMON_INFO_LEN 13
 	common_info_len = EHT_ML_COMMON_INFO_LEN;
 
 	if (include_mld_id) {
@@ -667,6 +672,76 @@ out:
 }
 
 
+/*
+ * control (2) + station info length (1) + MAC address (6) +
+ * beacon interval (2) + TSF offset (8) + DTIM info (2) + BSS
+ * parameters change counter (1)
+ */
+#define EHT_ML_STA_INFO_LENGTH 22
+size_t hostapd_eid_eht_basic_ml_len(struct hostapd_data *hapd,
+				    struct sta_info *info,
+				    bool include_mld_id)
+{
+	int link_id;
+	size_t len, num_frags;
+
+	if (!hapd->conf->mld_ap)
+		return 0;
+
+	/* Include WLAN_EID_EXT_MULTI_LINK (1) */
+	len = 1;
+	/* control field */
+	len += 2;
+	/* Common info len for Basic MLE */
+	len += EHT_ML_COMMON_INFO_LEN;
+	if (include_mld_id)
+		len++;
+
+	if (!info)
+		goto out;
+
+	/* Add link info for the other links */
+	for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; link_id++) {
+		struct mld_link_info *link = &info->mld_info.links[link_id];
+		struct hostapd_data *link_bss;
+		size_t sta_prof_len = EHT_ML_STA_INFO_LENGTH +
+			link->resp_sta_profile_len;
+
+		/* Skip the local one */
+		if (link_id == hapd->mld_link_id || !link->valid)
+			continue;
+
+		link_bss = hostapd_mld_get_link_bss(hapd, link_id);
+		if (!link_bss) {
+			wpa_printf(MSG_ERROR,
+				   "MLD: Couldn't find link BSS - skip it");
+			continue;
+		}
+
+		/* Per-STA Profile Subelement(1), Length (1) */
+		len += 2;
+		len += sta_prof_len;
+		/* Consider Fragment EID(1) and Length (1) for each subelement
+		 * fragment. */
+		if (sta_prof_len > 255) {
+			num_frags = (sta_prof_len / 255 - 1) +
+				!!(sta_prof_len % 255);
+			len += num_frags * 2;
+		}
+
+	}
+
+out:
+	if (len > 255) {
+		num_frags = (len / 255 - 1) + !!(len % 255);
+		len += num_frags * 2;
+	}
+
+	/* WLAN_EID_EXTENSION (1) + length (1) */
+	return len + 2;
+}
+
+
 static u8 * hostapd_eid_eht_reconf_ml(struct hostapd_data *hapd, u8 *eid)
 {
 #ifdef CONFIG_TESTING_OPTIONS
@@ -982,7 +1057,7 @@ static const u8 * auth_skip_fixed_fields(struct hostapd_data *hapd,
 #endif /* CONFIG_SAE */
 	const u8 *pos = mgmt->u.auth.variable;
 
-	/* Skip fixed fields as based on IEE P802.11-REVme/D3.0, Table 9-69
+	/* Skip fixed fields as based on IEEE Std 802.11-2024, Table 9-71
 	 * (Presence of fields and elements in Authentications frames) */
 	switch (auth_alg) {
 	case WLAN_AUTH_OPEN:
@@ -1278,13 +1353,26 @@ u16 hostapd_process_ml_assoc_req(struct hostapd_data *hapd,
 	 * length Common Info field. */
 	pos = end;
 	while (ml_end - pos > 2) {
-		size_t sub_elem_len = *(pos + 1);
-		size_t sta_info_len;
+		size_t sub_elem_len, sta_info_len;
 		u16 control;
 		const u8 *sub_elem_end;
+		int num_frag_subelems;
 
-		wpa_printf(MSG_DEBUG, "MLD: sub element len=%zu",
-			   sub_elem_len);
+		num_frag_subelems =
+			ieee802_11_defrag_mle_subelem(mlbuf, pos,
+						      &sub_elem_len);
+		if (num_frag_subelems < 0) {
+			wpa_printf(MSG_DEBUG,
+				   "MLD: Failed to parse MLE subelem");
+			goto out;
+		}
+
+		ml_len -= num_frag_subelems * 2;
+		ml_end = ((const u8 *) ml) + ml_len;
+
+		wpa_printf(MSG_DEBUG,
+			   "MLD: sub element len=%zu, Fragment subelems=%u",
+			   sub_elem_len, num_frag_subelems);
 
 		if (2 + sub_elem_len > (size_t) (ml_end - pos)) {
 			wpa_printf(MSG_DEBUG,
diff --git a/src/ap/ieee802_11_shared.c b/src/ap/ieee802_11_shared.c
index 986b7b81..e873e1c1 100644
--- a/src/ap/ieee802_11_shared.c
+++ b/src/ap/ieee802_11_shared.c
@@ -381,6 +381,10 @@ static void hostapd_ext_capab_byte(struct hostapd_data *hapd, u8 *pos, int idx,
 			/* Bit 13 - Collocated Interference Reporting */
 			*pos |= 0x20;
 		}
+		if (hapd->iface->conf->civic)
+			*pos |= 0x40; /* Bit 14 - Civic Location */
+		if (hapd->iface->conf->lci)
+			*pos |= 0x80; /* Bit 15 - Geospatial Location */
 		break;
 	case 2: /* Bits 16-23 */
 		if (hapd->conf->wnm_sleep_mode)
diff --git a/src/ap/ieee802_11_vht.c b/src/ap/ieee802_11_vht.c
index 4dc325ce..df5f8cf7 100644
--- a/src/ap/ieee802_11_vht.c
+++ b/src/ap/ieee802_11_vht.c
@@ -95,6 +95,9 @@ u8 * hostapd_eid_vht_operation(struct hostapd_data *hapd, u8 *eid)
 
 #ifdef CONFIG_IEEE80211BE
 	if (punct_bitmap) {
+		oper_chwidth = hostapd_get_oper_chwidth(hapd->iconf);
+		seg0 = hostapd_get_oper_centr_freq_seg0_idx(hapd->iconf);
+		seg1 = hostapd_get_oper_centr_freq_seg1_idx(hapd->iconf);
 		punct_update_legacy_bw(punct_bitmap,
 				       hapd->iconf->channel,
 				       &oper_chwidth, &seg0, &seg1);
diff --git a/src/ap/neighbor_db.c b/src/ap/neighbor_db.c
index f7a7d83d..1768982d 100644
--- a/src/ap/neighbor_db.c
+++ b/src/ap/neighbor_db.c
@@ -266,8 +266,6 @@ void hostapd_neighbor_set_own_report(struct hostapd_data *hapd)
 	if (ht) {
 		bssid_info |= NEI_REP_BSSID_INFO_HT |
 			NEI_REP_BSSID_INFO_DELAYED_BA;
-
-		/* VHT bit added in IEEE P802.11-REVmc/D4.3 */
 		if (vht)
 			bssid_info |= NEI_REP_BSSID_INFO_VHT;
 	}
@@ -317,8 +315,8 @@ void hostapd_neighbor_set_own_report(struct hostapd_data *hapd)
 
 	/*
 	 * Wide Bandwidth Channel subelement may be needed to allow the
-	 * receiving STA to send packets to the AP. See IEEE P802.11-REVmc/D5.0
-	 * Figure 9-301.
+	 * receiving STA to send packets to the AP. See IEEE Std 802.11-2024,
+	 * Figure 9-423 (Wide Bandwidth Channel subelement format).
 	 */
 	wpabuf_put_u8(nr, WNM_NEIGHBOR_WIDE_BW_CHAN);
 	wpabuf_put_u8(nr, 3);
diff --git a/src/ap/rrm.c b/src/ap/rrm.c
index fbcddf3f..73771e4c 100644
--- a/src/ap/rrm.c
+++ b/src/ap/rrm.c
@@ -536,13 +536,14 @@ int hostapd_send_range_req(struct hostapd_data *hapd, const u8 *addr,
 	if (!hapd->range_req_token) /* For wraparounds */
 		hapd->range_req_token++;
 
-	/* IEEE P802.11-REVmc/D5.0, 9.6.7.2 */
+	/* IEEE Std 802.11-2024, 9.6.6.2 (Radio Measurement Request frame
+	 * format) */
 	wpabuf_put_u8(buf, WLAN_ACTION_RADIO_MEASUREMENT);
 	wpabuf_put_u8(buf, WLAN_RRM_RADIO_MEASUREMENT_REQUEST);
 	wpabuf_put_u8(buf, hapd->range_req_token); /* Dialog Token */
 	wpabuf_put_le16(buf, 0); /* Number of Repetitions */
 
-	/* IEEE P802.11-REVmc/D5.0, 9.4.2.21 */
+	/* IEEE Std 802.11-2024, 9.4.2.19 (Measurement Request element) */
 	wpabuf_put_u8(buf, WLAN_EID_MEASURE_REQUEST);
 	len = wpabuf_put(buf, 1); /* Length will be set later */
 
@@ -554,7 +555,7 @@ int hostapd_send_range_req(struct hostapd_data *hapd, const u8 *addr,
 	wpabuf_put_u8(buf, 0); /* Measurement Request Mode */
 	wpabuf_put_u8(buf, MEASURE_TYPE_FTM_RANGE); /* Measurement Type */
 
-	/* IEEE P802.11-REVmc/D5.0, 9.4.2.21.19 */
+	/* IEEE Std 802.11-2024, 9.4.2.19.19 (FTM Range request) */
 	wpabuf_put_le16(buf, random_interval); /* Randomization Interval */
 	wpabuf_put_u8(buf, min_ap); /* Minimum AP Count */
 
diff --git a/src/ap/sta_info.c b/src/ap/sta_info.c
index 8aa96d2c..d43fb477 100644
--- a/src/ap/sta_info.c
+++ b/src/ap/sta_info.c
@@ -191,9 +191,10 @@ void ap_free_sta_pasn(struct hostapd_data *hapd, struct sta_info *sta)
 static void __ap_free_sta(struct hostapd_data *hapd, struct sta_info *sta)
 {
 #ifdef CONFIG_IEEE80211BE
-	if (hostapd_sta_is_link_sta(hapd, sta) &&
-	    !hostapd_drv_link_sta_remove(hapd, sta->addr))
+	if (hostapd_sta_is_link_sta(hapd, sta)) {
+		hostapd_drv_link_sta_remove(hapd, sta->addr);
 		return;
+	}
 #endif /* CONFIG_IEEE80211BE */
 
 	hostapd_drv_sta_remove(hapd, sta->addr);
@@ -201,8 +202,8 @@ static void __ap_free_sta(struct hostapd_data *hapd, struct sta_info *sta)
 
 
 #ifdef CONFIG_IEEE80211BE
-static void clear_wpa_sm_for_each_partner_link(struct hostapd_data *hapd,
-					       struct sta_info *psta)
+void clear_wpa_sm_for_each_partner_link(struct hostapd_data *hapd,
+					struct sta_info *psta)
 {
 	struct sta_info *lsta;
 	struct hostapd_data *lhapd;
@@ -350,7 +351,8 @@ void ap_free_sta(struct hostapd_data *hapd, struct sta_info *sta)
 	/* Release group references in case non-association link STA is removed
 	 * before association link STA */
 	if (hostapd_sta_is_link_sta(hapd, sta))
-		wpa_release_link_auth_ref(sta->wpa_sm, hapd->mld_link_id);
+		wpa_release_link_auth_ref(sta->wpa_sm, hapd->mld_link_id,
+					  false);
 #else /* CONFIG_IEEE80211BE */
 	wpa_auth_sta_deinit(sta->wpa_sm);
 #endif /* CONFIG_IEEE80211BE */
@@ -392,7 +394,7 @@ void ap_free_sta(struct hostapd_data *hapd, struct sta_info *sta)
 	p2p_group_notif_disassoc(hapd->p2p_group, sta->addr);
 #endif /* CONFIG_P2P */
 
-#ifdef CONFIG_INTERWORKING
+#if defined(CONFIG_INTERWORKING) || defined(CONFIG_DPP)
 	if (sta->gas_dialog) {
 		int i;
 
@@ -400,7 +402,7 @@ void ap_free_sta(struct hostapd_data *hapd, struct sta_info *sta)
 			gas_serv_dialog_clear(&sta->gas_dialog[i]);
 		os_free(sta->gas_dialog);
 	}
-#endif /* CONFIG_INTERWORKING */
+#endif /* CONFIG_INTERWORKING || CONFIG_DPP */
 
 	wpabuf_free(sta->wps_ie);
 	wpabuf_free(sta->p2p_ie);
diff --git a/src/ap/sta_info.h b/src/ap/sta_info.h
index 1730742a..9a8f4068 100644
--- a/src/ap/sta_info.h
+++ b/src/ap/sta_info.h
@@ -431,5 +431,7 @@ static inline void ap_sta_set_mld(struct sta_info *sta, bool mld)
 void ap_sta_free_sta_profile(struct mld_info *info);
 
 void hostapd_free_link_stas(struct hostapd_data *hapd);
+void clear_wpa_sm_for_each_partner_link(struct hostapd_data *hapd,
+					struct sta_info *psta);
 
 #endif /* STA_INFO_H */
diff --git a/src/ap/wpa_auth.c b/src/ap/wpa_auth.c
index 9295dc6a..29bd9bb8 100644
--- a/src/ap/wpa_auth.c
+++ b/src/ap/wpa_auth.c
@@ -125,17 +125,24 @@ static void wpa_gkeydone_sta(struct wpa_state_machine *sm)
 
 #ifdef CONFIG_IEEE80211BE
 
-void wpa_release_link_auth_ref(struct wpa_state_machine *sm,
-			       int release_link_id)
+void wpa_release_link_auth_ref(struct wpa_state_machine *sm, u8 link_id,
+			       bool rejected)
 {
-	int link_id;
+	struct wpa_authenticator *wpa_auth;
+	struct mld_link *link;
 
-	if (!sm || release_link_id >= MAX_NUM_MLD_LINKS)
+	if (!sm || link_id >= MAX_NUM_MLD_LINKS)
 		return;
 
-	for_each_sm_auth(sm, link_id) {
-		if (link_id == release_link_id)
-			sm->mld_links[link_id].wpa_auth = NULL;
+	link = &sm->mld_links[link_id];
+	if (link->valid) {
+		link->valid = false;
+		link->rejected = rejected;
+		wpa_auth = link->wpa_auth;
+		if (wpa_auth) {
+			link->wpa_auth = NULL;
+			wpa_group_put(wpa_auth, wpa_auth->group);
+		}
 	}
 }
 
@@ -634,7 +641,7 @@ void wpa_auth_set_ptk_rekey_timer(struct wpa_state_machine *sm)
 			   MACSTR " (%d seconds)",
 			   MAC2STR(wpa_auth_get_spa(sm)),
 			   sm->wpa_auth->conf.wpa_ptk_rekey);
-		eloop_cancel_timeout(wpa_rekey_ptk, sm->wpa_auth, sm);
+		eloop_cancel_timeout(wpa_rekey_ptk, ELOOP_ALL_CTX, sm);
 		eloop_register_timeout(sm->wpa_auth->conf.wpa_ptk_rekey, 0,
 				       wpa_rekey_ptk, sm->wpa_auth, sm);
 	}
@@ -1119,8 +1126,14 @@ static void wpa_free_sta_sm(struct wpa_state_machine *sm)
 	os_free(sm->rsnxe);
 	os_free(sm->rsn_selection);
 #ifdef CONFIG_IEEE80211BE
-	for_each_sm_auth(sm, link_id)
+	for_each_sm_auth(sm, link_id) {
+		struct wpa_authenticator *wpa_auth;
+
+		wpa_auth = sm->mld_links[link_id].wpa_auth;
 		sm->mld_links[link_id].wpa_auth = NULL;
+		sm->mld_links[link_id].valid = false;
+		wpa_group_put(wpa_auth, wpa_auth->group);
+	}
 #endif /* CONFIG_IEEE80211BE */
 	wpa_group_put(sm->wpa_auth, sm->group);
 #ifdef CONFIG_DPP2
@@ -1155,10 +1168,10 @@ void wpa_auth_sta_deinit(struct wpa_state_machine *sm)
 					       primary_auth, NULL);
 	}
 
-	eloop_cancel_timeout(wpa_send_eapol_timeout, wpa_auth, sm);
+	eloop_cancel_timeout(wpa_send_eapol_timeout, ELOOP_ALL_CTX, sm);
 	sm->pending_1_of_4_timeout = 0;
 	eloop_cancel_timeout(wpa_sm_call_step, sm, NULL);
-	eloop_cancel_timeout(wpa_rekey_ptk, wpa_auth, sm);
+	eloop_cancel_timeout(wpa_rekey_ptk, ELOOP_ALL_CTX, sm);
 #ifdef CONFIG_IEEE80211R_AP
 	wpa_ft_sta_deinit(sm);
 #endif /* CONFIG_IEEE80211R_AP */
@@ -1871,7 +1884,7 @@ void wpa_receive(struct wpa_authenticator *wpa_auth,
 	continue_fuzz:
 #endif /* TEST_FUZZ */
 		sm->MICVerified = true;
-		eloop_cancel_timeout(wpa_send_eapol_timeout, wpa_auth, sm);
+		eloop_cancel_timeout(wpa_send_eapol_timeout, ELOOP_ALL_CTX, sm);
 		sm->pending_1_of_4_timeout = 0;
 	}
 
@@ -2374,7 +2387,7 @@ void wpa_remove_ptk(struct wpa_state_machine *sm)
 		wpa_printf(MSG_DEBUG,
 			   "RSN: PTK Key ID 1 removal from the driver failed");
 	sm->pairwise_set = false;
-	eloop_cancel_timeout(wpa_rekey_ptk, sm->wpa_auth, sm);
+	eloop_cancel_timeout(wpa_rekey_ptk, ELOOP_ALL_CTX, sm);
 }
 
 
@@ -3676,6 +3689,12 @@ static int wpa_auth_validate_ml_kdes_m2(struct wpa_state_machine *sm,
 			return -1;
 		}
 
+		/* Skip rejected links although the non-AP MLD will send them in
+		 * M2 of the initial 4-way handshake. */
+		if (sm->mld_links[i].rejected) {
+			n_links++;
+			continue;
+		}
 		if (!sm->mld_links[i].valid || i == sm->mld_assoc_link_id) {
 			wpa_printf(MSG_DEBUG,
 				   "RSN: MLD: Invalid link ID=%u", i);
@@ -4078,7 +4097,7 @@ SM_STATE(WPA_PTK, PTKCALCNEGOTIATING)
 	}
 
 	sm->pending_1_of_4_timeout = 0;
-	eloop_cancel_timeout(wpa_send_eapol_timeout, sm->wpa_auth, sm);
+	eloop_cancel_timeout(wpa_send_eapol_timeout, ELOOP_ALL_CTX, sm);
 
 	if (wpa_key_mgmt_wpa_psk(sm->wpa_key_mgmt) && sm->PMK != pmk) {
 		/* PSK may have changed from the previous choice, so update
@@ -7011,7 +7030,7 @@ void wpa_auth_eapol_key_tx_status(struct wpa_authenticator *wpa_auth,
 		wpa_printf(MSG_DEBUG,
 			   "WPA: Increase initial EAPOL-Key 1/4 timeout by %u ms because of acknowledged frame",
 			   timeout_ms);
-		eloop_cancel_timeout(wpa_send_eapol_timeout, wpa_auth, sm);
+		eloop_cancel_timeout(wpa_send_eapol_timeout, ELOOP_ALL_CTX, sm);
 		eloop_register_timeout(timeout_ms / 1000,
 				       (timeout_ms % 1000) * 1000,
 				       wpa_send_eapol_timeout, wpa_auth, sm);
@@ -7601,6 +7620,7 @@ void wpa_auth_set_ml_info(struct wpa_state_machine *sm,
 		struct wpa_get_link_auth_ctx ctx;
 
 		sm_link->valid = link->valid;
+		sm_link->rejected = false;
 		if (!link->valid)
 			continue;
 
diff --git a/src/ap/wpa_auth.h b/src/ap/wpa_auth.h
index 45c8dd66..d849bab5 100644
--- a/src/ap/wpa_auth.h
+++ b/src/ap/wpa_auth.h
@@ -689,8 +689,8 @@ void wpa_auth_ml_get_key_info(struct wpa_authenticator *a,
 			      bool mgmt_frame_prot, bool beacon_prot,
 			      bool rekey);
 
-void wpa_release_link_auth_ref(struct wpa_state_machine *sm,
-			       int release_link_id);
+void wpa_release_link_auth_ref(struct wpa_state_machine *sm, u8 link_id,
+			       bool rejected);
 
 #define for_each_sm_auth(sm, link_id) \
 	for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; link_id++)	\
diff --git a/src/ap/wpa_auth_i.h b/src/ap/wpa_auth_i.h
index 0aa25b90..27658282 100644
--- a/src/ap/wpa_auth_i.h
+++ b/src/ap/wpa_auth_i.h
@@ -184,6 +184,7 @@ struct wpa_state_machine {
 
 	struct mld_link {
 		bool valid;
+		bool rejected;
 		u8 peer_addr[ETH_ALEN];
 
 		struct wpa_authenticator *wpa_auth;
diff --git a/src/ap/wpa_auth_ie.c b/src/ap/wpa_auth_ie.c
index d56eeaa0..83ae4e06 100644
--- a/src/ap/wpa_auth_ie.c
+++ b/src/ap/wpa_auth_ie.c
@@ -346,9 +346,6 @@ static u8 * rsne_write_data(u8 *buf, size_t len, u8 *pos, int group,
 
 		/* Management Group Cipher Suite */
 		switch (group_mgmt_cipher) {
-		case WPA_CIPHER_AES_128_CMAC:
-			RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_AES_128_CMAC);
-			break;
 		case WPA_CIPHER_BIP_GMAC_128:
 			RSN_SELECTOR_PUT(pos, RSN_CIPHER_SUITE_BIP_GMAC_128);
 			break;
@@ -832,6 +829,7 @@ wpa_validate_wpa_ie(struct wpa_authenticator *wpa_auth,
 	u32 selector;
 	size_t i;
 	const u8 *pmkid = NULL;
+	bool ap_pmf_enabled;
 
 	if (wpa_auth == NULL || sm == NULL)
 		return WPA_NOT_ENABLED;
@@ -1114,8 +1112,16 @@ wpa_validate_wpa_ie(struct wpa_authenticator *wpa_auth,
 				 wpa_auth->conf.ocv : 0);
 	}
 #endif /* CONFIG_OCV */
+	if (sm->rsn_override_2)
+		ap_pmf_enabled = conf->rsn_override_mfp_2 !=
+			NO_MGMT_FRAME_PROTECTION;
+	else if (sm->rsn_override)
+		ap_pmf_enabled = conf->rsn_override_mfp !=
+			NO_MGMT_FRAME_PROTECTION;
+	else
+		ap_pmf_enabled = conf->ieee80211w != NO_MGMT_FRAME_PROTECTION;
 
-	if (!wpa_auth_pmf_enabled(conf) ||
+	if (!ap_pmf_enabled ||
 	    !(data.capabilities & WPA_CAPABILITY_MFPC))
 		sm->mgmt_frame_prot = 0;
 	else
diff --git a/src/common/common_module_tests.c b/src/common/common_module_tests.c
index 5763c51f..4339fc77 100644
--- a/src/common/common_module_tests.c
+++ b/src/common/common_module_tests.c
@@ -608,7 +608,8 @@ static int sae_pk_tests(void)
 
 static int pasn_test_pasn_auth(void)
 {
-	/* Test vector taken from IEEE P802.11az/D2.6, J.12 */
+	/* Test vector taken from IEEE Std 802.11-2024,
+	 * J.12 (PASN Test Vectors) */
 	const u8 pmk[] = {
 		0xde, 0xf4, 0x3e, 0x55, 0x67, 0xe0, 0x1c, 0xa6,
 		0x64, 0x92, 0x65, 0xf1, 0x9a, 0x29, 0x0e, 0xef,
@@ -680,7 +681,8 @@ static int pasn_test_pasn_auth(void)
 
 static int pasn_test_no_pasn_auth(void)
 {
-	/* Test vector taken from IEEE P802.11az/D2.6, J.13 */
+	/* Test vector taken from IEEE Std 802.11-2024,
+	 * J.13 (KDK Test Vectors when PASN authentication is not used) */
 	const u8 pmk[] = {
 		0xde, 0xf4, 0x3e, 0x55, 0x67, 0xe0, 0x1c, 0xa6,
 		0x64, 0x92, 0x65, 0xf1, 0x9a, 0x29, 0x0e, 0xef,
diff --git a/src/common/ieee802_11_common.c b/src/common/ieee802_11_common.c
index c0d52652..a2f2ea4f 100644
--- a/src/common/ieee802_11_common.c
+++ b/src/common/ieee802_11_common.c
@@ -1024,14 +1024,25 @@ ParseRes ieee802_11_parse_link_assoc_req(struct ieee802_11_elems *elems,
 	pos += sizeof(*ml) + pos[sizeof(*ml)];
 
 	while (len > 2) {
-		size_t sub_elem_len = *(pos + 1);
-		size_t sta_info_len;
+		size_t sub_elem_len, sta_info_len;
 		u16 link_info_control;
 		const u8 *non_inherit;
+		int num_frag_subelems;
+
+		num_frag_subelems =
+			ieee802_11_defrag_mle_subelem(mlbuf, pos,
+						      &sub_elem_len);
+		if (num_frag_subelems < 0) {
+			wpa_printf(MSG_DEBUG,
+				   "MLD: Failed to parse MLE subelem");
+			goto out;
+		}
+
+		len -= num_frag_subelems * 2;
 
 		wpa_printf(MSG_DEBUG,
-			   "MLD: sub element: len=%zu, sub_elem_len=%zu",
-			   len, sub_elem_len);
+			   "MLD: sub element: len=%zu, sub_elem_len=%zu, Fragment subelems=%u",
+			   len, sub_elem_len, num_frag_subelems);
 
 		if (2 + sub_elem_len > len) {
 			if (show_errors)
@@ -2927,6 +2938,18 @@ int oper_class_bw_to_int(const struct oper_class_map *map)
 }
 
 
+bool is_24ghz_freq(int freq)
+{
+	return freq >= 2400 && freq <= 2484;
+}
+
+
+bool is_5ghz_freq(int freq)
+{
+	return freq >= 5150 && freq <= 5885;
+}
+
+
 int center_idx_to_bw_6ghz(u8 idx)
 {
 	/* Channel: 2 */
@@ -3447,6 +3470,70 @@ struct wpabuf * ieee802_11_defrag(const u8 *data, size_t len, bool ext_elem)
 }
 
 
+/**
+ * ieee802_11_defrag_mle_subelem - Defragment Multi-Link element subelements
+ * @mlbuf: Defragmented mlbuf (defragmented using ieee802_11_defrag())
+ * @parent_subelem: Pointer to the subelement which may be fragmented
+ * @defrag_len: Defragmented length of the subelement
+ * Returns: Number of Fragment subelements parsed on success, -1 otherwise
+ *
+ * This function defragments a subelement present inside an Multi-Link element.
+ * It should be called individually for each subelement.
+ *
+ * Subelements can use the Fragment subelement if they pack more than 255 bytes
+ * of data, see IEEE P802.11be/D7.0 Figure 35-4 - Per-STA Profile subelement
+ * fragmentation within a fragmented Multi-Link element.
+ */
+size_t ieee802_11_defrag_mle_subelem(struct wpabuf *mlbuf,
+				     const u8 *parent_subelem,
+				     size_t *defrag_len)
+{
+	u8 *buf, *pos, *end;
+	size_t len, subelem_len;
+	const size_t min_defrag_len = 255;
+	int num_frag_subelems = 0;
+
+	if (!mlbuf || !parent_subelem)
+		return -1;
+
+	buf = wpabuf_mhead_u8(mlbuf);
+	len = wpabuf_len(mlbuf);
+	end = buf + len;
+
+	*defrag_len = parent_subelem[1];
+	if (parent_subelem[1] < min_defrag_len)
+		return 0;
+
+	pos = (u8 *) parent_subelem;
+	if (2 + parent_subelem[1] > end - pos)
+		return -1;
+	pos += 2 + parent_subelem[1];
+	subelem_len = parent_subelem[1];
+
+	while (end - pos > 2 &&
+	       pos[0] == MULTI_LINK_SUB_ELEM_ID_FRAGMENT && pos[1]) {
+		size_t elen = 2 + pos[1];
+
+		/* This Multi-Link parent subelement has more data and is
+		 * fragmented. */
+		num_frag_subelems++;
+
+		if (elen > (size_t) (end - pos))
+			return -1;
+
+		os_memmove(pos, pos + 2, end - (pos + 2));
+		pos += elen - 2;
+		subelem_len += elen - 2;
+
+		/* Deduct Fragment subelement header */
+		len -= 2;
+	}
+
+	*defrag_len = subelem_len;
+	return num_frag_subelems;
+}
+
+
 const u8 * get_ml_ie(const u8 *ies, size_t len, u8 type)
 {
 	const struct element *elem;
diff --git a/src/common/ieee802_11_common.h b/src/common/ieee802_11_common.h
index 127375da..f57be562 100644
--- a/src/common/ieee802_11_common.h
+++ b/src/common/ieee802_11_common.h
@@ -300,6 +300,8 @@ u8 country_to_global_op_class(const char *country, u8 op_class);
 
 const struct oper_class_map * get_oper_class(const char *country, u8 op_class);
 int oper_class_bw_to_int(const struct oper_class_map *map);
+bool is_24ghz_freq(int freq);
+bool is_5ghz_freq(int freq);
 int center_idx_to_bw_6ghz(u8 idx);
 bool is_6ghz_freq(int freq);
 bool is_6ghz_op_class(u8 op_class);
@@ -378,6 +380,9 @@ int ieee802_edmg_is_allowed(struct ieee80211_edmg_config allowed,
 			    struct ieee80211_edmg_config requested);
 
 struct wpabuf * ieee802_11_defrag(const u8 *data, size_t len, bool ext_elem);
+size_t ieee802_11_defrag_mle_subelem(struct wpabuf *mlbuf,
+				     const u8 *parent_subelem,
+				     size_t *defrag_len);
 const u8 * get_ml_ie(const u8 *ies, size_t len, u8 type);
 const u8 * get_basic_mle_mld_addr(const u8 *buf, size_t len);
 
diff --git a/src/common/ieee802_11_defs.h b/src/common/ieee802_11_defs.h
index ca4ff88c..327d8929 100644
--- a/src/common/ieee802_11_defs.h
+++ b/src/common/ieee802_11_defs.h
@@ -707,7 +707,7 @@
 #define WLAN_PA_FILS_DISCOVERY 34
 #define WLAN_PA_LOCATION_MEASUREMENT_REPORT 47
 
-/* HT Action field values (IEEE P802.11-REVme/D4.0, 9.6.11.1, Table 9-491) */
+/* HT Action field values (IEEE Std 802.11-2024, 9.6.11.1, Table 9-517) */
 #define WLAN_HT_ACTION_NOTIFY_CHANWIDTH 0
 #define WLAN_HT_ACTION_SMPS 1
 #define WLAN_HT_ACTION_CSI 4
@@ -715,7 +715,7 @@
 #define WLAN_HT_ACTION_COMPRESSED_BF 6
 #define WLAN_HT_ACTION_ASEL_IDX_FEEDBACK 7
 
-/* VHT Action field values (IEEE P802.11-REVme/D4.0, 9.6.22.1, Table 9-579) */
+/* VHT Action field values (IEEE Std 802.11-2024, 9.6.22.1, Table 9-605) */
 #define WLAN_VHT_ACTION_COMPRESSED_BF 0
 #define WLAN_VHT_ACTION_GROUP_ID_MGMT 1
 #define WLAN_VHT_ACTION_OPMODE_NOTIF 2
@@ -808,6 +808,7 @@
 #define WLAN_RRM_CAPS_LCI_MEASUREMENT BIT(4)
 /* byte 5 (out of 5) */
 #define WLAN_RRM_CAPS_FTM_RANGE_REPORT BIT(2)
+#define WLAN_RRM_CAPS_CIVIC_LOCATION_MEASUREMENT BIT(3)
 
 /*
  * IEEE Std 802.11-2020, 9.4.2.20.19 (Fine Timing Measurement Range
@@ -2574,7 +2575,8 @@ struct ieee80211_6ghz_operation_info {
 /**
  * enum he_reg_info_6ghz_ap_type - Allowed Access Point types for 6 GHz Band
  *
- * IEEE P802.11-REVme/D4.0, Table E-12 (Regulatory Info subfield encoding)
+ * IEEE Std 802.11-2024, Table E-12 (Regulatory Info subfield interpretation by
+ * non-AP STAs with dot11ExtendedRegInfoSupport not set to true)
  */
 enum he_reg_info_6ghz_ap_type {
 	HE_REG_INFO_6GHZ_AP_TYPE_INDOOR         = 0,
@@ -2714,6 +2716,8 @@ struct ieee80211_eht_operation {
 	struct ieee80211_eht_oper_info oper_info; /* 0 or 3 or 5 octets */
 } STRUCT_PACKED;
 
+#define IEEE80211_EHT_OP_MIN_LEN (1 + 4)
+
 /* IEEE P802.11be/D1.5, 9.4.2.313 - EHT Capabilities element */
 
 #define  EHT_CAPABILITIES_IE_MIN_LEN 11
@@ -2891,17 +2895,6 @@ struct eht_ml_basic_common_info {
 #define EHT_PER_STA_CTRL_NSTR_BM_SIZE_MSK             0x0400
 #define EHT_PER_STA_CTRL_BSS_PARAM_CNT_PRESENT_MSK    0x0800
 
-/* IEEE P802.11be/D4.1, Figure 9-1001x - STA Control field format for the
- * Reconfiguration Multi-Link element */
-#define EHT_PER_STA_RECONF_CTRL_LINK_ID_MSK        0x000f
-#define EHT_PER_STA_RECONF_CTRL_COMPLETE_PROFILE   0x0010
-#define EHT_PER_STA_RECONF_CTRL_MAC_ADDR           0x0020
-#define EHT_PER_STA_RECONF_CTRL_AP_REMOVAL_TIMER   0x0040
-#define EHT_PER_STA_RECONF_CTRL_OP_UPDATE_TYPE_MSK 0x0780
-#define EHT_PER_STA_RECONF_CTRL_OP_PARAMS          0x0800
-#define EHT_PER_STA_RECONF_CTRL_NSTR_BITMAP_SIZE   0x1000
-#define EHT_PER_STA_RECONF_CTRL_NSTR_INDIC_BITMAP  0x2000
-
 /* IEEE P802.11be/D2.0, 9.4.2.312.2.4 - Per-STA Profile subelement format */
 struct ieee80211_eht_per_sta_profile {
 	le16 sta_control;
diff --git a/src/common/nan_de.c b/src/common/nan_de.c
index 4f63adc8..2833211f 100644
--- a/src/common/nan_de.c
+++ b/src/common/nan_de.c
@@ -604,6 +604,14 @@ static void nan_de_timer(void *eloop_ctx, void *timeout_ctx)
 			wpa_printf(MSG_DEBUG, "NAN: Service id %d expired",
 				   srv->id);
 			nan_de_del_srv(de, srv, NAN_DE_REASON_TIMEOUT);
+			if (srv->type == NAN_DE_PUBLISH &&
+			    de->cb.offload_cancel_publish)
+				de->cb.offload_cancel_publish(de->cb.ctx,
+							      srv->id);
+			if (srv->type == NAN_DE_SUBSCRIBE &&
+			    de->cb.offload_cancel_subscribe)
+				de->cb.offload_cancel_subscribe(de->cb.ctx,
+								srv->id);
 			continue;
 		}
 
diff --git a/src/common/nan_de.h b/src/common/nan_de.h
index 41e294e7..2900bab5 100644
--- a/src/common/nan_de.h
+++ b/src/common/nan_de.h
@@ -50,6 +50,9 @@ struct nan_callbacks {
 	void (*subscribe_terminated)(void *ctx, int subscribe_id,
 				     enum nan_de_reason reason);
 
+	void (*offload_cancel_publish)(void *ctx, int publish_id);
+	void (*offload_cancel_subscribe)(void *ctx, int subscribe_id);
+
 	void (*receive)(void *ctx, int id, int peer_instance_id,
 			const u8 *ssi, size_t ssi_len,
 			const u8 *peer_addr);
diff --git a/src/common/qca-vendor.h b/src/common/qca-vendor.h
index 3cc2f93c..4a38dc3b 100644
--- a/src/common/qca-vendor.h
+++ b/src/common/qca-vendor.h
@@ -1326,11 +1326,21 @@ enum qca_radiotap_vendor_ids {
  *	The attributes used with this event are defined in
  *	enum qca_wlan_vendor_attr_idle_shutdown.
  *
- * @QCA_NL80211_VENDOR_SUBCMD_PRI_LINK_MIGRATE: Vendor subcommand that can
- *	be used to trigger primary link migration from user space. Either just
- *	one ML client or a bunch of clients can be migrated.
+ * @QCA_NL80211_VENDOR_SUBCMD_PRI_LINK_MIGRATE: This vendor subcommand/event is
+ * 	used for primary link migration.
  *
- *	The attributes used with this subcommand are defined in
+ * 	This subcommand is used to trigger primary link migration from
+ * 	user space. Either just	one ML client or a bunch of clients can
+ * 	be migrated.
+ *
+ *	This subcommand is used as an event to notify user applications and
+ *	subsystems about primary link migration once it is completed
+ *	successfully. This event will send the MAC address of the peer for which
+ *	the primary link has been changed and the new link ID to ensure primary
+ *	link changes in WLAN subsystem are communicated to user applications
+ *	and also to manage the load of that primary link in a better way.
+ *
+ *	The attributes used with this subcommand/event are defined in
  *	&enum qca_wlan_vendor_attr_pri_link_migrate.
  *
  *	@QCA_WLAN_VENDOR_ATTR_PRI_LINK_MIGR_MLD_MAC_ADDR and
@@ -1346,6 +1356,28 @@ enum qca_radiotap_vendor_ids {
  *
  *	The attributes used with this command are defined in
  * 	enum qca_wlan_vendor_attr_periodic_probe_rsp_cfg.
+ *
+ * @QCA_NL80211_VENDOR_SUBCMD_CLASSIFIED_FLOW_STATUS: Vendor subcommand that can
+ *	be used to notify userspace about status updates of a classified flow
+ *	learned by the driver with
+ *	%QCA_NL80211_VENDOR_SUBCMD_FLOW_CLASSIFY_RESULT.
+ *	The attributes for this event are defined in
+ *	enum qca_wlan_vendor_attr_flow_status.
+ *
+ * @QCA_NL80211_VENDOR_SUBCMD_RX_MCS_MAP_CONFIG: Subcommand to update the
+ *	RX MCS MAP capability. This configuration is only applicable to
+ *	non-AP STA or non-AP MLD and allowed only in associated state and
+ *	valid until disconnection. This command results in the driver triggering
+ *	re-association to re-negotiate the updated RX MCS capability with the
+ *	peer. The attributes used with this command are defined in
+ *	enum qca_wlan_vendor_attr_rx_mcs_map_params.
+ *
+ * @QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE: Vendor subcommand/event
+ *	which is used to exchange Tx powerboost operations between
+ *	userspace and driver (kernel space).
+ *
+ *	The attributes used with this command/event are defined in
+ *	enum qca_wlan_vendor_attr_iq_data_inference.
  */
 enum qca_nl80211_vendor_subcmds {
 	QCA_NL80211_VENDOR_SUBCMD_UNSPEC = 0,
@@ -1587,6 +1619,9 @@ enum qca_nl80211_vendor_subcmds {
 	/* 255 - reserved for QCA */
 	QCA_NL80211_VENDOR_SUBCMD_PRI_LINK_MIGRATE = 256,
 	QCA_NL80211_VENDOR_SUBCMD_PERIODIC_PROBE_RSP_CFG = 257,
+	QCA_NL80211_VENDOR_SUBCMD_CLASSIFIED_FLOW_STATUS = 258,
+	QCA_NL80211_VENDOR_SUBCMD_RX_MCS_MAP_CONFIG = 259,
+	QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE = 260,
 };
 
 /* Compatibility defines for previously used subcmd names.
@@ -3888,6 +3923,26 @@ enum qca_wlan_vendor_attr_config {
 	 */
 	QCA_WLAN_VENDOR_ATTR_CONFIG_SETUP_LINK_RECONFIG_SUPPORT = 130,
 
+	/* 8-bit unsigned value to enable/disable DFS No Wait feature support
+	 * in AP mode.
+	 * 1 - Enable
+	 * 0 - Disable.
+	 *
+	 * DFS No Wait allows AP to be started within the subset of channel
+	 * bandwidth that does not require DFS while waiting for CAC to
+	 * complete on the subset that requires DFS. If no radar was detected,
+	 * switch to the full configured channel bandwidth.
+	 */
+	QCA_WLAN_VENDOR_ATTR_CONFIG_DFS_NO_WAIT_SUPPORT = 131,
+
+	/* Nested attribute to configure the EHT EMLSR operation and EHT MLO
+	 * links for the EMLSR operation to the driver in STA mode. This is
+	 * runtime configuration on STA after association and the configuration
+	 * is valid only for the current association.
+	 * Uses enum qca_wlan_vendor_attr_emlsr_info for values.
+	 */
+	QCA_WLAN_VENDOR_ATTR_CONFIG_EHT_EMLSR_LINKS = 132,
+
 	/* keep last */
 	QCA_WLAN_VENDOR_ATTR_CONFIG_AFTER_LAST,
 	QCA_WLAN_VENDOR_ATTR_CONFIG_MAX =
@@ -6463,6 +6518,84 @@ enum qca_vendor_attr_roam_candidate_selection_criteria {
  *	better Wi-Fi bands. E.g., STA would initially connect to a 2.4 GHz BSSID
  *	and would migrate to 5/6 GHz when it comes closer to the AP (high RSSI
  *	for 2.4 GHz BSS).
+ *
+ * @QCA_ATTR_ROAM_CONTROL_CANDIDATE_SCORE_WEIGHTAGE_2P4GHZ: Unsigned 8-bit
+ *	value.
+ *	Represents the weightage in percentage (%) of the total score that is
+ *	given for the roam scan candidates present on the 2.4 GHz band. The
+ *	configuration is valid until next disconnection. If this attribute is
+ *	not present, the existing configuration shall be used.
+ *
+ * @QCA_ATTR_ROAM_CONTROL_CANDIDATE_SCORE_WEIGHTAGE_5GHZ: Unsigned 8-bit
+ *	value.
+ *	Represents the weightage in percentage (%) of the total score that is
+ *	given for the roam scan candidates present on the 5 GHz band.
+ *	The configuration is valid until next disconnection. If this attribute
+ *	is not present, the existing configuration shall be used.
+ *
+ * @QCA_ATTR_ROAM_CONTROL_CANDIDATE_SCORE_WEIGHTAGE_6GHZ: Unsigned 8-bit
+ *	value.
+ *	Represents the weightage in percentage (%) of the total score that is
+ *	given for the roam scan candidates present on the 6 GHz band.
+ *	The configuration is valid until next disconnection. If this attribute
+ *	is not present, the existing configuration shall be used.
+ *
+ * @QCA_ATTR_ROAM_CONTROL_CANDIDATE_SCORE_THRESHOLD_PERCENTAGE: Unsigned 8-bit
+ *	value.
+ *	This attribute indicates the minimum roam score difference in
+ *	percentage (%). The roam candidate AP will be ignored if the score
+ *	difference percentage between the roam candidate AP and the current
+ *	connected AP is less than current connected AP score roam score delta.
+ *	The configuration is valid until next disconnection.
+ *	If this attribute is not present, the existing configuration shall be
+ *	used.
+ *
+ * @QCA_ATTR_ROAM_CONTROL_CONNECTED_LOW_RSSI_THRESHOLD_DECREMENT: Unsigned 8-bit
+ *	value in dB.
+ *	This attribute indicates the RSSI decrement value from the current low
+ *	RSSI threshold for the next low RSSI roam trigger when no candidate is
+ *	found during the current low RSSI roam trigger. This value is applicable
+ *	only for low RSSI roam triggers. This configuration is valid until next
+ *	disconnection. If this attribute is not present, the existing
+ *	configuration shall be used.
+ *
+ * @QCA_ATTR_ROAM_CONTROL_PERIODIC_ROAM_SCAN_INTERVAL: Unsigned 32-bit
+ *	value in seconds.
+ *	This attribute defines the interval after which the next roam scan will
+ *	start if the current scan finds no candidates. The scan repeats at this
+ *	interval until a candidate is found.
+ *	This configuration is valid until next disconnection. If this attribute
+ *	is not present, the existing configuration shall be used.
+ *
+ * @QCA_ATTR_ROAM_CONTROL_CANDIDATE_SCORE_MIN_DELTA_THRESHOLD: Unsigned 32-bit
+ *	value.
+ *	This attribute indicates the minimum roam score difference for an AP to
+ *	be considered as a candidate. A roam candidate AP will be ignored if
+ *	the score difference between the roam candidate AP and the current
+ *	connected AP is less than the sum of the current connected AP score and
+ *	the roam score delta.
+ *
+ *	The configuration is valid until next disconnection. If this attribute
+ *	is not present, the existing configuration shall be used.
+ *
+ * @QCA_ATTR_ROAM_CONTROL_CONNECTED_BSS_RECONNECT_DISALLOW_PERIOD: Unsigned
+ *	32-bit value.
+ *	This attribute specifies the duration (in seconds) of the current BSS
+ *	connection from the last successful association, after which the
+ *	connected BSS can be considered as a roaming candidate upon receiving
+ *	a Deauthentication or Disassociation frame from the BSS, provided no
+ *	alternative candidate is available. The connection timer to monitor the
+ *	disallow period should start after each successful connection.
+ *
+ *	This configuration is valid until next disconnection. If this attribute
+ *	is not present, the existing configuration shall be used.
+ *	0 - Always disallow roaming to the current connected BSS when a
+ *	Deauthentication or Disassociation frame is received from the connected
+ *	BSS.
+ *	Other values - Disallow roaming to the current connected BSS for the
+ *	specified duration from the last successful connection time when a
+ *	Deauthentication or Disassociation frame is received from the connected
+ *	BSS.
  */
 enum qca_vendor_attr_roam_control {
 	QCA_ATTR_ROAM_CONTROL_ENABLE = 1,
@@ -6496,6 +6629,14 @@ enum qca_vendor_attr_roam_control {
 	QCA_ATTR_ROAM_CONTROL_CANDIDATE_ROAM_RSSI_DIFF = 29,
 	QCA_ATTR_ROAM_CONTROL_6GHZ_CANDIDATE_ROAM_RSSI_DIFF = 30,
 	QCA_ATTR_ROAM_CONTROL_CONNECTED_HIGH_RSSI_OFFSET = 31,
+	QCA_ATTR_ROAM_CONTROL_CANDIDATE_SCORE_WEIGHTAGE_2P4GHZ = 32,
+	QCA_ATTR_ROAM_CONTROL_CANDIDATE_SCORE_WEIGHTAGE_5GHZ = 33,
+	QCA_ATTR_ROAM_CONTROL_CANDIDATE_SCORE_WEIGHTAGE_6GHZ = 34,
+	QCA_ATTR_ROAM_CONTROL_CANDIDATE_SCORE_THRESHOLD_PERCENTAGE = 35,
+	QCA_ATTR_ROAM_CONTROL_CONNECTED_LOW_RSSI_THRESHOLD_DECREMENT = 36,
+	QCA_ATTR_ROAM_CONTROL_PERIODIC_ROAM_SCAN_INTERVAL = 37,
+	QCA_ATTR_ROAM_CONTROL_CANDIDATE_SCORE_MIN_DELTA_THRESHOLD = 38,
+	QCA_ATTR_ROAM_CONTROL_CONNECTED_BSS_RECONNECT_DISALLOW_PERIOD = 39,
 
 	/* keep last */
 	QCA_ATTR_ROAM_CONTROL_AFTER_LAST,
@@ -9193,6 +9334,22 @@ enum qca_wlan_vendor_attr_ndp_params {
 	 * frames from each other.
 	 */
 	QCA_WLAN_VENDOR_ATTR_NDP_GTK_REQUIRED = 33,
+	/* Unsigned 32-bit attribute. Indicates the maximum latency of the NAN
+	 * data packets to be transmitted/received in milliseconds.
+	 * This attribute is optional, and it is configured for active NDP
+	 * session of a given NDP instance ID
+	 * %QCA_WLAN_VENDOR_ATTR_NDP_INSTANCE_ID using the command
+	 * %QCA_WLAN_VENDOR_NDP_SUB_CMD_UPDATE_CONFIG.
+	 */
+	QCA_WLAN_VENDOR_ATTR_NDP_MAX_LATENCY_MS = 34,
+	/* 32-bit unsigned value to indicate throughput in Mbps for the NDP
+	 * data of a given NDP session.
+	 * This attribute is optional, and it is configured for active NDP
+	 * session of a given NDP instance ID
+	 * %QCA_WLAN_VENDOR_ATTR_NDP_INSTANCE_ID using the command
+	 * %QCA_WLAN_VENDOR_NDP_SUB_CMD_UPDATE_CONFIG.
+	 */
+	QCA_WLAN_VENDOR_ATTR_NDP_TPUT = 35,
 
 	/* keep last */
 	QCA_WLAN_VENDOR_ATTR_NDP_PARAMS_AFTER_LAST,
@@ -9240,7 +9397,14 @@ enum qca_wlan_ndp_sub_cmd {
 	/* Command to indicate the peer about the end request being received */
 	QCA_WLAN_VENDOR_ATTR_NDP_END_IND = 11,
 	/* Command to indicate the peer of schedule update */
-	QCA_WLAN_VENDOR_ATTR_NDP_SCHEDULE_UPDATE_IND = 12
+	QCA_WLAN_VENDOR_ATTR_NDP_SCHEDULE_UPDATE_IND = 12,
+	/* Command to update dynamic configurations of active NDP sessions.
+	 * %QCA_WLAN_VENDOR_ATTR_NDP_INSTANCE_ID is a mandatory attribute and
+	 * at least one of the attributes
+	 * %QCA_WLAN_VENDOR_ATTR_NDP_MAX_LATENCY_MS and
+	 * %QCA_WLAN_VENDOR_ATTR_NDP_TPUT must be configured in this command.
+	 */
+	QCA_WLAN_VENDOR_NDP_SUB_CMD_UPDATE_CONFIG = 13,
 };
 
 /**
@@ -11344,7 +11508,9 @@ enum qca_wlan_vendor_attr_twt_setup {
  * @QCA_WLAN_VENDOR_TWT_STATUS_CHANNEL_SWITCH_IN_PROGRESS: FW rejected the TWT
  * setup request due to channel switch in progress.
  * @QCA_WLAN_VENDOR_TWT_STATUS_SCAN_IN_PROGRESS: FW rejected the TWT setup
- * request due to scan in progress.
+ * request due to scan in progress. This is also used in TWT_TERMINATE
+ * notification from the driver to indicate TWT session termination is due to
+ * scan in progress.
  * QCA_WLAN_VENDOR_TWT_STATUS_POWER_SAVE_EXIT_TERMINATE: The driver requested to
  * terminate an existing TWT session on power save exit request from userspace.
  * Used on the TWT_TERMINATE notification from the driver/firmware.
@@ -11362,6 +11528,12 @@ enum qca_wlan_vendor_attr_twt_setup {
  * driver/firmware.
  * @QCA_WLAN_VENDOR_TWT_STATUS_TIMEOUT: Requested TWT operation has timed out.
  * Used on the TWT_SET, TWT_TERMINATE notification from the driver/firmware.
+ * @QCA_WLAN_VENDOR_TWT_STATUS_CHAN_SWITCH_24GHZ: FW terminated the TWT
+ * session due to channel switch triggered to a 2.4 GHz channel. Used on the
+ * TWT_TERMINATE notification from the driver.
+ * @QCA_WLAN_VENDOR_TWT_STATUS_MLO_LINK_INACTIVE: FW terminated the TWT session
+ * due to the link inactivation triggered on the TWT session established
+ * link. Used on the TWT_TERMINATE notification from the driver.
  */
 enum qca_wlan_vendor_twt_status {
 	QCA_WLAN_VENDOR_TWT_STATUS_OK = 0,
@@ -11393,6 +11565,8 @@ enum qca_wlan_vendor_twt_status {
 	QCA_WLAN_VENDOR_TWT_STATUS_TWT_ALREADY_RESUMED = 26,
 	QCA_WLAN_VENDOR_TWT_STATUS_PEER_REJECTED = 27,
 	QCA_WLAN_VENDOR_TWT_STATUS_TIMEOUT = 28,
+	QCA_WLAN_VENDOR_TWT_STATUS_CHAN_SWITCH_24GHZ = 29,
+	QCA_WLAN_VENDOR_TWT_STATUS_MLO_LINK_INACTIVE = 30,
 };
 
 /**
@@ -15104,6 +15278,105 @@ enum qca_wlan_vendor_attr_ratemask_params {
 	QCA_WLAN_VENDOR_ATTR_RATEMASK_PARAMS_AFTER_LAST - 1,
 };
 
+/**
+ * enum qca_wlan_rx_mcs_map_params_phy_type - RX MCS map config PHY type
+ *
+ * @QCA_WLAN_RX_MCS_MAP_PARAMS_PHY_TYPE_VHT: VHT PHY type
+ * @QCA_WLAN_RX_MCS_MAP_PARAMS_PHY_TYPE_HE: HE PHY type
+ * @QCA_WLAN_RX_MCS_MAP_PARAMS_PHY_TYPE_EHT: EHT PHY type
+ */
+enum qca_wlan_rx_mcs_map_params_phy_type {
+	QCA_WLAN_RX_MCS_MAP_PARAMS_PHY_TYPE_VHT = 0,
+	QCA_WLAN_RX_MCS_MAP_PARAMS_PHY_TYPE_HE = 1,
+	QCA_WLAN_RX_MCS_MAP_PARAMS_PHY_TYPE_EHT = 2,
+};
+
+/**
+ * enum qca_wlan_vendor_attr_rx_mcs_map_params - Used by the vendor command
+ * QCA_NL80211_VENDOR_SUBCMD_RX_MCS_MAP_CONFIG.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_RX_MCS_MAP_PARAMS_LIST:
+ * Array of nested attributes containing
+ * QCA_WLAN_VENDOR_ATTR_RX_MCS_MAP_PARAMS_PHY_TYPE and
+ * QCA_WLAN_VENDOR_ATTR_RX_MCS_MAP_PARAMS_BITMAP and optionally
+ * QCA_WLAN_VENDOR_ATTR_RX_MCS_MAP_PARAMS_LINK_ID.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_RX_MCS_MAP_PARAMS_PHY_TYPE: u8, represents
+ * the PHY type to which RX MCS Map config is to be applied.
+ * The values for this attribute are referred from enum
+ * qca_wlan_rx_mcs_map_params_phy_type.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_RX_MCS_MAP_PARAMS_BITMAP: binary, RX MCS map bitmap.
+ *
+ * For EHT targets 3 bit correspond to one NSS setting.
+ * b0-2 => NSS1
+ * b3-5 => NSS2
+ * b6-8 => NSS3
+ * b9-11 => NSS4
+ * b12-14 => NSS5
+ * b15-17 => NSS6
+ * b18-20 => NSS7
+ * b21-23 => NSS8
+ *
+ * Below are the possible values
+ * 000 - Disabled/Not supported
+ * 001 - MCS 0-7
+ * 010 - MCS 0-9
+ * 011 - MCS 0-11
+ * 100 - MCS 0-13
+ * 110 - MCS 0-14
+ * 111 - MCS 0-15
+ *
+ * For HE targets, 2 bits correspond to one NSS setting
+ * b0-1 => NSS1
+ * b2-3 => NSS2
+ * b4-5 => NSS3
+ * b6-7 => NSS4
+ * b8-9 => NSS5
+ * b10-11 => NSS6
+ * b12-13 => NSS7
+ * b14-15 => NSS8
+ *
+ * Below are the possible values
+ * 00 - Disabled/Not supported
+ * 01 - MCS 0-7
+ * 10 - MCS 0-9
+ * 11 - MCS 0-11
+ *
+ * for VHT targets, 2 bits correspond to one NSS setting.
+ * b0-1 => NSS1
+ * b2-3 => NSS2
+ * b4-5 => NSS3
+ * b6-7 => NSS4
+ * b8-9 => NSS5
+ * b10-11 => NSS6
+ * b12-13 => NSS7
+ * b14-15 => NSS8
+ *
+ * Below are the possible values
+ * 00 - Disabled/Not supported
+ * 01 - MCS 0-7
+ * 10 - MCS 0-8
+ * 11 - MCS 0-9
+ *
+ * @QCA_WLAN_VENDOR_ATTR_RX_MCS_MAP_PARAMS_LINK_ID: u8, used to specify the
+ * MLO link ID of a link to be configured. Optional attribute.
+ * No need of this attribute in non-MLO cases. If the attribute is
+ * not provided, MCS map will be applied for the association link.
+ */
+enum qca_wlan_vendor_attr_rx_mcs_map_params {
+	QCA_WLAN_VENDOR_ATTR_RX_MCS_MAP_PARAMS_INVALID = 0,
+	QCA_WLAN_VENDOR_ATTR_RX_MCS_MAP_PARAMS_LIST = 1,
+	QCA_WLAN_VENDOR_ATTR_RX_MCS_MAP_PARAMS_PHY_TYPE = 2,
+	QCA_WLAN_VENDOR_ATTR_RX_MCS_MAP_PARAMS_BITMAP = 3,
+	QCA_WLAN_VENDOR_ATTR_RX_MCS_MAP_PARAMS_LINK_ID = 4,
+
+	/* keep last */
+	QCA_WLAN_VENDOR_ATTR_RX_MCS_MAP_PARAMS_AFTER_LAST,
+	QCA_WLAN_VENDOR_ATTR_RX_MCS_MAP_PARAMS_MAX =
+	QCA_WLAN_VENDOR_ATTR_RX_MCS_MAP_PARAMS_AFTER_LAST - 1,
+};
+
 /**
  * enum qca_wlan_audio_data_path - Defines the data path to be used for audio
  * traffic.
@@ -16039,10 +16312,14 @@ enum qca_wlan_vendor_attr_sr_stats {
  *
  * @QCA_WLAN_SR_REASON_CODE_CONCURRENCY: The SR feature is disabled/enabled due
  * to change in concurrent interfaces that are supported by the driver.
+ *
+ * @QCA_WLAN_SR_REASON_CODE_BCN_IE_CHANGE: The SR feature is disabled/enabled
+ * on non-AP STA, due to BSS SR parameter(s) update.
  */
 enum qca_wlan_sr_reason_code {
 	QCA_WLAN_SR_REASON_CODE_ROAMING = 0,
 	QCA_WLAN_SR_REASON_CODE_CONCURRENCY = 1,
+	QCA_WLAN_SR_REASON_CODE_BCN_IE_CHANGE = 2,
 };
 
 /**
@@ -16222,12 +16499,37 @@ enum qca_wlan_vendor_attr_sr_params {
  * This attribute is used in response from the driver to a command in which
  * %QCA_WLAN_VENDOR_ATTR_SR_OPERATION is set to
  * %QCA_WLAN_SR_OPERATION_GET_STATS.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_SR_MLO_LINKS: Array of nested links each identified
+ * by %QCA_WLAN_VENDOR_ATTR_SR_MLO_LINK_ID.
+ * This attribute enables user to configure a single or multiple links by
+ * nesting %QCA_WLAN_VENDOR_ATTR_SR_MLO_LINK_ID and corresponding SR
+ * configuration attributes defined in enum qca_wlan_vendor_attr_sr.
+ * In %QCA_WLAN_SR_OPERATION_GET_PARAMS or %QCA_WLAN_SR_OPERATION_GET_STATS
+ * in enum qca_wlan_sr_operation, %QCA_WLAN_VENDOR_ATTR_SR_MLO_LINK_ID shall
+ * be used to pack the per link configuration that are currently in use.
+ * For STA interface, this attribute is applicable only in connected state
+ * when the current connection is MLO capable. The valid values of
+ * %QCA_WLAN_VENDOR_ATTR_SR_MLO_LINK_ID are the link IDs of the connected AP
+ * MLD links.
+ * For AP interface, this attribute is applicable only after adding MLO
+ * links to the AP interface with %NL80211_CMD_ADD_LINK and the valid values
+ * of %QCA_WLAN_VENDOR_ATTR_SR_MLO_LINK_ID are the link IDs specified in
+ * %NL80211_CMD_ADD_LINK while adding the MLO links to the AP interface.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_SR_MLO_LINK_ID: 8-bit unsigned value. Used to specify
+ * the MLO link ID of a link that is being configured. This attribute must be
+ * included in each record nested under %QCA_WLAN_VENDOR_ATTR_SR_MLO_LINKS and
+ * may be included without nesting to indicate the target link for
+ * configuration attributes.
  */
 enum qca_wlan_vendor_attr_sr {
 	QCA_WLAN_VENDOR_ATTR_SR_INVALID = 0,
 	QCA_WLAN_VENDOR_ATTR_SR_OPERATION = 1,
 	QCA_WLAN_VENDOR_ATTR_SR_PARAMS = 2,
 	QCA_WLAN_VENDOR_ATTR_SR_STATS = 3,
+	QCA_WLAN_VENDOR_ATTR_SR_MLO_LINKS = 4,
+	QCA_WLAN_VENDOR_ATTR_SR_MLO_LINK_ID = 5,
 
 	/* Keep last */
 	QCA_WLAN_VENDOR_ATTR_SR_AFTER_LAST,
@@ -17654,6 +17956,30 @@ enum qca_wlan_vendor_attr_tpc_links {
 	QCA_WLAN_VENDOR_ATTR_TPC_AFTER_LAST - 1,
 };
 
+/**
+ * enum qca_wlan_vendor_attr_emlsr_info: Represent attributes to configure
+ * the EHT MLO links for EHT EMLSR operation and the EMLSR operation in STA
+ * mode. These attributes are used inside nested attribute
+ * %QCA_WLAN_VENDOR_ATTR_CONFIG_EMLSR_LINKS.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_EMLSR_OPERATION: Required attribute, u8.
+ * 0 - Enter, 1 - Exit
+ *
+ * @QCA_WLAN_VENDOR_ATTR_EMLSR_LINKS_BITMAP: Required, u16 attribute. This
+ * indicates the bitmap of the link IDs to specify the links corresponding
+ * to the bit set to be used for the EHT EMLSR operation.
+ */
+enum qca_wlan_vendor_attr_emlsr_info {
+	QCA_WLAN_VENDOR_ATTR_EMLSR_INVALID = 0,
+	QCA_WLAN_VENDOR_ATTR_EMLSR_OPERATION = 1,
+	QCA_WLAN_VENDOR_ATTR_EMLSR_LINKS_BITMAP = 2,
+
+	/* keep last */
+	QCA_WLAN_VENDOR_ATTR_EMLSR_AFTER_LAST,
+	QCA_WLAN_VENDOR_ATTR_EMLSR_MAX =
+	QCA_WLAN_VENDOR_ATTR_EMLSR_AFTER_LAST - 1,
+};
+
 /**
  * enum qca_wlan_vendor_attr_fw_page_fault_report - Used by the vendor
  * command %QCA_NL80211_VENDOR_SUBCMD_FW_PAGE_FAULT_REPORT.
@@ -18236,11 +18562,16 @@ enum qca_wlan_vendor_attr_flow_stats {
  * @QCA_WLAN_VENDOR_ATTR_FLOW_CLASSIFY_RESULT_TRAFFIC_TYPE: Mandatory u8
  * attribute indicates the traffic type learned for this flow tuple. Uses the
  * enum qca_traffic_type values.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_FLOW_CLASSIFY_RESULT_UL_TID: Optional u8 attribute
+ * indicates the TID value to be used by the driver in uplink direction for this
+ * flow tuple.
  */
 enum qca_wlan_vendor_attr_flow_classify_result {
 	QCA_WLAN_VENDOR_ATTR_FLOW_CLASSIFY_RESULT_INVALID = 0,
 	QCA_WLAN_VENDOR_ATTR_FLOW_CLASSIFY_RESULT_FLOW_TUPLE = 1,
 	QCA_WLAN_VENDOR_ATTR_FLOW_CLASSIFY_RESULT_TRAFFIC_TYPE = 2,
+	QCA_WLAN_VENDOR_ATTR_FLOW_CLASSIFY_RESULT_UL_TID = 3,
 
 	/* keep last */
 	QCA_WLAN_VENDOR_ATTR_FLOW_CLASSIFY_RESULT_LAST,
@@ -18651,10 +18982,15 @@ enum qca_wlan_connect_ext_features {
  * array. The feature flags are identified by their bit index (see &enum
  * qca_wlan_connect_ext_features) with the first byte being the least
  * significant one and the last one being the most significant one.
+ * @QCA_WLAN_VENDOR_ATTR_CONNECT_EXT_ALLOWED_BSSIDS: Nested attribute of
+ * BSSIDs to indicate allowed BSSIDs for association. This configuration stays
+ * in effect only for the current connection request and for the next connect
+ * request if there is no connection currently.
  */
 enum qca_wlan_vendor_attr_connect_ext {
 	QCA_WLAN_VENDOR_ATTR_CONNECT_EXT_INVALID = 0,
 	QCA_WLAN_VENDOR_ATTR_CONNECT_EXT_FEATURES = 1,
+	QCA_WLAN_VENDOR_ATTR_CONNECT_EXT_ALLOWED_BSSIDS = 2,
 
 	QCA_WLAN_VENDOR_ATTR_CONNECT_EXT_AFTER_LAST,
 	QCA_WLAN_VENDOR_ATTR_CONNECT_EXT_MAX =
@@ -18933,18 +19269,23 @@ enum qca_wlan_vendor_attr_idle_shutdown {
 
 /**
  * enum qca_wlan_vendor_attr_pri_link_migrate: Attributes used by the vendor
- * 	subcommand %QCA_NL80211_VENDOR_SUBCMD_PRI_LINK_MIGRATE.
+ * 	subcommand/event %QCA_NL80211_VENDOR_SUBCMD_PRI_LINK_MIGRATE.
  *
- * @QCA_WLAN_VENDOR_ATTR_PRI_LINK_MIGR_MLD_MAC_ADDR: 6 byte MAC address. When
- *	specified, indicates that primary link migration will occur only for
- *	the ML client with the given MLD MAC address.
+ * @QCA_WLAN_VENDOR_ATTR_PRI_LINK_MIGR_MLD_MAC_ADDR: 6 byte MAC address.
+ * 	(a) Used in a subcommand to indicate that primary link migration
+ * 	will occur only for the ML client with the given MLD MAC address.
+ * 	(b) Used in an event to specify the MAC address of the peer for which
+ * 	the primary link has been modified.
  * @QCA_WLAN_VENDOR_ATTR_PRI_LINK_MIGR_CURRENT_PRI_LINK_ID: Optional u8
- *	attribute. When specified, all ML clients having their current primary
+ *	attribute. Used with subcommand only.
+ *	When specified, all ML clients having their current primary
  *	link as specified will be considered for migration.
  * @QCA_WLAN_VENDOR_ATTR_PRI_LINK_MIGR_NEW_PRI_LINK_ID: Optional u8 attribute.
- *	Indicates the new primary link to which the selected ML clients
- *	should be migrated to. If not provided, the driver will select a
- *	suitable primary link on its own.
+ *	(a) Used in subcommand, to indicate the new primary link to which the
+ *	selected ML clients should be migrated to. If not provided, the driver
+ *	will select a suitable primary link on its own.
+ *	(b) Used in event, to indicate the new link ID which is set as the
+ *	primary link.
  */
 enum qca_wlan_vendor_attr_pri_link_migrate {
 	QCA_WLAN_VENDOR_ATTR_PRI_LINK_MIGR_INVALID = 0,
@@ -19066,4 +19407,223 @@ enum qca_wlan_vendor_attr_periodic_probe_rsp_cfg {
 	QCA_WLAN_VENDOR_ATTR_PROBE_RESP_CFG_AFTER_LAST - 1,
 };
 
+/**
+ * enum qca_flow_status_update_type - Attribute values for
+ * %QCA_WLAN_VENDOR_ATTR_FLOW_STATUS_UPDATE_TYPE.
+ * @QCA_FLOW_STATUS_UPDATE_PAUSE: Flow paused.
+ * @QCA_FLOW_STATUS_UPDATE_RESUME: Flow resumed.
+ * @QCA_FLOW_STATUS_UPDATE_DELETE: Flow deleted.
+ */
+enum qca_flow_status_update_type {
+	QCA_FLOW_STATUS_UPDATE_PAUSE = 0,
+	QCA_FLOW_STATUS_UPDATE_RESUME = 1,
+	QCA_FLOW_STATUS_UPDATE_DELETE = 2,
+};
+
+/**
+ * enum qca_wlan_vendor_attr_flow_status - Definition of attributes to
+ * specify status updates of a classified flow. This enum is used by
+ * @QCA_NL80211_VENDOR_SUBCMD_CLASSIFIED_FLOW_STATUS.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_FLOW_STATUS_TUPLE: Mandatory nested attribute
+ * containing attributes defined by enum qca_wlan_vendor_attr_flow_tuple.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_FLOW_STATUS_TRAFFIC_TYPE: Mandatory u8 attribute
+ * indicates the traffic type of this flow tuple. Uses the
+ * enum qca_traffic_type values.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_FLOW_STATUS_UPDATE_TYPE: Mandatory u8 attribute
+ * indicates the flow status update type.
+ * Uses the enum qca_flow_status_update_type values.
+ */
+enum qca_wlan_vendor_attr_flow_status {
+	QCA_WLAN_VENDOR_ATTR_FLOW_STATUS_INVALID = 0,
+	QCA_WLAN_VENDOR_ATTR_FLOW_STATUS_TUPLE = 1,
+	QCA_WLAN_VENDOR_ATTR_FLOW_STATUS_TRAFFIC_TYPE = 2,
+	QCA_WLAN_VENDOR_ATTR_FLOW_STATUS_UPDATE_TYPE = 3,
+
+	/* keep last */
+	QCA_WLAN_VENDOR_ATTR_FLOW_STATUS_LAST,
+	QCA_WLAN_VENDOR_ATTR_FLOW_STATUS_MAX =
+	QCA_WLAN_VENDOR_ATTR_FLOW_STATUS_LAST - 1,
+};
+
+/**
+ * enum qca_wlan_vendor_attr_iq_data_inference - Represents the attributes sent
+ * as part of IQ data inference messages.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_CMD_TYPE: u32 attribute represents
+ * the command type sent from userspace to the driver.
+ * The values are defined in enum qca_wlan_vendor_iq_inference_cmd_type.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_BW: u32 attribute containing
+ * one of the values of &enum nl80211_chan_width, describing the channel width.
+ * See the documentation of the enum for more information.
+ *
+ * @CA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_CHANNEL_FREQ: u32 attribute represents
+ * the channel frequency (in MHz).
+ * This is sent from the driver to user space as part of the event
+ * @QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_CENTER_FREQ_1: u32 attribute
+ * represents the primary center frequency (in MHz).
+ * This is sent from the driver to user space as part of the event
+ * @QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_CENTER_FREQ_2: u32 attribute
+ * represents the secondary center frequency (in MHz); valid only for
+ * 80+80 MHz channels.
+ * This is sent from the driver to user space as part of the event
+ * @QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_MCS: u32 attribute represents the MCS
+ * Index w.r.t. various PHY mode as per
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_PHY_MODE.
+ * This is sent from the driver to user space as part of the event
+ * @QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_TEMPERATURE: s32 attribute represents
+ * the device temperature in degree Celcius.
+ * This is sent from the driver to user space as part of event
+ * @QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_STAGE: u32 attributes represents the
+ * inference stage. The values are defined in
+ * enum qca_wlan_vendor_iq_inference_stage.
+ * This is sent from the driver to user space as part of the event
+ * @QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_EVM: s32 attribute represents the
+ * Error Vector Magniture (in dB). Userspace App derives EVM based on the IQ
+ * samples data and send it to the driver.
+ * This attribute is used with @QCA_WLAN_VENDOR_IQ_INFERENCE_CMD_RESULT.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_MASK_MARGIN: s32 attribute represents
+ * the Spectral Mask Margin (in dB). Userspace app derives mask margin based on
+ * the IQ samples data and send it to the driver.
+ * This attribute is used with @QCA_WLAN_VENDOR_IQ_INFERENCE_CMD_RESULT.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_PHY_MODE: u32 attribute represents
+ * the PHY mode for which inference is being sent.
+ * This is sent from the driver to user space as part of the event
+ * @QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_SAMPLE_SIZE: u32 attribute represents
+ * the IQ sample size (in bytes).
+ * This is sent from the driver to user space as part of event
+ * @QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE.
+ * User space application can read the IQ samples from the memory mapped
+ * IO file /dev/txpb.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_STATUS: u32 attribute represents the
+ * inference status.
+ * This is sent from the driver to user space as part of event
+ * @QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE.
+ * The values are defined in enum qca_wlan_vendor_iq_inference_status.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_COOKIE: u64 cookie provided by the
+ * driver for the specific inference request.
+ * This is sent from the driver to user space as part of event
+ * @QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE and the same cookie needs to be
+ * passed back to the driver as part of the command
+ * @QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE
+ * to maintain synchronization between commands and asynchronous events.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_PAD: Attribute used for padding for
+ * 64-bit alignment.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_TX_POWER: s32 attribute represents
+ * the TX power of an inferencing packet (in dBm).
+ * This is sent from the driver to user space as part of event
+ * @QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE.
+ *
+ * @QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_TX_CHAIN_IDX: u32 attribute
+ * represents the TX chain index on which inferencing is requested for.
+ * This is sent from the driver to user space as part of event
+ * @QCA_NL80211_VENDOR_SUBCMD_IQ_DATA_INFERENCE.
+ */
+enum qca_wlan_vendor_attr_iq_data_inference {
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_INVALID = 0,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_CMD_TYPE = 1,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_BW = 2,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_CHANNEL_FREQ = 3,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_CENTER_FREQ_1 = 4,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_CENTER_FREQ_2 = 5,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_MCS = 6,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_TEMPERATURE = 7,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_STAGE = 8,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_EVM = 9,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_MASK_MARGIN = 10,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_PHY_MODE = 11,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_SAMPLE_SIZE = 12,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_STATUS = 13,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_COOKIE = 14,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_PAD = 15,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_TX_POWER = 16,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_TX_CHAIN_IDX = 17,
+
+	/* keep last */
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_AFTER_LAST,
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_MAX =
+	QCA_WLAN_VENDOR_ATTR_IQ_DATA_INFERENCE_AFTER_LAST - 1,
+};
+
+/**
+ * enum qca_wlan_vendor_iq_inference_cmd_type - Represents the command types
+ * userspace app sends to the driver.
+ *
+ * @QCA_WLAN_VENDOR_IQ_INFERENCE_CMD_APP_START: Represents the stage where
+ * userspace app has started and is ready to receive IQ samples.
+ *
+ * @QCA_WLAN_VENDOR_IQ_INFERENCE_CMD_APP_STOP: Represents the stage where
+ * userspace app has stopped and is no longer ready to receive IQ samples.
+ *
+ * @QCA_WLAN_VENDOR_IQ_INFERENCE_CMD_RESULT: Represents the inference result
+ * sent from userspace to the driver.
+ *
+ * @QCA_WLAN_VENDOR_IQ_INFERENCE_CMD_FAILURE: Represents the inference failure
+ * sent from userspace to the driver.
+ *
+ */
+enum qca_wlan_vendor_iq_inference_cmd_type {
+	QCA_WLAN_VENDOR_IQ_INFERENCE_CMD_APP_START = 0,
+	QCA_WLAN_VENDOR_IQ_INFERENCE_CMD_APP_STOP = 1,
+	QCA_WLAN_VENDOR_IQ_INFERENCE_CMD_RESULT = 2,
+	QCA_WLAN_VENDOR_IQ_INFERENCE_CMD_FAILURE = 3,
+};
+
+/**
+ * enum qca_wlan_vendor_iq_inference_stage - Represents the inference stage
+ *
+ * @QCA_WLAN_VENDOR_IQ_INFERENCE_STAGE_FIRST_PASS: Represents the first
+ * pass in inference stage.
+ *
+ * @QCA_WLAN_VENDOR_IQ_INFERENCE_STAGE_SECOND_PASS: Represents the second
+ * pass in inference stage.
+ */
+enum qca_wlan_vendor_iq_inference_stage {
+	QCA_WLAN_VENDOR_IQ_INFERENCE_STAGE_FIRST_PASS = 0,
+	QCA_WLAN_VENDOR_IQ_INFERENCE_STAGE_SECOND_PASS = 1,
+};
+
+/**
+ * enum qca_wlan_vendor_iq_inference_status - Represents the inference
+ * status sent from driver to user space.
+ *
+ * @QCA_WLAN_VENDOR_IQ_INFERENCE_STATUS_START_INFERENCE: Represents the stage where
+ * userspace app to start the inference.
+ *
+ * @QCA_WLAN_VENDOR_IQ_INFERENCE_STATUS_ABORT: Represents the stage where
+ * userspace app to stop the inference.
+ *
+ * @QCA_WLAN_VENDOR_IQ_INFERENCE_STATUS_COMPLETE: Represents the stage where
+ * inference is complete.
+ *
+ */
+enum qca_wlan_vendor_iq_inference_status {
+	QCA_WLAN_VENDOR_IQ_INFERENCE_STATUS_START_INFERENCE = 0,
+	QCA_WLAN_VENDOR_IQ_INFERENCE_STATUS_ABORT = 1,
+	QCA_WLAN_VENDOR_IQ_INFERENCE_STATUS_COMPLETE = 2,
+};
+
 #endif /* QCA_VENDOR_H */
diff --git a/src/common/sae.c b/src/common/sae.c
index 801f3630..8005095f 100644
--- a/src/common/sae.c
+++ b/src/common/sae.c
@@ -1670,12 +1670,17 @@ fail:
 int sae_process_commit(struct sae_data *sae)
 {
 	u8 k[SAE_MAX_PRIME_LEN];
+	int ret = 0;
+
 	if (sae->tmp == NULL ||
 	    (sae->tmp->ec && sae_derive_k_ecc(sae, k) < 0) ||
 	    (sae->tmp->dh && sae_derive_k_ffc(sae, k) < 0) ||
 	    sae_derive_keys(sae, k) < 0)
-		return -1;
-	return 0;
+		ret = -1;
+
+	forced_memzero(k, SAE_MAX_PRIME_LEN);
+
+	return ret;
 }
 
 
diff --git a/src/common/wpa_common.c b/src/common/wpa_common.c
index 613ea7fd..4367a227 100644
--- a/src/common/wpa_common.c
+++ b/src/common/wpa_common.c
@@ -1420,8 +1420,9 @@ void wpa_ft_parse_ies_free(struct wpa_ft_ies *parse)
  * @akmp: Authentication and key management protocol
  * @cipher: The cipher suite
  *
- * According to IEEE P802.11az/D2.7, 12.12.7, the hash algorithm to use is the
- * hash algorithm defined for the Base AKM (see Table 9-151 (AKM suite
+ * According to IEEE Std 802.11-2024, 12.13.8 (PTKSA derivation with PASN
+ * authentication), the hash algorithm to use is the
+ * hash algorithm defined for the Base AKM (see Table 9-190 (AKM suite
  * selectors)). When there is no Base AKM, the hash algorithm is selected based
  * on the pairwise cipher suite provided in the RSNE by the AP in the second
  * PASN frame. SHA-256 is used as the hash algorithm, except for the ciphers
@@ -3158,10 +3159,10 @@ int wpa_cipher_put_suites(u8 *start, int ciphers)
 
 int wpa_pick_pairwise_cipher(int ciphers, int none_allowed)
 {
-	if (ciphers & WPA_CIPHER_CCMP_256)
-		return WPA_CIPHER_CCMP_256;
 	if (ciphers & WPA_CIPHER_GCMP_256)
 		return WPA_CIPHER_GCMP_256;
+	if (ciphers & WPA_CIPHER_CCMP_256)
+		return WPA_CIPHER_CCMP_256;
 	if (ciphers & WPA_CIPHER_CCMP)
 		return WPA_CIPHER_CCMP;
 	if (ciphers & WPA_CIPHER_GCMP)
@@ -3176,10 +3177,10 @@ int wpa_pick_pairwise_cipher(int ciphers, int none_allowed)
 
 int wpa_pick_group_cipher(int ciphers)
 {
-	if (ciphers & WPA_CIPHER_CCMP_256)
-		return WPA_CIPHER_CCMP_256;
 	if (ciphers & WPA_CIPHER_GCMP_256)
 		return WPA_CIPHER_GCMP_256;
+	if (ciphers & WPA_CIPHER_CCMP_256)
+		return WPA_CIPHER_CCMP_256;
 	if (ciphers & WPA_CIPHER_CCMP)
 		return WPA_CIPHER_CCMP;
 	if (ciphers & WPA_CIPHER_GCMP)
diff --git a/src/common/wpa_common.h b/src/common/wpa_common.h
index d2c326c4..5b9773e3 100644
--- a/src/common/wpa_common.h
+++ b/src/common/wpa_common.h
@@ -614,7 +614,7 @@ struct wpa_ft_ies {
 	struct wpabuf *fte_buf;
 };
 
-/* IEEE P802.11az/D2.6 - 9.4.2.303 PASN Parameters element */
+/* IEEE Std 802.11-2024 - 9.4.2.305 PASN Parameters element */
 #define WPA_PASN_CTRL_COMEBACK_INFO_PRESENT BIT(0)
 #define WPA_PASN_CTRL_GROUP_AND_KEY_PRESENT BIT(1)
 
diff --git a/src/crypto/crypto_linux.c b/src/crypto/crypto_linux.c
index 9278e279..5d4f6be9 100644
--- a/src/crypto/crypto_linux.c
+++ b/src/crypto/crypto_linux.c
@@ -363,8 +363,8 @@ int crypto_hash_finish(struct crypto_hash *ctx, u8 *mac, size_t *len)
 	}
 
 	if (*len < ctx->mac_len) {
-		crypto_hash_deinit(ctx);
 		*len = ctx->mac_len;
+		crypto_hash_deinit(ctx);
 		return -1;
 	}
 	*len = ctx->mac_len;
diff --git a/src/crypto/crypto_openssl.c b/src/crypto/crypto_openssl.c
index c84ccb46..2efe3ed9 100644
--- a/src/crypto/crypto_openssl.c
+++ b/src/crypto/crypto_openssl.c
@@ -431,7 +431,7 @@ int rc4_skip(const u8 *key, size_t keylen, size_t skip,
 	EVP_CIPHER_CTX *ctx;
 	int outl;
 	int res = -1;
-	unsigned char skip_buf[16];
+	unsigned char skip_buf[16] = { 0 };
 
 	openssl_load_legacy_provider();
 
diff --git a/src/crypto/tls_openssl.c b/src/crypto/tls_openssl.c
index 1eb3b916..3d636850 100644
--- a/src/crypto/tls_openssl.c
+++ b/src/crypto/tls_openssl.c
@@ -1567,6 +1567,7 @@ err:
 	if (!conn->private_key)
 		return -1;
 #endif /* !ANDROID */
+
 	return 0;
 #endif /* OPENSSL_NO_ENGINE */
 }
diff --git a/src/drivers/driver.h b/src/drivers/driver.h
index 8a7e6734..6fe66523 100644
--- a/src/drivers/driver.h
+++ b/src/drivers/driver.h
@@ -159,6 +159,12 @@ struct hostapd_channel_data {
 	 * need to set this)
 	 */
 	long double interference_factor;
+
+	/**
+	 * interference_bss_based - Indicates whether the interference was
+	 * calculated from number of BSSs
+	 */
+	bool interference_bss_based;
 #endif /* CONFIG_ACS */
 
 	/**
@@ -1413,6 +1419,16 @@ struct wpa_driver_associate_params {
 	 * spp_amsdu - SPP A-MSDU used on this connection
 	 */
 	bool spp_amsdu;
+
+	/**
+	 * bssid_filter - Allowed BSSIDs for the current association
+	 * This can be %NULL to indicate no constraint. */
+	const u8 *bssid_filter;
+
+	/**
+	 * bssid_filter_count - Number of allowed BSSIDs
+	 */
+	unsigned int bssid_filter_count;
 };
 
 enum hide_ssid {
@@ -1453,6 +1469,72 @@ struct unsol_bcast_probe_resp {
 	size_t unsol_bcast_probe_resp_tmpl_len;
 };
 
+struct mbssid_data {
+	/**
+	 * mbssid_tx_iface - Transmitting interface of the MBSSID set
+	 */
+	const char *mbssid_tx_iface;
+
+	/**
+	 * mbssid_tx_iface_linkid - Link ID of the transmitting interface if
+	 * it is part of an MLD. Otherwise, -1.
+	 */
+	int mbssid_tx_iface_linkid;
+
+	/**
+	 * mbssid_index - The index of this BSS in the MBSSID set
+	 */
+	unsigned int mbssid_index;
+
+	/**
+	 * mbssid_elem - Buffer containing all MBSSID elements
+	 */
+	u8 *mbssid_elem;
+
+	/**
+	 * mbssid_elem_len - Total length of all MBSSID elements
+	 */
+	size_t mbssid_elem_len;
+
+	/**
+	 * mbssid_elem_count - The number of MBSSID elements
+	 */
+	u8 mbssid_elem_count;
+
+	/**
+	 * mbssid_elem_offset - Offsets to elements in mbssid_elem.
+	 * Kernel will use these offsets to generate multiple BSSID beacons.
+	 */
+	u8 **mbssid_elem_offset;
+
+	/**
+	 * ema - Enhanced MBSSID advertisements support.
+	 */
+	bool ema;
+
+	/**
+	 * rnr_elem - This buffer contains all of reduced neighbor report (RNR)
+	 * elements
+	 */
+	u8 *rnr_elem;
+
+	/**
+	 * rnr_elem_len - Length of rnr_elem buffer
+	 */
+	size_t rnr_elem_len;
+
+	/**
+	 * rnr_elem_count - Number of RNR elements
+	 */
+	u8 rnr_elem_count;
+
+	/**
+	 * rnr_elem_offset - The offsets to the elements in rnr_elem.
+	 * The driver will use these to include RNR elements in EMA beacons.
+	 */
+	u8 **rnr_elem_offset;
+};
+
 struct wpa_driver_ap_params {
 	/**
 	 * head - Beacon head from IEEE 802.11 header to IEs before TIM IE
@@ -1791,40 +1873,11 @@ struct wpa_driver_ap_params {
 	size_t fd_frame_tmpl_len;
 
 	/**
-	 * mbssid_tx_iface - Transmitting interface of the MBSSID set
-	 */
-	const char *mbssid_tx_iface;
-
-	/**
-	 * mbssid_index - The index of this BSS in the MBSSID set
-	 */
-	unsigned int mbssid_index;
-
-	/**
-	 * mbssid_elem - Buffer containing all MBSSID elements
-	 */
-	u8 *mbssid_elem;
-
-	/**
-	 * mbssid_elem_len - Total length of all MBSSID elements
-	 */
-	size_t mbssid_elem_len;
-
-	/**
-	 * mbssid_elem_count - The number of MBSSID elements
-	 */
-	u8 mbssid_elem_count;
-
-	/**
-	 * mbssid_elem_offset - Offsets to elements in mbssid_elem.
-	 * Kernel will use these offsets to generate multiple BSSID beacons.
-	 */
-	u8 **mbssid_elem_offset;
-
-	/**
-	 * ema - Enhanced MBSSID advertisements support.
+	 * mbssid - MBSSID element related params for Beacon frames
+	 *
+	 * This is used to add MBSSID element in beacon data.
 	 */
-	bool ema;
+	struct mbssid_data mbssid;
 
 	/**
 	 * punct_bitmap - Preamble puncturing bitmap
@@ -1834,27 +1887,6 @@ struct wpa_driver_ap_params {
 	 */
 	u16 punct_bitmap;
 
-	/**
-	 * rnr_elem - This buffer contains all of reduced neighbor report (RNR)
-	 * elements
-	 */
-	u8 *rnr_elem;
-
-	/**
-	 * rnr_elem_len - Length of rnr_elem buffer
-	 */
-	size_t rnr_elem_len;
-
-	/**
-	 * rnr_elem_count - Number of RNR elements
-	 */
-	unsigned int rnr_elem_count;
-
-	/**
-	 * rnr_elem_offset - The offsets to the elements in rnr_elem.
-	 * The driver will use these to include RNR elements in EMA beacons.
-	 */
-	u8 **rnr_elem_offset;
 
 	/* Unsolicited broadcast Probe Response data */
 	struct unsol_bcast_probe_resp ubpr;
@@ -2773,6 +2805,7 @@ struct wpa_channel_info {
  * @proberesp_ies_len: Length of proberesp_ies in octets
  * @proberesp_ies_len: Length of proberesp_ies in octets
  * @probe_resp_len: Length of probe response template (@probe_resp)
+ * @mbssid: MBSSID element(s) to add into Beacon frames
  */
 struct beacon_data {
 	u8 *head, *tail;
@@ -2786,6 +2819,8 @@ struct beacon_data {
 	size_t proberesp_ies_len;
 	size_t assocresp_ies_len;
 	size_t probe_resp_len;
+
+	struct mbssid_data mbssid;
 };
 
 /**
diff --git a/src/drivers/driver_nl80211.c b/src/drivers/driver_nl80211.c
index 0848d16b..0e4283f1 100644
--- a/src/drivers/driver_nl80211.c
+++ b/src/drivers/driver_nl80211.c
@@ -2308,6 +2308,7 @@ static void * wpa_driver_nl80211_drv_init(void *ctx, const char *ifname,
 					  const char *driver_params,
 					  enum wpa_p2p_mode p2p_mode)
 {
+	static unsigned int next_unique_drv_id = 0;
 	struct wpa_driver_nl80211_data *drv;
 	struct i802_bss *bss;
 	char path[128], buf[200], *pos;
@@ -2340,6 +2341,7 @@ static void * wpa_driver_nl80211_drv_init(void *ctx, const char *ifname,
 	drv->ctx = ctx;
 	drv->hostapd = !!hostapd;
 	drv->eapol_sock = -1;
+	drv->unique_drv_id = next_unique_drv_id++;
 
 	/*
 	 * There is no driver capability flag for this, so assume it is
@@ -2409,6 +2411,7 @@ skip_wifi_status:
 	 * Use link ID 0 for the single "link" of a non-MLD.
 	 */
 	bss->valid_links = 0;
+	bss->active_links = 0;
 	bss->flink = &bss->links[0];
 	os_memcpy(bss->flink->addr, bss->addr, ETH_ALEN);
 
@@ -4981,8 +4984,7 @@ static int nl80211_unsol_bcast_probe_resp(struct i802_bss *bss,
 }
 
 
-static int nl80211_mbssid(struct nl_msg *msg,
-			 struct wpa_driver_ap_params *params)
+static int nl80211_mbssid(struct nl_msg *msg, struct mbssid_data *params)
 {
 	struct nlattr *config, *elems;
 	int ifidx;
@@ -5002,6 +5004,10 @@ static int nl80211_mbssid(struct nl_msg *msg,
 		    nla_put_u32(msg, NL80211_MBSSID_CONFIG_ATTR_TX_IFINDEX,
 				ifidx))
 			return -1;
+		if (params->mbssid_tx_iface_linkid >= 0 &&
+		    nla_put_u8(msg, NL80211_MBSSID_CONFIG_ATTR_TX_LINK_ID,
+			       params->mbssid_tx_iface_linkid))
+			return -1;
 	}
 
 	if (params->ema && nla_put_flag(msg, NL80211_MBSSID_CONFIG_ATTR_EMA))
@@ -5279,6 +5285,12 @@ static int wpa_driver_nl80211_set_ap(void *priv,
 	    nla_put(msg, NL80211_ATTR_SSID, params->ssid_len, params->ssid))
 		goto fail;
 
+	if (params->freq)
+		nl80211_link_set_freq(bss,
+				      params->mld_ap ? params->mld_link_id :
+				      NL80211_DRV_LINK_ID_NA,
+				      params->freq->freq);
+
 	if (params->mld_ap) {
 		wpa_printf(MSG_DEBUG, "nl80211: link_id=%u",
 			   params->mld_link_id);
@@ -5286,10 +5298,6 @@ static int wpa_driver_nl80211_set_ap(void *priv,
 		if (nla_put_u8(msg, NL80211_ATTR_MLO_LINK_ID,
 			       params->mld_link_id))
 			goto fail;
-
-		if (params->freq)
-			nl80211_link_set_freq(bss, params->mld_link_id,
-					      params->freq->freq);
 	}
 
 	if (params->proberesp && params->proberesp_len) {
@@ -5561,7 +5569,7 @@ static int wpa_driver_nl80211_set_ap(void *priv,
 	    nl80211_unsol_bcast_probe_resp(bss, msg, &params->ubpr) < 0)
 		goto fail;
 
-	if (nl80211_mbssid(msg, params) < 0)
+	if (nl80211_mbssid(msg, &params->mbssid) < 0)
 		goto fail;
 #endif /* CONFIG_IEEE80211AX */
 
@@ -6313,7 +6321,7 @@ int nl80211_create_iface(struct wpa_driver_nl80211_data *drv,
 					arg);
 
 	/* if error occurred and interface exists already */
-	if (ret == -ENFILE && if_nametoindex(ifname)) {
+	if (ret < 0 && if_nametoindex(ifname)) {
 		if (use_existing) {
 			wpa_printf(MSG_DEBUG, "nl80211: Continue using existing interface %s",
 				   ifname);
@@ -7288,6 +7296,26 @@ static int nl80211_connect_ext(struct wpa_driver_nl80211_data *drv,
 		    sizeof(features), features))
 		goto fail;
 
+	if (params->bssid_filter && params->bssid_filter_count) {
+		struct nlattr *bssid_list;
+		unsigned int i;
+
+		bssid_list = nla_nest_start(
+			msg, QCA_WLAN_VENDOR_ATTR_CONNECT_EXT_ALLOWED_BSSIDS);
+		if (!bssid_list)
+			goto fail;
+
+		for (i = 0; i < params->bssid_filter_count; i++) {
+			wpa_printf(MSG_DEBUG, "- bssid_filter[%d]=" MACSTR, i,
+				   MAC2STR(&params->bssid_filter[i * ETH_ALEN]));
+			if (nla_put(msg, i + 1, ETH_ALEN,
+				    &params->bssid_filter[i * ETH_ALEN]))
+				goto fail;
+		}
+
+		nla_nest_end(msg, bssid_list);
+	}
+
 	nla_nest_end(msg, attr);
 
 	return send_and_recv_cmd(drv, msg);
@@ -7562,27 +7590,26 @@ fail:
 }
 
 
-static int nl80211_set_mode(struct wpa_driver_nl80211_data *drv,
-			    int ifindex, enum nl80211_iftype mode)
+static int nl80211_set_mode(struct i802_bss *bss, enum nl80211_iftype mode)
 {
 	struct nl_msg *msg;
 	int ret = -ENOBUFS;
 
 	wpa_printf(MSG_DEBUG, "nl80211: Set mode ifindex %d iftype %d (%s)",
-		   ifindex, mode, nl80211_iftype_str(mode));
+		   bss->ifindex, mode, nl80211_iftype_str(mode));
 
-	msg = nl80211_cmd_msg(drv->first_bss, 0, NL80211_CMD_SET_INTERFACE);
+	msg = nl80211_cmd_msg(bss, 0, NL80211_CMD_SET_INTERFACE);
 	if (!msg || nla_put_u32(msg, NL80211_ATTR_IFTYPE, mode))
 		goto fail;
 
-	ret = send_and_recv_cmd(drv, msg);
+	ret = send_and_recv_cmd(bss->drv, msg);
 	msg = NULL;
 	if (!ret)
 		return 0;
 fail:
 	nlmsg_free(msg);
 	wpa_printf(MSG_DEBUG, "nl80211: Failed to set interface %d to mode %d:"
-		   " %d (%s)", ifindex, mode, ret, strerror(-ret));
+		   " %d (%s)", bss->ifindex, mode, ret, strerror(-ret));
 	return ret;
 }
 
@@ -7602,7 +7629,7 @@ static int wpa_driver_nl80211_set_mode_impl(
 	if (TEST_FAIL())
 		return -1;
 
-	mode_switch_res = nl80211_set_mode(drv, drv->ifindex, nlmode);
+	mode_switch_res = nl80211_set_mode(bss, nlmode);
 	if (mode_switch_res && nlmode == nl80211_get_ifmode(bss))
 		mode_switch_res = 0;
 
@@ -7666,7 +7693,7 @@ static int wpa_driver_nl80211_set_mode_impl(
 		}
 
 		/* Try to set the mode again while the interface is down */
-		mode_switch_res = nl80211_set_mode(drv, drv->ifindex, nlmode);
+		mode_switch_res = nl80211_set_mode(bss, nlmode);
 		if (mode_switch_res == -EBUSY) {
 			wpa_printf(MSG_DEBUG,
 				   "nl80211: Delaying mode set while interface going down");
@@ -8733,6 +8760,7 @@ static int i802_set_wds_sta(void *priv, const u8 *addr, int aid, int val,
 static void handle_eapol(int sock, void *eloop_ctx, void *sock_ctx)
 {
 	struct wpa_driver_nl80211_data *drv = eloop_ctx;
+	struct i802_bss *bss;
 	struct sockaddr_ll lladdr;
 	unsigned char buf[3000];
 	int len;
@@ -8746,8 +8774,10 @@ static void handle_eapol(int sock, void *eloop_ctx, void *sock_ctx)
 		return;
 	}
 
-	if (have_ifidx(drv, lladdr.sll_ifindex, IFIDX_ANY))
-		drv_event_eapol_rx(drv->ctx, lladdr.sll_addr, buf, len);
+	if (have_ifidx(drv, lladdr.sll_ifindex, IFIDX_ANY)) {
+		for (bss = drv->first_bss; bss; bss = bss->next)
+			drv_event_eapol_rx(bss->ctx, lladdr.sll_addr, buf, len);
+	}
 }
 
 
@@ -9164,6 +9194,10 @@ static int wpa_driver_nl80211_if_add(void *priv, enum wpa_driver_if_type type,
 			*drv_priv = new_bss;
 		nl80211_init_bss(new_bss);
 
+		/* Set interface mode to NL80211_IFTYPE_AP */
+		if (nl80211_set_mode(new_bss, nlmode))
+			return -1;
+
 		/* Subscribe management frames for this WPA_IF_AP_BSS */
 		if (nl80211_setup_ap(new_bss))
 			return -1;
@@ -9690,12 +9724,39 @@ fail:
 }
 
 
+void nl80211_update_active_links(struct i802_bss *bss, int link_id)
+{
+	struct i802_link *link = &bss->links[link_id];
+	size_t i;
+
+	wpa_printf(MSG_DEBUG, "nl80211: Update link (ifindex=%d link_id=%u)",
+		   bss->ifindex, link_id);
+
+	if (!(bss->active_links & BIT(link_id))) {
+		wpa_printf(MSG_DEBUG,
+			   "nl80211: MLD: Update link: Link not found");
+		return;
+	}
+
+	wpa_driver_nl80211_del_beacon(bss, link_id);
+
+	bss->active_links &= ~BIT(link_id);
+
+	/* Choose new deflink if we are removing that link */
+	if (bss->flink == link) {
+		for_each_link(bss->active_links, i) {
+			bss->flink = &bss->links[i];
+			break;
+		}
+	}
+}
+
+
 int nl80211_remove_link(struct i802_bss *bss, int link_id)
 {
 	struct wpa_driver_nl80211_data *drv = bss->drv;
 	struct i802_link *link;
 	struct nl_msg *msg;
-	size_t i;
 	int ret;
 	u8 link_addr[ETH_ALEN];
 
@@ -9710,20 +9771,13 @@ int nl80211_remove_link(struct i802_bss *bss, int link_id)
 
 	link = &bss->links[link_id];
 
-	wpa_driver_nl80211_del_beacon(bss, link_id);
-
 	os_memcpy(link_addr, link->addr, ETH_ALEN);
+
 	/* First remove the link locally */
-	bss->valid_links &= ~BIT(link_id);
 	os_memset(link->addr, 0, ETH_ALEN);
-
-	/* Choose new deflink if we are removing that link */
-	if (bss->flink == link) {
-		for_each_link_default(bss->valid_links, i, 0) {
-			bss->flink = &bss->links[i];
-			break;
-		}
-	}
+	/* Clear the active links and set the flink */
+	nl80211_update_active_links(bss, link_id);
+	bss->valid_links &= ~BIT(link_id);
 
 	/* If this was the last link, reset default link */
 	if (!bss->valid_links) {
@@ -11063,6 +11117,8 @@ static int driver_nl80211_link_remove(void *priv, enum wpa_driver_if_type type,
 		drv->ctx = bss->ctx;
 
 	if (!bss->valid_links) {
+		void *ctx = bss->ctx;
+
 		wpa_printf(MSG_DEBUG,
 			   "nl80211: No more links remaining, so remove interface");
 		ret = wpa_driver_nl80211_if_remove(bss, type, ifname);
@@ -11070,7 +11126,7 @@ static int driver_nl80211_link_remove(void *priv, enum wpa_driver_if_type type,
 			return ret;
 
 		/* Notify that the MLD interface is removed */
-		wpa_supplicant_event(bss->ctx, EVENT_MLD_INTERFACE_FREED, NULL);
+		wpa_supplicant_event(ctx, EVENT_MLD_INTERFACE_FREED, NULL);
 	}
 
 	return 0;
@@ -11490,8 +11546,8 @@ static int wpa_driver_nl80211_status(void *priv, char *buf, size_t buflen)
 	return pos - buf;
 }
 
-
-static int set_beacon_data(struct nl_msg *msg, struct beacon_data *settings)
+static int set_beacon_data(struct nl_msg *msg, struct beacon_data *settings,
+			   bool skip_mbssid)
 {
 	if ((settings->head &&
 	     nla_put(msg, NL80211_ATTR_BEACON_HEAD,
@@ -11513,6 +11569,11 @@ static int set_beacon_data(struct nl_msg *msg, struct beacon_data *settings)
 		     settings->probe_resp_len, settings->probe_resp)))
 		return -ENOBUFS;
 
+#ifdef CONFIG_IEEE80211AX
+	if (!skip_mbssid && nl80211_mbssid(msg, &settings->mbssid) < 0)
+		return -ENOBUFS;
+#endif /* CONFIG_IEEE80211AX */
+
 	return 0;
 }
 
@@ -11617,7 +11678,7 @@ static int nl80211_switch_channel(void *priv, struct csa_settings *settings)
 		goto error;
 
 	/* beacon_after params */
-	ret = set_beacon_data(msg, &settings->beacon_after);
+	ret = set_beacon_data(msg, &settings->beacon_after, false);
 	if (ret)
 		goto error;
 
@@ -11626,7 +11687,7 @@ static int nl80211_switch_channel(void *priv, struct csa_settings *settings)
 	if (!beacon_csa)
 		goto fail;
 
-	ret = set_beacon_data(msg, &settings->beacon_csa);
+	ret = set_beacon_data(msg, &settings->beacon_csa, true);
 	if (ret)
 		goto error;
 
@@ -11703,7 +11764,7 @@ static int nl80211_switch_color(void *priv, struct cca_settings *settings)
 		goto error;
 
 	/* beacon_after params */
-	ret = set_beacon_data(msg, &settings->beacon_after);
+	ret = set_beacon_data(msg, &settings->beacon_after, false);
 	if (ret)
 		goto error;
 
@@ -11714,7 +11775,7 @@ static int nl80211_switch_color(void *priv, struct cca_settings *settings)
 		goto error;
 	}
 
-	ret = set_beacon_data(msg, &settings->beacon_cca);
+	ret = set_beacon_data(msg, &settings->beacon_cca, true);
 	if (ret)
 		goto error;
 
@@ -12864,19 +12925,20 @@ static int add_freq_list(struct nl_msg *msg, int attr, const int *freq_list)
 }
 
 
-static int nl80211_qca_do_acs(struct wpa_driver_nl80211_data *drv,
+static int nl80211_qca_do_acs(struct i802_bss *bss,
 			      struct drv_acs_params *params)
 {
 	struct nl_msg *msg;
 	struct nlattr *data;
 	int ret;
 	int mode;
+	struct wpa_driver_nl80211_data *drv = bss->drv;
 
 	mode = hw_mode_to_qca_acs(params->hw_mode);
 	if (mode < 0)
 		return -1;
 
-	if (!(msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR)) ||
+	if (!(msg = nl80211_bss_msg(bss, 0, NL80211_CMD_VENDOR)) ||
 	    nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_QCA) ||
 	    nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
 			QCA_NL80211_VENDOR_SUBCMD_DO_ACS) ||
@@ -14146,7 +14208,7 @@ static int nl80211_do_acs(void *priv, struct drv_acs_params *params)
 
 #ifdef CONFIG_DRIVER_NL80211_QCA
 	if (drv->qca_do_acs)
-		return nl80211_qca_do_acs(drv, params);
+		return nl80211_qca_do_acs(bss, params);
 #endif /* CONFIG_DRIVER_NL80211_QCA */
 
 #if defined(CONFIG_DRIVER_NL80211_BRCM) || defined(CONFIG_DRIVER_NL80211_SYNA)
@@ -14625,7 +14687,7 @@ static int nl80211_link_add(void *priv, u8 link_id, const u8 *addr,
 		return -EINVAL;
 	}
 
-	if (bss->valid_links & BIT(link_id)) {
+	if (bss->active_links & BIT(link_id)) {
 		wpa_printf(MSG_DEBUG,
 			   "nl80211: MLD: Link %u already set", link_id);
 		return -EINVAL;
@@ -14657,14 +14719,16 @@ static int nl80211_link_add(void *priv, u8 link_id, const u8 *addr,
 	os_memcpy(bss->links[link_id].addr, addr, ETH_ALEN);
 
 	/* The new link is the first one, make it the default */
-	if (!bss->valid_links)
+	if (!bss->active_links)
 		bss->flink = &bss->links[link_id];
 
 	bss->valid_links |= BIT(link_id);
+	bss->active_links |= BIT(link_id);
 	bss->links[link_id].ctx = bss_ctx;
 
-	wpa_printf(MSG_DEBUG, "nl80211: MLD: valid_links=0x%04x on %s",
-		   bss->valid_links, bss->ifname);
+	wpa_printf(MSG_DEBUG,
+		   "nl80211: MLD: valid_links=0x%04x active_links=0x%04x on %s",
+		   bss->valid_links, bss->active_links, bss->ifname);
 
 	if (drv->rtnl_sk)
 		rtnl_neigh_add_fdb_entry(bss, addr, true);
diff --git a/src/drivers/driver_nl80211.h b/src/drivers/driver_nl80211.h
index bf3442ad..693bfb8c 100644
--- a/src/drivers/driver_nl80211.h
+++ b/src/drivers/driver_nl80211.h
@@ -65,7 +65,10 @@ struct i802_bss {
 	struct wpa_driver_nl80211_data *drv;
 	struct i802_bss *next;
 
+	/* The links which are physically present */
 	u16 valid_links;
+	/* The links which are in UP state */
+	u16 active_links;
 	struct i802_link links[MAX_NUM_MLD_LINKS];
 	struct i802_link *flink, *scan_link;
 
@@ -126,6 +129,7 @@ struct wpa_driver_nl80211_data {
 		u16 mld_capa_and_ops;
 	} iface_capa[NL80211_IFTYPE_MAX];
 	unsigned int num_iface_capa;
+	unsigned int unique_drv_id;
 
 	int has_capability;
 	int has_driver_key_mgmt;
@@ -383,6 +387,7 @@ void nl80211_restore_ap_mode(struct i802_bss *bss);
 struct i802_link * nl80211_get_link(struct i802_bss *bss, s8 link_id);
 u8 nl80211_get_link_id_from_link(struct i802_bss *bss, struct i802_link *link);
 int nl80211_remove_link(struct i802_bss *bss, int link_id);
+void nl80211_update_active_links(struct i802_bss *bss, int link_id);
 
 static inline bool nl80211_link_valid(u16 links, s8 link_id)
 {
diff --git a/src/drivers/driver_nl80211_capa.c b/src/drivers/driver_nl80211_capa.c
index 1dbfc229..71676e76 100644
--- a/src/drivers/driver_nl80211_capa.c
+++ b/src/drivers/driver_nl80211_capa.c
@@ -1472,11 +1472,11 @@ static void qca_nl80211_get_features(struct wpa_driver_nl80211_data *drv)
 	if (check_feature(QCA_WLAN_VENDOR_FEATURE_NAN_USD_OFFLOAD, &info))
 		drv->capa.flags2 |= WPA_DRIVER_FLAGS2_NAN_OFFLOAD;
 
-	if (!check_feature(QCA_WLAN_VENDOR_FEATURE_P2P_V2, &info))
-		drv->capa.flags2 &= ~WPA_DRIVER_FLAGS2_P2P_FEATURE_V2;
+	if (check_feature(QCA_WLAN_VENDOR_FEATURE_P2P_V2, &info))
+		drv->capa.flags2 |= WPA_DRIVER_FLAGS2_P2P_FEATURE_V2;
 
-	if (!check_feature(QCA_WLAN_VENDOR_FEATURE_PCC_MODE, &info))
-		drv->capa.flags2 &= ~WPA_DRIVER_FLAGS2_P2P_FEATURE_PCC_MODE;
+	if (check_feature(QCA_WLAN_VENDOR_FEATURE_PCC_MODE, &info))
+		drv->capa.flags2 |= WPA_DRIVER_FLAGS2_P2P_FEATURE_PCC_MODE;
 
 	os_free(info.flags);
 }
@@ -1598,11 +1598,17 @@ int wpa_driver_nl80211_capa(struct wpa_driver_nl80211_data *drv)
 	if (!info.data_tx_status)
 		drv->capa.flags &= ~WPA_DRIVER_FLAGS_EAPOL_TX_STATUS;
 
+	// By default, core supplicant enable WFD R2 and PCC mode for SME non-offload drivers.
+	// TODO Enable this code once the feature is tested on such driver implementations.
+#if 0
 	/* Enable P2P2 and PCC mode capabilities by default for the drivers
-	 * which can't explicitly indicate whether these capabilities are
-	 * supported. */
-	drv->capa.flags2 |= WPA_DRIVER_FLAGS2_P2P_FEATURE_V2;
-	drv->capa.flags2 |= WPA_DRIVER_FLAGS2_P2P_FEATURE_PCC_MODE;
+	 * for which SME runs in wpa_supplicant
+	 */
+	if (drv->capa.flags & WPA_DRIVER_FLAGS_SME) {
+		drv->capa.flags2 |= WPA_DRIVER_FLAGS2_P2P_FEATURE_V2;
+		drv->capa.flags2 |= WPA_DRIVER_FLAGS2_P2P_FEATURE_PCC_MODE;
+	}
+#endif
 
 #ifdef CONFIG_DRIVER_NL80211_QCA
 	if (!(info.capa->flags & WPA_DRIVER_FLAGS_DFS_OFFLOAD))
diff --git a/src/drivers/driver_nl80211_event.c b/src/drivers/driver_nl80211_event.c
index 246d49d8..b5a15cf8 100644
--- a/src/drivers/driver_nl80211_event.c
+++ b/src/drivers/driver_nl80211_event.c
@@ -584,11 +584,13 @@ struct links_info {
 };
 
 
-static void nl80211_get_basic_mle_links_info(const u8 *mle, size_t mle_len,
+static void nl80211_get_basic_mle_links_info(struct wpabuf *mlbuf,
 					     struct links_info *info)
 {
 	size_t rem_len;
 	const u8 *pos;
+	const u8 *mle = wpabuf_head(mlbuf);
+	size_t mle_len = wpabuf_len(mlbuf);
 
 	if (mle_len < MULTI_LINK_CONTROL_LEN + 1 ||
 	    mle_len - MULTI_LINK_CONTROL_LEN < mle[MULTI_LINK_CONTROL_LEN])
@@ -601,7 +603,20 @@ static void nl80211_get_basic_mle_links_info(const u8 *mle, size_t mle_len,
 
 	/* Parse Subelements */
 	while (rem_len > 2) {
-		size_t ie_len = 2 + pos[1];
+		size_t ie_len, subelem_defrag_len;
+		int num_frag_subelems;
+
+		num_frag_subelems =
+			ieee802_11_defrag_mle_subelem(mlbuf, pos,
+						      &subelem_defrag_len);
+		if (num_frag_subelems < 0) {
+			wpa_printf(MSG_DEBUG,
+				   "nl80211: Failed to parse MLE subelem");
+			break;
+		}
+
+		ie_len = 2 + subelem_defrag_len;
+		rem_len -= num_frag_subelems * 2;
 
 		if (rem_len < ie_len)
 			break;
@@ -611,7 +626,8 @@ static void nl80211_get_basic_mle_links_info(const u8 *mle, size_t mle_len,
 			const u8 *sta_profile;
 			u16 sta_ctrl;
 
-			if (pos[1] < BASIC_MLE_STA_PROF_STA_MAC_IDX + ETH_ALEN)
+			if (subelem_defrag_len <
+			    BASIC_MLE_STA_PROF_STA_MAC_IDX + ETH_ALEN)
 				goto next_subelem;
 
 			sta_profile = &pos[2];
@@ -667,8 +683,7 @@ static int nl80211_update_rejected_links_info(struct driver_sta_mlo_info *mlo,
 		return -1;
 	}
 	os_memset(&req_info, 0, sizeof(req_info));
-	nl80211_get_basic_mle_links_info(wpabuf_head(mle), wpabuf_len(mle),
-					 &req_info);
+	nl80211_get_basic_mle_links_info(mle, &req_info);
 	wpabuf_free(mle);
 
 	mle = ieee802_11_defrag(resp_elems.basic_mle, resp_elems.basic_mle_len,
@@ -679,8 +694,7 @@ static int nl80211_update_rejected_links_info(struct driver_sta_mlo_info *mlo,
 		return -1;
 	}
 	os_memset(&resp_info, 0, sizeof(resp_info));
-	nl80211_get_basic_mle_links_info(wpabuf_head(mle), wpabuf_len(mle),
-					 &resp_info);
+	nl80211_get_basic_mle_links_info(mle, &resp_info);
 	wpabuf_free(mle);
 
 	if (req_info.non_assoc_links != resp_info.non_assoc_links) {
@@ -2467,10 +2481,8 @@ static void nl80211_stop_ap(struct i802_bss *bss, struct nlattr **tb)
 			   "nl80211: STOP_AP event on link %d", link_id);
 		ctx = mld_link->ctx;
 
-		/* The driver would have already deleted the link and this call
-		 * will return an error. Ignore that since nl80211_remove_link()
-		 * is called here only to update the bss->links[] state. */
-		nl80211_remove_link(bss, link_id);
+		/* Bring down the active link */
+		nl80211_update_active_links(bss, link_id);
 	}
 
 	wpa_supplicant_event(ctx, EVENT_INTERFACE_UNAVAILABLE, NULL);
@@ -2679,7 +2691,7 @@ static void nl80211_spurious_frame(struct i802_bss *bss, struct nlattr **tb,
 
 #ifdef CONFIG_DRIVER_NL80211_QCA
 
-static void qca_nl80211_avoid_freq(struct wpa_driver_nl80211_data *drv,
+static void qca_nl80211_avoid_freq(struct i802_bss *bss,
 				   const u8 *data, size_t len)
 {
 	u32 i, count;
@@ -2720,7 +2732,7 @@ static void qca_nl80211_avoid_freq(struct wpa_driver_nl80211_data *drv,
 	}
 	event.freq_range.range = range;
 
-	wpa_supplicant_event(drv->ctx, EVENT_AVOID_FREQUENCIES, &event);
+	wpa_supplicant_event(bss->ctx, EVENT_AVOID_FREQUENCIES, &event);
 
 	os_free(range);
 }
@@ -2791,12 +2803,13 @@ try_2_4_or_5:
 }
 
 
-static void qca_nl80211_acs_select_ch(struct wpa_driver_nl80211_data *drv,
+static void qca_nl80211_acs_select_ch(struct i802_bss *bss,
 				   const u8 *data, size_t len)
 {
 	struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_ACS_MAX + 1];
 	union wpa_event_data event;
 	u8 chan;
+	struct wpa_driver_nl80211_data *drv = bss->drv;
 
 	wpa_printf(MSG_DEBUG,
 		   "nl80211: ACS channel selection vendor event received");
@@ -2882,7 +2895,7 @@ static void qca_nl80211_acs_select_ch(struct wpa_driver_nl80211_data *drv,
 
 	/* Ignore ACS channel list check for backwards compatibility */
 
-	wpa_supplicant_event(drv->ctx, EVENT_ACS_CHANNEL_SELECTED, &event);
+	wpa_supplicant_event(bss->ctx, EVENT_ACS_CHANNEL_SELECTED, &event);
 }
 
 
@@ -2926,7 +2939,7 @@ static void qca_nl80211_key_mgmt_auth(struct wpa_driver_nl80211_data *drv,
 #ifdef ANDROID_LIB_EVENT
 	wpa_driver_nl80211_driver_event(
 		drv, OUI_QCA, QCA_NL80211_VENDOR_SUBCMD_KEY_MGMT_ROAM_AUTH,
-		data, len);
+		(u8 *) data, len);
 #endif /* ANDROID_LIB_EVENT */
 #endif /* ANDROID */
 }
@@ -2952,8 +2965,9 @@ qca_nl80211_key_mgmt_auth_handler(struct wpa_driver_nl80211_data *drv,
 }
 
 
-static void qca_nl80211_dfs_offload_radar_event(
-	struct wpa_driver_nl80211_data *drv, u32 subcmd, u8 *msg, int length)
+static void
+qca_nl80211_dfs_offload_radar_event(struct i802_bss *bss, u32 subcmd, u8 *msg,
+				    int length)
 {
 	union wpa_event_data data;
 	struct nlattr *tb[NL80211_ATTR_MAX + 1];
@@ -2980,8 +2994,7 @@ static void qca_nl80211_dfs_offload_radar_event(
 			nla_get_u8(tb[NL80211_ATTR_MLO_LINK_ID]);
 	} else if (data.dfs_event.freq) {
 		data.dfs_event.link_id =
-			nl80211_get_link_id_by_freq(drv->first_bss,
-						    data.dfs_event.freq);
+			nl80211_get_link_id_by_freq(bss, data.dfs_event.freq);
 	}
 
 	wpa_printf(MSG_DEBUG, "nl80211: DFS event on freq %d MHz, link=%d",
@@ -3025,19 +3038,19 @@ static void qca_nl80211_dfs_offload_radar_event(
 
 	switch (subcmd) {
 	case QCA_NL80211_VENDOR_SUBCMD_DFS_OFFLOAD_RADAR_DETECTED:
-		wpa_supplicant_event(drv->ctx, EVENT_DFS_RADAR_DETECTED, &data);
+		wpa_supplicant_event(bss->ctx, EVENT_DFS_RADAR_DETECTED, &data);
 		break;
 	case QCA_NL80211_VENDOR_SUBCMD_DFS_OFFLOAD_CAC_STARTED:
-		wpa_supplicant_event(drv->ctx, EVENT_DFS_CAC_STARTED, &data);
+		wpa_supplicant_event(bss->ctx, EVENT_DFS_CAC_STARTED, &data);
 		break;
 	case QCA_NL80211_VENDOR_SUBCMD_DFS_OFFLOAD_CAC_FINISHED:
-		wpa_supplicant_event(drv->ctx, EVENT_DFS_CAC_FINISHED, &data);
+		wpa_supplicant_event(bss->ctx, EVENT_DFS_CAC_FINISHED, &data);
 		break;
 	case QCA_NL80211_VENDOR_SUBCMD_DFS_OFFLOAD_CAC_ABORTED:
-		wpa_supplicant_event(drv->ctx, EVENT_DFS_CAC_ABORTED, &data);
+		wpa_supplicant_event(bss->ctx, EVENT_DFS_CAC_ABORTED, &data);
 		break;
 	case QCA_NL80211_VENDOR_SUBCMD_DFS_OFFLOAD_CAC_NOP_FINISHED:
-		wpa_supplicant_event(drv->ctx, EVENT_DFS_NOP_FINISHED, &data);
+		wpa_supplicant_event(bss->ctx, EVENT_DFS_NOP_FINISHED, &data);
 		break;
 	default:
 		wpa_printf(MSG_DEBUG,
@@ -3048,13 +3061,14 @@ static void qca_nl80211_dfs_offload_radar_event(
 }
 
 
-static void qca_nl80211_scan_trigger_event(struct wpa_driver_nl80211_data *drv,
-					   u8 *data, size_t len)
+static void qca_nl80211_scan_trigger_event(struct i802_bss *bss, u8 *data,
+					   size_t len)
 {
 	struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_SCAN_MAX + 1];
 	u64 cookie = 0;
 	union wpa_event_data event;
 	struct scan_info *info;
+	struct wpa_driver_nl80211_data *drv = bss->drv;
 
 	if (nla_parse(tb, QCA_WLAN_VENDOR_ATTR_SCAN_MAX,
 		      (struct nlattr *) data, len, NULL) ||
@@ -3074,13 +3088,12 @@ static void qca_nl80211_scan_trigger_event(struct wpa_driver_nl80211_data *drv,
 	info->nl_scan_event = 0;
 
 	drv->scan_state = SCAN_STARTED;
-	wpa_supplicant_event(drv->ctx, EVENT_SCAN_STARTED, &event);
+	wpa_supplicant_event(bss->ctx, EVENT_SCAN_STARTED, &event);
 }
 
 
-static void send_vendor_scan_event(struct wpa_driver_nl80211_data *drv,
-				   int aborted, struct nlattr *tb[],
-				   int external_scan)
+static void send_vendor_scan_event(struct i802_bss *bss, int aborted,
+				   struct nlattr *tb[], int external_scan)
 {
 	union wpa_event_data event;
 	struct nlattr *nl;
@@ -3137,17 +3150,18 @@ static void send_vendor_scan_event(struct wpa_driver_nl80211_data *drv,
 		wpa_printf(MSG_DEBUG, "nl80211: Scan included frequencies:%s",
 			   msg);
 	}
-	wpa_supplicant_event(drv->ctx, EVENT_SCAN_RESULTS, &event);
+	wpa_supplicant_event(bss->ctx, EVENT_SCAN_RESULTS, &event);
 }
 
 
-static void qca_nl80211_scan_done_event(struct wpa_driver_nl80211_data *drv,
-					u8 *data, size_t len)
+static void qca_nl80211_scan_done_event(struct i802_bss *bss, u8 *data,
+					size_t len)
 {
 	struct nlattr *tb[QCA_WLAN_VENDOR_ATTR_SCAN_MAX + 1];
 	u64 cookie = 0;
 	enum scan_status status;
 	int external_scan;
+	struct wpa_driver_nl80211_data *drv = bss->drv;
 
 	if (nla_parse(tb, QCA_WLAN_VENDOR_ATTR_SCAN_MAX,
 		      (struct nlattr *) data, len, NULL) ||
@@ -3176,7 +3190,7 @@ static void qca_nl80211_scan_done_event(struct wpa_driver_nl80211_data *drv,
 		drv->last_scan_cmd = 0;
 	}
 
-	send_vendor_scan_event(drv, (status == VENDOR_SCAN_STATUS_ABORTED), tb,
+	send_vendor_scan_event(bss, (status == VENDOR_SCAN_STATUS_ABORTED), tb,
 			       external_scan);
 }
 
@@ -3208,8 +3222,7 @@ static void qca_nl80211_p2p_lo_stop_event(struct wpa_driver_nl80211_data *drv,
 
 #ifdef CONFIG_PASN
 
-static void qca_nl80211_pasn_auth(struct wpa_driver_nl80211_data *drv,
-				  u8 *data, size_t len)
+static void qca_nl80211_pasn_auth(struct i802_bss *bss, u8 *data, size_t len)
 {
 	int ret = -EINVAL;
 	struct nlattr *attr;
@@ -3276,7 +3289,7 @@ static void qca_nl80211_pasn_auth(struct wpa_driver_nl80211_data *drv,
 		   "nl80211: PASN auth action: %u, num_bssids: %d",
 		   event.pasn_auth.action,
 		   event.pasn_auth.num_peers);
-	wpa_supplicant_event(drv->ctx, EVENT_PASN_AUTH, &event);
+	wpa_supplicant_event(bss->ctx, EVENT_PASN_AUTH, &event);
 }
 
 #endif /* CONFIG_PASN */
@@ -3284,7 +3297,7 @@ static void qca_nl80211_pasn_auth(struct wpa_driver_nl80211_data *drv,
 #endif /* CONFIG_DRIVER_NL80211_QCA */
 
 
-static void nl80211_vendor_event_qca(struct wpa_driver_nl80211_data *drv,
+static void nl80211_vendor_event_qca(struct i802_bss *bss,
 				     u32 subcmd, u8 *data, size_t len)
 {
 	switch (subcmd) {
@@ -3293,40 +3306,40 @@ static void nl80211_vendor_event_qca(struct wpa_driver_nl80211_data *drv,
 		break;
 #ifdef CONFIG_DRIVER_NL80211_QCA
 	case QCA_NL80211_VENDOR_SUBCMD_AVOID_FREQUENCY:
-		qca_nl80211_avoid_freq(drv, data, len);
+		qca_nl80211_avoid_freq(bss, data, len);
 		break;
 	case QCA_NL80211_VENDOR_SUBCMD_KEY_MGMT_ROAM_AUTH:
-		qca_nl80211_key_mgmt_auth_handler(drv, data, len);
+		qca_nl80211_key_mgmt_auth_handler(bss->drv, data, len);
 		break;
 	case QCA_NL80211_VENDOR_SUBCMD_DO_ACS:
-		qca_nl80211_acs_select_ch(drv, data, len);
+		qca_nl80211_acs_select_ch(bss, data, len);
 		break;
 	case QCA_NL80211_VENDOR_SUBCMD_DFS_OFFLOAD_CAC_STARTED:
 	case QCA_NL80211_VENDOR_SUBCMD_DFS_OFFLOAD_CAC_FINISHED:
 	case QCA_NL80211_VENDOR_SUBCMD_DFS_OFFLOAD_CAC_ABORTED:
 	case QCA_NL80211_VENDOR_SUBCMD_DFS_OFFLOAD_CAC_NOP_FINISHED:
 	case QCA_NL80211_VENDOR_SUBCMD_DFS_OFFLOAD_RADAR_DETECTED:
-		qca_nl80211_dfs_offload_radar_event(drv, subcmd, data, len);
+		qca_nl80211_dfs_offload_radar_event(bss, subcmd, data, len);
 		break;
 	case QCA_NL80211_VENDOR_SUBCMD_TRIGGER_SCAN:
-		qca_nl80211_scan_trigger_event(drv, data, len);
+		qca_nl80211_scan_trigger_event(bss, data, len);
 		break;
 	case QCA_NL80211_VENDOR_SUBCMD_SCAN_DONE:
-		qca_nl80211_scan_done_event(drv, data, len);
+		qca_nl80211_scan_done_event(bss, data, len);
 		break;
 	case QCA_NL80211_VENDOR_SUBCMD_P2P_LISTEN_OFFLOAD_STOP:
-		qca_nl80211_p2p_lo_stop_event(drv, data, len);
+		qca_nl80211_p2p_lo_stop_event(bss->drv, data, len);
 		break;
 #ifdef CONFIG_PASN
 	case QCA_NL80211_VENDOR_SUBCMD_PASN:
-		qca_nl80211_pasn_auth(drv, data, len);
+		qca_nl80211_pasn_auth(bss, data, len);
 		break;
 #endif /* CONFIG_PASN */
 	case QCA_NL80211_VENDOR_SUBCMD_TID_TO_LINK_MAP:
-		qca_nl80211_tid_to_link_map_event(drv, data, len);
+		qca_nl80211_tid_to_link_map_event(bss->drv, data, len);
 		break;
 	case QCA_NL80211_VENDOR_SUBCMD_LINK_RECONFIG:
-		qca_nl80211_link_reconfig_event(drv, data, len);
+		qca_nl80211_link_reconfig_event(bss->drv, data, len);
 		break;
 #endif /* CONFIG_DRIVER_NL80211_QCA */
 	default:
@@ -3419,13 +3432,13 @@ static void nl80211_vendor_event_brcm(struct wpa_driver_nl80211_data *drv,
 #endif /* CONFIG_DRIVER_NL80211_BRCM || CONFIG_DRIVER_NL80211_SYNA */
 
 
-static void nl80211_vendor_event(struct wpa_driver_nl80211_data *drv,
-				 struct nlattr **tb)
+static void nl80211_vendor_event(struct i802_bss *bss, struct nlattr **tb)
 {
 	u32 vendor_id, subcmd, wiphy = 0;
 	int wiphy_idx;
 	u8 *data = NULL;
 	size_t len = 0;
+	struct wpa_driver_nl80211_data *drv = bss->drv;
 
 	if (!tb[NL80211_ATTR_VENDOR_ID] ||
 	    !tb[NL80211_ATTR_VENDOR_SUBCMD])
@@ -3467,7 +3480,7 @@ static void nl80211_vendor_event(struct wpa_driver_nl80211_data *drv,
 
 	switch (vendor_id) {
 	case OUI_QCA:
-		nl80211_vendor_event_qca(drv, subcmd, data, len);
+		nl80211_vendor_event_qca(bss, subcmd, data, len);
 		break;
 #if defined(CONFIG_DRIVER_NL80211_BRCM) || defined(CONFIG_DRIVER_NL80211_SYNA)
 	case OUI_BRCM:
@@ -4187,7 +4200,7 @@ static void do_process_drv_event(struct i802_bss *bss, int cmd,
 		nl80211_stop_ap(bss, tb);
 		break;
 	case NL80211_CMD_VENDOR:
-		nl80211_vendor_event(drv, tb);
+		nl80211_vendor_event(bss, tb);
 		break;
 	case NL80211_CMD_NEW_PEER_CANDIDATE:
 		nl80211_new_peer_candidate(drv, tb);
@@ -4242,13 +4255,13 @@ static void do_process_drv_event(struct i802_bss *bss, int cmd,
 
 
 static bool nl80211_drv_in_list(struct nl80211_global *global,
-				struct wpa_driver_nl80211_data *drv)
+				unsigned int unique_drv_id)
 {
 	struct wpa_driver_nl80211_data *tmp;
 
 	dl_list_for_each(tmp, &global->interfaces,
 			 struct wpa_driver_nl80211_data, list) {
-		if (drv == tmp)
+		if (tmp->unique_drv_id == unique_drv_id)
 			return true;
 	}
 
@@ -4308,6 +4321,8 @@ int process_global_event(struct nl_msg *msg, void *arg)
 
 	dl_list_for_each_safe(drv, tmp, &global->interfaces,
 			      struct wpa_driver_nl80211_data, list) {
+		unsigned int unique_drv_id = drv->unique_drv_id;
+
 		for (bss = drv->first_bss; bss; bss = bss->next) {
 			if (wiphy_idx_set)
 				wiphy_idx = nl80211_get_wiphy_index(bss);
@@ -4333,7 +4348,7 @@ int process_global_event(struct nl_msg *msg, void *arg)
 				 * e.g., due to NL80211_CMD_RADAR_DETECT event,
 				 * so need to stop the loop if that has
 				 * happened. */
-				if (!nl80211_drv_in_list(global, drv))
+				if (!nl80211_drv_in_list(global, unique_drv_id))
 					break;
 			}
 		}
diff --git a/src/drivers/nl80211_copy.h b/src/drivers/nl80211_copy.h
index f6c1b181..e9ccf43f 100644
--- a/src/drivers/nl80211_copy.h
+++ b/src/drivers/nl80211_copy.h
@@ -11,7 +11,7 @@
  * Copyright 2008 Jouni Malinen <jouni.malinen@atheros.com>
  * Copyright 2008 Colin McCabe <colin@cozybit.com>
  * Copyright 2015-2017	Intel Deutschland GmbH
- * Copyright (C) 2018-2024 Intel Corporation
+ * Copyright (C) 2018-2025 Intel Corporation
  *
  * Permission to use, copy, modify, and/or distribute this software for any
  * purpose with or without fee is hereby granted, provided that the above
@@ -2881,9 +2881,9 @@ enum nl80211_commands {
  * @NL80211_ATTR_VIF_RADIO_MASK: Bitmask of allowed radios (u32).
  *	A value of 0 means all radios.
  *
- * @NL80211_ATTR_SUPPORTED_SELECTORS: supported selectors, array of
- *	supported selectors as defined by IEEE 802.11 7.3.2.2 but without the
- *	length restriction (at most %NL80211_MAX_SUPP_SELECTORS).
+ * @NL80211_ATTR_SUPPORTED_SELECTORS: supported BSS Membership Selectors, array
+ *	of supported selectors as defined by IEEE Std 802.11-2020 9.4.2.3 but
+ *	without the length restriction (at most %NL80211_MAX_SUPP_SELECTORS).
  *	This can be used to provide a list of selectors that are implemented
  *	by the supplicant. If not given, support for SAE_H2E is assumed.
  *
@@ -2893,6 +2893,12 @@ enum nl80211_commands {
  * @NL80211_ATTR_EPCS: Flag attribute indicating that EPCS is enabled for a
  *	station interface.
  *
+ * @NL80211_ATTR_ASSOC_MLD_EXT_CAPA_OPS: Extended MLD capabilities and
+ *	operations that userspace implements to use during association/ML
+ *	link reconfig, currently only "BTM MLD Recommendation For Multiple
+ *	APs Support". Drivers may set additional flags that they support
+ *	in the kernel or device.
+ *
  * @NUM_NL80211_ATTR: total number of nl80211_attrs available
  * @NL80211_ATTR_MAX: highest attribute number currently defined
  * @__NL80211_ATTR_AFTER_LAST: internal use
@@ -3448,6 +3454,8 @@ enum nl80211_attrs {
 	NL80211_ATTR_MLO_RECONF_REM_LINKS,
 	NL80211_ATTR_EPCS,
 
+	NL80211_ATTR_ASSOC_MLD_EXT_CAPA_OPS,
+
 	/* add attributes here, update the policy in nl80211.c */
 
 	__NL80211_ATTR_AFTER_LAST,
@@ -4327,6 +4335,8 @@ enum nl80211_wmm_rule {
  *	otherwise completely disabled.
  * @NL80211_FREQUENCY_ATTR_ALLOW_6GHZ_VLP_AP: This channel can be used for a
  *	very low power (VLP) AP, despite being NO_IR.
+ * @NL80211_FREQUENCY_ATTR_ALLOW_20MHZ_ACTIVITY: This channel can be active in
+ *	20 MHz bandwidth, despite being NO_IR.
  * @NL80211_FREQUENCY_ATTR_MAX: highest frequency attribute number
  *	currently defined
  * @__NL80211_FREQUENCY_ATTR_AFTER_LAST: internal use
@@ -4371,6 +4381,7 @@ enum nl80211_frequency_attr {
 	NL80211_FREQUENCY_ATTR_NO_6GHZ_AFC_CLIENT,
 	NL80211_FREQUENCY_ATTR_CAN_MONITOR,
 	NL80211_FREQUENCY_ATTR_ALLOW_6GHZ_VLP_AP,
+	NL80211_FREQUENCY_ATTR_ALLOW_20MHZ_ACTIVITY,
 
 	/* keep last */
 	__NL80211_FREQUENCY_ATTR_AFTER_LAST,
@@ -4582,31 +4593,34 @@ enum nl80211_sched_scan_match_attr {
  * @NL80211_RRF_NO_6GHZ_AFC_CLIENT: Client connection to AFC AP not allowed
  * @NL80211_RRF_ALLOW_6GHZ_VLP_AP: Very low power (VLP) AP can be permitted
  *	despite NO_IR configuration.
+ * @NL80211_RRF_ALLOW_20MHZ_ACTIVITY: Allow activity in 20 MHz bandwidth,
+ *	despite NO_IR configuration.
  */
 enum nl80211_reg_rule_flags {
-	NL80211_RRF_NO_OFDM		= 1<<0,
-	NL80211_RRF_NO_CCK		= 1<<1,
-	NL80211_RRF_NO_INDOOR		= 1<<2,
-	NL80211_RRF_NO_OUTDOOR		= 1<<3,
-	NL80211_RRF_DFS			= 1<<4,
-	NL80211_RRF_PTP_ONLY		= 1<<5,
-	NL80211_RRF_PTMP_ONLY		= 1<<6,
-	NL80211_RRF_NO_IR		= 1<<7,
-	__NL80211_RRF_NO_IBSS		= 1<<8,
-	NL80211_RRF_AUTO_BW		= 1<<11,
-	NL80211_RRF_IR_CONCURRENT	= 1<<12,
-	NL80211_RRF_NO_HT40MINUS	= 1<<13,
-	NL80211_RRF_NO_HT40PLUS		= 1<<14,
-	NL80211_RRF_NO_80MHZ		= 1<<15,
-	NL80211_RRF_NO_160MHZ		= 1<<16,
-	NL80211_RRF_NO_HE		= 1<<17,
-	NL80211_RRF_NO_320MHZ		= 1<<18,
-	NL80211_RRF_NO_EHT		= 1<<19,
-	NL80211_RRF_PSD			= 1<<20,
-	NL80211_RRF_DFS_CONCURRENT	= 1<<21,
-	NL80211_RRF_NO_6GHZ_VLP_CLIENT	= 1<<22,
-	NL80211_RRF_NO_6GHZ_AFC_CLIENT	= 1<<23,
-	NL80211_RRF_ALLOW_6GHZ_VLP_AP	= 1<<24,
+	NL80211_RRF_NO_OFDM                 = 1 << 0,
+	NL80211_RRF_NO_CCK                  = 1 << 1,
+	NL80211_RRF_NO_INDOOR               = 1 << 2,
+	NL80211_RRF_NO_OUTDOOR              = 1 << 3,
+	NL80211_RRF_DFS                     = 1 << 4,
+	NL80211_RRF_PTP_ONLY                = 1 << 5,
+	NL80211_RRF_PTMP_ONLY               = 1 << 6,
+	NL80211_RRF_NO_IR                   = 1 << 7,
+	__NL80211_RRF_NO_IBSS               = 1 << 8,
+	NL80211_RRF_AUTO_BW                 = 1 << 11,
+	NL80211_RRF_IR_CONCURRENT           = 1 << 12,
+	NL80211_RRF_NO_HT40MINUS            = 1 << 13,
+	NL80211_RRF_NO_HT40PLUS             = 1 << 14,
+	NL80211_RRF_NO_80MHZ                = 1 << 15,
+	NL80211_RRF_NO_160MHZ               = 1 << 16,
+	NL80211_RRF_NO_HE                   = 1 << 17,
+	NL80211_RRF_NO_320MHZ               = 1 << 18,
+	NL80211_RRF_NO_EHT                  = 1 << 19,
+	NL80211_RRF_PSD                     = 1 << 20,
+	NL80211_RRF_DFS_CONCURRENT          = 1 << 21,
+	NL80211_RRF_NO_6GHZ_VLP_CLIENT      = 1 << 22,
+	NL80211_RRF_NO_6GHZ_AFC_CLIENT      = 1 << 23,
+	NL80211_RRF_ALLOW_6GHZ_VLP_AP       = 1 << 24,
+	NL80211_RRF_ALLOW_20MHZ_ACTIVITY    = 1 << 25,
 };
 
 #define NL80211_RRF_PASSIVE_SCAN	NL80211_RRF_NO_IR
@@ -4727,8 +4741,8 @@ enum nl80211_survey_info {
  * @NL80211_MNTR_FLAG_PLCPFAIL: pass frames with bad PLCP
  * @NL80211_MNTR_FLAG_CONTROL: pass control frames
  * @NL80211_MNTR_FLAG_OTHER_BSS: disable BSSID filtering
- * @NL80211_MNTR_FLAG_COOK_FRAMES: report frames after processing.
- *	overrides all other flags.
+ * @NL80211_MNTR_FLAG_COOK_FRAMES: deprecated
+ *	will unconditionally be refused
  * @NL80211_MNTR_FLAG_ACTIVE: use the configured MAC address
  *	and ACK incoming unicast packets.
  * @NL80211_MNTR_FLAG_SKIP_TX: do not pass local tx packets
@@ -8022,6 +8036,11 @@ enum nl80211_sar_specs_attrs {
  *	Setting this flag is permitted only if the driver advertises EMA support
  *	by setting wiphy->ema_max_profile_periodicity to non-zero.
  *
+ * @NL80211_MBSSID_CONFIG_ATTR_TX_LINK_ID: Link ID of the transmitted profile.
+ *	This parameter is mandatory when NL80211_ATTR_MBSSID_CONFIG attributes
+ *	are sent for a non-transmitted profile and if the transmitted profile
+ *	is part of an MLD. For all other cases this parameter is unnecessary.
+ *
  * @__NL80211_MBSSID_CONFIG_ATTR_LAST: Internal
  * @NL80211_MBSSID_CONFIG_ATTR_MAX: highest attribute
  */
@@ -8033,6 +8052,7 @@ enum nl80211_mbssid_config_attributes {
 	NL80211_MBSSID_CONFIG_ATTR_INDEX,
 	NL80211_MBSSID_CONFIG_ATTR_TX_IFINDEX,
 	NL80211_MBSSID_CONFIG_ATTR_EMA,
+	NL80211_MBSSID_CONFIG_ATTR_TX_LINK_ID,
 
 	/* keep last */
 	__NL80211_MBSSID_CONFIG_ATTR_LAST,
diff --git a/src/p2p/p2p.c b/src/p2p/p2p.c
index 4503830c..97fe16d8 100644
--- a/src/p2p/p2p.c
+++ b/src/p2p/p2p.c
@@ -6468,6 +6468,10 @@ void p2p_pasn_initialize(struct p2p_data *p2p, struct p2p_device *dev,
 					 dev->password);
 	} else if (verify) {
 		pasn->akmp = WPA_KEY_MGMT_SAE;
+		if (p2p->cfg->set_pmksa)
+			p2p->cfg->set_pmksa(p2p->cfg->cb_ctx,
+					    dev->info.p2p_device_addr,
+					    dev->info.dik_id);
 	} else {
 		pasn->akmp = WPA_KEY_MGMT_PASN;
 	}
@@ -6789,6 +6793,12 @@ static int p2p_pasn_handle_action_wrapper(struct p2p_data *p2p,
 					      msg.dira_len)) {
 				struct wpa_ie_data rsn_data;
 
+				if (p2p->cfg->set_pmksa)
+					p2p->cfg->set_pmksa(
+						p2p->cfg->cb_ctx,
+						dev->info.p2p_device_addr,
+						dev->info.dik_id);
+
 				if (wpa_parse_wpa_ie_rsn(elems.rsn_ie - 2,
 							 elems.rsn_ie_len + 2,
 							 &rsn_data) == 0 &&
@@ -7270,8 +7280,11 @@ int p2p_pasn_auth_rx(struct p2p_data *p2p, const struct ieee80211_mgmt *mgmt,
 	}
 
 	if (!dev->pasn) {
-		p2p_dbg(p2p, "PASN: Uninitialized");
-		return -1;
+		dev->pasn = pasn_data_init();
+		if (!dev->pasn) {
+			p2p_dbg(p2p, "PASN: Uninitialized");
+			return -1;
+		}
 	}
 
 	pasn = dev->pasn;
diff --git a/src/p2p/p2p.h b/src/p2p/p2p.h
index db70fd64..02d5bebd 100644
--- a/src/p2p/p2p.h
+++ b/src/p2p/p2p.h
@@ -1385,14 +1385,24 @@ struct p2p_config {
 	 * @dira_tag: DIRA Tag
 	 * Returns: Identity block ID on success, 0 on failure
 	 *
-	 * This function can be used to validate DIRA and configure PMK of a
-	 * paired/persistent peer from configuration. The handler function is
-	 * expected to call p2p_pasn_pmksa_set_pmk() to set the PMK/PMKID in
-	 * case a matching entry is found.
+	 * This function can be used to validate DIRA.
 	 */
 	int (*validate_dira)(void *ctx, const u8 *peer_addr,
 			     const u8 *dira_nonce, const u8 *dira_tag);
 
+	/**
+	 * set_pmksa - Configure PMK of a paired/persistent peer from
+	 *	configuration
+	 * @ctx: Callback context from cb_ctx
+	 * @peer_addr: P2P Device address of the peer
+	 * @dik_id: Identity block ID
+	 * Returns: 0 on success
+	 *
+	 * It is expected to call p2p_pasn_pmksa_set_pmk() to set the PMK/PMKID
+	 * for given dik_id.
+	 */
+	int (*set_pmksa)(void *ctx, const u8 *peer_addr, int dik_id);
+
 	/**
 	 * pasn_send_mgmt - Function handler to transmit a Management frame
 	 * @ctx: Callback context from cb_ctx
diff --git a/src/p2p/p2p_pd.c b/src/p2p/p2p_pd.c
index f08fa0e1..b0f893e7 100644
--- a/src/p2p/p2p_pd.c
+++ b/src/p2p/p2p_pd.c
@@ -1713,7 +1713,8 @@ static void p2p_process_prov_disc_bootstrap_resp(struct p2p_data *p2p,
 
 		if (p2p->cfg->bootstrap_rsp_rx)
 			p2p->cfg->bootstrap_rsp_rx(p2p->cfg->cb_ctx, sa, status,
-						   rx_freq, bootstrap);
+						   rx_freq,
+						   dev->req_bootstrap_method);
 		return;
 	}
 
@@ -1721,13 +1722,35 @@ static void p2p_process_prov_disc_bootstrap_resp(struct p2p_data *p2p,
 	if (msg->pbma_info_len >= 2)
 		bootstrap = WPA_GET_LE16(msg->pbma_info);
 
+	/* Overwrite the status if bootstrap method does not match */
+	if (status == P2P_SC_SUCCESS &&
+	    !(bootstrap == P2P_PBMA_PIN_CODE_DISPLAY &&
+	      dev->req_bootstrap_method == P2P_PBMA_PIN_CODE_KEYPAD) &&
+	    !(bootstrap == P2P_PBMA_PIN_CODE_KEYPAD &&
+	      dev->req_bootstrap_method == P2P_PBMA_PIN_CODE_DISPLAY) &&
+	    !(bootstrap == P2P_PBMA_PASSPHRASE_DISPLAY &&
+	      dev->req_bootstrap_method == P2P_PBMA_PASSPHRASE_KEYPAD) &&
+	    !(bootstrap == P2P_PBMA_PASSPHRASE_KEYPAD &&
+	      dev->req_bootstrap_method == P2P_PBMA_PASSPHRASE_DISPLAY) &&
+	    !(bootstrap == P2P_PBMA_NFC_TAG &&
+	      dev->req_bootstrap_method == P2P_PBMA_NFC_READER) &&
+	    !(bootstrap == P2P_PBMA_NFC_READER &&
+	      dev->req_bootstrap_method == P2P_PBMA_NFC_TAG) &&
+	    !(bootstrap == P2P_PBMA_QR_DISPLAY &&
+	      dev->req_bootstrap_method == P2P_PBMA_QR_SCAN) &&
+	    !(bootstrap == P2P_PBMA_QR_SCAN &&
+	      dev->req_bootstrap_method == P2P_PBMA_QR_DISPLAY) &&
+	    !(bootstrap == P2P_PBMA_OPPORTUNISTIC &&
+	      dev->req_bootstrap_method == P2P_PBMA_OPPORTUNISTIC))
+		status = P2P_SC_FAIL_INVALID_PARAMS;
+
 	p2p->cfg->send_action_done(p2p->cfg->cb_ctx);
 	if (dev->flags & P2P_DEV_PD_BEFORE_GO_NEG)
 		dev->flags &= ~P2P_DEV_PD_BEFORE_GO_NEG;
 
 	if (p2p->cfg->bootstrap_rsp_rx)
 		p2p->cfg->bootstrap_rsp_rx(p2p->cfg->cb_ctx, sa, status,
-					   rx_freq, bootstrap);
+					   rx_freq, dev->req_bootstrap_method);
 }
 
 
diff --git a/src/utils/common.c b/src/utils/common.c
index d62dec72..eb5a68b4 100644
--- a/src/utils/common.c
+++ b/src/utils/common.c
@@ -990,7 +990,7 @@ void int_array_add_unique(int **res, int a)
 }
 
 
-bool int_array_includes(int *arr, int val)
+bool int_array_includes(const int *arr, int val)
 {
 	int i;
 
@@ -1003,6 +1003,28 @@ bool int_array_includes(int *arr, int val)
 }
 
 
+bool int_array_equal(const int *a, const int *b)
+{
+	size_t alen, blen, i;
+
+	if (!a || !b)
+		return false;
+
+	alen = int_array_len(a);
+	blen = int_array_len(b);
+
+	if (alen != blen)
+		return false;
+
+	for (i = 0; i <= alen; i++) {
+		if (!int_array_includes(b, a[i]))
+			return false;
+	}
+
+	return true;
+}
+
+
 void str_clear_free(char *str)
 {
 	if (str) {
diff --git a/src/utils/common.h b/src/utils/common.h
index 3deb2046..d22cd615 100644
--- a/src/utils/common.h
+++ b/src/utils/common.h
@@ -595,7 +595,8 @@ size_t int_array_len(const int *a);
 void int_array_concat(int **res, const int *a);
 void int_array_sort_unique(int *a);
 void int_array_add_unique(int **res, int a);
-bool int_array_includes(int *arr, int val);
+bool int_array_includes(const int *arr, int val);
+bool int_array_equal(const int *a, const int *b);
 
 #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
 
diff --git a/wpa_supplicant/Android.bp b/wpa_supplicant/Android.bp
index cf902a1b..0911d052 100644
--- a/wpa_supplicant/Android.bp
+++ b/wpa_supplicant/Android.bp
@@ -1267,6 +1267,9 @@ cc_defaults {
 cc_binary {
     name: "wpa_cli",
     proprietary: true,
+    cflags: [
+        "-DCONFIG_NAN_USD",
+    ],
     srcs: [
         "wpa_cli.c",
         "src/common/cli.c",
@@ -1348,6 +1351,7 @@ wpa_supplicant_cc_binary {
             init_rc: ["aidl/vendor/android.hardware.wifi.supplicant-service.rc"],
         },
     },
+    vintf_fragment_modules: ["android.hardware.wifi.supplicant.xml"],
 }
 
 wpa_supplicant_cc_binary {
@@ -1527,6 +1531,19 @@ cc_library_static {
     ],
 }
 
+// wpa_supplicant.conf was previously generated by including wpa_supplicant_conf.mk
+// in an Android.mk file. The new approach will be to use the 'wpa_supplicant_conf_gen'
+// genrule below.
+genrule {
+    name: "wpa_supplicant_conf_gen",
+    srcs: [
+        "wpa_supplicant_conf.sh",
+        "wpa_supplicant_template.conf",
+    ],
+    cmd: "bash $(location wpa_supplicant_conf.sh) $(location wpa_supplicant_template.conf) > $(out)",
+    out: ["wpa_supplicant.conf"],
+}
+
 // End of non-cuttlefish section
 
 genrule {
diff --git a/wpa_supplicant/aidl/mainline/fuzzers/mainline_supplicant_service_fuzzer.cpp b/wpa_supplicant/aidl/mainline/fuzzers/mainline_supplicant_service_fuzzer.cpp
index 23b16adc..f23a9fbc 100644
--- a/wpa_supplicant/aidl/mainline/fuzzers/mainline_supplicant_service_fuzzer.cpp
+++ b/wpa_supplicant/aidl/mainline/fuzzers/mainline_supplicant_service_fuzzer.cpp
@@ -31,15 +31,11 @@ using namespace android;
 using ndk::SharedRefBase;
 
 extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
-    struct wpa_params params;
-    os_memset(&params, 0, sizeof(params));
-    params.wpa_debug_level = MSG_INFO;
-
-    struct wpa_global *global = wpa_supplicant_init(&params);
-    if (global == NULL) {
-        return 1;
-    }
-
+    // The wpa_global pointer will usually be initialized by wpa_supplicant_init().
+    // However, wpa_supplicant_init cannot be called from the fuzzer, since it seems
+    // to initialize a separate thread. For now, we can pass a nullptr to indicate that
+    // core supplicant has not been initialized.
+    struct wpa_global *global = nullptr;
     std::shared_ptr<MainlineSupplicant> service = SharedRefBase::make<MainlineSupplicant>(global);
     fuzzService(service->asBinder().get(), FuzzedDataProvider(data, size));
     return 0;
diff --git a/wpa_supplicant/aidl/mainline/mainline_supplicant.cpp b/wpa_supplicant/aidl/mainline/mainline_supplicant.cpp
index ff5c3881..c0282e0b 100644
--- a/wpa_supplicant/aidl/mainline/mainline_supplicant.cpp
+++ b/wpa_supplicant/aidl/mainline/mainline_supplicant.cpp
@@ -96,3 +96,13 @@ ndk::ScopedAStatus MainlineSupplicant::terminate() {
     wpa_supplicant_terminate_proc(wpa_global_);
     return ndk::ScopedAStatus::ok();
 }
+
+ndk::ScopedAStatus MainlineSupplicant::setDebugParams(
+        IMainlineSupplicant::DebugLevel level, bool showKeys) {
+    if (wpa_supplicant_set_debug_params(
+            wpa_global_, static_cast<uint32_t>(level),
+            false /* showTimestamp */, showKeys)) {
+        return createStatus(SupplicantStatusCode::FAILURE_UNKNOWN);
+    }
+    return ndk::ScopedAStatus::ok();
+}
diff --git a/wpa_supplicant/aidl/mainline/mainline_supplicant.h b/wpa_supplicant/aidl/mainline/mainline_supplicant.h
index fea7c733..fc1d792e 100644
--- a/wpa_supplicant/aidl/mainline/mainline_supplicant.h
+++ b/wpa_supplicant/aidl/mainline/mainline_supplicant.h
@@ -37,6 +37,7 @@ class MainlineSupplicant : public BnMainlineSupplicant {
             std::shared_ptr<IStaInterface>* _aidl_return);
         ndk::ScopedAStatus removeStaInterface(const std::string& ifaceName);
         ndk::ScopedAStatus terminate();
+        ndk::ScopedAStatus setDebugParams(IMainlineSupplicant::DebugLevel level, bool showKeys);
 
     private:
         // Raw pointer to the global structure maintained by the core
diff --git a/wpa_supplicant/aidl/vendor/aidl.cpp b/wpa_supplicant/aidl/vendor/aidl.cpp
index 462e1181..67995eee 100644
--- a/wpa_supplicant/aidl/vendor/aidl.cpp
+++ b/wpa_supplicant/aidl/vendor/aidl.cpp
@@ -1247,3 +1247,20 @@ void wpas_aidl_notify_p2p_bootstrap_response(
 		wpa_s, dev_addr, false, convert_p2p_status_code_to_p2p_prov_disc_status(status),
 		WPS_NOT_READY, 0, group_ifname, bootstrap_method);
 }
+
+void wpas_aidl_notify_auth_status_code(struct wpa_supplicant *wpa_s,
+	u16 auth_type, u16 auth_transaction, u16 status_code)
+{
+	if (!wpa_s)
+		return;
+
+	AidlManager *aidl_manager = AidlManager::getInstance();
+	if (!aidl_manager)
+		return;
+
+	wpa_printf(MSG_DEBUG,
+		"Notifying auth type: %d transaction id: %d status code: %d to aidl control ",
+		auth_type, auth_transaction, status_code);
+
+	aidl_manager->notifyAuthStatusCode(wpa_s, auth_type, auth_transaction, status_code);
+}
diff --git a/wpa_supplicant/aidl/vendor/aidl.h b/wpa_supplicant/aidl/vendor/aidl.h
index 039c6e10..f67e18a6 100644
--- a/wpa_supplicant/aidl/vendor/aidl.h
+++ b/wpa_supplicant/aidl/vendor/aidl.h
@@ -178,6 +178,8 @@ extern "C"
 		int publish_id, enum nan_de_reason reason);
 	void wpas_aidl_notify_usd_subscribe_terminated(struct wpa_supplicant *wpa_s,
 		int subscribe_id, enum nan_de_reason reason);
+	void wpas_aidl_notify_auth_status_code(struct wpa_supplicant *wpa_s,
+		u16 auth_type, u16 auth_transaction, u16 status_code);
 #else   // CONFIG_CTRL_IFACE_AIDL
 static inline int wpas_aidl_register_interface(struct wpa_supplicant *wpa_s)
 {
@@ -401,6 +403,8 @@ static void wpas_aidl_notify_usd_publish_terminated(struct wpa_supplicant *wpa_s
 		int publish_id, enum nan_de_reason reason) {}
 static void wpas_aidl_notify_usd_subscribe_terminated(struct wpa_supplicant *wpa_s,
 		int subscribe_id, enum nan_de_reason reason) {}
+static void wpas_aidl_notify_auth_status_code(struct wpa_supplicant *wpa_s,
+		u16 auth_type, u16 auth_transaction, u16 status_code) {}
 #endif  // CONFIG_CTRL_IFACE_AIDL
 
 #ifdef _cplusplus
diff --git a/wpa_supplicant/aidl/vendor/aidl_manager.cpp b/wpa_supplicant/aidl/vendor/aidl_manager.cpp
index ec895a03..68e1e6f4 100644
--- a/wpa_supplicant/aidl/vendor/aidl_manager.cpp
+++ b/wpa_supplicant/aidl/vendor/aidl_manager.cpp
@@ -1388,6 +1388,7 @@ void AidlManager::notifyP2pDeviceFound(
 
 	if (areAidlServiceAndClientAtLeastVersion(3)) {
 		P2pDeviceFoundEventParams params;
+		P2pDirInfo dirInfo;
 		params.srcAddress = macAddrToArray(addr);
 		params.p2pDeviceAddress = macAddrToArray(info->p2p_device_addr);
 		params.primaryDeviceType = byteArrToVec(info->pri_dev_type, 8);
@@ -1402,11 +1403,12 @@ void AidlManager::notifyP2pDeviceFound(
 			params.pairingBootstrappingMethods = convertP2pPairingBootstrappingMethodsToAidl(
 				info->pairing_config.bootstrap_methods);
 			if (info->nonce_tag_valid) {
-				params.dirInfo->cipherVersion =
+				dirInfo.cipherVersion =
 					P2pDirInfo::CipherVersion::DIRA_CIPHER_VERSION_128_BIT;
-				params.dirInfo->deviceInterfaceMacAddress = macAddrToArray(info->p2p_device_addr);
-				params.dirInfo->nonce = byteArrToVec(info->nonce, DEVICE_IDENTITY_NONCE_LEN);
-				params.dirInfo->dirTag = byteArrToVec(info->tag, DEVICE_IDENTITY_TAG_LEN);
+				dirInfo.deviceInterfaceMacAddress = macAddrToArray(info->p2p_device_addr);
+				dirInfo.nonce = byteArrToVec(info->nonce, DEVICE_IDENTITY_NONCE_LEN);
+				dirInfo.dirTag = byteArrToVec(info->tag, DEVICE_IDENTITY_TAG_LEN);
+				params.dirInfo = dirInfo;
 			}
 		}
 		callWithEachP2pIfaceCallback(
@@ -3173,6 +3175,32 @@ void AidlManager::notifyUsdSubscribeTerminated(struct wpa_supplicant *wpa_s,
 	}
 }
 
+void AidlManager::notifyAuthStatusCode(struct wpa_supplicant *wpa_s,
+		u16 auth_type, u16 auth_transaction, u16 status_code)
+{
+	if (!wpa_s) return;
+	std::string aidl_ifname = misc_utils::charBufToString(wpa_s->ifname);
+	AssociationRejectionData aidl_assoc_reject_data{};
+
+	// TODO If needed, expand for other authentication failures.
+	if (wpa_s->drv_flags & WPA_DRIVER_FLAGS_SME && auth_type == WLAN_AUTH_SAE
+			&& auth_transaction == 2 && status_code != WLAN_STATUS_SUCCESS) {
+		if (wpa_s->current_ssid) {
+			aidl_assoc_reject_data.ssid = std::vector<uint8_t>(
+				wpa_s->current_ssid->ssid,
+				wpa_s->current_ssid->ssid + wpa_s->current_ssid->ssid_len);
+		}
+		aidl_assoc_reject_data.bssid = macAddrToVec(wpa_s->pending_bssid);
+		aidl_assoc_reject_data.statusCode = static_cast<StaIfaceStatusCode>(status_code);
+		const std::function<
+			ndk::ScopedAStatus(std::shared_ptr<ISupplicantStaIfaceCallback>)>
+			func = std::bind(
+			&ISupplicantStaIfaceCallback::onAssociationRejected,
+			std::placeholders::_1, aidl_assoc_reject_data);
+			callWithEachStaIfaceCallback(aidl_ifname, func);
+	}
+}
+
 }  // namespace supplicant
 }  // namespace wifi
 }  // namespace hardware
diff --git a/wpa_supplicant/aidl/vendor/aidl_manager.h b/wpa_supplicant/aidl/vendor/aidl_manager.h
index 3c187899..9d09a392 100644
--- a/wpa_supplicant/aidl/vendor/aidl_manager.h
+++ b/wpa_supplicant/aidl/vendor/aidl_manager.h
@@ -193,6 +193,8 @@ public:
 			int publish_id, enum nan_de_reason reason);
 	void notifyUsdSubscribeTerminated(struct wpa_supplicant *wpa_s,
 			int subscribe_id, enum nan_de_reason reason);
+	void notifyAuthStatusCode(struct wpa_supplicant *wpa_s,
+			u16 auth_type, u16 auth_transaction, u16 status_code);
 
 	// Methods called from aidl objects.
 	int32_t isAidlServiceVersionAtLeast(int32_t expected_version);
diff --git a/wpa_supplicant/aidl/vendor/android.hardware.wifi.supplicant-service.rc b/wpa_supplicant/aidl/vendor/android.hardware.wifi.supplicant-service.rc
index 807d2d39..a8a09da0 100644
--- a/wpa_supplicant/aidl/vendor/android.hardware.wifi.supplicant-service.rc
+++ b/wpa_supplicant/aidl/vendor/android.hardware.wifi.supplicant-service.rc
@@ -1,13 +1,11 @@
 service wpa_supplicant /vendor/bin/hw/wpa_supplicant \
 	-O/data/vendor/wifi/wpa/sockets -dd \
 	-g@android:wpa_wlan0
-	#   we will start as root and wpa_supplicant will switch to user wifi
-	#   after setting up the capabilities required for WEXT
-	#   user wifi
-	#   group wifi inet keystore
 	interface aidl android.hardware.wifi.supplicant.ISupplicant/default
 	class main
 	socket wpa_wlan0 dgram 660 wifi wifi
-	user root
+	user wifi
+	group wifi net_raw net_admin
+	capabilities NET_RAW NET_ADMIN
 	disabled
 	oneshot
diff --git a/wpa_supplicant/aidl/vendor/p2p_iface.cpp b/wpa_supplicant/aidl/vendor/p2p_iface.cpp
index cbdf3426..6decebab 100644
--- a/wpa_supplicant/aidl/vendor/p2p_iface.cpp
+++ b/wpa_supplicant/aidl/vendor/p2p_iface.cpp
@@ -1192,7 +1192,7 @@ std::pair<std::string, ndk::ScopedAStatus> P2pIface::connectInternal(
 		}
 		p2p2 = true;
 		pairing_password = password.length() > 0 ? password.data() : nullptr;
-		if (authorize) {
+		if (authorize && !group_ifname.empty()) {
 			auto_join = 1;
 		}
 	}
@@ -1205,7 +1205,7 @@ std::pair<std::string, ndk::ScopedAStatus> P2pIface::connectInternal(
 		pre_selected_pin.length() > 0 ? pre_selected_pin.data() : nullptr;
 	int new_pin = wpas_p2p_connect(
 		wpa_s, peer_address.data(), pin, wps_method, persistent, auto_join,
-		join_existing_group, authorize, go_intent_signed, 0, 0, -1, false, ht40,
+		join_existing_group, authorize, go_intent_signed, frequency, 0, -1, false, ht40,
 		vht, CONF_OPER_CHWIDTH_USE_HT, he, edmg, nullptr, 0, is6GhzAllowed(wpa_s),
 		p2p2, bootstrap, pairing_password, skip_prov);
 	if (new_pin < 0) {
@@ -2135,10 +2135,6 @@ ndk::ScopedAStatus P2pIface::createGroupOwnerInternal(
 
 std::pair<int64_t, ndk::ScopedAStatus> P2pIface::getFeatureSetInternal()
 {
-	// By default, core supplicant enable WFD R2 and PCC mode for all drivers.
-	// TODO Enable this code once core supplicant implement the configuration flag
-	// to enable/disable the feature for all driver implementations.
-#if 0
 	int64_t featureSet = 0;
 	struct wpa_supplicant* wpa_s = retrieveIfacePtr();
 
@@ -2149,9 +2145,6 @@ std::pair<int64_t, ndk::ScopedAStatus> P2pIface::getFeatureSetInternal()
 		featureSet |= ISupplicantP2pIface::P2P_FEATURE_PCC_MODE_WPA3_COMPATIBILITY;
 	}
 	return {featureSet, ndk::ScopedAStatus::ok()};
-#else
-	return {0, ndk::ScopedAStatus::ok()};
-#endif
 }
 
 std::pair<uint32_t, ndk::ScopedAStatus>
@@ -2166,9 +2159,9 @@ P2pIface::startUsdBasedServiceDiscoveryInternal(
 
 	os_memset(&params, 0, sizeof(params));
 
-	if (serviceDiscoveryConfig.serviceSpecificInfo.size() > 0) {
-		auto ssiBuffer = misc_utils::convertVectorToWpaBuf(
+	auto ssiBuffer = misc_utils::convertVectorToWpaBuf(
 			serviceDiscoveryConfig.serviceSpecificInfo);
+	if (serviceDiscoveryConfig.serviceSpecificInfo.size() > 0) {
 		if (ssiBuffer && ssiBuffer.get() != nullptr) {
 			service_specific_info = ssiBuffer.get();
 		}
@@ -2177,23 +2170,20 @@ P2pIface::startUsdBasedServiceDiscoveryInternal(
 	params.active = true;
 	params.ttl = serviceDiscoveryConfig.timeoutInSeconds;
 	params.query_period = DEFAULT_QUERY_PERIOD_MS;
+	params.freq = NAN_USD_DEFAULT_FREQ;
 	if (serviceDiscoveryConfig.bandMask != 0) {
 		// TODO convert band to channel instead of scanning all channel frequencies.
 		params.freq_list = wpas_nan_usd_all_freqs(wpa_s);
-	} else {
-		if (serviceDiscoveryConfig.frequencyListMhz.size() != 0) {
-			params.freq_list = serviceDiscoveryConfig.frequencyListMhz.data();
-		} else {
-			params.freq = NAN_USD_DEFAULT_FREQ;
-		}
+	} else if (serviceDiscoveryConfig.frequencyListMhz.size() != 0) {
+		params.freq = serviceDiscoveryConfig.frequencyListMhz.front();
+		if (serviceDiscoveryConfig.frequencyListMhz.size() > 1)
+			params.freq_list = serviceDiscoveryConfig.frequencyListMhz.data() + 1;
 	}
 	sessionId = wpas_nan_usd_subscribe(wpa_s, serviceDiscoveryConfig.serviceName.c_str(),
 					      (enum nan_service_protocol_type)
 						  serviceDiscoveryConfig.serviceProtocolType,
 						  service_specific_info, &params, true);
-	if (service_specific_info != NULL) {
-		freeWpaBuf(service_specific_info);
-	}
+
 	if (sessionId > 0) {
 		return {sessionId, ndk::ScopedAStatus::ok()};
 	}
@@ -2225,9 +2215,9 @@ P2pIface::startUsdBasedServiceAdvertisementInternal(
 	struct wpabuf *service_specific_info = NULL;
 	os_memset(&params, 0, sizeof(params));
 
-	if (serviceAdvertisementConfig.serviceSpecificInfo.size() > 0) {
-		auto ssiBuffer = misc_utils::convertVectorToWpaBuf(
+	auto ssiBuffer = misc_utils::convertVectorToWpaBuf(
 			serviceAdvertisementConfig.serviceSpecificInfo);
+	if (serviceAdvertisementConfig.serviceSpecificInfo.size() > 0) {
 		if (ssiBuffer && ssiBuffer.get() != nullptr) {
 			service_specific_info = ssiBuffer.get();
 		}
@@ -2240,9 +2230,7 @@ P2pIface::startUsdBasedServiceAdvertisementInternal(
 					      (enum nan_service_protocol_type)
 						  serviceAdvertisementConfig.serviceProtocolType,
 						  service_specific_info, &params, true);
-	if (service_specific_info != NULL) {
-		freeWpaBuf(service_specific_info);
-	}
+
 	if (sessionId > 0) {
 		return {sessionId, ndk::ScopedAStatus::ok()};
 	}
diff --git a/wpa_supplicant/aidl/vendor/sta_network.cpp b/wpa_supplicant/aidl/vendor/sta_network.cpp
index f373e713..a38af2d0 100644
--- a/wpa_supplicant/aidl/vendor/sta_network.cpp
+++ b/wpa_supplicant/aidl/vendor/sta_network.cpp
@@ -2679,10 +2679,6 @@ ndk::ScopedAStatus StaNetwork::setMinimumTlsVersionEapPhase1ParamInternal(TlsVer
 	if (tlsVersion < TlsVersion::TLS_V1_0 || tlsVersion > TlsVersion::TLS_V1_3) {
 		return createStatus(SupplicantStatusCode::FAILURE_ARGS_INVALID);
 	}
-	if (tlsVersion == TlsVersion::TLS_V1_0) {
-		// no restriction
-		return ndk::ScopedAStatus::ok();
-	}
 
 	if (tlsVersion < TlsVersion::TLS_V1_3 && (tlsFlags & TLS_CONN_SUITEB)) {
 		// TLS configuration already set up for WPA3-Enterprise 192-bit mode
@@ -2705,6 +2701,9 @@ ndk::ScopedAStatus StaNetwork::setMinimumTlsVersionEapPhase1ParamInternal(TlsVer
 		case TlsVersion::TLS_V1_1:
 			tlsFlags |= TLS_CONN_DISABLE_TLSv1_0;
 			break;
+		case TlsVersion::TLS_V1_0:
+			// no restriction
+			break;
 		default:
 			return createStatus(SupplicantStatusCode::FAILURE_UNSUPPORTED);
 	}
diff --git a/wpa_supplicant/bss.c b/wpa_supplicant/bss.c
index 0afac49e..58adaf74 100644
--- a/wpa_supplicant/bss.c
+++ b/wpa_supplicant/bss.c
@@ -1711,6 +1711,82 @@ wpa_bss_parse_ml_rnr_ap_info(struct wpa_supplicant *wpa_s,
 }
 
 
+/**
+ * wpa_bss_validate_rsne_ml - Validate RSN IEs (RSNE/RSNOE/RSNO2E) of a BSS
+ * @wpa_s: Pointer to wpa_supplicant data
+ * @ssid: Network config
+ * @bss: BSS table entry
+ * Returns: true if the BSS configuration matches local profile and the elements
+ * meet MLO requirements, false otherwise
+ * @key_mgmt: Pointer to store key management
+ * @rsne_type_p: Type of RSNE to validate. If -1 is given, choose as per the
+ *	presence of RSN elements (association link); otherwise, validate
+ *	against the requested type (other affiliated links).
+ */
+static bool
+wpa_bss_validate_rsne_ml(struct wpa_supplicant *wpa_s, struct wpa_ssid *ssid,
+			 struct wpa_bss *bss, int *key_mgmt, int *rsne_type_p)
+{
+	struct ieee802_11_elems elems;
+	struct wpa_ie_data wpa_ie;
+	const u8 *rsne;
+	size_t rsne_len;
+	int rsne_type;
+	const u8 *ies_pos = wpa_bss_ie_ptr(bss);
+	size_t ies_len = bss->ie_len ? bss->ie_len : bss->beacon_ie_len;
+
+	if (ieee802_11_parse_elems(ies_pos, ies_len, &elems, 0) ==
+	    ParseFailed) {
+		wpa_dbg(wpa_s, MSG_DEBUG, "MLD: Failed to parse elements");
+		return false;
+	}
+
+	if (elems.rsne_override_2 && wpas_rsn_overriding(wpa_s, ssid)) {
+		rsne = elems.rsne_override_2;
+		rsne_len = elems.rsne_override_2_len;
+		rsne_type = 2;
+	} else if (elems.rsne_override && wpas_rsn_overriding(wpa_s, ssid)) {
+		rsne = elems.rsne_override;
+		rsne_len = elems.rsne_override_len;
+		rsne_type = 1;
+	} else {
+		rsne = elems.rsn_ie;
+		rsne_len = elems.rsn_ie_len;
+		rsne_type = 0;
+	}
+
+	if (!rsne ||
+	    wpa_parse_wpa_ie(rsne - 2, 2 + rsne_len, &wpa_ie)) {
+		wpa_dbg(wpa_s, MSG_DEBUG, "MLD: No RSN element");
+		return false;
+	}
+
+	if (*rsne_type_p != -1 && *rsne_type_p != rsne_type) {
+		wpa_dbg(wpa_s, MSG_DEBUG,
+			"MLD: No matching RSN element (RSNO mismatch)");
+		return false;
+	}
+
+	if (!(wpa_ie.capabilities & WPA_CAPABILITY_MFPC) ||
+	    wpas_get_ssid_pmf(wpa_s, ssid) == NO_MGMT_FRAME_PROTECTION) {
+		wpa_dbg(wpa_s, MSG_DEBUG,
+			"MLD: No management frame protection");
+		return false;
+	}
+
+	wpa_ie.key_mgmt &= ~(WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_FT_PSK |
+			     WPA_KEY_MGMT_PSK_SHA256);
+	wpa_dbg(wpa_s, MSG_DEBUG, "MLD: key_mgmt=0x%x", wpa_ie.key_mgmt);
+
+	if (key_mgmt)
+		*key_mgmt = wpa_ie.key_mgmt;
+
+	*rsne_type_p = rsne_type;
+
+	return !!(wpa_ie.key_mgmt & ssid->key_mgmt);
+}
+
+
 /**
  * wpa_bss_parse_basic_ml_element - Parse the Basic Multi-Link element
  * @wpa_s: Pointer to wpa_supplicant data
@@ -1757,8 +1833,9 @@ int wpa_bss_parse_basic_ml_element(struct wpa_supplicant *wpa_s,
 	u16 seen;
 	const u8 *ies_pos = wpa_bss_ie_ptr(bss);
 	size_t ies_len = bss->ie_len ? bss->ie_len : bss->beacon_ie_len;
-	int ret = -1;
+	int ret = -1, rsne_type, key_mgmt;
 	struct mld_link *l;
+	u16 valid_links;
 
 	if (ieee802_11_parse_elems(ies_pos, ies_len, &elems, 1) ==
 	    ParseFailed) {
@@ -1774,42 +1851,12 @@ int wpa_bss_parse_basic_ml_element(struct wpa_supplicant *wpa_s,
 
 	ml_ie_len = wpabuf_len(mlbuf);
 
-	if (ssid) {
-		struct wpa_ie_data ie;
-		const u8 *rsne;
-		size_t rsne_len;
-
-		if (elems.rsne_override_2 && wpas_rsn_overriding(wpa_s, ssid)) {
-			rsne = elems.rsne_override_2;
-			rsne_len = elems.rsne_override_2_len;
-		} else if (elems.rsne_override &&
-			   wpas_rsn_overriding(wpa_s, ssid)) {
-			rsne = elems.rsne_override;
-			rsne_len = elems.rsne_override_len;
-		} else {
-			rsne = elems.rsn_ie;
-			rsne_len = elems.rsn_ie_len;
-		}
-		if (!rsne ||
-		    wpa_parse_wpa_ie(rsne - 2, 2 + rsne_len, &ie)) {
-			wpa_dbg(wpa_s, MSG_DEBUG, "MLD: No RSN element");
-			goto out;
-		}
-
-		if (!(ie.capabilities & WPA_CAPABILITY_MFPC) ||
-		    wpas_get_ssid_pmf(wpa_s, ssid) == NO_MGMT_FRAME_PROTECTION) {
-			wpa_dbg(wpa_s, MSG_DEBUG,
-				"MLD: No management frame protection");
-			goto out;
-		}
-
-		ie.key_mgmt &= ~(WPA_KEY_MGMT_PSK | WPA_KEY_MGMT_FT_PSK |
-				 WPA_KEY_MGMT_PSK_SHA256);
-		if (!(ie.key_mgmt & ssid->key_mgmt)) {
-			wpa_dbg(wpa_s, MSG_DEBUG,
-				"MLD: No valid key management");
-			goto out;
-		}
+	rsne_type = -1;
+	if (ssid &&
+	    !wpa_bss_validate_rsne_ml(wpa_s, ssid, bss, &key_mgmt,
+				      &rsne_type)) {
+		wpa_dbg(wpa_s, MSG_DEBUG, "MLD: No valid key management");
+		goto out;
 	}
 
 	/*
@@ -1901,6 +1948,44 @@ int wpa_bss_parse_basic_ml_element(struct wpa_supplicant *wpa_s,
 	wpa_printf(MSG_DEBUG, "MLD: valid_links=%04hx (unresolved: 0x%04hx)",
 		   bss->valid_links, missing);
 
+	valid_links = bss->valid_links;
+	for_each_link(bss->valid_links, i) {
+		struct wpa_bss *neigh_bss;
+		int neigh_key_mgmt;
+
+		if (!ssid)
+			break;
+
+		if (i == link_id)
+			continue;
+
+		neigh_bss = wpa_bss_get_bssid(wpa_s, bss->mld_links[i].bssid);
+		if (!neigh_bss) /* cannot be NULL at this point */
+			continue;
+
+		/* As per IEEE P802.11be/D7.0, 12.6.2 (RSNA selection), all APs
+		 * affiliated with an AP MLD shall advertise at least one common
+		 * AKM suite selector in the AKM Suite List field of an RSNE or
+		 * RSNXE. Discard links that do not have compatibility
+		 * configuration with the association link.
+		 */
+		if (!wpa_bss_validate_rsne_ml(wpa_s, ssid, neigh_bss,
+					      &neigh_key_mgmt, &rsne_type) ||
+		    !(key_mgmt & neigh_key_mgmt)) {
+			wpa_printf(MSG_DEBUG,
+				   "MLD: Discard link %u due to RSN parameter mismatch",
+				   i);
+			valid_links &= ~BIT(i);
+			continue;
+		}
+	}
+
+	if (valid_links != bss->valid_links) {
+		wpa_printf(MSG_DEBUG, "MLD: Updated valid links=%04hx",
+			   valid_links);
+		bss->valid_links = valid_links;
+	}
+
 	for_each_link(bss->valid_links, i) {
 		wpa_printf(MSG_DEBUG, "MLD: link=%u, bssid=" MACSTR,
 			   i, MAC2STR(bss->mld_links[i].bssid));
@@ -1979,7 +2064,19 @@ u16 wpa_bss_parse_reconf_ml_element(struct wpa_supplicant *wpa_s,
 	len -= sizeof(*ml) + common_info->len;
 
 	while (len >= 2 + sizeof(struct ieee80211_eht_per_sta_profile)) {
-		size_t sub_elem_len = *(pos + 1);
+		size_t sub_elem_len;
+		int num_frag_subelems;
+
+		num_frag_subelems =
+			ieee802_11_defrag_mle_subelem(mlbuf, pos,
+						      &sub_elem_len);
+		if (num_frag_subelems < 0) {
+			wpa_printf(MSG_DEBUG,
+				   "MLD: Failed to parse MLE subelem");
+			break;
+		}
+
+		len -= num_frag_subelems * 2;
 
 		if (2 + sub_elem_len > len) {
 			wpa_printf(MSG_DEBUG,
diff --git a/wpa_supplicant/config_file.c b/wpa_supplicant/config_file.c
index 57bfbeda..2d01cbea 100644
--- a/wpa_supplicant/config_file.c
+++ b/wpa_supplicant/config_file.c
@@ -866,8 +866,8 @@ static void wpa_config_write_network(FILE *f, struct wpa_ssid *ssid)
 	INT_DEFe(sim_num, sim_num, DEFAULT_USER_SELECTED_SIM);
 #endif /* IEEE8021X_EAPOL */
 	INT(mode);
-	INT(no_auto_peer);
 #ifdef CONFIG_MESH
+	INT(no_auto_peer);
 	INT_DEF(mesh_fwding, DEFAULT_MESH_FWDING);
 #endif /* CONFIG_MESH */
 	INT(frequency);
diff --git a/wpa_supplicant/ctrl_iface.c b/wpa_supplicant/ctrl_iface.c
index 94fcec50..4fbcc60f 100644
--- a/wpa_supplicant/ctrl_iface.c
+++ b/wpa_supplicant/ctrl_iface.c
@@ -825,6 +825,23 @@ static int wpa_supplicant_ctrl_iface_set(struct wpa_supplicant *wpa_s,
 			wpa_s->rsnxe_override_eapol = NULL;
 		else
 			wpa_s->rsnxe_override_eapol = wpabuf_parse_bin(value);
+	} else if (os_strcasecmp(cmd, "link_ies") == 0) {
+		int link_id = atoi(value);
+		char *pos;
+
+		if (link_id < 0 || link_id >= MAX_NUM_MLD_LINKS)
+			return -1;
+
+		pos = os_strchr(value, ':');
+		if (!pos)
+			return -1;
+		pos++;
+
+		wpabuf_free(wpa_s->link_ies[link_id]);
+		if (os_strcmp(value, "NULL") == 0)
+			wpa_s->link_ies[link_id] = NULL;
+		else
+			wpa_s->link_ies[link_id] = wpabuf_parse_bin(pos);
 	} else if (os_strcasecmp(cmd, "reject_btm_req_reason") == 0) {
 		wpa_s->reject_btm_req_reason = atoi(value);
 	} else if (os_strcasecmp(cmd, "get_pref_freq_list_override") == 0) {
@@ -7348,7 +7365,18 @@ static int p2p_ctrl_group_add(struct wpa_supplicant *wpa_s, char *cmd)
 
 #ifdef CONFIG_ACS
 	if ((wpa_s->drv_flags & WPA_DRIVER_FLAGS_ACS_OFFLOAD) &&
-	    (acs || freq == 2 || freq == 5)) {
+	    (freq == 2 || freq == 5)) {
+		unsigned int res, size = P2P_MAX_PREF_CHANNELS;
+		struct weighted_pcl pref_freq_list[P2P_MAX_PREF_CHANNELS];
+
+		acs = 1;
+		res = wpa_drv_get_pref_freq_list(wpa_s, WPA_IF_P2P_GO,
+						 &size, pref_freq_list);
+		if (!res && size > 0)
+			acs = 0;
+	}
+
+	if ((wpa_s->drv_flags & WPA_DRIVER_FLAGS_ACS_OFFLOAD) && acs) {
 		if (freq == 2 && wpa_s->best_24_freq <= 0) {
 			wpa_s->p2p_go_acs_band = HOSTAPD_MODE_IEEE80211G;
 			wpa_s->p2p_go_do_acs = 1;
@@ -9042,6 +9070,14 @@ static void wpa_supplicant_ctrl_iface_flush(struct wpa_supplicant *wpa_s)
 	wpabuf_free(wpa_s->rsnxe_override_eapol);
 	wpa_s->rsnxe_override_eapol = NULL;
 	wpas_clear_driver_signal_override(wpa_s);
+	{
+		int i;
+
+		for (i = 0; i < MAX_NUM_MLD_LINKS; i++) {
+			wpabuf_free(wpa_s->link_ies[i]);
+			wpa_s->link_ies[i] = NULL;
+		}
+	}
 #ifndef CONFIG_NO_ROBUST_AV
 	wpa_s->disable_scs_support = 0;
 	wpa_s->disable_mscs_support = 0;
@@ -10747,7 +10783,7 @@ static void wpas_ctrl_neighbor_rep_cb(void *ctx, struct wpabuf *neighbor_rep)
 	const u8 *data;
 
 	/*
-	 * Neighbor Report element (IEEE P802.11-REVmc/D5.0)
+	 * Neighbor Report element (IEEE Std 802.11-2024, 9.4.2.35)
 	 * BSSID[6]
 	 * BSSID Information[4]
 	 * Operating Class[1]
diff --git a/wpa_supplicant/dbus/dbus_new.c b/wpa_supplicant/dbus/dbus_new.c
index 7893f356..0c5cfdf4 100644
--- a/wpa_supplicant/dbus/dbus_new.c
+++ b/wpa_supplicant/dbus/dbus_new.c
@@ -2390,7 +2390,7 @@ void wpas_dbus_signal_p2p_bootstrap_req(struct wpa_supplicant *wpa_s,
  * @wpa_s: %wpa_supplicant network interface data
  * @src: Source address of the peer with which bootstrapping is done
  * @status: Status of Bootstrapping handshake
- * @bootstrap_method: Peer's bootstrap method if status is success
+ * @bootstrap_method: Local device requested bootstrap method
  *
  * Sends a signal to notify that a peer P2P Device is requesting bootstrapping
  * negotiation with us.
diff --git a/wpa_supplicant/dbus/dbus_new_handlers.c b/wpa_supplicant/dbus/dbus_new_handlers.c
index e43bf833..e212235c 100644
--- a/wpa_supplicant/dbus/dbus_new_handlers.c
+++ b/wpa_supplicant/dbus/dbus_new_handlers.c
@@ -5801,7 +5801,6 @@ dbus_bool_t wpas_dbus_getter_bss_anqp(
 	struct bss_handler_args *args = user_data;
 	struct wpa_bss *bss;
 	struct wpa_bss_anqp *anqp;
-	struct wpa_bss_anqp_elem *elem;
 
 	bss = get_bss_helper(args, error, __func__);
 	if (!bss)
@@ -5815,6 +5814,8 @@ dbus_bool_t wpas_dbus_getter_bss_anqp(
 	anqp = bss->anqp;
 	if (anqp) {
 #ifdef CONFIG_INTERWORKING
+		struct wpa_bss_anqp_elem *elem;
+
 		if (anqp->capability_list &&
 		    !wpa_dbus_dict_append_byte_array(
 			    &iter_dict, "CapabilityList",
diff --git a/wpa_supplicant/dpp_supplicant.c b/wpa_supplicant/dpp_supplicant.c
index 70f7a3ba..5b4b8fa1 100644
--- a/wpa_supplicant/dpp_supplicant.c
+++ b/wpa_supplicant/dpp_supplicant.c
@@ -5805,6 +5805,7 @@ int wpas_dpp_push_button(struct wpa_supplicant *wpa_s, const char *cmd)
 		   "DPP: Scan to create channel list for PB discovery");
 	wpa_s->scan_req = MANUAL_SCAN_REQ;
 	wpa_s->scan_res_handler = wpas_dpp_pb_scan_res_handler;
+	wpa_supplicant_cancel_sched_scan(wpa_s);
 	wpa_supplicant_req_scan(wpa_s, 0, 0);
 	wpa_msg(wpa_s, MSG_INFO, DPP_EVENT_PB_STATUS "started");
 	return 0;
diff --git a/wpa_supplicant/events.c b/wpa_supplicant/events.c
index 68089563..7779ed94 100644
--- a/wpa_supplicant/events.c
+++ b/wpa_supplicant/events.c
@@ -345,12 +345,16 @@ void wpa_supplicant_stop_countermeasures(void *eloop_ctx, void *sock_ctx)
 
 void wpas_reset_mlo_info(struct wpa_supplicant *wpa_s)
 {
+	int i;
+
 	if (!wpa_s->valid_links)
 		return;
 
 	wpa_s->valid_links = 0;
 	wpa_s->mlo_assoc_link_id = 0;
 	os_memset(wpa_s->ap_mld_addr, 0, ETH_ALEN);
+	for (i = 0; i < MAX_NUM_MLD_LINKS; i++)
+		wpabuf_free(wpa_s->links[i].ies);
 	os_memset(wpa_s->links, 0, sizeof(wpa_s->links));
 }
 
@@ -2871,6 +2875,20 @@ static int wpas_select_network_from_last_scan(struct wpa_supplicant *wpa_s,
 }
 
 
+static bool equal_scan_freq_list(struct wpa_supplicant *self,
+				 struct wpa_supplicant *other)
+{
+	const int *list1, *list2;
+
+	list1 = self->conf->freq_list ? self->conf->freq_list :
+		self->last_scan_freqs;
+	list2 = other->conf->freq_list ? other->conf->freq_list :
+		other->last_scan_freqs;
+
+	return int_array_equal(list1, list2);
+}
+
+
 static int wpa_supplicant_event_scan_results(struct wpa_supplicant *wpa_s,
 					     union wpa_event_data *data)
 {
@@ -2898,12 +2916,19 @@ static int wpa_supplicant_event_scan_results(struct wpa_supplicant *wpa_s,
 	}
 
 	/*
-	 * Check other interfaces to see if they share the same radio. If
-	 * so, they get updated with this same scan info.
+	 * Manual scan requests are more specific to a use case than the
+	 * normal scan requests; hence, skip updating sibling radios.
+	 */
+	if (wpa_s->last_scan_req == MANUAL_SCAN_REQ)
+		return 0;
+
+	/*
+	 * Check other interfaces to see if they share the same radio and
+	 * frequency list. If so, they get updated with this same scan info.
 	 */
 	dl_list_for_each(ifs, &wpa_s->radio->ifaces, struct wpa_supplicant,
 			 radio_list) {
-		if (ifs != wpa_s) {
+		if (ifs != wpa_s && equal_scan_freq_list(wpa_s, ifs)) {
 			wpa_printf(MSG_DEBUG, "%s: Updating scan results from "
 				   "sibling", ifs->ifname);
 			res = _wpa_supplicant_event_scan_results(ifs, data, 0,
@@ -4097,17 +4122,28 @@ static unsigned int wpas_ml_parse_assoc(struct wpa_supplicant *wpa_s,
 	pos = ((u8 *) common_info) + common_info->len;
 	ml_len -= sizeof(*ml) + common_info->len;
 	while (ml_len > 2 && i < MAX_NUM_MLD_LINKS) {
-		u8 sub_elem_len = pos[1];
-		u8 sta_info_len, sta_info_len_min;
+		size_t sub_elem_len, sta_info_len, sta_info_len_min;
 		u8 nstr_bitmap_len = 0;
 		u16 ctrl;
 		const u8 *end;
+		int num_frag_subelems;
 
-		wpa_printf(MSG_DEBUG, "MLD: Subelement len=%u", sub_elem_len);
+		num_frag_subelems =
+			ieee802_11_defrag_mle_subelem(mlbuf, pos,
+						      &sub_elem_len);
+		if (num_frag_subelems < 0) {
+			wpa_printf(MSG_DEBUG,
+				   "MLD: Failed to parse MLE subelem");
+			goto out;
+		}
+
+		ml_len -= num_frag_subelems * 2;
+
+		wpa_printf(MSG_DEBUG, "MLD: Subelement len=%zu", sub_elem_len);
 
 		if (sub_elem_len > ml_len - 2) {
 			wpa_printf(MSG_DEBUG,
-				   "MLD: Invalid link info len: %u > %zu",
+				   "MLD: Invalid link info len: %zu > %zu",
 				   2 + sub_elem_len, ml_len);
 			goto out;
 		}
@@ -4118,7 +4154,7 @@ static unsigned int wpas_ml_parse_assoc(struct wpa_supplicant *wpa_s,
 		case EHT_ML_SUB_ELEM_FRAGMENT:
 		case EHT_ML_SUB_ELEM_VENDOR:
 			wpa_printf(MSG_DEBUG,
-				   "MLD: Skip subelement id=%u, len=%u",
+				   "MLD: Skip subelement id=%u, len=%zu",
 				   *pos, sub_elem_len);
 			pos += 2 + sub_elem_len;
 			ml_len -= 2 + sub_elem_len;
@@ -4189,11 +4225,12 @@ static unsigned int wpas_ml_parse_assoc(struct wpa_supplicant *wpa_s,
 
 		sta_info_len_min = 1 + ETH_ALEN + 8 + 2 + 2 + 1 +
 			nstr_bitmap_len;
-		if (sta_info_len_min > ml_len || sta_info_len_min > end - pos ||
+		if (sta_info_len_min > ml_len ||
+		    sta_info_len_min > (size_t) (end - pos) ||
 		    sta_info_len_min + 2 > sub_elem_len ||
 		    sta_info_len_min > *pos) {
 			wpa_printf(MSG_DEBUG,
-				   "MLD: Invalid STA info min len=%u, len=%u",
+				   "MLD: Invalid STA info min len=%zu, len=%u",
 				   sta_info_len_min, *pos);
 			goto out;
 		}
@@ -4214,7 +4251,7 @@ static unsigned int wpas_ml_parse_assoc(struct wpa_supplicant *wpa_s,
 		pos += sta_info_len;
 		ml_len -= sta_info_len;
 
-		wpa_printf(MSG_DEBUG, "MLD: sub_elem_len=%u, sta_info_len=%u",
+		wpa_printf(MSG_DEBUG, "MLD: sub_elem_len=%zu, sta_info_len=%zu",
 			   sub_elem_len, sta_info_len);
 
 		sub_elem_len -= sta_info_len + 2;
@@ -6356,9 +6393,10 @@ void wpa_supplicant_event(void *ctx, enum wpa_event_type event,
 			wpa_printf(MSG_DEBUG,
 				   "FST: MB IEs updated from auth IE");
 #endif /* CONFIG_FST */
-		sme_event_auth(wpa_s, data);
 		wpa_s->auth_status_code = data->auth.status_code;
-		wpas_notify_auth_status_code(wpa_s);
+		wpas_notify_auth_status_code(wpa_s, data->auth.auth_type,
+			data->auth.auth_transaction, data->auth.status_code);
+		sme_event_auth(wpa_s, data);
 		break;
 	case EVENT_ASSOC:
 #ifdef CONFIG_TESTING_OPTIONS
diff --git a/wpa_supplicant/mesh.c b/wpa_supplicant/mesh.c
index 869f0b39..297d644e 100644
--- a/wpa_supplicant/mesh.c
+++ b/wpa_supplicant/mesh.c
@@ -389,6 +389,8 @@ static int wpa_supplicant_mesh_init(struct wpa_supplicant *wpa_s,
 	int basic_rates_erp[] = { 10, 20, 55, 60, 110, 120, 240, -1 };
 	int rate_len;
 	int frequency;
+	bool is_dfs;
+	u8 chan;
 
 	if (!wpa_s->conf->user_mpm) {
 		/* not much for us to do here */
@@ -479,8 +481,35 @@ static int wpa_supplicant_mesh_init(struct wpa_supplicant *wpa_s,
 	bss->conf->ap_max_inactivity = wpa_s->conf->mesh_max_inactivity;
 	bss->conf->mesh_fwding = wpa_s->conf->mesh_fwding;
 
-	if (ieee80211_is_dfs(ssid->frequency, wpa_s->hw.modes,
-			     wpa_s->hw.num_modes) && wpa_s->conf->country[0]) {
+	ieee80211_freq_to_chan(freq->center_freq1, &chan);
+	if (wpa_s->mesh_vht_enabled) {
+		if (freq->bandwidth == 80)
+			conf->vht_oper_chwidth = CONF_OPER_CHWIDTH_80MHZ;
+		else if (freq->bandwidth == 160)
+			conf->vht_oper_chwidth = CONF_OPER_CHWIDTH_160MHZ;
+		conf->vht_oper_centr_freq_seg0_idx = chan;
+	}
+
+#ifdef CONFIG_IEEE80211AX
+	if (wpa_s->mesh_he_enabled) {
+		if (freq->bandwidth == 80)
+			conf->he_oper_chwidth = CONF_OPER_CHWIDTH_80MHZ;
+		else if (freq->bandwidth == 160)
+			conf->he_oper_chwidth = CONF_OPER_CHWIDTH_160MHZ;
+		conf->he_oper_centr_freq_seg0_idx = chan;
+	}
+#endif /* CONFIG_IEEE80211AX */
+
+	is_dfs = ieee80211_is_dfs(ssid->frequency, wpa_s->hw.modes,
+				  wpa_s->hw.num_modes);
+
+	/* Check if secondary 80 MHz of 160 MHz has DFS channels */
+	if (!is_dfs && freq->bandwidth == 160)
+		is_dfs = ieee80211_is_dfs(ssid->frequency + 80,
+					  wpa_s->hw.modes,
+					  wpa_s->hw.num_modes);
+
+	if (is_dfs && wpa_s->conf->country[0]) {
 		conf->ieee80211h = 1;
 		conf->ieee80211d = 1;
 		conf->country[0] = wpa_s->conf->country[0];
diff --git a/wpa_supplicant/nan_usd.c b/wpa_supplicant/nan_usd.c
index 946d62fb..b2d195ca 100644
--- a/wpa_supplicant/nan_usd.c
+++ b/wpa_supplicant/nan_usd.c
@@ -271,6 +271,15 @@ static void wpas_nan_de_publish_terminated(void *ctx, int publish_id,
 }
 
 
+static void wpas_nan_usd_offload_cancel_publish(void *ctx, int publish_id)
+{
+	struct wpa_supplicant *wpa_s = ctx;
+
+	if (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_OFFLOAD)
+		wpas_drv_nan_cancel_publish(wpa_s, publish_id);
+}
+
+
 static void wpas_nan_de_subscribe_terminated(void *ctx, int subscribe_id,
 					     enum nan_de_reason reason)
 {
@@ -280,6 +289,15 @@ static void wpas_nan_de_subscribe_terminated(void *ctx, int subscribe_id,
 }
 
 
+static void wpas_nan_usd_offload_cancel_subscribe(void *ctx, int subscribe_id)
+{
+	struct wpa_supplicant *wpa_s = ctx;
+
+	if (wpa_s->drv_flags2 & WPA_DRIVER_FLAGS2_NAN_OFFLOAD)
+		wpas_drv_nan_cancel_subscribe(wpa_s, subscribe_id);
+}
+
+
 static void wpas_nan_de_receive(void *ctx, int id, int peer_instance_id,
 				const u8 *ssi, size_t ssi_len,
 				const u8 *peer_addr)
@@ -316,6 +334,8 @@ int wpas_nan_usd_init(struct wpa_supplicant *wpa_s)
 	cb.replied = wpas_nan_de_replied;
 	cb.publish_terminated = wpas_nan_de_publish_terminated;
 	cb.subscribe_terminated = wpas_nan_de_subscribe_terminated;
+	cb.offload_cancel_publish = wpas_nan_usd_offload_cancel_publish;
+	cb.offload_cancel_subscribe = wpas_nan_usd_offload_cancel_subscribe;
 	cb.receive = wpas_nan_de_receive;
 #ifdef CONFIG_P2P
 	cb.process_p2p_usd_elems = wpas_nan_process_p2p_usd_elems;
diff --git a/wpa_supplicant/notify.c b/wpa_supplicant/notify.c
index aeff9656..113386cf 100644
--- a/wpa_supplicant/notify.c
+++ b/wpa_supplicant/notify.c
@@ -188,12 +188,16 @@ void wpas_notify_mlo_info_change_reason(struct wpa_supplicant *wpa_s,
 }
 
 
-void wpas_notify_auth_status_code(struct wpa_supplicant *wpa_s)
+void wpas_notify_auth_status_code(struct wpa_supplicant *wpa_s, u16 auth_type,
+					u16 auth_transaction, u16 status_code)
 {
 	if (wpa_s->p2p_mgmt)
 		return;
 
 	wpas_dbus_signal_prop_changed(wpa_s, WPAS_DBUS_PROP_AUTH_STATUS_CODE);
+
+	wpas_aidl_notify_auth_status_code(wpa_s, auth_type, auth_transaction,
+					  status_code);
 }
 
 
diff --git a/wpa_supplicant/notify.h b/wpa_supplicant/notify.h
index dc8ceaf9..ce99fd28 100644
--- a/wpa_supplicant/notify.h
+++ b/wpa_supplicant/notify.h
@@ -31,7 +31,8 @@ void wpas_notify_state_changed(struct wpa_supplicant *wpa_s,
 			       enum wpa_states new_state,
 			       enum wpa_states old_state);
 void wpas_notify_disconnect_reason(struct wpa_supplicant *wpa_s);
-void wpas_notify_auth_status_code(struct wpa_supplicant *wpa_s);
+void wpas_notify_auth_status_code(struct wpa_supplicant *wpa_s, u16 auth_type,
+				   u16 auth_transaction, u16 status_code);
 void wpas_notify_assoc_status_code(struct wpa_supplicant *wpa_s, const u8 *bssid, u8 timed_out,
 				   const u8 *assoc_resp_ie, size_t assoc_resp_ie_len);
 void wpas_notify_auth_timeout(struct wpa_supplicant *wpa_s);
diff --git a/wpa_supplicant/p2p_supplicant.c b/wpa_supplicant/p2p_supplicant.c
index f924ddec..7cb4bc64 100644
--- a/wpa_supplicant/p2p_supplicant.c
+++ b/wpa_supplicant/p2p_supplicant.c
@@ -2076,7 +2076,12 @@ static void wpas_start_gc(struct wpa_supplicant *wpa_s,
 		entry->network_ctx = ssid;
 		os_memcpy(entry->spa, wpa_s->own_addr, ETH_ALEN);
 
-		wpa_sm_pmksa_cache_add_entry(wpa_s->wpa, entry);
+		if (wpa_s->drv_flags & WPA_DRIVER_FLAGS_SME) {
+			wpa_sm_pmksa_cache_add_entry(wpa_s->wpa, entry);
+		} else {
+			os_free(wpa_s->p2p_pmksa_entry);
+			wpa_s->p2p_pmksa_entry = entry;
+		}
 		ssid->pmk_valid = true;
 	} else if (res->akmp == WPA_KEY_MGMT_SAE && res->sae_password[0]) {
 		ssid->auth_alg = WPA_AUTH_ALG_SAE;
@@ -5559,6 +5564,27 @@ static void wpas_bootstrap_rsp_rx(void *ctx, const u8 *addr,
 }
 
 
+static int wpas_set_pmksa(void *ctx, const u8 *peer_addr, int dik_id)
+{
+	struct wpa_supplicant *wpa_s = ctx;
+	struct wpa_dev_ik *ik;
+
+	for (ik = wpa_s->conf->identity; ik; ik = ik->next) {
+		if (ik->id == dik_id)
+			break;
+	}
+	if (!ik)
+		return -1;
+#ifdef CONFIG_PASN
+	p2p_pasn_pmksa_set_pmk(wpa_s->global->p2p, wpa_s->global->p2p_dev_addr,
+			       peer_addr,
+			       wpabuf_head(ik->pmk), wpabuf_len(ik->pmk),
+			       wpabuf_head(ik->pmkid));
+#endif /* CONFIG_PASN */
+	return 0;
+}
+
+
 static int wpas_validate_dira(void *ctx, const u8 *peer_addr,
 			      const u8 *dira_nonce, const u8 *dira_tag)
 {
@@ -5600,13 +5626,6 @@ static int wpas_validate_dira(void *ctx, const u8 *peer_addr,
 	if (!ik)
 		return 0;
 
-#ifdef CONFIG_PASN
-	p2p_pasn_pmksa_set_pmk(wpa_s->global->p2p, wpa_s->global->p2p_dev_addr,
-			       peer_addr,
-			       wpabuf_head(ik->pmk), wpabuf_len(ik->pmk),
-			       wpabuf_head(ik->pmkid));
-#endif /* CONFIG_PASN */
-
 	return ik->id;
 }
 
@@ -5836,6 +5855,7 @@ int wpas_p2p_init(struct wpa_global *global, struct wpa_supplicant *wpa_s)
 	p2p.bootstrap_req_rx = wpas_bootstrap_req_rx;
 	p2p.bootstrap_rsp_rx = wpas_bootstrap_rsp_rx;
 	p2p.validate_dira = wpas_validate_dira;
+	p2p.set_pmksa = wpas_set_pmksa;
 #ifdef CONFIG_PASN
 	p2p.pasn_send_mgmt = wpas_p2p_pasn_send_mgmt;
 	p2p.prepare_data_element = wpas_p2p_prepare_data_element;
@@ -5987,6 +6007,8 @@ int wpas_p2p_init(struct wpa_global *global, struct wpa_supplicant *wpa_s)
 
 	p2p.pairing_config.enable_pairing_setup =
 		wpa_s->conf->p2p_pairing_setup;
+	p2p.pairing_config.pairing_capable =
+		wpa_s->conf->p2p_pairing_setup;
 	p2p.pairing_config.enable_pairing_cache =
 		wpa_s->conf->p2p_pairing_cache;
 	p2p.pairing_config.bootstrap_methods =
@@ -7362,13 +7384,11 @@ int wpas_p2p_group_remove(struct wpa_supplicant *wpa_s, const char *ifname)
 
 static int wpas_p2p_select_go_freq(struct wpa_supplicant *wpa_s, int freq)
 {
-	unsigned int r;
+	unsigned int r, i, size = P2P_MAX_PREF_CHANNELS;
+	struct weighted_pcl pref_freq_list[P2P_MAX_PREF_CHANNELS];
+	int res = -1;
 
 	if (!wpa_s->conf->num_p2p_pref_chan && !freq) {
-		unsigned int i, size = P2P_MAX_PREF_CHANNELS;
-		struct weighted_pcl pref_freq_list[P2P_MAX_PREF_CHANNELS];
-		int res;
-
 		res = wpa_drv_get_pref_freq_list(wpa_s, WPA_IF_P2P_GO,
 						 &size, pref_freq_list);
 		if (!res && size > 0 && !is_p2p_allow_6ghz(wpa_s->global->p2p))
@@ -7404,6 +7424,13 @@ static int wpas_p2p_select_go_freq(struct wpa_supplicant *wpa_s, int freq)
 		}
 	}
 
+	if (freq == 2 || freq == 5 || freq == 6) {
+		res = wpa_drv_get_pref_freq_list(wpa_s, WPA_IF_P2P_GO,
+						 &size, pref_freq_list);
+		if (!res && size > 0 && !is_p2p_allow_6ghz(wpa_s->global->p2p))
+			size = p2p_remove_6ghz_channels(pref_freq_list, size);
+	}
+
 	if (freq == 2) {
 		wpa_printf(MSG_DEBUG, "P2P: Request to start GO on 2.4 GHz "
 			   "band");
@@ -7413,6 +7440,28 @@ static int wpas_p2p_select_go_freq(struct wpa_supplicant *wpa_s, int freq)
 			freq = wpa_s->best_24_freq;
 			wpa_printf(MSG_DEBUG, "P2P: Use best 2.4 GHz band "
 				   "channel: %d MHz", freq);
+		} else if (!res && size > 0) {
+			for (i = 0; i < size; i++) {
+				freq = pref_freq_list[i].freq;
+				if (is_24ghz_freq(freq) &&
+				    p2p_supported_freq(wpa_s->global->p2p,
+						       freq) &&
+				    !wpas_p2p_disallowed_freq(wpa_s->global,
+							      freq) &&
+				    p2p_pref_freq_allowed(&pref_freq_list[i],
+							  true))
+					break;
+			}
+
+			if (i >= size) {
+				wpa_printf(MSG_DEBUG,
+					   "P2P: Could not select 2.4 GHz channel for P2P group");
+				return -1;
+			}
+
+			wpa_printf(MSG_DEBUG,
+				   "P2P: Use preferred 2.4 GHz band channel: %d MHz",
+				   freq);
 		} else {
 			if (os_get_random((u8 *) &r, sizeof(r)) < 0)
 				return -1;
@@ -7449,6 +7498,27 @@ static int wpas_p2p_select_go_freq(struct wpa_supplicant *wpa_s, int freq)
 			freq = wpa_s->best_5_freq;
 			wpa_printf(MSG_DEBUG, "P2P: Use best 5 GHz band "
 				   "channel: %d MHz", freq);
+		} else if (!res && size > 0) {
+			for (i = 0; i < size; i++) {
+				freq = pref_freq_list[i].freq;
+				if (is_5ghz_freq(freq) &&
+				    p2p_supported_freq(wpa_s->global->p2p,
+						       freq) &&
+				    !wpas_p2p_disallowed_freq(wpa_s->global,
+							      freq) &&
+				    p2p_pref_freq_allowed(&pref_freq_list[i],
+							  true))
+					break;
+			}
+
+			if (i >= size) {
+				wpa_printf(MSG_DEBUG,
+					   "P2P: Could not select 5 GHz channel for P2P group");
+				return -1;
+			}
+			wpa_printf(MSG_DEBUG,
+				   "P2P: Use preferred 5 GHz band channel: %d MHz",
+				   freq);
 		} else {
 			const int freqs[] = {
 				/* operating class 115 */
@@ -7456,7 +7526,7 @@ static int wpas_p2p_select_go_freq(struct wpa_supplicant *wpa_s, int freq)
 				/* operating class 124 */
 				5745, 5765, 5785, 5805,
 			};
-			unsigned int i, num_freqs = ARRAY_SIZE(freqs);
+			unsigned int num_freqs = ARRAY_SIZE(freqs);
 
 			if (os_get_random((u8 *) &r, sizeof(r)) < 0)
 				return -1;
@@ -7493,6 +7563,36 @@ static int wpas_p2p_select_go_freq(struct wpa_supplicant *wpa_s, int freq)
 		}
 	}
 
+	if (freq == 6) {
+		wpa_printf(MSG_DEBUG, "P2P: Request to start GO on 6 GHz band");
+		if (!res && size > 0) {
+			for (i = 0; i < size; i++) {
+				freq = pref_freq_list[i].freq;
+				if (is_6ghz_freq(freq) &&
+				    p2p_supported_freq(wpa_s->global->p2p,
+						       freq) &&
+				    !wpas_p2p_disallowed_freq(wpa_s->global,
+							      freq) &&
+				    p2p_pref_freq_allowed(&pref_freq_list[i],
+							  true))
+					break;
+			}
+
+			if (i >= size) {
+				wpa_printf(MSG_DEBUG,
+					   "P2P: Could not select 6 GHz channel for P2P group");
+				return -1;
+			}
+
+			wpa_printf(MSG_DEBUG,
+				   "P2P: Use preferred 6 GHz band channel: %d MHz",
+				   freq);
+		} else {
+			wpa_printf(MSG_DEBUG,
+				   "P2P: No preferred 6 GHz channel available");
+		}
+	}
+
 	if (freq > 0 && !p2p_supported_freq_go(wpa_s->global->p2p, freq)) {
 		if ((wpa_s->drv_flags & WPA_DRIVER_FLAGS_DFS_OFFLOAD) &&
 		    ieee80211_is_dfs(freq, wpa_s->hw.modes,
@@ -8161,7 +8261,12 @@ static int wpas_start_p2p_client(struct wpa_supplicant *wpa_s,
 			entry->network_ctx = ssid;
 			os_memcpy(entry->spa, wpa_s->own_addr, ETH_ALEN);
 
-			wpa_sm_pmksa_cache_add_entry(wpa_s->wpa, entry);
+			if (wpa_s->drv_flags & WPA_DRIVER_FLAGS_SME) {
+				wpa_sm_pmksa_cache_add_entry(wpa_s->wpa, entry);
+			} else {
+				os_free(wpa_s->p2p_pmksa_entry);
+				wpa_s->p2p_pmksa_entry = entry;
+			}
 			ssid->pmk_valid = true;
 		}
 		wpa_s->current_ssid = ssid;
@@ -11575,6 +11680,10 @@ int wpas_p2p_pasn_auth_rx(struct wpa_supplicant *wpa_s,
 
 	if (wpa_s->global->p2p_disabled || !p2p)
 		return -2;
+
+	wpa_s->p2p2 = true;
+	if (wpa_s->p2p_mode == WPA_P2P_MODE_WFD_R1)
+		wpa_s->p2p_mode = WPA_P2P_MODE_WFD_R2;
 	return p2p_pasn_auth_rx(p2p, mgmt, len, freq);
 }
 
diff --git a/wpa_supplicant/p2p_supplicant.h b/wpa_supplicant/p2p_supplicant.h
index c5f2f9ca..140a2f75 100644
--- a/wpa_supplicant/p2p_supplicant.h
+++ b/wpa_supplicant/p2p_supplicant.h
@@ -374,7 +374,7 @@ static inline int wpas_p2p_group_remove(struct wpa_supplicant *wpa_s,
 }
 
 static inline struct wpabuf * wpas_p2p_usd_elems(struct wpa_supplicant *wpa_s,
-					const char *service_name)
+						 const char *service_name)
 {
 	return NULL;
 }
diff --git a/wpa_supplicant/rrm.c b/wpa_supplicant/rrm.c
index 2ec43105..88241e73 100644
--- a/wpa_supplicant/rrm.c
+++ b/wpa_supplicant/rrm.c
@@ -198,7 +198,8 @@ int wpas_rrm_send_neighbor_rep_request(struct wpa_supplicant *wpa_s,
 	}
 
 	if (lci) {
-		/* IEEE P802.11-REVmc/D5.0 9.4.2.21 */
+		/* IEEE Std 802.11-2024, 9.4.2.19 (Measurement Request element)
+		 */
 		wpabuf_put_u8(buf, WLAN_EID_MEASURE_REQUEST);
 		wpabuf_put_u8(buf, MEASURE_REQUEST_LCI_LEN);
 
@@ -215,13 +216,14 @@ int wpas_rrm_send_neighbor_rep_request(struct wpa_supplicant *wpa_s,
 		wpabuf_put_u8(buf, 0); /* Measurement Request Mode */
 		wpabuf_put_u8(buf, MEASURE_TYPE_LCI); /* Measurement Type */
 
-		/* IEEE P802.11-REVmc/D5.0 9.4.2.21.10 - LCI request */
+		/* IEEE Std 802.11-2024, 9.4.2.19.10 (LCI request) */
 		/* Location Subject */
 		wpabuf_put_u8(buf, LOCATION_SUBJECT_REMOTE);
 
 		/* Optional Subelements */
 		/*
-		 * IEEE P802.11-REVmc/D5.0 Figure 9-170
+		 * IEEE Std 802.11-2024, Figure 9-265 (Maximum Age subelement
+		 * format)
 		 * The Maximum Age subelement is required, otherwise the AP can
 		 * send only data that was determined after receiving the
 		 * request. Setting it here to unlimited age.
@@ -232,7 +234,8 @@ int wpas_rrm_send_neighbor_rep_request(struct wpa_supplicant *wpa_s,
 	}
 
 	if (civic) {
-		/* IEEE P802.11-REVmc/D5.0 9.4.2.21 */
+		/* IEEE Std 802.11-2024, 9.4.2.19 (Measurement Request element)
+		 */
 		wpabuf_put_u8(buf, WLAN_EID_MEASURE_REQUEST);
 		wpabuf_put_u8(buf, MEASURE_REQUEST_CIVIC_LEN);
 
@@ -250,8 +253,7 @@ int wpas_rrm_send_neighbor_rep_request(struct wpa_supplicant *wpa_s,
 		/* Measurement Type */
 		wpabuf_put_u8(buf, MEASURE_TYPE_LOCATION_CIVIC);
 
-		/* IEEE P802.11-REVmc/D5.0 9.4.2.21.14:
-		 * Location Civic request */
+		/* IEEE Std 802.11-2024, 9.4.2.19.14 (Location Civic request) */
 		/* Location Subject */
 		wpabuf_put_u8(buf, LOCATION_SUBJECT_REMOTE);
 		wpabuf_put_u8(buf, 0); /* Civic Location Type: IETF RFC 4776 */
diff --git a/wpa_supplicant/scan.c b/wpa_supplicant/scan.c
index ccedcc95..a4824678 100644
--- a/wpa_supplicant/scan.c
+++ b/wpa_supplicant/scan.c
@@ -2802,6 +2802,138 @@ static const struct minsnr_bitrate_entry he160_table[] = {
 	{ -1, 1441200 }  /* SNR > 51 */
 };
 
+/* See IEEE P802.11be/D7.0, Table 36-78 - EHT-MCSs for 484+242-tone MRU,
+ * NSS,u = 1
+ */
+static const struct minsnr_bitrate_entry eht60_table[] = {
+	{ 0, 0 },
+	{ 8, 25800 },   /* EHT80 with 20 MHz punctured MCS0 */
+	{ 11, 51600 },  /* EHT80 with 20 MHz punctured MCS1 */
+	{ 15, 77400 },  /* EHT80 with 20 MHz punctured MCS2 */
+	{ 17, 103200 }, /* EHT80 with 20 MHz punctured MCS3 */
+	{ 21, 154900 }, /* EHT80 with 20 MHz punctured MCS4 */
+	{ 24, 206500 }, /* EHT80 with 20 MHz punctured MCS5 */
+	{ 26, 232300 }, /* EHT80 with 20 MHz punctured MCS6 */
+	{ 31, 258100 }, /* EHT80 with 20 MHz punctured MCS7 */
+	{ 35, 309700 }, /* EHT80 with 20 MHz punctured MCS8 */
+	{ 37, 344100 }, /* EHT80 with 20 MHz punctured MCS9 */
+	{ 40, 387100 }, /* EHT80 with 20 MHz punctured MCS10 */
+	{ 42, 430100 }, /* EHT80 with 20 MHz punctured MCS11 */
+	{ 45, 464600 }, /* EHT80 with 20 MHz punctured MCS12 */
+	{ 48, 516200 }, /* EHT80 with 20 MHz punctured MCS13 */
+	{ -1, 516200 }  /* SNR > 48 */
+};
+
+/* See IEEE P802.11be/D7.0, Table 36-80 - EHT-MCSs for 996+484-tone MRU,
+ * NSS,u = 1
+ */
+static const struct minsnr_bitrate_entry eht120_table[] = {
+	{ 0, 0 },
+	{ 11, 53200 },   /* EHT160 with 40 MHz punctured MCS0 */
+	{ 14, 106500 },  /* EHT160 with 40 MHz punctured MCS1 */
+	{ 18, 159700 },  /* EHT160 with 40 MHz punctured MCS2 */
+	{ 20, 212900 },  /* EHT160 with 40 MHz punctured MCS3 */
+	{ 24, 319400 },  /* EHT160 with 40 MHz punctured MCS4 */
+	{ 27, 425900 },  /* EHT160 with 40 MHz punctured MCS5 */
+	{ 29, 479100 },  /* EHT160 with 40 MHz punctured MCS6 */
+	{ 34, 532400 },  /* EHT160 with 40 MHz punctured MCS7 */
+	{ 38, 638800 },  /* EHT160 with 40 MHz punctured MCS8 */
+	{ 40, 709800 },  /* EHT160 with 40 MHz punctured MCS9 */
+	{ 43, 798500 },  /* EHT160 with 40 MHz punctured MCS10 */
+	{ 45, 887200 },  /* EHT160 with 40 MHz punctured MCS11 */
+	{ 48, 958200 },  /* EHT160 with 40 MHz punctured MCS12 */
+	{ 51, 1064700 }, /* EHT160 with 40 MHz punctured MCS13 */
+	{ -1, 1064700 }  /* SNR > 51 */
+};
+
+/* See IEEE P802.11be/D7.0, Table 36-81 - EHT-MCSs for 996+484+242-tone MRU,
+ * NSS,u = 1
+ */
+static const struct minsnr_bitrate_entry eht140_table[] = {
+	{ 0, 0 },
+	{ 11, 61800 },   /* EHT160 with 20 MHz punctured MCS0 */
+	{ 14, 123700 },  /* EHT160 with 20 MHz punctured MCS1 */
+	{ 18, 185500 },  /* EHT160 with 20 MHz punctured MCS2 */
+	{ 20, 247400 },  /* EHT160 with 20 MHz punctured MCS3 */
+	{ 24, 371000 },  /* EHT160 with 20 MHz punctured MCS4 */
+	{ 27, 494700 },  /* EHT160 with 20 MHz punctured MCS5 */
+	{ 29, 556500 },  /* EHT160 with 20 MHz punctured MCS6 */
+	{ 34, 618400 },  /* EHT160 with 20 MHz punctured MCS7 */
+	{ 38, 742100 },  /* EHT160 with 20 MHz punctured MCS8 */
+	{ 40, 824500 },  /* EHT160 with 20 MHz punctured MCS9 */
+	{ 43, 927600 },  /* EHT160 with 20 MHz punctured MCS10 */
+	{ 45, 1030600 }, /* EHT160 with 20 MHz punctured MCS11 */
+	{ 48, 1113100 }, /* EHT160 with 20 MHz punctured MCS12 */
+	{ 51, 1236800 }, /* EHT160 with 20 MHz punctured MCS13 */
+	{ -1, 1236800 }  /* SNR > 51 */
+};
+
+/* See IEEE P802.11be/D7.0, Table 36-83 - EHT-MCSs for 2x996+484-tone NRU,
+ * NSS,u = 1
+ */
+static const struct minsnr_bitrate_entry eht200_table[] = {
+	{ 0, 0 },
+	{ 14, 89300 },    /* EHT320 with 120 MHz punctured MCS0 */
+	{ 17, 178500 },   /* EHT320 with 120 MHz punctured MCS1 */
+	{ 21, 267800 },   /* EHT320 with 120 MHz punctured MCS2 */
+	{ 23, 357100 },   /* EHT320 with 120 MHz punctured MCS3 */
+	{ 27, 535600 },   /* EHT320 with 120 MHz punctured MCS4 */
+	{ 30, 714100 },   /* EHT320 with 120 MHz punctured MCS5 */
+	{ 32, 803400 },   /* EHT320 with 120 MHz punctured MCS6 */
+	{ 37, 892600 },   /* EHT320 with 120 MHz punctured MCS7 */
+	{ 41, 1071200 },  /* EHT320 with 120 MHz punctured MCS8 */
+	{ 43, 1190100 },  /* EHT320 with 120 MHz punctured MCS9 */
+	{ 46, 1339000 },  /* EHT320 with 120 MHz punctured MCS10 */
+	{ 48, 1487700 },  /* EHT320 with 120 MHz punctured MCS11 */
+	{ 51, 1606800 },  /* EHT320 with 120 MHz punctured MCS12 */
+	{ 54, 1785300 },  /* EHT320 with 120 MHz punctured MCS13 */
+	{ -1, 1785300 }   /* SNR > 54 */
+};
+
+/* See IEEE P802.11be/D7.0, Table 36-84 - EHT-MCSs for 3x996-tone MRU,
+ * NSS,u = 1
+ */
+static const struct minsnr_bitrate_entry eht240_table[] = {
+	{ 0, 0 },
+	{ 14, 108100 },   /* EHT320 with 80 MHz punctured MCS0 */
+	{ 17, 216200 },   /* EHT320 with 80 MHz punctured MCS1 */
+	{ 21, 324300 },   /* EHT320 with 80 MHz punctured MCS2 */
+	{ 23, 432400 },   /* EHT320 with 80 MHz punctured MCS3 */
+	{ 27, 648500 },   /* EHT320 with 80 MHz punctured MCS4 */
+	{ 30, 864700 },   /* EHT320 with 80 MHz punctured MCS5 */
+	{ 32, 972800 },   /* EHT320 with 80 MHz punctured MCS6 */
+	{ 37, 1080900 },  /* EHT320 with 80 MHz punctured MCS7 */
+	{ 41, 1297100 },  /* EHT320 with 80 MHz punctured MCS8 */
+	{ 43, 1441200 },  /* EHT320 with 80 MHz punctured MCS9 */
+	{ 46, 1621300 },  /* EHT320 with 80 MHz punctured MCS10 */
+	{ 48, 1801500 },  /* EHT320 with 80 MHz punctured MCS11 */
+	{ 51, 1945600 },  /* EHT320 with 80 MHz punctured MCS12 */
+	{ 54, 2161800 },  /* EHT320 with 80 MHz punctured MCS13 */
+	{ -1, 2161800 }   /* SNR > 54 */
+};
+
+/* See IEEE P802.11be/D7.0, Table 36-85: EHT-MCSs for 3x996+484-tone MRU,
+ * NSS,u = 1
+ */
+static const struct minsnr_bitrate_entry eht280_table[] = {
+	{ 0, 0 },
+	{ 14, 125300 },   /* EHT320 with 40 MHz punctured MCS0 */
+	{ 17, 250600 },   /* EHT320 with 40 MHz punctured MCS1 */
+	{ 21, 375900 },   /* EHT320 with 40 MHz punctured MCS2 */
+	{ 23, 501200 },   /* EHT320 with 40 MHz punctured MCS3 */
+	{ 27, 751800 },   /* EHT320 with 40 MHz punctured MCS4 */
+	{ 30, 1002400 },  /* EHT320 with 40 MHz punctured MCS5 */
+	{ 32, 1127600 },  /* EHT320 with 40 MHz punctured MCS6 */
+	{ 37, 1252900 },  /* EHT320 with 40 MHz punctured MCS7 */
+	{ 41, 1503500 },  /* EHT320 with 40 MHz punctured MCS8 */
+	{ 43, 1670600 },  /* EHT320 with 40 MHz punctured MCS9 */
+	{ 46, 1879400 },  /* EHT320 with 40 MHz punctured MCS10 */
+	{ 48, 2088200 },  /* EHT320 with 40 MHz punctured MCS11 */
+	{ 51, 2255300 },  /* EHT320 with 40 MHz punctured MCS12 */
+	{ 54, 2505900 },  /* EHT320 with 40 MHz punctured MCS13 */
+	{ -1, 2505900 }   /* SNR > 54 */
+};
+
 /* See IEEE P802.11be/D2.0, Table 36-86: EHT-MCSs for 4x996-tone RU, NSS,u = 1
  */
 static const struct minsnr_bitrate_entry eht320_table[] = {
@@ -2891,6 +3023,96 @@ static unsigned int max_he_eht_rate(const struct minsnr_bitrate_entry table[],
 }
 
 
+static unsigned int get_eht_punctured_rate(enum chan_width cw,
+					   u8 num_punct_bits, int adjusted_snr,
+					   u8 boost)
+{
+	const struct minsnr_bitrate_entry *eht_table;
+
+	switch (cw) {
+	case CHAN_WIDTH_80:
+		switch (num_punct_bits) {
+		case 1:
+			/* EHT80 with 20 MHz punctured */
+			eht_table = eht60_table;
+			break;
+		default:
+			eht_table = he80_table;
+			break;
+		}
+		break;
+	case CHAN_WIDTH_160:
+		switch (num_punct_bits) {
+		case 2:
+			/* EHT160 with 40 MHz punctured */
+			eht_table = eht120_table;
+			break;
+		case 1:
+			/* EHT160 with 20 MHz punctured */
+			eht_table = eht140_table;
+			break;
+		default:
+			eht_table = he160_table;
+			break;
+		}
+		break;
+	case CHAN_WIDTH_320:
+		switch (num_punct_bits) {
+		case 6:
+			/* EHT320 with 120 MHz punctured */
+			eht_table = eht200_table;
+			break;
+		case 4:
+			/* EHT320 with 80 MHz punctured */
+			eht_table = eht240_table;
+			break;
+		case 2:
+			/* EHT320 with 40 MHz punctured */
+			eht_table = eht280_table;
+			break;
+		default:
+			eht_table = eht320_table;
+			break;
+		}
+		break;
+	default:
+		/* Puncturing is not supported for the channel width */
+		return 0;
+	}
+
+	return max_he_eht_rate(eht_table, adjusted_snr, true) + boost;
+}
+
+
+static u8 get_eht_num_punct_bits(const u8 *ies, size_t ies_len)
+{
+	const u8 *eht_ie;
+
+	eht_ie = get_ie_ext(ies, ies_len, WLAN_EID_EXT_EHT_OPERATION);
+	if (eht_ie && eht_ie[1] >= 1 + IEEE80211_EHT_OP_MIN_LEN) {
+		struct ieee80211_eht_operation *eht_op;
+
+		eht_op = (struct ieee80211_eht_operation *) &eht_ie[3];
+
+		if (eht_op->oper_params &
+		    EHT_OPER_DISABLED_SUBCHAN_BITMAP_PRESENT) {
+			u16 punct_bitmap;
+			u8 count = 0;
+
+			punct_bitmap = le_to_host16(
+				eht_op->oper_info.disabled_chan_bitmap);
+			while (punct_bitmap) {
+				count += punct_bitmap & 1;
+				punct_bitmap >>= 1;
+			}
+			return count;
+		}
+	}
+
+	return 0;
+}
+
+
 unsigned int wpas_get_est_tpt(const struct wpa_supplicant *wpa_s,
 			      const u8 *ies, size_t ies_len, int rate,
 			      int snr, int freq, enum chan_width *max_cw)
@@ -3048,8 +3270,9 @@ unsigned int wpas_get_est_tpt(const struct wpa_supplicant *wpa_s,
 		struct ieee80211_eht_capabilities *eht;
 		struct he_capabilities *own_he;
 		u8 cw, boost = 2;
-		const u8 *eht_ie;
+		const u8 *eht_ie = NULL;
 		bool is_eht = false;
+		u8 num_punct_bits;
 
 		ie = get_ie_ext(ies, ies_len, WLAN_EID_EXT_HE_CAPABILITIES);
 		if (!ie || (ie[1] < 1 + IEEE80211_HE_CAPAB_MIN_LEN))
@@ -3099,8 +3322,17 @@ unsigned int wpas_get_est_tpt(const struct wpa_supplicant *wpa_s,
 				*max_cw = CHAN_WIDTH_80;
 			adjusted_snr = snr + wpas_channel_width_rssi_bump(
 				ies, ies_len, CHAN_WIDTH_80);
-			tmp = max_he_eht_rate(he80_table, adjusted_snr,
-					      is_eht) + boost;
+
+			num_punct_bits = get_eht_num_punct_bits(ies, ies_len);
+			if (is_eht && num_punct_bits)
+				tmp = get_eht_punctured_rate(CHAN_WIDTH_80,
+							     num_punct_bits,
+							     adjusted_snr,
+							     boost);
+			else
+				tmp = max_he_eht_rate(he80_table, adjusted_snr,
+						      is_eht) + boost;
+
 			if (tmp > est)
 				est = tmp;
 		}
@@ -3114,13 +3346,21 @@ unsigned int wpas_get_est_tpt(const struct wpa_supplicant *wpa_s,
 				*max_cw = CHAN_WIDTH_160;
 			adjusted_snr = snr + wpas_channel_width_rssi_bump(
 				ies, ies_len, CHAN_WIDTH_160);
-			tmp = max_he_eht_rate(he160_table, adjusted_snr,
-					      is_eht) + boost;
+
+			num_punct_bits = get_eht_num_punct_bits(ies, ies_len);
+			if (is_eht && num_punct_bits)
+				tmp = get_eht_punctured_rate(CHAN_WIDTH_160,
+							     num_punct_bits,
+							     adjusted_snr,
+							     boost);
+			else
+				tmp = max_he_eht_rate(he160_table, adjusted_snr,
+						      is_eht) + boost;
 			if (tmp > est)
 				est = tmp;
 		}
 
-		if (!is_eht)
+		if (!is_eht || !eht_ie)
 			return est;
 
 		eht = (struct ieee80211_eht_capabilities *) &eht_ie[3];
@@ -3133,7 +3373,16 @@ unsigned int wpas_get_est_tpt(const struct wpa_supplicant *wpa_s,
 				*max_cw = CHAN_WIDTH_320;
 			adjusted_snr = snr + wpas_channel_width_rssi_bump(
 				ies, ies_len, CHAN_WIDTH_320);
-			tmp = max_he_eht_rate(eht320_table, adjusted_snr, true);
+
+			num_punct_bits = get_eht_num_punct_bits(ies, ies_len);
+			if (num_punct_bits)
+				tmp = get_eht_punctured_rate(CHAN_WIDTH_320,
+							     num_punct_bits,
+							     adjusted_snr,
+							     0);
+			else
+				tmp = max_he_eht_rate(eht320_table, adjusted_snr,
+						      true);
 			if (tmp > est)
 				est = tmp;
 		}
diff --git a/wpa_supplicant/sme.c b/wpa_supplicant/sme.c
index c6b4242d..2ea3efab 100644
--- a/wpa_supplicant/sme.c
+++ b/wpa_supplicant/sme.c
@@ -538,6 +538,12 @@ static void wpas_sme_set_mlo_links(struct wpa_supplicant *wpa_s,
 		os_memcpy(wpa_s->links[i].bssid, bssid, ETH_ALEN);
 		wpa_s->links[i].freq = bss->mld_links[i].freq;
 		wpa_s->links[i].disabled = bss->mld_links[i].disabled;
+		wpabuf_free(wpa_s->links[i].ies);
+		wpa_s->links[i].ies = NULL;
+#ifdef CONFIG_TESTING_OPTIONS
+		if (wpa_s->link_ies[i])
+			wpa_s->links[i].ies = wpabuf_dup(wpa_s->link_ies[i]);
+#endif /* CONFIG_TESTING_OPTIONS */
 
 		if (bss->mld_link_id == i)
 			wpa_s->links[i].bss = bss;
@@ -2706,11 +2712,19 @@ mscs_fail:
 				wpa_s->links[i].freq;
 			params.mld_params.mld_links[i].disabled =
 				wpa_s->links[i].disabled;
+			if (wpa_s->links[i].ies) {
+				params.mld_params.mld_links[i].ies =
+					wpabuf_head(wpa_s->links[i].ies);
+				params.mld_params.mld_links[i].ies_len =
+					wpabuf_len(wpa_s->links[i].ies);
+			}
 
 			wpa_printf(MSG_DEBUG,
-				   "MLD: id=%u, freq=%d, disabled=%u, " MACSTR,
+				   "MLD: id=%u, freq=%d, disabled=%u, ies_len=%zu, "
+				   MACSTR,
 				   i, wpa_s->links[i].freq,
 				   wpa_s->links[i].disabled,
+				   params.mld_params.mld_links[i].ies_len,
 				   MAC2STR(wpa_s->links[i].bssid));
 		}
 	}
diff --git a/wpa_supplicant/wnm_sta.c b/wpa_supplicant/wnm_sta.c
index 0ae27a75..e5d649f5 100644
--- a/wpa_supplicant/wnm_sta.c
+++ b/wpa_supplicant/wnm_sta.c
@@ -907,9 +907,10 @@ static int wnm_send_bss_transition_mgmt_resp(
 		wpabuf_put_data(buf, target_bssid, ETH_ALEN);
 	} else if (status == WNM_BSS_TM_ACCEPT) {
 		/*
-		 * P802.11-REVmc clarifies that the Target BSSID field is always
-		 * present when status code is zero, so use a fake value here if
-		 * no BSSID is yet known.
+		 * IEEE Std 802.11-2024, 9.6.13.10 (BSS Transition Management
+		 * Response frame format) clarifies that the Target BSSID field
+		 * is always present when status code is zero, so use a fake
+		 * value here if no BSSID is yet known.
 		 */
 		wpabuf_put_data(buf, "\0\0\0\0\0\0", ETH_ALEN);
 	}
diff --git a/wpa_supplicant/wpa_supplicant.c b/wpa_supplicant/wpa_supplicant.c
index b8c6f55e..8e5e91c1 100644
--- a/wpa_supplicant/wpa_supplicant.c
+++ b/wpa_supplicant/wpa_supplicant.c
@@ -660,6 +660,10 @@ static void wpa_supplicant_cleanup(struct wpa_supplicant *wpa_s)
 	wpabuf_free(wpa_s->rsnxe_override_eapol);
 	wpa_s->rsnxe_override_eapol = NULL;
 	wpas_clear_driver_signal_override(wpa_s);
+	for (i = 0; i < MAX_NUM_MLD_LINKS; i++) {
+		wpabuf_free(wpa_s->link_ies[i]);
+		wpa_s->link_ies[i] = NULL;
+	}
 #endif /* CONFIG_TESTING_OPTIONS */
 
 	if (wpa_s->conf != NULL) {
@@ -796,6 +800,11 @@ static void wpa_supplicant_cleanup(struct wpa_supplicant *wpa_s)
 	os_free(wpa_s->last_scan_res);
 	wpa_s->last_scan_res = NULL;
 
+#ifdef CONFIG_P2P
+	os_free(wpa_s->p2p_pmksa_entry);
+	wpa_s->p2p_pmksa_entry = NULL;
+#endif /* CONFIG_P2P */
+
 #ifdef CONFIG_HS20
 	if (wpa_s->drv_priv)
 		wpa_drv_configure_frame_filters(wpa_s, 0);
@@ -871,6 +880,11 @@ static void wpa_supplicant_cleanup(struct wpa_supplicant *wpa_s)
 	os_free(wpa_s->owe_trans_scan_freq);
 	wpa_s->owe_trans_scan_freq = NULL;
 #endif /* CONFIG_OWE */
+
+	for (i = 0; i < MAX_NUM_MLD_LINKS; i++) {
+		wpabuf_free(wpa_s->links[i].ies);
+		wpa_s->links[i].ies = NULL;
+	}
 }
 
 
@@ -3112,18 +3126,25 @@ static void ibss_mesh_select_40mhz(struct wpa_supplicant *wpa_s,
 				   const struct wpa_ssid *ssid,
 				   struct hostapd_hw_modes *mode,
 				   struct hostapd_freq_params *freq,
-				   int obss_scan) {
+				   int obss_scan, bool is_6ghz)
+{
 	int chan_idx;
 	struct hostapd_channel_data *pri_chan = NULL, *sec_chan = NULL;
 	int i, res;
 	unsigned int j;
-	static const int ht40plus[] = {
+	static const int ht40plus_5ghz[] = {
 		36, 44, 52, 60, 100, 108, 116, 124, 132, 140,
 		149, 157, 165, 173, 184, 192
 	};
+	static const int ht40plus_6ghz[] = {
+		1, 9, 17, 25, 33, 41, 49, 57, 65, 73,
+		81, 89, 97, 105, 113, 121, 129, 137, 145, 153,
+		161, 169, 177, 185, 193, 201, 209, 217, 225
+	};
+
 	int ht40 = -1;
 
-	if (!freq->ht_enabled)
+	if (!freq->ht_enabled && !is_6ghz)
 		return;
 
 	for (chan_idx = 0; chan_idx < mode->num_channels; chan_idx++) {
@@ -3145,10 +3166,19 @@ static void ibss_mesh_select_40mhz(struct wpa_supplicant *wpa_s,
 #endif
 
 	/* Check/setup HT40+/HT40- */
-	for (j = 0; j < ARRAY_SIZE(ht40plus); j++) {
-		if (ht40plus[j] == freq->channel) {
-			ht40 = 1;
-			break;
+	if (is_6ghz) {
+		for (j = 0; j < ARRAY_SIZE(ht40plus_6ghz); j++) {
+			if (ht40plus_6ghz[j] == freq->channel) {
+				ht40 = 1;
+				break;
+			}
+		}
+	} else {
+		for (j = 0; j < ARRAY_SIZE(ht40plus_5ghz); j++) {
+			if (ht40plus_5ghz[j] == freq->channel) {
+				ht40 = 1;
+				break;
+			}
 		}
 	}
 
@@ -3166,12 +3196,14 @@ static void ibss_mesh_select_40mhz(struct wpa_supplicant *wpa_s,
 	if (sec_chan->flag & (HOSTAPD_CHAN_DISABLED | HOSTAPD_CHAN_NO_IR))
 		return;
 
-	if (ht40 == -1) {
-		if (!(pri_chan->flag & HOSTAPD_CHAN_HT40MINUS))
-			return;
-	} else {
-		if (!(pri_chan->flag & HOSTAPD_CHAN_HT40PLUS))
-			return;
+	if (freq->ht_enabled) {
+		if (ht40 == -1) {
+			if (!(pri_chan->flag & HOSTAPD_CHAN_HT40MINUS))
+				return;
+		} else {
+			if (!(pri_chan->flag & HOSTAPD_CHAN_HT40PLUS))
+				return;
+		}
 	}
 	freq->sec_channel_offset = ht40;
 
@@ -3247,7 +3279,8 @@ static bool ibss_mesh_select_80_160mhz(struct wpa_supplicant *wpa_s,
 		6515, 6595, 6675, 6755, 6835, 6915, 6995
 	};
 	static const int bw160[] = {
-		5955, 6115, 6275, 6435, 6595, 6755, 6915
+		5180, 5500, 5745, 5955, 6115, 6275, 6435,
+		6595, 6755, 6915
 	};
 	static const int bw320[]= {
 		5955, 6255, 6115, 6415, 6275, 6575, 6435,
@@ -3258,6 +3291,8 @@ static bool ibss_mesh_select_80_160mhz(struct wpa_supplicant *wpa_s,
 	int i;
 	unsigned int j, k;
 	int chwidth, seg0, seg1;
+	int offset_in_160 = 1;
+	int offset_in_320 = 0;
 	u32 vht_caps = 0;
 	u8 channel = freq->channel;
 
@@ -3297,18 +3332,50 @@ static bool ibss_mesh_select_80_160mhz(struct wpa_supplicant *wpa_s,
 	seg0 = channel + 6;
 	seg1 = 0;
 
+	for (k = 0; k < ARRAY_SIZE(bw160); k++) {
+		if (bw80[j] >= bw160[k] &&
+		    bw80[j] < bw160[k] + 160) {
+			if (bw80[j] == bw160[k])
+				offset_in_160 = 1;
+			else
+				offset_in_160 = -1;
+			break;
+		}
+	}
+
+	for (k = 0; k < ARRAY_SIZE(bw320); k++) {
+		if (bw80[j] >= bw320[k] &&
+		    bw80[j] < bw320[k] + 320) {
+			if (bw80[j] == bw320[k])
+				offset_in_320 = 0;
+			else if (bw80[j] == bw320[k] + 80)
+				offset_in_320 = 1;
+			else if (bw80[j] == bw320[k] + 160)
+				offset_in_320 = 2;
+			else
+				offset_in_320 = 3;
+			break;
+		}
+	}
+
 	/* In 160 MHz, the initial four 20 MHz channels were validated
 	 * above. If 160 MHz is supported, check the remaining four 20 MHz
-	 * channels for the total of 160 MHz bandwidth for 6 GHz.
+	 * channels for the total of 160 MHz bandwidth.
 	 */
 	if ((mode->he_capab[ieee80211_mode].phy_cap[
 		     HE_PHYCAP_CHANNEL_WIDTH_SET_IDX] &
-	     HE_PHYCAP_CHANNEL_WIDTH_SET_160MHZ_IN_5G) && is_6ghz &&
-	    ibss_mesh_is_80mhz_avail(channel + 16, mode)) {
+	     HE_PHYCAP_CHANNEL_WIDTH_SET_160MHZ_IN_5G) &&
+	    (ssid->max_oper_chwidth == CONF_OPER_CHWIDTH_160MHZ ||
+	     ssid->max_oper_chwidth == CONF_OPER_CHWIDTH_320MHZ) &&
+	    ibss_mesh_is_80mhz_avail(channel + 16 * offset_in_160, mode)) {
 		for (j = 0; j < ARRAY_SIZE(bw160); j++) {
-			if (freq->freq == bw160[j]) {
+			u8 start_chan;
+
+			if (freq->freq >= bw160[j] &&
+			    freq->freq < bw160[j] + 160) {
 				chwidth = CONF_OPER_CHWIDTH_160MHZ;
-				seg0 = channel + 14;
+				ieee80211_freq_to_chan(bw160[j], &start_chan);
+				seg0 = start_chan + 14;
 				break;
 			}
 		}
@@ -3321,9 +3388,13 @@ static bool ibss_mesh_select_80_160mhz(struct wpa_supplicant *wpa_s,
 	if ((mode->eht_capab[ieee80211_mode].phy_cap[
 		     EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_IDX] &
 	     EHT_PHYCAP_320MHZ_IN_6GHZ_SUPPORT_MASK) && is_6ghz &&
-	    ibss_mesh_is_80mhz_avail(channel + 16, mode) &&
-	    ibss_mesh_is_80mhz_avail(channel + 32, mode) &&
-	    ibss_mesh_is_80mhz_avail(channel + 48, mode)) {
+	    ssid->max_oper_chwidth == CONF_OPER_CHWIDTH_320MHZ &&
+	    ibss_mesh_is_80mhz_avail(channel + 16 -
+				     64 * ((offset_in_320 + 1) / 4), mode) &&
+	    ibss_mesh_is_80mhz_avail(channel + 32 -
+				     64 * ((offset_in_320 + 2) / 4), mode) &&
+	    ibss_mesh_is_80mhz_avail(channel + 48 -
+				     64 * ((offset_in_320 + 3) / 4), mode)) {
 		for (j = 0; j < ARRAY_SIZE(bw320); j += 2) {
 			if (freq->freq >= bw320[j] &&
 			    freq->freq <= bw320[j + 1]) {
@@ -3450,9 +3521,10 @@ void ibss_mesh_setup_freq(struct wpa_supplicant *wpa_s,
 		freq->he_enabled = ibss_mesh_can_use_he(wpa_s, ssid, mode,
 							ieee80211_mode);
 	freq->channel = channel;
-	/* Setup higher BW only for 5 GHz */
+	/* Setup higher BW only for 5 and 6 GHz */
 	if (mode->mode == HOSTAPD_MODE_IEEE80211A) {
-		ibss_mesh_select_40mhz(wpa_s, ssid, mode, freq, obss_scan);
+		ibss_mesh_select_40mhz(wpa_s, ssid, mode, freq, obss_scan,
+				       is_6ghz);
 		if (!ibss_mesh_select_80_160mhz(wpa_s, ssid, mode, freq,
 						ieee80211_mode, is_6ghz))
 			freq->he_enabled = freq->vht_enabled = false;
@@ -4598,6 +4670,9 @@ static void wpas_start_assoc_cb(struct wpa_radio_work *work, int deinit)
 		params.pbss = (ssid->pbss != 2) ? ssid->pbss : 0;
 	}
 
+	params.bssid_filter = wpa_s->bssid_filter;
+	params.bssid_filter_count = wpa_s->bssid_filter_count;
+
 	if (ssid->mode == WPAS_MODE_IBSS && ssid->bssid_set &&
 	    wpa_s->conf->ap_scan == 2) {
 		params.bssid = ssid->bssid;
@@ -4909,6 +4984,15 @@ static void wpas_start_assoc_cb(struct wpa_radio_work *work, int deinit)
 		wpa_supplicant_req_auth_timeout(wpa_s, timeout, 0);
 	}
 
+#ifdef CONFIG_P2P
+	if (ssid->pmk_valid && wpa_s->p2p_pmksa_entry &&
+	    !(wpa_s->drv_flags & WPA_DRIVER_FLAGS_SME)) {
+		wpa_sm_pmksa_cache_add_entry(wpa_s->wpa,
+					     wpa_s->p2p_pmksa_entry);
+		wpa_s->p2p_pmksa_entry = NULL;
+	}
+#endif /* CONFIG_P2P */
+
 #ifdef CONFIG_WEP
 	if (wep_keys_set &&
 	    (wpa_s->drv_flags & WPA_DRIVER_FLAGS_SET_KEYS_AFTER_ASSOC)) {
diff --git a/wpa_supplicant/wpa_supplicant_conf.mk b/wpa_supplicant/wpa_supplicant_conf.mk
index ac594b68..be96494f 100644
--- a/wpa_supplicant/wpa_supplicant_conf.mk
+++ b/wpa_supplicant/wpa_supplicant_conf.mk
@@ -8,6 +8,11 @@
 # Include this makefile to generate your hardware specific wpa_supplicant.conf
 # Requires: WIFI_DRIVER_SOCKET_IFACE
 
+# This makefile should not be included since it has been converted to soong.
+ifndef FORCE_USE_ANDROIDMK_FOR_WPA_CONF
+$(error wpa_supplicant.conf already converted to soong, do not include wpa_supplicant_conf.mk in Android.mk. Instead replace it with Android.bp, for example in hardware/broadcom/wlan/bcmdhd/config/Android.bp or add 'FORCE_USE_ANDROIDMK_FOR_WPA_CONF := true' to your product config)
+endif
+
 LOCAL_PATH := $(call my-dir)
 
 ########################
diff --git a/wpa_supplicant/wpa_supplicant_i.h b/wpa_supplicant/wpa_supplicant_i.h
index 8965bfa1..44bb5279 100644
--- a/wpa_supplicant/wpa_supplicant_i.h
+++ b/wpa_supplicant/wpa_supplicant_i.h
@@ -757,6 +757,7 @@ struct wpa_supplicant {
 		unsigned int freq;
 		struct wpa_bss *bss;
 		bool disabled;
+		struct wpabuf *ies;
 	} links[MAX_NUM_MLD_LINKS];
 	u8 *last_con_fail_realm;
 	size_t last_con_fail_realm_len;
@@ -1114,6 +1115,7 @@ struct wpa_supplicant {
 
 #ifdef CONFIG_P2P
 	struct p2p_go_neg_results *go_params;
+	struct rsn_pmksa_cache_entry *p2p_pmksa_entry;
 	int create_p2p_iface;
 	u8 pending_interface_addr[ETH_ALEN];
 	char pending_interface_name[100];
@@ -1397,6 +1399,7 @@ struct wpa_supplicant {
 	unsigned int disable_eapol_g2_tx;
 	unsigned int eapol_2_key_info_set_mask;
 	int test_assoc_comeback_type;
+	struct wpabuf *link_ies[MAX_NUM_MLD_LINKS];
 #endif /* CONFIG_TESTING_OPTIONS */
 
 	struct wmm_ac_assoc_data *wmm_ac_assoc_info;
```

