```diff
diff --git a/assets/CarrierRestrictionOperatorDetails.json b/assets/CarrierRestrictionOperatorDetails.json
index a088f9497..b3c89765a 100644
--- a/assets/CarrierRestrictionOperatorDetails.json
+++ b/assets/CarrierRestrictionOperatorDetails.json
@@ -2,9 +2,13 @@
   "_comment": "Operator should register with its application package name, carrierId and all the corresponding  SHA256IDs",
   "_comment": "Example format :: << \"packageName\" : {\"carrierId\":[<int>], \"callerSHA256Ids\":[<SHAID1>, <SHAID2>]} >>",
   "com.vzw.hss.myverizon":{"carrierIds":[1839],"callerSHA256Ids":["AE23A03436DF07B0CD70FE881CDA2EC1D21215D7B7B0CC68E67B67F5DF89526A"]},
+  "com.verizon.mips.services":{"carrierIds":[1839],"callerSHA256Ids":["FF82050BF6BED1F152AC1A12DC83CACBAD401775161882872C6665FC5E15C8F2"]},
   "com.google.android.apps.tycho":{"carrierIds":[1989],"callerSHA256Ids":["B9CFCE1C47A6AC713442718F15EF55B00B3A6D1A6D48CB46249FA8EB51465350","4C36AF4A5BDAD97C1F3D8B283416D244496C2AC5EAFE8226079EF6F676FD1859"]},
   "com.comcast.mobile.mxs":{"carrierIds": [2032,2532,2556],"callerSHA256Ids":["914C26403B57D2D482359FC235CC825AD00D52B0121C18EF2B2B9D4DDA4B8996"]},
   "com.xfinity.digitalhome": {"carrierIds": [2032,2532,2556],"callerSHA256Ids":["31b4c17315c2269040d535f7b6a79cf4d11517c664d9de8f1ddf4f8a785aad47"]},
   "com.xfinity.digitalhome.debug":{"carrierIds": [2032,2532,2556],"callerSHA256Ids":["c9133e8168f97573c8c567f46777dff74ade0c015ecf2c5e91be3e4e76ddcae2"]},
-  "com.xfinity.dh.xm.app": {"carrierIds": [2032,2532,2556],"callerSHA256Ids":["c9133e8168f97573c8c567f46777dff74ade0c015ecf2c5e91be3e4e76ddcae2"]}
+  "com.xfinity.dh.xm.app": {"carrierIds": [2032,2532,2556],"callerSHA256Ids":["c9133e8168f97573c8c567f46777dff74ade0c015ecf2c5e91be3e4e76ddcae2"]},
+  "com.tmobile.tmte": {"carrierIds": [1],"callerSHA256Ids":["3D:1A:4B:EF:6E:E7:AF:7D:34:D1:20:E7:B1:AA:C0:DD:24:55:85:DE:62:37:CF:10:0F:68:33:3A:FA:CF:F5:62"]},
+  "com.tmobile.tuesdays": {"carrierIds": [1],"callerSHA256Ids":["3D:1A:4B:EF:6E:E7:AF:7D:34:D1:20:E7:B1:AA:C0:DD:24:55:85:DE:62:37:CF:10:0F:68:33:3A:FA:CF:F5:62","92:B5:F8:11:7F:BD:9B:D5:73:8F:F1:68:A4:FA:12:CB:E2:84:BE:83:4E:DE:1A:7B:B4:4D:D8:45:5B:A1:59:20"]},
+  "com.tmobile.pr.mytmobile": {"carrierIds": [1],"callerSHA256Ids":["92:B5:F8:11:7F:BD:9B:D5:73:8F:F1:68:A4:FA:12:CB:E2:84:BE:83:4E:DE:1A:7B:B4:4D:D8:45:5B:A1:59:20"]}
 }
\ No newline at end of file
diff --git a/assets/google_us_san_mtv_sat_s2.dat b/assets/google_us_san_mtv_sat_s2.dat
new file mode 100644
index 000000000..26516010a
Binary files /dev/null and b/assets/google_us_san_mtv_sat_s2.dat differ
diff --git a/assets/satellite_access_config.json b/assets/satellite_access_config.json
new file mode 100644
index 000000000..4f9f85342
--- /dev/null
+++ b/assets/satellite_access_config.json
@@ -0,0 +1,140 @@
+{
+    "access_control_configs": [
+        {
+            "config_id": 0,
+            "satellite_infos": [
+                {
+                    "satellite_id": "0db0312f-d73f-444d-b99b-a893dfb42edf",
+                    "satellite_position": {
+                        "longitude": -150.3,
+                        "altitude": 35786000
+                    },
+                    "bands": [
+                        259,
+                        260
+                    ],
+                    "earfcn_ranges": [
+                        {
+                            "start_earfcn": 3000,
+                            "end_earfcn": 4300
+                        }
+                    ]
+                }
+            ],
+            "tag_ids": [
+                6,
+                7,
+                8
+            ]
+        },
+        {
+            "config_id": 1,
+            "satellite_infos": [
+                {
+                    "satellite_id": "1dec24f8-9223-4196-ad7a-a03002db7af7",
+                    "satellite_position": {
+                        "longitude": 15.5,
+                        "altitude": 35786000
+                    },
+                    "bands": [
+                        257,
+                        258
+                    ],
+                    "earfcn_ranges": [
+                        {
+                            "start_earfcn": 3200,
+                            "end_earfcn": 3200
+                        }
+                    ]
+                }
+            ],
+            "tag_ids": [
+                9,
+                10,
+                11
+            ]
+        },
+        {
+            "config_id": 2,
+            "satellite_infos": [
+                {
+                    "satellite_id": "f60cb479-d85b-4f4e-b050-cc428f5eb4a4",
+                    "satellite_position": {
+                        "longitude": -150,
+                        "altitude": 35786000
+                    },
+                    "bands": [
+                        259,
+                        260
+                    ],
+                    "earfcn_ranges": [
+                        {
+                            "start_earfcn": 3300,
+                            "end_earfcn": 3400
+                        }
+                    ]
+                }
+            ],
+            "tag_ids": [
+                12,
+                13,
+                14
+            ]
+        },
+        {
+            "config_id": 3,
+            "satellite_infos": [
+                {
+                    "satellite_id": "c5837d96-9585-46aa-8dd0-a974583737fb",
+                    "satellite_position": {
+                        "longitude": -155,
+                        "altitude": 35786000
+                    },
+                    "bands": [
+                        261,
+                        262
+                    ],
+                    "earfcn_ranges": [
+                        {
+                            "start_earfcn": 3500,
+                            "end_earfcn": 3600
+                        }
+                    ]
+                }
+            ],
+            "tag_ids": [
+                15,
+                16,
+                17
+            ]
+        }
+        ,
+        {
+            "config_id": 4,
+            "satellite_infos": [
+                {
+                    "satellite_id": "6ef2a128-0477-4271-895f-dc4a221d2b23",
+                    "satellite_position": {
+                        "longitude": -66,
+                        "altitude": 35786000
+                    },
+                    "bands": [
+                        263,
+                        264
+                    ],
+                    "earfcn_ranges": [
+                        {
+                            "start_earfcn": 3700,
+                            "end_earfcn": 3800
+                        }
+                    ]
+                }
+            ],
+            "tag_ids": [
+                18,
+                19,
+                20
+            ]
+        }
+    ]
+}
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 226ab1845..f55369828 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -284,33 +284,33 @@
     <string name="data_enable_summary" msgid="696860063456536557">"Dozvoli korištenje podataka"</string>
     <string name="dialog_alert_title" msgid="5260471806940268478">"Pažnja"</string>
     <string name="roaming" msgid="1576180772877858949">"Roming"</string>
-    <string name="roaming_enable" msgid="6853685214521494819">"Povezivanje na usluge prijenosa podataka u romingu"</string>
-    <string name="roaming_disable" msgid="8856224638624592681">"Povezivanje na usluge prijenosa podataka u romingu"</string>
+    <string name="roaming_enable" msgid="6853685214521494819">"Povezivanje na usluge prenosa podataka u romingu"</string>
+    <string name="roaming_disable" msgid="8856224638624592681">"Povezivanje na usluge prenosa podataka u romingu"</string>
     <string name="roaming_reenable_message" msgid="1951802463885727915">"Roming podataka je isključen. Dodirnite da ga uključite."</string>
     <string name="roaming_enabled_message" msgid="9022249120750897">"Mogu nastati troškovi za roming. Dodirnite da izmijenite."</string>
-    <string name="roaming_notification_title" msgid="3590348480688047320">"Veza za prijenos podataka na mobilnoj mreži je izgubljena"</string>
+    <string name="roaming_notification_title" msgid="3590348480688047320">"Veza za prenos podataka na mobilnoj mreži je izgubljena"</string>
     <string name="roaming_on_notification_title" msgid="7451473196411559173">"Roming podataka je uključen"</string>
     <string name="roaming_warning" msgid="7855681468067171971">"Može dovesti do značajnih troškova."</string>
     <string name="roaming_check_price_warning" msgid="8212484083990570215">"Raspitajte se kod svog mobilnog operatera za cijene."</string>
     <string name="roaming_alert_title" msgid="5689615818220960940">"Dozvoliti roming podataka?"</string>
     <string name="limited_sim_function_notification_title" msgid="612715399099846281">"Ograničena funkcionalnost SIM-a"</string>
-    <string name="limited_sim_function_with_phone_num_notification_message" msgid="5928988883403677610">"Pozivi i usluge prijenosa podataka operatera <xliff:g id="CARRIER_NAME">%1$s</xliff:g> mogu biti blokirane kada koristite broj <xliff:g id="PHONE_NUMBER">%2$s</xliff:g>."</string>
-    <string name="limited_sim_function_notification_message" msgid="5338638075496721160">"Pozivi i usluge prijenosa pod. op. <xliff:g id="CARRIER_NAME">%1$s</xliff:g> mogu biti blok. kada koristite drugi SIM."</string>
+    <string name="limited_sim_function_with_phone_num_notification_message" msgid="5928988883403677610">"Pozivi i usluge prenosa podataka operatera <xliff:g id="CARRIER_NAME">%1$s</xliff:g> mogu biti blokirane kada koristite broj <xliff:g id="PHONE_NUMBER">%2$s</xliff:g>."</string>
+    <string name="limited_sim_function_notification_message" msgid="5338638075496721160">"Pozivi i usluge prenosa pod. op. <xliff:g id="CARRIER_NAME">%1$s</xliff:g> mogu biti blok. kada koristite drugi SIM."</string>
     <string name="sip_accounts_removed_notification_title" msgid="3528076957535736095">"Zastarjeli SIP računi su pronađeni i uklonjeni"</string>
     <string name="sip_accounts_removed_notification_message" msgid="1916856744869791592">"Android platforma više ne podržva SIP pozivanje.\nVaši postojeći SIP računi <xliff:g id="REMOVED_SIP_ACCOUNTS">%s</xliff:g> su uklonjeni.\nPotvrdite zadanu postavku računa za pozivanje."</string>
     <string name="sip_accounts_removed_notification_action" msgid="3772778402370555562">"Idi u postavke"</string>
     <string name="data_usage_title" msgid="8438592133893837464">"Prijenos podataka u aplikaciji"</string>
-    <string name="data_usage_template" msgid="6287906680674061783">"Iskorišteno je <xliff:g id="ID_1">%1$s</xliff:g> prijenosa podataka u periodu <xliff:g id="ID_2">%2$s</xliff:g>"</string>
+    <string name="data_usage_template" msgid="6287906680674061783">"Iskorišteno je <xliff:g id="ID_1">%1$s</xliff:g> prenosa podataka u periodu <xliff:g id="ID_2">%2$s</xliff:g>"</string>
     <string name="advanced_options_title" msgid="9208195294513520934">"Napredno"</string>
     <string name="carrier_settings_euicc" msgid="1190237227261337749">"Operater"</string>
     <string name="keywords_carrier_settings_euicc" msgid="8540160967922063745">"mobilni operater, esim, sim, euicc, promijeni mobilnog operatera, dodaj mobilnog operatera"</string>
     <string name="carrier_settings_euicc_summary" msgid="2027941166597330117">"<xliff:g id="CARRIER_NAME">%1$s</xliff:g> — <xliff:g id="PHONE_NUMBER">%2$s</xliff:g>"</string>
     <string name="mobile_data_settings_title" msgid="7228249980933944101">"Prijenos podataka na mobilnoj mreži"</string>
-    <string name="mobile_data_settings_summary" msgid="5012570152029118471">"Pristup prijenosu podataka mobilnom mrežom"</string>
+    <string name="mobile_data_settings_summary" msgid="5012570152029118471">"Pristup prenosu podataka mobilnom mrežom"</string>
     <string name="data_usage_disable_mobile" msgid="5669109209055988308">"Isključiti prijenos podataka na mobilnoj mreži?"</string>
     <string name="sim_selection_required_pref" msgid="6985901872978341314">"Potreban izbor"</string>
-    <string name="sim_change_data_title" msgid="9142726786345906606">"Promijeniti SIM za prijenos podataka?"</string>
-    <string name="sim_change_data_message" msgid="3567358694255933280">"Koristiti SIM karticu <xliff:g id="NEW_SIM">%1$s</xliff:g> umjesto SIM kartice <xliff:g id="OLD_SIM">%2$s</xliff:g> za prijenos podataka na mobilnoj mreži?"</string>
+    <string name="sim_change_data_title" msgid="9142726786345906606">"Promijeniti SIM za prenos podataka?"</string>
+    <string name="sim_change_data_message" msgid="3567358694255933280">"Koristiti SIM karticu <xliff:g id="NEW_SIM">%1$s</xliff:g> umjesto SIM kartice <xliff:g id="OLD_SIM">%2$s</xliff:g> za prenos podataka na mobilnoj mreži?"</string>
     <string name="wifi_calling_settings_title" msgid="5800018845662016507">"Pozivanje putem WiFi-ja"</string>
     <string name="video_calling_settings_title" msgid="342829454913266078">"Video pozivi putem operatera"</string>
     <string name="gsm_umts_options" msgid="4968446771519376808">"GSM/UMTS opcije"</string>
@@ -318,13 +318,13 @@
     <string name="throttle_data_usage" msgid="1944145350660420711">"Korištenje podataka"</string>
     <string name="throttle_current_usage" msgid="7483859109708658613">"Iskorišteni podaci u trenutnom periodu"</string>
     <string name="throttle_time_frame" msgid="1813452485948918791">"Period korištenja podataka"</string>
-    <string name="throttle_rate" msgid="7641913901133634905">"Pravila o brzini prijenosa podataka"</string>
+    <string name="throttle_rate" msgid="7641913901133634905">"Pravila o brzini prenosa podataka"</string>
     <string name="throttle_help" msgid="2624535757028809735">"Saznajte više"</string>
     <string name="throttle_status_subtext" msgid="1110276415078236687">"<xliff:g id="USED_0">%1$s</xliff:g> (<xliff:g id="USED_1">%2$d</xliff:g> ٪) od <xliff:g id="USED_2">%3$s</xliff:g> maksimuma perioda\nSljedeći period počinje za <xliff:g id="USED_3">%4$d</xliff:g> dan(a) (<xliff:g id="USED_4">%5$s</xliff:g>)"</string>
     <string name="throttle_data_usage_subtext" msgid="3185429653996709840">"<xliff:g id="USED_0">%1$s</xliff:g> (<xliff:g id="USED_1">%2$d</xliff:g> ٪) od <xliff:g id="USED_2">%3$s</xliff:g> maksimuma perioda"</string>
-    <string name="throttle_data_rate_reduced_subtext" msgid="8369839346277847725">"<xliff:g id="USED_0">%1$s</xliff:g> ograničenje je prekoračeno \nBrzina prijenosa podataka je smanjena na <xliff:g id="USED_1">%2$d</xliff:g> Kb/s"</string>
+    <string name="throttle_data_rate_reduced_subtext" msgid="8369839346277847725">"<xliff:g id="USED_0">%1$s</xliff:g> ograničenje je prekoračeno \nBrzina prenosa podataka je smanjena na <xliff:g id="USED_1">%2$d</xliff:g> Kb/s"</string>
     <string name="throttle_time_frame_subtext" msgid="6462089615392402127">"Proteklo je <xliff:g id="USED_0">%1$d</xliff:g> ٪ ciklusa\nSljedeći period počinje za <xliff:g id="USED_1">%2$d</xliff:g> dan(a) (<xliff:g id="USED_2">%3$s</xliff:g>)"</string>
-    <string name="throttle_rate_subtext" msgid="7221971817325779535">"Brzina prijenosa podataka se smanjuje na <xliff:g id="USED">%1$d</xliff:g> Kb/s ako se prekorači ograničenje korištenja podataka"</string>
+    <string name="throttle_rate_subtext" msgid="7221971817325779535">"Brzina prenosa podataka se smanjuje na <xliff:g id="USED">%1$d</xliff:g> Kb/s ako se prekorači ograničenje korištenja podataka"</string>
     <string name="throttle_help_subtext" msgid="2817114897095534807">"Više informacija o pravilima korištenja podataka mobilne mreže vašeg operatera"</string>
     <string name="cell_broadcast_sms" msgid="4053449797289031063">"SMS info servisa"</string>
     <string name="enable_disable_cell_bc_sms" msgid="4759958924031721350">"SMS info servisa"</string>
@@ -553,7 +553,7 @@
     <string name="incall_error_supp_service_switch" msgid="5272822448189448479">"Nije moguće prebacivati pozive."</string>
     <string name="incall_error_supp_service_resume" msgid="1276861499306817035">"Nije moguće nastaviti poziv."</string>
     <string name="incall_error_supp_service_separate" msgid="8932660028965274353">"Nije moguće odvojiti poziv."</string>
-    <string name="incall_error_supp_service_transfer" msgid="8211925891867334323">"Prijenos nije moguć."</string>
+    <string name="incall_error_supp_service_transfer" msgid="8211925891867334323">"Prenos nije moguć."</string>
     <string name="incall_error_supp_service_conference" msgid="27578082433544702">"Nije moguće spajati pozive."</string>
     <string name="incall_error_supp_service_reject" msgid="3044363092441655912">"Nije moguće odbiti poziv."</string>
     <string name="incall_error_supp_service_hangup" msgid="836524952243836735">"Nije moguće uputiti poziv(e)."</string>
@@ -621,7 +621,7 @@
     <string name="ota_title_activate" msgid="4049645324841263423">"Aktivirajte svoj telefon"</string>
     <string name="ota_touch_activate" msgid="838764494319694754">"Za aktiviranje telefonske usluge potrebno je uputiti poseban poziv. \n\nNakon što pritisnete „Aktiviraj“, poslušajte uputstva za aktiviranje telefona."</string>
     <string name="ota_hfa_activation_title" msgid="3300556778212729671">"Aktivacija u toku..."</string>
-    <string name="ota_hfa_activation_dialog_message" msgid="7921718445773342996">"Telefon aktivira uslugu prijenosa mobilnih podataka.\n\nTo može potrajati do 5 minuta."</string>
+    <string name="ota_hfa_activation_dialog_message" msgid="7921718445773342996">"Telefon aktivira uslugu prenosa mobilnih podataka.\n\nTo može potrajati do 5 minuta."</string>
     <string name="ota_skip_activation_dialog_title" msgid="7666611236789203797">"Preskočiti aktivaciju?"</string>
     <string name="ota_skip_activation_dialog_message" msgid="6691722887019708713">"Ako preskočite aktivaciju, nećete moći upućivati pozive niti se povezati na mobilne podatkovne mreže (iako se možete povezati s WiFi mrežama). Dok ne aktivirate telefon, prikazivat će se upit za aktivaciju svaki put kada upalite telefon."</string>
     <string name="ota_skip_activation_dialog_skip_label" msgid="5908029466817825633">"Preskoči"</string>
@@ -642,7 +642,7 @@
     <string name="phone_entered_ecm_text" msgid="8431238297843035842">"Aktiviran način rada za hitni povratni poziv"</string>
     <string name="phone_in_ecm_notification_title" msgid="6825016389926367946">"Način rada za hitni povratni poziv"</string>
     <string name="phone_in_ecm_call_notification_text" msgid="653972232922670335">"Podatkovna veza je onemogućena"</string>
-    <string name="phone_in_ecm_notification_complete_time" msgid="7341624337163082759">"Nema veze za prijenos podataka do <xliff:g id="COMPLETETIME">%s</xliff:g>"</string>
+    <string name="phone_in_ecm_notification_complete_time" msgid="7341624337163082759">"Nema veze za prenos podataka do <xliff:g id="COMPLETETIME">%s</xliff:g>"</string>
     <!-- format error in translation for alert_dialog_exit_ecm (7661603870224398025) -->
     <!-- format error in translation for alert_dialog_not_avaialble_in_ecm (8717711120099503279) -->
     <string name="alert_dialog_in_ecm_call" msgid="1207545603149771978">"Odabrana radnja nije dostupna tokom hitnog poziva."</string>
@@ -707,10 +707,10 @@
     <string name="mobile_data_status_roaming_with_plan_subtext" msgid="2576177169108123095">"Trenutno u romingu, plan za podatke je aktivan"</string>
     <string name="mobile_data_status_no_plan_subtext" msgid="170331026419263657">"Nema preostalih mobilnih podataka"</string>
     <string name="mobile_data_activate_prepaid" msgid="4276738964416795596">"Nema preostalih mobilnih podataka"</string>
-    <string name="mobile_data_activate_prepaid_summary" msgid="6846085278531605925">"Dodajte podatke za prijenos na mobilnoj mreži putem operatera <xliff:g id="PROVIDER_NAME">%s</xliff:g>"</string>
+    <string name="mobile_data_activate_prepaid_summary" msgid="6846085278531605925">"Dodajte podatke za prenos na mobilnoj mreži putem operatera <xliff:g id="PROVIDER_NAME">%s</xliff:g>"</string>
     <string name="mobile_data_activate_roaming_plan" msgid="922290995866269366">"Nema plana za roming"</string>
     <string name="mobile_data_activate_roaming_plan_summary" msgid="5379228493306235969">"Dodajte plan za roming pomoću pružaoca usluga <xliff:g id="PROVIDER_NAME">%s</xliff:g>"</string>
-    <string name="mobile_data_activate_footer" msgid="7895874069807204548">"Možete dodati podatke za prijenos na mobilnoj mreži ili plan za roming pomoću operatera, <xliff:g id="PROVIDER_NAME">%s</xliff:g>."</string>
+    <string name="mobile_data_activate_footer" msgid="7895874069807204548">"Možete dodati podatke za prenos na mobilnoj mreži ili plan za roming pomoću operatera, <xliff:g id="PROVIDER_NAME">%s</xliff:g>."</string>
     <string name="mobile_data_activate_diag_title" msgid="5401741936224757312">"Dodati podatke?"</string>
     <string name="mobile_data_activate_diag_message" msgid="3527260988020415441">"Možda ćete morati dodati podatke preko pružaoca usluga <xliff:g id="PROVIDER_NAME">%s</xliff:g>"</string>
     <string name="mobile_data_activate_button" msgid="1139792516354374612">"DODAJTE PODATKE"</string>
@@ -830,8 +830,8 @@
     <string name="supp_service_over_ut_precautions_dual_sim" msgid="5166866975550910474">"Za korištenje usluge <xliff:g id="SUPP_SERVICE">%1$s</xliff:g>, provjerite je li za SIM <xliff:g id="SIM_NUMBER">%2$d</xliff:g> uključen prijenos podataka na mobilnoj mreži. Ovo možete promijeniti u postavkama mobilne mreže."</string>
     <string name="supp_service_over_ut_precautions_roaming_dual_sim" msgid="6627654855191817965">"Za korištenje usluge <xliff:g id="SUPP_SERVICE">%1$s</xliff:g>, provjerite jesu li za SIM <xliff:g id="SIM_NUMBER">%2$d</xliff:g> uključeni prijenos podataka na mobilnoj mreži i roming podataka. Ovo možete promijeniti u postavkama mobilne mreže."</string>
     <string name="supp_service_over_ut_precautions_dialog_dismiss" msgid="5934541487903081652">"Odbaci"</string>
-    <string name="radio_info_data_connection_enable" msgid="6183729739783252840">"Omogućite vezu za prijenos podataka"</string>
-    <string name="radio_info_data_connection_disable" msgid="6404751291511368706">"Onemogući vezu za prijenos podataka"</string>
+    <string name="radio_info_data_connection_enable" msgid="6183729739783252840">"Omogućite vezu za prenos podataka"</string>
+    <string name="radio_info_data_connection_disable" msgid="6404751291511368706">"Onemogući vezu za prenos podataka"</string>
     <string name="volte_provisioned_switch_string" msgid="4812874990480336178">"VoLTE omogućen"</string>
     <string name="vt_provisioned_switch_string" msgid="8295542122512195979">"Video pozivi su omogućeni"</string>
     <string name="wfc_provisioned_switch_string" msgid="3835004640321078988">"WiFi poziv obezbijeđen"</string>
@@ -882,7 +882,7 @@
     <string name="radioInfo_lac" msgid="3892986460272607013">"LAC"</string>
     <string name="radioInfo_cid" msgid="1423185536264406705">"CID"</string>
     <string name="radio_info_subid" msgid="6839966868621703203">"Trenutni pomoćni ID:"</string>
-    <string name="radio_info_dds" msgid="1122593144425697126">"Pomoćni ID za zadani SIM za prijenos podataka:"</string>
+    <string name="radio_info_dds" msgid="1122593144425697126">"Pomoćni ID za zadani SIM za prenos podataka:"</string>
     <string name="radio_info_dl_kbps" msgid="2382922659525318726">"DL propusnost (kbps):"</string>
     <string name="radio_info_ul_kbps" msgid="2102225400904799036">"UL propusnost (kbps):"</string>
     <string name="radio_info_phy_chan_config" msgid="608045501232211303">"Konfiguracije fizičkih kanala:"</string>
@@ -902,7 +902,7 @@
     <string name="radio_info_message_waiting_label" msgid="1886549432566952078">"Poruka na čekanju:"</string>
     <string name="radio_info_phone_number_label" msgid="2533852539562512203">"Broj telefona:"</string>
     <string name="radio_info_voice_network_type_label" msgid="2395347336419593265">"Vrsta glasovne mreže:"</string>
-    <string name="radio_info_data_network_type_label" msgid="8886597029237501929">"Vrsta mreže za prijenos podataka:"</string>
+    <string name="radio_info_data_network_type_label" msgid="8886597029237501929">"Vrsta mreže za prenos podataka:"</string>
     <string name="radio_info_override_network_type_label" msgid="4176280017221092005">"Zaobilaženje vrste mreže:"</string>
     <string name="radio_info_voice_raw_registration_state_label" msgid="2822988327145825128">"Stanje registracije sirovog glasa:"</string>
     <string name="radio_info_data_raw_registration_state_label" msgid="2895895513822604539">"Stanje registracije sirovih podataka:"</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index f4c55930d..c6e47966e 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -680,7 +680,7 @@
     <string name="accessibility_settings_activity_title" msgid="7883415189273700298">"Accessibilitat"</string>
     <string name="status_hint_label_incoming_wifi_call" msgid="2606052595898044071">"Trucada per Wi-Fi de"</string>
     <string name="status_hint_label_wifi_call" msgid="942993035689809853">"Trucada per Wi-Fi"</string>
-    <string name="message_decode_error" msgid="1061856591500290887">"S\'ha produït un error en descodificar el missatge."</string>
+    <string name="message_decode_error" msgid="1061856591500290887">"Hi ha hagut un error en descodificar el missatge."</string>
     <string name="callFailed_cdma_activation" msgid="5392057031552253550">"Una targeta SIM ha activat el servei, i s\'ha actualitzat la funció d\'itinerància del telèfon."</string>
     <string name="callFailed_cdma_call_limit" msgid="1074219746093031412">"Hi ha massa trucades actives. Finalitza\'n alguna o combina-les abans de fer-ne una de nova."</string>
     <string name="callFailed_imei_not_accepted" msgid="7257903653685147251">"No es pot establir la connexió. Insereix una targeta SIM vàlida."</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 452df67ad..cefda5a55 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -297,7 +297,7 @@
     <string name="limited_sim_function_with_phone_num_notification_message" msgid="5928988883403677610">"Baliteke <xliff:g id="CARRIER_NAME">%1$s</xliff:g> bidezko deiak eta datu-zerbitzuak blokeatuta egotea <xliff:g id="PHONE_NUMBER">%2$s</xliff:g> telefono-zenbakia erabiltzean."</string>
     <string name="limited_sim_function_notification_message" msgid="5338638075496721160">"Baliteke <xliff:g id="CARRIER_NAME">%1$s</xliff:g> bidezko deiak eta datu-zerbitzuak blokeatuta egotea beste SIM txartel bat erabiltzean."</string>
     <string name="sip_accounts_removed_notification_title" msgid="3528076957535736095">"SIP-eko kontu zaharkituak aurkitu eta kendu dira"</string>
-    <string name="sip_accounts_removed_notification_message" msgid="1916856744869791592">"SIP bidezko deiak jadanik ez dira bateragarriak Android-en plataformarekin.\nZeneuzkan SIP-eko kontuak (<xliff:g id="REMOVED_SIP_ACCOUNTS">%s</xliff:g>) kendu egin dira.\nBerretsi deietarako ezarri duzun kontu lehenetsia."</string>
+    <string name="sip_accounts_removed_notification_message" msgid="1916856744869791592">"SIP bidezko deiak jadanik ez dira onartzen Android-en plataforman.\nZeneuzkan SIP-eko kontuak (<xliff:g id="REMOVED_SIP_ACCOUNTS">%s</xliff:g>) kendu egin dira.\nBerretsi deietarako ezarri duzun kontu lehenetsia."</string>
     <string name="sip_accounts_removed_notification_action" msgid="3772778402370555562">"Joan ezarpenetara"</string>
     <string name="data_usage_title" msgid="8438592133893837464">"Aplikazioak erabilitako datuak"</string>
     <string name="data_usage_template" msgid="6287906680674061783">"Datuen <xliff:g id="ID_1">%1$s</xliff:g> erabili dira data hauen artean: <xliff:g id="ID_2">%2$s</xliff:g>"</string>
@@ -543,9 +543,9 @@
     <string name="incall_error_ecm_emergency_only" msgid="5622379058883722080">"Larrialdikoak ez diren deiak egiteko, irten larrialdi-zerbitzuen deiak jasotzeko modutik."</string>
     <string name="incall_error_emergency_only" msgid="8786127461027964653">"Ez dago sarean erregistratuta."</string>
     <string name="incall_error_out_of_service" msgid="1927265196942672791">"Sare mugikorra ez dago erabilgarri."</string>
-    <string name="incall_error_out_of_service_2g" msgid="904434080740846116">"Sare mugikorra ez dago erabilgarri.\n\nDeia egiteko, konektatu hari gabeko sare batera.\n\n2G desgaituta dago gailuan, eta baliteke horrek konexioan eragina izatea. Aurrera egiteko, joan ezarpenetara eta eman 2G erabiltzeko baimena."</string>
+    <string name="incall_error_out_of_service_2g" msgid="904434080740846116">"Sare mugikorra ez dago erabilgarri.\n\nDeia egiteko, konektatu hari gabeko sare batera.\n\n2G desgaituta dago gailuan, eta baliteke horrek konexioan eragina izatea. Aurrera egiteko, joan Ezarpenak atalera eta eman 2G erabiltzeko baimena."</string>
     <string name="incall_error_out_of_service_wfc" msgid="4497663185857190885">"Sare mugikorra ez dago erabilgarri. Deia egiteko, konektatu haririk gabeko sare batera."</string>
-    <string name="incall_error_out_of_service_wfc_2g_user" msgid="8218768986365299663">"Sare mugikorra ez dago erabilgarri.\n\nDeia egiteko, konektatu hari gabeko sare batera.\n\n2G desgaituta dago gailuan, eta baliteke horrek konexioan eragina izatea. Aurrera egiteko, joan ezarpenetara eta eman 2G erabiltzeko baimena."</string>
+    <string name="incall_error_out_of_service_wfc_2g_user" msgid="8218768986365299663">"Sare mugikorra ez dago erabilgarri.\n\nDeia egiteko, konektatu hari gabeko sare batera.\n\n2G desgaituta dago gailuan, eta baliteke horrek konexioan eragina izatea. Aurrera egiteko, joan Ezarpenak atalera eta eman 2G erabiltzeko baimena."</string>
     <string name="incall_error_no_phone_number_supplied" msgid="8680831089508851894">"Deitzeko, idatzi balio duen zenbaki bat."</string>
     <string name="incall_error_call_failed" msgid="393508653582682539">"Ezin izan da deitu."</string>
     <string name="incall_error_cannot_add_call" msgid="5425764862628655443">"Une honetan, ezin da egin deia. Deitu ordez, mezu bat bidaltzen saia zaitezke."</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 3a2dc6985..ac8c6d9c5 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -600,10 +600,10 @@
     <string name="failedToImportSingleContactMsg" msgid="228095510489830266">"Kontaktin tuominen epäonnistui"</string>
     <string name="hac_mode_title" msgid="4127986689621125468">"Kuulolaitteet"</string>
     <string name="hac_mode_summary" msgid="7774989500136009881">"Ota kuulolaitteen yhteensopivuustoiminto käyttöön"</string>
-    <string name="rtt_mode_title" msgid="3075948111362818043">"RTT-puhelu (puhelusta lähetettävä teksti)"</string>
+    <string name="rtt_mode_title" msgid="3075948111362818043">"RTT-puhelu (reaaliaikainen tekstinsyöttö)"</string>
     <string name="rtt_mode_summary" msgid="8631541375609989562">"Salli viestit äänipuheluissa"</string>
     <string name="rtt_mode_more_information" msgid="587500128658756318">"RTT-toiminto auttaa kuuroja sekä käyttäjiä, joilla on kuulo‑ tai puhehäiriöitä tai jotka tarvitsevat muuta tukea pelkän puheen lisäksi.&lt;br&gt; &lt;a href=<xliff:g id="URL">http://support.google.com/mobile?p=telephony_rtt</xliff:g>&gt;Lisätietoja&lt;/a&gt;\n       &lt;br&gt;&lt;br&gt; – RTT-puhelut tallennetaan litterointiviestinä.\n       &lt;br&gt; – RTT ei ole käytettävissä videopuheluissa."</string>
-    <string name="no_rtt_when_roaming" msgid="5268008247378355389">"Huom. Puhelusta lähetettävä teksti (RTT) ei ole käytettävissä roaming-tilassa"</string>
+    <string name="no_rtt_when_roaming" msgid="5268008247378355389">"Huom. Reaaliaikainen tekstinsyöttö (RTT) ei ole käytettävissä roaming-tilassa"</string>
   <string-array name="tty_mode_entries">
     <item msgid="3238070884803849303">"TTY pois käytöstä"</item>
     <item msgid="1449091874731375214">"TTY täynnä"</item>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index efb22b10a..af0b7f1c4 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -193,7 +193,7 @@
     <string name="preferred_network_mode_dialogtitle" msgid="2781447433514459696">"Preferensi jenis jaringan"</string>
     <string name="forbidden_network" msgid="5081729819561333023">"(terlarang)"</string>
     <string name="choose_network_title" msgid="5335832663422653082">"Pilih jaringan"</string>
-    <string name="network_disconnected" msgid="8844141106841160825">"Terputus"</string>
+    <string name="network_disconnected" msgid="8844141106841160825">"Tidak terhubung"</string>
     <string name="network_connected" msgid="2760235679963580224">"Terhubung"</string>
     <string name="network_connecting" msgid="160901383582774987">"Menghubungkan..."</string>
     <string name="network_could_not_connect" msgid="6547460848093727998">"Tidak dapat terhubung"</string>
@@ -869,7 +869,7 @@
     <string name="radioInfo_phone_idle" msgid="2191653783170757819">"Tidak ada aktivitas"</string>
     <string name="radioInfo_phone_ringing" msgid="8100354169567413370">"Berdering"</string>
     <string name="radioInfo_phone_offhook" msgid="7564601639749936170">"Panggilan sedang Berlangsung"</string>
-    <string name="radioInfo_data_disconnected" msgid="8085447971880814541">"Terputus"</string>
+    <string name="radioInfo_data_disconnected" msgid="8085447971880814541">"Tidak terhubung"</string>
     <string name="radioInfo_data_connecting" msgid="925092271092152472">"Menghubungkan"</string>
     <string name="radioInfo_data_connected" msgid="7637335645634239508">"Terhubung"</string>
     <string name="radioInfo_data_suspended" msgid="8695262782642002785">"Ditangguhkan"</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 5e8999f2c..d13b2c04d 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -286,8 +286,8 @@
     <string name="roaming" msgid="1576180772877858949">"נדידה"</string>
     <string name="roaming_enable" msgid="6853685214521494819">"יש להתחבר לשירותי נתונים בעת נדידה"</string>
     <string name="roaming_disable" msgid="8856224638624592681">"יש להתחבר לשירותי נתונים בעת נדידה"</string>
-    <string name="roaming_reenable_message" msgid="1951802463885727915">"הנדידה מושבתת. אפשר להקיש כדי להפעיל אותה."</string>
-    <string name="roaming_enabled_message" msgid="9022249120750897">"ייתכנו חיובי נדידה. יש להקיש כדי לשנות."</string>
+    <string name="roaming_reenable_message" msgid="1951802463885727915">"הנדידה מושבתת. אפשר ללחוץ כדי להפעיל אותה."</string>
+    <string name="roaming_enabled_message" msgid="9022249120750897">"ייתכנו חיובי נדידה. יש ללחוץ כדי לשנות."</string>
     <string name="roaming_notification_title" msgid="3590348480688047320">"המכשיר התנתק מחבילת הגלישה"</string>
     <string name="roaming_on_notification_title" msgid="7451473196411559173">"נדידה מופעלת"</string>
     <string name="roaming_warning" msgid="7855681468067171971">"ייתכנו שיעורי חיוב גבוהים."</string>
@@ -564,11 +564,11 @@
     <string name="incall_error_carrier_roaming_satellite_mode" msgid="678603203562886361">"‏אפשר לשלוח ולקבל הודעות ללא חיבור לרשת סלולרית או לרשת Wi-Fi"</string>
     <string name="emergency_information_hint" msgid="9208897544917793012">"מידע למקרה חירום"</string>
     <string name="emergency_information_owner_hint" msgid="6256909888049185316">"בעלים"</string>
-    <string name="emergency_information_confirm_hint" msgid="5109017615894918914">"אפשר להקיש שוב כדי להציג את הפרטים"</string>
+    <string name="emergency_information_confirm_hint" msgid="5109017615894918914">"אפשר ללחוץ שוב כדי להציג את הפרטים"</string>
     <string name="emergency_enable_radio_dialog_title" msgid="2667568200755388829">"שיחת חירום"</string>
     <string name="single_emergency_number_title" msgid="8413371079579067196">"מספר חירום"</string>
     <string name="numerous_emergency_numbers_title" msgid="8972398932506755510">"מספרי חירום"</string>
-    <string name="emergency_call_shortcut_hint" msgid="1290485125107779500">"אפשר להקיש שוב כדי להתקשר אל <xliff:g id="EMERGENCY_NUMBER">%s</xliff:g>"</string>
+    <string name="emergency_call_shortcut_hint" msgid="1290485125107779500">"אפשר ללחוץ שוב כדי להתקשר אל <xliff:g id="EMERGENCY_NUMBER">%s</xliff:g>"</string>
     <string name="emergency_enable_radio_dialog_message" msgid="1695305158151408629">"הפעלת הרדיו מתבצעת…"</string>
     <string name="emergency_enable_radio_dialog_retry" msgid="4329131876852608587">"אין שירות. ניסיון חוזר מתבצע..."</string>
     <string name="radio_off_during_emergency_call" msgid="8011154134040481609">"אי אפשר לעבור למצב טיסה בזמן שיחת חירום."</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index ddbec3adf..8cb4d1da5 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -184,7 +184,7 @@
     <string name="connect_later" msgid="1950138106010005425">"現在このネットワークに接続できません。しばらくしてからもう一度お試しください。"</string>
     <string name="registration_done" msgid="5337407023566953292">"ネットワークに登録されました。"</string>
     <string name="already_auto" msgid="8607068290733079336">"すでに自動選択が適用されています。"</string>
-    <string name="select_automatically" msgid="779750291257872651">"ネットワークを自動的に選択"</string>
+    <string name="select_automatically" msgid="779750291257872651">"ネットワークを自動的に選択する"</string>
     <string name="manual_mode_disallowed_summary" msgid="3970048592179890197">"%1$s に接続中はご利用いただけません"</string>
     <string name="network_select_title" msgid="4117305053881611988">"ネットワーク"</string>
     <string name="register_automatically" msgid="3907580547590554834">"自動登録..."</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 9ef2be9d0..4b1c427e2 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -436,7 +436,7 @@
     <item msgid="7970797749269738435">"1"</item>
   </string-array>
     <string name="cdma_activate_device" msgid="5914720276140097632">"ಸಾಧನವನ್ನು ಸಕ್ರಿಯಗೊಳಿಸಿ"</string>
-    <string name="cdma_lte_data_service" msgid="359786441782404562">"ಡೇಟಾ ಸೇವೆಯನ್ನು ಹೊಂದಿಸಿ"</string>
+    <string name="cdma_lte_data_service" msgid="359786441782404562">"ಡೇಟಾ ಸೇವೆಯನ್ನು ಸೆಟಪ್ ಮಾಡಿ"</string>
     <string name="carrier_settings_title" msgid="6292869148169850220">"ವಾಹಕ ಸೆಟ್ಟಿಂಗ್‌ಗಳು"</string>
     <string name="fdn" msgid="2545904344666098749">"ಸ್ಥಿರ ಡಯಲಿಂಗ್‌‌ ಸಂಖ್ಯೆಗಳು"</string>
     <string name="fdn_with_label" msgid="6412087553365709494">"ಸ್ಥಿರ ಡಯಲ್ ಸಂಖ್ಯೆಗಳು (<xliff:g id="SUBSCRIPTIONLABEL">%s</xliff:g>)"</string>
@@ -456,7 +456,7 @@
     <string name="voice_privacy" msgid="7346935172372181951">"ಧ್ವನಿ ಗೌಪ್ಯತೆ"</string>
     <string name="voice_privacy_summary" msgid="3556460926168473346">"ಗೌಪ್ಯತೆ ವರ್ಧಿತ ಮೋಡ್ ಅನ್ನು ಸಕ್ರಿಯಗೊಳಿಸು"</string>
     <string name="tty_mode_option_title" msgid="3843817710032641703">"TTY ಮೋಡ್‌"</string>
-    <string name="tty_mode_option_summary" msgid="4770510287236494371">"TTY ಮೋಡ್‌ ಹೊಂದಿಸಿ"</string>
+    <string name="tty_mode_option_summary" msgid="4770510287236494371">"TTY ಮೋಡ್‌ ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="auto_retry_mode_title" msgid="2985801935424422340">"ಸ್ವಯಂ-ಮರುಪ್ರಯತ್ನಿಸುವಿಕೆ"</string>
     <string name="auto_retry_mode_summary" msgid="2863919925349511402">"ಸ್ವಯಂ ಮರುಪ್ರಯತ್ನಿಸುವಿಕೆ ಮೋಡ್‌‌ ಅನ್ನು ಸಕ್ರಿಯಗೊಳಿಸಿ"</string>
     <string name="tty_mode_not_allowed_video_call" msgid="6551976083652752815">"TTY ಮೋಡ್ ವೀಡಿಯೊ ಕರೆಯ ಸಂದರ್ಭದಲ್ಲಿ ಅನುಮತಿಸಲಾಗುವುದಿಲ್ಲ"</string>
@@ -495,7 +495,7 @@
     <string name="mismatchPin" msgid="1467254768290323845">"ನೀವು ಟೈಪ್‌ ಮಾಡಿದ ಪಿನ್‌ ಗಳು ಹೊಂದಿಕೆಯಾಗುವುದಿಲ್ಲ. ಮತ್ತೆ ಪ್ರಯತ್ನಿಸಿ."</string>
     <string name="invalidPin" msgid="7363723429414001979">"4 ರಿಂದ 8 ಸಂಖ್ಯೆಗಳಿರುವ ಪಿನ್‌ ಟೈಪ್ ಮಾಡಿ."</string>
     <string name="disable_sim_pin" msgid="3112303905548613752">"SIM PIN ತೆರವುಗೊಳಿಸಿ"</string>
-    <string name="enable_sim_pin" msgid="445461050748318980">"SIM PIN ಹೊಂದಿಸಿ"</string>
+    <string name="enable_sim_pin" msgid="445461050748318980">"SIM PIN ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="enable_in_progress" msgid="4135305985717272592">"PIN ಹೊಂದಿಸಲಾಗುತ್ತಿದೆ…"</string>
     <string name="enable_pin_ok" msgid="2877428038280804256">"PIN ಹೊಂದಿಸಲಾಗಿದೆ"</string>
     <string name="disable_pin_ok" msgid="888505244389647754">"PIN ತೆರವುಗೊಳಿಸಲಾಗಿದೆ"</string>
@@ -597,7 +597,7 @@
     <string name="importingSimContacts" msgid="4995457122107888932">"ಸಿಮ್‌ ಸಂಪರ್ಕಗಳನ್ನು ಆಮದು ಮಾಡಲಾಗುತ್ತಿದೆ"</string>
     <string name="importToFDNfromContacts" msgid="5068664870738407341">"ಸಂಪರ್ಕಗಳಿಂದ ಆಮದು ಮಾಡು"</string>
     <string name="singleContactImportedMsg" msgid="3619804066300998934">"ಆಮದು ಮಾಡಿದ ಸಂಪರ್ಕ"</string>
-    <string name="failedToImportSingleContactMsg" msgid="228095510489830266">"ಸಂಪರ್ಕ ಆಮದು ಮಾಡುವಲ್ಲಿ ವಿಫಲವಾಗಿದೆ"</string>
+    <string name="failedToImportSingleContactMsg" msgid="228095510489830266">"ಸಂಪರ್ಕವನ್ನು ಇಂಪೋರ್ಟ್ ಮಾಡಲು ವಿಫಲವಾಗಿದೆ"</string>
     <string name="hac_mode_title" msgid="4127986689621125468">"ಕೇಳುವಿಕೆ ಸಾಧನಗಳು"</string>
     <string name="hac_mode_summary" msgid="7774989500136009881">"ಶ್ರವಣ ಸಾಧನ ಹೊಂದಾಣಿಕೆಯನ್ನು ಆನ್‌ ಮಾಡಿ"</string>
     <string name="rtt_mode_title" msgid="3075948111362818043">"ನೈಜ-ಸಮಯ ಪಠ್ಯ (RTT) ಕರೆ"</string>
@@ -611,7 +611,7 @@
     <item msgid="2131559553795606483">"TTY VCO"</item>
   </string-array>
     <string name="dtmf_tones_title" msgid="7874845461117175236">"DTMF ಟೋನ್‌ಗಳು"</string>
-    <string name="dtmf_tones_summary" msgid="2294822239899471201">"DTMF ಟೋನ್‌ಗಳ ಅಳತೆಯನ್ನು ಹೊಂದಿಸಿ"</string>
+    <string name="dtmf_tones_summary" msgid="2294822239899471201">"DTMF ಟೋನ್‌ಗಳ ಅಳತೆಯನ್ನು ಸೆಟ್ ಮಾಡಿ"</string>
   <string-array name="dtmf_tone_entries">
     <item msgid="2271798469250155310">"ಸಾಮಾನ್ಯ"</item>
     <item msgid="6044210222666533564">"ದೀರ್ಘವಾದ"</item>
@@ -666,7 +666,7 @@
     <string name="description_dialpad_button" msgid="7395114120463883623">"ಡಯಲ್‌ಪ್ಯಾಡ್ ತೋರಿಸಿ"</string>
     <string name="pane_title_emergency_dialpad" msgid="3627372514638694401">"ತುರ್ತು ಡಯಲ್‌ಪ್ಯಾಡ್‌"</string>
     <string name="voicemail_visual_voicemail_switch_title" msgid="6610414098912832120">"ದೃಶ್ಯ ಧ್ವನಿಮೇಲ್"</string>
-    <string name="voicemail_set_pin_dialog_title" msgid="7005128605986960003">"ಪಿನ್ ಹೊಂದಿಸಿ"</string>
+    <string name="voicemail_set_pin_dialog_title" msgid="7005128605986960003">"ಪಿನ್ ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="voicemail_change_pin_dialog_title" msgid="4633077715231764435">"ಪಿನ್ ಬದಲಾಯಿಸಿ"</string>
     <string name="preference_category_ringtone" msgid="8787281191375434976">"ರಿಂಗ್‌ಟೋನ್‌‌ &amp; ವೈಬ್ರೇಟ್‌"</string>
     <string name="pstn_connection_service_label" msgid="9200102709997537069">"ಅಂತರ್-ರಚಿತ ಸಿಮ್‌ ಕಾರ್ಡ್‌ಗಳು"</string>
@@ -695,7 +695,7 @@
     <string name="change_pin_ok_label" msgid="6861082678817785330">"ಸರಿ"</string>
     <string name="change_pin_enter_old_pin_header" msgid="853151335217594829">"ನಿಮ್ಮ ಹಳೆಯ ಪಿನ್‌ ಅನ್ನು ದೃಢೀಕರಿಸಿ"</string>
     <string name="change_pin_enter_old_pin_hint" msgid="8801292976275169367">"ಮುಂದುವರಿಸಲು ನಿಮ್ಮ ಧ್ವನಿಮೇಲ್ ಪಿನ್ ಅನ್ನು ನಮೂದಿಸಿ."</string>
-    <string name="change_pin_enter_new_pin_header" msgid="4739465616733486118">"ಹೊಸ ಪಿನ್ ಹೊಂದಿಸಿ"</string>
+    <string name="change_pin_enter_new_pin_header" msgid="4739465616733486118">"ಹೊಸ ಪಿನ್ ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="change_pin_enter_new_pin_hint" msgid="2326038476516364210">"ಪಿನ್ <xliff:g id="MIN">%1$d</xliff:g>-<xliff:g id="MAX">%2$d</xliff:g> ಅಂಕಿಗಳನ್ನು ಹೊಂದಿರಬೇಕು."</string>
     <string name="change_pin_confirm_pin_header" msgid="2606303906320705726">"ನಿಮ್ಮ ಪಿನ್‌ ಅನ್ನು ದೃಢೀಕರಿಸಿ"</string>
     <string name="change_pin_confirm_pins_dont_match" msgid="305164501222587215">"ಪಿನ್‌ಗಳು ಹೊಂದಾಣಿಕೆಯಾಗುವುದಿಲ್ಲ"</string>
@@ -908,7 +908,7 @@
     <string name="radio_info_data_raw_registration_state_label" msgid="2895895513822604539">"ಡೇಟಾ ರಾ ರಿಜಿಸ್ಟ್ರೇಷನ್‌ ಸ್ಟೇಟ್‌:"</string>
     <string name="radio_info_wlan_data_raw_registration_state_label" msgid="6396894835757296612">"WLAN ಡೇಟಾ ರಾ ರಿಜಿಸ್ಟ್ರೇಷನ್‌ ಸ್ಟೇಟ್‌:"</string>
     <string name="phone_index_label" msgid="6222406512768964268">"ಫೋನ್ ಸೂಚಿಕೆಯನ್ನು ಆಯ್ಕೆಮಾಡಿ"</string>
-    <string name="radio_info_set_perferred_label" msgid="7408131389363136210">"ಆದ್ಯತೆಯ ನೆಟ್‌ವರ್ಕ್‌ ಪ್ರಕಾರವನ್ನು ಹೊಂದಿಸಿ:"</string>
+    <string name="radio_info_set_perferred_label" msgid="7408131389363136210">"ಆದ್ಯತೆಯ ನೆಟ್‌ವರ್ಕ್‌ ಪ್ರಕಾರವನ್ನು ಸೆಟ್ ಮಾಡಿ:"</string>
     <string name="radio_info_ping_hostname_v4" msgid="6951237885381284790">"ಹೋಸ್ಟ್‌ ಹೆಸರನ್ನು ಪಿಂಗ್ ಮಾಡಿ(www.google.com) IPv4:"</string>
     <string name="radio_info_ping_hostname_v6" msgid="2748637889486554603">"ಹೋಸ್ಟ್‌ ಹೆಸರನ್ನು ಪಿಂಗ್ ಮಾಡಿ(www.google.com) IPv6:"</string>
     <string name="radio_info_http_client_test" msgid="1329583721088428238">"HTTP ಕ್ಲೈಂಟ್ ಪರೀಕ್ಷೆ:"</string>
@@ -922,9 +922,9 @@
     <string name="radio_info_nr_available" msgid="3383388088451237182">"NR ಲಭ್ಯವಿದೆ (NSA):"</string>
     <string name="radio_info_nr_state" msgid="4158805093187555149">"NR ಸ್ಥಿತಿ (NSA):"</string>
     <string name="radio_info_nr_frequency" msgid="1201156032796584128">"NR ಫ್ರೀಕ್ವೆನ್ಸಿ:"</string>
-    <string name="band_mode_title" msgid="7988822920724576842">"ರೇಡಿಯೋ ಬ್ಯಾಂಡ್ ಮೋಡ್ ಹೊಂದಿಸಿ"</string>
+    <string name="band_mode_title" msgid="7988822920724576842">"ರೇಡಿಯೋ ಬ್ಯಾಂಡ್ ಮೋಡ್ ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="band_mode_loading" msgid="795923726636735967">"ಬ್ಯಾಂಡ್ ಪಟ್ಟಿಯನ್ನು ಲೋಡ್ ಮಾಡಲಾಗುತ್ತಿದೆ…"</string>
-    <string name="band_mode_set" msgid="6657819412803771421">"ಹೊಂದಿಸಿ"</string>
+    <string name="band_mode_set" msgid="6657819412803771421">"ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="band_mode_failed" msgid="1707488541847192924">"ವಿಫಲಗೊಂಡಿದೆ"</string>
     <string name="band_mode_succeeded" msgid="2230018000534761063">"ಯಶಸ್ವಿಯಾಗಿದೆ"</string>
     <string name="phone_info_label" product="tablet" msgid="7477478709388477397">"ಟ್ಯಾಬ್ಲೆಟ್ ಮಾಹಿತಿ"</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index a7054f93f..60bbe0a28 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -86,8 +86,8 @@
     <string name="voicemail_notifications_preference_title" msgid="7829238858063382977">"Билдирмелер"</string>
     <string name="cell_broadcast_settings" msgid="8135324242541809924">"Өзгөчө кырдаал тууралуу кулактандыруу"</string>
     <string name="call_settings" msgid="3677282690157603818">"Чалуу параметрлери"</string>
-    <string name="additional_gsm_call_settings" msgid="1561980168685658846">"Кошумча жөндөөлөр"</string>
-    <string name="additional_gsm_call_settings_with_label" msgid="7973920539979524908">"Кошумча жөндөөлөр (<xliff:g id="SUBSCRIPTIONLABEL">%s</xliff:g>)"</string>
+    <string name="additional_gsm_call_settings" msgid="1561980168685658846">"Кошумча параметрлер"</string>
+    <string name="additional_gsm_call_settings_with_label" msgid="7973920539979524908">"Кошумча параметрлер (<xliff:g id="SUBSCRIPTIONLABEL">%s</xliff:g>)"</string>
     <string name="sum_gsm_call_settings" msgid="7964692601608878138">"GSM менен гана чалуунун кошумча параметрлери"</string>
     <string name="additional_cdma_call_settings" msgid="2178016561980611304">"Кошумча CDMA чалуунун параметрлери"</string>
     <string name="sum_cdma_call_settings" msgid="3185825305136993636">"CDMA менен гана чалуунун кошумча параметрлери"</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index d3fe12d72..36477c1e0 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -560,7 +560,7 @@
     <string name="incall_error_supp_service_hold" msgid="8535056414643540997">"कॉल सुरू ठेवू शकत नाही."</string>
     <string name="incall_error_wfc_only_no_wireless_network" msgid="5860742792811400109">"कॉल करण्‍यासाठी वायरलेस नेटवर्कशी कनेक्‍ट करा."</string>
     <string name="incall_error_promote_wfc" msgid="9164896813931363415">"कॉल करण्यासाठी वाय-फाय कॉलिंग सक्षम करा."</string>
-    <string name="incall_error_satellite_enabled" msgid="5247740814607087814">"कॉल करण्यासाठी, सर्वप्रथम उपग्रह कनेक्शन बंद करा."</string>
+    <string name="incall_error_satellite_enabled" msgid="5247740814607087814">"कॉल करण्यासाठी, सर्वप्रथम सॅटेलाइट कनेक्शन बंद करा."</string>
     <string name="incall_error_carrier_roaming_satellite_mode" msgid="678603203562886361">"तुम्ही मोबाइल किंवा वाय-फाय नेटवर्कशिवाय मेसेज पाठवू आणि मिळवू शकता."</string>
     <string name="emergency_information_hint" msgid="9208897544917793012">"अतिमहत्त्वाची माहिती"</string>
     <string name="emergency_information_owner_hint" msgid="6256909888049185316">"मालक"</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index baa5aa790..a5ccf9d8f 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -130,7 +130,7 @@
     <string name="enable_cdma_cw" msgid="811047045863422232">"अन गर्नुहोस्"</string>
     <string name="disable_cdma_cw" msgid="7119290446496301734">"रद्द गर्नुहोस्"</string>
     <string name="cdma_call_waiting_in_ims_on" msgid="6390979414188659218">"IMS अन्तर्गत CDMA कल प्रतीक्षाको सुविधा सक्रिय छ"</string>
-    <string name="cdma_call_waiting_in_ims_off" msgid="1099246114368636334">"IMS अन्तर्गत CDMA कल प्रतीक्षाको सुविधा निष्क्रिय छ"</string>
+    <string name="cdma_call_waiting_in_ims_off" msgid="1099246114368636334">"IMS अन्तर्गत CDMA कल प्रतीक्षाको सुविधा अफ छ"</string>
     <string name="updating_title" msgid="6130548922615719689">"कल सेटिङहरू"</string>
     <string name="call_settings_admin_user_only" msgid="7238947387649986286">"कल सेटिङहरू केवल प्रशासकीय प्रयोगकर्ताद्वारा परिवर्तन गर्न सकिन्छ।"</string>
     <string name="phone_account_settings_user_restriction" msgid="9142685151087208396">"एड्मिन वा कार्य प्रोफाइलका प्रयोगकर्ता मात्र फोनमा लिंक गरिएको खाताका सेटिङ बदल्न सक्नुहुन्छ।"</string>
@@ -770,8 +770,8 @@
     <string name="clh_callFailed_protocol_Error_unspecified_txt" msgid="9203320572562697755">"कल पूरा गर्न सकिएन। त्रुटिको कोड: १११।"</string>
     <string name="clh_callFailed_interworking_unspecified_txt" msgid="7969686413930847182">"कल पूरा गर्न सकिएन। त्रुटिको कोड: १२७।"</string>
     <string name="labelCallBarring" msgid="4180377113052853173">"कल ब्यारिङ"</string>
-    <string name="sum_call_barring_enabled" msgid="5184331188926370824">"सक्रिय छ"</string>
-    <string name="sum_call_barring_disabled" msgid="5699448000600153096">"निष्क्रिय छ"</string>
+    <string name="sum_call_barring_enabled" msgid="5184331188926370824">"अन छ"</string>
+    <string name="sum_call_barring_disabled" msgid="5699448000600153096">"अफ छ"</string>
     <string name="call_barring_baoc" msgid="7400892586336429326">"सबै बहिर्गमन"</string>
     <string name="call_barring_baoc_enabled" msgid="3131509193386668182">"सबै बहिर्गमन कलहरूमाथिको रोक असक्षम पार्ने हो?"</string>
     <string name="call_barring_baoc_disabled" msgid="8534224684091141509">"सबै बहिर्गमन कलहरूमाथि रोक लगाउने हो?"</string>
@@ -863,7 +863,7 @@
     <string name="radioInfo_service_in" msgid="45753418231446400">"सेवामा"</string>
     <string name="radioInfo_service_out" msgid="287972405416142312">"सेवा उपलब्ध छैन"</string>
     <string name="radioInfo_service_emergency" msgid="4763879891415016848">"आपत्‌कालीन कल मात्र"</string>
-    <string name="radioInfo_service_off" msgid="3456583511226783064">"रेडियो निष्क्रिय छ"</string>
+    <string name="radioInfo_service_off" msgid="3456583511226783064">"रेडियो अफ छ"</string>
     <string name="radioInfo_roaming_in" msgid="3156335577793145965">"रोमिङ"</string>
     <string name="radioInfo_roaming_not" msgid="1904547918725478110">"रोमिङमा छैन"</string>
     <string name="radioInfo_phone_idle" msgid="2191653783170757819">"निष्क्रिय"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index 966aa1555..ecd6673f8 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -44,8 +44,8 @@
     <string name="pause_prompt_yes" msgid="8184132073048369575">"Sim"</string>
     <string name="pause_prompt_no" msgid="2145264674774138579">"Não"</string>
     <string name="wild_prompt_str" msgid="5858910969703305375">"Substituir caractere curinga por"</string>
-    <string name="no_vm_number" msgid="6623853880546176930">"Número correio de voz ausente"</string>
-    <string name="no_vm_number_msg" msgid="5165161462411372504">"Não há um número correio de voz armazenado no chip."</string>
+    <string name="no_vm_number" msgid="6623853880546176930">"Não há um número do correio de voz"</string>
+    <string name="no_vm_number_msg" msgid="5165161462411372504">"Não há um número do correio de voz armazenado no chip."</string>
     <string name="add_vm_number_str" msgid="7368168964435881637">"Adicionar número"</string>
     <string name="voice_number_setting_primary_user_only" msgid="3394706575741912843">"As configurações do correio de voz só podem ser modificadas pelo usuário principal."</string>
     <string name="puk_unlocked" msgid="4627340655215746511">"O seu chip foi desbloqueado. O seu telefone está desbloqueando…"</string>
@@ -157,7 +157,7 @@
     <item msgid="6813323051965618926">"Ocultar número"</item>
     <item msgid="9150034130629852635">"Mostrar número"</item>
   </string-array>
-    <string name="vm_changed" msgid="4739599044379692505">"Número correio de voz alterado."</string>
+    <string name="vm_changed" msgid="4739599044379692505">"Número do correio de voz alterado."</string>
     <string name="vm_change_failed" msgid="7877733929455763566">"Não foi possível alterar o número do correio de voz.\nEntre em contato com sua operadora se o problema persistir."</string>
     <string name="fw_change_failed" msgid="9179241823460192148">"Não foi possível alterar o número de encaminhamento.\nEntre em contato com sua operadora se o problema persistir."</string>
     <string name="fw_get_in_vm_failed" msgid="2432678237218183844">"Não foi possível recuperar e salvar as configurações de número atual de encaminhamento.\nMudar para o novo provedor?"</string>
@@ -521,7 +521,7 @@
     <string name="pin2_unblocked" msgid="4481107908727789303">"PIN2 não mais bloqueado"</string>
     <string name="pin2_error_exception" msgid="8116103864600823641">"Erro de rede ou do chip"</string>
     <string name="doneButton" msgid="7371209609238460207">"Concluído"</string>
-    <string name="voicemail_settings_number_label" msgid="1265118640154688162">"Número correio de voz"</string>
+    <string name="voicemail_settings_number_label" msgid="1265118640154688162">"Número do correio de voz"</string>
     <string name="card_title_dialing" msgid="8742182654254431781">"Chamando..."</string>
     <string name="card_title_redialing" msgid="18130232613559964">"Rediscando"</string>
     <string name="card_title_conf_call" msgid="901197309274457427">"Teleconferência"</string>
@@ -533,7 +533,7 @@
     <string name="notification_voicemail_title" msgid="3932876181831601351">"Novo correio de voz"</string>
     <string name="notification_voicemail_title_count" msgid="2806950319222327082">"Novo correio de voz (<xliff:g id="COUNT">%d</xliff:g>)"</string>
     <string name="notification_voicemail_text_format" msgid="5720947141702312537">"Discar <xliff:g id="VOICEMAIL_NUMBER">%s</xliff:g>"</string>
-    <string name="notification_voicemail_no_vm_number" msgid="3423686009815186750">"Número correio de voz desconhecido"</string>
+    <string name="notification_voicemail_no_vm_number" msgid="3423686009815186750">"Número do correio de voz desconhecido"</string>
     <string name="notification_network_selection_title" msgid="255595526707809121">"Sem serviço"</string>
     <string name="notification_network_selection_text" msgid="553288408722427659">"A rede selecionada (<xliff:g id="OPERATOR_NAME">%s</xliff:g>) não está disponível"</string>
     <string name="incall_error_power_off" product="watch" msgid="7191184639454113633">"Ative a rede móvel e desative o modo avião ou o modo de economia de bateria para ligar."</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index a5c21a2a8..9e2e94379 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -271,7 +271,7 @@
     <string name="preferred_network_mode_nr_lte_tdscdma_wcdma_summary" msgid="5912457779733343522">"Föredraget nätverksläge: NR/LTE/TDSCDMA/WCDMA"</string>
     <string name="preferred_network_mode_nr_lte_tdscdma_gsm_wcdma_summary" msgid="6769797110309412576">"Föredraget nätverksläge: NR/LTE/TDSCDMA/GSM/WCDMA"</string>
     <string name="preferred_network_mode_nr_lte_tdscdma_cdma_evdo_gsm_wcdma_summary" msgid="4260661428277578573">"Föredraget nätverksläge: NR/LTE/TDSCDMA/CDMA/EvDo/GSM/WCDMA"</string>
-    <string name="call_category" msgid="4394703838833058138">"Ringer upp"</string>
+    <string name="call_category" msgid="4394703838833058138">"Samtal"</string>
     <string name="network_operator_category" msgid="4992217193732304680">"Nätverk"</string>
     <string name="enhanced_4g_lte_mode_title" msgid="4213420368777080540">"Förbättrat 4G LTE-läge"</string>
     <!-- no translation found for enhanced_4g_lte_mode_title_variant:0 (7240155150166394308) -->
diff --git a/res/values/config.xml b/res/values/config.xml
index 847c4c525..4691f3dad 100644
--- a/res/values/config.xml
+++ b/res/values/config.xml
@@ -394,4 +394,13 @@
 
     <!-- Whether to turn off OEM-enabled satellite during emergency call -->
     <bool name="config_turn_off_oem_enabled_satellite_during_emergency_call">false</bool>
+
+    <!-- The timeout duration in milliseconds used to determine how long does it wait for modem to
+         get in-service state when dialing emergency routing emergency calls in airplane mode before
+         starting the call. If the value is 0, it doesn't wait and starts the call right after
+         turning radio power on. -->
+    <integer name="config_in_service_wait_timer_when_dialing_emergency_routing_ecc_in_apm">3000</integer>
+
+    <!-- Whether to turn off non-emergency nb iot ntn satellite for emergency call -->
+    <bool name="config_turn_off_non_emergency_nb_iot_ntn_satellite_for_emergency_call">true</bool>
 </resources>
diff --git a/src/com/android/phone/CarrierConfigLoader.java b/src/com/android/phone/CarrierConfigLoader.java
index c6c26b093..3a908d23d 100644
--- a/src/com/android/phone/CarrierConfigLoader.java
+++ b/src/com/android/phone/CarrierConfigLoader.java
@@ -23,6 +23,7 @@ import static android.telephony.TelephonyManager.ENABLE_FEATURE_MAPPING;
 
 import android.annotation.NonNull;
 import android.annotation.Nullable;
+import android.app.ActivityManager;
 import android.app.AppOpsManager;
 import android.app.compat.CompatChanges;
 import android.content.BroadcastReceiver;
@@ -899,8 +900,11 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
             mServiceConnection[phoneId] = serviceConnection;
         }
         try {
-            if (mContext.bindService(carrierService, serviceConnection,
-                    Context.BIND_AUTO_CREATE)) {
+            if (mFeatureFlags.supportCarrierServicesForHsum()
+                    ? mContext.bindServiceAsUser(carrierService, serviceConnection,
+                    Context.BIND_AUTO_CREATE, UserHandle.of(ActivityManager.getCurrentUser()))
+                    : mContext.bindService(carrierService, serviceConnection,
+                            Context.BIND_AUTO_CREATE)) {
                 if (eventId == EVENT_CONNECTED_TO_DEFAULT_FOR_NO_SIM_CONFIG) {
                     mServiceBoundForNoSimConfig[phoneId] = true;
                 } else {
@@ -1261,7 +1265,10 @@ public class CarrierConfigLoader extends ICarrierConfigLoader.Stub {
     @Nullable
     private String getPackageVersion(@NonNull String packageName) {
         try {
-            PackageInfo info = mContext.getPackageManager().getPackageInfo(packageName, 0);
+            PackageInfo info = mFeatureFlags.supportCarrierServicesForHsum()
+                    ? mContext.getPackageManager().getPackageInfoAsUser(packageName, 0,
+                    ActivityManager.getCurrentUser())
+                    : mContext.getPackageManager().getPackageInfo(packageName, 0);
             return Long.toString(info.getLongVersionCode());
         } catch (PackageManager.NameNotFoundException e) {
             return null;
diff --git a/src/com/android/phone/EmergencyCallbackModeExitDialog.java b/src/com/android/phone/EmergencyCallbackModeExitDialog.java
index 6901789da..6918d48aa 100644
--- a/src/com/android/phone/EmergencyCallbackModeExitDialog.java
+++ b/src/com/android/phone/EmergencyCallbackModeExitDialog.java
@@ -252,7 +252,8 @@ public class EmergencyCallbackModeExitDialog extends Activity implements OnCance
                                     if (DomainSelectionResolver.getInstance()
                                             .isDomainSelectionSupported()) {
                                         EmergencyStateTracker.getInstance()
-                                                .exitEmergencyCallbackMode();
+                                                .exitEmergencyCallbackMode(
+                                                        TelephonyManager.STOP_REASON_USER_ACTION);
                                     } else {
                                         mPhone.exitEmergencyCallbackMode();
                                     }
diff --git a/src/com/android/phone/EventLogTags.logtags b/src/com/android/phone/EventLogTags.logtags
index 474a01cd7..f7654afb8 100644
--- a/src/com/android/phone/EventLogTags.logtags
+++ b/src/com/android/phone/EventLogTags.logtags
@@ -1,4 +1,4 @@
-# See system/core/logcat/event.logtags for a description of the format of this file.
+# See system/logging/logcat/event.logtags for a description of the format of this file.
 
 option java_package com.android.phone;
 
diff --git a/src/com/android/phone/NotificationMgr.java b/src/com/android/phone/NotificationMgr.java
index 3c7b321c7..188baaad0 100644
--- a/src/com/android/phone/NotificationMgr.java
+++ b/src/com/android/phone/NotificationMgr.java
@@ -439,7 +439,10 @@ public class NotificationMgr {
                 mUserManager.getSerialNumbersOfUsers(/* excludeDying= */ true);
         List<UserHandle> users = new ArrayList<>(serialNumbersOfUsers.length);
         for (long serialNumber : serialNumbersOfUsers) {
-            users.add(mUserManager.getUserForSerialNumber(serialNumber));
+            UserHandle userHandle = mUserManager.getUserForSerialNumber(serialNumber);
+            if (userHandle != null) {
+                users.add(userHandle);
+            }
         }
         return users;
     }
@@ -878,7 +881,9 @@ public class NotificationMgr {
                             + (isManualSelection ? selectedNetworkOperatorName : ""));
                 }
 
-                if (isManualSelection) {
+                if (isManualSelection
+                        && isSubscriptionVisibleToUser(
+                              mSubscriptionManager.getActiveSubscriptionInfo(subId))) {
                     mSelectedNetworkOperatorName.put(subId, selectedNetworkOperatorName);
                     shouldShowNotification(serviceState, subId);
                 } else {
@@ -934,7 +939,9 @@ public class NotificationMgr {
                             + (isManualSelection ? selectedNetworkOperatorName : ""));
                 }
 
-                if (isManualSelection) {
+                if (isManualSelection
+                        && isSubscriptionVisibleToUser(
+                              mSubscriptionManager.getActiveSubscriptionInfo(subId))) {
                     mSelectedNetworkOperatorName.put(subId, selectedNetworkOperatorName);
                     shouldShowNotification(serviceState, subId);
                 } else {
@@ -949,6 +956,12 @@ public class NotificationMgr {
         }
     }
 
+    // TODO(b/261916533) This should be handled by SubscriptionManager#isSubscriptionVisible(),
+    // but that method doesn't support system callers, so here we are.
+    private boolean isSubscriptionVisibleToUser(SubscriptionInfo subInfo) {
+        return subInfo != null && (!subInfo.isOpportunistic() || subInfo.getGroupUuid() == null);
+    }
+
     private void dismissNetworkSelectionNotification(int subId) {
         if (mSelectedUnavailableNotify.get(subId, false)) {
             cancelNetworkSelection(subId);
diff --git a/src/com/android/phone/PhoneGlobals.java b/src/com/android/phone/PhoneGlobals.java
index 0433a3308..bab260ce2 100644
--- a/src/com/android/phone/PhoneGlobals.java
+++ b/src/com/android/phone/PhoneGlobals.java
@@ -44,6 +44,7 @@ import android.sysprop.TelephonyProperties;
 import android.telecom.TelecomManager;
 import android.telephony.AnomalyReporter;
 import android.telephony.CarrierConfigManager;
+import android.telephony.NetworkRegistrationInfo;
 import android.telephony.ServiceState;
 import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
@@ -373,12 +374,16 @@ public class PhoneGlobals extends ContextWrapper {
                     break;
 
                 case EVENT_DATA_ROAMING_DISCONNECTED:
+                    Log.d(LOG_TAG, "EVENT_DATA_ROAMING_DISCONNECTED");
                     if (SubscriptionManagerService.getInstance()
                             .isEsimBootStrapProvisioningActiveForSubId(msg.arg1)) {
                         Log.i(LOG_TAG,
                                 "skip notification/warnings during esim bootstrap activation");
+                    } else if (skipDataRoamingDisconnectedNotificationInSatelliteMode((msg.arg1))) {
+                        Log.i(LOG_TAG, "skip data roaming disconnected notification when device is "
+                                + "connected to satellite network that does not support data.");
                     } else {
-                        notificationMgr.showDataRoamingNotification(msg.arg1, false);
+                        notificationMgr.showDataRoamingNotification((msg.arg1), false);
                     }
                     break;
 
@@ -566,7 +571,10 @@ public class PhoneGlobals extends ContextWrapper {
                 // Initialize EmergencyStateTracker if domain selection is supported
                 boolean isSuplDdsSwitchRequiredForEmergencyCall = getResources()
                         .getBoolean(R.bool.config_gnss_supl_requires_default_data_for_emergency);
-                EmergencyStateTracker.make(this, isSuplDdsSwitchRequiredForEmergencyCall);
+                int inServiceWaitTimeWhenDialEccInApm = getResources().getInteger(R.integer
+                        .config_in_service_wait_timer_when_dialing_emergency_routing_ecc_in_apm);
+                EmergencyStateTracker.make(this, isSuplDdsSwitchRequiredForEmergencyCall,
+                        inServiceWaitTimeWhenDialEccInApm, mFeatureFlags);
                 DynamicRoutingController.getInstance().initialize(this);
             }
 
@@ -1495,4 +1503,32 @@ public class PhoneGlobals extends ContextWrapper {
         }
         pw.println("------- End PhoneGlobals -------");
     }
+
+    private boolean skipDataRoamingDisconnectedNotificationInSatelliteMode(int subId) {
+        SatelliteController satelliteController = SatelliteController.getInstance();
+        if (satelliteController.isSatelliteEnabledOrBeingEnabled()) {
+            Log.d(LOG_TAG, "skipDataRoamingDisconnected - skip notification as "
+                    + "satellite is enabled or being enabled");
+            return true;
+        }
+
+        int phoneId = SubscriptionManager.getPhoneId(subId);
+        Phone phone = PhoneFactory.getPhone(phoneId);
+        ServiceState serviceState = phone.getServiceState();
+        if (serviceState != null && serviceState.isUsingNonTerrestrialNetwork()) {
+            Log.d(LOG_TAG, "skipDataRoamingDisconnected - isUsingNtn");
+            List<Integer> capabilities =
+                    satelliteController.getCapabilitiesForCarrierRoamingSatelliteMode(phone);
+            if (!capabilities.contains(NetworkRegistrationInfo.SERVICE_TYPE_DATA)) {
+                // Skip data roaming disconnected notification as device is connected to
+                // non-terrestrial network that does not support data.
+                Log.d(LOG_TAG, "skipDataRoamingDisconnected - skip notification as "
+                        + "NTN does not support data");
+                return true;
+            }
+        }
+
+        Log.d(LOG_TAG, "skipDataRoamingDisconnected - do not skip notification.");
+        return false;
+    }
 }
diff --git a/src/com/android/phone/PhoneInterfaceManager.java b/src/com/android/phone/PhoneInterfaceManager.java
index 4624884eb..bafcc6f76 100644
--- a/src/com/android/phone/PhoneInterfaceManager.java
+++ b/src/com/android/phone/PhoneInterfaceManager.java
@@ -26,6 +26,9 @@ import static android.telephony.TelephonyManager.HAL_SERVICE_RADIO;
 import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_COMMUNICATION_ALLOWED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_ACCESS_BARRED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_SUCCESS;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP;
 
 import static com.android.internal.telephony.PhoneConstants.PHONE_TYPE_CDMA;
 import static com.android.internal.telephony.PhoneConstants.PHONE_TYPE_GSM;
@@ -158,10 +161,12 @@ import android.telephony.satellite.INtnSignalStrengthCallback;
 import android.telephony.satellite.ISatelliteCapabilitiesCallback;
 import android.telephony.satellite.ISatelliteCommunicationAllowedStateCallback;
 import android.telephony.satellite.ISatelliteDatagramCallback;
+import android.telephony.satellite.ISatelliteDisallowedReasonsCallback;
 import android.telephony.satellite.ISatelliteModemStateCallback;
 import android.telephony.satellite.ISatelliteProvisionStateCallback;
 import android.telephony.satellite.ISatelliteSupportedStateCallback;
 import android.telephony.satellite.ISatelliteTransmissionUpdateCallback;
+import android.telephony.satellite.ISelectedNbIotSatelliteSubscriptionCallback;
 import android.telephony.satellite.NtnSignalStrength;
 import android.telephony.satellite.NtnSignalStrengthCallback;
 import android.telephony.satellite.SatelliteCapabilities;
@@ -442,6 +447,9 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     private PackageManager mPackageManager;
     private final int mVendorApiLevel;
 
+    @Nullable
+    private ComponentName mTestEuiccUiComponent;
+
     /** User Activity */
     private final AtomicBoolean mNotifyUserActivity;
     private static final int USER_ACTIVITY_NOTIFICATION_DELAY = 200;
@@ -475,7 +483,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public static final String RESET_NETWORK_ERASE_MODEM_CONFIG_ENABLED =
             "reset_network_erase_modem_config_enabled";
 
-    private static final int SET_NETWORK_SELECTION_MODE_AUTOMATIC_TIMEOUT_MS = 2000; // 2 seconds
+    private static final int BLOCKING_REQUEST_DEFAULT_TIMEOUT_MS = 2000; // 2 seconds
 
     private static final int MODEM_ACTIVITY_TIME_OFFSET_CORRECTION_MS = 50;
 
@@ -949,12 +957,14 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                     break;
 
                 case CMD_NV_WRITE_CDMA_PRL:
+                    if (mFeatureFlags.cleanupCdma()) break;
                     request = (MainThreadRequest) msg.obj;
                     onCompleted = obtainMessage(EVENT_NV_WRITE_CDMA_PRL_DONE, request);
                     defaultPhone.nvWriteCdmaPrl((byte[]) request.argument, onCompleted);
                     break;
 
                 case EVENT_NV_WRITE_CDMA_PRL_DONE:
+                    if (mFeatureFlags.cleanupCdma()) break;
                     handleNullReturnEvent(msg, "nvWriteCdmaPrl");
                     break;
 
@@ -1707,11 +1717,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                     notifyRequester(request);
                     break;
                 case CMD_GET_CDMA_ROAMING_MODE:
+                    if (mFeatureFlags.cleanupCdma()) break;
                     request = (MainThreadRequest) msg.obj;
                     onCompleted = obtainMessage(EVENT_GET_CDMA_ROAMING_MODE_DONE, request);
                     getPhoneFromRequest(request).queryCdmaRoamingPreference(onCompleted);
                     break;
                 case EVENT_GET_CDMA_ROAMING_MODE_DONE:
+                    if (mFeatureFlags.cleanupCdma()) break;
                     ar = (AsyncResult) msg.obj;
                     request = (MainThreadRequest) ar.userObj;
                     if (ar.exception != null) {
@@ -1722,23 +1734,27 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                     notifyRequester(request);
                     break;
                 case CMD_SET_CDMA_ROAMING_MODE:
+                    if (mFeatureFlags.cleanupCdma()) break;
                     request = (MainThreadRequest) msg.obj;
                     onCompleted = obtainMessage(EVENT_SET_CDMA_ROAMING_MODE_DONE, request);
                     int mode = (int) request.argument;
                     getPhoneFromRequest(request).setCdmaRoamingPreference(mode, onCompleted);
                     break;
                 case EVENT_SET_CDMA_ROAMING_MODE_DONE:
+                    if (mFeatureFlags.cleanupCdma()) break;
                     ar = (AsyncResult) msg.obj;
                     request = (MainThreadRequest) ar.userObj;
                     request.result = ar.exception == null;
                     notifyRequester(request);
                     break;
                 case CMD_GET_CDMA_SUBSCRIPTION_MODE:
+                    if (mFeatureFlags.cleanupCdma()) break;
                     request = (MainThreadRequest) msg.obj;
                     onCompleted = obtainMessage(EVENT_GET_CDMA_SUBSCRIPTION_MODE_DONE, request);
                     getPhoneFromRequest(request).queryCdmaSubscriptionMode(onCompleted);
                     break;
                 case EVENT_GET_CDMA_SUBSCRIPTION_MODE_DONE:
+                    if (mFeatureFlags.cleanupCdma()) break;
                     ar = (AsyncResult) msg.obj;
                     request = (MainThreadRequest) ar.userObj;
                     if (ar.exception != null) {
@@ -1749,6 +1765,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                     notifyRequester(request);
                     break;
                 case CMD_SET_CDMA_SUBSCRIPTION_MODE:
+                    if (mFeatureFlags.cleanupCdma()) break;
                     request = (MainThreadRequest) msg.obj;
                     onCompleted = obtainMessage(EVENT_SET_CDMA_SUBSCRIPTION_MODE_DONE, request);
                     int subscriptionMode = (int) request.argument;
@@ -1756,6 +1773,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                             subscriptionMode, onCompleted);
                     break;
                 case EVENT_SET_CDMA_SUBSCRIPTION_MODE_DONE:
+                    if (mFeatureFlags.cleanupCdma()) break;
                     ar = (AsyncResult) msg.obj;
                     request = (MainThreadRequest) ar.userObj;
                     request.result = ar.exception == null;
@@ -1828,7 +1846,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                 }
                 case CMD_MODEM_REBOOT:
                     request = (MainThreadRequest) msg.obj;
-                    onCompleted = obtainMessage(EVENT_RESET_MODEM_CONFIG_DONE, request);
+                    onCompleted = obtainMessage(EVENT_CMD_MODEM_REBOOT_DONE, request);
                     defaultPhone.rebootModem(onCompleted);
                     break;
                 case EVENT_CMD_MODEM_REBOOT_DONE:
@@ -2569,6 +2587,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     }
 
     private void sendEraseModemConfig(@NonNull Phone phone) {
+        if (mFeatureFlags.cleanupCdma()) return;
         Boolean success = (Boolean) sendRequest(CMD_ERASE_MODEM_CONFIG, null);
         if (DBG) log("eraseModemConfig:" + ' ' + (success ? "ok" : "fail"));
     }
@@ -3676,9 +3695,6 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             return null;
         }
 
-        enforceTelephonyFeatureWithException(callingPackage,
-                PackageManager.FEATURE_TELEPHONY_GSM, "getImeiForSlot");
-
         final long identity = Binder.clearCallingIdentity();
         try {
             return phone.getImei();
@@ -3695,9 +3711,6 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             throw new SecurityException("Caller does not have permission");
         }
 
-        enforceTelephonyFeatureWithException(callingPackage,
-                PackageManager.FEATURE_TELEPHONY_GSM, "getPrimaryImei");
-
         final long identity = Binder.clearCallingIdentity();
         try {
             for (Phone phone : PhoneFactory.getPhones()) {
@@ -3713,9 +3726,6 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
     @Override
     public String getTypeAllocationCodeForSlot(int slotIndex) {
-        enforceTelephonyFeatureWithException(getCurrentPackageName(),
-                PackageManager.FEATURE_TELEPHONY_GSM, "getTypeAllocationCodeForSlot");
-
         Phone phone = PhoneFactory.getPhone(slotIndex);
         String tac = null;
         if (phone != null) {
@@ -3732,6 +3742,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
     @Override
     public String getMeidForSlot(int slotIndex, String callingPackage, String callingFeatureId) {
+        if (mFeatureFlags.cleanupCdma()) return null;
+
         try {
             mAppOps.checkPackage(Binder.getCallingUid(), callingPackage);
         } catch (SecurityException se) {
@@ -3763,6 +3775,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
     @Override
     public String getManufacturerCodeForSlot(int slotIndex) {
+        if (mFeatureFlags.cleanupCdma()) return null;
+
         enforceTelephonyFeatureWithException(getCurrentPackageName(),
                 PackageManager.FEATURE_TELEPHONY_CDMA, "getManufacturerCodeForSlot");
 
@@ -4033,6 +4047,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     public int getCdmaEriIconIndex(String callingPackage, String callingFeatureId) {
+        if (mFeatureFlags.cleanupCdma()) return -1;
         return getCdmaEriIconIndexForSubscriber(getDefaultSubscription(), callingPackage,
                 callingFeatureId);
     }
@@ -4040,6 +4055,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public int getCdmaEriIconIndexForSubscriber(int subId, String callingPackage,
             String callingFeatureId) {
+        if (mFeatureFlags.cleanupCdma()) return -1;
+
         if (!TelephonyPermissions.checkCallingOrSelfReadPhoneState(
                 mApp, subId, callingPackage, callingFeatureId,
                 "getCdmaEriIconIndexForSubscriber")) {
@@ -4070,6 +4087,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     public int getCdmaEriIconMode(String callingPackage, String callingFeatureId) {
+        if (mFeatureFlags.cleanupCdma()) return -1;
         return getCdmaEriIconModeForSubscriber(getDefaultSubscription(), callingPackage,
                 callingFeatureId);
     }
@@ -4077,6 +4095,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public int getCdmaEriIconModeForSubscriber(int subId, String callingPackage,
             String callingFeatureId) {
+        if (mFeatureFlags.cleanupCdma()) return -1;
+
         if (!TelephonyPermissions.checkCallingOrSelfReadPhoneState(
                 mApp, subId, callingPackage, callingFeatureId,
                 "getCdmaEriIconModeForSubscriber")) {
@@ -4101,6 +4121,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     public String getCdmaEriText(String callingPackage, String callingFeatureId) {
+        if (mFeatureFlags.cleanupCdma()) return null;
         return getCdmaEriTextForSubscriber(getDefaultSubscription(), callingPackage,
                 callingFeatureId);
     }
@@ -4108,6 +4129,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public String getCdmaEriTextForSubscriber(int subId, String callingPackage,
             String callingFeatureId) {
+        if (mFeatureFlags.cleanupCdma()) return null;
+
         if (!TelephonyPermissions.checkCallingOrSelfReadPhoneState(
                 mApp, subId, callingPackage, callingFeatureId,
                 "getCdmaEriIconTextForSubscriber")) {
@@ -4132,6 +4155,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     public String getCdmaMdn(int subId) {
+        if (mFeatureFlags.cleanupCdma()) return null;
+
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(
                 mApp, subId, "getCdmaMdn");
 
@@ -4157,6 +4182,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     public String getCdmaMin(int subId) {
+        if (mFeatureFlags.cleanupCdma()) return null;
+
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(
                 mApp, subId, "getCdmaMin");
 
@@ -4233,8 +4260,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
         final long identity = Binder.clearCallingIdentity();
         try {
-            Boolean success = (Boolean) sendRequest(CMD_SET_VOICEMAIL_NUMBER,
-                    new Pair<String, String>(alphaTag, number), new Integer(subId));
+            Boolean success = (Boolean) sendRequest(
+                    CMD_SET_VOICEMAIL_NUMBER,
+                    new Pair<String, String>(alphaTag, number),
+                    new Integer(subId),
+                    BLOCKING_REQUEST_DEFAULT_TIMEOUT_MS);
+            if (success == null) return false; // most likely due to a timeout
             return success;
         } finally {
             Binder.restoreCallingIdentity(identity);
@@ -6381,6 +6412,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     public String nvReadItem(int itemID) {
+        if (mFeatureFlags.cleanupCdma()) return null;
+
         WorkSource workSource = getWorkSource(Binder.getCallingUid());
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(
                 mApp, getDefaultSubscription(), "nvReadItem");
@@ -6406,6 +6439,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     public boolean nvWriteItem(int itemID, String itemValue) {
+        if (mFeatureFlags.cleanupCdma()) return false;
+
         WorkSource workSource = getWorkSource(Binder.getCallingUid());
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(
                 mApp, getDefaultSubscription(), "nvWriteItem");
@@ -6431,6 +6466,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     public boolean nvWriteCdmaPrl(byte[] preferredRoamingList) {
+        if (mFeatureFlags.cleanupCdma()) return false;
+
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(
                 mApp, getDefaultSubscription(), "nvWriteCdmaPrl");
 
@@ -6455,6 +6492,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     public boolean resetModemConfig(int slotIndex) {
+        if (mFeatureFlags.cleanupCdma()) return false;
         Phone phone = PhoneFactory.getPhone(slotIndex);
         if (phone != null) {
             TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(
@@ -6642,6 +6680,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      * Sets the ImsService Package Name that Telephony will bind to.
      *
      * @param slotIndex the slot ID that the ImsService should bind for.
+     * @param userId the user ID that the ImsService should bind for or {@link UserHandle#USER_NULL}
+     *               if there is no preference.
      * @param isCarrierService true if the ImsService is the carrier override, false if the
      *         ImsService is the device default ImsService.
      * @param featureTypes An integer array of feature types associated with a packageName.
@@ -6649,7 +6689,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      *                    with.
      * @return true if setting the ImsService to bind to succeeded, false if it did not.
      */
-    public boolean setBoundImsServiceOverride(int slotIndex, boolean isCarrierService,
+    public boolean setBoundImsServiceOverride(int slotIndex, int userId, boolean isCarrierService,
             int[] featureTypes, String packageName) {
         TelephonyPermissions.enforceShellOnly(Binder.getCallingUid(), "setBoundImsServiceOverride");
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
@@ -6661,12 +6701,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                 // may happen if the device does not support IMS.
                 return false;
             }
-            Map<Integer, String> featureConfig = new HashMap<>();
-            for (int featureType : featureTypes) {
-                featureConfig.put(featureType, packageName);
-            }
-            return mImsResolver.overrideImsServiceConfiguration(slotIndex, isCarrierService,
-                    featureConfig);
+            return mImsResolver.overrideImsServiceConfiguration(packageName, slotIndex, userId,
+                    isCarrierService, featureTypes);
         } finally {
             Binder.restoreCallingIdentity(identity);
         }
@@ -6804,7 +6840,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             }
             if (DBG) log("setNetworkSelectionModeAutomatic: subId " + subId);
             sendRequest(CMD_SET_NETWORK_SELECTION_MODE_AUTOMATIC, null, subId,
-                    SET_NETWORK_SELECTION_MODE_AUTOMATIC_TIMEOUT_MS);
+                    BLOCKING_REQUEST_DEFAULT_TIMEOUT_MS);
         } finally {
             Binder.restoreCallingIdentity(identity);
         }
@@ -7739,6 +7775,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public List<String> getPackagesWithCarrierPrivileges(int phoneId) {
         enforceReadPrivilegedPermission("getPackagesWithCarrierPrivileges");
+
+        enforceTelephonyFeatureWithException(
+                getCurrentPackageName(),
+                PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION,
+                "getPackagesWithCarrierPrivileges");
+
         Phone phone = PhoneFactory.getPhone(phoneId);
         if (phone == null) {
             return Collections.emptyList();
@@ -8592,9 +8634,10 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                 setNetworkSelectionModeAutomatic(subId);
                 Phone phone = getPhone(subId);
                 cleanUpAllowedNetworkTypes(phone, subId);
+
                 setDataRoamingEnabled(subId, phone == null ? false
                         : phone.getDataSettingsManager().isDefaultDataRoamingEnabled());
-                getPhone(subId).resetCarrierKeysForImsiEncryption();
+                getPhone(subId).resetCarrierKeysForImsiEncryption(true);
             }
             // There has been issues when Sms raw table somehow stores orphan
             // fragments. They lead to garbled message when new fragments come
@@ -9158,10 +9201,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             }
             String aid = null;
             try {
-                aid = UiccController.getInstance().getUiccPort(phone.getPhoneId())
-                        .getApplicationByType(appType).getAid();
+                UiccCardApplication app = UiccController.getInstance()
+                        .getUiccPort(phone.getPhoneId()).getApplicationByType(appType);
+                if (app == null) return null;
+                aid = app.getAid();
             } catch (Exception e) {
-                Log.e(LOG_TAG, "Not getting aid. Exception ex=" + e);
+                Log.e(LOG_TAG, "Not getting aid", e);
             }
             return aid;
         } finally {
@@ -9189,7 +9234,7 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             try {
                 esn = phone.getEsn();
             } catch (Exception e) {
-                Log.e(LOG_TAG, "Not getting ESN. Exception ex=" + e);
+                Log.e(LOG_TAG, "Not getting ESN", e);
             }
             return esn;
         } finally {
@@ -9205,6 +9250,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     public String getCdmaPrlVersion(int subId) {
+        if (mFeatureFlags.cleanupCdma()) return null;
+
         enforceReadPrivilegedPermission("getCdmaPrlVersion");
 
         enforceTelephonyFeatureWithException(getCurrentPackageName(),
@@ -10316,6 +10363,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
     @Override
     public int getCdmaRoamingMode(int subId) {
+        if (mFeatureFlags.cleanupCdma()) return TelephonyManager.CDMA_ROAMING_MODE_RADIO_DEFAULT;
+
         TelephonyPermissions
                 .enforceCallingOrSelfReadPrivilegedPhoneStatePermissionOrCarrierPrivilege(
                         mApp, subId, "getCdmaRoamingMode");
@@ -10333,6 +10382,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
     @Override
     public boolean setCdmaRoamingMode(int subId, int mode) {
+        if (mFeatureFlags.cleanupCdma()) return false;
+
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(
                 mApp, subId, "setCdmaRoamingMode");
 
@@ -10349,6 +10400,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
     @Override
     public int getCdmaSubscriptionMode(int subId) {
+        if (mFeatureFlags.cleanupCdma()) return TelephonyManager.CDMA_SUBSCRIPTION_UNKNOWN;
+
         TelephonyPermissions
                 .enforceCallingOrSelfReadPrivilegedPhoneStatePermissionOrCarrierPrivilege(
                         mApp, subId, "getCdmaSubscriptionMode");
@@ -10366,6 +10419,8 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
 
     @Override
     public boolean setCdmaSubscriptionMode(int subId, int mode) {
+        if (mFeatureFlags.cleanupCdma()) return false;
+
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(
                 mApp, subId, "setCdmaSubscriptionMode");
 
@@ -11696,10 +11751,10 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public boolean setBoundGbaServiceOverride(int subId, String packageName) {
         enforceModifyPermission();
-
+        int userId = ActivityManager.getCurrentUser();
         final long identity = Binder.clearCallingIdentity();
         try {
-            return getGbaManager(subId).overrideServicePackage(packageName);
+            return getGbaManager(subId).overrideServicePackage(packageName, userId);
         } finally {
             Binder.restoreCallingIdentity(identity);
         }
@@ -13196,40 +13251,70 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public void requestSatelliteEnabled(boolean enableSatellite, boolean enableDemoMode,
             boolean isEmergency, @NonNull IIntegerConsumer callback) {
         enforceSatelliteCommunicationPermission("requestSatelliteEnabled");
-        if (enableSatellite) {
-            ResultReceiver resultReceiver = new ResultReceiver(mMainThreadHandler) {
-                @Override
-                protected void onReceiveResult(int resultCode, Bundle resultData) {
-                    Log.d(LOG_TAG, "Satellite access restriction resultCode=" + resultCode
-                            + ", resultData=" + resultData);
-                    boolean isAllowed = false;
-                    Consumer<Integer> result = FunctionalUtils.ignoreRemoteException(
-                            callback::accept);
-                    if (resultCode == SATELLITE_RESULT_SUCCESS) {
-                        if (resultData != null
-                                && resultData.containsKey(KEY_SATELLITE_COMMUNICATION_ALLOWED)) {
-                            isAllowed = resultData.getBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            if (enableSatellite) {
+                String caller = "PIM:requestSatelliteEnabled";
+                ResultReceiver resultReceiver = new ResultReceiver(mMainThreadHandler) {
+                    @Override
+                    protected void onReceiveResult(int resultCode, Bundle resultData) {
+                        Log.d(LOG_TAG, "Satellite access restriction resultCode=" + resultCode
+                                + ", resultData=" + resultData);
+                        mSatelliteController.decrementResultReceiverCount(caller);
+
+                        boolean isAllowed = false;
+                        Consumer<Integer> result = FunctionalUtils.ignoreRemoteException(
+                                callback::accept);
+                        if (resultCode == SATELLITE_RESULT_SUCCESS) {
+                            if (resultData != null
+                                    && resultData.containsKey(
+                                    KEY_SATELLITE_COMMUNICATION_ALLOWED)) {
+                                isAllowed = resultData.getBoolean(
+                                        KEY_SATELLITE_COMMUNICATION_ALLOWED);
+                            } else {
+                                loge("KEY_SATELLITE_COMMUNICATION_ALLOWED does not exist.");
+                            }
                         } else {
-                            loge("KEY_SATELLITE_COMMUNICATION_ALLOWED does not exist.");
+                            result.accept(resultCode);
+                            return;
+                        }
+                        List<Integer> disallowedReasons =
+                                mSatelliteAccessController.getSatelliteDisallowedReasons();
+                        if (disallowedReasons.stream().anyMatch(r ->
+                                (r == SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP
+                                        || r == SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED
+                                        || r == SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED))) {
+                            result.accept(SATELLITE_RESULT_ACCESS_BARRED);
+                            return;
+                        }
+                        if (isAllowed) {
+                            ResultReceiver resultReceiver = new ResultReceiver(mMainThreadHandler) {
+                                @Override
+                                protected void onReceiveResult(int resultCode, Bundle resultData) {
+                                    Log.d(LOG_TAG, "updateSystemSelectionChannels resultCode="
+                                            + resultCode);
+                                    mSatelliteController.requestSatelliteEnabled(
+                                        enableSatellite, enableDemoMode, isEmergency, callback);
+                                }
+                            };
+                            mSatelliteAccessController.updateSystemSelectionChannels(
+                                    resultReceiver);
+                        } else {
+                            result.accept(SATELLITE_RESULT_ACCESS_BARRED);
                         }
-                    } else {
-                        result.accept(resultCode);
-                        return;
-                    }
-                    if (isAllowed) {
-                        mSatelliteController.requestSatelliteEnabled(
-                                enableSatellite, enableDemoMode, isEmergency, callback);
-                    } else {
-                        result.accept(SATELLITE_RESULT_ACCESS_BARRED);
                     }
-                }
-            };
-            mSatelliteAccessController.requestIsCommunicationAllowedForCurrentLocation(
-                    resultReceiver, true);
-        } else {
-            // No need to check if satellite is allowed at current location when disabling satellite
-            mSatelliteController.requestSatelliteEnabled(
-                    enableSatellite, enableDemoMode, isEmergency, callback);
+                };
+                mSatelliteAccessController.requestIsCommunicationAllowedForCurrentLocation(
+                        resultReceiver, true);
+                mSatelliteController.incrementResultReceiverCount(caller);
+            } else {
+                // No need to check if satellite is allowed at current location when disabling
+                // satellite
+                mSatelliteController.requestSatelliteEnabled(
+                        enableSatellite, enableDemoMode, isEmergency, callback);
+            }
+        } finally {
+            Binder.restoreCallingIdentity(identity);
         }
     }
 
@@ -13244,7 +13329,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public void requestIsSatelliteEnabled(@NonNull ResultReceiver result) {
         enforceSatelliteCommunicationPermission("requestIsSatelliteEnabled");
-        mSatelliteController.requestIsSatelliteEnabled(result);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.requestIsSatelliteEnabled(result);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13258,7 +13348,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public void requestIsDemoModeEnabled(@NonNull ResultReceiver result) {
         enforceSatelliteCommunicationPermission("requestIsDemoModeEnabled");
-        mSatelliteController.requestIsDemoModeEnabled(result);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.requestIsDemoModeEnabled(result);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13272,7 +13367,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public void requestIsEmergencyModeEnabled(@NonNull ResultReceiver result) {
         enforceSatelliteCommunicationPermission("requestIsEmergencyModeEnabled");
-        mSatelliteController.requestIsEmergencyModeEnabled(result);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.requestIsEmergencyModeEnabled(result);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13283,7 +13383,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     @Override
     public void requestIsSatelliteSupported(@NonNull ResultReceiver result) {
-        mSatelliteController.requestIsSatelliteSupported(result);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.requestIsSatelliteSupported(result);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13297,7 +13402,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public void requestSatelliteCapabilities(@NonNull ResultReceiver result) {
         enforceSatelliteCommunicationPermission("requestSatelliteCapabilities");
-        mSatelliteController.requestSatelliteCapabilities(result);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.requestSatelliteCapabilities(result);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13315,7 +13425,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             @NonNull IIntegerConsumer resultCallback,
             @NonNull ISatelliteTransmissionUpdateCallback callback) {
         enforceSatelliteCommunicationPermission("startSatelliteTransmissionUpdates");
-        mSatelliteController.startSatelliteTransmissionUpdates(resultCallback, callback);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.startSatelliteTransmissionUpdates(resultCallback, callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13333,7 +13448,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             @NonNull IIntegerConsumer resultCallback,
             @NonNull ISatelliteTransmissionUpdateCallback callback) {
         enforceSatelliteCommunicationPermission("stopSatelliteTransmissionUpdates");
-        mSatelliteController.stopSatelliteTransmissionUpdates(resultCallback, callback);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.stopSatelliteTransmissionUpdates(resultCallback, callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13355,8 +13475,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             @NonNull String token, @NonNull byte[] provisionData,
             @NonNull IIntegerConsumer callback) {
         enforceSatelliteCommunicationPermission("provisionSatelliteService");
-        return mSatelliteController.provisionSatelliteService(token, provisionData,
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.provisionSatelliteService(token, provisionData,
                 callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13374,7 +13499,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public void deprovisionSatelliteService(
             @NonNull String token, @NonNull IIntegerConsumer callback) {
         enforceSatelliteCommunicationPermission("deprovisionSatelliteService");
-        mSatelliteController.deprovisionSatelliteService(token, callback);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.deprovisionSatelliteService(token, callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13390,7 +13520,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @SatelliteManager.SatelliteResult public int registerForSatelliteProvisionStateChanged(
             @NonNull ISatelliteProvisionStateCallback callback) {
         enforceSatelliteCommunicationPermission("registerForSatelliteProvisionStateChanged");
-        return mSatelliteController.registerForSatelliteProvisionStateChanged(callback);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.registerForSatelliteProvisionStateChanged(callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13406,7 +13541,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public void unregisterForSatelliteProvisionStateChanged(
             @NonNull ISatelliteProvisionStateCallback callback) {
         enforceSatelliteCommunicationPermission("unregisterForSatelliteProvisionStateChanged");
-        mSatelliteController.unregisterForSatelliteProvisionStateChanged(callback);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.unregisterForSatelliteProvisionStateChanged(callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13421,7 +13561,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public void requestIsSatelliteProvisioned(@NonNull ResultReceiver result) {
         enforceSatelliteCommunicationPermission("requestIsSatelliteProvisioned");
-        mSatelliteController.requestIsSatelliteProvisioned(result);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.requestIsSatelliteProvisioned(result);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13437,7 +13582,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @SatelliteManager.SatelliteResult public int registerForSatelliteModemStateChanged(
             @NonNull ISatelliteModemStateCallback callback) {
         enforceSatelliteCommunicationPermission("registerForSatelliteModemStateChanged");
-        return mSatelliteController.registerForSatelliteModemStateChanged(callback);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.registerForSatelliteModemStateChanged(callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13452,7 +13602,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public void unregisterForModemStateChanged(@NonNull ISatelliteModemStateCallback callback) {
         enforceSatelliteCommunicationPermission("unregisterForModemStateChanged");
-        mSatelliteController.unregisterForModemStateChanged(callback);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.unregisterForModemStateChanged(callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13468,7 +13623,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @SatelliteManager.SatelliteResult public int registerForIncomingDatagram(
             @NonNull ISatelliteDatagramCallback callback) {
         enforceSatelliteCommunicationPermission("registerForIncomingDatagram");
-        return mSatelliteController.registerForIncomingDatagram(callback);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.registerForIncomingDatagram(callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13483,7 +13643,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public void unregisterForIncomingDatagram(@NonNull ISatelliteDatagramCallback callback) {
         enforceSatelliteCommunicationPermission("unregisterForIncomingDatagram");
-        mSatelliteController.unregisterForIncomingDatagram(callback);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.unregisterForIncomingDatagram(callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13499,7 +13664,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     public void pollPendingDatagrams(IIntegerConsumer callback) {
         enforceSatelliteCommunicationPermission("pollPendingDatagrams");
-        mSatelliteController.pollPendingDatagrams(callback);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.pollPendingDatagrams(callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13524,8 +13694,71 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             @NonNull SatelliteDatagram datagram, boolean needFullScreenPointingUI,
             @NonNull IIntegerConsumer callback) {
         enforceSatelliteCommunicationPermission("sendDatagram");
-        mSatelliteController.sendDatagram(datagramType, datagram, needFullScreenPointingUI,
-                callback);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.sendDatagram(datagramType, datagram, needFullScreenPointingUI,
+                    callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
+    /**
+     * Returns integer array of disallowed reasons of satellite.
+     *
+     * @return Integer array of disallowed reasons of satellite.
+     *
+     * @throws SecurityException if the caller doesn't have the required permission.
+     */
+    @NonNull public int[] getSatelliteDisallowedReasons() {
+        enforceSatelliteCommunicationPermission("getSatelliteDisallowedReasons");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteAccessController.getSatelliteDisallowedReasons()
+                    .stream().mapToInt(Integer::intValue).toArray();
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
+    /**
+     * Registers for disallowed reasons change event from satellite service.
+     *
+     * @param callback The callback to handle disallowed reasons changed event.
+     *
+     * @throws SecurityException if the caller doesn't have the required permission.
+     */
+    @Override
+    public void registerForSatelliteDisallowedReasonsChanged(
+            @NonNull ISatelliteDisallowedReasonsCallback callback) {
+        enforceSatelliteCommunicationPermission("registerForSatelliteDisallowedReasonsChanged");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteAccessController.registerForSatelliteDisallowedReasonsChanged(callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
+    /**
+     * Unregisters for disallowed reasons change event from satellite service.
+     * If callback was not registered before, the request will be ignored.
+     *
+     * @param callback The callback to handle disallowed reasons changed event.
+     *                 {@link #registerForSatelliteDisallowedReasonsChanged(
+     *                 ISatelliteDisallowedReasonsCallback)}.
+     * @throws SecurityException if the caller doesn't have the required permission.
+     */
+    @Override
+    public void unregisterForSatelliteDisallowedReasonsChanged(
+            @NonNull ISatelliteDisallowedReasonsCallback callback) {
+        enforceSatelliteCommunicationPermission("unregisterForSatelliteDisallowedReasonsChanged");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteAccessController.unregisterForSatelliteDisallowedReasonsChanged(callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13543,7 +13776,36 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public void requestIsCommunicationAllowedForCurrentLocation(int subId,
             @NonNull ResultReceiver result) {
         enforceSatelliteCommunicationPermission("requestIsCommunicationAllowedForCurrentLocation");
-        mSatelliteAccessController.requestIsCommunicationAllowedForCurrentLocation(result, false);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteAccessController.requestIsCommunicationAllowedForCurrentLocation(result,
+                    false);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
+    /**
+     * Request to get satellite access configuration for the current location.
+     *
+     * @param result The result receiver that returns the satellite access configuration
+     *               for the current location if the request is successful or an error code
+     *               if the request failed.
+     *
+     * @throws SecurityException if the caller doesn't have the required permission.
+     */
+    @Override
+    public void requestSatelliteAccessConfigurationForCurrentLocation(
+            @NonNull ResultReceiver result) {
+        enforceSatelliteCommunicationPermission(
+                "requestSatelliteAccessConfigurationForCurrentLocation");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteAccessController
+                    .requestSatelliteAccessConfigurationForCurrentLocation(result);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13557,22 +13819,119 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @Override
     public void requestTimeForNextSatelliteVisibility(@NonNull ResultReceiver result) {
         enforceSatelliteCommunicationPermission("requestTimeForNextSatelliteVisibility");
-        mSatelliteController.requestTimeForNextSatelliteVisibility(result);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.requestTimeForNextSatelliteVisibility(result);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
+    /**
+     * Request to get the name to display for Satellite subscription.
+     *
+     * @param result The result receiver that returns the display name to use for satellite feature
+     *               in the UI for current satellite subscription if the request is successful,
+     *               or an error code if the request failed.
+     *
+     * @throws SecurityException if the caller doesn't have the required permission.
+     */
+    @Override
+    public void requestSatelliteDisplayName(@NonNull ResultReceiver result) {
+        enforceSatelliteCommunicationPermission("requestSatelliteDisplayName");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.requestSatelliteDisplayName(result);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
+    /**
+     * Request to get the currently selected satellite subscription id.
+     *
+     * @param result The result receiver that returns the currently selected satellite subscription
+     *               id if the request is successful or an error code if the request failed.
+     *
+     * @throws SecurityException if the caller doesn't have the required permission.
+     */
+    @Override
+    public void requestSelectedNbIotSatelliteSubscriptionId(@NonNull ResultReceiver result) {
+        enforceSatelliteCommunicationPermission("requestSelectedNbIotSatelliteSubscriptionId");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.requestSelectedNbIotSatelliteSubscriptionId(result);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
+    /**
+     * Registers for selected satellite subscription changed event from the satellite service.
+     *
+     * @param callback The callback to handle the satellite subscription changed event.
+     *
+     * @return The {@link SatelliteManager.SatelliteResult} result of the operation.
+     *
+     * @throws SecurityException if the caller doesn't have required permission.
+     */
+    @Override
+    @SatelliteManager.SatelliteResult
+    public int registerForSelectedNbIotSatelliteSubscriptionChanged(
+            @NonNull ISelectedNbIotSatelliteSubscriptionCallback callback) {
+        enforceSatelliteCommunicationPermission(
+                "registerForSelectedNbIotSatelliteSubscriptionChanged");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.registerForSelectedNbIotSatelliteSubscriptionChanged(
+                    callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
-     * Inform that Device is aligned to satellite for demo mode.
+     * Unregisters for selected satellite subscription changed event from the satellite service.
+     * If callback was not registered before, the request will be ignored.
      *
-     * @param isAligned {@code true} Device is aligned with the satellite for demo mode
-     *                  {@code false} Device fails to align with the satellite for demo mode.
+     * @param callback The callback that was passed to {@link
+     *     #registerForSelectedNbIotSatelliteSubscriptionChanged(
+     *     ISelectedNbIotSatelliteSubscriptionCallback)}.
+     *
+     * @throws SecurityException if the caller doesn't have required permission.
+     */
+    @Override
+    public void unregisterForSelectedNbIotSatelliteSubscriptionChanged(
+            @NonNull ISelectedNbIotSatelliteSubscriptionCallback callback) {
+        enforceSatelliteCommunicationPermission(
+                "unregisterForSelectedNbIotSatelliteSubscriptionChanged");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.unregisterForSelectedNbIotSatelliteSubscriptionChanged(
+                    callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
+    /**
+     * Inform whether the device is aligned with the satellite in both real and demo mode.
+     *
+     * @param isAligned {@code true} Device is aligned with the satellite.
+     *                  {@code false} Device fails to align with the satellite.
      *
      * @throws SecurityException if the caller doesn't have required permission.
      */
     @RequiresPermission(Manifest.permission.SATELLITE_COMMUNICATION)
 
     public void setDeviceAlignedWithSatellite(@NonNull boolean isAligned) {
-        enforceSatelliteCommunicationPermission("informDeviceAlignedToSatellite");
-        mSatelliteController.setDeviceAlignedWithSatellite(isAligned);
+        enforceSatelliteCommunicationPermission("setDeviceAlignedWithSatellite");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.setDeviceAlignedWithSatellite(isAligned);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13766,7 +14125,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     @SatelliteManager.SatelliteResult public int registerForSatelliteSupportedStateChanged(
             @NonNull ISatelliteSupportedStateCallback callback) {
         enforceSatelliteCommunicationPermission("registerForSatelliteSupportedStateChanged");
-        return mSatelliteController.registerForSatelliteSupportedStateChanged(callback);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.registerForSatelliteSupportedStateChanged(callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13782,7 +14146,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
     public void unregisterForSatelliteSupportedStateChanged(
             @NonNull ISatelliteSupportedStateCallback callback) {
         enforceSatelliteCommunicationPermission("unregisterForSatelliteSupportedStateChanged");
-        mSatelliteController.unregisterForSatelliteSupportedStateChanged(callback);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.unregisterForSatelliteSupportedStateChanged(callback);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13803,8 +14172,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                 "setSatelliteServicePackageName");
-        return mSatelliteController.setSatelliteServicePackageName(servicePackageName,
-                provisioned);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.setSatelliteServicePackageName(servicePackageName,
+                    provisioned);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13821,7 +14195,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                 "setSatelliteGatewayServicePackageName");
-        return mSatelliteController.setSatelliteGatewayServicePackageName(servicePackageName);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.setSatelliteGatewayServicePackageName(servicePackageName);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13840,8 +14219,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                 Binder.getCallingUid(), "setSatellitePointingUiClassName");
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID,
-                "setSatelliteGatewayServicePackageName");
-        return mSatelliteController.setSatellitePointingUiClassName(packageName, className);
+                "setSatellitePointingUiClassName");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.setSatellitePointingUiClassName(packageName, className);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13859,7 +14243,33 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                 "setSatelliteListeningTimeoutDuration");
-        return mSatelliteController.setSatelliteListeningTimeoutDuration(timeoutMillis);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.setSatelliteListeningTimeoutDuration(timeoutMillis);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
+    /**
+     * This API can be used by only CTS to control ingoring cellular service state event.
+     *
+     * @param enabled Whether to enable boolean config.
+     * @return {@code true} if the value is set successfully, {@code false} otherwise.
+     */
+    public boolean setSatelliteIgnoreCellularServiceState(boolean enabled) {
+        Log.d(LOG_TAG, "setSatelliteIgnoreCellularServiceState - " + enabled);
+        TelephonyPermissions.enforceShellOnly(
+                Binder.getCallingUid(), "setSatelliteIgnoreCellularServiceState");
+        TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
+                SubscriptionManager.INVALID_SUBSCRIPTION_ID,
+                "setSatelliteIgnoreCellularServiceState");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.setSatelliteIgnoreCellularServiceState(enabled);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13878,8 +14288,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                 "setDatagramControllerTimeoutDuration");
-        return mSatelliteController.setDatagramControllerTimeoutDuration(
-                reset, timeoutType, timeoutMillis);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.setDatagramControllerTimeoutDuration(
+                    reset, timeoutType, timeoutMillis);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13898,7 +14313,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                 "ssetDatagramControllerBooleanConfig");
-        return mSatelliteController.setDatagramControllerBooleanConfig(reset, booleanType, enable);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.setDatagramControllerBooleanConfig(reset, booleanType,
+                    enable);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
 
@@ -13918,8 +14339,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                 "setSatelliteControllerTimeoutDuration");
-        return mSatelliteController.setSatelliteControllerTimeoutDuration(
-                reset, timeoutType, timeoutMillis);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.setSatelliteControllerTimeoutDuration(
+                    reset, timeoutType, timeoutMillis);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13942,8 +14368,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                 "setEmergencyCallToSatelliteHandoverType");
-        return mSatelliteController.setEmergencyCallToSatelliteHandoverType(
-                handoverType, delaySeconds);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.setEmergencyCallToSatelliteHandoverType(
+                    handoverType, delaySeconds);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13962,7 +14393,12 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                 "setOemEnabledSatelliteProvisionStatus");
-        return mSatelliteController.setOemEnabledSatelliteProvisionStatus(reset, isProvisioned);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.setOemEnabledSatelliteProvisionStatus(reset, isProvisioned);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13979,14 +14415,18 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
                 + ", locationCountryCodeTimestampNanos" + locationCountryCodeTimestampNanos
                 + ", reset=" + reset + ", cachedNetworkCountryCodes="
                 + String.join(", ", cachedNetworkCountryCodes.keySet()));
-        TelephonyPermissions.enforceShellOnly(
-                Binder.getCallingUid(), "setCachedLocationCountryCode");
+        TelephonyPermissions.enforceShellOnly(Binder.getCallingUid(), "setCountryCodes");
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
-                SubscriptionManager.INVALID_SUBSCRIPTION_ID,
-                "setCachedLocationCountryCode");
-        return TelephonyCountryDetector.getInstance(getDefaultPhone().getContext(), mFeatureFlags)
-                .setCountryCodes(reset, currentNetworkCountryCodes, cachedNetworkCountryCodes,
-                        locationCountryCode, locationCountryCodeTimestampNanos);
+                SubscriptionManager.INVALID_SUBSCRIPTION_ID, "setCountryCodes");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return TelephonyCountryDetector.getInstance(getDefaultPhone().getContext(),
+                    mFeatureFlags).setCountryCodes(reset, currentNetworkCountryCodes,
+                    cachedNetworkCountryCodes, locationCountryCode,
+                    locationCountryCodeTimestampNanos);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -13999,19 +14439,26 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
      */
     public boolean setSatelliteAccessControlOverlayConfigs(boolean reset, boolean isAllowed,
             String s2CellFile, long locationFreshDurationNanos,
-            List<String> satelliteCountryCodes) {
+            List<String> satelliteCountryCodes, String satelliteAccessConfigurationFile) {
         Log.d(LOG_TAG, "setSatelliteAccessControlOverlayConfigs: reset=" + reset
                 + ", isAllowed" + isAllowed + ", s2CellFile=" + s2CellFile
                 + ", locationFreshDurationNanos=" + locationFreshDurationNanos
                 + ", satelliteCountryCodes=" + ((satelliteCountryCodes != null)
-                ? String.join(", ", satelliteCountryCodes) : null));
+                ? String.join(", ", satelliteCountryCodes) : null)
+                + ", satelliteAccessConfigurationFile=" + satelliteAccessConfigurationFile);
         TelephonyPermissions.enforceShellOnly(
                 Binder.getCallingUid(), "setSatelliteAccessControlOverlayConfigs");
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                 "setSatelliteAccessControlOverlayConfigs");
-        return mSatelliteAccessController.setSatelliteAccessControlOverlayConfigs(reset, isAllowed,
-                s2CellFile, locationFreshDurationNanos, satelliteCountryCodes);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteAccessController.setSatelliteAccessControlOverlayConfigs(reset,
+                    isAllowed, s2CellFile, locationFreshDurationNanos, satelliteCountryCodes,
+                    satelliteAccessConfigurationFile);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -14036,8 +14483,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                 "setShouldSendDatagramToModemInDemoMode");
-        return mSatelliteController.setShouldSendDatagramToModemInDemoMode(
-                shouldSendToModemInDemoMode);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteController.setShouldSendDatagramToModemInDemoMode(
+                    shouldSendToModemInDemoMode);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -14062,8 +14514,13 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         TelephonyPermissions.enforceCallingOrSelfModifyPermissionOrCarrierPrivilege(mApp,
                 SubscriptionManager.INVALID_SUBSCRIPTION_ID,
                 "setIsSatelliteCommunicationAllowedForCurrentLocationCache");
-        return mSatelliteAccessController.setIsSatelliteCommunicationAllowedForCurrentLocationCache(
-                state);
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteAccessController
+                    .setIsSatelliteCommunicationAllowedForCurrentLocationCache(state);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
     }
 
     /**
@@ -14423,6 +14880,50 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
         }
     }
 
+    /**
+     * Deliver the list of deprovisioned satellite subscriber ids.
+     *
+     * @param list List of deprovisioned satellite subscriber ids.
+     * @param result The result receiver that returns whether deliver success or fail.
+     *
+     * @throws SecurityException if the caller doesn't have the required permission.
+     */
+    @Override
+    public void deprovisionSatellite(@NonNull List<SatelliteSubscriberInfo> list,
+            @NonNull ResultReceiver result) {
+        enforceSatelliteCommunicationPermission("deprovisionSatellite");
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.deprovisionSatellite(list, result);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
+
+    /**
+     * Inform whether application supports NTN SMS in satellite mode.
+     *
+     * This method is used by default messaging application to inform framework whether it supports
+     * NTN SMS or not.
+     *
+     * @param ntnSmsSupported {@code true} If application supports NTN SMS, else {@code false}.
+     *
+     * @throws SecurityException if the caller doesn't have required permission.
+     */
+    @Override
+    public void setNtnSmsSupported(boolean ntnSmsSupported) {
+        enforceSatelliteCommunicationPermission("setNtnSmsSupported");
+        enforceSendSmsPermission();
+
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            mSatelliteController.setNtnSmsSupportedByMessagesApp(ntnSmsSupported);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
     /**
      * This API can be used by only CTS to override the cached value for the device overlay config
      * value :
@@ -14455,4 +14956,70 @@ public class PhoneInterfaceManager extends ITelephony.Stub {
             Binder.restoreCallingIdentity(identity);
         }
     }
+
+    /**
+     * This API can be used by only CTS to override the Euicc UI component.
+     *
+     * @param componentName ui component to be launched for testing. {@code null} to reset.
+     *
+     * @hide
+     */
+    @Override
+    public void setTestEuiccUiComponent(@Nullable ComponentName componentName) {
+        enforceModifyPermission();
+        log("setTestEuiccUiComponent: " + componentName);
+        mTestEuiccUiComponent = componentName;
+    }
+
+    /**
+     * This API can be used by only CTS to retrieve the Euicc UI component.
+     *
+     * @return Euicc UI component. {@code null} if not available.
+     * @hide
+     */
+    @Override
+    @Nullable
+    public ComponentName getTestEuiccUiComponent() {
+        enforceReadPrivilegedPermission("getTestEuiccUiComponent");
+        return mTestEuiccUiComponent;
+    }
+
+    /**
+     * This API can be used only for test purpose to override the carrier roaming Ntn eligibility
+     *
+     * @param state        to update Ntn Eligibility.
+     * @param resetRequired to reset the overridden flag in satellite controller.
+     * @return {@code true} if the shell command is successful, {@code false} otherwise.
+     */
+    public boolean overrideCarrierRoamingNtnEligibilityChanged(boolean state,
+            boolean resetRequired) {
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return mSatelliteAccessController.overrideCarrierRoamingNtnEligibilityChanged(state,
+                    resetRequired);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
+
+    /**
+     * Returns carrier id maps to the passing {@link CarrierIdentifier}.
+     *
+     * @param carrierIdentifier {@link CarrierIdentifier}.
+     *
+     * @return carrier id from passing {@link CarrierIdentifier} or UNKNOWN_CARRIER_ID
+     * if the carrier cannot be identified
+     */
+    public int getCarrierIdFromIdentifier(@NonNull CarrierIdentifier carrierIdentifier) {
+        enforceReadPrivilegedPermission("getCarrierIdFromIdentifier");
+        enforceTelephonyFeatureWithException(getCurrentPackageName(),
+                PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, "getCarrierIdFromIdentifier");
+
+        final long identity = Binder.clearCallingIdentity();
+        try {
+            return CarrierResolver.getCarrierIdFromIdentifier(mApp, carrierIdentifier);
+        } finally {
+            Binder.restoreCallingIdentity(identity);
+        }
+    }
 }
diff --git a/src/com/android/phone/TelephonyShellCommand.java b/src/com/android/phone/TelephonyShellCommand.java
index bfc93e0ed..cd6a369cf 100644
--- a/src/com/android/phone/TelephonyShellCommand.java
+++ b/src/com/android/phone/TelephonyShellCommand.java
@@ -56,12 +56,12 @@ import com.android.ims.rcs.uce.util.FeatureTags;
 import com.android.internal.telephony.ITelephony;
 import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.PhoneFactory;
+import com.android.internal.telephony.TelephonyPermissions;
 import com.android.internal.telephony.d2d.Communicator;
 import com.android.internal.telephony.emergency.EmergencyNumberTracker;
 import com.android.internal.telephony.util.TelephonyUtils;
 import com.android.modules.utils.BasicShellCommandHandler;
 import com.android.phone.callcomposer.CallComposerPictureManager;
-import com.android.phone.euicc.EuiccUiDispatcherActivity;
 import com.android.phone.utils.CarrierAllowListInfo;
 
 import java.io.IOException;
@@ -131,9 +131,6 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
     private static final String CC_SET_VALUES_FROM_XML = "set-values-from-xml";
     private static final String CC_CLEAR_VALUES = "clear-values";
 
-    private static final String EUICC_SUBCOMMAND = "euicc";
-    private static final String EUICC_SET_UI_COMPONENT = "set-euicc-uicomponent";
-
     private static final String GBA_SUBCOMMAND = "gba";
     private static final String GBA_SET_SERVICE = "set-service";
     private static final String GBA_GET_SERVICE = "get-service";
@@ -190,6 +187,8 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
             "set-satellite-gateway-service-package-name";
     private static final String SET_SATELLITE_LISTENING_TIMEOUT_DURATION =
             "set-satellite-listening-timeout-duration";
+    private static final String SET_SATELLITE_IGNORE_CELLULAR_SERVICE_STATE =
+            "set-satellite-ignore-cellular-service-state";
     private static final String SET_SATELLITE_POINTING_UI_CLASS_NAME =
             "set-satellite-pointing-ui-class-name";
     private static final String SET_DATAGRAM_CONTROLLER_TIMEOUT_DURATION =
@@ -213,6 +212,9 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
     private static final String SET_SATELLITE_SUBSCRIBERID_LIST_CHANGED_INTENT_COMPONENT =
             "set-satellite-subscriberid-list-changed-intent-component";
 
+    private static final String SET_SATELLITE_ACCESS_RESTRICTION_CHECKING_RESULT =
+            "set-satellite-access-restriction-checking-result";
+
     private static final String DOMAIN_SELECTION_SUBCOMMAND = "domainselection";
     private static final String DOMAIN_SELECTION_SET_SERVICE_OVERRIDE = "set-dss-override";
     private static final String DOMAIN_SELECTION_CLEAR_SERVICE_OVERRIDE = "clear-dss-override";
@@ -230,6 +232,7 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
             "set-allowed-network-types-for-users";
     private static final String GET_IMEI = "get-imei";
     private static final String GET_SIM_SLOTS_MAPPING = "get-sim-slots-mapping";
+    private static final String COMMAND_DELETE_IMSI_KEY = "delete_imsi_key";
     // Take advantage of existing methods that already contain permissions checks when possible.
     private final ITelephony mInterface;
 
@@ -358,8 +361,6 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
                 return handleDataTestModeCommand();
             case END_BLOCK_SUPPRESSION:
                 return handleEndBlockSuppressionCommand();
-            case EUICC_SUBCOMMAND:
-                return handleEuiccCommand();
             case GBA_SUBCOMMAND:
                 return handleGbaCommand();
             case D2D_SUBCOMMAND:
@@ -405,6 +406,8 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
                 return handleSetSatelliteGatewayServicePackageNameCommand();
             case SET_SATELLITE_LISTENING_TIMEOUT_DURATION:
                 return handleSetSatelliteListeningTimeoutDuration();
+            case SET_SATELLITE_IGNORE_CELLULAR_SERVICE_STATE:
+                return handleSetSatelliteIgnoreCellularServiceState();
             case SET_SATELLITE_POINTING_UI_CLASS_NAME:
                 return handleSetSatellitePointingUiClassNameCommand();
             case SET_DATAGRAM_CONTROLLER_TIMEOUT_DURATION:
@@ -427,6 +430,10 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
                 return handleSetIsSatelliteCommunicationAllowedForCurrentLocationCache();
             case SET_SATELLITE_SUBSCRIBERID_LIST_CHANGED_INTENT_COMPONENT:
                 return handleSetSatelliteSubscriberIdListChangedIntentComponent();
+            case SET_SATELLITE_ACCESS_RESTRICTION_CHECKING_RESULT:
+                return handleOverrideCarrierRoamingNtnEligibilityChanged();
+            case COMMAND_DELETE_IMSI_KEY:
+                return handleDeleteTestImsiKey();
             default: {
                 return handleDefaultCommands(cmd);
             }
@@ -522,11 +529,14 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
     private void onHelpIms() {
         PrintWriter pw = getOutPrintWriter();
         pw.println("IMS Commands:");
-        pw.println("  ims set-ims-service [-s SLOT_ID] (-c | -d | -f) PACKAGE_NAME");
+        pw.println("  ims set-ims-service [-s SLOT_ID] [-u USER_ID] (-c | -d | -f) PACKAGE_NAME");
         pw.println("    Sets the ImsService defined in PACKAGE_NAME to to be the bound");
         pw.println("    ImsService. Options are:");
         pw.println("      -s: the slot ID that the ImsService should be bound for. If no option");
         pw.println("          is specified, it will choose the default voice SIM slot.");
+        pw.println("      -u: the user ID that the ImsService should be bound on. If no option");
+        pw.println("          is specified, the SYSTEM user ID will be preferred followed by the");
+        pw.println("          current user ID if they are different");
         pw.println("      -c: Override the ImsService defined in the carrier configuration.");
         pw.println("      -d: Override the ImsService defined in the device overlay.");
         pw.println("      -f: Set the feature that this override if for, if no option is");
@@ -691,15 +701,6 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
         pw.println("          is specified, it will choose the default voice SIM slot.");
     }
 
-    private void onHelpEuicc() {
-        PrintWriter pw = getOutPrintWriter();
-        pw.println("Euicc Commands:");
-        pw.println("  euicc set-euicc-uicomponent COMPONENT_NAME PACKAGE_NAME");
-        pw.println("  Sets the Euicc Ui-Component which handles EuiccService Actions.");
-        pw.println("  COMPONENT_NAME: The component name which handles UI Actions.");
-        pw.println("  PACKAGE_NAME: THe package name in which ui component belongs.");
-    }
-
     private void onHelpGba() {
         PrintWriter pw = getOutPrintWriter();
         pw.println("Gba Commands:");
@@ -1358,12 +1359,22 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
     private int handleImsSetServiceCommand() {
         PrintWriter errPw = getErrPrintWriter();
         int slotId = getDefaultSlot();
+        int userId = UserHandle.USER_NULL; // By default, set no userId constraint
         Boolean isCarrierService = null;
         List<Integer> featuresList = new ArrayList<>();
 
         String opt;
         while ((opt = getNextOption()) != null) {
             switch (opt) {
+                case "-u": {
+                    try {
+                        userId = Integer.parseInt(getNextArgRequired());
+                    } catch (NumberFormatException e) {
+                        errPw.println("ims set-ims-service requires an integer as a USER_ID");
+                        return -1;
+                    }
+                    break;
+                }
                 case "-s": {
                     try {
                         slotId = Integer.parseInt(getNextArgRequired());
@@ -1419,17 +1430,17 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
             for (int i = 0; i < featuresList.size(); i++) {
                 featureArray[i] = featuresList.get(i);
             }
-            boolean result = mInterface.setBoundImsServiceOverride(slotId, isCarrierService,
+            boolean result = mInterface.setBoundImsServiceOverride(slotId, userId, isCarrierService,
                     featureArray, packageName);
             if (VDBG) {
-                Log.v(LOG_TAG, "ims set-ims-service -s " + slotId + " "
+                Log.v(LOG_TAG, "ims set-ims-service -s " + slotId + " -u " + userId + " "
                         + (isCarrierService ? "-c " : "-d ")
                         + "-f " + featuresList + " "
                         + packageName + ", result=" + result);
             }
             getOutPrintWriter().println(result);
         } catch (RemoteException e) {
-            Log.w(LOG_TAG, "ims set-ims-service -s " + slotId + " "
+            Log.w(LOG_TAG, "ims set-ims-service -s " + slotId + " -u " + userId + " "
                     + (isCarrierService ? "-c " : "-d ")
                     + "-f " + featuresList + " "
                     + packageName + ", error" + e.getMessage());
@@ -1686,9 +1697,7 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
     }
 
     private boolean checkShellUid() {
-        // adb can run as root or as shell, depending on whether the device is rooted.
-        return UserHandle.isSameApp(Binder.getCallingUid(), Process.SHELL_UID)
-                || UserHandle.isSameApp(Binder.getCallingUid(), Process.ROOT_UID);
+        return TelephonyPermissions.isRootOrShell(Binder.getCallingUid());
     }
 
     private int handleCcCommand() {
@@ -2219,35 +2228,6 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
         return 0;
     }
 
-    private int handleEuiccCommand() {
-        String arg = getNextArg();
-        if (arg == null) {
-            onHelpEuicc();
-            return 0;
-        }
-
-        switch (arg) {
-            case EUICC_SET_UI_COMPONENT: {
-                return handleEuiccServiceCommand();
-            }
-        }
-        return -1;
-    }
-
-    private int handleEuiccServiceCommand() {
-        String uiComponent = getNextArg();
-        String packageName = getNextArg();
-        if (packageName == null || uiComponent == null) {
-            return -1;
-        }
-        EuiccUiDispatcherActivity.setTestEuiccUiComponent(packageName, uiComponent);
-        if (VDBG) {
-            Log.v(LOG_TAG, "euicc set-euicc-uicomponent " + uiComponent +" "
-                    + packageName);
-        }
-        return 0;
-    }
-
     private int handleRestartModemCommand() {
         // Verify that the user is allowed to run the command. Only allowed in rooted device in a
         // non user build.
@@ -3400,6 +3380,37 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
         return 0;
     }
 
+    private int handleSetSatelliteIgnoreCellularServiceState() {
+        PrintWriter errPw = getErrPrintWriter();
+        boolean enabled = false;
+
+        String opt;
+        while ((opt = getNextOption()) != null) {
+            switch (opt) {
+                case "-d": {
+                    enabled = Boolean.parseBoolean(getNextArgRequired());
+                    break;
+                }
+            }
+        }
+        Log.d(LOG_TAG, "handleSetSatelliteIgnoreCellularServiceState: enabled =" + enabled);
+
+        try {
+            boolean result = mInterface.setSatelliteIgnoreCellularServiceState(enabled);
+            if (VDBG) {
+                Log.v(LOG_TAG, "handleSetSatelliteIgnoreCellularServiceState " + enabled
+                        + ", result = " + result);
+            }
+            getOutPrintWriter().println(result);
+        } catch (RemoteException e) {
+            Log.w(LOG_TAG, "handleSetSatelliteIgnoreCellularServiceState: " + enabled
+                    + ", error = " + e.getMessage());
+            errPw.println("Exception: " + e.getMessage());
+            return -1;
+        }
+        return 0;
+    }
+
     private int handleSetDatagramControllerTimeoutDuration() {
         PrintWriter errPw = getErrPrintWriter();
         boolean reset = false;
@@ -3582,9 +3593,11 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
         String s2CellFile = null;
         long locationFreshDurationNanos = 0;
         List<String> satelliteCountryCodes = null;
+        String satelliteAccessConfigurationFile = null;
 
         String opt;
         while ((opt = getNextOption()) != null) {
+            Log.d(LOG_TAG, "handleSetSatelliteAccessControlOverlayConfigs: opt=" + opt);
             switch (opt) {
                 case "-r": {
                     reset = true;
@@ -3607,16 +3620,22 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
                     satelliteCountryCodes = Arrays.asList(countryCodeStr.split(","));
                     break;
                 }
+                case "-g": {
+                    satelliteAccessConfigurationFile = getNextArgRequired();
+                    break;
+                }
             }
         }
         Log.d(LOG_TAG, "handleSetSatelliteAccessControlOverlayConfigs: reset=" + reset
                 + ", isAllowed=" + isAllowed + ", s2CellFile=" + s2CellFile
                 + ", locationFreshDurationNanos=" + locationFreshDurationNanos
-                + ", satelliteCountryCodes=" + satelliteCountryCodes);
+                + ", satelliteCountryCodes=" + satelliteCountryCodes
+                + ", satelliteAccessConfigurationFile=" + satelliteAccessConfigurationFile);
 
         try {
             boolean result = mInterface.setSatelliteAccessControlOverlayConfigs(reset, isAllowed,
-                    s2CellFile, locationFreshDurationNanos, satelliteCountryCodes);
+                    s2CellFile, locationFreshDurationNanos, satelliteCountryCodes,
+                    satelliteAccessConfigurationFile);
             if (VDBG) {
                 Log.v(LOG_TAG, "setSatelliteAccessControlOverlayConfigs result =" + result);
             }
@@ -3726,7 +3745,6 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
         PrintWriter errPw = getErrPrintWriter();
         String opt;
         String state;
-
         if ((opt = getNextArg()) == null) {
             errPw.println(
                     "adb shell cmd phone set-is-satellite-communication-allowed-for-current"
@@ -3739,6 +3757,10 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
                     state = "cache_allowed";
                     break;
                 }
+                case "-na": {
+                    state = "cache_not_allowed";
+                    break;
+                }
                 case "-n": {
                     state = "cache_clear_and_not_allowed";
                     break;
@@ -4077,4 +4099,66 @@ public class TelephonyShellCommand extends BasicShellCommandHandler {
         }
         return jSonString;
     }
+
+    /**
+     * This method override the check for carrier roaming Ntn eligibility.
+     * <ul>
+     * <li> `adb shell cmd phone set-satellite-access-restriction-checking-result true` will set
+     * override eligibility to true.</li>
+     * <li> `adb shell cmd phone set-satellite-access-restriction-checking-result false` will
+     * override eligibility to false.</li>
+     * <li> `adb shell cmd phone set-satellite-access-restriction-checking-result` will reset the
+     * override data set through adb command.</li>
+     * </ul>
+     *
+     * @return {@code true} is command executed successfully otherwise {@code false}.
+     */
+    private int handleOverrideCarrierRoamingNtnEligibilityChanged() {
+        PrintWriter errPw = getErrPrintWriter();
+        String opt;
+        boolean state = false;
+        boolean isRestRequired = false;
+        try {
+            if ((opt = getNextArg()) == null) {
+                isRestRequired = true;
+            } else {
+                if ("true".equalsIgnoreCase(opt)) {
+                    state = true;
+                }
+            }
+            boolean result = mInterface.overrideCarrierRoamingNtnEligibilityChanged(state,
+                    isRestRequired);
+            if (VDBG) {
+                Log.v(LOG_TAG, "handleSetSatelliteAccessRestrictionCheckingResult "
+                        + "returns: "
+                        + result);
+            }
+            getOutPrintWriter().println(result);
+        } catch (RemoteException e) {
+            Log.w(LOG_TAG, "handleSetSatelliteAccessRestrictionCheckingResult("
+                    + state + "), error = " + e.getMessage());
+            errPw.println("Exception: " + e.getMessage());
+            return -1;
+        }
+        Log.d(LOG_TAG, "handleSetSatelliteAccessRestrictionCheckingResult(" + state + ")");
+        return 0;
+    }
+
+    private int handleDeleteTestImsiKey() {
+        if (!(checkShellUid())) {
+                Log.v(LOG_TAG,
+                    "handleCarrierRestrictionStatusCommand, MockModem service check fails or "
+                            + " checkShellUid fails");
+            return -1;
+        }
+
+        Phone phone = PhoneFactory.getDefaultPhone();
+        if (phone == null) {
+            Log.e(LOG_TAG,
+                    "handleCarrierRestrictionStatusCommand" + "No default Phone available");
+            return SubscriptionManager.INVALID_SUBSCRIPTION_ID;
+        }
+        phone.resetCarrierKeysForImsiEncryption(true);
+        return 1;
+    }
 }
diff --git a/src/com/android/phone/euicc/EuiccUiDispatcherActivity.java b/src/com/android/phone/euicc/EuiccUiDispatcherActivity.java
index a75f26f35..963232938 100644
--- a/src/com/android/phone/euicc/EuiccUiDispatcherActivity.java
+++ b/src/com/android/phone/euicc/EuiccUiDispatcherActivity.java
@@ -28,8 +28,8 @@ import android.os.Bundle;
 import android.os.UserHandle;
 import android.permission.LegacyPermissionManager;
 import android.service.euicc.EuiccService;
+import android.telephony.TelephonyManager;
 import android.telephony.euicc.EuiccManager;
-import android.text.TextUtils;
 import android.util.Log;
 
 import com.android.internal.annotations.VisibleForTesting;
@@ -59,8 +59,6 @@ public class EuiccUiDispatcherActivity extends Activity {
     private LegacyPermissionManager mPermissionManager;
     private boolean mGrantPermissionDone = false;
     private ThreadPoolExecutor mExecutor;
-    // Used for CTS EuiccManager action verification
-    private static ComponentName mTestEuiccUiComponentName;
 
     @Override
     public void onCreate(Bundle savedInstanceState) {
@@ -97,18 +95,6 @@ public class EuiccUiDispatcherActivity extends Activity {
         }
     }
 
-    /**
-    * This API used to set the Test EuiccUiComponent for CTS
-    * @param packageName package which handles the intent
-    * @param componentName ui component to be launched for testing
-    */
-    public static void setTestEuiccUiComponent(String packageName, String componentName) {
-        mTestEuiccUiComponentName = null;
-        if (!TextUtils.isEmpty(packageName) && !TextUtils.isEmpty(componentName)) {
-            mTestEuiccUiComponentName = new ComponentName(packageName, componentName);
-        }
-    }
-
     @VisibleForTesting
     @Nullable
     Intent resolveEuiccUiIntent() {
@@ -124,10 +110,11 @@ public class EuiccUiDispatcherActivity extends Activity {
             return null;
         }
 
-        if (mTestEuiccUiComponentName != null) {
-            Log.i(TAG, "Test mode");
-            euiccUiIntent.setComponent(mTestEuiccUiComponentName);
-            mTestEuiccUiComponentName = null;
+        ComponentName testEuiccUiComponent = ((TelephonyManager)
+                getSystemService(Context.TELEPHONY_SERVICE)).getTestEuiccUiComponent();
+        if (testEuiccUiComponent != null) {
+            Log.i(TAG, "Test mode: " + testEuiccUiComponent);
+            euiccUiIntent.setComponent(testEuiccUiComponent);
             return euiccUiIntent;
         }
 
diff --git a/src/com/android/phone/satellite/accesscontrol/S2RangeSatelliteOnDeviceAccessController.java b/src/com/android/phone/satellite/accesscontrol/S2RangeSatelliteOnDeviceAccessController.java
index 4490460c6..845ff18c2 100644
--- a/src/com/android/phone/satellite/accesscontrol/S2RangeSatelliteOnDeviceAccessController.java
+++ b/src/com/android/phone/satellite/accesscontrol/S2RangeSatelliteOnDeviceAccessController.java
@@ -16,10 +16,12 @@
 package com.android.phone.satellite.accesscontrol;
 
 import android.annotation.NonNull;
+import android.annotation.Nullable;
 import android.telephony.Rlog;
 
-import com.android.storage.s2.S2LevelRange;
+import com.android.internal.telephony.flags.FeatureFlags;
 import com.android.telephony.sats2range.read.SatS2RangeFileReader;
+import com.android.telephony.sats2range.read.SuffixTableRange;
 
 import com.google.common.geometry.S2CellId;
 import com.google.common.geometry.S2LatLng;
@@ -36,31 +38,42 @@ final class S2RangeSatelliteOnDeviceAccessController extends SatelliteOnDeviceAc
     private static final String TAG = "S2RangeSatelliteOnDeviceAccessController";
     private static final boolean DBG = false;
 
-    @NonNull private final SatS2RangeFileReader mSatS2RangeFileReader;
+    @NonNull
+    private final SatS2RangeFileReader mSatS2RangeFileReader;
 
     private final int mS2Level;
 
+    /** Feature flags to control behavior and errors. */
+    @NonNull
+    private final FeatureFlags mFeatureFlags;
+
     private S2RangeSatelliteOnDeviceAccessController(
-            @NonNull SatS2RangeFileReader satS2RangeFileReader, int s2Level) {
+            @NonNull SatS2RangeFileReader satS2RangeFileReader,
+            int s2Level,
+            @NonNull FeatureFlags featureFlags) {
         mSatS2RangeFileReader = Objects.requireNonNull(satS2RangeFileReader);
         mS2Level = s2Level;
+        mFeatureFlags = featureFlags;
     }
 
     /**
      * Returns a new {@link S2RangeSatelliteOnDeviceAccessController} using the specified data file.
      *
      * @param file The input file that contains the S2-range-based access restriction information.
-     * @throws IOException in the event of a problem while reading the underlying file.
+     * @throws IOException              in the event of a problem while reading the underlying file.
      * @throws IllegalArgumentException if either the S2 level defined by
-     * {@code config_oem_enabled_satellite_s2cell_level} or the satellite access allow defined by
-     * {@code config_oem_enabled_satellite_access_allow} does not match the values included in the
-     * header of the input file.
+     *                                  {@code config_oem_enabled_satellite_s2cell_level} or the
+     *                                  satellite access allow defined by
+     *                                  {@code config_oem_enabled_satellite_access_allow} does not
+     *                                  match the values included in the
+     *                                  header of the input file.
      */
     public static S2RangeSatelliteOnDeviceAccessController create(
-            @NonNull File file) throws IOException, IllegalArgumentException {
+            @NonNull File file, FeatureFlags featureFlags)
+            throws IOException, IllegalArgumentException {
         SatS2RangeFileReader reader = SatS2RangeFileReader.open(file);
         int s2Level = reader.getS2Level();
-        return new S2RangeSatelliteOnDeviceAccessController(reader, s2Level);
+        return new S2RangeSatelliteOnDeviceAccessController(reader, s2Level, featureFlags);
     }
 
     public static LocationToken createLocationTokenForLatLng(
@@ -84,7 +97,7 @@ final class S2RangeSatelliteOnDeviceAccessController extends SatelliteOnDeviceAc
     }
 
     private boolean isSatCommunicationAllowedAtLocation(long s2CellId) throws IOException {
-        S2LevelRange entry = mSatS2RangeFileReader.findEntryByCellId(s2CellId);
+        SuffixTableRange entry = mSatS2RangeFileReader.findEntryByCellId(s2CellId);
         if (mSatS2RangeFileReader.isAllowedList()) {
             // The file contains an allowed list of S2 cells. Thus, satellite is allowed if an
             // entry is found
@@ -158,4 +171,25 @@ final class S2RangeSatelliteOnDeviceAccessController extends SatelliteOnDeviceAc
             return Objects.hash(mS2CellId);
         }
     }
+
+    @Override
+    @Nullable
+    public Integer getRegionalConfigIdForLocation(@NonNull LocationToken locationToken)
+            throws IOException {
+        if (!mFeatureFlags.carrierRoamingNbIotNtn()) {
+            logd("getAccessControlConfigIdForLocation: carrierRoamingNbIotNtn is disabled");
+            return null;
+        }
+
+        if (locationToken instanceof LocationTokenImpl locationTokenImpl) {
+            return getRegionalConfigIdForLocation(locationTokenImpl.getS2CellId());
+        } else {
+            throw new IllegalArgumentException("Unknown locationToken=" + locationToken);
+        }
+    }
+
+    private Integer getRegionalConfigIdForLocation(long s2CellId) throws IOException {
+        SuffixTableRange entry = mSatS2RangeFileReader.findEntryByCellId(s2CellId);
+        return (entry == null) ? null : entry.getEntryValue();
+    }
 }
diff --git a/src/com/android/phone/satellite/accesscontrol/SatelliteAccessConfigurationParser.java b/src/com/android/phone/satellite/accesscontrol/SatelliteAccessConfigurationParser.java
new file mode 100644
index 000000000..ad0926b65
--- /dev/null
+++ b/src/com/android/phone/satellite/accesscontrol/SatelliteAccessConfigurationParser.java
@@ -0,0 +1,393 @@
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
+package com.android.phone.satellite.accesscontrol;
+
+import android.annotation.NonNull;
+import android.annotation.Nullable;
+import android.net.ParseException;
+import android.os.Build;
+import android.telephony.satellite.EarfcnRange;
+import android.telephony.satellite.SatelliteAccessConfiguration;
+import android.telephony.satellite.SatelliteInfo;
+import android.telephony.satellite.SatellitePosition;
+import android.util.Log;
+
+import com.android.internal.annotations.VisibleForTesting;
+
+import org.json.JSONArray;
+import org.json.JSONException;
+import org.json.JSONObject;
+
+import java.io.ByteArrayOutputStream;
+import java.io.FileInputStream;
+import java.io.FileNotFoundException;
+import java.io.IOException;
+import java.io.InputStream;
+import java.nio.charset.StandardCharsets;
+import java.util.ArrayList;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+import java.util.UUID;
+
+public class SatelliteAccessConfigurationParser {
+    private static final String TAG = "SatelliteAccessConfigurationParser";
+
+    public static final String SATELLITE_ACCESS_CONTROL_CONFIGS = "access_control_configs";
+    public static final String SATELLITE_CONFIG_ID = "config_id";
+    public static final String SATELLITE_INFOS = "satellite_infos";
+    public static final String SATELLITE_ID = "satellite_id";
+    public static final String SATELLITE_POSITION = "satellite_position";
+    public static final String SATELLITE_LONGITUDE = "longitude";
+    public static final String SATELLITE_ALTITUDE = "altitude";
+    public static final String SATELLITE_EARFCN_RANGES = "earfcn_ranges";
+    public static final String SATELLITE_START_EARFCN = "start_earfcn";
+    public static final String SATELLITE_END_EARFCN = "end_earfcn";
+    public static final String SATELLITE_BANDS = "bands";
+    public static final String SATELLITE_TAG_ID_LIST = "tag_ids";
+
+    /**
+     * Parses a JSON file containing satellite access configurations.
+     *
+     * @param fileName The name of the JSON file to parse.
+     * @return A map of satellite access configurations, keyed by config ID.
+     * @throws RuntimeException if the JSON file cannot be parsed or if a required field is missing.
+     */
+    @Nullable
+    public static Map<Integer, SatelliteAccessConfiguration> parse(@NonNull String fileName) {
+        logd("SatelliteAccessConfigurationParser: parse: " + fileName);
+        Map<Integer, SatelliteAccessConfiguration> satelliteAccessConfigurationMap;
+
+        try {
+            String jsonString = readJsonStringFromFile(fileName);
+            JSONObject satelliteAccessConfigJsonObject = new JSONObject(jsonString);
+            JSONArray configurationArrayJson = satelliteAccessConfigJsonObject.optJSONArray(
+                    SATELLITE_ACCESS_CONTROL_CONFIGS);
+
+            if (configurationArrayJson == null) {
+                loge("parse : failed to parse satellite access configurations json");
+                return null;
+            }
+
+            satelliteAccessConfigurationMap =
+                    parseSatelliteAccessConfigurations(configurationArrayJson);
+
+        } catch (JSONException | ParseException e) {
+            loge("Failed to parse satellite access configurations: " + e.getMessage());
+            throw new RuntimeException(e);
+        }
+
+        logd("satelliteAccessConfigurationMap= " + satelliteAccessConfigurationMap);
+        return satelliteAccessConfigurationMap;
+    }
+
+    private static void logd(String log) {
+        if (!Build.TYPE.equals("user")) {
+            Log.d(TAG, log);
+        }
+    }
+
+    private static void loge(String log) {
+        Log.e(TAG, log);
+    }
+
+    @NonNull
+    protected static List<Integer> parseSatelliteTagIdList(@NonNull JSONObject satelliteInfoJson) {
+        List<Integer> tagIdList = new ArrayList<>();
+        try {
+            JSONArray tagIdArray = satelliteInfoJson.optJSONArray(SATELLITE_TAG_ID_LIST);
+            tagIdList = parseIntegerList(tagIdArray);
+        } catch (JSONException e) {
+            loge("parseSatelliteInfo:  parsing is error");
+            return tagIdList;
+        }
+
+        logd("parseSatelliteBandList: " + tagIdList);
+        return tagIdList;
+    }
+
+    @Nullable
+    private static Map<Integer, SatelliteAccessConfiguration> parseSatelliteAccessConfigurations(
+            JSONArray satelliteAccessConfigurationJsonArray) throws JSONException {
+        Map<Integer, SatelliteAccessConfiguration> satelliteConfigMap = new HashMap<>();
+        if (satelliteAccessConfigurationJsonArray == null) {
+            loge("parseSatelliteAccessConfigurations: jsonArray is null, return null");
+            return null;
+        }
+
+        for (int i = 0; i < satelliteAccessConfigurationJsonArray.length(); i++) {
+            JSONObject satelliteAccessConfigurationJson =
+                    satelliteAccessConfigurationJsonArray.getJSONObject(i);
+
+            int configId = satelliteAccessConfigurationJson.optInt(SATELLITE_CONFIG_ID, -1);
+            if (!isRegionalConfigIdValid(configId)) {
+                loge("parseAccessControlConfigs: invalid config_id, return null");
+                return null;
+            }
+
+            JSONArray satelliteInfoJsonArray = satelliteAccessConfigurationJson
+                    .getJSONArray(SATELLITE_INFOS);
+            List<SatelliteInfo> satelliteInfoList = parseSatelliteInfoList(satelliteInfoJsonArray);
+            if (satelliteInfoList.isEmpty()) {
+                logd("parseAccessControlConfigs: satelliteInfoList is empty");
+            }
+
+            List<Integer> tagIdList = parseSatelliteTagIdList(satelliteAccessConfigurationJson);
+            if (satelliteInfoList.isEmpty() && tagIdList.isEmpty()) {
+                loge("parseAccessControlConfigs: satelliteInfoList is empty and tagId is null");
+                return null;
+            }
+
+            satelliteConfigMap.put(configId,
+                    new SatelliteAccessConfiguration(satelliteInfoList, tagIdList));
+        }
+
+        logd("parseSatelliteAccessConfigurations: " + satelliteConfigMap);
+        return satelliteConfigMap;
+    }
+
+    /**
+     * Checks if a regional configuration ID is valid.
+     * A valid regional configuration ID is a non-null integer that is greater than or equal to
+     * zero.
+     *
+     * @param configId The regional configuration ID to check.
+     * @return {@code true} if the ID is valid, {@code false} otherwise.
+     */
+    public static boolean isRegionalConfigIdValid(@Nullable Integer configId) {
+        return (configId != null && configId >= 0);
+    }
+
+    @Nullable
+    protected static UUID parseSatelliteId(@NonNull JSONObject satelliteInfoJson) {
+        String uuidString = satelliteInfoJson.optString(SATELLITE_ID, null);
+        UUID satelliteId;
+        if (uuidString != null) {
+            try {
+                satelliteId = UUID.fromString(uuidString);
+            } catch (IllegalArgumentException e) {
+                loge("getSatelliteId: invalid UUID format: " + uuidString + " | " + e.getMessage());
+                return null;
+            }
+        } else {
+            loge("getSatelliteId: satellite uuid is missing");
+            return null;
+        }
+
+        logd("getSatelliteId: satellite uuid is " + satelliteId);
+        return satelliteId;
+    }
+
+    @NonNull
+    protected static SatellitePosition parseSatellitePosition(
+            @NonNull JSONObject satelliteInfoJson) {
+        JSONObject jsonObject = satelliteInfoJson.optJSONObject(SATELLITE_POSITION);
+        SatellitePosition satellitePosition = new SatellitePosition(Double.NaN, Double.NaN);
+
+        if (jsonObject == null) {
+            loge("parseSatellitePosition: jsonObject is null");
+            return satellitePosition;
+        }
+
+        try {
+            double longitude = jsonObject.getDouble(SATELLITE_LONGITUDE);
+            double altitude = jsonObject.getDouble(SATELLITE_ALTITUDE);
+            if (isValidLongitude(longitude) && isValidAltitude(altitude)) {
+                satellitePosition = new SatellitePosition(longitude, altitude);
+            } else {
+                loge("parseSatellitePosition: invalid value: " + longitude + " | " + altitude);
+                return satellitePosition;
+            }
+        } catch (JSONException e) {
+            loge("parseSatellitePosition: json parsing error " + e.getMessage());
+            return satellitePosition;
+        }
+
+        logd("parseSatellitePosition: " + satellitePosition);
+        return satellitePosition;
+    }
+
+    @NonNull
+    protected static List<EarfcnRange> parseSatelliteEarfcnRangeList(
+            @NonNull JSONObject satelliteInfoJson) {
+        JSONArray earfcnRangesArray = satelliteInfoJson.optJSONArray(SATELLITE_EARFCN_RANGES);
+        List<EarfcnRange> earfcnRangeList = new ArrayList<>();
+        if (earfcnRangesArray == null) {
+            loge("parseSatelliteEarfcnRangeList: earfcn_ranges is missing");
+            return earfcnRangeList;
+        }
+
+        try {
+            for (int j = 0; j < earfcnRangesArray.length(); j++) {
+                JSONObject earfcnRangeJson = earfcnRangesArray.getJSONObject(j);
+                EarfcnRange earfcnRange = parseEarfcnRange(earfcnRangeJson);
+                if (earfcnRange == null) {
+                    loge("parseSatelliteEarfcnRangeList: earfcnRange is null, return empty list");
+                    earfcnRangeList.clear();
+                    return earfcnRangeList;
+                }
+                earfcnRangeList.add(earfcnRange);
+            }
+        } catch (JSONException e) {
+            loge("parseSatelliteEarfcnRangeList: earfcnRange json parsing error");
+            earfcnRangeList.clear();
+            return earfcnRangeList;
+        }
+        logd("parseSatelliteEarfcnRangeList: " + earfcnRangeList);
+        return earfcnRangeList;
+    }
+
+    @NonNull
+    protected static List<Integer> parseSatelliteBandList(@NonNull JSONObject satelliteInfoJson) {
+        List<Integer> bandList = new ArrayList<>();
+        try {
+            JSONArray bandArray = satelliteInfoJson.getJSONArray(SATELLITE_BANDS);
+            bandList = parseIntegerList(bandArray);
+        } catch (JSONException e) {
+            loge("parseSatelliteInfo: bands parsing is error");
+            return bandList;
+        }
+
+        logd("parseSatelliteBandList: " + bandList);
+        return bandList;
+    }
+
+    @NonNull
+    protected static List<SatelliteInfo> parseSatelliteInfoList(JSONArray satelliteInfojsonArray)
+            throws JSONException {
+        List<SatelliteInfo> satelliteInfoList = new ArrayList<>();
+        for (int i = 0; i < satelliteInfojsonArray.length(); i++) {
+            JSONObject SatelliteInfoJson = satelliteInfojsonArray.getJSONObject(i);
+            if (SatelliteInfoJson == null) {
+                satelliteInfoList.clear();
+                break;
+            }
+            UUID id = parseSatelliteId(SatelliteInfoJson);
+            SatellitePosition position = parseSatellitePosition(SatelliteInfoJson);
+            List<EarfcnRange> earfcnRangeList = parseSatelliteEarfcnRangeList(SatelliteInfoJson);
+            List<Integer> bandList = parseSatelliteBandList(SatelliteInfoJson);
+
+            if (id == null || (bandList.isEmpty() && earfcnRangeList.isEmpty())) {
+                loge("parseSatelliteInfo: id is " + id
+                        + " or both band list and earfcn range list are empty");
+                satelliteInfoList.clear();
+                return satelliteInfoList;
+            }
+
+            SatelliteInfo info = new SatelliteInfo(id, position, bandList, earfcnRangeList);
+            satelliteInfoList.add(info);
+        }
+        logd("parseSatelliteInfoList: " + satelliteInfoList);
+        return satelliteInfoList;
+    }
+
+    /**
+     * Load json file from the filePath
+     *
+     * @param jsonFilePath The file path of json file
+     * @return json string type json contents
+     */
+    @Nullable
+    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
+    public static String readJsonStringFromFile(@NonNull String jsonFilePath) {
+        logd("jsonFilePath is " + jsonFilePath);
+        String json = null;
+        try (InputStream inputStream = new FileInputStream(jsonFilePath);
+                ByteArrayOutputStream byteArrayStream = new ByteArrayOutputStream()) {
+            byte[] buffer = new byte[1024];
+            int length;
+            while ((length = inputStream.read(buffer)) != -1) {
+                byteArrayStream.write(buffer, 0, length);
+            }
+            json = byteArrayStream.toString(StandardCharsets.UTF_8);
+        } catch (FileNotFoundException e) {
+            loge("Error file " + jsonFilePath + " is not founded: " + e.getMessage());
+        } catch (IOException | NullPointerException e) {
+            loge("Error reading file " + jsonFilePath + ": " + e);
+        } finally {
+            logd("jsonString is " + json);
+        }
+        return json;
+    }
+
+    private static boolean isValidEarfcn(int earfcn) {
+        if (earfcn >= 0) {
+            return true;
+        }
+        loge("isValidEarfcn: earfcn value is out of valid range: " + earfcn);
+        return false;
+    }
+
+    private static boolean isValidEarfcnRange(int start, int end) {
+        if (start <= end) {
+            return true;
+        }
+        loge("isValidEarfcnRange: earfcn range start " + start + " is bigger than end " + end);
+        return false;
+    }
+
+    @Nullable
+    private static EarfcnRange parseEarfcnRange(@Nullable JSONObject jsonObject) {
+        logd("parseEarfcnRange");
+        if (jsonObject == null) {
+            loge("parseEarfcnRange: jsonObject is null");
+            return null;
+        }
+        try {
+            int start = jsonObject.getInt(SATELLITE_START_EARFCN);
+            int end = jsonObject.getInt(SATELLITE_END_EARFCN);
+
+            if (isValidEarfcn(start) && isValidEarfcn(end) && isValidEarfcnRange(start, end)) {
+                return new EarfcnRange(start, end);
+            }
+
+            loge("parseEarfcnRange: earfcn value is not valid, return null");
+            return null;
+        } catch (JSONException e) {
+            loge("parseEarfcnRange: json parsing error: " + e.getMessage());
+            return null;
+        }
+    }
+
+    @NonNull
+    private static List<Integer> parseIntegerList(@Nullable JSONArray jsonArray)
+            throws JSONException {
+        List<Integer> intList = new ArrayList<>();
+        if (jsonArray == null) {
+            loge("parseIntegerList: jsonArray is null, return IntArray with empty");
+            return intList;
+        }
+        for (int i = 0; i < jsonArray.length(); i++) {
+            try {
+                intList.add(jsonArray.getInt(i));
+            } catch (JSONException e) {
+                loge("parseIntegerList: jsonArray parsing error: " + e.getMessage());
+                intList.clear();
+            }
+        }
+        logd("parseIntegerList: " + intList);
+        return intList;
+    }
+
+    private static boolean isValidLongitude(double longitude) {
+        return (longitude >= -180.0 && longitude <= 180.0);
+    }
+
+    private static boolean isValidAltitude(double altitude) {
+        return (altitude >= 0);
+    }
+}
diff --git a/src/com/android/phone/satellite/accesscontrol/SatelliteAccessController.java b/src/com/android/phone/satellite/accesscontrol/SatelliteAccessController.java
index 7b244a1d9..291780cfb 100644
--- a/src/com/android/phone/satellite/accesscontrol/SatelliteAccessController.java
+++ b/src/com/android/phone/satellite/accesscontrol/SatelliteAccessController.java
@@ -16,12 +16,21 @@
 
 package com.android.phone.satellite.accesscontrol;
 
+import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_ACCESS_CONFIGURATION;
 import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_COMMUNICATION_ALLOWED;
 import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_PROVISIONED;
 import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_SUPPORTED;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_DISALLOWED_REASON_LOCATION_DISABLED;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_DISALLOWED_REASON_NOT_IN_ALLOWED_REGION;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_ACCESS_BARRED;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_INVALID_TELEPHONY_STATE;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_LOCATION_DISABLED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_LOCATION_NOT_AVAILABLE;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_NOT_SUPPORTED;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_NO_RESOURCES;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_SUCCESS;
 
@@ -34,7 +43,11 @@ import static com.android.internal.telephony.satellite.SatelliteController.SATEL
 import android.annotation.ArrayRes;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
+import android.app.Notification;
+import android.app.NotificationChannel;
+import android.app.NotificationManager;
 import android.content.BroadcastReceiver;
+import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
@@ -48,6 +61,7 @@ import android.os.Build;
 import android.os.Bundle;
 import android.os.CancellationSignal;
 import android.os.Handler;
+import android.os.HandlerExecutor;
 import android.os.HandlerThread;
 import android.os.IBinder;
 import android.os.Looper;
@@ -56,19 +70,29 @@ import android.os.RemoteException;
 import android.os.ResultReceiver;
 import android.os.SystemClock;
 import android.os.SystemProperties;
+import android.os.UserHandle;
 import android.provider.DeviceConfig;
 import android.telecom.TelecomManager;
 import android.telephony.AnomalyReporter;
+import android.telephony.CarrierConfigManager;
 import android.telephony.DropBoxManagerLoggerBackend;
+import android.telephony.NetworkRegistrationInfo;
 import android.telephony.PersistentLogger;
 import android.telephony.Rlog;
+import android.telephony.SubscriptionInfo;
 import android.telephony.SubscriptionManager;
+import android.telephony.satellite.EarfcnRange;
 import android.telephony.satellite.ISatelliteCommunicationAllowedStateCallback;
+import android.telephony.satellite.ISatelliteDisallowedReasonsCallback;
 import android.telephony.satellite.ISatelliteProvisionStateCallback;
 import android.telephony.satellite.ISatelliteSupportedStateCallback;
+import android.telephony.satellite.SatelliteAccessConfiguration;
+import android.telephony.satellite.SatelliteInfo;
 import android.telephony.satellite.SatelliteManager;
 import android.telephony.satellite.SatelliteSubscriberProvisionStatus;
+import android.telephony.satellite.SystemSelectionSpecifier;
 import android.text.TextUtils;
+import android.util.IntArray;
 import android.util.Pair;
 
 import com.android.internal.R;
@@ -76,6 +100,7 @@ import com.android.internal.annotations.GuardedBy;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.PhoneFactory;
+import com.android.internal.telephony.SmsApplication;
 import com.android.internal.telephony.TelephonyCountryDetector;
 import com.android.internal.telephony.flags.FeatureFlags;
 import com.android.internal.telephony.satellite.SatelliteConfig;
@@ -84,6 +109,7 @@ import com.android.internal.telephony.satellite.SatelliteController;
 import com.android.internal.telephony.satellite.metrics.AccessControllerMetricsStats;
 import com.android.internal.telephony.satellite.metrics.ConfigUpdaterMetricsStats;
 import com.android.internal.telephony.satellite.metrics.ControllerMetricsStats;
+import com.android.internal.telephony.subscription.SubscriptionManagerService;
 import com.android.internal.telephony.util.TelephonyUtils;
 import com.android.phone.PhoneGlobals;
 
@@ -97,16 +123,20 @@ import java.nio.file.StandardCopyOption;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collection;
+import java.util.HashMap;
 import java.util.HashSet;
 import java.util.LinkedHashMap;
 import java.util.List;
 import java.util.Locale;
 import java.util.Map;
+import java.util.Objects;
+import java.util.Optional;
 import java.util.Set;
 import java.util.UUID;
 import java.util.concurrent.ConcurrentHashMap;
 import java.util.concurrent.TimeUnit;
 import java.util.stream.Collectors;
+import java.util.stream.IntStream;
 
 /**
  * This module is responsible for making sure that satellite communication can be used by devices
@@ -144,12 +174,71 @@ public class SatelliteAccessController extends Handler {
     protected static final int EVENT_CONFIG_DATA_UPDATED = 4;
     protected static final int EVENT_COUNTRY_CODE_CHANGED = 5;
     protected static final int EVENT_LOCATION_SETTINGS_ENABLED = 6;
+    protected static final int CMD_UPDATE_SYSTEM_SELECTION_CHANNELS = 7;
+    protected static final int EVENT_LOCATION_SETTINGS_DISABLED = 8;
+
+    public static final int DEFAULT_REGIONAL_SATELLITE_CONFIG_ID = 0;
+    public static final int UNKNOWN_REGIONAL_SATELLITE_CONFIG_ID = -1;
+
+
+    private static final String KEY_AVAILABLE_NOTIFICATION_SHOWN = "available_notification_shown";
+    private static final String KEY_UNAVAILABLE_NOTIFICATION_SHOWN =
+            "unavailable_notification_shown";
+    private static final String AVAILABLE_NOTIFICATION_TAG = "available_notification_tag";
+    private static final String UNAVAILABLE_NOTIFICATION_TAG = "unavailable_notification_tag";
+    private static final int NOTIFICATION_ID = 1;
+    private static final String NOTIFICATION_CHANNEL = "satelliteChannel";
+    private static final String NOTIFICATION_CHANNEL_ID = "satellite";
+    private static final int SATELLITE_DISALLOWED_REASON_NONE = -1;
+    private static final List<Integer> DISALLOWED_REASONS_TO_BE_RESET =
+            Arrays.asList(SATELLITE_DISALLOWED_REASON_NOT_IN_ALLOWED_REGION,
+                    SATELLITE_DISALLOWED_REASON_LOCATION_DISABLED);
+
+    private static final HashMap<Integer, Pair<Integer, Integer>>
+            SATELLITE_SOS_UNAVAILABLE_REASONS = new HashMap<>(Map.of(
+            SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED, new Pair<>(
+                    R.string.satellite_sos_not_supported_notification_title,
+                    R.string.satellite_sos_not_supported_notification_summary),
+            SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED, new Pair<>(
+                    R.string.satellite_sos_not_provisioned_notification_title,
+                    R.string.satellite_sos_not_provisioned_notification_summary),
+            SATELLITE_DISALLOWED_REASON_NOT_IN_ALLOWED_REGION, new Pair<>(
+                    R.string.satellite_sos_not_in_allowed_region_notification_title,
+                    R.string.satellite_sos_not_in_allowed_region_notification_summary),
+            SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP, new Pair<>(
+                    R.string.satellite_sos_unsupported_default_sms_app_notification_title,
+                    R.string.satellite_sos_unsupported_default_sms_app_notification_summary),
+            SATELLITE_DISALLOWED_REASON_LOCATION_DISABLED, new Pair<>(
+                    R.string.satellite_sos_location_disabled_notification_title,
+                    R.string.satellite_sos_location_disabled_notification_summary)
+    ));
+
+    private static final HashMap<Integer, Pair<Integer, Integer>>
+            SATELLITE_MESSAGING_UNAVAILABLE_REASONS = new HashMap<>(Map.of(
+            SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED, new Pair<>(
+                    R.string.satellite_messaging_not_supported_notification_title,
+                    R.string.satellite_messaging_not_supported_notification_summary),
+            SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED, new Pair<>(
+                    R.string.satellite_messaging_not_provisioned_notification_title,
+                    R.string.satellite_messaging_not_provisioned_notification_summary),
+            SATELLITE_DISALLOWED_REASON_NOT_IN_ALLOWED_REGION, new Pair<>(
+                    R.string.satellite_messaging_not_in_allowed_region_notification_title,
+                    R.string.satellite_messaging_not_in_allowed_region_notification_summary),
+            SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP, new Pair<>(
+                    R.string.satellite_messaging_unsupported_default_sms_app_notification_title,
+                    R.string.satellite_messaging_unsupported_default_sms_app_notification_summary),
+            SATELLITE_DISALLOWED_REASON_LOCATION_DISABLED, new Pair<>(
+                    R.string.satellite_messaging_location_disabled_notification_title,
+                    R.string.satellite_messaging_location_disabled_notification_summary)
+    ));
 
     private static SatelliteAccessController sInstance;
 
     /** Feature flags to control behavior and errors. */
     @NonNull
     private final FeatureFlags mFeatureFlags;
+    @NonNull
+    private final Context mContext;
     @GuardedBy("mLock")
     @Nullable
     protected SatelliteOnDeviceAccessController mSatelliteOnDeviceAccessController;
@@ -174,11 +263,16 @@ public class SatelliteAccessController extends Handler {
     @NonNull
     private final ISatelliteProvisionStateCallback mInternalSatelliteProvisionStateCallback;
     @NonNull
+    private final ResultReceiver mInternalUpdateSystemSelectionChannelsResultReceiver;
+    @NonNull
     protected final Object mLock = new Object();
     @GuardedBy("mLock")
     @NonNull
     private final Set<ResultReceiver> mSatelliteAllowResultReceivers = new HashSet<>();
     @NonNull
+    private final Set<ResultReceiver>
+            mUpdateSystemSelectionChannelsResultReceivers = new HashSet<>();
+    @NonNull
     private List<String> mSatelliteCountryCodes;
     private boolean mIsSatelliteAllowAccessControl;
     @Nullable
@@ -191,14 +285,17 @@ public class SatelliteAccessController extends Handler {
     private boolean mOverriddenIsSatelliteAllowAccessControl;
     @Nullable
     private File mOverriddenSatelliteS2CellFile;
+    @Nullable
+    private String mOverriddenSatelliteConfigurationFileName;
     private long mOverriddenLocationFreshDurationNanos;
+
     @GuardedBy("mLock")
     @NonNull
-    private final Map<SatelliteOnDeviceAccessController.LocationToken, Boolean>
+    private final Map<SatelliteOnDeviceAccessController.LocationToken, Integer>
             mCachedAccessRestrictionMap = new LinkedHashMap<>() {
         @Override
         protected boolean removeEldestEntry(
-                Entry<SatelliteOnDeviceAccessController.LocationToken, Boolean> eldest) {
+                Entry<SatelliteOnDeviceAccessController.LocationToken, Integer> eldest) {
             return size() > MAX_CACHE_SIZE;
         }
     };
@@ -209,10 +306,39 @@ public class SatelliteAccessController extends Handler {
     @GuardedBy("mLock")
     @Nullable
     private Location mFreshLastKnownLocation = null;
+    @GuardedBy("mLock")
+    @Nullable
+    protected Integer mRegionalConfigId = null;
+    @GuardedBy("mLock")
+    @Nullable
+    protected Integer mNewRegionalConfigId = null;
+    @NonNull
+    private final CarrierConfigManager mCarrierConfigManager;
+    @NonNull
+    private final CarrierConfigManager.CarrierConfigChangeListener mCarrierConfigChangeListener;
+    /**
+     * Key: Sub Id, Value: (key: Regional satellite config Id, value: SatelliteRegionalConfig
+     * contains satellite config IDs and set of earfcns in the corresponding regions).
+     */
+    @GuardedBy("mRegionalSatelliteEarfcnsLock")
+    private Map<Integer, Map<Integer, SatelliteRegionalConfig>>
+            mSatelliteRegionalConfigPerSubMap = new HashMap();
+    @NonNull private final Object mRegionalSatelliteEarfcnsLock = new Object();
+
+    /** Key: Config ID; Value: SatelliteAccessConfiguration */
+    @GuardedBy("mLock")
+    @Nullable
+    @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
+    protected Map<Integer, SatelliteAccessConfiguration> mSatelliteAccessConfigMap;
 
     /** These are used for CTS test */
     private Path mCtsSatS2FilePath = null;
+    private Path mCtsSatelliteAccessConfigurationFilePath = null;
     protected static final String GOOGLE_US_SAN_SAT_S2_FILE_NAME = "google_us_san_sat_s2.dat";
+    protected static final String GOOGLE_US_SAN_SAT_MTV_S2_FILE_NAME =
+            "google_us_san_mtv_sat_s2.dat";
+    protected static final String SATELLITE_ACCESS_CONFIG_FILE_NAME =
+            "satellite_access_config.json";
 
     /** These are for config updater config data */
     private static final String SATELLITE_ACCESS_CONTROL_DATA_DIR = "satellite_access_control";
@@ -245,6 +371,7 @@ public class SatelliteAccessController extends Handler {
     protected static final int
             DEFAULT_MAX_RETRY_COUNT_FOR_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION = 3;
     protected static final int DEFAULT_THROTTLE_INTERVAL_FOR_LOCATION_QUERY_MINUTES = 10;
+    private static final int MAX_EARFCN_ARRAY_LENGTH = 32;
 
     private long mRetryIntervalToEvaluateUserInSatelliteAllowedRegion = 0;
     private int mMaxRetryCountForValidatingPossibleChangeInAllowedRegion = 0;
@@ -259,9 +386,13 @@ public class SatelliteAccessController extends Handler {
      */
     private final ConcurrentHashMap<IBinder, ISatelliteCommunicationAllowedStateCallback>
             mSatelliteCommunicationAllowedStateChangedListeners = new ConcurrentHashMap<>();
-    private final Object mSatelliteCommunicationAllowStateLock = new Object();
+    protected final Object mSatelliteCommunicationAllowStateLock = new Object();
     @GuardedBy("mSatelliteCommunicationAllowStateLock")
-    private boolean mCurrentSatelliteAllowedState = false;
+    protected boolean mCurrentSatelliteAllowedState = false;
+
+    private final ConcurrentHashMap<IBinder, ISatelliteDisallowedReasonsCallback>
+            mSatelliteDisallowedReasonsChangedListeners = new ConcurrentHashMap<>();
+    private final Object mSatelliteDisallowedReasonsLock = new Object();
 
     protected static final long ALLOWED_STATE_CACHE_VALID_DURATION_NANOS =
             TimeUnit.HOURS.toNanos(4);
@@ -273,6 +404,13 @@ public class SatelliteAccessController extends Handler {
     private long mOnDeviceLookupStartTimeMillis;
     private long mTotalCheckingStartTimeMillis;
 
+    private final boolean mNotifySatelliteAvailabilityEnabled;
+    private Notification mSatelliteAvailableNotification;
+    // Key: SatelliteManager#SatelliteDisallowedReason; Value: Notification
+    private final Map<Integer, Notification> mSatelliteUnAvailableNotifications = new HashMap<>();
+    private NotificationManager mNotificationManager;
+    private final List<Integer> mSatelliteDisallowedReasons = new ArrayList<>();
+
     protected BroadcastReceiver mLocationModeChangedBroadcastReceiver = new BroadcastReceiver() {
         @Override
         public void onReceive(Context context, Intent intent) {
@@ -281,6 +419,9 @@ public class SatelliteAccessController extends Handler {
                 if (mLocationManager.isLocationEnabled()) {
                     plogd("Location settings is just enabled");
                     sendRequestAsync(EVENT_LOCATION_SETTINGS_ENABLED, null);
+                } else {
+                    plogd("Location settings is just enabled");
+                    sendRequestAsync(EVENT_LOCATION_SETTINGS_DISABLED, null);
                 }
             }
         }
@@ -311,6 +452,7 @@ public class SatelliteAccessController extends Handler {
             @Nullable SatelliteOnDeviceAccessController satelliteOnDeviceAccessController,
             @Nullable File s2CellFile) {
         super(looper);
+        mContext = context;
         if (isSatellitePersistentLoggingEnabled(context, featureFlags)) {
             mPersistentLogger = new PersistentLogger(
                     DropBoxManagerLoggerBackend.getInstance(context));
@@ -330,6 +472,7 @@ public class SatelliteAccessController extends Handler {
         mControllerMetricsStats = ControllerMetricsStats.getInstance();
         mAccessControllerMetricsStats = AccessControllerMetricsStats.getInstance();
         initSharedPreferences(context);
+        checkSharedPreference();
         loadOverlayConfigs(context);
         // loadConfigUpdaterConfigs has to be called after loadOverlayConfigs
         // since config updater config has higher priority and thus can override overlay config
@@ -345,6 +488,9 @@ public class SatelliteAccessController extends Handler {
                 handleIsSatelliteSupportedResult(resultCode, resultData);
             }
         };
+        mSatelliteController.incrementResultReceiverCount(
+                "SAC:mInternalSatelliteSupportedResultReceiver");
+
         mInternalSatelliteProvisionedResultReceiver = new ResultReceiver(this) {
             @Override
             protected void onReceiveResult(int resultCode, Bundle resultData) {
@@ -353,37 +499,75 @@ public class SatelliteAccessController extends Handler {
         };
 
         mConfigUpdaterMetricsStats = ConfigUpdaterMetricsStats.getOrCreateInstance();
+        mNotifySatelliteAvailabilityEnabled =
+                context.getResources().getBoolean(
+                        R.bool.config_satellite_should_notify_availability);
+        initializeSatelliteSystemNotification(context);
+        registerDefaultSmsAppChangedBroadcastReceiver(context);
 
         mInternalSatelliteSupportedStateCallback = new ISatelliteSupportedStateCallback.Stub() {
             @Override
             public void onSatelliteSupportedStateChanged(boolean isSupported) {
                 logd("onSatelliteSupportedStateChanged: isSupported=" + isSupported);
                 if (isSupported) {
+                    final String caller = "SAC:onSatelliteSupportedStateChanged";
                     requestIsCommunicationAllowedForCurrentLocation(
                             new ResultReceiver(null) {
                                 @Override
                                 protected void onReceiveResult(int resultCode, Bundle resultData) {
+                                    mSatelliteController.decrementResultReceiverCount(caller);
                                     // do nothing
                                 }
                             }, false);
+                    mSatelliteController.incrementResultReceiverCount(caller);
+                    if (mSatelliteDisallowedReasons.contains(
+                            Integer.valueOf(SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED))) {
+                        mSatelliteDisallowedReasons.remove(
+                                Integer.valueOf(SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED));
+                        handleEventDisallowedReasonsChanged();
+                    }
+                } else {
+                    if (!mSatelliteDisallowedReasons.contains(
+                            Integer.valueOf(SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED))) {
+                        mSatelliteDisallowedReasons.add(
+                                Integer.valueOf(SATELLITE_DISALLOWED_REASON_NOT_SUPPORTED));
+                        handleEventDisallowedReasonsChanged();
+                    }
                 }
             }
         };
-        mSatelliteController.registerForSatelliteSupportedStateChanged(
+        int result = mSatelliteController.registerForSatelliteSupportedStateChanged(
                 mInternalSatelliteSupportedStateCallback);
+        plogd("registerForSatelliteSupportedStateChanged result: " + result);
 
         mInternalSatelliteProvisionStateCallback = new ISatelliteProvisionStateCallback.Stub() {
             @Override
             public void onSatelliteProvisionStateChanged(boolean isProvisioned) {
                 logd("onSatelliteProvisionStateChanged: isProvisioned=" + isProvisioned);
                 if (isProvisioned) {
+                    final String caller = "SAC:onSatelliteProvisionStateChanged";
                     requestIsCommunicationAllowedForCurrentLocation(
                             new ResultReceiver(null) {
                                 @Override
                                 protected void onReceiveResult(int resultCode, Bundle resultData) {
+                                    mSatelliteController.decrementResultReceiverCount(caller);
                                     // do nothing
                                 }
                             }, false);
+                    mSatelliteController.incrementResultReceiverCount(caller);
+                    if (mSatelliteDisallowedReasons.contains(
+                            SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED)) {
+                        mSatelliteDisallowedReasons.remove(
+                                Integer.valueOf(SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED));
+                        handleEventDisallowedReasonsChanged();
+                    }
+                } else {
+                    if (!mSatelliteDisallowedReasons.contains(
+                            SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED)) {
+                        mSatelliteDisallowedReasons.add(
+                                SATELLITE_DISALLOWED_REASON_NOT_PROVISIONED);
+                        handleEventDisallowedReasonsChanged();
+                    }
                 }
             }
 
@@ -394,12 +578,33 @@ public class SatelliteAccessController extends Handler {
                         + satelliteSubscriberProvisionStatus);
             }
         };
-        mSatelliteController.registerForSatelliteProvisionStateChanged(
+        initializeSatelliteSystemNotification(context);
+        result = mSatelliteController.registerForSatelliteProvisionStateChanged(
                 mInternalSatelliteProvisionStateCallback);
+        plogd("registerForSatelliteProvisionStateChanged result: " + result);
+
+        mInternalUpdateSystemSelectionChannelsResultReceiver = new ResultReceiver(this) {
+            @Override
+            protected void onReceiveResult(int resultCode, Bundle resultData) {
+                plogd("UpdateSystemSelectionChannels.onReceiveResult: resultCode=" + resultCode
+                          + ", resultData=" + resultData);
+                sendUpdateSystemSelectionChannelsResult(resultCode, resultData);
+            }
+        };
 
         // Init the SatelliteOnDeviceAccessController so that the S2 level can be cached
         initSatelliteOnDeviceAccessController();
         registerLocationModeChangedBroadcastReceiver(context);
+
+        mCarrierConfigManager = context.getSystemService(CarrierConfigManager.class);
+        mCarrierConfigChangeListener =
+                (slotIndex, subId, carrierId, specificCarrierId) -> handleCarrierConfigChanged(
+                    context, slotIndex, subId, carrierId, specificCarrierId);
+
+        if (mCarrierConfigManager != null) {
+            mCarrierConfigManager.registerCarrierConfigChangeListener(
+                    new HandlerExecutor(new Handler(looper)), mCarrierConfigChangeListener);
+        }
     }
 
     private void updateCurrentSatelliteAllowedState(boolean isAllowed) {
@@ -411,7 +616,14 @@ public class SatelliteAccessController extends Handler {
                 mCurrentSatelliteAllowedState = isAllowed;
                 notifySatelliteCommunicationAllowedStateChanged(isAllowed);
                 mControllerMetricsStats.reportAllowedStateChanged();
+                if (!isAllowed) {
+                    synchronized (mLock) {
+                        plogd("updateCurrentSatelliteAllowedState : set mNewRegionalConfigId null");
+                        mNewRegionalConfigId = null;
+                    }
+                }
             }
+            updateRegionalConfigId();
         }
     }
 
@@ -448,10 +660,14 @@ public class SatelliteAccessController extends Handler {
                 updateSatelliteConfigData((Context) ar.userObj);
                 break;
             case EVENT_LOCATION_SETTINGS_ENABLED:
+            case EVENT_LOCATION_SETTINGS_DISABLED:
                 // Fall through
             case EVENT_COUNTRY_CODE_CHANGED:
                 handleSatelliteAllowedRegionPossiblyChanged(msg.what);
                 break;
+            case CMD_UPDATE_SYSTEM_SELECTION_CHANNELS:
+                handleCmdUpdateSystemSelectionChannels((ResultReceiver) msg.obj);
+                break;
             default:
                 plogw("SatelliteAccessControllerHandler: unexpected message code: " + msg.what);
                 break;
@@ -479,7 +695,70 @@ public class SatelliteAccessController extends Handler {
         }
         mAccessControllerMetricsStats.setTriggeringEvent(TRIGGERING_EVENT_EXTERNAL_REQUEST);
         sendRequestAsync(CMD_IS_SATELLITE_COMMUNICATION_ALLOWED,
-                new Pair<>(mSatelliteController.getSatellitePhone().getSubId(), result));
+                new Pair<>(mSatelliteController.getSelectedSatelliteSubId(), result));
+        mSatelliteController.incrementResultReceiverCount(
+                "SAC:requestIsCommunicationAllowedForCurrentLocation");
+    }
+
+    /**
+     * Request to get satellite access configuration for the current location.
+     *
+     * @param result The result receiver that returns satellite access configuration
+     *               for the current location if the request is successful or an error code
+     *               if the request failed.
+     */
+    public void requestSatelliteAccessConfigurationForCurrentLocation(
+            @NonNull ResultReceiver result) {
+        if (!mFeatureFlags.carrierRoamingNbIotNtn()) {
+            plogd("carrierRoamingNbIotNtnFlag is disabled");
+            result.send(SATELLITE_RESULT_REQUEST_NOT_SUPPORTED, null);
+            return;
+        }
+        plogd("requestSatelliteAccessConfigurationForCurrentLocation");
+        ResultReceiver internalResultReceiver = new ResultReceiver(this) {
+            @Override
+            protected void onReceiveResult(int resultCode, Bundle resultData) {
+                plogd("requestSatelliteAccessConfigurationForCurrentLocation: resultCode="
+                        + resultCode + ", resultData=" + resultData);
+                boolean isSatelliteCommunicationAllowed = false;
+                if (resultCode == SATELLITE_RESULT_SUCCESS) {
+                    if (resultData.containsKey(KEY_SATELLITE_COMMUNICATION_ALLOWED)) {
+                        isSatelliteCommunicationAllowed =
+                                resultData.getBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED);
+                    } else {
+                        loge("KEY_SATELLITE_COMMUNICATION_ALLOWED does not exist.");
+                        result.send(SATELLITE_RESULT_INVALID_TELEPHONY_STATE, null);
+                        return;
+                    }
+                } else {
+                    loge("resultCode is not SATELLITE_RESULT_SUCCESS.");
+                    result.send(resultCode, null);
+                    return;
+                }
+
+                SatelliteAccessConfiguration satelliteAccessConfig = null;
+                synchronized (mLock) {
+                    if (isSatelliteCommunicationAllowed && SatelliteAccessConfigurationParser
+                            .isRegionalConfigIdValid(mRegionalConfigId)) {
+                        plogd("requestSatelliteAccessConfigurationForCurrentLocation : "
+                                + "mRegionalConfigId is " + mRegionalConfigId);
+                        satelliteAccessConfig = Optional.ofNullable(mSatelliteAccessConfigMap)
+                                .map(map -> map.get(mRegionalConfigId))
+                                .orElse(null);
+                    }
+                }
+                plogd("requestSatelliteAccessConfigurationForCurrentLocation : "
+                        + "satelliteAccessConfig is " + satelliteAccessConfig);
+                if (satelliteAccessConfig == null) {
+                    result.send(SATELLITE_RESULT_NO_RESOURCES, null);
+                } else {
+                    Bundle bundle = new Bundle();
+                    bundle.putParcelable(KEY_SATELLITE_ACCESS_CONFIGURATION, satelliteAccessConfig);
+                    result.send(resultCode, bundle);
+                }
+            }
+        };
+        requestIsCommunicationAllowedForCurrentLocation(internalResultReceiver, false);
     }
 
     /**
@@ -488,7 +767,8 @@ public class SatelliteAccessController extends Handler {
      */
     public boolean setSatelliteAccessControlOverlayConfigs(boolean reset, boolean isAllowed,
             @Nullable String s2CellFile, long locationFreshDurationNanos,
-            @Nullable List<String> satelliteCountryCodes) {
+            @Nullable List<String> satelliteCountryCodes,
+            @Nullable String satelliteConfigurationFile) {
         if (!isMockModemAllowed()) {
             plogd("setSatelliteAccessControllerOverlayConfigs: mock modem is not allowed");
             return false;
@@ -497,7 +777,8 @@ public class SatelliteAccessController extends Handler {
                 + ", isAllowed" + isAllowed + ", s2CellFile=" + s2CellFile
                 + ", locationFreshDurationNanos=" + locationFreshDurationNanos
                 + ", satelliteCountryCodes=" + ((satelliteCountryCodes != null)
-                ? String.join(", ", satelliteCountryCodes) : null));
+                ? String.join(", ", satelliteCountryCodes) : null)
+                + ", satelliteConfigurationFile=" + satelliteConfigurationFile);
         synchronized (mLock) {
             if (reset) {
                 mIsOverlayConfigOverridden = false;
@@ -513,9 +794,25 @@ public class SatelliteAccessController extends Handler {
                                 + " does not exist");
                         mOverriddenSatelliteS2CellFile = null;
                     }
+                    mCachedAccessRestrictionMap.clear();
                 } else {
                     mOverriddenSatelliteS2CellFile = null;
                 }
+                if (!TextUtils.isEmpty(satelliteConfigurationFile)) {
+                    File overriddenSatelliteConfigurationFile = getTestSatelliteConfiguration(
+                            satelliteConfigurationFile);
+                    if (overriddenSatelliteConfigurationFile.exists()) {
+                        mOverriddenSatelliteConfigurationFileName =
+                                overriddenSatelliteConfigurationFile.getAbsolutePath();
+                    } else {
+                        plogd("The overriding file "
+                                + overriddenSatelliteConfigurationFile.getAbsolutePath()
+                                + " does not exist");
+                        mOverriddenSatelliteConfigurationFileName = null;
+                    }
+                } else {
+                    mOverriddenSatelliteConfigurationFileName = null;
+                }
                 mOverriddenLocationFreshDurationNanos = locationFreshDurationNanos;
                 if (satelliteCountryCodes != null) {
                     mOverriddenSatelliteCountryCodes = satelliteCountryCodes;
@@ -529,10 +826,33 @@ public class SatelliteAccessController extends Handler {
         return true;
     }
 
+    /**
+     * Report updated system selection to modem and report the update result.
+     */
+    public void updateSystemSelectionChannels(@NonNull ResultReceiver result) {
+        plogd("updateSystemSelectionChannels");
+        if (!mFeatureFlags.carrierRoamingNbIotNtn()) {
+            plogd("updateSystemSelectionChannels: "
+                    + "carrierRoamingNbIotNtn flag is disabled");
+            result.send(SATELLITE_RESULT_REQUEST_NOT_SUPPORTED, null);
+            return;
+        }
+        synchronized (mLock) {
+            if (mRegionalConfigId == null) {
+                plogd("updateSystemSelectionChannels: Invalid Regional config ID."
+                        + " System Selection channels can not be passed down to modem");
+                result.send(SATELLITE_RESULT_ACCESS_BARRED, null);
+                return;
+            }
+        }
+        sendRequestAsync(CMD_UPDATE_SYSTEM_SELECTION_CHANNELS, result);
+    }
+
     protected File getTestSatelliteS2File(String fileName) {
         plogd("getTestSatelliteS2File: fileName=" + fileName);
-        if (TextUtils.equals(fileName, GOOGLE_US_SAN_SAT_S2_FILE_NAME)) {
-            mCtsSatS2FilePath = copyTestSatS2FileToPhoneDirectory(GOOGLE_US_SAN_SAT_S2_FILE_NAME);
+        if (TextUtils.equals(fileName, GOOGLE_US_SAN_SAT_S2_FILE_NAME)
+                || TextUtils.equals(fileName, GOOGLE_US_SAN_SAT_MTV_S2_FILE_NAME)) {
+            mCtsSatS2FilePath = copyTestAssetFileToPhoneDirectory(fileName);
             if (mCtsSatS2FilePath != null) {
                 return mCtsSatS2FilePath.toFile();
             } else {
@@ -542,8 +862,21 @@ public class SatelliteAccessController extends Handler {
         return new File(fileName);
     }
 
+    protected File getTestSatelliteConfiguration(String fileName) {
+        plogd("getTestSatelliteConfiguration: fileName=" + fileName);
+        if (TextUtils.equals(fileName, SATELLITE_ACCESS_CONFIG_FILE_NAME)) {
+            mCtsSatelliteAccessConfigurationFilePath = copyTestAssetFileToPhoneDirectory(fileName);
+            if (mCtsSatelliteAccessConfigurationFilePath != null) {
+                return mCtsSatelliteAccessConfigurationFilePath.toFile();
+            } else {
+                ploge("getTestSatelliteConfiguration: mCtsSatelliteConfigurationFilePath is null");
+            }
+        }
+        return new File(fileName);
+    }
+
     @Nullable
-    private static Path copyTestSatS2FileToPhoneDirectory(String sourceFileName) {
+    private static Path copyTestAssetFileToPhoneDirectory(String sourceFileName) {
         PhoneGlobals phoneGlobals = PhoneGlobals.getInstance();
         File ctsFile = phoneGlobals.getDir("cts", Context.MODE_PRIVATE);
         if (!ctsFile.exists()) {
@@ -551,19 +884,26 @@ public class SatelliteAccessController extends Handler {
         }
 
         Path targetDir = ctsFile.toPath();
-        Path targetSatS2FilePath = targetDir.resolve(sourceFileName);
+        Path targetFilePath = targetDir.resolve(sourceFileName);
         try {
-            InputStream inputStream = phoneGlobals.getAssets().open(sourceFileName);
+            var assetManager = phoneGlobals.getAssets();
+            if (assetManager == null) {
+                loge("copyTestAssetFileToPhoneDirectory: no assets");
+                return null;
+            }
+            InputStream inputStream = assetManager.open(sourceFileName);
             if (inputStream == null) {
-                loge("copyTestSatS2FileToPhoneDirectory: Resource=" + sourceFileName
+                loge("copyTestAssetFileToPhoneDirectory: Resource=" + sourceFileName
                         + " not found");
+                return null;
             } else {
-                Files.copy(inputStream, targetSatS2FilePath, StandardCopyOption.REPLACE_EXISTING);
+                Files.copy(inputStream, targetFilePath, StandardCopyOption.REPLACE_EXISTING);
             }
         } catch (IOException ex) {
-            loge("copyTestSatS2FileToPhoneDirectory: ex=" + ex);
+            loge("copyTestAssetFileToPhoneDirectory: ex=" + ex);
+            return null;
         }
-        return targetSatS2FilePath;
+        return targetFilePath;
     }
 
     @Nullable
@@ -611,7 +951,7 @@ public class SatelliteAccessController extends Handler {
     private boolean isS2CellFileValid(@NonNull File s2CellFile) {
         try {
             SatelliteOnDeviceAccessController satelliteOnDeviceAccessController =
-                    SatelliteOnDeviceAccessController.create(s2CellFile);
+                    SatelliteOnDeviceAccessController.create(s2CellFile, mFeatureFlags);
             int s2Level = satelliteOnDeviceAccessController.getS2Level();
             if (s2Level < MIN_S2_LEVEL || s2Level > MAX_S2_LEVEL) {
                 ploge("isS2CellFileValid: invalid s2 level = " + s2Level);
@@ -816,6 +1156,7 @@ public class SatelliteAccessController extends Handler {
             ploge("The satellite S2 cell file " + satelliteS2CellFileName + " does not exist");
             mSatelliteS2CellFile = null;
         }
+
         mLocationFreshDurationNanos = getSatelliteLocationFreshDurationFromOverlayConfig(context);
         mAccessControllerMetricsStats.setConfigDataSource(
                 SatelliteConstants.CONFIG_DATA_SOURCE_DEVICE_CONFIG);
@@ -826,6 +1167,36 @@ public class SatelliteAccessController extends Handler {
         mLocationQueryThrottleIntervalNanos = getLocationQueryThrottleIntervalNanos(context);
     }
 
+    protected void loadSatelliteAccessConfigurationFromDeviceConfig() {
+        logd("loadSatelliteAccessConfigurationFromDeviceConfig:");
+        String satelliteConfigurationFileName;
+        synchronized (mLock) {
+            if (mIsOverlayConfigOverridden && mOverriddenSatelliteConfigurationFileName != null) {
+                satelliteConfigurationFileName = mOverriddenSatelliteConfigurationFileName;
+            } else {
+                satelliteConfigurationFileName = getSatelliteConfigurationFileNameFromOverlayConfig(
+                        mContext);
+            }
+        }
+        loadSatelliteAccessConfigurationFromFile(satelliteConfigurationFileName);
+    }
+
+    protected void loadSatelliteAccessConfigurationFromFile(String fileName) {
+        logd("loadSatelliteAccessConfigurationFromFile: " + fileName);
+        if (!TextUtils.isEmpty(fileName)) {
+            try {
+                synchronized (mLock) {
+                    mSatelliteAccessConfigMap =
+                            SatelliteAccessConfigurationParser.parse(fileName);
+                }
+            } catch (Exception e) {
+                loge("loadSatelliteAccessConfigurationFromFile: failed load json file: " + e);
+            }
+        } else {
+            loge("loadSatelliteAccessConfigurationFromFile: fileName is empty");
+        }
+    }
+
     private void loadConfigUpdaterConfigs() {
         if (mSharedPreferences == null) {
             ploge("loadConfigUpdaterConfigs : mSharedPreferences is null");
@@ -946,6 +1317,18 @@ public class SatelliteAccessController extends Handler {
         }
     }
 
+    private void registerDefaultSmsAppChangedBroadcastReceiver(Context context) {
+        if (!mFeatureFlags.carrierRoamingNbIotNtn()) {
+            plogd("registerDefaultSmsAppChangedBroadcastReceiver: Flag "
+                    + "carrierRoamingNbIotNtn is disabled");
+            return;
+        }
+        IntentFilter intentFilter = new IntentFilter();
+        intentFilter.addAction(Intent.ACTION_PACKAGE_CHANGED);
+        intentFilter.addDataScheme("package");
+        context.registerReceiver(mDefaultSmsAppChangedBroadcastReceiver, intentFilter);
+    }
+
     private void registerLocationModeChangedBroadcastReceiver(Context context) {
         if (!mFeatureFlags.oemEnabledSatelliteFlag()) {
             plogd("registerLocationModeChangedBroadcastReceiver: Flag "
@@ -1002,8 +1385,8 @@ public class SatelliteAccessController extends Handler {
                         if (isRegionDisallowed(networkCountryIsoList)) {
                             Bundle bundle = new Bundle();
                             bundle.putBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED, false);
-                            mAccessControllerMetricsStats.setAccessControlType(
-                                    SatelliteConstants.ACCESS_CONTROL_TYPE_NETWORK_COUNTRY_CODE)
+                            mAccessControllerMetricsStats.setAccessControlType(SatelliteConstants
+                                            .ACCESS_CONTROL_TYPE_NETWORK_COUNTRY_CODE)
                                     .setCountryCodes(networkCountryIsoList);
                             sendSatelliteAllowResultToReceivers(SATELLITE_RESULT_SUCCESS, bundle,
                                     false);
@@ -1057,18 +1440,125 @@ public class SatelliteAccessController extends Handler {
         synchronized (mLock) {
             for (ResultReceiver resultReceiver : mSatelliteAllowResultReceivers) {
                 resultReceiver.send(resultCode, resultData);
+                mSatelliteController.decrementResultReceiverCount(
+                        "SAC:requestIsCommunicationAllowedForCurrentLocation");
             }
             mSatelliteAllowResultReceivers.clear();
         }
         if (!shouldRetryValidatingPossibleChangeInAllowedRegion(resultCode)) {
             setIsSatelliteAllowedRegionPossiblyChanged(false);
         }
+        Integer disallowedReason = getDisallowedReason(resultCode, allowed);
+        boolean isChanged = false;
+        if (disallowedReason != SATELLITE_DISALLOWED_REASON_NONE) {
+            if (!mSatelliteDisallowedReasons.contains(disallowedReason)) {
+                isChanged = true;
+            }
+        } else {
+            if (mSatelliteDisallowedReasons.contains(
+                    SATELLITE_DISALLOWED_REASON_NOT_IN_ALLOWED_REGION)
+                    || mSatelliteDisallowedReasons.contains(
+                    SATELLITE_DISALLOWED_REASON_LOCATION_DISABLED)) {
+                isChanged = true;
+            }
+        }
+        mSatelliteDisallowedReasons.removeAll(DISALLOWED_REASONS_TO_BE_RESET);
+        if (disallowedReason != SATELLITE_DISALLOWED_REASON_NONE) {
+            mSatelliteDisallowedReasons.add(disallowedReason);
+        }
+        if (isChanged) {
+            handleEventDisallowedReasonsChanged();
+        }
         synchronized (mIsAllowedCheckBeforeEnablingSatelliteLock) {
             mIsAllowedCheckBeforeEnablingSatellite = false;
         }
         reportMetrics(resultCode, allowed);
     }
 
+    private int getDisallowedReason(int resultCode, boolean allowed) {
+        if (resultCode == SATELLITE_RESULT_SUCCESS) {
+            if (!allowed) {
+                return SATELLITE_DISALLOWED_REASON_NOT_IN_ALLOWED_REGION;
+            }
+        } else if (resultCode == SATELLITE_RESULT_LOCATION_DISABLED) {
+            return SATELLITE_DISALLOWED_REASON_LOCATION_DISABLED;
+        }
+        return SATELLITE_DISALLOWED_REASON_NONE;
+    }
+
+    private void handleEventDisallowedReasonsChanged() {
+        logd("mSatelliteDisallowedReasons:"
+                + String.join(", ", mSatelliteDisallowedReasons.toString()));
+        notifySatelliteDisallowedReasonsChanged();
+        int subId = mSatelliteController.getSelectedSatelliteSubId();
+        if (mSatelliteController.isSatelliteSystemNotificationsEnabled(
+                CarrierConfigManager.CARRIER_ROAMING_NTN_CONNECT_MANUAL)) {
+            showSatelliteSystemNotification();
+        }
+    }
+
+    private void showSatelliteSystemNotification() {
+        if (mNotificationManager == null) {
+            logd("showSatelliteSystemNotification: NotificationManager is null");
+            return;
+        }
+
+        if (mSatelliteDisallowedReasons.isEmpty()) {
+            mNotificationManager.cancel(UNAVAILABLE_NOTIFICATION_TAG, NOTIFICATION_ID);
+            if (!hasAlreadyNotified(KEY_AVAILABLE_NOTIFICATION_SHOWN)) {
+                mNotificationManager.notifyAsUser(
+                        AVAILABLE_NOTIFICATION_TAG,
+                        NOTIFICATION_ID,
+                        mSatelliteAvailableNotification,
+                        UserHandle.ALL
+                );
+                markAsNotified(KEY_AVAILABLE_NOTIFICATION_SHOWN, true);
+                markAsNotified(KEY_UNAVAILABLE_NOTIFICATION_SHOWN, false);
+            }
+        } else {
+            mNotificationManager.cancel(AVAILABLE_NOTIFICATION_TAG, NOTIFICATION_ID);
+            for (Integer reason : mSatelliteDisallowedReasons) {
+                if (!hasAlreadyNotified(KEY_UNAVAILABLE_NOTIFICATION_SHOWN)) {
+                    mNotificationManager.notifyAsUser(
+                            UNAVAILABLE_NOTIFICATION_TAG,
+                            NOTIFICATION_ID,
+                            mSatelliteUnAvailableNotifications.get(reason),
+                            UserHandle.ALL
+                    );
+                    markAsNotified(KEY_UNAVAILABLE_NOTIFICATION_SHOWN, true);
+                    markAsNotified(KEY_AVAILABLE_NOTIFICATION_SHOWN, false);
+                    break;
+                }
+            }
+        }
+    }
+
+    private boolean hasAlreadyNotified(String key) {
+        return mSharedPreferences.getBoolean(key, false);
+    }
+
+    private void markAsNotified(String key, boolean notified) {
+        mSharedPreferences.edit().putBoolean(key, notified).apply();
+    }
+
+    private void checkSharedPreference() {
+        String[] keys = {
+                CONFIG_UPDATER_SATELLITE_IS_ALLOW_ACCESS_CONTROL_KEY,
+                LATEST_SATELLITE_COMMUNICATION_ALLOWED_KEY,
+                KEY_AVAILABLE_NOTIFICATION_SHOWN,
+                KEY_UNAVAILABLE_NOTIFICATION_SHOWN
+        };
+        // An Exception may occur if the initial value is set to HashSet while attempting to obtain
+        // a boolean value. If an exception occurs, the SharedPreferences will be removed with Keys.
+        Arrays.stream(keys).forEach(key -> {
+            try {
+                mSharedPreferences.getBoolean(key, false);
+            } catch (ClassCastException e) {
+                mSharedPreferences.edit().remove(key).apply();
+            }
+        });
+    }
+
     /**
      * Telephony-internal logic to verify if satellite access is restricted at the current
      * location.
@@ -1132,6 +1622,135 @@ public class SatelliteAccessController extends Handler {
         };
     }
 
+    private void initializeSatelliteSystemNotification(@NonNull Context context) {
+        final NotificationChannel notificationChannel = new NotificationChannel(
+                NOTIFICATION_CHANNEL_ID,
+                NOTIFICATION_CHANNEL,
+                NotificationManager.IMPORTANCE_DEFAULT
+        );
+        notificationChannel.setSound(null, null);
+        mNotificationManager = context.getSystemService(NotificationManager.class);
+        if(mNotificationManager == null) {
+            ploge("initializeSatelliteSystemNotification: notificationManager is null");
+            return;
+        }
+        mNotificationManager.createNotificationChannel(notificationChannel);
+
+        createAvailableNotifications(context);
+        createUnavailableNotifications(context);
+    }
+
+    private Notification createNotification(@NonNull Context context, String title,
+            String content) {
+        Notification.Builder notificationBuilder = new Notification.Builder(context)
+                .setContentTitle(title)
+                .setContentText(content)
+                .setSmallIcon(R.drawable.ic_android_satellite_24px)
+                .setChannelId(NOTIFICATION_CHANNEL_ID)
+                .setAutoCancel(true)
+                .setColor(context.getColor(
+                        com.android.internal.R.color.system_notification_accent_color))
+                .setVisibility(Notification.VISIBILITY_PUBLIC);
+
+        return notificationBuilder.build();
+    }
+
+    private void createAvailableNotifications(Context context) {
+        int subId = mSatelliteController.getSelectedSatelliteSubId();
+        int titleId;
+        int summaryId;
+
+        if (mSatelliteController.isSatelliteServiceSupportedByCarrier(
+                subId, NetworkRegistrationInfo.SERVICE_TYPE_SMS)) {
+            titleId = R.string.satellite_messaging_available_notification_title;
+            summaryId = R.string.satellite_messaging_available_notification_summary;
+        } else {
+            titleId = R.string.satellite_sos_available_notification_title;
+            summaryId = R.string.satellite_sos_available_notification_summary;
+        }
+
+        mSatelliteAvailableNotification = createNotification(
+                context,
+                context.getResources().getString(titleId),
+                context.getResources().getString(summaryId));
+    }
+
+    private void createUnavailableNotifications(Context context) {
+        int subId = mSatelliteController.getSelectedSatelliteSubId();
+
+        HashMap<Integer, Pair<Integer, Integer>> unavailableReasons;
+        if (mSatelliteController.isSatelliteServiceSupportedByCarrier(
+                subId, NetworkRegistrationInfo.SERVICE_TYPE_SMS)) {
+            unavailableReasons = SATELLITE_MESSAGING_UNAVAILABLE_REASONS;
+        } else {
+            unavailableReasons = SATELLITE_SOS_UNAVAILABLE_REASONS;
+        }
+
+        for (int reason : unavailableReasons.keySet()) {
+            Pair<Integer, Integer> notificationString =
+                    unavailableReasons.getOrDefault(reason, null);
+            if (notificationString != null) {
+                mSatelliteUnAvailableNotifications.put(reason,
+                        createNotification(
+                                context,
+                                context.getResources().getString(notificationString.first),
+                                context.getResources().getString(notificationString.second)));
+            }
+        }
+    }
+
+    private final BroadcastReceiver mDefaultSmsAppChangedBroadcastReceiver =
+            new BroadcastReceiver() {
+                @Override
+                public void onReceive(Context context, Intent intent) {
+                    if (intent.getAction()
+                            .equals(Intent.ACTION_PACKAGE_CHANGED)) {
+                        evaluatePossibleChangeInDefaultSmsApp(context);
+                    }
+                }
+            };
+
+    private void evaluatePossibleChangeInDefaultSmsApp(@NonNull Context context) {
+        if (!mFeatureFlags.carrierRoamingNbIotNtn()) {
+            plogd("evaluatePossibleChangeInDefaultSmsApp: Flag "
+                    + "carrierRoamingNbIotNtn is disabled");
+            return;
+        }
+
+        boolean isDefaultMsgAppSupported = false;
+        ComponentName componentName = SmsApplication.getDefaultSmsApplicationAsUser(
+                        context, true, context.getUser());
+        plogd("Current default SMS app:" + componentName);
+        if (componentName != null) {
+            String packageName = componentName.getPackageName();
+            List<String> supportedMsgApps =
+                    mSatelliteController.getSatelliteSupportedMsgApps(
+                            mSatelliteController.getSelectedSatelliteSubId());
+            plogd("supportedMsgApps:" + String.join(", ", supportedMsgApps));
+            if (supportedMsgApps.contains(packageName)) {
+                isDefaultMsgAppSupported = true;
+            }
+        } else {
+            plogd("No default SMS app");
+        }
+
+        if (isDefaultMsgAppSupported) {
+            if (mSatelliteDisallowedReasons.contains(Integer.valueOf(
+                    SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP))) {
+                mSatelliteDisallowedReasons.remove(Integer.valueOf(
+                        SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP));
+                handleEventDisallowedReasonsChanged();
+            }
+        } else {
+            if (!mSatelliteDisallowedReasons.contains(Integer.valueOf(
+                    SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP))) {
+                mSatelliteDisallowedReasons.add(Integer.valueOf(
+                        SATELLITE_DISALLOWED_REASON_UNSUPPORTED_DEFAULT_MSG_APP));
+                handleEventDisallowedReasonsChanged();
+            }
+        }
+    }
+
     private void handleSatelliteAllowedRegionPossiblyChanged(int handleEvent) {
         if (!mFeatureFlags.oemEnabledSatelliteFlag()) {
             ploge("handleSatelliteAllowedRegionPossiblyChanged: "
@@ -1242,14 +1861,6 @@ public class SatelliteAccessController extends Handler {
 
     private void executeLocationQuery() {
         plogd("executeLocationQuery");
-        synchronized (mPossibleChangeInSatelliteAllowedRegionLock) {
-            if (isSatelliteAllowedRegionPossiblyChanged()) {
-                mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos =
-                        getElapsedRealtimeNanos();
-                plogd("mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos is set "
-                        + mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos);
-            }
-        }
         synchronized (mLock) {
             mFreshLastKnownLocation = getFreshLastKnownLocation();
             checkSatelliteAccessRestrictionUsingOnDeviceData();
@@ -1321,6 +1932,16 @@ public class SatelliteAccessController extends Handler {
                         + "Request for current location was already sent to LocationManager");
                 return;
             }
+
+            synchronized (mPossibleChangeInSatelliteAllowedRegionLock) {
+                if (isSatelliteAllowedRegionPossiblyChanged()) {
+                    mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos =
+                            getElapsedRealtimeNanos();
+                    plogd("mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos is set "
+                            + mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos);
+                }
+            }
+
             mLocationRequestCancellationSignal = new CancellationSignal();
             mLocationQueryStartTimeMillis = System.currentTimeMillis();
             mLocationManager.getCurrentLocation(LocationManager.FUSED_PROVIDER,
@@ -1372,7 +1993,7 @@ public class SatelliteAccessController extends Handler {
         }
     }
 
-    private void checkSatelliteAccessRestrictionForLocation(@NonNull Location location) {
+    protected void checkSatelliteAccessRestrictionForLocation(@NonNull Location location) {
         synchronized (mLock) {
             try {
                 SatelliteOnDeviceAccessController.LocationToken locationToken =
@@ -1380,8 +2001,11 @@ public class SatelliteAccessController extends Handler {
                                 location.getLatitude(),
                                 location.getLongitude(), mS2Level);
                 boolean satelliteAllowed;
+
                 if (mCachedAccessRestrictionMap.containsKey(locationToken)) {
-                    satelliteAllowed = mCachedAccessRestrictionMap.get(locationToken);
+                    mNewRegionalConfigId = mCachedAccessRestrictionMap.get(locationToken);
+                    satelliteAllowed = (mNewRegionalConfigId != null);
+                    plogd("mNewRegionalConfigId is " + mNewRegionalConfigId);
                 } else {
                     if (!initSatelliteOnDeviceAccessController()) {
                         ploge("Failed to init SatelliteOnDeviceAccessController");
@@ -1391,9 +2015,23 @@ public class SatelliteAccessController extends Handler {
                                 false);
                         return;
                     }
-                    satelliteAllowed = mSatelliteOnDeviceAccessController
-                            .isSatCommunicationAllowedAtLocation(locationToken);
-                    updateCachedAccessRestrictionMap(locationToken, satelliteAllowed);
+
+                    if (mFeatureFlags.carrierRoamingNbIotNtn()) {
+                        synchronized (mLock) {
+                            mNewRegionalConfigId = mSatelliteOnDeviceAccessController
+                                    .getRegionalConfigIdForLocation(locationToken);
+                            plogd("mNewRegionalConfigId is " + mNewRegionalConfigId);
+                            satelliteAllowed = (mNewRegionalConfigId != null);
+                        }
+                    } else {
+                        plogd("checkSatelliteAccessRestrictionForLocation: "
+                                + "carrierRoamingNbIotNtn is disabled");
+                        satelliteAllowed = mSatelliteOnDeviceAccessController
+                                .isSatCommunicationAllowedAtLocation(locationToken);
+                        mNewRegionalConfigId =
+                                satelliteAllowed ? UNKNOWN_REGIONAL_SATELLITE_CONFIG_ID : null;
+                    }
+                    updateCachedAccessRestrictionMap(locationToken, mNewRegionalConfigId);
                 }
                 mAccessControllerMetricsStats.setOnDeviceLookupTime(mOnDeviceLookupStartTimeMillis);
                 Bundle bundle = new Bundle();
@@ -1422,11 +2060,25 @@ public class SatelliteAccessController extends Handler {
         }
     }
 
+    private void updateRegionalConfigId() {
+        synchronized (mLock) {
+            plogd("mNewRegionalConfigId: updatedValue = " + mNewRegionalConfigId
+                    + " | mRegionalConfigId: beforeValue = " + mRegionalConfigId);
+            if (!Objects.equals(mRegionalConfigId, mNewRegionalConfigId)) {
+                mRegionalConfigId = mNewRegionalConfigId;
+                notifyRegionalSatelliteConfigurationChanged(
+                        Optional.ofNullable(mSatelliteAccessConfigMap)
+                                .map(map -> map.get(mRegionalConfigId))
+                                .orElse(null));
+            }
+        }
+    }
+
     private void updateCachedAccessRestrictionMap(
             @NonNull SatelliteOnDeviceAccessController.LocationToken locationToken,
-            boolean satelliteAllowed) {
+            Integer regionalConfigId) {
         synchronized (mLock) {
-            mCachedAccessRestrictionMap.put(locationToken, satelliteAllowed);
+            mCachedAccessRestrictionMap.put(locationToken, regionalConfigId);
         }
     }
 
@@ -1568,7 +2220,8 @@ public class SatelliteAccessController extends Handler {
      *                               {@link SatelliteOnDeviceAccessController} instance and the
      *                               device is using a user build.
      */
-    private boolean initSatelliteOnDeviceAccessController() throws IllegalStateException {
+    private boolean initSatelliteOnDeviceAccessController()
+            throws IllegalStateException {
         synchronized (mLock) {
             if (getSatelliteS2CellFile() == null) return false;
 
@@ -1580,10 +2233,12 @@ public class SatelliteAccessController extends Handler {
 
             try {
                 mSatelliteOnDeviceAccessController =
-                        SatelliteOnDeviceAccessController.create(getSatelliteS2CellFile());
+                        SatelliteOnDeviceAccessController.create(
+                                getSatelliteS2CellFile(), mFeatureFlags);
                 restartKeepOnDeviceAccessControllerResourcesTimer();
                 mS2Level = mSatelliteOnDeviceAccessController.getS2Level();
                 plogd("mS2Level=" + mS2Level);
+                loadSatelliteAccessConfigurationFromDeviceConfig();
             } catch (Exception ex) {
                 ploge("Got exception in creating an instance of SatelliteOnDeviceAccessController,"
                         + " ex=" + ex + ", sat s2 file="
@@ -1591,6 +2246,7 @@ public class SatelliteAccessController extends Handler {
                 reportAnomaly(UUID_CREATE_ON_DEVICE_ACCESS_CONTROLLER_EXCEPTION,
                         "Exception in creating on-device satellite access controller");
                 mSatelliteOnDeviceAccessController = null;
+                mSatelliteAccessConfigMap = null;
                 if (!mIsOverlayConfigOverridden) {
                     mSatelliteS2CellFile = null;
                 }
@@ -1616,6 +2272,103 @@ public class SatelliteAccessController extends Handler {
         }
     }
 
+    private void handleCmdUpdateSystemSelectionChannels(
+            @NonNull ResultReceiver resultReceiver) {
+        synchronized (mLock) {
+            mUpdateSystemSelectionChannelsResultReceivers.add(resultReceiver);
+            if (mUpdateSystemSelectionChannelsResultReceivers.size() > 1) {
+                plogd("updateSystemSelectionChannels is already being processed");
+                return;
+            }
+            int subId =  mSatelliteController.getSelectedSatelliteSubId();
+            plogd("handleCmdUpdateSystemSelectionChannels: SatellitePhone subId: " + subId);
+            if (subId == SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
+                sendUpdateSystemSelectionChannelsResult(
+                        SATELLITE_RESULT_INVALID_TELEPHONY_STATE, null);
+                return;
+            }
+
+            String mccmnc = "";
+            final SubscriptionInfo subInfo = SubscriptionManagerService.getInstance()
+                    .getSubscriptionInfo(subId);
+            if (subInfo != null) {
+                mccmnc = subInfo.getMccString() + subInfo.getMncString();
+            }
+
+            final Integer[] regionalConfigId = new Integer[1];
+            regionalConfigId[0] = getSelectedRegionalConfigId();
+            if (regionalConfigId[0] != null
+                    && regionalConfigId[0] == UNKNOWN_REGIONAL_SATELLITE_CONFIG_ID) {
+                // The geofence file with old format return UNKNOWN_REGIONAL_SATELLITE_CONFIG_ID
+                // for an S2 cell present in the file.
+                // For backward compatibility, we will use DEFAULT_REGIONAL_SATELLITE_CONFIG_ID
+                // for such cases.
+                regionalConfigId[0] = DEFAULT_REGIONAL_SATELLITE_CONFIG_ID;
+            }
+            if (!SatelliteAccessConfigurationParser.isRegionalConfigIdValid(regionalConfigId[0])) {
+                plogd("handleCmdUpdateSystemSelectionChannels: mRegionalConfigId is not valid, "
+                        + "mRegionalConfig=" + getSelectedRegionalConfigId());
+                sendUpdateSystemSelectionChannelsResult(
+                        SATELLITE_RESULT_ACCESS_BARRED, null);
+                return;
+            }
+
+            SatelliteAccessConfiguration satelliteAccessConfiguration;
+            synchronized (mLock) {
+                satelliteAccessConfiguration = Optional.ofNullable(mSatelliteAccessConfigMap)
+                        .map(map -> map.get(regionalConfigId[0]))
+                        .orElse(null);
+            }
+            if (satelliteAccessConfiguration == null) {
+                plogd("handleCmdUpdateSystemSelectionChannels: satelliteAccessConfiguration "
+                        + "is not valid");
+                sendUpdateSystemSelectionChannelsResult(
+                        SATELLITE_RESULT_ACCESS_BARRED, null);
+                return;
+            }
+
+            List<SatelliteInfo> satelliteInfos =
+                    satelliteAccessConfiguration.getSatelliteInfos();
+            List<Integer> bandList = new ArrayList<>();
+            List<Integer> earfcnList = new ArrayList<>();
+            for (SatelliteInfo satelliteInfo : satelliteInfos) {
+                bandList.addAll(satelliteInfo.getBands());
+                List<EarfcnRange> earfcnRangeList = satelliteInfo.getEarfcnRanges();
+                earfcnRangeList.stream().flatMapToInt(
+                        earfcnRange -> IntStream.of(earfcnRange.getStartEarfcn(),
+                                earfcnRange.getEndEarfcn())).boxed().forEach(earfcnList::add);
+            }
+
+            IntArray bands = new IntArray(bandList.size());
+            bands.addAll(bandList.stream().mapToInt(Integer::intValue).toArray());
+            IntArray earfcns = new IntArray(
+                    Math.min(earfcnList.size(), MAX_EARFCN_ARRAY_LENGTH));
+            for (int i = 0; i < Math.min(earfcnList.size(), MAX_EARFCN_ARRAY_LENGTH); i++) {
+                earfcns.add(earfcnList.get(i));
+            }
+            IntArray tagIds = new IntArray(satelliteAccessConfiguration.getTagIds().size());
+            tagIds.addAll(satelliteAccessConfiguration.getTagIds().stream().mapToInt(
+                    Integer::intValue).toArray());
+
+            List<SystemSelectionSpecifier> selectionSpecifiers = new ArrayList<>();
+            selectionSpecifiers.add(new SystemSelectionSpecifier(mccmnc, bands, earfcns,
+                    satelliteInfos.toArray(new SatelliteInfo[0]), tagIds));
+            mSatelliteController.updateSystemSelectionChannels(selectionSpecifiers,
+                    mInternalUpdateSystemSelectionChannelsResultReceiver);
+        }
+    }
+
+    private void sendUpdateSystemSelectionChannelsResult(int resultCode, Bundle resultData) {
+        plogd("sendUpdateSystemSelectionChannelsResult: resultCode=" + resultCode);
+
+        synchronized (mLock) {
+            for (ResultReceiver resultReceiver : mUpdateSystemSelectionChannelsResultReceivers) {
+                resultReceiver.send(resultCode, resultData);
+            }
+            mUpdateSystemSelectionChannelsResultReceivers.clear();
+        }
+    }
+
     private static boolean getSatelliteAccessAllowFromOverlayConfig(@NonNull Context context) {
         Boolean accessAllowed = null;
         try {
@@ -1637,6 +2390,28 @@ public class SatelliteAccessController extends Handler {
         return accessAllowed;
     }
 
+
+    @Nullable
+    protected String getSatelliteConfigurationFileNameFromOverlayConfig(
+            @NonNull Context context) {
+        String satelliteAccessControlInfoFile = null;
+
+        if (!mFeatureFlags.carrierRoamingNbIotNtn()) {
+            logd("mFeatureFlags: carrierRoamingNbIotNtn is disabled");
+            return satelliteAccessControlInfoFile;
+        }
+
+        try {
+            satelliteAccessControlInfoFile = context.getResources().getString(
+                    com.android.internal.R.string.satellite_access_config_file);
+        } catch (Resources.NotFoundException ex) {
+            loge("getSatelliteConfigurationFileNameFromOverlayConfig: got ex=" + ex);
+        }
+
+        logd("satelliteAccessControlInfoFile =" + satelliteAccessControlInfoFile);
+        return satelliteAccessControlInfoFile;
+    }
+
     @Nullable
     private static String getSatelliteS2CellFileFromOverlayConfig(@NonNull Context context) {
         String s2CellFile = null;
@@ -1864,6 +2639,16 @@ public class SatelliteAccessController extends Handler {
                     logd("registerForCommunicationAllowedStateChanged: "
                             + "mCurrentSatelliteAllowedState " + mCurrentSatelliteAllowedState);
                 }
+                synchronized (mLock) {
+                    SatelliteAccessConfiguration satelliteAccessConfig =
+                            Optional.ofNullable(mSatelliteAccessConfigMap)
+                                    .map(map -> map.get(mRegionalConfigId))
+                                    .orElse(null);
+                    callback.onSatelliteAccessConfigurationChanged(satelliteAccessConfig);
+                    logd("registerForCommunicationAllowedStateChanged: satelliteAccessConfig: "
+                            + satelliteAccessConfig + " of mRegionalConfigId: "
+                            + mRegionalConfigId);
+                }
             } catch (RemoteException ex) {
                 ploge("registerForCommunicationAllowedStateChanged: RemoteException ex=" + ex);
             }
@@ -1893,6 +2678,75 @@ public class SatelliteAccessController extends Handler {
         mSatelliteCommunicationAllowedStateChangedListeners.remove(callback.asBinder());
     }
 
+    /**
+     * Returns integer array of disallowed reasons of satellite.
+     *
+     * @return Integer array of disallowed reasons of satellite.
+     */
+    @NonNull
+    public List<Integer> getSatelliteDisallowedReasons() {
+        if (!mFeatureFlags.carrierRoamingNbIotNtn()) {
+            plogd("getSatelliteDisallowedReasons: carrierRoamingNbIotNtn is disabled");
+            return new ArrayList<>();
+        }
+
+        synchronized (mSatelliteDisallowedReasonsLock) {
+            logd("mSatelliteDisallowedReasons:"
+                    + String.join(", ", mSatelliteDisallowedReasons.toString()));
+            return mSatelliteDisallowedReasons;
+        }
+    }
+
+    /**
+     * Registers for disallowed reasons change event from satellite service.
+     *
+     * @param callback The callback to handle disallowed reasons changed event.
+     */
+    public void registerForSatelliteDisallowedReasonsChanged(
+            @NonNull ISatelliteDisallowedReasonsCallback callback) {
+        if (!mFeatureFlags.carrierRoamingNbIotNtn()) {
+            plogd("registerForSatelliteDisallowedReasonsChanged: carrierRoamingNbIotNtn is "
+                    + "disabled");
+            return;
+        }
+
+        mSatelliteDisallowedReasonsChangedListeners.put(callback.asBinder(), callback);
+
+        this.post(() -> {
+            try {
+                synchronized (mSatelliteDisallowedReasonsLock) {
+                    callback.onSatelliteDisallowedReasonsChanged(
+                            mSatelliteDisallowedReasons.stream()
+                                    .mapToInt(Integer::intValue)
+                                    .toArray());
+                    logd("registerForSatelliteDisallowedReasonsChanged: "
+                            + "mSatelliteDisallowedReasons " + mSatelliteDisallowedReasons.size());
+                }
+            } catch (RemoteException ex) {
+                ploge("registerForSatelliteDisallowedReasonsChanged: RemoteException ex=" + ex);
+            }
+        });
+    }
+
+    /**
+     * Unregisters for disallowed reasons change event from satellite service.
+     * If callback was not registered before, the request will be ignored.
+     *
+     * @param callback The callback that was passed to
+     *                 {@link #registerForSatelliteDisallowedReasonsChanged(
+     *ISatelliteDisallowedReasonsCallback)}.
+     */
+    public void unregisterForSatelliteDisallowedReasonsChanged(
+            @NonNull ISatelliteDisallowedReasonsCallback callback) {
+        if (!mFeatureFlags.carrierRoamingNbIotNtn()) {
+            plogd("unregisterForSatelliteDisallowedReasonsChanged: "
+                    + "carrierRoamingNbIotNtn is disabled");
+            return;
+        }
+
+        mSatelliteDisallowedReasonsChangedListeners.remove(callback.asBinder());
+    }
+
     /**
      * This API can be used by only CTS to set the cache whether satellite communication is allowed.
      *
@@ -1920,6 +2774,10 @@ public class SatelliteAccessController extends Handler {
                 mLatestSatelliteCommunicationAllowedSetTime = getElapsedRealtimeNanos();
                 mLatestSatelliteCommunicationAllowed = true;
                 mCurrentSatelliteAllowedState = true;
+            } else if ("cache_not_allowed".equalsIgnoreCase(state)) {
+                mLatestSatelliteCommunicationAllowedSetTime = getElapsedRealtimeNanos();
+                mLatestSatelliteCommunicationAllowed = false;
+                mCurrentSatelliteAllowedState = false;
             } else if ("cache_clear_and_not_allowed".equalsIgnoreCase(state)) {
                 mLatestSatelliteCommunicationAllowedSetTime = 0;
                 mLatestSatelliteCommunicationAllowed = false;
@@ -1955,6 +2813,45 @@ public class SatelliteAccessController extends Handler {
         });
     }
 
+    private void notifySatelliteDisallowedReasonsChanged() {
+        plogd("notifySatelliteDisallowedReasonsChanged");
+
+        List<ISatelliteDisallowedReasonsCallback> deadCallersList = new ArrayList<>();
+        mSatelliteDisallowedReasonsChangedListeners.values().forEach(listener -> {
+            try {
+                listener.onSatelliteDisallowedReasonsChanged(
+                        mSatelliteDisallowedReasons.stream()
+                                .mapToInt(Integer::intValue)
+                                .toArray());
+            } catch (RemoteException e) {
+                plogd("notifySatelliteDisallowedReasonsChanged RemoteException: " + e);
+                deadCallersList.add(listener);
+            }
+        });
+        deadCallersList.forEach(listener -> {
+            mSatelliteDisallowedReasonsChangedListeners.remove(listener.asBinder());
+        });
+    }
+
+    protected void notifyRegionalSatelliteConfigurationChanged(
+            @Nullable SatelliteAccessConfiguration satelliteAccessConfig) {
+        plogd("notifyRegionalSatelliteConfigurationChanged : satelliteAccessConfig is "
+                + satelliteAccessConfig);
+
+        List<ISatelliteCommunicationAllowedStateCallback> deadCallersList = new ArrayList<>();
+        mSatelliteCommunicationAllowedStateChangedListeners.values().forEach(listener -> {
+            try {
+                listener.onSatelliteAccessConfigurationChanged(satelliteAccessConfig);
+            } catch (RemoteException e) {
+                plogd("handleEventNtnSignalStrengthChanged RemoteException: " + e);
+                deadCallersList.add(listener);
+            }
+        });
+        deadCallersList.forEach(listener -> {
+            mSatelliteCommunicationAllowedStateChangedListeners.remove(listener.asBinder());
+        });
+    }
+
     private void reportMetrics(int resultCode, boolean allowed) {
         if (resultCode == SATELLITE_RESULT_SUCCESS) {
             mControllerMetricsStats.reportAllowedSatelliteAccessCount(allowed);
@@ -1968,6 +2865,8 @@ public class SatelliteAccessController extends Handler {
                 .setIsAllowed(allowed)
                 .setIsEmergency(isInEmergency())
                 .setResult(resultCode)
+                .setCarrierId(mSatelliteController.getSatelliteCarrierId())
+                .setIsNtnOnlyCarrier(mSatelliteController.isNtnOnlyCarrier())
                 .reportAccessControllerMetrics();
         mLocationQueryStartTimeMillis = 0;
         mOnDeviceLookupStartTimeMillis = 0;
@@ -1995,7 +2894,7 @@ public class SatelliteAccessController extends Handler {
         Rlog.w(TAG, log);
     }
 
-    private static void loge(@NonNull String log) {
+    protected static void loge(@NonNull String log) {
         Rlog.e(TAG, log);
     }
 
@@ -2016,6 +2915,105 @@ public class SatelliteAccessController extends Handler {
         }
     }
 
+    /**
+     * This API can be used only for test purpose to override the carrier roaming Ntn eligibility
+     *
+     * @param state         to update Ntn Eligibility.
+     * @param resetRequired to reset the overridden flag in satellite controller.
+     * @return {@code true} if the shell command is successful, {@code false} otherwise.
+     */
+    public boolean overrideCarrierRoamingNtnEligibilityChanged(boolean state,
+            boolean resetRequired) {
+        if (!mFeatureFlags.carrierRoamingNbIotNtn()) {
+            logd("overrideCarrierRoamingNtnEligibilityChanged: "
+                    + "carrierRoamingNbIotNtn is disabled");
+            return false;
+        }
+
+        if (!isMockModemAllowed()) {
+            logd("overrideCarrierRoamingNtnEligibilityChanged: "
+                    + "mock modem not allowed.");
+            return false;
+        }
+
+        logd("calling overrideCarrierRoamingNtnEligibilityChanged");
+        return mSatelliteController.overrideCarrierRoamingNtnEligibilityChanged(state,
+                resetRequired);
+    }
+
+    private static final class SatelliteRegionalConfig {
+        /** Regional satellite config IDs */
+        private final int mConfigId;
+
+        /** Set of earfcns in the corresponding regions */
+        private final Set<Integer> mEarfcns;
+
+        SatelliteRegionalConfig(int configId, Set<Integer> earfcns) {
+            this.mConfigId = configId;
+            this.mEarfcns = earfcns;
+        }
+
+        public Set<Integer> getEarfcns() {
+            return mEarfcns;
+        }
+    }
+
+    private void updateSatelliteRegionalConfig(int subId) {
+        plogd("updateSatelliteRegionalConfig: subId: " + subId);
+        if (subId == SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
+            return;
+        }
+
+        mSatelliteController.updateRegionalSatelliteEarfcns(subId);
+        //key: regional satellite config Id,
+        //value: set of earfcns in the corresponding regions
+        Map<String, Set<Integer>> earfcnsMap = mSatelliteController
+                .getRegionalSatelliteEarfcns(subId);
+        if (earfcnsMap.isEmpty()) {
+            plogd("updateSatelliteRegionalConfig: Earfcns are not found for subId: "
+                    + subId);
+            return;
+        }
+
+        synchronized (mRegionalSatelliteEarfcnsLock) {
+            SatelliteRegionalConfig satelliteRegionalConfig;
+            /* Key: Regional satellite config ID, Value: SatelliteRegionalConfig
+             * contains satellite config IDs and set of earfcns in the corresponding regions.
+             */
+            Map<Integer, SatelliteRegionalConfig> satelliteRegionalConfigMap = new HashMap<>();
+            for (String configId: earfcnsMap.keySet()) {
+                Set<Integer> earfcnsSet = new HashSet<>();
+                for (int earfcn : earfcnsMap.get(configId)) {
+                    earfcnsSet.add(earfcn);
+                }
+                satelliteRegionalConfig = new SatelliteRegionalConfig(Integer.valueOf(configId),
+                        earfcnsSet);
+                satelliteRegionalConfigMap.put(Integer.valueOf(configId), satelliteRegionalConfig);
+            }
+
+            mSatelliteRegionalConfigPerSubMap.put(subId, satelliteRegionalConfigMap);
+        }
+    }
+
+    private void handleCarrierConfigChanged(@NonNull Context context, int slotIndex,
+            int subId, int carrierId, int specificCarrierId) {
+        if (!mFeatureFlags.carrierRoamingNbIotNtn()) {
+            plogd("handleCarrierConfigChanged: carrierRoamingNbIotNtn flag is disabled");
+            return;
+        }
+        plogd("handleCarrierConfigChanged: slotIndex=" + slotIndex + ", subId=" + subId
+                + ", carrierId=" + carrierId + ", specificCarrierId=" + specificCarrierId);
+        updateSatelliteRegionalConfig(subId);
+        evaluatePossibleChangeInDefaultSmsApp(context);
+    }
+
+    @Nullable
+    private Integer getSelectedRegionalConfigId() {
+        synchronized (mLock) {
+            return mRegionalConfigId;
+        }
+    }
+
     private void plogv(@NonNull String log) {
         Rlog.v(TAG, log);
         if (mPersistentLogger != null) {
diff --git a/src/com/android/phone/satellite/accesscontrol/SatelliteOnDeviceAccessController.java b/src/com/android/phone/satellite/accesscontrol/SatelliteOnDeviceAccessController.java
index 520699f3f..2d7cf9689 100644
--- a/src/com/android/phone/satellite/accesscontrol/SatelliteOnDeviceAccessController.java
+++ b/src/com/android/phone/satellite/accesscontrol/SatelliteOnDeviceAccessController.java
@@ -16,6 +16,9 @@
 package com.android.phone.satellite.accesscontrol;
 
 import android.annotation.NonNull;
+import android.annotation.Nullable;
+
+import com.android.internal.telephony.flags.FeatureFlags;
 
 import java.io.Closeable;
 import java.io.File;
@@ -34,13 +37,15 @@ public abstract class SatelliteOnDeviceAccessController implements Closeable {
      * but at the cost of some memory, or close it immediately after a single use.
      *
      * @param file The input file that contains the location-based access restriction information.
-     * @throws IOException in the unlikely event of errors when reading underlying file(s)
+     * @throws IOException              in the unlikely event of errors when reading underlying
+     *                                  file(s)
      * @throws IllegalArgumentException if the input file format does not match the format defined
-     * by the device overlay configs.
+     *                                  by the device overlay configs.
      */
     public static SatelliteOnDeviceAccessController create(
-            @NonNull File file) throws IOException, IllegalArgumentException {
-        return S2RangeSatelliteOnDeviceAccessController.create(file);
+            @NonNull File file, @NonNull FeatureFlags featureFlags)
+            throws IOException, IllegalArgumentException {
+        return S2RangeSatelliteOnDeviceAccessController.create(file, featureFlags);
     }
 
     /**
@@ -83,4 +88,14 @@ public abstract class SatelliteOnDeviceAccessController implements Closeable {
         /** This will print out the location information */
         public abstract String toPiiString();
     }
+
+    /**
+     * Returns an unsigned integer if a regional access control config ID is found for the current
+     * location, {@code null} otherwise.
+     *
+     * @throws IOException in the unlikely event of errors when reading the underlying file
+     */
+    @Nullable
+    public abstract Integer getRegionalConfigIdForLocation(LocationToken locationToken)
+            throws IOException;
 }
diff --git a/src/com/android/phone/satellite/entitlement/SatelliteEntitlementController.java b/src/com/android/phone/satellite/entitlement/SatelliteEntitlementController.java
index 8d9850d6c..1f46ff64f 100644
--- a/src/com/android/phone/satellite/entitlement/SatelliteEntitlementController.java
+++ b/src/com/android/phone/satellite/entitlement/SatelliteEntitlementController.java
@@ -489,7 +489,11 @@ public class SatelliteEntitlementController extends Handler {
         logd("queryCompleted: updateSatelliteEntitlementStatus");
         updateSatelliteEntitlementStatus(subId, entitlementResult.getEntitlementStatus() ==
                         SatelliteEntitlementResult.SATELLITE_ENTITLEMENT_STATUS_ENABLED,
-                entitlementResult.getAllowedPLMNList(), entitlementResult.getBarredPLMNList());
+                entitlementResult.getAllowedPLMNList(), entitlementResult.getBarredPLMNList(),
+                entitlementResult.getDataPlanInfoForPlmnList(),
+                entitlementResult.getAvailableServiceTypeInfoForPlmnList(),
+                entitlementResult.getDataServicePolicyInfoForPlmnList(),
+                entitlementResult.getVoiceServicePolicyInfoForPlmnList());
     }
 
     private boolean shouldStartQueryEntitlement(int subId) {
@@ -546,7 +550,10 @@ public class SatelliteEntitlementController extends Handler {
                 mSatelliteEntitlementResultPerSub.put(subId, enabledResult);
             }
             updateSatelliteEntitlementStatus(subId, true, enabledResult.getAllowedPLMNList(),
-                    enabledResult.getBarredPLMNList());
+                    enabledResult.getBarredPLMNList(), enabledResult.getDataPlanInfoForPlmnList(),
+                    enabledResult.getAvailableServiceTypeInfoForPlmnList(),
+                    enabledResult.getDataServicePolicyInfoForPlmnList(),
+                    enabledResult.getVoiceServicePolicyInfoForPlmnList());
         }
         resetEntitlementQueryPerSubId(subId);
     }
@@ -655,9 +662,14 @@ public class SatelliteEntitlementController extends Handler {
      */
     @VisibleForTesting(visibility = VisibleForTesting.Visibility.PRIVATE)
     public void updateSatelliteEntitlementStatus(int subId, boolean enabled,
-            List<String> plmnAllowedList, List<String> plmnBarredList) {
+            List<String> plmnAllowedList, List<String> plmnBarredList,
+            Map<String,Integer> plmnDataPlanMap,
+            Map<String, List<Integer>>plmnAllowedServicesMap,
+            Map<String,Integer>plmnDataServicePolicyMap,
+            Map<String, Integer>plmnVoiceServicePolicyMap) {
         SatelliteController.getInstance().onSatelliteEntitlementStatusUpdated(subId, enabled,
-                plmnAllowedList, plmnBarredList, null);
+                plmnAllowedList, plmnBarredList, plmnDataPlanMap, plmnAllowedServicesMap,
+                plmnDataServicePolicyMap, plmnVoiceServicePolicyMap, null);
     }
 
     private @SatelliteConstants.SatelliteEntitlementStatus int getEntitlementStatus(
diff --git a/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResponse.java b/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResponse.java
index 97cb355d8..7d6b5ba50 100644
--- a/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResponse.java
+++ b/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResponse.java
@@ -30,7 +30,9 @@ import org.json.JSONException;
 import org.json.JSONObject;
 
 import java.util.ArrayList;
+import java.util.HashMap;
 import java.util.List;
+import java.util.Map;
 import java.util.stream.Collectors;
 
 /**
@@ -51,6 +53,14 @@ public class SatelliteEntitlementResponse {
     private static final String PLMN_KEY = "PLMN";
     /** The data plan is of the metered or un-metered type. This value is optional. */
     private static final String DATA_PLAN_TYPE_KEY = "DataPlanType";
+    /** The allowed services info with array of allowed services */
+    private static final String ALLOWED_SERVICES_INFO_TYPE_KEY = "AllowedServicesInfo";
+    /** The allowed services with service type and service policy for the plmn*/
+    private static final String ALLOWED_SERVICES_KEY = "AllowedServices";
+    /** list of service type supported for the plmn*/
+    private static final String SERVICE_TYPE_KEY = "ServiceType";
+    /** list of service policy supported for the plmn*/
+    private static final String SERVICE_POLICY_KEY = "ServicePolicy";
 
     @SatelliteEntitlementResult.SatelliteEntitlementStatus private int mEntitlementStatus;
 
@@ -90,7 +100,7 @@ public class SatelliteEntitlementResponse {
      */
     public List<SatelliteNetworkInfo> getPlmnAllowed() {
         return mPlmnAllowedList.stream().map((info) -> new SatelliteNetworkInfo(info.mPlmn,
-                info.mDataPlanType)).collect(Collectors.toList());
+                info.mDataPlanType, info.mAllowedServicesInfo)).collect(Collectors.toList());
     }
 
     /**
@@ -125,10 +135,31 @@ public class SatelliteEntitlementResponse {
                 for (int i = 0; i < jsonArray.length(); i++) {
                     String dataPlanType = jsonArray.getJSONObject(i).has(DATA_PLAN_TYPE_KEY)
                             ? jsonArray.getJSONObject(i).getString(DATA_PLAN_TYPE_KEY) : "";
+                    Map<String, String> allowedServicesInfo = new HashMap<>();
+                    if (jsonArray.getJSONObject(i).has(ALLOWED_SERVICES_INFO_TYPE_KEY)) {
+                        allowedServicesInfo = new HashMap<>();
+                        JSONArray jsonArray1 = jsonArray.getJSONObject(i)
+                                .getJSONArray(ALLOWED_SERVICES_INFO_TYPE_KEY);
+                        for (int j = 0; j < jsonArray1.length(); j++) {
+                            String serviceType =  jsonArray1.getJSONObject(j)
+                                    .getJSONObject(ALLOWED_SERVICES_KEY)
+                                    .has(SERVICE_TYPE_KEY) ? jsonArray1.getJSONObject(j)
+                                    .getJSONObject(ALLOWED_SERVICES_KEY)
+                                    .getString(SERVICE_TYPE_KEY): "";
+                            String servicePolicy = jsonArray1.getJSONObject(j)
+                                    .getJSONObject(ALLOWED_SERVICES_KEY)
+                                    .has(SERVICE_POLICY_KEY) ? jsonArray1.getJSONObject(j)
+                                    .getJSONObject(ALLOWED_SERVICES_KEY)
+                                    .getString(SERVICE_POLICY_KEY) : "";
+                            allowedServicesInfo.put(serviceType, servicePolicy);
+                        }
+                    }
                     String plmn = jsonArray.getJSONObject(i).getString(PLMN_KEY);
-                    logd("parsingResponse: plmn=" + plmn + " dataplan=" + dataPlanType);
+                    logd("parsingResponse: plmn=" + plmn + " dataplan=" + dataPlanType
+                            + " allowedServices=" + allowedServicesInfo);
                     if (!TextUtils.isEmpty(plmn)) {
-                        mPlmnAllowedList.add(new SatelliteNetworkInfo(plmn, dataPlanType));
+                        mPlmnAllowedList.add(new SatelliteNetworkInfo(
+                                plmn, dataPlanType, allowedServicesInfo));
                     }
                 }
             }
diff --git a/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResult.java b/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResult.java
index 014e28e75..5d531fc01 100644
--- a/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResult.java
+++ b/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResult.java
@@ -16,12 +16,23 @@
 
 package com.android.phone.satellite.entitlement;
 
+import static android.telephony.CarrierConfigManager.SATELLITE_DATA_SUPPORT_ALL;
+import static android.telephony.CarrierConfigManager.SATELLITE_DATA_SUPPORT_BANDWIDTH_CONSTRAINED;
+import static android.telephony.NetworkRegistrationInfo.SERVICE_TYPE_DATA;
+import static android.telephony.NetworkRegistrationInfo.SERVICE_TYPE_VOICE;
+import static android.telephony.NetworkRegistrationInfo.SERVICE_TYPE_SMS;
+
+import static com.android.internal.telephony.satellite.SatelliteController.SATELLITE_DATA_PLAN_METERED;
+import static com.android.internal.telephony.satellite.SatelliteController.SATELLITE_DATA_PLAN_UNMETERED;
+
 import android.annotation.IntDef;
 
 import com.android.internal.telephony.satellite.SatelliteNetworkInfo;
 
 import java.util.ArrayList;
+import java.util.HashMap;
 import java.util.List;
+import java.util.Map;
 import java.util.stream.Collectors;
 
 /**
@@ -112,4 +123,85 @@ public class SatelliteEntitlementResult {
         return new SatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_DISABLED,
                 new ArrayList<>(), new ArrayList<>());
     }
+
+    /**
+     * Get the data plan for the plmn List
+     *
+     * @return data plan for the plmn List
+     */
+    public Map<String, Integer> getDataPlanInfoForPlmnList() {
+        Map<String, Integer> dataPlanInfo = new HashMap<>();
+
+        for (SatelliteNetworkInfo plmnInfo :  mAllowedSatelliteNetworkInfoList) {
+            int dataPlan = SATELLITE_DATA_PLAN_METERED; // default metered is available
+            if (plmnInfo.mDataPlanType.equalsIgnoreCase("unmetered")) {
+                dataPlan = SATELLITE_DATA_PLAN_UNMETERED; // overwrite data plan if unmetered
+            }
+            dataPlanInfo.put(plmnInfo.mPlmn, dataPlan);
+        }
+        return dataPlanInfo;
+    }
+
+    /**
+     * Get ServiceType at Allowed Services for the plmn List
+     *
+     * @return The Allowed Services for the plmn List
+     */
+    public Map<String, List<Integer>> getAvailableServiceTypeInfoForPlmnList() {
+        Map<String, List<Integer>> availableServicesInfo = new HashMap<>();
+        for (SatelliteNetworkInfo plmnInfo : mAllowedSatelliteNetworkInfoList) {
+            List<Integer> allowedServicesList = new ArrayList<>();
+            if (plmnInfo.mAllowedServicesInfo != null) {
+                for (String key : plmnInfo.mAllowedServicesInfo.keySet()) {
+                    if (key.equalsIgnoreCase("data")) {
+                        allowedServicesList.add(SERVICE_TYPE_DATA);
+                    } else if (key.equalsIgnoreCase("voice")) {
+                        allowedServicesList.add(SERVICE_TYPE_VOICE);
+                    }
+                }
+                // By default sms is added to the allowed services
+                allowedServicesList.add(SERVICE_TYPE_SMS);
+                availableServicesInfo.put(plmnInfo.mPlmn, allowedServicesList);
+            }
+        }
+        return availableServicesInfo;
+    }
+
+    /**
+     * Get ServicePolicy for data at Allowed Services for the plmn List
+     *
+     * @return The Allowed Services for the plmn List
+     */
+    public Map<String, Integer> getDataServicePolicyInfoForPlmnList() {
+        return getServicePolicyInfoForServiceType("data");
+    }
+
+    /**
+     * Get ServicePolicy for voice at Allowed Services for the plmn List
+     *
+     * @return The Allowed Services for the plmn List
+     */
+    public Map<String, Integer> getVoiceServicePolicyInfoForPlmnList() {
+        return getServicePolicyInfoForServiceType("voice");
+    }
+
+    public Map<String, Integer> getServicePolicyInfoForServiceType(String serviceType) {
+        Map<String, Integer> servicePolicyInfo = new HashMap<>();
+        for (SatelliteNetworkInfo plmnInfo : mAllowedSatelliteNetworkInfoList) {
+            if (plmnInfo.mAllowedServicesInfo != null) {
+                for (String key : plmnInfo.mAllowedServicesInfo.keySet()) {
+                    if (key.equalsIgnoreCase(serviceType)) {
+                        String servicePolicy = plmnInfo.mAllowedServicesInfo.get(key);
+                        if (servicePolicy.equalsIgnoreCase("constrained")) {
+                            servicePolicyInfo.put(plmnInfo.mPlmn,
+                                    SATELLITE_DATA_SUPPORT_BANDWIDTH_CONSTRAINED);
+                        } else if (servicePolicy.equalsIgnoreCase("unconstrained")) {
+                            servicePolicyInfo.put(plmnInfo.mPlmn, SATELLITE_DATA_SUPPORT_ALL);
+                        }
+                    }
+                }
+            }
+        }
+        return servicePolicyInfo;
+    }
 }
diff --git a/src/com/android/phone/settings/RadioInfo.java b/src/com/android/phone/settings/RadioInfo.java
index 24d680c19..4a5029613 100644
--- a/src/com/android/phone/settings/RadioInfo.java
+++ b/src/com/android/phone/settings/RadioInfo.java
@@ -85,7 +85,6 @@ import android.telephony.ims.ImsRcsManager;
 import android.telephony.ims.ProvisioningManager;
 import android.telephony.ims.feature.MmTelFeature;
 import android.telephony.ims.stub.ImsRegistrationImplBase;
-import android.telephony.satellite.EnableRequestAttributes;
 import android.telephony.satellite.SatelliteManager;
 import android.text.TextUtils;
 import android.util.Log;
@@ -207,7 +206,8 @@ public class RadioInfo extends AppCompatActivity {
             ServiceState.RIL_RADIO_TECHNOLOGY_GSM,
             ServiceState.RIL_RADIO_TECHNOLOGY_TD_SCDMA,
             ServiceState.RIL_RADIO_TECHNOLOGY_LTE_CA,
-            ServiceState.RIL_RADIO_TECHNOLOGY_NR
+            ServiceState.RIL_RADIO_TECHNOLOGY_NR,
+            ServiceState.RIL_RADIO_TECHNOLOGY_NB_IOT_NTN
     };
     private static String[] sPhoneIndexLabels = new String[0];
 
@@ -368,7 +368,7 @@ public class RadioInfo extends AppCompatActivity {
 
     private String mActionEsos;
     private String mActionEsosDemo;
-
+    private Intent mNonEsosIntent;
     private TelephonyDisplayInfo mDisplayInfo;
 
     private List<PhysicalChannelConfig> mPhysicalChannelConfigs = new ArrayList<>();
@@ -786,33 +786,33 @@ public class RadioInfo extends AppCompatActivity {
         mEsosDemoButton  = (Button) findViewById(R.id.demo_esos_questionnaire);
         mSatelliteEnableNonEmergencyModeButton = (Button) findViewById(
                 R.id.satellite_enable_non_emergency_mode);
-        CarrierConfigManager cm = getSystemService(CarrierConfigManager.class);
-        if (!cm.getConfigForSubId(mSubId,
-                        CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL)
-                .getBoolean(CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL)) {
-            mSatelliteEnableNonEmergencyModeButton.setVisibility(View.GONE);
-        }
-        if (!Build.isDebuggable()) {
-            if (!TextUtils.isEmpty(mActionEsos)) {
-                mEsosButton.setVisibility(View.GONE);
-            }
-            if (!TextUtils.isEmpty(mActionEsosDemo)) {
-                mEsosDemoButton.setVisibility(View.GONE);
-            }
-            mSatelliteEnableNonEmergencyModeButton.setVisibility(View.GONE);
+
+        if (shouldHideButton(mActionEsos)) {
+            mEsosButton.setVisibility(View.GONE);
         } else {
             mEsosButton.setOnClickListener(v -> startActivityAsUser(
                     new Intent(mActionEsos).addFlags(
                             Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK),
                     UserHandle.CURRENT)
             );
+        }
+        if (shouldHideButton(mActionEsosDemo)) {
+            mEsosDemoButton.setVisibility(View.GONE);
+        } else {
             mEsosDemoButton.setOnClickListener(v -> startActivityAsUser(
                     new Intent(mActionEsosDemo).addFlags(
                             Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK),
                     UserHandle.CURRENT)
             );
-            mSatelliteEnableNonEmergencyModeButton.setOnClickListener(v ->
-                    enableSatelliteNonEmergencyMode());
+        }
+        if (shouldHideNonEmergencyMode()) {
+            mSatelliteEnableNonEmergencyModeButton.setVisibility(View.GONE);
+        } else {
+            mSatelliteEnableNonEmergencyModeButton.setOnClickListener(v -> {
+                if (mNonEsosIntent != null) {
+                    sendBroadcast(mNonEsosIntent);
+                }
+            });
         }
 
         mOemInfoButton = (Button) findViewById(R.id.oem_info);
@@ -836,6 +836,21 @@ public class RadioInfo extends AppCompatActivity {
         restoreFromBundle(icicle);
     }
 
+    boolean shouldHideButton(String action) {
+        if (!Build.isDebuggable()) {
+            return true;
+        }
+        if (TextUtils.isEmpty(action)) {
+            return true;
+        }
+        PackageManager pm = getPackageManager();
+        Intent intent = new Intent(action);
+        if (pm.resolveActivity(intent, 0) == null) {
+            return true;
+        }
+        return false;
+    }
+
     @Override
     public Intent getParentActivityIntent() {
         Intent parentActivity = super.getParentActivityIntent();
@@ -1411,7 +1426,9 @@ public class RadioInfo extends AppCompatActivity {
     }
 
     private void updateNetworkType() {
-        if (SubscriptionManager.isValidPhoneId(mPhoneId)) {
+        SubscriptionManager mSm = getSystemService(SubscriptionManager.class);
+        if (SubscriptionManager.isValidPhoneId(mPhoneId)
+                && mSm.isActiveSubscriptionId(mSubId)) {
             mDataNetwork.setText(ServiceState.rilRadioTechnologyToString(
                     mTelephonyManager.getServiceStateForSlot(mPhoneId)
                             .getRilDataRadioTechnology()));
@@ -2138,27 +2155,68 @@ public class RadioInfo extends AppCompatActivity {
                 }
             };
 
-    /**
-     * Enable modem satellite for non-emergency mode.
-     */
-    private void enableSatelliteNonEmergencyMode() {
-        SatelliteManager sm = getSystemService(SatelliteManager.class);
+    private boolean shouldHideNonEmergencyMode() {
+        if (!Build.isDebuggable()) {
+            return true;
+        }
+        String action  = SatelliteManager.ACTION_SATELLITE_START_NON_EMERGENCY_SESSION;
+        if (TextUtils.isEmpty(action)) {
+            return true;
+        }
+        if (mNonEsosIntent != null) {
+            mNonEsosIntent = null;
+        }
         CarrierConfigManager cm = getSystemService(CarrierConfigManager.class);
-        if (sm == null || cm == null) {
-            loge("enableSatelliteNonEmergencyMode: sm or cm is null");
-            return;
+        if (cm == null) {
+            loge("shouldHideNonEmergencyMode: cm is null");
+            return true;
         }
-        if (!cm.getConfigForSubId(mSubId,
-                CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL)
-                .getBoolean(CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL)) {
-            loge("enableSatelliteNonEmergencyMode: KEY_SATELLITE_ATTACH_SUPPORTED_BOOL is false");
-            return;
+        PersistableBundle bundle = cm.getConfigForSubId(mSubId,
+                CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL,
+                CarrierConfigManager.KEY_SATELLITE_ESOS_SUPPORTED_BOOL);
+        if (!bundle.getBoolean(
+                CarrierConfigManager.KEY_SATELLITE_ESOS_SUPPORTED_BOOL, false)) {
+            log("shouldHideNonEmergencyMode: esos_supported false");
+            return true;
+        }
+        if (!bundle.getBoolean(
+                CarrierConfigManager.KEY_SATELLITE_ATTACH_SUPPORTED_BOOL, false)) {
+            log("shouldHideNonEmergencyMode: attach_supported false");
+            return true;
+        }
+
+        String packageName = getStringFromOverlayConfig(
+                com.android.internal.R.string.config_satellite_gateway_service_package);
+
+        String className = getStringFromOverlayConfig(com.android.internal.R.string
+                .config_satellite_carrier_roaming_non_emergency_session_class);
+        if (packageName == null || className == null
+                || packageName.isEmpty() || className.isEmpty()) {
+            Log.d(TAG, "shouldHideNonEmergencyMode:"
+                    + " packageName or className is null or empty.");
+            return true;
+        }
+        PackageManager pm = getPackageManager();
+        Intent intent = new Intent(action);
+        intent.setComponent(new ComponentName(packageName, className));
+        if (pm.queryBroadcastReceivers(intent, 0).isEmpty()) {
+            Log.d(TAG, "shouldHideNonEmergencyMode: Broadcast receiver not found for intent: "
+                    + intent);
+            return true;
+        }
+        mNonEsosIntent = intent;
+        return false;
+    }
+
+    private String getStringFromOverlayConfig(int resourceId) {
+        String name;
+        try {
+            name = getResources().getString(resourceId);
+        } catch (Resources.NotFoundException ex) {
+            loge("getStringFromOverlayConfig: ex=" + ex);
+            name = null;
         }
-        log("enableSatelliteNonEmergencyMode: requestEnabled");
-        sm.requestEnabled(new EnableRequestAttributes.Builder(true)
-                        .setDemoMode(false).setEmergencyMode(false).build(),
-                Runnable::run, res -> log("enableSatelliteNonEmergencyMode: " + res)
-        );
+        return name;
     }
 
     private boolean isImsVolteProvisioned() {
diff --git a/src/com/android/services/telephony/DisconnectCauseUtil.java b/src/com/android/services/telephony/DisconnectCauseUtil.java
index 48786dcd1..e753e2055 100644
--- a/src/com/android/services/telephony/DisconnectCauseUtil.java
+++ b/src/com/android/services/telephony/DisconnectCauseUtil.java
@@ -1046,7 +1046,7 @@ public class DisconnectCauseUtil {
     }
 
     private static Integer getSatelliteErrorString() {
-        if (SatelliteController.getInstance().isSatelliteEnabled()) {
+        if (SatelliteController.getInstance().isSatelliteEnabledOrBeingEnabled()) {
             return R.string.incall_error_satellite_enabled;
         }
         return R.string.incall_error_carrier_roaming_satellite_mode;
diff --git a/src/com/android/services/telephony/ImsConference.java b/src/com/android/services/telephony/ImsConference.java
index 7f0c800a3..af1ddb649 100644
--- a/src/com/android/services/telephony/ImsConference.java
+++ b/src/com/android/services/telephony/ImsConference.java
@@ -430,9 +430,9 @@ public class ImsConference extends TelephonyConferenceBase implements Holdable {
 
         super(phoneAccountHandle);
 
-        mTelecomAccountRegistry = telecomAccountRegistry;
-        mFeatureFlagProxy = featureFlagProxy;
-        mCarrierConfig = carrierConfig;
+        mTelecomAccountRegistry = Objects.requireNonNull(telecomAccountRegistry);
+        mFeatureFlagProxy = Objects.requireNonNull(featureFlagProxy);
+        mCarrierConfig = Objects.requireNonNull(carrierConfig);
 
         // Specify the connection time of the conference to be the connection time of the original
         // connection.
diff --git a/src/com/android/services/telephony/ImsConferenceController.java b/src/com/android/services/telephony/ImsConferenceController.java
index fa2151b2d..ca3bcfe76 100644
--- a/src/com/android/services/telephony/ImsConferenceController.java
+++ b/src/com/android/services/telephony/ImsConferenceController.java
@@ -142,9 +142,9 @@ public class ImsConferenceController {
     public ImsConferenceController(TelecomAccountRegistry telecomAccountRegistry,
             TelephonyConnectionServiceProxy connectionService,
             ImsConference.FeatureFlagProxy featureFlagProxy) {
-        mConnectionService = connectionService;
-        mTelecomAccountRegistry = telecomAccountRegistry;
-        mFeatureFlagProxy = featureFlagProxy;
+        mConnectionService = Objects.requireNonNull(connectionService);
+        mTelecomAccountRegistry = Objects.requireNonNull(telecomAccountRegistry);
+        mFeatureFlagProxy = Objects.requireNonNull(featureFlagProxy);
     }
 
     void addConference(ImsConference conference) {
diff --git a/src/com/android/services/telephony/TelecomAccountRegistry.java b/src/com/android/services/telephony/TelecomAccountRegistry.java
index c39d121cf..895626695 100644
--- a/src/com/android/services/telephony/TelecomAccountRegistry.java
+++ b/src/com/android/services/telephony/TelecomAccountRegistry.java
@@ -70,6 +70,7 @@ import com.android.internal.telephony.SimultaneousCallingTracker;
 import com.android.internal.telephony.flags.Flags;
 import com.android.internal.telephony.subscription.SubscriptionManagerService;
 import com.android.phone.PhoneGlobals;
+import com.android.phone.PhoneInterfaceManager;
 import com.android.phone.PhoneUtils;
 import com.android.phone.R;
 import com.android.telephony.Rlog;
@@ -434,7 +435,7 @@ public class TelecomAccountRegistry {
             boolean isVideoEnabledByPlatform = ImsManager.getInstance(mPhone.getContext(),
                     mPhone.getPhoneId()).isVtEnabledByPlatform();
 
-            if (!mIsPrimaryUser) {
+            if (!mDoesUserSupportVideoCalling) {
                 Log.i(this, "Disabling video calling for secondary user.");
                 mIsVideoCapable = false;
                 isVideoEnabledByPlatform = false;
@@ -651,8 +652,8 @@ public class TelecomAccountRegistry {
             // Check if IMS video pause is supported.
             PersistableBundle b =
                     PhoneGlobals.getInstance().getCarrierConfigForSubId(mPhone.getSubId());
-            return b != null &&
-                    b.getBoolean(CarrierConfigManager.KEY_SUPPORT_PAUSE_IMS_VIDEO_CALLS_BOOL);
+            if (b == null) return false;
+            return b.getBoolean(CarrierConfigManager.KEY_SUPPORT_PAUSE_IMS_VIDEO_CALLS_BOOL);
         }
 
         /**
@@ -697,8 +698,8 @@ public class TelecomAccountRegistry {
         private boolean isCarrierInstantLetteringSupported() {
             PersistableBundle b =
                     PhoneGlobals.getInstance().getCarrierConfigForSubId(mPhone.getSubId());
-            return b != null &&
-                    b.getBoolean(CarrierConfigManager.KEY_CARRIER_INSTANT_LETTERING_AVAILABLE_BOOL);
+            if (b == null) return false;
+            return b.getBoolean(CarrierConfigManager.KEY_CARRIER_INSTANT_LETTERING_AVAILABLE_BOOL);
         }
 
         /**
@@ -709,8 +710,8 @@ public class TelecomAccountRegistry {
         private boolean isCarrierAdhocConferenceCallSupported() {
             PersistableBundle b =
                     PhoneGlobals.getInstance().getCarrierConfigForSubId(mPhone.getSubId());
-            return b != null &&
-                    b.getBoolean(CarrierConfigManager.KEY_SUPPORT_ADHOC_CONFERENCE_CALLS_BOOL);
+            if (b == null) return false;
+            return b.getBoolean(CarrierConfigManager.KEY_SUPPORT_ADHOC_CONFERENCE_CALLS_BOOL);
         }
 
 
@@ -722,8 +723,8 @@ public class TelecomAccountRegistry {
         private boolean isCarrierMergeCallSupported() {
             PersistableBundle b =
                     PhoneGlobals.getInstance().getCarrierConfigForSubId(mPhone.getSubId());
-            return b != null &&
-                    b.getBoolean(CarrierConfigManager.KEY_SUPPORT_CONFERENCE_CALL_BOOL);
+            if (b == null) return false;
+            return b.getBoolean(CarrierConfigManager.KEY_SUPPORT_CONFERENCE_CALL_BOOL);
         }
 
         /**
@@ -734,6 +735,7 @@ public class TelecomAccountRegistry {
         private boolean isCarrierMergeImsCallSupported() {
             PersistableBundle b =
                     PhoneGlobals.getInstance().getCarrierConfigForSubId(mPhone.getSubId());
+            if (b == null) return false;
             return b.getBoolean(CarrierConfigManager.KEY_SUPPORT_IMS_CONFERENCE_CALL_BOOL);
         }
 
@@ -745,8 +747,8 @@ public class TelecomAccountRegistry {
         private boolean isCarrierEmergencyVideoCallsAllowed() {
             PersistableBundle b =
                     PhoneGlobals.getInstance().getCarrierConfigForSubId(mPhone.getSubId());
-            return b != null &&
-                    b.getBoolean(CarrierConfigManager.KEY_ALLOW_EMERGENCY_VIDEO_CALLS_BOOL);
+            if (b == null) return false;
+            return b.getBoolean(CarrierConfigManager.KEY_ALLOW_EMERGENCY_VIDEO_CALLS_BOOL);
         }
 
         /**
@@ -757,8 +759,8 @@ public class TelecomAccountRegistry {
         private boolean isCarrierVideoConferencingSupported() {
             PersistableBundle b =
                     PhoneGlobals.getInstance().getCarrierConfigForSubId(mPhone.getSubId());
-            return b != null &&
-                    b.getBoolean(CarrierConfigManager.KEY_SUPPORT_VIDEO_CONFERENCE_CALL_BOOL);
+            if (b == null) return false;
+            return b.getBoolean(CarrierConfigManager.KEY_SUPPORT_VIDEO_CONFERENCE_CALL_BOOL);
         }
 
         /**
@@ -771,7 +773,8 @@ public class TelecomAccountRegistry {
         private boolean isCarrierMergeOfWifiCallsAllowedWhenVoWifiOff() {
             PersistableBundle b =
                     PhoneGlobals.getInstance().getCarrierConfigForSubId(mPhone.getSubId());
-            return b != null && b.getBoolean(
+            if (b == null) return false;
+            return b.getBoolean(
                     CarrierConfigManager.KEY_ALLOW_MERGE_WIFI_CALLS_WHEN_VOWIFI_OFF_BOOL);
         }
 
@@ -784,6 +787,7 @@ public class TelecomAccountRegistry {
         private boolean isCarrierManageImsConferenceCallSupported() {
             PersistableBundle b =
                     PhoneGlobals.getInstance().getCarrierConfigForSubId(mPhone.getSubId());
+            if (b == null) return false;
             return b.getBoolean(CarrierConfigManager.KEY_SUPPORT_MANAGE_IMS_CONFERENCE_CALL_BOOL);
         }
 
@@ -796,6 +800,7 @@ public class TelecomAccountRegistry {
         private boolean isCarrierUsingSimCallManager() {
             PersistableBundle b =
                     PhoneGlobals.getInstance().getCarrierConfigForSubId(mPhone.getSubId());
+            if (b == null) return false;
             return !TextUtils.isEmpty(
                     b.getString(CarrierConfigManager.KEY_DEFAULT_SIM_CALL_MANAGER_STRING));
         }
@@ -810,6 +815,7 @@ public class TelecomAccountRegistry {
         private boolean isCarrierShowPreciseFailedCause() {
             PersistableBundle b =
                     PhoneGlobals.getInstance().getCarrierConfigForSubId(mPhone.getSubId());
+            if (b == null) return false;
             return b.getBoolean(CarrierConfigManager.KEY_SHOW_PRECISE_FAILED_CAUSE_BOOL);
         }
 
@@ -822,6 +828,7 @@ public class TelecomAccountRegistry {
         private boolean isCarrierUseCallRecordingTone() {
             PersistableBundle b =
                     PhoneGlobals.getInstance().getCarrierConfigForSubId(mPhone.getSubId());
+            if (b == null) return false;
             return b.getBoolean(CarrierConfigManager.KEY_PLAY_CALL_RECORDING_TONE_BOOL);
         }
 
@@ -831,6 +838,7 @@ public class TelecomAccountRegistry {
         private boolean isCarrierAllowRttWhenRoaming() {
             PersistableBundle b =
                     PhoneGlobals.getInstance().getCarrierConfigForSubId(mPhone.getSubId());
+            if (b == null) return false;
             return b.getBoolean(CarrierConfigManager.KEY_RTT_SUPPORTED_WHILE_ROAMING_BOOL);
         }
 
@@ -843,6 +851,7 @@ public class TelecomAccountRegistry {
         private Bundle getPhoneAccountExtras() {
             PersistableBundle b =
                     PhoneGlobals.getInstance().getCarrierConfigForSubId(mPhone.getSubId());
+            if (b == null) return new Bundle();
 
             int instantLetteringMaxLength = b.getInt(
                     CarrierConfigManager.KEY_CARRIER_INSTANT_LETTERING_LENGTH_LIMIT_INT);
@@ -1054,8 +1063,10 @@ public class TelecomAccountRegistry {
 
             boolean hasVoiceAvailability = isImsVoiceAvailable();
 
-            boolean isRttSupported = PhoneGlobals.getInstance().phoneMgr
-                    .isRttEnabled(mPhone.getSubId());
+            PhoneInterfaceManager phoneMgr = PhoneGlobals.getInstance()
+                .phoneMgr;
+            boolean isRttSupported = (phoneMgr != null) ?
+                phoneMgr.isRttEnabled(mPhone.getSubId()) : false;
 
             boolean isRoaming = mTelephonyManager.isNetworkRoaming(mPhone.getSubId());
             boolean isOnWfc = mPhone.getImsRegistrationTech()
@@ -1214,7 +1225,7 @@ public class TelecomAccountRegistry {
                 Log.i(this, "TelecomAccountRegistry: User changed, re-registering phone accounts.");
 
                 UserHandle currentUser = intent.getParcelableExtra(Intent.EXTRA_USER);
-                mIsPrimaryUser = currentUser == null ? true : currentUser.isSystem();
+                mDoesUserSupportVideoCalling = currentUser == null ? true : currentUser.isSystem();
 
                 // Any time the user changes, re-register the accounts.
                 tearDownAccounts();
@@ -1287,7 +1298,8 @@ public class TelecomAccountRegistry {
     private int mSubscriptionListenerState = LISTENER_STATE_UNREGISTERED;
     private int mServiceState = ServiceState.STATE_POWER_OFF;
     private int mActiveDataSubscriptionId = SubscriptionManager.INVALID_SUBSCRIPTION_ID;
-    private boolean mIsPrimaryUser = UserHandle.of(ActivityManager.getCurrentUser()).isSystem();
+    private boolean mDoesUserSupportVideoCalling =
+            UserHandle.of(ActivityManager.getCurrentUser()).isSystem();
     private ExponentialBackoff mRegisterSubscriptionListenerBackoff;
     private ExponentialBackoff mTelecomReadyBackoff;
     private final HandlerThread mHandlerThread = new HandlerThread("TelecomAccountRegistry");
diff --git a/src/com/android/services/telephony/TelephonyConnectionService.java b/src/com/android/services/telephony/TelephonyConnectionService.java
index 6a4ea3ede..6f8e83804 100644
--- a/src/com/android/services/telephony/TelephonyConnectionService.java
+++ b/src/com/android/services/telephony/TelephonyConnectionService.java
@@ -1185,8 +1185,7 @@ public class TelephonyConnectionService extends ConnectionService {
         boolean needToTurnOnRadio = (isEmergencyNumber && (!isRadioOn() || isAirplaneModeOn))
                 || (isRadioPowerDownOnBluetooth() && !isPhoneWifiCallingEnabled);
 
-        if (mSatelliteController.isSatelliteEnabled()
-                || mSatelliteController.isSatelliteBeingEnabled()) {
+        if (mSatelliteController.isSatelliteEnabledOrBeingEnabled()) {
             Log.d(this, "onCreateOutgoingConnection, "
                     + " needToTurnOnRadio=" + needToTurnOnRadio
                     + " needToTurnOffSatellite=" + needToTurnOffSatellite
@@ -1203,20 +1202,17 @@ public class TelephonyConnectionService extends ConnectionService {
             }
         }
 
-        boolean forNormalRoutingEmergencyCall = false;
         if (mDomainSelectionResolver.isDomainSelectionSupported()) {
-            if (isEmergencyNumber) {
-                // Normal routing emergency number shall be handled by normal call domain selector.
-                int routing = getEmergencyCallRouting(phone, number, needToTurnOnRadio);
-                if (routing != EmergencyNumber.EMERGENCY_CALL_ROUTING_NORMAL) {
-                    final Connection resultConnection =
-                            placeEmergencyConnection(phone,
-                                    request, numberToDial, isTestEmergencyNumber,
-                                    handle, needToTurnOnRadio, routing);
-                    if (resultConnection != null) return resultConnection;
-                }
-                forNormalRoutingEmergencyCall = true;
-                Log.d(this, "onCreateOutgoingConnection, forNormalRoutingEmergencyCall");
+            // Normal routing emergency number shall be handled by normal call domain selector.
+            int routing = (isEmergencyNumber)
+                    ? getEmergencyCallRouting(phone, number, needToTurnOnRadio)
+                    : EmergencyNumber.EMERGENCY_CALL_ROUTING_UNKNOWN;
+            if (isEmergencyNumber && routing != EmergencyNumber.EMERGENCY_CALL_ROUTING_NORMAL) {
+                final Connection resultConnection =
+                        placeEmergencyConnection(phone,
+                                request, numberToDial, isTestEmergencyNumber,
+                                handle, needToTurnOnRadio, routing);
+                if (resultConnection != null) return resultConnection;
             }
         }
 
@@ -1287,8 +1283,7 @@ public class TelephonyConnectionService extends ConnectionService {
                         // reporting the OUT_OF_SERVICE state.
                         return phone.getState() == PhoneConstants.State.OFFHOOK
                                 || (phone.getServiceStateTracker().isRadioOn()
-                                && (!mSatelliteController.isSatelliteEnabled()
-                                    && !mSatelliteController.isSatelliteBeingEnabled()));
+                                && !mSatelliteController.isSatelliteEnabledOrBeingEnabled());
                     } else {
                         SubscriptionInfoInternal subInfo = SubscriptionManagerService
                                 .getInstance().getSubscriptionInfoInternal(phone.getSubId());
@@ -1305,7 +1300,7 @@ public class TelephonyConnectionService extends ConnectionService {
                     }
                 }
             }, isEmergencyNumber && !isTestEmergencyNumber, phone, isTestEmergencyNumber,
-                    timeoutToOnTimeoutCallback, forNormalRoutingEmergencyCall);
+                    timeoutToOnTimeoutCallback);
             // Return the still unconnected GsmConnection and wait for the Radios to boot before
             // connecting it to the underlying Phone.
             return resultConnection;
@@ -2152,12 +2147,16 @@ public class TelephonyConnectionService extends ConnectionService {
     }
 
     private boolean shouldExitSatelliteModeForEmergencyCall(boolean isEmergencyNumber) {
-        if (!mSatelliteController.isSatelliteEnabled()
-                && !mSatelliteController.isSatelliteBeingEnabled()) {
+        if (!mSatelliteController.isSatelliteEnabledOrBeingEnabled()) {
             return false;
         }
 
         if (isEmergencyNumber) {
+            if (!shouldTurnOffNonEmergencyNbIotNtnSessionForEmergencyCall()) {
+                // Carrier
+                return false;
+            }
+
             if (mSatelliteController.isDemoModeEnabled()) {
                 // If user makes emergency call in demo mode, end the satellite session
                 return true;
@@ -2167,16 +2166,12 @@ public class TelephonyConnectionService extends ConnectionService {
                 return true;
             } else { // satellite is for emergency
                 if (mFeatureFlags.carrierRoamingNbIotNtn()) {
-                    Phone satellitePhone = mSatelliteController.getSatellitePhone();
-                    if (satellitePhone == null) {
-                        loge("satellite is/being enabled, but satellitePhone is null");
-                        return false;
-                    }
+                    int subId = mSatelliteController.getSelectedSatelliteSubId();
                     SubscriptionInfoInternal info = SubscriptionManagerService.getInstance()
-                            .getSubscriptionInfoInternal(satellitePhone.getSubId());
+                            .getSubscriptionInfoInternal(subId);
                     if (info == null) {
                         loge("satellite is/being enabled, but satellite sub "
-                                + satellitePhone.getSubId() + " is null");
+                                + subId + " is null");
                         return false;
                     }
 
@@ -4879,6 +4874,18 @@ public class TelephonyConnectionService extends ConnectionService {
         return turnOffSatellite;
     }
 
+    private boolean shouldTurnOffNonEmergencyNbIotNtnSessionForEmergencyCall() {
+        boolean turnOffSatellite = false;
+        try {
+            turnOffSatellite = getApplicationContext().getResources().getBoolean(R.bool
+                    .config_turn_off_non_emergency_nb_iot_ntn_satellite_for_emergency_call);
+        } catch (Resources.NotFoundException ex) {
+            Log.e(this, ex,
+                    "shouldTurnOffNonEmergencyNbIotNtnSessionForEmergencyCall: ex=" + ex);
+        }
+        return turnOffSatellite;
+    }
+
     /* Only for testing */
     @VisibleForTesting
     public void setFeatureFlags(FeatureFlags featureFlags) {
diff --git a/src/com/android/services/telephony/domainselection/NormalCallDomainSelector.java b/src/com/android/services/telephony/domainselection/NormalCallDomainSelector.java
index 37813e3db..a7ed708dc 100644
--- a/src/com/android/services/telephony/domainselection/NormalCallDomainSelector.java
+++ b/src/com/android/services/telephony/domainselection/NormalCallDomainSelector.java
@@ -140,7 +140,10 @@ public class NormalCallDomainSelector extends DomainSelectorBase implements
 
         if (subId == getSubId()) {
             logd("NormalCallDomainSelection triggered. Sub-id:" + subId);
-            sendEmptyMessageDelayed(MSG_WAIT_FOR_IMS_STATE_TIMEOUT, WAIT_FOR_IMS_STATE_TIMEOUT_MS);
+            if (!mReselectDomain) {
+                sendEmptyMessageDelayed(MSG_WAIT_FOR_IMS_STATE_TIMEOUT,
+                        WAIT_FOR_IMS_STATE_TIMEOUT_MS);
+            }
             post(() -> selectDomain());
         } else {
             mSelectorState = SelectorState.INACTIVE;
diff --git a/testapps/TestSatelliteApp/AndroidManifest.xml b/testapps/TestSatelliteApp/AndroidManifest.xml
index eaddf9516..a1f22fa4b 100644
--- a/testapps/TestSatelliteApp/AndroidManifest.xml
+++ b/testapps/TestSatelliteApp/AndroidManifest.xml
@@ -20,6 +20,7 @@
     <uses-permission android:name="android.permission.BIND_SATELLITE_SERVICE"/>
     <uses-permission android:name="android.permission.SATELLITE_COMMUNICATION"/>
     <uses-permission android:name="android.permission.READ_PRIVILEGED_PHONE_STATE"/>
+    <uses-permission android:name="android.permission.SEND_SMS"/>
     <application android:label="SatelliteTestApp">
         <activity android:name=".SatelliteTestApp"
              android:label="SatelliteTestApp"
diff --git a/testapps/TestSatelliteApp/res/layout/activity_Datagram.xml b/testapps/TestSatelliteApp/res/layout/activity_Datagram.xml
index 9e53f4185..ba6132865 100644
--- a/testapps/TestSatelliteApp/res/layout/activity_Datagram.xml
+++ b/testapps/TestSatelliteApp/res/layout/activity_Datagram.xml
@@ -15,12 +15,14 @@
   ~ limitations under the License
   -->
 
-<LinearLayout
+<ScrollView
     xmlns:android="http://schemas.android.com/apk/res/android"
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:orientation="vertical"
     android:gravity="center"
+    android:paddingTop="10dp"
+    android:paddingBottom="10dp"
     android:paddingLeft="4dp">
 
     <LinearLayout
@@ -125,4 +127,4 @@
             android:textColor="@android:color/holo_blue_light"
             android:textSize="15dp" />
     </LinearLayout>
-</LinearLayout>
+</ScrollView>
diff --git a/testapps/TestSatelliteApp/res/layout/activity_MultipleSendReceive.xml b/testapps/TestSatelliteApp/res/layout/activity_MultipleSendReceive.xml
index 3632ecbb1..c81eb3bfb 100644
--- a/testapps/TestSatelliteApp/res/layout/activity_MultipleSendReceive.xml
+++ b/testapps/TestSatelliteApp/res/layout/activity_MultipleSendReceive.xml
@@ -15,12 +15,14 @@
   ~ limitations under the License
   -->
 
-<LinearLayout
+<ScrollView
     xmlns:android="http://schemas.android.com/apk/res/android"
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:orientation="vertical"
     android:gravity="center"
+    android:paddingTop="10dp"
+    android:paddingBottom="10dp"
     android:paddingLeft="4dp">
 
     <LinearLayout
@@ -95,4 +97,4 @@
             android:layout_centerVertical="true"
             android:textSize="15dp" />
     </LinearLayout>
-</LinearLayout>
+</ScrollView>
diff --git a/testapps/TestSatelliteApp/res/layout/activity_NbIotSatellite.xml b/testapps/TestSatelliteApp/res/layout/activity_NbIotSatellite.xml
index c33522e5f..fef42929f 100644
--- a/testapps/TestSatelliteApp/res/layout/activity_NbIotSatellite.xml
+++ b/testapps/TestSatelliteApp/res/layout/activity_NbIotSatellite.xml
@@ -15,79 +15,86 @@
   ~ limitations under the License
   -->
 
-<LinearLayout
+<ScrollView
     xmlns:android="http://schemas.android.com/apk/res/android"
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:orientation="vertical"
     android:gravity="center"
-    android:paddingStart="4dp"
-    android:paddingEnd="4dp">
+    android:paddingTop="10dp"
+    android:paddingBottom="10dp"
+    android:paddingLeft="4dp">
 
-    <TextView
-        android:layout_width="wrap_content"
-        android:layout_height="0dp"
-        android:layout_weight="0"
-        android:textColor="@android:color/holo_blue_dark"
-        android:textSize="20sp"
-        android:text="@string/NbIotSatellite"/>
-    <Button
-        android:id="@+id/testRegisterForSupportedStateChanged"
+    <LinearLayout
         android:layout_width="match_parent"
         android:layout_height="wrap_content"
-        android:paddingStart="4dp"
-        android:paddingEnd="4dp"
-        android:text="@string/testRegisterForSupportedStateChanged"/>
-    <Button
-        android:id="@+id/testUnregisterForSupportedStateChanged"
-        android:layout_width="match_parent"
-        android:layout_height="wrap_content"
-        android:paddingStart="4dp"
-        android:paddingEnd="4dp"
-        android:text="@string/testUnregisterForSupportedStateChanged"/>
-    <Button
-        android:id="@+id/testRequestIsSupported"
-        android:layout_width="match_parent"
-        android:layout_height="wrap_content"
-        android:paddingStart="4dp"
-        android:paddingEnd="4dp"
-        android:text="@string/testRequestIsSupported"/>
-     <Button
-        android:id="@+id/reportSatelliteSupportedFromModem"
-        android:layout_width="match_parent"
-        android:layout_height="wrap_content"
-        android:paddingStart="4dp"
-        android:paddingEnd="4dp"
-        android:text="@string/reportSatelliteSupportedFromModem"/>
-    <Button
-        android:id="@+id/reportSatelliteNotSupportedFromModem"
-        android:layout_width="match_parent"
-        android:layout_height="wrap_content"
-        android:paddingStart="4dp"
-        android:paddingEnd="4dp"
-        android:text="@string/reportSatelliteNotSupportedFromModem"/>
-    <Button
-        android:id="@+id/showCurrentSatelliteSupportedStated"
-        android:layout_width="match_parent"
-        android:layout_height="wrap_content"
-        android:paddingStart="4dp"
-        android:paddingEnd="4dp"
-        android:text="@string/showCurrentSatelliteSupportedStated"/>
-    <Button
-        android:id="@+id/Back"
-        android:onClick="Back"
-        android:textColor="@android:color/holo_blue_dark"
-        android:layout_marginTop="100dp"
-        android:layout_gravity="center"
-        android:layout_width="wrap_content"
-        android:layout_height="wrap_content"
-        android:paddingStart="4dp"
-        android:paddingEnd="4dp"
-        android:text="@string/Back"/>
-    <TextView
-        android:id="@+id/text_id"
-        android:layout_width="300dp"
-        android:layout_height="200dp"
-        android:textColor="@android:color/holo_blue_light"
-        android:textSize="15sp" />
-</LinearLayout>
+        android:orientation="vertical">
+
+        <TextView
+            android:layout_width="wrap_content"
+            android:layout_height="0dp"
+            android:layout_weight="0"
+            android:textColor="@android:color/holo_blue_dark"
+            android:textSize="20sp"
+            android:text="@string/NbIotSatellite"/>
+        <Button
+            android:id="@+id/testRegisterForSupportedStateChanged"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingStart="4dp"
+            android:paddingEnd="4dp"
+            android:text="@string/testRegisterForSupportedStateChanged"/>
+        <Button
+            android:id="@+id/testUnregisterForSupportedStateChanged"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingStart="4dp"
+            android:paddingEnd="4dp"
+            android:text="@string/testUnregisterForSupportedStateChanged"/>
+        <Button
+            android:id="@+id/testRequestIsSupported"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingStart="4dp"
+            android:paddingEnd="4dp"
+            android:text="@string/testRequestIsSupported"/>
+         <Button
+            android:id="@+id/reportSatelliteSupportedFromModem"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingStart="4dp"
+            android:paddingEnd="4dp"
+            android:text="@string/reportSatelliteSupportedFromModem"/>
+        <Button
+            android:id="@+id/reportSatelliteNotSupportedFromModem"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingStart="4dp"
+            android:paddingEnd="4dp"
+            android:text="@string/reportSatelliteNotSupportedFromModem"/>
+        <Button
+            android:id="@+id/showCurrentSatelliteSupportedStated"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingStart="4dp"
+            android:paddingEnd="4dp"
+            android:text="@string/showCurrentSatelliteSupportedStated"/>
+        <Button
+            android:id="@+id/Back"
+            android:onClick="Back"
+            android:textColor="@android:color/holo_blue_dark"
+            android:layout_marginTop="100dp"
+            android:layout_gravity="center"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:paddingStart="4dp"
+            android:paddingEnd="4dp"
+            android:text="@string/Back"/>
+        <TextView
+            android:id="@+id/text_id"
+            android:layout_width="300dp"
+            android:layout_height="200dp"
+            android:textColor="@android:color/holo_blue_light"
+            android:textSize="15sp" />
+    </LinearLayout>
+</ScrollView>
diff --git a/testapps/TestSatelliteApp/res/layout/activity_Provisioning.xml b/testapps/TestSatelliteApp/res/layout/activity_Provisioning.xml
index da5105db0..afcc70650 100644
--- a/testapps/TestSatelliteApp/res/layout/activity_Provisioning.xml
+++ b/testapps/TestSatelliteApp/res/layout/activity_Provisioning.xml
@@ -15,12 +15,14 @@
   ~ limitations under the License
   -->
 
-<LinearLayout
+<ScrollView
     xmlns:android="http://schemas.android.com/apk/res/android"
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:orientation="vertical"
     android:gravity="center"
+    android:paddingTop="10dp"
+    android:paddingBottom="10dp"
     android:paddingLeft="4dp">
 
     <LinearLayout
@@ -90,4 +92,4 @@
             android:layout_centerVertical="true"
             android:textSize="15dp" />
     </LinearLayout>
-</LinearLayout>
+</ScrollView>
diff --git a/testapps/TestSatelliteApp/res/layout/activity_SatelliteControl.xml b/testapps/TestSatelliteApp/res/layout/activity_SatelliteControl.xml
index 151f6cafe..23f6ee94f 100644
--- a/testapps/TestSatelliteApp/res/layout/activity_SatelliteControl.xml
+++ b/testapps/TestSatelliteApp/res/layout/activity_SatelliteControl.xml
@@ -21,7 +21,8 @@
     android:layout_height="wrap_content"
     android:orientation="vertical"
     android:gravity="center"
-    android:paddingTop="100dp"
+    android:paddingTop="10dp"
+    android:paddingBottom="10dp"
     android:paddingLeft="4dp">
 
     <LinearLayout
@@ -37,11 +38,17 @@
             android:textSize="20dp"
             android:text="Satellite Control APIs"/>
         <Button
-            android:id="@+id/enableSatellite"
+            android:id="@+id/enableSatelliteDemoMode"
             android:layout_width="match_parent"
             android:layout_height="wrap_content"
             android:paddingRight="4dp"
-            android:text="@string/enableSatellite"/>
+            android:text="@string/enableSatelliteDemoMode"/>
+        <Button
+            android:id="@+id/enableSatelliteRealMode"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingRight="4dp"
+            android:text="@string/enableSatelliteRealMode"/>
         <Button
             android:id="@+id/disableSatellite"
             android:layout_width="match_parent"
@@ -138,6 +145,12 @@
             android:layout_height="wrap_content"
             android:paddingRight="4dp"
             android:text="@string/provisionSatellite"/>
+        <Button
+            android:id="@+id/deprovisionSatellite"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingRight="4dp"
+            android:text="@string/deprovisionSatellite"/>
          <Button
             android:id="@+id/Back"
             android:onClick="Back"
diff --git a/testapps/TestSatelliteApp/res/layout/activity_SatelliteTestApp.xml b/testapps/TestSatelliteApp/res/layout/activity_SatelliteTestApp.xml
index 8fdc01ff8..26b45e309 100644
--- a/testapps/TestSatelliteApp/res/layout/activity_SatelliteTestApp.xml
+++ b/testapps/TestSatelliteApp/res/layout/activity_SatelliteTestApp.xml
@@ -15,12 +15,14 @@
   ~ limitations under the License
   -->
 
-<LinearLayout
+<ScrollView
     xmlns:android="http://schemas.android.com/apk/res/android"
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:orientation="vertical"
-    android:paddingTop="100dp"
+    android:gravity="center"
+    android:paddingTop="10dp"
+    android:paddingBottom="10dp"
     android:paddingLeft="4dp">
 
     <LinearLayout
@@ -80,4 +82,4 @@
             android:paddingEnd="4dp"
             android:text="@string/TestSatelliteWrapper"/>
     </LinearLayout>
-</LinearLayout>
+</ScrollView>
diff --git a/testapps/TestSatelliteApp/res/layout/activity_SendReceive.xml b/testapps/TestSatelliteApp/res/layout/activity_SendReceive.xml
index 6490e5d4f..4ac348307 100644
--- a/testapps/TestSatelliteApp/res/layout/activity_SendReceive.xml
+++ b/testapps/TestSatelliteApp/res/layout/activity_SendReceive.xml
@@ -15,12 +15,14 @@
   ~ limitations under the License
   -->
 
-<LinearLayout
+<ScrollView
     xmlns:android="http://schemas.android.com/apk/res/android"
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:orientation="vertical"
     android:gravity="center"
+    android:paddingTop="10dp"
+    android:paddingBottom="10dp"
     android:paddingLeft="4dp">
 
     <LinearLayout
@@ -94,4 +96,4 @@
             android:layout_centerVertical="true"
             android:textSize="15dp" />
     </LinearLayout>
-</LinearLayout>
+</ScrollView>
diff --git a/testapps/TestSatelliteApp/res/layout/activity_TestSatelliteWrapper.xml b/testapps/TestSatelliteApp/res/layout/activity_TestSatelliteWrapper.xml
index 39a4bd690..b4df40a70 100644
--- a/testapps/TestSatelliteApp/res/layout/activity_TestSatelliteWrapper.xml
+++ b/testapps/TestSatelliteApp/res/layout/activity_TestSatelliteWrapper.xml
@@ -14,10 +14,16 @@
   ~ See the License for the specific language governing permissions and
   ~ limitations under the License
   -->
+
 <ScrollView
     xmlns:android="http://schemas.android.com/apk/res/android"
     android:layout_width="match_parent"
-    android:layout_height="match_parent">
+    android:layout_height="wrap_content"
+    android:orientation="vertical"
+    android:gravity="center"
+    android:paddingTop="10dp"
+    android:paddingBottom="10dp"
+    android:paddingLeft="4dp">
 
     <LinearLayout
         xmlns:android="http://schemas.android.com/apk/res/android"
@@ -167,6 +173,43 @@
             android:layout_height="wrap_content"
             android:paddingRight="4dp"
             android:text="@string/unregisterForModemStateChanged"/>
+        <Button
+            android:id="@+id/requestSatelliteSubscriberProvisionStatusWrapper"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingRight="4dp"
+            android:text="@string/requestSatelliteSubscriberProvisionStatus"/>
+        <Button
+            android:id="@+id/provisionSatelliteWrapper"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingRight="4dp"
+            android:text="@string/provisionSatellite"/>
+        <Button
+            android:id="@+id/deprovisionSatelliteWrapper"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingRight="4dp"
+            android:text="@string/deprovisionSatellite"/>
+        <Button
+            android:id="@+id/setNtnSmsSupportedTrue"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingRight="4dp"
+            android:text="@string/setNtnSmsSupportedTrue"/>
+        <Button
+            android:id="@+id/setNtnSmsSupportedFalse"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingRight="4dp"
+            android:text="@string/setNtnSmsSupportedFalse"/>
+        <Button
+            android:id="@+id/requestSatelliteAccessConfigurationForCurrentLocation"
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:paddingRight="4dp"
+            android:text="@string/requestSatelliteAccessConfigurationForCurrentLocation"/>
+
         <LinearLayout
             android:layout_width="match_parent"
             android:layout_height="wrap_content"
@@ -203,5 +246,4 @@
             android:layout_centerVertical="true"
             android:textSize="8dp" />
     </LinearLayout>
-
-</ScrollView>
\ No newline at end of file
+</ScrollView>
diff --git a/testapps/TestSatelliteApp/res/values/donottranslate_strings.xml b/testapps/TestSatelliteApp/res/values/donottranslate_strings.xml
index 728576a10..5c3a72d82 100644
--- a/testapps/TestSatelliteApp/res/values/donottranslate_strings.xml
+++ b/testapps/TestSatelliteApp/res/values/donottranslate_strings.xml
@@ -23,7 +23,8 @@
     <string name="SendReceive">Send and Receive datagrams</string>
     <string name="NbIotSatellite">NB IoT Satellite modem interface test</string>
 
-    <string name="enableSatellite">enableSatellite</string>
+    <string name="enableSatelliteRealMode">enableSatellite Real Mode</string>
+    <string name="enableSatelliteDemoMode">enableSatellite Demo Mode</string>
     <string name="disableSatellite">disableSatellite</string>
     <string name="requestIsSatelliteEnabled">requestIsSatelliteEnabled</string>
     <string name="requestIsDemoModeEnabled">requestIsDemoModeEnabled</string>
@@ -95,6 +96,10 @@
 
     <string name="requestSatelliteSubscriberProvisionStatus">requestSatelliteSubscriberProvisionStatus</string>
     <string name="provisionSatellite">provisionSatellite</string>
+    <string name="deprovisionSatellite">deprovisionSatellite</string>
+    <string name="setNtnSmsSupportedTrue">setNtnSmsSupportedTrue</string>
+    <string name="setNtnSmsSupportedFalse">setNtnSmsSupportedFalse</string>
+
 
     <string name="Back">Back</string>
     <string name="ClearLog">Clear Log</string>
@@ -104,4 +109,6 @@
 
     <string name="registerForModemStateChanged">registerForModemStateChanged</string>
     <string name="unregisterForModemStateChanged">unregisterForModemStateChanged</string>
+
+    <string name="requestSatelliteAccessConfigurationForCurrentLocation">requestSatelliteAccessConfigurationForCurrentLocation</string>
 </resources>
diff --git a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/Provisioning.java b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/Provisioning.java
index 15c8fd830..08984bea0 100644
--- a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/Provisioning.java
+++ b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/Provisioning.java
@@ -24,12 +24,14 @@ import android.os.CancellationSignal;
 import android.os.OutcomeReceiver;
 import android.telephony.satellite.SatelliteManager;
 import android.telephony.satellite.SatelliteProvisionStateCallback;
+import android.telephony.satellite.SatelliteSubscriberProvisionStatus;
 import android.telephony.satellite.stub.SatelliteResult;
 import android.util.Log;
 import android.view.View;
 import android.view.View.OnClickListener;
 import android.widget.TextView;
 
+import java.util.List;
 import java.util.concurrent.LinkedBlockingQueue;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.atomic.AtomicReference;
@@ -82,6 +84,12 @@ public class Provisioning extends Activity {
             Log.d(TAG, "onSatelliteProvisionStateChanged in SatelliteTestApp: provisioned="
                     + mProvisioned);
         }
+
+        @Override
+        public void onSatelliteSubscriptionProvisionStateChanged(
+                List<SatelliteSubscriberProvisionStatus> list) {
+            Log.d(TAG, "onSatelliteSubscriptionProvisionStateChanged in SatelliteTestApp" + list);
+        }
     }
 
     private void provisionServiceApp(View view) {
diff --git a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteControl.java b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteControl.java
index 379fc74d1..484a6d15f 100644
--- a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteControl.java
+++ b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteControl.java
@@ -35,6 +35,7 @@ import android.widget.TextView;
 import java.time.Duration;
 import java.util.ArrayList;
 import java.util.List;
+import android.util.Log;
 import java.util.concurrent.LinkedBlockingQueue;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.atomic.AtomicReference;
@@ -44,7 +45,7 @@ import java.util.concurrent.atomic.AtomicReference;
  */
 public class SatelliteControl extends Activity {
 
-    private static final long TIMEOUT = 3000;
+    private static final long TIMEOUT = TimeUnit.SECONDS.toMillis(3);
 
     private SatelliteManager mSatelliteManager;
     private SubscriptionManager mSubscriptionManager;
@@ -58,8 +59,10 @@ public class SatelliteControl extends Activity {
         mSubscriptionManager = getSystemService(SubscriptionManager.class);
 
         setContentView(R.layout.activity_SatelliteControl);
-        findViewById(R.id.enableSatellite)
-                .setOnClickListener(this::enableSatelliteApp);
+        findViewById(R.id.enableSatelliteDemoMode)
+                .setOnClickListener(v -> enableSatelliteApp(/* isDemoMode */ true));
+        findViewById(R.id.enableSatelliteRealMode)
+                .setOnClickListener(v -> enableSatelliteApp(/* isDemoMode */ false));
         findViewById(R.id.disableSatellite)
                 .setOnClickListener(this::disableSatelliteApp);
         findViewById(R.id.requestIsSatelliteEnabled)
@@ -92,6 +95,8 @@ public class SatelliteControl extends Activity {
                 .setOnClickListener(this::requestSatelliteSubscriberProvisionStatusApp);
         findViewById(R.id.provisionSatellite)
                 .setOnClickListener(this::provisionSatelliteApp);
+        findViewById(R.id.deprovisionSatellite)
+                .setOnClickListener(this::deprovisionSatelliteApp);
         findViewById(R.id.Back).setOnClickListener(new OnClickListener() {
             @Override
             public void onClick(View view) {
@@ -100,24 +105,32 @@ public class SatelliteControl extends Activity {
         });
     }
 
-    private void enableSatelliteApp(View view) {
+    private void enableSatelliteApp(boolean isDemoMode) {
         LinkedBlockingQueue<Integer> error = new LinkedBlockingQueue<>(1);
         mSatelliteManager.requestEnabled(
-                new EnableRequestAttributes.Builder(true).setDemoMode(true).setEmergencyMode(true)
+                new EnableRequestAttributes.Builder(true)
+                        .setDemoMode(isDemoMode)
+                        .setEmergencyMode(true)
                         .build(), Runnable::run, error::offer);
         TextView textView = findViewById(R.id.text_id);
+        Log.d("SatelliteTestApp", "enableSatelliteApp: isDemoMode=" + isDemoMode);
         try {
             Integer value = error.poll(TIMEOUT, TimeUnit.MILLISECONDS);
             if (value == null) {
                 textView.setText("Timed out to enable the satellite");
+                Log.d("SatelliteTestApp", "Timed out to enable the satellite");
             } else if (value != SatelliteResult.SATELLITE_RESULT_SUCCESS) {
                 textView.setText("Failed to enable the satellite, error ="
                         + SatelliteErrorUtils.mapError(value));
+                Log.d("SatelliteTestApp", "Failed to enable the satellite, error ="
+                        + SatelliteErrorUtils.mapError(value));
             } else {
                 textView.setText("Successfully enabled the satellite");
+                Log.d("SatelliteTestApp", "Successfully enabled the satellite");
             }
         } catch (InterruptedException e) {
             textView.setText("Enable SatelliteService exception caught =" + e);
+            Log.d("SatelliteTestApp", "Enable SatelliteService exception caught =" + e);
         }
     }
 
@@ -456,4 +469,36 @@ public class SatelliteControl extends Activity {
         }
         mSatelliteManager.provisionSatellite(list, Runnable::run, receiver);
     }
+
+    private void deprovisionSatelliteApp(View view) {
+        final AtomicReference<Boolean> enabled = new AtomicReference<>();
+        final AtomicReference<Integer> errorCode = new AtomicReference<>();
+        OutcomeReceiver<Boolean, SatelliteManager.SatelliteException> receiver =
+                new OutcomeReceiver<>() {
+                    @Override
+                    public void onResult(Boolean result) {
+                        enabled.set(result);
+                        TextView textView = findViewById(R.id.text_id);
+                        if (enabled.get()) {
+                            textView.setText("deprovisionSatellite is true");
+                        } else {
+                            textView.setText("Status for deprovisionSatellite result : "
+                                    + enabled.get());
+                        }
+                    }
+
+                    @Override
+                    public void onError(SatelliteManager.SatelliteException exception) {
+                        errorCode.set(exception.getErrorCode());
+                        TextView textView = findViewById(R.id.text_id);
+                        textView.setText("Status for deprovisionSatellite error : "
+                                + SatelliteErrorUtils.mapError(errorCode.get()));
+                    }
+                };
+        List<SatelliteSubscriberInfo> list = new ArrayList<>();
+        for (SatelliteSubscriberProvisionStatus status : mSatelliteSubscriberProvisionStatuses) {
+            list.add(status.getSatelliteSubscriberInfo());
+        }
+        mSatelliteManager.deprovisionSatellite(list, Runnable::run, receiver);
+    }
 }
diff --git a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteTestApp.java b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteTestApp.java
index 7c4ae00aa..cb56e87a8 100644
--- a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteTestApp.java
+++ b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SatelliteTestApp.java
@@ -16,11 +16,13 @@
 
 package com.android.phone.testapps.satellitetestapp;
 
+import android.Manifest;
 import android.app.Activity;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.Intent;
 import android.content.ServiceConnection;
+import android.content.pm.PackageManager;
 import android.os.Bundle;
 import android.os.IBinder;
 import android.telephony.satellite.stub.SatelliteDatagram;
@@ -42,6 +44,7 @@ public class SatelliteTestApp extends Activity {
 
     private TestSatelliteServiceConnection mSatelliteServiceConn;
     private List<SatelliteDatagram> mSentSatelliteDatagrams = new ArrayList<>();
+    private static final int REQUEST_CODE_SEND_SMS = 1;
 
     @Override
     public void onCreate(Bundle savedInstanceState) {
@@ -105,6 +108,16 @@ public class SatelliteTestApp extends Activity {
         });
     }
 
+    @Override
+    protected void onResume() {
+        super.onResume();
+        if (checkSelfPermission(Manifest.permission.SEND_SMS)
+                != PackageManager.PERMISSION_GRANTED) {
+            requestPermissions(new String[]{Manifest.permission.SEND_SMS}, REQUEST_CODE_SEND_SMS);
+        }
+    }
+
+
     private final ILocalSatelliteListener mSatelliteListener =
             new ILocalSatelliteListener.Stub() {
                 @Override
diff --git a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SendReceive.java b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SendReceive.java
index ede237797..bc60c9b7b 100644
--- a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SendReceive.java
+++ b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/SendReceive.java
@@ -290,7 +290,7 @@ public class SendReceive extends Activity {
             satellitePositionTextView.setText("startSatelliteTransmissionUpdates exception caught ="
                         + e);
         }
-        //Device is aligned with the satellite for demo mode
+        //Device is aligned with the satellite
         mSatelliteManager.setDeviceAlignedWithSatellite(true);
     }
 }
diff --git a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteService.java b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteService.java
index 9c75a8473..225fba0e7 100644
--- a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteService.java
+++ b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteService.java
@@ -60,7 +60,7 @@ public class TestSatelliteService extends SatelliteImplBase {
     private static final int SATELLITE_ALWAYS_VISIBLE = 0;
     /** SatelliteCapabilities constant indicating that the radio technology is proprietary. */
     private static final int[] SUPPORTED_RADIO_TECHNOLOGIES =
-            new int[]{NTRadioTechnology.PROPRIETARY};
+            new int[]{NTRadioTechnology.NB_IOT_NTN};
     /** SatelliteCapabilities constant indicating that pointing to satellite is required. */
     private static final boolean POINTING_TO_SATELLITE_REQUIRED = true;
     /** SatelliteCapabilities constant indicating the maximum number of characters per datagram. */
@@ -208,14 +208,14 @@ public class TestSatelliteService extends SatelliteImplBase {
 
     private void enableSatellite(@NonNull IIntegerConsumer errorCallback) {
         mIsEnabled = true;
-        updateSatelliteModemState(SatelliteModemState.SATELLITE_MODEM_STATE_IDLE);
         runWithExecutor(() -> errorCallback.accept(SatelliteResult.SATELLITE_RESULT_SUCCESS));
+        updateSatelliteModemState(SatelliteModemState.SATELLITE_MODEM_STATE_IN_SERVICE);
     }
 
     private void disableSatellite(@NonNull IIntegerConsumer errorCallback) {
         mIsEnabled = false;
-        updateSatelliteModemState(SatelliteModemState.SATELLITE_MODEM_STATE_OFF);
         runWithExecutor(() -> errorCallback.accept(SatelliteResult.SATELLITE_RESULT_SUCCESS));
+        updateSatelliteModemState(SatelliteModemState.SATELLITE_MODEM_STATE_OFF);
     }
 
     @Override
@@ -494,6 +494,7 @@ public class TestSatelliteService extends SatelliteImplBase {
      * @param modemState The {@link SatelliteModemState} to update.
      */
     private void updateSatelliteModemState(int modemState) {
+        logd("updateSatelliteModemState: new modemState=" + modemState);
         if (modemState == mModemState) {
             return;
         }
diff --git a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteWrapper.java b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteWrapper.java
index d8e6e7cfe..5092d03af 100644
--- a/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteWrapper.java
+++ b/testapps/TestSatelliteApp/src/com/android/phone/testapps/satellitetestapp/TestSatelliteWrapper.java
@@ -26,10 +26,13 @@ import android.telephony.SubscriptionManager;
 import android.telephony.satellite.wrapper.CarrierRoamingNtnModeListenerWrapper2;
 import android.telephony.satellite.wrapper.NtnSignalStrengthCallbackWrapper;
 import android.telephony.satellite.wrapper.NtnSignalStrengthWrapper;
+import android.telephony.satellite.wrapper.SatelliteAccessConfigurationWrapper;
 import android.telephony.satellite.wrapper.SatelliteCapabilitiesCallbackWrapper;
 import android.telephony.satellite.wrapper.SatelliteCommunicationAllowedStateCallbackWrapper;
 import android.telephony.satellite.wrapper.SatelliteManagerWrapper;
 import android.telephony.satellite.wrapper.SatelliteModemStateCallbackWrapper2;
+import android.telephony.satellite.wrapper.SatelliteSubscriberInfoWrapper;
+import android.telephony.satellite.wrapper.SatelliteSubscriberProvisionStatusWrapper;
 import android.util.Log;
 import android.view.View;
 import android.view.View.OnClickListener;
@@ -62,6 +65,8 @@ public class TestSatelliteWrapper extends Activity {
     private SatelliteCapabilitiesCallbackWrapper mSatelliteCapabilitiesCallback;
     private SubscriptionManager mSubscriptionManager;
     private int mSubId;
+    private List<SatelliteSubscriberProvisionStatusWrapper> mSatelliteSubscriberProvisionStatuses =
+            new ArrayList<>();
 
     private ListView mLogListView;
 
@@ -117,6 +122,20 @@ public class TestSatelliteWrapper extends Activity {
                 .setOnClickListener(this::registerForModemStateChanged);
         findViewById(R.id.unregisterForModemStateChanged)
                 .setOnClickListener(this::unregisterForModemStateChanged);
+        findViewById(R.id.requestSatelliteSubscriberProvisionStatusWrapper)
+                .setOnClickListener(this::requestSatelliteSubscriberProvisionStatus);
+        findViewById(R.id.provisionSatelliteWrapper)
+                .setOnClickListener(this::provisionSatellite);
+        findViewById(R.id.deprovisionSatelliteWrapper)
+                .setOnClickListener(this::deprovisionSatellite);
+        findViewById(R.id.setNtnSmsSupportedTrue)
+                .setOnClickListener(this::setNtnSmsSupportedTrue);
+        findViewById(R.id.setNtnSmsSupportedFalse)
+                .setOnClickListener(this::setNtnSmsSupportedFalse);
+        findViewById(R.id.requestSatelliteAccessConfigurationForCurrentLocation)
+                .setOnClickListener(this::requestSatelliteAccessConfigurationForCurrentLocation);
+
+
 
         findViewById(R.id.Back).setOnClickListener(new OnClickListener() {
             @Override
@@ -389,7 +408,137 @@ public class TestSatelliteWrapper extends Activity {
         }
     }
 
+    private void requestSatelliteSubscriberProvisionStatus(View view) {
+        addLogMessage("requestSatelliteSubscriberProvisionStatus");
+        logd("requestSatelliteSubscriberProvisionStatus");
+
+        if (mSubId == SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
+            addLogMessage("requestSatelliteSubscriberProvisionStatus: Subscription ID is invalid");
+            logd("requestSatelliteSubscriberProvisionStatus: Subscription ID is invalid");
+            return;
+        }
+
+        OutcomeReceiver<List<SatelliteSubscriberProvisionStatusWrapper>,
+                SatelliteManagerWrapper.SatelliteExceptionWrapper> receiver =
+                new OutcomeReceiver<>() {
+                    @Override
+                    public void onResult(List<SatelliteSubscriberProvisionStatusWrapper> result) {
+                        mSatelliteSubscriberProvisionStatuses = result;
+                        logd("requestSatelliteSubscriberProvisionStatus: onResult=" + result);
+                        addLogMessage(
+                                "requestSatelliteSubscriberProvisionStatus: onResult=" + result);
+                    }
+
+                    @Override
+                    public void onError(
+                            SatelliteManagerWrapper.SatelliteExceptionWrapper exception) {
+                        if (exception != null) {
+                            String onError = "requestSatelliteSubscriberProvisionStatus exception: "
+                                    + translateResultCodeToString(exception.getErrorCode());
+                            logd(onError);
+                            addLogMessage(onError);
+                        }
+                    }
+                };
+
+        try {
+            mSatelliteManagerWrapper.requestSatelliteSubscriberProvisionStatus(mExecutor, receiver);
+        } catch (SecurityException | IllegalArgumentException ex) {
+            String errorMessage = "requestSatelliteSubscriberProvisionStatus: " + ex.getMessage();
+            logd(errorMessage);
+            addLogMessage(errorMessage);
+        }
+    }
+
+    private void provisionSatellite(View view) {
+        addLogMessage("provisionSatellite");
+        logd("provisionSatellite");
+
+        if (mSubId == SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
+            addLogMessage("provisionSatellite: Subscription ID is invalid");
+            logd("provisionSatellite: Subscription ID is invalid");
+            return;
+        }
 
+        OutcomeReceiver<Boolean,
+                SatelliteManagerWrapper.SatelliteExceptionWrapper> receiver =
+                new OutcomeReceiver<>() {
+                    @Override
+                    public void onResult(Boolean result) {
+                        logd("provisionSatellite: onResult=" + result);
+                        addLogMessage("provisionSatellite: onResult=" + result);
+                    }
+
+                    @Override
+                    public void onError(
+                            SatelliteManagerWrapper.SatelliteExceptionWrapper exception) {
+                        if (exception != null) {
+                            String onError = "provisionSatellite exception: "
+                                    + translateResultCodeToString(exception.getErrorCode());
+                            logd(onError);
+                            addLogMessage(onError);
+                        }
+                    }
+                };
+
+        List<SatelliteSubscriberInfoWrapper> list = new ArrayList<>();
+        for (SatelliteSubscriberProvisionStatusWrapper status :
+                mSatelliteSubscriberProvisionStatuses) {
+            list.add(status.getSatelliteSubscriberInfo());
+        }
+        try {
+            mSatelliteManagerWrapper.provisionSatellite(list, mExecutor, receiver);
+        } catch (SecurityException | IllegalArgumentException ex) {
+            String errorMessage = "provisionSatellite: " + ex.getMessage();
+            logd(errorMessage);
+            addLogMessage(errorMessage);
+        }
+    }
+
+    private void deprovisionSatellite(View view) {
+        addLogMessage("deprovisionSatellite");
+        logd("deprovisionSatellite");
+
+        if (mSubId == SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
+            addLogMessage("deprovisionSatellite: Subscription ID is invalid");
+            logd("deprovisionSatellite: Subscription ID is invalid");
+            return;
+        }
+
+        OutcomeReceiver<Boolean,
+                SatelliteManagerWrapper.SatelliteExceptionWrapper> receiver =
+                new OutcomeReceiver<>() {
+                    @Override
+                    public void onResult(Boolean result) {
+                        logd("deprovisionSatellite: onResult=" + result);
+                        addLogMessage("deprovisionSatellite: onResult=" + result);
+                    }
+
+                    @Override
+                    public void onError(
+                            SatelliteManagerWrapper.SatelliteExceptionWrapper exception) {
+                        if (exception != null) {
+                            String onError = "deprovisionSatellite exception: "
+                                    + translateResultCodeToString(exception.getErrorCode());
+                            logd(onError);
+                            addLogMessage(onError);
+                        }
+                    }
+                };
+
+        List<SatelliteSubscriberInfoWrapper> list = new ArrayList<>();
+        for (SatelliteSubscriberProvisionStatusWrapper status :
+                mSatelliteSubscriberProvisionStatuses) {
+            list.add(status.getSatelliteSubscriberInfo());
+        }
+        try {
+            mSatelliteManagerWrapper.deprovisionSatellite(list, mExecutor, receiver);
+        } catch (SecurityException | IllegalArgumentException ex) {
+            String errorMessage = "deprovisionSatellite: " + ex.getMessage();
+            logd(errorMessage);
+            addLogMessage(errorMessage);
+        }
+    }
 
     public class NtnSignalStrengthCallback implements NtnSignalStrengthCallbackWrapper {
         @Override
@@ -558,6 +707,47 @@ public class TestSatelliteWrapper extends Activity {
         }
     }
 
+    private void requestSatelliteAccessConfigurationForCurrentLocation(View view) {
+        addLogMessage("requestSatelliteAccessConfigurationForCurrentLocation");
+        logd("requestSatelliteAccessConfigurationForCurrentLocation");
+        OutcomeReceiver<SatelliteAccessConfigurationWrapper,
+                SatelliteManagerWrapper.SatelliteExceptionWrapper> receiver =
+                new OutcomeReceiver<>() {
+                    @Override
+                    public void onResult(SatelliteAccessConfigurationWrapper result) {
+                        if (result != null) {
+                            addLogMessage("requestSatelliteAccessConfigurationForCurrentLocation: "
+                                    + result.getSatelliteInfos());
+                        } else {
+                            addLogMessage("requestSatelliteAccessConfigurationForCurrentLocation: "
+                                    + "null");
+                        }
+                    }
+
+                    @Override
+                    public void onError(
+                            SatelliteManagerWrapper.SatelliteExceptionWrapper exception) {
+                        if (exception != null) {
+                            String onError = "requestSatelliteAccessConfigurationForCurrentLocation"
+                                    + " exception: "
+                                    + translateResultCodeToString(exception.getErrorCode());
+                            logd(onError);
+                            addLogMessage(onError);
+                        }
+                    }
+                };
+
+        try {
+            mSatelliteManagerWrapper
+                    .requestSatelliteAccessConfigurationForCurrentLocation(mExecutor, receiver);
+        } catch (SecurityException ex) {
+            String errorMessage = "requestSatelliteAccessConfigurationForCurrentLocation: "
+                    + ex.getMessage();
+            logd(errorMessage);
+            addLogMessage(errorMessage);
+        }
+    }
+
     private void addAttachRestrictionForCarrier(View view) {
         addLogMessage("addAttachRestrictionForCarrier");
         logd("addAttachRestrictionForCarrier");
@@ -659,6 +849,31 @@ public class TestSatelliteWrapper extends Activity {
         }
     }
 
+    private void setNtnSmsSupportedTrue(View view) {
+        setNtnSmsSupported(true);
+    }
+
+    private void setNtnSmsSupportedFalse(View view) {
+        setNtnSmsSupported(false);
+    }
+
+    private void setNtnSmsSupported(boolean ntnSmsSupported) {
+        String msg = "setNtnSmsSupported:" + ntnSmsSupported;
+        addLogMessage(msg);
+        logd(msg);
+
+        try {
+            mSatelliteManagerWrapper.setNtnSmsSupported(ntnSmsSupported);
+            msg = "setNtnSmsSupported=" + ntnSmsSupported + " is successful";
+            logd(msg);
+            addLogMessage(msg);
+        } catch (SecurityException | IllegalStateException ex) {
+            msg = "setNtnSmsSupported=" + ntnSmsSupported + " failed. " + ex.getMessage();
+            logd(msg);
+            addLogMessage(msg);
+        }
+    }
+
     private int getActiveSubId() {
         int subId;
         List<SubscriptionInfo> subscriptionInfoList =
diff --git a/tests/src/com/android/TelephonyTestBase.java b/tests/src/com/android/TelephonyTestBase.java
index d72d85efb..94e91d331 100644
--- a/tests/src/com/android/TelephonyTestBase.java
+++ b/tests/src/com/android/TelephonyTestBase.java
@@ -16,21 +16,40 @@
 
 package com.android;
 
+import static org.junit.Assert.assertNotNull;
 import static org.mockito.Mockito.spy;
+import static org.mockito.Mockito.doCallRealMethod;
+import static org.mockito.Mockito.doReturn;
 
+import android.content.ContextWrapper;
+import android.content.res.Resources;
 import android.os.Handler;
 import android.os.Looper;
 import android.util.Log;
 
+import androidx.test.InstrumentationRegistry;
+
+import com.android.internal.telephony.GsmCdmaPhone;
+import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.PhoneConfigurationManager;
+import com.android.internal.telephony.PhoneFactory;
+import com.android.internal.telephony.data.DataConfigManager;
+import com.android.internal.telephony.data.DataNetworkController;
+import com.android.internal.telephony.metrics.MetricsCollector;
+import com.android.internal.telephony.metrics.PersistAtomsStorage;
+import com.android.phone.PhoneGlobals;
+import com.android.phone.PhoneInterfaceManager;
 
 import org.junit.After;
 import org.junit.Before;
 import org.junit.Rule;
+import org.mockito.Mock;
+import org.mockito.Mockito;
 import org.mockito.junit.MockitoJUnit;
 import org.mockito.junit.MockitoRule;
 
 import java.lang.reflect.Field;
+import java.util.Collections;
 import java.util.HashMap;
 import java.util.Iterator;
 import java.util.LinkedList;
@@ -39,31 +58,54 @@ import java.util.concurrent.Executor;
 import java.util.concurrent.TimeUnit;
 
 /**
- * Helper class to load Mockito Resources into a test.
+ * Helper class to load Mockito Resources into Telephony unit tests.
  */
 public class TelephonyTestBase {
     @Rule public final MockitoRule mocks = MockitoJUnit.rule();
 
     protected TestContext mContext;
+    @Mock protected PhoneGlobals mPhoneGlobals;
+    @Mock protected GsmCdmaPhone mPhone;
+    @Mock protected DataNetworkController mDataNetworkController;
+    @Mock private MetricsCollector mMetricsCollector;
 
     private final HashMap<InstanceKey, Object> mOldInstances = new HashMap<>();
     private final LinkedList<InstanceKey> mInstanceKeys = new LinkedList<>();
 
     @Before
     public void setUp() throws Exception {
-        mContext = spy(new TestContext());
-        // Set up the looper if it does not exist on the test thread.
         if (Looper.myLooper() == null) {
             Looper.prepare();
-            // Wait until the looper is not null anymore
-            for(int i = 0; i < 5; i++) {
-                if (Looper.myLooper() != null) {
-                    break;
-                }
-                Looper.prepare();
-                Thread.sleep(100);
-            }
         }
+
+        doCallRealMethod().when(mPhoneGlobals).getBaseContext();
+        doCallRealMethod().when(mPhoneGlobals).getResources();
+        doCallRealMethod().when(mPhone).getServiceState();
+
+        mContext = spy(new TestContext());
+        doReturn(mContext).when(mPhone).getContext();
+        replaceInstance(ContextWrapper.class, "mBase", mPhoneGlobals, mContext);
+
+        Resources resources = InstrumentationRegistry.getTargetContext().getResources();
+        assertNotNull(resources);
+        doReturn(resources).when(mContext).getResources();
+
+        replaceInstance(Handler.class, "mLooper", mPhone, Looper.myLooper());
+        replaceInstance(PhoneFactory.class, "sMadeDefaults", null, true);
+        replaceInstance(PhoneFactory.class, "sPhone", null, mPhone);
+        replaceInstance(PhoneFactory.class, "sPhones", null, new Phone[] {mPhone});
+        replaceInstance(PhoneGlobals.class, "sMe", null, mPhoneGlobals);
+        replaceInstance(PhoneFactory.class, "sMetricsCollector", null, mMetricsCollector);
+
+        doReturn(Mockito.mock(PersistAtomsStorage.class)).when(mMetricsCollector).getAtomsStorage();
+
+        doReturn(mDataNetworkController).when(mPhone).getDataNetworkController();
+        doReturn(Collections.emptyList()).when(mDataNetworkController)
+                .getInternetDataDisallowedReasons();
+        doReturn(Mockito.mock(DataConfigManager.class)).when(mDataNetworkController)
+                .getDataConfigManager();
+
+        mPhoneGlobals.phoneMgr = Mockito.mock(PhoneInterfaceManager.class);
     }
 
     @After
diff --git a/tests/src/com/android/TestContext.java b/tests/src/com/android/TestContext.java
index e464ad554..bf7832abc 100644
--- a/tests/src/com/android/TestContext.java
+++ b/tests/src/com/android/TestContext.java
@@ -21,13 +21,18 @@ import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.when;
 
+import android.annotation.NonNull;
+import android.annotation.Nullable;
 import android.content.AttributionSource;
 import android.content.BroadcastReceiver;
 import android.content.ContentResolver;
 import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
+import android.content.ServiceConnection;
 import android.content.pm.PackageManager;
+import android.content.res.AssetManager;
+import android.content.res.Resources;
 import android.os.Binder;
 import android.os.Handler;
 import android.os.Looper;
@@ -44,7 +49,10 @@ import android.test.mock.MockContext;
 import android.util.Log;
 import android.util.SparseArray;
 
+import androidx.test.InstrumentationRegistry;
+
 import org.mockito.Mock;
+import org.mockito.Mockito;
 import org.mockito.MockitoAnnotations;
 import org.mockito.stubbing.Answer;
 
@@ -86,6 +94,11 @@ public class TestContext extends MockContext {
         when(mPackageManager.hasSystemFeature(anyString())).thenReturn(true);
     }
 
+    @Override
+    public AssetManager getAssets() {
+        return Mockito.mock(AssetManager.class);
+    }
+
     @Override
     public Executor getMainExecutor() {
         // Just run on current thread
@@ -97,11 +110,21 @@ public class TestContext extends MockContext {
         return this;
     }
 
+    @Override
+    public @NonNull Context createAttributionContext(@Nullable String attributionTag) {
+        return this;
+    }
+
     @Override
     public String getPackageName() {
         return "com.android.phone.tests";
     }
 
+    @Override
+    public String getOpPackageName() {
+        return getPackageName();
+    }
+
     @Override
     public String getAttributionTag() {
         return "";
@@ -211,11 +234,21 @@ public class TestContext extends MockContext {
         return null;
     }
 
+    @Override
+    public Looper getMainLooper() {
+        return Looper.getMainLooper();
+    }
+
     @Override
     public Handler getMainThreadHandler() {
         return new Handler(Looper.getMainLooper());
     }
 
+    @Override
+    public Resources.Theme getTheme() {
+        return InstrumentationRegistry.getTargetContext().getTheme();
+    }
+
     /**
      * @return CarrierConfig PersistableBundle for the subscription specified.
      */
@@ -264,6 +297,11 @@ public class TestContext extends MockContext {
         }
     }
 
+    @Override
+    public void unbindService(ServiceConnection conn) {
+        // Override the base implementation to ensure we don't crash.
+    }
+
     public void grantPermission(String permission) {
         synchronized (mPermissionTable) {
             if (permission == null) return;
diff --git a/tests/src/com/android/phone/CarrierConfigLoaderTest.java b/tests/src/com/android/phone/CarrierConfigLoaderTest.java
index bda231379..5190b2150 100644
--- a/tests/src/com/android/phone/CarrierConfigLoaderTest.java
+++ b/tests/src/com/android/phone/CarrierConfigLoaderTest.java
@@ -41,7 +41,6 @@ import android.content.pm.PackageManager;
 import android.content.res.Resources;
 import android.os.Build;
 import android.os.Handler;
-import android.os.HandlerThread;
 import android.os.PermissionEnforcer;
 import android.os.PersistableBundle;
 import android.os.UserHandle;
@@ -51,10 +50,10 @@ import android.telephony.CarrierConfigManager;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
 import android.telephony.TelephonyRegistryManager;
+import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
 
 import androidx.test.InstrumentationRegistry;
-import androidx.test.ext.junit.runners.AndroidJUnit4;
 
 import com.android.TelephonyTestBase;
 import com.android.internal.telephony.IccCardConstants;
@@ -72,7 +71,6 @@ import org.junit.rules.TestRule;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
 import org.mockito.Mockito;
-import org.mockito.MockitoAnnotations;
 
 import java.io.FileDescriptor;
 import java.io.PrintWriter;
@@ -81,7 +79,8 @@ import java.io.StringWriter;
 /**
  * Unit Test for CarrierConfigLoader.
  */
-@RunWith(AndroidJUnit4.class)
+@RunWith(AndroidTestingRunner.class)
+@TestableLooper.RunWithLooper(setAsMainLooper = true)
 public class CarrierConfigLoaderTest extends TelephonyTestBase {
     @Rule
     public TestRule compatChangeRule = new PlatformCompatChangeRule();
@@ -108,7 +107,6 @@ public class CarrierConfigLoaderTest extends TelephonyTestBase {
     private TelephonyManager mTelephonyManager;
     private CarrierConfigLoader mCarrierConfigLoader;
     private Handler mHandler;
-    private HandlerThread mHandlerThread;
     private TestableLooper mTestableLooper;
 
     // The AIDL stub will use PermissionEnforcer to check permission from the caller.
@@ -117,7 +115,6 @@ public class CarrierConfigLoaderTest extends TelephonyTestBase {
     @Before
     public void setUp() throws Exception {
         super.setUp();
-        MockitoAnnotations.initMocks(this);
         doReturn(Context.PERMISSION_ENFORCER_SERVICE).when(mContext).getSystemServiceName(
                 eq(PermissionEnforcer.class));
         doReturn(mFakePermissionEnforcer).when(mContext).getSystemService(
@@ -151,10 +148,7 @@ public class CarrierConfigLoaderTest extends TelephonyTestBase {
         when(mContext.getSystemService(TelephonyRegistryManager.class)).thenReturn(
                 mTelephonyRegistryManager);
 
-        mHandlerThread = new HandlerThread("CarrierConfigLoaderTest");
-        mHandlerThread.start();
-
-        mTestableLooper = new TestableLooper(mHandlerThread.getLooper());
+        mTestableLooper = TestableLooper.get(this);
         mCarrierConfigLoader = new CarrierConfigLoader(mContext, mTestableLooper.getLooper(),
                 mFeatureFlags);
         mHandler = mCarrierConfigLoader.getHandler();
@@ -169,8 +163,6 @@ public class CarrierConfigLoaderTest extends TelephonyTestBase {
         mFakePermissionEnforcer.revoke(android.Manifest.permission.DUMP);
         mFakePermissionEnforcer.revoke(android.Manifest.permission.MODIFY_PHONE_STATE);
         mFakePermissionEnforcer.revoke(android.Manifest.permission.READ_PRIVILEGED_PHONE_STATE);
-        mTestableLooper.destroy();
-        mHandlerThread.quit();
         super.tearDown();
     }
 
diff --git a/tests/src/com/android/phone/ImsStateCallbackControllerTest.java b/tests/src/com/android/phone/ImsStateCallbackControllerTest.java
index 0e902a8ea..5521ac0b1 100644
--- a/tests/src/com/android/phone/ImsStateCallbackControllerTest.java
+++ b/tests/src/com/android/phone/ImsStateCallbackControllerTest.java
@@ -46,7 +46,6 @@ import android.content.Context;
 import android.os.Handler;
 import android.os.HandlerThread;
 import android.os.IBinder;
-import android.os.Looper;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyRegistryManager;
 import android.testing.TestableLooper;
@@ -70,7 +69,6 @@ import org.junit.Test;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Captor;
 import org.mockito.Mock;
-import org.mockito.MockitoAnnotations;
 import org.mockito.invocation.InvocationOnMock;
 import org.mockito.stubbing.Answer;
 
@@ -110,7 +108,6 @@ public class ImsStateCallbackControllerTest extends TelephonyTestBase {
     @Captor ArgumentCaptor<FeatureConnector.Listener<ImsManager>> mMmTelConnectorListenerSlot1;
     @Captor ArgumentCaptor<FeatureConnector.Listener<RcsFeatureManager>> mRcsConnectorListenerSlot0;
     @Captor ArgumentCaptor<FeatureConnector.Listener<RcsFeatureManager>> mRcsConnectorListenerSlot1;
-    @Mock private PhoneGlobals mPhone;
     @Mock ImsStateCallbackController.PhoneFactoryProxy mPhoneFactoryProxy;
     @Mock Phone mPhoneSlot0;
     @Mock Phone mPhoneSlot1;
@@ -134,16 +131,16 @@ public class ImsStateCallbackControllerTest extends TelephonyTestBase {
 
     @Before
     public void setUp() throws Exception {
-        MockitoAnnotations.initMocks(this);
+        super.setUp();
 
-        when(mPhone.getMainExecutor()).thenReturn(mExecutor);
-        when(mPhone.getSystemServiceName(eq(SubscriptionManager.class)))
+        when(mPhoneGlobals.getMainExecutor()).thenReturn(mExecutor);
+        when(mPhoneGlobals.getSystemServiceName(eq(SubscriptionManager.class)))
                 .thenReturn(Context.TELEPHONY_SUBSCRIPTION_SERVICE);
-        when(mPhone.getSystemService(eq(Context.TELEPHONY_SUBSCRIPTION_SERVICE)))
+        when(mPhoneGlobals.getSystemService(eq(Context.TELEPHONY_SUBSCRIPTION_SERVICE)))
                 .thenReturn(mSubscriptionManager);
-        when(mPhone.getSystemServiceName(eq(TelephonyRegistryManager.class)))
+        when(mPhoneGlobals.getSystemServiceName(eq(TelephonyRegistryManager.class)))
                 .thenReturn(Context.TELEPHONY_REGISTRY_SERVICE);
-        when(mPhone.getSystemService(eq(Context.TELEPHONY_REGISTRY_SERVICE)))
+        when(mPhoneGlobals.getSystemService(eq(Context.TELEPHONY_REGISTRY_SERVICE)))
                 .thenReturn(mTelephonyRegistryManager);
         when(mPhoneFactoryProxy.getPhone(eq(0))).thenReturn(mPhoneSlot0);
         when(mPhoneFactoryProxy.getPhone(eq(1))).thenReturn(mPhoneSlot1);
@@ -937,9 +934,6 @@ public class ImsStateCallbackControllerTest extends TelephonyTestBase {
     }
 
     private void createController(int slotCount) throws Exception {
-        if (Looper.myLooper() == null) {
-            Looper.prepare();
-        }
         makeFakeActiveSubIds(slotCount);
 
         when(mMmTelFeatureFactory
@@ -956,7 +950,7 @@ public class ImsStateCallbackControllerTest extends TelephonyTestBase {
                 .thenReturn(mRcsFeatureConnectorSlot1);
 
         mImsStateCallbackController =
-                new ImsStateCallbackController(mPhone, mHandlerThread.getLooper(),
+                new ImsStateCallbackController(mPhoneGlobals, mHandlerThread.getLooper(),
                         slotCount, mMmTelFeatureFactory, mRcsFeatureFactory, mImsResolver,
                         mFeatureFlags);
 
diff --git a/tests/src/com/android/phone/LocationAccessPolicyTest.java b/tests/src/com/android/phone/LocationAccessPolicyTest.java
index 58e7fbdc6..551c2cbc8 100644
--- a/tests/src/com/android/phone/LocationAccessPolicyTest.java
+++ b/tests/src/com/android/phone/LocationAccessPolicyTest.java
@@ -225,6 +225,8 @@ public class LocationAccessPolicyTest {
         try {
             when(mPackageManager.getApplicationInfo(anyString(), anyInt()))
                     .thenReturn(fakeAppInfo);
+            when(mPackageManager.getApplicationInfoAsUser(anyString(), anyInt(),
+                    any(UserHandle.class))).thenReturn(fakeAppInfo);
         } catch (Exception e) {
             // this is a formality
         }
diff --git a/tests/src/com/android/phone/NotificationMgrTest.java b/tests/src/com/android/phone/NotificationMgrTest.java
index 98c6a4a23..0c1f8a3ea 100644
--- a/tests/src/com/android/phone/NotificationMgrTest.java
+++ b/tests/src/com/android/phone/NotificationMgrTest.java
@@ -59,6 +59,7 @@ import android.content.SharedPreferences;
 import android.content.pm.ApplicationInfo;
 import android.content.res.Resources;
 import android.os.Build;
+import android.os.ParcelUuid;
 import android.os.PersistableBundle;
 import android.os.SystemClock;
 import android.os.UserHandle;
@@ -76,11 +77,8 @@ import android.testing.TestableLooper;
 import com.android.TelephonyTestBase;
 import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.PhoneConstants;
-import com.android.internal.telephony.PhoneFactory;
 import com.android.internal.telephony.ServiceStateTracker;
 import com.android.internal.telephony.SignalStrengthController;
-import com.android.internal.telephony.data.DataConfigManager;
-import com.android.internal.telephony.data.DataNetworkController;
 import com.android.internal.telephony.data.DataSettingsManager;
 import com.android.internal.telephony.util.NotificationChannelController;
 
@@ -89,9 +87,7 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
-import org.mockito.MockitoAnnotations;
 
-import java.util.Collections;
 import java.util.concurrent.TimeUnit;
 
 /**
@@ -110,13 +106,12 @@ public class NotificationMgrTest extends TelephonyTestBase {
     private static final String MOBILE_NETWORK_SELECTION_CLASS = ".testClass";
     private static final String CARRIER_NAME = "CoolCarrier";
 
-    @Mock PhoneGlobals mApp;
+    PhoneGlobals mApp; // mPhoneGlobals alias
     @Mock StatusBarManager mStatusBarManager;
     @Mock UserManager mUserManager;
     @Mock SubscriptionManager mSubscriptionManager;
     @Mock TelecomManager mTelecomManager;
     @Mock TelephonyManager mTelephonyManager;
-    @Mock Phone mPhone;
     @Mock SharedPreferences mSharedPreferences;
     @Mock NotificationManager mNotificationManager;
     @Mock SubscriptionInfo mSubscriptionInfo;
@@ -125,20 +120,16 @@ public class NotificationMgrTest extends TelephonyTestBase {
     @Mock ServiceStateTracker mServiceStateTracker;
     @Mock ServiceState mServiceState;
     @Mock CarrierConfigManager mCarrierConfigManager;
-    @Mock DataNetworkController mDataNetworkController;
     @Mock DataSettingsManager mDataSettingsManager;
-    @Mock DataConfigManager mDataConfigManager;
     @Mock SignalStrengthController mSignalStrengthController;
 
-    private Phone[] mPhones;
     private NotificationMgr mNotificationMgr;
     private TestableLooper mTestableLooper;
 
     @Before
     public void setUp() throws Exception {
-        MockitoAnnotations.initMocks(this);
-        mPhones = new Phone[]{mPhone};
-        replaceInstance(PhoneFactory.class, "sPhones", null, mPhones);
+        super.setUp();
+        mApp = mPhoneGlobals;
         when(mPhone.getPhoneType()).thenReturn(PhoneConstants.PHONE_TYPE_GSM);
         when(mPhone.getContext()).thenReturn(mMockedContext);
         when(mMockedContext.getResources()).thenReturn(mResources);
@@ -151,10 +142,6 @@ public class NotificationMgrTest extends TelephonyTestBase {
         when(mPhone.getServiceStateTracker()).thenReturn(mServiceStateTracker);
         mServiceStateTracker.mSS = mServiceState;
         when(mPhone.getSignalStrengthController()).thenReturn(mSignalStrengthController);
-        when(mPhone.getDataNetworkController()).thenReturn(mDataNetworkController);
-        when(mDataNetworkController.getInternetDataDisallowedReasons()).thenReturn(
-                Collections.emptyList());
-        when(mDataNetworkController.getDataConfigManager()).thenReturn(mDataConfigManager);
         when(mPhone.getDataSettingsManager()).thenReturn(mDataSettingsManager);
         when(mDataSettingsManager.isDataEnabledForReason(anyInt())).thenReturn(true);
         when(mApp.getSharedPreferences(anyString(), anyInt())).thenReturn(mSharedPreferences);
@@ -408,6 +395,35 @@ public class NotificationMgrTest extends TelephonyTestBase {
         verify(mNotificationManager, never()).notify(any(), anyInt(), any());
     }
 
+    @Test
+    public void testUpdateNetworkSelection_opportunisticSubscription_notificationNotSent()
+            throws Exception {
+        prepareResourcesForNetworkSelection();
+        when(mSubscriptionManager.getActiveSubscriptionInfo(eq(TEST_SUB_ID))).thenReturn(
+                mSubscriptionInfo);
+
+        when(mTelephonyManager.isManualNetworkSelectionAllowed()).thenReturn(true);
+        PersistableBundle config = new PersistableBundle();
+        config.putBoolean(CarrierConfigManager.KEY_OPERATOR_SELECTION_EXPAND_BOOL, true);
+        config.putBoolean(CarrierConfigManager.KEY_HIDE_CARRIER_NETWORK_SETTINGS_BOOL, false);
+        config.putBoolean(CarrierConfigManager.KEY_CSP_ENABLED_BOOL, false);
+        config.putBoolean(CarrierConfigManager.KEY_WORLD_PHONE_BOOL, true);
+        when(mCarrierConfigManager.getConfigForSubId(TEST_SUB_ID)).thenReturn(config);
+
+        when(mSubscriptionInfo.isOpportunistic()).thenReturn(true);
+        when(mSubscriptionInfo.getGroupUuid()).thenReturn(
+                ParcelUuid.fromString("5be5c5f3-3412-452e-86a0-6f18558ae8c8"));
+
+        mNotificationMgr.updateNetworkSelection(ServiceState.STATE_OUT_OF_SERVICE, TEST_SUB_ID);
+        try {
+            Thread.sleep(10000);
+        } catch (InterruptedException ignored) {
+        }
+        mNotificationMgr.updateNetworkSelection(ServiceState.STATE_OUT_OF_SERVICE, TEST_SUB_ID);
+
+        verify(mNotificationManager, never()).notify(any(), anyInt(), any());
+    }
+
     @Test
     public void testUpdateNetworkSelection_worldMode_userSetLTE_notificationNotSent() {
         prepareResourcesForNetworkSelection();
@@ -632,6 +648,8 @@ public class NotificationMgrTest extends TelephonyTestBase {
         when(mApp.getString(R.string.mobile_network_settings_class)).thenReturn(
                 MOBILE_NETWORK_SELECTION_CLASS);
         when(mSubscriptionManager.isActiveSubId(anyInt())).thenReturn(true);
+        when(mSubscriptionManager.getActiveSubscriptionInfo(eq(TEST_SUB_ID))).thenReturn(
+                mSubscriptionInfo);
     }
 
     private void moveTimeForward(long seconds) {
diff --git a/tests/src/com/android/phone/PhoneInterfaceManagerTest.java b/tests/src/com/android/phone/PhoneInterfaceManagerTest.java
index 7464ba2fa..ef6a02a72 100644
--- a/tests/src/com/android/phone/PhoneInterfaceManagerTest.java
+++ b/tests/src/com/android/phone/PhoneInterfaceManagerTest.java
@@ -20,7 +20,6 @@ import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
-import static org.junit.Assert.fail;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyString;
@@ -45,11 +44,14 @@ import android.os.Build;
 import android.os.UserHandle;
 import android.permission.flags.Flags;
 import android.platform.test.flag.junit.SetFlagsRule;
+import android.preference.PreferenceManager;
 import android.telephony.RadioAccessFamily;
 import android.telephony.TelephonyManager;
+import android.testing.AndroidTestingRunner;
+import android.testing.TestableLooper;
 
 import androidx.test.annotation.UiThreadTest;
-import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.platform.app.InstrumentationRegistry;
 
 import com.android.TelephonyTestBase;
 import com.android.internal.telephony.IIntegerConsumer;
@@ -57,6 +59,7 @@ import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.RILConstants;
 import com.android.internal.telephony.flags.FeatureFlags;
 import com.android.internal.telephony.subscription.SubscriptionManagerService;
+import com.android.phone.satellite.accesscontrol.SatelliteAccessController;
 
 import libcore.junit.util.compat.CoreCompatChangeRule.EnableCompatChanges;
 
@@ -66,6 +69,7 @@ import org.junit.Test;
 import org.junit.rules.TestRule;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
+import org.mockito.Mockito;
 
 import java.lang.reflect.Field;
 import java.lang.reflect.Modifier;
@@ -75,19 +79,18 @@ import java.util.Locale;
 /**
  * Unit Test for PhoneInterfaceManager.
  */
-@RunWith(AndroidJUnit4.class)
+@RunWith(AndroidTestingRunner.class)
+@TestableLooper.RunWithLooper(setAsMainLooper = true)
 public class PhoneInterfaceManagerTest extends TelephonyTestBase {
     @Rule
     public TestRule compatChangeRule = new PlatformCompatChangeRule();
 
     private PhoneInterfaceManager mPhoneInterfaceManager;
     private SharedPreferences mSharedPreferences;
-    private IIntegerConsumer mIIntegerConsumer;
+    @Mock private IIntegerConsumer mIIntegerConsumer;
     private static final String sDebugPackageName =
             PhoneInterfaceManagerTest.class.getPackageName();
 
-    @Mock
-    PhoneGlobals mPhoneGlobals;
     @Mock
     Phone mPhone;
     @Mock
@@ -108,6 +111,18 @@ public class PhoneInterfaceManagerTest extends TelephonyTestBase {
         super.setUp();
         doReturn(sDebugPackageName).when(mPhoneGlobals).getOpPackageName();
 
+        replaceInstance(SatelliteAccessController.class, "sInstance", null,
+                Mockito.mock(SatelliteAccessController.class));
+
+        mSharedPreferences = PreferenceManager.getDefaultSharedPreferences(
+                InstrumentationRegistry.getInstrumentation().getTargetContext());
+        doReturn(mSharedPreferences).when(mPhoneGlobals)
+                .getSharedPreferences(anyString(), anyInt());
+        mSharedPreferences.edit().remove(Phone.PREF_NULL_CIPHER_AND_INTEGRITY_ENABLED).commit();
+        mSharedPreferences.edit().remove(Phone.PREF_NULL_CIPHER_NOTIFICATIONS_ENABLED).commit();
+
+        // Trigger sInstance restore in tearDown, after PhoneInterfaceManager.init.
+        replaceInstance(PhoneInterfaceManager.class, "sInstance", null, null);
         // Note that PhoneInterfaceManager is a singleton. Calling init gives us a handle to the
         // global singleton, but the context that is passed in is unused if the phone app is already
         // alive on a test devices. You must use the spy to mock behavior. Mocks stemming from the
@@ -119,10 +134,6 @@ public class PhoneInterfaceManagerTest extends TelephonyTestBase {
         doReturn(mSubscriptionManagerService).when(mPhoneInterfaceManager)
                 .getSubscriptionManagerService();
         TelephonyManager.setupISubForTest(mSubscriptionManagerService);
-        mSharedPreferences = mPhoneInterfaceManager.getSharedPreferences();
-        mSharedPreferences.edit().remove(Phone.PREF_NULL_CIPHER_AND_INTEGRITY_ENABLED).commit();
-        mSharedPreferences.edit().remove(Phone.PREF_NULL_CIPHER_NOTIFICATIONS_ENABLED).commit();
-        mIIntegerConsumer = mock(IIntegerConsumer.class);
 
         // In order not to affect the existing implementation, define a telephony features
         // and disabled enforce_telephony_feature_mapping_for_public_apis feature flag
@@ -130,7 +141,9 @@ public class PhoneInterfaceManagerTest extends TelephonyTestBase {
         doReturn(false).when(mFeatureFlags).enforceTelephonyFeatureMappingForPublicApis();
         doReturn(true).when(mFeatureFlags).hsumPackageManager();
         mPhoneInterfaceManager.setPackageManager(mPackageManager);
+        doReturn(mPackageManager).when(mPhoneGlobals).getPackageManager();
         doReturn(true).when(mPackageManager).hasSystemFeature(anyString());
+        doReturn(new String[]{sDebugPackageName}).when(mPackageManager).getPackagesForUid(anyInt());
 
         mPhoneInterfaceManager.setAppOpsManager(mAppOps);
     }
@@ -491,15 +504,11 @@ public class PhoneInterfaceManagerTest extends TelephonyTestBase {
         mPhoneInterfaceManager.setFeatureFlags(mFeatureFlags);
         doNothing().when(mPhoneInterfaceManager).enforceModifyPermission();
 
-        try {
-            // FEATURE_TELEPHONY_CALLING
-            mPhoneInterfaceManager.handlePinMmiForSubscriber(1, "123456789");
+        // FEATURE_TELEPHONY_CALLING
+        mPhoneInterfaceManager.getVoiceActivationState(1, "com.test.package");
 
-            // FEATURE_TELEPHONY_RADIO_ACCESS
-            mPhoneInterfaceManager.toggleRadioOnOffForSubscriber(1);
-        } catch (Exception e) {
-            fail("Not expect exception " + e.getMessage());
-        }
+        // FEATURE_TELEPHONY_RADIO_ACCESS
+        mPhoneInterfaceManager.toggleRadioOnOffForSubscriber(1);
     }
 
     @Test
diff --git a/tests/src/com/android/phone/PhoneUtilsTest.java b/tests/src/com/android/phone/PhoneUtilsTest.java
index 3d7815cac..2d3d06533 100644
--- a/tests/src/com/android/phone/PhoneUtilsTest.java
+++ b/tests/src/com/android/phone/PhoneUtilsTest.java
@@ -30,15 +30,11 @@ import android.telephony.SubscriptionManager;
 import androidx.test.runner.AndroidJUnit4;
 
 import com.android.TelephonyTestBase;
-import com.android.internal.telephony.GsmCdmaPhone;
-import com.android.internal.telephony.Phone;
-import com.android.internal.telephony.PhoneFactory;
 
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
-import org.mockito.MockitoAnnotations;
 
 @RunWith(AndroidJUnit4.class)
 public class PhoneUtilsTest extends TelephonyTestBase {
@@ -46,8 +42,6 @@ public class PhoneUtilsTest extends TelephonyTestBase {
     private SubscriptionManager mMockSubscriptionManager;
     @Mock
     private SubscriptionInfo mMockSubscriptionInfo;
-    @Mock
-    private GsmCdmaPhone mMockPhone;
 
     private final int mPhoneAccountHandleIdInteger = 123;
     private final String mPhoneAccountHandleIdString = "123";
@@ -58,12 +52,10 @@ public class PhoneUtilsTest extends TelephonyTestBase {
 
     @Before
     public void setUp() throws Exception {
-        MockitoAnnotations.initMocks(this);
+        super.setUp();
         when(mMockSubscriptionManager.getActiveSubscriptionInfo(
                 eq(mPhoneAccountHandleIdInteger))).thenReturn(mMockSubscriptionInfo);
-        when(mMockPhone.getSubId()).thenReturn(mPhoneAccountHandleIdInteger);
-        Phone[] mPhones = new Phone[] {mMockPhone};
-        replaceInstance(PhoneFactory.class, "sPhones", null, mPhones);
+        when(mPhone.getSubId()).thenReturn(mPhoneAccountHandleIdInteger);
     }
 
     @Test
@@ -74,7 +66,7 @@ public class PhoneUtilsTest extends TelephonyTestBase {
 
     @Test
     public void testGetPhoneForPhoneAccountHandle() throws Exception {
-        assertEquals(mMockPhone, PhoneUtils.getPhoneForPhoneAccountHandle(
+        assertEquals(mPhone, PhoneUtils.getPhoneForPhoneAccountHandle(
                 mPhoneAccountHandleTest));
     }
 
diff --git a/tests/src/com/android/phone/euicc/EuiccUiDispatcherActivityTest.java b/tests/src/com/android/phone/euicc/EuiccUiDispatcherActivityTest.java
index 817220cda..1bd118a56 100644
--- a/tests/src/com/android/phone/euicc/EuiccUiDispatcherActivityTest.java
+++ b/tests/src/com/android/phone/euicc/EuiccUiDispatcherActivityTest.java
@@ -24,6 +24,7 @@ import android.content.Context;
 import android.content.Intent;
 import android.content.pm.ActivityInfo;
 import android.service.euicc.EuiccService;
+import android.telephony.TelephonyManager;
 import android.telephony.euicc.EuiccManager;
 
 import androidx.test.InstrumentationRegistry;
@@ -50,6 +51,7 @@ public class EuiccUiDispatcherActivityTest {
 
     @Mock private Context mMockContext;
     @Mock private EuiccManager mMockEuiccManager;
+    @Mock private TelephonyManager mTelephonyManager;
     private ActivityInfo mActivityInfo = ACTIVITY_INFO;
     private Intent mIntent = MANAGE_INTENT;
     private EuiccUiDispatcherActivity mActivity;
@@ -59,6 +61,8 @@ public class EuiccUiDispatcherActivityTest {
         MockitoAnnotations.initMocks(this);
         when(mMockEuiccManager.isEnabled()).thenReturn(true);
         when(mMockContext.getSystemService(Context.EUICC_SERVICE)).thenReturn(mMockEuiccManager);
+        when(mMockContext.getSystemService(Context.TELEPHONY_SERVICE))
+                .thenReturn(mTelephonyManager);
         InstrumentationRegistry.getInstrumentation().runOnMainSync(
                 new Runnable() {
                     @Override
diff --git a/tests/src/com/android/phone/satellite/accesscontrol/S2RangeSatelliteOnDeviceAccessControllerTest.java b/tests/src/com/android/phone/satellite/accesscontrol/S2RangeSatelliteOnDeviceAccessControllerTest.java
index 16a256d58..27f3ef7a8 100644
--- a/tests/src/com/android/phone/satellite/accesscontrol/S2RangeSatelliteOnDeviceAccessControllerTest.java
+++ b/tests/src/com/android/phone/satellite/accesscontrol/S2RangeSatelliteOnDeviceAccessControllerTest.java
@@ -16,13 +16,21 @@
 
 package com.android.phone.satellite.accesscontrol;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertThrows;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
+import static org.mockito.Mockito.doReturn;
+
+import android.annotation.Nullable;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 
-import com.android.storage.s2.S2LevelRange;
+import com.android.internal.telephony.flags.FeatureFlags;
 import com.android.telephony.sats2range.read.SatS2RangeFileFormat;
+import com.android.telephony.sats2range.read.SuffixTableRange;
 import com.android.telephony.sats2range.utils.TestUtils;
 import com.android.telephony.sats2range.write.SatS2RangeFileWriter;
 
@@ -33,6 +41,7 @@ import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
+import org.mockito.Mock;
 import org.mockito.MockitoAnnotations;
 
 import java.io.File;
@@ -44,6 +53,9 @@ import java.util.List;
 public class S2RangeSatelliteOnDeviceAccessControllerTest {
     private File mFile;
 
+    @Mock
+    private FeatureFlags mMockFeatureFlags;
+
     @Before
     public void setUp() throws Exception {
         MockitoAnnotations.initMocks(this);
@@ -60,18 +72,42 @@ public class S2RangeSatelliteOnDeviceAccessControllerTest {
 
     @Test
     public void testSatelliteAccessControl_AllowedList() throws Exception {
-        testSatelliteAccessControl(true);
+        testSatelliteAccessControl(true, null);
     }
 
     @Test
     public void testSatelliteAccessControl_DisallowedList() throws Exception {
-        testSatelliteAccessControl(false);
+        testSatelliteAccessControl(false, null);
+    }
+
+    @Test
+    public void testSatelliteAccessControl_AllowedList_validEntryValue() throws Exception {
+        testSatelliteAccessControl(true, 1);
+    }
+
+    @Test
+    public void testSatelliteAccessControl_DisallowedList_validEntryValue() {
+        assertThrows(IllegalArgumentException.class,
+                () -> testSatelliteAccessControl(false, 1));
     }
 
-    private void testSatelliteAccessControl(boolean isAllowedList) throws Exception {
+    private void testSatelliteAccessControl(boolean isAllowedList, @Nullable Integer entryValue)
+            throws Exception {
+        final int defaultEntryValue = -1;
+
+        if (!isAllowedList && entryValue != null) {
+            throw new IllegalArgumentException(
+                    "isAllowedList must be true when entryValue is present.");
+        }
+
+        List<Integer> expectedConfigIds = List.of(1, 1, 3);
         SatS2RangeFileFormat fileFormat = null;
         try {
-            fileFormat = createSatS2File(mFile, isAllowedList);
+            if (entryValue == null) {
+                fileFormat = createSatS2File(mFile, isAllowedList);
+            } else {
+                fileFormat = createSatS2FileWithEntryValue(mFile, isAllowedList, expectedConfigIds);
+            }
         } catch (Exception ex) {
             fail("Got unexpected exception in createSatS2File, ex=" + ex);
         }
@@ -79,8 +115,12 @@ public class S2RangeSatelliteOnDeviceAccessControllerTest {
         // Validate the output block file
         SatelliteOnDeviceAccessController accessController = null;
         try {
-            accessController = SatelliteOnDeviceAccessController.create(mFile);
+            accessController = SatelliteOnDeviceAccessController.create(mFile, mMockFeatureFlags);
             int s2Level = accessController.getS2Level();
+            if (entryValue == null) {
+                expectedConfigIds = List.of(defaultEntryValue, defaultEntryValue,
+                        defaultEntryValue);
+            }
 
             // Verify an edge cell of range 1 not in the output file
             S2CellId s2CellId = new S2CellId(TestUtils.createCellId(fileFormat, 1, 1000, 999));
@@ -88,9 +128,18 @@ public class S2RangeSatelliteOnDeviceAccessControllerTest {
             SatelliteOnDeviceAccessController.LocationToken locationToken =
                     SatelliteOnDeviceAccessController.createLocationTokenForLatLng(
                             s2LatLng.latDegrees(), s2LatLng.lngDegrees(), s2Level);
+
+            // Verify if the return value is null, when the carrierRoamingNbIotNtn is disabled.
+            doReturn(false).when(mMockFeatureFlags).carrierRoamingNbIotNtn();
+            assertNull(accessController.getRegionalConfigIdForLocation(locationToken));
+
+            doReturn(true).when(mMockFeatureFlags).carrierRoamingNbIotNtn();
             boolean isAllowed = accessController.isSatCommunicationAllowedAtLocation(locationToken);
             assertTrue(isAllowed != isAllowedList);
 
+            Integer configId = accessController.getRegionalConfigIdForLocation(locationToken);
+            assertNull(configId);
+
             // Verify cells in range1 present in the output file
             for (int suffix = 1000; suffix < 2000; suffix++) {
                 s2CellId = new S2CellId(TestUtils.createCellId(fileFormat, 1, 1000, suffix));
@@ -98,9 +147,13 @@ public class S2RangeSatelliteOnDeviceAccessControllerTest {
 
                 // Lookup using location token
                 locationToken = SatelliteOnDeviceAccessController.createLocationTokenForLatLng(
-                                s2LatLng.latDegrees(), s2LatLng.lngDegrees(), s2Level);
+                        s2LatLng.latDegrees(), s2LatLng.lngDegrees(), s2Level);
                 isAllowed = accessController.isSatCommunicationAllowedAtLocation(locationToken);
                 assertTrue(isAllowed == isAllowedList);
+
+                configId = accessController.getRegionalConfigIdForLocation(locationToken);
+                assertNotNull(configId);
+                assertEquals((int) expectedConfigIds.get(0), (int) configId);
             }
 
             // Verify the middle cell not in the output file
@@ -111,6 +164,10 @@ public class S2RangeSatelliteOnDeviceAccessControllerTest {
             isAllowed = accessController.isSatCommunicationAllowedAtLocation(locationToken);
             assertTrue(isAllowed != isAllowedList);
 
+            configId = accessController.getRegionalConfigIdForLocation(locationToken);
+            assertNull(configId);
+
+
             // Verify cells in range2 present in the output file
             for (int suffix = 2001; suffix < 3000; suffix++) {
                 s2CellId = new S2CellId(TestUtils.createCellId(fileFormat, 1, 1000, suffix));
@@ -119,6 +176,10 @@ public class S2RangeSatelliteOnDeviceAccessControllerTest {
                         s2LatLng.latDegrees(), s2LatLng.lngDegrees(), s2Level);
                 isAllowed = accessController.isSatCommunicationAllowedAtLocation(locationToken);
                 assertTrue(isAllowed == isAllowedList);
+
+                configId = accessController.getRegionalConfigIdForLocation(locationToken);
+                assertNotNull(configId);
+                assertEquals((int) expectedConfigIds.get(1), (int) configId);
             }
 
             // Verify an edge cell of range 2 not in the output file
@@ -129,6 +190,9 @@ public class S2RangeSatelliteOnDeviceAccessControllerTest {
             isAllowed = accessController.isSatCommunicationAllowedAtLocation(locationToken);
             assertTrue(isAllowed != isAllowedList);
 
+            configId = accessController.getRegionalConfigIdForLocation(locationToken);
+            assertNull(configId);
+
             // Verify an edge cell of range 3 not in the output file
             s2CellId = new S2CellId(TestUtils.createCellId(fileFormat, 1, 1001, 999));
             s2LatLng = s2CellId.toLatLng();
@@ -137,6 +201,9 @@ public class S2RangeSatelliteOnDeviceAccessControllerTest {
             isAllowed = accessController.isSatCommunicationAllowedAtLocation(locationToken);
             assertTrue(isAllowed != isAllowedList);
 
+            configId = accessController.getRegionalConfigIdForLocation(locationToken);
+            assertNull(configId);
+
             // Verify cells in range1 present in the output file
             for (int suffix = 1000; suffix < 2000; suffix++) {
                 s2CellId = new S2CellId(TestUtils.createCellId(fileFormat, 1, 1001, suffix));
@@ -145,6 +212,10 @@ public class S2RangeSatelliteOnDeviceAccessControllerTest {
                         s2LatLng.latDegrees(), s2LatLng.lngDegrees(), s2Level);
                 isAllowed = accessController.isSatCommunicationAllowedAtLocation(locationToken);
                 assertTrue(isAllowed == isAllowedList);
+
+                configId = accessController.getRegionalConfigIdForLocation(locationToken);
+                assertNotNull(configId);
+                assertEquals((int) expectedConfigIds.get(2), (int) configId);
             }
 
             // Verify an edge cell of range 3 not in the output file
@@ -154,6 +225,10 @@ public class S2RangeSatelliteOnDeviceAccessControllerTest {
                     s2LatLng.latDegrees(), s2LatLng.lngDegrees(), s2Level);
             isAllowed = accessController.isSatCommunicationAllowedAtLocation(locationToken);
             assertTrue(isAllowed != isAllowedList);
+
+            configId = accessController.getRegionalConfigIdForLocation(locationToken);
+            assertNull(configId);
+
         } catch (Exception ex) {
             fail("Unexpected exception when validating the output ex=" + ex);
         } finally {
@@ -163,27 +238,61 @@ public class S2RangeSatelliteOnDeviceAccessControllerTest {
         }
     }
 
-    private SatS2RangeFileFormat createSatS2File(
-            File file, boolean isAllowedList) throws Exception {
+    private SatS2RangeFileFormat createSatS2File(File file, boolean isAllowedList)
+            throws Exception {
         SatS2RangeFileFormat fileFormat;
-        S2LevelRange range1, range2, range3;
+        SuffixTableRange range1, range2, range3;
         try (SatS2RangeFileWriter satS2RangeFileWriter = SatS2RangeFileWriter.open(
                 file, TestUtils.createS2RangeFileFormat(isAllowedList))) {
             fileFormat = satS2RangeFileWriter.getFileFormat();
 
             // Two ranges that share a prefix.
-            range1 = new S2LevelRange(
+            range1 = new SuffixTableRange(
                     TestUtils.createCellId(fileFormat, 1, 1000, 1000),
                     TestUtils.createCellId(fileFormat, 1, 1000, 2000));
-            range2 = new S2LevelRange(
+            range2 = new SuffixTableRange(
                     TestUtils.createCellId(fileFormat, 1, 1000, 2001),
                     TestUtils.createCellId(fileFormat, 1, 1000, 3000));
             // This range has a different prefix, so will be in a different suffix table.
-            range3 = new S2LevelRange(
+            range3 = new SuffixTableRange(
                     TestUtils.createCellId(fileFormat, 1, 1001, 1000),
                     TestUtils.createCellId(fileFormat, 1, 1001, 2000));
 
-            List<S2LevelRange> ranges = new ArrayList<>();
+            List<SuffixTableRange> ranges = new ArrayList<>();
+            ranges.add(range1);
+            ranges.add(range2);
+            ranges.add(range3);
+            satS2RangeFileWriter.createSortedSuffixBlocks(ranges.iterator());
+        }
+        assertTrue(file.length() > 0);
+        return fileFormat;
+    }
+
+    private SatS2RangeFileFormat createSatS2FileWithEntryValue(
+            File file, boolean isAllowedList, List<Integer> entryValues) throws Exception {
+
+        SatS2RangeFileFormat fileFormat;
+        SuffixTableRange range1, range2, range3;
+        try (SatS2RangeFileWriter satS2RangeFileWriter = SatS2RangeFileWriter.open(
+                file, TestUtils.createS2RangeFileFormat(isAllowedList, 4, 1))) {
+            fileFormat = satS2RangeFileWriter.getFileFormat();
+
+            // Two ranges that share a prefix.
+            range1 = new SuffixTableRange(
+                    TestUtils.createCellId(fileFormat, 1, 1000, 1000),
+                    TestUtils.createCellId(fileFormat, 1, 1000, 2000),
+                    entryValues.get(0));
+            range2 = new SuffixTableRange(
+                    TestUtils.createCellId(fileFormat, 1, 1000, 2001),
+                    TestUtils.createCellId(fileFormat, 1, 1000, 3000),
+                    entryValues.get(1));
+            // This range has a different prefix, so will be in a different suffix table.
+            range3 = new SuffixTableRange(
+                    TestUtils.createCellId(fileFormat, 1, 1001, 1000),
+                    TestUtils.createCellId(fileFormat, 1, 1001, 2000),
+                    entryValues.get(2));
+
+            List<SuffixTableRange> ranges = new ArrayList<>();
             ranges.add(range1);
             ranges.add(range2);
             ranges.add(range3);
diff --git a/tests/src/com/android/phone/satellite/accesscontrol/SatelliteAccessConfigurationParserTest.java b/tests/src/com/android/phone/satellite/accesscontrol/SatelliteAccessConfigurationParserTest.java
new file mode 100644
index 000000000..72fb705da
--- /dev/null
+++ b/tests/src/com/android/phone/satellite/accesscontrol/SatelliteAccessConfigurationParserTest.java
@@ -0,0 +1,317 @@
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
+package com.android.phone.satellite.accesscontrol;
+
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessConfigurationParser.SATELLITE_ACCESS_CONTROL_CONFIGS;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessConfigurationParser.SATELLITE_CONFIG_ID;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessConfigurationParser.SATELLITE_INFOS;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessConfigurationParser.isRegionalConfigIdValid;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessConfigurationParser.parseSatelliteBandList;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessConfigurationParser.parseSatelliteEarfcnRangeList;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessConfigurationParser.parseSatelliteId;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessConfigurationParser.parseSatelliteInfoList;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessConfigurationParser.parseSatellitePosition;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessConfigurationParser.parseSatelliteTagIdList;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessConfigurationParser.readJsonStringFromFile;
+
+import static junit.framework.Assert.assertFalse;
+import static junit.framework.Assert.assertNotNull;
+import static junit.framework.Assert.assertTrue;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNull;
+
+import android.content.Context;
+import android.telephony.satellite.EarfcnRange;
+import android.telephony.satellite.SatelliteAccessConfiguration;
+import android.telephony.satellite.SatelliteInfo;
+import android.telephony.satellite.SatellitePosition;
+import android.util.Log;
+
+import androidx.annotation.NonNull;
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.platform.app.InstrumentationRegistry;
+
+import org.json.JSONArray;
+import org.json.JSONObject;
+import org.junit.After;
+import org.junit.AfterClass;
+import org.junit.Before;
+import org.junit.BeforeClass;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.MockitoAnnotations;
+
+import java.io.File;
+import java.io.FileOutputStream;
+import java.nio.charset.StandardCharsets;
+import java.util.ArrayList;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+import java.util.UUID;
+
+/** Unit test for {@link SatelliteAccessConfigurationParser} */
+@RunWith(AndroidJUnit4.class)
+public class SatelliteAccessConfigurationParserTest {
+    private static final String TAG = "SatelliteAccessConfigurationParserTest";
+
+    private static final String TEST_FILE_NAME = "test.json";
+    private static final String TEST_INVALID_FILE_NAME = "nonexistent_file.json";
+
+    private static final String TEST_SATELLITE_UUID1 = "5d0cc4f8-9223-4196-ad7a-803002db7af7";
+    private static final String TEST_SATELLITE_UUID2 = "0d30312e-a73f-444d-b99b-a893dfb42ee9";
+    private static final String TEST_SATELLITE_UUID3 = "01a0b0ca-11bc-4777-87ae-f39afbbec1e9";
+
+    private static final String VALID_JSON_STRING =
+            """
+            {
+             "access_control_configs": [
+               {
+                 "config_id": 123,
+                 "satellite_infos": [
+                   {
+                     "satellite_id": "5d0cc4f8-9223-4196-ad7a-803002db7af7",
+                     "satellite_position": {
+                       "longitude": 45.5,
+                       "altitude": 35786000
+                     },
+                     "bands": [
+                       1234,
+                       5678
+                     ],
+                     "earfcn_ranges": [
+                       {
+                         "start_earfcn": 1500,
+                         "end_earfcn": 1800
+                       }
+                     ]
+                   },
+                   {
+                     "satellite_id": "0d30312e-a73f-444d-b99b-a893dfb42ee9",
+                     "satellite_position": {
+                       "longitude": -120.3,
+                       "altitude": 35786000
+                     },
+                     "bands": [
+                       3456,
+                       7890
+                     ],
+                     "earfcn_ranges": [
+                       {
+                         "start_earfcn": 2000,
+                         "end_earfcn": 2300
+                       }
+                     ]
+                   }
+                 ],
+                 "tag_ids": [
+                   7,
+                   10
+                 ]
+               },
+               {
+                 "config_id": 890,
+                 "satellite_infos": [
+                   {
+                     "satellite_id": "01a0b0ca-11bc-4777-87ae-f39afbbec1e9",
+                     "satellite_position": {
+                       "longitude": -120,
+                       "altitude": 1234567
+                     },
+                     "bands": [
+                       13579,
+                       24680
+                     ],
+                     "earfcn_ranges": [
+                       {
+                         "start_earfcn": 6420,
+                         "end_earfcn": 15255
+                       }
+                     ]
+                   }
+                 ],
+                 "tag_ids": [
+                   6420,
+                   15255
+                 ]
+               }
+             ]
+             }
+            """;
+
+
+    // Mandatory : config_id ( >= 0)
+    // SatelliteInfoList : NonNull
+    // UUID (0-9, a-f and hyphen : '_' and 'z' are invalid)
+    // longitude (-180 ~ 180)
+    // altitude ( >= 0)
+    private static final String INVALID_JSON_STRING =
+            """
+            {
+              "access_control_configs": [
+                {
+                  "config_id": -100,
+                  "satellite_infos": [
+                    {
+                      "satellite_id": "01z0b0ca-11bc-4777_87ae-f39afbbec1e9",
+                      "satellite_position": {
+                        "longitude": -181,
+                        "altitude": -1
+                      },
+                      "earfcn_ranges": [
+                        {
+                          "start_earfcn": -1,
+                          "end_earfcn": 65536
+                        }
+                      ]
+                    }
+                  ]
+                }
+              ]
+            }
+            """;
+
+    @Before
+    public void setUp() throws Exception {
+        Log.d(TAG, "setUp");
+        MockitoAnnotations.initMocks(this);
+    }
+
+    @After
+    public void tearDown() throws Exception {
+        Log.d(TAG, "tearDown");
+    }
+
+    @AfterClass
+    public static void afterClass() throws Exception {
+    }
+
+    @BeforeClass
+    public static void beforeClass() throws Exception {
+    }
+
+    private static File createTestJsonFile(@NonNull String content) throws Exception {
+        Log.d(TAG, "createTestJsonFile");
+        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
+        File testFile = new File(context.getCacheDir(), TEST_FILE_NAME);
+        try (FileOutputStream fos = new FileOutputStream(testFile)) {
+            fos.write(content.getBytes(StandardCharsets.UTF_8));
+        }
+        return testFile;
+    }
+
+    @Test
+    public void testLoadJsonFile() throws Exception {
+        Log.d(TAG, "testLoadJsonFile");
+        assertNull(readJsonStringFromFile(TEST_INVALID_FILE_NAME));
+        assertNull(readJsonStringFromFile(null));
+
+        File file = createTestJsonFile(VALID_JSON_STRING);
+        assertEquals(VALID_JSON_STRING, readJsonStringFromFile(file.getPath()));
+
+        assertTrue(file.delete());
+    }
+
+
+    private SatelliteInfo getSatelliteInfo(UUID id, SatellitePosition position,
+            List<Integer> bandList, List<EarfcnRange> rangeList) {
+        return new SatelliteInfo(id, position, bandList, rangeList);
+    }
+
+    private Map<Integer, SatelliteAccessConfiguration> getExpectedMap() {
+        List<SatelliteInfo> satelliteInfoList1 = new ArrayList<>();
+        satelliteInfoList1.add(
+                getSatelliteInfo(UUID.fromString(TEST_SATELLITE_UUID1),
+                        new SatellitePosition(45.5, 35786000),
+                        List.of(1234, 5678),
+                        new ArrayList<>(List.of(new EarfcnRange(1500, 1800)))
+                ));
+        satelliteInfoList1.add(
+                getSatelliteInfo(UUID.fromString(TEST_SATELLITE_UUID2),
+                        new SatellitePosition(-120.3, 35786000),
+                        List.of(3456, 7890),
+                        new ArrayList<>(List.of(new EarfcnRange(2000, 2300)))
+                ));
+
+        List<Integer> tagIdList1 = List.of(7, 10);
+        SatelliteAccessConfiguration satelliteAccessConfiguration1 =
+                new SatelliteAccessConfiguration(satelliteInfoList1, tagIdList1);
+
+        HashMap<Integer, SatelliteAccessConfiguration> expectedResult = new HashMap<>();
+        expectedResult.put(123, satelliteAccessConfiguration1);
+
+        List<SatelliteInfo> satelliteInfoList2 = new ArrayList<>();
+        List<Integer> tagIdList2 = List.of(6420, 15255);
+        satelliteInfoList2.add(
+                getSatelliteInfo(UUID.fromString(TEST_SATELLITE_UUID3),
+                        new SatellitePosition(-120, 1234567),
+                        List.of(13579, 24680),
+                        new ArrayList<>(List.of(new EarfcnRange(6420, 15255)))
+                ));
+        SatelliteAccessConfiguration satelliteAccessConfiguration2 =
+                new SatelliteAccessConfiguration(satelliteInfoList2, tagIdList2);
+        expectedResult.put(890, satelliteAccessConfiguration2);
+        return expectedResult;
+    }
+
+
+    @Test
+    public void testParsingValidSatelliteAccessConfiguration() throws Exception {
+        Log.d(TAG, "testParsingValidSatelliteAccessConfiguration");
+        File file = createTestJsonFile(VALID_JSON_STRING);
+        assertEquals(getExpectedMap(),
+                SatelliteAccessConfigurationParser.parse(file.getCanonicalPath()));
+    }
+
+    @Test
+    public void testParsingInvalidSatelliteAccessConfiguration() throws Exception {
+        Log.d(TAG, "testParsingInvalidSatelliteAccessConfiguration");
+        File file = createTestJsonFile(INVALID_JSON_STRING);
+        String jsonString = readJsonStringFromFile(file.getCanonicalPath());
+        JSONObject satelliteAccessConfigJsonObject = new JSONObject(jsonString);
+        JSONArray configurationArrayJson = satelliteAccessConfigJsonObject.optJSONArray(
+                SATELLITE_ACCESS_CONTROL_CONFIGS);
+
+        for (int i = 0; i < configurationArrayJson.length(); i++) {
+            JSONObject configJson = configurationArrayJson.getJSONObject(i);
+
+            int configId = configJson.optInt(SATELLITE_CONFIG_ID, -1);
+            assertFalse(isRegionalConfigIdValid(configId));
+
+            JSONArray satelliteInfoArray = configJson.getJSONArray(SATELLITE_INFOS);
+            List<SatelliteInfo> satelliteInfoList = parseSatelliteInfoList(satelliteInfoArray);
+            assertNotNull(satelliteInfoList);
+            assertTrue(satelliteInfoList.isEmpty());
+
+            for (int j = 0; j < satelliteInfoArray.length(); j++) {
+                JSONObject infoJson = satelliteInfoArray.getJSONObject(i);
+                assertNull(parseSatelliteId(infoJson));
+                SatellitePosition satellitePosition = parseSatellitePosition(infoJson);
+                assertNotNull(satellitePosition);
+                assertTrue(Double.isNaN(satellitePosition.getLongitudeDegrees()));
+                assertTrue(Double.isNaN(satellitePosition.getAltitudeKm()));
+                assertTrue(parseSatelliteEarfcnRangeList(infoJson).isEmpty());
+                assertNotNull(parseSatelliteBandList(infoJson));
+                assertEquals(0, parseSatelliteBandList(infoJson).size());
+            }
+
+            List<Integer> tagIdList = parseSatelliteTagIdList(configJson);
+            assertNotNull(tagIdList);
+        }
+    }
+}
diff --git a/tests/src/com/android/phone/satellite/accesscontrol/SatelliteAccessControllerTest.java b/tests/src/com/android/phone/satellite/accesscontrol/SatelliteAccessControllerTest.java
index 55f72fc1f..3750dd18a 100644
--- a/tests/src/com/android/phone/satellite/accesscontrol/SatelliteAccessControllerTest.java
+++ b/tests/src/com/android/phone/satellite/accesscontrol/SatelliteAccessControllerTest.java
@@ -17,42 +17,56 @@
 package com.android.phone.satellite.accesscontrol;
 
 import static android.location.LocationManager.MODE_CHANGED_ACTION;
+import static android.telephony.SubscriptionManager.DEFAULT_SUBSCRIPTION_ID;
+import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_ACCESS_CONFIGURATION;
 import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_COMMUNICATION_ALLOWED;
 import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_PROVISIONED;
 import static android.telephony.satellite.SatelliteManager.KEY_SATELLITE_SUPPORTED;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_ACCESS_BARRED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_ERROR;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_LOCATION_DISABLED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_LOCATION_NOT_AVAILABLE;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_MODEM_ERROR;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_NOT_SUPPORTED;
+import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_NO_RESOURCES;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED;
 import static android.telephony.satellite.SatelliteManager.SATELLITE_RESULT_SUCCESS;
 
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.ALLOWED_STATE_CACHE_VALID_DURATION_NANOS;
-import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.EVENT_COUNTRY_CODE_CHANGED;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.CMD_IS_SATELLITE_COMMUNICATION_ALLOWED;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.DEFAULT_DELAY_MINUTES_BEFORE_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.DEFAULT_MAX_RETRY_COUNT_FOR_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.DEFAULT_REGIONAL_SATELLITE_CONFIG_ID;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.DEFAULT_S2_LEVEL;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.DEFAULT_THROTTLE_INTERVAL_FOR_LOCATION_QUERY_MINUTES;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.EVENT_CONFIG_DATA_UPDATED;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.EVENT_COUNTRY_CODE_CHANGED;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.EVENT_KEEP_ON_DEVICE_ACCESS_CONTROLLER_RESOURCES_TIMEOUT;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.EVENT_WAIT_FOR_CURRENT_LOCATION_TIMEOUT;
 import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.GOOGLE_US_SAN_SAT_S2_FILE_NAME;
-import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.DEFAULT_MAX_RETRY_COUNT_FOR_VALIDATING_POSSIBLE_CHANGE_IN_ALLOWED_REGION;
+import static com.android.phone.satellite.accesscontrol.SatelliteAccessController.UNKNOWN_REGIONAL_SATELLITE_CONFIG_ID;
 
+import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertSame;
 import static org.junit.Assert.assertTrue;
 import static org.junit.Assert.fail;
+import static org.junit.Assume.assumeTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyList;
 import static org.mockito.ArgumentMatchers.anyLong;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.ArgumentMatchers.nullable;
 import static org.mockito.Mockito.clearInvocations;
 import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.doThrow;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.spy;
@@ -61,33 +75,48 @@ import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.annotation.Nullable;
+import android.app.NotificationManager;
 import android.content.BroadcastReceiver;
 import android.content.Context;
 import android.content.Intent;
 import android.content.IntentFilter;
 import android.content.SharedPreferences;
+import android.content.pm.ApplicationInfo;
+import android.content.pm.PackageManager;
+import android.content.pm.ResolveInfo;
 import android.content.res.Resources;
 import android.location.Location;
 import android.location.LocationManager;
 import android.location.LocationRequest;
 import android.os.AsyncResult;
+import android.os.Build;
 import android.os.Bundle;
 import android.os.CancellationSignal;
 import android.os.DropBoxManager;
 import android.os.Handler;
-import android.os.HandlerThread;
+import android.os.IBinder;
 import android.os.Looper;
 import android.os.Message;
 import android.os.ResultReceiver;
+import android.os.UserHandle;
 import android.telecom.TelecomManager;
 import android.telephony.SubscriptionManager;
+import android.telephony.TelephonyManager;
+import android.telephony.satellite.EarfcnRange;
+import android.telephony.satellite.ISatelliteCommunicationAllowedStateCallback;
+import android.telephony.satellite.SatelliteAccessConfiguration;
+import android.telephony.satellite.SatelliteInfo;
 import android.telephony.satellite.SatelliteManager;
+import android.telephony.satellite.SatellitePosition;
+import android.telephony.satellite.SystemSelectionSpecifier;
+import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
 import android.util.Log;
 import android.util.Pair;
 
-import androidx.test.ext.junit.runners.AndroidJUnit4;
+import androidx.test.InstrumentationRegistry;
 
+import com.android.TelephonyTestBase;
 import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.PhoneFactory;
 import com.android.internal.telephony.TelephonyCountryDetector;
@@ -96,6 +125,7 @@ import com.android.internal.telephony.satellite.SatelliteConfig;
 import com.android.internal.telephony.satellite.SatelliteConfigParser;
 import com.android.internal.telephony.satellite.SatelliteController;
 import com.android.internal.telephony.satellite.SatelliteModemInterface;
+import com.android.internal.telephony.satellite.metrics.ControllerMetricsStats;
 
 import org.junit.After;
 import org.junit.Before;
@@ -104,10 +134,8 @@ import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Captor;
 import org.mockito.Mock;
-import org.mockito.MockitoAnnotations;
 
 import java.io.File;
-import java.lang.reflect.Field;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashMap;
@@ -115,14 +143,19 @@ import java.util.Iterator;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
+import java.util.UUID;
+import java.util.concurrent.ConcurrentHashMap;
 import java.util.concurrent.Executor;
 import java.util.concurrent.Semaphore;
 import java.util.concurrent.TimeUnit;
 import java.util.function.Consumer;
+import java.util.stream.Collectors;
+import java.util.stream.IntStream;
 
 /** Unit test for {@link SatelliteAccessController} */
-@RunWith(AndroidJUnit4.class)
-public class SatelliteAccessControllerTest {
+@RunWith(AndroidTestingRunner.class)
+@TestableLooper.RunWithLooper
+public class SatelliteAccessControllerTest extends TelephonyTestBase {
     private static final String TAG = "SatelliteAccessControllerTest";
     private static final String[] TEST_SATELLITE_COUNTRY_CODES = {"US", "CA", "UK"};
     private static final String[] TEST_SATELLITE_COUNTRY_CODES_EMPTY = {""};
@@ -156,8 +189,7 @@ public class SatelliteAccessControllerTest {
     private SatelliteModemInterface mMockSatelliteModemInterface;
     @Mock
     private DropBoxManager mMockDropBoxManager;
-    @Mock
-    private Context mMockContext;
+    private Context mMockContext;  // alias of mContext
     @Mock
     private Phone mMockPhone;
     @Mock
@@ -179,16 +211,32 @@ public class SatelliteAccessControllerTest {
     @Mock
     private SharedPreferences.Editor mMockSharedPreferencesEditor;
     @Mock
-    private Map<SatelliteOnDeviceAccessController.LocationToken, Boolean>
+    private Map<SatelliteOnDeviceAccessController.LocationToken, Integer>
             mMockCachedAccessRestrictionMap;
+    @Mock
+    HashMap<Integer, SatelliteAccessConfiguration> mMockSatelliteAccessConfigMap;
+
     @Mock
     private Intent mMockLocationIntent;
     @Mock
     private Set<ResultReceiver> mMockSatelliteAllowResultReceivers;
     @Mock
-    private ResultReceiver mMockSatelliteSupportedResultReceiver;
+    private TelephonyManager mMockTelephonyManager;
+    @Mock
+    private PackageManager mMockPackageManager;
+    @Mock
+    private List<ResolveInfo> mMockResolveInfoList;
+    @Mock
+    private NotificationManager mMockNotificationManager;
+    @Mock
+    private ApplicationInfo mMockApplicationInfo;
+    @Mock
+    private ResultReceiver mMockResultReceiver;
+    @Mock
+    private ConcurrentHashMap<IBinder, ISatelliteCommunicationAllowedStateCallback>
+            mSatelliteCommunicationAllowedStateCallbackMap;
+    private SatelliteInfo mSatelliteInfo;
 
-    private Looper mLooper;
     private TestableLooper mTestableLooper;
     private Phone[] mPhones;
     private TestSatelliteAccessController mSatelliteAccessControllerUT;
@@ -221,6 +269,8 @@ public class SatelliteAccessControllerTest {
     private ArgumentCaptor<Integer> mResultCodeIntCaptor;
     @Captor
     private ArgumentCaptor<Bundle> mResultDataBundleCaptor;
+    @Captor
+    private ArgumentCaptor<ISatelliteCommunicationAllowedStateCallback> mAllowedStateCallbackCaptor;
 
     private boolean mQueriedSatelliteAllowed = false;
     private int mQueriedSatelliteAllowedResultCode = SATELLITE_RESULT_SUCCESS;
@@ -249,19 +299,28 @@ public class SatelliteAccessControllerTest {
         }
     };
 
+    private int mQueriedSystemSelectionChannelUpdatedResultCode = SATELLITE_RESULT_SUCCESS;
+    private Semaphore mSystemSelectionChannelUpdatedSemaphore = new Semaphore(0);
+    private ResultReceiver mSystemSelectionChannelUpdatedReceiver = new ResultReceiver(null) {
+        @Override
+        protected void onReceiveResult(int resultCode, Bundle resultData) {
+            mQueriedSystemSelectionChannelUpdatedResultCode = resultCode;
+            try {
+                mSystemSelectionChannelUpdatedSemaphore.release();
+            } catch (Exception ex) {
+                fail("mSystemSelectionChannelUpdatedReceiver: Got exception in releasing "
+                        + "semaphore, ex="
+                        + ex);
+            }
+        }
+    };
+
     @Before
     public void setUp() throws Exception {
-        logd("setUp");
-        MockitoAnnotations.initMocks(this);
+        super.setUp();
 
-        if (Looper.myLooper() == null) {
-            Looper.prepare();
-        }
-
-        HandlerThread handlerThread = new HandlerThread("SatelliteAccessControllerTest");
-        handlerThread.start();
-        mLooper = handlerThread.getLooper();
-        mTestableLooper = new TestableLooper(mLooper);
+        mMockContext = mContext;
+        mTestableLooper = TestableLooper.get(this);
         when(mMockContext.getSystemServiceName(LocationManager.class)).thenReturn(
                 Context.LOCATION_SERVICE);
         when(mMockContext.getSystemServiceName(TelecomManager.class)).thenReturn(
@@ -274,6 +333,11 @@ public class SatelliteAccessControllerTest {
                 mMockTelecomManager);
         when(mMockContext.getSystemService(DropBoxManager.class)).thenReturn(
                 mMockDropBoxManager);
+        doAnswer(inv -> {
+            var args = inv.getArguments();
+            return InstrumentationRegistry.getTargetContext()
+                    .getDir((String) args[0], (Integer) args[1]);
+        }).when(mPhoneGlobals).getDir(anyString(), anyInt());
         mPhones = new Phone[]{mMockPhone, mMockPhone2};
         replaceInstance(PhoneFactory.class, "sPhones", null, mPhones);
         replaceInstance(SatelliteController.class, "sInstance", null,
@@ -282,8 +346,11 @@ public class SatelliteAccessControllerTest {
                 mMockSatelliteModemInterface);
         replaceInstance(TelephonyCountryDetector.class, "sInstance", null,
                 mMockCountryDetector);
+        replaceInstance(ControllerMetricsStats.class, "sInstance", null,
+                mock(ControllerMetricsStats.class));
         when(mMockSatelliteController.getSatellitePhone()).thenReturn(mMockPhone);
         when(mMockPhone.getSubId()).thenReturn(SubscriptionManager.getDefaultSubscriptionId());
+
         when(mMockContext.getResources()).thenReturn(mMockResources);
         when(mMockResources.getStringArray(
                 com.android.internal.R.array.config_oem_enabled_satellite_country_codes))
@@ -318,11 +385,12 @@ public class SatelliteAccessControllerTest {
         when(mMockLocation0.getLongitude()).thenReturn(0.0);
         when(mMockLocation1.getLatitude()).thenReturn(1.0);
         when(mMockLocation1.getLongitude()).thenReturn(1.0);
-        when(mMockSatelliteOnDeviceAccessController.isSatCommunicationAllowedAtLocation(
-                any(SatelliteOnDeviceAccessController.LocationToken.class))).thenReturn(true);
+        when(mMockSatelliteOnDeviceAccessController.getRegionalConfigIdForLocation(
+                any(SatelliteOnDeviceAccessController.LocationToken.class)))
+                .thenReturn(DEFAULT_REGIONAL_SATELLITE_CONFIG_ID);
 
-        when(mMockContext.getSharedPreferences(anyString(), anyInt())).thenReturn(
-                mMockSharedPreferences);
+        doReturn(mMockSharedPreferences).when(mMockContext)
+                .getSharedPreferences(anyString(), anyInt());
         when(mMockSharedPreferences.getBoolean(anyString(), anyBoolean())).thenReturn(true);
         when(mMockSharedPreferences.getStringSet(anyString(), any()))
                 .thenReturn(Set.of(TEST_SATELLITE_COUNTRY_CODES));
@@ -338,25 +406,40 @@ public class SatelliteAccessControllerTest {
         when(mMockFeatureFlags.satellitePersistentLogging()).thenReturn(true);
         when(mMockFeatureFlags.geofenceEnhancementForBetterUx()).thenReturn(true);
         when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
+        when(mMockFeatureFlags.carrierRoamingNbIotNtn()).thenReturn(true);
+
+        when(mMockContext.getSystemService(Context.TELEPHONY_SERVICE))
+                .thenReturn(mMockTelephonyManager);
+        when(mMockTelephonyManager.isSmsCapable()).thenReturn(true);
+        when(mMockContext.getPackageManager()).thenReturn(mMockPackageManager);
+        mMockResolveInfoList = new ArrayList<>();
+        when(mMockPackageManager.queryBroadcastReceiversAsUser(any(Intent.class), anyInt(), any(
+                UserHandle.class)))
+                .thenReturn(mMockResolveInfoList);
+        when(mMockContext.getSystemServiceName(
+                NotificationManager.class)).thenReturn(Context.NOTIFICATION_SERVICE);
+        when(mMockContext.getSystemService(Context.NOTIFICATION_SERVICE))
+                .thenReturn(mMockNotificationManager);
+        doReturn(mMockApplicationInfo).when(mMockContext).getApplicationInfo();
+        mMockApplicationInfo.targetSdkVersion = Build.VERSION_CODES.UPSIDE_DOWN_CAKE;
+        when(mMockPackageManager.getApplicationInfo(anyString(), anyInt()))
+                .thenReturn(mMockApplicationInfo);
+
+        mSatelliteInfo = new SatelliteInfo(
+                UUID.randomUUID(),
+                new SatellitePosition(10, 15),
+                new ArrayList<>(Arrays.asList(5, 30)),
+                new ArrayList<>(Arrays.asList(new EarfcnRange(0, 250))));
 
         mSatelliteAccessControllerUT = new TestSatelliteAccessController(mMockContext,
-                mMockFeatureFlags, mLooper, mMockLocationManager, mMockTelecomManager,
-                mMockSatelliteOnDeviceAccessController, mMockSatS2File);
+                mMockFeatureFlags, mTestableLooper.getLooper(), mMockLocationManager,
+                mMockTelecomManager, mMockSatelliteOnDeviceAccessController, mMockSatS2File);
         mTestableLooper.processAllMessages();
     }
 
     @After
     public void tearDown() throws Exception {
-        logd("tearDown");
-        if (mTestableLooper != null) {
-            mTestableLooper.destroy();
-            mTestableLooper = null;
-        }
-
-        if (mLooper != null) {
-            mLooper.quit();
-            mLooper = null;
-        }
+        super.tearDown();
     }
 
     @Test
@@ -368,6 +451,49 @@ public class SatelliteAccessControllerTest {
         assertEquals(inst1, inst2);
     }
 
+    @Test
+    public void testOnCurrentLocationNotAvailable() throws Exception {
+        // Verify the cache is used when the location is null and the cache is valid and true.
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos =
+                ALLOWED_STATE_CACHE_VALID_DURATION_NANOS - 1;
+        mSatelliteAccessControllerUT
+                .setIsSatelliteCommunicationAllowedForCurrentLocationCache("cache_allowed");
+        mSatelliteAccessControllerUT.setLocationRequestCancellationSignalAsNull(false);
+
+        sendCurrentLocationTimeoutEvent();
+        assertTrue(mSatelliteAccessControllerUT.isCurrentSatelliteAllowedState());
+
+        // Verify the cache is used when the location is null and the cache is valid and false.
+        mSatelliteAccessControllerUT
+                .setIsSatelliteCommunicationAllowedForCurrentLocationCache("cache_not_allowed");
+        mSatelliteAccessControllerUT.setLocationRequestCancellationSignalAsNull(false);
+
+        sendCurrentLocationTimeoutEvent();
+        assertFalse(mSatelliteAccessControllerUT.isCurrentSatelliteAllowedState());
+
+        // Verify the result code is SATELLITE_RESULT_LOCATION_NOT_AVAILABLE
+        // and allowedState is false when the location is null and the cache is expired
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos =
+                ALLOWED_STATE_CACHE_VALID_DURATION_NANOS + 1;
+        Iterator<ResultReceiver> mockResultReceiverIterator = mock(Iterator.class);
+        doReturn(mockResultReceiverIterator).when(mMockSatelliteAllowResultReceivers).iterator();
+        doReturn(true, false).when(mockResultReceiverIterator).hasNext();
+        doNothing().when(mMockSatelliteAllowResultReceivers).clear();
+        doReturn(mMockResultReceiver).when(mockResultReceiverIterator).next();
+        replaceInstance(SatelliteAccessController.class, "mSatelliteAllowResultReceivers",
+                mSatelliteAccessControllerUT, mMockSatelliteAllowResultReceivers);
+        mSatelliteAccessControllerUT.setIsSatelliteCommunicationAllowedForCurrentLocationCache(
+                "cache_clear_and_not_allowed");
+        mSatelliteAccessControllerUT.setLocationRequestCancellationSignalAsNull(false);
+
+        sendCurrentLocationTimeoutEvent();
+        verify(mMockResultReceiver)
+                .send(mResultCodeIntCaptor.capture(), any());
+        assertEquals(Integer.valueOf(SATELLITE_RESULT_LOCATION_NOT_AVAILABLE),
+                mResultCodeIntCaptor.getValue());
+        assertFalse(mSatelliteAccessControllerUT.isCurrentSatelliteAllowedState());
+    }
+
     @Test
     public void testIsSatelliteAccessAllowedForLocation() {
         when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
@@ -398,7 +524,7 @@ public class SatelliteAccessControllerTest {
         assertFalse(mSatelliteAccessControllerUT
                 .isSatelliteAccessAllowedForLocation(List.of(TEST_SATELLITE_COUNTRY_CODE_US)));
         assertFalse(mSatelliteAccessControllerUT.isSatelliteAccessAllowedForLocation(
-                        List.of(TEST_SATELLITE_COUNTRY_CODE_US, TEST_SATELLITE_COUNTRY_CODE_KR)));
+                List.of(TEST_SATELLITE_COUNTRY_CODE_US, TEST_SATELLITE_COUNTRY_CODE_KR)));
         assertTrue(mSatelliteAccessControllerUT
                 .isSatelliteAccessAllowedForLocation(List.of(TEST_SATELLITE_COUNTRY_CODE_KR)));
 
@@ -433,6 +559,310 @@ public class SatelliteAccessControllerTest {
                 .isSatelliteAccessAllowedForLocation(List.of(TEST_SATELLITE_COUNTRY_CODE_US)));
     }
 
+
+    private void setSatelliteCommunicationAllowed() throws Exception {
+        when(mMockContext.getResources()).thenReturn(mMockResources);
+        when(mMockResources.getBoolean(
+                com.android.internal.R.bool.config_oem_enabled_satellite_access_allow))
+                .thenReturn(TEST_SATELLITE_ALLOW);
+        setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
+        setUpResponseForRequestIsSatelliteProvisioned(true, SATELLITE_RESULT_SUCCESS);
+        doReturn(true).when(mMockLocationManager).isLocationEnabled();
+        when(mMockSatelliteOnDeviceAccessController.getRegionalConfigIdForLocation(
+                any(SatelliteOnDeviceAccessController.LocationToken.class)))
+                .thenReturn(DEFAULT_REGIONAL_SATELLITE_CONFIG_ID);
+        replaceInstance(SatelliteAccessController.class, "mCachedAccessRestrictionMap",
+                mSatelliteAccessControllerUT, mMockCachedAccessRestrictionMap);
+        doReturn(true).when(mMockCachedAccessRestrictionMap).containsKey(any());
+        doReturn(DEFAULT_REGIONAL_SATELLITE_CONFIG_ID)
+                .when(mMockCachedAccessRestrictionMap).get(any());
+    }
+
+    @Test
+    public void testRequestSatelliteAccessConfigurationForCurrentLocation() throws Exception {
+        // setup result receiver and satellite access configuration data
+        ResultReceiver mockResultReceiver = mock(ResultReceiver.class);
+        ArgumentCaptor<Integer> resultCodeCaptor = ArgumentCaptor.forClass(Integer.class);
+        ArgumentCaptor<Bundle> bundleCaptor = ArgumentCaptor.forClass(Bundle.class);
+        SatelliteAccessConfiguration satelliteAccessConfig = getSatelliteAccessConfiguration();
+
+        // setup satellite communication allowed state as true
+        setSatelliteCommunicationAllowed();
+
+        // setup map data of location and configId.
+        replaceInstance(SatelliteAccessController.class, "mSatelliteAccessConfigMap",
+                mSatelliteAccessControllerUT, mMockSatelliteAccessConfigMap);
+        doReturn(satelliteAccessConfig).when(mMockSatelliteAccessConfigMap).get(anyInt());
+        doReturn(null).when(mMockSatelliteAccessConfigMap).get(eq(null));
+        doReturn(null).when(mMockSatelliteAccessConfigMap)
+                .get(eq(UNKNOWN_REGIONAL_SATELLITE_CONFIG_ID));
+
+        // setup callback
+        ISatelliteCommunicationAllowedStateCallback mockSatelliteAllowedStateCallback = mock(
+                ISatelliteCommunicationAllowedStateCallback.class);
+        ArgumentCaptor<SatelliteAccessConfiguration> satelliteAccessConfigurationCaptor =
+                ArgumentCaptor.forClass(SatelliteAccessConfiguration.class);
+
+        when(mSatelliteCommunicationAllowedStateCallbackMap.values())
+                .thenReturn(List.of(mockSatelliteAllowedStateCallback));
+        replaceInstance(SatelliteAccessController.class,
+                "mSatelliteCommunicationAllowedStateChangedListeners", mSatelliteAccessControllerUT,
+                mSatelliteCommunicationAllowedStateCallbackMap);
+
+        // Test when the featureFlags.carrierRoamingNbIotNtn() is false
+        doReturn(false).when(mMockFeatureFlags).carrierRoamingNbIotNtn();
+
+        clearInvocations(mockResultReceiver);
+        mSatelliteAccessControllerUT
+                .requestSatelliteAccessConfigurationForCurrentLocation(mockResultReceiver);
+        mTestableLooper.processAllMessages();
+        verify(mockResultReceiver, times(1)).send(resultCodeCaptor.capture(),
+                bundleCaptor.capture());
+        assertEquals(SATELLITE_RESULT_REQUEST_NOT_SUPPORTED, (int) resultCodeCaptor.getValue());
+        assertNull(bundleCaptor.getValue());
+        verify(mockSatelliteAllowedStateCallback, never())
+                .onSatelliteAccessConfigurationChanged(any());
+
+        doReturn(true).when(mMockFeatureFlags).carrierRoamingNbIotNtn();
+
+        // Verify if the map is maintained after the cleanup event
+        sendSatelliteDeviceAccessControllerResourcesTimeOutEvent();
+
+        // satellite communication allowed state is enabled and
+        // regional config id is DEFAULT_REGIONAL_SATELLITE_CONFIG_ID.
+        clearInvocations(mockResultReceiver);
+        clearInvocations(mockSatelliteAllowedStateCallback);
+        mSatelliteAccessControllerUT
+                .requestSatelliteAccessConfigurationForCurrentLocation(mockResultReceiver);
+        mTestableLooper.processAllMessages();
+        verify(mockResultReceiver, times(1)).send(resultCodeCaptor.capture(),
+                bundleCaptor.capture());
+        assertEquals(SatelliteManager.SATELLITE_RESULT_SUCCESS, (int) resultCodeCaptor.getValue());
+        assertTrue(bundleCaptor.getValue().containsKey(KEY_SATELLITE_ACCESS_CONFIGURATION));
+        assertSame(bundleCaptor.getValue().getParcelable(KEY_SATELLITE_ACCESS_CONFIGURATION,
+                SatelliteAccessConfiguration.class), satelliteAccessConfig);
+        verify(mockSatelliteAllowedStateCallback, times(1))
+                .onSatelliteAccessConfigurationChanged(
+                        satelliteAccessConfigurationCaptor.capture());
+        assertEquals(satelliteAccessConfigurationCaptor.getValue(), satelliteAccessConfig);
+
+        // satellite communication allowed state is disabled and
+        // regional config id is null.
+        clearInvocations(mockResultReceiver);
+        clearInvocations(mockSatelliteAllowedStateCallback);
+        when(mMockCachedAccessRestrictionMap.get(any())).thenReturn(null);
+        mSatelliteAccessControllerUT
+                .requestSatelliteAccessConfigurationForCurrentLocation(mockResultReceiver);
+        mTestableLooper.processAllMessages();
+
+        verify(mockResultReceiver, times(1)).send(resultCodeCaptor.capture(),
+                bundleCaptor.capture());
+        assertEquals(SATELLITE_RESULT_NO_RESOURCES, (int) resultCodeCaptor.getValue());
+        assertNull(bundleCaptor.getValue());
+
+        verify(mockSatelliteAllowedStateCallback, times(1))
+                .onSatelliteAccessConfigurationChanged(
+                        satelliteAccessConfigurationCaptor.capture());
+        assertNull(satelliteAccessConfigurationCaptor.getValue());
+    }
+
+    private SatelliteAccessConfiguration getSatelliteAccessConfiguration() {
+        List<SatelliteInfo> satelliteInfoList = new ArrayList<>();
+        satelliteInfoList.add(mSatelliteInfo);
+        List<Integer> tagIds = new ArrayList<>(List.of(1, 2));
+        return new SatelliteAccessConfiguration(satelliteInfoList, tagIds);
+    }
+
+    @Test
+    public void testRegisterForCommunicationAllowedStateChanged() throws Exception {
+        ISatelliteCommunicationAllowedStateCallback mockSatelliteAllowedStateCallback = mock(
+                ISatelliteCommunicationAllowedStateCallback.class);
+        doReturn(true).when(mSatelliteCommunicationAllowedStateCallbackMap)
+                .put(any(IBinder.class), any(ISatelliteCommunicationAllowedStateCallback.class));
+        replaceInstance(SatelliteAccessController.class,
+                "mSatelliteCommunicationAllowedStateChangedListeners", mSatelliteAccessControllerUT,
+                mSatelliteCommunicationAllowedStateCallbackMap);
+
+        doReturn(false).when(mMockFeatureFlags).oemEnabledSatelliteFlag();
+        int result = mSatelliteAccessControllerUT.registerForCommunicationAllowedStateChanged(
+                DEFAULT_SUBSCRIPTION_ID, mockSatelliteAllowedStateCallback);
+        mTestableLooper.processAllMessages();
+        assertEquals(SATELLITE_RESULT_REQUEST_NOT_SUPPORTED, result);
+        verify(mockSatelliteAllowedStateCallback, never())
+                .onSatelliteCommunicationAllowedStateChanged(anyBoolean());
+        verify(mockSatelliteAllowedStateCallback, never())
+                .onSatelliteAccessConfigurationChanged(any(SatelliteAccessConfiguration.class));
+
+        doReturn(true).when(mMockFeatureFlags).oemEnabledSatelliteFlag();
+        result = mSatelliteAccessControllerUT.registerForCommunicationAllowedStateChanged(
+                DEFAULT_SUBSCRIPTION_ID, mockSatelliteAllowedStateCallback);
+        mTestableLooper.processAllMessages();
+        assertEquals(SATELLITE_RESULT_SUCCESS, result);
+        verify(mockSatelliteAllowedStateCallback, times(1))
+                .onSatelliteCommunicationAllowedStateChanged(anyBoolean());
+        verify(mockSatelliteAllowedStateCallback, times(1))
+                .onSatelliteAccessConfigurationChanged(
+                        nullable(SatelliteAccessConfiguration.class));
+    }
+
+    @Test
+    public void testNotifyRegionalSatelliteConfigurationChanged() throws Exception {
+        // setup test
+        ISatelliteCommunicationAllowedStateCallback mockSatelliteAllowedStateCallback = mock(
+                ISatelliteCommunicationAllowedStateCallback.class);
+        ArgumentCaptor<SatelliteAccessConfiguration> satelliteAccessConfigurationCaptor =
+                ArgumentCaptor.forClass(SatelliteAccessConfiguration.class);
+
+        when(mSatelliteCommunicationAllowedStateCallbackMap.values())
+                .thenReturn(List.of(mockSatelliteAllowedStateCallback));
+        replaceInstance(SatelliteAccessController.class,
+                "mSatelliteCommunicationAllowedStateChangedListeners", mSatelliteAccessControllerUT,
+                mSatelliteCommunicationAllowedStateCallbackMap);
+
+        // register callback
+        mSatelliteAccessControllerUT.registerForCommunicationAllowedStateChanged(
+                DEFAULT_SUBSCRIPTION_ID, mockSatelliteAllowedStateCallback);
+
+        // verify if the callback is
+        // the same instance from onmSatelliteCommunicationAllowedStateCallbackMap
+        verify(mSatelliteCommunicationAllowedStateCallbackMap).put(any(),
+                mAllowedStateCallbackCaptor.capture());
+        assertSame(mockSatelliteAllowedStateCallback, mAllowedStateCallbackCaptor.getValue());
+
+        // create SatelliteAccessConfiguration data for this test
+        SatelliteAccessConfiguration satelliteAccessConfig = getSatelliteAccessConfiguration();
+
+        // trigger notifyRegionalSatelliteConfigurationChanged
+        mSatelliteAccessControllerUT
+                .notifyRegionalSatelliteConfigurationChanged(satelliteAccessConfig);
+
+        // verify if the satelliteAccessConfig is the same instance with the captured one.
+        verify(mockSatelliteAllowedStateCallback).onSatelliteAccessConfigurationChanged(
+                satelliteAccessConfigurationCaptor.capture());
+        assertSame(satelliteAccessConfig, satelliteAccessConfigurationCaptor.getValue());
+    }
+
+    @Test
+    public void testCheckSatelliteAccessRestrictionForLocation() throws Exception {
+        // Setup
+        logd("testCheckSatelliteAccessRestrictionForLocation : setup");
+        ArgumentCaptor<Bundle> bundleCaptor = ArgumentCaptor.forClass(Bundle.class);
+        ArgumentCaptor<Integer> regionalConfigIdCaptor = ArgumentCaptor.forClass(Integer.class);
+        replaceInstance(SatelliteAccessController.class, "mS2Level",
+                mSatelliteAccessControllerUT, DEFAULT_S2_LEVEL);
+        Iterator<ResultReceiver> mockResultReceiverIterator = mock(Iterator.class);
+        mSatelliteAccessControllerUT.setRegionalConfigId(null);
+
+        doReturn(mockResultReceiverIterator).when(mMockSatelliteAllowResultReceivers).iterator();
+        doReturn(true, false).when(mockResultReceiverIterator).hasNext();
+        doNothing().when(mMockSatelliteAllowResultReceivers).clear();
+        doReturn(mMockResultReceiver).when(mockResultReceiverIterator).next();
+        replaceInstance(SatelliteAccessController.class, "mSatelliteAllowResultReceivers",
+                mSatelliteAccessControllerUT, mMockSatelliteAllowResultReceivers);
+        replaceInstance(SatelliteAccessController.class, "mCachedAccessRestrictionMap",
+                mSatelliteAccessControllerUT, mMockCachedAccessRestrictionMap);
+
+        // when mMockCachedAccessRestrictionMap is hit and has DEFAULT_REGIONAL_SATELLITE_CONFIG_ID,
+        // verify belows
+        // - the bundle data of KEY_SATELLITE_COMMUNICATION_ALLOWED is true
+        // - the newRegionalConfigId is the same as DEFAULT_REGIONAL_SATELLITE_CONFIG_ID
+        // - the regionalConfigId is the same as DEFAULT_REGIONAL_SATELLITE_CONFIG_ID
+        logd("testCheckSatelliteAccessRestrictionForLocation : case 1");
+        clearInvocations(mMockSatelliteOnDeviceAccessController);
+        clearInvocations(mMockCachedAccessRestrictionMap);
+
+        doReturn(true).when(mMockCachedAccessRestrictionMap)
+                .containsKey(any(SatelliteOnDeviceAccessController.LocationToken.class));
+        doReturn(DEFAULT_REGIONAL_SATELLITE_CONFIG_ID).when(mMockCachedAccessRestrictionMap)
+                .get(any(SatelliteOnDeviceAccessController.LocationToken.class));
+
+        mSatelliteAccessControllerUT.checkSatelliteAccessRestrictionForLocation(mMockLocation0);
+        verify(mMockResultReceiver, times(1))
+                .send(mResultCodeIntCaptor.capture(), bundleCaptor.capture());
+        verify(mMockSatelliteOnDeviceAccessController, never()).getRegionalConfigIdForLocation(
+                any(SatelliteOnDeviceAccessController.LocationToken.class));
+        assertEquals(Integer.valueOf(SATELLITE_RESULT_SUCCESS), mResultCodeIntCaptor.getValue());
+        assertTrue(bundleCaptor.getValue().getBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED));
+        assertEquals(Integer.valueOf(DEFAULT_REGIONAL_SATELLITE_CONFIG_ID),
+                mSatelliteAccessControllerUT.getNewRegionalConfigId());
+        assertEquals(Integer.valueOf(DEFAULT_REGIONAL_SATELLITE_CONFIG_ID),
+                mSatelliteAccessControllerUT.getRegionalConfigId());
+
+        // when mMockCachedAccessRestrictionMap is not hit and regionalConfigId is null
+        // verify belows
+        // - the bundle data of KEY_SATELLITE_COMMUNICATION_ALLOWED is false
+        // - the regionalConfigId is null
+        logd("testCheckSatelliteAccessRestrictionForLocation : case 2");
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        doReturn(false).when(mMockCachedAccessRestrictionMap)
+                .containsKey(any(SatelliteOnDeviceAccessController.LocationToken.class));
+        doReturn(true, false).when(mockResultReceiverIterator).hasNext();
+        when(mMockSatelliteOnDeviceAccessController.getRegionalConfigIdForLocation(
+                any(SatelliteOnDeviceAccessController.LocationToken.class)))
+                .thenReturn(null);
+
+        mSatelliteAccessControllerUT.checkSatelliteAccessRestrictionForLocation(mMockLocation0);
+        verify(mMockResultReceiver, times(2))
+                .send(mResultCodeIntCaptor.capture(), bundleCaptor.capture());
+        assertEquals(Integer.valueOf(SATELLITE_RESULT_SUCCESS), mResultCodeIntCaptor.getValue());
+        assertFalse(bundleCaptor.getValue().getBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED));
+        verify(mMockCachedAccessRestrictionMap, times(1))
+                .put(any(), regionalConfigIdCaptor.capture());
+        assertNull(regionalConfigIdCaptor.getValue());
+        assertNull(mSatelliteAccessControllerUT.getNewRegionalConfigId());
+        assertNull(mSatelliteAccessControllerUT.getRegionalConfigId());
+
+        // when mMockCachedAccessRestrictionMap is not hit and
+        // regionalConfigId is DEFAULT_REGIONAL_SATELLITE_CONFIG_ID
+        // verify belows
+        // - the bundle data of KEY_SATELLITE_COMMUNICATION_ALLOWED is true
+        // - the regionalConfigId is DEFAULT_REGIONAL_SATELLITE_CONFIG_ID
+        logd("testCheckSatelliteAccessRestrictionForLocation : case 3");
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        when(mMockSatelliteOnDeviceAccessController.getRegionalConfigIdForLocation(
+                any(SatelliteOnDeviceAccessController.LocationToken.class)))
+                .thenReturn(DEFAULT_REGIONAL_SATELLITE_CONFIG_ID);
+        doReturn(true, false).when(mockResultReceiverIterator).hasNext();
+
+        mSatelliteAccessControllerUT.checkSatelliteAccessRestrictionForLocation(mMockLocation0);
+        verify(mMockResultReceiver, times(3))
+                .send(mResultCodeIntCaptor.capture(), bundleCaptor.capture());
+        assertEquals(Integer.valueOf(SATELLITE_RESULT_SUCCESS), mResultCodeIntCaptor.getValue());
+        assertTrue(bundleCaptor.getValue().getBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED));
+        verify(mMockCachedAccessRestrictionMap, times(1))
+                .put(any(), regionalConfigIdCaptor.capture());
+
+        assertEquals(Integer.valueOf(DEFAULT_REGIONAL_SATELLITE_CONFIG_ID),
+                regionalConfigIdCaptor.getValue());
+        assertEquals(Integer.valueOf(DEFAULT_REGIONAL_SATELLITE_CONFIG_ID),
+                mSatelliteAccessControllerUT.getNewRegionalConfigId());
+        assertEquals(Integer.valueOf(DEFAULT_REGIONAL_SATELLITE_CONFIG_ID),
+                mSatelliteAccessControllerUT.getRegionalConfigId());
+
+
+        // when mMockCachedAccessRestrictionMap is not hit and regionalConfigId is null
+        // verify belows
+        // - the bundle data of KEY_SATELLITE_COMMUNICATION_ALLOWED is false
+        // - the regionalConfigId is null
+        logd("testCheckSatelliteAccessRestrictionForLocation : case 4");
+        clearInvocations(mMockCachedAccessRestrictionMap);
+        when(mMockSatelliteOnDeviceAccessController.getRegionalConfigIdForLocation(
+                any(SatelliteOnDeviceAccessController.LocationToken.class)))
+                .thenReturn(null);
+        doReturn(true, false).when(mockResultReceiverIterator).hasNext();
+
+        mSatelliteAccessControllerUT.checkSatelliteAccessRestrictionForLocation(mMockLocation0);
+        verify(mMockResultReceiver, times(4))
+                .send(mResultCodeIntCaptor.capture(), bundleCaptor.capture());
+        assertEquals(Integer.valueOf(SATELLITE_RESULT_SUCCESS), mResultCodeIntCaptor.getValue());
+        assertFalse(bundleCaptor.getValue().getBoolean(KEY_SATELLITE_COMMUNICATION_ALLOWED));
+        verify(mMockCachedAccessRestrictionMap, times(1))
+                .put(any(), regionalConfigIdCaptor.capture());
+        assertNull(regionalConfigIdCaptor.getValue());
+        assertNull(mSatelliteAccessControllerUT.getNewRegionalConfigId());
+        assertNull(mSatelliteAccessControllerUT.getRegionalConfigId());
+    }
+
     @Test
     public void testIsRegionDisallowed() throws Exception {
         // setup to make the return value of mQueriedSatelliteAllowed 'true'
@@ -444,12 +874,14 @@ public class SatelliteAccessControllerTest {
         setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
         setUpResponseForRequestIsSatelliteProvisioned(true, SATELLITE_RESULT_SUCCESS);
         doReturn(true).when(mMockLocationManager).isLocationEnabled();
-        when(mMockSatelliteOnDeviceAccessController.isSatCommunicationAllowedAtLocation(
-                any(SatelliteOnDeviceAccessController.LocationToken.class))).thenReturn(true);
+        when(mMockSatelliteOnDeviceAccessController.getRegionalConfigIdForLocation(
+                any(SatelliteOnDeviceAccessController.LocationToken.class)))
+                .thenReturn(DEFAULT_REGIONAL_SATELLITE_CONFIG_ID);
         replaceInstance(SatelliteAccessController.class, "mCachedAccessRestrictionMap",
                 mSatelliteAccessControllerUT, mMockCachedAccessRestrictionMap);
         doReturn(true).when(mMockCachedAccessRestrictionMap).containsKey(any());
-        doReturn(true).when(mMockCachedAccessRestrictionMap).get(any());
+        doReturn(DEFAULT_REGIONAL_SATELLITE_CONFIG_ID)
+                .when(mMockCachedAccessRestrictionMap).get(any());
 
         // get allowed country codes EMPTY from resources
         when(mMockResources.getStringArray(
@@ -681,7 +1113,7 @@ public class SatelliteAccessControllerTest {
         mTestableLooper.processAllMessages();
         assertTrue(
                 mSatelliteAccessControllerUT.isKeepOnDeviceAccessControllerResourcesTimerStarted());
-        verify(mMockSatelliteOnDeviceAccessController).isSatCommunicationAllowedAtLocation(
+        verify(mMockSatelliteOnDeviceAccessController).getRegionalConfigIdForLocation(
                 any(SatelliteOnDeviceAccessController.LocationToken.class));
         assertTrue(waitForRequestIsSatelliteAllowedForCurrentLocationResult(
                 mSatelliteAllowedSemaphore, 1));
@@ -726,7 +1158,7 @@ public class SatelliteAccessControllerTest {
         sendLocationRequestResult(mMockLocation0);
         assertFalse(mSatelliteAccessControllerUT.isWaitForCurrentLocationTimerStarted());
         // The LocationToken should be already in the cache
-        verify(mMockSatelliteOnDeviceAccessController, never()).isSatCommunicationAllowedAtLocation(
+        verify(mMockSatelliteOnDeviceAccessController, never()).getRegionalConfigIdForLocation(
                 any(SatelliteOnDeviceAccessController.LocationToken.class));
         assertTrue(waitForRequestIsSatelliteAllowedForCurrentLocationResult(
                 mSatelliteAllowedSemaphore, 1));
@@ -758,7 +1190,7 @@ public class SatelliteAccessControllerTest {
                 mSatelliteAccessControllerUT.getWaitForCurrentLocationTimeoutMillis());
         mTestableLooper.processAllMessages();
         assertFalse(mSatelliteAccessControllerUT.isWaitForCurrentLocationTimerStarted());
-        verify(mMockSatelliteOnDeviceAccessController, never()).isSatCommunicationAllowedAtLocation(
+        verify(mMockSatelliteOnDeviceAccessController, never()).getRegionalConfigIdForLocation(
                 any(SatelliteOnDeviceAccessController.LocationToken.class));
         assertTrue(waitForRequestIsSatelliteAllowedForCurrentLocationResult(
                 mSatelliteAllowedSemaphore, 1));
@@ -784,7 +1216,7 @@ public class SatelliteAccessControllerTest {
         verify(mMockLocationManager, never()).getCurrentLocation(anyString(),
                 any(LocationRequest.class), any(CancellationSignal.class), any(Executor.class),
                 any(Consumer.class));
-        verify(mMockSatelliteOnDeviceAccessController, never()).isSatCommunicationAllowedAtLocation(
+        verify(mMockSatelliteOnDeviceAccessController, never()).getRegionalConfigIdForLocation(
                 any(SatelliteOnDeviceAccessController.LocationToken.class));
         assertTrue(waitForRequestIsSatelliteAllowedForCurrentLocationResult(
                 mSatelliteAllowedSemaphore, 1));
@@ -792,6 +1224,91 @@ public class SatelliteAccessControllerTest {
         assertFalse(mQueriedSatelliteAllowed);
     }
 
+    @Test
+    public void testLocationQueryThrottleTimeUpdate() {
+        long firstMccChangedTime = 1;
+        long lastKnownLocationElapsedRealtime =
+                firstMccChangedTime + TEST_LOCATION_QUERY_THROTTLE_INTERVAL_NANOS;
+
+        // OEM-enabled satellite is supported
+        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
+
+        verify(mMockCountryDetector).registerForCountryCodeChanged(
+                mCountryDetectorHandlerCaptor.capture(), mCountryDetectorIntCaptor.capture(),
+                mCountryDetectorObjCaptor.capture());
+
+        assertSame(mCountryDetectorHandlerCaptor.getValue(), mSatelliteAccessControllerUT);
+        assertSame(mCountryDetectorIntCaptor.getValue(), EVENT_COUNTRY_CODE_CHANGED);
+        assertNull(mCountryDetectorObjCaptor.getValue());
+
+        // Setup to invoke GPS query
+        clearInvocations(mMockSatelliteOnDeviceAccessController);
+        setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
+        setUpResponseForRequestIsSatelliteProvisioned(true, SATELLITE_RESULT_SUCCESS);
+        doReturn(true).when(mMockLocationManager).isLocationEnabled();
+        when(mMockLocationManager.getLastKnownLocation(LocationManager.FUSED_PROVIDER))
+                .thenReturn(null);
+        when(mMockLocationManager.getLastKnownLocation(LocationManager.NETWORK_PROVIDER))
+                .thenReturn(null);
+
+        // When mcc changed first, so queried a location with GPS,
+        // verify if the mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos
+        // is the same with firstMccChangedTime.
+        // verify mMockLocationManager.getCurrentLocation() is invoked
+        // verify time(mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos) is
+        // firstMccChangedTime
+        clearInvocations(mMockLocationManager);
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos = firstMccChangedTime;
+        sendCommandValidateCountryCodeChangeEvent(mMockContext);
+        verify(mMockLocationManager, times(1))
+                .getCurrentLocation(any(), any(), any(), any(), any());
+        assertEquals(firstMccChangedTime, mSatelliteAccessControllerUT
+                .mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos);
+
+        // set current time less than throttle_interval
+        // verify mMockLocationManager.getCurrentLocation() is not invoked
+        // verify time(mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos) is not updated
+        clearInvocations(mMockLocationManager);
+        doReturn(lastKnownLocationElapsedRealtime).when(mMockLocation1).getElapsedRealtimeNanos();
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos =
+                (firstMccChangedTime + TEST_LOCATION_QUERY_THROTTLE_INTERVAL_NANOS - 1);
+        sendCommandValidateCountryCodeChangeEvent(mMockContext);
+        verify(mMockLocationManager, never())
+                .getCurrentLocation(any(), any(), any(), any(), any());
+        assertEquals(firstMccChangedTime, mSatelliteAccessControllerUT
+                .mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos);
+
+        // Test the scenario when last know location is fresh and
+        // current time is greater than the location query throttle interval
+        // verify mMockLocationManager.getCurrentLocation() is not invoked
+        // verify time(mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos) is not updated
+        clearInvocations(mMockLocationManager);
+        doReturn(lastKnownLocationElapsedRealtime).when(mMockLocation1).getElapsedRealtimeNanos();
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos =
+                (lastKnownLocationElapsedRealtime + TEST_LOCATION_FRESH_DURATION_NANOS - 1);
+        sendCommandValidateCountryCodeChangeEvent(mMockContext);
+        verify(mMockLocationManager, never())
+                .getCurrentLocation(any(), any(), any(), any(), any());
+        assertEquals(firstMccChangedTime, mSatelliteAccessControllerUT
+                .mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos);
+
+        // Test the scenario when last know location is not fresh and
+        // current time is greater than the location query throttle interval
+        // verify mMockLocationManager.getCurrentLocation() is invoked
+        // verify time(mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos) is updated
+        clearInvocations(mMockLocationManager);
+        mSatelliteAccessControllerUT.setLocationRequestCancellationSignalAsNull(true);
+        mSatelliteAccessControllerUT.elapsedRealtimeNanos =
+                (lastKnownLocationElapsedRealtime + TEST_LOCATION_FRESH_DURATION_NANOS + 1);
+        sendCommandValidateCountryCodeChangeEvent(mMockContext);
+        verify(mMockLocationManager, times(1))
+                .getCurrentLocation(any(), any(), any(), any(), any());
+        assertEquals(lastKnownLocationElapsedRealtime + TEST_LOCATION_FRESH_DURATION_NANOS + 1,
+                mSatelliteAccessControllerUT
+                        .mLastLocationQueryForPossibleChangeInAllowedRegionTimeNanos);
+    }
+
+
     @Test
     public void testAllowLocationQueryForSatelliteAllowedCheck() {
         mSatelliteAccessControllerUT.mLatestSatelliteCommunicationAllowedSetTime = 1;
@@ -849,7 +1366,7 @@ public class SatelliteAccessControllerTest {
         assertNull(mCountryDetectorObjCaptor.getValue());
 
         // Normal case that invokes
-        // mMockSatelliteOnDeviceAccessController.isSatCommunicationAllowedAtLocation
+        // mMockSatelliteOnDeviceAccessController.getRegionalConfigIdForLocation
         clearInvocations(mMockSatelliteOnDeviceAccessController);
         setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
         setUpResponseForRequestIsSatelliteProvisioned(true, SATELLITE_RESULT_SUCCESS);
@@ -857,14 +1374,14 @@ public class SatelliteAccessControllerTest {
         mSatelliteAccessControllerUT.elapsedRealtimeNanos = TEST_LOCATION_FRESH_DURATION_NANOS;
         sendCommandValidateCountryCodeChangeEvent(mMockContext);
         verify(mMockSatelliteOnDeviceAccessController,
-                times(1)).isSatCommunicationAllowedAtLocation(
+                times(1)).getRegionalConfigIdForLocation(
                 any(SatelliteOnDeviceAccessController.LocationToken.class));
 
         // Case that isCommunicationAllowedCacheValid is true
         clearInvocations(mMockSatelliteOnDeviceAccessController);
         mSatelliteAccessControllerUT.elapsedRealtimeNanos = TEST_LOCATION_FRESH_DURATION_NANOS + 1;
         sendCommandValidateCountryCodeChangeEvent(mMockContext);
-        verify(mMockSatelliteOnDeviceAccessController, never()).isSatCommunicationAllowedAtLocation(
+        verify(mMockSatelliteOnDeviceAccessController, never()).getRegionalConfigIdForLocation(
                 any(SatelliteOnDeviceAccessController.LocationToken.class));
 
         // Case that mLatestCacheEnforcedValidateTimeNanos is over
@@ -881,11 +1398,11 @@ public class SatelliteAccessControllerTest {
         when(mMockLocation0.getLongitude()).thenReturn(2.0);
         when(mMockLocation1.getLatitude()).thenReturn(3.0);
         when(mMockLocation1.getLongitude()).thenReturn(3.0);
-        when(mMockSatelliteOnDeviceAccessController.isSatCommunicationAllowedAtLocation(
-                any(SatelliteOnDeviceAccessController.LocationToken.class))).thenReturn(false);
+        when(mMockSatelliteOnDeviceAccessController.getRegionalConfigIdForLocation(
+                any(SatelliteOnDeviceAccessController.LocationToken.class))).thenReturn(null);
         sendCommandValidateCountryCodeChangeEvent(mMockContext);
         verify(mMockSatelliteOnDeviceAccessController,
-                times(1)).isSatCommunicationAllowedAtLocation(
+                times(1)).getRegionalConfigIdForLocation(
                 any(SatelliteOnDeviceAccessController.LocationToken.class));
     }
 
@@ -923,6 +1440,33 @@ public class SatelliteAccessControllerTest {
                 .getRetryCountPossibleChangeInSatelliteAllowedRegion() == 0);
     }
 
+    @Test
+    public void testLoadSatelliteAccessConfigurationFromDeviceConfig() {
+        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(false);
+        assertNull(mSatelliteAccessControllerUT
+                .getSatelliteConfigurationFileNameFromOverlayConfig(mMockContext));
+
+        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
+        when(mMockContext.getResources()).thenReturn(mMockResources);
+        when(mMockResources
+                .getString(eq(com.android.internal.R.string.satellite_access_config_file)))
+                .thenReturn("test_satellite_file.json");
+        assertEquals("test_satellite_file.json", mSatelliteAccessControllerUT
+                .getSatelliteConfigurationFileNameFromOverlayConfig(mMockContext));
+
+        when(mMockResources
+                .getString(eq(com.android.internal.R.string.satellite_access_config_file)))
+                .thenReturn(null);
+        assertNull(mSatelliteAccessControllerUT
+                .getSatelliteConfigurationFileNameFromOverlayConfig(mMockContext));
+        try {
+            mSatelliteAccessControllerUT.loadSatelliteAccessConfigurationFromDeviceConfig();
+        } catch (Exception e) {
+            fail("Unexpected exception thrown: " + e.getMessage());
+        }
+    }
+
+
     @Test
     public void testUpdateSatelliteConfigData() throws Exception {
         verify(mMockSatelliteController).registerForConfigUpdateChanged(
@@ -938,7 +1482,7 @@ public class SatelliteAccessControllerTest {
 
         // These APIs are executed during loadRemoteConfigs
         verify(mMockSharedPreferences, times(1)).getStringSet(anyString(), any());
-        verify(mMockSharedPreferences, times(1)).getBoolean(anyString(), anyBoolean());
+        verify(mMockSharedPreferences, times(5)).getBoolean(anyString(), anyBoolean());
 
         // satelliteConfig is null
         SatelliteConfigParser spyConfigParser =
@@ -985,6 +1529,7 @@ public class SatelliteAccessControllerTest {
         doReturn(mockConfig).when(mMockSatelliteController).getSatelliteConfig();
         File testS2File = mSatelliteAccessControllerUT
                 .getTestSatelliteS2File(GOOGLE_US_SAN_SAT_S2_FILE_NAME);
+        assumeTrue("Satellite not supported", testS2File != null && testS2File.exists());
         doReturn(List.of(TEST_SATELLITE_COUNTRY_CODES))
                 .when(mockConfig).getDeviceSatelliteCountryCodes();
         doReturn(true).when(mockConfig).isSatelliteDataForAllowedRegion();
@@ -1005,19 +1550,18 @@ public class SatelliteAccessControllerTest {
                 .thenReturn(TEST_SATELLITE_ALLOW);
         setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
         setUpResponseForRequestIsSatelliteProvisioned(true, SATELLITE_RESULT_SUCCESS);
-        when(mMockSatelliteOnDeviceAccessController.isSatCommunicationAllowedAtLocation(
-                any(SatelliteOnDeviceAccessController.LocationToken.class))).thenReturn(true);
+        when(mMockSatelliteOnDeviceAccessController.getRegionalConfigIdForLocation(
+                any(SatelliteOnDeviceAccessController.LocationToken.class)))
+                .thenReturn(DEFAULT_REGIONAL_SATELLITE_CONFIG_ID);
         replaceInstance(SatelliteAccessController.class, "mCachedAccessRestrictionMap",
                 mSatelliteAccessControllerUT, mMockCachedAccessRestrictionMap);
         doReturn(false).when(mMockCachedAccessRestrictionMap).containsKey(any());
         mSatelliteAccessControllerUT.elapsedRealtimeNanos = TEST_LOCATION_FRESH_DURATION_NANOS + 1;
 
         // Captor and Verify if the mockReceiver and mocContext is registered well
-        verify(mMockContext).registerReceiver(mLocationBroadcastReceiverCaptor.capture(),
-                mIntentFilterCaptor.capture());
-        assertSame(mSatelliteAccessControllerUT.getLocationBroadcastReceiver(),
-                mLocationBroadcastReceiverCaptor.getValue());
-        assertSame(MODE_CHANGED_ACTION, mIntentFilterCaptor.getValue().getAction(0));
+        verify(mMockContext, times(2))
+                .registerReceiver(mLocationBroadcastReceiverCaptor.capture(),
+                        mIntentFilterCaptor.capture());
 
         // When the intent action is not MODE_CHANGED_ACTION,
         // verify if the location manager never invoke isLocationEnabled()
@@ -1056,7 +1600,7 @@ public class SatelliteAccessControllerTest {
         // In emergency case,
         // verify if the location manager get FUSED provider and ignore location settings
         doReturn(true).when(mMockTelecomManager).isInEmergencyCall();
-        mSatelliteAccessControllerUT.setLocationRequestCancellationSignalAsNull();
+        mSatelliteAccessControllerUT.setLocationRequestCancellationSignalAsNull(true);
         mSatelliteAccessControllerUT.elapsedRealtimeNanos = TEST_LOCATION_FRESH_DURATION_NANOS + 1;
         mSatelliteAccessControllerUT.checkSatelliteAccessRestrictionUsingGPS();
 
@@ -1074,7 +1618,7 @@ public class SatelliteAccessControllerTest {
         doReturn(false).when(mMockPhone2).isInEcm();
         doReturn(false).when(mMockSatelliteController).isInEmergencyMode();
         doReturn(true).when(mMockLocationManager).isLocationEnabled();
-        mSatelliteAccessControllerUT.setLocationRequestCancellationSignalAsNull();
+        mSatelliteAccessControllerUT.setLocationRequestCancellationSignalAsNull(true);
         mSatelliteAccessControllerUT.checkSatelliteAccessRestrictionUsingGPS();
 
         verify(mMockLocationManager, times(1))
@@ -1087,10 +1631,10 @@ public class SatelliteAccessControllerTest {
     @Test
     public void testHandleIsSatelliteSupportedResult() throws Exception {
         // Setup for this test case
-        Iterator<ResultReceiver> mockIterator = mock(Iterator.class);
-        doReturn(mockIterator).when(mMockSatelliteAllowResultReceivers).iterator();
-        doReturn(true, false).when(mockIterator).hasNext();
-        doReturn(mMockSatelliteSupportedResultReceiver).when(mockIterator).next();
+        Iterator<ResultReceiver> mockResultReceiverIterator = mock(Iterator.class);
+        doReturn(mockResultReceiverIterator).when(mMockSatelliteAllowResultReceivers).iterator();
+        doReturn(true, false).when(mockResultReceiverIterator).hasNext();
+        doReturn(mMockResultReceiver).when(mockResultReceiverIterator).next();
 
         replaceInstance(SatelliteAccessController.class, "mSatelliteAllowResultReceivers",
                 mSatelliteAccessControllerUT, mMockSatelliteAllowResultReceivers);
@@ -1099,10 +1643,10 @@ public class SatelliteAccessControllerTest {
         // case that resultCode is not SATELLITE_RESULT_SUCCESS
         int resultCode = SATELLITE_RESULT_ERROR;
         Bundle bundle = new Bundle();
-        doReturn(true, false).when(mockIterator).hasNext();
-        clearInvocations(mMockSatelliteSupportedResultReceiver);
+        doReturn(true, false).when(mockResultReceiverIterator).hasNext();
+        clearInvocations(mMockResultReceiver);
         mSatelliteAccessControllerUT.handleIsSatelliteSupportedResult(resultCode, bundle);
-        verify(mMockSatelliteSupportedResultReceiver)
+        verify(mMockResultReceiver)
                 .send(mResultCodeIntCaptor.capture(), any());
         assertEquals(Integer.valueOf(SATELLITE_RESULT_ERROR), mResultCodeIntCaptor.getValue());
 
@@ -1110,20 +1654,19 @@ public class SatelliteAccessControllerTest {
         // verify that the resultCode is delivered as it were
         resultCode = SATELLITE_RESULT_SUCCESS;
         bundle.putBoolean(KEY_SATELLITE_PROVISIONED, false);
-        doReturn(true, false).when(mockIterator).hasNext();
-        clearInvocations(mMockSatelliteSupportedResultReceiver);
+        doReturn(true, false).when(mockResultReceiverIterator).hasNext();
+        clearInvocations(mMockResultReceiver);
         mSatelliteAccessControllerUT.handleIsSatelliteSupportedResult(resultCode, bundle);
-        verify(mMockSatelliteSupportedResultReceiver)
-                .send(mResultCodeIntCaptor.capture(), any());
+        verify(mMockResultReceiver).send(mResultCodeIntCaptor.capture(), any());
         assertEquals(Integer.valueOf(SATELLITE_RESULT_SUCCESS), mResultCodeIntCaptor.getValue());
 
         // case KEY_SATELLITE_SUPPORTED is false
         // verify SATELLITE_RESULT_NOT_SUPPORTED is captured
         bundle.putBoolean(KEY_SATELLITE_SUPPORTED, false);
-        doReturn(true, false).when(mockIterator).hasNext();
-        clearInvocations(mMockSatelliteSupportedResultReceiver);
+        doReturn(true, false).when(mockResultReceiverIterator).hasNext();
+        clearInvocations(mMockResultReceiver);
         mSatelliteAccessControllerUT.handleIsSatelliteSupportedResult(resultCode, bundle);
-        verify(mMockSatelliteSupportedResultReceiver)
+        verify(mMockResultReceiver)
                 .send(mResultCodeIntCaptor.capture(), mResultDataBundleCaptor.capture());
         assertEquals(Integer.valueOf(SATELLITE_RESULT_NOT_SUPPORTED),
                 mResultCodeIntCaptor.getValue());
@@ -1135,10 +1678,10 @@ public class SatelliteAccessControllerTest {
         bundle.putBoolean(KEY_SATELLITE_SUPPORTED, true);
         when(mMockCountryDetector.getCurrentNetworkCountryIso())
                 .thenReturn(List.of(TEST_SATELLITE_COUNTRY_CODE_KR));
-        doReturn(true, false).when(mockIterator).hasNext();
-        clearInvocations(mMockSatelliteSupportedResultReceiver);
+        doReturn(true, false).when(mockResultReceiverIterator).hasNext();
+        clearInvocations(mMockResultReceiver);
         mSatelliteAccessControllerUT.handleIsSatelliteSupportedResult(resultCode, bundle);
-        verify(mMockSatelliteSupportedResultReceiver)
+        verify(mMockResultReceiver)
                 .send(mResultCodeIntCaptor.capture(), mResultDataBundleCaptor.capture());
         assertEquals(Integer.valueOf(SATELLITE_RESULT_SUCCESS),
                 mResultCodeIntCaptor.getValue());
@@ -1150,10 +1693,10 @@ public class SatelliteAccessControllerTest {
         when(mMockCountryDetector.getCurrentNetworkCountryIso())
                 .thenReturn(List.of(TEST_SATELLITE_COUNTRY_CODE_US));
         doReturn(false).when(mMockLocationManager).isLocationEnabled();
-        doReturn(true, false).when(mockIterator).hasNext();
-        clearInvocations(mMockSatelliteSupportedResultReceiver);
+        doReturn(true, false).when(mockResultReceiverIterator).hasNext();
+        clearInvocations(mMockResultReceiver);
         mSatelliteAccessControllerUT.handleIsSatelliteSupportedResult(resultCode, bundle);
-        verify(mMockSatelliteSupportedResultReceiver)
+        verify(mMockResultReceiver)
                 .send(mResultCodeIntCaptor.capture(), mResultDataBundleCaptor.capture());
         assertEquals(Integer.valueOf(SATELLITE_RESULT_LOCATION_DISABLED),
                 mResultCodeIntCaptor.getValue());
@@ -1173,7 +1716,7 @@ public class SatelliteAccessControllerTest {
         doReturn(false).when(mMockPhone2).isInEcm();
         doReturn(false).when(mMockSatelliteController).isInEmergencyMode();
         doReturn(true).when(mMockLocationManager).isLocationEnabled();
-        mSatelliteAccessControllerUT.setLocationRequestCancellationSignalAsNull();
+        mSatelliteAccessControllerUT.setLocationRequestCancellationSignalAsNull(true);
         mSatelliteAccessControllerUT.elapsedRealtimeNanos = TEST_LOCATION_FRESH_DURATION_NANOS + 1;
 
         // Invoking requestIsCommunicationAllowedForCurrentLocation(resultReceiver, "false");
@@ -1198,9 +1741,317 @@ public class SatelliteAccessControllerTest {
                 any(Consumer.class));
     }
 
+    @Test
+    public void testUpdateSystemSelectionChannels() {
+        // Set non-emergency case
+        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
+        when(mMockFeatureFlags.carrierRoamingNbIotNtn()).thenReturn(true);
+
+        setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
+        setUpResponseForRequestIsSatelliteProvisioned(true, SATELLITE_RESULT_SUCCESS);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso()).thenReturn(EMPTY_STRING_LIST);
+
+        // Invoke when regional config ID is not set.
+        mSatelliteAccessControllerUT.setRegionalConfigId(null);
+        mSatelliteAccessControllerUT.updateSystemSelectionChannels(
+                mSystemSelectionChannelUpdatedReceiver);
+        mTestableLooper.processAllMessages();
+        assertTrue(waitForRequestUpdateSystemSelectionChannelResult(
+                mSystemSelectionChannelUpdatedSemaphore, 1));
+        assertEquals(SATELLITE_RESULT_ACCESS_BARRED,
+                mQueriedSystemSelectionChannelUpdatedResultCode);
+
+        // Invoke when mSatelliteAccessConfigMap does not have data for given regional config ID
+        int satelliteRegionalConfigId = DEFAULT_REGIONAL_SATELLITE_CONFIG_ID;
+        mSatelliteAccessControllerUT.setRegionalConfigId(satelliteRegionalConfigId);
+        mSatelliteAccessControllerUT.resetSatelliteAccessConfigMap();
+        mSatelliteAccessControllerUT.updateSystemSelectionChannels(
+                mSystemSelectionChannelUpdatedReceiver);
+        mTestableLooper.processAllMessages();
+        assertTrue(waitForRequestUpdateSystemSelectionChannelResult(
+                mSystemSelectionChannelUpdatedSemaphore, 1));
+        assertEquals(SATELLITE_RESULT_ACCESS_BARRED,
+                mQueriedSystemSelectionChannelUpdatedResultCode);
+
+        // Invoke when mSatelliteAccessConfigMap does not have data and given data is old format.
+        satelliteRegionalConfigId = UNKNOWN_REGIONAL_SATELLITE_CONFIG_ID;
+        mSatelliteAccessControllerUT.setRegionalConfigId(satelliteRegionalConfigId);
+        mSatelliteAccessControllerUT.resetSatelliteAccessConfigMap();
+        mSatelliteAccessControllerUT.updateSystemSelectionChannels(
+                mSystemSelectionChannelUpdatedReceiver);
+        mTestableLooper.processAllMessages();
+        assertTrue(waitForRequestUpdateSystemSelectionChannelResult(
+                mSystemSelectionChannelUpdatedSemaphore, 1));
+        assertEquals(SATELLITE_RESULT_ACCESS_BARRED,
+                mQueriedSystemSelectionChannelUpdatedResultCode);
+
+        satelliteRegionalConfigId = DEFAULT_REGIONAL_SATELLITE_CONFIG_ID;
+        // Return success when SatelliteController.updateSystemSelectionChannels was invoked
+        setupResponseForUpdateSystemSelectionChannels(SATELLITE_RESULT_SUCCESS);
+
+        // Invoke updateSystemSelectionChannels when there is corresponding satellite access config.
+        // Create satellite info 1
+        String seed1 = "test-seed-satellite1";
+        UUID uuid1 = UUID.nameUUIDFromBytes(seed1.getBytes());
+        SatellitePosition satellitePosition1 = new SatellitePosition(0, 35876);
+        int[] bands1 = {200, 201, 202};
+        EarfcnRange earfcnRange1 = new EarfcnRange(300, 301);
+        EarfcnRange earfcnRange2 = new EarfcnRange(310, 311);
+        List<EarfcnRange> earfcnRangeList1 = new ArrayList<>(
+                Arrays.asList(earfcnRange1, earfcnRange2));
+        SatelliteInfo satelliteInfo1 = new SatelliteInfo(uuid1, satellitePosition1, Arrays.stream(
+                bands1).boxed().collect(Collectors.toList()), earfcnRangeList1);
+        // Create satellite info 2
+        String seed2 = "test-seed-satellite2";
+        UUID uuid2 = UUID.nameUUIDFromBytes(seed2.getBytes());
+        SatellitePosition satellitePosition2 = new SatellitePosition(120, 35876);
+        int[] bands2 = {210, 211, 212};
+        EarfcnRange earfcnRange3 = new EarfcnRange(320, 321);
+        EarfcnRange earfcnRange4 = new EarfcnRange(330, 331);
+        List<EarfcnRange> earfcnRangeList2 = new ArrayList<>(
+                Arrays.asList(earfcnRange3, earfcnRange4));
+        SatelliteInfo satelliteInfo2 = new SatelliteInfo(uuid2, satellitePosition2, Arrays.stream(
+                bands2).boxed().collect(Collectors.toList()), earfcnRangeList2);
+        // Create satellite info 3
+        String seed3 = "test-seed-satellite3";
+        UUID uuid3 = UUID.nameUUIDFromBytes(seed3.getBytes());
+        SatellitePosition satellitePosition3 = new SatellitePosition(120, 35876);
+        int[] bands3 = {220, 221, 222};
+        EarfcnRange earfcnRange5 = new EarfcnRange(340, 341);
+        EarfcnRange earfcnRange6 = new EarfcnRange(350, 351);
+        List<EarfcnRange> earfcnRangeList3 = new ArrayList<>(
+                Arrays.asList(earfcnRange5, earfcnRange6));
+        SatelliteInfo satelliteInfo3 = new SatelliteInfo(uuid3, satellitePosition3, Arrays.stream(
+                bands3).boxed().collect(Collectors.toList()), earfcnRangeList3);
+
+        int[] tagIds = {1, 2, 3};
+        SatelliteAccessConfiguration satelliteAccessConfiguration =
+                new SatelliteAccessConfiguration(new ArrayList<>(
+                        Arrays.asList(satelliteInfo1, satelliteInfo2, satelliteInfo3)),
+                        Arrays.stream(tagIds).boxed().collect(Collectors.toList()));
+
+        // Add satellite access configuration to map
+        mSatelliteAccessControllerUT.setSatelliteAccessConfigMap(satelliteRegionalConfigId,
+                satelliteAccessConfiguration);
+
+        // Invoke updateSystemSelectionChannel
+        mSatelliteAccessControllerUT.updateSystemSelectionChannels(
+                mSystemSelectionChannelUpdatedReceiver);
+        mTestableLooper.processAllMessages();
+        assertTrue(waitForRequestUpdateSystemSelectionChannelResult(
+                mSystemSelectionChannelUpdatedSemaphore, 1));
+        assertEquals(SATELLITE_RESULT_SUCCESS,
+                mQueriedSystemSelectionChannelUpdatedResultCode);
+        ArgumentCaptor<List<SystemSelectionSpecifier>> systemSelectionSpecifierListCaptor =
+                ArgumentCaptor.forClass(List.class);
+        verify(mMockSatelliteController, times(1)).updateSystemSelectionChannels(
+                systemSelectionSpecifierListCaptor.capture(), any(ResultReceiver.class));
+        List<SystemSelectionSpecifier> capturedList = systemSelectionSpecifierListCaptor.getValue();
+        SystemSelectionSpecifier systemSelectionSpecifier = capturedList.getFirst();
+
+        // Verify the fields value of given systemSelectionSpecifier matched with expected.
+        int[] expectedBandsArray = IntStream.concat(
+                IntStream.concat(Arrays.stream(bands1), Arrays.stream(bands2)),
+                Arrays.stream(bands3)).toArray();
+        int[] actualBandsArray = systemSelectionSpecifier.getBands();
+        assertArrayEquals(expectedBandsArray, actualBandsArray);
+
+        int[] expectedEarfcnsArray = {300, 301, 310, 311, 320, 321, 330, 331, 340, 341, 350, 351};
+        int[] actualEarfcnsArray = systemSelectionSpecifier.getEarfcns();
+        assertArrayEquals(expectedEarfcnsArray, actualEarfcnsArray);
+
+        SatelliteInfo[] expectedSatelliteInfos = {satelliteInfo1, satelliteInfo2, satelliteInfo3};
+        assertArrayEquals(expectedSatelliteInfos,
+                systemSelectionSpecifier.getSatelliteInfos().toArray(new SatelliteInfo[0]));
+
+        int[] actualTagIdArray = systemSelectionSpecifier.getTagIds();
+        assertArrayEquals(tagIds, actualTagIdArray);
+
+        // Verify backward compatibility when there is valid data for default regional config ID
+        satelliteRegionalConfigId = UNKNOWN_REGIONAL_SATELLITE_CONFIG_ID;
+        mSatelliteAccessControllerUT.setRegionalConfigId(satelliteRegionalConfigId);
+        mSatelliteAccessControllerUT.updateSystemSelectionChannels(
+                mSystemSelectionChannelUpdatedReceiver);
+        mTestableLooper.processAllMessages();
+
+        // updateSelectionChannelResult will be invoked with the data for default regional config ID
+        assertTrue(waitForRequestUpdateSystemSelectionChannelResult(
+                mSystemSelectionChannelUpdatedSemaphore, 1));
+        systemSelectionSpecifierListCaptor = ArgumentCaptor.forClass(List.class);
+        verify(mMockSatelliteController, times(2)).updateSystemSelectionChannels(
+                systemSelectionSpecifierListCaptor.capture(), any(ResultReceiver.class));
+        capturedList = systemSelectionSpecifierListCaptor.getValue();
+        systemSelectionSpecifier = capturedList.getFirst();
+
+        // Data will be same with default regional config ID
+
+        // Verify the fields value of given systemSelectionSpecifier matched with expected.
+        actualBandsArray = systemSelectionSpecifier.getBands();
+        assertArrayEquals(expectedBandsArray, actualBandsArray);
+
+        actualEarfcnsArray = systemSelectionSpecifier.getEarfcns();
+        assertArrayEquals(expectedEarfcnsArray, actualEarfcnsArray);
+
+        assertArrayEquals(expectedSatelliteInfos,
+                systemSelectionSpecifier.getSatelliteInfos().toArray(new SatelliteInfo[0]));
+
+        actualTagIdArray = systemSelectionSpecifier.getTagIds();
+        assertArrayEquals(tagIds, actualTagIdArray);
+
+        mSatelliteAccessControllerUT.resetSatelliteAccessConfigMap();
+    }
+
+    @Test
+    public void testUpdateSystemSelectionChannels_HandleInvalidInput() {
+        // Set non-emergency case
+        when(mMockFeatureFlags.oemEnabledSatelliteFlag()).thenReturn(true);
+        when(mMockFeatureFlags.carrierRoamingNbIotNtn()).thenReturn(true);
+
+        setUpResponseForRequestIsSatelliteSupported(true, SATELLITE_RESULT_SUCCESS);
+        setUpResponseForRequestIsSatelliteProvisioned(true, SATELLITE_RESULT_SUCCESS);
+        when(mMockCountryDetector.getCurrentNetworkCountryIso()).thenReturn(EMPTY_STRING_LIST);
+        int satelliteRegionalConfigId = DEFAULT_REGIONAL_SATELLITE_CONFIG_ID;
+        mSatelliteAccessControllerUT.setRegionalConfigId(satelliteRegionalConfigId);
+        // Set return success when SatelliteController.updateSystemSelectionChannels was invoked
+        setupResponseForUpdateSystemSelectionChannels(SATELLITE_RESULT_SUCCESS);
+
+        // Create satellite info in which satellite position is null.
+        String seed1 = "test-seed-satellite1";
+        UUID uuid1 = UUID.nameUUIDFromBytes(seed1.getBytes());
+        SatellitePosition satellitePosition1 = null;
+        List<Integer> bandList1 = new ArrayList<>(List.of(200, 201, 202));
+        EarfcnRange earfcnRange1 = new EarfcnRange(300, 301);
+        EarfcnRange earfcnRange2 = new EarfcnRange(310, 311);
+        List<EarfcnRange> earfcnRangeList1 = new ArrayList<>(
+                Arrays.asList(earfcnRange1, earfcnRange2));
+        SatelliteInfo satelliteInfo1 = new SatelliteInfo(uuid1, satellitePosition1, bandList1,
+                earfcnRangeList1);
+
+        // Create satellite info in which band list is empty
+        String seed2 = "test-seed-satellite2";
+        UUID uuid2 = UUID.nameUUIDFromBytes(seed2.getBytes());
+        SatellitePosition satellitePosition2 = new SatellitePosition(120, 35876);
+        List<Integer> bandList2 = new ArrayList<>();
+        EarfcnRange earfcnRange3 = new EarfcnRange(320, 321);
+        EarfcnRange earfcnRange4 = new EarfcnRange(330, 331);
+        List<EarfcnRange> earfcnRangeList2 = new ArrayList<>(
+                Arrays.asList(earfcnRange3, earfcnRange4));
+        SatelliteInfo satelliteInfo2 = new SatelliteInfo(uuid2, satellitePosition2, bandList2,
+                earfcnRangeList2);
+
+        // Create satellite info 3, every field is valid
+        String seed3 = "test-seed-satellite3";
+        UUID uuid3 = UUID.nameUUIDFromBytes(seed3.getBytes());
+        SatellitePosition satellitePosition3 = new SatellitePosition(120, 35876);
+        List<Integer> bandList3 = new ArrayList<>(List.of(220, 221, 222));
+        EarfcnRange earfcnRange5 = new EarfcnRange(340, 341);
+        EarfcnRange earfcnRange6 = new EarfcnRange(350, 351);
+        List<EarfcnRange> earfcnRangeList3 = new ArrayList<>(
+                Arrays.asList(earfcnRange5, earfcnRange6));
+        SatelliteInfo satelliteInfo3 = new SatelliteInfo(uuid3, satellitePosition3, bandList3,
+                earfcnRangeList3);
+        // Add empty tagId list
+        List<Integer> tagIdList = new ArrayList<>();
+
+        // Create satelliteAccessConfiguration with some of files of added Satellite info are empty.
+        SatelliteAccessConfiguration satelliteAccessConfiguration1 =
+                new SatelliteAccessConfiguration(new ArrayList<>(
+                        Arrays.asList(satelliteInfo1, satelliteInfo2, satelliteInfo3)), tagIdList);
+
+        // Add satellite access configuration to map
+        mSatelliteAccessControllerUT.setSatelliteAccessConfigMap(satelliteRegionalConfigId,
+                satelliteAccessConfiguration1);
+
+        // Invoke updateSystemSelectionChannel
+        mSatelliteAccessControllerUT.updateSystemSelectionChannels(
+                mSystemSelectionChannelUpdatedReceiver);
+        mTestableLooper.processAllMessages();
+        assertTrue(waitForRequestUpdateSystemSelectionChannelResult(
+                mSystemSelectionChannelUpdatedSemaphore, 1));
+        assertEquals(SATELLITE_RESULT_SUCCESS,
+                mQueriedSystemSelectionChannelUpdatedResultCode);
+        ArgumentCaptor<List<SystemSelectionSpecifier>> systemSelectionSpecifierListCaptor =
+                ArgumentCaptor.forClass(List.class);
+        verify(mMockSatelliteController, times(1)).updateSystemSelectionChannels(
+                systemSelectionSpecifierListCaptor.capture(), any(ResultReceiver.class));
+        List<SystemSelectionSpecifier> capturedList = systemSelectionSpecifierListCaptor.getValue();
+        SystemSelectionSpecifier systemSelectionSpecifier = capturedList.getFirst();
+
+        // Verify the fields value of given systemSelectionSpecifier matched with expected.
+        List<Integer> expectedBandList = new ArrayList<>(bandList1);
+        expectedBandList.addAll(bandList2);
+        expectedBandList.addAll(bandList3);
+
+        List<Integer> actualBandList = Arrays.stream(systemSelectionSpecifier.getBands()).boxed()
+                .collect(Collectors.toList());
+        assertEquals(expectedBandList, actualBandList);
+
+        List<Integer> expectedEarfcnList = new ArrayList<>(
+                List.of(300, 301, 310, 311, 320, 321, 330, 331, 340, 341, 350, 351));
+        List<Integer> actualEarfcnList = Arrays.stream(systemSelectionSpecifier.getEarfcns())
+                .boxed().collect(Collectors.toList());
+        assertEquals(expectedEarfcnList, actualEarfcnList);
+
+        assertEquals(satelliteInfo1, systemSelectionSpecifier.getSatelliteInfos().get(0));
+        assertEquals(satelliteInfo2, systemSelectionSpecifier.getSatelliteInfos().get(1));
+        assertEquals(satelliteInfo3, systemSelectionSpecifier.getSatelliteInfos().get(2));
+
+        List<Integer> actualTagIdList = Arrays.stream(systemSelectionSpecifier.getTagIds()).boxed()
+                .collect(Collectors.toList());
+        assertEquals(tagIdList, actualTagIdList);
+
+        // Create satelliteAccessConfiguration with empty list of SatelliteInfo.
+        SatelliteAccessConfiguration satelliteAccessConfiguration2 =
+                new SatelliteAccessConfiguration(new ArrayList<>(), tagIdList);
+        mSatelliteAccessControllerUT.setSatelliteAccessConfigMap(
+                DEFAULT_REGIONAL_SATELLITE_CONFIG_ID, satelliteAccessConfiguration2);
+
+        // Invoke updateSystemSelectionChannel
+        mSatelliteAccessControllerUT.updateSystemSelectionChannels(
+                mSystemSelectionChannelUpdatedReceiver);
+        mTestableLooper.processAllMessages();
+        assertTrue(waitForRequestUpdateSystemSelectionChannelResult(
+                mSystemSelectionChannelUpdatedSemaphore, 1));
+        assertEquals(SATELLITE_RESULT_SUCCESS,
+                mQueriedSystemSelectionChannelUpdatedResultCode);
+        systemSelectionSpecifierListCaptor = ArgumentCaptor.forClass(List.class);
+        verify(mMockSatelliteController, times(2)).updateSystemSelectionChannels(
+                systemSelectionSpecifierListCaptor.capture(), any(ResultReceiver.class));
+        capturedList = systemSelectionSpecifierListCaptor.getValue();
+        systemSelectionSpecifier = capturedList.getFirst();
+
+        // Verify the fields value of given systemSelectionSpecifier matched with expected.
+        assertEquals(0, systemSelectionSpecifier.getBands().length);
+        assertEquals(0, systemSelectionSpecifier.getEarfcns().length);
+
+        SatelliteInfo[] expectedSatelliteInfoArray = new SatelliteInfo[0];
+        assertArrayEquals(expectedSatelliteInfoArray,
+                systemSelectionSpecifier.getSatelliteInfos().toArray(new SatelliteInfo[0]));
+
+        actualTagIdList = Arrays.stream(systemSelectionSpecifier.getTagIds()).boxed().collect(
+                Collectors.toList());
+        assertEquals(tagIdList, actualTagIdList);
+
+        mSatelliteAccessControllerUT.resetSatelliteAccessConfigMap();
+    }
+
+    @Test
+    public void testCheckSharedPreferenceException() {
+        doReturn(mMockSharedPreferencesEditor).when(mMockSharedPreferencesEditor)
+                .remove(anyString());
+        doThrow(new ClassCastException()).when(mMockSharedPreferences)
+                .getBoolean(anyString(), eq(false));
+
+        mSatelliteAccessControllerUT = new TestSatelliteAccessController(mMockContext,
+                mMockFeatureFlags, mTestableLooper.getLooper(), mMockLocationManager,
+                mMockTelecomManager, mMockSatelliteOnDeviceAccessController, mMockSatS2File);
+
+        verify(mMockSharedPreferencesEditor, times(4)).remove(anyString());
+    }
+
     private void sendSatelliteCommunicationAllowedEvent() {
         Pair<Integer, ResultReceiver> requestPair =
-                new Pair<>(SubscriptionManager.DEFAULT_SUBSCRIPTION_ID,
+                new Pair<>(DEFAULT_SUBSCRIPTION_ID,
                         mSatelliteAccessControllerUT.getResultReceiverCurrentLocation());
         Message msg = mSatelliteAccessControllerUT.obtainMessage(
                 CMD_IS_SATELLITE_COMMUNICATION_ALLOWED);
@@ -1209,6 +2060,12 @@ public class SatelliteAccessControllerTest {
         mTestableLooper.processAllMessages();
     }
 
+    private void sendSatelliteDeviceAccessControllerResourcesTimeOutEvent() {
+        Message msg = mSatelliteAccessControllerUT
+                .obtainMessage(EVENT_KEEP_ON_DEVICE_ACCESS_CONTROLLER_RESOURCES_TIMEOUT);
+        msg.sendToTarget();
+        mTestableLooper.processAllMessages();
+    }
 
     private void sendConfigUpdateChangedEvent(Context context) {
         Message msg = mSatelliteAccessControllerUT.obtainMessage(EVENT_CONFIG_DATA_UPDATED);
@@ -1217,6 +2074,13 @@ public class SatelliteAccessControllerTest {
         mTestableLooper.processAllMessages();
     }
 
+    private void sendCurrentLocationTimeoutEvent() {
+        Message msg = mSatelliteAccessControllerUT
+                .obtainMessage(EVENT_WAIT_FOR_CURRENT_LOCATION_TIMEOUT);
+        msg.sendToTarget();
+        mTestableLooper.processAllMessages();
+    }
+
     private void sendCommandValidateCountryCodeChangeEvent(Context context) {
         Message msg = mSatelliteAccessControllerUT.obtainMessage(EVENT_COUNTRY_CODE_CHANGED);
         msg.obj = new AsyncResult(context, SATELLITE_RESULT_SUCCESS, null);
@@ -1255,6 +2119,24 @@ public class SatelliteAccessControllerTest {
         return true;
     }
 
+    private boolean waitForRequestUpdateSystemSelectionChannelResult(Semaphore semaphore,
+            int expectedNumberOfEvents) {
+        for (int i = 0; i < expectedNumberOfEvents; i++) {
+            try {
+                if (!semaphore.tryAcquire(TIMEOUT, TimeUnit.MILLISECONDS)) {
+                    logd("Timeout to receive "
+                            + "updateSystemSelectionChannel()"
+                            + " callback");
+                    return false;
+                }
+            } catch (Exception ex) {
+                logd("updateSystemSelectionChannel: Got exception=" + ex);
+                return false;
+            }
+        }
+        return true;
+    }
+
     private void sendLocationRequestResult(Location location) {
         mLocationRequestConsumerCaptor.getValue().accept(location);
         mTestableLooper.processAllMessages();
@@ -1291,6 +2173,16 @@ public class SatelliteAccessControllerTest {
         }).when(mMockSatelliteController).requestIsSatelliteProvisioned(any(ResultReceiver.class));
     }
 
+    private void setupResponseForUpdateSystemSelectionChannels(
+            @SatelliteManager.SatelliteResult int error) {
+        doAnswer(invocation -> {
+            ResultReceiver resultReceiver = invocation.getArgument(1);
+            resultReceiver.send(error, null);
+            return null;
+        }).when(mMockSatelliteController).updateSystemSelectionChannels(anyList(),
+                any(ResultReceiver.class));
+    }
+
     @SafeVarargs
     private static <E> List<E> listOf(E... values) {
         return Arrays.asList(values);
@@ -1300,13 +2192,6 @@ public class SatelliteAccessControllerTest {
         Log.d(TAG, message);
     }
 
-    private static void replaceInstance(final Class c,
-            final String instanceName, final Object obj, final Object newValue) throws Exception {
-        Field field = c.getDeclaredField(instanceName);
-        field.setAccessible(true);
-        field.set(obj, newValue);
-    }
-
     private static class TestSatelliteAccessController extends SatelliteAccessController {
         public long elapsedRealtimeNanos = 0;
 
@@ -1382,9 +2267,55 @@ public class SatelliteAccessControllerTest {
             return mLocationModeChangedBroadcastReceiver;
         }
 
-        public void setLocationRequestCancellationSignalAsNull() {
+        public void setLocationRequestCancellationSignalAsNull(boolean isNull) {
             synchronized (mLock) {
-                mLocationRequestCancellationSignal = null;
+                mLocationRequestCancellationSignal = isNull ? null : new CancellationSignal();
+            }
+        }
+
+        public boolean isCurrentSatelliteAllowedState() {
+            synchronized (mSatelliteCommunicationAllowStateLock) {
+                return mCurrentSatelliteAllowedState;
+            }
+        }
+
+        @Nullable
+        public Integer getRegionalConfigId() {
+            synchronized (mLock) {
+                return mRegionalConfigId;
+            }
+        }
+
+        @Nullable
+        public Integer getNewRegionalConfigId() {
+            synchronized (mLock) {
+                return mNewRegionalConfigId;
+            }
+        }
+
+        public void setRegionalConfigId(@Nullable Integer regionalConfigId) {
+            synchronized (mLock) {
+                mRegionalConfigId = regionalConfigId;
+            }
+        }
+
+        public void setSatelliteAccessConfigMap(int regionalConfigId,
+                SatelliteAccessConfiguration satelliteAccessConfiguration) {
+            synchronized (mLock) {
+                if (mSatelliteAccessConfigMap == null) {
+                    mSatelliteAccessConfigMap = new HashMap<>();
+                }
+                mSatelliteAccessConfigMap.put(regionalConfigId, satelliteAccessConfiguration);
+            }
+        }
+
+        public void resetSatelliteAccessConfigMap() {
+            synchronized (mLock) {
+                if (mSatelliteAccessConfigMap == null) {
+                    mSatelliteAccessConfigMap = new HashMap<>();
+                } else {
+                    mSatelliteAccessConfigMap.clear();
+                }
             }
         }
     }
diff --git a/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementControllerTest.java b/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementControllerTest.java
index e66351910..a3b38df7c 100644
--- a/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementControllerTest.java
+++ b/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementControllerTest.java
@@ -16,10 +16,18 @@
 
 package com.android.phone.satellite.entitlement;
 
+import static android.telephony.CarrierConfigManager.SATELLITE_DATA_SUPPORT_ALL;
+import static android.telephony.CarrierConfigManager.SATELLITE_DATA_SUPPORT_BANDWIDTH_CONSTRAINED;
+import static android.telephony.NetworkRegistrationInfo.SERVICE_TYPE_DATA;
+import static android.telephony.NetworkRegistrationInfo.SERVICE_TYPE_VOICE;
+
+import static com.android.internal.telephony.satellite.SatelliteController.SATELLITE_DATA_PLAN_METERED;
+import static com.android.internal.telephony.satellite.SatelliteController.SATELLITE_DATA_PLAN_UNMETERED;
 import static com.android.libraries.entitlement.ServiceEntitlementException.ERROR_HTTP_STATUS_NOT_SUCCESS;
 import static com.android.phone.satellite.entitlement.SatelliteEntitlementResult.SATELLITE_ENTITLEMENT_STATUS_DISABLED;
 import static com.android.phone.satellite.entitlement.SatelliteEntitlementResult.SATELLITE_ENTITLEMENT_STATUS_ENABLED;
 
+import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
@@ -27,6 +35,7 @@ import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyList;
+import static org.mockito.ArgumentMatchers.anyMap;
 import static org.mockito.ArgumentMatchers.anyVararg;
 import static org.mockito.Mockito.clearInvocations;
 import static org.mockito.Mockito.doAnswer;
@@ -46,18 +55,16 @@ import android.net.Network;
 import android.net.NetworkCapabilities;
 import android.net.wifi.WifiInfo;
 import android.os.Handler;
-import android.os.HandlerThread;
 import android.os.Looper;
-import android.os.Message;
 import android.os.PersistableBundle;
 import android.telephony.CarrierConfigManager;
 import android.telephony.TelephonyManager;
+import android.testing.AndroidTestingRunner;
 import android.testing.TestableLooper;
 import android.util.Log;
 import android.util.Pair;
 
 import androidx.annotation.NonNull;
-import androidx.test.ext.junit.runners.AndroidJUnit4;
 
 import com.android.TelephonyTestBase;
 import com.android.internal.telephony.ExponentialBackoff;
@@ -70,7 +77,6 @@ import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.Mock;
-import org.mockito.MockitoAnnotations;
 import org.mockito.invocation.InvocationOnMock;
 import org.mockito.stubbing.Answer;
 
@@ -83,7 +89,8 @@ import java.util.Map;
 import java.util.concurrent.Executor;
 import java.util.concurrent.TimeUnit;
 
-@RunWith(AndroidJUnit4.class)
+@RunWith(AndroidTestingRunner.class)
+@TestableLooper.RunWithLooper
 public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
     private static final String TAG = "SatelliteEntitlementControllerTest";
     private static final int SUB_ID = 0;
@@ -92,15 +99,34 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
     private static final int DEFAULT_QUERY_REFRESH_DAY = 7;
     private static final List<String> PLMN_ALLOWED_LIST = Arrays.asList("31026", "302820");
     private static final List<String> PLMN_BARRED_LIST = Arrays.asList("12345", "98765");
+    private static final Map<String, Integer> PLMN_DATA_PLAN_LIST = Map.of(
+            "31026", SATELLITE_DATA_PLAN_METERED,
+            "302820", SATELLITE_DATA_PLAN_UNMETERED);
     private static final List<String> EMPTY_PLMN_LIST = new ArrayList<>();
+    private static final Map<String, Integer> EMPTY_PLMN_DATA_PLAN_LIST = new HashMap<>();
+    private static final Map<String, List<Integer>> PLMN_ALLOWED_SERVICES_LIST = Map.of(
+            "31026", List.of(SERVICE_TYPE_DATA),
+            "302820", List.of(SERVICE_TYPE_DATA, SERVICE_TYPE_VOICE)
+    );
+    private static final Map<String, Integer> PLMN_DATA_SERVICE_POLICY_LIST = Map.of(
+            "31026", SATELLITE_DATA_SUPPORT_BANDWIDTH_CONSTRAINED,
+            "302820", SATELLITE_DATA_SUPPORT_ALL);
+    private static final Map<String, Integer> PLMN_VOICE_SERVICE_POLICY_LIST = Map.of(
+            "31026", SATELLITE_DATA_SUPPORT_ALL,
+            "302820", SATELLITE_DATA_SUPPORT_BANDWIDTH_CONSTRAINED
+    );
+    private static final Map<String, List<Integer>> EMPTY_PLMN_ALLOWED_SERVICES_LIST =
+            new HashMap<>();
+    private static final Map<String, Integer> EMPTY_PLMN_DATA_SERVICE_POLICY_LIST =
+            new HashMap<>();
+    private static final Map<String, Integer> EMPTY_PLMN_VOICE_SERVICE_POLICY_LIST =
+            new HashMap<>();
     private static final int CMD_START_QUERY_ENTITLEMENT = 1;
     private static final int CMD_RETRY_QUERY_ENTITLEMENT = 2;
     private static final int CMD_SIM_REFRESH = 3;
     private static final int MAX_RETRY_COUNT = 5;
-    @Mock
-    CarrierConfigManager mCarrierConfigManager;
-    @Mock
-    ConnectivityManager mConnectivityManager;
+    @Mock CarrierConfigManager mCarrierConfigManager;
+    @Mock ConnectivityManager mConnectivityManager;
     @Mock Network mNetwork;
     @Mock TelephonyManager mTelephonyManager;
     @Mock SubscriptionManagerService mMockSubscriptionManagerService;
@@ -113,23 +139,17 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
     private TestableLooper mTestableLooper;
     private List<Pair<Executor, CarrierConfigManager.CarrierConfigChangeListener>>
             mCarrierConfigChangedListenerList = new ArrayList<>();
+
     @Before
     public void setUp() throws Exception {
         super.setUp();
-        MockitoAnnotations.initMocks(this);
 
         replaceInstance(SubscriptionManagerService.class, "sInstance", null,
                 mMockSubscriptionManagerService);
         replaceInstance(SatelliteController.class, "sInstance", null, mSatelliteController);
 
-        HandlerThread handlerThread = new HandlerThread("SatelliteEntitlementController");
-        handlerThread.start();
-        mHandler = new Handler(handlerThread.getLooper()) {
-            @Override
-            public void handleMessage(Message msg) {
-            }
-        };
-        mTestableLooper = new TestableLooper(mHandler.getLooper());
+        mTestableLooper = TestableLooper.get(this);
+        mHandler = new Handler(mTestableLooper.getLooper());
         doReturn(Context.TELEPHONY_SERVICE).when(mContext).getSystemServiceName(
                 TelephonyManager.class);
         doReturn(mTelephonyManager).when(mContext).getSystemService(Context.TELEPHONY_SERVICE);
@@ -160,9 +180,8 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
                 Context.CONNECTIVITY_SERVICE);
         doReturn(mNetwork).when(mConnectivityManager).getActiveNetwork();
         doReturn(ACTIVE_SUB_ID).when(mMockSubscriptionManagerService).getActiveSubIdList(true);
-        mSatelliteEntitlementController = new TestSatelliteEntitlementController(mContext,
-                mHandler.getLooper(), mSatelliteEntitlementApi);
-        mSatelliteEntitlementController = spy(mSatelliteEntitlementController);
+        mSatelliteEntitlementController = spy(new TestSatelliteEntitlementController(mContext,
+                mTestableLooper.getLooper(), mSatelliteEntitlementApi));
         doReturn(mSatelliteEntitlementResult).when(
                 mSatelliteEntitlementApi).checkEntitlementStatus();
     }
@@ -174,7 +193,6 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
 
     @Test
     public void testShouldStartQueryEntitlement() throws Exception {
-        logd("testShouldStartQueryEntitlement");
         doReturn(ACTIVE_SUB_ID).when(mMockSubscriptionManagerService).getActiveSubIdList(true);
 
         // Verify don't start the query when KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL is false.
@@ -184,7 +202,7 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
 
         verify(mSatelliteEntitlementApi, never()).checkEntitlementStatus();
         verify(mSatelliteController, never()).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
 
         mCarrierConfigBundle.putBoolean(
                 CarrierConfigManager.KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL, true);
@@ -195,7 +213,7 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
 
         verify(mSatelliteEntitlementApi, never()).checkEntitlementStatus();
         verify(mSatelliteController, never()).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
 
         setInternetConnected(true);
         // Verify don't start the query when last query refresh time is not expired.
@@ -204,7 +222,7 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
 
         verify(mSatelliteEntitlementApi, never()).checkEntitlementStatus();
         verify(mSatelliteController, never()).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
 
         setLastQueryTime(0L);
         // Verify don't start the query when retry count is reached max
@@ -217,7 +235,7 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
 
         verify(mSatelliteEntitlementApi, never()).checkEntitlementStatus();
         verify(mSatelliteController, never()).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
 
         replaceInstance(SatelliteEntitlementController.class, "mRetryCountPerSub",
                 mSatelliteEntitlementController, new HashMap<>());
@@ -231,7 +249,7 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
 
         verify(mSatelliteEntitlementApi, never()).checkEntitlementStatus();
         verify(mSatelliteController, never()).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
 
         replaceInstance(SatelliteEntitlementController.class, "mIsEntitlementInProgressPerSub",
                 mSatelliteEntitlementController, new HashMap<>());
@@ -239,17 +257,17 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         doReturn(mSatelliteEntitlementResult).when(
                 mSatelliteEntitlementApi).checkEntitlementStatus();
         setSatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_ENABLED, PLMN_ALLOWED_LIST,
-                PLMN_BARRED_LIST);
+                PLMN_BARRED_LIST, PLMN_DATA_PLAN_LIST, PLMN_ALLOWED_SERVICES_LIST,
+                PLMN_DATA_SERVICE_POLICY_LIST, PLMN_VOICE_SERVICE_POLICY_LIST);
         mSatelliteEntitlementController.handleCmdStartQueryEntitlement();
 
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
     }
 
     @Test
     public void testCheckSatelliteEntitlementStatus() throws Exception {
-        logd("testCheckSatelliteEntitlementStatus");
         setIsQueryAvailableTrue();
         // Verify don't call the checkSatelliteEntitlementStatus when getActiveSubIdList is empty.
         doReturn(new int[]{}).when(mMockSubscriptionManagerService).getActiveSubIdList(true);
@@ -258,7 +276,7 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         verify(mSatelliteEntitlementApi, never()).checkEntitlementStatus();
         // Verify don't call the updateSatelliteEntitlementStatus.
         verify(mSatelliteController, never()).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
 
         // Verify call the checkSatelliteEntitlementStatus with invalid response.
         setIsQueryAvailableTrue();
@@ -273,7 +291,10 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         // Verify call the updateSatelliteEntitlementStatus with satellite service is disabled
         // , empty PLMNAllowed and empty PLMNBarred.
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(eq(SUB_ID),
-                eq(false), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST), any());
+                eq(false), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST),
+                eq(EMPTY_PLMN_DATA_PLAN_LIST), eq(EMPTY_PLMN_ALLOWED_SERVICES_LIST),
+                eq(EMPTY_PLMN_DATA_SERVICE_POLICY_LIST), eq(EMPTY_PLMN_VOICE_SERVICE_POLICY_LIST),
+                any());
 
         // Verify call the checkSatelliteEntitlementStatus with the subscribed result.
         clearInvocationsForMock();
@@ -281,14 +302,17 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         doReturn(mSatelliteEntitlementResult).when(
                 mSatelliteEntitlementApi).checkEntitlementStatus();
         setSatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_ENABLED, PLMN_ALLOWED_LIST,
-                PLMN_BARRED_LIST);
+                PLMN_BARRED_LIST, PLMN_DATA_PLAN_LIST, PLMN_ALLOWED_SERVICES_LIST,
+                PLMN_DATA_SERVICE_POLICY_LIST, PLMN_VOICE_SERVICE_POLICY_LIST);
         mSatelliteEntitlementController.handleCmdStartQueryEntitlement();
 
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         // Verify call the updateSatelliteEntitlementStatus with satellite service is enable,
         // availablePLMNAllowedList and availablePLMNBarredList.
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(eq(SUB_ID), eq(true),
-                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), any());
+                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), eq(PLMN_DATA_PLAN_LIST),
+                eq(PLMN_ALLOWED_SERVICES_LIST), eq(PLMN_DATA_SERVICE_POLICY_LIST),
+                eq(PLMN_VOICE_SERVICE_POLICY_LIST), any());
 
         // Change subId and verify call the updateSatelliteEntitlementStatus with satellite
         // service is enable, availablePLMNAllowedList and availablePLMNBarredList
@@ -299,48 +323,58 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
 
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(eq(SUB_ID_2), eq(true),
-                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), any());
+                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), eq(PLMN_DATA_PLAN_LIST),
+                eq(PLMN_ALLOWED_SERVICES_LIST), eq(PLMN_DATA_SERVICE_POLICY_LIST),
+                eq(PLMN_VOICE_SERVICE_POLICY_LIST), any());
 
         // Verify call the updateSatelliteEntitlementStatus with satellite service is enable,
         // availablePLMNAllowedList and empty plmn barred list.
         clearInvocationsForMock();
         setIsQueryAvailableTrue();
         setSatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_ENABLED, PLMN_ALLOWED_LIST,
-                new ArrayList<>());
+                new ArrayList<>(), new HashMap<>(), new HashMap<>(), new HashMap<>(),
+                new HashMap<>());
         mSatelliteEntitlementController.handleCmdStartQueryEntitlement();
 
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(eq(SUB_ID), eq(true),
-                eq(PLMN_ALLOWED_LIST), eq(EMPTY_PLMN_LIST), any());
+                eq(PLMN_ALLOWED_LIST), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_DATA_PLAN_LIST),
+                eq(EMPTY_PLMN_ALLOWED_SERVICES_LIST), eq(EMPTY_PLMN_DATA_SERVICE_POLICY_LIST),
+                eq(EMPTY_PLMN_VOICE_SERVICE_POLICY_LIST), any());
 
         // Verify call the updateSatelliteEntitlementStatus with satellite service is enable,
         // empty PLMNAllowedList and PLMNBarredList.
         clearInvocationsForMock();
         setIsQueryAvailableTrue();
         setSatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_ENABLED, new ArrayList<>(),
-                new ArrayList<>());
+                new ArrayList<>(), new HashMap<>(), new HashMap<>(), new HashMap<>(),
+                new HashMap<>());
         mSatelliteEntitlementController.handleCmdStartQueryEntitlement();
 
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(eq(SUB_ID), eq(true),
-                eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST), any());
+                eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_DATA_PLAN_LIST),
+                eq(EMPTY_PLMN_ALLOWED_SERVICES_LIST), eq(EMPTY_PLMN_DATA_SERVICE_POLICY_LIST),
+                eq(EMPTY_PLMN_VOICE_SERVICE_POLICY_LIST), any());
 
         // Verify call the updateSatelliteEntitlementStatus with satellite service is enable,
         // empty PLMNAllowedList and availablePLMNBarredList.
         clearInvocationsForMock();
         setIsQueryAvailableTrue();
         setSatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_ENABLED, new ArrayList<>(),
-                PLMN_BARRED_LIST);
+                PLMN_BARRED_LIST, PLMN_DATA_PLAN_LIST, PLMN_ALLOWED_SERVICES_LIST,
+                PLMN_DATA_SERVICE_POLICY_LIST, PLMN_VOICE_SERVICE_POLICY_LIST);
         mSatelliteEntitlementController.handleCmdStartQueryEntitlement();
 
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(eq(SUB_ID), eq(true),
-                eq(EMPTY_PLMN_LIST), eq(PLMN_BARRED_LIST), any());
+                eq(EMPTY_PLMN_LIST), eq(PLMN_BARRED_LIST), eq(PLMN_DATA_PLAN_LIST),
+                eq(PLMN_ALLOWED_SERVICES_LIST), eq(PLMN_DATA_SERVICE_POLICY_LIST),
+                eq(PLMN_VOICE_SERVICE_POLICY_LIST), any());
     }
 
     @Test
     public void testCheckSatelliteEntitlementStatusWhenInternetConnected() throws Exception {
-        logd("testCheckSatelliteEntitlementStatusWhenInternetConnected");
         ConnectivityManager.NetworkCallback networkCallback =
                 (ConnectivityManager.NetworkCallback) getValue("mNetworkCallback");
         Network mockNetwork = mock(Network.class);
@@ -349,7 +383,8 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         setInternetConnected(true);
         setLastQueryTime(0L);
         setSatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_ENABLED, PLMN_ALLOWED_LIST,
-                PLMN_BARRED_LIST);
+                PLMN_BARRED_LIST, PLMN_DATA_PLAN_LIST, PLMN_ALLOWED_SERVICES_LIST,
+                PLMN_DATA_SERVICE_POLICY_LIST, PLMN_VOICE_SERVICE_POLICY_LIST);
 
         networkCallback.onAvailable(mockNetwork);
         mTestableLooper.processAllMessages();
@@ -357,29 +392,32 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         // Verify call the updateSatelliteEntitlementStatus with satellite service is available.
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(eq(SUB_ID), eq(true),
-                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), any());
+                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), eq(PLMN_DATA_PLAN_LIST),
+                eq(PLMN_ALLOWED_SERVICES_LIST), eq(PLMN_DATA_SERVICE_POLICY_LIST),
+                eq(PLMN_VOICE_SERVICE_POLICY_LIST), any());
     }
 
     @Test
     public void testCheckSatelliteEntitlementStatusWhenCarrierConfigChanged() throws Exception {
-        logd("testCheckSatelliteEntitlementStatusWhenCarrierConfigChanged");
         // Verify the called the checkSatelliteEntitlementStatus when CarrierConfigChanged
         // occurred and Internet is connected.
         setInternetConnected(true);
         setLastQueryTime(0L);
         setSatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_ENABLED, PLMN_ALLOWED_LIST,
-                PLMN_BARRED_LIST);
+                PLMN_BARRED_LIST, PLMN_DATA_PLAN_LIST, PLMN_ALLOWED_SERVICES_LIST,
+                PLMN_DATA_SERVICE_POLICY_LIST, PLMN_VOICE_SERVICE_POLICY_LIST);
         triggerCarrierConfigChanged();
 
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         // Verify call the updateSatelliteEntitlementStatus with satellite service is available.
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(eq(SUB_ID), eq(true),
-                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), any());
+                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), eq(PLMN_DATA_PLAN_LIST),
+                eq(PLMN_ALLOWED_SERVICES_LIST), eq(PLMN_DATA_SERVICE_POLICY_LIST),
+                eq(PLMN_VOICE_SERVICE_POLICY_LIST), any());
     }
 
     @Test
     public void testCheckWhenStartCmdIsReceivedDuringRetry() throws Exception {
-        logd("testCheckWhenStartCmdIsReceivedDuringRetry");
         // Verify that start cmd is ignored and retry is performed up to 5 times when start cmd
         // occurs during retries.
         setIsQueryAvailableTrue();
@@ -393,47 +431,47 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         verify(mSatelliteEntitlementApi, times(1)).checkEntitlementStatus();
         // Verify that the retry count is 0 after receiving a 503 with retry-after header in
         // response.
-        assertTrue(retryCountPerSub.getOrDefault(SUB_ID, 0) == 0);
+        assertEquals(0, retryCountPerSub.getOrDefault(SUB_ID, 0).longValue());
 
         // Verify that the retry count is 1 for the second query when receiving a 503 with
         // retry-after header in response.
         mTestableLooper.moveTimeForward(TimeUnit.SECONDS.toMillis(1));
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi, times(2)).checkEntitlementStatus();
-        assertTrue(retryCountPerSub.get(SUB_ID) == 1);
+        assertEquals(1, retryCountPerSub.get(SUB_ID).longValue());
 
         // Verify that the retry count is 2 for the third query when receiving a 503 with
         // retry-after header in response.
         mTestableLooper.moveTimeForward(TimeUnit.SECONDS.toMillis(1));
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi, times(3)).checkEntitlementStatus();
-        assertTrue(retryCountPerSub.get(SUB_ID) == 2);
+        assertEquals(2, retryCountPerSub.get(SUB_ID).longValue());
 
         // Verify that start CMD is ignored during retries.
         sendMessage(CMD_START_QUERY_ENTITLEMENT, SUB_ID);
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi, times(3)).checkEntitlementStatus();
-        assertTrue(retryCountPerSub.get(SUB_ID) == 2);
+        assertEquals(2, retryCountPerSub.get(SUB_ID).longValue());
 
         // Verify that the retry count is 3 for the forth query when receiving a 503 with
         // retry-after header in response.
         mTestableLooper.moveTimeForward(TimeUnit.SECONDS.toMillis(1));
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi, times(4)).checkEntitlementStatus();
-        assertTrue(retryCountPerSub.get(SUB_ID) == 3);
+        assertEquals(3, retryCountPerSub.get(SUB_ID).longValue());
 
         // Verify that the retry count is 4 for the fifth query when receiving a 503 with
         // retry-after header in response.
         mTestableLooper.moveTimeForward(TimeUnit.SECONDS.toMillis(1));
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi, times(5)).checkEntitlementStatus();
-        assertTrue(retryCountPerSub.get(SUB_ID) == 4);
+        assertEquals(4, retryCountPerSub.get(SUB_ID).longValue());
 
         // Verify that start CMD is ignored during retries.
         sendMessage(CMD_START_QUERY_ENTITLEMENT, SUB_ID);
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi, times(5)).checkEntitlementStatus();
-        assertTrue(retryCountPerSub.get(SUB_ID) == 4);
+        assertEquals(4, retryCountPerSub.get(SUB_ID).longValue());
 
         // Verify that the retry count is 5 for the sixth query when receiving a 503 with
         // retry-after header in response.
@@ -444,7 +482,10 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
 
         // Verify only called onSatelliteEntitlementStatusUpdated once.
         verify(mSatelliteController, times(1)).onSatelliteEntitlementStatusUpdated(eq(SUB_ID),
-                eq(false), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST), any());
+                eq(false), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST),
+                eq(EMPTY_PLMN_DATA_PLAN_LIST), eq(EMPTY_PLMN_ALLOWED_SERVICES_LIST),
+                eq(EMPTY_PLMN_DATA_SERVICE_POLICY_LIST),
+                eq(EMPTY_PLMN_VOICE_SERVICE_POLICY_LIST), any());
 
         // Verify that the query is not restarted after reaching the maximum retry count even if
         // a start cmd is received.
@@ -463,7 +504,6 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
 
     @Test
     public void testCheckAfterInternetConnectionChangedDuringRetry() throws Exception {
-        logd("testCheckAfterInternetConnectionChangedDuringRetry");
         // Verify that the retry count is maintained even when internet connection is lost and
         // connected during retries, and that up to 5 retries are performed.
         setIsQueryAvailableTrue();
@@ -477,48 +517,48 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         verify(mSatelliteEntitlementApi, times(1)).checkEntitlementStatus();
         // Verify that the retry count is 0 after receiving a 503 with retry-after header in
         // response.
-        assertTrue(retryCountPerSub.getOrDefault(SUB_ID, 0) == 0);
+        assertEquals(0, retryCountPerSub.getOrDefault(SUB_ID, 0).longValue());
 
         // Verify that the retry count is 1 for the second query when receiving a 503 with
         // retry-after header in response.
         mTestableLooper.moveTimeForward(TimeUnit.SECONDS.toMillis(1));
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi, times(2)).checkEntitlementStatus();
-        assertTrue(retryCountPerSub.get(SUB_ID) == 1);
+        assertEquals(1, retryCountPerSub.get(SUB_ID).longValue());
 
         // Verify that no query is executed and the retry count does not increase when internet
         // connection is lost during the second retry.
         setInternetConnected(false);
-        mTestableLooper.moveTimeForward(TimeUnit.SECONDS.toMillis(1));
+        mTestableLooper.moveTimeForward(TimeUnit.SECONDS.toMillis(2));
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi, times(2)).checkEntitlementStatus();
-        assertTrue(retryCountPerSub.get(SUB_ID) == 1);
+        assertEquals(1, retryCountPerSub.get(SUB_ID).longValue());
 
         // Verify that the query is started when internet connection is restored and that the
         // retry count does not increase.
         setInternetConnected(true);
-        logd("internet connected again");
+        Log.d(TAG, "internet connected again");
         sendMessage(CMD_START_QUERY_ENTITLEMENT, SUB_ID);
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi, times(3)).checkEntitlementStatus();
-        assertTrue(retryCountPerSub.get(SUB_ID) == 1);
+        assertEquals(1, retryCountPerSub.get(SUB_ID).longValue());
 
         // Verify that the retry count is increases after received a 503 with retry-after header
         // in response.
         mTestableLooper.moveTimeForward(TimeUnit.SECONDS.toMillis(1));
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi, times(4)).checkEntitlementStatus();
-        assertTrue(retryCountPerSub.get(SUB_ID) == 2);
+        assertEquals(2, retryCountPerSub.get(SUB_ID).longValue());
 
         mTestableLooper.moveTimeForward(TimeUnit.SECONDS.toMillis(1));
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi, times(5)).checkEntitlementStatus();
-        assertTrue(retryCountPerSub.get(SUB_ID) == 3);
+        assertEquals(3, retryCountPerSub.get(SUB_ID).longValue());
 
         mTestableLooper.moveTimeForward(TimeUnit.SECONDS.toMillis(1));
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi, times(6)).checkEntitlementStatus();
-        assertTrue(retryCountPerSub.get(SUB_ID) == 4);
+        assertEquals(4, retryCountPerSub.get(SUB_ID).longValue());
 
         mTestableLooper.moveTimeForward(TimeUnit.SECONDS.toMillis(1));
         mTestableLooper.processAllMessages();
@@ -541,12 +581,14 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
 
         // Verify only called onSatelliteEntitlementStatusUpdated once.
         verify(mSatelliteController, times(1)).onSatelliteEntitlementStatusUpdated(eq(SUB_ID),
-                eq(false), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST), any());
+                eq(false), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST),
+                eq(EMPTY_PLMN_DATA_PLAN_LIST), eq(EMPTY_PLMN_ALLOWED_SERVICES_LIST),
+                eq(EMPTY_PLMN_DATA_SERVICE_POLICY_LIST), eq(EMPTY_PLMN_VOICE_SERVICE_POLICY_LIST),
+                any());
     }
 
     @Test
     public void testStartQueryEntitlementStatus_error500() throws Exception {
-        logd("testStartQueryEntitlementStatus_error500");
         setIsQueryAvailableTrue();
         Map<Integer, Integer> retryCountPerSub =
                 (Map<Integer, Integer>) getValue("mRetryCountPerSub");
@@ -557,12 +599,14 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         verify(mSatelliteEntitlementApi, times(1)).checkEntitlementStatus();
         assertNull(retryCountPerSub.get(SUB_ID));
         verify(mSatelliteController, times(1)).onSatelliteEntitlementStatusUpdated(eq(SUB_ID),
-                eq(false), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST), any());
+                eq(false), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST),
+                eq(EMPTY_PLMN_DATA_PLAN_LIST), eq(EMPTY_PLMN_ALLOWED_SERVICES_LIST),
+                eq(EMPTY_PLMN_DATA_SERVICE_POLICY_LIST),
+                eq(EMPTY_PLMN_VOICE_SERVICE_POLICY_LIST), any());
     }
 
     @Test
     public void testStartQueryEntitlementStatus_error503_retrySuccess() throws Exception {
-        logd("testStartQueryEntitlementStatus_error503_retrySuccess");
         setIsQueryAvailableTrue();
         set503RetryAfterResponse();
         Map<Integer, Integer> retryCountPerSub =
@@ -579,18 +623,20 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         doReturn(mSatelliteEntitlementResult).when(
                 mSatelliteEntitlementApi).checkEntitlementStatus();
         setSatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_ENABLED, PLMN_ALLOWED_LIST,
-                PLMN_BARRED_LIST);
+                PLMN_BARRED_LIST, PLMN_DATA_PLAN_LIST, PLMN_ALLOWED_SERVICES_LIST,
+                PLMN_DATA_SERVICE_POLICY_LIST, PLMN_VOICE_SERVICE_POLICY_LIST);
         mTestableLooper.moveTimeForward(TimeUnit.SECONDS.toMillis(1));
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi, times(2)).checkEntitlementStatus();
         assertNull(retryCountPerSub.get(SUB_ID));
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(eq(SUB_ID), eq(true),
-                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), any());
+                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), eq(PLMN_DATA_PLAN_LIST),
+                eq(PLMN_ALLOWED_SERVICES_LIST), eq(PLMN_DATA_SERVICE_POLICY_LIST),
+                eq(PLMN_VOICE_SERVICE_POLICY_LIST), any());
     }
 
     @Test
     public void testStartQueryEntitlementStatus_otherError_retrySuccess() throws Exception {
-        logd("testStartQueryEntitlementStatus_otherError_retrySuccess");
         setIsQueryAvailableTrue();
         Map<Integer, Integer> retryCountPerSub =
                 (Map<Integer, Integer>) getValue("mRetryCountPerSub");
@@ -609,35 +655,37 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         assertNotNull(exponentialBackoffPerSub.get(SUB_ID));
         // Verify don't call the onSatelliteEntitlementStatusUpdated.
         verify(mSatelliteController, never()).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
 
         // Verify the retry in progress.
         sendMessage(CMD_RETRY_QUERY_ENTITLEMENT, SUB_ID);
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi, times(2)).checkEntitlementStatus();
-        assertTrue(retryCountPerSub.get(SUB_ID) == 1);
+        assertEquals(1, retryCountPerSub.get(SUB_ID).longValue());
         // Verify don't call the onSatelliteEntitlementStatusUpdated.
         verify(mSatelliteController, never()).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
 
         // Received the 200 response, Verify call the onSatelliteEntitlementStatusUpdated.
         setIsQueryAvailableTrue();
         doReturn(mSatelliteEntitlementResult).when(
                 mSatelliteEntitlementApi).checkEntitlementStatus();
         setSatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_ENABLED, PLMN_ALLOWED_LIST,
-                PLMN_BARRED_LIST);
+                PLMN_BARRED_LIST, PLMN_DATA_PLAN_LIST, PLMN_ALLOWED_SERVICES_LIST,
+                PLMN_DATA_SERVICE_POLICY_LIST, PLMN_VOICE_SERVICE_POLICY_LIST);
 
         sendMessage(CMD_RETRY_QUERY_ENTITLEMENT, SUB_ID);
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi, times(3)).checkEntitlementStatus();
-        assertTrue(retryCountPerSub.get(SUB_ID) == 1);
+        assertEquals(1, retryCountPerSub.get(SUB_ID).longValue());
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(eq(SUB_ID), eq(true),
-                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), any());
+                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), eq(PLMN_DATA_PLAN_LIST),
+                eq(PLMN_ALLOWED_SERVICES_LIST), eq(PLMN_DATA_SERVICE_POLICY_LIST),
+                eq(PLMN_VOICE_SERVICE_POLICY_LIST), any());
     }
 
     @Test
     public void testSatelliteEntitlementSupportedChangedFromSupportToNotSupport() throws Exception {
-        logd("testSatelliteEntitlementSupportedChangedFromSupportToNotSupport");
         setIsQueryAvailableTrue();
 
         // KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL changed from Support(entitlement status
@@ -645,14 +693,18 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         doReturn(mSatelliteEntitlementResult).when(
                 mSatelliteEntitlementApi).checkEntitlementStatus();
         setSatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_DISABLED, EMPTY_PLMN_LIST,
-                EMPTY_PLMN_LIST);
+                EMPTY_PLMN_LIST, EMPTY_PLMN_DATA_PLAN_LIST, EMPTY_PLMN_ALLOWED_SERVICES_LIST,
+                EMPTY_PLMN_DATA_SERVICE_POLICY_LIST, EMPTY_PLMN_VOICE_SERVICE_POLICY_LIST);
         sendMessage(CMD_START_QUERY_ENTITLEMENT, SUB_ID);
         mTestableLooper.processAllMessages();
 
         // Verify call the onSatelliteEntitlementStatusUpdated - entitlement status false
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(anyInt(),
-                eq(false), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST), any());
+                eq(false), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST),
+                eq(EMPTY_PLMN_DATA_PLAN_LIST), eq(EMPTY_PLMN_ALLOWED_SERVICES_LIST),
+                eq(EMPTY_PLMN_DATA_SERVICE_POLICY_LIST), eq(EMPTY_PLMN_VOICE_SERVICE_POLICY_LIST),
+                any());
 
         // Verify call the onSatelliteEntitlementStatusUpdated - entitlement status true
         mCarrierConfigBundle.putBoolean(
@@ -661,7 +713,10 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         mTestableLooper.processAllMessages();
 
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(anyInt(),
-                eq(true), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST), any());
+                eq(true), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST),
+                eq(EMPTY_PLMN_DATA_PLAN_LIST), eq(EMPTY_PLMN_ALLOWED_SERVICES_LIST),
+                eq(EMPTY_PLMN_DATA_SERVICE_POLICY_LIST), eq(EMPTY_PLMN_VOICE_SERVICE_POLICY_LIST),
+                any());
 
         // KEY_SATELLITE_ENTITLEMENT_SUPPORTED_BOOL changed from Support(entitlement status
         // enabled) to not support.
@@ -670,14 +725,17 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         doReturn(mSatelliteEntitlementResult).when(
                 mSatelliteEntitlementApi).checkEntitlementStatus();
         setSatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_ENABLED, PLMN_ALLOWED_LIST,
-                PLMN_BARRED_LIST);
+                PLMN_BARRED_LIST, PLMN_DATA_PLAN_LIST, PLMN_ALLOWED_SERVICES_LIST,
+                PLMN_DATA_SERVICE_POLICY_LIST, PLMN_VOICE_SERVICE_POLICY_LIST);
         sendMessage(CMD_START_QUERY_ENTITLEMENT, SUB_ID);
         mTestableLooper.processAllMessages();
 
         // Verify call the onSatelliteEntitlementStatusUpdated - entitlement status true.
         verify(mSatelliteEntitlementApi, times(2)).checkEntitlementStatus();
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(anyInt(),
-                eq(true), eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), any());
+                eq(true), eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST),
+                eq(PLMN_DATA_PLAN_LIST), eq(PLMN_ALLOWED_SERVICES_LIST), eq(PLMN_DATA_SERVICE_POLICY_LIST),
+                eq(PLMN_VOICE_SERVICE_POLICY_LIST), any());
 
         // Verify not call the onSatelliteEntitlementStatusUpdated.
         clearInvocationsForMock();
@@ -687,12 +745,13 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         mTestableLooper.processAllMessages();
 
         verify(mSatelliteController, never()).onSatelliteEntitlementStatusUpdated(anyInt(),
-                eq(true), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST), any());
+                eq(true), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST),
+                eq(PLMN_DATA_PLAN_LIST), eq(PLMN_ALLOWED_SERVICES_LIST),
+                eq(PLMN_DATA_SERVICE_POLICY_LIST), eq(PLMN_VOICE_SERVICE_POLICY_LIST), any());
     }
 
     @Test
     public void testStartQueryEntitlementStatus_refreshStatus() throws Exception {
-        logd("testStartQueryEntitlementStatus_refreshStatus");
         setIsQueryAvailableTrue();
         mCarrierConfigBundle.putInt(
                 CarrierConfigManager.KEY_SATELLITE_ENTITLEMENT_STATUS_REFRESH_DAYS_INT, 1);
@@ -701,13 +760,14 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         doReturn(mSatelliteEntitlementResult).when(
                 mSatelliteEntitlementApi).checkEntitlementStatus();
         setSatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_ENABLED, PLMN_ALLOWED_LIST,
-                PLMN_BARRED_LIST);
+                PLMN_BARRED_LIST, PLMN_DATA_PLAN_LIST, PLMN_ALLOWED_SERVICES_LIST,
+                PLMN_DATA_SERVICE_POLICY_LIST, PLMN_VOICE_SERVICE_POLICY_LIST);
         sendMessage(CMD_START_QUERY_ENTITLEMENT, SUB_ID);
         mTestableLooper.processAllMessages();
 
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
 
         // After move to the refresh time, verify the query started and success.
         setLastQueryTime(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(1) - 1000);
@@ -716,13 +776,12 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
 
         verify(mSatelliteEntitlementApi, times(2)).checkEntitlementStatus();
         verify(mSatelliteController, times(2)).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
     }
 
     @Test
     public void testStartQueryEntitlementStatus_internetDisconnectedAndConnectedAgain()
             throws Exception {
-        logd("testStartQueryEntitlementStatus_internetDisconnectedAndConnectedAgain");
         setIsQueryAvailableTrue();
 
         // Verify the query does not start if there is no internet connection.
@@ -732,25 +791,27 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
 
         verify(mSatelliteEntitlementApi, never()).checkEntitlementStatus();
         verify(mSatelliteController, never()).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
 
         // Verify the query start and success after internet connected.
         setInternetConnected(true);
         doReturn(mSatelliteEntitlementResult).when(
                 mSatelliteEntitlementApi).checkEntitlementStatus();
         setSatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_ENABLED, PLMN_ALLOWED_LIST,
-                PLMN_BARRED_LIST);
+                PLMN_BARRED_LIST, PLMN_DATA_PLAN_LIST, PLMN_ALLOWED_SERVICES_LIST,
+                PLMN_DATA_SERVICE_POLICY_LIST, PLMN_VOICE_SERVICE_POLICY_LIST);
         sendMessage(CMD_START_QUERY_ENTITLEMENT, SUB_ID);
         mTestableLooper.processAllMessages();
 
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(eq(SUB_ID), eq(true),
-                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), any());
+                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), eq(PLMN_DATA_PLAN_LIST),
+                eq(PLMN_ALLOWED_SERVICES_LIST), eq(PLMN_DATA_SERVICE_POLICY_LIST),
+                eq(PLMN_VOICE_SERVICE_POLICY_LIST), any());
     }
 
     @Test
     public void testStartQueryEntitlementStatus_error503_error500() throws Exception {
-        logd("testStartQueryEntitlementStatus_error503_error500");
         setIsQueryAvailableTrue();
         set503RetryAfterResponse();
 
@@ -760,7 +821,7 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         verify(mSatelliteController, never()).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
 
         // Verify whether the second query has been triggered and whether
         // onSatelliteEntitlementStatusUpdated has been called after received the 500 error.
@@ -770,12 +831,14 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(eq(SUB_ID),
-                eq(false), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST), any());
+                eq(false), eq(EMPTY_PLMN_LIST), eq(EMPTY_PLMN_LIST),
+                eq(EMPTY_PLMN_DATA_PLAN_LIST), eq(EMPTY_PLMN_ALLOWED_SERVICES_LIST),
+                eq(EMPTY_PLMN_DATA_SERVICE_POLICY_LIST), eq(EMPTY_PLMN_VOICE_SERVICE_POLICY_LIST),
+                any());
     }
 
     @Test
     public void testStartQueryEntitlementStatus_error503_otherError() throws Exception {
-        logd("testStartQueryEntitlementStatus_error503_otherError");
         setIsQueryAvailableTrue();
         set503RetryAfterResponse();
 
@@ -785,7 +848,7 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         verify(mSatelliteController, never()).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
 
         // Verify whether the second query was triggered and onSatelliteEntitlementStatusUpdated
         // was not called after received a 503 error without valid retry-after header.
@@ -795,37 +858,40 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         mTestableLooper.processAllMessages();
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         verify(mSatelliteController, never()).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
 
         // Verify whether the third query was triggered and onSatelliteEntitlementStatusUpdated
         // was called after received a success case.
         doReturn(mSatelliteEntitlementResult).when(
                 mSatelliteEntitlementApi).checkEntitlementStatus();
         setSatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_ENABLED, PLMN_ALLOWED_LIST,
-                PLMN_BARRED_LIST);
+                PLMN_BARRED_LIST, PLMN_DATA_PLAN_LIST, PLMN_ALLOWED_SERVICES_LIST,
+                PLMN_DATA_SERVICE_POLICY_LIST, PLMN_VOICE_SERVICE_POLICY_LIST);
         mTestableLooper.moveTimeForward(TimeUnit.MINUTES.toMillis(10));
         mTestableLooper.processAllMessages();
 
         verify(mSatelliteEntitlementApi, times(2)).checkEntitlementStatus();
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(eq(SUB_ID), eq(true),
-                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), any());
+                eq(PLMN_ALLOWED_LIST), eq(PLMN_BARRED_LIST), eq(PLMN_DATA_PLAN_LIST),
+                eq(PLMN_ALLOWED_SERVICES_LIST), eq(PLMN_DATA_SERVICE_POLICY_LIST),
+                eq(PLMN_VOICE_SERVICE_POLICY_LIST), any());
     }
 
     @Test
     public void testStartQueryEntitlementStatus_AfterSimRefresh() throws Exception {
-        logd("testStartQueryEntitlementStatus_AfterSimRefresh");
         setIsQueryAvailableTrue();
 
         // Verify the first query complete.
         doReturn(mSatelliteEntitlementResult).when(
                 mSatelliteEntitlementApi).checkEntitlementStatus();
         setSatelliteEntitlementResult(SATELLITE_ENTITLEMENT_STATUS_ENABLED, PLMN_ALLOWED_LIST,
-                PLMN_BARRED_LIST);
+                PLMN_BARRED_LIST, PLMN_DATA_PLAN_LIST, PLMN_ALLOWED_SERVICES_LIST,
+                PLMN_DATA_SERVICE_POLICY_LIST, PLMN_VOICE_SERVICE_POLICY_LIST);
         mSatelliteEntitlementController.handleCmdStartQueryEntitlement();
 
         verify(mSatelliteEntitlementApi).checkEntitlementStatus();
         verify(mSatelliteController).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+                anyBoolean(), anyList(), anyList(), anyMap(), anyMap(), anyMap(), anyMap(), any());
 
         // SIM_REFRESH event occurred before expired the query refresh timer, verify the start
         // the query.
@@ -834,8 +900,9 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
         mTestableLooper.processAllMessages();
 
         verify(mSatelliteEntitlementApi, times(2)).checkEntitlementStatus();
-        verify(mSatelliteController, times(2)).onSatelliteEntitlementStatusUpdated(anyInt(),
-                anyBoolean(), anyList(), anyList(), any());
+        verify(mSatelliteController, times(2))
+                .onSatelliteEntitlementStatusUpdated(anyInt(), anyBoolean(), anyList(), anyList(),
+                        anyMap(), anyMap(), anyMap(), anyMap(), any());
     }
 
     private void triggerCarrierConfigChanged() {
@@ -893,10 +960,21 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
     }
 
     private void setSatelliteEntitlementResult(int entitlementStatus,
-            List<String> plmnAllowedList, List<String> plmnBarredList) {
+            List<String> plmnAllowedList, List<String> plmnBarredList,
+            Map<String,Integer> plmnDataPlanMap,
+            Map<String,List<Integer>> plmnAllowedServicesMap,
+            Map<String,Integer> plmnDataServicePolicyMap,
+            Map<String,Integer> plmnVoiceServicePolicyMap) {
         doReturn(entitlementStatus).when(mSatelliteEntitlementResult).getEntitlementStatus();
         doReturn(plmnAllowedList).when(mSatelliteEntitlementResult).getAllowedPLMNList();
         doReturn(plmnBarredList).when(mSatelliteEntitlementResult).getBarredPLMNList();
+        doReturn(plmnDataPlanMap).when(mSatelliteEntitlementResult).getDataPlanInfoForPlmnList();
+        doReturn(plmnAllowedServicesMap).when(mSatelliteEntitlementResult)
+                .getAvailableServiceTypeInfoForPlmnList();
+        doReturn(plmnDataServicePolicyMap).when(mSatelliteEntitlementResult)
+                .getDataServicePolicyInfoForPlmnList();
+        doReturn(plmnVoiceServicePolicyMap).when(mSatelliteEntitlementResult)
+                .getVoiceServicePolicyInfoForPlmnList();
     }
 
     private void setLastQueryTime(Long lastQueryTime) throws Exception {
@@ -952,12 +1030,8 @@ public class SatelliteEntitlementControllerTest extends TelephonyTestBase {
 
         @Override
         public SatelliteEntitlementApi getSatelliteEntitlementApi(int subId) {
-            logd("getSatelliteEntitlementApi");
+            Log.d(TAG, "getSatelliteEntitlementApi");
             return mInjectSatelliteEntitlementApi;
         }
     }
-
-    private static void logd(String log) {
-        Log.d(TAG, log);
-    }
 }
diff --git a/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResponseTest.java b/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResponseTest.java
index 8e45a736c..92dd9977c 100644
--- a/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResponseTest.java
+++ b/tests/src/com/android/phone/satellite/entitlement/SatelliteEntitlementResponseTest.java
@@ -16,6 +16,11 @@
 
 package com.android.phone.satellite.entitlement;
 
+import static android.telephony.CarrierConfigManager.SATELLITE_DATA_SUPPORT_ALL;
+import static android.telephony.CarrierConfigManager.SATELLITE_DATA_SUPPORT_BANDWIDTH_CONSTRAINED;
+import static android.telephony.NetworkRegistrationInfo.SERVICE_TYPE_DATA;
+import static android.telephony.NetworkRegistrationInfo.SERVICE_TYPE_VOICE;
+
 import static com.android.phone.satellite.entitlement.SatelliteEntitlementResult.SATELLITE_ENTITLEMENT_STATUS_DISABLED;
 import static com.android.phone.satellite.entitlement.SatelliteEntitlementResult.SATELLITE_ENTITLEMENT_STATUS_ENABLED;
 import static com.android.phone.satellite.entitlement.SatelliteEntitlementResult.SATELLITE_ENTITLEMENT_STATUS_INCOMPATIBLE;
@@ -34,13 +39,17 @@ import org.junit.runner.RunWith;
 
 import java.util.Arrays;
 import java.util.List;
+import java.util.Map;
 
 @RunWith(AndroidJUnit4.class)
 public class SatelliteEntitlementResponseTest {
     private static final String TEST_OTHER_APP_ID = "ap201x";
+
     private static final List<SatelliteNetworkInfo> TEST_PLMN_DATA_PLAN_TYPE_LIST = Arrays.asList(
-            new SatelliteNetworkInfo("31026", "unmetered"),
-            new SatelliteNetworkInfo("302820", "metered"));
+            new SatelliteNetworkInfo("31026", "unmetered",
+                    Map.of("data","constrained")),
+            new SatelliteNetworkInfo("302820", "metered",
+                    Map.of("voice","unconstrained")));
     private static final List<String> TEST_PLMN_BARRED_LIST = Arrays.asList("31017", "302020");
     private static final String RESPONSE_WITHOUT_SATELLITE_APP_ID =
             "{\"VERS\":{\"version\":\"1\",\"validity\":\"172800\"},"
@@ -77,10 +86,14 @@ public class SatelliteEntitlementResponseTest {
                 response.getPlmnAllowed().get(0).mPlmn);
         assertEquals(TEST_PLMN_DATA_PLAN_TYPE_LIST.get(0).mDataPlanType,
                 response.getPlmnAllowed().get(0).mDataPlanType);
+        assertEquals(TEST_PLMN_DATA_PLAN_TYPE_LIST.get(0).mAllowedServicesInfo,
+                response.getPlmnAllowed().get(0).mAllowedServicesInfo);
         assertEquals(TEST_PLMN_DATA_PLAN_TYPE_LIST.get(1).mPlmn,
                 response.getPlmnAllowed().get(1).mPlmn);
         assertEquals(TEST_PLMN_DATA_PLAN_TYPE_LIST.get(1).mDataPlanType,
                 response.getPlmnAllowed().get(1).mDataPlanType);
+        assertEquals(TEST_PLMN_DATA_PLAN_TYPE_LIST.get(1).mAllowedServicesInfo,
+                response.getPlmnAllowed().get(1).mAllowedServicesInfo);
         assertTrue(response.getPlmnBarredList().size() == 2);
         assertEquals(TEST_PLMN_BARRED_LIST, response.getPlmnBarredList());
 
@@ -207,15 +220,17 @@ public class SatelliteEntitlementResponseTest {
 
     private String getPLMNListOrEmpty(int entitlementStatus) {
         return entitlementStatus == SATELLITE_ENTITLEMENT_STATUS_ENABLED ? ","
-                + "\"PLMNAllowed\":[{\"PLMN\":\"31026\",\"DataPlanType\":\"unmetered\"},"
-                + "{\"PLMN\":\"302820\",\"DataPlanType\":\"metered\"}],"
+                + "\"PLMNAllowed\":[{\"PLMN\":\"31026\",\"DataPlanType\":\"unmetered\",\"AllowedServicesInfo\":[{\"AllowedServices\":{\"ServiceType\":\"data\",\"ServicePolicy\":\"constrained\"}}]},"
+                + "{\"PLMN\":\"302820\",\"DataPlanType\":\"metered\",\"AllowedServicesInfo\":[{\"AllowedServices\":{\"ServiceType\":\"voice\",\"ServicePolicy\":\"unconstrained\"}}]}],"
                 + "\"PLMNBarred\":[{\"PLMN\":\"31017\"},"
                 + "{\"PLMN\":\"302020\"}]" : "";
     }
 
     private String getAllowedPlmns(String firstPlmn, String secondPlmn) {
-        return ",\"PLMNAllowed\":[{\"PLMN\":\"" + firstPlmn + "\",\"DataPlanType\":\"unmetered\"},"
-                + "{\"PLMN\":\"" + secondPlmn + "\",\"DataPlanType\":\"metered\"}]";
+        return ",\"PLMNAllowed\":[{\"PLMN\":\"" + firstPlmn +
+                "\",\"DataPlanType\":\"unmetered\",\"AllowedServicesInfo\":[{\"AllowedServices\":{\"ServiceType\":\"data\",\"ServicePolicy\":\"constrained\"}}]},"
+                + "{\"PLMN\":\"" + secondPlmn +
+                "\",\"DataPlanType\":\"metered\",\"AllowedServicesInfo\":[{\"AllowedServices\":{\"ServiceType\":\"voice\",\"ServicePolicy\":\"unconstrained\"}}]}]";
     }
 
     private String getBarredPlmns(String firstPlmn, String secondPlmn) {
@@ -237,8 +252,8 @@ public class SatelliteEntitlementResponseTest {
                 + "\"TOKEN\":{\"token\":\"ASH127AHHA88SF\"},\""
                 + ServiceEntitlement.APP_SATELLITE_ENTITLEMENT + "\":{"
                 + "\"EntitlementStatus\":\"" + SATELLITE_ENTITLEMENT_STATUS_ENABLED + "\""
-                + ",\"PLMNAllowed\":[{\"PLMN\":\"31026\",\"DataPlanType\":\"unmetered\"},"
-                + "{\"PLMN\":\"302820\",\"DataPlanType\":\"metered\"}]"
+                + ",\"PLMNAllowed\":[{\"PLMN\":\"31026\",\"DataPlanType\":\"unmetered\",\"AllowedServicesInfo\":[{\"AllowedServices\":{\"ServiceType\":\"data\",\"ServicePolicy\":\"constrained\"}}]},"
+                + "{\"PLMN\":\"302820\",\"DataPlanType\":\"metered\",\"AllowedServicesInfo\":[{\"AllowedServices\":{\"ServiceType\":\"voice\",\"ServicePolicy\":\"unconstrained\"}}]}]"
                 + getBarredPlmns(firstPlmn, secondPlmn)
                 + "}}";
     }
diff --git a/tests/src/com/android/services/telephony/DisconnectCauseUtilTest.java b/tests/src/com/android/services/telephony/DisconnectCauseUtilTest.java
index 71a23e6a4..fe6d6f74f 100644
--- a/tests/src/com/android/services/telephony/DisconnectCauseUtilTest.java
+++ b/tests/src/com/android/services/telephony/DisconnectCauseUtilTest.java
@@ -22,7 +22,6 @@ import static android.media.ToneGenerator.TONE_SUP_BUSY;
 import static junit.framework.Assert.assertNotNull;
 import static junit.framework.TestCase.assertEquals;
 
-import static org.mockito.Mockito.mock;
 import static org.testng.Assert.assertFalse;
 import static org.testng.Assert.assertTrue;
 
@@ -38,15 +37,11 @@ import androidx.test.runner.AndroidJUnit4;
 
 import com.android.TelephonyTestBase;
 import com.android.internal.telephony.CallFailCause;
-import com.android.internal.telephony.GsmCdmaPhone;
-import com.android.internal.telephony.Phone;
-import com.android.internal.telephony.PhoneFactory;
 import com.android.phone.R;
 
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
-import org.mockito.Mock;
 
 import java.util.Locale;
 
@@ -57,13 +52,6 @@ public class DisconnectCauseUtilTest extends TelephonyTestBase {
     public static final int PHONE_ID = 123;
     public static final String EMPTY_STRING = "";
 
-    // dynamic
-    private Context mContext;
-
-    //Mocks
-    @Mock
-    private GsmCdmaPhone mMockPhone;
-
     private final FlagsAdapter mFeatureFlags = new FlagsAdapter(){
         @Override
         public boolean doNotOverridePreciseLabel() {
@@ -74,11 +62,6 @@ public class DisconnectCauseUtilTest extends TelephonyTestBase {
     @Before
     public void setUp() throws Exception {
         super.setUp();
-        // objects that call static getInstance()
-        mMockPhone = mock(GsmCdmaPhone.class);
-        mContext = InstrumentationRegistry.getTargetContext();
-        // set mocks
-        setSinglePhone();
     }
 
     /**
@@ -253,11 +236,6 @@ public class DisconnectCauseUtilTest extends TelephonyTestBase {
         return config;
     }
 
-    private void setSinglePhone() throws Exception {
-        Phone[] mPhones = new Phone[]{mMockPhone};
-        replaceInstance(PhoneFactory.class, "sPhones", null, mPhones);
-    }
-
     private Resources getResourcesForLocale(Context context, Locale locale) {
         Configuration config = new Configuration();
         config.setToDefaults();
@@ -268,7 +246,7 @@ public class DisconnectCauseUtilTest extends TelephonyTestBase {
 
     private void safeAssertLabel(Integer resourceId,
             android.telecom.DisconnectCause disconnectCause) {
-        Resources r = getResourcesForLocale(mContext, Locale.US);
+        Resources r = getResourcesForLocale(InstrumentationRegistry.getTargetContext(), Locale.US);
         if (resourceId == null || r == null) {
             return;
         }
diff --git a/tests/src/com/android/services/telephony/ImsConferenceControllerTest.java b/tests/src/com/android/services/telephony/ImsConferenceControllerTest.java
index b1572f137..eacb00147 100644
--- a/tests/src/com/android/services/telephony/ImsConferenceControllerTest.java
+++ b/tests/src/com/android/services/telephony/ImsConferenceControllerTest.java
@@ -25,21 +25,27 @@ import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.content.ComponentName;
-import android.os.Looper;
+import android.content.pm.PackageManager;
 import android.telecom.PhoneAccountHandle;
 
 import androidx.test.filters.SmallTest;
+import androidx.test.runner.AndroidJUnit4;
 
+import com.android.TelephonyTestBase;
+
+import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
+import org.junit.runner.RunWith;
 import org.mockito.Mock;
-import org.mockito.MockitoAnnotations;
 
 /**
  * Tests the functionality in ImsConferenceController.java
  */
-
-public class ImsConferenceControllerTest {
+@RunWith(AndroidJUnit4.class)
+public class ImsConferenceControllerTest extends TelephonyTestBase {
+    @Mock
+    PackageManager mPackageManager;
 
     @Mock
     private TelephonyConnectionServiceProxy mMockTelephonyConnectionServiceProxy;
@@ -64,11 +70,14 @@ public class ImsConferenceControllerTest {
 
     @Before
     public void setUp() throws Exception {
-        MockitoAnnotations.initMocks(this);
-        if (Looper.myLooper() == null) {
-            Looper.prepare();
-        }
-        mTelecomAccountRegistry = TelecomAccountRegistry.getInstance(null);
+        super.setUp();
+
+        when(mContext.getPackageManager()).thenReturn(mPackageManager);
+        when(mPackageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY)).thenReturn(true);
+        when(mPackageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_CALLING))
+                .thenReturn(true);
+
+        mTelecomAccountRegistry = TelecomAccountRegistry.getInstance(mContext);
         mTestTelephonyConnectionA = new TestTelephonyConnection();
         mTestTelephonyConnectionB = new TestTelephonyConnection();
 
@@ -79,6 +88,11 @@ public class ImsConferenceControllerTest {
                 mMockTelephonyConnectionServiceProxy, () -> false);
     }
 
+    @After
+    public void tearDown() throws Exception {
+        super.tearDown();
+    }
+
     /**
      * Behavior: add telephony connections B and A to conference controller,
      *           set status for connections, remove one call
diff --git a/tests/src/com/android/services/telephony/ImsConferenceTest.java b/tests/src/com/android/services/telephony/ImsConferenceTest.java
index ca16bc779..b6cb11a7e 100644
--- a/tests/src/com/android/services/telephony/ImsConferenceTest.java
+++ b/tests/src/com/android/services/telephony/ImsConferenceTest.java
@@ -123,6 +123,30 @@ public class ImsConferenceTest {
         }
     }
 
+    /**
+     * Verifies that the default address presentation of an ImsConference is
+     * {@link TelecomManager#PRESENTATION_UNKNOWN}
+     */
+    @Test
+    @SmallTest
+    public void testDefaultNumberPresentationIsValid() {
+        when(mMockTelecomAccountRegistry.isUsingSimCallManager(any(PhoneAccountHandle.class)))
+                .thenReturn(false);
+        mConferenceHost.setConnectionProperties(Connection.PROPERTY_ASSISTED_DIALING
+                | Connection.PROPERTY_WIFI);
+        Bundle extras = new Bundle();
+        extras.putInt(TelecomManager.EXTRA_CALL_NETWORK_TYPE, TelephonyManager.NETWORK_TYPE_IWLAN);
+        mConferenceHost.putTelephonyExtras(extras);
+        mConferenceHost.setStatusHints(new StatusHints("WIFIs", null, null));
+
+        ImsConference imsConference = new ImsConference(mMockTelecomAccountRegistry,
+                mMockTelephonyConnectionServiceProxy, mConferenceHost,
+                null /* phoneAccountHandle */, () -> true /* featureFlagProxy */,
+                new ImsConference.CarrierConfiguration.Builder().build());
+
+        assertEquals(TelecomManager.PRESENTATION_UNKNOWN, imsConference.getAddressPresentation());
+    }
+
     /**
      * Verifies that an ImsConference will inform listeners when the "fullness" of the conference
      * changes as participants come and go.
diff --git a/tests/src/com/android/services/telephony/TelecomAccountRegistryTest.java b/tests/src/com/android/services/telephony/TelecomAccountRegistryTest.java
index fc544b0e7..d0fc69dd3 100644
--- a/tests/src/com/android/services/telephony/TelecomAccountRegistryTest.java
+++ b/tests/src/com/android/services/telephony/TelecomAccountRegistryTest.java
@@ -50,9 +50,8 @@ import android.testing.TestableLooper;
 import com.android.TelephonyTestBase;
 import com.android.internal.telephony.Phone;
 import com.android.internal.telephony.PhoneConstants;
-import com.android.internal.telephony.PhoneFactory;
+import com.android.internal.telephony.SimultaneousCallingTracker;
 import com.android.internal.telephony.flags.Flags;
-import com.android.phone.PhoneGlobals;
 import com.android.phone.PhoneInterfaceManager;
 import com.android.phone.R;
 
@@ -63,7 +62,7 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
-import org.mockito.MockitoAnnotations;
+import org.mockito.Mockito;
 
 @RunWith(AndroidTestingRunner.class)
 @TestableLooper.RunWithLooper(setAsMainLooper = true)
@@ -83,7 +82,6 @@ public class TelecomAccountRegistryTest extends TelephonyTestBase {
     @Mock ImsManager mImsManager;
     @Mock SubscriptionManager mSubscriptionManager;
     @Mock ContentProvider mContentProvider;
-    @Mock PhoneGlobals mPhoneGlobals;
     @Mock Phone mPhone;
     @Mock Resources mResources;
     @Mock Drawable mDrawable;
@@ -96,18 +94,13 @@ public class TelecomAccountRegistryTest extends TelephonyTestBase {
     private BroadcastReceiver mUserSwitchedAndConfigChangedReceiver;
     private BroadcastReceiver mLocaleChangedBroadcastReceiver;
     private ContentResolver mContentResolver;
-    private Phone[] mPhones;
     private TestableLooper mTestableLooper;
 
     @Before
     public void setUp() throws Exception {
         super.setUp();
         mSetFlagsRule.disableFlags(Flags.FLAG_DELAY_PHONE_ACCOUNT_REGISTRATION);
-        MockitoAnnotations.initMocks(this);
 
-        mPhones = new Phone[]{mPhone};
-        replaceInstance(PhoneFactory.class, "sPhones", null, mPhones);
-        replaceInstance(PhoneGlobals.class, "sMe", null, mPhoneGlobals);
         replaceInstance(PhoneInterfaceManager.class, "sInstance", null, mPhoneInterfaceManager);
         when(mPhone.getPhoneType()).thenReturn(PhoneConstants.PHONE_TYPE_GSM);
         when(mPhone.getContext()).thenReturn(mMockedContext);
@@ -182,6 +175,9 @@ public class TelecomAccountRegistryTest extends TelephonyTestBase {
                 broadcastReceiverArgumentCaptor.getAllValues().get(0);
         mLocaleChangedBroadcastReceiver = broadcastReceiverArgumentCaptor.getAllValues().get(1);
 
+        replaceInstance(SimultaneousCallingTracker.class, "sInstance", null,
+                Mockito.mock(SimultaneousCallingTracker.class));
+
         mTestableLooper.processAllMessages();
     }
 
diff --git a/tests/src/com/android/services/telephony/TelephonyConnectionServiceTest.java b/tests/src/com/android/services/telephony/TelephonyConnectionServiceTest.java
index b6b1a36b4..349716710 100644
--- a/tests/src/com/android/services/telephony/TelephonyConnectionServiceTest.java
+++ b/tests/src/com/android/services/telephony/TelephonyConnectionServiceTest.java
@@ -61,7 +61,6 @@ import android.net.Uri;
 import android.os.AsyncResult;
 import android.os.Bundle;
 import android.os.Handler;
-import android.os.Looper;
 import android.platform.test.flag.junit.SetFlagsRule;
 import android.telecom.Conference;
 import android.telecom.Conferenceable;
@@ -283,7 +282,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
     @Before
     public void setUp() throws Exception {
         super.setUp();
-        doReturn(Looper.getMainLooper()).when(mContext).getMainLooper();
+
         mTestConnectionService = new TestTelephonyConnectionService(mContext);
         mTestConnectionService.setFeatureFlags(mFeatureFlags);
         mTestConnectionService.setPhoneFactoryProxy(mPhoneFactoryProxy);
@@ -1309,7 +1308,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(0), eq(false));
+                eq(testPhone), eq(false), eq(0));
 
         assertFalse(callback.getValue()
                 .isOkToCall(testPhone, ServiceState.STATE_OUT_OF_SERVICE, false));
@@ -1337,7 +1336,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(0), eq(false));
+                eq(testPhone), eq(false), eq(0));
 
         assertFalse(callback.getValue()
                 .isOkToCall(testPhone, ServiceState.STATE_OUT_OF_SERVICE, false));
@@ -1440,7 +1439,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
     @Test
     @SmallTest
     public void testCreateOutgoingEmergencyConnection_exitingSatellite_placeCall() {
-        when(mSatelliteController.isSatelliteEnabled()).thenReturn(true);
+        when(mSatelliteController.isSatelliteEnabledOrBeingEnabled()).thenReturn(true);
         doReturn(true).when(mMockResources).getBoolean(anyInt());
         doReturn(true).when(mTelephonyManagerProxy).isCurrentEmergencyNumber(
                 anyString());
@@ -1449,14 +1448,14 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(0), eq(false));
+                eq(testPhone), eq(false), eq(0));
 
         assertFalse(callback.getValue()
                 .isOkToCall(testPhone, ServiceState.STATE_OUT_OF_SERVICE, false));
         when(mSST.isRadioOn()).thenReturn(true);
         assertFalse(callback.getValue()
                 .isOkToCall(testPhone, ServiceState.STATE_OUT_OF_SERVICE, false));
-        when(mSatelliteController.isSatelliteEnabled()).thenReturn(false);
+        when(mSatelliteController.isSatelliteEnabledOrBeingEnabled()).thenReturn(false);
         assertTrue(callback.getValue()
                 .isOkToCall(testPhone, ServiceState.STATE_OUT_OF_SERVICE, false));
 
@@ -1481,9 +1480,10 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
     public void testCreateOutgoingEmergencyConnection_exitingSatellite_EmergencySatellite()
             throws Exception {
         doReturn(true).when(mFeatureFlags).carrierRoamingNbIotNtn();
-        doReturn(true).when(mSatelliteController).isSatelliteEnabled();
+        doReturn(true).when(mSatelliteController).isSatelliteEnabledOrBeingEnabled();
 
-        // Set config_turn_off_oem_enabled_satellite_during_emergency_call as false
+        // Set config_turn_off_non_emergency_nb_iot_ntn_satellite_for_emergency_call as true
+        doReturn(true).when(mMockResources).getBoolean(anyInt());
         doReturn(true).when(mTelephonyManagerProxy).isCurrentEmergencyNumber(anyString());
         doReturn(false).when(mSatelliteController).isDemoModeEnabled();
 
@@ -1500,7 +1500,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
     @SmallTest
     public void testCreateOutgoingEmergencyConnection_exitingSatellite_OEM() throws Exception {
         doReturn(true).when(mFeatureFlags).carrierRoamingNbIotNtn();
-        doReturn(true).when(mSatelliteController).isSatelliteEnabled();
+        doReturn(true).when(mSatelliteController).isSatelliteEnabledOrBeingEnabled();
 
         // Set config_turn_off_oem_enabled_satellite_during_emergency_call as false
         doReturn(false).when(mMockResources).getBoolean(anyInt());
@@ -1509,9 +1509,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
 
         // Satellite is for emergency
         doReturn(true).when(mSatelliteController).getRequestIsEmergency();
-        Phone phone = mock(Phone.class);
-        doReturn(1).when(phone).getSubId();
-        doReturn(phone).when(mSatelliteController).getSatellitePhone();
+        doReturn(1).when(mSatelliteController).getSelectedSatelliteSubId();
         SubscriptionManagerService isub = mock(SubscriptionManagerService.class);
         replaceInstance(SubscriptionManagerService.class, "sInstance", null, isub);
         SubscriptionInfoInternal info = mock(SubscriptionInfoInternal.class);
@@ -1539,7 +1537,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
     @SmallTest
     public void testCreateOutgoingEmergencyConnection_exitingSatellite_Carrier() throws Exception {
         doReturn(true).when(mFeatureFlags).carrierRoamingNbIotNtn();
-        doReturn(true).when(mSatelliteController).isSatelliteEnabled();
+        doReturn(true).when(mSatelliteController).isSatelliteEnabledOrBeingEnabled();
 
         // Set config_turn_off_oem_enabled_satellite_during_emergency_call as false
         doReturn(false).when(mMockResources).getBoolean(anyInt());
@@ -1548,9 +1546,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
 
         // Satellite is for emergency
         doReturn(true).when(mSatelliteController).getRequestIsEmergency();
-        Phone phone = mock(Phone.class);
-        doReturn(1).when(phone).getSubId();
-        doReturn(phone).when(mSatelliteController).getSatellitePhone();
+        doReturn(1).when(mSatelliteController).getSelectedSatelliteSubId();
         SubscriptionManagerService isub = mock(SubscriptionManagerService.class);
         replaceInstance(SubscriptionManagerService.class, "sInstance", null, isub);
         SubscriptionInfoInternal info = mock(SubscriptionInfoInternal.class);
@@ -1567,6 +1563,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 mConnection.getDisconnectCause().getTelephonyDisconnectCause());
 
         // Carrier: shouldTurnOffCarrierSatelliteForEmergencyCall = true
+        doReturn(true).when(mMockResources).getBoolean(anyInt());
         doReturn(true).when(mSatelliteController).shouldTurnOffCarrierSatelliteForEmergencyCall();
         setupConnectionServiceInApm();
 
@@ -1574,6 +1571,28 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         assertNull(mConnection.getDisconnectCause());
     }
 
+    @Test
+    @SmallTest
+    public void testCreateOutgoingEmergencyConnection_NonEmergencySatelliteSession() {
+        doReturn(true).when(mFeatureFlags).carrierRoamingNbIotNtn();
+        doReturn(true).when(mSatelliteController).isSatelliteEnabledOrBeingEnabled();
+
+        // Set config_turn_off_non_emergency_nb_iot_ntn_satellite_for_emergency_call as false
+        doReturn(false).when(mMockResources).getBoolean(anyInt());
+        doReturn(true).when(mTelephonyManagerProxy).isCurrentEmergencyNumber(anyString());
+        doReturn(false).when(mSatelliteController).isDemoModeEnabled();
+
+        // Satellite is for emergency
+        doReturn(false).when(mSatelliteController).getRequestIsEmergency();
+
+        setupConnectionServiceInApm();
+
+        // Verify DisconnectCause which not allows emergency call
+        assertNotNull(mConnection.getDisconnectCause());
+        assertEquals(android.telephony.DisconnectCause.SATELLITE_ENABLED,
+                mConnection.getDisconnectCause().getTelephonyDisconnectCause());
+    }
+
     /**
      * Test that the TelephonyConnectionService successfully turns radio on before placing the
      * call when radio off because bluetooth on and wifi calling is not enabled
@@ -1604,7 +1623,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 PHONE_ACCOUNT_HANDLE_1, connectionRequest);
 
         verify(mRadioOnHelper).triggerRadioOnAndListen(any(), eq(false),
-                eq(testPhone0), eq(false), eq(0), eq(false));
+                eq(testPhone0), eq(false), eq(0));
     }
 
     /**
@@ -1638,7 +1657,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 PHONE_ACCOUNT_HANDLE_1, connectionRequest);
 
         verify(mRadioOnHelper).triggerRadioOnAndListen(any(), eq(false),
-                eq(testPhone0), eq(false), eq(0), eq(false));
+                eq(testPhone0), eq(false), eq(0));
     }
 
     /**
@@ -1671,7 +1690,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
                 PHONE_ACCOUNT_HANDLE_1, connectionRequest);
 
         verify(mRadioOnHelper, times(0)).triggerRadioOnAndListen(any(),
-                eq(true), eq(testPhone0), eq(false), eq(0), eq(false));
+                eq(true), eq(testPhone0), eq(false), eq(0));
     }
 
     /**
@@ -2824,7 +2843,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS), eq(true));
+                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS));
 
         ServiceState ss = new ServiceState();
         ss.setState(ServiceState.STATE_OUT_OF_SERVICE);
@@ -2863,7 +2882,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS), eq(true));
+                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS));
 
         ServiceState ss = new ServiceState();
         ss.setState(ServiceState.STATE_OUT_OF_SERVICE);
@@ -2888,7 +2907,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS), eq(true));
+                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS));
 
         ServiceState ss = new ServiceState();
         ss.setState(ServiceState.STATE_IN_SERVICE);
@@ -2924,7 +2943,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS), eq(true));
+                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS));
 
         ServiceState ss = new ServiceState();
         ss.setState(ServiceState.STATE_IN_SERVICE);
@@ -2961,7 +2980,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS), eq(true));
+                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS));
 
         ServiceState ss = new ServiceState();
         ss.setState(ServiceState.STATE_IN_SERVICE);
@@ -2998,7 +3017,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
         ArgumentCaptor<RadioOnStateListener.Callback> callback =
                 ArgumentCaptor.forClass(RadioOnStateListener.Callback.class);
         verify(mRadioOnHelper).triggerRadioOnAndListen(callback.capture(), eq(true),
-                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS), eq(true));
+                eq(testPhone), eq(false), eq(TIMEOUT_TO_DYNAMIC_ROUTING_MS));
 
         mConnection.setDisconnected(null);
 
@@ -3753,7 +3772,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
     @Test
     public void testNormalCallSatelliteEnabled() {
         setupForCallTest();
-        doReturn(true).when(mSatelliteController).isSatelliteEnabled();
+        doReturn(true).when(mSatelliteController).isSatelliteEnabledOrBeingEnabled();
 
         mConnection = mTestConnectionService.onCreateOutgoingConnection(PHONE_ACCOUNT_HANDLE_1,
                 createConnectionRequest(PHONE_ACCOUNT_HANDLE_1, "1234", TELECOM_CALL_ID1));
@@ -3766,7 +3785,7 @@ public class TelephonyConnectionServiceTest extends TelephonyTestBase {
     @Test
     public void testEmergencyCallSatelliteEnabled_blockEmergencyCall() {
         setupForCallTest();
-        doReturn(true).when(mSatelliteController).isSatelliteEnabled();
+        doReturn(true).when(mSatelliteController).isSatelliteEnabledOrBeingEnabled();
         doReturn(false).when(mMockResources).getBoolean(anyInt());
         doReturn(true).when(mTelephonyManagerProxy).isCurrentEmergencyNumber(
                 anyString());
diff --git a/tests/src/com/android/services/telephony/TelephonyManagerTest.java b/tests/src/com/android/services/telephony/TelephonyManagerTest.java
index 20c062f14..efb737524 100644
--- a/tests/src/com/android/services/telephony/TelephonyManagerTest.java
+++ b/tests/src/com/android/services/telephony/TelephonyManagerTest.java
@@ -15,10 +15,12 @@
  */
 
 package com.android.services.telephony;
-import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.fail;
 import static org.junit.Assume.assumeFalse;
+import static org.junit.Assert.assertThrows;
 import static org.junit.Assume.assumeTrue;
+import static org.junit.Assert.assertArrayEquals;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.anyInt;
@@ -34,7 +36,9 @@ import android.app.PropertyInvalidatedCache;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.pm.PackageManager;
+import android.os.OutcomeReceiver;
 import android.os.RemoteException;
+import android.platform.test.annotations.RequiresFlagsEnabled;
 import android.telecom.PhoneAccountHandle;
 import android.telephony.SubscriptionManager;
 import android.telephony.TelephonyManager;
@@ -43,9 +47,10 @@ import android.test.mock.MockContext;
 
 import androidx.test.runner.AndroidJUnit4;
 
-import com.android.internal.telephony.ITelephony;
 import com.android.internal.telephony.IPhoneSubInfo;
+import com.android.internal.telephony.ITelephony;
 import com.android.internal.telephony.PhoneConstants;
+import com.android.internal.telephony.flags.Flags;
 
 import org.junit.After;
 import org.junit.Before;
@@ -53,13 +58,16 @@ import org.junit.Test;
 import org.junit.runner.RunWith;
 
 import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
+import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.Executor;
 import java.util.concurrent.Executors;
 import java.util.concurrent.LinkedBlockingQueue;
 import java.util.concurrent.TimeUnit;
+import java.util.concurrent.atomic.AtomicReference;
 
 /** Unit tests for {@link TelephonyManager}. */
 @RunWith(AndroidJUnit4.class)
@@ -130,6 +138,55 @@ public class TelephonyManagerTest {
         TelephonyManager.disableServiceHandleCaching();
     }
 
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_SUPPORT_ISIM_RECORD)
+    public void testGetImsPcscfAddresses() throws Exception {
+        assumeTrue(hasFeature(PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, true));
+        List<String> pcscfs = Arrays.asList(new String[] { "1.1.1.1 ", " 2.2.2.2"});
+        when(mMockIPhoneSubInfo.getImsPcscfAddresses(anyInt(), anyString()))
+                .thenReturn(pcscfs);
+
+        List<String> actualResult = mTelephonyManager.getImsPcscfAddresses();
+
+        assertTrue(pcscfs.equals(actualResult));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_SUPPORT_ISIM_RECORD)
+    public void testGetImsPcscfAddresses_ReturnEmptyListWhenNotAvailable() throws Exception {
+        assumeTrue(hasFeature(PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, true));
+        List<String> pcscfs = new ArrayList<>();
+        when(mMockIPhoneSubInfo.getImsPcscfAddresses(anyInt(), anyString()))
+                .thenReturn(pcscfs);
+
+        List<String> actualResult = mTelephonyManager.getImsPcscfAddresses();
+
+        assertTrue(pcscfs.equals(actualResult));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_SUPPORT_ISIM_RECORD)
+    public void testGetImsPcscfAddresses_ReturnEmptyListForInvalidSubId() throws Exception {
+        assumeTrue(hasFeature(PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, true));
+        List<String> pcscfs = new ArrayList<>();
+        when(mMockIPhoneSubInfo.getImsPcscfAddresses(anyInt(), anyString()))
+                .thenThrow(new IllegalArgumentException("Invalid subscription"));
+
+        List<String> actualResult = mTelephonyManager.getImsPcscfAddresses();
+
+        assertTrue(pcscfs.equals(actualResult));
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_SUPPORT_ISIM_RECORD)
+    public void testGetImsPcscfAddresses_ThrowRuntimeException() throws Exception {
+        assumeTrue(hasFeature(PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, true));
+        when(mMockIPhoneSubInfo.getImsPcscfAddresses(anyInt(), anyString()))
+                .thenThrow(new IllegalStateException("ISIM is not loaded"));
+
+        assertThrows(RuntimeException.class, () -> mTelephonyManager.getImsPcscfAddresses());
+    }
+
     @Test
     public void testFilterEmergencyNumbersByCategories() throws Exception {
         Map<Integer, List<EmergencyNumber>> emergencyNumberLists = new HashMap<>();
@@ -260,6 +317,70 @@ public class TelephonyManagerTest {
         assertEquals(null, mTelephonyManager.getSimServiceTable(PhoneConstants.APPTYPE_RUIM));
     }
 
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_SUPPORT_ISIM_RECORD)
+    public void testGetSimServiceTableFromIsimAsByteArrayType() throws Exception {
+        assumeTrue(hasFeature(PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, true));
+        String simServiceTable = "34FA754E8390BD02";
+        Executor executor = Executors.newSingleThreadExecutor();
+        TestOutcomeReceiver<byte[], Exception> receiver = new TestOutcomeReceiver<>();
+        when(mMockIPhoneSubInfo.getIsimIst(anyInt())).thenReturn(simServiceTable);
+
+        mTelephonyManager.getSimServiceTable(
+                PhoneConstants.APPTYPE_ISIM, executor, receiver);
+
+        byte[] actualResult = receiver.getResult();
+        assertArrayEquals(hexStringToBytes(simServiceTable), actualResult);
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_SUPPORT_ISIM_RECORD)
+    public void testGetSimServiceTableFromUsimAsByteArrayType() throws Exception {
+        assumeTrue(hasFeature(PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, true));
+        String simServiceTable = "34FA754E8390BD02";
+        Executor executor = Executors.newSingleThreadExecutor();
+        TestOutcomeReceiver<byte[], Exception> receiver = new TestOutcomeReceiver<>();
+        when(mMockIPhoneSubInfo.getSimServiceTable(anyInt(), anyInt()))
+                .thenReturn(simServiceTable);
+
+        mTelephonyManager.getSimServiceTable(
+                PhoneConstants.APPTYPE_USIM, executor, receiver);
+
+        byte[] actualResult = receiver.getResult();
+        assertArrayEquals(hexStringToBytes(simServiceTable), actualResult);
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_SUPPORT_ISIM_RECORD)
+    public void testGetSimServiceTable_ReturnEmptyArrayWhenNotAvailable() throws Exception {
+        assumeTrue(hasFeature(PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, true));
+        Executor executor = Executors.newSingleThreadExecutor();
+        TestOutcomeReceiver<byte[], Exception> receiver = new TestOutcomeReceiver<>();
+        when(mMockIPhoneSubInfo.getSimServiceTable(anyInt(), anyInt())).thenReturn(null);
+
+        mTelephonyManager.getSimServiceTable(
+                PhoneConstants.APPTYPE_RUIM, executor, receiver);
+
+        byte[] actualResult = receiver.getResult();
+        assertArrayEquals(new byte[0], actualResult);
+    }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_SUPPORT_ISIM_RECORD)
+    public void testGetSimServiceTable_CallbackErrorIfExceptionIsThrown() throws Exception {
+        assumeTrue(hasFeature(PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION, true));
+        Executor executor = Executors.newSingleThreadExecutor();
+        TestOutcomeReceiver<byte[], Exception> receiver = new TestOutcomeReceiver<>();
+        when(mMockIPhoneSubInfo.getIsimIst(anyInt()))
+                .thenThrow(new IllegalStateException("ISIM is not loaded"));
+
+        mTelephonyManager.getSimServiceTable(
+                PhoneConstants.APPTYPE_ISIM, executor, receiver);
+
+        Exception error = receiver.getError();
+        assertTrue(error instanceof IllegalStateException);
+    }
+
     private boolean hasFeature(String feature, boolean status) {
         doReturn(status)
                 .when(mPackageManager).hasSystemFeature(
@@ -295,4 +416,58 @@ public class TelephonyManagerTest {
         });
 
     }
+
+    private static class TestOutcomeReceiver<R, E extends Throwable>
+            implements OutcomeReceiver<R, E> {
+        final int mTimeoutSeconds = 3;
+        CountDownLatch mLatch = new CountDownLatch(1);
+        AtomicReference<R> mResult = new AtomicReference<>();
+        AtomicReference<E> mError = new AtomicReference<>();
+
+        public R getResult() throws InterruptedException {
+            assertTrue(mLatch.await(mTimeoutSeconds, TimeUnit.SECONDS));
+            assertNotNull(mResult.get());
+            return mResult.get();
+        }
+
+        public E getError() throws InterruptedException {
+            assertTrue(mLatch.await(mTimeoutSeconds, TimeUnit.SECONDS));
+            assertNotNull(mError.get());
+            return mError.get();
+        }
+
+        @Override
+        public void onResult(R result) {
+            mResult.set(result);
+            mLatch.countDown();
+        }
+
+        @Override
+        public void onError(E error) {
+            mError.set(error);
+            mLatch.countDown();
+        }
+    }
+
+    private static byte[] hexStringToBytes(String s) {
+        byte[] ret;
+        if (s == null) return null;
+        int sz = s.length();
+        ret = new byte[sz / 2];
+
+        for (int i = 0; i < sz; i += 2) {
+            ret[i / 2] = (byte) ((hexCharToInt(s.charAt(i)) << 4)
+                                | hexCharToInt(s.charAt(i + 1)));
+        }
+
+        return ret;
+    }
+
+    private static int hexCharToInt(char c) {
+        if (c >= '0' && c <= '9') return (c - '0');
+        if (c >= 'A' && c <= 'F') return (c - 'A' + 10);
+        if (c >= 'a' && c <= 'f') return (c - 'a' + 10);
+
+        throw new RuntimeException("invalid hex char '" + c + "'");
+    }
 }
\ No newline at end of file
diff --git a/tests/src/com/android/services/telephony/TestTelephonyConnection.java b/tests/src/com/android/services/telephony/TestTelephonyConnection.java
index d91435ccd..9f1a0ec21 100644
--- a/tests/src/com/android/services/telephony/TestTelephonyConnection.java
+++ b/tests/src/com/android/services/telephony/TestTelephonyConnection.java
@@ -16,27 +16,31 @@
 
 package com.android.services.telephony;
 
-import android.content.AttributionSource;
-import android.content.ContentResolver;
-import android.os.Process;
-import android.os.UserHandle;
-import android.telephony.TelephonyManager;
-
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.notNull;
 import static org.mockito.Mockito.doNothing;
+import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.when;
 
+import android.content.AttributionSource;
 import android.content.Context;
+import android.content.pm.ApplicationInfo;
 import android.content.res.Resources;
+import android.os.Build;
 import android.os.Bundle;
 import android.os.PersistableBundle;
+import android.os.Process;
+import android.os.UserHandle;
+import android.provider.Settings;
 import android.telecom.PhoneAccountHandle;
 import android.telecom.VideoProfile;
 import android.telephony.CarrierConfigManager;
+import android.telephony.TelephonyManager;
+import android.test.mock.MockContentProvider;
+import android.test.mock.MockContentResolver;
 
 import com.android.ims.ImsCall;
 import com.android.internal.telephony.Call;
@@ -69,9 +73,6 @@ public class TestTelephonyConnection extends TelephonyConnection {
     @Mock
     Context mMockContext;
 
-    @Mock
-    ContentResolver mMockContentResolver;
-
     @Mock
     Resources mMockResources;
 
@@ -96,6 +97,7 @@ public class TestTelephonyConnection extends TelephonyConnection {
     @Mock
     CarrierConfigManager mCarrierConfigManager;
 
+    private MockContentResolver mMockContentResolver;
     private boolean mIsImsConnection;
     private boolean mIsImsExternalConnection;
     private boolean mIsConferenceSupported = true;
@@ -136,6 +138,14 @@ public class TestTelephonyConnection extends TelephonyConnection {
         mMockContext = mock(Context.class);
         mMockTelephonyManager = mock(TelephonyManager.class);
         mOriginalConnection = mMockRadioConnection;
+
+        ApplicationInfo applicationInfo = new ApplicationInfo();
+        applicationInfo.targetSdkVersion = Build.VERSION_CODES.CUR_DEVELOPMENT;
+        doReturn(applicationInfo).when(mMockContext).getApplicationInfo();
+        mMockContentResolver = new MockContentResolver(mMockContext);
+        mMockContentResolver.addProvider(Settings.AUTHORITY,
+                new EmptyContentProvider(mMockContext));
+
         // Set up mMockRadioConnection and mMockPhone to contain an active call
         when(mMockRadioConnection.getState()).thenReturn(Call.State.ACTIVE);
         when(mOriginalConnection.getState()).thenReturn(Call.State.ACTIVE);
@@ -159,8 +169,7 @@ public class TestTelephonyConnection extends TelephonyConnection {
         when(mMockContext.getSystemService(Context.TELEPHONY_SERVICE))
                 .thenReturn(mMockTelephonyManager);
         when(mMockContext.getAttributionSource()).thenReturn(attributionSource);
-        when(mMockContentResolver.getUserId()).thenReturn(UserHandle.USER_CURRENT);
-        when(mMockContentResolver.getAttributionSource()).thenReturn(attributionSource);
+        when(mMockContext.getUserId()).thenReturn(UserHandle.USER_CURRENT);
         when(mMockResources.getBoolean(anyInt())).thenReturn(false);
         when(mMockPhone.getDefaultPhone()).thenReturn(mMockPhone);
         when(mMockPhone.getPhoneType()).thenReturn(PhoneConstants.PHONE_TYPE_IMS);
@@ -320,4 +329,15 @@ public class TestTelephonyConnection extends TelephonyConnection {
     public void setMockImsPhoneConnection(ImsPhoneConnection connection) {
         mImsPhoneConnection = connection;
     }
+
+    static class EmptyContentProvider extends MockContentProvider {
+        EmptyContentProvider(Context context) {
+            super(context);
+        }
+
+        @Override
+        public Bundle call(String method, String request, Bundle args) {
+            return new Bundle();
+        }
+    }
 }
diff --git a/tests/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelectorTest.java b/tests/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelectorTest.java
index 8a83ab0e8..51493d393 100644
--- a/tests/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelectorTest.java
+++ b/tests/src/com/android/services/telephony/domainselection/EmergencyCallDomainSelectorTest.java
@@ -127,6 +127,7 @@ import android.telephony.ims.ProvisioningManager;
 import android.testing.TestableLooper;
 import android.util.Log;
 import android.util.SparseArray;
+import android.view.Display;
 
 import androidx.test.filters.SmallTest;
 
@@ -230,6 +231,11 @@ public class EmergencyCallDomainSelectorTest {
             public Resources getResources() {
                 return mResources;
             }
+
+            @Override
+            public int getDisplayId() {
+                return Display.DEFAULT_DISPLAY;
+            }
         };
 
         if (Looper.myLooper() == null) {
diff --git a/tests/src/com/android/services/telephony/domainselection/NormalCallDomainSelectorTest.java b/tests/src/com/android/services/telephony/domainselection/NormalCallDomainSelectorTest.java
index 49411bdb4..7acc7d6b3 100644
--- a/tests/src/com/android/services/telephony/domainselection/NormalCallDomainSelectorTest.java
+++ b/tests/src/com/android/services/telephony/domainselection/NormalCallDomainSelectorTest.java
@@ -743,6 +743,27 @@ public class NormalCallDomainSelectorTest {
                 mNormalCallDomainSelector.getSelectorState());
     }
 
+    @Test
+    public void testReselectDomainNoTimeoutMessage() {
+        final TestTransportSelectorCallback transportSelectorCallback =
+                new TestTransportSelectorCallback(mNormalCallDomainSelector);
+
+        DomainSelectionService.SelectionAttributes attributes =
+                new DomainSelectionService.SelectionAttributes.Builder(
+                        SLOT_ID, SUB_ID_1, SELECTOR_TYPE_CALLING)
+                        .setAddress(TEST_URI)
+                        .setCallId(TEST_CALLID)
+                        .setEmergency(false)
+                        .setVideoCall(false)
+                        .setExitedFromAirplaneMode(false)
+                        .build();
+
+        mNormalCallDomainSelector.selectDomain(null, transportSelectorCallback);
+        mNormalCallDomainSelector.reselectDomain(attributes);
+        assertFalse(mNormalCallDomainSelector.hasMessages(
+                NormalCallDomainSelector.MSG_WAIT_FOR_IMS_STATE_TIMEOUT));
+    }
+
     static class TestTransportSelectorCallback implements TransportSelectorCallback,
             WwanSelectorCallback {
         public boolean mCreated;
diff --git a/tests/src/com/android/services/telephony/rcs/RcsFeatureControllerTest.java b/tests/src/com/android/services/telephony/rcs/RcsFeatureControllerTest.java
index 07c9fd084..649d3dd4e 100644
--- a/tests/src/com/android/services/telephony/rcs/RcsFeatureControllerTest.java
+++ b/tests/src/com/android/services/telephony/rcs/RcsFeatureControllerTest.java
@@ -45,6 +45,7 @@ import com.android.TelephonyTestBase;
 import com.android.ims.FeatureConnector;
 import com.android.ims.RcsFeatureManager;
 import com.android.internal.telephony.imsphone.ImsRegistrationCallbackHelper;
+import com.android.phone.ImsStateCallbackController;
 
 import org.junit.After;
 import org.junit.Before;
@@ -84,6 +85,9 @@ public class RcsFeatureControllerTest extends TelephonyTestBase {
     @Before
     public void setUp() throws Exception {
         super.setUp();
+
+        replaceInstance(ImsStateCallbackController.class, "sInstance", null,
+                mock(ImsStateCallbackController.class));
     }
 
     @After
diff --git a/tests/src/com/android/services/telephony/rcs/SipTransportControllerTest.java b/tests/src/com/android/services/telephony/rcs/SipTransportControllerTest.java
index 42a45f425..df7a37ebe 100644
--- a/tests/src/com/android/services/telephony/rcs/SipTransportControllerTest.java
+++ b/tests/src/com/android/services/telephony/rcs/SipTransportControllerTest.java
@@ -147,12 +147,16 @@ public class SipTransportControllerTest extends TelephonyTestBase {
 
     @After
     public void tearDown() throws Exception {
-        super.tearDown();
-        boolean isShutdown = mExecutorService == null || mExecutorService.isShutdown();
-        if (!isShutdown) {
+        var monitor = RcsProvisioningMonitor.getInstance();
+        if (monitor != null) {
+            monitor.overrideImsFeatureValidation(TEST_SUB_ID, null);
+        }
+
+        if (mExecutorService != null && !mExecutorService.isShutdown()) {
             mExecutorService.shutdownNow();
         }
-        RcsProvisioningMonitor.getInstance().overrideImsFeatureValidation(TEST_SUB_ID, null);
+
+        super.tearDown();
     }
 
     @SmallTest
diff --git a/tests/src/com/android/services/telephony/rcs/TelephonyRcsServiceTest.java b/tests/src/com/android/services/telephony/rcs/TelephonyRcsServiceTest.java
index 4cabf955a..34ed5c653 100644
--- a/tests/src/com/android/services/telephony/rcs/TelephonyRcsServiceTest.java
+++ b/tests/src/com/android/services/telephony/rcs/TelephonyRcsServiceTest.java
@@ -20,6 +20,7 @@ import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.spy;
 import static org.mockito.Mockito.times;
@@ -40,6 +41,7 @@ import com.android.ims.FeatureConnector;
 import com.android.ims.RcsFeatureManager;
 import com.android.internal.telephony.ISub;
 import com.android.internal.telephony.flags.FeatureFlags;
+import com.android.phone.ImsStateCallbackController;
 
 import org.junit.After;
 import org.junit.Before;
@@ -103,6 +105,9 @@ public class TelephonyRcsServiceTest extends TelephonyTestBase {
                 eq(1), anyInt());
         doReturn(true).when(mResourceProxy).getDeviceUceEnabled(any());
 
+        replaceInstance(ImsStateCallbackController.class, "sInstance", null,
+                mock(ImsStateCallbackController.class));
+
         replaceInstance(TelephonyManager.class, "sInstance", null, mTelephonyManager);
         doReturn(2).when(mTelephonyManager).getActiveModemCount();
     }
diff --git a/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/HeaderBlock.java b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/HeaderBlock.java
index 9895d1a0a..9592e1ebc 100644
--- a/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/HeaderBlock.java
+++ b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/HeaderBlock.java
@@ -40,10 +40,26 @@ public final class HeaderBlock {
         int suffixBitCount = blockData.getUnsignedByte(offset++);
         int suffixRecordBitCount = blockData.getUnsignedByte(offset++);
         int suffixTableBlockIdOffset = blockData.getUnsignedByte(offset++);
-        boolean isAllowedList = (blockData.getUnsignedByte(offset) == TRUE);
-        mFileFormat = new SatS2RangeFileFormat(
-                dataS2Level, prefixBitCount, suffixBitCount, suffixTableBlockIdOffset,
-                suffixRecordBitCount, isAllowedList);
+        boolean isAllowedList = (blockData.getUnsignedByte(offset++) == TRUE);
+
+
+        // Check if the block is in the original format or the enhanced format.
+        // If the offset is equal to the block data size, this block is in the original format.
+        // If the offset is less than the block data size, this block is an enhanced block, which
+        // has additional fields:
+        //  - the size of an entry value in bytes
+        //  - version number of header block
+        if (offset < blockData.getSize()) {
+            int entryValueSizeInBytes = blockData.getUnsignedByte(offset++);
+            int versionNumber = blockData.getInt(offset);
+            mFileFormat = new SatS2RangeFileFormat(
+                    dataS2Level, prefixBitCount, suffixBitCount, suffixTableBlockIdOffset,
+                    suffixRecordBitCount, isAllowedList, entryValueSizeInBytes, versionNumber);
+        } else {
+            mFileFormat = new SatS2RangeFileFormat(
+                    dataS2Level, prefixBitCount, suffixBitCount, suffixTableBlockIdOffset,
+                    suffixRecordBitCount, isAllowedList);
+        }
     }
 
     /** Creates a {@link HeaderBlock} from low-level block data from a block file. */
diff --git a/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/PopulatedSuffixTableBlock.java b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/PopulatedSuffixTableBlock.java
index 9aa56b2fc..1eb66ac45 100644
--- a/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/PopulatedSuffixTableBlock.java
+++ b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/PopulatedSuffixTableBlock.java
@@ -20,7 +20,6 @@ import static com.android.storage.s2.S2Support.MAX_FACE_ID;
 import static com.android.storage.s2.S2Support.cellIdToString;
 import static com.android.storage.util.Conditions.checkStateInRange;
 
-import com.android.storage.s2.S2LevelRange;
 import com.android.storage.table.packed.read.IntValueTypedPackedTable;
 import com.android.storage.table.reader.IntValueTable;
 
@@ -59,7 +58,8 @@ final class PopulatedSuffixTableBlock implements SuffixTableBlock.SuffixTableBlo
             SatS2RangeFileFormat fileFormat, IntValueTypedPackedTable packedTable) {
         mFileFormat = Objects.requireNonNull(fileFormat);
         mPackedTable = Objects.requireNonNull(packedTable);
-        mSuffixTableSharedData = SuffixTableSharedData.fromBytes(packedTable.getSharedData());
+        mSuffixTableSharedData = SuffixTableSharedData.fromTypedData(
+                packedTable.getSharedDataAsTyped(), fileFormat);
 
         // Obtain the prefix. All cellIds in this table will share the same prefix except for end
         // range values (which are exclusive so can be for mPrefix + 1 with a suffix value of 0).
@@ -88,6 +88,16 @@ final class PopulatedSuffixTableBlock implements SuffixTableBlock.SuffixTableBlo
         return mPackedTable.getEntryCount();
     }
 
+    @Override
+    public int getEntryValueCount() {
+        return mSuffixTableSharedData.getNumberOfEntryValues();
+    }
+
+    @Override
+    public int getEntryValue(int index) {
+        return mSuffixTableSharedData.getEntryValue(index);
+    }
+
     /**
      * Returns an entry that matches the supplied matcher. If multiple entries match, an arbitrary
      * matching entry is returned. If no entries match then {@code null} is returned.
@@ -141,7 +151,7 @@ final class PopulatedSuffixTableBlock implements SuffixTableBlock.SuffixTableBlo
 
         private final IntValueTable.TableEntry mSuffixTableEntry;
 
-        private S2LevelRange mSuffixTableRange;
+        private SuffixTableRange mSuffixTableRange;
 
         Entry(IntValueTable.TableEntry suffixTableEntry) {
             mSuffixTableEntry = Objects.requireNonNull(suffixTableEntry);
@@ -154,7 +164,7 @@ final class PopulatedSuffixTableBlock implements SuffixTableBlock.SuffixTableBlo
 
         /** Returns the data for this entry. */
         @Override
-        public S2LevelRange getSuffixTableRange() {
+        public SuffixTableRange getSuffixTableRange() {
             // Creating SuffixTableRange is relatively expensive so it is created lazily and
             // memoized.
             if (mSuffixTableRange == null) {
@@ -190,7 +200,8 @@ final class PopulatedSuffixTableBlock implements SuffixTableBlock.SuffixTableBlo
                     endCellIdSuffix = 0;
                 }
                 long endCellId = mFileFormat.createCellId(endCellPrefixValue, endCellIdSuffix);
-                mSuffixTableRange = new S2LevelRange(startCellId, endCellId);
+                int entryValue = getEntryValue();
+                mSuffixTableRange = new SuffixTableRange(startCellId, endCellId, entryValue);
             }
             return mSuffixTableRange;
         }
@@ -218,5 +229,9 @@ final class PopulatedSuffixTableBlock implements SuffixTableBlock.SuffixTableBlo
                     + "mSuffixTableEntry=" + mSuffixTableEntry
                     + '}';
         }
+
+        private int getEntryValue() {
+            return mSuffixTableSharedData.getEntryValue(mSuffixTableEntry.getIndex());
+        }
     }
 }
diff --git a/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SatS2RangeFileFormat.java b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SatS2RangeFileFormat.java
index 39507aab9..a3357660e 100644
--- a/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SatS2RangeFileFormat.java
+++ b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SatS2RangeFileFormat.java
@@ -53,6 +53,10 @@ public final class SatS2RangeFileFormat {
     /** The format version of the satellite S2 data file, read and written. */
     public static final int VERSION = 1;
 
+    private static final int DEFAULT_ENTRY_VALUE_SIZE_IN_BYTES = 0;
+    private static final int DEFAULT_VERSION_NUMBER = 0;
+    private static final int MAX_ENTRY_BYTE_COUNT = 4;
+
     private final int mDataS2Level;
 
     private final int mPrefixBitCount;
@@ -86,12 +90,29 @@ public final class SatS2RangeFileFormat {
      */
     private final boolean mIsAllowedList;
 
+    /**
+     * Entry value size in bytes
+     */
+    private final int mEntryValueSizeInBytes;
+
+    /**
+     * Version number
+     */
+    private final int mVersionNumber;
+
+    public SatS2RangeFileFormat(int s2Level, int prefixBitCount, int suffixBitCount,
+            int suffixTableBlockIdOffset, int tableEntryBitCount, boolean isAllowedList) {
+        this(s2Level, prefixBitCount, suffixBitCount, suffixTableBlockIdOffset, tableEntryBitCount,
+                isAllowedList, DEFAULT_ENTRY_VALUE_SIZE_IN_BYTES, DEFAULT_VERSION_NUMBER);
+    }
+
     /**
      * Creates a new file format. This constructor validates the values against various hard-coded
      * constraints and will throw an {@link IllegalArgumentException} if they are not satisfied.
      */
     public SatS2RangeFileFormat(int s2Level, int prefixBitCount, int suffixBitCount,
-            int suffixTableBlockIdOffset, int tableEntryBitCount, boolean isAllowedList) {
+            int suffixTableBlockIdOffset, int tableEntryBitCount, boolean isAllowedList,
+            int entryValueSizeInBytes, int versionNumber) {
 
         Conditions.checkArgInRange("s2Level", s2Level, 0, MAX_S2_LEVEL);
 
@@ -180,6 +201,12 @@ public final class SatS2RangeFileFormat {
         mSuffixTableBlockIdOffset = suffixTableBlockIdOffset;
 
         mIsAllowedList = isAllowedList;
+
+        Conditions.checkArgInRange("entryValueSizeInBytes", entryValueSizeInBytes, 0,
+                MAX_ENTRY_BYTE_COUNT);
+        mEntryValueSizeInBytes = entryValueSizeInBytes;
+
+        mVersionNumber = versionNumber;
     }
 
     /** Returns the S2 level of all geo data stored in the file. */
@@ -345,6 +372,18 @@ public final class SatS2RangeFileFormat {
                 + "}";
     }
 
+    /**
+     * Returns the length of entry value in Bytes.
+     * @return the length of entry value
+     */
+    public int getEntryValueSizeInBytes() {
+        return mEntryValueSizeInBytes;
+    }
+
+    public int getVersionNumber() {
+        return mVersionNumber;
+    }
+
     @Override
     public String toString() {
         return "SatS2RangeFileFormat{"
@@ -359,6 +398,8 @@ public final class SatS2RangeFileFormat {
                 + ", mSuffixTableBlockIdOffset=" + mSuffixTableBlockIdOffset
                 + ", mUnusedCellIdBitCount=" + mUnusedCellIdBitCount
                 + ", mIsAllowedList=" + mIsAllowedList
+                + ", mEntryValueSizeInBytes=" + mEntryValueSizeInBytes
+                + ", mVersionNumber=" + mVersionNumber
                 + '}';
     }
 
@@ -381,7 +422,9 @@ public final class SatS2RangeFileFormat {
                 && mTableEntryMaxRangeLengthValue == that.mTableEntryMaxRangeLengthValue
                 && mSuffixTableBlockIdOffset == that.mSuffixTableBlockIdOffset
                 && mIsAllowedList == that.mIsAllowedList
-                && mUnusedCellIdBitCount == that.mUnusedCellIdBitCount;
+                && mUnusedCellIdBitCount == that.mUnusedCellIdBitCount
+                && mEntryValueSizeInBytes == that.mEntryValueSizeInBytes
+                && mVersionNumber == that.mVersionNumber;
     }
 
     @Override
@@ -389,7 +432,7 @@ public final class SatS2RangeFileFormat {
         return Objects.hash(mDataS2Level, mPrefixBitCount, mMaxPrefixValue, mSuffixBitCount,
                 mMaxSuffixValue, mTableEntryBitCount, mTableEntryRangeLengthBitCount,
                 mTableEntryMaxRangeLengthValue, mSuffixTableBlockIdOffset, mIsAllowedList,
-                mUnusedCellIdBitCount);
+                mUnusedCellIdBitCount, mEntryValueSizeInBytes, mVersionNumber);
     }
 
     private void checkS2Level(String name, long cellId) {
diff --git a/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SatS2RangeFileReader.java b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SatS2RangeFileReader.java
index ecfa0a9d7..2c6c4aff8 100644
--- a/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SatS2RangeFileReader.java
+++ b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SatS2RangeFileReader.java
@@ -19,7 +19,6 @@ package com.android.telephony.sats2range.read;
 import com.android.storage.block.read.Block;
 import com.android.storage.block.read.BlockFileReader;
 import com.android.storage.block.read.BlockInfo;
-import com.android.storage.s2.S2LevelRange;
 import com.android.storage.s2.S2Support;
 import com.android.storage.util.Conditions;
 import com.android.storage.util.Visitor;
@@ -144,11 +143,11 @@ public final class SatS2RangeFileReader implements AutoCloseable {
     }
 
     /**
-     * Finds an {@link S2LevelRange} associated with a range covering {@code cellId}.
+     * Finds an {@link SuffixTableRange} associated with a range covering {@code cellId}.
      * Returns {@code null} if no range exists. Throws {@link IllegalArgumentException} if
      * {@code cellId} is not the correct S2 level for the file. See {@link #getS2Level()}.
      */
-    public S2LevelRange findEntryByCellId(long cellId) throws IOException {
+    public SuffixTableRange findEntryByCellId(long cellId) throws IOException {
         checkNotClosed();
         int dataS2Level = mFileFormat.getS2Level();
         int searchS2Level = S2Support.getS2Level(cellId);
diff --git a/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SuffixTableBlock.java b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SuffixTableBlock.java
index 90ddd8955..0ee4f7855 100644
--- a/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SuffixTableBlock.java
+++ b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SuffixTableBlock.java
@@ -20,7 +20,6 @@ import static com.android.storage.s2.S2Support.cellIdToString;
 import static com.android.storage.s2.S2Support.getS2Level;
 
 import com.android.storage.block.read.BlockData;
-import com.android.storage.s2.S2LevelRange;
 import com.android.storage.table.packed.read.IntValueTypedPackedTable;
 import com.android.storage.util.BitwiseUtils;
 import com.android.storage.util.Visitor;
@@ -83,6 +82,12 @@ public final class SuffixTableBlock {
 
         /** Returns the number of entries in the table. */
         int getEntryCount();
+
+        /** Returns the number of entry values from the shared data. */
+        int getEntryValueCount();
+
+        /** Returns the entry value from the shared data for the given index. */
+        int getEntryValue(int index);
     }
 
     private SuffixTableBlock(SatS2RangeFileFormat fileFormat, SuffixTableBlockDelegate delegate) {
@@ -151,6 +156,16 @@ public final class SuffixTableBlock {
         return mDelegate.getEntryCount();
     }
 
+    /** Returns the number of entry values from the shared data. */
+    public int getEntryValueCount() {
+        return mDelegate.getEntryValueCount();
+    }
+
+    /** Returns the entry value from the shared data for the given index. */
+    public int getEntryValue(int index) {
+        return mDelegate.getEntryValue(index);
+    }
+
     /** A {@link Visitor} for the {@link SuffixTableBlock}. See {@link #visit} */
     public interface SuffixTableBlockVisitor extends Visitor {
 
@@ -180,6 +195,6 @@ public final class SuffixTableBlock {
         public abstract int getIndex();
 
         /** Returns the data for this entry. */
-        public abstract S2LevelRange getSuffixTableRange();
+        public abstract SuffixTableRange getSuffixTableRange();
     }
 }
diff --git a/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SuffixTableRange.java b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SuffixTableRange.java
new file mode 100644
index 000000000..8c1466f26
--- /dev/null
+++ b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SuffixTableRange.java
@@ -0,0 +1,75 @@
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
+package com.android.telephony.sats2range.read;
+
+import static com.android.storage.s2.S2Support.cellIdToString;
+
+import com.android.storage.s2.S2LevelRange;
+
+import java.util.Objects;
+
+public final class SuffixTableRange extends S2LevelRange {
+    private static final int DEFAULT_ENTRY_VALUE = -1;
+    private final int mEntryValue;
+
+    // For backward compatibility
+    public SuffixTableRange(long startCellId, long endCellId) {
+        this(startCellId, endCellId, DEFAULT_ENTRY_VALUE);
+    }
+
+    public SuffixTableRange(long startCellId, long endCellId, int entryValue) {
+        super(startCellId, endCellId);
+        mEntryValue = entryValue;
+    }
+
+    /** Returns the entry value associated with this range. */
+    public int getEntryValue() {
+        return mEntryValue;
+    }
+
+    @Override
+    public boolean equals(Object o) {
+        if (this == o) {
+            return true;
+        }
+        if (o == null || getClass() != o.getClass()) {
+            return false;
+        }
+
+        if (super.equals(o)) {
+            int entryValue = ((SuffixTableRange) o).mEntryValue;
+            return mEntryValue == entryValue;
+        } else {
+            return false;
+        }
+    }
+
+    @Override
+    public int hashCode() {
+        return Objects.hash(mStartCellId, mEndCellId, mEntryValue);
+    }
+
+    @Override
+    public String toString() {
+        return "SuffixTableRange{"
+                + "mS2Level=" + mS2Level
+                + ", mStartCellId=" + cellIdToString(mStartCellId)
+                + ", mEndCellId=" + cellIdToString(mEndCellId)
+                + ", mEntryValue=" + mEntryValue
+                + '}';
+    }
+}
diff --git a/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SuffixTableSharedData.java b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SuffixTableSharedData.java
index 2221b2ced..14cb92f39 100644
--- a/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SuffixTableSharedData.java
+++ b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/SuffixTableSharedData.java
@@ -16,11 +16,13 @@
 
 package com.android.telephony.sats2range.read;
 
+import com.android.storage.block.read.TypedData;
 import com.android.storage.io.read.TypedInputStream;
 import com.android.storage.table.reader.Table;
 
 import java.io.ByteArrayInputStream;
 import java.io.IOException;
+import java.util.List;
 import java.util.Objects;
 
 /**
@@ -28,14 +30,98 @@ import java.util.Objects;
  * entries in the table and is required when interpreting the table's block data.
  */
 public final class SuffixTableSharedData {
-
+    public static final int INVALID_ENTRY_VALUE = -1;
     private final int mTablePrefix;
+    private final int mEntryValueSizeInBytes;
+    private final int mNumberOfEntryValues;
+    private final int mHeaderByteOffsetToRead;
+    private List<Integer> mEntryValuesToWrite = List.of(); // This is used for write path
+    private final TypedData mSharedDataToRead; // This is used for read path
 
     /**
      * Creates a {@link SuffixTableSharedData}. See also {@link #fromBytes(byte[])}.
      */
     public SuffixTableSharedData(int tablePrefix) {
         mTablePrefix = tablePrefix;
+        mEntryValueSizeInBytes = 0;
+        mNumberOfEntryValues = 0;
+        mHeaderByteOffsetToRead = 0;
+        mSharedDataToRead = null;
+    }
+
+    /**
+     * This constructor is used for write path
+     */
+    public SuffixTableSharedData(int tablePrefix, List<Integer> entryValues,
+            SatS2RangeFileFormat fileFormat) {
+        mSharedDataToRead = null;
+        mTablePrefix = tablePrefix;
+        mNumberOfEntryValues = entryValues.size();
+        mEntryValuesToWrite = entryValues;
+        mEntryValueSizeInBytes = fileFormat.getEntryValueSizeInBytes();
+        mHeaderByteOffsetToRead = 0;
+    }
+
+    /**
+     * This constructor is used for read path
+     */
+    public SuffixTableSharedData(TypedData sharedDataToRead, SatS2RangeFileFormat fileFormat) {
+        mSharedDataToRead = Objects.requireNonNull(sharedDataToRead);
+        int offset = 0;
+        // extract prefix value
+        mTablePrefix = mSharedDataToRead.getInt(offset);
+        offset += Integer.BYTES;
+
+        // If the size of shared data is greater than the offset, extract the number of entry
+        // values.
+        if ((offset + Integer.BYTES) < mSharedDataToRead.getSize()) {
+            mNumberOfEntryValues = mSharedDataToRead.getInt(offset);
+            mHeaderByteOffsetToRead = offset + Integer.BYTES;
+            mEntryValueSizeInBytes = fileFormat.getEntryValueSizeInBytes();
+        } else {
+            mNumberOfEntryValues = 0;
+            mHeaderByteOffsetToRead = offset;
+            mEntryValueSizeInBytes = 0;
+        }
+    }
+
+    /**
+     * This is used for read path
+     */
+    public static SuffixTableSharedData fromTypedData(TypedData sharedData,
+            SatS2RangeFileFormat fileFormat) {
+        return new SuffixTableSharedData(sharedData, fileFormat);
+    }
+
+    /**
+     * Reads the entry value at a specific position in the byte buffer and returns it.
+     *
+     * @param entryIndex The index of entry to be read.
+     * @return entry value (integer) read from the byte buffer.
+     */
+    public int getEntryValue(int entryIndex) {
+        if (mSharedDataToRead == null || entryIndex < 0 || mNumberOfEntryValues == 0) {
+            return INVALID_ENTRY_VALUE;
+        }
+
+        if (mNumberOfEntryValues == 1) {
+            entryIndex = 0;
+        }
+
+        int offset;
+        if (entryIndex < mNumberOfEntryValues) {
+            // offset = table prefix(4) + entry value count(4) + size of entry * entry index
+            offset = mHeaderByteOffsetToRead + (mEntryValueSizeInBytes * entryIndex);
+        } else {
+            return INVALID_ENTRY_VALUE;
+        }
+
+        return getValueInternal(mSharedDataToRead, mEntryValueSizeInBytes, offset);
+    }
+
+    // Entry lists to be written to a byte buffer.
+    public List<Integer> getEntryValuesToWrite() {
+        return mEntryValuesToWrite;
     }
 
     /**
@@ -46,6 +132,20 @@ public final class SuffixTableSharedData {
         return mTablePrefix;
     }
 
+    /**
+     * Returns the number of entry values.
+     */
+    public int getNumberOfEntryValues() {
+        return mNumberOfEntryValues;
+    }
+
+    /**
+     * Returns the size of entry value in Bytes.
+     */
+    public int getEntryValueSizeInBytes() {
+        return mEntryValueSizeInBytes;
+    }
+
     @Override
     public boolean equals(Object o) {
         if (this == o) {
@@ -55,18 +155,22 @@ public final class SuffixTableSharedData {
             return false;
         }
         SuffixTableSharedData that = (SuffixTableSharedData) o;
-        return mTablePrefix == that.mTablePrefix;
+        return mTablePrefix == that.mTablePrefix
+                && mNumberOfEntryValues == that.mNumberOfEntryValues
+                && mEntryValuesToWrite.equals(that.mEntryValuesToWrite);
     }
 
     @Override
     public int hashCode() {
-        return Objects.hash(mTablePrefix);
+        return Objects.hash(mTablePrefix, mNumberOfEntryValues, mEntryValuesToWrite);
     }
 
     @Override
     public String toString() {
         return "SuffixTableSharedData{"
                 + "mTablePrefix=" + mTablePrefix
+                + "mNumberOfEntries=" + mNumberOfEntryValues
+                + "mEntryValuesToWrite=" + mEntryValuesToWrite
                 + '}';
     }
 
@@ -82,4 +186,21 @@ public final class SuffixTableSharedData {
             throw new RuntimeException(e);
         }
     }
+
+    private int getValueInternal(TypedData buffer, int valueSizeBytes, int byteOffset) {
+        if (byteOffset < 0) {
+            throw new IllegalArgumentException(
+                    "byteOffset=" + byteOffset + " must not be negative");
+        }
+
+        // High bytes read first.
+        int value = 0;
+        int bytesRead = 0;
+        while (bytesRead++ < valueSizeBytes) {
+            value <<= Byte.SIZE;
+            value |= buffer.getUnsignedByte(byteOffset++);
+        }
+
+        return value;
+    }
 }
diff --git a/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/UnpopulatedSuffixTableBlock.java b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/UnpopulatedSuffixTableBlock.java
index 56730c2c3..c8ccb6b06 100644
--- a/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/UnpopulatedSuffixTableBlock.java
+++ b/utils/satellite/s2storage/src/readonly/java/com/android/telephony/sats2range/read/UnpopulatedSuffixTableBlock.java
@@ -16,6 +16,8 @@
 
 package com.android.telephony.sats2range.read;
 
+import static com.android.telephony.sats2range.read.SuffixTableSharedData.INVALID_ENTRY_VALUE;
+
 /**
  * An implementation of {@link SuffixTableBlock.SuffixTableBlockDelegate} for tables that are not
  * backed by real block data, i.e. have zero entries.
@@ -47,4 +49,16 @@ final class UnpopulatedSuffixTableBlock implements SuffixTableBlock.SuffixTableB
     public int getEntryCount() {
         return 0;
     }
+
+    /** Returns the number of entry values from the shared data. */
+    @Override
+    public int getEntryValueCount() {
+        return 0;
+    }
+
+    /** Returns the entry value from the shared data for the given index. */
+    @Override
+    public int getEntryValue(int index) {
+        return INVALID_ENTRY_VALUE;
+    }
 }
diff --git a/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SatS2RangeFileFormatTest.java b/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SatS2RangeFileFormatTest.java
index 80ef46765..65da1e424 100644
--- a/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SatS2RangeFileFormatTest.java
+++ b/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SatS2RangeFileFormatTest.java
@@ -67,10 +67,12 @@ public class SatS2RangeFileFormatTest {
         int suffixBitCount = 16;
         int suffixTableBlockIdOffset = 5;
         int suffixTableEntryBitCount = 24;
+        int suffixTableEntryValueSizeInBytes = 4;
+        int versionNumber = 2;
         boolean isAllowedList = false;
         SatS2RangeFileFormat satS2RangeFileFormat = new SatS2RangeFileFormat(s2Level,
                 prefixBitCount, suffixBitCount, suffixTableBlockIdOffset, suffixTableEntryBitCount,
-                isAllowedList);
+                isAllowedList, suffixTableEntryValueSizeInBytes, versionNumber);
 
         assertEquals(2, satS2RangeFileFormat.calculateRangeLength(
                 cellId(s2Level, 0, 0), cellId(s2Level, 0, 2)));
@@ -92,9 +94,11 @@ public class SatS2RangeFileFormatTest {
         int suffixTableBlockIdOffset = 5;
         int suffixTableEntryBitCount = 24;
         boolean isAllowedList = true;
+        int suffixTableEntryValueSizeInBytes = 4;
+        int versionNumber = 2;
         SatS2RangeFileFormat satS2RangeFileFormat = new SatS2RangeFileFormat(s2Level,
                 prefixBitCount, suffixBitCount, suffixTableBlockIdOffset, suffixTableEntryBitCount,
-                isAllowedList);
+                isAllowedList, suffixTableEntryValueSizeInBytes, versionNumber);
 
         // Too many bits for prefixValue
         assertThrows(IllegalArgumentException.class,
@@ -127,9 +131,11 @@ public class SatS2RangeFileFormatTest {
         int suffixTableBlockIdOffset = 5;
         int suffixTableEntryBitCount = 24;
         boolean isAllowedList = true;
+        int suffixTableEntryValueSizeInBytes = 4;
+        int versionNumber = 2;
         SatS2RangeFileFormat satS2RangeFileFormat = new SatS2RangeFileFormat(s2Level,
                 prefixBitCount, suffixBitCount, suffixTableBlockIdOffset, suffixTableEntryBitCount,
-                isAllowedList);
+                isAllowedList, suffixTableEntryValueSizeInBytes, versionNumber);
 
         assertEquals(0, satS2RangeFileFormat.extractFaceIdFromPrefix(0b00000000000));
         assertEquals(5, satS2RangeFileFormat.extractFaceIdFromPrefix(0b10100000000));
@@ -147,9 +153,11 @@ public class SatS2RangeFileFormatTest {
         int suffixTableBlockIdOffset = 5;
         int suffixTableEntryBitCount = 24;
         boolean isAllowedList = true;
+        int suffixTableEntryValueSizeInBytes = 4;
+        int versionNumber = 2;
         SatS2RangeFileFormat satS2RangeFileFormat = new SatS2RangeFileFormat(s2Level,
                 prefixBitCount, suffixBitCount, suffixTableBlockIdOffset, suffixTableEntryBitCount,
-                isAllowedList);
+                isAllowedList, suffixTableEntryValueSizeInBytes, versionNumber);
 
         // Too many bits for rangeLength
         assertThrows(IllegalArgumentException.class,
@@ -161,6 +169,33 @@ public class SatS2RangeFileFormatTest {
         assertTrue(satS2RangeFileFormat.isAllowedList());
     }
 
+    @Test
+    public void extractEntryValueByteCount() {
+        int s2Level = 12;
+        int prefixBitCount = 11;
+        int suffixBitCount = 16;
+        int suffixTableBlockIdOffset = 5;
+        int suffixTableEntryBitCount = 24;
+        boolean isAllowedList = true;
+        final int[] suffixTableEntryValueSizeInBytes = {5};
+        int versionNumber = 1;
+
+        // Table entry byte count exceeds BYTE range.
+        assertThrows(IllegalArgumentException.class,
+                () -> new SatS2RangeFileFormat(s2Level, prefixBitCount, suffixBitCount,
+                        suffixTableBlockIdOffset, suffixTableEntryBitCount, isAllowedList,
+                        suffixTableEntryValueSizeInBytes[0], versionNumber));
+
+        suffixTableEntryValueSizeInBytes[0] = 1;
+        SatS2RangeFileFormat satS2RangeFileFormat = new SatS2RangeFileFormat(s2Level,
+                prefixBitCount, suffixBitCount, suffixTableBlockIdOffset, suffixTableEntryBitCount,
+                isAllowedList, suffixTableEntryValueSizeInBytes[0], versionNumber);
+
+        assertEquals(suffixTableEntryValueSizeInBytes[0],
+                satS2RangeFileFormat.getEntryValueSizeInBytes());
+        assertEquals(versionNumber, satS2RangeFileFormat.getVersionNumber());
+    }
+
     private static int maxValForBits(int bits) {
         return intPow2(bits) - 1;
     }
diff --git a/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SatS2RangeFileReaderTest.java b/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SatS2RangeFileReaderTest.java
index bbfaef77f..6de40e1e8 100644
--- a/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SatS2RangeFileReaderTest.java
+++ b/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SatS2RangeFileReaderTest.java
@@ -17,10 +17,11 @@
 package com.android.telephony.sats2range;
 
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
 
-import com.android.storage.s2.S2LevelRange;
 import com.android.telephony.sats2range.read.SatS2RangeFileFormat;
 import com.android.telephony.sats2range.read.SatS2RangeFileReader;
+import com.android.telephony.sats2range.read.SuffixTableRange;
 import com.android.telephony.sats2range.utils.TestUtils;
 import com.android.telephony.sats2range.write.SatS2RangeFileWriter;
 
@@ -38,24 +39,24 @@ public class SatS2RangeFileReaderTest {
 
         SatS2RangeFileFormat fileFormat;
         boolean isAllowedList = true;
-        S2LevelRange expectedRange1, expectedRange2, expectedRange3;
+        SuffixTableRange expectedRange1, expectedRange2, expectedRange3;
         try (SatS2RangeFileWriter satS2RangeFileWriter = SatS2RangeFileWriter.open(
                 file, TestUtils.createS2RangeFileFormat(isAllowedList))) {
             fileFormat = satS2RangeFileWriter.getFileFormat();
 
             // Two ranges that share a prefix.
-            expectedRange1 = new S2LevelRange(
+            expectedRange1 = new SuffixTableRange(
                     TestUtils.createCellId(fileFormat, 1, 1000, 1000),
                     TestUtils.createCellId(fileFormat, 1, 1000, 2000));
-            expectedRange2 = new S2LevelRange(
+            expectedRange2 = new SuffixTableRange(
                     TestUtils.createCellId(fileFormat, 1, 1000, 2000),
                     TestUtils.createCellId(fileFormat, 1, 1000, 3000));
             // This range has a different prefix, so will be in a different suffix table.
-            expectedRange3 = new S2LevelRange(
+            expectedRange3 = new SuffixTableRange(
                     TestUtils.createCellId(fileFormat, 1, 1001, 1000),
                     TestUtils.createCellId(fileFormat, 1, 1001, 2000));
 
-            List<S2LevelRange> ranges = new ArrayList<>();
+            List<SuffixTableRange> ranges = new ArrayList<>();
             ranges.add(expectedRange1);
             ranges.add(expectedRange2);
             ranges.add(expectedRange3);
@@ -65,17 +66,80 @@ public class SatS2RangeFileReaderTest {
         try (SatS2RangeFileReader satS2RangeFileReader = SatS2RangeFileReader.open(file)) {
             assertEquals(isAllowedList, satS2RangeFileReader.isAllowedList());
 
-            S2LevelRange range1 = satS2RangeFileReader.findEntryByCellId(
+            SuffixTableRange range1 = satS2RangeFileReader.findEntryByCellId(
                     TestUtils.createCellId(fileFormat, 1, 1000, 1500));
             assertEquals(expectedRange1, range1);
 
-            S2LevelRange range2 = satS2RangeFileReader.findEntryByCellId(
+            SuffixTableRange range2 = satS2RangeFileReader.findEntryByCellId(
                     TestUtils.createCellId(fileFormat, 1, 1000, 2500));
             assertEquals(expectedRange2, range2);
 
-            S2LevelRange range3 = satS2RangeFileReader.findEntryByCellId(
+            SuffixTableRange range3 = satS2RangeFileReader.findEntryByCellId(
                     TestUtils.createCellId(fileFormat, 1, 1001, 1500));
             assertEquals(expectedRange3, range3);
         }
     }
+
+    @Test
+    public void findEntryByCellIdWithEntryValue() throws IOException {
+        final boolean isAllowedList = true;
+        final int entryValueSizeInBytes = 4;
+        final int versionNumber = 0;
+        final int entryValue1 = 1;
+        final int entryValue2 = 2;
+        final int entryValue3 = 3;
+
+        File file = File.createTempFile("test", ".dat");
+        SatS2RangeFileFormat fileFormat;
+
+        SuffixTableRange expectedRange1, expectedRange2, expectedRange3;
+        try (SatS2RangeFileWriter satS2RangeFileWriter = SatS2RangeFileWriter.open(file,
+                TestUtils.createS2RangeFileFormat(isAllowedList, entryValueSizeInBytes,
+                        versionNumber))) {
+            fileFormat = satS2RangeFileWriter.getFileFormat();
+
+            // Two ranges that share a prefix.
+            expectedRange1 = new SuffixTableRange(
+                    TestUtils.createCellId(fileFormat, 1, 1000, 1000),
+                    TestUtils.createCellId(fileFormat, 1, 1000, 2000),
+                    entryValue1);
+            expectedRange2 = new SuffixTableRange(
+                    TestUtils.createCellId(fileFormat, 1, 1000, 2000),
+                    TestUtils.createCellId(fileFormat, 1, 1000, 3000),
+                    entryValue2);
+            // This range has a different prefix, so will be in a different suffix table.
+            expectedRange3 = new SuffixTableRange(
+                    TestUtils.createCellId(fileFormat, 1, 1001, 1000),
+                    TestUtils.createCellId(fileFormat, 1, 1001, 2000),
+                    entryValue3);
+
+            List<SuffixTableRange> ranges = new ArrayList<>();
+            ranges.add(expectedRange1);
+            ranges.add(expectedRange2);
+            ranges.add(expectedRange3);
+            satS2RangeFileWriter.createSortedSuffixBlocks(ranges.iterator());
+        }
+
+        try (SatS2RangeFileReader satS2RangeFileReader = SatS2RangeFileReader.open(file)) {
+            assertEquals(isAllowedList, satS2RangeFileReader.isAllowedList());
+
+            SuffixTableRange range1 = satS2RangeFileReader.findEntryByCellId(
+                    TestUtils.createCellId(fileFormat, 1, 1000, 1500));
+            assertNotNull(range1);
+            assertEquals(expectedRange1, range1);
+            assertEquals(entryValue1, range1.getEntryValue());
+
+            SuffixTableRange range2 = satS2RangeFileReader.findEntryByCellId(
+                    TestUtils.createCellId(fileFormat, 1, 1000, 2500));
+            assertNotNull(range2);
+            assertEquals(expectedRange2, range2);
+            assertEquals(entryValue2, range2.getEntryValue());
+
+            SuffixTableRange range3 = satS2RangeFileReader.findEntryByCellId(
+                    TestUtils.createCellId(fileFormat, 1, 1001, 1500));
+            assertNotNull(range3);
+            assertEquals(expectedRange3, range3);
+            assertEquals(entryValue3, range3.getEntryValue());
+        }
+    }
 }
diff --git a/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SuffixTableBlockTest.java b/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SuffixTableBlockTest.java
index 04b915bf9..7b9ce4a95 100644
--- a/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SuffixTableBlockTest.java
+++ b/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SuffixTableBlockTest.java
@@ -24,9 +24,9 @@ import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.argThat;
 
 import com.android.storage.block.write.BlockWriter;
-import com.android.storage.s2.S2LevelRange;
 import com.android.telephony.sats2range.read.SatS2RangeFileFormat;
 import com.android.telephony.sats2range.read.SuffixTableBlock;
+import com.android.telephony.sats2range.read.SuffixTableRange;
 import com.android.telephony.sats2range.read.SuffixTableSharedData;
 import com.android.telephony.sats2range.utils.TestUtils;
 import com.android.telephony.sats2range.write.SuffixTableWriter;
@@ -78,12 +78,14 @@ public class SuffixTableBlockTest {
         long invalidEndCellId = fileFormat.createCellId(tablePrefixValue + 1, maxSuffixValue);
         long validEndCellId = fileFormat.createCellId(tablePrefixValue, maxSuffixValue);
         {
-            S2LevelRange badStartCellId = new S2LevelRange(invalidStartCellId, validEndCellId);
+            SuffixTableRange badStartCellId = new SuffixTableRange(invalidStartCellId,
+                    validEndCellId);
             assertThrows(IllegalArgumentException.class,
                     () -> suffixTableWriter.addRange(badStartCellId));
         }
         {
-            S2LevelRange badEndCellId = new S2LevelRange(validStartCellId, invalidEndCellId);
+            SuffixTableRange badEndCellId = new SuffixTableRange(validStartCellId,
+                    invalidEndCellId);
             assertThrows(IllegalArgumentException.class,
                     () -> suffixTableWriter.addRange(badEndCellId));
         }
@@ -101,13 +103,13 @@ public class SuffixTableBlockTest {
 
         SuffixTableWriter suffixTableWriter =
                 SuffixTableWriter.createPopulated(fileFormat, suffixTableSharedData);
-        S2LevelRange suffixTableRange1 = new S2LevelRange(
+        SuffixTableRange suffixTableRange1 = new SuffixTableRange(
                 fileFormat.createCellId(tablePrefixValue, 1000),
                 fileFormat.createCellId(tablePrefixValue, 1001));
         suffixTableWriter.addRange(suffixTableRange1);
 
         // It's fine to add a range that starts adjacent to the last one.
-        S2LevelRange suffixTableRange2 = new S2LevelRange(
+        SuffixTableRange suffixTableRange2 = new SuffixTableRange(
                 fileFormat.createCellId(tablePrefixValue, 1001),
                 fileFormat.createCellId(tablePrefixValue, 1002));
         suffixTableWriter.addRange(suffixTableRange2);
@@ -117,7 +119,7 @@ public class SuffixTableBlockTest {
                 () -> suffixTableWriter.addRange(suffixTableRange2));
 
         // Try similar checks at the top end of the table.
-        S2LevelRange suffixTableRange3 = new S2LevelRange(
+        SuffixTableRange suffixTableRange3 = new SuffixTableRange(
                 fileFormat.createCellId(tablePrefixValue, maxSuffixValue - 1),
                 fileFormat.createCellId(tablePrefixValue, maxSuffixValue));
         suffixTableWriter.addRange(suffixTableRange3);
@@ -131,7 +133,7 @@ public class SuffixTableBlockTest {
                 () -> suffixTableWriter.addRange(suffixTableRange3));
 
         // Now "complete" the table: there can be no entry after this one.
-        S2LevelRange suffixTableRange4 = new S2LevelRange(
+        SuffixTableRange suffixTableRange4 = new SuffixTableRange(
                 fileFormat.createCellId(tablePrefixValue, maxSuffixValue),
                 fileFormat.createCellId(tablePrefixValue + 1, 0));
         suffixTableWriter.addRange(suffixTableRange4);
@@ -180,23 +182,23 @@ public class SuffixTableBlockTest {
 
         long entry1StartCellId = fileFormat.createCellId(tablePrefix, 1000);
         long entry1EndCellId = fileFormat.createCellId(tablePrefix, 2000);
-        S2LevelRange entry1 = new S2LevelRange(entry1StartCellId, entry1EndCellId);
+        SuffixTableRange entry1 = new SuffixTableRange(entry1StartCellId, entry1EndCellId);
         suffixTableWriter.addRange(entry1);
 
         long entry2StartCellId = fileFormat.createCellId(tablePrefix, 2000);
         long entry2EndCellId = fileFormat.createCellId(tablePrefix, 3000);
-        S2LevelRange entry2 = new S2LevelRange(entry2StartCellId, entry2EndCellId);
+        SuffixTableRange entry2 = new SuffixTableRange(entry2StartCellId, entry2EndCellId);
         suffixTableWriter.addRange(entry2);
 
         // There is a deliberate gap here between entry2 and entry3.
         long entry3StartCellId = fileFormat.createCellId(tablePrefix, 4000);
         long entry3EndCellId = fileFormat.createCellId(tablePrefix, 5000);
-        S2LevelRange entry3 = new S2LevelRange(entry3StartCellId, entry3EndCellId);
+        SuffixTableRange entry3 = new SuffixTableRange(entry3StartCellId, entry3EndCellId);
         suffixTableWriter.addRange(entry3);
 
         long entry4StartCellId = fileFormat.createCellId(tablePrefix, maxSuffix - 999);
         long entry4EndCellId = fileFormat.createCellId(tablePrefix + 1, 0);
-        S2LevelRange entry4 = new S2LevelRange(entry4StartCellId, entry4EndCellId);
+        SuffixTableRange entry4 = new SuffixTableRange(entry4StartCellId, entry4EndCellId);
         suffixTableWriter.addRange(entry4);
 
         BlockWriter.ReadBack blockReadback = suffixTableWriter.close();
@@ -251,7 +253,7 @@ public class SuffixTableBlockTest {
                 SuffixTableWriter.createPopulated(fileFormat, suffixTableSharedData);
         long entry1StartCellId = fileFormat.createCellId(tablePrefix, 1000);
         long entry1EndCellId = fileFormat.createCellId(tablePrefix, 2000);
-        S2LevelRange entry1 = new S2LevelRange(entry1StartCellId, entry1EndCellId);
+        SuffixTableRange entry1 = new SuffixTableRange(entry1StartCellId, entry1EndCellId);
         suffixTableWriter.addRange(entry1);
         BlockWriter.ReadBack blockReadback = suffixTableWriter.close();
 
@@ -276,12 +278,12 @@ public class SuffixTableBlockTest {
         SuffixTableWriter suffixTableWriter =
                 SuffixTableWriter.createPopulated(fileFormat, sharedData);
 
-        S2LevelRange entry1 = new S2LevelRange(
+        SuffixTableRange entry1 = new SuffixTableRange(
                 fileFormat.createCellId(tablePrefix, 1001),
                 fileFormat.createCellId(tablePrefix, 1101));
         suffixTableWriter.addRange(entry1);
 
-        S2LevelRange entry2 = new S2LevelRange(
+        SuffixTableRange entry2 = new SuffixTableRange(
                 fileFormat.createCellId(tablePrefix, 2001),
                 fileFormat.createCellId(tablePrefix, 2101));
         suffixTableWriter.addRange(entry2);
@@ -302,7 +304,7 @@ public class SuffixTableBlockTest {
         inOrder.verify(mockVisitor).end();
     }
 
-    private S2LevelRange findEntryByCellId(SatS2RangeFileFormat fileFormat,
+    private SuffixTableRange findEntryByCellId(SatS2RangeFileFormat fileFormat,
             SuffixTableBlock suffixTableBlock, int prefix, int suffix) {
         long cellId = fileFormat.createCellId(prefix, suffix);
         SuffixTableBlock.Entry entry = suffixTableBlock.findEntryByCellId(cellId);
diff --git a/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SuffixTableExtraInfoTest.java b/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SuffixTableExtraInfoTest.java
index f992ae7e2..f978bd5a8 100644
--- a/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SuffixTableExtraInfoTest.java
+++ b/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SuffixTableExtraInfoTest.java
@@ -20,9 +20,9 @@ import static org.junit.Assert.assertEquals;
 
 import com.android.storage.block.read.BlockInfo;
 import com.android.storage.block.write.BlockWriter;
-import com.android.storage.s2.S2LevelRange;
 import com.android.telephony.sats2range.read.SatS2RangeFileFormat;
 import com.android.telephony.sats2range.read.SuffixTableExtraInfo;
+import com.android.telephony.sats2range.read.SuffixTableRange;
 import com.android.telephony.sats2range.read.SuffixTableSharedData;
 import com.android.telephony.sats2range.utils.TestUtils;
 import com.android.telephony.sats2range.write.SuffixTableWriter;
@@ -54,13 +54,13 @@ public class SuffixTableExtraInfoTest {
                 SuffixTableWriter.createPopulated(fileFormat, suffixTableSharedData);
 
         int tablePrefix = suffixTableSharedData.getTablePrefix();
-        S2LevelRange range1 = new S2LevelRange(
+        SuffixTableRange range1 = new SuffixTableRange(
                 fileFormat.createCellId(tablePrefix, 1000),
                 fileFormat.createCellId(tablePrefix, 1001));
-        S2LevelRange range2 = new S2LevelRange(
+        SuffixTableRange range2 = new SuffixTableRange(
                 fileFormat.createCellId(tablePrefix, 1002),
                 fileFormat.createCellId(tablePrefix, 1003));
-        S2LevelRange range3 = new S2LevelRange(
+        SuffixTableRange range3 = new SuffixTableRange(
                 fileFormat.createCellId(tablePrefix, 1004),
                 fileFormat.createCellId(tablePrefix, 1005));
 
diff --git a/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SuffixTableSharedDataTest.java b/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SuffixTableSharedDataTest.java
index 2baefa9e5..ee2162662 100644
--- a/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SuffixTableSharedDataTest.java
+++ b/utils/satellite/s2storage/src/test/java/com/android/telephony/sats2range/SuffixTableSharedDataTest.java
@@ -18,11 +18,18 @@ package com.android.telephony.sats2range;
 
 import static org.junit.Assert.assertEquals;
 
+import com.android.storage.block.read.BlockData;
+import com.android.telephony.sats2range.read.SatS2RangeFileFormat;
 import com.android.telephony.sats2range.read.SuffixTableSharedData;
 import com.android.telephony.sats2range.write.SuffixTableSharedDataWriter;
 
 import org.junit.Test;
 
+import java.nio.ByteBuffer;
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.List;
+
 /** Tests for {@link SuffixTableSharedData} and {@link SuffixTableSharedDataWriter}. */
 public class SuffixTableSharedDataTest {
     @Test
@@ -33,5 +40,106 @@ public class SuffixTableSharedDataTest {
 
         assertEquals(sharedData, SuffixTableSharedData.fromBytes(bytes));
     }
-}
 
+    @Test
+    public void testSuffixTableSharedDataWithEntryValues() {
+        int prefix = 321;
+        int entryValueSizeInBytes = 1;
+        List<Integer> entryValues = new ArrayList<>(Arrays.asList(0x01, 0x7F, 0xFF));
+        int versionNumber = 1;
+
+        // Verify whether fromTypedData returns correct SuffixTableSharedData when entryByte is 1
+        verifySharedData(prefix, entryValueSizeInBytes, entryValues.size(), entryValues,
+                versionNumber);
+
+        // Verify when entryValueSizeInBytes is 2
+        entryValueSizeInBytes = 2;
+        entryValues = new ArrayList<>(Arrays.asList(0x001, 0x5FFF, 0xAFFF, 0xFFFF));
+        verifySharedData(prefix, entryValueSizeInBytes, entryValues.size(), entryValues,
+                versionNumber);
+
+        // Verify when entryValueSizeInBytes is 3
+        entryValueSizeInBytes = 3;
+        entryValues = new ArrayList<>(
+                Arrays.asList(0x000001, 0x4FFFFF, 0x8FFFFF, 0xBFFFFF, 0xFFFFFF));
+        verifySharedData(prefix, entryValueSizeInBytes, entryValues.size(), entryValues,
+                versionNumber);
+
+        // Verify when entryValueSizeInBytes is 4, max int value is 0x7FFFFFFF.
+        // ConfigID is supported up to 0x7FFFFFFF for now.
+        entryValueSizeInBytes = 4;
+        entryValues = new ArrayList<>(
+                Arrays.asList(0x00000001, 0x2FFFFFFF, 0x3FFFFFFF, 0x4FFFFFFF, 0x5FFFFFFF,
+                        0x6FFFFFFF, 0x7FFFFFFF));
+        verifySharedData(prefix, entryValueSizeInBytes, entryValues.size(), entryValues,
+                versionNumber);
+
+        // Verify when every entry has same value.
+        entryValues = new ArrayList<>(
+                Arrays.asList(0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF, 0x3FFFFFFF,
+                        0x3FFFFFFF, 0x3FFFFFFF));
+        verifySharedData(prefix, entryValueSizeInBytes, entryValues.size(), entryValues,
+                versionNumber);
+
+        // Verify when entry is empty
+        // entryValueSizeInBytes is set as 4, but there is no entry list
+        entryValues = new ArrayList<>(List.of());
+        verifySharedData(prefix, entryValueSizeInBytes, entryValues.size(), entryValues,
+                versionNumber);
+        // entryValueSizeInBytes is 0, no entry list
+        entryValueSizeInBytes = 0;
+        verifySharedData(prefix, entryValueSizeInBytes, entryValues.size(), entryValues,
+                versionNumber);
+    }
+
+    private BlockData createBlockedDataFromByteBuffer(int prefix,
+            List<Integer> entryValues, SatS2RangeFileFormat fileFormat) {
+        SuffixTableSharedData sharedDataToWrite = new SuffixTableSharedData(prefix, entryValues,
+                fileFormat);
+        ByteBuffer byteBuffer = ByteBuffer.wrap(
+                SuffixTableSharedDataWriter.toBytes(sharedDataToWrite));
+        return new BlockData(byteBuffer.asReadOnlyBuffer());
+    }
+
+    private void verifySharedData(int expectedTablePrefix, int expectedEntryValueSizeInBytes,
+            int expectedNumberOfEntryValues, List<Integer> expectedEntryValues, int versionNumber) {
+        SatS2RangeFileFormat fileFormat = createSatS2RangeFileFormat(expectedEntryValueSizeInBytes,
+                versionNumber);
+        BlockData blockData = createBlockedDataFromByteBuffer(
+                expectedTablePrefix, expectedEntryValues, fileFormat);
+        SuffixTableSharedData sharedData = SuffixTableSharedData.fromTypedData(blockData,
+                fileFormat);
+
+        assertEquals(expectedTablePrefix, sharedData.getTablePrefix());
+        if (!expectedEntryValues.isEmpty()) {
+            assertEquals(expectedEntryValueSizeInBytes, sharedData.getEntryValueSizeInBytes());
+        } else {
+            assertEquals(0, sharedData.getEntryValueSizeInBytes());
+        }
+
+        // If every entry has same value, block data contains only 1 entry info
+        if (expectedEntryValues.stream().distinct().count() == 1) {
+            assertEquals(3 * Integer.BYTES, blockData.getSize());
+            // Verify whether the entry value count has been set to 1.
+            assertEquals(1, sharedData.getNumberOfEntryValues());
+        } else {
+            assertEquals(expectedNumberOfEntryValues, sharedData.getNumberOfEntryValues());
+        }
+        for (int i = 0; i < expectedNumberOfEntryValues; i++) {
+            assertEquals((int) expectedEntryValues.get(i), sharedData.getEntryValue(i));
+        }
+    }
+
+    private SatS2RangeFileFormat createSatS2RangeFileFormat(int entryByteCount, int versionNumber) {
+        int s2Level = 12;
+        int prefixBitCount = 11;
+        int suffixBitCount = 16;
+        int suffixTableBlockIdOffset = 5;
+        int suffixTableEntryBitCount = 24;
+        boolean isAllowedList = true;
+
+        return new SatS2RangeFileFormat(s2Level,
+                prefixBitCount, suffixBitCount, suffixTableBlockIdOffset, suffixTableEntryBitCount,
+                isAllowedList, entryByteCount, versionNumber);
+    }
+}
diff --git a/utils/satellite/s2storage/src/testutils/java/com/android/telephony/sats2range/testutils/TestUtils.java b/utils/satellite/s2storage/src/testutils/java/com/android/telephony/sats2range/testutils/TestUtils.java
index 3dfc720b2..a7e7d0beb 100644
--- a/utils/satellite/s2storage/src/testutils/java/com/android/telephony/sats2range/testutils/TestUtils.java
+++ b/utils/satellite/s2storage/src/testutils/java/com/android/telephony/sats2range/testutils/TestUtils.java
@@ -19,25 +19,37 @@ package com.android.telephony.sats2range.utils;
 import static com.android.storage.s2.S2Support.FACE_BIT_COUNT;
 
 import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.fail;
 
 import com.android.storage.util.BitwiseUtils;
 import com.android.telephony.sats2range.read.SatS2RangeFileFormat;
 
 import java.io.File;
 import java.io.IOException;
+import java.io.InputStream;
 import java.io.PrintStream;
 import java.nio.file.FileVisitResult;
 import java.nio.file.Files;
 import java.nio.file.Path;
 import java.nio.file.SimpleFileVisitor;
+import java.nio.file.StandardCopyOption;
 import java.nio.file.attribute.BasicFileAttributes;
 
 /** A utility class for satellite tests */
 public class TestUtils {
     public static final int TEST_S2_LEVEL = 12;
+    public static final String TEST_DATA_RESOURCE_DIR = "data/";
 
     /** Returns a valid {@link SatS2RangeFileFormat}. */
     public static SatS2RangeFileFormat createS2RangeFileFormat(boolean isAllowedList) {
+        return createS2RangeFileFormat(isAllowedList,
+                /* entryValueSizeInBytes */0,
+                /* versionNumber */0);
+    }
+
+    /** Returns a valid {@link SatS2RangeFileFormat}. */
+    public static SatS2RangeFileFormat createS2RangeFileFormat(boolean isAllowedList,
+            int entryValueSizeInBytes, int versionNumber) {
         int dataS2Level = TEST_S2_LEVEL;
         int faceIdBits = 3;
         int bitCountPerLevel = 2;
@@ -48,7 +60,8 @@ public class TestUtils {
         int suffixTableEntryBitCount = 4 * Byte.SIZE;
         int suffixTableBlockIdOffset = 5;
         return new SatS2RangeFileFormat(dataS2Level, prefixBitCount, suffixBitCount,
-                suffixTableBlockIdOffset, suffixTableEntryBitCount, isAllowedList);
+                suffixTableBlockIdOffset, suffixTableEntryBitCount, isAllowedList,
+                entryValueSizeInBytes, versionNumber);
     }
 
     /** Create an S2 cell ID */
@@ -77,6 +90,31 @@ public class TestUtils {
         return fileFormat.createCellId(prefixValue, suffixBits);
     }
 
+    /**
+     * Copy a test resource to the target directory.
+     */
+    public static Path copyTestResource(Class<?> baseClass, String testResource, Path targetDir)
+            throws IOException {
+        Files.createDirectories(targetDir);
+        return copyResource(baseClass, TEST_DATA_RESOURCE_DIR + testResource, targetDir);
+    }
+
+    private static Path copyResource(Class<?> baseClass, String relativeResourcePath,
+            Path targetDir) throws IOException {
+        String fileName = relativeResourcePath;
+        if (relativeResourcePath.contains("/")) {
+            fileName = relativeResourcePath.substring(relativeResourcePath.lastIndexOf('/') + 1);
+        }
+        Path targetResourceFile = targetDir.resolve(fileName);
+        try (InputStream inputStream = baseClass.getResourceAsStream(relativeResourcePath)) {
+            if (inputStream == null) {
+                fail("Resource=" + relativeResourcePath + " not found");
+            }
+            Files.copy(inputStream, targetResourceFile, StandardCopyOption.REPLACE_EXISTING);
+        }
+        return targetResourceFile;
+    }
+
     /** Create a temporary directory */
     public static Path createTempDir(Class<?> testClass) throws IOException {
         return Files.createTempDirectory(testClass.getSimpleName());
@@ -107,21 +145,19 @@ public class TestUtils {
         try (PrintStream printer = new PrintStream(outputFile)) {
             // Range 1
             for (int suffix = 1000; suffix < 2000; suffix++) {
-                printer.println(fileFormat.createCellId(0b100_11111111, suffix));
+                printer.println(fileFormat.createCellId(0b100_11111111, suffix) + ",1");
             }
 
             // Range 2
             for (int suffix = 2001; suffix < 3000; suffix++) {
-                printer.println(fileFormat.createCellId(0b100_11111111, suffix));
+                printer.println(fileFormat.createCellId(0b100_11111111, suffix) + ",2");
             }
 
             // Range 3
             for (int suffix = 1000; suffix < 2000; suffix++) {
-                printer.println(fileFormat.createCellId(0b101_11111111, suffix));
+                printer.println(fileFormat.createCellId(0b101_11111111, suffix) + ",3");
             }
-            printer.print(fileFormat.createCellId(0b101_11111111, 2000));
-
-            printer.close();
+            printer.print(fileFormat.createCellId(0b101_11111111, 2000) + ",3");
         }
     }
 
@@ -130,15 +166,41 @@ public class TestUtils {
             File outputFile, SatS2RangeFileFormat fileFormat) throws Exception {
         try (PrintStream printer = new PrintStream(outputFile)) {
             // Valid line
-            printer.println(fileFormat.createCellId(0b100_11111111, 100));
+            printer.println(fileFormat.createCellId(0b100_11111111, 100) + ",0");
 
             // Invalid line
             printer.print("Invalid line");
 
             // Another valid line
-            printer.println(fileFormat.createCellId(0b100_11111111, 200));
+            printer.println(fileFormat.createCellId(0b100_11111111, 200) + ",1");
+        }
+    }
 
-            printer.close();
+    /** Create a valid test satellite S2 cell file */
+    public static void createValidTestS2CellFileWithValidEntryValue(
+            File outputFile, SatS2RangeFileFormat fileFormat) throws Exception {
+
+        try (PrintStream printer = new PrintStream(outputFile)) {
+            // Range 1
+            for (int suffix = 1000; suffix < 1500; suffix++) {
+                printer.println(fileFormat.createCellId(0b100_11111111, suffix) + ",1");
+            }
+
+            // Range 2
+            for (int suffix = 1500; suffix < 2000; suffix++) {
+                printer.println(fileFormat.createCellId(0b100_11111111, suffix) + ",2");
+            }
+
+            // Range 3
+            for (int suffix = 2001; suffix < 3000; suffix++) {
+                printer.println(fileFormat.createCellId(0b100_11111111, suffix) + ",3");
+            }
+
+            // Range 4
+            for (int suffix = 1000; suffix < 2000; suffix++) {
+                printer.println(fileFormat.createCellId(0b101_11111111, suffix) + ",4");
+            }
+            printer.print(fileFormat.createCellId(0b101_11111111, 2000) + ",4");
         }
     }
 }
diff --git a/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/HeaderBlockWriter.java b/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/HeaderBlockWriter.java
index d4e9310d3..04359225f 100644
--- a/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/HeaderBlockWriter.java
+++ b/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/HeaderBlockWriter.java
@@ -63,6 +63,8 @@ public final class HeaderBlockWriter implements BlockWriter {
             tos.writeUnsignedByte(mFileFormat.getSuffixTableBlockIdOffset());
             tos.writeUnsignedByte(mFileFormat.isAllowedList()
                     ? HeaderBlock.TRUE : HeaderBlock.FALSE);
+            tos.writeUnsignedByte(mFileFormat.getEntryValueSizeInBytes());
+            tos.writeInt(mFileFormat.getVersionNumber());
         }
 
         FileChannel fileChannel = FileChannel.open(mFile.toPath(), StandardOpenOption.READ);
diff --git a/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/SatS2RangeFileWriter.java b/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/SatS2RangeFileWriter.java
index 9b3c20ea8..1827a9671 100644
--- a/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/SatS2RangeFileWriter.java
+++ b/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/SatS2RangeFileWriter.java
@@ -19,9 +19,9 @@ package com.android.telephony.sats2range.write;
 import com.android.storage.block.write.BlockFileWriter;
 import com.android.storage.block.write.BlockWriter;
 import com.android.storage.block.write.EmptyBlockWriter;
-import com.android.storage.s2.S2LevelRange;
 import com.android.storage.s2.S2Support;
 import com.android.telephony.sats2range.read.SatS2RangeFileFormat;
+import com.android.telephony.sats2range.read.SuffixTableRange;
 import com.android.telephony.sats2range.read.SuffixTableSharedData;
 
 import java.io.File;
@@ -64,8 +64,8 @@ public final class SatS2RangeFileWriter implements AutoCloseable {
      * needed to fit them into suffix blocks. The ranges must be of the expected S2 level
      * and ordered by cell ID.
      */
-    public void createSortedSuffixBlocks(Iterator<S2LevelRange> ranges) throws IOException {
-        PushBackIterator<S2LevelRange> pushBackIterator = new PushBackIterator<>(ranges);
+    public void createSortedSuffixBlocks(Iterator<SuffixTableRange> ranges) throws IOException {
+        PushBackIterator<SuffixTableRange> pushBackIterator = new PushBackIterator<>(ranges);
 
         // For each prefix value, collect all the ranges that match.
         for (int currentPrefix = 0;
@@ -74,7 +74,7 @@ public final class SatS2RangeFileWriter implements AutoCloseable {
 
             // Step 1:
             // populate samePrefixRanges, which holds ranges that have a prefix of currentPrefix.
-            List<S2LevelRange> samePrefixRanges =
+            List<SuffixTableRange> samePrefixRanges =
                     collectSamePrefixRanges(pushBackIterator, currentPrefix);
 
             // Step 2: Write samePrefixRanges to a suffix table.
@@ -88,11 +88,12 @@ public final class SatS2RangeFileWriter implements AutoCloseable {
         }
     }
 
-    private List<S2LevelRange> collectSamePrefixRanges(
-            PushBackIterator<S2LevelRange> pushBackIterator, int currentPrefix) {
-        List<S2LevelRange> samePrefixRanges = new ArrayList<>();
+    private List<SuffixTableRange> collectSamePrefixRanges(
+            PushBackIterator<SuffixTableRange> pushBackIterator, int currentPrefix) {
+        List<SuffixTableRange> samePrefixRanges = new ArrayList<>();
         while (pushBackIterator.hasNext()) {
-            S2LevelRange currentRange = pushBackIterator.next();
+            SuffixTableRange currentRange = pushBackIterator.next();
+            int entryValue = currentRange.getEntryValue();
 
             long startCellId = currentRange.getStartCellId();
             if (mFileFormat.getS2Level() != S2Support.getS2Level(startCellId)) {
@@ -123,17 +124,19 @@ public final class SatS2RangeFileWriter implements AutoCloseable {
                 // Create a range for the current prefix.
                 {
                     long newEndCellId = mFileFormat.createCellId(startCellPrefix + 1, 0);
-                    S2LevelRange satS2Range = new S2LevelRange(startCellId, newEndCellId);
+                    SuffixTableRange satS2Range = new SuffixTableRange(startCellId, newEndCellId,
+                            entryValue);
                     samePrefixRanges.add(satS2Range);
                 }
 
-                Deque<S2LevelRange> otherRanges = new ArrayDeque<>();
+                Deque<SuffixTableRange> otherRanges = new ArrayDeque<>();
                 // Intermediate prefixes.
                 startCellPrefix = startCellPrefix + 1;
                 while (startCellPrefix != endCellPrefixValue) {
                     long newStartCellId = mFileFormat.createCellId(startCellPrefix, 0);
                     long newEndCellId = mFileFormat.createCellId(startCellPrefix + 1, 0);
-                    S2LevelRange satS2Range = new S2LevelRange(newStartCellId, newEndCellId);
+                    SuffixTableRange satS2Range = new SuffixTableRange(newStartCellId,
+                            newEndCellId, entryValue);
                     otherRanges.add(satS2Range);
                     startCellPrefix++;
                 }
@@ -142,7 +145,8 @@ public final class SatS2RangeFileWriter implements AutoCloseable {
                 {
                     long newStartCellId = mFileFormat.createCellId(endCellPrefixValue, 0);
                     if (newStartCellId != endCellId) {
-                        S2LevelRange satS2Range = new S2LevelRange(newStartCellId, endCellId);
+                        SuffixTableRange satS2Range = new SuffixTableRange(newStartCellId,
+                                endCellId, entryValue);
                         otherRanges.add(satS2Range);
                     }
                 }
@@ -160,41 +164,22 @@ public final class SatS2RangeFileWriter implements AutoCloseable {
     }
 
     private BlockWriter writeSamePrefixRanges(
-            int currentPrefix, List<S2LevelRange> samePrefixRanges) throws IOException {
+            int currentPrefix, List<SuffixTableRange> samePrefixRanges) throws IOException {
         BlockWriter blockWriter;
         if (samePrefixRanges.size() == 0) {
             // Add an empty block.
             blockWriter = SuffixTableWriter.createEmptyBlockWriter();
         } else {
+            List<SuffixTableRange> suffixTableRanges = convertSamePrefixRangesToSuffixTableRanges(
+                    samePrefixRanges);
+            List<Integer> entryValues = getEntryValues(suffixTableRanges);
             // Create a suffix table block.
-            SuffixTableSharedData sharedData = new SuffixTableSharedData(currentPrefix);
+            SuffixTableSharedData sharedData = new SuffixTableSharedData(currentPrefix, entryValues,
+                    mFileFormat);
             SuffixTableWriter suffixTableWriter =
                     SuffixTableWriter.createPopulated(mFileFormat, sharedData);
-            S2LevelRange lastRange = null;
-            for (S2LevelRange currentRange : samePrefixRanges) {
-                // Validate ranges don't overlap.
-                if (lastRange != null) {
-                    if (lastRange.overlaps(currentRange)) {
-                        throw new IllegalStateException("lastRange=" + lastRange + " overlaps"
-                                + " currentRange=" + currentRange);
-                    }
-                }
-                lastRange = currentRange;
-
-                // Split the range so it fits.
-                final int maxRangeLength = mFileFormat.getTableEntryMaxRangeLengthValue();
-                long startCellId = currentRange.getStartCellId();
-                long endCellId = currentRange.getEndCellId();
-                int rangeLength = mFileFormat.calculateRangeLength(startCellId, endCellId);
-                while (rangeLength > maxRangeLength) {
-                    long newEndCellId = S2Support.offsetCellId(startCellId, maxRangeLength);
-                    S2LevelRange suffixTableRange = new S2LevelRange(startCellId, newEndCellId);
-                    suffixTableWriter.addRange(suffixTableRange);
-                    startCellId = newEndCellId;
-                    rangeLength = mFileFormat.calculateRangeLength(startCellId, endCellId);
-                }
-                S2LevelRange suffixTableRange = new S2LevelRange(startCellId, endCellId);
-                suffixTableWriter.addRange(suffixTableRange);
+            for (SuffixTableRange range : suffixTableRanges) {
+                suffixTableWriter.addRange(range);
             }
             blockWriter = suffixTableWriter;
         }
@@ -234,4 +219,48 @@ public final class SatS2RangeFileWriter implements AutoCloseable {
     public SatS2RangeFileFormat getFileFormat() {
         return mFileFormat;
     }
+
+    private List<SuffixTableRange> convertSamePrefixRangesToSuffixTableRanges(
+            List<SuffixTableRange> samePrefixRanges) {
+        List<SuffixTableRange> suffixTableRanges = new ArrayList<>();
+        SuffixTableRange lastRange = null;
+        for (SuffixTableRange currentRange : samePrefixRanges) {
+            // Validate ranges don't overlap.
+            if (lastRange != null) {
+                if (lastRange.overlaps(currentRange)) {
+                    throw new IllegalStateException("lastRange=" + lastRange + " overlaps"
+                            + " currentRange=" + currentRange);
+                }
+            }
+            lastRange = currentRange;
+            int entryValue = currentRange.getEntryValue();
+
+            // Split the range so it fits.
+            final int maxRangeLength = mFileFormat.getTableEntryMaxRangeLengthValue();
+            long startCellId = currentRange.getStartCellId();
+            long endCellId = currentRange.getEndCellId();
+            int rangeLength = mFileFormat.calculateRangeLength(startCellId, endCellId);
+            while (rangeLength > maxRangeLength) {
+                long newEndCellId = S2Support.offsetCellId(startCellId, maxRangeLength);
+                SuffixTableRange suffixTableRange =
+                        new SuffixTableRange(startCellId, newEndCellId, entryValue);
+                suffixTableRanges.add(suffixTableRange);
+                startCellId = newEndCellId;
+                rangeLength = mFileFormat.calculateRangeLength(startCellId, endCellId);
+            }
+            SuffixTableRange suffixTableRange =
+                    new SuffixTableRange(startCellId, endCellId, entryValue);
+            suffixTableRanges.add(suffixTableRange);
+        }
+        return suffixTableRanges;
+    }
+
+    private List<Integer> getEntryValues(List<SuffixTableRange> suffixTableRanges) {
+        List<Integer> entryValues = new ArrayList<>();
+        for (SuffixTableRange suffixTableRange : suffixTableRanges) {
+            entryValues.add(suffixTableRange.getEntryValue());
+        }
+        return entryValues;
+    }
+
 }
diff --git a/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/SuffixTableSharedDataWriter.java b/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/SuffixTableSharedDataWriter.java
index 54991482c..a739e5e69 100644
--- a/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/SuffixTableSharedDataWriter.java
+++ b/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/SuffixTableSharedDataWriter.java
@@ -21,21 +21,37 @@ import com.android.telephony.sats2range.read.SuffixTableSharedData;
 
 import java.io.ByteArrayOutputStream;
 import java.io.IOException;
+import java.util.List;
 
 /**
  * Converts a {@link SuffixTableSharedData} to a byte[] for writing.
  * See also {@link SuffixTableSharedData#fromBytes(byte[])}.
  */
 public final class SuffixTableSharedDataWriter {
-
+    private static final int BUFFER_SIZE = (int) Math.pow(2, 20);
     private SuffixTableSharedDataWriter() {
     }
 
     /** Returns the byte[] for the supplied {@link SuffixTableSharedData} */
     public static byte[] toBytes(SuffixTableSharedData suffixTableSharedData) {
+        int entryValueSizeInBytes = suffixTableSharedData.getEntryValueSizeInBytes();
+        List<Integer> entryValues = suffixTableSharedData.getEntryValuesToWrite();
+        // If every entry has same value, compress to save memory
+        int numberOfEntryValues =
+                entryValues.stream().distinct().count() == 1 ? 1 : entryValues.size();
+
         try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
-                TypedOutputStream tos = new TypedOutputStream(baos)) {
+                TypedOutputStream tos = new TypedOutputStream(baos, BUFFER_SIZE)) {
             tos.writeInt(suffixTableSharedData.getTablePrefix());
+
+            if (entryValueSizeInBytes > 0 && !entryValues.isEmpty()) {
+                tos.writeInt(numberOfEntryValues);
+                for (int i = 0; i < numberOfEntryValues; i++) {
+                    // ConfigId is supported up to 0x7FFFFFFF
+                    tos.writeVarByteValue(entryValueSizeInBytes, entryValues.get(i));
+                }
+            }
+
             tos.flush();
             return baos.toByteArray();
         } catch (IOException e) {
diff --git a/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/SuffixTableWriter.java b/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/SuffixTableWriter.java
index dc265d57f..31b35eb26 100644
--- a/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/SuffixTableWriter.java
+++ b/utils/satellite/s2storage/src/write/java/com/android/telephony/sats2range/write/SuffixTableWriter.java
@@ -22,11 +22,11 @@ import com.android.storage.block.read.BlockData;
 import com.android.storage.block.write.BlockWriter;
 import com.android.storage.block.write.EmptyBlockWriter;
 import com.android.storage.io.write.TypedOutputStream;
-import com.android.storage.s2.S2LevelRange;
 import com.android.storage.s2.S2Support;
 import com.android.storage.table.packed.write.PackedTableWriter;
 import com.android.telephony.sats2range.read.SatS2RangeFileFormat;
 import com.android.telephony.sats2range.read.SuffixTableExtraInfo;
+import com.android.telephony.sats2range.read.SuffixTableRange;
 import com.android.telephony.sats2range.read.SuffixTableSharedData;
 
 import java.io.ByteArrayOutputStream;
@@ -42,7 +42,7 @@ import java.nio.file.StandardOpenOption;
  * To write empty tables use {@link #createEmptyBlockWriter()}.
  * To write populated tables use {@link
  * #createPopulated(SatS2RangeFileFormat, SuffixTableSharedData)} and add entries with
- * {@link #addRange(S2LevelRange)}
+ * {@link #addRange(SuffixTableRange)}
  */
 public final class SuffixTableWriter implements BlockWriter {
 
@@ -54,7 +54,7 @@ public final class SuffixTableWriter implements BlockWriter {
 
     private final File mFile;
 
-    private S2LevelRange mLastRangeAdded;
+    private SuffixTableRange mLastRangeAdded;
 
     private SuffixTableWriter(SatS2RangeFileFormat fileFormat, SuffixTableSharedData sharedData)
             throws IOException {
@@ -90,7 +90,7 @@ public final class SuffixTableWriter implements BlockWriter {
      * called at least once. See {@link SuffixTableWriter#createEmptyBlockWriter()} for empty
      * tables.
      */
-    public void addRange(S2LevelRange suffixTableRange) throws IOException {
+    public void addRange(SuffixTableRange suffixTableRange) throws IOException {
         checkIsOpen();
 
         long rangeStartCellId = suffixTableRange.getStartCellId();
diff --git a/utils/satellite/tools/Android.bp b/utils/satellite/tools/Android.bp
index d48b91190..b7b5decc9 100644
--- a/utils/satellite/tools/Android.bp
+++ b/utils/satellite/tools/Android.bp
@@ -70,11 +70,12 @@ java_binary_host {
 java_test_host {
     name: "SatelliteToolsTests",
     srcs: ["src/test/java/**/*.java"],
+    java_resource_dirs: ["src/test/java/"],
     static_libs: [
         "junit",
         "satellite-s2storage-tools",
         "s2-geometry-library-java",
-        "satellite-s2storage-testutils"
+        "satellite-s2storage-testutils",
     ],
     test_suites: ["general-tests"],
-}
\ No newline at end of file
+}
diff --git a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/CreateSatS2File.java b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/CreateSatS2File.java
index f82cd5ca5..2db1d4ed7 100644
--- a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/CreateSatS2File.java
+++ b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/CreateSatS2File.java
@@ -37,7 +37,11 @@ public final class CreateSatS2File {
         int s2Level = arguments.s2Level;
         String outputFile = arguments.outputFile;
         boolean isAllowedList = Arguments.getBooleanValue(arguments.isAllowedList);
-        SatS2FileCreator.create(inputFile, s2Level, isAllowedList, outputFile);
+        int entryValueSizeInBytes = Arguments.validateEntryValueSize(isAllowedList,
+                arguments.entryValueSizeInBytes);
+        int versionNumber = arguments.versionNumber;
+        SatS2FileCreator.create(inputFile, s2Level, isAllowedList, entryValueSizeInBytes,
+                versionNumber, outputFile);
     }
 
     private static class Arguments {
@@ -56,6 +60,14 @@ public final class CreateSatS2File {
                 required = true)
         public String isAllowedList;
 
+        @Parameter(names = "--entry-value-byte-size",
+                description = "byte size length for entry values")
+        public int entryValueSizeInBytes;
+
+        @Parameter(names = "--version-number",
+                description = "version number for header block")
+        public int versionNumber;
+
         @Parameter(names = "--output-file",
                 description = "sat s2 file",
                 required = true)
@@ -68,5 +80,16 @@ public final class CreateSatS2File {
                 throw new ParameterException("Invalid boolean string:" + value);
             }
         }
+
+        public static int validateEntryValueSize(boolean isAllowedList, int entryValueSizeInBytes) {
+            if (entryValueSizeInBytes < 0
+                    || (!isAllowedList && entryValueSizeInBytes > 0)
+                    || entryValueSizeInBytes > 4) {
+                throw new IllegalArgumentException(
+                        "Invalid entryValueSizeInBytes: " + entryValueSizeInBytes
+                                + ", isAllowedList: " + isAllowedList);
+            }
+            return entryValueSizeInBytes;
+        }
     }
 }
diff --git a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/CreateTestSatS2File.java b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/CreateTestSatS2File.java
index f9a9347bf..0bda4ecae 100644
--- a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/CreateTestSatS2File.java
+++ b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/CreateTestSatS2File.java
@@ -16,8 +16,8 @@
 
 package com.android.telephony.tools.sats2;
 
-import com.android.storage.s2.S2LevelRange;
 import com.android.telephony.sats2range.read.SatS2RangeFileFormat;
+import com.android.telephony.sats2range.read.SuffixTableRange;
 import com.android.telephony.sats2range.write.SatS2RangeFileWriter;
 
 import java.io.File;
@@ -26,6 +26,10 @@ import java.util.List;
 
 /** Creates a Sat S2 file with a small amount of test data. Useful for testing other tools. */
 public final class CreateTestSatS2File {
+    private static final int S2_LEVEL = 12;
+    private static final boolean IS_ALLOWED_LIST = true;
+    private static final int ENTRY_VALUE_BYTE_SIZE = 4;
+    private static final int VERSION_NUMBER = 1;
 
     /**
      * Usage:
@@ -34,7 +38,8 @@ public final class CreateTestSatS2File {
     public static void main(String[] args) throws Exception {
         File file = new File(args[0]);
 
-        SatS2RangeFileFormat fileFormat = FileFormats.getFileFormatForLevel(12, true);
+        SatS2RangeFileFormat fileFormat = FileFormats.getFileFormatForLevel(S2_LEVEL,
+                IS_ALLOWED_LIST, ENTRY_VALUE_BYTE_SIZE, VERSION_NUMBER);
         if (fileFormat.getPrefixBitCount() != 11) {
             throw new IllegalStateException("Fake data requires 11 prefix bits");
         }
@@ -42,18 +47,21 @@ public final class CreateTestSatS2File {
         try (SatS2RangeFileWriter satS2RangeFileWriter =
                      SatS2RangeFileWriter.open(file, fileFormat)) {
             // Two ranges that share a prefix.
-            S2LevelRange range1 = new S2LevelRange(
+            SuffixTableRange range1 = new SuffixTableRange(
                     fileFormat.createCellId(0b100_11111111, 1000),
-                    fileFormat.createCellId(0b100_11111111, 2000));
-            S2LevelRange range2 = new S2LevelRange(
                     fileFormat.createCellId(0b100_11111111, 2000),
-                    fileFormat.createCellId(0b100_11111111, 3000));
+                    1);
+            SuffixTableRange range2 = new SuffixTableRange(
+                    fileFormat.createCellId(0b100_11111111, 2000),
+                    fileFormat.createCellId(0b100_11111111, 3000),
+                    2);
             // This range has a different face, so a different prefix, and will be in a different
             // suffix table.
-            S2LevelRange range3 = new S2LevelRange(
+            SuffixTableRange range3 = new SuffixTableRange(
                     fileFormat.createCellId(0b101_11111111, 1000),
-                    fileFormat.createCellId(0b101_11111111, 2000));
-            List<S2LevelRange> allRanges = listOf(range1, range2, range3);
+                    fileFormat.createCellId(0b101_11111111, 2000),
+                    3);
+            List<SuffixTableRange> allRanges = listOf(range1, range2, range3);
             satS2RangeFileWriter.createSortedSuffixBlocks(allRanges.iterator());
         }
     }
diff --git a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/FileFormats.java b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/FileFormats.java
index b800897d1..32e6f4837 100644
--- a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/FileFormats.java
+++ b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/FileFormats.java
@@ -56,4 +56,19 @@ public final class FileFormats {
                         + ", isAllowedList=" + isAllowedList + " not mapped");
         }
     }
+
+    /** Maps an S2 level to one of the file format constants declared on by class. */
+    public static SatS2RangeFileFormat getFileFormatForLevel(int s2Level, boolean isAllowedList,
+            int entryValueSizeInBytes, int versionNumber) {
+        SatS2RangeFileFormat fileFormat = getFileFormatForLevel(s2Level, isAllowedList);
+        return new SatS2RangeFileFormat(
+                fileFormat.getS2Level(),
+                fileFormat.getPrefixBitCount(),
+                fileFormat.getSuffixBitCount(),
+                fileFormat.getSuffixTableBlockIdOffset(),
+                fileFormat.getTableEntryBitCount(),
+                fileFormat.isAllowedList(),
+                entryValueSizeInBytes,
+                versionNumber);
+    }
 }
diff --git a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2FileCreator.java b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2FileCreator.java
index dd7d8c014..74c4011f8 100644
--- a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2FileCreator.java
+++ b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2FileCreator.java
@@ -16,9 +16,9 @@
 
 package com.android.telephony.tools.sats2;
 
-import com.android.storage.s2.S2LevelRange;
 import com.android.telephony.sats2range.read.SatS2RangeFileFormat;
 import com.android.telephony.sats2range.read.SatS2RangeFileReader;
+import com.android.telephony.sats2range.read.SuffixTableRange;
 import com.android.telephony.sats2range.write.SatS2RangeFileWriter;
 
 import com.google.common.base.Stopwatch;
@@ -29,21 +29,22 @@ import java.io.FileInputStream;
 import java.io.InputStream;
 import java.nio.charset.StandardCharsets;
 import java.util.ArrayList;
-import java.util.Collections;
-import java.util.HashSet;
+import java.util.Comparator;
+import java.util.HashMap;
 import java.util.Iterator;
 import java.util.List;
+import java.util.Map;
 import java.util.Objects;
 import java.util.Scanner;
-import java.util.Set;
 import java.util.concurrent.TimeUnit;
 
 /** A util class for creating a satellite S2 file from the list of S2 cells. */
 public final class SatS2FileCreator {
     /**
      * @param inputFile The input text file containing the list of S2 Cell IDs. Each line in the
-     *                  file contains a number in the range of a 64-bit number which represents the
-     *                  ID of a S2 cell.
+     *                  file contains two numbers separated by a comma. The first number is in the
+     *                  range of a 64bit number which represents the ID of a S2 cell. The second
+     *                  number is satellite access config ID for the S2 cell.
      * @param s2Level The S2 level of all S2 cells in the input file.
      * @param isAllowedList {@code true} means the input file contains an allowed list of S2 cells.
      *                      {@code false} means the input file contains a disallowed list of S2
@@ -52,36 +53,38 @@ public final class SatS2FileCreator {
      *                   written.
      */
     public static void create(String inputFile, int s2Level, boolean isAllowedList,
-            String outputFile) throws Exception {
+            int entryValueSizeInBytes, int versionNumber, String outputFile) throws Exception {
         // Read a list of S2 cells from input file
-        List<Long> s2Cells = readS2CellsFromFile(inputFile);
+        List<Pair<Long, Integer>> s2Cells = readS2CellsFromFile(inputFile);
         System.out.println("Number of S2 cells read from file:" + s2Cells.size());
 
         // Convert the input list of S2 Cells into the list of sorted S2CellId
         System.out.println("Denormalizing S2 Cell IDs to the expected s2 level=" + s2Level);
-        List<S2CellId> sortedS2CellIds = denormalize(s2Cells, s2Level);
+        List<Pair<S2CellId, Integer>> sortedS2CellIds = normalize(s2Cells, s2Level);
+
         // IDs of S2CellId are converted to unsigned long numbers, which will be then used to
         // compare S2CellId.
-        Collections.sort(sortedS2CellIds);
+        sortedS2CellIds.sort(Comparator.comparing(o -> o.first));
         System.out.println("Number of S2 cell IDs:" + sortedS2CellIds.size());
 
         // Compress the list of S2CellId into S2 ranges
         List<SatS2Range> satS2Ranges = createSatS2Ranges(sortedS2CellIds, s2Level);
 
         // Write the S2 ranges into a block file
-        SatS2RangeFileFormat fileFormat =
-                FileFormats.getFileFormatForLevel(s2Level, isAllowedList);
+        SatS2RangeFileFormat fileFormat = FileFormats.getFileFormatForLevel(s2Level, isAllowedList,
+                entryValueSizeInBytes, versionNumber);
         try (SatS2RangeFileWriter satS2RangeFileWriter =
                      SatS2RangeFileWriter.open(new File(outputFile), fileFormat)) {
-            Iterator<S2LevelRange> s2LevelRangeIterator = satS2Ranges
+            Iterator<SuffixTableRange> suffixTableRangeIterator = satS2Ranges
                     .stream()
-                    .map(x -> new S2LevelRange(x.rangeStart.id(), x.rangeEnd.id()))
+                    .map(x -> new SuffixTableRange(x.rangeStart.id(), x.rangeEnd.id(),
+                            x.entryValue))
                     .iterator();
             /*
              * Group the sorted ranges into contiguous suffix blocks. Big ranges might get split as
              * needed to fit them into suffix blocks.
              */
-            satS2RangeFileWriter.createSortedSuffixBlocks(s2LevelRangeIterator);
+            satS2RangeFileWriter.createSortedSuffixBlocks(suffixTableRangeIterator);
         }
 
         // Validate the output block file
@@ -94,18 +97,26 @@ public final class SatS2FileCreator {
                         + "argument=" + isAllowedList);
             }
 
-            // Verify that all input S2 cells are present in the output block file
-            for (S2CellId s2CellId : sortedS2CellIds) {
-                if (satS2RangeFileReader.findEntryByCellId(s2CellId.id()) == null) {
-                    throw new IllegalStateException("s2CellId=" + s2CellId
+            // Verify that all input S2 cells are present in the output block file and the their
+            // entry value matches the provided entry value
+            for (Pair<S2CellId, Integer> s2CellInfo : sortedS2CellIds) {
+                SuffixTableRange entry =
+                        satS2RangeFileReader.findEntryByCellId(s2CellInfo.first.id());
+                if (entry == null) {
+                    throw new IllegalStateException("s2CellInfo=" + s2CellInfo
                             + " is not present in the output sat s2 file");
+                } else if (entry.getEntryValue() != s2CellInfo.second) {
+                    throw new IllegalStateException("entry.getEntryValue=" + entry.getEntryValue()
+                            + " does not match the provided entry value=" + s2CellInfo.second);
                 }
             }
 
             // Verify the cell right before the first cell in the sortedS2CellIds is not present in
             // the output block file
-            S2CellId prevCell = sortedS2CellIds.get(0).prev();
-            if (!sortedS2CellIds.contains(prevCell)
+            S2CellId prevCell = sortedS2CellIds.getFirst().first.prev();
+            boolean containsPrevCell = sortedS2CellIds.stream()
+                    .anyMatch(pair -> pair.first.equals(prevCell));
+            if (!containsPrevCell
                     && satS2RangeFileReader.findEntryByCellId(prevCell.id()) != null) {
                 throw new IllegalStateException("The cell " + prevCell + ", which is right "
                         + "before the first cell is unexpectedly present in the output sat s2"
@@ -116,8 +127,10 @@ public final class SatS2FileCreator {
 
             // Verify the cell right after the last cell in the sortedS2CellIds is not present in
             // the output block file
-            S2CellId nextCell = sortedS2CellIds.get(sortedS2CellIds.size() - 1).next();
-            if (!sortedS2CellIds.contains(nextCell)
+            S2CellId nextCell = sortedS2CellIds.getLast().first.next();
+            boolean containsNextCell = sortedS2CellIds.stream()
+                    .anyMatch(pair -> pair.first.equals(nextCell));
+            if (!containsNextCell
                     && satS2RangeFileReader.findEntryByCellId(nextCell.id()) != null) {
                 throw new IllegalStateException("The cell " + nextCell + ", which is right "
                         + "after the last cell is unexpectedly present in the output sat s2"
@@ -136,17 +149,24 @@ public final class SatS2FileCreator {
      *                  a 64-bit number - the ID of a S2 cell.
      * @return A list of S2 cells.
      */
-    private static List<Long> readS2CellsFromFile(String inputFile) throws Exception {
-        List<Long> s2Cells = new ArrayList();
+    private static List<Pair<Long, Integer>> readS2CellsFromFile(String inputFile)
+            throws Exception {
+        List<Pair<Long, Integer>> s2Cells = new ArrayList<>();
         InputStream inputStream = new FileInputStream(inputFile);
-        try (Scanner scanner = new Scanner(inputStream, StandardCharsets.UTF_8.name())) {
+        try (Scanner scanner = new Scanner(inputStream, StandardCharsets.UTF_8)) {
             while (scanner.hasNextLine()) {
                 String line = scanner.nextLine();
+                String[] s2CellInfoStrs = line.split(",");
+                if (s2CellInfoStrs == null || s2CellInfoStrs.length != 2) {
+                    throw new IllegalStateException("The Input s2 cell file has invalid format, "
+                            + "current line=" + line);
+                }
                 try {
-                    s2Cells.add(Long.parseLong(line));
+                    s2Cells.add(new Pair<>(Long.parseLong(s2CellInfoStrs[0]),
+                            Integer.parseUnsignedInt(s2CellInfoStrs[1])));
                 } catch (Exception ex) {
                     throw new IllegalStateException("Input s2 cell file has invalid format, "
-                            + "current line=" + line);
+                            + "current line=" + line + ", ex=" + ex);
                 }
             }
         }
@@ -156,30 +176,36 @@ public final class SatS2FileCreator {
     /**
      * Convert the list of S2 Cell numbers into the list of S2 Cell IDs at the expected level.
      */
-    private static List<S2CellId> denormalize(List<Long> s2CellNumbers, int s2Level) {
-        Set<S2CellId> result = new HashSet<>();
-        for (long s2CellNumber : s2CellNumbers) {
-            S2CellId s2CellId = new S2CellId(s2CellNumber);
+    private static List<Pair<S2CellId, Integer>> normalize(
+            List<Pair<Long, Integer>> s2CellNumbers, int s2Level) {
+        Map<S2CellId, Integer> s2CellIdMap = new HashMap<>();
+        for (Pair<Long, Integer> s2CellInfo : s2CellNumbers) {
+            S2CellId s2CellId = new S2CellId(s2CellInfo.first);
             if (s2CellId.level() == s2Level) {
-                if (!result.contains(s2CellId)) {
-                    result.add(s2CellId);
+                if (!s2CellIdMap.containsKey(s2CellId)) {
+                    s2CellIdMap.put(s2CellId, s2CellInfo.second);
                 }
             } else if (s2CellId.level() < s2Level) {
                 S2CellId childEnd = s2CellId.childEnd(s2Level);
                 for (s2CellId = s2CellId.childBegin(s2Level); !s2CellId.equals(childEnd);
                         s2CellId = s2CellId.next()) {
-                    if (!result.contains(s2CellId)) {
-                        result.add(s2CellId);
+                    if (!s2CellIdMap.containsKey(s2CellId)) {
+                        s2CellIdMap.put(s2CellId, s2CellInfo.second);
                     }
                 }
             } else {
                 S2CellId parent = s2CellId.parent(s2Level);
-                if (!result.contains(parent)) {
-                    result.add(parent);
+                if (!s2CellIdMap.containsKey(parent)) {
+                    s2CellIdMap.put(parent, s2CellInfo.second);
                 }
             }
         }
-        return new ArrayList(result);
+
+        List<Pair<S2CellId, Integer>> result = new ArrayList();
+        for (Map.Entry<S2CellId, Integer> entry : s2CellIdMap.entrySet()) {
+            result.add(new Pair<>(entry.getKey(), entry.getValue()));
+        }
+        return result;
     }
 
     /**
@@ -189,32 +215,38 @@ public final class SatS2FileCreator {
      * @param s2Level The level of all S2CellId.
      * @return List of S2 ranges.
      */
-    private static List<SatS2Range> createSatS2Ranges(List<S2CellId> sortedS2CellIds, int s2Level) {
+    private static List<SatS2Range> createSatS2Ranges(List<Pair<S2CellId, Integer>> sortedS2CellIds,
+            int s2Level) {
         Stopwatch stopwatch = Stopwatch.createStarted();
         List<SatS2Range> ranges = new ArrayList<>();
-        if (sortedS2CellIds != null && sortedS2CellIds.size() > 0) {
+        if (sortedS2CellIds != null && !sortedS2CellIds.isEmpty()) {
             S2CellId rangeStart = null;
             S2CellId rangeEnd = null;
+            int rangeEntryValue = 0;
             for (int i = 0; i < sortedS2CellIds.size(); i++) {
-                S2CellId currentS2CellId = sortedS2CellIds.get(i);
+                S2CellId currentS2CellId = sortedS2CellIds.get(i).first;
                 checkCellIdIsAtLevel(currentS2CellId, s2Level);
 
-                SatS2Range currentRange = createS2Range(currentS2CellId, s2Level);
+                SatS2Range currentRange = createS2Range(currentS2CellId, s2Level,
+                        sortedS2CellIds.get(i).second);
                 S2CellId currentS2CellRangeStart = currentRange.rangeStart;
                 S2CellId currentS2CellRangeEnd = currentRange.rangeEnd;
 
                 if (rangeStart == null) {
                     // First time round the loop initialize rangeStart / rangeEnd only.
                     rangeStart = currentS2CellRangeStart;
-                } else if (rangeEnd.id() != currentS2CellRangeStart.id()) {
-                    // If there's a gap between cellIds, store the range we have so far and start a
-                    // new range.
-                    ranges.add(new SatS2Range(rangeStart, rangeEnd));
+                    rangeEntryValue = currentRange.entryValue;
+                } else if (rangeEnd.id() != currentS2CellRangeStart.id()
+                        || currentRange.entryValue != rangeEntryValue) {
+                    // If there's a gap between cellIds or entry values are different, store the
+                    // range we have so far and start a new range.
+                    ranges.add(new SatS2Range(rangeStart, rangeEnd, rangeEntryValue));
                     rangeStart = currentS2CellRangeStart;
+                    rangeEntryValue = currentRange.entryValue;
                 }
                 rangeEnd = currentS2CellRangeEnd;
             }
-            ranges.add(new SatS2Range(rangeStart, rangeEnd));
+            ranges.add(new SatS2Range(rangeStart, rangeEnd, rangeEntryValue));
         }
 
         // Sorting the ranges is not necessary. As the input is sorted , it will already be sorted.
@@ -226,8 +258,7 @@ public final class SatS2FileCreator {
     /**
      * @return A pair of S2CellId for the range [s2CellId, s2CellId's next sibling)
      */
-    private static SatS2Range createS2Range(
-            S2CellId s2CellId, int s2Level) {
+    private static SatS2Range createS2Range(S2CellId s2CellId, int s2Level, int entryValue) {
         // Since s2CellId is at s2Level, s2CellId.childBegin(s2Level) returns itself.
         S2CellId firstS2CellRangeStart = s2CellId.childBegin(s2Level);
         // Get the immediate next sibling of s2CellId
@@ -240,7 +271,7 @@ public final class SatS2FileCreator {
                     + ", childEnd(" + s2Level + ") produced an unsupported"
                     + " value=" + firstS2CellRangeEnd);
         }
-        return new SatS2Range(firstS2CellRangeStart, firstS2CellRangeEnd);
+        return new SatS2Range(firstS2CellRangeStart, firstS2CellRangeEnd, entryValue);
     }
 
     private static void checkCellIdIsAtLevel(S2CellId cellId, int s2Level) {
@@ -255,6 +286,7 @@ public final class SatS2FileCreator {
      * (inclusive) and an end cell ID (exclusive).
      */
     private static class SatS2Range {
+        public final int entryValue;
         public final S2CellId rangeStart;
         public final S2CellId rangeEnd;
 
@@ -262,7 +294,8 @@ public final class SatS2FileCreator {
          * Creates an instance. If the range is invalid or the cell IDs are from different levels
          * this method throws an {@link IllegalArgumentException}.
          */
-        SatS2Range(S2CellId rangeStart, S2CellId rangeEnd) {
+        SatS2Range(S2CellId rangeStart, S2CellId rangeEnd, int entryValue) {
+            this.entryValue = entryValue;
             this.rangeStart = Objects.requireNonNull(rangeStart);
             this.rangeEnd = Objects.requireNonNull(rangeEnd);
             if (rangeStart.level() != rangeEnd.level()) {
@@ -275,4 +308,17 @@ public final class SatS2FileCreator {
             }
         }
     }
+
+    /** A basic pair class. */
+    static class Pair<A, B> {
+
+        public final A first;
+
+        public final B second;
+
+        Pair(A first, B second) {
+            this.first = first;
+            this.second = second;
+        }
+    }
 }
diff --git a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2LocationLookup.java b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2LocationLookup.java
index 713cca82b..9a03d7c69 100644
--- a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2LocationLookup.java
+++ b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/SatS2LocationLookup.java
@@ -17,6 +17,7 @@
 package com.android.telephony.tools.sats2;
 
 import com.android.telephony.sats2range.read.SatS2RangeFileReader;
+import com.android.telephony.sats2range.read.SuffixTableRange;
 
 import com.beust.jcommander.JCommander;
 import com.beust.jcommander.Parameter;
@@ -43,10 +44,12 @@ public final class SatS2LocationLookup {
                     satS2RangeFileReader.getS2Level());
             System.out.println("s2CellId=" + Long.toUnsignedString(s2CellId.id())
                     + ", token=" + s2CellId.toToken());
-            if (satS2RangeFileReader.findEntryByCellId(s2CellId.id()) == null) {
+            SuffixTableRange entry = satS2RangeFileReader.findEntryByCellId(s2CellId.id());
+            if (entry == null) {
                 System.out.println("The input file does not contain the input location");
             } else {
-                System.out.println("The input file contains the input location");
+                System.out.println("The input file contains the input location, entryValue="
+                        + entry.getEntryValue());
             }
         }
     }
diff --git a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/dump/SuffixTableBlockDumper.java b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/dump/SuffixTableBlockDumper.java
index a5d75b450..7e0246a20 100644
--- a/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/dump/SuffixTableBlockDumper.java
+++ b/utils/satellite/tools/src/main/java/com/android/telephony/tools/sats2/dump/SuffixTableBlockDumper.java
@@ -55,11 +55,12 @@ public final class SuffixTableBlockDumper implements SuffixTableBlock.SuffixTabl
             writer.println("Entry count=" + entryCount);
             if (entryCount > 0) {
                 for (int i = 0; i < entryCount; i++) {
-                    writer.println(
-                            "[" + i + "]=" + suffixTableBlock.getEntryByIndex(i)
-                                    .getSuffixTableRange());
+                    writer.println("Entry[" + i + "]=" + suffixTableBlock.getEntryByIndex(
+                            i).getSuffixTableRange());
                 }
             }
+            int entryValueCount = suffixTableBlock.getEntryValueCount();
+            writer.println("Entry value count=" + entryValueCount);
         }
     }
 }
diff --git a/utils/satellite/tools/src/test/java/com/android/telephony/tools/sats2/CreateSatS2FileTest.java b/utils/satellite/tools/src/test/java/com/android/telephony/tools/sats2/CreateSatS2FileTest.java
index 80c1807ea..13ec22e1b 100644
--- a/utils/satellite/tools/src/test/java/com/android/telephony/tools/sats2/CreateSatS2FileTest.java
+++ b/utils/satellite/tools/src/test/java/com/android/telephony/tools/sats2/CreateSatS2FileTest.java
@@ -16,11 +16,14 @@
 
 package com.android.telephony.tools.sats2;
 
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.fail;
 
 import com.android.telephony.sats2range.read.SatS2RangeFileFormat;
 import com.android.telephony.sats2range.read.SatS2RangeFileReader;
+import com.android.telephony.sats2range.read.SuffixTableRange;
 import com.android.telephony.sats2range.utils.TestUtils;
 
 import org.junit.After;
@@ -34,6 +37,10 @@ import java.nio.file.Path;
 
 /** Tests for {@link CreateSatS2File} */
 public final class CreateSatS2FileTest {
+    private static final int S2_LEVEL = 12;
+    private static final boolean IS_ALLOWED_LIST = true;
+    private static final int ENTRY_VALUE_BYTE_SIZE = 4;
+    private static final int VERSION_NUMBER = 0;
     private Path mTempDirPath;
 
     @Before
@@ -48,20 +55,8 @@ public final class CreateSatS2FileTest {
         }
     }
 
-    @Test
-    public void testCreateSatS2FileWithValidInput_AllowedList() throws Exception {
-        testCreateSatS2FileWithValidInput(true);
-    }
-
-    @Test
-    public void testCreateSatS2FileWithValidInput_DisallowedList() throws Exception {
-        testCreateSatS2FileWithValidInput(false);
-    }
-
     @Test
     public void testCreateSatS2FileWithInvalidInput() throws Exception {
-        int s2Level = 12;
-        boolean isAllowedList = true;
         Path inputDirPath = mTempDirPath.resolve("input");
         Files.createDirectory(inputDirPath);
         Path inputFilePath = inputDirPath.resolve("s2cells.txt");
@@ -71,14 +66,17 @@ public final class CreateSatS2FileTest {
         Path outputFilePath = outputDirPath.resolve("sats2.dat");
 
         // Create test input S2 cell file
-        SatS2RangeFileFormat fileFormat = FileFormats.getFileFormatForLevel(s2Level, isAllowedList);
+        SatS2RangeFileFormat fileFormat = FileFormats.getFileFormatForLevel(S2_LEVEL,
+                IS_ALLOWED_LIST, ENTRY_VALUE_BYTE_SIZE, VERSION_NUMBER);
         TestUtils.createInvalidTestS2CellFile(inputFilePath.toFile(), fileFormat);
 
         // Commandline input arguments
         String[] args = {
                 "--input-file", inputFilePath.toAbsolutePath().toString(),
-                "--s2-level", String.valueOf(s2Level),
-                "--is-allowed-list", isAllowedList ? "true" : "false",
+                "--s2-level", String.valueOf(S2_LEVEL),
+                "--is-allowed-list", String.valueOf(IS_ALLOWED_LIST),
+                "--entry-value-byte-size", String.valueOf(ENTRY_VALUE_BYTE_SIZE),
+                "--version-number", String.valueOf(VERSION_NUMBER),
                 "--output-file", outputFilePath.toAbsolutePath().toString()
         };
 
@@ -92,8 +90,8 @@ public final class CreateSatS2FileTest {
         fail("Exception should have been caught");
     }
 
-    private void testCreateSatS2FileWithValidInput(boolean isAllowedList) throws Exception {
-        int s2Level = 12;
+    @Test
+    public void testCreateSatS2FileWithValidInput() throws Exception {
         Path inputDirPath = mTempDirPath.resolve("input");
         Files.createDirectory(inputDirPath);
         Path inputFilePath = inputDirPath.resolve("s2cells.txt");
@@ -104,18 +102,24 @@ public final class CreateSatS2FileTest {
 
         /*
          * Create test input S2 cell file with the following ranges:
-         * 1) [(prefix=0b100_11111111, suffix=1000), (prefix=0b100_11111111, suffix=2000))
-         * 2) [(prefix=0b100_11111111, suffix=2001), (prefix=0b100_11111111, suffix=3000))
-         * 3) [(prefix=0b101_11111111, suffix=1000), (prefix=0b101_11111111, suffix=2001))
+         * 1) [(prefix=0b100_11111111, suffix=1000), (prefix=0b100_11111111, suffix=2000),
+         * entryValue=1)
+         * 2) [(prefix=0b100_11111111, suffix=2001), (prefix=0b100_11111111, suffix=3000),
+         * entryValue=2)
+         * 3) [(prefix=0b101_11111111, suffix=1000), (prefix=0b101_11111111, suffix=2001)),
+         * entryValue=3)
          */
-        SatS2RangeFileFormat fileFormat = FileFormats.getFileFormatForLevel(s2Level, isAllowedList);
+        SatS2RangeFileFormat fileFormat = FileFormats.getFileFormatForLevel(S2_LEVEL,
+                IS_ALLOWED_LIST, ENTRY_VALUE_BYTE_SIZE, VERSION_NUMBER);
         TestUtils.createValidTestS2CellFile(inputFilePath.toFile(), fileFormat);
 
         // Commandline input arguments
         String[] args = {
                 "--input-file", inputFilePath.toAbsolutePath().toString(),
-                "--s2-level", String.valueOf(s2Level),
-                "--is-allowed-list", isAllowedList ? "true" : "false",
+                "--s2-level", String.valueOf(S2_LEVEL),
+                "--is-allowed-list", String.valueOf(IS_ALLOWED_LIST),
+                "--entry-value-byte-size", String.valueOf(ENTRY_VALUE_BYTE_SIZE),
+                "--version-number", String.valueOf(VERSION_NUMBER),
                 "--output-file", outputFilePath.toAbsolutePath().toString()
         };
 
@@ -130,11 +134,6 @@ public final class CreateSatS2FileTest {
         try {
             SatS2RangeFileReader satS2RangeFileReader =
                          SatS2RangeFileReader.open(outputFilePath.toFile());
-            if (isAllowedList != satS2RangeFileReader.isAllowedList()) {
-                fail("isAllowedList="
-                        + satS2RangeFileReader.isAllowedList() + " does not match the input "
-                        + "argument=" + isAllowedList);
-            }
 
             // Verify an edge cell (prefix=0b100_11111111, suffix=100)
             long s2CellId = fileFormat.createCellId(0b100_11111111, 100);
@@ -144,6 +143,10 @@ public final class CreateSatS2FileTest {
             s2CellId = fileFormat.createCellId(0b100_11111111, 2000);
             assertNull(satS2RangeFileReader.findEntryByCellId(s2CellId));
 
+            // Verify a middle cell (prefix=0b100_11111111, suffix=2000)
+            s2CellId = fileFormat.createCellId(0b100_11111111, 2000);
+            assertNull(satS2RangeFileReader.findEntryByCellId(s2CellId));
+
             // Verify an edge cell (prefix=0b100_11111111, suffix=4000)
             s2CellId = fileFormat.createCellId(0b100_11111111, 4000);
             assertNull(satS2RangeFileReader.findEntryByCellId(s2CellId));
@@ -163,4 +166,320 @@ public final class CreateSatS2FileTest {
             fail("Unexpected exception when validating the output ex=" + ex);
         }
     }
+
+    @Test
+    public void testCreateSatS2FileWithValidCellIdAndValidEntryValue() throws Exception {
+        Path inputDirPath = mTempDirPath.resolve("input");
+        Files.createDirectory(inputDirPath);
+        Path inputFilePath = inputDirPath.resolve("s2cells.txt");
+
+        Path outputDirPath = mTempDirPath.resolve("output");
+        Files.createDirectory(outputDirPath);
+        Path outputFilePath = outputDirPath.resolve("sats2.dat");
+
+        /*
+         * Create test input S2 cell file with the following ranges:
+         * 1) [(prefix=0b100_11111111, suffix=1000), (prefix=0b100_11111111, suffix=1500),
+         * entryValue=1)
+         * 2) [(prefix=0b100_11111111, suffix=1500), (prefix=0b100_11111111, suffix=2000),
+         * entryValue=2)
+         * 3) [(prefix=0b100_11111111, suffix=2001), (prefix=0b100_11111111, suffix=3000),
+         * entryValue=3)
+         * 4) [(prefix=0b101_11111111, suffix=1000), (prefix=0b101_11111111, suffix=2001)),
+         * entryValue=4)
+         */
+        SatS2RangeFileFormat fileFormat = FileFormats.getFileFormatForLevel(S2_LEVEL,
+                IS_ALLOWED_LIST, ENTRY_VALUE_BYTE_SIZE, VERSION_NUMBER);
+        TestUtils.createValidTestS2CellFileWithValidEntryValue(inputFilePath.toFile(), fileFormat);
+
+        // Commandline input arguments
+        String[] args = {
+                "--input-file", inputFilePath.toAbsolutePath().toString(),
+                "--s2-level", String.valueOf(S2_LEVEL),
+                "--is-allowed-list", String.valueOf(IS_ALLOWED_LIST),
+                "--entry-value-byte-size", String.valueOf(ENTRY_VALUE_BYTE_SIZE),
+                "--version-number", String.valueOf(VERSION_NUMBER),
+                "--output-file", outputFilePath.toAbsolutePath().toString()
+        };
+
+        // Execute the tool CreateSatS2File and expect successful result
+        try {
+            CreateSatS2File.main(args);
+        } catch (Exception ex) {
+            fail("Unexpected exception when executing the tool ex=" + ex);
+        }
+
+
+        // Validate the output block file
+        try {
+            SatS2RangeFileReader satS2RangeFileReader =
+                    SatS2RangeFileReader.open(outputFilePath.toFile());
+
+            // Verify a cell outside the valid range (prefix=0b100_11111111, suffix=0)
+            long s2CellId = fileFormat.createCellId(0b100_11111111, 0);
+            SuffixTableRange suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNull(suffixTableRange);
+
+            // Verify a cell outside the valid range (prefix=0b100_11111111, suffix=0)
+            s2CellId = fileFormat.createCellId(0b100_11111111, 999);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNull(suffixTableRange);
+
+            // Verify the first cell (prefix=0b100_11111111, suffix=1000)
+            int expectedEntryValue = 1;
+            s2CellId = fileFormat.createCellId(0b100_11111111, 1000);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNotNull(suffixTableRange);
+            Integer entryValue = suffixTableRange.getEntryValue();
+            assertNotNull(entryValue);
+            assertEquals(expectedEntryValue, (int) entryValue);
+
+            // Verify the mid cell of 1st range (prefix=0b100_11111111, suffix=1499)
+            s2CellId = fileFormat.createCellId(0b100_11111111, 1250);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNotNull(suffixTableRange);
+            entryValue = suffixTableRange.getEntryValue();
+            assertNotNull(entryValue);
+            assertEquals(expectedEntryValue, (int) entryValue);
+
+            // Verify the end of 1st range (prefix=0b100_11111111, suffix=1499)
+            s2CellId = fileFormat.createCellId(0b100_11111111, 1499);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNotNull(suffixTableRange);
+            entryValue = suffixTableRange.getEntryValue();
+            assertNotNull(entryValue);
+            assertEquals(expectedEntryValue, (int) entryValue);
+
+            // Verify the first cell of 2nd range (prefix=0b100_11111111, suffix=1500)
+            expectedEntryValue = 2;
+            s2CellId = fileFormat.createCellId(0b100_11111111, 1500);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNotNull(suffixTableRange);
+            entryValue = suffixTableRange.getEntryValue();
+            assertNotNull(entryValue);
+            assertEquals(expectedEntryValue, (int) entryValue);
+
+            // Verify the mid cell of 2nd range (prefix=0b100_11111111, suffix=1750)
+            s2CellId = fileFormat.createCellId(0b100_11111111, 1750);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNotNull(suffixTableRange);
+            entryValue = suffixTableRange.getEntryValue();
+            assertNotNull(entryValue);
+            assertEquals(expectedEntryValue, (int) entryValue);
+
+            // Verify the end cell of 2nd range (prefix=0b100_11111111, suffix=1999)
+            s2CellId = fileFormat.createCellId(0b100_11111111, 1999);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNotNull(suffixTableRange);
+            entryValue = suffixTableRange.getEntryValue();
+            assertNotNull(entryValue);
+            assertEquals(expectedEntryValue, (int) entryValue);
+
+            // Verify a cell outside the valid range (prefix=0b100_11111111, suffix=2000)
+            s2CellId = fileFormat.createCellId(0b100_11111111, 2000);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNull(suffixTableRange);
+
+            expectedEntryValue = 3;
+            // Verify the first cell of 3rd range (prefix=0b100_11111111, suffix=2001)
+            s2CellId = fileFormat.createCellId(0b100_11111111, 2001);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNotNull(suffixTableRange);
+            entryValue = suffixTableRange.getEntryValue();
+            assertNotNull(entryValue);
+            assertEquals(expectedEntryValue, (int) entryValue);
+
+            // Verify the mid cell of 3rd range (prefix=0b100_11111111, suffix=2001)
+            s2CellId = fileFormat.createCellId(0b100_11111111, 2500);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNotNull(suffixTableRange);
+            entryValue = suffixTableRange.getEntryValue();
+            assertNotNull(entryValue);
+            assertEquals(expectedEntryValue, (int) entryValue);
+
+            // Verify the end cell of 3rd range (prefix=0b100_11111111, suffix=2999)
+            s2CellId = fileFormat.createCellId(0b100_11111111, 2999);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNotNull(suffixTableRange);
+            entryValue = suffixTableRange.getEntryValue();
+            assertNotNull(entryValue);
+            assertEquals(expectedEntryValue, (int) entryValue);
+
+            // Verify a cell outside the valid range(prefix=0b100_11111111, suffix=3000)
+            s2CellId = fileFormat.createCellId(0b100_11111111, 3000);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNull(suffixTableRange);
+
+            int maxSuffixValue = (1 << fileFormat.getSuffixBitCount()) - 1;
+            // Verify a cell outside the valid range (prefix=0b100_11111111, suffix=max value)
+            s2CellId = fileFormat.createCellId(0b100_11111111, maxSuffixValue);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNull(suffixTableRange);
+
+            // Verify a cell outside the valid range (prefix=0b101_11111111, suffix=0)
+            s2CellId = fileFormat.createCellId(0b101_11111111, 0);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNull(suffixTableRange);
+
+            // Verify a cell outside the valid range (prefix=0b101_11111111, suffix=999)
+            s2CellId = fileFormat.createCellId(0b101_11111111, 999);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNull(suffixTableRange);
+
+            // Verify the first cell of 4th range (prefix=0b101_11111111, suffix=1000)
+            expectedEntryValue = 4;
+            s2CellId = fileFormat.createCellId(0b101_11111111, 1000);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNotNull(suffixTableRange);
+            entryValue = suffixTableRange.getEntryValue();
+            assertNotNull(entryValue);
+            assertEquals(expectedEntryValue, (int) entryValue);
+
+            // Verify a mid cell of 4th range (prefix=0b101_11111111, suffix=1500)
+            s2CellId = fileFormat.createCellId(0b101_11111111, 1500);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNotNull(suffixTableRange);
+            entryValue = suffixTableRange.getEntryValue();
+            assertNotNull(entryValue);
+            assertEquals(expectedEntryValue, (int) entryValue);
+
+            // Verify a cell of 4th range (prefix=0b101_11111111, suffix=2000)
+            s2CellId = fileFormat.createCellId(0b101_11111111, 2000);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNotNull(suffixTableRange);
+            entryValue = suffixTableRange.getEntryValue();
+            assertNotNull(entryValue);
+            assertEquals(expectedEntryValue, (int) entryValue);
+
+            // Verify the end cell of 4th range (prefix=0b101_11111111, suffix=2001)
+            s2CellId = fileFormat.createCellId(0b101_11111111, 2001);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNull(suffixTableRange);
+
+            // Verify a cell outside the valid range (prefix=0b101_11111111, suffix=max value)
+            s2CellId = fileFormat.createCellId(0b101_11111111, maxSuffixValue);
+            suffixTableRange = satS2RangeFileReader.findEntryByCellId(s2CellId);
+            assertNull(suffixTableRange);
+        } catch (Exception ex) {
+            fail("Unexpected exception when validating the output ex=" + ex);
+        }
+    }
+
+    @Test
+    public void testCreateSatS2FileWithValidInputAndRandomEntryValue() throws Exception {
+        String inputFileName = "s2cells_random_entry_value.txt";
+        Path inputDirPath = mTempDirPath.resolve("input");
+        Path inputFilePath = inputDirPath.resolve(inputFileName);
+        TestUtils.copyTestResource(getClass(), inputFileName, inputDirPath);
+
+        Path outputDirPath = mTempDirPath.resolve("output");
+        Files.createDirectory(outputDirPath);
+        Path outputFilePath = outputDirPath.resolve("sats2.dat");
+
+        // Commandline input arguments
+        String[] args = {
+                "--input-file", inputFilePath.toAbsolutePath().toString(),
+                "--s2-level", String.valueOf(S2_LEVEL),
+                "--is-allowed-list", String.valueOf(IS_ALLOWED_LIST),
+                "--entry-value-byte-size", String.valueOf(ENTRY_VALUE_BYTE_SIZE),
+                "--version-number", String.valueOf(VERSION_NUMBER),
+                "--output-file", outputFilePath.toAbsolutePath().toString()
+        };
+
+        // Execute the tool CreateSatS2File and expect successful result
+        try {
+            CreateSatS2File.main(args);
+        } catch (Exception ex) {
+            fail("Unexpected exception when executing the tool ex=" + ex);
+        }
+    }
+
+    @Test
+    public void testCreateSatS2FileWithValidCellIdAndInValidInputParameter() throws Exception {
+        Path inputDirPath = mTempDirPath.resolve("input");
+        Files.createDirectory(inputDirPath);
+        Path inputFilePath = inputDirPath.resolve("s2cells.txt");
+
+        Path outputDirPath = mTempDirPath.resolve("output");
+        Files.createDirectory(outputDirPath);
+        Path outputFilePath = outputDirPath.resolve("sats2.dat");
+
+        /*
+         * Create test input S2 cell file with the following ranges:
+         * 1) [(prefix=0b100_11111111, suffix=1000), (prefix=0b100_11111111, suffix=1500),
+         * entryValue=1)
+         * 2) [(prefix=0b100_11111111, suffix=1500), (prefix=0b100_11111111, suffix=2000),
+         * entryValue=2)
+         * 3) [(prefix=0b100_11111111, suffix=2001), (prefix=0b100_11111111, suffix=3000),
+         * entryValue=3)
+         * 4) [(prefix=0b101_11111111, suffix=1000), (prefix=0b101_11111111, suffix=2001)),
+         * entryValue=4)
+         */
+        SatS2RangeFileFormat fileFormat = FileFormats.getFileFormatForLevel(S2_LEVEL,
+                IS_ALLOWED_LIST, ENTRY_VALUE_BYTE_SIZE, VERSION_NUMBER);
+        TestUtils.createValidTestS2CellFileWithValidEntryValue(inputFilePath.toFile(), fileFormat);
+
+        // Entry value size in byte < 0
+        String[] args = {
+                "--input-file", inputFilePath.toAbsolutePath().toString(),
+                "--s2-level", String.valueOf(S2_LEVEL),
+                "--is-allowed-list", String.valueOf(IS_ALLOWED_LIST),
+                "--entry-value-byte-size", String.valueOf(-1),
+                "--version-number", String.valueOf(VERSION_NUMBER),
+                "--output-file", outputFilePath.toAbsolutePath().toString()
+        };
+
+        // Execute the tool CreateSatS2File and expect exception
+        try {
+            CreateSatS2File.main(args);
+            fail("Exception should have been caught");
+        } catch (IllegalArgumentException ex) {
+            // Expected exception
+        } catch (Exception ex) {
+            // Unexpected exception
+            fail("Unexpected exception, ex=" + ex);
+        }
+
+        // isAllowList is false && entryValueSizeInBytes > 0
+        args = new String[]{
+                "--input-file", inputFilePath.toAbsolutePath().toString(),
+                "--s2-level", String.valueOf(S2_LEVEL),
+                "--is-allowed-list", String.valueOf(false),
+                "--entry-value-byte-size", String.valueOf(ENTRY_VALUE_BYTE_SIZE),
+                "--version-number", String.valueOf(VERSION_NUMBER),
+                "--output-file", outputFilePath.toAbsolutePath().toString()
+        };
+
+        // Execute the tool CreateSatS2File and expect exception
+        try {
+            CreateSatS2File.main(args);
+            fail("Exception should have been caught");
+        } catch (IllegalArgumentException ex) {
+            // Expected exception
+        } catch (Exception ex) {
+            // Unexpected exception
+            fail("Unexpected exception, ex=" + ex);
+        }
+
+        // entryValueSizeInBytes > 4
+        args = new String[]{
+                "--input-file", inputFilePath.toAbsolutePath().toString(),
+                "--s2-level", String.valueOf(S2_LEVEL),
+                "--is-allowed-list", String.valueOf(IS_ALLOWED_LIST),
+                "--entry-value-byte-size", String.valueOf(ENTRY_VALUE_BYTE_SIZE + 1),
+                "--version-number", String.valueOf(VERSION_NUMBER),
+                "--output-file", outputFilePath.toAbsolutePath().toString()
+        };
+
+        // Execute the tool CreateSatS2File and expect exception
+        try {
+            CreateSatS2File.main(args);
+            fail("Exception should have been caught");
+        } catch (IllegalArgumentException ex) {
+            // Expected exception
+        } catch (Exception ex) {
+            // Unexpected exception
+            fail("Unexpected exception, ex=" + ex);
+        }
+    }
 }
diff --git a/utils/satellite/tools/src/test/java/com/android/telephony/tools/sats2/data/s2cells_random_entry_value.txt b/utils/satellite/tools/src/test/java/com/android/telephony/tools/sats2/data/s2cells_random_entry_value.txt
new file mode 100644
index 000000000..24ca9505a
--- /dev/null
+++ b/utils/satellite/tools/src/test/java/com/android/telephony/tools/sats2/data/s2cells_random_entry_value.txt
@@ -0,0 +1,1545 @@
+5522342230481698816,3
+5522349927063093248,9
+5522732557109559296,2
+5522767741481648128,3
+5522789731714203648,4
+5522798527807225856,2
+5522890886783959040,6
+5522978847714181120,0
+5523000837946736640,9
+5523027226225803264,8
+5523081102295564288,2
+5523088798876958720,2
+5523097594969980928,3
+5523103092528119808,0
+5523827670690824192,3
+5523858457016401920,5
+5523893641388490752,3
+5523915631621046272,4
+5523924427714068480,2
+5523977204272201728,9
+5523999194504757248,1
+5524021184737312768,7
+5524029980830334976,5
+5524038776923357184,5
+5524789743365128192,2
+5524808435062800384,4
+5524843619434889216,4
+5524878803806978048,8
+5524909590132555776,6
+5525067919806955520,2
+5525089910039511040,3
+5525138288551133184,5
+5525160278783688704,7
+5525195463155777536,0
+5525283424085999616,0
+5525635267806887936,2
+5526198217760309248,1
+5526761167713730560,7
+5527324117667151872,5
+5527609990690373632,2
+5527618786783395840,3
+5527627582876418048,6
+5527634918680559616,0
+5527728737946173440,2
+5527763922318262272,6
+5527799106690351104,9
+5527834291062439936,0
+5527856281294995456,1
+5527865077388017664,5
+5527921152481034240,9
+5527926650039173120,3
+5527935446132195328,3
+5527944242225217536,9
+5527970630504284160,2
+5527978327085678592,4
+5528542376550727680,0
+5528551172643749888,3
+5528559968736772096,5
+5528586357015838720,2
+5528595153108860928,5
+5528603949201883136,8
+5528718298411171840,5
+5529012967527415808,5
+5529312034690170880,9
+5529334024922726400,1
+5529342821015748608,1
+5529348318573887488,7
+5529360413201793024,4
+5529382403434348544,3
+5529417587806437376,9
+5529505548736659456,3
+5529580315527348224,1
+5529606703806414848,8
+5529765033480814592,5
+5529809013945925632,8
+5529998061226426368,0
+5530002527992414208,8
+5530028916271480832,8
+5530037712364503040,1
+5530046508457525248,9
+5533098752736231424,1
+5533107548829253632,4
+5533221898038542336,1
+5533230694131564544,9
+5533516567154786304,8
+5533805738712891392,2
+5533811236271030272,0
+5533820032364052480,5
+5533859546063175680,6
+5533864012829163520,5
+5533886003061719040,3
+5533921187433807872,2
+5534009148364029952,0
+5534083915154718720,1
+5534096009782624256,9
+5534101507340763136,1
+5534110303433785344,2
+5534132293666340864,5
+5534157582433779712,7
+5534163079991918592,0
+5534170776573313024,2
+5534268633108185088,6
+5562600848732717056,8
+5562605315498704896,9
+5562672316988522496,3
+5562699066044841984,5
+5562706401848983552,1
+5562715197942005760,4
+5562737188174561280,1
+5562772372546650112,7
+5562860333476872192,9
+5562948294407094272,1
+5562970284639649792,9
+5562979080732672000,3
+5562996672918716416,6
+5563059619959406592,8
+5563352914686115840,9
+5563651981848870912,4
+5563673972081426432,1
+5563700360360493056,9
+5563709156453515264,8
+5563717952546537472,1
+5563737009316429824,3
+5563757534965137408,8
+5563779525197692928,6
+5563805913476759552,2
+5563814709569781760,1
+5563819382494199808,3
+5567879947655053312,1
+5567913688918130688,7
+5567922485011152896,5
+5567944475243708416,0
+5567979659615797248,9
+5568001649848352768,1
+5568010445941374976,2
+5568028038127419392,7
+5568124795150663680,2
+5568129261916651520,2
+5568758113848262656,0
+5568763611406401536,1
+5568788900173840384,9
+5568806767237791744,1
+5568854870871506944,8
+5568863666964529152,3
+5568894453290106880,8
+5568929637662195712,0
+5568964822034284544,1
+5569052782964506624,0
+5569193520452861952,0
+5569545364173750272,2
+5570108314127171584,9
+5570671264080592896,6
+5572078638964146176,6
+5573274907615166464,4
+5573499207987232768,4
+5573594865498849280,0
+5573613557196521472,6
+5573622353289543680,0
+5573697120080232448,7
+5573837857568587776,9
+5573978595056943104,3
+5574053361847631872,5
+5574081124516233216,4
+5574238079801098240,9
+5574246875894120448,0
+5574255671987142656,2
+5574277662219698176,2
+5806560488703655936,7
+5806567910407143424,6
+5806635255494344704,3
+5806670439866433536,5
+5806705624238522368,1
+5806727614471077888,4
+5806754002750144512,7
+5806775992982700032,8
+5806811177354788864,6
+5806846361726877696,3
+5806868351959433216,0
+5806885944145477632,2
+5806894740238499840,9
+5806916730471055360,3
+5806951914843144192,6
+5806982701168721920,7
+5807097050378010624,1
+5807105846471032832,6
+5815321397353775104,1
+5815330193446797312,4
+5815355482214236160,1
+5815572086004908032,4
+5815592701847928832,7
+5815611668423507968,6
+5815620464516530176,3
+5815642454749085696,3
+5815677639121174528,9
+5815765600051396608,0
+5815906337539751936,2
+5815981104330440704,3
+5815989900423462912,9
+5815997597004857344,2
+5816099851586240512,2
+5816135035958329344,9
+5816183414469951488,5
+5816192210562973696,9
+5816218598842040320,2
+5816240589074595840,2
+5816328550004817920,5
+5816469287493173248,2
+5816610024981528576,5
+5816750762469883904,3
+5816838723400105984,6
+5816873907772194816,3
+5816909092144283648,0
+5816931082376839168,0
+5816939878469861376,7
+5816948674562883584,0
+5817485236237238272,6
+5817494032330260480,4
+5817520420609327104,9
+5817529216702349312,8
+5817546808888393728,0
+5817555604981415936,8
+5817577595213971456,7
+5817960225260437504,6
+5817969021353459712,5
+5818013001818570752,3
+5818034992051126272,4
+5818070176423215104,2
+5818369243585970176,8
+5818721087306858496,6
+5818861824795213824,1
+5819002562283569152,4
+5819090523213791232,2
+5819125707585880064,5
+5819160891957968896,2
+5819182882190524416,7
+5819191678283546624,7
+5819200474376568832,4
+5819207804543565824,9
+5819235658748657664,4
+5819244454841679872,0
+5819266445074235392,1
+5819301629446324224,4
+5819331041382367232,0
+5819442366934679552,6
+5819477551306768384,7
+5819565512236990464,9
+5819706249725345792,8
+5820058093446234112,7
+5820621043399655424,4
+5822028418283208704,7
+5824280218096893952,5
+5825687592980447232,8
+5826250542933868544,9
+5826602386654756864,3
+5826743124143112192,9
+5826831085073334272,5
+5826866269445423104,8
+5826883862705209344,8
+5826932240143089664,3
+5826941036236111872,6
+5826976220608200704,5
+5826985016701222912,1
+5827007006933778432,3
+5827042191305867264,9
+5827064181538422784,1
+5827072977631444992,9
+5827090569817489408,1
+5827376442840711168,7
+5827662315863932928,4
+5827671111956955136,6
+5827785461166243840,3
+5827790134090661888,3
+5830617803119394816,2
+5830644191398461440,9
+5830652987491483648,8
+5830661783584505856,8
+5830670579677528064,7
+5843438108699262976,9
+5843490610379489280,1
+5843508477443440640,6
+5843543661815529472,1
+5843631622745751552,0
+5845414205972283392,6
+5845448015954837504,1
+5845456812047859712,9
+5845478802280415232,7
+5845513986652504064,0
+5845549171024592896,5
+5845659122187370496,7
+5845667918280392704,0
+5846798216233746432,5
+5849050016047431680,7
+5850457390930984960,9
+5851020340884406272,1
+5851583290837827584,1
+5851935134558715904,3
+5852075872047071232,7
+5852216609535426560,1
+5852304570465648640,6
+5852339754837737472,9
+5852374939209826304,8
+5852401052610985984,6
+5852405725535404032,9
+5852413422116798464,9
+5852467298186559488,1
+5852476094279581696,3
+5852484890372603904,6
+5852720941775192064,2
+5852813644349308928,2
+5852832336046981120,7
+5852867520419069952,5
+5852889510651625472,1
+5852907102837669888,0
+5852915898930692096,9
+5852937889163247616,1
+5852973073535336448,0
+5853272140698091520,8
+5853566809814335488,5
+5853650303978569728,9
+5853654770744557568,3
+5853676760977113088,1
+5853764721907335168,7
+5853838389186396160,1
+5853860379418951680,8
+5853865876977090560,6
+5853887867209646080,9
+5853909857442201600,8
+5853918653535223808,2
+5853927449628246016,0
+5856975291565473792,6
+5856979693906952192,3
+5857352428348768256,8
+5857371120046440448,8
+5857419498558062592,7
+5857441488790618112,8
+5857476673162706944,1
+5857564634092929024,6
+5857705371581284352,9
+5857846109069639680,5
+5857920875860328448,9
+5857938468046372864,0
+5857947264139395072,5
+5857969254371950592,4
+5858004438744039424,6
+5858033759143591936,9
+5858202350837039104,3
+5858223241557966848,3
+5858228739116105728,1
+5858250729348661248,8
+5858276018116100096,8
+5858281515674238976,0
+5858288937377726464,5
+5860648764208840704,1
+5860674052976279552,5
+5860682849069301760,4
+5954941781895282688,2
+5954968170174349312,0
+5954976966267371520,0
+5954985762360393728,9
+5955073723290615808,8
+5955082519383638016,0
+5955091315476660224,0
+5955113305709215744,0
+5955148490081304576,9
+5955236451011526656,0
+5955377188499881984,8
+5955517925988237312,3
+5955592692778926080,9
+5955601488871948288,6
+5955699706184073216,6
+5955710340523098112,5
+5955715838081236992,5
+5955724634174259200,1
+5955733430267281408,4
+5955742226360303616,4
+5955856575569592320,1
+5955865371662614528,8
+5955940138453303296,1
+5957136407104323584,5
+5959388206918008832,3
+5960795581801562112,5
+5961358531754983424,8
+5961644404778205184,6
+5962295315661848576,2
+5962304111754870784,7
+5962392072685092864,9
+5962400868778115072,3
+5962431655103692800,6
+5962466839475781632,9
+5962488829708337152,6
+5962506421894381568,4
+5962515217987403776,9
+5962537208219959296,4
+5962572392592048128,4
+5962594382824603648,8
+5962603178917625856,1
+5962673547661803520,6
+5962928634359447552,2
+5962937430452469760,0
+5962959420685025280,0
+5962994605057114112,6
+5963016595289669632,0
+5963025391382691840,3
+5963060575754780672,8
+5963069371847802880,5
+5963078167940825088,5
+5963100158173380608,6
+5963135342545469440,0
+5963170526917558272,6
+5963680700312846336,7
+5963821437801201664,5
+5964173281522089984,2
+5964736231475511296,4
+5966143606359064576,3
+5968395406172749824,7
+5969802781056303104,7
+5970365731009724416,6
+5970717574730612736,5
+5970858312218968064,2
+5970933079009656832,3
+5970959467288723456,9
+5970968263381745664,9
+5970973760939884544,5
+5971117796963123200,9
+5971126593056145408,1
+5971152981335212032,5
+5971161777428234240,2
+5971298116870078464,7
+5971320107102633984,9
+5971328903195656192,5
+5971346495381700608,7
+5971421262172389376,1
+5971561999660744704,6
+5971649960590966784,9
+5971685144963055616,8
+5986642901147320320,5
+5986651697240342528,6
+5986761648403120128,2
+5986849609333342208,7
+5986884793705431040,1
+5986906783937986560,5
+5986933172217053184,0
+5986955162449608704,8
+5986990346821697536,3
+5987025531193786368,3
+5987091501891452928,7
+5987100297984475136,9
+5987482928030941184,0
+5987504918263496704,1
+5987510415821635584,7
+5987531306542563328,8
+5987540102635585536,4
+5987548898728607744,7
+5987663247937896448,0
+5987668745496035328,9
+5989801798053920768,4
+5989809494635315200,1
+5989844679007404032,7
+5989853475100426240,2
+5989875465332981760,2
+5989910649705070592,9
+5989998610635292672,3
+5990139348123648000,0
+5990227309053870080,6
+5990262493425958912,9
+5990284483658514432,8
+5990293279751536640,6
+5990321132614451200,4
+5990328464123625472,2
+5990337260216647680,5
+5990346056309669888,9
+5990631929332891648,2
+5991194879286312960,4
+5991757829239734272,7
+5993165204123287552,7
+5995417003936972800,1
+5997668803750658048,8
+6003298303284871168,4
+6008083377888952320,3
+6008435221609840640,6
+6008523182540062720,7
+6008558366912151552,4
+6008580357144707072,4
+6008606745423773696,2
+6008628735656329216,1
+6008663920028418048,8
+6008766174609801216,8
+6008773871191195648,3
+6008782667284217856,7
+6008857434074906624,5
+6008945395005128704,1
+6008980579377217536,0
+6009002569609773056,4
+6009011365702795264,7
+6009016863260934144,9
+6009028957888839680,6
+6009050948121395200,2
+6009072938353950720,6
+6009373379906240512,8
+6009407189888794624,7
+6009415985981816832,0
+6009437976214372352,5
+6009473160586461184,8
+6009772227749216256,5
+6010124071470104576,2
+6010264808958459904,6
+6010352769888681984,0
+6010387954260770816,7
+6010409944493326336,1
+6010418740586348544,6
+6010423207352336384,7
+6010436332772392960,1
+6010458323004948480,9
+6010546283935170560,7
+6010687021423525888,0
+6010827758911881216,6
+6010915719842103296,5
+6010937710074658816,7
+6010946506167681024,6
+6011061954888597504,3
+6011091641702547456,0
+6011126826074636288,8
+6011148816307191808,8
+6011157612400214016,2
+6012072406074523648,0
+6012081202167545856,3
+6012111988493123584,5
+6052908267930124288,7
+6052991830813835264,0
+6053000626906857472,1
+6053035811278946304,1
+6053044607371968512,1
+6053066597604524032,8
+6053101781976612864,0
+6053189742906834944,6
+6053330480395190272,7
+6053471217883545600,5
+6053545984674234368,3
+6053554780767256576,4
+6053669129976545280,6
+6053677926069567488,8
+6053686722162589696,6
+6053695518255611904,3
+6053805469418389504,0
+6053893430348611584,1
+6054034167836966912,5
+6054122128767188992,3
+6054173805813694464,8
+6054179303371833344,5
+6054205691650899968,5
+6054227681883455488,1
+6054315642813677568,0
+6054456380302032896,3
+6054597117790388224,0
+6054737855278743552,5
+6054825816208965632,8
+6054861000581054464,5
+6054891786906632192,8
+6054997340022898688,7
+6055006136115920896,4
+6055032524394987520,6
+6055234834534498304,2
+6055252426720542720,9
+6055261222813564928,7
+6055283213046120448,8
+6055318397418209280,2
+6055340387650764800,9
+6055349183743787008,2
+6055384368115875840,2
+6055393164208898048,1
+6055401960301920256,6
+6055423950534475776,5
+6055459134906564608,7
+6055494319278653440,6
+6056070463371608064,1
+6056092453604163584,1
+6056144955284389888,0
+6056162822348341248,1
+6056198006720430080,0
+6056285967650652160,9
+6056360734441340928,3
+6056369530534363136,3
+6056378326627385344,2
+6056385679611396096,9
+6056479481697140736,9
+6056501471929696256,9
+6056510268022718464,7
+6056528959720390656,9
+6056643308929679360,6
+6056651005511073792,2
+6056659801604096000,9
+6056668597697118208,1
+6056690587929673728,1
+6056725772301762560,1
+6056760956673851392,7
+6057060023836606464,6
+6057345896859828224,7
+6057366787580755968,6
+6057372285138894848,4
+6057394275371450368,7
+6057768109324894208,8
+6057776905417916416,1
+6057785701510938624,6
+6057820885883027456,3
+6057829681976049664,3
+6057851672208605184,2
+6057886856580694016,6
+6057922040952782848,9
+6057944031185338368,3
+6057952827278360576,6
+6057970419464404992,1
+6058031992115560448,7
+6060345364580401152,4
+6089619861669937152,5
+6089627558251331584,3
+6089646249949003776,1
+6089653946530398208,6
+6089662742623420416,2
+6089671538716442624,7
+6089733111367598080,1
+6089737784292016128,3
+6089763897693175808,5
+6089799082065264640,1
+6089821072297820160,7
+6089829868390842368,6
+6089834541315260416,1
+6089847460576886784,4
+6090068462414069760,5
+6090076158995464192,3
+6090084955088486400,7
+6090093751181508608,8
+6090102547274530816,0
+6090130309943132160,8
+6090203702344286208,0
+6090344439832641536,9
+6090432400762863616,1
+6090467585134952448,6
+6090489575367507968,2
+6090498371460530176,0
+6090537953879130112,0
+6092283978344038400,7
+6092292774437060608,7
+6092679802530037760,7
+6092741375181193216,0
+6092754294442819584,3
+6092758967367237632,7
+6092767763460259840,6
+6092789753692815360,2
+6092877714623037440,5
+6092965675553259520,4
+6093000859925348352,9
+6093022850157903872,9
+6093031646250926080,0
+6093071228669526016,1
+6093089920367198208,7
+6093198772018348032,6
+6093219662739275776,5
+6093225160297414656,5
+6093299927088103424,2
+6093651770808991744,9
+6093950837971746816,2
+6093986022343835648,3
+6094021206715924480,7
+6094043196948480000,4
+6094051993041502208,7
+6094060789134524416,6
+6094205924602281984,0
+6094210322715901952,4
+6094232312948457472,6
+6094285020787113984,7
+6094289487553101824,5
+6094307079739146240,4
+6094315875832168448,3
+6094337866064723968,1
+6094425826994946048,1
+6094777670715834368,5
+6095340620669255680,2
+6096747995552808960,9
+6102377495087022080,8
+6107162569691103232,3
+6107483627086413824,6
+6107492423179436032,1
+6107501219272458240,4
+6107830797882884096,3
+6107835470807302144,3
+6107848596227358720,8
+6107853062993346560,7
+6107861859086368768,0
+6107883849318924288,7
+6107905839551479808,1
+6107923431737524224,0
+6107932227830546432,1
+6107954218063101952,6
+6107989402435190784,4
+6108077363365412864,7
+6108165324295634944,5
+6108187314528190464,2
+6108199409156096000,3
+6108204906714234880,0
+6108213702807257088,1
+6108235693039812608,7
+6108270877411901440,4
+6108358838342123520,4
+6108499575830478848,7
+6108851419551367168,4
+6110258794434920448,0
+6111455063085940736,9
+6111538625969651712,6
+6111635382992896000,6
+6111647477620801536,5
+6111652975178940416,3
+6111661771271962624,6
+6111683761504518144,3
+6111705751737073664,9
+6111723343923118080,9
+6111732140016140288,1
+6111754130248695808,8
+6111789314620784640,5
+6111877275551006720,0
+6112229119271895040,9
+6112580962992783360,5
+6112721700481138688,1
+6112809661411360768,5
+6112844845783449600,5
+6112972389132271616,1
+6112981185225293824,3
+6112989981318316032,4
+6113014995207847936,8
+6113249448882601984,0
+6113253864108982272,8
+6113262660202004480,7
+6113271456295026688,5
+6114344579643736064,9
+6114362171829780480,1
+6114370967922802688,5
+6114392958155358208,3
+6114428142527447040,9
+6114458928853024768,5
+6114523800039063552,2
+6114529297597202432,5
+6114538093690224640,4
+6118714863486238720,7
+6118804198805995520,5
+6118812994899017728,9
+6118825089526923264,5
+6118830587085062144,3
+6118839383178084352,4
+6118914149968773120,6
+6119015305038528512,9
+6119037295271084032,9
+6119063614830673920,8
+6119068081596661760,5
+6119075778178056192,2
+6219844919352098816,0
+6220231947445075968,7
+6220262733770653696,4
+6220284724003209216,1
+6220293520096231424,8
+6220311112282275840,0
+6220385879072964608,8
+6220473840003186688,9
+6220495830235742208,2
+6220504626328764416,6
+6220522218514808832,4
+6220526891439226880,5
+6220579393119453184,1
+6220878460282208256,0
+6221230304003096576,4
+6221318264933318656,4
+6221353449305407488,1
+6221375439537963008,1
+6221423818049585152,9
+6221445808282140672,6
+6221450481206558720,9
+6221473661145055232,3
+6221596441375145984,0
+6221604137956540416,3
+6221609635514679296,2
+6221634924282118144,4
+6221670108654206976,2
+6221705293026295808,7
+6221727283258851328,1
+6221732780816990208,3
+6221754771049545728,6
+6236726064970727424,3
+6236733417954738176,3
+6238237549861535744,3
+6238246345954557952,2
+6238272734233624576,6
+6238281530326646784,9
+6238286203251064832,2
+6238382685396402176,7
+6238417869768491008,0
+6238804897861468160,7
+6238840082233556992,8
+6238862072466112512,9
+6238866745390530560,9
+6238914849024245760,2
+6238923645117267968,2
+6238945635349823488,8
+6238980819721912320,6
+6239002809954467840,2
+6239011606047490048,1
+6244592727070081024,3
+6244733464558436352,5
+6244821425488658432,1
+6244856609860747264,3
+6244878600093302784,9
+6244886296674697216,3
+6244906087883997184,3
+6244926978604924928,6
+6244962162977013760,1
+6244997347349102592,4
+6245019337581658112,5
+6245028133674680320,8
+6245047186149605376,8
+6245058918926516224,8
+6245063318046769152,8
+6245072114139791360,2
+6245239239907213312,6
+6245248036000235520,9
+6245283220372324352,1
+6245292016465346560,2
+6245314006697902080,3
+6245349191069990912,2
+6245437152000212992,5
+6245643860186234880,9
+6245648259306487808,2
+6245801090349006848,9
+6245837374232723456,8
+6245846170325745664,7
+6245854966418767872,5
+6245876956651323392,0
+6245912141023412224,0
+6246000101953634304,2
+6246140839441989632,0
+6246215606232678400,8
+6246241994511745024,9
+6246250790604767232,1
+6246259586697789440,2
+6246400324186144768,0
+6246409120279166976,2
+6246435508558233600,9
+6246444304651255808,0
+6246453100744278016,4
+6246458598302416896,6
+6246774158139588608,1
+6247126001860476928,5
+6247209564744187904,8
+6247297525674409984,6
+6247319515906965504,4
+6247407476837187584,4
+6247548214325542912,4
+6247900058046431232,9
+6248463007999852544,8
+6248814851720740864,6
+6248955589209096192,9
+6249043550139318272,7
+6249065540371873792,8
+6249074336464896000,2
+6249153501302095872,1
+6249162297395118080,6
+6249237064185806848,3
+6249325025116028928,9
+6249360209488117760,4
+6249382199720673280,6
+6249390995813695488,1
+6249408587999739904,5
+6249430578232295424,7
+6249465762604384256,1
+6249487752836939776,2
+6249515240627634176,7
+6249568017185767424,9
+6249575713767161856,5
+6249823103883411456,4
+6250666429301915648,6
+6250785176557715456,0
+6250873137487937536,2
+6250908321860026368,9
+6250930312092581888,2
+6250935809650720768,6
+6250956700371648512,4
+6250978690604204032,8
+6255499882417618944,3
+6261129381951832064,5
+6263381181765517312,7
+6264788556649070592,3
+6265140400369958912,4
+6265228361300180992,4
+6265263545672269824,2
+6265285535904825344,5
+6265290208829243392,5
+6265313298573426688,3
+6265333914416447488,4
+6265355904649003008,5
+6265361402207141888,5
+6265383392439697408,5
+6265506537742008320,1
+6265514234323402752,9
+6265519731881541632,3
+6265545020648980480,4
+6265580205021069312,7
+6265615389393158144,4
+6265637379625713664,2
+6265642877183852544,1
+6265664867416408064,3
+6266280593927962624,7
+6266288290509357056,1
+6266293788067495936,3
+6266350962672140288,5
+6266358659253534720,8
+6266364156811673600,9
+6266389445579112448,3
+6266424629951201280,0
+6266459814323290112,3
+6266547775253512192,3
+6266635736183734272,0
+6266670920555823104,9
+6266692910788378624,9
+6266698408346517504,1
+6266720398579073024,1
+6266741289300000768,1
+6267884781392887808,1
+6273514280927100928,2
+6282521480181841920,3
+6287306554785923072,5
+6287869504739344384,5
+6288221348460232704,9
+6288309309390454784,4
+6288331299623010304,0
+6288335972547428352,2
+6288359062291611648,3
+6288411838849744896,0
+6288419260553232384,4
+6288423933477650432,5
+6288622945082277888,5
+6288630366785765376,7
+6288635039710183424,3
+6288661153111343104,6
+6288683143343898624,9
+6288687816268316672,1
+6288710631134593024,2
+6288995404646187008,4
+6289347248367075328,5
+6289435209297297408,2
+6289457199529852928,2
+6289462697087991808,4
+6289483587808919552,3
+6289536364367052800,3
+6289545160460075008,2
+6289553956553097216,4
+6289722181832146944,1
+6289751868646096896,8
+6289787053018185728,6
+6289822237390274560,5
+6289844227622830080,8
+6289853023715852288,6
+6289962974878629888,4
+6289998159250718720,5
+6290033343622807552,6
+6290055333855363072,6
+6290064129948385280,1
+6290097848662884352,7
+6295096869546622976,5
+6295104291250110464,4
+6295109788808249344,4
+6295135077575688192,8
+6295157067808243712,8
+6295162565366382592,6
+6295184555598938112,8
+6295258222877999104,2
+6295346183808221184,9
+6295368174040776704,5
+6295376970133798912,4
+6295394562319843328,5
+6295447338877976576,2
+6295456134970998784,5
+6295464931064020992,5
+6296124638040686592,8
+6296196381174398976,7
+6296225793110441984,9
+6296260977482530816,2
+6296282967715086336,5
+6296291763808108544,9
+6296297261366247424,7
+6296309355994152960,5
+6296384122784841728,6
+6296472083715063808,4
+6296507268087152640,8
+6296529258319708160,6
+6296557106887655424,1
+6296577636831330304,6
+6296876703994085376,4
+6297439653947506688,6
+6298002603900928000,9
+6299409978784481280,6
+6301661778598166528,4
+6303913578411851776,9
+6306165378225537024,1
+6307572753109090304,5
+6307871820271845376,2
+6307907004643934208,0
+6307928994876489728,2
+6307937790969511936,3
+6307972975341600768,1
+6307981771434622976,9
+6308294032736911360,3
+6308314579860455424,1
+6308333615155511296,9
+6308342411248533504,2
+6308364401481089024,7
+6308399585853177856,0
+6308487546783399936,6
+6308909759248465920,0
+6309261602969354240,4
+6309824552922775552,0
+6310176396643663872,2
+6310378431905267712,1
+6310383104829685760,3
+6310391900922707968,8
+6310400697015730176,5
+6310515046225018880,6
+6310523842318041088,8
+6310598609108729856,6
+6310739346597085184,5
+6310814113387773952,0
+6310822909480796160,2
+6310937258690084864,4
+6310946054783107072,5
+6310954850876129280,0
+6311161559062151168,0
+6311513402783039488,2
+6312920777666592768,6
+6315172577480278016,5
+6316579952363831296,7
+6317142902317252608,9
+6317494746038140928,5
+6317635483526496256,9
+6317723444456718336,3
+6317758628828807168,0
+6317780619061362688,7
+6317789415154384896,3
+6317807007340429312,1
+6317828997572984832,1
+6317916958503206912,0
+6318268802224095232,8
+6318620645944983552,7
+6318695412735672320,0
+6318704208828694528,4
+6318820001146994688,7
+6318987058194939904,2
+6318994479898427392,6
+6319020868177494016,8
+6319029664270516224,1
+6319038460363538432,7
+6319060450596093952,4
+6319095634968182784,0
+6319130819340271616,7
+6319240770503049216,1
+6319249566596071424,8
+6319254033362059264,3
+6321422201572556800,2
+6321452987898134528,3
+6321488172270223360,9
+6321576133200445440,1
+6321716870688800768,9
+6321804831619022848,0
+6321840015991111680,6
+6321862006223667200,4
+6321870802316689408,1
+6321889494014361600,4
+6321910384735289344,2
+6322209451898044416,8
+6322508519060799488,1
+6322530509293355008,5
+6322556897572421632,1
+6322562395130560512,1
+6322614072177065984,8
+6322636062409621504,1
+6322644858502643712,6
+6322649260844122112,5
+6322662450688688128,1
+6322671246781710336,2
+6322680042874732544,7
+6350238202313310208,8
+6350246998406332416,7
+6350268988638887936,1
+6350304173010976768,7
+6350326163243532288,7
+6350334959336554496,2
+6350378939801665536,3
+6350387735894687744,7
+6350409726127243264,6
+6350444910499332096,3
+6350470199266770944,8
+6350475696824909824,7
+6351007860452753408,0
+6351043044824842240,1
+6351078229196931072,1
+6351183782313197568,8
+6351482849475952640,2
+6352045799429373952,1
+6353453174312927232,2
+6355704974126612480,2
+6357112349010165760,5
+6357675298963587072,7
+6357961171986808832,8
+6357969968079831040,1
+6358065350713540608,3
+6358084317289119744,3
+6358093113382141952,6
+6358115103614697472,9
+6358150287986786304,6
+6358708839893696512,4
+6358717635986718720,0
+6358744024265785344,2
+6358752820358807552,1
+6358849577382051840,6
+6358858373475074048,0
+6358884761754140672,2
+6358893557847162880,5
+6359270690335490048,6
+6360255509156593664,6
+6360583507219054592,5
+6360639307434164224,5
+6360643980358582272,1
+6360652776451604480,1
+6360705553009737728,2
+6360723145195782144,6
+6360731941288804352,2
+6360753931521359872,1
+6360841892451581952,8
+6360929853381804032,8
+6360978231893426176,4
+6361000222125981696,9
+6361035406498070528,6
+6361123367428292608,9
+6361264104916647936,7
+6361615948637536256,5
+6361967792358424576,6
+6362055753288646656,7
+6362090937660735488,4
+6362112927893291008,0
+6362117600817709056,1
+6362139316172357632,6
+6362161306404913152,3
+6362183296637468672,8
+6362192092730490880,3
+6362209684916535296,2
+6362307541451407360,8
+6362390004823490560,9
+6362477965753712640,1
+6362499955986268160,3
+6362508752079290368,7
+6362526344265334784,7
+6362580495213002752,9
+6362587916916490240,4
+6363046413265272832,8
+6363076100079222784,4
+6363111284451311616,9
+6363146468823400448,9
+6363234429753622528,1
+6363375167241977856,3
+6363458730125688832,8
+6363467526218711040,7
+6363476322311733248,2
+6363498312544288768,3
+6363533496916377600,5
+6363568681288466432,1
+6363603865660555264,9
+6363639050032644096,1
+6363661040265199616,5
+6363665713189617664,3
+6363688528055894016,7
+6363709418776821760,8
+6363731409009377280,7
+6363740205102399488,6
+6363757797288443904,3
+6364100844916310016,2
+6366001900520734720,4
+6366088761939329024,9
+6366097558032351232,5
+6366102230956769280,9
+6366115150218395648,8
+6366123946311417856,8
+6366132742404440064,6
+6366248466003263488,1
+6366277877939306496,9
+6366299868171862016,7
+6366388928613711872,3
+6366418615427661824,8
+6366440605660217344,9
+6366449401753239552,8
+6366466993939283968,5
+6366475790032306176,3
+6366503552700907520,2
+6366524168543928320,1
+6366559352916017152,7
+6366581343148572672,2
+6366590139241594880,6
+6464165199136948224,9
+6470165234089721856,4
+6470172930671116288,8
+6470181726764138496,4
+6470190522857160704,6
+6470212513089716224,4
+6470234503322271744,0
+6470243299415293952,3
+6470260891601338368,7
+6470335658392027136,3
+6470423619322249216,3
+6470445609554804736,2
+6470450282479222784,7
+6470533570485026816,7
+6470552537060605952,6
+6470559958764093440,5
+6470568754857115648,3
+6470577550950137856,3
+6470599541182693376,8
+6470634725554782208,1
+6470669909926871040,0
+6470757870857093120,3
+6470898608345448448,2
+6471039345833803776,0
+6471127306764025856,8
+6471162491136114688,8
+6471184481368670208,9
+6471212244037271552,7
+6471232859880292352,6
+6471254850112847872,6
+6471260347670986752,3
+6471281238391914496,3
+6471625385531408384,6
+6471713621339537408,5
+6471721043043024896,0
+6471729839136047104,3
+6471738635229069312,1
+6471760625461624832,6
+6471782615694180352,8
+6471791411787202560,9
+6471809003973246976,3
+6471883770763935744,2
+6472024508252291072,7
+6472165245740646400,4
+6472517089461534720,0
+6473080039414956032,6
+6473642989368377344,4
+6473994833089265664,0
+6474082794019487744,6
+6474104784252043264,3
+6474113580345065472,5
+6474131172531109888,2
+6474135845455527936,7
+6474188347135754240,2
+6474210337368309760,3
+6474352174368292864,7
+6474359870949687296,2
+6474368667042709504,8
+6474377463135731712,4
+6474399453368287232,5
+6474434637740376064,9
+6474469822112464896,9
+6474505006484553728,8
+6474526996717109248,4
+6474614957647331328,9
+6474620455205470208,6
+8741781545842376704,6
+8741790341935398912,1
+8741809033633071104,1
+8741820028749348864,1
+8741825526307487744,1
+8741834322400509952,1
+8741856312633065472,9
+8741891497005154304,7
+8741913487237709824,0
+8741922283330732032,3
+8741939875516776448,1
+8741945373074915328,5
+8742071816912109568,2
+8742102603237687296,5
+8742137787609776128,0
+8742167474423726080,1
+8742326903609753600,5
+8742348893842309120,3
+8742400570888814592,9
+8742419262586486784,2
+8742454446958575616,7
+8742542407888797696,3
+8742630368819019776,3
+8742652359051575296,4
+8742674074406223872,8
+8742678747330641920,8
+8742700737563197440,8
+8742735921935286272,7
+8742823882865508352,6
+8742911843795730432,9
+8742947028167819264,8
+8742982212539908096,3
+8743008325941067776,6
+8743012998865485824,2
+8743020695446880256,6
+8743077870051524608,4
+8743083367609663488,9
+8743091064191057920,9
+8743369240632885248,8
+8743394529400324096,1
+8743400026958462976,4
+8934968762499596288,9
+8934996525168197632,5
+8935005321261219840,6
+8935014117354242048,9
+8935109409793638400,4
+8935128466563530752,8
+8935137262656552960,5
+8935159252889108480,0
+8935181243121664000,7
+8935193337749569536,3
+8935198835307708416,4
+8935207631400730624,8
+8935229621633286144,8
+8935264806005374976,3
+8935352766935597056,4
+8935427533726285824,9
+8935453922005352448,1
+8935462718098374656,3
+8935471514191396864,1
+8935480310284419072,3
+8935612251679752192,6
+8936852500795883520,6
+8936861296888905728,1
+8936883287121461248,6
+8936918471493550080,4
+8936949257819127808,9
+8937059208981905408,5
+8937094393353994240,4
+8937129577726083072,7
+8937164762098171904,9
+8937186752330727424,1
+8937195548423749632,6
+8937230732795838464,5
+8937239528888860672,0
+8937274713260949504,5
+8937283509353971712,8
+8937305499586527232,5
+8937340683958616064,9
+8937375868330704896,3
+8937411052702793728,3
+8937494615586504704,1
+8937516605819060224,9
+8937604566749282304,4
+8937696925726015488,4
+8937705721819037696,6
+8937727712051593216,9
+8937762896423682048,2
+8937784886656237568,9
+8937793682749259776,5
+8938325846377103360,6
+8938361030749192192,7
+8938396215121281024,5
+8938447892167786496,0
+8938453389725925376,4
+8938479778004992000,1
+8938501768237547520,8
+8938536952609636352,0
+8938642505725902848,8
+8938677690097991680,8
+8938712874470080512,2
+8938734864702636032,1
+8938743660795658240,7
+8939275824423501824,0
+8939302143983091712,1
+8939306610749079552,7
+8939315406842101760,6
+8939410789475811328,3
+8962888936141619200,2
+8962897732234641408,4
+8962919722467196928,2
+8962954906839285760,8
+8962984232875982848,1
+8963060459955552256,6
+8963085748722991104,2
+8963091246281129984,6
+8963100042374152192,7
+8963478274374107136,1
+8963485970955501568,0
+8966811993629523968,6
+8966825119049580544,0
+8966829585815568384,5
+8966838381908590592,7
+8966860372141146112,9
+8966895556513234944,5
+8966917546745790464,0
+8966926342838812672,3
+8966970323303923712,4
+8966979119396945920,9
+8967001109629501440,8
+8967036294001590272,5
+8967058284234145792,6
+8967067080327168000,4
+8967524477164322816,7
+8967533273257345024,3
+8967568457629433856,7
+8967577253722456064,8
+8967599243955011584,2
+8967634428327100416,1
+8967669612699189248,0
+8967691602931744768,4
+8967717991210811392,8
+8967726787303833600,9
+8967753175582900224,9
+8967775165815455744,5
+8967810350187544576,9
+8967915903303811072,0
+8967951087675899904,2
+8967986272047988736,8
+8968536027861876736,1
+8968544823954898944,1
+8968553620047921152,7
+8968580008326987776,8
+8968588804420009984,0
+8968685561443254272,6
+8968694357536276480,7
+8968720745815343104,5
+8968729541908365312,6
+8969477209815252992,0
+8969551976605941760,0
+8969626743396630528,2
+8969635539489652736,3
+8969644335582674944,2
+8969695737751273472,8
+8969723500419874816,0
+8969745490652430336,5
+8969833451582652416,9
+8969921412512874496,8
+8969956596884963328,5
+8969978587117518848,0
+8969987383210541056,5
+8970136916791918592,6
+8970145712884940800,1
+8970154508977963008,6
+8970180897257029632,7
+8970255664047718400,4
+8970396401536073728,1
+8970513684208025600,3
+8972665793535803392,4
+8972700977907892224,2
+8972736162279981056,6
+8972841715396247552,4
+8972876899768336384,1
+8972912084140425216,9
+8972934074372980736,3
+8972942870466002944,4
+8973285918093869056,6
+8973294714186891264,0
+8973303510279913472,1
+8973338694652002304,3
+8973347490745024512,4
+8973369480977580032,1
+8973404665349668864,6
+8973439849721757696,6
+8973461839954313216,8
+8973488228233379840,8
+8973497024326402048,8
+8973523412605468672,7
+8973545402838024192,4
+8973580587210113024,8
+8973615771582201856,3
+8973637761814757376,8
+8973646557907779584,1
+8973653979611267072,1
+8973681742279868416,7
+8973690538372890624,4
+8975462951116865536,5
+8975603688605220864,2
+8975744426093576192,2
+8975885163581931520,5
+8976002536448196608,8
+8977230897094852608,2
+8977235363860840448,0
+8977323324791062528,4
+8977345315023618048,4
+8977433275953840128,0
+8977515464448016384,1
+8977596003674750976,0
+8977604799767773184,5
+8977613595860795392,2
+8977631188046839808,1
+8977639984139862016,4
+8977661974372417536,8
+8977697158744506368,8
+8977719148977061888,3
+8977727945070084096,2
+8977763129442172928,7
+8977770482426183680,6
+8977824702093328384,1
+8977833498186350592,9
+8977842294279372800,7
+8977867308168904704,2
+8978629269726953472,9
+8978633942651371520,7
+8978660330930438144,5
+8978669127023460352,3
+8978677923116482560,6
+8978685254625656832,3
+8986422883022536704,0
+8987158456301518848,8
+8987166152882913280,9
+8987174948975935488,9
+8987254113813135360,9
+8987262909906157568,2
+8987270606487552000,4
+8988494362929266688,8
+8988501698733408256,1
+8988554836068794368,6
+8988573527766466560,4
+8988582323859488768,2
+8988604314092044288,5
+8988692275022266368,9
+8988780235952488448,9
+8988828614464110592,5
+8988850604696666112,8
+8988885789068754944,2
+8988920973440843776,0
+8988956157812932608,8
+8988978148045488128,6
+8988982820969906176,7
+8989026526557110272,5
+8989048516789665792,9
+8989066108975710208,6
+8989074905068732416,2
+8989096895301287936,1
+8989122184068726784,4
+8989127681626865664,3
+8989135378208260096,6
+8989326693231493120,7
+9127270322540642304,9
+9127279118633664512,5
+9127301108866220032,8
+9127336293238308864,8
+9127367079563886592,4
+9127441846354575360,0
+9127468165914165248,3
+9127472632680153088,8
+9127481428773175296,9
+9127858286383595520,4
```

