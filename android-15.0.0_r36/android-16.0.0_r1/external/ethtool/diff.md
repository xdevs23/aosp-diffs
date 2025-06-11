```diff
diff --git a/Android.bp b/Android.bp
index 54e04d3..e217943 100644
--- a/Android.bp
+++ b/Android.bp
@@ -59,7 +59,7 @@ cc_binary {
         "-DETHTOOL_ENABLE_NETLINK",
         // causes a fair bit of binary bloat: "-DETHTOOL_ENABLE_PRETTY_DUMP",
         "-DPACKAGE=\"ethtool\"",
-        "-DVERSION=\"6.5\"",
+        "-DVERSION=\"6.11\"",
     ],
     apex_available: [
         "com.android.tethering",
diff --git a/Makefile.am b/Makefile.am
index ae3b667..862886b 100644
--- a/Makefile.am
+++ b/Makefile.am
@@ -6,8 +6,12 @@ man_MANS = ethtool.8
 EXTRA_DIST = LICENSE ethtool.8 ethtool.spec.in aclocal.m4 ChangeLog autogen.sh
 
 sbin_PROGRAMS = ethtool
-ethtool_SOURCES = ethtool.c uapi/linux/ethtool.h internal.h \
+ethtool_SOURCES = ethtool.c uapi/linux/const.h uapi/linux/ethtool.h internal.h \
 		  uapi/linux/net_tstamp.h uapi/linux/if.h uapi/linux/hdlc/ioctl.h \
+		  uapi/linux/if_addr.h uapi/linux/if_ether.h uapi/linux/if_link.h \
+		  uapi/linux/libc-compat.h uapi/linux/net_tstamp.h uapi/linux/neighbour.h \
+		  uapi/linux/posix_types.h uapi/linux/rtnetlink.h uapi/linux/socket.h \
+		  uapi/linux/stddef.h uapi/linux/types.h \
 		  rxclass.c common.c common.h \
 		  json_writer.c json_writer.h json_print.c json_print.h \
 		  list.h
@@ -44,6 +48,7 @@ ethtool_SOURCES += \
 		  netlink/desc-rtnl.c netlink/cable_test.c netlink/tunnels.c \
 		  netlink/plca.c \
 		  netlink/pse-pd.c \
+		  netlink/phy.c \
 		  uapi/linux/ethtool_netlink.h \
 		  uapi/linux/netlink.h uapi/linux/genetlink.h \
 		  uapi/linux/rtnetlink.h uapi/linux/if_link.h \
@@ -55,12 +60,12 @@ endif
 TESTS = test-cmdline
 check_PROGRAMS = test-cmdline
 test_cmdline_SOURCES = test-cmdline.c test-common.c $(ethtool_SOURCES) 
-test_cmdline_CFLAGS = -DTEST_ETHTOOL
+test_cmdline_CFLAGS = -D_POSIX_C_SOURCE=200809L -DTEST_ETHTOOL
 if !ETHTOOL_ENABLE_NETLINK
 TESTS += test-features
 check_PROGRAMS += test-features
 test_features_SOURCES = test-features.c test-common.c $(ethtool_SOURCES) 
-test_features_CFLAGS = -DTEST_ETHTOOL
+test_features_CFLAGS = -D_POSIX_C_SOURCE=200809L -DTEST_ETHTOOL
 endif
 
 dist-hook:
diff --git a/NEWS b/NEWS
index e5eca95..4fb5713 100644
--- a/NEWS
+++ b/NEWS
@@ -1,3 +1,41 @@
+Version 6.11 - October 8, 2024
+	* Feature: cmis: print active and inactive firmware versions
+	* Feature: flash transceiver module firmware (--flash-module-firmware)
+	* Feature: add T1BRR 10Mb/s mode to link mode tables
+	* Feature: support for disabling netlink from command line
+	* Fix: fix lanes parameter format specifier
+	* Fix: add missing clause 33 PSE manual description
+	* Fix: qsf: Better handling of Page A2h netlink read failure
+	* Fix: rss: retrieve ring count using ETHTOOL_GRXRINGS ioctl (-x)
+	* Misc: man page formatting fix
+
+Version 6.10 - August 9, 2024
+	* Feature: suport for PoE in PSE (--show-pse and --set-pse)
+	* Feature: add statistics support to tsinfo (-T)
+	* Feature: add JSON output to base command (no option)
+	* Feature: add JSON output to EEE info (--show-eee)
+	* Fix: qsfp: better handling on page 03h read failure (-m)
+	* Fix: handle zero arguments for module eeprom dump (-m)
+	* Fix: check for missing arguments in do_srxfh() (-X)
+	* Misc: compiler warnings in "make check"
+	* Misc: more descriptive error when JSON output is not available
+
+Version 6.9 - May 23, 2024
+	* Feature: support for rx-flow-hash gtp (-N)
+	* Feature: support for RSS input transformation (-X)
+	* Fix: typo in coalescing output (-c)
+	* Fix: document all debugging flags in man page
+
+Version 6.7 - January 29, 2024
+	* Feature: support for setting TCP data split
+	* Fix: fix new gcc14 warning
+	* Fix: fix SFF-8472 transceiver module identification (-m)
+	* Misc: code cleanup
+
+Version 6.6 - November 23, 2023
+	* Feature: support for more CMIS transceiver modules (-m)
+	* Fix: fix build on systems with old kernel uapi headers
+
 Version 6.5 - September 12, 2023
 	* Feature: register dump for hns3 driver (-d)
 	* Fix: fix fallback to ioctl for sset (-s)
diff --git a/OWNERS b/OWNERS
index c24680e..9310bff 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 set noparent
 file:platform/packages/modules/Connectivity:main:/OWNERS_core_networking
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/cmis.c b/cmis.c
index 531932e..6fe5dfb 100644
--- a/cmis.c
+++ b/cmis.c
@@ -884,6 +884,129 @@ static void cmis_show_dom(const struct cmis_memory_map *map)
 		sff_show_thresholds(sd);
 }
 
+/* Print active and inactive firmware versions. Relevant documents:
+ * [1] CMIS Rev. 5, page 115, section 8.2.9, Table 8-14
+ * [2] CMIS Rev. 5, page 127, section 8.4.1, Table 8-37
+ */
+static void cmis_show_fw_version_common(const char *name, __u8 major,
+					__u8 minor)
+{
+	if (major == 0 && minor == 0) {
+		return;
+	} else if (major == 0xFF && minor == 0xFF) {
+		printf("\t%-41s : Invalid\n", name);
+		return;
+	}
+
+	printf("\t%-41s : %d.%d\n", name, major, minor);
+}
+
+static void cmis_show_fw_active_version(const struct cmis_memory_map *map)
+{
+	__u8 major = map->lower_memory[CMIS_MODULE_ACTIVE_FW_MAJOR_OFFSET];
+	__u8 minor = map->lower_memory[CMIS_MODULE_ACTIVE_FW_MINOR_OFFSET];
+
+	cmis_show_fw_version_common("Active firmware version", major, minor);
+}
+
+static void cmis_show_fw_inactive_version(const struct cmis_memory_map *map)
+{
+	__u8 major;
+	__u8 minor;
+
+	if (!map->page_01h)
+		return;
+
+	major = map->page_01h[CMIS_MODULE_INACTIVE_FW_MAJOR_OFFSET];
+	minor = map->page_01h[CMIS_MODULE_INACTIVE_FW_MINOR_OFFSET];
+	cmis_show_fw_version_common("Inactive firmware version", major, minor);
+}
+
+static void cmis_show_fw_version(const struct cmis_memory_map *map)
+{
+	cmis_show_fw_active_version(map);
+	cmis_show_fw_inactive_version(map);
+}
+
+static u8 cmis_cdb_instances_get(const struct cmis_memory_map *map)
+{
+	return (map->page_01h[CMIS_CDB_ADVER_OFFSET] &
+		CMIS_CDB_ADVER_INSTANCES_MASK) >> 6;
+}
+
+static bool cmis_cdb_is_supported(const struct cmis_memory_map *map)
+{
+	__u8 cdb_instances = cmis_cdb_instances_get(map);
+
+	/* Up to two CDB instances are supported. */
+	return cdb_instances == 1 || cdb_instances == 2;
+}
+
+static void cmis_show_cdb_instances(const struct cmis_memory_map *map)
+{
+	__u8 cdb_instances = cmis_cdb_instances_get(map);
+
+	printf("\t%-41s : %u\n", "CDB instances", cdb_instances);
+}
+
+static void cmis_show_cdb_mode(const struct cmis_memory_map *map)
+{
+	__u8 mode = map->page_01h[CMIS_CDB_ADVER_OFFSET] &
+		    CMIS_CDB_ADVER_MODE_MASK;
+
+	printf("\t%-41s : %s\n", "CDB background mode",
+	       mode ? "Supported" : "Not supported");
+}
+
+static void cmis_show_cdb_epl_pages(const struct cmis_memory_map *map)
+{
+	__u8 epl_pages = map->page_01h[CMIS_CDB_ADVER_OFFSET] &
+			 CMIS_CDB_ADVER_EPL_MASK;
+
+	printf("\t%-41s : %u\n", "CDB EPL pages", epl_pages);
+}
+
+static void cmis_show_cdb_rw_len(const struct cmis_memory_map *map)
+{
+	__u16 rw_len = map->page_01h[CMIS_CDB_ADVER_RW_LEN_OFFSET];
+
+	/* Maximum read / write length for CDB EPL pages and the LPL page in
+	 * units of 8 bytes, in addition to the minimum 8 bytes.
+	 */
+	rw_len = (rw_len + 1) * 8;
+	printf("\t%-41s : %u\n", "CDB Maximum EPL RW length", rw_len);
+	printf("\t%-41s : %u\n", "CDB Maximum LPL RW length",
+	       rw_len > CMIS_PAGE_SIZE ? CMIS_PAGE_SIZE : rw_len);
+}
+
+static void cmis_show_cdb_trigger(const struct cmis_memory_map *map)
+{
+	__u8 trigger = map->page_01h[CMIS_CDB_ADVER_TRIGGER_OFFSET] &
+		       CMIS_CDB_ADVER_TRIGGER_MASK;
+
+	/* Whether a CDB command can be triggered in a single write to the LPL
+	 * page, or by multiple writes ending with the writing of the CDB
+	 * Command Code (CMDID).
+	 */
+	printf("\t%-41s : %s\n", "CDB trigger method",
+	       trigger ? "Single write" : "Multiple writes");
+}
+
+/* Print CDB messaging support advertisement. Relevant documents:
+ * [1] CMIS Rev. 5, page 133, section 8.4.11
+ */
+static void cmis_show_cdb_adver(const struct cmis_memory_map *map)
+{
+	if (!map->page_01h || !cmis_cdb_is_supported(map))
+		return;
+
+	cmis_show_cdb_instances(map);
+	cmis_show_cdb_mode(map);
+	cmis_show_cdb_epl_pages(map);
+	cmis_show_cdb_rw_len(map);
+	cmis_show_cdb_trigger(map);
+}
+
 static void cmis_show_all_common(const struct cmis_memory_map *map)
 {
 	cmis_show_identifier(map);
@@ -900,6 +1023,8 @@ static void cmis_show_all_common(const struct cmis_memory_map *map)
 	cmis_show_mod_fault_cause(map);
 	cmis_show_mod_lvl_controls(map);
 	cmis_show_dom(map);
+	cmis_show_fw_version(map);
+	cmis_show_cdb_adver(map);
 }
 
 static void cmis_memory_map_init_buf(struct cmis_memory_map *map,
diff --git a/cmis.h b/cmis.h
index 8d66f92..cee2a38 100644
--- a/cmis.h
+++ b/cmis.h
@@ -41,6 +41,10 @@
 #define CMIS_LOW_PWR_ALLOW_REQUEST_HW_MASK	0x40
 #define CMIS_LOW_PWR_REQUEST_SW_MASK		0x10
 
+/* Module Active Firmware Version (Page 0) */
+#define CMIS_MODULE_ACTIVE_FW_MAJOR_OFFSET	0x27
+#define CMIS_MODULE_ACTIVE_FW_MINOR_OFFSET	0x28
+
 /* Module Fault Information (Page 0) */
 #define CMIS_MODULE_FAULT_OFFSET		0x29
 #define CMIS_MODULE_FAULT_NO_FAULT		0x00
@@ -134,6 +138,10 @@
  * GlobalOffset = 2 * 0x80 + LocalOffset
  */
 
+/* Module Inactive Firmware Version (Page 1) */
+#define CMIS_MODULE_INACTIVE_FW_MAJOR_OFFSET	0x80
+#define CMIS_MODULE_INACTIVE_FW_MINOR_OFFSET	0x81
+
 /* Supported Link Length (Page 1) */
 #define CMIS_SMF_LEN_OFFSET			0x84
 #define CMIS_OM5_LEN_OFFSET			0x85
@@ -183,6 +191,17 @@
 #define CMIS_SIG_INTEG_TX_OFFSET		0xA1
 #define CMIS_SIG_INTEG_RX_OFFSET		0xA2
 
+/* CDB Messaging Support Advertisement */
+#define CMIS_CDB_ADVER_OFFSET			0xA3
+#define CMIS_CDB_ADVER_INSTANCES_MASK		0xC0
+#define CMIS_CDB_ADVER_MODE_MASK		0x20
+#define CMIS_CDB_ADVER_EPL_MASK			0x0F
+
+#define CMIS_CDB_ADVER_RW_LEN_OFFSET		0xA4
+
+#define CMIS_CDB_ADVER_TRIGGER_OFFSET		0xA5
+#define CMIS_CDB_ADVER_TRIGGER_MASK		0x80
+
 /*-----------------------------------------------------------------------
  * Upper Memory Page 0x02: Optional Page that informs about module-defined
  * thresholds for module-level and lane-specific threshold crossing monitors.
diff --git a/common.c b/common.c
index b8fd4d5..4fda4b4 100644
--- a/common.c
+++ b/common.c
@@ -5,6 +5,7 @@
  */
 
 #include "internal.h"
+#include "json_print.h"
 #include "common.h"
 
 #ifndef HAVE_NETIF_MSG
@@ -129,21 +130,28 @@ static char *unparse_wolopts(int wolopts)
 
 int dump_wol(struct ethtool_wolinfo *wol)
 {
-	fprintf(stdout, "	Supports Wake-on: %s\n",
-		unparse_wolopts(wol->supported));
-	fprintf(stdout, "	Wake-on: %s\n",
-		unparse_wolopts(wol->wolopts));
+	print_string(PRINT_ANY, "supports-wake-on",
+		    "	Supports Wake-on: %s\n", unparse_wolopts(wol->supported));
+	print_string(PRINT_ANY, "wake-on",
+		    "	Wake-on: %s\n", unparse_wolopts(wol->wolopts));
+
 	if (wol->supported & WAKE_MAGICSECURE) {
 		int i;
 		int delim = 0;
 
-		fprintf(stdout, "        SecureOn password: ");
+		open_json_array("secureon-password", "");
+		if (!is_json_context())
+			fprintf(stdout, "        SecureOn password: ");
 		for (i = 0; i < SOPASS_MAX; i++) {
-			fprintf(stdout, "%s%02x", delim ? ":" : "",
-				wol->sopass[i]);
+			__u8 sopass = wol->sopass[i];
+
+			if (!is_json_context())
+				fprintf(stdout, "%s%02x", delim ? ":" : "", sopass);
+			else
+				print_hex(PRINT_JSON, NULL, "%02u", sopass);
 			delim = 1;
 		}
-		fprintf(stdout, "\n");
+		close_json_array("\n");
 	}
 
 	return 0;
@@ -151,26 +159,50 @@ int dump_wol(struct ethtool_wolinfo *wol)
 
 void dump_mdix(u8 mdix, u8 mdix_ctrl)
 {
-	fprintf(stdout, "	MDI-X: ");
+	bool mdi_x = false;
+	bool mdi_x_forced = false;
+	bool mdi_x_auto = false;
+
 	if (mdix_ctrl == ETH_TP_MDI) {
-		fprintf(stdout, "off (forced)\n");
+		mdi_x = false;
+		mdi_x_forced = true;
 	} else if (mdix_ctrl == ETH_TP_MDI_X) {
-		fprintf(stdout, "on (forced)\n");
+		mdi_x = true;
+		mdi_x_forced = true;
 	} else {
 		switch (mdix) {
-		case ETH_TP_MDI:
-			fprintf(stdout, "off");
-			break;
 		case ETH_TP_MDI_X:
-			fprintf(stdout, "on");
+			mdi_x = true;
 			break;
 		default:
-			fprintf(stdout, "Unknown");
-			break;
+			print_string(PRINT_FP, NULL, "\tMDI-X: %s\n", "Unknown");
+			return;
 		}
 		if (mdix_ctrl == ETH_TP_MDI_AUTO)
-			fprintf(stdout, " (auto)");
-		fprintf(stdout, "\n");
+			mdi_x_auto = true;
+	}
+
+	if (is_json_context()) {
+		print_bool(PRINT_JSON, "mdi-x", NULL, mdi_x);
+		print_bool(PRINT_JSON, "mdi-x-forced", NULL, mdi_x_forced);
+		print_bool(PRINT_JSON, "mdi-x-auto", NULL, mdi_x_auto);
+	} else {
+		fprintf(stdout, "	MDI-X: ");
+		if (mdi_x_forced) {
+			if (mdi_x)
+				fprintf(stdout, "on (forced)\n");
+			else
+				fprintf(stdout, "off (forced)\n");
+		} else {
+			if (mdi_x)
+				fprintf(stdout, "on");
+			else
+				fprintf(stdout, "off");
+
+			if (mdi_x_auto)
+				fprintf(stdout, " (auto)");
+			fprintf(stdout, "\n");
+		}
 	}
 }
 
diff --git a/configure.ac b/configure.ac
index 11efb99..f9f169e 100644
--- a/configure.ac
+++ b/configure.ac
@@ -1,5 +1,5 @@
 dnl Process this file with autoconf to produce a configure script.
-AC_INIT(ethtool, 6.5, netdev@vger.kernel.org)
+AC_INIT(ethtool, 6.11, netdev@vger.kernel.org)
 AC_PREREQ(2.52)
 AC_CONFIG_MACRO_DIR([m4])
 AC_CONFIG_SRCDIR([ethtool.c])
diff --git a/ethtool.8.in b/ethtool.8.in
index c0c37a4..9e272f7 100644
--- a/ethtool.8.in
+++ b/ethtool.8.in
@@ -117,7 +117,7 @@
 .  hy \\n(HY
 ..
 .
-.TH ETHTOOL 8 "September 2023" "Ethtool version @VERSION@"
+.TH ETHTOOL 8 "October 2024" "Ethtool version @VERSION@"
 .SH NAME
 ethtool \- query or control network driver and hardware settings
 .
@@ -137,12 +137,19 @@ ethtool \- query or control network driver and hardware settings
 .BN --debug
 .I args
 .HP
+.B ethtool [--disable-netlink]
+.I args
+.HP
 .B ethtool [--json]
 .I args
 .HP
 .B ethtool [-I | --include-statistics]
 .I args
 .HP
+.B ethtool
+.BN --phy
+.I args
+.HP
 .B ethtool \-\-monitor
 [
 .I command
@@ -202,6 +209,7 @@ ethtool \- query or control network driver and hardware settings
 .BN rx\-jumbo
 .BN tx
 .BN rx\-buf\-len
+.B3 tcp\-data\-split auto on off
 .BN cqe\-size
 .BN tx\-push
 .BN rx\-push
@@ -350,6 +358,7 @@ ethtool \- query or control network driver and hardware settings
 .RB ...\ | \ default \ ]
 .RB [ hfunc
 .IR FUNC ]
+.B2 xfrm symmetric-xor none
 .RB [ context
 .I CTX
 .RB |\  new ]
@@ -534,6 +543,19 @@ ethtool \- query or control network driver and hardware settings
 .I devname
 .RB [ podl\-pse\-admin\-control
 .BR enable | disable ]
+.RB [ c33\-pse\-admin\-control
+.BR enable | disable ]
+.BN c33\-pse\-avail\-pw\-limit N
+.HP
+.B ethtool \-\-flash\-module\-firmware
+.I devname
+.BI file
+.IR FILE
+.RB [ pass
+.IR PASS ]
+.HP
+.B ethtool \-\-show\-phys
+.I devname
 .
 .\" Adjust lines (i.e. full justification) and hyphenate.
 .ad
@@ -564,8 +586,15 @@ Turns on debugging messages. Argument is interpreted as a mask:
 nokeep;
 lB	l.
 0x01  Parser information
+0x02  Summary of netlink messages
+0x04  Hex dump of sent netlink messages
+0x08  Hex dump of received netlink messages
+0x10  Structure of netlink messages
 .TE
 .TP
+.BI \-\-disable-netlink
+Do not use netlink and fall back to the ioctl interface if possible.
+.TP
 .BI \-\-json
 Output results in JavaScript Object Notation (JSON). Only a subset of
 options support this. Those which do not will continue to output
@@ -575,6 +604,23 @@ plain text in the presence of this option.
 Include command-related statistics in the output. This option allows
 displaying relevant device statistics for selected get commands.
 .TP
+.BI \-\-phy \ N
+Target a PHY within the interface. The PHY index can be retrieved with
+.B \-\-show\-phys. PHY index 0 targets the phy device directly attached to
+the ethernet MAC, if any.
+The following commands can accept a PHY index:
+.TS
+nokeep;
+lB	l.
+\-\-cable\-test
+\-\-cable\-test\-tdr
+\-\-get\-plca\-cfg
+\-\-set\-plca\-cfg
+\-\-get\-plca\-status
+\-\-show-pse
+\-\-set-pse
+.TE
+.TP
 .B \-a \-\-show\-pause
 Queries the specified Ethernet device for pause parameter information.
 .RS 4
@@ -629,6 +675,9 @@ Changes the number of ring entries for the Tx ring.
 .BI rx\-buf\-len \ N
 Changes the size of a buffer in the Rx ring.
 .TP
+.BI tcp\-data\-split \ auto|on|off
+Specifies the state of TCP data split.
+.TP
 .BI cqe\-size \ N
 Changes the size of completion queue event.
 .TP
@@ -843,6 +892,7 @@ lB	l	lB.
 0x8000000000000000000000000	10baseT1S Full
 0x10000000000000000000000000	10baseT1S Half
 0x20000000000000000000000000	10baseT1S_P2MP Half
+0x40000000000000000000000000	10baseT1BRR Full
 0x004	100baseT Half
 0x008	100baseT Full
 0x80000000000000000	100baseT1 Full
@@ -1150,6 +1200,10 @@ Specifies the RSS context to spread packets over multiple queues; either
 for the default RSS context, or a value returned by
 .BI ethtool\ -X\  ... \ context
 .BR new .
+If combined with
+.BR action \ or\  queue ,
+the Rx queue specified will be added to the value read from the RSS indirection
+table to produce the actual Rx queue to deliver to.
 .TP
 .BI vf \ N
 Specifies the Virtual Function the filter applies to. Not compatible with action.
@@ -1197,6 +1251,19 @@ even if a nibble is zero.
 Sets RSS hash function of the specified network device.
 List of RSS hash functions which kernel supports is shown as a part of the --show-rxfh command output.
 .TP
+.BI xfrm
+Sets the RSS input transformation. Currently, only the
+.B symmetric-xor
+transformation is supported where the NIC XORs the L3 and/or L4 source and
+destination fields (as selected by
+.B --config-nfc rx-flow-hash
+) before passing them to the hash algorithm. The RSS hash function will
+then yield the same hash for the other flow direction where the source and
+destination fields are swapped (i.e. Symmetric RSS). Note that XORing the
+input parameters reduces the entropy of the input set and the hash algorithm
+could potentially be exploited. Switch off (default) by
+.B xfrm none.
+.TP
 .BI start\  N
 For the \fBequal\fR and \fBweight\fR options, sets the starting receive queue
 for spreading flows to \fIN\fR.
@@ -1738,7 +1805,51 @@ status depend on internal PSE state machine and automatic PD classification
 support. It corresponds to IEEE 802.3-2018 30.15.1.1.3
 (aPoDLPSEPowerDetectionStatus) with potential values being
 .B disabled, searching, delivering power, sleep, idle, error
-.RE
+.TP
+.B c33-pse-admin-state
+This attribute indicates the operational status of c33 PSE functions, which
+can be modified using the
+.B c33-pse-admin-control
+parameter. It corresponds to IEEE 802.3-2022 30.9.1.1.2 (aPSEAdminState),
+with potential values being
+.B enabled, disabled
+.TP
+.B c33-pse-power-detection-status
+This attribute indicates the power detection status of the c33 PSE. The
+status depend on internal PSE state machine and automatic PD classification
+support. It corresponds to IEEE 802.3-2022 30.9.1.1.5
+(aPSEPowerDetectionStatus) with potential values being
+.B disabled, searching, delivering power, test, fault, other fault
+.TP
+.B c33-pse-extended-state
+This attribute indicates the Extended state of the c33 PSE. The extended
+state correlated with the c33 PSE Extended Substate allows to have more
+detail on the c33 PSE current error state.
+It corresponds to IEEE 802.3-2022 33.2.4.4 Variables.
+.TP
+.B c33-pse-extended-substate
+This attribute indicates the Extended substate of the c33 PSE. Correlated
+with the c33 PSE Extended state value, it allows to have more detail on the
+c33 PSE current error state.
+.TP
+.B c33-pse-power-class
+This attribute identifies the power class of the c33 PSE. It depends on
+the class negotiated between the PSE and the PD. It corresponds to
+IEEE 802.3-2022 30.9.1.1.8 (aPSEPowerClassification).
+.TP
+.B c33-pse-actual-power
+This attribute identifies the actual power drawn by the c33 PSE. It
+corresponds to ``IEEE 802.3-2022`` 30.9.1.1.23 (aPSEActualPower). Actual
+power is reported in mW.
+.TP
+.B c33-pse-available-power-limit
+This attribute identifies the configured c33 PSE power limit in mW.
+.TP
+.B c33-pse-power-limit-ranges
+This attribute specifies the allowed power limit ranges in mW for
+configuring the c33-pse-avail-pw-limit parameter. It defines the valid
+power levels that can be assigned to the c33 PSE in compliance with the
+c33 standard.
 
 .RE
 .TP
@@ -1749,6 +1860,70 @@ Set Power Sourcing Equipment (PSE) parameters.
 .A2 podl-pse-admin-control \ enable disable
 This parameter manages PoDL PSE Admin operations in accordance with the IEEE
 802.3-2018 30.15.1.2.1 (acPoDLPSEAdminControl) specification.
+.TP
+.A2 c33-pse-admin-control \ enable disable
+This parameter manages c33 PSE Admin operations in accordance with the IEEE
+802.3-2022 30.9.1.2.1 (acPSEAdminControl) specification.
+.TP
+.B c33-pse-avail-pw-limit \ N
+This parameter manages c33 PSE Available Power Limit in mW, in accordance
+with the IEEE 802.3-2022 33.2.4.4 Variables (pse_available_power)
+specification.
+
+.RE
+.TP
+.B \-\-flash\-module\-firmware
+Flash the transceiver module's firmware. The firmware update process is
+composed from three logical steps. Downloading a firmware image to the
+transceiver module, running the image and committing the image so that it is
+run upon reset. When flash command is given, the firmware update process is
+performed in its entirety in that order.
+.RS 4
+.TP
+.BI file \ FILE
+Specifies the filename of the transceiver module firmware image. The firmware
+must first be installed in one of the directories where the kernel firmware
+loader or firmware agent will look, such as /lib/firmware. The firmware image
+is downloaded to the transceiver module, validated, run and committed.
+.RE
+.RS 4
+.TP
+.BI pass \ PASS
+Optional transceiver module password that might be required as part of the
+transceiver module firmware update process.
+
+.RE
+.TP
+.B \-\-show\-phys
+Show the PHY devices attached to an interface, and the way they link together.
+.RS 4
+.TP
+.B phy_index
+The PHY's index, that identifies it within the network interface. If the
+interface has multiple PHYs, they will each have a unique index on that
+interface. This index can then be used for commands that targets PHYs.
+.TP
+.B drvname
+The name of the driver bound to this PHY device.
+.TP
+.B name
+The PHY's device name, matching the name found in sysfs.
+.TP
+.B downstream_sfp_name
+If the PHY drives an SFP cage, this field contains the name of the associated
+SFP bus.
+.TP
+.B upstream_type \ mac | phy
+Indicates the nature of the device the PHY is attached to.
+.TP
+.B upstream_index
+If the PHY's upstream_type is
+.B phy
+, this field indicates the phy_index of the upstream phy.
+.TP
+.B upstream_sfp_name
+If the PHY is withing an SFP/SFF module, this field contains the name of the
+upstream SFP bus.
 
 .SH BUGS
 Not supported (in part or whole) on all network drivers.
diff --git a/ethtool.c b/ethtool.c
index af51220..a1393bc 100644
--- a/ethtool.c
+++ b/ethtool.c
@@ -70,6 +70,18 @@ static void exit_bad_args(void)
 	exit(1);
 }
 
+static void exit_bad_args_info(const char *info) __attribute__((noreturn));
+
+static void exit_bad_args_info(const char *info)
+{
+	fprintf(stderr,
+		"ethtool: bad command line argument(s)\n"
+		"%s\n"
+		"For more information run ethtool -h\n",
+		info);
+	exit(1);
+}
+
 static void exit_nlonly_param(const char *name) __attribute__((noreturn));
 
 static void exit_nlonly_param(const char *name)
@@ -360,6 +372,18 @@ static int rxflow_str_to_type(const char *str)
 		flow_type = AH_ESP_V4_FLOW;
 	else if (!strcmp(str, "sctp4"))
 		flow_type = SCTP_V4_FLOW;
+	else if (!strcmp(str, "gtpc4"))
+		flow_type = GTPC_V4_FLOW;
+	else if (!strcmp(str, "gtpc4t"))
+		flow_type = GTPC_TEID_V4_FLOW;
+	else if (!strcmp(str, "gtpu4"))
+		flow_type = GTPU_V4_FLOW;
+	else if (!strcmp(str, "gtpu4e"))
+		flow_type = GTPU_EH_V4_FLOW;
+	else if (!strcmp(str, "gtpu4u"))
+		flow_type = GTPU_UL_V4_FLOW;
+	else if (!strcmp(str, "gtpu4d"))
+		flow_type = GTPU_DL_V4_FLOW;
 	else if (!strcmp(str, "tcp6"))
 		flow_type = TCP_V6_FLOW;
 	else if (!strcmp(str, "udp6"))
@@ -370,6 +394,18 @@ static int rxflow_str_to_type(const char *str)
 		flow_type = SCTP_V6_FLOW;
 	else if (!strcmp(str, "ether"))
 		flow_type = ETHER_FLOW;
+	else if (!strcmp(str, "gtpc6"))
+		flow_type = GTPC_V6_FLOW;
+	else if (!strcmp(str, "gtpc6t"))
+		flow_type = GTPC_TEID_V6_FLOW;
+	else if (!strcmp(str, "gtpu6"))
+		flow_type = GTPU_V6_FLOW;
+	else if (!strcmp(str, "gtpu6e"))
+		flow_type = GTPU_EH_V6_FLOW;
+	else if (!strcmp(str, "gtpu6u"))
+		flow_type = GTPU_UL_V6_FLOW;
+	else if (!strcmp(str, "gtpu6d"))
+		flow_type = GTPU_DL_V6_FLOW;
 
 	return flow_type;
 }
@@ -483,6 +519,7 @@ static void init_global_link_mode_masks(void)
 		ETHTOOL_LINK_MODE_10baseT1S_Full_BIT,
 		ETHTOOL_LINK_MODE_10baseT1S_Half_BIT,
 		ETHTOOL_LINK_MODE_10baseT1S_P2MP_Half_BIT,
+		ETHTOOL_LINK_MODE_10baseT1BRR_Full_BIT,
 	};
 	static const enum ethtool_link_mode_bit_indices
 		additional_advertised_flags_bits[] = {
@@ -743,6 +780,8 @@ static void dump_link_caps(const char *prefix, const char *an_prefix,
 		  "10baseT1S/Half" },
 		{ 0, ETHTOOL_LINK_MODE_10baseT1S_P2MP_Half_BIT,
 		  "10baseT1S/Half" },
+		{ 0, ETHTOOL_LINK_MODE_10baseT1BRR_Full_BIT,
+		  "10baseT1BRR/Full" },
 	};
 	int indent;
 	int did1, new_line_pend;
@@ -1010,6 +1049,9 @@ static int parse_rxfhashopts(char *optstr, u32 *data)
 		case 'n':
 			*data |= RXH_L4_B_2_3;
 			break;
+		case 'e':
+			*data |= RXH_GTP_TEID;
+			break;
 		case 'r':
 			*data |= RXH_DISCARD;
 			break;
@@ -1042,6 +1084,8 @@ static char *unparse_rxfhashopts(u64 opts)
 			strcat(buf, "L4 bytes 0 & 1 [TCP/UDP src port]\n");
 		if (opts & RXH_L4_B_2_3)
 			strcat(buf, "L4 bytes 2 & 3 [TCP/UDP dst port]\n");
+		if (opts & RXH_GTP_TEID)
+			strcat(buf, "GTP TEID\n");
 	} else {
 		sprintf(buf, "None");
 	}
@@ -1559,6 +1603,24 @@ static int dump_rxfhash(int fhash, u64 val)
 	case SCTP_V4_FLOW:
 		fprintf(stdout, "SCTP over IPV4 flows");
 		break;
+	case GTPC_V4_FLOW:
+		fprintf(stdout, "GTP-C over IPV4 flows");
+		break;
+	case GTPC_TEID_V4_FLOW:
+		fprintf(stdout, "GTP-C (include TEID) over IPV4 flows");
+		break;
+	case GTPU_V4_FLOW:
+		fprintf(stdout, "GTP-U over IPV4 flows");
+		break;
+	case GTPU_EH_V4_FLOW:
+		fprintf(stdout, "GTP-U and Extension Header over IPV4 flows");
+		break;
+	case GTPU_UL_V4_FLOW:
+		fprintf(stdout, "GTP-U PSC Uplink over IPV4 flows");
+		break;
+	case GTPU_DL_V4_FLOW:
+		fprintf(stdout, "GTP-U PSC Downlink over IPV4 flows");
+		break;
 	case AH_ESP_V4_FLOW:
 	case AH_V4_FLOW:
 	case ESP_V4_FLOW:
@@ -1573,6 +1635,24 @@ static int dump_rxfhash(int fhash, u64 val)
 	case SCTP_V6_FLOW:
 		fprintf(stdout, "SCTP over IPV6 flows");
 		break;
+	case GTPC_V6_FLOW:
+		fprintf(stdout, "GTP-C over IPV6 flows");
+		break;
+	case GTPC_TEID_V6_FLOW:
+		fprintf(stdout, "GTP-C (include TEID) over IPV6 flows");
+		break;
+	case GTPU_V6_FLOW:
+		fprintf(stdout, "GTP-U over IPV6 flows");
+		break;
+	case GTPU_EH_V6_FLOW:
+		fprintf(stdout, "GTP-U and Extension Header over IPV6 flows");
+		break;
+	case GTPU_UL_V6_FLOW:
+		fprintf(stdout, "GTP-U PSC Uplink over IPV6 flows");
+		break;
+	case GTPU_DL_V6_FLOW:
+		fprintf(stdout, "GTP-U PSC Downlink over IPV6 flows");
+		break;
 	case AH_ESP_V6_FLOW:
 	case AH_V6_FLOW:
 	case ESP_V6_FLOW:
@@ -3803,8 +3883,10 @@ static int do_srxclass(struct cmd_context *ctx)
 			nfccmd.flow_type |= FLOW_RSS;
 
 		err = send_ioctl(ctx, &nfccmd);
-		if (err < 0)
+		if (err < 0) {
 			perror("Cannot change RX network flow hashing options");
+			return 1;
+		}
 	} else if (!strcmp(ctx->argp[0], "flow-type")) {
 		struct ethtool_rx_flow_spec rx_rule_fs;
 		__u32 rss_context = 0;
@@ -4029,6 +4111,10 @@ static int do_grxfh(struct cmd_context *ctx)
 		       (const char *)hfuncs->data + i * ETH_GSTRING_LEN,
 		       (rss->hfunc & (1 << i)) ? "on" : "off");
 
+	printf("RSS input transformation:\n");
+	printf("    symmetric-xor: %s\n",
+	       (rss->input_xfrm & RXH_XFRM_SYM_XOR) ? "on" : "off");
+
 out:
 	free(hfuncs);
 	free(rss);
@@ -4146,6 +4232,7 @@ static int do_srxfh(struct cmd_context *ctx)
 	u32 arg_num = 0, indir_bytes = 0;
 	u32 req_hfunc = 0;
 	u32 entry_size = sizeof(rss_head.rss_config[0]);
+	u32 req_input_xfrm = 0xff;
 	u32 num_weights = 0;
 	u32 rss_context = 0;
 	int delete = 0;
@@ -4189,8 +4276,21 @@ static int do_srxfh(struct cmd_context *ctx)
 			if (!req_hfunc_name)
 				exit_bad_args();
 			++arg_num;
+		} else if (!strcmp(ctx->argp[arg_num], "xfrm")) {
+			++arg_num;
+			if (!ctx->argp[arg_num])
+				exit_bad_args();
+			if (!strcmp(ctx->argp[arg_num], "symmetric-xor"))
+				req_input_xfrm = RXH_XFRM_SYM_XOR;
+			else if (!strcmp(ctx->argp[arg_num], "none"))
+				req_input_xfrm = 0;
+			else
+				exit_bad_args();
+			++arg_num;
 		} else if (!strcmp(ctx->argp[arg_num], "context")) {
 			++arg_num;
+			if (!ctx->argp[arg_num])
+				exit_bad_args();
 			if(!strcmp(ctx->argp[arg_num], "new"))
 				rss_context = ETH_RXFH_CONTEXT_ALLOC;
 			else
@@ -4333,6 +4433,7 @@ static int do_srxfh(struct cmd_context *ctx)
 	rss->cmd = ETHTOOL_SRSSH;
 	rss->rss_context = rss_context;
 	rss->hfunc = req_hfunc;
+	rss->input_xfrm = req_input_xfrm;
 	if (delete) {
 		rss->indir_size = rss->key_size = 0;
 	} else {
@@ -5640,6 +5741,7 @@ struct option {
 	const char	*opts;
 	bool		no_dev;
 	bool		json;
+	bool		targets_phy;
 	int		(*func)(struct cmd_context *);
 	nl_chk_t	nlchk;
 	nl_func_t	nlfunc;
@@ -5651,6 +5753,7 @@ static const struct option args[] = {
 	{
 		/* "default" entry when no switch is used */
 		.opts	= "",
+		.json	= true,
 		.func	= do_gset,
 		.nlfunc	= nl_gset,
 		.help	= "Display standard information about device",
@@ -5748,6 +5851,7 @@ static const struct option args[] = {
 			  "		[ rx-jumbo N ]\n"
 			  "		[ tx N ]\n"
 			  "		[ rx-buf-len N ]\n"
+			  "		[ tcp-data-split auto|on|off ]\n"
 			  "		[ cqe-size N ]\n"
 			  "		[ tx-push on|off ]\n"
 			  "		[ rx-push on|off ]\n"
@@ -5833,7 +5937,8 @@ static const struct option args[] = {
 		.func	= do_grxclass,
 		.help	= "Show Rx network flow classification options or rules",
 		.xhelp	= "		[ rx-flow-hash tcp4|udp4|ah4|esp4|sctp4|"
-			  "tcp6|udp6|ah6|esp6|sctp6 [context %d] |\n"
+			  "gtpc4|gtpc4t|gtpu4|gtpu4e|gtpu4u|gtpu4d|tcp6|udp6|ah6|esp6|sctp6|"
+			  "gtpc6|gtpc6t|gtpu6|gtpu6e|gtpu6u|gtpu6d [context %d] |\n"
 			  "		  rule %d ]\n"
 	},
 	{
@@ -5841,7 +5946,8 @@ static const struct option args[] = {
 		.func	= do_srxclass,
 		.help	= "Configure Rx network flow classification options or rules",
 		.xhelp	= "		rx-flow-hash tcp4|udp4|ah4|esp4|sctp4|"
-			  "tcp6|udp6|ah6|esp6|sctp6 m|v|t|s|d|f|n|r... [context %d] |\n"
+			  "gtpc4|gtpc4t|gtpu4|gtpu4e|gtpu4u|gtpu4d|tcp6|udp6|ah6|esp6|sctp6"
+			  "|gtpc6|gtpc6t|gtpu6|gtpu6e|gtpu6u|gtpu6d m|v|t|s|d|f|n|r|e... [context %d] |\n"
 			  "		flow-type ether|ip4|tcp4|udp4|sctp4|ah4|esp4|"
 			  "ip6|tcp6|udp6|ah6|esp6|sctp6\n"
 			  "			[ src %x:%x:%x:%x:%x:%x [m %x:%x:%x:%x:%x:%x] ]\n"
@@ -5886,6 +5992,7 @@ static const struct option args[] = {
 			  "		[ equal N | weight W0 W1 ... | default ]\n"
 			  "		[ hkey %x:%x:%x:%x:%x:.... ]\n"
 			  "		[ hfunc FUNC ]\n"
+			  "		[ xfrm symmetric-xor|none ]\n"
 			  "		[ delete ]\n"
 	},
 	{
@@ -5956,6 +6063,7 @@ static const struct option args[] = {
 	},
 	{
 		.opts	= "--show-eee",
+		.json	= true,
 		.func	= do_geee,
 		.nlfunc	= nl_geee,
 		.help	= "Show EEE settings",
@@ -6053,12 +6161,14 @@ static const struct option args[] = {
 	},
 	{
 		.opts	= "--cable-test",
+		.targets_phy	= true,
 		.json	= true,
 		.nlfunc	= nl_cable_test,
 		.help	= "Perform a cable test",
 	},
 	{
 		.opts	= "--cable-test-tdr",
+		.targets_phy	= true,
 		.json	= true,
 		.nlfunc	= nl_cable_test_tdr,
 		.help	= "Print cable test time domain reflectrometery data",
@@ -6086,11 +6196,13 @@ static const struct option args[] = {
 	},
 	{
 		.opts	= "--get-plca-cfg",
+		.targets_phy	= true,
 		.nlfunc	= nl_plca_get_cfg,
 		.help	= "Get PLCA configuration",
 	},
 	{
 		.opts	= "--set-plca-cfg",
+		.targets_phy	= true,
 		.nlfunc	= nl_plca_set_cfg,
 		.help	= "Set PLCA configuration",
 		.xhelp  = "		[ enable on|off ]\n"
@@ -6102,6 +6214,7 @@ static const struct option args[] = {
 	},
 	{
 		.opts	= "--get-plca-status",
+		.targets_phy	= true,
 		.nlfunc	= nl_plca_get_status,
 		.help	= "Get PLCA status information",
 	},
@@ -6123,15 +6236,31 @@ static const struct option args[] = {
 	},
 	{
 		.opts	= "--show-pse",
+		.targets_phy	= true,
 		.json	= true,
 		.nlfunc	= nl_gpse,
 		.help	= "Show settings for Power Sourcing Equipment",
 	},
 	{
 		.opts	= "--set-pse",
+		.targets_phy	= true,
 		.nlfunc	= nl_spse,
 		.help	= "Set Power Sourcing Equipment settings",
 		.xhelp	= "		[ podl-pse-admin-control enable|disable ]\n"
+			  "		[ c33-pse-admin-control enable|disable ]\n"
+			  "		[ c33-pse-avail-pw-limit N ]\n"
+	},
+	{
+		.opts	= "--flash-module-firmware",
+		.nlfunc	= nl_flash_module_fw,
+		.help	= "Flash transceiver module firmware",
+		.xhelp	= "		file FILE\n"
+			  "		[ pass PASS ]\n"
+	},
+	{
+		.opts	= "--show-phys",
+		.nlfunc	= nl_get_phy,
+		.help	= "List PHYs"
 	},
 	{
 		.opts	= "-h|--help",
@@ -6157,7 +6286,8 @@ static int show_usage(struct cmd_context *ctx __maybe_unused)
 	fprintf(stdout,	"Usage:\n");
 	for (i = 0; args[i].opts; i++) {
 		fputs("        ethtool [ FLAGS ] ", stdout);
-		fprintf(stdout, "%s %s\t%s\n",
+		fprintf(stdout, "%s%s %s\t%s\n",
+			args[i].targets_phy ? "[ --phy PHY ] " : "",
 			args[i].opts,
 			args[i].no_dev ? "\t" : "DEVNAME",
 			args[i].help);
@@ -6367,7 +6497,7 @@ static int do_perqueue(struct cmd_context *ctx)
 	return 0;
 }
 
-static int ioctl_init(struct cmd_context *ctx, bool no_dev)
+int ioctl_init(struct cmd_context *ctx, bool no_dev)
 {
 	if (no_dev) {
 		ctx->fd = -1;
@@ -6424,6 +6554,12 @@ int main(int argc, char **argp)
 			argc -= 2;
 			continue;
 		}
+		if (*argp && !strcmp(*argp, "--disable-netlink")) {
+			ctx.nl_disable = true;
+			argp += 1;
+			argc -= 1;
+			continue;
+		}
 		if (*argp && !strcmp(*argp, "--json")) {
 			ctx.json = true;
 			argp += 1;
@@ -6437,6 +6573,19 @@ int main(int argc, char **argp)
 			argc -= 1;
 			continue;
 		}
+		if (*argp && !strcmp(*argp, "--phy")) {
+			char *eptr;
+
+			if (argc < 2)
+				exit_bad_args_info("--phy parameters expects a phy index");
+
+			ctx.phy_index = strtoul(argp[1], &eptr, 0);
+			if (!argp[1][0] || *eptr)
+				exit_bad_args_info("invalid phy index");
+			argp += 2;
+			argc -= 2;
+			continue;
+		}
 		break;
 	}
 	if (*argp && !strcmp(*argp, "--monitor")) {
@@ -6471,13 +6620,17 @@ int main(int argc, char **argp)
 			exit_bad_args();
 	}
 	if (ctx.json && !args[k].json)
-		exit_bad_args();
+		exit_bad_args_info("JSON output not available for this subcommand");
+
+	if (!args[k].targets_phy && ctx.phy_index)
+		exit_bad_args_info("Unexpected --phy parameter");
+
 	ctx.argc = argc;
 	ctx.argp = argp;
 	netlink_run_handler(&ctx, args[k].nlchk, args[k].nlfunc, !args[k].func);
 
 	if (ctx.json) /* no IOCTL command supports JSON output */
-		exit_bad_args();
+		exit_nlonly_param("--json");
 
 	ret = ioctl_init(&ctx, args[k].no_dev);
 	if (ret)
diff --git a/internal.h b/internal.h
index 4b994f5..f33539d 100644
--- a/internal.h
+++ b/internal.h
@@ -221,7 +221,9 @@ struct cmd_context {
 	char **argp;		/* arguments to the sub-command */
 	unsigned long debug;	/* debugging mask */
 	bool json;		/* Output JSON, if supported */
+	bool nl_disable;	/* Disable netlink even if available */
 	bool show_stats;	/* include command-specific stats */
+	uint32_t phy_index;	/* the phy index this command targets */
 #ifdef ETHTOOL_ENABLE_NETLINK
 	struct nl_context *nlctx;	/* netlink context (opaque) */
 #endif
@@ -280,6 +282,7 @@ int test_fclose(FILE *fh);
 #endif
 #endif
 
+int ioctl_init(struct cmd_context *ctx, bool no_dev);
 int send_ioctl(struct cmd_context *ctx, void *cmd);
 
 void dump_hex(FILE *f, const u8 *data, int len, int offset);
diff --git a/libmnl/README b/libmnl/README
index fbac9d2..4a2ccab 100644
--- a/libmnl/README
+++ b/libmnl/README
@@ -18,11 +18,29 @@ on top of this library.
 is reduced, i.e. the library provides many helpers, but the programmer is not
 forced to use them.
 
+= Documentation =
+
+If doxygen is installed on your system, you can enable it via:
+
+       ./configure --with-doxygen=yes
+
+then type `make`.
+
+To access the doxygen documentation, open the doxygen/html/index.html file with
+a web browser.
+
 = Example files =
 
 You can find several example files under examples/ that you can compile by
 invoking `make check'.
 
+= Contributing =
+
+Please submit any patches to <netfilter-devel@vger.kernel.org>.
+
+The contributions should broadly follow the Linux Kernel process, as detailed
+in https://www.kernel.org/doc/html/latest/process/submitting-patches.html
+
 --
 08/sep/2010
 Pablo Neira Ayuso <pablo@netfilter.org>
diff --git a/libmnl/config.h b/libmnl/config.h
index f7c60e2..6a0fc45 100644
--- a/libmnl/config.h
+++ b/libmnl/config.h
@@ -1 +1,12 @@
+#define HAVE_DLFCN_H 1
+#define HAVE_INTTYPES_H 1
+#define HAVE_STDINT_H 1
+#define HAVE_STDIO_H 1
+#define HAVE_STDLIB_H 1
+#define HAVE_STRINGS_H 1
+#define HAVE_STRING_H 1
+#define HAVE_SYS_STAT_H 1
+#define HAVE_SYS_TYPES_H 1
+#define HAVE_UNISTD_H 1
 #define HAVE_VISIBILITY_HIDDEN 1
+#define STDC_HEADERS 1
diff --git a/libmnl/configure.ac b/libmnl/configure.ac
index 4698aec..9305766 100644
--- a/libmnl/configure.ac
+++ b/libmnl/configure.ac
@@ -45,7 +45,7 @@ AC_CONFIG_FILES([Makefile
 
 AC_ARG_WITH([doxygen], [AS_HELP_STRING([--with-doxygen],
 	    [create doxygen documentation])],
-	    [with_doxygen="$withval"], [with_doxygen=yes])
+	    [with_doxygen="$withval"], [with_doxygen=no])
 
 AS_IF([test "x$with_doxygen" != xno], [
 	AC_CHECK_PROGS([DOXYGEN], [doxygen])
diff --git a/libmnl/doxygen/doxygen.cfg.in b/libmnl/doxygen/doxygen.cfg.in
index 24089ac..1c73f51 100644
--- a/libmnl/doxygen/doxygen.cfg.in
+++ b/libmnl/doxygen/doxygen.cfg.in
@@ -9,7 +9,7 @@ OPTIMIZE_OUTPUT_FOR_C  = YES
 INPUT                  = @top_srcdir@
 FILE_PATTERNS          = */src/*.c
 RECURSIVE              = YES
-EXCLUDE_SYMBOLS        = EXPORT_SYMBOL mnl_nlmsg_batch mnl_socket
+EXCLUDE_SYMBOLS        = mnl_nlmsg_batch mnl_socket nstats
 EXAMPLE_PATTERNS       =
 INPUT_FILTER           = "sed 's/EXPORT_SYMBOL//g'"
 SOURCE_BROWSER         = YES
@@ -20,4 +20,3 @@ LATEX_CMD_NAME         = latex
 GENERATE_MAN           = YES
 MAN_LINKS              = YES
 HAVE_DOT               = @HAVE_DOT@
-DOT_TRANSPARENT        = YES
diff --git a/libmnl/include/libmnl/libmnl.h b/libmnl/include/libmnl/libmnl.h
index 4bd0b92..9c03280 100644
--- a/libmnl/include/libmnl/libmnl.h
+++ b/libmnl/include/libmnl/libmnl.h
@@ -92,6 +92,7 @@ extern uint8_t mnl_attr_get_u8(const struct nlattr *attr);
 extern uint16_t mnl_attr_get_u16(const struct nlattr *attr);
 extern uint32_t mnl_attr_get_u32(const struct nlattr *attr);
 extern uint64_t mnl_attr_get_u64(const struct nlattr *attr);
+extern uint64_t mnl_attr_get_uint(const struct nlattr *attr);
 extern const char *mnl_attr_get_str(const struct nlattr *attr);
 
 /* TLV attribute putters */
diff --git a/libmnl/src/attr.c b/libmnl/src/attr.c
index bc39df4..20e99b1 100644
--- a/libmnl/src/attr.c
+++ b/libmnl/src/attr.c
@@ -389,6 +389,45 @@ EXPORT_SYMBOL uint64_t mnl_attr_get_u64(const struct nlattr *attr)
 	return tmp;
 }
 
+/**
+ * mnl_attr_get_uint - returns 64-bit unsigned integer attribute.
+ * \param attr pointer to netlink attribute
+ *
+ * This helper function reads the variable-length netlink attribute NLA_UINT
+ * that provides a 32-bit or 64-bit integer payload. Its use is recommended only
+ * in these cases.
+ *
+ * Recommended validation for NLA_UINT is:
+ *
+ * \verbatim
+	if (!mnl_attr_validate(attr, NLA_U32) &&
+	    !mnl_attr_validate(attr, NLA_U64)) {
+		perror("mnl_attr_validate");
+		return MNL_CB_ERROR;
+	}
+\endverbatim
+ *
+ * \returns the 64-bit value of the attribute payload. On error, it returns
+ * UINT64_MAX if the length of the netlink attribute is not an 8-bit, 16-bit,
+ * 32-bit and 64-bit integer. Therefore, there is no way to distinguish between
+ * UINT64_MAX and an error. Also, errno is never set.
+ */
+EXPORT_SYMBOL uint64_t mnl_attr_get_uint(const struct nlattr *attr)
+{
+	switch (mnl_attr_get_payload_len(attr)) {
+	case sizeof(uint8_t):
+		return mnl_attr_get_u8(attr);
+	case sizeof(uint16_t):
+		return mnl_attr_get_u16(attr);
+	case sizeof(uint32_t):
+		return mnl_attr_get_u32(attr);
+	case sizeof(uint64_t):
+		return mnl_attr_get_u64(attr);
+	}
+
+	return -1ULL;
+}
+
 /**
  * mnl_attr_get_str - get pointer to string attribute
  * \param attr pointer to netlink attribute
diff --git a/libmnl/src/callback.c b/libmnl/src/callback.c
index f5349c3..703ae80 100644
--- a/libmnl/src/callback.c
+++ b/libmnl/src/callback.c
@@ -21,7 +21,7 @@ static int mnl_cb_error(const struct nlmsghdr *nlh, void *data)
 	const struct nlmsgerr *err = mnl_nlmsg_get_payload(nlh);
 
 	if (nlh->nlmsg_len < mnl_nlmsg_size(sizeof(struct nlmsgerr))) {
-		errno = EBADMSG; 
+		errno = EBADMSG;
 		return MNL_CB_ERROR;
 	}
 	/* Netlink subsystems returns the errno value with different signess */
@@ -73,7 +73,7 @@ static inline int __mnl_cb_run(const void *buf, size_t numbytes,
 		}
 
 		/* netlink data message handling */
-		if (nlh->nlmsg_type >= NLMSG_MIN_TYPE) { 
+		if (nlh->nlmsg_type >= NLMSG_MIN_TYPE) {
 			if (cb_data){
 				ret = cb_data(nlh, data);
 				if (ret <= MNL_CB_STOP)
diff --git a/libmnl/src/libmnl.map b/libmnl/src/libmnl.map
index e5920e5..cd58863 100644
--- a/libmnl/src/libmnl.map
+++ b/libmnl/src/libmnl.map
@@ -77,3 +77,7 @@ LIBMNL_1.2 {
   mnl_socket_open2;
   mnl_socket_fdopen;
 } LIBMNL_1.1;
+
+LIBMNL_1.3 {
+  mnl_attr_get_uint;
+} LIBMNL_1.2;
diff --git a/libmnl/src/nlmsg.c b/libmnl/src/nlmsg.c
index c634501..30a7e63 100644
--- a/libmnl/src/nlmsg.c
+++ b/libmnl/src/nlmsg.c
@@ -152,9 +152,14 @@ EXPORT_SYMBOL void *mnl_nlmsg_get_payload_offset(const struct nlmsghdr *nlh,
  */
 EXPORT_SYMBOL bool mnl_nlmsg_ok(const struct nlmsghdr *nlh, int len)
 {
-	return len >= (int)sizeof(struct nlmsghdr) &&
+	size_t ulen = len;
+
+	if (len < 0)
+		return false;
+
+	return ulen           >= sizeof(struct nlmsghdr) &&
 	       nlh->nlmsg_len >= sizeof(struct nlmsghdr) &&
-	       (int)nlh->nlmsg_len <= len;
+	       nlh->nlmsg_len <= ulen;
 }
 
 /**
diff --git a/libmnl/src/socket.c b/libmnl/src/socket.c
index 85b6bcc..60ba2cd 100644
--- a/libmnl/src/socket.c
+++ b/libmnl/src/socket.c
@@ -206,7 +206,7 @@ EXPORT_SYMBOL int mnl_socket_bind(struct mnl_socket *nl, unsigned int groups,
 
 	addr_len = sizeof(nl->addr);
 	ret = getsockname(nl->fd, (struct sockaddr *) &nl->addr, &addr_len);
-	if (ret < 0)	
+	if (ret < 0)
 		return ret;
 
 	if (addr_len != sizeof(nl->addr)) {
@@ -226,7 +226,7 @@ EXPORT_SYMBOL int mnl_socket_bind(struct mnl_socket *nl, unsigned int groups,
  * \param buf buffer containing the netlink message to be sent
  * \param len number of bytes in the buffer that you want to send
  *
- * On error, it returns -1 and errno is appropriately set. Otherwise, it 
+ * On error, it returns -1 and errno is appropriately set. Otherwise, it
  * returns the number of bytes sent.
  */
 EXPORT_SYMBOL ssize_t mnl_socket_sendto(const struct mnl_socket *nl,
@@ -235,7 +235,7 @@ EXPORT_SYMBOL ssize_t mnl_socket_sendto(const struct mnl_socket *nl,
 	static const struct sockaddr_nl snl = {
 		.nl_family = AF_NETLINK
 	};
-	return sendto(nl->fd, buf, len, 0, 
+	return sendto(nl->fd, buf, len, 0,
 		      (struct sockaddr *) &snl, sizeof(snl));
 }
 
diff --git a/netlink/cable_test.c b/netlink/cable_test.c
index 9305a47..fdb046e 100644
--- a/netlink/cable_test.c
+++ b/netlink/cable_test.c
@@ -18,7 +18,7 @@ struct cable_test_context {
 };
 
 static int nl_get_cable_test_result(const struct nlattr *nest, uint8_t *pair,
-				    uint16_t *code)
+				    uint16_t *code, uint32_t *src)
 {
 	const struct nlattr *tb[ETHTOOL_A_CABLE_RESULT_MAX+1] = {};
 	DECLARE_ATTR_TB_INFO(tb);
@@ -32,12 +32,15 @@ static int nl_get_cable_test_result(const struct nlattr *nest, uint8_t *pair,
 
 	*pair = mnl_attr_get_u8(tb[ETHTOOL_A_CABLE_RESULT_PAIR]);
 	*code = mnl_attr_get_u8(tb[ETHTOOL_A_CABLE_RESULT_CODE]);
+	if (tb[ETHTOOL_A_CABLE_RESULT_SRC])
+		*src = mnl_attr_get_u32(tb[ETHTOOL_A_CABLE_RESULT_SRC]);
 
 	return 0;
 }
 
 static int nl_get_cable_test_fault_length(const struct nlattr *nest,
-					  uint8_t *pair, unsigned int *cm)
+					  uint8_t *pair, unsigned int *cm,
+					  uint32_t *src)
 {
 	const struct nlattr *tb[ETHTOOL_A_CABLE_FAULT_LENGTH_MAX+1] = {};
 	DECLARE_ATTR_TB_INFO(tb);
@@ -51,6 +54,8 @@ static int nl_get_cable_test_fault_length(const struct nlattr *nest,
 
 	*pair = mnl_attr_get_u8(tb[ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR]);
 	*cm = mnl_attr_get_u32(tb[ETHTOOL_A_CABLE_FAULT_LENGTH_CM]);
+	if (tb[ETHTOOL_A_CABLE_FAULT_LENGTH_SRC])
+		*src = mnl_attr_get_u32(tb[ETHTOOL_A_CABLE_FAULT_LENGTH_SRC]);
 
 	return 0;
 }
@@ -88,33 +93,54 @@ static char *nl_pair2txt(uint8_t pair)
 	}
 }
 
+static char *nl_src2txt(uint32_t src)
+{
+	switch (src) {
+	case ETHTOOL_A_CABLE_INF_SRC_TDR:
+		return "TDR";
+	case ETHTOOL_A_CABLE_INF_SRC_ALCD:
+		return "ALCD";
+	default:
+		return "Unknown";
+	}
+}
+
 static int nl_cable_test_ntf_attr(struct nlattr *evattr)
 {
 	unsigned int cm;
+	uint32_t src = UINT32_MAX;
 	uint16_t code;
 	uint8_t pair;
 	int ret;
 
 	switch (mnl_attr_get_type(evattr)) {
 	case ETHTOOL_A_CABLE_NEST_RESULT:
-		ret = nl_get_cable_test_result(evattr, &pair, &code);
+		ret = nl_get_cable_test_result(evattr, &pair, &code, &src);
 		if (ret < 0)
 			return ret;
 
 		open_json_object(NULL);
 		print_string(PRINT_ANY, "pair", "%s ", nl_pair2txt(pair));
-		print_string(PRINT_ANY, "code", "code %s\n", nl_code2txt(code));
+		print_string(PRINT_ANY, "code", "code %s", nl_code2txt(code));
+		if (src != UINT32_MAX)
+			print_string(PRINT_ANY, "src", ", source: %s",
+				     nl_src2txt(src));
+		print_nl();
 		close_json_object();
 		break;
 
 	case ETHTOOL_A_CABLE_NEST_FAULT_LENGTH:
-		ret = nl_get_cable_test_fault_length(evattr, &pair, &cm);
+		ret = nl_get_cable_test_fault_length(evattr, &pair, &cm, &src);
 		if (ret < 0)
 			return ret;
 		open_json_object(NULL);
 		print_string(PRINT_ANY, "pair", "%s, ", nl_pair2txt(pair));
-		print_float(PRINT_ANY, "length", "fault length: %0.2fm\n",
+		print_float(PRINT_ANY, "length", "fault length: %0.2fm",
 			    (float)cm / 100);
+		if (src != UINT32_MAX)
+			print_string(PRINT_ANY, "src", ", source: %s",
+				     nl_src2txt(src));
+		print_nl();
 		close_json_object();
 		break;
 	}
@@ -572,8 +598,8 @@ int nl_cable_test_tdr(struct cmd_context *ctx)
 	if (ret < 0)
 		return 2;
 
-	if (ethnla_fill_header(msgbuff, ETHTOOL_A_CABLE_TEST_TDR_HEADER,
-			       ctx->devname, 0))
+	if (ethnla_fill_header_phy(msgbuff, ETHTOOL_A_CABLE_TEST_TDR_HEADER,
+				   ctx->devname, ctx->phy_index, 0))
 		return -EMSGSIZE;
 
 	ret = nl_parser(nlctx, tdr_params, NULL, PARSER_GROUP_NEST, NULL);
diff --git a/netlink/coalesce.c b/netlink/coalesce.c
index bc34d3d..bc8b57b 100644
--- a/netlink/coalesce.c
+++ b/netlink/coalesce.c
@@ -39,9 +39,9 @@ int coalesce_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 		show_cr();
 	print_string(PRINT_ANY, "ifname", "Coalesce parameters for %s:\n",
 		     nlctx->devname);
-	show_bool("rx", "Adaptive RX: %s  ",
+	show_bool("adaptive-rx", "Adaptive RX: %s  ",
 		  tb[ETHTOOL_A_COALESCE_USE_ADAPTIVE_RX]);
-	show_bool("tx", "TX: %s\n", tb[ETHTOOL_A_COALESCE_USE_ADAPTIVE_TX]);
+	show_bool("adaptive-tx", "TX: %s\n", tb[ETHTOOL_A_COALESCE_USE_ADAPTIVE_TX]);
 	show_u32("stats-block-usecs", "stats-block-usecs:\t",
 		 tb[ETHTOOL_A_COALESCE_STATS_BLOCK_USECS]);
 	show_u32("sample-interval", "sample-interval:\t",
@@ -85,15 +85,15 @@ int coalesce_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 	show_u32("tx-frame-high", "tx-frame-high:\t",
 		 tb[ETHTOOL_A_COALESCE_TX_MAX_FRAMES_HIGH]);
 	show_cr();
-	show_bool("rx", "CQE mode RX: %s  ",
+	show_bool("cqe-mode-rx", "CQE mode RX: %s  ",
 		  tb[ETHTOOL_A_COALESCE_USE_CQE_MODE_RX]);
-	show_bool("tx", "TX: %s\n", tb[ETHTOOL_A_COALESCE_USE_CQE_MODE_TX]);
+	show_bool("cqe-mode-tx", "TX: %s\n", tb[ETHTOOL_A_COALESCE_USE_CQE_MODE_TX]);
 	show_cr();
 	show_u32("tx-aggr-max-bytes", "tx-aggr-max-bytes:\t",
 		 tb[ETHTOOL_A_COALESCE_TX_AGGR_MAX_BYTES]);
 	show_u32("tx-aggr-max-frames", "tx-aggr-max-frames:\t",
 		 tb[ETHTOOL_A_COALESCE_TX_AGGR_MAX_FRAMES]);
-	show_u32("tx-aggr-time-usecs", "tx-aggr-time-usecs\t",
+	show_u32("tx-aggr-time-usecs", "tx-aggr-time-usecs:\t",
 		 tb[ETHTOOL_A_COALESCE_TX_AGGR_TIME_USECS]);
 	show_cr();
 
diff --git a/netlink/desc-ethtool.c b/netlink/desc-ethtool.c
index 661de26..32a9eb3 100644
--- a/netlink/desc-ethtool.c
+++ b/netlink/desc-ethtool.c
@@ -252,12 +252,14 @@ static const struct pretty_nla_desc __cable_test_result_desc[] = {
 	NLATTR_DESC_INVALID(ETHTOOL_A_CABLE_RESULT_UNSPEC),
 	NLATTR_DESC_U8(ETHTOOL_A_CABLE_RESULT_PAIR),
 	NLATTR_DESC_U8(ETHTOOL_A_CABLE_RESULT_CODE),
+	NLATTR_DESC_U32(ETHTOOL_A_CABLE_RESULT_SRC),
 };
 
 static const struct pretty_nla_desc __cable_test_flength_desc[] = {
 	NLATTR_DESC_INVALID(ETHTOOL_A_CABLE_FAULT_LENGTH_UNSPEC),
 	NLATTR_DESC_U8(ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR),
 	NLATTR_DESC_U32(ETHTOOL_A_CABLE_FAULT_LENGTH_CM),
+	NLATTR_DESC_U32(ETHTOOL_A_CABLE_FAULT_LENGTH_SRC),
 };
 
 static const struct pretty_nla_desc __cable_nest_desc[] = {
@@ -496,6 +498,17 @@ static const struct pretty_nla_desc __mm_desc[] = {
 	NLATTR_DESC_NESTED(ETHTOOL_A_MM_STATS, mm_stat),
 };
 
+static const struct pretty_nla_desc __module_fw_flash_desc[] = {
+	NLATTR_DESC_INVALID(ETHTOOL_A_MODULE_FW_FLASH_UNSPEC),
+	NLATTR_DESC_NESTED(ETHTOOL_A_MODULE_FW_FLASH_HEADER, header),
+	NLATTR_DESC_STRING(ETHTOOL_A_MODULE_FW_FLASH_FILE_NAME),
+	NLATTR_DESC_U32(ETHTOOL_A_MODULE_FW_FLASH_PASSWORD),
+	NLATTR_DESC_U32(ETHTOOL_A_MODULE_FW_FLASH_STATUS),
+	NLATTR_DESC_STRING(ETHTOOL_A_MODULE_FW_FLASH_STATUS_MSG),
+	NLATTR_DESC_UINT(ETHTOOL_A_MODULE_FW_FLASH_DONE),
+	NLATTR_DESC_UINT(ETHTOOL_A_MODULE_FW_FLASH_TOTAL),
+};
+
 const struct pretty_nlmsg_desc ethnl_umsg_desc[] = {
 	NLMSG_DESC_INVALID(ETHTOOL_MSG_USER_NONE),
 	NLMSG_DESC(ETHTOOL_MSG_STRSET_GET, strset),
@@ -541,6 +554,7 @@ const struct pretty_nlmsg_desc ethnl_umsg_desc[] = {
 	NLMSG_DESC(ETHTOOL_MSG_PLCA_GET_STATUS, plca),
 	NLMSG_DESC(ETHTOOL_MSG_MM_GET, mm),
 	NLMSG_DESC(ETHTOOL_MSG_MM_SET, mm),
+	NLMSG_DESC(ETHTOOL_MSG_MODULE_FW_FLASH_ACT, module_fw_flash),
 };
 
 const unsigned int ethnl_umsg_n_desc = ARRAY_SIZE(ethnl_umsg_desc);
@@ -590,6 +604,7 @@ const struct pretty_nlmsg_desc ethnl_kmsg_desc[] = {
 	NLMSG_DESC(ETHTOOL_MSG_PLCA_NTF, plca),
 	NLMSG_DESC(ETHTOOL_MSG_MM_GET_REPLY, mm),
 	NLMSG_DESC(ETHTOOL_MSG_MM_NTF, mm),
+	NLMSG_DESC(ETHTOOL_MSG_MODULE_FW_FLASH_NTF, module_fw_flash),
 };
 
 const unsigned int ethnl_kmsg_n_desc = ARRAY_SIZE(ethnl_kmsg_desc);
diff --git a/netlink/eee.c b/netlink/eee.c
index 04d8f0b..51b9d10 100644
--- a/netlink/eee.c
+++ b/netlink/eee.c
@@ -14,6 +14,7 @@
 #include "netlink.h"
 #include "bitset.h"
 #include "parser.h"
+#include "../json_writer.h"
 
 /* EEE_GET */
 
@@ -21,13 +22,13 @@ int eee_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 {
 	const struct nlattr *tb[ETHTOOL_A_EEE_MAX + 1] = {};
 	DECLARE_ATTR_TB_INFO(tb);
-	bool enabled, active, tx_lpi_enabled;
+	bool enabled, active, tx_lpi_enabled, status_support;
 	struct nl_context *nlctx = data;
 	bool silent;
 	int err_ret;
 	int ret;
 
-	silent = nlctx->is_dump || nlctx->is_monitor;
+	silent = nlctx->is_dump || nlctx->is_monitor || is_json_context();
 	err_ret = silent ? MNL_CB_OK : MNL_CB_ERROR;
 	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
 	if (ret < 0)
@@ -46,42 +47,43 @@ int eee_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 	active = mnl_attr_get_u8(tb[ETHTOOL_A_EEE_ACTIVE]);
 	enabled = mnl_attr_get_u8(tb[ETHTOOL_A_EEE_ENABLED]);
 	tx_lpi_enabled = mnl_attr_get_u8(tb[ETHTOOL_A_EEE_TX_LPI_ENABLED]);
+	status_support = bitset_is_empty(tb[ETHTOOL_A_EEE_MODES_OURS], true, &ret);
 
 	if (silent)
 		putchar('\n');
-	printf("EEE settings for %s:\n", nlctx->devname);
-	printf("\tEEE status: ");
-	if (bitset_is_empty(tb[ETHTOOL_A_EEE_MODES_OURS], true, &ret)) {
-		printf("not supported\n");
+	print_string(PRINT_ANY, "ifname", "EEE settings for %s:\n", nlctx->devname);
+	print_string(PRINT_FP, NULL, "\tEEE status: ", NULL);
+	if (status_support) {
+		print_string(PRINT_ANY, "status", "%s\n", "not supported");
 		return MNL_CB_OK;
 	}
 	if (!enabled)
-		printf("disabled\n");
+		print_string(PRINT_ANY, "status", "%s\n", "disabled");
 	else
-		printf("enabled - %s\n", active ? "active" : "inactive");
-	printf("\tTx LPI: ");
+		print_string(PRINT_ANY, "status", "enabled - %s\n", active ? "active" : "inactive");
+	print_string(PRINT_FP, NULL, "\tTx LPI: ", NULL);
 	if (tx_lpi_enabled)
-		printf("%u (us)\n",
+		print_uint(PRINT_ANY, "tx-lpi", "%u (us)\n",
 		       mnl_attr_get_u32(tb[ETHTOOL_A_EEE_TX_LPI_TIMER]));
 	else
-		printf("disabled\n");
+		print_string(PRINT_FP, NULL, "%s\n", "disabled");
 
 	ret = dump_link_modes(nlctx, tb[ETHTOOL_A_EEE_MODES_OURS], true,
 			      LM_CLASS_REAL,
 			      "Supported EEE link modes:  ", NULL, "\n",
-			      "Not reported");
+			      "Not reported", "supported-eee-link-modes");
 	if (ret < 0)
 		return err_ret;
 	ret = dump_link_modes(nlctx, tb[ETHTOOL_A_EEE_MODES_OURS], false,
 			      LM_CLASS_REAL,
 			      "Advertised EEE link modes:  ", NULL, "\n",
-			      "Not reported");
+			      "Not reported", "advertised-eee-link-modes");
 	if (ret < 0)
 		return err_ret;
 	ret = dump_link_modes(nlctx, tb[ETHTOOL_A_EEE_MODES_PEER], false,
 			      LM_CLASS_REAL,
 			      "Link partner advertised EEE link modes:  ", NULL,
-			      "\n", "Not reported");
+			      "\n", "Not reported", "link-partner-advertised-eee-link-modes");
 	if (ret < 0)
 		return err_ret;
 
@@ -102,11 +104,18 @@ int nl_geee(struct cmd_context *ctx)
 		return 1;
 	}
 
+	new_json_obj(ctx->json);
+	open_json_object(NULL);
+
 	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_EEE_GET,
 				      ETHTOOL_A_EEE_HEADER, 0);
 	if (ret < 0)
-		return ret;
-	return nlsock_send_get_request(nlsk, eee_reply_cb);
+		goto out;
+	ret =  nlsock_send_get_request(nlsk, eee_reply_cb);
+out:
+	close_json_object();
+	delete_json_obj();
+	return ret;
 }
 
 /* EEE_SET */
diff --git a/netlink/extapi.h b/netlink/extapi.h
index e2d6b71..9d6eddf 100644
--- a/netlink/extapi.h
+++ b/netlink/extapi.h
@@ -55,6 +55,8 @@ int nl_get_mm(struct cmd_context *ctx);
 int nl_set_mm(struct cmd_context *ctx);
 int nl_gpse(struct cmd_context *ctx);
 int nl_spse(struct cmd_context *ctx);
+int nl_flash_module_fw(struct cmd_context *ctx);
+int nl_get_phy(struct cmd_context *ctx);
 
 void nl_monitor_usage(void);
 
@@ -130,6 +132,8 @@ nl_get_eeprom_page(struct cmd_context *ctx __maybe_unused,
 #define nl_set_mm		NULL
 #define nl_gpse			NULL
 #define nl_spse			NULL
+#define nl_flash_module_fw	NULL
+#define nl_get_phy		NULL
 
 #endif /* ETHTOOL_ENABLE_NETLINK */
 
diff --git a/netlink/module-eeprom.c b/netlink/module-eeprom.c
index 49833a2..2b30d04 100644
--- a/netlink/module-eeprom.c
+++ b/netlink/module-eeprom.c
@@ -22,6 +22,7 @@
 #define ETH_I2C_MAX_ADDRESS	0x7F
 
 struct cmd_params {
+	unsigned long present;
 	u8 dump_hex;
 	u8 dump_raw;
 	u32 offset;
@@ -31,6 +32,14 @@ struct cmd_params {
 	u32 i2c_address;
 };
 
+enum {
+	PARAM_OFFSET = 2,
+	PARAM_LENGTH,
+	PARAM_PAGE,
+	PARAM_BANK,
+	PARAM_I2C,
+};
+
 static const struct param_parser getmodule_params[] = {
 	{
 		.arg		= "hex",
@@ -44,31 +53,31 @@ static const struct param_parser getmodule_params[] = {
 		.dest_offset	= offsetof(struct cmd_params, dump_raw),
 		.min_argc	= 1,
 	},
-	{
+	[PARAM_OFFSET] = {
 		.arg		= "offset",
 		.handler	= nl_parse_direct_u32,
 		.dest_offset	= offsetof(struct cmd_params, offset),
 		.min_argc	= 1,
 	},
-	{
+	[PARAM_LENGTH] = {
 		.arg		= "length",
 		.handler	= nl_parse_direct_u32,
 		.dest_offset	= offsetof(struct cmd_params, length),
 		.min_argc	= 1,
 	},
-	{
+	[PARAM_PAGE] = {
 		.arg		= "page",
 		.handler	= nl_parse_direct_u32,
 		.dest_offset	= offsetof(struct cmd_params, page),
 		.min_argc	= 1,
 	},
-	{
+	[PARAM_BANK] = {
 		.arg		= "bank",
 		.handler	= nl_parse_direct_u32,
 		.dest_offset	= offsetof(struct cmd_params, bank),
 		.min_argc	= 1,
 	},
-	{
+	[PARAM_I2C] = {
 		.arg		= "i2c",
 		.handler	= nl_parse_direct_u32,
 		.dest_offset	= offsetof(struct cmd_params, i2c_address),
@@ -216,6 +225,8 @@ static int eeprom_parse(struct cmd_context *ctx)
 
 	switch (request.data[0]) {
 #ifdef ETHTOOL_ENABLE_PRETTY_DUMP
+	case SFF8024_ID_GBIC:
+	case SFF8024_ID_SOLDERED_MODULE:
 	case SFF8024_ID_SFP:
 		return sff8079_show_all_nl(ctx);
 	case SFF8024_ID_QSFP:
@@ -225,6 +236,9 @@ static int eeprom_parse(struct cmd_context *ctx)
 	case SFF8024_ID_QSFP_DD:
 	case SFF8024_ID_OSFP:
 	case SFF8024_ID_DSFP:
+	case SFF8024_ID_QSFP_PLUS_CMIS:
+	case SFF8024_ID_SFP_DD_CMIS:
+	case SFF8024_ID_SFP_PLUS_CMIS:
 		return cmis_show_all_nl(ctx);
 #endif
 	default:
@@ -262,15 +276,18 @@ int nl_getmodule(struct cmd_context *ctx)
 	 * ioctl. Netlink can only request specific pages.
 	 */
 	if ((getmodule_cmd_params.dump_hex || getmodule_cmd_params.dump_raw) &&
-	    !getmodule_cmd_params.page && !getmodule_cmd_params.bank &&
-	    !getmodule_cmd_params.i2c_address) {
+	    !(getmodule_cmd_params.present & (1 << PARAM_PAGE |
+					      1 << PARAM_BANK |
+					      1 << PARAM_I2C))) {
 		nlctx->ioctl_fallback = true;
 		return -EOPNOTSUPP;
 	}
 
 #ifdef ETHTOOL_ENABLE_PRETTY_DUMP
-	if (getmodule_cmd_params.page || getmodule_cmd_params.bank ||
-	    getmodule_cmd_params.offset || getmodule_cmd_params.length)
+	if (getmodule_cmd_params.present & (1 << PARAM_PAGE |
+					    1 << PARAM_BANK |
+					    1 << PARAM_OFFSET |
+					    1 << PARAM_LENGTH))
 #endif
 		getmodule_cmd_params.dump_hex = true;
 
diff --git a/netlink/module.c b/netlink/module.c
index 54aa6d0..a92f272 100644
--- a/netlink/module.c
+++ b/netlink/module.c
@@ -10,6 +10,7 @@
 #include <inttypes.h>
 #include <string.h>
 #include <stdio.h>
+#include <stdarg.h>
 
 #include "../internal.h"
 #include "../common.h"
@@ -177,3 +178,185 @@ int nl_smodule(struct cmd_context *ctx)
 	else
 		return nlctx->exit_code ?: 83;
 }
+
+/* MODULE_FW_FLASH_ACT */
+
+static const struct param_parser flash_module_fw_params[] = {
+	{
+		.arg		= "file",
+		.type		= ETHTOOL_A_MODULE_FW_FLASH_FILE_NAME,
+		.handler	= nl_parse_string,
+		.min_argc	= 1,
+	},
+	{
+		.arg		= "pass",
+		.type		= ETHTOOL_A_MODULE_FW_FLASH_PASSWORD,
+		.handler	= nl_parse_direct_u32,
+		.min_argc	= 1,
+	},
+	{}
+};
+
+struct module_flash_context {
+	uint8_t breakout:1,
+		first:1;
+};
+
+static int module_fw_flash_ntf_cb(const struct nlmsghdr *nlhdr, void *data)
+{
+	const struct nlattr *tb[ETHTOOL_A_MODULE_FW_FLASH_MAX + 1] = {};
+	struct module_flash_context *mfctx;
+	struct nl_context *nlctx = data;
+	DECLARE_ATTR_TB_INFO(tb);
+	u8 status = 0;
+	int ret;
+
+	mfctx = nlctx->cmd_private;
+
+	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
+	if (ret < 0)
+		return MNL_CB_OK;
+	nlctx->devname = get_dev_name(tb[ETHTOOL_A_MODULE_FW_FLASH_HEADER]);
+	if (!dev_ok(nlctx))
+		return MNL_CB_OK;
+
+	if (tb[ETHTOOL_A_MODULE_FW_FLASH_STATUS])
+		status = mnl_attr_get_u32(tb[ETHTOOL_A_MODULE_FW_FLASH_STATUS]);
+
+	switch (status) {
+	case ETHTOOL_MODULE_FW_FLASH_STATUS_STARTED:
+		print_string(PRINT_FP, NULL,
+			     "Transceiver module firmware flashing started for device %s\n",
+			     nlctx->devname);
+		break;
+	case ETHTOOL_MODULE_FW_FLASH_STATUS_IN_PROGRESS:
+		if (mfctx->first) {
+			print_string(PRINT_FP, NULL,
+				     "Transceiver module firmware flashing in progress for device %s\n",
+				     nlctx->devname);
+			mfctx->first = 0;
+		}
+		break;
+	case ETHTOOL_MODULE_FW_FLASH_STATUS_COMPLETED:
+		print_nl();
+		print_string(PRINT_FP, NULL,
+			     "Transceiver module firmware flashing completed for device %s\n",
+			     nlctx->devname);
+		mfctx->breakout = 1;
+		break;
+	case ETHTOOL_MODULE_FW_FLASH_STATUS_ERROR:
+		print_nl();
+		print_string(PRINT_FP, NULL,
+			     "Transceiver module firmware flashing encountered an error for device %s\n",
+			     nlctx->devname);
+		mfctx->breakout = 1;
+		break;
+	default:
+		break;
+	}
+
+	if (tb[ETHTOOL_A_MODULE_FW_FLASH_STATUS_MSG]) {
+		const char *status_msg;
+
+		status_msg = mnl_attr_get_str(tb[ETHTOOL_A_MODULE_FW_FLASH_STATUS_MSG]);
+		print_string(PRINT_FP, NULL, "Status message: %s\n", status_msg);
+	}
+
+	if (tb[ETHTOOL_A_MODULE_FW_FLASH_DONE] &&
+	    tb[ETHTOOL_A_MODULE_FW_FLASH_TOTAL]) {
+		uint64_t done, total;
+
+		done = attr_get_uint(tb[ETHTOOL_A_MODULE_FW_FLASH_DONE]);
+		total = attr_get_uint(tb[ETHTOOL_A_MODULE_FW_FLASH_TOTAL]);
+
+		if (total)
+			print_u64(PRINT_FP, NULL, "Progress: %"PRIu64"%\r",
+				  done * 100 / total);
+	}
+
+	return MNL_CB_OK;
+}
+
+static int nl_flash_module_fw_cb(const struct nlmsghdr *nlhdr, void *data)
+{
+	const struct genlmsghdr *ghdr = (const struct genlmsghdr *)(nlhdr + 1);
+
+	if (ghdr->cmd != ETHTOOL_MSG_MODULE_FW_FLASH_NTF)
+		return MNL_CB_OK;
+
+	module_fw_flash_ntf_cb(nlhdr, data);
+
+	return MNL_CB_STOP;
+}
+
+static int nl_flash_module_fw_process_ntf(struct cmd_context *ctx)
+{
+	struct nl_context *nlctx = ctx->nlctx;
+	struct module_flash_context *mfctx;
+	struct nl_socket *nlsk;
+	int ret;
+
+	nlsk = nlctx->ethnl_socket;
+
+	mfctx = malloc(sizeof(struct module_flash_context));
+	if (!mfctx)
+		return -ENOMEM;
+
+	mfctx->breakout = 0;
+	mfctx->first = 1;
+	nlctx->cmd_private = mfctx;
+
+	while (!mfctx->breakout) {
+		ret = nlsock_process_reply(nlsk, nl_flash_module_fw_cb, nlctx);
+		if (ret)
+			goto out;
+		nlsk->seq++;
+	}
+
+out:
+	free(mfctx);
+	return ret;
+}
+
+int nl_flash_module_fw(struct cmd_context *ctx)
+{
+	struct nl_context *nlctx = ctx->nlctx;
+	struct nl_msg_buff *msgbuff;
+	struct nl_socket *nlsk;
+	int ret;
+
+	if (netlink_cmd_check(ctx, ETHTOOL_MSG_MODULE_FW_FLASH_ACT, false))
+		return -EOPNOTSUPP;
+	if (!ctx->argc) {
+		fprintf(stderr, "ethtool (--flash-module-firmware): parameters missing\n");
+		return 1;
+	}
+
+	nlctx->cmd = "--flash-module-firmware";
+	nlctx->argp = ctx->argp;
+	nlctx->argc = ctx->argc;
+	nlctx->devname = ctx->devname;
+	nlsk = nlctx->ethnl_socket;
+	msgbuff = &nlsk->msgbuff;
+
+	ret = msg_init(nlctx, msgbuff, ETHTOOL_MSG_MODULE_FW_FLASH_ACT,
+		       NLM_F_REQUEST | NLM_F_ACK);
+	if (ret < 0)
+		return 2;
+	if (ethnla_fill_header(msgbuff, ETHTOOL_A_MODULE_FW_FLASH_HEADER,
+			       ctx->devname, 0))
+		return -EMSGSIZE;
+
+	ret = nl_parser(nlctx, flash_module_fw_params, NULL, PARSER_GROUP_NONE,
+			NULL);
+	if (ret < 0)
+		return 1;
+
+	ret = nlsock_sendmsg(nlsk, NULL);
+	if (ret < 0)
+		fprintf(stderr, "Cannot flash transceiver module firmware\n");
+	else
+		ret = nl_flash_module_fw_process_ntf(ctx);
+
+	return ret;
+}
diff --git a/netlink/msgbuff.c b/netlink/msgbuff.c
index 216f5b9..2275840 100644
--- a/netlink/msgbuff.c
+++ b/netlink/msgbuff.c
@@ -138,17 +138,9 @@ struct nlattr *ethnla_nest_start(struct nl_msg_buff *msgbuff, uint16_t type)
 	return NULL;
 }
 
-/**
- * ethnla_fill_header() - write standard ethtool request header to message
- * @msgbuff: message buffer
- * @type:    attribute type for header nest
- * @devname: device name (NULL to omit)
- * @flags:   request flags (omitted if 0)
- *
- * Return: pointer to the nest attribute or null of error
- */
-bool ethnla_fill_header(struct nl_msg_buff *msgbuff, uint16_t type,
-			const char *devname, uint32_t flags)
+static bool __ethnla_fill_header_phy(struct nl_msg_buff *msgbuff, uint16_t type,
+				     const char *devname, uint32_t phy_index,
+				     uint32_t flags)
 {
 	struct nlattr *nest;
 
@@ -159,7 +151,9 @@ bool ethnla_fill_header(struct nl_msg_buff *msgbuff, uint16_t type,
 	if ((devname &&
 	     ethnla_put_strz(msgbuff, ETHTOOL_A_HEADER_DEV_NAME, devname)) ||
 	    (flags &&
-	     ethnla_put_u32(msgbuff, ETHTOOL_A_HEADER_FLAGS, flags)))
+	     ethnla_put_u32(msgbuff, ETHTOOL_A_HEADER_FLAGS, flags)) ||
+	    (phy_index &&
+	     ethnla_put_u32(msgbuff, ETHTOOL_A_HEADER_PHY_INDEX, phy_index)))
 		goto err;
 
 	ethnla_nest_end(msgbuff, nest);
@@ -170,6 +164,40 @@ err:
 	return true;
 }
 
+/**
+ * ethnla_fill_header() - write standard ethtool request header to message
+ * @msgbuff: message buffer
+ * @type:    attribute type for header nest
+ * @devname: device name (NULL to omit)
+ * @flags:   request flags (omitted if 0)
+ *
+ * Return: pointer to the nest attribute or null of error
+ */
+bool ethnla_fill_header(struct nl_msg_buff *msgbuff, uint16_t type,
+			const char *devname, uint32_t flags)
+{
+	return __ethnla_fill_header_phy(msgbuff, type, devname, 0, flags);
+}
+
+/**
+ * ethnla_fill_header_phy() - write standard ethtool request header to message,
+ *			      targetting a device's phy
+ * @msgbuff: message buffer
+ * @type:    attribute type for header nest
+ * @devname: device name (NULL to omit)
+ * @phy_index: phy index to target (0 to omit)
+ * @flags:   request flags (omitted if 0)
+ *
+ * Return: pointer to the nest attribute or null of error
+ */
+bool ethnla_fill_header_phy(struct nl_msg_buff *msgbuff, uint16_t type,
+			    const char *devname, uint32_t phy_index,
+			    uint32_t flags)
+{
+	return __ethnla_fill_header_phy(msgbuff, type, devname, phy_index,
+					flags);
+}
+
 /**
  * __msg_init() - init a genetlink message, fill netlink and genetlink header
  * @msgbuff: message buffer
diff --git a/netlink/msgbuff.h b/netlink/msgbuff.h
index 7d6731f..7df19fc 100644
--- a/netlink/msgbuff.h
+++ b/netlink/msgbuff.h
@@ -47,6 +47,9 @@ bool ethnla_put(struct nl_msg_buff *msgbuff, uint16_t type, size_t len,
 struct nlattr *ethnla_nest_start(struct nl_msg_buff *msgbuff, uint16_t type);
 bool ethnla_fill_header(struct nl_msg_buff *msgbuff, uint16_t type,
 			const char *devname, uint32_t flags);
+bool ethnla_fill_header_phy(struct nl_msg_buff *msgbuff, uint16_t type,
+			    const char *devname, uint32_t phy_index,
+			    uint32_t flags);
 
 /* length of current message */
 static inline unsigned int msgbuff_len(const struct nl_msg_buff *msgbuff)
diff --git a/netlink/netlink.c b/netlink/netlink.c
index ef0d825..3cf1710 100644
--- a/netlink/netlink.c
+++ b/netlink/netlink.c
@@ -470,6 +470,11 @@ void netlink_run_handler(struct cmd_context *ctx, nl_chk_t nlchk,
 	const char *reason;
 	int ret;
 
+	if (ctx->nl_disable) {
+		reason = "netlink disabled";
+		goto no_support;
+	}
+
 	if (nlchk && !nlchk(ctx)) {
 		reason = "ioctl-only request";
 		goto no_support;
diff --git a/netlink/netlink.h b/netlink/netlink.h
index 1274a3b..ad2a787 100644
--- a/netlink/netlink.h
+++ b/netlink/netlink.h
@@ -98,7 +98,7 @@ int module_reply_cb(const struct nlmsghdr *nlhdr, void *data);
 int dump_link_modes(struct nl_context *nlctx, const struct nlattr *bitset,
 		    bool mask, unsigned int class, const char *before,
 		    const char *between, const char *after,
-		    const char *if_none);
+		    const char *if_none, const char *json_key);
 
 static inline void show_u32(const char *key,
 			    const char *fmt,
@@ -175,4 +175,20 @@ static inline int netlink_init_rtnl_socket(struct nl_context *nlctx)
 	return nlsock_init(nlctx, &nlctx->rtnl_socket, NETLINK_ROUTE);
 }
 
+static inline uint64_t attr_get_uint(const struct nlattr *attr)
+{
+	switch (mnl_attr_get_payload_len(attr)) {
+	case sizeof(uint8_t):
+		return mnl_attr_get_u8(attr);
+	case sizeof(uint16_t):
+		return mnl_attr_get_u16(attr);
+	case sizeof(uint32_t):
+		return mnl_attr_get_u32(attr);
+	case sizeof(uint64_t):
+		return mnl_attr_get_u64(attr);
+	}
+
+	return -1ULL;
+}
+
 #endif /* ETHTOOL_NETLINK_INT_H__ */
diff --git a/netlink/nlsock.c b/netlink/nlsock.c
index 0ec2738..5450c9b 100644
--- a/netlink/nlsock.c
+++ b/netlink/nlsock.c
@@ -291,6 +291,44 @@ int nlsock_prep_get_request(struct nl_socket *nlsk, unsigned int nlcmd,
 	ret = msg_init(nlctx, &nlsk->msgbuff, nlcmd, nlm_flags);
 	if (ret < 0)
 		return ret;
+	if (ethnla_fill_header_phy(&nlsk->msgbuff, hdr_attrtype, devname,
+				   nlctx->ctx->phy_index, flags))
+		return -EMSGSIZE;
+
+	return 0;
+}
+
+/**
+ * nlsock_prep_filtered_dump_request() - Initialize a filtered DUMP request
+ * @nlsk: netlink socket
+ * @nlcmd: netlink command
+ * @hdr_attrtype: netlink command header attribute
+ * @flags: netlink command header flags
+ *
+ * Prepare a DUMP request that may include the device index as a filtering
+ * attribute in the header.
+ *
+ * Return: 0 on success, or a negative number on error
+ */
+int nlsock_prep_filtered_dump_request(struct nl_socket *nlsk,
+				      unsigned int nlcmd, uint16_t hdr_attrtype,
+				      u32 flags)
+{
+	struct nl_context *nlctx = nlsk->nlctx;
+	const char *devname = nlctx->ctx->devname;
+	unsigned int nlm_flags;
+	int ret;
+
+	nlctx->is_dump = true;
+	nlm_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP;
+
+	if (devname && !strcmp(devname, WILDCARD_DEVNAME))
+		devname = NULL;
+
+	ret = msg_init(nlctx, &nlsk->msgbuff, nlcmd, nlm_flags);
+	if (ret < 0)
+		return ret;
+
 	if (ethnla_fill_header(&nlsk->msgbuff, hdr_attrtype, devname, flags))
 		return -EMSGSIZE;
 
diff --git a/netlink/nlsock.h b/netlink/nlsock.h
index b015f86..6a72966 100644
--- a/netlink/nlsock.h
+++ b/netlink/nlsock.h
@@ -38,6 +38,8 @@ int nlsock_init(struct nl_context *nlctx, struct nl_socket **__nlsk,
 void nlsock_done(struct nl_socket *nlsk);
 int nlsock_prep_get_request(struct nl_socket *nlsk, unsigned int nlcmd,
 			    uint16_t hdr_attrtype, u32 flags);
+int nlsock_prep_filtered_dump_request(struct nl_socket *nlsk, unsigned int nlcmd,
+				      uint16_t hdr_attrtype, u32 flags);
 ssize_t nlsock_sendmsg(struct nl_socket *nlsk, struct nl_msg_buff *__msgbuff);
 int nlsock_send_get_request(struct nl_socket *nlsk, mnl_cb_t cb);
 int nlsock_process_reply(struct nl_socket *nlsk, mnl_cb_t reply_cb, void *data);
diff --git a/netlink/parser.c b/netlink/parser.c
index 6f86361..cd32752 100644
--- a/netlink/parser.c
+++ b/netlink/parser.c
@@ -996,7 +996,7 @@ static void tmp_buff_destroy(struct tmp_buff *head)
  *               and their handlers; the array must be terminated by null
  *               element {}
  * @dest:        optional destination to copy parsed data to (at
- *               param_parser::offset)
+ *               param_parser::offset); buffer should start with presence bitmap
  * @group_style: defines if identifiers in .group represent separate messages,
  *               nested attributes or are not allowed
  * @msgbuffs:    (only used for @group_style = PARSER_GROUP_MSG) array to store
@@ -1096,7 +1096,14 @@ int nl_parser(struct nl_context *nlctx, const struct param_parser *params,
 			buff = tmp_buff_find(buffs, parser->group);
 		msgbuff = buff ? buff->msgbuff : &nlsk->msgbuff;
 
-		param_dest = dest ? ((char *)dest + parser->dest_offset) : NULL;
+		if (dest) {
+			unsigned long index = parser - params;
+
+			param_dest = ((char *)dest + parser->dest_offset);
+			set_bit(index, (unsigned long *)dest);
+		} else {
+			param_dest = NULL;
+		}
 		ret = parser->handler(nlctx, parser->type, parser->handler_data,
 				      msgbuff, param_dest);
 		if (ret < 0)
diff --git a/netlink/phy.c b/netlink/phy.c
new file mode 100644
index 0000000..7578191
--- /dev/null
+++ b/netlink/phy.c
@@ -0,0 +1,116 @@
+/*
+ * phy.c - List PHYs on an interface and their parameters
+ *
+ * Implementation of "ethtool --show-phys <dev>"
+ */
+
+#include <errno.h>
+#include <inttypes.h>
+#include <string.h>
+#include <stdio.h>
+
+#include "../internal.h"
+#include "../common.h"
+#include "netlink.h"
+
+/* PHY_GET / PHY_DUMP */
+
+static const char * phy_upstream_type_to_str(uint8_t upstream_type)
+{
+	switch (upstream_type) {
+	case PHY_UPSTREAM_PHY: return "phy";
+	case PHY_UPSTREAM_MAC: return "mac";
+	default: return "Unknown";
+	}
+}
+
+int phy_reply_cb(const struct nlmsghdr *nlhdr, void *data)
+{
+	const struct nlattr *tb[ETHTOOL_A_PHY_MAX + 1] = {};
+	struct nl_context *nlctx = data;
+	DECLARE_ATTR_TB_INFO(tb);
+	uint8_t upstream_type;
+	bool silent;
+	int err_ret;
+	int ret;
+
+	silent = nlctx->is_dump || nlctx->is_monitor;
+	err_ret = silent ? MNL_CB_OK : MNL_CB_ERROR;
+	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
+	if (ret < 0)
+		return err_ret;
+	nlctx->devname = get_dev_name(tb[ETHTOOL_A_PHY_HEADER]);
+	if (!dev_ok(nlctx))
+		return err_ret;
+
+	if (silent)
+		print_nl();
+
+	open_json_object(NULL);
+
+	print_string(PRINT_ANY, "ifname", "PHY for %s:\n", nlctx->devname);
+
+	show_u32("phy_index", "PHY index: ", tb[ETHTOOL_A_PHY_INDEX]);
+
+	if (tb[ETHTOOL_A_PHY_DRVNAME])
+		print_string(PRINT_ANY, "drvname", "Driver name: %s\n",
+		     mnl_attr_get_str(tb[ETHTOOL_A_PHY_DRVNAME]));
+
+	if (tb[ETHTOOL_A_PHY_NAME])
+		print_string(PRINT_ANY, "name", "PHY device name: %s\n",
+		     mnl_attr_get_str(tb[ETHTOOL_A_PHY_NAME]));
+
+	if (tb[ETHTOOL_A_PHY_DOWNSTREAM_SFP_NAME])
+		print_string(PRINT_ANY, "downstream_sfp_name",
+			     "Downstream SFP bus name: %s\n",
+			     mnl_attr_get_str(tb[ETHTOOL_A_PHY_DOWNSTREAM_SFP_NAME]));
+
+	if (tb[ETHTOOL_A_PHY_UPSTREAM_TYPE]) {
+		upstream_type = mnl_attr_get_u8(tb[ETHTOOL_A_PHY_UPSTREAM_TYPE]);
+		print_string(PRINT_ANY, "upstream_type", "Upstream type: %s\n",
+			     phy_upstream_type_to_str(upstream_type));
+	}
+
+	if (tb[ETHTOOL_A_PHY_UPSTREAM_INDEX])
+		show_u32("upstream_index", "Upstream PHY index: ",
+			 tb[ETHTOOL_A_PHY_UPSTREAM_INDEX]);
+
+	if (tb[ETHTOOL_A_PHY_UPSTREAM_SFP_NAME])
+		print_string(PRINT_ANY, "upstream_sfp_name", "Upstream SFP name: %s\n",
+			     mnl_attr_get_str(tb[ETHTOOL_A_PHY_UPSTREAM_SFP_NAME]));
+
+	if (!silent)
+		print_nl();
+
+	close_json_object();
+
+	return MNL_CB_OK;
+
+	close_json_object();
+	return err_ret;
+}
+
+int nl_get_phy(struct cmd_context *ctx)
+{
+	struct nl_context *nlctx = ctx->nlctx;
+	struct nl_socket *nlsk = nlctx->ethnl_socket;
+	int ret;
+
+	if (netlink_cmd_check(ctx, ETHTOOL_MSG_PHY_GET, true))
+		return -EOPNOTSUPP;
+	if (ctx->argc > 0) {
+		fprintf(stderr, "ethtool: unexpected parameter '%s'\n",
+			*ctx->argp);
+		return 1;
+	}
+
+	ret = nlsock_prep_filtered_dump_request(nlsk, ETHTOOL_MSG_PHY_GET,
+						ETHTOOL_A_PHY_HEADER, 0);
+	if (ret)
+		return ret;
+
+	new_json_obj(ctx->json);
+	ret = nlsock_send_get_request(nlsk, phy_reply_cb);
+	delete_json_obj();
+	return ret;
+}
diff --git a/netlink/plca.c b/netlink/plca.c
index 7d61e3b..7dc30a3 100644
--- a/netlink/plca.c
+++ b/netlink/plca.c
@@ -211,8 +211,8 @@ int nl_plca_set_cfg(struct cmd_context *ctx)
 		       NLM_F_REQUEST | NLM_F_ACK);
 	if (ret < 0)
 		return 2;
-	if (ethnla_fill_header(msgbuff, ETHTOOL_A_PLCA_HEADER,
-			       ctx->devname, 0))
+	if (ethnla_fill_header_phy(msgbuff, ETHTOOL_A_PLCA_HEADER,
+				   ctx->devname, ctx->phy_index, 0))
 		return -EMSGSIZE;
 
 	ret = nl_parser(nlctx, set_plca_params, NULL, PARSER_GROUP_NONE, NULL);
diff --git a/netlink/prettymsg.c b/netlink/prettymsg.c
index fbf684f..0eb4447 100644
--- a/netlink/prettymsg.c
+++ b/netlink/prettymsg.c
@@ -15,6 +15,8 @@
 #include <linux/if_link.h>
 #include <libmnl/libmnl.h>
 
+#include "../internal.h"
+#include "netlink.h"
 #include "prettymsg.h"
 
 #define __INDENT 4
@@ -114,6 +116,9 @@ static int pretty_print_attr(const struct nlattr *attr,
 	case NLA_U64:
 		printf("%" PRIu64, mnl_attr_get_u64(attr));
 		break;
+	case NLA_UINT:
+		printf("%" PRIu64, attr_get_uint(attr));
+		break;
 	case NLA_X8:
 		printf("0x%02x", mnl_attr_get_u8(attr));
 		break;
diff --git a/netlink/prettymsg.h b/netlink/prettymsg.h
index 8ca1db3..ef8e73f 100644
--- a/netlink/prettymsg.h
+++ b/netlink/prettymsg.h
@@ -18,6 +18,7 @@ enum pretty_nla_format {
 	NLA_U16,
 	NLA_U32,
 	NLA_U64,
+	NLA_UINT,
 	NLA_X8,
 	NLA_X16,
 	NLA_X32,
@@ -67,6 +68,7 @@ struct pretty_nlmsg_desc {
 #define NLATTR_DESC_U16(_name)		NLATTR_DESC(_name, NLA_U16)
 #define NLATTR_DESC_U32(_name)		NLATTR_DESC(_name, NLA_U32)
 #define NLATTR_DESC_U64(_name)		NLATTR_DESC(_name, NLA_U64)
+#define NLATTR_DESC_UINT(_name)		NLATTR_DESC(_name, NLA_UINT)
 #define NLATTR_DESC_X8(_name)		NLATTR_DESC(_name, NLA_X8)
 #define NLATTR_DESC_X16(_name)		NLATTR_DESC(_name, NLA_X16)
 #define NLATTR_DESC_X32(_name)		NLATTR_DESC(_name, NLA_X32)
diff --git a/netlink/pse-pd.c b/netlink/pse-pd.c
index d6faff8..fd1fc4d 100644
--- a/netlink/pse-pd.c
+++ b/netlink/pse-pd.c
@@ -54,10 +54,261 @@ static const char *podl_pse_pw_d_status_name(u32 val)
 	}
 }
 
+static const char *c33_pse_admin_state_name(u32 val)
+{
+	switch (val) {
+	case ETHTOOL_C33_PSE_ADMIN_STATE_UNKNOWN:
+		return "unknown";
+	case ETHTOOL_C33_PSE_ADMIN_STATE_DISABLED:
+		return "disabled";
+	case ETHTOOL_C33_PSE_ADMIN_STATE_ENABLED:
+		return "enabled";
+	default:
+		return "unsupported";
+	}
+}
+
+static const char *c33_pse_pw_d_status_name(u32 val)
+{
+	switch (val) {
+	case ETHTOOL_C33_PSE_PW_D_STATUS_UNKNOWN:
+		return "unknown";
+	case ETHTOOL_C33_PSE_PW_D_STATUS_DISABLED:
+		return "disabled";
+	case ETHTOOL_C33_PSE_PW_D_STATUS_SEARCHING:
+		return "searching";
+	case ETHTOOL_C33_PSE_PW_D_STATUS_DELIVERING:
+		return "delivering power";
+	case ETHTOOL_C33_PSE_PW_D_STATUS_TEST:
+		return "test";
+	case ETHTOOL_C33_PSE_PW_D_STATUS_FAULT:
+		return "fault";
+	case ETHTOOL_C33_PSE_PW_D_STATUS_OTHERFAULT:
+		return "otherfault";
+	default:
+		return "unsupported";
+	}
+}
+
+static const char *c33_pse_ext_state_name(u32 val)
+{
+	switch (val) {
+	case ETHTOOL_C33_PSE_EXT_STATE_ERROR_CONDITION:
+		return "Group of error_condition states";
+	case ETHTOOL_C33_PSE_EXT_STATE_MR_MPS_VALID:
+		return "Group of mr_mps_valid states";
+	case ETHTOOL_C33_PSE_EXT_STATE_MR_PSE_ENABLE:
+		return "Group of mr_pse_enable states";
+	case ETHTOOL_C33_PSE_EXT_STATE_OPTION_DETECT_TED:
+		return "Group of option_detect_ted";
+	case ETHTOOL_C33_PSE_EXT_STATE_OPTION_VPORT_LIM:
+		return "Group of option_vport_lim states";
+	case ETHTOOL_C33_PSE_EXT_STATE_OVLD_DETECTED:
+		return "Group of ovld_detected states";
+	case ETHTOOL_C33_PSE_EXT_STATE_PD_DLL_POWER_TYPE:
+		return "Group of pd_dll_power_type states";
+	case ETHTOOL_C33_PSE_EXT_STATE_POWER_NOT_AVAILABLE:
+		return "Group of power_not_available states";
+	case ETHTOOL_C33_PSE_EXT_STATE_SHORT_DETECTED:
+		return "Group of short_detected states";
+	default:
+		return "unsupported";
+	}
+}
+
+static const char *c33_pse_ext_substate_mr_mps_valid_name(u32 val)
+{
+	switch (val) {
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_MPS_VALID_DETECTED_UNDERLOAD:
+		return "Underload state";
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_MPS_VALID_CONNECTION_OPEN:
+		return "Port is not connected";
+	default:
+		return "unsupported";
+	}
+}
+
+static const char *c33_pse_ext_substate_error_condition_name(u32 val)
+{
+	switch (val) {
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_NON_EXISTING_PORT:
+		return "Non-existing port number";
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNDEFINED_PORT:
+		return "Undefined port";
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_INTERNAL_HW_FAULT:
+		return "Internal hardware fault";
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_COMM_ERROR_AFTER_FORCE_ON:
+		return "Communication error after force on";
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNKNOWN_PORT_STATUS:
+		return "Unknown port status";
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_TURN_OFF:
+		return "Host crash turn off";
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_FORCE_SHUTDOWN:
+		return "Host crash force shutdown";
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_CONFIG_CHANGE:
+		return "Configuration change";
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_DETECTED_OVER_TEMP:
+		return "Over temperature detected";
+	default:
+		return "unsupported";
+	}
+}
+
+static const char *c33_pse_ext_substate_mr_pse_enable_name(u32 val)
+{
+	switch (val) {
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_PSE_ENABLE_DISABLE_PIN_ACTIVE:
+		return "Disable pin active";
+	default:
+		return "unsupported";
+	}
+}
+
+static const char *c33_pse_ext_substate_option_detect_ted_name(u32 val)
+{
+	switch (val) {
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_DET_IN_PROCESS:
+		return "Detection in process";
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_CONNECTION_CHECK_ERROR:
+		return "Connection check error";
+	default:
+		return "unsupported";
+	}
+}
+
+static const char *c33_pse_ext_substate_option_vport_lim_name(u32 val)
+{
+	switch (val) {
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_HIGH_VOLTAGE:
+		return "Main supply voltage is high";
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_LOW_VOLTAGE:
+		return "Main supply voltage is low";
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_VOLTAGE_INJECTION:
+		return "Voltage injection into the port";
+	default:
+		return "unsupported";
+	}
+}
+
+static const char *c33_pse_ext_substate_ovld_detected_name(u32 val)
+{
+	switch (val) {
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_OVLD_DETECTED_OVERLOAD:
+		return "Overload state";
+	default:
+		return "unsupported";
+	}
+}
+
+static const char *c33_pse_ext_substate_power_not_available_name(u32 val)
+{
+	switch (val) {
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_BUDGET_EXCEEDED:
+		return "Power budget exceeded for the controller";
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PORT_PW_LIMIT_EXCEEDS_CONTROLLER_BUDGET:
+		return "Configured port power limit exceeded controller power budget";
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PD_REQUEST_EXCEEDS_PORT_LIMIT:
+		return "Power request from PD exceeds port limit";
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_HW_PW_LIMIT:
+		return "Power denied due to Hardware power limit";
+	default:
+		return "unsupported";
+	}
+}
+
+static const char *c33_pse_ext_substate_short_detected_name(u32 val)
+{
+	switch (val) {
+	case ETHTOOL_C33_PSE_EXT_SUBSTATE_SHORT_DETECTED_SHORT_CONDITION:
+		return "Short condition was detected";
+	default:
+		return "unsupported";
+	}
+}
+
+struct c33_pse_ext_substate_desc {
+	u32 state;
+	const char *(*substate_name)(u32 val);
+};
+
+static const struct c33_pse_ext_substate_desc c33_pse_ext_substate_map[] = {
+	{ ETHTOOL_C33_PSE_EXT_STATE_ERROR_CONDITION,
+	  c33_pse_ext_substate_error_condition_name },
+	{ ETHTOOL_C33_PSE_EXT_STATE_MR_MPS_VALID,
+	  c33_pse_ext_substate_mr_mps_valid_name },
+	{ ETHTOOL_C33_PSE_EXT_STATE_MR_PSE_ENABLE,
+	  c33_pse_ext_substate_mr_pse_enable_name },
+	{ ETHTOOL_C33_PSE_EXT_STATE_OPTION_DETECT_TED,
+	  c33_pse_ext_substate_option_detect_ted_name },
+	{ ETHTOOL_C33_PSE_EXT_STATE_OPTION_VPORT_LIM,
+	  c33_pse_ext_substate_option_vport_lim_name },
+	{ ETHTOOL_C33_PSE_EXT_STATE_OVLD_DETECTED,
+	  c33_pse_ext_substate_ovld_detected_name },
+	{ ETHTOOL_C33_PSE_EXT_STATE_POWER_NOT_AVAILABLE,
+	  c33_pse_ext_substate_power_not_available_name },
+	{ ETHTOOL_C33_PSE_EXT_STATE_SHORT_DETECTED,
+	  c33_pse_ext_substate_short_detected_name },
+	{ /* sentinel */ }
+};
+
+static void c33_pse_print_ext_substate(u32 state, u32 substate)
+{
+	const struct c33_pse_ext_substate_desc *substate_map;
+
+	substate_map = c33_pse_ext_substate_map;
+	while (substate_map->state) {
+		if (substate_map->state == state) {
+			print_string(PRINT_ANY, "c33-pse-extended-substate",
+				     "Clause 33 PSE Extended Substate: %s\n",
+				     substate_map->substate_name(substate));
+			return;
+		}
+		substate_map++;
+	}
+}
+
+static int c33_pse_dump_pw_limit_range(const struct nlattr *range)
+{
+	const struct nlattr *range_tb[ETHTOOL_A_C33_PSE_PW_LIMIT_MAX + 1] = {};
+	DECLARE_ATTR_TB_INFO(range_tb);
+	const struct nlattr *attr;
+	u32 min, max;
+	int ret;
+
+	ret = mnl_attr_parse_nested(range, attr_cb, &range_tb_info);
+	if (ret < 0) {
+		fprintf(stderr,
+			"malformed netlink message (power limit range)\n");
+		return 1;
+	}
+
+	attr = range_tb[ETHTOOL_A_C33_PSE_PW_LIMIT_MIN];
+	if (!attr || mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
+		fprintf(stderr,
+			"malformed netlink message (power limit min)\n");
+		return 1;
+	}
+	min = mnl_attr_get_u32(attr);
+
+	attr = range_tb[ETHTOOL_A_C33_PSE_PW_LIMIT_MAX];
+	if (!attr || mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
+		fprintf(stderr,
+			"malformed netlink message (power limit max)\n");
+		return 1;
+	}
+	max = mnl_attr_get_u32(attr);
+
+	print_string(PRINT_ANY, "range", "\trange:\n", NULL);
+	print_uint(PRINT_ANY, "min", "\t\tmin %u\n", min);
+	print_uint(PRINT_ANY, "max", "\t\tmax %u\n", max);
+	return 0;
+}
+
 int pse_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 {
 	const struct nlattr *tb[ETHTOOL_A_PSE_MAX + 1] = {};
 	struct nl_context *nlctx = data;
+	const struct nlattr *attr;
 	DECLARE_ATTR_TB_INFO(tb);
 	bool silent;
 	int err_ret;
@@ -98,6 +349,77 @@ int pse_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 			     podl_pse_pw_d_status_name(val));
 	}
 
+	if (tb[ETHTOOL_A_C33_PSE_ADMIN_STATE]) {
+		u32 val;
+
+		val = mnl_attr_get_u32(tb[ETHTOOL_A_C33_PSE_ADMIN_STATE]);
+		print_string(PRINT_ANY, "c33-pse-admin-state",
+			     "Clause 33 PSE Admin State: %s\n",
+			     c33_pse_admin_state_name(val));
+	}
+
+	if (tb[ETHTOOL_A_C33_PSE_PW_D_STATUS]) {
+		u32 val;
+
+		val = mnl_attr_get_u32(tb[ETHTOOL_A_C33_PSE_PW_D_STATUS]);
+		print_string(PRINT_ANY, "c33-pse-power-detection-status",
+			     "Clause 33 PSE Power Detection Status: %s\n",
+			     c33_pse_pw_d_status_name(val));
+	}
+
+	if (tb[ETHTOOL_A_C33_PSE_EXT_STATE]) {
+		u32 val;
+
+		val = mnl_attr_get_u32(tb[ETHTOOL_A_C33_PSE_EXT_STATE]);
+		print_string(PRINT_ANY, "c33-pse-extended-state",
+			     "Clause 33 PSE Extended State: %s\n",
+			     c33_pse_ext_state_name(val));
+
+		if (tb[ETHTOOL_A_C33_PSE_EXT_SUBSTATE]) {
+			u32 substate;
+
+			substate = mnl_attr_get_u32(tb[ETHTOOL_A_C33_PSE_EXT_SUBSTATE]);
+			c33_pse_print_ext_substate(val, substate);
+		}
+	}
+
+	if (tb[ETHTOOL_A_C33_PSE_PW_CLASS]) {
+		u32 val;
+
+		val = mnl_attr_get_u32(tb[ETHTOOL_A_C33_PSE_PW_CLASS]);
+		print_uint(PRINT_ANY, "c33-pse-power-class",
+			   "Clause 33 PSE Power Class: %u\n", val);
+	}
+
+	if (tb[ETHTOOL_A_C33_PSE_ACTUAL_PW]) {
+		u32 val;
+
+		val = mnl_attr_get_u32(tb[ETHTOOL_A_C33_PSE_ACTUAL_PW]);
+		print_uint(PRINT_ANY, "c33-pse-actual-power",
+			   "Clause 33 PSE Actual Power: %u\n", val);
+	}
+
+	if (tb[ETHTOOL_A_C33_PSE_AVAIL_PW_LIMIT]) {
+		u32 val;
+
+		val = mnl_attr_get_u32(tb[ETHTOOL_A_C33_PSE_AVAIL_PW_LIMIT]);
+		print_uint(PRINT_ANY, "c33-pse-available-power-limit",
+			   "Clause 33 PSE Available Power Limit: %u\n", val);
+	}
+
+	if (tb[ETHTOOL_A_C33_PSE_PW_LIMIT_RANGES]) {
+		print_string(PRINT_ANY, "c33-pse-power-limit-ranges",
+			     "Clause 33 PSE Power Limit Ranges:\n", NULL);
+		mnl_attr_for_each(attr, nlhdr, GENL_HDRLEN) {
+			if (mnl_attr_get_type(attr) == ETHTOOL_A_C33_PSE_PW_LIMIT_RANGES) {
+				if (c33_pse_dump_pw_limit_range(attr)) {
+					close_json_object();
+					return err_ret;
+				}
+			}
+		}
+	}
+
 	close_json_object();
 
 	return MNL_CB_OK;
@@ -138,6 +460,12 @@ static const struct lookup_entry_u32 podl_pse_admin_control_values[] = {
 	{}
 };
 
+static const struct lookup_entry_u32 c33_pse_admin_control_values[] = {
+	{ .arg = "enable",	.val = ETHTOOL_C33_PSE_ADMIN_STATE_ENABLED },
+	{ .arg = "disable",	.val = ETHTOOL_C33_PSE_ADMIN_STATE_DISABLED },
+	{}
+};
+
 static const struct param_parser spse_params[] = {
 	{
 		.arg		= "podl-pse-admin-control",
@@ -146,6 +474,19 @@ static const struct param_parser spse_params[] = {
 		.handler_data	= podl_pse_admin_control_values,
 		.min_argc	= 1,
 	},
+	{
+		.arg		= "c33-pse-admin-control",
+		.type		= ETHTOOL_A_C33_PSE_ADMIN_CONTROL,
+		.handler	= nl_parse_lookup_u32,
+		.handler_data	= c33_pse_admin_control_values,
+		.min_argc	= 1,
+	},
+	{
+		.arg		= "c33-pse-avail-pw-limit",
+		.type		= ETHTOOL_A_C33_PSE_AVAIL_PW_LIMIT,
+		.handler	= nl_parse_direct_u32,
+		.min_argc	= 1,
+	},
 	{}
 };
 
@@ -174,8 +515,8 @@ int nl_spse(struct cmd_context *ctx)
 		       NLM_F_REQUEST | NLM_F_ACK);
 	if (ret < 0)
 		return 2;
-	if (ethnla_fill_header(msgbuff, ETHTOOL_A_PSE_HEADER,
-			       ctx->devname, 0))
+	if (ethnla_fill_header_phy(msgbuff, ETHTOOL_A_PSE_HEADER,
+				   ctx->devname, ctx->phy_index, 0))
 		return -EMSGSIZE;
 
 	ret = nl_parser(nlctx, spse_params, NULL, PARSER_GROUP_NONE, NULL);
diff --git a/netlink/rings.c b/netlink/rings.c
index 51d28c2..f9eb67a 100644
--- a/netlink/rings.c
+++ b/netlink/rings.c
@@ -116,6 +116,22 @@ int nl_gring(struct cmd_context *ctx)
 
 /* RINGS_SET */
 
+static const struct lookup_entry_u8 tcp_data_split_values[] = {
+	{
+		.arg		= "auto",
+		.val		= ETHTOOL_TCP_DATA_SPLIT_UNKNOWN,
+	},
+	{
+		.arg		= "off",
+		.val		= ETHTOOL_TCP_DATA_SPLIT_DISABLED,
+	},
+	{
+		.arg		= "on",
+		.val		= ETHTOOL_TCP_DATA_SPLIT_ENABLED,
+	},
+	{}
+};
+
 static const struct param_parser sring_params[] = {
 	{
 		.arg		= "rx",
@@ -153,6 +169,13 @@ static const struct param_parser sring_params[] = {
 		.handler        = nl_parse_direct_u32,
 		.min_argc       = 1,
 	},
+	{
+		.arg		= "tcp-data-split",
+		.type		= ETHTOOL_A_RINGS_TCP_DATA_SPLIT,
+		.handler	= nl_parse_lookup_u8,
+		.handler_data	= tcp_data_split_values,
+		.min_argc	= 1,
+	},
 	{
 		.arg            = "cqe-size",
 		.type           = ETHTOOL_A_RINGS_CQE_SIZE,
diff --git a/netlink/rss.c b/netlink/rss.c
index 4ad6065..0ee8a0d 100644
--- a/netlink/rss.c
+++ b/netlink/rss.c
@@ -21,7 +21,8 @@ struct cb_args {
 
 void dump_json_rss_info(struct cmd_context *ctx, u32 *indir_table,
 			u32 indir_size, u8 *hkey, u32 hkey_size,
-			const struct stringset *hash_funcs, u8 hfunc)
+			const struct stringset *hash_funcs, u8 hfunc,
+			u32 input_xfrm)
 {
 	unsigned int i;
 
@@ -46,6 +47,12 @@ void dump_json_rss_info(struct cmd_context *ctx, u32 *indir_table,
 			if (hfunc & (1 << i)) {
 				print_string(PRINT_JSON, "rss-hash-function",
 					     NULL, get_string(hash_funcs, i));
+				open_json_object("rss-input-transformation");
+				print_bool(PRINT_JSON, "symmetric-xor", NULL,
+					   (input_xfrm & RXH_XFRM_SYM_XOR) ?
+					   true : false);
+
+				close_json_object();
 				break;
 			}
 		}
@@ -54,29 +61,29 @@ void dump_json_rss_info(struct cmd_context *ctx, u32 *indir_table,
 	close_json_object();
 }
 
-int get_channels_cb(const struct nlmsghdr *nlhdr, void *data)
+/* There is no netlink equivalent for ETHTOOL_GRXRINGS. */
+static int get_num_rings(struct cb_args *args)
 {
-	const struct nlattr *tb[ETHTOOL_A_CHANNELS_MAX + 1] = {};
-	DECLARE_ATTR_TB_INFO(tb);
-	struct cb_args *args = data;
 	struct nl_context *nlctx = args->nlctx;
-	bool silent;
-	int err_ret;
+	struct cmd_context *ctx = nlctx->ctx;
+	struct ethtool_rxnfc ring_count = {
+		.cmd = ETHTOOL_GRXRINGS,
+	};
 	int ret;
 
-	silent = nlctx->is_dump || nlctx->is_monitor;
-	err_ret = silent ? MNL_CB_OK : MNL_CB_ERROR;
-	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
-	if (ret < 0)
-		return err_ret;
-	nlctx->devname = get_dev_name(tb[ETHTOOL_A_CHANNELS_HEADER]);
-	if (!dev_ok(nlctx))
-		return err_ret;
-	if (tb[ETHTOOL_A_CHANNELS_COMBINED_COUNT])
-		args->num_rings = mnl_attr_get_u32(tb[ETHTOOL_A_CHANNELS_COMBINED_COUNT]);
-	if (tb[ETHTOOL_A_CHANNELS_RX_COUNT])
-		args->num_rings += mnl_attr_get_u32(tb[ETHTOOL_A_CHANNELS_RX_COUNT]);
-	return MNL_CB_OK;
+	ret = ioctl_init(ctx, false);
+	if (ret)
+		return ret;
+
+	ret = send_ioctl(ctx, &ring_count);
+	if (ret) {
+		perror("Cannot get RX ring count");
+		return ret;
+	}
+
+	args->num_rings = (u32)ring_count.data;
+
+	return 0;
 }
 
 int rss_reply_cb(const struct nlmsghdr *nlhdr, void *data)
@@ -89,6 +96,7 @@ int rss_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 	const struct stringset *hash_funcs;
 	u32 rss_hfunc = 0, indir_size;
 	u32 *indir_table = NULL;
+	u32 input_xfrm = 0;
 	u8 *hkey = NULL;
 	bool silent;
 	int err_ret;
@@ -118,6 +126,9 @@ int rss_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 		hkey = mnl_attr_get_payload(tb[ETHTOOL_A_RSS_HKEY]);
 	}
 
+	if (tb[ETHTOOL_A_RSS_INPUT_XFRM])
+		input_xfrm = mnl_attr_get_u32(tb[ETHTOOL_A_RSS_INPUT_XFRM]);
+
 	/* Fetch RSS hash functions and their status and print */
 	if (!nlctx->is_monitor) {
 		ret = netlink_init_ethnl2_socket(nlctx);
@@ -131,29 +142,15 @@ int rss_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 	if (ret < 0)
 		return silent ? MNL_CB_OK : MNL_CB_ERROR;
 
-	nlctx->devname = get_dev_name(tb[ETHTOOL_A_RSS_HEADER]);
-	if (!dev_ok(nlctx))
-		return MNL_CB_OK;
-
-	/* Fetch ring count info into args->num_rings */
-	ret = nlsock_prep_get_request(nlctx->ethnl2_socket,
-				      ETHTOOL_MSG_CHANNELS_GET,
-				      ETHTOOL_A_CHANNELS_HEADER, 0);
-	if (ret < 0)
-		return MNL_CB_ERROR;
-
-	ret = nlsock_sendmsg(nlctx->ethnl2_socket, NULL);
-	if (ret < 0)
-		return MNL_CB_ERROR;
-
-	ret = nlsock_process_reply(nlctx->ethnl2_socket, get_channels_cb, args);
+	ret = get_num_rings(args);
 	if (ret < 0)
 		return MNL_CB_ERROR;
 
 	indir_size = indir_bytes / sizeof(u32);
 	if (is_json_context()) {
 		dump_json_rss_info(nlctx->ctx, (u32 *)indir_table, indir_size,
-				   hkey, hkey_bytes, hash_funcs, rss_hfunc);
+				   hkey, hkey_bytes, hash_funcs, rss_hfunc,
+				   input_xfrm);
 	} else {
 		print_indir_table(nlctx->ctx, args->num_rings,
 				  indir_size, (u32 *)indir_table);
@@ -167,6 +164,9 @@ int rss_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 			printf("    %s: %s\n", get_string(hash_funcs, i),
 			       (rss_hfunc & (1 << i)) ? "on" : "off");
 		}
+		printf("RSS input transformation:\n");
+		printf("    symmetric-xor: %s\n",
+		       (input_xfrm & RXH_XFRM_SYM_XOR) ? "on" : "off");
 	}
 
 	return MNL_CB_OK;
diff --git a/netlink/settings.c b/netlink/settings.c
index a506618..3008258 100644
--- a/netlink/settings.c
+++ b/netlink/settings.c
@@ -11,6 +11,8 @@
 
 #include "../internal.h"
 #include "../common.h"
+#include "json_print.h"
+#include "json_writer.h"
 #include "netlink.h"
 #include "strset.h"
 #include "bitset.h"
@@ -175,6 +177,7 @@ static const struct link_mode_info link_modes[] = {
 	[ETHTOOL_LINK_MODE_10baseT1S_Full_BIT]		= __REAL(10),
 	[ETHTOOL_LINK_MODE_10baseT1S_Half_BIT]		= __HALF_DUPLEX(10),
 	[ETHTOOL_LINK_MODE_10baseT1S_P2MP_Half_BIT]	= __HALF_DUPLEX(10),
+	[ETHTOOL_LINK_MODE_10baseT1BRR_Full_BIT]	= __REAL(10),
 };
 const unsigned int link_modes_count = ARRAY_SIZE(link_modes);
 
@@ -192,15 +195,21 @@ static bool lm_class_match(unsigned int mode, enum link_mode_class class)
 }
 
 static void print_enum(const char *const *info, unsigned int n_info,
-		       unsigned int val, const char *label)
+		       unsigned int val, const char *label, const char *json_key)
 {
-	if (val >= n_info || !info[val])
-		printf("\t%s: Unknown! (%d)\n", label, val);
-	else
-		printf("\t%s: %s\n", label, info[val]);
+	if (val >= n_info || !info[val]) {
+		if (!is_json_context())
+			printf("\t%s: Unknown! (%d)\n", label, val);
+	} else {
+		if (!is_json_context())
+			printf("\t%s: %s\n", label, info[val]);
+		else
+			print_string(PRINT_JSON, json_key, "%s", info[val]);
+	}
 }
 
-static int dump_pause(const struct nlattr *attr, bool mask, const char *label)
+static int dump_pause(const struct nlattr *attr, bool mask, const char *label,
+		      const char *label_json)
 {
 	bool pause, asym;
 	int ret = 0;
@@ -213,11 +222,13 @@ static int dump_pause(const struct nlattr *attr, bool mask, const char *label)
 	if (ret < 0)
 		goto err;
 
-	printf("\t%s", label);
+	if (!is_json_context())
+		printf("\t%s", label);
 	if (pause)
-		printf("%s\n", asym ?  "Symmetric Receive-only" : "Symmetric");
+		print_string(PRINT_ANY, label_json, "%s\n",
+			     asym ?  "Symmetric Receive-only" : "Symmetric");
 	else
-		printf("%s\n", asym ? "Transmit-only" : "No");
+		print_string(PRINT_ANY, label_json, "%s\n", asym ? "Transmit-only" : "No");
 
 	return 0;
 err:
@@ -229,13 +240,14 @@ static void print_banner(struct nl_context *nlctx)
 {
 	if (nlctx->no_banner)
 		return;
-	printf("Settings for %s:\n", nlctx->devname);
+	print_string(PRINT_ANY, "ifname", "Settings for %s:\n", nlctx->devname);
 	nlctx->no_banner = true;
 }
 
 int dump_link_modes(struct nl_context *nlctx, const struct nlattr *bitset,
 		    bool mask, unsigned int class, const char *before,
-		    const char *between, const char *after, const char *if_none)
+		    const char *between, const char *after, const char *if_none,
+		    const char *json_key)
 {
 	const struct nlattr *bitset_tb[ETHTOOL_A_BITSET_MAX + 1] = {};
 	DECLARE_ATTR_TB_INFO(bitset_tb);
@@ -260,6 +272,7 @@ int dump_link_modes(struct nl_context *nlctx, const struct nlattr *bitset,
 
 	bits = bitset_tb[ETHTOOL_A_BITSET_BITS];
 
+	open_json_array(json_key, "");
 	if (!bits) {
 		const struct stringset *lm_strings;
 		unsigned int count;
@@ -280,7 +293,9 @@ int dump_link_modes(struct nl_context *nlctx, const struct nlattr *bitset,
 		if (mnl_attr_get_payload_len(bits) / 4 < (count + 31) / 32)
 			goto err_nonl;
 
-		printf("\t%s", before);
+		if (!is_json_context())
+			printf("\t%s", before);
+
 		for (idx = 0; idx < count; idx++) {
 			const uint32_t *raw_data = mnl_attr_get_payload(bits);
 			char buff[14];
@@ -298,21 +313,27 @@ int dump_link_modes(struct nl_context *nlctx, const struct nlattr *bitset,
 				first = false;
 			/* ugly hack to preserve old output format */
 			if (class == LM_CLASS_REAL && (idx == prev + 1) &&
-			    prev < link_modes_count &&
-			    link_modes[prev].class == LM_CLASS_REAL &&
-			    link_modes[prev].duplex == DUPLEX_HALF)
-				putchar(' ');
-			else if (between)
-				printf("\t%s", between);
+				prev < link_modes_count &&
+				link_modes[prev].class == LM_CLASS_REAL &&
+				link_modes[prev].duplex == DUPLEX_HALF) {
+				if (!is_json_context())
+					putchar(' ');
+			} else if (between) {
+				if (!is_json_context())
+					printf("\t%s", between);
+			}
 			else
-				printf("\n\t%*s", before_len, "");
-			printf("%s", name);
+				if (!is_json_context())
+					printf("\n\t%*s", before_len, "");
+			print_string(PRINT_ANY, NULL, "%s", name);
 			prev = idx;
 		}
 		goto after;
 	}
 
-	printf("\t%s", before);
+	if (!is_json_context())
+		printf("\t%s", before);
+
 	mnl_attr_for_each_nested(bit, bits) {
 		const struct nlattr *tb[ETHTOOL_A_BITSET_BIT_MAX + 1] = {};
 		DECLARE_ATTR_TB_INFO(tb);
@@ -342,27 +363,31 @@ int dump_link_modes(struct nl_context *nlctx, const struct nlattr *bitset,
 			if ((class == LM_CLASS_REAL) && (idx == prev + 1) &&
 			    (prev < link_modes_count) &&
 			    (link_modes[prev].class == LM_CLASS_REAL) &&
-			    (link_modes[prev].duplex == DUPLEX_HALF))
-				putchar(' ');
-			else if (between)
-				printf("\t%s", between);
+			    (link_modes[prev].duplex == DUPLEX_HALF)) {
+				if (!is_json_context())
+					putchar(' ');
+			} else if (between) {
+				if (!is_json_context())
+					printf("\t%s", between);
+			}
 			else
-				printf("\n\t%*s", before_len, "");
+				if (!is_json_context())
+					printf("\n\t%*s", before_len, "");
 		}
-		printf("%s", name);
+		print_string(PRINT_ANY, NULL, "%s", name);
 		prev = idx;
 	}
 after:
 	if (first && if_none)
-		printf("%s", if_none);
-	printf("%s", after);
-
+		print_string(PRINT_FP, NULL, "%s", if_none);
+	close_json_array(after);
 	return 0;
 err:
 	putchar('\n');
 err_nonl:
 	fflush(stdout);
 	fprintf(stderr, "malformed netlink message (link_modes)\n");
+	close_json_array("");
 	return ret;
 }
 
@@ -373,16 +398,16 @@ static int dump_our_modes(struct nl_context *nlctx, const struct nlattr *attr)
 
 	print_banner(nlctx);
 	ret = dump_link_modes(nlctx, attr, true, LM_CLASS_PORT,
-			      "Supported ports: [ ", " ", " ]\n", NULL);
+			      "Supported ports: [ ", " ", " ]\n", NULL, "supported-ports");
 	if (ret < 0)
 		return ret;
 
 	ret = dump_link_modes(nlctx, attr, true, LM_CLASS_REAL,
 			      "Supported link modes:   ", NULL, "\n",
-			      "Not reported");
+			      "Not reported", "supported-link-modes");
 	if (ret < 0)
 		return ret;
-	ret = dump_pause(attr, true, "Supported pause frame use: ");
+	ret = dump_pause(attr, true, "Supported pause frame use: ", "supported-pause-frame-use");
 	if (ret < 0)
 		return ret;
 
@@ -390,32 +415,40 @@ static int dump_our_modes(struct nl_context *nlctx, const struct nlattr *attr)
 				 &ret);
 	if (ret < 0)
 		return ret;
-	printf("\tSupports auto-negotiation: %s\n", autoneg ? "Yes" : "No");
+
+	if (is_json_context())
+		print_bool(PRINT_JSON, "supports-auto-negotiation", NULL, autoneg);
+	else
+		printf("\tSupports auto-negotiation: %s\n", autoneg ? "Yes" : "No");
 
 	ret = dump_link_modes(nlctx, attr, true, LM_CLASS_FEC,
 			      "Supported FEC modes: ", " ", "\n",
-			      "Not reported");
+			      "Not reported", "supported-fec-modes");
 	if (ret < 0)
 		return ret;
 
 	ret = dump_link_modes(nlctx, attr, false, LM_CLASS_REAL,
 			      "Advertised link modes:  ", NULL, "\n",
-			      "Not reported");
+			      "Not reported", "advertised-link-modes");
 	if (ret < 0)
 		return ret;
 
-	ret = dump_pause(attr, false, "Advertised pause frame use: ");
+	ret = dump_pause(attr, false, "Advertised pause frame use: ", "advertised-pause-frame-use");
 	if (ret < 0)
 		return ret;
 	autoneg = bitset_get_bit(attr, false, ETHTOOL_LINK_MODE_Autoneg_BIT,
 				 &ret);
 	if (ret < 0)
 		return ret;
-	printf("\tAdvertised auto-negotiation: %s\n", autoneg ? "Yes" : "No");
+
+	if (!is_json_context())
+		printf("\tAdvertised auto-negotiation: %s\n", autoneg ? "Yes" : "No");
+	else
+		print_bool(PRINT_JSON, "advertised-auto-negotiation", NULL, autoneg);
 
 	ret = dump_link_modes(nlctx, attr, false, LM_CLASS_FEC,
 			      "Advertised FEC modes: ", " ", "\n",
-			      "Not reported");
+			      "Not reported", "advertised-fec-modes");
 	return ret;
 }
 
@@ -427,12 +460,13 @@ static int dump_peer_modes(struct nl_context *nlctx, const struct nlattr *attr)
 	print_banner(nlctx);
 	ret = dump_link_modes(nlctx, attr, false, LM_CLASS_REAL,
 			      "Link partner advertised link modes:  ",
-			      NULL, "\n", "Not reported");
+			      NULL, "\n", "Not reported", "link-partner-advertised-link-modes");
 	if (ret < 0)
 		return ret;
 
 	ret = dump_pause(attr, false,
-			 "Link partner advertised pause frame use: ");
+			 "Link partner advertised pause frame use: ",
+			 "link-partner-advertised-pause-frame-use");
 	if (ret < 0)
 		return ret;
 
@@ -440,12 +474,16 @@ static int dump_peer_modes(struct nl_context *nlctx, const struct nlattr *attr)
 				 ETHTOOL_LINK_MODE_Autoneg_BIT, &ret);
 	if (ret < 0)
 		return ret;
-	printf("\tLink partner advertised auto-negotiation: %s\n",
-	       autoneg ? "Yes" : "No");
+
+	if (!is_json_context())
+		print_string(PRINT_FP, NULL, "\tLink partner advertised auto-negotiation: %s\n",
+			autoneg ? "Yes" : "No");
+	else
+		print_bool(PRINT_JSON, "link-partner-advertised-auto-negotiation", NULL, autoneg);
 
 	ret = dump_link_modes(nlctx, attr, false, LM_CLASS_FEC,
 			      "Link partner advertised FEC modes: ",
-			      " ", "\n", "Not reported");
+			      " ", "\n", "Not reported", "link-partner-advertised-fec-modes");
 	return ret;
 }
 
@@ -479,30 +517,36 @@ int linkmodes_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 		uint32_t val = mnl_attr_get_u32(tb[ETHTOOL_A_LINKMODES_SPEED]);
 
 		print_banner(nlctx);
-		if (val == 0 || val == (uint16_t)(-1) || val == (uint32_t)(-1))
-			printf("\tSpeed: Unknown!\n");
-		else
-			printf("\tSpeed: %uMb/s\n", val);
+		if (val == 0 || val == (uint16_t)(-1) || val == (uint32_t)(-1)) {
+			if (!is_json_context())
+				printf("\tSpeed: Unknown!\n");
+		} else {
+			print_uint(PRINT_ANY, "speed", "\tSpeed: %uMb/s\n", val);
+		}
 	}
 	if (tb[ETHTOOL_A_LINKMODES_LANES]) {
 		uint32_t val = mnl_attr_get_u32(tb[ETHTOOL_A_LINKMODES_LANES]);
 
 		print_banner(nlctx);
-		printf("\tLanes: %u\n", val);
+		print_uint(PRINT_ANY, "lanes", "\tLanes: %u\n", val);
 	}
 	if (tb[ETHTOOL_A_LINKMODES_DUPLEX]) {
 		uint8_t val = mnl_attr_get_u8(tb[ETHTOOL_A_LINKMODES_DUPLEX]);
 
 		print_banner(nlctx);
 		print_enum(names_duplex, ARRAY_SIZE(names_duplex), val,
-			   "Duplex");
+			   "Duplex", "duplex");
 	}
 	if (tb[ETHTOOL_A_LINKMODES_AUTONEG]) {
 		int autoneg = mnl_attr_get_u8(tb[ETHTOOL_A_LINKMODES_AUTONEG]);
 
 		print_banner(nlctx);
-		printf("\tAuto-negotiation: %s\n",
-		       (autoneg == AUTONEG_DISABLE) ? "off" : "on");
+		if (!is_json_context())
+			printf("\tAuto-negotiation: %s\n",
+						(autoneg == AUTONEG_DISABLE) ? "off" : "on");
+		else
+			print_bool(PRINT_JSON, "auto-negotiation", NULL,
+				   autoneg != AUTONEG_DISABLE);
 	}
 	if (tb[ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG]) {
 		uint8_t val;
@@ -512,7 +556,7 @@ int linkmodes_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 		print_banner(nlctx);
 		print_enum(names_master_slave_cfg,
 			   ARRAY_SIZE(names_master_slave_cfg), val,
-			   "master-slave cfg");
+			   "master-slave cfg", "master-slave-cfg");
 	}
 	if (tb[ETHTOOL_A_LINKMODES_MASTER_SLAVE_STATE]) {
 		uint8_t val;
@@ -521,14 +565,14 @@ int linkmodes_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 		print_banner(nlctx);
 		print_enum(names_master_slave_state,
 			   ARRAY_SIZE(names_master_slave_state), val,
-			   "master-slave status");
+			   "master-slave status", "master-slave-status");
 	}
 
 	return MNL_CB_OK;
 err:
 	if (nlctx->is_monitor || nlctx->is_dump)
 		return MNL_CB_OK;
-	fputs("No data available\n", stdout);
+	fputs("No data available\n", stderr);
 	nlctx->exit_code = 75;
 	return MNL_CB_ERROR;
 }
@@ -554,14 +598,14 @@ int linkinfo_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 		uint8_t val = mnl_attr_get_u8(tb[ETHTOOL_A_LINKINFO_PORT]);
 
 		print_banner(nlctx);
-		print_enum(names_port, ARRAY_SIZE(names_port), val, "Port");
+		print_enum(names_port, ARRAY_SIZE(names_port), val, "Port", "port");
 		port = val;
 	}
 	if (tb[ETHTOOL_A_LINKINFO_PHYADDR]) {
 		uint8_t val = mnl_attr_get_u8(tb[ETHTOOL_A_LINKINFO_PHYADDR]);
 
 		print_banner(nlctx);
-		printf("\tPHYAD: %u\n", val);
+		print_uint(PRINT_ANY, "phyad", "\tPHYAD: %u\n", val);
 	}
 	if (tb[ETHTOOL_A_LINKINFO_TRANSCEIVER]) {
 		uint8_t val;
@@ -569,7 +613,7 @@ int linkinfo_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 		val = mnl_attr_get_u8(tb[ETHTOOL_A_LINKINFO_TRANSCEIVER]);
 		print_banner(nlctx);
 		print_enum(names_transceiver, ARRAY_SIZE(names_transceiver),
-			   val, "Transceiver");
+			   val, "Transceiver", "transceiver");
 	}
 	if (tb[ETHTOOL_A_LINKINFO_TP_MDIX] && tb[ETHTOOL_A_LINKINFO_TP_MDIX_CTRL] &&
 	    port == PORT_TP) {
@@ -714,9 +758,9 @@ static void linkstate_link_ext_substate_print(const struct nlattr *tb[],
 
 	link_ext_substate_str = link_ext_substate_get(link_ext_state_val, link_ext_substate_val);
 	if (!link_ext_substate_str)
-		printf(", %u", link_ext_substate_val);
+		print_uint(PRINT_ANY, NULL, ", %u", link_ext_state_val);
 	else
-		printf(", %s", link_ext_substate_str);
+		print_string(PRINT_ANY, NULL, ", %s", link_ext_substate_str);
 }
 
 static void linkstate_link_ext_state_print(const struct nlattr *tb[])
@@ -732,13 +776,14 @@ static void linkstate_link_ext_state_print(const struct nlattr *tb[])
 	link_ext_state_str = get_enum_string(names_link_ext_state,
 					     ARRAY_SIZE(names_link_ext_state),
 					     link_ext_state_val);
+	open_json_array("link-state", "");
 	if (!link_ext_state_str)
-		printf(" (%u", link_ext_state_val);
+		print_uint(PRINT_ANY, NULL, " (%u", link_ext_state_val);
 	else
-		printf(" (%s", link_ext_state_str);
+		print_string(PRINT_ANY, NULL, " (%s", link_ext_state_str);
 
 	linkstate_link_ext_substate_print(tb, link_ext_state_val);
-	printf(")");
+	close_json_array(")");
 }
 
 int linkstate_reply_cb(const struct nlmsghdr *nlhdr, void *data)
@@ -761,24 +806,29 @@ int linkstate_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 		uint8_t val = mnl_attr_get_u8(tb[ETHTOOL_A_LINKSTATE_LINK]);
 
 		print_banner(nlctx);
-		printf("\tLink detected: %s", val ? "yes" : "no");
+		if (!is_json_context())
+			print_string(PRINT_FP, NULL, "\tLink detected: %s", val ? "yes" : "no");
+		else
+			print_bool(PRINT_JSON, "link-detected", NULL, val);
 		linkstate_link_ext_state_print(tb);
-		printf("\n");
+		if (!is_json_context())
+			printf("\n");
 	}
 
 	if (tb[ETHTOOL_A_LINKSTATE_SQI]) {
 		uint32_t val = mnl_attr_get_u32(tb[ETHTOOL_A_LINKSTATE_SQI]);
 
 		print_banner(nlctx);
-		printf("\tSQI: %u", val);
+		print_uint(PRINT_ANY, "sqi", "\tSQI: %u", val);
 
 		if (tb[ETHTOOL_A_LINKSTATE_SQI_MAX]) {
 			uint32_t max;
 
 			max = mnl_attr_get_u32(tb[ETHTOOL_A_LINKSTATE_SQI_MAX]);
-			printf("/%u\n", max);
+			print_uint(PRINT_ANY, "sqi-max", "/%u\n", max);
 		} else {
-			printf("\n");
+			if (!is_json_context())
+				printf("\n");
 		}
 	}
 
@@ -786,7 +836,7 @@ int linkstate_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 		uint32_t val;
 
 		val = mnl_attr_get_u32(tb[ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT]);
-		printf("\tLink Down Events: %u\n", val);
+		print_uint(PRINT_ANY, "link-down-events", "\tLink Down Events: %u\n", val);
 	}
 
 	return MNL_CB_OK;
@@ -856,7 +906,7 @@ void msgmask_cb2(unsigned int idx __maybe_unused, const char *name,
 		 bool val, void *data __maybe_unused)
 {
 	if (val)
-		printf(" %s", name);
+		print_string(PRINT_FP, NULL, " %s", name);
 }
 
 int debug_reply_cb(const struct nlmsghdr *nlhdr, void *data)
@@ -889,13 +939,16 @@ int debug_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 
 	print_banner(nlctx);
 	walk_bitset(tb[ETHTOOL_A_DEBUG_MSGMASK], NULL, msgmask_cb, &msg_mask);
-	printf("        Current message level: 0x%08x (%u)\n"
-	       "                              ",
-	       msg_mask, msg_mask);
+
+	print_uint(PRINT_ANY, "current-message-level",
+		   "        Current message level: 0x%1$08x (%1$u)\n                              ",
+		   msg_mask);
+
 	walk_bitset(tb[ETHTOOL_A_DEBUG_MSGMASK], msgmask_strings, msgmask_cb2,
-		    NULL);
-	fputc('\n', stdout);
+			NULL);
 
+	if (!is_json_context())
+		fputc('\n', stdout);
 	return MNL_CB_OK;
 }
 
@@ -916,18 +969,26 @@ int plca_cfg_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 		return MNL_CB_OK;
 
 	print_banner(nlctx);
-	printf("\tPLCA support: ");
+	if (!is_json_context())
+		printf("\tPLCA support: ");
 
 	if (tb[ETHTOOL_A_PLCA_VERSION]) {
 		uint16_t val = mnl_attr_get_u16(tb[ETHTOOL_A_PLCA_VERSION]);
 
-		printf("OPEN Alliance v%u.%u",
-		       (unsigned int)((val >> 4) & 0xF),
-		       (unsigned int)(val & 0xF));
-	} else
-		printf("non-standard");
+		if (!is_json_context()) {
+			printf("OPEN Alliance v%u.%u\n",
+			(unsigned int)((val >> 4) & 0xF),
+			(unsigned int)(val & 0xF));
+		} else {
+			unsigned int length = snprintf(NULL, 0, "%1$u.%1$u", val);
+			char buff[length];
 
-	printf("\n");
+			snprintf(buff, length, "%u.%u", (unsigned int)((val >> 4) & 0xF),
+				(unsigned int)(val & 0xF));
+			print_string(PRINT_JSON, "open-alliance-v", NULL, buff);
+		}
+	} else
+		print_string(PRINT_ANY, "plca-support", "%s\n", "non-standard");
 
 	return MNL_CB_OK;
 }
@@ -949,16 +1010,14 @@ int plca_status_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 		return MNL_CB_OK;
 
 	print_banner(nlctx);
-	printf("\tPLCA status: ");
-
+	const char *status;
 	if (tb[ETHTOOL_A_PLCA_STATUS]) {
 		uint8_t val = mnl_attr_get_u8(tb[ETHTOOL_A_PLCA_STATUS]);
-
-		printf(val ? "up" : "down");
-	} else
-		printf("unknown");
-
-	printf("\n");
+		status = val ? "up" : "down";
+		print_string(PRINT_ANY, "plca-status", "PLCA status: %s", status);
+	} else {
+		print_string(PRINT_FP, NULL, "PLCA status: %s", "unknown");
+	}
 
 	return MNL_CB_OK;
 }
@@ -984,7 +1043,10 @@ static int gset_request(struct cmd_context *ctx, uint8_t msg_type,
 
 int nl_gset(struct cmd_context *ctx)
 {
-	int ret;
+	int ret = 0;
+
+	new_json_obj(ctx->json);
+	open_json_object(NULL);
 
 	/* Check for the base set of commands */
 	if (netlink_cmd_check(ctx, ETHTOOL_MSG_LINKMODES_GET, true) ||
@@ -999,44 +1061,50 @@ int nl_gset(struct cmd_context *ctx)
 	ret = gset_request(ctx, ETHTOOL_MSG_LINKMODES_GET,
 			   ETHTOOL_A_LINKMODES_HEADER, linkmodes_reply_cb);
 	if (ret == -ENODEV)
-		return ret;
+		goto out;
 
 	ret = gset_request(ctx, ETHTOOL_MSG_LINKINFO_GET,
 			   ETHTOOL_A_LINKINFO_HEADER, linkinfo_reply_cb);
 	if (ret == -ENODEV)
-		return ret;
+		goto out;
 
 	ret = gset_request(ctx, ETHTOOL_MSG_WOL_GET, ETHTOOL_A_WOL_HEADER,
 			   wol_reply_cb);
 	if (ret == -ENODEV)
-		return ret;
+		goto out;
 
 	ret = gset_request(ctx, ETHTOOL_MSG_PLCA_GET_CFG,
 			   ETHTOOL_A_PLCA_HEADER, plca_cfg_reply_cb);
 	if (ret == -ENODEV)
-		return ret;
+		goto out;
 
 	ret = gset_request(ctx, ETHTOOL_MSG_DEBUG_GET, ETHTOOL_A_DEBUG_HEADER,
 			   debug_reply_cb);
 	if (ret == -ENODEV)
-		return ret;
+		goto out;
 
 	ret = gset_request(ctx, ETHTOOL_MSG_LINKSTATE_GET,
 			   ETHTOOL_A_LINKSTATE_HEADER, linkstate_reply_cb);
 	if (ret == -ENODEV)
-		return ret;
+		goto out;
 
 	ret = gset_request(ctx, ETHTOOL_MSG_PLCA_GET_STATUS,
 			   ETHTOOL_A_PLCA_HEADER, plca_status_reply_cb);
 	if (ret == -ENODEV)
-		return ret;
+		goto out;
 
 	if (!ctx->nlctx->no_banner) {
-		printf("No data available\n");
-		return 75;
+		print_string(PRINT_FP, NULL, "%s", "No data available\n");
+		ret = 75;
+		goto out;
 	}
 
-	return 0;
+	ret = 0;
+
+out:
+	close_json_object();
+	delete_json_obj();
+	return ret;
 }
 
 /* SET_SETTINGS */
diff --git a/netlink/strset.c b/netlink/strset.c
index fbc9c17..949d597 100644
--- a/netlink/strset.c
+++ b/netlink/strset.c
@@ -118,7 +118,7 @@ static struct perdev_strings *get_perdev_by_ifindex(int ifindex)
 		return perdev;
 
 	/* not found, allocate and insert into list */
-	perdev = calloc(sizeof(*perdev), 1);
+	perdev = calloc(1, sizeof(*perdev));
 	if (!perdev)
 		return NULL;
 	perdev->ifindex = ifindex;
diff --git a/netlink/tsinfo.c b/netlink/tsinfo.c
index c6571ff..4df4141 100644
--- a/netlink/tsinfo.c
+++ b/netlink/tsinfo.c
@@ -5,6 +5,7 @@
  */
 
 #include <errno.h>
+#include <inttypes.h>
 #include <string.h>
 #include <stdio.h>
 
@@ -15,6 +16,60 @@
 
 /* TSINFO_GET */
 
+static int tsinfo_show_stats(const struct nlattr *nest)
+{
+	const struct nlattr *tb[ETHTOOL_A_TS_STAT_MAX + 1] = {};
+	DECLARE_ATTR_TB_INFO(tb);
+	static const struct {
+		unsigned int attr;
+		char *name;
+	} stats[] = {
+		{ ETHTOOL_A_TS_STAT_TX_PKTS, "tx_pkts" },
+		{ ETHTOOL_A_TS_STAT_TX_LOST, "tx_lost" },
+		{ ETHTOOL_A_TS_STAT_TX_ERR, "tx_err" },
+	};
+	bool header = false;
+	unsigned int i;
+	__u64 val;
+	int ret;
+
+	ret = mnl_attr_parse_nested(nest, attr_cb, &tb_info);
+	if (ret < 0)
+		return ret;
+
+	open_json_object("statistics");
+	for (i = 0; i < ARRAY_SIZE(stats); i++) {
+		char fmt[64];
+
+		if (!tb[stats[i].attr])
+			continue;
+
+		if (!header && !is_json_context()) {
+			printf("Statistics:\n");
+			header = true;
+		}
+
+		if (!mnl_attr_validate(tb[stats[i].attr], MNL_TYPE_U32)) {
+			val = mnl_attr_get_u32(tb[stats[i].attr]);
+		} else if (!mnl_attr_validate(tb[stats[i].attr], MNL_TYPE_U64)) {
+			val = mnl_attr_get_u64(tb[stats[i].attr]);
+		} else {
+			fprintf(stderr, "malformed netlink message (statistic)\n");
+			goto err_close_stats;
+		}
+
+		snprintf(fmt, sizeof(fmt), "  %s: %%" PRIu64 "\n", stats[i].name);
+		print_u64(PRINT_ANY, stats[i].name, fmt, val);
+	}
+	close_json_object();
+
+	return 0;
+
+err_close_stats:
+	close_json_object();
+	return -1;
+}
+
 static void tsinfo_dump_cb(unsigned int idx, const char *name, bool val,
 			   void *data __maybe_unused)
 {
@@ -99,6 +154,12 @@ int tsinfo_reply_cb(const struct nlmsghdr *nlhdr, void *data)
 	if (ret < 0)
 		return err_ret;
 
+	if (tb[ETHTOOL_A_TSINFO_STATS]) {
+		ret = tsinfo_show_stats(tb[ETHTOOL_A_TSINFO_STATS]);
+		if (ret < 0)
+			return err_ret;
+	}
+
 	return MNL_CB_OK;
 }
 
@@ -106,6 +167,7 @@ int nl_tsinfo(struct cmd_context *ctx)
 {
 	struct nl_context *nlctx = ctx->nlctx;
 	struct nl_socket *nlsk = nlctx->ethnl_socket;
+	u32 flags;
 	int ret;
 
 	if (netlink_cmd_check(ctx, ETHTOOL_MSG_TSINFO_GET, true))
@@ -116,8 +178,9 @@ int nl_tsinfo(struct cmd_context *ctx)
 		return 1;
 	}
 
+	flags = get_stats_flag(nlctx, ETHTOOL_MSG_TSINFO_GET, ETHTOOL_A_TSINFO_HEADER);
 	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_TSINFO_GET,
-				      ETHTOOL_A_TSINFO_HEADER, 0);
+				      ETHTOOL_A_TSINFO_HEADER, flags);
 	if (ret < 0)
 		return ret;
 	return nlsock_send_get_request(nlsk, tsinfo_reply_cb);
diff --git a/qsfp.c b/qsfp.c
index 5a535c5..a3a919d 100644
--- a/qsfp.c
+++ b/qsfp.c
@@ -977,15 +977,20 @@ void sff8636_show_all_ioctl(const __u8 *id, __u32 eeprom_len)
 {
 	struct sff8636_memory_map map = {};
 
-	if (id[SFF8636_ID_OFFSET] == SFF8024_ID_QSFP_DD ||
-	    id[SFF8636_ID_OFFSET] == SFF8024_ID_OSFP ||
-	    id[SFF8636_ID_OFFSET] == SFF8024_ID_DSFP) {
+	switch (id[SFF8636_ID_OFFSET]) {
+	case SFF8024_ID_QSFP_DD:
+	case SFF8024_ID_OSFP:
+	case SFF8024_ID_DSFP:
+	case SFF8024_ID_QSFP_PLUS_CMIS:
+	case SFF8024_ID_SFP_DD_CMIS:
+	case SFF8024_ID_SFP_PLUS_CMIS:
 		cmis_show_all_ioctl(id);
-		return;
+		break;
+	default:
+		sff8636_memory_map_init_buf(&map, id, eeprom_len);
+		sff8636_show_all_common(&map);
+		break;
 	}
-
-	sff8636_memory_map_init_buf(&map, id, eeprom_len);
-	sff8636_show_all_common(&map);
 }
 
 static void sff8636_request_init(struct ethtool_module_eeprom *request, u8 page,
@@ -1033,8 +1038,15 @@ sff8636_memory_map_init_pages(struct cmd_context *ctx,
 
 	sff8636_request_init(&request, 0x3, SFF8636_PAGE_SIZE);
 	ret = nl_get_eeprom_page(ctx, &request);
-	if (ret < 0)
-		return ret;
+	if (ret < 0) {
+		/* Page 03h is not available due to a bug in the driver.
+		 * This is a non-fatal error and sff8636_dom_parse()
+		 * handles this correctly.
+		 */
+		fprintf(stderr, "Failed to read Upper Page 03h, driver error?\n");
+		return 0;
+	}
+
 	map->page_03h = request.data - SFF8636_PAGE_SIZE;
 
 	return 0;
diff --git a/rxclass.c b/rxclass.c
index f17e3a5..1e202cc 100644
--- a/rxclass.c
+++ b/rxclass.c
@@ -248,13 +248,17 @@ static void rxclass_print_nfc_rule(struct ethtool_rx_flow_spec *fsp,
 
 	rxclass_print_nfc_spec_ext(fsp);
 
-	if (fsp->flow_type & FLOW_RSS)
-		fprintf(stdout, "\tRSS Context ID: %u\n", rss_context);
-
 	if (fsp->ring_cookie == RX_CLS_FLOW_DISC) {
 		fprintf(stdout, "\tAction: Drop\n");
 	} else if (fsp->ring_cookie == RX_CLS_FLOW_WAKE) {
 		fprintf(stdout, "\tAction: Wake-on-LAN\n");
+	} else if (fsp->flow_type & FLOW_RSS) {
+		u64 queue = ethtool_get_flow_spec_ring(fsp->ring_cookie);
+
+		fprintf(stdout, "\tAction: Direct to RSS Context %u", rss_context);
+		if (queue)
+			fprintf(stdout, " (queue base offset: %llu)", queue);
+		fprintf(stdout, "\n");
 	} else {
 		u64 vf = ethtool_get_flow_spec_ring_vf(fsp->ring_cookie);
 		u64 queue = ethtool_get_flow_spec_ring(fsp->ring_cookie);
diff --git a/sff-common.c b/sff-common.c
index a5c1510..a412a6e 100644
--- a/sff-common.c
+++ b/sff-common.c
@@ -162,6 +162,15 @@ void sff8024_show_identifier(const __u8 *id, int id_offset)
 	case SFF8024_ID_DSFP:
 		printf(" (DSFP Dual Small Form Factor Pluggable Transceiver)\n");
 		break;
+	case SFF8024_ID_QSFP_PLUS_CMIS:
+		printf(" (QSFP+ or later with Common Management Interface Specification (CMIS))\n");
+		break;
+	case SFF8024_ID_SFP_DD_CMIS:
+		printf(" (SFP-DD Double Density 2X Pluggable Transceiver with Common Management Interface Specification (CMIS))\n");
+		break;
+	case SFF8024_ID_SFP_PLUS_CMIS:
+		printf(" (SFP+ and later with Common Management Interface Specification (CMIS))\n");
+		break;
 	default:
 		printf(" (reserved or unknown)\n");
 		break;
diff --git a/sff-common.h b/sff-common.h
index 57bcc4a..899dc5b 100644
--- a/sff-common.h
+++ b/sff-common.h
@@ -64,7 +64,10 @@
 #define  SFF8024_ID_QSFP_DD				0x18
 #define  SFF8024_ID_OSFP				0x19
 #define  SFF8024_ID_DSFP				0x1B
-#define  SFF8024_ID_LAST				SFF8024_ID_DSFP
+#define  SFF8024_ID_QSFP_PLUS_CMIS			0x1E
+#define  SFF8024_ID_SFP_DD_CMIS				0x1F
+#define  SFF8024_ID_SFP_PLUS_CMIS			0x20
+#define  SFF8024_ID_LAST				SFF8024_ID_SFP_PLUS_CMIS
 #define  SFF8024_ID_UNALLOCATED_LAST	0x7F
 #define  SFF8024_ID_VENDOR_START		0x80
 #define  SFF8024_ID_VENDOR_LAST			0xFF
diff --git a/sfpid.c b/sfpid.c
index 1bc45c1..d9bda70 100644
--- a/sfpid.c
+++ b/sfpid.c
@@ -494,8 +494,10 @@ int sff8079_show_all_nl(struct cmd_context *ctx)
 	/* Read A2h page */
 	ret = sff8079_get_eeprom_page(ctx, SFF8079_I2C_ADDRESS_HIGH,
 				      buf + ETH_MODULE_SFF_8079_LEN);
-	if (ret)
+	if (ret) {
+		fprintf(stderr, "Failed to read Page A2h.\n");
 		goto out;
+	}
 
 	sff8472_show_all(buf);
 out:
diff --git a/shell-completion/bash/ethtool b/shell-completion/bash/ethtool
index 99c5f6f..3c775a1 100644
--- a/shell-completion/bash/ethtool
+++ b/shell-completion/bash/ethtool
@@ -79,6 +79,8 @@ _ethtool_flow_type()
 	local types='ah4 ah6 esp4 esp6 ether sctp4 sctp6 tcp4 tcp6 udp4 udp6'
 	if [ "${1-}" != --hash ]; then
 		types="$types ip4 ip6"
+	else
+		types="gtpc4 gtpc6 gtpc4t gtpc6t gtpu4 gtpu6 gtpu4e gtpu6e gtpu4u gtpu6u gtpu4d gtpu6d $types"
 	fi
 	COMPREPLY=( $( compgen -W "$types" -- "$cur" ) )
 }
@@ -171,7 +173,7 @@ _ethtool_change()
 			return ;;
 		wol)
 			# $cur is a set of wol type characters.
-			_ethtool_compgen_letterset p u m b a g s f d
+			_ethtool_compgen_letterset p u m b a g s f d e
 			return ;;
 		xcvr)
 			COMPREPLY=( $( compgen -W 'internal external' -- "$cur" ) )
@@ -483,7 +485,7 @@ _ethtool_config_nfc()
 					_ethtool_flow_type --hash
 					return ;;
 				5)
-					_ethtool_compgen_letterset m v t s d f n r
+					_ethtool_compgen_letterset m v t s d f n r e
 					return ;;
 				6)
 					COMPREPLY=( $( compgen -W context -- "$cur" ) )
@@ -1162,6 +1164,32 @@ _ethtool_set_module()
 	COMPREPLY=( $( compgen -W "${!settings[*]}" -- "$cur" ) )
 }
 
+# Completion for ethtool --flash-module-firmware
+_ethtool_flash_module_firmware()
+{
+	local -A settings=(
+		[file]=1
+		[pass]=1
+	)
+
+	case "$prev" in
+		file)
+			_ethtool_firmware
+			return ;;
+		pass)
+			# Number
+			return ;;
+	esac
+
+	# Remove settings which have been seen
+	local word
+	for word in "${words[@]:3:${#words[@]}-4}"; do
+		unset "settings[$word]"
+	done
+
+	COMPREPLY=( $( compgen -W "${!settings[*]}" -- "$cur" ) )
+}
+
 # Complete any ethtool command
 _ethtool()
 {
@@ -1215,6 +1243,7 @@ _ethtool()
 		[--test]=test
 		[--set-module]=set_module
 		[--show-module]=devname
+		[--flash-module-firmware]=flash_module_firmware
 	)
 	local -A other_funcs=(
 		[--config-ntuple]=config_nfc
diff --git a/test-cmdline.c b/test-cmdline.c
index cb803ed..c48be87 100644
--- a/test-cmdline.c
+++ b/test-cmdline.c
@@ -25,6 +25,7 @@ static struct test_case {
 	{ 1, "" },
 	{ 0, "devname" },
 	{ 0, "15_char_devname" },
+	{ !IS_NL, "--json devname" },
 	/* netlink interface allows names up to 127 characters */
 	{ !IS_NL, "16_char_devname!" },
 	{ !IS_NL, "127_char_devname0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde" },
diff --git a/uapi/linux/const.h b/uapi/linux/const.h
index 1eb84b5..2122610 100644
--- a/uapi/linux/const.h
+++ b/uapi/linux/const.h
@@ -28,6 +28,23 @@
 #define _BITUL(x)	(_UL(1) << (x))
 #define _BITULL(x)	(_ULL(1) << (x))
 
+#if !defined(__ASSEMBLY__)
+/*
+ * Missing __asm__ support
+ *
+ * __BIT128() would not work in the __asm__ code, as it shifts an
+ * 'unsigned __init128' data type as direct representation of
+ * 128 bit constants is not supported in the gcc compiler, as
+ * they get silently truncated.
+ *
+ * TODO: Please revisit this implementation when gcc compiler
+ * starts representing 128 bit constants directly like long
+ * and unsigned long etc. Subsequently drop the comment for
+ * GENMASK_U128() which would then start supporting __asm__ code.
+ */
+#define _BIT128(x)	((unsigned __int128)(1) << (x))
+#endif
+
 #define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (__typeof__(x))(a) - 1)
 #define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))
 
diff --git a/uapi/linux/ethtool.h b/uapi/linux/ethtool.h
index 1d0731b..7022fcc 100644
--- a/uapi/linux/ethtool.h
+++ b/uapi/linux/ethtool.h
@@ -750,6 +750,252 @@ enum ethtool_module_power_mode {
 	ETHTOOL_MODULE_POWER_MODE_HIGH,
 };
 
+/**
+ * enum ethtool_c33_pse_ext_state - groups of PSE extended states
+ *      functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_STATE_ERROR_CONDITION: Group of error_condition states
+ * @ETHTOOL_C33_PSE_EXT_STATE_MR_MPS_VALID: Group of mr_mps_valid states
+ * @ETHTOOL_C33_PSE_EXT_STATE_MR_PSE_ENABLE: Group of mr_pse_enable states
+ * @ETHTOOL_C33_PSE_EXT_STATE_OPTION_DETECT_TED: Group of option_detect_ted
+ *	states
+ * @ETHTOOL_C33_PSE_EXT_STATE_OPTION_VPORT_LIM: Group of option_vport_lim states
+ * @ETHTOOL_C33_PSE_EXT_STATE_OVLD_DETECTED: Group of ovld_detected states
+ * @ETHTOOL_C33_PSE_EXT_STATE_PD_DLL_POWER_TYPE: Group of pd_dll_power_type
+ *	states
+ * @ETHTOOL_C33_PSE_EXT_STATE_POWER_NOT_AVAILABLE: Group of power_not_available
+ *	states
+ * @ETHTOOL_C33_PSE_EXT_STATE_SHORT_DETECTED: Group of short_detected states
+ */
+enum ethtool_c33_pse_ext_state {
+	ETHTOOL_C33_PSE_EXT_STATE_ERROR_CONDITION = 1,
+	ETHTOOL_C33_PSE_EXT_STATE_MR_MPS_VALID,
+	ETHTOOL_C33_PSE_EXT_STATE_MR_PSE_ENABLE,
+	ETHTOOL_C33_PSE_EXT_STATE_OPTION_DETECT_TED,
+	ETHTOOL_C33_PSE_EXT_STATE_OPTION_VPORT_LIM,
+	ETHTOOL_C33_PSE_EXT_STATE_OVLD_DETECTED,
+	ETHTOOL_C33_PSE_EXT_STATE_PD_DLL_POWER_TYPE,
+	ETHTOOL_C33_PSE_EXT_STATE_POWER_NOT_AVAILABLE,
+	ETHTOOL_C33_PSE_EXT_STATE_SHORT_DETECTED,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_mr_mps_valid - mr_mps_valid states
+ *      functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_MPS_VALID_DETECTED_UNDERLOAD: Underload
+ *	state
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_MPS_VALID_CONNECTION_OPEN: Port is not
+ *	connected
+ *
+ * The PSE monitors either the DC or AC Maintain Power Signature
+ * (MPS, see 33.2.9.1). This variable indicates the presence or absence of
+ * a valid MPS.
+ */
+enum ethtool_c33_pse_ext_substate_mr_mps_valid {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_MPS_VALID_DETECTED_UNDERLOAD = 1,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_MPS_VALID_CONNECTION_OPEN,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_error_condition - error_condition states
+ *      functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_NON_EXISTING_PORT: Non-existing
+ *	port number
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNDEFINED_PORT: Undefined port
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_INTERNAL_HW_FAULT: Internal
+ *	hardware fault
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_COMM_ERROR_AFTER_FORCE_ON:
+ *	Communication error after force on
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNKNOWN_PORT_STATUS: Unknown
+ *	port status
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_TURN_OFF: Host
+ *	crash turn off
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_FORCE_SHUTDOWN:
+ *	Host crash force shutdown
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_CONFIG_CHANGE: Configuration
+ *	change
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_DETECTED_OVER_TEMP: Over
+ *	temperature detected
+ *
+ * error_condition is a variable indicating the status of
+ * implementation-specific fault conditions or optionally other system faults
+ * that prevent the PSE from meeting the specifications in Table 33–11 and that
+ * require the PSE not to source power. These error conditions are different
+ * from those monitored by the state diagrams in Figure 33–10.
+ */
+enum ethtool_c33_pse_ext_substate_error_condition {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_NON_EXISTING_PORT = 1,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNDEFINED_PORT,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_INTERNAL_HW_FAULT,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_COMM_ERROR_AFTER_FORCE_ON,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_UNKNOWN_PORT_STATUS,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_TURN_OFF,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_HOST_CRASH_FORCE_SHUTDOWN,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_CONFIG_CHANGE,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_ERROR_CONDITION_DETECTED_OVER_TEMP,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_mr_pse_enable - mr_pse_enable states
+ *      functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_PSE_ENABLE_DISABLE_PIN_ACTIVE: Disable
+ *	pin active
+ *
+ * mr_pse_enable is control variable that selects PSE operation and test
+ * functions.
+ */
+enum ethtool_c33_pse_ext_substate_mr_pse_enable {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_MR_PSE_ENABLE_DISABLE_PIN_ACTIVE = 1,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_option_detect_ted - option_detect_ted
+ *	states functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_DET_IN_PROCESS: Detection
+ *	in process
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_CONNECTION_CHECK_ERROR:
+ *	Connection check error
+ *
+ * option_detect_ted is a variable indicating if detection can be performed
+ * by the PSE during the ted_timer interval.
+ */
+enum ethtool_c33_pse_ext_substate_option_detect_ted {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_DET_IN_PROCESS = 1,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_DETECT_TED_CONNECTION_CHECK_ERROR,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_option_vport_lim - option_vport_lim states
+ *      functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_HIGH_VOLTAGE: Main supply
+ *	voltage is high
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_LOW_VOLTAGE: Main supply
+ *	voltage is low
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_VOLTAGE_INJECTION: Voltage
+ *	injection into the port
+ *
+ * option_vport_lim is an optional variable indicates if VPSE is out of the
+ * operating range during normal operating state.
+ */
+enum ethtool_c33_pse_ext_substate_option_vport_lim {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_HIGH_VOLTAGE = 1,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_LOW_VOLTAGE,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_OPTION_VPORT_LIM_VOLTAGE_INJECTION,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_ovld_detected - ovld_detected states
+ *      functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_OVLD_DETECTED_OVERLOAD: Overload state
+ *
+ * ovld_detected is a variable indicating if the PSE output current has been
+ * in an overload condition (see 33.2.7.6) for at least TCUT of a one-second
+ * sliding time.
+ */
+enum ethtool_c33_pse_ext_substate_ovld_detected {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_OVLD_DETECTED_OVERLOAD = 1,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_power_not_available - power_not_available
+ *	states functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_BUDGET_EXCEEDED: Power
+ *	budget exceeded for the controller
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PORT_PW_LIMIT_EXCEEDS_CONTROLLER_BUDGET:
+ *	Configured port power limit exceeded controller power budget
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PD_REQUEST_EXCEEDS_PORT_LIMIT:
+ *	Power request from PD exceeds port limit
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_HW_PW_LIMIT: Power
+ *	denied due to Hardware power limit
+ *
+ * power_not_available is a variable that is asserted in an
+ * implementation-dependent manner when the PSE is no longer capable of
+ * sourcing sufficient power to support the attached PD. Sufficient power
+ * is defined by classification; see 33.2.6.
+ */
+enum ethtool_c33_pse_ext_substate_power_not_available {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_BUDGET_EXCEEDED =  1,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PORT_PW_LIMIT_EXCEEDS_CONTROLLER_BUDGET,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_PD_REQUEST_EXCEEDS_PORT_LIMIT,
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_POWER_NOT_AVAILABLE_HW_PW_LIMIT,
+};
+
+/**
+ * enum ethtool_c33_pse_ext_substate_short_detected - short_detected states
+ *      functions. IEEE 802.3-2022 33.2.4.4 Variables
+ *
+ * @ETHTOOL_C33_PSE_EXT_SUBSTATE_SHORT_DETECTED_SHORT_CONDITION: Short
+ *	condition was detected
+ *
+ * short_detected is a variable indicating if the PSE output current has been
+ * in a short circuit condition for TLIM within a sliding window (see 33.2.7.7).
+ */
+enum ethtool_c33_pse_ext_substate_short_detected {
+	ETHTOOL_C33_PSE_EXT_SUBSTATE_SHORT_DETECTED_SHORT_CONDITION = 1,
+};
+
+/**
+ * enum ethtool_pse_types - Types of PSE controller.
+ * @ETHTOOL_PSE_UNKNOWN: Type of PSE controller is unknown
+ * @ETHTOOL_PSE_PODL: PSE controller which support PoDL
+ * @ETHTOOL_PSE_C33: PSE controller which support Clause 33 (PoE)
+ */
+enum ethtool_pse_types {
+	ETHTOOL_PSE_UNKNOWN =	1 << 0,
+	ETHTOOL_PSE_PODL =	1 << 1,
+	ETHTOOL_PSE_C33 =	1 << 2,
+};
+
+/**
+ * enum ethtool_c33_pse_admin_state - operational state of the PoDL PSE
+ *	functions. IEEE 802.3-2022 30.9.1.1.2 aPSEAdminState
+ * @ETHTOOL_C33_PSE_ADMIN_STATE_UNKNOWN: state of PSE functions is unknown
+ * @ETHTOOL_C33_PSE_ADMIN_STATE_DISABLED: PSE functions are disabled
+ * @ETHTOOL_C33_PSE_ADMIN_STATE_ENABLED: PSE functions are enabled
+ */
+enum ethtool_c33_pse_admin_state {
+	ETHTOOL_C33_PSE_ADMIN_STATE_UNKNOWN = 1,
+	ETHTOOL_C33_PSE_ADMIN_STATE_DISABLED,
+	ETHTOOL_C33_PSE_ADMIN_STATE_ENABLED,
+};
+
+/**
+ * enum ethtool_c33_pse_pw_d_status - power detection status of the PSE.
+ *	IEEE 802.3-2022 30.9.1.1.3 aPoDLPSEPowerDetectionStatus:
+ * @ETHTOOL_C33_PSE_PW_D_STATUS_UNKNOWN: PSE status is unknown
+ * @ETHTOOL_C33_PSE_PW_D_STATUS_DISABLED: The enumeration "disabled"
+ *	indicates that the PSE State diagram is in the state DISABLED.
+ * @ETHTOOL_C33_PSE_PW_D_STATUS_SEARCHING: The enumeration "searching"
+ *	indicates the PSE State diagram is in a state other than those
+ *	listed.
+ * @ETHTOOL_C33_PSE_PW_D_STATUS_DELIVERING: The enumeration
+ *	"deliveringPower" indicates that the PSE State diagram is in the
+ *	state POWER_ON.
+ * @ETHTOOL_C33_PSE_PW_D_STATUS_TEST: The enumeration "test" indicates that
+ *	the PSE State diagram is in the state TEST_MODE.
+ * @ETHTOOL_C33_PSE_PW_D_STATUS_FAULT: The enumeration "fault" indicates that
+ *	the PSE State diagram is in the state TEST_ERROR.
+ * @ETHTOOL_C33_PSE_PW_D_STATUS_OTHERFAULT: The enumeration "otherFault"
+ *	indicates that the PSE State diagram is in the state IDLE due to
+ *	the variable error_condition = true.
+ */
+enum ethtool_c33_pse_pw_d_status {
+	ETHTOOL_C33_PSE_PW_D_STATUS_UNKNOWN = 1,
+	ETHTOOL_C33_PSE_PW_D_STATUS_DISABLED,
+	ETHTOOL_C33_PSE_PW_D_STATUS_SEARCHING,
+	ETHTOOL_C33_PSE_PW_D_STATUS_DELIVERING,
+	ETHTOOL_C33_PSE_PW_D_STATUS_TEST,
+	ETHTOOL_C33_PSE_PW_D_STATUS_FAULT,
+	ETHTOOL_C33_PSE_PW_D_STATUS_OTHERFAULT,
+};
+
 /**
  * enum ethtool_podl_pse_admin_state - operational state of the PoDL PSE
  *	functions. IEEE 802.3-2018 30.15.1.1.2 aPoDLPSEAdminState
@@ -820,6 +1066,24 @@ enum ethtool_mm_verify_status {
 	ETHTOOL_MM_VERIFY_STATUS_DISABLED,
 };
 
+/**
+ * enum ethtool_module_fw_flash_status - plug-in module firmware flashing status
+ * @ETHTOOL_MODULE_FW_FLASH_STATUS_STARTED: The firmware flashing process has
+ *	started.
+ * @ETHTOOL_MODULE_FW_FLASH_STATUS_IN_PROGRESS: The firmware flashing process
+ *	is in progress.
+ * @ETHTOOL_MODULE_FW_FLASH_STATUS_COMPLETED: The firmware flashing process was
+ *	completed successfully.
+ * @ETHTOOL_MODULE_FW_FLASH_STATUS_ERROR: The firmware flashing process was
+ *	stopped due to an error.
+ */
+enum ethtool_module_fw_flash_status {
+	ETHTOOL_MODULE_FW_FLASH_STATUS_STARTED = 1,
+	ETHTOOL_MODULE_FW_FLASH_STATUS_IN_PROGRESS,
+	ETHTOOL_MODULE_FW_FLASH_STATUS_COMPLETED,
+	ETHTOOL_MODULE_FW_FLASH_STATUS_ERROR,
+};
+
 /**
  * struct ethtool_gstrings - string set for data tagging
  * @cmd: Command number = %ETHTOOL_GSTRINGS
@@ -1264,6 +1528,8 @@ struct ethtool_rxfh_indir {
  *	hardware hash key.
  * @hfunc: Defines the current RSS hash function used by HW (or to be set to).
  *	Valid values are one of the %ETH_RSS_HASH_*.
+ * @input_xfrm: Defines how the input data is transformed. Valid values are one
+ *	of %RXH_XFRM_*.
  * @rsvd8: Reserved for future use; see the note on reserved space.
  * @rsvd32: Reserved for future use; see the note on reserved space.
  * @rss_config: RX ring/queue index for each hash value i.e., indirection table
@@ -1283,7 +1549,8 @@ struct ethtool_rxfh {
 	__u32   indir_size;
 	__u32   key_size;
 	__u8	hfunc;
-	__u8	rsvd8[3];
+	__u8	input_xfrm;
+	__u8	rsvd8[2];
 	__u32	rsvd32;
 	__u32   rss_config[];
 };
@@ -1785,6 +2052,7 @@ enum ethtool_link_mode_bit_indices {
 	ETHTOOL_LINK_MODE_10baseT1S_Full_BIT		 = 99,
 	ETHTOOL_LINK_MODE_10baseT1S_Half_BIT		 = 100,
 	ETHTOOL_LINK_MODE_10baseT1S_P2MP_Half_BIT	 = 101,
+	ETHTOOL_LINK_MODE_10baseT1BRR_Full_BIT		 = 102,
 
 	/* must be last entry */
 	__ETHTOOL_LINK_MODE_MASK_NBITS
@@ -1990,6 +2258,15 @@ static __inline__ int ethtool_validate_duplex(__u8 duplex)
 
 #define WOL_MODE_COUNT		8
 
+/* RSS hash function data
+ * XOR the corresponding source and destination fields of each specified
+ * protocol. Both copies of the XOR'ed fields are fed into the RSS and RXHASH
+ * calculation. Note that this XORing reduces the input set entropy and could
+ * be exploited to reduce the RSS queue spread.
+ */
+#define	RXH_XFRM_SYM_XOR	(1 << 0)
+#define	RXH_XFRM_NO_CHANGE	0xff
+
 /* L2-L4 network traffic flow types */
 #define	TCP_V4_FLOW	0x01	/* hash or spec (tcp_ip4_spec) */
 #define	UDP_V4_FLOW	0x02	/* hash or spec (udp_ip4_spec) */
@@ -2009,6 +2286,53 @@ static __inline__ int ethtool_validate_duplex(__u8 duplex)
 #define	IPV4_FLOW	0x10	/* hash only */
 #define	IPV6_FLOW	0x11	/* hash only */
 #define	ETHER_FLOW	0x12	/* spec only (ether_spec) */
+
+/* Used for GTP-U IPv4 and IPv6.
+ * The format of GTP packets only includes
+ * elements such as TEID and GTP version.
+ * It is primarily intended for data communication of the UE.
+ */
+#define GTPU_V4_FLOW 0x13	/* hash only */
+#define GTPU_V6_FLOW 0x14	/* hash only */
+
+/* Use for GTP-C IPv4 and v6.
+ * The format of these GTP packets does not include TEID.
+ * Primarily expected to be used for communication
+ * to create sessions for UE data communication,
+ * commonly referred to as CSR (Create Session Request).
+ */
+#define GTPC_V4_FLOW 0x15	/* hash only */
+#define GTPC_V6_FLOW 0x16	/* hash only */
+
+/* Use for GTP-C IPv4 and v6.
+ * Unlike GTPC_V4_FLOW, the format of these GTP packets includes TEID.
+ * After session creation, it becomes this packet.
+ * This is mainly used for requests to realize UE handover.
+ */
+#define GTPC_TEID_V4_FLOW 0x17	/* hash only */
+#define GTPC_TEID_V6_FLOW 0x18	/* hash only */
+
+/* Use for GTP-U and extended headers for the PSC (PDU Session Container).
+ * The format of these GTP packets includes TEID and QFI.
+ * In 5G communication using UPF (User Plane Function),
+ * data communication with this extended header is performed.
+ */
+#define GTPU_EH_V4_FLOW 0x19	/* hash only */
+#define GTPU_EH_V6_FLOW 0x1a	/* hash only */
+
+/* Use for GTP-U IPv4 and v6 PSC (PDU Session Container) extended headers.
+ * This differs from GTPU_EH_V(4|6)_FLOW in that it is distinguished by
+ * UL/DL included in the PSC.
+ * There are differences in the data included based on Downlink/Uplink,
+ * and can be used to distinguish packets.
+ * The functions described so far are useful when you want to
+ * handle communication from the mobile network in UPF, PGW, etc.
+ */
+#define GTPU_UL_V4_FLOW 0x1b	/* hash only */
+#define GTPU_UL_V6_FLOW 0x1c	/* hash only */
+#define GTPU_DL_V4_FLOW 0x1d	/* hash only */
+#define GTPU_DL_V6_FLOW 0x1e	/* hash only */
+
 /* Flag to enable additional fields in struct ethtool_rx_flow_spec */
 #define	FLOW_EXT	0x80000000
 #define	FLOW_MAC_EXT	0x40000000
@@ -2023,6 +2347,7 @@ static __inline__ int ethtool_validate_duplex(__u8 duplex)
 #define	RXH_IP_DST	(1 << 5)
 #define	RXH_L4_B_0_1	(1 << 6) /* src port in case of TCP/UDP/SCTP */
 #define	RXH_L4_B_2_3	(1 << 7) /* dst port in case of TCP/UDP/SCTP */
+#define	RXH_GTP_TEID	(1 << 8) /* teid in case of GTP */
 #define	RXH_DISCARD	(1 << 31)
 
 #define	RX_CLS_FLOW_DISC	0xffffffffffffffffULL
@@ -2126,18 +2451,6 @@ enum ethtool_reset_flags {
  *	refused. For drivers: ignore this field (use kernel's
  *	__ETHTOOL_LINK_MODE_MASK_NBITS instead), any change to it will
  *	be overwritten by kernel.
- * @supported: Bitmap with each bit meaning given by
- *	%ethtool_link_mode_bit_indices for the link modes, physical
- *	connectors and other link features for which the interface
- *	supports autonegotiation or auto-detection.  Read-only.
- * @advertising: Bitmap with each bit meaning given by
- *	%ethtool_link_mode_bit_indices for the link modes, physical
- *	connectors and other link features that are advertised through
- *	autonegotiation or enabled for auto-detection.
- * @lp_advertising: Bitmap with each bit meaning given by
- *	%ethtool_link_mode_bit_indices for the link modes, and other
- *	link features that the link partner advertised through
- *	autonegotiation; 0 if unknown or not applicable.  Read-only.
  * @transceiver: Used to distinguish different possible PHY types,
  *	reported consistently by PHYLIB.  Read-only.
  * @master_slave_cfg: Master/slave port mode.
@@ -2179,6 +2492,21 @@ enum ethtool_reset_flags {
  * %set_link_ksettings() should validate all fields other than @cmd
  * and @link_mode_masks_nwords that are not described as read-only or
  * deprecated, and must ignore all fields described as read-only.
+ *
+ * @link_mode_masks is divided into three bitfields, each of length
+ * @link_mode_masks_nwords:
+ * - supported: Bitmap with each bit meaning given by
+ *	%ethtool_link_mode_bit_indices for the link modes, physical
+ *	connectors and other link features for which the interface
+ *	supports autonegotiation or auto-detection.  Read-only.
+ * - advertising: Bitmap with each bit meaning given by
+ *	%ethtool_link_mode_bit_indices for the link modes, physical
+ *	connectors and other link features that are advertised through
+ *	autonegotiation or enabled for auto-detection.
+ * - lp_advertising: Bitmap with each bit meaning given by
+ *	%ethtool_link_mode_bit_indices for the link modes, and other
+ *	link features that the link partner advertised through
+ *	autonegotiation; 0 if unknown or not applicable.  Read-only.
  */
 struct ethtool_link_settings {
 	__u32	cmd;
@@ -2203,4 +2531,20 @@ struct ethtool_link_settings {
 	 * __u32 map_lp_advertising[link_mode_masks_nwords];
 	 */
 };
+
+/**
+ * enum phy_upstream - Represents the upstream component a given PHY device
+ * is connected to, as in what is on the other end of the MII bus. Most PHYs
+ * will be attached to an Ethernet MAC controller, but in some cases, there's
+ * an intermediate PHY used as a media-converter, which will driver another
+ * MII interface as its output.
+ * @PHY_UPSTREAM_MAC: Upstream component is a MAC (a switch port,
+ *		      or ethernet controller)
+ * @PHY_UPSTREAM_PHY: Upstream component is a PHY (likely a media converter)
+ */
+enum phy_upstream {
+	PHY_UPSTREAM_MAC,
+	PHY_UPSTREAM_PHY,
+};
+
 #endif /* _LINUX_ETHTOOL_H */
diff --git a/uapi/linux/ethtool_netlink.h b/uapi/linux/ethtool_netlink.h
index a8b0d79..5d2bdd3 100644
--- a/uapi/linux/ethtool_netlink.h
+++ b/uapi/linux/ethtool_netlink.h
@@ -57,6 +57,8 @@ enum {
 	ETHTOOL_MSG_PLCA_GET_STATUS,
 	ETHTOOL_MSG_MM_GET,
 	ETHTOOL_MSG_MM_SET,
+	ETHTOOL_MSG_MODULE_FW_FLASH_ACT,
+	ETHTOOL_MSG_PHY_GET,
 
 	/* add new constants above here */
 	__ETHTOOL_MSG_USER_CNT,
@@ -109,6 +111,9 @@ enum {
 	ETHTOOL_MSG_PLCA_NTF,
 	ETHTOOL_MSG_MM_GET_REPLY,
 	ETHTOOL_MSG_MM_NTF,
+	ETHTOOL_MSG_MODULE_FW_FLASH_NTF,
+	ETHTOOL_MSG_PHY_GET_REPLY,
+	ETHTOOL_MSG_PHY_NTF,
 
 	/* add new constants above here */
 	__ETHTOOL_MSG_KERNEL_CNT,
@@ -117,12 +122,11 @@ enum {
 
 /* request header */
 
-/* use compact bitsets in reply */
-#define ETHTOOL_FLAG_COMPACT_BITSETS	(1 << 0)
-/* provide optional reply for SET or ACT requests */
-#define ETHTOOL_FLAG_OMIT_REPLY	(1 << 1)
-/* request statistics, if supported by the driver */
-#define ETHTOOL_FLAG_STATS		(1 << 2)
+enum ethtool_header_flags {
+	ETHTOOL_FLAG_COMPACT_BITSETS	= 1 << 0,	/* use compact bitsets in reply */
+	ETHTOOL_FLAG_OMIT_REPLY		= 1 << 1,	/* provide optional reply for SET or ACT requests */
+	ETHTOOL_FLAG_STATS		= 1 << 2,	/* request statistics, if supported by the driver */
+};
 
 #define ETHTOOL_FLAG_ALL (ETHTOOL_FLAG_COMPACT_BITSETS | \
 			  ETHTOOL_FLAG_OMIT_REPLY | \
@@ -133,6 +137,7 @@ enum {
 	ETHTOOL_A_HEADER_DEV_INDEX,		/* u32 */
 	ETHTOOL_A_HEADER_DEV_NAME,		/* string */
 	ETHTOOL_A_HEADER_FLAGS,			/* u32 - ETHTOOL_FLAG_* */
+	ETHTOOL_A_HEADER_PHY_INDEX,		/* u32 */
 
 	/* add new constants above here */
 	__ETHTOOL_A_HEADER_CNT,
@@ -416,12 +421,34 @@ enum {
 	ETHTOOL_A_COALESCE_TX_AGGR_MAX_BYTES,		/* u32 */
 	ETHTOOL_A_COALESCE_TX_AGGR_MAX_FRAMES,		/* u32 */
 	ETHTOOL_A_COALESCE_TX_AGGR_TIME_USECS,		/* u32 */
+	/* nest - _A_PROFILE_IRQ_MODERATION */
+	ETHTOOL_A_COALESCE_RX_PROFILE,
+	/* nest - _A_PROFILE_IRQ_MODERATION */
+	ETHTOOL_A_COALESCE_TX_PROFILE,
 
 	/* add new constants above here */
 	__ETHTOOL_A_COALESCE_CNT,
 	ETHTOOL_A_COALESCE_MAX = (__ETHTOOL_A_COALESCE_CNT - 1)
 };
 
+enum {
+	ETHTOOL_A_PROFILE_UNSPEC,
+	/* nest, _A_IRQ_MODERATION_* */
+	ETHTOOL_A_PROFILE_IRQ_MODERATION,
+	__ETHTOOL_A_PROFILE_CNT,
+	ETHTOOL_A_PROFILE_MAX = (__ETHTOOL_A_PROFILE_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_IRQ_MODERATION_UNSPEC,
+	ETHTOOL_A_IRQ_MODERATION_USEC,			/* u32 */
+	ETHTOOL_A_IRQ_MODERATION_PKTS,			/* u32 */
+	ETHTOOL_A_IRQ_MODERATION_COMPS,			/* u32 */
+
+	__ETHTOOL_A_IRQ_MODERATION_CNT,
+	ETHTOOL_A_IRQ_MODERATION_MAX = (__ETHTOOL_A_IRQ_MODERATION_CNT - 1)
+};
+
 /* PAUSE */
 
 enum {
@@ -478,12 +505,26 @@ enum {
 	ETHTOOL_A_TSINFO_TX_TYPES,			/* bitset */
 	ETHTOOL_A_TSINFO_RX_FILTERS,			/* bitset */
 	ETHTOOL_A_TSINFO_PHC_INDEX,			/* u32 */
+	ETHTOOL_A_TSINFO_STATS,				/* nest - _A_TSINFO_STAT */
 
 	/* add new constants above here */
 	__ETHTOOL_A_TSINFO_CNT,
 	ETHTOOL_A_TSINFO_MAX = (__ETHTOOL_A_TSINFO_CNT - 1)
 };
 
+enum {
+	ETHTOOL_A_TS_STAT_UNSPEC,
+
+	ETHTOOL_A_TS_STAT_TX_PKTS,			/* uint */
+	ETHTOOL_A_TS_STAT_TX_LOST,			/* uint */
+	ETHTOOL_A_TS_STAT_TX_ERR,			/* uint */
+
+	/* add new constants above here */
+	__ETHTOOL_A_TS_STAT_CNT,
+	ETHTOOL_A_TS_STAT_MAX = (__ETHTOOL_A_TS_STAT_CNT - 1)
+
+};
+
 /* PHC VCLOCKS */
 
 enum {
@@ -515,6 +556,14 @@ enum {
 	ETHTOOL_A_CABLE_RESULT_CODE_OPEN,
 	ETHTOOL_A_CABLE_RESULT_CODE_SAME_SHORT,
 	ETHTOOL_A_CABLE_RESULT_CODE_CROSS_SHORT,
+	/* detected reflection caused by the impedance discontinuity between
+	 * a regular 100 Ohm cable and a part with the abnormal impedance value
+	 */
+	ETHTOOL_A_CABLE_RESULT_CODE_IMPEDANCE_MISMATCH,
+	/* TDR not possible due to high noise level */
+	ETHTOOL_A_CABLE_RESULT_CODE_NOISE,
+	/* TDR resolution not possible / out of distance */
+	ETHTOOL_A_CABLE_RESULT_CODE_RESOLUTION_NOT_POSSIBLE,
 };
 
 enum {
@@ -524,10 +573,20 @@ enum {
 	ETHTOOL_A_CABLE_PAIR_D,
 };
 
+/* Information source for specific results. */
+enum {
+	ETHTOOL_A_CABLE_INF_SRC_UNSPEC,
+	/* Results provided by the Time Domain Reflectometry (TDR) */
+	ETHTOOL_A_CABLE_INF_SRC_TDR,
+	/* Results provided by the Active Link Cable Diagnostic (ALCD) */
+	ETHTOOL_A_CABLE_INF_SRC_ALCD,
+};
+
 enum {
 	ETHTOOL_A_CABLE_RESULT_UNSPEC,
 	ETHTOOL_A_CABLE_RESULT_PAIR,		/* u8 ETHTOOL_A_CABLE_PAIR_ */
 	ETHTOOL_A_CABLE_RESULT_CODE,		/* u8 ETHTOOL_A_CABLE_RESULT_CODE_ */
+	ETHTOOL_A_CABLE_RESULT_SRC,		/* u32 ETHTOOL_A_CABLE_INF_SRC_ */
 
 	__ETHTOOL_A_CABLE_RESULT_CNT,
 	ETHTOOL_A_CABLE_RESULT_MAX = (__ETHTOOL_A_CABLE_RESULT_CNT - 1)
@@ -537,6 +596,7 @@ enum {
 	ETHTOOL_A_CABLE_FAULT_LENGTH_UNSPEC,
 	ETHTOOL_A_CABLE_FAULT_LENGTH_PAIR,	/* u8 ETHTOOL_A_CABLE_PAIR_ */
 	ETHTOOL_A_CABLE_FAULT_LENGTH_CM,	/* u32 */
+	ETHTOOL_A_CABLE_FAULT_LENGTH_SRC,	/* u32 ETHTOOL_A_CABLE_INF_SRC_ */
 
 	__ETHTOOL_A_CABLE_FAULT_LENGTH_CNT,
 	ETHTOOL_A_CABLE_FAULT_LENGTH_MAX = (__ETHTOOL_A_CABLE_FAULT_LENGTH_CNT - 1)
@@ -889,12 +949,27 @@ enum {
 };
 
 /* Power Sourcing Equipment */
+enum {
+	ETHTOOL_A_C33_PSE_PW_LIMIT_UNSPEC,
+	ETHTOOL_A_C33_PSE_PW_LIMIT_MIN,	/* u32 */
+	ETHTOOL_A_C33_PSE_PW_LIMIT_MAX,	/* u32 */
+};
+
 enum {
 	ETHTOOL_A_PSE_UNSPEC,
 	ETHTOOL_A_PSE_HEADER,			/* nest - _A_HEADER_* */
 	ETHTOOL_A_PODL_PSE_ADMIN_STATE,		/* u32 */
 	ETHTOOL_A_PODL_PSE_ADMIN_CONTROL,	/* u32 */
 	ETHTOOL_A_PODL_PSE_PW_D_STATUS,		/* u32 */
+	ETHTOOL_A_C33_PSE_ADMIN_STATE,		/* u32 */
+	ETHTOOL_A_C33_PSE_ADMIN_CONTROL,	/* u32 */
+	ETHTOOL_A_C33_PSE_PW_D_STATUS,		/* u32 */
+	ETHTOOL_A_C33_PSE_PW_CLASS,		/* u32 */
+	ETHTOOL_A_C33_PSE_ACTUAL_PW,		/* u32 */
+	ETHTOOL_A_C33_PSE_EXT_STATE,		/* u32 */
+	ETHTOOL_A_C33_PSE_EXT_SUBSTATE,		/* u32 */
+	ETHTOOL_A_C33_PSE_AVAIL_PW_LIMIT,	/* u32 */
+	ETHTOOL_A_C33_PSE_PW_LIMIT_RANGES,	/* nest - _C33_PSE_PW_LIMIT_* */
 
 	/* add new constants above here */
 	__ETHTOOL_A_PSE_CNT,
@@ -908,6 +983,8 @@ enum {
 	ETHTOOL_A_RSS_HFUNC,		/* u32 */
 	ETHTOOL_A_RSS_INDIR,		/* binary */
 	ETHTOOL_A_RSS_HKEY,		/* binary */
+	ETHTOOL_A_RSS_INPUT_XFRM,	/* u32 */
+	ETHTOOL_A_RSS_START_CONTEXT,	/* u32 */
 
 	__ETHTOOL_A_RSS_CNT,
 	ETHTOOL_A_RSS_MAX = (__ETHTOOL_A_RSS_CNT - 1),
@@ -975,6 +1052,39 @@ enum {
 	ETHTOOL_A_MM_MAX = (__ETHTOOL_A_MM_CNT - 1)
 };
 
+/* MODULE_FW_FLASH */
+
+enum {
+	ETHTOOL_A_MODULE_FW_FLASH_UNSPEC,
+	ETHTOOL_A_MODULE_FW_FLASH_HEADER,		/* nest - _A_HEADER_* */
+	ETHTOOL_A_MODULE_FW_FLASH_FILE_NAME,		/* string */
+	ETHTOOL_A_MODULE_FW_FLASH_PASSWORD,		/* u32 */
+	ETHTOOL_A_MODULE_FW_FLASH_STATUS,		/* u32 */
+	ETHTOOL_A_MODULE_FW_FLASH_STATUS_MSG,		/* string */
+	ETHTOOL_A_MODULE_FW_FLASH_DONE,			/* uint */
+	ETHTOOL_A_MODULE_FW_FLASH_TOTAL,		/* uint */
+
+	/* add new constants above here */
+	__ETHTOOL_A_MODULE_FW_FLASH_CNT,
+	ETHTOOL_A_MODULE_FW_FLASH_MAX = (__ETHTOOL_A_MODULE_FW_FLASH_CNT - 1)
+};
+
+enum {
+	ETHTOOL_A_PHY_UNSPEC,
+	ETHTOOL_A_PHY_HEADER,			/* nest - _A_HEADER_* */
+	ETHTOOL_A_PHY_INDEX,			/* u32 */
+	ETHTOOL_A_PHY_DRVNAME,			/* string */
+	ETHTOOL_A_PHY_NAME,			/* string */
+	ETHTOOL_A_PHY_UPSTREAM_TYPE,		/* u32 */
+	ETHTOOL_A_PHY_UPSTREAM_INDEX,		/* u32 */
+	ETHTOOL_A_PHY_UPSTREAM_SFP_NAME,	/* string */
+	ETHTOOL_A_PHY_DOWNSTREAM_SFP_NAME,	/* string */
+
+	/* add new constants above here */
+	__ETHTOOL_A_PHY_CNT,
+	ETHTOOL_A_PHY_MAX = (__ETHTOOL_A_PHY_CNT - 1)
+};
+
 /* generic netlink info */
 #define ETHTOOL_GENL_NAME "ethtool"
 #define ETHTOOL_GENL_VERSION 1
diff --git a/uapi/linux/if_link.h b/uapi/linux/if_link.h
index 02af33c..987efed 100644
--- a/uapi/linux/if_link.h
+++ b/uapi/linux/if_link.h
@@ -376,7 +376,7 @@ enum {
 
 	IFLA_GSO_IPV4_MAX_SIZE,
 	IFLA_GRO_IPV4_MAX_SIZE,
-
+	IFLA_DPLL_PIN,
 	__IFLA_MAX
 };
 
@@ -459,6 +459,286 @@ enum in6_addr_gen_mode {
 
 /* Bridge section */
 
+/**
+ * DOC: Bridge enum definition
+ *
+ * Please *note* that the timer values in the following section are expected
+ * in clock_t format, which is seconds multiplied by USER_HZ (generally
+ * defined as 100).
+ *
+ * @IFLA_BR_FORWARD_DELAY
+ *   The bridge forwarding delay is the time spent in LISTENING state
+ *   (before moving to LEARNING) and in LEARNING state (before moving
+ *   to FORWARDING). Only relevant if STP is enabled.
+ *
+ *   The valid values are between (2 * USER_HZ) and (30 * USER_HZ).
+ *   The default value is (15 * USER_HZ).
+ *
+ * @IFLA_BR_HELLO_TIME
+ *   The time between hello packets sent by the bridge, when it is a root
+ *   bridge or a designated bridge. Only relevant if STP is enabled.
+ *
+ *   The valid values are between (1 * USER_HZ) and (10 * USER_HZ).
+ *   The default value is (2 * USER_HZ).
+ *
+ * @IFLA_BR_MAX_AGE
+ *   The hello packet timeout is the time until another bridge in the
+ *   spanning tree is assumed to be dead, after reception of its last hello
+ *   message. Only relevant if STP is enabled.
+ *
+ *   The valid values are between (6 * USER_HZ) and (40 * USER_HZ).
+ *   The default value is (20 * USER_HZ).
+ *
+ * @IFLA_BR_AGEING_TIME
+ *   Configure the bridge's FDB entries aging time. It is the time a MAC
+ *   address will be kept in the FDB after a packet has been received from
+ *   that address. After this time has passed, entries are cleaned up.
+ *   Allow values outside the 802.1 standard specification for special cases:
+ *
+ *     * 0 - entry never ages (all permanent)
+ *     * 1 - entry disappears (no persistence)
+ *
+ *   The default value is (300 * USER_HZ).
+ *
+ * @IFLA_BR_STP_STATE
+ *   Turn spanning tree protocol on (*IFLA_BR_STP_STATE* > 0) or off
+ *   (*IFLA_BR_STP_STATE* == 0) for this bridge.
+ *
+ *   The default value is 0 (disabled).
+ *
+ * @IFLA_BR_PRIORITY
+ *   Set this bridge's spanning tree priority, used during STP root bridge
+ *   election.
+ *
+ *   The valid values are between 0 and 65535.
+ *
+ * @IFLA_BR_VLAN_FILTERING
+ *   Turn VLAN filtering on (*IFLA_BR_VLAN_FILTERING* > 0) or off
+ *   (*IFLA_BR_VLAN_FILTERING* == 0). When disabled, the bridge will not
+ *   consider the VLAN tag when handling packets.
+ *
+ *   The default value is 0 (disabled).
+ *
+ * @IFLA_BR_VLAN_PROTOCOL
+ *   Set the protocol used for VLAN filtering.
+ *
+ *   The valid values are 0x8100(802.1Q) or 0x88A8(802.1AD). The default value
+ *   is 0x8100(802.1Q).
+ *
+ * @IFLA_BR_GROUP_FWD_MASK
+ *   The group forwarding mask. This is the bitmask that is applied to
+ *   decide whether to forward incoming frames destined to link-local
+ *   addresses (of the form 01:80:C2:00:00:0X).
+ *
+ *   The default value is 0, which means the bridge does not forward any
+ *   link-local frames coming on this port.
+ *
+ * @IFLA_BR_ROOT_ID
+ *   The bridge root id, read only.
+ *
+ * @IFLA_BR_BRIDGE_ID
+ *   The bridge id, read only.
+ *
+ * @IFLA_BR_ROOT_PORT
+ *   The bridge root port, read only.
+ *
+ * @IFLA_BR_ROOT_PATH_COST
+ *   The bridge root path cost, read only.
+ *
+ * @IFLA_BR_TOPOLOGY_CHANGE
+ *   The bridge topology change, read only.
+ *
+ * @IFLA_BR_TOPOLOGY_CHANGE_DETECTED
+ *   The bridge topology change detected, read only.
+ *
+ * @IFLA_BR_HELLO_TIMER
+ *   The bridge hello timer, read only.
+ *
+ * @IFLA_BR_TCN_TIMER
+ *   The bridge tcn timer, read only.
+ *
+ * @IFLA_BR_TOPOLOGY_CHANGE_TIMER
+ *   The bridge topology change timer, read only.
+ *
+ * @IFLA_BR_GC_TIMER
+ *   The bridge gc timer, read only.
+ *
+ * @IFLA_BR_GROUP_ADDR
+ *   Set the MAC address of the multicast group this bridge uses for STP.
+ *   The address must be a link-local address in standard Ethernet MAC address
+ *   format. It is an address of the form 01:80:C2:00:00:0X, with X in [0, 4..f].
+ *
+ *   The default value is 0.
+ *
+ * @IFLA_BR_FDB_FLUSH
+ *   Flush bridge's fdb dynamic entries.
+ *
+ * @IFLA_BR_MCAST_ROUTER
+ *   Set bridge's multicast router if IGMP snooping is enabled.
+ *   The valid values are:
+ *
+ *     * 0 - disabled.
+ *     * 1 - automatic (queried).
+ *     * 2 - permanently enabled.
+ *
+ *   The default value is 1.
+ *
+ * @IFLA_BR_MCAST_SNOOPING
+ *   Turn multicast snooping on (*IFLA_BR_MCAST_SNOOPING* > 0) or off
+ *   (*IFLA_BR_MCAST_SNOOPING* == 0).
+ *
+ *   The default value is 1.
+ *
+ * @IFLA_BR_MCAST_QUERY_USE_IFADDR
+ *   If enabled use the bridge's own IP address as source address for IGMP
+ *   queries (*IFLA_BR_MCAST_QUERY_USE_IFADDR* > 0) or the default of 0.0.0.0
+ *   (*IFLA_BR_MCAST_QUERY_USE_IFADDR* == 0).
+ *
+ *   The default value is 0 (disabled).
+ *
+ * @IFLA_BR_MCAST_QUERIER
+ *   Enable (*IFLA_BR_MULTICAST_QUERIER* > 0) or disable
+ *   (*IFLA_BR_MULTICAST_QUERIER* == 0) IGMP querier, ie sending of multicast
+ *   queries by the bridge.
+ *
+ *   The default value is 0 (disabled).
+ *
+ * @IFLA_BR_MCAST_HASH_ELASTICITY
+ *   Set multicast database hash elasticity, It is the maximum chain length in
+ *   the multicast hash table. This attribute is *deprecated* and the value
+ *   is always 16.
+ *
+ * @IFLA_BR_MCAST_HASH_MAX
+ *   Set maximum size of the multicast hash table
+ *
+ *   The default value is 4096, the value must be a power of 2.
+ *
+ * @IFLA_BR_MCAST_LAST_MEMBER_CNT
+ *   The Last Member Query Count is the number of Group-Specific Queries
+ *   sent before the router assumes there are no local members. The Last
+ *   Member Query Count is also the number of Group-and-Source-Specific
+ *   Queries sent before the router assumes there are no listeners for a
+ *   particular source.
+ *
+ *   The default value is 2.
+ *
+ * @IFLA_BR_MCAST_STARTUP_QUERY_CNT
+ *   The Startup Query Count is the number of Queries sent out on startup,
+ *   separated by the Startup Query Interval.
+ *
+ *   The default value is 2.
+ *
+ * @IFLA_BR_MCAST_LAST_MEMBER_INTVL
+ *   The Last Member Query Interval is the Max Response Time inserted into
+ *   Group-Specific Queries sent in response to Leave Group messages, and
+ *   is also the amount of time between Group-Specific Query messages.
+ *
+ *   The default value is (1 * USER_HZ).
+ *
+ * @IFLA_BR_MCAST_MEMBERSHIP_INTVL
+ *   The interval after which the bridge will leave a group, if no membership
+ *   reports for this group are received.
+ *
+ *   The default value is (260 * USER_HZ).
+ *
+ * @IFLA_BR_MCAST_QUERIER_INTVL
+ *   The interval between queries sent by other routers. if no queries are
+ *   seen after this delay has passed, the bridge will start to send its own
+ *   queries (as if *IFLA_BR_MCAST_QUERIER_INTVL* was enabled).
+ *
+ *   The default value is (255 * USER_HZ).
+ *
+ * @IFLA_BR_MCAST_QUERY_INTVL
+ *   The Query Interval is the interval between General Queries sent by
+ *   the Querier.
+ *
+ *   The default value is (125 * USER_HZ). The minimum value is (1 * USER_HZ).
+ *
+ * @IFLA_BR_MCAST_QUERY_RESPONSE_INTVL
+ *   The Max Response Time used to calculate the Max Resp Code inserted
+ *   into the periodic General Queries.
+ *
+ *   The default value is (10 * USER_HZ).
+ *
+ * @IFLA_BR_MCAST_STARTUP_QUERY_INTVL
+ *   The interval between queries in the startup phase.
+ *
+ *   The default value is (125 * USER_HZ) / 4. The minimum value is (1 * USER_HZ).
+ *
+ * @IFLA_BR_NF_CALL_IPTABLES
+ *   Enable (*NF_CALL_IPTABLES* > 0) or disable (*NF_CALL_IPTABLES* == 0)
+ *   iptables hooks on the bridge.
+ *
+ *   The default value is 0 (disabled).
+ *
+ * @IFLA_BR_NF_CALL_IP6TABLES
+ *   Enable (*NF_CALL_IP6TABLES* > 0) or disable (*NF_CALL_IP6TABLES* == 0)
+ *   ip6tables hooks on the bridge.
+ *
+ *   The default value is 0 (disabled).
+ *
+ * @IFLA_BR_NF_CALL_ARPTABLES
+ *   Enable (*NF_CALL_ARPTABLES* > 0) or disable (*NF_CALL_ARPTABLES* == 0)
+ *   arptables hooks on the bridge.
+ *
+ *   The default value is 0 (disabled).
+ *
+ * @IFLA_BR_VLAN_DEFAULT_PVID
+ *   VLAN ID applied to untagged and priority-tagged incoming packets.
+ *
+ *   The default value is 1. Setting to the special value 0 makes all ports of
+ *   this bridge not have a PVID by default, which means that they will
+ *   not accept VLAN-untagged traffic.
+ *
+ * @IFLA_BR_PAD
+ *   Bridge attribute padding type for netlink message.
+ *
+ * @IFLA_BR_VLAN_STATS_ENABLED
+ *   Enable (*IFLA_BR_VLAN_STATS_ENABLED* == 1) or disable
+ *   (*IFLA_BR_VLAN_STATS_ENABLED* == 0) per-VLAN stats accounting.
+ *
+ *   The default value is 0 (disabled).
+ *
+ * @IFLA_BR_MCAST_STATS_ENABLED
+ *   Enable (*IFLA_BR_MCAST_STATS_ENABLED* > 0) or disable
+ *   (*IFLA_BR_MCAST_STATS_ENABLED* == 0) multicast (IGMP/MLD) stats
+ *   accounting.
+ *
+ *   The default value is 0 (disabled).
+ *
+ * @IFLA_BR_MCAST_IGMP_VERSION
+ *   Set the IGMP version.
+ *
+ *   The valid values are 2 and 3. The default value is 2.
+ *
+ * @IFLA_BR_MCAST_MLD_VERSION
+ *   Set the MLD version.
+ *
+ *   The valid values are 1 and 2. The default value is 1.
+ *
+ * @IFLA_BR_VLAN_STATS_PER_PORT
+ *   Enable (*IFLA_BR_VLAN_STATS_PER_PORT* == 1) or disable
+ *   (*IFLA_BR_VLAN_STATS_PER_PORT* == 0) per-VLAN per-port stats accounting.
+ *   Can be changed only when there are no port VLANs configured.
+ *
+ *   The default value is 0 (disabled).
+ *
+ * @IFLA_BR_MULTI_BOOLOPT
+ *   The multi_boolopt is used to control new boolean options to avoid adding
+ *   new netlink attributes. You can look at ``enum br_boolopt_id`` for those
+ *   options.
+ *
+ * @IFLA_BR_MCAST_QUERIER_STATE
+ *   Bridge mcast querier states, read only.
+ *
+ * @IFLA_BR_FDB_N_LEARNED
+ *   The number of dynamically learned FDB entries for the current bridge,
+ *   read only.
+ *
+ * @IFLA_BR_FDB_MAX_LEARNED
+ *   Set the number of max dynamically learned FDB entries for the current
+ *   bridge.
+ */
 enum {
 	IFLA_BR_UNSPEC,
 	IFLA_BR_FORWARD_DELAY,
@@ -508,6 +788,8 @@ enum {
 	IFLA_BR_VLAN_STATS_PER_PORT,
 	IFLA_BR_MULTI_BOOLOPT,
 	IFLA_BR_MCAST_QUERIER_STATE,
+	IFLA_BR_FDB_N_LEARNED,
+	IFLA_BR_FDB_MAX_LEARNED,
 	__IFLA_BR_MAX,
 };
 
@@ -518,11 +800,252 @@ struct ifla_bridge_id {
 	__u8	addr[6]; /* ETH_ALEN */
 };
 
+/**
+ * DOC: Bridge mode enum definition
+ *
+ * @BRIDGE_MODE_HAIRPIN
+ *   Controls whether traffic may be sent back out of the port on which it
+ *   was received. This option is also called reflective relay mode, and is
+ *   used to support basic VEPA (Virtual Ethernet Port Aggregator)
+ *   capabilities. By default, this flag is turned off and the bridge will
+ *   not forward traffic back out of the receiving port.
+ */
 enum {
 	BRIDGE_MODE_UNSPEC,
 	BRIDGE_MODE_HAIRPIN,
 };
 
+/**
+ * DOC: Bridge port enum definition
+ *
+ * @IFLA_BRPORT_STATE
+ *   The operation state of the port. Here are the valid values.
+ *
+ *     * 0 - port is in STP *DISABLED* state. Make this port completely
+ *       inactive for STP. This is also called BPDU filter and could be used
+ *       to disable STP on an untrusted port, like a leaf virtual device.
+ *       The traffic forwarding is also stopped on this port.
+ *     * 1 - port is in STP *LISTENING* state. Only valid if STP is enabled
+ *       on the bridge. In this state the port listens for STP BPDUs and
+ *       drops all other traffic frames.
+ *     * 2 - port is in STP *LEARNING* state. Only valid if STP is enabled on
+ *       the bridge. In this state the port will accept traffic only for the
+ *       purpose of updating MAC address tables.
+ *     * 3 - port is in STP *FORWARDING* state. Port is fully active.
+ *     * 4 - port is in STP *BLOCKING* state. Only valid if STP is enabled on
+ *       the bridge. This state is used during the STP election process.
+ *       In this state, port will only process STP BPDUs.
+ *
+ * @IFLA_BRPORT_PRIORITY
+ *   The STP port priority. The valid values are between 0 and 255.
+ *
+ * @IFLA_BRPORT_COST
+ *   The STP path cost of the port. The valid values are between 1 and 65535.
+ *
+ * @IFLA_BRPORT_MODE
+ *   Set the bridge port mode. See *BRIDGE_MODE_HAIRPIN* for more details.
+ *
+ * @IFLA_BRPORT_GUARD
+ *   Controls whether STP BPDUs will be processed by the bridge port. By
+ *   default, the flag is turned off to allow BPDU processing. Turning this
+ *   flag on will disable the bridge port if a STP BPDU packet is received.
+ *
+ *   If the bridge has Spanning Tree enabled, hostile devices on the network
+ *   may send BPDU on a port and cause network failure. Setting *guard on*
+ *   will detect and stop this by disabling the port. The port will be
+ *   restarted if the link is brought down, or removed and reattached.
+ *
+ * @IFLA_BRPORT_PROTECT
+ *   Controls whether a given port is allowed to become a root port or not.
+ *   Only used when STP is enabled on the bridge. By default the flag is off.
+ *
+ *   This feature is also called root port guard. If BPDU is received from a
+ *   leaf (edge) port, it should not be elected as root port. This could
+ *   be used if using STP on a bridge and the downstream bridges are not fully
+ *   trusted; this prevents a hostile guest from rerouting traffic.
+ *
+ * @IFLA_BRPORT_FAST_LEAVE
+ *   This flag allows the bridge to immediately stop multicast traffic
+ *   forwarding on a port that receives an IGMP Leave message. It is only used
+ *   when IGMP snooping is enabled on the bridge. By default the flag is off.
+ *
+ * @IFLA_BRPORT_LEARNING
+ *   Controls whether a given port will learn *source* MAC addresses from
+ *   received traffic or not. Also controls whether dynamic FDB entries
+ *   (which can also be added by software) will be refreshed by incoming
+ *   traffic. By default this flag is on.
+ *
+ * @IFLA_BRPORT_UNICAST_FLOOD
+ *   Controls whether unicast traffic for which there is no FDB entry will
+ *   be flooded towards this port. By default this flag is on.
+ *
+ * @IFLA_BRPORT_PROXYARP
+ *   Enable proxy ARP on this port.
+ *
+ * @IFLA_BRPORT_LEARNING_SYNC
+ *   Controls whether a given port will sync MAC addresses learned on device
+ *   port to bridge FDB.
+ *
+ * @IFLA_BRPORT_PROXYARP_WIFI
+ *   Enable proxy ARP on this port which meets extended requirements by
+ *   IEEE 802.11 and Hotspot 2.0 specifications.
+ *
+ * @IFLA_BRPORT_ROOT_ID
+ *
+ * @IFLA_BRPORT_BRIDGE_ID
+ *
+ * @IFLA_BRPORT_DESIGNATED_PORT
+ *
+ * @IFLA_BRPORT_DESIGNATED_COST
+ *
+ * @IFLA_BRPORT_ID
+ *
+ * @IFLA_BRPORT_NO
+ *
+ * @IFLA_BRPORT_TOPOLOGY_CHANGE_ACK
+ *
+ * @IFLA_BRPORT_CONFIG_PENDING
+ *
+ * @IFLA_BRPORT_MESSAGE_AGE_TIMER
+ *
+ * @IFLA_BRPORT_FORWARD_DELAY_TIMER
+ *
+ * @IFLA_BRPORT_HOLD_TIMER
+ *
+ * @IFLA_BRPORT_FLUSH
+ *   Flush bridge ports' fdb dynamic entries.
+ *
+ * @IFLA_BRPORT_MULTICAST_ROUTER
+ *   Configure the port's multicast router presence. A port with
+ *   a multicast router will receive all multicast traffic.
+ *   The valid values are:
+ *
+ *     * 0 disable multicast routers on this port
+ *     * 1 let the system detect the presence of routers (default)
+ *     * 2 permanently enable multicast traffic forwarding on this port
+ *     * 3 enable multicast routers temporarily on this port, not depending
+ *         on incoming queries.
+ *
+ * @IFLA_BRPORT_PAD
+ *
+ * @IFLA_BRPORT_MCAST_FLOOD
+ *   Controls whether a given port will flood multicast traffic for which
+ *   there is no MDB entry. By default this flag is on.
+ *
+ * @IFLA_BRPORT_MCAST_TO_UCAST
+ *   Controls whether a given port will replicate packets using unicast
+ *   instead of multicast. By default this flag is off.
+ *
+ *   This is done by copying the packet per host and changing the multicast
+ *   destination MAC to a unicast one accordingly.
+ *
+ *   *mcast_to_unicast* works on top of the multicast snooping feature of the
+ *   bridge. Which means unicast copies are only delivered to hosts which
+ *   are interested in unicast and signaled this via IGMP/MLD reports previously.
+ *
+ *   This feature is intended for interface types which have a more reliable
+ *   and/or efficient way to deliver unicast packets than broadcast ones
+ *   (e.g. WiFi).
+ *
+ *   However, it should only be enabled on interfaces where no IGMPv2/MLDv1
+ *   report suppression takes place. IGMP/MLD report suppression issue is
+ *   usually overcome by the network daemon (supplicant) enabling AP isolation
+ *   and by that separating all STAs.
+ *
+ *   Delivery of STA-to-STA IP multicast is made possible again by enabling
+ *   and utilizing the bridge hairpin mode, which considers the incoming port
+ *   as a potential outgoing port, too (see *BRIDGE_MODE_HAIRPIN* option).
+ *   Hairpin mode is performed after multicast snooping, therefore leading
+ *   to only deliver reports to STAs running a multicast router.
+ *
+ * @IFLA_BRPORT_VLAN_TUNNEL
+ *   Controls whether vlan to tunnel mapping is enabled on the port.
+ *   By default this flag is off.
+ *
+ * @IFLA_BRPORT_BCAST_FLOOD
+ *   Controls flooding of broadcast traffic on the given port. By default
+ *   this flag is on.
+ *
+ * @IFLA_BRPORT_GROUP_FWD_MASK
+ *   Set the group forward mask. This is a bitmask that is applied to
+ *   decide whether to forward incoming frames destined to link-local
+ *   addresses. The addresses of the form are 01:80:C2:00:00:0X (defaults
+ *   to 0, which means the bridge does not forward any link-local frames
+ *   coming on this port).
+ *
+ * @IFLA_BRPORT_NEIGH_SUPPRESS
+ *   Controls whether neighbor discovery (arp and nd) proxy and suppression
+ *   is enabled on the port. By default this flag is off.
+ *
+ * @IFLA_BRPORT_ISOLATED
+ *   Controls whether a given port will be isolated, which means it will be
+ *   able to communicate with non-isolated ports only. By default this
+ *   flag is off.
+ *
+ * @IFLA_BRPORT_BACKUP_PORT
+ *   Set a backup port. If the port loses carrier all traffic will be
+ *   redirected to the configured backup port. Set the value to 0 to disable
+ *   it.
+ *
+ * @IFLA_BRPORT_MRP_RING_OPEN
+ *
+ * @IFLA_BRPORT_MRP_IN_OPEN
+ *
+ * @IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT
+ *   The number of per-port EHT hosts limit. The default value is 512.
+ *   Setting to 0 is not allowed.
+ *
+ * @IFLA_BRPORT_MCAST_EHT_HOSTS_CNT
+ *   The current number of tracked hosts, read only.
+ *
+ * @IFLA_BRPORT_LOCKED
+ *   Controls whether a port will be locked, meaning that hosts behind the
+ *   port will not be able to communicate through the port unless an FDB
+ *   entry with the unit's MAC address is in the FDB. The common use case is
+ *   that hosts are allowed access through authentication with the IEEE 802.1X
+ *   protocol or based on whitelists. By default this flag is off.
+ *
+ *   Please note that secure 802.1X deployments should always use the
+ *   *BR_BOOLOPT_NO_LL_LEARN* flag, to not permit the bridge to populate its
+ *   FDB based on link-local (EAPOL) traffic received on the port.
+ *
+ * @IFLA_BRPORT_MAB
+ *   Controls whether a port will use MAC Authentication Bypass (MAB), a
+ *   technique through which select MAC addresses may be allowed on a locked
+ *   port, without using 802.1X authentication. Packets with an unknown source
+ *   MAC address generates a "locked" FDB entry on the incoming bridge port.
+ *   The common use case is for user space to react to these bridge FDB
+ *   notifications and optionally replace the locked FDB entry with a normal
+ *   one, allowing traffic to pass for whitelisted MAC addresses.
+ *
+ *   Setting this flag also requires *IFLA_BRPORT_LOCKED* and
+ *   *IFLA_BRPORT_LEARNING*. *IFLA_BRPORT_LOCKED* ensures that unauthorized
+ *   data packets are dropped, and *IFLA_BRPORT_LEARNING* allows the dynamic
+ *   FDB entries installed by user space (as replacements for the locked FDB
+ *   entries) to be refreshed and/or aged out.
+ *
+ * @IFLA_BRPORT_MCAST_N_GROUPS
+ *
+ * @IFLA_BRPORT_MCAST_MAX_GROUPS
+ *   Sets the maximum number of MDB entries that can be registered for a
+ *   given port. Attempts to register more MDB entries at the port than this
+ *   limit allows will be rejected, whether they are done through netlink
+ *   (e.g. the bridge tool), or IGMP or MLD membership reports. Setting a
+ *   limit of 0 disables the limit. The default value is 0.
+ *
+ * @IFLA_BRPORT_NEIGH_VLAN_SUPPRESS
+ *   Controls whether neighbor discovery (arp and nd) proxy and suppression is
+ *   enabled for a given port. By default this flag is off.
+ *
+ *   Note that this option only takes effect when *IFLA_BRPORT_NEIGH_SUPPRESS*
+ *   is enabled for a given port.
+ *
+ * @IFLA_BRPORT_BACKUP_NHID
+ *   The FDB nexthop object ID to attach to packets being redirected to a
+ *   backup port that has VLAN tunnel mapping enabled (via the
+ *   *IFLA_BRPORT_VLAN_TUNNEL* option). Setting a value of 0 (default) has
+ *   the effect of not attaching any ID.
+ */
 enum {
 	IFLA_BRPORT_UNSPEC,
 	IFLA_BRPORT_STATE,	/* Spanning tree state     */
@@ -568,6 +1091,7 @@ enum {
 	IFLA_BRPORT_MCAST_N_GROUPS,
 	IFLA_BRPORT_MCAST_MAX_GROUPS,
 	IFLA_BRPORT_NEIGH_VLAN_SUPPRESS,
+	IFLA_BRPORT_BACKUP_NHID,
 	__IFLA_BRPORT_MAX
 };
 #define IFLA_BRPORT_MAX (__IFLA_BRPORT_MAX - 1)
@@ -753,6 +1277,30 @@ struct tunnel_msg {
 	__u32 ifindex;
 };
 
+/* netkit section */
+enum netkit_action {
+	NETKIT_NEXT	= -1,
+	NETKIT_PASS	= 0,
+	NETKIT_DROP	= 2,
+	NETKIT_REDIRECT	= 7,
+};
+
+enum netkit_mode {
+	NETKIT_L2,
+	NETKIT_L3,
+};
+
+enum {
+	IFLA_NETKIT_UNSPEC,
+	IFLA_NETKIT_PEER_INFO,
+	IFLA_NETKIT_PRIMARY,
+	IFLA_NETKIT_POLICY,
+	IFLA_NETKIT_PEER_POLICY,
+	IFLA_NETKIT_MODE,
+	__IFLA_NETKIT_MAX,
+};
+#define IFLA_NETKIT_MAX	(__IFLA_NETKIT_MAX - 1)
+
 /* VXLAN section */
 
 /* include statistics in the dump */
@@ -827,6 +1375,7 @@ enum {
 	IFLA_VXLAN_DF,
 	IFLA_VXLAN_VNIFILTER, /* only applicable with COLLECT_METADATA mode */
 	IFLA_VXLAN_LOCALBYPASS,
+	IFLA_VXLAN_LABEL_POLICY, /* IPv6 flow label policy; ifla_vxlan_label_policy */
 	__IFLA_VXLAN_MAX
 };
 #define IFLA_VXLAN_MAX	(__IFLA_VXLAN_MAX - 1)
@@ -844,6 +1393,13 @@ enum ifla_vxlan_df {
 	VXLAN_DF_MAX = __VXLAN_DF_END - 1,
 };
 
+enum ifla_vxlan_label_policy {
+	VXLAN_LABEL_FIXED = 0,
+	VXLAN_LABEL_INHERIT = 1,
+	__VXLAN_LABEL_END,
+	VXLAN_LABEL_MAX = __VXLAN_LABEL_END - 1,
+};
+
 /* GENEVE section */
 enum {
 	IFLA_GENEVE_UNSPEC,
@@ -908,6 +1464,8 @@ enum {
 	IFLA_GTP_ROLE,
 	IFLA_GTP_CREATE_SOCKETS,
 	IFLA_GTP_RESTART_COUNT,
+	IFLA_GTP_LOCAL,
+	IFLA_GTP_LOCAL6,
 	__IFLA_GTP_MAX,
 };
 #define IFLA_GTP_MAX (__IFLA_GTP_MAX - 1)
@@ -947,6 +1505,7 @@ enum {
 	IFLA_BOND_AD_LACP_ACTIVE,
 	IFLA_BOND_MISSED_MAX,
 	IFLA_BOND_NS_IP6_TARGET,
+	IFLA_BOND_COUPLED_CONTROL,
 	__IFLA_BOND_MAX,
 };
 
@@ -1212,6 +1771,7 @@ enum {
 	IFLA_HSR_PROTOCOL,		/* Indicate different protocol than
 					 * HSR. For example PRP.
 					 */
+	IFLA_HSR_INTERLINK,		/* HSR interlink network device */
 	__IFLA_HSR_MAX,
 };
 
@@ -1389,7 +1949,9 @@ enum {
 
 enum {
 	IFLA_DSA_UNSPEC,
-	IFLA_DSA_MASTER,
+	IFLA_DSA_CONDUIT,
+	/* Deprecated, use IFLA_DSA_CONDUIT instead */
+	IFLA_DSA_MASTER = IFLA_DSA_CONDUIT,
 	__IFLA_DSA_MAX,
 };
 
diff --git a/uapi/linux/libc-compat.h b/uapi/linux/libc-compat.h
index a159991..e25cd3f 100644
--- a/uapi/linux/libc-compat.h
+++ b/uapi/linux/libc-compat.h
@@ -140,25 +140,6 @@
 
 #endif /* _NETINET_IN_H */
 
-/* Coordinate with glibc netipx/ipx.h header. */
-#if defined(__NETIPX_IPX_H)
-
-#define __UAPI_DEF_SOCKADDR_IPX			0
-#define __UAPI_DEF_IPX_ROUTE_DEFINITION		0
-#define __UAPI_DEF_IPX_INTERFACE_DEFINITION	0
-#define __UAPI_DEF_IPX_CONFIG_DATA		0
-#define __UAPI_DEF_IPX_ROUTE_DEF		0
-
-#else /* defined(__NETIPX_IPX_H) */
-
-#define __UAPI_DEF_SOCKADDR_IPX			1
-#define __UAPI_DEF_IPX_ROUTE_DEFINITION		1
-#define __UAPI_DEF_IPX_INTERFACE_DEFINITION	1
-#define __UAPI_DEF_IPX_CONFIG_DATA		1
-#define __UAPI_DEF_IPX_ROUTE_DEF		1
-
-#endif /* defined(__NETIPX_IPX_H) */
-
 /* Definitions for xattr.h */
 #if defined(_SYS_XATTR_H)
 #define __UAPI_DEF_XATTR		0
@@ -240,23 +221,6 @@
 #define __UAPI_DEF_IP6_MTUINFO		1
 #endif
 
-/* Definitions for ipx.h */
-#ifndef __UAPI_DEF_SOCKADDR_IPX
-#define __UAPI_DEF_SOCKADDR_IPX			1
-#endif
-#ifndef __UAPI_DEF_IPX_ROUTE_DEFINITION
-#define __UAPI_DEF_IPX_ROUTE_DEFINITION		1
-#endif
-#ifndef __UAPI_DEF_IPX_INTERFACE_DEFINITION
-#define __UAPI_DEF_IPX_INTERFACE_DEFINITION	1
-#endif
-#ifndef __UAPI_DEF_IPX_CONFIG_DATA
-#define __UAPI_DEF_IPX_CONFIG_DATA		1
-#endif
-#ifndef __UAPI_DEF_IPX_ROUTE_DEF
-#define __UAPI_DEF_IPX_ROUTE_DEF		1
-#endif
-
 /* Definitions for xattr.h */
 #ifndef __UAPI_DEF_XATTR
 #define __UAPI_DEF_XATTR		1
diff --git a/uapi/linux/net_tstamp.h b/uapi/linux/net_tstamp.h
index a2c66b3..858339d 100644
--- a/uapi/linux/net_tstamp.h
+++ b/uapi/linux/net_tstamp.h
@@ -32,8 +32,9 @@ enum {
 	SOF_TIMESTAMPING_OPT_TX_SWHW = (1<<14),
 	SOF_TIMESTAMPING_BIND_PHC = (1 << 15),
 	SOF_TIMESTAMPING_OPT_ID_TCP = (1 << 16),
+	SOF_TIMESTAMPING_OPT_RX_FILTER = (1 << 17),
 
-	SOF_TIMESTAMPING_LAST = SOF_TIMESTAMPING_OPT_ID_TCP,
+	SOF_TIMESTAMPING_LAST = SOF_TIMESTAMPING_OPT_RX_FILTER,
 	SOF_TIMESTAMPING_MASK = (SOF_TIMESTAMPING_LAST - 1) |
 				 SOF_TIMESTAMPING_LAST
 };
diff --git a/uapi/linux/netlink.h b/uapi/linux/netlink.h
index 47bac97..ff64eb1 100644
--- a/uapi/linux/netlink.h
+++ b/uapi/linux/netlink.h
@@ -294,6 +294,8 @@ struct nla_bitfield32 {
  *	entry has attributes again, the policy for those inner ones
  *	and the corresponding maxtype may be specified.
  * @NL_ATTR_TYPE_BITFIELD32: &struct nla_bitfield32 attribute
+ * @NL_ATTR_TYPE_SINT: 32-bit or 64-bit signed attribute, aligned to 4B
+ * @NL_ATTR_TYPE_UINT: 32-bit or 64-bit unsigned attribute, aligned to 4B
  */
 enum netlink_attribute_type {
 	NL_ATTR_TYPE_INVALID,
@@ -318,6 +320,9 @@ enum netlink_attribute_type {
 	NL_ATTR_TYPE_NESTED_ARRAY,
 
 	NL_ATTR_TYPE_BITFIELD32,
+
+	NL_ATTR_TYPE_SINT,
+	NL_ATTR_TYPE_UINT,
 };
 
 /**
diff --git a/uapi/linux/rtnetlink.h b/uapi/linux/rtnetlink.h
index 2132e94..4e6c8e1 100644
--- a/uapi/linux/rtnetlink.h
+++ b/uapi/linux/rtnetlink.h
@@ -502,13 +502,17 @@ enum {
 
 #define RTAX_MAX (__RTAX_MAX - 1)
 
-#define RTAX_FEATURE_ECN	(1 << 0)
-#define RTAX_FEATURE_SACK	(1 << 1)
-#define RTAX_FEATURE_TIMESTAMP	(1 << 2)
-#define RTAX_FEATURE_ALLFRAG	(1 << 3)
-
-#define RTAX_FEATURE_MASK	(RTAX_FEATURE_ECN | RTAX_FEATURE_SACK | \
-				 RTAX_FEATURE_TIMESTAMP | RTAX_FEATURE_ALLFRAG)
+#define RTAX_FEATURE_ECN		(1 << 0)
+#define RTAX_FEATURE_SACK		(1 << 1) /* unused */
+#define RTAX_FEATURE_TIMESTAMP		(1 << 2) /* unused */
+#define RTAX_FEATURE_ALLFRAG		(1 << 3) /* unused */
+#define RTAX_FEATURE_TCP_USEC_TS	(1 << 4)
+
+#define RTAX_FEATURE_MASK	(RTAX_FEATURE_ECN |		\
+				 RTAX_FEATURE_SACK |		\
+				 RTAX_FEATURE_TIMESTAMP |	\
+				 RTAX_FEATURE_ALLFRAG |		\
+				 RTAX_FEATURE_TCP_USEC_TS)
 
 struct rta_session {
 	__u8	proto;
diff --git a/uapi/linux/stddef.h b/uapi/linux/stddef.h
index bb6ea51..96aa341 100644
--- a/uapi/linux/stddef.h
+++ b/uapi/linux/stddef.h
@@ -27,8 +27,13 @@
 	union { \
 		struct { MEMBERS } ATTRS; \
 		struct TAG { MEMBERS } ATTRS NAME; \
-	}
+	} ATTRS
 
+#ifdef __cplusplus
+/* sizeof(struct{}) is 1 in C++, not 0, can't use C version of the macro. */
+#define __DECLARE_FLEX_ARRAY(T, member)	\
+	T member[0]
+#else
 /**
  * __DECLARE_FLEX_ARRAY() - Declare a flexible array usable in a union
  *
@@ -45,3 +50,17 @@
 		TYPE NAME[]; \
 	}
 #endif
+
+#ifndef __counted_by
+#define __counted_by(m)
+#endif
+
+#ifndef __counted_by_le
+#define __counted_by_le(m)
+#endif
+
+#ifndef __counted_by_be
+#define __counted_by_be(m)
+#endif
+
+#endif /* _LINUX_STDDEF_H */
```

