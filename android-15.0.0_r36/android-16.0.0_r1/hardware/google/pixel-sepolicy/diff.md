```diff
diff --git a/googlebattery/pixelsystemservice_app.te b/googlebattery/pixelsystemservice_app.te
new file mode 100644
index 0000000..818662e
--- /dev/null
+++ b/googlebattery/pixelsystemservice_app.te
@@ -0,0 +1,4 @@
+# To find and bind Google Battery HAL
+allow pixelsystemservice_app hal_googlebattery_service:service_manager find;
+binder_call(pixelsystemservice_app, hal_googlebattery)
+
diff --git a/h2omg/file.te b/h2omg/file.te
new file mode 100644
index 0000000..9aeacc7
--- /dev/null
+++ b/h2omg/file.te
@@ -0,0 +1,3 @@
+type sysfs_h2omg_drv, fs_type, sysfs_type;
+type sysfs_h2omg_fuse, fs_type, sysfs_type;
+type sysfs_h2omg_dev, fs_type, sysfs_type;
diff --git a/h2omg/file_contexts b/h2omg/file_contexts
new file mode 100644
index 0000000..5b0cd1e
--- /dev/null
+++ b/h2omg/file_contexts
@@ -0,0 +1,2 @@
+# h2omg init script
+/vendor/bin/hw/init.h2omg.sh           u:object_r:h2omg_vendor_exec:s0
diff --git a/h2omg/genfs_contexts b/h2omg/genfs_contexts
new file mode 100644
index 0000000..14ebe30
--- /dev/null
+++ b/h2omg/genfs_contexts
@@ -0,0 +1,5 @@
+genfscon sysfs /bus/i2c/drivers/h2omg   u:object_r:sysfs_h2omg_drv:s0
+genfscon sysfs /devices/platform/53f1000.spmi/spmi-0/0-02/i2c-44/44-0070 u:object_r:sysfs_h2omg_dev:s0
+genfscon sysfs /devices/platform/53f1000.spmi/spmi-0/0-02/i2c-44/44-0071 u:object_r:sysfs_h2omg_dev:s0
+genfscon sysfs /devices/platform/53f1000.spmi/spmi-0/0-02/i2c-44/44-0070/fuse/enable u:object_r:sysfs_h2omg_fuse:s0
+genfscon sysfs /devices/platform/53f1000.spmi/spmi-0/0-02/i2c-44/44-0071/fuse/enable u:object_r:sysfs_h2omg_fuse:s0
diff --git a/h2omg/h2omg_exec.te b/h2omg/h2omg_exec.te
new file mode 100644
index 0000000..aa3d10e
--- /dev/null
+++ b/h2omg/h2omg_exec.te
@@ -0,0 +1,9 @@
+type h2omg_vendor, domain;
+type h2omg_vendor_exec, exec_type, vendor_file_type, file_type;
+
+init_daemon_domain(h2omg_vendor);
+
+allow h2omg_vendor sysfs_batteryinfo:dir search;
+allow h2omg_vendor sysfs_h2omg_drv:dir r_dir_perms;
+allow h2omg_vendor sysfs_h2omg_dev:dir r_dir_perms;
+allow h2omg_vendor sysfs_h2omg_fuse:file rw_file_perms;
diff --git a/h2omg/pixelstats_vendor.te b/h2omg/pixelstats_vendor.te
new file mode 100644
index 0000000..be6183d
--- /dev/null
+++ b/h2omg/pixelstats_vendor.te
@@ -0,0 +1,8 @@
+# Access needed for pixelstatus
+allow pixelstats_vendor sysfs_h2omg_drv:dir search;
+allow pixelstats_vendor sysfs_h2omg_dev:dir search;
+allow pixelstats_vendor sysfs_h2omg_drv:dir r_dir_perms;
+allow pixelstats_vendor sysfs_h2omg_dev:dir r_dir_perms;
+allow pixelstats_vendor sysfs_h2omg_dev:file r_file_perms;
+allow pixelstats_vendor sysfs_h2omg_fuse:file r_file_perms;
+
diff --git a/pixelstats/file_contexts b/pixelstats/file_contexts
deleted file mode 100644
index a899889..0000000
--- a/pixelstats/file_contexts
+++ /dev/null
@@ -1,3 +0,0 @@
-# pixelstats binary
-/vendor/bin/pixelstats-vendor           u:object_r:pixelstats_vendor_exec:s0
-
diff --git a/pixelstats/pixelstats_vendor.te b/pixelstats/pixelstats_vendor.te
index 5242c79..7e4c687 100644
--- a/pixelstats/pixelstats_vendor.te
+++ b/pixelstats/pixelstats_vendor.te
@@ -1,10 +1,6 @@
+# define pixelstats
 type pixelstats_vendor, domain;
-
-# IStats
-binder_use(pixelstats_vendor)
-
 type pixelstats_vendor_exec, exec_type, vendor_file_type, file_type;
-init_daemon_domain(pixelstats_vendor)
 
 # UeventListener
 r_dir_file(pixelstats_vendor, sysfs_batteryinfo)
@@ -44,3 +40,6 @@ allow pixelstats_vendor sysfs_zram:file r_file_perms;
 # Pixel MM Metrics 2024a2
 r_dir_file(pixelstats_vendor, proc_vendor_mm)
 r_dir_file(pixelstats_vendor, sysfs_vendor_mm)
+
+# Pixel Water Intrusion Stats (h2omg)
+#  see h2omg/pixelstats_vendor.te for additional access policies
diff --git a/power-libperfmgr/hal_power_default.te b/power-libperfmgr/hal_power_default.te
index 8d6a9fe..121fa09 100644
--- a/power-libperfmgr/hal_power_default.te
+++ b/power-libperfmgr/hal_power_default.te
@@ -35,6 +35,10 @@ allow hal_power_default sysfs_thermal:file rw_file_perms;
 allow hal_power_default sysfs_thermal:lnk_file r_file_perms;
 set_prop(hal_power_default, vendor_thermal_prop)
 
+# Allow hal_power to access IStats AIDL
+allow hal_power_default fwk_stats_service:service_manager find;
+binder_call(hal_power_default, stats_service_server);
+
 userdebug_or_eng(`
 # Allow reading /data/vendor/* for debugging
   allow hal_power_default vendor_data_file:file r_file_perms;
```

