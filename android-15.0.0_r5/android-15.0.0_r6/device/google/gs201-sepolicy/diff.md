```diff
diff --git a/tracking_denials/bug_map b/tracking_denials/bug_map
index 75fe53c..aa33000 100644
--- a/tracking_denials/bug_map
+++ b/tracking_denials/bug_map
@@ -1,6 +1,11 @@
+dump_display sysfs file b/350831939
+dump_modem sscoredump_vendor_data_coredump_file dir b/361726277
+dump_modem sscoredump_vendor_data_logcat_file dir b/361726277
+dumpstate unlabeled file b/350832009
 hal_face_default traced_producer_socket sock_file b/305600808
 hal_power_default hal_power_default capability b/237492146
 hal_sensors_default sysfs file b/336451433
+hal_vibrator_default default_android_service service_manager b/360057889
 incidentd debugfs_wakeup_sources file b/282626428
 incidentd incidentd anon_inode b/282626428
 insmod-sh insmod-sh key b/336451874
@@ -9,7 +14,9 @@ kernel kernel capability b/336451113
 kernel tmpfs chr_file b/321731318
 rfsd vendor_cbd_prop file b/317734397
 shell sysfs_net file b/329380891
+ssr_detector_app default_prop file b/359428005
 surfaceflinger selinuxfs file b/315104594
+system_server vendor_default_prop file b/366116786
 vendor_init debugfs_trace_marker file b/336451787
 vendor_init default_prop file b/315104479
 vendor_init default_prop file b/315104803
@@ -18,3 +25,5 @@ vendor_init default_prop file b/323086890
 vendor_init default_prop file b/329380363
 vendor_init default_prop file b/329381126
 vendor_init default_prop property_service b/315104803
+vendor_init default_prop property_service b/359427666
+vendor_init default_prop property_service b/359428317
diff --git a/whitechapel_pro/device.te b/whitechapel_pro/device.te
index ae74fea..d23a1ad 100644
--- a/whitechapel_pro/device.te
+++ b/whitechapel_pro/device.te
@@ -1,8 +1,6 @@
+# device.te
 type modem_block_device, dev_type;
 type custom_ab_block_device, dev_type;
-type persist_block_device, dev_type;
-type efs_block_device, dev_type;
-type modem_userdata_block_device, dev_type;
 type mfg_data_block_device, dev_type;
 type vendor_toe_device, dev_type;
 type lwis_device, dev_type;
@@ -20,3 +18,4 @@ type fips_block_device, dev_type;
 # SecureElement SPI device
 type st54spi_device, dev_type;
 type st33spi_device, dev_type;
+
diff --git a/whitechapel_pro/dump_power.te b/whitechapel_pro/dump_power.te
new file mode 100644
index 0000000..d745b20
--- /dev/null
+++ b/whitechapel_pro/dump_power.te
@@ -0,0 +1,15 @@
+# Allow dumpstate to execute dump_power
+pixel_bugreport(dump_power);
+
+allow dump_power sysfs_acpm_stats:dir r_dir_perms;
+allow dump_power sysfs_acpm_stats:file r_file_perms;
+allow dump_power sysfs_cpu:file r_file_perms;
+allow dump_power sysfs_wlc:file r_file_perms;
+allow dump_power sysfs_wlc:dir search;
+allow dump_power sysfs_batteryinfo:dir r_dir_perms;
+allow dump_power sysfs_batteryinfo:file r_file_perms;
+allow dump_power logbuffer_device:chr_file r_file_perms;
+allow dump_power mitigation_vendor_data_file:dir r_dir_perms;
+allow dump_power mitigation_vendor_data_file:file r_file_perms;
+allow dump_power sysfs_bcl:dir r_dir_perms;
+allow dump_power sysfs_bcl:file r_file_perms;
diff --git a/whitechapel_pro/dump_power_gs201.te b/whitechapel_pro/dump_power_gs201.te
deleted file mode 100644
index b61001c..0000000
--- a/whitechapel_pro/dump_power_gs201.te
+++ /dev/null
@@ -1,30 +0,0 @@
-
-pixel_bugreport(dump_power_gs201)
-allow dump_power_gs201 sysfs_acpm_stats:dir r_dir_perms;
-allow dump_power_gs201 sysfs_acpm_stats:file r_file_perms;
-allow dump_power_gs201 sysfs_cpu:file r_file_perms;
-allow dump_power_gs201 vendor_toolbox_exec:file execute_no_trans;
-allow dump_power_gs201 logbuffer_device:chr_file r_file_perms;
-allow dump_power_gs201 mitigation_vendor_data_file:dir r_dir_perms;
-allow dump_power_gs201 sysfs:dir r_dir_perms;
-allow dump_power_gs201 sysfs_batteryinfo:dir r_dir_perms;
-allow dump_power_gs201 sysfs_batteryinfo:file r_file_perms;
-allow dump_power_gs201 sysfs_bcl:dir r_dir_perms;
-allow dump_power_gs201 sysfs_bcl:file r_file_perms;
-allow dump_power_gs201 sysfs_wlc:dir r_dir_perms;
-allow dump_power_gs201 sysfs_wlc:file r_file_perms;
-allow dump_power_gs201 battery_history_device:chr_file r_file_perms;
-allow dump_power_gs201 mitigation_vendor_data_file:file r_file_perms;
-
-userdebug_or_eng(`
-  allow dump_power_gs201 debugfs:dir r_dir_perms;
-  allow dump_power_gs201 vendor_battery_debugfs:dir r_dir_perms;
-  allow dump_power_gs201 vendor_battery_debugfs:file r_file_perms;
-  allow dump_power_gs201 vendor_charger_debugfs:dir r_dir_perms;
-  allow dump_power_gs201 vendor_charger_debugfs:file r_file_perms;
-  allow dump_power_gs201 vendor_pm_genpd_debugfs:file r_file_perms;
-  allow dump_power_gs201 vendor_maxfg_debugfs:dir r_dir_perms;
-  allow dump_power_gs201 vendor_maxfg_debugfs:file r_file_perms;
-  allow dump_power_gs201 vendor_votable_debugfs:dir r_dir_perms;
-  allow dump_power_gs201 vendor_votable_debugfs:file r_file_perms;
-')
diff --git a/whitechapel_pro/file_contexts b/whitechapel_pro/file_contexts
index 4bed047..dc8e89b 100644
--- a/whitechapel_pro/file_contexts
+++ b/whitechapel_pro/file_contexts
@@ -15,6 +15,7 @@
 /vendor/bin/trusty_apploader                                                u:object_r:trusty_apploader_exec:s0
 /vendor/bin/trusty_metricsd                                                 u:object_r:trusty_metricsd_exec:s0
 /vendor/bin/dumpsys                                                         u:object_r:vendor_dumpsys:s0
+/vendor/bin/dump/dump_power                                                 u:object_r:dump_power_exec:s0
 /vendor/bin/init\.uwb\.calib\.sh                                            u:object_r:vendor_uwb_init_exec:s0
 /vendor/bin/hw/android\.hardware\.gatekeeper@1\.0-service\.trusty           u:object_r:hal_gatekeeper_default_exec:s0
 /vendor/bin/hw/android\.hardware\.gatekeeper-service\.trusty                u:object_r:hal_gatekeeper_default_exec:s0
@@ -40,8 +41,6 @@
 /vendor/bin/hw/android\.hardware\.memtrack-service\.pixel                   u:object_r:hal_memtrack_default_exec:s0
 /system_ext/bin/convert_to_ext4\.sh                                         u:object_r:convert-to-ext4-sh_exec:s0
 /vendor/bin/hw/disable_contaminant_detection\.sh                            u:object_r:disable-contaminant-detection-sh_exec:s0
-/vendor/bin/dump/dump_power_gs201\.sh                                       u:object_r:dump_power_gs201_exec:s0
-/vendor/bin/ufs_firmware_update\.sh                                         u:object_r:ufs_firmware_update_exec:s0
 /vendor/bin/init\.check_ap_pd_auth\.sh                                      u:object_r:init-check_ap_pd_auth-sh_exec:s0
 
 # Vendor Firmwares
@@ -60,6 +59,7 @@
 /vendor/lib(64)?/libGralloc4Wrapper\.so                                     u:object_r:same_process_hal_file:s0
 /vendor/lib(64)?/pixel-power-ext-V1-ndk\.so                                 u:object_r:same_process_hal_file:s0
 /vendor/lib(64)?/android\.frameworks\.stats-V1-ndk\.so                      u:object_r:same_process_hal_file:s0
+/vendor/lib(64)?/android\.frameworks\.stats-V2-ndk\.so                      u:object_r:same_process_hal_file:s0
 /vendor/lib(64)?/vendor-pixelatoms-cpp\.so                                  u:object_r:same_process_hal_file:s0
 /vendor/lib(64)?/libprotobuf-cpp-lite-(\d+\.){2,3}so                        u:object_r:same_process_hal_file:s0
 
diff --git a/whitechapel_pro/genfs_contexts b/whitechapel_pro/genfs_contexts
index d8e63eb..ee65fab 100644
--- a/whitechapel_pro/genfs_contexts
+++ b/whitechapel_pro/genfs_contexts
@@ -33,6 +33,7 @@ genfscon sysfs /devices/platform/28000000.mali/dma_buf_gpu_mem                 u
 genfscon sysfs /devices/platform/28000000.mali/total_gpu_mem                   u:object_r:sysfs_gpu:s0
 genfscon sysfs /devices/platform/28000000.mali/kprcs                           u:object_r:sysfs_gpu:s0
 genfscon sysfs /devices/platform/28000000.mali/dvfs_period                     u:object_r:sysfs_gpu:s0
+genfscon sysfs /devices/platform/28000000.mali/cur_freq                        u:object_r:sysfs_gpu:s0
 
 # Fabric
 genfscon sysfs /devices/platform/17000010.devfreq_mif/devfreq/17000010.devfreq_mif/min_freq                u:object_r:sysfs_fabric:s0
@@ -64,6 +65,55 @@ genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-me
 genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device             u:object_r:sysfs_odpm:s0
 genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/wakeup                 u:object_r:sysfs_wakeup:s0
 
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_power0_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_power1_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_power2_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_power3_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_power4_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_power5_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_power6_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_power7_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_power8_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_power9_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_power10_scale   u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_power11_scale   u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_power0_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_power1_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_power2_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_power3_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_power4_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_power5_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_power6_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_power7_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_power8_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_power9_scale    u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_power10_scale   u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_power11_scale   u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_current0_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_current1_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_current2_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_current3_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_current4_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_current5_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_current6_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_current7_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_current8_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_current9_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_current10_scale u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18100000/i2c-20/20-001f/s2mpg12-meter/s2mpg12-odpm//iio:device0/in_current11_scale u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_current0_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_current1_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_current2_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_current3_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_current4_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_current5_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_current6_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_current7_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_current8_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_current9_scale  u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_current10_scale u:object_r:sysfs_odpm:s0
+genfscon sysfs /devices/platform/acpm_mfd_bus@18110000/i2c-21/21-002f/s2mpg13-meter/s2mpg13-odpm/iio:device1/in_current11_scale u:object_r:sysfs_odpm:s0
+
 # Devfreq current frequency
 genfscon sysfs /devices/platform/17000010.devfreq_mif/devfreq/17000010.devfreq_mif/cur_freq             u:object_r:sysfs_devfreq_cur:s0
 genfscon sysfs /devices/platform/17000020.devfreq_int/devfreq/17000020.devfreq_int/cur_freq             u:object_r:sysfs_devfreq_cur:s0
@@ -102,12 +152,16 @@ genfscon sysfs /devices/platform/1c2c0000.drmdsim/1c2c0000.drmdsim.0/panel_extin
 genfscon sysfs /devices/platform/1c2c0000.drmdsim/1c2c0000.drmdsim.0/panel_name                           u:object_r:sysfs_display:s0
 genfscon sysfs /devices/platform/1c2c0000.drmdsim/1c2c0000.drmdsim.0/serial_number                        u:object_r:sysfs_display:s0
 genfscon sysfs /devices/platform/1c2c0000.drmdsim/1c2c0000.drmdsim.0/refresh_rate                         u:object_r:sysfs_display:s0
+genfscon sysfs /devices/platform/1c2c0000.drmdsim/1c2c0000.drmdsim.0/panel_pwr_vreg                       u:object_r:sysfs_display:s0
+genfscon sysfs /devices/platform/1c2c0000.drmdsim/1c2c0000.drmdsim.0/power_mode                           u:object_r:sysfs_display:s0
+genfscon sysfs /devices/platform/1c2c0000.drmdsim/1c2c0000.drmdsim.0/power_state                          u:object_r:sysfs_display:s0
 
 genfscon sysfs /devices/platform/1c2d0000.drmdsim/1c2d0000.drmdsim.0/backlight                            u:object_r:sysfs_leds:s0
 genfscon sysfs /devices/platform/1c2d0000.drmdsim/1c2d0000.drmdsim.0/panel_extinfo                        u:object_r:sysfs_display:s0
 genfscon sysfs /devices/platform/1c2d0000.drmdsim/1c2d0000.drmdsim.0/panel_name                           u:object_r:sysfs_display:s0
 genfscon sysfs /devices/platform/1c2d0000.drmdsim/1c2d0000.drmdsim.0/serial_number                        u:object_r:sysfs_display:s0
 genfscon sysfs /devices/platform/1c2d0000.drmdsim/1c2d0000.drmdsim.0/refresh_rate                         u:object_r:sysfs_display:s0
+genfscon sysfs /devices/platform/1c2d0000.drmdsim/1c2d0000.drmdsim.0/power_state                          u:object_r:sysfs_display:s0
 
 genfscon sysfs /devices/platform/1c240000.drmdecon/dqe0/atc                                               u:object_r:sysfs_display:s0
 genfscon sysfs /devices/platform/1c241000.drmdecon/dqe1/atc                                               u:object_r:sysfs_display:s0
diff --git a/whitechapel_pro/hal_camera_default.te b/whitechapel_pro/hal_camera_default.te
index 25f2ffc..af2350f 100644
--- a/whitechapel_pro/hal_camera_default.te
+++ b/whitechapel_pro/hal_camera_default.te
@@ -88,6 +88,7 @@ allow hal_camera_default sysfs_devfreq_cur:file r_file_perms;
 # Allow camera HAL to read backlight of display
 allow hal_camera_default sysfs_leds:dir r_dir_perms;
 allow hal_camera_default sysfs_leds:file r_file_perms;
+allow hal_camera_default sysfs_display:file r_file_perms;
 
 # Allow camera HAL to send trace packets to Perfetto
 userdebug_or_eng(`perfetto_producer(hal_camera_default)')
diff --git a/whitechapel_pro/hal_radioext_default.te b/whitechapel_pro/hal_radioext_default.te
index fb6bc03..7e21da8 100644
--- a/whitechapel_pro/hal_radioext_default.te
+++ b/whitechapel_pro/hal_radioext_default.te
@@ -4,6 +4,7 @@ init_daemon_domain(hal_radioext_default)
 
 hwbinder_use(hal_radioext_default)
 get_prop(hal_radioext_default, hwservicemanager_prop)
+set_prop(hal_radioext_default, vendor_gril_prop)
 add_hwservice(hal_radioext_default, hal_radioext_hwservice)
 
 binder_call(hal_radioext_default, grilservice_app)
diff --git a/whitechapel_pro/kernel.te b/whitechapel_pro/kernel.te
index d44eed6..1af0a9a 100644
--- a/whitechapel_pro/kernel.te
+++ b/whitechapel_pro/kernel.te
@@ -1,4 +1,4 @@
-allow kernel vendor_fw_file:dir search;
+allow kernel vendor_fw_file:dir r_dir_perms;
 allow kernel vendor_fw_file:file r_file_perms;
 
 # ZRam
diff --git a/whitechapel_pro/modem_svc_sit.te b/whitechapel_pro/modem_svc_sit.te
index 5a703c9..606cd52 100644
--- a/whitechapel_pro/modem_svc_sit.te
+++ b/whitechapel_pro/modem_svc_sit.te
@@ -48,4 +48,9 @@ perfetto_producer(modem_svc_sit)
 # Allow modem_svc_sit to access modem image file/dir
 allow modem_svc_sit modem_img_file:dir r_dir_perms;
 allow modem_svc_sit modem_img_file:file r_file_perms;
-allow modem_svc_sit modem_img_file:lnk_file r_file_perms;
\ No newline at end of file
+allow modem_svc_sit modem_img_file:lnk_file r_file_perms;
+
+# Allow modem_svc_sit to access socket for UMI
+userdebug_or_eng(`
+  allow modem_svc_sit radio_vendor_data_file:sock_file { create unlink };
+')
diff --git a/whitechapel_pro/property.te b/whitechapel_pro/property.te
index 559511a..2dfe16d 100644
--- a/whitechapel_pro/property.te
+++ b/whitechapel_pro/property.te
@@ -1,9 +1,12 @@
+# whitechapel_pro Property Define
+
 vendor_internal_prop(vendor_diag_prop)
 vendor_internal_prop(vendor_slog_prop)
 vendor_internal_prop(vendor_modem_prop)
 vendor_internal_prop(vendor_persist_config_default_prop)
 vendor_internal_prop(vendor_cbd_prop)
 vendor_internal_prop(vendor_rild_prop)
+vendor_internal_prop(vendor_gril_prop)
 vendor_internal_prop(vendor_carrier_prop)
 vendor_internal_prop(vendor_ssrdump_prop)
 vendor_internal_prop(vendor_wifi_version)
@@ -23,7 +26,7 @@ vendor_internal_prop(vendor_persist_sys_default_prop)
 vendor_internal_prop(vendor_display_prop)
 
 # Fingerprint
-vendor_internal_prop(vendor_fingerprint_prop)
+vendor_restricted_prop(vendor_fingerprint_prop)
 
 # UWB calibration
 system_vendor_config_prop(vendor_uwb_calibration_prop)
@@ -44,3 +47,6 @@ vendor_restricted_prop(vendor_arm_runtime_option_prop)
 
 # SJTAG lock state
 vendor_internal_prop(vendor_sjtag_lock_state_prop)
+
+# Bluetooth props
+vendor_restricted_prop(vendor_bluetooth_prop)
diff --git a/whitechapel_pro/property_contexts b/whitechapel_pro/property_contexts
index 0ff833e..9f1747b 100644
--- a/whitechapel_pro/property_contexts
+++ b/whitechapel_pro/property_contexts
@@ -38,6 +38,9 @@ vendor.sys.rild_reset                      u:object_r:vendor_rild_prop:s0
 persist.vendor.radio.                      u:object_r:vendor_rild_prop:s0
 ro.vendor.config.build_carrier             u:object_r:vendor_carrier_prop:s0
 
+# for GRIL
+vendor.gril.                               u:object_r:vendor_gril_prop:s0
+
 persist.vendor.config.                     u:object_r:vendor_persist_config_default_prop:s0
 
 # SSR Detector
diff --git a/whitechapel_pro/ufs_firmware_update.te b/whitechapel_pro/ufs_firmware_update.te
index f33c2da..121e462 100644
--- a/whitechapel_pro/ufs_firmware_update.te
+++ b/whitechapel_pro/ufs_firmware_update.te
@@ -1,11 +1,11 @@
-type ufs_firmware_update, domain;
-type ufs_firmware_update_exec, vendor_file_type, exec_type, file_type;
-
+# ufs ffu
 init_daemon_domain(ufs_firmware_update)
 
+# ufs ffu
 allow ufs_firmware_update vendor_toolbox_exec:file execute_no_trans;
 allow ufs_firmware_update block_device:dir r_dir_perms;
 allow ufs_firmware_update fips_block_device:blk_file rw_file_perms;
 allow ufs_firmware_update sysfs:dir r_dir_perms;
 allow ufs_firmware_update sysfs_scsi_devices_0000:dir search;
 allow ufs_firmware_update sysfs_scsi_devices_0000:file r_file_perms;
+
```

