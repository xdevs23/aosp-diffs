```diff
diff --git a/Android.mk b/Android.mk
deleted file mode 100644
index 14b535868..000000000
--- a/Android.mk
+++ /dev/null
@@ -1,85 +0,0 @@
-#
-# Copyright (C) 2016 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-#
-
-LOCAL_PATH := $(call my-dir)
-
-include $(call all-subdir-makefiles)
-
-ifeq ($(HOST_OS),linux)
-
-# ACTS framework
-ACTS_DISTRO := $(HOST_OUT)/acts-dist/acts.zip
-
-$(ACTS_DISTRO): $(sort $(shell find $(LOCAL_PATH)/acts))
-	@echo "Packaging ACTS into $(ACTS_DISTRO)"
-	@mkdir -p $(HOST_OUT)/acts-dist/
-	@rm -f $(HOST_OUT)/acts-dist/acts.zip
-	$(hide) zip $(HOST_OUT)/acts-dist/acts.zip $(shell find tools/test/connectivity/acts/* ! -wholename "*__pycache__*")
-acts: $(ACTS_DISTRO)
-.PHONY: acts
-
-$(call dist-for-goals,acts tests,$(ACTS_DISTRO))
-
-
-# core ACTS test suite
-ACTS_TESTS_DISTRO_DIR := $(HOST_OUT)/acts_tests-dist
-ACTS_TESTS_DISTRO := $(ACTS_TESTS_DISTRO_DIR)/acts_tests.zip
-LOCAL_ACTS_TESTS_DIR := tools/test/connectivity/acts_tests
-LOCAL_ACTS_FRAMEWORK_DIR := tools/test/connectivity/acts/framework
-
-$(ACTS_TESTS_DISTRO): $(sort $(shell find $(LOCAL_PATH)/acts*))
-	@echo "Packaging ACTS core test suite into $(ACTS_TESTS_DISTRO)"
-	@rm -rf $(ACTS_TESTS_DISTRO_DIR)
-	# Copy over the contents of acts_tests, resolving symlinks
-	@rsync -auv --copy-links $(LOCAL_ACTS_TESTS_DIR)/ $(ACTS_TESTS_DISTRO_DIR)
-	# Copy over the ACTS framework
-	@rsync -auv $(LOCAL_ACTS_FRAMEWORK_DIR)/ $(ACTS_TESTS_DISTRO_DIR)/acts_framework
-	# Make a zip archive
-	@cd $(ACTS_TESTS_DISTRO_DIR) && find . ! -wholename "*__pycache__*" -printf "%P\n" | xargs zip acts_tests.zip
-acts_tests: $(ACTS_TESTS_DISTRO)
-.PHONY: acts_tests
-
-$(call dist-for-goals,acts_tests tests,$(ACTS_TESTS_DISTRO))
-
-
-# Wear specific Android Connectivity Test Suite
-WTS_ACTS_DISTRO_DIR := $(HOST_OUT)/wts-acts-dist
-WTS_ACTS_DISTRO := $(WTS_ACTS_DISTRO_DIR)/wts-acts
-WTS_ACTS_DISTRO_ARCHIVE := $(WTS_ACTS_DISTRO_DIR)/wts-acts.zip
-WTS_LOCAL_ACTS_DIR := tools/test/connectivity/acts/framework/acts/
-
-$(WTS_ACTS_DISTRO): $(SOONG_ZIP)
-	@echo "Packaging WTS-ACTS into $(WTS_ACTS_DISTRO)"
-	# clean-up and mkdir for dist
-	@rm -Rf $(WTS_ACTS_DISTRO_DIR)
-	@mkdir -p $(WTS_ACTS_DISTRO_DIR)
-	# grab the files from local acts framework and zip them up
-	$(hide) find $(WTS_LOCAL_ACTS_DIR) | sort >$@.list
-	$(hide) $(SOONG_ZIP) -d -P acts -o $(WTS_ACTS_DISTRO_ARCHIVE) -C tools/test/connectivity/acts/framework/acts/ -l $@.list
-	# add in the local wts py files for use with the prebuilt
-	$(hide) zip -r $(WTS_ACTS_DISTRO_ARCHIVE) -j tools/test/connectivity/wts-acts/*.py
-	# create executable tool from the archive
-	$(hide) echo '#!/usr/bin/env python3' | cat - $(WTS_ACTS_DISTRO_DIR)/wts-acts.zip > $(WTS_ACTS_DISTRO_DIR)/wts-acts
-	$(hide) chmod 755 $(WTS_ACTS_DISTRO)
-
-wts-acts: $(WTS_ACTS_DISTRO)
-.PHONY: wts-acts
-
-$(call dist-for-goals,wts-acts tests,$(WTS_ACTS_DISTRO))
-
-
-
-endif
diff --git a/acts_tests/acts_contrib/test_utils/cellular/keysight_5g_testapp.py b/acts_tests/acts_contrib/test_utils/cellular/keysight_5g_testapp.py
index 430f39649..fb1e320b4 100644
--- a/acts_tests/acts_contrib/test_utils/cellular/keysight_5g_testapp.py
+++ b/acts_tests/acts_contrib/test_utils/cellular/keysight_5g_testapp.py
@@ -495,6 +495,16 @@ class Keysight5GTestApp(object):
             'BSE:CONFig:LTE:{}:PHY:DL:SFRame:ALLocation:ALL {}'.format(
                 Keysight5GTestApp._format_cells(cell), dl_subframe_allocation))
 
+    @skip_config_if_none_decorator
+    def set_lte_cell_tdd_frame_config(self, cell, frame_config=1, ssf_config=1):
+        self.send_cmd(
+            'BSE:CONFig:LTE:{}:PHY:TDD:ULDL:CONFig {}'.format(
+                Keysight5GTestApp._format_cells(cell), frame_config))
+        self.send_cmd(
+            'BSE:CONFig:LTE:{}:PHY:TDD:SSFRame:CONFig {}'.format(
+                Keysight5GTestApp._format_cells(cell), ssf_config))
+
+
     def set_cell_dl_power(self, cell_type, cell, power, full_bw):
         """Function to set cell power
 
@@ -636,7 +646,7 @@ class Keysight5GTestApp(object):
                 tdd_pattern_mapping[tdd_pattern]))
         self.send_cmd('BSE:CONFig:NR5G:SCHeduling:QCONFig:APPLy:ALL')
 
-    def set_nr_cell_mcs(self, cell, dl_mcs, ul_mcs):
+    def set_nr_cell_mcs(self, cell, dl_mcs_table, dl_mcs, ul_mcs_table, ul_mcs):
         """Function to set NR cell DL & UL MCS
 
         Args:
@@ -647,6 +657,12 @@ class Keysight5GTestApp(object):
         self.assert_cell_off('NR5G', cell)
         frame_config_count = 5
         slot_config_count = 8
+        self.send_cmd(
+            'BSE:CONFig:NR5G:SCHeduling:SETParameter "CELLALL:BWPALL", "DL:MCS:TABle", "{}"'
+            .format(dl_mcs_table))
+        self.send_cmd(
+            'BSE:CONFig:NR5G:SCHeduling:SETParameter "CELLALL:BWPALL", "UL:MCS:TABle", "{}"'
+            .format(ul_mcs_table))
         if isinstance(dl_mcs, dict):
             self.configure_nr_link_adaptation(cell, link_config=dl_mcs)
         else:
@@ -723,15 +739,17 @@ class Keysight5GTestApp(object):
             'BSE:CONFig:LTE:SCHeduling:SETParameter "CELLALL", "DL:MCS:TABle", "{}"'
             .format(dl_mcs_table_formatted))
         self.configure_lte_periodic_csi_reporting(cell, 1)
-        if dl_mcs == 'WCQI':
-            self.send_cmd('BSE:CONFig:LTE:{}:PHY:DL:IMCS:MODE WCQI'.format(
-                Keysight5GTestApp._format_cells(cell)))
-        else:
+
+        if isinstance(dl_mcs, dict) and dl_mcs['link_policy'] == 'WCQI':
+            self.configure_lte_link_adaptation(cell, dl_mcs)
+        elif isinstance(dl_mcs, int):
             self.send_cmd('BSE:CONFig:LTE:{}:PHY:DL:IMCS:MODE EXPLicit'.format(
                 Keysight5GTestApp._format_cells(cell)))
             self.send_cmd(
                 'BSE:CONFig:LTE:SCHeduling:SETParameter "CELLALL:SFALL:CWALL", "DL:IMCS", "{}"'
                 .format(dl_mcs))
+        else:
+            self.log.error('Invalid LTE MCS setting.')
         self.send_cmd(
             'BSE:CONFig:LTE:SCHeduling:SETParameter "CELLALL", "UL:MCS:TABle", "{}"'
             .format(ul_mcs_table))
@@ -739,6 +757,42 @@ class Keysight5GTestApp(object):
             'BSE:CONFig:LTE:SCHeduling:SETParameter "CELLALL:SFALL", "UL:IMCS", "{}"'
             .format(ul_mcs))
 
+    def configure_lte_link_adaptation(self, cell, link_config):
+        self.send_cmd('BSE:CONFig:LTE:{}:PHY:DL:IMCS:MODE WCQI'.format(
+            Keysight5GTestApp._format_cells(cell)))
+        self.send_cmd('BSE:CONFig:LTE:{}:SCHeduling:DL:ALGorithm:BLER:STATE {}'.format(
+            Keysight5GTestApp._format_cells(cell), link_config['bler_adaptation']))
+        if int(link_config['bler_adaptation']):
+            full_link_config = {'max_mcs_offset': 20,  'min_mcs_offset': -20, 'bler_high_threshold': 15,
+                                   'bler_low_threshold': 5, 'bler_adaptation_window': 100, 'bler_min_ack_nack': 10,
+                                   'rank_adjustment': 0, 'rank_adjustment_mcs': 5, 'rank_adjustment_mcs_offset': 10,
+                                   'rank_adjustment_min_ack_nack': 50}
+            full_link_config.update(link_config)
+            self.log.info(full_link_config)
+
+            self.send_cmd('BSE:CONFig:LTE:{}:SCHeduling:DL:ALGorithm:BLER:MAX:MCS:OFFSet {}'.format(
+                Keysight5GTestApp._format_cells(cell), full_link_config['max_mcs_offset']))
+            self.send_cmd('BSE:CONFig:LTE:{}:SCHeduling:DL:ALGorithm:BLER:MCS:MIN:OFFSet {}'.format(
+                Keysight5GTestApp._format_cells(cell), full_link_config['min_mcs_offset']))
+            self.send_cmd('BSE:CONFig:LTE:{}:SCHeduling:DL:ALGorithm:BLER:HIGH:THReshold {}'.format(
+                Keysight5GTestApp._format_cells(cell), full_link_config['bler_high_threshold']))
+            self.send_cmd('BSE:CONFig:LTE:{}:SCHeduling:DL:ALGorithm:BLER:LOW:THReshold {}'.format(
+                Keysight5GTestApp._format_cells(cell), full_link_config['bler_low_threshold']))
+            self.send_cmd('BSE:CONFig:LTE:{}:SCHeduling:DL:ALGorithm:BLER:ACK:NACK:WINDow:TTI {}'.format(
+                Keysight5GTestApp._format_cells(cell), full_link_config['bler_adaptation_window']))
+            self.send_cmd('BSE:CONFig:LTE:{}:SCHeduling:DL:ALGorithm:BLER:NUMBer:MINimum:ACK:NACK {}'.format(
+                Keysight5GTestApp._format_cells(cell), full_link_config['bler_min_ack_nack']))
+            self.send_cmd('BSE:CONFig:LTE:{}:SCHeduling:DL:ALGorithm:BLER:RANK:ADJust:STATE {}'.format(
+                Keysight5GTestApp._format_cells(cell), full_link_config['rank_adjustment']))
+            if int(full_link_config['rank_adjustment']):
+                self.send_cmd('BSE:CONFig:LTE:{}:SCHeduling:DL:ALGorithm:BLER:RANK:ADJust:MCS:ADJust {}'.format(
+                    Keysight5GTestApp._format_cells(cell), full_link_config['rank_adjustment_mcs']))
+                self.send_cmd('BSE:CONFig:LTE:{}:SCHeduling:DL:ALGorithm:BLER:RANK:ADJust:MCS:OFFSet {}'.format(
+                    Keysight5GTestApp._format_cells(cell), full_link_config['rank_adjustment_mcs_offset']))
+                self.send_cmd('BSE:CONFig:LTE:{}:SCHeduling:DL:ALGorithm:BLER:RANK:ADJust:MINimum:NUMBer:ACK:NACK {}'.format(
+                    Keysight5GTestApp._format_cells(cell), full_link_config['rank_adjustment_min_ack_nack']))
+
+
     def configure_lte_periodic_csi_reporting(self, cell, enable):
         """Function to enable/disable LTE CSI reporting."""
 
@@ -815,6 +869,15 @@ class Keysight5GTestApp(object):
     def set_channel_emulator_state(self, state):
         self.send_cmd('BSE:CONFig:FADing:ENABle {}'.format(int(state)))
 
+    def enable_awgn_noise(self, cell_type, cell, enable, noise_level=-100):
+        self.send_cmd('BSE:CONFig:{}:{}:IMPairments:AWGN:POWer {}'.format(cell_type,
+                                                                          Keysight5GTestApp._format_cells(cell),
+                                                                          noise_level))
+        self.send_cmd('BSE:CONFig:{}:{}:IMPairments:AWGN:STATe {}'.format(cell_type,
+                                                                          Keysight5GTestApp._format_cells(cell),
+                                                                          enable))
+        self.send_cmd('BSE:CONFig:{}:APPLY'.format(cell_type))
+
     def apply_lte_carrier_agg(self, cells):
         """Function to start LTE carrier aggregation on already configured cells"""
         if self.wait_for_cell_status('LTE', 'CELL1', 'CONN', 60):
@@ -976,10 +1039,11 @@ class Keysight5GTestApp(object):
         self._configure_bler_measurement(cell_type, 0, length)
         self._set_bler_measurement_state(cell_type, 1)
         time.sleep(0.1)
-        #bler_check = self.get_bler_result(cell_type, cells, length, 0)
-        #if bler_check['total']['DL']['frame_count'] == 0:
-        #    self.log.warning('BLER measurement did not start. Retrying')
-        #    self.start_bler_measurement(cell_type, cells, length)
+        bler_check = self.get_bler_result(cell_type, [1],[1], length, 0)
+        if bler_check['total']['DL']['frame_count'] == 0:
+            self.log.warning('BLER measurement did not start. Retrying')
+            self._set_bler_measurement_state(cell_type, 0)
+            self._set_bler_measurement_state(cell_type, 1)
 
     def _get_bler(self, cell_type, link, cell):
         """Helper function to get single-cell BLER measurement results."""
@@ -1041,9 +1105,11 @@ class Keysight5GTestApp(object):
             dl_cells = [dl_cells]
         if not isinstance(ul_cells, list):
             ul_cells = [ul_cells]
+        start_time = time.time()
         while wait_for_length:
             dl_bler = self._get_bler(cell_type, 'DL', dl_cells[0])
-            if dl_bler['frame_count'] < length:
+            elapsed_subframes = (time.time() - start_time)/SUBFRAME_DURATION
+            if dl_bler['frame_count'] < length and elapsed_subframes < 2*length:
                 time.sleep(polling_interval)
             else:
                 break
@@ -1181,6 +1247,6 @@ class Keysight5GTestApp(object):
                 cell_type, Keysight5GTestApp._format_cells(cell), num_reports),
             read_response=1)
         self.send_cmd('BSE:CONFig:{}:PReamble:REPort:CLEAr'.format(cell_type))
-        if 'No Data' in report:
+        if 'No data available' in report:
             report = None
         return report
diff --git a/acts_tests/acts_contrib/test_utils/cellular/performance/CellularThroughputBaseTest.py b/acts_tests/acts_contrib/test_utils/cellular/performance/CellularThroughputBaseTest.py
index 231c00c65..c1ad10f0c 100644
--- a/acts_tests/acts_contrib/test_utils/cellular/performance/CellularThroughputBaseTest.py
+++ b/acts_tests/acts_contrib/test_utils/cellular/performance/CellularThroughputBaseTest.py
@@ -51,7 +51,6 @@ PHONE_BATTERY_VOLTAGE_DEFAULT = 4
 from functools import wraps
 import logging
 
-
 def suspend_logging(func):
 
     @wraps(func)
@@ -121,6 +120,7 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
         if self.power_monitor:
             self.power_monitor.connect_usb()
             self.dut.wait_for_boot_completion()
+            self.dut_utils.start_services()
         self.log.info('Turning airplane mode on')
         try:
             self.dut_utils.toggle_airplane_mode(True, False)
@@ -139,8 +139,12 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
             self.dut_utils.start_pixel_logger()
 
     def teardown_test(self):
+        self.process_testcase_results()
         if self.power_monitor:
+            self.log.info('Reconnecting USB and waiting for boot completion.')
             self.power_monitor.connect_usb()
+            self.dut.wait_for_boot_completion()
+            self.dut_utils.start_services()
         self.retry_flag = False
         self.log.info('Turing airplane mode on')
         self.dut_utils.toggle_airplane_mode(True, False)
@@ -151,7 +155,6 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
         os.makedirs(self.log_path, exist_ok=True)
         if self.testclass_params.get('enable_pixel_logs', 0):
             self.dut_utils.stop_pixel_logger(log_path)
-        self.process_testcase_results()
         self.pass_fail_check()
 
     def on_retry(self):
@@ -179,14 +182,21 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
         self.log.debug('device start time %s, host start time %s', device_time,
                        host_time)
         self.device_to_host_offset = float(device_time) - host_time
-        if hasattr(self, 'bitses'):
+        self.power_monitor_config = {}
+        if hasattr(self, 'bitses') and self.testclass_params.get('measure_power', 1):
             power_monitor = self.bitses[0]
             power_monitor.setup(registry=self.user_params)
-        elif hasattr(self, 'monsoons'):
+            self.power_monitor_config = {'voltage': self.user_params['Bits'][0]['Monsoon']['monsoon_voltage'],
+                                         'frequency': 976.5925,
+                                         'measurement_type': 'power'}
+        elif hasattr(self, 'monsoons') and self.testclass_params.get('measure_power', 1):
             power_monitor = power_monitor_lib.PowerMonitorMonsoonFacade(
                 self.monsoons[0])
             self.monsoons[0].set_max_current(self.MonsoonParams['current'])
             self.monsoons[0].set_voltage(self.MonsoonParams['voltage'])
+            self.power_monitor_config = {'voltage': self.MonsoonParams['voltage'],
+                                         'frequency': self.MonsoonParams['frequency'],
+                                         'measurement_type': 'current'}
         else:
             power_monitor = None
         return power_monitor
@@ -323,52 +333,20 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
         return result
 
     def run_single_throughput_measurement(self, testcase_params):
-        result = collections.OrderedDict()
-        self.log.info('Starting BLER & throughput tests.')
-        if testcase_params['endc_combo_config']['nr_cell_count']:
-            self.keysight_test_app.start_bler_measurement(
-                'NR5G', testcase_params['endc_combo_config']['nr_dl_carriers'],
-                testcase_params['bler_measurement_length'])
-        if testcase_params['endc_combo_config']['lte_cell_count']:
-            self.keysight_test_app.start_bler_measurement(
-                'LTE',
-                testcase_params['endc_combo_config']['lte_dl_carriers'][0],
-                testcase_params['bler_measurement_length'])
-
-        if self.testclass_params['traffic_type'] != 'PHY':
-            result['iperf_throughput'] = self.run_iperf_traffic(
-                testcase_params)
-
-        if testcase_params['endc_combo_config']['nr_cell_count']:
-            result['nr_bler_result'] = self.keysight_test_app.get_bler_result(
-                'NR5G', testcase_params['endc_combo_config']['nr_dl_carriers'],
-                testcase_params['endc_combo_config']['nr_ul_carriers'],
-                testcase_params['bler_measurement_length'])
-            result['nr_tput_result'] = self.keysight_test_app.get_throughput(
-                'NR5G', testcase_params['endc_combo_config']['nr_dl_carriers'],
-                testcase_params['endc_combo_config']['nr_ul_carriers'])
-        if testcase_params['endc_combo_config']['lte_cell_count']:
-            result['lte_bler_result'] = self.keysight_test_app.get_bler_result(
-                cell_type='LTE',
-                dl_cells=testcase_params['endc_combo_config']
-                ['lte_dl_carriers'],
-                ul_cells=testcase_params['endc_combo_config']
-                ['lte_ul_carriers'],
-                length=testcase_params['bler_measurement_length'])
-            result['lte_tput_result'] = self.keysight_test_app.get_throughput(
-                'LTE', testcase_params['endc_combo_config']['lte_dl_carriers'],
-                testcase_params['endc_combo_config']['lte_ul_carriers'])
+        self.start_single_throughput_measurement(testcase_params)
+        result = self.stop_single_throughput_measurement(testcase_params)
         return result
 
-    @suspend_logging
+    #@suspend_logging
     def meausre_power_silently(self, measurement_time, measurement_wait,
-                               data_path):
+                               data_path, measurement_tag):
+        measurement_name = '{}_{}'.format(self.test_name, measurement_tag)
         measurement_args = dict(duration=measurement_time,
                                 measure_after_seconds=measurement_wait,
-                                hz=self.MonsoonParams['frequency'])
+                                hz=self.power_monitor_config['frequency'])
 
         self.power_monitor.measure(measurement_args=measurement_args,
-                                   measurement_name=self.test_name,
+                                   measurement_name=measurement_name,
                                    start_time=self.device_to_host_offset,
                                    monsoon_output_path=data_path)
 
@@ -386,12 +364,13 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
             measurement_tag: tag to append to file names
         """
         if self.dut.is_connected():
+            self.dut_utils.go_to_sleep()
             self.dut_utils.stop_services()
             time.sleep(SHORT_SLEEP)
             self.dut_utils.log_odpm(
                 os.path.join(
                     context.get_current_context().get_full_output_path(),
-                    '{}.txt'.format('before')))
+                    '{}_odpm_{}_{}.txt'.format(self.test_name, measurement_tag, 'start')))
             self.power_monitor.disconnect_usb()
         else:
             self.log.info('DUT already disconnected. Skipping USB operations.')
@@ -399,44 +378,58 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
         self.log.info('Starting power measurement. Duration: {}s. Offset: '
                       '{}s. Voltage: {} V.'.format(
                           measurement_time, measurement_wait,
-                          self.MonsoonParams['voltage']))
+                          self.power_monitor_config['voltage']))
         # Collecting current measurement data and plot
         tag = '{}_{}'.format(self.test_name, measurement_tag)
         data_path = os.path.join(
             context.get_current_context().get_full_output_path(),
             '{}.txt'.format(tag))
         self.meausre_power_silently(measurement_time, measurement_wait,
-                                    data_path)
+                                    data_path, measurement_tag)
         self.power_monitor.release_resources()
         if hasattr(self, 'bitses') and self.bits_root_rail_csv_export:
             path = os.path.join(
                 context.get_current_context().get_full_output_path(), 'Kibble')
+            os.makedirs(path, exist_ok=True)
             self.power_monitor.get_bits_root_rail_csv_export(
-                path, self.test_name)
+                path, '{}_{}'.format(self.test_name, measurement_tag))
+        samples = self.power_monitor.get_waveform(file_path=data_path)
 
         if reconnect_usb:
             self.log.info('Reconnecting USB.')
             self.power_monitor.connect_usb()
             self.dut.wait_for_boot_completion()
+            time.sleep(LONG_SLEEP)
             # Save ODPM if applicable
             self.dut_utils.log_odpm(
                 os.path.join(
                     context.get_current_context().get_full_output_path(),
-                    '{}.txt'.format('after')))
+                    '{}_odpm_{}_{}.txt'.format(self.test_name, measurement_tag, 'end')))
             # Restart Sl4a and other services
             self.dut_utils.start_services()
 
-        samples = self.power_monitor.get_waveform(file_path=data_path)
-
-        current = [sample[1] for sample in samples]
-        average_current = sum(current) * 1000 / len(current)
-        self.log.info('Average current computed: {}'.format(average_current))
+        measurement_samples = [sample[1] for sample in samples]
+        average_measurement = sum(measurement_samples) * 1000 / len(measurement_samples)
+        if self.power_monitor_config['measurement_type'] == 'current':
+            average_power = average_measurement * self.power_monitor_config['voltage']
+        else:
+            average_power = average_measurement
+        self.log.info('Average power : {}'.format(average_power))
         plot_title = '{}_{}'.format(self.test_name, measurement_tag)
         power_plot_utils.current_waveform_plot(
-            samples, self.MonsoonParams['voltage'],
+            samples, self.power_monitor_config['voltage'],
             context.get_current_context().get_full_output_path(), plot_title)
 
-        return average_current
+        return average_power
+
+    @wputils.nonblocking
+    def collect_power_data_nonblocking(self,
+                           measurement_time,
+                           measurement_wait,
+                           reconnect_usb=0,
+                           measurement_tag=0):
+        return self.collect_power_data(
+            measurement_time, measurement_wait, reconnect_usb, measurement_tag)
 
     def print_throughput_result(self, result):
         # Print Test Summary
@@ -491,10 +484,14 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
                     result['iperf_throughput']))
 
     def setup_tester(self, testcase_params):
+
         # Configure all cells
         self.keysight_test_app.toggle_contiguous_nr_channels(0)
         for cell_idx, cell in enumerate(
                 testcase_params['endc_combo_config']['cell_list']):
+            self.keysight_test_app.enable_awgn_noise(cell['cell_type'], cell['cell_number'], 0)
+            self.keysight_test_app.set_channel_emulator_state(0)
+
             if cell['cell_type'] == 'NR5G':
                 self.keysight_test_app.set_nr_cell_type(
                     cell['cell_type'], cell['cell_number'],
@@ -506,7 +503,7 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
                                                  cell['band'])
             self.keysight_test_app.set_cell_dl_power(
                 cell['cell_type'], cell['cell_number'],
-                testcase_params['cell_power_sweep'][cell_idx][0], 1)
+                testcase_params['cell_power_sweep'][cell_idx][0], 0)
             self.keysight_test_app.set_cell_input_power(
                 cell['cell_type'], cell['cell_number'],
                 self.testclass_params['input_power'][cell['cell_type']])
@@ -536,10 +533,20 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
                     cell['cell_number'], cell['num_codewords'])
                 self.keysight_test_app.set_lte_cell_num_layers(
                     cell['cell_number'], cell['num_layers'])
-                self.keysight_test_app.set_lte_cell_dl_subframe_allocation(
-                    cell['cell_number'], cell['dl_subframe_allocation'])
-                self.keysight_test_app.set_lte_control_region_size(
-                    cell['cell_number'], 1)
+
+                # self.keysight_test_app.set_lte_cell_dl_subframe_allocation(
+                #     cell['cell_number'], cell['dl_subframe_allocation'])
+                # self.keysight_test_app.set_lte_cell_tdd_frame_config(
+                #     cell['cell_number'], cell['tdd_frame_config'], cell['tdd_ssf_config'])
+                # self.keysight_test_app.set_lte_control_region_size(
+                #     cell['cell_number'], 1)
+                # self.keysight_test_app.set_lte_cell_mcs(
+                #     cell['cell_number'], testcase_params['lte_dl_mcs_table'],
+                #     testcase_params['lte_dl_mcs'],
+                #     testcase_params['lte_ul_mcs_table'],
+                #     testcase_params['lte_ul_mcs'])
+                # self.keysight_test_app.set_lte_ul_mac_padding(
+                #     self.testclass_params['lte_ul_mac_padding'])
             if cell['ul_enabled'] and cell['cell_type'] == 'NR5G':
                 self.keysight_test_app.set_cell_mimo_config(
                     cell['cell_type'], cell['cell_number'], 'UL',
@@ -553,29 +560,21 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
         if testcase_params.get('force_contiguous_nr_channel', False):
             self.keysight_test_app.toggle_contiguous_nr_channels(1)
 
-        if testcase_params['endc_combo_config']['lte_cell_count']:
-            self.keysight_test_app.set_lte_cell_mcs(
-                'CELL1', testcase_params['lte_dl_mcs_table'],
-                testcase_params['lte_dl_mcs'],
-                testcase_params['lte_ul_mcs_table'],
-                testcase_params['lte_ul_mcs'])
-            self.keysight_test_app.set_lte_ul_mac_padding(
-                self.testclass_params['lte_ul_mac_padding'])
-
         if testcase_params['endc_combo_config']['nr_cell_count']:
-            if 'schedule_scenario' in testcase_params:
-                self.keysight_test_app.set_nr_cell_schedule_scenario(
-                    'CELL1', testcase_params['schedule_scenario'])
-                if testcase_params['schedule_scenario'] == 'FULL_TPUT':
-                    self.keysight_test_app.set_nr_schedule_slot_ratio(
-                        'CELL1', testcase_params['schedule_slot_ratio'])
-                    self.keysight_test_app.set_nr_schedule_tdd_pattern(
-                        'CELL1', testcase_params.get('tdd_pattern', 0))
-            self.keysight_test_app.set_nr_ul_dft_precoding(
-                'CELL1', testcase_params['transform_precoding'])
-            self.keysight_test_app.set_nr_cell_mcs(
-                'CELL1', testcase_params['nr_dl_mcs'],
-                testcase_params['nr_ul_mcs'])
+            #if 'schedule_scenario' in testcase_params:
+            #     self.keysight_test_app.set_nr_cell_schedule_scenario(
+            #         'CELL1', testcase_params['schedule_scenario'])
+            #     if testcase_params['schedule_scenario'] == 'FULL_TPUT':
+            #         self.keysight_test_app.set_nr_schedule_slot_ratio(
+            #             'CELL1', testcase_params['schedule_slot_ratio'])
+            #         self.keysight_test_app.set_nr_schedule_tdd_pattern(
+            #             'CELL1', testcase_params.get('tdd_pattern', 0))
+            # self.keysight_test_app.set_nr_ul_dft_precoding(
+            #     'CELL1', testcase_params['transform_precoding'])
+            # self.keysight_test_app.set_nr_cell_mcs(
+            #     'CELL1', testcase_params['nr_dl_mcs_table'], testcase_params['nr_dl_mcs'],
+            #     testcase_params['nr_ul_mcs_table'],
+            #     testcase_params['nr_ul_mcs'])
             self.keysight_test_app.set_dl_carriers(
                 testcase_params['endc_combo_config']['nr_dl_carriers'])
             self.keysight_test_app.set_ul_carriers(
@@ -642,7 +641,7 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
                         'NR5G', 'CELL1', 'CONN', 10 * (idx + 1)):
                     self.log.info('Connected! Waiting for {} seconds.'.format(
                         LONG_SLEEP))
-                    time.sleep(LONG_SLEEP)
+                    time.sleep(10*LONG_SLEEP)
                     break
                 elif idx < num_apm_toggles - 1:
                     self.log.info('Turning on airplane mode now.')
@@ -651,13 +650,18 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
                 else:
                     asserts.fail('DUT did not connect to NR.')
 
+        #AWGN and fading are turned on after CELL ON and connect due to bug in UXM
+        for cell in testcase_params['endc_combo_config']['cell_list']:
+            if 'awgn_noise_level' in self.testclass_params:
+                self.keysight_test_app.enable_awgn_noise(cell['cell_type'], cell['cell_number'],
+                                                         1,
+                                                         self.testclass_params['awgn_noise_level'])
+
         if 'fading_scenario' in self.testclass_params and self.testclass_params[
                 'fading_scenario']['enable']:
             self.log.info('Enabling fading.')
             self.keysight_test_app.set_channel_emulator_state(
                 self.testclass_params['fading_scenario']['enable'])
-        else:
-            self.keysight_test_app.set_channel_emulator_state(0)
 
     def _test_throughput_bler(self, testcase_params):
         """Test function to run cellular throughput and BLER measurements.
@@ -688,6 +692,8 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
 
         # Setup tester and wait for DUT to connect
         self.setup_tester(testcase_params)
+        # Put DUT to sleep for power measurements
+        self.dut_utils.go_to_sleep()
 
         # Run throughput test loop
         stop_counter = 0
@@ -704,7 +710,7 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
             for cell in testcase_params['endc_combo_config']['cell_list']:
                 if not self.keysight_test_app.wait_for_cell_status(
                         cell['cell_type'], cell['cell_number'],
-                    ['ACT', 'CONN'], VERY_SHORT_SLEEP, VERY_SHORT_SLEEP):
+                    ['ACT', 'CONN'], LONG_SLEEP, VERY_SHORT_SLEEP):
                     connected = 0
             if not connected:
                 self.log.info('DUT lost connection to cells. Ending test.')
@@ -718,26 +724,27 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
                 cell_power_array.append(current_cell_power)
                 self.keysight_test_app.set_cell_dl_power(
                     cell['cell_type'], cell['cell_number'], current_cell_power,
-                    1)
+                    0)
             result['cell_power'] = cell_power_array
             # Start BLER and throughput measurements
             self.log.info('Cell powers: {}'.format(cell_power_array))
             self.start_single_throughput_measurement(testcase_params)
             if self.power_monitor:
                 measurement_wait = LONG_SLEEP if (power_idx == 0) else 0
-                current_average_current = self.collect_power_data(
+                average_power = self.collect_power_data(
                     self.testclass_params['traffic_duration'],
                     measurement_wait,
                     reconnect_usb=0,
                     measurement_tag=power_idx)
+                result['average_power'] = average_power
             current_throughput = self.stop_single_throughput_measurement(
                 testcase_params)
-            lte_rx_meas = self.dut_utils.get_rx_measurements('LTE')
-            nr_rx_meas = self.dut_utils.get_rx_measurements('NR5G')
             result['throughput_measurements'] = current_throughput
             self.print_throughput_result(current_throughput)
 
-            if self.testclass_params.get('log_rsrp_metrics', 1):
+            if self.testclass_params.get('log_rsrp_metrics', 1) and self.dut.is_connected():
+                lte_rx_meas = self.dut_utils.get_rx_measurements('LTE')
+                nr_rx_meas = self.dut_utils.get_rx_measurements('NR5G')
                 result['lte_rx_measurements'] = lte_rx_meas
                 result['nr_rx_measurements'] = nr_rx_meas
                 self.log.info('LTE Rx Measurements: {}'.format(lte_rx_meas))
@@ -759,9 +766,27 @@ class CellularThroughputBaseTest(base_test.BaseTestClass):
         # Save results
         self.testclass_results[self.current_test_name] = testcase_results
 
+    def dut_rockbottom(self):
+        """Set the dut to rockbottom state
+
+        """
+        # The rockbottom script might include a device reboot, so it is
+        # necessary to stop SL4A during its execution.
+        self.dut.stop_services()
+        self.log.info('Executing rockbottom script for ' + self.dut.model)
+        os.system('{} {}'.format('/root/rockbottom_km4.sh', self.dut.serial))
+        # Make sure the DUT is in root mode after coming back
+        self.dut.root_adb()
+        # Restart SL4A
+        self.dut.start_services()
+
     def test_measure_power(self):
+
+        self.dut_rockbottom()
         self.log.info('Turing screen off')
         self.dut_utils.set_screen_state(0)
+        self.dut_utils.toggle_airplane_mode(True, False)
+        self.dut_utils.go_to_sleep()
         time.sleep(10)
         self.log.info('Measuring power now.')
-        self.collect_power_data(60, 0)
+        self.collect_power_data(600, 10)
diff --git a/acts_tests/acts_contrib/test_utils/cellular/performance/cellular_performance_test_utils.py b/acts_tests/acts_contrib/test_utils/cellular/performance/cellular_performance_test_utils.py
index 89819f999..0c1dfd058 100644
--- a/acts_tests/acts_contrib/test_utils/cellular/performance/cellular_performance_test_utils.py
+++ b/acts_tests/acts_contrib/test_utils/cellular/performance/cellular_performance_test_utils.py
@@ -74,32 +74,11 @@ LONG_SLEEP = 10
 
 POWER_STATS_DUMPSYS_CMD = 'dumpsys android.hardware.power.stats.IPowerStats/default delta'
 
-
-class ObjNew(object):
-    """Create a random obj with unknown attributes and value.
-
-    """
-
-    def __init__(self, **kwargs):
-        self.__dict__.update(kwargs)
-
-    def __contains__(self, item):
-        """Function to check if one attribute is contained in the object.
-
-        Args:
-            item: the item to check
-        Return:
-            True/False
-        """
-        return hasattr(self, item)
-
-
 def extract_test_id(testcase_params, id_fields):
     test_id = collections.OrderedDict(
         (param, testcase_params[param]) for param in id_fields)
     return test_id
 
-
 def generate_endc_combo_config_from_string(endc_combo_str):
     """Function to generate ENDC combo config from combo string
 
@@ -124,7 +103,7 @@ def generate_endc_combo_config_from_string(endc_combo_str):
     cell_config_regex = re.compile(
         r'(?P<cell_type>[B,N])(?P<band>[0-9]+)(?P<bandwidth_class>[A-Z])\[bw=(?P<dl_bandwidth>[0-9]+)\]'
         r'(\[ch=)?(?P<channel>[0-9]+)?\]?'
-        r'\[ant=(?P<dl_mimo_config>[0-9]+),?(?P<transmission_mode>[TM0-9]+)?,?(?P<num_layers>[TM0-9]+)?,?(?P<num_codewords>[TM0-9]+)?\];?'
+        r'\[ant=(?P<dl_mimo_config>[0-9]+),?(?P<transmission_mode>[TM0-9]+)?,?(?P<num_layers>[0-9]+)?,?(?P<num_codewords>[0-9]+)?\]?;?'
         r'(?P<ul_bandwidth_class>[A-Z])?(\[ant=)?(?P<ul_mimo_config>[0-9])?(\])?'
     )
     for cell_string in endc_combo_list:
@@ -146,6 +125,9 @@ def generate_endc_combo_config_from_string(endc_combo_str):
             cell_config['dl_mimo_config'] = 'D{nss}U{nss}'.format(
                 nss=cell_config['dl_mimo_config'])
             cell_config['dl_subframe_allocation'] = [1] * 10
+            cell_config['tdd_frame_config'] = 5
+            cell_config['tdd_ssf_config']=8
+            cell_config['tdd_ssf_config'] = 8
             lte_dl_carriers.append(cell_config['cell_number'])
         else:
             # Configure NR specific parameters
@@ -194,6 +176,9 @@ def generate_endc_combo_config_from_csv_row(test_config):
     Returns:
         endc_combo_config: dictionary with all ENDC combo settings
     """
+    for key, value in test_config.items():
+        if value == '':
+            test_config[key] = None
     endc_combo_config = collections.OrderedDict()
     lte_cell_count = 0
     nr_cell_count = 0
@@ -206,32 +191,22 @@ def generate_endc_combo_config_from_csv_row(test_config):
     cell_config_list = []
     if 'lte_band' in test_config and test_config['lte_band']:
         lte_cell = {
-            'cell_type':
-            'LTE',
-            'cell_number':
-            1,
-            'pcc':
-            1,
-            'band':
-            test_config['lte_band'],
-            'dl_bandwidth':
-            test_config['lte_bandwidth'],
-            'ul_enabled':
-            1,
-            'duplex_mode':
-            test_config['lte_duplex_mode'],
-            'dl_mimo_config':
-            'D{nss}U{nss}'.format(nss=test_config['lte_dl_mimo_config']),
-            'ul_mimo_config':
-            'D{nss}U{nss}'.format(nss=test_config['lte_ul_mimo_config']),
-            'transmission_mode':
-            test_config['lte_tm_mode'],
-            'num_codewords':
-            test_config['lte_codewords'],
-            'num_layers':
-            test_config['lte_layers'],
+            'cell_type': 'LTE',
+            'cell_number': 1,
+            'pcc': 1,
+            'band': test_config['lte_band'],
+            'dl_bandwidth': test_config['lte_bandwidth'],
+            'ul_enabled': 1,
+            'duplex_mode': test_config['lte_duplex_mode'],
+            'dl_mimo_config': 'D{nss}U{nss}'.format(nss=test_config['lte_dl_mimo_config']),
+            'ul_mimo_config': 'D{nss}U{nss}'.format(nss=test_config['lte_ul_mimo_config']),
+            'transmission_mode': test_config['lte_tm_mode'],
+            'num_codewords': test_config['lte_codewords'],
+            'num_layers': test_config['lte_layers'],
             'dl_subframe_allocation':
-            test_config.get('dl_subframe_allocation', [1] * 10)
+                list(test_config['lte_dl_subframe_allocation']) if test_config['lte_dl_subframe_allocation'] else [1]*10,
+            'tdd_frame_config': test_config['lte_tdd_frame_config'],
+            'tdd_ssf_config': test_config['lte_tdd_ssf_config']
         }
         cell_config_list.append(lte_cell)
         endc_combo_config['lte_pcc'] = 1
@@ -297,6 +272,7 @@ class PixelDeviceUtils():
     def __init__(self, dut, log):
         self.dut = dut
         self.log = log
+        self.set_screen_timeout(15)
 
     def stop_services(self):
         """Gracefully stop sl4a before power measurement"""
@@ -638,6 +614,31 @@ class PixelDeviceUtils():
             return False
         return True
 
+    def set_screen_timeout(self, timeout=5):
+        self.dut.adb.shell('settings put system screen_off_timeout {}'.format(
+            timeout * 1000))
+    def get_screen_state(self):
+        screen_state_output = self.dut.adb.shell(
+            "dumpsys display | grep 'mScreenState'")
+        if 'ON' in screen_state_output:
+            return 1
+        else:
+            return 0
+
+    def set_screen_state(self, state):
+        curr_state = self.get_screen_state()
+        if state == curr_state:
+            self.log.debug('Screen state already {}'.format(state))
+        elif state == True:
+            self.dut.adb.shell('input keyevent KEYCODE_WAKEUP')
+        elif state == False:
+            self.dut.adb.shell('input keyevent KEYCODE_SLEEP')
+
+    def go_to_sleep(self):
+        if self.dut.skip_sl4a:
+            self.set_screen_state(0)
+        else:
+            self.dut.droid.goToSleepNow()
 
 class AndroidNonPixelDeviceUtils():
 
@@ -645,6 +646,9 @@ class AndroidNonPixelDeviceUtils():
         self.dut = dut
         self.log = log
         self.set_screen_timeout()
+        if getattr(dut, "stop_logcat", 0):
+            self.log.info('Stopping ADB logcat.')
+            dut.stop_adb_logcat()
 
     def start_services(self):
         self.log.debug('stop_services not supported on non_pixel devices')
@@ -705,6 +709,9 @@ class AndroidNonPixelDeviceUtils():
         elif state == False:
             self.dut.adb.shell('input keyevent KEYCODE_SLEEP')
 
+    def go_to_sleep(self):
+        self.set_screen_state(0)
+
     def set_screen_timeout(self, timeout=5):
         self.dut.adb.shell('settings put system screen_off_timeout {}'.format(
             timeout * 1000))
diff --git a/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/__init__.py b/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/__init__.py
index 8f34fc5ec..a6ef9069c 100644
--- a/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/__init__.py
+++ b/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/__init__.py
@@ -647,6 +647,20 @@ def empty_rssi_result():
     return collections.OrderedDict([('data', []), ('mean', float('nan')),
                                     ('stdev', float('nan'))])
 
+# Phone fold status
+def check_fold_status(dut):
+    fold_status = 'NA'
+    try:
+        fold_status_str = dut.adb.shell('sensor_test sample -s 65547.0 -n1',timeout=2)
+    except:
+        return fold_status
+    if 'Data: 1.000000' in fold_status_str:
+        fold_status = 'folded'
+    elif 'Data: 0.000000' in fold_status_str:
+        fold_status = 'unfolded'
+    else:
+        fold_status = 'NA'
+    return fold_status
 
 @nonblocking
 def get_connected_rssi_nb(dut,
diff --git a/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/bokeh_figure.py b/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/bokeh_figure.py
index 60b74d549..ee082b2ac 100644
--- a/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/bokeh_figure.py
+++ b/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/bokeh_figure.py
@@ -304,8 +304,7 @@ class BokehFigure():
                 bokeh.models.LinearAxis(
                     y_range_name='secondary',
                     axis_label=self.fig_property['secondary_y_label'],
-                    axis_label_text_font_size=self.
-                    fig_property['axis_label_size']), 'right')
+                    axis_label_text_font_size=self.fig_property['axis_label_size']), 'right')
         # plot formatting
         self.plot.legend.location = self.fig_property['legend_location']
         self.plot.legend.click_policy = 'hide'
diff --git a/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/brcm_utils.py b/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/brcm_utils.py
index ef703e9d6..d6c07d46a 100644
--- a/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/brcm_utils.py
+++ b/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/brcm_utils.py
@@ -443,6 +443,11 @@ class LinkLayerStats():
     TX_PER_REGEX = re.compile(
         r'(?P<mode>\S+) PER\s+:\s*(?P<nss1>[0-9, ,(,),%]*)'
         '\n\s*:?\s*(?P<nss2>[0-9, ,(,),%]*)')
+    TX_BW = re.compile(
+        r'TX BW[\s+]?:\s*(?P<tx_bw>[0-9, ,(,),%]*)')
+    RX_BW = re.compile(
+        r'RX BW\s+:\s*(?P<rx_bw>[0-9, ,(,),%]*)')
+    TXRX_BW_REGEX = re.compile(r'(?P<count>[0-9]+)\((?P<percent>[0-9]+)%\)')
     RX_GOOD_FCS_REGEX = re.compile(r'goodfcs (?P<rx_good_fcs>[0-9]*)')
     RX_BAD_FCS_REGEX = re.compile(r'rxbadfcs (?P<rx_bad_fcs>[0-9]*)')
     RX_AGG_REGEX = re.compile(r'rxmpduperampdu (?P<aggregation>[0-9]*)')
@@ -455,7 +460,8 @@ class LinkLayerStats():
     MCS_ID = collections.namedtuple(
         'mcs_id', ['mode', 'num_streams', 'bandwidth', 'mcs', 'gi'])
     MODE_MAP = {'0': '11a/g', '1': '11b', '2': '11n', '3': '11ac'}
-    BW_MAP = {'0': 20, '1': 40, '2': 80}
+    BW_MAP = {'0': 20, '1': 40, '2': 80, '3': 160}
+
 
     def __init__(self, dut, llstats_enabled=True):
         self.dut = dut
@@ -591,6 +597,75 @@ class LinkLayerStats():
 
         return mpdu_stats
 
+    def _parse_bw_stats(self, llstats_output):
+        tx_bw_match_iter = re.finditer(self.TX_BW, llstats_output)
+        rx_bw_match_iter = re.finditer(self.RX_BW, llstats_output)
+        bw_stats = {}
+        for rx_bw_match, tx_bw_match, in zip(rx_bw_match_iter, tx_bw_match_iter):
+            rx_bw_cnt_iter = re.finditer(self.TXRX_BW_REGEX, rx_bw_match.group('rx_bw'))
+            tx_bw_cnt_iter = re.finditer(self.TXRX_BW_REGEX, tx_bw_match.group('tx_bw'))
+            tx_phy_bw_weight_sum = 0
+            rx_phy_bw_weight_sum = 0
+            tx_bw_adjust_cnt = 0
+            rx_bw_adjust_cnt = 0
+            rx_common_bw = self.bandwidth
+            tx_common_bw = self.bandwidth
+            rx_common_bw_pct = 0
+            tx_common_bw_pct = 0
+            for bw_id, (rx_bw_stats, tx_bw_stats) in enumerate(
+                              itertools.zip_longest(rx_bw_cnt_iter, tx_bw_cnt_iter)):
+                current_bw = self.BW_MAP[str(bw_id)]
+                current_bw_stats = collections.OrderedDict(
+                    txbwcnt = int(tx_bw_stats.group('count'))
+                    if tx_bw_stats else 0,
+                    txbwpct = int(tx_bw_stats.group('percent'))
+                    if tx_bw_stats else 0,
+                    rxbwcnt = int(rx_bw_stats.group('count'))
+                    if rx_bw_stats else 0,
+                    rxbwpct = int(rx_bw_stats.group('percent'))
+                    if rx_bw_stats else 0,
+                    bw=current_bw)
+                if current_bw_stats['rxbwpct'] > rx_common_bw_pct:
+                    rx_common_bw_pct = current_bw_stats['rxbwpct']
+                    rx_common_bw = current_bw
+                if current_bw_stats['txbwpct'] > tx_common_bw_pct:
+                    tx_common_bw_pct = current_bw_stats['txbwpct']
+                    tx_common_bw = current_bw
+                bw_stats[current_bw] = current_bw_stats
+                if int(current_bw) != int(self.bandwidth) and current_bw_stats['txbwpct'] > 0:
+                    tx_bw_adjust_cnt = tx_bw_adjust_cnt + 1
+                if int(current_bw) != int(self.bandwidth) and current_bw_stats['rxbwpct'] > 0:
+                    rx_bw_adjust_cnt = rx_bw_adjust_cnt + 1
+                if float(current_bw) <= float(self.bandwidth):
+                    tx_phy_bw_weight_sum = tx_phy_bw_weight_sum + (float(current_bw)/float(self.bandwidth)) * (float(current_bw_stats['txbwpct'])/float(100))
+                    rx_phy_bw_weight_sum = rx_phy_bw_weight_sum + (float(current_bw)/float(self.bandwidth)) * (float(current_bw_stats['rxbwpct'])/float(100))
+            if tx_phy_bw_weight_sum != 0:
+                bw_stats['tx_phy_bw_weight'] = float(tx_phy_bw_weight_sum)
+            else:
+                bw_stats['tx_phy_bw_weight'] = 1
+            if rx_phy_bw_weight_sum != 0:
+                bw_stats['rx_phy_bw_weight'] = float(rx_phy_bw_weight_sum)
+            else:
+                bw_stats['rx_phy_bw_weight'] = 1
+            if tx_bw_adjust_cnt > 0:
+                bw_stats['tx_bw_adjusted_flag'] = True
+                bw_stats['tx_common_bw'] = tx_common_bw
+                bw_stats['tx_common_bw_pct'] = tx_common_bw_pct
+            else:
+                bw_stats['tx_bw_adjusted_flag'] = False
+                bw_stats['tx_common_bw'] = self.bandwidth
+                bw_stats['tx_common_bw_pct'] = 100
+            if rx_bw_adjust_cnt > 0:
+                bw_stats['rx_bw_adjusted_flag'] = True
+                bw_stats['rx_common_bw'] = rx_common_bw
+                bw_stats['rx_common_bw_pct'] = rx_common_bw_pct
+            else:
+                bw_stats['rx_bw_adjusted_flag'] = False
+                bw_stats['rx_common_bw'] = self.bandwidth
+                bw_stats['rx_common_bw_pct'] = 100
+        return bw_stats
+
+
     def _generate_stats_summary(self, llstats_dict):
         llstats_summary = collections.OrderedDict(common_tx_mcs=None,
                                                   common_tx_mcs_count=0,
@@ -598,6 +673,10 @@ class LinkLayerStats():
                                                   common_rx_mcs=None,
                                                   common_rx_mcs_count=0,
                                                   common_rx_mcs_freq=0,
+                                                  common_rx_bw = None,
+                                                  common_rx_bw_pct = 0,
+                                                  common_tx_bw = None,
+                                                  common_tx_bw_pct = 0,
                                                   rx_per=float('nan'))
         mcs_ids = []
         tx_mpdu = []
@@ -616,17 +695,21 @@ class LinkLayerStats():
         llstats_summary['common_tx_mcs_count'] = numpy.max(tx_mpdu)
         llstats_summary['common_rx_mcs'] = mcs_ids[numpy.argmax(rx_mpdu)]
         llstats_summary['common_rx_mcs_count'] = numpy.max(rx_mpdu)
+        llstats_summary['common_rx_bw'] = llstats_dict['bw_stats']['rx_common_bw']
+        llstats_summary['common_rx_bw_pct'] = llstats_dict['bw_stats']['rx_common_bw_pct']
+        llstats_summary['common_tx_bw'] = llstats_dict['bw_stats']['tx_common_bw']
+        llstats_summary['common_tx_bw_pct'] = llstats_dict['bw_stats']['tx_common_bw_pct']
         if sum(tx_mpdu):
-            llstats_summary['mean_tx_phy_rate'] = numpy.average(
-                phy_rates, weights=tx_mpdu)
+            llstats_summary['mean_tx_phy_rate'] = numpy.multiply(numpy.average(
+                phy_rates, weights=tx_mpdu), llstats_dict['bw_stats']['tx_phy_bw_weight'])
             llstats_summary['common_tx_mcs_freq'] = (
                 llstats_summary['common_tx_mcs_count'] / sum(tx_mpdu))
         else:
             llstats_summary['mean_tx_phy_rate'] = 0
             llstats_summary['common_tx_mcs_freq'] = 0
         if sum(rx_mpdu):
-            llstats_summary['mean_rx_phy_rate'] = numpy.average(
-                phy_rates, weights=rx_mpdu)
+            llstats_summary['mean_rx_phy_rate'] = numpy.multiply(numpy.average(
+                phy_rates, weights=rx_mpdu), llstats_dict['bw_stats']['rx_phy_bw_weight'])
             llstats_summary['common_rx_mcs_freq'] = (
                 llstats_summary['common_rx_mcs_count'] / sum(rx_mpdu))
             total_rx_frames = llstats_dict['mpdu_stats'][
@@ -648,9 +731,11 @@ class LinkLayerStats():
         self.llstats_incremental['phy_log_output'] = phy_log_output
         self.llstats_incremental['mcs_stats'] = self._parse_mcs_stats(
             llstats_output)
+        self.llstats_incremental['bw_stats'] = self._parse_bw_stats(
+            llstats_output)
         self.llstats_incremental['mpdu_stats'] = self._parse_mpdu_stats(
             llstats_output)
         self.llstats_incremental['summary'] = self._generate_stats_summary(
             self.llstats_incremental)
         self.llstats_cumulative['summary'] = self._generate_stats_summary(
-            self.llstats_cumulative)
+            self.llstats_cumulative)
\ No newline at end of file
diff --git a/acts_tests/acts_contrib/test_utils/wifi/wifi_test_utils.py b/acts_tests/acts_contrib/test_utils/wifi/wifi_test_utils.py
index 5af197101..79ded25b3 100755
--- a/acts_tests/acts_contrib/test_utils/wifi/wifi_test_utils.py
+++ b/acts_tests/acts_contrib/test_utils/wifi/wifi_test_utils.py
@@ -24,7 +24,6 @@ import subprocess
 import time
 
 from retry import retry
-from typing import Optional, Union
 
 from collections import namedtuple
 from enum import IntEnum
@@ -35,6 +34,8 @@ from acts import context
 from acts import signals
 from acts import utils
 from acts.controllers import attenuator
+from acts.controllers.adb_lib.error import AdbCommandError
+from acts.controllers.android_device import AndroidDevice
 from acts.controllers.ap_lib import hostapd_security
 from acts.controllers.ap_lib import hostapd_ap_preset
 from acts.controllers.ap_lib.hostapd_constants import BAND_2G
@@ -3041,20 +3042,17 @@ def kill_iperf3_server_by_port(port: str):
     except subprocess.CalledProcessError:
         logging.info("Error executing shell command with subprocess.")
 
-def get_host_public_ipv4_address() -> Optional[str]:
-  """Retrieves the host's public IPv4 address using the ifconfig command.
+def get_host_iperf_ipv4_address(dut: AndroidDevice) -> str | None:
+  """Gets the host's iPerf IPv4 address.
 
-  This function tries to extract the host's public IPv4 address by parsing
-  the output of the ifconfig command. It will filter out private IP addresses
-  (e.g., 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16).
+  This function tries to get the host's iPerf IPv4 address by finding the first
+  IPv4 address for iperf server that can be pinged.
 
-  Returns:
-    str: The public IPv4 address, if found.
-    None: If no public IPv4 address is found or in case of errors.
+  Args:
+    dut: The Android device.
 
-  Raises:
-    May print errors related to executing ifconfig or parsing the IPs, but
-    exceptions are handled and won't be raised beyond the function.
+  Returns:
+    The host's iPerf IPv4 address, if found; None, otherwise.
   """
   try:
     # Run ifconfig command and get its output
@@ -3079,13 +3077,24 @@ def get_host_public_ipv4_address() -> Optional[str]:
   for ip_str in matches:
     try:
       ip = ipaddress.ip_address(ip_str)
-      if not ip.is_private:
-        return ip_str
     except ValueError:
-      logging.info("Invalid IP address format: %s", ip_str)
+      logging.warning("Invalid IP address: %s", str(ip))
+      continue
+    if ip.is_loopback:
+      logging.info("Skip loopback IP address: %s", str(ip))
+      continue
+    try:
+      ping_result = dut.adb.shell("ping -c 6 {}".format(str(ip)))
+      dut.log.info("Host IP ping result: %s" % ping_result)
+      if "100% packet loss" in ping_result:
+        logging.warning("Ping host IP %s results: %s", str(ip), ping_result)
+        continue
+      return ip_str
+    except AdbCommandError as e:
+      logging.warning("Failed to ping host IP %s: %s", str(ip), e)
       continue
 
-  # Return None if no public IP is found
+  # Return None if no suitable host iPerf server IP found
   return None
 
 def get_iperf_server_port():
diff --git a/acts_tests/tests/google/cellular/performance/CellularFr1RvRTest.py b/acts_tests/tests/google/cellular/performance/CellularFr1RvRTest.py
index 605580d87..8b7fa2e81 100644
--- a/acts_tests/tests/google/cellular/performance/CellularFr1RvRTest.py
+++ b/acts_tests/tests/google/cellular/performance/CellularFr1RvRTest.py
@@ -44,12 +44,16 @@ class CellularFr1RvrTest(CellularThroughputBaseTest):
         self.testclass_params = self.user_params['nr_rvr_test_params']
         self.tests = self.generate_test_cases(
             channel_list=['LOW', 'MID', 'HIGH'],
+            schedule_scenario='FULL_TPUT',
+            schedule_slot_ratio = 80,
             nr_ul_mcs=4,
             lte_dl_mcs_table='QAM256',
             lte_dl_mcs=4,
             lte_ul_mcs_table='QAM256',
             lte_ul_mcs=4,
-            transform_precoding=0)
+            transform_precoding=0,
+            nr_dl_mcs_table='Q256',
+            nr_ul_mcs_table='Q64')
 
     def process_testclass_results(self):
         pass
@@ -68,6 +72,7 @@ class CellularFr1RvrTest(CellularThroughputBaseTest):
 
         average_throughput_list = []
         theoretical_throughput_list = []
+        average_power_list = []
         nr_cell_index = testcase_data['testcase_params']['endc_combo_config']['lte_cell_count']
         cell_power_list = testcase_data['testcase_params']['cell_power_sweep'][nr_cell_index]
         for result in testcase_data['results']:
@@ -75,19 +80,25 @@ class CellularFr1RvrTest(CellularThroughputBaseTest):
                 result['throughput_measurements']['nr_tput_result']['total']['DL']['average_tput'])
             theoretical_throughput_list.append(
                 result['throughput_measurements']['nr_tput_result']['total']['DL']['theoretical_tput'])
+            if self.power_monitor:
+                average_power_list.append(result['average_power'])
         padding_len = len(cell_power_list) - len(average_throughput_list)
         average_throughput_list.extend([0] * padding_len)
         theoretical_throughput_list.extend([0] * padding_len)
+        if self.power_monitor:
+            average_power_list.extend([0] * padding_len)
 
         testcase_data['average_throughput_list'] = average_throughput_list
         testcase_data[
             'theoretical_throughput_list'] = theoretical_throughput_list
+        testcase_data['average_power_list'] = average_power_list
         testcase_data['cell_power_list'] = cell_power_list
 
         plot = BokehFigure(
             title='Band {} - RvR'.format(testcase_data['testcase_params']['endc_combo_config']['cell_list'][nr_cell_index]['band']),
-            x_label='Cell Power (dBm)',
-            primary_y_label='PHY Rate (Mbps)')
+            x_label='Cell Power (dBm/SCS)',
+            primary_y_label='PHY Rate (Mbps)',
+            secondary_y_label='Power Consumption (mW)')
 
         plot.add_line(
             testcase_data['cell_power_list'],
@@ -100,7 +111,16 @@ class CellularFr1RvrTest(CellularThroughputBaseTest):
             'Average Throughput',
             width=1,
             style='dashed')
+        if self.power_monitor:
+            plot.add_line(
+                testcase_data['cell_power_list'],
+                testcase_data['average_power_list'],
+                'Power Consumption (mW)',
+                width=1,
+                style='dashdot',
+                y_axis='secondary')
         plot.generate_figure()
+        self.log.info(self.log_path)
         output_file_path = os.path.join(self.log_path, '{}.html'.format(self.current_test_name))
         BokehFigure.save_figure(plot, output_file_path)
 
diff --git a/acts_tests/tests/google/cellular/performance/CellularFr1SensitivityTest.py b/acts_tests/tests/google/cellular/performance/CellularFr1SensitivityTest.py
index 3057cfbf9..49bf794c1 100644
--- a/acts_tests/tests/google/cellular/performance/CellularFr1SensitivityTest.py
+++ b/acts_tests/tests/google/cellular/performance/CellularFr1SensitivityTest.py
@@ -52,7 +52,9 @@ class CellularFr1SensitivityTest(CellularThroughputBaseTest):
             lte_ul_mcs=4,
             transform_precoding=0,
             schedule_scenario='FULL_TPUT',
-            schedule_slot_ratio=80
+            schedule_slot_ratio=80,
+            nr_dl_mcs_table='Q256',
+            nr_ul_mcs_table='Q64'
         )
 
     def process_testclass_results(self):
@@ -72,21 +74,25 @@ class CellularFr1SensitivityTest(CellularThroughputBaseTest):
                     'average_throughput': [],
                     'theoretical_throughput': [],
                     'cell_power': [],
+                    'average_power': []
                 }
                 plots[test_id] = BokehFigure(
                     title='Band {} - BLER Curves'.format(cell_config['band']),
-                    x_label='Cell Power (dBm)',
+                    x_label='Cell Power (dBm/SCS)',
                     primary_y_label='BLER (Mbps)')
                 test_id_rvr = test_id + tuple('RvR')
                 plots[test_id_rvr] = BokehFigure(
                     title='Band {} - RvR'.format(cell_config['band']),
-                    x_label='Cell Power (dBm)',
-                    primary_y_label='PHY Rate (Mbps)')
+                    x_label='Cell Power (dBm/SCS)',
+                    primary_y_label='PHY Rate (Mbps)',
+                    secondary_y_label='Power Consumption (mW)')
             # Compile test id data and metrics
             compiled_data[test_id]['average_throughput'].append(
                 testcase_data['average_throughput_list'])
             compiled_data[test_id]['cell_power'].append(
                 testcase_data['cell_power_list'])
+            compiled_data[test_id]['average_power'].append(
+                testcase_data['average_power_list'])
             compiled_data[test_id]['mcs'].append(
                 testcase_data['testcase_params']['nr_dl_mcs'])
             # Add test id to plots
@@ -101,6 +107,16 @@ class CellularFr1SensitivityTest(CellularThroughputBaseTest):
                 'MCS {}'.format(testcase_data['testcase_params']['nr_dl_mcs']),
                 width=1,
                 style='dashed')
+            if self.power_monitor:
+                plots[test_id_rvr].add_line(
+                    testcase_data['cell_power_list'],
+                    testcase_data['average_power_list'],
+                    'MCS {} - Power'.format(
+                        testcase_data['testcase_params']['nr_dl_mcs']),
+                    width=1,
+                    style='dashdot',
+                    y_axis='secondary')
+
 
         for test_id, test_data in compiled_data.items():
             test_id_rvr = test_id + tuple('RvR')
@@ -153,6 +169,7 @@ class CellularFr1SensitivityTest(CellularThroughputBaseTest):
         theoretical_throughput_list = []
         nr_cell_index = testcase_data['testcase_params']['endc_combo_config'][
             'lte_cell_count']
+        average_power_list = []
         cell_power_list = testcase_data['testcase_params']['cell_power_sweep'][
             nr_cell_index]
         for result in testcase_data['results']:
@@ -164,9 +181,13 @@ class CellularFr1SensitivityTest(CellularThroughputBaseTest):
             theoretical_throughput_list.append(
                 result['throughput_measurements']['nr_tput_result']['total']
                 ['DL']['theoretical_tput'])
+            if self.power_monitor:
+                average_power_list.append(result['average_power'])
         padding_len = len(cell_power_list) - len(average_throughput_list)
         average_throughput_list.extend([0] * padding_len)
         theoretical_throughput_list.extend([0] * padding_len)
+        if self.power_monitor:
+            average_power_list.extend([0] * padding_len)
 
         bler_above_threshold = [
             bler > self.testclass_params['bler_threshold']
@@ -189,6 +210,7 @@ class CellularFr1SensitivityTest(CellularThroughputBaseTest):
         testcase_data[
             'theoretical_throughput_list'] = theoretical_throughput_list
         testcase_data['cell_power_list'] = cell_power_list
+        testcase_data['average_power_list'] = average_power_list
         testcase_data['sensitivity'] = sensitivity
 
         results_file_path = os.path.join(
@@ -278,5 +300,7 @@ class CellularFr1Sensitivity_SampleMCS_Test(CellularFr1SensitivityTest):
             lte_ul_mcs=4,
             transform_precoding=0,
             schedule_scenario='FULL_TPUT',
-            schedule_slot_ratio=80
+            schedule_slot_ratio=80,
+            nr_dl_mcs_table='Q256',
+            nr_ul_mcs_table='Q64'
         )
\ No newline at end of file
diff --git a/acts_tests/tests/google/cellular/performance/CellularFr2PeakThroughputTest.py b/acts_tests/tests/google/cellular/performance/CellularFr2PeakThroughputTest.py
index 548452b48..338f26607 100644
--- a/acts_tests/tests/google/cellular/performance/CellularFr2PeakThroughputTest.py
+++ b/acts_tests/tests/google/cellular/performance/CellularFr2PeakThroughputTest.py
@@ -414,7 +414,9 @@ class CellularFr2DlPeakThroughputTest(CellularFr2PeakThroughputTest):
                                               lte_dl_mcs=4,
                                               lte_dl_mcs_table='QAM64',
                                               lte_ul_mcs=4,
-                                              lte_ul_mcs_table='QAM64')
+                                              lte_ul_mcs_table='QAM64',
+                                              nr_dl_mcs_table='Q256',
+                                              nr_ul_mcs_table='Q64')
 
 
 class CellularFr2CpOfdmUlPeakThroughputTest(CellularFr2PeakThroughputTest):
@@ -437,7 +439,9 @@ class CellularFr2CpOfdmUlPeakThroughputTest(CellularFr2PeakThroughputTest):
                                               lte_dl_mcs=4,
                                               lte_dl_mcs_table='QAM64',
                                               lte_ul_mcs=4,
-                                              lte_ul_mcs_table='QAM64')
+                                              lte_ul_mcs_table='QAM64',
+                                              nr_dl_mcs_table='Q256',
+                                              nr_ul_mcs_table='Q64')
 
         self.tests.extend(
             self.generate_test_cases(['N257', 'N258', 'N260', 'N261'],
@@ -455,7 +459,9 @@ class CellularFr2CpOfdmUlPeakThroughputTest(CellularFr2PeakThroughputTest):
                                      lte_dl_mcs=4,
                                      lte_dl_mcs_table='QAM64',
                                      lte_ul_mcs=4,
-                                     lte_ul_mcs_table='QAM64'))
+                                     lte_ul_mcs_table='QAM64',
+                                     nr_dl_mcs_table='Q256',
+                                     nr_ul_mcs_table='Q64'))
         self.tests.extend(
             self.generate_test_cases(['N257', 'N258', 'N260', 'N261'],
                                      ['low', 'mid', 'high'], [(4, 16), (4, 25),
@@ -472,7 +478,9 @@ class CellularFr2CpOfdmUlPeakThroughputTest(CellularFr2PeakThroughputTest):
                                      lte_dl_mcs=4,
                                      lte_dl_mcs_table='QAM64',
                                      lte_ul_mcs=4,
-                                     lte_ul_mcs_table='QAM64'))
+                                     lte_ul_mcs_table='QAM64',
+                                     nr_dl_mcs_table='Q256',
+                                     nr_ul_mcs_table='Q64'))
 
 
 class CellularFr2DftsOfdmUlPeakThroughputTest(CellularFr2PeakThroughputTest):
@@ -495,7 +503,9 @@ class CellularFr2DftsOfdmUlPeakThroughputTest(CellularFr2PeakThroughputTest):
                                               lte_dl_mcs=4,
                                               lte_dl_mcs_table='QAM64',
                                               lte_ul_mcs=4,
-                                              lte_ul_mcs_table='QAM64')
+                                              lte_ul_mcs_table='QAM64',
+                                              nr_dl_mcs_table='Q256',
+                                              nr_ul_mcs_table='Q64')
 
         self.tests.extend(
             self.generate_test_cases(['N257', 'N258', 'N260', 'N261'],
@@ -513,7 +523,9 @@ class CellularFr2DftsOfdmUlPeakThroughputTest(CellularFr2PeakThroughputTest):
                                      lte_dl_mcs=4,
                                      lte_dl_mcs_table='QAM64',
                                      lte_ul_mcs=4,
-                                     lte_ul_mcs_table='QAM64'))
+                                     lte_ul_mcs_table='QAM64',
+                                     nr_dl_mcs_table='Q256',
+                                     nr_ul_mcs_table='Q64'))
         self.tests.extend(
             self.generate_test_cases(['N257', 'N258', 'N260', 'N261'],
                                      ['low', 'mid', 'high'], [(4, 16), (4, 25),
@@ -530,7 +542,9 @@ class CellularFr2DftsOfdmUlPeakThroughputTest(CellularFr2PeakThroughputTest):
                                      lte_dl_mcs=4,
                                      lte_dl_mcs_table='QAM64',
                                      lte_ul_mcs=4,
-                                     lte_ul_mcs_table='QAM64'))
+                                     lte_ul_mcs_table='QAM64',
+                                     nr_dl_mcs_table='Q256',
+                                     nr_ul_mcs_table='Q64'))
 
 
 class CellularFr2DlFrequencySweepPeakThroughputTest(
@@ -559,7 +573,9 @@ class CellularFr2DlFrequencySweepPeakThroughputTest(
             lte_dl_mcs=4,
             lte_dl_mcs_table='QAM64',
             lte_ul_mcs=4,
-            lte_ul_mcs_table='QAM64')
+            lte_ul_mcs_table='QAM64',
+            nr_dl_mcs_table='Q256',
+            nr_ul_mcs_table='Q64')
 
     def generate_test_cases(self, bands, channels, nr_mcs_pair_list,
                             num_dl_cells_list, num_ul_cells_list,
diff --git a/acts_tests/tests/google/cellular/performance/CellularFr2SensitivityTest.py b/acts_tests/tests/google/cellular/performance/CellularFr2SensitivityTest.py
index bf5fafb96..6362185a3 100644
--- a/acts_tests/tests/google/cellular/performance/CellularFr2SensitivityTest.py
+++ b/acts_tests/tests/google/cellular/performance/CellularFr2SensitivityTest.py
@@ -58,7 +58,9 @@ class CellularFr2SensitivityTest(CellularThroughputBaseTest):
             schedule_scenario="FULL_TPUT",
             schedule_slot_ratio=80,
             force_contiguous_nr_channel=True,
-            transform_precoding=0)
+            transform_precoding=0,
+            nr_dl_mcs_table='Q256',
+            nr_ul_mcs_table='Q64')
 
     def process_testclass_results(self):
         # Plot individual test id results raw data and compile metrics
diff --git a/acts_tests/tests/google/cellular/performance/CellularFr2UplinkPowerSweepTest.py b/acts_tests/tests/google/cellular/performance/CellularFr2UplinkPowerSweepTest.py
index ce56a6c19..9e7d53566 100644
--- a/acts_tests/tests/google/cellular/performance/CellularFr2UplinkPowerSweepTest.py
+++ b/acts_tests/tests/google/cellular/performance/CellularFr2UplinkPowerSweepTest.py
@@ -316,7 +316,9 @@ class CellularFr2CpOfdmUplinkPowerSweepTest(CellularFr2UplinkPowerSweepTest):
                                               lte_dl_mcs=4,
                                               lte_dl_mcs_table='QAM64',
                                               lte_ul_mcs=4,
-                                              lte_ul_mcs_table='QAM64')
+                                              lte_ul_mcs_table='QAM64',
+                                              nr_dl_mcs_table='Q256',
+                                              nr_ul_mcs_table='Q64')
 
         self.tests.extend(
             self.generate_test_cases(['N257', 'N258', 'N260', 'N261'],
@@ -334,7 +336,9 @@ class CellularFr2CpOfdmUplinkPowerSweepTest(CellularFr2UplinkPowerSweepTest):
                                      lte_dl_mcs=4,
                                      lte_dl_mcs_table='QAM64',
                                      lte_ul_mcs=4,
-                                     lte_ul_mcs_table='QAM64'))
+                                     lte_ul_mcs_table='QAM64',
+                                      nr_dl_mcs_table='Q256',
+                                      nr_ul_mcs_table='Q64'))
         self.tests.extend(
             self.generate_test_cases(['N257', 'N258', 'N260', 'N261'],
                                      ['low', 'mid', 'high'], [(4, 16), (4, 25),
@@ -351,7 +355,9 @@ class CellularFr2CpOfdmUplinkPowerSweepTest(CellularFr2UplinkPowerSweepTest):
                                      lte_dl_mcs=4,
                                      lte_dl_mcs_table='QAM64',
                                      lte_ul_mcs=4,
-                                     lte_ul_mcs_table='QAM64'))
+                                     lte_ul_mcs_table='QAM64',
+                                      nr_dl_mcs_table='Q256',
+                                      nr_ul_mcs_table='Q64'))
 
 
 class CellularFr2DftsOfdmUplinkPowerSweepTest(CellularFr2UplinkPowerSweepTest):
@@ -375,7 +381,9 @@ class CellularFr2DftsOfdmUplinkPowerSweepTest(CellularFr2UplinkPowerSweepTest):
                                               lte_dl_mcs=4,
                                               lte_dl_mcs_table='QAM64',
                                               lte_ul_mcs=4,
-                                              lte_ul_mcs_table='QAM64')
+                                              lte_ul_mcs_table='QAM64',
+                                              nr_dl_mcs_table='Q256',
+                                              nr_ul_mcs_table='Q64')
 
         self.tests.extend(
             self.generate_test_cases(['N257', 'N258', 'N260', 'N261'],
@@ -393,7 +401,9 @@ class CellularFr2DftsOfdmUplinkPowerSweepTest(CellularFr2UplinkPowerSweepTest):
                                      lte_dl_mcs=4,
                                      lte_dl_mcs_table='QAM64',
                                      lte_ul_mcs=4,
-                                     lte_ul_mcs_table='QAM64'))
+                                     lte_ul_mcs_table='QAM64',
+                                      nr_dl_mcs_table='Q256',
+                                      nr_ul_mcs_table='Q64'))
         self.tests.extend(
             self.generate_test_cases(['N257', 'N258', 'N260', 'N261'],
                                      ['low', 'mid', 'high'], [(4, 16), (4, 25),
@@ -410,4 +420,6 @@ class CellularFr2DftsOfdmUplinkPowerSweepTest(CellularFr2UplinkPowerSweepTest):
                                      lte_dl_mcs=4,
                                      lte_dl_mcs_table='QAM64',
                                      lte_ul_mcs=4,
-                                     lte_ul_mcs_table='QAM64'))
+                                     lte_ul_mcs_table='QAM64',
+                                      nr_dl_mcs_table='Q256',
+                                      nr_ul_mcs_table='Q64'))
diff --git a/acts_tests/tests/google/cellular/performance/CellularLteFr1EndcRvrTest.py b/acts_tests/tests/google/cellular/performance/CellularLteFr1EndcRvrTest.py
new file mode 100644
index 000000000..24ee42b07
--- /dev/null
+++ b/acts_tests/tests/google/cellular/performance/CellularLteFr1EndcRvrTest.py
@@ -0,0 +1,182 @@
+#!/usr/bin/env python3.4
+#
+#   Copyright 2022 - The Android Open Source Project
+#
+#   Licensed under the Apache License, Version 2.0 (the 'License');
+#   you may not use this file except in compliance with the License.
+#   You may obtain a copy of the License at
+#
+#       http://www.apache.org/licenses/LICENSE-2.0
+#
+#   Unless required by applicable law or agreed to in writing, software
+#   distributed under the License is distributed on an 'AS IS' BASIS,
+#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+#   See the License for the specific language governing permissions and
+#   limitations under the License.
+
+import collections
+import csv
+import itertools
+import numpy
+import json
+import re
+import os
+from acts import context
+from acts import base_test
+from acts.metrics.loggers.blackbox import BlackboxMappedMetricLogger
+from acts_contrib.test_utils.cellular.performance import cellular_performance_test_utils as cputils
+from acts_contrib.test_utils.cellular.performance.CellularThroughputBaseTest import CellularThroughputBaseTest
+from acts_contrib.test_utils.wifi import wifi_performance_test_utils as wputils
+from acts_contrib.test_utils.wifi.wifi_performance_test_utils.bokeh_figure import BokehFigure
+from functools import partial
+
+
+class CellularLteFr1EndcRvrTest(CellularThroughputBaseTest):
+    """Class to test ENDC sensitivity"""
+
+    def __init__(self, controllers):
+        base_test.BaseTestClass.__init__(self, controllers)
+        self.testcase_metric_logger = (
+            BlackboxMappedMetricLogger.for_test_case())
+        self.testclass_metric_logger = (
+            BlackboxMappedMetricLogger.for_test_class())
+        self.publish_testcase_metrics = True
+        self.testclass_params = self.user_params['endc_rvr_test_params']
+        self.tests = self.generate_test_cases(lte_dl_mcs_table='QAM256',
+                                              lte_ul_mcs_table='QAM256',
+                                              lte_ul_mcs=4,
+                                              nr_ul_mcs=4,
+                                              transform_precoding=0,
+                                              schedule_scenario='FULL_TPUT',
+                                              schedule_slot_ratio=80,
+                                              nr_dl_mcs_table='Q256',
+                                              nr_ul_mcs_table='Q64')
+
+    def process_testclass_results(self):
+        pass
+
+    def process_testcase_results(self):
+        if self.current_test_name not in self.testclass_results:
+            return
+        testcase_data = self.testclass_results[self.current_test_name]
+
+        average_power_list = []
+        cell_throughput_lists = {}
+        for current_cell_idx, current_cell in enumerate(testcase_data['testcase_params']['endc_combo_config']['cell_list']):
+            cell_throughput_lists[current_cell_idx]=[]
+
+        for result in testcase_data['results']:
+            for current_cell_idx, current_cell in enumerate(testcase_data['testcase_params']['endc_combo_config']['cell_list']):
+                if current_cell['cell_type'] == 'LTE':
+                    cell_throughput_lists[current_cell_idx].append(
+                        result['throughput_measurements']['lte_tput_result'][current_cell['cell_number']]
+                        ['DL']['average_tput'])
+                else:
+                    cell_throughput_lists[current_cell_idx].append(
+                        result['throughput_measurements']['nr_tput_result'][current_cell['cell_number']]
+                        ['DL']['average_tput'])
+            if self.power_monitor:
+                average_power_list.append(result['average_power'])
+
+        plot = BokehFigure(
+            title='ENDC RvR',
+            x_label='Cell Power (dBm/SCS)',
+            primary_y_label='PHY Rate (Mbps)',
+            secondary_y_label='Power Consumption (mW)')
+
+        for cell_idx, cell_throughput_list in cell_throughput_lists.items():
+            plot.add_line(
+                testcase_data['testcase_params']['cell_power_sweep'][cell_idx],
+                cell_throughput_lists[cell_idx],
+                'Cell {} - Average Throughput'.format(cell_idx),
+                width=1)
+
+        if self.power_monitor:
+            plot.add_line(
+                testcase_data['testcase_params']['cell_power_sweep'][0],
+                average_power_list,
+                'Power Consumption (mW)',
+                width=1,
+                style='dashdot',
+                y_axis='secondary')
+
+        plot.generate_figure()
+        output_file_path = os.path.join(self.log_path, '{}.html'.format(self.current_test_name))
+        BokehFigure.save_figure(plot, output_file_path)
+
+        results_file_path = os.path.join(
+            context.get_current_context().get_full_output_path(),
+            '{}.json'.format(self.current_test_name))
+        with open(results_file_path, 'w') as results_file:
+            json.dump(wputils.serialize_dict(testcase_data),
+                      results_file,
+                      indent=4)
+
+    def get_per_cell_power_sweeps(self, testcase_params):
+        cell_power_sweeps = []
+        # Construct test cell sweep
+        lte_sweep = list(
+            numpy.arange(self.testclass_params['lte_cell_power_start'],
+                         self.testclass_params['lte_cell_power_stop'],
+                         self.testclass_params['lte_cell_power_step']))
+        nr_sweep = list(
+            numpy.arange(self.testclass_params['nr_cell_power_start'],
+                         self.testclass_params['nr_cell_power_stop'],
+                         self.testclass_params['nr_cell_power_step']))
+        if len(lte_sweep) > len(nr_sweep):
+            nr_sweep_pad = len(lte_sweep) - len(nr_sweep)
+            nr_sweep.extend([nr_sweep[-1]]*nr_sweep_pad)
+        elif len(lte_sweep) < len(nr_sweep):
+            lte_sweep_pad = len(nr_sweep) - len(lte_sweep)
+            lte_sweep.extend([lte_sweep[-1]]*lte_sweep_pad)
+
+
+        for cell_idx, cell_config in enumerate(testcase_params['endc_combo_config']['cell_list']):
+            if testcase_params['test_cell_idx'] in [cell_idx, 'all']:
+                if cell_config['cell_type'] == 'LTE':
+                    cell_power_sweeps.append(lte_sweep)
+                elif cell_config['cell_type'] == 'NR5G':
+                    cell_power_sweeps.append(nr_sweep)
+            elif cell_config['cell_type'] == 'LTE':
+                cell_power_sweeps.append([self.testclass_params['lte_cell_power_start']
+                             ] * len(nr_sweep))
+            elif cell_config['cell_type'] == 'NR5G':
+                cell_power_sweeps.append([self.testclass_params['nr_cell_power_start']
+                             ] * len(lte_sweep))
+        return cell_power_sweeps
+
+    def generate_test_cases(self, lte_dl_mcs_table,
+                            lte_ul_mcs_table, lte_ul_mcs,
+                            nr_ul_mcs, **kwargs):
+        test_cases = []
+        with open(self.testclass_params['endc_combo_file'],
+                  'r') as endc_combos:
+            for endc_combo_str in endc_combos:
+                if endc_combo_str[0] == '#':
+                    continue
+                endc_combo_config = cputils.generate_endc_combo_config_from_string(
+                    endc_combo_str)
+                special_chars = '+[]=;,\n'
+                for char in special_chars:
+                    endc_combo_str = endc_combo_str.replace(char, '_')
+                endc_combo_str = endc_combo_str.replace('__', '_')
+                endc_combo_str = endc_combo_str.strip('_')
+                test_cell_list = list(range(len(endc_combo_config['cell_list'])))
+                test_cell_list.append('all')
+                for cell_idx in test_cell_list:
+                    test_name = 'test_rvr_{}_cell_{}'.format(
+                        endc_combo_str, cell_idx)
+                    test_params = collections.OrderedDict(
+                        endc_combo_config=endc_combo_config,
+                        test_cell_idx=cell_idx,
+                        lte_dl_mcs_table=lte_dl_mcs_table,
+                        lte_dl_mcs=self.testclass_params['link_adaptation_config']['LTE'],
+                        lte_ul_mcs_table=lte_ul_mcs_table,
+                        lte_ul_mcs=lte_ul_mcs,
+                        nr_dl_mcs=self.testclass_params['link_adaptation_config']['NR5G'],
+                        nr_ul_mcs=nr_ul_mcs,
+                        **kwargs)
+                    setattr(self, test_name,
+                            partial(self._test_throughput_bler, test_params))
+                    test_cases.append(test_name)
+        return test_cases
\ No newline at end of file
diff --git a/acts_tests/tests/google/cellular/performance/CellularLteFr1EndcSensitivityTest.py b/acts_tests/tests/google/cellular/performance/CellularLteFr1EndcSensitivityTest.py
index 3d347c0f5..a56a13a40 100644
--- a/acts_tests/tests/google/cellular/performance/CellularLteFr1EndcSensitivityTest.py
+++ b/acts_tests/tests/google/cellular/performance/CellularLteFr1EndcSensitivityTest.py
@@ -50,7 +50,9 @@ class CellularLteFr1EndcSensitivityTest(CellularThroughputBaseTest):
                                               nr_ul_mcs=4,
                                               transform_precoding=0,
                                               schedule_scenario='FULL_TPUT',
-                                              schedule_slot_ratio=80)
+                                              schedule_slot_ratio=80,
+                                              nr_dl_mcs_table='Q256',
+                                              nr_ul_mcs_table='Q64')
 
     def process_testclass_results(self):
         """Saves CSV with all test results to enable comparison."""
@@ -80,6 +82,7 @@ class CellularLteFr1EndcSensitivityTest(CellularThroughputBaseTest):
         bler_list = []
         average_throughput_list = []
         theoretical_throughput_list = []
+        average_power_list = []
         test_cell_idx = testcase_data['testcase_params']['test_cell_idx']
         test_cell_config = testcase_data['testcase_params']['endc_combo_config']['cell_list'][test_cell_idx]
         cell_power_list = testcase_data['testcase_params']['cell_power_sweep'][
@@ -104,9 +107,13 @@ class CellularLteFr1EndcSensitivityTest(CellularThroughputBaseTest):
                 theoretical_throughput_list.append(
                     result['throughput_measurements']['nr_tput_result'][test_cell_config['cell_number']]
                     ['DL']['theoretical_tput'])
+            if self.power_monitor:
+                average_power_list.append(result['average_power'])
         padding_len = len(cell_power_list) - len(average_throughput_list)
         average_throughput_list.extend([0] * padding_len)
         theoretical_throughput_list.extend([0] * padding_len)
+        average_throughput_list.extend([0] * padding_len)
+
 
         bler_above_threshold = [
             bler > self.testclass_params['bler_threshold']
@@ -137,6 +144,7 @@ class CellularLteFr1EndcSensitivityTest(CellularThroughputBaseTest):
         testcase_data[
             'theoretical_throughput_list'] = theoretical_throughput_list
         testcase_data['cell_power_list'] = cell_power_list
+        testcase_data['average_power_list'] = average_power_list
         testcase_data['sensitivity'] = sensitivity
 
         results_file_path = os.path.join(
@@ -246,4 +254,6 @@ class CellularLteFr1EndcSensitivity_SampleMCS_Test(CellularLteFr1EndcSensitivity
                                               nr_ul_mcs=4,
                                               transform_precoding=0,
                                               schedule_scenario='FULL_TPUT',
-                                              schedule_slot_ratio=80)
\ No newline at end of file
+                                              schedule_slot_ratio=80,
+                                              nr_dl_mcs_table='Q256',
+                                              nr_ul_mcs_table='Q64')
\ No newline at end of file
diff --git a/acts_tests/tests/google/cellular/performance/CellularLtePlusFr1PeakThroughputTest.py b/acts_tests/tests/google/cellular/performance/CellularLtePlusFr1PeakThroughputTest.py
index 1a90e9e39..b6c594ea1 100644
--- a/acts_tests/tests/google/cellular/performance/CellularLtePlusFr1PeakThroughputTest.py
+++ b/acts_tests/tests/google/cellular/performance/CellularLtePlusFr1PeakThroughputTest.py
@@ -261,7 +261,9 @@ class CellularLteFr1EndcPeakThroughputTest(CellularLtePlusFr1PeakThroughputTest
                                               lte_ul_mcs_table='QAM256',
                                               transform_precoding=0,
                                               schedule_scenario='FULL_TPUT',
-                                              schedule_slot_ratio=80)
+                                              schedule_slot_ratio=80,
+                                              nr_dl_mcs_table='Q256',
+                                              nr_ul_mcs_table='Q64')
 
     def generate_test_cases(self, mcs_pair_list, **kwargs):
         test_cases = []
@@ -315,7 +317,9 @@ class CellularFr1SingleCellPeakThroughputTest(CellularLtePlusFr1PeakThroughputTe
             lte_dl_mcs=4,
             lte_dl_mcs_table='QAM256',
             lte_ul_mcs=4,
-            lte_ul_mcs_table='QAM64')
+            lte_ul_mcs_table='QAM64',
+          nr_dl_mcs_table='Q256',
+          nr_ul_mcs_table='Q64')
 
     def generate_test_cases(self, nr_mcs_pair_list, nr_channel_list, **kwargs):
 
@@ -357,6 +361,7 @@ class CellularLteSingleCellPeakThroughputTest(CellularLtePlusFr1PeakThroughputTe
         self.publish_testcase_metrics = True
         self.testclass_params = self.user_params['throughput_test_params']
         self.tests = self.generate_test_cases(lte_mcs_pair_list=[
+            (('QAM256', 28), ('QAM256', 23)),
             (('QAM256', 27), ('QAM256', 4)), (('QAM256', 4), ('QAM256', 27))
         ],
                                               transform_precoding=0)
diff --git a/acts_tests/tests/google/cellular/performance/CellularLteRvrTest.py b/acts_tests/tests/google/cellular/performance/CellularLteRvrTest.py
index 16e6e9572..74c4ad1b9 100644
--- a/acts_tests/tests/google/cellular/performance/CellularLteRvrTest.py
+++ b/acts_tests/tests/google/cellular/performance/CellularLteRvrTest.py
@@ -68,15 +68,16 @@ class CellularLteRvrTest(CellularThroughputBaseTest):
                     title='Band {} ({}) - BLER Curves'.format(
                         cell_config['band'],
                         testcase_data['testcase_params']['lte_dl_mcs_table']),
-                    x_label='Cell Power (dBm)',
+                    x_label='Cell Power (dBm/SCS)',
                     primary_y_label='BLER (Mbps)')
                 test_id_rvr = test_id + tuple('RvR')
                 plots[test_id_rvr] = BokehFigure(
                     title='Band {} ({}) - RvR'.format(
                         cell_config['band'],
                         testcase_data['testcase_params']['lte_dl_mcs_table']),
-                    x_label='Cell Power (dBm)',
-                    primary_y_label='PHY Rate (Mbps)')
+                    x_label='Cell Power (dBm/SCS)',
+                    primary_y_label='PHY Rate (Mbps)',
+                    secondary_y_label='Power Consumption (mW)')
             # Compile test id data and metrics
             compiled_data[test_id]['average_throughput'].append(
                 testcase_data['average_throughput_list'])
@@ -88,16 +89,25 @@ class CellularLteRvrTest(CellularThroughputBaseTest):
             plots[test_id].add_line(
                 testcase_data['cell_power_list'],
                 testcase_data['bler_list'],
-                'MCS {}'.format(
-                    testcase_data['testcase_params']['lte_dl_mcs']),
+                'Band {} - BLER'.format(
+                    cell_config['band']),
                 width=1)
             plots[test_id_rvr].add_line(
                 testcase_data['cell_power_list'],
                 testcase_data['average_throughput_list'],
-                'MCS {}'.format(
-                    testcase_data['testcase_params']['lte_dl_mcs']),
+                'Band {} - RvR'.format(
+                    cell_config['band']),
                 width=1,
                 style='dashed')
+            if self.power_monitor:
+                plots[test_id_rvr].add_line(
+                    testcase_data['cell_power_list'],
+                    testcase_data['average_power_list'],
+                    'Band {} - Power Consumption (mW)'.format(
+                        cell_config['band']),
+                    width=1,
+                    style='dashdot',
+                    y_axis='secondary')
 
         # Compute average RvRs and compute metrics over orientations
         for test_id, test_data in compiled_data.items():
@@ -137,6 +147,7 @@ class CellularLteRvrTest(CellularThroughputBaseTest):
         bler_list = []
         average_throughput_list = []
         theoretical_throughput_list = []
+        average_power_list = []
         cell_power_list = testcase_data['testcase_params']['cell_power_sweep'][
             0]
         for result in testcase_data['results']:
@@ -146,20 +157,26 @@ class CellularLteRvrTest(CellularThroughputBaseTest):
                 result['throughput_measurements']['lte_tput_result']['total']['DL']['average_tput'])
             theoretical_throughput_list.append(
                 result['throughput_measurements']['lte_tput_result']['total']['DL']['theoretical_tput'])
+            if self.power_monitor:
+                average_power_list.append(result['average_power'])
         padding_len = len(cell_power_list) - len(average_throughput_list)
         average_throughput_list.extend([0] * padding_len)
         theoretical_throughput_list.extend([0] * padding_len)
+        if self.power_monitor:
+            average_power_list.extend([0] * padding_len)
 
         testcase_data['bler_list'] = bler_list
         testcase_data['average_throughput_list'] = average_throughput_list
         testcase_data[
             'theoretical_throughput_list'] = theoretical_throughput_list
+        testcase_data['average_power_list'] = average_power_list
         testcase_data['cell_power_list'] = cell_power_list
 
         plot = BokehFigure(
             title='Band {} - RvR'.format(testcase_data['testcase_params']['endc_combo_config']['cell_list'][0]['band']),
             x_label='Cell Power (dBm)',
-            primary_y_label='PHY Rate (Mbps)')
+            primary_y_label='PHY Rate (Mbps)',
+            secondary_y_label='Power Consumption (mW)')
 
         plot.add_line(
             testcase_data['cell_power_list'],
@@ -169,9 +186,17 @@ class CellularLteRvrTest(CellularThroughputBaseTest):
         plot.add_line(
             testcase_data['cell_power_list'],
             testcase_data['theoretical_throughput_list'],
-            'Average Throughput',
+            'Theoretical Throughput',
             width=1,
             style='dashed')
+        if self.power_monitor:
+            plot.add_line(
+                testcase_data['cell_power_list'],
+                testcase_data['average_power_list'],
+                'Power Consumption (mW)',
+                width=1,
+                style='dashdot',
+                y_axis='secondary')
         plot.generate_figure()
         output_file_path = os.path.join(self.log_path, '{}.html'.format(self.current_test_name))
         BokehFigure.save_figure(plot, output_file_path)
@@ -202,7 +227,7 @@ class CellularLteRvrTest(CellularThroughputBaseTest):
                 test_params = collections.OrderedDict(
                     endc_combo_config=endc_combo_config,
                     lte_dl_mcs_table=lte_dl_mcs_table,
-                    lte_dl_mcs='WCQI',
+                    lte_dl_mcs=self.testclass_params['link_adaptation_config'],
                     lte_ul_mcs_table=lte_ul_mcs_table,
                     lte_ul_mcs=lte_ul_mcs,
                     **kwargs)
diff --git a/acts_tests/tests/google/cellular/performance/CellularLteSensitivityTest.py b/acts_tests/tests/google/cellular/performance/CellularLteSensitivityTest.py
index f3b5afeee..c3d8a0c49 100644
--- a/acts_tests/tests/google/cellular/performance/CellularLteSensitivityTest.py
+++ b/acts_tests/tests/google/cellular/performance/CellularLteSensitivityTest.py
@@ -69,15 +69,16 @@ class CellularLteSensitivityTest(CellularThroughputBaseTest):
                     title='Band {} ({}) - BLER Curves'.format(
                         cell_config['band'],
                         testcase_data['testcase_params']['lte_dl_mcs_table']),
-                    x_label='Cell Power (dBm)',
+                    x_label='Cell Power (dBm/SCS)',
                     primary_y_label='BLER (Mbps)')
                 test_id_rvr = test_id + tuple('RvR')
                 plots[test_id_rvr] = BokehFigure(
                     title='Band {} ({}) - RvR'.format(
                         cell_config['band'],
                         testcase_data['testcase_params']['lte_dl_mcs_table']),
-                    x_label='Cell Power (dBm)',
-                    primary_y_label='PHY Rate (Mbps)')
+                    x_label='Cell Power (dBm/SCS)',
+                    primary_y_label='PHY Rate (Mbps)',
+                    secondary_y_label='Power Consumption (mW)')
             # Compile test id data and metrics
             compiled_data[test_id]['average_throughput'].append(
                 testcase_data['average_throughput_list'])
@@ -99,6 +100,15 @@ class CellularLteSensitivityTest(CellularThroughputBaseTest):
                     testcase_data['testcase_params']['lte_dl_mcs']),
                 width=1,
                 style='dashed')
+            if self.power_monitor:
+                plots[test_id_rvr].add_line(
+                    testcase_data['cell_power_list'],
+                    testcase_data['average_power_list'],
+                    'MCS {} - Power'.format(
+                        testcase_data['testcase_params']['lte_dl_mcs']),
+                    width=1,
+                    style='dashdot',
+                    y_axis='secondary')
 
         for test_id, test_data in compiled_data.items():
             test_id_rvr = test_id + tuple('RvR')
@@ -149,6 +159,7 @@ class CellularLteSensitivityTest(CellularThroughputBaseTest):
         bler_list = []
         average_throughput_list = []
         theoretical_throughput_list = []
+        average_power_list = []
         cell_power_list = testcase_data['testcase_params']['cell_power_sweep'][
             0]
         for result in testcase_data['results']:
@@ -160,9 +171,13 @@ class CellularLteSensitivityTest(CellularThroughputBaseTest):
             theoretical_throughput_list.append(
                 result['throughput_measurements']['lte_tput_result']['total']
                 ['DL']['theoretical_tput'])
+            if self.power_monitor:
+                average_power_list.append(result['average_power'])
         padding_len = len(cell_power_list) - len(average_throughput_list)
         average_throughput_list.extend([0] * padding_len)
         theoretical_throughput_list.extend([0] * padding_len)
+        if self.power_monitor:
+            average_power_list.extend([0] * padding_len)
 
         bler_above_threshold = [
             bler > self.testclass_params['bler_threshold']
@@ -185,8 +200,10 @@ class CellularLteSensitivityTest(CellularThroughputBaseTest):
         testcase_data[
             'theoretical_throughput_list'] = theoretical_throughput_list
         testcase_data['cell_power_list'] = cell_power_list
+        testcase_data['average_power_list'] = average_power_list
         testcase_data['sensitivity'] = sensitivity
 
+
         results_file_path = os.path.join(
             context.get_current_context().get_full_output_path(),
             '{}.json'.format(self.current_test_name))
@@ -253,6 +270,42 @@ class CellularLteSensitivityTest(CellularThroughputBaseTest):
         return test_cases
 
 
+class CellularLteSensitivity_QAM256_Test(CellularLteSensitivityTest):
+    """Class to test single cell LTE sensitivity"""
+
+    def __init__(self, controllers):
+        base_test.BaseTestClass.__init__(self, controllers)
+        self.testcase_metric_logger = (
+            BlackboxMappedMetricLogger.for_test_case())
+        self.testclass_metric_logger = (
+            BlackboxMappedMetricLogger.for_test_class())
+        self.publish_testcase_metrics = True
+        self.testclass_params = self.user_params['lte_sensitivity_test_params']
+        self.tests = self.generate_test_cases(list(
+            numpy.arange(27, -1, -1)),
+                                              lte_dl_mcs_table='QAM256',
+                                              lte_ul_mcs_table='QAM256',
+                                              lte_ul_mcs=4,
+                                              transform_precoding=0)
+
+class CellularLteSensitivity_QAM64_Test(CellularLteSensitivityTest):
+    """Class to test single cell LTE sensitivity"""
+
+    def __init__(self, controllers):
+        base_test.BaseTestClass.__init__(self, controllers)
+        self.testcase_metric_logger = (
+            BlackboxMappedMetricLogger.for_test_case())
+        self.testclass_metric_logger = (
+            BlackboxMappedMetricLogger.for_test_class())
+        self.publish_testcase_metrics = True
+        self.testclass_params = self.user_params['lte_sensitivity_test_params']
+        self.tests = self.generate_test_cases(list(
+            numpy.arange(27, -1, -1)),
+                                              lte_dl_mcs_table='QAM64',
+                                              lte_ul_mcs_table='QAM64',
+                                              lte_ul_mcs=4,
+                                              transform_precoding=0)
+
 class CellularLteSensitivity_SampleMCS_Test(CellularLteSensitivityTest):
     """Class to test single cell LTE sensitivity"""
 
diff --git a/acts_tests/tests/google/cellular/performance/CellularPageDecodeTest.py b/acts_tests/tests/google/cellular/performance/CellularPageDecodeTest.py
index 21a501503..db01e27c4 100644
--- a/acts_tests/tests/google/cellular/performance/CellularPageDecodeTest.py
+++ b/acts_tests/tests/google/cellular/performance/CellularPageDecodeTest.py
@@ -32,7 +32,8 @@ from functools import partial
 
 VERY_SHORT_SLEEP = 0.1
 SHORT_SLEEP = 1
-MEDIUM_SLEEP = 5
+TWO_SECOND_SLEEP = 2
+MEDIUM_SLEEP = 3
 LONG_SLEEP = 10
 STOP_COUNTER_LIMIT = 3
 
@@ -50,6 +51,57 @@ class CellularPageDecodeTest(CellularThroughputBaseTest):
         self.testclass_params = self.user_params['page_decode_test_params']
         self.tests = self.generate_test_cases()
 
+    def process_testcase_results(self):
+        if self.current_test_name not in self.testclass_results:
+            return
+        testcase_data = self.testclass_results[self.current_test_name]
+        results_file_path = os.path.join(
+            context.get_current_context().get_full_output_path(),
+            '{}.json'.format(self.current_test_name))
+        with open(results_file_path, 'w') as results_file:
+            json.dump(wputils.serialize_dict(testcase_data),
+                      results_file,
+                      indent=4)
+
+        decode_probability_list = []
+        average_power_list = []
+        cell_power_list = testcase_data['testcase_params']['cell_power_sweep'][0]
+        for result in testcase_data['results']:
+            decode_probability_list.append(result['decode_probability'])
+            if self.power_monitor:
+                average_power_list.append(result['average_power'])
+        padding_len = len(cell_power_list) - len(decode_probability_list)
+        decode_probability_list.extend([0] * padding_len)
+
+        testcase_data['decode_probability_list'] = decode_probability_list
+        testcase_data['cell_power_list'] = cell_power_list
+
+        plot = BokehFigure(
+            title='Band {} - Page Decode Probability'.format(testcase_data['testcase_params']['endc_combo_config']['cell_list'][0]['band']),
+            x_label='Cell Power (dBm)',
+            primary_y_label='Decode Probability',
+            secondary_y_label='Power Consumption (mW)'
+        )
+
+        plot.add_line(
+            testcase_data['cell_power_list'],
+            testcase_data['decode_probability_list'],
+            'Decode Probability',
+            width=1)
+        if self.power_monitor:
+            plot.add_line(
+                testcase_data['testcase_params']['cell_power_sweep'][0],
+                average_power_list,
+                'Power Consumption (mW)',
+                width=1,
+                style='dashdot',
+                y_axis='secondary')
+        plot.generate_figure()
+        output_file_path = os.path.join(
+            context.get_current_context().get_full_output_path(),
+            '{}.html'.format(self.current_test_name))
+        BokehFigure.save_figure(plot, output_file_path)
+
     def _test_page_decode(self, testcase_params):
         """Test function to run cellular throughput and BLER measurements.
 
@@ -79,6 +131,9 @@ class CellularPageDecodeTest(CellularThroughputBaseTest):
 
         # Setup tester and wait for DUT to connect
         self.setup_tester(testcase_params)
+        # Put DUT to sleep for power measurements
+        self.dut_utils.go_to_sleep()
+
         test_cell = testcase_params['endc_combo_config']['cell_list'][0]
 
         # Release RRC connection
@@ -102,9 +157,17 @@ class CellularPageDecodeTest(CellularThroughputBaseTest):
                 cell_power_array.append(current_cell_power)
                 self.keysight_test_app.set_cell_dl_power(
                     cell['cell_type'], cell['cell_number'], current_cell_power,
-                    1)
+                    0)
+            self.log.info('Cell Power: {}'.format(cell_power_array))
             result['cell_power'] = cell_power_array
             # Start BLER and throughput measurements
+            if self.power_monitor:
+                measurement_wait = LONG_SLEEP if (power_idx == 0) else 0
+                average_power_future = self.collect_power_data_nonblocking(
+                    min(10, self.testclass_params['num_measurements'])*MEDIUM_SLEEP,
+                    measurement_wait,
+                    reconnect_usb=0,
+                    measurement_tag=power_idx)
             decode_counter = 0
             for idx in range(self.testclass_params['num_measurements']):
                 # Page device
@@ -114,17 +177,20 @@ class CellularPageDecodeTest(CellularThroughputBaseTest):
                 # Fetch page result
                 preamble_report = self.keysight_test_app.fetch_preamble_report(
                     test_cell['cell_type'], test_cell['cell_number'])
-                self.log.info(preamble_report)
                 # If rach attempted, increment decode counter.
                 if preamble_report:
                     decode_counter = decode_counter + 1
-            lte_rx_meas = self.dut_utils.get_rx_measurements('LTE')
-            nr_rx_meas = self.dut_utils.get_rx_measurements('NR5G')
+                self.log.info('Decode probability: {}/{}'.format(decode_counter, idx+1))
             result[
                 'decode_probability'] = decode_counter / self.testclass_params[
                     'num_measurements']
+            if self.power_monitor:
+                average_power = average_power_future.result()
+                result['average_power'] = average_power
 
-            if self.testclass_params.get('log_rsrp_metrics', 1):
+            if self.testclass_params.get('log_rsrp_metrics', 1) and self.dut.is_connected():
+                lte_rx_meas = self.dut_utils.get_rx_measurements('LTE')
+                nr_rx_meas = self.dut_utils.get_rx_measurements('NR5G')
                 result['lte_rx_measurements'] = lte_rx_meas
                 result['nr_rx_measurements'] = nr_rx_meas
                 self.log.info('LTE Rx Measurements: {}'.format(lte_rx_meas))
@@ -144,42 +210,6 @@ class CellularPageDecodeTest(CellularThroughputBaseTest):
         # Save results
         self.testclass_results[self.current_test_name] = testcase_results
 
-    def get_per_cell_power_sweeps(self, testcase_params):
-        # get reference test
-        nr_cell_index = testcase_params['endc_combo_config']['lte_cell_count']
-        current_band = testcase_params['endc_combo_config']['cell_list'][
-            nr_cell_index]['band']
-        reference_test = None
-        reference_sensitivity = None
-        for testcase_name, testcase_data in self.testclass_results.items():
-            if testcase_data['testcase_params']['endc_combo_config'][
-                    'cell_list'][nr_cell_index]['band'] == current_band:
-                reference_test = testcase_name
-                reference_sensitivity = testcase_data['sensitivity']
-        if reference_test and reference_sensitivity and not self.retry_flag:
-            start_atten = reference_sensitivity + self.testclass_params[
-                'adjacent_mcs_gap']
-            self.log.info(
-                "Reference test {} found. Sensitivity {} dBm. Starting at {} dBm"
-                .format(reference_test, reference_sensitivity, start_atten))
-        else:
-            start_atten = self.testclass_params['nr_cell_power_start']
-            self.log.info(
-                "Reference test not found. Starting at {} dBm".format(
-                    start_atten))
-        # get current cell power start
-        nr_cell_sweep = list(
-            numpy.arange(start_atten,
-                         self.testclass_params['nr_cell_power_stop'],
-                         self.testclass_params['nr_cell_power_step']))
-        lte_sweep = [self.testclass_params['lte_cell_power']
-                     ] * len(nr_cell_sweep)
-        if nr_cell_index == 0:
-            cell_power_sweeps = [nr_cell_sweep]
-        else:
-            cell_power_sweeps = [lte_sweep, nr_cell_sweep]
-        return cell_power_sweeps
-
     def compile_test_params(self, testcase_params):
         """Function that completes all test params based on the test name.
 
@@ -192,6 +222,25 @@ class CellularPageDecodeTest(CellularThroughputBaseTest):
             testcase_params)
         return testcase_params
 
+class CellularFr1PageDecodeTest(CellularPageDecodeTest):
+
+    def __init__(self, controllers):
+        base_test.BaseTestClass.__init__(self, controllers)
+        self.testcase_metric_logger = (
+            BlackboxMappedMetricLogger.for_test_case())
+        self.testclass_metric_logger = (
+            BlackboxMappedMetricLogger.for_test_class())
+        self.publish_testcase_metrics = True
+        self.testclass_params = self.user_params['page_decode_test_params']
+        self.tests = self.generate_test_cases()
+
+    def get_per_cell_power_sweeps(self, testcase_params):
+        nr_cell_sweep = list(
+            numpy.arange(self.testclass_params['nr_cell_power_start'],
+                         self.testclass_params['nr_cell_power_stop'],
+                         self.testclass_params['nr_cell_power_step']))
+        return [nr_cell_sweep]
+
     def generate_test_cases(self, **kwargs):
         test_cases = []
         with open(self.testclass_params['nr_single_cell_configs'],
@@ -212,8 +261,55 @@ class CellularPageDecodeTest(CellularThroughputBaseTest):
                     nr_dl_mcs=4,
                     nr_ul_mcs=4,
                     transform_precoding=0,
-                    # schedule_scenario='FULL_TPUT',
-                    # schedule_slot_ratio=80
+                    nr_dl_mcs_table='Q256',
+                    nr_ul_mcs_table='Q64',
+                    **kwargs)
+                setattr(self, test_name,
+                        partial(self._test_page_decode, test_params))
+                test_cases.append(test_name)
+        return test_cases
+
+
+class CellularLtePageDecodeTest(CellularPageDecodeTest):
+
+    def __init__(self, controllers):
+        base_test.BaseTestClass.__init__(self, controllers)
+        self.testcase_metric_logger = (
+            BlackboxMappedMetricLogger.for_test_case())
+        self.testclass_metric_logger = (
+            BlackboxMappedMetricLogger.for_test_class())
+        self.publish_testcase_metrics = True
+        self.testclass_params = self.user_params['page_decode_test_params']
+        self.tests = self.generate_test_cases()
+
+    def get_per_cell_power_sweeps(self, testcase_params):
+        lte_cell_sweep = list(
+            numpy.arange(self.testclass_params['lte_cell_power_start'],
+                         self.testclass_params['lte_cell_power_stop'],
+                         self.testclass_params['lte_cell_power_step']))
+        cell_power_sweeps = [lte_cell_sweep]
+        return cell_power_sweeps
+
+    def generate_test_cases(self, **kwargs):
+        test_cases = []
+        with open(self.testclass_params['lte_single_cell_configs'],
+                  'r') as csvfile:
+            test_configs = csv.DictReader(csvfile)
+            for test_config in test_configs:
+                if int(test_config['skip_test']):
+                    continue
+                endc_combo_config = cputils.generate_endc_combo_config_from_csv_row(
+                    test_config)
+                test_name = 'test_lte_B{}'.format(test_config['lte_band'])
+                test_params = collections.OrderedDict(
+                    endc_combo_config=endc_combo_config,
+                    lte_dl_mcs_table='QAM256',
+                    lte_dl_mcs=4,
+                    lte_ul_mcs_table='QAM256',
+                    lte_ul_mcs=4,
+                    nr_dl_mcs=4,
+                    nr_ul_mcs=4,
+                    transform_precoding=0,
                     **kwargs)
                 setattr(self, test_name,
                         partial(self._test_page_decode, test_params))
diff --git a/acts_tests/tests/google/wifi/WifiIOTConnectionTest.py b/acts_tests/tests/google/wifi/WifiIOTConnectionTest.py
index 382c4deab..1a3f194ed 100644
--- a/acts_tests/tests/google/wifi/WifiIOTConnectionTest.py
+++ b/acts_tests/tests/google/wifi/WifiIOTConnectionTest.py
@@ -65,7 +65,8 @@ class WifiIOTConnectionTest(WifiBaseTest):
     def teardown_test(self):
         self.dut.droid.wakeLockRelease()
         self.dut.droid.goToSleepNow()
-        wutils.stop_pcap(self.packet_capture, self.pcap_procs, False)
+        if hasattr(self, 'packet_capture'):
+            wutils.stop_pcap(self.packet_capture, self.pcap_procs, False)
 
     def on_fail(self, test_name, begin_time):
         self.dut.take_bug_report(test_name, begin_time)
diff --git a/acts_tests/tests/google/wifi/WifiManagerTest.py b/acts_tests/tests/google/wifi/WifiManagerTest.py
index b70044585..26cc60752 100644
--- a/acts_tests/tests/google/wifi/WifiManagerTest.py
+++ b/acts_tests/tests/google/wifi/WifiManagerTest.py
@@ -95,11 +95,6 @@ class WifiManagerTest(WifiBaseTest):
         self.open_network_2g = self.open_network[0]["2g"]
         self.open_network_5g = self.open_network[0]["5g"]
 
-        # Use local host as iperf server.
-        asserts.assert_true(
-          wutils.get_host_public_ipv4_address(),
-          "The host has no public ip address")
-        self.iperf_server_address = wutils.get_host_public_ipv4_address()
         self.iperf_server_port = wutils.get_iperf_server_port()
         try:
           self.iperf_server = IPerfServer(self.iperf_server_port)
@@ -281,6 +276,11 @@ class WifiManagerTest(WifiBaseTest):
         wait_time = 5
         network, ad = params
         SSID = network[WifiEnums.SSID_KEY]
+        # Use local host as iperf server.
+        self.iperf_server_address = wutils.get_host_iperf_ipv4_address(ad)
+        asserts.assert_true(self.iperf_server_address, "The host has no "
+                                "available IPv4 address for iperf client to "
+                                "connect to.")
         self.log.info("Starting iperf traffic through {}".format(SSID))
         time.sleep(wait_time)
         port_arg = "-p {}".format(self.iperf_server_port)
diff --git a/acts_tests/tests/google/wifi/WifiNetworkSuggestionTest.py b/acts_tests/tests/google/wifi/WifiNetworkSuggestionTest.py
index f3b9c66ea..0bcffb8b9 100644
--- a/acts_tests/tests/google/wifi/WifiNetworkSuggestionTest.py
+++ b/acts_tests/tests/google/wifi/WifiNetworkSuggestionTest.py
@@ -71,7 +71,7 @@ class WifiNetworkSuggestionTest(WifiBaseTest):
             "open_network", "reference_networks", "hidden_networks",
             "radius_conf_2g", "radius_conf_5g", "ca_cert", "eap_identity",
             "eap_password", "passpoint_networks", "domain_suffix_match",
-            "wifi6_models"
+            "wifi6_models", "google_pixel_watch_models"
         ]
         self.unpack_userparams(opt_param_names=opt_param, )
 
@@ -103,9 +103,12 @@ class WifiNetworkSuggestionTest(WifiBaseTest):
             self.passpoint_network[WifiEnums.SSID_KEY] = \
                 self.passpoint_networks[BOINGO][WifiEnums.SSID_KEY][0]
         self.dut.droid.wifiRemoveNetworkSuggestions([])
-        self.dut.adb.shell(
-            "pm disable com.google.android.apps.carrier.carrierwifi",
-            ignore_status=True)
+        if "google_pixel_watch_models" in self.user_params:
+            if not self.dut.model in \
+                self.user_params["google_pixel_watch_models"]:
+                self.dut.adb.shell(
+                    "pm disable com.google.android.apps.carrier.carrierwifi",
+                    ignore_status=True)
 
     def setup_test(self):
         super().setup_test()
@@ -141,8 +144,11 @@ class WifiNetworkSuggestionTest(WifiBaseTest):
             str(self.dut.droid.telephonyGetSimCarrierId()))
 
     def teardown_class(self):
-        self.dut.adb.shell(
-            "pm enable com.google.android.apps.carrier.carrierwifi")
+        if "google_pixel_watch_models" in self.user_params:
+            if not self.dut.model in \
+                self.user_params["google_pixel_watch_models"]:
+                self.dut.adb.shell(
+                    "pm enable com.google.android.apps.carrier.carrierwifi")
         if "AccessPoint" in self.user_params:
             del self.user_params["reference_networks"]
             del self.user_params["open_network"]
@@ -257,6 +263,11 @@ class WifiNetworkSuggestionTest(WifiBaseTest):
         self.dut.reboot()
         time.sleep(DEFAULT_TIMEOUT)
 
+        if "google_pixel_watch_models" in self.user_params:
+            if self.dut.model in \
+                self.user_params["google_pixel_watch_models"]:
+                self.dut.unlock_screen()
+
         wutils.wait_for_connect(self.dut, wifi_network[WifiEnums.SSID_KEY])
         wutils.verify_11ax_wifi_connection(self.dut, self.wifi6_models,
                                            "wifi6_ap" in self.user_params)
diff --git a/acts_tests/tests/google/wifi/WifiPreTest.py b/acts_tests/tests/google/wifi/WifiPreTest.py
index ebc156797..cc470786e 100644
--- a/acts_tests/tests/google/wifi/WifiPreTest.py
+++ b/acts_tests/tests/google/wifi/WifiPreTest.py
@@ -28,7 +28,6 @@ from acts.controllers.utils_lib.ssh import connection
 
 _POLL_AP_RETRY_INTERVAL_SEC = 1
 _WAIT_OPENWRT_AP_BOOT_SEC = 30
-_NO_ATTENUATION = 0
 
 class WifiPreTest(WifiBaseTest):
   """ Wi-Fi PreTest."""
@@ -39,7 +38,7 @@ class WifiPreTest(WifiBaseTest):
   def setup_class(self):
     super().setup_class()
 
-    req_params = ["Attenuator", "OpenWrtAP"]
+    req_params = ["OpenWrtAP"]
     self.unpack_userparams(req_param_names=req_params)
 
     self.dut = self.android_devices[0]
@@ -59,11 +58,6 @@ class WifiPreTest(WifiBaseTest):
         raise signals.TestFailure(
           f"Unable to connect to OpenWrt AP: {openwrt.ssh_settings.hostname}")
 
-    # Set all attenuators to 0 dB.
-    for i, attenuator in enumerate(self.attenuators):
-      attenuator.set_atten(_NO_ATTENUATION)
-      logging.info(f"Attenuator {i} set to {_NO_ATTENUATION} dB")
-
     self.start_openwrt()
 
     wutils.list_scan_results(self.dut, wait_time=30)
diff --git a/acts_tests/tests/google/wifi/WifiRvrTest.py b/acts_tests/tests/google/wifi/WifiRvrTest.py
index 1daf8635a..05009f624 100644
--- a/acts_tests/tests/google/wifi/WifiRvrTest.py
+++ b/acts_tests/tests/google/wifi/WifiRvrTest.py
@@ -515,6 +515,7 @@ class WifiRvrTest(base_test.BaseTestClass):
         # Compile test result and meta data
         rvr_result = collections.OrderedDict()
         rvr_result['test_name'] = self.current_test_name
+        rvr_result['phone_fold_status'] = wputils.check_fold_status(self.sta_dut)
         rvr_result['testcase_params'] = testcase_params.copy()
         rvr_result['ap_settings'] = self.access_point.ap_settings.copy()
         rvr_result['fixed_attenuation'] = self.testbed_params[
diff --git a/acts_tests/tests/google/wifi/WifiSoftApAcsTest.py b/acts_tests/tests/google/wifi/WifiSoftApAcsTest.py
index 06bfa532c..fb8add899 100644
--- a/acts_tests/tests/google/wifi/WifiSoftApAcsTest.py
+++ b/acts_tests/tests/google/wifi/WifiSoftApAcsTest.py
@@ -68,7 +68,7 @@ class WifiSoftApAcsTest(WifiBaseTest):
             "wifi6_models",
         ]
         opt_param = [
-            "iperf_server_address", "reference_networks", "pixel_models"
+            "reference_networks", "pixel_models"
         ]
         self.unpack_userparams(req_param_names=req_params,
                                opt_param_names=opt_param)
@@ -78,11 +78,6 @@ class WifiSoftApAcsTest(WifiBaseTest):
         }
         self.pcap_procs = None
 
-        # Use local host as iperf server.
-        asserts.assert_true(
-          wutils.get_host_public_ipv4_address(),
-          "The host has no public ip address")
-        self.iperf_server_address = wutils.get_host_public_ipv4_address()
         self.iperf_server_port = wutils.get_iperf_server_port()
         try:
           self.iperf_server = IPerfServer(self.iperf_server_port)
@@ -135,6 +130,11 @@ class WifiSoftApAcsTest(WifiBaseTest):
         """
         network, ad = params
         SSID = network[WifiEnums.SSID_KEY]
+        # Use local host as iperf server.
+        self.iperf_server_address = wutils.get_host_iperf_ipv4_address(ad)
+        asserts.assert_true(self.iperf_server_address, "The host has no "
+                                "available IPv4 address for iperf client to "
+                                "connect to.")
         self.log.info("Starting iperf traffic through {}".format(SSID))
         port_arg = "-p {} -t {}".format(self.iperf_server_port, 3)
         success, data = ad.run_iperf_client(self.iperf_server_address,
diff --git a/acts_tests/tests/google/wifi/WifiStaApConcurrencyTest.py b/acts_tests/tests/google/wifi/WifiStaApConcurrencyTest.py
index c41f32514..5e408f56f 100644
--- a/acts_tests/tests/google/wifi/WifiStaApConcurrencyTest.py
+++ b/acts_tests/tests/google/wifi/WifiStaApConcurrencyTest.py
@@ -73,11 +73,6 @@ class WifiStaApConcurrencyTest(WifiBaseTest):
                       "wifi6_models"]
         self.unpack_userparams(req_param_names=req_params,)
 
-        # Use local host as iperf server.
-        asserts.assert_true(
-          wutils.get_host_public_ipv4_address(),
-          "The host has no public ip address")
-        self.iperf_server_address = wutils.get_host_public_ipv4_address()
         self.iperf_server_port = wutils.get_iperf_server_port()
         try:
           self.iperf_server = IPerfServer(self.iperf_server_port)
@@ -172,6 +167,12 @@ class WifiStaApConcurrencyTest(WifiBaseTest):
             wait_time = 5
             network, ad = params
             ssid = network[WifiEnums.SSID_KEY]
+            # Use local host as iperf server.
+            self.iperf_server_address = wutils.get_host_iperf_ipv4_address(ad)
+            asserts.assert_true(self.iperf_server_address, "The host has no "
+                                "available IPv4 address for iperf client to "
+                                "connect to.")
+
             ad.log.info("Starting iperf traffic through {} to {} port:{}".
                 format(ssid, self.iperf_server_address,
                        self.iperf_server_port))
diff --git a/acts_tests/tests/google/wifi/WifiStressTest.py b/acts_tests/tests/google/wifi/WifiStressTest.py
index 6928d2516..098ce400f 100644
--- a/acts_tests/tests/google/wifi/WifiStressTest.py
+++ b/acts_tests/tests/google/wifi/WifiStressTest.py
@@ -71,7 +71,7 @@ class WifiStressTest(WifiBaseTest):
         wutils.wifi_test_device_init(self.dut)
         req_params = []
         opt_param = [
-            "open_network", "reference_networks", "iperf_server_address",
+            "open_network", "reference_networks",
             "stress_count", "stress_hours", "attn_vals", "pno_interval",
         ]
         self.unpack_userparams(req_param_names=req_params,
@@ -92,11 +92,6 @@ class WifiStressTest(WifiBaseTest):
         self.open_5g = self.open_network[0]["5g"]
         self.networks = [self.wpa_2g, self.wpa_5g, self.open_2g, self.open_5g]
 
-        # Use local host as iperf server.
-        asserts.assert_true(
-          wutils.get_host_public_ipv4_address(),
-          "The host has no public ip address")
-        self.iperf_server_address = wutils.get_host_public_ipv4_address()
         self.iperf_server_port = wutils.get_iperf_server_port()
         try:
           self.iperf_server = IPerfServer(self.iperf_server_port)
@@ -250,6 +245,11 @@ class WifiStressTest(WifiBaseTest):
 
     def run_long_traffic(self, sec, args, q):
         try:
+            # Use local host as iperf server.
+            self.iperf_server_address = wutils.get_host_iperf_ipv4_address(self.dut)
+            asserts.assert_true(self.iperf_server_address, "The host has no "
+                                "available IPv4 address for iperf client to "
+                                "connect to.")
             # Start IPerf traffic
             self.log.info("Running iperf client {}".format(args))
             result, data = self.dut.run_iperf_client(self.iperf_server_address,
@@ -335,6 +335,11 @@ class WifiStressTest(WifiBaseTest):
                 asserts.assert_true(net_id != -1,
                                     "Add network %r failed" % self.wpa_5g)
                 self.scan_and_connect_by_id(self.wpa_5g, net_id)
+                # Use local host as iperf server.
+                self.iperf_server_address = wutils.get_host_iperf_ipv4_address(self.dut)
+                asserts.assert_true(self.iperf_server_address, "The host has no "
+                                "available IPv4 address for iperf client to "
+                                "connect to.")
                 # Start IPerf traffic from phone to server.
                 # Upload data for 10s.
                 args = "-p {} -t {}".format(self.iperf_server_port, 10)
@@ -661,6 +666,11 @@ class WifiStressTest(WifiBaseTest):
                 self.log.debug("WiFi was enabled on the device in %s s." %
                                startup_time)
                 time.sleep(DEFAULT_TIMEOUT)
+                # Use local host as iperf server.
+                self.iperf_server_address = wutils.get_host_iperf_ipv4_address(self.dut)
+                asserts.assert_true(self.iperf_server_address, "The host has no "
+                                "available IPv4 address for iperf client to "
+                                "connect to.")
                 # Start IPerf traffic from phone to server.
                 # Upload data for 10s.
                 args = "-p {} -t {}".format(self.iperf_server_port, 10)
diff --git a/acts_tests/tests/google/wifi/WifiWakeTest.py b/acts_tests/tests/google/wifi/WifiWakeTest.py
index ddd5899db..8f29c6b80 100644
--- a/acts_tests/tests/google/wifi/WifiWakeTest.py
+++ b/acts_tests/tests/google/wifi/WifiWakeTest.py
@@ -57,7 +57,8 @@ class WifiWakeTest(WifiBaseTest):
         self.dut.droid.wifiScannerToggleAlwaysAvailable(True)
 
         self.unpack_userparams(req_param_names=[],
-                               opt_param_names=["reference_networks"])
+                               opt_param_names=["reference_networks",
+                                                "google_pixel_watch_models"])
 
         if "AccessPoint" in self.user_params:
             self.legacy_configure_ap_and_start(mirror_ap=False, ap_count=2)
@@ -201,6 +202,10 @@ class WifiWakeTest(WifiBaseTest):
         off Wifi while connected to that network and the user has not moved
         (i.e. moved out of range of the AP then came back).
         """
+        if "google_pixel_watch_models" in self.user_params:
+            if self.dut.model in self.user_params["google_pixel_watch_models"]:
+                wutils.disable_wear_wifimediator(self.dut, True)
+
         wutils.wifi_connect(self.dut, self.ap_a, num_of_tries=5)
         wutils.wifi_toggle_state(self.dut, new_state=False)
         time.sleep(PRESCAN_DELAY_SEC)
@@ -210,6 +215,10 @@ class WifiWakeTest(WifiBaseTest):
             self.dut.droid.wifiCheckState(),
             "Expect Wifi Wake to not enable Wifi, but Wifi was enabled.")
 
+        if "google_pixel_watch_models" in self.user_params:
+            if self.dut.model in self.user_params["google_pixel_watch_models"]:
+                wutils.disable_wear_wifimediator(self.dut, False)
+
     @test_tracker_info(uuid="ec7a54a5-f293-43f5-a1dd-d41679aa1825")
     def test_reconnect_wifi_saved_network(self):
         """Tests that Wifi Wake re-enables Wifi for a saved network."""
@@ -401,8 +410,9 @@ class WifiWakeTest(WifiBaseTest):
         wutils.wait_for_disconnect(self.dut, DISCONNECT_TIMEOUT_SEC)
         self.log.info("Wifi Disconnected")
 
-        if self.dut.model in self.user_params["google_pixel_watch_models"]:
-            wutils.disable_wear_wifimediator(self.dut, True)
+        if "google_pixel_watch_models" in self.user_params:
+            if self.dut.model in self.user_params["google_pixel_watch_models"]:
+                wutils.disable_wear_wifimediator(self.dut, True)
 
         self.do_location_scan(2)
         time.sleep(LAST_DISCONNECT_TIMEOUT_SEC * 1.2)
@@ -415,8 +425,9 @@ class WifiWakeTest(WifiBaseTest):
         self.ap_a_atten.set_atten(30)
         self.ap_b_atten.set_atten(0)
 
-        if self.dut.model in self.user_params["google_pixel_watch_models"]:
-            wutils.disable_wear_wifimediator(self.dut, False)
+        if "google_pixel_watch_models" in self.user_params:
+            if self.dut.model in self.user_params["google_pixel_watch_models"]:
+                wutils.disable_wear_wifimediator(self.dut, False)
 
         self.do_location_scan(
             SCANS_REQUIRED_TO_FIND_SSID, self.ap_b[wutils.WifiEnums.SSID_KEY])
```

