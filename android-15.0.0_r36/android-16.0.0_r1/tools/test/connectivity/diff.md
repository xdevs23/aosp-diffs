```diff
diff --git a/OWNERS b/OWNERS
index 25372fa60..4ef77c446 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,3 @@
 dgoldfarb@google.com
 htellez@google.com
-markdr@google.com
 xianyuanjia@google.com
diff --git a/acts/framework/acts/controllers/OWNERS b/acts/framework/acts/controllers/OWNERS
index 448fb529f..3b0247925 100644
--- a/acts/framework/acts/controllers/OWNERS
+++ b/acts/framework/acts/controllers/OWNERS
@@ -1,5 +1,4 @@
 per-file asus_axe11000_ap.py = martschneider@google.com
-per-file fuchsia_device.py = chcl@google.com, dhobsd@google.com, haydennix@google.com, jmbrenna@google.com, mnck@google.com, nickchee@google.com, sbalana@google.com, silberst@google.com, tturney@google.com
-per-file bluetooth_pts_device.py = tturney@google.com
-per-file cellular_simulator.py = iguarna@google.com, chaoyangf@google.com, codycaldwell@google.com, yixiang@google.com
+per-file fuchsia_device.py = chcl@google.com, dhobsd@google.com, haydennix@google.com, jmbrenna@google.com, mnck@google.com, nickchee@google.com, sbalana@google.com, silberst@google.com
+per-file cellular_simulator.py = iguarna@google.com, chaoyangf@google.com
 per-file openwrt_ap.py = jerrypcchen@google.com, martschneider@google.com, gmoturu@google.com, mingchenchung@google.com, timhuang@google.com
diff --git a/acts/framework/acts/controllers/anritsu_lib/OWNERS b/acts/framework/acts/controllers/anritsu_lib/OWNERS
index e4010df21..923044814 100644
--- a/acts/framework/acts/controllers/anritsu_lib/OWNERS
+++ b/acts/framework/acts/controllers/anritsu_lib/OWNERS
@@ -1,4 +1,3 @@
 iguarna@google.com
 chaoyangf@google.com
 yixiang@google.com
-codycaldwell@google.com
\ No newline at end of file
diff --git a/acts/framework/acts/controllers/cellular_lib/OWNERS b/acts/framework/acts/controllers/cellular_lib/OWNERS
index f88a96cbf..1d5c06629 100644
--- a/acts/framework/acts/controllers/cellular_lib/OWNERS
+++ b/acts/framework/acts/controllers/cellular_lib/OWNERS
@@ -5,4 +5,3 @@ codycaldwell@google.com
 
 per-file PresetSimulation.py = hmtuan@google.com
 per-file PresetSimulation.py = harjani@google.com
-per-file PresetSimulation.py = jethier@google.com
\ No newline at end of file
diff --git a/acts/framework/acts/controllers/fuchsia_lib/OWNERS b/acts/framework/acts/controllers/fuchsia_lib/OWNERS
index 130db54c9..5984981ba 100644
--- a/acts/framework/acts/controllers/fuchsia_lib/OWNERS
+++ b/acts/framework/acts/controllers/fuchsia_lib/OWNERS
@@ -3,7 +3,5 @@ dhobsd@google.com
 haydennix@google.com
 jmbrenna@google.com
 mnck@google.com
-nickchee@google.com
 sbalana@google.com
 silberst@google.com
-tturney@google.com
diff --git a/acts/framework/acts/controllers/rohdeschwarz_lib/OWNERS b/acts/framework/acts/controllers/rohdeschwarz_lib/OWNERS
index e4010df21..923044814 100644
--- a/acts/framework/acts/controllers/rohdeschwarz_lib/OWNERS
+++ b/acts/framework/acts/controllers/rohdeschwarz_lib/OWNERS
@@ -1,4 +1,3 @@
 iguarna@google.com
 chaoyangf@google.com
 yixiang@google.com
-codycaldwell@google.com
\ No newline at end of file
diff --git a/acts/framework/acts/controllers/uxm_lib/OWNERS b/acts/framework/acts/controllers/uxm_lib/OWNERS
index 0c406220a..58764864b 100644
--- a/acts/framework/acts/controllers/uxm_lib/OWNERS
+++ b/acts/framework/acts/controllers/uxm_lib/OWNERS
@@ -1,3 +1,2 @@
 jethier@google.com
-hmtuan@google.com
-harjani@google.com
\ No newline at end of file
+harjani@google.com
diff --git a/acts_tests/acts_contrib/test_utils/wifi/delay_line.py b/acts_tests/acts_contrib/test_utils/wifi/delay_line.py
new file mode 100644
index 000000000..286ee223f
--- /dev/null
+++ b/acts_tests/acts_contrib/test_utils/wifi/delay_line.py
@@ -0,0 +1,146 @@
+#!/usr/bin/env python3
+#
+#   Copyright 2024 - The Android Open Source Project
+#
+#   Licensed under the Apache License, Version 2.0 (the "License");
+#   you may not use this file except in compliance with the License.
+#   You may obtain a copy of the License at
+#
+#       http://www.apache.org/licenses/LICENSE-2.0
+#
+#   Unless required by applicable law or agreed to in writing, software
+#   distributed under the License is distributed on an "AS IS" BASIS,
+#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+#   See the License for the specific language governing permissions and
+#   limitations under the License.
+
+
+import socket
+import time
+from acts import logger
+
+SHORT_SLEEP = 1
+
+
+def create(configs):
+    """Factory method for OTA chambers.
+
+    Args:
+        configs: list of dicts with chamber settings. settings must contain the
+        following: type (string denoting type of chamber)
+    """
+    objs = []
+    for config in configs:
+        try:
+            delay_line_class = globals()[config['model']]
+        except KeyError:
+            raise KeyError('Invalid instrument configuration.')
+        objs.append(delay_line_class(config))
+    return objs
+
+
+def detroy(objs):
+    for obj in objs:
+        obj.teardown()
+
+
+class DelayLineInstrument(object):
+    """Base class implementation for delay line.
+
+    Base class provides functions whose implementation is shared by all
+    delay line models.
+    """
+
+    def reset(self):
+        """Resets the delay line to its zero/home state."""
+        raise NotImplementedError
+
+    def set_delay(self, delay):
+        """Set delay on delay line.
+
+        Args:
+            delay: value of desired delay in nanoseconds
+        """
+        raise NotImplementedError
+
+    def get_delay(self):
+        """Get delay on delay line."""
+        raise NotImplementedError
+
+    def teardown(self):
+        """Teardown delay line instrument."""
+
+        raise NotImplementedError
+
+
+class FixedDelayLine(DelayLineInstrument):
+    """Class that implements a fixed delay line"""
+
+    def __init__(self, config):
+        self.config = config.copy()
+        self.delay = self.config['delay']
+
+    def teardown(self):
+        pass
+
+    def reset(self):
+        pass
+
+    def set_delay(self, delay):
+        self.log.error('Delay cannot be set on fixed delay line.')
+
+    def get_delay(self):
+        return self.delay
+
+
+class ColbyXR100(DelayLineInstrument):
+    """Class that implements Colby XR100 delay line."""
+
+    def __init__(self, config):
+        self.config = config.copy()
+        self.device_id = self.config['ip_address']
+        self.log = logger.create_tagged_trace_logger('ColbyXR100|{}'.format(
+            self.device_id))
+
+        # Create a socket object
+        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
+        try:
+            self.socket.settimeout(5.0)
+            self.socket.connect((self.config['ip_address'], self.config['port']))
+            id = self.send_message('*IDN?')
+            self.log.info('ID Response: {}'.format(str(id)))
+        except socket.error as e:
+            raise RuntimeError("Socket error occurred:", str(e))
+
+    def teardown(self):
+        self.socket.close()
+
+    def send_message(self, message):
+        message += '\n'
+        try:
+            self.socket.sendall(message.encode())
+            self.log.debug("Message sent: {}".format(str(message)))
+        except:
+            raise RuntimeError("Socket error occurred.")
+
+        if "?" in message:
+            try:
+                response = self.socket.recv(1024)
+                return response
+            except socket.timeout:
+                print("Timeout occurred while waiting for response.")
+        return None
+
+    def set_delay(self, delay):
+        """Set delay on delay line.
+
+        Args:
+            delay: value of desired delay in nanoseconds
+        """
+        self.send_message('DEL {} ns'.format(delay))
+        self.send_message('*OPC?')
+        time.sleep(SHORT_SLEEP)
+
+    def get_delay(self):
+        """Get delay on delay line."""
+        return self.send_message('DEL?')
diff --git a/acts_tests/acts_contrib/test_utils/wifi/ota_chamber.py b/acts_tests/acts_contrib/test_utils/wifi/ota_chamber.py
index 280e72eec..b49ba14ad 100644
--- a/acts_tests/acts_contrib/test_utils/wifi/ota_chamber.py
+++ b/acts_tests/acts_contrib/test_utils/wifi/ota_chamber.py
@@ -267,6 +267,7 @@ class BluetestChamber(OtaChamber):
         self.set_stirrer_pos(2, orientation * 100 / 360)
 
     def start_continuous_stirrers(self):
+        self.log.info('Start continuous stirrer sweep.')
         if self.current_mode != 'continuous':
             self._init_continuous_mode()
         self.chamber.chamber_stirring_continuous_start()
diff --git a/acts_tests/acts_contrib/test_utils/wifi/phase_shifter.py b/acts_tests/acts_contrib/test_utils/wifi/phase_shifter.py
new file mode 100644
index 000000000..37185893f
--- /dev/null
+++ b/acts_tests/acts_contrib/test_utils/wifi/phase_shifter.py
@@ -0,0 +1,66 @@
+#!/usr/bin/env python3
+#
+#   Copyright 2024 - The Android Open Source Project
+#
+#   Licensed under the Apache License, Version 2.0 (the "License");
+#   you may not use this file except in compliance with the License.
+#   You may obtain a copy of the License at
+#
+#       http://www.apache.org/licenses/LICENSE-2.0
+#
+#   Unless required by applicable law or agreed to in writing, software
+#   distributed under the License is distributed on an "AS IS" BASIS,
+#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+#   See the License for the specific language governing permissions and
+#   limitations under the License.
+
+
+import subprocess
+import threading
+import time
+from acts import logger
+
+SHORT_SLEEP = 1
+
+class VaunixPhaseShifter():
+    """Class that implements Colby XR100 delay line."""
+
+    def __init__(self):
+        self.log = logger.create_tagged_trace_logger('VaunixPhaseShifter')
+        self.binary = '/usr/local/bin/VaunixLPSController'
+        self.frequency = 4000
+        self.phase = 0
+
+    def set_frequency(self, frequency):
+        self.frequency = frequency
+        self.log.debug('')
+        command = '{} {} 0'.format(self.binary, self.frequency)
+        self.log.debug(command)
+        output = subprocess.check_output(command, shell=True)
+        self.log.debug(output)
+
+    def set_phase(self, phase):
+        self.phase = phase
+        command = '{} {} {}'.format(self.binary, self.frequency, phase)
+        self.log.debug(command)
+        output = subprocess.check_output(command, shell=True)
+        self.log.debug(output)
+
+    def _loop_phase(self, phase_increment = 45, dwell_time=1):
+        self.t = threading.current_thread()
+        phase = 0
+        while getattr(self.t, "do_run", True):
+            self.log.info('Setting Phase to {}.'.format(phase))
+            self.set_phase(phase)
+            time.sleep(dwell_time)
+            self.log.info('Computing next phase')
+            phase = int((phase + phase_increment) % 360)
+            self.log.info('Next Phase = {}.'.format(phase))
+        print("Stopping phase loop.")
+
+    def start_phase_loop(self, phase_increment = 45, dwell_time=1):
+        t = threading.Thread(target=self._loop_phase, args=(phase_increment, dwell_time))
+        t.start()
+
+    def stop_phase_loop(self):
+        self.t.do_run = False
diff --git a/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/__init__.py b/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/__init__.py
index a6ef9069c..8b64ba48a 100644
--- a/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/__init__.py
+++ b/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/__init__.py
@@ -124,9 +124,8 @@ def extract_sub_dict(full_dict, fields):
         (field, full_dict[field]) for field in fields)
     return sub_dict
 
-def write_antenna_tune_code(dut, tune_code):
+def write_antenna_tune_code(dut, tune_code, readback_check = True):
     flag_tune_code_forcing_on = 0
-    # Use AT Command file to enable tune code forcing 
     for n_enable in range(5):
         logging.debug('{}-th Enabling modem test mode'.format(n_enable))
         try:
@@ -153,22 +152,27 @@ def write_antenna_tune_code(dut, tune_code):
     logging.debug('Write Tune Code: {}'.format("modem_cmd raw " + tune_code['tune_code_cmd']))
     flag_tc_reg_correct = True
     # Check tune code register values
-    for tune_code_register_key in tune_code['tune_code_registers'].keys():
-        try:
-            at_tc_reg_output = dut.adb.shell("modem_cmd raw AT+MIPIREAD={}".format(tune_code_register_key))
-            time.sleep(SHORT_SLEEP)
-        except:
-            pass
-        if "+MIPIREAD:"+tune_code['tune_code_registers'][tune_code_register_key].lower() in at_tc_reg_output:
-            logging.info('Forced tune code register {} value matches expectation: {}'.format(tune_code_register_key, tune_code['tune_code_registers'][tune_code_register_key]))
+    if readback_check:
+        # Check tune code register values
+        for tune_code_register_key in tune_code['tune_code_registers'].keys():
+            try:
+                at_tc_reg_output = dut.adb.shell("modem_cmd raw AT+MIPIREAD={}".format(tune_code_register_key))
+                time.sleep(SHORT_SLEEP)
+            except:
+                pass
+            if "+MIPIREAD:"+tune_code['tune_code_registers'][tune_code_register_key].lower() in at_tc_reg_output:
+                logging.info('Forced tune code register {} value matches expectation: {}'.format(tune_code_register_key, tune_code['tune_code_registers'][tune_code_register_key]))
+            else:
+                logging.warning('Expected tune code register {} value: {}'.format(tune_code_register_key, tune_code['tune_code_registers'][tune_code_register_key]))
+                logging.warning('tune code register value is set to {}'.format(at_tc_reg_output))
+                flag_tc_reg_correct = False
+        if flag_tc_reg_correct:
+            return True
         else:
-            logging.warning('Expected tune code register {} value: {}'.format(tune_code_register_key, tune_code['tune_code_registers'][tune_code_register_key]))
-            logging.warning('tune code register value is set to {}'.format(at_tc_reg_output))
-            flag_tc_reg_correct = False
-    if flag_tc_reg_correct:
-        return True
+            raise RuntimeError("Enable modem test mode SUCCESSFUL, but register values NOT correct")
     else:
-        raise RuntimeError("Enable modem test mode SUCCESSFUL, but register values NOT correct")
+        logging.info('Tune code validation skipped.')
+        return True
 
 # Miscellaneous Wifi Utilities
 def check_skip_conditions(testcase_params, dut, access_point,
@@ -696,6 +700,7 @@ def get_connected_rssi(dut,
         all reported RSSI values (signal_poll, per chain, etc.) and their
         statistics
     """
+    pass
 
 
 @nonblocking
@@ -715,6 +720,7 @@ def get_scan_rssi(dut, tracked_bssids, num_measurements=1):
         scan_rssi: dict containing the measurement results as well as the
         statistics of the scan RSSI for all BSSIDs in tracked_bssids
     """
+    pass
 
 
 @detect_wifi_decorator
@@ -725,11 +731,13 @@ def get_sw_signature(dut):
         bdf_signature: signature consisting of last three digits of bdf cksums
         fw_signature: floating point firmware version, i.e., major.minor
     """
+    pass
 
 
 @detect_wifi_decorator
 def get_country_code(dut):
     """Function that returns the current wifi country code."""
+    pass
 
 
 @detect_wifi_decorator
@@ -744,16 +752,19 @@ def push_config(dut, config_file):
         dut: dut to push bdf file to
         config_file: path to bdf_file to push
     """
+    pass
 
 
 @detect_wifi_decorator
 def start_wifi_logging(dut):
     """Function to start collecting wifi-related logs"""
+    pass
 
 
 @detect_wifi_decorator
 def stop_wifi_logging(dut):
     """Function to start collecting wifi-related logs"""
+    pass
 
 
 @detect_wifi_decorator
@@ -765,16 +776,19 @@ def push_firmware(dut, firmware_files):
         firmware_files: path to wlanmdsp.mbn file
         datamsc_file: path to Data.msc file
     """
+    pass
 
 
 @detect_wifi_decorator
 def disable_beamforming(dut):
     """Function to disable beamforming."""
+    pass
 
 
 @detect_wifi_decorator
 def set_nss_capability(dut, nss):
     """Function to set number of spatial streams supported."""
+    pass
 
 
 @detect_wifi_decorator
@@ -785,6 +799,7 @@ def set_chain_mask(dut, chain_mask):
         dut: android device
         chain_mask: desired chain mask in [0, 1, '2x2']
     """
+    pass
 
 
 # Link layer stats utilities
diff --git a/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/bokeh_figure.py b/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/bokeh_figure.py
index ee082b2ac..589777585 100644
--- a/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/bokeh_figure.py
+++ b/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/bokeh_figure.py
@@ -19,6 +19,7 @@ import collections
 import itertools
 import json
 import math
+import numpy
 from acts_contrib.test_utils.wifi import wifi_performance_test_utils as wputils
 
 
@@ -123,22 +124,25 @@ class BokehFigure():
         self.plot.add_tools(
             bokeh.models.tools.WheelZoomTool(dimensions='height'))
 
-    def _filter_line(self, x_data, y_data, hover_text=None):
+    def _filter_line(self, x_data, y_data, hover_text=None, error_bars=[]):
         """Function to remove NaN points from bokeh plots."""
         x_data_filtered = []
         y_data_filtered = []
+        error_bars_data_filtered = []
         hover_text_filtered = {}
         for idx, xy in enumerate(
-                itertools.zip_longest(x_data, y_data, fillvalue=float('nan'))):
+                itertools.zip_longest(x_data, y_data, error_bars, fillvalue=float('nan'))):
             if not math.isnan(xy[1]):
                 x_data_filtered.append(xy[0])
                 y_data_filtered.append(xy[1])
+                if len(error_bars)>0:
+                    error_bars_data_filtered.append(xy[2])
                 if hover_text:
                     for key, value in hover_text.items():
                         hover_text_filtered.setdefault(key, [])
                         hover_text_filtered[key].append(
                             value[idx] if len(value) > idx else '')
-        return x_data_filtered, y_data_filtered, hover_text_filtered
+        return x_data_filtered, y_data_filtered, hover_text_filtered, error_bars_data_filtered
 
     def add_line(self,
                  x_data,
@@ -151,6 +155,7 @@ class BokehFigure():
                  marker=None,
                  marker_size=10,
                  shaded_region=None,
+                 error_bars=[],
                  y_axis='default'):
         """Function to add line to existing BokehFigure.
 
@@ -175,8 +180,8 @@ class BokehFigure():
             style = [5, 5]
         if isinstance(hover_text, list):
             hover_text = {'info': hover_text}
-        x_data_filter, y_data_filter, hover_text_filter = self._filter_line(
-            x_data, y_data, hover_text)
+        x_data_filter, y_data_filter, hover_text_filter, error_bars_filter = self._filter_line(
+            x_data, y_data, hover_text, error_bars)
         self.figure_data.append({
             'x_data': x_data_filter,
             'y_data': y_data_filter,
@@ -188,6 +193,7 @@ class BokehFigure():
             'marker': marker,
             'marker_size': marker_size,
             'shaded_region': shaded_region,
+            'error_bars': error_bars_filter,
             'y_axis': y_axis
         })
         self.fig_property['num_lines'] += 1
@@ -243,7 +249,7 @@ class BokehFigure():
         """
         self.init_plot()
         two_axes = False
-        for line in self.figure_data:
+        for line_idx, line in enumerate(self.figure_data):
             data_dict = {'x': line['x_data'], 'y': line['y_data']}
             for key, value in line['hover_text'].items():
                 data_dict[key] = value
@@ -268,6 +274,14 @@ class BokehFigure():
                                 color='#7570B3',
                                 line_alpha=0.1,
                                 fill_alpha=0.1)
+            if line['error_bars']:
+                data_dict = {'base': numpy.add(line['x_data'], (pow(-1,line_idx)*0.01*line_idx)/self.fig_property['num_lines']),
+                             'lower': numpy.subtract(line['y_data'],line['error_bars']),
+                             'upper': numpy.add(line['y_data'],line['error_bars']),}
+                source_error = bokeh.models.ColumnDataSource(data=data_dict)
+                self.plot.add_layout(
+                    bokeh.models.Whisker(source=source_error, base="base", upper="upper", lower="lower", line_color=line['color'])
+                )
             if line['marker'] in self.MARKERS:
                 marker_func = getattr(self.plot, line['marker'])
                 marker_func(x='x',
@@ -295,10 +309,16 @@ class BokehFigure():
             'axis_label_size']
         self.plot.yaxis.major_label_text_font_size = self.fig_property[
             'axis_tick_label_size']
-        self.plot.y_range = bokeh.models.DataRange1d(names=['default'])
+        default_y_range_renderers = [renderer for renderer in self.plot.renderers if renderer.y_range_name == 'default']
+        self.plot.y_range = bokeh.models.DataRange1d(name='default',
+                                                     renderers = default_y_range_renderers)
         if two_axes and 'secondary' not in self.plot.extra_y_ranges:
+            secondary_y_range_renderers = [renderer for renderer in self.plot.renderers if
+                                         renderer.y_range_name == 'secondary']
+
             self.plot.extra_y_ranges = {
-                'secondary': bokeh.models.DataRange1d(names=['secondary'])
+                'secondary': bokeh.models.DataRange1d(name='secondary',
+                                                      renderers=secondary_y_range_renderers)
             }
             self.plot.add_layout(
                 bokeh.models.LinearAxis(
diff --git a/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/brcm_utils.py b/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/brcm_utils.py
index d6c07d46a..9cb4e8433 100644
--- a/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/brcm_utils.py
+++ b/acts_tests/acts_contrib/test_utils/wifi/wifi_performance_test_utils/brcm_utils.py
@@ -23,6 +23,7 @@ import numpy
 import re
 import statistics
 import time
+from acts_contrib.test_utils.wifi import wifi_test_utils as wutils
 
 VERY_SHORT_SLEEP = 0.5
 SHORT_SLEEP = 1
@@ -174,6 +175,7 @@ def get_connected_rssi(dut,
          ('bssid', []), ('ssid', []), ('frequency', []),
          ('signal_poll_rssi', empty_rssi_result()),
          ('signal_poll_avg_rssi', empty_rssi_result()),
+         ('reported_rssi', empty_rssi_result()),
          ('chain_0_rssi', empty_rssi_result()),
          ('chain_1_rssi', empty_rssi_result())])
 
@@ -219,6 +221,7 @@ def get_connected_rssi(dut,
         if interface == 'wlan0':
             try:
                 per_chain_rssi = dut.adb.shell('wl phy_rssi_ant')
+                reported_rssi = int(dut.adb.shell('wl rssi'))
                 chain_0_rssi = re.search(
                     r'rssi\[0\]\s(?P<chain_0_rssi>[0-9\-]*)', per_chain_rssi)
                 if chain_0_rssi:
@@ -234,8 +237,10 @@ def get_connected_rssi(dut,
             except:
                 chain_0_rssi = RSSI_ERROR_VAL
                 chain_1_rssi = RSSI_ERROR_VAL
+                reported_rssi = RSSI_ERROR_VAL
             connected_rssi['chain_0_rssi']['data'].append(chain_0_rssi)
             connected_rssi['chain_1_rssi']['data'].append(chain_1_rssi)
+            connected_rssi['reported_rssi']['data'].append(reported_rssi)
             combined_rssi = math.pow(10, chain_0_rssi / 10) + math.pow(
                 10, chain_1_rssi / 10)
             combined_rssi = 10 * math.log10(combined_rssi)
@@ -738,4 +743,254 @@ class LinkLayerStats():
         self.llstats_incremental['summary'] = self._generate_stats_summary(
             self.llstats_incremental)
         self.llstats_cumulative['summary'] = self._generate_stats_summary(
-            self.llstats_cumulative)
\ No newline at end of file
+            self.llstats_cumulative)
+
+
+class RangingLink():
+    def __init__(self, initiator, responder):
+        self.initiator_dut = initiator
+        self.responder_dut = responder
+        self.soft_ap_mac_address = '00:12:32:45:76:85'
+        self.SUPPORTED_BANDWIDTHS = [20, 40, 80, 160]
+
+    def reset_device(self, dut, associate):
+        if associate:
+            # dut.adb.shell('echo 1 > /sys/wifi/wl_accel_force_reg_on')
+            # time.sleep(SHORT_SLEEP)
+            # dut.adb.shell('ifconfig wlan0 down')
+            # time.sleep(MED_SLEEP)
+            # dut.adb.shell('echo 1 > /sys/wifi/wl_accel_force_reg_on')
+            # time.sleep(SHORT_SLEEP)
+            # dut.adb.shell('ifconfig wlan0 up')
+            # time.sleep(MED_SLEEP)
+            dut.adb.shell('wl down')
+            time.sleep(MED_SLEEP)
+            dut.adb.shell('wl up')
+
+        else:
+            dut.adb.shell('wl down')
+            time.sleep(MED_SLEEP)
+            dut.adb.shell('wl up')
+
+    def get_ap_intf(self, soft_ap_output):
+        """Reads the AP interface from a file"""
+        SOFT_AP_REGEX = r"ifname:\s*(.*?)\s"
+        match = re.search(SOFT_AP_REGEX, soft_ap_output)
+        if match:
+            return match.group(1)
+        else:
+            raise RuntimeError('Could not find soft ap interface')
+
+    def setup_soft_ap(self, channel, bandwidth, ranging_method, az_enabled):
+
+        """Sets up a Soft-AP on responder DUT"""
+        # To allow DFS channels
+        self.responder_dut.adb.shell('wl down')
+        self.responder_dut.adb.shell('wl spect 0')
+        self.responder_dut.adb.shell('wl up')
+
+        # Create AP interface
+        # added for 11az
+        soft_ap_out = self.responder_dut.adb.shell('wl interface_create ap -m {}'.format(self.soft_ap_mac_address))
+        self.soft_ap_interface = self.get_ap_intf(soft_ap_out)
+        time.sleep(SHORT_SLEEP)
+        # if ranging_method == '11mc':
+        #     self.responder_dut.adb.shell('wl -i {} chanspec {}/{}'.format(self.soft_ap_interface, channel, bandwidth))
+        #elif ranging_method == '11az':
+        self.responder_dut.adb.shell('wl -i {} bss down'.format(self.soft_ap_interface))
+        time.sleep(SHORT_SLEEP)
+        if channel < 13:
+            self.responder_dut.adb.shell('wl -i {} chanspec {}'.format(self.soft_ap_interface, channel))
+        else:
+            self.responder_dut.adb.shell('wl -i {} chanspec {}/{}'.format(self.soft_ap_interface, channel, bandwidth))
+        time.sleep(SHORT_SLEEP)
+        self.responder_dut.adb.shell('wl -i {} oce fd_tx_duration 0'.format(self.soft_ap_interface))
+        time.sleep(SHORT_SLEEP)
+        self.responder_dut.adb.shell('wl -i {} up'.format(self.soft_ap_interface))
+        time.sleep(SHORT_SLEEP)
+        self.responder_dut.adb.shell("wl -i {} ssid testftm".format(self.soft_ap_interface))
+        time.sleep(SHORT_SLEEP)
+        self.responder_dut.adb.shell('wl -i {} status'.format(self.soft_ap_interface))
+        if 'one_sided' not in ranging_method:
+            self.enable_ranging_at_responder(bandwidth, az_enabled)
+        self.test_network = {"SSID": "testftm"}
+
+    def check_soft_ap_status(self):
+        return self.responder_dut.adb.shell('wl -i {} status'.format(self.soft_ap_interface))
+
+    def enable_ranging_at_responder(self, bandwidth_11az, az_enabled=1):
+        BW_MAPPING = {160: 5, 80: 2, 40: 1, 20: 0}
+        self.responder_dut.adb.shell('wl -i {} scansuppress 1'.format(self.soft_ap_interface))
+        self.responder_dut.adb.shell('wl scansuppress 1')
+        self.responder_dut.adb.shell('wl -i {} ftm enable'.format(self.soft_ap_interface))
+        if az_enabled:
+            self.responder_dut.adb.shell('wl -i {} ftm ntb config min-delta 100ms'.format(self.soft_ap_interface))
+            self.responder_dut.adb.shell('wl -i {} ftm ntb config max-delta 500ms'.format(self.soft_ap_interface))
+            self.responder_dut.adb.shell('wl -i {} ftm ntb config format-bw {}'.format(self.soft_ap_interface,
+                                                                                       BW_MAPPING[bandwidth_11az]))
+            self.responder_dut.adb.shell('wl -i {} ftm ntb config num-meas 100'.format(self.soft_ap_interface))
+            self.responder_dut.adb.shell('wl -i {} ftm ntb config max-i2r-sts-leq-80 2'.format(self.soft_ap_interface))
+            self.responder_dut.adb.shell('wl -i {} ftm ntb config max-r2i-sts-leq-80 2'.format(self.soft_ap_interface))
+            self.responder_dut.adb.shell('wl -i {} ftm ntb config max-i2r-sts-gt-80 2'.format(self.soft_ap_interface))
+            self.responder_dut.adb.shell('wl -i {} ftm ntb config max-r2i-sts-gt-80 2'.format(self.soft_ap_interface))
+            self.responder_dut.adb.shell('wl -i {} ftm ntb config max-i2r-rep 0'.format(self.soft_ap_interface))
+            self.responder_dut.adb.shell('wl -i {} ftm ntb config max-r2i-rep 0'.format(self.soft_ap_interface))
+            self.responder_dut.adb.shell('wl -i {} ftm ntb config options -sec-ltf-supported'.format(self.soft_ap_interface))
+            self.responder_dut.adb.shell('wl -i {} ftm ntb config options -sec-ltf-required'.format(self.soft_ap_interface))
+
+
+    def enable_ranging_at_initiator(self):
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm enable')
+
+    def setup_ranging_link(self, channel, bandwidth, associate_initiator=0, ranging_method='11mc', az_enabled=1, country_code='US'):
+        self.reset_device(self.initiator_dut, associate_initiator)
+        self.reset_device(self.responder_dut, associate_initiator)
+        wutils.set_wifi_country_code(self.initiator_dut, country_code)
+        wutils.set_wifi_country_code(self.responder_dut, country_code)
+
+        self.setup_soft_ap(channel, bandwidth, ranging_method, az_enabled)
+        if associate_initiator:
+            #self.initiator_dut.adb.shell('wl -i wlan0 join testftm')
+            self.initiator_dut.adb.shell('cmd wifi connect-network testftm open')
+            associated = 0
+            for idx in range(10):
+                status = self.initiator_dut.adb.shell('wl -i wlan0 status')
+                if 'testftm' in status:
+                    associated = 1
+                    break
+                else:
+                    time.sleep(SHORT_SLEEP)
+            if not associated:
+                raise RuntimeError('Could not connect to soft AP.')
+        self.enable_ranging_at_initiator()
+
+    def run_single_11mc_range(self, channel, bandwidth, no_meas_frames=8, one_sided = 0, ant_diversity = 0):
+        """Triggers the 11mc ranging measurements"""
+        # TODO: Debug why an extra 'wl -i wlan0 proxd ftm 1 delete' is often needed here on P22
+        self.initiator_dut.adb.shell('wl -i wlan0 proxd ftm 1 config burst-duration 128')
+        self.initiator_dut.adb.shell('wl -i wlan0 proxd ftm 1 config burst-timeout 128')
+        self.initiator_dut.adb.shell('wl -i wlan0 proxd ftm 1 config ftm-sep 3400us')
+        if one_sided:
+            self.initiator_dut.adb.shell('wl -i wlan0 proxd ftm 1 config options +randmac +auto-vhtack')
+            self.initiator_dut.adb.shell('wl -i wlan0 proxd ftm 1 config options +initiator +no_scan_cache +one-way')
+        else:
+            self.initiator_dut.adb.shell('wl -i wlan0 proxd ftm 1 config options +initiator +randmac +auto-vhtack')
+        if ant_diversity:
+            self.initiator_dut.adb.shell('wl -i wlan0 proxd ftm 1 config options +ant_diversity')
+            self.initiator_dut.adb.shell('wl -i wlan0 proxd ftm 1 config ant_div_mode 1')
+        if channel < 13:
+            self.initiator_dut.adb.shell('wl -i wlan0 proxd ftm 1 config chanspec {}'.format(channel))
+        else:
+            self.initiator_dut.adb.shell('wl -i wlan0 proxd ftm 1 config chanspec {}/{}'.format(channel, bandwidth))
+        self.initiator_dut.adb.shell('wl -i wlan0 proxd ftm 1 config peer {}'.format(self.soft_ap_mac_address))
+        self.initiator_dut.adb.shell('wl -i wlan0 proxd ftm 1 config num-ftm {}'.format(no_meas_frames))
+        self.initiator_dut.adb.shell('wl -i wlan0 proxd ftm 1 start')
+        time.sleep(VERY_SHORT_SLEEP)
+        result = self.initiator_dut.adb.shell('wl -i wlan0 proxd ftm 1 result')
+        result = self.parse_11mc_ranging_result(result)
+        self.initiator_dut.adb.shell('wl -i wlan0 proxd ftm 1 delete')
+        return result
+
+    def run_single_11az_range(self, channel, bandwidth, no_meas_frames=8):
+        BW_MAPPING = {160: 5, 80: 2, 40: 1, 20: 0}
+        # result = self.initiator_dut.adb.shell('halutil -rtt -sta {} {} {} 0 3'.format(
+        #     self.soft_ap_mac_address, channel, BW_MAPPING[bandwidth]))
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm ntb 1 config chanspec {}/{}'.format(channel, bandwidth))
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm ntb 1 config peer {}'.format(self.soft_ap_mac_address))
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm ntb 1 config options +initiator')
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm ntb config min-delta 100ms')
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm ntb config max-delta 1s')
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm ntb config format-bw {}'.format(BW_MAPPING[bandwidth]))
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm ntb config num-meas {}'.format(no_meas_frames))
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm ntb config max-i2r-sts-leq-80 2')
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm ntb config max-r2i-sts-leq-80 2')
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm ntb config max-i2r-sts-gt-80 2')
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm ntb config max-r2i-sts-gt-80 2')
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm ntb config max-i2r-rep 0')
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm ntb config max-r2i-rep 0')
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm ntb config options -sec-ltf-supported')
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm ntb config options -sec-ltf-required')
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm 1 start')
+        time.sleep(no_meas_frames*VERY_SHORT_SLEEP)
+        result = self.initiator_dut.adb.shell('wl -i wlan0 ftm 1 result')
+        result = self.parse_11az_ranging_result(result)
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm 1 result')
+        self.initiator_dut.adb.shell('wl -i wlan0 ftm 1 delete')
+        return result
+
+
+    def measure_range(self, num_iterations, channel, bandwidth, no_meas_frames=8, ranging_method='11mc', ant_diversity=0, verbose = 1):
+        ranging_results = {'raw_results': [], 'compiled_results': {}, 'summary': {}}
+        try:
+            logging.info(self.check_soft_ap_status())
+        except:
+            logging.warning('Soft AP may have crashed.')
+        try:
+            association_status = self.initiator_dut.adb.shell('wl status')
+            logging.info(association_status)
+            if 'testftm' not in association_status:
+                logging.warning('Initiator DUT may have disconnected from AP')
+        except:
+            logging.warning('Initiator DUT may have disconnected from AP')
+        for idx in range(num_iterations):
+            try:
+                logging.debug(self.check_soft_ap_status())
+            except:
+                logging.debug('Soft AP may have crashed.')
+            if '11mc' in ranging_method:
+                one_sided = ('one_sided' in ranging_method)
+                result = self.run_single_11mc_range(channel, bandwidth, no_meas_frames, one_sided=one_sided, ant_diversity=ant_diversity)
+            elif ranging_method == '11az':
+                result = self.run_single_11az_range(channel, bandwidth, no_meas_frames)
+            ranging_results['raw_results'].append(result)
+            if verbose:
+                logging.info(result)
+        ranging_results['compiled_results']['distance'] = [x['avg_dist'] for x in ranging_results['raw_results']]
+        ranging_results['compiled_results']['std_dev'] = [x['std_deviation'] for x in ranging_results['raw_results']]
+        ranging_results['compiled_results']['rtt'] = [x['rtt'] for x in ranging_results['raw_results']]
+        ranging_results['compiled_results']['rssi'] = [x['rssi'] for x in ranging_results['raw_results']]
+
+        ranging_results['summary']['avg_distance'] = numpy.mean(ranging_results['compiled_results']['distance'])
+        ranging_results['summary']['std_dev_distance'] = numpy.std(ranging_results['compiled_results']['distance'])
+        ranging_results['summary']['avg_rtt'] = numpy.mean(ranging_results['compiled_results']['rtt'])
+        ranging_results['summary']['std_dev_rtt'] = numpy.std(ranging_results['compiled_results']['rtt'])
+        ranging_results['summary']['avg_rssi'] = numpy.mean(ranging_results['compiled_results']['rssi'])
+        ranging_results['summary']['std_dev_rssi'] = numpy.std(ranging_results['compiled_results']['rssi'])
+        return ranging_results
+
+    def parse_11mc_ranging_result(self, ranging_output):
+        pattern = r"(\w+)[ :=]+([-:.x\d]+)"
+        matches = re.findall(pattern, ranging_output, re.MULTILINE)
+        matches = dict(matches)
+        numerical_fields = ['sessionId', 'state', 'status','avg_dist', 'burst_duration', 'burst_num', 'valid_measure_cnt',
+                            'num_ftm', 'num_measurements', 'snr', 'bitflips','rtt', 'rssi', 'std_deviation']
+        for key in numerical_fields:
+            matches[key]=float(matches[key])
+        return matches
+
+    def parse_11az_ranging_result(self, ranging_output):
+        pattern = r"(\w+)[ :=]+([-:.x\d]+)"
+        matches = re.findall(pattern, ranging_output, re.MULTILINE)
+        matches = dict(matches)
+        # numerical_fields = ['burst_num', 'measurement_number', 'success_number', 'number_per_burst_peer',
+        #                     'status', 'retry_after_duration', 'type', 'rssi', 'rx_rate', 'rtt', 'rtt_sd', 'distance',
+        #                     'burst_duration', 'negotiated_burst_num', 'frequency', 'packet_bw',
+        #                     'i2r_tx_ltf_repetition_cnt', 'r2i_tx_ltf_repetition_cnt']
+        numerical_fields = ['id', 'status', 'state', 'rtt_mean', 'rtt_sd', 'distance', 'rssi_mean']
+        result = {}
+        for key in numerical_fields:
+            result[key] = float(matches[key])
+        result['avg_dist'] = result['distance']
+        result['std_deviation'] = result['rtt_sd']
+        result['rtt'] = result['rtt_mean']
+        result['rssi'] = result['rssi_mean']
+        return result
+
+    def cleanup_soft_ap(self):
+        """Cleans up the soft-AP interface"""
+        self.responder_dut.adb.shell('wl -i {} interface_remove'.format(self.soft_ap_interface))
+        self.responder_dut.adb.shell('wl scansuppress 0')
+
+    def teardown_ranging_link(self):
+        self.initiator_dut.adb.shell('wl -i wlan0 disassoc')
+        self.cleanup_soft_ap()
\ No newline at end of file
diff --git a/acts_tests/tests/OWNERS b/acts_tests/tests/OWNERS
index f780c718d..1f22d161c 100644
--- a/acts_tests/tests/OWNERS
+++ b/acts_tests/tests/OWNERS
@@ -9,11 +9,9 @@ ashutoshrsingh@google.com
 dvj@google.com
 gmoturu@google.com
 mrtyler@google.com
-codycaldwell@google.com
 chaoyangf@google.com
 wju@google.com
 albeed@google.com
-jethier@google.com
 
 # Pixel GTW
 jasonkmlu@google.com
@@ -28,17 +26,14 @@ mingchenchung@google.com
 
 
 # Fuchsia
-belgum@google.com
 chcl@google.com
 dhobsd@google.com
 haydennix@google.com
 jmbrenna@google.com
 nmccracken@google.com
 mnck@google.com
-nickchee@google.com
 sakuma@google.com
 silberst@google.com
-tturney@google.com
 sbalana@google.com
 
 # TechEng
@@ -50,4 +45,3 @@ yixiang@google.com
 oelayach@google.com
 qijiang@google.com
 sriramsundar@google.com
-xouyang@google.com
diff --git a/acts_tests/tests/google/wifi/RangingComparisonTest.py b/acts_tests/tests/google/wifi/RangingComparisonTest.py
new file mode 100644
index 000000000..f91fae240
--- /dev/null
+++ b/acts_tests/tests/google/wifi/RangingComparisonTest.py
@@ -0,0 +1,714 @@
+#!/usr/bin/env python3.8
+#
+#   Copyright 2024 - The Android Open Source Project
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
+import json
+import logging
+import numpy
+import pandas
+import os
+import re
+import subprocess
+import time
+from acts import asserts
+from acts import base_test
+from acts import context
+from acts import utils
+import acts_contrib.test_utils.bt.bt_test_utils as btutils
+from acts_contrib.test_utils.wifi import wifi_performance_test_utils as wputils
+from acts_contrib.test_utils.wifi import wifi_test_utils as wutils
+
+SHORT_SLEEP = 1
+MED_SLEEP = 5
+
+
+class UwbRangingLink(object):
+    def __init__(self, initiator, responder, uwb_ranging_params):
+        self.initiator_dut = initiator
+        self.responder_dut = responder
+        self.uwb_ranging_params = uwb_ranging_params
+        self.responder_dut.adb.shell('cmd uwb force-country-code enabled US')
+        self.initiator_dut.adb.shell('cmd uwb force-country-code enabled US')
+        self.responder_dut.adb.shell('cmd uwb enable-uwb')
+        self.initiator_dut.adb.shell('cmd uwb enable-uwb')
+        self.ANTENNA_MAPPING = {'ranging': 'none', 'patch': 'azimuth-only'}
+
+    def setup_initiator(self):
+        self.initiator_dut.adb.shell('cmd uwb start-fira-ranging-session '
+                                     '-i 1 -c {} -t controller -r initiator -a 11 -d 22 -e {} -j 3600000'.format(
+            self.uwb_ranging_params['channel'], self.ANTENNA_MAPPING[self.uwb_ranging_params['initiator_antenna']]))
+
+    def clean_up_initiator(self):
+        self.initiator_dut.adb.shell('cmd uwb stop-all-ranging-sessions')
+
+    def measure_range(self, duration):
+        self.responder_dut.adb.shell('cmd uwb start-fira-ranging-session '
+                                     '-i 1 -c {} -t controlee -r responder -a 22 -d 11 -e {} -j 3600000'.format(
+            self.uwb_ranging_params['channel'], self.ANTENNA_MAPPING[self.uwb_ranging_params['responder_antenna']]))
+        ranging_output = ''
+        for idx in range(int(duration/3)):
+            ranging_output = ranging_output + self.responder_dut.adb.shell('cmd uwb get-ranging-session-reports 1')
+            time.sleep(3)
+        self.responder_dut.adb.shell('cmd uwb stop-all-ranging-sessions')
+        logging.debug(ranging_output)
+        ranging_result = self.parse_ranging_result(ranging_output)
+        return ranging_result
+
+    def parse_ranging_result(self, ranging_output):
+        pattern = r"meters: ([\d.]+).*rssiDbm: (-?\d+)"
+        matches = re.findall(pattern, ranging_output)
+
+        measurements = []
+        for match in matches:
+            meters, rssiDbm = match
+            measurements.append({"distance": float(meters), "rssi": int(rssiDbm)})
+        distance_array = [result['distance'] for result in measurements]
+        rssi_array = [result['rssi'] for result in measurements]
+        avg_distance = numpy.mean(distance_array)
+        std_dev_distance = numpy.std(distance_array)
+        avg_rssi = numpy.mean(rssi_array)
+        std_dev_rssi = numpy.std(rssi_array)
+        result = {
+            'raw_results': measurements,
+            'compiled_results': {'distance' : distance_array, 'rssi': rssi_array},
+            'summary': {'avg_distance': avg_distance, 'avg_rssi': avg_rssi,
+                        'std_dev_distance': std_dev_distance, 'std_dev_rssi': std_dev_rssi,
+                        }
+        }
+        return result
+
+class BtRangingLinkV2(object):
+    def __init__(self, initiator, responder, bt_ranging_params):
+        # self.dut1 = self.android_devices[0]
+        # self.dut2 = self.android_devices[1]
+        self.initiator = initiator
+        self.reflector = responder
+        self.bt_ranging_params = bt_ranging_params
+        utils.sync_device_time(self.initiator)
+        utils.sync_device_time(self.reflector)
+        self.setup_devices()
+
+    def setup_devices(self):
+        self.reflector.adb.shell("cmd bluetooth_manager disable")
+        time.sleep(MED_SLEEP)
+        try:
+            self.reflector.adb.shell("rm data/misc/bluetooth/logs/cs_log*")
+        except:
+            logging.info('Could not delete CS logs')
+        self.reflector.adb.shell("cmd bluetooth_manager enable")
+        self.setprop_overwrite_default(self.reflector)
+        self.restart_app(self.reflector)
+        time.sleep(SHORT_SLEEP)
+        self.app_click_reflector(self.reflector)
+
+        self.initiator.adb.shell("cmd bluetooth_manager disable")
+        time.sleep(MED_SLEEP)
+        try:
+            self.initiator.adb.shell("rm data/misc/bluetooth/logs/cs_log*")
+        except:
+            logging.info('Could not delete CS logs')
+        self.initiator.adb.shell("cmd bluetooth_manager enable")
+        self.setprop_overwrite_default(self.initiator)
+    def restart_app(self, device):
+        device.ensure_screen_on()
+        device.unlock_screen()
+        device.adb.shell("am force-stop com.android.bluetooth.channelsoundingtestapp")
+        time.sleep(2)
+        device.adb.shell(
+            "am start -n com.android.bluetooth.channelsoundingtestapp/com.android.bluetooth.channelsoundingtestapp.MainActivity")
+
+    def app_click_reflector(self, device):
+        # step 1
+        filename_re = re.compile(r'([^ ]+.xml)')
+        #st = subprocess.check_output('adb -s {0} shell uiautomator dump'.format(device.serial), shell=True).decode('utf-8')
+        st = device.adb.shell('uiautomator dump')
+        filename_device = filename_re.findall(st)[0]
+        device.adb.pull('{} tmp.xml'.format(filename_device))
+        with open("tmp.xml", 'r') as f:
+            xml = f.read()
+
+        button_reflector = re.compile(
+            r'text="Reflector" resource-id="com.android.bluetooth.channelsoundingtestapp:id/button_reflector" class="android.widget.Button" package="com.android.bluetooth.channelsoundingtestapp" content-desc="" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="\[([0-9]*),([0-9]*)]\[([0-9]*),([0-9]*)\]"'
+        )
+        button_reflector_cord = self.get_cord(button_reflector, xml)
+
+        print("Push [Reflector] on reflector")
+        self.push_button(device,button_reflector_cord)
+        #device.adb.shell("input tap {} {}".format(button_reflector_cord[0], button_reflector_cord[1]))
+        time.sleep(0.5)
+
+        # step 2
+        filename_re = re.compile(r'([^ ]+.xml)')
+        #st = subprocess.check_output('adb -s {0} shell uiautomator dump'.format(device.serial), shell=True).decode('utf-8')
+        st = device.adb.shell('uiautomator dump')
+        filename_device = filename_re.findall(st)[0]
+        device.adb.pull('{} tmp.xml'.format(filename_device))
+        with open("tmp.xml", 'r') as f:
+            xml = f.read()
+
+        button_start_advertising = re.compile(
+            r'text="Start Advertising" resource-id="com.android.bluetooth.channelsoundingtestapp:id/btn_advertising" class="android.widget.Button" package="com.android.bluetooth.channelsoundingtestapp" content-desc="" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="\[([0-9]*),([0-9]*)]\[([0-9]*),([0-9]*)\]"'
+        )
+        button_start_advertising_cord = self.get_cord(button_start_advertising, xml)
+
+        print("Push [Start Advertising] on reflector")
+        self.push_button(device, button_start_advertising_cord)
+        #device.adb.shell("input tap {} {}".format(button_start_advertising_cord[0],
+        #                                                      button_start_advertising_cord[1]))
+        time.sleep(0.5)
+
+
+    def app_click_initiator(self, device, duration=10):
+        # step 1
+        filename_re = re.compile(r'([^ ]+.xml)')
+        st = device.adb.shell('uiautomator dump')
+        #st = subprocess.check_output('adb -s {0} shell uiautomator dump'.format(device.serial), shell=True).decode('utf-8')
+        filename_device = filename_re.findall(st)[0]
+        device.adb.pull('{} tmp.xml'.format(filename_device))
+        with open("tmp.xml", 'r') as f:
+            xml = f.read()
+
+        button_initiator = re.compile(
+            r'text="Initiator" resource-id="com.android.bluetooth.channelsoundingtestapp:id/button_initiator" class="android.widget.Button" package="com.android.bluetooth.channelsoundingtestapp" content-desc="" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="\[([0-9]*),([0-9]*)]\[([0-9]*),([0-9]*)\]"'
+        )
+        button_initiator_cord = self.get_cord(button_initiator, xml)
+
+        print("Push [Initiator] on initiator")
+        self.push_button(device, button_initiator_cord)
+        #device.adb.shell("input tap {} {}".format(button_initiator_cord[0], button_initiator_cord[1]))
+        time.sleep(0.5)
+
+        # step 2
+        filename_re = re.compile(r'([^ ]+.xml)')
+        st = device.adb.shell('uiautomator dump')
+        #st = subprocess.check_output('adb -s {0} shell uiautomator dump'.format(device.serial), shell=True).decode('utf-8')
+        filename_device = filename_re.findall(st)[0]
+        device.adb.pull('{} tmp.xml'.format(filename_device))
+        with open("tmp.xml", 'r') as f:
+            xml = f.read()
+
+        button_connect_gatt = re.compile(
+            r'text="Connect Gatt" resource-id="com.android.bluetooth.channelsoundingtestapp:id/btn_connect_gatt" class="android.widget.Button" package="com.android.bluetooth.channelsoundingtestapp" content-desc="" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="\[([0-9]*),([0-9]*)]\[([0-9]*),([0-9]*)\]"'
+        )
+        button_connect_gatt_cord = self.get_cord(button_connect_gatt, xml)
+
+        button_start_distance_measurement = re.compile(
+            r'text="Start Distance Measurement" resource-id="com.android.bluetooth.channelsoundingtestapp:id/btn_cs" class="android.widget.Button" package="com.android.bluetooth.channelsoundingtestapp" content-desc="" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="\[([0-9]*),([0-9]*)]\[([0-9]*),([0-9]*)\]"'
+        )
+        button_start_distance_measurement_cord = self.get_cord(button_start_distance_measurement, xml)
+
+        print("Push [Connect] on initiator")
+        self.push_button(device, button_connect_gatt_cord)
+        #device.adb.shell(
+        #    "input tap {} {}".format(button_connect_gatt_cord[0], button_connect_gatt_cord[1]))
+        time.sleep(MED_SLEEP)
+
+        print("Push [Start Distance Measurement] on initiator")
+        self.push_button(device, button_start_distance_measurement_cord)
+        #device.adb.shell("input tap {} {}".format(button_start_distance_measurement_cord[0],
+        #                                                      button_start_distance_measurement_cord[1]))
+        time.sleep(0.5)
+
+        # step 3
+        print('wait for {} seconds'.format(duration))
+        time.sleep(duration)
+
+        # if want infinite until button press
+        # _ = input("Press Enter to continue...")
+
+        print("Push [Stop Distance Measurement] on initiator")
+        self.push_button(device, button_start_distance_measurement_cord)
+        #device.adb.shell("input tap {} {}".format(button_start_distance_measurement_cord[0],
+        #                                                      button_start_distance_measurement_cord[1]))
+        time.sleep(0.5)
+
+
+    def get_cord(self, p, fi):
+        x1, y1, x2, y2 = p.findall(fi)[0]
+        cord = ((int(x1) + int(x2)) // 2, (int(y1) + int(y2)) // 2)
+        return cord
+
+
+    def push_button(self, device, button_cord):
+        device.ensure_screen_on()
+        time.sleep(SHORT_SLEEP)
+        device.adb.shell("input tap {0} {1}".format(button_cord[0], button_cord[1]))
+
+
+    def setprop_and_load_cal(self, device):
+        subprocess.run(["./cs_setprop.sh", device])
+        time.sleep(SHORT_SLEEP)
+        subprocess.run(["./load_cal_P24_zero.sh", device])
+        time.sleep(SHORT_SLEEP)
+
+
+    def setprop_overwrite_default(self, device):
+        device.adb.shell('setprop bluetooth.core.cs.channel_map 1FFFFFFFFFFFFC7FFFFC')
+        device.adb.shell('setprop bluetooth.core.cs.max_procedure_count 4')
+        device.adb.shell('setprop bluetooth.core.cs.max_subevent_len 2000000')
+
+
+    def unlock_device(self, device):
+        device.adb.shell("input keyevent 82")
+
+
+    def start_channel_sounding(self, init_device, refl_device):
+        self.app_click_reflector(refl_device)
+        self.app_click_initiator(init_device)
+
+    def parse_bt_cs_results(self, log_path):
+        measurements = []
+        with open(log_path,'r') as log:
+            for line in log:
+                if 'resultMeters' in line:
+                    range = float(line.split(' ')[1].rstrip().rstrip(','))
+                    if range == -1.976171:
+                        measurements.append(float('nan'))
+                    else:
+                        measurements.append(range)
+        avg_distance = numpy.mean(measurements)
+        std_dev_distance = numpy.std(measurements)
+        avg_rssi = 0
+        std_dev_rssi = 0
+        result = {
+            'measurements': measurements,
+            'summary': {'avg_distance': avg_distance, 'avg_rssi': avg_rssi,
+                        'std_dev_distance': std_dev_distance, 'std_dev_rssi': std_dev_rssi,
+                        }
+        }
+        return result
+
+    def collect_log_and_rename(self, device, test_name):
+        files = device.get_file_names("data/misc/bluetooth/logs")
+        log_folder = context.get_current_context().get_full_output_path() + "/cs_logs"
+        os.system("mkdir {0}".format(log_folder))
+        for filename in files:
+            if "cs_log" not in filename:
+                continue
+            log_path = context.get_current_context().get_full_output_path() + "/cs_logs/" + test_name + ".txt"
+            device.pull_files(filename, log_path)
+        return log_path
+    def do_channel_sounding(self, test_name="temp", duration=20):
+        self.initiator.adb.shell("cmd bluetooth_manager enable")
+
+        # App setup
+        self.restart_app(self.initiator)
+        time.sleep(SHORT_SLEEP)
+
+        self.app_click_initiator(self.initiator, duration)
+
+        # self.collect_log_and_rename(self.initiator, test_name=test_name)
+        log_filepath = "./{0}".format(test_name)
+        #adb("pull data/misc/bluetooth/logs {0}".format(log_filepath), device.serial)
+        #self.initiator.pull_files('data/misc/bluetooth/logs', log_filepath)
+
+        log_file_path = self.collect_log_and_rename(self.initiator, test_name=test_name)
+        result = self.parse_bt_cs_results(log_file_path)
+
+        self.initiator.adb.shell("cmd bluetooth_manager disable")
+        self.initiator.adb.shell("rm data/misc/bluetooth/logs/cs_log*")
+        return result
+
+class BtRangingLink(object):
+    def __init__(self, initiator, responder, bt_ranging_params):
+        # self.dut1 = self.android_devices[0]
+        # self.dut2 = self.android_devices[1]
+        self.initiator = initiator
+        self.reflector = responder
+        self.bt_ranging_params = bt_ranging_params
+        self.CSParameters = bt_ranging_params['CSParameters']
+        utils.sync_device_time(self.initiator)
+        utils.sync_device_time(self.reflector)
+        self.setup_devices()
+
+    def setup_devices(self):
+        # CS setprop
+        for dut in [self.initiator, self.reflector]:
+            self.cs_setprop(dut)
+            time.sleep(SHORT_SLEEP)
+            logging.info('Loading BT cal')
+            subprocess.call([self.bt_ranging_params['calibration_file'], dut.serial])
+            #self.load_cal(dut)
+            time.sleep(SHORT_SLEEP)
+            dut.button_cord = self.app_setup(dut)
+        time.sleep(MED_SLEEP)
+
+    def cs_setprop(self, dut):
+        logging.info("{0} setting CS prop ...".format(dut.serial))
+        for key in self.CSParameters:
+            dut.adb.shell("setprop bluetooth.core.cs.{0} {1}".format(key, self.CSParameters[key]))
+
+        ori_mask = dut.adb.getprop("persist.bluetooth.bqr.event_mask")
+        new_mask = (int(ori_mask) | 1)
+        dut.adb.shell("setprop persist.bluetooth.bqr.event_mask {0}".format(new_mask))
+        dut.adb.shell("setprop persist.bluetooth.bqr.min_interval_ms 500")
+
+        dut.adb.shell("touch data/misc/bluetooth/logs/cs_log_tmp.txt")
+        dut.adb.shell("cmd bluetooth_manager disable")
+        dut.adb.shell("cmd bluetooth_manager wait-for-state:STATE_OFF")
+        dut.adb.shell("rm data/misc/bluetooth/logs/cs_log*")
+        dut.adb.shell("cmd bluetooth_manager enable")
+
+        time.sleep(MED_SLEEP)
+
+    def load_cal(self, dut):
+        logging.info("{0} loading calibration file ...".format(dut.serial))
+        with open(self.bt_ranging_params['calibration_file'], 'r') as f:
+            for line in f:
+                if not line[0] == '#':
+                    dut.adb.shell("/vendor/bin/hw/hci_inject -c {0}".format(line))
+
+    def app_setup(self, dut):
+        logging.info("{0} restarting CS App ...".format(dut.serial))
+        dut.ensure_screen_on()
+        dut.unlock_screen()
+        self._restart_app(dut)
+
+        button_connect_gatt = re.compile(
+            r'text="Connect Gatt" resource-id="com.example.ble_test:id/btn_connect_gatt" class="android.widget.Button" package="com.example.ble_test" content-desc="" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="\[([0-9]*),([0-9]*)]\[([0-9]*),([0-9]*)\]"'
+        )
+        button_adv = re.compile(
+            r'text="Start Adv" resource-id="com.example.ble_test:id/btn_adv" class="android.widget.Button" package="com.example.ble_test" content-desc="" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="\[([0-9]*),([0-9]*)]\[([0-9]*),([0-9]*)\]"'
+        )
+        button_clear_log = re.compile(
+            r'text="Clear log" resource-id="com.example.ble_test:id/btn_clear_log" class="android.widget.Button" package="com.example.ble_test" content-desc="" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="\[([0-9]*),([0-9]*)]\[([0-9]*),([0-9]*)\]"'
+        )
+        button_cs = re.compile(
+            r'text="Start CS" resource-id="com.example.ble_test:id/btn_cs" class="android.widget.Button" package="com.example.ble_test" content-desc="" checkable="false" checked="false" clickable="true" enabled="true" focusable="true" focused="false" scrollable="false" long-clickable="false" password="false" selected="false" bounds="\[([0-9]*),([0-9]*)]\[([0-9]*),([0-9]*)\]"'
+        )
+
+        dut_xml = ""
+        filename_re = re.compile(r'([^ ]+.xml)')
+        st = subprocess.check_output('adb -s {0} shell uiautomator dump'.format(dut.serial), shell=True).decode('utf-8')
+        filename_device = filename_re.findall(st)[0]
+        dut.adb.pull("{0} tmp.xml".format(filename_device))
+        with open("tmp.xml", 'r') as f:
+            dut_xml = f.read()
+        connect_gatt_cord = self._get_cord(button_connect_gatt, dut_xml)
+        adv_cord = self._get_cord(button_adv, dut_xml)
+        clear_log_cord = self._get_cord(button_clear_log, dut_xml)
+        cs_cord = self._get_cord(button_cs, dut_xml)
+        button_cord = {"connect_gatt": connect_gatt_cord,
+                       "adv": adv_cord,
+                       "clear_log": clear_log_cord,
+                       "cs": cs_cord}
+
+        return button_cord
+
+    def collect_log_and_rename(self, device, test_name):
+        files = device.get_file_names("data/misc/bluetooth/logs")
+        log_folder = context.get_current_context().get_full_output_path() + "/cs_logs"
+        os.system("mkdir {0}".format(log_folder))
+        for filename in files:
+            if "cs_log" not in filename:
+                continue
+            log_path = context.get_current_context().get_full_output_path() + "/cs_logs/" + test_name + ".txt"
+            device.pull_files(filename, log_path)
+        return log_path
+
+    def collect_bt_metric(self, tag):
+        self._get_bt_link_metrics(self.initiator, duration=5, bqr_tag='Monitoring , Handle: 0x0040', tag=tag)
+        self._get_bt_link_metrics(self.reflector, duration=5, bqr_tag='Monitoring , Handle: 0x0040', tag=tag)
+
+
+    def start_advertising(self):
+        # Start CS
+        logging.info("Push [Start Adv] on reflector")
+        self._push_button(self.reflector, self.reflector.button_cord["adv"])
+        time.sleep(SHORT_SLEEP)
+
+    def parse_bt_cs_results(self, log_path):
+        measurements = []
+        with open(log_path,'r') as log:
+            for line in log:
+                if 'resultMeters' in line:
+                    range = float(line.split(' ')[1].rstrip())
+                    if range == -1.976171:
+                        measurements.append(float('nan'))
+                    else:
+                        measurements.append(range)
+        avg_distance = numpy.mean(measurements)
+        std_dev_distance = numpy.std(measurements)
+        avg_rssi = 0
+        std_dev_rssi = 0
+        result = {
+            'measurements': measurements,
+            'summary': {'avg_distance': avg_distance, 'avg_rssi': avg_rssi,
+                        'std_dev_distance': std_dev_distance, 'std_dev_rssi': std_dev_rssi,
+                        }
+        }
+        return result
+    def do_channel_sounding(self, test_name="cs_log_temp"):
+        self.cs_setprop(self.initiator)
+        self.initiator.button_cord = self.app_setup(self.initiator)
+
+        logging.info("Push [Connect Gatt] on initiator")
+        self._push_button(self.initiator, self.initiator.button_cord["connect_gatt"])
+        found = self._wait_for_keyword(self.initiator, "CYDBG: MTU changed to: 517", start_time=utils.get_current_epoch_time(), timeout=10)
+        time.sleep(MED_SLEEP)
+        if not found:
+            return False
+
+        logging.info("Push [Start CS] on initiator")
+        push_button_time = utils.get_current_epoch_time()
+        self._push_button(self.initiator, self.initiator.button_cord["cs"])
+
+        keyword_finish_procedures = "CYDBG: Add Node {0} with distance".format(self.CSParameters["max_procedure_count"])
+        timeout = self.CSParameters["max_procedure_count"] * self.CSParameters["min_procedure_interval"] *  self.CSParameters["conn_interval"] * 1.25 / 1000 * 1.5 # may need to adjust according to max_procedure_count
+        self._wait_for_keyword(self.initiator, keyword_finish_procedures, push_button_time, timeout)
+        time.sleep(MED_SLEEP)
+
+        log_file_path = self.collect_log_and_rename(self.initiator, test_name=test_name)
+        result = self.parse_bt_cs_results(log_file_path)
+        #self.log.info("Total Test run time: {0} s".format((utils.get_current_epoch_time() - self.begin_time)/1000.0))
+        return result
+
+    def _restart_app(self, device):
+        device.adb.shell("am force-stop com.example.ble_test")
+        time.sleep(2)
+        device.adb.shell("am start -n com.example.ble_test/com.example.ble_test.MainActivity")
+
+    def _restart_bt(self, device):
+        device.adb.shell("cmd bluetooth_manager disable")
+        device.adb.shell("cmd bluetooth_manager wait-for-state:STATE_OFF")
+        device.adb.shell("cmd bluetooth_manager enable")
+
+    def _get_cord(self, p, fi):
+        x1, y1, x2, y2 = p.findall(fi)[0]
+        cord = ((int(x1) + int(x2)) // 2, (int(y1) + int(y2)) // 2)
+        return cord
+
+    def _wait_for_keyword(self, dut, keyword, start_time, timeout=600):
+        wait = True
+        while wait:
+            if utils.get_current_epoch_time() - start_time > timeout * 1000:
+                logging.info("Wait for {0} timeout".format(keyword))
+                return False
+            time.sleep(0.5)
+            result = dut.search_logcat(keyword, start_time, utils.get_current_epoch_time())
+            if len(result) > 0:
+                wait = False
+                logging.info("Found \"{0}\" with wait time {1} s".format(keyword, (
+                            utils.get_current_epoch_time() - start_time) / 1000.0))
+                return True
+
+    def _push_button(self, dut, button_cord):
+        dut.ensure_screen_on()
+        #dut.unlock_screen()
+        time.sleep(SHORT_SLEEP)
+        dut.adb.shell("input tap {0} {1}".format(button_cord[0], button_cord[1]))
+
+    def _read_distance_from_logcat(self, logcat_filename):
+        distance_readout = []
+        counter_readout = []
+        with open(logcat_filename, 'r') as f:
+            for line in f:
+                if "---- Distance" in line:
+                    distance_readout.append(float(line.split()[-2]))
+                if "---- End of Procedure complete counter" in line:
+                    counter_readout.append(int(line.split()[-6].split(':')[-1]))
+
+        distance_readout = numpy.array(distance_readout)
+        counter_readout = numpy.array(counter_readout)
+
+        return counter_readout, distance_readout
+
+    def _get_bt_link_metrics(self, dut, duration=5, bqr_tag='Monitoring , Handle: 0x0040', tag=''):
+        """Get bt link metrics such as rssi and tx pwls.
+
+        Returns:
+            master_metrics_list: list of metrics of central device
+            slave_metrics_list: list of metric of peripheral device
+        """
+
+        self.raw_bt_metrics_path = os.path.join(context.get_current_context().get_full_output_path(),
+                                                'BT_Raw_Metrics')
+
+        # Get master rssi and power level
+        process_data_dict = btutils.get_bt_metric(
+            dut, duration=duration, bqr_tag=bqr_tag, tag=tag, log_path=self.raw_bt_metrics_path)
+        rssi_master = process_data_dict.get('rssi')
+        pwl_master = process_data_dict.get('pwlv')
+        rssi_c0_master = process_data_dict.get('rssi_c0')
+        rssi_c1_master = process_data_dict.get('rssi_c1')
+        txpw_c0_master = process_data_dict.get('txpw_c0')
+        txpw_c1_master = process_data_dict.get('txpw_c1')
+        bftx_master = process_data_dict.get('bftx')
+        divtx_master = process_data_dict.get('divtx')
+        linkquality_master = process_data_dict.get('linkquality')
+
+        condition = False
+        if condition:
+            rssi_slave = btutils.get_bt_rssi(self.bt_device,
+                                             tag=tag,
+                                             log_path=self.raw_bt_metrics_path)
+        else:
+            rssi_slave = None
+
+        master_metrics_list = [
+            rssi_master, pwl_master, rssi_c0_master, rssi_c1_master,
+            txpw_c0_master, txpw_c1_master, bftx_master, divtx_master, linkquality_master
+        ]
+        slave_metrics_list = [rssi_slave]
+
+        # rssi, pwlv, rssi_c0, rssi_c1, txpw_c0, txpw_c1, bftx, divtx
+
+        return master_metrics_list, slave_metrics_list
+
+
+class RangingComparisonTest(base_test.BaseTestClass):
+
+    def __init__(self, controllers):
+        base_test.BaseTestClass.__init__(self, controllers)
+
+    def setup_class(self):
+        """Initializes common test hardware and parameters.
+
+        This function initializes hardware and compiles parameters that are
+        common to all tests in this class.
+        """
+        self.duts = self.android_devices
+        req_params = [
+            'wifi_ranging_params', 'bt_ranging_params', 'uwb_ranging_params'
+        ]
+        self.unpack_userparams(req_params, [])
+
+        self.testclass_results = {}
+
+    def teardown_test(self):
+        self.process_testcase_result()
+
+    def teardown_class(self):
+        user_input = input('Please reconnect {} and press enter when done.'.format(self.duts[-1].serial))
+        time.sleep(MED_SLEEP)
+        self.duts[1].start_services()
+        if self.uwb_ranging_params['enabled']:
+            self.uwb_ranging_link.clean_up_initiator()
+        if self.wifi_ranging_params['11mc_config']['enabled'] or self.wifi_ranging_params['11az_config']['enabled']:
+            self.wifi_ranging_link.teardown_ranging_link()
+        for dev in self.android_devices:
+            wutils.wifi_toggle_state(dev, False)
+            dev.go_to_sleep()
+
+    def reset_remote_devices(self):
+        user_input = input('Ensure {} is connected and press enter when done.'.format(self.duts[-1].serial))
+        for dev in self.android_devices:
+            dev.reboot()
+        # Turn Wifi On
+        for dev in self.android_devices:
+            # self.log.info('Turning on airplane mode.')
+            # try:
+            #     asserts.assert_true(utils.force_airplane_mode(dev, True),
+            #                         'Can not turn on airplane mode.')
+            # except:
+            #     self.log.warning('Could not enable airplane mode!')
+            wutils.reset_wifi(dev)
+            wutils.wifi_toggle_state(dev, True)
+
+        if self.wifi_ranging_params['11mc_config']['enabled'] or self.wifi_ranging_params['11az_config']['enabled']:
+            self.log.info('Setting up WiFi ranging link.')
+            self.wifi_ranging_link = wputils.brcm_utils.RangingLink(self.duts[0], self.duts[1])
+            self.wifi_ranging_link.setup_ranging_link(self.wifi_ranging_params['channel'],
+                                                      self.wifi_ranging_params['bandwidth'],
+                                                      self.wifi_ranging_params['associate_initiator'],
+                                                      '11mc',
+                                                      self.wifi_ranging_params['11az_config']['enabled'])
+        if self.uwb_ranging_params['enabled']:
+            self.log.info('Setting up UWB ranging link')
+            self.uwb_ranging_link = UwbRangingLink(self.duts[1], self.duts[0], self.uwb_ranging_params)
+            self.uwb_ranging_link.clean_up_initiator()
+            self.uwb_ranging_link.setup_initiator()
+        if self.bt_ranging_params['enabled']:
+            self.log.info('Setting up BT ranging link')
+            self.bt_ranging_link = BtRangingLinkV2(self.duts[0], self.duts[1], self.bt_ranging_params)
+            #self.bt_ranging_link.setup_devices()
+            #self.bt_ranging_link.start_advertising()
+
+        # try:
+        #     self.wifi_ranging_link.teardown_ranging_link()
+        # except:
+        #     self.log.warning('Could not tear down wifi link')
+
+        self.duts[1].stop_services()
+        time.sleep(MED_SLEEP)
+        user_input = input('Disconnect {}, position for test, and press enter when done.'.format(self.duts[-1].serial))
+
+    def test_ranging(self):
+
+        self.test_results = collections.OrderedDict()
+        self.log.info('Starting ranging test.')
+        first_reset_needed = 1
+        while 1:
+            location = input('Enter location ID. Enter "Done" to stop the test: ')
+            if location == 'Done':
+                break
+            true_distance = input('Enter true distance (in meters) between devices: ')
+            if first_reset_needed or self.wifi_ranging_params['reset_devices']:
+                self.reset_remote_devices()
+                first_reset_needed = 0
+            location_result = collections.OrderedDict()
+            location_result['location_id'] = location
+            location_result['true_distance'] = true_distance
+            self.log.info('Starting ranging test at location {} with distance {}.'.format(location, true_distance))
+            if self.wifi_ranging_params['11mc_config']['enabled']:
+                self.log.info('Starting WiFi ranging test.')
+                wifi_11mc_ranging_result = self.wifi_ranging_link.measure_range(self.wifi_ranging_params['num_measurements'],
+                                                                           self.wifi_ranging_params['channel'],
+                                                                           self.wifi_ranging_params['11mc_config']['bandwidth'],
+                                                                           self.wifi_ranging_params['11mc_config']['num_frames'],
+                                                                           ranging_method='11mc',
+                                                                           ant_diversity=0)
+                self.log.info(wifi_11mc_ranging_result['summary'])
+                location_result['wifi_11mc_ranging_result'] = wifi_11mc_ranging_result
+                # wifi_11mc_ant_diversity_ranging_result = self.wifi_ranging_link.measure_range(self.wifi_ranging_params['num_measurements'],
+                #                                                            self.wifi_ranging_params['channel'],
+                #                                                            self.wifi_ranging_params['11mc_config']['bandwidth'],
+                #                                                            self.wifi_ranging_params['11mc_config']['num_frames'],
+                #                                                            ranging_method='11mc',
+                #                                                            ant_diversity=1)
+                # self.log.info(wifi_11mc_ant_diversity_ranging_result['summary'])
+                # location_result['wifi_11mc_ant_diversity_ranging_result'] = wifi_11mc_ant_diversity_ranging_result
+            if self.wifi_ranging_params['11az_config']['enabled']:
+                wifi_11az_ranging_result = self.wifi_ranging_link.measure_range(self.wifi_ranging_params['num_measurements'],
+                                                                           self.wifi_ranging_params['channel'],
+                                                                           self.wifi_ranging_params['11az_config']['bandwidth'],
+                                                                           self.wifi_ranging_params['11az_config']['num_frames'],
+                                                                           ranging_method='11az')
+                self.log.info(wifi_11az_ranging_result['summary'])
+                location_result['wifi_11az_ranging_result'] = wifi_11az_ranging_result
+            if self.uwb_ranging_params['enabled']:
+                self.log.info('Starting UWB ranging test.')
+                location_result['uwb_ranging_result'] = self.uwb_ranging_link.measure_range(
+                    duration=self.uwb_ranging_params['duration'])
+                self.log.info(location_result['uwb_ranging_result'])
+            if self.bt_ranging_params['enabled']:
+                self.log.info('Starting BT ranging test.')
+                location_result['bt_ranging_result'] = self.bt_ranging_link.do_channel_sounding(test_name=location)
+                self.log.info(location_result['bt_ranging_result']['summary'])
+            self.test_results[location] = location_result
+            results_file_path = os.path.join(
+                context.get_current_context().get_full_output_path(),
+                '{}.json'.format(self.current_test_name))
+            with open(results_file_path, 'w') as results_file:
+                json.dump(wputils.serialize_dict(self.test_results),
+                          results_file,
+                          indent=4)
+        return self.test_results
+
+
+
+    def process_testcase_result(self):
+        pass
\ No newline at end of file
diff --git a/acts_tests/tests/google/wifi/WifiRangingTest.py b/acts_tests/tests/google/wifi/WifiRangingTest.py
new file mode 100644
index 000000000..804696ca8
--- /dev/null
+++ b/acts_tests/tests/google/wifi/WifiRangingTest.py
@@ -0,0 +1,313 @@
+#!/usr/bin/env python3.8
+#
+#   Copyright 2024 - The Android Open Source Project
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
+import itertools
+import json
+import logging
+import numpy
+import pandas
+import os
+import time
+from acts import asserts
+from acts import base_test
+from acts import context
+from acts import utils
+from acts.metrics.loggers.blackbox import BlackboxMappedMetricLogger
+from acts_contrib.test_utils.wifi import delay_line
+from acts_contrib.test_utils.wifi import phase_shifter
+from acts_contrib.test_utils.wifi import wifi_performance_test_utils as wputils
+from acts_contrib.test_utils.wifi import wifi_retail_ap as retail_ap
+from acts_contrib.test_utils.wifi import wifi_test_utils as wutils
+from functools import partial
+from matplotlib import pyplot
+
+
+class WifiRangingTest(base_test.BaseTestClass):
+    """Class to test Wifi ranging.
+
+    This class implements Wifi ranging in a conducted setup with programmable
+    delay line. The class sets up the instruments, configures them, and characterizes
+    ranging performance over different multipath profiles.
+    """
+
+    def __init__(self, controllers):
+        base_test.BaseTestClass.__init__(self, controllers)
+        self.testcase_metric_logger = (
+            BlackboxMappedMetricLogger.for_test_case())
+        self.testclass_metric_logger = (
+            BlackboxMappedMetricLogger.for_test_class())
+        self.publish_testcase_metrics = True
+        #self.tests = self.generate_test_cases()
+
+    def setup_class(self):
+        """Initializes common test hardware and parameters.
+
+        This function initializes hardware and compiles parameters that are
+        common to all tests in this class.
+        """
+        self.duts = self.android_devices
+        req_params = [
+            'DelayLineInstruments', 'testbed_params', 'ranging_test_params'
+        ]
+        opt_params = ['RetailAccessPoints']
+        self.unpack_userparams(req_params, opt_params)
+        self.testclass_params = self.ranging_test_params
+        self.delay_lines = delay_line.create(self.DelayLineInstruments)
+        if hasattr(self, 'RetailAccessPoints'):
+            self.access_point = retail_ap.create(self.RetailAccessPoints)[0]
+        self.paths = []
+        for path in self.testbed_params['paths']:
+            self.paths.append({'delay_intrument': self.delay_lines[path['delay_instrument_index']],
+                               'attenuator': self.attenuators[path['attenuator_port']],
+                               'phase_shifter': phase_shifter.VaunixPhaseShifter() if path.get('phase_shifter', 0) else None
+                               })
+
+        # Turn Wifi On
+        for dev in self.android_devices:
+            if self.testclass_params.get('airplane_mode', 0):
+                self.log.info('Turning on airplane mode.')
+                asserts.assert_true(utils.force_airplane_mode(dev, True),
+                                    'Can not turn on airplane mode.')
+            wutils.reset_wifi(dev)
+            wutils.wifi_toggle_state(dev, True)
+        for atten in self.attenuators:
+            atten.set_atten(0)
+
+        self.testclass_results = {}
+
+    def teardown_test(self):
+        self.process_testcase_result(self.testclass_results[self.current_test_name])
+
+    def teardown_class(self):
+        # Turn WiFi OFF
+        if hasattr(self, 'access_point'):
+            self.access_point.teardown()
+        for dev in self.android_devices:
+            wutils.wifi_toggle_state(dev, False)
+            dev.go_to_sleep()
+    def _test_ranging(self, testcase_params):
+        testcase_params = self.compile_test_params(testcase_params)
+        ranging_link = wputils.brcm_utils.RangingLink(self.duts[0], self.duts[1])
+
+        ranging_link.setup_ranging_link(testcase_params['channel'],
+                                        testcase_params['bandwidth'],
+                                        self.testclass_params['associate_initiator'],
+                                        testcase_params['ranging_method'])
+        if testcase_params['channel'] in wutils.WifiEnums.channel_5G_to_freq:
+            testcase_params['swept_path']['phase_shifter'].set_frequency(
+                wutils.WifiEnums.channel_5G_to_freq[testcase_params['channel']])
+        else:
+            testcase_params['swept_path']['phase_shifter'].set_frequency(4000)
+        for path in self.paths:
+            if path == testcase_params['swept_path']:
+                continue
+            if not isinstance(path['delay_intrument'], delay_line.FixedDelayLine):
+                path['delay_intrument'].set_delay(self.testclass_params['fixed_path_delay'])
+            path['attenuator'].set_atten(self.testclass_params['fixed_path_attenuation'])
+
+        looped_phase = (self.testclass_params['swept_path_phase']['stop'] == -1)
+        if looped_phase:
+            testcase_params['swept_path']['phase_shifter'].start_phase_loop(
+                self.testclass_params['swept_path_phase']['step'],
+                self.testclass_params['swept_path_phase']['dwell_time'])
+        ranging_sweep_results = collections.OrderedDict()
+
+        for attenuation in testcase_params['attenuation_sweep']:
+            self.log.info(testcase_params['attenuation_sweep'])
+            self.log.info(testcase_params['delay_sweep'])
+            ranging_sweep_results[attenuation] = collections.OrderedDict()
+            for delay in testcase_params['delay_sweep']:
+                ranging_sweep_results[attenuation][delay] = collections.OrderedDict()
+                phase_sweep = [1] if looped_phase else testcase_params['phase_sweep']
+                for phase in phase_sweep:
+                    self.log.info('Swept Path Config: {}ns, {}dB, {}deg'.format(delay, attenuation, phase))
+                    testcase_params['swept_path']['delay_intrument'].set_delay(delay)
+                    testcase_params['swept_path']['attenuator'].set_atten(attenuation)
+                    testcase_params['swept_path']['phase_shifter'].set_phase(phase)
+                    result = ranging_link.measure_range(self.testclass_params['ranging_measurements'],
+                                                        testcase_params['channel'],
+                                                        testcase_params['bandwidth'],
+                                                        no_meas_frames=self.testclass_params['ftm_exchanges'],
+                                                        ranging_method=testcase_params['ranging_method'])
+                    self.log.info(result['summary'])
+                    ranging_sweep_results[attenuation][delay][phase] = result
+
+        if looped_phase:
+            testcase_params['swept_path']['phase_shifter'].stop_phase_loop()
+
+        ranging_link.teardown_ranging_link()
+        test_result = {}
+        test_result['testcase_params']=testcase_params
+        test_result['ranging_sweep_results'] = ranging_sweep_results
+        self.testclass_results[self.current_test_name] = test_result
+
+    def process_testcase_result(self, test_result):
+        results_file_path = os.path.join(
+            context.get_current_context().get_full_output_path(),
+            '{}.json'.format(self.current_test_name))
+        with open(results_file_path, 'w') as results_file:
+            json.dump(wputils.serialize_dict(test_result),
+                      results_file,
+                      indent=4)
+        compiled_sweep_results = {'distance': [],'std_dev_distance': [],
+                                  'rtt': [], 'std_dev_rtt': [],
+                                  'rssi': [], 'std_dev_rssi': [],
+                                  'std_dev': []}
+        for current_attenuation, attenuation_results in test_result['ranging_sweep_results'].items():
+            compiled_sweep_results['distance'].append([])
+            compiled_sweep_results['std_dev_distance'].append([])
+            compiled_sweep_results['rtt'].append([])
+            compiled_sweep_results['std_dev_rtt'].append([])
+            compiled_sweep_results['rssi'].append([])
+            compiled_sweep_results['std_dev_rssi'].append([])
+            for current_delay, delay_results in attenuation_results.items():
+                distance = numpy.mean([val['summary']['avg_distance'] for key, val in delay_results.items()])
+                std_dev_distance = numpy.mean([val['summary']['std_dev_distance'] for key, val in delay_results.items()])
+                rtt = numpy.mean([val['summary']['avg_rtt'] for key, val in delay_results.items()])
+                rssi = numpy.mean([val['summary']['avg_rssi'] for key, val in delay_results.items()])
+                std_dev_rtt = numpy.mean([val['summary']['std_dev_rtt'] for key, val in delay_results.items()])
+                std_dev_rssi = numpy.mean([val['summary']['std_dev_rssi'] for key, val in delay_results.items()])
+                compiled_sweep_results['distance'][-1].append(distance)
+                compiled_sweep_results['std_dev_distance'][-1].append(std_dev_distance)
+                compiled_sweep_results['rtt'][-1].append(rtt)
+                compiled_sweep_results['std_dev_rtt'][-1].append(std_dev_rtt)
+                compiled_sweep_results['rssi'][-1].append(rssi)
+                compiled_sweep_results['std_dev_rssi'][-1].append(std_dev_rssi)
+
+
+        self.plot_attenuation_delay_sweep_results(
+            test_result['testcase_params']['attenuation_sweep'],
+            test_result['testcase_params']['delay_sweep'],
+            compiled_sweep_results['distance'],
+            'distance')
+        self.plot_attenuation_delay_sweep_results(
+            test_result['testcase_params']['attenuation_sweep'],
+            test_result['testcase_params']['delay_sweep'],
+            compiled_sweep_results['std_dev_distance'],
+            'std_dev_distance')
+        self.plot_attenuation_delay_sweep_results(
+            test_result['testcase_params']['attenuation_sweep'],
+            test_result['testcase_params']['delay_sweep'],
+            compiled_sweep_results['rtt'],
+            'rtt')
+        self.plot_attenuation_delay_sweep_results(
+            test_result['testcase_params']['attenuation_sweep'],
+            test_result['testcase_params']['delay_sweep'],
+            compiled_sweep_results['std_dev_rtt'],
+            'std_dev_rtt')
+        self.plot_attenuation_delay_sweep_results(
+            test_result['testcase_params']['attenuation_sweep'],
+            test_result['testcase_params']['delay_sweep'],
+            compiled_sweep_results['rssi'],
+            'rssi')
+        self.plot_attenuation_delay_sweep_results(
+            test_result['testcase_params']['attenuation_sweep'],
+            test_result['testcase_params']['delay_sweep'],
+            compiled_sweep_results['std_dev_rssi'],
+            'std_dev_rssi')
+
+    def plot_attenuation_delay_sweep_results(self, row_axis_data, column_axis_data, plot_data, plot_name):
+        idx = pandas.Index(row_axis_data)
+        df = pandas.DataFrame(plot_data, index=idx, columns=column_axis_data)
+        results_file_name = '{} - {}.csv'.format(self.current_test_name, plot_name)
+        current_context = context.get_current_context().get_full_output_path()
+        results_file_path = os.path.join(current_context, results_file_name)
+        df.to_csv(results_file_path)
+        vals = numpy.around(df.values, 2)
+        norm = pyplot.Normalize(vals.min() - 1, vals.max() + 1)
+        colours = pyplot.cm.coolwarm(norm(vals))
+
+        fig = pyplot.figure(figsize=(15, 8))
+        ax = fig.add_subplot(111, frameon=True, xticks=[], yticks=[])
+
+        the_table = pyplot.table(cellText=vals, rowLabels=df.index, colLabels=df.columns,
+                                 colWidths=[0.03] * vals.shape[1], loc='center',
+                                 cellColours=colours)
+
+        results_file_name = '{} - {}.png'.format(self.current_test_name, plot_name)
+        current_context = context.get_current_context().get_full_output_path()
+        results_file_path = os.path.join(current_context, results_file_name)
+        pyplot.savefig(results_file_path, bbox_inches='tight')
+
+    def compile_test_params(self, testcase_params):
+        # tests to support are
+        #   * single path attenuation, delay sweep
+        #   * two path delay sweep (relative sweep)
+
+        # Pick first configurable-delay path as swept path
+        #for path in self.paths:
+        #    if not isinstance(path['delay_intrument'], delay_line.FixedDelayLine):
+        #        testcase_params['swept_path'] = path
+        #        break
+        testcase_params['swept_path'] = self.paths[testcase_params['swept_path_index']]
+        num_atten_steps = int(
+            (self.testclass_params['swept_path_attenuation']['stop'] - self.testclass_params['swept_path_attenuation']['start']) /
+            self.testclass_params['swept_path_attenuation']['step'])
+        testcase_params['attenuation_sweep'] = [
+            self.testclass_params['swept_path_attenuation']['start'] + x * self.testclass_params['swept_path_attenuation']['step']
+            for x in range(0, num_atten_steps)
+        ]
+        testcase_params['delay_sweep'] = numpy.arange(self.testclass_params['swept_path_delay']['start'],
+                                                      self.testclass_params['swept_path_delay']['stop'],
+                                                      self.testclass_params['swept_path_delay']['step'])
+        testcase_params['phase_sweep'] = numpy.arange(self.testclass_params['swept_path_phase']['start'],
+                                                      self.testclass_params['swept_path_phase']['stop'],
+                                                      self.testclass_params['swept_path_phase']['step'])
+        return testcase_params
+
+
+    def generate_test_cases(self, num_paths = 2, ranging_method = '11mc'):
+        """Function that auto-generates test cases for a test class."""
+        test_cases = []
+        test_configs = [{'channel': 6, 'bandwidth': 20},
+                        {'channel': 36, 'bandwidth': 20},
+                        {'channel': 36, 'bandwidth': 40},
+                        {'channel': 36, 'bandwidth': 80},
+                        {'channel': 36, 'bandwidth': 160},
+                        {'channel': 149, 'bandwidth': 20},
+                        {'channel': 149, 'bandwidth': 40},
+                        {'channel': 149, 'bandwidth': 80}]
+
+        for swept_path_index, test_config in itertools.product(range(num_paths), test_configs):
+            test_name = 'test_{}_path_ranging_swept_path_{}_ch{}_{}'.format(
+                num_paths, swept_path_index, test_config['channel'], test_config['bandwidth'])
+            test_params = collections.OrderedDict(
+                num_paths = num_paths,
+                swept_path_index = swept_path_index,
+                channel=test_config['channel'],
+                bandwidth=test_config['bandwidth'],
+                ranging_method = ranging_method
+            )
+            setattr(self, test_name, partial(self._test_ranging, test_params))
+            test_cases.append(test_name)
+        return test_cases
+
+
+class WifiRanging_11mc_Test(WifiRangingTest):
+    def __init__(self, controllers):
+        super().__init__(controllers)
+        self.tests = self.generate_test_cases(ranging_method = '11mc')
+
+class WifiRanging_OneSidedRtt_Test(WifiRangingTest):
+    def __init__(self, controllers):
+        super().__init__(controllers)
+        self.tests = self.generate_test_cases(ranging_method = '11mc_one_sided')
+
+class WifiRanging_11az_Test(WifiRangingTest):
+    def __init__(self, controllers):
+        super().__init__(controllers)
+        self.tests = self.generate_test_cases(ranging_method = '11az')
\ No newline at end of file
diff --git a/acts_tests/tests/google/wifi/WifiRssiTest.py b/acts_tests/tests/google/wifi/WifiRssiTest.py
index eb00327b6..47c2cd9b4 100644
--- a/acts_tests/tests/google/wifi/WifiRssiTest.py
+++ b/acts_tests/tests/google/wifi/WifiRssiTest.py
@@ -15,6 +15,7 @@
 #   limitations under the License.
 
 import collections
+import csv
 import itertools
 import json
 import logging
@@ -240,6 +241,7 @@ class WifiRssiTest(base_test.BaseTestClass):
              ('scan_rssi', {}),
              ('chain_0_rssi', {}),
              ('chain_1_rssi', {}),
+             ('reported_rssi', {}),
              ('total_attenuation', []),
              ('predicted_rssi', [])])
         # yapf: enable
@@ -321,6 +323,10 @@ class WifiRssiTest(base_test.BaseTestClass):
                         postprocessed_results['chain_1_rssi']['mean'],
                         'Chain 1 RSSI',
                         marker='circle')
+        figure.add_line(postprocessed_results['total_attenuation'],
+                        postprocessed_results['reported_rssi']['mean'],
+                        'Reported RSSI',
+                        marker='circle')
         figure.add_line(postprocessed_results['total_attenuation'],
                         postprocessed_results['predicted_rssi'],
                         'Predicted RSSI',
@@ -353,6 +359,7 @@ class WifiRssiTest(base_test.BaseTestClass):
              ('scan_rssi', []),
              ('chain_0_rssi', []),
              ('chain_1_rssi', []),
+             ('reported_rssi', []),
              ('predicted_rssi', [])])
         # yapf: enable
         for key, val in rssi_time_series.items():
@@ -395,7 +402,8 @@ class WifiRssiTest(base_test.BaseTestClass):
         Args:
             postprocessed_results: compiled arrays of RSSI data
         """
-        monitored_rssis = ['signal_poll_rssi', 'chain_0_rssi', 'chain_1_rssi']
+        monitored_rssis = ['signal_poll_rssi', 'chain_0_rssi', 'chain_1_rssi',
+                           'reported_rssi']
 
         rssi_dist = collections.OrderedDict()
         for rssi_key in monitored_rssis:
@@ -421,14 +429,9 @@ class WifiRssiTest(base_test.BaseTestClass):
                              primary_y_label='p(RSSI = x)',
                              secondary_y_label='p(RSSI <= x)')
         for rssi_key, rssi_data in rssi_dist.items():
-            figure.add_line(x_data=rssi_data['rssi_values'],
-                            y_data=rssi_data['rssi_pdf'],
-                            legend='{} PDF'.format(rssi_key),
-                            y_axis='default')
             figure.add_line(x_data=rssi_data['rssi_values'],
                             y_data=rssi_data['rssi_cdf'],
-                            legend='{} CDF'.format(rssi_key),
-                            y_axis='secondary')
+                            legend='{} CDF'.format(rssi_key))
         output_file_path = os.path.join(self.log_path,
                                         self.current_test_name + '_dist.html')
         figure.generate_figure(output_file_path)
@@ -565,6 +568,14 @@ class WifiRssiTest(base_test.BaseTestClass):
             self.dut.droid.wakeLockAcquireDim()
         else:
             self.dut.go_to_sleep()
+        tune_code = None
+        if 'tune_code' in testcase_params:
+            tune_code= testcase_params['tune_code']
+        elif 'tune_code' in self.testbed_params and int(self.testbed_params['tune_code']['manual_tune_code']):
+            tune_code = self.testbed_params['tune_code'][testcase_params['band']]
+        if tune_code:
+            self.log.info('Forcing antenna tune code.')
+            wputils.write_antenna_tune_code(self.dut, tune_code, readback_check=False)
         if wputils.validate_network(self.dut,
                                     testcase_params['test_network']['SSID']):
             self.log.info('Already connected to desired network')
@@ -1111,3 +1122,51 @@ class WifiOtaRssi_TenDegree_Test(WifiOtaRssiTest):
                                               ['ActiveTraffic'],
                                               ['orientation'],
                                               list(range(0, 360, 10)))
+
+class WifiOtaRssi_TuneCodeSweep_Test(WifiOtaRssiTest):
+
+    def __init__(self, controllers):
+        WifiRssiTest.__init__(self, controllers)
+        self.tests = self.generate_test_cases('test_rssi_variation',
+                                              [6, 36, 149, '6g37'],
+                                              ['bw20', 'bw80', 'bw160'],
+                                              ['ActiveTraffic'],
+                                              'StirrersOn', 0)
+
+    def generate_test_cases(self, test_type, channels, modes, traffic_modes,
+                            chamber_mode, orientation):
+        test_cases = []
+        allowed_configs = {
+            20: [
+                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 64, 100,
+                116, 132, 140, 149, 153, 157, 161, '6g37', '6g117', '6g213'
+            ],
+            40: [36, 44, 100, 149, 157, '6g37', '6g117', '6g213'],
+            80: [36, 100, 149, '6g37', '6g117', '6g213'],
+            160: [36, '6g37', '6g117', '6g213']
+        }
+        with open(self.user_params['testbed_params']['tune_code_file'],
+                  'r') as csvfile:
+            tune_code_configs = csv.DictReader(csvfile)
+            for (tune_code_config, channel, mode, traffic,
+                 ) in itertools.product(tune_code_configs, channels, modes, traffic_modes,
+
+                                                 ):
+                bandwidth = int(''.join([x for x in mode if x.isdigit()]))
+                if channel not in allowed_configs[bandwidth]:
+                    continue
+                test_name = test_type + '_ch{}_{}_{}_tc_{}'.format(
+                    channel, mode, traffic, tune_code_config['band'])
+                testcase_params = collections.OrderedDict(
+                    channel=channel,
+                    mode=mode,
+                    active_traffic=(traffic == 'ActiveTraffic'),
+                    traffic_type=self.user_params['rssi_test_params']
+                    ['traffic_type'],
+                    chamber_mode=chamber_mode,
+                    orientation=orientation,
+                    tune_code = tune_code_config)
+                test_function = self._test_ota_rssi
+                setattr(self, test_name, partial(test_function, testcase_params))
+                test_cases.append(test_name)
+        return test_cases
\ No newline at end of file
diff --git a/acts_tests/tests/google/wifi/WifiSoftApTest.py b/acts_tests/tests/google/wifi/WifiSoftApTest.py
index 211562dcf..1ab900fe2 100644
--- a/acts_tests/tests/google/wifi/WifiSoftApTest.py
+++ b/acts_tests/tests/google/wifi/WifiSoftApTest.py
@@ -33,6 +33,7 @@ WIFI_CONFIG_APBAND_AUTO = WifiEnums.WIFI_CONFIG_APBAND_AUTO
 WPA3_SAE_TRANSITION_SOFTAP = WifiEnums.SoftApSecurityType.WPA3_SAE_TRANSITION
 WPA3_SAE_SOFTAP = WifiEnums.SoftApSecurityType.WPA3_SAE
 WAIT_AFTER_REBOOT = 10
+WAIT_AFTER_SOFTAP_RESUME = 10
 
 
 class WifiSoftApTest(WifiBaseTest):
@@ -289,6 +290,7 @@ class WifiSoftApTest(WifiBaseTest):
         self.dut.reboot()
         time.sleep(WAIT_AFTER_REBOOT)
         wutils.start_wifi_tethering_saved_config(self.dut)
+        time.sleep(WAIT_AFTER_SOFTAP_RESUME)
         wutils.connect_to_wifi_network(self.dut_client, config, hidden=hidden)
 
     """ Tests Begin """
diff --git a/acts_tests/tests/google/wifi/WifiStaApConcurrencyTest.py b/acts_tests/tests/google/wifi/WifiStaApConcurrencyTest.py
index 5e408f56f..4eaa91598 100644
--- a/acts_tests/tests/google/wifi/WifiStaApConcurrencyTest.py
+++ b/acts_tests/tests/google/wifi/WifiStaApConcurrencyTest.py
@@ -320,7 +320,7 @@ class WifiStaApConcurrencyTest(WifiBaseTest):
         Switch DUT SoftAp to 5G band if currently in 2G.
         Switch DUT SoftAp to 2G band if currently in 5G.
         """
-        wlan1_freq = int(self.get_wlan1_status(self.dut)['freq'])
+        wlan1_freq = int(self.get_sap_interface_status(self.dut)['freq'])
         if wlan1_freq in wutils.WifiEnums.ALL_5G_FREQUENCIES:
             band = WIFI_CONFIG_APBAND_2G
         elif wlan1_freq in wutils.WifiEnums.ALL_2G_FREQUENCIES:
@@ -328,12 +328,15 @@ class WifiStaApConcurrencyTest(WifiBaseTest):
         wutils.stop_wifi_tethering(ad)
         self.start_softap_and_verify(band)
 
-    def get_wlan1_status(self, ad):
-        """ get wlan1 interface status"""
-        get_wlan1 = 'hostapd_cli status'
-        out_wlan1 = ad.adb.shell(get_wlan1)
-        out_wlan1 = dict(re.findall(r'(\S+)=(".*?"|\S+)', out_wlan1))
-        return out_wlan1
+    def get_sap_interface_status(self, ad):
+        """ get SAP interface status"""
+        sap_interface = "wlan1"
+        if self.dut.model in self.dbs_supported_models:
+            sap_interface = "wlan2"
+        get_sap_interface_status = f"hostapd_cli -p /data/vendor/wifi/hostapd/ctrl -i {sap_interface} status"
+        out_sap_interface_status = ad.adb.shell(get_sap_interface_status)
+        out_sap_interface_status = dict(re.findall(r'(\S+)=(".*?"|\S+)', out_sap_interface_status))
+        return out_sap_interface_status
 
     def enable_mobile_data(self, ad):
         """Make sure that cell data is enabled if there is a sim present."""
diff --git a/acts_tests/tests/google/wifi/WifiStressTest.py b/acts_tests/tests/google/wifi/WifiStressTest.py
index 098ce400f..8a7663deb 100644
--- a/acts_tests/tests/google/wifi/WifiStressTest.py
+++ b/acts_tests/tests/google/wifi/WifiStressTest.py
@@ -422,7 +422,7 @@ class WifiStressTest(WifiBaseTest):
             "https://www.youtube.com/watch?v=WNCl-69POro",
             "https://www.youtube.com/watch?v=dVkK36KOcqs",
             "https://www.youtube.com/watch?v=0wCC3aLXdOw",
-            "https://www.youtube.com/watch?v=QpyGNwnEmKo",
+            "https://www.youtube.com/watch?v=rN6nlNC9WQA",
             "https://www.youtube.com/watch?v=RK1K2bCg4J8"
         ]
         try:
diff --git a/acts_tests/tests/google/wifi/WifiTxPowerCheckTest.py b/acts_tests/tests/google/wifi/WifiTxPowerCheckTest.py
index d0a333479..6e68c5980 100644
--- a/acts_tests/tests/google/wifi/WifiTxPowerCheckTest.py
+++ b/acts_tests/tests/google/wifi/WifiTxPowerCheckTest.py
@@ -136,8 +136,14 @@ class WifiTxPowerCheckTest(base_test.BaseTestClass):
                              "Failed to enable WiFi verbose logging.")
 
         # decode nvram
-        self.nvram_sar_data = self.read_nvram_sar_data()
-        self.csv_sar_data = self.read_sar_csv(self.testclass_params['sar_csv'])
+        try:
+            self.nvram_sar_data = self.read_nvram_sar_data()
+        except:
+            self.nvram_sar_data = None
+        if 'sar_csv' in self.testclass_params:
+            self.csv_sar_data = self.read_sar_csv(self.testclass_params['sar_csv'])
+        else:
+            self.csv_sar_data = None
 
         # Configure test retries
         self.user_params['retry_tests'] = [self.__class__.__name__]
@@ -372,7 +378,10 @@ class WifiTxPowerCheckTest(base_test.BaseTestClass):
             testcase_params['sar_state']]['brcm_index'][0], current_band,
                       'mimo', self.sar_state_mapping[
                           testcase_params['sar_state']]['brcm_index'][1])
-        sar_powers = self.nvram_sar_data[sar_config][sub_band_idx - 1]
+        if self.nvram_sar_data:
+            sar_powers = self.nvram_sar_data[sar_config][sub_band_idx - 1]
+        else:
+            sar_powers = [float('nan'), float('nan')]
         return sar_config, sar_powers
 
     def get_sar_power_from_csv(self, testcase_params):
@@ -403,12 +412,15 @@ class WifiTxPowerCheckTest(base_test.BaseTestClass):
                 sub_band_idx = band[1]
                 break
         sar_config = (reg_domain, 'mimo', current_band)
-        sar_powers = [
-            self.csv_sar_data[testcase_params['sar_state']]['SAR Powers']
-            [sar_config][0][sub_band_idx - 1],
-            self.csv_sar_data[testcase_params['sar_state']]['SAR Powers']
-            [sar_config][1][sub_band_idx - 1]
-        ]
+        if self.csv_sar_data:
+            sar_powers = [
+                self.csv_sar_data[testcase_params['sar_state']]['SAR Powers']
+                [sar_config][0][sub_band_idx - 1],
+                self.csv_sar_data[testcase_params['sar_state']]['SAR Powers']
+                [sar_config][1][sub_band_idx - 1]
+            ]
+        else:
+            sar_powers = [float('nan'), float('nan')]
         return sar_config, sar_powers
 
     def process_wl_curpower(self, wl_curpower_file, testcase_params):
@@ -971,7 +983,7 @@ class WifiTxPowerCheck_BasicSAR_Test(WifiTxPowerCheckTest):
         self.tests = self.generate_test_cases(
             ap_power='standard',
             channels=[6, 36, 52, 100, 149, '6g37'],
-            modes=['bw20', 'bw160'],
+            modes=['bw20', 'bw80', 'bw160'],
             test_types=[
                 'test_tx_power',
             ],
```

