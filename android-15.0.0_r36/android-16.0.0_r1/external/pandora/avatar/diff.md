```diff
diff --git a/.github/workflows/avatar.yml b/.github/workflows/avatar.yml
index 21945ef..46eb14e 100644
--- a/.github/workflows/avatar.yml
+++ b/.github/workflows/avatar.yml
@@ -79,7 +79,7 @@ jobs:
       - name: Install
         run: |
           pip install --upgrade pip
-          pip install rootcanal==1.3.0
+          pip install rootcanal==1.10.0
           pip install .
       - name: Rootcanal
         run: nohup python -m rootcanal > rootcanal.log &
diff --git a/OWNERS b/OWNERS
index 20a7f4a..0cab446 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 girardier@google.com
 charliebout@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/avatar/__init__.py b/avatar/__init__.py
index abc4653..5066965 100644
--- a/avatar/__init__.py
+++ b/avatar/__init__.py
@@ -17,7 +17,7 @@ Avatar is a scalable multi-platform Bluetooth testing tool capable of running
 any Bluetooth test cases virtually and physically.
 """
 
-__version__ = "0.0.4"
+__version__ = "0.0.10"
 
 import argparse
 import enum
@@ -27,6 +27,7 @@ import grpc.aio
 import importlib
 import logging
 import pathlib
+import re
 
 from avatar import pandora_server
 from avatar.aio import asynchronous
@@ -42,6 +43,7 @@ from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Size
 # public symbols
 __all__ = [
     'asynchronous',
+    'enableFlag',
     'parameterized',
     'rpc_except',
     'PandoraDevices',
@@ -54,6 +56,7 @@ PANDORA_COMMON_SERVER_CLASSES: Dict[str, Type[pandora_server.PandoraServer[Any]]
     'PandoraDevice': pandora_server.PandoraServer,
     'AndroidDevice': pandora_server.AndroidPandoraServer,
     'BumbleDevice': pandora_server.BumblePandoraServer,
+    'UsbDevice': pandora_server.UsbBumblePandoraServer,
 }
 
 KEY_PANDORA_SERVER_CLASS = 'pandora_server_class'
@@ -205,6 +208,73 @@ def parameterized(*inputs: Tuple[Any, ...]) -> Type[Wrapper]:
     return wrapper
 
 
+def enableFlag(flag: str) -> Callable[..., Any]:
+    """Enable aconfig flag.
+
+    Requires that the test class declares a devices: Optional[PandoraDevices] attribute.
+
+    Args:
+        flag: aconfig flag name including package, e.g.: 'com.android.bluetooth.flags.<flag_name>'
+
+    Raises:
+        AttributeError: when the 'devices' attribute is not found or not set
+        TypeError: when the provided flag argument is not a string
+    """
+
+    def getFlagValue(server: PandoraServer[Any], flag: str) -> str:
+        cmd_output = server.device.adb.shell(f'aflags list -c com.android.bt | grep {flag}').decode().split('\n')
+        cmd_output = [x for x in cmd_output if x] # Filter out empty lines from shell result
+        if len(cmd_output) == 0:
+            raise signals.TestError(f'Flag [{flag}] is not present in the aflags list of the device')
+        if len(cmd_output) != 1:
+            raise signals.TestError(f'Flag [{flag}] has multiple entries in the aflags list of the device. Output was {cmd_output}')
+        return cmd_output[0]
+
+    def isFlagEnabled(server: PandoraServer[Any], flag: str) -> bool:
+        return bool(re.search(flag + '.* enabled', getFlagValue(server, flag)))
+
+    # A "valid" flag is either already enabled or writable
+    def isFlagValidForTest(server: PandoraServer[Any], flag: str) -> bool:
+        return bool(re.search(flag + '.* (enabled|read-write)', getFlagValue(server, flag)))
+
+    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
+        @functools.wraps(func)
+        def wrapper(self: base_test.BaseTestClass, *args: Any, **kwargs: Any) -> Any:
+            devices = getattr(self, 'devices', None)
+
+            if not devices:
+                raise AttributeError("Attribute 'devices' not found in test class or is None")
+
+            if not isinstance(devices, PandoraDevices):
+                raise TypeError("devices attribute must be of a PandoraDevices type")
+
+            listOfServerToRestoreFlag: List[PandoraServer[Any]] = []
+
+            for server in devices._servers:
+                if isinstance(server, pandora_server.AndroidPandoraServer):
+                    if not isFlagValidForTest(server, flag):
+                        raise signals.TestSkip('Flag cannot be enabled on this device')
+                    if isFlagEnabled(server, flag):
+                        continue # Nothing to do flag is already active
+                    server.device.adb.shell(f'aflags enable --immediate {flag}')  # type: ignore
+                    if not isFlagEnabled(server, flag):
+                        raise signals.TestError('Despite writable flag, runner couldn\'t enable it')
+                    listOfServerToRestoreFlag.append(server)
+
+            result = func(self, *args, **kwargs)
+
+            for server in listOfServerToRestoreFlag:
+                server.device.adb.shell(f'aflags unset --immediate {flag}')  # type: ignore
+                if isFlagEnabled(server, flag):
+                    raise signals.TestError('Despite writable flag, runner couldn\'t reset its initial value')
+
+            return result
+
+        return wrapper
+
+    return decorator
+
+
 _T = TypeVar('_T')
 
 
diff --git a/avatar/cases/le_host_test.py b/avatar/cases/le_host_test.py
index b6ab4aa..7070dcb 100644
--- a/avatar/cases/le_host_test.py
+++ b/avatar/cases/le_host_test.py
@@ -30,11 +30,16 @@ from mobly.asserts import assert_false  # type: ignore
 from mobly.asserts import assert_is_not_none  # type: ignore
 from mobly.asserts import assert_true  # type: ignore
 from mobly.asserts import explicit_pass  # type: ignore
+from pandora.host_pb2 import PRIMARY_1M
+from pandora.host_pb2 import PRIMARY_CODED
 from pandora.host_pb2 import PUBLIC
 from pandora.host_pb2 import RANDOM
+from pandora.host_pb2 import SECONDARY_1M
+from pandora.host_pb2 import SECONDARY_CODED
 from pandora.host_pb2 import Connection
 from pandora.host_pb2 import DataTypes
 from pandora.host_pb2 import OwnAddressType
+from pandora.host_pb2 import PrimaryPhy
 from typing import Any, Dict, Literal, Optional, Union
 
 
@@ -58,9 +63,12 @@ class LeHostTest(base_test.BaseTestClass):  # type: ignore[misc]
     dut: PandoraDevice
     ref: PandoraDevice
 
+    scan_timeout: float
+
     def setup_class(self) -> None:
         self.devices = PandoraDevices(self)
         self.dut, self.ref, *_ = self.devices
+        self.scan_timeout = float(self.user_params.get('scan_timeout') or 15.0)  # type: ignore
 
         # Enable BR/EDR mode for Bumble devices.
         for device in self.devices:
@@ -113,8 +121,7 @@ class LeHostTest(base_test.BaseTestClass):  # type: ignore[misc]
             own_address_type=PUBLIC,
         )
 
-        scan = self.dut.host.Scan(legacy=False, passive=False, timeout=5.0)
-        report = next((x for x in scan if x.public == self.ref.address))
+        scan = self.dut.host.Scan(legacy=False, passive=False, timeout=self.scan_timeout)
         try:
             report = next((x for x in scan if x.public == self.ref.address))
 
@@ -138,6 +145,85 @@ class LeHostTest(base_test.BaseTestClass):  # type: ignore[misc]
             scan.cancel()
             advertise.cancel()
 
+    @avatar.parameterized(
+        *itertools.product(
+            # The advertisement cannot be both connectable and scannable.
+            ('connectable', 'non_connectable', 'non_connectable_scannable'),
+            ('directed', 'undirected'),
+            # Bumble does not send multiple HCI commands, so it must also fit in
+            # 1 HCI command (max length 251 minus overhead).
+            (0, 150),
+            (PRIMARY_1M, PRIMARY_CODED),
+        ),
+    )  # type: ignore[misc]
+    def test_extended_scan(
+        self,
+        connectable_scannable: Union[
+            Literal['connectable'], Literal['non_connectable'], Literal['non_connectable_scannable']
+        ],
+        directed: Union[Literal['directed'], Literal['undirected']],
+        data_len: int,
+        primary_phy: PrimaryPhy,
+    ) -> None:
+        '''
+        Advertise from the REF device with the specified extended advertising
+        event properties. Use the manufacturer specific data to pad the advertising data to the
+        desired length. The scan response data must always be provided when
+        scannable.
+        '''
+        man_specific_data_length = max(0, data_len - 5)  # Flags (3) + LV (2)
+        man_specific_data = bytes([random.randint(1, 255) for _ in range(man_specific_data_length)])
+        data = DataTypes(manufacturer_specific_data=man_specific_data) if data_len > 0 else None
+        scan_response_data = None
+        # Extended advertisements with advertising data cannot also have
+        # scan response data.
+        if connectable_scannable == 'non_connectable_scannable':
+            scan_response_data = data
+            data = None
+
+        is_connectable = True if connectable_scannable == 'connectable' else False
+        target = self.dut.address if directed == 'directed' else None
+
+        # For a better test, make the secondary phy the same as the primary to
+        # avoid the scan just scanning the 1M advertisement when the primary
+        # phy is CODED.
+        secondary_phy = SECONDARY_1M
+        if primary_phy == PRIMARY_CODED:
+            secondary_phy = SECONDARY_CODED
+
+        advertise = self.ref.host.Advertise(
+            legacy=False,
+            connectable=is_connectable,
+            data=data,  # type: ignore[arg-type]
+            scan_response_data=scan_response_data,  # type: ignore[arg-type]
+            public=target,
+            own_address_type=PUBLIC,
+            primary_phy=primary_phy,
+            secondary_phy=secondary_phy,
+        )
+
+        scan = self.dut.host.Scan(
+            legacy=False,
+            passive=False,
+            timeout=self.scan_timeout,
+            phys=[primary_phy],
+        )
+        try:
+            report = next((x for x in scan if x.public == self.ref.address))
+
+            # TODO: scannable is not set by the android server
+            # TODO: direct_address is not set by the android server
+            assert_false(report.legacy, msg='expected extended advertising report')
+            assert_equal(report.connectable, is_connectable)
+            assert_equal(report.data.manufacturer_specific_data, man_specific_data)
+            assert_false(report.truncated, msg='expected non-truncated advertising report')
+            assert_equal(report.primary_phy, primary_phy)
+        except grpc.aio.AioRpcError as e:
+            raise e
+        finally:
+            scan.cancel()
+            advertise.cancel()
+
     @avatar.parameterized(
         (dict(incomplete_service_class_uuids16=["183A", "181F"]),),
         (dict(incomplete_service_class_uuids32=["FFFF183A", "FFFF181F"]),),
@@ -173,7 +259,7 @@ class LeHostTest(base_test.BaseTestClass):  # type: ignore[misc]
             own_address_type=PUBLIC,
         )
 
-        scan = self.dut.host.Scan(legacy=False, passive=False)
+        scan = self.dut.host.Scan(legacy=False, passive=False, timeout=self.scan_timeout)
         report = next((x for x in scan if x.public == self.ref.address))
 
         scan.cancel()
@@ -198,13 +284,13 @@ class LeHostTest(base_test.BaseTestClass):  # type: ignore[misc]
             data=DataTypes(manufacturer_specific_data=b'pause cafe'),
         )
 
-        scan = self.dut.aio.host.Scan(own_address_type=RANDOM)
+        scan = self.dut.aio.host.Scan(own_address_type=RANDOM, timeout=self.scan_timeout)
         ref = await anext((x async for x in scan if x.data.manufacturer_specific_data == b'pause cafe'))
         scan.cancel()
 
         ref_dut_res, dut_ref_res = await asyncio.gather(
             anext(aiter(advertise)),
-            self.dut.aio.host.ConnectLE(**ref.address_asdict(), own_address_type=RANDOM),
+            self.dut.aio.host.ConnectLE(**ref.address_asdict(), own_address_type=RANDOM, timeout=self.scan_timeout),
         )
         assert_equal(dut_ref_res.result_variant(), 'connection')
         dut_ref, ref_dut = dut_ref_res.connection, ref_dut_res.connection
@@ -226,13 +312,13 @@ class LeHostTest(base_test.BaseTestClass):  # type: ignore[misc]
             data=DataTypes(manufacturer_specific_data=b'pause cafe'),
         )
 
-        scan = self.dut.aio.host.Scan(own_address_type=RANDOM)
+        scan = self.dut.aio.host.Scan(own_address_type=RANDOM, timeout=self.scan_timeout)
         ref = await anext((x async for x in scan if x.data.manufacturer_specific_data == b'pause cafe'))
         scan.cancel()
 
         ref_dut_res, dut_ref_res = await asyncio.gather(
             anext(aiter(advertise)),
-            self.dut.aio.host.ConnectLE(**ref.address_asdict(), own_address_type=RANDOM),
+            self.dut.aio.host.ConnectLE(**ref.address_asdict(), own_address_type=RANDOM, timeout=self.scan_timeout),
         )
         assert_equal(dut_ref_res.result_variant(), 'connection')
         dut_ref, ref_dut = dut_ref_res.connection, ref_dut_res.connection
diff --git a/avatar/cases/le_security_test.py b/avatar/cases/le_security_test.py
index b91d8c7..d8495e9 100644
--- a/avatar/cases/le_security_test.py
+++ b/avatar/cases/le_security_test.py
@@ -20,7 +20,7 @@ import logging
 from avatar import BumblePandoraDevice
 from avatar import PandoraDevice
 from avatar import PandoraDevices
-from avatar import pandora
+from avatar import pandora_snippet
 from bumble.pairing import PairingConfig
 from bumble.pairing import PairingDelegate
 from mobly import base_test
@@ -226,7 +226,7 @@ class LeSecurityTest(base_test.BaseTestClass):  # type: ignore[misc]
                 scan.cancel()
 
                 # Initiator - LE connect
-                return await pandora.connect_le(initiator, advertisement, acceptor_scan, initiator_addr_type)
+                return await pandora_snippet.connect_le(initiator, advertisement, acceptor_scan, initiator_addr_type)
 
             # Make LE connection.
             if connect == 'incoming_connection':
@@ -269,7 +269,7 @@ class LeSecurityTest(base_test.BaseTestClass):  # type: ignore[misc]
 
             connect_and_pair_task.add_done_callback(on_done)
 
-            ref_ev = await asyncio.wait_for(ref_pairing_fut, timeout=5.0)
+            ref_ev = await asyncio.wait_for(ref_pairing_fut, timeout=15.0)
             self.ref.log.info(f'REF pairing event: {ref_ev.method_variant()}')
 
             dut_ev_answer, ref_ev_answer = None, None
@@ -376,7 +376,7 @@ class LeSecurityTest(base_test.BaseTestClass):  # type: ignore[misc]
                             assert ref_dut_classic_res.connection
                             ref_dut_classic = ref_dut_classic_res.connection
                         else:
-                            ref_dut_classic, _ = await pandora.connect(self.ref, self.dut)
+                            ref_dut_classic, _ = await pandora_snippet.connect(self.ref, self.dut)
                         # Try to encrypt Classic connection
                         ref_dut_secure = await self.ref.aio.security.Secure(ref_dut_classic, classic=LEVEL2)
                         assert_equal(ref_dut_secure.result_variant(), 'success')
diff --git a/avatar/cases/security_test.py b/avatar/cases/security_test.py
index 5213119..f6e8758 100644
--- a/avatar/cases/security_test.py
+++ b/avatar/cases/security_test.py
@@ -16,11 +16,12 @@ import asyncio
 import avatar
 import itertools
 import logging
+import secrets
 
 from avatar import BumblePandoraDevice
 from avatar import PandoraDevice
 from avatar import PandoraDevices
-from avatar import pandora
+from avatar import pandora_snippet
 from bumble.hci import HCI_CENTRAL_ROLE
 from bumble.hci import HCI_PERIPHERAL_ROLE
 from bumble.hci import HCI_Write_Default_Link_Policy_Settings_Command
@@ -103,6 +104,7 @@ class SecurityTest(base_test.BaseTestClass):  # type: ignore[misc]
                 device.config.setdefault('address_resolution_offload', True)
                 device.config.setdefault('classic_enabled', True)
                 device.config.setdefault('classic_ssp_enabled', True)
+                device.config.setdefault('irk', secrets.token_hex(16))
                 device.config.setdefault(
                     'server',
                     {
@@ -249,16 +251,16 @@ class SecurityTest(base_test.BaseTestClass):  # type: ignore[misc]
 
             # Make classic connection.
             if connect == 'incoming_connection':
-                ref_dut, dut_ref = await pandora.connect(initiator=self.ref, acceptor=self.dut)
+                ref_dut, dut_ref = await pandora_snippet.connect(initiator=self.ref, acceptor=self.dut)
             else:
-                dut_ref, ref_dut = await pandora.connect(initiator=self.dut, acceptor=self.ref)
+                dut_ref, ref_dut = await pandora_snippet.connect(initiator=self.dut, acceptor=self.ref)
 
             # Retrieve Bumble connection
             if isinstance(self.dut, BumblePandoraDevice):
-                dut_ref_bumble = pandora.get_raw_connection(self.dut, dut_ref)
+                dut_ref_bumble = pandora_snippet.get_raw_connection(self.dut, dut_ref)
             # Role switch.
             if isinstance(self.ref, BumblePandoraDevice):
-                ref_dut_bumble = pandora.get_raw_connection(self.ref, ref_dut)
+                ref_dut_bumble = pandora_snippet.get_raw_connection(self.ref, ref_dut)
                 if ref_dut_bumble is not None:
                     role = {
                         'against_central': HCI_CENTRAL_ROLE,
@@ -328,7 +330,7 @@ class SecurityTest(base_test.BaseTestClass):  # type: ignore[misc]
 
             connect_and_pair_task.add_done_callback(on_done)
 
-            ref_ev = await asyncio.wait_for(ref_pairing_fut, timeout=5.0)
+            ref_ev = await asyncio.wait_for(ref_pairing_fut, timeout=15.0)
             self.ref.log.info(f'REF pairing event: {ref_ev.method_variant()}')
 
             dut_ev_answer, ref_ev_answer = None, None
diff --git a/avatar/controllers/usb_bumble_device.py b/avatar/controllers/usb_bumble_device.py
new file mode 100644
index 0000000..e733e25
--- /dev/null
+++ b/avatar/controllers/usb_bumble_device.py
@@ -0,0 +1,36 @@
+# Copyright 2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""UsbDevice Bumble Mobly controller."""
+
+
+from bumble.pandora.device import PandoraDevice as BumblePandoraDevice
+from typing import Any, Dict, List
+
+MOBLY_CONTROLLER_CONFIG_NAME = 'UsbDevice'
+
+
+def create(configs: List[Dict[str, Any]]) -> List[BumblePandoraDevice]:
+    """Create a list of `BumbleDevice` from configs."""
+
+    def transport_from_id(id: str) -> str:
+        return f'pyusb:!{id.removeprefix("usb:")}'
+
+    return [BumblePandoraDevice(config={'transport': transport_from_id(config['id'])}) for config in configs]
+
+
+from .bumble_device import destroy
+from .bumble_device import get_info
+
+__all__ = ["MOBLY_CONTROLLER_CONFIG_NAME", "create", "destroy", "get_info"]
diff --git a/avatar/metrics/interceptors.py b/avatar/metrics/interceptors.py
index 3ac7da1..019a4a2 100644
--- a/avatar/metrics/interceptors.py
+++ b/avatar/metrics/interceptors.py
@@ -61,8 +61,7 @@ def aio_interceptors(device: PandoraClient) -> Sequence[grpc.aio.ClientIntercept
 
 
 class UnaryOutcome(Protocol, Generic[_T_co]):
-    def result(self) -> _T_co:
-        ...
+    def result(self) -> _T_co: ...
 
 
 class UnaryUnaryInterceptor(grpc.UnaryUnaryClientInterceptor):  # type: ignore[misc]
diff --git a/avatar/metrics/trace.py b/avatar/metrics/trace.py
index 86bc21a..96caa6f 100644
--- a/avatar/metrics/trace.py
+++ b/avatar/metrics/trace.py
@@ -102,8 +102,7 @@ def hook_test(test: BaseTestClass, devices: PandoraDevices) -> None:
 
 
 class AsTrace(Protocol):
-    def as_trace(self) -> TracePacket:
-        ...
+    def as_trace(self) -> TracePacket: ...
 
 
 class Callsite(AsTrace):
@@ -156,11 +155,15 @@ class Callsite(AsTrace):
                 name=self.name,
                 type=TrackEvent.Type.TYPE_SLICE_BEGIN,
                 track_uuid=devices_id[self.device],
-                debug_annotations=None
-                if self.message is None
-                else [
-                    DebugAnnotation(name=self.message.__class__.__name__, dict_entries=debug_message(self.message)[1])
-                ],
+                debug_annotations=(
+                    None
+                    if self.message is None
+                    else [
+                        DebugAnnotation(
+                            name=self.message.__class__.__name__, dict_entries=debug_message(self.message)[1]
+                        )
+                    ]
+                ),
             ),
             trusted_packet_sequence_id=devices_process_id[self.device],
         )
@@ -184,11 +187,15 @@ class CallEvent(AsTrace):
                 name=self.callsite.name,
                 type=TrackEvent.Type.TYPE_INSTANT,
                 track_uuid=devices_id[self.callsite.device],
-                debug_annotations=None
-                if self.message is None
-                else [
-                    DebugAnnotation(name=self.message.__class__.__name__, dict_entries=debug_message(self.message)[1])
-                ],
+                debug_annotations=(
+                    None
+                    if self.message is None
+                    else [
+                        DebugAnnotation(
+                            name=self.message.__class__.__name__, dict_entries=debug_message(self.message)[1]
+                        )
+                    ]
+                ),
             ),
             trusted_packet_sequence_id=devices_process_id[self.callsite.device],
         )
@@ -228,11 +235,15 @@ class CallEnd(CallEvent):
                 name=self.callsite.name,
                 type=TrackEvent.Type.TYPE_SLICE_END,
                 track_uuid=devices_id[self.callsite.device],
-                debug_annotations=None
-                if self.message is None
-                else [
-                    DebugAnnotation(name=self.message.__class__.__name__, dict_entries=debug_message(self.message)[1])
-                ],
+                debug_annotations=(
+                    None
+                    if self.message is None
+                    else [
+                        DebugAnnotation(
+                            name=self.message.__class__.__name__, dict_entries=debug_message(self.message)[1]
+                        )
+                    ]
+                ),
             ),
             trusted_packet_sequence_id=devices_process_id[self.callsite.device],
         )
diff --git a/avatar/metrics/trace_pb2.pyi b/avatar/metrics/trace_pb2.pyi
index fcfac67..009da07 100644
--- a/avatar/metrics/trace_pb2.pyi
+++ b/avatar/metrics/trace_pb2.pyi
@@ -64,6 +64,7 @@ class TrackEvent(_message.Message):
         TYPE_SLICE_END: _ClassVar[TrackEvent.Type]
         TYPE_INSTANT: _ClassVar[TrackEvent.Type]
         TYPE_COUNTER: _ClassVar[TrackEvent.Type]
+
     TYPE_UNSPECIFIED: TrackEvent.Type
     TYPE_SLICE_BEGIN: TrackEvent.Type
     TYPE_SLICE_END: TrackEvent.Type
diff --git a/avatar/pandora_client.py b/avatar/pandora_client.py
index 98211c6..1f407d3 100644
--- a/avatar/pandora_client.py
+++ b/avatar/pandora_client.py
@@ -118,7 +118,11 @@ class PandoraClient:
                 )
                 return
             except grpc.aio.AioRpcError as e:
-                if e.code() in (grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED):
+                if e.code() in (
+                    grpc.StatusCode.UNAVAILABLE,
+                    grpc.StatusCode.DEADLINE_EXCEEDED,
+                    grpc.StatusCode.CANCELLED,
+                ):
                     if attempts <= max_attempts:
                         self.log.debug(f'Server unavailable, retry [{attempts}/{max_attempts}].')
                         attempts += 1
diff --git a/avatar/pandora_server.py b/avatar/pandora_server.py
index aafc3fc..ae86309 100644
--- a/avatar/pandora_server.py
+++ b/avatar/pandora_server.py
@@ -25,6 +25,7 @@ import types
 
 from avatar.controllers import bumble_device
 from avatar.controllers import pandora_device
+from avatar.controllers import usb_bumble_device
 from avatar.pandora_client import BumblePandoraClient
 from avatar.pandora_client import PandoraClient
 from bumble import pandora as bumble_server
@@ -105,6 +106,10 @@ class BumblePandoraServer(PandoraServer[BumblePandoraDevice]):
         avatar.aio.run_until_complete(server_stop())
 
 
+class UsbBumblePandoraServer(BumblePandoraServer):
+    MOBLY_CONTROLLER_MODULE = usb_bumble_device
+
+
 class AndroidPandoraServer(PandoraServer[AndroidDevice]):
     """Manages the Pandora gRPC server on an AndroidDevice."""
 
diff --git a/avatar/pandora.py b/avatar/pandora_snippet.py
similarity index 100%
rename from avatar/pandora.py
rename to avatar/pandora_snippet.py
diff --git a/doc/android-guide.md b/doc/android-guide.md
index 5e5fa21..0f825a0 100644
--- a/doc/android-guide.md
+++ b/doc/android-guide.md
@@ -31,7 +31,7 @@ from the root of your Android repository:
 
 ```shell
 source build/envsetup.sh
-lunch aosp_cf_x86_64_phone-userdebug
+lunch aosp_cf_x86_64_phone-trunk_staging-userdebug
 acloud create --local-image --local-instance
 ```
 
@@ -75,6 +75,8 @@ Create a new Avatar test class file `codelab_test.py` in the Android Avatar
 tests folder, `packages/modules/Bluetooth/android/pandora/test/`:
 
 ```python
+import asyncio # Provides utilities for calling asynchronous functions.
+
 from typing import Optional  # Avatar is strictly typed.
 
 # Importing Mobly modules required for the test.
@@ -90,7 +92,7 @@ from pandora.host_pb2 import RANDOM, DataTypes
 
 
 # The test class to test the LE (Bluetooth Low Energy) Connectivity.
-class CodelabTest(base_test.BaseTestClass):
+class CodelabTest(base_test.BaseTestClass): # type: ignore[misc]
     devices: Optional[PandoraDevices] = None
     dut: PandoraClient
     ref: BumblePandoraClient  # `BumblePandoraClient` is a sub-class of `PandoraClient`
@@ -98,7 +100,7 @@ class CodelabTest(base_test.BaseTestClass):
     # Method to set up the DUT and REF devices for the test (called once).
     def setup_class(self) -> None:
         self.devices = PandoraDevices(self)  # Create Pandora devices from the config.
-        self.dut, ref = self.devices
+        self.dut, ref, *_ = self.devices
         assert isinstance(ref, BumblePandoraClient)  # REF device is a Bumble device.
         self.ref = ref
 
diff --git a/doc/overview.md b/doc/overview.md
index 4050b12..a50d22e 100644
--- a/doc/overview.md
+++ b/doc/overview.md
@@ -81,8 +81,7 @@ For example, using another Android device to emulate an interoperability
 behavior of a specific headset would require building dedicated hooks in the
 Android Bluetooth stack and the corresponding APIs which wouldn't be practical.
 
-However, other setups are also supported (see [Extended architecture](
-#extended-architecture)).
+However, other setups are also supported (see [Extended architecture](#extended-architecture)).
 
 ## Types of Avatar tests
 
diff --git a/pyproject.toml b/pyproject.toml
index 496da6b..ab89e0f 100644
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -9,10 +9,10 @@ classifiers = [
     "License :: OSI Approved :: Apache Software License"
 ]
 dependencies = [
-    "bt-test-interfaces",
-    "bumble==0.0.170",
+    "bt-test-interfaces>=0.0.6",
+    "bumble>=0.0.199",
     "protobuf==4.24.2",
-    "grpcio==1.57",
+    "grpcio>=1.62.1",
     "mobly==1.12.2",
     "portpicker>=1.5.2",
 ]
@@ -25,11 +25,11 @@ avatar = "avatar:main"
 
 [project.optional-dependencies]
 dev = [
-    "rootcanal==1.3.0",
-    "grpcio-tools>=1.57",
+    "rootcanal>=1.10.0",
+    "grpcio-tools>=1.62.1",
     "pyright==1.1.298",
     "mypy==1.5.1",
-    "black==23.7.0",
+    "black==24.10.0",
     "isort==5.12.0",
     "types-psutil==5.9.5.16",
     "types-setuptools==68.1.0.1",
```

