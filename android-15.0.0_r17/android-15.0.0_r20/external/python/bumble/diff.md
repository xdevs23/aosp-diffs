```diff
diff --git a/.github/workflows/python-avatar.yml b/.github/workflows/python-avatar.yml
index a7403a3..90ca0f0 100644
--- a/.github/workflows/python-avatar.yml
+++ b/.github/workflows/python-avatar.yml
@@ -40,4 +40,11 @@ jobs:
           avatar --list | grep -Ev '^=' > test-names.txt
           timeout 5m avatar --test-beds bumble.bumbles --tests $(split test-names.txt -n l/${{ matrix.shard }})
       - name: Rootcanal Logs
+        if: always()
         run: cat rootcanal.log
+      - name: Upload Mobly logs
+        if: always()
+        uses: actions/upload-artifact@v3
+        with:
+          name: mobly-logs
+          path: /tmp/logs/mobly/bumble.bumbles/
diff --git a/apps/controller_info.py b/apps/controller_info.py
index 7cf3332..9ac0882 100644
--- a/apps/controller_info.py
+++ b/apps/controller_info.py
@@ -27,6 +27,7 @@ from bumble.colors import color
 from bumble.core import name_or_number
 from bumble.hci import (
     map_null_terminated_utf8_string,
+    CodecID,
     LeFeature,
     HCI_SUCCESS,
     HCI_VERSION_NAMES,
@@ -50,6 +51,8 @@ from bumble.hci import (
     HCI_LE_Read_Maximum_Advertising_Data_Length_Command,
     HCI_LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH_COMMAND,
     HCI_LE_Read_Suggested_Default_Data_Length_Command,
+    HCI_Read_Local_Supported_Codecs_Command,
+    HCI_Read_Local_Supported_Codecs_V2_Command,
     HCI_Read_Local_Version_Information_Command,
 )
 from bumble.host import Host
@@ -168,6 +171,60 @@ async def get_acl_flow_control_info(host: Host) -> None:
         )
 
 
+# -----------------------------------------------------------------------------
+async def get_codecs_info(host: Host) -> None:
+    print()
+
+    if host.supports_command(HCI_Read_Local_Supported_Codecs_V2_Command.op_code):
+        response = await host.send_command(
+            HCI_Read_Local_Supported_Codecs_V2_Command(), check_result=True
+        )
+        print(color('Codecs:', 'yellow'))
+
+        for codec_id, transport in zip(
+            response.return_parameters.standard_codec_ids,
+            response.return_parameters.standard_codec_transports,
+        ):
+            transport_name = HCI_Read_Local_Supported_Codecs_V2_Command.Transport(
+                transport
+            ).name
+            codec_name = CodecID(codec_id).name
+            print(f'  {codec_name} - {transport_name}')
+
+        for codec_id, transport in zip(
+            response.return_parameters.vendor_specific_codec_ids,
+            response.return_parameters.vendor_specific_codec_transports,
+        ):
+            transport_name = HCI_Read_Local_Supported_Codecs_V2_Command.Transport(
+                transport
+            ).name
+            company = name_or_number(COMPANY_IDENTIFIERS, codec_id >> 16)
+            print(f'  {company} / {codec_id & 0xFFFF} - {transport_name}')
+
+        if not response.return_parameters.standard_codec_ids:
+            print('  No standard codecs')
+        if not response.return_parameters.vendor_specific_codec_ids:
+            print('  No Vendor-specific codecs')
+
+    if host.supports_command(HCI_Read_Local_Supported_Codecs_Command.op_code):
+        response = await host.send_command(
+            HCI_Read_Local_Supported_Codecs_Command(), check_result=True
+        )
+        print(color('Codecs (BR/EDR):', 'yellow'))
+        for codec_id in response.return_parameters.standard_codec_ids:
+            codec_name = CodecID(codec_id).name
+            print(f'  {codec_name}')
+
+        for codec_id in response.return_parameters.vendor_specific_codec_ids:
+            company = name_or_number(COMPANY_IDENTIFIERS, codec_id >> 16)
+            print(f'  {company} / {codec_id & 0xFFFF}')
+
+        if not response.return_parameters.standard_codec_ids:
+            print('  No standard codecs')
+        if not response.return_parameters.vendor_specific_codec_ids:
+            print('  No Vendor-specific codecs')
+
+
 # -----------------------------------------------------------------------------
 async def async_main(latency_probes, transport):
     print('<<< connecting to HCI...')
@@ -220,6 +277,9 @@ async def async_main(latency_probes, transport):
         # Print the ACL flow control info
         await get_acl_flow_control_info(host)
 
+        # Get codec info
+        await get_codecs_info(host)
+
         # Print the list of commands supported by the controller
         print()
         print(color('Supported Commands:', 'yellow'))
diff --git a/bumble/att.py b/bumble/att.py
index 6eed040..aeae7c9 100644
--- a/bumble/att.py
+++ b/bumble/att.py
@@ -811,7 +811,7 @@ class Attribute(EventEmitter):
                 enum_list: List[str] = [p.name for p in cls if p.name is not None]
                 enum_list_str = ",".join(enum_list)
                 raise TypeError(
-                    f"Attribute::permissions error:\nExpected a string containing any of the keys, separated by commas: {enum_list_str  }\nGot: {permissions_str}"
+                    f"Attribute::permissions error:\nExpected a string containing any of the keys, separated by commas: {enum_list_str}\nGot: {permissions_str}"
                 ) from exc
 
     # Permission flags(legacy-use only)
diff --git a/bumble/avdtp.py b/bumble/avdtp.py
index 85f7ede..fd79dc3 100644
--- a/bumble/avdtp.py
+++ b/bumble/avdtp.py
@@ -580,10 +580,10 @@ class ServiceCapabilities:
         self.service_category = service_category
         self.service_capabilities_bytes = service_capabilities_bytes
 
-    def to_string(self, details: List[str] = []) -> str:
+    def to_string(self, details: Optional[List[str]] = None) -> str:
         attributes = ','.join(
             [name_or_number(AVDTP_SERVICE_CATEGORY_NAMES, self.service_category)]
-            + details
+            + (details or [])
         )
         return f'ServiceCapabilities({attributes})'
 
diff --git a/bumble/device.py b/bumble/device.py
index 034b0e9..38d0ca6 100644
--- a/bumble/device.py
+++ b/bumble/device.py
@@ -1766,9 +1766,9 @@ device_host_event_handlers: List[str] = []
 # -----------------------------------------------------------------------------
 class Device(CompositeEventEmitter):
     # Incomplete list of fields.
-    random_address: Address  # Random address that may change with RPA
-    public_address: Address  # Public address (obtained from the controller)
-    static_address: Address  # Random address that can be set but does not change
+    random_address: Address  # Random private address that may change periodically
+    public_address: Address  # Public address that is globally unique (from controller)
+    static_address: Address  # Random static address that does not change once set
     classic_enabled: bool
     name: str
     class_of_device: int
diff --git a/bumble/gatt.py b/bumble/gatt.py
index 3e679bb..ea65116 100644
--- a/bumble/gatt.py
+++ b/bumble/gatt.py
@@ -345,7 +345,7 @@ class Service(Attribute):
         uuid: Union[str, UUID],
         characteristics: List[Characteristic],
         primary=True,
-        included_services: List[Service] = [],
+        included_services: Iterable[Service] = (),
     ) -> None:
         # Convert the uuid to a UUID object if it isn't already
         if isinstance(uuid, str):
@@ -361,7 +361,7 @@ class Service(Attribute):
             uuid.to_pdu_bytes(),
         )
         self.uuid = uuid
-        self.included_services = included_services[:]
+        self.included_services = list(included_services)
         self.characteristics = characteristics[:]
         self.primary = primary
 
@@ -395,7 +395,7 @@ class TemplateService(Service):
         self,
         characteristics: List[Characteristic],
         primary: bool = True,
-        included_services: List[Service] = [],
+        included_services: Iterable[Service] = (),
     ) -> None:
         super().__init__(self.UUID, characteristics, primary, included_services)
 
diff --git a/bumble/hci.py b/bumble/hci.py
index 1d0cd8e..f79098a 100644
--- a/bumble/hci.py
+++ b/bumble/hci.py
@@ -3440,11 +3440,11 @@ class HCI_Read_Local_Supported_Codecs_V2_Command(HCI_Command):
     See Bluetooth spec @ 7.4.8 Read Local Supported Codecs Command
     '''
 
-    class Transport(OpenIntEnum):
-        BR_EDR_ACL = 0x00
-        BR_EDR_SCO = 0x01
-        LE_CIS = 0x02
-        LE_BIS = 0x03
+    class Transport(enum.IntFlag):
+        BR_EDR_ACL = 1 << 0
+        BR_EDR_SCO = 1 << 1
+        LE_CIS = 1 << 2
+        LE_BIS = 1 << 3
 
 
 # -----------------------------------------------------------------------------
diff --git a/bumble/profiles/hap.py b/bumble/profiles/hap.py
index 1ef055c..5c912d8 100644
--- a/bumble/profiles/hap.py
+++ b/bumble/profiles/hap.py
@@ -25,7 +25,7 @@ from bumble.utils import AsyncRunner, OpenIntEnum
 from bumble.hci import Address
 from dataclasses import dataclass, field
 import logging
-from typing import Dict, List, Optional, Set, Union
+from typing import Any, Dict, List, Optional, Set, Union
 
 
 # -----------------------------------------------------------------------------
@@ -271,24 +271,12 @@ class HearingAccessService(gatt.TemplateService):
             def on_disconnection(_reason) -> None:
                 self.currently_connected_clients.remove(connection)
 
-            # TODO Should we filter on device bonded && device is HAP ?
-            self.currently_connected_clients.add(connection)
-            if (
-                connection.peer_address
-                not in self.preset_changed_operations_history_per_device
-            ):
-                self.preset_changed_operations_history_per_device[
-                    connection.peer_address
-                ] = []
-                return
-
-            async def on_connection_async() -> None:
-                # Send all the PresetChangedOperation that occur when not connected
-                await self._preset_changed_operation(connection)
-                # Update the active preset index if needed
-                await self.notify_active_preset_for_connection(connection)
+            @connection.on('pairing')  # type: ignore
+            def on_pairing(*_: Any) -> None:
+                self.on_incoming_paired_connection(connection)
 
-            connection.abort_on('disconnection', on_connection_async())
+            if connection.peer_resolvable_address:
+                self.on_incoming_paired_connection(connection)
 
         self.hearing_aid_features_characteristic = gatt.Characteristic(
             uuid=gatt.GATT_HEARING_AID_FEATURES_CHARACTERISTIC,
@@ -325,6 +313,27 @@ class HearingAccessService(gatt.TemplateService):
             ]
         )
 
+    def on_incoming_paired_connection(self, connection: Connection):
+        '''Setup initial operations to handle a remote bonded HAP device'''
+        # TODO Should we filter on HAP device only ?
+        self.currently_connected_clients.add(connection)
+        if (
+            connection.peer_address
+            not in self.preset_changed_operations_history_per_device
+        ):
+            self.preset_changed_operations_history_per_device[
+                connection.peer_address
+            ] = []
+            return
+
+        async def on_connection_async() -> None:
+            # Send all the PresetChangedOperation that occur when not connected
+            await self._preset_changed_operation(connection)
+            # Update the active preset index if needed
+            await self.notify_active_preset_for_connection(connection)
+
+        connection.abort_on('disconnection', on_connection_async())
+
     def _on_read_active_preset_index(
         self, __connection__: Optional[Connection]
     ) -> bytes:
diff --git a/bumble/transport/android_netsim.py b/bumble/transport/android_netsim.py
index 264266d..9a3e016 100644
--- a/bumble/transport/android_netsim.py
+++ b/bumble/transport/android_netsim.py
@@ -70,6 +70,9 @@ def get_ini_dir() -> Optional[pathlib.Path]:
     elif sys.platform == 'linux':
         if xdg_runtime_dir := os.environ.get('XDG_RUNTIME_DIR', None):
             return pathlib.Path(xdg_runtime_dir)
+        tmpdir = os.environ.get('TMPDIR', '/tmp')
+        if pathlib.Path(tmpdir).is_dir():
+            return pathlib.Path(tmpdir)
     elif sys.platform == 'win32':
         if local_app_data_dir := os.environ.get('LOCALAPPDATA', None):
             return pathlib.Path(local_app_data_dir) / 'Temp'
diff --git a/bumble/transport/pyusb.py b/bumble/transport/pyusb.py
index 26f9991..1fabe14 100644
--- a/bumble/transport/pyusb.py
+++ b/bumble/transport/pyusb.py
@@ -221,8 +221,9 @@ async def open_pyusb_transport(spec: str) -> Transport:
         async def close(self):
             await self.source.stop()
             await self.sink.stop()
-            devices_in_use.remove(device.address)
             usb.util.release_interface(self.device, 0)
+            if devices_in_use and device.address in devices_in_use:
+                devices_in_use.remove(device.address)
 
     usb_find = usb.core.find
     try:
diff --git a/docs/mkdocs/src/examples/index.md b/docs/mkdocs/src/examples/index.md
index ae729ae..3ba723d 100644
--- a/docs/mkdocs/src/examples/index.md
+++ b/docs/mkdocs/src/examples/index.md
@@ -1,7 +1,7 @@
 EXAMPLES
 ========
 
-The project includes a few simple example applications the illustrate some of the ways the library APIs can be used.
+The project includes a few simple example applications to illustrate some of the ways the library APIs can be used.
 These examples include:
 
 ## `battery_service.py`
@@ -25,6 +25,9 @@ An app that implements a virtual Bluetooth speaker that can receive audio.
 ## `run_advertiser.py`
 An app that runs a simple device that just advertises (BLE).
 
+## `run_cig_setup.py`
+An app that creates a simple CIG containing two CISes. **Note**: If using the example config file (e.g. `device1.json`), the `address` needs to be removed, so that the devices are given different random addresses.
+
 ## `run_classic_connect.py`
 An app that connects to a Bluetooth Classic device and prints its services.
 
@@ -42,6 +45,9 @@ An app that connected to a device (BLE) and encrypts the connection.
 ## `run_controller.py`
 Creates two linked controllers, attaches one to a transport, and the other to a local host with a GATT server application. This can be used, for example, to attach a virtual controller to a native stack, like BlueZ on Linux, and use the native tools, like `bluetoothctl`, to scan and connect to the GATT server included in the example.
 
+## `run_csis_servers.py`
+Runs CSIS servers on two devices to form a Coordinated Set. **Note**: If using the example config file (e.g. `device1.json`), the `address` needs to be removed, so that the devices are given different random addresses.   
+
 ## `run_gatt_client_and_server.py`
 Runs a local GATT server and GATT client, connected to each other. The GATT client discovers and logs all the services and characteristics exposed by the GATT server
 
diff --git a/examples/run_cig_setup.py b/examples/run_cig_setup.py
index 29a54ad..b0a0fe1 100644
--- a/examples/run_cig_setup.py
+++ b/examples/run_cig_setup.py
@@ -36,13 +36,10 @@ from bumble.transport import open_transport_or_link
 async def main() -> None:
     if len(sys.argv) < 3:
         print(
-            'Usage: run_cig_setup.py <config-file>'
+            'Usage: run_cig_setup.py <config-file> '
             '<transport-spec-for-device-1> <transport-spec-for-device-2>'
         )
-        print(
-            'example: run_cig_setup.py device1.json'
-            'tcp-client:127.0.0.1:6402 tcp-client:127.0.0.1:6402'
-        )
+        print('example: run_cig_setup.py device1.json hci-socket:0 hci-socket:1')
         return
 
     print('<<< connecting to HCI...')
@@ -65,18 +62,18 @@ async def main() -> None:
     advertising_set = await devices[0].create_advertising_set()
 
     connection = await devices[1].connect(
-        devices[0].public_address, own_address_type=OwnAddressType.PUBLIC
+        devices[0].random_address, own_address_type=OwnAddressType.RANDOM
     )
 
     cid_ids = [2, 3]
     cis_handles = await devices[1].setup_cig(
         cig_id=1,
         cis_id=cid_ids,
-        sdu_interval=(10000, 0),
+        sdu_interval=(10000, 255),
         framing=0,
         max_sdu=(120, 0),
         retransmission_number=13,
-        max_transport_latency=(100, 0),
+        max_transport_latency=(100, 5),
     )
 
     def on_cis_request(
diff --git a/examples/run_csis_servers.py b/examples/run_csis_servers.py
index 9853523..d1f5f67 100644
--- a/examples/run_csis_servers.py
+++ b/examples/run_csis_servers.py
@@ -38,13 +38,10 @@ from bumble.transport import open_transport_or_link
 async def main() -> None:
     if len(sys.argv) < 3:
         print(
-            'Usage: run_cig_setup.py <config-file>'
+            'Usage: run_csis_servers.py <config-file> '
             '<transport-spec-for-device-1> <transport-spec-for-device-2>'
         )
-        print(
-            'example: run_cig_setup.py device1.json'
-            'tcp-client:127.0.0.1:6402 tcp-client:127.0.0.1:6402'
-        )
+        print('example: run_csis_servers.py device1.json ' 'hci-socket:0 hci-socket:1')
         return
 
     print('<<< connecting to HCI...')
diff --git a/setup.cfg b/setup.cfg
index 44d8541..305357a 100644
--- a/setup.cfg
+++ b/setup.cfg
@@ -99,7 +99,7 @@ development =
     types-protobuf >= 4.21.0
     wasmtime == 20.0.0
 avatar =
-    pandora-avatar == 0.0.9
+    pandora-avatar == 0.0.10
     rootcanal == 1.10.0 ; python_version>='3.10'
 pandora =
     bt-test-interfaces >= 0.0.6
diff --git a/tests/hap_test.py b/tests/hap_test.py
index 58392fd..29bff2f 100644
--- a/tests/hap_test.py
+++ b/tests/hap_test.py
@@ -25,6 +25,7 @@ import sys
 from bumble import att, device
 from bumble.profiles import hap
 from .test_utils import TwoDevices
+from bumble.keys import PairingKeys
 
 # -----------------------------------------------------------------------------
 # Logging
@@ -86,6 +87,10 @@ async def hap_client():
     devices.connections[0].encryption = 1  # type: ignore
     devices.connections[1].encryption = 1  # type: ignore
 
+    devices[0].on_pairing(
+        devices.connections[0], devices.connections[0].peer_address, PairingKeys(), True
+    )
+
     peer = device.Peer(devices.connections[1])  # type: ignore
     hap_client = await peer.discover_service_and_create_proxy(
         hap.HearingAccessServiceProxy
```

