```diff
diff --git a/.devcontainer/devcontainer.json b/.devcontainer/devcontainer.json
new file mode 100644
index 0000000..92ebdab
--- /dev/null
+++ b/.devcontainer/devcontainer.json
@@ -0,0 +1,30 @@
+// For format details, see https://aka.ms/devcontainer.json. For config options, see the
+// README at: https://github.com/devcontainers/templates/tree/main/src/python
+{
+	// Or use a Dockerfile or Docker Compose file. More info: https://containers.dev/guide/dockerfile
+    "image": "mcr.microsoft.com/devcontainers/universal:2",
+
+	// Features to add to the dev container. More info: https://containers.dev/features.
+	// "features": {},
+
+	// Use 'forwardPorts' to make a list of ports inside the container available locally.
+	// "forwardPorts": [],
+
+	// Use 'postCreateCommand' to run commands after the container is created.
+    "postCreateCommand": 
+        "python -m pip install '.[build,test,development,documentation]'",
+
+    // Configure tool-specific properties.
+    "customizations": {
+        // Configure properties specific to VS Code.
+        "vscode": {
+            // Add the IDs of extensions you want installed when the container is created.
+            "extensions": [
+                "ms-python.python"
+            ]
+        }
+    }
+
+	// Uncomment to connect as root instead. More info: https://aka.ms/dev-containers-non-root.
+	// "remoteUser": "root"
+}
diff --git a/METADATA b/METADATA
index 48086d7..e4b9b79 100644
--- a/METADATA
+++ b/METADATA
@@ -11,7 +11,7 @@ third_party {
     type: GIT
     value: "https://github.com/google/bumble"
   }
-  version: "783b2d70a517a4c5fd828a0f6b8b2a46fe8750c5"
-  last_upgrade_date { year: 2023 month: 9 day: 12 }
+  version: "737abdc481b226b16d85174d9ae0ebd9346b0fb4"
+  last_upgrade_date { year: 2024 month: 9 day: 17 }
   license_type: NOTICE
 }
diff --git a/OWNERS b/OWNERS
index c14a64c..fc48548 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,3 @@
 boccongibod@google.com
 charliebout@google.com
 girardier@google.com
-licorne@google.com
diff --git a/apps/auracast.py b/apps/auracast.py
new file mode 100644
index 0000000..96f2a23
--- /dev/null
+++ b/apps/auracast.py
@@ -0,0 +1,692 @@
+# Copyright 2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+from __future__ import annotations
+import asyncio
+import contextlib
+import dataclasses
+import logging
+import os
+from typing import cast, Any, AsyncGenerator, Coroutine, Dict, Optional, Tuple
+
+import click
+import pyee
+
+from bumble.colors import color
+import bumble.company_ids
+import bumble.core
+import bumble.device
+import bumble.gatt
+import bumble.hci
+import bumble.profiles.bap
+import bumble.profiles.bass
+import bumble.profiles.pbp
+import bumble.transport
+import bumble.utils
+
+
+# -----------------------------------------------------------------------------
+# Logging
+# -----------------------------------------------------------------------------
+logger = logging.getLogger(__name__)
+
+
+# -----------------------------------------------------------------------------
+# Constants
+# -----------------------------------------------------------------------------
+AURACAST_DEFAULT_DEVICE_NAME = 'Bumble Auracast'
+AURACAST_DEFAULT_DEVICE_ADDRESS = bumble.hci.Address('F0:F1:F2:F3:F4:F5')
+AURACAST_DEFAULT_SYNC_TIMEOUT = 5.0
+AURACAST_DEFAULT_ATT_MTU = 256
+
+
+# -----------------------------------------------------------------------------
+# Scan For Broadcasts
+# -----------------------------------------------------------------------------
+class BroadcastScanner(pyee.EventEmitter):
+    @dataclasses.dataclass
+    class Broadcast(pyee.EventEmitter):
+        name: str
+        sync: bumble.device.PeriodicAdvertisingSync
+        rssi: int = 0
+        public_broadcast_announcement: Optional[
+            bumble.profiles.pbp.PublicBroadcastAnnouncement
+        ] = None
+        broadcast_audio_announcement: Optional[
+            bumble.profiles.bap.BroadcastAudioAnnouncement
+        ] = None
+        basic_audio_announcement: Optional[
+            bumble.profiles.bap.BasicAudioAnnouncement
+        ] = None
+        appearance: Optional[bumble.core.Appearance] = None
+        biginfo: Optional[bumble.device.BIGInfoAdvertisement] = None
+        manufacturer_data: Optional[Tuple[str, bytes]] = None
+
+        def __post_init__(self) -> None:
+            super().__init__()
+            self.sync.on('establishment', self.on_sync_establishment)
+            self.sync.on('loss', self.on_sync_loss)
+            self.sync.on('periodic_advertisement', self.on_periodic_advertisement)
+            self.sync.on('biginfo_advertisement', self.on_biginfo_advertisement)
+
+        def update(self, advertisement: bumble.device.Advertisement) -> None:
+            self.rssi = advertisement.rssi
+            for service_data in advertisement.data.get_all(
+                bumble.core.AdvertisingData.SERVICE_DATA
+            ):
+                assert isinstance(service_data, tuple)
+                service_uuid, data = service_data
+                assert isinstance(data, bytes)
+
+                if (
+                    service_uuid
+                    == bumble.gatt.GATT_PUBLIC_BROADCAST_ANNOUNCEMENT_SERVICE
+                ):
+                    self.public_broadcast_announcement = (
+                        bumble.profiles.pbp.PublicBroadcastAnnouncement.from_bytes(data)
+                    )
+                    continue
+
+                if (
+                    service_uuid
+                    == bumble.gatt.GATT_BROADCAST_AUDIO_ANNOUNCEMENT_SERVICE
+                ):
+                    self.broadcast_audio_announcement = (
+                        bumble.profiles.bap.BroadcastAudioAnnouncement.from_bytes(data)
+                    )
+                    continue
+
+            self.appearance = advertisement.data.get(  # type: ignore[assignment]
+                bumble.core.AdvertisingData.APPEARANCE
+            )
+
+            if manufacturer_data := advertisement.data.get(
+                bumble.core.AdvertisingData.MANUFACTURER_SPECIFIC_DATA
+            ):
+                assert isinstance(manufacturer_data, tuple)
+                company_id = cast(int, manufacturer_data[0])
+                data = cast(bytes, manufacturer_data[1])
+                self.manufacturer_data = (
+                    bumble.company_ids.COMPANY_IDENTIFIERS.get(
+                        company_id, f'0x{company_id:04X}'
+                    ),
+                    data,
+                )
+
+            self.emit('update')
+
+        def print(self) -> None:
+            print(
+                color('Broadcast:', 'yellow'),
+                self.sync.advertiser_address,
+                color(self.sync.state.name, 'green'),
+            )
+            print(f'  {color("Name", "cyan")}:         {self.name}')
+            if self.appearance:
+                print(f'  {color("Appearance", "cyan")}:   {str(self.appearance)}')
+            print(f'  {color("RSSI", "cyan")}:         {self.rssi}')
+            print(f'  {color("SID", "cyan")}:          {self.sync.sid}')
+
+            if self.manufacturer_data:
+                print(
+                    f'  {color("Manufacturer Data", "cyan")}: '
+                    f'{self.manufacturer_data[0]} -> {self.manufacturer_data[1].hex()}'
+                )
+
+            if self.broadcast_audio_announcement:
+                print(
+                    f'  {color("Broadcast ID", "cyan")}: '
+                    f'{self.broadcast_audio_announcement.broadcast_id}'
+                )
+
+            if self.public_broadcast_announcement:
+                print(
+                    f'  {color("Features", "cyan")}:     '
+                    f'{self.public_broadcast_announcement.features}'
+                )
+                print(
+                    f'  {color("Metadata", "cyan")}:     '
+                    f'{self.public_broadcast_announcement.metadata}'
+                )
+
+            if self.basic_audio_announcement:
+                print(color('  Audio:', 'cyan'))
+                print(
+                    color('    Presentation Delay:', 'magenta'),
+                    self.basic_audio_announcement.presentation_delay,
+                )
+                for subgroup in self.basic_audio_announcement.subgroups:
+                    print(color('    Subgroup:', 'magenta'))
+                    print(color('      Codec ID:', 'yellow'))
+                    print(
+                        color('        Coding Format:           ', 'green'),
+                        subgroup.codec_id.coding_format.name,
+                    )
+                    print(
+                        color('        Company ID:              ', 'green'),
+                        subgroup.codec_id.company_id,
+                    )
+                    print(
+                        color('        Vendor Specific Codec ID:', 'green'),
+                        subgroup.codec_id.vendor_specific_codec_id,
+                    )
+                    print(
+                        color('      Codec Config:', 'yellow'),
+                        subgroup.codec_specific_configuration,
+                    )
+                    print(color('      Metadata:    ', 'yellow'), subgroup.metadata)
+
+                    for bis in subgroup.bis:
+                        print(color(f'      BIS [{bis.index}]:', 'yellow'))
+                        print(
+                            color('       Codec Config:', 'green'),
+                            bis.codec_specific_configuration,
+                        )
+
+            if self.biginfo:
+                print(color('  BIG:', 'cyan'))
+                print(
+                    color('    Number of BIS:', 'magenta'),
+                    self.biginfo.num_bis,
+                )
+                print(
+                    color('    PHY:          ', 'magenta'),
+                    self.biginfo.phy.name,
+                )
+                print(
+                    color('    Framed:       ', 'magenta'),
+                    self.biginfo.framed,
+                )
+                print(
+                    color('    Encrypted:    ', 'magenta'),
+                    self.biginfo.encrypted,
+                )
+
+        def on_sync_establishment(self) -> None:
+            self.emit('sync_establishment')
+
+        def on_sync_loss(self) -> None:
+            self.basic_audio_announcement = None
+            self.biginfo = None
+            self.emit('sync_loss')
+
+        def on_periodic_advertisement(
+            self, advertisement: bumble.device.PeriodicAdvertisement
+        ) -> None:
+            if advertisement.data is None:
+                return
+
+            for service_data in advertisement.data.get_all(
+                bumble.core.AdvertisingData.SERVICE_DATA
+            ):
+                assert isinstance(service_data, tuple)
+                service_uuid, data = service_data
+                assert isinstance(data, bytes)
+
+                if service_uuid == bumble.gatt.GATT_BASIC_AUDIO_ANNOUNCEMENT_SERVICE:
+                    self.basic_audio_announcement = (
+                        bumble.profiles.bap.BasicAudioAnnouncement.from_bytes(data)
+                    )
+                    break
+
+            self.emit('change')
+
+        def on_biginfo_advertisement(
+            self, advertisement: bumble.device.BIGInfoAdvertisement
+        ) -> None:
+            self.biginfo = advertisement
+            self.emit('change')
+
+    def __init__(
+        self,
+        device: bumble.device.Device,
+        filter_duplicates: bool,
+        sync_timeout: float,
+    ):
+        super().__init__()
+        self.device = device
+        self.filter_duplicates = filter_duplicates
+        self.sync_timeout = sync_timeout
+        self.broadcasts: Dict[bumble.hci.Address, BroadcastScanner.Broadcast] = {}
+        device.on('advertisement', self.on_advertisement)
+
+    async def start(self) -> None:
+        await self.device.start_scanning(
+            active=False,
+            filter_duplicates=False,
+        )
+
+    async def stop(self) -> None:
+        await self.device.stop_scanning()
+
+    def on_advertisement(self, advertisement: bumble.device.Advertisement) -> None:
+        if (
+            broadcast_name := advertisement.data.get(
+                bumble.core.AdvertisingData.BROADCAST_NAME
+            )
+        ) is None:
+            return
+        assert isinstance(broadcast_name, str)
+
+        if broadcast := self.broadcasts.get(advertisement.address):
+            broadcast.update(advertisement)
+            return
+
+        bumble.utils.AsyncRunner.spawn(
+            self.on_new_broadcast(broadcast_name, advertisement)
+        )
+
+    async def on_new_broadcast(
+        self, name: str, advertisement: bumble.device.Advertisement
+    ) -> None:
+        periodic_advertising_sync = await self.device.create_periodic_advertising_sync(
+            advertiser_address=advertisement.address,
+            sid=advertisement.sid,
+            sync_timeout=self.sync_timeout,
+            filter_duplicates=self.filter_duplicates,
+        )
+        broadcast = self.Broadcast(
+            name,
+            periodic_advertising_sync,
+        )
+        broadcast.update(advertisement)
+        self.broadcasts[advertisement.address] = broadcast
+        periodic_advertising_sync.on('loss', lambda: self.on_broadcast_loss(broadcast))
+        self.emit('new_broadcast', broadcast)
+
+    def on_broadcast_loss(self, broadcast: Broadcast) -> None:
+        del self.broadcasts[broadcast.sync.advertiser_address]
+        bumble.utils.AsyncRunner.spawn(broadcast.sync.terminate())
+        self.emit('broadcast_loss', broadcast)
+
+
+class PrintingBroadcastScanner:
+    def __init__(
+        self, device: bumble.device.Device, filter_duplicates: bool, sync_timeout: float
+    ) -> None:
+        self.scanner = BroadcastScanner(device, filter_duplicates, sync_timeout)
+        self.scanner.on('new_broadcast', self.on_new_broadcast)
+        self.scanner.on('broadcast_loss', self.on_broadcast_loss)
+        self.scanner.on('update', self.refresh)
+        self.status_message = ''
+
+    async def start(self) -> None:
+        self.status_message = color('Scanning...', 'green')
+        await self.scanner.start()
+
+    def on_new_broadcast(self, broadcast: BroadcastScanner.Broadcast) -> None:
+        self.status_message = color(
+            f'+Found {len(self.scanner.broadcasts)} broadcasts', 'green'
+        )
+        broadcast.on('change', self.refresh)
+        broadcast.on('update', self.refresh)
+        self.refresh()
+
+    def on_broadcast_loss(self, broadcast: BroadcastScanner.Broadcast) -> None:
+        self.status_message = color(
+            f'-Found {len(self.scanner.broadcasts)} broadcasts', 'green'
+        )
+        self.refresh()
+
+    def refresh(self) -> None:
+        # Clear the screen from the top
+        print('\033[H')
+        print('\033[0J')
+        print('\033[H')
+
+        # Print the status message
+        print(self.status_message)
+        print("==========================================")
+
+        # Print all broadcasts
+        for broadcast in self.scanner.broadcasts.values():
+            broadcast.print()
+            print('------------------------------------------')
+
+        # Clear the screen to the bottom
+        print('\033[0J')
+
+
+@contextlib.asynccontextmanager
+async def create_device(transport: str) -> AsyncGenerator[bumble.device.Device, Any]:
+    async with await bumble.transport.open_transport(transport) as (
+        hci_source,
+        hci_sink,
+    ):
+        device_config = bumble.device.DeviceConfiguration(
+            name=AURACAST_DEFAULT_DEVICE_NAME,
+            address=AURACAST_DEFAULT_DEVICE_ADDRESS,
+            keystore='JsonKeyStore',
+        )
+
+        device = bumble.device.Device.from_config_with_hci(
+            device_config,
+            hci_source,
+            hci_sink,
+        )
+        await device.power_on()
+
+        yield device
+
+
+async def find_broadcast_by_name(
+    device: bumble.device.Device, name: Optional[str]
+) -> BroadcastScanner.Broadcast:
+    result = asyncio.get_running_loop().create_future()
+
+    def on_broadcast_change(broadcast: BroadcastScanner.Broadcast) -> None:
+        if broadcast.basic_audio_announcement and not result.done():
+            print(color('Broadcast basic audio announcement received', 'green'))
+            result.set_result(broadcast)
+
+    def on_new_broadcast(broadcast: BroadcastScanner.Broadcast) -> None:
+        if name is None or broadcast.name == name:
+            print(color('Broadcast found:', 'green'), broadcast.name)
+            broadcast.on('change', lambda: on_broadcast_change(broadcast))
+            return
+
+        print(color(f'Skipping broadcast {broadcast.name}'))
+
+    scanner = BroadcastScanner(device, False, AURACAST_DEFAULT_SYNC_TIMEOUT)
+    scanner.on('new_broadcast', on_new_broadcast)
+    await scanner.start()
+
+    broadcast = await result
+    await scanner.stop()
+
+    return broadcast
+
+
+async def run_scan(
+    filter_duplicates: bool, sync_timeout: float, transport: str
+) -> None:
+    async with create_device(transport) as device:
+        if not device.supports_le_periodic_advertising:
+            print(color('Periodic advertising not supported', 'red'))
+            return
+
+        scanner = PrintingBroadcastScanner(device, filter_duplicates, sync_timeout)
+        await scanner.start()
+        await asyncio.get_running_loop().create_future()
+
+
+async def run_assist(
+    broadcast_name: Optional[str],
+    source_id: Optional[int],
+    command: str,
+    transport: str,
+    address: str,
+) -> None:
+    async with create_device(transport) as device:
+        if not device.supports_le_periodic_advertising:
+            print(color('Periodic advertising not supported', 'red'))
+            return
+
+        # Connect to the server
+        print(f'=== Connecting to {address}...')
+        connection = await device.connect(address)
+        peer = bumble.device.Peer(connection)
+        print(f'=== Connected to {peer}')
+
+        print("+++ Encrypting connection...")
+        await peer.connection.encrypt()
+        print("+++ Connection encrypted")
+
+        # Request a larger MTU
+        mtu = AURACAST_DEFAULT_ATT_MTU
+        print(color(f'$$$ Requesting MTU={mtu}', 'yellow'))
+        await peer.request_mtu(mtu)
+
+        # Get the BASS service
+        bass = await peer.discover_service_and_create_proxy(
+            bumble.profiles.bass.BroadcastAudioScanServiceProxy
+        )
+
+        # Check that the service was found
+        if not bass:
+            print(color('!!! Broadcast Audio Scan Service not found', 'red'))
+            return
+
+        # Subscribe to and read the broadcast receive state characteristics
+        for i, broadcast_receive_state in enumerate(bass.broadcast_receive_states):
+            try:
+                await broadcast_receive_state.subscribe(
+                    lambda value, i=i: print(
+                        f"{color(f'Broadcast Receive State Update [{i}]:', 'green')} {value}"
+                    )
+                )
+            except bumble.core.ProtocolError as error:
+                print(
+                    color(
+                        f'!!! Failed to subscribe to Broadcast Receive State characteristic:',
+                        'red',
+                    ),
+                    error,
+                )
+            value = await broadcast_receive_state.read_value()
+            print(
+                f'{color(f"Initial Broadcast Receive State [{i}]:", "green")} {value}'
+            )
+
+        if command == 'monitor-state':
+            await peer.sustain()
+            return
+
+        if command == 'add-source':
+            # Find the requested broadcast
+            await bass.remote_scan_started()
+            if broadcast_name:
+                print(color('Scanning for broadcast:', 'cyan'), broadcast_name)
+            else:
+                print(color('Scanning for any broadcast', 'cyan'))
+            broadcast = await find_broadcast_by_name(device, broadcast_name)
+
+            if broadcast.broadcast_audio_announcement is None:
+                print(color('No broadcast audio announcement found', 'red'))
+                return
+
+            if (
+                broadcast.basic_audio_announcement is None
+                or not broadcast.basic_audio_announcement.subgroups
+            ):
+                print(color('No subgroups found', 'red'))
+                return
+
+            # Add the source
+            print(color('Adding source:', 'blue'), broadcast.sync.advertiser_address)
+            await bass.add_source(
+                broadcast.sync.advertiser_address,
+                broadcast.sync.sid,
+                broadcast.broadcast_audio_announcement.broadcast_id,
+                bumble.profiles.bass.PeriodicAdvertisingSyncParams.SYNCHRONIZE_TO_PA_PAST_AVAILABLE,
+                0xFFFF,
+                [
+                    bumble.profiles.bass.SubgroupInfo(
+                        bumble.profiles.bass.SubgroupInfo.ANY_BIS,
+                        bytes(broadcast.basic_audio_announcement.subgroups[0].metadata),
+                    )
+                ],
+            )
+
+            # Initiate a PA Sync Transfer
+            await broadcast.sync.transfer(peer.connection)
+
+            # Notify the sink that we're done scanning.
+            await bass.remote_scan_stopped()
+
+            await peer.sustain()
+            return
+
+        if command == 'modify-source':
+            if source_id is None:
+                print(color('!!! modify-source requires --source-id'))
+                return
+
+            # Find the requested broadcast
+            await bass.remote_scan_started()
+            if broadcast_name:
+                print(color('Scanning for broadcast:', 'cyan'), broadcast_name)
+            else:
+                print(color('Scanning for any broadcast', 'cyan'))
+            broadcast = await find_broadcast_by_name(device, broadcast_name)
+
+            if broadcast.broadcast_audio_announcement is None:
+                print(color('No broadcast audio announcement found', 'red'))
+                return
+
+            if (
+                broadcast.basic_audio_announcement is None
+                or not broadcast.basic_audio_announcement.subgroups
+            ):
+                print(color('No subgroups found', 'red'))
+                return
+
+            # Modify the source
+            print(
+                color('Modifying source:', 'blue'),
+                source_id,
+            )
+            await bass.modify_source(
+                source_id,
+                bumble.profiles.bass.PeriodicAdvertisingSyncParams.SYNCHRONIZE_TO_PA_PAST_NOT_AVAILABLE,
+                0xFFFF,
+                [
+                    bumble.profiles.bass.SubgroupInfo(
+                        bumble.profiles.bass.SubgroupInfo.ANY_BIS,
+                        bytes(broadcast.basic_audio_announcement.subgroups[0].metadata),
+                    )
+                ],
+            )
+            await peer.sustain()
+            return
+
+        if command == 'remove-source':
+            if source_id is None:
+                print(color('!!! remove-source requires --source-id'))
+                return
+
+            # Remove the source
+            print(color('Removing source:', 'blue'), source_id)
+            await bass.remove_source(source_id)
+            await peer.sustain()
+            return
+
+        print(color(f'!!! invalid command {command}'))
+
+
+async def run_pair(transport: str, address: str) -> None:
+    async with create_device(transport) as device:
+
+        # Connect to the server
+        print(f'=== Connecting to {address}...')
+        async with device.connect_as_gatt(address) as peer:
+            print(f'=== Connected to {peer}')
+
+            print("+++ Initiating pairing...")
+            await peer.connection.pair()
+            print("+++ Paired")
+
+
+def run_async(async_command: Coroutine) -> None:
+    try:
+        asyncio.run(async_command)
+    except bumble.core.ProtocolError as error:
+        if error.error_namespace == 'att' and error.error_code in list(
+            bumble.profiles.bass.ApplicationError
+        ):
+            message = bumble.profiles.bass.ApplicationError(error.error_code).name
+        else:
+            message = str(error)
+
+        print(
+            color('!!! An error occurred while executing the command:', 'red'), message
+        )
+
+
+# -----------------------------------------------------------------------------
+# Main
+# -----------------------------------------------------------------------------
+@click.group()
+@click.pass_context
+def auracast(
+    ctx,
+):
+    ctx.ensure_object(dict)
+
+
+@auracast.command('scan')
+@click.option(
+    '--filter-duplicates', is_flag=True, default=False, help='Filter duplicates'
+)
+@click.option(
+    '--sync-timeout',
+    metavar='SYNC_TIMEOUT',
+    type=float,
+    default=AURACAST_DEFAULT_SYNC_TIMEOUT,
+    help='Sync timeout (in seconds)',
+)
+@click.argument('transport')
+@click.pass_context
+def scan(ctx, filter_duplicates, sync_timeout, transport):
+    """Scan for public broadcasts"""
+    run_async(run_scan(filter_duplicates, sync_timeout, transport))
+
+
+@auracast.command('assist')
+@click.option(
+    '--broadcast-name',
+    metavar='BROADCAST_NAME',
+    help='Broadcast Name to tune to',
+)
+@click.option(
+    '--source-id',
+    metavar='SOURCE_ID',
+    type=int,
+    help='Source ID (for remove-source command)',
+)
+@click.option(
+    '--command',
+    type=click.Choice(
+        ['monitor-state', 'add-source', 'modify-source', 'remove-source']
+    ),
+    required=True,
+)
+@click.argument('transport')
+@click.argument('address')
+@click.pass_context
+def assist(ctx, broadcast_name, source_id, command, transport, address):
+    """Scan for broadcasts on behalf of a audio server"""
+    run_async(run_assist(broadcast_name, source_id, command, transport, address))
+
+
+@auracast.command('pair')
+@click.argument('transport')
+@click.argument('address')
+@click.pass_context
+def pair(ctx, transport, address):
+    """Pair with an audio server"""
+    run_async(run_pair(transport, address))
+
+
+def main():
+    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
+    auracast()
+
+
+# -----------------------------------------------------------------------------
+if __name__ == "__main__":
+    main()  # pylint: disable=no-value-for-parameter
diff --git a/apps/bench.py b/apps/bench.py
index f0e8b58..0e5addb 100644
--- a/apps/bench.py
+++ b/apps/bench.py
@@ -40,6 +40,8 @@ from bumble.hci import (
     HCI_LE_1M_PHY,
     HCI_LE_2M_PHY,
     HCI_LE_CODED_PHY,
+    HCI_CENTRAL_ROLE,
+    HCI_PERIPHERAL_ROLE,
     HCI_Constant,
     HCI_Error,
     HCI_StatusError,
@@ -57,6 +59,7 @@ from bumble.transport import open_transport_or_link
 import bumble.rfcomm
 import bumble.core
 from bumble.utils import AsyncRunner
+from bumble.pairing import PairingConfig
 
 
 # -----------------------------------------------------------------------------
@@ -128,40 +131,34 @@ def le_phy_name(phy_id):
 
 
 def print_connection(connection):
+    params = []
     if connection.transport == BT_LE_TRANSPORT:
-        phy_state = (
+        params.append(
             'PHY='
             f'TX:{le_phy_name(connection.phy.tx_phy)}/'
             f'RX:{le_phy_name(connection.phy.rx_phy)}'
         )
 
-        data_length = (
+        params.append(
             'DL=('
             f'TX:{connection.data_length[0]}/{connection.data_length[1]},'
             f'RX:{connection.data_length[2]}/{connection.data_length[3]}'
             ')'
         )
-        connection_parameters = (
+
+        params.append(
             'Parameters='
             f'{connection.parameters.connection_interval * 1.25:.2f}/'
             f'{connection.parameters.peripheral_latency}/'
             f'{connection.parameters.supervision_timeout * 10} '
         )
 
-    else:
-        phy_state = ''
-        data_length = ''
-        connection_parameters = ''
+        params.append(f'MTU={connection.att_mtu}')
 
-    mtu = connection.att_mtu
+    else:
+        params.append(f'Role={HCI_Constant.role_name(connection.role)}')
 
-    logging.info(
-        f'{color("@@@ Connection:", "yellow")} '
-        f'{connection_parameters} '
-        f'{data_length} '
-        f'{phy_state} '
-        f'MTU={mtu}'
-    )
+    logging.info(color('@@@ Connection: ', 'yellow') + ' '.join(params))
 
 
 def make_sdp_records(channel):
@@ -214,6 +211,17 @@ def log_stats(title, stats):
     )
 
 
+async def switch_roles(connection, role):
+    target_role = HCI_CENTRAL_ROLE if role == "central" else HCI_PERIPHERAL_ROLE
+    if connection.role != target_role:
+        logging.info(f'{color("### Switching roles to:", "cyan")} {role}')
+        try:
+            await connection.switch_role(target_role)
+            logging.info(color('### Role switch complete', 'cyan'))
+        except HCI_Error as error:
+            logging.info(f'{color("### Role switch failed:", "red")} {error}')
+
+
 class PacketType(enum.IntEnum):
     RESET = 0
     SEQUENCE = 1
@@ -1034,6 +1042,10 @@ class RfcommServer(StreamedPacketIO):
 
     def on_dlc(self, dlc):
         logging.info(color(f'*** DLC connected: {dlc}', 'blue'))
+        if self.credits_threshold is not None:
+            dlc.rx_threshold = self.credits_threshold
+        if self.max_credits is not None:
+            dlc.rx_max_credits = self.max_credits
         dlc.sink = self.on_packet
         self.io_sink = dlc.write
         self.dlc = dlc
@@ -1063,6 +1075,7 @@ class Central(Connection.Listener):
         authenticate,
         encrypt,
         extended_data_length,
+        role_switch,
     ):
         super().__init__()
         self.transport = transport
@@ -1073,6 +1086,7 @@ class Central(Connection.Listener):
         self.authenticate = authenticate
         self.encrypt = encrypt or authenticate
         self.extended_data_length = extended_data_length
+        self.role_switch = role_switch
         self.device = None
         self.connection = None
 
@@ -1123,6 +1137,11 @@ class Central(Connection.Listener):
             role = self.role_factory(mode)
             self.device.classic_enabled = self.classic
 
+            # Set up a pairing config factory with minimal requirements.
+            self.device.pairing_config_factory = lambda _: PairingConfig(
+                sc=False, mitm=False, bonding=False
+            )
+
             await self.device.power_on()
 
             if self.classic:
@@ -1151,6 +1170,10 @@ class Central(Connection.Listener):
             self.connection.listener = self
             print_connection(self.connection)
 
+            # Switch roles if needed.
+            if self.role_switch:
+                await switch_roles(self.connection, self.role_switch)
+
             # Wait a bit after the connection, some controllers aren't very good when
             # we start sending data right away while some connection parameters are
             # updated post connection
@@ -1212,20 +1235,30 @@ class Central(Connection.Listener):
     def on_connection_data_length_change(self):
         print_connection(self.connection)
 
+    def on_role_change(self):
+        print_connection(self.connection)
+
 
 # -----------------------------------------------------------------------------
 # Peripheral
 # -----------------------------------------------------------------------------
 class Peripheral(Device.Listener, Connection.Listener):
     def __init__(
-        self, transport, classic, extended_data_length, role_factory, mode_factory
+        self,
+        transport,
+        role_factory,
+        mode_factory,
+        classic,
+        extended_data_length,
+        role_switch,
     ):
         self.transport = transport
         self.classic = classic
-        self.extended_data_length = extended_data_length
         self.role_factory = role_factory
-        self.role = None
         self.mode_factory = mode_factory
+        self.extended_data_length = extended_data_length
+        self.role_switch = role_switch
+        self.role = None
         self.mode = None
         self.device = None
         self.connection = None
@@ -1248,6 +1281,11 @@ class Peripheral(Device.Listener, Connection.Listener):
             self.role = self.role_factory(self.mode)
             self.device.classic_enabled = self.classic
 
+            # Set up a pairing config factory with minimal requirements.
+            self.device.pairing_config_factory = lambda _: PairingConfig(
+                sc=False, mitm=False, bonding=False
+            )
+
             await self.device.power_on()
 
             if self.classic:
@@ -1274,6 +1312,7 @@ class Peripheral(Device.Listener, Connection.Listener):
 
             await self.connected.wait()
             logging.info(color('### Connected', 'cyan'))
+            print_connection(self.connection)
 
             await self.mode.on_connection(self.connection)
             await self.role.run()
@@ -1290,7 +1329,7 @@ class Peripheral(Device.Listener, Connection.Listener):
             AsyncRunner.spawn(self.device.set_connectable(False))
 
         # Request a new data length if needed
-        if self.extended_data_length:
+        if not self.classic and self.extended_data_length:
             logging.info("+++ Requesting extended data length")
             AsyncRunner.spawn(
                 connection.set_data_length(
@@ -1298,6 +1337,10 @@ class Peripheral(Device.Listener, Connection.Listener):
                 )
             )
 
+        # Switch roles if needed.
+        if self.role_switch:
+            AsyncRunner.spawn(switch_roles(connection, self.role_switch))
+
     def on_disconnection(self, reason):
         logging.info(color(f'!!! Disconnection: reason={reason}', 'red'))
         self.connection = None
@@ -1319,6 +1362,9 @@ class Peripheral(Device.Listener, Connection.Listener):
     def on_connection_data_length_change(self):
         print_connection(self.connection)
 
+    def on_role_change(self):
+        print_connection(self.connection)
+
 
 # -----------------------------------------------------------------------------
 def create_mode_factory(ctx, default_mode):
@@ -1448,6 +1494,11 @@ def create_role_factory(ctx, default_role):
     '--extended-data-length',
     help='Request a data length upon connection, specified as tx_octets/tx_time',
 )
+@click.option(
+    '--role-switch',
+    type=click.Choice(['central', 'peripheral']),
+    help='Request role switch upon connection (central or peripheral)',
+)
 @click.option(
     '--rfcomm-channel',
     type=int,
@@ -1512,7 +1563,7 @@ def create_role_factory(ctx, default_role):
     '--packet-size',
     '-s',
     metavar='SIZE',
-    type=click.IntRange(8, 4096),
+    type=click.IntRange(8, 8192),
     default=500,
     help='Packet size (client or ping role)',
 )
@@ -1572,6 +1623,7 @@ def bench(
     mode,
     att_mtu,
     extended_data_length,
+    role_switch,
     packet_size,
     packet_count,
     start_delay,
@@ -1614,12 +1666,12 @@ def bench(
     ctx.obj['repeat_delay'] = repeat_delay
     ctx.obj['pace'] = pace
     ctx.obj['linger'] = linger
-
     ctx.obj['extended_data_length'] = (
         [int(x) for x in extended_data_length.split('/')]
         if extended_data_length
         else None
     )
+    ctx.obj['role_switch'] = role_switch
     ctx.obj['classic'] = mode in ('rfcomm-client', 'rfcomm-server')
 
 
@@ -1663,6 +1715,7 @@ def central(
             authenticate,
             encrypt or authenticate,
             ctx.obj['extended_data_length'],
+            ctx.obj['role_switch'],
         ).run()
 
     asyncio.run(run_central())
@@ -1679,10 +1732,11 @@ def peripheral(ctx, transport):
     async def run_peripheral():
         await Peripheral(
             transport,
-            ctx.obj['classic'],
-            ctx.obj['extended_data_length'],
             role_factory,
             mode_factory,
+            ctx.obj['classic'],
+            ctx.obj['extended_data_length'],
+            ctx.obj['role_switch'],
         ).run()
 
     asyncio.run(run_peripheral())
diff --git a/apps/console.py b/apps/console.py
index 5d04636..e942321 100644
--- a/apps/console.py
+++ b/apps/console.py
@@ -63,6 +63,7 @@ from bumble.transport import open_transport_or_link
 from bumble.gatt import Characteristic, Service, CharacteristicDeclaration, Descriptor
 from bumble.gatt_client import CharacteristicProxy
 from bumble.hci import (
+    Address,
     HCI_Constant,
     HCI_LE_1M_PHY,
     HCI_LE_2M_PHY,
@@ -289,11 +290,7 @@ class ConsoleApp:
                     device_config, hci_source, hci_sink
                 )
             else:
-                random_address = (
-                    f"{random.randint(192,255):02X}"  # address is static random
-                )
-                for random_byte in random.sample(range(255), 5):
-                    random_address += f":{random_byte:02X}"
+                random_address = Address.generate_static_address()
                 self.append_to_log(f"Setting random address: {random_address}")
                 self.device = Device.with_hci(
                     'Bumble', random_address, hci_source, hci_sink
@@ -503,21 +500,9 @@ class ConsoleApp:
             self.show_error('not connected')
             return
 
-        # Discover all services, characteristics and descriptors
-        self.append_to_output('discovering services...')
-        await self.connected_peer.discover_services()
-        self.append_to_output(
-            f'found {len(self.connected_peer.services)} services,'
-            ' discovering characteristics...'
-        )
-        await self.connected_peer.discover_characteristics()
-        self.append_to_output('found characteristics, discovering descriptors...')
-        for service in self.connected_peer.services:
-            for characteristic in service.characteristics:
-                await self.connected_peer.discover_descriptors(characteristic)
-        self.append_to_output('discovery completed')
-
-        self.show_remote_services(self.connected_peer.services)
+        self.append_to_output('Service Discovery starting...')
+        await self.connected_peer.discover_all()
+        self.append_to_output('Service Discovery done!')
 
     async def discover_attributes(self):
         if not self.connected_peer:
diff --git a/apps/controller_info.py b/apps/controller_info.py
index 83ac3bb..7cf3332 100644
--- a/apps/controller_info.py
+++ b/apps/controller_info.py
@@ -27,7 +27,7 @@ from bumble.colors import color
 from bumble.core import name_or_number
 from bumble.hci import (
     map_null_terminated_utf8_string,
-    LeFeatureMask,
+    LeFeature,
     HCI_SUCCESS,
     HCI_VERSION_NAMES,
     LMP_VERSION_NAMES,
@@ -140,7 +140,7 @@ async def get_le_info(host: Host) -> None:
 
     print(color('LE Features:', 'yellow'))
     for feature in host.supported_le_features:
-        print(LeFeatureMask(feature).name)
+        print(f'  {LeFeature(feature).name}')
 
 
 # -----------------------------------------------------------------------------
@@ -224,7 +224,7 @@ async def async_main(latency_probes, transport):
         print()
         print(color('Supported Commands:', 'yellow'))
         for command in host.supported_commands:
-            print('  ', HCI_Command.command_name(command))
+            print(f'  {HCI_Command.command_name(command)}')
 
 
 # -----------------------------------------------------------------------------
diff --git a/apps/device_info.py b/apps/device_info.py
new file mode 100644
index 0000000..df18c65
--- /dev/null
+++ b/apps/device_info.py
@@ -0,0 +1,230 @@
+# Copyright 2021-2022 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+import asyncio
+import os
+import logging
+from typing import Callable, Iterable, Optional
+
+import click
+
+from bumble.core import ProtocolError
+from bumble.colors import color
+from bumble.device import Device, Peer
+from bumble.gatt import Service
+from bumble.profiles.device_information_service import DeviceInformationServiceProxy
+from bumble.profiles.battery_service import BatteryServiceProxy
+from bumble.profiles.gap import GenericAccessServiceProxy
+from bumble.profiles.tmap import TelephonyAndMediaAudioServiceProxy
+from bumble.transport import open_transport_or_link
+
+
+# -----------------------------------------------------------------------------
+async def try_show(function: Callable, *args, **kwargs) -> None:
+    try:
+        await function(*args, **kwargs)
+    except ProtocolError as error:
+        print(color('ERROR:', 'red'), error)
+
+
+# -----------------------------------------------------------------------------
+def show_services(services: Iterable[Service]) -> None:
+    for service in services:
+        print(color(str(service), 'cyan'))
+
+        for characteristic in service.characteristics:
+            print(color('  ' + str(characteristic), 'magenta'))
+
+
+# -----------------------------------------------------------------------------
+async def show_gap_information(
+    gap_service: GenericAccessServiceProxy,
+):
+    print(color('### Generic Access Profile', 'yellow'))
+
+    if gap_service.device_name:
+        print(
+            color(' Device Name:', 'green'),
+            await gap_service.device_name.read_value(),
+        )
+
+    if gap_service.appearance:
+        print(
+            color(' Appearance: ', 'green'),
+            await gap_service.appearance.read_value(),
+        )
+
+    print()
+
+
+# -----------------------------------------------------------------------------
+async def show_device_information(
+    device_information_service: DeviceInformationServiceProxy,
+):
+    print(color('### Device Information', 'yellow'))
+
+    if device_information_service.manufacturer_name:
+        print(
+            color('  Manufacturer Name:', 'green'),
+            await device_information_service.manufacturer_name.read_value(),
+        )
+
+    if device_information_service.model_number:
+        print(
+            color('  Model Number:     ', 'green'),
+            await device_information_service.model_number.read_value(),
+        )
+
+    if device_information_service.serial_number:
+        print(
+            color('  Serial Number:    ', 'green'),
+            await device_information_service.serial_number.read_value(),
+        )
+
+    if device_information_service.firmware_revision:
+        print(
+            color('  Firmware Revision:', 'green'),
+            await device_information_service.firmware_revision.read_value(),
+        )
+
+    print()
+
+
+# -----------------------------------------------------------------------------
+async def show_battery_level(
+    battery_service: BatteryServiceProxy,
+):
+    print(color('### Battery Information', 'yellow'))
+
+    if battery_service.battery_level:
+        print(
+            color('  Battery Level:', 'green'),
+            await battery_service.battery_level.read_value(),
+        )
+
+    print()
+
+
+# -----------------------------------------------------------------------------
+async def show_tmas(
+    tmas: TelephonyAndMediaAudioServiceProxy,
+):
+    print(color('### Telephony And Media Audio Service', 'yellow'))
+
+    if tmas.role:
+        print(
+            color('  Role:', 'green'),
+            await tmas.role.read_value(),
+        )
+
+    print()
+
+
+# -----------------------------------------------------------------------------
+async def show_device_info(peer, done: Optional[asyncio.Future]) -> None:
+    try:
+        # Discover all services
+        print(color('### Discovering Services and Characteristics', 'magenta'))
+        await peer.discover_services()
+        for service in peer.services:
+            await service.discover_characteristics()
+
+        print(color('=== Services ===', 'yellow'))
+        show_services(peer.services)
+        print()
+
+        if gap_service := peer.create_service_proxy(GenericAccessServiceProxy):
+            await try_show(show_gap_information, gap_service)
+
+        if device_information_service := peer.create_service_proxy(
+            DeviceInformationServiceProxy
+        ):
+            await try_show(show_device_information, device_information_service)
+
+        if battery_service := peer.create_service_proxy(BatteryServiceProxy):
+            await try_show(show_battery_level, battery_service)
+
+        if tmas := peer.create_service_proxy(TelephonyAndMediaAudioServiceProxy):
+            await try_show(show_tmas, tmas)
+
+        if done is not None:
+            done.set_result(None)
+    except asyncio.CancelledError:
+        print(color('!!! Operation canceled', 'red'))
+
+
+# -----------------------------------------------------------------------------
+async def async_main(device_config, encrypt, transport, address_or_name):
+    async with await open_transport_or_link(transport) as (hci_source, hci_sink):
+
+        # Create a device
+        if device_config:
+            device = Device.from_config_file_with_hci(
+                device_config, hci_source, hci_sink
+            )
+        else:
+            device = Device.with_hci(
+                'Bumble', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink
+            )
+        await device.power_on()
+
+        if address_or_name:
+            # Connect to the target peer
+            print(color('>>> Connecting...', 'green'))
+            connection = await device.connect(address_or_name)
+            print(color('>>> Connected', 'green'))
+
+            # Encrypt the connection if required
+            if encrypt:
+                print(color('+++ Encrypting connection...', 'blue'))
+                await connection.encrypt()
+                print(color('+++ Encryption established', 'blue'))
+
+            await show_device_info(Peer(connection), None)
+        else:
+            # Wait for a connection
+            done = asyncio.get_running_loop().create_future()
+            device.on(
+                'connection',
+                lambda connection: asyncio.create_task(
+                    show_device_info(Peer(connection), done)
+                ),
+            )
+            await device.start_advertising(auto_restart=True)
+
+            print(color('### Waiting for connection...', 'blue'))
+            await done
+
+
+# -----------------------------------------------------------------------------
+@click.command()
+@click.option('--device-config', help='Device configuration', type=click.Path())
+@click.option('--encrypt', help='Encrypt the connection', is_flag=True, default=False)
+@click.argument('transport')
+@click.argument('address-or-name', required=False)
+def main(device_config, encrypt, transport, address_or_name):
+    """
+    Dump the GATT database on a remote device. If ADDRESS_OR_NAME is not specified,
+    wait for an incoming connection.
+    """
+    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
+    asyncio.run(async_main(device_config, encrypt, transport, address_or_name))
+
+
+# -----------------------------------------------------------------------------
+if __name__ == '__main__':
+    main()
diff --git a/apps/gatt_dump.py b/apps/gatt_dump.py
index a3205c0..3b3e874 100644
--- a/apps/gatt_dump.py
+++ b/apps/gatt_dump.py
@@ -75,11 +75,15 @@ async def async_main(device_config, encrypt, transport, address_or_name):
 
         if address_or_name:
             # Connect to the target peer
+            print(color('>>> Connecting...', 'green'))
             connection = await device.connect(address_or_name)
+            print(color('>>> Connected', 'green'))
 
             # Encrypt the connection if required
             if encrypt:
+                print(color('+++ Encrypting connection...', 'blue'))
                 await connection.encrypt()
+                print(color('+++ Encryption established', 'blue'))
 
             await dump_gatt_db(Peer(connection), None)
         else:
diff --git a/apps/lea_unicast/app.py b/apps/lea_unicast/app.py
index ae3b442..5885dab 100644
--- a/apps/lea_unicast/app.py
+++ b/apps/lea_unicast/app.py
@@ -33,7 +33,6 @@ import ctypes
 import wasmtime
 import wasmtime.loader
 import liblc3  # type: ignore
-import logging
 
 import click
 import aiohttp.web
@@ -43,7 +42,7 @@ from bumble.core import AdvertisingData
 from bumble.colors import color
 from bumble.device import Device, DeviceConfiguration, AdvertisingParameters
 from bumble.transport import open_transport
-from bumble.profiles import bap
+from bumble.profiles import ascs, bap, pacs
 from bumble.hci import Address, CodecID, CodingFormat, HCI_IsoDataPacket
 
 # -----------------------------------------------------------------------------
@@ -57,8 +56,8 @@ logger = logging.getLogger(__name__)
 DEFAULT_UI_PORT = 7654
 
 
-def _sink_pac_record() -> bap.PacRecord:
-    return bap.PacRecord(
+def _sink_pac_record() -> pacs.PacRecord:
+    return pacs.PacRecord(
         coding_format=CodingFormat(CodecID.LC3),
         codec_specific_capabilities=bap.CodecSpecificCapabilities(
             supported_sampling_frequencies=(
@@ -79,8 +78,8 @@ def _sink_pac_record() -> bap.PacRecord:
     )
 
 
-def _source_pac_record() -> bap.PacRecord:
-    return bap.PacRecord(
+def _source_pac_record() -> pacs.PacRecord:
+    return pacs.PacRecord(
         coding_format=CodingFormat(CodecID.LC3),
         codec_specific_capabilities=bap.CodecSpecificCapabilities(
             supported_sampling_frequencies=(
@@ -447,7 +446,7 @@ class Speaker:
             )
 
             self.device.add_service(
-                bap.PublishedAudioCapabilitiesService(
+                pacs.PublishedAudioCapabilitiesService(
                     supported_source_context=bap.ContextType(0xFFFF),
                     available_source_context=bap.ContextType(0xFFFF),
                     supported_sink_context=bap.ContextType(0xFFFF),  # All context types
@@ -461,10 +460,10 @@ class Speaker:
                 )
             )
 
-            ascs = bap.AudioStreamControlService(
+            ascs_service = ascs.AudioStreamControlService(
                 self.device, sink_ase_id=[1], source_ase_id=[2]
             )
-            self.device.add_service(ascs)
+            self.device.add_service(ascs_service)
 
             advertising_data = bytes(
                 AdvertisingData(
@@ -479,13 +478,13 @@ class Speaker:
                         ),
                         (
                             AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
-                            bytes(bap.PublishedAudioCapabilitiesService.UUID),
+                            bytes(pacs.PublishedAudioCapabilitiesService.UUID),
                         ),
                     ]
                 )
             ) + bytes(bap.UnicastServerAdvertisingData())
 
-            def on_pdu(pdu: HCI_IsoDataPacket, ase: bap.AseStateMachine):
+            def on_pdu(pdu: HCI_IsoDataPacket, ase: ascs.AseStateMachine):
                 codec_config = ase.codec_specific_configuration
                 assert isinstance(codec_config, bap.CodecSpecificConfiguration)
                 pcm = decode(
@@ -495,12 +494,12 @@ class Speaker:
                 )
                 self.device.abort_on('disconnection', self.ui_server.send_audio(pcm))
 
-            def on_ase_state_change(ase: bap.AseStateMachine) -> None:
-                if ase.state == bap.AseStateMachine.State.STREAMING:
+            def on_ase_state_change(ase: ascs.AseStateMachine) -> None:
+                if ase.state == ascs.AseStateMachine.State.STREAMING:
                     codec_config = ase.codec_specific_configuration
                     assert isinstance(codec_config, bap.CodecSpecificConfiguration)
                     assert ase.cis_link
-                    if ase.role == bap.AudioRole.SOURCE:
+                    if ase.role == ascs.AudioRole.SOURCE:
                         ase.cis_link.abort_on(
                             'disconnection',
                             lc3_source_task(
@@ -516,10 +515,10 @@ class Speaker:
                         )
                     else:
                         ase.cis_link.sink = functools.partial(on_pdu, ase=ase)
-                elif ase.state == bap.AseStateMachine.State.CODEC_CONFIGURED:
+                elif ase.state == ascs.AseStateMachine.State.CODEC_CONFIGURED:
                     codec_config = ase.codec_specific_configuration
                     assert isinstance(codec_config, bap.CodecSpecificConfiguration)
-                    if ase.role == bap.AudioRole.SOURCE:
+                    if ase.role == ascs.AudioRole.SOURCE:
                         setup_encoders(
                             codec_config.sampling_frequency.hz,
                             codec_config.frame_duration.us,
@@ -532,7 +531,7 @@ class Speaker:
                             codec_config.audio_channel_allocation.channel_count,
                         )
 
-            for ase in ascs.ase_state_machines.values():
+            for ase in ascs_service.ase_state_machines.values():
                 ase.on('state_change', functools.partial(on_ase_state_change, ase=ase))
 
             await self.device.power_on()
diff --git a/apps/pair.py b/apps/pair.py
index c1ea332..67eec90 100644
--- a/apps/pair.py
+++ b/apps/pair.py
@@ -46,6 +46,12 @@ from bumble.att import (
     ATT_INSUFFICIENT_AUTHENTICATION_ERROR,
     ATT_INSUFFICIENT_ENCRYPTION_ERROR,
 )
+from bumble.utils import AsyncRunner
+
+# -----------------------------------------------------------------------------
+# Constants
+# -----------------------------------------------------------------------------
+POST_PAIRING_DELAY = 1
 
 
 # -----------------------------------------------------------------------------
@@ -235,8 +241,10 @@ def on_connection(connection, request):
 
     # Listen for pairing events
     connection.on('pairing_start', on_pairing_start)
-    connection.on('pairing', lambda keys: on_pairing(connection.peer_address, keys))
-    connection.on('pairing_failure', on_pairing_failure)
+    connection.on('pairing', lambda keys: on_pairing(connection, keys))
+    connection.on(
+        'pairing_failure', lambda reason: on_pairing_failure(connection, reason)
+    )
 
     # Listen for encryption changes
     connection.on(
@@ -270,19 +278,24 @@ def on_pairing_start():
 
 
 # -----------------------------------------------------------------------------
-def on_pairing(address, keys):
+@AsyncRunner.run_in_task()
+async def on_pairing(connection, keys):
     print(color('***-----------------------------------', 'cyan'))
-    print(color(f'*** Paired! (peer identity={address})', 'cyan'))
+    print(color(f'*** Paired! (peer identity={connection.peer_address})', 'cyan'))
     keys.print(prefix=color('*** ', 'cyan'))
     print(color('***-----------------------------------', 'cyan'))
+    await asyncio.sleep(POST_PAIRING_DELAY)
+    await connection.disconnect()
     Waiter.instance.terminate()
 
 
 # -----------------------------------------------------------------------------
-def on_pairing_failure(reason):
+@AsyncRunner.run_in_task()
+async def on_pairing_failure(connection, reason):
     print(color('***-----------------------------------', 'red'))
     print(color(f'*** Pairing failed: {smp_error_name(reason)}', 'red'))
     print(color('***-----------------------------------', 'red'))
+    await connection.disconnect()
     Waiter.instance.terminate()
 
 
@@ -293,6 +306,7 @@ async def pair(
     mitm,
     bond,
     ctkd,
+    identity_address,
     linger,
     io,
     oob,
@@ -382,11 +396,18 @@ async def pair(
             oob_contexts = None
 
         # Set up a pairing config factory
+        if identity_address == 'public':
+            identity_address_type = PairingConfig.AddressType.PUBLIC
+        elif identity_address == 'random':
+            identity_address_type = PairingConfig.AddressType.RANDOM
+        else:
+            identity_address_type = None
         device.pairing_config_factory = lambda connection: PairingConfig(
             sc=sc,
             mitm=mitm,
             bonding=bond,
             oob=oob_contexts,
+            identity_address_type=identity_address_type,
             delegate=Delegate(mode, connection, io, prompt),
         )
 
@@ -457,6 +478,10 @@ class LogHandler(logging.Handler):
     help='Enable CTKD',
     show_default=True,
 )
+@click.option(
+    '--identity-address',
+    type=click.Choice(['random', 'public']),
+)
 @click.option('--linger', default=False, is_flag=True, help='Linger after pairing')
 @click.option(
     '--io',
@@ -493,6 +518,7 @@ def main(
     mitm,
     bond,
     ctkd,
+    identity_address,
     linger,
     io,
     oob,
@@ -518,6 +544,7 @@ def main(
             mitm,
             bond,
             ctkd,
+            identity_address,
             linger,
             io,
             oob,
diff --git a/bumble/at.py b/bumble/at.py
index 78a4b08..ed9aeed 100644
--- a/bumble/at.py
+++ b/bumble/at.py
@@ -14,13 +14,19 @@
 
 from typing import List, Union
 
+from bumble import core
+
+
+class AtParsingError(core.InvalidPacketError):
+    """Error raised when parsing AT commands fails."""
+
 
 def tokenize_parameters(buffer: bytes) -> List[bytes]:
     """Split input parameters into tokens.
     Removes space characters outside of double quote blocks:
     T-rec-V-25 - 5.2.1 Command line general format: "Space characters (IA5 2/0)
     are ignored [..], unless they are embedded in numeric or string constants"
-    Raises ValueError in case of invalid input string."""
+    Raises AtParsingError in case of invalid input string."""
 
     tokens = []
     in_quotes = False
@@ -43,11 +49,11 @@ def tokenize_parameters(buffer: bytes) -> List[bytes]:
                 token = bytearray()
             elif char == b'(':
                 if len(token) > 0:
-                    raise ValueError("open_paren following regular character")
+                    raise AtParsingError("open_paren following regular character")
                 tokens.append(char)
             elif char == b'"':
                 if len(token) > 0:
-                    raise ValueError("quote following regular character")
+                    raise AtParsingError("quote following regular character")
                 in_quotes = True
                 token.extend(char)
             else:
@@ -59,7 +65,7 @@ def tokenize_parameters(buffer: bytes) -> List[bytes]:
 
 def parse_parameters(buffer: bytes) -> List[Union[bytes, list]]:
     """Parse the parameters using the comma and parenthesis separators.
-    Raises ValueError in case of invalid input string."""
+    Raises AtParsingError in case of invalid input string."""
 
     tokens = tokenize_parameters(buffer)
     accumulator: List[list] = [[]]
@@ -73,7 +79,7 @@ def parse_parameters(buffer: bytes) -> List[Union[bytes, list]]:
             accumulator.append([])
         elif token == b')':
             if len(accumulator) < 2:
-                raise ValueError("close_paren without matching open_paren")
+                raise AtParsingError("close_paren without matching open_paren")
             accumulator[-1].append(current)
             current = accumulator.pop()
         else:
@@ -81,5 +87,5 @@ def parse_parameters(buffer: bytes) -> List[Union[bytes, list]]:
 
     accumulator[-1].append(current)
     if len(accumulator) > 1:
-        raise ValueError("missing close_paren")
+        raise AtParsingError("missing close_paren")
     return accumulator[0]
diff --git a/bumble/att.py b/bumble/att.py
index 0fce3ce..6eed040 100644
--- a/bumble/att.py
+++ b/bumble/att.py
@@ -23,6 +23,7 @@
 # Imports
 # -----------------------------------------------------------------------------
 from __future__ import annotations
+
 import enum
 import functools
 import inspect
@@ -41,6 +42,7 @@ from typing import (
 
 from pyee import EventEmitter
 
+from bumble import utils
 from bumble.core import UUID, name_or_number, ProtocolError
 from bumble.hci import HCI_Object, key_with_value
 from bumble.colors import color
@@ -145,43 +147,57 @@ ATT_RESPONSES = [
     ATT_EXECUTE_WRITE_RESPONSE
 ]
 
-ATT_INVALID_HANDLE_ERROR                   = 0x01
-ATT_READ_NOT_PERMITTED_ERROR               = 0x02
-ATT_WRITE_NOT_PERMITTED_ERROR              = 0x03
-ATT_INVALID_PDU_ERROR                      = 0x04
-ATT_INSUFFICIENT_AUTHENTICATION_ERROR      = 0x05
-ATT_REQUEST_NOT_SUPPORTED_ERROR            = 0x06
-ATT_INVALID_OFFSET_ERROR                   = 0x07
-ATT_INSUFFICIENT_AUTHORIZATION_ERROR       = 0x08
-ATT_PREPARE_QUEUE_FULL_ERROR               = 0x09
-ATT_ATTRIBUTE_NOT_FOUND_ERROR              = 0x0A
-ATT_ATTRIBUTE_NOT_LONG_ERROR               = 0x0B
-ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE_ERROR = 0x0C
-ATT_INVALID_ATTRIBUTE_LENGTH_ERROR         = 0x0D
-ATT_UNLIKELY_ERROR_ERROR                   = 0x0E
-ATT_INSUFFICIENT_ENCRYPTION_ERROR          = 0x0F
-ATT_UNSUPPORTED_GROUP_TYPE_ERROR           = 0x10
-ATT_INSUFFICIENT_RESOURCES_ERROR           = 0x11
-
-ATT_ERROR_NAMES = {
-    ATT_INVALID_HANDLE_ERROR:                   'ATT_INVALID_HANDLE_ERROR',
-    ATT_READ_NOT_PERMITTED_ERROR:               'ATT_READ_NOT_PERMITTED_ERROR',
-    ATT_WRITE_NOT_PERMITTED_ERROR:              'ATT_WRITE_NOT_PERMITTED_ERROR',
-    ATT_INVALID_PDU_ERROR:                      'ATT_INVALID_PDU_ERROR',
-    ATT_INSUFFICIENT_AUTHENTICATION_ERROR:      'ATT_INSUFFICIENT_AUTHENTICATION_ERROR',
-    ATT_REQUEST_NOT_SUPPORTED_ERROR:            'ATT_REQUEST_NOT_SUPPORTED_ERROR',
-    ATT_INVALID_OFFSET_ERROR:                   'ATT_INVALID_OFFSET_ERROR',
-    ATT_INSUFFICIENT_AUTHORIZATION_ERROR:       'ATT_INSUFFICIENT_AUTHORIZATION_ERROR',
-    ATT_PREPARE_QUEUE_FULL_ERROR:               'ATT_PREPARE_QUEUE_FULL_ERROR',
-    ATT_ATTRIBUTE_NOT_FOUND_ERROR:              'ATT_ATTRIBUTE_NOT_FOUND_ERROR',
-    ATT_ATTRIBUTE_NOT_LONG_ERROR:               'ATT_ATTRIBUTE_NOT_LONG_ERROR',
-    ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE_ERROR: 'ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE_ERROR',
-    ATT_INVALID_ATTRIBUTE_LENGTH_ERROR:         'ATT_INVALID_ATTRIBUTE_LENGTH_ERROR',
-    ATT_UNLIKELY_ERROR_ERROR:                   'ATT_UNLIKELY_ERROR_ERROR',
-    ATT_INSUFFICIENT_ENCRYPTION_ERROR:          'ATT_INSUFFICIENT_ENCRYPTION_ERROR',
-    ATT_UNSUPPORTED_GROUP_TYPE_ERROR:           'ATT_UNSUPPORTED_GROUP_TYPE_ERROR',
-    ATT_INSUFFICIENT_RESOURCES_ERROR:           'ATT_INSUFFICIENT_RESOURCES_ERROR'
-}
+class ErrorCode(utils.OpenIntEnum):
+    '''
+    See
+
+    * Bluetooth spec @ Vol 3, Part F - 3.4.1.1 Error Response
+    * Core Specification Supplement: Common Profile And Service Error Codes
+    '''
+    INVALID_HANDLE                   = 0x01
+    READ_NOT_PERMITTED               = 0x02
+    WRITE_NOT_PERMITTED              = 0x03
+    INVALID_PDU                      = 0x04
+    INSUFFICIENT_AUTHENTICATION      = 0x05
+    REQUEST_NOT_SUPPORTED            = 0x06
+    INVALID_OFFSET                   = 0x07
+    INSUFFICIENT_AUTHORIZATION       = 0x08
+    PREPARE_QUEUE_FULL               = 0x09
+    ATTRIBUTE_NOT_FOUND              = 0x0A
+    ATTRIBUTE_NOT_LONG               = 0x0B
+    INSUFFICIENT_ENCRYPTION_KEY_SIZE = 0x0C
+    INVALID_ATTRIBUTE_LENGTH         = 0x0D
+    UNLIKELY_ERROR                   = 0x0E
+    INSUFFICIENT_ENCRYPTION          = 0x0F
+    UNSUPPORTED_GROUP_TYPE           = 0x10
+    INSUFFICIENT_RESOURCES           = 0x11
+    DATABASE_OUT_OF_SYNC             = 0x12
+    VALUE_NOT_ALLOWED                = 0x13
+    # 0x80 – 0x9F: Application Error
+    # 0xE0 – 0xFF: Common Profile and Service Error Codes
+    WRITE_REQUEST_REJECTED           = 0xFC
+    CCCD_IMPROPERLY_CONFIGURED       = 0xFD
+    PROCEDURE_ALREADY_IN_PROGRESS    = 0xFE
+    OUT_OF_RANGE                     = 0xFF
+
+# Backward Compatible Constants
+ATT_INVALID_HANDLE_ERROR                   = ErrorCode.INVALID_HANDLE
+ATT_READ_NOT_PERMITTED_ERROR               = ErrorCode.READ_NOT_PERMITTED
+ATT_WRITE_NOT_PERMITTED_ERROR              = ErrorCode.WRITE_NOT_PERMITTED
+ATT_INVALID_PDU_ERROR                      = ErrorCode.INVALID_PDU
+ATT_INSUFFICIENT_AUTHENTICATION_ERROR      = ErrorCode.INSUFFICIENT_AUTHENTICATION
+ATT_REQUEST_NOT_SUPPORTED_ERROR            = ErrorCode.REQUEST_NOT_SUPPORTED
+ATT_INVALID_OFFSET_ERROR                   = ErrorCode.INVALID_OFFSET
+ATT_INSUFFICIENT_AUTHORIZATION_ERROR       = ErrorCode.INSUFFICIENT_AUTHORIZATION
+ATT_PREPARE_QUEUE_FULL_ERROR               = ErrorCode.PREPARE_QUEUE_FULL
+ATT_ATTRIBUTE_NOT_FOUND_ERROR              = ErrorCode.ATTRIBUTE_NOT_FOUND
+ATT_ATTRIBUTE_NOT_LONG_ERROR               = ErrorCode.ATTRIBUTE_NOT_LONG
+ATT_INSUFFICIENT_ENCRYPTION_KEY_SIZE_ERROR = ErrorCode.INSUFFICIENT_ENCRYPTION_KEY_SIZE
+ATT_INVALID_ATTRIBUTE_LENGTH_ERROR         = ErrorCode.INVALID_ATTRIBUTE_LENGTH
+ATT_UNLIKELY_ERROR_ERROR                   = ErrorCode.UNLIKELY_ERROR
+ATT_INSUFFICIENT_ENCRYPTION_ERROR          = ErrorCode.INSUFFICIENT_ENCRYPTION
+ATT_UNSUPPORTED_GROUP_TYPE_ERROR           = ErrorCode.UNSUPPORTED_GROUP_TYPE
+ATT_INSUFFICIENT_RESOURCES_ERROR           = ErrorCode.INSUFFICIENT_RESOURCES
 
 ATT_DEFAULT_MTU = 23
 
@@ -245,9 +261,9 @@ class ATT_PDU:
     def pdu_name(op_code):
         return name_or_number(ATT_PDU_NAMES, op_code, 2)
 
-    @staticmethod
-    def error_name(error_code):
-        return name_or_number(ATT_ERROR_NAMES, error_code, 2)
+    @classmethod
+    def error_name(cls, error_code: int) -> str:
+        return ErrorCode(error_code).name
 
     @staticmethod
     def subclass(fields):
diff --git a/bumble/avc.py b/bumble/avc.py
index 1d0a7dc..8e6b968 100644
--- a/bumble/avc.py
+++ b/bumble/avc.py
@@ -20,6 +20,7 @@ import enum
 import struct
 from typing import Dict, Type, Union, Tuple
 
+from bumble import core
 from bumble.utils import OpenIntEnum
 
 
@@ -88,7 +89,9 @@ class Frame:
             short_name = subclass.__name__.replace("ResponseFrame", "")
             category_class = ResponseFrame
         else:
-            raise ValueError(f"invalid subclass name {subclass.__name__}")
+            raise core.InvalidArgumentError(
+                f"invalid subclass name {subclass.__name__}"
+            )
 
         uppercase_indexes = [
             i for i in range(len(short_name)) if short_name[i].isupper()
@@ -106,7 +109,7 @@ class Frame:
     @staticmethod
     def from_bytes(data: bytes) -> Frame:
         if data[0] >> 4 != 0:
-            raise ValueError("first 4 bits must be 0s")
+            raise core.InvalidPacketError("first 4 bits must be 0s")
 
         ctype_or_response = data[0] & 0xF
         subunit_type = Frame.SubunitType(data[1] >> 3)
@@ -122,7 +125,7 @@ class Frame:
             # Extended to the next byte
             extension = data[2]
             if extension == 0:
-                raise ValueError("extended subunit ID value reserved")
+                raise core.InvalidPacketError("extended subunit ID value reserved")
             if extension == 0xFF:
                 subunit_id = 5 + 254 + data[3]
                 opcode_offset = 4
@@ -131,7 +134,7 @@ class Frame:
                 opcode_offset = 3
 
         elif subunit_id == 6:
-            raise ValueError("reserved subunit ID")
+            raise core.InvalidPacketError("reserved subunit ID")
 
         opcode = Frame.OperationCode(data[opcode_offset])
         operands = data[opcode_offset + 1 :]
@@ -448,7 +451,7 @@ class PassThroughFrame:
         operation_data: bytes,
     ) -> None:
         if len(operation_data) > 255:
-            raise ValueError("operation data must be <= 255 bytes")
+            raise core.InvalidArgumentError("operation data must be <= 255 bytes")
         self.state_flag = state_flag
         self.operation_id = operation_id
         self.operation_data = operation_data
diff --git a/bumble/avctp.py b/bumble/avctp.py
index 2271324..6d70256 100644
--- a/bumble/avctp.py
+++ b/bumble/avctp.py
@@ -23,6 +23,7 @@ from typing import Callable, cast, Dict, Optional
 
 from bumble.colors import color
 from bumble import avc
+from bumble import core
 from bumble import l2cap
 
 # -----------------------------------------------------------------------------
@@ -275,7 +276,7 @@ class Protocol:
         self, pid: int, handler: Protocol.CommandHandler
     ) -> None:
         if pid not in self.command_handlers or self.command_handlers[pid] != handler:
-            raise ValueError("command handler not registered")
+            raise core.InvalidArgumentError("command handler not registered")
         del self.command_handlers[pid]
 
     def register_response_handler(
@@ -287,5 +288,5 @@ class Protocol:
         self, pid: int, handler: Protocol.ResponseHandler
     ) -> None:
         if pid not in self.response_handlers or self.response_handlers[pid] != handler:
-            raise ValueError("response handler not registered")
+            raise core.InvalidArgumentError("response handler not registered")
         del self.response_handlers[pid]
diff --git a/bumble/avdtp.py b/bumble/avdtp.py
index 713f7b7..85f7ede 100644
--- a/bumble/avdtp.py
+++ b/bumble/avdtp.py
@@ -43,6 +43,7 @@ from .core import (
     BT_ADVANCED_AUDIO_DISTRIBUTION_SERVICE,
     InvalidStateError,
     ProtocolError,
+    InvalidArgumentError,
     name_or_number,
 )
 from .a2dp import (
@@ -700,7 +701,7 @@ class Message:  # pylint:disable=attribute-defined-outside-init
             signal_identifier_str = name[:-7]
             message_type = Message.MessageType.RESPONSE_REJECT
         else:
-            raise ValueError('invalid class name')
+            raise InvalidArgumentError('invalid class name')
 
         subclass.message_type = message_type
 
@@ -2162,6 +2163,9 @@ class LocalStreamEndPoint(StreamEndPoint, EventEmitter):
     def on_abort_command(self):
         self.emit('abort')
 
+    def on_delayreport_command(self, delay: int):
+        self.emit('delay_report', delay)
+
     def on_rtp_channel_open(self):
         self.emit('rtp_channel_open')
 
diff --git a/bumble/avrcp.py b/bumble/avrcp.py
index 11f4eff..e06a5a6 100644
--- a/bumble/avrcp.py
+++ b/bumble/avrcp.py
@@ -55,6 +55,7 @@ from bumble.sdp import (
 )
 from bumble.utils import AsyncRunner, OpenIntEnum
 from bumble.core import (
+    InvalidArgumentError,
     ProtocolError,
     BT_L2CAP_PROTOCOL_ID,
     BT_AVCTP_PROTOCOL_ID,
@@ -1411,7 +1412,7 @@ class Protocol(pyee.EventEmitter):
     def notify_track_changed(self, identifier: bytes) -> None:
         """Notify the connected peer of a Track change."""
         if len(identifier) != 8:
-            raise ValueError("identifier must be 8 bytes")
+            raise InvalidArgumentError("identifier must be 8 bytes")
         self.notify_event(TrackChangedEvent(identifier))
 
     def notify_playback_position_changed(self, position: int) -> None:
diff --git a/bumble/codecs.py b/bumble/codecs.py
index 1d7ae82..cfb3cad 100644
--- a/bumble/codecs.py
+++ b/bumble/codecs.py
@@ -18,6 +18,8 @@
 from __future__ import annotations
 from dataclasses import dataclass
 
+from bumble import core
+
 
 # -----------------------------------------------------------------------------
 class BitReader:
@@ -40,7 +42,7 @@ class BitReader:
         """ "Read up to 32 bits."""
 
         if bits > 32:
-            raise ValueError('maximum read size is 32')
+            raise core.InvalidArgumentError('maximum read size is 32')
 
         if self.bits_cached >= bits:
             # We have enough bits.
@@ -53,7 +55,7 @@ class BitReader:
         feed_size = len(feed_bytes)
         feed_int = int.from_bytes(feed_bytes, byteorder='big')
         if 8 * feed_size + self.bits_cached < bits:
-            raise ValueError('trying to read past the data')
+            raise core.InvalidArgumentError('trying to read past the data')
         self.byte_position += feed_size
 
         # Combine the new cache and the old cache
@@ -68,7 +70,7 @@ class BitReader:
 
     def read_bytes(self, count: int):
         if self.bit_position + 8 * count > 8 * len(self.data):
-            raise ValueError('not enough data')
+            raise core.InvalidArgumentError('not enough data')
 
         if self.bit_position % 8:
             # Not byte aligned
@@ -113,7 +115,7 @@ class AacAudioRtpPacket:
 
     @staticmethod
     def program_config_element(reader: BitReader):
-        raise ValueError('program_config_element not supported')
+        raise core.InvalidPacketError('program_config_element not supported')
 
     @dataclass
     class GASpecificConfig:
@@ -140,7 +142,7 @@ class AacAudioRtpPacket:
                     aac_spectral_data_resilience_flags = reader.read(1)
                 extension_flag_3 = reader.read(1)
                 if extension_flag_3 == 1:
-                    raise ValueError('extensionFlag3 == 1 not supported')
+                    raise core.InvalidPacketError('extensionFlag3 == 1 not supported')
 
     @staticmethod
     def audio_object_type(reader: BitReader):
@@ -216,7 +218,7 @@ class AacAudioRtpPacket:
                     reader, self.channel_configuration, self.audio_object_type
                 )
             else:
-                raise ValueError(
+                raise core.InvalidPacketError(
                     f'audioObjectType {self.audio_object_type} not supported'
                 )
 
@@ -260,7 +262,7 @@ class AacAudioRtpPacket:
             else:
                 audio_mux_version_a = 0
             if audio_mux_version_a != 0:
-                raise ValueError('audioMuxVersionA != 0 not supported')
+                raise core.InvalidPacketError('audioMuxVersionA != 0 not supported')
             if audio_mux_version == 1:
                 tara_buffer_fullness = AacAudioRtpPacket.latm_value(reader)
             stream_cnt = 0
@@ -268,10 +270,10 @@ class AacAudioRtpPacket:
             num_sub_frames = reader.read(6)
             num_program = reader.read(4)
             if num_program != 0:
-                raise ValueError('num_program != 0 not supported')
+                raise core.InvalidPacketError('num_program != 0 not supported')
             num_layer = reader.read(3)
             if num_layer != 0:
-                raise ValueError('num_layer != 0 not supported')
+                raise core.InvalidPacketError('num_layer != 0 not supported')
             if audio_mux_version == 0:
                 self.audio_specific_config = AacAudioRtpPacket.AudioSpecificConfig(
                     reader
@@ -284,7 +286,7 @@ class AacAudioRtpPacket:
                 )
                 audio_specific_config_len = reader.bit_position - marker
                 if asc_len < audio_specific_config_len:
-                    raise ValueError('audio_specific_config_len > asc_len')
+                    raise core.InvalidPacketError('audio_specific_config_len > asc_len')
                 asc_len -= audio_specific_config_len
                 reader.skip(asc_len)
             frame_length_type = reader.read(3)
@@ -293,7 +295,9 @@ class AacAudioRtpPacket:
             elif frame_length_type == 1:
                 frame_length = reader.read(9)
             else:
-                raise ValueError(f'frame_length_type {frame_length_type} not supported')
+                raise core.InvalidPacketError(
+                    f'frame_length_type {frame_length_type} not supported'
+                )
 
             self.other_data_present = reader.read(1)
             if self.other_data_present:
@@ -318,12 +322,12 @@ class AacAudioRtpPacket:
 
         def __init__(self, reader: BitReader, mux_config_present: int):
             if mux_config_present == 0:
-                raise ValueError('muxConfigPresent == 0 not supported')
+                raise core.InvalidPacketError('muxConfigPresent == 0 not supported')
 
             # AudioMuxElement - ISO/EIC 14496-3 Table 1.41
             use_same_stream_mux = reader.read(1)
             if use_same_stream_mux:
-                raise ValueError('useSameStreamMux == 1 not supported')
+                raise core.InvalidPacketError('useSameStreamMux == 1 not supported')
             self.stream_mux_config = AacAudioRtpPacket.StreamMuxConfig(reader)
 
             # We only support:
diff --git a/bumble/colors.py b/bumble/colors.py
index 2813cfe..37ce03a 100644
--- a/bumble/colors.py
+++ b/bumble/colors.py
@@ -16,6 +16,10 @@ from functools import partial
 from typing import List, Optional, Union
 
 
+class ColorError(ValueError):
+    """Error raised when a color spec is invalid."""
+
+
 # ANSI color names. There is also a "default"
 COLORS = ('black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white')
 
@@ -52,7 +56,7 @@ def _color_code(spec: ColorSpec, base: int) -> str:
     elif isinstance(spec, int) and 0 <= spec <= 255:
         return _join(base + 8, 5, spec)
     else:
-        raise ValueError('Invalid color spec "%s"' % spec)
+        raise ColorError('Invalid color spec "%s"' % spec)
 
 
 def color(
@@ -72,7 +76,7 @@ def color(
             if style_part in STYLES:
                 codes.append(STYLES.index(style_part))
             else:
-                raise ValueError('Invalid style "%s"' % style_part)
+                raise ColorError('Invalid style "%s"' % style_part)
 
     if codes:
         return '\x1b[{0}m{1}\x1b[0m'.format(_join(*codes), s)
diff --git a/bumble/core.py b/bumble/core.py
index dce721a..f6d42dd 100644
--- a/bumble/core.py
+++ b/bumble/core.py
@@ -16,11 +16,14 @@
 # Imports
 # -----------------------------------------------------------------------------
 from __future__ import annotations
+import dataclasses
 import enum
 import struct
 from typing import List, Optional, Tuple, Union, cast, Dict
+from typing_extensions import Self
 
-from .company_ids import COMPANY_IDENTIFIERS
+from bumble.company_ids import COMPANY_IDENTIFIERS
+from bumble.utils import OpenIntEnum
 
 
 # -----------------------------------------------------------------------------
@@ -76,7 +79,13 @@ def get_dict_key_by_value(dictionary, value):
 # -----------------------------------------------------------------------------
 # Exceptions
 # -----------------------------------------------------------------------------
-class BaseError(Exception):
+
+
+class BaseBumbleError(Exception):
+    """Base Error raised by Bumble."""
+
+
+class BaseError(BaseBumbleError):
     """Base class for errors with an error code, error name and namespace"""
 
     def __init__(
@@ -115,18 +124,42 @@ class ProtocolError(BaseError):
     """Protocol Error"""
 
 
-class TimeoutError(Exception):  # pylint: disable=redefined-builtin
+class TimeoutError(BaseBumbleError):  # pylint: disable=redefined-builtin
     """Timeout Error"""
 
 
-class CommandTimeoutError(Exception):
+class CommandTimeoutError(BaseBumbleError):
     """Command Timeout Error"""
 
 
-class InvalidStateError(Exception):
+class InvalidStateError(BaseBumbleError):
     """Invalid State Error"""
 
 
+class InvalidArgumentError(BaseBumbleError, ValueError):
+    """Invalid Argument Error"""
+
+
+class InvalidPacketError(BaseBumbleError, ValueError):
+    """Invalid Packet Error"""
+
+
+class InvalidOperationError(BaseBumbleError, RuntimeError):
+    """Invalid Operation Error"""
+
+
+class NotSupportedError(BaseBumbleError, RuntimeError):
+    """Not Supported"""
+
+
+class OutOfResourcesError(BaseBumbleError, RuntimeError):
+    """Out of Resources Error"""
+
+
+class UnreachableError(BaseBumbleError):
+    """The code path raising this error should be unreachable."""
+
+
 class ConnectionError(BaseError):  # pylint: disable=redefined-builtin
     """Connection Error"""
 
@@ -185,12 +218,12 @@ class UUID:
                     or uuid_str_or_int[18] != '-'
                     or uuid_str_or_int[23] != '-'
                 ):
-                    raise ValueError('invalid UUID format')
+                    raise InvalidArgumentError('invalid UUID format')
                 uuid_str = uuid_str_or_int.replace('-', '')
             else:
                 uuid_str = uuid_str_or_int
             if len(uuid_str) != 32 and len(uuid_str) != 8 and len(uuid_str) != 4:
-                raise ValueError(f"invalid UUID format: {uuid_str}")
+                raise InvalidArgumentError(f"invalid UUID format: {uuid_str}")
             self.uuid_bytes = bytes(reversed(bytes.fromhex(uuid_str)))
         self.name = name
 
@@ -215,7 +248,7 @@ class UUID:
 
             return self.register()
 
-        raise ValueError('only 2, 4 and 16 bytes are allowed')
+        raise InvalidArgumentError('only 2, 4 and 16 bytes are allowed')
 
     @classmethod
     def from_16_bits(cls, uuid_16: int, name: Optional[str] = None) -> UUID:
@@ -692,11 +725,569 @@ class DeviceClass:
         return name_or_number(class_names, minor_device_class)
 
 
+# -----------------------------------------------------------------------------
+# Appearance
+# -----------------------------------------------------------------------------
+class Appearance:
+    class Category(OpenIntEnum):
+        UNKNOWN = 0x0000
+        PHONE = 0x0001
+        COMPUTER = 0x0002
+        WATCH = 0x0003
+        CLOCK = 0x0004
+        DISPLAY = 0x0005
+        REMOTE_CONTROL = 0x0006
+        EYE_GLASSES = 0x0007
+        TAG = 0x0008
+        KEYRING = 0x0009
+        MEDIA_PLAYER = 0x000A
+        BARCODE_SCANNER = 0x000B
+        THERMOMETER = 0x000C
+        HEART_RATE_SENSOR = 0x000D
+        BLOOD_PRESSURE = 0x000E
+        HUMAN_INTERFACE_DEVICE = 0x000F
+        GLUCOSE_METER = 0x0010
+        RUNNING_WALKING_SENSOR = 0x0011
+        CYCLING = 0x0012
+        CONTROL_DEVICE = 0x0013
+        NETWORK_DEVICE = 0x0014
+        SENSOR = 0x0015
+        LIGHT_FIXTURES = 0x0016
+        FAN = 0x0017
+        HVAC = 0x0018
+        AIR_CONDITIONING = 0x0019
+        HUMIDIFIER = 0x001A
+        HEATING = 0x001B
+        ACCESS_CONTROL = 0x001C
+        MOTORIZED_DEVICE = 0x001D
+        POWER_DEVICE = 0x001E
+        LIGHT_SOURCE = 0x001F
+        WINDOW_COVERING = 0x0020
+        AUDIO_SINK = 0x0021
+        AUDIO_SOURCE = 0x0022
+        MOTORIZED_VEHICLE = 0x0023
+        DOMESTIC_APPLIANCE = 0x0024
+        WEARABLE_AUDIO_DEVICE = 0x0025
+        AIRCRAFT = 0x0026
+        AV_EQUIPMENT = 0x0027
+        DISPLAY_EQUIPMENT = 0x0028
+        HEARING_AID = 0x0029
+        GAMING = 0x002A
+        SIGNAGE = 0x002B
+        PULSE_OXIMETER = 0x0031
+        WEIGHT_SCALE = 0x0032
+        PERSONAL_MOBILITY_DEVICE = 0x0033
+        CONTINUOUS_GLUCOSE_MONITOR = 0x0034
+        INSULIN_PUMP = 0x0035
+        MEDICATION_DELIVERY = 0x0036
+        SPIROMETER = 0x0037
+        OUTDOOR_SPORTS_ACTIVITY = 0x0051
+
+    class UnknownSubcategory(OpenIntEnum):
+        GENERIC_UNKNOWN = 0x00
+
+    class PhoneSubcategory(OpenIntEnum):
+        GENERIC_PHONE = 0x00
+
+    class ComputerSubcategory(OpenIntEnum):
+        GENERIC_COMPUTER = 0x00
+        DESKTOP_WORKSTATION = 0x01
+        SERVER_CLASS_COMPUTER = 0x02
+        LAPTOP = 0x03
+        HANDHELD_PC_PDA = 0x04
+        PALM_SIZE_PC_PDA = 0x05
+        WEARABLE_COMPUTER = 0x06
+        TABLET = 0x07
+        DOCKING_STATION = 0x08
+        ALL_IN_ONE = 0x09
+        BLADE_SERVER = 0x0A
+        CONVERTIBLE = 0x0B
+        DETACHABLE = 0x0C
+        IOT_GATEWAY = 0x0D
+        MINI_PC = 0x0E
+        STICK_PC = 0x0F
+
+    class WatchSubcategory(OpenIntEnum):
+        GENENERIC_WATCH = 0x00
+        SPORTS_WATCH = 0x01
+        SMARTWATCH = 0x02
+
+    class ClockSubcategory(OpenIntEnum):
+        GENERIC_CLOCK = 0x00
+
+    class DisplaySubcategory(OpenIntEnum):
+        GENERIC_DISPLAY = 0x00
+
+    class RemoteControlSubcategory(OpenIntEnum):
+        GENERIC_REMOTE_CONTROL = 0x00
+
+    class EyeglassesSubcategory(OpenIntEnum):
+        GENERIC_EYEGLASSES = 0x00
+
+    class TagSubcategory(OpenIntEnum):
+        GENERIC_TAG = 0x00
+
+    class KeyringSubcategory(OpenIntEnum):
+        GENERIC_KEYRING = 0x00
+
+    class MediaPlayerSubcategory(OpenIntEnum):
+        GENERIC_MEDIA_PLAYER = 0x00
+
+    class BarcodeScannerSubcategory(OpenIntEnum):
+        GENERIC_BARCODE_SCANNER = 0x00
+
+    class ThermometerSubcategory(OpenIntEnum):
+        GENERIC_THERMOMETER = 0x00
+        EAR_THERMOMETER = 0x01
+
+    class HeartRateSensorSubcategory(OpenIntEnum):
+        GENERIC_HEART_RATE_SENSOR = 0x00
+        HEART_RATE_BELT = 0x01
+
+    class BloodPressureSubcategory(OpenIntEnum):
+        GENERIC_BLOOD_PRESSURE = 0x00
+        ARM_BLOOD_PRESSURE = 0x01
+        WRIST_BLOOD_PRESSURE = 0x02
+
+    class HumanInterfaceDeviceSubcategory(OpenIntEnum):
+        GENERIC_HUMAN_INTERFACE_DEVICE = 0x00
+        KEYBOARD = 0x01
+        MOUSE = 0x02
+        JOYSTICK = 0x03
+        GAMEPAD = 0x04
+        DIGITIZER_TABLET = 0x05
+        CARD_READER = 0x06
+        DIGITAL_PEN = 0x07
+        BARCODE_SCANNER = 0x08
+        TOUCHPAD = 0x09
+        PRESENTATION_REMOTE = 0x0A
+
+    class GlucoseMeterSubcategory(OpenIntEnum):
+        GENERIC_GLUCOSE_METER = 0x00
+
+    class RunningWalkingSensorSubcategory(OpenIntEnum):
+        GENERIC_RUNNING_WALKING_SENSOR = 0x00
+        IN_SHOE_RUNNING_WALKING_SENSOR = 0x01
+        ON_SHOW_RUNNING_WALKING_SENSOR = 0x02
+        ON_HIP_RUNNING_WALKING_SENSOR = 0x03
+
+    class CyclingSubcategory(OpenIntEnum):
+        GENERIC_CYCLING = 0x00
+        CYCLING_COMPUTER = 0x01
+        SPEED_SENSOR = 0x02
+        CADENCE_SENSOR = 0x03
+        POWER_SENSOR = 0x04
+        SPEED_AND_CADENCE_SENSOR = 0x05
+
+    class ControlDeviceSubcategory(OpenIntEnum):
+        GENERIC_CONTROL_DEVICE = 0x00
+        SWITCH = 0x01
+        MULTI_SWITCH = 0x02
+        BUTTON = 0x03
+        SLIDER = 0x04
+        ROTARY_SWITCH = 0x05
+        TOUCH_PANEL = 0x06
+        SINGLE_SWITCH = 0x07
+        DOUBLE_SWITCH = 0x08
+        TRIPLE_SWITCH = 0x09
+        BATTERY_SWITCH = 0x0A
+        ENERGY_HARVESTING_SWITCH = 0x0B
+        PUSH_BUTTON = 0x0C
+
+    class NetworkDeviceSubcategory(OpenIntEnum):
+        GENERIC_NETWORK_DEVICE = 0x00
+        ACCESS_POINT = 0x01
+        MESH_DEVICE = 0x02
+        MESH_NETWORK_PROXY = 0x03
+
+    class SensorSubcategory(OpenIntEnum):
+        GENERIC_SENSOR = 0x00
+        MOTION_SENSOR = 0x01
+        AIR_QUALITY_SENSOR = 0x02
+        TEMPERATURE_SENSOR = 0x03
+        HUMIDITY_SENSOR = 0x04
+        LEAK_SENSOR = 0x05
+        SMOKE_SENSOR = 0x06
+        OCCUPANCY_SENSOR = 0x07
+        CONTACT_SENSOR = 0x08
+        CARBON_MONOXIDE_SENSOR = 0x09
+        CARBON_DIOXIDE_SENSOR = 0x0A
+        AMBIENT_LIGHT_SENSOR = 0x0B
+        ENERGY_SENSOR = 0x0C
+        COLOR_LIGHT_SENSOR = 0x0D
+        RAIN_SENSOR = 0x0E
+        FIRE_SENSOR = 0x0F
+        WIND_SENSOR = 0x10
+        PROXIMITY_SENSOR = 0x11
+        MULTI_SENSOR = 0x12
+        FLUSH_MOUNTED_SENSOR = 0x13
+        CEILING_MOUNTED_SENSOR = 0x14
+        WALL_MOUNTED_SENSOR = 0x15
+        MULTISENSOR = 0x16
+        ENERGY_METER = 0x17
+        FLAME_DETECTOR = 0x18
+        VEHICLE_TIRE_PRESSURE_SENSOR = 0x19
+
+    class LightFixturesSubcategory(OpenIntEnum):
+        GENERIC_LIGHT_FIXTURES = 0x00
+        WALL_LIGHT = 0x01
+        CEILING_LIGHT = 0x02
+        FLOOR_LIGHT = 0x03
+        CABINET_LIGHT = 0x04
+        DESK_LIGHT = 0x05
+        TROFFER_LIGHT = 0x06
+        PENDANT_LIGHT = 0x07
+        IN_GROUND_LIGHT = 0x08
+        FLOOD_LIGHT = 0x09
+        UNDERWATER_LIGHT = 0x0A
+        BOLLARD_WITH_LIGHT = 0x0B
+        PATHWAY_LIGHT = 0x0C
+        GARDEN_LIGHT = 0x0D
+        POLE_TOP_LIGHT = 0x0E
+        SPOTLIGHT = 0x0F
+        LINEAR_LIGHT = 0x10
+        STREET_LIGHT = 0x11
+        SHELVES_LIGHT = 0x12
+        BAY_LIGHT = 0x013
+        EMERGENCY_EXIT_LIGHT = 0x14
+        LIGHT_CONTROLLER = 0x15
+        LIGHT_DRIVER = 0x16
+        BULB = 0x17
+        LOW_BAY_LIGHT = 0x18
+        HIGH_BAY_LIGHT = 0x19
+
+    class FanSubcategory(OpenIntEnum):
+        GENERIC_FAN = 0x00
+        CEILING_FAN = 0x01
+        AXIAL_FAN = 0x02
+        EXHAUST_FAN = 0x03
+        PEDESTAL_FAN = 0x04
+        DESK_FAN = 0x05
+        WALL_FAN = 0x06
+
+    class HvacSubcategory(OpenIntEnum):
+        GENERIC_HVAC = 0x00
+        THERMOSTAT = 0x01
+        HUMIDIFIER = 0x02
+        DEHUMIDIFIER = 0x03
+        HEATER = 0x04
+        RADIATOR = 0x05
+        BOILER = 0x06
+        HEAT_PUMP = 0x07
+        INFRARED_HEATER = 0x08
+        RADIANT_PANEL_HEATER = 0x09
+        FAN_HEATER = 0x0A
+        AIR_CURTAIN = 0x0B
+
+    class AirConditioningSubcategory(OpenIntEnum):
+        GENERIC_AIR_CONDITIONING = 0x00
+
+    class HumidifierSubcategory(OpenIntEnum):
+        GENERIC_HUMIDIFIER = 0x00
+
+    class HeatingSubcategory(OpenIntEnum):
+        GENERIC_HEATING = 0x00
+        RADIATOR = 0x01
+        BOILER = 0x02
+        HEAT_PUMP = 0x03
+        INFRARED_HEATER = 0x04
+        RADIANT_PANEL_HEATER = 0x05
+        FAN_HEATER = 0x06
+        AIR_CURTAIN = 0x07
+
+    class AccessControlSubcategory(OpenIntEnum):
+        GENERIC_ACCESS_CONTROL = 0x00
+        ACCESS_DOOR = 0x01
+        GARAGE_DOOR = 0x02
+        EMERGENCY_EXIT_DOOR = 0x03
+        ACCESS_LOCK = 0x04
+        ELEVATOR = 0x05
+        WINDOW = 0x06
+        ENTRANCE_GATE = 0x07
+        DOOR_LOCK = 0x08
+        LOCKER = 0x09
+
+    class MotorizedDeviceSubcategory(OpenIntEnum):
+        GENERIC_MOTORIZED_DEVICE = 0x00
+        MOTORIZED_GATE = 0x01
+        AWNING = 0x02
+        BLINDS_OR_SHADES = 0x03
+        CURTAINS = 0x04
+        SCREEN = 0x05
+
+    class PowerDeviceSubcategory(OpenIntEnum):
+        GENERIC_POWER_DEVICE = 0x00
+        POWER_OUTLET = 0x01
+        POWER_STRIP = 0x02
+        PLUG = 0x03
+        POWER_SUPPLY = 0x04
+        LED_DRIVER = 0x05
+        FLUORESCENT_LAMP_GEAR = 0x06
+        HID_LAMP_GEAR = 0x07
+        CHARGE_CASE = 0x08
+        POWER_BANK = 0x09
+
+    class LightSourceSubcategory(OpenIntEnum):
+        GENERIC_LIGHT_SOURCE = 0x00
+        INCANDESCENT_LIGHT_BULB = 0x01
+        LED_LAMP = 0x02
+        HID_LAMP = 0x03
+        FLUORESCENT_LAMP = 0x04
+        LED_ARRAY = 0x05
+        MULTI_COLOR_LED_ARRAY = 0x06
+        LOW_VOLTAGE_HALOGEN = 0x07
+        ORGANIC_LIGHT_EMITTING_DIODE = 0x08
+
+    class WindowCoveringSubcategory(OpenIntEnum):
+        GENERIC_WINDOW_COVERING = 0x00
+        WINDOW_SHADES = 0x01
+        WINDOW_BLINDS = 0x02
+        WINDOW_AWNING = 0x03
+        WINDOW_CURTAIN = 0x04
+        EXTERIOR_SHUTTER = 0x05
+        EXTERIOR_SCREEN = 0x06
+
+    class AudioSinkSubcategory(OpenIntEnum):
+        GENERIC_AUDIO_SINK = 0x00
+        STANDALONE_SPEAKER = 0x01
+        SOUNDBAR = 0x02
+        BOOKSHELF_SPEAKER = 0x03
+        STANDMOUNTED_SPEAKER = 0x04
+        SPEAKERPHONE = 0x05
+
+    class AudioSourceSubcategory(OpenIntEnum):
+        GENERIC_AUDIO_SOURCE = 0x00
+        MICROPHONE = 0x01
+        ALARM = 0x02
+        BELL = 0x03
+        HORN = 0x04
+        BROADCASTING_DEVICE = 0x05
+        SERVICE_DESK = 0x06
+        KIOSK = 0x07
+        BROADCASTING_ROOM = 0x08
+        AUDITORIUM = 0x09
+
+    class MotorizedVehicleSubcategory(OpenIntEnum):
+        GENERIC_MOTORIZED_VEHICLE = 0x00
+        CAR = 0x01
+        LARGE_GOODS_VEHICLE = 0x02
+        TWO_WHEELED_VEHICLE = 0x03
+        MOTORBIKE = 0x04
+        SCOOTER = 0x05
+        MOPED = 0x06
+        THREE_WHEELED_VEHICLE = 0x07
+        LIGHT_VEHICLE = 0x08
+        QUAD_BIKE = 0x09
+        MINIBUS = 0x0A
+        BUS = 0x0B
+        TROLLEY = 0x0C
+        AGRICULTURAL_VEHICLE = 0x0D
+        CAMPER_CARAVAN = 0x0E
+        RECREATIONAL_VEHICLE_MOTOR_HOME = 0x0F
+
+    class DomesticApplianceSubcategory(OpenIntEnum):
+        GENERIC_DOMESTIC_APPLIANCE = 0x00
+        REFRIGERATOR = 0x01
+        FREEZER = 0x02
+        OVEN = 0x03
+        MICROWAVE = 0x04
+        TOASTER = 0x05
+        WASHING_MACHINE = 0x06
+        DRYER = 0x07
+        COFFEE_MAKER = 0x08
+        CLOTHES_IRON = 0x09
+        CURLING_IRON = 0x0A
+        HAIR_DRYER = 0x0B
+        VACUUM_CLEANER = 0x0C
+        ROBOTIC_VACUUM_CLEANER = 0x0D
+        RICE_COOKER = 0x0E
+        CLOTHES_STEAMER = 0x0F
+
+    class WearableAudioDeviceSubcategory(OpenIntEnum):
+        GENERIC_WEARABLE_AUDIO_DEVICE = 0x00
+        EARBUD = 0x01
+        HEADSET = 0x02
+        HEADPHONES = 0x03
+        NECK_BAND = 0x04
+
+    class AircraftSubcategory(OpenIntEnum):
+        GENERIC_AIRCRAFT = 0x00
+        LIGHT_AIRCRAFT = 0x01
+        MICROLIGHT = 0x02
+        PARAGLIDER = 0x03
+        LARGE_PASSENGER_AIRCRAFT = 0x04
+
+    class AvEquipmentSubcategory(OpenIntEnum):
+        GENERIC_AV_EQUIPMENT = 0x00
+        AMPLIFIER = 0x01
+        RECEIVER = 0x02
+        RADIO = 0x03
+        TUNER = 0x04
+        TURNTABLE = 0x05
+        CD_PLAYER = 0x06
+        DVD_PLAYER = 0x07
+        BLUERAY_PLAYER = 0x08
+        OPTICAL_DISC_PLAYER = 0x09
+        SET_TOP_BOX = 0x0A
+
+    class DisplayEquipmentSubcategory(OpenIntEnum):
+        GENERIC_DISPLAY_EQUIPMENT = 0x00
+        TELEVISION = 0x01
+        MONITOR = 0x02
+        PROJECTOR = 0x03
+
+    class HearingAidSubcategory(OpenIntEnum):
+        GENERIC_HEARING_AID = 0x00
+        IN_EAR_HEARING_AID = 0x01
+        BEHIND_EAR_HEARING_AID = 0x02
+        COCHLEAR_IMPLANT = 0x03
+
+    class GamingSubcategory(OpenIntEnum):
+        GENERIC_GAMING = 0x00
+        HOME_VIDEO_GAME_CONSOLE = 0x01
+        PORTABLE_HANDHELD_CONSOLE = 0x02
+
+    class SignageSubcategory(OpenIntEnum):
+        GENERIC_SIGNAGE = 0x00
+        DIGITAL_SIGNAGE = 0x01
+        ELECTRONIC_LABEL = 0x02
+
+    class PulseOximeterSubcategory(OpenIntEnum):
+        GENERIC_PULSE_OXIMETER = 0x00
+        FINGERTIP_PULSE_OXIMETER = 0x01
+        WRIST_WORN_PULSE_OXIMETER = 0x02
+
+    class WeightScaleSubcategory(OpenIntEnum):
+        GENERIC_WEIGHT_SCALE = 0x00
+
+    class PersonalMobilityDeviceSubcategory(OpenIntEnum):
+        GENERIC_PERSONAL_MOBILITY_DEVICE = 0x00
+        POWERED_WHEELCHAIR = 0x01
+        MOBILITY_SCOOTER = 0x02
+
+    class ContinuousGlucoseMonitorSubcategory(OpenIntEnum):
+        GENERIC_CONTINUOUS_GLUCOSE_MONITOR = 0x00
+
+    class InsulinPumpSubcategory(OpenIntEnum):
+        GENERIC_INSULIN_PUMP = 0x00
+        INSULIN_PUMP_DURABLE_PUMP = 0x01
+        INSULIN_PUMP_PATCH_PUMP = 0x02
+        INSULIN_PEN = 0x03
+
+    class MedicationDeliverySubcategory(OpenIntEnum):
+        GENERIC_MEDICATION_DELIVERY = 0x00
+
+    class SpirometerSubcategory(OpenIntEnum):
+        GENERIC_SPIROMETER = 0x00
+        HANDHELD_SPIROMETER = 0x01
+
+    class OutdoorSportsActivitySubcategory(OpenIntEnum):
+        GENERIC_OUTDOOR_SPORTS_ACTIVITY = 0x00
+        LOCATION_DISPLAY = 0x01
+        LOCATION_AND_NAVIGATION_DISPLAY = 0x02
+        LOCATION_POD = 0x03
+        LOCATION_AND_NAVIGATION_POD = 0x04
+
+    class _OpenSubcategory(OpenIntEnum):
+        GENERIC = 0x00
+
+    SUBCATEGORY_CLASSES = {
+        Category.UNKNOWN: UnknownSubcategory,
+        Category.PHONE: PhoneSubcategory,
+        Category.COMPUTER: ComputerSubcategory,
+        Category.WATCH: WatchSubcategory,
+        Category.CLOCK: ClockSubcategory,
+        Category.DISPLAY: DisplaySubcategory,
+        Category.REMOTE_CONTROL: RemoteControlSubcategory,
+        Category.EYE_GLASSES: EyeglassesSubcategory,
+        Category.TAG: TagSubcategory,
+        Category.KEYRING: KeyringSubcategory,
+        Category.MEDIA_PLAYER: MediaPlayerSubcategory,
+        Category.BARCODE_SCANNER: BarcodeScannerSubcategory,
+        Category.THERMOMETER: ThermometerSubcategory,
+        Category.HEART_RATE_SENSOR: HeartRateSensorSubcategory,
+        Category.BLOOD_PRESSURE: BloodPressureSubcategory,
+        Category.HUMAN_INTERFACE_DEVICE: HumanInterfaceDeviceSubcategory,
+        Category.GLUCOSE_METER: GlucoseMeterSubcategory,
+        Category.RUNNING_WALKING_SENSOR: RunningWalkingSensorSubcategory,
+        Category.CYCLING: CyclingSubcategory,
+        Category.CONTROL_DEVICE: ControlDeviceSubcategory,
+        Category.NETWORK_DEVICE: NetworkDeviceSubcategory,
+        Category.SENSOR: SensorSubcategory,
+        Category.LIGHT_FIXTURES: LightFixturesSubcategory,
+        Category.FAN: FanSubcategory,
+        Category.HVAC: HvacSubcategory,
+        Category.AIR_CONDITIONING: AirConditioningSubcategory,
+        Category.HUMIDIFIER: HumidifierSubcategory,
+        Category.HEATING: HeatingSubcategory,
+        Category.ACCESS_CONTROL: AccessControlSubcategory,
+        Category.MOTORIZED_DEVICE: MotorizedDeviceSubcategory,
+        Category.POWER_DEVICE: PowerDeviceSubcategory,
+        Category.LIGHT_SOURCE: LightSourceSubcategory,
+        Category.WINDOW_COVERING: WindowCoveringSubcategory,
+        Category.AUDIO_SINK: AudioSinkSubcategory,
+        Category.AUDIO_SOURCE: AudioSourceSubcategory,
+        Category.MOTORIZED_VEHICLE: MotorizedVehicleSubcategory,
+        Category.DOMESTIC_APPLIANCE: DomesticApplianceSubcategory,
+        Category.WEARABLE_AUDIO_DEVICE: WearableAudioDeviceSubcategory,
+        Category.AIRCRAFT: AircraftSubcategory,
+        Category.AV_EQUIPMENT: AvEquipmentSubcategory,
+        Category.DISPLAY_EQUIPMENT: DisplayEquipmentSubcategory,
+        Category.HEARING_AID: HearingAidSubcategory,
+        Category.GAMING: GamingSubcategory,
+        Category.SIGNAGE: SignageSubcategory,
+        Category.PULSE_OXIMETER: PulseOximeterSubcategory,
+        Category.WEIGHT_SCALE: WeightScaleSubcategory,
+        Category.PERSONAL_MOBILITY_DEVICE: PersonalMobilityDeviceSubcategory,
+        Category.CONTINUOUS_GLUCOSE_MONITOR: ContinuousGlucoseMonitorSubcategory,
+        Category.INSULIN_PUMP: InsulinPumpSubcategory,
+        Category.MEDICATION_DELIVERY: MedicationDeliverySubcategory,
+        Category.SPIROMETER: SpirometerSubcategory,
+        Category.OUTDOOR_SPORTS_ACTIVITY: OutdoorSportsActivitySubcategory,
+    }
+
+    category: Category
+    subcategory: enum.IntEnum
+
+    @classmethod
+    def from_int(cls, appearance: int) -> Self:
+        category = cls.Category(appearance >> 6)
+        return cls(category, appearance & 0x3F)
+
+    def __init__(self, category: Category, subcategory: int) -> None:
+        self.category = category
+        if subcategory_class := self.SUBCATEGORY_CLASSES.get(category):
+            self.subcategory = subcategory_class(subcategory)
+        else:
+            self.subcategory = self._OpenSubcategory(subcategory)
+
+    def __int__(self) -> int:
+        return self.category << 6 | self.subcategory
+
+    def __repr__(self) -> str:
+        return (
+            'Appearance('
+            f'category={self.category.name}, '
+            f'subcategory={self.subcategory.name}'
+            ')'
+        )
+
+    def __str__(self) -> str:
+        return f'{self.category.name}/{self.subcategory.name}'
+
+
 # -----------------------------------------------------------------------------
 # Advertising Data
 # -----------------------------------------------------------------------------
-AdvertisingObject = Union[
-    List[UUID], Tuple[UUID, bytes], bytes, str, int, Tuple[int, int], Tuple[int, bytes]
+AdvertisingDataObject = Union[
+    List[UUID],
+    Tuple[UUID, bytes],
+    bytes,
+    str,
+    int,
+    Tuple[int, int],
+    Tuple[int, bytes],
+    Appearance,
 ]
 
 
@@ -704,109 +1295,115 @@ class AdvertisingData:
     # fmt: off
     # pylint: disable=line-too-long
 
-    # This list is only partial, it still needs to be filled in from the spec
-    FLAGS                                          = 0x01
-    INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS  = 0x02
-    COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS    = 0x03
-    INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS  = 0x04
-    COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS    = 0x05
-    INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS = 0x06
-    COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS   = 0x07
-    SHORTENED_LOCAL_NAME                           = 0x08
-    COMPLETE_LOCAL_NAME                            = 0x09
-    TX_POWER_LEVEL                                 = 0x0A
-    CLASS_OF_DEVICE                                = 0x0D
-    SIMPLE_PAIRING_HASH_C                          = 0x0E
-    SIMPLE_PAIRING_HASH_C_192                      = 0x0E
-    SIMPLE_PAIRING_RANDOMIZER_R                    = 0x0F
-    SIMPLE_PAIRING_RANDOMIZER_R_192                = 0x0F
-    DEVICE_ID                                      = 0x10
-    SECURITY_MANAGER_TK_VALUE                      = 0x10
-    SECURITY_MANAGER_OUT_OF_BAND_FLAGS             = 0x11
-    PERIPHERAL_CONNECTION_INTERVAL_RANGE           = 0x12
-    LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS      = 0x14
-    LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS     = 0x15
-    SERVICE_DATA                                   = 0x16
-    SERVICE_DATA_16_BIT_UUID                       = 0x16
-    PUBLIC_TARGET_ADDRESS                          = 0x17
-    RANDOM_TARGET_ADDRESS                          = 0x18
-    APPEARANCE                                     = 0x19
-    ADVERTISING_INTERVAL                           = 0x1A
-    LE_BLUETOOTH_DEVICE_ADDRESS                    = 0x1B
-    LE_ROLE                                        = 0x1C
-    SIMPLE_PAIRING_HASH_C_256                      = 0x1D
-    SIMPLE_PAIRING_RANDOMIZER_R_256                = 0x1E
-    LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS      = 0x1F
-    SERVICE_DATA_32_BIT_UUID                       = 0x20
-    SERVICE_DATA_128_BIT_UUID                      = 0x21
-    LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE       = 0x22
-    LE_SECURE_CONNECTIONS_RANDOM_VALUE             = 0x23
-    URI                                            = 0x24
-    INDOOR_POSITIONING                             = 0x25
-    TRANSPORT_DISCOVERY_DATA                       = 0x26
-    LE_SUPPORTED_FEATURES                          = 0x27
-    CHANNEL_MAP_UPDATE_INDICATION                  = 0x28
-    PB_ADV                                         = 0x29
-    MESH_MESSAGE                                   = 0x2A
-    MESH_BEACON                                    = 0x2B
-    BIGINFO                                        = 0x2C
-    BROADCAST_CODE                                 = 0x2D
-    RESOLVABLE_SET_IDENTIFIER                      = 0x2E
-    ADVERTISING_INTERVAL_LONG                      = 0x2F
-    THREE_D_INFORMATION_DATA                       = 0x3D
-    MANUFACTURER_SPECIFIC_DATA                     = 0xFF
+    FLAGS                                            = 0x01
+    INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS    = 0x02
+    COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS      = 0x03
+    INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS    = 0x04
+    COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS      = 0x05
+    INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS   = 0x06
+    COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS     = 0x07
+    SHORTENED_LOCAL_NAME                             = 0x08
+    COMPLETE_LOCAL_NAME                              = 0x09
+    TX_POWER_LEVEL                                   = 0x0A
+    CLASS_OF_DEVICE                                  = 0x0D
+    SIMPLE_PAIRING_HASH_C                            = 0x0E
+    SIMPLE_PAIRING_HASH_C_192                        = 0x0E
+    SIMPLE_PAIRING_RANDOMIZER_R                      = 0x0F
+    SIMPLE_PAIRING_RANDOMIZER_R_192                  = 0x0F
+    DEVICE_ID                                        = 0x10
+    SECURITY_MANAGER_TK_VALUE                        = 0x10
+    SECURITY_MANAGER_OUT_OF_BAND_FLAGS               = 0x11
+    PERIPHERAL_CONNECTION_INTERVAL_RANGE             = 0x12
+    LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS        = 0x14
+    LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS       = 0x15
+    SERVICE_DATA                                     = 0x16
+    SERVICE_DATA_16_BIT_UUID                         = 0x16
+    PUBLIC_TARGET_ADDRESS                            = 0x17
+    RANDOM_TARGET_ADDRESS                            = 0x18
+    APPEARANCE                                       = 0x19
+    ADVERTISING_INTERVAL                             = 0x1A
+    LE_BLUETOOTH_DEVICE_ADDRESS                      = 0x1B
+    LE_ROLE                                          = 0x1C
+    SIMPLE_PAIRING_HASH_C_256                        = 0x1D
+    SIMPLE_PAIRING_RANDOMIZER_R_256                  = 0x1E
+    LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS        = 0x1F
+    SERVICE_DATA_32_BIT_UUID                         = 0x20
+    SERVICE_DATA_128_BIT_UUID                        = 0x21
+    LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE         = 0x22
+    LE_SECURE_CONNECTIONS_RANDOM_VALUE               = 0x23
+    URI                                              = 0x24
+    INDOOR_POSITIONING                               = 0x25
+    TRANSPORT_DISCOVERY_DATA                         = 0x26
+    LE_SUPPORTED_FEATURES                            = 0x27
+    CHANNEL_MAP_UPDATE_INDICATION                    = 0x28
+    PB_ADV                                           = 0x29
+    MESH_MESSAGE                                     = 0x2A
+    MESH_BEACON                                      = 0x2B
+    BIGINFO                                          = 0x2C
+    BROADCAST_CODE                                   = 0x2D
+    RESOLVABLE_SET_IDENTIFIER                        = 0x2E
+    ADVERTISING_INTERVAL_LONG                        = 0x2F
+    BROADCAST_NAME                                   = 0x30
+    ENCRYPTED_ADVERTISING_DATA                       = 0X31
+    PERIODIC_ADVERTISING_RESPONSE_TIMING_INFORMATION = 0X32
+    ELECTRONIC_SHELF_LABEL                           = 0X34
+    THREE_D_INFORMATION_DATA                         = 0x3D
+    MANUFACTURER_SPECIFIC_DATA                       = 0xFF
 
     AD_TYPE_NAMES = {
-        FLAGS:                                          'FLAGS',
-        INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS:  'INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS',
-        COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS:    'COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS',
-        INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS:  'INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS',
-        COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS:    'COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS',
-        INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS: 'INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS',
-        COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS:   'COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS',
-        SHORTENED_LOCAL_NAME:                           'SHORTENED_LOCAL_NAME',
-        COMPLETE_LOCAL_NAME:                            'COMPLETE_LOCAL_NAME',
-        TX_POWER_LEVEL:                                 'TX_POWER_LEVEL',
-        CLASS_OF_DEVICE:                                'CLASS_OF_DEVICE',
-        SIMPLE_PAIRING_HASH_C:                          'SIMPLE_PAIRING_HASH_C',
-        SIMPLE_PAIRING_HASH_C_192:                      'SIMPLE_PAIRING_HASH_C_192',
-        SIMPLE_PAIRING_RANDOMIZER_R:                    'SIMPLE_PAIRING_RANDOMIZER_R',
-        SIMPLE_PAIRING_RANDOMIZER_R_192:                'SIMPLE_PAIRING_RANDOMIZER_R_192',
-        DEVICE_ID:                                      'DEVICE_ID',
-        SECURITY_MANAGER_TK_VALUE:                      'SECURITY_MANAGER_TK_VALUE',
-        SECURITY_MANAGER_OUT_OF_BAND_FLAGS:             'SECURITY_MANAGER_OUT_OF_BAND_FLAGS',
-        PERIPHERAL_CONNECTION_INTERVAL_RANGE:           'PERIPHERAL_CONNECTION_INTERVAL_RANGE',
-        LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS:      'LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS',
-        LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS:     'LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS',
-        SERVICE_DATA:                                   'SERVICE_DATA',
-        SERVICE_DATA_16_BIT_UUID:                       'SERVICE_DATA_16_BIT_UUID',
-        PUBLIC_TARGET_ADDRESS:                          'PUBLIC_TARGET_ADDRESS',
-        RANDOM_TARGET_ADDRESS:                          'RANDOM_TARGET_ADDRESS',
-        APPEARANCE:                                     'APPEARANCE',
-        ADVERTISING_INTERVAL:                           'ADVERTISING_INTERVAL',
-        LE_BLUETOOTH_DEVICE_ADDRESS:                    'LE_BLUETOOTH_DEVICE_ADDRESS',
-        LE_ROLE:                                        'LE_ROLE',
-        SIMPLE_PAIRING_HASH_C_256:                      'SIMPLE_PAIRING_HASH_C_256',
-        SIMPLE_PAIRING_RANDOMIZER_R_256:                'SIMPLE_PAIRING_RANDOMIZER_R_256',
-        LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS:      'LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS',
-        SERVICE_DATA_32_BIT_UUID:                       'SERVICE_DATA_32_BIT_UUID',
-        SERVICE_DATA_128_BIT_UUID:                      'SERVICE_DATA_128_BIT_UUID',
-        LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE:       'LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE',
-        LE_SECURE_CONNECTIONS_RANDOM_VALUE:             'LE_SECURE_CONNECTIONS_RANDOM_VALUE',
-        URI:                                            'URI',
-        INDOOR_POSITIONING:                             'INDOOR_POSITIONING',
-        TRANSPORT_DISCOVERY_DATA:                       'TRANSPORT_DISCOVERY_DATA',
-        LE_SUPPORTED_FEATURES:                          'LE_SUPPORTED_FEATURES',
-        CHANNEL_MAP_UPDATE_INDICATION:                  'CHANNEL_MAP_UPDATE_INDICATION',
-        PB_ADV:                                         'PB_ADV',
-        MESH_MESSAGE:                                   'MESH_MESSAGE',
-        MESH_BEACON:                                    'MESH_BEACON',
-        BIGINFO:                                        'BIGINFO',
-        BROADCAST_CODE:                                 'BROADCAST_CODE',
-        RESOLVABLE_SET_IDENTIFIER:                      'RESOLVABLE_SET_IDENTIFIER',
-        ADVERTISING_INTERVAL_LONG:                      'ADVERTISING_INTERVAL_LONG',
-        THREE_D_INFORMATION_DATA:                       'THREE_D_INFORMATION_DATA',
-        MANUFACTURER_SPECIFIC_DATA:                     'MANUFACTURER_SPECIFIC_DATA'
+        FLAGS:                                            'FLAGS',
+        INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS:    'INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS',
+        COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS:      'COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS',
+        INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS:    'INCOMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS',
+        COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS:      'COMPLETE_LIST_OF_32_BIT_SERVICE_CLASS_UUIDS',
+        INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS:   'INCOMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS',
+        COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS:     'COMPLETE_LIST_OF_128_BIT_SERVICE_CLASS_UUIDS',
+        SHORTENED_LOCAL_NAME:                             'SHORTENED_LOCAL_NAME',
+        COMPLETE_LOCAL_NAME:                              'COMPLETE_LOCAL_NAME',
+        TX_POWER_LEVEL:                                   'TX_POWER_LEVEL',
+        CLASS_OF_DEVICE:                                  'CLASS_OF_DEVICE',
+        SIMPLE_PAIRING_HASH_C:                            'SIMPLE_PAIRING_HASH_C',
+        SIMPLE_PAIRING_HASH_C_192:                        'SIMPLE_PAIRING_HASH_C_192',
+        SIMPLE_PAIRING_RANDOMIZER_R:                      'SIMPLE_PAIRING_RANDOMIZER_R',
+        SIMPLE_PAIRING_RANDOMIZER_R_192:                  'SIMPLE_PAIRING_RANDOMIZER_R_192',
+        DEVICE_ID:                                        'DEVICE_ID',
+        SECURITY_MANAGER_TK_VALUE:                        'SECURITY_MANAGER_TK_VALUE',
+        SECURITY_MANAGER_OUT_OF_BAND_FLAGS:               'SECURITY_MANAGER_OUT_OF_BAND_FLAGS',
+        PERIPHERAL_CONNECTION_INTERVAL_RANGE:             'PERIPHERAL_CONNECTION_INTERVAL_RANGE',
+        LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS:        'LIST_OF_16_BIT_SERVICE_SOLICITATION_UUIDS',
+        LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS:       'LIST_OF_128_BIT_SERVICE_SOLICITATION_UUIDS',
+        SERVICE_DATA_16_BIT_UUID:                         'SERVICE_DATA_16_BIT_UUID',
+        PUBLIC_TARGET_ADDRESS:                            'PUBLIC_TARGET_ADDRESS',
+        RANDOM_TARGET_ADDRESS:                            'RANDOM_TARGET_ADDRESS',
+        APPEARANCE:                                       'APPEARANCE',
+        ADVERTISING_INTERVAL:                             'ADVERTISING_INTERVAL',
+        LE_BLUETOOTH_DEVICE_ADDRESS:                      'LE_BLUETOOTH_DEVICE_ADDRESS',
+        LE_ROLE:                                          'LE_ROLE',
+        SIMPLE_PAIRING_HASH_C_256:                        'SIMPLE_PAIRING_HASH_C_256',
+        SIMPLE_PAIRING_RANDOMIZER_R_256:                  'SIMPLE_PAIRING_RANDOMIZER_R_256',
+        LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS:        'LIST_OF_32_BIT_SERVICE_SOLICITATION_UUIDS',
+        SERVICE_DATA_32_BIT_UUID:                         'SERVICE_DATA_32_BIT_UUID',
+        SERVICE_DATA_128_BIT_UUID:                        'SERVICE_DATA_128_BIT_UUID',
+        LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE:         'LE_SECURE_CONNECTIONS_CONFIRMATION_VALUE',
+        LE_SECURE_CONNECTIONS_RANDOM_VALUE:               'LE_SECURE_CONNECTIONS_RANDOM_VALUE',
+        URI:                                              'URI',
+        INDOOR_POSITIONING:                               'INDOOR_POSITIONING',
+        TRANSPORT_DISCOVERY_DATA:                         'TRANSPORT_DISCOVERY_DATA',
+        LE_SUPPORTED_FEATURES:                            'LE_SUPPORTED_FEATURES',
+        CHANNEL_MAP_UPDATE_INDICATION:                    'CHANNEL_MAP_UPDATE_INDICATION',
+        PB_ADV:                                           'PB_ADV',
+        MESH_MESSAGE:                                     'MESH_MESSAGE',
+        MESH_BEACON:                                      'MESH_BEACON',
+        BIGINFO:                                          'BIGINFO',
+        BROADCAST_CODE:                                   'BROADCAST_CODE',
+        RESOLVABLE_SET_IDENTIFIER:                        'RESOLVABLE_SET_IDENTIFIER',
+        ADVERTISING_INTERVAL_LONG:                        'ADVERTISING_INTERVAL_LONG',
+        BROADCAST_NAME:                                   'BROADCAST_NAME',
+        ENCRYPTED_ADVERTISING_DATA:                       'ENCRYPTED_ADVERTISING_DATA',
+        PERIODIC_ADVERTISING_RESPONSE_TIMING_INFORMATION: 'PERIODIC_ADVERTISING_RESPONSE_TIMING_INFORMATION',
+        ELECTRONIC_SHELF_LABEL:                           'ELECTRONIC_SHELF_LABEL',
+        THREE_D_INFORMATION_DATA:                         'THREE_D_INFORMATION_DATA',
+        MANUFACTURER_SPECIFIC_DATA:                       'MANUFACTURER_SPECIFIC_DATA'
     }
 
     LE_LIMITED_DISCOVERABLE_MODE_FLAG = 0x01
@@ -915,7 +1512,11 @@ class AdvertisingData:
             ad_data_str = f'company={company_name}, data={ad_data[2:].hex()}'
         elif ad_type == AdvertisingData.APPEARANCE:
             ad_type_str = 'Appearance'
-            ad_data_str = ad_data.hex()
+            appearance = Appearance.from_int(struct.unpack_from('<H', ad_data, 0)[0])
+            ad_data_str = str(appearance)
+        elif ad_type == AdvertisingData.BROADCAST_NAME:
+            ad_type_str = 'Broadcast Name'
+            ad_data_str = ad_data.decode('utf-8')
         else:
             ad_type_str = AdvertisingData.AD_TYPE_NAMES.get(ad_type, f'0x{ad_type:02X}')
             ad_data_str = ad_data.hex()
@@ -924,7 +1525,7 @@ class AdvertisingData:
 
     # pylint: disable=too-many-return-statements
     @staticmethod
-    def ad_data_to_object(ad_type: int, ad_data: bytes) -> AdvertisingObject:
+    def ad_data_to_object(ad_type: int, ad_data: bytes) -> AdvertisingDataObject:
         if ad_type in (
             AdvertisingData.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
             AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
@@ -959,16 +1560,14 @@ class AdvertisingData:
             AdvertisingData.SHORTENED_LOCAL_NAME,
             AdvertisingData.COMPLETE_LOCAL_NAME,
             AdvertisingData.URI,
+            AdvertisingData.BROADCAST_NAME,
         ):
             return ad_data.decode("utf-8")
 
         if ad_type in (AdvertisingData.TX_POWER_LEVEL, AdvertisingData.FLAGS):
             return cast(int, struct.unpack('B', ad_data)[0])
 
-        if ad_type in (
-            AdvertisingData.APPEARANCE,
-            AdvertisingData.ADVERTISING_INTERVAL,
-        ):
+        if ad_type in (AdvertisingData.ADVERTISING_INTERVAL,):
             return cast(int, struct.unpack('<H', ad_data)[0])
 
         if ad_type == AdvertisingData.CLASS_OF_DEVICE:
@@ -980,6 +1579,11 @@ class AdvertisingData:
         if ad_type == AdvertisingData.MANUFACTURER_SPECIFIC_DATA:
             return (cast(int, struct.unpack_from('<H', ad_data, 0)[0]), ad_data[2:])
 
+        if ad_type == AdvertisingData.APPEARANCE:
+            return Appearance.from_int(
+                cast(int, struct.unpack_from('<H', ad_data, 0)[0])
+            )
+
         return ad_data
 
     def append(self, data: bytes) -> None:
@@ -993,27 +1597,27 @@ class AdvertisingData:
                 self.ad_structures.append((ad_type, ad_data))
             offset += length
 
-    def get_all(self, type_id: int, raw: bool = False) -> List[AdvertisingObject]:
+    def get_all(self, type_id: int, raw: bool = False) -> List[AdvertisingDataObject]:
         '''
         Get Advertising Data Structure(s) with a given type
 
         Returns a (possibly empty) list of matches.
         '''
 
-        def process_ad_data(ad_data: bytes) -> AdvertisingObject:
+        def process_ad_data(ad_data: bytes) -> AdvertisingDataObject:
             return ad_data if raw else self.ad_data_to_object(type_id, ad_data)
 
         return [process_ad_data(ad[1]) for ad in self.ad_structures if ad[0] == type_id]
 
-    def get(self, type_id: int, raw: bool = False) -> Optional[AdvertisingObject]:
+    def get(self, type_id: int, raw: bool = False) -> Optional[AdvertisingDataObject]:
         '''
         Get Advertising Data Structure(s) with a given type
 
         Returns the first entry, or None if no structure matches.
         '''
 
-        all = self.get_all(type_id, raw=raw)
-        return all[0] if all else None
+        all_objects = self.get_all(type_id, raw=raw)
+        return all_objects[0] if all_objects else None
 
     def __bytes__(self):
         return b''.join(
diff --git a/bumble/decoder.py b/bumble/decoder.py
index 2eb70bc..83a23b1 100644
--- a/bumble/decoder.py
+++ b/bumble/decoder.py
@@ -12,6 +12,8 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
+from typing import Union
+
 # -----------------------------------------------------------------------------
 # Constants
 # -----------------------------------------------------------------------------
@@ -149,7 +151,7 @@ QMF_COEFFS = [3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11]
 # -----------------------------------------------------------------------------
 # Classes
 # -----------------------------------------------------------------------------
-class G722Decoder(object):
+class G722Decoder:
     """G.722 decoder with bitrate 64kbit/s.
 
     For the Blocks in the sub-band decoders, please refer to the G.722
@@ -157,7 +159,7 @@ class G722Decoder(object):
     https://www.itu.int/rec/T-REC-G.722-201209-I
     """
 
-    def __init__(self):
+    def __init__(self) -> None:
         self._x = [0] * 24
         self._band = [Band(), Band()]
         # The initial value in BLOCK 3L
@@ -165,12 +167,12 @@ class G722Decoder(object):
         # The initial value in BLOCK 3H
         self._band[1].det = 8
 
-    def decode_frame(self, encoded_data) -> bytearray:
+    def decode_frame(self, encoded_data: Union[bytes, bytearray]) -> bytearray:
         result_array = bytearray(len(encoded_data) * 4)
         self.g722_decode(result_array, encoded_data)
         return result_array
 
-    def g722_decode(self, result_array, encoded_data) -> int:
+    def g722_decode(self, result_array, encoded_data: Union[bytes, bytearray]) -> int:
         """Decode the data frame using g722 decoder."""
         result_length = 0
 
@@ -198,14 +200,16 @@ class G722Decoder(object):
 
         return result_length
 
-    def update_decoded_result(self, xout, byte_length, byte_array) -> int:
+    def update_decoded_result(
+        self, xout: int, byte_length: int, byte_array: bytearray
+    ) -> int:
         result = (int)(xout >> 11)
         bytes_result = result.to_bytes(2, 'little', signed=True)
         byte_array[byte_length] = bytes_result[0]
         byte_array[byte_length + 1] = bytes_result[1]
         return byte_length + 2
 
-    def lower_sub_band_decoder(self, lower_bits) -> int:
+    def lower_sub_band_decoder(self, lower_bits: int) -> int:
         """Lower sub-band decoder for last six bits."""
 
         # Block 5L
@@ -258,7 +262,7 @@ class G722Decoder(object):
 
         return rlow
 
-    def higher_sub_band_decoder(self, higher_bits) -> int:
+    def higher_sub_band_decoder(self, higher_bits: int) -> int:
         """Higher sub-band decoder for first two bits."""
 
         # Block 2H
@@ -306,14 +310,14 @@ class G722Decoder(object):
 
 
 # -----------------------------------------------------------------------------
-class Band(object):
-    """Structure for G722 decode proccessing."""
+class Band:
+    """Structure for G722 decode processing."""
 
     s: int = 0
     nb: int = 0
     det: int = 0
 
-    def __init__(self):
+    def __init__(self) -> None:
         self._sp = 0
         self._sz = 0
         self._r = [0] * 3
diff --git a/bumble/device.py b/bumble/device.py
index f9e6b9d..034b0e9 100644
--- a/bumble/device.py
+++ b/bumble/device.py
@@ -16,22 +16,22 @@
 # Imports
 # -----------------------------------------------------------------------------
 from __future__ import annotations
-from enum import IntEnum
-import copy
-import functools
-import json
 import asyncio
-import logging
-import secrets
-import sys
+from collections.abc import Iterable
 from contextlib import (
     asynccontextmanager,
     AsyncExitStack,
     closing,
-    AbstractAsyncContextManager,
 )
+import copy
 from dataclasses import dataclass, field
-from collections.abc import Iterable
+from enum import Enum, IntEnum
+import functools
+import itertools
+import json
+import logging
+import secrets
+import sys
 from typing import (
     Any,
     Callable,
@@ -51,6 +51,7 @@ from typing_extensions import Self
 
 from pyee import EventEmitter
 
+from bumble import hci
 from .colors import color
 from .att import ATT_CID, ATT_DEFAULT_MTU, ATT_PDU
 from .gatt import Characteristic, Descriptor, Service
@@ -81,6 +82,7 @@ from .hci import (
     HCI_MITM_REQUIRED_GENERAL_BONDING_AUTHENTICATION_REQUIREMENTS,
     HCI_MITM_REQUIRED_NO_BONDING_AUTHENTICATION_REQUIREMENTS,
     HCI_NO_INPUT_NO_OUTPUT_IO_CAPABILITY,
+    HCI_OPERATION_CANCELLED_BY_HOST_ERROR,
     HCI_R2_PAGE_SCAN_REPETITION_MODE,
     HCI_REMOTE_USER_TERMINATED_CONNECTION_ERROR,
     HCI_SUCCESS,
@@ -102,11 +104,17 @@ from .hci import (
     HCI_LE_Accept_CIS_Request_Command,
     HCI_LE_Add_Device_To_Resolving_List_Command,
     HCI_LE_Advertising_Report_Event,
+    HCI_LE_BIGInfo_Advertising_Report_Event,
     HCI_LE_Clear_Resolving_List_Command,
     HCI_LE_Connection_Update_Command,
     HCI_LE_Create_Connection_Cancel_Command,
     HCI_LE_Create_Connection_Command,
     HCI_LE_Create_CIS_Command,
+    HCI_LE_Periodic_Advertising_Create_Sync_Command,
+    HCI_LE_Periodic_Advertising_Create_Sync_Cancel_Command,
+    HCI_LE_Periodic_Advertising_Report_Event,
+    HCI_LE_Periodic_Advertising_Sync_Transfer_Command,
+    HCI_LE_Periodic_Advertising_Terminate_Sync_Command,
     HCI_LE_Enable_Encryption_Command,
     HCI_LE_Extended_Advertising_Report_Event,
     HCI_LE_Extended_Create_Connection_Command,
@@ -162,21 +170,29 @@ from .hci import (
     OwnAddressType,
     LeFeature,
     LeFeatureMask,
+    LmpFeatureMask,
     Phy,
     phy_list_to_bits,
 )
 from .host import Host
-from .gap import GenericAccessService
+from .profiles.gap import GenericAccessService
 from .core import (
     BT_BR_EDR_TRANSPORT,
     BT_CENTRAL_ROLE,
     BT_LE_TRANSPORT,
     BT_PERIPHERAL_ROLE,
     AdvertisingData,
+    BaseBumbleError,
     ConnectionParameterUpdateError,
     CommandTimeoutError,
+    ConnectionParameters,
     ConnectionPHY,
+    InvalidArgumentError,
+    InvalidOperationError,
     InvalidStateError,
+    NotSupportedError,
+    OutOfResourcesError,
+    UnreachableError,
 )
 from .utils import (
     AsyncRunner,
@@ -191,13 +207,13 @@ from .keys import (
     KeyStore,
     PairingKeys,
 )
-from .pairing import PairingConfig
-from . import gatt_client
-from . import gatt_server
-from . import smp
-from . import sdp
-from . import l2cap
-from . import core
+from bumble import pairing
+from bumble import gatt_client
+from bumble import gatt_server
+from bumble import smp
+from bumble import sdp
+from bumble import l2cap
+from bumble import core
 
 if TYPE_CHECKING:
     from .transport.common import TransportSource, TransportSink
@@ -248,6 +264,9 @@ DEVICE_DEFAULT_L2CAP_COC_MAX_CREDITS          = l2cap.L2CAP_LE_CREDIT_BASED_CONN
 DEVICE_DEFAULT_ADVERTISING_TX_POWER           = (
     HCI_LE_Set_Extended_Advertising_Parameters_Command.TX_POWER_NO_PREFERENCE
 )
+DEVICE_DEFAULT_PERIODIC_ADVERTISING_SYNC_SKIP = 0
+DEVICE_DEFAULT_PERIODIC_ADVERTISING_SYNC_TIMEOUT = 5.0
+DEVICE_DEFAULT_LE_RPA_TIMEOUT                 = 15 * 60 # 15 minutes (in seconds)
 
 # fmt: on
 # pylint: enable=line-too-long
@@ -259,6 +278,8 @@ DEVICE_MAX_HIGH_DUTY_CYCLE_CONNECTABLE_DIRECTED_ADVERTISING_DURATION = 1.28
 # -----------------------------------------------------------------------------
 # Classes
 # -----------------------------------------------------------------------------
+class ObjectLookupError(BaseBumbleError):
+    """Error raised when failed to lookup an object."""
 
 
 # -----------------------------------------------------------------------------
@@ -552,6 +573,70 @@ class AdvertisingEventProperties:
         )
 
 
+# -----------------------------------------------------------------------------
+@dataclass
+class PeriodicAdvertisement:
+    address: Address
+    sid: int
+    tx_power: int = (
+        HCI_LE_Periodic_Advertising_Report_Event.TX_POWER_INFORMATION_NOT_AVAILABLE
+    )
+    rssi: int = HCI_LE_Periodic_Advertising_Report_Event.RSSI_NOT_AVAILABLE
+    is_truncated: bool = False
+    data_bytes: bytes = b''
+
+    # Constants
+    TX_POWER_NOT_AVAILABLE: ClassVar[int] = (
+        HCI_LE_Periodic_Advertising_Report_Event.TX_POWER_INFORMATION_NOT_AVAILABLE
+    )
+    RSSI_NOT_AVAILABLE: ClassVar[int] = (
+        HCI_LE_Periodic_Advertising_Report_Event.RSSI_NOT_AVAILABLE
+    )
+
+    def __post_init__(self) -> None:
+        self.data = (
+            None if self.is_truncated else AdvertisingData.from_bytes(self.data_bytes)
+        )
+
+
+# -----------------------------------------------------------------------------
+@dataclass
+class BIGInfoAdvertisement:
+    address: Address
+    sid: int
+    num_bis: int
+    nse: int
+    iso_interval: int
+    bn: int
+    pto: int
+    irc: int
+    max_pdu: int
+    sdu_interval: int
+    max_sdu: int
+    phy: Phy
+    framed: bool
+    encrypted: bool
+
+    @classmethod
+    def from_report(cls, address: Address, sid: int, report) -> Self:
+        return cls(
+            address,
+            sid,
+            report.num_bis,
+            report.nse,
+            report.iso_interval,
+            report.bn,
+            report.pto,
+            report.irc,
+            report.max_pdu,
+            report.sdu_interval,
+            report.max_sdu,
+            Phy(report.phy),
+            report.framing != 0,
+            report.encryption != 0,
+        )
+
+
 # -----------------------------------------------------------------------------
 # TODO: replace with typing.TypeAlias when the code base is all Python >= 3.10
 AdvertisingChannelMap = HCI_LE_Set_Extended_Advertising_Parameters_Command.ChannelMap
@@ -795,6 +880,206 @@ class AdvertisingSet(EventEmitter):
         self.emit('termination', status)
 
 
+# -----------------------------------------------------------------------------
+class PeriodicAdvertisingSync(EventEmitter):
+    class State(Enum):
+        INIT = 0
+        PENDING = 1
+        ESTABLISHED = 2
+        CANCELLED = 3
+        ERROR = 4
+        LOST = 5
+        TERMINATED = 6
+
+    _state: State
+    sync_handle: Optional[int]
+    advertiser_address: Address
+    sid: int
+    skip: int
+    sync_timeout: float  # Sync timeout, in seconds
+    filter_duplicates: bool
+    status: int
+    advertiser_phy: int
+    periodic_advertising_interval: int
+    advertiser_clock_accuracy: int
+
+    def __init__(
+        self,
+        device: Device,
+        advertiser_address: Address,
+        sid: int,
+        skip: int,
+        sync_timeout: float,
+        filter_duplicates: bool,
+    ) -> None:
+        super().__init__()
+        self._state = self.State.INIT
+        self.sync_handle = None
+        self.device = device
+        self.advertiser_address = advertiser_address
+        self.sid = sid
+        self.skip = skip
+        self.sync_timeout = sync_timeout
+        self.filter_duplicates = filter_duplicates
+        self.status = HCI_SUCCESS
+        self.advertiser_phy = 0
+        self.periodic_advertising_interval = 0
+        self.advertiser_clock_accuracy = 0
+        self.data_accumulator = b''
+
+    @property
+    def state(self) -> State:
+        return self._state
+
+    @state.setter
+    def state(self, state: State) -> None:
+        logger.debug(f'{self} -> {state.name}')
+        self._state = state
+        self.emit('state_change')
+
+    async def establish(self) -> None:
+        if self.state != self.State.INIT:
+            raise InvalidStateError('sync not in init state')
+
+        options = HCI_LE_Periodic_Advertising_Create_Sync_Command.Options(0)
+        if self.filter_duplicates:
+            options |= (
+                HCI_LE_Periodic_Advertising_Create_Sync_Command.Options.DUPLICATE_FILTERING_INITIALLY_ENABLED
+            )
+
+        response = await self.device.send_command(
+            HCI_LE_Periodic_Advertising_Create_Sync_Command(
+                options=options,
+                advertising_sid=self.sid,
+                advertiser_address_type=self.advertiser_address.address_type,
+                advertiser_address=self.advertiser_address,
+                skip=self.skip,
+                sync_timeout=int(self.sync_timeout * 100),
+                sync_cte_type=0,
+            )
+        )
+        if response.status != HCI_Command_Status_Event.PENDING:
+            raise HCI_StatusError(response)
+
+        self.state = self.State.PENDING
+
+    async def terminate(self) -> None:
+        if self.state in (self.State.INIT, self.State.CANCELLED, self.State.TERMINATED):
+            return
+
+        if self.state == self.State.PENDING:
+            self.state = self.State.CANCELLED
+            response = await self.device.send_command(
+                HCI_LE_Periodic_Advertising_Create_Sync_Cancel_Command(),
+            )
+            if response.return_parameters == HCI_SUCCESS:
+                if self in self.device.periodic_advertising_syncs:
+                    self.device.periodic_advertising_syncs.remove(self)
+            return
+
+        if self.state in (self.State.ESTABLISHED, self.State.ERROR, self.State.LOST):
+            self.state = self.State.TERMINATED
+            if self.sync_handle is not None:
+                await self.device.send_command(
+                    HCI_LE_Periodic_Advertising_Terminate_Sync_Command(
+                        sync_handle=self.sync_handle
+                    )
+                )
+            self.device.periodic_advertising_syncs.remove(self)
+
+    async def transfer(self, connection: Connection, service_data: int = 0) -> None:
+        if self.sync_handle is not None:
+            await connection.transfer_periodic_sync(self.sync_handle, service_data)
+
+    def on_establishment(
+        self,
+        status,
+        sync_handle,
+        advertiser_phy,
+        periodic_advertising_interval,
+        advertiser_clock_accuracy,
+    ) -> None:
+        self.status = status
+
+        if self.state == self.State.CANCELLED:
+            # Somehow, we receive an established event after trying to cancel, most
+            # likely because the cancel command was sent too late, when the sync was
+            # already established, but before the established event was sent.
+            # We need to automatically terminate.
+            logger.debug(
+                "received established event for cancelled sync, will terminate"
+            )
+            self.state = self.State.ESTABLISHED
+            AsyncRunner.spawn(self.terminate())
+            return
+
+        if status == HCI_SUCCESS:
+            self.sync_handle = sync_handle
+            self.advertiser_phy = advertiser_phy
+            self.periodic_advertising_interval = periodic_advertising_interval
+            self.advertiser_clock_accuracy = advertiser_clock_accuracy
+            self.state = self.State.ESTABLISHED
+            self.emit('establishment')
+            return
+
+        # We don't need to keep a reference anymore
+        if self in self.device.periodic_advertising_syncs:
+            self.device.periodic_advertising_syncs.remove(self)
+
+        if status == HCI_OPERATION_CANCELLED_BY_HOST_ERROR:
+            self.state = self.State.CANCELLED
+            self.emit('cancellation')
+            return
+
+        self.state = self.State.ERROR
+        self.emit('error')
+
+    def on_loss(self):
+        self.state = self.State.LOST
+        self.emit('loss')
+
+    def on_periodic_advertising_report(self, report) -> None:
+        self.data_accumulator += report.data
+        if (
+            report.data_status
+            == HCI_LE_Periodic_Advertising_Report_Event.DataStatus.DATA_INCOMPLETE_MORE_TO_COME
+        ):
+            return
+
+        self.emit(
+            'periodic_advertisement',
+            PeriodicAdvertisement(
+                self.advertiser_address,
+                self.sid,
+                report.tx_power,
+                report.rssi,
+                is_truncated=(
+                    report.data_status
+                    == HCI_LE_Periodic_Advertising_Report_Event.DataStatus.DATA_INCOMPLETE_TRUNCATED_NO_MORE_TO_COME
+                ),
+                data_bytes=self.data_accumulator,
+            ),
+        )
+        self.data_accumulator = b''
+
+    def on_biginfo_advertising_report(self, report) -> None:
+        self.emit(
+            'biginfo_advertisement',
+            BIGInfoAdvertisement.from_report(self.advertiser_address, self.sid, report),
+        )
+
+    def __str__(self) -> str:
+        return (
+            'PeriodicAdvertisingSync('
+            f'state={self.state.name}, '
+            f'sync_handle={self.sync_handle}, '
+            f'sid={self.sid}, '
+            f'skip={self.skip}, '
+            f'filter_duplicates={self.filter_duplicates}'
+            ')'
+        )
+
+
 # -----------------------------------------------------------------------------
 class LePhyOptions:
     # Coded PHY preference
@@ -867,6 +1152,15 @@ class Peer:
     async def discover_attributes(self) -> List[gatt_client.AttributeProxy]:
         return await self.gatt_client.discover_attributes()
 
+    async def discover_all(self):
+        await self.discover_services()
+        for service in self.services:
+            await self.discover_characteristics(service=service)
+
+        for service in self.services:
+            for characteristic in service.characteristics:
+                await self.discover_descriptors(characteristic=characteristic)
+
     async def subscribe(
         self,
         characteristic: gatt_client.CharacteristicProxy,
@@ -906,12 +1200,29 @@ class Peer:
         return self.gatt_client.get_services_by_uuid(uuid)
 
     def get_characteristics_by_uuid(
-        self, uuid: core.UUID, service: Optional[gatt_client.ServiceProxy] = None
+        self,
+        uuid: core.UUID,
+        service: Optional[Union[gatt_client.ServiceProxy, core.UUID]] = None,
     ) -> List[gatt_client.CharacteristicProxy]:
+        if isinstance(service, core.UUID):
+            return list(
+                itertools.chain(
+                    *[
+                        self.get_characteristics_by_uuid(uuid, s)
+                        for s in self.get_services_by_uuid(service)
+                    ]
+                )
+            )
+
         return self.gatt_client.get_characteristics_by_uuid(uuid, service)
 
-    def create_service_proxy(self, proxy_class: Type[_PROXY_CLASS]) -> _PROXY_CLASS:
-        return cast(_PROXY_CLASS, proxy_class.from_client(self.gatt_client))
+    def create_service_proxy(
+        self, proxy_class: Type[_PROXY_CLASS]
+    ) -> Optional[_PROXY_CLASS]:
+        if proxy := proxy_class.from_client(self.gatt_client):
+            return cast(_PROXY_CLASS, proxy)
+
+        return None
 
     async def discover_service_and_create_proxy(
         self, proxy_class: Type[_PROXY_CLASS]
@@ -1008,6 +1319,7 @@ class Connection(CompositeEventEmitter):
     handle: int
     transport: int
     self_address: Address
+    self_resolvable_address: Optional[Address]
     peer_address: Address
     peer_resolvable_address: Optional[Address]
     peer_le_features: Optional[LeFeatureMask]
@@ -1055,6 +1367,7 @@ class Connection(CompositeEventEmitter):
         handle,
         transport,
         self_address,
+        self_resolvable_address,
         peer_address,
         peer_resolvable_address,
         role,
@@ -1066,6 +1379,7 @@ class Connection(CompositeEventEmitter):
         self.handle = handle
         self.transport = transport
         self.self_address = self_address
+        self.self_resolvable_address = self_resolvable_address
         self.peer_address = peer_address
         self.peer_resolvable_address = peer_resolvable_address
         self.peer_name = None  # Classic only
@@ -1099,6 +1413,7 @@ class Connection(CompositeEventEmitter):
             None,
             BT_BR_EDR_TRANSPORT,
             device.public_address,
+            None,
             peer_address,
             None,
             role,
@@ -1192,11 +1507,9 @@ class Connection(CompositeEventEmitter):
 
         try:
             await asyncio.wait_for(self.device.abort_on('flush', abort), timeout)
-        except asyncio.TimeoutError:
-            pass
-
-        self.remove_listener('disconnection', abort.set_result)
-        self.remove_listener('disconnection_failure', abort.set_exception)
+        finally:
+            self.remove_listener('disconnection', abort.set_result)
+            self.remove_listener('disconnection_failure', abort.set_exception)
 
     async def set_data_length(self, tx_octets, tx_time) -> None:
         return await self.device.set_data_length(self, tx_octets, tx_time)
@@ -1227,6 +1540,11 @@ class Connection(CompositeEventEmitter):
     async def get_phy(self):
         return await self.device.get_connection_phy(self)
 
+    async def transfer_periodic_sync(
+        self, sync_handle: int, service_data: int = 0
+    ) -> None:
+        await self.device.transfer_periodic_sync(self, sync_handle, service_data)
+
     # [Classic only]
     async def request_remote_name(self):
         return await self.device.request_remote_name(self)
@@ -1257,7 +1575,9 @@ class Connection(CompositeEventEmitter):
             f'Connection(handle=0x{self.handle:04X}, '
             f'role={self.role_name}, '
             f'self_address={self.self_address}, '
-            f'peer_address={self.peer_address})'
+            f'self_resolvable_address={self.self_resolvable_address}, '
+            f'peer_address={self.peer_address}, '
+            f'peer_resolvable_address={self.peer_resolvable_address})'
         )
 
 
@@ -1272,13 +1592,15 @@ class DeviceConfiguration:
     advertising_interval_min: int = DEVICE_DEFAULT_ADVERTISING_INTERVAL
     advertising_interval_max: int = DEVICE_DEFAULT_ADVERTISING_INTERVAL
     le_enabled: bool = True
-    # LE host enable 2nd parameter
     le_simultaneous_enabled: bool = False
+    le_privacy_enabled: bool = False
+    le_rpa_timeout: int = DEVICE_DEFAULT_LE_RPA_TIMEOUT
     classic_enabled: bool = False
     classic_sc_enabled: bool = True
     classic_ssp_enabled: bool = True
     classic_smp_enabled: bool = True
     classic_accept_any: bool = True
+    classic_interlaced_scan_enabled: bool = True
     connectable: bool = True
     discoverable: bool = True
     advertising_data: bytes = bytes(
@@ -1289,7 +1611,10 @@ class DeviceConfiguration:
     irk: bytes = bytes(16)  # This really must be changed for any level of security
     keystore: Optional[str] = None
     address_resolution_offload: bool = False
+    address_generation_offload: bool = False
     cis_enabled: bool = False
+    identity_address_type: Optional[int] = None
+    io_capability: int = pairing.PairingDelegate.IoCapability.NO_OUTPUT_NO_INPUT
 
     def __post_init__(self) -> None:
         self.gatt_services: List[Dict[str, Any]] = []
@@ -1374,7 +1699,9 @@ def with_connection_from_handle(function):
     @functools.wraps(function)
     def wrapper(self, connection_handle, *args, **kwargs):
         if (connection := self.lookup_connection(connection_handle)) is None:
-            raise ValueError(f'no connection for handle: 0x{connection_handle:04x}')
+            raise ObjectLookupError(
+                f'no connection for handle: 0x{connection_handle:04x}'
+            )
         return function(self, connection, *args, **kwargs)
 
     return wrapper
@@ -1389,7 +1716,7 @@ def with_connection_from_address(function):
         for connection in self.connections.values():
             if connection.peer_address == address:
                 return function(self, connection, *args, **kwargs)
-        raise ValueError('no connection for address')
+        raise ObjectLookupError('no connection for address')
 
     return wrapper
 
@@ -1409,6 +1736,20 @@ def try_with_connection_from_address(function):
     return wrapper
 
 
+# Decorator that converts the first argument from a sync handle to a periodic
+# advertising sync object
+def with_periodic_advertising_sync_from_handle(function):
+    @functools.wraps(function)
+    def wrapper(self, sync_handle, *args, **kwargs):
+        if (sync := self.lookup_periodic_advertising_sync(sync_handle)) is None:
+            raise ValueError(
+                f'no periodic advertising sync for handle: 0x{sync_handle:04x}'
+            )
+        return function(self, sync, *args, **kwargs)
+
+    return wrapper
+
+
 # Decorator that adds a method to the list of event handlers for host events.
 # This assumes that the method name starts with `on_`
 def host_event_handler(function):
@@ -1425,8 +1766,9 @@ device_host_event_handlers: List[str] = []
 # -----------------------------------------------------------------------------
 class Device(CompositeEventEmitter):
     # Incomplete list of fields.
-    random_address: Address
-    public_address: Address
+    random_address: Address  # Random address that may change with RPA
+    public_address: Address  # Public address (obtained from the controller)
+    static_address: Address  # Random address that can be set but does not change
     classic_enabled: bool
     name: str
     class_of_device: int
@@ -1439,6 +1781,7 @@ class Device(CompositeEventEmitter):
         Address, List[asyncio.Future[Union[Connection, Tuple[Address, int, int]]]]
     ]
     advertisement_accumulators: Dict[Address, AdvertisementDataAccumulator]
+    periodic_advertising_syncs: List[PeriodicAdvertisingSync]
     config: DeviceConfiguration
     legacy_advertiser: Optional[LegacyAdvertiser]
     sco_links: Dict[int, ScoLink]
@@ -1524,6 +1867,7 @@ class Device(CompositeEventEmitter):
             [l2cap.L2CAP_Information_Request.EXTENDED_FEATURE_FIXED_CHANNELS]
         )
         self.advertisement_accumulators = {}  # Accumulators, by address
+        self.periodic_advertising_syncs = []
         self.scanning = False
         self.scanning_is_passive = False
         self.discovering = False
@@ -1554,26 +1898,33 @@ class Device(CompositeEventEmitter):
         config = config or DeviceConfiguration()
         self.config = config
 
-        self.public_address = Address('00:00:00:00:00:00')
         self.name = config.name
+        self.public_address = Address.ANY
         self.random_address = config.address
+        self.static_address = config.address
         self.class_of_device = config.class_of_device
         self.keystore = None
         self.irk = config.irk
         self.le_enabled = config.le_enabled
-        self.classic_enabled = config.classic_enabled
         self.le_simultaneous_enabled = config.le_simultaneous_enabled
+        self.le_privacy_enabled = config.le_privacy_enabled
+        self.le_rpa_timeout = config.le_rpa_timeout
+        self.le_rpa_periodic_update_task: Optional[asyncio.Task] = None
+        self.classic_enabled = config.classic_enabled
         self.cis_enabled = config.cis_enabled
         self.classic_sc_enabled = config.classic_sc_enabled
         self.classic_ssp_enabled = config.classic_ssp_enabled
         self.classic_smp_enabled = config.classic_smp_enabled
+        self.classic_interlaced_scan_enabled = config.classic_interlaced_scan_enabled
         self.discoverable = config.discoverable
         self.connectable = config.connectable
         self.classic_accept_any = config.classic_accept_any
         self.address_resolution_offload = config.address_resolution_offload
+        self.address_generation_offload = config.address_generation_offload
 
         # Extended advertising.
         self.extended_advertising_sets: Dict[int, AdvertisingSet] = {}
+        self.connecting_extended_advertising_sets: Dict[int, AdvertisingSet] = {}
 
         # Legacy advertising.
         # The advertising and scan response data, as well as the advertising interval
@@ -1625,10 +1976,23 @@ class Device(CompositeEventEmitter):
             if isinstance(address, str):
                 address = Address(address)
             self.random_address = address
+            self.static_address = address
 
         # Setup SMP
         self.smp_manager = smp.Manager(
-            self, pairing_config_factory=lambda connection: PairingConfig()
+            self,
+            pairing_config_factory=lambda connection: pairing.PairingConfig(
+                identity_address_type=(
+                    pairing.PairingConfig.AddressType(self.config.identity_address_type)
+                    if self.config.identity_address_type
+                    else None
+                ),
+                delegate=pairing.PairingDelegate(
+                    io_capability=pairing.PairingDelegate.IoCapability(
+                        self.config.io_capability
+                    )
+                ),
+            ),
         )
 
         self.l2cap_channel_manager.register_fixed_channel(smp.SMP_CID, self.on_smp_pdu)
@@ -1706,6 +2070,18 @@ class Device(CompositeEventEmitter):
 
         return None
 
+    def lookup_periodic_advertising_sync(
+        self, sync_handle: int
+    ) -> Optional[PeriodicAdvertisingSync]:
+        return next(
+            (
+                sync
+                for sync in self.periodic_advertising_syncs
+                if sync.sync_handle == sync_handle
+            ),
+            None,
+        )
+
     @deprecated("Please use create_l2cap_server()")
     def register_l2cap_server(self, psm, server) -> int:
         return self.l2cap_channel_manager.register_server(psm, server)
@@ -1798,7 +2174,7 @@ class Device(CompositeEventEmitter):
                 spec=spec,
             )
         else:
-            raise ValueError(f'Unexpected mode {spec}')
+            raise InvalidArgumentError(f'Unexpected mode {spec}')
 
     def send_l2cap_pdu(self, connection_handle: int, cid: int, pdu: bytes) -> None:
         self.host.send_l2cap_pdu(connection_handle, cid, pdu)
@@ -1840,26 +2216,26 @@ class Device(CompositeEventEmitter):
                 HCI_Write_LE_Host_Support_Command(
                     le_supported_host=int(self.le_enabled),
                     simultaneous_le_host=int(self.le_simultaneous_enabled),
-                )
+                ),
+                check_result=True,
             )
 
         if self.le_enabled:
-            # Set the controller address
-            if self.random_address == Address.ANY_RANDOM:
-                # Try to use an address generated at random by the controller
-                if self.host.supports_command(HCI_LE_RAND_COMMAND):
-                    # Get 8 random bytes
-                    response = await self.send_command(
-                        HCI_LE_Rand_Command(), check_result=True
+            # Generate a random address if not set.
+            if self.static_address == Address.ANY_RANDOM:
+                self.static_address = Address.generate_static_address()
+
+            # If LE Privacy is enabled, generate an RPA
+            if self.le_privacy_enabled:
+                self.random_address = Address.generate_private_address(self.irk)
+                logger.info(f'Initial RPA: {self.random_address}')
+                if self.le_rpa_timeout > 0:
+                    # Start a task to periodically generate a new RPA
+                    self.le_rpa_periodic_update_task = asyncio.create_task(
+                        self._run_rpa_periodic_update()
                     )
-
-                    # Ensure the address bytes can be a static random address
-                    address_bytes = response.return_parameters.random_number[
-                        :5
-                    ] + bytes([response.return_parameters.random_number[5] | 0xC0])
-
-                    # Create a static random address from the random bytes
-                    self.random_address = Address(address_bytes)
+            else:
+                self.random_address = self.static_address
 
             if self.random_address != Address.ANY_RANDOM:
                 logger.debug(
@@ -1884,7 +2260,8 @@ class Device(CompositeEventEmitter):
                 await self.send_command(
                     HCI_LE_Set_Address_Resolution_Enable_Command(
                         address_resolution_enable=1
-                    )
+                    ),
+                    check_result=True,
                 )
 
             if self.cis_enabled:
@@ -1892,7 +2269,8 @@ class Device(CompositeEventEmitter):
                     HCI_LE_Set_Host_Feature_Command(
                         bit_number=LeFeature.CONNECTED_ISOCHRONOUS_STREAM,
                         bit_value=1,
-                    )
+                    ),
+                    check_result=True,
                 )
 
         if self.classic_enabled:
@@ -1915,6 +2293,21 @@ class Device(CompositeEventEmitter):
             await self.set_connectable(self.connectable)
             await self.set_discoverable(self.discoverable)
 
+            if self.classic_interlaced_scan_enabled:
+                if self.host.supports_lmp_features(LmpFeatureMask.INTERLACED_PAGE_SCAN):
+                    await self.send_command(
+                        hci.HCI_Write_Page_Scan_Type_Command(page_scan_type=1),
+                        check_result=True,
+                    )
+
+                if self.host.supports_lmp_features(
+                    LmpFeatureMask.INTERLACED_INQUIRY_SCAN
+                ):
+                    await self.send_command(
+                        hci.HCI_Write_Inquiry_Scan_Type_Command(scan_type=1),
+                        check_result=True,
+                    )
+
         # Done
         self.powered_on = True
 
@@ -1923,9 +2316,45 @@ class Device(CompositeEventEmitter):
 
     async def power_off(self) -> None:
         if self.powered_on:
+            if self.le_rpa_periodic_update_task:
+                self.le_rpa_periodic_update_task.cancel()
+
             await self.host.flush()
+
             self.powered_on = False
 
+    async def update_rpa(self) -> bool:
+        """
+        Try to update the RPA.
+
+        Returns:
+          True if the RPA was updated, False if it could not be updated.
+        """
+
+        # Check if this is a good time to rotate the address
+        if self.is_advertising or self.is_scanning or self.is_le_connecting:
+            logger.debug('skipping RPA update')
+            return False
+
+        random_address = Address.generate_private_address(self.irk)
+        response = await self.send_command(
+            HCI_LE_Set_Random_Address_Command(random_address=self.random_address)
+        )
+        if response.return_parameters == HCI_SUCCESS:
+            logger.info(f'new RPA: {random_address}')
+            self.random_address = random_address
+            return True
+        else:
+            logger.warning(f'failed to set RPA: {response.return_parameters}')
+            return False
+
+    async def _run_rpa_periodic_update(self) -> None:
+        """Update the RPA periodically"""
+        while self.le_rpa_timeout != 0:
+            await asyncio.sleep(self.le_rpa_timeout)
+            if not self.update_rpa():
+                logger.debug("periodic RPA update failed")
+
     async def refresh_resolving_list(self) -> None:
         assert self.keystore is not None
 
@@ -1933,7 +2362,7 @@ class Device(CompositeEventEmitter):
         # Create a host-side address resolver
         self.address_resolver = smp.AddressResolver(resolving_keys)
 
-        if self.address_resolution_offload:
+        if self.address_resolution_offload or self.address_generation_offload:
             await self.send_command(HCI_LE_Clear_Resolving_List_Command())
 
             # Add an empty entry for non-directed address generation.
@@ -1959,7 +2388,7 @@ class Device(CompositeEventEmitter):
     def supports_le_features(self, feature: LeFeatureMask) -> bool:
         return self.host.supports_le_features(feature)
 
-    def supports_le_phy(self, phy):
+    def supports_le_phy(self, phy: int) -> bool:
         if phy == HCI_LE_1M_PHY:
             return True
 
@@ -1968,7 +2397,7 @@ class Device(CompositeEventEmitter):
             HCI_LE_CODED_PHY: LeFeatureMask.LE_CODED_PHY,
         }
         if phy not in feature_map:
-            raise ValueError('invalid PHY')
+            raise InvalidArgumentError('invalid PHY')
 
         return self.supports_le_features(feature_map[phy])
 
@@ -1976,6 +2405,10 @@ class Device(CompositeEventEmitter):
     def supports_le_extended_advertising(self):
         return self.supports_le_features(LeFeatureMask.LE_EXTENDED_ADVERTISING)
 
+    @property
+    def supports_le_periodic_advertising(self):
+        return self.supports_le_features(LeFeatureMask.LE_PERIODIC_ADVERTISING)
+
     async def start_advertising(
         self,
         advertising_type: AdvertisingType = AdvertisingType.UNDIRECTED_CONNECTABLE_SCANNABLE,
@@ -2028,7 +2461,7 @@ class Device(CompositeEventEmitter):
         # Decide what peer address to use
         if advertising_type.is_directed:
             if target is None:
-                raise ValueError('directed advertising requires a target')
+                raise InvalidArgumentError('directed advertising requires a target')
             peer_address = target
         else:
             peer_address = Address.ANY
@@ -2135,7 +2568,7 @@ class Device(CompositeEventEmitter):
             and advertising_data
             and scan_response_data
         ):
-            raise ValueError(
+            raise InvalidArgumentError(
                 "Extended advertisements can't have both data and scan \
                               response data"
             )
@@ -2151,7 +2584,9 @@ class Device(CompositeEventEmitter):
                 if handle not in self.extended_advertising_sets
             )
         except StopIteration as exc:
-            raise RuntimeError("all valid advertising handles already in use") from exc
+            raise OutOfResourcesError(
+                "all valid advertising handles already in use"
+            ) from exc
 
         # Use the device's random address if a random address is needed but none was
         # provided.
@@ -2250,14 +2685,14 @@ class Device(CompositeEventEmitter):
     ) -> None:
         # Check that the arguments are legal
         if scan_interval < scan_window:
-            raise ValueError('scan_interval must be >= scan_window')
+            raise InvalidArgumentError('scan_interval must be >= scan_window')
         if (
             scan_interval < DEVICE_MIN_SCAN_INTERVAL
             or scan_interval > DEVICE_MAX_SCAN_INTERVAL
         ):
-            raise ValueError('scan_interval out of range')
+            raise InvalidArgumentError('scan_interval out of range')
         if scan_window < DEVICE_MIN_SCAN_WINDOW or scan_window > DEVICE_MAX_SCAN_WINDOW:
-            raise ValueError('scan_interval out of range')
+            raise InvalidArgumentError('scan_interval out of range')
 
         # Reset the accumulators
         self.advertisement_accumulators = {}
@@ -2285,7 +2720,7 @@ class Device(CompositeEventEmitter):
                     scanning_phy_count += 1
 
             if scanning_phy_count == 0:
-                raise ValueError('at least one scanning PHY must be enabled')
+                raise InvalidArgumentError('at least one scanning PHY must be enabled')
 
             await self.send_command(
                 HCI_LE_Set_Extended_Scan_Parameters_Command(
@@ -2368,6 +2803,120 @@ class Device(CompositeEventEmitter):
         if advertisement := accumulator.update(report):
             self.emit('advertisement', advertisement)
 
+    async def create_periodic_advertising_sync(
+        self,
+        advertiser_address: Address,
+        sid: int,
+        skip: int = DEVICE_DEFAULT_PERIODIC_ADVERTISING_SYNC_SKIP,
+        sync_timeout: float = DEVICE_DEFAULT_PERIODIC_ADVERTISING_SYNC_TIMEOUT,
+        filter_duplicates: bool = False,
+    ) -> PeriodicAdvertisingSync:
+        # Check that the controller supports the feature.
+        if not self.supports_le_periodic_advertising:
+            raise NotSupportedError()
+
+        # Check that there isn't already an equivalent entry
+        if any(
+            sync.advertiser_address == advertiser_address and sync.sid == sid
+            for sync in self.periodic_advertising_syncs
+        ):
+            raise ValueError("equivalent entry already created")
+
+        # Create a new entry
+        sync = PeriodicAdvertisingSync(
+            device=self,
+            advertiser_address=advertiser_address,
+            sid=sid,
+            skip=skip,
+            sync_timeout=sync_timeout,
+            filter_duplicates=filter_duplicates,
+        )
+
+        self.periodic_advertising_syncs.append(sync)
+
+        # Check if any sync should be started
+        await self._update_periodic_advertising_syncs()
+
+        return sync
+
+    async def _update_periodic_advertising_syncs(self) -> None:
+        # Check if there's already a pending sync
+        if any(
+            sync.state == PeriodicAdvertisingSync.State.PENDING
+            for sync in self.periodic_advertising_syncs
+        ):
+            logger.debug("at least one sync pending, nothing to update yet")
+            return
+
+        # Start the next sync that's waiting to be started
+        if ready := next(
+            (
+                sync
+                for sync in self.periodic_advertising_syncs
+                if sync.state == PeriodicAdvertisingSync.State.INIT
+            ),
+            None,
+        ):
+            await ready.establish()
+            return
+
+    @host_event_handler
+    def on_periodic_advertising_sync_establishment(
+        self,
+        status: int,
+        sync_handle: int,
+        advertising_sid: int,
+        advertiser_address: Address,
+        advertiser_phy: int,
+        periodic_advertising_interval: int,
+        advertiser_clock_accuracy: int,
+    ) -> None:
+        for periodic_advertising_sync in self.periodic_advertising_syncs:
+            if (
+                periodic_advertising_sync.advertiser_address == advertiser_address
+                and periodic_advertising_sync.sid == advertising_sid
+            ):
+                periodic_advertising_sync.on_establishment(
+                    status,
+                    sync_handle,
+                    advertiser_phy,
+                    periodic_advertising_interval,
+                    advertiser_clock_accuracy,
+                )
+
+                AsyncRunner.spawn(self._update_periodic_advertising_syncs())
+
+                return
+
+        logger.warning(
+            "periodic advertising sync establishment for unknown address/sid"
+        )
+
+    @host_event_handler
+    @with_periodic_advertising_sync_from_handle
+    def on_periodic_advertising_sync_loss(
+        self, periodic_advertising_sync: PeriodicAdvertisingSync
+    ):
+        periodic_advertising_sync.on_loss()
+
+    @host_event_handler
+    @with_periodic_advertising_sync_from_handle
+    def on_periodic_advertising_report(
+        self,
+        periodic_advertising_sync: PeriodicAdvertisingSync,
+        report: HCI_LE_Periodic_Advertising_Report_Event,
+    ):
+        periodic_advertising_sync.on_periodic_advertising_report(report)
+
+    @host_event_handler
+    @with_periodic_advertising_sync_from_handle
+    def on_biginfo_advertising_report(
+        self,
+        periodic_advertising_sync: PeriodicAdvertisingSync,
+        report: HCI_LE_BIGInfo_Advertising_Report_Event,
+    ):
+        periodic_advertising_sync.on_biginfo_advertising_report(report)
+
     async def start_discovery(self, auto_restart: bool = True) -> None:
         await self.send_command(
             HCI_Write_Inquiry_Mode_Command(inquiry_mode=HCI_EXTENDED_INQUIRY_MODE),
@@ -2463,23 +3012,52 @@ class Device(CompositeEventEmitter):
         ] = None,
         own_address_type: int = OwnAddressType.RANDOM,
         timeout: Optional[float] = DEVICE_DEFAULT_CONNECT_TIMEOUT,
+        always_resolve: bool = False,
     ) -> Connection:
         '''
         Request a connection to a peer.
-        When transport is BLE, this method cannot be called if there is already a
+
+        When the transport is BLE, this method cannot be called if there is already a
         pending connection.
 
-        connection_parameters_preferences: (BLE only, ignored for BR/EDR)
-          * None: use the 1M PHY with default parameters
-          * map: each entry has a PHY as key and a ConnectionParametersPreferences
-            object as value
+        Args:
+          peer_address:
+            Address or name of the device to connect to.
+            If a string is passed:
+              If the string is an address followed by a `@` suffix, the `always_resolve`
+              argument is implicitly set to True, so the connection is made to the
+              address after resolution.
+              If the string is any other address, the connection is made to that
+              address (with or without address resolution, depending on the
+              `always_resolve` argument).
+              For any other string, a scan for devices using that string as their name
+              is initiated, and a connection to the first matching device's address
+              is made. In that case, `always_resolve` is ignored.
+
+          connection_parameters_preferences:
+            (BLE only, ignored for BR/EDR)
+            * None: use the 1M PHY with default parameters
+            * map: each entry has a PHY as key and a ConnectionParametersPreferences
+              object as value
 
-        own_address_type: (BLE only)
+          own_address_type:
+            (BLE only, ignored for BR/EDR)
+            OwnAddressType.RANDOM to use this device's random address, or
+            OwnAddressType.PUBLIC to use this device's public address.
+
+          timeout:
+            Maximum time to wait for a connection to be established, in seconds.
+            Pass None for an unlimited time.
+
+          always_resolve:
+            (BLE only, ignored for BR/EDR)
+            If True, always initiate a scan, resolving addresses, and connect to the
+            address that resolves to `peer_address`.
         '''
 
         # Check parameters
         if transport not in (BT_LE_TRANSPORT, BT_BR_EDR_TRANSPORT):
-            raise ValueError('invalid transport')
+            raise InvalidArgumentError('invalid transport')
 
         # Adjust the transport automatically if we need to
         if transport == BT_LE_TRANSPORT and not self.le_enabled:
@@ -2493,11 +3071,19 @@ class Device(CompositeEventEmitter):
 
         if isinstance(peer_address, str):
             try:
-                peer_address = Address.from_string_for_transport(
-                    peer_address, transport
-                )
-            except ValueError:
+                if transport == BT_LE_TRANSPORT and peer_address.endswith('@'):
+                    peer_address = Address.from_string_for_transport(
+                        peer_address[:-1], transport
+                    )
+                    always_resolve = True
+                    logger.debug('forcing address resolution')
+                else:
+                    peer_address = Address.from_string_for_transport(
+                        peer_address, transport
+                    )
+            except (InvalidArgumentError, ValueError):
                 # If the address is not parsable, assume it is a name instead
+                always_resolve = False
                 logger.debug('looking for peer by name')
                 peer_address = await self.find_peer_by_name(
                     peer_address, transport
@@ -2508,10 +3094,16 @@ class Device(CompositeEventEmitter):
                 transport == BT_BR_EDR_TRANSPORT
                 and peer_address.address_type != Address.PUBLIC_DEVICE_ADDRESS
             ):
-                raise ValueError('BR/EDR addresses must be PUBLIC')
+                raise InvalidArgumentError('BR/EDR addresses must be PUBLIC')
 
         assert isinstance(peer_address, Address)
 
+        if transport == BT_LE_TRANSPORT and always_resolve:
+            logger.debug('resolving address')
+            peer_address = await self.find_peer_by_identity_address(
+                peer_address
+            )  # TODO: timeout
+
         def on_connection(connection):
             if transport == BT_LE_TRANSPORT or (
                 # match BR/EDR connection event against peer address
@@ -2559,7 +3151,7 @@ class Device(CompositeEventEmitter):
                         )
                     )
                     if not phys:
-                        raise ValueError('at least one supported PHY needed')
+                        raise InvalidArgumentError('at least one supported PHY needed')
 
                     phy_count = len(phys)
                     initiating_phys = phy_list_to_bits(phys)
@@ -2631,7 +3223,7 @@ class Device(CompositeEventEmitter):
                     )
                 else:
                     if HCI_LE_1M_PHY not in connection_parameters_preferences:
-                        raise ValueError('1M PHY preferences required')
+                        raise InvalidArgumentError('1M PHY preferences required')
 
                     prefs = connection_parameters_preferences[HCI_LE_1M_PHY]
                     result = await self.send_command(
@@ -2731,7 +3323,7 @@ class Device(CompositeEventEmitter):
         if isinstance(peer_address, str):
             try:
                 peer_address = Address(peer_address)
-            except ValueError:
+            except InvalidArgumentError:
                 # If the address is not parsable, assume it is a name instead
                 logger.debug('looking for peer by name')
                 peer_address = await self.find_peer_by_name(
@@ -2741,7 +3333,7 @@ class Device(CompositeEventEmitter):
         assert isinstance(peer_address, Address)
 
         if peer_address == Address.NIL:
-            raise ValueError('accept on nil address')
+            raise InvalidArgumentError('accept on nil address')
 
         # Create a future so that we can wait for the request
         pending_request_fut = asyncio.get_running_loop().create_future()
@@ -2854,7 +3446,7 @@ class Device(CompositeEventEmitter):
             if isinstance(peer_address, str):
                 try:
                     peer_address = Address(peer_address)
-                except ValueError:
+                except InvalidArgumentError:
                     # If the address is not parsable, assume it is a name instead
                     logger.debug('looking for peer by name')
                     peer_address = await self.find_peer_by_name(
@@ -2897,10 +3489,10 @@ class Device(CompositeEventEmitter):
 
     async def set_data_length(self, connection, tx_octets, tx_time) -> None:
         if tx_octets < 0x001B or tx_octets > 0x00FB:
-            raise ValueError('tx_octets must be between 0x001B and 0x00FB')
+            raise InvalidArgumentError('tx_octets must be between 0x001B and 0x00FB')
 
         if tx_time < 0x0148 or tx_time > 0x4290:
-            raise ValueError('tx_time must be between 0x0148 and 0x4290')
+            raise InvalidArgumentError('tx_time must be between 0x0148 and 0x4290')
 
         return await self.send_command(
             HCI_LE_Set_Data_Length_Command(
@@ -3013,15 +3605,26 @@ class Device(CompositeEventEmitter):
             check_result=True,
         )
 
+    async def transfer_periodic_sync(
+        self, connection: Connection, sync_handle: int, service_data: int = 0
+    ) -> None:
+        return await self.send_command(
+            HCI_LE_Periodic_Advertising_Sync_Transfer_Command(
+                connection_handle=connection.handle,
+                service_data=service_data,
+                sync_handle=sync_handle,
+            ),
+            check_result=True,
+        )
+
     async def find_peer_by_name(self, name, transport=BT_LE_TRANSPORT):
         """
-        Scan for a peer with a give name and return its address and transport
+        Scan for a peer with a given name and return its address.
         """
 
         # Create a future to wait for an address to be found
         peer_address = asyncio.get_running_loop().create_future()
 
-        # Scan/inquire with event handlers to handle scan/inquiry results
         def on_peer_found(address, ad_data):
             local_name = ad_data.get(AdvertisingData.COMPLETE_LOCAL_NAME, raw=True)
             if local_name is None:
@@ -3030,13 +3633,13 @@ class Device(CompositeEventEmitter):
                 if local_name.decode('utf-8') == name:
                     peer_address.set_result(address)
 
-        handler = None
+        listener = None
         was_scanning = self.scanning
         was_discovering = self.discovering
         try:
             if transport == BT_LE_TRANSPORT:
                 event_name = 'advertisement'
-                handler = self.on(
+                listener = self.on(
                     event_name,
                     lambda advertisement: on_peer_found(
                         advertisement.address, advertisement.data
@@ -3048,7 +3651,7 @@ class Device(CompositeEventEmitter):
 
             elif transport == BT_BR_EDR_TRANSPORT:
                 event_name = 'inquiry_result'
-                handler = self.on(
+                listener = self.on(
                     event_name,
                     lambda address, class_of_device, eir_data, rssi: on_peer_found(
                         address, eir_data
@@ -3062,21 +3665,67 @@ class Device(CompositeEventEmitter):
 
             return await self.abort_on('flush', peer_address)
         finally:
-            if handler is not None:
-                self.remove_listener(event_name, handler)
+            if listener is not None:
+                self.remove_listener(event_name, listener)
 
             if transport == BT_LE_TRANSPORT and not was_scanning:
                 await self.stop_scanning()
             elif transport == BT_BR_EDR_TRANSPORT and not was_discovering:
                 await self.stop_discovery()
 
+    async def find_peer_by_identity_address(self, identity_address: Address) -> Address:
+        """
+        Scan for a peer with a resolvable address that can be resolved to a given
+        identity address.
+        """
+
+        # Create a future to wait for an address to be found
+        peer_address = asyncio.get_running_loop().create_future()
+
+        def on_peer_found(address, _):
+            if address == identity_address:
+                if not peer_address.done():
+                    logger.debug(f'*** Matching public address found for {address}')
+                    peer_address.set_result(address)
+                return
+
+            if address.is_resolvable:
+                resolved_address = self.address_resolver.resolve(address)
+                if resolved_address == identity_address:
+                    if not peer_address.done():
+                        logger.debug(f'*** Matching identity found for {address}')
+                        peer_address.set_result(address)
+                return
+
+        was_scanning = self.scanning
+        event_name = 'advertisement'
+        listener = None
+        try:
+            listener = self.on(
+                event_name,
+                lambda advertisement: on_peer_found(
+                    advertisement.address, advertisement.data
+                ),
+            )
+
+            if not self.scanning:
+                await self.start_scanning(filter_duplicates=True)
+
+            return await self.abort_on('flush', peer_address)
+        finally:
+            if listener is not None:
+                self.remove_listener(event_name, listener)
+
+            if not was_scanning:
+                await self.stop_scanning()
+
     @property
-    def pairing_config_factory(self) -> Callable[[Connection], PairingConfig]:
+    def pairing_config_factory(self) -> Callable[[Connection], pairing.PairingConfig]:
         return self.smp_manager.pairing_config_factory
 
     @pairing_config_factory.setter
     def pairing_config_factory(
-        self, pairing_config_factory: Callable[[Connection], PairingConfig]
+        self, pairing_config_factory: Callable[[Connection], pairing.PairingConfig]
     ) -> None:
         self.smp_manager.pairing_config_factory = pairing_config_factory
 
@@ -3175,7 +3824,7 @@ class Device(CompositeEventEmitter):
 
     async def encrypt(self, connection, enable=True):
         if not enable and connection.transport == BT_LE_TRANSPORT:
-            raise ValueError('`enable` parameter is classic only.')
+            raise InvalidArgumentError('`enable` parameter is classic only.')
 
         # Set up event handlers
         pending_encryption = asyncio.get_running_loop().create_future()
@@ -3194,11 +3843,12 @@ class Device(CompositeEventEmitter):
             if connection.transport == BT_LE_TRANSPORT:
                 # Look for a key in the key store
                 if self.keystore is None:
-                    raise RuntimeError('no key store')
+                    raise InvalidOperationError('no key store')
 
+                logger.debug(f'Looking up key for {connection.peer_address}')
                 keys = await self.keystore.get(str(connection.peer_address))
                 if keys is None:
-                    raise RuntimeError('keys not found in key store')
+                    raise InvalidOperationError('keys not found in key store')
 
                 if keys.ltk is not None:
                     ltk = keys.ltk.value
@@ -3209,7 +3859,7 @@ class Device(CompositeEventEmitter):
                     rand = keys.ltk_central.rand
                     ediv = keys.ltk_central.ediv
                 else:
-                    raise RuntimeError('no LTK found for peer')
+                    raise InvalidOperationError('no LTK found for peer')
 
                 if connection.role != HCI_CENTRAL_ROLE:
                     raise InvalidStateError('only centrals can start encryption')
@@ -3484,7 +4134,7 @@ class Device(CompositeEventEmitter):
                 return cis_link
 
         # Mypy believes this is reachable when context is an ExitStack.
-        raise InvalidStateError('Unreachable')
+        raise UnreachableError()
 
     # [LE only]
     @experimental('Only for testing.')
@@ -3605,18 +4255,38 @@ class Device(CompositeEventEmitter):
             )
             return
 
-        if not (connection := self.lookup_connection(connection_handle)):
-            logger.warning(f'no connection for handle 0x{connection_handle:04x}')
+        if connection := self.lookup_connection(connection_handle):
+            # We have already received the connection complete event.
+            self._complete_le_extended_advertising_connection(
+                connection, advertising_set
+            )
             return
 
+        # Associate the connection handle with the advertising set, the connection
+        # will complete later.
+        logger.debug(
+            f'the connection with handle {connection_handle:04X} will complete later'
+        )
+        self.connecting_extended_advertising_sets[connection_handle] = advertising_set
+
+    def _complete_le_extended_advertising_connection(
+        self, connection: Connection, advertising_set: AdvertisingSet
+    ) -> None:
         # Update the connection address.
         connection.self_address = (
             advertising_set.random_address
-            if advertising_set.advertising_parameters.own_address_type
+            if advertising_set.random_address is not None
+            and advertising_set.advertising_parameters.own_address_type
             in (OwnAddressType.RANDOM, OwnAddressType.RESOLVABLE_OR_RANDOM)
             else self.public_address
         )
 
+        if advertising_set.advertising_parameters.own_address_type in (
+            OwnAddressType.RANDOM,
+            OwnAddressType.PUBLIC,
+        ):
+            connection.self_resolvable_address = None
+
         # Setup auto-restart of the advertising set if needed.
         if advertising_set.auto_restart:
             connection.once(
@@ -3652,12 +4322,23 @@ class Device(CompositeEventEmitter):
     @host_event_handler
     def on_connection(
         self,
-        connection_handle,
-        transport,
-        peer_address,
-        role,
-        connection_parameters,
-    ):
+        connection_handle: int,
+        transport: int,
+        peer_address: Address,
+        self_resolvable_address: Optional[Address],
+        peer_resolvable_address: Optional[Address],
+        role: int,
+        connection_parameters: ConnectionParameters,
+    ) -> None:
+        # Convert all-zeros addresses into None.
+        if self_resolvable_address == Address.ANY_RANDOM:
+            self_resolvable_address = None
+        if (
+            peer_resolvable_address == Address.ANY_RANDOM
+            or not peer_address.is_resolved
+        ):
+            peer_resolvable_address = None
+
         logger.debug(
             f'*** Connection: [0x{connection_handle:04X}] '
             f'{peer_address} {"" if role is None else HCI_Constant.role_name(role)}'
@@ -3678,17 +4359,18 @@ class Device(CompositeEventEmitter):
 
             return
 
-        # Resolve the peer address if we can
-        peer_resolvable_address = None
-        if self.address_resolver:
-            if peer_address.is_resolvable:
-                resolved_address = self.address_resolver.resolve(peer_address)
-                if resolved_address is not None:
-                    logger.debug(f'*** Address resolved as {resolved_address}')
-                    peer_resolvable_address = peer_address
-                    peer_address = resolved_address
+        if peer_resolvable_address is None:
+            # Resolve the peer address if we can
+            if self.address_resolver:
+                if peer_address.is_resolvable:
+                    resolved_address = self.address_resolver.resolve(peer_address)
+                    if resolved_address is not None:
+                        logger.debug(f'*** Address resolved as {resolved_address}')
+                        peer_resolvable_address = peer_address
+                        peer_address = resolved_address
 
         self_address = None
+        own_address_type: Optional[int] = None
         if role == HCI_CENTRAL_ROLE:
             own_address_type = self.connect_own_address_type
             assert own_address_type is not None
@@ -3717,12 +4399,18 @@ class Device(CompositeEventEmitter):
                 else self.random_address
             )
 
+        # Some controllers may return local resolvable address even not using address
+        # generation offloading. Ignore the value to prevent SMP failure.
+        if own_address_type in (OwnAddressType.RANDOM, OwnAddressType.PUBLIC):
+            self_resolvable_address = None
+
         # Create a connection.
         connection = Connection(
             self,
             connection_handle,
             transport,
             self_address,
+            self_resolvable_address,
             peer_address,
             peer_resolvable_address,
             role,
@@ -3733,9 +4421,10 @@ class Device(CompositeEventEmitter):
 
         if role == HCI_PERIPHERAL_ROLE and self.legacy_advertiser:
             if self.legacy_advertiser.auto_restart:
+                advertiser = self.legacy_advertiser
                 connection.once(
                     'disconnection',
-                    lambda _: self.abort_on('flush', self.legacy_advertiser.start()),
+                    lambda _: self.abort_on('flush', advertiser.start()),
                 )
             else:
                 self.legacy_advertiser = None
@@ -3743,6 +4432,16 @@ class Device(CompositeEventEmitter):
         if role == HCI_CENTRAL_ROLE or not self.supports_le_extended_advertising:
             # We can emit now, we have all the info we need
             self._emit_le_connection(connection)
+            return
+
+        if role == HCI_PERIPHERAL_ROLE and self.supports_le_extended_advertising:
+            if advertising_set := self.connecting_extended_advertising_sets.pop(
+                connection_handle, None
+            ):
+                # We have already received the advertising set termination event.
+                self._complete_le_extended_advertising_connection(
+                    connection, advertising_set
+                )
 
     @host_event_handler
     def on_connection_failure(self, transport, peer_address, error_code):
@@ -3948,7 +4647,7 @@ class Device(CompositeEventEmitter):
             return await pairing_config.delegate.confirm(auto=True)
 
         async def na() -> bool:
-            assert False, "N/A: unreachable"
+            raise UnreachableError()
 
         # See Bluetooth spec @ Vol 3, Part C 5.2.2.6
         methods = {
@@ -4409,5 +5108,6 @@ class Device(CompositeEventEmitter):
         return (
             f'Device(name="{self.name}", '
             f'random_address="{self.random_address}", '
-            f'public_address="{self.public_address}")'
+            f'public_address="{self.public_address}", '
+            f'static_address="{self.static_address}")'
         )
diff --git a/bumble/drivers/rtk.py b/bumble/drivers/rtk.py
index 4a9034d..c332bf0 100644
--- a/bumble/drivers/rtk.py
+++ b/bumble/drivers/rtk.py
@@ -33,6 +33,7 @@ from typing import Tuple
 import weakref
 
 
+from bumble import core
 from bumble.hci import (
     hci_vendor_command_op_code,
     STATUS_SPEC,
@@ -49,6 +50,10 @@ from bumble.drivers import common
 logger = logging.getLogger(__name__)
 
 
+class RtkFirmwareError(core.BaseBumbleError):
+    """Error raised when RTK firmware initialization fails."""
+
+
 # -----------------------------------------------------------------------------
 # Constants
 # -----------------------------------------------------------------------------
@@ -208,15 +213,15 @@ class Firmware:
         extension_sig = bytes([0x51, 0x04, 0xFD, 0x77])
 
         if not firmware.startswith(RTK_EPATCH_SIGNATURE):
-            raise ValueError("Firmware does not start with epatch signature")
+            raise RtkFirmwareError("Firmware does not start with epatch signature")
 
         if not firmware.endswith(extension_sig):
-            raise ValueError("Firmware does not end with extension sig")
+            raise RtkFirmwareError("Firmware does not end with extension sig")
 
         # The firmware should start with a 14 byte header.
         epatch_header_size = 14
         if len(firmware) < epatch_header_size:
-            raise ValueError("Firmware too short")
+            raise RtkFirmwareError("Firmware too short")
 
         # Look for the "project ID", starting from the end.
         offset = len(firmware) - len(extension_sig)
@@ -230,7 +235,7 @@ class Firmware:
                 break
 
             if length == 0:
-                raise ValueError("Invalid 0-length instruction")
+                raise RtkFirmwareError("Invalid 0-length instruction")
 
             if opcode == 0 and length == 1:
                 project_id = firmware[offset - 1]
@@ -239,7 +244,7 @@ class Firmware:
             offset -= length
 
         if project_id < 0:
-            raise ValueError("Project ID not found")
+            raise RtkFirmwareError("Project ID not found")
 
         self.project_id = project_id
 
@@ -252,7 +257,7 @@ class Firmware:
         # <PatchLength_1><PatchLength_2>...<PatchLength_N> (16 bits each)
         # <PatchOffset_1><PatchOffset_2>...<PatchOffset_N> (32 bits each)
         if epatch_header_size + 8 * num_patches > len(firmware):
-            raise ValueError("Firmware too short")
+            raise RtkFirmwareError("Firmware too short")
         chip_id_table_offset = epatch_header_size
         patch_length_table_offset = chip_id_table_offset + 2 * num_patches
         patch_offset_table_offset = chip_id_table_offset + 4 * num_patches
@@ -266,7 +271,7 @@ class Firmware:
                 "<I", firmware, patch_offset_table_offset + 4 * patch_index
             )
             if patch_offset + patch_length > len(firmware):
-                raise ValueError("Firmware too short")
+                raise RtkFirmwareError("Firmware too short")
 
             # Get the SVN version for the patch
             (svn_version,) = struct.unpack_from(
@@ -296,6 +301,8 @@ class Driver(common.Driver):
         fw_name: str = ""
         config_name: str = ""
 
+    POST_RESET_DELAY: float = 0.2
+
     DRIVER_INFOS = [
         # 8723A
         DriverInfo(
@@ -490,12 +497,24 @@ class Driver(common.Driver):
 
     @classmethod
     async def driver_info_for_host(cls, host):
-        await host.send_command(HCI_Reset_Command(), check_result=True)
-        host.ready = True  # Needed to let the host know the controller is ready.
+        try:
+            await host.send_command(
+                HCI_Reset_Command(),
+                check_result=True,
+                response_timeout=cls.POST_RESET_DELAY,
+            )
+            host.ready = True  # Needed to let the host know the controller is ready.
+        except asyncio.exceptions.TimeoutError:
+            logger.warning("timeout waiting for hci reset, retrying")
+            await host.send_command(HCI_Reset_Command(), check_result=True)
+            host.ready = True
+
+        command = HCI_Read_Local_Version_Information_Command()
+        response = await host.send_command(command, check_result=True)
+        if response.command_opcode != command.op_code:
+            logger.error("failed to probe local version information")
+            return None
 
-        response = await host.send_command(
-            HCI_Read_Local_Version_Information_Command(), check_result=True
-        )
         local_version = response.return_parameters
 
         logger.debug(
@@ -645,7 +664,7 @@ class Driver(common.Driver):
         ):
             return await self.download_for_rtl8723b()
 
-        raise ValueError("ROM not supported")
+        raise RtkFirmwareError("ROM not supported")
 
     async def init_controller(self):
         await self.download_firmware()
diff --git a/bumble/gatt.py b/bumble/gatt.py
index 896cec0..3e679bb 100644
--- a/bumble/gatt.py
+++ b/bumble/gatt.py
@@ -39,7 +39,7 @@ from typing import (
 )
 
 from bumble.colors import color
-from bumble.core import UUID
+from bumble.core import BaseBumbleError, UUID
 from bumble.att import Attribute, AttributeValue
 
 if TYPE_CHECKING:
@@ -238,22 +238,22 @@ GATT_SEARCH_CONTROL_POINT_CHARACTERISTIC                  = UUID.from_16_bits(0x
 GATT_CONTENT_CONTROL_ID_CHARACTERISTIC                    = UUID.from_16_bits(0x2BBA, 'Content Control Id')
 
 # Telephone Bearer Service (TBS)
-GATT_BEARER_PROVIDER_NAME_CHARACTERISTIC                      = UUID.from_16_bits(0x2BB4, 'Bearer Provider Name')
-GATT_BEARER_UCI_CHARACTERISTIC                                = UUID.from_16_bits(0x2BB5, 'Bearer UCI')
-GATT_BEARER_TECHNOLOGY_CHARACTERISTIC                         = UUID.from_16_bits(0x2BB6, 'Bearer Technology')
-GATT_BEARER_URI_SCHEMES_SUPPORTED_LIST_CHARACTERISTIC         = UUID.from_16_bits(0x2BB7, 'Bearer URI Schemes Supported List')
-GATT_BEARER_SIGNAL_STRENGTH_CHARACTERISTIC                    = UUID.from_16_bits(0x2BB8, 'Bearer Signal Strength')
-GATT_BEARER_SIGNAL_STRENGTH_REPORTING_INTERVAL_CHARACTERISTIC = UUID.from_16_bits(0x2BB9, 'Bearer Signal Strength Reporting Interval')
-GATT_BEARER_LIST_CURRENT_CALLS_CHARACTERISTIC                 = UUID.from_16_bits(0x2BBA, 'Bearer List Current Calls')
-GATT_CONTENT_CONTROL_ID_CHARACTERISTIC                        = UUID.from_16_bits(0x2BBB, 'Content Control ID')
-GATT_STATUS_FLAGS_CHARACTERISTIC                              = UUID.from_16_bits(0x2BBC, 'Status Flags')
-GATT_INCOMING_CALL_TARGET_BEARER_URI_CHARACTERISTIC           = UUID.from_16_bits(0x2BBD, 'Incoming Call Target Bearer URI')
-GATT_CALL_STATE_CHARACTERISTIC                                = UUID.from_16_bits(0x2BBE, 'Call State')
-GATT_CALL_CONTROL_POINT_CHARACTERISTIC                        = UUID.from_16_bits(0x2BBF, 'Call Control Point')
-GATT_CALL_CONTROL_POINT_OPTIONAL_OPCODES_CHARACTERISTIC       = UUID.from_16_bits(0x2BC0, 'Call Control Point Optional Opcodes')
-GATT_TERMINATION_REASON_CHARACTERISTIC                        = UUID.from_16_bits(0x2BC1, 'Termination Reason')
-GATT_INCOMING_CALL_CHARACTERISTIC                             = UUID.from_16_bits(0x2BC2, 'Incoming Call')
-GATT_CALL_FRIENDLY_NAME_CHARACTERISTIC                        = UUID.from_16_bits(0x2BC3, 'Call Friendly Name')
+GATT_BEARER_PROVIDER_NAME_CHARACTERISTIC                      = UUID.from_16_bits(0x2BB3, 'Bearer Provider Name')
+GATT_BEARER_UCI_CHARACTERISTIC                                = UUID.from_16_bits(0x2BB4, 'Bearer UCI')
+GATT_BEARER_TECHNOLOGY_CHARACTERISTIC                         = UUID.from_16_bits(0x2BB5, 'Bearer Technology')
+GATT_BEARER_URI_SCHEMES_SUPPORTED_LIST_CHARACTERISTIC         = UUID.from_16_bits(0x2BB6, 'Bearer URI Schemes Supported List')
+GATT_BEARER_SIGNAL_STRENGTH_CHARACTERISTIC                    = UUID.from_16_bits(0x2BB7, 'Bearer Signal Strength')
+GATT_BEARER_SIGNAL_STRENGTH_REPORTING_INTERVAL_CHARACTERISTIC = UUID.from_16_bits(0x2BB8, 'Bearer Signal Strength Reporting Interval')
+GATT_BEARER_LIST_CURRENT_CALLS_CHARACTERISTIC                 = UUID.from_16_bits(0x2BB9, 'Bearer List Current Calls')
+GATT_CONTENT_CONTROL_ID_CHARACTERISTIC                        = UUID.from_16_bits(0x2BBA, 'Content Control ID')
+GATT_STATUS_FLAGS_CHARACTERISTIC                              = UUID.from_16_bits(0x2BBB, 'Status Flags')
+GATT_INCOMING_CALL_TARGET_BEARER_URI_CHARACTERISTIC           = UUID.from_16_bits(0x2BBC, 'Incoming Call Target Bearer URI')
+GATT_CALL_STATE_CHARACTERISTIC                                = UUID.from_16_bits(0x2BBD, 'Call State')
+GATT_CALL_CONTROL_POINT_CHARACTERISTIC                        = UUID.from_16_bits(0x2BBE, 'Call Control Point')
+GATT_CALL_CONTROL_POINT_OPTIONAL_OPCODES_CHARACTERISTIC       = UUID.from_16_bits(0x2BBF, 'Call Control Point Optional Opcodes')
+GATT_TERMINATION_REASON_CHARACTERISTIC                        = UUID.from_16_bits(0x2BC0, 'Termination Reason')
+GATT_INCOMING_CALL_CHARACTERISTIC                             = UUID.from_16_bits(0x2BC1, 'Incoming Call')
+GATT_CALL_FRIENDLY_NAME_CHARACTERISTIC                        = UUID.from_16_bits(0x2BC2, 'Call Friendly Name')
 
 # Microphone Control Service (MICS)
 GATT_MUTE_CHARACTERISTIC = UUID.from_16_bits(0x2BC3, 'Mute')
@@ -275,6 +275,11 @@ GATT_SOURCE_AUDIO_LOCATION_CHARACTERISTIC       = UUID.from_16_bits(0x2BCC, 'Sou
 GATT_AVAILABLE_AUDIO_CONTEXTS_CHARACTERISTIC    = UUID.from_16_bits(0x2BCD, 'Available Audio Contexts')
 GATT_SUPPORTED_AUDIO_CONTEXTS_CHARACTERISTIC    = UUID.from_16_bits(0x2BCE, 'Supported Audio Contexts')
 
+# Hearing Access Service
+GATT_HEARING_AID_FEATURES_CHARACTERISTIC             = UUID.from_16_bits(0x2BDA, 'Hearing Aid Features')
+GATT_HEARING_AID_PRESET_CONTROL_POINT_CHARACTERISTIC = UUID.from_16_bits(0x2BDB, 'Hearing Aid Preset Control Point')
+GATT_ACTIVE_PRESET_INDEX_CHARACTERISTIC              = UUID.from_16_bits(0x2BDC, 'Active Preset Index')
+
 # ASHA Service
 GATT_ASHA_SERVICE                             = UUID.from_16_bits(0xFDF0, 'Audio Streaming for Hearing Aid')
 GATT_ASHA_READ_ONLY_PROPERTIES_CHARACTERISTIC = UUID('6333651e-c481-4a3e-9169-7c902aad37bb', 'ReadOnlyProperties')
@@ -320,6 +325,11 @@ def show_services(services: Iterable[Service]) -> None:
                 print(color('    ' + str(descriptor), 'green'))
 
 
+# -----------------------------------------------------------------------------
+class InvalidServiceError(BaseBumbleError):
+    """The service is not compliant with the spec/profile"""
+
+
 # -----------------------------------------------------------------------------
 class Service(Attribute):
     '''
diff --git a/bumble/gatt_client.py b/bumble/gatt_client.py
index c71aabd..b975a31 100644
--- a/bumble/gatt_client.py
+++ b/bumble/gatt_client.py
@@ -68,7 +68,7 @@ from .att import (
     ATT_Error,
 )
 from . import core
-from .core import UUID, InvalidStateError, ProtocolError
+from .core import UUID, InvalidStateError
 from .gatt import (
     GATT_CHARACTERISTIC_ATTRIBUTE_TYPE,
     GATT_CLIENT_CHARACTERISTIC_CONFIGURATION_DESCRIPTOR,
@@ -253,7 +253,7 @@ class ProfileServiceProxy:
     SERVICE_CLASS: Type[TemplateService]
 
     @classmethod
-    def from_client(cls, client: Client) -> ProfileServiceProxy:
+    def from_client(cls, client: Client) -> Optional[ProfileServiceProxy]:
         return ServiceProxy.from_client(cls, client, cls.SERVICE_CLASS.UUID)
 
 
@@ -283,6 +283,8 @@ class Client:
         self.services = []
         self.cached_values = {}
 
+        connection.on('disconnection', self.on_disconnection)
+
     def send_gatt_pdu(self, pdu: bytes) -> None:
         self.connection.send_l2cap_pdu(ATT_CID, pdu)
 
@@ -331,9 +333,9 @@ class Client:
     async def request_mtu(self, mtu: int) -> int:
         # Check the range
         if mtu < ATT_DEFAULT_MTU:
-            raise ValueError(f'MTU must be >= {ATT_DEFAULT_MTU}')
+            raise core.InvalidArgumentError(f'MTU must be >= {ATT_DEFAULT_MTU}')
         if mtu > 0xFFFF:
-            raise ValueError('MTU must be <= 0xFFFF')
+            raise core.InvalidArgumentError('MTU must be <= 0xFFFF')
 
         # We can only send one request per connection
         if self.mtu_exchange_done:
@@ -343,12 +345,7 @@ class Client:
         self.mtu_exchange_done = True
         response = await self.send_request(ATT_Exchange_MTU_Request(client_rx_mtu=mtu))
         if response.op_code == ATT_ERROR_RESPONSE:
-            raise ProtocolError(
-                response.error_code,
-                'att',
-                ATT_PDU.error_name(response.error_code),
-                response,
-            )
+            raise ATT_Error(error_code=response.error_code, message=response)
 
         # Compute the final MTU
         self.connection.att_mtu = min(mtu, response.server_rx_mtu)
@@ -405,7 +402,7 @@ class Client:
         if not already_known:
             self.services.append(service)
 
-    async def discover_services(self, uuids: Iterable[UUID] = []) -> List[ServiceProxy]:
+    async def discover_services(self, uuids: Iterable[UUID] = ()) -> List[ServiceProxy]:
         '''
         See Vol 3, Part G - 4.4.1 Discover All Primary Services
         '''
@@ -934,12 +931,7 @@ class Client:
         if response is None:
             raise TimeoutError('read timeout')
         if response.op_code == ATT_ERROR_RESPONSE:
-            raise ProtocolError(
-                response.error_code,
-                'att',
-                ATT_PDU.error_name(response.error_code),
-                response,
-            )
+            raise ATT_Error(error_code=response.error_code, message=response)
 
         # If the value is the max size for the MTU, try to read more unless the caller
         # specifically asked not to do that
@@ -961,12 +953,7 @@ class Client:
                         ATT_INVALID_OFFSET_ERROR,
                     ):
                         break
-                    raise ProtocolError(
-                        response.error_code,
-                        'att',
-                        ATT_PDU.error_name(response.error_code),
-                        response,
-                    )
+                    raise ATT_Error(error_code=response.error_code, message=response)
 
                 part = response.part_attribute_value
                 attribute_value += part
@@ -1059,12 +1046,7 @@ class Client:
                 )
             )
             if response.op_code == ATT_ERROR_RESPONSE:
-                raise ProtocolError(
-                    response.error_code,
-                    'att',
-                    ATT_PDU.error_name(response.error_code),
-                    response,
-                )
+                raise ATT_Error(error_code=response.error_code, message=response)
         else:
             await self.send_command(
                 ATT_Write_Command(
@@ -1072,6 +1054,10 @@ class Client:
                 )
             )
 
+    def on_disconnection(self, _) -> None:
+        if self.pending_response and not self.pending_response.done():
+            self.pending_response.cancel()
+
     def on_gatt_pdu(self, att_pdu: ATT_PDU) -> None:
         logger.debug(
             f'GATT Response to client: [0x{self.connection.handle:04X}] {att_pdu}'
diff --git a/bumble/gatt_server.py b/bumble/gatt_server.py
index be2b88e..0ee673c 100644
--- a/bumble/gatt_server.py
+++ b/bumble/gatt_server.py
@@ -915,7 +915,7 @@ class Server(EventEmitter):
         See Bluetooth spec Vol 3, Part F - 3.4.5.1 Write Request
         '''
 
-        # Check  that the attribute exists
+        # Check that the attribute exists
         attribute = self.get_attribute(request.attribute_handle)
         if attribute is None:
             self.send_response(
@@ -942,11 +942,19 @@ class Server(EventEmitter):
             )
             return
 
-        # Accept the value
-        await attribute.write_value(connection, request.attribute_value)
-
-        # Done
-        self.send_response(connection, ATT_Write_Response())
+        try:
+            # Accept the value
+            await attribute.write_value(connection, request.attribute_value)
+        except ATT_Error as error:
+            response = ATT_Error_Response(
+                request_opcode_in_error=request.op_code,
+                attribute_handle_in_error=request.attribute_handle,
+                error_code=error.error_code,
+            )
+        else:
+            # Done
+            response = ATT_Write_Response()
+        self.send_response(connection, response)
 
     @AsyncRunner.run_in_task()
     async def on_att_write_command(self, connection, request):
diff --git a/bumble/hci.py b/bumble/hci.py
index 9ef40bf..1d0cd8e 100644
--- a/bumble/hci.py
+++ b/bumble/hci.py
@@ -26,16 +26,19 @@ import struct
 from typing import Any, Callable, Dict, Iterable, List, Optional, Type, Union, ClassVar
 
 from bumble import crypto
-from .colors import color
-from .core import (
+from bumble.colors import color
+from bumble.core import (
     BT_BR_EDR_TRANSPORT,
     AdvertisingData,
     DeviceClass,
+    InvalidArgumentError,
+    InvalidPacketError,
     ProtocolError,
     bit_flags_to_strings,
     name_or_number,
     padded_bytes,
 )
+from bumble.utils import OpenIntEnum
 
 
 # -----------------------------------------------------------------------------
@@ -91,14 +94,14 @@ def map_class_of_device(class_of_device):
     )
 
 
-def phy_list_to_bits(phys):
+def phy_list_to_bits(phys: Optional[Iterable[int]]) -> int:
     if phys is None:
         return 0
 
     phy_bits = 0
     for phy in phys:
         if phy not in HCI_LE_PHY_TYPE_TO_BIT:
-            raise ValueError('invalid PHY')
+            raise InvalidArgumentError('invalid PHY')
         phy_bits |= 1 << HCI_LE_PHY_TYPE_TO_BIT[phy]
     return phy_bits
 
@@ -264,6 +267,19 @@ HCI_LE_PERIODIC_ADVERTISING_SYNC_TRANSFER_RECEIVED_V2_EVENT = 0X26
 HCI_LE_PERIODIC_ADVERTISING_SUBEVENT_DATA_REQUEST_EVENT     = 0X27
 HCI_LE_PERIODIC_ADVERTISING_RESPONSE_REPORT_EVENT           = 0X28
 HCI_LE_ENHANCED_CONNECTION_COMPLETE_V2_EVENT                = 0X29
+HCI_LE_READ_ALL_REMOTE_FEATURES_COMPLETE_EVENT              = 0x2A
+HCI_LE_CIS_ESTABLISHED_V2_EVENT                             = 0x2B
+HCI_LE_CS_READ_REMOTE_SUPPORTED_CAPABILITIES_COMPLETE_EVENT = 0x2C
+HCI_LE_CS_READ_REMOTE_FAE_TABLE_COMPLETE_EVENT              = 0x2D
+HCI_LE_CS_SECURITY_ENABLE_COMPLETE_EVENT                    = 0x2E
+HCI_LE_CS_CONFIG_COMPLETE_EVENT                             = 0x2F
+HCI_LE_CS_PROCEDURE_ENABLE_EVENT                            = 0x30
+HCI_LE_CS_SUBEVENT_RESULT_EVENT                             = 0x31
+HCI_LE_CS_SUBEVENT_RESULT_CONTINUE_EVENT                    = 0x32
+HCI_LE_CS_TEST_END_COMPLETE_EVENT                           = 0x33
+HCI_LE_MONITORED_ADVERTISERS_REPORT_EVENT                   = 0x34
+HCI_LE_FRAME_SPACE_UPDATE_EVENT                             = 0x35
+
 
 
 # HCI Command
@@ -570,11 +586,36 @@ HCI_LE_SET_DATA_RELATED_ADDRESS_CHANGES_COMMAND                          = hci_c
 HCI_LE_SET_DEFAULT_SUBRATE_COMMAND                                       = hci_command_op_code(0x08, 0x007D)
 HCI_LE_SUBRATE_REQUEST_COMMAND                                           = hci_command_op_code(0x08, 0x007E)
 HCI_LE_SET_EXTENDED_ADVERTISING_PARAMETERS_V2_COMMAND                    = hci_command_op_code(0x08, 0x007F)
+HCI_LE_SET_DECISION_DATA_COMMAND                                         = hci_command_op_code(0x08, 0x0080)
+HCI_LE_SET_DECISION_INSTRUCTIONS_COMMAND                                 = hci_command_op_code(0x08, 0x0081)
 HCI_LE_SET_PERIODIC_ADVERTISING_SUBEVENT_DATA_COMMAND                    = hci_command_op_code(0x08, 0x0082)
 HCI_LE_SET_PERIODIC_ADVERTISING_RESPONSE_DATA_COMMAND                    = hci_command_op_code(0x08, 0x0083)
 HCI_LE_SET_PERIODIC_SYNC_SUBEVENT_COMMAND                                = hci_command_op_code(0x08, 0x0084)
 HCI_LE_EXTENDED_CREATE_CONNECTION_V2_COMMAND                             = hci_command_op_code(0x08, 0x0085)
 HCI_LE_SET_PERIODIC_ADVERTISING_PARAMETERS_V2_COMMAND                    = hci_command_op_code(0x08, 0x0086)
+HCI_LE_READ_ALL_LOCAL_SUPPORTED_FEATURES_COMMAND                         = hci_command_op_code(0x08, 0x0087)
+HCI_LE_READ_ALL_REMOTE_FEATURES_COMMAND                                  = hci_command_op_code(0x08, 0x0088)
+HCI_LE_CS_READ_LOCAL_SUPPORTED_CAPABILITIES_COMMAND                      = hci_command_op_code(0x08, 0x0089)
+HCI_LE_CS_READ_REMOTE_SUPPORTED_CAPABILITIES_COMMAND                     = hci_command_op_code(0x08, 0x008A)
+HCI_LE_CS_WRITE_CACHED_REMOTE_SUPPORTED_CAPABILITIES                     = hci_command_op_code(0x08, 0x008B)
+HCI_LE_CS_SECURITY_ENABLE_COMMAND                                        = hci_command_op_code(0x08, 0x008C)
+HCI_LE_CS_SET_DEFAULT_SETTINGS_COMMAND                                   = hci_command_op_code(0x08, 0x008D)
+HCI_LE_CS_READ_REMOTE_FAE_TABLE_COMMAND                                  = hci_command_op_code(0x08, 0x008E)
+HCI_LE_CS_WRITE_CACHED_REMOTE_FAE_TABLE_COMMAND                          = hci_command_op_code(0x08, 0x008F)
+HCI_LE_CS_CREATE_CONFIG_COMMAND                                          = hci_command_op_code(0x08, 0x0090)
+HCI_LE_CS_REMOVE_CONFIG_COMMAND                                          = hci_command_op_code(0x08, 0x0091)
+HCI_LE_CS_SET_CHANNEL_CLASSIFICATION_COMMAND                             = hci_command_op_code(0x08, 0x0092)
+HCI_LE_CS_SET_PROCEDURE_PARAMETERS_COMMAND                               = hci_command_op_code(0x08, 0x0093)
+HCI_LE_CS_PROCEDURE_ENABLE_COMMAND                                       = hci_command_op_code(0x08, 0x0094)
+HCI_LE_CS_TEST_COMMAND                                                   = hci_command_op_code(0x08, 0x0095)
+HCI_LE_CS_TEST_END_COMMAND                                               = hci_command_op_code(0x08, 0x0096)
+HCI_LE_SET_HOST_FEATURE_V2_COMMAND                                       = hci_command_op_code(0x08, 0x0097)
+HCI_LE_ADD_DEVICE_TO_MONITORED_ADVERTISERS_LIST_COMMAND                  = hci_command_op_code(0x08, 0x0098)
+HCI_LE_REMOVE_DEVICE_FROM_MONITORED_ADVERTISERS_LIST_COMMAND             = hci_command_op_code(0x08, 0x0099)
+HCI_LE_CLEAR_MONITORED_ADVERTISERS_LIST_COMMAND                          = hci_command_op_code(0x08, 0x009A)
+HCI_LE_READ_MONITORED_ADVERTISERS_LIST_SIZE_COMMAND                      = hci_command_op_code(0x08, 0x009B)
+HCI_LE_ENABLE_MONITORING_ADVERTISERS_COMMAND                             = hci_command_op_code(0x08, 0x009C)
+HCI_LE_FRAME_SPACE_UPDATE_COMMAND                                        = hci_command_op_code(0x08, 0x009D)
 
 
 # HCI Error Codes
@@ -1104,7 +1145,7 @@ HCI_SUPPORTED_COMMANDS_MASKS = {
 
 # LE Supported Features
 # See Bluetooth spec @ Vol 6, Part B, 4.6 FEATURE SUPPORT
-class LeFeature(enum.IntEnum):
+class LeFeature(OpenIntEnum):
     LE_ENCRYPTION                                  = 0
     CONNECTION_PARAMETERS_REQUEST_PROCEDURE        = 1
     EXTENDED_REJECT_INDICATION                     = 2
@@ -1147,8 +1188,16 @@ class LeFeature(enum.IntEnum):
     CHANNEL_CLASSIFICATION                         = 39
     ADVERTISING_CODING_SELECTION                   = 40
     ADVERTISING_CODING_SELECTION_HOST_SUPPORT      = 41
+    DECISION_BASED_ADVERTISING_FILTERING           = 42
     PERIODIC_ADVERTISING_WITH_RESPONSES_ADVERTISER = 43
     PERIODIC_ADVERTISING_WITH_RESPONSES_SCANNER    = 44
+    UNSEGMENTED_FRAMED_MODE                        = 45
+    CHANNEL_SOUNDING                               = 46
+    CHANNEL_SOUNDING_HOST_SUPPORT                  = 47
+    CHANNEL_SOUNDING_TONE_QUALITY_INDICATION       = 48
+    LL_EXTENDED_FEATURE_SET                        = 63
+    MONITORING_ADVERTISERS                         = 64
+    FRAME_SPACE_UPDATE                             = 65
 
 class LeFeatureMask(enum.IntFlag):
     LE_ENCRYPTION                                  = 1 << LeFeature.LE_ENCRYPTION
@@ -1193,8 +1242,16 @@ class LeFeatureMask(enum.IntFlag):
     CHANNEL_CLASSIFICATION                         = 1 << LeFeature.CHANNEL_CLASSIFICATION
     ADVERTISING_CODING_SELECTION                   = 1 << LeFeature.ADVERTISING_CODING_SELECTION
     ADVERTISING_CODING_SELECTION_HOST_SUPPORT      = 1 << LeFeature.ADVERTISING_CODING_SELECTION_HOST_SUPPORT
+    DECISION_BASED_ADVERTISING_FILTERING           = 1 << LeFeature.DECISION_BASED_ADVERTISING_FILTERING
     PERIODIC_ADVERTISING_WITH_RESPONSES_ADVERTISER = 1 << LeFeature.PERIODIC_ADVERTISING_WITH_RESPONSES_ADVERTISER
     PERIODIC_ADVERTISING_WITH_RESPONSES_SCANNER    = 1 << LeFeature.PERIODIC_ADVERTISING_WITH_RESPONSES_SCANNER
+    UNSEGMENTED_FRAMED_MODE                        = 1 << LeFeature.UNSEGMENTED_FRAMED_MODE
+    CHANNEL_SOUNDING                               = 1 << LeFeature.CHANNEL_SOUNDING
+    CHANNEL_SOUNDING_HOST_SUPPORT                  = 1 << LeFeature.CHANNEL_SOUNDING_HOST_SUPPORT
+    CHANNEL_SOUNDING_TONE_QUALITY_INDICATION       = 1 << LeFeature.CHANNEL_SOUNDING_TONE_QUALITY_INDICATION
+    LL_EXTENDED_FEATURE_SET                        = 1 << LeFeature.LL_EXTENDED_FEATURE_SET
+    MONITORING_ADVERTISERS                         = 1 << LeFeature.MONITORING_ADVERTISERS
+    FRAME_SPACE_UPDATE                             = 1 << LeFeature.FRAME_SPACE_UPDATE
 
 class LmpFeature(enum.IntEnum):
     # Page 0 (Legacy LMP features)
@@ -1380,7 +1437,7 @@ class LmpFeatureMask(enum.IntFlag):
 STATUS_SPEC = {'size': 1, 'mapper': lambda x: HCI_Constant.status_name(x)}
 
 
-class CodecID(enum.IntEnum):
+class CodecID(OpenIntEnum):
     # fmt: off
     U_LOG           = 0x00
     A_LOG           = 0x01
@@ -1552,7 +1609,7 @@ class HCI_Object:
             new_offset, field_value = field_type(data, offset)
             return (field_value, new_offset - offset)
 
-        raise ValueError(f'unknown field type {field_type}')
+        raise InvalidArgumentError(f'unknown field type {field_type}')
 
     @staticmethod
     def dict_from_bytes(data, offset, fields):
@@ -1562,12 +1619,16 @@ class HCI_Object:
                 # This is an array field, starting with a 1-byte item count.
                 item_count = data[offset]
                 offset += 1
+                # Set fields first, because item_count might be 0.
+                for sub_field_name, _ in field:
+                    result[sub_field_name] = []
+
                 for _ in range(item_count):
                     for sub_field_name, sub_field_type in field:
                         value, size = HCI_Object.parse_field(
                             data, offset, sub_field_type
                         )
-                        result.setdefault(sub_field_name, []).append(value)
+                        result[sub_field_name].append(value)
                         offset += size
                 continue
 
@@ -1621,7 +1682,7 @@ class HCI_Object:
                 if 0 <= field_value <= 255:
                     field_bytes = bytes([field_value])
                 else:
-                    raise ValueError('value too large for *-typed field')
+                    raise InvalidArgumentError('value too large for *-typed field')
             else:
                 field_bytes = bytes(field_value)
         elif field_type == 'v':
@@ -1640,7 +1701,9 @@ class HCI_Object:
                 elif len(field_bytes) > field_type:
                     field_bytes = field_bytes[:field_type]
         else:
-            raise ValueError(f"don't know how to serialize type {type(field_value)}")
+            raise InvalidArgumentError(
+                f"don't know how to serialize type {type(field_value)}"
+            )
 
         return field_bytes
 
@@ -1834,6 +1897,12 @@ class Address:
             data, offset, Address.PUBLIC_DEVICE_ADDRESS
         )
 
+    @staticmethod
+    def parse_random_address(data, offset):
+        return Address.parse_address_with_type(
+            data, offset, Address.RANDOM_DEVICE_ADDRESS
+        )
+
     @staticmethod
     def parse_address_with_type(data, offset, address_type):
         return offset + 6, Address(data[offset : offset + 6], address_type)
@@ -1904,7 +1973,7 @@ class Address:
             self.address_bytes = bytes(reversed(bytes.fromhex(address)))
 
         if len(self.address_bytes) != 6:
-            raise ValueError('invalid address length')
+            raise InvalidArgumentError('invalid address length')
 
         self.address_type = address_type
 
@@ -1960,13 +2029,17 @@ class Address:
 
     def __eq__(self, other):
         return (
-            self.address_bytes == other.address_bytes
+            isinstance(other, Address)
+            and self.address_bytes == other.address_bytes
             and self.is_public == other.is_public
         )
 
     def __str__(self):
         return self.to_string()
 
+    def __repr__(self):
+        return f'Address({self.to_string(False)}/{self.address_type_name(self.address_type)})'
+
 
 # Predefined address values
 Address.NIL = Address(b"\xff\xff\xff\xff\xff\xff", Address.PUBLIC_DEVICE_ADDRESS)
@@ -2104,7 +2177,7 @@ class HCI_Command(HCI_Packet):
         op_code, length = struct.unpack_from('<HB', packet, 1)
         parameters = packet[4:]
         if len(parameters) != length:
-            raise ValueError('invalid packet length')
+            raise InvalidPacketError('invalid packet length')
 
         # Look for a registered class
         cls = HCI_Command.command_classes.get(op_code)
@@ -2967,6 +3040,27 @@ class HCI_Write_Inquiry_Scan_Activity_Command(HCI_Command):
     '''
 
 
+# -----------------------------------------------------------------------------
+@HCI_Command.command(
+    return_parameters_fields=[
+        ('status', STATUS_SPEC),
+        ('authentication_enable', 1),
+    ]
+)
+class HCI_Read_Authentication_Enable_Command(HCI_Command):
+    '''
+    See Bluetooth spec @ 7.3.23 Read Authentication Enable Command
+    '''
+
+
+# -----------------------------------------------------------------------------
+@HCI_Command.command([('authentication_enable', 1)])
+class HCI_Write_Authentication_Enable_Command(HCI_Command):
+    '''
+    See Bluetooth spec @ 7.3.24 Write Authentication Enable Command
+    '''
+
+
 # -----------------------------------------------------------------------------
 @HCI_Command.command(
     return_parameters_fields=[
@@ -3007,7 +3101,12 @@ class HCI_Write_Voice_Setting_Command(HCI_Command):
 
 
 # -----------------------------------------------------------------------------
-@HCI_Command.command()
+@HCI_Command.command(
+    return_parameters_fields=[
+        ('status', STATUS_SPEC),
+        ('synchronous_flow_control_enable', 1),
+    ]
+)
 class HCI_Read_Synchronous_Flow_Control_Enable_Command(HCI_Command):
     '''
     See Bluetooth spec @ 7.3.36 Read Synchronous Flow Control Enable Command
@@ -3176,7 +3275,13 @@ class HCI_Set_Event_Mask_Page_2_Command(HCI_Command):
 
 
 # -----------------------------------------------------------------------------
-@HCI_Command.command()
+@HCI_Command.command(
+    return_parameters_fields=[
+        ('status', STATUS_SPEC),
+        ('le_supported_host', 1),
+        ('unused', 1),
+    ]
+)
 class HCI_Read_LE_Host_Support_Command(HCI_Command):
     '''
     See Bluetooth spec @ 7.3.78 Read LE Host Support Command
@@ -3309,13 +3414,39 @@ class HCI_Read_BD_ADDR_Command(HCI_Command):
 
 
 # -----------------------------------------------------------------------------
-@HCI_Command.command()
+@HCI_Command.command(
+    return_parameters_fields=[
+        ("status", STATUS_SPEC),
+        [("standard_codec_ids", 1)],
+        [("vendor_specific_codec_ids", 4)],
+    ]
+)
 class HCI_Read_Local_Supported_Codecs_Command(HCI_Command):
     '''
     See Bluetooth spec @ 7.4.8 Read Local Supported Codecs Command
     '''
 
 
+# -----------------------------------------------------------------------------
+@HCI_Command.command(
+    return_parameters_fields=[
+        ("status", STATUS_SPEC),
+        [("standard_codec_ids", 1), ("standard_codec_transports", 1)],
+        [("vendor_specific_codec_ids", 4), ("vendor_specific_codec_transports", 1)],
+    ]
+)
+class HCI_Read_Local_Supported_Codecs_V2_Command(HCI_Command):
+    '''
+    See Bluetooth spec @ 7.4.8 Read Local Supported Codecs Command
+    '''
+
+    class Transport(OpenIntEnum):
+        BR_EDR_ACL = 0x00
+        BR_EDR_SCO = 0x01
+        LE_CIS = 0x02
+        LE_BIS = 0x03
+
+
 # -----------------------------------------------------------------------------
 @HCI_Command.command(
     fields=[('handle', 2)],
@@ -3473,7 +3604,12 @@ class HCI_LE_Set_Advertising_Parameters_Command(HCI_Command):
 
 
 # -----------------------------------------------------------------------------
-@HCI_Command.command()
+@HCI_Command.command(
+    return_parameters_fields=[
+        ('status', STATUS_SPEC),
+        ('tx_power_level', 1),
+    ]
+)
 class HCI_LE_Read_Advertising_Physical_Channel_Tx_Power_Command(HCI_Command):
     '''
     See Bluetooth spec @ 7.8.6 LE Read Advertising Physical Channel Tx Power Command
@@ -3597,7 +3733,12 @@ class HCI_LE_Create_Connection_Cancel_Command(HCI_Command):
 
 
 # -----------------------------------------------------------------------------
-@HCI_Command.command()
+@HCI_Command.command(
+    return_parameters_fields=[
+        ('status', STATUS_SPEC),
+        ('filter_accept_list_size', 1),
+    ]
+)
 class HCI_LE_Read_Filter_Accept_List_Size_Command(HCI_Command):
     '''
     See Bluetooth spec @ 7.8.14 LE Read Filter Accept List Size Command
@@ -3708,7 +3849,12 @@ class HCI_LE_Long_Term_Key_Request_Negative_Reply_Command(HCI_Command):
 
 
 # -----------------------------------------------------------------------------
-@HCI_Command.command()
+@HCI_Command.command(
+    return_parameters_fields=[
+        ('status', STATUS_SPEC),
+        ('le_states', 8),
+    ]
+)
 class HCI_LE_Read_Supported_States_Command(HCI_Command):
     '''
     See Bluetooth spec @ 7.8.27 LE Read Supported States Command
@@ -4452,6 +4598,68 @@ class HCI_LE_Extended_Create_Connection_Command(HCI_Command):
         )
 
 
+# -----------------------------------------------------------------------------
+@HCI_Command.command(
+    [
+        (
+            'options',
+            {
+                'size': 1,
+                'mapper': lambda x: HCI_LE_Periodic_Advertising_Create_Sync_Command.Options(
+                    x
+                ).name,
+            },
+        ),
+        ('advertising_sid', 1),
+        ('advertiser_address_type', Address.ADDRESS_TYPE_SPEC),
+        ('advertiser_address', Address.parse_address_preceded_by_type),
+        ('skip', 2),
+        ('sync_timeout', 2),
+        (
+            'sync_cte_type',
+            {
+                'size': 1,
+                'mapper': lambda x: HCI_LE_Periodic_Advertising_Create_Sync_Command.CteType(
+                    x
+                ).name,
+            },
+        ),
+    ]
+)
+class HCI_LE_Periodic_Advertising_Create_Sync_Command(HCI_Command):
+    '''
+    See Bluetooth spec @ 7.8.67 LE Periodic Advertising Create Sync command
+    '''
+
+    class Options(enum.IntFlag):
+        USE_PERIODIC_ADVERTISER_LIST = 1 << 0
+        REPORTING_INITIALLY_DISABLED = 1 << 1
+        DUPLICATE_FILTERING_INITIALLY_ENABLED = 1 << 2
+
+    class CteType(enum.IntFlag):
+        DO_NOT_SYNC_TO_PACKETS_WITH_AN_AOA_CONSTANT_TONE_EXTENSION = 1 << 0
+        DO_NOT_SYNC_TO_PACKETS_WITH_AN_AOD_CONSTANT_TONE_EXTENSION_1US = 1 << 1
+        DO_NOT_SYNC_TO_PACKETS_WITH_AN_AOD_CONSTANT_TONE_EXTENSION_2US = 1 << 2
+        DO_NOT_SYNC_TO_PACKETS_WITH_A_TYPE_3_CONSTANT_TONE_EXTENSION = 1 << 3
+        DO_NOT_SYNC_TO_PACKETS_WITHOUT_A_CONSTANT_TONE_EXTENSION = 1 << 4
+
+
+# -----------------------------------------------------------------------------
+@HCI_Command.command()
+class HCI_LE_Periodic_Advertising_Create_Sync_Cancel_Command(HCI_Command):
+    '''
+    See Bluetooth spec @ 7.8.68 LE Periodic Advertising Create Sync Cancel Command
+    '''
+
+
+# -----------------------------------------------------------------------------
+@HCI_Command.command([('sync_handle', 2)])
+class HCI_LE_Periodic_Advertising_Terminate_Sync_Command(HCI_Command):
+    '''
+    See Bluetooth spec @ 7.8.69 LE Periodic Advertising Terminate Sync Command
+    '''
+
+
 # -----------------------------------------------------------------------------
 @HCI_Command.command(
     [
@@ -4488,10 +4696,28 @@ class HCI_LE_Set_Privacy_Mode_Command(HCI_Command):
 
 
 # -----------------------------------------------------------------------------
-@HCI_Command.command([('bit_number', 1), ('bit_value', 1)])
-class HCI_LE_Set_Host_Feature_Command(HCI_Command):
+@HCI_Command.command([('sync_handle', 2), ('enable', 1)])
+class HCI_LE_Set_Periodic_Advertising_Receive_Enable_Command(HCI_Command):
     '''
-    See Bluetooth spec @ 7.8.115 LE Set Host Feature Command
+    See Bluetooth spec @ 7.8.88 LE Set Periodic Advertising Receive Enable Command
+    '''
+
+    class Enable(enum.IntFlag):
+        REPORTING_ENABLED = 1 << 0
+        DUPLICATE_FILTERING_ENABLED = 1 << 1
+
+
+# -----------------------------------------------------------------------------
+@HCI_Command.command(
+    fields=[('connection_handle', 2), ('service_data', 2), ('sync_handle', 2)],
+    return_parameters_fields=[
+        ('status', STATUS_SPEC),
+        ('connection_handle', 2),
+    ],
+)
+class HCI_LE_Periodic_Advertising_Sync_Transfer_Command(HCI_Command):
+    '''
+    See Bluetooth spec @ 7.8.89 LE Periodic Advertising Sync Transfer Command
     '''
 
 
@@ -4603,6 +4829,102 @@ class HCI_LE_Reject_CIS_Request_Command(HCI_Command):
     reason: int
 
 
+# -----------------------------------------------------------------------------
+@HCI_Command.command(
+    fields=[
+        ('big_handle', 1),
+        ('advertising_handle', 1),
+        ('num_bis', 1),
+        ('sdu_interval', 3),
+        ('max_sdu', 2),
+        ('max_transport_latency', 2),
+        ('rtn', 1),
+        ('phy', 1),
+        ('packing', 1),
+        ('framing', 1),
+        ('encryption', 1),
+        ('broadcast_code', 16),
+    ],
+)
+class HCI_LE_Create_BIG_Command(HCI_Command):
+    '''
+    See Bluetooth spec @ 7.8.103 LE Create BIG command
+    '''
+
+    big_handle: int
+    advertising_handle: int
+    num_bis: int
+    sdu_interval: int
+    max_sdu: int
+    max_transport_latency: int
+    rtn: int
+    phy: int
+    packing: int
+    framing: int
+    encryption: int
+    broadcast_code: int
+
+
+# -----------------------------------------------------------------------------
+@HCI_Command.command(
+    fields=[
+        ('big_handle', 1),
+        ('reason', {'size': 1, 'mapper': HCI_Constant.error_name}),
+    ],
+)
+class HCI_LE_Terminate_BIG_Command(HCI_Command):
+    '''
+    See Bluetooth spec @ 7.8.105 LE Terminate BIG command
+    '''
+
+    big_handle: int
+    reason: int
+
+
+# -----------------------------------------------------------------------------
+@HCI_Command.command(
+    fields=[
+        ('big_handle', 1),
+        ('sync_handle', 2),
+        ('encryption', 1),
+        ('broadcast_code', 16),
+        ('mse', 1),
+        ('big_sync_timeout', 2),
+        [('bis', 1)],
+    ],
+)
+class HCI_LE_BIG_Create_Sync_Command(HCI_Command):
+    '''
+    See Bluetooth spec @ 7.8.106 LE BIG Create Sync command
+    '''
+
+    big_handle: int
+    sync_handle: int
+    encryption: int
+    broadcast_code: int
+    mse: int
+    big_sync_timeout: int
+    bis: List[int]
+
+
+# -----------------------------------------------------------------------------
+@HCI_Command.command(
+    fields=[
+        ('big_handle', 1),
+    ],
+    return_parameters_fields=[
+        ('status', STATUS_SPEC),
+        ('big_handle', 2),
+    ],
+)
+class HCI_LE_BIG_Terminate_Sync_Command(HCI_Command):
+    '''
+    See Bluetooth spec @ 7.8.107. LE BIG Terminate Sync command
+    '''
+
+    big_handle: int
+
+
 # -----------------------------------------------------------------------------
 @HCI_Command.command(
     fields=[
@@ -4655,6 +4977,14 @@ class HCI_LE_Remove_ISO_Data_Path_Command(HCI_Command):
     data_path_direction: int
 
 
+# -----------------------------------------------------------------------------
+@HCI_Command.command([('bit_number', 1), ('bit_value', 1)])
+class HCI_LE_Set_Host_Feature_Command(HCI_Command):
+    '''
+    See Bluetooth spec @ 7.8.115 LE Set Host Feature Command
+    '''
+
+
 # -----------------------------------------------------------------------------
 # HCI Events
 # -----------------------------------------------------------------------------
@@ -4729,7 +5059,7 @@ class HCI_Event(HCI_Packet):
         length = packet[2]
         parameters = packet[3:]
         if len(parameters) != length:
-            raise ValueError('invalid packet length')
+            raise InvalidPacketError('invalid packet length')
 
         cls: Any
         if event_code == HCI_LE_META_EVENT:
@@ -5096,8 +5426,8 @@ class HCI_LE_Data_Length_Change_Event(HCI_LE_Meta_Event):
         ),
         ('peer_address_type', Address.ADDRESS_TYPE_SPEC),
         ('peer_address', Address.parse_address_preceded_by_type),
-        ('local_resolvable_private_address', Address.parse_address),
-        ('peer_resolvable_private_address', Address.parse_address),
+        ('local_resolvable_private_address', Address.parse_random_address),
+        ('peer_resolvable_private_address', Address.parse_random_address),
         ('connection_interval', 2),
         ('peripheral_latency', 2),
         ('supervision_timeout', 2),
@@ -5271,6 +5601,142 @@ HCI_LE_Meta_Event.subevent_classes[HCI_LE_EXTENDED_ADVERTISING_REPORT_EVENT] = (
 )
 
 
+# -----------------------------------------------------------------------------
+@HCI_LE_Meta_Event.event(
+    [
+        ('status', STATUS_SPEC),
+        ('sync_handle', 2),
+        ('advertising_sid', 1),
+        ('advertiser_address_type', Address.ADDRESS_TYPE_SPEC),
+        ('advertiser_address', Address.parse_address_preceded_by_type),
+        ('advertiser_phy', {'size': 1, 'mapper': HCI_Constant.le_phy_name}),
+        ('periodic_advertising_interval', 2),
+        ('advertiser_clock_accuracy', 1),
+    ]
+)
+class HCI_LE_Periodic_Advertising_Sync_Established_Event(HCI_LE_Meta_Event):
+    '''
+    See Bluetooth spec @ 7.7.65.14 LE Periodic Advertising Sync Established Event
+    '''
+
+
+# -----------------------------------------------------------------------------
+@HCI_LE_Meta_Event.event(
+    [
+        ('status', STATUS_SPEC),
+        ('sync_handle', 2),
+        ('advertising_sid', 1),
+        ('advertiser_address_type', Address.ADDRESS_TYPE_SPEC),
+        ('advertiser_address', Address.parse_address_preceded_by_type),
+        ('advertiser_phy', {'size': 1, 'mapper': HCI_Constant.le_phy_name}),
+        ('periodic_advertising_interval', 2),
+        ('advertiser_clock_accuracy', 1),
+        ('num_subevents', 1),
+        ('subevent_interval', 1),
+        ('response_slot_delay', 1),
+        ('response_slot_spacing', 1),
+    ]
+)
+class HCI_LE_Periodic_Advertising_Sync_Established_V2_Event(HCI_LE_Meta_Event):
+    '''
+    See Bluetooth spec @ 7.7.65.14 LE Periodic Advertising Sync Established Event
+    '''
+
+
+# -----------------------------------------------------------------------------
+@HCI_LE_Meta_Event.event(
+    [
+        ('sync_handle', 2),
+        ('tx_power', -1),
+        ('rssi', -1),
+        (
+            'cte_type',
+            {
+                'size': 1,
+                'mapper': lambda x: HCI_LE_Periodic_Advertising_Report_Event.CteType(
+                    x
+                ).name,
+            },
+        ),
+        (
+            'data_status',
+            {
+                'size': 1,
+                'mapper': lambda x: HCI_LE_Periodic_Advertising_Report_Event.DataStatus(
+                    x
+                ).name,
+            },
+        ),
+        ('data', 'v'),
+    ]
+)
+class HCI_LE_Periodic_Advertising_Report_Event(HCI_LE_Meta_Event):
+    '''
+    See Bluetooth spec @ 7.7.65.15 LE Periodic Advertising Report Event
+    '''
+
+    TX_POWER_INFORMATION_NOT_AVAILABLE = 0x7F
+    RSSI_NOT_AVAILABLE = 0x7F
+
+    class CteType(OpenIntEnum):
+        AOA_CONSTANT_TONE_EXTENSION = 0x00
+        AOD_CONSTANT_TONE_EXTENSION_1US = 0x01
+        AOD_CONSTANT_TONE_EXTENSION_2US = 0x02
+        NO_CONSTANT_TONE_EXTENSION = 0xFF
+
+    class DataStatus(OpenIntEnum):
+        DATA_COMPLETE = 0x00
+        DATA_INCOMPLETE_MORE_TO_COME = 0x01
+        DATA_INCOMPLETE_TRUNCATED_NO_MORE_TO_COME = 0x02
+
+
+# -----------------------------------------------------------------------------
+@HCI_LE_Meta_Event.event(
+    [
+        ('sync_handle', 2),
+        ('tx_power', -1),
+        ('rssi', -1),
+        (
+            'cte_type',
+            {
+                'size': 1,
+                'mapper': lambda x: HCI_LE_Periodic_Advertising_Report_Event.CteType(
+                    x
+                ).name,
+            },
+        ),
+        ('periodic_event_counter', 2),
+        ('subevent', 1),
+        (
+            'data_status',
+            {
+                'size': 1,
+                'mapper': lambda x: HCI_LE_Periodic_Advertising_Report_Event.DataStatus(
+                    x
+                ).name,
+            },
+        ),
+        ('data', 'v'),
+    ]
+)
+class HCI_LE_Periodic_Advertising_Report_V2_Event(HCI_LE_Meta_Event):
+    '''
+    See Bluetooth spec @ 7.7.65.15 LE Periodic Advertising Report Event
+    '''
+
+
+# -----------------------------------------------------------------------------
+@HCI_LE_Meta_Event.event(
+    [
+        ('sync_handle', 2),
+    ]
+)
+class HCI_LE_Periodic_Advertising_Sync_Lost_Event(HCI_LE_Meta_Event):
+    '''
+    See Bluetooth spec @ 7.7.65.16 LE Periodic Advertising Sync Lost Event
+    '''
+
+
 # -----------------------------------------------------------------------------
 @HCI_LE_Meta_Event.event(
     [
@@ -5294,6 +5760,27 @@ class HCI_LE_Channel_Selection_Algorithm_Event(HCI_LE_Meta_Event):
     '''
 
 
+# -----------------------------------------------------------------------------
+@HCI_LE_Meta_Event.event(
+    [
+        ('status', STATUS_SPEC),
+        ('connection_handle', 2),
+        ('service_data', 2),
+        ('sync_handle', 2),
+        ('advertising_sid', 1),
+        ('advertiser_address_type', Address.ADDRESS_TYPE_SPEC),
+        ('advertiser_address', Address.parse_address_preceded_by_type),
+        ('advertiser_phy', 1),
+        ('periodic_advertising_interval', 2),
+        ('advertiser_clock_accuracy', 1),
+    ]
+)
+class HCI_LE_Periodic_Advertising_Sync_Transfer_Received_Event(HCI_LE_Meta_Event):
+    '''
+    See Bluetooth spec @ 7.7.65.24 LE Periodic Advertising Sync Transfer Received Event
+    '''
+
+
 # -----------------------------------------------------------------------------
 @HCI_LE_Meta_Event.event(
     [
@@ -5336,6 +5823,30 @@ class HCI_LE_CIS_Request_Event(HCI_LE_Meta_Event):
     '''
 
 
+# -----------------------------------------------------------------------------
+@HCI_LE_Meta_Event.event(
+    [
+        ('sync_handle', 2),
+        ('num_bis', 1),
+        ('nse', 1),
+        ('iso_interval', 2),
+        ('bn', 1),
+        ('pto', 1),
+        ('irc', 1),
+        ('max_pdu', 2),
+        ('sdu_interval', 3),
+        ('max_sdu', 2),
+        ('phy', {'size': 1, 'mapper': HCI_Constant.le_phy_name}),
+        ('framing', 1),
+        ('encryption', 1),
+    ]
+)
+class HCI_LE_BIGInfo_Advertising_Report_Event(HCI_LE_Meta_Event):
+    '''
+    See Bluetooth spec @ 7.7.65.34 LE BIGInfo Advertising Report Event
+    '''
+
+
 # -----------------------------------------------------------------------------
 @HCI_Event.event([('status', STATUS_SPEC)])
 class HCI_Inquiry_Complete_Event(HCI_Event):
@@ -5962,6 +6473,23 @@ class HCI_Synchronous_Connection_Changed_Event(HCI_Event):
     '''
 
 
+# -----------------------------------------------------------------------------
+@HCI_Event.event(
+    [
+        ('status', STATUS_SPEC),
+        ('connection_handle', 2),
+        ('max_tx_latency', 2),
+        ('max_rx_latency', 2),
+        ('min_remote_timeout', 2),
+        ('min_local_timeout', 2),
+    ]
+)
+class HCI_Sniff_Subrating_Event(HCI_Event):
+    '''
+    See Bluetooth spec @ 7.7.37 Sniff Subrating Event
+    '''
+
+
 # -----------------------------------------------------------------------------
 @HCI_Event.event(
     [
@@ -6104,7 +6632,7 @@ class HCI_AclDataPacket(HCI_Packet):
         bc_flag = (h >> 14) & 3
         data = packet[5:]
         if len(data) != data_total_length:
-            raise ValueError('invalid packet length')
+            raise InvalidPacketError('invalid packet length')
         return HCI_AclDataPacket(
             connection_handle, pb_flag, bc_flag, data_total_length, data
         )
@@ -6152,7 +6680,7 @@ class HCI_SynchronousDataPacket(HCI_Packet):
         packet_status = (h >> 12) & 0b11
         data = packet[4:]
         if len(data) != data_total_length:
-            raise ValueError(
+            raise InvalidPacketError(
                 f'invalid packet length {len(data)} != {data_total_length}'
             )
         return HCI_SynchronousDataPacket(
diff --git a/bumble/hid.py b/bumble/hid.py
index 1b4aa00..d4a2a72 100644
--- a/bumble/hid.py
+++ b/bumble/hid.py
@@ -23,13 +23,12 @@ import struct
 
 from abc import ABC, abstractmethod
 from pyee import EventEmitter
-from typing import Optional, Callable, TYPE_CHECKING
+from typing import Optional, Callable
 from typing_extensions import override
 
 from bumble import l2cap, device
-from bumble.colors import color
 from bumble.core import InvalidStateError, ProtocolError
-from .hci import Address
+from bumble.hci import Address
 
 
 # -----------------------------------------------------------------------------
@@ -220,31 +219,27 @@ class HID(ABC, EventEmitter):
     async def connect_control_channel(self) -> None:
         # Create a new L2CAP connection - control channel
         try:
-            self.l2cap_ctrl_channel = await self.device.l2cap_channel_manager.connect(
+            channel = await self.device.l2cap_channel_manager.connect(
                 self.connection, HID_CONTROL_PSM
             )
+            channel.sink = self.on_ctrl_pdu
+            self.l2cap_ctrl_channel = channel
         except ProtocolError:
             logging.exception(f'L2CAP connection failed.')
             raise
 
-        assert self.l2cap_ctrl_channel is not None
-        # Become a sink for the L2CAP channel
-        self.l2cap_ctrl_channel.sink = self.on_ctrl_pdu
-
     async def connect_interrupt_channel(self) -> None:
         # Create a new L2CAP connection - interrupt channel
         try:
-            self.l2cap_intr_channel = await self.device.l2cap_channel_manager.connect(
+            channel = await self.device.l2cap_channel_manager.connect(
                 self.connection, HID_INTERRUPT_PSM
             )
+            channel.sink = self.on_intr_pdu
+            self.l2cap_intr_channel = channel
         except ProtocolError:
             logging.exception(f'L2CAP connection failed.')
             raise
 
-        assert self.l2cap_intr_channel is not None
-        # Become a sink for the L2CAP channel
-        self.l2cap_intr_channel.sink = self.on_intr_pdu
-
     async def disconnect_interrupt_channel(self) -> None:
         if self.l2cap_intr_channel is None:
             raise InvalidStateError('invalid state')
@@ -334,17 +329,18 @@ class Device(HID):
         ERR_INVALID_PARAMETER = 0x04
         SUCCESS = 0xFF
 
+    @dataclass
     class GetSetStatus:
-        def __init__(self) -> None:
-            self.data = bytearray()
-            self.status = 0
+        data: bytes = b''
+        status: int = 0
+
+    get_report_cb: Optional[Callable[[int, int, int], GetSetStatus]] = None
+    set_report_cb: Optional[Callable[[int, int, int, bytes], GetSetStatus]] = None
+    get_protocol_cb: Optional[Callable[[], GetSetStatus]] = None
+    set_protocol_cb: Optional[Callable[[int], GetSetStatus]] = None
 
     def __init__(self, device: device.Device) -> None:
         super().__init__(device, HID.Role.DEVICE)
-        get_report_cb: Optional[Callable[[int, int, int], None]] = None
-        set_report_cb: Optional[Callable[[int, int, int, bytes], None]] = None
-        get_protocol_cb: Optional[Callable[[], None]] = None
-        set_protocol_cb: Optional[Callable[[int], None]] = None
 
     @override
     def on_ctrl_pdu(self, pdu: bytes) -> None:
@@ -410,7 +406,6 @@ class Device(HID):
             buffer_size = 0
 
         ret = self.get_report_cb(report_id, report_type, buffer_size)
-        assert ret is not None
         if ret.status == self.GetSetReturn.FAILURE:
             self.send_handshake_message(Message.Handshake.ERR_UNKNOWN)
         elif ret.status == self.GetSetReturn.SUCCESS:
@@ -428,7 +423,9 @@ class Device(HID):
         elif ret.status == self.GetSetReturn.ERR_UNSUPPORTED_REQUEST:
             self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)
 
-    def register_get_report_cb(self, cb: Callable[[int, int, int], None]) -> None:
+    def register_get_report_cb(
+        self, cb: Callable[[int, int, int], Device.GetSetStatus]
+    ) -> None:
         self.get_report_cb = cb
         logger.debug("GetReport callback registered successfully")
 
@@ -442,7 +439,6 @@ class Device(HID):
         report_data = pdu[2:]
         report_size = len(report_data) + 1
         ret = self.set_report_cb(report_id, report_type, report_size, report_data)
-        assert ret is not None
         if ret.status == self.GetSetReturn.SUCCESS:
             self.send_handshake_message(Message.Handshake.SUCCESSFUL)
         elif ret.status == self.GetSetReturn.ERR_INVALID_PARAMETER:
@@ -453,7 +449,7 @@ class Device(HID):
             self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)
 
     def register_set_report_cb(
-        self, cb: Callable[[int, int, int, bytes], None]
+        self, cb: Callable[[int, int, int, bytes], Device.GetSetStatus]
     ) -> None:
         self.set_report_cb = cb
         logger.debug("SetReport callback registered successfully")
@@ -464,13 +460,12 @@ class Device(HID):
             self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)
             return
         ret = self.get_protocol_cb()
-        assert ret is not None
         if ret.status == self.GetSetReturn.SUCCESS:
             self.send_control_data(Message.ReportType.OTHER_REPORT, ret.data)
         else:
             self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)
 
-    def register_get_protocol_cb(self, cb: Callable[[], None]) -> None:
+    def register_get_protocol_cb(self, cb: Callable[[], Device.GetSetStatus]) -> None:
         self.get_protocol_cb = cb
         logger.debug("GetProtocol callback registered successfully")
 
@@ -480,13 +475,14 @@ class Device(HID):
             self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)
             return
         ret = self.set_protocol_cb(pdu[0] & 0x01)
-        assert ret is not None
         if ret.status == self.GetSetReturn.SUCCESS:
             self.send_handshake_message(Message.Handshake.SUCCESSFUL)
         else:
             self.send_handshake_message(Message.Handshake.ERR_UNSUPPORTED_REQUEST)
 
-    def register_set_protocol_cb(self, cb: Callable[[int], None]) -> None:
+    def register_set_protocol_cb(
+        self, cb: Callable[[int], Device.GetSetStatus]
+    ) -> None:
         self.set_protocol_cb = cb
         logger.debug("SetProtocol callback registered successfully")
 
diff --git a/bumble/host.py b/bumble/host.py
index 64b6668..a3d3dad 100644
--- a/bumble/host.py
+++ b/bumble/host.py
@@ -171,7 +171,7 @@ class Host(AbortableEventEmitter):
         self.cis_links = {}  # CIS links, by connection handle
         self.sco_links = {}  # SCO links, by connection handle
         self.pending_command = None
-        self.pending_response = None
+        self.pending_response: Optional[asyncio.Future[Any]] = None
         self.number_of_supported_advertising_sets = 0
         self.maximum_advertising_data_length = 31
         self.local_version = None
@@ -514,7 +514,9 @@ class Host(AbortableEventEmitter):
         if self.hci_sink:
             self.hci_sink.on_packet(bytes(packet))
 
-    async def send_command(self, command, check_result=False):
+    async def send_command(
+        self, command, check_result=False, response_timeout: Optional[int] = None
+    ):
         # Wait until we can send (only one pending command at a time)
         async with self.command_semaphore:
             assert self.pending_command is None
@@ -526,12 +528,13 @@ class Host(AbortableEventEmitter):
 
             try:
                 self.send_hci_packet(command)
-                response = await self.pending_response
+                await asyncio.wait_for(self.pending_response, timeout=response_timeout)
+                response = self.pending_response.result()
 
                 # Check the return parameters if required
                 if check_result:
                     if isinstance(response, hci.HCI_Command_Status_Event):
-                        status = response.status
+                        status = response.status  # type: ignore[attr-defined]
                     elif isinstance(response.return_parameters, int):
                         status = response.return_parameters
                     elif isinstance(response.return_parameters, bytes):
@@ -625,14 +628,21 @@ class Host(AbortableEventEmitter):
 
     # Packet Sink protocol (packets coming from the controller via HCI)
     def on_packet(self, packet: bytes) -> None:
-        hci_packet = hci.HCI_Packet.from_bytes(packet)
+        try:
+            hci_packet = hci.HCI_Packet.from_bytes(packet)
+        except Exception as error:
+            logger.warning(f'!!! error parsing packet from bytes: {error}')
+            return
+
         if self.ready or (
             isinstance(hci_packet, hci.HCI_Command_Complete_Event)
             and hci_packet.command_opcode == hci.HCI_RESET_COMMAND
         ):
             self.on_hci_packet(hci_packet)
         else:
-            logger.debug('reset not done, ignoring packet from controller')
+            logger.debug(
+                f'reset not done, ignoring packet from controller: {hci_packet}'
+            )
 
     def on_transport_lost(self):
         # Called by the source when the transport has been lost.
@@ -772,6 +782,8 @@ class Host(AbortableEventEmitter):
                 event.connection_handle,
                 BT_LE_TRANSPORT,
                 event.peer_address,
+                getattr(event, 'local_resolvable_private_address', None),
+                getattr(event, 'peer_resolvable_private_address', None),
                 event.role,
                 connection_parameters,
             )
@@ -787,6 +799,10 @@ class Host(AbortableEventEmitter):
         # Just use the same implementation as for the non-enhanced event for now
         self.on_hci_le_connection_complete_event(event)
 
+    def on_hci_le_enhanced_connection_complete_v2_event(self, event):
+        # Just use the same implementation as for the v1 event for now
+        self.on_hci_le_enhanced_connection_complete_event(event)
+
     def on_hci_connection_complete_event(self, event):
         if event.status == hci.HCI_SUCCESS:
             # Create/update the connection
@@ -813,6 +829,8 @@ class Host(AbortableEventEmitter):
                 event.bd_addr,
                 None,
                 None,
+                None,
+                None,
             )
         else:
             logger.debug(f'### BR/EDR CONNECTION FAILED: {event.status}')
@@ -905,6 +923,27 @@ class Host(AbortableEventEmitter):
             event.num_completed_extended_advertising_events,
         )
 
+    def on_hci_le_periodic_advertising_sync_established_event(self, event):
+        self.emit(
+            'periodic_advertising_sync_establishment',
+            event.status,
+            event.sync_handle,
+            event.advertising_sid,
+            event.advertiser_address,
+            event.advertiser_phy,
+            event.periodic_advertising_interval,
+            event.advertiser_clock_accuracy,
+        )
+
+    def on_hci_le_periodic_advertising_sync_lost_event(self, event):
+        self.emit('periodic_advertising_sync_loss', event.sync_handle)
+
+    def on_hci_le_periodic_advertising_report_event(self, event):
+        self.emit('periodic_advertising_report', event.sync_handle, event)
+
+    def on_hci_le_biginfo_advertising_report_event(self, event):
+        self.emit('biginfo_advertising_report', event.sync_handle, event)
+
     def on_hci_le_cis_request_event(self, event):
         self.emit(
             'cis_request',
diff --git a/bumble/l2cap.py b/bumble/l2cap.py
index b4f0121..53c84d5 100644
--- a/bumble/l2cap.py
+++ b/bumble/l2cap.py
@@ -41,7 +41,14 @@ from typing import (
 
 from .utils import deprecated
 from .colors import color
-from .core import BT_CENTRAL_ROLE, InvalidStateError, ProtocolError
+from .core import (
+    BT_CENTRAL_ROLE,
+    InvalidStateError,
+    InvalidArgumentError,
+    InvalidPacketError,
+    OutOfResourcesError,
+    ProtocolError,
+)
 from .hci import (
     HCI_LE_Connection_Update_Command,
     HCI_Object,
@@ -189,17 +196,17 @@ class LeCreditBasedChannelSpec:
             self.max_credits < 1
             or self.max_credits > L2CAP_LE_CREDIT_BASED_CONNECTION_MAX_CREDITS
         ):
-            raise ValueError('max credits out of range')
+            raise InvalidArgumentError('max credits out of range')
         if (
             self.mtu < L2CAP_LE_CREDIT_BASED_CONNECTION_MIN_MTU
             or self.mtu > L2CAP_LE_CREDIT_BASED_CONNECTION_MAX_MTU
         ):
-            raise ValueError('MTU out of range')
+            raise InvalidArgumentError('MTU out of range')
         if (
             self.mps < L2CAP_LE_CREDIT_BASED_CONNECTION_MIN_MPS
             or self.mps > L2CAP_LE_CREDIT_BASED_CONNECTION_MAX_MPS
         ):
-            raise ValueError('MPS out of range')
+            raise InvalidArgumentError('MPS out of range')
 
 
 class L2CAP_PDU:
@@ -211,7 +218,7 @@ class L2CAP_PDU:
     def from_bytes(data: bytes) -> L2CAP_PDU:
         # Check parameters
         if len(data) < 4:
-            raise ValueError('not enough data for L2CAP header')
+            raise InvalidPacketError('not enough data for L2CAP header')
 
         _, l2cap_pdu_cid = struct.unpack_from('<HH', data, 0)
         l2cap_pdu_payload = data[4:]
@@ -816,7 +823,7 @@ class ClassicChannel(EventEmitter):
 
         # Check that we can start a new connection
         if self.connection_result:
-            raise RuntimeError('connection already pending')
+            raise InvalidStateError('connection already pending')
 
         self._change_state(self.State.WAIT_CONNECT_RSP)
         self.send_control_frame(
@@ -1129,7 +1136,7 @@ class LeCreditBasedChannel(EventEmitter):
         # Check that we can start a new connection
         identifier = self.manager.next_identifier(self.connection)
         if identifier in self.manager.le_coc_requests:
-            raise RuntimeError('too many concurrent connection requests')
+            raise InvalidStateError('too many concurrent connection requests')
 
         self._change_state(self.State.CONNECTING)
         request = L2CAP_LE_Credit_Based_Connection_Request(
@@ -1516,7 +1523,7 @@ class ChannelManager:
             if cid not in channels:
                 return cid
 
-        raise RuntimeError('no free CID available')
+        raise OutOfResourcesError('no free CID available')
 
     @staticmethod
     def find_free_le_cid(channels: Iterable[int]) -> int:
@@ -1529,7 +1536,7 @@ class ChannelManager:
             if cid not in channels:
                 return cid
 
-        raise RuntimeError('no free CID')
+        raise OutOfResourcesError('no free CID')
 
     def next_identifier(self, connection: Connection) -> int:
         identifier = (self.identifiers.setdefault(connection.handle, 0) + 1) % 256
@@ -1576,15 +1583,15 @@ class ChannelManager:
         else:
             # Check that the PSM isn't already in use
             if spec.psm in self.servers:
-                raise ValueError('PSM already in use')
+                raise InvalidArgumentError('PSM already in use')
 
             # Check that the PSM is valid
             if spec.psm % 2 == 0:
-                raise ValueError('invalid PSM (not odd)')
+                raise InvalidArgumentError('invalid PSM (not odd)')
             check = spec.psm >> 8
             while check:
                 if check % 2 != 0:
-                    raise ValueError('invalid PSM')
+                    raise InvalidArgumentError('invalid PSM')
                 check >>= 8
 
         self.servers[spec.psm] = ClassicChannelServer(self, spec.psm, handler, spec.mtu)
@@ -1626,7 +1633,7 @@ class ChannelManager:
         else:
             # Check that the PSM isn't already in use
             if spec.psm in self.le_coc_servers:
-                raise ValueError('PSM already in use')
+                raise InvalidArgumentError('PSM already in use')
 
         self.le_coc_servers[spec.psm] = LeCreditBasedChannelServer(
             self,
@@ -2154,10 +2161,10 @@ class ChannelManager:
         connection_channels = self.channels.setdefault(connection.handle, {})
         source_cid = self.find_free_le_cid(connection_channels)
         if source_cid is None:  # Should never happen!
-            raise RuntimeError('all CIDs already in use')
+            raise OutOfResourcesError('all CIDs already in use')
 
         if spec.psm is None:
-            raise ValueError('PSM cannot be None')
+            raise InvalidArgumentError('PSM cannot be None')
 
         # Create the channel
         logger.debug(f'creating coc channel with cid={source_cid} for psm {spec.psm}')
@@ -2206,10 +2213,10 @@ class ChannelManager:
         connection_channels = self.channels.setdefault(connection.handle, {})
         source_cid = self.find_free_br_edr_cid(connection_channels)
         if source_cid is None:  # Should never happen!
-            raise RuntimeError('all CIDs already in use')
+            raise OutOfResourcesError('all CIDs already in use')
 
         if spec.psm is None:
-            raise ValueError('PSM cannot be None')
+            raise InvalidArgumentError('PSM cannot be None')
 
         # Create the channel
         logger.debug(
diff --git a/bumble/link.py b/bumble/link.py
index 5ef56b7..8971e21 100644
--- a/bumble/link.py
+++ b/bumble/link.py
@@ -19,7 +19,12 @@ import logging
 import asyncio
 from functools import partial
 
-from bumble.core import BT_PERIPHERAL_ROLE, BT_BR_EDR_TRANSPORT, BT_LE_TRANSPORT
+from bumble.core import (
+    BT_PERIPHERAL_ROLE,
+    BT_BR_EDR_TRANSPORT,
+    BT_LE_TRANSPORT,
+    InvalidStateError,
+)
 from bumble.colors import color
 from bumble.hci import (
     Address,
@@ -405,12 +410,12 @@ class RemoteLink:
 
     def add_controller(self, controller):
         if self.controller:
-            raise ValueError('controller already set')
+            raise InvalidStateError('controller already set')
         self.controller = controller
 
     def remove_controller(self, controller):
         if self.controller != controller:
-            raise ValueError('controller mismatch')
+            raise InvalidStateError('controller mismatch')
         self.controller = None
 
     def get_pending_connection(self):
diff --git a/bumble/pandora/__init__.py b/bumble/pandora/__init__.py
index e02f54a..8fb4b6e 100644
--- a/bumble/pandora/__init__.py
+++ b/bumble/pandora/__init__.py
@@ -25,8 +25,10 @@ import grpc.aio
 from .config import Config
 from .device import PandoraDevice
 from .host import HostService
+from .l2cap import L2CAPService
 from .security import SecurityService, SecurityStorageService
 from pandora.host_grpc_aio import add_HostServicer_to_server
+from pandora.l2cap_grpc_aio import add_L2CAPServicer_to_server
 from pandora.security_grpc_aio import (
     add_SecurityServicer_to_server,
     add_SecurityStorageServicer_to_server,
@@ -77,6 +79,7 @@ async def serve(
             add_SecurityStorageServicer_to_server(
                 SecurityStorageService(bumble.device, config), server
             )
+            add_L2CAPServicer_to_server(L2CAPService(bumble.device, config), server)
 
             # call hooks if any.
             for hook in _SERVICERS_HOOKS:
diff --git a/bumble/pandora/host.py b/bumble/pandora/host.py
index 4904274..aff063c 100644
--- a/bumble/pandora/host.py
+++ b/bumble/pandora/host.py
@@ -28,6 +28,7 @@ from bumble.core import (
     BT_PERIPHERAL_ROLE,
     UUID,
     AdvertisingData,
+    Appearance,
     ConnectionError,
 )
 from bumble.device import (
@@ -988,8 +989,8 @@ class HostService(HostServicer):
             dt.random_target_addresses.extend(
                 [data[i * 6 :: i * 6 + 6] for i in range(int(len(data) / 6))]
             )
-        if i := cast(int, ad.get(AdvertisingData.APPEARANCE)):
-            dt.appearance = i
+        if appearance := cast(Appearance, ad.get(AdvertisingData.APPEARANCE)):
+            dt.appearance = int(appearance)
         if i := cast(int, ad.get(AdvertisingData.ADVERTISING_INTERVAL)):
             dt.advertising_interval = i
         if s := cast(str, ad.get(AdvertisingData.URI)):
diff --git a/bumble/pandora/l2cap.py b/bumble/pandora/l2cap.py
new file mode 100644
index 0000000..488478c
--- /dev/null
+++ b/bumble/pandora/l2cap.py
@@ -0,0 +1,310 @@
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
+from __future__ import annotations
+import asyncio
+import grpc
+import json
+import logging
+
+from asyncio import Queue as AsyncQueue, Future
+
+from . import utils
+from .config import Config
+from bumble.core import OutOfResourcesError, InvalidArgumentError
+from bumble.device import Device
+from bumble.l2cap import (
+    ClassicChannel,
+    ClassicChannelServer,
+    ClassicChannelSpec,
+    LeCreditBasedChannel,
+    LeCreditBasedChannelServer,
+    LeCreditBasedChannelSpec,
+)
+from google.protobuf import any_pb2, empty_pb2  # pytype: disable=pyi-error
+from pandora.l2cap_grpc_aio import L2CAPServicer  # pytype: disable=pyi-error
+from pandora.l2cap_pb2 import (  # pytype: disable=pyi-error
+    COMMAND_NOT_UNDERSTOOD,
+    INVALID_CID_IN_REQUEST,
+    Channel as PandoraChannel,
+    ConnectRequest,
+    ConnectResponse,
+    CreditBasedChannelRequest,
+    DisconnectRequest,
+    DisconnectResponse,
+    ReceiveRequest,
+    ReceiveResponse,
+    SendRequest,
+    SendResponse,
+    WaitConnectionRequest,
+    WaitConnectionResponse,
+    WaitDisconnectionRequest,
+    WaitDisconnectionResponse,
+)
+from typing import AsyncGenerator, Dict, Optional, Union
+from dataclasses import dataclass
+
+L2capChannel = Union[ClassicChannel, LeCreditBasedChannel]
+
+
+@dataclass
+class ChannelContext:
+    close_future: Future
+    sdu_queue: AsyncQueue
+
+
+class L2CAPService(L2CAPServicer):
+    def __init__(self, device: Device, config: Config) -> None:
+        self.log = utils.BumbleServerLoggerAdapter(
+            logging.getLogger(), {'service_name': 'L2CAP', 'device': device}
+        )
+        self.device = device
+        self.config = config
+        self.channels: Dict[bytes, ChannelContext] = {}
+
+    def register_event(self, l2cap_channel: L2capChannel) -> ChannelContext:
+        close_future = asyncio.get_running_loop().create_future()
+        sdu_queue: AsyncQueue = AsyncQueue()
+
+        def on_channel_sdu(sdu):
+            sdu_queue.put_nowait(sdu)
+
+        def on_close():
+            close_future.set_result(None)
+
+        l2cap_channel.sink = on_channel_sdu
+        l2cap_channel.on('close', on_close)
+
+        return ChannelContext(close_future, sdu_queue)
+
+    @utils.rpc
+    async def WaitConnection(
+        self, request: WaitConnectionRequest, context: grpc.ServicerContext
+    ) -> WaitConnectionResponse:
+        self.log.debug('WaitConnection')
+        if not request.connection:
+            raise ValueError('A valid connection field must be set')
+
+        # find connection on device based on connection cookie value
+        connection_handle = int.from_bytes(request.connection.cookie.value, 'big')
+        connection = self.device.lookup_connection(connection_handle)
+
+        if not connection:
+            raise ValueError('The connection specified is invalid.')
+
+        oneof = request.WhichOneof('type')
+        self.log.debug(f'WaitConnection channel request type: {oneof}.')
+        channel_type = getattr(request, oneof)
+        spec: Optional[Union[ClassicChannelSpec, LeCreditBasedChannelSpec]] = None
+        l2cap_server: Optional[
+            Union[ClassicChannelServer, LeCreditBasedChannelServer]
+        ] = None
+        if isinstance(channel_type, CreditBasedChannelRequest):
+            spec = LeCreditBasedChannelSpec(
+                psm=channel_type.spsm,
+                max_credits=channel_type.initial_credit,
+                mtu=channel_type.mtu,
+                mps=channel_type.mps,
+            )
+            if channel_type.spsm in self.device.l2cap_channel_manager.le_coc_servers:
+                l2cap_server = self.device.l2cap_channel_manager.le_coc_servers[
+                    channel_type.spsm
+                ]
+        else:
+            spec = ClassicChannelSpec(
+                psm=channel_type.psm,
+                mtu=channel_type.mtu,
+            )
+            if channel_type.psm in self.device.l2cap_channel_manager.servers:
+                l2cap_server = self.device.l2cap_channel_manager.servers[
+                    channel_type.psm
+                ]
+
+        self.log.info(f'Listening for L2CAP connection on PSM {spec.psm}')
+        channel_future: Future[PandoraChannel] = (
+            asyncio.get_running_loop().create_future()
+        )
+
+        def on_l2cap_channel(l2cap_channel: L2capChannel):
+            try:
+                channel_context = self.register_event(l2cap_channel)
+                pandora_channel: PandoraChannel = self.craft_pandora_channel(
+                    connection_handle, l2cap_channel
+                )
+                self.channels[pandora_channel.cookie.value] = channel_context
+                channel_future.set_result(pandora_channel)
+            except Exception as e:
+                self.log.error(f'Failed to set channel future: {e}')
+
+        if l2cap_server is None:
+            l2cap_server = self.device.create_l2cap_server(
+                spec=spec, handler=on_l2cap_channel
+            )
+        else:
+            l2cap_server.on('connection', on_l2cap_channel)
+
+        try:
+            self.log.debug('Waiting for a channel connection.')
+            pandora_channel: PandoraChannel = await channel_future
+
+            return WaitConnectionResponse(channel=pandora_channel)
+        except Exception as e:
+            self.log.warning(f'Exception: {e}')
+
+        return WaitConnectionResponse(error=COMMAND_NOT_UNDERSTOOD)
+
+    @utils.rpc
+    async def WaitDisconnection(
+        self, request: WaitDisconnectionRequest, context: grpc.ServicerContext
+    ) -> WaitDisconnectionResponse:
+        try:
+            self.log.debug('WaitDisconnection')
+
+            await self.lookup_context(request.channel).close_future
+            self.log.debug("return WaitDisconnectionResponse")
+            return WaitDisconnectionResponse(success=empty_pb2.Empty())
+        except KeyError as e:
+            self.log.warning(f'WaitDisconnection: Unable to find the channel: {e}')
+            return WaitDisconnectionResponse(error=INVALID_CID_IN_REQUEST)
+        except Exception as e:
+            self.log.exception(f'WaitDisonnection failed: {e}')
+            return WaitDisconnectionResponse(error=COMMAND_NOT_UNDERSTOOD)
+
+    @utils.rpc
+    async def Receive(
+        self, request: ReceiveRequest, context: grpc.ServicerContext
+    ) -> AsyncGenerator[ReceiveResponse, None]:
+        self.log.debug('Receive')
+        oneof = request.WhichOneof('source')
+        self.log.debug(f'Source: {oneof}.')
+        pandora_channel = getattr(request, oneof)
+
+        sdu_queue = self.lookup_context(pandora_channel).sdu_queue
+
+        while sdu := await sdu_queue.get():
+            self.log.debug(f'Receive: Received {len(sdu)} bytes -> {sdu.decode()}')
+            response = ReceiveResponse(data=sdu)
+            yield response
+
+    @utils.rpc
+    async def Connect(
+        self, request: ConnectRequest, context: grpc.ServicerContext
+    ) -> ConnectResponse:
+        self.log.debug('Connect')
+
+        if not request.connection:
+            raise ValueError('A valid connection field must be set')
+
+        # find connection on device based on connection cookie value
+        connection_handle = int.from_bytes(request.connection.cookie.value, 'big')
+        connection = self.device.lookup_connection(connection_handle)
+
+        if not connection:
+            raise ValueError('The connection specified is invalid.')
+
+        oneof = request.WhichOneof('type')
+        self.log.debug(f'Channel request type: {oneof}.')
+        channel_type = getattr(request, oneof)
+        spec: Optional[Union[ClassicChannelSpec, LeCreditBasedChannelSpec]] = None
+        if isinstance(channel_type, CreditBasedChannelRequest):
+            spec = LeCreditBasedChannelSpec(
+                psm=channel_type.spsm,
+                max_credits=channel_type.initial_credit,
+                mtu=channel_type.mtu,
+                mps=channel_type.mps,
+            )
+        else:
+            spec = ClassicChannelSpec(
+                psm=channel_type.psm,
+                mtu=channel_type.mtu,
+            )
+
+        try:
+            self.log.info(f'Opening L2CAP channel on PSM = {spec.psm}')
+            l2cap_channel = await connection.create_l2cap_channel(spec=spec)
+            channel_context = self.register_event(l2cap_channel)
+            pandora_channel = self.craft_pandora_channel(
+                connection_handle, l2cap_channel
+            )
+            self.channels[pandora_channel.cookie.value] = channel_context
+
+            return ConnectResponse(channel=pandora_channel)
+
+        except OutOfResourcesError as e:
+            self.log.error(e)
+            return ConnectResponse(error=INVALID_CID_IN_REQUEST)
+        except InvalidArgumentError as e:
+            self.log.error(e)
+            return ConnectResponse(error=COMMAND_NOT_UNDERSTOOD)
+
+    @utils.rpc
+    async def Disconnect(
+        self, request: DisconnectRequest, context: grpc.ServicerContext
+    ) -> DisconnectResponse:
+        try:
+            self.log.debug('Disconnect')
+            l2cap_channel = self.lookup_channel(request.channel)
+            if not l2cap_channel:
+                self.log.warning('Disconnect: Unable to find the channel')
+                return DisconnectResponse(error=INVALID_CID_IN_REQUEST)
+
+            await l2cap_channel.disconnect()
+            return DisconnectResponse(success=empty_pb2.Empty())
+        except Exception as e:
+            self.log.exception(f'Disonnect failed: {e}')
+            return DisconnectResponse(error=COMMAND_NOT_UNDERSTOOD)
+
+    @utils.rpc
+    async def Send(
+        self, request: SendRequest, context: grpc.ServicerContext
+    ) -> SendResponse:
+        self.log.debug('Send')
+        try:
+            oneof = request.WhichOneof('sink')
+            self.log.debug(f'Sink: {oneof}.')
+            pandora_channel = getattr(request, oneof)
+
+            l2cap_channel = self.lookup_channel(pandora_channel)
+            if not l2cap_channel:
+                return SendResponse(error=COMMAND_NOT_UNDERSTOOD)
+            if isinstance(l2cap_channel, ClassicChannel):
+                l2cap_channel.send_pdu(request.data)
+            else:
+                l2cap_channel.write(request.data)
+            return SendResponse(success=empty_pb2.Empty())
+        except Exception as e:
+            self.log.exception(f'Disonnect failed: {e}')
+            return SendResponse(error=COMMAND_NOT_UNDERSTOOD)
+
+    def craft_pandora_channel(
+        self,
+        connection_handle: int,
+        l2cap_channel: L2capChannel,
+    ) -> PandoraChannel:
+        parameters = {
+            "connection_handle": connection_handle,
+            "source_cid": l2cap_channel.source_cid,
+        }
+        cookie = any_pb2.Any()
+        cookie.value = json.dumps(parameters).encode()
+        return PandoraChannel(cookie=cookie)
+
+    def lookup_channel(self, pandora_channel: PandoraChannel) -> L2capChannel:
+        (connection_handle, source_cid) = json.loads(
+            pandora_channel.cookie.value
+        ).values()
+
+        return self.device.l2cap_channel_manager.channels[connection_handle][source_cid]
+
+    def lookup_context(self, pandora_channel: PandoraChannel) -> ChannelContext:
+        return self.channels[pandora_channel.cookie.value]
diff --git a/bumble/profiles/aics.py b/bumble/profiles/aics.py
new file mode 100644
index 0000000..3a69627
--- /dev/null
+++ b/bumble/profiles/aics.py
@@ -0,0 +1,520 @@
+# Copyright 2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""LE Audio - Audio Input Control Service"""
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+import logging
+import struct
+
+from dataclasses import dataclass
+from typing import Optional
+
+from bumble import gatt
+from bumble.device import Connection
+from bumble.att import ATT_Error
+from bumble.gatt import (
+    Characteristic,
+    DelegatedCharacteristicAdapter,
+    TemplateService,
+    CharacteristicValue,
+    PackedCharacteristicAdapter,
+    GATT_AUDIO_INPUT_CONTROL_SERVICE,
+    GATT_AUDIO_INPUT_STATE_CHARACTERISTIC,
+    GATT_GAIN_SETTINGS_ATTRIBUTE_CHARACTERISTIC,
+    GATT_AUDIO_INPUT_TYPE_CHARACTERISTIC,
+    GATT_AUDIO_INPUT_STATUS_CHARACTERISTIC,
+    GATT_AUDIO_INPUT_CONTROL_POINT_CHARACTERISTIC,
+    GATT_AUDIO_INPUT_DESCRIPTION_CHARACTERISTIC,
+)
+from bumble.gatt_client import ProfileServiceProxy, ServiceProxy
+from bumble.utils import OpenIntEnum
+
+# -----------------------------------------------------------------------------
+# Logging
+# -----------------------------------------------------------------------------
+logger = logging.getLogger(__name__)
+
+
+# -----------------------------------------------------------------------------
+# Constants
+# -----------------------------------------------------------------------------
+CHANGE_COUNTER_MAX_VALUE = 0xFF
+GAIN_SETTINGS_MIN_VALUE = 0
+GAIN_SETTINGS_MAX_VALUE = 255
+
+
+class ErrorCode(OpenIntEnum):
+    '''
+    Cf. 1.6 Application error codes
+    '''
+
+    INVALID_CHANGE_COUNTER = 0x80
+    OPCODE_NOT_SUPPORTED = 0x81
+    MUTE_DISABLED = 0x82
+    VALUE_OUT_OF_RANGE = 0x83
+    GAIN_MODE_CHANGE_NOT_ALLOWED = 0x84
+
+
+class Mute(OpenIntEnum):
+    '''
+    Cf. 2.2.1.2 Mute Field
+    '''
+
+    NOT_MUTED = 0x00
+    MUTED = 0x01
+    DISABLED = 0x02
+
+
+class GainMode(OpenIntEnum):
+    '''
+    Cf. 2.2.1.3 Gain Mode
+    '''
+
+    MANUAL_ONLY = 0x00
+    AUTOMATIC_ONLY = 0x01
+    MANUAL = 0x02
+    AUTOMATIC = 0x03
+
+
+class AudioInputStatus(OpenIntEnum):
+    '''
+    Cf. 3.4 Audio Input Status
+    '''
+
+    INATIVE = 0x00
+    ACTIVE = 0x01
+
+
+class AudioInputControlPointOpCode(OpenIntEnum):
+    '''
+    Cf. 3.5.1 Audio Input Control Point procedure requirements
+    '''
+
+    SET_GAIN_SETTING = 0x00
+    UNMUTE = 0x02
+    MUTE = 0x03
+    SET_MANUAL_GAIN_MODE = 0x04
+    SET_AUTOMATIC_GAIN_MODE = 0x05
+
+
+# -----------------------------------------------------------------------------
+@dataclass
+class AudioInputState:
+    '''
+    Cf. 2.2.1 Audio Input State
+    '''
+
+    gain_settings: int = 0
+    mute: Mute = Mute.NOT_MUTED
+    gain_mode: GainMode = GainMode.MANUAL
+    change_counter: int = 0
+    attribute_value: Optional[CharacteristicValue] = None
+
+    def __bytes__(self) -> bytes:
+        return bytes(
+            [self.gain_settings, self.mute, self.gain_mode, self.change_counter]
+        )
+
+    @classmethod
+    def from_bytes(cls, data: bytes):
+        gain_settings, mute, gain_mode, change_counter = struct.unpack("BBBB", data)
+        return cls(gain_settings, mute, gain_mode, change_counter)
+
+    def update_gain_settings_unit(self, gain_settings_unit: int) -> None:
+        self.gain_settings_unit = gain_settings_unit
+
+    def increment_gain_settings(self, gain_settings_unit: int) -> None:
+        self.gain_settings += gain_settings_unit
+        self.increment_change_counter()
+
+    def decrement_gain_settings(self) -> None:
+        self.gain_settings -= self.gain_settings_unit
+        self.increment_change_counter()
+
+    def increment_change_counter(self):
+        self.change_counter = (self.change_counter + 1) % (CHANGE_COUNTER_MAX_VALUE + 1)
+
+    async def notify_subscribers_via_connection(self, connection: Connection) -> None:
+        assert self.attribute_value is not None
+        await connection.device.notify_subscribers(
+            attribute=self.attribute_value, value=bytes(self)
+        )
+
+    def on_read(self, _connection: Optional[Connection]) -> bytes:
+        return bytes(self)
+
+
+@dataclass
+class GainSettingsProperties:
+    '''
+    Cf. 3.2 Gain Settings Properties
+    '''
+
+    gain_settings_unit: int = 1
+    gain_settings_minimum: int = GAIN_SETTINGS_MIN_VALUE
+    gain_settings_maximum: int = GAIN_SETTINGS_MAX_VALUE
+
+    @classmethod
+    def from_bytes(cls, data: bytes):
+        (gain_settings_unit, gain_settings_minimum, gain_settings_maximum) = (
+            struct.unpack('BBB', data)
+        )
+        GainSettingsProperties(
+            gain_settings_unit, gain_settings_minimum, gain_settings_maximum
+        )
+
+    def __bytes__(self) -> bytes:
+        return bytes(
+            [
+                self.gain_settings_unit,
+                self.gain_settings_minimum,
+                self.gain_settings_maximum,
+            ]
+        )
+
+    def on_read(self, _connection: Optional[Connection]) -> bytes:
+        return bytes(self)
+
+
+@dataclass
+class AudioInputControlPoint:
+    '''
+    Cf. 3.5.2 Audio Input Control Point
+    '''
+
+    audio_input_state: AudioInputState
+    gain_settings_properties: GainSettingsProperties
+
+    async def on_write(self, connection: Optional[Connection], value: bytes) -> None:
+        assert connection
+
+        opcode = AudioInputControlPointOpCode(value[0])
+
+        if opcode == AudioInputControlPointOpCode.SET_GAIN_SETTING:
+            gain_settings_operand = value[2]
+            await self._set_gain_settings(connection, gain_settings_operand)
+        elif opcode == AudioInputControlPointOpCode.UNMUTE:
+            await self._unmute(connection)
+        elif opcode == AudioInputControlPointOpCode.MUTE:
+            change_counter_operand = value[1]
+            await self._mute(connection, change_counter_operand)
+        elif opcode == AudioInputControlPointOpCode.SET_MANUAL_GAIN_MODE:
+            await self._set_manual_gain_mode(connection)
+        elif opcode == AudioInputControlPointOpCode.SET_AUTOMATIC_GAIN_MODE:
+            await self._set_automatic_gain_mode(connection)
+        else:
+            logger.error(f"OpCode value is incorrect: {opcode}")
+            raise ATT_Error(ErrorCode.OPCODE_NOT_SUPPORTED)
+
+    async def _set_gain_settings(
+        self, connection: Connection, gain_settings_operand: int
+    ) -> None:
+        '''Cf. 3.5.2.1 Set Gain Settings Procedure'''
+
+        gain_mode = self.audio_input_state.gain_mode
+
+        logger.error(f"set_gain_setting: gain_mode: {gain_mode}")
+        if not (gain_mode == GainMode.MANUAL or gain_mode == GainMode.MANUAL_ONLY):
+            logger.warning(
+                "GainMode should be either MANUAL or MANUAL_ONLY Cf Spec Audio Input Control Service 3.5.2.1"
+            )
+            return
+
+        if (
+            gain_settings_operand < self.gain_settings_properties.gain_settings_minimum
+            or gain_settings_operand
+            > self.gain_settings_properties.gain_settings_maximum
+        ):
+            logger.error("gain_seetings value out of range")
+            raise ATT_Error(ErrorCode.VALUE_OUT_OF_RANGE)
+
+        if self.audio_input_state.gain_settings != gain_settings_operand:
+            self.audio_input_state.gain_settings = gain_settings_operand
+            await self.audio_input_state.notify_subscribers_via_connection(connection)
+
+    async def _unmute(self, connection: Connection):
+        '''Cf. 3.5.2.2 Unmute procedure'''
+
+        logger.error(f'unmute: {self.audio_input_state.mute}')
+        mute = self.audio_input_state.mute
+        if mute == Mute.DISABLED:
+            logger.error("unmute: Cannot change Mute value, Mute state is DISABLED")
+            raise ATT_Error(ErrorCode.MUTE_DISABLED)
+
+        if mute == Mute.NOT_MUTED:
+            return
+
+        self.audio_input_state.mute = Mute.NOT_MUTED
+        self.audio_input_state.increment_change_counter()
+        await self.audio_input_state.notify_subscribers_via_connection(connection)
+
+    async def _mute(self, connection: Connection, change_counter_operand: int) -> None:
+        '''Cf. 3.5.5.2 Mute procedure'''
+
+        change_counter = self.audio_input_state.change_counter
+        mute = self.audio_input_state.mute
+        if mute == Mute.DISABLED:
+            logger.error("mute: Cannot change Mute value, Mute state is DISABLED")
+            raise ATT_Error(ErrorCode.MUTE_DISABLED)
+
+        if change_counter != change_counter_operand:
+            raise ATT_Error(ErrorCode.INVALID_CHANGE_COUNTER)
+
+        if mute == Mute.MUTED:
+            return
+
+        self.audio_input_state.mute = Mute.MUTED
+        self.audio_input_state.increment_change_counter()
+        await self.audio_input_state.notify_subscribers_via_connection(connection)
+
+    async def _set_manual_gain_mode(self, connection: Connection) -> None:
+        '''Cf. 3.5.2.4 Set Manual Gain Mode procedure'''
+
+        gain_mode = self.audio_input_state.gain_mode
+        if gain_mode in (GainMode.AUTOMATIC_ONLY, GainMode.MANUAL_ONLY):
+            logger.error(f"Cannot change gain_mode, bad state: {gain_mode}")
+            raise ATT_Error(ErrorCode.GAIN_MODE_CHANGE_NOT_ALLOWED)
+
+        if gain_mode == GainMode.MANUAL:
+            return
+
+        self.audio_input_state.gain_mode = GainMode.MANUAL
+        self.audio_input_state.increment_change_counter()
+        await self.audio_input_state.notify_subscribers_via_connection(connection)
+
+    async def _set_automatic_gain_mode(self, connection: Connection) -> None:
+        '''Cf. 3.5.2.5 Set Automatic Gain Mode'''
+
+        gain_mode = self.audio_input_state.gain_mode
+        if gain_mode in (GainMode.AUTOMATIC_ONLY, GainMode.MANUAL_ONLY):
+            logger.error(f"Cannot change gain_mode, bad state: {gain_mode}")
+            raise ATT_Error(ErrorCode.GAIN_MODE_CHANGE_NOT_ALLOWED)
+
+        if gain_mode == GainMode.AUTOMATIC:
+            return
+
+        self.audio_input_state.gain_mode = GainMode.AUTOMATIC
+        self.audio_input_state.increment_change_counter()
+        await self.audio_input_state.notify_subscribers_via_connection(connection)
+
+
+@dataclass
+class AudioInputDescription:
+    '''
+    Cf. 3.6 Audio Input Description
+    '''
+
+    audio_input_description: str = "Bluetooth"
+    attribute_value: Optional[CharacteristicValue] = None
+
+    @classmethod
+    def from_bytes(cls, data: bytes):
+        return cls(audio_input_description=data.decode('utf-8'))
+
+    def __bytes__(self) -> bytes:
+        return self.audio_input_description.encode('utf-8')
+
+    def on_read(self, _connection: Optional[Connection]) -> bytes:
+        return self.audio_input_description.encode('utf-8')
+
+    async def on_write(self, connection: Optional[Connection], value: bytes) -> None:
+        assert connection
+        assert self.attribute_value
+
+        self.audio_input_description = value.decode('utf-8')
+        await connection.device.notify_subscribers(
+            attribute=self.attribute_value, value=value
+        )
+
+
+class AICSService(TemplateService):
+    UUID = GATT_AUDIO_INPUT_CONTROL_SERVICE
+
+    def __init__(
+        self,
+        audio_input_state: Optional[AudioInputState] = None,
+        gain_settings_properties: Optional[GainSettingsProperties] = None,
+        audio_input_type: str = "local",
+        audio_input_status: Optional[AudioInputStatus] = None,
+        audio_input_description: Optional[AudioInputDescription] = None,
+    ):
+        self.audio_input_state = (
+            AudioInputState() if audio_input_state is None else audio_input_state
+        )
+        self.gain_settings_properties = (
+            GainSettingsProperties()
+            if gain_settings_properties is None
+            else gain_settings_properties
+        )
+        self.audio_input_status = (
+            AudioInputStatus.ACTIVE
+            if audio_input_status is None
+            else audio_input_status
+        )
+        self.audio_input_description = (
+            AudioInputDescription()
+            if audio_input_description is None
+            else audio_input_description
+        )
+
+        self.audio_input_control_point: AudioInputControlPoint = AudioInputControlPoint(
+            self.audio_input_state, self.gain_settings_properties
+        )
+
+        self.audio_input_state_characteristic = DelegatedCharacteristicAdapter(
+            Characteristic(
+                uuid=GATT_AUDIO_INPUT_STATE_CHARACTERISTIC,
+                properties=Characteristic.Properties.READ
+                | Characteristic.Properties.NOTIFY,
+                permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
+                value=CharacteristicValue(read=self.audio_input_state.on_read),
+            ),
+            encode=lambda value: bytes(value),
+        )
+        self.audio_input_state.attribute_value = (
+            self.audio_input_state_characteristic.value
+        )
+
+        self.gain_settings_properties_characteristic = DelegatedCharacteristicAdapter(
+            Characteristic(
+                uuid=GATT_GAIN_SETTINGS_ATTRIBUTE_CHARACTERISTIC,
+                properties=Characteristic.Properties.READ,
+                permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
+                value=CharacteristicValue(read=self.gain_settings_properties.on_read),
+            )
+        )
+
+        self.audio_input_type_characteristic = Characteristic(
+            uuid=GATT_AUDIO_INPUT_TYPE_CHARACTERISTIC,
+            properties=Characteristic.Properties.READ,
+            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
+            value=audio_input_type,
+        )
+
+        self.audio_input_status_characteristic = Characteristic(
+            uuid=GATT_AUDIO_INPUT_STATUS_CHARACTERISTIC,
+            properties=Characteristic.Properties.READ,
+            permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
+            value=bytes([self.audio_input_status]),
+        )
+
+        self.audio_input_control_point_characteristic = DelegatedCharacteristicAdapter(
+            Characteristic(
+                uuid=GATT_AUDIO_INPUT_CONTROL_POINT_CHARACTERISTIC,
+                properties=Characteristic.Properties.WRITE,
+                permissions=Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
+                value=CharacteristicValue(
+                    write=self.audio_input_control_point.on_write
+                ),
+            )
+        )
+
+        self.audio_input_description_characteristic = DelegatedCharacteristicAdapter(
+            Characteristic(
+                uuid=GATT_AUDIO_INPUT_DESCRIPTION_CHARACTERISTIC,
+                properties=Characteristic.Properties.READ
+                | Characteristic.Properties.NOTIFY
+                | Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
+                permissions=Characteristic.Permissions.READ_REQUIRES_ENCRYPTION
+                | Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
+                value=CharacteristicValue(
+                    write=self.audio_input_description.on_write,
+                    read=self.audio_input_description.on_read,
+                ),
+            )
+        )
+        self.audio_input_description.attribute_value = (
+            self.audio_input_control_point_characteristic.value
+        )
+
+        super().__init__(
+            characteristics=[
+                self.audio_input_state_characteristic,  # type: ignore
+                self.gain_settings_properties_characteristic,  # type: ignore
+                self.audio_input_type_characteristic,  # type: ignore
+                self.audio_input_status_characteristic,  # type: ignore
+                self.audio_input_control_point_characteristic,  # type: ignore
+                self.audio_input_description_characteristic,  # type: ignore
+            ],
+            primary=False,
+        )
+
+
+# -----------------------------------------------------------------------------
+# Client
+# -----------------------------------------------------------------------------
+class AICSServiceProxy(ProfileServiceProxy):
+    SERVICE_CLASS = AICSService
+
+    def __init__(self, service_proxy: ServiceProxy) -> None:
+        self.service_proxy = service_proxy
+
+        if not (
+            characteristics := service_proxy.get_characteristics_by_uuid(
+                GATT_AUDIO_INPUT_STATE_CHARACTERISTIC
+            )
+        ):
+            raise gatt.InvalidServiceError("Audio Input State Characteristic not found")
+        self.audio_input_state = DelegatedCharacteristicAdapter(
+            characteristic=characteristics[0], decode=AudioInputState.from_bytes
+        )
+
+        if not (
+            characteristics := service_proxy.get_characteristics_by_uuid(
+                GATT_GAIN_SETTINGS_ATTRIBUTE_CHARACTERISTIC
+            )
+        ):
+            raise gatt.InvalidServiceError(
+                "Gain Settings Attribute Characteristic not found"
+            )
+        self.gain_settings_properties = PackedCharacteristicAdapter(
+            characteristics[0],
+            'BBB',
+        )
+
+        if not (
+            characteristics := service_proxy.get_characteristics_by_uuid(
+                GATT_AUDIO_INPUT_STATUS_CHARACTERISTIC
+            )
+        ):
+            raise gatt.InvalidServiceError(
+                "Audio Input Status Characteristic not found"
+            )
+        self.audio_input_status = PackedCharacteristicAdapter(
+            characteristics[0],
+            'B',
+        )
+
+        if not (
+            characteristics := service_proxy.get_characteristics_by_uuid(
+                GATT_AUDIO_INPUT_CONTROL_POINT_CHARACTERISTIC
+            )
+        ):
+            raise gatt.InvalidServiceError(
+                "Audio Input Control Point Characteristic not found"
+            )
+        self.audio_input_control_point = characteristics[0]
+
+        if not (
+            characteristics := service_proxy.get_characteristics_by_uuid(
+                GATT_AUDIO_INPUT_DESCRIPTION_CHARACTERISTIC
+            )
+        ):
+            raise gatt.InvalidServiceError(
+                "Audio Input Description Characteristic not found"
+            )
+        self.audio_input_description = characteristics[0]
diff --git a/bumble/profiles/ascs.py b/bumble/profiles/ascs.py
new file mode 100644
index 0000000..35f4594
--- /dev/null
+++ b/bumble/profiles/ascs.py
@@ -0,0 +1,739 @@
+# Copyright 2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for
+
+"""LE Audio - Audio Stream Control Service"""
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+from __future__ import annotations
+import enum
+import logging
+import struct
+from typing import Any, Dict, List, Optional, Sequence, Tuple, Type, Union
+
+from bumble import colors
+from bumble.profiles.bap import CodecSpecificConfiguration
+from bumble.profiles import le_audio
+from bumble import device
+from bumble import gatt
+from bumble import gatt_client
+from bumble import hci
+
+# -----------------------------------------------------------------------------
+# Logging
+# -----------------------------------------------------------------------------
+logger = logging.getLogger(__name__)
+
+
+# -----------------------------------------------------------------------------
+# ASE Operations
+# -----------------------------------------------------------------------------
+
+
+class ASE_Operation:
+    '''
+    See Audio Stream Control Service - 5 ASE Control operations.
+    '''
+
+    classes: Dict[int, Type[ASE_Operation]] = {}
+    op_code: int
+    name: str
+    fields: Optional[Sequence[Any]] = None
+    ase_id: List[int]
+
+    class Opcode(enum.IntEnum):
+        # fmt: off
+        CONFIG_CODEC         = 0x01
+        CONFIG_QOS           = 0x02
+        ENABLE               = 0x03
+        RECEIVER_START_READY = 0x04
+        DISABLE              = 0x05
+        RECEIVER_STOP_READY  = 0x06
+        UPDATE_METADATA      = 0x07
+        RELEASE              = 0x08
+
+    @staticmethod
+    def from_bytes(pdu: bytes) -> ASE_Operation:
+        op_code = pdu[0]
+
+        cls = ASE_Operation.classes.get(op_code)
+        if cls is None:
+            instance = ASE_Operation(pdu)
+            instance.name = ASE_Operation.Opcode(op_code).name
+            instance.op_code = op_code
+            return instance
+        self = cls.__new__(cls)
+        ASE_Operation.__init__(self, pdu)
+        if self.fields is not None:
+            self.init_from_bytes(pdu, 1)
+        return self
+
+    @staticmethod
+    def subclass(fields):
+        def inner(cls: Type[ASE_Operation]):
+            try:
+                operation = ASE_Operation.Opcode[cls.__name__[4:].upper()]
+                cls.name = operation.name
+                cls.op_code = operation
+            except:
+                raise KeyError(f'PDU name {cls.name} not found in Ase_Operation.Opcode')
+            cls.fields = fields
+
+            # Register a factory for this class
+            ASE_Operation.classes[cls.op_code] = cls
+
+            return cls
+
+        return inner
+
+    def __init__(self, pdu: Optional[bytes] = None, **kwargs) -> None:
+        if self.fields is not None and kwargs:
+            hci.HCI_Object.init_from_fields(self, self.fields, kwargs)
+        if pdu is None:
+            pdu = bytes([self.op_code]) + hci.HCI_Object.dict_to_bytes(
+                kwargs, self.fields
+            )
+        self.pdu = pdu
+
+    def init_from_bytes(self, pdu: bytes, offset: int):
+        return hci.HCI_Object.init_from_bytes(self, pdu, offset, self.fields)
+
+    def __bytes__(self) -> bytes:
+        return self.pdu
+
+    def __str__(self) -> str:
+        result = f'{colors.color(self.name, "yellow")} '
+        if fields := getattr(self, 'fields', None):
+            result += ':\n' + hci.HCI_Object.format_fields(self.__dict__, fields, '  ')
+        else:
+            if len(self.pdu) > 1:
+                result += f': {self.pdu.hex()}'
+        return result
+
+
+@ASE_Operation.subclass(
+    [
+        [
+            ('ase_id', 1),
+            ('target_latency', 1),
+            ('target_phy', 1),
+            ('codec_id', hci.CodingFormat.parse_from_bytes),
+            ('codec_specific_configuration', 'v'),
+        ],
+    ]
+)
+class ASE_Config_Codec(ASE_Operation):
+    '''
+    See Audio Stream Control Service 5.1 - Config Codec Operation
+    '''
+
+    target_latency: List[int]
+    target_phy: List[int]
+    codec_id: List[hci.CodingFormat]
+    codec_specific_configuration: List[bytes]
+
+
+@ASE_Operation.subclass(
+    [
+        [
+            ('ase_id', 1),
+            ('cig_id', 1),
+            ('cis_id', 1),
+            ('sdu_interval', 3),
+            ('framing', 1),
+            ('phy', 1),
+            ('max_sdu', 2),
+            ('retransmission_number', 1),
+            ('max_transport_latency', 2),
+            ('presentation_delay', 3),
+        ],
+    ]
+)
+class ASE_Config_QOS(ASE_Operation):
+    '''
+    See Audio Stream Control Service 5.2 - Config Qos Operation
+    '''
+
+    cig_id: List[int]
+    cis_id: List[int]
+    sdu_interval: List[int]
+    framing: List[int]
+    phy: List[int]
+    max_sdu: List[int]
+    retransmission_number: List[int]
+    max_transport_latency: List[int]
+    presentation_delay: List[int]
+
+
+@ASE_Operation.subclass([[('ase_id', 1), ('metadata', 'v')]])
+class ASE_Enable(ASE_Operation):
+    '''
+    See Audio Stream Control Service 5.3 - Enable Operation
+    '''
+
+    metadata: bytes
+
+
+@ASE_Operation.subclass([[('ase_id', 1)]])
+class ASE_Receiver_Start_Ready(ASE_Operation):
+    '''
+    See Audio Stream Control Service 5.4 - Receiver Start Ready Operation
+    '''
+
+
+@ASE_Operation.subclass([[('ase_id', 1)]])
+class ASE_Disable(ASE_Operation):
+    '''
+    See Audio Stream Control Service 5.5 - Disable Operation
+    '''
+
+
+@ASE_Operation.subclass([[('ase_id', 1)]])
+class ASE_Receiver_Stop_Ready(ASE_Operation):
+    '''
+    See Audio Stream Control Service 5.6 - Receiver Stop Ready Operation
+    '''
+
+
+@ASE_Operation.subclass([[('ase_id', 1), ('metadata', 'v')]])
+class ASE_Update_Metadata(ASE_Operation):
+    '''
+    See Audio Stream Control Service 5.7 - Update Metadata Operation
+    '''
+
+    metadata: List[bytes]
+
+
+@ASE_Operation.subclass([[('ase_id', 1)]])
+class ASE_Release(ASE_Operation):
+    '''
+    See Audio Stream Control Service 5.8 - Release Operation
+    '''
+
+
+class AseResponseCode(enum.IntEnum):
+    # fmt: off
+    SUCCESS                                     = 0x00
+    UNSUPPORTED_OPCODE                          = 0x01
+    INVALID_LENGTH                              = 0x02
+    INVALID_ASE_ID                              = 0x03
+    INVALID_ASE_STATE_MACHINE_TRANSITION        = 0x04
+    INVALID_ASE_DIRECTION                       = 0x05
+    UNSUPPORTED_AUDIO_CAPABILITIES              = 0x06
+    UNSUPPORTED_CONFIGURATION_PARAMETER_VALUE   = 0x07
+    REJECTED_CONFIGURATION_PARAMETER_VALUE      = 0x08
+    INVALID_CONFIGURATION_PARAMETER_VALUE       = 0x09
+    UNSUPPORTED_METADATA                        = 0x0A
+    REJECTED_METADATA                           = 0x0B
+    INVALID_METADATA                            = 0x0C
+    INSUFFICIENT_RESOURCES                      = 0x0D
+    UNSPECIFIED_ERROR                           = 0x0E
+
+
+class AseReasonCode(enum.IntEnum):
+    # fmt: off
+    NONE                            = 0x00
+    CODEC_ID                        = 0x01
+    CODEC_SPECIFIC_CONFIGURATION    = 0x02
+    SDU_INTERVAL                    = 0x03
+    FRAMING                         = 0x04
+    PHY                             = 0x05
+    MAXIMUM_SDU_SIZE                = 0x06
+    RETRANSMISSION_NUMBER           = 0x07
+    MAX_TRANSPORT_LATENCY           = 0x08
+    PRESENTATION_DELAY              = 0x09
+    INVALID_ASE_CIS_MAPPING         = 0x0A
+
+
+# -----------------------------------------------------------------------------
+class AudioRole(enum.IntEnum):
+    SINK = hci.HCI_LE_Setup_ISO_Data_Path_Command.Direction.CONTROLLER_TO_HOST
+    SOURCE = hci.HCI_LE_Setup_ISO_Data_Path_Command.Direction.HOST_TO_CONTROLLER
+
+
+# -----------------------------------------------------------------------------
+class AseStateMachine(gatt.Characteristic):
+    class State(enum.IntEnum):
+        # fmt: off
+        IDLE             = 0x00
+        CODEC_CONFIGURED = 0x01
+        QOS_CONFIGURED   = 0x02
+        ENABLING         = 0x03
+        STREAMING        = 0x04
+        DISABLING        = 0x05
+        RELEASING        = 0x06
+
+    cis_link: Optional[device.CisLink] = None
+
+    # Additional parameters in CODEC_CONFIGURED State
+    preferred_framing = 0  # Unframed PDU supported
+    preferred_phy = 0
+    preferred_retransmission_number = 13
+    preferred_max_transport_latency = 100
+    supported_presentation_delay_min = 0
+    supported_presentation_delay_max = 0
+    preferred_presentation_delay_min = 0
+    preferred_presentation_delay_max = 0
+    codec_id = hci.CodingFormat(hci.CodecID.LC3)
+    codec_specific_configuration: Union[CodecSpecificConfiguration, bytes] = b''
+
+    # Additional parameters in QOS_CONFIGURED State
+    cig_id = 0
+    cis_id = 0
+    sdu_interval = 0
+    framing = 0
+    phy = 0
+    max_sdu = 0
+    retransmission_number = 0
+    max_transport_latency = 0
+    presentation_delay = 0
+
+    # Additional parameters in ENABLING, STREAMING, DISABLING State
+    metadata = le_audio.Metadata()
+
+    def __init__(
+        self,
+        role: AudioRole,
+        ase_id: int,
+        service: AudioStreamControlService,
+    ) -> None:
+        self.service = service
+        self.ase_id = ase_id
+        self._state = AseStateMachine.State.IDLE
+        self.role = role
+
+        uuid = (
+            gatt.GATT_SINK_ASE_CHARACTERISTIC
+            if role == AudioRole.SINK
+            else gatt.GATT_SOURCE_ASE_CHARACTERISTIC
+        )
+        super().__init__(
+            uuid=uuid,
+            properties=gatt.Characteristic.Properties.READ
+            | gatt.Characteristic.Properties.NOTIFY,
+            permissions=gatt.Characteristic.Permissions.READABLE,
+            value=gatt.CharacteristicValue(read=self.on_read),
+        )
+
+        self.service.device.on('cis_request', self.on_cis_request)
+        self.service.device.on('cis_establishment', self.on_cis_establishment)
+
+    def on_cis_request(
+        self,
+        acl_connection: device.Connection,
+        cis_handle: int,
+        cig_id: int,
+        cis_id: int,
+    ) -> None:
+        if (
+            cig_id == self.cig_id
+            and cis_id == self.cis_id
+            and self.state == self.State.ENABLING
+        ):
+            acl_connection.abort_on(
+                'flush', self.service.device.accept_cis_request(cis_handle)
+            )
+
+    def on_cis_establishment(self, cis_link: device.CisLink) -> None:
+        if (
+            cis_link.cig_id == self.cig_id
+            and cis_link.cis_id == self.cis_id
+            and self.state == self.State.ENABLING
+        ):
+            cis_link.on('disconnection', self.on_cis_disconnection)
+
+            async def post_cis_established():
+                await self.service.device.send_command(
+                    hci.HCI_LE_Setup_ISO_Data_Path_Command(
+                        connection_handle=cis_link.handle,
+                        data_path_direction=self.role,
+                        data_path_id=0x00,  # Fixed HCI
+                        codec_id=hci.CodingFormat(hci.CodecID.TRANSPARENT),
+                        controller_delay=0,
+                        codec_configuration=b'',
+                    )
+                )
+                if self.role == AudioRole.SINK:
+                    self.state = self.State.STREAMING
+                await self.service.device.notify_subscribers(self, self.value)
+
+            cis_link.acl_connection.abort_on('flush', post_cis_established())
+            self.cis_link = cis_link
+
+    def on_cis_disconnection(self, _reason) -> None:
+        self.cis_link = None
+
+    def on_config_codec(
+        self,
+        target_latency: int,
+        target_phy: int,
+        codec_id: hci.CodingFormat,
+        codec_specific_configuration: bytes,
+    ) -> Tuple[AseResponseCode, AseReasonCode]:
+        if self.state not in (
+            self.State.IDLE,
+            self.State.CODEC_CONFIGURED,
+            self.State.QOS_CONFIGURED,
+        ):
+            return (
+                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
+                AseReasonCode.NONE,
+            )
+
+        self.max_transport_latency = target_latency
+        self.phy = target_phy
+        self.codec_id = codec_id
+        if codec_id.codec_id == hci.CodecID.VENDOR_SPECIFIC:
+            self.codec_specific_configuration = codec_specific_configuration
+        else:
+            self.codec_specific_configuration = CodecSpecificConfiguration.from_bytes(
+                codec_specific_configuration
+            )
+
+        self.state = self.State.CODEC_CONFIGURED
+
+        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
+
+    def on_config_qos(
+        self,
+        cig_id: int,
+        cis_id: int,
+        sdu_interval: int,
+        framing: int,
+        phy: int,
+        max_sdu: int,
+        retransmission_number: int,
+        max_transport_latency: int,
+        presentation_delay: int,
+    ) -> Tuple[AseResponseCode, AseReasonCode]:
+        if self.state not in (
+            AseStateMachine.State.CODEC_CONFIGURED,
+            AseStateMachine.State.QOS_CONFIGURED,
+        ):
+            return (
+                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
+                AseReasonCode.NONE,
+            )
+
+        self.cig_id = cig_id
+        self.cis_id = cis_id
+        self.sdu_interval = sdu_interval
+        self.framing = framing
+        self.phy = phy
+        self.max_sdu = max_sdu
+        self.retransmission_number = retransmission_number
+        self.max_transport_latency = max_transport_latency
+        self.presentation_delay = presentation_delay
+
+        self.state = self.State.QOS_CONFIGURED
+
+        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
+
+    def on_enable(self, metadata: bytes) -> Tuple[AseResponseCode, AseReasonCode]:
+        if self.state != AseStateMachine.State.QOS_CONFIGURED:
+            return (
+                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
+                AseReasonCode.NONE,
+            )
+
+        self.metadata = le_audio.Metadata.from_bytes(metadata)
+        self.state = self.State.ENABLING
+
+        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
+
+    def on_receiver_start_ready(self) -> Tuple[AseResponseCode, AseReasonCode]:
+        if self.state != AseStateMachine.State.ENABLING:
+            return (
+                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
+                AseReasonCode.NONE,
+            )
+        self.state = self.State.STREAMING
+        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
+
+    def on_disable(self) -> Tuple[AseResponseCode, AseReasonCode]:
+        if self.state not in (
+            AseStateMachine.State.ENABLING,
+            AseStateMachine.State.STREAMING,
+        ):
+            return (
+                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
+                AseReasonCode.NONE,
+            )
+        if self.role == AudioRole.SINK:
+            self.state = self.State.QOS_CONFIGURED
+        else:
+            self.state = self.State.DISABLING
+        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
+
+    def on_receiver_stop_ready(self) -> Tuple[AseResponseCode, AseReasonCode]:
+        if (
+            self.role != AudioRole.SOURCE
+            or self.state != AseStateMachine.State.DISABLING
+        ):
+            return (
+                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
+                AseReasonCode.NONE,
+            )
+        self.state = self.State.QOS_CONFIGURED
+        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
+
+    def on_update_metadata(
+        self, metadata: bytes
+    ) -> Tuple[AseResponseCode, AseReasonCode]:
+        if self.state not in (
+            AseStateMachine.State.ENABLING,
+            AseStateMachine.State.STREAMING,
+        ):
+            return (
+                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
+                AseReasonCode.NONE,
+            )
+        self.metadata = le_audio.Metadata.from_bytes(metadata)
+        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
+
+    def on_release(self) -> Tuple[AseResponseCode, AseReasonCode]:
+        if self.state == AseStateMachine.State.IDLE:
+            return (
+                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
+                AseReasonCode.NONE,
+            )
+        self.state = self.State.RELEASING
+
+        async def remove_cis_async():
+            await self.service.device.send_command(
+                hci.HCI_LE_Remove_ISO_Data_Path_Command(
+                    connection_handle=self.cis_link.handle,
+                    data_path_direction=self.role,
+                )
+            )
+            self.state = self.State.IDLE
+            await self.service.device.notify_subscribers(self, self.value)
+
+        self.service.device.abort_on('flush', remove_cis_async())
+        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
+
+    @property
+    def state(self) -> State:
+        return self._state
+
+    @state.setter
+    def state(self, new_state: State) -> None:
+        logger.debug(f'{self} state change -> {colors.color(new_state.name, "cyan")}')
+        self._state = new_state
+        self.emit('state_change')
+
+    @property
+    def value(self):
+        '''Returns ASE_ID, ASE_STATE, and ASE Additional Parameters.'''
+
+        if self.state == self.State.CODEC_CONFIGURED:
+            codec_specific_configuration_bytes = bytes(
+                self.codec_specific_configuration
+            )
+            additional_parameters = (
+                struct.pack(
+                    '<BBBH',
+                    self.preferred_framing,
+                    self.preferred_phy,
+                    self.preferred_retransmission_number,
+                    self.preferred_max_transport_latency,
+                )
+                + self.supported_presentation_delay_min.to_bytes(3, 'little')
+                + self.supported_presentation_delay_max.to_bytes(3, 'little')
+                + self.preferred_presentation_delay_min.to_bytes(3, 'little')
+                + self.preferred_presentation_delay_max.to_bytes(3, 'little')
+                + bytes(self.codec_id)
+                + bytes([len(codec_specific_configuration_bytes)])
+                + codec_specific_configuration_bytes
+            )
+        elif self.state == self.State.QOS_CONFIGURED:
+            additional_parameters = (
+                bytes([self.cig_id, self.cis_id])
+                + self.sdu_interval.to_bytes(3, 'little')
+                + struct.pack(
+                    '<BBHBH',
+                    self.framing,
+                    self.phy,
+                    self.max_sdu,
+                    self.retransmission_number,
+                    self.max_transport_latency,
+                )
+                + self.presentation_delay.to_bytes(3, 'little')
+            )
+        elif self.state in (
+            self.State.ENABLING,
+            self.State.STREAMING,
+            self.State.DISABLING,
+        ):
+            metadata_bytes = bytes(self.metadata)
+            additional_parameters = (
+                bytes([self.cig_id, self.cis_id, len(metadata_bytes)]) + metadata_bytes
+            )
+        else:
+            additional_parameters = b''
+
+        return bytes([self.ase_id, self.state]) + additional_parameters
+
+    @value.setter
+    def value(self, _new_value):
+        # Readonly. Do nothing in the setter.
+        pass
+
+    def on_read(self, _: Optional[device.Connection]) -> bytes:
+        return self.value
+
+    def __str__(self) -> str:
+        return (
+            f'AseStateMachine(id={self.ase_id}, role={self.role.name} '
+            f'state={self._state.name})'
+        )
+
+
+# -----------------------------------------------------------------------------
+class AudioStreamControlService(gatt.TemplateService):
+    UUID = gatt.GATT_AUDIO_STREAM_CONTROL_SERVICE
+
+    ase_state_machines: Dict[int, AseStateMachine]
+    ase_control_point: gatt.Characteristic
+    _active_client: Optional[device.Connection] = None
+
+    def __init__(
+        self,
+        device: device.Device,
+        source_ase_id: Sequence[int] = (),
+        sink_ase_id: Sequence[int] = (),
+    ) -> None:
+        self.device = device
+        self.ase_state_machines = {
+            **{
+                id: AseStateMachine(role=AudioRole.SINK, ase_id=id, service=self)
+                for id in sink_ase_id
+            },
+            **{
+                id: AseStateMachine(role=AudioRole.SOURCE, ase_id=id, service=self)
+                for id in source_ase_id
+            },
+        }  # ASE state machines, by ASE ID
+
+        self.ase_control_point = gatt.Characteristic(
+            uuid=gatt.GATT_ASE_CONTROL_POINT_CHARACTERISTIC,
+            properties=gatt.Characteristic.Properties.WRITE
+            | gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE
+            | gatt.Characteristic.Properties.NOTIFY,
+            permissions=gatt.Characteristic.Permissions.WRITEABLE,
+            value=gatt.CharacteristicValue(write=self.on_write_ase_control_point),
+        )
+
+        super().__init__([self.ase_control_point, *self.ase_state_machines.values()])
+
+    def on_operation(self, opcode: ASE_Operation.Opcode, ase_id: int, args):
+        if ase := self.ase_state_machines.get(ase_id):
+            handler = getattr(ase, 'on_' + opcode.name.lower())
+            return (ase_id, *handler(*args))
+        else:
+            return (ase_id, AseResponseCode.INVALID_ASE_ID, AseReasonCode.NONE)
+
+    def _on_client_disconnected(self, _reason: int) -> None:
+        for ase in self.ase_state_machines.values():
+            ase.state = AseStateMachine.State.IDLE
+        self._active_client = None
+
+    def on_write_ase_control_point(self, connection, data):
+        if not self._active_client and connection:
+            self._active_client = connection
+            connection.once('disconnection', self._on_client_disconnected)
+
+        operation = ASE_Operation.from_bytes(data)
+        responses = []
+        logger.debug(f'*** ASCS Write {operation} ***')
+
+        if operation.op_code == ASE_Operation.Opcode.CONFIG_CODEC:
+            for ase_id, *args in zip(
+                operation.ase_id,
+                operation.target_latency,
+                operation.target_phy,
+                operation.codec_id,
+                operation.codec_specific_configuration,
+            ):
+                responses.append(self.on_operation(operation.op_code, ase_id, args))
+        elif operation.op_code == ASE_Operation.Opcode.CONFIG_QOS:
+            for ase_id, *args in zip(
+                operation.ase_id,
+                operation.cig_id,
+                operation.cis_id,
+                operation.sdu_interval,
+                operation.framing,
+                operation.phy,
+                operation.max_sdu,
+                operation.retransmission_number,
+                operation.max_transport_latency,
+                operation.presentation_delay,
+            ):
+                responses.append(self.on_operation(operation.op_code, ase_id, args))
+        elif operation.op_code in (
+            ASE_Operation.Opcode.ENABLE,
+            ASE_Operation.Opcode.UPDATE_METADATA,
+        ):
+            for ase_id, *args in zip(
+                operation.ase_id,
+                operation.metadata,
+            ):
+                responses.append(self.on_operation(operation.op_code, ase_id, args))
+        elif operation.op_code in (
+            ASE_Operation.Opcode.RECEIVER_START_READY,
+            ASE_Operation.Opcode.DISABLE,
+            ASE_Operation.Opcode.RECEIVER_STOP_READY,
+            ASE_Operation.Opcode.RELEASE,
+        ):
+            for ase_id in operation.ase_id:
+                responses.append(self.on_operation(operation.op_code, ase_id, []))
+
+        control_point_notification = bytes(
+            [operation.op_code, len(responses)]
+        ) + b''.join(map(bytes, responses))
+        self.device.abort_on(
+            'flush',
+            self.device.notify_subscribers(
+                self.ase_control_point, control_point_notification
+            ),
+        )
+
+        for ase_id, *_ in responses:
+            if ase := self.ase_state_machines.get(ase_id):
+                self.device.abort_on(
+                    'flush',
+                    self.device.notify_subscribers(ase, ase.value),
+                )
+
+
+# -----------------------------------------------------------------------------
+class AudioStreamControlServiceProxy(gatt_client.ProfileServiceProxy):
+    SERVICE_CLASS = AudioStreamControlService
+
+    sink_ase: List[gatt_client.CharacteristicProxy]
+    source_ase: List[gatt_client.CharacteristicProxy]
+    ase_control_point: gatt_client.CharacteristicProxy
+
+    def __init__(self, service_proxy: gatt_client.ServiceProxy):
+        self.service_proxy = service_proxy
+
+        self.sink_ase = service_proxy.get_characteristics_by_uuid(
+            gatt.GATT_SINK_ASE_CHARACTERISTIC
+        )
+        self.source_ase = service_proxy.get_characteristics_by_uuid(
+            gatt.GATT_SOURCE_ASE_CHARACTERISTIC
+        )
+        self.ase_control_point = service_proxy.get_characteristics_by_uuid(
+            gatt.GATT_ASE_CONTROL_POINT_CHARACTERISTIC
+        )[0]
diff --git a/bumble/profiles/asha.py b/bumble/profiles/asha.py
new file mode 100644
index 0000000..b2aa441
--- /dev/null
+++ b/bumble/profiles/asha.py
@@ -0,0 +1,295 @@
+# Copyright 2021-2022 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+import enum
+import struct
+import logging
+from typing import List, Optional, Callable, Union, Any
+
+from bumble import l2cap
+from bumble import utils
+from bumble import gatt
+from bumble import gatt_client
+from bumble.core import AdvertisingData
+from bumble.device import Device, Connection
+
+# -----------------------------------------------------------------------------
+# Logging
+# -----------------------------------------------------------------------------
+_logger = logging.getLogger(__name__)
+
+
+# -----------------------------------------------------------------------------
+# Constants
+# -----------------------------------------------------------------------------
+class DeviceCapabilities(enum.IntFlag):
+    IS_RIGHT = 0x01
+    IS_DUAL = 0x02
+    CSIS_SUPPORTED = 0x04
+
+
+class FeatureMap(enum.IntFlag):
+    LE_COC_AUDIO_OUTPUT_STREAMING_SUPPORTED = 0x01
+
+
+class AudioType(utils.OpenIntEnum):
+    UNKNOWN = 0x00
+    RINGTONE = 0x01
+    PHONE_CALL = 0x02
+    MEDIA = 0x03
+
+
+class OpCode(utils.OpenIntEnum):
+    START = 1
+    STOP = 2
+    STATUS = 3
+
+
+class Codec(utils.OpenIntEnum):
+    G_722_16KHZ = 1
+
+
+class SupportedCodecs(enum.IntFlag):
+    G_722_16KHZ = 1 << Codec.G_722_16KHZ
+
+
+class PeripheralStatus(utils.OpenIntEnum):
+    """Status update on the other peripheral."""
+
+    OTHER_PERIPHERAL_DISCONNECTED = 1
+    OTHER_PERIPHERAL_CONNECTED = 2
+    CONNECTION_PARAMETER_UPDATED = 3
+
+
+class AudioStatus(utils.OpenIntEnum):
+    """Status report field for the audio control point."""
+
+    OK = 0
+    UNKNOWN_COMMAND = -1
+    ILLEGAL_PARAMETERS = -2
+
+
+# -----------------------------------------------------------------------------
+class AshaService(gatt.TemplateService):
+    UUID = gatt.GATT_ASHA_SERVICE
+
+    audio_sink: Optional[Callable[[bytes], Any]]
+    active_codec: Optional[Codec] = None
+    audio_type: Optional[AudioType] = None
+    volume: Optional[int] = None
+    other_state: Optional[int] = None
+    connection: Optional[Connection] = None
+
+    def __init__(
+        self,
+        capability: int,
+        hisyncid: Union[List[int], bytes],
+        device: Device,
+        psm: int = 0,
+        audio_sink: Optional[Callable[[bytes], Any]] = None,
+        feature_map: int = FeatureMap.LE_COC_AUDIO_OUTPUT_STREAMING_SUPPORTED,
+        protocol_version: int = 0x01,
+        render_delay_milliseconds: int = 0,
+        supported_codecs: int = SupportedCodecs.G_722_16KHZ,
+    ) -> None:
+        if len(hisyncid) != 8:
+            _logger.warning('HiSyncId should have a length of 8, got %d', len(hisyncid))
+
+        self.hisyncid = bytes(hisyncid)
+        self.capability = capability
+        self.device = device
+        self.audio_out_data = b''
+        self.psm = psm  # a non-zero psm is mainly for testing purpose
+        self.audio_sink = audio_sink
+        self.protocol_version = protocol_version
+
+        self.read_only_properties_characteristic = gatt.Characteristic(
+            gatt.GATT_ASHA_READ_ONLY_PROPERTIES_CHARACTERISTIC,
+            gatt.Characteristic.Properties.READ,
+            gatt.Characteristic.READABLE,
+            struct.pack(
+                "<BB8sBH2sH",
+                protocol_version,
+                capability,
+                self.hisyncid,
+                feature_map,
+                render_delay_milliseconds,
+                b'\x00\x00',
+                supported_codecs,
+            ),
+        )
+
+        self.audio_control_point_characteristic = gatt.Characteristic(
+            gatt.GATT_ASHA_AUDIO_CONTROL_POINT_CHARACTERISTIC,
+            gatt.Characteristic.Properties.WRITE
+            | gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
+            gatt.Characteristic.WRITEABLE,
+            gatt.CharacteristicValue(write=self._on_audio_control_point_write),
+        )
+        self.audio_status_characteristic = gatt.Characteristic(
+            gatt.GATT_ASHA_AUDIO_STATUS_CHARACTERISTIC,
+            gatt.Characteristic.Properties.READ | gatt.Characteristic.Properties.NOTIFY,
+            gatt.Characteristic.READABLE,
+            bytes([AudioStatus.OK]),
+        )
+        self.volume_characteristic = gatt.Characteristic(
+            gatt.GATT_ASHA_VOLUME_CHARACTERISTIC,
+            gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
+            gatt.Characteristic.WRITEABLE,
+            gatt.CharacteristicValue(write=self._on_volume_write),
+        )
+
+        # let the server find a free PSM
+        self.psm = device.create_l2cap_server(
+            spec=l2cap.LeCreditBasedChannelSpec(psm=self.psm, max_credits=8),
+            handler=self._on_connection,
+        ).psm
+        self.le_psm_out_characteristic = gatt.Characteristic(
+            gatt.GATT_ASHA_LE_PSM_OUT_CHARACTERISTIC,
+            gatt.Characteristic.Properties.READ,
+            gatt.Characteristic.READABLE,
+            struct.pack('<H', self.psm),
+        )
+
+        characteristics = [
+            self.read_only_properties_characteristic,
+            self.audio_control_point_characteristic,
+            self.audio_status_characteristic,
+            self.volume_characteristic,
+            self.le_psm_out_characteristic,
+        ]
+
+        super().__init__(characteristics)
+
+    def get_advertising_data(self) -> bytes:
+        # Advertisement only uses 4 least significant bytes of the HiSyncId.
+        return bytes(
+            AdvertisingData(
+                [
+                    (
+                        AdvertisingData.SERVICE_DATA_16_BIT_UUID,
+                        bytes(gatt.GATT_ASHA_SERVICE)
+                        + bytes([self.protocol_version, self.capability])
+                        + self.hisyncid[:4],
+                    ),
+                ]
+            )
+        )
+
+    # Handler for audio control commands
+    async def _on_audio_control_point_write(
+        self, connection: Optional[Connection], value: bytes
+    ) -> None:
+        _logger.debug(f'--- AUDIO CONTROL POINT Write:{value.hex()}')
+        opcode = value[0]
+        if opcode == OpCode.START:
+            # Start
+            self.active_codec = Codec(value[1])
+            self.audio_type = AudioType(value[2])
+            self.volume = value[3]
+            self.other_state = value[4]
+            _logger.debug(
+                f'### START: codec={self.active_codec.name}, '
+                f'audio_type={self.audio_type.name}, '
+                f'volume={self.volume}, '
+                f'other_state={self.other_state}'
+            )
+            self.emit('started')
+        elif opcode == OpCode.STOP:
+            _logger.debug('### STOP')
+            self.active_codec = None
+            self.audio_type = None
+            self.volume = None
+            self.other_state = None
+            self.emit('stopped')
+        elif opcode == OpCode.STATUS:
+            _logger.debug('### STATUS: %s', PeripheralStatus(value[1]).name)
+
+        if self.connection is None and connection:
+            self.connection = connection
+
+            def on_disconnection(_reason) -> None:
+                self.connection = None
+                self.active_codec = None
+                self.audio_type = None
+                self.volume = None
+                self.other_state = None
+                self.emit('disconnected')
+
+            connection.once('disconnection', on_disconnection)
+
+        # OPCODE_STATUS does not need audio status point update
+        if opcode != OpCode.STATUS:
+            await self.device.notify_subscribers(
+                self.audio_status_characteristic, force=True
+            )
+
+    # Handler for volume control
+    def _on_volume_write(self, connection: Optional[Connection], value: bytes) -> None:
+        _logger.debug(f'--- VOLUME Write:{value[0]}')
+        self.volume = value[0]
+        self.emit('volume_changed')
+
+    # Register an L2CAP CoC server
+    def _on_connection(self, channel: l2cap.LeCreditBasedChannel) -> None:
+        def on_data(data: bytes) -> None:
+            if self.audio_sink:  # pylint: disable=not-callable
+                self.audio_sink(data)
+
+        channel.sink = on_data
+
+
+# -----------------------------------------------------------------------------
+class AshaServiceProxy(gatt_client.ProfileServiceProxy):
+    SERVICE_CLASS = AshaService
+    read_only_properties_characteristic: gatt_client.CharacteristicProxy
+    audio_control_point_characteristic: gatt_client.CharacteristicProxy
+    audio_status_point_characteristic: gatt_client.CharacteristicProxy
+    volume_characteristic: gatt_client.CharacteristicProxy
+    psm_characteristic: gatt_client.CharacteristicProxy
+
+    def __init__(self, service_proxy: gatt_client.ServiceProxy) -> None:
+        self.service_proxy = service_proxy
+
+        for uuid, attribute_name in (
+            (
+                gatt.GATT_ASHA_READ_ONLY_PROPERTIES_CHARACTERISTIC,
+                'read_only_properties_characteristic',
+            ),
+            (
+                gatt.GATT_ASHA_AUDIO_CONTROL_POINT_CHARACTERISTIC,
+                'audio_control_point_characteristic',
+            ),
+            (
+                gatt.GATT_ASHA_AUDIO_STATUS_CHARACTERISTIC,
+                'audio_status_point_characteristic',
+            ),
+            (
+                gatt.GATT_ASHA_VOLUME_CHARACTERISTIC,
+                'volume_characteristic',
+            ),
+            (
+                gatt.GATT_ASHA_LE_PSM_OUT_CHARACTERISTIC,
+                'psm_characteristic',
+            ),
+        ):
+            if not (
+                characteristics := self.service_proxy.get_characteristics_by_uuid(uuid)
+            ):
+                raise gatt.InvalidServiceError(f"Missing {uuid} Characteristic")
+            setattr(self, attribute_name, characteristics[0])
diff --git a/bumble/profiles/asha_service.py b/bumble/profiles/asha_service.py
deleted file mode 100644
index acbc47e..0000000
--- a/bumble/profiles/asha_service.py
+++ /dev/null
@@ -1,193 +0,0 @@
-# Copyright 2021-2022 Google LLC
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      https://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-
-# -----------------------------------------------------------------------------
-# Imports
-# -----------------------------------------------------------------------------
-import struct
-import logging
-from typing import List, Optional
-
-from bumble import l2cap
-from ..core import AdvertisingData
-from ..device import Device, Connection
-from ..gatt import (
-    GATT_ASHA_SERVICE,
-    GATT_ASHA_READ_ONLY_PROPERTIES_CHARACTERISTIC,
-    GATT_ASHA_AUDIO_CONTROL_POINT_CHARACTERISTIC,
-    GATT_ASHA_AUDIO_STATUS_CHARACTERISTIC,
-    GATT_ASHA_VOLUME_CHARACTERISTIC,
-    GATT_ASHA_LE_PSM_OUT_CHARACTERISTIC,
-    TemplateService,
-    Characteristic,
-    CharacteristicValue,
-)
-from ..utils import AsyncRunner
-
-# -----------------------------------------------------------------------------
-# Logging
-# -----------------------------------------------------------------------------
-logger = logging.getLogger(__name__)
-
-
-# -----------------------------------------------------------------------------
-class AshaService(TemplateService):
-    UUID = GATT_ASHA_SERVICE
-    OPCODE_START = 1
-    OPCODE_STOP = 2
-    OPCODE_STATUS = 3
-    PROTOCOL_VERSION = 0x01
-    RESERVED_FOR_FUTURE_USE = [00, 00]
-    FEATURE_MAP = [0x01]  # [LE CoC audio output streaming supported]
-    SUPPORTED_CODEC_ID = [0x02, 0x01]  # Codec IDs [G.722 at 16 kHz]
-    RENDER_DELAY = [00, 00]
-
-    def __init__(self, capability: int, hisyncid: List[int], device: Device, psm=0):
-        self.hisyncid = hisyncid
-        self.capability = capability  # Device Capabilities [Left, Monaural]
-        self.device = device
-        self.audio_out_data = b''
-        self.psm = psm  # a non-zero psm is mainly for testing purpose
-
-        # Handler for volume control
-        def on_volume_write(connection, value):
-            logger.info(f'--- VOLUME Write:{value[0]}')
-            self.emit('volume', connection, value[0])
-
-        # Handler for audio control commands
-        def on_audio_control_point_write(connection: Optional[Connection], value):
-            logger.info(f'--- AUDIO CONTROL POINT Write:{value.hex()}')
-            opcode = value[0]
-            if opcode == AshaService.OPCODE_START:
-                # Start
-                audio_type = ('Unknown', 'Ringtone', 'Phone Call', 'Media')[value[2]]
-                logger.info(
-                    f'### START: codec={value[1]}, '
-                    f'audio_type={audio_type}, '
-                    f'volume={value[3]}, '
-                    f'otherstate={value[4]}'
-                )
-                self.emit(
-                    'start',
-                    connection,
-                    {
-                        'codec': value[1],
-                        'audiotype': value[2],
-                        'volume': value[3],
-                        'otherstate': value[4],
-                    },
-                )
-            elif opcode == AshaService.OPCODE_STOP:
-                logger.info('### STOP')
-                self.emit('stop', connection)
-            elif opcode == AshaService.OPCODE_STATUS:
-                logger.info(f'### STATUS: connected={value[1]}')
-
-            # OPCODE_STATUS does not need audio status point update
-            if opcode != AshaService.OPCODE_STATUS:
-                AsyncRunner.spawn(
-                    device.notify_subscribers(
-                        self.audio_status_characteristic, force=True
-                    )
-                )
-
-        self.read_only_properties_characteristic = Characteristic(
-            GATT_ASHA_READ_ONLY_PROPERTIES_CHARACTERISTIC,
-            Characteristic.Properties.READ,
-            Characteristic.READABLE,
-            bytes(
-                [
-                    AshaService.PROTOCOL_VERSION,  # Version
-                    self.capability,
-                ]
-            )
-            + bytes(self.hisyncid)
-            + bytes(AshaService.FEATURE_MAP)
-            + bytes(AshaService.RENDER_DELAY)
-            + bytes(AshaService.RESERVED_FOR_FUTURE_USE)
-            + bytes(AshaService.SUPPORTED_CODEC_ID),
-        )
-
-        self.audio_control_point_characteristic = Characteristic(
-            GATT_ASHA_AUDIO_CONTROL_POINT_CHARACTERISTIC,
-            Characteristic.Properties.WRITE
-            | Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
-            Characteristic.WRITEABLE,
-            CharacteristicValue(write=on_audio_control_point_write),
-        )
-        self.audio_status_characteristic = Characteristic(
-            GATT_ASHA_AUDIO_STATUS_CHARACTERISTIC,
-            Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
-            Characteristic.READABLE,
-            bytes([0]),
-        )
-        self.volume_characteristic = Characteristic(
-            GATT_ASHA_VOLUME_CHARACTERISTIC,
-            Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
-            Characteristic.WRITEABLE,
-            CharacteristicValue(write=on_volume_write),
-        )
-
-        # Register an L2CAP CoC server
-        def on_coc(channel):
-            def on_data(data):
-                logging.debug(f'<<< data received:{data}')
-
-                self.emit('data', channel.connection, data)
-                self.audio_out_data += data
-
-            channel.sink = on_data
-
-        # let the server find a free PSM
-        self.psm = device.create_l2cap_server(
-            spec=l2cap.LeCreditBasedChannelSpec(psm=self.psm, max_credits=8),
-            handler=on_coc,
-        ).psm
-        self.le_psm_out_characteristic = Characteristic(
-            GATT_ASHA_LE_PSM_OUT_CHARACTERISTIC,
-            Characteristic.Properties.READ,
-            Characteristic.READABLE,
-            struct.pack('<H', self.psm),
-        )
-
-        characteristics = [
-            self.read_only_properties_characteristic,
-            self.audio_control_point_characteristic,
-            self.audio_status_characteristic,
-            self.volume_characteristic,
-            self.le_psm_out_characteristic,
-        ]
-
-        super().__init__(characteristics)
-
-    def get_advertising_data(self):
-        # Advertisement only uses 4 least significant bytes of the HiSyncId.
-        return bytes(
-            AdvertisingData(
-                [
-                    (
-                        AdvertisingData.SERVICE_DATA_16_BIT_UUID,
-                        bytes(GATT_ASHA_SERVICE)
-                        + bytes(
-                            [
-                                AshaService.PROTOCOL_VERSION,
-                                self.capability,
-                            ]
-                        )
-                        + bytes(self.hisyncid[:4]),
-                    ),
-                ]
-            )
-        )
diff --git a/bumble/profiles/bap.py b/bumble/profiles/bap.py
index c0123b1..8a00eaf 100644
--- a/bumble/profiles/bap.py
+++ b/bumble/profiles/bap.py
@@ -24,14 +24,14 @@ import enum
 import struct
 import functools
 import logging
-from typing import Optional, List, Union, Type, Dict, Any, Tuple
+from typing import List
+from typing_extensions import Self
 
 from bumble import core
-from bumble import colors
-from bumble import device
 from bumble import hci
 from bumble import gatt
-from bumble import gatt_client
+from bumble import utils
+from bumble.profiles import le_audio
 
 
 # -----------------------------------------------------------------------------
@@ -115,7 +115,7 @@ class ContextType(enum.IntFlag):
     EMERGENCY_ALARM  = 0x0800
 
 
-class SamplingFrequency(enum.IntEnum):
+class SamplingFrequency(utils.OpenIntEnum):
     '''Bluetooth Assigned Numbers, Section 6.12.5.1 - Sampling Frequency'''
 
     # fmt: off
@@ -240,7 +240,7 @@ class SupportedFrameDuration(enum.IntFlag):
     DURATION_10000_US_PREFERRED = 0b0010
 
 
-class AnnouncementType(enum.IntEnum):
+class AnnouncementType(utils.OpenIntEnum):
     '''Basic Audio Profile, 3.5.3. Additional Audio Stream Control Service requirements'''
 
     # fmt: off
@@ -248,231 +248,6 @@ class AnnouncementType(enum.IntEnum):
     TARGETED = 0x01
 
 
-# -----------------------------------------------------------------------------
-# ASE Operations
-# -----------------------------------------------------------------------------
-
-
-class ASE_Operation:
-    '''
-    See Audio Stream Control Service - 5 ASE Control operations.
-    '''
-
-    classes: Dict[int, Type[ASE_Operation]] = {}
-    op_code: int
-    name: str
-    fields: Optional[Sequence[Any]] = None
-    ase_id: List[int]
-
-    class Opcode(enum.IntEnum):
-        # fmt: off
-        CONFIG_CODEC         = 0x01
-        CONFIG_QOS           = 0x02
-        ENABLE               = 0x03
-        RECEIVER_START_READY = 0x04
-        DISABLE              = 0x05
-        RECEIVER_STOP_READY  = 0x06
-        UPDATE_METADATA      = 0x07
-        RELEASE              = 0x08
-
-    @staticmethod
-    def from_bytes(pdu: bytes) -> ASE_Operation:
-        op_code = pdu[0]
-
-        cls = ASE_Operation.classes.get(op_code)
-        if cls is None:
-            instance = ASE_Operation(pdu)
-            instance.name = ASE_Operation.Opcode(op_code).name
-            instance.op_code = op_code
-            return instance
-        self = cls.__new__(cls)
-        ASE_Operation.__init__(self, pdu)
-        if self.fields is not None:
-            self.init_from_bytes(pdu, 1)
-        return self
-
-    @staticmethod
-    def subclass(fields):
-        def inner(cls: Type[ASE_Operation]):
-            try:
-                operation = ASE_Operation.Opcode[cls.__name__[4:].upper()]
-                cls.name = operation.name
-                cls.op_code = operation
-            except:
-                raise KeyError(f'PDU name {cls.name} not found in Ase_Operation.Opcode')
-            cls.fields = fields
-
-            # Register a factory for this class
-            ASE_Operation.classes[cls.op_code] = cls
-
-            return cls
-
-        return inner
-
-    def __init__(self, pdu: Optional[bytes] = None, **kwargs) -> None:
-        if self.fields is not None and kwargs:
-            hci.HCI_Object.init_from_fields(self, self.fields, kwargs)
-        if pdu is None:
-            pdu = bytes([self.op_code]) + hci.HCI_Object.dict_to_bytes(
-                kwargs, self.fields
-            )
-        self.pdu = pdu
-
-    def init_from_bytes(self, pdu: bytes, offset: int):
-        return hci.HCI_Object.init_from_bytes(self, pdu, offset, self.fields)
-
-    def __bytes__(self) -> bytes:
-        return self.pdu
-
-    def __str__(self) -> str:
-        result = f'{colors.color(self.name, "yellow")} '
-        if fields := getattr(self, 'fields', None):
-            result += ':\n' + hci.HCI_Object.format_fields(self.__dict__, fields, '  ')
-        else:
-            if len(self.pdu) > 1:
-                result += f': {self.pdu.hex()}'
-        return result
-
-
-@ASE_Operation.subclass(
-    [
-        [
-            ('ase_id', 1),
-            ('target_latency', 1),
-            ('target_phy', 1),
-            ('codec_id', hci.CodingFormat.parse_from_bytes),
-            ('codec_specific_configuration', 'v'),
-        ],
-    ]
-)
-class ASE_Config_Codec(ASE_Operation):
-    '''
-    See Audio Stream Control Service 5.1 - Config Codec Operation
-    '''
-
-    target_latency: List[int]
-    target_phy: List[int]
-    codec_id: List[hci.CodingFormat]
-    codec_specific_configuration: List[bytes]
-
-
-@ASE_Operation.subclass(
-    [
-        [
-            ('ase_id', 1),
-            ('cig_id', 1),
-            ('cis_id', 1),
-            ('sdu_interval', 3),
-            ('framing', 1),
-            ('phy', 1),
-            ('max_sdu', 2),
-            ('retransmission_number', 1),
-            ('max_transport_latency', 2),
-            ('presentation_delay', 3),
-        ],
-    ]
-)
-class ASE_Config_QOS(ASE_Operation):
-    '''
-    See Audio Stream Control Service 5.2 - Config Qos Operation
-    '''
-
-    cig_id: List[int]
-    cis_id: List[int]
-    sdu_interval: List[int]
-    framing: List[int]
-    phy: List[int]
-    max_sdu: List[int]
-    retransmission_number: List[int]
-    max_transport_latency: List[int]
-    presentation_delay: List[int]
-
-
-@ASE_Operation.subclass([[('ase_id', 1), ('metadata', 'v')]])
-class ASE_Enable(ASE_Operation):
-    '''
-    See Audio Stream Control Service 5.3 - Enable Operation
-    '''
-
-    metadata: bytes
-
-
-@ASE_Operation.subclass([[('ase_id', 1)]])
-class ASE_Receiver_Start_Ready(ASE_Operation):
-    '''
-    See Audio Stream Control Service 5.4 - Receiver Start Ready Operation
-    '''
-
-
-@ASE_Operation.subclass([[('ase_id', 1)]])
-class ASE_Disable(ASE_Operation):
-    '''
-    See Audio Stream Control Service 5.5 - Disable Operation
-    '''
-
-
-@ASE_Operation.subclass([[('ase_id', 1)]])
-class ASE_Receiver_Stop_Ready(ASE_Operation):
-    '''
-    See Audio Stream Control Service 5.6 - Receiver Stop Ready Operation
-    '''
-
-
-@ASE_Operation.subclass([[('ase_id', 1), ('metadata', 'v')]])
-class ASE_Update_Metadata(ASE_Operation):
-    '''
-    See Audio Stream Control Service 5.7 - Update Metadata Operation
-    '''
-
-    metadata: List[bytes]
-
-
-@ASE_Operation.subclass([[('ase_id', 1)]])
-class ASE_Release(ASE_Operation):
-    '''
-    See Audio Stream Control Service 5.8 - Release Operation
-    '''
-
-
-class AseResponseCode(enum.IntEnum):
-    # fmt: off
-    SUCCESS                                     = 0x00
-    UNSUPPORTED_OPCODE                          = 0x01
-    INVALID_LENGTH                              = 0x02
-    INVALID_ASE_ID                              = 0x03
-    INVALID_ASE_STATE_MACHINE_TRANSITION        = 0x04
-    INVALID_ASE_DIRECTION                       = 0x05
-    UNSUPPORTED_AUDIO_CAPABILITIES              = 0x06
-    UNSUPPORTED_CONFIGURATION_PARAMETER_VALUE   = 0x07
-    REJECTED_CONFIGURATION_PARAMETER_VALUE      = 0x08
-    INVALID_CONFIGURATION_PARAMETER_VALUE       = 0x09
-    UNSUPPORTED_METADATA                        = 0x0A
-    REJECTED_METADATA                           = 0x0B
-    INVALID_METADATA                            = 0x0C
-    INSUFFICIENT_RESOURCES                      = 0x0D
-    UNSPECIFIED_ERROR                           = 0x0E
-
-
-class AseReasonCode(enum.IntEnum):
-    # fmt: off
-    NONE                            = 0x00
-    CODEC_ID                        = 0x01
-    CODEC_SPECIFIC_CONFIGURATION    = 0x02
-    SDU_INTERVAL                    = 0x03
-    FRAMING                         = 0x04
-    PHY                             = 0x05
-    MAXIMUM_SDU_SIZE                = 0x06
-    RETRANSMISSION_NUMBER           = 0x07
-    MAX_TRANSPORT_LATENCY           = 0x08
-    PRESENTATION_DELAY              = 0x09
-    INVALID_ASE_CIS_MAPPING         = 0x0A
-
-
-class AudioRole(enum.IntEnum):
-    SINK = hci.HCI_LE_Setup_ISO_Data_Path_Command.Direction.CONTROLLER_TO_HOST
-    SOURCE = hci.HCI_LE_Setup_ISO_Data_Path_Command.Direction.HOST_TO_CONTROLLER
-
-
 @dataclasses.dataclass
 class UnicastServerAdvertisingData:
     """Advertising Data for ASCS."""
@@ -613,7 +388,7 @@ class CodecSpecificConfiguration:
     * Basic Audio Profile, 4.3.2 - Codec_Specific_Capabilities LTV requirements
     '''
 
-    class Type(enum.IntEnum):
+    class Type(utils.OpenIntEnum):
         # fmt: off
         SAMPLING_FREQUENCY       = 0x01
         FRAME_DURATION           = 0x02
@@ -681,645 +456,93 @@ class CodecSpecificConfiguration:
 
 
 @dataclasses.dataclass
-class PacRecord:
-    coding_format: hci.CodingFormat
-    codec_specific_capabilities: Union[CodecSpecificCapabilities, bytes]
-    # TODO: Parse Metadata
-    metadata: bytes = b''
+class BroadcastAudioAnnouncement:
+    broadcast_id: int
 
     @classmethod
-    def from_bytes(cls, data: bytes) -> PacRecord:
-        offset, coding_format = hci.CodingFormat.parse_from_bytes(data, 0)
-        codec_specific_capabilities_size = data[offset]
-
-        offset += 1
-        codec_specific_capabilities_bytes = data[
-            offset : offset + codec_specific_capabilities_size
-        ]
-        offset += codec_specific_capabilities_size
-        metadata_size = data[offset]
-        metadata = data[offset : offset + metadata_size]
-
-        codec_specific_capabilities: Union[CodecSpecificCapabilities, bytes]
-        if coding_format.codec_id == hci.CodecID.VENDOR_SPECIFIC:
-            codec_specific_capabilities = codec_specific_capabilities_bytes
-        else:
-            codec_specific_capabilities = CodecSpecificCapabilities.from_bytes(
-                codec_specific_capabilities_bytes
-            )
-
-        return PacRecord(
-            coding_format=coding_format,
-            codec_specific_capabilities=codec_specific_capabilities,
-            metadata=metadata,
-        )
-
-    def __bytes__(self) -> bytes:
-        capabilities_bytes = bytes(self.codec_specific_capabilities)
-        return (
-            bytes(self.coding_format)
-            + bytes([len(capabilities_bytes)])
-            + capabilities_bytes
-            + bytes([len(self.metadata)])
-            + self.metadata
-        )
-
+    def from_bytes(cls, data: bytes) -> Self:
+        return cls(int.from_bytes(data[:3], 'little'))
 
-# -----------------------------------------------------------------------------
-# Server
-# -----------------------------------------------------------------------------
-class PublishedAudioCapabilitiesService(gatt.TemplateService):
-    UUID = gatt.GATT_PUBLISHED_AUDIO_CAPABILITIES_SERVICE
-
-    sink_pac: Optional[gatt.Characteristic]
-    sink_audio_locations: Optional[gatt.Characteristic]
-    source_pac: Optional[gatt.Characteristic]
-    source_audio_locations: Optional[gatt.Characteristic]
-    available_audio_contexts: gatt.Characteristic
-    supported_audio_contexts: gatt.Characteristic
-
-    def __init__(
-        self,
-        supported_source_context: ContextType,
-        supported_sink_context: ContextType,
-        available_source_context: ContextType,
-        available_sink_context: ContextType,
-        sink_pac: Sequence[PacRecord] = [],
-        sink_audio_locations: Optional[AudioLocation] = None,
-        source_pac: Sequence[PacRecord] = [],
-        source_audio_locations: Optional[AudioLocation] = None,
-    ) -> None:
-        characteristics = []
-
-        self.supported_audio_contexts = gatt.Characteristic(
-            uuid=gatt.GATT_SUPPORTED_AUDIO_CONTEXTS_CHARACTERISTIC,
-            properties=gatt.Characteristic.Properties.READ,
-            permissions=gatt.Characteristic.Permissions.READABLE,
-            value=struct.pack('<HH', supported_sink_context, supported_source_context),
-        )
-        characteristics.append(self.supported_audio_contexts)
-
-        self.available_audio_contexts = gatt.Characteristic(
-            uuid=gatt.GATT_AVAILABLE_AUDIO_CONTEXTS_CHARACTERISTIC,
-            properties=gatt.Characteristic.Properties.READ
-            | gatt.Characteristic.Properties.NOTIFY,
-            permissions=gatt.Characteristic.Permissions.READABLE,
-            value=struct.pack('<HH', available_sink_context, available_source_context),
-        )
-        characteristics.append(self.available_audio_contexts)
-
-        if sink_pac:
-            self.sink_pac = gatt.Characteristic(
-                uuid=gatt.GATT_SINK_PAC_CHARACTERISTIC,
-                properties=gatt.Characteristic.Properties.READ,
-                permissions=gatt.Characteristic.Permissions.READABLE,
-                value=bytes([len(sink_pac)]) + b''.join(map(bytes, sink_pac)),
-            )
-            characteristics.append(self.sink_pac)
-
-        if sink_audio_locations is not None:
-            self.sink_audio_locations = gatt.Characteristic(
-                uuid=gatt.GATT_SINK_AUDIO_LOCATION_CHARACTERISTIC,
-                properties=gatt.Characteristic.Properties.READ,
-                permissions=gatt.Characteristic.Permissions.READABLE,
-                value=struct.pack('<I', sink_audio_locations),
-            )
-            characteristics.append(self.sink_audio_locations)
-
-        if source_pac:
-            self.source_pac = gatt.Characteristic(
-                uuid=gatt.GATT_SOURCE_PAC_CHARACTERISTIC,
-                properties=gatt.Characteristic.Properties.READ,
-                permissions=gatt.Characteristic.Permissions.READABLE,
-                value=bytes([len(source_pac)]) + b''.join(map(bytes, source_pac)),
-            )
-            characteristics.append(self.source_pac)
-
-        if source_audio_locations is not None:
-            self.source_audio_locations = gatt.Characteristic(
-                uuid=gatt.GATT_SOURCE_AUDIO_LOCATION_CHARACTERISTIC,
-                properties=gatt.Characteristic.Properties.READ,
-                permissions=gatt.Characteristic.Permissions.READABLE,
-                value=struct.pack('<I', source_audio_locations),
-            )
-            characteristics.append(self.source_audio_locations)
 
-        super().__init__(characteristics)
-
-
-class AseStateMachine(gatt.Characteristic):
-    class State(enum.IntEnum):
-        # fmt: off
-        IDLE             = 0x00
-        CODEC_CONFIGURED = 0x01
-        QOS_CONFIGURED   = 0x02
-        ENABLING         = 0x03
-        STREAMING        = 0x04
-        DISABLING        = 0x05
-        RELEASING        = 0x06
-
-    cis_link: Optional[device.CisLink] = None
-
-    # Additional parameters in CODEC_CONFIGURED State
-    preferred_framing = 0  # Unframed PDU supported
-    preferred_phy = 0
-    preferred_retransmission_number = 13
-    preferred_max_transport_latency = 100
-    supported_presentation_delay_min = 0
-    supported_presentation_delay_max = 0
-    preferred_presentation_delay_min = 0
-    preferred_presentation_delay_max = 0
-    codec_id = hci.CodingFormat(hci.CodecID.LC3)
-    codec_specific_configuration: Union[CodecSpecificConfiguration, bytes] = b''
-
-    # Additional parameters in QOS_CONFIGURED State
-    cig_id = 0
-    cis_id = 0
-    sdu_interval = 0
-    framing = 0
-    phy = 0
-    max_sdu = 0
-    retransmission_number = 0
-    max_transport_latency = 0
-    presentation_delay = 0
-
-    # Additional parameters in ENABLING, STREAMING, DISABLING State
-    # TODO: Parse this
-    metadata = b''
-
-    def __init__(
-        self,
-        role: AudioRole,
-        ase_id: int,
-        service: AudioStreamControlService,
-    ) -> None:
-        self.service = service
-        self.ase_id = ase_id
-        self._state = AseStateMachine.State.IDLE
-        self.role = role
-
-        uuid = (
-            gatt.GATT_SINK_ASE_CHARACTERISTIC
-            if role == AudioRole.SINK
-            else gatt.GATT_SOURCE_ASE_CHARACTERISTIC
-        )
-        super().__init__(
-            uuid=uuid,
-            properties=gatt.Characteristic.Properties.READ
-            | gatt.Characteristic.Properties.NOTIFY,
-            permissions=gatt.Characteristic.Permissions.READABLE,
-            value=gatt.CharacteristicValue(read=self.on_read),
-        )
+@dataclasses.dataclass
+class BasicAudioAnnouncement:
+    @dataclasses.dataclass
+    class BIS:
+        index: int
+        codec_specific_configuration: CodecSpecificConfiguration
+
+    @dataclasses.dataclass
+    class CodecInfo:
+        coding_format: hci.CodecID
+        company_id: int
+        vendor_specific_codec_id: int
+
+        @classmethod
+        def from_bytes(cls, data: bytes) -> Self:
+            coding_format = hci.CodecID(data[0])
+            company_id = int.from_bytes(data[1:3], 'little')
+            vendor_specific_codec_id = int.from_bytes(data[3:5], 'little')
+            return cls(coding_format, company_id, vendor_specific_codec_id)
+
+    @dataclasses.dataclass
+    class Subgroup:
+        codec_id: BasicAudioAnnouncement.CodecInfo
+        codec_specific_configuration: CodecSpecificConfiguration
+        metadata: le_audio.Metadata
+        bis: List[BasicAudioAnnouncement.BIS]
+
+    presentation_delay: int
+    subgroups: List[BasicAudioAnnouncement.Subgroup]
 
-        self.service.device.on('cis_request', self.on_cis_request)
-        self.service.device.on('cis_establishment', self.on_cis_establishment)
-
-    def on_cis_request(
-        self,
-        acl_connection: device.Connection,
-        cis_handle: int,
-        cig_id: int,
-        cis_id: int,
-    ) -> None:
-        if (
-            cig_id == self.cig_id
-            and cis_id == self.cis_id
-            and self.state == self.State.ENABLING
-        ):
-            acl_connection.abort_on(
-                'flush', self.service.device.accept_cis_request(cis_handle)
+    @classmethod
+    def from_bytes(cls, data: bytes) -> Self:
+        presentation_delay = int.from_bytes(data[:3], 'little')
+        subgroups = []
+        offset = 4
+        for _ in range(data[3]):
+            num_bis = data[offset]
+            offset += 1
+            codec_id = cls.CodecInfo.from_bytes(data[offset : offset + 5])
+            offset += 5
+            codec_specific_configuration_length = data[offset]
+            offset += 1
+            codec_specific_configuration = data[
+                offset : offset + codec_specific_configuration_length
+            ]
+            offset += codec_specific_configuration_length
+            metadata_length = data[offset]
+            offset += 1
+            metadata = le_audio.Metadata.from_bytes(
+                data[offset : offset + metadata_length]
             )
-
-    def on_cis_establishment(self, cis_link: device.CisLink) -> None:
-        if (
-            cis_link.cig_id == self.cig_id
-            and cis_link.cis_id == self.cis_id
-            and self.state == self.State.ENABLING
-        ):
-            cis_link.on('disconnection', self.on_cis_disconnection)
-
-            async def post_cis_established():
-                await self.service.device.send_command(
-                    hci.HCI_LE_Setup_ISO_Data_Path_Command(
-                        connection_handle=cis_link.handle,
-                        data_path_direction=self.role,
-                        data_path_id=0x00,  # Fixed HCI
-                        codec_id=hci.CodingFormat(hci.CodecID.TRANSPARENT),
-                        controller_delay=0,
-                        codec_configuration=b'',
+            offset += metadata_length
+
+            bis = []
+            for _ in range(num_bis):
+                bis_index = data[offset]
+                offset += 1
+                bis_codec_specific_configuration_length = data[offset]
+                offset += 1
+                bis_codec_specific_configuration = data[
+                    offset : offset + bis_codec_specific_configuration_length
+                ]
+                offset += bis_codec_specific_configuration_length
+                bis.append(
+                    cls.BIS(
+                        bis_index,
+                        CodecSpecificConfiguration.from_bytes(
+                            bis_codec_specific_configuration
+                        ),
                     )
                 )
-                if self.role == AudioRole.SINK:
-                    self.state = self.State.STREAMING
-                await self.service.device.notify_subscribers(self, self.value)
-
-            cis_link.acl_connection.abort_on('flush', post_cis_established())
-            self.cis_link = cis_link
-
-    def on_cis_disconnection(self, _reason) -> None:
-        self.cis_link = None
-
-    def on_config_codec(
-        self,
-        target_latency: int,
-        target_phy: int,
-        codec_id: hci.CodingFormat,
-        codec_specific_configuration: bytes,
-    ) -> Tuple[AseResponseCode, AseReasonCode]:
-        if self.state not in (
-            self.State.IDLE,
-            self.State.CODEC_CONFIGURED,
-            self.State.QOS_CONFIGURED,
-        ):
-            return (
-                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
-                AseReasonCode.NONE,
-            )
-
-        self.max_transport_latency = target_latency
-        self.phy = target_phy
-        self.codec_id = codec_id
-        if codec_id.codec_id == hci.CodecID.VENDOR_SPECIFIC:
-            self.codec_specific_configuration = codec_specific_configuration
-        else:
-            self.codec_specific_configuration = CodecSpecificConfiguration.from_bytes(
-                codec_specific_configuration
-            )
-
-        self.state = self.State.CODEC_CONFIGURED
-
-        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
-
-    def on_config_qos(
-        self,
-        cig_id: int,
-        cis_id: int,
-        sdu_interval: int,
-        framing: int,
-        phy: int,
-        max_sdu: int,
-        retransmission_number: int,
-        max_transport_latency: int,
-        presentation_delay: int,
-    ) -> Tuple[AseResponseCode, AseReasonCode]:
-        if self.state not in (
-            AseStateMachine.State.CODEC_CONFIGURED,
-            AseStateMachine.State.QOS_CONFIGURED,
-        ):
-            return (
-                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
-                AseReasonCode.NONE,
-            )
-
-        self.cig_id = cig_id
-        self.cis_id = cis_id
-        self.sdu_interval = sdu_interval
-        self.framing = framing
-        self.phy = phy
-        self.max_sdu = max_sdu
-        self.retransmission_number = retransmission_number
-        self.max_transport_latency = max_transport_latency
-        self.presentation_delay = presentation_delay
-
-        self.state = self.State.QOS_CONFIGURED
-
-        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
-
-    def on_enable(self, metadata: bytes) -> Tuple[AseResponseCode, AseReasonCode]:
-        if self.state != AseStateMachine.State.QOS_CONFIGURED:
-            return (
-                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
-                AseReasonCode.NONE,
-            )
-
-        self.metadata = metadata
-        self.state = self.State.ENABLING
-
-        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
-
-    def on_receiver_start_ready(self) -> Tuple[AseResponseCode, AseReasonCode]:
-        if self.state != AseStateMachine.State.ENABLING:
-            return (
-                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
-                AseReasonCode.NONE,
-            )
-        self.state = self.State.STREAMING
-        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
-
-    def on_disable(self) -> Tuple[AseResponseCode, AseReasonCode]:
-        if self.state not in (
-            AseStateMachine.State.ENABLING,
-            AseStateMachine.State.STREAMING,
-        ):
-            return (
-                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
-                AseReasonCode.NONE,
-            )
-        if self.role == AudioRole.SINK:
-            self.state = self.State.QOS_CONFIGURED
-        else:
-            self.state = self.State.DISABLING
-        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
-
-    def on_receiver_stop_ready(self) -> Tuple[AseResponseCode, AseReasonCode]:
-        if (
-            self.role != AudioRole.SOURCE
-            or self.state != AseStateMachine.State.DISABLING
-        ):
-            return (
-                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
-                AseReasonCode.NONE,
-            )
-        self.state = self.State.QOS_CONFIGURED
-        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
-
-    def on_update_metadata(
-        self, metadata: bytes
-    ) -> Tuple[AseResponseCode, AseReasonCode]:
-        if self.state not in (
-            AseStateMachine.State.ENABLING,
-            AseStateMachine.State.STREAMING,
-        ):
-            return (
-                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
-                AseReasonCode.NONE,
-            )
-        self.metadata = metadata
-        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
-
-    def on_release(self) -> Tuple[AseResponseCode, AseReasonCode]:
-        if self.state == AseStateMachine.State.IDLE:
-            return (
-                AseResponseCode.INVALID_ASE_STATE_MACHINE_TRANSITION,
-                AseReasonCode.NONE,
-            )
-        self.state = self.State.RELEASING
-
-        async def remove_cis_async():
-            await self.service.device.send_command(
-                hci.HCI_LE_Remove_ISO_Data_Path_Command(
-                    connection_handle=self.cis_link.handle,
-                    data_path_direction=self.role,
-                )
-            )
-            self.state = self.State.IDLE
-            await self.service.device.notify_subscribers(self, self.value)
-
-        self.service.device.abort_on('flush', remove_cis_async())
-        return (AseResponseCode.SUCCESS, AseReasonCode.NONE)
-
-    @property
-    def state(self) -> State:
-        return self._state
-
-    @state.setter
-    def state(self, new_state: State) -> None:
-        logger.debug(f'{self} state change -> {colors.color(new_state.name, "cyan")}')
-        self._state = new_state
-        self.emit('state_change')
 
-    @property
-    def value(self):
-        '''Returns ASE_ID, ASE_STATE, and ASE Additional Parameters.'''
-
-        if self.state == self.State.CODEC_CONFIGURED:
-            codec_specific_configuration_bytes = bytes(
-                self.codec_specific_configuration
-            )
-            additional_parameters = (
-                struct.pack(
-                    '<BBBH',
-                    self.preferred_framing,
-                    self.preferred_phy,
-                    self.preferred_retransmission_number,
-                    self.preferred_max_transport_latency,
-                )
-                + self.supported_presentation_delay_min.to_bytes(3, 'little')
-                + self.supported_presentation_delay_max.to_bytes(3, 'little')
-                + self.preferred_presentation_delay_min.to_bytes(3, 'little')
-                + self.preferred_presentation_delay_max.to_bytes(3, 'little')
-                + bytes(self.codec_id)
-                + bytes([len(codec_specific_configuration_bytes)])
-                + codec_specific_configuration_bytes
-            )
-        elif self.state == self.State.QOS_CONFIGURED:
-            additional_parameters = (
-                bytes([self.cig_id, self.cis_id])
-                + self.sdu_interval.to_bytes(3, 'little')
-                + struct.pack(
-                    '<BBHBH',
-                    self.framing,
-                    self.phy,
-                    self.max_sdu,
-                    self.retransmission_number,
-                    self.max_transport_latency,
+            subgroups.append(
+                cls.Subgroup(
+                    codec_id,
+                    CodecSpecificConfiguration.from_bytes(codec_specific_configuration),
+                    metadata,
+                    bis,
                 )
-                + self.presentation_delay.to_bytes(3, 'little')
-            )
-        elif self.state in (
-            self.State.ENABLING,
-            self.State.STREAMING,
-            self.State.DISABLING,
-        ):
-            additional_parameters = (
-                bytes([self.cig_id, self.cis_id, len(self.metadata)]) + self.metadata
             )
-        else:
-            additional_parameters = b''
-
-        return bytes([self.ase_id, self.state]) + additional_parameters
-
-    @value.setter
-    def value(self, _new_value):
-        # Readonly. Do nothing in the setter.
-        pass
 
-    def on_read(self, _: Optional[device.Connection]) -> bytes:
-        return self.value
-
-    def __str__(self) -> str:
-        return (
-            f'AseStateMachine(id={self.ase_id}, role={self.role.name} '
-            f'state={self._state.name})'
-        )
-
-
-class AudioStreamControlService(gatt.TemplateService):
-    UUID = gatt.GATT_AUDIO_STREAM_CONTROL_SERVICE
-
-    ase_state_machines: Dict[int, AseStateMachine]
-    ase_control_point: gatt.Characteristic
-    _active_client: Optional[device.Connection] = None
-
-    def __init__(
-        self,
-        device: device.Device,
-        source_ase_id: Sequence[int] = [],
-        sink_ase_id: Sequence[int] = [],
-    ) -> None:
-        self.device = device
-        self.ase_state_machines = {
-            **{
-                id: AseStateMachine(role=AudioRole.SINK, ase_id=id, service=self)
-                for id in sink_ase_id
-            },
-            **{
-                id: AseStateMachine(role=AudioRole.SOURCE, ase_id=id, service=self)
-                for id in source_ase_id
-            },
-        }  # ASE state machines, by ASE ID
-
-        self.ase_control_point = gatt.Characteristic(
-            uuid=gatt.GATT_ASE_CONTROL_POINT_CHARACTERISTIC,
-            properties=gatt.Characteristic.Properties.WRITE
-            | gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE
-            | gatt.Characteristic.Properties.NOTIFY,
-            permissions=gatt.Characteristic.Permissions.WRITEABLE,
-            value=gatt.CharacteristicValue(write=self.on_write_ase_control_point),
-        )
-
-        super().__init__([self.ase_control_point, *self.ase_state_machines.values()])
-
-    def on_operation(self, opcode: ASE_Operation.Opcode, ase_id: int, args):
-        if ase := self.ase_state_machines.get(ase_id):
-            handler = getattr(ase, 'on_' + opcode.name.lower())
-            return (ase_id, *handler(*args))
-        else:
-            return (ase_id, AseResponseCode.INVALID_ASE_ID, AseReasonCode.NONE)
-
-    def _on_client_disconnected(self, _reason: int) -> None:
-        for ase in self.ase_state_machines.values():
-            ase.state = AseStateMachine.State.IDLE
-        self._active_client = None
-
-    def on_write_ase_control_point(self, connection, data):
-        if not self._active_client and connection:
-            self._active_client = connection
-            connection.once('disconnection', self._on_client_disconnected)
-
-        operation = ASE_Operation.from_bytes(data)
-        responses = []
-        logger.debug(f'*** ASCS Write {operation} ***')
-
-        if operation.op_code == ASE_Operation.Opcode.CONFIG_CODEC:
-            for ase_id, *args in zip(
-                operation.ase_id,
-                operation.target_latency,
-                operation.target_phy,
-                operation.codec_id,
-                operation.codec_specific_configuration,
-            ):
-                responses.append(self.on_operation(operation.op_code, ase_id, args))
-        elif operation.op_code == ASE_Operation.Opcode.CONFIG_QOS:
-            for ase_id, *args in zip(
-                operation.ase_id,
-                operation.cig_id,
-                operation.cis_id,
-                operation.sdu_interval,
-                operation.framing,
-                operation.phy,
-                operation.max_sdu,
-                operation.retransmission_number,
-                operation.max_transport_latency,
-                operation.presentation_delay,
-            ):
-                responses.append(self.on_operation(operation.op_code, ase_id, args))
-        elif operation.op_code in (
-            ASE_Operation.Opcode.ENABLE,
-            ASE_Operation.Opcode.UPDATE_METADATA,
-        ):
-            for ase_id, *args in zip(
-                operation.ase_id,
-                operation.metadata,
-            ):
-                responses.append(self.on_operation(operation.op_code, ase_id, args))
-        elif operation.op_code in (
-            ASE_Operation.Opcode.RECEIVER_START_READY,
-            ASE_Operation.Opcode.DISABLE,
-            ASE_Operation.Opcode.RECEIVER_STOP_READY,
-            ASE_Operation.Opcode.RELEASE,
-        ):
-            for ase_id in operation.ase_id:
-                responses.append(self.on_operation(operation.op_code, ase_id, []))
-
-        control_point_notification = bytes(
-            [operation.op_code, len(responses)]
-        ) + b''.join(map(bytes, responses))
-        self.device.abort_on(
-            'flush',
-            self.device.notify_subscribers(
-                self.ase_control_point, control_point_notification
-            ),
-        )
-
-        for ase_id, *_ in responses:
-            if ase := self.ase_state_machines.get(ase_id):
-                self.device.abort_on(
-                    'flush',
-                    self.device.notify_subscribers(ase, ase.value),
-                )
-
-
-# -----------------------------------------------------------------------------
-# Client
-# -----------------------------------------------------------------------------
-class PublishedAudioCapabilitiesServiceProxy(gatt_client.ProfileServiceProxy):
-    SERVICE_CLASS = PublishedAudioCapabilitiesService
-
-    sink_pac: Optional[gatt_client.CharacteristicProxy] = None
-    sink_audio_locations: Optional[gatt_client.CharacteristicProxy] = None
-    source_pac: Optional[gatt_client.CharacteristicProxy] = None
-    source_audio_locations: Optional[gatt_client.CharacteristicProxy] = None
-    available_audio_contexts: gatt_client.CharacteristicProxy
-    supported_audio_contexts: gatt_client.CharacteristicProxy
-
-    def __init__(self, service_proxy: gatt_client.ServiceProxy):
-        self.service_proxy = service_proxy
-
-        self.available_audio_contexts = service_proxy.get_characteristics_by_uuid(
-            gatt.GATT_AVAILABLE_AUDIO_CONTEXTS_CHARACTERISTIC
-        )[0]
-        self.supported_audio_contexts = service_proxy.get_characteristics_by_uuid(
-            gatt.GATT_SUPPORTED_AUDIO_CONTEXTS_CHARACTERISTIC
-        )[0]
-
-        if characteristics := service_proxy.get_characteristics_by_uuid(
-            gatt.GATT_SINK_PAC_CHARACTERISTIC
-        ):
-            self.sink_pac = characteristics[0]
-
-        if characteristics := service_proxy.get_characteristics_by_uuid(
-            gatt.GATT_SOURCE_PAC_CHARACTERISTIC
-        ):
-            self.source_pac = characteristics[0]
-
-        if characteristics := service_proxy.get_characteristics_by_uuid(
-            gatt.GATT_SINK_AUDIO_LOCATION_CHARACTERISTIC
-        ):
-            self.sink_audio_locations = characteristics[0]
-
-        if characteristics := service_proxy.get_characteristics_by_uuid(
-            gatt.GATT_SOURCE_AUDIO_LOCATION_CHARACTERISTIC
-        ):
-            self.source_audio_locations = characteristics[0]
-
-
-class AudioStreamControlServiceProxy(gatt_client.ProfileServiceProxy):
-    SERVICE_CLASS = AudioStreamControlService
-
-    sink_ase: List[gatt_client.CharacteristicProxy]
-    source_ase: List[gatt_client.CharacteristicProxy]
-    ase_control_point: gatt_client.CharacteristicProxy
-
-    def __init__(self, service_proxy: gatt_client.ServiceProxy):
-        self.service_proxy = service_proxy
-
-        self.sink_ase = service_proxy.get_characteristics_by_uuid(
-            gatt.GATT_SINK_ASE_CHARACTERISTIC
-        )
-        self.source_ase = service_proxy.get_characteristics_by_uuid(
-            gatt.GATT_SOURCE_ASE_CHARACTERISTIC
-        )
-        self.ase_control_point = service_proxy.get_characteristics_by_uuid(
-            gatt.GATT_ASE_CONTROL_POINT_CHARACTERISTIC
-        )[0]
+        return cls(presentation_delay, subgroups)
diff --git a/bumble/profiles/bass.py b/bumble/profiles/bass.py
new file mode 100644
index 0000000..57531db
--- /dev/null
+++ b/bumble/profiles/bass.py
@@ -0,0 +1,440 @@
+# Copyright 2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for
+
+"""LE Audio - Broadcast Audio Scan Service"""
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+from __future__ import annotations
+import dataclasses
+import logging
+import struct
+from typing import ClassVar, List, Optional, Sequence
+
+from bumble import core
+from bumble import device
+from bumble import gatt
+from bumble import gatt_client
+from bumble import hci
+from bumble import utils
+
+# -----------------------------------------------------------------------------
+# Logging
+# -----------------------------------------------------------------------------
+logger = logging.getLogger(__name__)
+
+
+# -----------------------------------------------------------------------------
+# Constants
+# -----------------------------------------------------------------------------
+class ApplicationError(utils.OpenIntEnum):
+    OPCODE_NOT_SUPPORTED = 0x80
+    INVALID_SOURCE_ID = 0x81
+
+
+# -----------------------------------------------------------------------------
+def encode_subgroups(subgroups: Sequence[SubgroupInfo]) -> bytes:
+    return bytes([len(subgroups)]) + b"".join(
+        struct.pack("<IB", subgroup.bis_sync, len(subgroup.metadata))
+        + subgroup.metadata
+        for subgroup in subgroups
+    )
+
+
+def decode_subgroups(data: bytes) -> List[SubgroupInfo]:
+    num_subgroups = data[0]
+    offset = 1
+    subgroups = []
+    for _ in range(num_subgroups):
+        bis_sync = struct.unpack("<I", data[offset : offset + 4])[0]
+        metadata_length = data[offset + 4]
+        metadata = data[offset + 5 : offset + 5 + metadata_length]
+        offset += 5 + metadata_length
+        subgroups.append(SubgroupInfo(bis_sync, metadata))
+
+    return subgroups
+
+
+# -----------------------------------------------------------------------------
+class PeriodicAdvertisingSyncParams(utils.OpenIntEnum):
+    DO_NOT_SYNCHRONIZE_TO_PA = 0x00
+    SYNCHRONIZE_TO_PA_PAST_AVAILABLE = 0x01
+    SYNCHRONIZE_TO_PA_PAST_NOT_AVAILABLE = 0x02
+
+
+@dataclasses.dataclass
+class SubgroupInfo:
+    ANY_BIS: ClassVar[int] = 0xFFFFFFFF
+
+    bis_sync: int
+    metadata: bytes
+
+
+class ControlPointOperation:
+    class OpCode(utils.OpenIntEnum):
+        REMOTE_SCAN_STOPPED = 0x00
+        REMOTE_SCAN_STARTED = 0x01
+        ADD_SOURCE = 0x02
+        MODIFY_SOURCE = 0x03
+        SET_BROADCAST_CODE = 0x04
+        REMOVE_SOURCE = 0x05
+
+    op_code: OpCode
+    parameters: bytes
+
+    @classmethod
+    def from_bytes(cls, data: bytes) -> ControlPointOperation:
+        op_code = data[0]
+
+        if op_code == cls.OpCode.REMOTE_SCAN_STOPPED:
+            return RemoteScanStoppedOperation()
+
+        if op_code == cls.OpCode.REMOTE_SCAN_STARTED:
+            return RemoteScanStartedOperation()
+
+        if op_code == cls.OpCode.ADD_SOURCE:
+            return AddSourceOperation.from_parameters(data[1:])
+
+        if op_code == cls.OpCode.MODIFY_SOURCE:
+            return ModifySourceOperation.from_parameters(data[1:])
+
+        if op_code == cls.OpCode.SET_BROADCAST_CODE:
+            return SetBroadcastCodeOperation.from_parameters(data[1:])
+
+        if op_code == cls.OpCode.REMOVE_SOURCE:
+            return RemoveSourceOperation.from_parameters(data[1:])
+
+        raise core.InvalidArgumentError("invalid op code")
+
+    def __init__(self, op_code: OpCode, parameters: bytes = b"") -> None:
+        self.op_code = op_code
+        self.parameters = parameters
+
+    def __bytes__(self) -> bytes:
+        return bytes([self.op_code]) + self.parameters
+
+
+class RemoteScanStoppedOperation(ControlPointOperation):
+    def __init__(self) -> None:
+        super().__init__(ControlPointOperation.OpCode.REMOTE_SCAN_STOPPED)
+
+
+class RemoteScanStartedOperation(ControlPointOperation):
+    def __init__(self) -> None:
+        super().__init__(ControlPointOperation.OpCode.REMOTE_SCAN_STARTED)
+
+
+class AddSourceOperation(ControlPointOperation):
+    @classmethod
+    def from_parameters(cls, parameters: bytes) -> AddSourceOperation:
+        instance = cls.__new__(cls)
+        instance.op_code = ControlPointOperation.OpCode.ADD_SOURCE
+        instance.parameters = parameters
+        instance.advertiser_address = hci.Address.parse_address_preceded_by_type(
+            parameters, 1
+        )[1]
+        instance.advertising_sid = parameters[7]
+        instance.broadcast_id = int.from_bytes(parameters[8:11], "little")
+        instance.pa_sync = PeriodicAdvertisingSyncParams(parameters[11])
+        instance.pa_interval = struct.unpack("<H", parameters[12:14])[0]
+        instance.subgroups = decode_subgroups(parameters[14:])
+        return instance
+
+    def __init__(
+        self,
+        advertiser_address: hci.Address,
+        advertising_sid: int,
+        broadcast_id: int,
+        pa_sync: PeriodicAdvertisingSyncParams,
+        pa_interval: int,
+        subgroups: Sequence[SubgroupInfo],
+    ) -> None:
+        super().__init__(
+            ControlPointOperation.OpCode.ADD_SOURCE,
+            struct.pack(
+                "<B6sB3sBH",
+                advertiser_address.address_type,
+                bytes(advertiser_address),
+                advertising_sid,
+                broadcast_id.to_bytes(3, "little"),
+                pa_sync,
+                pa_interval,
+            )
+            + encode_subgroups(subgroups),
+        )
+        self.advertiser_address = advertiser_address
+        self.advertising_sid = advertising_sid
+        self.broadcast_id = broadcast_id
+        self.pa_sync = pa_sync
+        self.pa_interval = pa_interval
+        self.subgroups = list(subgroups)
+
+
+class ModifySourceOperation(ControlPointOperation):
+    @classmethod
+    def from_parameters(cls, parameters: bytes) -> ModifySourceOperation:
+        instance = cls.__new__(cls)
+        instance.op_code = ControlPointOperation.OpCode.MODIFY_SOURCE
+        instance.parameters = parameters
+        instance.source_id = parameters[0]
+        instance.pa_sync = PeriodicAdvertisingSyncParams(parameters[1])
+        instance.pa_interval = struct.unpack("<H", parameters[2:4])[0]
+        instance.subgroups = decode_subgroups(parameters[4:])
+        return instance
+
+    def __init__(
+        self,
+        source_id: int,
+        pa_sync: PeriodicAdvertisingSyncParams,
+        pa_interval: int,
+        subgroups: Sequence[SubgroupInfo],
+    ) -> None:
+        super().__init__(
+            ControlPointOperation.OpCode.MODIFY_SOURCE,
+            struct.pack("<BBH", source_id, pa_sync, pa_interval)
+            + encode_subgroups(subgroups),
+        )
+        self.source_id = source_id
+        self.pa_sync = pa_sync
+        self.pa_interval = pa_interval
+        self.subgroups = list(subgroups)
+
+
+class SetBroadcastCodeOperation(ControlPointOperation):
+    @classmethod
+    def from_parameters(cls, parameters: bytes) -> SetBroadcastCodeOperation:
+        instance = cls.__new__(cls)
+        instance.op_code = ControlPointOperation.OpCode.SET_BROADCAST_CODE
+        instance.parameters = parameters
+        instance.source_id = parameters[0]
+        instance.broadcast_code = parameters[1:17]
+        return instance
+
+    def __init__(
+        self,
+        source_id: int,
+        broadcast_code: bytes,
+    ) -> None:
+        super().__init__(
+            ControlPointOperation.OpCode.SET_BROADCAST_CODE,
+            bytes([source_id]) + broadcast_code,
+        )
+        self.source_id = source_id
+        self.broadcast_code = broadcast_code
+
+        if len(self.broadcast_code) != 16:
+            raise core.InvalidArgumentError("broadcast_code must be 16 bytes")
+
+
+class RemoveSourceOperation(ControlPointOperation):
+    @classmethod
+    def from_parameters(cls, parameters: bytes) -> RemoveSourceOperation:
+        instance = cls.__new__(cls)
+        instance.op_code = ControlPointOperation.OpCode.REMOVE_SOURCE
+        instance.parameters = parameters
+        instance.source_id = parameters[0]
+        return instance
+
+    def __init__(self, source_id: int) -> None:
+        super().__init__(ControlPointOperation.OpCode.REMOVE_SOURCE, bytes([source_id]))
+        self.source_id = source_id
+
+
+@dataclasses.dataclass
+class BroadcastReceiveState:
+    class PeriodicAdvertisingSyncState(utils.OpenIntEnum):
+        NOT_SYNCHRONIZED_TO_PA = 0x00
+        SYNCINFO_REQUEST = 0x01
+        SYNCHRONIZED_TO_PA = 0x02
+        FAILED_TO_SYNCHRONIZE_TO_PA = 0x03
+        NO_PAST = 0x04
+
+    class BigEncryption(utils.OpenIntEnum):
+        NOT_ENCRYPTED = 0x00
+        BROADCAST_CODE_REQUIRED = 0x01
+        DECRYPTING = 0x02
+        BAD_CODE = 0x03
+
+    source_id: int
+    source_address: hci.Address
+    source_adv_sid: int
+    broadcast_id: int
+    pa_sync_state: PeriodicAdvertisingSyncState
+    big_encryption: BigEncryption
+    bad_code: bytes
+    subgroups: List[SubgroupInfo]
+
+    @classmethod
+    def from_bytes(cls, data: bytes) -> Optional[BroadcastReceiveState]:
+        if not data:
+            return None
+
+        source_id = data[0]
+        _, source_address = hci.Address.parse_address_preceded_by_type(data, 2)
+        source_adv_sid = data[8]
+        broadcast_id = int.from_bytes(data[9:12], "little")
+        pa_sync_state = cls.PeriodicAdvertisingSyncState(data[12])
+        big_encryption = cls.BigEncryption(data[13])
+        if big_encryption == cls.BigEncryption.BAD_CODE:
+            bad_code = data[14:30]
+            subgroups = decode_subgroups(data[30:])
+        else:
+            bad_code = b""
+            subgroups = decode_subgroups(data[14:])
+
+        return cls(
+            source_id,
+            source_address,
+            source_adv_sid,
+            broadcast_id,
+            pa_sync_state,
+            big_encryption,
+            bad_code,
+            subgroups,
+        )
+
+    def __bytes__(self) -> bytes:
+        return (
+            struct.pack(
+                "<BB6sB3sBB",
+                self.source_id,
+                self.source_address.address_type,
+                bytes(self.source_address),
+                self.source_adv_sid,
+                self.broadcast_id.to_bytes(3, "little"),
+                self.pa_sync_state,
+                self.big_encryption,
+            )
+            + self.bad_code
+            + encode_subgroups(self.subgroups)
+        )
+
+
+# -----------------------------------------------------------------------------
+class BroadcastAudioScanService(gatt.TemplateService):
+    UUID = gatt.GATT_BROADCAST_AUDIO_SCAN_SERVICE
+
+    def __init__(self):
+        self.broadcast_audio_scan_control_point_characteristic = gatt.Characteristic(
+            gatt.GATT_BROADCAST_AUDIO_SCAN_CONTROL_POINT_CHARACTERISTIC,
+            gatt.Characteristic.Properties.WRITE
+            | gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE,
+            gatt.Characteristic.WRITEABLE,
+            gatt.CharacteristicValue(
+                write=self.on_broadcast_audio_scan_control_point_write
+            ),
+        )
+
+        self.broadcast_receive_state_characteristic = gatt.Characteristic(
+            gatt.GATT_BROADCAST_RECEIVE_STATE_CHARACTERISTIC,
+            gatt.Characteristic.Properties.READ | gatt.Characteristic.Properties.NOTIFY,
+            gatt.Characteristic.Permissions.READABLE
+            | gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
+            b"12",  # TEST
+        )
+
+        super().__init__([self.battery_level_characteristic])
+
+    def on_broadcast_audio_scan_control_point_write(
+        self, connection: device.Connection, value: bytes
+    ) -> None:
+        pass
+
+
+# -----------------------------------------------------------------------------
+class BroadcastAudioScanServiceProxy(gatt_client.ProfileServiceProxy):
+    SERVICE_CLASS = BroadcastAudioScanService
+
+    broadcast_audio_scan_control_point: gatt_client.CharacteristicProxy
+    broadcast_receive_states: List[gatt.DelegatedCharacteristicAdapter]
+
+    def __init__(self, service_proxy: gatt_client.ServiceProxy):
+        self.service_proxy = service_proxy
+
+        if not (
+            characteristics := service_proxy.get_characteristics_by_uuid(
+                gatt.GATT_BROADCAST_AUDIO_SCAN_CONTROL_POINT_CHARACTERISTIC
+            )
+        ):
+            raise gatt.InvalidServiceError(
+                "Broadcast Audio Scan Control Point characteristic not found"
+            )
+        self.broadcast_audio_scan_control_point = characteristics[0]
+
+        if not (
+            characteristics := service_proxy.get_characteristics_by_uuid(
+                gatt.GATT_BROADCAST_RECEIVE_STATE_CHARACTERISTIC
+            )
+        ):
+            raise gatt.InvalidServiceError(
+                "Broadcast Receive State characteristic not found"
+            )
+        self.broadcast_receive_states = [
+            gatt.DelegatedCharacteristicAdapter(
+                characteristic, decode=BroadcastReceiveState.from_bytes
+            )
+            for characteristic in characteristics
+        ]
+
+    async def send_control_point_operation(
+        self, operation: ControlPointOperation
+    ) -> None:
+        await self.broadcast_audio_scan_control_point.write_value(
+            bytes(operation), with_response=True
+        )
+
+    async def remote_scan_started(self) -> None:
+        await self.send_control_point_operation(RemoteScanStartedOperation())
+
+    async def remote_scan_stopped(self) -> None:
+        await self.send_control_point_operation(RemoteScanStoppedOperation())
+
+    async def add_source(
+        self,
+        advertiser_address: hci.Address,
+        advertising_sid: int,
+        broadcast_id: int,
+        pa_sync: PeriodicAdvertisingSyncParams,
+        pa_interval: int,
+        subgroups: Sequence[SubgroupInfo],
+    ) -> None:
+        await self.send_control_point_operation(
+            AddSourceOperation(
+                advertiser_address,
+                advertising_sid,
+                broadcast_id,
+                pa_sync,
+                pa_interval,
+                subgroups,
+            )
+        )
+
+    async def modify_source(
+        self,
+        source_id: int,
+        pa_sync: PeriodicAdvertisingSyncParams,
+        pa_interval: int,
+        subgroups: Sequence[SubgroupInfo],
+    ) -> None:
+        await self.send_control_point_operation(
+            ModifySourceOperation(
+                source_id,
+                pa_sync,
+                pa_interval,
+                subgroups,
+            )
+        )
+
+    async def remove_source(self, source_id: int) -> None:
+        await self.send_control_point_operation(RemoveSourceOperation(source_id))
diff --git a/bumble/profiles/csip.py b/bumble/profiles/csip.py
index 03fba9c..9ba3baf 100644
--- a/bumble/profiles/csip.py
+++ b/bumble/profiles/csip.py
@@ -113,7 +113,7 @@ class CoordinatedSetIdentificationService(gatt.TemplateService):
         set_member_rank: Optional[int] = None,
     ) -> None:
         if len(set_identity_resolving_key) != SET_IDENTITY_RESOLVING_KEY_LENGTH:
-            raise ValueError(
+            raise core.InvalidArgumentError(
                 f'Invalid SIRK length {len(set_identity_resolving_key)}, expected {SET_IDENTITY_RESOLVING_KEY_LENGTH}'
             )
 
@@ -178,7 +178,7 @@ class CoordinatedSetIdentificationService(gatt.TemplateService):
                 key = await connection.device.get_link_key(connection.peer_address)
 
             if not key:
-                raise RuntimeError('LTK or LinkKey is not present')
+                raise core.InvalidOperationError('LTK or LinkKey is not present')
 
             sirk_bytes = sef(key, self.set_identity_resolving_key)
 
@@ -234,7 +234,7 @@ class CoordinatedSetIdentificationProxy(gatt_client.ProfileServiceProxy):
         '''Reads SIRK and decrypts if encrypted.'''
         response = await self.set_identity_resolving_key.read_value()
         if len(response) != SET_IDENTITY_RESOLVING_KEY_LENGTH + 1:
-            raise RuntimeError('Invalid SIRK value')
+            raise core.InvalidPacketError('Invalid SIRK value')
 
         sirk_type = SirkType(response[0])
         if sirk_type == SirkType.PLAINTEXT:
@@ -250,7 +250,7 @@ class CoordinatedSetIdentificationProxy(gatt_client.ProfileServiceProxy):
                 key = await device.get_link_key(connection.peer_address)
 
             if not key:
-                raise RuntimeError('LTK or LinkKey is not present')
+                raise core.InvalidOperationError('LTK or LinkKey is not present')
 
             sirk = sef(key, response[1:])
 
diff --git a/bumble/profiles/gap.py b/bumble/profiles/gap.py
new file mode 100644
index 0000000..0dd6e51
--- /dev/null
+++ b/bumble/profiles/gap.py
@@ -0,0 +1,110 @@
+# Copyright 2021-2022 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Generic Access Profile"""
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+import logging
+import struct
+from typing import Optional, Tuple, Union
+
+from bumble.core import Appearance
+from bumble.gatt import (
+    TemplateService,
+    Characteristic,
+    CharacteristicAdapter,
+    DelegatedCharacteristicAdapter,
+    UTF8CharacteristicAdapter,
+    GATT_GENERIC_ACCESS_SERVICE,
+    GATT_DEVICE_NAME_CHARACTERISTIC,
+    GATT_APPEARANCE_CHARACTERISTIC,
+)
+from bumble.gatt_client import ProfileServiceProxy, ServiceProxy
+
+# -----------------------------------------------------------------------------
+# Logging
+# -----------------------------------------------------------------------------
+logger = logging.getLogger(__name__)
+
+
+# -----------------------------------------------------------------------------
+# Classes
+# -----------------------------------------------------------------------------
+
+
+# -----------------------------------------------------------------------------
+class GenericAccessService(TemplateService):
+    UUID = GATT_GENERIC_ACCESS_SERVICE
+
+    def __init__(
+        self, device_name: str, appearance: Union[Appearance, Tuple[int, int], int] = 0
+    ):
+        if isinstance(appearance, int):
+            appearance_int = appearance
+        elif isinstance(appearance, tuple):
+            appearance_int = (appearance[0] << 6) | appearance[1]
+        elif isinstance(appearance, Appearance):
+            appearance_int = int(appearance)
+        else:
+            raise TypeError()
+
+        self.device_name_characteristic = Characteristic(
+            GATT_DEVICE_NAME_CHARACTERISTIC,
+            Characteristic.Properties.READ,
+            Characteristic.READABLE,
+            device_name.encode('utf-8')[:248],
+        )
+
+        self.appearance_characteristic = Characteristic(
+            GATT_APPEARANCE_CHARACTERISTIC,
+            Characteristic.Properties.READ,
+            Characteristic.READABLE,
+            struct.pack('<H', appearance_int),
+        )
+
+        super().__init__(
+            [self.device_name_characteristic, self.appearance_characteristic]
+        )
+
+
+# -----------------------------------------------------------------------------
+class GenericAccessServiceProxy(ProfileServiceProxy):
+    SERVICE_CLASS = GenericAccessService
+
+    device_name: Optional[CharacteristicAdapter]
+    appearance: Optional[DelegatedCharacteristicAdapter]
+
+    def __init__(self, service_proxy: ServiceProxy):
+        self.service_proxy = service_proxy
+
+        if characteristics := service_proxy.get_characteristics_by_uuid(
+            GATT_DEVICE_NAME_CHARACTERISTIC
+        ):
+            self.device_name = UTF8CharacteristicAdapter(characteristics[0])
+        else:
+            self.device_name = None
+
+        if characteristics := service_proxy.get_characteristics_by_uuid(
+            GATT_APPEARANCE_CHARACTERISTIC
+        ):
+            self.appearance = DelegatedCharacteristicAdapter(
+                characteristics[0],
+                decode=lambda value: Appearance.from_int(
+                    struct.unpack_from('<H', value, 0)[0],
+                ),
+            )
+        else:
+            self.appearance = None
diff --git a/bumble/profiles/hap.py b/bumble/profiles/hap.py
new file mode 100644
index 0000000..1ef055c
--- /dev/null
+++ b/bumble/profiles/hap.py
@@ -0,0 +1,665 @@
+# Copyright 2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+from __future__ import annotations
+import asyncio
+import functools
+from bumble import att, gatt, gatt_client
+from bumble.core import InvalidArgumentError, InvalidStateError
+from bumble.device import Device, Connection
+from bumble.utils import AsyncRunner, OpenIntEnum
+from bumble.hci import Address
+from dataclasses import dataclass, field
+import logging
+from typing import Dict, List, Optional, Set, Union
+
+
+# -----------------------------------------------------------------------------
+# Constants
+# -----------------------------------------------------------------------------
+class ErrorCode(OpenIntEnum):
+    '''See Hearing Access Service 2.4. Attribute Profile error codes.'''
+
+    INVALID_OPCODE = 0x80
+    WRITE_NAME_NOT_ALLOWED = 0x81
+    PRESET_SYNCHRONIZATION_NOT_SUPPORTED = 0x82
+    PRESET_OPERATION_NOT_POSSIBLE = 0x83
+    INVALID_PARAMETERS_LENGTH = 0x84
+
+
+class HearingAidType(OpenIntEnum):
+    '''See Hearing Access Service 3.1. Hearing Aid Features.'''
+
+    BINAURAL_HEARING_AID = 0b00
+    MONAURAL_HEARING_AID = 0b01
+    BANDED_HEARING_AID = 0b10
+
+
+class PresetSynchronizationSupport(OpenIntEnum):
+    '''See Hearing Access Service 3.1. Hearing Aid Features.'''
+
+    PRESET_SYNCHRONIZATION_IS_NOT_SUPPORTED = 0b0
+    PRESET_SYNCHRONIZATION_IS_SUPPORTED = 0b1
+
+
+class IndependentPresets(OpenIntEnum):
+    '''See Hearing Access Service 3.1. Hearing Aid Features.'''
+
+    IDENTICAL_PRESET_RECORD = 0b0
+    DIFFERENT_PRESET_RECORD = 0b1
+
+
+class DynamicPresets(OpenIntEnum):
+    '''See Hearing Access Service 3.1. Hearing Aid Features.'''
+
+    PRESET_RECORDS_DOES_NOT_CHANGE = 0b0
+    PRESET_RECORDS_MAY_CHANGE = 0b1
+
+
+class WritablePresetsSupport(OpenIntEnum):
+    '''See Hearing Access Service 3.1. Hearing Aid Features.'''
+
+    WRITABLE_PRESET_RECORDS_NOT_SUPPORTED = 0b0
+    WRITABLE_PRESET_RECORDS_SUPPORTED = 0b1
+
+
+class HearingAidPresetControlPointOpcode(OpenIntEnum):
+    '''See Hearing Access Service 3.3.1 Hearing Aid Preset Control Point operation requirements.'''
+
+    # fmt: off
+    READ_PRESETS_REQUEST                     = 0x01
+    READ_PRESET_RESPONSE                     = 0x02
+    PRESET_CHANGED                           = 0x03
+    WRITE_PRESET_NAME                        = 0x04
+    SET_ACTIVE_PRESET                        = 0x05
+    SET_NEXT_PRESET                          = 0x06
+    SET_PREVIOUS_PRESET                      = 0x07
+    SET_ACTIVE_PRESET_SYNCHRONIZED_LOCALLY   = 0x08
+    SET_NEXT_PRESET_SYNCHRONIZED_LOCALLY     = 0x09
+    SET_PREVIOUS_PRESET_SYNCHRONIZED_LOCALLY = 0x0A
+
+
+@dataclass
+class HearingAidFeatures:
+    '''See Hearing Access Service 3.1. Hearing Aid Features.'''
+
+    hearing_aid_type: HearingAidType
+    preset_synchronization_support: PresetSynchronizationSupport
+    independent_presets: IndependentPresets
+    dynamic_presets: DynamicPresets
+    writable_presets_support: WritablePresetsSupport
+
+    def __bytes__(self) -> bytes:
+        return bytes(
+            [
+                (self.hearing_aid_type << 0)
+                | (self.preset_synchronization_support << 2)
+                | (self.independent_presets << 3)
+                | (self.dynamic_presets << 4)
+                | (self.writable_presets_support << 5)
+            ]
+        )
+
+
+def HearingAidFeatures_from_bytes(data: int) -> HearingAidFeatures:
+    return HearingAidFeatures(
+        HearingAidType(data & 0b11),
+        PresetSynchronizationSupport(data >> 2 & 0b1),
+        IndependentPresets(data >> 3 & 0b1),
+        DynamicPresets(data >> 4 & 0b1),
+        WritablePresetsSupport(data >> 5 & 0b1),
+    )
+
+
+@dataclass
+class PresetChangedOperation:
+    '''See Hearing Access Service 3.2.2.2. Preset Changed operation.'''
+
+    class ChangeId(OpenIntEnum):
+        # fmt: off
+        GENERIC_UPDATE            = 0x00
+        PRESET_RECORD_DELETED     = 0x01
+        PRESET_RECORD_AVAILABLE   = 0x02
+        PRESET_RECORD_UNAVAILABLE = 0x03
+
+    @dataclass
+    class Generic:
+        prev_index: int
+        preset_record: PresetRecord
+
+        def __bytes__(self) -> bytes:
+            return bytes([self.prev_index]) + bytes(self.preset_record)
+
+    change_id: ChangeId
+    additional_parameters: Union[Generic, int]
+
+    def to_bytes(self, is_last: bool) -> bytes:
+        if isinstance(self.additional_parameters, PresetChangedOperation.Generic):
+            additional_parameters_bytes = bytes(self.additional_parameters)
+        else:
+            additional_parameters_bytes = bytes([self.additional_parameters])
+
+        return (
+            bytes(
+                [
+                    HearingAidPresetControlPointOpcode.PRESET_CHANGED,
+                    self.change_id,
+                    is_last,
+                ]
+            )
+            + additional_parameters_bytes
+        )
+
+
+class PresetChangedOperationDeleted(PresetChangedOperation):
+    def __init__(self, index) -> None:
+        self.change_id = PresetChangedOperation.ChangeId.PRESET_RECORD_DELETED
+        self.additional_parameters = index
+
+
+class PresetChangedOperationAvailable(PresetChangedOperation):
+    def __init__(self, index) -> None:
+        self.change_id = PresetChangedOperation.ChangeId.PRESET_RECORD_AVAILABLE
+        self.additional_parameters = index
+
+
+class PresetChangedOperationUnavailable(PresetChangedOperation):
+    def __init__(self, index) -> None:
+        self.change_id = PresetChangedOperation.ChangeId.PRESET_RECORD_UNAVAILABLE
+        self.additional_parameters = index
+
+
+@dataclass
+class PresetRecord:
+    '''See Hearing Access Service 2.8. Preset record.'''
+
+    @dataclass
+    class Property:
+        class Writable(OpenIntEnum):
+            CANNOT_BE_WRITTEN = 0b0
+            CAN_BE_WRITTEN = 0b1
+
+        class IsAvailable(OpenIntEnum):
+            IS_UNAVAILABLE = 0b0
+            IS_AVAILABLE = 0b1
+
+        writable: Writable = Writable.CAN_BE_WRITTEN
+        is_available: IsAvailable = IsAvailable.IS_AVAILABLE
+
+        def __bytes__(self) -> bytes:
+            return bytes([self.writable | (self.is_available << 1)])
+
+    index: int
+    name: str
+    properties: Property = field(default_factory=Property)
+
+    def __bytes__(self) -> bytes:
+        return bytes([self.index]) + bytes(self.properties) + self.name.encode('utf-8')
+
+    def is_available(self) -> bool:
+        return (
+            self.properties.is_available
+            == PresetRecord.Property.IsAvailable.IS_AVAILABLE
+        )
+
+
+# -----------------------------------------------------------------------------
+# Server
+# -----------------------------------------------------------------------------
+class HearingAccessService(gatt.TemplateService):
+    UUID = gatt.GATT_HEARING_ACCESS_SERVICE
+
+    hearing_aid_features_characteristic: gatt.Characteristic
+    hearing_aid_preset_control_point: gatt.Characteristic
+    active_preset_index_characteristic: gatt.Characteristic
+    active_preset_index: int
+    active_preset_index_per_device: Dict[Address, int]
+
+    device: Device
+
+    server_features: HearingAidFeatures
+    preset_records: Dict[int, PresetRecord]  # key is the preset index
+    read_presets_request_in_progress: bool
+
+    preset_changed_operations_history_per_device: Dict[
+        Address, List[PresetChangedOperation]
+    ]
+
+    # Keep an updated list of connected client to send notification to
+    currently_connected_clients: Set[Connection]
+
+    def __init__(
+        self, device: Device, features: HearingAidFeatures, presets: List[PresetRecord]
+    ) -> None:
+        self.active_preset_index_per_device = {}
+        self.read_presets_request_in_progress = False
+        self.preset_changed_operations_history_per_device = {}
+        self.currently_connected_clients = set()
+
+        self.device = device
+        self.server_features = features
+        if len(presets) < 1:
+            raise InvalidArgumentError(f'Invalid presets: {presets}')
+
+        self.preset_records = {}
+        for p in presets:
+            if len(p.name.encode()) < 1 or len(p.name.encode()) > 40:
+                raise InvalidArgumentError(f'Invalid name: {p.name}')
+
+            self.preset_records[p.index] = p
+
+        # associate the lowest index as the current active preset at startup
+        self.active_preset_index = sorted(self.preset_records.keys())[0]
+
+        @device.on('connection')  # type: ignore
+        def on_connection(connection: Connection) -> None:
+            @connection.on('disconnection')  # type: ignore
+            def on_disconnection(_reason) -> None:
+                self.currently_connected_clients.remove(connection)
+
+            # TODO Should we filter on device bonded && device is HAP ?
+            self.currently_connected_clients.add(connection)
+            if (
+                connection.peer_address
+                not in self.preset_changed_operations_history_per_device
+            ):
+                self.preset_changed_operations_history_per_device[
+                    connection.peer_address
+                ] = []
+                return
+
+            async def on_connection_async() -> None:
+                # Send all the PresetChangedOperation that occur when not connected
+                await self._preset_changed_operation(connection)
+                # Update the active preset index if needed
+                await self.notify_active_preset_for_connection(connection)
+
+            connection.abort_on('disconnection', on_connection_async())
+
+        self.hearing_aid_features_characteristic = gatt.Characteristic(
+            uuid=gatt.GATT_HEARING_AID_FEATURES_CHARACTERISTIC,
+            properties=gatt.Characteristic.Properties.READ,
+            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
+            value=bytes(self.server_features),
+        )
+        self.hearing_aid_preset_control_point = gatt.Characteristic(
+            uuid=gatt.GATT_HEARING_AID_PRESET_CONTROL_POINT_CHARACTERISTIC,
+            properties=(
+                gatt.Characteristic.Properties.WRITE
+                | gatt.Characteristic.Properties.INDICATE
+            ),
+            permissions=gatt.Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
+            value=gatt.CharacteristicValue(
+                write=self._on_write_hearing_aid_preset_control_point
+            ),
+        )
+        self.active_preset_index_characteristic = gatt.Characteristic(
+            uuid=gatt.GATT_ACTIVE_PRESET_INDEX_CHARACTERISTIC,
+            properties=(
+                gatt.Characteristic.Properties.READ
+                | gatt.Characteristic.Properties.NOTIFY
+            ),
+            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
+            value=gatt.CharacteristicValue(read=self._on_read_active_preset_index),
+        )
+
+        super().__init__(
+            [
+                self.hearing_aid_features_characteristic,
+                self.hearing_aid_preset_control_point,
+                self.active_preset_index_characteristic,
+            ]
+        )
+
+    def _on_read_active_preset_index(
+        self, __connection__: Optional[Connection]
+    ) -> bytes:
+        return bytes([self.active_preset_index])
+
+    # TODO this need to be triggered when device is unbonded
+    def on_forget(self, addr: Address) -> None:
+        self.preset_changed_operations_history_per_device.pop(addr)
+
+    async def _on_write_hearing_aid_preset_control_point(
+        self, connection: Optional[Connection], value: bytes
+    ):
+        assert connection
+
+        opcode = HearingAidPresetControlPointOpcode(value[0])
+        handler = getattr(self, '_on_' + opcode.name.lower())
+        await handler(connection, value)
+
+    async def _on_read_presets_request(
+        self, connection: Optional[Connection], value: bytes
+    ):
+        assert connection
+        if connection.att_mtu < 49:  # 2.5. GATT sub-procedure requirements
+            logging.warning(f'HAS require MTU >= 49: {connection}')
+
+        if self.read_presets_request_in_progress:
+            raise att.ATT_Error(att.ErrorCode.PROCEDURE_ALREADY_IN_PROGRESS)
+        self.read_presets_request_in_progress = True
+
+        start_index = value[1]
+        if start_index == 0x00:
+            raise att.ATT_Error(att.ErrorCode.OUT_OF_RANGE)
+
+        num_presets = value[2]
+        if num_presets == 0x00:
+            raise att.ATT_Error(att.ErrorCode.OUT_OF_RANGE)
+
+        # Sending `num_presets` presets ordered by increasing index field, starting from start_index
+        presets = [
+            self.preset_records[key]
+            for key in sorted(self.preset_records.keys())
+            if self.preset_records[key].index >= start_index
+        ]
+        del presets[num_presets:]
+        if len(presets) == 0:
+            raise att.ATT_Error(att.ErrorCode.OUT_OF_RANGE)
+
+        AsyncRunner.spawn(self._read_preset_response(connection, presets))
+
+    async def _read_preset_response(
+        self, connection: Connection, presets: List[PresetRecord]
+    ):
+        # If the ATT bearer is terminated before all notifications or indications are sent, then the server shall consider the Read Presets Request operation aborted and shall not either continue or restart the operation when the client reconnects.
+        try:
+            for i, preset in enumerate(presets):
+                await connection.device.indicate_subscriber(
+                    connection,
+                    self.hearing_aid_preset_control_point,
+                    value=bytes(
+                        [
+                            HearingAidPresetControlPointOpcode.READ_PRESET_RESPONSE,
+                            i == len(presets) - 1,
+                        ]
+                    )
+                    + bytes(preset),
+                )
+
+        finally:
+            # indicate_subscriber can raise a TimeoutError, we need to gracefully terminate the operation
+            self.read_presets_request_in_progress = False
+
+    async def generic_update(self, op: PresetChangedOperation) -> None:
+        '''Server API to perform a generic update. It is the responsibility of the caller to modify the preset_records to match the PresetChangedOperation being sent'''
+        await self._notifyPresetOperations(op)
+
+    async def delete_preset(self, index: int) -> None:
+        '''Server API to delete a preset. It should not be the current active preset'''
+
+        if index == self.active_preset_index:
+            raise InvalidStateError('Cannot delete active preset')
+
+        del self.preset_records[index]
+        await self._notifyPresetOperations(PresetChangedOperationDeleted(index))
+
+    async def available_preset(self, index: int) -> None:
+        '''Server API to make a preset available'''
+
+        preset = self.preset_records[index]
+        preset.properties.is_available = PresetRecord.Property.IsAvailable.IS_AVAILABLE
+        await self._notifyPresetOperations(PresetChangedOperationAvailable(index))
+
+    async def unavailable_preset(self, index: int) -> None:
+        '''Server API to make a preset unavailable. It should not be the current active preset'''
+
+        if index == self.active_preset_index:
+            raise InvalidStateError('Cannot set active preset as unavailable')
+
+        preset = self.preset_records[index]
+        preset.properties.is_available = (
+            PresetRecord.Property.IsAvailable.IS_UNAVAILABLE
+        )
+        await self._notifyPresetOperations(PresetChangedOperationUnavailable(index))
+
+    async def _preset_changed_operation(self, connection: Connection) -> None:
+        '''Send all PresetChangedOperation saved for a given connection'''
+        op_list = self.preset_changed_operations_history_per_device.get(
+            connection.peer_address, []
+        )
+
+        # Notification will be sent in index order
+        def get_op_index(op: PresetChangedOperation) -> int:
+            if isinstance(op.additional_parameters, PresetChangedOperation.Generic):
+                return op.additional_parameters.prev_index
+            return op.additional_parameters
+
+        op_list.sort(key=get_op_index)
+        # If the ATT bearer is terminated before all notifications or indications are sent, then the server shall consider the Preset Changed operation aborted and shall continue the operation when the client reconnects.
+        while len(op_list) > 0:
+            try:
+                await connection.device.indicate_subscriber(
+                    connection,
+                    self.hearing_aid_preset_control_point,
+                    value=op_list[0].to_bytes(len(op_list) == 1),
+                )
+                # Remove item once sent, and keep the non sent item in the list
+                op_list.pop(0)
+            except TimeoutError:
+                break
+
+    async def _notifyPresetOperations(self, op: PresetChangedOperation) -> None:
+        for historyList in self.preset_changed_operations_history_per_device.values():
+            historyList.append(op)
+
+        for connection in self.currently_connected_clients:
+            await self._preset_changed_operation(connection)
+
+    async def _on_write_preset_name(
+        self, connection: Optional[Connection], value: bytes
+    ):
+        assert connection
+
+        if self.read_presets_request_in_progress:
+            raise att.ATT_Error(att.ErrorCode.PROCEDURE_ALREADY_IN_PROGRESS)
+
+        index = value[1]
+        preset = self.preset_records.get(index, None)
+        if (
+            not preset
+            or preset.properties.writable
+            == PresetRecord.Property.Writable.CANNOT_BE_WRITTEN
+        ):
+            raise att.ATT_Error(ErrorCode.WRITE_NAME_NOT_ALLOWED)
+
+        name = value[2:].decode('utf-8')
+        if not name or len(name) > 40:
+            raise att.ATT_Error(ErrorCode.INVALID_PARAMETERS_LENGTH)
+
+        preset.name = name
+
+        await self.generic_update(
+            PresetChangedOperation(
+                PresetChangedOperation.ChangeId.GENERIC_UPDATE,
+                PresetChangedOperation.Generic(index, preset),
+            )
+        )
+
+    async def notify_active_preset_for_connection(self, connection: Connection) -> None:
+        if (
+            self.active_preset_index_per_device.get(connection.peer_address, 0x00)
+            == self.active_preset_index
+        ):
+            # Nothing to do, peer is already updated
+            return
+
+        await connection.device.notify_subscriber(
+            connection,
+            attribute=self.active_preset_index_characteristic,
+            value=bytes([self.active_preset_index]),
+        )
+        self.active_preset_index_per_device[connection.peer_address] = (
+            self.active_preset_index
+        )
+
+    async def notify_active_preset(self) -> None:
+        for connection in self.currently_connected_clients:
+            await self.notify_active_preset_for_connection(connection)
+
+    async def set_active_preset(
+        self, connection: Optional[Connection], value: bytes
+    ) -> None:
+        assert connection
+        index = value[1]
+        preset = self.preset_records.get(index, None)
+        if (
+            not preset
+            or preset.properties.is_available
+            != PresetRecord.Property.IsAvailable.IS_AVAILABLE
+        ):
+            raise att.ATT_Error(ErrorCode.PRESET_OPERATION_NOT_POSSIBLE)
+
+        if index == self.active_preset_index:
+            # Already at correct value
+            return
+
+        self.active_preset_index = index
+        await self.notify_active_preset()
+
+    async def _on_set_active_preset(
+        self, connection: Optional[Connection], value: bytes
+    ):
+        await self.set_active_preset(connection, value)
+
+    async def set_next_or_previous_preset(
+        self, connection: Optional[Connection], is_previous
+    ):
+        '''Set the next or the previous preset as active'''
+        assert connection
+
+        if self.active_preset_index == 0x00:
+            raise att.ATT_Error(ErrorCode.PRESET_OPERATION_NOT_POSSIBLE)
+
+        first_preset: Optional[PresetRecord] = None  # To loop to first preset
+        next_preset: Optional[PresetRecord] = None
+        for index, record in sorted(self.preset_records.items(), reverse=is_previous):
+            if not record.is_available():
+                continue
+            if first_preset == None:
+                first_preset = record
+            if is_previous:
+                if index >= self.active_preset_index:
+                    continue
+            elif index <= self.active_preset_index:
+                continue
+            next_preset = record
+            break
+
+        if not first_preset:  # If no other preset are available
+            raise att.ATT_Error(ErrorCode.PRESET_OPERATION_NOT_POSSIBLE)
+
+        if next_preset:
+            self.active_preset_index = next_preset.index
+        else:
+            self.active_preset_index = first_preset.index
+        await self.notify_active_preset()
+
+    async def _on_set_next_preset(
+        self, connection: Optional[Connection], __value__: bytes
+    ) -> None:
+        await self.set_next_or_previous_preset(connection, False)
+
+    async def _on_set_previous_preset(
+        self, connection: Optional[Connection], __value__: bytes
+    ) -> None:
+        await self.set_next_or_previous_preset(connection, True)
+
+    async def _on_set_active_preset_synchronized_locally(
+        self, connection: Optional[Connection], value: bytes
+    ):
+        if (
+            self.server_features.preset_synchronization_support
+            == PresetSynchronizationSupport.PRESET_SYNCHRONIZATION_IS_SUPPORTED
+        ):
+            raise att.ATT_Error(ErrorCode.PRESET_SYNCHRONIZATION_NOT_SUPPORTED)
+        await self.set_active_preset(connection, value)
+        # TODO (low priority) inform other server of the change
+
+    async def _on_set_next_preset_synchronized_locally(
+        self, connection: Optional[Connection], __value__: bytes
+    ):
+        if (
+            self.server_features.preset_synchronization_support
+            == PresetSynchronizationSupport.PRESET_SYNCHRONIZATION_IS_SUPPORTED
+        ):
+            raise att.ATT_Error(ErrorCode.PRESET_SYNCHRONIZATION_NOT_SUPPORTED)
+        await self.set_next_or_previous_preset(connection, False)
+        # TODO (low priority) inform other server of the change
+
+    async def _on_set_previous_preset_synchronized_locally(
+        self, connection: Optional[Connection], __value__: bytes
+    ):
+        if (
+            self.server_features.preset_synchronization_support
+            == PresetSynchronizationSupport.PRESET_SYNCHRONIZATION_IS_SUPPORTED
+        ):
+            raise att.ATT_Error(ErrorCode.PRESET_SYNCHRONIZATION_NOT_SUPPORTED)
+        await self.set_next_or_previous_preset(connection, True)
+        # TODO (low priority) inform other server of the change
+
+
+# -----------------------------------------------------------------------------
+# Client
+# -----------------------------------------------------------------------------
+class HearingAccessServiceProxy(gatt_client.ProfileServiceProxy):
+    SERVICE_CLASS = HearingAccessService
+
+    hearing_aid_preset_control_point: gatt_client.CharacteristicProxy
+    preset_control_point_indications: asyncio.Queue
+
+    def __init__(self, service_proxy: gatt_client.ServiceProxy) -> None:
+        self.service_proxy = service_proxy
+
+        self.server_features = gatt.PackedCharacteristicAdapter(
+            service_proxy.get_characteristics_by_uuid(
+                gatt.GATT_HEARING_AID_FEATURES_CHARACTERISTIC
+            )[0],
+            'B',
+        )
+
+        self.hearing_aid_preset_control_point = (
+            service_proxy.get_characteristics_by_uuid(
+                gatt.GATT_HEARING_AID_PRESET_CONTROL_POINT_CHARACTERISTIC
+            )[0]
+        )
+
+        self.active_preset_index = gatt.PackedCharacteristicAdapter(
+            service_proxy.get_characteristics_by_uuid(
+                gatt.GATT_ACTIVE_PRESET_INDEX_CHARACTERISTIC
+            )[0],
+            'B',
+        )
+
+    async def setup_subscription(self):
+        self.preset_control_point_indications = asyncio.Queue()
+        self.active_preset_index_notification = asyncio.Queue()
+
+        def on_active_preset_index_notification(data: bytes):
+            self.active_preset_index_notification.put_nowait(data)
+
+        def on_preset_control_point_indication(data: bytes):
+            self.preset_control_point_indications.put_nowait(data)
+
+        await self.hearing_aid_preset_control_point.subscribe(
+            functools.partial(on_preset_control_point_indication), prefer_notify=False
+        )
+
+        await self.active_preset_index.subscribe(
+            functools.partial(on_active_preset_index_notification)
+        )
diff --git a/bumble/profiles/heart_rate_service.py b/bumble/profiles/heart_rate_service.py
index fe46cb2..0c9a12f 100644
--- a/bumble/profiles/heart_rate_service.py
+++ b/bumble/profiles/heart_rate_service.py
@@ -19,6 +19,7 @@
 from enum import IntEnum
 import struct
 
+from bumble import core
 from ..gatt_client import ProfileServiceProxy
 from ..att import ATT_Error
 from ..gatt import (
@@ -59,17 +60,17 @@ class HeartRateService(TemplateService):
             rr_intervals=None,
         ):
             if heart_rate < 0 or heart_rate > 0xFFFF:
-                raise ValueError('heart_rate out of range')
+                raise core.InvalidArgumentError('heart_rate out of range')
 
             if energy_expended is not None and (
                 energy_expended < 0 or energy_expended > 0xFFFF
             ):
-                raise ValueError('energy_expended out of range')
+                raise core.InvalidArgumentError('energy_expended out of range')
 
             if rr_intervals:
                 for rr_interval in rr_intervals:
                     if rr_interval < 0 or rr_interval * 1024 > 0xFFFF:
-                        raise ValueError('rr_intervals out of range')
+                        raise core.InvalidArgumentError('rr_intervals out of range')
 
             self.heart_rate = heart_rate
             self.sensor_contact_detected = sensor_contact_detected
diff --git a/bumble/profiles/le_audio.py b/bumble/profiles/le_audio.py
new file mode 100644
index 0000000..b152fd9
--- /dev/null
+++ b/bumble/profiles/le_audio.py
@@ -0,0 +1,83 @@
+# Copyright 2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+from __future__ import annotations
+import dataclasses
+import struct
+from typing import List, Type
+from typing_extensions import Self
+
+from bumble import utils
+
+
+# -----------------------------------------------------------------------------
+# Classes
+# -----------------------------------------------------------------------------
+@dataclasses.dataclass
+class Metadata:
+    '''Bluetooth Assigned Numbers, Section 6.12.6 - Metadata LTV structures.
+
+    As Metadata fields may extend, and Spec doesn't forbid duplication, we don't parse
+    Metadata into a key-value style dataclass here. Rather, we encourage users to parse
+    again outside the lib.
+    '''
+
+    class Tag(utils.OpenIntEnum):
+        # fmt: off
+        PREFERRED_AUDIO_CONTEXTS                 = 0x01
+        STREAMING_AUDIO_CONTEXTS                 = 0x02
+        PROGRAM_INFO                             = 0x03
+        LANGUAGE                                 = 0x04
+        CCID_LIST                                = 0x05
+        PARENTAL_RATING                          = 0x06
+        PROGRAM_INFO_URI                         = 0x07
+        AUDIO_ACTIVE_STATE                       = 0x08
+        BROADCAST_AUDIO_IMMEDIATE_RENDERING_FLAG = 0x09
+        ASSISTED_LISTENING_STREAM                = 0x0A
+        BROADCAST_NAME                           = 0x0B
+        EXTENDED_METADATA                        = 0xFE
+        VENDOR_SPECIFIC                          = 0xFF
+
+    @dataclasses.dataclass
+    class Entry:
+        tag: Metadata.Tag
+        data: bytes
+
+        @classmethod
+        def from_bytes(cls: Type[Self], data: bytes) -> Self:
+            return cls(tag=Metadata.Tag(data[0]), data=data[1:])
+
+        def __bytes__(self) -> bytes:
+            return bytes([len(self.data) + 1, self.tag]) + self.data
+
+    entries: List[Entry] = dataclasses.field(default_factory=list)
+
+    @classmethod
+    def from_bytes(cls: Type[Self], data: bytes) -> Self:
+        entries = []
+        offset = 0
+        length = len(data)
+        while offset < length:
+            entry_length = data[offset]
+            offset += 1
+            entries.append(cls.Entry.from_bytes(data[offset : offset + entry_length]))
+            offset += entry_length
+
+        return cls(entries)
+
+    def __bytes__(self) -> bytes:
+        return b''.join([bytes(entry) for entry in self.entries])
diff --git a/bumble/profiles/mcp.py b/bumble/profiles/mcp.py
new file mode 100644
index 0000000..5e12573
--- /dev/null
+++ b/bumble/profiles/mcp.py
@@ -0,0 +1,448 @@
+# Copyright 2021-2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+from __future__ import annotations
+
+import asyncio
+import dataclasses
+import enum
+import struct
+
+from bumble import core
+from bumble import device
+from bumble import gatt
+from bumble import gatt_client
+from bumble import utils
+
+from typing import Type, Optional, ClassVar, Dict, TYPE_CHECKING
+from typing_extensions import Self
+
+# -----------------------------------------------------------------------------
+# Constants
+# -----------------------------------------------------------------------------
+
+
+class PlayingOrder(utils.OpenIntEnum):
+    '''See Media Control Service 3.15. Playing Order.'''
+
+    SINGLE_ONCE = 0x01
+    SINGLE_REPEAT = 0x02
+    IN_ORDER_ONCE = 0x03
+    IN_ORDER_REPEAT = 0x04
+    OLDEST_ONCE = 0x05
+    OLDEST_REPEAT = 0x06
+    NEWEST_ONCE = 0x07
+    NEWEST_REPEAT = 0x08
+    SHUFFLE_ONCE = 0x09
+    SHUFFLE_REPEAT = 0x0A
+
+
+class PlayingOrderSupported(enum.IntFlag):
+    '''See Media Control Service 3.16. Playing Orders Supported.'''
+
+    SINGLE_ONCE = 0x0001
+    SINGLE_REPEAT = 0x0002
+    IN_ORDER_ONCE = 0x0004
+    IN_ORDER_REPEAT = 0x0008
+    OLDEST_ONCE = 0x0010
+    OLDEST_REPEAT = 0x0020
+    NEWEST_ONCE = 0x0040
+    NEWEST_REPEAT = 0x0080
+    SHUFFLE_ONCE = 0x0100
+    SHUFFLE_REPEAT = 0x0200
+
+
+class MediaState(utils.OpenIntEnum):
+    '''See Media Control Service 3.17. Media State.'''
+
+    INACTIVE = 0x00
+    PLAYING = 0x01
+    PAUSED = 0x02
+    SEEKING = 0x03
+
+
+class MediaControlPointOpcode(utils.OpenIntEnum):
+    '''See Media Control Service 3.18. Media Control Point.'''
+
+    PLAY = 0x01
+    PAUSE = 0x02
+    FAST_REWIND = 0x03
+    FAST_FORWARD = 0x04
+    STOP = 0x05
+    MOVE_RELATIVE = 0x10
+    PREVIOUS_SEGMENT = 0x20
+    NEXT_SEGMENT = 0x21
+    FIRST_SEGMENT = 0x22
+    LAST_SEGMENT = 0x23
+    GOTO_SEGMENT = 0x24
+    PREVIOUS_TRACK = 0x30
+    NEXT_TRACK = 0x31
+    FIRST_TRACK = 0x32
+    LAST_TRACK = 0x33
+    GOTO_TRACK = 0x34
+    PREVIOUS_GROUP = 0x40
+    NEXT_GROUP = 0x41
+    FIRST_GROUP = 0x42
+    LAST_GROUP = 0x43
+    GOTO_GROUP = 0x44
+
+
+class MediaControlPointResultCode(enum.IntFlag):
+    '''See Media Control Service 3.18.2. Media Control Point Notification.'''
+
+    SUCCESS = 0x01
+    OPCODE_NOT_SUPPORTED = 0x02
+    MEDIA_PLAYER_INACTIVE = 0x03
+    COMMAND_CANNOT_BE_COMPLETED = 0x04
+
+
+class MediaControlPointOpcodeSupported(enum.IntFlag):
+    '''See Media Control Service 3.19. Media Control Point Opcodes Supported.'''
+
+    PLAY = 0x00000001
+    PAUSE = 0x00000002
+    FAST_REWIND = 0x00000004
+    FAST_FORWARD = 0x00000008
+    STOP = 0x00000010
+    MOVE_RELATIVE = 0x00000020
+    PREVIOUS_SEGMENT = 0x00000040
+    NEXT_SEGMENT = 0x00000080
+    FIRST_SEGMENT = 0x00000100
+    LAST_SEGMENT = 0x00000200
+    GOTO_SEGMENT = 0x00000400
+    PREVIOUS_TRACK = 0x00000800
+    NEXT_TRACK = 0x00001000
+    FIRST_TRACK = 0x00002000
+    LAST_TRACK = 0x00004000
+    GOTO_TRACK = 0x00008000
+    PREVIOUS_GROUP = 0x00010000
+    NEXT_GROUP = 0x00020000
+    FIRST_GROUP = 0x00040000
+    LAST_GROUP = 0x00080000
+    GOTO_GROUP = 0x00100000
+
+
+class SearchControlPointItemType(utils.OpenIntEnum):
+    '''See Media Control Service 3.20. Search Control Point.'''
+
+    TRACK_NAME = 0x01
+    ARTIST_NAME = 0x02
+    ALBUM_NAME = 0x03
+    GROUP_NAME = 0x04
+    EARLIEST_YEAR = 0x05
+    LATEST_YEAR = 0x06
+    GENRE = 0x07
+    ONLY_TRACKS = 0x08
+    ONLY_GROUPS = 0x09
+
+
+class ObjectType(utils.OpenIntEnum):
+    '''See Media Control Service 4.4.1. Object Type field.'''
+
+    TASK = 0
+    GROUP = 1
+
+
+# -----------------------------------------------------------------------------
+# Classes
+# -----------------------------------------------------------------------------
+
+
+class ObjectId(int):
+    '''See Media Control Service 4.4.2. Object ID field.'''
+
+    @classmethod
+    def create_from_bytes(cls: Type[Self], data: bytes) -> Self:
+        return cls(int.from_bytes(data, byteorder='little', signed=False))
+
+    def __bytes__(self) -> bytes:
+        return self.to_bytes(6, 'little')
+
+
+@dataclasses.dataclass
+class GroupObjectType:
+    '''See Media Control Service 4.4. Group Object Type.'''
+
+    object_type: ObjectType
+    object_id: ObjectId
+
+    @classmethod
+    def from_bytes(cls: Type[Self], data: bytes) -> Self:
+        return cls(
+            object_type=ObjectType(data[0]),
+            object_id=ObjectId.create_from_bytes(data[1:]),
+        )
+
+    def __bytes__(self) -> bytes:
+        return bytes([self.object_type]) + bytes(self.object_id)
+
+
+# -----------------------------------------------------------------------------
+# Server
+# -----------------------------------------------------------------------------
+class MediaControlService(gatt.TemplateService):
+    '''Media Control Service server implementation, only for testing currently.'''
+
+    UUID = gatt.GATT_MEDIA_CONTROL_SERVICE
+
+    def __init__(self, media_player_name: Optional[str] = None) -> None:
+        self.track_position = 0
+
+        self.media_player_name_characteristic = gatt.Characteristic(
+            uuid=gatt.GATT_MEDIA_PLAYER_NAME_CHARACTERISTIC,
+            properties=gatt.Characteristic.Properties.READ
+            | gatt.Characteristic.Properties.NOTIFY,
+            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
+            value=media_player_name or 'Bumble Player',
+        )
+        self.track_changed_characteristic = gatt.Characteristic(
+            uuid=gatt.GATT_TRACK_CHANGED_CHARACTERISTIC,
+            properties=gatt.Characteristic.Properties.NOTIFY,
+            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
+            value=b'',
+        )
+        self.track_title_characteristic = gatt.Characteristic(
+            uuid=gatt.GATT_TRACK_TITLE_CHARACTERISTIC,
+            properties=gatt.Characteristic.Properties.READ
+            | gatt.Characteristic.Properties.NOTIFY,
+            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
+            value=b'',
+        )
+        self.track_duration_characteristic = gatt.Characteristic(
+            uuid=gatt.GATT_TRACK_DURATION_CHARACTERISTIC,
+            properties=gatt.Characteristic.Properties.READ
+            | gatt.Characteristic.Properties.NOTIFY,
+            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
+            value=b'',
+        )
+        self.track_position_characteristic = gatt.Characteristic(
+            uuid=gatt.GATT_TRACK_POSITION_CHARACTERISTIC,
+            properties=gatt.Characteristic.Properties.READ
+            | gatt.Characteristic.Properties.WRITE
+            | gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE
+            | gatt.Characteristic.Properties.NOTIFY,
+            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION
+            | gatt.Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
+            value=b'',
+        )
+        self.media_state_characteristic = gatt.Characteristic(
+            uuid=gatt.GATT_MEDIA_STATE_CHARACTERISTIC,
+            properties=gatt.Characteristic.Properties.READ
+            | gatt.Characteristic.Properties.NOTIFY,
+            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
+            value=b'',
+        )
+        self.media_control_point_characteristic = gatt.Characteristic(
+            uuid=gatt.GATT_MEDIA_CONTROL_POINT_CHARACTERISTIC,
+            properties=gatt.Characteristic.Properties.WRITE
+            | gatt.Characteristic.Properties.WRITE_WITHOUT_RESPONSE
+            | gatt.Characteristic.Properties.NOTIFY,
+            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION
+            | gatt.Characteristic.Permissions.WRITE_REQUIRES_ENCRYPTION,
+            value=gatt.CharacteristicValue(write=self.on_media_control_point),
+        )
+        self.media_control_point_opcodes_supported_characteristic = gatt.Characteristic(
+            uuid=gatt.GATT_MEDIA_CONTROL_POINT_OPCODES_SUPPORTED_CHARACTERISTIC,
+            properties=gatt.Characteristic.Properties.READ
+            | gatt.Characteristic.Properties.NOTIFY,
+            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
+            value=b'',
+        )
+        self.content_control_id_characteristic = gatt.Characteristic(
+            uuid=gatt.GATT_CONTENT_CONTROL_ID_CHARACTERISTIC,
+            properties=gatt.Characteristic.Properties.READ,
+            permissions=gatt.Characteristic.Permissions.READ_REQUIRES_ENCRYPTION,
+            value=b'',
+        )
+
+        super().__init__(
+            [
+                self.media_player_name_characteristic,
+                self.track_changed_characteristic,
+                self.track_title_characteristic,
+                self.track_duration_characteristic,
+                self.track_position_characteristic,
+                self.media_state_characteristic,
+                self.media_control_point_characteristic,
+                self.media_control_point_opcodes_supported_characteristic,
+                self.content_control_id_characteristic,
+            ]
+        )
+
+    async def on_media_control_point(
+        self, connection: Optional[device.Connection], data: bytes
+    ) -> None:
+        if not connection:
+            raise core.InvalidStateError()
+
+        opcode = MediaControlPointOpcode(data[0])
+
+        await connection.device.notify_subscriber(
+            connection,
+            self.media_control_point_characteristic,
+            value=bytes([opcode, MediaControlPointResultCode.SUCCESS]),
+        )
+
+
+class GenericMediaControlService(MediaControlService):
+    UUID = gatt.GATT_GENERIC_MEDIA_CONTROL_SERVICE
+
+
+# -----------------------------------------------------------------------------
+# Client
+# -----------------------------------------------------------------------------
+class MediaControlServiceProxy(
+    gatt_client.ProfileServiceProxy, utils.CompositeEventEmitter
+):
+    SERVICE_CLASS = MediaControlService
+
+    _CHARACTERISTICS: ClassVar[Dict[str, core.UUID]] = {
+        'media_player_name': gatt.GATT_MEDIA_PLAYER_NAME_CHARACTERISTIC,
+        'media_player_icon_object_id': gatt.GATT_MEDIA_PLAYER_ICON_OBJECT_ID_CHARACTERISTIC,
+        'media_player_icon_url': gatt.GATT_MEDIA_PLAYER_ICON_URL_CHARACTERISTIC,
+        'track_changed': gatt.GATT_TRACK_CHANGED_CHARACTERISTIC,
+        'track_title': gatt.GATT_TRACK_TITLE_CHARACTERISTIC,
+        'track_duration': gatt.GATT_TRACK_DURATION_CHARACTERISTIC,
+        'track_position': gatt.GATT_TRACK_POSITION_CHARACTERISTIC,
+        'playback_speed': gatt.GATT_PLAYBACK_SPEED_CHARACTERISTIC,
+        'seeking_speed': gatt.GATT_SEEKING_SPEED_CHARACTERISTIC,
+        'current_track_segments_object_id': gatt.GATT_CURRENT_TRACK_SEGMENTS_OBJECT_ID_CHARACTERISTIC,
+        'current_track_object_id': gatt.GATT_CURRENT_TRACK_OBJECT_ID_CHARACTERISTIC,
+        'next_track_object_id': gatt.GATT_NEXT_TRACK_OBJECT_ID_CHARACTERISTIC,
+        'parent_group_object_id': gatt.GATT_PARENT_GROUP_OBJECT_ID_CHARACTERISTIC,
+        'current_group_object_id': gatt.GATT_CURRENT_GROUP_OBJECT_ID_CHARACTERISTIC,
+        'playing_order': gatt.GATT_PLAYING_ORDER_CHARACTERISTIC,
+        'playing_orders_supported': gatt.GATT_PLAYING_ORDERS_SUPPORTED_CHARACTERISTIC,
+        'media_state': gatt.GATT_MEDIA_STATE_CHARACTERISTIC,
+        'media_control_point': gatt.GATT_MEDIA_CONTROL_POINT_CHARACTERISTIC,
+        'media_control_point_opcodes_supported': gatt.GATT_MEDIA_CONTROL_POINT_OPCODES_SUPPORTED_CHARACTERISTIC,
+        'search_control_point': gatt.GATT_SEARCH_CONTROL_POINT_CHARACTERISTIC,
+        'search_results_object_id': gatt.GATT_SEARCH_RESULTS_OBJECT_ID_CHARACTERISTIC,
+        'content_control_id': gatt.GATT_CONTENT_CONTROL_ID_CHARACTERISTIC,
+    }
+
+    media_player_name: Optional[gatt_client.CharacteristicProxy] = None
+    media_player_icon_object_id: Optional[gatt_client.CharacteristicProxy] = None
+    media_player_icon_url: Optional[gatt_client.CharacteristicProxy] = None
+    track_changed: Optional[gatt_client.CharacteristicProxy] = None
+    track_title: Optional[gatt_client.CharacteristicProxy] = None
+    track_duration: Optional[gatt_client.CharacteristicProxy] = None
+    track_position: Optional[gatt_client.CharacteristicProxy] = None
+    playback_speed: Optional[gatt_client.CharacteristicProxy] = None
+    seeking_speed: Optional[gatt_client.CharacteristicProxy] = None
+    current_track_segments_object_id: Optional[gatt_client.CharacteristicProxy] = None
+    current_track_object_id: Optional[gatt_client.CharacteristicProxy] = None
+    next_track_object_id: Optional[gatt_client.CharacteristicProxy] = None
+    parent_group_object_id: Optional[gatt_client.CharacteristicProxy] = None
+    current_group_object_id: Optional[gatt_client.CharacteristicProxy] = None
+    playing_order: Optional[gatt_client.CharacteristicProxy] = None
+    playing_orders_supported: Optional[gatt_client.CharacteristicProxy] = None
+    media_state: Optional[gatt_client.CharacteristicProxy] = None
+    media_control_point: Optional[gatt_client.CharacteristicProxy] = None
+    media_control_point_opcodes_supported: Optional[gatt_client.CharacteristicProxy] = (
+        None
+    )
+    search_control_point: Optional[gatt_client.CharacteristicProxy] = None
+    search_results_object_id: Optional[gatt_client.CharacteristicProxy] = None
+    content_control_id: Optional[gatt_client.CharacteristicProxy] = None
+
+    if TYPE_CHECKING:
+        media_control_point_notifications: asyncio.Queue[bytes]
+
+    def __init__(self, service_proxy: gatt_client.ServiceProxy) -> None:
+        utils.CompositeEventEmitter.__init__(self)
+        self.service_proxy = service_proxy
+        self.lock = asyncio.Lock()
+        self.media_control_point_notifications = asyncio.Queue()
+
+        for field, uuid in self._CHARACTERISTICS.items():
+            if characteristics := service_proxy.get_characteristics_by_uuid(uuid):
+                setattr(self, field, characteristics[0])
+
+    async def subscribe_characteristics(self) -> None:
+        if self.media_control_point:
+            await self.media_control_point.subscribe(self._on_media_control_point)
+        if self.media_state:
+            await self.media_state.subscribe(self._on_media_state)
+        if self.track_changed:
+            await self.track_changed.subscribe(self._on_track_changed)
+        if self.track_title:
+            await self.track_title.subscribe(self._on_track_title)
+        if self.track_duration:
+            await self.track_duration.subscribe(self._on_track_duration)
+        if self.track_position:
+            await self.track_position.subscribe(self._on_track_position)
+
+    async def write_control_point(
+        self, opcode: MediaControlPointOpcode
+    ) -> MediaControlPointResultCode:
+        '''Writes a Media Control Point Opcode to peer and waits for the notification.
+
+        The write operation will be executed when there isn't other pending commands.
+
+        Args:
+            opcode: opcode defined in `MediaControlPointOpcode`.
+
+        Returns:
+            Response code provided in `MediaControlPointResultCode`
+
+        Raises:
+            InvalidOperationError: Server does not have Media Control Point Characteristic.
+            InvalidStateError: Server replies a notification with mismatched opcode.
+        '''
+        if not self.media_control_point:
+            raise core.InvalidOperationError("Peer does not have media control point")
+
+        async with self.lock:
+            await self.media_control_point.write_value(
+                bytes([opcode]),
+                with_response=False,
+            )
+
+            (
+                response_opcode,
+                response_code,
+            ) = await self.media_control_point_notifications.get()
+            if response_opcode != opcode:
+                raise core.InvalidStateError(
+                    f"Expected {opcode} notification, but get {response_opcode}"
+                )
+            return MediaControlPointResultCode(response_code)
+
+    def _on_media_control_point(self, data: bytes) -> None:
+        self.media_control_point_notifications.put_nowait(data)
+
+    def _on_media_state(self, data: bytes) -> None:
+        self.emit('media_state', MediaState(data[0]))
+
+    def _on_track_changed(self, data: bytes) -> None:
+        del data
+        self.emit('track_changed')
+
+    def _on_track_title(self, data: bytes) -> None:
+        self.emit('track_title', data.decode("utf-8"))
+
+    def _on_track_duration(self, data: bytes) -> None:
+        self.emit('track_duration', struct.unpack_from('<i', data)[0])
+
+    def _on_track_position(self, data: bytes) -> None:
+        self.emit('track_position', struct.unpack_from('<i', data)[0])
+
+
+class GenericMediaControlServiceProxy(MediaControlServiceProxy):
+    SERVICE_CLASS = GenericMediaControlService
diff --git a/bumble/profiles/pacs.py b/bumble/profiles/pacs.py
new file mode 100644
index 0000000..adab088
--- /dev/null
+++ b/bumble/profiles/pacs.py
@@ -0,0 +1,210 @@
+# Copyright 2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for
+
+"""LE Audio - Published Audio Capabilities Service"""
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+from __future__ import annotations
+import dataclasses
+import logging
+import struct
+from typing import Optional, Sequence, Union
+
+from bumble.profiles.bap import AudioLocation, CodecSpecificCapabilities, ContextType
+from bumble.profiles import le_audio
+from bumble import gatt
+from bumble import gatt_client
+from bumble import hci
+
+
+# -----------------------------------------------------------------------------
+# Logging
+# -----------------------------------------------------------------------------
+logger = logging.getLogger(__name__)
+
+
+# -----------------------------------------------------------------------------
+@dataclasses.dataclass
+class PacRecord:
+    '''Published Audio Capabilities Service, Table 3.2/3.4.'''
+
+    coding_format: hci.CodingFormat
+    codec_specific_capabilities: Union[CodecSpecificCapabilities, bytes]
+    metadata: le_audio.Metadata = dataclasses.field(default_factory=le_audio.Metadata)
+
+    @classmethod
+    def from_bytes(cls, data: bytes) -> PacRecord:
+        offset, coding_format = hci.CodingFormat.parse_from_bytes(data, 0)
+        codec_specific_capabilities_size = data[offset]
+
+        offset += 1
+        codec_specific_capabilities_bytes = data[
+            offset : offset + codec_specific_capabilities_size
+        ]
+        offset += codec_specific_capabilities_size
+        metadata_size = data[offset]
+        offset += 1
+        metadata = le_audio.Metadata.from_bytes(data[offset : offset + metadata_size])
+
+        codec_specific_capabilities: Union[CodecSpecificCapabilities, bytes]
+        if coding_format.codec_id == hci.CodecID.VENDOR_SPECIFIC:
+            codec_specific_capabilities = codec_specific_capabilities_bytes
+        else:
+            codec_specific_capabilities = CodecSpecificCapabilities.from_bytes(
+                codec_specific_capabilities_bytes
+            )
+
+        return PacRecord(
+            coding_format=coding_format,
+            codec_specific_capabilities=codec_specific_capabilities,
+            metadata=metadata,
+        )
+
+    def __bytes__(self) -> bytes:
+        capabilities_bytes = bytes(self.codec_specific_capabilities)
+        metadata_bytes = bytes(self.metadata)
+        return (
+            bytes(self.coding_format)
+            + bytes([len(capabilities_bytes)])
+            + capabilities_bytes
+            + bytes([len(metadata_bytes)])
+            + metadata_bytes
+        )
+
+
+# -----------------------------------------------------------------------------
+# Server
+# -----------------------------------------------------------------------------
+class PublishedAudioCapabilitiesService(gatt.TemplateService):
+    UUID = gatt.GATT_PUBLISHED_AUDIO_CAPABILITIES_SERVICE
+
+    sink_pac: Optional[gatt.Characteristic]
+    sink_audio_locations: Optional[gatt.Characteristic]
+    source_pac: Optional[gatt.Characteristic]
+    source_audio_locations: Optional[gatt.Characteristic]
+    available_audio_contexts: gatt.Characteristic
+    supported_audio_contexts: gatt.Characteristic
+
+    def __init__(
+        self,
+        supported_source_context: ContextType,
+        supported_sink_context: ContextType,
+        available_source_context: ContextType,
+        available_sink_context: ContextType,
+        sink_pac: Sequence[PacRecord] = (),
+        sink_audio_locations: Optional[AudioLocation] = None,
+        source_pac: Sequence[PacRecord] = (),
+        source_audio_locations: Optional[AudioLocation] = None,
+    ) -> None:
+        characteristics = []
+
+        self.supported_audio_contexts = gatt.Characteristic(
+            uuid=gatt.GATT_SUPPORTED_AUDIO_CONTEXTS_CHARACTERISTIC,
+            properties=gatt.Characteristic.Properties.READ,
+            permissions=gatt.Characteristic.Permissions.READABLE,
+            value=struct.pack('<HH', supported_sink_context, supported_source_context),
+        )
+        characteristics.append(self.supported_audio_contexts)
+
+        self.available_audio_contexts = gatt.Characteristic(
+            uuid=gatt.GATT_AVAILABLE_AUDIO_CONTEXTS_CHARACTERISTIC,
+            properties=gatt.Characteristic.Properties.READ
+            | gatt.Characteristic.Properties.NOTIFY,
+            permissions=gatt.Characteristic.Permissions.READABLE,
+            value=struct.pack('<HH', available_sink_context, available_source_context),
+        )
+        characteristics.append(self.available_audio_contexts)
+
+        if sink_pac:
+            self.sink_pac = gatt.Characteristic(
+                uuid=gatt.GATT_SINK_PAC_CHARACTERISTIC,
+                properties=gatt.Characteristic.Properties.READ,
+                permissions=gatt.Characteristic.Permissions.READABLE,
+                value=bytes([len(sink_pac)]) + b''.join(map(bytes, sink_pac)),
+            )
+            characteristics.append(self.sink_pac)
+
+        if sink_audio_locations is not None:
+            self.sink_audio_locations = gatt.Characteristic(
+                uuid=gatt.GATT_SINK_AUDIO_LOCATION_CHARACTERISTIC,
+                properties=gatt.Characteristic.Properties.READ,
+                permissions=gatt.Characteristic.Permissions.READABLE,
+                value=struct.pack('<I', sink_audio_locations),
+            )
+            characteristics.append(self.sink_audio_locations)
+
+        if source_pac:
+            self.source_pac = gatt.Characteristic(
+                uuid=gatt.GATT_SOURCE_PAC_CHARACTERISTIC,
+                properties=gatt.Characteristic.Properties.READ,
+                permissions=gatt.Characteristic.Permissions.READABLE,
+                value=bytes([len(source_pac)]) + b''.join(map(bytes, source_pac)),
+            )
+            characteristics.append(self.source_pac)
+
+        if source_audio_locations is not None:
+            self.source_audio_locations = gatt.Characteristic(
+                uuid=gatt.GATT_SOURCE_AUDIO_LOCATION_CHARACTERISTIC,
+                properties=gatt.Characteristic.Properties.READ,
+                permissions=gatt.Characteristic.Permissions.READABLE,
+                value=struct.pack('<I', source_audio_locations),
+            )
+            characteristics.append(self.source_audio_locations)
+
+        super().__init__(characteristics)
+
+
+# -----------------------------------------------------------------------------
+# Client
+# -----------------------------------------------------------------------------
+class PublishedAudioCapabilitiesServiceProxy(gatt_client.ProfileServiceProxy):
+    SERVICE_CLASS = PublishedAudioCapabilitiesService
+
+    sink_pac: Optional[gatt_client.CharacteristicProxy] = None
+    sink_audio_locations: Optional[gatt_client.CharacteristicProxy] = None
+    source_pac: Optional[gatt_client.CharacteristicProxy] = None
+    source_audio_locations: Optional[gatt_client.CharacteristicProxy] = None
+    available_audio_contexts: gatt_client.CharacteristicProxy
+    supported_audio_contexts: gatt_client.CharacteristicProxy
+
+    def __init__(self, service_proxy: gatt_client.ServiceProxy):
+        self.service_proxy = service_proxy
+
+        self.available_audio_contexts = service_proxy.get_characteristics_by_uuid(
+            gatt.GATT_AVAILABLE_AUDIO_CONTEXTS_CHARACTERISTIC
+        )[0]
+        self.supported_audio_contexts = service_proxy.get_characteristics_by_uuid(
+            gatt.GATT_SUPPORTED_AUDIO_CONTEXTS_CHARACTERISTIC
+        )[0]
+
+        if characteristics := service_proxy.get_characteristics_by_uuid(
+            gatt.GATT_SINK_PAC_CHARACTERISTIC
+        ):
+            self.sink_pac = characteristics[0]
+
+        if characteristics := service_proxy.get_characteristics_by_uuid(
+            gatt.GATT_SOURCE_PAC_CHARACTERISTIC
+        ):
+            self.source_pac = characteristics[0]
+
+        if characteristics := service_proxy.get_characteristics_by_uuid(
+            gatt.GATT_SINK_AUDIO_LOCATION_CHARACTERISTIC
+        ):
+            self.sink_audio_locations = characteristics[0]
+
+        if characteristics := service_proxy.get_characteristics_by_uuid(
+            gatt.GATT_SOURCE_AUDIO_LOCATION_CHARACTERISTIC
+        ):
+            self.source_audio_locations = characteristics[0]
diff --git a/bumble/profiles/pbp.py b/bumble/profiles/pbp.py
new file mode 100644
index 0000000..058bd6d
--- /dev/null
+++ b/bumble/profiles/pbp.py
@@ -0,0 +1,46 @@
+# Copyright 2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+from __future__ import annotations
+import dataclasses
+import enum
+from typing_extensions import Self
+
+from bumble.profiles import le_audio
+
+
+# -----------------------------------------------------------------------------
+# Classes
+# -----------------------------------------------------------------------------
+@dataclasses.dataclass
+class PublicBroadcastAnnouncement:
+    class Features(enum.IntFlag):
+        ENCRYPTED = 1 << 0
+        STANDARD_QUALITY_CONFIGURATION = 1 << 1
+        HIGH_QUALITY_CONFIGURATION = 1 << 2
+
+    features: Features
+    metadata: le_audio.Metadata
+
+    @classmethod
+    def from_bytes(cls, data: bytes) -> Self:
+        features = cls.Features(data[0])
+        metadata_length = data[1]
+        metadata_ltv = data[1 : 1 + metadata_length]
+        return cls(
+            features=features, metadata=le_audio.Metadata.from_bytes(metadata_ltv)
+        )
diff --git a/bumble/profiles/tmap.py b/bumble/profiles/tmap.py
new file mode 100644
index 0000000..7b65015
--- /dev/null
+++ b/bumble/profiles/tmap.py
@@ -0,0 +1,89 @@
+# Copyright 2021-2022 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""LE Audio - Telephony and Media Audio Profile"""
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+import enum
+import logging
+import struct
+
+from bumble.gatt import (
+    TemplateService,
+    Characteristic,
+    DelegatedCharacteristicAdapter,
+    InvalidServiceError,
+    GATT_TELEPHONY_AND_MEDIA_AUDIO_SERVICE,
+    GATT_TMAP_ROLE_CHARACTERISTIC,
+)
+from bumble.gatt_client import ProfileServiceProxy, ServiceProxy
+
+
+# -----------------------------------------------------------------------------
+# Logging
+# -----------------------------------------------------------------------------
+logger = logging.getLogger(__name__)
+
+
+# -----------------------------------------------------------------------------
+# Classes
+# -----------------------------------------------------------------------------
+class Role(enum.IntFlag):
+    CALL_GATEWAY = 1 << 0
+    CALL_TERMINAL = 1 << 1
+    UNICAST_MEDIA_SENDER = 1 << 2
+    UNICAST_MEDIA_RECEIVER = 1 << 3
+    BROADCAST_MEDIA_SENDER = 1 << 4
+    BROADCAST_MEDIA_RECEIVER = 1 << 5
+
+
+# -----------------------------------------------------------------------------
+class TelephonyAndMediaAudioService(TemplateService):
+    UUID = GATT_TELEPHONY_AND_MEDIA_AUDIO_SERVICE
+
+    def __init__(self, role: Role):
+        self.role_characteristic = Characteristic(
+            GATT_TMAP_ROLE_CHARACTERISTIC,
+            Characteristic.Properties.READ,
+            Characteristic.READABLE,
+            struct.pack('<H', int(role)),
+        )
+
+        super().__init__([self.role_characteristic])
+
+
+# -----------------------------------------------------------------------------
+class TelephonyAndMediaAudioServiceProxy(ProfileServiceProxy):
+    SERVICE_CLASS = TelephonyAndMediaAudioService
+
+    role: DelegatedCharacteristicAdapter
+
+    def __init__(self, service_proxy: ServiceProxy):
+        self.service_proxy = service_proxy
+
+        if not (
+            characteristics := service_proxy.get_characteristics_by_uuid(
+                GATT_TMAP_ROLE_CHARACTERISTIC
+            )
+        ):
+            raise InvalidServiceError('TMAP Role characteristic not found')
+
+        self.role = DelegatedCharacteristicAdapter(
+            characteristics[0],
+            decode=lambda value: Role(
+                struct.unpack_from('<H', value, 0)[0],
+            ),
+        )
diff --git a/bumble/profiles/vcp.py b/bumble/profiles/vcp.py
index 0788219..57452d9 100644
--- a/bumble/profiles/vcp.py
+++ b/bumble/profiles/vcp.py
@@ -24,7 +24,7 @@ from bumble import device
 from bumble import gatt
 from bumble import gatt_client
 
-from typing import Optional
+from typing import Optional, Sequence
 
 # -----------------------------------------------------------------------------
 # Constants
@@ -88,6 +88,7 @@ class VolumeControlService(gatt.TemplateService):
         muted: int = 0,
         change_counter: int = 0,
         volume_flags: int = 0,
+        included_services: Sequence[gatt.Service] = (),
     ) -> None:
         self.step_size = step_size
         self.volume_setting = volume_setting
@@ -117,11 +118,12 @@ class VolumeControlService(gatt.TemplateService):
         )
 
         super().__init__(
-            [
+            characteristics=[
                 self.volume_state,
                 self.volume_control_point,
                 self.volume_flags,
-            ]
+            ],
+            included_services=list(included_services),
         )
 
     @property
diff --git a/bumble/rfcomm.py b/bumble/rfcomm.py
index 2d8a627..2de7374 100644
--- a/bumble/rfcomm.py
+++ b/bumble/rfcomm.py
@@ -36,7 +36,9 @@ from .core import (
     BT_RFCOMM_PROTOCOL_ID,
     BT_BR_EDR_TRANSPORT,
     BT_L2CAP_PROTOCOL_ID,
+    InvalidArgumentError,
     InvalidStateError,
+    InvalidPacketError,
     ProtocolError,
 )
 
@@ -335,7 +337,7 @@ class RFCOMM_Frame:
         frame = RFCOMM_Frame(frame_type, c_r, dlci, p_f, information)
         if frame.fcs != fcs:
             logger.warning(f'FCS mismatch: got {fcs:02X}, expected {frame.fcs:02X}')
-            raise ValueError('fcs mismatch')
+            raise InvalidPacketError('fcs mismatch')
 
         return frame
 
@@ -713,7 +715,7 @@ class DLC(EventEmitter):
                 # Automatically convert strings to bytes using UTF-8
                 data = data.encode('utf-8')
             else:
-                raise ValueError('write only accept bytes or strings')
+                raise InvalidArgumentError('write only accept bytes or strings')
 
         self.tx_buffer += data
         self.drained.clear()
@@ -734,7 +736,16 @@ class DLC(EventEmitter):
         self.emit('close')
 
     def __str__(self) -> str:
-        return f'DLC(dlci={self.dlci},state={self.state.name})'
+        return (
+            f'DLC(dlci={self.dlci}, '
+            f'state={self.state.name}, '
+            f'rx_max_frame_size={self.rx_max_frame_size}, '
+            f'rx_credits={self.rx_credits}, '
+            f'rx_max_credits={self.rx_max_credits}, '
+            f'tx_max_frame_size={self.tx_max_frame_size}, '
+            f'tx_credits={self.tx_credits}'
+            ')'
+        )
 
 
 # -----------------------------------------------------------------------------
diff --git a/bumble/sdp.py b/bumble/sdp.py
index 543c322..88c575d 100644
--- a/bumble/sdp.py
+++ b/bumble/sdp.py
@@ -23,7 +23,7 @@ from typing_extensions import Self
 
 from . import core, l2cap
 from .colors import color
-from .core import InvalidStateError
+from .core import InvalidStateError, InvalidArgumentError, InvalidPacketError
 from .hci import HCI_Object, name_or_number, key_with_value
 
 if TYPE_CHECKING:
@@ -189,7 +189,9 @@ class DataElement:
         self.bytes = None
         if element_type in (DataElement.UNSIGNED_INTEGER, DataElement.SIGNED_INTEGER):
             if value_size is None:
-                raise ValueError('integer types must have a value size specified')
+                raise InvalidArgumentError(
+                    'integer types must have a value size specified'
+                )
 
     @staticmethod
     def nil() -> DataElement:
@@ -265,7 +267,7 @@ class DataElement:
         if len(data) == 8:
             return struct.unpack('>Q', data)[0]
 
-        raise ValueError(f'invalid integer length {len(data)}')
+        raise InvalidPacketError(f'invalid integer length {len(data)}')
 
     @staticmethod
     def signed_integer_from_bytes(data):
@@ -281,7 +283,7 @@ class DataElement:
         if len(data) == 8:
             return struct.unpack('>q', data)[0]
 
-        raise ValueError(f'invalid integer length {len(data)}')
+        raise InvalidPacketError(f'invalid integer length {len(data)}')
 
     @staticmethod
     def list_from_bytes(data):
@@ -354,7 +356,7 @@ class DataElement:
             data = b''
         elif self.type == DataElement.UNSIGNED_INTEGER:
             if self.value < 0:
-                raise ValueError('UNSIGNED_INTEGER cannot be negative')
+                raise InvalidArgumentError('UNSIGNED_INTEGER cannot be negative')
 
             if self.value_size == 1:
                 data = struct.pack('B', self.value)
@@ -365,7 +367,7 @@ class DataElement:
             elif self.value_size == 8:
                 data = struct.pack('>Q', self.value)
             else:
-                raise ValueError('invalid value_size')
+                raise InvalidArgumentError('invalid value_size')
         elif self.type == DataElement.SIGNED_INTEGER:
             if self.value_size == 1:
                 data = struct.pack('b', self.value)
@@ -376,7 +378,7 @@ class DataElement:
             elif self.value_size == 8:
                 data = struct.pack('>q', self.value)
             else:
-                raise ValueError('invalid value_size')
+                raise InvalidArgumentError('invalid value_size')
         elif self.type == DataElement.UUID:
             data = bytes(reversed(bytes(self.value)))
         elif self.type == DataElement.URL:
@@ -392,7 +394,7 @@ class DataElement:
         size_bytes = b''
         if self.type == DataElement.NIL:
             if size != 0:
-                raise ValueError('NIL must be empty')
+                raise InvalidArgumentError('NIL must be empty')
             size_index = 0
         elif self.type in (
             DataElement.UNSIGNED_INTEGER,
@@ -410,7 +412,7 @@ class DataElement:
             elif size == 16:
                 size_index = 4
             else:
-                raise ValueError('invalid data size')
+                raise InvalidArgumentError('invalid data size')
         elif self.type in (
             DataElement.TEXT_STRING,
             DataElement.SEQUENCE,
@@ -427,10 +429,10 @@ class DataElement:
                 size_index = 7
                 size_bytes = struct.pack('>I', size)
             else:
-                raise ValueError('invalid data size')
+                raise InvalidArgumentError('invalid data size')
         elif self.type == DataElement.BOOLEAN:
             if size != 1:
-                raise ValueError('boolean must be 1 byte')
+                raise InvalidArgumentError('boolean must be 1 byte')
             size_index = 0
 
         self.bytes = bytes([self.type << 3 | size_index]) + size_bytes + data
diff --git a/bumble/smp.py b/bumble/smp.py
index 3a88a31..c055e71 100644
--- a/bumble/smp.py
+++ b/bumble/smp.py
@@ -55,6 +55,7 @@ from .core import (
     BT_CENTRAL_ROLE,
     BT_LE_TRANSPORT,
     AdvertisingData,
+    InvalidArgumentError,
     ProtocolError,
     name_or_number,
 )
@@ -763,11 +764,16 @@ class Session:
         self.peer_io_capability = SMP_NO_INPUT_NO_OUTPUT_IO_CAPABILITY
 
         # OOB
-        self.oob_data_flag = 0 if pairing_config.oob is None else 1
+        self.oob_data_flag = (
+            1 if pairing_config.oob and pairing_config.oob.peer_data else 0
+        )
 
         # Set up addresses
-        self_address = connection.self_address
+        self_address = connection.self_resolvable_address or connection.self_address
         peer_address = connection.peer_resolvable_address or connection.peer_address
+        logger.debug(
+            f"pairing with self_address={self_address}, peer_address={peer_address}"
+        )
         if self.is_initiator:
             self.ia = bytes(self_address)
             self.iat = 1 if self_address.is_random else 0
@@ -784,7 +790,7 @@ class Session:
             self.peer_oob_data = pairing_config.oob.peer_data
             if pairing_config.sc:
                 if pairing_config.oob.our_context is None:
-                    raise ValueError(
+                    raise InvalidArgumentError(
                         "oob pairing config requires a context when sc is True"
                     )
                 self.r = pairing_config.oob.our_context.r
@@ -793,7 +799,7 @@ class Session:
                     self.tk = pairing_config.oob.legacy_context.tk
             else:
                 if pairing_config.oob.legacy_context is None:
-                    raise ValueError(
+                    raise InvalidArgumentError(
                         "oob pairing config requires a legacy context when sc is False"
                     )
                 self.r = bytes(16)
@@ -1010,8 +1016,10 @@ class Session:
         self.send_command(response)
 
     def send_pairing_confirm_command(self) -> None:
-        self.r = crypto.r()
-        logger.debug(f'generated random: {self.r.hex()}')
+
+        if self.pairing_method != PairingMethod.OOB:
+            self.r = crypto.r()
+            logger.debug(f'generated random: {self.r.hex()}')
 
         if self.sc:
 
@@ -1074,11 +1082,19 @@ class Session:
         )
 
     def send_identity_address_command(self) -> None:
-        identity_address = {
-            None: self.connection.self_address,
-            Address.PUBLIC_DEVICE_ADDRESS: self.manager.device.public_address,
-            Address.RANDOM_DEVICE_ADDRESS: self.manager.device.random_address,
-        }[self.pairing_config.identity_address_type]
+        if self.pairing_config.identity_address_type == Address.PUBLIC_DEVICE_ADDRESS:
+            identity_address = self.manager.device.public_address
+        elif self.pairing_config.identity_address_type == Address.RANDOM_DEVICE_ADDRESS:
+            identity_address = self.manager.device.static_address
+        else:
+            # No identity address type set. If the controller has a public address, it
+            # will be more responsible to be the identity address.
+            if self.manager.device.public_address != Address.ANY:
+                logger.debug("No identity address type set, using PUBLIC")
+                identity_address = self.manager.device.public_address
+            else:
+                logger.debug("No identity address type set, using RANDOM")
+                identity_address = self.manager.device.static_address
         self.send_command(
             SMP_Identity_Address_Information_Command(
                 addr_type=identity_address.address_type,
@@ -1723,7 +1739,6 @@ class Session:
         if self.pairing_method in (
             PairingMethod.JUST_WORKS,
             PairingMethod.NUMERIC_COMPARISON,
-            PairingMethod.OOB,
         ):
             ra = bytes(16)
             rb = ra
@@ -1731,6 +1746,22 @@ class Session:
             assert self.passkey
             ra = self.passkey.to_bytes(16, byteorder='little')
             rb = ra
+        elif self.pairing_method == PairingMethod.OOB:
+            if self.is_initiator:
+                if self.peer_oob_data:
+                    rb = self.peer_oob_data.r
+                    ra = self.r
+                else:
+                    rb = bytes(16)
+                    ra = self.r
+            else:
+                if self.peer_oob_data:
+                    ra = self.peer_oob_data.r
+                    rb = self.r
+                else:
+                    ra = bytes(16)
+                    rb = self.r
+
         else:
             return
 
diff --git a/bumble/snoop.py b/bumble/snoop.py
index 4b331d2..326603f 100644
--- a/bumble/snoop.py
+++ b/bumble/snoop.py
@@ -23,6 +23,7 @@ import datetime
 from typing import BinaryIO, Generator
 import os
 
+from bumble import core
 from bumble.hci import HCI_COMMAND_PACKET, HCI_EVENT_PACKET
 
 
@@ -138,13 +139,13 @@ def create_snooper(spec: str) -> Generator[Snooper, None, None]:
 
     """
     if ':' not in spec:
-        raise ValueError('snooper type prefix missing')
+        raise core.InvalidArgumentError('snooper type prefix missing')
 
     snooper_type, snooper_args = spec.split(':', maxsplit=1)
 
     if snooper_type == 'btsnoop':
         if ':' not in snooper_args:
-            raise ValueError('I/O type for btsnoop snooper type missing')
+            raise core.InvalidArgumentError('I/O type for btsnoop snooper type missing')
 
         io_type, io_name = snooper_args.split(':', maxsplit=1)
         if io_type == 'file':
@@ -165,6 +166,6 @@ def create_snooper(spec: str) -> Generator[Snooper, None, None]:
                 _SNOOPER_INSTANCE_COUNT -= 1
                 return
 
-        raise ValueError(f'I/O type {io_type} not supported')
+        raise core.InvalidArgumentError(f'I/O type {io_type} not supported')
 
-    raise ValueError(f'snooper type {snooper_type} not found')
+    raise core.InvalidArgumentError(f'snooper type {snooper_type} not found')
diff --git a/bumble/transport/__init__.py b/bumble/transport/__init__.py
index 6a9a6b5..0d42343 100644
--- a/bumble/transport/__init__.py
+++ b/bumble/transport/__init__.py
@@ -20,7 +20,7 @@ import logging
 import os
 from typing import Optional
 
-from .common import Transport, AsyncPipeSink, SnoopingTransport
+from .common import Transport, AsyncPipeSink, SnoopingTransport, TransportSpecError
 from ..snoop import create_snooper
 
 # -----------------------------------------------------------------------------
@@ -180,7 +180,13 @@ async def _open_transport(scheme: str, spec: Optional[str]) -> Transport:
 
         return await open_android_netsim_transport(spec)
 
-    raise ValueError('unknown transport scheme')
+    if scheme == 'unix':
+        from .unix import open_unix_client_transport
+
+        assert spec
+        return await open_unix_client_transport(spec)
+
+    raise TransportSpecError('unknown transport scheme')
 
 
 # -----------------------------------------------------------------------------
diff --git a/bumble/transport/android_emulator.py b/bumble/transport/android_emulator.py
index 9cd7ec2..d2bc8ef 100644
--- a/bumble/transport/android_emulator.py
+++ b/bumble/transport/android_emulator.py
@@ -20,7 +20,13 @@ import grpc.aio
 
 from typing import Optional, Union
 
-from .common import PumpedTransport, PumpedPacketSource, PumpedPacketSink, Transport
+from .common import (
+    PumpedTransport,
+    PumpedPacketSource,
+    PumpedPacketSink,
+    Transport,
+    TransportSpecError,
+)
 
 # pylint: disable=no-name-in-module
 from .grpc_protobuf.emulated_bluetooth_pb2_grpc import EmulatedBluetoothServiceStub
@@ -77,7 +83,7 @@ async def open_android_emulator_transport(spec: Optional[str]) -> Transport:
             elif ':' in param:
                 server_host, server_port = param.split(':')
             else:
-                raise ValueError('invalid parameter')
+                raise TransportSpecError('invalid parameter')
 
     # Connect to the gRPC server
     server_address = f'{server_host}:{server_port}'
@@ -94,7 +100,7 @@ async def open_android_emulator_transport(spec: Optional[str]) -> Transport:
         service = VhciForwardingServiceStub(channel)
         hci_device = HciDevice(service.attachVhci())
     else:
-        raise ValueError('invalid mode')
+        raise TransportSpecError('invalid mode')
 
     # Create the transport object
     class EmulatorTransport(PumpedTransport):
diff --git a/bumble/transport/android_netsim.py b/bumble/transport/android_netsim.py
index e9d36cd..264266d 100644
--- a/bumble/transport/android_netsim.py
+++ b/bumble/transport/android_netsim.py
@@ -31,6 +31,8 @@ from .common import (
     PumpedPacketSource,
     PumpedPacketSink,
     Transport,
+    TransportSpecError,
+    TransportInitError,
 )
 
 # pylint: disable=no-name-in-module
@@ -135,7 +137,7 @@ async def open_android_netsim_controller_transport(
     server_host: Optional[str], server_port: int, options: Dict[str, str]
 ) -> Transport:
     if not server_port:
-        raise ValueError('invalid port')
+        raise TransportSpecError('invalid port')
     if server_host == '_' or not server_host:
         server_host = 'localhost'
 
@@ -288,7 +290,7 @@ async def open_android_netsim_host_transport_with_address(
         instance_number = 0 if options is None else int(options.get('instance', '0'))
         server_port = find_grpc_port(instance_number)
         if not server_port:
-            raise RuntimeError('gRPC server port not found')
+            raise TransportInitError('gRPC server port not found')
 
     # Connect to the gRPC server
     server_address = f'{server_host}:{server_port}'
@@ -326,7 +328,7 @@ async def open_android_netsim_host_transport_with_channel(
 
             if response_type == 'error':
                 logger.warning(f'received error: {response.error}')
-                raise RuntimeError(response.error)
+                raise TransportInitError(response.error)
 
             if response_type == 'hci_packet':
                 return (
@@ -334,7 +336,7 @@ async def open_android_netsim_host_transport_with_channel(
                     + response.hci_packet.packet
                 )
 
-            raise ValueError('unsupported response type')
+            raise TransportSpecError('unsupported response type')
 
         async def write(self, packet):
             await self.hci_device.write(
@@ -429,7 +431,7 @@ async def open_android_netsim_transport(spec: Optional[str]) -> Transport:
     options: Dict[str, str] = {}
     for param in params[params_offset:]:
         if '=' not in param:
-            raise ValueError('invalid parameter, expected <name>=<value>')
+            raise TransportSpecError('invalid parameter, expected <name>=<value>')
         option_name, option_value = param.split('=')
         options[option_name] = option_value
 
@@ -440,7 +442,7 @@ async def open_android_netsim_transport(spec: Optional[str]) -> Transport:
         )
     if mode == 'controller':
         if host is None:
-            raise ValueError('<host>:<port> missing')
+            raise TransportSpecError('<host>:<port> missing')
         return await open_android_netsim_controller_transport(host, port, options)
 
-    raise ValueError('invalid mode option')
+    raise TransportSpecError('invalid mode option')
diff --git a/bumble/transport/common.py b/bumble/transport/common.py
index ffbf7b0..f2c7fcb 100644
--- a/bumble/transport/common.py
+++ b/bumble/transport/common.py
@@ -23,6 +23,7 @@ import logging
 import io
 from typing import Any, ContextManager, Tuple, Optional, Protocol, Dict
 
+from bumble import core
 from bumble import hci
 from bumble.colors import color
 from bumble.snoop import Snooper
@@ -49,10 +50,16 @@ HCI_PACKET_INFO: Dict[int, Tuple[int, int, str]] = {
 # -----------------------------------------------------------------------------
 # Errors
 # -----------------------------------------------------------------------------
-class TransportLostError(Exception):
-    """
-    The Transport has been lost/disconnected.
-    """
+class TransportLostError(core.BaseBumbleError, RuntimeError):
+    """The Transport has been lost/disconnected."""
+
+
+class TransportInitError(core.BaseBumbleError, RuntimeError):
+    """Error raised when the transport cannot be initialized."""
+
+
+class TransportSpecError(core.BaseBumbleError, ValueError):
+    """Error raised when the transport spec is invalid."""
 
 
 # -----------------------------------------------------------------------------
@@ -132,7 +139,9 @@ class PacketParser:
                         packet_type
                     ) or self.extended_packet_info.get(packet_type)
                     if self.packet_info is None:
-                        raise ValueError(f'invalid packet type {packet_type}')
+                        raise core.InvalidPacketError(
+                            f'invalid packet type {packet_type}'
+                        )
                     self.state = PacketParser.NEED_LENGTH
                     self.bytes_needed = self.packet_info[0] + self.packet_info[1]
                 elif self.state == PacketParser.NEED_LENGTH:
@@ -178,19 +187,19 @@ class PacketReader:
         # Get the packet info based on its type
         packet_info = HCI_PACKET_INFO.get(packet_type[0])
         if packet_info is None:
-            raise ValueError(f'invalid packet type {packet_type[0]} found')
+            raise core.InvalidPacketError(f'invalid packet type {packet_type[0]} found')
 
         # Read the header (that includes the length)
         header_size = packet_info[0] + packet_info[1]
         header = self.source.read(header_size)
         if len(header) != header_size:
-            raise ValueError('packet too short')
+            raise core.InvalidPacketError('packet too short')
 
         # Read the body
         body_length = struct.unpack_from(packet_info[2], header, packet_info[1])[0]
         body = self.source.read(body_length)
         if len(body) != body_length:
-            raise ValueError('packet too short')
+            raise core.InvalidPacketError('packet too short')
 
         return packet_type + header + body
 
@@ -211,7 +220,7 @@ class AsyncPacketReader:
         # Get the packet info based on its type
         packet_info = HCI_PACKET_INFO.get(packet_type[0])
         if packet_info is None:
-            raise ValueError(f'invalid packet type {packet_type[0]} found')
+            raise core.InvalidPacketError(f'invalid packet type {packet_type[0]} found')
 
         # Read the header (that includes the length)
         header_size = packet_info[0] + packet_info[1]
@@ -239,26 +248,28 @@ class AsyncPipeSink:
 
 
 # -----------------------------------------------------------------------------
-class ParserSource:
+class BaseSource:
     """
     Base class designed to be subclassed by transport-specific source classes
     """
 
     terminated: asyncio.Future[None]
-    parser: PacketParser
+    sink: Optional[TransportSink]
 
     def __init__(self) -> None:
-        self.parser = PacketParser()
         self.terminated = asyncio.get_running_loop().create_future()
+        self.sink = None
 
     def set_packet_sink(self, sink: TransportSink) -> None:
-        self.parser.set_packet_sink(sink)
+        self.sink = sink
 
     def on_transport_lost(self) -> None:
-        self.terminated.set_result(None)
-        if self.parser.sink:
-            if hasattr(self.parser.sink, 'on_transport_lost'):
-                self.parser.sink.on_transport_lost()
+        if not self.terminated.done():
+            self.terminated.set_result(None)
+
+        if self.sink:
+            if hasattr(self.sink, 'on_transport_lost'):
+                self.sink.on_transport_lost()
 
     async def wait_for_termination(self) -> None:
         """
@@ -271,6 +282,23 @@ class ParserSource:
         pass
 
 
+# -----------------------------------------------------------------------------
+class ParserSource(BaseSource):
+    """
+    Base class for sources that use an HCI parser.
+    """
+
+    parser: PacketParser
+
+    def __init__(self) -> None:
+        super().__init__()
+        self.parser = PacketParser()
+
+    def set_packet_sink(self, sink: TransportSink) -> None:
+        super().set_packet_sink(sink)
+        self.parser.set_packet_sink(sink)
+
+
 # -----------------------------------------------------------------------------
 class StreamPacketSource(asyncio.Protocol, ParserSource):
     def data_received(self, data: bytes) -> None:
@@ -420,7 +448,7 @@ class SnoopingTransport(Transport):
             return SnoopingTransport(
                 transport, exit_stack.enter_context(snooper), exit_stack.pop_all().close
             )
-        raise RuntimeError('unexpected code path')  # Satisfy the type checker
+        raise core.UnreachableError()  # Satisfy the type checker
 
     class Source:
         sink: TransportSink
diff --git a/bumble/transport/pyusb.py b/bumble/transport/pyusb.py
index 68a1dfd..26f9991 100644
--- a/bumble/transport/pyusb.py
+++ b/bumble/transport/pyusb.py
@@ -23,13 +23,13 @@ import time
 import usb.core
 import usb.util
 
-from typing import Optional
+from typing import Optional, Set
 from usb.core import Device as UsbDevice
 from usb.core import USBError
 from usb.util import CTRL_TYPE_CLASS, CTRL_RECIPIENT_OTHER
 from usb.legacy import REQ_SET_FEATURE, REQ_CLEAR_FEATURE, CLASS_HUB
 
-from .common import Transport, ParserSource
+from .common import Transport, ParserSource, TransportInitError
 from .. import hci
 from ..colors import color
 
@@ -46,6 +46,11 @@ RESET_DELAY = 3
 # -----------------------------------------------------------------------------
 logger = logging.getLogger(__name__)
 
+# -----------------------------------------------------------------------------
+# Global
+# -----------------------------------------------------------------------------
+devices_in_use: Set[int] = set()
+
 
 # -----------------------------------------------------------------------------
 async def open_pyusb_transport(spec: str) -> Transport:
@@ -216,6 +221,7 @@ async def open_pyusb_transport(spec: str) -> Transport:
         async def close(self):
             await self.source.stop()
             await self.sink.stop()
+            devices_in_use.remove(device.address)
             usb.util.release_interface(self.device, 0)
 
     usb_find = usb.core.find
@@ -233,7 +239,18 @@ async def open_pyusb_transport(spec: str) -> Transport:
         spec = spec[1:]
     if ':' in spec:
         vendor_id, product_id = spec.split(':')
-        device = usb_find(idVendor=int(vendor_id, 16), idProduct=int(product_id, 16))
+        device = None
+        devices = usb_find(
+            find_all=True, idVendor=int(vendor_id, 16), idProduct=int(product_id, 16)
+        )
+        for d in devices:
+            if d.address in devices_in_use:
+                continue
+            device = d
+            devices_in_use.add(d.address)
+            break
+        if device is None:
+            raise ValueError('device already in use')
     elif '-' in spec:
 
         def device_path(device):
@@ -259,7 +276,7 @@ async def open_pyusb_transport(spec: str) -> Transport:
             device = None
 
     if device is None:
-        raise ValueError('device not found')
+        raise TransportInitError('device not found')
     logger.debug(f'USB Device: {device}')
 
     # Power Cycle the device
diff --git a/bumble/transport/unix.py b/bumble/transport/unix.py
new file mode 100644
index 0000000..973872b
--- /dev/null
+++ b/bumble/transport/unix.py
@@ -0,0 +1,56 @@
+# Copyright 2021-2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+import asyncio
+import logging
+
+from .common import Transport, StreamPacketSource, StreamPacketSink
+
+# -----------------------------------------------------------------------------
+# Logging
+# -----------------------------------------------------------------------------
+logger = logging.getLogger(__name__)
+
+
+# -----------------------------------------------------------------------------
+async def open_unix_client_transport(spec: str) -> Transport:
+    '''Open a UNIX socket client transport.
+
+    The parameter is the path of unix socket. For abstract socket, the first character
+    needs to be '@'.
+
+    Example:
+        * /tmp/hci.socket
+        * @hci_socket
+    '''
+
+    class UnixPacketSource(StreamPacketSource):
+        def connection_lost(self, exc):
+            logger.debug(f'connection lost: {exc}')
+            self.on_transport_lost()
+
+    # For abstract socket, the first character should be null character.
+    if spec.startswith('@'):
+        spec = '\0' + spec[1:]
+
+    (
+        unix_transport,
+        packet_source,
+    ) = await asyncio.get_running_loop().create_unix_connection(UnixPacketSource, spec)
+    packet_sink = StreamPacketSink(unix_transport)
+
+    return Transport(packet_source, packet_sink)
diff --git a/bumble/transport/usb.py b/bumble/transport/usb.py
index 69e9649..0b865cf 100644
--- a/bumble/transport/usb.py
+++ b/bumble/transport/usb.py
@@ -15,19 +15,18 @@
 # -----------------------------------------------------------------------------
 # Imports
 # -----------------------------------------------------------------------------
+from __future__ import annotations
 import asyncio
 import logging
 import threading
-import collections
 import ctypes
 import platform
 
 import usb1
 
-from bumble.transport.common import Transport, ParserSource
+from bumble.transport.common import Transport, BaseSource, TransportInitError
 from bumble import hci
 from bumble.colors import color
-from bumble.utils import AsyncRunner
 
 
 # -----------------------------------------------------------------------------
@@ -115,13 +114,17 @@ async def open_usb_transport(spec: str) -> Transport:
             self.device = device
             self.acl_out = acl_out
             self.acl_out_transfer = device.getTransfer()
-            self.packets = collections.deque()  # Queue of packets waiting to be sent
+            self.acl_out_transfer_ready = asyncio.Semaphore(1)
+            self.packets: asyncio.Queue[bytes] = (
+                asyncio.Queue()
+            )  # Queue of packets waiting to be sent
             self.loop = asyncio.get_running_loop()
+            self.queue_task = None
             self.cancel_done = self.loop.create_future()
             self.closed = False
 
         def start(self):
-            pass
+            self.queue_task = asyncio.create_task(self.process_queue())
 
         def on_packet(self, packet):
             # Ignore packets if we're closed
@@ -133,62 +136,64 @@ async def open_usb_transport(spec: str) -> Transport:
                 return
 
             # Queue the packet
-            self.packets.append(packet)
-            if len(self.packets) == 1:
-                # The queue was previously empty, re-prime the pump
-                self.process_queue()
+            self.packets.put_nowait(packet)
 
         def transfer_callback(self, transfer):
+            self.loop.call_soon_threadsafe(self.acl_out_transfer_ready.release)
             status = transfer.getStatus()
 
             # pylint: disable=no-member
-            if status == usb1.TRANSFER_COMPLETED:
-                self.loop.call_soon_threadsafe(self.on_packet_sent)
-            elif status == usb1.TRANSFER_CANCELLED:
+            if status == usb1.TRANSFER_CANCELLED:
                 self.loop.call_soon_threadsafe(self.cancel_done.set_result, None)
-            else:
+                return
+
+            if status != usb1.TRANSFER_COMPLETED:
                 logger.warning(
                     color(f'!!! OUT transfer not completed: status={status}', 'red')
                 )
 
-        def on_packet_sent(self):
-            if self.packets:
-                self.packets.popleft()
-                self.process_queue()
-
-        def process_queue(self):
-            if len(self.packets) == 0:
-                return  # Nothing to do
-
-            packet = self.packets[0]
-            packet_type = packet[0]
-            if packet_type == hci.HCI_ACL_DATA_PACKET:
-                self.acl_out_transfer.setBulk(
-                    self.acl_out, packet[1:], callback=self.transfer_callback
-                )
-                self.acl_out_transfer.submit()
-            elif packet_type == hci.HCI_COMMAND_PACKET:
-                self.acl_out_transfer.setControl(
-                    USB_RECIPIENT_DEVICE | USB_REQUEST_TYPE_CLASS,
-                    0,
-                    0,
-                    0,
-                    packet[1:],
-                    callback=self.transfer_callback,
-                )
-                self.acl_out_transfer.submit()
-            else:
-                logger.warning(color(f'unsupported packet type {packet_type}', 'red'))
+        async def process_queue(self):
+            while True:
+                # Wait for a packet to transfer.
+                packet = await self.packets.get()
+
+                # Wait until we can start a transfer.
+                await self.acl_out_transfer_ready.acquire()
+
+                # Transfer the packet.
+                packet_type = packet[0]
+                if packet_type == hci.HCI_ACL_DATA_PACKET:
+                    self.acl_out_transfer.setBulk(
+                        self.acl_out, packet[1:], callback=self.transfer_callback
+                    )
+                    self.acl_out_transfer.submit()
+                elif packet_type == hci.HCI_COMMAND_PACKET:
+                    self.acl_out_transfer.setControl(
+                        USB_RECIPIENT_DEVICE | USB_REQUEST_TYPE_CLASS,
+                        0,
+                        0,
+                        0,
+                        packet[1:],
+                        callback=self.transfer_callback,
+                    )
+                    self.acl_out_transfer.submit()
+                else:
+                    logger.warning(
+                        color(f'unsupported packet type {packet_type}', 'red')
+                    )
 
         def close(self):
             self.closed = True
+            if self.queue_task:
+                self.queue_task.cancel()
 
         async def terminate(self):
             if not self.closed:
                 self.close()
 
             # Empty the packet queue so that we don't send any more data
-            self.packets.clear()
+            while not self.packets.empty():
+                self.packets.get_nowait()
 
             # If we have a transfer in flight, cancel it
             if self.acl_out_transfer.isSubmitted():
@@ -203,7 +208,7 @@ async def open_usb_transport(spec: str) -> Transport:
                 except usb1.USBError:
                     logger.debug('OUT transfer likely already completed')
 
-    class UsbPacketSource(asyncio.Protocol, ParserSource):
+    class UsbPacketSource(asyncio.Protocol, BaseSource):
         def __init__(self, device, metadata, acl_in, events_in):
             super().__init__()
             self.device = device
@@ -280,7 +285,13 @@ async def open_usb_transport(spec: str) -> Transport:
                     packet = await self.queue.get()
                 except asyncio.CancelledError:
                     return
-                self.parser.feed_data(packet)
+                if self.sink:
+                    try:
+                        self.sink.on_packet(packet)
+                    except Exception as error:
+                        logger.exception(
+                            color(f'!!! Exception in sink.on_packet: {error}', 'red')
+                        )
 
         def close(self):
             self.closed = True
@@ -442,7 +453,7 @@ async def open_usb_transport(spec: str) -> Transport:
 
         if found is None:
             context.close()
-            raise ValueError('device not found')
+            raise TransportInitError('device not found')
 
         logger.debug(f'USB Device: {found}')
 
@@ -507,7 +518,7 @@ async def open_usb_transport(spec: str) -> Transport:
 
         endpoints = find_endpoints(found)
         if endpoints is None:
-            raise ValueError('no compatible interface found for device')
+            raise TransportInitError('no compatible interface found for device')
         (configuration, interface, setting, acl_in, acl_out, events_in) = endpoints
         logger.debug(
             f'selected endpoints: configuration={configuration}, '
diff --git a/docs/images/favicon.ico b/docs/images/favicon.ico
new file mode 100644
index 0000000..8b83a50
Binary files /dev/null and b/docs/images/favicon.ico differ
diff --git a/examples/asha_sink.html b/examples/asha_sink.html
new file mode 100644
index 0000000..410fd1e
--- /dev/null
+++ b/examples/asha_sink.html
@@ -0,0 +1,95 @@
+<html data-bs-theme="dark">
+
+<head>
+    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"
+        integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
+    <script src="https://unpkg.com/pcm-player"></script>
+</head>
+
+<body>
+    <nav class="navbar navbar-dark bg-primary">
+        <div class="container">
+            <span class="navbar-brand mb-0 h1">Bumble ASHA Sink</span>
+        </div>
+    </nav>
+    <br>
+
+    <div class="container">
+
+        <div class="row">
+            <div class="col-auto">
+                <button id="connect-audio" class="btn btn-danger" onclick="connectAudio()">Connect Audio</button>
+            </div>
+        </div>
+
+        <hr>
+
+        <div class="row">
+            <div class="col-4">
+                <label class="form-label">Browser Gain</label>
+                <input type="range" class="form-range" id="browser-gain" min="0" max="2" value="1" step="0.1"
+                    onchange="setGain()">
+            </div>
+        </div>
+
+        <hr>
+
+        <div id="socketStateContainer" class="bg-body-tertiary p-3 rounded-2">
+            <h3>Log</h3>
+            <code id="log" style="white-space: pre-line;"></code>
+        </div>
+    </div>
+
+
+    <script>
+        let atResponseInput = document.getElementById("at_response")
+        let gainInput = document.getElementById('browser-gain')
+        let log = document.getElementById("log")
+        let socket = new WebSocket('ws://localhost:8888');
+        let sampleRate = 0;
+        let player;
+
+        socket.binaryType = "arraybuffer";
+        socket.onopen = _ => {
+            log.textContent += 'SOCKET OPEN\n'
+        }
+        socket.onclose = _ => {
+            log.textContent += 'SOCKET CLOSED\n'
+        }
+        socket.onerror = (error) => {
+            log.textContent += 'SOCKET ERROR\n'
+            console.log(`ERROR: ${error}`)
+        }
+        socket.onmessage = function (message) {
+            if (typeof message.data === 'string' || message.data instanceof String) {
+                log.textContent += `<-- ${event.data}\n`
+            } else {
+                // BINARY audio data.
+                if (player == null) return;
+                player.feed(message.data);
+            }
+        };
+
+        function connectAudio() {
+            player = new PCMPlayer({
+                inputCodec: 'Int16',
+                channels: 1,
+                sampleRate: 16000,
+                flushTime: 20,
+            });
+            player.volume(gainInput.value);
+            const button = document.getElementById("connect-audio")
+            button.disabled = true;
+            button.textContent = "Audio Connected";
+        }
+
+        function setGain() {
+            if (player != null) {
+                player.volume(gainInput.value);
+            }
+        }
+    </script>
+    </div>
+</body>
+
+</html>
\ No newline at end of file
diff --git a/examples/asha_sink1.json b/examples/asha_sink1.json
index badef8b..dc383e8 100644
--- a/examples/asha_sink1.json
+++ b/examples/asha_sink1.json
@@ -1,5 +1,6 @@
 {
     "name": "Bumble Aid Left",
     "address": "F1:F2:F3:F4:F5:F6",
+    "identity_address_type": 1,
     "keystore": "JsonKeyStore"
-}
+}
\ No newline at end of file
diff --git a/examples/asha_sink2.json b/examples/asha_sink2.json
index 785d406..b8dc6b8 100644
--- a/examples/asha_sink2.json
+++ b/examples/asha_sink2.json
@@ -1,5 +1,6 @@
 {
     "name": "Bumble Aid Right",
     "address": "F7:F8:F9:FA:FB:FC",
+    "identity_address_type": 1,
     "keystore": "JsonKeyStore"
-}
+}
\ No newline at end of file
diff --git a/examples/device_with_rpa.json b/examples/device_with_rpa.json
new file mode 100644
index 0000000..56f1ec2
--- /dev/null
+++ b/examples/device_with_rpa.json
@@ -0,0 +1,7 @@
+{
+    "name": "Bumble",
+    "address": "F0:F1:F2:F3:F4:F5",
+    "keystore": "JsonKeyStore",
+    "irk": "865F81FF5A8B486EAAE29A27AD9F77DC",
+    "le_privacy_enabled": true
+}
diff --git a/examples/leaudio.json b/examples/leaudio.json
index ad5f6c8..3c48166 100644
--- a/examples/leaudio.json
+++ b/examples/leaudio.json
@@ -3,5 +3,6 @@
     "keystore": "JsonKeyStore",
     "address": "F0:F1:F2:F3:F4:FA",
     "class_of_device": 2376708,
+    "cis_enabled": true,
     "advertising_interval": 100
 }
diff --git a/examples/mcp_server.html b/examples/mcp_server.html
new file mode 100644
index 0000000..b0b98d7
--- /dev/null
+++ b/examples/mcp_server.html
@@ -0,0 +1,83 @@
+<html data-bs-theme="dark">
+
+<head>
+    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"
+        integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
+</head>
+
+<body>
+    <nav class="navbar navbar-dark bg-primary">
+        <div class="container">
+            <span class="navbar-brand mb-0 h1">Bumble LEA Media Control Client</span>
+        </div>
+    </nav>
+    <br>
+
+    <div class="container">
+
+        <label class="form-label">Server Port</label>
+        <div class="input-group mb-3">
+            <input type="text" class="form-control" aria-label="Port Number" value="8989" id="port">
+            <button class="btn btn-primary" type="button" onclick="connect()">Connect</button>
+        </div>
+
+        <button class="btn btn-primary" onclick="send_opcode(0x01)">Play</button>
+        <button class="btn btn-primary" onclick="send_opcode(0x02)">Pause</button>
+        <button class="btn btn-primary" onclick="send_opcode(0x03)">Fast Rewind</button>
+        <button class="btn btn-primary" onclick="send_opcode(0x04)">Fast Forward</button>
+        <button class="btn btn-primary" onclick="send_opcode(0x05)">Stop</button>
+
+        </br></br>
+
+        <button class="btn btn-primary" onclick="send_opcode(0x30)">Previous Track</button>
+        <button class="btn btn-primary" onclick="send_opcode(0x31)">Next Track</button>
+
+        <hr>
+
+        <div id="socketStateContainer" class="bg-body-tertiary p-3 rounded-2">
+            <h3>Log</h3>
+            <code id="log" style="white-space: pre-line;"></code>
+        </div>
+    </div>
+
+
+    <script>
+        let portInput = document.getElementById("port")
+        let log = document.getElementById("log")
+        let socket
+
+        function connect() {
+            socket = new WebSocket(`ws://localhost:${portInput.value}`);
+            socket.onopen = _ => {
+                log.textContent += 'OPEN\n'
+            }
+            socket.onclose = _ => {
+                log.textContent += 'CLOSED\n'
+            }
+            socket.onerror = (error) => {
+                log.textContent += 'ERROR\n'
+                console.log(`ERROR: ${error}`)
+            }
+            socket.onmessage = (event) => {
+                log.textContent += `<-- ${event.data}\n`
+            }
+        }
+
+        function send(message) {
+            if (socket && socket.readyState == WebSocket.OPEN) {
+                let jsonMessage = JSON.stringify(message)
+                log.textContent += `--> ${jsonMessage}\n`
+                socket.send(jsonMessage)
+            } else {
+                log.textContent += 'NOT CONNECTED\n'
+            }
+        }
+
+        function send_opcode(opcode) {
+            send({ 'opcode': opcode })
+        }
+    </script>
+    </div>
+</body>
+
+</html>
\ No newline at end of file
diff --git a/examples/run_asha_sink.py b/examples/run_asha_sink.py
index 105eb75..485e17e 100644
--- a/examples/run_asha_sink.py
+++ b/examples/run_asha_sink.py
@@ -16,192 +16,104 @@
 # Imports
 # -----------------------------------------------------------------------------
 import asyncio
-import struct
 import sys
 import os
 import logging
+import websockets
 
-from bumble import l2cap
+from typing import Optional
+
+from bumble import decoder
+from bumble import gatt
 from bumble.core import AdvertisingData
-from bumble.device import Device
+from bumble.device import Device, AdvertisingParameters
 from bumble.transport import open_transport_or_link
-from bumble.core import UUID
-from bumble.gatt import Service, Characteristic, CharacteristicValue
+from bumble.profiles import asha
 
+ws_connection: Optional[websockets.WebSocketServerProtocol] = None
+g722_decoder = decoder.G722Decoder()
 
-# -----------------------------------------------------------------------------
-# Constants
-# -----------------------------------------------------------------------------
-ASHA_SERVICE = UUID.from_16_bits(0xFDF0, 'Audio Streaming for Hearing Aid')
-ASHA_READ_ONLY_PROPERTIES_CHARACTERISTIC = UUID(
-    '6333651e-c481-4a3e-9169-7c902aad37bb', 'ReadOnlyProperties'
-)
-ASHA_AUDIO_CONTROL_POINT_CHARACTERISTIC = UUID(
-    'f0d4de7e-4a88-476c-9d9f-1937b0996cc0', 'AudioControlPoint'
-)
-ASHA_AUDIO_STATUS_CHARACTERISTIC = UUID(
-    '38663f1a-e711-4cac-b641-326b56404837', 'AudioStatus'
-)
-ASHA_VOLUME_CHARACTERISTIC = UUID('00e4ca9e-ab14-41e4-8823-f9e70c7e91df', 'Volume')
-ASHA_LE_PSM_OUT_CHARACTERISTIC = UUID(
-    '2d410339-82b6-42aa-b34e-e2e01df8cc1a', 'LE_PSM_OUT'
-)
+
+async def ws_server(ws_client: websockets.WebSocketServerProtocol, path: str):
+    del path
+    global ws_connection
+    ws_connection = ws_client
+
+    async for message in ws_client:
+        print(message)
 
 
 # -----------------------------------------------------------------------------
 async def main() -> None:
-    if len(sys.argv) != 4:
-        print(
-            'Usage: python run_asha_sink.py <device-config> <transport-spec> '
-            '<audio-file>'
-        )
-        print('example: python run_asha_sink.py device1.json usb:0 audio_out.g722')
+    if len(sys.argv) != 3:
+        print('Usage: python run_asha_sink.py <device-config> <transport-spec>')
+        print('example: python run_asha_sink.py device1.json usb:0')
         return
 
-    audio_out = open(sys.argv[3], 'wb')
-
     async with await open_transport_or_link(sys.argv[2]) as hci_transport:
         device = Device.from_config_file_with_hci(
             sys.argv[1], hci_transport.source, hci_transport.sink
         )
 
-        # Handler for audio control commands
-        def on_audio_control_point_write(_connection, value):
-            print('--- AUDIO CONTROL POINT Write:', value.hex())
-            opcode = value[0]
-            if opcode == 1:
-                # Start
-                audio_type = ('Unknown', 'Ringtone', 'Phone Call', 'Media')[value[2]]
-                print(
-                    f'### START: codec={value[1]}, audio_type={audio_type}, '
-                    f'volume={value[3]}, otherstate={value[4]}'
-                )
-            elif opcode == 2:
-                print('### STOP')
-            elif opcode == 3:
-                print(f'### STATUS: connected={value[1]}')
-
-            # Respond with a status
-            asyncio.create_task(
-                device.notify_subscribers(audio_status_characteristic, force=True)
-            )
-
-        # Handler for volume control
-        def on_volume_write(_connection, value):
-            print('--- VOLUME Write:', value[0])
-
-        # Register an L2CAP CoC server
-        def on_coc(channel):
-            def on_data(data):
-                print('<<< Voice data received:', data.hex())
-                audio_out.write(data)
-
-            channel.sink = on_data
-
-        server = device.create_l2cap_server(
-            spec=l2cap.LeCreditBasedChannelSpec(max_credits=8), handler=on_coc
-        )
-        print(f'### LE_PSM_OUT = {server.psm}')
-
-        # Add the ASHA service to the GATT server
-        read_only_properties_characteristic = Characteristic(
-            ASHA_READ_ONLY_PROPERTIES_CHARACTERISTIC,
-            Characteristic.Properties.READ,
-            Characteristic.READABLE,
-            bytes(
-                [
-                    0x01,  # Version
-                    0x00,  # Device Capabilities [Left, Monaural]
-                    0x01,
-                    0x02,
-                    0x03,
-                    0x04,
-                    0x05,
-                    0x06,
-                    0x07,
-                    0x08,  # HiSyncId
-                    0x01,  # Feature Map [LE CoC audio output streaming supported]
-                    0x00,
-                    0x00,  # Render Delay
-                    0x00,
-                    0x00,  # RFU
-                    0x02,
-                    0x00,  # Codec IDs [G.722 at 16 kHz]
-                ]
-            ),
-        )
-        audio_control_point_characteristic = Characteristic(
-            ASHA_AUDIO_CONTROL_POINT_CHARACTERISTIC,
-            Characteristic.Properties.WRITE | Characteristic.WRITE_WITHOUT_RESPONSE,
-            Characteristic.WRITEABLE,
-            CharacteristicValue(write=on_audio_control_point_write),
-        )
-        audio_status_characteristic = Characteristic(
-            ASHA_AUDIO_STATUS_CHARACTERISTIC,
-            Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
-            Characteristic.READABLE,
-            bytes([0]),
-        )
-        volume_characteristic = Characteristic(
-            ASHA_VOLUME_CHARACTERISTIC,
-            Characteristic.WRITE_WITHOUT_RESPONSE,
-            Characteristic.WRITEABLE,
-            CharacteristicValue(write=on_volume_write),
-        )
-        le_psm_out_characteristic = Characteristic(
-            ASHA_LE_PSM_OUT_CHARACTERISTIC,
-            Characteristic.Properties.READ,
-            Characteristic.READABLE,
-            struct.pack('<H', server.psm),
-        )
-        device.add_service(
-            Service(
-                ASHA_SERVICE,
-                [
-                    read_only_properties_characteristic,
-                    audio_control_point_characteristic,
-                    audio_status_characteristic,
-                    volume_characteristic,
-                    le_psm_out_characteristic,
-                ],
-            )
+        def on_audio_packet(packet: bytes) -> None:
+            global ws_connection
+            if ws_connection:
+                offset = 1
+                while offset < len(packet):
+                    pcm_data = g722_decoder.decode_frame(packet[offset : offset + 80])
+                    offset += 80
+                    asyncio.get_running_loop().create_task(ws_connection.send(pcm_data))
+            else:
+                logging.info("No active client")
+
+        asha_service = asha.AshaService(
+            capability=0,
+            hisyncid=b'\x01\x02\x03\x04\x05\x06\x07\x08',
+            device=device,
+            audio_sink=on_audio_packet,
         )
+        device.add_service(asha_service)
 
         # Set the advertising data
-        device.advertising_data = bytes(
-            AdvertisingData(
-                [
-                    (AdvertisingData.COMPLETE_LOCAL_NAME, bytes(device.name, 'utf-8')),
-                    (AdvertisingData.FLAGS, bytes([0x06])),
-                    (
-                        AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
-                        bytes(ASHA_SERVICE),
-                    ),
-                    (
-                        AdvertisingData.SERVICE_DATA_16_BIT_UUID,
-                        bytes(ASHA_SERVICE)
-                        + bytes(
-                            [
-                                0x01,  # Protocol Version
-                                0x00,  # Capability
-                                0x01,
-                                0x02,
-                                0x03,
-                                0x04,  # Truncated HiSyncID
-                            ]
+        advertising_data = (
+            bytes(
+                AdvertisingData(
+                    [
+                        (
+                            AdvertisingData.COMPLETE_LOCAL_NAME,
+                            bytes(device.name, 'utf-8'),
                         ),
-                    ),
-                ]
+                        (AdvertisingData.FLAGS, bytes([0x06])),
+                        (
+                            AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
+                            bytes(gatt.GATT_ASHA_SERVICE),
+                        ),
+                    ]
+                )
             )
+            + asha_service.get_advertising_data()
         )
 
         # Go!
         await device.power_on()
-        await device.start_advertising(auto_restart=True)
+        await device.create_advertising_set(
+            auto_restart=True,
+            advertising_data=advertising_data,
+            advertising_parameters=AdvertisingParameters(
+                primary_advertising_interval_min=100,
+                primary_advertising_interval_max=100,
+            ),
+        )
 
-        await hci_transport.source.wait_for_termination()
+        await websockets.serve(ws_server, port=8888)
+
+        await hci_transport.source.terminated
 
 
 # -----------------------------------------------------------------------------
-logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
+logging.basicConfig(
+    level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper(),
+    format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
+    datefmt='%Y-%m-%d %H:%M:%S',
+)
 asyncio.run(main())
diff --git a/examples/run_hap_server.py b/examples/run_hap_server.py
new file mode 100644
index 0000000..18f1c38
--- /dev/null
+++ b/examples/run_hap_server.py
@@ -0,0 +1,107 @@
+# Copyright 2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+import asyncio
+import logging
+import sys
+import os
+
+from bumble.core import AdvertisingData
+from bumble.device import Device
+from bumble import att
+from bumble.profiles.hap import (
+    HearingAccessService,
+    HearingAidFeatures,
+    HearingAidType,
+    PresetSynchronizationSupport,
+    IndependentPresets,
+    DynamicPresets,
+    WritablePresetsSupport,
+    PresetRecord,
+)
+
+from bumble.transport import open_transport_or_link
+
+server_features = HearingAidFeatures(
+    HearingAidType.MONAURAL_HEARING_AID,
+    PresetSynchronizationSupport.PRESET_SYNCHRONIZATION_IS_NOT_SUPPORTED,
+    IndependentPresets.IDENTICAL_PRESET_RECORD,
+    DynamicPresets.PRESET_RECORDS_DOES_NOT_CHANGE,
+    WritablePresetsSupport.WRITABLE_PRESET_RECORDS_SUPPORTED,
+)
+
+foo_preset = PresetRecord(1, "foo preset")
+bar_preset = PresetRecord(50, "bar preset")
+foobar_preset = PresetRecord(5, "foobar preset")
+
+
+# -----------------------------------------------------------------------------
+async def main() -> None:
+    if len(sys.argv) < 3:
+        print('Usage: run_hap_server.py <config-file> <transport-spec-for-device>')
+        print('example: run_hap_server.py device1.json pty:hci_pty')
+        return
+
+    print('<<< connecting to HCI...')
+    async with await open_transport_or_link(sys.argv[2]) as hci_transport:
+        print('<<< connected')
+
+        device = Device.from_config_file_with_hci(
+            sys.argv[1], hci_transport.source, hci_transport.sink
+        )
+
+        await device.power_on()
+
+        hap = HearingAccessService(
+            device, server_features, [foo_preset, bar_preset, foobar_preset]
+        )
+        device.add_service(hap)
+
+        advertising_data = bytes(
+            AdvertisingData(
+                [
+                    (
+                        AdvertisingData.COMPLETE_LOCAL_NAME,
+                        bytes('Bumble HearingAccessService', 'utf-8'),
+                    ),
+                    (
+                        AdvertisingData.FLAGS,
+                        bytes(
+                            [
+                                AdvertisingData.LE_GENERAL_DISCOVERABLE_MODE_FLAG
+                                | AdvertisingData.BR_EDR_HOST_FLAG
+                                | AdvertisingData.BR_EDR_CONTROLLER_FLAG
+                            ]
+                        ),
+                    ),
+                    (
+                        AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
+                        bytes(HearingAccessService.UUID),
+                    ),
+                ]
+            )
+        )
+
+        await device.create_advertising_set(
+            advertising_data=advertising_data,
+            auto_restart=True,
+        )
+
+
+# -----------------------------------------------------------------------------
+logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
+asyncio.run(main())
diff --git a/examples/run_hid_device.py b/examples/run_hid_device.py
index 2287be0..160e395 100644
--- a/examples/run_hid_device.py
+++ b/examples/run_hid_device.py
@@ -21,7 +21,7 @@ import os
 import logging
 import json
 import websockets
-from bumble.colors import color
+import struct
 
 from bumble.device import Device
 from bumble.transport import open_transport_or_link
@@ -30,9 +30,7 @@ from bumble.core import (
     BT_L2CAP_PROTOCOL_ID,
     BT_HUMAN_INTERFACE_DEVICE_SERVICE,
     BT_HIDP_PROTOCOL_ID,
-    UUID,
 )
-from bumble.hci import Address
 from bumble.hid import (
     Device as HID_Device,
     HID_CONTROL_PSM,
@@ -40,20 +38,17 @@ from bumble.hid import (
     Message,
 )
 from bumble.sdp import (
-    Client as SDP_Client,
     DataElement,
     ServiceAttribute,
     SDP_PUBLIC_BROWSE_ROOT,
     SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
     SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
     SDP_BLUETOOTH_PROFILE_DESCRIPTOR_LIST_ATTRIBUTE_ID,
-    SDP_ALL_ATTRIBUTES_RANGE,
     SDP_LANGUAGE_BASE_ATTRIBUTE_ID_LIST_ATTRIBUTE_ID,
     SDP_ADDITIONAL_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
     SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
     SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
 )
-from bumble.utils import AsyncRunner
 
 # -----------------------------------------------------------------------------
 # SDP attributes for Bluetooth HID devices
@@ -430,7 +425,7 @@ deviceData = DeviceData()
 
 
 # -----------------------------------------------------------------------------
-async def keyboard_device(hid_device):
+async def keyboard_device(hid_device: HID_Device):
 
     # Start a Websocket server to receive events from a web page
     async def serve(websocket, _path):
@@ -476,9 +471,9 @@ async def keyboard_device(hid_device):
                     # limiting x and y values within logical max and min range
                     x = max(log_min, min(log_max, x))
                     y = max(log_min, min(log_max, y))
-                    x_cord = x.to_bytes(signed=True)
-                    y_cord = y.to_bytes(signed=True)
-                    deviceData.mouseData = bytearray([0x02, 0x00]) + x_cord + y_cord
+                    deviceData.mouseData = bytearray([0x02, 0x00]) + struct.pack(
+                        ">bb", x, y
+                    )
                     hid_device.send_data(deviceData.mouseData)
             except websockets.exceptions.ConnectionClosedOK:
                 pass
@@ -515,7 +510,9 @@ async def main() -> None:
     def on_hid_data_cb(pdu: bytes):
         print(f'Received Data, PDU: {pdu.hex()}')
 
-    def on_get_report_cb(report_id: int, report_type: int, buffer_size: int):
+    def on_get_report_cb(
+        report_id: int, report_type: int, buffer_size: int
+    ) -> HID_Device.GetSetStatus:
         retValue = hid_device.GetSetStatus()
         print(
             "GET_REPORT report_id: "
@@ -555,8 +552,7 @@ async def main() -> None:
 
     def on_set_report_cb(
         report_id: int, report_type: int, report_size: int, data: bytes
-    ):
-        retValue = hid_device.GetSetStatus()
+    ) -> HID_Device.GetSetStatus:
         print(
             "SET_REPORT report_id: "
             + str(report_id)
@@ -568,33 +564,33 @@ async def main() -> None:
             + str(data)
         )
         if report_type == Message.ReportType.FEATURE_REPORT:
-            retValue.status = hid_device.GetSetReturn.ERR_INVALID_PARAMETER
+            status = HID_Device.GetSetReturn.ERR_INVALID_PARAMETER
         elif report_type == Message.ReportType.INPUT_REPORT:
             if report_id == 1 and report_size != len(deviceData.keyboardData):
-                retValue.status = hid_device.GetSetReturn.ERR_INVALID_PARAMETER
+                status = HID_Device.GetSetReturn.ERR_INVALID_PARAMETER
             elif report_id == 2 and report_size != len(deviceData.mouseData):
-                retValue.status = hid_device.GetSetReturn.ERR_INVALID_PARAMETER
+                status = HID_Device.GetSetReturn.ERR_INVALID_PARAMETER
             elif report_id == 3:
-                retValue.status = hid_device.GetSetReturn.REPORT_ID_NOT_FOUND
+                status = HID_Device.GetSetReturn.REPORT_ID_NOT_FOUND
             else:
-                retValue.status = hid_device.GetSetReturn.SUCCESS
+                status = HID_Device.GetSetReturn.SUCCESS
         else:
-            retValue.status = hid_device.GetSetReturn.SUCCESS
+            status = HID_Device.GetSetReturn.SUCCESS
 
-        return retValue
+        return HID_Device.GetSetStatus(status=status)
 
-    def on_get_protocol_cb():
-        retValue = hid_device.GetSetStatus()
-        retValue.data = protocol_mode.to_bytes()
-        retValue.status = hid_device.GetSetReturn.SUCCESS
-        return retValue
+    def on_get_protocol_cb() -> HID_Device.GetSetStatus:
+        return HID_Device.GetSetStatus(
+            data=bytes([protocol_mode]),
+            status=hid_device.GetSetReturn.SUCCESS,
+        )
 
-    def on_set_protocol_cb(protocol: int):
-        retValue = hid_device.GetSetStatus()
+    def on_set_protocol_cb(protocol: int) -> HID_Device.GetSetStatus:
         # We do not support SET_PROTOCOL.
         print(f"SET_PROTOCOL report_id: {protocol}")
-        retValue.status = hid_device.GetSetReturn.ERR_UNSUPPORTED_REQUEST
-        return retValue
+        return HID_Device.GetSetStatus(
+            status=hid_device.GetSetReturn.ERR_UNSUPPORTED_REQUEST
+        )
 
     def on_virtual_cable_unplug_cb():
         print('Received Virtual Cable Unplug')
diff --git a/examples/run_mcp_client.py b/examples/run_mcp_client.py
new file mode 100644
index 0000000..83dad5b
--- /dev/null
+++ b/examples/run_mcp_client.py
@@ -0,0 +1,194 @@
+# Copyright 2021-2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+import asyncio
+import logging
+import sys
+import os
+import websockets
+import json
+
+from bumble.core import AdvertisingData
+from bumble.device import (
+    Device,
+    AdvertisingParameters,
+    AdvertisingEventProperties,
+    Connection,
+    Peer,
+)
+from bumble.hci import (
+    CodecID,
+    CodingFormat,
+    OwnAddressType,
+)
+from bumble.profiles.ascs import AudioStreamControlService
+from bumble.profiles.bap import (
+    CodecSpecificCapabilities,
+    ContextType,
+    AudioLocation,
+    SupportedSamplingFrequency,
+    SupportedFrameDuration,
+    UnicastServerAdvertisingData,
+)
+from bumble.profiles.mcp import (
+    MediaControlServiceProxy,
+    GenericMediaControlServiceProxy,
+    MediaState,
+    MediaControlPointOpcode,
+)
+from bumble.profiles.pacs import PacRecord, PublishedAudioCapabilitiesService
+from bumble.transport import open_transport_or_link
+
+from typing import Optional
+
+
+# -----------------------------------------------------------------------------
+async def main() -> None:
+    if len(sys.argv) < 3:
+        print('Usage: run_mcp_client.py <config-file>' '<transport-spec-for-device>')
+        return
+
+    print('<<< connecting to HCI...')
+    async with await open_transport_or_link(sys.argv[2]) as hci_transport:
+        print('<<< connected')
+
+        device = Device.from_config_file_with_hci(
+            sys.argv[1], hci_transport.source, hci_transport.sink
+        )
+
+        await device.power_on()
+
+        # Add "placeholder" services to enable Android LEA features.
+        device.add_service(
+            PublishedAudioCapabilitiesService(
+                supported_source_context=ContextType.PROHIBITED,
+                available_source_context=ContextType.PROHIBITED,
+                supported_sink_context=ContextType.MEDIA,
+                available_sink_context=ContextType.MEDIA,
+                sink_audio_locations=(
+                    AudioLocation.FRONT_LEFT | AudioLocation.FRONT_RIGHT
+                ),
+                sink_pac=[
+                    PacRecord(
+                        coding_format=CodingFormat(CodecID.LC3),
+                        codec_specific_capabilities=CodecSpecificCapabilities(
+                            supported_sampling_frequencies=(
+                                SupportedSamplingFrequency.FREQ_16000
+                                | SupportedSamplingFrequency.FREQ_32000
+                                | SupportedSamplingFrequency.FREQ_48000
+                            ),
+                            supported_frame_durations=(
+                                SupportedFrameDuration.DURATION_10000_US_SUPPORTED
+                            ),
+                            supported_audio_channel_count=[1, 2],
+                            min_octets_per_codec_frame=0,
+                            max_octets_per_codec_frame=320,
+                            supported_max_codec_frames_per_sdu=2,
+                        ),
+                    ),
+                ],
+            )
+        )
+        device.add_service(AudioStreamControlService(device, sink_ase_id=[1]))
+
+        ws: Optional[websockets.WebSocketServerProtocol] = None
+        mcp: Optional[MediaControlServiceProxy] = None
+
+        advertising_data = bytes(
+            AdvertisingData(
+                [
+                    (
+                        AdvertisingData.COMPLETE_LOCAL_NAME,
+                        bytes('Bumble LE Audio', 'utf-8'),
+                    ),
+                    (
+                        AdvertisingData.FLAGS,
+                        bytes([AdvertisingData.LE_GENERAL_DISCOVERABLE_MODE_FLAG]),
+                    ),
+                    (
+                        AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
+                        bytes(PublishedAudioCapabilitiesService.UUID),
+                    ),
+                ]
+            )
+        ) + bytes(UnicastServerAdvertisingData())
+
+        await device.create_advertising_set(
+            advertising_parameters=AdvertisingParameters(
+                advertising_event_properties=AdvertisingEventProperties(),
+                own_address_type=OwnAddressType.RANDOM,
+                primary_advertising_interval_max=100,
+                primary_advertising_interval_min=100,
+            ),
+            advertising_data=advertising_data,
+            auto_restart=True,
+        )
+
+        def on_media_state(media_state: MediaState) -> None:
+            if ws:
+                asyncio.create_task(
+                    ws.send(json.dumps({'media_state': media_state.name}))
+                )
+
+        def on_track_title(title: str) -> None:
+            if ws:
+                asyncio.create_task(ws.send(json.dumps({'title': title})))
+
+        def on_track_duration(duration: int) -> None:
+            if ws:
+                asyncio.create_task(ws.send(json.dumps({'duration': duration})))
+
+        def on_track_position(position: int) -> None:
+            if ws:
+                asyncio.create_task(ws.send(json.dumps({'position': position})))
+
+        def on_connection(connection: Connection) -> None:
+            async def on_connection_async():
+                async with Peer(connection) as peer:
+                    nonlocal mcp
+                    mcp = peer.create_service_proxy(MediaControlServiceProxy)
+                    if not mcp:
+                        mcp = peer.create_service_proxy(GenericMediaControlServiceProxy)
+                    mcp.on('media_state', on_media_state)
+                    mcp.on('track_title', on_track_title)
+                    mcp.on('track_duration', on_track_duration)
+                    mcp.on('track_position', on_track_position)
+                    await mcp.subscribe_characteristics()
+
+            connection.abort_on('disconnection', on_connection_async())
+
+        device.on('connection', on_connection)
+
+        async def serve(websocket: websockets.WebSocketServerProtocol, _path):
+            nonlocal ws
+            ws = websocket
+            async for message in websocket:
+                request = json.loads(message)
+                if mcp:
+                    await mcp.write_control_point(
+                        MediaControlPointOpcode(request['opcode'])
+                    )
+            ws = None
+
+        await websockets.serve(serve, 'localhost', 8989)
+
+        await hci_transport.source.terminated
+
+
+# -----------------------------------------------------------------------------
+logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'DEBUG').upper())
+asyncio.run(main())
diff --git a/examples/run_unicast_server.py b/examples/run_unicast_server.py
index 95ae551..3ff1c96 100644
--- a/examples/run_unicast_server.py
+++ b/examples/run_unicast_server.py
@@ -34,8 +34,8 @@ from bumble.hci import (
     CodingFormat,
     HCI_IsoDataPacket,
 )
+from bumble.profiles.ascs import AseStateMachine, AudioStreamControlService
 from bumble.profiles.bap import (
-    AseStateMachine,
     UnicastServerAdvertisingData,
     CodecSpecificConfiguration,
     CodecSpecificCapabilities,
@@ -43,13 +43,10 @@ from bumble.profiles.bap import (
     AudioLocation,
     SupportedSamplingFrequency,
     SupportedFrameDuration,
-    PacRecord,
-    PublishedAudioCapabilitiesService,
-    AudioStreamControlService,
 )
 from bumble.profiles.cap import CommonAudioServiceService
 from bumble.profiles.csip import CoordinatedSetIdentificationService, SirkType
-
+from bumble.profiles.pacs import PacRecord, PublishedAudioCapabilitiesService
 from bumble.transport import open_transport_or_link
 
 
diff --git a/examples/run_vcp_renderer.py b/examples/run_vcp_renderer.py
index 0cffbae..ba9c840 100644
--- a/examples/run_vcp_renderer.py
+++ b/examples/run_vcp_renderer.py
@@ -30,6 +30,7 @@ from bumble.hci import (
     CodingFormat,
     OwnAddressType,
 )
+from bumble.profiles.ascs import AudioStreamControlService
 from bumble.profiles.bap import (
     UnicastServerAdvertisingData,
     CodecSpecificCapabilities,
@@ -37,10 +38,8 @@ from bumble.profiles.bap import (
     AudioLocation,
     SupportedSamplingFrequency,
     SupportedFrameDuration,
-    PacRecord,
-    PublishedAudioCapabilitiesService,
-    AudioStreamControlService,
 )
+from bumble.profiles.pacs import PacRecord, PublishedAudioCapabilitiesService
 from bumble.profiles.cap import CommonAudioServiceService
 from bumble.profiles.csip import CoordinatedSetIdentificationService, SirkType
 from bumble.profiles.vcp import VolumeControlService
diff --git a/extras/android/BtBench/app/src/main/java/com/github/google/bumble/btbench/MainActivity.kt b/extras/android/BtBench/app/src/main/java/com/github/google/bumble/btbench/MainActivity.kt
index 6081837..dea3e3c 100644
--- a/extras/android/BtBench/app/src/main/java/com/github/google/bumble/btbench/MainActivity.kt
+++ b/extras/android/BtBench/app/src/main/java/com/github/google/bumble/btbench/MainActivity.kt
@@ -142,7 +142,7 @@ class MainActivity : ComponentActivity() {
                 ::runRfcommClient,
                 ::runRfcommServer,
                 ::runL2capClient,
-                ::runL2capServer
+                ::runL2capServer,
             )
         }
 
@@ -166,6 +166,8 @@ class MainActivity : ComponentActivity() {
                 "rfcomm-server" -> runRfcommServer()
                 "l2cap-client" -> runL2capClient()
                 "l2cap-server" -> runL2capServer()
+                "scan-start" -> runScan(true)
+                "stop-start" -> runScan(false)
             }
         }
     }
@@ -190,6 +192,11 @@ class MainActivity : ComponentActivity() {
         l2capServer?.run()
     }
 
+    private fun runScan(startScan: Boolean) {
+        val scan = bluetoothAdapter?.let { Scan(it) }
+        scan?.run(startScan)
+    }
+
     @SuppressLint("MissingPermission")
     fun becomeDiscoverable() {
         val discoverableIntent = Intent(BluetoothAdapter.ACTION_REQUEST_DISCOVERABLE)
@@ -206,7 +213,7 @@ fun MainView(
     runRfcommClient: () -> Unit,
     runRfcommServer: () -> Unit,
     runL2capClient: () -> Unit,
-    runL2capServer: () -> Unit
+    runL2capServer: () -> Unit,
 ) {
     BTBenchTheme {
         val scrollState = rememberScrollState()
diff --git a/extras/android/BtBench/app/src/main/java/com/github/google/bumble/btbench/Model.kt b/extras/android/BtBench/app/src/main/java/com/github/google/bumble/btbench/Model.kt
index 1a8cd6d..66ceb0d 100644
--- a/extras/android/BtBench/app/src/main/java/com/github/google/bumble/btbench/Model.kt
+++ b/extras/android/BtBench/app/src/main/java/com/github/google/bumble/btbench/Model.kt
@@ -150,7 +150,8 @@ class AppViewModel : ViewModel() {
         } else if (senderPacketSizeSlider < 0.5F) {
             512
         } else if (senderPacketSizeSlider < 0.7F) {
-            1024
+            // 970 is a value that works well on Android.
+            970
         } else if (senderPacketSizeSlider < 0.9F) {
             2048
         } else {
diff --git a/extras/android/BtBench/app/src/main/java/com/github/google/bumble/btbench/Scan.kt b/extras/android/BtBench/app/src/main/java/com/github/google/bumble/btbench/Scan.kt
new file mode 100644
index 0000000..7cb8e7a
--- /dev/null
+++ b/extras/android/BtBench/app/src/main/java/com/github/google/bumble/btbench/Scan.kt
@@ -0,0 +1,38 @@
+package com.github.google.bumble.btbench
+
+import android.annotation.SuppressLint
+import android.bluetooth.BluetoothAdapter
+import android.bluetooth.BluetoothDevice
+import android.bluetooth.le.ScanCallback
+import android.bluetooth.le.ScanResult
+import java.util.logging.Logger
+
+private val Log = Logger.getLogger("btbench.scan")
+
+class Scan(val bluetoothAdapter: BluetoothAdapter) {
+    @SuppressLint("MissingPermission")
+    fun run(startScan: Boolean) {
+        var bluetoothLeScanner = bluetoothAdapter.bluetoothLeScanner
+
+        val scanCallback = object : ScanCallback() {
+            override fun onScanResult(callbackType: Int, result: ScanResult?) {
+                super.onScanResult(callbackType, result)
+                val device: BluetoothDevice? = result?.device
+                val deviceName = device?.name ?: "Unknown"
+                val deviceAddress = device?.address ?: "Unknown"
+                Log.info("Device found: $deviceName ($deviceAddress)")
+            }
+
+            override fun onScanFailed(errorCode: Int) {
+                // Handle scan failure
+                Log.warning("Scan failed with error code: $errorCode")
+            }
+        }
+
+        if (startScan) {
+            bluetoothLeScanner?.startScan(scanCallback)
+        } else {
+            bluetoothLeScanner?.stopScan(scanCallback)
+        }
+    }
+}
\ No newline at end of file
diff --git a/tasks.py b/tasks.py
index fab7cf1..ba12765 100644
--- a/tasks.py
+++ b/tasks.py
@@ -20,7 +20,10 @@ Invoke tasks
 # Imports
 # -----------------------------------------------------------------------------
 import os
-
+import glob
+import shutil
+import urllib
+from pathlib import Path
 from invoke import task, call, Collection
 from invoke.exceptions import Exit, UnexpectedExit
 
@@ -205,5 +208,21 @@ def serve(ctx, port=8000):
     server.serve_forever()
 
 
+# -----------------------------------------------------------------------------
+@task
+def web_build(ctx):
+    # Step 1: build the wheel
+    build(ctx)
+    # Step 2: Copy the wheel to the web folder, so the http server can access it
+    newest_wheel = Path(max(glob.glob('dist/*.whl'), key=lambda f: os.path.getmtime(f)))
+    shutil.copy(newest_wheel, Path('web/'))
+    # Step 3: Write wheel's name to web/packageFile
+    with open(Path('web', 'packageFile'), mode='w') as package_file:
+        package_file.write(str(Path('/') / newest_wheel.name))
+    # Step 4: Success!
+    print('Include ?packageFile=true in your URL!')
+
+
 # -----------------------------------------------------------------------------
 web_tasks.add_task(serve)
+web_tasks.add_task(web_build, name="build")
diff --git a/tests/aics_test.py b/tests/aics_test.py
new file mode 100644
index 0000000..9526558
--- /dev/null
+++ b/tests/aics_test.py
@@ -0,0 +1,494 @@
+# Copyright 2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+import pytest
+import pytest_asyncio
+
+from bumble import device
+
+from bumble.att import ATT_Error
+
+from bumble.profiles.aics import (
+    Mute,
+    AICSService,
+    AudioInputState,
+    AICSServiceProxy,
+    GainMode,
+    AudioInputStatus,
+    AudioInputControlPointOpCode,
+    ErrorCode,
+)
+from bumble.profiles.vcp import VolumeControlService, VolumeControlServiceProxy
+
+from .test_utils import TwoDevices
+
+
+# -----------------------------------------------------------------------------
+# Tests
+# -----------------------------------------------------------------------------
+aics_service = AICSService()
+vcp_service = VolumeControlService(
+    volume_setting=32, muted=1, volume_flags=1, included_services=[aics_service]
+)
+
+
+@pytest_asyncio.fixture
+async def aics_client():
+    devices = TwoDevices()
+    devices[0].add_service(vcp_service)
+
+    await devices.setup_connection()
+
+    assert devices.connections[0]
+    assert devices.connections[1]
+
+    devices.connections[0].encryption = 1
+    devices.connections[1].encryption = 1
+
+    peer = device.Peer(devices.connections[1])
+
+    vcp_client = await peer.discover_service_and_create_proxy(VolumeControlServiceProxy)
+
+    assert vcp_client
+    included_services = await peer.discover_included_services(vcp_client.service_proxy)
+    assert included_services
+    aics_service_discovered = included_services[0]
+    await peer.discover_characteristics(service=aics_service_discovered)
+    aics_client = AICSServiceProxy(aics_service_discovered)
+
+    yield aics_client
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_init_service(aics_client: AICSServiceProxy):
+    assert await aics_client.audio_input_state.read_value() == AudioInputState(
+        gain_settings=0,
+        mute=Mute.NOT_MUTED,
+        gain_mode=GainMode.MANUAL,
+        change_counter=0,
+    )
+    assert await aics_client.gain_settings_properties.read_value() == (1, 0, 255)
+    assert await aics_client.audio_input_status.read_value() == (
+        AudioInputStatus.ACTIVE
+    )
+
+
+@pytest.mark.asyncio
+async def test_wrong_opcode_raise_error(aics_client: AICSServiceProxy):
+    with pytest.raises(ATT_Error) as e:
+        await aics_client.audio_input_control_point.write_value(
+            bytes(
+                [
+                    0xFF,
+                ]
+            ),
+            with_response=True,
+        )
+
+    assert e.value.error_code == ErrorCode.OPCODE_NOT_SUPPORTED
+
+
+@pytest.mark.asyncio
+async def test_set_gain_setting_when_gain_mode_automatic_only(
+    aics_client: AICSServiceProxy,
+):
+    aics_service.audio_input_state.gain_mode = GainMode.AUTOMATIC_ONLY
+
+    change_counter = 0
+    gain_settings = 120
+    await aics_client.audio_input_control_point.write_value(
+        bytes(
+            [
+                AudioInputControlPointOpCode.SET_GAIN_SETTING,
+                change_counter,
+                gain_settings,
+            ]
+        )
+    )
+
+    # Unchanged
+    assert await aics_client.audio_input_state.read_value() == AudioInputState(
+        gain_settings=0,
+        mute=Mute.NOT_MUTED,
+        gain_mode=GainMode.AUTOMATIC_ONLY,
+        change_counter=0,
+    )
+
+
+@pytest.mark.asyncio
+async def test_set_gain_setting_when_gain_mode_automatic(aics_client: AICSServiceProxy):
+    aics_service.audio_input_state.gain_mode = GainMode.AUTOMATIC
+    change_counter = 0
+    gain_settings = 120
+    await aics_client.audio_input_control_point.write_value(
+        bytes(
+            [
+                AudioInputControlPointOpCode.SET_GAIN_SETTING,
+                change_counter,
+                gain_settings,
+            ]
+        )
+    )
+
+    # Unchanged
+    assert await aics_client.audio_input_state.read_value() == AudioInputState(
+        gain_settings=0,
+        mute=Mute.NOT_MUTED,
+        gain_mode=GainMode.AUTOMATIC,
+        change_counter=0,
+    )
+
+
+@pytest.mark.asyncio
+async def test_set_gain_setting_when_gain_mode_MANUAL(aics_client: AICSServiceProxy):
+    aics_service.audio_input_state.gain_mode = GainMode.MANUAL
+    change_counter = 0
+    gain_settings = 120
+    await aics_client.audio_input_control_point.write_value(
+        bytes(
+            [
+                AudioInputControlPointOpCode.SET_GAIN_SETTING,
+                change_counter,
+                gain_settings,
+            ]
+        )
+    )
+
+    assert await aics_client.audio_input_state.read_value() == AudioInputState(
+        gain_settings=gain_settings,
+        mute=Mute.NOT_MUTED,
+        gain_mode=GainMode.MANUAL,
+        change_counter=change_counter,
+    )
+
+
+@pytest.mark.asyncio
+async def test_set_gain_setting_when_gain_mode_MANUAL_ONLY(
+    aics_client: AICSServiceProxy,
+):
+    aics_service.audio_input_state.gain_mode = GainMode.MANUAL_ONLY
+    change_counter = 0
+    gain_settings = 120
+    await aics_client.audio_input_control_point.write_value(
+        bytes(
+            [
+                AudioInputControlPointOpCode.SET_GAIN_SETTING,
+                change_counter,
+                gain_settings,
+            ]
+        )
+    )
+
+    assert await aics_client.audio_input_state.read_value() == AudioInputState(
+        gain_settings=gain_settings,
+        mute=Mute.NOT_MUTED,
+        gain_mode=GainMode.MANUAL_ONLY,
+        change_counter=change_counter,
+    )
+
+
+@pytest.mark.asyncio
+async def test_unmute_when_muted(aics_client: AICSServiceProxy):
+    aics_service.audio_input_state.mute = Mute.MUTED
+    change_counter = 0
+    await aics_client.audio_input_control_point.write_value(
+        bytes(
+            [
+                AudioInputControlPointOpCode.UNMUTE,
+                change_counter,
+            ]
+        )
+    )
+
+    change_counter += 1
+
+    state: AudioInputState = await aics_client.audio_input_state.read_value()
+    assert state.mute == Mute.NOT_MUTED
+    assert state.change_counter == change_counter
+
+
+@pytest.mark.asyncio
+async def test_unmute_when_mute_disabled(aics_client: AICSServiceProxy):
+    aics_service.audio_input_state.mute = Mute.DISABLED
+    aics_service.audio_input_state.change_counter = 0
+    change_counter = 0
+
+    with pytest.raises(ATT_Error) as e:
+        await aics_client.audio_input_control_point.write_value(
+            bytes(
+                [
+                    AudioInputControlPointOpCode.UNMUTE,
+                    change_counter,
+                ]
+            ),
+            with_response=True,
+        )
+
+    assert e.value.error_code == ErrorCode.MUTE_DISABLED
+
+    state: AudioInputState = await aics_client.audio_input_state.read_value()
+    assert state.mute == Mute.DISABLED
+    assert state.change_counter == change_counter
+
+
+@pytest.mark.asyncio
+async def test_mute_when_not_muted(aics_client: AICSServiceProxy):
+    aics_service.audio_input_state.mute = Mute.NOT_MUTED
+    aics_service.audio_input_state.change_counter = 0
+    change_counter = 0
+
+    await aics_client.audio_input_control_point.write_value(
+        bytes(
+            [
+                AudioInputControlPointOpCode.MUTE,
+                change_counter,
+            ]
+        )
+    )
+
+    change_counter += 1
+    state: AudioInputState = await aics_client.audio_input_state.read_value()
+    assert state.mute == Mute.MUTED
+    assert state.change_counter == change_counter
+
+
+@pytest.mark.asyncio
+async def test_mute_when_mute_disabled(aics_client: AICSServiceProxy):
+    aics_service.audio_input_state.mute = Mute.DISABLED
+    aics_service.audio_input_state.change_counter = 0
+    change_counter = 0
+
+    with pytest.raises(ATT_Error) as e:
+        await aics_client.audio_input_control_point.write_value(
+            bytes(
+                [
+                    AudioInputControlPointOpCode.MUTE,
+                    change_counter,
+                ]
+            ),
+            with_response=True,
+        )
+
+    assert e.value.error_code == ErrorCode.MUTE_DISABLED
+
+    state: AudioInputState = await aics_client.audio_input_state.read_value()
+    assert state.mute == Mute.DISABLED
+    assert state.change_counter == change_counter
+
+
+@pytest.mark.asyncio
+async def test_set_manual_gain_mode_when_automatic(aics_client: AICSServiceProxy):
+    aics_service.audio_input_state.gain_mode = GainMode.AUTOMATIC
+    aics_service.audio_input_state.change_counter = 0
+    change_counter = 0
+
+    await aics_client.audio_input_control_point.write_value(
+        bytes(
+            [
+                AudioInputControlPointOpCode.SET_MANUAL_GAIN_MODE,
+                change_counter,
+            ]
+        )
+    )
+
+    change_counter += 1
+    state: AudioInputState = await aics_client.audio_input_state.read_value()
+    assert state.gain_mode == GainMode.MANUAL
+    assert state.change_counter == change_counter
+
+
+@pytest.mark.asyncio
+async def test_set_manual_gain_mode_when_already_manual(aics_client: AICSServiceProxy):
+    aics_service.audio_input_state.gain_mode = GainMode.MANUAL
+    aics_service.audio_input_state.change_counter = 0
+    change_counter = 0
+
+    await aics_client.audio_input_control_point.write_value(
+        bytes(
+            [
+                AudioInputControlPointOpCode.SET_MANUAL_GAIN_MODE,
+                change_counter,
+            ]
+        )
+    )
+
+    # No change expected
+    state: AudioInputState = await aics_client.audio_input_state.read_value()
+    assert state.gain_mode == GainMode.MANUAL
+    assert state.change_counter == change_counter
+
+
+@pytest.mark.asyncio
+async def test_set_manual_gain_mode_when_manual_only(aics_client: AICSServiceProxy):
+    aics_service.audio_input_state.gain_mode = GainMode.MANUAL_ONLY
+    aics_service.audio_input_state.change_counter = 0
+    change_counter = 0
+
+    with pytest.raises(ATT_Error) as e:
+        await aics_client.audio_input_control_point.write_value(
+            bytes(
+                [
+                    AudioInputControlPointOpCode.SET_MANUAL_GAIN_MODE,
+                    change_counter,
+                ]
+            ),
+            with_response=True,
+        )
+
+    assert e.value.error_code == ErrorCode.GAIN_MODE_CHANGE_NOT_ALLOWED
+
+    state: AudioInputState = await aics_client.audio_input_state.read_value()
+    assert state.gain_mode == GainMode.MANUAL_ONLY
+    assert state.change_counter == change_counter
+
+
+@pytest.mark.asyncio
+async def test_set_manual_gain_mode_when_automatic_only(aics_client: AICSServiceProxy):
+    aics_service.audio_input_state.gain_mode = GainMode.AUTOMATIC_ONLY
+    aics_service.audio_input_state.change_counter = 0
+    change_counter = 0
+
+    with pytest.raises(ATT_Error) as e:
+        await aics_client.audio_input_control_point.write_value(
+            bytes(
+                [
+                    AudioInputControlPointOpCode.SET_MANUAL_GAIN_MODE,
+                    change_counter,
+                ]
+            ),
+            with_response=True,
+        )
+
+    assert e.value.error_code == ErrorCode.GAIN_MODE_CHANGE_NOT_ALLOWED
+
+    # No change expected
+    state: AudioInputState = await aics_client.audio_input_state.read_value()
+    assert state.gain_mode == GainMode.AUTOMATIC_ONLY
+    assert state.change_counter == change_counter
+
+
+@pytest.mark.asyncio
+async def test_set_automatic_gain_mode_when_manual(aics_client: AICSServiceProxy):
+    aics_service.audio_input_state.gain_mode = GainMode.MANUAL
+    aics_service.audio_input_state.change_counter = 0
+    change_counter = 0
+
+    await aics_client.audio_input_control_point.write_value(
+        bytes(
+            [
+                AudioInputControlPointOpCode.SET_AUTOMATIC_GAIN_MODE,
+                change_counter,
+            ]
+        )
+    )
+
+    change_counter += 1
+    state: AudioInputState = await aics_client.audio_input_state.read_value()
+    assert state.gain_mode == GainMode.AUTOMATIC
+    assert state.change_counter == change_counter
+
+
+@pytest.mark.asyncio
+async def test_set_automatic_gain_mode_when_already_automatic(
+    aics_client: AICSServiceProxy,
+):
+    aics_service.audio_input_state.gain_mode = GainMode.AUTOMATIC
+    aics_service.audio_input_state.change_counter = 0
+    change_counter = 0
+
+    await aics_client.audio_input_control_point.write_value(
+        bytes(
+            [
+                AudioInputControlPointOpCode.SET_AUTOMATIC_GAIN_MODE,
+                change_counter,
+            ]
+        )
+    )
+
+    # No change expected
+    state: AudioInputState = await aics_client.audio_input_state.read_value()
+    assert state.gain_mode == GainMode.AUTOMATIC
+    assert state.change_counter == change_counter
+
+
+@pytest.mark.asyncio
+async def test_set_automatic_gain_mode_when_manual_only(aics_client: AICSServiceProxy):
+    aics_service.audio_input_state.gain_mode = GainMode.MANUAL_ONLY
+    aics_service.audio_input_state.change_counter = 0
+    change_counter = 0
+
+    with pytest.raises(ATT_Error) as e:
+        await aics_client.audio_input_control_point.write_value(
+            bytes(
+                [
+                    AudioInputControlPointOpCode.SET_AUTOMATIC_GAIN_MODE,
+                    change_counter,
+                ]
+            ),
+            with_response=True,
+        )
+
+    assert e.value.error_code == ErrorCode.GAIN_MODE_CHANGE_NOT_ALLOWED
+
+    # No change expected
+    state: AudioInputState = await aics_client.audio_input_state.read_value()
+    assert state.gain_mode == GainMode.MANUAL_ONLY
+    assert state.change_counter == change_counter
+
+
+@pytest.mark.asyncio
+async def test_set_automatic_gain_mode_when_automatic_only(
+    aics_client: AICSServiceProxy,
+):
+    aics_service.audio_input_state.gain_mode = GainMode.AUTOMATIC_ONLY
+    aics_service.audio_input_state.change_counter = 0
+    change_counter = 0
+
+    with pytest.raises(ATT_Error) as e:
+        await aics_client.audio_input_control_point.write_value(
+            bytes(
+                [
+                    AudioInputControlPointOpCode.SET_AUTOMATIC_GAIN_MODE,
+                    change_counter,
+                ]
+            ),
+            with_response=True,
+        )
+
+    assert e.value.error_code == ErrorCode.GAIN_MODE_CHANGE_NOT_ALLOWED
+
+    # No change expected
+    state: AudioInputState = await aics_client.audio_input_state.read_value()
+    assert state.gain_mode == GainMode.AUTOMATIC_ONLY
+    assert state.change_counter == change_counter
+
+
+@pytest.mark.asyncio
+async def test_audio_input_description_initial_value(aics_client: AICSServiceProxy):
+    description = await aics_client.audio_input_description.read_value()
+    assert description.decode('utf-8') == "Bluetooth"
+
+
+@pytest.mark.asyncio
+async def test_audio_input_description_write_and_read(aics_client: AICSServiceProxy):
+    new_description = "Line Input".encode('utf-8')
+
+    await aics_client.audio_input_description.write_value(new_description)
+
+    description = await aics_client.audio_input_description.read_value()
+    assert description == new_description
diff --git a/tests/asha_test.py b/tests/asha_test.py
new file mode 100644
index 0000000..269e4a8
--- /dev/null
+++ b/tests/asha_test.py
@@ -0,0 +1,163 @@
+# Copyright 2021-2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+import asyncio
+import pytest
+import struct
+from unittest import mock
+
+from bumble import device as bumble_device
+from bumble.profiles import asha
+
+from .test_utils import TwoDevices
+
+# -----------------------------------------------------------------------------
+HI_SYNC_ID = b'\x00\x01\x02\x03\x04\x05\x06\x07'
+TIMEOUT = 0.1
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_get_only_properties():
+    devices = TwoDevices()
+    await devices.setup_connection()
+
+    asha_service = asha.AshaService(
+        hisyncid=HI_SYNC_ID,
+        device=devices[0],
+        protocol_version=0x01,
+        capability=0x02,
+        feature_map=0x03,
+        render_delay_milliseconds=0x04,
+        supported_codecs=0x05,
+    )
+    devices[0].add_service(asha_service)
+
+    async with bumble_device.Peer(devices.connections[1]) as peer:
+        asha_client = peer.create_service_proxy(asha.AshaServiceProxy)
+        assert asha_client
+
+        read_only_properties = (
+            await asha_client.read_only_properties_characteristic.read_value()
+        )
+        (
+            protocol_version,
+            capabilities,
+            hi_sync_id,
+            feature_map,
+            render_delay_milliseconds,
+            _,
+            supported_codecs,
+        ) = struct.unpack("<BB8sBHHH", read_only_properties)
+        assert protocol_version == 0x01
+        assert capabilities == 0x02
+        assert hi_sync_id == HI_SYNC_ID
+        assert feature_map == 0x03
+        assert render_delay_milliseconds == 0x04
+        assert supported_codecs == 0x05
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_get_psm():
+    devices = TwoDevices()
+    await devices.setup_connection()
+
+    asha_service = asha.AshaService(
+        hisyncid=HI_SYNC_ID,
+        device=devices[0],
+        capability=0,
+    )
+    devices[0].add_service(asha_service)
+
+    async with bumble_device.Peer(devices.connections[1]) as peer:
+        asha_client = peer.create_service_proxy(asha.AshaServiceProxy)
+        assert asha_client
+
+        psm = (await asha_client.psm_characteristic.read_value())[0]
+        assert psm == asha_service.psm
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_write_audio_control_point_start():
+    devices = TwoDevices()
+    await devices.setup_connection()
+
+    asha_service = asha.AshaService(
+        hisyncid=HI_SYNC_ID,
+        device=devices[0],
+        capability=0,
+    )
+    devices[0].add_service(asha_service)
+
+    async with bumble_device.Peer(devices.connections[1]) as peer:
+        asha_client = peer.create_service_proxy(asha.AshaServiceProxy)
+        assert asha_client
+        status_notifications = asyncio.Queue()
+        await asha_client.audio_status_point_characteristic.subscribe(
+            status_notifications.put_nowait
+        )
+
+        start_cb = mock.MagicMock()
+        asha_service.on('started', start_cb)
+        await asha_client.audio_control_point_characteristic.write_value(
+            bytes(
+                [asha.OpCode.START, asha.Codec.G_722_16KHZ, asha.AudioType.MEDIA, 0, 1]
+            )
+        )
+        status = (await asyncio.wait_for(status_notifications.get(), TIMEOUT))[0]
+        assert status == asha.AudioStatus.OK
+
+        start_cb.assert_called_once()
+        assert asha_service.active_codec == asha.Codec.G_722_16KHZ
+        assert asha_service.volume == 0
+        assert asha_service.other_state == 1
+        assert asha_service.audio_type == asha.AudioType.MEDIA
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_write_audio_control_point_stop():
+    devices = TwoDevices()
+    await devices.setup_connection()
+
+    asha_service = asha.AshaService(
+        hisyncid=HI_SYNC_ID,
+        device=devices[0],
+        capability=0,
+    )
+    devices[0].add_service(asha_service)
+
+    async with bumble_device.Peer(devices.connections[1]) as peer:
+        asha_client = peer.create_service_proxy(asha.AshaServiceProxy)
+        assert asha_client
+        status_notifications = asyncio.Queue()
+        await asha_client.audio_status_point_characteristic.subscribe(
+            status_notifications.put_nowait
+        )
+
+        stop_cb = mock.MagicMock()
+        asha_service.on('stopped', stop_cb)
+        await asha_client.audio_control_point_characteristic.write_value(
+            bytes([asha.OpCode.STOP])
+        )
+        status = (await asyncio.wait_for(status_notifications.get(), TIMEOUT))[0]
+        assert status == asha.AudioStatus.OK
+
+        stop_cb.assert_called_once()
+        assert asha_service.active_codec is None
+        assert asha_service.volume is None
+        assert asha_service.other_state is None
+        assert asha_service.audio_type is None
diff --git a/tests/bap_test.py b/tests/bap_test.py
index 0b6db1a..0b57fcd 100644
--- a/tests/bap_test.py
+++ b/tests/bap_test.py
@@ -23,8 +23,9 @@ import logging
 
 from bumble import device
 from bumble.hci import CodecID, CodingFormat
-from bumble.profiles.bap import (
-    AudioLocation,
+from bumble.profiles.ascs import (
+    AudioStreamControlService,
+    AudioStreamControlServiceProxy,
     AseStateMachine,
     ASE_Operation,
     ASE_Config_Codec,
@@ -35,6 +36,9 @@ from bumble.profiles.bap import (
     ASE_Receiver_Stop_Ready,
     ASE_Release,
     ASE_Update_Metadata,
+)
+from bumble.profiles.bap import (
+    AudioLocation,
     SupportedFrameDuration,
     SupportedSamplingFrequency,
     SamplingFrequency,
@@ -42,12 +46,13 @@ from bumble.profiles.bap import (
     CodecSpecificCapabilities,
     CodecSpecificConfiguration,
     ContextType,
+)
+from bumble.profiles.pacs import (
     PacRecord,
-    AudioStreamControlService,
-    AudioStreamControlServiceProxy,
     PublishedAudioCapabilitiesService,
     PublishedAudioCapabilitiesServiceProxy,
 )
+from bumble.profiles.le_audio import Metadata
 from tests.test_utils import TwoDevices
 
 
@@ -97,7 +102,7 @@ def test_pac_record() -> None:
     pac_record = PacRecord(
         coding_format=CodingFormat(CodecID.LC3),
         codec_specific_capabilities=cap,
-        metadata=b'',
+        metadata=Metadata([Metadata.Entry(tag=Metadata.Tag.VENDOR_SPECIFIC, data=b'')]),
     )
     assert PacRecord.from_bytes(bytes(pac_record)) == pac_record
 
@@ -142,7 +147,7 @@ def test_ASE_Config_QOS() -> None:
 def test_ASE_Enable() -> None:
     operation = ASE_Enable(
         ase_id=[1, 2],
-        metadata=[b'foo', b'bar'],
+        metadata=[b'', b''],
     )
     basic_check(operation)
 
@@ -151,7 +156,7 @@ def test_ASE_Enable() -> None:
 def test_ASE_Update_Metadata() -> None:
     operation = ASE_Update_Metadata(
         ase_id=[1, 2],
-        metadata=[b'foo', b'bar'],
+        metadata=[b'', b''],
     )
     basic_check(operation)
 
diff --git a/tests/bass_test.py b/tests/bass_test.py
new file mode 100644
index 0000000..b893555
--- /dev/null
+++ b/tests/bass_test.py
@@ -0,0 +1,146 @@
+# Copyright 2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+import asyncio
+import os
+import logging
+
+from bumble import hci
+from bumble.profiles import bass
+
+
+# -----------------------------------------------------------------------------
+# Logging
+# -----------------------------------------------------------------------------
+logger = logging.getLogger(__name__)
+
+
+# -----------------------------------------------------------------------------
+def basic_operation_check(operation: bass.ControlPointOperation) -> None:
+    serialized = bytes(operation)
+    parsed = bass.ControlPointOperation.from_bytes(serialized)
+    assert bytes(parsed) == serialized
+
+
+# -----------------------------------------------------------------------------
+def test_operations() -> None:
+    op1 = bass.RemoteScanStoppedOperation()
+    basic_operation_check(op1)
+
+    op2 = bass.RemoteScanStartedOperation()
+    basic_operation_check(op2)
+
+    op3 = bass.AddSourceOperation(
+        hci.Address("AA:BB:CC:DD:EE:FF"),
+        34,
+        123456,
+        bass.PeriodicAdvertisingSyncParams.SYNCHRONIZE_TO_PA_PAST_NOT_AVAILABLE,
+        456,
+        (),
+    )
+    basic_operation_check(op3)
+
+    op4 = bass.AddSourceOperation(
+        hci.Address("AA:BB:CC:DD:EE:FF"),
+        34,
+        123456,
+        bass.PeriodicAdvertisingSyncParams.SYNCHRONIZE_TO_PA_PAST_NOT_AVAILABLE,
+        456,
+        (
+            bass.SubgroupInfo(6677, bytes.fromhex('aabbcc')),
+            bass.SubgroupInfo(8899, bytes.fromhex('ddeeff')),
+        ),
+    )
+    basic_operation_check(op4)
+
+    op5 = bass.ModifySourceOperation(
+        12,
+        bass.PeriodicAdvertisingSyncParams.SYNCHRONIZE_TO_PA_PAST_NOT_AVAILABLE,
+        567,
+        (),
+    )
+    basic_operation_check(op5)
+
+    op6 = bass.ModifySourceOperation(
+        12,
+        bass.PeriodicAdvertisingSyncParams.SYNCHRONIZE_TO_PA_PAST_NOT_AVAILABLE,
+        567,
+        (
+            bass.SubgroupInfo(6677, bytes.fromhex('112233')),
+            bass.SubgroupInfo(8899, bytes.fromhex('4567')),
+        ),
+    )
+    basic_operation_check(op6)
+
+    op7 = bass.SetBroadcastCodeOperation(
+        7, bytes.fromhex('a0a1a2a3a4a5a6a7a8a9aaabacadaeaf')
+    )
+    basic_operation_check(op7)
+
+    op8 = bass.RemoveSourceOperation(7)
+    basic_operation_check(op8)
+
+
+# -----------------------------------------------------------------------------
+def basic_broadcast_receive_state_check(brs: bass.BroadcastReceiveState) -> None:
+    serialized = bytes(brs)
+    parsed = bass.BroadcastReceiveState.from_bytes(serialized)
+    assert parsed is not None
+    assert bytes(parsed) == serialized
+
+
+def test_broadcast_receive_state() -> None:
+    subgroups = [
+        bass.SubgroupInfo(6677, bytes.fromhex('112233')),
+        bass.SubgroupInfo(8899, bytes.fromhex('4567')),
+    ]
+
+    brs1 = bass.BroadcastReceiveState(
+        12,
+        hci.Address("AA:BB:CC:DD:EE:FF"),
+        123,
+        123456,
+        bass.BroadcastReceiveState.PeriodicAdvertisingSyncState.SYNCHRONIZED_TO_PA,
+        bass.BroadcastReceiveState.BigEncryption.DECRYPTING,
+        b'',
+        subgroups,
+    )
+    basic_broadcast_receive_state_check(brs1)
+
+    brs2 = bass.BroadcastReceiveState(
+        12,
+        hci.Address("AA:BB:CC:DD:EE:FF"),
+        123,
+        123456,
+        bass.BroadcastReceiveState.PeriodicAdvertisingSyncState.SYNCHRONIZED_TO_PA,
+        bass.BroadcastReceiveState.BigEncryption.BAD_CODE,
+        bytes.fromhex('a0a1a2a3a4a5a6a7a8a9aaabacadaeaf'),
+        subgroups,
+    )
+    basic_broadcast_receive_state_check(brs2)
+
+
+# -----------------------------------------------------------------------------
+async def run():
+    test_operations()
+    test_broadcast_receive_state()
+
+
+# -----------------------------------------------------------------------------
+if __name__ == '__main__':
+    logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
+    asyncio.run(run())
diff --git a/tests/core_test.py b/tests/core_test.py
index 11afb1c..7592082 100644
--- a/tests/core_test.py
+++ b/tests/core_test.py
@@ -15,7 +15,9 @@
 # -----------------------------------------------------------------------------
 # Imports
 # -----------------------------------------------------------------------------
-from bumble.core import AdvertisingData, UUID, get_dict_key_by_value
+from enum import IntEnum
+
+from bumble.core import AdvertisingData, Appearance, UUID, get_dict_key_by_value
 
 
 # -----------------------------------------------------------------------------
@@ -66,8 +68,35 @@ def test_uuid_to_hex_str() -> None:
     )
 
 
+# -----------------------------------------------------------------------------
+def test_appearance() -> None:
+    a = Appearance(Appearance.Category.COMPUTER, Appearance.ComputerSubcategory.LAPTOP)
+    assert str(a) == 'COMPUTER/LAPTOP'
+    assert int(a) == 0x0083
+
+    a = Appearance(Appearance.Category.HUMAN_INTERFACE_DEVICE, 0x77)
+    assert str(a) == 'HUMAN_INTERFACE_DEVICE/HumanInterfaceDeviceSubcategory[119]'
+    assert int(a) == 0x03C0 | 0x77
+
+    a = Appearance.from_int(0x0381)
+    assert a.category == Appearance.Category.BLOOD_PRESSURE
+    assert a.subcategory == Appearance.BloodPressureSubcategory.ARM_BLOOD_PRESSURE
+    assert int(a) == 0x381
+
+    a = Appearance.from_int(0x038A)
+    assert a.category == Appearance.Category.BLOOD_PRESSURE
+    assert a.subcategory == 0x0A
+    assert int(a) == 0x038A
+
+    a = Appearance.from_int(0x3333)
+    assert a.category == 0xCC
+    assert a.subcategory == 0x33
+    assert int(a) == 0x3333
+
+
 # -----------------------------------------------------------------------------
 if __name__ == '__main__':
     test_ad_data()
     test_get_dict_key_by_value()
     test_uuid_to_hex_str()
+    test_appearance()
diff --git a/tests/device_test.py b/tests/device_test.py
index ac0c96b..45b84ce 100644
--- a/tests/device_test.py
+++ b/tests/device_test.py
@@ -276,36 +276,6 @@ async def test_legacy_advertising():
     assert not device.is_advertising
 
 
-# -----------------------------------------------------------------------------
-@pytest.mark.parametrize(
-    'own_address_type,',
-    (OwnAddressType.PUBLIC, OwnAddressType.RANDOM),
-)
-@pytest.mark.asyncio
-async def test_legacy_advertising_connection(own_address_type):
-    device = Device(host=mock.AsyncMock(Host))
-    peer_address = Address('F0:F1:F2:F3:F4:F5')
-
-    # Start advertising
-    await device.start_advertising()
-    device.on_connection(
-        0x0001,
-        BT_LE_TRANSPORT,
-        peer_address,
-        BT_PERIPHERAL_ROLE,
-        ConnectionParameters(0, 0, 0),
-    )
-
-    if own_address_type == OwnAddressType.PUBLIC:
-        assert device.lookup_connection(0x0001).self_address == device.public_address
-    else:
-        assert device.lookup_connection(0x0001).self_address == device.random_address
-
-    # For unknown reason, read_phy() in on_connection() would be killed at the end of
-    # test, so we force scheduling here to avoid an warning.
-    await asyncio.sleep(0.0001)
-
-
 # -----------------------------------------------------------------------------
 @pytest.mark.parametrize(
     'auto_restart,',
@@ -320,6 +290,8 @@ async def test_legacy_advertising_disconnection(auto_restart):
         0x0001,
         BT_LE_TRANSPORT,
         peer_address,
+        None,
+        None,
         BT_PERIPHERAL_ROLE,
         ConnectionParameters(0, 0, 0),
     )
@@ -369,6 +341,8 @@ async def test_extended_advertising_connection(own_address_type):
         0x0001,
         BT_LE_TRANSPORT,
         peer_address,
+        None,
+        None,
         BT_PERIPHERAL_ROLE,
         ConnectionParameters(0, 0, 0),
     )
@@ -384,9 +358,43 @@ async def test_extended_advertising_connection(own_address_type):
     else:
         assert device.lookup_connection(0x0001).self_address == device.random_address
 
-    # For unknown reason, read_phy() in on_connection() would be killed at the end of
-    # test, so we force scheduling here to avoid an warning.
-    await asyncio.sleep(0.0001)
+    await async_barrier()
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.parametrize(
+    'own_address_type,',
+    (OwnAddressType.PUBLIC, OwnAddressType.RANDOM),
+)
+@pytest.mark.asyncio
+async def test_extended_advertising_connection_out_of_order(own_address_type):
+    device = Device(host=mock.AsyncMock(spec=Host))
+    peer_address = Address('F0:F1:F2:F3:F4:F5')
+    advertising_set = await device.create_advertising_set(
+        advertising_parameters=AdvertisingParameters(own_address_type=own_address_type)
+    )
+    device.on_advertising_set_termination(
+        HCI_SUCCESS,
+        advertising_set.advertising_handle,
+        0x0001,
+        0,
+    )
+    device.on_connection(
+        0x0001,
+        BT_LE_TRANSPORT,
+        peer_address,
+        None,
+        None,
+        BT_PERIPHERAL_ROLE,
+        ConnectionParameters(0, 0, 0),
+    )
+
+    if own_address_type == OwnAddressType.PUBLIC:
+        assert device.lookup_connection(0x0001).self_address == device.public_address
+    else:
+        assert device.lookup_connection(0x0001).self_address == device.random_address
+
+    await async_barrier()
 
 
 # -----------------------------------------------------------------------------
@@ -528,6 +536,16 @@ async def test_cis_setup_failure():
         await asyncio.wait_for(cis_create_task, _TIMEOUT)
 
 
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_power_on_default_static_address_should_not_be_any():
+    devices = TwoDevices()
+    devices[0].static_address = devices[0].random_address = Address.ANY_RANDOM
+    await devices[0].power_on()
+
+    assert devices[0].static_address != Address.ANY_RANDOM
+
+
 # -----------------------------------------------------------------------------
 def test_gatt_services_with_gas():
     device = Device(host=Host(None, None))
diff --git a/tests/gatt_test.py b/tests/gatt_test.py
index e3c9209..f783cae 100644
--- a/tests/gatt_test.py
+++ b/tests/gatt_test.py
@@ -47,8 +47,10 @@ from bumble.att import (
     ATT_EXCHANGE_MTU_REQUEST,
     ATT_ATTRIBUTE_NOT_FOUND_ERROR,
     ATT_PDU,
+    ATT_Error,
     ATT_Error_Response,
     ATT_Read_By_Group_Type_Request,
+    ErrorCode,
 )
 from .test_utils import async_barrier
 
@@ -879,6 +881,57 @@ async def test_unsubscribe():
     mock1.assert_called_once_with(ANY, False, False)
 
 
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_discover_all():
+    [client, server] = LinkedDevices().devices[:2]
+
+    characteristic1 = Characteristic(
+        'FDB159DB-036C-49E3-B3DB-6325AC750806',
+        Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
+        Characteristic.READABLE,
+        bytes([1, 2, 3]),
+    )
+
+    descriptor1 = Descriptor('2902', 'READABLE,WRITEABLE')
+    descriptor2 = Descriptor('AAAA', 'READABLE,WRITEABLE')
+    characteristic2 = Characteristic(
+        '3234C4F4-3F34-4616-8935-45A50EE05DEB',
+        Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
+        Characteristic.READABLE,
+        bytes([1, 2, 3]),
+        descriptors=[descriptor1, descriptor2],
+    )
+
+    service1 = Service(
+        '3A657F47-D34F-46B3-B1EC-698E29B6B829',
+        [characteristic1, characteristic2],
+    )
+    service2 = Service('1111', [])
+    server.add_services([service1, service2])
+
+    await client.power_on()
+    await server.power_on()
+    connection = await client.connect(server.random_address)
+    peer = Peer(connection)
+
+    await peer.discover_all()
+    assert len(peer.gatt_client.services) == 3
+    # service 1800 gets added automatically
+    assert peer.gatt_client.services[0].uuid == UUID('1800')
+    assert peer.gatt_client.services[1].uuid == service1.uuid
+    assert peer.gatt_client.services[2].uuid == service2.uuid
+    s = peer.get_services_by_uuid(service1.uuid)
+    assert len(s) == 1
+    assert len(s[0].characteristics) == 2
+    c = peer.get_characteristics_by_uuid(uuid=characteristic2.uuid, service=s[0])
+    assert len(c) == 1
+    assert len(c[0].descriptors) == 2
+    s = peer.get_services_by_uuid(service2.uuid)
+    assert len(s) == 1
+    assert len(s[0].characteristics) == 0
+
+
 # -----------------------------------------------------------------------------
 @pytest.mark.asyncio
 async def test_mtu_exchange():
@@ -1146,6 +1199,82 @@ def test_get_attribute_group():
     )
 
 
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_get_characteristics_by_uuid():
+    [client, server] = LinkedDevices().devices[:2]
+
+    characteristic1 = Characteristic(
+        '1234',
+        Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
+        Characteristic.READABLE,
+        bytes([1, 2, 3]),
+    )
+    characteristic2 = Characteristic(
+        '5678',
+        Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
+        Characteristic.READABLE,
+        bytes([1, 2, 3]),
+    )
+    service1 = Service(
+        'ABCD',
+        [characteristic1, characteristic2],
+    )
+    service2 = Service(
+        'FFFF',
+        [characteristic1],
+    )
+
+    server.add_services([service1, service2])
+
+    await client.power_on()
+    await server.power_on()
+    connection = await client.connect(server.random_address)
+    peer = Peer(connection)
+
+    await peer.discover_services()
+    await peer.discover_characteristics()
+    c = peer.get_characteristics_by_uuid(uuid=UUID('1234'))
+    assert len(c) == 2
+    assert isinstance(c[0], CharacteristicProxy)
+    c = peer.get_characteristics_by_uuid(uuid=UUID('1234'), service=UUID('ABCD'))
+    assert len(c) == 1
+    assert isinstance(c[0], CharacteristicProxy)
+    c = peer.get_characteristics_by_uuid(uuid=UUID('1234'), service=UUID('AAAA'))
+    assert len(c) == 0
+
+    s = peer.get_services_by_uuid(uuid=UUID('ABCD'))
+    assert len(s) == 1
+    c = peer.get_characteristics_by_uuid(uuid=UUID('1234'), service=s[0])
+    assert len(s) == 1
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_write_return_error():
+    [client, server] = LinkedDevices().devices[:2]
+
+    on_write = Mock(side_effect=ATT_Error(error_code=ErrorCode.VALUE_NOT_ALLOWED))
+    characteristic = Characteristic(
+        '1234',
+        Characteristic.Properties.WRITE,
+        Characteristic.Permissions.WRITEABLE,
+        CharacteristicValue(write=on_write),
+    )
+    service = Service('ABCD', [characteristic])
+    server.add_service(service)
+
+    await client.power_on()
+    await server.power_on()
+    connection = await client.connect(server.random_address)
+
+    async with Peer(connection) as peer:
+        c = peer.get_characteristics_by_uuid(uuid=UUID('1234'))[0]
+        with pytest.raises(ATT_Error) as e:
+            await c.write_value(b'', with_response=True)
+        assert e.value.error_code == ErrorCode.VALUE_NOT_ALLOWED
+
+
 # -----------------------------------------------------------------------------
 if __name__ == '__main__':
     logging.basicConfig(level=os.environ.get('BUMBLE_LOGLEVEL', 'INFO').upper())
diff --git a/tests/hap_test.py b/tests/hap_test.py
new file mode 100644
index 0000000..58392fd
--- /dev/null
+++ b/tests/hap_test.py
@@ -0,0 +1,227 @@
+# Copyright 2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+import asyncio
+import pytest
+import functools
+import pytest_asyncio
+import logging
+import sys
+
+from bumble import att, device
+from bumble.profiles import hap
+from .test_utils import TwoDevices
+
+# -----------------------------------------------------------------------------
+# Logging
+# -----------------------------------------------------------------------------
+logger = logging.getLogger(__name__)
+logger.setLevel(logging.DEBUG)
+
+foo_preset = hap.PresetRecord(1, "foo preset")
+bar_preset = hap.PresetRecord(50, "bar preset")
+foobar_preset = hap.PresetRecord(5, "foobar preset")
+unavailable_preset = hap.PresetRecord(
+    78,
+    "foobar preset",
+    hap.PresetRecord.Property(
+        hap.PresetRecord.Property.Writable.CANNOT_BE_WRITTEN,
+        hap.PresetRecord.Property.IsAvailable.IS_UNAVAILABLE,
+    ),
+)
+
+server_features = hap.HearingAidFeatures(
+    hap.HearingAidType.MONAURAL_HEARING_AID,
+    hap.PresetSynchronizationSupport.PRESET_SYNCHRONIZATION_IS_NOT_SUPPORTED,
+    hap.IndependentPresets.IDENTICAL_PRESET_RECORD,
+    hap.DynamicPresets.PRESET_RECORDS_DOES_NOT_CHANGE,
+    hap.WritablePresetsSupport.WRITABLE_PRESET_RECORDS_SUPPORTED,
+)
+
+TIMEOUT = 0.1
+
+
+async def assert_queue_is_empty(queue: asyncio.Queue):
+    assert queue.empty()
+
+    # Check that nothing is being added during TIMEOUT secondes
+    if sys.version_info >= (3, 11):
+        with pytest.raises(TimeoutError):
+            await asyncio.wait_for(queue.get(), TIMEOUT)
+    else:
+        with pytest.raises(asyncio.TimeoutError):
+            await asyncio.wait_for(queue.get(), TIMEOUT)
+
+
+# -----------------------------------------------------------------------------
+@pytest_asyncio.fixture
+async def hap_client():
+    devices = TwoDevices()
+    devices[0].add_service(
+        hap.HearingAccessService(
+            devices[0],
+            server_features,
+            [foo_preset, bar_preset, foobar_preset, unavailable_preset],
+        )
+    )
+
+    await devices.setup_connection()
+    # TODO negotiate MTU > 49 to not truncate preset names
+
+    # Mock encryption.
+    devices.connections[0].encryption = 1  # type: ignore
+    devices.connections[1].encryption = 1  # type: ignore
+
+    peer = device.Peer(devices.connections[1])  # type: ignore
+    hap_client = await peer.discover_service_and_create_proxy(
+        hap.HearingAccessServiceProxy
+    )
+    assert hap_client
+    await hap_client.setup_subscription()
+
+    yield hap_client
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_init_service(hap_client: hap.HearingAccessServiceProxy):
+    assert (
+        hap.HearingAidFeatures_from_bytes(await hap_client.server_features.read_value())
+        == server_features
+    )
+    assert (await hap_client.active_preset_index.read_value()) == (foo_preset.index)
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_read_all_presets(hap_client: hap.HearingAccessServiceProxy):
+    await hap_client.hearing_aid_preset_control_point.write_value(
+        bytes([hap.HearingAidPresetControlPointOpcode.READ_PRESETS_REQUEST, 1, 0xFF])
+    )
+    assert (await hap_client.preset_control_point_indications.get()) == bytes(
+        [hap.HearingAidPresetControlPointOpcode.READ_PRESET_RESPONSE, 0]
+    ) + bytes(foo_preset)
+    assert (await hap_client.preset_control_point_indications.get()) == bytes(
+        [hap.HearingAidPresetControlPointOpcode.READ_PRESET_RESPONSE, 0]
+    ) + bytes(foobar_preset)
+    assert (await hap_client.preset_control_point_indications.get()) == bytes(
+        [hap.HearingAidPresetControlPointOpcode.READ_PRESET_RESPONSE, 0]
+    ) + bytes(bar_preset)
+    assert (await hap_client.preset_control_point_indications.get()) == bytes(
+        [hap.HearingAidPresetControlPointOpcode.READ_PRESET_RESPONSE, 1]
+    ) + bytes(unavailable_preset)
+
+    await assert_queue_is_empty(hap_client.preset_control_point_indications)
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_read_partial_presets(hap_client: hap.HearingAccessServiceProxy):
+    await hap_client.hearing_aid_preset_control_point.write_value(
+        bytes([hap.HearingAidPresetControlPointOpcode.READ_PRESETS_REQUEST, 3, 2])
+    )
+    assert (await hap_client.preset_control_point_indications.get())[2:] == bytes(
+        foobar_preset
+    )
+    assert (await hap_client.preset_control_point_indications.get())[2:] == bytes(
+        bar_preset
+    )
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_set_active_preset_valid(hap_client: hap.HearingAccessServiceProxy):
+    await hap_client.hearing_aid_preset_control_point.write_value(
+        bytes(
+            [hap.HearingAidPresetControlPointOpcode.SET_ACTIVE_PRESET, bar_preset.index]
+        )
+    )
+    assert (await hap_client.active_preset_index_notification.get()) == bar_preset.index
+
+    assert (await hap_client.active_preset_index.read_value()) == (bar_preset.index)
+
+    await assert_queue_is_empty(hap_client.active_preset_index_notification)
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_set_active_preset_invalid(hap_client: hap.HearingAccessServiceProxy):
+    with pytest.raises(att.ATT_Error) as e:
+        await hap_client.hearing_aid_preset_control_point.write_value(
+            bytes(
+                [
+                    hap.HearingAidPresetControlPointOpcode.SET_ACTIVE_PRESET,
+                    unavailable_preset.index,
+                ]
+            ),
+            with_response=True,
+        )
+    assert e.value.error_code == hap.ErrorCode.PRESET_OPERATION_NOT_POSSIBLE
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_set_next_preset(hap_client: hap.HearingAccessServiceProxy):
+    await hap_client.hearing_aid_preset_control_point.write_value(
+        bytes([hap.HearingAidPresetControlPointOpcode.SET_NEXT_PRESET])
+    )
+    assert (
+        await hap_client.active_preset_index_notification.get()
+    ) == foobar_preset.index
+
+    assert (await hap_client.active_preset_index.read_value()) == (foobar_preset.index)
+
+    await assert_queue_is_empty(hap_client.active_preset_index_notification)
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_set_next_preset_will_loop_to_first(
+    hap_client: hap.HearingAccessServiceProxy,
+):
+    async def go_next(new_preset: hap.PresetRecord):
+        await hap_client.hearing_aid_preset_control_point.write_value(
+            bytes([hap.HearingAidPresetControlPointOpcode.SET_NEXT_PRESET])
+        )
+        assert (
+            await hap_client.active_preset_index_notification.get()
+        ) == new_preset.index
+
+        assert (await hap_client.active_preset_index.read_value()) == (new_preset.index)
+
+    await go_next(foobar_preset)
+    await go_next(bar_preset)
+    await go_next(foo_preset)
+
+    # Note that there is a invalid preset in the preset record of the server
+
+    await assert_queue_is_empty(hap_client.active_preset_index_notification)
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_set_previous_preset_will_loop_to_last(
+    hap_client: hap.HearingAccessServiceProxy,
+):
+    await hap_client.hearing_aid_preset_control_point.write_value(
+        bytes([hap.HearingAidPresetControlPointOpcode.SET_PREVIOUS_PRESET])
+    )
+    assert (await hap_client.active_preset_index_notification.get()) == bar_preset.index
+
+    assert (await hap_client.active_preset_index.read_value()) == (bar_preset.index)
+
+    await assert_queue_is_empty(hap_client.active_preset_index_notification)
diff --git a/tests/hci_test.py b/tests/hci_test.py
index 72f4022..1b69cda 100644
--- a/tests/hci_test.py
+++ b/tests/hci_test.py
@@ -60,6 +60,8 @@ from bumble.hci import (
     HCI_Number_Of_Completed_Packets_Event,
     HCI_Packet,
     HCI_PIN_Code_Request_Reply_Command,
+    HCI_Read_Local_Supported_Codecs_Command,
+    HCI_Read_Local_Supported_Codecs_V2_Command,
     HCI_Read_Local_Supported_Commands_Command,
     HCI_Read_Local_Supported_Features_Command,
     HCI_Read_Local_Version_Information_Command,
@@ -476,6 +478,51 @@ def test_HCI_LE_Setup_ISO_Data_Path_Command():
     basic_check(command)
 
 
+# -----------------------------------------------------------------------------
+def test_HCI_Read_Local_Supported_Codecs_Command_Complete():
+    returned_parameters = (
+        HCI_Read_Local_Supported_Codecs_Command.parse_return_parameters(
+            bytes([HCI_SUCCESS, 3, CodecID.A_LOG, CodecID.CVSD, CodecID.LINEAR_PCM, 0])
+        )
+    )
+    assert returned_parameters.standard_codec_ids == [
+        CodecID.A_LOG,
+        CodecID.CVSD,
+        CodecID.LINEAR_PCM,
+    ]
+
+
+# -----------------------------------------------------------------------------
+def test_HCI_Read_Local_Supported_Codecs_V2_Command_Complete():
+    returned_parameters = (
+        HCI_Read_Local_Supported_Codecs_V2_Command.parse_return_parameters(
+            bytes(
+                [
+                    HCI_SUCCESS,
+                    3,
+                    CodecID.A_LOG,
+                    HCI_Read_Local_Supported_Codecs_V2_Command.Transport.BR_EDR_ACL,
+                    CodecID.CVSD,
+                    HCI_Read_Local_Supported_Codecs_V2_Command.Transport.BR_EDR_SCO,
+                    CodecID.LINEAR_PCM,
+                    HCI_Read_Local_Supported_Codecs_V2_Command.Transport.LE_CIS,
+                    0,
+                ]
+            )
+        )
+    )
+    assert returned_parameters.standard_codec_ids == [
+        CodecID.A_LOG,
+        CodecID.CVSD,
+        CodecID.LINEAR_PCM,
+    ]
+    assert returned_parameters.standard_codec_transports == [
+        HCI_Read_Local_Supported_Codecs_V2_Command.Transport.BR_EDR_ACL,
+        HCI_Read_Local_Supported_Codecs_V2_Command.Transport.BR_EDR_SCO,
+        HCI_Read_Local_Supported_Codecs_V2_Command.Transport.LE_CIS,
+    ]
+
+
 # -----------------------------------------------------------------------------
 def test_address():
     a = Address('C4:F2:17:1A:1D:BB')
diff --git a/tests/import_test.py b/tests/import_test.py
index e0b6e3c..9542511 100644
--- a/tests/import_test.py
+++ b/tests/import_test.py
@@ -27,7 +27,6 @@ def test_import():
         core,
         crypto,
         device,
-        gap,
         hci,
         hfp,
         host,
@@ -41,6 +40,22 @@ def test_import():
         utils,
     )
 
+    from bumble.profiles import (
+        ascs,
+        bap,
+        bass,
+        battery_service,
+        cap,
+        csip,
+        device_information_service,
+        gap,
+        heart_rate_service,
+        le_audio,
+        pacs,
+        pbp,
+        vcp,
+    )
+
     assert att
     assert bridge
     assert company_ids
@@ -48,7 +63,6 @@ def test_import():
     assert core
     assert crypto
     assert device
-    assert gap
     assert hci
     assert hfp
     assert host
@@ -61,6 +75,20 @@ def test_import():
     assert transport
     assert utils
 
+    assert ascs
+    assert bap
+    assert bass
+    assert battery_service
+    assert cap
+    assert csip
+    assert device_information_service
+    assert gap
+    assert heart_rate_service
+    assert le_audio
+    assert pacs
+    assert pbp
+    assert vcp
+
 
 # -----------------------------------------------------------------------------
 def test_app_imports():
diff --git a/tests/le_audio_test.py b/tests/le_audio_test.py
new file mode 100644
index 0000000..264a96d
--- /dev/null
+++ b/tests/le_audio_test.py
@@ -0,0 +1,39 @@
+# Copyright 2021-2024 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+from bumble.profiles import le_audio
+
+
+def test_parse_metadata():
+    metadata = le_audio.Metadata(
+        entries=[
+            le_audio.Metadata.Entry(
+                tag=le_audio.Metadata.Tag.PROGRAM_INFO,
+                data=b'',
+            ),
+            le_audio.Metadata.Entry(
+                tag=le_audio.Metadata.Tag.STREAMING_AUDIO_CONTEXTS,
+                data=bytes([0, 0]),
+            ),
+            le_audio.Metadata.Entry(
+                tag=le_audio.Metadata.Tag.PREFERRED_AUDIO_CONTEXTS,
+                data=bytes([1, 2]),
+            ),
+        ]
+    )
+
+    assert le_audio.Metadata.from_bytes(bytes(metadata)) == metadata
diff --git a/tests/mcp_test.py b/tests/mcp_test.py
new file mode 100644
index 0000000..c063536
--- /dev/null
+++ b/tests/mcp_test.py
@@ -0,0 +1,132 @@
+# Copyright 2021-2023 Google LLC
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      https://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+# -----------------------------------------------------------------------------
+# Imports
+# -----------------------------------------------------------------------------
+import asyncio
+import dataclasses
+import pytest
+import pytest_asyncio
+import struct
+import logging
+
+from bumble import device
+from bumble.profiles import mcp
+from tests.test_utils import TwoDevices
+
+
+# -----------------------------------------------------------------------------
+# Logging
+# -----------------------------------------------------------------------------
+logger = logging.getLogger(__name__)
+
+
+# -----------------------------------------------------------------------------
+# Helpers
+# -----------------------------------------------------------------------------
+TIMEOUT = 0.1
+
+
+@dataclasses.dataclass
+class GmcsContext:
+    devices: TwoDevices
+    client: mcp.GenericMediaControlServiceProxy
+    server: mcp.GenericMediaControlService
+
+
+# -----------------------------------------------------------------------------
+@pytest_asyncio.fixture
+async def gmcs_context():
+    devices = TwoDevices()
+    server = mcp.GenericMediaControlService()
+    devices[0].add_service(server)
+
+    await devices.setup_connection()
+    devices.connections[0].encryption = 1
+    devices.connections[1].encryption = 1
+    peer = device.Peer(devices.connections[1])
+    client = await peer.discover_service_and_create_proxy(
+        mcp.GenericMediaControlServiceProxy
+    )
+    await client.subscribe_characteristics()
+
+    return GmcsContext(devices=devices, server=server, client=client)
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_update_media_state(gmcs_context):
+    state = asyncio.Queue()
+    gmcs_context.client.on('media_state', state.put_nowait)
+
+    await gmcs_context.devices[0].notify_subscribers(
+        gmcs_context.server.media_state_characteristic,
+        value=bytes([mcp.MediaState.PLAYING]),
+    )
+
+    assert (await asyncio.wait_for(state.get(), TIMEOUT)) == mcp.MediaState.PLAYING
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_update_track_title(gmcs_context):
+    state = asyncio.Queue()
+    gmcs_context.client.on('track_title', state.put_nowait)
+
+    await gmcs_context.devices[0].notify_subscribers(
+        gmcs_context.server.track_title_characteristic,
+        value="My Song".encode(),
+    )
+
+    assert (await asyncio.wait_for(state.get(), TIMEOUT)) == "My Song"
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_update_track_duration(gmcs_context):
+    state = asyncio.Queue()
+    gmcs_context.client.on('track_duration', state.put_nowait)
+
+    await gmcs_context.devices[0].notify_subscribers(
+        gmcs_context.server.track_duration_characteristic,
+        value=struct.pack("<i", 1000),
+    )
+
+    assert (await asyncio.wait_for(state.get(), TIMEOUT)) == 1000
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_update_track_position(gmcs_context):
+    state = asyncio.Queue()
+    gmcs_context.client.on('track_position', state.put_nowait)
+
+    await gmcs_context.devices[0].notify_subscribers(
+        gmcs_context.server.track_position_characteristic,
+        value=struct.pack("<i", 1000),
+    )
+
+    assert (await asyncio.wait_for(state.get(), TIMEOUT)) == 1000
+
+
+# -----------------------------------------------------------------------------
+@pytest.mark.asyncio
+async def test_write_media_control_point(gmcs_context):
+    assert (
+        await asyncio.wait_for(
+            gmcs_context.client.write_control_point(mcp.MediaControlPointOpcode.PAUSE),
+            TIMEOUT,
+        )
+    ) == mcp.MediaControlPointResultCode.SUCCESS
diff --git a/tests/smp_test.py b/tests/smp_test.py
index 7a32b23..7f17bc2 100644
--- a/tests/smp_test.py
+++ b/tests/smp_test.py
@@ -17,13 +17,17 @@
 # -----------------------------------------------------------------------------
 
 import pytest
+from unittest import mock
 
 from bumble import smp
+from bumble import pairing
 from bumble.crypto import EccKey, aes_cmac, ah, c1, f4, f5, f6, g2, h6, h7, s1
 from bumble.pairing import OobData, OobSharedData, LeRole
 from bumble.hci import Address
 from bumble.core import AdvertisingData
+from bumble.device import Device
 
+from typing import Optional
 
 # -----------------------------------------------------------------------------
 # pylint: disable=invalid-name
@@ -251,6 +255,57 @@ def test_link_key_to_ltk(ct2: bool, expected: str):
     assert smp.Session.derive_ltk(LINK_KEY, ct2) == reversed_hex(expected)
 
 
+# -----------------------------------------------------------------------------
+@pytest.mark.parametrize(
+    'identity_address_type, public_address, random_address, expected_identity_address',
+    [
+        (
+            None,
+            Address("00:11:22:33:44:55", Address.PUBLIC_DEVICE_ADDRESS),
+            Address("EE:EE:EE:EE:EE:EE", Address.RANDOM_DEVICE_ADDRESS),
+            Address("00:11:22:33:44:55", Address.PUBLIC_DEVICE_ADDRESS),
+        ),
+        (
+            None,
+            Address.ANY,
+            Address("EE:EE:EE:EE:EE:EE", Address.RANDOM_DEVICE_ADDRESS),
+            Address("EE:EE:EE:EE:EE:EE", Address.RANDOM_DEVICE_ADDRESS),
+        ),
+        (
+            pairing.PairingConfig.AddressType.PUBLIC,
+            Address("00:11:22:33:44:55", Address.PUBLIC_DEVICE_ADDRESS),
+            Address("EE:EE:EE:EE:EE:EE", Address.RANDOM_DEVICE_ADDRESS),
+            Address("00:11:22:33:44:55", Address.PUBLIC_DEVICE_ADDRESS),
+        ),
+        (
+            pairing.PairingConfig.AddressType.RANDOM,
+            Address("00:11:22:33:44:55", Address.PUBLIC_DEVICE_ADDRESS),
+            Address("EE:EE:EE:EE:EE:EE", Address.RANDOM_DEVICE_ADDRESS),
+            Address("EE:EE:EE:EE:EE:EE", Address.RANDOM_DEVICE_ADDRESS),
+        ),
+    ],
+)
+@pytest.mark.asyncio
+async def test_send_identity_address_command(
+    identity_address_type: Optional[pairing.PairingConfig.AddressType],
+    public_address: Address,
+    random_address: Address,
+    expected_identity_address: Address,
+):
+    device = Device()
+    device.public_address = public_address
+    device.static_address = random_address
+    pairing_config = pairing.PairingConfig(identity_address_type=identity_address_type)
+    session = smp.Session(device.smp_manager, mock.MagicMock(), pairing_config, True)
+
+    with mock.patch.object(session, 'send_command') as mock_method:
+        session.send_identity_address_command()
+
+    actual_command = mock_method.call_args.args[0]
+    assert actual_command.addr_type == expected_identity_address.address_type
+    assert actual_command.bd_addr == expected_identity_address
+
+
 # -----------------------------------------------------------------------------
 if __name__ == '__main__':
     test_ecc()
diff --git a/tests/vcp_test.py b/tests/vcp_test.py
index d45a5f5..5853ed9 100644
--- a/tests/vcp_test.py
+++ b/tests/vcp_test.py
@@ -39,6 +39,9 @@ async def vcp_client():
 
     await devices.setup_connection()
 
+    assert devices.connections[0]
+    assert devices.connections[1]
+
     # Mock encryption.
     devices.connections[0].encryption = 1
     devices.connections[1].encryption = 1
diff --git a/web/.gitignore b/web/.gitignore
new file mode 100644
index 0000000..1d9b8aa
--- /dev/null
+++ b/web/.gitignore
@@ -0,0 +1,3 @@
+# files created by invoke web.build
+*.whl
+packageFile
diff --git a/web/README.md b/web/README.md
index a8cc89c..532dfd1 100644
--- a/web/README.md
+++ b/web/README.md
@@ -24,9 +24,14 @@ controller using some other transport (ex: `python apps/hci_bridge.py ws-server:
 For HTTP, start an HTTP server with the `web` directory as its
 root. You can use the invoke task `inv web.serve` for convenience.
 
+`inv web.build` will build the local copy of bumble and automatically copy the `.whl` file
+to the web directory. To use this build, include the param `?packageFile=true` to the URL.
+
 In a browser, open either `scanner/scanner.html` or `speaker/speaker.html`.
 You can pass optional query parameters:
 
+  * `packageFile=true` will automatically use the bumble package built via the
+    `inv web.build` command.
   * `package` may be set to point to a local build of Bumble (`.whl` files).
      The filename must be URL-encoded of course, and must be located under
      the `web` directory (the HTTP server won't serve files not under its
@@ -45,4 +50,6 @@ Example:
 
 
 NOTE: to get a local build of the Bumble package, use `inv build`, the built `.whl` file can be found in the `dist` directory. 
-Make a copy of the built `.whl` file in the `web` directory.
\ No newline at end of file
+Make a copy of the built `.whl` file in the `web` directory.
+
+Tip: During web developement, disable caching. [Chrome](https://stackoverflow.com/a/7000899]) / [Firefiox](https://stackoverflow.com/a/289771)
\ No newline at end of file
diff --git a/web/bumble.js b/web/bumble.js
index c554bc2..33b62f6 100644
--- a/web/bumble.js
+++ b/web/bumble.js
@@ -75,7 +75,6 @@ export class Bumble extends EventTarget {
         }
 
         // Load the Bumble module
-        bumblePackage ||= 'bumble';
         console.log('Installing micropip');
         this.log(`Installing ${bumblePackage}`)
         await this.pyodide.loadPackage('micropip');
@@ -166,6 +165,20 @@ export class Bumble extends EventTarget {
     }
 }
 
+async function getBumblePackage() {
+    const params = (new URL(document.location)).searchParams;
+    // First check the packageFile override param
+    if (params.has('packageFile')) {
+        return await (await fetch('/packageFile')).text() 
+    }
+    // Then check the package override param
+    if (params.has('package')) {
+        return params.get('package')
+    }
+    // If no override params, default to the main package
+    return 'bumble'
+}
+
 export async function setupSimpleApp(appUrl, bumbleControls, log) {
     // Load Bumble
     log('Loading Bumble');
@@ -173,8 +186,7 @@ export async function setupSimpleApp(appUrl, bumbleControls, log) {
     bumble.addEventListener('log', (event) => {
         log(event.message);
     })
-    const params = (new URL(document.location)).searchParams;
-    await bumble.loadRuntime(params.get('package'));
+    await bumble.loadRuntime(await getBumblePackage());
 
     log('Bumble is ready!')
     const app = await bumble.loadApp(appUrl);
diff --git a/web/favicon.ico b/web/favicon.ico
new file mode 120000
index 0000000..505de13
--- /dev/null
+++ b/web/favicon.ico
@@ -0,0 +1 @@
+../docs/images/favicon.ico
\ No newline at end of file
diff --git a/web/scanner/scanner.py b/web/scanner/scanner.py
index 9ff6aba..69ee43a 100644
--- a/web/scanner/scanner.py
+++ b/web/scanner/scanner.py
@@ -15,12 +15,21 @@
 # -----------------------------------------------------------------------------
 # Imports
 # -----------------------------------------------------------------------------
+import pyee
+
 from bumble.device import Device
 from bumble.hci import HCI_Reset_Command
 
 
 # -----------------------------------------------------------------------------
-class Scanner:
+class Scanner(pyee.EventEmitter):
+    """
+    Scanner web app
+
+    Emitted events:
+        update: Emit when new `ScanEntry` are available.
+    """
+
     class ScanEntry:
         def __init__(self, advertisement):
             self.address = advertisement.address.to_string(False)
@@ -39,13 +48,12 @@ class Scanner:
             'Bumble', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink
         )
         self.scan_entries = {}
-        self.listeners = {}
         self.device.on('advertisement', self.on_advertisement)
 
     async def start(self):
         print('### Starting Scanner')
         self.scan_entries = {}
-        self.emit_update()
+        self.emit('update', self.scan_entries)
         await self.device.power_on()
         await self.device.start_scanning()
         print('### Scanner started')
@@ -56,16 +64,9 @@ class Scanner:
         await self.device.power_off()
         print('### Scanner stopped')
 
-    def emit_update(self):
-        if listener := self.listeners.get('update'):
-            listener(list(self.scan_entries.values()))
-
-    def on(self, event_name, listener):
-        self.listeners[event_name] = listener
-
     def on_advertisement(self, advertisement):
         self.scan_entries[advertisement.address] = self.ScanEntry(advertisement)
-        self.emit_update()
+        self.emit('update', self.scan_entries)
 
 
 # -----------------------------------------------------------------------------
```

