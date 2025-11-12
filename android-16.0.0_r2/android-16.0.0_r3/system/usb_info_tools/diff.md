```diff
diff --git a/dumpsys_to_lsusb/Android.bp b/dumpsys_to_lsusb/Android.bp
new file mode 100644
index 0000000..9070948
--- /dev/null
+++ b/dumpsys_to_lsusb/Android.bp
@@ -0,0 +1,48 @@
+// Copyright 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_team: "trendy_team_android_usb",
+}
+
+rust_defaults {
+    name: "dumpsys_to_lsusb_defaults",
+    rustlibs: [
+        "liblog_rust",
+        "liblogger",
+        "libanyhow",
+        "libframework_usb_protos_rs",
+        "libprotobuf",
+        "libtypec_sysfs_helper",
+        "libwalkdir",
+        "libclap",
+    ],
+}
+
+rust_binary {
+    name: "dumpsys_to_lsusb",
+    crate_name: "dumpsys_to_lsusb",
+    srcs: ["src/main.rs"],
+    defaults: ["dumpsys_to_lsusb_defaults"],
+    prefer_rlib: true,
+}
+
+rust_test {
+    name: "dumpsys_to_lsusb_test",
+    crate_name: "dumpsys_to_lsusb_test",
+    srcs: ["src/main.rs"],
+    defaults: ["dumpsys_to_lsusb_defaults"],
+    test_suites: ["general-tests"],
+    auto_gen_config: true,
+}
diff --git a/dumpsys_to_lsusb/src/main.rs b/dumpsys_to_lsusb/src/main.rs
new file mode 100644
index 0000000..da56137
--- /dev/null
+++ b/dumpsys_to_lsusb/src/main.rs
@@ -0,0 +1,646 @@
+// Copyright 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! Parses `dumpsys usb` data from an Android device and outputs it in a format similar to `lsusb` verbose and tree (usbutils).
+use anyhow::{anyhow, bail, Context, Result};
+use clap::{Parser, ValueEnum};
+use framework_usb_protos_rs::enums::UsbEndPointDirection;
+use framework_usb_protos_rs::enums::UsbEndPointType;
+use framework_usb_protos_rs::usb::UsbDeviceProto;
+use framework_usb_protos_rs::usb::UsbServiceDumpProto;
+use log::debug;
+use protobuf::Message;
+use std::collections::HashMap;
+use std::fmt;
+use std::fs::{self, read_link};
+use std::io::stdout;
+use std::io::Write;
+use std::num::ParseIntError;
+use std::path::{Path, PathBuf};
+use std::process::Command;
+use typec_sysfs_helper::typec_class_utils::OutputWriter;
+use walkdir::WalkDir;
+
+const INDENT_STEP: usize = 2;
+const INDENT_STEP_TREE: usize = 4;
+const USB_SYSFS_PATH_PREFIX: &str = "/sys/bus/usb/devices";
+const TREE_ROOT_SYMBOL: &str = "/:  ";
+const BRANCH_SYMBOL: &str = "|__";
+const LEAF_KEY: &str = "";
+
+/// Encapsulates the output format for the `dumpsys_to_lsusb` tool.
+#[derive(ValueEnum, Clone, Debug, PartialEq, Eq)]
+enum OutputFormat {
+    /// Prints detailed information about USB devices, their configurations, interfaces, and endpoints.
+    Verbose,
+    /// Prints a tree-like representation of the device hierarchy.
+    Tree,
+}
+
+/// Defines the log levels that can be set via command-line arguments.
+///
+/// Reflects the log levels from log::LevelFilter.
+#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
+enum LogLevel {
+    Off,
+    Error,
+    Warn,
+    Info,
+    Debug,
+    Trace,
+}
+
+impl From<LogLevel> for log::LevelFilter {
+    fn from(level: LogLevel) -> Self {
+        match level {
+            LogLevel::Off => log::LevelFilter::Off,
+            LogLevel::Error => log::LevelFilter::Error,
+            LogLevel::Warn => log::LevelFilter::Warn,
+            LogLevel::Info => log::LevelFilter::Info,
+            LogLevel::Debug => log::LevelFilter::Debug,
+            LogLevel::Trace => log::LevelFilter::Trace,
+        }
+    }
+}
+
+#[derive(Parser, Debug)]
+#[command(version = "1.0", about = "Display information about connected USB devices", long_about = None)]
+struct Args {
+    #[arg(value_enum, short, long, default_value_t = OutputFormat::Verbose)]
+    format: OutputFormat,
+    #[arg(value_enum, long, default_value_t = LogLevel::Info)]
+    log_level: LogLevel,
+}
+
+/// Extracts the bus number and the device number from a USB path.
+///
+/// The function expects a path in the format `/dev/bus/usb/<bus>/<dev>`. If the path does not
+/// match this format, it returns (0, 0). The USB path represents the device location in sysfs,
+/// where the bus number is the bus on which the device is connected, and the device number is the
+/// device's address on that bus.
+fn extract_bus_dev(usb_path: &str) -> (u8, u8) {
+    let path = Path::new(usb_path);
+    if path.starts_with("/dev/bus/usb") {
+        let path_comp: Vec<_> = path.components().collect();
+        let bus_str = path_comp[path_comp.len() - 2].as_os_str().to_string_lossy();
+        let dev_str = path_comp[path_comp.len() - 1].as_os_str().to_string_lossy();
+        return (
+            bus_str.parse::<u8>().unwrap_or_default(),
+            dev_str.parse::<u8>().unwrap_or_default(),
+        );
+    }
+    (0, 0)
+}
+
+/// Prints a key-value pair with aligned output, using the provided `OutputWriter`.
+///
+/// The value is printed as a string, and if the value is `None`, an empty string is printed. The
+/// key is left-aligned to 20 characters, and the value follows.
+fn print_aligned_string_output<W: Write>(
+    key: &str,
+    value: Option<String>,
+    outp_writer: &mut OutputWriter<W>,
+) -> Result<()> {
+    outp_writer.print_str_indent(&format!("{:<20} {}", key, value.unwrap_or_default()))
+}
+
+/// Prints a key-value pair with aligned output, using the provided `OutputWriter`.
+///
+/// The value is printed as a hexadecimal number, and if the value is `None`, 0 is printed. The
+/// key is left-aligned to 20 characters, and the value is a 4-digit hexadecimal number.
+fn print_aligned_hex_output<W: Write>(
+    key: &str,
+    value: Option<String>,
+    outp_writer: &mut OutputWriter<W>,
+) -> Result<()> {
+    outp_writer.print_str_indent(&format!(
+        "{:<20} 0x{:04x}",
+        key,
+        value.unwrap_or_default().parse::<i32>().unwrap_or_default()
+    ))
+}
+
+/// Holds the information needed to print a field of a structure.
+///
+/// The `key` is the name of the field, `value` is the value of the field, and `print_fn` is
+/// the function that prints the key-value pair using an `OutputWriter`.struct PrintableStructField<'a, W: std::io::Write> {
+struct PrintableStructField<'a, W: std::io::Write> {
+    key: &'a str,
+    value: Option<String>,
+    print_fn: fn(&str, Option<String>, &mut OutputWriter<W>) -> Result<()>,
+}
+
+impl<'a, W: std::io::Write> PrintableStructField<'a, W> {
+    fn new(
+        key: &'a str,
+        value: Option<String>,
+        print_fn: fn(&str, Option<String>, &mut OutputWriter<W>) -> Result<()>,
+    ) -> Self {
+        PrintableStructField { key, value, print_fn }
+    }
+}
+
+/// Prints a list of fields to the output writer.
+fn print_struct_fields<W: Write>(
+    fields_to_print: &[PrintableStructField<'_, W>],
+    outp_writer: &mut OutputWriter<W>,
+) -> Result<()> {
+    fields_to_print.iter().try_for_each(|f| (f.print_fn)(f.key, f.value.clone(), outp_writer))
+}
+
+/// Finds the path to the device's sysfs directory.
+///
+/// The function uses the bus number and the device number to construct the path to the device's
+/// sysfs directory. It iterates through all directories under the sysfs path prefix, and returns
+/// the path to the directory whose devnum matches the provided devnum. If no matching directory
+/// is found, it returns an error.
+fn find_sysfs_usb_path(busnum: u8, devnum: u8) -> Result<PathBuf> {
+    let path_root = format!("{USB_SYSFS_PATH_PREFIX}/usb{busnum}");
+    let dir_walker = WalkDir::new(path_root.clone()).into_iter();
+    for entry in dir_walker.filter_entry(|e| e.file_type().is_dir()) {
+        let mut entry_path = entry?.into_path();
+        entry_path.push("devnum");
+        if let Ok(devnum_str) = fs::read_to_string(&entry_path) {
+            if devnum_str.trim().parse::<u8>().unwrap_or_default() == devnum {
+                entry_path.pop();
+                return Ok(entry_path);
+            }
+        }
+    }
+    bail!("Cannot find sysfs path for device {busnum}, {devnum}, {path_root}")
+}
+
+/// Reads the USB device information from sysfs.
+///
+/// The function reads the USB device information from sysfs, which is the kernel's view of the
+/// device. It uses the path to the device's sysfs directory and the file name to read the information.
+/// The read value is trimmed.
+fn read_sysfs_info(device_sysfs_path: &Path, file_name: &str) -> Result<String> {
+    let file_path = device_sysfs_path.join(file_name);
+    let sysfs_contents = fs::read_to_string(&file_path)
+        .with_context(|| format!("Failed to read sysfs file: {:?}", file_path))?;
+    Ok(sysfs_contents.trim().to_string())
+}
+
+/// Prints USB device information in a format similar to `lsusb -v`.
+///
+/// The function iterates through the provided `devices` and prints detailed information about
+/// each device, including its device descriptor, configuration descriptors, interface descriptors,
+/// and endpoint descriptors. The output is formatted using the provided `OutputWriter`.lsusb
+fn lsusb_v<W: Write>(devices: &[UsbDeviceProto], outp_writer: &mut OutputWriter<W>) -> Result<()> {
+    for device in devices {
+        let (busnum, devnum) = extract_bus_dev(&device.name.clone().unwrap_or_default());
+        let device_path: PathBuf = find_sysfs_usb_path(busnum, devnum)?;
+        outp_writer.print_str_indent(&format!(
+            "Bus {} Device {}: ID {:04x}:{:04x} {} {}",
+            busnum,
+            devnum,
+            device.vendor_id.unwrap_or_default(),
+            device.product_id.unwrap_or_default(),
+            device.manufacturer_name.clone().unwrap_or_default(),
+            device.product_name.clone().unwrap_or_default(),
+        ))?;
+
+        // Device info
+        outp_writer.print_str_indent("Device Descriptor:")?;
+        outp_writer.indent += INDENT_STEP;
+        let configs = &device.configurations;
+        let device_fields_to_print = &[
+            PrintableStructField::new(
+                "class",
+                // TODO b/419018462: add mechanism to decode class based on https://www.usb.org/defined-class-codes
+                Some(device.class.map_or("0".to_string(), |s| s.to_string())),
+                print_aligned_hex_output,
+            ),
+            PrintableStructField::new(
+                "subclass",
+                Some(device.subclass.map_or("0".to_string(), |s| s.to_string())),
+                print_aligned_string_output,
+            ),
+            PrintableStructField::new(
+                "protocol",
+                Some(device.protocol.map_or("0".to_string(), |s| s.to_string())),
+                print_aligned_string_output,
+            ),
+            PrintableStructField::new(
+                "serial_number",
+                device.serial_number.clone(),
+                print_aligned_string_output,
+            ),
+            PrintableStructField::new(
+                "speed",
+                read_sysfs_info(&device_path, "speed").map(|s| format!("{}M", s.trim())).ok(),
+                print_aligned_string_output,
+            ),
+            PrintableStructField::new(
+                "bcdUSB",
+                Some(read_sysfs_info(&device_path, "version")?),
+                print_aligned_string_output,
+            ),
+            PrintableStructField::new(
+                "num_configurations",
+                Some(configs.len().to_string()),
+                print_aligned_string_output,
+            ),
+        ];
+        print_struct_fields(device_fields_to_print, outp_writer)?;
+
+        // Configurations info
+        for config in configs {
+            outp_writer.print_str_indent("Configuration Descriptor:")?;
+            outp_writer.indent += INDENT_STEP;
+
+            let interfaces = &config.interfaces;
+            let config_fields_to_print = &[
+                PrintableStructField::new(
+                    "id",
+                    config.id.map(|s| s.to_string()),
+                    print_aligned_string_output,
+                ),
+                PrintableStructField::new("name", config.name.clone(), print_aligned_string_output),
+                PrintableStructField::new(
+                    "attributes",
+                    config.attributes.map(|s| s.to_string()),
+                    print_aligned_hex_output,
+                ),
+                PrintableStructField::new(
+                    "max_power",
+                    config.max_power.map(|s| s.to_string() + "mA"),
+                    print_aligned_string_output,
+                ),
+                PrintableStructField::new(
+                    "num_interfaces",
+                    Some(config.interfaces.len().to_string()),
+                    print_aligned_string_output,
+                ),
+            ];
+            print_struct_fields(config_fields_to_print, outp_writer)?;
+
+            // Interfaces info
+            for interface in interfaces {
+                outp_writer.print_str_indent("Interface Descriptor:")?;
+                outp_writer.indent += INDENT_STEP;
+
+                let endpoints = &interface.endpoints;
+                let interface_fields_to_print = &[
+                    PrintableStructField::new(
+                        "id",
+                        interface.id.map(|s| s.to_string()),
+                        print_aligned_string_output,
+                    ),
+                    PrintableStructField::new(
+                        "name",
+                        interface.name.clone(),
+                        print_aligned_string_output,
+                    ),
+                    PrintableStructField::new(
+                        "alternate_settings",
+                        interface.alternate_settings.map(|s| s.to_string()),
+                        print_aligned_string_output,
+                    ),
+                    PrintableStructField::new(
+                        "class",
+                        interface.class.map(|s| s.to_string()),
+                        print_aligned_string_output,
+                    ),
+                    PrintableStructField::new(
+                        "subclass",
+                        interface.subclass.map(|s| s.to_string()),
+                        print_aligned_string_output,
+                    ),
+                    PrintableStructField::new(
+                        "protocol",
+                        interface.protocol.map(|s| s.to_string()),
+                        print_aligned_string_output,
+                    ),
+                    PrintableStructField::new(
+                        "num_endpoints",
+                        Some(endpoints.len().to_string()),
+                        print_aligned_string_output,
+                    ),
+                ];
+                print_struct_fields(interface_fields_to_print, outp_writer)?;
+
+                // Endpoints info
+                for endp in endpoints {
+                    outp_writer.print_str_indent("Endpoint Descriptor:")?;
+                    outp_writer.indent += INDENT_STEP;
+                    let endpoint_type: Option<UsbEndPointType> =
+                        endp.type_.map(|e| e.enum_value_or_default());
+                    let endpoint_direction: Option<UsbEndPointDirection> =
+                        endp.direction.map(|e| e.enum_value_or_default());
+                    let endp_fields_to_print = &[
+                        PrintableStructField::new(
+                            "endpoint_number",
+                            endp.endpoint_number.map(|s| s.to_string()),
+                            print_aligned_string_output,
+                        ),
+                        PrintableStructField::new(
+                            "type",
+                            endpoint_type.map(|e| format!("{:?}", e)),
+                            print_aligned_string_output,
+                        ),
+                        PrintableStructField::new(
+                            "address",
+                            endp.address.map(|s| s.to_string()),
+                            print_aligned_hex_output,
+                        ),
+                        PrintableStructField::new(
+                            "direction",
+                            endpoint_direction.map(|e| format!("{:?}", e)),
+                            print_aligned_string_output,
+                        ),
+                        PrintableStructField::new(
+                            "attributes",
+                            endp.attributes.map(|s| s.to_string()),
+                            print_aligned_string_output,
+                        ),
+                        PrintableStructField::new(
+                            "max_packet_size",
+                            endp.max_packet_size.map(|s| s.to_string()),
+                            print_aligned_hex_output,
+                        ),
+                        PrintableStructField::new(
+                            "interval",
+                            endp.interval.map(|s| s.to_string()),
+                            print_aligned_hex_output,
+                        ),
+                    ];
+                    print_struct_fields(endp_fields_to_print, outp_writer)?;
+                    outp_writer.indent -= INDENT_STEP;
+                }
+                outp_writer.indent -= INDENT_STEP;
+            }
+            outp_writer.indent -= INDENT_STEP;
+        }
+        outp_writer.indent -= INDENT_STEP;
+    }
+    Ok(())
+}
+
+/// Holds the representation of a device in the context of the tree command
+#[derive(Debug)]
+struct UsbDeviceReprTree {
+    devnum: u8,
+    interface: Option<u8>,
+    configuration: Option<u8>,
+    class: Option<i32>,
+    driver: Option<String>,
+    speed: Option<u32>,
+}
+
+impl fmt::Display for UsbDeviceReprTree {
+    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
+        let mut output: String = format!("Dev {:03}", self.devnum);
+        if let Some(cfg) = self.configuration {
+            output.push_str(&format!(", Cfg {cfg}"));
+        }
+        if let Some(intf) = self.interface {
+            output.push_str(&format!(", If {intf}"));
+        }
+        output.push_str(&format!(
+            ", Class=0x{:04x}, Driver={}, {}M",
+            self.class.unwrap_or_default(),
+            self.driver.clone().unwrap_or_default(),
+            self.speed.unwrap_or_default()
+        ));
+        write!(f, "{}", output)
+    }
+}
+
+/// Organizes USB devices in a hierarchy using hash maps.
+///
+/// The `UsbDeviceHierarchy` is a map where keys are strings like "Bus 001" or "Port 001".
+/// Each key maps to a `HierarchyNode`, which can be either:
+///   - `Branch(UsbDeviceHierarchy)`: Represents a sub-level, i.e., a port with its sub-ports
+///   - `Leaf(UsbDeviceReprTree)`: Contains the actual device information.
+///
+/// Conceptual example of the hierarchy this structure represents:
+///
+/// Bus 001: Branch (
+/// ├── Port 001: Leaf(Dev 001, Class=root_hub, Driver=vhci_hcd/4p, 1000M)
+/// ├── Port 002: Branch (
+/// │   ├── Port 001: Leaf(Dev 003, Class=Audio, Driver=snd-usb-audio, 5000M)
+/// │   └── Port 003: Leaf(Dev 005, Class=Audio, Driver=snd-usb-audio, 5000M)
+/// |   )
+/// └── Port 003: Leaf(Dev 004, Class=Vendor Specific Class, Driver=usbfs, 5000M)
+/// )
+/// Bus 002 Branch (
+/// └── Port 001: Leaf(Dev 002, Class=root_hub, Driver=vhci_hcd/4p, 1000M)
+/// )
+///
+/// Note: Internally, a `Leaf` node (device information) is stored under an empty
+/// string key (`LEAF_KEY`) within a `Branch` node.
+type UsbDeviceHierarchy = HashMap<String, HierarchyNode>;
+
+/// Holds the information about a node in the USB device hierarchy.
+///
+/// The node can either be a branch (i.e., a sub-hierarchy) or a leaf (i.e., the device
+/// information).
+#[derive(Debug)]
+enum HierarchyNode {
+    Branch(UsbDeviceHierarchy),
+    Leaf(UsbDeviceReprTree),
+}
+
+#[derive(Debug, PartialEq, Eq)]
+enum UsbPathComponent {
+    Bus(u8),
+    Port(u8),
+    Configuration(u8),
+    Interface(u8),
+}
+
+/// Adds the information about a device to the hierarchy.
+fn add_device_to_hierarchy(
+    hierarchy: &mut UsbDeviceHierarchy,
+    dev_path: &Path,
+    mut dev_repr: UsbDeviceReprTree,
+) -> Result<()> {
+    let path_to_device = dev_path.file_name().and_then(|os_str| os_str.to_str()).unwrap_or("");
+
+    // Traverse the path.
+    // USB device path format: /sys/bus/usb/devices/<busnum>-<port[.port]>...:<config num>.<interface num>
+    //
+    // Symbols meaning:
+    //     * "-" separates the bus nr. from the rest of the path (<bus_num>-<rest_of_path>)
+    //     * "." separates either:
+    //         * ports (<bus_num>.<port>.<port>.<port>)
+    //         * config and if numbers (<config_num>.<if_num>)
+    //     * ":" comes before a configuration number
+    let mut path_components: Vec<UsbPathComponent> = Vec::new();
+
+    // Split the path into a first part that starts with bus number and second that starts with config number by ":"
+    let (bus_part, config_part) = match path_to_device.split_once(":") {
+        Some((bus, config)) => (bus, Some(config)),
+        _ => (path_to_device, None),
+    };
+    // Parse bus part, extract bus
+    let dash_count = bus_part.matches("-").count();
+    let (bus_num, ports) = match dash_count {
+        1 => bus_part
+            .split_once("-")
+            .expect("Malformed device path, delimiter count was 1, split_once must succeed"),
+        _ => bail!("Malformed device path, no bus number included"),
+    };
+    path_components.push(UsbPathComponent::Bus(bus_num.parse::<u8>()?));
+    // Extract ports
+    let mut port_components = ports
+        .split('.')
+        .map(|s| Ok::<UsbPathComponent, ParseIntError>(UsbPathComponent::Port(s.parse::<u8>()?)))
+        .collect::<Result<Vec<_>, _>>()?;
+    path_components.append(&mut port_components);
+
+    // Parse config part
+    if let Some(config_part) = config_part {
+        let (conf_num, if_num) = config_part.split_once(".").expect("Malformed device path, configuration number and interface number should be split by a `.`");
+        path_components.push(UsbPathComponent::Configuration(conf_num.parse::<u8>()?));
+        path_components.push(UsbPathComponent::Interface(if_num.parse::<u8>()?));
+    };
+
+    // Add to hierarchy
+    let mut hierarchy_ptr = hierarchy;
+    for component in path_components {
+        match component {
+            UsbPathComponent::Bus(bus_num) => {
+                let bus_key = format!("Bus {:03}", bus_num); // current key
+                let next_node = hierarchy_ptr
+                    .entry(bus_key)
+                    .or_insert_with(|| HierarchyNode::Branch(HashMap::new()));
+                if let HierarchyNode::Branch(next_hierarchy_ptr) = next_node {
+                    // update the hierarchy pointer.
+                    hierarchy_ptr = next_hierarchy_ptr;
+                } else {
+                    bail!("Found a device already at the same physical position. This should not happen.");
+                }
+            }
+            UsbPathComponent::Port(port_num) => {
+                let port_key = format!("Port {:03}", port_num);
+                let next_node = hierarchy_ptr
+                    .entry(port_key)
+                    .or_insert_with(|| HierarchyNode::Branch(HashMap::new()));
+                if let HierarchyNode::Branch(next_hierarchy_ptr) = next_node {
+                    // update the hierarchy pointer.
+                    hierarchy_ptr = next_hierarchy_ptr;
+                } else {
+                    bail!("Found a device already at the same physical position. This should not happen.");
+                }
+            }
+            UsbPathComponent::Configuration(cfg_num) => {
+                dev_repr.configuration = Some(cfg_num);
+            }
+            UsbPathComponent::Interface(if_num) => {
+                dev_repr.interface = Some(if_num);
+            }
+        }
+    }
+    hierarchy_ptr.insert(LEAF_KEY.to_string(), HierarchyNode::Leaf(dev_repr));
+    Ok(())
+}
+
+/// Prints one level of the device hierarchy and recursively calls itself for the next level.
+fn print_device_hierarchy<W: Write>(
+    hierarchy: &UsbDeviceHierarchy,
+    outp_writer: &mut OutputWriter<W>,
+) -> Result<()> {
+    let mut keys_sorted: Vec<&String> = hierarchy.keys().collect();
+    keys_sorted.sort_unstable();
+    for key in keys_sorted {
+        let prefix = match outp_writer.indent {
+            0 => TREE_ROOT_SYMBOL,
+            _ => BRANCH_SYMBOL,
+        };
+        match hierarchy.get(key).unwrap() {
+            // unwrap is acceptable as if the key that has just been taken from the map has disappeared this is a sign of a serious issue.
+            HierarchyNode::Branch(sub_hierarchy) => {
+                // check if it is the node just above the leaf
+                if sub_hierarchy.len() == 1 && sub_hierarchy.contains_key(LEAF_KEY) {
+                    if let Some(HierarchyNode::Leaf(value)) = sub_hierarchy.get(LEAF_KEY) {
+                        outp_writer.print_str_indent(&format!("{prefix}{}: {}", key, value))?;
+                    } else {
+                        bail!("Malformed hierarchy {:?}", hierarchy);
+                    }
+                } else {
+                    outp_writer.print_str_indent(&format!("{prefix}{}", key))?;
+                    outp_writer.indent += INDENT_STEP_TREE;
+                    print_device_hierarchy(sub_hierarchy, outp_writer)?;
+                    outp_writer.indent -= INDENT_STEP_TREE;
+                }
+            }
+            HierarchyNode::Leaf(dev_repr) => {
+                outp_writer.print_str_indent(&format!("{prefix}{}", dev_repr))?;
+            }
+        }
+    }
+    Ok(())
+}
+
+/// Prints USB device information in a format similar to `lsusb -t`.
+///
+/// The function iterates through the provided `devices` and prints a tree-like representation
+/// of the USB bus and device hierarchy.
+fn lsusb_t<W: Write>(devices: &[UsbDeviceProto], outp_writer: &mut OutputWriter<W>) -> Result<()> {
+    let mut device_hierarchy: UsbDeviceHierarchy = HashMap::new();
+    for device in devices {
+        let (busnum, devnum) = extract_bus_dev(&device.name.clone().unwrap_or_default());
+        let mut device_path: PathBuf = find_sysfs_usb_path(busnum, devnum)?;
+        debug!("{:?}", device_path);
+        let device_repr = UsbDeviceReprTree {
+            devnum,
+            interface: None,
+            configuration: None,
+            class: device.class,
+            driver: {
+                device_path.push("driver");
+                let driver = read_link(&device_path).ok().and_then(|target_path: PathBuf| {
+                    target_path.file_name().map(|os_str| os_str.to_string_lossy().into_owned())
+                });
+                device_path.pop();
+                driver
+            },
+            speed: read_sysfs_info(&device_path, "speed")
+                .map(|s| s.parse::<u32>().unwrap_or(0))
+                .ok(),
+        };
+        add_device_to_hierarchy(&mut device_hierarchy, &device_path, device_repr)?;
+    }
+    debug!("Constructed device hierarchy: {:?}", device_hierarchy);
+    print_device_hierarchy(&device_hierarchy, outp_writer)?;
+    Ok(())
+}
+
+fn main() -> Result<()> {
+    let args = Args::parse();
+    logger::init(
+        logger::Config::default()
+            .with_tag_on_device("usb_info")
+            .with_max_level(args.log_level.into()),
+    );
+
+    // Fetch dumpsys usb data.
+    let output = Command::new("dumpsys").arg("usb").arg("--proto").output()?;
+    let Ok(usb_service_dump) = UsbServiceDumpProto::parse_from_bytes(&output.stdout) else {
+        return Err(anyhow!("Cannot decode dumpsys usb data"));
+    };
+    let usb_host_manager = usb_service_dump.host_manager;
+
+    // Produce the output.
+    let mut outp_writer = OutputWriter::new(stdout(), 0);
+    match args.format {
+        OutputFormat::Verbose => lsusb_v(&usb_host_manager.devices, &mut outp_writer)?,
+        OutputFormat::Tree => lsusb_t(&usb_host_manager.devices, &mut outp_writer)?,
+    }
+
+    Ok(())
+}
diff --git a/typec_connector_class_helper/Android.bp b/typec_connector_class_helper/Android.bp
index a54abc6..ffe1678 100644
--- a/typec_connector_class_helper/Android.bp
+++ b/typec_connector_class_helper/Android.bp
@@ -41,7 +41,12 @@ rust_test {
     defaults: ["typec_connector_class_helper_defaults"],
     test_suites: ["general-tests"],
     auto_gen_config: true,
-    // Required to access /dev/cros_ec.
-    require_root: true,
     rustlibs: ["libtempfile"],
 }
+
+rust_library {
+    name: "libtypec_sysfs_helper",
+    crate_name: "typec_sysfs_helper",
+    srcs: ["src/lib.rs"],
+    defaults: ["typec_connector_class_helper_defaults"],
+}
diff --git a/typec_connector_class_helper/src/lib.rs b/typec_connector_class_helper/src/lib.rs
new file mode 100644
index 0000000..4c60600
--- /dev/null
+++ b/typec_connector_class_helper/src/lib.rs
@@ -0,0 +1,20 @@
+// Copyright 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! Provides utilities for parsing and displaying information from the Type-C connector
+//! class in the Linux kernel. It includes functions for reading and decoding VDOs, identifying
+//! different types of devices, and printing information about ports, partners, cables, and plugs.
+
+pub mod typec_class_utils;
+pub mod usb_pd_utils;
diff --git a/typec_connector_class_helper/src/main.rs b/typec_connector_class_helper/src/main.rs
index 34baa11..166f48b 100644
--- a/typec_connector_class_helper/src/main.rs
+++ b/typec_connector_class_helper/src/main.rs
@@ -12,7 +12,11 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-//! main
+//! Provides a command-line tool to query and display information about
+//! USB-C ports using the Typec Connector Class.
+//!
+//! It iterates through the Typec Connector Class sysfs entries, parses the
+//! relevant information, and prints it to the standard output.
 
 mod typec_class_utils;
 mod usb_pd_utils;
diff --git a/typec_connector_class_helper/src/typec_class_utils.rs b/typec_connector_class_helper/src/typec_class_utils.rs
index 8fc93d0..0b80099 100644
--- a/typec_connector_class_helper/src/typec_class_utils.rs
+++ b/typec_connector_class_helper/src/typec_class_utils.rs
@@ -12,7 +12,8 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-//! typec_class_utils
+//! Provides utility functions for parsing and printing information from the Type-C connector class in sysfs.
+//! It includes functions for reading and decoding VDOs, printing directory contents, and handling different types of devices and ports.
 
 use crate::usb_pd_utils::*;
 use anyhow::{bail, Context, Result};
@@ -24,20 +25,32 @@ use std::{
     path::{Path, PathBuf},
 };
 
+/// The base path for the Type-C connector class in sysfs.
 pub const TYPEC_SYSFS_PATH: &str = "/sys/class/typec";
 
+/// Regex for matching mode directories (e.g., "mode0", "mode1").
 pub const MODE_REGEX: &str = "^mode[0-9]+$";
+/// Regex for matching plug alternate mode directories (e.g., "port0-plug1.0").
 pub const PLUG_ALT_MODE_REGEX: &str = "^port[0-9]+\\-plug[0-9]+\\.[0-9]+$";
+/// Regex for matching plug directories (e.g., "port0-plug1").
 pub const PLUG_REGEX: &str = "^port[0-9]+\\-plug[0-9]+$";
+/// Regex for matching port directories (e.g., "port0", "port1").
 pub const PORT_REGEX: &str = "^port[0-9]+$";
+/// Regex for matching partner alternate mode directories (e.g., "port0-partner.0").
 pub const PARTNER_ALT_MODE_REGEX: &str = "^port[0-9]+-partner\\.[0-9]+$";
+/// Regex for matching partner PDO (Power Delivery Object) directories (e.g., "pd0", "pd1").
 pub const PARTNER_PDO_REGEX: &str = "^pd[0-9]+$";
+/// Regex for matching PDO capabilities directories (e.g., "sink-capabilities", "source-capabilities").
 pub const PDO_CAPABILITIES_REGEX: &str = "^(sink|source)-capabilities$";
+/// Regex for matching PDO type directories (e.g., "0:battery", "1:fixed_supply").
 pub const PDO_TYPE_REGEX: &str =
     "^[0-9]+:(battery|fixed_supply|programmable_supply|variable_supply)$";
+/// Regex for matching USB port directories (e.g., "usb0-port0", "usb1-port2").
 pub const USB_PORT_REGEX: &str = "^usb[0-9]+\\-port[0-9]+$";
+/// Regex for matching USB device directories (e.g., "0-1", "1-2.3").
 pub const USB_DEVICE_REGEX: &str = "^[0-9]+\\-[0-9]+(\\.[0-9]+)*$";
 
+/// The number of spaces to indent for each level of nesting.
 pub const INDENT_STEP: usize = 2;
 
 const ERR_READ_DIR: &str = "Failed to iterate over files in directory";
@@ -61,18 +74,30 @@ impl<T> WarnErr for Result<T> {
     }
 }
 
+/// A struct for writing formatted output with indentation.
+///
+/// This struct wraps a `Write` object and provides methods for printing strings and files
+/// with proper indentation. It maintains an `indent` level to control the spacing before
+/// each line of output.
 pub struct OutputWriter<W: Write> {
     buffer: W,
-    indent: usize,
+    /// indent
+    pub indent: usize,
 }
 
 impl<W: Write> OutputWriter<W> {
+    /// Creates a new `OutputWriter`.
+    ///
+    /// # Arguments
+    ///
+    /// * `buffer`: The `Write` object to which the output will be written.
+    /// * `indent`: The initial indentation level.
     pub fn new(buffer: W, indent: usize) -> Self {
         Self { buffer, indent }
     }
 
     /// Prints a string with indentation.
-    fn print_str_indent(&mut self, str_to_print: &str) -> Result<()> {
+    pub fn print_str_indent(&mut self, str_to_print: &str) -> Result<()> {
         writeln!(self.buffer, "{:indent$}{str_to_print}", "", indent = self.indent)
             .with_context(|| format!("{ERR_WRITE_TO_BUFFER} {:?}", str_to_print))?;
         Ok(())
@@ -360,7 +385,7 @@ pub fn read_vdo(vdo_path: &Path) -> Result<u32> {
     Ok(vdo)
 }
 
-// Prints the immediate files in an alternate mode directory, then prints the files in each mode subdirectory.
+/// Prints the immediate files in an alternate mode directory, then prints the files in each mode subdirectory.
 pub fn print_alt_mode<W: Write>(alt_mode_dir_path: &Path, out_writer: &mut OutputWriter<W>) {
     if !(alt_mode_dir_path.is_dir() | alt_mode_dir_path.is_symlink()) {
         warn!("{ERR_PATH_NOT_DIR_OR_SYMLINK}: {:?}", alt_mode_dir_path);
@@ -381,7 +406,7 @@ pub fn print_alt_mode<W: Write>(alt_mode_dir_path: &Path, out_writer: &mut Outpu
     out_writer.indent -= INDENT_STEP;
 }
 
-// Prints detailed information about the PDOs given at capabilities_dir_path, including available voltages and currents.
+/// Prints detailed information about the PDOs given at capabilities_dir_path, including available voltages and currents.
 pub fn print_pdo_capabilities<W: Write>(capabilities: &Path, out_writer: &mut OutputWriter<W>) {
     out_writer.print_dir_files(capabilities).warn_err();
     out_writer.indent += INDENT_STEP;
@@ -397,8 +422,8 @@ pub fn print_pdo_capabilities<W: Write>(capabilities: &Path, out_writer: &mut Ou
     out_writer.indent -= INDENT_STEP;
 }
 
-// Prints the immediate files in a PDO data directory, then call
-// print_pdo_capabilities to print more detailed PDO information.
+/// Prints the immediate files in a PDO data directory, then call
+/// print_pdo_capabilities to print more detailed PDO information.
 pub fn print_pdos<W: Write>(pdo_dir_path: &Path, out_writer: &mut OutputWriter<W>) {
     if !(pdo_dir_path.is_dir() | pdo_dir_path.is_symlink()) {
         warn!("{ERR_PATH_NOT_DIR_OR_SYMLINK}: {:?}", pdo_dir_path);
@@ -589,8 +614,8 @@ pub fn print_physical_location<W: Write>(
     Ok(())
 }
 
-// Prints the `busnum`, `devnum`, `devpath` in the usb device directory, which are minimal
-// info needed to map to corresponding peripheral.
+/// Prints the `busnum`, `devnum`, `devpath` in the usb device directory, which are minimal
+/// info needed to map to corresponding peripheral.
 pub fn print_usb_device_info<W: Write>(usb_device: &Path, out_writer: &mut OutputWriter<W>) {
     out_writer.print_str_indent("usb_device").warn_err();
 
@@ -603,7 +628,7 @@ pub fn print_usb_device_info<W: Write>(usb_device: &Path, out_writer: &mut Outpu
     out_writer.indent -= INDENT_STEP;
 }
 
-// Finds and prints information about the usb device in the usb port directory.
+/// Finds and prints information about the usb device in the usb port directory.
 pub fn print_usb_device<W: Write>(usb_port: &Path, out_writer: &mut OutputWriter<W>) {
     let usb_device_dir = usb_port.join("device");
     if !(usb_device_dir.is_dir() | usb_device_dir.is_symlink()) {
diff --git a/typec_connector_class_helper/src/typec_class_utils_tests.rs b/typec_connector_class_helper/src/typec_class_utils_tests.rs
index 2ddbbfd..81a07bf 100644
--- a/typec_connector_class_helper/src/typec_class_utils_tests.rs
+++ b/typec_connector_class_helper/src/typec_class_utils_tests.rs
@@ -12,7 +12,7 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-//! typec_class_utils_tests
+//! Tests for the `typec_class_utils` module.
 
 use std::path::PathBuf;
 use std::{fs, io::Write};
diff --git a/typec_connector_class_helper/src/usb_pd_utils.rs b/typec_connector_class_helper/src/usb_pd_utils.rs
index 35f51fb..04525cc 100644
--- a/typec_connector_class_helper/src/usb_pd_utils.rs
+++ b/typec_connector_class_helper/src/usb_pd_utils.rs
@@ -12,13 +12,19 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-//! usb_pd_utils
+//! Provides utilities for decoding USB Power Delivery (PD) data,
+//! including Vendor Data Objects (VDOs) and their fields.
 
 /// Contains information for decoding a specific piece of data from a
-/// Vendor Data Object (VDO).
+/// Vendor Data Object (VDO). A VDO is a 32-bit value that contains
+/// information about a device or cable, and is used in USB PD
+/// communication.
 pub struct VdoField {
+    /// index
     pub index: i32,
+    /// mask
     pub mask: u32,
+    /// description
     pub description: &'static str,
 }
 
@@ -31,51 +37,118 @@ impl VdoField {
 }
 
 // Masks for id_header fields.
+/// UFP_PRODUCT_TYPE_MASK
+///
+/// ref: USB Power Delivery R2.0 V1.3, Section 6.4.4.3.1.1 ID Header VDO, Table 6-23 ID Header VDO
 pub const UFP_PRODUCT_TYPE_MASK: u32 = 0x38000000;
+/// DFP_PRODUCT_TYPE_MASK
+///
+/// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.1 ID Header VDO, Table 6-29 ID Header VDO
 pub const DFP_PRODUCT_TYPE_MASK: u32 = 0x03800000;
 
+/// Represents the USB Power Delivery (PD) revision.
 #[derive(Debug, PartialEq)]
 pub enum PdRev {
+    /// Represents an unknown or unspecified PD revision.
     None,
+    /// Represents the PD 2.0 revision.
     Pd20,
+    /// Represents the PD 3.0 revision.
     Pd30,
+    /// Represents the PD 3.1 revision.
     Pd31,
 }
 
+/// Represents the type of cable.
+///
+/// ref: USB Power Delivery R2.0 V1.3, Section 6.4.4.3.1.1.4 Product Type (Cable Plug), Table 6-25 Product Types (Cable Plug)
 #[derive(Debug, PartialEq)]
 pub enum CableType {
+    /// Represents a passive cable.
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 1.6 Terms and Abbreviations, Table 1-1 Terms and Abbreviations, Row: Passive Cable
     Passive,
+    /// Represents an active cable.
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 1.6 Terms and Abbreviations, Table 1-1 Terms and Abbreviations, Row: Active Cable
     Active,
+    /// Represents a VCONN Powered USB Device (VPD).
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 1.6 Terms and Abbreviations, Table 1-1 Terms and Abbreviations, VCONN Powered USB Device (VPD)
     Vpd,
 }
 
+/// Represents the type of port.
+///
+/// ref: USB Power Delivery R2.0 V1.3
 #[derive(Debug, PartialEq)]
 pub enum PortType {
+    /// Represents a USB-PD Upstream Facing Port.
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 1.6 Terms and Abbreviations, Table 1-1 Terms and Abbreviations, Row: Upstream Facing Port (UFP)
     Ufp,
+    /// Represents a USB-PD Downstream Facing Port.
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 1.6 Terms and Abbreviations, Table 1-1 Terms and Abbreviations, Row: Downstream Facing Port (DFP)
     Dfp,
+    /// Represents a USB-PD Dual-Role Data Port.
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 1.6 Terms and Abbreviations, Table 1-1 Terms and Abbreviations, Row: Dual-Role Data (DRD)
     Drd,
 }
 
+/// Represents the type of product.
+///
+/// ref: USB Power Delivery R2.0 V1.3
 #[derive(Debug, PartialEq)]
 pub enum ProductType {
+    /// Represents a cable, including its cable type and PD revision.
     Cable((CableType, PdRev)),
+    /// Represents an Alternate Mode Adapter (AMA), including its PD revision.
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 1.6 Terms and Abbreviations, Table 1-1 Terms and Abbreviations, Row: Alternate Mode Adapter (AMA)
     Ama(PdRev),
+    /// Represents a VCONN Powered USB Device (VPD), including its PD revision.
+    ///
+    /// ref: TODO 3.0
     Vpd(PdRev),
+    /// Represents a port, including its port type and PD revision.
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 1.6 Terms and Abbreviations, Table 1-1 Terms and Abbreviations, Row: Port
     Port((PortType, PdRev)),
+    /// Represents a product of an unspecified or unknown type.
     Other,
 }
 
 /// Constants specific to USB PD revision 2.0.
+///
+/// ref: USB Power Delivery R2.0 V1.3
 pub mod pd20_data {
     use super::VdoField;
 
-    // Expected product identifiers extracted from id_header VDO.
+    // Expected product type identifiers extracted from id_header VDO - both UFP and Cable Plug types.
+    /// Indicates a product is an Alternate Mode Adapter
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 6.4.4.3.1.1 ID Header VDO, Table 6-23 ID Header VDO, Row: B29..27
     pub const AMA_COMP: u32 = 0x28000000;
-    // Expected id_header field results.
-    pub const PASSIVE_CABLE_COMP: u32 = 0x20000000;
-    pub const ACTIVE_CABLE_COMP: u32 = 0x18000000;
 
-    // Vendor Data Objects (VDO) decoding information (source: USB PD spec).
+    /// Indicates a product is a passive cable
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 6.4.4.3.1.1 ID Header VDO, Table 6-23 ID Header VDO, Row: B29..27
+    pub const PASSIVE_CABLE_COMP: u32 = 0x18000000;
+
+    /// Indicates a product is an active cable
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 6.4.4.3.1.1 ID Header VDO, Table 6-23 ID Header VDO, Row: B29..27
+    pub const ACTIVE_CABLE_COMP: u32 = 0x20000000;
+
+    // TODO: add the PDUSB HUB and PDUSB Peripheral product types
+    // ref: USB Power Delivery R2.0 V1.3, Section 6.4.4.3.1.1 ID Header VDO, Table 6-23 ID Header VDO, Row: B29..27
+
+    // Vendor Data Objects (VDO) decoding information
+    /// Contains information about the product, including its vendor ID, product type, and USB capabilities.
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 6.4.4.3.1.1 ID Header VDO, Table 6-23 ID Header VDO
     pub const ID_HEADER_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x0000ffff, description: "USB Vendor ID" },
         VdoField { index: 16, mask: 0x03ff0000, description: "Reserved" },
@@ -85,28 +158,23 @@ pub mod pd20_data {
         VdoField { index: 31, mask: 0x80000000, description: "USB Capable as a USB Host" },
     ];
 
+    /// Contains information about the certification status of a product.
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 6.4.4.3.1.2 Cert Stat VDO, Table 6-26 Cert Stat VDO
     pub const CERT_STAT_VDO: &[VdoField] =
-        &[VdoField { index: 0, mask: 0xffffffff, description: "XID" }];
+        &[VdoField { index: 0, mask: 0xffffffff, description: "XID" }]; // XID assigned by USB-IF
 
+    /// Contains information about the product, including its bcdDevice and USB Product ID.
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 6.4.4.3.1.3 Product VDO, Table 6-27 Product VDO
     pub const PRODUCT_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x0000ffff, description: "bcdDevice" },
         VdoField { index: 16, mask: 0xffff0000, description: "USB Product ID" },
     ];
 
-    pub const AMA_VDO: &[VdoField] = &[
-        VdoField { index: 0, mask: 0x00000007, description: "USB SS Signaling Support" },
-        VdoField { index: 3, mask: 0x00000008, description: "Vbus Required" },
-        VdoField { index: 4, mask: 0x00000010, description: "Vconn Required" },
-        VdoField { index: 5, mask: 0x000000e0, description: "Vconn Power" },
-        VdoField { index: 8, mask: 0x00000100, description: "SSRX2 Directionality Support" },
-        VdoField { index: 9, mask: 0x00000200, description: "SSRX1 Directionality Support" },
-        VdoField { index: 10, mask: 0x00000400, description: "SSTX2 Directionality Support" },
-        VdoField { index: 11, mask: 0x00000800, description: "SSTX1 Directionality Support" },
-        VdoField { index: 12, mask: 0x00fff000, description: "Reserved" },
-        VdoField { index: 24, mask: 0x0f000000, description: "Firmware Version" },
-        VdoField { index: 28, mask: 0xf0000000, description: "Hardware Version" },
-    ];
-
+    /// Contains information about a passive cable.
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 6.4.4.3.1.4.1 Passive Cable VDO, Table 6-28 Passive Cable VDO
     pub const PASSIVE_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x00000007, description: "USB Speed" },
         VdoField { index: 3, mask: 0x00000008, description: "Reserved" },
@@ -125,6 +193,9 @@ pub mod pd20_data {
         VdoField { index: 28, mask: 0xf0000000, description: "HW Version" },
     ];
 
+    /// Contains information about an active cable.
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 6.4.4.3.1.4.2 Active Cable VDO, Table 6-29 Active Cable VDO
     pub const ACTIVE_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x00000007, description: "USB Speed" },
         VdoField { index: 3, mask: 0x00000008, description: "SOP'' Controller Present" },
@@ -142,23 +213,75 @@ pub mod pd20_data {
         VdoField { index: 24, mask: 0x0f000000, description: "Firmware Version" },
         VdoField { index: 28, mask: 0xf0000000, description: "HW Version" },
     ];
+
+    /// Contains information about an Alternate Mode Adapter (AMA).
+    ///
+    /// ref: USB Power Delivery R2.0 V1.3, Section 6.4.4.3.1.5 Alternate Mode Adapter VDO, Table 6-30 AMA VDO
+    pub const AMA_VDO: &[VdoField] = &[
+        VdoField { index: 0, mask: 0x00000007, description: "USB SS Signaling Support" },
+        VdoField { index: 3, mask: 0x00000008, description: "Vbus Required" },
+        VdoField { index: 4, mask: 0x00000010, description: "Vconn Required" },
+        VdoField { index: 5, mask: 0x000000e0, description: "Vconn Power" },
+        VdoField { index: 8, mask: 0x00000100, description: "SSRX2 Directionality Support" },
+        VdoField { index: 9, mask: 0x00000200, description: "SSRX1 Directionality Support" },
+        VdoField { index: 10, mask: 0x00000400, description: "SSTX2 Directionality Support" },
+        VdoField { index: 11, mask: 0x00000800, description: "SSTX1 Directionality Support" },
+        VdoField { index: 12, mask: 0x00fff000, description: "Reserved" },
+        VdoField { index: 24, mask: 0x0f000000, description: "Firmware Version" },
+        VdoField { index: 28, mask: 0xf0000000, description: "Hardware Version" },
+    ];
+
+    // TODO: Decode USB SuperSpeed Signaling Support ref: USB Power Delivery R2.0 V1.3, Section 6.4.4.3.1.5 Alternate Mode Adapter VDO, Table 6-30 AMA VDO, Row B2..0
 }
 
 /// Constants specific to USB PD revision 3.0.
+///
+/// ref: USB Power Delivery R3.0 V2.0
 pub mod pd30_data {
     use super::VdoField;
 
+    /// Indicates a product is an Alternate Mode Adapter
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.1 ID Header VDO, Table 6-29 ID Header VDO, Row: B29..27
     pub const AMA_COMP: u32 = 0x28000000;
+    /// Indicates a product is a VCONN Powered USB Device
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.1 ID Header VDO, Table 6-29 ID Header VDO, Row: B29..27
     pub const VPD_COMP: u32 = 0x30000000;
+    ///  Indicates a product is a PDUSB Hub's Upstream Facing Port
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.1 ID Header VDO, Table 6-29 ID Header VDO, Row: B29..27
     pub const HUB_COMP: u32 = 0x08000000;
+    /// Indicates a product is a PDUSB Peripheral
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.1 ID Header VDO, Table 6-29 ID Header VDO, Row: B29..27
     pub const PERIPHERAL_COMP: u32 = 0x10000000;
+    /// Indicates a product is a PDUSB Hub's Downstream Facing Port
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.1 ID Header VDO, Table 6-29 ID Header VDO, Row: B25..23
     pub const DFP_HUB_COMP: u32 = 0x00800000;
+    /// Indicates a product is a PDUSB Host's Downstream Facing Port
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.1 ID Header VDO, Table 6-29 ID Header VDO, Row: B25..23
     pub const DFP_HOST_COMP: u32 = 0x01000000;
+    /// Indicates a product is a Power Brick
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.1 ID Header VDO, Table 6-29 ID Header VDO, Row: B25..23
     pub const POWER_BRICK_COMP: u32 = 0x01800000;
+
     // Expected id_header field results.
+    /// Indicates a product is a passive cable
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.1 ID Header VDO, Table 6-29 ID Header VDO, Row: B29..27
     pub const PASSIVE_CABLE_COMP: u32 = 0x18000000;
+    /// Indicates a product is an active cable
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.1 ID Header VDO, Table 6-29 ID Header VDO, Row: B29..27
     pub const ACTIVE_CABLE_COMP: u32 = 0x20000000;
 
+    /// Contains information about the product, including its vendor ID, product type, and USB capabilities.
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.1 ID Header VDO, Table 6-29 ID Header VDO
     pub const ID_HEADER_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x0000ffff, description: "USB Vendor ID" },
         VdoField { index: 16, mask: 0x007f0000, description: "Reserved" },
@@ -169,14 +292,23 @@ pub mod pd30_data {
         VdoField { index: 31, mask: 0x80000000, description: "USB Capable as a USB Host" },
     ];
 
+    /// Contains information about the certification status of a product.
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.2 Cert Stat VDO, Table 6-33 Cert Stat VDO
     pub const CERT_STAT_VDO: &[VdoField] =
         &[VdoField { index: 0, mask: 0xffffffff, description: "XID" }];
 
+    /// Contains information about the product, including its bcdDevice and USB Product ID.
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.3 Product VDO , Table 6-34 Product VDO
     pub const PRODUCT_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x0000ffff, description: "bcdDevice" },
         VdoField { index: 16, mask: 0xffff0000, description: "USB Product ID" },
     ];
 
+    /// Contains information about an Alternate Mode Adapter (AMA).
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.8 Alternate Mode Adapter VDO , Table 6-41 AMA VDO
     pub const AMA_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x00000007, description: "USB Highest Speed" },
         VdoField { index: 3, mask: 0x00000008, description: "Vbus Required" },
@@ -188,6 +320,9 @@ pub mod pd30_data {
         VdoField { index: 28, mask: 0xf0000000, description: "Hardware Version" },
     ];
 
+    /// Contains information about a VCONN Powered USB Device (VPD).
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.9 Vconn Powered USB Device VDO, Table 6-42 VPD VDO
     pub const VPD_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x00000001, description: "Charge Through Support" },
         VdoField { index: 1, mask: 0x0000007e, description: "Ground Impedance" },
@@ -198,6 +333,9 @@ pub mod pd30_data {
         VdoField { index: 17, mask: 0x001e0000, description: "Reserved" },
     ];
 
+    /// Contains information about a passive cable.
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.6 Passive Cable VDO, Table 6-38 Passive Cable VDO
     pub const PASSIVE_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x00000007, description: "USB Speed" },
         VdoField { index: 3, mask: 0x00000018, description: "Reserved" },
@@ -214,6 +352,9 @@ pub mod pd30_data {
         VdoField { index: 28, mask: 0xf0000000, description: "HW Version" },
     ];
 
+    /// Contains information about a USB-PD Upstream Facing Port (UFP).
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.4 UFP VDOs, Table 6-35 UFP VDO 1
     pub const UFP_VDO1: &[VdoField] = &[
         VdoField { index: 0, mask: 0x00000007, description: "USB Highest Speed" },
         VdoField { index: 3, mask: 0x00000038, description: "Alternate Modes" },
@@ -223,6 +364,9 @@ pub mod pd30_data {
         VdoField { index: 29, mask: 0xe0000000, description: "UFP VDO Version" },
     ];
 
+    /// Contains information about a USB-PD Upstream Facing Port (UFP).
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.4 UFP VDOs, Table 6-36 UFP VDO 2
     pub const UFP_VDO2: &[VdoField] = &[
         VdoField { index: 0, mask: 0x0000007f, description: "USB3 Max Power" },
         VdoField { index: 7, mask: 0x00003f80, description: "USB3 Min Power" },
@@ -232,6 +376,9 @@ pub mod pd30_data {
         VdoField { index: 30, mask: 0xc0000000, description: "Reserved" },
     ];
 
+    /// Contains information about a USB-PD Downstream Facing Port (DFP).
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.5 DFP VDO, Table 6-37 DFP VDO
     pub const DFP_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x0000001f, description: "Port Number" },
         VdoField { index: 5, mask: 0x00ffffe0, description: "Reserved" },
@@ -243,6 +390,9 @@ pub mod pd30_data {
         VdoField { index: 28, mask: 0xf0000000, description: "HW Version" },
     ];
 
+    /// Contains information about an active cable.
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.7 Active Cable VDOs, Table 6-39 Active Cable VDO 1
     pub const ACTIVE_VDO1: &[VdoField] = &[
         VdoField { index: 0, mask: 0x00000007, description: "USB Speed" },
         VdoField { index: 3, mask: 0x00000008, description: "SOP'' Controller Present" },
@@ -258,6 +408,9 @@ pub mod pd30_data {
         VdoField { index: 20, mask: 0x00100000, description: "Reserved" },
     ];
 
+    /// Contains information about an active cable.
+    ///
+    /// ref: USB Power Delivery R3.0 V2.0, Section 6.4.4.3.1.7 Active Cable VDOs , Table 6-40 Active Cable VDO 2
     pub const ACTIVE_VDO2: &[VdoField] = &[
         VdoField { index: 0, mask: 0x00000001, description: "USB Gen" },
         VdoField { index: 1, mask: 0x00000002, description: "Reserved" },
@@ -278,19 +431,49 @@ pub mod pd30_data {
 }
 
 /// Constants specific to USB PD revision 3.1.
+///
+/// ref: USB Power Delivery R3.1 V1.8
 pub mod pd31_data {
     use super::VdoField;
 
+    /// Indicates a product is a PDUSB Hub's Upstream Facing Port
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.1.3 Product Type (UFP), Table 6-34 Product Types (UFP), Row: PDUSB Hub
     pub const HUB_COMP: u32 = 0x08000000;
+    /// Indicates a product is a PDUSB Peripheral
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.1.3 Product Type (UFP), Table 6-34 Product Types (UFP), Row: PDUSB Peripheral
     pub const PERIPHERAL_COMP: u32 = 0x10000000;
+    /// Indicates a product is a PDUSB Hub's Downstream Facing Port
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.1.6 Product Type (DFP), Table 6-36 Product Types (DFP), Row: PDUSB Hub
     pub const DFP_HUB_COMP: u32 = 0x00800000;
+    /// Indicates a product is a PDUSB Host's Downstream Facing Port
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.1.6 Product Type (DFP), Table 6-36 Product Types (DFP), Row: PDUSB Host
     pub const DFP_HOST_COMP: u32 = 0x01000000;
+    /// Indicates a product is a Power Brick
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.1.6 Product Type (DFP), Table 6-36 Product Types (DFP), Row: Power Brick
     pub const POWER_BRICK_COMP: u32 = 0x01800000;
+
     // Expected id_header field results.
+    /// Indicates a product is a passive cable
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.1.4 Product Type (Cable Plug), Table 6-35 Product Types (Cable Plug/VPD), Row: Passive Cable
     pub const PASSIVE_CABLE_COMP: u32 = 0x18000000;
+    /// Indicates a product is an active cable
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.1.4 Product Type (Cable Plug), Table 6-35 Product Types (Cable Plug/VPD), Row: Active Cable
     pub const ACTIVE_CABLE_COMP: u32 = 0x20000000;
+    /// Indicates a product is a VCONN Powered USB Device
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.1.4 Product Type (Cable Plug), Table 6-35 Product Types (Cable Plug/VPD), Row: VCONN Powered USB Device
     pub const VPD_COMP: u32 = 0x30000000;
 
+    /// Contains information about the product, including its vendor ID, product type, and USB capabilities.
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.1 ID Header VDO, Table 6-33 ID Header VDO
     pub const ID_HEADER_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x0000ffff, description: "USB Vendor ID" },
         VdoField { index: 16, mask: 0x001f0000, description: "Reserved" },
@@ -302,14 +485,23 @@ pub mod pd31_data {
         VdoField { index: 31, mask: 0x80000000, description: "USB Capable as a USB Host" },
     ];
 
+    /// Contains information about the certification status of a product.
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.2 Cert Stat VDO, Table 6-37 Cert Stat VDO
     pub const CERT_STAT_VDO: &[VdoField] =
         &[VdoField { index: 0, mask: 0xffffffff, description: "XID" }];
 
+    /// Contains information about the product, including its bcdDevice and USB Product ID.
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.3 Product VDO, Table 6-38 Product VDO
     pub const PRODUCT_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x0000ffff, description: "bcdDevice" },
         VdoField { index: 16, mask: 0xffff0000, description: "USB Product ID" },
     ];
 
+    /// Contains information about a USB-PD Upstream Facing Port (UFP).
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.4 UFP VDO, Table 6-39 UFP VDO
     pub const UFP_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x00000007, description: "USB Highest Speed" },
         VdoField { index: 3, mask: 0x00000038, description: "Alternate Modes" },
@@ -323,6 +515,9 @@ pub mod pd31_data {
         VdoField { index: 29, mask: 0xe0000000, description: "UFP VDO Version" },
     ];
 
+    /// Contains information about a USB-PD Downstream Facing Port (DFP).
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.5 DFP VDO, Table 6-40 DFP VDO
     pub const DFP_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x0000001f, description: "Port Number" },
         VdoField { index: 5, mask: 0x003fffe0, description: "Reserved" },
@@ -332,6 +527,9 @@ pub mod pd31_data {
         VdoField { index: 29, mask: 0xe0000000, description: "DFP VDO Version" },
     ];
 
+    /// Contains information about a passive cable.
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.6 Passive Cable VDO, Table 6-41 Passive Cable VDO
     pub const PASSIVE_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x00000007, description: "USB Speed" },
         VdoField { index: 3, mask: 0x00000018, description: "Reserved" },
@@ -348,6 +546,9 @@ pub mod pd31_data {
         VdoField { index: 28, mask: 0xf0000000, description: "HW Version" },
     ];
 
+    /// Contains information about an active cable.
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.7 Active Cable VDOs, Table 6-42 Active Cable VDO 1
     pub const ACTIVE_VDO1: &[VdoField] = &[
         VdoField { index: 0, mask: 0x00000007, description: "USB Speed" },
         VdoField { index: 3, mask: 0x00000008, description: "SOP'' Controller Present" },
@@ -366,6 +567,9 @@ pub mod pd31_data {
         VdoField { index: 28, mask: 0xf0000000, description: "HW Version" },
     ];
 
+    /// Contains information about an active cable.
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.7 Active Cable VDOs, Table 6-43 Active Cable VDO 2
     pub const ACTIVE_VDO2: &[VdoField] = &[
         VdoField { index: 0, mask: 0x00000001, description: "USB Gen" },
         VdoField { index: 1, mask: 0x00000002, description: "Reserved" },
@@ -384,6 +588,9 @@ pub mod pd31_data {
         VdoField { index: 24, mask: 0xff000000, description: "Max Operating Tempurature" },
     ];
 
+    /// Contains information about a VCONN Powered USB Device (VPD).
+    ///
+    /// ref: USB Power Delivery R3.1 V1.8, Section 6.4.4.3.1.9 VCONN Powered USB Device VDO, Table 6-44 VPD VDO
     pub const VPD_VDO: &[VdoField] = &[
         VdoField { index: 0, mask: 0x00000001, description: "Charge Through Support" },
         VdoField { index: 1, mask: 0x0000007e, description: "Ground Impedance" },
```

