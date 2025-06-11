```diff
diff --git a/typec_connector_class_helper/src/typec_class_utils.rs b/typec_connector_class_helper/src/typec_class_utils.rs
index a4017dc..8fc93d0 100644
--- a/typec_connector_class_helper/src/typec_class_utils.rs
+++ b/typec_connector_class_helper/src/typec_class_utils.rs
@@ -48,6 +48,19 @@ const ERR_DIR_ENTRY_ACCESS: &str = "Cannot access entry in directory";
 const ERR_WRITE_TO_BUFFER: &str = "Cannot write to output buffer. Attempted to print";
 const ERR_PATH_NOT_DIR_OR_SYMLINK: &str = "The path is not a directory or a symbolic link";
 
+trait WarnErr {
+    fn warn_err(self);
+}
+
+impl<T> WarnErr for Result<T> {
+    /// In case the result is an error, logs the error message as a warning.
+    fn warn_err(self) {
+        if let Err(err) = self {
+            warn!("{err:#}");
+        }
+    }
+}
+
 pub struct OutputWriter<W: Write> {
     buffer: W,
     indent: usize,
@@ -91,7 +104,7 @@ impl<W: Write> OutputWriter<W> {
 
         for path in get_sorted_paths_from_dir(dir_path, |path| path.is_file())? {
             self.indent += INDENT_STEP;
-            let _ = self.print_file_formatted(&path).inspect_err(|err| warn!("{:?}: {err}", path));
+            self.print_file_formatted(&path).warn_err();
             self.indent -= INDENT_STEP;
         }
 
@@ -138,8 +151,7 @@ pub fn print_decoded_vdos_from_files<W: Write>(
 ) {
     for (filename, vdo_fields) in filename_vdo_fields_arr {
         identity_path_buf.push(filename);
-        let _ = print_vdo(identity_path_buf, vdo_fields, out_writer)
-            .inspect_err(|err| warn!("{:#}", err));
+        print_vdo(identity_path_buf, vdo_fields, out_writer).warn_err();
         identity_path_buf.pop();
     }
 }
@@ -154,7 +166,7 @@ pub fn print_decoded_vdos_from_files<W: Write>(
 /// # Returns
 /// * `Result<()>` - A Result indicating success or failure of the printing operation.
 pub fn print_identity<W: Write>(dev_path: &Path, out_writer: &mut OutputWriter<W>) -> Result<()> {
-    out_writer.print_str_indent("identity").inspect_err(|err| warn!("{:#}", err)).ok();
+    out_writer.print_str_indent("identity").warn_err();
 
     out_writer.indent += INDENT_STEP;
 
@@ -196,7 +208,7 @@ pub fn print_partner_identity<W: Write>(
         bail!("{ERR_PATH_NOT_DIR_OR_SYMLINK}: {:?}", identity_path_buf);
     }
 
-    let _ = print_identity(partner_path, out_writer).inspect_err(|err| warn!("{:#}", err));
+    print_identity(partner_path, out_writer).warn_err();
 
     out_writer.indent += INDENT_STEP;
 
@@ -327,12 +339,10 @@ pub fn print_vdo<W: Write>(
 ) -> Result<()> {
     let vdo = read_vdo(vdo_path)?;
     let vdo_str = format!("{}: 0x{:x}", get_path_basename(vdo_path)?, vdo);
-    let _ = out_writer.print_str_indent(&vdo_str).inspect_err(|err| warn!("{:#}", err));
+    out_writer.print_str_indent(&vdo_str).warn_err();
     out_writer.indent += INDENT_STEP;
     for vdo_field in vdo_description {
-        let _ = out_writer
-            .print_str_indent(&vdo_field.decode_vdo(vdo))
-            .inspect_err(|err| warn!("{:#}", err)); // log error but continue iterating.
+        out_writer.print_str_indent(&vdo_field.decode_vdo(vdo)).warn_err(); // log error but continue iterating.
     }
     out_writer.indent -= INDENT_STEP;
     Ok(())
@@ -357,33 +367,33 @@ pub fn print_alt_mode<W: Write>(alt_mode_dir_path: &Path, out_writer: &mut Outpu
         return;
     }
 
-    let _ = out_writer.print_dir_files(alt_mode_dir_path).inspect_err(|err| warn!("{:#}", err));
+    out_writer.print_dir_files(alt_mode_dir_path).warn_err();
     out_writer.indent += INDENT_STEP;
-    let _ = parse_dirs_and_execute(
+    parse_dirs_and_execute(
         alt_mode_dir_path,
         out_writer,
         MODE_REGEX,
         |path: &Path, out_writer: &mut OutputWriter<W>| {
-            let _ = out_writer.print_dir_files(path).inspect_err(|err| warn!("{:#}", err));
+            out_writer.print_dir_files(path).warn_err();
         },
     )
-    .inspect_err(|err| warn!("{:#}", err));
+    .warn_err();
     out_writer.indent -= INDENT_STEP;
 }
 
 // Prints detailed information about the PDOs given at capabilities_dir_path, including available voltages and currents.
 pub fn print_pdo_capabilities<W: Write>(capabilities: &Path, out_writer: &mut OutputWriter<W>) {
-    let _ = out_writer.print_dir_files(capabilities).inspect_err(|err| warn!("{:#}", err));
+    out_writer.print_dir_files(capabilities).warn_err();
     out_writer.indent += INDENT_STEP;
-    let _ = parse_dirs_and_execute(
+    parse_dirs_and_execute(
         capabilities,
         out_writer,
         PDO_TYPE_REGEX,
         |path: &Path, out_writer: &mut OutputWriter<W>| {
-            let _ = out_writer.print_dir_files(path).inspect_err(|err| warn!("{:#}", err));
+            out_writer.print_dir_files(path).warn_err();
         },
     )
-    .inspect_err(|err| warn!("{:#}", err));
+    .warn_err();
     out_writer.indent -= INDENT_STEP;
 }
 
@@ -395,15 +405,15 @@ pub fn print_pdos<W: Write>(pdo_dir_path: &Path, out_writer: &mut OutputWriter<W
         return;
     }
 
-    let _ = out_writer.print_dir_files(pdo_dir_path).inspect_err(|err| warn!("{:#}", err));
+    out_writer.print_dir_files(pdo_dir_path).warn_err();
     out_writer.indent += INDENT_STEP;
-    let _ = parse_dirs_and_execute(
+    parse_dirs_and_execute(
         pdo_dir_path,
         out_writer,
         PDO_CAPABILITIES_REGEX,
         print_pdo_capabilities,
     )
-    .inspect_err(|err| warn!("{:#}", err));
+    .warn_err();
     out_writer.indent -= INDENT_STEP;
 }
 
@@ -416,23 +426,16 @@ pub fn print_partner<W: Write>(port_path: &Path, out_writer: &mut OutputWriter<W
         bail!("{ERR_PATH_NOT_DIR_OR_SYMLINK}: {:?}", partner_path_buf);
     }
 
-    let _ = out_writer.print_dir_files(&partner_path_buf).inspect_err(|err| warn!("{:#}", err));
+    out_writer.print_dir_files(&partner_path_buf).warn_err();
 
     out_writer.indent += INDENT_STEP;
 
-    let _ =
-        print_partner_identity(&partner_path_buf, out_writer).inspect_err(|err| warn!("{:#}", err));
+    print_partner_identity(&partner_path_buf, out_writer).warn_err();
 
-    let _ = parse_dirs_and_execute(
-        &partner_path_buf,
-        out_writer,
-        PARTNER_ALT_MODE_REGEX,
-        print_alt_mode,
-    )
-    .inspect_err(|err| warn!("{:#}", err));
+    parse_dirs_and_execute(&partner_path_buf, out_writer, PARTNER_ALT_MODE_REGEX, print_alt_mode)
+        .warn_err();
 
-    let _ = parse_dirs_and_execute(&partner_path_buf, out_writer, PARTNER_PDO_REGEX, print_pdos)
-        .inspect_err(|err| warn!("{:#}", err));
+    parse_dirs_and_execute(&partner_path_buf, out_writer, PARTNER_PDO_REGEX, print_pdos).warn_err();
 
     out_writer.indent -= INDENT_STEP;
     Ok(())
@@ -494,7 +497,7 @@ pub fn print_cable_identity<W: Write>(cable: &Path, out_writer: &mut OutputWrite
         return;
     }
 
-    let _ = print_identity(cable, out_writer).inspect_err(|err| warn!("{:#}", err));
+    print_identity(cable, out_writer).warn_err();
 
     out_writer.indent += INDENT_STEP;
 
@@ -535,10 +538,9 @@ pub fn print_plug_info<W: Write>(plug: &Path, out_writer: &mut OutputWriter<W>)
         return;
     }
 
-    let _ = out_writer.print_dir_files(plug);
+    out_writer.print_dir_files(plug).warn_err();
     out_writer.indent += INDENT_STEP;
-    let _ = parse_dirs_and_execute(plug, out_writer, PLUG_ALT_MODE_REGEX, print_alt_mode)
-        .inspect_err(|err| warn!("{:#}", err));
+    parse_dirs_and_execute(plug, out_writer, PLUG_ALT_MODE_REGEX, print_alt_mode).warn_err();
     out_writer.indent -= INDENT_STEP;
 }
 
@@ -558,12 +560,11 @@ pub fn print_cable<W: Write>(port: &Path, out_writer: &mut OutputWriter<W>) -> R
         bail!("{ERR_PATH_NOT_DIR_OR_SYMLINK}: {:?}", cable_dir);
     }
 
-    out_writer.print_dir_files(&cable_dir).inspect_err(|err| warn!("{:#}", err)).ok();
+    out_writer.print_dir_files(&cable_dir).warn_err();
 
     out_writer.indent += INDENT_STEP;
     print_cable_identity(&cable_dir, out_writer);
-    let _ = parse_dirs_and_execute(&cable_dir, out_writer, PLUG_REGEX, print_plug_info)
-        .inspect_err(|err| warn!("{:#}", err));
+    parse_dirs_and_execute(&cable_dir, out_writer, PLUG_REGEX, print_plug_info).warn_err();
     out_writer.indent -= INDENT_STEP;
 
     Ok(())
@@ -591,24 +592,14 @@ pub fn print_physical_location<W: Write>(
 // Prints the `busnum`, `devnum`, `devpath` in the usb device directory, which are minimal
 // info needed to map to corresponding peripheral.
 pub fn print_usb_device_info<W: Write>(usb_device: &Path, out_writer: &mut OutputWriter<W>) {
-    out_writer.print_str_indent("usb_device").inspect_err(|err| warn!("{:#}", err)).ok();
+    out_writer.print_str_indent("usb_device").warn_err();
 
     out_writer.indent += INDENT_STEP;
-    out_writer
-        .print_file_formatted(&usb_device.join("busnum"))
-        .inspect_err(|err| warn!("{:#}", err))
-        .ok();
-    out_writer
-        .print_file_formatted(&usb_device.join("devnum"))
-        .inspect_err(|err| warn!("{:#}", err))
-        .ok();
-    out_writer
-        .print_file_formatted(&usb_device.join("devpath"))
-        .inspect_err(|err| warn!("{:#}", err))
-        .ok();
+    out_writer.print_file_formatted(&usb_device.join("busnum")).warn_err();
+    out_writer.print_file_formatted(&usb_device.join("devnum")).warn_err();
+    out_writer.print_file_formatted(&usb_device.join("devpath")).warn_err();
     parse_dirs_and_execute(usb_device, out_writer, USB_DEVICE_REGEX, print_usb_device_info)
-        .inspect_err(|err| warn!("{:#}", err))
-        .ok();
+        .warn_err();
     out_writer.indent -= INDENT_STEP;
 }
 
@@ -628,7 +619,7 @@ pub fn print_usb_subsystem<W: Write>(
     port_path: &Path,
     out_writer: &mut OutputWriter<W>,
 ) -> Result<()> {
-    let _ = parse_dirs_and_execute(port_path, out_writer, USB_PORT_REGEX, print_usb_device);
+    parse_dirs_and_execute(port_path, out_writer, USB_PORT_REGEX, print_usb_device).warn_err();
     Ok(())
 }
 
@@ -654,13 +645,13 @@ pub fn print_drm_subsystem<W: Write>(
 
 /// Prints relevant type-c connector class information for the port located at the sysfs path "port_path".
 pub fn print_port_info<W: Write>(port_path: &Path, out_writer: &mut OutputWriter<W>) {
-    let _ = out_writer.print_dir_files(port_path).inspect_err(|err| warn!("{:#}", err));
+    out_writer.print_dir_files(port_path).warn_err();
     out_writer.indent += INDENT_STEP;
-    let _ = print_partner(port_path, out_writer).inspect_err(|err| warn!("{:#}", err));
-    print_cable(port_path, out_writer).inspect_err(|err| warn!("{:#}", err)).ok();
-    print_physical_location(port_path, out_writer).inspect_err(|err| warn!("{:#}", err)).ok();
-    print_usb_subsystem(port_path, out_writer).inspect_err(|err| warn!("{:#}", err)).ok();
-    print_drm_subsystem(port_path, out_writer).inspect_err(|err| warn!("{:#}", err)).ok();
+    print_partner(port_path, out_writer).warn_err();
+    print_cable(port_path, out_writer).warn_err();
+    print_physical_location(port_path, out_writer).warn_err();
+    print_usb_subsystem(port_path, out_writer).warn_err();
+    print_drm_subsystem(port_path, out_writer).warn_err();
     out_writer.indent -= INDENT_STEP;
 }
 
```

