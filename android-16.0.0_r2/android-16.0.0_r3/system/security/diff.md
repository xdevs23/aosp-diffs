```diff
diff --git a/hals/.gitignore b/hals/.gitignore
new file mode 100644
index 00000000..f25c464e
--- /dev/null
+++ b/hals/.gitignore
@@ -0,0 +1,2 @@
+target
+**/Cargo.lock
diff --git a/hals/Android.bp b/hals/Android.bp
new file mode 100644
index 00000000..cda66e91
--- /dev/null
+++ b/hals/Android.bp
@@ -0,0 +1,18 @@
+// Copyright 2025, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+    default_team: "trendy_team_android_hardware_backed_security",
+}
diff --git a/hals/Cargo.toml b/hals/Cargo.toml
new file mode 100644
index 00000000..1cffc56f
--- /dev/null
+++ b/hals/Cargo.toml
@@ -0,0 +1,10 @@
+[workspace]
+members = [
+  "derive",
+  "wire",
+]
+resolver = "2"
+
+[patch.crates-io]
+hal-wire-derive = { path = "derive" }
+hal-wire = { path = "wire" }
\ No newline at end of file
diff --git a/hals/derive/Android.bp b/hals/derive/Android.bp
new file mode 100644
index 00000000..e3b73ba5
--- /dev/null
+++ b/hals/derive/Android.bp
@@ -0,0 +1,31 @@
+// Copyright 2022, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+rust_proc_macro {
+    name: "libhal_wire_derive",
+    crate_name: "hal_wire_derive",
+    cargo_env_compat: true,
+    cargo_pkg_version: "0.1.0",
+    srcs: ["src/lib.rs"],
+    edition: "2021",
+    rustlibs: [
+        "libproc_macro2",
+        "libquote",
+        "libsyn",
+    ],
+}
diff --git a/hals/derive/Cargo.toml b/hals/derive/Cargo.toml
new file mode 100644
index 00000000..27a53abe
--- /dev/null
+++ b/hals/derive/Cargo.toml
@@ -0,0 +1,16 @@
+# Note that Cargo is not an officially supported build tool (Android's Soong is the official
+# tool).  This Cargo.toml file is included purely for the convenience of developers.
+
+[package]
+name = "hal-wire-derive"
+version = "0.1.0"
+authors = ["David Drysdale <drysdale@google.com>"]
+edition = "2021"
+
+[lib]
+proc-macro = true
+
+[dependencies]
+proc-macro2 = "1.0.69"
+quote = "1.0.36"
+syn = { version = "2.0.38", features = ["derive", "parsing"] }
diff --git a/hals/derive/src/lib.rs b/hals/derive/src/lib.rs
new file mode 100644
index 00000000..8bd0483a
--- /dev/null
+++ b/hals/derive/src/lib.rs
@@ -0,0 +1,229 @@
+// Copyright 2022, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! Derive macro for `hal_wire::AsCborValue`.
+
+use proc_macro2::TokenStream;
+use quote::{quote, quote_spanned};
+use syn::{
+    parse_macro_input, parse_quote, spanned::Spanned, Data, DeriveInput, Fields, GenericParam,
+    Generics, Index,
+};
+
+/// Derive macro that implements the `hal_wire::AsCborValue` trait.
+#[proc_macro_derive(AsCborValue)]
+pub fn derive_as_cbor_value(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
+    let input = parse_macro_input!(input as DeriveInput);
+    derive_as_cbor_value_internal(&input)
+}
+
+fn derive_as_cbor_value_internal(input: &DeriveInput) -> proc_macro::TokenStream {
+    let name = &input.ident;
+
+    // Add a bound `T: hal_wire::AsCborValue` for every type parameter `T`.
+    let generics = add_trait_bounds(&input.generics);
+    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
+
+    let from_val = from_val_struct(&input.data);
+    let to_val = to_val_struct(&input.data);
+
+    let expanded = quote! {
+        // The generated impl
+        impl #impl_generics hal_wire::AsCborValue for #name #ty_generics #where_clause {
+            fn from_cbor_value(value: ciborium::value::Value) -> Result<Self, hal_wire::CborError> {
+                #from_val
+            }
+            fn to_cbor_value(self) -> Result<ciborium::value::Value, hal_wire::CborError> {
+                #to_val
+            }
+        }
+    };
+
+    expanded.into()
+}
+
+/// Add a bound `T: hal_wire::AsCborValue` for every type parameter `T`.
+fn add_trait_bounds(generics: &Generics) -> Generics {
+    let mut generics = generics.clone();
+    for param in &mut generics.params {
+        if let GenericParam::Type(ref mut type_param) = *param {
+            type_param.bounds.push(parse_quote!(hal_wire::AsCborValue));
+        }
+    }
+    generics
+}
+
+/// Generate an expression to convert an instance of a compound type to `ciborium::value::Value`
+fn to_val_struct(data: &Data) -> TokenStream {
+    match *data {
+        Data::Struct(ref data) => {
+            match data.fields {
+                Fields::Named(ref fields) => {
+                    // Expands to an expression like
+                    //
+                    //     {
+                    //         let mut v = Vec::new();
+                    //         v.try_reserve(3)?;
+                    //         v.push(hal_wire::AsCborValue::to_cbor_value(self.x)?);
+                    //         v.push(hal_wire::AsCborValue::to_cbor_value(self.y)?);
+                    //         v.push(hal_wire::AsCborValue::to_cbor_value(self.z)?);
+                    //         Ok(ciborium::value::Value::Array(v))
+                    //     }
+                    let nfields = fields.named.len();
+                    let recurse = fields.named.iter().map(|f| {
+                        let name = &f.ident;
+                        quote_spanned! {f.span()=>
+                            v.push(hal_wire::AsCborValue::to_cbor_value(self.#name)?)
+                        }
+                    });
+                    quote! {
+                        {
+                            let mut v = Vec::new();
+                            v.try_reserve(#nfields)?;
+                            #(#recurse; )*
+                            Ok(ciborium::value::Value::Array(v))
+                        }
+                    }
+                }
+                Fields::Unnamed(ref fields) if fields.unnamed.len() == 1 => {
+                    // For a newtype, expands to an expression
+                    //
+                    //     self.0.to_cbor_value()
+                    quote! {
+                        self.0.to_cbor_value()
+                    }
+                }
+                Fields::Unnamed(_) => unimplemented!(),
+                Fields::Unit => unimplemented!(),
+            }
+        }
+        Data::Enum(_) => {
+            quote! {
+                let v: ciborium::value::Integer = (self as i32).into();
+                Ok(ciborium::value::Value::Integer(v))
+            }
+        }
+        Data::Union(_) => unimplemented!(),
+    }
+}
+
+/// Generate an expression to convert a `ciborium::value::Value` into an instance of a compound
+/// type.
+fn from_val_struct(data: &Data) -> TokenStream {
+    match data {
+        Data::Struct(ref data) => {
+            match data.fields {
+                Fields::Named(ref fields) => {
+                    // Expands to an expression like
+                    //
+                    //     let mut a = match value {
+                    //         ciborium::value::Value::Array(a) => a,
+                    //         _ => return hal_wire::cbor_type_error(&value, "arr"),
+                    //     };
+                    //     if a.len() != 3 {
+                    //         return Err(hal_wire::CborError::UnexpectedItem("arr", "arr len 3"));
+                    //     }
+                    //     // Fields specified in reverse order to reduce shifting.
+                    //     Ok(Self {
+                    //         z: <ZType>::from_cbor_value(a.remove(2))?,
+                    //         y: <YType>::from_cbor_value(a.remove(1))?,
+                    //         x: <XType>::from_cbor_value(a.remove(0))?,
+                    //     })
+                    //
+                    // but using fully qualified function call syntax.
+                    let nfields = fields.named.len();
+                    let recurse = fields.named.iter().enumerate().rev().map(|(i, f)| {
+                        let name = &f.ident;
+                        let index = Index::from(i);
+                        let typ = &f.ty;
+                        quote_spanned! {f.span()=>
+                                        #name: <#typ>::from_cbor_value(a.remove(#index))?
+                        }
+                    });
+                    quote! {
+                        let mut a = match value {
+                            ciborium::value::Value::Array(a) => a,
+                            _ => return hal_wire::cbor_type_error(&value, "arr"),
+                        };
+                        if a.len() != #nfields {
+                            return Err(hal_wire::CborError::UnexpectedItem(
+                                "arr",
+                                concat!("arr len ", stringify!(#nfields)),
+                            ));
+                        }
+                        // Fields specified in reverse order to reduce shifting.
+                        Ok(Self {
+                            #(#recurse, )*
+                        })
+                    }
+                }
+                Fields::Unnamed(ref fields) if fields.unnamed.len() == 1 => {
+                    // For a newtype, expands to an expression like
+                    //
+                    //     Ok(Self(<InnerType>::from_cbor_value(value)?))
+                    let inner = fields.unnamed.first().unwrap();
+                    let typ = &inner.ty;
+                    quote! {
+                        Ok(Self(<#typ>::from_cbor_value(value)?))
+                    }
+                }
+                Fields::Unnamed(_) => unimplemented!(),
+                Fields::Unit => unimplemented!(),
+            }
+        }
+        Data::Enum(enum_data) => {
+            // This only copes with variants with no fields.
+            // Expands to an expression like:
+            //
+            //     use core::convert::TryInto;
+            //     let v: i32 = match value {
+            //         ciborium::value::Value::Integer(i) => i.try_into().map_err(|_| {
+            //             hal_wire::CborError::InvalidValue
+            //         })?,
+            //         v => return hal_wire::cbor_type_error(&v, &"int"),
+            //     };
+            //     match v {
+            //         x if x == Self::Variant1 as i32 => Ok(Self::Variant1),
+            //         x if x == Self::Variant2 as i32 => Ok(Self::Variant2),
+            //         x if x == Self::Variant3 as i32 => Ok(Self::Variant3),
+            //         _ => Err( hal_wire::CborError::NonEnumValue(v)),
+            //     }
+            let recurse = enum_data.variants.iter().map(|variant| {
+                let vname = &variant.ident;
+                quote_spanned! {variant.span()=>
+                                x if x == Self::#vname as i32 => Ok(Self::#vname),
+                }
+            });
+
+            quote! {
+                use core::convert::TryInto;
+                // First get the int value as an `i32`.
+                let v: i32 = match value {
+                    ciborium::value::Value::Integer(i) => i.try_into().map_err(|_| {
+                        hal_wire::CborError::InvalidValue
+                    })?,
+                    v => return hal_wire::cbor_type_error(&v, &"int"),
+                };
+                // Now match against enum possibilities.
+                match v {
+                    #(#recurse)*
+                    _ => Err(
+                        hal_wire::CborError::NonEnumValue(v)
+                    ),
+                }
+            }
+        }
+        Data::Union(_) => unimplemented!(),
+    }
+}
diff --git a/hals/rustfmt.toml b/hals/rustfmt.toml
new file mode 100644
index 00000000..cefaa42a
--- /dev/null
+++ b/hals/rustfmt.toml
@@ -0,0 +1,5 @@
+# Android Format Style
+
+edition = "2021"
+use_small_heuristics = "Max"
+newline_style = "Unix"
diff --git a/hals/wire/Android.bp b/hals/wire/Android.bp
new file mode 100644
index 00000000..d632aef8
--- /dev/null
+++ b/hals/wire/Android.bp
@@ -0,0 +1,56 @@
+// Copyright 2025, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+rust_library {
+    name: "libhal_wire",
+    crate_name: "hal_wire",
+    srcs: ["src/lib.rs"],
+    host_supported: true,
+    vendor_available: true,
+    edition: "2021",
+    lints: "android",
+    rustlibs: [
+        "libciborium",
+        "libciborium_io",
+    ],
+    proc_macros: [
+        "libhal_wire_derive",
+    ],
+}
+
+rust_library_rlib {
+    name: "libhal_wire_nostd",
+    crate_name: "hal_wire",
+    srcs: ["src/lib.rs"],
+    vendor_available: true,
+    edition: "2021",
+    lints: "android",
+    rustlibs: [
+        "libciborium_nostd",
+        "libciborium_io_nostd",
+    ],
+    proc_macros: [
+        "libhal_wire_derive",
+    ],
+    prefer_rlib: true,
+    no_stdlibs: true,
+    stdlibs: [
+        "libcompiler_builtins.rust_sysroot",
+        "libcore.rust_sysroot",
+    ],
+}
diff --git a/hals/wire/Cargo.toml b/hals/wire/Cargo.toml
new file mode 100644
index 00000000..8663edbf
--- /dev/null
+++ b/hals/wire/Cargo.toml
@@ -0,0 +1,13 @@
+# Note that Cargo is not an officially supported build tool (Android's Soong is the official
+# tool).  This Cargo.toml file is included purely for the convenience of developers.
+
+[package]
+name = "hal-wire"
+version = "0.1.0"
+authors = ["David Drysdale <drysdale@google.com>"]
+edition = "2021"
+license = "Apache-2.0"
+
+[dependencies]
+ciborium = { version = "^0.2.2", default-features = false }
+ciborium-io = "^0.2.0"
diff --git a/hals/wire/src/lib.rs b/hals/wire/src/lib.rs
new file mode 100644
index 00000000..17462796
--- /dev/null
+++ b/hals/wire/src/lib.rs
@@ -0,0 +1,241 @@
+// Copyright 2025, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! Types used for CBOR serialization of messages.
+
+#![no_std]
+extern crate alloc;
+
+/// Re-export of crate used for CBOR encoding.
+pub use ciborium as cbor;
+
+use alloc::vec::Vec;
+use cbor::value::Value;
+
+pub mod mem;
+
+/// Marker structure indicating that the EOF was encountered when reading CBOR data.
+#[derive(Debug)]
+pub struct EndOfFile;
+
+/// Error type for failures in encoding or decoding CBOR types.
+pub enum CborError {
+    /// CBOR decoding failure.
+    DecodeFailed(ciborium::de::Error<EndOfFile>),
+    /// CBOR encoding failure.
+    EncodeFailed,
+    /// CBOR input had extra data.
+    ExtraneousData,
+    /// Integer value outside expected range.
+    OutOfRangeIntegerValue,
+    /// Integer value that doesn't match expected set of allowed enum values.
+    NonEnumValue(i32),
+    /// Unexpected CBOR item encountered (got, want).
+    UnexpectedItem(&'static str, &'static str),
+    /// Value conversion failure.
+    InvalidValue,
+    /// Allocation failure.
+    AllocationFailed,
+}
+
+impl<T> From<ciborium::de::Error<T>> for CborError {
+    fn from(e: ciborium::de::Error<T>) -> Self {
+        // Make sure we use our [`EndOfFile`] marker.
+        use ciborium::de::Error::{Io, RecursionLimitExceeded, Semantic, Syntax};
+        let e = match e {
+            Io(_) => Io(EndOfFile),
+            Syntax(x) => Syntax(x),
+            Semantic(a, b) => Semantic(a, b),
+            RecursionLimitExceeded => RecursionLimitExceeded,
+        };
+        CborError::DecodeFailed(e)
+    }
+}
+
+impl<T> From<ciborium::ser::Error<T>> for CborError {
+    fn from(_e: ciborium::ser::Error<T>) -> Self {
+        CborError::EncodeFailed
+    }
+}
+
+impl From<alloc::collections::TryReserveError> for CborError {
+    fn from(_e: alloc::collections::TryReserveError) -> Self {
+        CborError::AllocationFailed
+    }
+}
+
+impl core::fmt::Debug for CborError {
+    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
+        match self {
+            CborError::DecodeFailed(de) => write!(f, "decode CBOR failure: {de:?}"),
+            CborError::EncodeFailed => write!(f, "encode CBOR failure"),
+            CborError::ExtraneousData => write!(f, "extraneous data in CBOR input"),
+            CborError::OutOfRangeIntegerValue => write!(f, "out of range integer value"),
+            CborError::NonEnumValue(val) => write!(f, "integer {val} not a valid enum value"),
+            CborError::UnexpectedItem(got, want) => write!(f, "got {got}, expected {want}"),
+            CborError::InvalidValue => write!(f, "invalid CBOR value"),
+            CborError::AllocationFailed => write!(f, "allocation failed"),
+        }
+    }
+}
+
+/// Return an error indicating that an unexpected CBOR type was encountered.
+pub fn cbor_type_error<T>(value: &Value, want: &'static str) -> Result<T, CborError> {
+    let got = match value {
+        Value::Integer(_) => "int",
+        Value::Bytes(_) => "bstr",
+        Value::Text(_) => "tstr",
+        Value::Array(_) => "array",
+        Value::Map(_) => "map",
+        Value::Tag(_, _) => "tag",
+        Value::Float(_) => "float",
+        Value::Bool(_) => "bool",
+        Value::Null => "null",
+        _ => "unknown",
+    };
+    Err(CborError::UnexpectedItem(got, want))
+}
+
+/// Read a [`Value`] from a byte slice, failing if any extra data remains after the `Value` has been
+/// read.
+pub fn read_to_value(mut slice: &[u8]) -> Result<Value, CborError> {
+    let value = ciborium::de::from_reader_with_recursion_limit(&mut slice, 16)?;
+    if slice.is_empty() {
+        Ok(value)
+    } else {
+        Err(CborError::ExtraneousData)
+    }
+}
+
+/// Trait for types that can be converted to/from a [`Value`].
+pub trait AsCborValue: Sized {
+    /// Convert a [`Value`] into an instance of the type.
+    fn from_cbor_value(value: Value) -> Result<Self, CborError>;
+
+    /// Convert the object into a [`Value`], consuming it along the way.
+    fn to_cbor_value(self) -> Result<Value, CborError>;
+
+    /// Create an object instance from serialized CBOR data in a slice.
+    fn from_slice(slice: &[u8]) -> Result<Self, CborError> {
+        Self::from_cbor_value(read_to_value(slice)?)
+    }
+
+    /// Serialize this object to a vector, consuming it along the way.
+    fn into_vec(self) -> Result<Vec<u8>, CborError> {
+        let mut data = Vec::new();
+        cbor::ser::into_writer(&self.to_cbor_value()?, &mut data)?;
+        Ok(data)
+    }
+}
+
+/// An `Option<T>` encodes as `( ? t )`, where `t` is whatever `T` encodes as in CBOR.
+impl<T: AsCborValue> AsCborValue for Option<T> {
+    fn from_cbor_value(value: Value) -> Result<Self, CborError> {
+        let mut arr = match value {
+            Value::Array(a) => a,
+            _ => return Err(CborError::UnexpectedItem("non-arr", "arr")),
+        };
+        match arr.len() {
+            0 => Ok(None),
+            1 => Ok(Some(<T>::from_cbor_value(arr.remove(0))?)),
+            _ => Err(CborError::UnexpectedItem("arr len >1", "arr len 0/1")),
+        }
+    }
+    fn to_cbor_value(self) -> Result<Value, CborError> {
+        match self {
+            Some(t) => Ok(Value::Array(vec_try![t.to_cbor_value()?]?)),
+            None => Ok(Value::Array(Vec::new())),
+        }
+    }
+}
+
+impl<T: AsCborValue, const N: usize> AsCborValue for [T; N] {
+    fn from_cbor_value(value: Value) -> Result<Self, CborError> {
+        let arr = match value {
+            Value::Array(a) => a,
+            _ => return cbor_type_error(&value, "arr"),
+        };
+        let results: Result<Vec<_>, _> = arr.into_iter().map(<T>::from_cbor_value).collect();
+        let results: Vec<_> = results?;
+        results.try_into().map_err(|_e| CborError::UnexpectedItem("arr other len", "arr fixed len"))
+    }
+    fn to_cbor_value(self) -> Result<Value, CborError> {
+        let values: Result<Vec<_>, _> = self.into_iter().map(|v| v.to_cbor_value()).collect();
+        Ok(Value::Array(values?))
+    }
+}
+
+/// A `Vec<T>` encodes as `( * t )`, where `t` is whatever `T` encodes as in CBOR.
+impl<T: AsCborValue> AsCborValue for Vec<T> {
+    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
+        let arr = match value {
+            cbor::value::Value::Array(a) => a,
+            _ => return cbor_type_error(&value, "arr"),
+        };
+        let results: Result<Vec<_>, _> = arr.into_iter().map(<T>::from_cbor_value).collect();
+        results
+    }
+    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
+        let values: Result<Vec<_>, _> = self.into_iter().map(|v| v.to_cbor_value()).collect();
+        Ok(cbor::value::Value::Array(values?))
+    }
+}
+
+impl AsCborValue for Vec<u8> {
+    fn from_cbor_value(value: Value) -> Result<Self, CborError> {
+        match value {
+            Value::Bytes(bstr) => Ok(bstr),
+            _ => cbor_type_error(&value, "bstr"),
+        }
+    }
+    fn to_cbor_value(self) -> Result<Value, CborError> {
+        Ok(Value::Bytes(self))
+    }
+}
+
+impl AsCborValue for bool {
+    fn from_cbor_value(value: cbor::value::Value) -> Result<Self, CborError> {
+        match value {
+            cbor::value::Value::Bool(b) => Ok(b),
+            _ => cbor_type_error(&value, "bool"),
+        }
+    }
+    fn to_cbor_value(self) -> Result<cbor::value::Value, CborError> {
+        Ok(cbor::value::Value::Bool(self))
+    }
+}
+
+impl AsCborValue for i32 {
+    fn from_cbor_value(value: Value) -> Result<Self, CborError> {
+        match value {
+            Value::Integer(i) => i.try_into().map_err(|_| CborError::OutOfRangeIntegerValue),
+            _ => crate::cbor_type_error(&value, "i32"),
+        }
+    }
+    fn to_cbor_value(self) -> Result<Value, CborError> {
+        Ok(Value::Integer(self.into()))
+    }
+}
+
+impl AsCborValue for i64 {
+    fn from_cbor_value(value: Value) -> Result<Self, CborError> {
+        match value {
+            Value::Integer(i) => i.try_into().map_err(|_| CborError::InvalidValue),
+            _ => crate::cbor_type_error(&value, "i64"),
+        }
+    }
+    fn to_cbor_value(self) -> Result<Value, CborError> {
+        Ok(Value::Integer(self.into()))
+    }
+}
diff --git a/hals/wire/src/mem.rs b/hals/wire/src/mem.rs
new file mode 100644
index 00000000..8bcc884e
--- /dev/null
+++ b/hals/wire/src/mem.rs
@@ -0,0 +1,136 @@
+// Copyright 2025, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! Utilities to help with fallible allocation.
+
+use alloc::collections::TryReserveError;
+use alloc::vec::Vec;
+
+/// Function that mimics `slice.to_vec()` but which detects allocation failures.
+#[inline]
+pub fn try_to_vec<T: Clone>(s: &[T]) -> Result<Vec<T>, TryReserveError> {
+    let mut v = vec_try_with_capacity::<T>(s.len())?;
+    v.extend_from_slice(s);
+    Ok(v)
+}
+
+/// Extension trait to provide fallible-allocation variants of `Vec` methods.
+pub trait FallibleAllocExt<T> {
+    /// Try to add the `value` to the collection, failing on memory exhaustion.
+    fn try_push(&mut self, value: T) -> Result<(), TryReserveError>;
+    /// Try to extend the collection with the contents of `other`, failing on memory exhaustion.
+    fn try_extend_from_slice(&mut self, other: &[T]) -> Result<(), TryReserveError>
+    where
+        T: Clone;
+}
+
+impl<T> FallibleAllocExt<T> for Vec<T> {
+    fn try_push(&mut self, value: T) -> Result<(), TryReserveError> {
+        self.try_reserve(1)?;
+        self.push(value);
+        Ok(())
+    }
+    fn try_extend_from_slice(&mut self, other: &[T]) -> Result<(), TryReserveError>
+    where
+        T: Clone,
+    {
+        self.try_reserve(other.len())?;
+        self.extend_from_slice(other);
+        Ok(())
+    }
+}
+
+/// Create a `Vec<T>` with the given length reserved, detecting allocation failure.
+pub fn vec_try_with_capacity<T>(len: usize) -> Result<Vec<T>, TryReserveError> {
+    let mut v = alloc::vec::Vec::new();
+    v.try_reserve(len)?;
+    Ok(v)
+}
+
+/// Macro that mimics `vec!` but which detects allocation failure.
+#[macro_export]
+macro_rules! vec_try {
+    { $elem:expr ; $len:expr } => {
+        $crate::mem::vec_try_fill_with_alloc_err($elem, $len)
+    };
+    { $x1:expr, $x2:expr, $x3:expr, $x4:expr $(,)? } => {
+        $crate::mem::vec_try4_with_alloc_err($x1, $x2, $x3, $x4)
+    };
+    { $x1:expr, $x2:expr, $x3:expr $(,)? } => {
+        $crate::mem::vec_try3_with_alloc_err($x1, $x2, $x3)
+    };
+    { $x1:expr, $x2:expr $(,)? } => {
+        $crate::mem::vec_try2_with_alloc_err($x1, $x2)
+    };
+    { $x1:expr $(,)? } => {
+        $crate::mem::vec_try1_with_alloc_err($x1)
+    };
+}
+
+/// Function that mimics `vec![<val>; <len>]` but which detects allocation failure with the given
+/// error.
+pub fn vec_try_fill_with_alloc_err<T: Clone>(
+    elem: T,
+    len: usize,
+) -> Result<Vec<T>, TryReserveError> {
+    let mut v = alloc::vec::Vec::new();
+    v.try_reserve(len)?;
+    v.resize(len, elem);
+    Ok(v)
+}
+
+/// Function that mimics `vec![x1, x2, x3, x4]` but which detects allocation failure with the given
+/// error.
+pub fn vec_try4_with_alloc_err<T: Clone>(
+    x1: T,
+    x2: T,
+    x3: T,
+    x4: T,
+) -> Result<Vec<T>, TryReserveError> {
+    let mut v = alloc::vec::Vec::new();
+    v.try_reserve(4)?;
+    v.push(x1);
+    v.push(x2);
+    v.push(x3);
+    v.push(x4);
+    Ok(v)
+}
+
+/// Function that mimics `vec![x1, x2, x3]` but which detects allocation failure with the given
+/// error.
+pub fn vec_try3_with_alloc_err<T: Clone>(x1: T, x2: T, x3: T) -> Result<Vec<T>, TryReserveError> {
+    let mut v = alloc::vec::Vec::new();
+    v.try_reserve(3)?;
+    v.push(x1);
+    v.push(x2);
+    v.push(x3);
+    Ok(v)
+}
+
+/// Function that mimics `vec![x1, x2]` but which detects allocation failure with the given error.
+pub fn vec_try2_with_alloc_err<T: Clone>(x1: T, x2: T) -> Result<Vec<T>, TryReserveError> {
+    let mut v = alloc::vec::Vec::new();
+    v.try_reserve(2)?;
+    v.push(x1);
+    v.push(x2);
+    Ok(v)
+}
+
+/// Function that mimics `vec![x1]` but which detects allocation failure with the given error.
+pub fn vec_try1_with_alloc_err<T: Clone>(x1: T) -> Result<Vec<T>, TryReserveError> {
+    let mut v = alloc::vec::Vec::new();
+    v.try_reserve(1)?;
+    v.push(x1);
+    Ok(v)
+}
diff --git a/keystore2/Android.bp b/keystore2/Android.bp
index 92a4bed8..abd0f633 100644
--- a/keystore2/Android.bp
+++ b/keystore2/Android.bp
@@ -31,10 +31,6 @@ rust_defaults {
         "keystore2_use_latest_aidl_rust",
         "structured_log_rust_defaults",
     ],
-    cfgs: select(release_flag("RELEASE_AVF_ENABLE_EARLY_VM"), {
-        true: ["early_vm"],
-        default: [],
-    }),
     rustlibs: [
         "android.hardware.security.rkp-V3-rust",
         "android.hardware.security.secureclock-V1-rust",
diff --git a/keystore2/TEST_MAPPING b/keystore2/TEST_MAPPING
index f12a301f..2307d874 100644
--- a/keystore2/TEST_MAPPING
+++ b/keystore2/TEST_MAPPING
@@ -34,6 +34,9 @@
     {
       "name": "CtsKeystorePerformanceTestCases"
     },
+    {
+      "name": "keystore2_engine_tests"
+    },
     {
       "name": "librkpd_client.test"
     },
diff --git a/keystore2/aconfig/flags.aconfig b/keystore2/aconfig/flags.aconfig
index 9161de87..9d23f7db 100644
--- a/keystore2/aconfig/flags.aconfig
+++ b/keystore2/aconfig/flags.aconfig
@@ -34,17 +34,28 @@ flag {
 }
 
 flag {
-  name: "use_blob_state_column"
+  name: "attest_modules"
   namespace: "hardware_backed_security"
-  description: "Use state database column to track superseded blobentry rows"
-  bug: "319563050"
+  description: "Support attestation of modules"
+  bug: "369375199"
   is_fixed_read_only: true
 }
 
 flag {
-  name: "attest_modules"
+  name: "count_keys_per_uid"
   namespace: "hardware_backed_security"
-  description: "Support attestation of modules"
-  bug: "369375199"
+  description: "Track counts of keys per-uid"
+  bug: "395078130"
+  is_fixed_read_only: true
+}
+
+flag {
+  name: "remove_rebound_keyblobs_fix"
+  namespace: "hardware_backed_security"
+  description: "Garbage collect keyblobs associated with keys that have been rebound"
+  bug: "416190842"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
   is_fixed_read_only: true
 }
diff --git a/keystore2/aidl/Android.bp b/keystore2/aidl/Android.bp
index 13bf455e..30cff35c 100644
--- a/keystore2/aidl/Android.bp
+++ b/keystore2/aidl/Android.bp
@@ -162,68 +162,3 @@ aidl_interface {
         },
     },
 }
-
-// java_defaults that includes the latest Keystore2 AIDL library.
-// Modules that depend on KeyMint directly can include this java_defaults to avoid
-// managing dependency versions explicitly.
-java_defaults {
-    name: "keystore2_use_latest_aidl_java_static",
-    static_libs: [
-        "android.system.keystore2-V5-java-source",
-    ],
-}
-
-java_defaults {
-    name: "keystore2_use_latest_aidl_java_shared",
-    libs: [
-        "android.system.keystore2-V5-java-source",
-    ],
-}
-
-java_defaults {
-    name: "keystore2_use_latest_aidl_java",
-    libs: [
-        "android.system.keystore2-V5-java",
-    ],
-}
-
-// cc_defaults that includes the latest Keystore2 AIDL library.
-// Modules that depend on KeyMint directly can include this cc_defaults to avoid
-// managing dependency versions explicitly.
-cc_defaults {
-    name: "keystore2_use_latest_aidl_ndk_static",
-    static_libs: [
-        "android.system.keystore2-V5-ndk",
-    ],
-}
-
-cc_defaults {
-    name: "keystore2_use_latest_aidl_ndk_shared",
-    shared_libs: [
-        "android.system.keystore2-V5-ndk",
-    ],
-}
-
-cc_defaults {
-    name: "keystore2_use_latest_aidl_cpp_shared",
-    shared_libs: [
-        "android.system.keystore2-V5-cpp",
-    ],
-}
-
-cc_defaults {
-    name: "keystore2_use_latest_aidl_cpp_static",
-    static_libs: [
-        "android.system.keystore2-V5-cpp",
-    ],
-}
-
-// A rust_defaults that includes the latest Keystore2 AIDL library.
-// Modules that depend on Keystore2 directly can include this rust_defaults to avoid
-// managing dependency versions explicitly.
-rust_defaults {
-    name: "keystore2_use_latest_aidl_rust",
-    rustlibs: [
-        "android.system.keystore2-V5-rust",
-    ],
-}
diff --git a/keystore2/aidl/android/security/authorization/IKeystoreAuthorization.aidl b/keystore2/aidl/android/security/authorization/IKeystoreAuthorization.aidl
index fd532f62..9c6778d9 100644
--- a/keystore2/aidl/android/security/authorization/IKeystoreAuthorization.aidl
+++ b/keystore2/aidl/android/security/authorization/IKeystoreAuthorization.aidl
@@ -53,7 +53,7 @@ interface IKeystoreAuthorization {
      *  - The (correct) password is provided, proving that the user has authenticated using LSKF or
      *    equivalent.  This is the most powerful type of unlock.  Keystore uses the password to
      *    decrypt the user's UnlockedDeviceRequired super keys from disk.  It also uses the password
-     *    to decrypt the user's AfterFirstUnlock super key from disk, if not already done.
+     *    to decrypt the user's CredentialEncrypted super key from disk, if not already done.
      *
      *  - The user's UnlockedDeviceRequired super keys are cached in biometric-encrypted form, and a
      *    matching valid HardwareAuthToken has been added to Keystore.  I.e., class 3 biometric
@@ -108,6 +108,17 @@ interface IKeystoreAuthorization {
      */
     void onDeviceLocked(in int userId, in long[] unlockingSids, in boolean weakUnlockEnabled);
 
+    /**
+    * Tells keystore about a user's credential-encrypted storage being locked.
+    * Callers require 'Lock' permission
+    *
+    * ## Error conditions:
+    * 'ResponseCode::PERMISSION_DENIED' - if the callers do not have the 'Lock' permission.
+    *
+    * @param userId - Android user id
+    */
+    void onUserStorageLocked(in int userId);
+
     /**
      * Tells Keystore that weak unlock methods can no longer unlock the device for the given user.
      * This is intended to be called after an earlier call to onDeviceLocked() with
diff --git a/keystore2/legacykeystore/lib.rs b/keystore2/legacykeystore/lib.rs
index b173da83..6dcc1d9d 100644
--- a/keystore2/legacykeystore/lib.rs
+++ b/keystore2/legacykeystore/lib.rs
@@ -29,6 +29,7 @@ use keystore2::{
     legacy_blob::LegacyBlobLoader, maintenance::DeleteListener, maintenance::Domain,
     utils::uid_to_android_user, utils::watchdog as wd,
 };
+use log::{error, warn};
 use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
 use std::sync::Arc;
 use std::{
@@ -224,7 +225,7 @@ fn into_logged_binder(e: anyhow::Error) -> BinderStatus {
         Some(Error::Binder(_, _)) | None => (ERROR_SYSTEM_ERROR, true),
     };
     if log_error {
-        log::error!("{:?}", e);
+        error!("{e:?}");
     }
     BinderStatus::new_service_specific_error(rc, anyhow_error_to_cstring(&e).as_deref())
 }
@@ -385,7 +386,7 @@ impl LegacyKeystore {
         };
 
         if let Err(e) = self.bulk_delete_uid(uid) {
-            log::warn!("In LegacyKeystore::delete_namespace: {:?}", e);
+            warn!("In LegacyKeystore::delete_namespace: {e:?}");
         }
         let mut db = self.open_db().context("In LegacyKeystore::delete_namespace.")?;
         db.remove_uid(uid).context("In LegacyKeystore::delete_namespace.")
@@ -393,7 +394,7 @@ impl LegacyKeystore {
 
     fn delete_user(&self, user_id: u32) -> Result<()> {
         if let Err(e) = self.bulk_delete_user(user_id) {
-            log::warn!("In LegacyKeystore::delete_user: {:?}", e);
+            warn!("In LegacyKeystore::delete_user: {e:?}");
         }
         let mut db = self.open_db().context("In LegacyKeystore::delete_user.")?;
         db.remove_user(user_id).context("In LegacyKeystore::delete_user.")
@@ -481,7 +482,7 @@ impl LegacyKeystore {
                 .context("In bulk_delete_uid: Trying to list entries.")?;
             for alias in entries.iter() {
                 if let Err(e) = state.legacy_loader.remove_legacy_keystore_entry(uid, alias) {
-                    log::warn!("In bulk_delete_uid: Failed to delete legacy entry. {:?}", e);
+                    warn!("In bulk_delete_uid: Failed to delete legacy entry. {e:?}");
                 }
             }
             Ok(())
@@ -497,7 +498,7 @@ impl LegacyKeystore {
             for (uid, entries) in entries.iter() {
                 for alias in entries.iter() {
                     if let Err(e) = state.legacy_loader.remove_legacy_keystore_entry(*uid, alias) {
-                        log::warn!("In bulk_delete_user: Failed to delete legacy entry. {:?}", e);
+                        warn!("In bulk_delete_user: Failed to delete legacy entry. {e:?}");
                     }
                 }
             }
@@ -516,7 +517,7 @@ impl LegacyKeystore {
                 if let Some(key) = SUPER_KEY
                     .read()
                     .unwrap()
-                    .get_after_first_unlock_key_by_user_id(uid_to_android_user(uid))
+                    .get_credential_encrypted_key_by_user_id(uid_to_android_user(uid))
                 {
                     key.decrypt(ciphertext, iv, tag)
                 } else {
diff --git a/keystore2/rkpd_client/src/lib.rs b/keystore2/rkpd_client/src/lib.rs
index 936fe3d6..6284be3c 100644
--- a/keystore2/rkpd_client/src/lib.rs
+++ b/keystore2/rkpd_client/src/lib.rs
@@ -25,6 +25,7 @@ use android_security_rkp_aidl::aidl::android::security::rkp::{
 };
 use anyhow::{Context, Result};
 use binder::{BinderFeatures, Interface, StatusCode, Strong};
+use log::{error, warn};
 use message_macro::source_location_msg;
 use std::sync::Mutex;
 use std::time::Duration;
@@ -94,7 +95,7 @@ impl<T> SafeSender<T> {
             // It's possible for the corresponding receiver to time out and be dropped. In this
             // case send() will fail. This error is not actionable though, so only log the error.
             if inner.send(value).is_err() {
-                log::error!("SafeSender::send() failed");
+                error!("SafeSender::send() failed");
             }
         }
     }
@@ -122,7 +123,7 @@ impl IGetRegistrationCallback for GetRegistrationCallback {
         Ok(())
     }
     fn onCancel(&self) -> binder::Result<()> {
-        log::warn!("IGetRegistrationCallback cancelled");
+        warn!("IGetRegistrationCallback cancelled");
         self.registration_tx.send(
             Err(Error::RequestCancelled)
                 .context(source_location_msg!("GetRegistrationCallback cancelled.")),
@@ -130,7 +131,7 @@ impl IGetRegistrationCallback for GetRegistrationCallback {
         Ok(())
     }
     fn onError(&self, description: &str) -> binder::Result<()> {
-        log::error!("IGetRegistrationCallback failed: '{description}'");
+        error!("IGetRegistrationCallback failed: '{description}'");
         self.registration_tx.send(
             Err(Error::GetRegistrationFailed)
                 .context(source_location_msg!("GetRegistrationCallback failed: {:?}", description)),
@@ -183,14 +184,14 @@ impl IGetKeyCallback for GetKeyCallback {
         Ok(())
     }
     fn onCancel(&self) -> binder::Result<()> {
-        log::warn!("IGetKeyCallback cancelled");
+        warn!("IGetKeyCallback cancelled");
         self.key_tx.send(
             Err(Error::RequestCancelled).context(source_location_msg!("GetKeyCallback cancelled.")),
         );
         Ok(())
     }
     fn onError(&self, error: GetKeyErrorCode, description: &str) -> binder::Result<()> {
-        log::error!("IGetKeyCallback failed: {description}");
+        error!("IGetKeyCallback failed: {description}");
         self.key_tx.send(Err(Error::GetKeyFailed(error)).context(source_location_msg!(
             "GetKeyCallback failed: {:?} {:?}",
             error,
@@ -215,7 +216,7 @@ async fn get_rkpd_attestation_key_from_registration_async(
         Err(e) => {
             // Make a best effort attempt to cancel the timed out request.
             if let Err(e) = registration.cancelGetKey(&cb) {
-                log::error!("IRegistration::cancelGetKey failed: {:?}", e);
+                error!("IRegistration::cancelGetKey failed: {e:?}");
             }
             Err(Error::RetryableTimeout)
                 .context(source_location_msg!("Waiting for RKPD key timed out: {:?}", e))
@@ -256,7 +257,7 @@ impl IStoreUpgradedKeyCallback for StoreUpgradedKeyCallback {
     }
 
     fn onError(&self, error: &str) -> binder::Result<()> {
-        log::error!("IStoreUpgradedKeyCallback failed: {error}");
+        error!("IStoreUpgradedKeyCallback failed: {error}");
         self.completer.send(
             Err(Error::StoreUpgradedKeyFailed)
                 .context(source_location_msg!("Failed to store upgraded key: {:?}", error)),
diff --git a/keystore2/selinux/src/concurrency_test.rs b/keystore2/selinux/src/concurrency_test.rs
index fa97f3aa..d7f3c366 100644
--- a/keystore2/selinux/src/concurrency_test.rs
+++ b/keystore2/selinux/src/concurrency_test.rs
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 use keystore2_selinux::{check_access, Context};
+use log::info;
 use nix::sched::sched_setaffinity;
 use nix::sched::CpuSet;
 use nix::unistd::getpid;
@@ -78,7 +79,7 @@ fn test_concurrent_check_access() {
     let mut threads: Vec<thread::JoinHandle<()>> = Vec::new();
 
     for i in 0..cpus {
-        log::info!("Spawning thread {}", i);
+        info!("Spawning thread {}", i);
         let turnpike_clone = turnpike.clone();
         let complete_count_clone = complete_count.clone();
         threads.push(thread::spawn(move || {
@@ -87,7 +88,7 @@ fn test_concurrent_check_access() {
             sched_setaffinity(getpid(), &cpu_set).unwrap();
             let mut cat_count: CatCount = Default::default();
 
-            log::info!("Thread 0 reached turnpike");
+            info!("Thread 0 reached turnpike");
             loop {
                 turnpike_clone.fetch_add(1, Ordering::Relaxed);
                 loop {
diff --git a/keystore2/src/apc.rs b/keystore2/src/apc.rs
index fc36a0c1..de78304b 100644
--- a/keystore2/src/apc.rs
+++ b/keystore2/src/apc.rs
@@ -15,12 +15,6 @@
 //! This module implements the Android Protected Confirmation (APC) service as defined
 //! in the android.security.apc AIDL spec.
 
-use std::{
-    cmp::PartialEq,
-    collections::HashMap,
-    sync::{mpsc::Sender, Arc, Mutex},
-};
-
 use crate::error::anyhow_error_to_cstring;
 use crate::ks_err;
 use crate::utils::{compat_2_response_code, ui_opts_2_compat, watchdog as wd};
@@ -36,7 +30,13 @@ use android_security_apc::binder::{
 use anyhow::{Context, Result};
 use keystore2_apc_compat::ApcHal;
 use keystore2_selinux as selinux;
+use log::error;
 use std::time::{Duration, Instant};
+use std::{
+    cmp::PartialEq,
+    collections::HashMap,
+    sync::{mpsc::Sender, Arc, Mutex},
+};
 
 /// This is the main APC error type, it wraps binder exceptions and the
 /// APC ResponseCode.
@@ -80,7 +80,7 @@ impl Error {
 ///
 /// All non `Error` error conditions get mapped onto ResponseCode::SYSTEM_ERROR`.
 pub fn into_logged_binder(e: anyhow::Error) -> BinderStatus {
-    log::error!("{:#?}", e);
+    error!("{e:#?}");
     let root_cause = e.root_cause();
     let rc = match root_cause.downcast_ref::<Error>() {
         Some(Error::Rc(rcode)) => rcode.0,
@@ -210,7 +210,7 @@ impl ApcManager {
                 state.rate_limiting.remove(&uid);
                 // Send confirmation token to the enforcement module.
                 if let Err(e) = state.confirmation_token_sender.send(confirmation_token.to_vec()) {
-                    log::error!("Got confirmation token, but receiver would not have it. {:?}", e);
+                    error!("Got confirmation token, but receiver would not have it. {e:?}");
                 }
             }
             // If cancelled by the user or if aborted by the client.
@@ -221,7 +221,7 @@ impl ApcManager {
                 rate_info.timestamp = start;
             }
             (ResponseCode::OK, _, None) => {
-                log::error!(
+                error!(
                     "Confirmation prompt was successful but no confirmation token was returned."
                 );
             }
@@ -232,10 +232,10 @@ impl ApcManager {
 
         if let Ok(listener) = callback.into_interface::<dyn IConfirmationCallback>() {
             if let Err(e) = listener.onCompleted(rc, data_confirmed) {
-                log::error!("Reporting completion to client failed {:?}", e)
+                error!("Reporting completion to client failed {e:?}")
             }
         } else {
-            log::error!("SpIBinder is not a IConfirmationCallback.");
+            error!("SpIBinder is not a IConfirmationCallback.");
         }
     }
 
diff --git a/keystore2/src/audit_log.rs b/keystore2/src/audit_log.rs
index 4952b3bf..0d987cd1 100644
--- a/keystore2/src/audit_log.rs
+++ b/keystore2/src/audit_log.rs
@@ -20,6 +20,7 @@ use android_system_keystore2::aidl::android::system::keystore2::{
     Domain::Domain, KeyDescriptor::KeyDescriptor,
 };
 use libc::uid_t;
+use log::info;
 use structured_log::{structured_log, LOG_ID_SECURITY};
 
 const TAG_KEY_GENERATED: u32 = 210024;
@@ -35,7 +36,7 @@ fn key_owner(domain: Domain, nspace: i64, uid: i32) -> i32 {
         Domain::APP => uid,
         Domain::SELINUX => (nspace | FLAG_NAMESPACE) as i32,
         d => {
-            log::info!("Not logging audit event for key with domain {d:?}");
+            info!("Not logging audit event for key with domain {d:?}");
             0
         }
     }
diff --git a/keystore2/src/authorization.rs b/keystore2/src/authorization.rs
index 7812df65..8a9e59d4 100644
--- a/keystore2/src/authorization.rs
+++ b/keystore2/src/authorization.rs
@@ -19,7 +19,8 @@ use crate::error::Error as KeystoreError;
 use crate::globals::{DB, ENFORCEMENTS, LEGACY_IMPORTER, SUPER_KEY};
 use crate::ks_err;
 use crate::permission::KeystorePerm;
-use crate::utils::{check_keystore_permission, watchdog as wd};
+use crate::super_key::WipeKeyOption;
+use crate::utils::{check_keystore_permission, watchdog as wd, Challenge, SecureUserId};
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
 };
@@ -35,6 +36,7 @@ use android_system_keystore2::aidl::android::system::keystore2::ResponseCode::Re
 use anyhow::{Context, Result};
 use keystore2_crypto::Password;
 use keystore2_selinux as selinux;
+use log::{error, info};
 
 /// This is the Authorization error type, it wraps binder exceptions and the
 /// Authorization ResponseCode
@@ -60,7 +62,7 @@ pub enum Error {
 ///
 /// All non `Error` error conditions get mapped onto ResponseCode::SYSTEM_ERROR`.
 pub fn into_logged_binder(e: anyhow::Error) -> BinderStatus {
-    log::error!("{:#?}", e);
+    error!("{e:#?}");
     let root_cause = e.root_cause();
     if let Some(KeystoreError::Rc(ks_rcode)) = root_cause.downcast_ref::<KeystoreError>() {
         let rc = match *ks_rcode {
@@ -109,7 +111,7 @@ impl AuthorizationManager {
         check_keystore_permission(KeystorePerm::AddAuth)
             .context(ks_err!("caller missing AddAuth permissions"))?;
 
-        log::info!(
+        info!(
             "add_auth_token(challenge={}, userId={}, authId={}, authType={:#x}, timestamp={}ms)",
             auth_token.challenge,
             auth_token.userId,
@@ -123,11 +125,7 @@ impl AuthorizationManager {
     }
 
     fn on_device_unlocked(&self, user_id: i32, password: Option<Password>) -> Result<()> {
-        log::info!(
-            "on_device_unlocked(user_id={}, password.is_some()={})",
-            user_id,
-            password.is_some(),
-        );
+        info!("on_device_unlocked(user_id={user_id}, password.is_some()={})", password.is_some());
         check_keystore_permission(KeystorePerm::Unlock)
             .context(ks_err!("caller missing Unlock permissions"))?;
         ENFORCEMENTS.set_device_locked(user_id, false);
@@ -147,14 +145,11 @@ impl AuthorizationManager {
     fn on_device_locked(
         &self,
         user_id: i32,
-        unlocking_sids: &[i64],
+        unlocking_sids: &[SecureUserId],
         weak_unlock_enabled: bool,
     ) -> Result<()> {
-        log::info!(
-            "on_device_locked(user_id={}, unlocking_sids={:?}, weak_unlock_enabled={})",
-            user_id,
-            unlocking_sids,
-            weak_unlock_enabled
+        info!(
+            "on_device_locked(user_id={user_id}, unlocking_sids={unlocking_sids:?}, weak_unlock_enabled={weak_unlock_enabled})",
         );
         check_keystore_permission(KeystorePerm::Lock)
             .context(ks_err!("caller missing Lock permission"))?;
@@ -171,26 +166,44 @@ impl AuthorizationManager {
         Ok(())
     }
 
+    fn on_user_storage_locked(&self, user_id: i32) -> Result<()> {
+        log::info!("on_user_storage_locked(user_id={})", user_id);
+
+        check_keystore_permission(KeystorePerm::Lock)
+            .context(ks_err!("caller missing Lock permission"))?;
+
+        // Delete super key in cache, if exists.
+        SUPER_KEY.write().unwrap().forget_all_keys_for_user(user_id as u32);
+
+        Ok(())
+    }
+
     fn on_weak_unlock_methods_expired(&self, user_id: i32) -> Result<()> {
-        log::info!("on_weak_unlock_methods_expired(user_id={})", user_id);
+        info!("on_weak_unlock_methods_expired(user_id={user_id})");
         check_keystore_permission(KeystorePerm::Lock)
             .context(ks_err!("caller missing Lock permission"))?;
-        SUPER_KEY.write().unwrap().wipe_plaintext_unlocked_device_required_keys(user_id as u32);
+        SUPER_KEY
+            .write()
+            .unwrap()
+            .wipe_unlocked_device_required_keys(user_id as u32, WipeKeyOption::PlaintextOnly);
         Ok(())
     }
 
     fn on_non_lskf_unlock_methods_expired(&self, user_id: i32) -> Result<()> {
-        log::info!("on_non_lskf_unlock_methods_expired(user_id={})", user_id);
+        info!("on_non_lskf_unlock_methods_expired(user_id={user_id})");
         check_keystore_permission(KeystorePerm::Lock)
             .context(ks_err!("caller missing Lock permission"))?;
-        SUPER_KEY.write().unwrap().wipe_all_unlocked_device_required_keys(user_id as u32);
+        SUPER_KEY.write().unwrap().wipe_unlocked_device_required_keys(
+            user_id as u32,
+            WipeKeyOption::PlaintextAndBiometric,
+        );
         Ok(())
     }
 
     fn get_auth_tokens_for_credstore(
         &self,
-        challenge: i64,
-        secure_user_id: i64,
+        challenge: Challenge,
+        sid: SecureUserId,
         auth_token_max_age_millis: i64,
     ) -> Result<AuthorizationTokens> {
         // Check permission. Function should return if this failed. Therefore having '?' at the end
@@ -199,19 +212,19 @@ impl AuthorizationManager {
             .context(ks_err!("caller missing GetAuthToken permission"))?;
 
         // If the challenge is zero, return error
-        if challenge == 0 {
+        if challenge.0 == 0 {
             return Err(Error::Rc(ResponseCode::INVALID_ARGUMENT))
                 .context(ks_err!("Challenge can not be zero."));
         }
         // Obtain the auth token and the timestamp token from the enforcement module.
         let (auth_token, ts_token) =
-            ENFORCEMENTS.get_auth_tokens(challenge, secure_user_id, auth_token_max_age_millis)?;
+            ENFORCEMENTS.get_auth_tokens(challenge, sid, auth_token_max_age_millis)?;
         Ok(AuthorizationTokens { authToken: auth_token, timestampToken: ts_token })
     }
 
     fn get_last_auth_time(
         &self,
-        secure_user_id: i64,
+        sid: SecureUserId,
         auth_types: &[HardwareAuthenticatorType],
     ) -> Result<i64> {
         // Check keystore permission.
@@ -220,7 +233,7 @@ impl AuthorizationManager {
 
         let mut max_time: i64 = -1;
         for auth_type in auth_types.iter() {
-            if let Some(time) = ENFORCEMENTS.get_last_auth_time(secure_user_id, *auth_type) {
+            if let Some(time) = ENFORCEMENTS.get_last_auth_time(sid, *auth_type) {
                 if time.milliseconds() > max_time {
                     max_time = time.milliseconds();
                 }
@@ -255,11 +268,18 @@ impl IKeystoreAuthorization for AuthorizationManager {
         unlocking_sids: &[i64],
         weak_unlock_enabled: bool,
     ) -> BinderResult<()> {
+        let unlocking_sids: Vec<_> = unlocking_sids.iter().map(|sid| SecureUserId(*sid)).collect();
         let _wp = wd::watch("IKeystoreAuthorization::onDeviceLocked");
-        self.on_device_locked(user_id, unlocking_sids, weak_unlock_enabled)
+        self.on_device_locked(user_id, &unlocking_sids, weak_unlock_enabled)
             .map_err(into_logged_binder)
     }
 
+    fn onUserStorageLocked(&self, user_id: i32) -> BinderResult<()> {
+        log::info!("onUserStorageLocked(user={user_id})");
+        let _wp = wd::watch("IKeystoreMaintenance::onUserStorageLocked");
+        self.on_user_storage_locked(user_id).map_err(into_logged_binder)
+    }
+
     fn onWeakUnlockMethodsExpired(&self, user_id: i32) -> BinderResult<()> {
         let _wp = wd::watch("IKeystoreAuthorization::onWeakUnlockMethodsExpired");
         self.on_weak_unlock_methods_expired(user_id).map_err(into_logged_binder)
@@ -276,8 +296,10 @@ impl IKeystoreAuthorization for AuthorizationManager {
         secure_user_id: i64,
         auth_token_max_age_millis: i64,
     ) -> binder::Result<AuthorizationTokens> {
+        let sid = SecureUserId(secure_user_id);
+        let challenge = Challenge(challenge);
         let _wp = wd::watch("IKeystoreAuthorization::getAuthTokensForCredStore");
-        self.get_auth_tokens_for_credstore(challenge, secure_user_id, auth_token_max_age_millis)
+        self.get_auth_tokens_for_credstore(challenge, sid, auth_token_max_age_millis)
             .map_err(into_logged_binder)
     }
 
@@ -286,6 +308,7 @@ impl IKeystoreAuthorization for AuthorizationManager {
         secure_user_id: i64,
         auth_types: &[HardwareAuthenticatorType],
     ) -> binder::Result<i64> {
-        self.get_last_auth_time(secure_user_id, auth_types).map_err(into_logged_binder)
+        let sid = SecureUserId(secure_user_id);
+        self.get_last_auth_time(sid, auth_types).map_err(into_logged_binder)
     }
 }
diff --git a/keystore2/src/boot_level_keys.rs b/keystore2/src/boot_level_keys.rs
index e2e67ff7..7d4aef17 100644
--- a/keystore2/src/boot_level_keys.rs
+++ b/keystore2/src/boot_level_keys.rs
@@ -26,8 +26,13 @@ use android_hardware_security_keymint::aidl::android::hardware::security::keymin
 };
 use anyhow::{Context, Result};
 use keystore2_crypto::{hkdf_expand, ZVec, AES_256_KEY_LENGTH};
+use log::{error, info};
 use std::{collections::VecDeque, convert::TryFrom};
 
+/// Boot level value.
+#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
+pub struct BootLevel(pub usize);
+
 /// Strategies used to prevent later boot stages from using the KM key that protects the level 0
 /// key
 #[derive(Debug, PartialEq, Eq, Clone, Copy)]
@@ -54,20 +59,20 @@ fn lookup_level_zero_km_and_strategy() -> Result<Option<(SecurityLevel, DenyLate
     let property_val = if let Some(p) = property_val {
         p
     } else {
-        log::info!("{} not set, inferring from installed KM instances", PROPERTY_NAME);
+        info!("{PROPERTY_NAME} not set, inferring from installed KM instances");
         return Ok(None);
     };
     let (level, strategy) = if let Some(c) = property_val.split_once(':') {
         c
     } else {
-        log::error!("Missing colon in {}: {:?}", PROPERTY_NAME, property_val);
+        error!("Missing colon in {PROPERTY_NAME}: {property_val:?}");
         return Ok(None);
     };
     let level = match level {
         "TRUSTED_ENVIRONMENT" => SecurityLevel::TRUSTED_ENVIRONMENT,
         "STRONGBOX" => SecurityLevel::STRONGBOX,
         _ => {
-            log::error!("Unknown security level in {}: {:?}", PROPERTY_NAME, level);
+            error!("Unknown security level in {PROPERTY_NAME}: {level:?}");
             return Ok(None);
         }
     };
@@ -75,11 +80,11 @@ fn lookup_level_zero_km_and_strategy() -> Result<Option<(SecurityLevel, DenyLate
         "EARLY_BOOT_ONLY" => DenyLaterStrategy::EarlyBootOnly,
         "MAX_USES_PER_BOOT" => DenyLaterStrategy::MaxUsesPerBoot,
         _ => {
-            log::error!("Unknown DenyLaterStrategy in {}: {:?}", PROPERTY_NAME, strategy);
+            error!("Unknown DenyLaterStrategy in {PROPERTY_NAME}: {strategy:?}");
             return Ok(None);
         }
     };
-    log::info!("Set from {}: {}", PROPERTY_NAME, property_val);
+    info!("Set from {PROPERTY_NAME}: {property_val}");
     Ok(Some((level, strategy)))
 }
 
@@ -112,7 +117,7 @@ fn get_level_zero_key_km_and_strategy() -> Result<(KeyMintDevice, DenyLaterStrat
 pub fn get_level_zero_key(db: &mut KeystoreDB) -> Result<ZVec> {
     let (km_dev, deny_later_strategy) = get_level_zero_key_km_and_strategy()
         .context(ks_err!("get preferred KM instance failed"))?;
-    log::info!(
+    info!(
         "In get_level_zero_key: security_level={:?}, deny_later_strategy={:?}",
         km_dev.security_level(),
         deny_later_strategy
@@ -138,18 +143,14 @@ pub fn get_level_zero_key(db: &mut KeystoreDB) -> Result<ZVec> {
         .lookup_or_generate_key(db, &key_desc, KeyType::Client, &params, |key_characteristics| {
             key_characteristics.iter().any(|kc| {
                 if kc.securityLevel != required_security_level {
-                    log::error!(
+                    error!(
                         "In get_level_zero_key: security level expected={:?} got={:?}",
-                        required_security_level,
-                        kc.securityLevel
+                        required_security_level, kc.securityLevel
                     );
                     return false;
                 }
                 if !kc.authorizations.iter().any(|a| a == &required_param) {
-                    log::error!(
-                        "In get_level_zero_key: required param absent {:?}",
-                        required_param
-                    );
+                    error!("In get_level_zero_key: required param {required_param:?} absent");
                     return false;
                 }
                 true
@@ -183,7 +184,7 @@ pub fn get_level_zero_key(db: &mut KeystoreDB) -> Result<ZVec> {
 /// When the boot level advances, keys prior to the current boot level are securely dropped.
 pub struct BootLevelKeyCache {
     /// Least boot level currently accessible, if any is.
-    current: usize,
+    current: BootLevel,
     /// Invariant: cache entry *i*, if it exists, holds the HKDF key for boot level
     /// *i* + `current`. If the cache is non-empty it can be grown forwards, but it cannot be
     /// grown backwards, so keys below `current` are inaccessible.
@@ -200,11 +201,11 @@ impl BootLevelKeyCache {
     pub fn new(level_zero_key: ZVec) -> Self {
         let mut cache: VecDeque<ZVec> = VecDeque::new();
         cache.push_back(level_zero_key);
-        Self { current: 0, cache }
+        Self { current: BootLevel(0), cache }
     }
 
     /// Report whether the key for the given level can be inferred.
-    pub fn level_accessible(&self, boot_level: usize) -> bool {
+    pub fn level_accessible(&self, boot_level: BootLevel) -> bool {
         // If the requested boot level is lower than the current boot level
         // or if we have reached the end (`cache.empty()`) we can't retrieve
         // the boot key.
@@ -213,16 +214,16 @@ impl BootLevelKeyCache {
 
     /// Get the HKDF key for boot level `boot_level`. The key for level *i*+1
     /// is calculated from the level *i* key using `hkdf_expand`.
-    fn get_hkdf_key(&mut self, boot_level: usize) -> Result<Option<&ZVec>> {
+    fn get_hkdf_key(&mut self, boot_level: BootLevel) -> Result<Option<&ZVec>> {
         if !self.level_accessible(boot_level) {
             return Ok(None);
         }
         // `self.cache.len()` represents the first entry not in the cache,
         // so `self.current + self.cache.len()` is the first boot level not in the cache.
-        let first_not_cached = self.current + self.cache.len();
+        let first_not_cached = self.current.0 + self.cache.len();
 
         // Grow the cache forwards until it contains the desired boot level.
-        for _level in first_not_cached..=boot_level {
+        for _level in first_not_cached..=boot_level.0 {
             // We check at the start that cache is non-empty and future iterations only push,
             // so this must unwrap.
             let highest_key = self.cache.back().unwrap();
@@ -232,16 +233,15 @@ impl BootLevelKeyCache {
         }
 
         // If we reach this point, we should have a key at index boot_level - current.
-        Ok(Some(self.cache.get(boot_level - self.current).unwrap()))
+        Ok(Some(self.cache.get(boot_level.0 - self.current.0).unwrap()))
     }
 
     /// Drop keys prior to the given boot level, while retaining the ability to generate keys for
     /// that level and later.
-    pub fn advance_boot_level(&mut self, new_boot_level: usize) -> Result<()> {
+    pub fn advance_boot_level(&mut self, new_boot_level: BootLevel) -> Result<()> {
         if !self.level_accessible(new_boot_level) {
-            log::error!(
-                "Failed to advance boot level to {}, current is {}, cache size {}",
-                new_boot_level,
+            error!(
+                "Failed to advance boot level to {new_boot_level:?}, current is {:?}, cache size {}",
                 self.current,
                 self.cache.len()
             );
@@ -254,7 +254,7 @@ impl BootLevelKeyCache {
 
         // Then we split the queue at the index of the new boot level and discard the front,
         // keeping only the keys with the current boot level or higher.
-        self.cache = self.cache.split_off(new_boot_level - self.current);
+        self.cache = self.cache.split_off(new_boot_level.0 - self.current.0);
 
         // The new cache has the new boot level at index 0, so we set `current` to
         // `new_boot_level`.
@@ -271,7 +271,7 @@ impl BootLevelKeyCache {
 
     fn expand_key(
         &mut self,
-        boot_level: usize,
+        boot_level: BootLevel,
         out_len: usize,
         info: &[u8],
     ) -> Result<Option<ZVec>> {
@@ -283,7 +283,7 @@ impl BootLevelKeyCache {
     }
 
     /// Return the AES-256-GCM key for the current boot level.
-    pub fn aes_key(&mut self, boot_level: usize) -> Result<Option<ZVec>> {
+    pub fn aes_key(&mut self, boot_level: BootLevel) -> Result<Option<ZVec>> {
         self.expand_key(boot_level, AES_256_KEY_LENGTH, BootLevelKeyCache::HKDF_AES)
             .context(ks_err!("expand_key failed"))
     }
@@ -297,42 +297,42 @@ mod test {
     fn test_output_is_consistent() -> Result<()> {
         let initial_key = b"initial key";
         let mut blkc = BootLevelKeyCache::new(ZVec::try_from(initial_key as &[u8])?);
-        assert!(blkc.level_accessible(0));
-        assert!(blkc.level_accessible(9));
-        assert!(blkc.level_accessible(10));
-        assert!(blkc.level_accessible(100));
-        let v0 = blkc.aes_key(0).unwrap().unwrap();
-        let v10 = blkc.aes_key(10).unwrap().unwrap();
-        assert_eq!(Some(&v0), blkc.aes_key(0)?.as_ref());
-        assert_eq!(Some(&v10), blkc.aes_key(10)?.as_ref());
-        blkc.advance_boot_level(5)?;
-        assert!(!blkc.level_accessible(0));
-        assert!(blkc.level_accessible(9));
-        assert!(blkc.level_accessible(10));
-        assert!(blkc.level_accessible(100));
-        assert_eq!(None, blkc.aes_key(0)?);
-        assert_eq!(Some(&v10), blkc.aes_key(10)?.as_ref());
-        blkc.advance_boot_level(10)?;
-        assert!(!blkc.level_accessible(0));
-        assert!(!blkc.level_accessible(9));
-        assert!(blkc.level_accessible(10));
-        assert!(blkc.level_accessible(100));
-        assert_eq!(None, blkc.aes_key(0)?);
-        assert_eq!(Some(&v10), blkc.aes_key(10)?.as_ref());
-        blkc.advance_boot_level(0)?;
-        assert!(!blkc.level_accessible(0));
-        assert!(!blkc.level_accessible(9));
-        assert!(blkc.level_accessible(10));
-        assert!(blkc.level_accessible(100));
-        assert_eq!(None, blkc.aes_key(0)?);
-        assert_eq!(Some(v10), blkc.aes_key(10)?);
+        assert!(blkc.level_accessible(BootLevel(0)));
+        assert!(blkc.level_accessible(BootLevel(9)));
+        assert!(blkc.level_accessible(BootLevel(10)));
+        assert!(blkc.level_accessible(BootLevel(100)));
+        let v0 = blkc.aes_key(BootLevel(0)).unwrap().unwrap();
+        let v10 = blkc.aes_key(BootLevel(10)).unwrap().unwrap();
+        assert_eq!(Some(&v0), blkc.aes_key(BootLevel(0))?.as_ref());
+        assert_eq!(Some(&v10), blkc.aes_key(BootLevel(10))?.as_ref());
+        blkc.advance_boot_level(BootLevel(5))?;
+        assert!(!blkc.level_accessible(BootLevel(0)));
+        assert!(blkc.level_accessible(BootLevel(9)));
+        assert!(blkc.level_accessible(BootLevel(10)));
+        assert!(blkc.level_accessible(BootLevel(100)));
+        assert_eq!(None, blkc.aes_key(BootLevel(0))?);
+        assert_eq!(Some(&v10), blkc.aes_key(BootLevel(10))?.as_ref());
+        blkc.advance_boot_level(BootLevel(10))?;
+        assert!(!blkc.level_accessible(BootLevel(0)));
+        assert!(!blkc.level_accessible(BootLevel(9)));
+        assert!(blkc.level_accessible(BootLevel(10)));
+        assert!(blkc.level_accessible(BootLevel(100)));
+        assert_eq!(None, blkc.aes_key(BootLevel(0))?);
+        assert_eq!(Some(&v10), blkc.aes_key(BootLevel(10))?.as_ref());
+        blkc.advance_boot_level(BootLevel(0))?;
+        assert!(!blkc.level_accessible(BootLevel(0)));
+        assert!(!blkc.level_accessible(BootLevel(9)));
+        assert!(blkc.level_accessible(BootLevel(10)));
+        assert!(blkc.level_accessible(BootLevel(100)));
+        assert_eq!(None, blkc.aes_key(BootLevel(0))?);
+        assert_eq!(Some(v10), blkc.aes_key(BootLevel(10))?);
         blkc.finish();
-        assert!(!blkc.level_accessible(0));
-        assert!(!blkc.level_accessible(9));
-        assert!(!blkc.level_accessible(10));
-        assert!(!blkc.level_accessible(100));
-        assert_eq!(None, blkc.aes_key(0)?);
-        assert_eq!(None, blkc.aes_key(10)?);
+        assert!(!blkc.level_accessible(BootLevel(0)));
+        assert!(!blkc.level_accessible(BootLevel(9)));
+        assert!(!blkc.level_accessible(BootLevel(10)));
+        assert!(!blkc.level_accessible(BootLevel(100)));
+        assert_eq!(None, blkc.aes_key(BootLevel(0))?);
+        assert_eq!(None, blkc.aes_key(BootLevel(10))?);
         Ok(())
     }
 }
diff --git a/keystore2/src/crypto/zvec.rs b/keystore2/src/crypto/zvec.rs
index 00cbb1c8..6c2db2fa 100644
--- a/keystore2/src/crypto/zvec.rs
+++ b/keystore2/src/crypto/zvec.rs
@@ -15,6 +15,7 @@
 //! Implements ZVec, a vector that is mlocked during its lifetime and zeroed
 //! when dropped.
 
+use log::error;
 use nix::sys::mman::{mlock, munlock};
 use std::convert::TryFrom;
 use std::fmt;
@@ -82,7 +83,7 @@ impl Drop for ZVec {
                 // by `mlock` in `ZVec::new` or the `TryFrom<Vec<u8>>` implementation.
                 unsafe { munlock(NonNull::from(&self.elems).cast(), self.elems.len()) }
             {
-                log::error!("In ZVec::drop: `munlock` failed: {:?}.", e);
+                error!("In ZVec::drop: `munlock` failed: {e:?}");
             }
         }
     }
diff --git a/keystore2/src/database.rs b/keystore2/src/database.rs
index 8f5617f2..fb91f047 100644
--- a/keystore2/src/database.rs
+++ b/keystore2/src/database.rs
@@ -53,7 +53,9 @@ use crate::impl_metadata; // This is in database/utils.rs
 use crate::key_parameter::{KeyParameter, KeyParameterValue, Tag};
 use crate::ks_err;
 use crate::permission::KeyPermSet;
-use crate::utils::{get_current_time_in_milliseconds, watchdog as wd, AID_USER_OFFSET};
+use crate::utils::{
+    get_current_time_in_milliseconds, watchdog as wd, Challenge, SecureUserId, AID_USER_OFFSET,
+};
 use crate::{
     error::{Error as KsError, ErrorCode, ResponseCode},
     super_key::SuperKeyType,
@@ -69,15 +71,11 @@ use android_system_keystore2::aidl::android::system::keystore2::{
     Domain::Domain, KeyDescriptor::KeyDescriptor,
 };
 use anyhow::{anyhow, Context, Result};
-use keystore2_flags;
-use std::{convert::TryFrom, convert::TryInto, ops::Deref, sync::LazyLock, time::SystemTimeError};
-use utils as db_utils;
-use utils::SqlField;
-
 use keystore2_crypto::ZVec;
-use log::error;
+use keystore2_flags;
+use log::{error, info};
 #[cfg(not(test))]
-use rand::prelude::random;
+use rand::random;
 use rusqlite::{
     params, params_from_iter,
     types::FromSql,
@@ -86,13 +84,15 @@ use rusqlite::{
     types::{FromSqlError, Value, ValueRef},
     Connection, OptionalExtension, ToSql, Transaction,
 };
-
 use std::{
     collections::{HashMap, HashSet},
     path::Path,
     sync::{Arc, Condvar, Mutex},
     time::{Duration, SystemTime},
 };
+use std::{convert::TryFrom, convert::TryInto, ops::Deref, sync::LazyLock, time::SystemTimeError};
+use utils as db_utils;
+use utils::SqlField;
 
 use TransactionBehavior::Immediate;
 
@@ -870,9 +870,13 @@ impl AuthTokenEntry {
     }
 
     /// Checks if this auth token satisfies the given authentication information.
-    pub fn satisfies(&self, user_secure_ids: &[i64], auth_type: HardwareAuthenticatorType) -> bool {
-        user_secure_ids.iter().any(|&sid| {
-            (sid == self.auth_token.userId || sid == self.auth_token.authenticatorId)
+    pub fn satisfies(
+        &self,
+        user_sids: &[SecureUserId],
+        auth_type: HardwareAuthenticatorType,
+    ) -> bool {
+        user_sids.iter().any(|&sid| {
+            (sid.0 == self.auth_token.userId || sid.0 == self.auth_token.authenticatorId)
                 && ((auth_type.0 & self.auth_token.authenticatorType.0) != 0)
         })
     }
@@ -893,8 +897,8 @@ impl AuthTokenEntry {
     }
 
     /// Returns the challenge value of the auth token.
-    pub fn challenge(&self) -> i64 {
-        self.auth_token.challenge
+    pub fn challenge(&self) -> Challenge {
+        Challenge(self.auth_token.challenge)
     }
 }
 
@@ -988,7 +992,7 @@ impl KeystoreDB {
             .context("Trying to prepare query to mark superseded keyblobs")?;
         stmt.execute(params![BlobState::Superseded, sc_key_blob, sc_key_blob])
             .context(ks_err!("Failed to set state=superseded state for keyblobs"))?;
-        log::info!("marked non-current blobentry rows for keyblobs as superseded");
+        info!("marked non-current blobentry rows for keyblobs as superseded");
 
         // Mark keyblobs that don't have a corresponding key.
         // This may take a while if there are excessive numbers of keys in the database.
@@ -1003,7 +1007,7 @@ impl KeystoreDB {
             .context("Trying to prepare query to mark orphaned keyblobs")?;
         stmt.execute(params![BlobState::Orphaned, sc_key_blob])
             .context(ks_err!("Failed to set state=orphaned for keyblobs"))?;
-        log::info!("marked orphaned blobentry rows for keyblobs");
+        info!("marked orphaned blobentry rows for keyblobs");
 
         // Add an index to make it fast to find out of date blobentry rows.
         let _wp = wd::watch("KeystoreDB::from_1_to_2 add blobentry index");
@@ -1290,6 +1294,40 @@ impl KeystoreDB {
         }
     }
 
+    /// Return the top `max_usize` uids by numbers of keys owned, together with their key
+    /// count. Only return uids that own more than `min_key_count` keys.
+    pub fn per_uid_counts(
+        &mut self,
+        max_uids: usize,
+        min_key_count: usize,
+    ) -> Result<Vec<(i32, usize)>> {
+        self.with_transaction(Immediate("TX_per_uid_counts"), |tx| {
+            let mut stmt = tx
+                .prepare(
+                    "SELECT namespace, COUNT(*) FROM persistent.keyentry
+                         WHERE domain = ?
+                         GROUP BY namespace
+                         ORDER BY COUNT(*) DESC
+                         LIMIT ?;",
+                )
+                .context(ks_err!("KeystoreDB::per_uid_counts: failed to prepare statement"))?;
+            let mut rows = stmt
+                .query(params![Domain::APP.0, max_uids])
+                .context(ks_err!("KeystoreDB::per_uid_counts: query failed"))?;
+            let mut results = Vec::new();
+            db_utils::with_rows_extract_all(&mut rows, |row| {
+                let uid: i32 = row.get(0).context("Failed to read namespace column")?;
+                let count: usize = row.get(1).context("Failed to read count")?;
+                if count > min_key_count {
+                    results.push((uid, count));
+                }
+                Ok(())
+            })?;
+            Ok(results).no_gc()
+        })
+        .context("KeystoreDB::per_uid_counts")
+    }
+
     /// This function is intended to be used by the garbage collector.
     /// It deletes the blobs given by `blob_ids_to_delete`. It then tries to find up to `max_blobs`
     /// superseded key blobs that might need special handling by the garbage collector.
@@ -1316,56 +1354,25 @@ impl KeystoreDB {
             Self::cleanup_unreferenced(tx).context("Trying to cleanup unreferenced.")?;
 
             // Find up to `max_blobs` more out-of-date key blobs, load their metadata and return it.
-            let result: Vec<(i64, Vec<u8>)> = if keystore2_flags::use_blob_state_column() {
-                let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob find_next v2");
-                let mut stmt = tx
-                    .prepare(
-                        "SELECT id, blob FROM persistent.blobentry
+            let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob find_next v2");
+            let mut stmt = tx
+                .prepare(
+                    "SELECT id, blob FROM persistent.blobentry
                         WHERE subcomponent_type = ? AND state != ?
                         LIMIT ?;",
-                    )
-                    .context("Trying to prepare query for superseded blobs.")?;
-
-                let rows = stmt
-                    .query_map(
-                        params![SubComponentType::KEY_BLOB, BlobState::Current, max_blobs as i64],
-                        |row| Ok((row.get(0)?, row.get(1)?)),
-                    )
-                    .context("Trying to query superseded blob.")?;
+                )
+                .context("Trying to prepare query for superseded blobs.")?;
 
-                rows.collect::<Result<Vec<(i64, Vec<u8>)>, rusqlite::Error>>()
-                    .context("Trying to extract superseded blobs.")?
-            } else {
-                let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob find_next v1");
-                let mut stmt = tx
-                    .prepare(
-                        "SELECT id, blob FROM persistent.blobentry
-                        WHERE subcomponent_type = ?
-                        AND (
-                            id NOT IN (
-                                SELECT MAX(id) FROM persistent.blobentry
-                                WHERE subcomponent_type = ?
-                                GROUP BY keyentryid, subcomponent_type
-                            )
-                        OR keyentryid NOT IN (SELECT id FROM persistent.keyentry)
-                    ) LIMIT ?;",
-                    )
-                    .context("Trying to prepare query for superseded blobs.")?;
-
-                let rows = stmt
-                    .query_map(
-                        params![
-                            SubComponentType::KEY_BLOB,
-                            SubComponentType::KEY_BLOB,
-                            max_blobs as i64,
-                        ],
-                        |row| Ok((row.get(0)?, row.get(1)?)),
-                    )
-                    .context("Trying to query superseded blob.")?;
+            let rows = stmt
+                .query_map(
+                    params![SubComponentType::KEY_BLOB, BlobState::Current, max_blobs as i64],
+                    |row| Ok((row.get(0)?, row.get(1)?)),
+                )
+                .context("Trying to query superseded blob.")?;
 
-                rows.collect::<Result<Vec<(i64, Vec<u8>)>, rusqlite::Error>>()
-                    .context("Trying to extract superseded blobs.")?
-            };
+            let result: Vec<(i64, Vec<u8>)> = rows
+                .collect::<Result<Vec<(i64, Vec<u8>)>, rusqlite::Error>>()
+                .context("Trying to extract superseded blobs.")?;
 
             let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob load_metadata");
             let result = result
@@ -1385,30 +1392,13 @@ impl KeystoreDB {
 
             // We did not find any out-of-date key blobs, so let's remove other types of superseded
             // blob in one transaction.
-            if keystore2_flags::use_blob_state_column() {
-                let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob delete v2");
-                tx.execute(
-                    "DELETE FROM persistent.blobentry
+            let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob delete v2");
+            tx.execute(
+                "DELETE FROM persistent.blobentry
                     WHERE subcomponent_type != ? AND state != ?;",
-                    params![SubComponentType::KEY_BLOB, BlobState::Current],
-                )
-                .context("Trying to purge out-of-date blobs (other than keyblobs)")?;
-            } else {
-                let _wp = wd::watch("KeystoreDB::handle_next_superseded_blob delete v1");
-                tx.execute(
-                    "DELETE FROM persistent.blobentry
-                    WHERE NOT subcomponent_type = ?
-                    AND (
-                        id NOT IN (
-                           SELECT MAX(id) FROM persistent.blobentry
-                           WHERE NOT subcomponent_type = ?
-                           GROUP BY keyentryid, subcomponent_type
-                        ) OR keyentryid NOT IN (SELECT id FROM persistent.keyentry)
-                    );",
-                    params![SubComponentType::KEY_BLOB, SubComponentType::KEY_BLOB],
-                )
-                .context("Trying to purge superseded blobs.")?;
-            }
+                params![SubComponentType::KEY_BLOB, BlobState::Current],
+            )
+            .context("Trying to purge out-of-date blobs (other than keyblobs)")?;
 
             Ok(vec![]).no_gc()
         })
@@ -1417,15 +1407,40 @@ impl KeystoreDB {
 
     /// This maintenance function should be called only once before the database is used for the
     /// first time. It restores the invariant that `KeyLifeCycle::Existing` is a transient state.
+    ///
     /// The function transitions all key entries from Existing to Unreferenced unconditionally and
     /// returns the number of rows affected. If this returns a value greater than 0, it means that
     /// Keystore crashed at some point during key generation. Callers may want to log such
     /// occurrences.
-    /// Unlike with `mark_unreferenced`, we don't need to purge grants, because only keys that made
+    ///
+    /// Unlike with `remove_key_rows`, we don't need to purge grants, because only keys that made
     /// it to `KeyLifeCycle::Live` may have grants.
+    ///
+    /// The function also marks any `blobentry` rows that don't have an owning `keyentry` row as
+    /// orphaned.
     pub fn cleanup_leftovers(&mut self) -> Result<usize> {
         let _wp = wd::watch("KeystoreDB::cleanup_leftovers");
 
+        if keystore2_flags::remove_rebound_keyblobs_fix() {
+            self.with_transaction(Immediate("TX_cleanup_leftovers_mark_orphans"), |tx| {
+                // Mark as orphaned any blobentry rows that have no associated keyentry row.
+                // Apply a per-reboot limit to avoid the possibility of delayed startup.
+                tx.execute(
+                    "UPDATE persistent.blobentry SET state = ?
+                    WHERE id IN (
+                      SELECT id FROM persistent.blobentry
+                      WHERE keyentryid NOT IN (
+                        SELECT id FROM persistent.keyentry
+                      )
+                      LIMIT 100000);",
+                    params![BlobState::Orphaned],
+                )
+                .context("Trying to mark orphaned blobs")
+                .need_gc()
+            })
+            .context(ks_err!())?;
+        }
+
         self.with_transaction(Immediate("TX_cleanup_leftovers"), |tx| {
             tx.execute(
                 "UPDATE persistent.keyentry SET state = ? WHERE state = ?;",
@@ -1790,6 +1805,9 @@ impl KeystoreDB {
                     .context(ks_err!("Domain {:?} must be either App or SELinux.", domain));
             }
         }
+        // Mark any existing key for the alias/domain/namespace/key_type as `Unreferenced` (and wipe
+        // its alias/domain/namespace info) so it can be removed in a subsequent GC pass (in
+        // `cleanup_unreferenced()`).
         let updated = tx
             .execute(
                 "UPDATE persistent.keyentry
@@ -1798,6 +1816,7 @@ impl KeystoreDB {
                 params![KeyLifeCycle::Unreferenced, alias, domain.0 as u32, namespace, key_type],
             )
             .context(ks_err!("Failed to rebind existing entry."))?;
+        // Bind the new key ID to the alias and make it `Live`.
         let result = tx
             .execute(
                 "UPDATE persistent.keyentry
@@ -2292,7 +2311,7 @@ impl KeystoreDB {
             .context("Failed to update key usage count.")?;
 
             match limit {
-                1 => Self::mark_unreferenced(tx, key_id)
+                1 => Self::remove_key_rows(tx, key_id)
                     .map(|need_gc| (need_gc, ()))
                     .context("Trying to mark limited use key for deletion."),
                 0 => Err(KsError::Km(ErrorCode::INVALID_KEY_BLOB)).context("Key is exhausted."),
@@ -2420,7 +2439,11 @@ impl KeystoreDB {
         Ok((key_id_guard, key_entry))
     }
 
-    fn mark_unreferenced(tx: &Transaction, key_id: i64) -> Result<bool> {
+    /// Remove database table rows associated with the given `key_id`. The one exception
+    /// is that `blobentry` rows are not immediately deleted, but are instead marked as
+    /// orphaned so they can be removed in a later GC operation (which also involves
+    /// notifying the owning KeyMint of keyblob deletion).
+    fn remove_key_rows(tx: &Transaction, key_id: i64) -> Result<bool> {
         let updated = tx
             .execute("DELETE FROM persistent.keyentry WHERE id = ?;", params![key_id])
             .context("Trying to delete keyentry.")?;
@@ -2440,7 +2463,7 @@ impl KeystoreDB {
             "UPDATE persistent.blobentry SET state = ? WHERE keyentryid = ?",
             params![BlobState::Orphaned, key_id],
         )
-        .context("Trying to mark blobentrys as superseded")?;
+        .context("Trying to mark blobentrys as orphaned")?;
         Ok(updated != 0)
     }
 
@@ -2477,9 +2500,9 @@ impl KeystoreDB {
             check_permission(&access.descriptor, access.vector)
                 .context("While checking permission.")?;
 
-            Self::mark_unreferenced(tx, access.key_id)
+            Self::remove_key_rows(tx, access.key_id)
                 .map(|need_gc| (need_gc, ()))
-                .context("Trying to mark the key unreferenced.")
+                .context("Trying to remove key DB rows")
         })
         .context(ks_err!())
     }
@@ -2582,6 +2605,22 @@ impl KeystoreDB {
                 params![KeyLifeCycle::Unreferenced],
             )
             .context("Trying to delete grants.")?;
+
+            if keystore2_flags::remove_rebound_keyblobs_fix() {
+                // Mark as orphaned any blobentry rows that are associated with keyentry rows that
+                // are about to be deleted.  The orphaned rows will be removed in a later GC
+                // operation (which also involves notifying the owning KeyMint of keyblob deletion).
+                tx.execute(
+                    "UPDATE persistent.blobentry SET state=?
+                    WHERE keyentryid IN (
+                      SELECT id FROM persistent.keyentry
+                      WHERE state = ?
+                    );",
+                    params![BlobState::Orphaned, KeyLifeCycle::Unreferenced],
+                )
+                .context("Trying to mark to-be-orphaned blobs")?;
+            }
+
             tx.execute(
                 "DELETE FROM persistent.keyentry
                 WHERE state = ?;",
@@ -2647,8 +2686,8 @@ impl KeystoreDB {
 
             let mut notify_gc = false;
             for key_id in key_ids {
-                notify_gc = Self::mark_unreferenced(tx, key_id)
-                    .context("In unbind_keys_for_user. Failed to mark key id as unreferenced.")?
+                notify_gc = Self::remove_key_rows(tx, key_id)
+                    .context("In unbind_keys_for_user. Failed to remove key rows.")?
                     || notify_gc;
             }
             Ok(()).do_gc(notify_gc)
@@ -2708,13 +2747,13 @@ impl KeystoreDB {
                     matches!(kp.key_parameter_value(), KeyParameterValue::UserSecureID(_))
                 });
                 if is_auth_bound_key {
-                    notify_gc = Self::mark_unreferenced(tx, key_id)
+                    notify_gc = Self::remove_key_rows(tx, key_id)
                         .context("In unbind_auth_bound_keys_for_user.")?
                         || notify_gc;
                     num_unbound += 1;
                 }
             }
-            log::info!("Deleting {num_unbound} auth-bound keys for user {user_id}");
+            info!("Deleting {num_unbound} auth-bound keys for user {user_id}");
             Ok(()).do_gc(notify_gc)
         })
         .context(ks_err!())
@@ -3012,7 +3051,7 @@ impl KeystoreDB {
     pub fn get_app_uids_affected_by_sid(
         &mut self,
         user_id: i32,
-        secure_user_id: i64,
+        sid: SecureUserId,
     ) -> Result<Vec<i64>> {
         let _wp = wd::watch("KeystoreDB::get_app_uids_affected_by_sid");
 
@@ -3058,7 +3097,7 @@ impl KeystoreDB {
                     let is_key_bound_to_sid = params.iter().any(|kp| {
                         matches!(
                             kp.key_parameter_value(),
-                            KeyParameterValue::UserSecureID(sid) if *sid == secure_user_id
+                            KeyParameterValue::UserSecureID(s) if *s == sid.0
                         )
                     });
                     Ok(is_key_bound_to_sid).no_gc()
diff --git a/keystore2/src/database/perboot.rs b/keystore2/src/database/perboot.rs
index a1890a66..5e9ea1d4 100644
--- a/keystore2/src/database/perboot.rs
+++ b/keystore2/src/database/perboot.rs
@@ -16,6 +16,7 @@
 //! for the main Keystore 2.0 database module.
 
 use super::AuthTokenEntry;
+use crate::utils::SecureUserId;
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     HardwareAuthToken::HardwareAuthToken, HardwareAuthenticatorType::HardwareAuthenticatorType,
 };
@@ -26,16 +27,16 @@ use std::sync::RwLock;
 
 #[derive(PartialEq, PartialOrd, Ord, Eq, Hash)]
 struct AuthTokenId {
-    user_id: i64,
-    auth_id: i64,
+    user_id: SecureUserId,
+    auth_id: SecureUserId,
     authenticator_type: HardwareAuthenticatorType,
 }
 
 impl AuthTokenId {
     fn from_auth_token(tok: &HardwareAuthToken) -> Self {
         AuthTokenId {
-            user_id: tok.userId,
-            auth_id: tok.authenticatorId,
+            user_id: SecureUserId(tok.userId),
+            auth_id: SecureUserId(tok.authenticatorId),
             authenticator_type: tok.authenticatorType,
         }
     }
diff --git a/keystore2/src/database/tests.rs b/keystore2/src/database/tests.rs
index fdcf2544..2c4f18fe 100644
--- a/keystore2/src/database/tests.rs
+++ b/keystore2/src/database/tests.rs
@@ -15,14 +15,14 @@
 //! Database tests.
 
 use super::*;
+use super::utils as db_utils;
 use crate::key_parameter::{
     Algorithm, BlockMode, Digest, EcCurve, HardwareAuthenticatorType, KeyOrigin, KeyParameter,
     KeyParameterValue, KeyPurpose, PaddingMode, SecurityLevel,
 };
 use crate::key_perm_set;
 use crate::permission::{KeyPerm, KeyPermSet};
-use crate::super_key::{SuperKeyManager, USER_AFTER_FIRST_UNLOCK_SUPER_KEY, SuperEncryptionAlgorithm, SuperKeyType};
-use keystore2_test_utils::TempDir;
+use crate::super_key::{SuperKeyManager, CREDENTIAL_ENCRYPTED_SUPER_KEY, SuperEncryptionAlgorithm, SuperKeyType};
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     HardwareAuthToken::HardwareAuthToken,
     HardwareAuthenticatorType::HardwareAuthenticatorType as kmhw_authenticator_type,
@@ -30,6 +30,8 @@ use android_hardware_security_keymint::aidl::android::hardware::security::keymin
 use android_hardware_security_secureclock::aidl::android::hardware::security::secureclock::{
     Timestamp::Timestamp,
 };
+use keystore2_test_utils::TempDir;
+use keystore2_flags;
 use std::cell::RefCell;
 use std::collections::BTreeMap;
 use std::fmt::Write;
@@ -41,6 +43,14 @@ use crate::utils::AesGcm;
 #[cfg(disabled)]
 use std::time::Instant;
 
+fn init_logging() {
+    android_logger::init_once(
+        android_logger::Config::default()
+            .with_tag("keystore2_test")
+            .with_max_level(log::LevelFilter::Debug),
+    );
+}
+
 pub fn new_test_db() -> Result<KeystoreDB> {
     new_test_db_at("file::memory:")
 }
@@ -1570,7 +1580,7 @@ fn get_keyentry(db: &KeystoreDB) -> Result<Vec<KeyEntryRow>> {
 }
 
 fn make_test_params(max_usage_count: Option<i32>) -> Vec<KeyParameter> {
-    make_test_params_with_sids(max_usage_count, &[42])
+    make_test_params_with_sids(max_usage_count, &[SecureUserId(42)])
 }
 
 // Note: The parameters and SecurityLevel associations are nonsensical. This
@@ -1578,7 +1588,7 @@ fn make_test_params(max_usage_count: Option<i32>) -> Vec<KeyParameter> {
 // database.
 fn make_test_params_with_sids(
     max_usage_count: Option<i32>,
-    user_secure_ids: &[i64],
+    user_sids: &[SecureUserId],
 ) -> Vec<KeyParameter> {
     let mut params = vec![
         KeyParameter::new(KeyParameterValue::Invalid, SecurityLevel::TRUSTED_ENVIRONMENT),
@@ -1788,9 +1798,9 @@ fn make_test_params_with_sids(
         ));
     }
 
-    for sid in user_secure_ids.iter() {
+    for sid in user_sids.iter() {
         params.push(KeyParameter::new(
-            KeyParameterValue::UserSecureID(*sid),
+            KeyParameterValue::UserSecureID(sid.0),
             SecurityLevel::STRONGBOX,
         ));
     }
@@ -1804,7 +1814,14 @@ pub fn make_test_key_entry(
     alias: &str,
     max_usage_count: Option<i32>,
 ) -> Result<KeyIdGuard> {
-    make_test_key_entry_with_sids(db, domain, namespace, alias, max_usage_count, &[42])
+    make_test_key_entry_with_sids(
+        db,
+        domain,
+        namespace,
+        alias,
+        max_usage_count,
+        &[SecureUserId(42)],
+    )
 }
 
 pub fn make_test_key_entry_with_sids(
@@ -1813,7 +1830,7 @@ pub fn make_test_key_entry_with_sids(
     namespace: i64,
     alias: &str,
     max_usage_count: Option<i32>,
-    sids: &[i64],
+    sids: &[SecureUserId],
 ) -> Result<KeyIdGuard> {
     let key_id = create_key_entry(db, &domain, &namespace, KeyType::Client, &KEYSTORE_UUID)?;
     let mut blob_metadata = BlobMetaData::new();
@@ -2204,7 +2221,7 @@ fn test_unbind_auth_bound_keys_for_user() -> Result<()> {
     let nspace: i64 = (user_id * AID_USER_OFFSET).into();
     let other_user_id = 2;
     let other_user_nspace: i64 = (other_user_id * AID_USER_OFFSET).into();
-    let super_key_type = &USER_AFTER_FIRST_UNLOCK_SUPER_KEY;
+    let super_key_type = &CREDENTIAL_ENCRYPTED_SUPER_KEY;
 
     // Create a superencryption key.
     let super_key = keystore2_crypto::generate_aes256_key()?;
@@ -2261,23 +2278,18 @@ fn test_store_super_key() -> Result<()> {
     let (encrypted_super_key, metadata) = SuperKeyManager::encrypt_with_password(&super_key, &pw)?;
     db.store_super_key(
         1,
-        &USER_AFTER_FIRST_UNLOCK_SUPER_KEY,
+        &CREDENTIAL_ENCRYPTED_SUPER_KEY,
         &encrypted_super_key,
         &metadata,
         &KeyMetaData::new(),
     )?;
 
     // Check if super key exists.
-    assert!(db.key_exists(
-        Domain::APP,
-        1,
-        USER_AFTER_FIRST_UNLOCK_SUPER_KEY.alias,
-        KeyType::Super
-    )?);
+    assert!(db.key_exists(Domain::APP, 1, CREDENTIAL_ENCRYPTED_SUPER_KEY.alias, KeyType::Super)?);
 
-    let (_, key_entry) = db.load_super_key(&USER_AFTER_FIRST_UNLOCK_SUPER_KEY, 1)?.unwrap();
+    let (_, key_entry) = db.load_super_key(&CREDENTIAL_ENCRYPTED_SUPER_KEY, 1)?.unwrap();
     let loaded_super_key = SuperKeyManager::extract_super_key_from_key_entry(
-        USER_AFTER_FIRST_UNLOCK_SUPER_KEY.algorithm,
+        CREDENTIAL_ENCRYPTED_SUPER_KEY.algorithm,
         key_entry,
         &pw,
         None,
@@ -2517,6 +2529,30 @@ fn find_auth_token_entry_returns_latest() -> Result<()> {
     Ok(())
 }
 
+/// Returns `Vec` of (key id, blob id, blob state)
+fn describe_blobs(db: &mut KeystoreDB, sc_type: SubComponentType) -> Vec<(i64, i64, BlobState)> {
+    db.with_transaction(TransactionBehavior::Deferred, |tx| {
+        let mut stmt = tx
+            .prepare(
+                "SELECT keyentryid, state, id FROM blobentry
+                            WHERE subcomponent_type = ? ORDER BY keyentryid, id;",
+            )
+            .unwrap();
+        let mut rows = stmt.query(params![sc_type]).unwrap();
+        let mut blobinfo = vec![];
+        db_utils::with_rows_extract_all(&mut rows, |row| {
+            let key_id: i64 = row.get(0).unwrap();
+            let state: BlobState = row.get(1).unwrap();
+            let blob_id: i64 = row.get(2).unwrap();
+            blobinfo.push((key_id, blob_id, state));
+            Ok(())
+        })
+        .unwrap();
+        Ok(blobinfo).no_gc()
+    })
+    .unwrap()
+}
+
 fn blob_count(db: &mut KeystoreDB, sc_type: SubComponentType) -> usize {
     db.with_transaction(TransactionBehavior::Deferred, |tx| {
         tx.query_row(
@@ -2547,79 +2583,182 @@ fn blob_count_in_state(db: &mut KeystoreDB, sc_type: SubComponentType, state: Bl
 
 #[test]
 fn test_blobentry_gc() -> Result<()> {
+    use BlobState::{Current, Orphaned, Superseded};
+
+    // Make parts of the test conditional on whether the fix for lost keyblobs from key rebind is
+    // present.
+    let fixed = keystore2_flags::remove_rebound_keyblobs_fix();
+
+    init_logging();
     let mut db = new_test_db()?;
-    let _key_id1 = make_test_key_entry(&mut db, Domain::APP, 1, "key1", None)?.0;
-    let key_guard2 = make_test_key_entry(&mut db, Domain::APP, 2, "key2", None)?;
-    let key_guard3 = make_test_key_entry(&mut db, Domain::APP, 3, "key3", None)?;
+
+    // Create 5 keys, and arrange things so the that the key IDs, aliases and namespace values
+    // (owning uids) all run 0..=4.  The corresponding 3 initial blobs for key N will have ids of:
+    // - KEY_BLOB:   1 + 3xN
+    // - CERT:       1 + 3xN + 1
+    // - CERT_CHAIN: 1 + 3xN + 2
+    let _key_id0 = make_test_key_entry(&mut db, Domain::APP, 0, "key0", None)?.0;
+    let key_guard1 = make_test_key_entry(&mut db, Domain::APP, 1, "key1", None)?;
+    let _key_id2 = make_test_key_entry(&mut db, Domain::APP, 2, "key2", None)?.0;
+    let key_id3 = make_test_key_entry(&mut db, Domain::APP, 3, "key3", None)?.0;
     let key_id4 = make_test_key_entry(&mut db, Domain::APP, 4, "key4", None)?.0;
-    let key_id5 = make_test_key_entry(&mut db, Domain::APP, 5, "key5", None)?.0;
+    let orig_blob_id = |keyid: i64| 1 + 3 * keyid;
+
+    assert_eq!(
+        describe_blobs(&mut db, SubComponentType::KEY_BLOB),
+        vec![
+            (0, orig_blob_id(0), Current),
+            (1, orig_blob_id(1), Current),
+            (2, orig_blob_id(2), Current),
+            (3, orig_blob_id(3), Current),
+            (4, orig_blob_id(4), Current)
+        ],
+        "After creating 5 keys"
+    );
+    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
+    assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));
+
+    // Replace the keyblob for key ID 1 by directly updating the blob entry, analogous to
+    // the key upgrade flow.  The previous blob will still exist, but be superseded.
+    log::info!("Replace key1's blob");
+    db.set_blob(&key_guard1, SubComponentType::KEY_BLOB, Some(&[1, 2, 3]), None)?;
 
-    assert_eq!(5, blob_count(&mut db, SubComponentType::KEY_BLOB));
-    assert_eq!(5, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Current));
-    assert_eq!(0, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Superseded));
-    assert_eq!(0, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Orphaned));
+    assert_eq!(
+        describe_blobs(&mut db, SubComponentType::KEY_BLOB),
+        vec![
+            (0, orig_blob_id(0), Current),
+            (1, orig_blob_id(1), Superseded),
+            (1, 16, Current),
+            (2, orig_blob_id(2), Current),
+            (3, orig_blob_id(3), Current),
+            (4, orig_blob_id(4), Current)
+        ],
+        "After replacing key1's blob"
+    );
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));
 
-    // Replace the keyblobs for keys 2 and 3.  The previous blobs will still exist.
-    db.set_blob(&key_guard2, SubComponentType::KEY_BLOB, Some(&[1, 2, 3]), None)?;
-    db.set_blob(&key_guard3, SubComponentType::KEY_BLOB, Some(&[1, 2, 3]), None)?;
+    // Replace the keyblob for "key2" by creating a new key (with a new ID) under the same alias,
+    // and note that the new "key2" has no CERT[_CHAIN]. The old key still exists.
+    log::info!("Rebind key2");
+    db.store_new_key(
+        &KeyDescriptor {
+            domain: super::Domain::APP,
+            nspace: 2,
+            alias: Some("key2".to_string()),
+            blob: None,
+        },
+        KeyType::Client,
+        &make_test_params_with_sids(None, &[]),
+        &BlobInfo::new(&[1, 2, 3], &BlobMetaData::new()),
+        &CertificateInfo::new(None, None),
+        &KeyMetaData::new(),
+        &KEYSTORE_UUID,
+    )?;
 
-    assert_eq!(7, blob_count(&mut db, SubComponentType::KEY_BLOB));
-    assert_eq!(5, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Current));
-    assert_eq!(2, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Superseded));
-    assert_eq!(0, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Orphaned));
+    assert_eq!(
+        describe_blobs(&mut db, SubComponentType::KEY_BLOB),
+        vec![
+            (0, orig_blob_id(0), Current),
+            (1, orig_blob_id(1), Superseded),
+            (1, 16, Current),
+            (2, orig_blob_id(2), Current), // original keyID for 'key2' alias
+            (3, orig_blob_id(3), Current),
+            (4, orig_blob_id(4), Current),
+            (5, 17, Current), // new keyID for existing 'key2' alias
+        ],
+        "After rebinding 'key2'"
+    );
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));
 
-    // Delete keys 4 and 5.  The keyblobs aren't removed yet.
+    // Delete keys 3 and 4.  The keyblobs aren't removed yet, but are marked as orphaned.
+    log::info!("Delete key3 and key4");
     db.with_transaction(Immediate("TX_delete_test_keys"), |tx| {
-        KeystoreDB::mark_unreferenced(tx, key_id4)?;
-        KeystoreDB::mark_unreferenced(tx, key_id5)?;
+        KeystoreDB::remove_key_rows(tx, key_id3)?;
+        KeystoreDB::remove_key_rows(tx, key_id4)?;
         Ok(()).no_gc()
     })
     .unwrap();
 
-    assert_eq!(7, blob_count(&mut db, SubComponentType::KEY_BLOB));
-    assert_eq!(3, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Current));
-    assert_eq!(2, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Superseded));
-    assert_eq!(2, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Orphaned));
+    assert_eq!(
+        describe_blobs(&mut db, SubComponentType::KEY_BLOB),
+        vec![
+            (0, orig_blob_id(0), Current),
+            (1, orig_blob_id(1), Superseded),
+            (1, 16, Current),
+            (2, orig_blob_id(2), Current),
+            (3, orig_blob_id(3), Orphaned),
+            (4, orig_blob_id(4), Orphaned),
+            (5, 17, Current),
+        ],
+        "After deleting key3 and key4"
+    );
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));
 
-    // First garbage collection should return all 4 blobentry rows that are no longer current for
-    // their key.
+    // First garbage collection should mark the original keyblob for key2 as orphaned, then return
+    // all 4 blobentry rows that are no longer current for their key.
+    log::info!("Perform GC([])");
     let superseded = db.handle_next_superseded_blobs(&[], 20).unwrap();
     let superseded_ids: Vec<i64> = superseded.iter().map(|v| v.blob_id).collect();
-    assert_eq!(4, superseded.len());
-    assert_eq!(7, blob_count(&mut db, SubComponentType::KEY_BLOB));
-    assert_eq!(3, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Current));
-    assert_eq!(2, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Superseded));
-    assert_eq!(2, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Orphaned));
+    let (want_superseded, want_key2_state) = if fixed {
+        (vec![orig_blob_id(1), orig_blob_id(2), orig_blob_id(3), orig_blob_id(4)], Orphaned)
+    } else {
+        // Prior behaviour leaves the rebound keyblob present and Current.
+        (vec![orig_blob_id(1), orig_blob_id(3), orig_blob_id(4)], Current)
+    };
+
+    assert_eq!(superseded_ids, want_superseded,);
+    assert_eq!(
+        describe_blobs(&mut db, SubComponentType::KEY_BLOB),
+        vec![
+            (0, orig_blob_id(0), Current),
+            (1, orig_blob_id(1), Superseded),
+            (1, 16, Current),
+            (2, orig_blob_id(2), want_key2_state),
+            (3, orig_blob_id(3), Orphaned),
+            (4, orig_blob_id(4), Orphaned),
+            (5, 17, Current),
+        ],
+        "After GC(&[])"
+    );
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT));
     assert_eq!(5, blob_count(&mut db, SubComponentType::CERT_CHAIN));
 
     // Feed the superseded blob IDs back in, to trigger removal of the old KEY_BLOB entries.  As no
     // new superseded KEY_BLOBs are found, the unreferenced CERT/CERT_CHAIN blobs are removed.
+    log::info!("Perform GC([keyblobs])");
     let superseded = db.handle_next_superseded_blobs(&superseded_ids, 20).unwrap();
     let superseded_ids: Vec<i64> = superseded.iter().map(|v| v.blob_id).collect();
     assert_eq!(0, superseded.len());
-    assert_eq!(3, blob_count(&mut db, SubComponentType::KEY_BLOB));
-    assert_eq!(3, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Current));
-    assert_eq!(0, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Superseded));
-    assert_eq!(0, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Orphaned));
-    assert_eq!(3, blob_count(&mut db, SubComponentType::CERT));
-    assert_eq!(3, blob_count(&mut db, SubComponentType::CERT_CHAIN));
+    let final_blobs = if fixed {
+        vec![(0, orig_blob_id(0), Current), (1, 16, Current), (5, 17, Current)]
+    } else {
+        vec![
+            (0, orig_blob_id(0), Current),
+            (1, 16, Current),
+            (2, orig_blob_id(2), Current), // orphaned/leaked
+            (5, 17, Current),
+        ]
+    };
+
+    assert_eq!(
+        describe_blobs(&mut db, SubComponentType::KEY_BLOB),
+        final_blobs,
+        "After GC({superseded_ids:?})"
+    );
+    // The CERT[_CHAIN] blobs for keys 2,3,4 are now gone.
+    let final_cert_count = if fixed { 2 } else { 3 };
+    assert_eq!(final_cert_count, blob_count(&mut db, SubComponentType::CERT));
+    assert_eq!(final_cert_count, blob_count(&mut db, SubComponentType::CERT_CHAIN));
 
     // Nothing left to garbage collect.
     let superseded = db.handle_next_superseded_blobs(&superseded_ids, 20).unwrap();
     assert_eq!(0, superseded.len());
-    assert_eq!(3, blob_count(&mut db, SubComponentType::KEY_BLOB));
-    assert_eq!(3, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Current));
-    assert_eq!(0, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Superseded));
-    assert_eq!(0, blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Orphaned));
-    assert_eq!(3, blob_count(&mut db, SubComponentType::CERT));
-    assert_eq!(3, blob_count(&mut db, SubComponentType::CERT_CHAIN));
+    assert_eq!(describe_blobs(&mut db, SubComponentType::KEY_BLOB), final_blobs, "After GC(&[])");
+    assert_eq!(final_cert_count, blob_count(&mut db, SubComponentType::CERT));
+    assert_eq!(final_cert_count, blob_count(&mut db, SubComponentType::CERT_CHAIN));
 
     Ok(())
 }
@@ -2639,8 +2778,8 @@ fn test_upgrade_1_to_2() -> Result<()> {
 
     // Delete keys 4 and 5.  The keyblobs aren't removed yet.
     db.with_transaction(Immediate("TX_delete_test_keys"), |tx| {
-        KeystoreDB::mark_unreferenced(tx, key_id4)?;
-        KeystoreDB::mark_unreferenced(tx, key_id5)?;
+        KeystoreDB::remove_key_rows(tx, key_id4)?;
+        KeystoreDB::remove_key_rows(tx, key_id5)?;
         Ok(()).no_gc()
     })
     .unwrap();
@@ -2693,8 +2832,8 @@ fn test_load_key_descriptor() -> Result<()> {
 fn test_get_list_app_uids_for_sid() -> Result<()> {
     let uid: i32 = 1;
     let uid_offset: i64 = (uid as i64) * (AID_USER_OFFSET as i64);
-    let first_sid = 667;
-    let second_sid = 669;
+    let first_sid = SecureUserId(667);
+    let second_sid = SecureUserId(669);
     let first_app_id: i64 = 123 + uid_offset;
     let second_app_id: i64 = 456 + uid_offset;
     let third_app_id: i64 = 789 + uid_offset;
@@ -2752,9 +2891,9 @@ fn test_get_list_app_uids_for_sid() -> Result<()> {
 fn test_get_list_app_uids_with_multiple_sids() -> Result<()> {
     let uid: i32 = 1;
     let uid_offset: i64 = (uid as i64) * (AID_USER_OFFSET as i64);
-    let first_sid = 667;
-    let second_sid = 669;
-    let third_sid = 772;
+    let first_sid = SecureUserId(667);
+    let second_sid = SecureUserId(669);
+    let third_sid = SecureUserId(772);
     let first_app_id: i64 = 123 + uid_offset;
     let second_app_id: i64 = 456 + uid_offset;
     let mut db = new_test_db()?;
@@ -2833,7 +2972,7 @@ fn db_populate_keys(db: &mut KeystoreDB, next_keyid: usize, key_count: usize) {
 /// database population.
 fn run_with_many_keys<F, T>(max_count: usize, test_fn: F) -> Result<()>
 where
-    F: Fn(&mut KeystoreDB) -> T,
+    F: Fn(&mut KeystoreDB, usize) -> T,
 {
     prep_and_run_with_many_keys(max_count, |_db| (), test_fn)
 }
@@ -2842,14 +2981,10 @@ where
 /// database population.
 fn prep_and_run_with_many_keys<F, T, P>(max_count: usize, prep_fn: P, test_fn: F) -> Result<()>
 where
-    F: Fn(&mut KeystoreDB) -> T,
+    F: Fn(&mut KeystoreDB, usize) -> T,
     P: Fn(&mut KeystoreDB),
 {
-    android_logger::init_once(
-        android_logger::Config::default()
-            .with_tag("keystore2_test")
-            .with_max_level(log::LevelFilter::Debug),
-    );
+    init_logging();
     // Put the test database on disk for a more realistic result.
     let db_root = tempfile::Builder::new().prefix("ks2db-test-").tempdir().unwrap();
     let mut db_path = db_root.path().to_owned();
@@ -2868,7 +3003,7 @@ where
 
         // Time execution of the test function.
         let start = std::time::Instant::now();
-        let _result = test_fn(&mut db);
+        let _result = test_fn(&mut db, key_count);
         println!("{key_count}, {}", start.elapsed().as_secs_f64());
 
         next_keyid = key_count;
@@ -2879,11 +3014,15 @@ where
 }
 
 fn db_key_count(db: &mut KeystoreDB) -> usize {
+    db_key_count_in_state(db, KeyLifeCycle::Live)
+}
+
+fn db_key_count_in_state(db: &mut KeystoreDB, state: KeyLifeCycle) -> usize {
     db.with_transaction(TransactionBehavior::Deferred, |tx| {
         tx.query_row(
             "SELECT COUNT(*) FROM persistent.keyentry
-                         WHERE domain = ? AND state = ? AND key_type = ?;",
-            params![Domain::APP.0 as u32, KeyLifeCycle::Live, KeyType::Client],
+                         WHERE state = ? AND key_type = ?;",
+            params![state, KeyType::Client],
             |row| row.get::<usize, usize>(0),
         )
         .context(ks_err!("Failed to count number of keys."))
@@ -2892,15 +3031,33 @@ fn db_key_count(db: &mut KeystoreDB) -> usize {
     .unwrap()
 }
 
+#[test]
+fn test_per_uid_counts() -> Result<()> {
+    run_with_many_keys(1_000_000, |db, key_count| {
+        // There is one uid with more than zero keys.
+        assert_eq!(db.per_uid_counts(0, 0).unwrap(), vec![]);
+        assert_eq!(db.per_uid_counts(1, 0).unwrap(), vec![(10001, key_count)]);
+        assert_eq!(db.per_uid_counts(10, 0).unwrap(), vec![(10001, key_count)]);
+
+        // There are no uids with > `key_count` keys.
+        assert_eq!(db.per_uid_counts(1, key_count).unwrap(), vec![]);
+        assert_eq!(db.per_uid_counts(10, key_count).unwrap(), vec![]);
+
+        // There is one uid with >= `key_count` keys.
+        assert_eq!(db.per_uid_counts(1, key_count - 1).unwrap(), vec![(10001, key_count)]);
+        assert_eq!(db.per_uid_counts(10, key_count - 1).unwrap(), vec![(10001, key_count)]);
+    })
+}
+
 #[test]
 fn test_handle_superseded_with_many_keys() -> Result<()> {
-    run_with_many_keys(1_000_000, |db| db.handle_next_superseded_blobs(&[], 20))
+    run_with_many_keys(1_000_000, |db, _| db.handle_next_superseded_blobs(&[], 20))
 }
 
 #[test]
 fn test_get_storage_stats_with_many_keys() -> Result<()> {
     use android_security_metrics::aidl::android::security::metrics::Storage::Storage as MetricsStorage;
-    run_with_many_keys(1_000_000, |db| {
+    run_with_many_keys(1_000_000, |db, _| {
         db.get_storage_stat(MetricsStorage::DATABASE).unwrap();
         db.get_storage_stat(MetricsStorage::KEY_ENTRY).unwrap();
         db.get_storage_stat(MetricsStorage::KEY_ENTRY_ID_INDEX).unwrap();
@@ -2920,7 +3077,7 @@ fn test_get_storage_stats_with_many_keys() -> Result<()> {
 
 #[test]
 fn test_list_keys_with_many_keys() -> Result<()> {
-    run_with_many_keys(1_000_000, |db: &mut KeystoreDB| -> Result<()> {
+    run_with_many_keys(1_000_000, |db: &mut KeystoreDB, _| -> Result<()> {
         // Behave equivalently to how clients list aliases.
         let domain = Domain::APP;
         let namespace = 10001;
@@ -2966,7 +3123,7 @@ fn test_upgrade_1_to_2_with_many_keys() -> Result<()> {
             })
             .unwrap();
         },
-        |db: &mut KeystoreDB| -> Result<()> {
+        |db: &mut KeystoreDB, _| -> Result<()> {
             // Run the upgrade process.
             db.with_transaction(Immediate("TX_upgrade_1_to_2"), |tx| {
                 KeystoreDB::from_1_to_2(tx).no_gc()
@@ -2975,3 +3132,82 @@ fn test_upgrade_1_to_2_with_many_keys() -> Result<()> {
         },
     )
 }
+#[test]
+fn test_many_rebind_same_alias() -> Result<()> {
+    init_logging();
+    let fixed = keystore2_flags::remove_rebound_keyblobs_fix();
+
+    // Put the test database on disk for a more realistic result.
+    let db_root = tempfile::Builder::new().prefix("ks2db-test-").tempdir().unwrap();
+    let mut db_path = db_root.path().to_owned();
+    db_path.push("ks2-test.sqlite");
+    let mut db = new_test_db_at(&db_path.to_string_lossy())?;
+
+    let descriptor = KeyDescriptor {
+        domain: super::Domain::APP,
+        nspace: 0, // uid
+        alias: Some("reused-alias".to_string()),
+        blob: None,
+    };
+    let params = make_test_params(None);
+    let blob_metadata = BlobMetaData::new();
+    let blob_info = BlobInfo::new(TEST_KEY_BLOB, &blob_metadata);
+    let cert_info = CertificateInfo::new(None, None);
+    let key_metadata = KeyMetaData::new();
+
+    let key_count = 500;
+    for _ in 0..key_count {
+        let _key_id = db.store_new_key(
+            &descriptor,
+            KeyType::Client,
+            &params,
+            &blob_info,
+            &cert_info,
+            &key_metadata,
+            &KEYSTORE_UUID,
+        )?;
+    }
+
+    // Nothing removed yet, but only one live key.
+    assert_eq!(db_key_count_in_state(&mut db, KeyLifeCycle::Live), 1);
+    assert_eq!(db_key_count_in_state(&mut db, KeyLifeCycle::Unreferenced), key_count - 1);
+    assert_eq!(
+        blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Current),
+        key_count
+    );
+    let mut orphan_blob_count = key_count - 1;
+
+    let mut superseded_ids = vec![];
+    while orphan_blob_count > 0 || !superseded_ids.is_empty() {
+        // Calling GC should...
+        println!("pass {} blob ids to handle_next_superseded_blobs", superseded_ids.len());
+        let superseded_blobs = db.handle_next_superseded_blobs(&superseded_ids, 20)?;
+
+        // ... remove all unreferenced `keyentry` rows
+        assert_eq!(db_key_count_in_state(&mut db, KeyLifeCycle::Live), 1);
+        assert_eq!(db_key_count_in_state(&mut db, KeyLifeCycle::Unreferenced), 0);
+
+        if !fixed {
+            // Prior behaviour incorrectly leaves orphaned keyblobs alone.
+            assert_eq!(superseded_blobs.len(), 0);
+            assert_eq!(
+                blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Current),
+                key_count
+            );
+            return Ok(());
+        }
+
+        // ... reduce the number of blobs in the table by the number of IDs passed in
+        orphan_blob_count -= superseded_ids.len();
+        assert_eq!(
+            blob_count_in_state(&mut db, SubComponentType::KEY_BLOB, BlobState::Orphaned),
+            orphan_blob_count
+        );
+        println!("now left with {orphan_blob_count} orphan blobs");
+
+        assert_eq!(superseded_blobs.len(), std::cmp::min(20, orphan_blob_count));
+        superseded_ids = superseded_blobs.into_iter().map(|sb| sb.blob_id).collect();
+    }
+
+    Ok(())
+}
diff --git a/keystore2/src/database/versioning.rs b/keystore2/src/database/versioning.rs
index a047cf36..48313c39 100644
--- a/keystore2/src/database/versioning.rs
+++ b/keystore2/src/database/versioning.rs
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 use anyhow::{anyhow, Context, Result};
+use log::info;
 use rusqlite::{params, OptionalExtension, Transaction};
 
 fn create_or_get_version(tx: &Transaction, current_version: u32) -> Result<u32> {
@@ -82,11 +83,11 @@ where
     let mut db_version = create_or_get_version(tx, current_version)
         .context("In upgrade_database: Failed to get database version.")?;
     while db_version < current_version {
-        log::info!("Current DB version={db_version}, perform upgrade");
+        info!("Current DB version={db_version}, perform upgrade");
         db_version = upgraders[db_version as usize](tx).with_context(|| {
             format!("In upgrade_database: Trying to upgrade from db version {}.", db_version)
         })?;
-        log::info!("DB upgrade successful, current DB version now={db_version}");
+        info!("DB upgrade successful, current DB version now={db_version}");
     }
     update_version(tx, db_version).context("In upgrade_database.")
 }
diff --git a/keystore2/src/enforcements.rs b/keystore2/src/enforcements.rs
index d086dd27..4b0f21b5 100644
--- a/keystore2/src/enforcements.rs
+++ b/keystore2/src/enforcements.rs
@@ -18,10 +18,12 @@ use crate::ks_err;
 use crate::error::{map_binder_status, Error, ErrorCode};
 use crate::globals::{get_timestamp_service, ASYNC_TASK, DB, ENFORCEMENTS};
 use crate::key_parameter::{KeyParameter, KeyParameterValue};
-use crate::{authorization::Error as AuthzError, super_key::SuperEncryptionType};
 use crate::{
+    authorization::Error as AuthzError, super_key::{SuperEncryptionType},
+    boot_level_keys::BootLevel,
     database::{AuthTokenEntry, BootTime},
     globals::SUPER_KEY,
+    utils::{Challenge, SecureUserId},
 };
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, ErrorCode::ErrorCode as Ec, HardwareAuthToken::HardwareAuthToken,
@@ -37,6 +39,7 @@ use android_system_keystore2::aidl::android::system::keystore2::{
     OperationChallenge::OperationChallenge,
 };
 use anyhow::{Context, Result};
+use log::{error, info};
 use std::{
     collections::{HashMap, HashSet},
     sync::{
@@ -151,7 +154,7 @@ struct TokenReceiverMap {
     /// counter (second field in the tuple) turns 0, the map is cleaned from stale entries.
     /// The cleanup counter is decremented every time a new receiver is added.
     /// and reset to TokenReceiverMap::CLEANUP_PERIOD + 1 after each cleanup.
-    map_and_cleanup_counter: Mutex<(HashMap<i64, TokenReceiver>, u8)>,
+    map_and_cleanup_counter: Mutex<(HashMap<Challenge, TokenReceiver>, u8)>,
 }
 
 impl Default for TokenReceiverMap {
@@ -173,7 +176,7 @@ impl TokenReceiverMap {
             // added.
             let mut map = self.map_and_cleanup_counter.lock().unwrap();
             let (ref mut map, _) = *map;
-            map.remove_entry(&hat.challenge)
+            map.remove_entry(&Challenge(hat.challenge))
         };
 
         if let Some((_, recv)) = recv {
@@ -181,7 +184,7 @@ impl TokenReceiverMap {
         }
     }
 
-    pub fn add_receiver(&self, challenge: i64, recv: TokenReceiver) {
+    pub fn add_receiver(&self, challenge: Challenge, recv: TokenReceiver) {
         let mut map = self.map_and_cleanup_counter.lock().unwrap();
         let (ref mut map, ref mut cleanup_counter) = *map;
         map.insert(challenge, recv);
@@ -210,20 +213,17 @@ impl TokenReceiver {
     }
 }
 
-fn get_timestamp_token(challenge: i64) -> Result<TimeStampToken, Error> {
+fn get_timestamp_token(challenge: Challenge) -> Result<TimeStampToken, Error> {
     let dev = get_timestamp_service().expect(concat!(
         "Secure Clock service must be present ",
         "if TimeStampTokens are required."
     ));
-    map_binder_status(dev.generateTimeStamp(challenge))
+    map_binder_status(dev.generateTimeStamp(challenge.0))
 }
 
-fn timestamp_token_request(challenge: i64, sender: Sender<Result<TimeStampToken, Error>>) {
+fn timestamp_token_request(challenge: Challenge, sender: Sender<Result<TimeStampToken, Error>>) {
     if let Err(e) = sender.send(get_timestamp_token(challenge)) {
-        log::info!(
-            concat!("Receiver hung up ", "before timestamp token could be delivered. {:?}"),
-            e
-        );
+        info!("Receiver hung up before timestamp token could be delivered. {e:?}");
     }
 }
 
@@ -231,7 +231,10 @@ impl AuthInfo {
     /// This function gets called after an operation was successfully created.
     /// It makes all the preparations required, so that the operation has all the authentication
     /// related artifacts to advance on update and finish.
-    pub fn finalize_create_authorization(&mut self, challenge: i64) -> Option<OperationChallenge> {
+    pub fn finalize_create_authorization(
+        &mut self,
+        challenge: Challenge,
+    ) -> Option<OperationChallenge> {
         match &self.state {
             DeferredAuthState::OpAuthRequired => {
                 let auth_request = AuthRequest::op_auth();
@@ -239,7 +242,7 @@ impl AuthInfo {
                 ENFORCEMENTS.register_op_auth_receiver(challenge, token_receiver);
 
                 self.state = DeferredAuthState::Waiting(auth_request);
-                Some(OperationChallenge { challenge })
+                Some(OperationChallenge { challenge: challenge.0 })
             }
             DeferredAuthState::TimeStampRequired(hat) => {
                 let hat = (*hat).clone();
@@ -276,10 +279,9 @@ impl AuthInfo {
                         Ok(t) => confirmation_token = Some(t),
                         Err(TryRecvError::Empty) => break,
                         Err(TryRecvError::Disconnected) => {
-                            log::error!(concat!(
-                                "We got disconnected from the APC service, ",
-                                "this should never happen."
-                            ));
+                            error!(
+                                "We got disconnected from the APC service, this should never happen."
+                            );
                             break;
                         }
                     }
@@ -449,12 +451,12 @@ impl Enforcements {
         let mut no_auth_required: bool = false;
         let mut caller_nonce_allowed = false;
         let mut user_id: i32 = -1;
-        let mut user_secure_ids = Vec::<i64>::new();
+        let mut user_sids = Vec::<SecureUserId>::new();
         let mut key_time_out: Option<i64> = None;
         let mut unlocked_device_required = false;
         let mut key_usage_limited: Option<i64> = None;
         let mut confirmation_token_receiver: Option<Arc<Mutex<Option<Receiver<Vec<u8>>>>>> = None;
-        let mut max_boot_level: Option<i32> = None;
+        let mut max_boot_level: Option<BootLevel> = None;
 
         // iterate through key parameters, recording information we need for authorization
         // enforcements later, or enforcing authorizations in place, where applicable
@@ -499,7 +501,7 @@ impl Enforcements {
                     }
                 }
                 KeyParameterValue::UserSecureID(s) => {
-                    user_secure_ids.push(*s);
+                    user_sids.push(SecureUserId(*s));
                 }
                 KeyParameterValue::UserID(u) => {
                     user_id = *u;
@@ -517,7 +519,7 @@ impl Enforcements {
                     confirmation_token_receiver = Some(self.confirmation_token_receiver.clone());
                 }
                 KeyParameterValue::MaxBootLevel(level) => {
-                    max_boot_level = Some(*level);
+                    max_boot_level = Some(BootLevel(*level as usize));
                 }
                 // NOTE: as per offline discussion, sanitizing key parameters and rejecting
                 // create operation if any non-allowed tags are present, is not done in
@@ -535,19 +537,17 @@ impl Enforcements {
         }
 
         // if both NO_AUTH_REQUIRED and USER_SECURE_ID tags are present, return error
-        if !user_secure_ids.is_empty() && no_auth_required {
+        if !user_sids.is_empty() && no_auth_required {
             return Err(Error::Km(Ec::INVALID_KEY_BLOB))
                 .context(ks_err!("key has both NO_AUTH_REQUIRED and USER_SECURE_ID tags."));
         }
 
         // if either of auth_type or secure_id is present and the other is not present, return error
-        if (user_auth_type.is_some() && user_secure_ids.is_empty())
-            || (user_auth_type.is_none() && !user_secure_ids.is_empty())
+        if (user_auth_type.is_some() && user_sids.is_empty())
+            || (user_auth_type.is_none() && !user_sids.is_empty())
         {
             return Err(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED)).context(ks_err!(
-                "Auth required, but auth type {:?} + sids {:?} inconsistently specified",
-                user_auth_type,
-                user_secure_ids,
+                "Auth required, but auth type {user_auth_type:?} + {user_sids:?} inconsistently specified"
             ));
         }
 
@@ -575,19 +575,16 @@ impl Enforcements {
             }
         }
 
-        let (hat, state) = if user_secure_ids.is_empty() {
+        let (hat, state) = if user_sids.is_empty() {
             (None, DeferredAuthState::NoAuthRequired)
         } else if let Some(key_time_out) = key_time_out {
             let hat = Self::find_auth_token(|hat: &AuthTokenEntry| match user_auth_type {
-                Some(auth_type) => hat.satisfies(&user_secure_ids, auth_type),
+                Some(auth_type) => hat.satisfies(&user_sids, auth_type),
                 None => false, // not reachable due to earlier check
             })
             .ok_or(Error::Km(Ec::KEY_USER_NOT_AUTHENTICATED))
             .context(ks_err!(
-                "No suitable auth token for sids {:?} type {:?} received in last {}s found.",
-                user_secure_ids,
-                user_auth_type,
-                key_time_out
+                "No suitable auth token for {user_sids:?} type {user_auth_type:?} received in last {key_time_out}s found",
             ))?;
             let now = BootTime::now();
             let token_age =
@@ -608,7 +605,7 @@ impl Enforcements {
                     hat.auth_token().authenticatorType.0,
                     hat.auth_token().timestamp.milliSeconds,
                     hat.time_received(),
-                    user_secure_ids,
+                    user_sids,
                     user_auth_type,
                     token_age.seconds(),
                     key_time_out
@@ -679,7 +676,7 @@ impl Enforcements {
     /// This is to be called by create_operation, once it has received the operation challenge
     /// from keymint for an operation whose authorization decision is OpAuthRequired, as signalled
     /// by the DeferredAuthState.
-    fn register_op_auth_receiver(&self, challenge: i64, recv: TokenReceiver) {
+    fn register_op_auth_receiver(&self, challenge: Challenge, recv: TokenReceiver) {
         self.op_auth_map.add_receiver(challenge, recv);
     }
 
@@ -702,14 +699,15 @@ impl Enforcements {
         let mut result = Candidate { priority: 0, enc_type: SuperEncryptionType::None };
         for kp in key_parameters {
             let t = match kp.key_parameter_value() {
-                KeyParameterValue::MaxBootLevel(level) => {
-                    Candidate { priority: 3, enc_type: SuperEncryptionType::BootLevel(*level) }
-                }
+                KeyParameterValue::MaxBootLevel(level) => Candidate {
+                    priority: 3,
+                    enc_type: SuperEncryptionType::BootLevel(BootLevel(*level as usize)),
+                },
                 KeyParameterValue::UnlockedDeviceRequired if *domain == Domain::APP => {
                     Candidate { priority: 2, enc_type: SuperEncryptionType::UnlockedDeviceRequired }
                 }
                 KeyParameterValue::UserSecureID(_) if *domain == Domain::APP => {
-                    Candidate { priority: 1, enc_type: SuperEncryptionType::AfterFirstUnlock }
+                    Candidate { priority: 1, enc_type: SuperEncryptionType::CredentialEncrypted }
                 }
                 _ => Candidate { priority: 0, enc_type: SuperEncryptionType::None },
             };
@@ -722,21 +720,21 @@ impl Enforcements {
 
     /// Finds a matching auth token along with a timestamp token.
     /// This method looks through auth-tokens cached by keystore which satisfy the given
-    /// authentication information (i.e. |secureUserId|).
-    /// The most recent matching auth token which has a |challenge| field which matches
-    /// the passed-in |challenge| parameter is returned.
-    /// In this case the |authTokenMaxAgeMillis| parameter is not used.
+    /// authentication information (i.e. `SecureUserId`).
+    /// The most recent matching auth token which has a `challenge` field which matches
+    /// the passed-in `challenge` parameter is returned.
+    /// In this case the `auth_token_max_age_millis` parameter is not used.
     ///
-    /// Otherwise, the most recent matching auth token which is younger than |authTokenMaxAgeMillis|
-    /// is returned.
+    /// Otherwise, the most recent matching auth token which is younger than
+    /// `auth_token_max_age_millis` is returned.
     pub fn get_auth_tokens(
         &self,
-        challenge: i64,
-        secure_user_id: i64,
+        challenge: Challenge,
+        sid: SecureUserId,
         auth_token_max_age_millis: i64,
     ) -> Result<(HardwareAuthToken, TimeStampToken)> {
         let auth_type = HardwareAuthenticatorType::ANY;
-        let sids: Vec<i64> = vec![secure_user_id];
+        let sids: Vec<SecureUserId> = vec![sid];
         // Filter the matching auth tokens by challenge
         let result = Self::find_auth_token(|hat: &AuthTokenEntry| {
             (challenge == hat.challenge()) && hat.satisfies(&sids, auth_type)
@@ -751,7 +749,7 @@ impl Enforcements {
                 let result = Self::find_auth_token(|auth_token_entry: &AuthTokenEntry| {
                     let token_valid = now_in_millis
                         .checked_sub(&auth_token_entry.time_received())
-                        .map_or(false, |token_age_in_millis| {
+                        .is_some_and(|token_age_in_millis| {
                             auth_token_max_age_millis > token_age_in_millis.milliseconds()
                         });
                     token_valid && auth_token_entry.satisfies(&sids, auth_type)
@@ -781,13 +779,11 @@ impl Enforcements {
     /// Finds the most recent received time for an auth token that matches the given secure user id and authenticator
     pub fn get_last_auth_time(
         &self,
-        secure_user_id: i64,
+        sid: SecureUserId,
         auth_type: HardwareAuthenticatorType,
     ) -> Option<BootTime> {
-        let sids: Vec<i64> = vec![secure_user_id];
-
         let result =
-            Self::find_auth_token(|entry: &AuthTokenEntry| entry.satisfies(&sids, auth_type));
+            Self::find_auth_token(|entry: &AuthTokenEntry| entry.satisfies(&[sid], auth_type));
 
         result.map(|auth_token_entry| auth_token_entry.time_received())
     }
diff --git a/keystore2/src/entropy.rs b/keystore2/src/entropy.rs
index 1dcdc86f..f6921e8a 100644
--- a/keystore2/src/entropy.rs
+++ b/keystore2/src/entropy.rs
@@ -55,12 +55,7 @@ pub fn feed_devices() {
     let data = match get_entropy(km_devs.len() * ENTROPY_SIZE) {
         Ok(data) => data,
         Err(e) => {
-            error!(
-                "Failed to retrieve {}*{} bytes of entropy: {:?}",
-                km_devs.len(),
-                ENTROPY_SIZE,
-                e
-            );
+            error!("Failed to retrieve {}*{ENTROPY_SIZE} bytes of entropy: {e:?}", km_devs.len());
             return;
         }
     };
@@ -68,7 +63,7 @@ pub fn feed_devices() {
         let offset = i * ENTROPY_SIZE;
         let sub_data = &data[offset..(offset + ENTROPY_SIZE)];
         if let Err(e) = km_dev.addRngEntropy(sub_data) {
-            error!("Failed to feed entropy to KeyMint device: {:?}", e);
+            error!("Failed to feed entropy to KeyMint device: {e:?}");
         }
     }
 }
diff --git a/keystore2/src/error.rs b/keystore2/src/error.rs
index d57ba0c1..476ba078 100644
--- a/keystore2/src/error.rs
+++ b/keystore2/src/error.rs
@@ -34,6 +34,7 @@ use android_system_keystore2::binder::{
     ExceptionCode, Result as BinderResult, Status as BinderStatus, StatusCode,
 };
 use keystore2_selinux as selinux;
+use log::{error, warn};
 use postprocessor_client::Error as PostProcessorError;
 use rkpd_client::Error as RkpdError;
 use std::cmp::PartialEq;
@@ -89,7 +90,7 @@ impl From<RkpdError> for Error {
                         ResponseCode::OUT_OF_KEYS_REQUIRES_SYSTEM_UPGRADE
                     }
                     _ => {
-                        log::error!("Unexpected get key error from rkpd: {e:?}");
+                        error!("Unexpected get key error from rkpd: {e:?}");
                         ResponseCode::OUT_OF_KEYS_TRANSIENT_ERROR
                     }
                 };
@@ -117,7 +118,7 @@ pub fn wrapped_rkpd_error_to_ks_error(e: &anyhow::Error) -> Error {
     match e.downcast_ref::<RkpdError>() {
         Some(e) => Error::from(*e),
         None => {
-            log::error!("Failed to downcast the anyhow::Error to rkpd_client::Error: {e:?}");
+            error!("Failed to downcast the anyhow::Error to rkpd_client::Error: {e:?}");
             Error::Rc(ResponseCode::SYSTEM_ERROR)
         }
     }
@@ -180,7 +181,7 @@ pub fn into_logged_binder(e: anyhow::Error) -> BinderStatus {
         e.root_cause().downcast_ref::<Error>(),
         Some(Error::Rc(ResponseCode::KEY_NOT_FOUND))
     ) {
-        log::error!("{:?}", e);
+        error!("{e:?}");
     }
     into_binder(e)
 }
@@ -193,7 +194,7 @@ pub fn anyhow_error_to_cstring(e: &anyhow::Error) -> Option<CString> {
     match CString::new(format!("{:?}", e)) {
         Ok(msg) => Some(msg),
         Err(_) => {
-            log::warn!("Cannot convert error message to CStr. It contained a nul byte.");
+            warn!("Cannot convert error message to CStr. It contained a nul byte.");
             None
         }
     }
diff --git a/keystore2/src/gc.rs b/keystore2/src/gc.rs
index 97416718..a172add9 100644
--- a/keystore2/src/gc.rs
+++ b/keystore2/src/gc.rs
@@ -27,6 +27,7 @@ use crate::{
 };
 use anyhow::{Context, Result};
 use async_task::AsyncTask;
+use log::error;
 use std::sync::{
     atomic::{AtomicU8, Ordering},
     Arc, RwLock,
@@ -148,7 +149,7 @@ impl GcInternal {
             return;
         }
         if let Err(e) = self.process_one_key() {
-            log::error!("Error trying to delete blob entry. {:?}", e);
+            error!("Error trying to delete blob entry: {e:?}");
         }
         // Schedule the next step. This gives high priority requests a chance to interleave.
         if !self.deleted_blob_ids.is_empty() {
diff --git a/keystore2/src/globals.rs b/keystore2/src/globals.rs
index 9ee2a1e6..28e3b7fb 100644
--- a/keystore2/src/globals.rs
+++ b/keystore2/src/globals.rs
@@ -46,6 +46,7 @@ use android_security_compat::aidl::android::security::compat::IKeystoreCompatSer
 use anyhow::{Context, Result};
 use binder::FromIBinder;
 use binder::{get_declared_instances, is_declared};
+use log::{error, info};
 use rustutils::system_properties::PropertyWatcher;
 use std::sync::{
     atomic::{AtomicBool, Ordering},
@@ -71,20 +72,18 @@ pub fn create_thread_local_db() -> KeystoreDB {
     let mut db = match result {
         Ok(db) => db,
         Err(e) => {
-            log::error!("Failed to open Keystore database at {db_path:?}: {e:?}");
-            log::error!("Has /data been mounted correctly?");
+            error!("Failed to open Keystore database at {db_path:?}: {e:?}");
+            error!("Has /data been mounted correctly?");
             panic!("Failed to open database for Keystore, cannot continue: {e:?}")
         }
     };
 
     DB_INIT.call_once(|| {
-        log::info!("Touching Keystore 2.0 database for this first time since boot.");
-        log::info!("Calling cleanup leftovers.");
+        info!("Touching Keystore 2.0 database for this first time since boot.");
+        info!("Calling cleanup leftovers.");
         let n = db.cleanup_leftovers().expect("Failed to cleanup database on startup");
         if n != 0 {
-            log::info!(
-                "Cleaned up {n} failed entries, indicating keystore crash on key generation"
-            );
+            info!("Cleaned up {n} failed entries, indicating keystore crash on key generation");
         }
     });
     db
@@ -236,13 +235,13 @@ fn connect_keymint(
         .context(ks_err!("Get service name from binder service"))?;
 
     let (keymint, hal_version) = if let Some(service_name) = service_name {
+        // Allow a few retries for retrieving the /default KeyMint instance, as it is needed at
+        // startup and may also be starting up.  (However, note that a slow-starting /default
+        // KeyMint will result in extended boot times.)
+        let retry_count = if *security_level == SecurityLevel::TRUSTED_ENVIRONMENT { 6 } else { 1 };
         let km: Strong<dyn IKeyMintDevice> =
-            if SecurityLevel::TRUSTED_ENVIRONMENT == *security_level {
-                map_binder_status_code(retry_get_interface(&service_name))
-            } else {
-                map_binder_status_code(binder::get_interface(&service_name))
-            }
-            .context(ks_err!("Trying to connect to genuine KeyMint service."))?;
+            map_binder_status_code(retry_get_interface(&service_name, retry_count))
+                .context(ks_err!("Trying to connect to genuine KeyMint service."))?;
         // Map the HAL version code for KeyMint to be <AIDL version> * 100, so
         // - V1 is 100
         // - V2 is 200
@@ -279,19 +278,15 @@ fn connect_keymint(
     let keymint = match hal_version {
         Some(400) | Some(300) | Some(200) => {
             // KeyMint v2+: use as-is (we don't have any software emulation of v3 or v4-specific KeyMint features).
-            log::info!(
-                "KeyMint device is current version ({:?}) for security level: {:?}",
-                hal_version,
-                security_level
+            info!(
+                "KeyMint device is current version ({hal_version:?}) for security level: {security_level:?}",
             );
             keymint
         }
         Some(100) => {
             // KeyMint v1: perform software emulation.
-            log::info!(
-                "Add emulation wrapper around {:?} device for security level: {:?}",
-                hal_version,
-                security_level
+            info!(
+                "Add emulation wrapper around {hal_version:?} device for security level: {security_level:?}",
             );
             BacklevelKeyMintWrapper::wrap(KeyMintV1::new(*security_level), keymint)
                 .context(ks_err!("Trying to create V1 compatibility wrapper."))?
@@ -300,18 +295,15 @@ fn connect_keymint(
             // Compatibility wrapper around a KeyMaster device: this roughly
             // behaves like KeyMint V1 (e.g. it includes AGREE_KEY support,
             // albeit in software.)
-            log::info!(
-                "Add emulation wrapper around Keymaster device for security level: {:?}",
-                security_level
+            info!(
+                "Add emulation wrapper around Keymaster device for security level: {security_level:?}",
             );
             BacklevelKeyMintWrapper::wrap(KeyMintV1::new(*security_level), keymint)
                 .context(ks_err!("Trying to create km_compat V1 compatibility wrapper ."))?
         }
         _ => {
             return Err(Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE)).context(ks_err!(
-                "unexpected hal_version {:?} for security level: {:?}",
-                hal_version,
-                security_level
+                "unexpected hal_version {hal_version:?} for {security_level:?}",
             ));
         }
     };
@@ -471,14 +463,14 @@ pub fn await_boot_completed() {
     // boots, which on a very slow device (e.g., emulator for a non-native architecture) can
     // take minutes. Blocking here would be unexpected only if it never finishes.
     let _wp = wd::watch_millis("await_boot_completed", 300_000);
-    log::info!("monitoring for sys.boot_completed=1");
+    info!("monitoring for sys.boot_completed=1");
     while let Err(e) = watch_for_boot_completed() {
-        log::error!("failed to watch for boot_completed: {e:?}");
+        error!("failed to watch for boot_completed: {e:?}");
         std::thread::sleep(std::time::Duration::from_secs(5));
     }
 
     BOOT_COMPLETED.store(true, Ordering::Release);
-    log::info!("wait_for_boot_completed done, triggering GC");
+    info!("wait_for_boot_completed done, triggering GC");
 
     // Garbage collection may have been skipped until now, so trigger a check.
     GC.notify_gc();
diff --git a/keystore2/src/keystore2_main.rs b/keystore2/src/keystore2_main.rs
index e08a5f28..4757bd9f 100644
--- a/keystore2/src/keystore2_main.rs
+++ b/keystore2/src/keystore2_main.rs
@@ -54,7 +54,7 @@ fn main() {
     );
     // Redirect panic messages to logcat.
     panic::set_hook(Box::new(|panic_info| {
-        error!("{}", panic_info);
+        error!("{panic_info}");
     }));
 
     // Saying hi.
@@ -64,9 +64,9 @@ fn main() {
     args.next().expect("That's odd. How is there not even a first argument?");
 
     // This must happen early before any other sqlite operations.
-    log::info!("Setting up sqlite logging for keystore2");
+    info!("Setting up sqlite logging for keystore2");
     fn sqlite_log_handler(err: c_int, message: &str) {
-        log::error!("[SQLITE3] {}: {}", err, message);
+        error!("[SQLITE3] {err}: {message}");
     }
     // SAFETY: There are no other threads yet, `sqlite_log_handler` is threadsafe, and it doesn't
     // invoke any SQLite calls.
diff --git a/keystore2/src/km_compat.rs b/keystore2/src/km_compat.rs
index 95e92943..305fcf5f 100644
--- a/keystore2/src/km_compat.rs
+++ b/keystore2/src/km_compat.rs
@@ -28,6 +28,7 @@ use android_hardware_security_keymint::aidl::android::hardware::security::keymin
     KeyParameterValue::KeyParameterValue, KeyPurpose::KeyPurpose, SecurityLevel::SecurityLevel,
     Tag::Tag,
 };
+use log::error;
 use android_security_compat::aidl::android::security::compat::IKeystoreCompatService::IKeystoreCompatService;
 use anyhow::Context;
 use keystore2_crypto::{hmac_sha256, HMAC_SHA256_LEN};
@@ -111,7 +112,7 @@ pub fn unwrap_keyblob(keyblob: &[u8]) -> KeyBlob {
     let got_tag = match hmac_sha256(KEYBLOB_HMAC_KEY, inner_keyblob) {
         Ok(tag) => tag,
         Err(e) => {
-            log::error!("Error calculating HMAC-SHA256 for keyblob unwrap: {:?}", e);
+            error!("Error calculating HMAC-SHA256 for keyblob unwrap: {e:?}");
             return KeyBlob::Raw(keyblob);
         }
     };
diff --git a/keystore2/src/km_compat/Android.bp b/keystore2/src/km_compat/Android.bp
index 36e18f0f..8c8a9076 100644
--- a/keystore2/src/km_compat/Android.bp
+++ b/keystore2/src/km_compat/Android.bp
@@ -58,7 +58,6 @@ cc_library {
     srcs: ["km_compat.cpp"],
     defaults: [
         "keymint_use_latest_hal_aidl_ndk_shared",
-        "keystore2_use_latest_aidl_ndk_shared",
     ],
     shared_libs: [
         "android.hardware.keymaster@3.0",
@@ -86,8 +85,6 @@ cc_library {
         "keymint_use_latest_hal_aidl_ndk_shared",
     ],
     shared_libs: [
-        "android.hardware.security.secureclock-V1-ndk",
-        "android.hardware.security.sharedsecret-V1-ndk",
         "android.security.compat-ndk",
         "libbinder_ndk",
         "libcrypto",
@@ -112,7 +109,6 @@ cc_test {
     ],
     defaults: [
         "keymint_use_latest_hal_aidl_ndk_shared",
-        "keystore2_use_latest_aidl_ndk_shared",
     ],
     shared_libs: [
         "android.hardware.keymaster@3.0",
diff --git a/keystore2/src/km_compat/km_compat.cpp b/keystore2/src/km_compat/km_compat.cpp
index 7a6ef4ae..70c72d4b 100644
--- a/keystore2/src/km_compat/km_compat.cpp
+++ b/keystore2/src/km_compat/km_compat.cpp
@@ -23,7 +23,6 @@
 #include <aidl/android/hardware/security/keymint/ErrorCode.h>
 #include <aidl/android/hardware/security/keymint/KeyParameterValue.h>
 #include <aidl/android/hardware/security/keymint/PaddingMode.h>
-#include <aidl/android/system/keystore2/ResponseCode.h>
 #include <android-base/logging.h>
 #include <android/hidl/manager/1.2/IServiceManager.h>
 #include <binder/IServiceManager.h>
@@ -42,7 +41,6 @@ using ::aidl::android::hardware::security::keymint::Digest;
 using ::aidl::android::hardware::security::keymint::KeyParameterValue;
 using ::aidl::android::hardware::security::keymint::PaddingMode;
 using ::aidl::android::hardware::security::keymint::Tag;
-using ::aidl::android::system::keystore2::ResponseCode;
 using ::android::hardware::hidl_vec;
 using ::android::hardware::keymaster::V4_0::TagType;
 using ::android::hidl::manager::V1_2::IServiceManager;
diff --git a/keystore2/src/legacy_blob.rs b/keystore2/src/legacy_blob.rs
index e05e6865..d0a99a98 100644
--- a/keystore2/src/legacy_blob.rs
+++ b/keystore2/src/legacy_blob.rs
@@ -26,6 +26,7 @@ use android_hardware_security_keymint::aidl::android::hardware::security::keymin
 };
 use anyhow::{Context, Result};
 use keystore2_crypto::{aes_gcm_decrypt, Password, ZVec};
+use log::{error, info, warn};
 use std::collections::{HashMap, HashSet};
 use std::sync::Arc;
 use std::{convert::TryInto, fs::File, path::Path, path::PathBuf};
@@ -823,7 +824,7 @@ impl LegacyBlobLoader {
         Ok(blob.and_then(|blob| match blob.value {
             BlobValue::Generic(blob) => Some(blob),
             _ => {
-                log::info!("Unexpected legacy keystore entry blob type. Ignoring");
+                info!("Unexpected legacy keystore entry blob type. Ignoring");
                 None
             }
         }))
@@ -919,7 +920,7 @@ impl LegacyBlobLoader {
     fn make_legacy_keystore_entry_filename(&self, uid: u32, alias: &str) -> Option<PathBuf> {
         // Legacy entries must not use known keystore prefixes.
         if Self::is_keystore_alias(alias) {
-            log::warn!(
+            warn!(
                 "Known keystore prefixes cannot be used with legacy keystore -> ignoring request."
             );
             return None;
@@ -973,7 +974,7 @@ impl LegacyBlobLoader {
         for entry in dir {
             if (*entry.context(ks_err!("Trying to access dir entry"))?.file_name())
                 .to_str()
-                .map_or(false, |f| f.starts_with("user_"))
+                .is_some_and(|f| f.starts_with("user_"))
             {
                 return Ok(false);
             }
@@ -1104,17 +1105,17 @@ impl LegacyBlobLoader {
                     // Only a subset of keys are expected.
                     ErrorKind::NotFound => continue,
                     // Log error but ignore.
-                    _ => log::error!("Error while deleting key blob entries. {:?}", e),
+                    _ => error!("Error while deleting key blob entries: {e:?}"),
                 }
             }
             let path = self.make_chr_filename(uid, alias, prefix);
             if let Err(e) = Self::with_retry_interrupted(|| fs::remove_file(path.as_path())) {
                 match e.kind() {
                     ErrorKind::NotFound => {
-                        log::info!("No characteristics file found for legacy key blob.")
+                        info!("No characteristics file found for legacy key blob.")
                     }
                     // Log error but ignore.
-                    _ => log::error!("Error while deleting key blob entries. {:?}", e),
+                    _ => error!("Error while deleting key blob entries: {e:?}"),
                 }
             }
             something_was_deleted = true;
@@ -1131,7 +1132,7 @@ impl LegacyBlobLoader {
                     // USRCERT and CACERT are optional either or both may or may not be present.
                     ErrorKind::NotFound => continue,
                     // Log error but ignore.
-                    _ => log::error!("Error while deleting key blob entries. {:?}", e),
+                    _ => error!("Error while deleting key blob entries: {e:?}"),
                 }
                 something_was_deleted = true;
             }
diff --git a/keystore2/src/legacy_importer.rs b/keystore2/src/legacy_importer.rs
index 0d8dc4a9..1418be46 100644
--- a/keystore2/src/legacy_importer.rs
+++ b/keystore2/src/legacy_importer.rs
@@ -22,7 +22,7 @@ use crate::error::{map_km_error, Error};
 use crate::key_parameter::{KeyParameter, KeyParameterValue};
 use crate::ks_err;
 use crate::legacy_blob::{self, Blob, BlobValue, LegacyKeyCharacteristics};
-use crate::super_key::USER_AFTER_FIRST_UNLOCK_SUPER_KEY;
+use crate::super_key::CREDENTIAL_ENCRYPTED_SUPER_KEY;
 use crate::utils::{
     key_characteristics_to_internal, uid_to_android_user, upgrade_keyblob_if_required_with,
     watchdog as wd, AesGcm,
@@ -35,6 +35,7 @@ use android_system_keystore2::aidl::android::system::keystore2::{
 use anyhow::{Context, Result};
 use core::ops::Deref;
 use keystore2_crypto::{Password, ZVec};
+use log::{error, info};
 use std::collections::{HashMap, HashSet};
 use std::sync::atomic::{AtomicU8, Ordering};
 use std::sync::mpsc::channel;
@@ -265,7 +266,7 @@ impl LegacyImporter {
 
             // Send the result to the requester.
             if let Err(e) = sender.send((new_state, result)) {
-                log::error!("In do_serialized. Error in sending the result. {:?}", e);
+                error!("In do_serialized. Error in sending the result: {e:?}");
             }
         });
 
@@ -450,7 +451,7 @@ impl LegacyImporterState {
 
         match self
             .db
-            .load_super_key(&USER_AFTER_FIRST_UNLOCK_SUPER_KEY, user_id)
+            .load_super_key(&CREDENTIAL_ENCRYPTED_SUPER_KEY, user_id)
             .context(ks_err!("Failed to load super key"))?
         {
             Some((_, entry)) => Ok(entry.id()),
@@ -729,7 +730,7 @@ impl LegacyImporterState {
             self.db
                 .store_super_key(
                     user_id,
-                    &USER_AFTER_FIRST_UNLOCK_SUPER_KEY,
+                    &CREDENTIAL_ENCRYPTED_SUPER_KEY,
                     &blob,
                     &blob_metadata,
                     &KeyMetaData::new(),
@@ -772,7 +773,7 @@ impl LegacyImporterState {
 
         let super_key_id = self
             .db
-            .load_super_key(&USER_AFTER_FIRST_UNLOCK_SUPER_KEY, user_id)
+            .load_super_key(&CREDENTIAL_ENCRYPTED_SUPER_KEY, user_id)
             .context(ks_err!("Failed to load super key"))?
             .map(|(_, entry)| entry.id());
 
@@ -807,7 +808,7 @@ impl LegacyImporterState {
                 continue;
             }
             if uid == rustutils::users::AID_SYSTEM && is_de_critical {
-                log::info!("skip deletion of system key '{alias}' which is DE-critical");
+                info!("skip deletion of system key '{alias}' which is DE-critical");
                 continue;
             }
 
diff --git a/keystore2/src/maintenance.rs b/keystore2/src/maintenance.rs
index a0f5ee8a..76690970 100644
--- a/keystore2/src/maintenance.rs
+++ b/keystore2/src/maintenance.rs
@@ -25,7 +25,7 @@ use crate::permission::{KeyPerm, KeystorePerm};
 use crate::super_key::SuperKeyManager;
 use crate::utils::{
     check_dump_permission, check_get_app_uids_affected_by_sid_permissions, check_key_permission,
-    check_keystore_permission, uid_to_android_user, watchdog as wd,
+    check_keystore_permission, uid_to_android_user, watchdog as wd, SecureUserId
 };
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     ErrorCode::ErrorCode, IKeyMintDevice::IKeyMintDevice, KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel, Tag::Tag,
@@ -51,6 +51,7 @@ use der::{DerOrd, Encode, asn1::OctetString, asn1::SetOfVec, Sequence};
 use keystore2_crypto::Password;
 use rustutils::system_properties::PropertyWatcher;
 use std::cmp::Ordering;
+use log::{error, info, warn};
 
 /// Reexport Domain for the benefit of DeleteListener
 pub use android_system_keystore2::aidl::android::system::keystore2::Domain::Domain;
@@ -186,7 +187,7 @@ impl Maintenance {
 
         if let Some(min_version) = min_version {
             if hw_info.versionNumber < min_version {
-                log::info!("skipping {name} for {sec_level:?} since its keymint version {} is less than the minimum required version {min_version}", hw_info.versionNumber);
+                info!("skipping {name} for {sec_level:?} since its keymint version {} is less than the minimum required version {min_version}", hw_info.versionNumber);
                 return Ok(());
             }
         }
@@ -211,25 +212,18 @@ impl Maintenance {
         sec_levels.iter().try_fold((), |_result, (sec_level, sec_level_string)| {
             let curr_result = Maintenance::call_with_watchdog(*sec_level, name, &op, min_version);
             match curr_result {
-                Ok(()) => log::info!(
-                    "Call to {} succeeded for security level {}.",
-                    name,
-                    &sec_level_string
-                ),
+                Ok(()) => {
+                    info!("Call to {name} succeeded for security level {sec_level_string}");
+                }
                 Err(ref e) => {
                     if *sec_level == SecurityLevel::STRONGBOX
                         && e.downcast_ref::<Error>()
                             == Some(&Error::Km(ErrorCode::HARDWARE_TYPE_UNAVAILABLE))
                     {
-                        log::info!("Call to {} failed for StrongBox as it is not available", name);
+                        info!("Call to {name} failed for StrongBox as it is not available");
                         return Ok(());
                     } else {
-                        log::error!(
-                            "Call to {} failed for security level {}: {}.",
-                            name,
-                            &sec_level_string,
-                            e
-                        )
+                        error!("Call to {name} failed for security level {sec_level_string}: {e}")
                     }
                 }
             }
@@ -240,12 +234,12 @@ impl Maintenance {
     fn early_boot_ended() -> Result<()> {
         check_keystore_permission(KeystorePerm::EarlyBootEnded)
             .context(ks_err!("Checking permission"))?;
-        log::info!("In early_boot_ended.");
+        info!("In early_boot_ended.");
 
         if let Err(e) =
             DB.with(|db| SuperKeyManager::set_up_boot_level_cache(&SUPER_KEY, &mut db.borrow_mut()))
         {
-            log::error!("SUPER_KEY.set_up_boot_level_cache failed:\n{:?}\n:(", e);
+            error!("SUPER_KEY.set_up_boot_level_cache failed: {e:?}");
         }
         Maintenance::call_on_all_security_levels("earlyBootEnded", |dev| dev.earlyBootEnded(), None)
     }
@@ -264,21 +258,21 @@ impl Maintenance {
         if rustutils::system_properties::read_bool("keystore.module_hash.sent", false)
             .unwrap_or(false)
         {
-            log::info!("Module info has already been sent.");
+            info!("Module info has already been sent.");
             return;
         }
         if keystore2_flags::attest_modules() {
             std::thread::spawn(move || {
                 // Wait for apex info to be available before populating.
                 Self::watch_apex_info().unwrap_or_else(|e| {
-                    log::error!("failed to monitor apexd.status property: {e:?}");
+                    error!("failed to monitor apexd.status property: {e:?}");
                     panic!("Terminating due to inaccessibility of apexd.status property, blocking boot: {e:?}");
                 });
             });
         } else {
             rustutils::system_properties::write("keystore.module_hash.sent", "true")
                 .unwrap_or_else(|e| {
-                        log::error!("Failed to set keystore.module_hash.sent to true; this will therefore block boot: {e:?}");
+                        error!("Failed to set keystore.module_hash.sent to true; this will therefore block boot: {e:?}");
                         panic!("Crashing Keystore because it failed to set keystore.module_hash.sent to true (which blocks boot).");
                     }
                 );
@@ -291,19 +285,19 @@ impl Maintenance {
     /// Blocks waiting for system property changes, so must be run in its own thread.
     fn watch_apex_info() -> Result<()> {
         let apex_prop = "apexd.status";
-        log::info!("start monitoring '{apex_prop}' property");
+        info!("start monitoring '{apex_prop}' property");
         let mut w =
             PropertyWatcher::new(apex_prop).context(ks_err!("PropertyWatcher::new failed"))?;
         loop {
             let value = w.read(|_name, value| Ok(value.to_string()));
-            log::info!("property '{apex_prop}' is now '{value:?}'");
+            info!("property '{apex_prop}' is now '{value:?}'");
             if matches!(value.as_deref(), Ok("activated")) {
                 Self::read_and_set_module_info();
                 return Ok(());
             }
-            log::info!("await a change to '{apex_prop}'...");
+            info!("await a change to '{apex_prop}'...");
             w.wait(None).context(ks_err!("property wait failed"))?;
-            log::info!("await a change to '{apex_prop}'...notified");
+            info!("await a change to '{apex_prop}'...notified");
         }
     }
 
@@ -319,15 +313,15 @@ impl Maintenance {
     /// - the `keystore.module_hash.sent` property cannot be updated
     fn read_and_set_module_info() {
         let modules = Self::read_apex_info().unwrap_or_else(|e| {
-            log::error!("failed to read apex info: {e:?}");
+            error!("failed to read apex info: {e:?}");
             panic!("Terminating due to unavailability of apex info, blocking boot: {e:?}");
         });
         Self::set_module_info(modules).unwrap_or_else(|e| {
-            log::error!("failed to set module info: {e:?}");
+            error!("failed to set module info: {e:?}");
             panic!("Terminating due to KeyMint not accepting module info, blocking boot: {e:?}");
         });
         rustutils::system_properties::write("keystore.module_hash.sent", "true").unwrap_or_else(|e| {
-            log::error!("failed to set keystore.module_hash.sent property: {e:?}");
+            error!("failed to set keystore.module_hash.sent property: {e:?}");
             panic!("Terminating due to failure to set keystore.module_hash.sent property, blocking boot: {e:?}");
         });
     }
@@ -340,7 +334,7 @@ impl Maintenance {
         packages
             .into_iter()
             .map(|pkg| {
-                log::info!("apex modules += {} version {}", pkg.moduleName, pkg.versionCode);
+                info!("apex modules += {} version {}", pkg.moduleName, pkg.versionCode);
                 let name = OctetString::new(pkg.moduleName.as_bytes()).map_err(|e| {
                     anyhow!("failed to convert '{}' to OCTET_STRING: {e:?}", pkg.moduleName)
                 })?;
@@ -370,7 +364,7 @@ impl Maintenance {
 
         let user_id = uid_to_android_user(calling_uid);
 
-        let super_key = SUPER_KEY.read().unwrap().get_after_first_unlock_key_by_user_id(user_id);
+        let super_key = SUPER_KEY.read().unwrap().get_credential_encrypted_key_by_user_id(user_id);
 
         DB.with(|db| {
             let (key_id_guard, _) = LEGACY_IMPORTER
@@ -400,21 +394,18 @@ impl Maintenance {
         // Security critical permission check. This statement must return on fail.
         check_keystore_permission(KeystorePerm::DeleteAllKeys)
             .context(ks_err!("Checking permission"))?;
-        log::info!("In delete_all_keys.");
+        info!("In delete_all_keys.");
 
         Maintenance::call_on_all_security_levels("deleteAllKeys", |dev| dev.deleteAllKeys(), None)
     }
 
-    fn get_app_uids_affected_by_sid(
-        user_id: i32,
-        secure_user_id: i64,
-    ) -> Result<std::vec::Vec<i64>> {
+    fn get_app_uids_affected_by_sid(user_id: i32, sid: SecureUserId) -> Result<std::vec::Vec<i64>> {
         // This method is intended to be called by Settings and discloses a list of apps
         // associated with a user, so it requires the "android.permission.MANAGE_USERS"
         // permission (to avoid leaking list of apps to unauthorized callers).
         check_get_app_uids_affected_by_sid_permissions().context(ks_err!())?;
-        DB.with(|db| db.borrow_mut().get_app_uids_affected_by_sid(user_id, secure_user_id))
-            .context(ks_err!("Failed to get app UIDs affected by SID"))
+        DB.with(|db| db.borrow_mut().get_app_uids_affected_by_sid(user_id, sid))
+            .context(ks_err!("Failed to get app UIDs affected by {sid:?}"))
     }
 
     fn dump_state(&self, f: &mut dyn std::io::Write) -> std::io::Result<()> {
@@ -449,6 +440,26 @@ impl Maintenance {
             }
         }
 
+        if keystore2_flags::count_keys_per_uid() {
+            // Display database top key counts per uid.
+            let max_uids = 10;
+            let min_count = 5;
+            writeln!(f, "Top-{max_uids} per-uid key counts (where > {min_count} keys):")?;
+            DB.with(|db| -> std::io::Result<()> {
+                let mut db = db.borrow_mut();
+                let counts = db.per_uid_counts(max_uids, min_count).unwrap_or_else(|e| {
+                    log::error!("failed to retrieve top {max_uids} per-uid counts: {e:?}");
+                    let _ = writeln!(f, "  DB retrieval failed: {e:?}");
+                    Vec::new()
+                });
+                for (uid, count) in counts {
+                    writeln!(f, "  uid={uid:<8}: key_count: {count}")?;
+                }
+                Ok(())
+            })?;
+            writeln!(f)?;
+        }
+
         // Display database size information.
         match crate::metrics_store::pull_storage_stats() {
             Ok(atoms) => {
@@ -487,7 +498,7 @@ impl Maintenance {
             let pragma_i32 = |f: &mut dyn std::io::Write, name| -> std::io::Result<()> {
                 let mut db = db.borrow_mut();
                 let value: i32 = db.pragma(name).unwrap_or_else(|e| {
-                    log::error!("unknown value for '{name}', failed: {e:?}");
+                    error!("unknown value for '{name}', failed: {e:?}");
                     -1
                 });
                 writeln!(f, "  {name} = {value}")
@@ -515,7 +526,7 @@ impl Maintenance {
     }
 
     fn set_module_info(module_info: Vec<ModuleInfo>) -> Result<()> {
-        log::info!("set_module_info with {} modules", module_info.len());
+        info!("set_module_info with {} modules", module_info.len());
         let encoding = Self::encode_module_info(module_info)
             .map_err(|e| anyhow!({ e }))
             .context(ks_err!("Failed to encode module_info"))?;
@@ -525,9 +536,7 @@ impl Maintenance {
             let mut saved = ENCODED_MODULE_INFO.write().unwrap();
             if let Some(saved_encoding) = &*saved {
                 if *saved_encoding == encoding {
-                    log::warn!(
-                        "Module info already set, ignoring repeated attempt to set same info."
-                    );
+                    warn!("Module info already set, ignoring repeated attempt to set same info.");
                     return Ok(());
                 }
                 return Err(Error::Rc(ResponseCode::INVALID_ARGUMENT)).context(ks_err!(
@@ -558,15 +567,15 @@ impl Interface for Maintenance {
         f: &mut dyn std::io::Write,
         _args: &[&std::ffi::CStr],
     ) -> Result<(), binder::StatusCode> {
-        log::info!("dump()");
+        info!("dump()");
         let _wp = wd::watch("IKeystoreMaintenance::dump");
         check_dump_permission().map_err(|_e| {
-            log::error!("dump permission denied");
+            error!("dump permission denied");
             binder::StatusCode::PERMISSION_DENIED
         })?;
 
         self.dump_state(f).map_err(|e| {
-            log::error!("dump_state failed: {e:?}");
+            error!("dump_state failed: {e:?}");
             binder::StatusCode::UNKNOWN_ERROR
         })
     }
@@ -574,7 +583,7 @@ impl Interface for Maintenance {
 
 impl IKeystoreMaintenance for Maintenance {
     fn onUserAdded(&self, user_id: i32) -> BinderResult<()> {
-        log::info!("onUserAdded(user={user_id})");
+        info!("onUserAdded(user={user_id})");
         let _wp = wd::watch("IKeystoreMaintenance::onUserAdded");
         self.add_or_remove_user(user_id).map_err(into_logged_binder)
     }
@@ -585,32 +594,32 @@ impl IKeystoreMaintenance for Maintenance {
         password: &[u8],
         allow_existing: bool,
     ) -> BinderResult<()> {
-        log::info!("initUserSuperKeys(user={user_id}, allow_existing={allow_existing})");
+        info!("initUserSuperKeys(user={user_id}, allow_existing={allow_existing})");
         let _wp = wd::watch("IKeystoreMaintenance::initUserSuperKeys");
         self.init_user_super_keys(user_id, password.into(), allow_existing)
             .map_err(into_logged_binder)
     }
 
     fn onUserRemoved(&self, user_id: i32) -> BinderResult<()> {
-        log::info!("onUserRemoved(user={user_id})");
+        info!("onUserRemoved(user={user_id})");
         let _wp = wd::watch("IKeystoreMaintenance::onUserRemoved");
         self.add_or_remove_user(user_id).map_err(into_logged_binder)
     }
 
     fn onUserLskfRemoved(&self, user_id: i32) -> BinderResult<()> {
-        log::info!("onUserLskfRemoved(user={user_id})");
+        info!("onUserLskfRemoved(user={user_id})");
         let _wp = wd::watch("IKeystoreMaintenance::onUserLskfRemoved");
         Self::on_user_lskf_removed(user_id).map_err(into_logged_binder)
     }
 
     fn clearNamespace(&self, domain: Domain, nspace: i64) -> BinderResult<()> {
-        log::info!("clearNamespace({domain:?}, nspace={nspace})");
+        info!("clearNamespace({domain:?}, nspace={nspace})");
         let _wp = wd::watch("IKeystoreMaintenance::clearNamespace");
         self.clear_namespace(domain, nspace).map_err(into_logged_binder)
     }
 
     fn earlyBootEnded(&self) -> BinderResult<()> {
-        log::info!("earlyBootEnded()");
+        info!("earlyBootEnded()");
         let _wp = wd::watch("IKeystoreMaintenance::earlyBootEnded");
         Self::early_boot_ended().map_err(into_logged_binder)
     }
@@ -620,13 +629,13 @@ impl IKeystoreMaintenance for Maintenance {
         source: &KeyDescriptor,
         destination: &KeyDescriptor,
     ) -> BinderResult<()> {
-        log::info!("migrateKeyNamespace(src={source:?}, dest={destination:?})");
+        info!("migrateKeyNamespace(src={source:?}, dest={destination:?})");
         let _wp = wd::watch("IKeystoreMaintenance::migrateKeyNamespace");
         Self::migrate_key_namespace(source, destination).map_err(into_logged_binder)
     }
 
     fn deleteAllKeys(&self) -> BinderResult<()> {
-        log::warn!("deleteAllKeys() invoked, indicating initial setup or post-factory reset");
+        warn!("deleteAllKeys() invoked, indicating initial setup or post-factory reset");
         let _wp = wd::watch("IKeystoreMaintenance::deleteAllKeys");
         Self::delete_all_keys().map_err(into_logged_binder)
     }
@@ -636,8 +645,9 @@ impl IKeystoreMaintenance for Maintenance {
         user_id: i32,
         secure_user_id: i64,
     ) -> BinderResult<std::vec::Vec<i64>> {
-        log::info!("getAppUidsAffectedBySid(secure_user_id={secure_user_id:?})");
+        let sid = SecureUserId(secure_user_id);
+        info!("getAppUidsAffectedBySid({user_id:?}, {sid:?})");
         let _wp = wd::watch("IKeystoreMaintenance::getAppUidsAffectedBySid");
-        Self::get_app_uids_affected_by_sid(user_id, secure_user_id).map_err(into_logged_binder)
+        Self::get_app_uids_affected_by_sid(user_id, sid).map_err(into_logged_binder)
     }
 }
diff --git a/keystore2/src/metrics_store.rs b/keystore2/src/metrics_store.rs
index 30c5973e..ed93c1b6 100644
--- a/keystore2/src/metrics_store.rs
+++ b/keystore2/src/metrics_store.rs
@@ -45,6 +45,7 @@ use android_security_metrics::aidl::android::security::metrics::{
     SecurityLevel::SecurityLevel as MetricsSecurityLevel, Storage::Storage as MetricsStorage,
 };
 use anyhow::{anyhow, Context, Result};
+use log::{error, warn};
 use std::collections::HashMap;
 use std::sync::{LazyLock, Mutex};
 
@@ -155,7 +156,7 @@ impl MetricsStore {
                 *atom_count += 1;
             } else {
                 // This is a rare case, if at all.
-                log::error!("In insert_atom: Maximum storage limit reached for overflow atom.")
+                error!("In insert_atom: Maximum storage limit reached for overflow atom.")
             }
         }
     }
@@ -553,7 +554,7 @@ pub(crate) fn pull_storage_stats() -> Result<Vec<KeystoreAtom>> {
                 ..Default::default()
             }),
             Err(error) => {
-                log::error!("pull_metrics_callback: Error getting storage stat: {}", error)
+                error!("pull_metrics_callback: Error getting storage stat: {error}")
             }
         };
     };
@@ -596,7 +597,7 @@ pub fn update_keystore_crash_sysprop() {
         // Proceed to write the system property with value 0.
         Ok(None) => 0,
         Err(error) => {
-            log::warn!(
+            warn!(
                 concat!(
                     "In update_keystore_crash_sysprop: ",
                     "Failed to read the existing system property due to: {:?}.",
@@ -611,7 +612,7 @@ pub fn update_keystore_crash_sysprop() {
     if let Err(e) =
         rustutils::system_properties::write(KEYSTORE_CRASH_COUNT_PROPERTY, &new_count.to_string())
     {
-        log::error!(
+        error!(
             concat!(
                 "In update_keystore_crash_sysprop:: ",
                 "Failed to write the system property due to error: {:?}"
diff --git a/keystore2/src/operation.rs b/keystore2/src/operation.rs
index 0d5e88f3..7d73ba90 100644
--- a/keystore2/src/operation.rs
+++ b/keystore2/src/operation.rs
@@ -143,6 +143,7 @@ use android_system_keystore2::aidl::android::system::keystore2::{
     IKeystoreOperation::BnKeystoreOperation, IKeystoreOperation::IKeystoreOperation,
 };
 use anyhow::{anyhow, Context, Result};
+use log::{error, warn};
 use std::{
     collections::HashMap,
     sync::{Arc, Mutex, MutexGuard, Weak},
@@ -296,7 +297,7 @@ impl Operation {
 
         // We abort the operation. If there was an error we log it but ignore it.
         if let Err(e) = map_km_error(self.km_op.abort()) {
-            log::warn!("In prune: KeyMint::abort failed with {:?}.", e);
+            warn!("In prune: KeyMint::abort failed: {e:?}.");
         }
 
         Ok(())
@@ -473,7 +474,7 @@ impl Drop for Operation {
             // If the operation was still active we call abort, setting
             // the outcome to `Outcome::Dropped`
             if let Err(e) = self.abort(Outcome::Dropped) {
-                log::error!("While dropping Operation: abort failed:\n    {:?}", e);
+                error!("While dropping Operation: abort failed: {e:?}");
             }
         }
     }
@@ -867,7 +868,7 @@ impl IKeystoreOperation for KeystoreOperation {
                 // There is no reason to clutter the log with it. It is never the cause
                 // for a true problem.
                 Some(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE)) => {}
-                _ => log::error!("{:?}", e),
+                _ => error!("{e:?}"),
             };
             into_binder(e)
         })
diff --git a/keystore2/src/remote_provisioning.rs b/keystore2/src/remote_provisioning.rs
index a1ce5f6a..9304e1d4 100644
--- a/keystore2/src/remote_provisioning.rs
+++ b/keystore2/src/remote_provisioning.rs
@@ -19,23 +19,23 @@
 //! certificate chains signed by some root authority and stored in a keystore SQLite
 //! DB.
 
+use crate::error::wrapped_rkpd_error_to_ks_error;
+use crate::globals::get_remotely_provisioned_component_name;
+use crate::ks_err;
+use crate::metrics_store::log_rkp_error_stats;
+use crate::watchdog_helper::watchdog as wd;
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, AttestationKey::AttestationKey, KeyParameter::KeyParameter,
     KeyParameterValue::KeyParameterValue, SecurityLevel::SecurityLevel, Tag::Tag,
 };
+use android_security_metrics::aidl::android::security::metrics::RkpError::RkpError as MetricsRkpError;
 use android_security_rkp_aidl::aidl::android::security::rkp::RemotelyProvisionedKey::RemotelyProvisionedKey;
 use android_system_keystore2::aidl::android::system::keystore2::{
     Domain::Domain, KeyDescriptor::KeyDescriptor,
 };
 use anyhow::{Context, Result};
 use keystore2_crypto::parse_subject_from_certificate;
-
-use crate::error::wrapped_rkpd_error_to_ks_error;
-use crate::globals::get_remotely_provisioned_component_name;
-use crate::ks_err;
-use crate::metrics_store::log_rkp_error_stats;
-use crate::watchdog_helper::watchdog as wd;
-use android_security_metrics::aidl::android::security::metrics::RkpError::RkpError as MetricsRkpError;
+use log::{error, warn};
 
 /// Contains helper functions to check if remote provisioning is enabled on the system and, if so,
 /// to assign and retrieve attestation keys and certificate chains.
@@ -91,10 +91,10 @@ impl RemProvState {
             match get_rkpd_attestation_key(&self.security_level, caller_uid) {
                 Err(e) => {
                     if self.is_rkp_only() {
-                        log::error!("Error occurred: {:?}", e);
+                        error!("Error occurred: {e:?}");
                         return Err(wrapped_rkpd_error_to_ks_error(&e)).context(format!("{e:?}"));
                     }
-                    log::warn!("Error occurred: {:?}", e);
+                    warn!("Error occurred: {e:?}");
                     log_rkp_error_stats(
                         MetricsRkpError::FALL_BACK_DURING_HYBRID,
                         &self.security_level,
diff --git a/keystore2/src/security_level.rs b/keystore2/src/security_level.rs
index 233f2ae9..d9c1aff6 100644
--- a/keystore2/src/security_level.rs
+++ b/keystore2/src/security_level.rs
@@ -35,7 +35,7 @@ use crate::utils::{
     check_device_attestation_permissions, check_key_permission,
     check_unique_id_attestation_permissions, is_device_id_attestation_tag,
     key_characteristics_to_internal, log_security_safe_params, uid_to_android_user, watchdog as wd,
-    UNDEFINED_NOT_AFTER,
+    Challenge, UNDEFINED_NOT_AFTER,
 };
 use crate::{
     database::{
@@ -64,6 +64,7 @@ use android_system_keystore2::aidl::android::system::keystore2::{
     KeyMetadata::KeyMetadata, KeyParameters::KeyParameters, ResponseCode::ResponseCode,
 };
 use anyhow::{anyhow, Context, Result};
+use log::error;
 use postprocessor_client::process_certificate_chain;
 use rkpd_client::store_rkpd_attestation_key;
 use rustutils::system_properties::read_bool;
@@ -265,7 +266,7 @@ impl KeystoreSecurityLevel {
                 let super_key = SUPER_KEY
                     .read()
                     .unwrap()
-                    .get_after_first_unlock_key_by_user_id(uid_to_android_user(caller_uid));
+                    .get_credential_encrypted_key_by_user_id(uid_to_android_user(caller_uid));
                 let (key_id_guard, mut key_entry) = DB
                     .with::<_, Result<(KeyIdGuard, KeyEntry)>>(|db| {
                         LEGACY_IMPORTER.with_try_import(key, caller_uid, super_key, || {
@@ -362,7 +363,7 @@ impl KeystoreSecurityLevel {
                                 {
                                     log_key_integrity_violation(&key);
                                 } else {
-                                    log::error!("Failed to load key descriptor for audit log");
+                                    error!("Failed to load key descriptor for audit log");
                                 }
                             }
                             return v;
@@ -373,7 +374,8 @@ impl KeystoreSecurityLevel {
             )
             .context(ks_err!("Failed to begin operation."))?;
 
-        let operation_challenge = auth_info.finalize_create_authorization(begin_result.challenge);
+        let operation_challenge =
+            auth_info.finalize_create_authorization(Challenge(begin_result.challenge));
 
         let op_params: Vec<KeyParameter> = operation_parameters.to_vec();
 
@@ -790,7 +792,7 @@ impl KeystoreSecurityLevel {
         // Import_wrapped_key requires the rebind permission for the new key.
         check_key_permission(KeyPerm::Rebind, &key, &None).context(ks_err!())?;
 
-        let super_key = SUPER_KEY.read().unwrap().get_after_first_unlock_key_by_user_id(user_id);
+        let super_key = SUPER_KEY.read().unwrap().get_credential_encrypted_key_by_user_id(user_id);
 
         let (wrapping_key_id_guard, mut wrapping_key_entry) = DB
             .with(|db| {
diff --git a/keystore2/src/service.rs b/keystore2/src/service.rs
index 85ac7bc4..d1325cd6 100644
--- a/keystore2/src/service.rs
+++ b/keystore2/src/service.rs
@@ -52,6 +52,7 @@ use android_system_keystore2::aidl::android::system::keystore2::{
 use anyhow::{Context, Result};
 use error::Error;
 use keystore2_selinux as selinux;
+use log::error;
 
 /// Implementation of the IKeystoreService.
 #[derive(Default)]
@@ -72,8 +73,8 @@ impl KeystoreService {
         ) {
             Ok(v) => v,
             Err(e) => {
-                log::error!("Failed to construct mandatory security level TEE: {e:?}");
-                log::error!("Does the device have a /default Keymaster or KeyMint instance?");
+                error!("Failed to construct mandatory security level TEE: {e:?}");
+                error!("Does the device have a /default Keymaster or KeyMint instance?");
                 return Err(e.context(ks_err!("Trying to construct mandatory security level TEE")));
             }
         };
@@ -140,7 +141,7 @@ impl KeystoreService {
         let super_key = SUPER_KEY
             .read()
             .unwrap()
-            .get_after_first_unlock_key_by_user_id(uid_to_android_user(caller_uid));
+            .get_credential_encrypted_key_by_user_id(uid_to_android_user(caller_uid));
 
         let (key_id_guard, mut key_entry) = DB
             .with(|db| {
@@ -197,7 +198,7 @@ impl KeystoreService {
         let super_key = SUPER_KEY
             .read()
             .unwrap()
-            .get_after_first_unlock_key_by_user_id(uid_to_android_user(caller_uid));
+            .get_credential_encrypted_key_by_user_id(uid_to_android_user(caller_uid));
 
         DB.with::<_, Result<()>>(|db| {
             let entry = match LEGACY_IMPORTER.with_try_import(key, caller_uid, super_key, || {
@@ -347,7 +348,7 @@ impl KeystoreService {
         let super_key = SUPER_KEY
             .read()
             .unwrap()
-            .get_after_first_unlock_key_by_user_id(uid_to_android_user(caller_uid));
+            .get_credential_encrypted_key_by_user_id(uid_to_android_user(caller_uid));
 
         DB.with(|db| {
             LEGACY_IMPORTER.with_try_import(key, caller_uid, super_key, || {
@@ -371,7 +372,7 @@ impl KeystoreService {
         let super_key = SUPER_KEY
             .read()
             .unwrap()
-            .get_after_first_unlock_key_by_user_id(uid_to_android_user(caller_uid));
+            .get_credential_encrypted_key_by_user_id(uid_to_android_user(caller_uid));
 
         DB.with(|db| {
             LEGACY_IMPORTER.with_try_import(key, caller_uid, super_key, || {
diff --git a/keystore2/src/shared_secret_negotiation.rs b/keystore2/src/shared_secret_negotiation.rs
index ff0ddf8a..24919529 100644
--- a/keystore2/src/shared_secret_negotiation.rs
+++ b/keystore2/src/shared_secret_negotiation.rs
@@ -26,6 +26,7 @@ use android_security_compat::aidl::android::security::compat::IKeystoreCompatSer
 use anyhow::Result;
 use binder::get_declared_instances;
 use keystore2_hal_names::get_hidl_instances;
+use log::{error, info, warn};
 use std::fmt::{self, Display, Formatter};
 use std::time::Duration;
 
@@ -45,7 +46,7 @@ pub fn perform_shared_secret_negotiation() {
             .expect("In perform_shared_secret_negotiation: Trying to list participants.");
         let connected = connect_participants(participants);
         negotiate_shared_secret(connected);
-        log::info!("Shared secret negotiation concluded successfully.");
+        info!("Shared secret negotiation concluded successfully.");
 
         // Once shared secret negotiation is done, the StrongBox and TEE have a common key that
         // can be used to authenticate a possible RootOfTrust transfer.
@@ -98,10 +99,10 @@ fn filter_map_legacy_km_instances(
         "default" => Some(SharedSecretParticipant::Hidl { is_strongbox: false, version }),
         "strongbox" => Some(SharedSecretParticipant::Hidl { is_strongbox: true, version }),
         _ => {
-            log::warn!("Found unexpected keymaster instance: \"{}\"", name);
-            log::warn!("Device is misconfigured. Allowed instances are:");
-            log::warn!("   * default");
-            log::warn!("   * strongbox");
+            warn!("Found unexpected keymaster instance: '{name}'");
+            warn!("Device is misconfigured. Allowed instances are:");
+            warn!("   * default");
+            warn!("   * strongbox");
             None
         }
     }
@@ -155,71 +156,67 @@ fn connect_participants(
     let mut connected_participants: Vec<(Strong<dyn ISharedSecret>, SharedSecretParticipant)> =
         vec![];
     loop {
-        let (connected, not_connected) = participants.into_iter().fold(
-            (connected_participants, vec![]),
-            |(mut connected, mut failed), e| {
-                match e {
-                    SharedSecretParticipant::Aidl(instance_name) => {
-                        let service_name = format!(
-                            "{}/{}",
-                            <BpSharedSecret as ISharedSecret>::get_descriptor(),
-                            instance_name
-                        );
-                        match map_binder_status_code(binder::get_interface(&service_name)) {
-                            Err(e) => {
-                                log::warn!(
-                                    "Unable to connect \"{}\" with error:\n{:?}\nRetrying later.",
-                                    service_name,
-                                    e
+        let (connected, not_connected) =
+            participants.into_iter().fold(
+                (connected_participants, vec![]),
+                |(mut connected, mut failed), e| {
+                    match e {
+                        SharedSecretParticipant::Aidl(instance_name) => {
+                            let service_name = format!(
+                                "{}/{}",
+                                <BpSharedSecret as ISharedSecret>::get_descriptor(),
+                                instance_name
+                            );
+                            match map_binder_status_code(binder::get_interface(&service_name)) {
+                                Err(e) => {
+                                    warn!(
+                                    "Unable to connect '{service_name}': {e:?}\nRetrying later.",
                                 );
-                                failed.push(SharedSecretParticipant::Aidl(instance_name));
+                                    failed.push(SharedSecretParticipant::Aidl(instance_name));
+                                }
+                                Ok(service) => connected
+                                    .push((service, SharedSecretParticipant::Aidl(instance_name))),
                             }
-                            Ok(service) => connected
-                                .push((service, SharedSecretParticipant::Aidl(instance_name))),
                         }
-                    }
-                    SharedSecretParticipant::Hidl { is_strongbox, version } => {
-                        // This is a no-op if it was called before.
-                        keystore2_km_compat::add_keymint_device_service();
+                        SharedSecretParticipant::Hidl { is_strongbox, version } => {
+                            // This is a no-op if it was called before.
+                            keystore2_km_compat::add_keymint_device_service();
 
-                        // If we cannot connect to the compatibility service there is no way to
-                        // recover.
-                        // PANIC! - Unless you brought your towel.
-                        let keystore_compat_service: Strong<dyn IKeystoreCompatService> =
-                            map_binder_status_code(binder::get_interface(COMPAT_PACKAGE_NAME))
-                                .expect(
+                            // If we cannot connect to the compatibility service there is no way to
+                            // recover.
+                            // PANIC! - Unless you brought your towel.
+                            let keystore_compat_service: Strong<dyn IKeystoreCompatService> =
+                                map_binder_status_code(binder::get_interface(COMPAT_PACKAGE_NAME))
+                                    .expect(
                                     "In connect_participants: Trying to connect to compat service.",
                                 );
 
-                        match map_binder_status(keystore_compat_service.getSharedSecret(
-                            if is_strongbox {
-                                SecurityLevel::STRONGBOX
-                            } else {
-                                SecurityLevel::TRUSTED_ENVIRONMENT
-                            },
-                        )) {
-                            Err(e) => {
-                                log::warn!(
-                                    concat!(
-                                        "Unable to connect keymaster device \"{}\" ",
-                                        "with error:\n{:?}\nRetrying later."
-                                    ),
-                                    if is_strongbox { "strongbox" } else { "TEE" },
-                                    e
-                                );
-                                failed
-                                    .push(SharedSecretParticipant::Hidl { is_strongbox, version });
+                            match map_binder_status(keystore_compat_service.getSharedSecret(
+                                if is_strongbox {
+                                    SecurityLevel::STRONGBOX
+                                } else {
+                                    SecurityLevel::TRUSTED_ENVIRONMENT
+                                },
+                            )) {
+                                Err(e) => {
+                                    warn!("Unable to connect {} keymaster device: {e:?}\nRetrying later.",
+                                        if is_strongbox { "StrongBox" } else { "TEE" },
+                                    );
+                                    failed.push(SharedSecretParticipant::Hidl {
+                                        is_strongbox,
+                                        version,
+                                    });
+                                }
+                                Ok(service) => connected.push((
+                                    service,
+                                    SharedSecretParticipant::Hidl { is_strongbox, version },
+                                )),
                             }
-                            Ok(service) => connected.push((
-                                service,
-                                SharedSecretParticipant::Hidl { is_strongbox, version },
-                            )),
                         }
                     }
-                }
-                (connected, failed)
-            },
-        );
+                    (connected, failed)
+                },
+            );
         participants = not_connected;
         connected_participants = connected;
         if participants.is_empty() {
@@ -245,8 +242,8 @@ fn negotiate_shared_secret(
 
         match result {
             Err(e) => {
-                log::warn!("{:?}", e);
-                log::warn!("Retrying in one second.");
+                warn!("{e:?}");
+                warn!("Retrying in one second.");
                 std::thread::sleep(Duration::from_millis(1000));
             }
             Ok(params) => break params,
@@ -271,9 +268,9 @@ fn negotiate_shared_secret(
     });
 
     if let Err(e) = negotiation_result {
-        log::error!("In negotiate_shared_secret: {:?}.", e);
+        error!("In negotiate_shared_secret: {e:?}");
         if let SharedSecretError::Checksum(_) = e {
-            log::error!(concat!(
+            error!(concat!(
                 "This means that this device is NOT PROVISIONED CORRECTLY.\n",
                 "User authorization and other security functions will not work\n",
                 "as expected. Please contact your OEM for instructions.",
@@ -287,7 +284,7 @@ pub fn transfer_root_of_trust() {
     let strongbox = match get_keymint_device(&SecurityLevel::STRONGBOX) {
         Ok((s, _, _)) => s,
         Err(_e) => {
-            log::info!("No StrongBox Keymint available, so no RoT transfer");
+            info!("No StrongBox Keymint available, so no RoT transfer");
             return;
         }
     };
@@ -299,7 +296,7 @@ pub fn transfer_root_of_trust() {
             // - it already has RootOfTrust information
             // - it's a KeyMint v1 implementation that doesn't understand the method.
             // In either case, we're done.
-            log::info!("StrongBox does not provide a challenge, so no RoT transfer: {:?}", e);
+            info!("StrongBox does not provide a challenge, so no RoT transfer: {e:?}");
             return;
         }
     };
@@ -307,14 +304,14 @@ pub fn transfer_root_of_trust() {
     let tee = match get_keymint_device(&SecurityLevel::TRUSTED_ENVIRONMENT) {
         Ok((s, _, _)) => s,
         Err(e) => {
-            log::error!("No TEE KeyMint implementation found! {:?}", e);
+            error!("No TEE KeyMint implementation found! {e:?}");
             return;
         }
     };
     let root_of_trust = match tee.getRootOfTrust(&challenge) {
         Ok(rot) => rot,
         Err(e) => {
-            log::error!("TEE KeyMint failed to return RootOfTrust info: {:?}", e);
+            error!("TEE KeyMint failed to return RootOfTrust info: {e:?}");
             return;
         }
     };
@@ -322,7 +319,7 @@ pub fn transfer_root_of_trust() {
     // Just pass it on to the StrongBox KeyMint instance.
     let result = strongbox.sendRootOfTrust(&root_of_trust);
     if let Err(e) = result {
-        log::error!("Failed to send RootOfTrust to StrongBox: {:?}", e);
+        error!("Failed to send RootOfTrust to StrongBox: {e:?}");
     }
-    log::info!("RootOfTrust transfer process complete");
+    info!("RootOfTrust transfer process complete");
 }
diff --git a/keystore2/src/super_key.rs b/keystore2/src/super_key.rs
index 3e657530..4c8bf68e 100644
--- a/keystore2/src/super_key.rs
+++ b/keystore2/src/super_key.rs
@@ -13,7 +13,7 @@
 // limitations under the License.
 
 use crate::{
-    boot_level_keys::{get_level_zero_key, BootLevelKeyCache},
+    boot_level_keys::{get_level_zero_key, BootLevel, BootLevelKeyCache},
     database::BlobMetaData,
     database::BlobMetaEntry,
     database::EncryptedBy,
@@ -28,7 +28,7 @@ use crate::{
     ks_err,
     legacy_importer::LegacyImporter,
     raw_device::KeyMintDevice,
-    utils::{watchdog as wd, AesGcm, AID_KEYSTORE},
+    utils::{watchdog as wd, AesGcm, SecureUserId, AID_KEYSTORE},
 };
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, BlockMode::BlockMode, HardwareAuthToken::HardwareAuthToken,
@@ -44,6 +44,7 @@ use keystore2_crypto::{
     aes_gcm_decrypt, aes_gcm_encrypt, generate_aes256_key, generate_salt, Password, ZVec,
     AES_256_KEY_LENGTH,
 };
+use log::{error, info, warn};
 use rustutils::system_properties::PropertyWatcher;
 use std::{
     collections::HashMap,
@@ -55,7 +56,8 @@ use std::{convert::TryFrom, ops::Deref};
 #[cfg(test)]
 mod tests;
 
-const MAX_MAX_BOOT_LEVEL: usize = 1_000_000_000;
+const MAX_MAX_BOOT_LEVEL: BootLevel = BootLevel(1_000_000_000);
+
 /// Allow up to 15 seconds between the user unlocking using a biometric, and the auth
 /// token being used to unlock in [`SuperKeyManager::try_unlock_user_with_biometric`].
 /// This seems short enough for security purposes, while long enough that even the
@@ -64,6 +66,15 @@ const BIOMETRIC_AUTH_TIMEOUT_S: i32 = 15; // seconds
 
 type UserId = u32;
 
+/// Specify which keys should be wiped given a particular user's UserSuperKeys
+#[derive(PartialEq)]
+pub enum WipeKeyOption {
+    /// Wipe unlocked_device_required_symmetric/private and biometric_unlock keys
+    PlaintextAndBiometric,
+    /// Wipe only unlocked_device_required_symmetric/private keys
+    PlaintextOnly,
+}
+
 /// Encryption algorithm used by a particular type of superencryption key
 #[derive(Debug, Clone, Copy, PartialEq, Eq)]
 pub enum SuperEncryptionAlgorithm {
@@ -85,13 +96,14 @@ pub struct SuperKeyType<'a> {
     pub name: &'a str,
 }
 
-/// The user's AfterFirstUnlock super key. This super key is loaded into memory when the user first
-/// unlocks the device, and it remains in memory until the device reboots. This is used to encrypt
+/// The user's CredentialEncrypted super key. This super key is loaded into memory when the user's
+/// credential encrypted storage is unlocked. It remains in memory until the user's credential
+/// encrypted storage is locked, through a device reboot or user logout. This is used to encrypt
 /// keys that require user authentication but not an unlocked device.
-pub const USER_AFTER_FIRST_UNLOCK_SUPER_KEY: SuperKeyType = SuperKeyType {
+pub const CREDENTIAL_ENCRYPTED_SUPER_KEY: SuperKeyType = SuperKeyType {
     alias: "USER_SUPER_KEY",
     algorithm: SuperEncryptionAlgorithm::Aes256Gcm,
-    name: "AfterFirstUnlock super key",
+    name: "CredentialEncrypted super key",
 };
 
 /// The user's UnlockedDeviceRequired symmetric super key. This super key is loaded into memory each
@@ -117,12 +129,12 @@ pub const USER_UNLOCKED_DEVICE_REQUIRED_P521_SUPER_KEY: SuperKeyType = SuperKeyT
 pub enum SuperEncryptionType {
     /// Do not superencrypt this key.
     None,
-    /// Superencrypt with the AfterFirstUnlock super key.
-    AfterFirstUnlock,
+    /// Superencrypt with the CredentialEncrypted super key.
+    CredentialEncrypted,
     /// Superencrypt with an UnlockedDeviceRequired super key.
     UnlockedDeviceRequired,
     /// Superencrypt with a key based on the desired boot level
-    BootLevel(i32),
+    BootLevel(BootLevel),
 }
 
 #[derive(Debug, Clone, Copy)]
@@ -130,7 +142,7 @@ pub enum SuperKeyIdentifier {
     /// id of the super key in the database.
     DatabaseId(i64),
     /// Boot level of the encrypting boot level key
-    BootLevel(i32),
+    BootLevel(BootLevel),
 }
 
 impl SuperKeyIdentifier {
@@ -138,7 +150,9 @@ impl SuperKeyIdentifier {
         if let Some(EncryptedBy::KeyId(key_id)) = metadata.encrypted_by() {
             Some(SuperKeyIdentifier::DatabaseId(*key_id))
         } else {
-            metadata.max_boot_level().map(|boot_level| SuperKeyIdentifier::BootLevel(*boot_level))
+            metadata
+                .max_boot_level()
+                .map(|boot_level| SuperKeyIdentifier::BootLevel(BootLevel(*boot_level as usize)))
         }
     }
 
@@ -148,7 +162,7 @@ impl SuperKeyIdentifier {
                 metadata.add(BlobMetaEntry::EncryptedBy(EncryptedBy::KeyId(*id)));
             }
             SuperKeyIdentifier::BootLevel(level) => {
-                metadata.add(BlobMetaEntry::MaxBootLevel(*level));
+                metadata.add(BlobMetaEntry::MaxBootLevel(level.0 as i32));
             }
         }
     }
@@ -241,7 +255,7 @@ impl LockedKey {
 /// information about that biometric-bound key.
 struct BiometricUnlock {
     /// List of auth token SIDs that are accepted by the encrypting biometric-bound key.
-    sids: Vec<i64>,
+    sids: Vec<SecureUserId>,
     /// Key descriptor of the encrypting biometric-bound key.
     key_desc: KeyDescriptor,
     /// The UnlockedDeviceRequired super keys, encrypted with a biometric-bound key.
@@ -251,14 +265,15 @@ struct BiometricUnlock {
 
 #[derive(Default)]
 struct UserSuperKeys {
-    /// The AfterFirstUnlock super key is used for synthetic password binding of authentication
+    /// The CredentialEncrypted super key is used for synthetic password binding of authentication
     /// bound keys. There is one key per android user. The key is stored on flash encrypted with a
     /// key derived from a secret, that is itself derived from the user's synthetic password. (In
     /// most cases, the user's synthetic password can, in turn, only be decrypted using the user's
-    /// Lock Screen Knowledge Factor or LSKF.) When the user unlocks the device for the first time,
-    /// this key is unlocked, i.e., decrypted, and stays memory resident until the device reboots.
-    after_first_unlock: Option<Arc<SuperKey>>,
-    /// The UnlockedDeviceRequired symmetric super key works like the AfterFirstUnlock super key
+    /// Lock Screen Knowledge Factor or LSKF.) When the user logs into the device this key is
+    /// unlocked, i.e., decrypted, and stays memory resident until the user logs out or the device
+    /// reboots.
+    credential_encrypted: Option<Arc<SuperKey>>,
+    /// The UnlockedDeviceRequired symmetric super key works like the CredentialEncrypted super key
     /// with the distinction that it is cleared from memory when the device is locked.
     unlocked_device_required_symmetric: Option<Arc<SuperKey>>,
     /// When the device is locked, keys that use the UnlockedDeviceRequired key parameter can still
@@ -295,18 +310,18 @@ impl SuperKeyManager {
     pub fn set_up_boot_level_cache(skm: &Arc<RwLock<Self>>, db: &mut KeystoreDB) -> Result<()> {
         let mut skm_guard = skm.write().unwrap();
         if skm_guard.data.boot_level_key_cache.is_some() {
-            log::info!("In set_up_boot_level_cache: called for a second time");
+            info!("In set_up_boot_level_cache: called for a second time");
             return Ok(());
         }
         let level_zero_key =
             get_level_zero_key(db).context(ks_err!("get_level_zero_key failed"))?;
         skm_guard.data.boot_level_key_cache =
             Some(Mutex::new(BootLevelKeyCache::new(level_zero_key)));
-        log::info!("Starting boot level watcher.");
+        info!("Starting boot level watcher.");
         let clone = skm.clone();
         std::thread::spawn(move || {
             Self::watch_boot_level(clone)
-                .unwrap_or_else(|e| log::error!("watch_boot_level failed:\n{:?}", e));
+                .unwrap_or_else(|e| error!("watch_boot_level failed: {e:?}"));
         });
         Ok(())
     }
@@ -318,7 +333,7 @@ impl SuperKeyManager {
             .context(ks_err!("PropertyWatcher::new failed"))?;
         loop {
             let level = w
-                .read(|_n, v| v.parse::<usize>().map_err(std::convert::Into::into))
+                .read(|_n, v| v.parse::<usize>().map_err(std::convert::Into::into).map(BootLevel))
                 .context(ks_err!("read of property failed"))?;
 
             // This scope limits the skm_guard life, so we don't hold the skm_guard while
@@ -334,15 +349,13 @@ impl SuperKeyManager {
                     .get_mut()
                     .unwrap();
                 if level < MAX_MAX_BOOT_LEVEL {
-                    log::info!("Read keystore.boot_level value {}", level);
+                    info!("Read keystore.boot_level value {level:?}");
                     boot_level_key_cache
                         .advance_boot_level(level)
                         .context(ks_err!("advance_boot_level failed"))?;
                 } else {
-                    log::info!(
-                        "keystore.boot_level {} hits maximum {}, finishing.",
-                        level,
-                        MAX_MAX_BOOT_LEVEL
+                    info!(
+                        "keystore.boot_level {level:?} hits maximum {MAX_MAX_BOOT_LEVEL:?}, finishing.",
                     );
                     boot_level_key_cache.finish();
                     break;
@@ -353,18 +366,18 @@ impl SuperKeyManager {
         Ok(())
     }
 
-    pub fn level_accessible(&self, boot_level: i32) -> bool {
+    pub fn level_accessible(&self, boot_level: BootLevel) -> bool {
         self.data
             .boot_level_key_cache
             .as_ref()
-            .map_or(false, |c| c.lock().unwrap().level_accessible(boot_level as usize))
+            .is_some_and(|c| c.lock().unwrap().level_accessible(boot_level))
     }
 
     pub fn forget_all_keys_for_user(&mut self, user: UserId) {
         self.data.user_keys.remove(&user);
     }
 
-    fn install_after_first_unlock_key_for_user(
+    fn install_credential_encrypted_key_for_user(
         &mut self,
         user: UserId,
         super_key: Arc<SuperKey>,
@@ -372,7 +385,7 @@ impl SuperKeyManager {
         self.data
             .add_key_to_key_index(&super_key)
             .context(ks_err!("add_key_to_key_index failed"))?;
-        self.data.user_keys.entry(user).or_default().after_first_unlock = Some(super_key);
+        self.data.user_keys.entry(user).or_default().credential_encrypted = Some(super_key);
         Ok(())
     }
 
@@ -385,7 +398,7 @@ impl SuperKeyManager {
                 .data
                 .boot_level_key_cache
                 .as_ref()
-                .map(|b| b.lock().unwrap().aes_key(*level as usize))
+                .map(|b| b.lock().unwrap().aes_key(*level))
                 .transpose()
                 .context(ks_err!("aes_key failed"))?
                 .flatten()
@@ -400,21 +413,21 @@ impl SuperKeyManager {
         })
     }
 
-    /// Returns the AfterFirstUnlock superencryption key for the given user ID, or None if the user
-    /// has not yet unlocked the device since boot.
-    pub fn get_after_first_unlock_key_by_user_id(
+    /// Returns the CredentialEncrypted superencryption key for the given user ID, or None if the
+    /// user has not yet unlocked the device since boot.
+    pub fn get_credential_encrypted_key_by_user_id(
         &self,
         user_id: UserId,
     ) -> Option<Arc<dyn AesGcm + Send + Sync>> {
-        self.get_after_first_unlock_key_by_user_id_internal(user_id)
+        self.get_credential_encrypted_key_by_user_id_internal(user_id)
             .map(|sk| -> Arc<dyn AesGcm + Send + Sync> { sk })
     }
 
-    fn get_after_first_unlock_key_by_user_id_internal(
+    fn get_credential_encrypted_key_by_user_id_internal(
         &self,
         user_id: UserId,
     ) -> Option<Arc<SuperKey>> {
-        self.data.user_keys.get(&user_id).and_then(|e| e.after_first_unlock.as_ref().cloned())
+        self.data.user_keys.get(&user_id).and_then(|e| e.credential_encrypted.as_ref().cloned())
     }
 
     /// Check if a given key is super-encrypted, from its metadata. If so, unwrap the key using
@@ -478,7 +491,7 @@ impl SuperKeyManager {
         }
     }
 
-    /// Checks if the user's AfterFirstUnlock super key exists in the database (or legacy database).
+    /// Checks if the user's CredentialEncrypted super key exists in the database (or legacy database).
     /// The reference to self is unused but it is required to prevent calling this function
     /// concurrently with skm state database changes.
     fn super_key_exists_in_db_for_user(
@@ -491,7 +504,7 @@ impl SuperKeyManager {
             .key_exists(
                 Domain::APP,
                 user_id as u64 as i64,
-                USER_AFTER_FIRST_UNLOCK_SUPER_KEY.alias,
+                CREDENTIAL_ENCRYPTED_SUPER_KEY.alias,
                 KeyType::Super,
             )
             .context(ks_err!())?;
@@ -513,8 +526,8 @@ impl SuperKeyManager {
     ) -> Result<Arc<SuperKey>> {
         let super_key = Self::extract_super_key_from_key_entry(algorithm, entry, pw, None)
             .context(ks_err!("Failed to extract super key from key entry"))?;
-        self.install_after_first_unlock_key_for_user(user_id, super_key.clone())
-            .context(ks_err!("Failed to install AfterFirstUnlock super key for user!"))?;
+        self.install_credential_encrypted_key_for_user(user_id, super_key.clone())
+            .context(ks_err!("Failed to install CredentialEncrypted super key for user!"))?;
         Ok(super_key)
     }
 
@@ -672,20 +685,20 @@ impl SuperKeyManager {
     ) -> Result<(Vec<u8>, BlobMetaData)> {
         match Enforcements::super_encryption_required(domain, key_parameters, flags) {
             SuperEncryptionType::None => Ok((key_blob.to_vec(), BlobMetaData::new())),
-            SuperEncryptionType::AfterFirstUnlock => {
-                // Encrypt the given key blob with the user's AfterFirstUnlock super key. If the
-                // user has not unlocked the device since boot or the super keys were never
-                // initialized for the user for some reason, an error is returned.
+            SuperEncryptionType::CredentialEncrypted => {
+                // Encrypt the given key blob with the user's CredentialEncrypted super key. If the
+                // user has not logged in or the super keys were never initialized for the user for
+                // some reason, an error is returned.
                 match self
                     .get_user_state(db, legacy_importer, user_id)
                     .context(ks_err!("Failed to get user state for user {user_id}"))?
                 {
-                    UserState::AfterFirstUnlock(super_key) => {
+                    UserState::CeUnlocked(super_key) => {
                         Self::encrypt_with_aes_super_key(key_blob, &super_key).context(ks_err!(
-                            "Failed to encrypt with AfterFirstUnlock super key for user {user_id}"
-                        ))
+                        "Failed to encrypt with CredentialEncrypted super key for user {user_id}"
+                    ))
                     }
-                    UserState::BeforeFirstUnlock => {
+                    UserState::CeLocked => {
                         Err(Error::Rc(ResponseCode::LOCKED)).context(ks_err!("Device is locked."))
                     }
                     UserState::Uninitialized => Err(Error::Rc(ResponseCode::UNINITIALIZED))
@@ -747,7 +760,7 @@ impl SuperKeyManager {
         password: &Password,
         reencrypt_with: Option<Arc<SuperKey>>,
     ) -> Result<Arc<SuperKey>> {
-        log::info!("Creating {} for user {}", key_type.name, user_id);
+        info!("Creating {} for user {user_id}", key_type.name);
         let (super_key, public_key) = match key_type.algorithm {
             SuperEncryptionAlgorithm::Aes256Gcm => {
                 (generate_aes256_key().context(ks_err!("Failed to generate AES-256 key."))?, None)
@@ -873,7 +886,7 @@ impl SuperKeyManager {
         &mut self,
         db: &mut KeystoreDB,
         user_id: UserId,
-        unlocking_sids: &[i64],
+        unlocking_sids: &[SecureUserId],
         weak_unlock_enabled: bool,
     ) {
         let entry = self.data.user_keys.entry(user_id).or_default();
@@ -907,7 +920,7 @@ impl SuperKeyManager {
                     ),
                 ];
                 for sid in unlocking_sids {
-                    key_params.push(KeyParameterValue::UserSecureID(*sid));
+                    key_params.push(KeyParameterValue::UserSecureID(sid.0));
                 }
                 let key_params: Vec<KmKeyParameter> =
                     key_params.into_iter().map(|x| x.into()).collect();
@@ -930,31 +943,38 @@ impl SuperKeyManager {
                 Ok(())
             })();
             if let Err(e) = res {
-                log::error!("Error setting up biometric unlock: {:#?}", e);
+                error!("Error setting up biometric unlock: {e:#?}");
                 // The caller can't do anything about the error, and for security reasons we still
                 // wipe the keys (unless a weak unlock method is enabled).  So just log the error.
             }
         }
         // Wipe the plaintext copy of the keys, unless a weak unlock method is enabled.
-        if !weak_unlock_enabled {
-            entry.unlocked_device_required_symmetric = None;
-            entry.unlocked_device_required_private = None;
+        if weak_unlock_enabled {
+            Self::log_status_of_unlocked_device_required_keys(user_id, entry);
+        } else {
+            Self::wipe_unlocked_device_required_keys_internal(
+                user_id,
+                entry,
+                WipeKeyOption::PlaintextOnly,
+            )
         }
-        Self::log_status_of_unlocked_device_required_keys(user_id, entry);
     }
 
-    pub fn wipe_plaintext_unlocked_device_required_keys(&mut self, user_id: UserId) {
+    pub fn wipe_unlocked_device_required_keys(&mut self, user_id: UserId, wipe_key: WipeKeyOption) {
         let entry = self.data.user_keys.entry(user_id).or_default();
-        entry.unlocked_device_required_symmetric = None;
-        entry.unlocked_device_required_private = None;
-        Self::log_status_of_unlocked_device_required_keys(user_id, entry);
+        Self::wipe_unlocked_device_required_keys_internal(user_id, entry, wipe_key);
     }
 
-    pub fn wipe_all_unlocked_device_required_keys(&mut self, user_id: UserId) {
-        let entry = self.data.user_keys.entry(user_id).or_default();
+    fn wipe_unlocked_device_required_keys_internal(
+        user_id: UserId,
+        entry: &mut UserSuperKeys,
+        wipe_key: WipeKeyOption,
+    ) {
         entry.unlocked_device_required_symmetric = None;
         entry.unlocked_device_required_private = None;
-        entry.biometric_unlock = None;
+        if wipe_key == WipeKeyOption::PlaintextAndBiometric {
+            entry.biometric_unlock = None;
+        }
         Self::log_status_of_unlocked_device_required_keys(user_id, entry);
     }
 
@@ -970,7 +990,7 @@ impl SuperKeyManager {
             (true, false) => "retained in plaintext",
             (true, true) => "retained in plaintext, with biometric-encrypted copy too",
         };
-        log::info!("UnlockedDeviceRequired super keys for user {user_id} are {status}.");
+        info!("UnlockedDeviceRequired super keys for user {user_id} are {status}.");
     }
 
     /// User has unlocked, not using a password. See if any of our stored auth tokens can be used
@@ -1006,7 +1026,8 @@ impl SuperKeyManager {
             for sid in &biometric.sids {
                 let sid = *sid;
                 if let Some(auth_token_entry) = db.find_auth_token_entry(|entry| {
-                    entry.auth_token().userId == sid || entry.auth_token().authenticatorId == sid
+                    entry.auth_token().userId == sid.0
+                        || entry.auth_token().authenticatorId == sid.0
                 }) {
                     let res: Result<(Arc<SuperKey>, Arc<SuperKey>)> = (|| {
                         let symmetric = biometric.symmetric.decrypt(
@@ -1033,7 +1054,7 @@ impl SuperKeyManager {
                             entry.unlocked_device_required_private = Some(private.clone());
                             self.data.add_key_to_key_index(&symmetric)?;
                             self.data.add_key_to_key_index(&private)?;
-                            log::info!("Successfully unlocked user {user_id} with biometric {sid}",);
+                            info!("Successfully unlocked user {user_id} with biometric {sid:?}");
                             return Ok(());
                         }
                         Err(e) => {
@@ -1044,9 +1065,9 @@ impl SuperKeyManager {
                 }
             }
             if !errs.is_empty() {
-                log::warn!("biometric unlock failed for all SIDs, with errors:");
+                warn!("biometric unlock failed for all SIDs, with errors:");
                 for (sid, err) in errs {
-                    log::warn!("  biometric {sid}: {err}");
+                    warn!("  biometric {sid:?}: {err}");
                 }
             }
         }
@@ -1062,8 +1083,8 @@ impl SuperKeyManager {
         legacy_importer: &LegacyImporter,
         user_id: UserId,
     ) -> Result<UserState> {
-        match self.get_after_first_unlock_key_by_user_id_internal(user_id) {
-            Some(super_key) => Ok(UserState::AfterFirstUnlock(super_key)),
+        match self.get_credential_encrypted_key_by_user_id_internal(user_id) {
+            Some(super_key) => Ok(UserState::CeUnlocked(super_key)),
             None => {
                 // Check if a super key exists in the database or legacy database.
                 // If so, return locked user state.
@@ -1071,7 +1092,7 @@ impl SuperKeyManager {
                     .super_key_exists_in_db_for_user(db, legacy_importer, user_id)
                     .context(ks_err!())?
                 {
-                    Ok(UserState::BeforeFirstUnlock)
+                    Ok(UserState::CeLocked)
                 } else {
                     Ok(UserState::Uninitialized)
                 }
@@ -1087,7 +1108,7 @@ impl SuperKeyManager {
         legacy_importer: &LegacyImporter,
         user_id: UserId,
     ) -> Result<()> {
-        log::info!("remove_user(user={user_id})");
+        info!("remove_user(user={user_id})");
         // Mark keys created on behalf of the user as unreferenced.
         legacy_importer
             .bulk_delete_user(user_id, false)
@@ -1099,7 +1120,7 @@ impl SuperKeyManager {
         Ok(())
     }
 
-    /// Initializes the given user by creating their super keys, both AfterFirstUnlock and
+    /// Initializes the given user by creating their super keys, both CredentialEncrypted and
     /// UnlockedDeviceRequired. If allow_existing is true, then the user already being initialized
     /// is not considered an error.
     pub fn initialize_user(
@@ -1110,19 +1131,19 @@ impl SuperKeyManager {
         password: &Password,
         allow_existing: bool,
     ) -> Result<()> {
-        // Create the AfterFirstUnlock super key.
+        // Create the CredentialEncrypted super key.
         if self.super_key_exists_in_db_for_user(db, legacy_importer, user_id)? {
-            log::info!("AfterFirstUnlock super key already exists");
+            info!("CredentialEncrypted super key already exists");
             if !allow_existing {
                 return Err(Error::sys()).context(ks_err!("Tried to re-init an initialized user!"));
             }
         } else {
             let super_key = self
-                .create_super_key(db, user_id, &USER_AFTER_FIRST_UNLOCK_SUPER_KEY, password, None)
-                .context(ks_err!("Failed to create AfterFirstUnlock super key"))?;
+                .create_super_key(db, user_id, &CREDENTIAL_ENCRYPTED_SUPER_KEY, password, None)
+                .context(ks_err!("Failed to create CredentialEncrypted super key"))?;
 
-            self.install_after_first_unlock_key_for_user(user_id, super_key)
-                .context(ks_err!("Failed to install AfterFirstUnlock super key for user"))?;
+            self.install_credential_encrypted_key_for_user(user_id, super_key)
+                .context(ks_err!("Failed to install CredentialEncrypted super key for user"))?;
         }
 
         // Create the UnlockedDeviceRequired super keys.
@@ -1132,11 +1153,11 @@ impl SuperKeyManager {
 
     /// Unlocks the given user with the given password.
     ///
-    /// If the user state is BeforeFirstUnlock:
-    /// - Unlock the user's AfterFirstUnlock super key
+    /// If the user state is CeLocked:
+    /// - Unlock the user's CredentialEncrypted super key
     /// - Unlock the user's UnlockedDeviceRequired super keys
     ///
-    /// If the user state is AfterFirstUnlock:
+    /// If the user state is CeUnlocked:
     /// - Unlock the user's UnlockedDeviceRequired super keys only
     ///
     pub fn unlock_user(
@@ -1146,16 +1167,16 @@ impl SuperKeyManager {
         user_id: UserId,
         password: &Password,
     ) -> Result<()> {
-        log::info!("unlock_user(user={user_id})");
+        info!("unlock_user(user={user_id})");
         match self.get_user_state(db, legacy_importer, user_id)? {
-            UserState::AfterFirstUnlock(_) => {
+            UserState::CeUnlocked(_) => {
                 self.unlock_unlocked_device_required_keys(db, user_id, password)
             }
             UserState::Uninitialized => {
                 Err(Error::sys()).context(ks_err!("Tried to unlock an uninitialized user!"))
             }
-            UserState::BeforeFirstUnlock => {
-                let alias = &USER_AFTER_FIRST_UNLOCK_SUPER_KEY;
+            UserState::CeLocked => {
+                let alias = &CREDENTIAL_ENCRYPTED_SUPER_KEY;
                 let result = legacy_importer
                     .with_try_import_super_key(user_id, password, || {
                         db.load_super_key(alias, user_id)
@@ -1185,13 +1206,13 @@ impl SuperKeyManager {
 /// This enum represents different states of the user's life cycle in the device.
 /// For now, only three states are defined. More states may be added later.
 pub enum UserState {
-    // The user's super keys exist, and the user has unlocked the device at least once since boot.
-    // Hence, the AfterFirstUnlock super key is available in the cache.
-    AfterFirstUnlock(Arc<SuperKey>),
-    // The user's super keys exist, but the user hasn't unlocked the device at least once since
-    // boot. Hence, the AfterFirstUnlock and UnlockedDeviceRequired super keys are not available in
+    // The user's super keys exist, and the user is running and their CE storage is unlocked.
+    // Hence, the CredentialEncrypted super key is available in the cache.
+    CeUnlocked(Arc<SuperKey>),
+    // The user's super keys exist, but the user is not running and their CE storage is locked.
+    // Hence, the CredentialEncrypted and UnlockedDeviceRequired super keys are not available in
     // the cache. However, they exist in the database in encrypted form.
-    BeforeFirstUnlock,
+    CeLocked,
     // The user's super keys don't exist. I.e., there's no user with the given user ID, or the user
     // is in the process of being created or destroyed.
     Uninitialized,
diff --git a/keystore2/src/super_key/tests.rs b/keystore2/src/super_key/tests.rs
index 76a96a71..0ed0bf8d 100644
--- a/keystore2/src/super_key/tests.rs
+++ b/keystore2/src/super_key/tests.rs
@@ -57,7 +57,7 @@ fn assert_unlocked(
     let user_state =
         skm.write().unwrap().get_user_state(keystore_db, legacy_importer, user_id).unwrap();
     match user_state {
-        UserState::AfterFirstUnlock(_) => {}
+        UserState::CeUnlocked(_) => {}
         _ => panic!("{}", err_msg),
     }
 }
@@ -72,7 +72,7 @@ fn assert_locked(
     let user_state =
         skm.write().unwrap().get_user_state(keystore_db, legacy_importer, user_id).unwrap();
     match user_state {
-        UserState::BeforeFirstUnlock => {}
+        UserState::CeLocked => {}
         _ => panic!("{}", err_msg),
     }
 }
diff --git a/keystore2/src/utils.rs b/keystore2/src/utils.rs
index 35290df5..1ea36674 100644
--- a/keystore2/src/utils.rs
+++ b/keystore2/src/utils.rs
@@ -48,7 +48,7 @@ use keystore2_apc_compat::{
     APC_COMPAT_ERROR_SYSTEM_ERROR,
 };
 use keystore2_crypto::{aes_gcm_decrypt, aes_gcm_encrypt, ZVec};
-use log::{info, warn};
+use log::{debug, error, info, warn};
 use std::iter::IntoIterator;
 use std::thread::sleep;
 use std::time::Duration;
@@ -56,6 +56,23 @@ use std::time::Duration;
 #[cfg(test)]
 mod tests;
 
+/// A secure user ID ("sid") corresponding to an `AndroidUserId` that has been registered with a
+/// secure authenticator instance.
+///
+/// The underlying integer type is `i64` to match the AIDL `long` types used in authenticator
+/// HALs.
+#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
+pub struct SecureUserId(pub i64);
+
+/// A per-operation authentication challenge value.
+///
+/// The underlying integer type is `i64` to match the AIDL `long` type that is:
+/// - returned by KeyMint in `BeginResult`
+/// - passed on by `keystore2` in the `OperationChallenge` AIDL type on the
+///   `IKeystoreService` AIDL interface.
+#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
+pub struct Challenge(pub i64);
+
 /// Per RFC 5280 4.1.2.5, an undefined expiration (not-after) field should be set to GeneralizedTime
 /// 999912312359559, which is 253402300799000 ms from Jan 1, 1970.
 pub const UNDEFINED_NOT_AFTER: i64 = 253402300799000i64;
@@ -214,11 +231,9 @@ where
 {
     let (format, key_material, mut chars) =
         crate::sw_keyblob::export_key(inner_keyblob, upgrade_params)?;
-    log::debug!(
-        "importing {:?} key material (len={}) with original chars={:?}",
-        format,
+    debug!(
+        "importing {format:?} key material (len={}) with original chars={chars:?}",
         key_material.len(),
-        chars
     );
     let asymmetric = chars.iter().any(|kp| {
         kp.tag == Tag::ALGORITHM
@@ -279,7 +294,7 @@ where
             value: KeyParameterValue::DateTime(UNDEFINED_NOT_AFTER),
         });
     }
-    log::debug!("import parameters={import_params:?}");
+    debug!("import parameters={import_params:?}");
 
     let creation_result = {
         let _wp = watchdog::watch(
@@ -382,9 +397,7 @@ where
                 //
                 //    The inner keyblob should still be recognized by the hardware implementation, so
                 //    strip the prefix and attempt a key upgrade.
-                log::info!(
-                    "found apparent km_compat(Keymaster) HW blob, attempt strip-and-upgrade"
-                );
+                info!("found apparent km_compat(Keymaster) HW blob, attempt strip-and-upgrade");
                 let inner_keyblob = &key_blob[km_compat::KEYMASTER_BLOB_HW_PREFIX.len()..];
                 upgrade_keyblob_and_perform_op(
                     km_dev,
@@ -405,7 +418,7 @@ where
                 //    The inner keyblob should be in the format produced by the C++ reference
                 //    implementation of KeyMint.  Extract the key material and import it into the
                 //    current KeyMint device.
-                log::info!("found apparent km_compat(Keymaster) SW blob, attempt strip-and-import");
+                info!("found apparent km_compat(Keymaster) SW blob, attempt strip-and-import");
                 let inner_keyblob = &key_blob[km_compat::KEYMASTER_BLOB_SW_PREFIX.len()..];
                 import_keyblob_and_perform_op(
                     km_dev,
@@ -429,9 +442,7 @@ where
                 //    The inner keyblob should be in the format produced by the C++ reference
                 //    implementation of KeyMint.  Extract the key material and import it into the
                 //    current KeyMint device.
-                log::info!(
-                    "found apparent km_compat.rs(KeyMint) SW blob, attempt strip-and-import"
-                );
+                info!("found apparent km_compat.rs(KeyMint) SW blob, attempt strip-and-import");
                 import_keyblob_and_perform_op(
                     km_dev,
                     inner_keyblob,
@@ -565,7 +576,7 @@ pub(crate) fn estimate_safe_amount_to_return(
         // that the binder overhead is 60% (to be confirmed). So break after
         // 350KB and return a partial list.
         if bytes > response_size_limit {
-            log::warn!(
+            warn!(
                 "{domain:?}:{namespace}: Key descriptors list ({} items after {start_past_alias:?}) \
                  may exceed binder size, returning {count} items est. {bytes} bytes",
                 key_descriptors.len(),
@@ -662,24 +673,32 @@ impl<T: AesGcmKey> AesGcm for T {
     }
 }
 
+/// Get the Binder interface identified by `name`, retrying any failures up to the given
+/// `retry_count`.
 pub(crate) fn retry_get_interface<T: FromIBinder + ?Sized>(
     name: &str,
+    retry_count: usize,
 ) -> Result<Strong<T>, StatusCode> {
-    let retry_count = if cfg!(early_vm) { 5 } else { 1 };
-
-    let mut wait_time = Duration::from_secs(5);
-    for i in 1..retry_count {
-        match binder::get_interface(name) {
-            Ok(res) => return Ok(res),
-            Err(e) => {
-                warn!("failed to get interface {name}. Retry {i}/{retry_count}: {e:?}");
-                sleep(wait_time);
-                wait_time *= 2;
+    let mut attempts = 0;
+    let mut wait_time = Duration::from_secs(1);
+    loop {
+        let err = match binder::get_interface(name) {
+            Ok(res) => {
+                if attempts > 1 {
+                    info!("Success on get_interface({name}) after {attempts} failures!");
+                }
+                return Ok(res);
             }
+            Err(e) => e,
+        };
+        attempts += 1;
+        error!("Failed (attempt {attempts} of {retry_count}) to get_interface {name}: {err:?}");
+        if attempts >= retry_count {
+            error!("Give up retrying after {attempts} failures, return final error: {err:?}");
+            return Err(err);
         }
+        info!("Blocking wait {wait_time:?} before retry of get_interface({name})");
+        sleep(wait_time);
+        wait_time *= 2;
     }
-    if retry_count > 1 {
-        info!("{retry_count}-th (last) retry to get interface: {name}");
-    }
-    binder::get_interface(name)
 }
diff --git a/keystore2/test_utils/Android.bp b/keystore2/test_utils/Android.bp
index 57da27fc..3f581eed 100644
--- a/keystore2/test_utils/Android.bp
+++ b/keystore2/test_utils/Android.bp
@@ -45,7 +45,6 @@ rust_defaults {
         "libcppbor",
         "libkeymaster_portable",
         "libkeymint_support",
-        "libkeystore-engine",
         "libkeystore2_ffi_test_utils",
     ],
     shared_libs: [
@@ -59,12 +58,6 @@ rust_library {
     crate_name: "keystore2_test_utils",
     srcs: ["lib.rs"],
     defaults: ["libkeystore2_test_utils_defaults"],
-    static_libs: [
-        // Also include static_libs for the NDK variants so that they are available
-        // for dependencies.
-        "android.system.keystore2-V5-ndk",
-        "android.hardware.security.keymint-V4-ndk",
-    ],
 }
 
 rust_test {
@@ -92,7 +85,6 @@ cc_library_static {
     static_libs: [
         "libkeymaster_portable",
         "libkeymint_support",
-        "libkeystore-engine",
     ],
     shared_libs: [
         "libbase",
diff --git a/keystore2/test_utils/ffi_test_utils.cpp b/keystore2/test_utils/ffi_test_utils.cpp
index ea030692..056c6e18 100644
--- a/keystore2/test_utils/ffi_test_utils.cpp
+++ b/keystore2/test_utils/ffi_test_utils.cpp
@@ -22,9 +22,6 @@ using std::vector;
 #define LENGTH_MASK 0x80
 #define LENGTH_VALUE_MASK 0x7F
 
-/* EVP_PKEY_from_keystore is from system/security/keystore-engine. */
-extern "C" EVP_PKEY* EVP_PKEY_from_keystore(const char* key_id);
-
 typedef std::vector<uint8_t> certificate_t;
 
 /**
@@ -87,8 +84,6 @@ struct TEST_SECURE_KEY_WRAPPER_Delete {
     void operator()(TEST_SECURE_KEY_WRAPPER* p) { TEST_SECURE_KEY_WRAPPER_free(p); }
 };
 
-const std::string keystore2_grant_id_prefix("ks2_keystore-engine_grant_id:");
-
 string bin2hex(const vector<uint8_t>& data) {
     string retval;
     char nibble2hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
@@ -475,140 +470,6 @@ CxxResult createWrappedKey(rust::Vec<rust::u8> encrypted_secure_key,
     return cxx_result;
 }
 
-/**
- * Perform EC/RSA sign operation using `EVP_PKEY`.
- */
-bool performSignData(const char* data, size_t data_len, EVP_PKEY* pkey, unsigned char** signature,
-                     size_t* signature_len) {
-    // Create the signing context
-    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
-    if (md_ctx == NULL) {
-        LOG(ERROR) << "Failed to create signing context";
-        return false;
-    }
-
-    // Initialize the signing operation
-    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
-        LOG(ERROR) << "Failed to initialize signing operation";
-        EVP_MD_CTX_free(md_ctx);
-        return false;
-    }
-
-    // Sign the data
-    if (EVP_DigestSignUpdate(md_ctx, data, data_len) != 1) {
-        LOG(ERROR) << "Failed to sign data";
-        EVP_MD_CTX_free(md_ctx);
-        return false;
-    }
-
-    // Determine the length of the signature
-    if (EVP_DigestSignFinal(md_ctx, NULL, signature_len) != 1) {
-        LOG(ERROR) << "Failed to determine signature length";
-        EVP_MD_CTX_free(md_ctx);
-        return false;
-    }
-
-    // Allocate memory for the signature
-    *signature = (unsigned char*)malloc(*signature_len);
-    if (*signature == NULL) {
-        LOG(ERROR) << "Failed to allocate memory for the signature";
-        EVP_MD_CTX_free(md_ctx);
-        return false;
-    }
-
-    // Perform the final signing operation
-    if (EVP_DigestSignFinal(md_ctx, *signature, signature_len) != 1) {
-        LOG(ERROR) << "Failed to perform signing operation";
-        free(*signature);
-        EVP_MD_CTX_free(md_ctx);
-        return false;
-    }
-
-    EVP_MD_CTX_free(md_ctx);
-    return true;
-}
-
-/**
- * Perform EC/RSA verify operation using `EVP_PKEY`.
- */
-int performVerifySignature(const char* data, size_t data_len, EVP_PKEY* pkey,
-                           const unsigned char* signature, size_t signature_len) {
-    // Create the verification context
-    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
-    if (md_ctx == NULL) {
-        LOG(ERROR) << "Failed to create verification context";
-        return false;
-    }
-
-    // Initialize the verification operation
-    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
-        LOG(ERROR) << "Failed to initialize verification operation";
-        EVP_MD_CTX_free(md_ctx);
-        return false;
-    }
-
-    // Verify the data
-    if (EVP_DigestVerifyUpdate(md_ctx, data, data_len) != 1) {
-        LOG(ERROR) << "Failed to verify data";
-        EVP_MD_CTX_free(md_ctx);
-        return false;
-    }
-
-    // Perform the verification operation
-    int ret = EVP_DigestVerifyFinal(md_ctx, signature, signature_len);
-    EVP_MD_CTX_free(md_ctx);
-
-    return ret == 1;
-}
-
-/**
- * Extract the `EVP_PKEY` for the given KeyMint Key and perform Sign/Verify operations
- * using extracted `EVP_PKEY`.
- */
-bool performCryptoOpUsingKeystoreEngine(int64_t grant_id) {
-    const int KEY_ID_LEN = 20;
-    char key_id[KEY_ID_LEN] = "";
-    snprintf(key_id, KEY_ID_LEN, "%" PRIx64, grant_id);
-    std::string str_key = std::string(keystore2_grant_id_prefix) + key_id;
-    bool result = false;
-
-#if defined(OPENSSL_IS_BORINGSSL)
-    EVP_PKEY* evp = EVP_PKEY_from_keystore(str_key.c_str());
-    if (!evp) {
-        LOG(ERROR) << "Error while loading a key from keystore-engine";
-        return false;
-    }
-
-    int algo_type = EVP_PKEY_id(evp);
-    if (algo_type != EVP_PKEY_RSA && algo_type != EVP_PKEY_EC) {
-        LOG(ERROR) << "Unsupported Algorithm. Only RSA and EC are allowed.";
-        EVP_PKEY_free(evp);
-        return false;
-    }
-
-    unsigned char* signature = NULL;
-    size_t signature_len = 0;
-    const char* INPUT_DATA = "MY MESSAGE FOR SIGN";
-    size_t data_len = strlen(INPUT_DATA);
-    if (!performSignData(INPUT_DATA, data_len, evp, &signature, &signature_len)) {
-        LOG(ERROR) << "Failed to sign data";
-        EVP_PKEY_free(evp);
-        return false;
-    }
-
-    result = performVerifySignature(INPUT_DATA, data_len, evp, signature, signature_len);
-    if (!result) {
-        LOG(ERROR) << "Signature verification failed";
-    } else {
-        LOG(INFO) << "Signature verification success";
-    }
-
-    free(signature);
-    EVP_PKEY_free(evp);
-#endif
-    return result;
-}
-
 CxxResult getValueFromAttestRecord(rust::Vec<rust::u8> cert_buf, int32_t tag,
                                    int32_t expected_sec_level) {
     CxxResult cxx_result{};
diff --git a/keystore2/test_utils/ffi_test_utils.hpp b/keystore2/test_utils/ffi_test_utils.hpp
index c4db1ba4..081718cb 100644
--- a/keystore2/test_utils/ffi_test_utils.hpp
+++ b/keystore2/test_utils/ffi_test_utils.hpp
@@ -8,7 +8,6 @@ CxxResult createWrappedKey(rust::Vec<rust::u8> encrypted_secure_key,
                            rust::Vec<rust::u8> encrypted_transport_key, rust::Vec<rust::u8> iv,
                            rust::Vec<rust::u8> tag);
 CxxResult buildAsn1DerEncodedWrappedKeyDescription();
-bool performCryptoOpUsingKeystoreEngine(int64_t grant_id);
 CxxResult getValueFromAttestRecord(rust::Vec<rust::u8> cert_buf, int32_t tag,
                                    int32_t expected_sec_level);
 uint32_t getOsVersion();
diff --git a/keystore2/test_utils/ffi_test_utils.rs b/keystore2/test_utils/ffi_test_utils.rs
index 1ccdcc81..9eb8368a 100644
--- a/keystore2/test_utils/ffi_test_utils.rs
+++ b/keystore2/test_utils/ffi_test_utils.rs
@@ -36,7 +36,6 @@ mod ffi {
             tag: Vec<u8>,
         ) -> CxxResult;
         fn buildAsn1DerEncodedWrappedKeyDescription() -> CxxResult;
-        fn performCryptoOpUsingKeystoreEngine(grant_id: i64) -> bool;
         fn getValueFromAttestRecord(
             cert_buf: Vec<u8>,
             tag: i32,
@@ -106,15 +105,6 @@ pub fn create_wrapped_key_additional_auth_data() -> Result<Vec<u8>, Error> {
     get_result(ffi::buildAsn1DerEncodedWrappedKeyDescription())
 }
 
-/// Performs crypto operation using Keystore-Engine APIs.
-pub fn perform_crypto_op_using_keystore_engine(grant_id: i64) -> Result<bool, Error> {
-    if ffi::performCryptoOpUsingKeystoreEngine(grant_id) {
-        return Ok(true);
-    }
-
-    Err(Error::Keystore2EngineOpFailed)
-}
-
 /// Get the value of the given `Tag` from attestation record.
 pub fn get_value_from_attest_record(
     cert_buf: &[u8],
diff --git a/keystore2/test_utils/lib.rs b/keystore2/test_utils/lib.rs
index 8e74f92b..3456aca8 100644
--- a/keystore2/test_utils/lib.rs
+++ b/keystore2/test_utils/lib.rs
@@ -14,11 +14,11 @@
 
 //! Implements TempDir which aids in creating an cleaning up temporary directories for testing.
 
+use log::info;
 use std::fs::{create_dir, remove_dir_all};
 use std::io::ErrorKind;
 use std::path::{Path, PathBuf};
 use std::{env::temp_dir, ops::Deref};
-
 use android_system_keystore2::aidl::android::system::keystore2::{
     IKeystoreService::IKeystoreService,
     IKeystoreSecurityLevel::IKeystoreSecurityLevel, KeyDescriptor::KeyDescriptor,
@@ -88,7 +88,7 @@ impl TempDir {
     #[allow(dead_code)]
     pub fn do_not_drop(&mut self) {
         println!("Disabled automatic cleanup for: {:?}", self.path);
-        log::info!("Disabled automatic cleanup for: {:?}", self.path);
+        info!("Disabled automatic cleanup for: {:?}", self.path);
         self.do_drop = false;
     }
 }
diff --git a/keystore2/tests/Android.bp b/keystore2/tests/Android.bp
index 8ec52389..87bf42b6 100644
--- a/keystore2/tests/Android.bp
+++ b/keystore2/tests/Android.bp
@@ -28,12 +28,6 @@ rust_test {
         "keymint_use_latest_hal_aidl_rust",
         "keystore2_use_latest_aidl_rust",
     ],
-    static_libs: [
-        // Also include static_libs for the NDK variants so that they are available
-        // for dependencies.
-        "android.system.keystore2-V5-ndk",
-        "android.hardware.security.keymint-V4-ndk",
-    ],
     srcs: ["keystore2_client_tests.rs"],
     test_suites: [
         "automotive-sdv-tests",
diff --git a/keystore2/tests/keystore-engine/Android.bp b/keystore2/tests/keystore-engine/Android.bp
new file mode 100644
index 00000000..01d89679
--- /dev/null
+++ b/keystore2/tests/keystore-engine/Android.bp
@@ -0,0 +1,62 @@
+// Copyright 2022, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+rust_test {
+    name: "keystore2_engine_tests",
+    defaults: [
+        "keymint_use_latest_hal_aidl_rust",
+        "keystore2_use_latest_aidl_rust",
+    ],
+    srcs: ["engine_tests.rs"],
+    test_suites: [
+        "general-tests",
+    ],
+    test_config: "AndroidTestEngine.xml",
+
+    rustlibs: [
+        "libbinder_rs",
+        "libkeystore2_test_utils",
+        "libopenssl",
+        "librustutils",
+    ],
+    static_libs: [
+        "libkeystore2_ffi_engine",
+        "libkeystore-engine",
+        "libkeymaster_portable",
+        "libkeymint_support",
+        // Also need the -ndk variants because libkeystore-engine depends on them.
+        // TODO: figure out why using the ".._use_latest_aidl_ndk_static" defaults doesn't work.
+        "android.system.keystore2-V5-ndk",
+        "android.hardware.security.keymint-V4-ndk",
+    ],
+    require_root: true,
+}
+
+cc_library_static {
+    name: "libkeystore2_ffi_engine",
+    srcs: ["ffi_engine.cpp"],
+    defaults: [
+        "keymint_use_latest_hal_aidl_ndk_static",
+        "keystore2_use_latest_aidl_ndk_static",
+    ],
+    static_libs: [
+        "libkeystore-engine",
+        "libkeymaster_portable",
+        "libkeymint_support",
+    ],
+    shared_libs: [
+        "libbase",
+        "libcrypto",
+    ],
+}
diff --git a/keystore2/tests/keystore-engine/AndroidTestEngine.xml b/keystore2/tests/keystore-engine/AndroidTestEngine.xml
new file mode 100644
index 00000000..eb8748a9
--- /dev/null
+++ b/keystore2/tests/keystore-engine/AndroidTestEngine.xml
@@ -0,0 +1,39 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2022 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<configuration description="Config to run keystore2_engine_tests device tests.">
+
+    <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer">
+    </target_preparer>
+
+    <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
+        <option name="cleanup" value="true" />
+        <option
+            name="push"
+            value="keystore2_engine_tests->/data/local/tmp/keystore2_engine_tests"
+        />
+    </target_preparer>
+
+    <test class="com.android.tradefed.testtype.rust.RustBinaryTest" >
+        <option name="test-device-path" value="/data/local/tmp" />
+        <option name="module-name" value="keystore2_engine_tests" />
+        <!-- When we run run multiple tests by default they run in parallel.
+          This will create issue as we create various child/user contexts
+          in a test leading to issues with IPC.
+          Serializing tests with below configuration to avoid IPC issues.
+        -->
+        <option name="native-test-flag" value="--test-threads=1" />
+    </test>
+</configuration>
diff --git a/keystore2/tests/keystore2_client_keystore_engine_tests.rs b/keystore2/tests/keystore-engine/engine_tests.rs
similarity index 88%
rename from keystore2/tests/keystore2_client_keystore_engine_tests.rs
rename to keystore2/tests/keystore-engine/engine_tests.rs
index a4d7f2cb..e41ee980 100644
--- a/keystore2/tests/keystore2_client_keystore_engine_tests.rs
+++ b/keystore2/tests/keystore-engine/engine_tests.rs
@@ -12,6 +12,17 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+//! This crate tests the keystore-engine library.
+//!
+//! The keystore-engine library provides a BoringSSL crypto engine where private
+//! key operations are performed by Android Keystore (i.e. via the `IKeystoreService`
+//! AIDL interface).  This allows some system components to use the BoringSSL API
+//! from C++ code, but still have the underlying key material held in secure hardware.
+//!
+//! The keystore-engine library is not widely exposed, nor is it vendor stable, so
+//! these tests are separate from the general tests of `IKeystoreService` (which _is_
+//! vendor-stable).
+
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, Digest::Digest, EcCurve::EcCurve, KeyPurpose::KeyPurpose,
     PaddingMode::PaddingMode,
@@ -20,13 +31,28 @@ use android_system_keystore2::aidl::android::system::keystore2::{
     Domain::Domain, IKeystoreService::IKeystoreService, KeyDescriptor::KeyDescriptor,
     KeyPermission::KeyPermission,
 };
-use keystore2_test_utils::ffi_test_utils::perform_crypto_op_using_keystore_engine;
 use keystore2_test_utils::{
-    authorizations::AuthSetBuilder, get_keystore_service, run_as, SecLevel,
+    authorizations::AuthSetBuilder, get_keystore_service, key_generations::Error, run_as, SecLevel,
 };
 use openssl::x509::X509;
 use rustutils::users::AID_USER_OFFSET;
 
+extern "C" {
+    // In ffi_engine.{cpp,hpp}
+    pub fn performCryptoOpUsingKeystoreEngine(grant_id: i64) -> bool;
+}
+
+/// Performs crypto operation using Keystore-Engine APIs.
+pub fn perform_crypto_op_using_keystore_engine(grant_id: i64) -> Result<(), Error> {
+    // SAFETY: no memory passed over FFI boundary.
+    let success = unsafe { performCryptoOpUsingKeystoreEngine(grant_id) };
+    if success {
+        Ok(())
+    } else {
+        Err(Error::Keystore2EngineOpFailed)
+    }
+}
+
 fn generate_rsa_key_and_grant_to_user(
     sl: &SecLevel,
     alias: &str,
@@ -137,7 +163,7 @@ fn perform_crypto_op_using_granted_key(
     grant_key_nspace: i64,
 ) {
     // Load the granted key from Keystore2-Engine API and perform crypto operations.
-    assert!(perform_crypto_op_using_keystore_engine(grant_key_nspace).unwrap());
+    assert!(perform_crypto_op_using_keystore_engine(grant_key_nspace).is_ok());
 
     // Delete the granted key.
     keystore2
diff --git a/keystore2/tests/keystore-engine/ffi_engine.cpp b/keystore2/tests/keystore-engine/ffi_engine.cpp
new file mode 100644
index 00000000..47cfacf5
--- /dev/null
+++ b/keystore2/tests/keystore-engine/ffi_engine.cpp
@@ -0,0 +1,149 @@
+#include "ffi_engine.hpp"
+
+#include <android-base/logging.h>
+#include <keymaster/km_openssl/openssl_err.h>
+#include <keymaster/km_openssl/openssl_utils.h>
+
+#include <openssl/mem.h>
+
+/* EVP_PKEY_from_keystore is from system/security/keystore-engine. */
+extern "C" EVP_PKEY* EVP_PKEY_from_keystore(const char* key_id);
+
+namespace {
+
+const std::string keystore2_grant_id_prefix("ks2_keystore-engine_grant_id:");
+
+/**
+ * Perform EC/RSA verify operation using `EVP_PKEY`.
+ */
+int performVerifySignature(const char* data, size_t data_len, EVP_PKEY* pkey,
+                           const unsigned char* signature, size_t signature_len) {
+    // Create the verification context
+    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
+    if (md_ctx == NULL) {
+        LOG(ERROR) << "Failed to create verification context";
+        return false;
+    }
+
+    // Initialize the verification operation
+    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
+        LOG(ERROR) << "Failed to initialize verification operation";
+        EVP_MD_CTX_free(md_ctx);
+        return false;
+    }
+
+    // Verify the data
+    if (EVP_DigestVerifyUpdate(md_ctx, data, data_len) != 1) {
+        LOG(ERROR) << "Failed to verify data";
+        EVP_MD_CTX_free(md_ctx);
+        return false;
+    }
+
+    // Perform the verification operation
+    int ret = EVP_DigestVerifyFinal(md_ctx, signature, signature_len);
+    EVP_MD_CTX_free(md_ctx);
+
+    return ret == 1;
+}
+
+/**
+ * Perform EC/RSA sign operation using `EVP_PKEY`.
+ */
+bool performSignData(const char* data, size_t data_len, EVP_PKEY* pkey, unsigned char** signature,
+                     size_t* signature_len) {
+    // Create the signing context
+    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
+    if (md_ctx == NULL) {
+        LOG(ERROR) << "Failed to create signing context";
+        return false;
+    }
+
+    // Initialize the signing operation
+    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
+        LOG(ERROR) << "Failed to initialize signing operation";
+        EVP_MD_CTX_free(md_ctx);
+        return false;
+    }
+
+    // Sign the data
+    if (EVP_DigestSignUpdate(md_ctx, data, data_len) != 1) {
+        LOG(ERROR) << "Failed to sign data";
+        EVP_MD_CTX_free(md_ctx);
+        return false;
+    }
+
+    // Determine the length of the signature
+    if (EVP_DigestSignFinal(md_ctx, NULL, signature_len) != 1) {
+        LOG(ERROR) << "Failed to determine signature length";
+        EVP_MD_CTX_free(md_ctx);
+        return false;
+    }
+
+    // Allocate memory for the signature
+    *signature = (unsigned char*)malloc(*signature_len);
+    if (*signature == NULL) {
+        LOG(ERROR) << "Failed to allocate memory for the signature";
+        EVP_MD_CTX_free(md_ctx);
+        return false;
+    }
+
+    // Perform the final signing operation
+    if (EVP_DigestSignFinal(md_ctx, *signature, signature_len) != 1) {
+        LOG(ERROR) << "Failed to perform signing operation";
+        free(*signature);
+        EVP_MD_CTX_free(md_ctx);
+        return false;
+    }
+
+    EVP_MD_CTX_free(md_ctx);
+    return true;
+}
+
+}  // namespace
+
+/**
+ * Extract the `EVP_PKEY` for the given KeyMint Key and perform Sign/Verify operations
+ * using extracted `EVP_PKEY`.
+ */
+extern "C" bool performCryptoOpUsingKeystoreEngine(int64_t grant_id) {
+    const int KEY_ID_LEN = 20;
+    char key_id[KEY_ID_LEN] = "";
+    snprintf(key_id, KEY_ID_LEN, "%" PRIx64, grant_id);
+    std::string str_key = std::string(keystore2_grant_id_prefix) + key_id;
+    bool result = false;
+
+    EVP_PKEY* evp = EVP_PKEY_from_keystore(str_key.c_str());
+    if (!evp) {
+        LOG(ERROR) << "Error while loading a key from keystore-engine";
+        return false;
+    }
+
+    int algo_type = EVP_PKEY_id(evp);
+    if (algo_type != EVP_PKEY_RSA && algo_type != EVP_PKEY_EC) {
+        LOG(ERROR) << "Unsupported Algorithm. Only RSA and EC are allowed.";
+        EVP_PKEY_free(evp);
+        return false;
+    }
+
+    unsigned char* signature = NULL;
+    size_t signature_len = 0;
+    const char* INPUT_DATA = "MY MESSAGE FOR SIGN";
+    size_t data_len = strlen(INPUT_DATA);
+    if (!performSignData(INPUT_DATA, data_len, evp, &signature, &signature_len)) {
+        LOG(ERROR) << "Failed to sign data";
+        EVP_PKEY_free(evp);
+        return false;
+    }
+
+    result = performVerifySignature(INPUT_DATA, data_len, evp, signature, signature_len);
+    if (!result) {
+        LOG(ERROR) << "Signature verification failed";
+    } else {
+        LOG(INFO) << "Signature verification success";
+    }
+
+    free(signature);
+    EVP_PKEY_free(evp);
+
+    return result;
+}
diff --git a/keystore2/tests/keystore-engine/ffi_engine.hpp b/keystore2/tests/keystore-engine/ffi_engine.hpp
new file mode 100644
index 00000000..b61b6d59
--- /dev/null
+++ b/keystore2/tests/keystore-engine/ffi_engine.hpp
@@ -0,0 +1,5 @@
+#pragma once
+
+#include <stdint.h>
+
+extern "C" bool performCryptoOpUsingKeystoreEngine(int64_t grant_id);
diff --git a/keystore2/tests/keystore2_client_3des_key_tests.rs b/keystore2/tests/keystore2_client_3des_key_tests.rs
index 4cb81d14..575b896e 100644
--- a/keystore2/tests/keystore2_client_3des_key_tests.rs
+++ b/keystore2/tests/keystore2_client_3des_key_tests.rs
@@ -13,7 +13,8 @@
 // limitations under the License.
 
 use crate::keystore2_client_test_utils::{
-    perform_sample_sym_key_decrypt_op, perform_sample_sym_key_encrypt_op, SAMPLE_PLAIN_TEXT,
+    delete_app_key, perform_sample_sym_key_decrypt_op, perform_sample_sym_key_encrypt_op,
+    SAMPLE_PLAIN_TEXT,
 };
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, BlockMode::BlockMode, ErrorCode::ErrorCode, KeyPurpose::KeyPurpose,
@@ -64,6 +65,7 @@ fn create_3des_key_and_operation(
         &key_metadata.key,
     )
     .unwrap();
+    delete_app_key(&sl.keystore2, &alias).unwrap();
     assert!(plain_text.is_some());
     assert_eq!(plain_text.unwrap(), SAMPLE_PLAIN_TEXT.to_vec());
     Ok(())
@@ -152,6 +154,7 @@ fn keystore2_3des_key_fails_missing_padding() {
         &op_params,
         false,
     ));
+    delete_app_key(&sl.keystore2, alias).unwrap();
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_PADDING_MODE), result.unwrap_err());
 }
@@ -190,6 +193,7 @@ fn keystore2_3des_key_encrypt_fails_invalid_input_length() {
     // length of input.
     let invalid_block_size_msg = b"my message 111";
     let result = key_generations::map_ks_error(op.finish(Some(invalid_block_size_msg), None));
+    delete_app_key(&sl.keystore2, alias).unwrap();
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INVALID_INPUT_LENGTH), result.unwrap_err());
 }
diff --git a/keystore2/tests/keystore2_client_aes_key_tests.rs b/keystore2/tests/keystore2_client_aes_key_tests.rs
index 7128911d..a3c4236a 100644
--- a/keystore2/tests/keystore2_client_aes_key_tests.rs
+++ b/keystore2/tests/keystore2_client_aes_key_tests.rs
@@ -13,7 +13,8 @@
 // limitations under the License.
 
 use crate::keystore2_client_test_utils::{
-    perform_sample_sym_key_decrypt_op, perform_sample_sym_key_encrypt_op, SAMPLE_PLAIN_TEXT,
+    delete_app_key, perform_sample_sym_key_decrypt_op, perform_sample_sym_key_encrypt_op,
+    SAMPLE_PLAIN_TEXT,
 };
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, BlockMode::BlockMode, ErrorCode::ErrorCode, KeyPurpose::KeyPurpose,
@@ -67,6 +68,7 @@ fn create_aes_key_and_operation(
         &key_metadata.key,
     )
     .unwrap();
+    delete_app_key(&sl.keystore2, &alias).unwrap();
     assert!(plain_text.is_some());
     assert_eq!(plain_text.unwrap(), SAMPLE_PLAIN_TEXT.to_vec());
     Ok(())
@@ -246,6 +248,7 @@ fn keystore2_aes_key_op_fails_multi_block_modes() {
         &op_params,
         false,
     ));
+    delete_app_key(&sl.keystore2, alias).unwrap();
     assert!(result.is_err());
     assert!(matches!(
         result.unwrap_err(),
@@ -299,6 +302,7 @@ fn keystore2_aes_key_op_fails_multi_padding_modes() {
         &op_params,
         false,
     ));
+    delete_app_key(&sl.keystore2, alias).unwrap();
     assert!(result.is_err());
     assert!(matches!(
         result.unwrap_err(),
@@ -335,6 +339,7 @@ fn keystore2_aes_key_op_fails_incompatible_padding() {
         None,
         &key_metadata.key,
     ));
+    delete_app_key(&sl.keystore2, alias).unwrap();
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_PADDING_MODE), result.unwrap_err());
 }
@@ -366,6 +371,7 @@ fn keystore2_aes_key_op_fails_incompatible_blockmode() {
         None,
         &key_metadata.key,
     ));
+    delete_app_key(&sl.keystore2, alias).unwrap();
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_BLOCK_MODE), result.unwrap_err());
 }
@@ -467,6 +473,7 @@ fn keystore2_aes_key_op_fails_nonce_prohibited() {
         None,
         &key_metadata.key,
     ));
+    delete_app_key(&sl.keystore2, alias).unwrap();
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::CALLER_NONCE_PROHIBITED), result.unwrap_err());
 }
diff --git a/keystore2/tests/keystore2_client_attest_key_tests.rs b/keystore2/tests/keystore2_client_attest_key_tests.rs
index 553add07..773c6b9a 100644
--- a/keystore2/tests/keystore2_client_attest_key_tests.rs
+++ b/keystore2/tests/keystore2_client_attest_key_tests.rs
@@ -66,7 +66,7 @@ fn keystore2_attest_rsa_signing_key_success() {
             &sl,
             Domain::APP,
             -1,
-            Some(sign_key_alias),
+            Some(sign_key_alias.clone()),
             &key_generations::KeyParams {
                 key_size: 2048,
                 purpose: vec![KeyPurpose::SIGN, KeyPurpose::VERIFY],
@@ -87,6 +87,8 @@ fn keystore2_attest_rsa_signing_key_success() {
         cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
         cert_chain.extend(attestation_key_metadata.certificateChain.as_ref().unwrap());
         validate_certchain(&cert_chain).expect("Error while validating cert chain");
+        sl.keystore2.deleteKey(&attestation_key_metadata.key).unwrap();
+        sl.keystore2.deleteKey(&sign_key_metadata.key).unwrap();
     }
 }
 
@@ -141,6 +143,8 @@ fn keystore2_attest_rsa_encrypt_key_success() {
         cert_chain.extend(attestation_key_metadata.certificateChain.as_ref().unwrap());
 
         validate_certchain(&cert_chain).expect("Error while validating cert chain.");
+        sl.keystore2.deleteKey(&attestation_key_metadata.key).unwrap();
+        sl.keystore2.deleteKey(&decrypt_key_metadata.key).unwrap();
     }
 }
 
@@ -183,6 +187,8 @@ fn keystore2_attest_ec_key_success() {
         cert_chain.extend(attestation_key_metadata.certificateChain.as_ref().unwrap());
 
         validate_certchain(&cert_chain).expect("Error while validating cert chain.");
+        sl.keystore2.deleteKey(&attestation_key_metadata.key).unwrap();
+        sl.keystore2.deleteKey(&ec_key_metadata.key).unwrap();
     }
 }
 
@@ -248,6 +254,8 @@ fn keystore2_attest_rsa_signing_key_with_ec_25519_key_success() {
     cert_chain.extend(attestation_key_metadata.certificate.as_ref().unwrap());
     cert_chain.extend(attestation_key_metadata.certificateChain.as_ref().unwrap());
     validate_certchain(&cert_chain).expect("Error while validating cert chain");
+    sl.keystore2.deleteKey(&attestation_key_metadata.key).unwrap();
+    sl.keystore2.deleteKey(&sign_key_metadata.key).unwrap();
 }
 
 /// Try to generate RSA attestation key with multiple purposes. Test should fail with error code
@@ -380,6 +388,7 @@ fn keystore2_attest_key_fails_missing_challenge() {
         },
         Some(&attestation_key_metadata.key),
     ));
+    sl.keystore2.deleteKey(&attestation_key_metadata.key).unwrap();
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::ATTESTATION_CHALLENGE_MISSING), result.unwrap_err());
 }
@@ -417,6 +426,7 @@ fn keystore2_attest_rsa_key_with_non_attest_key_fails_incompat_purpose_error() {
         },
         Some(&non_attest_key_metadata.key),
     ));
+    sl.keystore2.deleteKey(&non_attest_key_metadata.key).unwrap();
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_PURPOSE), result.unwrap_err());
 }
@@ -460,6 +470,7 @@ fn keystore2_attest_rsa_key_with_symmetric_key_fails_sys_error() {
         },
         Some(&sym_key_metadata.key),
     ));
+    sl.keystore2.deleteKey(&sym_key_metadata.key).unwrap();
     assert!(result.is_err());
     assert_eq!(Error::Rc(ResponseCode::INVALID_ARGUMENT), result.unwrap_err());
 }
@@ -544,8 +555,10 @@ fn generate_attested_key_with_device_attest_ids(algorithm: Algorithm) {
             SecurityLevel::TRUSTED_ENVIRONMENT,
         )
         .expect("Attest id verification failed.");
+        sl.keystore2.deleteKey(&key_metadata.key).unwrap();
         assert_eq!(attest_id_value, value);
     }
+    sl.keystore2.deleteKey(&attest_key_metadata.key).unwrap();
 }
 
 #[test]
@@ -595,7 +608,7 @@ fn keystore2_attest_key_fails_with_invalid_attestation_id() {
         let result = key_generations::map_ks_error(key_generations::generate_key_with_attest_id(
             &sl,
             Algorithm::EC,
-            Some(ec_key_alias),
+            Some(ec_key_alias.clone()),
             att_challenge,
             &attest_key_metadata.key,
             attest_id,
@@ -605,6 +618,7 @@ fn keystore2_attest_key_fails_with_invalid_attestation_id() {
         assert!(result.is_err());
         device_id_attestation_check_acceptable_error(attest_id, result.unwrap_err());
     }
+    sl.keystore2.deleteKey(&attest_key_metadata.key).unwrap();
 }
 
 ///  If `DEVICE_ID_ATTESTATION_FEATURE` is not supported then test tries to generate an attested
@@ -636,7 +650,7 @@ fn keystore2_attest_key_without_attestation_id_support_fails_with_cannot_attest_
         let result = key_generations::map_ks_error(key_generations::generate_key_with_attest_id(
             &sl,
             Algorithm::RSA,
-            Some(key_alias),
+            Some(key_alias.clone()),
             att_challenge,
             &attest_key_metadata.key,
             attest_id,
@@ -648,6 +662,7 @@ fn keystore2_attest_key_without_attestation_id_support_fails_with_cannot_attest_
         );
         assert_eq!(result.unwrap_err(), Error::Km(ErrorCode::CANNOT_ATTEST_IDS));
     }
+    sl.keystore2.deleteKey(&attest_key_metadata.key).unwrap();
 }
 
 /// Try to generate an attestation key from user context with UID other than AID_SYSTEM or AID_ROOT
diff --git a/keystore2/tests/keystore2_client_ec_key_tests.rs b/keystore2/tests/keystore2_client_ec_key_tests.rs
index 17a88e74..193940bd 100644
--- a/keystore2/tests/keystore2_client_ec_key_tests.rs
+++ b/keystore2/tests/keystore2_client_ec_key_tests.rs
@@ -332,6 +332,7 @@ fn keystore2_ec_25519_generate_key_success() {
             &op_response.iOperation.unwrap()
         ))
     );
+    sl.keystore2.deleteKey(&key_metadata.key).unwrap();
 }
 
 /// Generate EC keys with curve `CURVE_25519` and digest modes `MD5, SHA1, SHA-2 224, SHA-2 256,
@@ -375,6 +376,7 @@ fn keystore2_ec_25519_generate_key_fail() {
             assert!(result.is_err(), "unexpected success for digest {digest:?}");
             assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_DIGEST), result.unwrap_err());
         }
+        sl.keystore2.deleteKey(&key_metadata.key).unwrap();
     }
 }
 
@@ -408,6 +410,7 @@ fn keystore2_create_op_with_incompatible_key_digest() {
         assert!(result.is_err());
         assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_DIGEST), result.unwrap_err());
     }
+    sl.keystore2.deleteKey(&key_metadata.key).unwrap();
 }
 
 /// Generate a key in client#1 and try to use it in other client#2.
diff --git a/keystore2/tests/keystore2_client_hmac_key_tests.rs b/keystore2/tests/keystore2_client_hmac_key_tests.rs
index 76780a0b..47c667c4 100644
--- a/keystore2/tests/keystore2_client_hmac_key_tests.rs
+++ b/keystore2/tests/keystore2_client_hmac_key_tests.rs
@@ -12,7 +12,7 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use crate::keystore2_client_test_utils::perform_sample_sign_operation;
+use crate::keystore2_client_test_utils::{delete_app_key, perform_sample_sign_operation};
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Algorithm::Algorithm, Digest::Digest, ErrorCode::ErrorCode, KeyPurpose::KeyPurpose,
 };
@@ -73,6 +73,7 @@ fn keystore2_hmac_key_op_success() {
             Ok(()),
             create_hmac_key_and_operation(&sl, &alias, key_size, mac_len, min_mac_len, digest,)
         );
+        delete_app_key(&sl.keystore2, &alias).unwrap();
     }
 }
 
@@ -97,6 +98,7 @@ fn keystore2_hmac_gen_keys_fails_expect_unsupported_key_size() {
 
         match result {
             Ok(_) => {
+                delete_app_key(&sl.keystore2, &alias).unwrap();
                 assert!((key_size >= 64 && key_size % 8 == 0));
             }
             Err(e) => {
@@ -126,6 +128,7 @@ fn keystore2_hmac_gen_keys_fails_expect_unsupported_min_mac_length() {
             digest,
         )) {
             Ok(_) => {
+                delete_app_key(&sl.keystore2, &alias).unwrap();
                 assert!((min_mac_len >= 64 && min_mac_len % 8 == 0));
             }
             Err(e) => {
@@ -251,6 +254,7 @@ fn keystore2_hmac_key_op_with_mac_len_greater_than_digest_len_fail() {
 
         assert!(result.is_err());
         assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_MAC_LENGTH), result.unwrap_err());
+        delete_app_key(&sl.keystore2, &alias).unwrap();
     }
 }
 
@@ -281,5 +285,6 @@ fn keystore2_hmac_key_op_with_mac_len_less_than_min_mac_len_fail() {
 
         assert!(result.is_err());
         assert_eq!(Error::Km(ErrorCode::INVALID_MAC_LENGTH), result.unwrap_err());
+        delete_app_key(&sl.keystore2, &alias).unwrap();
     }
 }
diff --git a/keystore2/tests/keystore2_client_import_keys_tests.rs b/keystore2/tests/keystore2_client_import_keys_tests.rs
index f3a267bb..9469bc6b 100644
--- a/keystore2/tests/keystore2_client_import_keys_tests.rs
+++ b/keystore2/tests/keystore2_client_import_keys_tests.rs
@@ -13,7 +13,7 @@
 // limitations under the License.
 
 use crate::keystore2_client_test_utils::{
-    encrypt_secure_key, encrypt_transport_key, get_vsr_api_level,
+    delete_app_key, encrypt_secure_key, encrypt_transport_key, get_vsr_api_level,
     perform_sample_asym_sign_verify_op, perform_sample_hmac_sign_verify_op,
     perform_sample_sym_key_decrypt_op, perform_sample_sym_key_encrypt_op, SAMPLE_PLAIN_TEXT,
 };
@@ -147,9 +147,11 @@ fn keystore2_rsa_import_key_success() {
         &sl,
         Domain::APP,
         -1,
-        Some(alias),
+        Some(alias.clone()),
         import_params,
     );
+
+    delete_app_key(&sl.keystore2, &alias).unwrap();
 }
 
 /// Import RSA key without providing key-size and public exponent in import key parameters list.
@@ -177,9 +179,10 @@ fn keystore2_rsa_import_key_determine_key_size_and_pub_exponent() {
         &sl,
         Domain::APP,
         -1,
-        Some(alias),
+        Some(alias.clone()),
         import_params,
     );
+    delete_app_key(&sl.keystore2, &alias).unwrap();
 }
 
 /// Try to import RSA key with wrong key size as import-key-parameter. Test should fail to import
@@ -315,11 +318,17 @@ fn keystore2_import_ec_key_success() {
         .cert_not_before(0)
         .cert_not_after(253402300799000);
 
-    let key_metadata =
-        key_generations::import_ec_p_256_key(&sl, Domain::APP, -1, Some(alias), import_params)
-            .expect("Failed to import EC key.");
+    let key_metadata = key_generations::import_ec_p_256_key(
+        &sl,
+        Domain::APP,
+        -1,
+        Some(alias.clone()),
+        import_params,
+    )
+    .expect("Failed to import EC key.");
 
     perform_sample_asym_sign_verify_op(&sl.binder, &key_metadata, None, Some(Digest::SHA_2_256));
+    delete_app_key(&sl.keystore2, &alias).unwrap();
 }
 
 /// Try to import EC key with wrong ec-curve as import-key-parameter. Test should fail to import a
@@ -358,10 +367,11 @@ fn keystore2_import_aes_key_success() {
     let sl = SecLevel::tee();
 
     let alias = format!("ks_aes_key_test_import_1_{}{}", getuid(), 256);
-    let key_metadata = key_generations::import_aes_key(&sl, Domain::APP, -1, Some(alias))
+    let key_metadata = key_generations::import_aes_key(&sl, Domain::APP, -1, Some(alias.clone()))
         .expect("Failed to import AES key.");
 
     perform_sym_key_encrypt_decrypt_op(&sl.binder, &key_metadata);
+    delete_app_key(&sl.keystore2, &alias).unwrap();
 }
 
 /// Import 3DES key and verify key parameters. Try to create an operation using the imported key.
@@ -372,10 +382,11 @@ fn keystore2_import_3des_key_success() {
 
     let alias = format!("ks_3des_key_test_import_1_{}{}", getuid(), 168);
 
-    let key_metadata = key_generations::import_3des_key(&sl, Domain::APP, -1, Some(alias))
+    let key_metadata = key_generations::import_3des_key(&sl, Domain::APP, -1, Some(alias.clone()))
         .expect("Failed to import 3DES key.");
 
     perform_sym_key_encrypt_decrypt_op(&sl.binder, &key_metadata);
+    delete_app_key(&sl.keystore2, &alias).unwrap();
 }
 
 /// Import HMAC key and verify key parameters. Try to create an operation using the imported key.
@@ -386,10 +397,11 @@ fn keystore2_import_hmac_key_success() {
 
     let alias = format!("ks_hmac_key_test_import_1_{}", getuid());
 
-    let key_metadata = key_generations::import_hmac_key(&sl, Domain::APP, -1, Some(alias))
+    let key_metadata = key_generations::import_hmac_key(&sl, Domain::APP, -1, Some(alias.clone()))
         .expect("Failed to import HMAC key.");
 
     perform_sample_hmac_sign_verify_op(&sl.binder, &key_metadata.key);
+    delete_app_key(&sl.keystore2, &alias).unwrap();
 }
 
 /// This test creates a wrapped key data and imports it. Validates the imported wrapped key.
@@ -415,7 +427,7 @@ fn keystore2_create_wrapped_key_and_import_wrapped_key_success() {
     let wrapping_key_metadata = key_generations::import_wrapping_key(
         &sl,
         key_generations::RSA_2048_KEY,
-        Some(wrapping_key_alias),
+        Some(wrapping_key_alias.clone()),
     )
     .unwrap();
 
@@ -438,13 +450,15 @@ fn keystore2_create_wrapped_key_and_import_wrapped_key_success() {
     let secured_key_alias = format!("ks_wrapped_aes_key_{}", getuid());
     let secured_key_metadata = key_generations::import_wrapped_key(
         &sl,
-        Some(secured_key_alias),
+        Some(secured_key_alias.clone()),
         &wrapping_key_metadata,
         Some(wrapped_key_data.to_vec()),
     )
     .unwrap();
 
     perform_sym_key_encrypt_decrypt_op(&sl.binder, &secured_key_metadata);
+    delete_app_key(&sl.keystore2, &secured_key_alias).unwrap();
+    delete_app_key(&sl.keystore2, &wrapping_key_alias).unwrap();
 }
 
 /// Create a wrapped key data with invalid Additional Authenticated Data (AAD) and
@@ -471,7 +485,7 @@ fn keystore2_create_wrapped_key_with_invalid_aad_and_import_wrapped_key_fail() {
     let wrapping_key_metadata = key_generations::import_wrapping_key(
         &sl,
         key_generations::RSA_2048_KEY,
-        Some(wrapping_key_alias),
+        Some(wrapping_key_alias.clone()),
     )
     .unwrap();
 
@@ -500,6 +514,7 @@ fn keystore2_create_wrapped_key_with_invalid_aad_and_import_wrapped_key_fail() {
 
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::VERIFICATION_FAILED), result.unwrap_err());
+    delete_app_key(&sl.keystore2, &wrapping_key_alias).unwrap();
 }
 
 /// Import wrapped AES key and use it for crypto operations. Test should import wrapped key and
@@ -528,14 +543,16 @@ fn keystore2_import_wrapped_key_success() {
         &sl,
         Domain::APP,
         -1,
-        Some(alias),
-        Some(wrapping_key_alias),
+        Some(alias.clone()),
+        Some(wrapping_key_alias.clone()),
         wrapping_key_params,
     )
     .expect("Failed to import wrapped key.");
 
     // Try to perform operations using wrapped key.
     perform_sym_key_encrypt_decrypt_op(&sl.binder, &key_metadata);
+    delete_app_key(&sl.keystore2, &alias).unwrap();
+    delete_app_key(&sl.keystore2, &wrapping_key_alias).unwrap();
 }
 
 /// Import wrapping-key without specifying KeyPurpose::WRAP_KEY in import key parameters. Try to
@@ -568,12 +585,13 @@ fn keystore2_import_wrapped_key_fails_with_wrong_purpose() {
             Domain::APP,
             -1,
             Some(alias),
-            Some(wrapping_key_alias),
+            Some(wrapping_key_alias.clone()),
             wrapping_key_params,
         ));
 
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_PURPOSE), result.unwrap_err());
+    delete_app_key(&sl.keystore2, &wrapping_key_alias).unwrap();
 }
 
 /// Try to import wrapped key whose wrapping key is missing in Android Keystore.
diff --git a/keystore2/tests/keystore2_client_key_agreement_tests.rs b/keystore2/tests/keystore2_client_key_agreement_tests.rs
index 6744b60d..58e709ca 100644
--- a/keystore2/tests/keystore2_client_key_agreement_tests.rs
+++ b/keystore2/tests/keystore2_client_key_agreement_tests.rs
@@ -12,6 +12,7 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+use crate::skip_if_no_hw_curve25519_support;
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Digest::Digest, EcCurve::EcCurve, ErrorCode::ErrorCode, KeyPurpose::KeyPurpose,
 };
@@ -105,6 +106,7 @@ fn perform_ec_key_agreement(ec_curve: EcCurve) {
     let local_pub_key = local_key.public_key_to_der().unwrap();
 
     check_agreement(&sl.binder, &keymint_key.key, &keymint_pub_key, &local_key, &local_pub_key);
+    sl.keystore2.deleteKey(&keymint_key.key).unwrap();
 }
 
 test_ec_key_agree!(test_ec_p224_key_agreement, EcCurve::P_224);
@@ -117,6 +119,7 @@ test_ec_key_agree!(test_ec_p521_key_agreement, EcCurve::P_521);
 #[test]
 fn keystore2_ec_25519_agree_key_success() {
     let sl = SecLevel::tee();
+    skip_if_no_hw_curve25519_support!(sl);
 
     let alias = format!("ks_ec_25519_test_key_agree_{}", getuid());
     let keymint_key = key_generations::generate_ec_agree_key(
@@ -135,6 +138,7 @@ fn keystore2_ec_25519_agree_key_success() {
     let local_pub_key = local_key.public_key_to_der().unwrap();
 
     check_agreement(&sl.binder, &keymint_key.key, &keymint_pub_key, &local_key, &local_pub_key);
+    sl.keystore2.deleteKey(&keymint_key.key).unwrap();
 }
 
 /// Generate two EC keys with different curves and try to perform local ECDH. Since keys are using
@@ -142,6 +146,7 @@ fn keystore2_ec_25519_agree_key_success() {
 #[test]
 fn keystore2_ec_agree_key_with_different_curves_fail() {
     let sl = SecLevel::tee();
+    skip_if_no_hw_curve25519_support!(sl);
 
     let alias = format!("ks_test_key_agree_fail{}", getuid());
     let keymint_key = key_generations::generate_ec_agree_key(
@@ -167,4 +172,5 @@ fn keystore2_ec_agree_key_with_different_curves_fail() {
     let result = key_generations::map_ks_error(op.finish(Some(&local_pub_key), None));
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INVALID_ARGUMENT), result.unwrap_err());
+    sl.keystore2.deleteKey(&keymint_key.key).unwrap();
 }
diff --git a/keystore2/tests/keystore2_client_key_id_domain_tests.rs b/keystore2/tests/keystore2_client_key_id_domain_tests.rs
index 8f9191f3..74da6414 100644
--- a/keystore2/tests/keystore2_client_key_id_domain_tests.rs
+++ b/keystore2/tests/keystore2_client_key_id_domain_tests.rs
@@ -97,6 +97,7 @@ fn keystore2_find_key_with_key_id_as_domain() {
             &op_response.iOperation.unwrap()
         ))
     );
+    sl.keystore2.deleteKey(&key_metadata.key).unwrap();
 }
 
 /// Generate a key with an alias. Generate another key and bind it to the same alias.
@@ -164,6 +165,7 @@ fn keystore2_key_id_alias_rebind_verify_by_alias() {
             &op_response.iOperation.unwrap()
         ))
     );
+    sl.keystore2.deleteKey(&new_key_metadata.key).unwrap();
 }
 
 /// Generate a key with an alias. Load the generated key with `Domain::KEY_ID`. Generate another
@@ -250,4 +252,5 @@ fn keystore2_key_id_alias_rebind_verify_by_key_id() {
             &op_response.iOperation.unwrap()
         ))
     );
+    sl.keystore2.deleteKey(&new_key_metadata.key).unwrap();
 }
diff --git a/keystore2/tests/keystore2_client_list_entries_tests.rs b/keystore2/tests/keystore2_client_list_entries_tests.rs
index bb1d6cff..511ac01a 100644
--- a/keystore2/tests/keystore2_client_list_entries_tests.rs
+++ b/keystore2/tests/keystore2_client_list_entries_tests.rs
@@ -616,6 +616,8 @@ fn keystore2_list_entries_batched_validate_count_and_order_success() {
                 ALIAS_PREFIX.to_owned() + "_5",
             ],
         );
+
+        delete_all_entries(&sl.keystore2);
     };
 
     // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
diff --git a/keystore2/tests/keystore2_client_operation_tests.rs b/keystore2/tests/keystore2_client_operation_tests.rs
index 1f8396e2..d98567cd 100644
--- a/keystore2/tests/keystore2_client_operation_tests.rs
+++ b/keystore2/tests/keystore2_client_operation_tests.rs
@@ -13,8 +13,8 @@
 // limitations under the License.
 
 use crate::keystore2_client_test_utils::{
-    create_signing_operation, execute_op_run_as_child, perform_sample_sign_operation,
-    BarrierReached, ForcedOp, TestOutcome,
+    create_signing_operation, delete_app_key, delete_key, execute_op_run_as_child,
+    perform_sample_sign_operation, BarrierReached, ForcedOp, TestOutcome,
 };
 use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
     Digest::Digest, ErrorCode::ErrorCode, KeyPurpose::KeyPurpose,
@@ -154,9 +154,11 @@ fn keystore2_forced_op_after_backendbusy_test() {
             Digest::SHA_2_256,
             Domain::SELINUX,
             100,
-            Some(alias),
+            Some(alias.clone()),
         )
         .expect("Client failed to create forced operation after BACKEND_BUSY state.");
+        let sl = SecLevel::tee();
+        delete_key(&sl.keystore2, Domain::SELINUX, 100, Some(alias), None).unwrap();
     };
 
     // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
@@ -385,6 +387,7 @@ fn keystore2_ops_prune_test() {
         }
         _ => panic!("Operation should have created successfully."),
     }
+    sl.keystore2.deleteKey(&key_metadata.key).unwrap();
 }
 
 /// Try to create forced operations with various contexts -
@@ -412,10 +415,13 @@ fn keystore2_forced_op_perm_denied_test() {
                 Digest::SHA_2_256,
                 Domain::APP,
                 -1,
-                Some(alias),
+                Some(alias.clone()),
             ));
             assert!(result.is_err());
             assert_eq!(Error::Rc(ResponseCode::PERMISSION_DENIED), result.unwrap_err());
+
+            let sl = SecLevel::tee();
+            delete_app_key(&sl.keystore2, &alias).unwrap();
         };
 
         // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
@@ -444,9 +450,18 @@ fn keystore2_forced_op_success_test() {
             Digest::SHA_2_256,
             Domain::SELINUX,
             key_generations::SELINUX_VOLD_NAMESPACE,
-            Some(alias),
+            Some(alias.clone()),
         )
         .expect("Client with vold context failed to create forced operation.");
+        let sl = SecLevel::tee();
+        delete_key(
+            &sl.keystore2,
+            Domain::SELINUX,
+            key_generations::SELINUX_VOLD_NAMESPACE,
+            Some(alias),
+            None,
+        )
+        .unwrap();
     };
 
     // Safety: only one thread at this point (enforced by `AndroidTest.xml` setting
@@ -461,13 +476,14 @@ fn keystore2_forced_op_success_test() {
 /// when multiple threads try to access the operation handle at same time.
 #[test]
 fn keystore2_op_fails_operation_busy() {
+    let alias = "op_busy_alias_test_key";
     let op_response = create_signing_operation(
         ForcedOp(false),
         KeyPurpose::SIGN,
         Digest::SHA_2_256,
         Domain::APP,
         -1,
-        Some("op_busy_alias_test_key".to_string()),
+        Some(alias.to_string()),
     )
     .unwrap();
 
@@ -480,6 +496,9 @@ fn keystore2_op_fails_operation_busy() {
     let result2 = th_handle_2.join().unwrap();
 
     assert!(result1 || result2);
+
+    let sl = SecLevel::tee();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Create an operation and use it for performing sign operation. After completing the operation
@@ -487,13 +506,14 @@ fn keystore2_op_fails_operation_busy() {
 /// code `INVALID_OPERATION_HANDLE`.
 #[test]
 fn keystore2_abort_finalized_op_fail_test() {
+    let alias = "ks_op_abort_fail_test_key";
     let op_response = create_signing_operation(
         ForcedOp(false),
         KeyPurpose::SIGN,
         Digest::SHA_2_256,
         Domain::APP,
         -1,
-        Some("ks_op_abort_fail_test_key".to_string()),
+        Some(alias.to_string()),
     )
     .unwrap();
 
@@ -502,6 +522,9 @@ fn keystore2_abort_finalized_op_fail_test() {
     let result = key_generations::map_ks_error(op.abort());
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE), result.unwrap_err());
+
+    let sl = SecLevel::tee();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Create an operation and use it for performing sign operation. Before finishing the operation
@@ -510,13 +533,14 @@ fn keystore2_abort_finalized_op_fail_test() {
 /// code `INVALID_OPERATION_HANDLE`.
 #[test]
 fn keystore2_op_abort_success_test() {
+    let alias = "ks_op_abort_success_key";
     let op_response = create_signing_operation(
         ForcedOp(false),
         KeyPurpose::SIGN,
         Digest::SHA_2_256,
         Domain::APP,
         -1,
-        Some("ks_op_abort_success_key".to_string()),
+        Some(alias.to_string()),
     )
     .unwrap();
 
@@ -529,6 +553,9 @@ fn keystore2_op_abort_success_test() {
     let result = key_generations::map_ks_error(op.finish(None, None));
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INVALID_OPERATION_HANDLE), result.unwrap_err());
+
+    let sl = SecLevel::tee();
+    delete_app_key(&sl.keystore2, alias).unwrap();
 }
 
 /// Executes an operation in a thread. Performs an `update` operation repeatedly till the user
@@ -561,13 +588,14 @@ fn perform_abort_op_busy_in_thread(
 #[test]
 fn keystore2_op_abort_fails_with_operation_busy_error_test() {
     loop {
+        let alias = "op_abort_busy_alias_test_key";
         let op_response = create_signing_operation(
             ForcedOp(false),
             KeyPurpose::SIGN,
             Digest::SHA_2_256,
             Domain::APP,
             -1,
-            Some("op_abort_busy_alias_test_key".to_string()),
+            Some(alias.to_string()),
         )
         .unwrap();
         let op: binder::Strong<dyn IKeystoreOperation> = op_response.iOperation.unwrap();
@@ -596,5 +624,8 @@ fn keystore2_op_abort_fails_with_operation_busy_error_test() {
             return;
         }
         assert_eq!(result, 0);
+
+        let sl = SecLevel::tee();
+        delete_app_key(&sl.keystore2, alias).unwrap();
     }
 }
diff --git a/keystore2/tests/keystore2_client_rsa_key_tests.rs b/keystore2/tests/keystore2_client_rsa_key_tests.rs
index cb8729f1..428cd984 100644
--- a/keystore2/tests/keystore2_client_rsa_key_tests.rs
+++ b/keystore2/tests/keystore2_client_rsa_key_tests.rs
@@ -1610,6 +1610,7 @@ fn keystore2_rsa_generate_keys() {
         KeyPurpose::DECRYPT,
         ForcedOp(false),
     ));
+    delete_app_key(&sl.keystore2, alias).unwrap();
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_PADDING_MODE), result.unwrap_err());
 }
@@ -1638,6 +1639,7 @@ fn keystore2_rsa_encrypt_key_op_invalid_purpose() {
         KeyPurpose::SIGN,
         ForcedOp(false),
     ));
+    delete_app_key(&sl.keystore2, alias).unwrap();
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_PURPOSE), result.unwrap_err());
 }
@@ -1666,6 +1668,7 @@ fn keystore2_rsa_sign_key_op_invalid_purpose() {
         KeyPurpose::DECRYPT,
         ForcedOp(false),
     ));
+    delete_app_key(&sl.keystore2, alias).unwrap();
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_PURPOSE), result.unwrap_err());
 }
@@ -1694,6 +1697,7 @@ fn keystore2_rsa_key_unsupported_purpose() {
         KeyPurpose::AGREE_KEY,
         ForcedOp(false),
     ));
+    delete_app_key(&sl.keystore2, alias).unwrap();
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_PURPOSE), result.unwrap_err());
 }
@@ -1725,6 +1729,7 @@ fn keystore2_rsa_encrypt_key_unsupported_padding() {
             KeyPurpose::DECRYPT,
             ForcedOp(false),
         ));
+        delete_app_key(&sl.keystore2, &alias).unwrap();
         assert!(result.is_err());
         assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_PADDING_MODE), result.unwrap_err());
     }
@@ -1757,6 +1762,7 @@ fn keystore2_rsa_signing_key_unsupported_padding() {
             KeyPurpose::SIGN,
             ForcedOp(false),
         ));
+        delete_app_key(&sl.keystore2, &alias).unwrap();
         assert!(result.is_err());
         assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_PADDING_MODE), result.unwrap_err());
     }
@@ -1788,6 +1794,7 @@ fn keystore2_rsa_key_unsupported_op() {
         ForcedOp(false),
     ));
 
+    delete_app_key(&sl.keystore2, alias).unwrap();
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_PURPOSE), result.unwrap_err());
 }
@@ -1818,6 +1825,7 @@ fn keystore2_rsa_key_missing_purpose() {
         ForcedOp(false),
     ));
 
+    delete_app_key(&sl.keystore2, alias).unwrap();
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::INCOMPATIBLE_PURPOSE), result.unwrap_err());
 }
@@ -1847,6 +1855,7 @@ fn keystore2_rsa_gen_keys_with_oaep_paddings_without_digest() {
         ForcedOp(false),
     ));
 
+    delete_app_key(&sl.keystore2, alias).unwrap();
     assert!(result.is_err());
     assert_eq!(Error::Km(ErrorCode::UNSUPPORTED_DIGEST), result.unwrap_err());
 }
diff --git a/keystore2/tests/keystore2_client_test_utils.rs b/keystore2/tests/keystore2_client_test_utils.rs
index 8d708662..e9a08f5a 100644
--- a/keystore2/tests/keystore2_client_test_utils.rs
+++ b/keystore2/tests/keystore2_client_test_utils.rs
@@ -153,6 +153,16 @@ macro_rules! require_keymint {
     };
 }
 
+#[macro_export]
+macro_rules! skip_if_no_hw_curve25519_support {
+    ($sl:ident) => {
+        if $sl.get_keymint_version() < 2 {
+            // Curve 25519 was included in version 2 of the KeyMint interface.
+            return;
+        }
+    };
+}
+
 /// Generate EC key and grant it to the list of users with given access vector.
 /// Returns the list of granted keys `nspace` values in the order of given grantee uids.
 pub fn generate_ec_key_and_grant_to_users(
@@ -320,6 +330,7 @@ pub unsafe fn execute_op_run_as_child(
     agid: Gid,
     forced_op: ForcedOp,
 ) -> run_as::ChildHandle<TestOutcome, BarrierReached> {
+    let al = alias.unwrap();
     let child_fn = move |reader: &mut ChannelReader<BarrierReached>,
                          writer: &mut ChannelWriter<BarrierReached>| {
         let result = key_generations::map_ks_error(create_signing_operation(
@@ -328,7 +339,7 @@ pub unsafe fn execute_op_run_as_child(
             Digest::SHA_2_256,
             domain,
             nspace,
-            alias,
+            Some(al.clone()),
         ));
 
         // Let the parent know that an operation has been started, then
@@ -338,7 +349,7 @@ pub unsafe fn execute_op_run_as_child(
         reader.recv();
 
         // Continue performing the operation after parent notifies.
-        match &result {
+        let status = match &result {
             Ok(CreateOperationResponse { iOperation: Some(op), .. }) => {
                 match key_generations::map_ks_error(perform_sample_sign_operation(op)) {
                     Ok(()) => TestOutcome::Ok,
@@ -351,7 +362,12 @@ pub unsafe fn execute_op_run_as_child(
             Ok(_) => TestOutcome::OtherErr,
             Err(Error::Rc(ResponseCode::BACKEND_BUSY)) => TestOutcome::BackendBusy,
             _ => TestOutcome::OtherErr,
-        }
+        };
+
+        let sl = SecLevel::tee();
+        delete_key(&sl.keystore2, domain, nspace, Some(al), None).unwrap();
+
+        status
     };
 
     // Safety: The caller guarantees that there are no other threads.
@@ -437,12 +453,18 @@ pub fn delete_app_key(
     keystore2: &binder::Strong<dyn IKeystoreService>,
     alias: &str,
 ) -> binder::Result<()> {
-    keystore2.deleteKey(&KeyDescriptor {
-        domain: Domain::APP,
-        nspace: -1,
-        alias: Some(alias.to_string()),
-        blob: None,
-    })
+    delete_key(keystore2, Domain::APP, -1, Some(alias.to_string()), None)
+}
+
+/// Delete a key with the given alias or blob.
+pub fn delete_key(
+    keystore2: &binder::Strong<dyn IKeystoreService>,
+    domain: Domain,
+    nspace: i64,
+    alias: Option<String>,
+    blob: Option<Vec<u8>>,
+) -> binder::Result<()> {
+    keystore2.deleteKey(&KeyDescriptor { domain, nspace, alias, blob })
 }
 
 /// Deletes all entries from keystore.
diff --git a/keystore2/tests/keystore2_client_tests.rs b/keystore2/tests/keystore2_client_tests.rs
index 34ba81f7..ce96c8d1 100644
--- a/keystore2/tests/keystore2_client_tests.rs
+++ b/keystore2/tests/keystore2_client_tests.rs
@@ -25,7 +25,6 @@ pub mod keystore2_client_hmac_key_tests;
 pub mod keystore2_client_import_keys_tests;
 pub mod keystore2_client_key_agreement_tests;
 pub mod keystore2_client_key_id_domain_tests;
-pub mod keystore2_client_keystore_engine_tests;
 pub mod keystore2_client_list_entries_tests;
 pub mod keystore2_client_operation_tests;
 pub mod keystore2_client_rsa_key_tests;
diff --git a/keystore2/tests/keystore2_client_update_subcomponent_tests.rs b/keystore2/tests/keystore2_client_update_subcomponent_tests.rs
index 0e382988..1327bdd6 100644
--- a/keystore2/tests/keystore2_client_update_subcomponent_tests.rs
+++ b/keystore2/tests/keystore2_client_update_subcomponent_tests.rs
@@ -52,6 +52,7 @@ fn keystore2_update_subcomponent_success() {
     let key_entry_response = sl.keystore2.getKeyEntry(&key_metadata.key).unwrap();
     assert_eq!(Some(other_cert.to_vec()), key_entry_response.metadata.certificate);
     assert_eq!(Some(other_cert_chain.to_vec()), key_entry_response.metadata.certificateChain);
+    sl.keystore2.deleteKey(&key_metadata.key).unwrap();
 }
 
 /// Try to update non-existing asymmetric key public cert and certificate chain. Test should fail
diff --git a/keystore2/watchdog/src/lib.rs b/keystore2/watchdog/src/lib.rs
index f6a12918..39d896c3 100644
--- a/keystore2/watchdog/src/lib.rs
+++ b/keystore2/watchdog/src/lib.rs
@@ -17,15 +17,14 @@
 
 //! This module implements a watchdog thread.
 
+use log::{info, warn};
 use std::{
     cmp::min,
     collections::HashMap,
+    marker::PhantomData,
     sync::Arc,
     sync::{Condvar, Mutex, MutexGuard},
     thread,
-};
-use std::{
-    marker::PhantomData,
     time::{Duration, Instant},
 };
 
@@ -140,7 +139,7 @@ impl WatchdogState {
         }
         self.update_noisy_timeout();
         self.last_report = Some(Instant::now());
-        log::warn!("### Keystore Watchdog report - BEGIN ###");
+        warn!("### Keystore Watchdog report - BEGIN ###");
 
         let now = Instant::now();
         let mut overdue_records: Vec<(&Index, &Record)> = self
@@ -149,13 +148,8 @@ impl WatchdogState {
             .filter(|(_, r)| r.deadline.saturating_duration_since(now) == Duration::new(0, 0))
             .collect();
 
-        log::warn!(
-            concat!(
-                "When extracting from a bug report, please include this header ",
-                "and all {} records below (to footer)"
-            ),
-            overdue_records.len()
-        );
+        warn!("When extracting from a bug report, please include this header");
+        warn!("and all {} records below.", overdue_records.len());
 
         // Watch points can be nested, i.e., a single thread may have multiple armed
         // watch points. And the most recent on each thread (thread recent) is closest to the point
@@ -185,7 +179,7 @@ impl WatchdogState {
             for (i, r) in g.iter() {
                 match &r.context {
                     Some(ctx) => {
-                        log::warn!(
+                        warn!(
                             "{:?} {} Started: {} Pending: {:?} Overdue {:?} for {:?}",
                             i.tid,
                             i.id,
@@ -196,7 +190,7 @@ impl WatchdogState {
                         );
                     }
                     None => {
-                        log::warn!(
+                        warn!(
                             "{:?} {} Started: {} Pending: {:?} Overdue {:?}",
                             i.tid,
                             i.id,
@@ -208,7 +202,7 @@ impl WatchdogState {
                 }
             }
         }
-        log::warn!("### Keystore Watchdog report - END ###");
+        warn!("### Keystore Watchdog report - END ###");
     }
 
     fn disarm(&mut self, index: Index) {
@@ -242,7 +236,7 @@ impl WatchdogState {
 
     fn arm(&mut self, index: Index, record: Record) {
         if self.records.insert(index.clone(), record).is_some() {
-            log::warn!("Recursive watchdog record at \"{:?}\" replaces previous record.", index);
+            warn!("Recursive watchdog record at \"{index:?}\" replaces previous record.");
         }
     }
 }
@@ -281,8 +275,8 @@ impl Watchdog {
         timeout: Duration,
     ) -> Option<WatchPoint> {
         let Some(deadline) = Instant::now().checked_add(timeout) else {
-            log::warn!("Deadline computation failed for WatchPoint \"{}\"", id);
-            log::warn!("WatchPoint not armed.");
+            warn!("Deadline computation failed for WatchPoint \"{id}\"");
+            warn!("WatchPoint not armed.");
             return None;
         };
         wd.arm(context, id, deadline);
@@ -374,7 +368,7 @@ impl Watchdog {
                     break;
                 }
             }
-            log::info!("Watchdog thread idle -> terminating. Have a great day.");
+            info!("Watchdog thread idle -> terminating. Have a great day.");
         }));
         state.state = State::Running;
     }
diff --git a/provisioner/rkp_factory_extraction_lib.h b/provisioner/rkp_factory_extraction_lib.h
index f6f21f5a..3515f489 100644
--- a/provisioner/rkp_factory_extraction_lib.h
+++ b/provisioner/rkp_factory_extraction_lib.h
@@ -33,18 +33,6 @@ std::unordered_set<std::string> parseCommaDelimited(const std::string& input);
 // Challenge size must be between 32 and 64 bytes inclusive.
 constexpr size_t kChallengeSize = 64;
 
-// How CSRs should be validated when the rkp_factory_extraction_tool's "self_test"
-// flag is set to "true".
-struct CsrValidationConfig {
-    // Names of IRemotelyProvisionedComponent instances for which degenerate DICE
-    // chains are allowed.
-    std::unordered_set<std::string>* allow_degenerate_irpc_names;
-
-    // Names of IRemotelyProvisionedComponent instances for which UDS certificate
-    // chains are required to be present in the CSR.
-    std::unordered_set<std::string>* require_uds_certs_irpc_names;
-};
-
 // Contains a the result of an operation that should return cborData on success.
 // Returns an an error message and null cborData on error.
 template <typename T> struct CborResult {
diff --git a/provisioner/rkp_factory_extraction_tool.cpp b/provisioner/rkp_factory_extraction_tool.cpp
index f65e0ae8..d470fe69 100644
--- a/provisioner/rkp_factory_extraction_tool.cpp
+++ b/provisioner/rkp_factory_extraction_tool.cpp
@@ -62,6 +62,17 @@ constexpr std::string_view kBinaryCsrOutput = "csr";     // Just the raw csr as
 constexpr std::string_view kBuildPlusCsr = "build+csr";  // Text-encoded (JSON) build
                                                          // fingerprint plus CSR.
 
+// How CSRs should be validated when the "self_test" flag is set to "true".
+struct CsrValidationConfig {
+    // Names of IRemotelyProvisionedComponent instances for which degenerate DICE
+    // chains are allowed.
+    std::unordered_set<std::string>* allow_degenerate_irpc_names;
+
+    // Names of IRemotelyProvisionedComponent instances for which UDS certificate
+    // chains are required to be present in the CSR.
+    std::unordered_set<std::string>* require_uds_certs_irpc_names;
+};
+
 std::string getFullServiceName(const char* descriptor, const char* name) {
     return  std::string(descriptor) + "/" + name;
 }
@@ -106,7 +117,9 @@ void getCsrForIRpc(const char* descriptor, const char* name, IRemotelyProvisione
         exit(-1);
     }
 
-    writeOutput(std::string(name), *request);
+    if (fullName != RKPVM_INSTANCE_NAME) {
+        writeOutput(std::string(name), *request);
+    }
 }
 
 // Callback for AServiceManager_forEachDeclaredInstance that writes out a CSR
```

