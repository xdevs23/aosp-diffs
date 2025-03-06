```diff
diff --git a/Android.bp b/Android.bp
index 269964747..e194951b0 100644
--- a/Android.bp
+++ b/Android.bp
@@ -479,6 +479,7 @@ java_library_static {
         "//apex_available:platform",
         "com.android.tethering",
         "com.android.wifi",
+        "com.android.neuralnetworks",
     ],
 }
 
@@ -619,7 +620,7 @@ java_library_static {
 
     optimize: {
         proguard_flags_files: ["java/lite/proguard.pgcfg"],
-    }
+    },
 }
 
 // Java lite library (compatibility for old host-side users)
@@ -755,7 +756,6 @@ filegroup {
     path: "src",
 }
 
-
 filegroup {
     name: "libprotobuf-internal-any-proto",
     srcs: [
diff --git a/src/google/protobuf/compiler/java/enum_field_lite.cc b/src/google/protobuf/compiler/java/enum_field_lite.cc
index e80b938f3..7629d0da8 100644
--- a/src/google/protobuf/compiler/java/enum_field_lite.cc
+++ b/src/google/protobuf/compiler/java/enum_field_lite.cc
@@ -124,10 +124,6 @@ void SetEnumVariables(const FieldDescriptor* descriptor, int messageBitIndex,
   } else {
     (*variables)["unknown"] = (*variables)["default"];
   }
-
-  // We use `x.getClass()` as a null check because it generates less bytecode
-  // than an `if (x == null) { throw ... }` statement.
-  (*variables)["null_check"] = "value.getClass();\n";
 }
 
 }  // namespace
@@ -621,16 +617,18 @@ void RepeatedImmutableEnumFieldLiteGenerator::GenerateMembers(
       "}\n");
   WriteFieldAccessorDocComment(printer, descriptor_, LIST_INDEXED_SETTER);
   printer->Print(variables_,
+                 "@java.lang.SuppressWarnings(\"ReturnValueIgnored\")\n"
                  "private void set$capitalized_name$(\n"
                  "    int index, $type$ value) {\n"
-                 "  $null_check$"
+                 "  value.getClass();  // minimal bytecode null check\n"
                  "  ensure$capitalized_name$IsMutable();\n"
                  "  $name$_.setInt(index, value.getNumber());\n"
                  "}\n");
   WriteFieldAccessorDocComment(printer, descriptor_, LIST_ADDER);
   printer->Print(variables_,
+                 "@java.lang.SuppressWarnings(\"ReturnValueIgnored\")\n"
                  "private void add$capitalized_name$($type$ value) {\n"
-                 "  $null_check$"
+                 "  value.getClass();  // minimal bytecode null check\n"
                  "  ensure$capitalized_name$IsMutable();\n"
                  "  $name$_.addInt(value.getNumber());\n"
                  "}\n");
diff --git a/src/google/protobuf/compiler/java/message_field_lite.cc b/src/google/protobuf/compiler/java/message_field_lite.cc
index da96790e0..578585cc9 100644
--- a/src/google/protobuf/compiler/java/message_field_lite.cc
+++ b/src/google/protobuf/compiler/java/message_field_lite.cc
@@ -104,10 +104,6 @@ void SetMessageVariables(const FieldDescriptor* descriptor, int messageBitIndex,
       GenerateGetBitFromLocal(builderBitIndex);
   (*variables)["set_has_field_bit_to_local"] =
       GenerateSetBitToLocal(messageBitIndex);
-
-  // We use `x.getClass()` as a null check because it generates less bytecode
-  // than an `if (x == null) { throw ... }` statement.
-  (*variables)["null_check"] = "value.getClass();\n";
 }
 
 }  // namespace
@@ -187,8 +183,9 @@ void ImmutableMessageFieldLiteGenerator::GenerateMembers(
   // Field.Builder setField(Field value)
   WriteFieldDocComment(printer, descriptor_);
   printer->Print(variables_,
+                 "@java.lang.SuppressWarnings(\"ReturnValueIgnored\")\n"
                  "private void set$capitalized_name$($type$ value) {\n"
-                 "  $null_check$"
+                 "  value.getClass();  // minimal bytecode null check\n"
                  "  $name$_ = value;\n"
                  "  $set_has_field_bit_message$\n"
                  "  }\n");
@@ -197,9 +194,9 @@ void ImmutableMessageFieldLiteGenerator::GenerateMembers(
   WriteFieldDocComment(printer, descriptor_);
   printer->Print(
       variables_,
-      "@java.lang.SuppressWarnings({\"ReferenceEquality\"})\n"
+      "@java.lang.SuppressWarnings({\"ReferenceEquality\", \"ReturnValueIgnored\"})\n"
       "private void merge$capitalized_name$($type$ value) {\n"
-      "  $null_check$"
+      "  value.getClass();  // minimal bytecode null check\n"
       "  if ($name$_ != null &&\n"
       "      $name$_ != $type$.getDefaultInstance()) {\n"
       "    $name$_ =\n"
@@ -379,8 +376,9 @@ void ImmutableMessageOneofFieldLiteGenerator::GenerateMembers(
   // Field.Builder setField(Field value)
   WriteFieldDocComment(printer, descriptor_);
   printer->Print(variables_,
+                 "@java.lang.SuppressWarnings(\"ReturnValueIgnored\")\n"
                  "private void set$capitalized_name$($type$ value) {\n"
-                 "  $null_check$"
+                 "  value.getClass();  // minimal bytecode null check\n"
                  "  $oneof_name$_ = value;\n"
                  "  $set_oneof_case_message$;\n"
                  "}\n");
@@ -389,8 +387,9 @@ void ImmutableMessageOneofFieldLiteGenerator::GenerateMembers(
   WriteFieldDocComment(printer, descriptor_);
   printer->Print(
       variables_,
+      "@java.lang.SuppressWarnings(\"ReturnValueIgnored\")\n"
       "private void merge$capitalized_name$($type$ value) {\n"
-      "  $null_check$"
+      "  value.getClass();  // minimal bytecode null check\n"
       "  if ($has_oneof_case_message$ &&\n"
       "      $oneof_name$_ != $type$.getDefaultInstance()) {\n"
       "    $oneof_name$_ = $type$.newBuilder(($type$) $oneof_name$_)\n"
@@ -588,9 +587,10 @@ void RepeatedImmutableMessageFieldLiteGenerator::GenerateMembers(
   // Builder setRepeatedField(int index, Field value)
   WriteFieldDocComment(printer, descriptor_);
   printer->Print(variables_,
+                 "@java.lang.SuppressWarnings(\"ReturnValueIgnored\")\n"
                  "private void set$capitalized_name$(\n"
                  "    int index, $type$ value) {\n"
-                 "  $null_check$"
+                 "  value.getClass();  // minimal bytecode null check\n"
                  "  ensure$capitalized_name$IsMutable();\n"
                  "  $name$_.set(index, value);\n"
                  "}\n");
@@ -598,8 +598,9 @@ void RepeatedImmutableMessageFieldLiteGenerator::GenerateMembers(
   // Builder addRepeatedField(Field value)
   WriteFieldDocComment(printer, descriptor_);
   printer->Print(variables_,
+                 "@java.lang.SuppressWarnings(\"ReturnValueIgnored\")\n"
                  "private void add$capitalized_name$($type$ value) {\n"
-                 "  $null_check$"
+                 "  value.getClass();  // minimal bytecode null check\n"
                  "  ensure$capitalized_name$IsMutable();\n"
                  "  $name$_.add(value);\n"
                  "}\n");
@@ -607,9 +608,10 @@ void RepeatedImmutableMessageFieldLiteGenerator::GenerateMembers(
   // Builder addRepeatedField(int index, Field value)
   WriteFieldDocComment(printer, descriptor_);
   printer->Print(variables_,
+                 "@java.lang.SuppressWarnings(\"ReturnValueIgnored\")\n"
                  "private void add$capitalized_name$(\n"
                  "    int index, $type$ value) {\n"
-                 "  $null_check$"
+                 "  value.getClass();  // minimal bytecode null check\n"
                  "  ensure$capitalized_name$IsMutable();\n"
                  "  $name$_.add(index, value);\n"
                  "}\n");
diff --git a/src/google/protobuf/compiler/java/string_field_lite.cc b/src/google/protobuf/compiler/java/string_field_lite.cc
index 49f6891d5..7a08ee836 100644
--- a/src/google/protobuf/compiler/java/string_field_lite.cc
+++ b/src/google/protobuf/compiler/java/string_field_lite.cc
@@ -77,10 +77,6 @@ void SetPrimitiveVariables(const FieldDescriptor* descriptor,
       StrCat(static_cast<int32_t>(WireFormat::MakeTag(descriptor)));
   (*variables)["tag_size"] = StrCat(
       WireFormat::TagSize(descriptor->number(), GetType(descriptor)));
-  // We use `x.getClass()` as a null check because it generates less bytecode
-  // than an `if (x == null) { throw ... }` statement.
-  (*variables)["null_check"] =
-      "  java.lang.Class<?> valueClass = value.getClass();\n";
 
   // TODO(birdo): Add @deprecated javadoc when generating javadoc is supported
   // by the proto compiler
@@ -215,9 +211,10 @@ void ImmutableStringFieldLiteGenerator::GenerateMembers(
 
   WriteFieldAccessorDocComment(printer, descriptor_, SETTER);
   printer->Print(variables_,
+                 "@java.lang.SuppressWarnings(\"ReturnValueIgnored\")\n"
                  "private void set$capitalized_name$(\n"
                  "    java.lang.String value) {\n"
-                 "$null_check$"
+                 "  value.getClass();  // minimal bytecode null check\n"
                  "  $set_has_field_bit_message$\n"
                  "  $name$_ = value;\n"
                  "}\n");
@@ -411,9 +408,10 @@ void ImmutableStringOneofFieldLiteGenerator::GenerateMembers(
 
   WriteFieldAccessorDocComment(printer, descriptor_, SETTER);
   printer->Print(variables_,
+                 "@java.lang.SuppressWarnings(\"ReturnValueIgnored\")\n"
                  "private void ${$set$capitalized_name$$}$(\n"
                  "    java.lang.String value) {\n"
-                 "$null_check$"
+                 "  value.getClass();  // minimal bytecode null check\n"
                  "  $set_oneof_case_message$;\n"
                  "  $oneof_name$_ = value;\n"
                  "}\n");
@@ -607,17 +605,19 @@ void RepeatedImmutableStringFieldLiteGenerator::GenerateMembers(
 
   WriteFieldAccessorDocComment(printer, descriptor_, LIST_INDEXED_SETTER);
   printer->Print(variables_,
+                 "@java.lang.SuppressWarnings(\"ReturnValueIgnored\")\n"
                  "private void set$capitalized_name$(\n"
                  "    int index, java.lang.String value) {\n"
-                 "$null_check$"
+                 "  value.getClass();  // minimal bytecode null check\n"
                  "  ensure$capitalized_name$IsMutable();\n"
                  "  $name$_.set(index, value);\n"
                  "}\n");
   WriteFieldAccessorDocComment(printer, descriptor_, LIST_ADDER);
   printer->Print(variables_,
+                 "@java.lang.SuppressWarnings(\"ReturnValueIgnored\")\n"
                  "private void add$capitalized_name$(\n"
                  "    java.lang.String value) {\n"
-                 "$null_check$"
+                 "  value.getClass();  // minimal bytecode null check\n"
                  "  ensure$capitalized_name$IsMutable();\n"
                  "  $name$_.add(value);\n"
                  "}\n");
```

