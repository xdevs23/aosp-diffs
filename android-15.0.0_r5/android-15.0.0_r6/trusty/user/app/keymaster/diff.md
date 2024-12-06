```diff
diff --git a/keymaster_attributes.proto b/keymaster_attributes.proto
index 03e8e58..8f7f81b 100644
--- a/keymaster_attributes.proto
+++ b/keymaster_attributes.proto
@@ -64,3 +64,7 @@ message AttestationKey {
 message AttestationCert {
   required bytes content = 1 [(nanopb).max_size=2048];
 };
+
+message UdsCerts{
+  repeated AttestationCert certs = 1 [(nanopb).max_count=3];
+};
```

