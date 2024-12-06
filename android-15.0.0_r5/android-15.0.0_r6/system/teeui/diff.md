```diff
diff --git a/libteeui/include/teeui/common_message_types.h b/libteeui/include/teeui/common_message_types.h
index c9fb2a6..d5df2e3 100644
--- a/libteeui/include/teeui/common_message_types.h
+++ b/libteeui/include/teeui/common_message_types.h
@@ -67,7 +67,7 @@ enum class TestModeCommands : uint64_t {
     CANCEL_EVENT = 1ull,
 };
 
-using MsgString = static_vec<const char>;
+using MsgString = static_vec<char>;
 template <typename T> using MsgVector = static_vec<T>;
 
 template <typename T> inline const uint8_t* copyField(T& field, const uint8_t*(&pos)) {
@@ -133,7 +133,7 @@ inline WriteStream write(WriteStream out, const MsgVector<uint8_t>& v) {
 
 // MsgString
 inline std::tuple<ReadStream, MsgString> read(Message<MsgString>, ReadStream in) {
-    return readSimpleVecInPlace<const char>(in);
+    return readSimpleVecInPlace<char>(in);
 }
 inline WriteStream write(WriteStream out, const MsgString& v) {
     return writeSimpleVec(out, v);
diff --git a/libteeui/include/teeui/generic_operation.h b/libteeui/include/teeui/generic_operation.h
index e821e13..6ce6b70 100644
--- a/libteeui/include/teeui/generic_operation.h
+++ b/libteeui/include/teeui/generic_operation.h
@@ -166,7 +166,7 @@ template <typename Derived, typename TimeStamp> class Operation {
 
     bool isPending() const { return error_ != ResponseCode::Ignored; }
 
-    const MsgString getPrompt() const {
+    MsgString getPrompt() {
         return {&promptStringBuffer_[0], &promptStringBuffer_[strlen(promptStringBuffer_)]};
     }
 
```

