```diff
diff --git a/OWNERS b/OWNERS
index 38550c1..0c632a5 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,4 @@
 # Owners for OBEX library
 
-sattiraju@google.com
+klhyun@google.com
 siyuanh@google.com
diff --git a/src/com/android/obex/ObexHelper.java b/src/com/android/obex/ObexHelper.java
index 5a21252..5b61cd0 100644
--- a/src/com/android/obex/ObexHelper.java
+++ b/src/com/android/obex/ObexHelper.java
@@ -211,11 +211,23 @@ public final class ObexHelper {
                         length = ((0xFF & headerArray[index]) << 8) +
                                  (0xFF & headerArray[index + 1]);
                         index += 2;
+
+                        // An empty Name header
+                        if (headerID == HeaderSet.NAME && length == OBEX_BYTE_SEQ_HEADER_LEN) {
+                            headerImpl.setEmptyNameHeader();
+                            continue;
+                        }
+
                         if (length <= OBEX_BYTE_SEQ_HEADER_LEN) {
                             Log.e(TAG, "Remote sent an OBEX packet with " +
-                                  "incorrect header length = " + length);
+                                    "incorrect header length = " + length);
                             break;
                         }
+                        if (length - OBEX_BYTE_SEQ_HEADER_LEN > headerArray.length - index) {
+                            Log.e(TAG, "Remote sent an OBEX packet with " +
+                                    "incorrect header length = " + length);
+                            throw new IOException("Incorrect header length");
+                        }
                         length -= OBEX_BYTE_SEQ_HEADER_LEN;
                         value = new byte[length];
                         System.arraycopy(headerArray, index, value, 0, length);
```

