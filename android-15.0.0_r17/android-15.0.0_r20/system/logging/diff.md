```diff
diff --git a/liblog/include/android/log.h b/liblog/include/android/log.h
index e203f27d..218ef2c3 100644
--- a/liblog/include/android/log.h
+++ b/liblog/include/android/log.h
@@ -55,6 +55,7 @@
  */
 
 #include <stdarg.h>
+#include <stdbool.h>
 #include <stddef.h>
 #include <stdint.h>
 #include <sys/cdefs.h>
@@ -170,6 +171,10 @@ typedef enum log_id {
   LOG_ID_DEFAULT = 0x7FFFFFFF
 } log_id_t;
 
+static inline bool __android_log_id_is_valid(log_id_t id) {
+  return id >= LOG_ID_MIN && id < LOG_ID_MAX;
+}
+
 /**
  * Writes the constant string `text` to the log buffer `id`,
  * with priority `prio` and tag `tag`.
diff --git a/liblog/logger_name.cpp b/liblog/logger_name.cpp
index e72290ed..afab5e3f 100644
--- a/liblog/logger_name.cpp
+++ b/liblog/logger_name.cpp
@@ -34,7 +34,7 @@ static const char* LOG_NAME[LOG_ID_MAX] = {
 };
 
 const char* android_log_id_to_name(log_id_t log_id) {
-  if (log_id >= LOG_ID_MAX) {
+  if (!__android_log_id_is_valid(log_id)) {
     log_id = LOG_ID_MAIN;
   }
   return LOG_NAME[log_id];
diff --git a/liblog/logger_read.cpp b/liblog/logger_read.cpp
index 4937042e..4675c608 100644
--- a/liblog/logger_read.cpp
+++ b/liblog/logger_read.cpp
@@ -61,14 +61,14 @@ struct logger_list* android_logger_list_alloc_time(int mode, log_time start, pid
 }
 
 /* Open the named log and add it to the logger list */
-struct logger* android_logger_open(struct logger_list* logger_list, log_id_t logId) {
-  if (!logger_list || (logId >= LOG_ID_MAX)) {
+struct logger* android_logger_open(struct logger_list* logger_list, log_id_t log_id) {
+  if (!logger_list || !__android_log_id_is_valid(log_id)) {
     return nullptr;
   }
 
-  logger_list->log_mask |= 1 << logId;
+  logger_list->log_mask |= 1 << log_id;
 
-  uintptr_t logger = logId;
+  uintptr_t logger = log_id;
   logger |= (logger_list->mode & ANDROID_LOG_PSTORE) ? LOGGER_PMSG : LOGGER_LOGD;
   return reinterpret_cast<struct logger*>(logger);
 }
diff --git a/liblog/pmsg_reader.cpp b/liblog/pmsg_reader.cpp
index 4d603db5..72da5a87 100644
--- a/liblog/pmsg_reader.cpp
+++ b/liblog/pmsg_reader.cpp
@@ -78,7 +78,8 @@ int PmsgRead(struct logger_list* logger_list, struct log_msg* log_msg) {
       return preread_count ? -EIO : -EAGAIN;
     }
     if ((buf.p.magic != LOGGER_MAGIC) || (buf.p.len <= sizeof(buf)) ||
-        (buf.p.len > (sizeof(buf) + LOGGER_ENTRY_MAX_PAYLOAD)) || (buf.l.id >= LOG_ID_MAX) ||
+        (buf.p.len > (sizeof(buf) + LOGGER_ENTRY_MAX_PAYLOAD)) ||
+        !__android_log_id_is_valid(static_cast<log_id_t>(buf.l.id)) ||
         (buf.l.realtime.tv_nsec >= NS_PER_SEC) ||
         ((buf.l.id != LOG_ID_EVENTS) && (buf.l.id != LOG_ID_SECURITY) &&
          ((buf.prio == ANDROID_LOG_UNKNOWN) || (buf.prio == ANDROID_LOG_DEFAULT) ||
diff --git a/logcat/logcat.cpp b/logcat/logcat.cpp
index c8fcf46a..7e79c6d7 100644
--- a/logcat/logcat.cpp
+++ b/logcat/logcat.cpp
@@ -831,7 +831,7 @@ int Logcat::Run(int argc, char** argv) {
                         id_mask = -1;
                     } else {
                         log_id_t log_id = android_name_to_log_id(buffer.c_str());
-                        if (log_id >= LOG_ID_MAX) {
+                        if (!__android_log_id_is_valid(log_id)) {
                             error(EXIT_FAILURE, 0, "Unknown -b buffer '%s'.", buffer.c_str());
                         }
                         if (log_id == LOG_ID_SECURITY) {
@@ -1194,9 +1194,8 @@ If you have enabled significant logging, look into using the -G option to increa
             error(EXIT_FAILURE, errno, "Logcat read failure");
         }
 
-        if (log_msg.id() > LOG_ID_MAX) {
-            error(EXIT_FAILURE, 0, "Unexpected log id (%d) over LOG_ID_MAX (%d).", log_msg.id(),
-                  LOG_ID_MAX);
+        if (!__android_log_id_is_valid(static_cast<log_id_t>(log_msg.id()))) {
+            error(EXIT_FAILURE, 0, "Unexpected log id (%d) out of bounds.", log_msg.id());
         }
 
         if (!uids.empty() && uids.count(log_msg.entry.uid) == 0) {
diff --git a/logd/CommandListener.cpp b/logd/CommandListener.cpp
index 0ba16213..ff1d34c9 100644
--- a/logd/CommandListener.cpp
+++ b/logd/CommandListener.cpp
@@ -178,7 +178,7 @@ int CommandListener::GetStatisticsCmd::runCommand(SocketClient* cli, int argc, c
             }
 
             int id = atoi(argv[i]);
-            if ((id < LOG_ID_MIN) || (LOG_ID_MAX <= id)) {
+            if (!__android_log_id_is_valid(static_cast<log_id_t>(id))) {
                 cli->sendMsg("Range Error");
                 return 0;
             }
diff --git a/logd/LogListener.cpp b/logd/LogListener.cpp
index 182567de..4e94651a 100644
--- a/logd/LogListener.cpp
+++ b/logd/LogListener.cpp
@@ -98,8 +98,7 @@ void LogListener::HandleData() {
     android_log_header_t* header =
         reinterpret_cast<android_log_header_t*>(buffer);
     log_id_t logId = static_cast<log_id_t>(header->id);
-    if (/* logId < LOG_ID_MIN || */ logId >= LOG_ID_MAX ||
-        logId == LOG_ID_KERNEL) {
+    if (!__android_log_id_is_valid(logId) || logId == LOG_ID_KERNEL) {
         return;
     }
 
diff --git a/logd/SerializedLogBuffer.cpp b/logd/SerializedLogBuffer.cpp
index 75ba8451..a197f489 100644
--- a/logd/SerializedLogBuffer.cpp
+++ b/logd/SerializedLogBuffer.cpp
@@ -135,7 +135,7 @@ bool SerializedLogBuffer::ShouldLog(log_id_t log_id, const char* msg, uint16_t l
 
 int SerializedLogBuffer::Log(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid, pid_t tid,
                              const char* msg, uint16_t len) {
-    if (log_id >= LOG_ID_MAX || len == 0) {
+    if (!__android_log_id_is_valid(log_id) || len == 0) {
         return -EINVAL;
     }
 
diff --git a/logd/SimpleLogBuffer.cpp b/logd/SimpleLogBuffer.cpp
index f492a406..443e977d 100644
--- a/logd/SimpleLogBuffer.cpp
+++ b/logd/SimpleLogBuffer.cpp
@@ -80,7 +80,7 @@ bool SimpleLogBuffer::ShouldLog(log_id_t log_id, const char* msg, uint16_t len)
 
 int SimpleLogBuffer::Log(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid, pid_t tid,
                          const char* msg, uint16_t len) {
-    if (log_id >= LOG_ID_MAX) {
+    if (!__android_log_id_is_valid(log_id)) {
         return -EINVAL;
     }
 
```

