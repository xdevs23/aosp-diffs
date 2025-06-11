```diff
diff --git a/.clang-format b/.clang-format
new file mode 100644
index 0000000..fa9d143
--- /dev/null
+++ b/.clang-format
@@ -0,0 +1,24 @@
+#
+# Copyright (C) 2016 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+#
+# Below are some minor deviations from the default Google style to
+# accommodate for handling of the large legacy code base.
+#
+
+BasedOnStyle: Google
+CommentPragmas: NOLINT:.*
+DerivePointerAlignment: false
diff --git a/1.0/adaptation/android_logmsg.cpp b/1.0/adaptation/android_logmsg.cpp
index 36b906c..dcfafa5 100644
--- a/1.0/adaptation/android_logmsg.cpp
+++ b/1.0/adaptation/android_logmsg.cpp
@@ -17,6 +17,7 @@
  *
  ******************************************************************************/
 #include "android_logmsg.h"
+
 #include "halcore.h"
 
 void DispHal(const char* title, const void* data, size_t length);
@@ -70,7 +71,7 @@ void DispHal(const char* title, const void* data, size_t length) {
     STLOG_HAL_D("%s", title);
     return;
   } else {
-      STLOG_HAL_D("%s: ", title);
+    STLOG_HAL_D("%s: ", title);
   }
   for (i = 0, k = 0; i < length; i++, k++) {
     if (k > 31) {
@@ -78,14 +79,14 @@ void DispHal(const char* title, const void* data, size_t length) {
       if (first_line == true) {
         first_line = false;
         if (title[0] == 'R') {
-            STLOG_HAL_D("Rx %s\n", line);
+          STLOG_HAL_D("Rx %s\n", line);
         } else if (title[0] == 'T') {
-            STLOG_HAL_D("Tx %s\n", line);
+          STLOG_HAL_D("Tx %s\n", line);
         } else {
-            STLOG_HAL_D("%s\n", line);
+          STLOG_HAL_D("%s\n", line);
         }
       } else {
-          STLOG_HAL_D("%s\n", line);
+        STLOG_HAL_D("%s\n", line);
       }
       line[k] = 0;
     }
@@ -94,13 +95,13 @@ void DispHal(const char* title, const void* data, size_t length) {
 
   if (first_line == true) {
     if (title[0] == 'R') {
-        STLOG_HAL_D("Rx %s\n", line);
+      STLOG_HAL_D("Rx %s\n", line);
     } else if (title[0] == 'T') {
-        STLOG_HAL_D("Tx %s\n", line);
+      STLOG_HAL_D("Tx %s\n", line);
     } else {
-        STLOG_HAL_D("%s\n", line);
+      STLOG_HAL_D("%s\n", line);
     }
   } else {
-      STLOG_HAL_D("%s\n", line);
+    STLOG_HAL_D("%s\n", line);
   }
 }
diff --git a/1.0/adaptation/config.cpp b/1.0/adaptation/config.cpp
index 96c452d..3ce68f7 100644
--- a/1.0/adaptation/config.cpp
+++ b/1.0/adaptation/config.cpp
@@ -20,13 +20,15 @@
  *
  *
  ******************************************************************************/
+#include <log/log.h>
 #include <stdio.h>
+#include <sys/stat.h>
+
 #include <list>
 #include <string>
 #include <vector>
-#include <log/log.h>
+
 #include "android_logmsg.h"
-#include <sys/stat.h>
 const char alternative_config_path[] = "";
 const char* transport_config_paths[] = {"/odm/etc/", "/vendor/etc/", "/etc/"};
 
@@ -142,8 +144,7 @@ inline int getDigitValue(char c, int base) {
 ** Returns:     none
 **
 *******************************************************************************/
-void findConfigFile(const string& configName,
-                                                string& filePath) {
+void findConfigFile(const string& configName, string& filePath) {
   for (int i = 0; i < transport_config_path_size - 1; i++) {
     filePath.assign(transport_config_paths[i]);
     filePath += configName;
@@ -189,15 +190,15 @@ bool CNfcConfig::readConfig(const char* name, bool bResetContent) {
   state = BEGIN_LINE;
   /* open config file, read it into a buffer */
   if ((fd = fopen(name, "rb")) == NULL) {
-      STLOG_HAL_W("%s Cannot open config file %s\n", __func__, name);
+    STLOG_HAL_W("%s Cannot open config file %s\n", __func__, name);
     if (bResetContent) {
-        STLOG_HAL_W("%s Using default value for all settings\n", __func__);
+      STLOG_HAL_W("%s Using default value for all settings\n", __func__);
       mValidFile = false;
     }
     return false;
   }
   STLOG_HAL_D("%s Opened %s config %s\n", __func__,
-        (bResetContent ? "base" : "optional"), name);
+              (bResetContent ? "base" : "optional"), name);
 
   mValidFile = true;
   if (size() > 0) {
@@ -259,13 +260,13 @@ bool CNfcConfig::readConfig(const char* name, bool bResetContent) {
           state = NUM_VALUE;
           base = 10;
           numValue = getDigitValue(c, base);
-          i=0;
+          i = 0;
           break;
         } else if (c != '\n' && c != '\r') {
           state = END_LINE;
           break;
         }
-        [[fallthrough]]; // fall through to numValue to handle numValue
+        [[fallthrough]];  // fall through to numValue to handle numValue
 
       case NUM_VALUE:
         if (isDigit(c, base)) {
@@ -388,7 +389,7 @@ CNfcConfig& CNfcConfig::GetInstance() {
 *******************************************************************************/
 bool CNfcConfig::getValue(const char* name, char* pValue, size_t& len) const {
   const CNfcParam* pParam = find(name);
-  if (pParam == NULL || pValue== NULL) return false;
+  if (pParam == NULL || pValue == NULL) return false;
 
   if (pParam->str_len() > 0) {
     memset(pValue, 0, len);
@@ -460,7 +461,8 @@ const CNfcParam* CNfcConfig::find(const char* p_name) const {
       if ((*it)->str_len() > 0) {
         STLOG_HAL_D("%s found %s=%s\n", __func__, p_name, (*it)->str_value());
       } else {
-        STLOG_HAL_D("%s found %s=(0x%lX)\n", __func__, p_name, (*it)->numValue());
+        STLOG_HAL_D("%s found %s=(0x%lX)\n", __func__, p_name,
+                    (*it)->numValue());
       }
       return *it;
     } else
@@ -499,8 +501,8 @@ void CNfcConfig::add(const CNfcParam* pParam) {
     m_list.push_back(pParam);
     return;
   }
-  for (list<const CNfcParam *>::iterator it = m_list.begin(),
-                                         itEnd = m_list.end();
+  for (list<const CNfcParam*>::iterator it = m_list.begin(),
+                                        itEnd = m_list.end();
        it != itEnd; ++it) {
     if (**it < pParam->c_str()) continue;
     m_list.insert(it, pParam);
@@ -521,8 +523,8 @@ void CNfcConfig::add(const CNfcParam* pParam) {
 void CNfcConfig::moveFromList() {
   if (m_list.size() == 0) return;
 
-  for (list<const CNfcParam *>::iterator it = m_list.begin(),
-                                         itEnd = m_list.end();
+  for (list<const CNfcParam*>::iterator it = m_list.begin(),
+                                        itEnd = m_list.end();
        it != itEnd; ++it)
     push_back(*it);
   m_list.clear();
diff --git a/1.0/adaptation/i2clayer.c b/1.0/adaptation/i2clayer.c
index 35a96ac..7959854 100644
--- a/1.0/adaptation/i2clayer.c
+++ b/1.0/adaptation/i2clayer.c
@@ -23,17 +23,17 @@
 #include <limits.h>
 #include <linux/input.h> /* not required for all builds */
 #include <poll.h>
+#include <pthread.h>
 #include <stdint.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <sys/ioctl.h>
 #include <unistd.h>
-#include <pthread.h>
 
+#include "android_logmsg.h"
 #include "halcore.h"
 #include "halcore_private.h"
-#include "android_logmsg.h"
 
 #define ST21NFC_MAGIC 0xEA
 
@@ -76,137 +76,135 @@ static int i2cWrite(int fd, const uint8_t* pvBuffer, int length);
  * On exit of this thread, destroy the HAL thread instance.
  * @param arg  Handle of the HAL layer
  */
-static void* I2cWorkerThread(void* arg)
-{
-    bool closeThread = false;
-    HALHANDLE hHAL = (HALHANDLE)arg;
-    STLOG_HAL_V("echo thread started...\n");
-    bool readOk= false;
+static void* I2cWorkerThread(void* arg) {
+  bool closeThread = false;
+  HALHANDLE hHAL = (HALHANDLE)arg;
+  STLOG_HAL_V("echo thread started...\n");
+  bool readOk = false;
 
-    do {
-        event_table[0].fd = fidI2c;
-        event_table[0].events = POLLIN;
-        event_table[0].revents = 0;
+  do {
+    event_table[0].fd = fidI2c;
+    event_table[0].events = POLLIN;
+    event_table[0].revents = 0;
 
-        event_table[1].fd = cmdPipe[0];
-        event_table[1].events = POLLIN;
-        event_table[1].revents = 0;
+    event_table[1].fd = cmdPipe[0];
+    event_table[1].events = POLLIN;
+    event_table[1].revents = 0;
 
-        STLOG_HAL_D("echo thread go to sleep...\n");
+    STLOG_HAL_D("echo thread go to sleep...\n");
 
-        int poll_status = poll(event_table, 2, -1);
+    int poll_status = poll(event_table, 2, -1);
 
-        if (-1 == poll_status) {
-            STLOG_HAL_E("error in poll call\n");
-            return 0;
-        }
+    if (-1 == poll_status) {
+      STLOG_HAL_E("error in poll call\n");
+      return 0;
+    }
 
-        if (event_table[0].revents & POLLIN) {
-            STLOG_HAL_D("echo thread wakeup from chip...\n");
-
-            uint8_t buffer[300];
-
-            do {
-                // load first four bytes:
-                int bytesRead = i2cRead(fidI2c, buffer, 3);
-
-                if (bytesRead == 3) {
-                    if ((buffer[0] != 0x7E) && (buffer[1] != 0x7E)) {
-                        readOk = true;
-                    } else {
-                        if (buffer[1] != 0x7E) {
-                            STLOG_HAL_W("Idle data: 2nd byte is 0x%02x\n, reading next 2 bytes",
-                                  buffer[1]);
-                            buffer[0] = buffer[1];
-                            buffer[1] = buffer[2];
-                            bytesRead = i2cRead(fidI2c, buffer + 2, 1);
-                            if (bytesRead == 1) {
-                                readOk = true;
-                            }
-                        } else if (buffer[2] != 0x7E) {
-                            STLOG_HAL_W("Idle data: 3rd byte is 0x%02x\n, reading next  byte",
-                                  buffer[2]);
-                            buffer[0] = buffer[2];
-                            bytesRead = i2cRead(fidI2c, buffer + 1, 2);
-                            if (bytesRead == 2) {
-                                readOk = true;
-                            }
-                        } else {
-                            STLOG_HAL_W("received idle data\n");
-                        }
-                    }
-
-                    if (readOk == true) {
-                        int remaining = buffer[2];
-
-                        // read and pass to HALCore
-                        bytesRead = i2cRead(fidI2c, buffer + 3, remaining);
-                        if (bytesRead == remaining) {
-                            DispHal("RX DATA", buffer, 3 + bytesRead);
-                            HalSendUpstream(hHAL, buffer, 3 + bytesRead);
-                        } else {
-                            readOk = false;
-                            STLOG_HAL_E("! didn't read expected bytes from i2c\n");
-                        }
-                    }
-
-                } else {
-                    STLOG_HAL_E("! didn't read 3 requested bytes from i2c\n");
-                }
-
-                readOk = false;
-                memset(buffer, 0xca, sizeof(buffer));
-
-                /* read while we have data available */
-            } while (i2cGetGPIOState(fidI2c) == 1);
-        }
+    if (event_table[0].revents & POLLIN) {
+      STLOG_HAL_D("echo thread wakeup from chip...\n");
+
+      uint8_t buffer[300];
+
+      do {
+        // load first four bytes:
+        int bytesRead = i2cRead(fidI2c, buffer, 3);
+
+        if (bytesRead == 3) {
+          if ((buffer[0] != 0x7E) && (buffer[1] != 0x7E)) {
+            readOk = true;
+          } else {
+            if (buffer[1] != 0x7E) {
+              STLOG_HAL_W(
+                  "Idle data: 2nd byte is 0x%02x\n, reading next 2 bytes",
+                  buffer[1]);
+              buffer[0] = buffer[1];
+              buffer[1] = buffer[2];
+              bytesRead = i2cRead(fidI2c, buffer + 2, 1);
+              if (bytesRead == 1) {
+                readOk = true;
+              }
+            } else if (buffer[2] != 0x7E) {
+              STLOG_HAL_W("Idle data: 3rd byte is 0x%02x\n, reading next  byte",
+                          buffer[2]);
+              buffer[0] = buffer[2];
+              bytesRead = i2cRead(fidI2c, buffer + 1, 2);
+              if (bytesRead == 2) {
+                readOk = true;
+              }
+            } else {
+              STLOG_HAL_W("received idle data\n");
+            }
+          }
 
-        if (event_table[1].revents & POLLIN) {
-            STLOG_HAL_V("thread received command.. \n");
-
-            char cmd = 0;
-            read(cmdPipe[0], &cmd, 1);
-
-            switch (cmd) {
-                case 'X':
-                    STLOG_HAL_D("received close command\n");
-                    closeThread = true;
-                    break;
-
-                case 'W': {
-                    size_t length;
-                    uint8_t buffer[MAX_BUFFER_SIZE];
-                    STLOG_HAL_V("received write command\n");
-                    read(cmdPipe[0], &length, sizeof(length));
-                    if (length <= MAX_BUFFER_SIZE)
-                      {
-                        read(cmdPipe[0], buffer, length);
-                        i2cWrite(fidI2c, buffer, length);
-                      }
-                    else {
-                        STLOG_HAL_E("! received bigger data than expected!! Data not transmitted to NFCC \n");
-                        size_t bytes_read = 1;
-                        // Read all the data to empty but do not use it as not expected
-                        while((bytes_read > 0) && (length > 0))
-                          {
-                            bytes_read = read(cmdPipe[0],buffer,MAX_BUFFER_SIZE);
-                            length = length - bytes_read;
-                          }
-                    }
-                }
-                break;
+          if (readOk == true) {
+            int remaining = buffer[2];
+
+            // read and pass to HALCore
+            bytesRead = i2cRead(fidI2c, buffer + 3, remaining);
+            if (bytesRead == remaining) {
+              DispHal("RX DATA", buffer, 3 + bytesRead);
+              HalSendUpstream(hHAL, buffer, 3 + bytesRead);
+            } else {
+              readOk = false;
+              STLOG_HAL_E("! didn't read expected bytes from i2c\n");
             }
+          }
+
+        } else {
+          STLOG_HAL_E("! didn't read 3 requested bytes from i2c\n");
         }
 
-    } while (!closeThread);
+        readOk = false;
+        memset(buffer, 0xca, sizeof(buffer));
+
+        /* read while we have data available */
+      } while (i2cGetGPIOState(fidI2c) == 1);
+    }
 
-    close(fidI2c);
-    close(cmdPipe[0]);
-    close(cmdPipe[1]);
+    if (event_table[1].revents & POLLIN) {
+      STLOG_HAL_V("thread received command.. \n");
+
+      char cmd = 0;
+      read(cmdPipe[0], &cmd, 1);
+
+      switch (cmd) {
+        case 'X':
+          STLOG_HAL_D("received close command\n");
+          closeThread = true;
+          break;
+
+        case 'W': {
+          size_t length;
+          uint8_t buffer[MAX_BUFFER_SIZE];
+          STLOG_HAL_V("received write command\n");
+          read(cmdPipe[0], &length, sizeof(length));
+          if (length <= MAX_BUFFER_SIZE) {
+            read(cmdPipe[0], buffer, length);
+            i2cWrite(fidI2c, buffer, length);
+          } else {
+            STLOG_HAL_E(
+                "! received bigger data than expected!! Data not transmitted "
+                "to NFCC \n");
+            size_t bytes_read = 1;
+            // Read all the data to empty but do not use it as not expected
+            while ((bytes_read > 0) && (length > 0)) {
+              bytes_read = read(cmdPipe[0], buffer, MAX_BUFFER_SIZE);
+              length = length - bytes_read;
+            }
+          }
+        } break;
+      }
+    }
 
-    HalDestroy(hHAL);
-    STLOG_HAL_D("thread exit\n");
-    return 0;
+  } while (!closeThread);
+
+  close(fidI2c);
+  close(cmdPipe[0]);
+  close(cmdPipe[1]);
+
+  HalDestroy(hHAL);
+  STLOG_HAL_D("thread exit\n");
+  return 0;
 }
 
 /**
@@ -216,9 +214,8 @@ static void* I2cWorkerThread(void* arg)
  * @param len Size of command or data
  * @return
  */
-int I2cWriteCmd(const uint8_t* x, size_t len)
-{
-    return write(cmdPipe[1], x, len);
+int I2cWriteCmd(const uint8_t* x, size_t len) {
+  return write(cmdPipe[1], x, len);
 }
 
 /**
@@ -227,59 +224,56 @@ int I2cWriteCmd(const uint8_t* x, size_t len)
  * @param callb HAL Core callback upon reception on I2C
  * @param pHandle HAL context handle
  */
-bool I2cOpenLayer(void* dev, HAL_CALLBACK callb, HALHANDLE* pHandle)
-{
-    uint32_t NoDbgFlag = HAL_FLAG_DEBUG;
-
-      (void) pthread_mutex_lock(&i2ctransport_mtx);
-    fidI2c = open("/dev/st21nfc", O_RDWR);
-    if (fidI2c < 0) {
-        STLOG_HAL_W("unable to open /dev/st21nfc\n");
-        return false;
-    }
+bool I2cOpenLayer(void* dev, HAL_CALLBACK callb, HALHANDLE* pHandle) {
+  uint32_t NoDbgFlag = HAL_FLAG_DEBUG;
 
-    i2cSetPolarity(fidI2c, false, true);
-    i2cResetPulse(fidI2c);
+  (void)pthread_mutex_lock(&i2ctransport_mtx);
+  fidI2c = open("/dev/st21nfc", O_RDWR);
+  if (fidI2c < 0) {
+    STLOG_HAL_W("unable to open /dev/st21nfc\n");
+    return false;
+  }
 
-    if ((pipe(cmdPipe) == -1)) {
-        STLOG_HAL_W("unable to open cmdpipe\n");
-        return false;
-    }
+  i2cSetPolarity(fidI2c, false, true);
+  i2cResetPulse(fidI2c);
 
-    *pHandle = HalCreate(dev, callb, NoDbgFlag);
+  if ((pipe(cmdPipe) == -1)) {
+    STLOG_HAL_W("unable to open cmdpipe\n");
+    return false;
+  }
 
-    if (!*pHandle) {
-        STLOG_HAL_E("failed to create NFC HAL Core \n");
-        return false;
-    }
+  *pHandle = HalCreate(dev, callb, NoDbgFlag);
 
-      (void) pthread_mutex_unlock(&i2ctransport_mtx);
+  if (!*pHandle) {
+    STLOG_HAL_E("failed to create NFC HAL Core \n");
+    return false;
+  }
 
-    return (pthread_create(&threadHandle, NULL, I2cWorkerThread, *pHandle) == 0);
+  (void)pthread_mutex_unlock(&i2ctransport_mtx);
+
+  return (pthread_create(&threadHandle, NULL, I2cWorkerThread, *pHandle) == 0);
 }
 
 /**
  * Terminates the I2C layer.
  */
-void I2cCloseLayer()
-{
-    uint8_t cmd = 'X';
-    int ret;
-    ALOGD("%s: enter\n", __func__);
-
-    (void)pthread_mutex_lock(&i2ctransport_mtx);
-
-    if (threadHandle == (pthread_t)NULL)
-        return;
-
-    I2cWriteCmd(&cmd, sizeof(cmd));
-    /* wait for terminate */
-    ret = pthread_join(threadHandle,(void**)NULL);
-    if (ret != 0) {
-        ALOGE("%s: failed to wait for thread (%d)", __func__, ret);
-    }
-    threadHandle = (pthread_t)NULL;
-    (void)pthread_mutex_unlock(&i2ctransport_mtx);
+void I2cCloseLayer() {
+  uint8_t cmd = 'X';
+  int ret;
+  ALOGD("%s: enter\n", __func__);
+
+  (void)pthread_mutex_lock(&i2ctransport_mtx);
+
+  if (threadHandle == (pthread_t)NULL) return;
+
+  I2cWriteCmd(&cmd, sizeof(cmd));
+  /* wait for terminate */
+  ret = pthread_join(threadHandle, (void**)NULL);
+  if (ret != 0) {
+    ALOGE("%s: failed to wait for thread (%d)", __func__, ret);
+  }
+  threadHandle = (pthread_t)NULL;
+  (void)pthread_mutex_unlock(&i2ctransport_mtx);
 }
 /**************************************************************************************************
  *
@@ -293,31 +287,30 @@ void I2cCloseLayer()
  * @param edge Polarity (RISING or FALLING)
  * @return Result of IOCTL system call (0 if ok)
  */
-static int i2cSetPolarity(int fid, bool low, bool edge)
-{
-    int result;
-    unsigned int io_code;
-
-    if (low) {
-        if (edge) {
-            io_code = ST21NFC_SET_POLARITY_FALLING;
-        } else {
-            io_code = ST21NFC_SET_POLARITY_LOW;
-        }
+static int i2cSetPolarity(int fid, bool low, bool edge) {
+  int result;
+  unsigned int io_code;
 
+  if (low) {
+    if (edge) {
+      io_code = ST21NFC_SET_POLARITY_FALLING;
     } else {
-        if (edge) {
-            io_code = ST21NFC_SET_POLARITY_RISING;
-        } else {
-            io_code = ST21NFC_SET_POLARITY_HIGH;
-        }
+      io_code = ST21NFC_SET_POLARITY_LOW;
     }
 
-    if (-1 == (result = ioctl(fid, io_code, NULL))) {
-        result = -1;
+  } else {
+    if (edge) {
+      io_code = ST21NFC_SET_POLARITY_RISING;
+    } else {
+      io_code = ST21NFC_SET_POLARITY_HIGH;
     }
+  }
+
+  if (-1 == (result = ioctl(fid, io_code, NULL))) {
+    result = -1;
+  }
 
-    return result;
+  return result;
 } /* i2cSetPolarity*/
 
 /**
@@ -325,15 +318,14 @@ static int i2cSetPolarity(int fid, bool low, bool edge)
  * @param fid File descriptor for NFC device
  * @return Result of IOCTL system call (0 if ok)
  */
-static int i2cResetPulse(int fid)
-{
-    int result;
-
-    if (-1 == (result = ioctl(fid, ST21NFC_PULSE_RESET, NULL))) {
-        result = -1;
-    }
-    STLOG_HAL_D("! i2cResetPulse!!, result = %d", result);
-    return result;
+static int i2cResetPulse(int fid) {
+  int result;
+
+  if (-1 == (result = ioctl(fid, ST21NFC_PULSE_RESET, NULL))) {
+    result = -1;
+  }
+  STLOG_HAL_D("! i2cResetPulse!!, result = %d", result);
+  return result;
 } /* i2cResetPulse*/
 
 /**
@@ -343,32 +335,31 @@ static int i2cResetPulse(int fid)
  * @param length Data size
  * @return 0 if bytes written, -1 if error
  */
-static int i2cWrite(int fid, const uint8_t* pvBuffer, int length)
-{
-    int retries = 0;
-    int result = 0;
-
-    while (retries < 3) {
-        result = write(fid, pvBuffer, length);
-
-        if (result < 0) {
-            char msg[LINUX_DBGBUFFER_SIZE];
-
-            strerror_r(errno, msg, LINUX_DBGBUFFER_SIZE);
-            STLOG_HAL_W("! i2cWrite!!, errno is '%s'", msg);
-            usleep(4000);
-            retries++;
-        } else if (result > 0) {
-            result = 0;
-            return result;
-        } else {
-            STLOG_HAL_W("write on i2c failed, retrying\n");
-            usleep(4000);
-            retries++;
-        }
+static int i2cWrite(int fid, const uint8_t* pvBuffer, int length) {
+  int retries = 0;
+  int result = 0;
+
+  while (retries < 3) {
+    result = write(fid, pvBuffer, length);
+
+    if (result < 0) {
+      char msg[LINUX_DBGBUFFER_SIZE];
+
+      strerror_r(errno, msg, LINUX_DBGBUFFER_SIZE);
+      STLOG_HAL_W("! i2cWrite!!, errno is '%s'", msg);
+      usleep(4000);
+      retries++;
+    } else if (result > 0) {
+      result = 0;
+      return result;
+    } else {
+      STLOG_HAL_W("write on i2c failed, retrying\n");
+      usleep(4000);
+      retries++;
     }
+  }
 
-    return -1;
+  return -1;
 } /* i2cWrite */
 
 /**
@@ -379,44 +370,45 @@ static int i2cWrite(int fid, const uint8_t* pvBuffer, int length)
  * @param length Data size to read
  * @return Length of read data, -1 if error
  */
-static int i2cRead(int fid, uint8_t* pvBuffer, int length)
-{
-    int retries = 0;
-    int result = -1;
-
-    while ((retries < 3) && (result < 0)) {
-        result = read(fid, pvBuffer, length);
-
-        if (result == -1) {
-            int e = errno;
-            if (e == EAGAIN) {
-                /* File is nonblocking, and no data is available.
-                 * This is not an error condition!
-                 */
-                result = 0;
-                STLOG_HAL_D("## i2cRead - got EAGAIN. No data available. return 0 bytes");
-            } else {
-                /* unexpected result */
-                char msg[LINUX_DBGBUFFER_SIZE];
-                strerror_r(e, msg, LINUX_DBGBUFFER_SIZE);
-                STLOG_HAL_W("## i2cRead returns %d errno %d (%s)", result, e, msg);
-            }
-        }
-
-        if (result < 0) {
-            if (retries < 3) {
-                /* delays are different and increasing for the three retries. */
-                static const uint8_t delayTab[] = {2, 3, 5};
-                int delay = delayTab[retries];
+static int i2cRead(int fid, uint8_t* pvBuffer, int length) {
+  int retries = 0;
+  int result = -1;
+
+  while ((retries < 3) && (result < 0)) {
+    result = read(fid, pvBuffer, length);
+
+    if (result == -1) {
+      int e = errno;
+      if (e == EAGAIN) {
+        /* File is nonblocking, and no data is available.
+         * This is not an error condition!
+         */
+        result = 0;
+        STLOG_HAL_D(
+            "## i2cRead - got EAGAIN. No data available. return 0 bytes");
+      } else {
+        /* unexpected result */
+        char msg[LINUX_DBGBUFFER_SIZE];
+        strerror_r(e, msg, LINUX_DBGBUFFER_SIZE);
+        STLOG_HAL_W("## i2cRead returns %d errno %d (%s)", result, e, msg);
+      }
+    }
 
-                retries++;
-                STLOG_HAL_W("## i2cRead retry %d/3 in %d milliseconds.", retries, delay);
-                usleep(delay * 1000);
-                continue;
-            }
-        }
+    if (result < 0) {
+      if (retries < 3) {
+        /* delays are different and increasing for the three retries. */
+        static const uint8_t delayTab[] = {2, 3, 5};
+        int delay = delayTab[retries];
+
+        retries++;
+        STLOG_HAL_W("## i2cRead retry %d/3 in %d milliseconds.", retries,
+                    delay);
+        usleep(delay * 1000);
+        continue;
+      }
     }
-    return result;
+  }
+  return result;
 } /* i2cRead */
 
 /**
@@ -429,13 +421,12 @@ static int i2cRead(int fid, uint8_t* pvBuffer, int length)
  *  Result > 0:     Pin active
  *  Result = 0:     Pin not active
  */
-static int i2cGetGPIOState(int fid)
-{
-    int result;
+static int i2cGetGPIOState(int fid) {
+  int result;
 
-    if (-1 == (result = ioctl(fid, ST21NFC_GET_WAKEUP, NULL))) {
-        result = -1;
-    }
+  if (-1 == (result = ioctl(fid, ST21NFC_GET_WAKEUP, NULL))) {
+    result = -1;
+  }
 
-    return result;
+  return result;
 } /* i2cGetGPIOState */
diff --git a/1.0/gki/common/gki.h b/1.0/gki/common/gki.h
index 083d1bf..acfe983 100644
--- a/1.0/gki/common/gki.h
+++ b/1.0/gki/common/gki.h
@@ -301,7 +301,7 @@
 #endif /* GKI_NUM_FIXED_BUF_POOLS < 16 */
 
 /* Timer list entry callback type
-*/
+ */
 typedef void(TIMER_CBACK)(void* p_tle);
 #ifndef TIMER_PARAM_TYPE
 #ifdef WIN2000
@@ -311,7 +311,7 @@ typedef void(TIMER_CBACK)(void* p_tle);
 #endif
 #endif
 /* Define a timer list entry
-*/
+ */
 typedef struct _tle {
   struct _tle* p_next;
   struct _tle* p_prev;
@@ -323,7 +323,7 @@ typedef struct _tle {
 } TIMER_LIST_ENT;
 
 /* Define a timer list queue
-*/
+ */
 typedef struct {
   TIMER_LIST_ENT* p_first;
   TIMER_LIST_ENT* p_last;
@@ -342,7 +342,7 @@ typedef struct {
 #define GKI_IS_QUEUE_EMPTY(p_q) ((p_q)->count == 0)
 
 /* Task constants
-*/
+ */
 #ifndef TASKPTR
 typedef void (*TASKPTR)(uint32_t);
 #endif
@@ -359,7 +359,7 @@ extern "C" {
 #endif
 
 /* Task management
-*/
+ */
 extern uint8_t GKI_create_task(TASKPTR, uint8_t, int8_t*, uint16_t*, uint16_t,
                                void*, void*);
 extern void GKI_exit_task(uint8_t);
@@ -374,12 +374,12 @@ extern uint8_t GKI_is_task_running(uint8_t);
 extern void GKI_shutdown(void);
 
 /* memory management
-*/
+ */
 extern void GKI_shiftdown(uint8_t* p_mem, uint32_t len, uint32_t shift_amount);
 extern void GKI_shiftup(uint8_t* p_dest, uint8_t* p_src, uint32_t len);
 
 /* To send buffers and events between tasks
-*/
+ */
 extern uint8_t GKI_isend_event(uint8_t, uint16_t);
 extern void GKI_isend_msg(uint8_t, uint8_t, void*);
 extern void* GKI_read_mbox(uint8_t);
@@ -387,7 +387,7 @@ extern void GKI_send_msg(uint8_t, uint8_t, void*);
 extern uint8_t GKI_send_event(uint8_t, uint16_t);
 
 /* To get and release buffers, change owner and get size
-*/
+ */
 extern void GKI_change_buf_owner(void*, uint8_t);
 extern uint8_t GKI_create_pool(uint16_t, uint16_t, uint8_t, void*);
 extern void GKI_delete_pool(uint8_t);
@@ -414,7 +414,7 @@ extern void GKI_register_mempool(void* p_mem);
 extern uint8_t GKI_set_pool_permission(uint8_t, uint8_t);
 
 /* User buffer queue management
-*/
+ */
 extern void* GKI_dequeue(BUFFER_Q*);
 extern void GKI_enqueue(BUFFER_Q*, void*);
 extern void GKI_enqueue_head(BUFFER_Q*, void*);
@@ -427,7 +427,7 @@ extern void* GKI_remove_from_queue(BUFFER_Q*, void*);
 extern uint16_t GKI_get_pool_bufsize(uint8_t);
 
 /* Timer management
-*/
+ */
 extern void GKI_add_to_timer_list(TIMER_LIST_Q*, TIMER_LIST_ENT*);
 extern void GKI_delay(uint32_t);
 extern uint32_t GKI_get_tick_count(void);
@@ -446,23 +446,23 @@ extern uint16_t GKI_wait(uint16_t, uint32_t);
 /* Start and Stop system time tick callback
  * true for start system tick if time queue is not empty
  * false to stop system tick if time queue is empty
-*/
+ */
 typedef void(SYSTEM_TICK_CBACK)(bool);
 
 /* Time queue management for system ticks
-*/
+ */
 extern bool GKI_timer_queue_empty(void);
 extern void GKI_timer_queue_register_callback(SYSTEM_TICK_CBACK*);
 
 /* Disable Interrupts, Enable Interrupts
-*/
+ */
 extern void GKI_enable(void);
 extern void GKI_disable(void);
 extern void GKI_sched_lock(void);
 extern void GKI_sched_unlock(void);
 
 /* Allocate (Free) memory from an OS
-*/
+ */
 extern void* GKI_os_malloc(uint32_t);
 extern void GKI_os_free(void*);
 
@@ -470,7 +470,7 @@ extern void GKI_os_free(void*);
 extern uint32_t GKI_get_os_tick_count(void);
 
 /* Exception handling
-*/
+ */
 extern void GKI_exception(uint16_t, char*);
 
 #if GKI_DEBUG == TRUE
diff --git a/1.0/gki/ulinux/data_types.h b/1.0/gki/ulinux/data_types.h
index 060c870..800d2e3 100644
--- a/1.0/gki/ulinux/data_types.h
+++ b/1.0/gki/ulinux/data_types.h
@@ -48,7 +48,7 @@ typedef unsigned char UBYTE;
 #define BIG_ENDIAN FALSE
 #endif
 
-#define UINT16_LOW_BYTE(x) ((x)&0xff)
+#define UINT16_LOW_BYTE(x) ((x) & 0xff)
 #define UINT16_HI_BYTE(x) ((x) >> 8)
 
 #endif
diff --git a/1.0/hal/halcore.c b/1.0/hal/halcore.c
index 2912b05..da5a90a 100644
--- a/1.0/hal/halcore.c
+++ b/1.0/hal/halcore.c
@@ -18,14 +18,14 @@
  ----------------------------------------------------------------------*/
 #define LOG_TAG "NfcHal"
 
-
 #include <hardware/nfc.h>
-#include "halcore_private.h"
-#include "android_logmsg.h"
-#include <stdlib.h>
-#include <string.h>
 #include <pthread.h>
 #include <semaphore.h>
+#include <stdlib.h>
+#include <string.h>
+
+#include "android_logmsg.h"
+#include "halcore_private.h"
 
 pthread_mutex_t debugOutputSem = PTHREAD_MUTEX_INITIALIZER;
 bool halTraceMask = true;
@@ -38,11 +38,11 @@ extern uint32_t ScrProtocolTraceFlag;  // = SCR_PROTO_TRACE_ALL;
 static void HalStopTimer(HalInstance* inst);
 
 typedef struct {
-    struct nfc_nci_device nci_device;  // nci_device must be first struct member
-    // below declarations are private variables within HAL
-    nfc_stack_callback_t* p_cback;
-    nfc_stack_data_callback_t* p_data_cback;
-    HALHANDLE hHAL;
+  struct nfc_nci_device nci_device;  // nci_device must be first struct member
+  // below declarations are private variables within HAL
+  nfc_stack_callback_t* p_cback;
+  nfc_stack_data_callback_t* p_data_cback;
+  HALHANDLE hHAL;
 } st21nfc_dev_t;  // beware, is a duplication of structure in nfc_nci_st21nfc.c
 
 /**************************************************************************************************
@@ -52,13 +52,13 @@ typedef struct {
  **************************************************************************************************/
 
 static void* HalWorkerThread(void* arg);
-static inline int sem_wait_nointr(sem_t *sem);
+static inline int sem_wait_nointr(sem_t* sem);
 
 static void HalOnNewUpstreamFrame(HalInstance* inst, const uint8_t* data,
                                   size_t length);
 static void HalTriggerNextDsPacket(HalInstance* inst);
-static bool HalEnqueueThreadMessage(HalInstance* inst, ThreadMesssage* msg);
-static bool HalDequeueThreadMessage(HalInstance* inst, ThreadMesssage* msg);
+static bool HalEnqueueThreadMessage(HalInstance* inst, ThreadMessage* msg);
+static bool HalDequeueThreadMessage(HalInstance* inst, ThreadMessage* msg);
 static HalBuffer* HalAllocBuffer(HalInstance* inst);
 static HalBuffer* HalFreeBuffer(HalInstance* inst, HalBuffer* b);
 static uint32_t HalSemWait(sem_t* pSemaphore, uint32_t timeout);
@@ -81,58 +81,58 @@ static uint32_t HalSemWait(sem_t* pSemaphore, uint32_t timeout);
  * @param length Configure if debug and trace allowed, trace level
  */
 void HalCoreCallback(void* context, uint32_t event, const void* d,
-                     size_t length)
-{
-    const uint8_t* data = (const uint8_t*)d;
-    uint8_t cmd = 'W';
-
-    st21nfc_dev_t* dev = (st21nfc_dev_t*)context;
-
-    switch (event) {
-        case HAL_EVENT_DSWRITE:
-            STLOG_HAL_V("!! got event HAL_EVENT_DSWRITE for %zu bytes\n", length);
-            DispHal("TX DATA", (data), length);
-
-            // Send write command to IO thread
-            cmd = 'W';
-            I2cWriteCmd(&cmd, sizeof(cmd));
-            I2cWriteCmd((const uint8_t*)&length, sizeof(length));
-            I2cWriteCmd(data, length);
-            break;
-
-        case HAL_EVENT_DATAIND:
-            STLOG_HAL_V("!! got event HAL_EVENT_DATAIND for %zu bytes\n", length);
-
-            if ((length >= 3) && (data[2] != (length - 3))) {
-                STLOG_HAL_W("length is illogical. Header length is %d, packet length %zu\n",
-                      data[2], length);
-            }
+                     size_t length) {
+  const uint8_t* data = (const uint8_t*)d;
+  uint8_t cmd = 'W';
+
+  st21nfc_dev_t* dev = (st21nfc_dev_t*)context;
+
+  switch (event) {
+    case HAL_EVENT_DSWRITE:
+      STLOG_HAL_V("!! got event HAL_EVENT_DSWRITE for %zu bytes\n", length);
+      DispHal("TX DATA", (data), length);
+
+      // Send write command to IO thread
+      cmd = 'W';
+      I2cWriteCmd(&cmd, sizeof(cmd));
+      I2cWriteCmd((const uint8_t*)&length, sizeof(length));
+      I2cWriteCmd(data, length);
+      break;
+
+    case HAL_EVENT_DATAIND:
+      STLOG_HAL_V("!! got event HAL_EVENT_DATAIND for %zu bytes\n", length);
+
+      if ((length >= 3) && (data[2] != (length - 3))) {
+        STLOG_HAL_W(
+            "length is illogical. Header length is %d, packet length %zu\n",
+            data[2], length);
+      }
 
-            dev->p_data_cback(length, (uint8_t*)data);
-            break;
+      dev->p_data_cback(length, (uint8_t*)data);
+      break;
 
-        case HAL_EVENT_ERROR:
-            STLOG_HAL_E("!! got event HAL_EVENT_ERROR\n");
-            DispHal("Received unexpected HAL message !!!", data, length);
-            break;
+    case HAL_EVENT_ERROR:
+      STLOG_HAL_E("!! got event HAL_EVENT_ERROR\n");
+      DispHal("Received unexpected HAL message !!!", data, length);
+      break;
 
-        case HAL_EVENT_LINKLOST:
-            STLOG_HAL_E("!! got event HAL_EVENT_LINKLOST or HAL_EVENT_ERROR\n");
+    case HAL_EVENT_LINKLOST:
+      STLOG_HAL_E("!! got event HAL_EVENT_LINKLOST or HAL_EVENT_ERROR\n");
 
-            dev->p_cback(HAL_NFC_ERROR_EVT, HAL_NFC_STATUS_ERR_CMD_TIMEOUT);
+      dev->p_cback(HAL_NFC_ERROR_EVT, HAL_NFC_STATUS_ERR_CMD_TIMEOUT);
 
-            // Write terminate command
-            cmd = 'X';
-            I2cWriteCmd(&cmd, sizeof(cmd));
-            break;
+      // Write terminate command
+      cmd = 'X';
+      I2cWriteCmd(&cmd, sizeof(cmd));
+      break;
 
-        case HAL_EVENT_TIMER_TIMEOUT:
-            STLOG_HAL_D("!! got event HAL_EVENT_TIMER_TIMEOUT \n");
-            dev->p_cback(HAL_WRAPPER_TIMEOUT_EVT, HAL_NFC_STATUS_OK);
+    case HAL_EVENT_TIMER_TIMEOUT:
+      STLOG_HAL_D("!! got event HAL_EVENT_TIMER_TIMEOUT \n");
+      dev->p_cback(HAL_WRAPPER_TIMEOUT_EVT, HAL_NFC_STATUS_OK);
 
-            //            dev->p_data_cback(0, NULL);
-            break;
-    }
+      //            dev->p_data_cback(0, NULL);
+      break;
+  }
 }
 
 /**
@@ -143,101 +143,99 @@ void HalCoreCallback(void* context, uint32_t event, const void* d,
  * @param callback HAL callback function pointer
  * @param flags Configure if debug and trace allowed, trace level
  */
-HALHANDLE HalCreate(void* context, HAL_CALLBACK callback, uint32_t flags)
-{
-    halTraceMask = true;
+HALHANDLE HalCreate(void* context, HAL_CALLBACK callback, uint32_t flags) {
+  halTraceMask = true;
 
-    if (flags & HAL_FLAG_NO_DEBUG) {
-        halTraceMask = false;
-    }
+  if (flags & HAL_FLAG_NO_DEBUG) {
+    halTraceMask = false;
+  }
 
-    STLOG_HAL_V("HalCreate enter\n");
+  STLOG_HAL_V("HalCreate enter\n");
 
-    HalInstance* inst = calloc(1, sizeof(HalInstance));
+  HalInstance* inst = calloc(1, sizeof(HalInstance));
 
-    if (!inst) {
-        STLOG_HAL_E("!out of memory\n");
-        return NULL;
-    }
-
-    // We need a semaphore to wakeup our protocol thread
-    if (0 != sem_init(&inst->semaphore, 0, 0)) {
-        STLOG_HAL_E("!sem_init failed\n");
-        free(inst);
-        return NULL;
-    }
+  if (!inst) {
+    STLOG_HAL_E("!out of memory\n");
+    return NULL;
+  }
 
-    // We need a semaphore to manage buffers
-    if (0 != sem_init(&inst->bufferResourceSem, 0, NUM_BUFFERS)) {
-        STLOG_HAL_E("!sem_init failed\n");
-        sem_destroy(&inst->semaphore);
-        free(inst);
-        return NULL;
-    }
+  // We need a semaphore to wakeup our protocol thread
+  if (0 != sem_init(&inst->semaphore, 0, 0)) {
+    STLOG_HAL_E("!sem_init failed\n");
+    free(inst);
+    return NULL;
+  }
 
-    // We need a semaphore to block upstream data indications
-    if (0 != sem_init(&inst->upstreamBlock, 0, 0)) {
-        STLOG_HAL_E("!sem_init failed\n");
-        sem_destroy(&inst->semaphore);
-        sem_destroy(&inst->bufferResourceSem);
-        free(inst);
-        return NULL;
-    }
+  // We need a semaphore to manage buffers
+  if (0 != sem_init(&inst->bufferResourceSem, 0, NUM_BUFFERS)) {
+    STLOG_HAL_E("!sem_init failed\n");
+    sem_destroy(&inst->semaphore);
+    free(inst);
+    return NULL;
+  }
 
-    // Initialize remaining data-members
-    inst->context = context;
-    inst->callback = callback;
-    inst->flags = flags;
-    inst->freeBufferList = 0;
-    inst->pendingNciList = 0;
-    inst->nciBuffer = 0;
-    inst->ringReadPos = 0;
-    inst->ringWritePos = 0;
-    inst->timeout = HAL_SLEEP_TIMER_DURATION;
-
-    inst->bufferData = calloc(NUM_BUFFERS, sizeof(HalBuffer));
-    if (!inst->bufferData) {
-        STLOG_HAL_E("!failed to allocate memory\n");
-        sem_destroy(&inst->semaphore);
-        sem_destroy(&inst->bufferResourceSem);
-        sem_destroy(&inst->upstreamBlock);
-        free(inst);
-        return NULL;
-    }
+  // We need a semaphore to block upstream data indications
+  if (0 != sem_init(&inst->upstreamBlock, 0, 0)) {
+    STLOG_HAL_E("!sem_init failed\n");
+    sem_destroy(&inst->semaphore);
+    sem_destroy(&inst->bufferResourceSem);
+    free(inst);
+    return NULL;
+  }
+
+  // Initialize remaining data-members
+  inst->context = context;
+  inst->callback = callback;
+  inst->flags = flags;
+  inst->freeBufferList = 0;
+  inst->pendingNciList = 0;
+  inst->nciBuffer = 0;
+  inst->ringReadPos = 0;
+  inst->ringWritePos = 0;
+  inst->timeout = HAL_SLEEP_TIMER_DURATION;
+
+  inst->bufferData = calloc(NUM_BUFFERS, sizeof(HalBuffer));
+  if (!inst->bufferData) {
+    STLOG_HAL_E("!failed to allocate memory\n");
+    sem_destroy(&inst->semaphore);
+    sem_destroy(&inst->bufferResourceSem);
+    sem_destroy(&inst->upstreamBlock);
+    free(inst);
+    return NULL;
+  }
 
-    // Concatenate the buffers into a linked list for easy access
-    size_t i;
-    for (i = 0; i < NUM_BUFFERS; i++) {
-        HalBuffer* b = &inst->bufferData[i];
-        b->next = inst->freeBufferList;
-        inst->freeBufferList = b;
-    }
+  // Concatenate the buffers into a linked list for easy access
+  size_t i;
+  for (i = 0; i < NUM_BUFFERS; i++) {
+    HalBuffer* b = &inst->bufferData[i];
+    b->next = inst->freeBufferList;
+    inst->freeBufferList = b;
+  }
 
-    if (0 != pthread_mutex_init(&inst->hMutex, 0))
-      {
-        STLOG_HAL_E("!failed to initialize Mutex \n");
-        sem_destroy(&inst->semaphore);
-        sem_destroy(&inst->bufferResourceSem);
-        sem_destroy(&inst->upstreamBlock);
-        free(inst->bufferData);
-        free(inst);
-        return NULL;
-      }
+  if (0 != pthread_mutex_init(&inst->hMutex, 0)) {
+    STLOG_HAL_E("!failed to initialize Mutex \n");
+    sem_destroy(&inst->semaphore);
+    sem_destroy(&inst->bufferResourceSem);
+    sem_destroy(&inst->upstreamBlock);
+    free(inst->bufferData);
+    free(inst);
+    return NULL;
+  }
 
-    // Spawn the thread
-    if (0 != pthread_create(&inst->thread, NULL, HalWorkerThread, inst)) {
-        STLOG_HAL_E("!failed to spawn workerthread \n");
-        sem_destroy(&inst->semaphore);
-        sem_destroy(&inst->bufferResourceSem);
-        sem_destroy(&inst->upstreamBlock);
-        pthread_mutex_destroy(&inst->hMutex);
-        free(inst->bufferData);
-        free(inst);
-        return NULL;
-    }
+  // Spawn the thread
+  if (0 != pthread_create(&inst->thread, NULL, HalWorkerThread, inst)) {
+    STLOG_HAL_E("!failed to spawn workerthread \n");
+    sem_destroy(&inst->semaphore);
+    sem_destroy(&inst->bufferResourceSem);
+    sem_destroy(&inst->upstreamBlock);
+    pthread_mutex_destroy(&inst->hMutex);
+    free(inst->bufferData);
+    free(inst);
+    return NULL;
+  }
 
-    STLOG_HAL_V("HalCreate exit\n");
-    return (HALHANDLE)inst;
+  STLOG_HAL_V("HalCreate exit\n");
+  return (HALHANDLE)inst;
 }
 
 /**
@@ -246,107 +244,108 @@ HALHANDLE HalCreate(void* context, HAL_CALLBACK callback, uint32_t flags)
  * resources.
  * @param hHAL HAL handle
  */
-void HalDestroy(HALHANDLE hHAL)
-{
-    HalInstance* inst = (HalInstance*)hHAL;
-    // Tell the thread that we want to finish
-    ThreadMesssage msg;
-    msg.command = MSG_EXIT_REQUEST;
-    msg.payload = 0;
-    msg.length = 0;
-
-    HalEnqueueThreadMessage(inst, &msg);
-
-    // Wait for thread to finish
-    pthread_join(inst->thread, NULL);
-
-    // Cleanup and exit
-    sem_destroy(&inst->semaphore);
-    sem_destroy(&inst->upstreamBlock);
-    sem_destroy(&inst->bufferResourceSem);
-    pthread_mutex_destroy(&inst->hMutex);
-
-    // Free resources
-    free(inst->bufferData);
-    free(inst);
-
-    STLOG_HAL_V("HalDestroy done\n");
+void HalDestroy(HALHANDLE hHAL) {
+  HalInstance* inst = (HalInstance*)hHAL;
+  // Tell the thread that we want to finish
+  ThreadMessage msg;
+  msg.command = MSG_EXIT_REQUEST;
+  msg.payload = 0;
+  msg.length = 0;
+
+  HalEnqueueThreadMessage(inst, &msg);
+
+  // Wait for thread to finish
+  pthread_join(inst->thread, NULL);
+
+  // Cleanup and exit
+  sem_destroy(&inst->semaphore);
+  sem_destroy(&inst->upstreamBlock);
+  sem_destroy(&inst->bufferResourceSem);
+  pthread_mutex_destroy(&inst->hMutex);
+
+  // Free resources
+  free(inst->bufferData);
+  free(inst);
+
+  STLOG_HAL_V("HalDestroy done\n");
 }
 
 /**
  * Send an NCI message downstream to HAL protocol layer (DH->NFCC transfer).
- * Block if more than NUM_BUFFERS (10) transfers are outstanding, otherwise will return immediately.
+ * Block if more than NUM_BUFFERS (10) transfers are outstanding, otherwise will
+ * return immediately.
  * @param hHAL HAL handle
  * @param data Data message
  * @param size Message size
  */ bool HalSendDownstream(HALHANDLE hHAL, const uint8_t* data, size_t size)
 {
-    // Send an NCI frame downstream. will
-    HalInstance* inst = (HalInstance*)hHAL;
+  // Send an NCI frame downstream. will
+  HalInstance* inst = (HalInstance*)hHAL;
 
-    if ((size <= MAX_BUFFER_SIZE) && (size > 0)) {
-        ThreadMesssage msg;
-        HalBuffer* b = HalAllocBuffer(inst);
+  if ((size <= MAX_BUFFER_SIZE) && (size > 0)) {
+    ThreadMessage msg;
+    HalBuffer* b = HalAllocBuffer(inst);
 
-        if (!b) {
-            // Should never be reachable
-            return false;
-        }
+    if (!b) {
+      // Should never be reachable
+      return false;
+    }
 
-        memcpy(b->data, data, size);
-        b->length = size;
+    memcpy(b->data, data, size);
+    b->length = size;
 
-        msg.command = MSG_TX_DATA;
-        msg.payload = 0;
-        msg.length = 0;
-        msg.buffer = b;
+    msg.command = MSG_TX_DATA;
+    msg.payload = 0;
+    msg.length = 0;
+    msg.buffer = b;
 
-        return HalEnqueueThreadMessage(inst, &msg);
+    return HalEnqueueThreadMessage(inst, &msg);
 
-    } else {
-        STLOG_HAL_E("HalSendDownstream size to large %zu instead of %d\n", size,
-              MAX_BUFFER_SIZE);
-        return false;
-    }
+  } else {
+    STLOG_HAL_E("HalSendDownstream size to large %zu instead of %d\n", size,
+                MAX_BUFFER_SIZE);
+    return false;
+  }
 }
 
 // HAL WRAPPER
 /**
  * Send an NCI message downstream to HAL protocol layer (DH->NFCC transfer).
- * Block if more than NUM_BUFFERS (10) transfers are outstanding, otherwise will return immediately.
+ * Block if more than NUM_BUFFERS (10) transfers are outstanding, otherwise will
+ * return immediately.
  * @param hHAL HAL handle
  * @param data Data message
  * @param size Message size
  */ bool HalSendDownstreamTimer(HALHANDLE hHAL, const uint8_t* data,
                                 size_t size, uint8_t duration)
 {
-    // Send an NCI frame downstream. will
-    HalInstance* inst = (HalInstance*)hHAL;
+  // Send an NCI frame downstream. will
+  HalInstance* inst = (HalInstance*)hHAL;
 
-    if ((size <= MAX_BUFFER_SIZE) && (size > 0)) {
-        ThreadMesssage msg;
-        HalBuffer* b = HalAllocBuffer(inst);
+  if ((size <= MAX_BUFFER_SIZE) && (size > 0)) {
+    ThreadMessage msg;
+    HalBuffer* b = HalAllocBuffer(inst);
 
-        if (!b) {
-            // Should never be reachable
-            return false;
-        }
+    if (!b) {
+      // Should never be reachable
+      return false;
+    }
 
-        memcpy(b->data, data, size);
-        b->length = size;
+    memcpy(b->data, data, size);
+    b->length = size;
 
-        msg.command = MSG_TX_DATA_TIMER_START;
-        msg.payload = 0;
-        msg.length = duration;
-        msg.buffer = b;
+    msg.command = MSG_TX_DATA_TIMER_START;
+    msg.payload = 0;
+    msg.length = duration;
+    msg.buffer = b;
 
-        return HalEnqueueThreadMessage(inst, &msg);
+    return HalEnqueueThreadMessage(inst, &msg);
 
-    } else {
-        STLOG_HAL_E("HalSendDownstreamTimer size to large %zu instead of %d\n", size,
-              MAX_BUFFER_SIZE);
-        return false;
-    }
+  } else {
+    STLOG_HAL_E("HalSendDownstreamTimer size to large %zu instead of %d\n",
+                size, MAX_BUFFER_SIZE);
+    return false;
+  }
 }
 
 /**
@@ -357,15 +356,12 @@ void HalDestroy(HALHANDLE hHAL)
  * @param data Data message
  * @param size Message size
  */
-bool HalSendDownstreamStopTimer(HALHANDLE hHAL)
-{
-    // Send an NCI frame downstream. will
-    HalInstance* inst = (HalInstance*)hHAL;
-
-    HalStopTimer(inst);
-    return 1;
-
+bool HalSendDownstreamStopTimer(HALHANDLE hHAL) {
+  // Send an NCI frame downstream. will
+  HalInstance* inst = (HalInstance*)hHAL;
 
+  HalStopTimer(inst);
+  return 1;
 }
 
 /**
@@ -373,26 +369,26 @@ bool HalSendDownstreamStopTimer(HALHANDLE hHAL)
  * @param hHAL HAL handle
  * @param data Data message
  * @param size Message size
- */ bool HalSendUpstream(HALHANDLE hHAL, const uint8_t* data, size_t size)
-{
-    HalInstance* inst = (HalInstance*)hHAL;
-    if ((size <= MAX_BUFFER_SIZE) && (size > 0)) {
-        ThreadMesssage msg;
-        msg.command = MSG_RX_DATA;
-        msg.payload = data;
-        msg.length = size;
-
-        if (HalEnqueueThreadMessage(inst, &msg)) {
-            // Block until the protocol has taken a copy of the data
-            sem_wait_nointr(&inst->upstreamBlock);
-            return true;
-        }
-        return false;
-    } else {
-        STLOG_HAL_E("HalSendUpstream size to large %zu instead of %d\n", size,
-              MAX_BUFFER_SIZE);
-        return false;
+ */
+bool HalSendUpstream(HALHANDLE hHAL, const uint8_t* data, size_t size) {
+  HalInstance* inst = (HalInstance*)hHAL;
+  if ((size <= MAX_BUFFER_SIZE) && (size > 0)) {
+    ThreadMessage msg;
+    msg.command = MSG_RX_DATA;
+    msg.payload = data;
+    msg.length = size;
+
+    if (HalEnqueueThreadMessage(inst, &msg)) {
+      // Block until the protocol has taken a copy of the data
+      sem_wait_nointr(&inst->upstreamBlock);
+      return true;
     }
+    return false;
+  } else {
+    STLOG_HAL_E("HalSendUpstream size to large %zu instead of %d\n", size,
+                MAX_BUFFER_SIZE);
+    return false;
+  }
 }
 
 /**************************************************************************************************
@@ -403,60 +399,56 @@ bool HalSendDownstreamStopTimer(HALHANDLE hHAL)
 /*
  * Get current time stamp
  */
-struct timespec HalGetTimestamp(void)
-{
-    struct timespec tm;
-    clock_gettime(CLOCK_REALTIME, &tm);
-    return tm;
+struct timespec HalGetTimestamp(void) {
+  struct timespec tm;
+  clock_gettime(CLOCK_REALTIME, &tm);
+  return tm;
 }
 
-int HalTimeDiffInMs(struct timespec start, struct timespec end)
-{
-    struct timespec temp;
-    if ((end.tv_nsec - start.tv_nsec) < 0) {
-        temp.tv_sec = end.tv_sec - start.tv_sec - 1;
-        temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
-    } else {
-        temp.tv_sec = end.tv_sec - start.tv_sec;
-        temp.tv_nsec = end.tv_nsec - start.tv_nsec;
-    }
-
-    return (temp.tv_nsec / 1000000) + (temp.tv_sec * 1000);
+int HalTimeDiffInMs(struct timespec start, struct timespec end) {
+  struct timespec temp;
+  if ((end.tv_nsec - start.tv_nsec) < 0) {
+    temp.tv_sec = end.tv_sec - start.tv_sec - 1;
+    temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
+  } else {
+    temp.tv_sec = end.tv_sec - start.tv_sec;
+    temp.tv_nsec = end.tv_nsec - start.tv_nsec;
+  }
+
+  return (temp.tv_nsec / 1000000) + (temp.tv_sec * 1000);
 }
 
-
 /**
  * Determine the next shortest sleep to fulfill the pending timer requirements.
  * @param inst HAL instance
  * @param now timespec structure for time definition
  */
-static uint32_t HalCalcSemWaitingTime(HalInstance* inst, struct timespec* now)
-{
-    // Default to infinite wait time
-    uint32_t result = OS_SYNC_INFINITE;
+static uint32_t HalCalcSemWaitingTime(HalInstance* inst, struct timespec* now) {
+  // Default to infinite wait time
+  uint32_t result = OS_SYNC_INFINITE;
 
-    if (inst->timer.active) {
-        int delta =
-            inst->timer.duration - HalTimeDiffInMs(inst->timer.startTime, *now);
+  if (inst->timer.active) {
+    int delta =
+        inst->timer.duration - HalTimeDiffInMs(inst->timer.startTime, *now);
 
-        if (delta < 0) {
-            // If we have a timer that has already expired, pick a zero wait time
-            result = 0;
+    if (delta < 0) {
+      // If we have a timer that has already expired, pick a zero wait time
+      result = 0;
 
-        } else if ((uint32_t)delta < result) {
-            // Smaller time difference? If so take it
-            result = delta;
-        }
+    } else if ((uint32_t)delta < result) {
+      // Smaller time difference? If so take it
+      result = delta;
     }
+  }
 
-    if (result != OS_SYNC_INFINITE) {
-        // Add one millisecond on top of that, so the waiting semaphore will time
-        // out just a moment
-        // after the timer should expire
-        result += 1;
-    }
+  if (result != OS_SYNC_INFINITE) {
+    // Add one millisecond on top of that, so the waiting semaphore will time
+    // out just a moment
+    // after the timer should expire
+    result += 1;
+  }
 
-    return result;
+  return result;
 }
 
 /**************************************************************************************************
@@ -465,18 +457,16 @@ static uint32_t HalCalcSemWaitingTime(HalInstance* inst, struct timespec* now)
  *
  **************************************************************************************************/
 
-static void HalStopTimer(HalInstance* inst)
-{
-    inst->timer.active = false;
-    STLOG_HAL_D("HalStopTimer \n");
+static void HalStopTimer(HalInstance* inst) {
+  inst->timer.active = false;
+  STLOG_HAL_D("HalStopTimer \n");
 }
 
-static void HalStartTimer(HalInstance* inst, uint32_t duration)
-{
-    STLOG_HAL_D("HalStartTimer \n");
-    inst->timer.startTime = HalGetTimestamp();
-    inst->timer.active = true;
-    inst->timer.duration = duration;
+static void HalStartTimer(HalInstance* inst, uint32_t duration) {
+  STLOG_HAL_D("HalStartTimer \n");
+  inst->timer.startTime = HalGetTimestamp();
+  inst->timer.active = true;
+  inst->timer.duration = duration;
 }
 
 /**************************************************************************************************
@@ -491,39 +481,38 @@ static void HalStartTimer(HalInstance* inst, uint32_t duration)
  * @param msg Message to send
  * @return true if message properly copied in ring buffer
  */
-static bool HalEnqueueThreadMessage(HalInstance* inst, ThreadMesssage* msg)
-{
-    // Put a message to the queue
-    int nextWriteSlot;
-    bool result = true;
+static bool HalEnqueueThreadMessage(HalInstance* inst, ThreadMessage* msg) {
+  // Put a message to the queue
+  int nextWriteSlot;
+  bool result = true;
 
-    pthread_mutex_lock(&inst->hMutex);
+  pthread_mutex_lock(&inst->hMutex);
 
-    nextWriteSlot = inst->ringWritePos + 1;
+  nextWriteSlot = inst->ringWritePos + 1;
 
-    if (nextWriteSlot == HAL_QUEUE_MAX) {
-        nextWriteSlot = 0;
-    }
+  if (nextWriteSlot == HAL_QUEUE_MAX) {
+    nextWriteSlot = 0;
+  }
 
-    // Check that we don't overflow the queue entries
-    if (nextWriteSlot == inst->ringReadPos) {
-        STLOG_HAL_E("HAL thread message ring: RNR (implement me!!)");
-        result = false;
-    }
+  // Check that we don't overflow the queue entries
+  if (nextWriteSlot == inst->ringReadPos) {
+    STLOG_HAL_E("HAL thread message ring: RNR (implement me!!)");
+    result = false;
+  }
 
-    if (result) {
-        // inst->ring[nextWriteSlot] = *msg;
-        memcpy(&(inst->ring[nextWriteSlot]), msg, sizeof(ThreadMesssage));
-        inst->ringWritePos = nextWriteSlot;
-    }
+  if (result) {
+    // inst->ring[nextWriteSlot] = *msg;
+    memcpy(&(inst->ring[nextWriteSlot]), msg, sizeof(ThreadMessage));
+    inst->ringWritePos = nextWriteSlot;
+  }
 
-    pthread_mutex_unlock(&inst->hMutex);
+  pthread_mutex_unlock(&inst->hMutex);
 
-    if (result) {
-        sem_post(&inst->semaphore);
-    }
+  if (result) {
+    sem_post(&inst->semaphore);
+  }
 
-    return result;
+  return result;
 }
 
 /**
@@ -532,35 +521,33 @@ static bool HalEnqueueThreadMessage(HalInstance* inst, ThreadMesssage* msg)
  * @param msg Message received
  * @return true if there is a new message to pull, false otherwise.
  */
-static bool HalDequeueThreadMessage(HalInstance* inst, ThreadMesssage* msg)
-{
-    int nextCmdIndex;
-    bool result = true;
-    // New data available
-    pthread_mutex_lock(&inst->hMutex);
-
-    // Get new timer read index
-    nextCmdIndex = inst->ringReadPos + 1;
-
-    if (nextCmdIndex == HAL_QUEUE_MAX) {
-        nextCmdIndex = 0;
-    }
-     //check if ring buffer is empty
-    if (inst->ringReadPos == inst->ringWritePos)
-      {
-        STLOG_HAL_E("HAL thread message ring: already read last valid data");
-        result = false;
-      }
-
-    // Get new element from ringbuffer
-    if (result) {
-    memcpy(msg, &(inst->ring[nextCmdIndex]), sizeof(ThreadMesssage));
+static bool HalDequeueThreadMessage(HalInstance* inst, ThreadMessage* msg) {
+  int nextCmdIndex;
+  bool result = true;
+  // New data available
+  pthread_mutex_lock(&inst->hMutex);
+
+  // Get new timer read index
+  nextCmdIndex = inst->ringReadPos + 1;
+
+  if (nextCmdIndex == HAL_QUEUE_MAX) {
+    nextCmdIndex = 0;
+  }
+  // check if ring buffer is empty
+  if (inst->ringReadPos == inst->ringWritePos) {
+    STLOG_HAL_E("HAL thread message ring: already read last valid data");
+    result = false;
+  }
+
+  // Get new element from ringbuffer
+  if (result) {
+    memcpy(msg, &(inst->ring[nextCmdIndex]), sizeof(ThreadMessage));
     inst->ringReadPos = nextCmdIndex;
-    }
+  }
 
-    pthread_mutex_unlock(&inst->hMutex);
+  pthread_mutex_unlock(&inst->hMutex);
 
-    return result;
+  return result;
 }
 
 /**************************************************************************************************
@@ -574,30 +561,29 @@ static bool HalDequeueThreadMessage(HalInstance* inst, ThreadMesssage* msg)
  * @param inst HAL instance
  * @return Pointer to allocated HAL buffer
  */
-static HalBuffer* HalAllocBuffer(HalInstance* inst)
-{
-    HalBuffer* b;
+static HalBuffer* HalAllocBuffer(HalInstance* inst) {
+  HalBuffer* b;
 
-    // Wait until we have a buffer resource
-    sem_wait_nointr(&inst->bufferResourceSem);
+  // Wait until we have a buffer resource
+  sem_wait_nointr(&inst->bufferResourceSem);
 
-    pthread_mutex_lock(&inst->hMutex);
+  pthread_mutex_lock(&inst->hMutex);
 
-    b = inst->freeBufferList;
-    if (b) {
-        inst->freeBufferList = b->next;
-        b->next = 0;
-    }
+  b = inst->freeBufferList;
+  if (b) {
+    inst->freeBufferList = b->next;
+    b->next = 0;
+  }
 
-    pthread_mutex_unlock(&inst->hMutex);
+  pthread_mutex_unlock(&inst->hMutex);
 
-    if (!b) {
-        STLOG_HAL_E(
-            "! unable to allocate buffer resource."
-            "check bufferResourceSem\n");
-    }
+  if (!b) {
+    STLOG_HAL_E(
+        "! unable to allocate buffer resource."
+        "check bufferResourceSem\n");
+  }
 
-    return b;
+  return b;
 }
 
 /**
@@ -606,19 +592,18 @@ static HalBuffer* HalAllocBuffer(HalInstance* inst)
  * @param b Pointer of HAL buffer to free
  * @return Pointer of freed HAL buffer
  */
-static HalBuffer* HalFreeBuffer(HalInstance* inst, HalBuffer* b)
-{
-    pthread_mutex_lock(&inst->hMutex);
+static HalBuffer* HalFreeBuffer(HalInstance* inst, HalBuffer* b) {
+  pthread_mutex_lock(&inst->hMutex);
 
-    b->next = inst->freeBufferList;
-    inst->freeBufferList = b;
+  b->next = inst->freeBufferList;
+  inst->freeBufferList = b;
 
-    pthread_mutex_unlock(&inst->hMutex);
+  pthread_mutex_unlock(&inst->hMutex);
 
-    // Unblock treads waiting for a buffer
-    sem_post(&inst->bufferResourceSem);
+  // Unblock treads waiting for a buffer
+  sem_post(&inst->bufferResourceSem);
 
-    return b;
+  return b;
 }
 
 /**************************************************************************************************
@@ -632,39 +617,37 @@ static HalBuffer* HalFreeBuffer(HalInstance* inst, HalBuffer* b)
  * @param inst HAL instance
  * @param e HAL event
  */
-static void Hal_event_handler(HalInstance* inst, HalEvent e)
-{
-    switch (e) {
-        case EVT_RX_DATA: {
-            // New data packet arrived
-            const uint8_t* nciData;
-            size_t nciLength;
-
-            // Extract raw NCI data from frame
-            nciData = inst->lastUsFrame;
-            nciLength = inst->lastUsFrameSize;
-
-            // Pass received raw NCI data to stack
-            inst->callback(inst->context, HAL_EVENT_DATAIND, nciData, nciLength);
-        }
-        break;
-
-        case EVT_TX_DATA:
-            // NCI data arrived from stack
-            // Send data
-            inst->callback(inst->context, HAL_EVENT_DSWRITE, inst->nciBuffer->data,
-                           inst->nciBuffer->length);
-
-            // Free the buffer
-            HalFreeBuffer(inst, inst->nciBuffer);
-            inst->nciBuffer = 0;
-            break;
-
-        // HAL WRAPPER
-        case EVT_TIMER:
-            inst->callback(inst->context, HAL_EVENT_TIMER_TIMEOUT, NULL, 0);
-            break;
-    }
+static void Hal_event_handler(HalInstance* inst, HalEvent e) {
+  switch (e) {
+    case EVT_RX_DATA: {
+      // New data packet arrived
+      const uint8_t* nciData;
+      size_t nciLength;
+
+      // Extract raw NCI data from frame
+      nciData = inst->lastUsFrame;
+      nciLength = inst->lastUsFrameSize;
+
+      // Pass received raw NCI data to stack
+      inst->callback(inst->context, HAL_EVENT_DATAIND, nciData, nciLength);
+    } break;
+
+    case EVT_TX_DATA:
+      // NCI data arrived from stack
+      // Send data
+      inst->callback(inst->context, HAL_EVENT_DSWRITE, inst->nciBuffer->data,
+                     inst->nciBuffer->length);
+
+      // Free the buffer
+      HalFreeBuffer(inst, inst->nciBuffer);
+      inst->nciBuffer = 0;
+      break;
+
+    // HAL WRAPPER
+    case EVT_TIMER:
+      inst->callback(inst->context, HAL_EVENT_TIMER_TIMEOUT, NULL, 0);
+      break;
+  }
 }
 
 /**************************************************************************************************
@@ -678,124 +661,121 @@ static void Hal_event_handler(HalInstance* inst, HalEvent e)
  * RX/TX/TIMER are dispatched from here.
  * @param arg HAL instance arguments
  */
-static void* HalWorkerThread(void* arg)
-{
-    HalInstance* inst = (HalInstance*)arg;
-    inst->exitRequest = false;
-
-    STLOG_HAL_V("thread running\n");
-
-    while (!inst->exitRequest) {
-        struct timespec now = HalGetTimestamp();
-        uint32_t waitResult =
-            HalSemWait(&inst->semaphore, HalCalcSemWaitingTime(inst, &now));
-
-        switch (waitResult) {
-            case OS_SYNC_TIMEOUT: {
-                // One or more times have expired
-                STLOG_HAL_W("OS_SYNC_TIMEOUT\n");
-                now = HalGetTimestamp();
-
-                // HAL WRAPPER
-                // callback to hal wrapper
-                // Unblock
-                sem_post(&inst->upstreamBlock);
-
-                // Data frame
-                Hal_event_handler(inst, EVT_TIMER);
-            }
-            break;
-
-            case OS_SYNC_RELEASED: {
-                // A message arrived
-                ThreadMesssage msg;
-
-                if (HalDequeueThreadMessage(inst, &msg)) {
-                    switch (msg.command) {
-                        case MSG_EXIT_REQUEST:
-
-                            STLOG_HAL_V("received exit request from upper layer\n");
-                            inst->exitRequest = true;
-                            break;
-
-                        case MSG_TX_DATA:
-                            STLOG_HAL_V("received new NCI data from stack\n");
-
-                            // Attack to end of list
-                            if (!inst->pendingNciList) {
-                                inst->pendingNciList = msg.buffer;
-                                inst->pendingNciList->next = 0;
-                            } else {
-                                // Find last element of the list. b->next is zero for this
-                                // element
-                                HalBuffer* b;
-                                for (b = inst->pendingNciList; b->next; b = b->next) {
-                                };
-
-                                // Concatenate to list
-                                b->next = msg.buffer;
-                                msg.buffer->next = 0;
-                            }
-
-                            // Start transmitting if we're in the correct state
-                            HalTriggerNextDsPacket(inst);
-                            break;
-
-                        // HAL WRAPPER
-                        case MSG_TX_DATA_TIMER_START:
-                            STLOG_HAL_V("received new NCI data from stack, need timer start\n");
-
-                            // Attack to end of list
-                            if (!inst->pendingNciList) {
-                                inst->pendingNciList = msg.buffer;
-                                inst->pendingNciList->next = 0;
-                            } else {
-                                // Find last element of the list. b->next is zero for this
-                                // element
-                                HalBuffer* b;
-                                for (b = inst->pendingNciList; b->next; b = b->next) {
-                                };
-
-                                // Concatenate to list
-                                b->next = msg.buffer;
-                                msg.buffer->next = 0;
-                            }
-
-                            // Start timer
-                            HalStartTimer(inst, msg.length);
-
-                            // Start transmitting if we're in the correct state
-                            HalTriggerNextDsPacket(inst);
-                            break;
-
-                        case MSG_RX_DATA:
-                            STLOG_HAL_D("received new data from CLF\n");
-                            HalOnNewUpstreamFrame(inst, msg.payload, msg.length);
-                            break;
-
-                        default:
-                            STLOG_HAL_E("!received unkown thread message?\n");
-                            break;
-                    }
-                } else {
-                    STLOG_HAL_E("!got wakeup in workerthread, but no message here? ?\n");
-
-            }
-            }
-            break;
-
-            case OS_SYNC_FAILED:
-
-              STLOG_HAL_E(
-                    "!Something went horribly wrong.. The semaphore wait function "
-                    "failed\n");
-                inst->exitRequest = true;
-                break;
+static void* HalWorkerThread(void* arg) {
+  HalInstance* inst = (HalInstance*)arg;
+  inst->exitRequest = false;
+
+  STLOG_HAL_V("thread running\n");
+
+  while (!inst->exitRequest) {
+    struct timespec now = HalGetTimestamp();
+    uint32_t waitResult =
+        HalSemWait(&inst->semaphore, HalCalcSemWaitingTime(inst, &now));
+
+    switch (waitResult) {
+      case OS_SYNC_TIMEOUT: {
+        // One or more times have expired
+        STLOG_HAL_W("OS_SYNC_TIMEOUT\n");
+        now = HalGetTimestamp();
+
+        // HAL WRAPPER
+        // callback to hal wrapper
+        // Unblock
+        sem_post(&inst->upstreamBlock);
+
+        // Data frame
+        Hal_event_handler(inst, EVT_TIMER);
+      } break;
+
+      case OS_SYNC_RELEASED: {
+        // A message arrived
+        ThreadMessage msg;
+
+        if (HalDequeueThreadMessage(inst, &msg)) {
+          switch (msg.command) {
+            case MSG_EXIT_REQUEST:
+
+              STLOG_HAL_V("received exit request from upper layer\n");
+              inst->exitRequest = true;
+              break;
+
+            case MSG_TX_DATA:
+              STLOG_HAL_V("received new NCI data from stack\n");
+
+              // Attack to end of list
+              if (!inst->pendingNciList) {
+                inst->pendingNciList = msg.buffer;
+                inst->pendingNciList->next = 0;
+              } else {
+                // Find last element of the list. b->next is zero for this
+                // element
+                HalBuffer* b;
+                for (b = inst->pendingNciList; b->next; b = b->next) {
+                };
+
+                // Concatenate to list
+                b->next = msg.buffer;
+                msg.buffer->next = 0;
+              }
+
+              // Start transmitting if we're in the correct state
+              HalTriggerNextDsPacket(inst);
+              break;
+
+            // HAL WRAPPER
+            case MSG_TX_DATA_TIMER_START:
+              STLOG_HAL_V(
+                  "received new NCI data from stack, need timer start\n");
+
+              // Attack to end of list
+              if (!inst->pendingNciList) {
+                inst->pendingNciList = msg.buffer;
+                inst->pendingNciList->next = 0;
+              } else {
+                // Find last element of the list. b->next is zero for this
+                // element
+                HalBuffer* b;
+                for (b = inst->pendingNciList; b->next; b = b->next) {
+                };
+
+                // Concatenate to list
+                b->next = msg.buffer;
+                msg.buffer->next = 0;
+              }
+
+              // Start timer
+              HalStartTimer(inst, msg.length);
+
+              // Start transmitting if we're in the correct state
+              HalTriggerNextDsPacket(inst);
+              break;
+
+            case MSG_RX_DATA:
+              STLOG_HAL_D("received new data from CLF\n");
+              HalOnNewUpstreamFrame(inst, msg.payload, msg.length);
+              break;
+
+            default:
+              STLOG_HAL_E("!received unknown thread message?\n");
+              break;
+          }
+        } else {
+          STLOG_HAL_E("!got wakeup in workerthread, but no message here? ?\n");
         }
+      } break;
+
+      case OS_SYNC_FAILED:
+
+        STLOG_HAL_E(
+            "!Something went horribly wrong.. The semaphore wait function "
+            "failed\n");
+        inst->exitRequest = true;
+        break;
     }
+  }
 
-    STLOG_HAL_D("thread about to exit\n");
-    return NULL;
+  STLOG_HAL_D("thread about to exit\n");
+  return NULL;
 }
 
 /**************************************************************************************************
@@ -809,10 +789,12 @@ static void* HalWorkerThread(void* arg)
  * @return sem_wait return value.
  */
 
-static inline int sem_wait_nointr(sem_t *sem) {
+static inline int sem_wait_nointr(sem_t* sem) {
   while (sem_wait(sem))
-    if (errno == EINTR) errno = 0;
-    else return -1;
+    if (errno == EINTR)
+      errno = 0;
+    else
+      return -1;
   return 0;
 }
 
@@ -823,39 +805,37 @@ static inline int sem_wait_nointr(sem_t *sem) {
  * @param length Size of HAL data
  */
 static void HalOnNewUpstreamFrame(HalInstance* inst, const uint8_t* data,
-                                  size_t length)
-{
-    memcpy(inst->lastUsFrame, data, length);
-    inst->lastUsFrameSize = length;
-
-    // Data frame
-    Hal_event_handler(inst, EVT_RX_DATA);
-    // Allow the I2C thread to get the next message (if done early, it may
-    // overwrite before handled)
-    sem_post(&inst->upstreamBlock);
+                                  size_t length) {
+  memcpy(inst->lastUsFrame, data, length);
+  inst->lastUsFrameSize = length;
+
+  // Data frame
+  Hal_event_handler(inst, EVT_RX_DATA);
+  // Allow the I2C thread to get the next message (if done early, it may
+  // overwrite before handled)
+  sem_post(&inst->upstreamBlock);
 }
 
 /**
  * Send out the next queued up buffer for TX if any.
  * @param inst HAL instance
  */
-static void HalTriggerNextDsPacket(HalInstance* inst)
-{
-    // Check if we have something to transmit downstream
-    HalBuffer* b = inst->pendingNciList;
-
-    if (b) {
-        // Get the buffer from the pending list
-        inst->pendingNciList = b->next;
-        inst->nciBuffer = b;
-
-        STLOG_HAL_V("trigger transport of next NCI data downstream\n");
-        // Process the new nci frame
-        Hal_event_handler(inst, EVT_TX_DATA);
-
-    } else {
-        STLOG_HAL_V("no new NCI data to transmit, enter wait..\n");
-    }
+static void HalTriggerNextDsPacket(HalInstance* inst) {
+  // Check if we have something to transmit downstream
+  HalBuffer* b = inst->pendingNciList;
+
+  if (b) {
+    // Get the buffer from the pending list
+    inst->pendingNciList = b->next;
+    inst->nciBuffer = b;
+
+    STLOG_HAL_V("trigger transport of next NCI data downstream\n");
+    // Process the new nci frame
+    Hal_event_handler(inst, EVT_TX_DATA);
+
+  } else {
+    STLOG_HAL_V("no new NCI data to transmit, enter wait..\n");
+  }
 }
 
 /*
@@ -864,68 +844,68 @@ static void HalTriggerNextDsPacket(HalInstance* inst)
  * param uint32_t timeout
  * return uint32_t
  */
-static uint32_t HalSemWait(sem_t* pSemaphore, uint32_t timeout)
-{
-    uint32_t result = OS_SYNC_RELEASED;
-    bool gotResult = false;
-
-    if (timeout == OS_SYNC_INFINITE) {
-        while (!gotResult) {
-            if (sem_wait(pSemaphore) == -1) {
-                int e = errno;
-                char msg[200];
-
-                if (e == EINTR) {
-                    STLOG_HAL_W(
-                        "! semaphore (infin) wait interrupted by system signal. re-enter "
-                        "wait");
-                    continue;
-                }
-
-                strerror_r(e, msg, sizeof(msg) - 1);
-                STLOG_HAL_E("! semaphore (infin) wait failed. sem=0x%p, %s", pSemaphore, msg);
-                gotResult = true;
-                result = OS_SYNC_FAILED;
-            } else {
-                gotResult = true;
-            }
-        };
-    } else {
-        struct timespec tm;
-        long oneSecInNs = (int)1e9;
-
-        clock_gettime(CLOCK_REALTIME, &tm);
-
-        /* add timeout (can't overflow): */
-        tm.tv_sec += (timeout / 1000);
-        tm.tv_nsec += ((timeout % 1000) * 1000000);
-
-        /* make sure nanoseconds are below a million */
-        if (tm.tv_nsec >= oneSecInNs) {
-            tm.tv_sec++;
-            tm.tv_nsec -= oneSecInNs;
+static uint32_t HalSemWait(sem_t* pSemaphore, uint32_t timeout) {
+  uint32_t result = OS_SYNC_RELEASED;
+  bool gotResult = false;
+
+  if (timeout == OS_SYNC_INFINITE) {
+    while (!gotResult) {
+      if (sem_wait(pSemaphore) == -1) {
+        int e = errno;
+        char msg[200];
+
+        if (e == EINTR) {
+          STLOG_HAL_W(
+              "! semaphore (infin) wait interrupted by system signal. re-enter "
+              "wait");
+          continue;
+        }
+
+        strerror_r(e, msg, sizeof(msg) - 1);
+        STLOG_HAL_E("! semaphore (infin) wait failed. sem=0x%p, %s", pSemaphore,
+                    msg);
+        gotResult = true;
+        result = OS_SYNC_FAILED;
+      } else {
+        gotResult = true;
+      }
+    };
+  } else {
+    struct timespec tm;
+    long oneSecInNs = (int)1e9;
+
+    clock_gettime(CLOCK_REALTIME, &tm);
+
+    /* add timeout (can't overflow): */
+    tm.tv_sec += (timeout / 1000);
+    tm.tv_nsec += ((timeout % 1000) * 1000000);
+
+    /* make sure nanoseconds are below a million */
+    if (tm.tv_nsec >= oneSecInNs) {
+      tm.tv_sec++;
+      tm.tv_nsec -= oneSecInNs;
+    }
+
+    while (!gotResult) {
+      if (sem_timedwait(pSemaphore, &tm) == -1) {
+        int e = errno;
+
+        if (e == EINTR) {
+          /* interrupted by signal? repeat sem_wait again */
+          continue;
         }
 
-        while (!gotResult) {
-            if (sem_timedwait(pSemaphore, &tm) == -1) {
-                int e = errno;
-
-                if (e == EINTR) {
-                    /* interrupted by signal? repeat sem_wait again */
-                    continue;
-                }
-
-                if (e == ETIMEDOUT) {
-                    result = OS_SYNC_TIMEOUT;
-                    gotResult = true;
-                } else {
-                    result = OS_SYNC_FAILED;
-                    gotResult = true;
-                }
-            } else {
-                gotResult = true;
-            }
+        if (e == ETIMEDOUT) {
+          result = OS_SYNC_TIMEOUT;
+          gotResult = true;
+        } else {
+          result = OS_SYNC_FAILED;
+          gotResult = true;
         }
+      } else {
+        gotResult = true;
+      }
     }
-    return result;
+  }
+  return result;
 }
diff --git a/1.0/hal/halcore_private.h b/1.0/hal/halcore_private.h
index 5bb4853..2c5289a 100644
--- a/1.0/hal/halcore_private.h
+++ b/1.0/hal/halcore_private.h
@@ -23,6 +23,7 @@
 #include <semaphore.h>
 #include <stdint.h>
 #include <time.h>
+
 #include "halcore.h"
 
 #define MAX_NCIFRAME_PAYLOAD_SIZE 255
@@ -65,68 +66,68 @@
 #define HAL_SLEEP_TIMER_DURATION 500 /* ordinary t1 timeout to resent data */
 
 typedef struct tagHalBuffer {
-    uint8_t data[MAX_BUFFER_SIZE];
-    size_t length;
-    struct tagHalBuffer* next;
+  uint8_t data[MAX_BUFFER_SIZE];
+  size_t length;
+  struct tagHalBuffer* next;
 } HalBuffer;
 
 typedef struct tagThreadMessage {
-    uint32_t command;    /* message type / command */
-    const void* payload; /* ptr to message related data item */
-    size_t length;       /* length of above payload */
-    HalBuffer* buffer;   /* buffer object (optional) */
-} ThreadMesssage;
+  uint32_t command;    /* message type / command */
+  const void* payload; /* ptr to message related data item */
+  size_t length;       /* length of above payload */
+  HalBuffer* buffer;   /* buffer object (optional) */
+} ThreadMessage;
 
 typedef enum {
-    EVT_RX_DATA = 0,
-    EVT_TX_DATA = 1,
-    // HAL WRAPPER
-    EVT_TIMER = 2,
+  EVT_RX_DATA = 0,
+  EVT_TX_DATA = 1,
+  // HAL WRAPPER
+  EVT_TIMER = 2,
 } HalEvent;
 
 typedef struct tagTimer {
-    struct timespec startTime; /* start time (CLOCK_REALTIME)       */
-    uint32_t duration;         /* timer duration in milliseconds    */
-    bool active;               /* true if timer is currently active */
+  struct timespec startTime; /* start time (CLOCK_REALTIME)       */
+  uint32_t duration;         /* timer duration in milliseconds    */
+  bool active;               /* true if timer is currently active */
 } Timer;
 
 typedef struct tagHalInstance {
-    uint32_t flags;
-
-    void* context;
-    HAL_CALLBACK callback;
-
-    /* current timeout values */
-    uint32_t timeout;
-    Timer timer;
-
-    /* threading and runtime support */
-    bool exitRequest;
-    sem_t semaphore;
-    pthread_t thread;
-    pthread_mutex_t hMutex; /* guards the message ringbuffer */
-
-    /* IOBuffers for read/writes */
-    HalBuffer* bufferData;
-    HalBuffer* freeBufferList;
-    HalBuffer* pendingNciList; /* outgoing packages waiting to be processed */
-    HalBuffer* nciBuffer;      /* current buffer in progress */
-    sem_t bufferResourceSem;
-
-    sem_t upstreamBlock;
-
-    /* message ring-buffer */
-    ThreadMesssage ring[HAL_QUEUE_MAX];
-    int ringReadPos;
-    int ringWritePos;
-
-    /* current frame going downstream */
-    uint8_t lastDsFrame[MAX_BUFFER_SIZE];
-    size_t lastDsFrameSize;
-
-    /* current frame from CLF */
-    uint8_t lastUsFrame[MAX_BUFFER_SIZE];
-    size_t lastUsFrameSize;
+  uint32_t flags;
+
+  void* context;
+  HAL_CALLBACK callback;
+
+  /* current timeout values */
+  uint32_t timeout;
+  Timer timer;
+
+  /* threading and runtime support */
+  bool exitRequest;
+  sem_t semaphore;
+  pthread_t thread;
+  pthread_mutex_t hMutex; /* guards the message ringbuffer */
+
+  /* IOBuffers for read/writes */
+  HalBuffer* bufferData;
+  HalBuffer* freeBufferList;
+  HalBuffer* pendingNciList; /* outgoing packages waiting to be processed */
+  HalBuffer* nciBuffer;      /* current buffer in progress */
+  sem_t bufferResourceSem;
+
+  sem_t upstreamBlock;
+
+  /* message ring-buffer */
+  ThreadMessage ring[HAL_QUEUE_MAX];
+  int ringReadPos;
+  int ringWritePos;
+
+  /* current frame going downstream */
+  uint8_t lastDsFrame[MAX_BUFFER_SIZE];
+  size_t lastDsFrameSize;
+
+  /* current frame from CLF */
+  uint8_t lastUsFrame[MAX_BUFFER_SIZE];
+  size_t lastUsFrameSize;
 
 } HalInstance;
 
diff --git a/1.0/hal_wrapper.c b/1.0/hal_wrapper.c
index 1c2ca51..0c60974 100644
--- a/1.0/hal_wrapper.c
+++ b/1.0/hal_wrapper.c
@@ -21,6 +21,7 @@
 #include <errno.h>
 #include <hardware/nfc.h>
 #include <string.h>
+
 #include "android_logmsg.h"
 #include "halcore.h"
 
@@ -80,13 +81,11 @@ bool hal_wrapper_open(st21nfc_dev_t* dev, nfc_stack_callback_t* p_cback,
 }
 
 int hal_wrapper_close(int call_cb) {
-
   STLOG_HAL_D("%s", __func__);
 
   mHalWrapperState = HAL_WRAPPER_STATE_CLOSED;
   I2cCloseLayer();
-  if (call_cb)
-  mHalWrapperCallback(HAL_NFC_CLOSE_CPLT_EVT, HAL_NFC_STATUS_OK);
+  if (call_cb) mHalWrapperCallback(HAL_NFC_CLOSE_CPLT_EVT, HAL_NFC_STATUS_OK);
 
   return 1;
 }
@@ -122,7 +121,8 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
         // Send PROP_NFC_MODE_SET_CMD(ON)
         if (!HalSendDownstreamTimer(mHalHandle, propNfcModeSetCmdOn,
                                     sizeof(propNfcModeSetCmdOn), 100)) {
-          STLOG_HAL_E("NFC-NCI HAL: %s  HalSendDownstreamTimer failed", __func__);
+          STLOG_HAL_E("NFC-NCI HAL: %s  HalSendDownstreamTimer failed",
+                      __func__);
         }
         mHalWrapperState = HAL_WRAPPER_STATE_NFC_ENABLE_ON;
       } else {
@@ -142,7 +142,7 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
         // Send CORE_INIT_CMD
         STLOG_HAL_D("%s - Sending CORE_INIT_CMD", __func__);
         if (!HalSendDownstream(mHalHandle, coreInitCmd, sizeof(coreInitCmd))) {
-           STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
+          STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
         }
       }
       // CORE_INIT_RSP
@@ -175,9 +175,9 @@ static void halWrapperCallback(uint8_t event, uint8_t event_status) {
       if (event == HAL_WRAPPER_TIMEOUT_EVT) {
         // timeout
         // Send CORE_INIT_CMD
-          STLOG_HAL_D("%s - Sending CORE_INIT_CMD", __func__);
+        STLOG_HAL_D("%s - Sending CORE_INIT_CMD", __func__);
         if (!HalSendDownstream(mHalHandle, coreInitCmd, sizeof(coreInitCmd))) {
-            STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
+          STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
         }
         return;
       }
diff --git a/1.0/include/android_logmsg.h b/1.0/include/android_logmsg.h
index 197d1da..7aaf05a 100644
--- a/1.0/include/android_logmsg.h
+++ b/1.0/include/android_logmsg.h
@@ -25,9 +25,10 @@
 extern "C" {
 #endif
 
-#include "data_types.h"
-#include <log/log.h>
 #include <cutils/properties.h>
+#include <log/log.h>
+
+#include "data_types.h"
 
 #define DISP_NCI ProtoDispAdapterDisplayNciPacket
 #define HAL_LOG_TAG "StNfcHal"
@@ -36,37 +37,37 @@ extern unsigned char hal_trace_level;
 extern int GetNumValue(const char* name, void* p_value, unsigned long len);
 
 /* #######################
-* Set the log module name in .conf file
-* ########################## */
+ * Set the log module name in .conf file
+ * ########################## */
 #define NAME_STNFC_HAL_LOGLEVEL "STNFC_HAL_LOGLEVEL"
 
 /* #######################
-* Set the logging level
-* ######################## */
-#define STNFC_TRACE_LEVEL_NONE    0x00
-#define STNFC_TRACE_LEVEL_ERROR   0x01
+ * Set the logging level
+ * ######################## */
+#define STNFC_TRACE_LEVEL_NONE 0x00
+#define STNFC_TRACE_LEVEL_ERROR 0x01
 #define STNFC_TRACE_LEVEL_WARNING 0x02
-#define STNFC_TRACE_LEVEL_DEBUG   0x03
+#define STNFC_TRACE_LEVEL_DEBUG 0x03
 #define STNFC_TRACE_LEVEL_VERBOSE 0x04
 
-#define STLOG_HAL_V(...)                                       \
-  {                                                              \
-    if (hal_trace_level >= STNFC_TRACE_LEVEL_VERBOSE)  \
+#define STLOG_HAL_V(...)                                    \
+  {                                                         \
+    if (hal_trace_level >= STNFC_TRACE_LEVEL_VERBOSE)       \
       LOG_PRI(ANDROID_LOG_DEBUG, HAL_LOG_TAG, __VA_ARGS__); \
   }
-#define STLOG_HAL_D(...)                                       \
-  {                                                              \
-    if (hal_trace_level >= STNFC_TRACE_LEVEL_DEBUG)  \
+#define STLOG_HAL_D(...)                                    \
+  {                                                         \
+    if (hal_trace_level >= STNFC_TRACE_LEVEL_DEBUG)         \
       LOG_PRI(ANDROID_LOG_DEBUG, HAL_LOG_TAG, __VA_ARGS__); \
   }
-#define STLOG_HAL_W(...)                                      \
-  {                                                             \
-    if (hal_trace_level >= STNFC_TRACE_LEVEL_WARNING)  \
+#define STLOG_HAL_W(...)                                   \
+  {                                                        \
+    if (hal_trace_level >= STNFC_TRACE_LEVEL_WARNING)      \
       LOG_PRI(ANDROID_LOG_WARN, HAL_LOG_TAG, __VA_ARGS__); \
   }
-#define STLOG_HAL_E(...)                                       \
-  {                                                              \
-    if (hal_trace_level >= STNFC_TRACE_LEVEL_ERROR)  \
+#define STLOG_HAL_E(...)                                    \
+  {                                                         \
+    if (hal_trace_level >= STNFC_TRACE_LEVEL_ERROR)         \
       LOG_PRI(ANDROID_LOG_ERROR, HAL_LOG_TAG, __VA_ARGS__); \
   }
 /*******************************************************************************
@@ -86,7 +87,7 @@ extern int GetNumValue(const char* name, void* p_value, unsigned long len);
 **                  STNFC_TRACE_LEVEL_DEBUG   3     * Debug messages (general)
 **
 *******************************************************************************/
-unsigned char InitializeSTLogLevel()  ;
+unsigned char InitializeSTLogLevel();
 
 void DispHal(const char* title, const void* data, size_t length);
 
diff --git a/1.0/include/halcore.h b/1.0/include/halcore.h
index 4b646b6..6096ab4 100644
--- a/1.0/include/halcore.h
+++ b/1.0/include/halcore.h
@@ -20,17 +20,17 @@
 #define __HALCORE_H_
 
 #include <errno.h>
+#include <pthread.h>
 #include <stdbool.h>
 #include <stdint.h>
 #include <stdlib.h>
-#include <pthread.h>
 
 /* events sent from the callback */
 #define HAL_EVENT_DSWRITE 1  /* write raw HAL data downstream   */
 #define HAL_EVENT_DATAIND 2  /* new NCI frame received from CLF  */
 #define HAL_EVENT_LINKLOST 3 /* connection/link lost             */
 #define HAL_EVENT_ERROR 4    /* protocol got into an error state */
-#define HAL_EVENT_JUNKRECEIVED                                        \
+#define HAL_EVENT_JUNKRECEIVED \
   5 /* protocol signals that junk has been received. resyncronization */
 
 #define HAL_EVENT_TIMER_TIMEOUT 6
diff --git a/1.0/nfc_nci_st21nfc.c b/1.0/nfc_nci_st21nfc.c
index 1d69df1..497fad6 100644
--- a/1.0/nfc_nci_st21nfc.c
+++ b/1.0/nfc_nci_st21nfc.c
@@ -23,8 +23,8 @@
 #include <cutils/properties.h>
 #include <errno.h>
 #include <hardware/nfc.h>
-#include <string.h>
 #include <pthread.h>
+#include <string.h>
 
 #include "android_logmsg.h"
 #include "halcore.h"
@@ -33,7 +33,6 @@ extern void HalCoreCallback(void* context, uint32_t event, const void* d,
                             size_t length);
 extern bool I2cOpenLayer(void* dev, HAL_CALLBACK callb, HALHANDLE* pHandle);
 
-
 typedef struct {
   struct nfc_nci_device nci_device;  // nci_device must be first struct member
   // below declarations are private variables within HAL
@@ -49,7 +48,6 @@ pthread_mutex_t hal_mtx = PTHREAD_MUTEX_INITIALIZER;
 
 uint8_t hal_dta_state = 0;
 
-
 /*
  * NCI HAL method implementations. These must be overridden
  */
@@ -69,7 +67,7 @@ static int hal_open(const struct nfc_nci_device* p_dev,
 
   (void)pthread_mutex_lock(&hal_mtx);
   st21nfc_dev_t* dev = (st21nfc_dev_t*)p_dev;
-  if (! hal_is_closed ) {
+  if (!hal_is_closed) {
     hal_wrapper_close(0);
   }
   dev->p_cback = p_cback;
@@ -79,12 +77,11 @@ static int hal_open(const struct nfc_nci_device* p_dev,
 
   result = hal_wrapper_open(dev, p_cback, p_data_cback, &dev->hHAL);
 
-  if (!result || !dev->hHAL)
-    {
-      dev->p_cback(HAL_NFC_OPEN_CPLT_EVT, HAL_NFC_STATUS_FAILED);
-      (void) pthread_mutex_unlock(&hal_mtx);
-      return -1;  // We are doomed, stop it here, NOW !
-    }
+  if (!result || !dev->hHAL) {
+    dev->p_cback(HAL_NFC_OPEN_CPLT_EVT, HAL_NFC_STATUS_FAILED);
+    (void)pthread_mutex_unlock(&hal_mtx);
+    return -1;  // We are doomed, stop it here, NOW !
+  }
   hal_is_closed = 0;
   (void)pthread_mutex_unlock(&hal_mtx);
   return 0;
@@ -98,24 +95,21 @@ static int hal_write(const struct nfc_nci_device* p_dev, uint16_t data_len,
 
   /* check if HAL is closed */
   int ret = (int)data_len;
-  (void) pthread_mutex_lock(&hal_mtx);
-  if (hal_is_closed)
-    {
-      ret = 0;
-    }
-
-  if (!ret)
-    {
-      (void) pthread_mutex_unlock(&hal_mtx);
-      return ret;
-    }
-  if (!HalSendDownstream(dev->hHAL, p_data, data_len))
-    {
-      STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
-      (void) pthread_mutex_unlock(&hal_mtx);
-      return 0;
-    }
-  (void) pthread_mutex_unlock(&hal_mtx);
+  (void)pthread_mutex_lock(&hal_mtx);
+  if (hal_is_closed) {
+    ret = 0;
+  }
+
+  if (!ret) {
+    (void)pthread_mutex_unlock(&hal_mtx);
+    return ret;
+  }
+  if (!HalSendDownstream(dev->hHAL, p_data, data_len)) {
+    STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
+    (void)pthread_mutex_unlock(&hal_mtx);
+    return 0;
+  }
+  (void)pthread_mutex_unlock(&hal_mtx);
 
   return ret;
 }
@@ -128,23 +122,25 @@ static int hal_core_initialized(const struct nfc_nci_device* p_dev,
   st21nfc_dev_t* dev = (st21nfc_dev_t*)p_dev;
   hal_dta_state = *p_core_init_rsp_params;
   dev->p_cback(HAL_NFC_POST_INIT_CPLT_EVT, HAL_NFC_STATUS_OK);
-  (void) pthread_mutex_unlock(&hal_mtx);
+  (void)pthread_mutex_unlock(&hal_mtx);
 
   return 0;  // return != 0 to signal ready immediate
 }
 
-static int hal_pre_discover(__attribute__((unused)) const struct nfc_nci_device* p_dev) {
+static int hal_pre_discover(__attribute__((unused))
+                            const struct nfc_nci_device* p_dev) {
   STLOG_HAL_D("NFC-NCI HAL: %s", __func__);
 
   return 0;  // false if no vendor-specific pre-discovery actions are needed
 }
 
-static int hal_close(__attribute__((unused)) const struct nfc_nci_device* p_dev) {
+static int hal_close(__attribute__((unused))
+                     const struct nfc_nci_device* p_dev) {
   STLOG_HAL_D("NFC-NCI HAL: %s", __func__);
 
   /* check if HAL is closed */
   (void)pthread_mutex_lock(&hal_mtx);
-  if ( hal_is_closed ) {
+  if (hal_is_closed) {
     (void)pthread_mutex_unlock(&hal_mtx);
     return 1;
   }
@@ -161,7 +157,8 @@ static int hal_close(__attribute__((unused)) const struct nfc_nci_device* p_dev)
   return 0;
 }
 
-static int hal_control_granted(__attribute__((unused)) const struct nfc_nci_device* p_dev) {
+static int hal_control_granted(__attribute__((unused))
+                               const struct nfc_nci_device* p_dev) {
   STLOG_HAL_D("NFC-NCI HAL: %s", __func__);
 
   return 0;
@@ -174,20 +171,18 @@ static int hal_power_cycle(const struct nfc_nci_device* p_dev) {
 
   /* check if HAL is closed */
   int ret = HAL_NFC_STATUS_OK;
-  (void) pthread_mutex_lock(&hal_mtx);
-  if (hal_is_closed)
-    {
-      ret = HAL_NFC_STATUS_FAILED;
-    }
-
-  if (ret != HAL_NFC_STATUS_OK)
-    {
-      (void) pthread_mutex_unlock(&hal_mtx);
-      return ret;
-    }
+  (void)pthread_mutex_lock(&hal_mtx);
+  if (hal_is_closed) {
+    ret = HAL_NFC_STATUS_FAILED;
+  }
+
+  if (ret != HAL_NFC_STATUS_OK) {
+    (void)pthread_mutex_unlock(&hal_mtx);
+    return ret;
+  }
   dev->p_cback(HAL_NFC_OPEN_CPLT_EVT, HAL_NFC_STATUS_OK);
 
-  (void) pthread_mutex_unlock(&hal_mtx);
+  (void)pthread_mutex_unlock(&hal_mtx);
   return HAL_NFC_STATUS_OK;
 }
 
@@ -197,15 +192,14 @@ static int hal_power_cycle(const struct nfc_nci_device* p_dev) {
 
 /* Close an opened nfc device instance */
 static int nfc_close(hw_device_t* dev) {
-  (void) pthread_mutex_lock(&hal_mtx);
+  (void)pthread_mutex_lock(&hal_mtx);
   free(dev);
-  (void) pthread_mutex_unlock(&hal_mtx);
+  (void)pthread_mutex_unlock(&hal_mtx);
   return 0;
 }
 
 static int nfc_open(const hw_module_t* module, const char* name,
                     hw_device_t** device) {
-
   if (strcmp(name, NFC_NCI_CONTROLLER) == 0) {
     st21nfc_dev_t* dev = calloc(1, sizeof(st21nfc_dev_t));
 
diff --git a/1.1/Nfc.cpp b/1.1/Nfc.cpp
index 97820d9..58352b6 100644
--- a/1.1/Nfc.cpp
+++ b/1.1/Nfc.cpp
@@ -19,7 +19,9 @@
 
 #define LOG_TAG "android.hardware.nfc@1.1-impl"
 #include "Nfc.h"
+
 #include <log/log.h>
+
 #include "StNfc_hal_api.h"
 
 #define CHK_STATUS(x) \
diff --git a/1.1/StNfcService.cpp b/1.1/StNfcService.cpp
index 66891b1..a5be228 100644
--- a/1.1/StNfcService.cpp
+++ b/1.1/StNfcService.cpp
@@ -19,8 +19,8 @@
 
 #define LOG_TAG "stnfc@1.1-service.st"
 #include <android/hardware/nfc/1.1/INfc.h>
-
 #include <hidl/LegacySupport.h>
+
 #include "Nfc.h"
 
 // Generated HIDL files
diff --git a/1.1/StNfc_hal_api.h b/1.1/StNfc_hal_api.h
index 8881401..f9f71af 100644
--- a/1.1/StNfc_hal_api.h
+++ b/1.1/StNfc_hal_api.h
@@ -29,7 +29,6 @@ using ::android::hardware::nfc::V1_1::NfcConfig;
 #define NFC_MODE_OFF 0
 #define NFC_MODE_QuickBoot 2
 
-
 int StNfc_hal_open(nfc_stack_callback_t* p_cback,
                    nfc_stack_data_callback_t* p_data_cback);
 int StNfc_hal_write(uint16_t data_len, const uint8_t* p_data);
diff --git a/1.1/hal_st21nfc.cc b/1.1/hal_st21nfc.cc
index c88ea8b..7e57582 100644
--- a/1.1/hal_st21nfc.cc
+++ b/1.1/hal_st21nfc.cc
@@ -340,7 +340,7 @@ int StNfc_hal_core_initialized(uint8_t* p_core_init_rsp_params) {
   hal_dta_state = *p_core_init_rsp_params;
 
   hal_wrapper_send_config();
-  (void) pthread_mutex_unlock(&hal_mtx);
+  (void)pthread_mutex_unlock(&hal_mtx);
 
   return 0;  // return != 0 to signal ready immediate
 }
@@ -410,8 +410,8 @@ int StNfc_hal_power_cycle() {
 
 void StNfc_hal_factoryReset() {
   STLOG_HAL_D("HAL st21nfc: %s", __func__);
-  //hal_wrapper_factoryReset();
-  // Nothing needed for factory reset in st21nfc case.
+  // hal_wrapper_factoryReset();
+  //  Nothing needed for factory reset in st21nfc case.
 }
 
 int StNfc_hal_closeForPowerOffCase() {
diff --git a/1.2/Nfc.cpp b/1.2/Nfc.cpp
index 80945f0..1e9ded4 100644
--- a/1.2/Nfc.cpp
+++ b/1.2/Nfc.cpp
@@ -18,14 +18,14 @@
  ******************************************************************************/
 
 #define LOG_TAG "android.hardware.nfc@1.2-impl"
-#include <log/log.h>
 #include "Nfc.h"
-#include "StNfc_hal_api.h"
 
+#include <log/log.h>
 
+#include "StNfc_hal_api.h"
 
-#define CHK_STATUS(x) ((x) == NFCSTATUS_SUCCESS) \
-      ? (V1_0::NfcStatus::OK) : (V1_0::NfcStatus::FAILED)
+#define CHK_STATUS(x) \
+  ((x) == NFCSTATUS_SUCCESS) ? (V1_0::NfcStatus::OK) : (V1_0::NfcStatus::FAILED)
 
 bool nfc_debug_enabled = true;
 
@@ -41,7 +41,7 @@ sp<V1_0::INfcClientCallback> Nfc::mCallbackV1_0 = nullptr;
 Return<V1_0::NfcStatus> Nfc::open_1_1(
     const sp<V1_1::INfcClientCallback>& clientCallback) {
   if (clientCallback == nullptr) {
-    ALOGD_IF(nfc_debug_enabled,"Nfc::open null callback");
+    ALOGD_IF(nfc_debug_enabled, "Nfc::open null callback");
     return V1_0::NfcStatus::FAILED;
   } else {
     pthread_mutex_lock(&mLockOpenClose);
@@ -69,7 +69,8 @@ Return<V1_0::NfcStatus> Nfc::open(
   }
 
   int ret = StNfc_hal_open(eventCallback, dataCallback);
-  ALOGD_IF(nfc_debug_enabled, "Nfc::open Exit (count:%llu)", (unsigned long long)mOpenCount);
+  ALOGD_IF(nfc_debug_enabled, "Nfc::open Exit (count:%llu)",
+           (unsigned long long)mOpenCount);
   pthread_mutex_unlock(&mLockOpenClose);
   return ret == 0 ? V1_0::NfcStatus::OK : V1_0::NfcStatus::FAILED;
 }
diff --git a/1.2/Nfc.h b/1.2/Nfc.h
index df966f9..37c7430 100644
--- a/1.2/Nfc.h
+++ b/1.2/Nfc.h
@@ -32,15 +32,15 @@ namespace nfc {
 namespace V1_2 {
 namespace implementation {
 
-using ::android::hidl::base::V1_0::IBase;
-using ::android::hardware::nfc::V1_2::INfc;
+using ::android::sp;
 using ::android::hardware::hidl_array;
 using ::android::hardware::hidl_memory;
 using ::android::hardware::hidl_string;
 using ::android::hardware::hidl_vec;
 using ::android::hardware::Return;
 using ::android::hardware::Void;
-using ::android::sp;
+using ::android::hardware::nfc::V1_2::INfc;
+using ::android::hidl::base::V1_0::IBase;
 struct Nfc : public V1_2::INfc, public hidl_death_recipient {
  public:
   // Methods from ::android::hardware::nfc::V1_0::INfc follow.
@@ -99,8 +99,7 @@ struct Nfc : public V1_2::INfc, public hidl_death_recipient {
 
   virtual void serviceDied(uint64_t cookie, const wp<IBase>& /*who*/) {
     pthread_mutex_lock(&mLockOpenClose);
-    ALOGE("serviceDied!!! %llu, %llu, %s, %s",
-          (unsigned long long)cookie,
+    ALOGE("serviceDied!!! %llu, %llu, %s, %s", (unsigned long long)cookie,
           (unsigned long long)mOpenCount,
           (mCallbackV1_0 == nullptr ? "null" : "defined"),
           (mCallbackV1_1 == nullptr ? "null" : "defined"));
diff --git a/1.2/StNfcService.cpp b/1.2/StNfcService.cpp
index efa38bf..8305ab4 100644
--- a/1.2/StNfcService.cpp
+++ b/1.2/StNfcService.cpp
@@ -21,8 +21,8 @@
 #include <android-base/properties.h>
 #include <android/hardware/nfc/1.1/INfc.h>
 #include <dlfcn.h>
-
 #include <hidl/LegacySupport.h>
+
 #include "Nfc.h"
 
 #if defined(ST_LIB_32)
diff --git a/1.2/StNfc_hal_api.h b/1.2/StNfc_hal_api.h
index bfb1885..9a77eda 100644
--- a/1.2/StNfc_hal_api.h
+++ b/1.2/StNfc_hal_api.h
@@ -27,10 +27,9 @@
 using ::android::hardware::nfc::V1_2::NfcConfig;
 
 #define NFC_MODE_OFF 0
-#define NFC_MODE_ON  1
+#define NFC_MODE_ON 1
 #define NFC_MODE_QuickBoot 2
 
-
 int StNfc_hal_open(nfc_stack_callback_t* p_cback,
                    nfc_stack_data_callback_t* p_data_cback);
 int StNfc_hal_write(uint16_t data_len, const uint8_t* p_data);
diff --git a/1.2/hal_st21nfc.cc b/1.2/hal_st21nfc.cc
index a9e71f7..11e399e 100644
--- a/1.2/hal_st21nfc.cc
+++ b/1.2/hal_st21nfc.cc
@@ -429,8 +429,8 @@ int StNfc_hal_power_cycle() {
 
 void StNfc_hal_factoryReset() {
   STLOG_HAL_D("HAL st21nfc: %s", __func__);
-  //hal_wrapper_factoryReset();
-  // Nothing needed for factory reset in st21nfc case.
+  // hal_wrapper_factoryReset();
+  //  Nothing needed for factory reset in st21nfc case.
 }
 
 int StNfc_hal_closeForPowerOffCase() {
diff --git a/OWNERS b/OWNERS
index f46dccd..47f209f 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,2 @@
 # Bug component: 48448
-include platform/packages/apps/Nfc:/OWNERS
\ No newline at end of file
+include platform/packages/modules/Nfc:/OWNERS
\ No newline at end of file
diff --git a/aidl/Android.bp b/aidl/Android.bp
index 7cc07a0..3d44275 100644
--- a/aidl/Android.bp
+++ b/aidl/Android.bp
@@ -72,3 +72,44 @@ cc_fuzz {
     ],
     vendor: true,
 }
+
+prebuilt_etc {
+    name: "nfc-service-default.xml",
+    src: "nfc-service-default.xml",
+    sub_dir: "vintf",
+    installable: false,
+}
+
+genrule {
+    name: "com.google.android.hardware.nfc.st.rc-gen",
+    srcs: ["nfc-service-default.rc"],
+    out: ["com.google.android.hardware.nfc.st.rc"],
+    cmd: "sed -E 's@/vendor/bin@/apex/com.google.android.hardware.nfc.st/bin@' $(in) > $(out)",
+}
+
+prebuilt_etc {
+    name: "com.google.android.hardware.nfc.st.rc",
+    src: ":com.google.android.hardware.nfc.st.rc-gen",
+    installable: false,
+}
+
+apex {
+    name: "com.google.android.hardware.nfc.st",
+    manifest: "apex_manifest.json",
+    file_contexts: "file_contexts",
+    key: "com.android.hardware.key",
+    certificate: ":com.android.hardware.certificate",
+    updatable: false,
+    vendor: true,
+
+    binaries: ["android.hardware.nfc-service.st"],
+    prebuilts: [
+        "com.google.android.hardware.nfc.st.rc",
+        "nfc-service-default.xml",
+        "android.hardware.nfc.prebuilt.xml",
+        "android.hardware.nfc.hce.prebuilt.xml",
+        "android.hardware.nfc.hcef.prebuilt.xml",
+        "com.nxp.mifare.prebuilt.xml",
+        "android.hardware.nfc.ese.prebuilt.xml",
+    ],
+}
diff --git a/aidl/Nfc.cpp b/aidl/Nfc.cpp
index bcadc16..f3c4a05 100644
--- a/aidl/Nfc.cpp
+++ b/aidl/Nfc.cpp
@@ -182,6 +182,10 @@ void OnDeath(void* cookie) {
   return ndk::ScopedAStatus::ok();
 }
 
+binder_status_t Nfc::dump(int fd, const char**, uint32_t) {
+  StNfc_hal_dump(fd);
+  return STATUS_OK;
+}
 }  // namespace nfc
 }  // namespace hardware
 }  // namespace android
diff --git a/aidl/Nfc.h b/aidl/Nfc.h
index 2ac623b..707bd65 100644
--- a/aidl/Nfc.h
+++ b/aidl/Nfc.h
@@ -49,6 +49,7 @@ struct Nfc : public BnNfc {
                              int32_t* _aidl_return) override;
   ::ndk::ScopedAStatus setEnableVerboseLogging(bool enable) override;
   ::ndk::ScopedAStatus isVerboseLoggingEnabled(bool* _aidl_return) override;
+  binder_status_t dump(int fd, const char** args, uint32_t numArgs) override;
 
   static void eventCallback(uint8_t event, uint8_t status) {
     if (mCallback != nullptr) {
diff --git a/aidl/StNfc_hal_api.h b/aidl/StNfc_hal_api.h
index 6b6b3c1..1df55b6 100644
--- a/aidl/StNfc_hal_api.h
+++ b/aidl/StNfc_hal_api.h
@@ -65,4 +65,8 @@ void StNfc_hal_setLogging(bool enable);
 
 bool StNfc_hal_isLoggingEnabled();
 
+void StNfc_hal_dump(int fd);
+uint16_t
+iso14443_crc(const uint8_t *data, size_t szLen, int type);
+
 #endif /* _STNFC_HAL_API_H_ */
diff --git a/aidl/apex_manifest.json b/aidl/apex_manifest.json
new file mode 100644
index 0000000..9484e91
--- /dev/null
+++ b/aidl/apex_manifest.json
@@ -0,0 +1,4 @@
+{
+    "name": "com.google.android.hardware.nfc.st",
+    "version": 1
+}
\ No newline at end of file
diff --git a/aidl/file_contexts b/aidl/file_contexts
new file mode 100644
index 0000000..7457d8c
--- /dev/null
+++ b/aidl/file_contexts
@@ -0,0 +1,3 @@
+(/.*)?                                              u:object_r:vendor_file:s0
+/etc(/.*)?                                          u:object_r:vendor_configs_file:s0
+/bin/hw/android\.hardware\.nfc-service\.st          u:object_r:hal_nfc_default_exec:s0
\ No newline at end of file
diff --git a/aidl/fuzzer/NfcServiceFuzzer.cpp b/aidl/fuzzer/NfcServiceFuzzer.cpp
index 6cded0e..389ad14 100644
--- a/aidl/fuzzer/NfcServiceFuzzer.cpp
+++ b/aidl/fuzzer/NfcServiceFuzzer.cpp
@@ -20,9 +20,9 @@
 
 #include "Nfc.h"
 
+using ::aidl::android::hardware::nfc::Nfc;
 using android::fuzzService;
 using ndk::SharedRefBase;
-using ::aidl::android::hardware::nfc::Nfc;
 
 extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
   std::shared_ptr<Nfc> nfc_service = ndk::SharedRefBase::make<Nfc>();
diff --git a/aidl/hal_st21nfc.cc b/aidl/hal_st21nfc.cc
index e46c080..fddbfa3 100644
--- a/aidl/hal_st21nfc.cc
+++ b/aidl/hal_st21nfc.cc
@@ -28,9 +28,9 @@
 #include "StNfc_hal_api.h"
 #include "android_logmsg.h"
 #include "hal_config.h"
+#include "hal_fd.h"
 #include "halcore.h"
 #include "st21nfc_dev.h"
-#include "hal_fd.h"
 
 #if defined(ST_LIB_32)
 #define VENDOR_LIB_PATH "/vendor/lib/"
@@ -39,6 +39,13 @@
 #endif
 #define VENDOR_LIB_EXT ".so"
 
+
+#define CRC_PRESET_A 0x6363
+#define CRC_PRESET_B 0xFFFF
+#define Type_A 0
+#define Type_B 1
+
+
 bool dbg_logging = false;
 
 extern void HalCoreCallback(void* context, uint32_t event, const void* d,
@@ -54,6 +61,7 @@ uint8_t hal_is_closed = 1;
 pthread_mutex_t hal_mtx = PTHREAD_MUTEX_INITIALIZER;
 st21nfc_dev_t dev;
 int nfc_mode = 0;
+uint8_t nci_cmd[256];
 
 /*
  * NCI HAL method implementations. These must be overridden
@@ -67,7 +75,7 @@ extern int hal_wrapper_close(int call_cb, int nfc_mode);
 
 extern void hal_wrapper_send_config();
 extern void hal_wrapper_factoryReset();
-extern void hal_wrapper_set_observer_mode(uint8_t enable);
+extern void hal_wrapper_set_observer_mode(uint8_t enable, bool per_tech_cmd);
 extern void hal_wrapper_get_observer_mode();
 
 /* Make sure to always post nfc_stack_callback_t in a separate thread.
@@ -314,7 +322,10 @@ int StNfc_hal_write(uint16_t data_len, const uint8_t* p_data) {
   STLOG_HAL_D("HAL st21nfc: %s", __func__);
 
   uint8_t NCI_ANDROID_PASSIVE_OBSERVER_PREFIX[] = {0x2f, 0x0c, 0x02, 0x02};
+  uint8_t NCI_ANDROID_PASSIVE_OBSERVER_PER_TECH_PREFIX[] = {0x2f, 0x0c, 0x02,
+                                                            0x05};
   uint8_t NCI_QUERY_ANDROID_PASSIVE_OBSERVER_PREFIX[] = {0x2f, 0x0c, 0x01, 0x4};
+  uint8_t NCI_ANDROID_PREFIX[] = {0x2f, 0x0c};
   uint8_t RF_GET_LISTEN_OBSERVE_MODE_STATE[5] = {0x21, 0x17, 0x00};
   uint8_t RF_SET_LISTEN_OBSERVE_MODE_STATE[4] = {0x21, 0x16, 0x01, 0x0};
   uint8_t CORE_GET_CONFIG_OBSERVER[5] = {0x20, 0x03, 0x02, 0x01, 0xa3};
@@ -362,10 +373,10 @@ int StNfc_hal_write(uint16_t data_len, const uint8_t* p_data) {
         mTechObserved = 0x7;
       }
       mSetObserve[3] = mTechObserved;
-      hal_wrapper_set_observer_mode(mTechObserved);
+      hal_wrapper_set_observer_mode(mTechObserved, false);
     } else {
       mSetObserve[6] = p_data[4];
-      hal_wrapper_set_observer_mode(p_data[4]);
+      hal_wrapper_set_observer_mode(p_data[4], false);
     }
 
     if (!HalSendDownstream(dev.hHAL, mSetObserve, mSetObserve_size)) {
@@ -373,6 +384,116 @@ int StNfc_hal_write(uint16_t data_len, const uint8_t* p_data) {
       (void)pthread_mutex_unlock(&hal_mtx);
       return 0;
     }
+  } else if (data_len == 5 &&
+             !memcmp(p_data, NCI_ANDROID_PASSIVE_OBSERVER_PER_TECH_PREFIX,
+                     sizeof(NCI_ANDROID_PASSIVE_OBSERVER_PER_TECH_PREFIX))) {
+    mSetObserve = RF_SET_LISTEN_OBSERVE_MODE_STATE;
+    mSetObserve_size = 4;
+    if (p_data[4]) {
+      mTechObserved = p_data[4];
+    }
+    mSetObserve[3] = mTechObserved;
+    hal_wrapper_set_observer_mode(mTechObserved, true);
+    if (!HalSendDownstream(dev.hHAL, mSetObserve, mSetObserve_size)) {
+      STLOG_HAL_E("HAL st21nfc %s  SendDownstream failed", __func__);
+      (void)pthread_mutex_unlock(&hal_mtx);
+      return 0;
+    }
+  } else if (!memcmp(p_data, NCI_ANDROID_PREFIX, sizeof(NCI_ANDROID_PREFIX)) &&
+             p_data[3] == 0x6) {
+    DispHal("TX DATA", (p_data), data_len);
+
+    memcpy(nci_cmd+3, p_data+4, 4);
+    nci_cmd[0] = 0x2f;
+    nci_cmd[1] = 0x19;
+
+    int index = 8;
+    int ll_index = 7;
+    uint8_t nci_length = 0;
+    uint16_t crc = 0;
+    bool prefix_match = false;
+    bool exact_match = true;
+
+    while (index < data_len) {
+      // Read the Type field (1 byte)
+      uint8_t type_field = p_data[index];
+      int tlv_len = p_data[index + 1];
+      prefix_match = false;
+      exact_match = true;
+      if (p_data[index] == 0x01) {
+        crc = iso14443_crc(p_data + index + 3, (uint8_t)((tlv_len - 1) / 2),
+                           Type_B);
+      } else if ((p_data[index] & 0xF0) == 0x00) {
+        crc = iso14443_crc(p_data + index + 3, (uint8_t)((tlv_len - 1) / 2),
+                           Type_A);
+      } else {
+        prefix_match = true;
+      }
+
+      nci_cmd[ll_index++] = p_data[index++];
+      nci_cmd[ll_index++] =
+          (!prefix_match) ? p_data[index++] + 4 : p_data[index++];
+      nci_cmd[ll_index++] = p_data[index++];
+
+      memcpy(nci_cmd + ll_index, p_data + index, (uint8_t)((tlv_len - 1) / 2));
+      ll_index += (tlv_len - 1) / 2;
+      index += (tlv_len - 1) / 2;
+      int crc_index = 0;
+      if (!prefix_match) {
+        crc_index = ll_index;
+        nci_cmd[ll_index++] = (uint8_t)crc;
+        nci_cmd[ll_index++] = (uint8_t)(crc >> 8);
+      }
+
+      memcpy(nci_cmd + ll_index, p_data + index, (tlv_len - 1) / 2);
+      for (int i = 0; i < (tlv_len - 1) / 2; ++i) {
+        if (p_data[index + i] != 0xFF) {
+            exact_match = false;
+            break;
+        }
+      }
+      ll_index += (tlv_len - 1) / 2;
+      index += (tlv_len - 1) / 2;
+      uint8_t crc_mask = exact_match ? 0xFF : 0x00;
+      if (!prefix_match) {
+        nci_cmd[ll_index++] = crc_mask;
+        nci_cmd[ll_index++] = crc_mask;
+
+        if (!exact_match) {
+        nci_cmd[crc_index] = crc_mask;
+        nci_cmd[crc_index +1] = crc_mask;
+        }
+
+      }
+    }
+    nci_length = ll_index;
+    nci_cmd[2] = ll_index -3;
+
+    if (!HalSendDownstream(dev.hHAL, nci_cmd, nci_length)) {
+      STLOG_HAL_E("HAL st21nfc %s  SendDownstream failed", __func__);
+      (void)pthread_mutex_unlock(&hal_mtx);
+      return 0;
+    }
+  } else if (!memcmp(p_data, NCI_ANDROID_PREFIX, sizeof(NCI_ANDROID_PREFIX)) &&
+             p_data[3] == 0x9) {
+    DispHal("TX DATA", (p_data), data_len);
+    memcpy(nci_cmd + 3, p_data + 4, data_len - 4);
+
+    uint16_t crc = iso14443_crc(nci_cmd + 7, nci_cmd[5] - 1, Type_A);
+
+    uint8_t len = p_data[2];
+    nci_cmd[0] = 0x2f;
+    nci_cmd[1] = 0x1d;
+    nci_cmd[5] = nci_cmd[5] + 2;
+    nci_cmd[data_len - 1] = (uint8_t)crc;
+    nci_cmd[data_len] = (uint8_t)(crc >> 8);
+
+    nci_cmd[2] = p_data[2] + 1;
+    if (!HalSendDownstream(dev.hHAL, nci_cmd, nci_cmd[2] + 3)) {
+      STLOG_HAL_E("HAL st21nfc %s  SendDownstream failed", __func__);
+      (void)pthread_mutex_unlock(&hal_mtx);
+      return 0;
+    }
   } else if (!HalSendDownstream(dev.hHAL, p_data, data_len)) {
     STLOG_HAL_E("HAL st21nfc %s  SendDownstream failed", __func__);
     (void)pthread_mutex_unlock(&hal_mtx);
@@ -594,3 +715,24 @@ void StNfc_hal_setLogging(bool enable) {
 }
 
 bool StNfc_hal_isLoggingEnabled() { return dbg_logging; }
+
+void StNfc_hal_dump(int fd) { hal_wrapper_dumplog(fd); }
+
+uint16_t iso14443_crc(const uint8_t* data, size_t szLen, int type) {
+  uint16_t tempCrc;
+  if (type == Type_A) {
+    tempCrc = (unsigned short)CRC_PRESET_A;
+  } else {
+    tempCrc = (unsigned short)CRC_PRESET_B;
+  }
+  do {
+    uint8_t bt;
+    bt = *data++;
+    bt = (bt ^ (uint8_t)(tempCrc & 0x00FF));
+    bt = (bt ^ (bt << 4));
+    tempCrc = (tempCrc >> 8) ^ ((uint32_t)bt << 8) ^ ((uint32_t)bt << 3) ^
+              ((uint32_t)bt >> 4);
+  } while (--szLen);
+
+  return tempCrc;
+}
diff --git a/st21nfc/Android.bp b/st21nfc/Android.bp
index 8a3f316..4ebbb04 100644
--- a/st21nfc/Android.bp
+++ b/st21nfc/Android.bp
@@ -39,7 +39,8 @@ cc_library_shared {
         "hal/halcore.cc",
         "hal_wrapper.cc",
         "hal/hal_fwlog.cc",
-	"hal/hal_fd.cc",
+        "hal/hal_fd.cc",
+        "hal/hal_event_logger.cc",
     ],
 
     local_include_dirs: [
diff --git a/st21nfc/adaptation/android_logmsg.cpp b/st21nfc/adaptation/android_logmsg.cpp
index 72e5b6a..b944aae 100644
--- a/st21nfc/adaptation/android_logmsg.cpp
+++ b/st21nfc/adaptation/android_logmsg.cpp
@@ -17,6 +17,7 @@
  *
  ******************************************************************************/
 #include "android_logmsg.h"
+
 #include <pthread.h>
 #include <stdio.h>
 
@@ -52,7 +53,9 @@ unsigned char InitializeSTLogLevel() {
   num = 1;
   if (GetNumValue(NAME_STNFC_HAL_LOGLEVEL, &num, sizeof(num))) {
     hal_conf_trace_level = (unsigned char)num;
-    hal_trace_level = hal_conf_trace_level;
+    if (hal_trace_level != STNFC_TRACE_LEVEL_VERBOSE) {
+      hal_trace_level = hal_conf_trace_level;
+    }
   }
 
   STLOG_HAL_D("%s: HAL log level=%u, hal_log_cnt (before reset): #%04X",
diff --git a/st21nfc/adaptation/config.cpp b/st21nfc/adaptation/config.cpp
index 7308fac..285fe1f 100644
--- a/st21nfc/adaptation/config.cpp
+++ b/st21nfc/adaptation/config.cpp
@@ -20,13 +20,17 @@
  *
  *
  ******************************************************************************/
+#include "config.h"
+
 #include <android-base/properties.h>
 #include <log/log.h>
 #include <stdio.h>
 #include <sys/stat.h>
+
 #include <list>
 #include <string>
 #include <vector>
+
 #include "android_logmsg.h"
 const char alternative_config_path[] = "";
 const char* transport_config_paths[] = {"/odm/etc/", "/vendor/etc/", "/etc/"};
@@ -268,7 +272,7 @@ bool CNfcConfig::readConfig(const char* name, bool bResetContent) {
           state = END_LINE;
           break;
         }
-        [[fallthrough]]; // fall through to numValue to handle numValue
+        [[fallthrough]];  // fall through to numValue to handle numValue
 
       case NUM_VALUE:
         if (isDigit(c, base)) {
diff --git a/st21nfc/adaptation/i2clayer.cc b/st21nfc/adaptation/i2clayer.cc
index fbb7dba..54589cc 100644
--- a/st21nfc/adaptation/i2clayer.cc
+++ b/st21nfc/adaptation/i2clayer.cc
@@ -32,9 +32,9 @@
 #include <unistd.h>
 
 #include "android_logmsg.h"
+#include "hal_config.h"
 #include "halcore.h"
 #include "halcore_private.h"
-#include "hal_config.h"
 
 #define ST21NFC_MAGIC 0xEA
 
@@ -93,7 +93,7 @@ static void* I2cWorkerThread(void* arg) {
   STLOG_HAL_D("echo thread started...\n");
   bool readOk = false;
   int eventNum = (notifyResetRequest <= 0) ? 2 : 3;
-  bool reseting = false;
+  bool resetting= false;
 
   do {
     event_table[0].fd = fidI2c;
@@ -232,9 +232,9 @@ static void* I2cWorkerThread(void* arg) {
       if (byte < 10) {
         reset[byte] = '\0';
       }
-      if (byte > 0 && reset[0] =='1' && reseting == false) {
+      if (byte > 0 && reset[0] == '1' && resetting== false) {
         STLOG_HAL_E("trigger NFCC reset.. \n");
-        reseting = true;
+        resetting= true;
         i2cResetPulse(fidI2c);
       }
     }
@@ -278,18 +278,19 @@ bool I2cOpenLayer(void* dev, HAL_CALLBACK callb, HALHANDLE* pHandle) {
   char nfc_reset_req_node[128];
 
   /*Read device node path*/
-  if (!GetStrValue(NAME_ST_NFC_DEV_NODE, (char *)nfc_dev_node,
+  if (!GetStrValue(NAME_ST_NFC_DEV_NODE, (char*)nfc_dev_node,
                    sizeof(nfc_dev_node))) {
     STLOG_HAL_D("Open /dev/st21nfc\n");
     strcpy(nfc_dev_node, "/dev/st21nfc");
   }
   /*Read nfcc reset request sysfs*/
-  if (GetStrValue(NAME_ST_NFC_RESET_REQ_SYSFS, (char *)nfc_reset_req_node,
+  if (GetStrValue(NAME_ST_NFC_RESET_REQ_SYSFS, (char*)nfc_reset_req_node,
                   sizeof(nfc_reset_req_node))) {
     STLOG_HAL_D("Open %s\n", nfc_reset_req_node);
     notifyResetRequest = open(nfc_reset_req_node, O_RDONLY);
     if (notifyResetRequest < 0) {
-      STLOG_HAL_E("unable to open %s (%s) \n", nfc_reset_req_node, strerror(errno));
+      STLOG_HAL_E("unable to open %s (%s) \n", nfc_reset_req_node,
+                  strerror(errno));
     }
   }
 
@@ -508,7 +509,6 @@ redo:
     result = write(fid, pvBuffer, length);
 
     if (result < 0) {
-
       strerror_r(errno, msg, LINUX_DBGBUFFER_SIZE);
       STLOG_HAL_W("! i2cWrite!!, errno is '%s'", msg);
       usleep(4000);
@@ -550,8 +550,7 @@ static int i2cRead(int fid, uint8_t* pvBuffer, int length) {
     result = read(fid, pvBuffer, length);
 
     if (result == -1) {
-      int e = errno;
-      if (e == EAGAIN) {
+      if (errno == EAGAIN) {
         /* File is nonblocking, and no data is available.
          * This is not an error condition!
          */
@@ -561,23 +560,20 @@ static int i2cRead(int fid, uint8_t* pvBuffer, int length) {
       } else {
         /* unexpected result */
         char msg[LINUX_DBGBUFFER_SIZE];
-        strerror_r(e, msg, LINUX_DBGBUFFER_SIZE);
-        STLOG_HAL_W("## i2cRead returns %d errno %d (%s)", result, e, msg);
+        strerror_r(errno, msg, LINUX_DBGBUFFER_SIZE);
+        STLOG_HAL_W("## i2cRead returns %d errno %d (%s)", result, errno, msg);
       }
     }
 
-    if (result < 0) {
-      if (retries < 3) {
-        /* delays are different and increasing for the three retries. */
-        static const uint8_t delayTab[] = {2, 3, 5};
-        int delay = delayTab[retries];
-
-        retries++;
-        STLOG_HAL_W("## i2cRead retry %d/3 in %d milliseconds.", retries,
-                    delay);
-        usleep(delay * 1000);
-        continue;
-      }
+    if (result < 0 && retries < 3) {
+      /* delays are different and increasing for the three retries. */
+      static const uint8_t delayTab[] = {2, 3, 5};
+      int delay = delayTab[retries];
+
+      retries++;
+      STLOG_HAL_W("## i2cRead retry %d/3 in %d milliseconds.", retries, delay);
+      usleep(delay * 1000);
+      continue;
     }
   }
   return result;
diff --git a/st21nfc/gki/ulinux/data_types.h b/st21nfc/gki/ulinux/data_types.h
index 060c870..800d2e3 100644
--- a/st21nfc/gki/ulinux/data_types.h
+++ b/st21nfc/gki/ulinux/data_types.h
@@ -48,7 +48,7 @@ typedef unsigned char UBYTE;
 #define BIG_ENDIAN FALSE
 #endif
 
-#define UINT16_LOW_BYTE(x) ((x)&0xff)
+#define UINT16_LOW_BYTE(x) ((x) & 0xff)
 #define UINT16_HI_BYTE(x) ((x) >> 8)
 
 #endif
diff --git a/st21nfc/hal/hal_event_logger.cc b/st21nfc/hal/hal_event_logger.cc
new file mode 100644
index 0000000..8774a9a
--- /dev/null
+++ b/st21nfc/hal/hal_event_logger.cc
@@ -0,0 +1,134 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "hal_event_logger.h"
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <fcntl.h>
+#include <sys/stat.h>
+
+#include <cstring>
+#include <ctime>
+
+#include "config.h"
+#include "hal_config.h"
+
+#define TIMESTAMP_BUFFER_SIZE 64
+#define HAL_LOG_FILE_SIZE 32 * 1024 * 1024
+#define HAL_MEM_BUFFER_SIZE 256 * 1024
+
+HalEventLogger& HalEventLogger::getInstance() {
+  static HalEventLogger nfc_event_eventLogger;
+  return nfc_event_eventLogger;
+}
+HalEventLogger& HalEventLogger::log() {
+  struct timespec tv;
+  clock_gettime(CLOCK_REALTIME, &tv);
+  time_t rawtime = tv.tv_sec;
+  struct tm* timeinfo;
+  char buffer[TIMESTAMP_BUFFER_SIZE];
+  char timestamp[TIMESTAMP_BUFFER_SIZE];
+  timeinfo = localtime(&rawtime);
+  int milliseconds = tv.tv_nsec / 1000000;
+  strftime(buffer, sizeof(buffer), "%m-%d %H:%M:%S", timeinfo);
+  sprintf(timestamp, "%s.%03d", buffer, milliseconds);
+  if (ss.str().size() > HAL_MEM_BUFFER_SIZE) {
+    std::string currentString = ss.str();
+    currentString =
+        currentString.substr(currentString.size() - HAL_MEM_BUFFER_SIZE);
+    std::ostringstream newBuffer;
+    newBuffer << currentString;
+    newBuffer << timestamp << ": ";
+    ss.str("");
+    ss.clear();
+    ss << newBuffer.str();
+  } else {
+    ss << timestamp << ": ";
+  }
+  return getInstance();
+}
+
+void HalEventLogger::initialize() {
+  LOG(DEBUG) << __func__;
+  unsigned long num = 0;
+  char HalLogPath[256];
+
+  if (GetNumValue(NAME_HAL_EVENT_LOG_DEBUG_ENABLED, &num, sizeof(num))) {
+    logging_enabled = (num == 1) ? true : false;
+  }
+  LOG(INFO) << __func__ << " logging_enabled: " << logging_enabled;
+  if (!logging_enabled) {
+    return;
+  }
+  if (!GetStrValue(NAME_HAL_EVENT_LOG_STORAGE, (char*)HalLogPath,
+                   sizeof(HalLogPath))) {
+    LOG(WARNING) << __func__
+                 << " HAL log path not found in conf. use default location "
+                    "/data/vendor/nfc";
+    strcpy(HalLogPath, "/data/vendor/nfc");
+  }
+  EventFilePath = HalLogPath;
+  EventFilePath += "/hal_event_log.txt";
+}
+
+void HalEventLogger::store_log() {
+  LOG(DEBUG) << __func__;
+  if (!logging_enabled) return;
+  std::ofstream logFile;
+  if (std::filesystem::exists(EventFilePath) &&
+      std::filesystem::file_size(EventFilePath) > HAL_LOG_FILE_SIZE) {
+    logFile.open(EventFilePath, std::ios::out | std::ios::trunc);
+  } else {
+    logFile.open(EventFilePath, std::ios::app);
+  }
+  if (logFile.is_open()) {
+    logFile << ss.rdbuf();
+    logFile.close();
+    ss.str("");
+    ss.clear();
+  } else {
+    LOG(ERROR) << __func__ << " EventEventLogger: Log file " << EventFilePath
+               << " couldn't be opened! errno: " << errno;
+  }
+}
+
+void HalEventLogger::dump_log(int fd) {
+  LOG(DEBUG) << __func__;
+  if (!logging_enabled) return;
+  std::ostringstream oss;
+  if (std::filesystem::exists(EventFilePath) &&
+      std::filesystem::file_size(EventFilePath) > 0) {
+    std::ifstream readFile(EventFilePath);
+    if (readFile.is_open()) {
+      oss << readFile.rdbuf() << ss.str();
+      readFile.close();
+    } else {
+      LOG(ERROR) << __func__ << " EventEventLogger: Failed to open log file "
+                 << EventFilePath << " for reading!";
+      oss << ss.str();
+    }
+  } else {
+    LOG(INFO) << __func__ << " EventEventLogger: Log file " << EventFilePath
+              << " not exists or no content";
+    oss << ss.str();
+  }
+
+  dprintf(fd, "===== Nfc HAL Event Log v1 =====\n");
+  ::android::base::WriteStringToFd(oss.str(), fd);
+  dprintf(fd, "===== Nfc HAL Event Log v1 =====\n");
+  fsync(fd);
+}
\ No newline at end of file
diff --git a/st21nfc/hal/hal_fd.cc b/st21nfc/hal/hal_fd.cc
index 3cf002f..4b73b91 100644
--- a/st21nfc/hal/hal_fd.cc
+++ b/st21nfc/hal/hal_fd.cc
@@ -18,20 +18,23 @@
  ******************************************************************************/
 #define LOG_TAG "NfcHalFd"
 #include "hal_fd.h"
+
 #include <cutils/properties.h>
 #include <dlfcn.h>
 #include <errno.h>
 #include <hardware/nfc.h>
 #include <string.h>
+
 #include "android_logmsg.h"
+#include "hal_event_logger.h"
 #include "halcore.h"
 /* Initialize fw info structure pointer used to access fw info structure */
-FWInfo *mFWInfo = NULL;
+FWInfo* mFWInfo = NULL;
 
-FWCap *mFWCap = NULL;
+FWCap* mFWCap = NULL;
 
-FILE *mFwFileBin;
-FILE *mCustomFileBin;
+FILE* mFwFileBin;
+FILE* mCustomFileBin;
 fpos_t mPos;
 fpos_t mPosInit;
 uint8_t mBinData[260];
@@ -41,9 +44,9 @@ bool mCustomParamDone = false;
 bool mUwbConfigDone = false;
 bool mUwbConfigNeeded = false;
 bool mGetCustomerField = false;
-uint8_t *pCmd;
+uint8_t* pCmd;
 int mFWRecovCount = 0;
-const char *FwType = "generic";
+const char* FwType = "generic";
 char mApduAuthent[24];
 
 static const uint8_t propNfcModeSetCmdOn[] = {0x2f, 0x02, 0x02, 0x02, 0x01};
@@ -117,8 +120,7 @@ void SendExitLoadMode(HALHANDLE mmHalHandle);
 void SendSwitchToUserMode(HALHANDLE mmHalHandle);
 extern void hal_wrapper_update_complete();
 
-typedef size_t (*STLoadUwbParams)(void *out_buff,
-                                  size_t buf_size);
+typedef size_t (*STLoadUwbParams)(void* out_buff, size_t buf_size);
 
 /***********************************************************************
  * Determine UserKey
@@ -174,27 +176,29 @@ int hal_fd_init() {
 
   STLOG_HAL_D("  %s - enter", __func__);
 
-  if (!GetStrValue(NAME_STNFC_FW_PATH_STORAGE, (char *)FwPath,
-                   sizeof(FwPath))) {
+  if (!GetStrValue(NAME_STNFC_FW_PATH_STORAGE, (char*)FwPath, sizeof(FwPath))) {
     STLOG_HAL_D(
         "%s - FW path not found in conf. use default location /vendor/firmware "
-        "\n", __func__);
+        "\n",
+        __func__);
     strcpy(FwPath, "/vendor/firmware");
   }
 
-  if (!GetStrValue(NAME_STNFC_FW_BIN_NAME, (char *)fwBinName,
+  if (!GetStrValue(NAME_STNFC_FW_BIN_NAME, (char*)fwBinName,
                    sizeof(fwBinName))) {
     STLOG_HAL_D(
         "%s - FW binary file name not found in conf. use default name "
-        "/st21nfc_fw.bin \n", __func__);
+        "/st21nfc_fw.bin \n",
+        __func__);
     strcpy(fwBinName, "/st21nfc_fw.bin");
   }
 
-  if (!GetStrValue(NAME_STNFC_FW_CONF_NAME, (char *)fwConfName,
+  if (!GetStrValue(NAME_STNFC_FW_CONF_NAME, (char*)fwConfName,
                    sizeof(fwConfName))) {
     STLOG_HAL_D(
         "%s - FW config file name not found in conf. use default name "
-        "/st21nfc_conf.bin \n", __func__);
+        "/st21nfc_conf.bin \n",
+        __func__);
     strcpy(fwConfName, "/st21nfc_conf.bin");
   }
 
@@ -206,7 +210,7 @@ int hal_fd_init() {
   STLOG_HAL_D("%s - FW config binary file = %s", __func__, ConfPath);
 
   // Initializing structure holding FW patch details
-  mFWInfo = (FWInfo *)malloc(sizeof(FWInfo));
+  mFWInfo = (FWInfo*)malloc(sizeof(FWInfo));
 
   if (mFWInfo == NULL) {
     result = 0;
@@ -215,7 +219,7 @@ int hal_fd_init() {
   memset(mFWInfo, 0, sizeof(FWInfo));
 
   // Initializing structure holding FW Capabilities
-  mFWCap = (FWCap *)malloc(sizeof(FWCap));
+  mFWCap = (FWCap*)malloc(sizeof(FWCap));
 
   if (mFWCap == NULL) {
     result = 0;
@@ -228,7 +232,7 @@ int hal_fd_init() {
 
   // Check if FW patch binary file is present
   // If not, get recovery FW patch file
-  if ((mFwFileBin = fopen((char *)FwPath, "r")) == NULL) {
+  if ((mFwFileBin = fopen((char*)FwPath, "r")) == NULL) {
     STLOG_HAL_D("%s - %s not detected", __func__, fwBinName);
   } else {
     STLOG_HAL_D("%s - %s file detected\n", __func__, fwBinName);
@@ -284,7 +288,7 @@ int hal_fd_init() {
     }
   }
 
-  if ((mCustomFileBin = fopen((char *)ConfPath, "r")) == NULL) {
+  if ((mCustomFileBin = fopen((char*)ConfPath, "r")) == NULL) {
     STLOG_HAL_D("%s - st21nfc custom configuration not detected\n", __func__);
   } else {
     STLOG_HAL_D("%s - %s file detected\n", __func__, ConfPath);
@@ -321,12 +325,12 @@ void hal_fd_close() {
 
 FWInfo* hal_fd_getFwInfo() {
   STLOG_HAL_D("  %s -enter", __func__);
-   return mFWInfo;
+  return mFWInfo;
 }
 
 FWCap* hal_fd_getFwCap() {
   STLOG_HAL_D("  %s -enter", __func__);
-   return mFWCap;
+  return mFWCap;
 }
 
 /**
@@ -343,7 +347,7 @@ FWCap* hal_fd_getFwCap() {
  *               FT_CLF_MODE_ERROR if Error
  */
 
-uint8_t ft_cmd_HwReset(uint8_t *pdata, uint8_t *clf_mode) {
+uint8_t ft_cmd_HwReset(uint8_t* pdata, uint8_t* clf_mode) {
   uint8_t result = 0;
 
   STLOG_HAL_D("  %s - execution", __func__);
@@ -429,7 +433,9 @@ uint8_t ft_cmd_HwReset(uint8_t *pdata, uint8_t *clf_mode) {
       (mFWInfo->chipHwVersion == HW_ST54L)) {
     if ((mFwFileBin != NULL) &&
         (mFWInfo->fileFwVersion != mFWInfo->chipFwVersion)) {
-      STLOG_HAL_D("---> Firmware update needed\n");
+      STLOG_HAL_D("---> Firmware update needed from 0x%08X to 0x%08X\n",
+                  mFWInfo->chipFwVersion, mFWInfo->fileFwVersion);
+
       result |= FW_UPDATE_NEEDED;
     } else {
       STLOG_HAL_D("---> No Firmware update needed\n");
@@ -438,8 +444,9 @@ uint8_t ft_cmd_HwReset(uint8_t *pdata, uint8_t *clf_mode) {
     if ((mFWInfo->fileCustVersion != 0) &&
         (mFWInfo->chipCustVersion != mFWInfo->fileCustVersion)) {
       STLOG_HAL_D(
-          "%s - Need to apply new st21nfc custom configuration settings\n",
-          __func__);
+          "%s - Need to apply new st21nfc custom configuration settings from "
+          "0x%04X to 0x%04X\n",
+          __func__, mFWInfo->chipCustVersion, mFWInfo->fileCustVersion);
       if (!mCustomParamFailed) result |= CONF_UPDATE_NEEDED;
     } else {
       STLOG_HAL_D("%s - No need to apply custom configuration settings\n",
@@ -455,7 +462,7 @@ uint8_t ft_cmd_HwReset(uint8_t *pdata, uint8_t *clf_mode) {
 
   uint8_t FWVersionMajor = (uint8_t)(hal_fd_getFwInfo()->chipFwVersion >> 24);
   uint8_t FWVersionMinor =
-        (uint8_t)((hal_fd_getFwInfo()->chipFwVersion & 0x00FF0000) >> 16);
+      (uint8_t)((hal_fd_getFwInfo()->chipFwVersion & 0x00FF0000) >> 16);
 
   if (hal_fd_getFwInfo()->chipHwVersion == HW_ST54L &&
       (FWVersionMajor >= 0x2) && (FWVersionMinor >= 0x5)) {
@@ -463,11 +470,17 @@ uint8_t ft_cmd_HwReset(uint8_t *pdata, uint8_t *clf_mode) {
   } else {
     mFWCap->ObserveMode = 0x1;
   }
+  if (hal_fd_getFwInfo()->chipHwVersion == HW_ST54L &&
+      (FWVersionMajor >= 0x2) && (FWVersionMinor >= 0x6)) {
+    mFWCap->ExitFrameSupport = 0x1;
+  } else {
+    mFWCap->ExitFrameSupport = 0x0;
+  }
   return result;
 } /* ft_cmd_HwReset */
 
 void ExitHibernateHandler(HALHANDLE mHalHandle, uint16_t data_len,
-                          uint8_t *p_data) {
+                          uint8_t* p_data) {
   STLOG_HAL_D("%s - Enter", __func__);
   if (data_len < 3) {
     STLOG_HAL_E("%s - Error, too short data (%d)", __func__, data_len);
@@ -492,7 +505,11 @@ void ExitHibernateHandler(HALHANDLE mHalHandle, uint16_t data_len,
             "%s - send NCI_PROP_NFC_FW_UPDATE_CMD and use 100 ms timer for "
             "each cmd from here",
             __func__);
-
+        HalEventLogger::getInstance().log()
+            << __func__
+            << " send NCI_PROP_NFC_FW_UPDATE_CMD and use 100 ms timer for "
+               "each cmd from here "
+            << std::endl;
         if (!HalSendDownstreamTimer(mHalHandle, NciPropNfcFwUpdate,
                                     sizeof(NciPropNfcFwUpdate),
                                     FW_TIMER_DURATION)) {
@@ -538,40 +555,39 @@ void ExitHibernateHandler(HALHANDLE mHalHandle, uint16_t data_len,
 }
 
 bool ft_CheckUWBConf() {
-
   char uwbLibName[256];
   STLOG_HAL_D("%s", __func__);
 
-  if (!GetStrValue(NAME_STNFC_UWB_LIB_NAME, (char *)uwbLibName,
+  if (!GetStrValue(NAME_STNFC_UWB_LIB_NAME, (char*)uwbLibName,
                    sizeof(uwbLibName))) {
     STLOG_HAL_D(
-        "%s - UWB conf library name not found in conf. use default name ", __func__);
+        "%s - UWB conf library name not found in conf. use default name ",
+        __func__);
     strcpy(uwbLibName, "/vendor/lib64/libqorvo_uwb_params_nfcc.so");
   }
 
   STLOG_HAL_D("%s - UWB conf library = %s", __func__, uwbLibName);
 
-  void *stdll = dlopen(uwbLibName, RTLD_NOW);
+  void* stdll = dlopen(uwbLibName, RTLD_NOW);
   if (stdll) {
     STLoadUwbParams fn =
         (STLoadUwbParams)dlsym(stdll, "load_uwb_params_from_files");
-  if (fn) {
-    size_t lengthOutput =
-        fn(nciPropSetUwbConfig + 9, 100);
-    STLOG_HAL_D("%s: lengthOutput = %zu", __func__, lengthOutput);
-    if (lengthOutput > 0) {
-      memcpy(nciPropSetUwbConfig, nciHeaderPropSetUwbConfig, 9);
-      nciPropSetUwbConfig[2] = lengthOutput + 6;
-      nciPropSetUwbConfig[8] = lengthOutput;
-      mFWInfo->fileUwbVersion =
-          nciPropSetUwbConfig[9] << 8 | nciPropSetUwbConfig[10];
-      STLOG_HAL_D("%s --> uwb configuration version 0x%04X \n", __func__,
-                  mFWInfo->fileUwbVersion);
-      return true;
-    } else {
-      STLOG_HAL_D("%s: lengthOutput null", __func__);
+    if (fn) {
+      size_t lengthOutput = fn(nciPropSetUwbConfig + 9, 100);
+      STLOG_HAL_D("%s: lengthOutput = %zu", __func__, lengthOutput);
+      if (lengthOutput > 0) {
+        memcpy(nciPropSetUwbConfig, nciHeaderPropSetUwbConfig, 9);
+        nciPropSetUwbConfig[2] = lengthOutput + 6;
+        nciPropSetUwbConfig[8] = lengthOutput;
+        mFWInfo->fileUwbVersion =
+            nciPropSetUwbConfig[9] << 8 | nciPropSetUwbConfig[10];
+        STLOG_HAL_D("%s --> uwb configuration version 0x%04X \n", __func__,
+                    mFWInfo->fileUwbVersion);
+        return true;
+      } else {
+        STLOG_HAL_D("%s: lengthOutput null", __func__);
+      }
     }
-   }
   } else {
     STLOG_HAL_D("libqorvo_uwb_params_nfcc not found, do nothing.");
   }
@@ -605,7 +621,7 @@ void resetHandlerState() {
 **
 **
 *******************************************************************************/
-void UpdateHandler(HALHANDLE mHalHandle, uint16_t data_len, uint8_t *p_data) {
+void UpdateHandler(HALHANDLE mHalHandle, uint16_t data_len, uint8_t* p_data) {
   HalSendDownstreamStopTimer(mHalHandle);
 
   switch (mHalFDState) {
@@ -614,7 +630,9 @@ void UpdateHandler(HALHANDLE mHalHandle, uint16_t data_len, uint8_t *p_data) {
 
       if ((p_data[data_len - 2] == 0x90) && (p_data[data_len - 1] == 0x00)) {
         STLOG_HAL_D("%s - send APDU_AUTHENTICATION_CMD", __func__);
-        if (!HalSendDownstreamTimer(mHalHandle, (uint8_t *)mApduAuthent,
+        HalEventLogger::getInstance().log()
+            << __func__ << " send APDU_AUTHENTICATION_CMD " << std::endl;
+        if (!HalSendDownstreamTimer(mHalHandle, (uint8_t*)mApduAuthent,
                                     sizeof(mApduAuthent), FW_TIMER_DURATION)) {
           STLOG_HAL_E("%s - SendDownstream failed", __func__);
         }
@@ -633,7 +651,10 @@ void UpdateHandler(HALHANDLE mHalHandle, uint16_t data_len, uint8_t *p_data) {
           STLOG_HAL_D(
               " %s - send APDU_ERASE_FLASH_CMD (keep appli and NDEF areas)",
               __func__);
-
+          HalEventLogger::getInstance().log()
+              << __func__
+              << " send APDU_ERASE_FLASH_CMD (keep appli and NDEF areas "
+              << std::endl;
           if (!HalSendDownstreamTimer(mHalHandle, ApduEraseNfcKeepAppliAndNdef,
                                       sizeof(ApduEraseNfcKeepAppliAndNdef),
                                       FW_TIMER_DURATION)) {
@@ -661,6 +682,8 @@ void UpdateHandler(HALHANDLE mHalHandle, uint16_t data_len, uint8_t *p_data) {
           if ((fread(mBinData, sizeof(uint8_t), 3, mFwFileBin) == 3) &&
               (fread(mBinData + 3, sizeof(uint8_t), mBinData[2], mFwFileBin) ==
                mBinData[2])) {
+            HalEventLogger::getInstance().log()
+                << __func__ << "  LINE: " << __LINE__ << std::endl;
             if (!HalSendDownstreamTimer(mHalHandle, mBinData, mBinData[2] + 3,
                                         FW_TIMER_DURATION)) {
               STLOG_HAL_E("%s - SendDownstream failed", __func__);
@@ -676,6 +699,8 @@ void UpdateHandler(HALHANDLE mHalHandle, uint16_t data_len, uint8_t *p_data) {
           if ((fread(mBinData, sizeof(uint8_t), 3, mFwFileBin) == 3) &&
               (fread(mBinData + 3, sizeof(uint8_t), mBinData[2], mFwFileBin) ==
                mBinData[2])) {
+            HalEventLogger::getInstance().log()
+                << __func__ << " Last Tx was NOK. Retry " << std::endl;
             if (!HalSendDownstreamTimer(mHalHandle, mBinData, mBinData[2] + 3,
                                         FW_TIMER_DURATION)) {
               STLOG_HAL_E("%s - SendDownstream failed", __func__);
@@ -733,6 +758,9 @@ static void UpdateHandlerST54L(HALHANDLE mHalHandle, uint16_t data_len,
 
   switch (mHalFD54LState) {
     case HAL_FD_ST54L_STATE_PUY_KEYUSER:
+      HalEventLogger::getInstance().log()
+          << __func__ << " mHalFD54LState: " << HAL_FD_ST54L_STATE_PUY_KEYUSER
+          << std::endl;
       if (!HalSendDownstreamTimer(
               mHalHandle, (uint8_t*)ApduPutKeyUser1[mFWInfo->chipProdType],
               sizeof(ApduPutKeyUser1[mFWInfo->chipProdType]),
@@ -744,6 +772,10 @@ static void UpdateHandlerST54L(HALHANDLE mHalHandle, uint16_t data_len,
 
     case HAL_FD_ST54L_STATE_ERASE_UPGRADE_START:
       if ((p_data[data_len - 2] == 0x90) && (p_data[data_len - 1] == 0x00)) {
+        HalEventLogger::getInstance().log()
+            << __func__
+            << " mHalFD54LState: " << HAL_FD_ST54L_STATE_ERASE_UPGRADE_START
+            << std::endl;
         if (!HalSendDownstreamTimer(mHalHandle, (uint8_t*)ApduEraseUpgradeStart,
                                     sizeof(ApduEraseUpgradeStart),
                                     FW_TIMER_DURATION)) {
@@ -758,6 +790,10 @@ static void UpdateHandlerST54L(HALHANDLE mHalHandle, uint16_t data_len,
 
     case HAL_FD_ST54L_STATE_ERASE_NFC_AREA:
       if ((p_data[data_len - 2] == 0x90) && (p_data[data_len - 1] == 0x00)) {
+        HalEventLogger::getInstance().log()
+            << __func__
+            << " mHalFD54LState: " << HAL_FD_ST54L_STATE_ERASE_NFC_AREA
+            << std::endl;
         if (!HalSendDownstreamTimer(mHalHandle, (uint8_t*)ApduEraseNfcArea,
                                     sizeof(ApduEraseNfcArea),
                                     FW_TIMER_DURATION)) {
@@ -772,6 +808,10 @@ static void UpdateHandlerST54L(HALHANDLE mHalHandle, uint16_t data_len,
 
     case HAL_FD_ST54L_STATE_ERASE_UPGRADE_STOP:
       if ((p_data[data_len - 2] == 0x90) && (p_data[data_len - 1] == 0x00)) {
+        HalEventLogger::getInstance().log()
+            << __func__
+            << " mHalFD54LState: " << HAL_FD_ST54L_STATE_ERASE_UPGRADE_STOP
+            << std::endl;
         if (!HalSendDownstreamTimer(mHalHandle, (uint8_t*)ApduEraseUpgradeStop,
                                     sizeof(ApduEraseUpgradeStop),
                                     FW_TIMER_DURATION)) {
@@ -795,12 +835,16 @@ static void UpdateHandlerST54L(HALHANDLE mHalHandle, uint16_t data_len,
           if ((fread(mBinData, sizeof(uint8_t), 3, mFwFileBin) == 3) &&
               (fread(mBinData + 3, sizeof(uint8_t), mBinData[2], mFwFileBin) ==
                mBinData[2])) {
+            HalEventLogger::getInstance().log()
+                << __func__ << "  LINE: " << __LINE__ << std::endl;
             if (!HalSendDownstreamTimer(mHalHandle, mBinData, mBinData[2] + 3,
                                         FW_TIMER_DURATION)) {
               STLOG_HAL_E("%s - SendDownstream failed", __func__);
             }
           } else {
             STLOG_HAL_D("%s - EOF of FW binary", __func__);
+            HalEventLogger::getInstance().log()
+                << __func__ << "  EOF of FW binary " << std::endl;
             if (!HalSendDownstreamTimer(
                     mHalHandle, (uint8_t*)ApduSetVariousConfig,
                     sizeof(ApduSetVariousConfig), FW_TIMER_DURATION)) {
@@ -815,6 +859,8 @@ static void UpdateHandlerST54L(HALHANDLE mHalHandle, uint16_t data_len,
           if ((fread(mBinData, sizeof(uint8_t), 3, mFwFileBin) == 3) &&
               (fread(mBinData + 3, sizeof(uint8_t), mBinData[2], mFwFileBin) ==
                mBinData[2])) {
+            HalEventLogger::getInstance().log()
+                << __func__ << "  Last Tx was NOK. Retry " << std::endl;
             if (!HalSendDownstreamTimer(mHalHandle, mBinData, mBinData[2] + 3,
                                         FW_TIMER_DURATION)) {
               STLOG_HAL_E("%s - SendDownstream failed", __func__);
@@ -822,6 +868,8 @@ static void UpdateHandlerST54L(HALHANDLE mHalHandle, uint16_t data_len,
             fgetpos(mFwFileBin, &mPos);  // save current position in stream
           } else {
             STLOG_HAL_D("%s - EOF of FW binary", __func__);
+            HalEventLogger::getInstance().log()
+                << __func__ << "  LINE: " << __LINE__ << std::endl;
             if (!HalSendDownstreamTimer(
                     mHalHandle, (uint8_t*)ApduSetVariousConfig,
                     sizeof(ApduSetVariousConfig), FW_TIMER_DURATION)) {
@@ -886,7 +934,7 @@ void FwUpdateHandler(HALHANDLE mHalHandle, uint16_t data_len, uint8_t* p_data) {
 }
 
 void ApplyCustomParamHandler(HALHANDLE mHalHandle, uint16_t data_len,
-                             uint8_t *p_data) {
+                             uint8_t* p_data) {
   STLOG_HAL_D("%s - Enter ", __func__);
   if (data_len < 3) {
     STLOG_HAL_E("%s : Error, too short data (%d)", __func__, data_len);
@@ -943,7 +991,6 @@ void ApplyCustomParamHandler(HALHANDLE mHalHandle, uint16_t data_len,
             mGetCustomerField = true;
 
           } else if (!mCustomParamDone) {
-
             STLOG_HAL_D("%s - EOF of custom file.", __func__);
             memset(nciPropSetConfig_CustomField, 0x0,
                    sizeof(nciPropSetConfig_CustomField));
@@ -999,7 +1046,7 @@ void ApplyCustomParamHandler(HALHANDLE mHalHandle, uint16_t data_len,
 }
 
 void ApplyUwbParamHandler(HALHANDLE mHalHandle, uint16_t data_len,
-                          uint8_t *p_data) {
+                          uint8_t* p_data) {
   STLOG_HAL_D("%s - Enter ", __func__);
   if (data_len < 3) {
     STLOG_HAL_E("%s : Error, too short data (%d)", __func__, data_len);
@@ -1088,7 +1135,7 @@ void ApplyUwbParamHandler(HALHANDLE mHalHandle, uint16_t data_len,
 
 void SendExitLoadMode(HALHANDLE mmHalHandle) {
   STLOG_HAL_D("%s - Send APDU_EXIT_LOAD_MODE_CMD", __func__);
-
+  HalEventLogger::getInstance().log() << __func__ << std::endl;
   if (!HalSendDownstreamTimer(mmHalHandle, ApduExitLoadMode,
                               sizeof(ApduExitLoadMode), FW_TIMER_DURATION)) {
     STLOG_HAL_E("%s - SendDownstream failed", __func__);
@@ -1098,7 +1145,7 @@ void SendExitLoadMode(HALHANDLE mmHalHandle) {
 
 void SendSwitchToUserMode(HALHANDLE mmHalHandle) {
   STLOG_HAL_D("%s: enter", __func__);
-
+  HalEventLogger::getInstance().log() << __func__ << std::endl;
   if (!HalSendDownstreamTimer(mmHalHandle, ApduSwitchToUser,
                               sizeof(ApduSwitchToUser), FW_TIMER_DURATION)) {
     STLOG_HAL_E("%s - SendDownstream failed", __func__);
diff --git a/st21nfc/hal/hal_fwlog.cc b/st21nfc/hal/hal_fwlog.cc
index 615c366..6aee8b1 100644
--- a/st21nfc/hal/hal_fwlog.cc
+++ b/st21nfc/hal/hal_fwlog.cc
@@ -19,21 +19,23 @@
 #define LOG_TAG "NfcHalFwLog"
 
 #include "hal_fwlog.h"
+
 #include <cutils/properties.h>
 #include <dlfcn.h>
 #include <errno.h>
 #include <hardware/nfc.h>
 #include <string.h>
+
 #include "android_logmsg.h"
-#include "halcore.h"
 #include "hal_fd.h"
+#include "halcore.h"
 
 extern void DispHal(const char* title, const void* data, size_t length);
 
 uint8_t handlePollingLoopData(uint8_t format, uint8_t* tlvBuffer,
                               uint16_t data_len, uint8_t** NewTlv) {
   uint8_t value_len = 0;
-  uint8_t flag= 0;
+  uint8_t flag = 0;
 
   uint32_t timestamp = (tlvBuffer[data_len - 4] << 24) |
                        (tlvBuffer[data_len - 3] << 16) |
@@ -77,14 +79,14 @@ uint8_t handlePollingLoopData(uint8_t format, uint8_t* tlvBuffer,
 
       // work-around type-A short frame notification bug
       if (hal_fd_getFwInfo()->chipHwVersion == HW_ST54J &&
-          (tlvBuffer[2] & 0xF) == 0x01 && // short frame
-          tlvBuffer[5] == 0x00 && // no error
-          tlvBuffer[6] == 0x0F // incorrect real size
-          ) {
+          (tlvBuffer[2] & 0xF) == 0x01 &&  // short frame
+          tlvBuffer[5] == 0x00 &&          // no error
+          tlvBuffer[6] == 0x0F             // incorrect real size
+      ) {
         tlv_size = 9;
       }
 
-      value_len = tlv_size- 3;
+      value_len = tlv_size - 3;
       *NewTlv = (uint8_t*)malloc(tlv_size * sizeof(uint8_t));
       uint8_t gain;
       uint8_t type;
@@ -93,9 +95,9 @@ uint8_t handlePollingLoopData(uint8_t format, uint8_t* tlvBuffer,
 
       switch (tlvBuffer[2] & 0xF) {
         case 0x1:
-           flag |= 0x01;
-           type = TYPE_A;
-           break;
+          flag |= 0x01;
+          type = TYPE_A;
+          break;
         case 0x2:
         case 0x3:
         case 0x4:
@@ -103,11 +105,11 @@ uint8_t handlePollingLoopData(uint8_t format, uint8_t* tlvBuffer,
         case 0x6:
         case 0xB:
         case 0xD:
-            type = TYPE_A;
+          type = TYPE_A;
           break;
         case 0x7:
         case 0xC:
-            type = TYPE_B;
+          type = TYPE_B;
           break;
         case 0x8:
         case 0x9:
@@ -137,8 +139,8 @@ uint8_t handlePollingLoopData(uint8_t format, uint8_t* tlvBuffer,
       (*NewTlv)[6] = ts & 0xFF;
       (*NewTlv)[7] = gain;
       if (tlv_size > 8) {
-      memcpy(*NewTlv + 8, tlvBuffer + 8, length_value);
-    }
+        memcpy(*NewTlv + 8, tlvBuffer + 8, length_value);
+      }
     } break;
     default:
       break;
@@ -169,7 +171,6 @@ int notifyPollingLoopFrames(uint8_t* p_data, uint16_t data_len,
                                     &tlvFormatted);
 
     if (tlvFormatted != NULL) {
-
       if (ObserverNtf == NULL) {
         ObserverNtf = (uint8_t*)malloc(4 * sizeof(uint8_t));
         memcpy(ObserverNtf, NCI_ANDROID_PASSIVE_OBSERVER_HEADER, 4);
diff --git a/st21nfc/hal/hal_fwlog.h b/st21nfc/hal/hal_fwlog.h
index bb5c1b5..193def3 100644
--- a/st21nfc/hal/hal_fwlog.h
+++ b/st21nfc/hal/hal_fwlog.h
@@ -23,7 +23,7 @@
 
 #include "halcore.h"
 
-    static const int T_CERx = 0x09;
+static const int T_CERx = 0x09;
 static const int T_fieldOn = 0x10;
 static const int T_fieldOff = 0x11;
 static const int T_CERxError = 0x19;
diff --git a/st21nfc/hal/halcore.cc b/st21nfc/hal/halcore.cc
index da1bae7..da5d043 100644
--- a/st21nfc/hal/halcore.cc
+++ b/st21nfc/hal/halcore.cc
@@ -27,9 +27,9 @@
 #include <unistd.h>
 
 #include "android_logmsg.h"
+#include "hal_fd.h"
 #include "halcore_private.h"
 #include "st21nfc_dev.h"
-#include "hal_fd.h"
 
 extern int I2cWriteCmd(const uint8_t* x, size_t len);
 extern void DispHal(const char* title, const void* data, size_t length);
@@ -41,12 +41,17 @@ static void HalStopTimer(HalInstance* inst);
 static bool rf_deactivate_delay;
 struct timespec start_tx_data;
 uint8_t NCI_ANDROID_GET_CAPS[] = {0x2f, 0x0c, 0x01, 0x0};
-uint8_t NCI_ANDROID_GET_CAPS_RSP[] = {0x4f,0x0c,0x0e,0x00,0x00,0x00,0x00,0x03,
-                                      0x00,0x01,0x01, //Passive Observe mode
-                                      0x01,0x01,0x01, //Polling frame ntf
-                                      0x03,0x01,0x00  //Autotransact polling loop filter
-                                    };
-
+uint8_t NCI_ANDROID_GET_CAPS_RSP[] = {
+    0x4f, 0x0c,
+    0x14,                          // Command length
+    0x00, 0x00, 0x00, 0x00,
+    0x05,                          // Nb of capabilities
+    0x00, 0x01, 0x01,              // Passive Observe mode
+    0x01, 0x01, 0x01,              // Polling frame ntf
+    0x03, 0x01, 0x00,              // Autotransact polling loop filter
+    0x04, 0x01, 0x05,              // Nb of max exit frame entries
+    0x05, 0x01, 0x01               // Polling loop annotations
+};
 
 /**************************************************************************************************
  *
@@ -60,8 +65,8 @@ static inline int sem_wait_nointr(sem_t* sem);
 static void HalOnNewUpstreamFrame(HalInstance* inst, const uint8_t* data,
                                   size_t length);
 static void HalTriggerNextDsPacket(HalInstance* inst);
-static bool HalEnqueueThreadMessage(HalInstance* inst, ThreadMesssage* msg);
-static bool HalDequeueThreadMessage(HalInstance* inst, ThreadMesssage* msg);
+static bool HalEnqueueThreadMessage(HalInstance* inst, ThreadMessage* msg);
+static bool HalDequeueThreadMessage(HalInstance* inst, ThreadMessage* msg);
 static HalBuffer* HalAllocBuffer(HalInstance* inst);
 static HalBuffer* HalFreeBuffer(HalInstance* inst, HalBuffer* b);
 static uint32_t HalSemWait(sem_t* pSemaphore, uint32_t timeout);
@@ -95,12 +100,12 @@ void HalCoreCallback(void* context, uint32_t event, const void* d,
 
   switch (event) {
     case HAL_EVENT_DSWRITE:
-      if (rf_deactivate_delay && length == 4 && data[0] == 0x21
-          && data[1] == 0x06 && data[2] == 0x01) {
+      if (rf_deactivate_delay && length == 4 && data[0] == 0x21 &&
+          data[1] == 0x06 && data[2] == 0x01) {
         delta_time_ms = HalTimeDiffInMs(start_tx_data, HalGetTimestamp());
         if (delta_time_ms >= 0 && delta_time_ms < TX_DELAY) {
-            STLOG_HAL_D("Delay %d ms\n", TX_DELAY - delta_time_ms);
-            usleep(1000 * (TX_DELAY - delta_time_ms));
+          STLOG_HAL_D("Delay %d ms\n", TX_DELAY - delta_time_ms);
+          usleep(1000 * (TX_DELAY - delta_time_ms));
         }
         rf_deactivate_delay = false;
       } else if (length > 1 && data[0] == 0x00 && data[1] == 0x00) {
@@ -112,11 +117,24 @@ void HalCoreCallback(void* context, uint32_t event, const void* d,
       STLOG_HAL_V("!! got event HAL_EVENT_DSWRITE for %zu bytes\n", length);
 
       DispHal("TX DATA", (data), length);
-      if (length == 4 && !memcmp(data, NCI_ANDROID_GET_CAPS,
-           sizeof(NCI_ANDROID_GET_CAPS))) {
-          NCI_ANDROID_GET_CAPS_RSP[10] = hal_fd_getFwCap()->ObserveMode;
+      if (length == 4 &&
+          !memcmp(data, NCI_ANDROID_GET_CAPS, sizeof(NCI_ANDROID_GET_CAPS))) {
+        NCI_ANDROID_GET_CAPS_RSP[2] = sizeof(NCI_ANDROID_GET_CAPS_RSP) - 3;
+        NCI_ANDROID_GET_CAPS_RSP[10] = hal_fd_getFwCap()->ObserveMode;
+        NCI_ANDROID_GET_CAPS_RSP[16] = hal_fd_getFwCap()->ExitFrameSupport;
+        uint8_t FWVersionMajor = (uint8_t)(hal_fd_getFwInfo()->chipFwVersion >> 24);
+        uint8_t FWVersionMinor =
+          (uint8_t)((hal_fd_getFwInfo()->chipFwVersion & 0x00FF0000) >> 16);
+        // Declare support for reader mode annotation only if fw version >= 2.06.
+        if (hal_fd_getFwInfo()->chipHwVersion == HW_ST54L &&
+          (FWVersionMajor >= 0x2) && (FWVersionMinor >= 0x6)) {
+            NCI_ANDROID_GET_CAPS_RSP[22] = 1;
+        } else {
+            NCI_ANDROID_GET_CAPS_RSP[22] = 0;
+        }
 
-        dev->p_data_cback(NCI_ANDROID_GET_CAPS_RSP[2]+3, NCI_ANDROID_GET_CAPS_RSP);
+        dev->p_data_cback(sizeof(NCI_ANDROID_GET_CAPS_RSP),
+                          NCI_ANDROID_GET_CAPS_RSP);
       } else {
         // Send write command to IO thread
         cmd = 'W';
@@ -133,8 +151,8 @@ void HalCoreCallback(void* context, uint32_t event, const void* d,
         STLOG_HAL_W(
             "length is illogical. Header length is %d, packet length %zu\n",
             data[2], length);
-      } else if (length > 1 && rf_deactivate_delay
-                 && data[0] == 0x00 && data[1] == 0x00) {
+      } else if (length > 1 && rf_deactivate_delay && data[0] == 0x00 &&
+                 data[1] == 0x00) {
         rf_deactivate_delay = false;
       }
 
@@ -275,7 +293,7 @@ HALHANDLE HalCreate(void* context, HAL_CALLBACK callback, uint32_t flags) {
 void HalDestroy(HALHANDLE hHAL) {
   HalInstance* inst = (HalInstance*)hHAL;
   // Tell the thread that we want to finish
-  ThreadMesssage msg;
+  ThreadMessage msg;
   msg.command = MSG_EXIT_REQUEST;
   msg.payload = 0;
   msg.length = 0;
@@ -305,17 +323,17 @@ void HalDestroy(HALHANDLE hHAL) {
  * @param hHAL HAL handle
  * @param data Data message
  * @param size Message size
- */ bool HalSendDownstream(HALHANDLE hHAL, const uint8_t* data, size_t size)
-{
+ */
+bool HalSendDownstream(HALHANDLE hHAL, const uint8_t* data, size_t size) {
   // Send an NCI frame downstream. will
   HalInstance* inst = (HalInstance*)hHAL;
-  if(inst == nullptr) {
+  if (inst == nullptr) {
     STLOG_HAL_E("HalInstance is null.");
     return false;
   }
 
   if ((size <= MAX_BUFFER_SIZE) && (size > 0)) {
-    ThreadMesssage msg;
+    ThreadMessage msg;
     HalBuffer* b = HalAllocBuffer(inst);
 
     if (!b) {
@@ -355,7 +373,7 @@ bool HalSendDownstreamTimer(HALHANDLE hHAL, const uint8_t* data, size_t size,
   HalInstance* inst = (HalInstance*)hHAL;
 
   if ((size <= MAX_BUFFER_SIZE) && (size > 0)) {
-    ThreadMesssage msg;
+    ThreadMessage msg;
     HalBuffer* b = HalAllocBuffer(inst);
 
     if (!b) {
@@ -383,7 +401,7 @@ bool HalSendDownstreamTimer(HALHANDLE hHAL, const uint8_t* data, size_t size,
 bool HalSendDownstreamTimer(HALHANDLE hHAL, uint32_t duration) {
   HalInstance* inst = (HalInstance*)hHAL;
 
-  ThreadMesssage msg;
+  ThreadMessage msg;
 
   msg.command = MSG_TIMER_START;
   msg.payload = 0;
@@ -417,7 +435,7 @@ bool HalSendDownstreamStopTimer(HALHANDLE hHAL) {
 bool HalSendUpstream(HALHANDLE hHAL, const uint8_t* data, size_t size) {
   HalInstance* inst = (HalInstance*)hHAL;
   if ((size <= MAX_BUFFER_SIZE) && (size > 0)) {
-    ThreadMesssage msg;
+    ThreadMessage msg;
     msg.command = MSG_RX_DATA;
     msg.payload = data;
     msg.length = size;
@@ -525,7 +543,7 @@ static void HalStartTimer(HalInstance* inst, uint32_t duration) {
  * @param msg Message to send
  * @return true if message properly copied in ring buffer
  */
-static bool HalEnqueueThreadMessage(HalInstance* inst, ThreadMesssage* msg) {
+static bool HalEnqueueThreadMessage(HalInstance* inst, ThreadMessage* msg) {
   // Put a message to the queue
   int nextWriteSlot;
   bool result = true;
@@ -546,7 +564,7 @@ static bool HalEnqueueThreadMessage(HalInstance* inst, ThreadMesssage* msg) {
 
   if (result) {
     // inst->ring[nextWriteSlot] = *msg;
-    memcpy(&(inst->ring[nextWriteSlot]), msg, sizeof(ThreadMesssage));
+    memcpy(&(inst->ring[nextWriteSlot]), msg, sizeof(ThreadMessage));
     inst->ringWritePos = nextWriteSlot;
   }
 
@@ -565,7 +583,7 @@ static bool HalEnqueueThreadMessage(HalInstance* inst, ThreadMesssage* msg) {
  * @param msg Message received
  * @return true if there is a new message to pull, false otherwise.
  */
-static bool HalDequeueThreadMessage(HalInstance* inst, ThreadMesssage* msg) {
+static bool HalDequeueThreadMessage(HalInstance* inst, ThreadMessage* msg) {
   int nextCmdIndex;
   bool result = true;
   // New data available
@@ -585,7 +603,7 @@ static bool HalDequeueThreadMessage(HalInstance* inst, ThreadMesssage* msg) {
 
   // Get new element from ringbuffer
   if (result) {
-    memcpy(msg, &(inst->ring[nextCmdIndex]), sizeof(ThreadMesssage));
+    memcpy(msg, &(inst->ring[nextCmdIndex]), sizeof(ThreadMessage));
     inst->ringReadPos = nextCmdIndex;
   }
 
@@ -607,7 +625,7 @@ static bool HalDequeueThreadMessage(HalInstance* inst, ThreadMesssage* msg) {
  */
 static HalBuffer* HalAllocBuffer(HalInstance* inst) {
   HalBuffer* b;
-  if(inst == nullptr) {
+  if (inst == nullptr) {
     STLOG_HAL_E("HalInstance is null.");
     return nullptr;
   }
@@ -731,7 +749,7 @@ static void* HalWorkerThread(void* arg) {
 
       case OS_SYNC_RELEASED: {
         // A message arrived
-        ThreadMesssage msg;
+        ThreadMessage msg;
 
         if (HalDequeueThreadMessage(inst, &msg)) {
           switch (msg.command) {
@@ -804,7 +822,7 @@ static void* HalWorkerThread(void* arg) {
               STLOG_HAL_D("MSG_TIMER_START \n");
               break;
             default:
-              STLOG_HAL_E("!received unkown thread message?\n");
+              STLOG_HAL_E("!received unknown thread message?\n");
               break;
           }
         } else {
diff --git a/st21nfc/hal/halcore_private.h b/st21nfc/hal/halcore_private.h
index 27483db..0ebab51 100644
--- a/st21nfc/hal/halcore_private.h
+++ b/st21nfc/hal/halcore_private.h
@@ -23,6 +23,7 @@
 #include <semaphore.h>
 #include <stdint.h>
 #include <time.h>
+
 #include "halcore.h"
 
 #define MAX_NCIFRAME_PAYLOAD_SIZE 255
@@ -76,7 +77,7 @@ typedef struct tagThreadMessage {
   const void* payload; /* ptr to message related data item */
   size_t length;       /* length of above payload */
   HalBuffer* buffer;   /* buffer object (optional) */
-} ThreadMesssage;
+} ThreadMessage;
 
 typedef enum {
   EVT_RX_DATA = 0,
@@ -117,7 +118,7 @@ typedef struct tagHalInstance {
   sem_t upstreamBlock;
 
   /* message ring-buffer */
-  ThreadMesssage ring[HAL_QUEUE_MAX];
+  ThreadMessage ring[HAL_QUEUE_MAX];
   int ringReadPos;
   int ringWritePos;
 
diff --git a/st21nfc/hal_wrapper.cc b/st21nfc/hal_wrapper.cc
index 381a94f..c86238d 100644
--- a/st21nfc/hal_wrapper.cc
+++ b/st21nfc/hal_wrapper.cc
@@ -25,6 +25,7 @@
 #include <unistd.h>
 
 #include "android_logmsg.h"
+#include "hal_event_logger.h"
 #include "hal_fd.h"
 #include "hal_fwlog.h"
 #include "halcore.h"
@@ -38,6 +39,7 @@ extern void I2cRecovery();
 
 static void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data);
 static void halWrapperCallback(uint8_t event, uint8_t event_status);
+static std::string hal_wrapper_state_to_str(uint16_t event);
 
 nfc_stack_callback_t* mHalWrapperCallback = NULL;
 nfc_stack_data_callback_t* mHalWrapperDataCallback = NULL;
@@ -79,6 +81,9 @@ unsigned long hal_field_timer = 0;
 static bool sEnableFwLog = false;
 uint8_t mObserverMode = 0;
 bool mObserverRsp = false;
+bool mPerTechCmdRsp = false;
+bool storedLog = false;
+bool mObserveModeSuspended = false;
 
 void wait_ready() {
   pthread_mutex_lock(&mutex);
@@ -113,6 +118,7 @@ bool hal_wrapper_open(st21nfc_dev_t* dev, nfc_stack_callback_t* p_cback,
 
   mObserverMode = 0;
   mObserverRsp = false;
+  mObserveModeSuspended = false;
 
   mHalWrapperCallback = p_cback;
   mHalWrapperDataCallback = p_data_cback;
@@ -129,6 +135,8 @@ bool hal_wrapper_open(st21nfc_dev_t* dev, nfc_stack_callback_t* p_cback,
   isDebuggable = property_get_int32("ro.debuggable", 0);
   mHalHandle = *pHandle;
 
+  HalEventLogger::getInstance().initialize();
+  HalEventLogger::getInstance().log() << __func__ << std::endl;
   HalSendDownstreamTimer(mHalHandle, 10000);
 
   return 1;
@@ -139,6 +147,8 @@ int hal_wrapper_close(int call_cb, int nfc_mode) {
   uint8_t propNfcModeSetCmdQb[] = {0x2f, 0x02, 0x02, 0x02, (uint8_t)nfc_mode};
 
   mHalWrapperState = HAL_WRAPPER_STATE_CLOSING;
+  HalEventLogger::getInstance().log() << __func__ << std::endl;
+
   // Send PROP_NFC_MODE_SET_CMD
   if (!HalSendDownstreamTimer(mHalHandle, propNfcModeSetCmdQb,
                               sizeof(propNfcModeSetCmdQb), 100)) {
@@ -168,6 +178,7 @@ void hal_wrapper_send_core_config_prop() {
       STLOG_HAL_V("%s - Enter", __func__);
       set_ready(0);
 
+      HalEventLogger::getInstance().log() << __func__ << std::endl;
       if (!HalSendDownstreamTimer(mHalHandle, ConfigBuffer, retlen, 1000)) {
         STLOG_HAL_E("NFC-NCI HAL: %s  SendDownstream failed", __func__);
       }
@@ -183,6 +194,7 @@ void hal_wrapper_send_vs_config() {
   set_ready(0);
   mHalWrapperState = HAL_WRAPPER_STATE_PROP_CONFIG;
   mReadFwConfigDone = true;
+  HalEventLogger::getInstance().log() << __func__ << std::endl;
   if (!HalSendDownstreamTimer(mHalHandle, nciPropGetFwDbgTracesConfig,
                               sizeof(nciPropGetFwDbgTracesConfig), 1000)) {
     STLOG_HAL_E("%s - SendDownstream failed", __func__);
@@ -201,9 +213,11 @@ void hal_wrapper_factoryReset() {
   STLOG_HAL_V("%s - mfactoryReset = %d", __func__, mfactoryReset);
 }
 
-void hal_wrapper_set_observer_mode(uint8_t enable) {
+void hal_wrapper_set_observer_mode(uint8_t enable, bool per_tech_cmd) {
   mObserverMode = enable;
   mObserverRsp = true;
+  mPerTechCmdRsp = per_tech_cmd;
+  mObserveModeSuspended = false;
 }
 void hal_wrapper_get_observer_mode() { mObserverRsp = true; }
 
@@ -278,6 +292,8 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
             } else {
               STLOG_HAL_V("%s - Send APDU_GET_ATR_CMD", __func__);
               mRetryFwDwl--;
+              HalEventLogger::getInstance().log()
+                  << __func__ << " Send APDU_GET_ATR_CMD" << std::endl;
               if (!HalSendDownstreamTimer(mHalHandle, ApduGetAtr,
                                           sizeof(ApduGetAtr),
                                           FW_TIMER_DURATION)) {
@@ -338,6 +354,8 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
         STLOG_HAL_V("%s - Sending PROP_NFC_MODE_SET_CMD", __func__);
         // Send PROP_NFC_MODE_SET_CMD(ON)
         mHalWrapperState = HAL_WRAPPER_STATE_NFC_ENABLE_ON;
+        HalEventLogger::getInstance().log()
+            << __func__ << " Sending PROP_NFC_MODE_SET_CMD" << std::endl;
         if (!HalSendDownstreamTimer(mHalHandle, propNfcModeSetCmdOn,
                                     sizeof(propNfcModeSetCmdOn), 500)) {
           STLOG_HAL_E("NFC-NCI HAL: %s  HalSendDownstreamTimer failed",
@@ -423,8 +441,8 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
           // NFC_STATUS_OK
           if (p_data[3] == 0x00) {
             bool confNeeded = false;
-            bool firmware_debug_enabled =
-                property_get_int32("persist.vendor.nfc.firmware_debug_enabled", 0);
+            bool firmware_debug_enabled = property_get_int32(
+                "persist.vendor.nfc.firmware_debug_enabled", 0);
 
             // Check if FW DBG shall be set
             if (GetNumValue(NAME_STNFC_FW_DEBUG_ENABLED, &num, sizeof(num)) ||
@@ -477,8 +495,9 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
                     __func__);
               }
 
-              if (data_len < 9 || p_data[6] == 0 || p_data[6] < (data_len - 7)
-                  || p_data[6] > (sizeof(nciPropEnableFwDbgTraces) - 9)) {
+              if (data_len < 9 || p_data[6] == 0 ||
+                  p_data[6] < (data_len - 7) ||
+                  p_data[6] > (sizeof(nciPropEnableFwDbgTraces) - 9)) {
                 if (confNeeded) {
                   android_errorWriteLog(0x534e4554, "169328517");
                   confNeeded = false;
@@ -529,7 +548,7 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
           p_data[0] = 0x4f;
           p_data[1] = 0x0c;
           p_data[2] = 0x02;
-          p_data[3] = 0x02;
+          p_data[3] = mPerTechCmdRsp ? 0x05 : 0x02;
           p_data[4] = rsp_status;
           data_len = 0x5;
         } else if (((p_data[0] == 0x41) && (p_data[1] == 0x17) &&
@@ -543,7 +562,11 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
               STLOG_HAL_E("mObserverMode got out of sync");
               mObserverMode = p_data[4];
             }
+            if (!mObserveModeSuspended) {
             p_data[5] = p_data[4];
+            } else {
+              p_data[5] =  0x00;
+            }
           } else {
             if (p_data[7] != mObserverMode) {
               STLOG_HAL_E("mObserverMode got out of sync");
@@ -557,8 +580,56 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
           p_data[3] = 0x04;
           p_data[4] = rsp_status;
           data_len = 0x6;
+          DispHal("RX DATA", (p_data), data_len);
         }
       }
+
+      if ((p_data[0] == 0x4f) && (p_data[1] == 0x19)) {
+        p_data[4] = p_data[3];
+        p_data[0] = 0x4f;
+        p_data[1] = 0x0c;
+        p_data[2] = 0x02;
+        p_data[3] = 0x06;
+        data_len = 0x5;
+        DispHal("RX DATA", (p_data), data_len);
+      } else if ((p_data[0] == 0x6f) && (p_data[1] == 0x1b)) {
+        // PROP_RF_OBSERVE_MODE_SUSPENDED_NTF
+        mObserveModeSuspended = true;
+        // Remove two byte CRC at end of frame.
+        data_len -= 2;
+        p_data[2] -= 2;
+        p_data[4] -= 2;
+        memcpy(nciAndroidPassiveObserver, p_data + 3, data_len - 3);
+
+        p_data[0] = 0x6f;
+        p_data[1] = 0x0c;
+        p_data[2] = p_data[2] + 1;
+        p_data[3] = 0xB;
+        memcpy(p_data + 4, nciAndroidPassiveObserver, data_len - 3);
+        data_len = data_len + 1;
+        DispHal("RX DATA", (p_data), data_len);
+      } else if ((p_data[0] == 0x6f) && (p_data[1] == 0x1c)) {
+        // PROP_RF_OBSERVE_MODE_RESUMED_NTF
+        mObserveModeSuspended = false;
+
+        p_data[0] = 0x6f;
+        p_data[1] = 0x0c;
+        p_data[2] = p_data[2] + 1;
+        p_data[3] = 0xC;
+        data_len = data_len + 1;
+        DispHal("RX DATA", (p_data), data_len);
+      } else if ((p_data[0] == 0x4f) && (p_data[1] == 0x1d)) {
+        // PROP_RF_SET_CUST_PASSIVE_POLL_FRAME_RSP
+        memcpy(nciAndroidPassiveObserver, p_data + 3, data_len - 3);
+        p_data[4] = p_data[3];
+        p_data[0] = 0x4f;
+        p_data[1] = 0x0c;
+        p_data[2] = 0x02;
+        p_data[3] = 0x09;
+        data_len = 0x5;
+        DispHal("RX DATA", (p_data), data_len);
+      }
+
       if (!((p_data[0] == 0x60) && (p_data[3] == 0xa0))) {
         if (mHciCreditLent && (p_data[0] == 0x60) && (p_data[1] == 0x06)) {
           if (p_data[4] == 0x01) {  // HCI connection
@@ -580,6 +651,8 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
             // start timer
             if (hal_field_timer) {
               mFieldInfoTimerStarted = true;
+              HalEventLogger::getInstance().log()
+                  << __func__ << " LINE: " << __LINE__ << std::endl;
               HalSendDownstreamTimer(mHalHandle, 20000);
             }
           } else if (p_data[3] == 0x00) {
@@ -593,7 +666,6 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
           // start timer
           mTimerStarted = true;
           mIsActiveRW = true;
-          HalSendDownstreamTimer(mHalHandle, 5000);
           (void)pthread_mutex_unlock(&mutex_activerw);
         } else if ((p_data[0] == 0x6f) && (p_data[1] == 0x06)) {
           (void)pthread_mutex_lock(&mutex_activerw);
@@ -602,12 +674,12 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
             HalSendDownstreamStopTimer(mHalHandle);
             mTimerStarted = false;
           }
-          if(mIsActiveRW == true) {
+          if (mIsActiveRW == true) {
             mIsActiveRW = false;
           } else {
-            mError_count ++;
+            mError_count++;
             STLOG_HAL_E("Error Act -> Act count=%d", mError_count);
-            if(mError_count > 20) {
+            if (mError_count > 20) {
               mError_count = 0;
               STLOG_HAL_E("NFC Recovery Start");
               mTimerStarted = true;
@@ -628,7 +700,8 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
             mTimerStarted = false;
           }
         } else if (p_data[0] == 0x60 && p_data[1] == 0x00) {
-          STLOG_HAL_E("%s - Reset trigger from 0x%x to 0x0", __func__, p_data[3]);
+          STLOG_HAL_E("%s - Reset trigger from 0x%x to 0x0", __func__,
+                      p_data[3]);
           p_data[3] = 0x0;  // Only reset trigger that should be received in
                             // HAL_WRAPPER_STATE_READY is unreocoverable error.
           mHalWrapperState = HAL_WRAPPER_STATE_RECOVERY;
@@ -716,6 +789,9 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
             __func__);
         // start timer
         mTimerStarted = true;
+        HalEventLogger::getInstance().log()
+            << __func__ << " HAL_WRAPPER_STATE_SET_ACTIVERW_TIMER "
+            << std::endl;
         HalSendDownstreamTimer(mHalHandle, 5000);
         // Chip state should back to Active
         // at screen off state.
@@ -743,11 +819,14 @@ void halWrapperDataCallback(uint16_t data_len, uint8_t* p_data) {
       }
       break;
     case HAL_WRAPPER_STATE_RECOVERY:
+      STLOG_HAL_W("%s - mHalWrapperState = HAL_WRAPPER_STATE_RECOVERY",
+                  __func__);
       break;
   }
 }
 
-static void halWrapperCallback(uint8_t event, __attribute__((unused))uint8_t event_status) {
+static void halWrapperCallback(uint8_t event,
+                               __attribute__((unused)) uint8_t event_status) {
   uint8_t coreInitCmd[] = {0x20, 0x01, 0x02, 0x00, 0x00};
   uint8_t rfDeactivateCmd[] = {0x21, 0x06, 0x01, 0x00};
   uint8_t p_data[6];
@@ -769,7 +848,14 @@ static void halWrapperCallback(uint8_t event, __attribute__((unused))uint8_t eve
         STLOG_HAL_E("NFC-NCI HAL: %s  Timeout accessing the CLF.", __func__);
         HalSendDownstreamStopTimer(mHalHandle);
         I2cRecovery();
-        abort(); // TODO: fix it when we have a better recovery method.
+        HalEventLogger::getInstance().log()
+            << __func__ << " Timeout accessing the CLF."
+            << " mHalWrapperState="
+            << hal_wrapper_state_to_str(mHalWrapperState)
+            << " mIsActiveRW=" << mIsActiveRW
+            << " mTimerStarted=" << mTimerStarted << std::endl;
+        HalEventLogger::getInstance().store_log();
+        abort();  // TODO: fix it when we have a better recovery method.
         return;
       }
       break;
@@ -786,7 +872,14 @@ static void halWrapperCallback(uint8_t event, __attribute__((unused))uint8_t eve
       if (event == HAL_WRAPPER_TIMEOUT_EVT) {
         STLOG_HAL_E("%s - Timer for FW update procedure timeout, retry",
                     __func__);
-        abort(); // TODO: fix it when we have a better recovery method.
+        HalEventLogger::getInstance().log()
+            << __func__ << " Timer for FW update procedure timeout, retry"
+            << " mHalWrapperState="
+            << hal_wrapper_state_to_str(mHalWrapperState)
+            << " mIsActiveRW=" << mIsActiveRW
+            << " mTimerStarted=" << mTimerStarted << std::endl;
+        HalEventLogger::getInstance().store_log();
+        abort();  // TODO: fix it when we have a better recovery method.
         HalSendDownstreamStopTimer(mHalHandle);
         resetHandlerState();
         I2cResetPulse();
@@ -808,7 +901,14 @@ static void halWrapperCallback(uint8_t event, __attribute__((unused))uint8_t eve
     case HAL_WRAPPER_STATE_PROP_CONFIG:
       if (event == HAL_WRAPPER_TIMEOUT_EVT) {
         STLOG_HAL_E("%s - Timer when sending conf parameters, retry", __func__);
-        abort(); // TODO: fix it when we have a better recovery method.
+        HalEventLogger::getInstance().log()
+            << __func__ << " Timer when sending conf parameters, retry"
+            << " mHalWrapperState="
+            << hal_wrapper_state_to_str(mHalWrapperState)
+            << " mIsActiveRW=" << mIsActiveRW
+            << " mTimerStarted=" << mTimerStarted << std::endl;
+        HalEventLogger::getInstance().store_log();
+        abort();  // TODO: fix it when we have a better recovery method.
         HalSendDownstreamStopTimer(mHalHandle);
         resetHandlerState();
         I2cResetPulse();
@@ -847,7 +947,45 @@ static void halWrapperCallback(uint8_t event, __attribute__((unused))uint8_t eve
       }
       break;
 
+    case HAL_WRAPPER_STATE_EXIT_HIBERNATE_INTERNAL:
+      if (event == HAL_WRAPPER_TIMEOUT_EVT) {
+        STLOG_HAL_E("NFC-NCI HAL: %s  Timeout at state: %s", __func__,
+                    hal_wrapper_state_to_str(mHalWrapperState).c_str());
+        HalEventLogger::getInstance().log()
+            << __func__ << " Timer when sending conf parameters, retry"
+            << " mHalWrapperState="
+            << hal_wrapper_state_to_str(mHalWrapperState)
+            << " mIsActiveRW=" << mIsActiveRW
+            << " mTimerStarted=" << mTimerStarted << std::endl;
+        HalEventLogger::getInstance().store_log();
+        HalSendDownstreamStopTimer(mHalHandle);
+        p_data[0] = 0x60;
+        p_data[1] = 0x00;
+        p_data[2] = 0x03;
+        p_data[3] = 0xAB;
+        p_data[4] = 0x00;
+        p_data[5] = 0x00;
+        data_len = 0x6;
+        mHalWrapperDataCallback(data_len, p_data);
+        mHalWrapperState = HAL_WRAPPER_STATE_OPEN;
+        return;
+      }
+      break;
+
     default:
+      if (event == HAL_WRAPPER_TIMEOUT_EVT) {
+        STLOG_HAL_E("NFC-NCI HAL: %s  Timeout at state: %s", __func__,
+                    hal_wrapper_state_to_str(mHalWrapperState).c_str());
+        if (!storedLog) {
+          HalEventLogger::getInstance().log()
+              << __func__ << " Timeout at state: "
+              << hal_wrapper_state_to_str(mHalWrapperState)
+              << " mIsActiveRW=" << mIsActiveRW
+              << " mTimerStarted=" << mTimerStarted << std::endl;
+          HalEventLogger::getInstance().store_log();
+          storedLog = true;
+        }
+      }
       break;
   }
 
@@ -883,3 +1021,62 @@ void hal_wrapper_setFwLogging(bool enable) {
 
   sEnableFwLog = enable;
 }
+
+/*******************************************************************************
+ **
+ ** Function         hal_wrapper_dumplog
+ **
+ ** Description      Dump HAL event logs.
+ **
+ ** Returns          void
+ **
+ *******************************************************************************/
+void hal_wrapper_dumplog(int fd) {
+  ALOGD("%s : fd= %d", __func__, fd);
+
+  HalEventLogger::getInstance().dump_log(fd);
+}
+
+/*******************************************************************************
+**
+** Function         hal_wrapper_state_to_str
+**
+** Description      convert wrapper state to string
+**
+** Returns          string
+**
+*******************************************************************************/
+static std::string hal_wrapper_state_to_str(uint16_t event) {
+  switch (event) {
+    case HAL_WRAPPER_STATE_CLOSED:
+      return "HAL_WRAPPER_STATE_CLOSED";
+    case HAL_WRAPPER_STATE_OPEN:
+      return "HAL_WRAPPER_STATE_OPEN";
+    case HAL_WRAPPER_STATE_OPEN_CPLT:
+      return "HAL_WRAPPER_STATE_OPEN_CPLT";
+    case HAL_WRAPPER_STATE_NFC_ENABLE_ON:
+      return "HAL_WRAPPER_STATE_NFC_ENABLE_ON";
+    case HAL_WRAPPER_STATE_PROP_CONFIG:
+      return "HAL_WRAPPER_STATE_PROP_CONFIG";
+    case HAL_WRAPPER_STATE_READY:
+      return "HAL_WRAPPER_STATE_READY";
+    case HAL_WRAPPER_STATE_CLOSING:
+      return "HAL_WRAPPER_STATE_CLOSING";
+    case HAL_WRAPPER_STATE_EXIT_HIBERNATE_INTERNAL:
+      return "HAL_WRAPPER_STATE_EXIT_HIBERNATE_INTERNAL";
+    case HAL_WRAPPER_STATE_UPDATE:
+      return "HAL_WRAPPER_STATE_UPDATE";
+    case HAL_WRAPPER_STATE_APPLY_CUSTOM_PARAM:
+      return "HAL_WRAPPER_STATE_APPLY_CUSTOM_PARAM";
+    case HAL_WRAPPER_STATE_APPLY_UWB_PARAM:
+      return "HAL_WRAPPER_STATE_APPLY_UWB_PARAM";
+    case HAL_WRAPPER_STATE_SET_ACTIVERW_TIMER:
+      return "HAL_WRAPPER_STATE_SET_ACTIVERW_TIMER";
+    case HAL_WRAPPER_STATE_APPLY_PROP_CONFIG:
+      return "HAL_WRAPPER_STATE_APPLY_PROP_CONFIG";
+    case HAL_WRAPPER_STATE_RECOVERY:
+      return "HAL_WRAPPER_STATE_RECOVERY";
+    default:
+      return "Unknown";
+  }
+}
\ No newline at end of file
diff --git a/st21nfc/include/android_logmsg.h b/st21nfc/include/android_logmsg.h
index 6769c05..5766239 100644
--- a/st21nfc/include/android_logmsg.h
+++ b/st21nfc/include/android_logmsg.h
@@ -27,6 +27,7 @@ extern "C" {
 
 #include <cutils/properties.h>
 #include <log/log.h>
+
 #include "data_types.h"
 
 #define DISP_NCI ProtoDispAdapterDisplayNciPacket
@@ -68,10 +69,10 @@ extern int GetStrValue(const char* name, char* pValue, unsigned long l);
 #define STNFC_TRACE_LEVEL_MASK 0x0F
 #define STNFC_TRACE_FLAG_PRIVACY 0x10
 
-#define STLOG_HAL_V(...)                                    \
-  {                                                         \
-    if ((hal_trace_level & STNFC_TRACE_LEVEL_MASK) >=       \
-        STNFC_TRACE_LEVEL_VERBOSE)                          \
+#define STLOG_HAL_V(...)                                      \
+  {                                                           \
+    if ((hal_trace_level & STNFC_TRACE_LEVEL_MASK) >=         \
+        STNFC_TRACE_LEVEL_VERBOSE)                            \
       LOG_PRI(ANDROID_LOG_VERBOSE, HAL_LOG_TAG, __VA_ARGS__); \
   }
 #define STLOG_HAL_D(...)                                                       \
diff --git a/st21nfc/include/config.h b/st21nfc/include/config.h
new file mode 100644
index 0000000..4b467fd
--- /dev/null
+++ b/st21nfc/include/config.h
@@ -0,0 +1,23 @@
+/*
+ * Copyright 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#ifndef CONFIG_H_
+#define CONFIG_H_
+
+extern "C" int GetNumValue(const char* name, void* pValue, unsigned long len);
+extern "C" int GetStrValue(const char* name, char* pValue, unsigned long l);
+
+#endif  // CONFIG_H_
\ No newline at end of file
diff --git a/st21nfc/include/hal_config.h b/st21nfc/include/hal_config.h
index fe526ba..cb2616a 100644
--- a/st21nfc/include/hal_config.h
+++ b/st21nfc/include/hal_config.h
@@ -45,5 +45,7 @@
 #define NAME_CORE_CONF_PROP "CORE_CONF_PROP"
 #define NAME_ST_NFC_DEV_NODE "ST_NFC_DEV_NODE"
 #define NAME_ST_NFC_RESET_REQ_SYSFS "ST_NFC_RESET_REQ_SYSFS"
+#define NAME_HAL_EVENT_LOG_DEBUG_ENABLED "HAL_EVENT_LOG_DEBUG_ENABLED"
+#define NAME_HAL_EVENT_LOG_STORAGE "HAL_EVENT_LOG_STORAGE"
 
 #endif
diff --git a/st21nfc/include/hal_event_logger.h b/st21nfc/include/hal_event_logger.h
new file mode 100644
index 0000000..0885f37
--- /dev/null
+++ b/st21nfc/include/hal_event_logger.h
@@ -0,0 +1,50 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <fstream>
+#include <sstream>
+#include <string>
+
+class HalEventLogger {
+ public:
+  static HalEventLogger& getInstance();
+  HalEventLogger& log();
+  void dump_log(int fd);
+  void initialize();
+  void store_log();
+
+  template <typename T>
+  HalEventLogger& operator<<(const T& value) {
+    ss << value;
+    return *this;
+  }
+  HalEventLogger& operator<<(std::ostream& (*manip)(std::ostream&)) {
+    if (manip == static_cast<std::ostream& (*)(std::ostream&)>(std::endl)) {
+      ss << std::endl;
+    }
+    return *this;
+  }
+
+ private:
+  HalEventLogger() {}
+  HalEventLogger(const HalEventLogger&) = delete;
+  HalEventLogger& operator=(const HalEventLogger&) = delete;
+  std::stringstream ss;
+  bool logging_enabled;
+  std::string EventFilePath;
+};
\ No newline at end of file
diff --git a/st21nfc/include/hal_fd.h b/st21nfc/include/hal_fd.h
index 3b2af48..56a6ac9 100644
--- a/st21nfc/include/hal_fd.h
+++ b/st21nfc/include/hal_fd.h
@@ -42,13 +42,12 @@ typedef struct FWInfo {
   uint8_t chipProdType;
 } FWInfo;
 
-
 /*
  *Structure containing capabilities
  */
 typedef struct FWCap {
   uint8_t ObserveMode;
-
+  uint8_t ExitFrameSupport;
 } FWCap;
 
 typedef enum {
@@ -98,9 +97,9 @@ void FwUpdateHandler(HALHANDLE mHalHandle, uint16_t data_len, uint8_t* p_data);
 void ApplyCustomParamHandler(HALHANDLE mHalHandle, uint16_t data_len,
                              uint8_t* p_data);
 void ApplyUwbParamHandler(HALHANDLE mHalHandle, uint16_t data_len,
-                             uint8_t* p_data);
+                          uint8_t* p_data);
 void resetHandlerState();
-bool ft_CheckUWBConf() ;
+bool ft_CheckUWBConf();
 FWInfo* hal_fd_getFwInfo();
 FWCap* hal_fd_getFwCap();
 #endif /* HAL_FD_H_ */
diff --git a/st21nfc/include/halcore.h b/st21nfc/include/halcore.h
index ddae93e..5b65008 100644
--- a/st21nfc/include/halcore.h
+++ b/st21nfc/include/halcore.h
@@ -87,4 +87,5 @@ bool HalSendUpstream(HALHANDLE hHAL, const uint8_t* data, size_t size);
 void hal_wrapper_set_state(hal_wrapper_state_e new_wrapper_state);
 void hal_wrapper_setFwLogging(bool enable);
 void I2cResetPulse();
+void hal_wrapper_dumplog(int fd);
 #endif
diff --git a/st21nfc/libnfc-hal-st-example.conf b/st21nfc/libnfc-hal-st-example.conf
index cfc13d9..b8737de 100644
--- a/st21nfc/libnfc-hal-st-example.conf
+++ b/st21nfc/libnfc-hal-st-example.conf
@@ -145,3 +145,10 @@ CORE_CONF_PROP={ 20, 02, 0a, 03,
         80, 01, 01       
 }
 
+###############################################################################
+# Vendor specific mode to enable HAL event log.
+HAL_EVENT_LOG_DEBUG_ENABLED=0
+
+###############################################################################
+# File used for NFC HAL event log storage
+HAL_EVENT_LOG_STORAGE="/data/vendor/nfc"
```

