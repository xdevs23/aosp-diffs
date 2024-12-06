```diff
diff --git a/include/tinyalsa/mixer_plugin.h b/include/tinyalsa/mixer_plugin.h
index e8ef91a..80fd9f8 100644
--- a/include/tinyalsa/mixer_plugin.h
+++ b/include/tinyalsa/mixer_plugin.h
@@ -31,6 +31,8 @@
 #ifndef __MIXER_PLUGIN_H__
 #define __MIXER_PLUGIN_H__
 
+#include <pthread.h>
+
 #define MIXER_PLUGIN_OPEN_FN(name)                             \
     int name##_open(struct mixer_plugin **plugin,              \
                     unsigned int card)
@@ -78,6 +80,7 @@ struct mixer_plugin {
 
     struct snd_control *controls;
     unsigned int num_controls;
+    pthread_mutex_t mutex;
 };
 
 struct snd_value_enum {
diff --git a/mixer_plugin.c b/mixer_plugin.c
index 015120a..673d307 100644
--- a/mixer_plugin.c
+++ b/mixer_plugin.c
@@ -132,7 +132,9 @@ static int mixer_plug_info_integer(struct snd_control *ctl,
 
 void mixer_plug_notifier_cb(struct mixer_plugin *plugin)
 {
+    pthread_mutex_lock(&plugin->mutex);
     plugin->event_cnt++;
+    pthread_mutex_unlock(&plugin->mutex);
     eventfd_write(plugin->eventfd, 1);
 }
 
@@ -144,13 +146,20 @@ static ssize_t mixer_plug_read_event(void *data, struct snd_ctl_event *ev, size_
     struct mixer_plugin *plugin = plug_data->plugin;
     eventfd_t evfd;
     ssize_t result = 0;
+    unsigned int i, read_cnt;
 
     result = plugin->ops->read_event(plugin, (struct ctl_event *)ev, size);
 
     if (result > 0) {
-        plugin->event_cnt -=  result / sizeof(struct snd_ctl_event);
-        if (plugin->event_cnt <= 0) {
+        read_cnt = result / sizeof(struct snd_ctl_event);
+        pthread_mutex_lock(&plugin->mutex);
+        plugin->event_cnt -= read_cnt;
+        if (plugin->event_cnt < 0) {
             plugin->event_cnt = 0;
+        }
+        pthread_mutex_unlock(&plugin->mutex);
+
+        for (i = 0; i < read_cnt; ++i) {
             eventfd_read(plugin->eventfd, &evfd);
         }
     }
@@ -163,6 +172,7 @@ static int mixer_plug_subscribe_events(struct mixer_plug_data *plug_data,
 {
     struct mixer_plugin *plugin = plug_data->plugin;
     eventfd_t evfd;
+    unsigned int count;
 
     if (*subscribe < 0 || *subscribe > 1) {
         *subscribe = plugin->subscribed;
@@ -174,10 +184,13 @@ static int mixer_plug_subscribe_events(struct mixer_plug_data *plug_data,
     } else if (plugin->subscribed && !*subscribe) {
         plugin->ops->subscribe_events(plugin, NULL);
 
-        if (plugin->event_cnt)
-            eventfd_read(plugin->eventfd, &evfd);
-
+        pthread_mutex_lock(&plugin->mutex);
+        count = plugin->event_cnt;
         plugin->event_cnt = 0;
+        pthread_mutex_unlock(&plugin->mutex);
+        for (int i = 0; i < count; ++i) {
+            eventfd_read(plugin->eventfd, &evfd);
+        }
     }
 
     plugin->subscribed = *subscribe;
@@ -342,9 +355,16 @@ static void mixer_plug_close(void *data)
     struct mixer_plug_data *plug_data = data;
     struct mixer_plugin *plugin = plug_data->plugin;
     eventfd_t evfd;
+    unsigned int count;
 
-    if (plugin->event_cnt)
+    pthread_mutex_lock(&plugin->mutex);
+    count = plugin->event_cnt;
+    pthread_mutex_unlock(&plugin->mutex);
+    pthread_mutex_destroy(&plugin->mutex);
+
+    for (int i = 0; i < count; ++i) {
         eventfd_read(plugin->eventfd, &evfd);
+    }
 
     plugin->ops->close(&plugin);
     dlclose(plug_data->dl_hdl);
@@ -479,7 +499,8 @@ int mixer_plugin_open(unsigned int card, void **data,
     plug_data->plugin = plugin;
     plug_data->card = card;
     plug_data->dl_hdl = dl_hdl;
-    plugin->eventfd = eventfd(0, 0);
+    plugin->eventfd = eventfd(0, EFD_SEMAPHORE);
+    pthread_mutex_init(&plugin->mutex, NULL);
 
     *data = plug_data;
     *ops = &mixer_plug_ops;
```

