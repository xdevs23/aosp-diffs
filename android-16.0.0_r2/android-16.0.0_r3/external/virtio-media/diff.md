```diff
diff --git a/driver/virtio_media_ioctls.c b/driver/virtio_media_ioctls.c
index 2d9a400..2bbcf98 100644
--- a/driver/virtio_media_ioctls.c
+++ b/driver/virtio_media_ioctls.c
@@ -14,6 +14,8 @@
 #include "scatterlist_filler.h"
 #include "virtio_media.h"
 
+#include <linux/version.h>
+
 /**
  * Send an ioctl that has no driver payload, but expects a reponse from the host (i.e. an
  * ioctl specified with _IOR).
@@ -478,9 +480,11 @@ SIMPLE_WR_IOCTL(enum_framesizes, VIDIOC_ENUM_FRAMESIZES,
 		struct v4l2_frmsizeenum)
 SIMPLE_WR_IOCTL(enum_frameintervals, VIDIOC_ENUM_FRAMEINTERVALS,
 		struct v4l2_frmivalenum)
+#if LINUX_VERSION_CODE < KERNEL_VERSION(6,15,0)
 SIMPLE_WR_IOCTL(queryctrl, VIDIOC_QUERYCTRL, struct v4l2_queryctrl)
 SIMPLE_WR_IOCTL(g_ctrl, VIDIOC_G_CTRL, struct v4l2_control)
 SIMPLE_WR_IOCTL(s_ctrl, VIDIOC_S_CTRL, struct v4l2_control)
+#endif
 SIMPLE_WR_IOCTL(query_ext_ctrl, VIDIOC_QUERY_EXT_CTRL,
 		struct v4l2_query_ext_ctrl)
 SIMPLE_WR_IOCTL(s_dv_timings, VIDIOC_S_DV_TIMINGS, struct v4l2_dv_timings)
@@ -1143,10 +1147,12 @@ const struct v4l2_ioctl_ops virtio_media_ioctl_ops = {
 	.vidioc_s_output = virtio_media_s_output,
 
 	/* Control handling */
+#if LINUX_VERSION_CODE < KERNEL_VERSION(6,15,0)
 	.vidioc_queryctrl = virtio_media_queryctrl,
-	.vidioc_query_ext_ctrl = virtio_media_query_ext_ctrl,
 	.vidioc_g_ctrl = virtio_media_g_ctrl,
 	.vidioc_s_ctrl = virtio_media_s_ctrl,
+#endif
+	.vidioc_query_ext_ctrl = virtio_media_query_ext_ctrl,
 	.vidioc_g_ext_ctrls = virtio_media_g_ext_ctrls,
 	.vidioc_s_ext_ctrls = virtio_media_s_ext_ctrls,
 	.vidioc_try_ext_ctrls = virtio_media_try_ext_ctrls,
```

