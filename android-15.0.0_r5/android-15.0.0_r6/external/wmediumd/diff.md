```diff
diff --git a/wmediumd/inc/usfstl/vhost.h b/wmediumd/inc/usfstl/vhost.h
index 85a76d9..16d6f01 100644
--- a/wmediumd/inc/usfstl/vhost.h
+++ b/wmediumd/inc/usfstl/vhost.h
@@ -31,6 +31,19 @@ struct usfstl_vhost_user_ops {
 		       struct usfstl_vhost_user_buf *buf,
 		       unsigned int vring);
 	void (*disconnected)(struct usfstl_vhost_user_dev *dev);
+	// Called to initiate a snapshot or restore. Implementor should spawn a
+	// thread that reads or writes state to `fd` and then closes `fd`.
+	//
+	// Attempting to read/write to `fd` directly from `start_data_transfer`
+	// will likely cause a deadlock.
+	//
+	// `transfer_direction == 0` => snapshot (should write to the fd)
+	// `transfer_direction == 1` => restore (should read from the fd)
+	void (*start_data_transfer)(struct usfstl_vhost_user_dev *dev, uint32_t transfer_direction, int fd);
+	// Called to check if the work spawn by `start_data_transfer`
+	// succeeded. Should block until the work completes and abort if
+	// something went wrong.
+	void (*check_data_transfer)(struct usfstl_vhost_user_dev *dev);
 };
 
 /**
@@ -140,13 +153,6 @@ void usfstl_vhost_user_config_changed(struct usfstl_vhost_user_dev *dev);
  */
 void *usfstl_vhost_user_to_va(struct usfstl_vhost_user_dev *dev, uint64_t addr);
 
-/**
- * usfstl_vhost_user_to_va - translate address
- * @dev: device to translate address for
- * @addr: host-side virtual addr
- */
-uint64_t usfstl_vhost_user_to_phys(struct usfstl_vhost_user_dev *dev, uint64_t addr);
-
 /**
  * usfstl_vhost_phys_to_va - translate address
  * @dev: device to translate address for
diff --git a/wmediumd/inc/usfstl/vhostproto.h b/wmediumd/inc/usfstl/vhostproto.h
index 8e7b2ac..4858814 100644
--- a/wmediumd/inc/usfstl/vhostproto.h
+++ b/wmediumd/inc/usfstl/vhostproto.h
@@ -33,20 +33,8 @@ struct vhost_user_region {
 	uint64_t mmap_offset;
 };
 
-struct vring_snapshot {
-	int8_t enabled;
-	int8_t sleeping;
-	int8_t triggered;
-
-	unsigned int num;
-	uint64_t desc_guest_addr;
-	uint64_t avail_guest_addr;
-	uint64_t used_guest_addr;
-	uint16_t last_avail_idx;
-};
 
 struct vhost_user_snapshot {
-	struct vring_snapshot vrings[NUM_SNAPSHOT_QUEUES];
 };
 
 
@@ -60,6 +48,10 @@ struct vhost_user_msg {
 		struct {
 			uint32_t idx, num;
 		} vring_state;
+		// "A vring descriptor index for split virtqueues"
+		struct {
+			uint32_t idx, index_in_avail_ring;
+		} vring_desc_index_split;
 		struct {
 			uint32_t idx, flags;
 			uint64_t descriptor;
@@ -85,6 +77,10 @@ struct vhost_user_msg {
 			uint64_t size;
 			uint64_t offset;
 		} vring_area;
+		struct {
+			uint32_t transfer_direction;
+			uint32_t migration_phase;
+		} device_state_transfer;
 		struct {
 			int8_t bool_store;
 			struct vhost_user_snapshot snapshot;
@@ -102,6 +98,7 @@ struct vhost_user_msg {
 #define VHOST_USER_SET_VRING_NUM		 8
 #define VHOST_USER_SET_VRING_ADDR		 9
 #define VHOST_USER_SET_VRING_BASE		10
+#define VHOST_USER_GET_VRING_BASE		11
 #define VHOST_USER_SET_VRING_KICK		12
 #define VHOST_USER_SET_VRING_CALL		13
 #define VHOST_USER_GET_PROTOCOL_FEATURES	15
@@ -110,8 +107,8 @@ struct vhost_user_msg {
 #define VHOST_USER_SET_SLAVE_REQ_FD		21
 #define VHOST_USER_GET_CONFIG			24
 #define VHOST_USER_VRING_KICK			35
-#define VHOST_USER_SLEEP			1000
-#define VHOST_USER_WAKE				1001
+#define VHOST_USER_SET_DEVICE_STATE_FD		42
+#define VHOST_USER_CHECK_DEVICE_STATE		43
 #define VHOST_USER_SNAPSHOT			1002
 #define VHOST_USER_RESTORE			1003
 #define VHOST_USER_GET_SHARED_MEMORY_REGIONS	1004
@@ -136,5 +133,6 @@ struct vhost_user_msg {
 #define VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD       12
 #define VHOST_USER_PROTOCOL_F_RESET_DEVICE         13
 #define VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS 14
+#define VHOST_USER_PROTOCOL_F_DEVICE_STATE         19
 
 #endif // _USFSTL_VHOST_PROTO_H_
diff --git a/wmediumd/lib/vhost.c b/wmediumd/lib/vhost.c
index f5d1631..3fc5c44 100644
--- a/wmediumd/lib/vhost.c
+++ b/wmediumd/lib/vhost.c
@@ -41,11 +41,7 @@ struct usfstl_vhost_user_dev_int {
 	struct {
 		struct usfstl_loop_entry entry;
 		bool enabled;
-		bool sleeping;
 		bool triggered;
-		uint64_t desc_guest_addr;
-		uint64_t avail_guest_addr;
-		uint64_t used_guest_addr;
 		struct vring virtq;
 		int call_fd;
 		uint16_t last_avail_idx;
@@ -447,6 +443,7 @@ usfstl_vhost_user_update_virtq_kick(struct usfstl_vhost_user_dev_int *dev,
 	if (dev->virtqs[virtq].entry.fd != -1) {
 		usfstl_loop_unregister(&dev->virtqs[virtq].entry);
 		close(dev->virtqs[virtq].entry.fd);
+		dev->virtqs[virtq].entry.fd = -1;
 	}
 
 	if (fd != -1) {
@@ -583,14 +580,6 @@ static void usfstl_vhost_user_handle_msg(struct usfstl_loop_entry *entry)
 		USFSTL_ASSERT_EQ(msg.payload.vring_addr.flags, (uint32_t)0, "0x%x");
 		USFSTL_ASSERT(!dev->virtqs[msg.payload.vring_addr.idx].enabled);
 
-		// Save the guest physical addresses to make snapshotting more convenient.
-		dev->virtqs[msg.payload.vring_addr.idx].desc_guest_addr =
-			usfstl_vhost_user_to_phys(&dev->ext, msg.payload.vring_addr.descriptor);
-		dev->virtqs[msg.payload.vring_addr.idx].used_guest_addr =
-			usfstl_vhost_user_to_phys(&dev->ext, msg.payload.vring_addr.used);
-		dev->virtqs[msg.payload.vring_addr.idx].avail_guest_addr =
-			usfstl_vhost_user_to_phys(&dev->ext, msg.payload.vring_addr.avail);
-
 		dev->virtqs[msg.payload.vring_addr.idx].last_avail_idx = 0;
 		dev->virtqs[msg.payload.vring_addr.idx].virtq.desc =
 			usfstl_vhost_user_to_va(&dev->ext,
@@ -606,11 +595,23 @@ static void usfstl_vhost_user_handle_msg(struct usfstl_loop_entry *entry)
 			    dev->virtqs[msg.payload.vring_addr.idx].virtq.used);
 		break;
 	case VHOST_USER_SET_VRING_BASE:
-		/* ignored - logging not supported */
-		/*
-		 * FIXME: our Linux UML virtio implementation
-		 *        shouldn't send this
-		 */
+		USFSTL_ASSERT(len == (int)sizeof(msg.payload.vring_desc_index_split));
+		USFSTL_ASSERT(msg.payload.vring_desc_index_split.idx < dev->ext.server->max_queues);
+		dev->virtqs[msg.payload.vring_desc_index_split.idx].last_avail_idx =
+			msg.payload.vring_desc_index_split.index_in_avail_ring;
+		break;
+	case VHOST_USER_GET_VRING_BASE:
+		USFSTL_ASSERT(len == (int)sizeof(msg.payload.vring_state));
+		USFSTL_ASSERT(msg.payload.vring_state.idx < dev->ext.server->max_queues);
+		USFSTL_ASSERT(msg.payload.vring_state.num == 0);  // reserved
+		virtq = msg.payload.vring_state.idx;
+		// Stop the queue.
+		usfstl_vhost_user_update_virtq_kick(dev, virtq, -1);
+		// Build the response.
+		msg.payload.vring_desc_index_split.idx = virtq;
+		msg.payload.vring_desc_index_split.index_in_avail_ring =
+			dev->virtqs[virtq].last_avail_idx;
+		reply_len = (int)sizeof(msg.payload.vring_desc_index_split);
 		break;
 	case VHOST_USER_SET_VRING_KICK:
 		USFSTL_ASSERT(len == (int)sizeof(msg.payload.u64));
@@ -644,6 +645,7 @@ static void usfstl_vhost_user_handle_msg(struct usfstl_loop_entry *entry)
 		msg.payload.u64 |= 1ULL << VHOST_USER_PROTOCOL_F_SLAVE_REQ;
 		msg.payload.u64 |= 1ULL << VHOST_USER_PROTOCOL_F_SLAVE_SEND_FD;
 		msg.payload.u64 |= 1ULL << VHOST_USER_PROTOCOL_F_REPLY_ACK;
+		msg.payload.u64 |= 1ULL << VHOST_USER_PROTOCOL_F_DEVICE_STATE;
 		break;
 	case VHOST_USER_SET_VRING_ENABLE:
 		USFSTL_ASSERT(len == (int)sizeof(msg.payload.vring_state));
@@ -686,88 +688,37 @@ static void usfstl_vhost_user_handle_msg(struct usfstl_loop_entry *entry)
 		reply_len = sizeof(uint64_t);
 		msg.payload.u64 = 0;
 		break;
-	case VHOST_USER_SLEEP:
-		USFSTL_ASSERT_EQ(len, (ssize_t)0, "%zd");
-		USFSTL_ASSERT_EQ(dev->ext.server->max_queues, NUM_SNAPSHOT_QUEUES, "%d");
-		for (virtq = 0; virtq < dev->ext.server->max_queues; virtq++) {
-			if (dev->virtqs[virtq].enabled) {
-				dev->virtqs[virtq].enabled = false;
-				dev->virtqs[virtq].sleeping = true;
-				usfstl_loop_unregister(&dev->virtqs[virtq].entry);
-			}
-		}
-		msg.payload.i8 = 1; // success
-		reply_len = sizeof(msg.payload.i8);
+	case VHOST_USER_SET_DEVICE_STATE_FD: {
+		USFSTL_ASSERT_EQ(len, sizeof(msg.payload.device_state_transfer), "%zd");
+		USFSTL_ASSERT_EQ(msg.payload.device_state_transfer.migration_phase, /* stopped */ (uint32_t)0, "%d");
+		// Read the attached FD.
+		usfstl_vhost_user_get_msg_fds(&msghdr, &fd, 1);
+		USFSTL_ASSERT_CMP(fd, !=, -1, "%d");
+		// Delegate the data transfer to the backend.
+		USFSTL_ASSERT(dev->ext.server->ops->start_data_transfer);
+		dev->ext.server->ops->start_data_transfer(&dev->ext, msg.payload.device_state_transfer.transfer_direction, fd);
+		// Respond with success and the "invalid FD" flag (because we
+		// didn't include an FD in the response).
+		msg.payload.u64 = 0x100;
+		reply_len = sizeof(msg.payload.u64);
 		break;
-	case VHOST_USER_WAKE:
+	}
+	case VHOST_USER_CHECK_DEVICE_STATE: {
 		USFSTL_ASSERT_EQ(len, (ssize_t)0, "%zd");
-		USFSTL_ASSERT_EQ(dev->ext.server->max_queues, NUM_SNAPSHOT_QUEUES, "%d");
-		// enable previously enabled queues on wake
-		for (virtq = 0; virtq < dev->ext.server->max_queues; virtq++) {
-			if (dev->virtqs[virtq].sleeping) {
-				dev->virtqs[virtq].enabled = true;
-				dev->virtqs[virtq].sleeping = false;
-				usfstl_loop_register(&dev->virtqs[virtq].entry);
-				// TODO: is this needed?
-				usfstl_vhost_user_virtq_kick(dev, virtq);
-			}
-		}
-		msg.payload.i8 = 1; // success
-		reply_len = sizeof(msg.payload.i8);
+		USFSTL_ASSERT(dev->ext.server->ops->check_data_transfer);
+	        dev->ext.server->ops->check_data_transfer(&dev->ext);
+		msg.payload.u64 = 0;
+		reply_len = sizeof(msg.payload.u64);
 		break;
+	}
 	case VHOST_USER_SNAPSHOT: {
 		USFSTL_ASSERT_EQ(len, (ssize_t)0, "%zd");
-		USFSTL_ASSERT_EQ(dev->ext.server->max_queues, NUM_SNAPSHOT_QUEUES, "%d");
-		for (virtq = 0; virtq < dev->ext.server->max_queues; virtq++) {
-			struct vring_snapshot* snapshot = &msg.payload.snapshot_response.snapshot.vrings[virtq];
-			snapshot->enabled = dev->virtqs[virtq].enabled;
-			snapshot->sleeping = dev->virtqs[virtq].sleeping;
-			snapshot->triggered = dev->virtqs[virtq].triggered;
-			snapshot->num = dev->virtqs[virtq].virtq.num;
-			snapshot->desc_guest_addr = dev->virtqs[virtq].desc_guest_addr;
-			snapshot->avail_guest_addr = dev->virtqs[virtq].avail_guest_addr;
-			snapshot->used_guest_addr = dev->virtqs[virtq].used_guest_addr;
-			snapshot->last_avail_idx = dev->virtqs[virtq].last_avail_idx;
-		}
 		msg.payload.snapshot_response.bool_store = 1;
 		reply_len = (int)sizeof(msg.payload.snapshot_response);
 		break;
 	}
 	case VHOST_USER_RESTORE: {
-		int *fds;
 		USFSTL_ASSERT(len == (int)sizeof(msg.payload.restore_request));
-		USFSTL_ASSERT_EQ(dev->ext.server->max_queues, NUM_SNAPSHOT_QUEUES, "%d");
-
-		fds = (int*)malloc(dev->ext.server->max_queues * sizeof(int));
-		for (virtq = 0; virtq < dev->ext.server->max_queues; virtq++) {
-			fds[virtq] = -1;
-		}
-		usfstl_vhost_user_get_msg_fds(&msghdr, fds, 2);
-
-		for (virtq = 0; virtq < dev->ext.server->max_queues; virtq++) {
-			const struct vring_snapshot* snapshot = &msg.payload.restore_request.snapshot.vrings[virtq];
-			dev->virtqs[virtq].enabled = snapshot->enabled;
-			dev->virtqs[virtq].sleeping = snapshot->sleeping;
-			dev->virtqs[virtq].triggered = snapshot->triggered;
-			dev->virtqs[virtq].virtq.num = snapshot->num;
-			dev->virtqs[virtq].desc_guest_addr = snapshot->desc_guest_addr;
-			dev->virtqs[virtq].avail_guest_addr = snapshot->avail_guest_addr;
-			dev->virtqs[virtq].used_guest_addr = snapshot->used_guest_addr;
-			dev->virtqs[virtq].last_avail_idx = snapshot->last_avail_idx;
-
-			dev->virtqs[virtq].entry.fd = fds[virtq];
-
-			// Translate vring guest physical addresses.
-			dev->virtqs[virtq].virtq.desc = usfstl_vhost_phys_to_va(&dev->ext, dev->virtqs[virtq].desc_guest_addr);
-			dev->virtqs[virtq].virtq.used = usfstl_vhost_phys_to_va(&dev->ext, dev->virtqs[virtq].used_guest_addr);
-			dev->virtqs[virtq].virtq.avail = usfstl_vhost_phys_to_va(&dev->ext, dev->virtqs[virtq].avail_guest_addr);
-			USFSTL_ASSERT(dev->virtqs[virtq].virtq.avail &&
-				      dev->virtqs[virtq].virtq.desc &&
-				      dev->virtqs[virtq].virtq.used);
-		}
-
-		free(fds);
-
 		msg.payload.i8 = 1; // success
 		reply_len = sizeof(msg.payload.i8);
 		break;
@@ -946,25 +897,6 @@ void *usfstl_vhost_user_to_va(struct usfstl_vhost_user_dev *extdev, uint64_t add
 	return NULL;
 }
 
-uint64_t usfstl_vhost_user_to_phys(struct usfstl_vhost_user_dev *extdev, uint64_t addr)
-{
-	struct usfstl_vhost_user_dev_int *dev;
-	unsigned int region;
-
-	dev = container_of(extdev, struct usfstl_vhost_user_dev_int, ext);
-
-	for (region = 0; region < dev->n_regions; region++) {
-		if (addr >= dev->regions[region].user_addr &&
-		    addr < dev->regions[region].user_addr +
-			   dev->regions[region].size)
-			return addr -
-				dev->regions[region].user_addr +
-				dev->regions[region].guest_phys_addr;
-	}
-	USFSTL_ASSERT(0, "cannot translate user address %"PRIx64"\n", addr);
-	return 0;
-}
-
 void *usfstl_vhost_phys_to_va(struct usfstl_vhost_user_dev *extdev, uint64_t addr)
 {
 	struct usfstl_vhost_user_dev_int *dev;
diff --git a/wmediumd/wmediumd.c b/wmediumd/wmediumd.c
index 53f22c6..210f6f9 100644
--- a/wmediumd/wmediumd.c
+++ b/wmediumd/wmediumd.c
@@ -39,6 +39,7 @@
 #include <unistd.h>
 #include <stdarg.h>
 #include <endian.h>
+#include <pthread.h>
 #include <sys/msg.h>
 #include <usfstl/loop.h>
 #include <usfstl/sched.h>
@@ -784,7 +785,7 @@ static void send_cloned_frame_msg(struct wmediumd *ctx, struct client *src,
 	if (nla_put(msg, HWSIM_ATTR_ADDR_RECEIVER, ETH_ALEN,
 		    dst->hwaddr) ||
 	    nla_put(msg, HWSIM_ATTR_FRAME, data_len, data) ||
-	    nla_put_u32(msg, HWSIM_ATTR_RX_RATE, 1) ||
+	    nla_put_u32(msg, HWSIM_ATTR_RX_RATE, 7) ||
 	    nla_put_u32(msg, HWSIM_ATTR_FREQ, freq) ||
 	    nla_put_u32(msg, HWSIM_ATTR_SIGNAL, signal)) {
 		w_logf(ctx, LOG_ERR, "%s: Failed to fill a payload\n", __func__);
@@ -1348,6 +1349,63 @@ static void wmediumd_vu_disconnected(struct usfstl_vhost_user_dev *dev)
 	wmediumd_remove_client(dev->server->data, client);
 }
 
+static void *do_data_transfer(void *cookie) {
+	struct wmediumd *ctx = cookie;
+	switch (ctx->data_transfer_direction) {
+	case 0: // save
+		// No device state to save yet, just close the FD.
+		close(ctx->data_transfer_fd);
+		break;
+	case 1: { // load
+		// No device state to load yet, just verify it is empty.
+		uint8_t buf;
+		int n = read(ctx->data_transfer_fd, &buf, 1);
+		if (n < 0) {
+			w_logf(ctx, LOG_ERR, "%s: read failed: %s\n", __func__, strerror(errno));
+			abort();
+		}
+		if (n != 0) {
+			w_logf(ctx, LOG_ERR, "%s: loaded device state is non-empty. BUG!\n", __func__);
+			abort();
+		}
+		close(ctx->data_transfer_fd);
+		break;
+	}
+	default:
+		w_logf(ctx, LOG_ERR, "%s: invalid transfer_direction: %d\n", __func__, ctx->data_transfer_direction);
+		abort();
+	}
+	return NULL;
+}
+
+static void wmediumd_vu_start_data_transfer(struct usfstl_vhost_user_dev *dev, uint32_t transfer_direction, int fd) {
+	struct wmediumd *ctx = dev->server->data;
+
+	if (ctx->data_transfer_fd != -1) {
+		w_logf(ctx, LOG_ERR, "%s: can't start multiple data transfers\n", __func__);
+		abort();
+	}
+
+	ctx->data_transfer_fd = fd;
+	ctx->data_transfer_direction = transfer_direction;
+	if (pthread_create(&ctx->data_transfer_thread, NULL, &do_data_transfer, ctx)) {
+		w_logf(ctx, LOG_ERR, "%s: pthread_create failed: %s\n", __func__, strerror(errno));
+		abort();
+	}
+}
+static void wmediumd_vu_check_data_transfer(struct usfstl_vhost_user_dev *dev) {
+	struct wmediumd *ctx = dev->server->data;
+	if (ctx->data_transfer_fd == -1) {
+		w_logf(ctx, LOG_ERR, "%s: no active data transfer\n", __func__);
+		abort();
+	}
+	if (pthread_join(ctx->data_transfer_thread, NULL)) {
+		w_logf(ctx, LOG_ERR, "%s: pthread_join failed: %s\n", __func__, strerror(errno));
+		abort();
+	}
+	ctx->data_transfer_fd = -1;
+}
+
 static int process_set_snr_message(struct wmediumd *ctx, struct wmediumd_set_snr *set_snr) {
 	struct station *node1 = get_station_by_addr(ctx, set_snr->node1_mac);
 	struct station *node2 = get_station_by_addr(ctx, set_snr->node2_mac);
@@ -1519,6 +1577,8 @@ static const struct usfstl_vhost_user_ops wmediumd_vu_ops = {
 	.connected = wmediumd_vu_connected,
 	.handle = wmediumd_vu_handle,
 	.disconnected = wmediumd_vu_disconnected,
+	.start_data_transfer = wmediumd_vu_start_data_transfer,
+	.check_data_transfer = wmediumd_vu_check_data_transfer,
 };
 
 static void close_pcapng(struct wmediumd *ctx) {
@@ -2140,14 +2200,14 @@ int wmediumd_main(int argc, char *argv[], int event_fd, int msq_id)
 
 	if (time_socket) {
 		usfstl_sched_ctrl_start(&ctrl, time_socket,
-				      1000 /* nsec per usec */,
+				      100,
 				      (uint64_t)-1 /* no ID */,
 				      &scheduler);
 		vusrv.scheduler = &scheduler;
 		vusrv.ctrl = &ctrl;
 		ctx.ctrl = &ctrl;
 	} else {
-		usfstl_sched_wallclock_init(&scheduler, 1000);
+		usfstl_sched_wallclock_init(&scheduler, 100);
 	}
 
 	// Control event_fd to communicate WmediumdService.
@@ -2157,6 +2217,8 @@ int wmediumd_main(int argc, char *argv[], int event_fd, int msq_id)
 	usfstl_loop_register(&ctx.grpc_loop);
 	ctx.msq_id = msq_id;
 
+	ctx.data_transfer_fd = -1;
+
 	while (1) {
 		if (time_socket) {
 			usfstl_sched_next(&scheduler);
diff --git a/wmediumd/wmediumd.h b/wmediumd/wmediumd.h
index 4632713..6731c63 100644
--- a/wmediumd/wmediumd.h
+++ b/wmediumd/wmediumd.h
@@ -133,6 +133,7 @@ enum {
 
 #define SNR_DEFAULT 30
 
+#include <pthread.h>
 #include <stdint.h>
 #include <stdbool.h>
 #include <syslog.h>
@@ -256,6 +257,12 @@ struct wmediumd {
 	FILE *pcap_file;
 
 	char *config_path;
+
+	// data_transfer_thread and data_transfer_direction are undefined when
+	// data_transfer_fd is invalid (-1).
+	int data_transfer_fd;
+	uint32_t data_transfer_direction;
+	pthread_t data_transfer_thread;
 };
 
 struct hwsim_tx_rate {
```

