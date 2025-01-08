```diff
diff --git a/system/profile/avrcp/avrcp_sdp_records.cc b/system/profile/avrcp/avrcp_sdp_records.cc
index b58f047422..394c6d81ff 100644
--- a/system/profile/avrcp/avrcp_sdp_records.cc
+++ b/system/profile/avrcp/avrcp_sdp_records.cc
@@ -98,8 +98,9 @@ uint16_t AvrcSdpRecordHelper::RemoveRecord(const uint16_t request_id) {
     } else {
       log::info("Removing the record for service uuid 0x{:x}", service_uuid);
       bta_sys_remove_uuid(service_uuid);
+      auto result = AVRC_RemoveRecord(sdp_record_handle_);
       sdp_record_handle_ = RECORD_NOT_ASSIGNED;
-      return AVRC_RemoveRecord(sdp_record_handle_);
+      return result;
     }
   }
   // Nothing to remove.
```

