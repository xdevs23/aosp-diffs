```diff
diff --git a/discovery/dnssd/impl/dns_data_graph.cc b/discovery/dnssd/impl/dns_data_graph.cc
index 079dbf7d..269b35ba 100644
--- a/discovery/dnssd/impl/dns_data_graph.cc
+++ b/discovery/dnssd/impl/dns_data_graph.cc
@@ -310,8 +310,11 @@ void DnsDataGraphImpl::Node::ApplyChildChange(DomainName child_name,
     AddChild(pair.first->second.get());
   } else if (event == RecordChangedEvent::kExpired) {
     const auto it = graph_->nodes_.find(child_name);
-    OSP_DCHECK(it != graph_->nodes_.end());
-    RemoveChild(it->second.get());
+    if (it == graph_->nodes_.end()) {
+      OSP_LOG_WARN << "Unable to find child_name=" << child_name.ToString();
+    } else {
+      RemoveChild(it->second.get());
+    }
   }
 }
 
```

