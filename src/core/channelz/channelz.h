//
//
// Copyright 2018 gRPC authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//

#ifndef GRPC_SRC_CORE_CHANNELZ_CHANNELZ_H
#define GRPC_SRC_CORE_CHANNELZ_CHANNELZ_H

#include <grpc/grpc.h>
#include <grpc/impl/connectivity_state.h>
#include <grpc/slice.h>
#include <grpc/support/port_platform.h>
#include <stddef.h>

#include <atomic>
#include <cstdint>
#include <initializer_list>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <type_traits>
#include <utility>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_set.h"
#include "absl/container/inlined_vector.h"
#include "absl/strings/string_view.h"
#include "src/core/channelz/channel_trace.h"
#include "src/core/lib/channel/channel_args.h"
#include "src/core/util/dual_ref_counted.h"
#include "src/core/util/json/json.h"
#include "src/core/util/per_cpu.h"
#include "src/core/util/ref_counted.h"
#include "src/core/util/ref_counted_ptr.h"
#include "src/core/util/string.h"
#include "src/core/util/sync.h"
#include "src/core/util/time.h"
#include "src/core/util/time_precise.h"
#include "src/core/util/useful.h"
#include "src/proto/grpc/channelz/v2/channelz.upb.h"

// Channel arg key for channelz node.
#define GRPC_ARG_CHANNELZ_CHANNEL_NODE \
  "grpc.internal.no_subchannel.channelz_channel_node"

// Channel arg key for the containing base node
#define GRPC_ARG_CHANNELZ_CONTAINING_BASE_NODE \
  "grpc.internal.no_subchannel.channelz_containing_base_node"

// Channel arg key for indicating an internal channel.
#define GRPC_ARG_CHANNELZ_IS_INTERNAL_CHANNEL \
  "grpc.channelz_is_internal_channel"

/// This is the default value for whether or not to enable channelz. If
/// GRPC_ARG_ENABLE_CHANNELZ is set, it will override this default value.
#define GRPC_ENABLE_CHANNELZ_DEFAULT true

/// This is the default value for the maximum amount of memory used by trace
/// events per channel trace node. If
/// GRPC_ARG_MAX_CHANNEL_TRACE_EVENT_MEMORY_PER_NODE is set, it will override
/// this default value.
#define GRPC_MAX_CHANNEL_TRACE_EVENT_MEMORY_PER_NODE_DEFAULT (1024 * 4)

namespace grpc_core {

namespace channelz {

class SocketNode;
class ListenSocketNode;
class DataSource;
class DataSink;
class PropertyList;
class ZTrace;

namespace testing {
class CallCountingHelperPeer;
class SubchannelNodePeer;
}  // namespace testing

// base class for all channelz entities
class BaseNode : public DualRefCounted<BaseNode> {
 public:
  // There are only four high level channelz entities. However, to support
  // GetTopChannelsRequest, we split the Channel entity into two different
  // types. All children of BaseNode must be one of these types.
  enum class EntityType {
    kTopLevelChannel,
    kInternalChannel,
    kSubchannel,
    kServer,
    kListenSocket,
    kSocket,
    kCall,
    kResourceQuota,
  };

  static absl::string_view EntityTypeString(EntityType type) {
    switch (type) {
      case EntityType::kTopLevelChannel:
        return "top_level_channel";
      case EntityType::kInternalChannel:
        return "internal_channel";
      case EntityType::kSubchannel:
        return "subchannel";
      case EntityType::kServer:
        return "server";
      case EntityType::kListenSocket:
        return "listen_socket";
      case EntityType::kSocket:
        return "socket";
      case EntityType::kCall:
        return "call";
      case EntityType::kResourceQuota:
        return "resource_quota";
    }
    return "unknown";
  }

  static absl::string_view EntityTypeToKind(EntityType type) {
    switch (type) {
      case EntityType::kTopLevelChannel:
        return "channel";
      case EntityType::kInternalChannel:
        return "internal_channel";
      case EntityType::kSubchannel:
        return "subchannel";
      case EntityType::kServer:
        return "server";
      case EntityType::kListenSocket:
        return "listen_socket";
      case EntityType::kSocket:
        return "socket";
      case EntityType::kCall:
        return "call";
      case EntityType::kResourceQuota:
        return "resource_quota";
    }
  }

  static std::optional<EntityType> KindToEntityType(absl::string_view kind) {
    if (kind == "channel") return EntityType::kTopLevelChannel;
    if (kind == "internal_channel") return EntityType::kInternalChannel;
    if (kind == "subchannel") return EntityType::kSubchannel;
    if (kind == "server") return EntityType::kServer;
    if (kind == "listen_socket") return EntityType::kListenSocket;
    if (kind == "socket") return EntityType::kSocket;
    if (kind == "call") return EntityType::kCall;
    if (kind == "resource_quota") return EntityType::kResourceQuota;
    return std::nullopt;
  }

 protected:
  BaseNode(EntityType type, size_t max_trace_memory, std::string name);

  // Leaf derived types should call NodeConstructed() in their constructors
  // to complete the initialization.
  void NodeConstructed();

 public:
  void Orphaned() override;

  bool HasParent(const BaseNode* parent) const {
    MutexLock lock(&parent_mu_);
    return parents_.find(parent) != parents_.end();
  }

  void AddParent(BaseNode* parent) {
    MutexLock lock(&parent_mu_);
    parents_.insert(parent->WeakRef());
  }

  void RemoveParent(BaseNode* parent) {
    MutexLock lock(&parent_mu_);
    parents_.erase(parent);
  }

  static absl::string_view ChannelArgName() {
    return GRPC_ARG_CHANNELZ_CONTAINING_BASE_NODE;
  }
  static int ChannelArgsCompare(const BaseNode* a, const BaseNode* b) {
    return QsortCompare(a, b);
  }

  // All children must implement this function.
  virtual Json RenderJson() = 0;

  // Renders the json and returns allocated string that must be freed by the
  // caller.
  std::string RenderJsonString();

  EntityType type() const { return type_; }
  intptr_t uuid() {
    const intptr_t id = uuid_.load(std::memory_order_relaxed);
    if (id > 0) return id;
    return UuidSlow();
  }
  const std::string& name() const { return name_; }

  void RunZTrace(absl::string_view name, Timestamp deadline,
                 std::map<std::string, std::string> args,
                 std::shared_ptr<grpc_event_engine::experimental::EventEngine>
                     event_engine,
                 absl::AnyInvocable<void(Json output)> callback);
  Json::Object AdditionalInfo();

  const ChannelTrace& trace() const { return trace_; }
  template <typename... Args>
  ChannelTrace::Node NewTraceNode(Args&&... args) {
    return trace_.NewNode(std::forward<Args>(args)...);
  }
  ChannelTrace& mutable_trace() { return trace_; }

  void SerializeEntity(grpc_channelz_v2_Entity* entity, upb_Arena* arena);

  std::string SerializeEntityToString();

 protected:
  void PopulateJsonFromDataSources(Json::Object& json);
  // V2: Add any node-specific data to the sink.
  // This is information that used to be provided by overloaded RenderJson
  // methods.
  // Over time the hope is that we can eliminate this method and move all
  // functionality into data sources.
  virtual void AddNodeSpecificData(DataSink sink);

 private:
  // to allow the ChannelzRegistry to set uuid_ under its lock.
  friend class ChannelzRegistry;
  // allow data source to register/unregister itself
  friend class DataSource;
  using ParentSet = absl::flat_hash_set<WeakRefCountedPtr<BaseNode>,
                                        WeakRefCountedPtrHash<BaseNode>,
                                        WeakRefCountedPtrEq<BaseNode>>;

  intptr_t UuidSlow();

  const EntityType type_;
  bool node_constructed_called_ = false;
  uint64_t orphaned_index_ = 0;  // updated by registry
  std::atomic<intptr_t> uuid_;
  std::string name_;
  Mutex data_sources_mu_;
  absl::InlinedVector<DataSource*, 3> data_sources_
      ABSL_GUARDED_BY(data_sources_mu_);
  BaseNode* prev_;  // updated by registry
  BaseNode* next_;  // updated by registry
  mutable Mutex parent_mu_;
  ParentSet parents_ ABSL_GUARDED_BY(parent_mu_);
  ChannelTrace trace_;
};

namespace detail {
inline ChannelTrace* LogOutputFrom(BaseNode* n) {
  if (n == nullptr) return nullptr;
  return LogOutputFrom(n->mutable_trace());
}

template <typename N>
inline std::enable_if_t<std::is_base_of_v<BaseNode, N>, ChannelTrace*>
LogOutputFrom(const RefCountedPtr<N>& n) {
  return LogOutputFrom(n.get());
}
}  // namespace detail

class ZTrace {
 public:
  virtual ~ZTrace() = default;
  virtual void Run(Timestamp deadline, std::map<std::string, std::string> args,
                   std::shared_ptr<grpc_event_engine::experimental::EventEngine>
                       event_engine,
                   absl::AnyInvocable<void(Json)>) = 0;
};

// This class is used to collect additional information about the channelz
// node. It's the backing implementation for DataSink. channelz users should
// use DataSink instead of this class directly.
// We form a shared_ptr<> around this class during collection.
// In DataSink we use a weak_ptr<> to allow rapid resource reclamation once
// the collection is complete (or has timed out).
class DataSinkImplementation {
 public:
  class Data {
   public:
    virtual ~Data() = default;
    virtual Json::Object ToJson() = 0;
    virtual void FillProto(google_protobuf_Any* any, upb_Arena* arena) = 0;
  };

  void AddData(absl::string_view name, std::unique_ptr<Data> data);
  Json::Object Finalize(bool timed_out);
  void Finalize(bool timed_out, grpc_channelz_v2_Entity* entity,
                upb_Arena* arena);

 private:
  Mutex mu_;
  std::map<std::string, std::unique_ptr<Data>> additional_info_
      ABSL_GUARDED_BY(mu_);
};

// Wrapper around absl::AnyInvocable<void()> that is used to notify when the
// DataSink has completed.
// We hold a shared_ptr<> around this class in DataSink to keep knowledge of
// when the DataSink has completed.
class DataSinkCompletionNotification {
 public:
  explicit DataSinkCompletionNotification(absl::AnyInvocable<void()> callback)
      : callback_(std::move(callback)) {}
  ~DataSinkCompletionNotification() { callback_(); }

 private:
  absl::AnyInvocable<void()> callback_;
};

class DataSink {
 public:
  DataSink(std::shared_ptr<DataSinkImplementation> impl,
           std::shared_ptr<DataSinkCompletionNotification> notification)
      : impl_(impl), notification_(std::move(notification)) {}

  template <typename T>
  std::void_t<decltype(std::declval<T>().TakeJsonObject())> AddData(
      absl::string_view name, T value) {
    class DataImpl final : public DataSinkImplementation::Data {
     public:
      explicit DataImpl(T value) : value_(std::move(value)) {}
      Json::Object ToJson() override { return value_.TakeJsonObject(); }
      void FillProto(google_protobuf_Any* any, upb_Arena* arena) override {
        value_.FillAny(any, arena);
      }

     private:
      T value_;
    };
    AddData(name, std::make_unique<DataImpl>(std::move(value)));
  }

 private:
  void AddData(absl::string_view name,
               std::unique_ptr<DataSinkImplementation::Data> data) {
    auto impl = impl_.lock();
    if (impl == nullptr) return;
    impl->AddData(name, std::move(data));
  }

  std::weak_ptr<DataSinkImplementation> impl_;
  std::shared_ptr<DataSinkCompletionNotification> notification_;
};

class DataSource {
 public:
  explicit DataSource(RefCountedPtr<BaseNode> node);

  // Add any relevant json fragments to the output.
  // This method must not cause the DataSource to be deleted, or else there will
  // be a deadlock.
  virtual void AddData(DataSink) {}

  // If this data source exports some ztrace, return it here.
  virtual std::unique_ptr<ZTrace> GetZTrace(absl::string_view /*name*/) {
    return nullptr;
  }

 protected:
  ~DataSource();
  RefCountedPtr<BaseNode> channelz_node() { return node_; }
  const BaseNode* channelz_node() const { return node_.get(); }

  // This method must be called in the most derived class's constructor.
  // It adds this data source to the node's list of data sources.
  void SourceConstructed();

  // This method must be called in the most derived class's destructor.
  // It removes this data source from the node's list of data sources.
  // If it is not called, then the AddData() function pointer may be invalid
  // when the node is queried.
  void SourceDestructing();

 private:
  RefCountedPtr<BaseNode> node_;
};

struct CallCounts {
  int64_t calls_started = 0;
  int64_t calls_succeeded = 0;
  int64_t calls_failed = 0;
  gpr_cycle_counter last_call_started_cycle = 0;

  std::string last_call_started_timestamp() const {
    return gpr_format_timespec(
        gpr_cycle_counter_to_time(last_call_started_cycle));
  }

  void PopulateJson(Json::Object& json) const;
  PropertyList ToPropertyList() const;
};

// This class is a helper class for channelz entities that deal with Channels,
// Subchannels, and Servers, since those have similar proto definitions.
// This class has the ability to:
//   - track calls_{started,succeeded,failed}
//   - track last_call_started_timestamp
//   - perform rendering of the above items
class CallCountingHelper final {
 public:
  void RecordCallStarted();
  void RecordCallFailed();
  void RecordCallSucceeded();

  CallCounts GetCallCounts() const {
    return {
        calls_started_.load(std::memory_order_relaxed),
        calls_succeeded_.load(std::memory_order_relaxed),
        calls_failed_.load(std::memory_order_relaxed),
        last_call_started_cycle_.load(std::memory_order_relaxed),
    };
  }

 private:
  // testing peer friend.
  friend class testing::CallCountingHelperPeer;

  std::atomic<int64_t> calls_started_{0};
  std::atomic<int64_t> calls_succeeded_{0};
  std::atomic<int64_t> calls_failed_{0};
  std::atomic<gpr_cycle_counter> last_call_started_cycle_{0};
};

class PerCpuCallCountingHelper final {
 public:
  void RecordCallStarted();
  void RecordCallFailed();
  void RecordCallSucceeded();

  CallCounts GetCallCounts() const;

 private:
  // testing peer friend.
  friend class testing::CallCountingHelperPeer;

  // We want to ensure that this per-cpu data structure lands on different
  // cachelines per cpu.
  struct alignas(GPR_CACHELINE_SIZE) PerCpuData {
    std::atomic<int64_t> calls_started{0};
    std::atomic<int64_t> calls_succeeded{0};
    std::atomic<int64_t> calls_failed{0};
    std::atomic<gpr_cycle_counter> last_call_started_cycle{0};
  };
  PerCpu<PerCpuData> per_cpu_data_{PerCpuOptions().SetCpusPerShard(4)};
};

// Handles channelz bookkeeping for channels
class ChannelNode final : public BaseNode {
 public:
  ChannelNode(std::string target, size_t max_trace_memory,
              bool is_internal_channel);

  void Orphaned() override {
    ChannelArgs to_destroy;
    {
      MutexLock lock(&channel_args_mu_);
      std::swap(channel_args_, to_destroy);
    }
    BaseNode::Orphaned();
  }

  static absl::string_view ChannelArgName() {
    return GRPC_ARG_CHANNELZ_CHANNEL_NODE;
  }
  static int ChannelArgsCompare(const ChannelNode* a, const ChannelNode* b) {
    return QsortCompare(a, b);
  }

  // Returns the string description of the given connectivity state.
  static const char* GetChannelConnectivityStateChangeString(
      grpc_connectivity_state state);

  Json RenderJson() override;

  // proxy methods to composed classes.
  void SetChannelArgs(const ChannelArgs& channel_args) {
    ChannelArgs to_destroy;
    MutexLock lock(&channel_args_mu_);
    std::swap(channel_args_, to_destroy);
    channel_args_ = channel_args;
  }
  void RecordCallStarted() { call_counter_.RecordCallStarted(); }
  void RecordCallFailed() { call_counter_.RecordCallFailed(); }
  void RecordCallSucceeded() { call_counter_.RecordCallSucceeded(); }

  void SetConnectivityState(grpc_connectivity_state state);

  const std::string& target() const { return target_; }
  std::optional<std::string> connectivity_state();
  CallCounts GetCallCounts() const { return call_counter_.GetCallCounts(); }
  std::set<intptr_t> child_channels() const;
  std::set<intptr_t> child_subchannels() const;
  ChannelArgs channel_args() const {
    MutexLock lock(&channel_args_mu_);
    return channel_args_;
  }

 private:
  void PopulateChildRefs(Json::Object* json);
  void AddNodeSpecificData(DataSink sink) override;

  std::string target_;
  CallCountingHelper call_counter_;
  // TODO(ctiller): keeping channel args here can create odd circular references
  // that are hard to reason about. Consider moving this to a DataSource.
  mutable Mutex channel_args_mu_;
  ChannelArgs channel_args_ ABSL_GUARDED_BY(channel_args_mu_);

  // Least significant bit indicates whether the value is set.  Remaining
  // bits are a grpc_connectivity_state value.
  std::atomic<int> connectivity_state_{0};
};

// Handles channelz bookkeeping for subchannels
class SubchannelNode final : public BaseNode {
 public:
  SubchannelNode(std::string target_address, size_t max_trace_memory);
  ~SubchannelNode() override;

  void Orphaned() override {
    ChannelArgs to_destroy;
    {
      MutexLock lock(&channel_args_mu_);
      std::swap(channel_args_, to_destroy);
    }
    BaseNode::Orphaned();
  }

  // Sets the subchannel's connectivity state without health checking.
  void UpdateConnectivityState(grpc_connectivity_state state);

  Json RenderJson() override;

  // proxy methods to composed classes.
  void SetChannelArgs(const ChannelArgs& channel_args) {
    ChannelArgs to_destroy;
    MutexLock lock(&channel_args_mu_);
    std::swap(channel_args_, to_destroy);
    channel_args_ = channel_args;
  }
  void RecordCallStarted() { call_counter_.RecordCallStarted(); }
  void RecordCallFailed() { call_counter_.RecordCallFailed(); }
  void RecordCallSucceeded() { call_counter_.RecordCallSucceeded(); }

  const std::string& target() const { return target_; }
  std::string connectivity_state() const;
  CallCounts GetCallCounts() const { return call_counter_.GetCallCounts(); }
  ChannelArgs channel_args() const {
    MutexLock lock(&channel_args_mu_);
    return channel_args_;
  }

 private:
  void AddNodeSpecificData(DataSink sink) override;

  // Allows the channel trace test to access trace_.
  friend class testing::SubchannelNodePeer;

  std::atomic<grpc_connectivity_state> connectivity_state_{GRPC_CHANNEL_IDLE};
  std::string target_;
  CallCountingHelper call_counter_;
  // TODO(ctiller): keeping channel args here can create odd circular references
  // that are hard to reason about. Consider moving this to a DataSource.
  mutable Mutex channel_args_mu_;
  ChannelArgs channel_args_ ABSL_GUARDED_BY(channel_args_mu_);
};

// Handles channelz bookkeeping for servers
class ServerNode final : public BaseNode {
 public:
  explicit ServerNode(size_t max_trace_memory);

  ~ServerNode() override;

  void Orphaned() override {
    ChannelArgs to_destroy;
    {
      MutexLock lock(&channel_args_mu_);
      std::swap(channel_args_, to_destroy);
    }
    BaseNode::Orphaned();
  }

  Json RenderJson() override;

  std::string RenderServerSockets(intptr_t start_socket_id,
                                  intptr_t max_results);

  // proxy methods to composed classes.
  void SetChannelArgs(const ChannelArgs& channel_args) {
    ChannelArgs to_destroy;
    MutexLock lock(&channel_args_mu_);
    std::swap(channel_args_, to_destroy);
    channel_args_ = channel_args;
  }
  void RecordCallStarted() { call_counter_.RecordCallStarted(); }
  void RecordCallFailed() { call_counter_.RecordCallFailed(); }
  void RecordCallSucceeded() { call_counter_.RecordCallSucceeded(); }

  CallCounts GetCallCounts() const { return call_counter_.GetCallCounts(); }

  std::map<intptr_t, WeakRefCountedPtr<ListenSocketNode>> child_listen_sockets()
      const;
  std::map<intptr_t, WeakRefCountedPtr<SocketNode>> child_sockets() const;

  ChannelArgs channel_args() const {
    MutexLock lock(&channel_args_mu_);
    return channel_args_;
  }

 private:
  void AddNodeSpecificData(DataSink sink) override;

  PerCpuCallCountingHelper call_counter_;
  // TODO(ctiller): keeping channel args here can create odd circular references
  // that are hard to reason about. Consider moving this to a DataSource.
  mutable Mutex channel_args_mu_;
  ChannelArgs channel_args_ ABSL_GUARDED_BY(channel_args_mu_);
};

#define GRPC_ARG_CHANNELZ_SECURITY "grpc.internal.channelz_security"

// Handles channelz bookkeeping for sockets
class SocketNode final : public BaseNode {
 public:
  struct Security : public RefCounted<Security> {
    struct Tls {
      // This is a workaround for https://bugs.llvm.org/show_bug.cgi?id=50346
      Tls() {}

      enum class NameType { kUnset = 0, kStandardName = 1, kOtherName = 2 };
      NameType type = NameType::kUnset;
      // Holds the value of standard_name or other_names if type is not kUnset.
      std::string name;
      std::string local_certificate;
      std::string remote_certificate;

      Json RenderJson();
      PropertyList ToPropertyList() const;
    };
    enum class ModelType { kUnset = 0, kTls = 1, kOther = 2 };
    ModelType type = ModelType::kUnset;
    std::optional<Tls> tls;
    std::optional<Json> other;

    Json RenderJson();
    PropertyList ToPropertyList() const;

    static absl::string_view ChannelArgName() {
      return GRPC_ARG_CHANNELZ_SECURITY;
    }

    static int ChannelArgsCompare(const Security* a, const Security* b) {
      return QsortCompare(a, b);
    }
  };

  SocketNode(std::string local, std::string remote, std::string name,
             RefCountedPtr<Security> security);
  ~SocketNode() override {}

  Json RenderJson() override;

  void RecordStreamStartedFromLocal();
  void RecordStreamStartedFromRemote();
  void RecordStreamSucceeded() {
    streams_succeeded_.fetch_add(1, std::memory_order_relaxed);
  }
  void RecordStreamFailed() {
    streams_failed_.fetch_add(1, std::memory_order_relaxed);
  }
  void RecordMessagesSent(uint32_t num_sent);
  void RecordMessageReceived();
  void RecordKeepaliveSent() {
    keepalives_sent_.fetch_add(1, std::memory_order_relaxed);
  }

  const std::string& remote() { return remote_; }

  int64_t streams_started() const {
    return streams_started_.load(std::memory_order_relaxed);
  }
  int64_t streams_succeeded() const {
    return streams_succeeded_.load(std::memory_order_relaxed);
  }
  int64_t streams_failed() const {
    return streams_failed_.load(std::memory_order_relaxed);
  }
  int64_t messages_sent() const {
    return messages_sent_.load(std::memory_order_relaxed);
  }
  int64_t messages_received() const {
    return messages_received_.load(std::memory_order_relaxed);
  }
  int64_t keepalives_sent() const {
    return keepalives_sent_.load(std::memory_order_relaxed);
  }
  auto last_local_stream_created_timestamp() const {
    return CycleCounterToTimestamp(
        last_local_stream_created_cycle_.load(std::memory_order_relaxed));
  }
  auto last_remote_stream_created_timestamp() const {
    return CycleCounterToTimestamp(
        last_remote_stream_created_cycle_.load(std::memory_order_relaxed));
  }
  auto last_message_sent_timestamp() const {
    return CycleCounterToTimestamp(
        last_message_sent_cycle_.load(std::memory_order_relaxed));
  }
  auto last_message_received_timestamp() const {
    return CycleCounterToTimestamp(
        last_message_received_cycle_.load(std::memory_order_relaxed));
  }
  const std::string& local() const { return local_; }
  const std::string& remote() const { return remote_; }

  RefCountedPtr<Security> security() const { return security_; }

 private:
  std::optional<std::string> CycleCounterToTimestamp(
      gpr_cycle_counter cycle_counter) const {
    return gpr_format_timespec(gpr_cycle_counter_to_time(cycle_counter));
  }
  void AddNodeSpecificData(DataSink sink) override;

  std::atomic<int64_t> streams_started_{0};
  std::atomic<int64_t> streams_succeeded_{0};
  std::atomic<int64_t> streams_failed_{0};
  std::atomic<int64_t> messages_sent_{0};
  std::atomic<int64_t> messages_received_{0};
  std::atomic<int64_t> keepalives_sent_{0};
  std::atomic<gpr_cycle_counter> last_local_stream_created_cycle_{0};
  std::atomic<gpr_cycle_counter> last_remote_stream_created_cycle_{0};
  std::atomic<gpr_cycle_counter> last_message_sent_cycle_{0};
  std::atomic<gpr_cycle_counter> last_message_received_cycle_{0};
  std::string local_;
  std::string remote_;
  RefCountedPtr<Security> const security_;
};

// Handles channelz bookkeeping for listen sockets
class ListenSocketNode final : public BaseNode {
 public:
  ListenSocketNode(std::string local_addr, std::string name);
  ~ListenSocketNode() override {}

  Json RenderJson() override;

 private:
  void AddNodeSpecificData(DataSink sink) override;

  std::string local_addr_;
};

class CallNode final : public BaseNode {
 public:
  explicit CallNode(std::string name)
      : BaseNode(EntityType::kCall, 0, std::move(name)) {
    NodeConstructed();
  }

  Json RenderJson() override;
};

class ResourceQuotaNode final : public BaseNode {
 public:
  explicit ResourceQuotaNode(std::string name)
      : BaseNode(EntityType::kResourceQuota, 0, std::move(name)) {
    NodeConstructed();
  }

  Json RenderJson() override { return Json::FromString("ResourceQuota"); }
};

}  // namespace channelz
}  // namespace grpc_core

#endif  // GRPC_SRC_CORE_CHANNELZ_CHANNELZ_H
