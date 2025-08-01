// Copyright 2022 gRPC authors.
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

#include "test/core/event_engine/event_engine_test_utils.h"

#include <grpc/event_engine/event_engine.h>
#include <grpc/event_engine/memory_allocator.h>
#include <grpc/event_engine/slice.h>
#include <grpc/event_engine/slice_buffer.h>
#include <grpc/slice_buffer.h>
#include <stdlib.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <utility>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "src/core/lib/event_engine/channel_args_endpoint_config.h"
#include "src/core/lib/event_engine/shim.h"
#include "src/core/lib/event_engine/tcp_socket_utils.h"
#include "src/core/lib/resource_quota/memory_quota.h"
#include "src/core/util/crash.h"
#include "src/core/util/notification.h"
#include "src/core/util/time.h"
#include "test/core/test_util/build.h"

// IWYU pragma: no_include <sys/socket.h>

namespace grpc_event_engine {
namespace experimental {

namespace {
constexpr int kMinMessageSize = 1024;
constexpr int kMaxMessageSize = 4096;
}  // namespace

// Returns a random message with bounded length.
std::string GetNextSendMessage() {
  static const char alphanum[] =
      "0123456789"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz";
  static std::random_device rd;
  static std::seed_seq seed{rd()};
  static std::mt19937 gen(seed);
  static std::uniform_real_distribution<> dis(kMinMessageSize, kMaxMessageSize);
  static grpc_core::Mutex g_mu;
  std::string tmp_s;
  int len;
  {
    grpc_core::MutexLock lock(&g_mu);
    len = dis(gen);
  }
  tmp_s.reserve(len);
  for (int i = 0; i < len; ++i) {
    tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
  }
  return tmp_s;
}

void AppendStringToSliceBuffer(SliceBuffer* buf, absl::string_view data) {
  buf->Append(Slice::FromCopiedString(data));
}

std::string ExtractSliceBufferIntoString(SliceBuffer* buf) {
  if (!buf->Length()) {
    return std::string();
  }
  std::string tmp(buf->Length(), '\0');
  char* bytes = const_cast<char*>(tmp.c_str());
  grpc_slice_buffer_move_first_into_buffer(buf->c_slice_buffer(), buf->Length(),
                                           bytes);
  return tmp;
}

absl::Status SendValidatePayload(absl::string_view data,
                                 EventEngine::Endpoint* send_endpoint,
                                 EventEngine::Endpoint* receive_endpoint) {
  CHECK_NE(receive_endpoint, nullptr);
  CHECK_NE(send_endpoint, nullptr);
  int num_bytes_written = data.size();
  grpc_core::Notification read_signal;
  grpc_core::Notification write_signal;
  SliceBuffer read_slice_buf;
  SliceBuffer read_store_buf;
  SliceBuffer write_slice_buf;

  read_slice_buf.Clear();
  write_slice_buf.Clear();
  read_store_buf.Clear();
  // std::cout << "SendValidatePayload ... " << std::endl;
  // fflush(stdout);

  AppendStringToSliceBuffer(&write_slice_buf, data);
  size_t num_bytes_remaining = num_bytes_written;
  std::function<void(absl::Status)> read_cb;
  read_cb = [receive_endpoint, &read_slice_buf, &read_store_buf, &read_cb,
             &read_signal, &num_bytes_remaining](absl::Status status) {
    CHECK_OK(status);
    if (read_slice_buf.Length() == num_bytes_remaining) {
      read_slice_buf.MoveFirstNBytesIntoSliceBuffer(read_slice_buf.Length(),
                                                    read_store_buf);
      read_signal.Notify();
      return;
    }
    num_bytes_remaining -= read_slice_buf.Length();
    read_slice_buf.MoveFirstNBytesIntoSliceBuffer(read_slice_buf.Length(),
                                                  read_store_buf);
    EventEngine::Endpoint::ReadArgs args;
    args.set_read_hint_bytes(num_bytes_remaining);
    if (receive_endpoint->Read(read_cb, &read_slice_buf, std::move(args))) {
      CHECK_NE(read_slice_buf.Length(), 0u);
      read_cb(absl::OkStatus());
    }
  };
  // Start asynchronous reading at the receive_endpoint.
  EventEngine::Endpoint::ReadArgs args;
  args.set_read_hint_bytes(num_bytes_written);
  if (receive_endpoint->Read(read_cb, &read_slice_buf, std::move(args))) {
    read_cb(absl::OkStatus());
  }
  // Start asynchronous writing at the send_endpoint.
  if (send_endpoint->Write(
          [&write_signal](absl::Status status) {
            CHECK_OK(status);
            write_signal.Notify();
          },
          &write_slice_buf, EventEngine::Endpoint::WriteArgs())) {
    write_signal.Notify();
  }
  write_signal.WaitForNotification();
  read_signal.WaitForNotification();
  // Check if data written == data read
  std::string data_read = ExtractSliceBufferIntoString(&read_store_buf);
  if (data != data_read) {
    LOG(INFO) << "Data written = " << data;
    LOG(INFO) << "Data read = " << data_read;
    return absl::CancelledError("Data read != Data written");
  }
  return absl::OkStatus();
}

absl::Status ConnectionManager::BindAndStartListener(
    const std::vector<std::string>& addrs, bool listener_type_oracle) {
  grpc_core::MutexLock lock(&mu_);
  if (addrs.empty()) {
    return absl::InvalidArgumentError(
        "Atleast one bind address must be specified");
  }
  for (auto& addr : addrs) {
    if (listeners_.find(addr) != listeners_.end()) {
      // There is already a listener at this address. Return error.
      return absl::AlreadyExistsError(
          absl::StrCat("Listener already existis for address: ", addr));
    }
  }
  EventEngine::Listener::AcceptCallback accept_cb =
      [this](std::unique_ptr<EventEngine::Endpoint> ep,
             MemoryAllocator /*memory_allocator*/) {
        last_in_progress_connection_.SetServerEndpoint(std::move(ep));
      };

  EventEngine* event_engine = listener_type_oracle ? oracle_event_engine_.get()
                                                   : test_event_engine_.get();

  ChannelArgsEndpointConfig config;
  auto status = event_engine->CreateListener(
      std::move(accept_cb), [](absl::Status status) { CHECK_OK(status); },
      config,
      std::make_unique<grpc_core::MemoryQuota>(
          grpc_core::MakeRefCounted<grpc_core::channelz::ResourceQuotaNode>(
              "foo")));
  if (!status.ok()) {
    return status.status();
  }

  std::shared_ptr<EventEngine::Listener> listener((*status).release());
  for (auto& addr : addrs) {
    auto bind_status = listener->Bind(*URIToResolvedAddress(addr));
    if (!bind_status.ok()) {
      LOG(ERROR) << "Binding listener failed: "
                 << bind_status.status().ToString();
      return bind_status.status();
    }
  }
  CHECK_OK(listener->Start());
  // Insert same listener pointer for all bind addresses after the listener
  // has started successfully.
  for (auto& addr : addrs) {
    listeners_.insert(std::pair(addr, listener));
  }
  return absl::OkStatus();
}

absl::StatusOr<std::tuple<std::unique_ptr<EventEngine::Endpoint>,
                          std::unique_ptr<EventEngine::Endpoint>>>
ConnectionManager::CreateConnection(std::string target_addr,
                                    EventEngine::Duration timeout,
                                    bool client_type_oracle) {
  // Only allow one CreateConnection call to proceed at a time.
  grpc_core::MutexLock lock(&mu_);
  std::string conn_name =
      absl::StrCat("connection-", std::to_string(num_processed_connections_++));
  EventEngine* event_engine = client_type_oracle ? oracle_event_engine_.get()
                                                 : test_event_engine_.get();
  ChannelArgsEndpointConfig config;
  event_engine->Connect(
      [this](absl::StatusOr<std::unique_ptr<EventEngine::Endpoint>> status) {
        if (!status.ok()) {
          LOG(ERROR) << "Connect failed: " << status.status().ToString();
          last_in_progress_connection_.SetClientEndpoint(nullptr);
        } else {
          last_in_progress_connection_.SetClientEndpoint(std::move(*status));
        }
      },
      *URIToResolvedAddress(target_addr), config,
      memory_quota_->CreateMemoryAllocator(conn_name), timeout);

  auto client_endpoint = last_in_progress_connection_.GetClientEndpoint();
  if (client_endpoint != nullptr &&
      listeners_.find(target_addr) != listeners_.end()) {
    // There is a listener for the specified address. Wait until it
    // creates a ServerEndpoint after accepting the connection.
    auto server_endpoint = last_in_progress_connection_.GetServerEndpoint();
    CHECK(server_endpoint != nullptr);
    // Set last_in_progress_connection_ to nullptr
    return std::tuple(std::move(client_endpoint), std::move(server_endpoint));
  }
  return absl::CancelledError("Failed to create connection.");
}

bool IsSaneTimerEnvironment() {
  return grpc_core::IsEventEngineClientEnabled() &&
         grpc_core::IsEventEngineListenerEnabled() &&
         grpc_core::IsEventEngineDnsEnabled() &&
         grpc_core::IsEventEngineDnsNonClientChannelEnabled() &&
         !grpc_event_engine::experimental::
             EventEngineExperimentDisabledForPython();
}

}  // namespace experimental
}  // namespace grpc_event_engine
