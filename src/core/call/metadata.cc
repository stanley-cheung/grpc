// Copyright 2024 gRPC authors.
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

#include "src/core/call/metadata.h"

#include <grpc/support/port_platform.h>

#include "src/core/call/metadata_batch.h"
#include "src/core/lib/transport/error_utils.h"

namespace grpc_core {

ServerMetadataHandle ServerMetadataFromStatus(const absl::Status& status) {
  auto hdl = Arena::MakePooledForOverwrite<ServerMetadata>();
  grpc_status_code code;
  std::string message;
  grpc_error_get_status(status, Timestamp::InfFuture(), &code, &message,
                        nullptr, nullptr);
  hdl->Set(GrpcStatusMetadata(), code);
  if (!status.ok()) {
    hdl->Set(GrpcMessageMetadata(), Slice::FromCopiedString(message));
  }
  return hdl;
}

absl::Status ServerMetadataToStatus(ServerMetadata& md) {
  const auto grpc_status =
      md.get(GrpcStatusMetadata()).value_or(GRPC_STATUS_UNKNOWN);
  const auto* error_slice = md.get_pointer(GrpcMessageMetadata());
  return grpc_error_set_int(
      absl::Status(static_cast<absl::StatusCode>(grpc_status),
                   error_slice->as_string_view()),
      StatusIntProperty::kRpcStatus, grpc_status);
}

void SetServerMetadataFromStatus(ServerMetadata& md,
                                 const absl::Status& status) {
  grpc_status_code code;
  std::string message;
  grpc_error_get_status(status, Timestamp::InfFuture(), &code, &message,
                        nullptr, nullptr);
  md.Set(GrpcStatusMetadata(), code);
  if (!status.ok()) {
    md.Set(GrpcMessageMetadata(), Slice::FromCopiedString(message));
  }
}

ServerMetadataHandle CancelledServerMetadataFromStatus(
    const absl::Status& status) {
  auto hdl = ServerMetadataFromStatus(status);
  hdl->Set(GrpcCallWasCancelled(), true);
  return hdl;
}

ServerMetadataHandle ServerMetadataFromStatus(grpc_status_code code,
                                              absl::string_view message) {
  auto hdl = Arena::MakePooledForOverwrite<ServerMetadata>();
  hdl->Set(GrpcStatusMetadata(), code);
  hdl->Set(GrpcMessageMetadata(), Slice::FromCopiedString(message));
  return hdl;
}

ServerMetadataHandle CancelledServerMetadataFromStatus(
    grpc_status_code code, absl::string_view message) {
  auto hdl = Arena::MakePooledForOverwrite<ServerMetadata>();
  hdl->Set(GrpcStatusMetadata(), code);
  hdl->Set(GrpcMessageMetadata(), Slice::FromCopiedString(message));
  hdl->Set(GrpcCallWasCancelled(), true);
  return hdl;
}

}  // namespace grpc_core
