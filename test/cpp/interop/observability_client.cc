//
//
// Copyright 2015 gRPC authors.
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

#include <memory>
#include <unordered_map>

#include "absl/flags/flag.h"

#include <grpc/grpc.h>
#include <grpc/support/alloc.h>
#include <grpc/support/log.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/ext/gcp_observability.h>

#include "src/core/lib/gpr/string.h"
#include "src/core/lib/gprpp/crash.h"
#include "test/core/util/test_config.h"
#include "test/cpp/interop/client_helper.h"
#include "test/cpp/interop/interop_client.h"
#include "test/cpp/util/test_config.h"

ABSL_FLAG(bool, enable_observability, false,
          "Whether to enable GCP Observability");

using grpc::testing::CreateChannelForTestCase;
using grpc::testing::GetServiceAccountJsonKey;
using grpc::testing::UpdateActions;

namespace {

// Parse the contents of FLAGS_additional_metadata into a map. Allow
// alphanumeric characters and dashes in keys, and any character but semicolons
// in values. Convert keys to lowercase. On failure, log an error and return
// false.
bool ParseAdditionalMetadataFlag(
    const std::string& flag,
    std::multimap<std::string, std::string>* additional_metadata) {
  size_t start_pos = 0;
  while (start_pos < flag.length()) {
    size_t colon_pos = flag.find(':', start_pos);
    if (colon_pos == std::string::npos) {
      gpr_log(GPR_ERROR,
              "Couldn't parse metadata flag: extra characters at end of flag");
      return false;
    }
    size_t semicolon_pos = flag.find(';', colon_pos);

    std::string key = flag.substr(start_pos, colon_pos - start_pos);
    std::string value =
        flag.substr(colon_pos + 1, semicolon_pos - colon_pos - 1);

    constexpr char alphanum_and_hyphen[] =
        "-0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (key.find_first_not_of(alphanum_and_hyphen) != std::string::npos) {
      gpr_log(GPR_ERROR,
              "Couldn't parse metadata flag: key contains characters other "
              "than alphanumeric and hyphens: %s",
              key.c_str());
      return false;
    }

    // Convert to lowercase.
    for (char& c : key) {
      if (c >= 'A' && c <= 'Z') {
        c += ('a' - 'A');
      }
    }

    gpr_log(GPR_INFO, "Adding additional metadata with key %s and value %s",
            key.c_str(), value.c_str());
    additional_metadata->insert({key, value});

    if (semicolon_pos == std::string::npos) {
      break;
    } else {
      start_pos = semicolon_pos + 1;
    }
  }

  return true;
}

}  // namespace

int main(int argc, char** argv) {
  grpc::testing::TestEnvironment env(&argc, argv);
  grpc::testing::InitTest(&argc, &argv, true);
  gpr_log(GPR_INFO, "Testing these cases: %s",
          absl::GetFlag(FLAGS_test_case).c_str());
  int ret = 0;

  if (absl::GetFlag(FLAGS_enable_observability)) {
    auto status = grpc::experimental::GcpObservabilityInit();
    gpr_log(GPR_DEBUG, "GcpObservabilityInit() status_code: %d", status.code());
    if (!status.ok()) {
      return 1;
    }
  }

  grpc::testing::ChannelCreationFunc channel_creation_func;
  std::string test_case = absl::GetFlag(FLAGS_test_case);
  if (absl::GetFlag(FLAGS_additional_metadata).empty()) {
    channel_creation_func = [test_case]() {
      std::vector<std::unique_ptr<
          grpc::experimental::ClientInterceptorFactoryInterface>>
          factories;
      if (absl::GetFlag(FLAGS_log_metadata_and_status)) {
        factories.emplace_back(
            new grpc::testing::MetadataAndStatusLoggerInterceptorFactory());
      }
      return CreateChannelForTestCase(test_case, std::move(factories));
    };
  } else {
    std::multimap<std::string, std::string> additional_metadata;
    if (!ParseAdditionalMetadataFlag(absl::GetFlag(FLAGS_additional_metadata),
                                     &additional_metadata)) {
      return 1;
    }

    channel_creation_func = [test_case, additional_metadata]() {
      std::vector<std::unique_ptr<
          grpc::experimental::ClientInterceptorFactoryInterface>>
          factories;
      factories.emplace_back(
          new grpc::testing::AdditionalMetadataInterceptorFactory(
              additional_metadata));
      if (absl::GetFlag(FLAGS_log_metadata_and_status)) {
        factories.emplace_back(
            new grpc::testing::MetadataAndStatusLoggerInterceptorFactory());
      }
      return CreateChannelForTestCase(test_case, std::move(factories));
    };
  }

  grpc::testing::InteropClient client(
      channel_creation_func, true,
      absl::GetFlag(FLAGS_do_not_abort_on_transient_failures));

  std::unordered_map<std::string, std::function<bool()>> actions;
  actions["empty_unary"] =
      std::bind(&grpc::testing::InteropClient::DoEmpty, &client);
  actions["large_unary"] =
      std::bind(&grpc::testing::InteropClient::DoLargeUnary, &client);
  actions["server_compressed_unary"] = std::bind(
      &grpc::testing::InteropClient::DoServerCompressedUnary, &client);
  actions["client_compressed_unary"] = std::bind(
      &grpc::testing::InteropClient::DoClientCompressedUnary, &client);
  actions["client_streaming"] =
      std::bind(&grpc::testing::InteropClient::DoRequestStreaming, &client);
  actions["server_streaming"] =
      std::bind(&grpc::testing::InteropClient::DoResponseStreaming, &client);
  actions["server_compressed_streaming"] = std::bind(
      &grpc::testing::InteropClient::DoServerCompressedStreaming, &client);
  actions["client_compressed_streaming"] = std::bind(
      &grpc::testing::InteropClient::DoClientCompressedStreaming, &client);
  actions["slow_consumer"] = std::bind(
      &grpc::testing::InteropClient::DoResponseStreamingWithSlowConsumer,
      &client);
  actions["half_duplex"] =
      std::bind(&grpc::testing::InteropClient::DoHalfDuplex, &client);
  actions["ping_pong"] =
      std::bind(&grpc::testing::InteropClient::DoPingPong, &client);
  actions["cancel_after_begin"] =
      std::bind(&grpc::testing::InteropClient::DoCancelAfterBegin, &client);
  actions["cancel_after_first_response"] = std::bind(
      &grpc::testing::InteropClient::DoCancelAfterFirstResponse, &client);
  actions["timeout_on_sleeping_server"] = std::bind(
      &grpc::testing::InteropClient::DoTimeoutOnSleepingServer, &client);
  actions["empty_stream"] =
      std::bind(&grpc::testing::InteropClient::DoEmptyStream, &client);
  actions["pick_first_unary"] =
      std::bind(&grpc::testing::InteropClient::DoPickFirstUnary, &client);
  if (absl::GetFlag(FLAGS_use_tls)) {
    actions["compute_engine_creds"] =
        std::bind(&grpc::testing::InteropClient::DoComputeEngineCreds, &client,
                  absl::GetFlag(FLAGS_default_service_account),
                  absl::GetFlag(FLAGS_oauth_scope));
    actions["jwt_token_creds"] =
        std::bind(&grpc::testing::InteropClient::DoJwtTokenCreds, &client,
                  GetServiceAccountJsonKey());
    actions["oauth2_auth_token"] =
        std::bind(&grpc::testing::InteropClient::DoOauth2AuthToken, &client,
                  absl::GetFlag(FLAGS_default_service_account),
                  absl::GetFlag(FLAGS_oauth_scope));
    actions["per_rpc_creds"] =
        std::bind(&grpc::testing::InteropClient::DoPerRpcCreds, &client,
                  GetServiceAccountJsonKey());
  }
  if (absl::GetFlag(FLAGS_custom_credentials_type) ==
      "google_default_credentials") {
    actions["google_default_credentials"] =
        std::bind(&grpc::testing::InteropClient::DoGoogleDefaultCredentials,
                  &client, absl::GetFlag(FLAGS_default_service_account));
  }
  actions["status_code_and_message"] =
      std::bind(&grpc::testing::InteropClient::DoStatusWithMessage, &client);
  actions["special_status_message"] =
      std::bind(&grpc::testing::InteropClient::DoSpecialStatusMessage, &client);
  actions["custom_metadata"] =
      std::bind(&grpc::testing::InteropClient::DoCustomMetadata, &client);
  actions["unimplemented_method"] =
      std::bind(&grpc::testing::InteropClient::DoUnimplementedMethod, &client);
  actions["unimplemented_service"] =
      std::bind(&grpc::testing::InteropClient::DoUnimplementedService, &client);
  actions["channel_soak"] = std::bind(
      &grpc::testing::InteropClient::DoChannelSoakTest, &client,
      absl::GetFlag(FLAGS_server_host), absl::GetFlag(FLAGS_soak_iterations),
      absl::GetFlag(FLAGS_soak_max_failures),
      absl::GetFlag(FLAGS_soak_per_iteration_max_acceptable_latency_ms),
      absl::GetFlag(FLAGS_soak_min_time_ms_between_rpcs),
      absl::GetFlag(FLAGS_soak_overall_timeout_seconds));
  actions["rpc_soak"] = std::bind(
      &grpc::testing::InteropClient::DoRpcSoakTest, &client,
      absl::GetFlag(FLAGS_server_host), absl::GetFlag(FLAGS_soak_iterations),
      absl::GetFlag(FLAGS_soak_max_failures),
      absl::GetFlag(FLAGS_soak_per_iteration_max_acceptable_latency_ms),
      absl::GetFlag(FLAGS_soak_min_time_ms_between_rpcs),
      absl::GetFlag(FLAGS_soak_overall_timeout_seconds));
  actions["long_lived_channel"] =
      std::bind(&grpc::testing::InteropClient::DoLongLivedChannelTest, &client,
                absl::GetFlag(FLAGS_soak_iterations),
                absl::GetFlag(FLAGS_iteration_interval));

  UpdateActions(&actions);

  if (absl::GetFlag(FLAGS_test_case) == "all") {
    for (const auto& action : actions) {
      for (int i = 0; i < absl::GetFlag(FLAGS_num_times); i++) {
        action.second();
      }
    }
  } else if (actions.find(absl::GetFlag(FLAGS_test_case)) != actions.end()) {
    for (int i = 0; i < absl::GetFlag(FLAGS_num_times); i++) {
      actions.find(absl::GetFlag(FLAGS_test_case))->second();
    }
  } else {
    std::string test_cases;
    for (const auto& action : actions) {
      if (!test_cases.empty()) test_cases += "\n";
      test_cases += action.first;
    }
    gpr_log(GPR_ERROR, "Unsupported test case %s. Valid options are\n%s",
            absl::GetFlag(FLAGS_test_case).c_str(), test_cases.c_str());
    ret = 1;
  }

  if (absl::GetFlag(FLAGS_enable_observability)) {
    grpc::experimental::GcpObservabilityClose();
    // TODO(stanleycheung): remove this once the observability exporter plugin
    //                      is able to gracefully flush observability data to
    //                      cloud at shutdown
    const int observability_exporter_sleep_seconds = 65;
    gpr_log(GPR_DEBUG, "Sleeping %ds before shutdown.",
            observability_exporter_sleep_seconds);
    gpr_sleep_until(
        gpr_time_add(gpr_now(GPR_CLOCK_REALTIME),
                     gpr_time_from_seconds(observability_exporter_sleep_seconds,
                                           GPR_TIMESPAN)));
  }

  return ret;
}
