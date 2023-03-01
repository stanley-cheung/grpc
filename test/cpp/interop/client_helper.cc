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

#include "test/cpp/interop/client_helper.h"

#include <fstream>
#include <memory>
#include <sstream>

#include "absl/flags/declare.h"
#include "absl/flags/flag.h"
#include "absl/strings/match.h"

#include <grpc/grpc.h>
#include <grpc/support/alloc.h>
#include <grpc/support/log.h>
#include <grpcpp/channel.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>

#include "src/core/lib/gprpp/crash.h"
#include "src/core/lib/slice/b64.h"
#include "src/cpp/client/secure_credentials.h"
#include "test/core/security/oauth2_utils.h"
#include "test/cpp/util/create_test_channel.h"
#include "test/cpp/util/test_credentials_provider.h"

ABSL_FLAG(bool, use_alts, false,
          "Whether to use alts. Enable alts will disable tls.");
ABSL_FLAG(bool, use_tls, false, "Whether to use tls.");
ABSL_FLAG(std::string, custom_credentials_type, "",
          "User provided credentials type.");
ABSL_FLAG(bool, use_test_ca, false, "False to use SSL roots for google");
ABSL_FLAG(int32_t, server_port, 0, "Server port.");
ABSL_FLAG(std::string, server_host, "localhost", "Server host to connect to");
ABSL_FLAG(std::string, server_host_override, "",
          "Override the server host which is sent in HTTP header");
ABSL_FLAG(
    std::string, test_case, "large_unary",
    "Configure different test cases. Valid options are:\n\n"
    "all : all test cases;\n"

    // TODO(veblush): Replace the help message with the following full message
    // once Abseil fixes the flag-help compiler error on Windows. (b/171659833)
    //
    //"cancel_after_begin : cancel stream after starting it;\n"
    //"cancel_after_first_response: cancel on first response;\n"
    //"channel_soak: sends 'soak_iterations' rpcs, rebuilds channel each
    // time;\n" "client_compressed_streaming : compressed request streaming with
    //" "client_compressed_unary : single compressed request;\n"
    //"client_streaming : request streaming with single response;\n"
    //"compute_engine_creds: large_unary with compute engine auth;\n"
    //"custom_metadata: server will echo custom metadata;\n"
    //"empty_stream : bi-di stream with no request/response;\n"
    //"empty_unary : empty (zero bytes) request and response;\n"
    //"google_default_credentials: large unary using GDC;\n"
    //"half_duplex : half-duplex streaming;\n"
    //"jwt_token_creds: large_unary with JWT token auth;\n"
    //"large_unary : single request and (large) response;\n"
    //"long_lived_channel: sends large_unary rpcs over a long-lived channel;\n"
    //"oauth2_auth_token: raw oauth2 access token auth;\n"
    //"per_rpc_creds: raw oauth2 access token on a single rpc;\n"
    //"ping_pong : full-duplex streaming;\n"
    //"response streaming;\n"
    //"rpc_soak: 'sends soak_iterations' large_unary rpcs;\n"
    //"server_compressed_streaming : single request with compressed "
    //"server_compressed_unary : single compressed response;\n"
    //"server_streaming : single request with response streaming;\n"
    //"slow_consumer : single request with response streaming with "
    //"slow client consumer;\n"
    //"special_status_message: verify Unicode and whitespace in status
    // message;\n" "status_code_and_message: verify status code & message;\n"
    //"timeout_on_sleeping_server: deadline exceeds on stream;\n"
    //"unimplemented_method: client calls an unimplemented method;\n"
    //"unimplemented_service: client calls an unimplemented service;\n"
    //
);
ABSL_FLAG(int32_t, num_times, 1, "Number of times to run the test case");
ABSL_FLAG(std::string, default_service_account, "",
          "Email of GCE default service account");
ABSL_FLAG(std::string, service_account_key_file, "",
          "Path to service account json key file.");
ABSL_FLAG(std::string, oauth_scope, "", "Scope for OAuth tokens.");
ABSL_FLAG(bool, do_not_abort_on_transient_failures, false,
          "If set to 'true', abort() is not called in case of transient "
          "failures (i.e failures that are temporary and will likely go away "
          "on retrying; like a temporary connection failure) and an error "
          "message is printed instead. Note that this flag just controls "
          "whether abort() is called or not. It does not control whether the "
          "test is retried in case of transient failures (and currently the "
          "interop tests are not retried even if this flag is set to true)");
ABSL_FLAG(int32_t, soak_iterations, 1000,
          "The number of iterations to use for the two soak tests; rpc_soak "
          "and channel_soak.");
ABSL_FLAG(int32_t, soak_max_failures, 0,
          "The number of iterations in soak tests that are allowed to fail "
          "(either due to non-OK status code or exceeding the "
          "per-iteration max acceptable latency).");
ABSL_FLAG(int32_t, soak_per_iteration_max_acceptable_latency_ms, 0,
          "The number of milliseconds a single iteration in the two soak "
          "tests (rpc_soak and channel_soak) should take.");
ABSL_FLAG(int32_t, soak_overall_timeout_seconds, 0,
          "The overall number of seconds after which a soak test should "
          "stop and fail, if the desired number of iterations have not yet "
          "completed.");
ABSL_FLAG(int32_t, soak_min_time_ms_between_rpcs, 0,
          "The minimum time in milliseconds between consecutive RPCs in a "
          "soak test (rpc_soak or channel_soak), useful for limiting QPS");
ABSL_FLAG(int32_t, iteration_interval, 10,
          "The interval in seconds between rpcs. This is used by "
          "long_connection test");
ABSL_FLAG(std::string, additional_metadata, "",
          "Additional metadata to send in each request, as a "
          "semicolon-separated list of key:value pairs.");
ABSL_FLAG(
    bool, log_metadata_and_status, false,
    "If set to 'true', will print received initial and trailing metadata, "
    "grpc-status and error message to the console, in a stable format.");

namespace grpc {
namespace testing {

std::string GetServiceAccountJsonKey() {
  static std::string json_key;
  if (json_key.empty()) {
    std::ifstream json_key_file(absl::GetFlag(FLAGS_service_account_key_file));
    std::stringstream key_stream;
    key_stream << json_key_file.rdbuf();
    json_key = key_stream.str();
  }
  return json_key;
}

std::string GetOauth2AccessToken() {
  std::shared_ptr<CallCredentials> creds = GoogleComputeEngineCredentials();
  SecureCallCredentials* secure_creds =
      dynamic_cast<SecureCallCredentials*>(creds.get());
  GPR_ASSERT(secure_creds != nullptr);
  grpc_call_credentials* c_creds = secure_creds->GetRawCreds();
  char* token = grpc_test_fetch_oauth2_token_with_credentials(c_creds);
  GPR_ASSERT(token != nullptr);
  gpr_log(GPR_INFO, "Get raw oauth2 access token: %s", token);
  std::string access_token(token + sizeof("Bearer ") - 1);
  gpr_free(token);
  return access_token;
}

void UpdateActions(
    std::unordered_map<std::string, std::function<bool()>>* /*actions*/) {}

std::shared_ptr<Channel> CreateChannelForTestCase(
    const std::string& test_case,
    std::vector<
        std::unique_ptr<experimental::ClientInterceptorFactoryInterface>>
        interceptor_creators) {
  std::string server_uri = absl::GetFlag(FLAGS_server_host);
  int32_t port = absl::GetFlag(FLAGS_server_port);
  if (port != 0) {
    absl::StrAppend(&server_uri, ":", std::to_string(port));
  }
  std::shared_ptr<CallCredentials> creds;
  if (test_case == "compute_engine_creds") {
    creds = absl::GetFlag(FLAGS_custom_credentials_type) ==
                    "google_default_credentials"
                ? nullptr
                : GoogleComputeEngineCredentials();
  } else if (test_case == "jwt_token_creds") {
    std::string json_key = GetServiceAccountJsonKey();
    std::chrono::seconds token_lifetime = std::chrono::hours(1);
    creds = absl::GetFlag(FLAGS_custom_credentials_type) ==
                    "google_default_credentials"
                ? nullptr
                : ServiceAccountJWTAccessCredentials(json_key,
                                                     token_lifetime.count());
  } else if (test_case == "oauth2_auth_token") {
    creds = absl::GetFlag(FLAGS_custom_credentials_type) ==
                    "google_default_credentials"
                ? nullptr
                : AccessTokenCredentials(GetOauth2AccessToken());
  } else if (test_case == "pick_first_unary") {
    ChannelArguments channel_args;
    // allow the LB policy to be configured with service config
    channel_args.SetInt(GRPC_ARG_SERVICE_CONFIG_DISABLE_RESOLUTION, 0);
    return CreateTestChannel(
        server_uri, absl::GetFlag(FLAGS_custom_credentials_type),
        absl::GetFlag(FLAGS_server_host_override),
        !absl::GetFlag(FLAGS_use_test_ca), creds, channel_args);
  }
  if (absl::GetFlag(FLAGS_custom_credentials_type).empty()) {
    transport_security security_type =
        absl::GetFlag(FLAGS_use_alts)
            ? ALTS
            : (absl::GetFlag(FLAGS_use_tls) ? TLS : INSECURE);
    return CreateTestChannel(server_uri,
                             absl::GetFlag(FLAGS_server_host_override),
                             security_type, !absl::GetFlag(FLAGS_use_test_ca),
                             creds, std::move(interceptor_creators));
  } else {
    if (interceptor_creators.empty()) {
      return CreateTestChannel(
          server_uri, absl::GetFlag(FLAGS_custom_credentials_type), creds);
    } else {
      return CreateTestChannel(server_uri,
                               absl::GetFlag(FLAGS_custom_credentials_type),
                               creds, std::move(interceptor_creators));
    }
  }
}

static void log_metadata_entry(const std::string& prefix,
                               const grpc::string_ref& key,
                               const grpc::string_ref& value) {
  auto key_str = std::string(key.begin(), key.end());
  auto value_str = std::string(value.begin(), value.end());
  if (absl::EndsWith(key_str, "-bin")) {
    auto converted =
        grpc_base64_encode(value_str.c_str(), value_str.length(), 0, 0);
    value_str = std::string(converted);
    gpr_free(converted);
  }
  gpr_log(GPR_ERROR, "%s %s: %s", prefix.c_str(), key_str.c_str(),
          value_str.c_str());
}

void MetadataAndStatusLoggerInterceptor::Intercept(
    experimental::InterceptorBatchMethods* methods) {
  if (methods->QueryInterceptionHookPoint(
          experimental::InterceptionHookPoints::POST_RECV_INITIAL_METADATA)) {
    auto initial_metadata = methods->GetRecvInitialMetadata();

    for (const auto& entry : *initial_metadata) {
      log_metadata_entry("GRPC_INITIAL_METADATA", entry.first, entry.second);
    }
  }

  if (methods->QueryInterceptionHookPoint(
          experimental::InterceptionHookPoints::POST_RECV_STATUS)) {
    auto trailing_metadata = methods->GetRecvTrailingMetadata();
    for (const auto& entry : *trailing_metadata) {
      log_metadata_entry("GRPC_TRAILING_METADATA", entry.first, entry.second);
    }

    auto status = methods->GetRecvStatus();
    gpr_log(GPR_ERROR, "GRPC_STATUS %d", status->error_code());
    gpr_log(GPR_ERROR, "GRPC_ERROR_MESSAGE %s",
            status->error_message().c_str());
  }

  methods->Proceed();
}

}  // namespace testing
}  // namespace grpc
