#pragma once

#include <userver/dynamic_config/snapshot.hpp>
#include <userver/formats/json/value.hpp>
#include <userver/formats/parse/to.hpp>

#include <auth/infra/workers/email_outbox_runtime_config.hpp>
#include <auth/services/policies/auth_runtime_policies.hpp>

namespace smirkly::auth::services::policies {

AuthRuntimePolicies Parse(
    const userver::formats::json::Value& value,
    userver::formats::parse::To<AuthRuntimePolicies>);

}  // namespace smirkly::auth::services::policies

namespace smirkly::auth::infra::workers {

EmailOutboxRuntimeConfig Parse(
    const userver::formats::json::Value& value,
    userver::formats::parse::To<EmailOutboxRuntimeConfig>);

}  // namespace smirkly::auth::infra::workers

namespace smirkly::auth::config {

using AuthRuntimeConfig = services::policies::AuthRuntimePolicies;
using EmailOutboxRuntimeConfig = infra::workers::EmailOutboxRuntimeConfig;

extern const userver::dynamic_config::Key<AuthRuntimeConfig>
    kAuthRuntimeConfig;

extern const userver::dynamic_config::Key<EmailOutboxRuntimeConfig>
    kEmailOutboxRuntimeConfig;

}  // namespace smirkly::auth::config
