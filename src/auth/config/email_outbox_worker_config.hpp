#pragma once

#include <string>

#include <userver/components/component_config.hpp>

#include <auth/infra/messaging/smtp/curl_smtp_client.hpp>
#include <auth/infra/workers/email_outbox_processor.hpp>

namespace smirkly::auth::config {

struct EmailOutboxWorkerConfig final {
  bool enabled{true};
  std::string task_processor_name{"email-outbox-task-processor"};
  infra::workers::EmailOutboxWorkerStaticConfig worker;
  infra::messaging::smtp::SmtpConfig smtp;
  std::string from_email;
  std::string from_name;
};

EmailOutboxWorkerConfig ParseEmailOutboxWorkerConfig(
    const userver::components::ComponentConfig& cfg);

}  // namespace smirkly::auth::config
