#include <auth/config/email_outbox_worker_config.hpp>

#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

namespace smirkly::auth::config {
namespace {

infra::messaging::smtp::TlsMode ParseTlsMode(std::string_view value) {
  if (value == "none") return infra::messaging::smtp::TlsMode::kNone;
  if (value == "starttls") return infra::messaging::smtp::TlsMode::kStartTls;
  if (value == "tls") return infra::messaging::smtp::TlsMode::kTls;
  throw std::runtime_error("invalid smtp.tls_mode: " + std::string{value});
}

}  // namespace

EmailOutboxWorkerConfig ParseEmailOutboxWorkerConfig(
    const userver::components::ComponentConfig& cfg) {
  const auto& smtp = cfg["smtp"];

  EmailOutboxWorkerConfig out;
  out.enabled = cfg["enabled"].As<bool>(true);
  out.task_processor_name =
      cfg["task_processor"].As<std::string>("email-outbox-task-processor");
  out.worker.enabled = out.enabled;
  out.worker.poll_interval =
      std::chrono::milliseconds{cfg["poll_interval_ms"].As<int>(1000)};

  out.smtp.host = smtp["host"].As<std::string>();
  out.smtp.port = static_cast<std::uint16_t>(smtp["port"].As<int>(587));
  out.smtp.tls_mode =
      ParseTlsMode(smtp["tls_mode"].As<std::string>("starttls"));
  out.smtp.username = smtp["username"].As<std::string>();
  out.smtp.app_password = smtp["app_password"].As<std::string>();
  out.smtp.connect_timeout_ms =
      std::chrono::milliseconds{smtp["connect_timeout_ms"].As<int>(20000)};
  out.smtp.timeout_ms =
      std::chrono::milliseconds{smtp["timeout_ms"].As<int>(30000)};
  out.from_email = smtp["from_email"].As<std::string>();
  out.from_name = smtp["from_name"].As<std::string>("");

  return out;
}

}  // namespace smirkly::auth::config
