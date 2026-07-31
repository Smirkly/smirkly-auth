#include <cstddef>
#include <exception>
#include <string>
#include <vector>

#include <userver/formats/json.hpp>
#include <userver/logging/log.hpp>

#include <auth/infra/workers/email_outbox_processor.hpp>
#include <auth/infra/workers/email_outbox_retry_policy.hpp>
#include <auth/services/ports/notifications/email_verification_sender.hpp>
#include <auth/services/ports/repositories/email_outbox_repository.hpp>
#include <auth/services/ports/repositories/user_repository.hpp>
#include <auth/services/ports/uow/db_transaction.hpp>
#include <auth/services/ports/uow/transaction_manager.hpp>

namespace smirkly::auth::infra::workers {
EmailOutboxProcessor::EmailOutboxProcessor(
    services::ports::TransactionManager& tx_manager,
    services::ports::EmailOutboxRepository& outbox_repo,
    services::ports::EmailVerificationSender& sender,
    userver::engine::TaskProcessor& task_processor,
    EmailOutboxWorkerStaticConfig static_config,
    const EmailOutboxRuntimeConfigProvider& runtime_config_provider)
    : tx_manager_(tx_manager),
      outbox_repo_(outbox_repo),
      sender_(sender),
      task_processor_(task_processor),
      static_config_(static_config),
      runtime_config_provider_(runtime_config_provider) {}

EmailOutboxProcessor::~EmailOutboxProcessor() { Stop(); }

void EmailOutboxProcessor::Start() {
  if (started_ || !static_config_.enabled) return;

  auto settings = userver::utils::PeriodicTask::Settings{
      std::chrono::duration_cast<std::chrono::milliseconds>(
          static_config_.poll_interval)};
  settings.task_processor = &task_processor_;
  task_.Start("email-outbox-processor", settings, [this] { Tick(); });

  started_ = true;
  LOG_INFO() << "EmailOutboxProcessor started";
}

void EmailOutboxProcessor::Stop() noexcept {
  if (!started_) return;
  try {
    task_.Stop();
  } catch (...) {
  }
  started_ = false;
}

void EmailOutboxProcessor::Tick() {
  const auto cfg = runtime_config_provider_.Get();
  if (!cfg.processing_enabled) {
    return;
  }

  const auto now = std::chrono::system_clock::now();

  std::vector<services::ports::EmailOutboxEntry> batch;
  try {
    auto tx = tx_manager_.Begin("email_outbox.claim");
    batch = outbox_repo_.ClaimBatch(*tx, cfg.batch_size, now, cfg.stuck_timeout,
                                    cfg.max_attempts);
    tx->Commit();
  } catch (const std::exception& e) {
    LOG_ERROR() << "EmailOutboxProcessor: claim failed: " << e.what();
    return;
  }

  if (batch.empty()) {
    return;
  }

  for (const auto& job : batch) {
    try {
      if (job.template_name == "verification_code") {
        services::ports::VerificationEmail msg;
        try {
          const auto payload =
              USERVER_NAMESPACE::formats::json::FromString(job.payload_json);
          msg.to_email = job.to_email;
          msg.code = payload["code"].As<std::string>();
          msg.locale = payload["locale"].As<std::string>("ru");
          msg.correlation_id = job.correlation_id;
        } catch (const std::exception&) {
          throw services::ports::EmailDeliveryError(
              "invalid verification email outbox payload", false);
        }
        sender_.SendVerificationEmail(msg);
      } else if (job.template_name == "password_reset") {
        services::ports::PasswordResetEmail msg;
        try {
          const auto payload =
              USERVER_NAMESPACE::formats::json::FromString(job.payload_json);
          msg.to_email = job.to_email;
          msg.token = payload["token"].As<std::string>();
          msg.locale = payload["locale"].As<std::string>("ru");
          msg.correlation_id = job.correlation_id;
        } catch (const std::exception&) {
          throw services::ports::EmailDeliveryError(
              "invalid password reset email outbox payload", false);
        }
        sender_.SendPasswordResetEmail(msg);
      } else {
        throw services::ports::EmailDeliveryError(
            "unknown email outbox template: " + job.template_name, false);
      }

      auto tx = tx_manager_.Begin("email_outbox.mark_sent");
      const bool persisted = outbox_repo_.MarkSent(
          *tx, job.id, job.lease_id, std::chrono::system_clock::now());
      tx->Commit();

      if (persisted) {
        LOG_INFO() << "EmailOutboxProcessor: marked sent job_id=" << job.id;
      } else {
        LOG_WARNING() << "EmailOutboxProcessor: send result ignored after "
                         "lease loss job_id="
                      << job.id;
      }
    } catch (const std::exception& e) {
      const std::size_t attempt = static_cast<std::size_t>(job.attempts);

      try {
        auto tx = tx_manager_.Begin("email_outbox.reschedule");
        const auto failure_now = std::chrono::system_clock::now();

        bool retryable = true;
        if (const auto* delivery_error =
                dynamic_cast<const services::ports::EmailDeliveryError*>(&e)) {
          retryable = delivery_error->IsRetryable();
        }

        bool persisted = false;
        if (ShouldMarkEmailOutboxDead(attempt, cfg.max_attempts, retryable)) {
          persisted = outbox_repo_.MarkDead(*tx, job.id, job.lease_id,
                                            failure_now, std::string{e.what()});
        } else {
          const auto delay = ComputeEmailOutboxRetryDelay(attempt, cfg);
          const auto next_at = failure_now + delay;
          persisted = outbox_repo_.Reschedule(*tx, job.id, job.lease_id,
                                              next_at, std::string{e.what()});
        }

        tx->Commit();

        if (!persisted) {
          LOG_WARNING() << "EmailOutboxProcessor: failure result ignored after "
                           "lease loss job_id="
                        << job.id;
        }
      } catch (const std::exception& db_e) {
        LOG_ERROR()
            << "EmailOutboxProcessor: failed to persist send result for job_id="
            << job.id << ": " << db_e.what()
            << " (original send error: " << e.what() << ")";
      }

      LOG_WARNING() << "EmailOutboxProcessor: send failed job_id=" << job.id
                    << " attempt=" << job.attempts << " error=" << e.what();
    }
  }
}
}  // namespace smirkly::auth::infra::workers
