#include <algorithm>
#include <exception>

#include <userver/formats/json.hpp>
#include <userver/logging/log.hpp>

#include <auth/infra/workers/email_outbox_processor.hpp>
#include <auth/services/ports/notifications/email_verification_sender.hpp>
#include <auth/services/ports/repositories/email_outbox_repository.hpp>
#include <auth/services/ports/repositories/user_repository.hpp>
#include <auth/services/ports/uow/db_transaction.hpp>
#include <auth/services/ports/uow/transaction_manager.hpp>

namespace smirkly::auth::infra::workers {
    EmailOutboxProcessor::EmailOutboxProcessor(services::ports::TransactionManager &tx_manager,
                                               services::ports::EmailOutboxRepository &outbox_repo,
                                               services::ports::EmailVerificationSender &sender,
                                               userver::engine::TaskProcessor &task_processor,
                                               EmailOutboxProcessorConfig cfg)
        : tx_manager_(tx_manager)
          , outbox_repo_(outbox_repo)
          , sender_(sender)
          , task_processor_(task_processor)
          , cfg_(cfg) {
    }

    EmailOutboxProcessor::~EmailOutboxProcessor() {
        Stop();
    }

    void EmailOutboxProcessor::Start() {
        if (started_ || !cfg_.enabled) return;

        auto settings = userver::utils::PeriodicTask::Settings{
            std::chrono::duration_cast<std::chrono::milliseconds>(cfg_.poll_interval)
        };
        task_.Start("email-outbox-processor", settings, [this] { Tick(); });


        started_ = true;
        LOG_INFO() << "EmailOutboxProcessor started";
    }

    void EmailOutboxProcessor::Stop() noexcept {
        if (!started_) return;
        try { task_.Stop(); } catch (...) {
        }
        started_ = false;
    }

    std::chrono::seconds EmailOutboxProcessor::ComputeRetryDelay(std::size_t attempt) const {
        const auto pow2 = (attempt >= 30) ? (1ULL << 30) : (1ULL << attempt);
        const auto delay = std::chrono::seconds(cfg_.retry_base_delay.count() * static_cast<long long>(pow2));
        return std::min(delay, cfg_.retry_max_delay);
    }

    void EmailOutboxProcessor::Tick() {
        const auto now = std::chrono::system_clock::now();

        std::vector<services::ports::EmailOutboxEntry> batch;
        try {
            auto tx = tx_manager_.Begin("email_outbox.claim");
            batch = outbox_repo_.ClaimBatch(
                *tx,
                cfg_.batch_size,
                now,
                cfg_.stuck_timeout,
                cfg_.max_attempts
            );
            tx->Commit();
        } catch (const std::exception &e) {
            LOG_ERROR() << "EmailOutboxProcessor: claim failed: " << e.what();
            return;
        }

        if (batch.empty()) {
            return;
        }

        for (const auto &job: batch) {
            try {
                const auto payload = USERVER_NAMESPACE::formats::json::FromString(job.payload_json);

                services::ports::VerificationEmail msg;
                msg.to_email = job.to_email;
                msg.code = payload["code"].As<std::string>();
                msg.correlation_id = job.correlation_id;
                sender_.SendVerificationEmail(msg);
                LOG_INFO() << "marked sent job_id=" << job.id;

                auto tx = tx_manager_.Begin("email_outbox.mark_sent");
                outbox_repo_.MarkSent(*tx, job.id, now);
                tx->Commit();
            } catch (const std::exception &e) {
                LOG_INFO() << "rescheduled/dead job_id=" << job.id;

                const std::size_t next_attempt = job.attempts + 1;

                try {
                    auto tx = tx_manager_.Begin("email_outbox.reschedule");

                    if (next_attempt >= cfg_.max_attempts) {
                        outbox_repo_.MarkDead(*tx, job.id, now, std::string{e.what()});
                    } else {
                        const auto delay = ComputeRetryDelay(next_attempt);
                        const auto next_at = now + delay;
                        outbox_repo_.Reschedule(*tx, job.id, next_attempt, next_at, std::string{e.what()});
                    }

                    tx->Commit();
                } catch (const std::exception &db_e) {
                    LOG_ERROR() << "EmailOutboxProcessor: failed to persist send result for job_id="
                            << job.id << ": " << db_e.what()
                            << " (original send error: " << e.what() << ")";
                }

                LOG_WARNING() << "EmailOutboxProcessor: send failed job_id=" << job.id
                          << " attempt=" << job.attempts
                          << " error=" << e.what();
            }
        }
    }
}
