#include <auth/infra/security/password/task_processor_password_hasher.hpp>

#include <stdexcept>
#include <utility>

#include <userver/engine/task/current_task.hpp>
#include <userver/utils/async.hpp>

namespace smirkly::auth::infra::security {

TaskProcessorPasswordHasher::TaskProcessorPasswordHasher(
    userver::engine::TaskProcessor& task_processor,
    std::unique_ptr<services::ports::PasswordHasher> delegate)
    : task_processor_(task_processor), delegate_(std::move(delegate)) {
  if (!delegate_) {
    throw std::invalid_argument("password hasher delegate must not be null");
  }
}

std::string TaskProcessorPasswordHasher::Hash(std::string_view password) const {
  if (&userver::engine::current_task::GetTaskProcessor() == &task_processor_) {
    return delegate_->Hash(password);
  }

  return userver::utils::Async(task_processor_, "password_hash",
                               [this, password = std::string{password}] {
                                 return delegate_->Hash(password);
                               })
      .Get();
}

bool TaskProcessorPasswordHasher::Verify(std::string_view password,
                                         std::string_view encoded_hash) const {
  if (&userver::engine::current_task::GetTaskProcessor() == &task_processor_) {
    return delegate_->Verify(password, encoded_hash);
  }

  return userver::utils::Async(task_processor_, "password_verify",
                               [this, password = std::string{password},
                                encoded_hash = std::string{encoded_hash}] {
                                 return delegate_->Verify(password,
                                                          encoded_hash);
                               })
      .Get();
}

}  // namespace smirkly::auth::infra::security
