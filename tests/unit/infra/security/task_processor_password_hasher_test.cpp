#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <userver/engine/task/current_task.hpp>
#include <userver/utest/utest.hpp>

#include <auth/infra/security/password/task_processor_password_hasher.hpp>

namespace smirkly::auth::infra::security {
namespace {

class RecordingPasswordHasher final : public services::ports::PasswordHasher {
 public:
  std::string Hash(std::string_view password) const override {
    last_password = password;
    return "encoded:" + std::string{password};
  }

  bool Verify(std::string_view password,
              std::string_view encoded_hash) const override {
    last_password = password;
    last_hash = encoded_hash;
    return encoded_hash == "encoded:" + std::string{password};
  }

  mutable std::string last_password;
  mutable std::string last_hash;
};

UTEST(TaskProcessorPasswordHasher, DelegatesHashAndVerify) {
  auto delegate = std::make_unique<RecordingPasswordHasher>();
  auto* delegate_ptr = delegate.get();
  TaskProcessorPasswordHasher hasher{
      userver::engine::current_task::GetTaskProcessor(), std::move(delegate)};

  const auto encoded = hasher.Hash("StrongPass123!");

  EXPECT_EQ(encoded, "encoded:StrongPass123!");
  EXPECT_EQ(delegate_ptr->last_password, "StrongPass123!");
  EXPECT_TRUE(hasher.Verify("StrongPass123!", encoded));
  EXPECT_EQ(delegate_ptr->last_hash, encoded);
}

UTEST(TaskProcessorPasswordHasher, RejectsNullDelegate) {
  EXPECT_THROW(static_cast<void>(TaskProcessorPasswordHasher{
                   userver::engine::current_task::GetTaskProcessor(), nullptr}),
               std::invalid_argument);
}

}  // namespace
}  // namespace smirkly::auth::infra::security
