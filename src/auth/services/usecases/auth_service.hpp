#pragma once

#include <auth/services/ports/repositories/email_outbox_repository.hpp>
#include <auth/services/ports/messaging/email_verification_sender.hpp>
#include <auth/services/ports/security/jwt_token_provider.hpp>
#include <auth/services/ports/security/password_hasher.hpp>
#include <auth/services/ports/repositories/user_repository.hpp>
#include <auth/services/ports/support/verification_code_generator.hpp>
#include <auth/services/contracts/sign_up.hpp>

namespace smirkly::auth::services::usecases {
    class AuthService {
    public:
        AuthService(
            ports::UserRepository &user_repo,
            ports::PasswordHasher &password_hasher,
            ports::EmailVerificationSender &email_sender,
            ports::VerificationCodeGenerator &code_generator,
            ports::EmailOutboxRepository &email_outbox_repo,
            ports::TransactionManager &transaction_manager
            /* dependences */);

        SignUpResult SignUp(const SignUpCommand &cmd);

    private:
        ports::UserRepository &user_repo_;
        ports::PasswordHasher &password_hasher_;
        ports::EmailVerificationSender &email_sender_;
        ports::VerificationCodeGenerator &code_generator_;
        ports::EmailOutboxRepository &email_outbox_repo_;
        ports::TransactionManager &transaction_manager_;
    };
}
