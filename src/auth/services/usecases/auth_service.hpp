#pragma once

#include <auth/services/ports/repositories/email_outbox_repository.hpp>
#include <auth/services/ports/security/jwt_token_provider.hpp>
#include <auth/services/ports/security/password_hasher.hpp>
#include <auth/services/ports/repositories/user_repository.hpp>
#include <auth/services/ports/support/verification_code_generator.hpp>
#include <auth/services/ports/uow/transaction_manager.hpp>
#include <auth/services/contracts/sign_up.hpp>
#include <auth/services/contracts/verify_email.hpp>

#include <auth/services/ports/repositories/email_verification_repository.hpp>

namespace smirkly::auth::services::usecases {
    class AuthService {
    public:
        AuthService(
            ports::TransactionManager &transaction_manager,
            ports::UserRepository &user_repo,
            ports::EmailOutboxRepository &email_outbox_repo,
            ports::EmailVerificationRepository &email_verification_repo,
            ports::PasswordHasher &password_hasher,
            ports::VerificationCodeGenerator &code_generator
            /* dependences */);

        SignUpResult SignUp(const SignUpCommand &cmd);

        void VerifyEmail(const VerifyEmailCommand &cmd);

    private:
        ports::UserRepository &user_repo_;
        ports::PasswordHasher &password_hasher_;
        ports::VerificationCodeGenerator &code_generator_;
        ports::EmailOutboxRepository &email_outbox_repo_;
        ports::EmailVerificationRepository &email_verification_repo_;
        ports::TransactionManager &transaction_manager_;
    };
}
