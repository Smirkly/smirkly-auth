#pragma once

#include <auth/services/types/sign_up.hpp>
#include <auth/services/ports/email_verification_sender.hpp>
#include <auth/services/ports/jwt_token_provider.hpp>
#include <auth/services/ports/password_hasher.hpp>
#include <auth/services/ports/user_repository.hpp>
#include <auth/services/ports/verification_code_generator.hpp>

namespace smirkly::auth::services::services {
    class AuthService {
    public:
        AuthService(
            ports::UserRepository &user_repo,
            ports::PasswordHasher &password_hasher,
            ports::EmailVerificationSender &email_sender,
            ports::VerificationCodeGenerator &code_generator
            /* dependences */);

        SignUpResult SignUp(const SignUpCommand &cmd);

    private:
        ports::UserRepository &user_repo_;
        ports::PasswordHasher &password_hasher_;
        ports::EmailVerificationSender &email_sender_;
        ports::VerificationCodeGenerator &code_generator_;
    };
}
