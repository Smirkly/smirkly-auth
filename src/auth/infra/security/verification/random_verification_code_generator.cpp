#include <auth/infra/security/verification/random_verification_code_generator.hpp>

#include <random>
#include <string_view>

namespace smirkly::auth::infra::security {
    namespace {
        std::mt19937_64 &GetRng() {
            static thread_local std::mt19937_64 rng(std::random_device{}());
            return rng;
        }

        constexpr std::string_view kDigits = "0123456789";
    }

    RandomVerificationCodeGenerator::RandomVerificationCodeGenerator(std::size_t lenght) : lenght_(lenght) {
    }

    std::string RandomVerificationCodeGenerator::Generate() {
        auto &rng = GetRng();
        std::uniform_int_distribution<std::size_t> distribution(0, kDigits.size() - 1);

        std::string code;
        code.reserve(lenght_);

        for (std::size_t i{0}; i < lenght_; ++i) {
            code.push_back(kDigits[distribution(rng)]);
        }

        return code;
    }
}
