#include <auth/infra/security/verification/random_verification_code_generator.hpp>

#include <array>
#include <stdexcept>
#include <string_view>

#include <openssl/rand.h>

namespace smirkly::auth::infra::security {
    namespace {
        constexpr std::string_view kDigits = "0123456789";
        constexpr unsigned char kMaxUniformDigitByte = 249;
        constexpr std::size_t kRandomBufferSize = 32;
    }

    RandomVerificationCodeGenerator::RandomVerificationCodeGenerator(std::size_t length) : length_(length) {
    }

    std::string RandomVerificationCodeGenerator::Generate() {
        std::string code;
        code.reserve(length_);

        while (code.size() < length_) {
            std::array<unsigned char, kRandomBufferSize> buffer{};
            if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1) {
                throw std::runtime_error("RAND_bytes failed");
            }

            for (const auto byte: buffer) {
                if (byte > kMaxUniformDigitByte) {
                    continue;
                }

                code.push_back(kDigits[byte % kDigits.size()]);
                if (code.size() == length_) {
                    break;
                }
            }
        }

        return code;
    }
}
