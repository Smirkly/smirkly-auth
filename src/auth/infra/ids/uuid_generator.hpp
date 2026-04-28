#pragma once

#include <auth/services/ports/support/id_generator.hpp>

namespace smirkly::auth::infra::ids {
    class UuidGenerator final : public services::ports::support::IdGenerator {
    public:
        [[nodiscard]] std::string Generate() override;
    };
}
