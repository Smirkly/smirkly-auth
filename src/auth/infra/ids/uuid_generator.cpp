#include <auth/infra/ids/uuid_generator.hpp>

#include <userver/utils/uuid4.hpp>

namespace smirkly::auth::infra::ids {

    std::string UuidGenerator::Generate() {
        return USERVER_NAMESPACE::utils::generators::GenerateUuid();
    }

}