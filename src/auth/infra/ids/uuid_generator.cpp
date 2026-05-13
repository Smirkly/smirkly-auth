#include <auth/infra/ids/uuid_generator.hpp>

#include <userver/utils/boost_uuid4.hpp>

namespace smirkly::auth::infra::ids {

    std::string UuidGenerator::Generate() {
        return USERVER_NAMESPACE::utils::ToString(
            USERVER_NAMESPACE::utils::generators::GenerateBoostUuid()
        );
    }

}
