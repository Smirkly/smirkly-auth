#pragma once

#include <userver/components/component_config.hpp>

#include <auth/infra/http/request_meta_extractor.hpp>

namespace smirkly::auth::config {

infra::http::ClientIpExtractorConfig ParseClientIpExtractorConfig(
    const userver::components::ComponentConfig& cfg);

}  // namespace smirkly::auth::config
