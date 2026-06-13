#pragma once

namespace smirkly::auth::services::ports {
    enum class ReadConsistency {
        kEventual,
        kStrong,
    };
}
