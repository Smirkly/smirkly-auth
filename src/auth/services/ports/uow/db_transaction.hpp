#pragma once

namespace smirkly::auth::services::ports {
    class DbTransaction {
    public:
        virtual ~DbTransaction() noexcept = default;

        virtual void Commit() = 0;
    };
}
