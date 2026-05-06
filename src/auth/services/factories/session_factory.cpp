#include <auth/services/factories/session_factory.hpp>

#include <utility>

namespace smirkly::auth::services::factories {
    ports::NewSessionData SessionFactory::CreateForSignIn(
        std::string session_id,
        std::string user_id,
        std::string device_id,
        std::string refresh_token_hash,
        std::string token_family_id,
        const contracts::RequestMeta &meta
    ) {
        return ports::NewSessionData{
            .id = std::move(session_id),
            .user_id = std::move(user_id),
            .device_id = std::move(device_id),
            .refresh_token_hash = std::move(refresh_token_hash),
            .ip = meta.ip,
            .user_agent = meta.user_agent,
            .expires_at = std::chrono::system_clock::now() + std::chrono::hours{24 * 30},
            .token_family_id = std::move(token_family_id),
            .replaced_by_session_id = std::nullopt,
        };
    }

    ports::NewSessionData SessionFactory::CreateForRefreshRotation(
        std::string session_id,
        const domain::models::Session &previous_session,
        std::string refresh_token_hash,
        const contracts::RequestMeta &meta
    ) {
        return ports::NewSessionData{
            .id = std::move(session_id),
            .user_id = previous_session.user_id,
            .device_id = previous_session.device_id,
            .refresh_token_hash = std::move(refresh_token_hash),
            .ip = meta.ip ? meta.ip : previous_session.ip,
            .user_agent = meta.user_agent ? meta.user_agent : previous_session.user_agent,
            .expires_at = std::chrono::system_clock::now() + std::chrono::hours{24 * 30},
            .token_family_id = previous_session.token_family_id,
            .replaced_by_session_id = std::nullopt,
        };
    }
}
