#include <auth/infra/security/jwt/jwt_cpp_token_provider.hpp>
#include <auth/services/errors/access_token_errors.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <userver/formats/json.hpp>
#include <userver/utest/utest.hpp>

namespace {
std::filesystem::path ProjectRoot() {
  const auto relative_key_path = std::filesystem::path{
      "third_party/cpp-jwt/examples/rsa_256/jwtRS256.key"};

  auto path = std::filesystem::current_path();
  for (int i = 0; i < 4; ++i) {
    if (std::filesystem::exists(path / relative_key_path)) {
      return path;
    }
    path = path.parent_path();
  }

  throw std::runtime_error(
      "failed to locate project root from test working directory");
}

std::string ReadTextFile(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    throw std::runtime_error("failed to open test key: " + path.string());
  }

  std::ostringstream buffer;
  buffer << input.rdbuf();
  return buffer.str();
}

smirkly::auth::infra::security::jwt::JwtCppTokenProvider MakeProvider() {
  const auto root = ProjectRoot();
  return smirkly::auth::infra::security::jwt::JwtCppTokenProvider({
      .private_key_pem = ReadTextFile(
          root / "third_party/cpp-jwt/examples/rsa_256/jwtRS256.key"),
      .public_key_pem = ReadTextFile(
          root / "third_party/cpp-jwt/examples/rsa_256/jwtRS256.key.pub"),
      .key_id = "test-rs256",
      .issuer = "smirkly-auth-test",
      .audience = "smirkly-api-test",
      .access_ttl = std::chrono::seconds{900},
      .refresh_ttl = std::chrono::seconds{3600},
  });
}

UTEST(JwtCppTokenProvider, GenerateAndParseRefreshTokenRs256) {
  auto provider = MakeProvider();

  const auto tokens =
      provider.GenerateTokens("7c03fcb2-88a9-482c-a6f1-a95f86210aaa",
                              "8296d634-a545-4d34-a48b-557b246e8038",
                              "6ac66b0e-ddc0-4116-b098-8f54d8947f58");

  EXPECT_FALSE(tokens.access_token.empty());
  EXPECT_FALSE(tokens.refresh_token.empty());

  const auto claims = provider.ParseRefreshToken(tokens.refresh_token);
  EXPECT_EQ(claims.user_id, "7c03fcb2-88a9-482c-a6f1-a95f86210aaa");
  EXPECT_EQ(claims.session_id, "8296d634-a545-4d34-a48b-557b246e8038");
  ASSERT_TRUE(claims.token_family_id.has_value());
  EXPECT_EQ(*claims.token_family_id, "6ac66b0e-ddc0-4116-b098-8f54d8947f58");
}

UTEST(JwtCppTokenProvider, GenerateAndParseAccessTokenRs256) {
  auto provider = MakeProvider();

  const auto access_token =
      provider.GenerateAccessToken("7c03fcb2-88a9-482c-a6f1-a95f86210aaa",
                                   "8296d634-a545-4d34-a48b-557b246e8038");

  EXPECT_FALSE(access_token.empty());

  const auto claims = provider.ParseAccessToken(access_token);
  EXPECT_EQ(claims.user_id, "7c03fcb2-88a9-482c-a6f1-a95f86210aaa");
  EXPECT_EQ(claims.session_id, "8296d634-a545-4d34-a48b-557b246e8038");
}

UTEST(JwtCppTokenProvider, RejectsRefreshTokenAsAccessToken) {
  auto provider = MakeProvider();

  const auto refresh_token =
      provider.GenerateRefreshToken("7c03fcb2-88a9-482c-a6f1-a95f86210aaa",
                                    "8296d634-a545-4d34-a48b-557b246e8038",
                                    "6ac66b0e-ddc0-4116-b098-8f54d8947f58");

  EXPECT_THROW(static_cast<void>(provider.ParseAccessToken(refresh_token)),
               smirkly::auth::services::errors::InvalidAccessToken);
}

UTEST(JwtCppTokenProvider, PublishesPublicJwks) {
  auto provider = MakeProvider();

  const auto jwks =
      userver::formats::json::FromString(provider.GetPublicJwksJson());
  ASSERT_TRUE(jwks.HasMember("keys"));
  ASSERT_FALSE(jwks["keys"].IsEmpty());

  const auto key = jwks["keys"][0];
  EXPECT_EQ(key["kty"].As<std::string>(), "RSA");
  EXPECT_EQ(key["use"].As<std::string>(), "sig");
  EXPECT_EQ(key["alg"].As<std::string>(), "RS256");
  EXPECT_EQ(key["kid"].As<std::string>(), "test-rs256");
  EXPECT_FALSE(key["n"].As<std::string>().empty());
  EXPECT_EQ(key["e"].As<std::string>(), "AQAB");
}
}  // namespace
