#include <auth/infra/mapping/dto_mappers.hpp>

#include <userver/utest/utest.hpp>

namespace {

UTEST(DtoMappers, MapsUserVerificationFlags) {
  smirkly::auth::domain::models::User user;
  user.id = "7c03fcb2-88a9-482c-a6f1-a95f86210aaa";
  user.username = "verified_user";
  user.password = "password-hash";
  user.is_email_verified = true;
  user.is_phone_verified = true;

  const auto dto = smirkly::auth::infra::mapping::ToUserDto(user);

  EXPECT_TRUE(dto.is_email_verified);
  EXPECT_TRUE(dto.is_phone_verified);
}

}  // namespace
