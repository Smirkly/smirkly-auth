#include <auth/infra/ids/uuid_generator.hpp>

#include <userver/utest/utest.hpp>

namespace {

bool IsLowerHex(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

}  // namespace

UTEST(UuidGenerator, GeneratesCanonicalUuidString) {
  smirkly::auth::infra::ids::UuidGenerator generator;

  const auto id = generator.Generate();

  ASSERT_EQ(id.size(), 36);
  EXPECT_EQ(id[8], '-');
  EXPECT_EQ(id[13], '-');
  EXPECT_EQ(id[18], '-');
  EXPECT_EQ(id[23], '-');

  for (std::size_t i = 0; i < id.size(); ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      continue;
    }

    EXPECT_TRUE(IsLowerHex(id[i])) << id;
  }

  EXPECT_NE(id, generator.Generate());
}
