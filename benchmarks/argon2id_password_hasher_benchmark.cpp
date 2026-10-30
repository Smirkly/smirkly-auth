#include <string>

#include <benchmark/benchmark.h>

#include <auth/infra/security/password/argon2id_password_hasher.hpp>

namespace smirkly::auth::infra::security {
namespace {

void Argon2idHash(benchmark::State& state) {
  const Argon2idPasswordHasher hasher;
  const std::string password = "CorrectHorseBatteryStaple123!";

  for ([[maybe_unused]] const auto iteration : state) {
    auto hash = hasher.Hash(password);
    benchmark::DoNotOptimize(hash);
  }
}

void Argon2idVerify(benchmark::State& state) {
  const Argon2idPasswordHasher hasher;
  const std::string password = "CorrectHorseBatteryStaple123!";
  const auto hash = hasher.Hash(password);

  for ([[maybe_unused]] const auto iteration : state) {
    auto matches = hasher.Verify(password, hash);
    benchmark::DoNotOptimize(matches);
  }
}

BENCHMARK(Argon2idHash)->Unit(benchmark::kMillisecond)->Iterations(5);
BENCHMARK(Argon2idVerify)->Unit(benchmark::kMillisecond)->Iterations(5);

}  // namespace
}  // namespace smirkly::auth::infra::security
