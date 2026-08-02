import pytest
from testsuite.databases.pgsql import discover

pytest_plugins = [
    "pytest_userver.plugins.core",
    "pytest_userver.plugins.service",
    "pytest_userver.plugins.postgresql",
]

USERVER_CONFIG_HOOKS = [
    "auth_jwt_key_paths",
    "disable_email_outbox_worker",
    "auth_dynamic_config_defaults",
]


@pytest.fixture(scope="session")
def auth_jwt_key_paths(service_source_dir):
    def patch_config(_config_yaml, config_vars):
        key_dir = service_source_dir / "third_party/cpp-jwt/examples/rsa_256"
        config_vars["AUTH_JWT_PRIVATE_KEY_PATH"] = str(
            key_dir / "jwtRS256.key"
        )
        config_vars["AUTH_JWT_PUBLIC_KEY_PATH"] = str(
            key_dir / "jwtRS256.key.pub"
        )

    return patch_config


@pytest.fixture(scope="session")
def disable_email_outbox_worker():
    def patch_config(config_yaml, _config_vars):
        components = config_yaml["components_manager"]["components"]
        components["email-outbox-worker"]["enabled"] = False

    return patch_config


@pytest.fixture(scope="session")
def auth_dynamic_config_defaults():
    def patch_config(config_yaml, _config_vars):
        defaults = config_yaml["components_manager"]["components"]["dynamic-config"].setdefault(
            "defaults",
            {},
        )
        defaults["SMIRKLY_AUTH_RUNTIME_CONFIG"] = {
            "sign_up": {
                "rate_limit": {
                    "window_seconds": 900,
                    "max_attempts_per_ip": 2,
                },
            },
            "sign_in": {
                "require_verified_email": True,
                "rate_limit": {
                    "window_seconds": 900,
                    "max_attempts_per_identifier": 2,
                    "max_attempts_per_user": 2,
                    "max_attempts_per_ip": 1000,
                },
            },
            "session_activity": {
                "update_threshold_seconds": 300,
            },
            "email_verification": {
                "code_ttl_seconds": 900,
                "max_code_attempts": 2,
                "rate_limit_window_seconds": 900,
                "max_attempts_per_email": 2,
                "max_attempts_per_user": 2,
                "max_attempts_per_ip": 1000,
            },
            "password_reset": {
                "token_ttl_seconds": 900,
                "max_token_attempts": 2,
                "rate_limit_window_seconds": 900,
                "max_attempts_per_email": 4,
                "max_attempts_per_user": 4,
                "max_attempts_per_ip": 1000,
            },
        }
        defaults["SMIRKLY_EMAIL_OUTBOX_RUNTIME_CONFIG"] = {
            "processing_enabled": True,
            "batch_size": 20,
            "max_attempts": 3,
            "stuck_timeout_seconds": 300,
            "retry_base_delay_seconds": 2,
            "retry_max_delay_seconds": 600,
        }

    return patch_config


@pytest.fixture(scope="session")
def pgsql_local(service_source_dir, tmp_path_factory, pgsql_local_create):
    schema_dir = tmp_path_factory.mktemp("pgsql_schema")
    schema_path = schema_dir / "auth.sql"
    migration_dir = service_source_dir / "migrations"
    up_migrations = sorted(migration_dir.glob("*.up.sql"))

    schema_sql = "\n\n".join(
        path.read_text()
        for path in up_migrations
    )
    schema_path.write_text(schema_sql)

    databases = discover.find_schemas(None, [schema_dir])
    return pgsql_local_create(list(databases.values()))
