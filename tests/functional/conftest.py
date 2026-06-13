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
def pgsql_local(service_source_dir, tmp_path_factory, pgsql_local_create):
    schema_dir = tmp_path_factory.mktemp("pgsql_schema")
    schema_path = schema_dir / "auth.sql"
    migration_dir = service_source_dir / "migrations"

    schema_sql = "\n\n".join(
        path.read_text()
        for path in sorted(migration_dir.glob("*.up.sql"))
    )
    schema_path.write_text(schema_sql)

    databases = discover.find_schemas(None, [schema_dir])
    return pgsql_local_create(list(databases.values()))
