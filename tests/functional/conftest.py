import pytest

pytest_plugins = [
    "pytest_userver.plugins.core",
    "pytest_userver.plugins.service",
    "pytest_userver.plugins.postgresql",
    "pytest_userver.plugins.redis",
]
