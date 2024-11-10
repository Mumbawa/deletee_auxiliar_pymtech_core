import json
import logging
import os
import re
from pymtech_core.settings import (
    AWSSettings,
    BaseAWSSecretsSettings,
    get_settings,
    init_secrets_client,
    get_logger,
    SecretsManagerClient,
)
import pytest


@pytest.fixture()
def setup_env():
    # Create env file .env.local_unit_test
    content = """
host=host_local_unit_test
port=5432
user=user_local_unit_test
password=password_local_unit_test
database=database_local_unit_test
"""
    with open(".env.local_unit_test", "w") as f:
        f.write(content)
    yield
    os.remove(".env.local_unit_test")


def test_settings(setup_env):
    # Example of a settings class
    class DBSettings(BaseAWSSecretsSettings):
        _secret_attribute_: str = "DB_SECRET_PATH"
        host: str
        port: int
        user: str
        password: str
        database: str

    os.environ["EXECUTION_TYPE"] = "local"
    os.environ["ENVIRONMENT"] = "unit_test"
    local_db_settings = get_settings(DBSettings)
    assert local_db_settings.host == "host_local_unit_test"
    os.environ["EXECUTION_TYPE"] = "aws"
    os.environ["ENVIRONMENT"] = "prod"
    os.environ["DB_SECRET_PATH"] = "db/production"
    from functools import partial

    # This is meant only for testing
    editted_init_secrets_client = partial(
        init_secrets_client,
        secrets_type="DUMMY",
        response={
            "host": "localhost_dummy",
            "port": 5432,
            "user": "user",
            "password": "password",
            "database": "database",
        },
    )
    local_db_settings = get_settings(
        DBSettings, secrets_client_initializer=editted_init_secrets_client
    )
    assert local_db_settings.host == "localhost_dummy"


def test_get_logger_without_powertools():
    logger = get_logger("test_logger")
    assert logger.name == "test_logger"
    assert logger.level == logging.INFO
    assert logger.hasHandlers()


class TestSecretsManagerClient:
    def setup_method(self):
        aws_settings = AWSSettings(region_name="us-east-1")
        self.secrets_client = SecretsManagerClient(aws_settings)

    def test_get_secret_value(self):
        secret = self.secrets_client.get_secret_value("pymt1-eisa_softim_api_credentials")
        assert isinstance(secret, str)
        assert isinstance(json.loads(secret), dict)

    def test_get_secret_json_obj(self):
        secret = self.secrets_client.get_secret_json_obj("pymt1-eisa_softim_api_credentials")
        assert isinstance(secret, dict)
