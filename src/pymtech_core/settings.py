import logging
import os
from functools import lru_cache
from typing import Callable, Literal, Optional, Protocol, Type, TypeVar

import boto3
import orjson
import pydantic
import pydantic_settings
from botocore.exceptions import ClientError, NoCredentialsError
from pydantic_settings import SettingsConfigDict

try:
    from aws_lambda_powertools import Logger
    # Warn that we are using powertools
except ImportError:
    Logger = None


def get_logger(name: str, level: int = logging.INFO):
    # If logger already exists reeturn same logger instance
    if Logger:
        return Logger(service=name)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if logger.hasHandlers():
        return logger
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


logger = get_logger(__name__)


class AWSSecretsMixIn:
    _secret_attribute_: str


def get_secret_path(settings_class) -> str:
    if not isinstance(settings_class._secret_attribute_, pydantic.fields.ModelPrivateAttr):
        raise AttributeError(
            f"Class {settings_class.__name__} must have a string attribute '_secret_attribute_'"
        )
    return settings_class._secret_attribute_.get_default()  # type: ignore


class BaseSettingsExtraIgnored(pydantic_settings.BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")


class BaseAWSSecretsSettings(BaseSettingsExtraIgnored, AWSSecretsMixIn):
    pass


class AWSSettings(BaseSettingsExtraIgnored):
    AWS_REGION: str = "us-east-1"
    AWS_PROFILE: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[pydantic.SecretStr] = None
    AWS_ACCESS_KEY_ID: Optional[pydantic.SecretStr] = None


class DummyClient:
    def __init__(self, response: dict = {}):
        self.response = response

    def get_secret_json_obj(self, secret_name: str) -> dict:
        return self.response


class SecretsManagerClient:
    def __init__(self, aws_settings: AWSSettings):
        self.aws_settings = aws_settings
        self.client = self._create_secrets_manager_client()

    def _create_aws_session(self):
        aws_access_key = (
            self.aws_settings.AWS_ACCESS_KEY_ID.get_secret_value()
            if self.aws_settings.AWS_ACCESS_KEY_ID is not None
            else None
        )
        aws_secret_access_key = (
            self.aws_settings.AWS_SECRET_ACCESS_KEY.get_secret_value()
            if self.aws_settings.AWS_SECRET_ACCESS_KEY is not None
            else None
        )
        if (
            aws_access_key is None
            or aws_secret_access_key is None
            or "AWS_EXECUTION_ENV" in os.environ
        ):
            logger.debug("Using default credentials")
            session = boto3.Session(
                region_name=self.aws_settings.AWS_REGION,
            )
        else:
            logger.debug("Using provided credentials")
            session = boto3.Session(
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_access_key,
                region_name=self.aws_settings.AWS_REGION,
                profile_name=self.aws_settings.AWS_PROFILE,
            )
        return session

    def _create_secrets_manager_client(self):
        """
        The credentiales need codfigure the AWS_PROFILE and AWS_REGION environment variables
        """
        session = self._create_aws_session()
        try:
            return session.client(
                "secretsmanager",
            )
        except NoCredentialsError:
            logger.error("Credentials not available")
            raise

    def get_secret_value(self, secret_name: str):
        try:
            response = self.client.get_secret_value(SecretId=secret_name)
        except ClientError as e:
            # For a list of exceptions thrown, see
            # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
            raise e
        secret = response["SecretString"]
        return secret

    def get_secret_json_obj(self, secret_name: str):
        return orjson.loads(self.get_secret_value(secret_name))

    def get_specific_secret(self, key: str, secret_name: str):
        secret_dict = self.get_secret_value(secret_name)
        return secret_dict.get(key)


T = TypeVar("T", bound=pydantic_settings.BaseSettings)


class SecretsClient(Protocol):
    def get_secret_json_obj(self, secret_name: str) -> dict: ...


def init_secrets_client(secrets_type: Literal["AWS", "DUMMY"] = "AWS", **kwargs) -> SecretsClient:
    if secrets_type == "DUMMY":
        secrets_client = DummyClient(**kwargs)
    elif secrets_type == "AWS":
        aws_settings = get_settings(AWSSettings)
        secrets_client = SecretsManagerClient(aws_settings)
    else:
        raise ValueError(f"Secrets type {secrets_type} not supported")
    return secrets_client


def retrieve_secret_from_secrets_manager(secret_name: str, secrets_client: SecretsClient) -> dict:
    dict_secrets = secrets_client.get_secret_json_obj(secret_name)
    return dict_secrets


def get_settings(
    settings_class: Type[T],
    directory: Optional[str] = None,
    secrets_client_initializer: Callable[[], SecretsClient] = init_secrets_client,
) -> T:
    EXECUTION_TYPE = os.environ.get("EXECUTION_TYPE", "local")
    ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")

    env_file = f".env.{EXECUTION_TYPE}_{ENVIRONMENT}".lower()
    if directory:
        env_file = os.path.join(directory, env_file)
    logger.info(f"env_file: {env_file}")

    if EXECUTION_TYPE == "aws":
        if issubclass(settings_class, AWSSecretsMixIn):
            secret_attr = get_secret_path(settings_class)
            secret_path = os.environ.get(secret_attr)
            if not secret_path:
                raise AttributeError(
                    f"Secret Path not found for {settings_class.__name__}. Please set the environment variable {secret_attr} with the AWS secret path."
                )
            secrets_client = secrets_client_initializer()
            dict_secrets = secrets_client.get_secret_json_obj(secret_path)
            settings = settings_class(**dict_secrets)
        else:
            if os.path.exists(env_file):
                logger.info(f"Env file {env_file} exists, using it")
                settings = settings_class(_env_file=env_file)
            else:
                logger.warning("Using default env variables")
                settings = settings_class()
    else:
        if not os.path.exists(env_file):
            raise FileNotFoundError(f"File {env_file} not found. Please create this file.")
        settings = settings_class(_env_file=env_file)

    return settings
