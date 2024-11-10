import os
import pytest


@pytest.fixture(scope="session", autouse=True)
def keep_same_env():
    initial_env = os.environ
    yield
    os.environ = initial_env
