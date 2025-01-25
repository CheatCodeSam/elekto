from flask.testing import FlaskClient
from pytest_mock import MockerFixture
import pytest
from elekto import APP

@pytest.fixture
def client():
    with APP.test_client() as c:
        yield c

def test_app_route_ok(client: FlaskClient, mocker: MockerFixture):
    mocker.patch('elekto.middlewares.auth.authenticated', return_value=True)

    response = client.get('/app')
    assert response.status_code == 200
