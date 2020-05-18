from .test_main_app import client
from main import get_password_hash


def test_create_user():
    response = client.post(
        "/users/",
        json={"email": "deadpool@example.com", "password": "chimichangas4life", "username":"foobar"},
    )
    
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["email"] == "deadpool@example.com"
    assert "id" in data
    user_id = data["id"]
    login_data = {
      "username": "foobar",
      "password": "chimichangas4life",
    }
    response = client.get(
        "/users/"
    )

    assert response.status_code == 200, response.text
    data = response.json()

    assert len(data) == 1