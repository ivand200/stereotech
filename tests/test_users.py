from fastapi.testclient import TestClient

from main import app

client = TestClient(app)

def test_login_user_info_logout():
    """
    request user login
    request user info
    request user logout
    """
    payload = {
        "username": "usertest_14",
        "password": "pass_w0rD"
    }
    response_create_user = client.post("/api/v1/registration", json=payload)

    # login
    response_login = client.post("/api/v1/login", json=payload)
    response_login_body = response_login.json()
    assert response_login.status_code == 200
    assert len(response_login_body["access_token"]) > 10
    token = response_login_body["access_token"]

    # get user info
    response_info = client.get("api/v1/user", headers={"Token": token})
    response_info_body = response_info.json()
    assert response_info.status_code == 200
    assert response_info_body["username"] == "usertest_14"

    # logout
    response_logout = client.post("api/v1/logout", headers={"Token": token})
    assert response_logout.status_code == 204

    # get user info after logout
    response_get_info_logout = client.get("api/v1/user", headers={"Token": token})
    assert response_get_info_logout.status_code == 401


def test_registration_login_deletion_user():
    """
    Request to create user
    Request to create user with existing username
    Request to create user with wrong password

    Request to login with wrong login

    Request to login with existing user

    Request to delete user
    Request to delete user with wrong id


    """
    payload = {
        "username": "usertest_11",
        "password": "pass_w0rD"
    }
    # Create new user
    response_create_user = client.post("/api/v1/registration", json=payload)
    response_create_user_body = response_create_user.json()
    assert response_create_user.status_code == 201
    assert response_create_user_body["username"] == "usertest_11"
    id = response_create_user_body["id"]

    # Create user with existing username
    response_create_user_wrong = client.post("/api/v1/registration", json=payload)
    assert response_create_user_wrong.status_code == 400

    # Create user with wrong password
    payload_2 = {
        "username": "client_test",
        "password": "pass_worD"
    }
    response_create_wrong_pass = client.post("/api/v1/registration", json=payload_2)
    assert response_create_wrong_pass.status_code == 422

    # User login
    response_to_login = client.post("/api/v1/login", json=payload)
    response_to_login_body = response_to_login.json()
    assert response_to_login.status_code == 200
    token = response_to_login_body["access_token"]

    # User login with wrong creds
    payload_3 = {
        "username": "client_test",
        "password": "pass_word"
    }
    response_login_wrong = client.post("/api/v1/login", json=payload_3)
    assert response_login_wrong.status_code == 422

    # Request to delete with wrong token
    response_delete_wrong_token = client.delete(f"/api/v1/user/{id}", headers={"Token": "X60Jpy125"})
    assert response_delete_wrong_token.status_code == 401

    # Request to delete user by id
    response_delete_user = client.delete(f"/api/v1/user/{id}", headers={"Token": token})
    assert response_delete_user.status_code == 204

    # Request to delete user with wrong id
    response_delete_user = client.delete("/api/v1/user/99999", headers={"Token": token})
    assert response_delete_user.status_code == 404
