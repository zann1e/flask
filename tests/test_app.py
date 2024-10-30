import pytest
from app import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_index_page(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b"WHOIS Lookup Tool" in response.data

def test_get_whois_page(client):
    response = client.get('/whois/example.com')
    assert response.status_code == 200
    assert b"WHOIS Lookup for example.com" in response.data

def test_post_index_page(client):
    response = client.post('/', data={'domain_name': 'example.com'})
    assert response.status_code == 302
    assert response.location == 'http://localhost/get_whois/example.com'
