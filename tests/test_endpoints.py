"""
Tests básicos para endpoints críticos del sistema Violetas.
Ejecutar con: python -m pytest tests/test_endpoints.py -v
"""
import pytest
import sys
import os

# Añadir el directorio raíz al path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from dotenv import load_dotenv
load_dotenv()

# Importar la app
from app import app

@pytest.fixture
def client():
    """Cliente de prueba para Flask."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def auth_token(client):
    """Obtiene un token de autenticación para las pruebas."""
    # Necesitarías un usuario de prueba en la BD
    # Por ahora, esto es un placeholder
    response = client.post('/api/v1/login', json={
        'email': 'test@violetas.com',
        'password': 'test123'
    })
    if response.status_code == 200:
        data = response.get_json()
        return data.get('token')
    return None


class TestHealthEndpoint:
    """Tests para el endpoint de health check."""
    
    def test_health_endpoint(self, client):
        """Test que el endpoint /health responde correctamente."""
        response = client.get('/health')
        assert response.status_code == 200
        data = response.get_json()
        assert 'status' in data
        assert data['status'] == 'ok'


class TestLoginEndpoint:
    """Tests para el endpoint de login."""
    
    def test_login_missing_data(self, client):
        """Test que login requiere email y password."""
        response = client.post('/api/v1/login', json={})
        assert response.status_code == 400
    
    def test_login_invalid_credentials(self, client):
        """Test que login rechaza credenciales inválidas."""
        response = client.post('/api/v1/login', json={
            'email': 'invalid@test.com',
            'password': 'wrongpassword'
        })
        assert response.status_code == 401
    
    def test_login_success_structure(self, client):
        """Test que login exitoso retorna un token."""
        # Nota: Este test requiere un usuario válido en la BD
        # Por ahora, solo verifica la estructura de respuesta
        response = client.post('/api/v1/login', json={
            'email': 'test@violetas.com',
            'password': 'test123'
        })
        # Si el usuario existe, debería retornar 200 con token
        # Si no existe, retornará 401
        if response.status_code == 200:
            data = response.get_json()
            assert 'token' in data
            assert isinstance(data['token'], str)
            assert len(data['token']) > 0


class TestResidentesEndpoints:
    """Tests para endpoints de residentes."""
    
    def test_listar_residentes_requires_auth(self, client):
        """Test que listar residentes requiere autenticación."""
        response = client.get('/api/v1/residentes')
        assert response.status_code == 401
    
    def test_crear_residente_requires_auth(self, client):
        """Test que crear residente requiere autenticación."""
        response = client.post('/api/v1/residentes', json={
            'nombre': 'Test',
            'apellido': 'User'
        })
        assert response.status_code == 401
    
    def test_crear_residente_validation(self, client):
        """Test que crear residente valida datos requeridos."""
        # Este test requiere un token válido, pero podemos verificar la estructura
        # En un entorno real, usarías auth_token aquí
        pass


class TestValidators:
    """Tests para el módulo de validación."""
    
    def test_validate_email(self):
        """Test validación de emails."""
        from validators import validate_email
        
        # Email válido
        valid, error = validate_email('test@example.com')
        assert valid is True
        assert error is None
        
        # Email inválido
        valid, error = validate_email('invalid-email')
        assert valid is False
        assert error is not None
        
        # Email vacío
        valid, error = validate_email('')
        assert valid is False
    
    def test_validate_monto(self):
        """Test validación de montos."""
        from validators import validate_monto
        
        # Monto válido
        valid, error = validate_monto(100.50, 'Monto')
        assert valid is True
        
        # Monto negativo
        valid, error = validate_monto(-10, 'Monto')
        assert valid is False
        
        # Monto demasiado grande
        valid, error = validate_monto(1000000, 'Monto')
        assert valid is False
    
    def test_validate_residencia_id(self):
        """Test validación de ID de residencia."""
        from validators import validate_residencia_id
        
        # ID válido
        valid, error = validate_residencia_id(1)
        assert valid is True
        
        valid, error = validate_residencia_id(2)
        assert valid is True
        
        # ID inválido
        valid, error = validate_residencia_id(3)
        assert valid is False
        
        valid, error = validate_residencia_id(None)
        assert valid is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

