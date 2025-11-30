"""
Script rápido para probar el endpoint de residentes
"""
import requests
import json

# URL base
BASE_URL = "http://localhost:5000"

print("=" * 60)
print("🧪 PRUEBA RÁPIDA DEL ENDPOINT DE RESIDENTES")
print("=" * 60)
print()

# 1. Verificar health check
print("1️⃣ Verificando health check...")
try:
    response = requests.get(f"{BASE_URL}/health", timeout=5)
    if response.status_code == 200:
        print("  ✅ Servidor está corriendo")
        print(f"     Respuesta: {response.json()}")
    else:
        print(f"  ⚠️  Servidor responde con código: {response.status_code}")
except requests.exceptions.ConnectionError:
    print("  ❌ No se puede conectar al servidor")
    print("     Asegúrate de que el servidor esté corriendo: python app.py")
    exit(1)
except Exception as e:
    print(f"  ❌ Error: {str(e)}")
    exit(1)

print()

# 2. Hacer login
print("2️⃣ Haciendo login...")
try:
    login_data = {
        "email": "admin@violetas1.com",
        "password": "admin123"
    }
    response = requests.post(
        f"{BASE_URL}/api/v1/login",
        json=login_data,
        timeout=5
    )
    
    if response.status_code == 200:
        token = response.json().get('token')
        if token:
            print("  ✅ Login exitoso")
            print(f"     Token obtenido: {token[:50]}...")
        else:
            print("  ❌ Login falló: No se recibió token")
            print(f"     Respuesta: {response.json()}")
            exit(1)
    else:
        print(f"  ❌ Login falló con código: {response.status_code}")
        print(f"     Respuesta: {response.json()}")
        exit(1)
        
except Exception as e:
    print(f"  ❌ Error en login: {str(e)}")
    exit(1)

print()

# 3. Listar residentes
print("3️⃣ Listando residentes...")
try:
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(
        f"{BASE_URL}/api/v1/residentes",
        headers=headers,
        timeout=10
    )
    
    if response.status_code == 200:
        data = response.json()
        total = data.get('total', 0)
        residentes = data.get('residentes', [])
        
        print(f"  ✅ Petición exitosa")
        print(f"     Total de residentes: {total}")
        
        if total > 0:
            print(f"\n     Primeros residentes:")
            for i, res in enumerate(residentes[:5], 1):
                nombre = f"{res.get('nombre', '')} {res.get('apellido', '')}"
                residencia = res.get('nombre_residencia', f"Residencia {res.get('id_residencia', '?')}")
                activo = "✅ Activo" if res.get('activo') else "❌ Inactivo"
                print(f"       {i}. {nombre} - {residencia} {activo}")
        else:
            print("  ⚠️  NO HAY RESIDENTES EN LA BASE DE DATOS")
            print("     Esto es normal si es la primera vez que usas el sistema")
            print("     Crea un residente desde el frontend")
            
    elif response.status_code == 401:
        print("  ❌ Error 401: Token inválido o expirado")
        print(f"     Respuesta: {response.json()}")
    elif response.status_code == 500:
        print("  ❌ Error 500: Error interno del servidor")
        print(f"     Respuesta: {response.json()}")
        print("     Revisa los logs del servidor Flask")
    else:
        print(f"  ❌ Error con código: {response.status_code}")
        print(f"     Respuesta: {response.json()}")
        
except requests.exceptions.Timeout:
    print("  ❌ Timeout: La petición tardó demasiado")
    print("     Puede ser un problema de conexión a la base de datos")
except Exception as e:
    print(f"  ❌ Error: {str(e)}")

print()
print("=" * 60)
print("✅ PRUEBA COMPLETADA")
print("=" * 60)

