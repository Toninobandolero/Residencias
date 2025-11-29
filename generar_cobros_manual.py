import os
import sys
import requests
from dotenv import load_dotenv

load_dotenv()

def generar_cobros_previstos():
    """Genera cobros previstos manualmente usando el endpoint."""
    print("Generando cobros previstos...\n")
    
    # Obtener token del usuario (necesitarías tenerlo en .env o pasarlo como parámetro)
    # Por ahora, vamos a usar el endpoint directamente
    
    API_URL = "http://localhost:5000"
    
    # Primero necesitamos hacer login para obtener el token
    # Usando credenciales por defecto
    login_data = {
        "email": "admin@violetas.com",
        "password": "admin123"  # Ajusta según tu contraseña
    }
    
    try:
        # Login
        print("1. Iniciando sesión...")
        login_res = requests.post(f"{API_URL}/api/v1/login", json=login_data)
        
        if login_res.status_code != 200:
            print(f"❌ Error en login: {login_res.status_code}")
            print(f"   Respuesta: {login_res.text}")
            return
        
        token = login_res.json().get('token')
        if not token:
            print("❌ No se obtuvo token del login")
            return
        
        print("✅ Login exitoso\n")
        
        # Generar cobros previstos
        print("2. Generando cobros previstos...")
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        generar_res = requests.post(
            f"{API_URL}/api/v1/facturacion/cobros/generar-previstos",
            headers=headers,
            json={}
        )
        
        if generar_res.status_code in [200, 201]:
            data = generar_res.json()
            print("✅ Cobros previstos generados exitosamente")
            print(f"   Cobros generados: {data.get('cobros_generados', 0)}")
            print(f"   Cobros duplicados: {data.get('cobros_duplicados', 0)}")
            print(f"   Mes referencia: {data.get('mes_referencia', 'N/A')}")
            print(f"   Total residentes procesados: {data.get('total_residentes_procesados', 0)}")
        else:
            print(f"❌ Error al generar cobros: {generar_res.status_code}")
            print(f"   Respuesta: {generar_res.text}")
        
        # Verificar cobros generados
        print("\n3. Verificando cobros previstos generados...")
        cobros_res = requests.get(
            f"{API_URL}/api/v1/facturacion/cobros",
            headers=headers
        )
        
        if cobros_res.status_code == 200:
            cobros_data = cobros_res.json()
            cobros_previstos = [c for c in cobros_data.get('cobros', []) if c.get('es_cobro_previsto')]
            print(f"✅ Total de cobros previstos: {len(cobros_previstos)}")
            
            for cobro in cobros_previstos:
                print(f"   - {cobro.get('residente')}: €{cobro.get('monto')} | Fecha: {cobro.get('fecha_prevista')} | Estado: {cobro.get('estado')}")
        else:
            print(f"❌ Error al listar cobros: {cobros_res.status_code}")
            print(f"   Respuesta: {cobros_res.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Error: No se pudo conectar al servidor Flask")
        print("   Asegúrate de que el servidor esté ejecutándose en http://localhost:5000")
    except Exception as e:
        print(f"❌ Error inesperado: {str(e)}")

if __name__ == '__main__':
    generar_cobros_previstos()

