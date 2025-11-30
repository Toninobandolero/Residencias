"""
Script para regenerar los cobros previstos.
Llama al endpoint de generación de cobros previstos.
"""
import os
import sys
import requests
from dotenv import load_dotenv

load_dotenv()

API_URL = os.getenv('API_URL', 'http://localhost:5000')

def regenerar_cobros_previstos():
    """Regenera los cobros previstos llamando al endpoint."""
    print("🔄 Regenerando cobros previstos...")
    print("=" * 60)
    
    # Obtener token del usuario (necesitarías estar autenticado)
    # Por ahora, vamos a hacer una llamada directa al endpoint
    # En producción, necesitarías obtener el token primero
    
    try:
        # Llamar al endpoint de generación
        response = requests.post(
            f"{API_URL}/api/v1/facturacion/cobros/generar-previstos",
            json={},
            headers={
                'Content-Type': 'application/json'
            },
            timeout=30
        )
        
        if response.status_code == 200 or response.status_code == 201:
            data = response.json()
            print("✅ Cobros previstos regenerados exitosamente")
            print(f"   - Cobros generados: {data.get('cobros_generados', 0)}")
            print(f"   - Cobros eliminados: {data.get('cobros_eliminados', 0)}")
            print(f"   - Cobros duplicados: {data.get('cobros_duplicados', 0)}")
            print(f"   - Mes de referencia: {data.get('mes_referencia', 'N/A')}")
            print(f"   - Total residentes procesados: {data.get('total_residentes_procesados', 0)}")
            if 'errores' in data and data['errores']:
                print(f"   - Errores: {len(data['errores'])}")
                for error in data['errores']:
                    print(f"     • {error}")
        elif response.status_code == 401:
            print("❌ Error: No autorizado. Necesitas estar autenticado.")
            print("   Por favor, usa el botón de regeneración desde el frontend.")
        else:
            print(f"❌ Error: {response.status_code}")
            try:
                error_data = response.json()
                print(f"   Mensaje: {error_data.get('error', 'Error desconocido')}")
            except:
                print(f"   Respuesta: {response.text}")
                
    except requests.exceptions.ConnectionError:
        print("❌ Error: No se pudo conectar al servidor.")
        print(f"   Verifica que el servidor esté corriendo en {API_URL}")
    except Exception as e:
        print(f"❌ Error inesperado: {str(e)}")

if __name__ == "__main__":
    regenerar_cobros_previstos()

