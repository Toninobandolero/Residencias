"""
Script de prueba para verificar la generación automática de cobros previstos.
Este script muestra cómo usar el endpoint de generación de cobros previstos.
"""
import requests
import json
from datetime import datetime

# Configuración
API_URL = "http://localhost:5000"
# Necesitarás un token JWT válido - obtén uno haciendo login primero
TOKEN = "TU_TOKEN_JWT_AQUI"  # Reemplaza con un token real

def generar_cobros_previstos(mes=None):
    """
    Genera cobros previstos para todos los residentes activos.
    
    Args:
        mes: Opcional, formato 'YYYY-MM'. Si no se proporciona, usa el mes siguiente.
    """
    url = f"{API_URL}/api/v1/facturacion/cobros/generar-previstos"
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json"
    }
    
    data = {}
    if mes:
        data["mes"] = mes
    
    print(f"\n{'='*60}")
    print("GENERACIÓN DE COBROS PREVISTOS")
    print(f"{'='*60}")
    if mes:
        print(f"Mes de referencia: {mes}")
    else:
        siguiente_mes = datetime.now()
        if siguiente_mes.month == 12:
            siguiente_mes = siguiente_mes.replace(year=siguiente_mes.year + 1, month=1)
        else:
            siguiente_mes = siguiente_mes.replace(month=siguiente_mes.month + 1)
        print(f"Mes de referencia: {siguiente_mes.strftime('%Y-%m')} (mes siguiente)")
    print(f"{'='*60}\n")
    
    try:
        response = requests.post(url, headers=headers, json=data)
        
        if response.status_code == 201:
            resultado = response.json()
            print("✅ Cobros previstos generados exitosamente!")
            print(f"\nResumen:")
            print(f"  - Cobros generados: {resultado.get('cobros_generados', 0)}")
            print(f"  - Cobros duplicados (ya existían): {resultado.get('cobros_duplicados', 0)}")
            print(f"  - Total residentes procesados: {resultado.get('total_residentes_procesados', 0)}")
            print(f"  - Mes de referencia: {resultado.get('mes_referencia', 'N/A')}")
            
            if resultado.get('errores'):
                print(f"\n⚠️  Errores encontrados:")
                for error in resultado['errores']:
                    print(f"  - {error}")
        else:
            print(f"❌ Error: {response.status_code}")
            print(f"Respuesta: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Error: No se pudo conectar al servidor.")
        print("Asegúrate de que el servidor Flask esté ejecutándose en http://localhost:5000")
    except Exception as e:
        print(f"❌ Error inesperado: {str(e)}")


def listar_cobros():
    """Lista todos los cobros (previstos y realizados) de la residencia."""
    url = f"{API_URL}/api/v1/facturacion/cobros"
    headers = {
        "Authorization": f"Bearer {TOKEN}"
    }
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            cobros = data.get('cobros', [])
            total = data.get('total', 0)
            
            print(f"\n{'='*60}")
            print(f"LISTADO DE COBROS (Total: {total})")
            print(f"{'='*60}\n")
            
            if cobros:
                for cobro in cobros[:10]:  # Mostrar solo los primeros 10
                    tipo = "📋 PREVISTO" if cobro.get('es_cobro_previsto') else "✅ REALIZADO"
                    estado = cobro.get('estado', 'N/A')
                    fecha = cobro.get('fecha_prevista') or cobro.get('fecha_pago', 'N/A')
                    
                    print(f"{tipo} | {cobro.get('residente', 'N/A')}")
                    print(f"  Monto: €{cobro.get('monto', 0):.2f}")
                    print(f"  Fecha: {fecha}")
                    print(f"  Estado: {estado}")
                    print(f"  Método: {cobro.get('metodo_pago', 'N/A')}")
                    print()
                
                if total > 10:
                    print(f"... y {total - 10} más")
            else:
                print("No hay cobros registrados.")
        else:
            print(f"❌ Error: {response.status_code}")
            print(f"Respuesta: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Error: No se pudo conectar al servidor.")
    except Exception as e:
        print(f"❌ Error inesperado: {str(e)}")


if __name__ == '__main__':
    print("\n" + "="*60)
    print("SCRIPT DE PRUEBA - GENERACIÓN DE COBROS PREVISTOS")
    print("="*60)
    print("\n⚠️  IMPORTANTE: Debes actualizar la variable TOKEN con un token JWT válido.")
    print("   Obtén un token haciendo login en la aplicación.\n")
    
    # Descomenta las siguientes líneas después de actualizar el TOKEN
    # generar_cobros_previstos()  # Genera para el mes siguiente
    # generar_cobros_previstos("2025-02")  # Genera para un mes específico
    # listar_cobros()  # Lista todos los cobros

