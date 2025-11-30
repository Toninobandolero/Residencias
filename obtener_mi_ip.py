"""
Script para obtener tu IP pública actual
Útil para autorizarla en Cloud SQL
"""
import requests

print("=" * 60)
print("🌐 OBTENER MI IP PÚBLICA")
print("=" * 60)
print()

try:
    # Intentar obtener IP desde varios servicios
    services = [
        ("ipify.org", "https://api.ipify.org?format=json"),
        ("ifconfig.me", "https://ifconfig.me/ip"),
        ("icanhazip.com", "https://icanhazip.com"),
    ]
    
    ip_obtenida = None
    servicio_usado = None
    
    for nombre, url in services:
        try:
            if "json" in url:
                response = requests.get(url, timeout=5)
                ip_obtenida = response.json().get('ip', response.text.strip())
            else:
                response = requests.get(url, timeout=5)
                ip_obtenida = response.text.strip()
            
            if ip_obtenida and len(ip_obtenida.split('.')) == 4:
                servicio_usado = nombre
                break
        except:
            continue
    
    if ip_obtenida:
        print(f"✅ Tu IP pública actual es: {ip_obtenida}")
        print(f"   (Obtenida desde: {servicio_usado})")
        print()
        print("📋 Para autorizarla en Cloud SQL:")
        print("   1. Ve a: https://console.cloud.google.com/sql/instances/residencias/overview")
        print("   2. Menú → 'Conexiones' o 'Connections'")
        print("   3. 'Autorizar redes' o 'Authorized networks'")
        print("   4. 'Agregar red' o 'Add network'")
        print(f"   5. Ingresa: {ip_obtenida}/32")
        print("   6. Guarda y espera 1-2 minutos")
        print()
        print(f"🔗 Formato para copiar: {ip_obtenida}/32")
    else:
        print("❌ No se pudo obtener la IP pública")
        print("   Intenta manualmente en: https://whatismyipaddress.com/")
        
except Exception as e:
    print(f"❌ Error: {str(e)}")
    print()
    print("💡 Alternativa: Visita https://whatismyipaddress.com/ para obtener tu IP")

