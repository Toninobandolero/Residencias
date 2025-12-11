#!/usr/bin/env python3
"""
Script para eliminar logs de debug temporales antes de producción
"""
import re

def limpiar_logs_backend():
    """Eliminar logs de debug del backend (app.py)"""
    with open('app.py', 'r', encoding='utf-8') as f:
        contenido = f.read()
    
    # Contar logs antes
    logs_antes = len(re.findall(r'app\.logger\.(debug|info)\(f?["\'].*[🔍📍]', contenido))
    
    # Eliminar líneas con logs de debug que contengan emojis
    lineas = contenido.split('\n')
    lineas_limpias = []
    
    for linea in lineas:
        # Mantener la línea si NO contiene logs de debug con emojis
        if not re.search(r'app\.logger\.(debug|info)\(f?["\'].*[🔍📍]', linea):
            lineas_limpias.append(linea)
        else:
            print(f"  ❌ Eliminando: {linea.strip()[:80]}...")
    
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write('\n'.join(lineas_limpias))
    
    logs_despues = len(re.findall(r'app\.logger\.(debug|info)\(f?["\'].*[🔍📍]', '\n'.join(lineas_limpias)))
    print(f"\n✅ Backend: {logs_antes - logs_despues} logs eliminados")
    return logs_antes - logs_despues

def limpiar_logs_frontend():
    """Eliminar logs de debug del frontend (index.html)"""
    with open('static/index.html', 'r', encoding='utf-8') as f:
        contenido = f.read()
    
    # Contar logs antes
    logs_antes = len(re.findall(r'console\.log\([^)]*[🔍📍]', contenido))
    
    # Eliminar líneas con console.log que contengan emojis
    lineas = contenido.split('\n')
    lineas_limpias = []
    
    for linea in lineas:
        # Mantener la línea si NO contiene console.log con emojis
        if not re.search(r'console\.log\([^)]*[🔍📍]', linea):
            lineas_limpias.append(linea)
        else:
            print(f"  ❌ Eliminando: {linea.strip()[:80]}...")
    
    with open('static/index.html', 'w', encoding='utf-8') as f:
        f.write('\n'.join(lineas_limpias))
    
    logs_despues = len(re.findall(r'console\.log\([^)]*[🔍📍]', '\n'.join(lineas_limpias)))
    print(f"\n✅ Frontend: {logs_antes - logs_despues} logs eliminados")
    return logs_antes - logs_despues

if __name__ == '__main__':
    print("=" * 80)
    print("LIMPIANDO LOGS DE DEBUG TEMPORALES")
    print("=" * 80)
    
    print("\n📝 Procesando backend (app.py)...")
    backend_eliminados = limpiar_logs_backend()
    
    print("\n📝 Procesando frontend (static/index.html)...")
    frontend_eliminados = limpiar_logs_frontend()
    
    print("\n" + "=" * 80)
    print(f"✅ LIMPIEZA COMPLETADA: {backend_eliminados + frontend_eliminados} logs eliminados")
    print("=" * 80)
