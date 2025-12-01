# Script para limpiar el historial de Git removiendo el archivo de credenciales
# Ejecutar con: .\limpiar_historial.ps1

Write-Host "🧹 Limpiando historial de Git..." -ForegroundColor Cyan

# Establecer variable de entorno para suprimir advertencias
$env:FILTER_BRANCH_SQUELCH_WARNING = "1"

# Remover el archivo del historial completo
Write-Host "Removiendo archivo del historial..." -ForegroundColor Yellow
git filter-branch --force --index-filter "git rm --cached --ignore-unmatch residencias-479706-8c3bdbf8bbf8.json" --prune-empty --tag-name-filter cat -- --all

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Archivo removido del historial" -ForegroundColor Green
    
    # Limpiar referencias de backup
    Write-Host "Limpiando referencias de backup..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force .git\refs\original -ErrorAction SilentlyContinue
    
    # Limpiar reflog
    Write-Host "Limpiando reflog..." -ForegroundColor Yellow
    git reflog expire --expire=now --all
    
    # Recolectar basura
    Write-Host "Recolectando basura..." -ForegroundColor Yellow
    git gc --prune=now --aggressive
    
    Write-Host "`n✅ Historial limpiado exitosamente" -ForegroundColor Green
    Write-Host "`n⚠️  IMPORTANTE: Ahora debes hacer force push:" -ForegroundColor Yellow
    Write-Host "   git push origin main --force" -ForegroundColor White
    Write-Host "`n⚠️  ADVERTENCIA: Esto reescribirá el historial en el remoto." -ForegroundColor Red
    Write-Host "   Asegúrate de que nadie más esté trabajando en el repositorio." -ForegroundColor Red
} else {
    Write-Host "❌ Error al limpiar el historial" -ForegroundColor Red
    exit 1
}

