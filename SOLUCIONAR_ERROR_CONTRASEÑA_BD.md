# 🔧 Solucionar Error: "password authentication failed for user postgres"

## 🔴 Problema Identificado

El error en los logs muestra:
```
ERROR: password authentication failed for user "postgres"
```

Esto significa que la contraseña guardada en el secret `db-password` no coincide con la contraseña real del usuario `postgres` en Cloud SQL.

> **Nota:** Si encuentras este error después de una rotación de contraseñas, asegúrate de que Cloud SQL y Secret Manager tengan la misma contraseña.

---

## ✅ Solución: Actualizar Contraseña de Cloud SQL

Tienes dos opciones:

### **Opción 1: Cambiar contraseña en Cloud SQL y actualizar el secret (Recomendado)**

#### Paso 1: Cambiar contraseña en Cloud SQL

```bash
# Generar una nueva contraseña segura (guárdala, la necesitarás)
# O usa esta para generar una:
openssl rand -base64 32

# Cambiar contraseña del usuario postgres en Cloud SQL
gcloud sql users set-password postgres \
  --instance=residencias \
  --password="TU_NUEVA_CONTRASEÑA_AQUI" \
  --project=residencias-479706
```

**⚠️ IMPORTANTE:** Reemplaza `TU_NUEVA_CONTRASEÑA_AQUI` con una contraseña segura que hayas generado.

#### Paso 2: Actualizar el secret con la nueva contraseña

```bash
# Actualizar el secret db-password con la nueva contraseña
echo -n "TU_NUEVA_CONTRASEÑA_AQUI" | gcloud secrets versions add db-password \
  --data-file=- \
  --project=residencias-479706
```

**⚠️ IMPORTANTE:** Usa la misma contraseña que pusiste en el Paso 1.

#### Paso 3: Verificar que se actualizó

```bash
# Ver las versiones del secret
gcloud secrets versions list db-password --project=residencias-479706
```

---

### **Opción 2: Ver contraseña actual del secret y cambiar Cloud SQL**

Si quieres usar la contraseña que ya está en el secret:

#### Paso 1: Ver la contraseña actual del secret (solo si tienes permisos)

**Nota:** No puedes "ver" el contenido del secret directamente por seguridad, pero puedes intentar conectarte con la contraseña que crees que es.

#### Paso 2: Cambiar contraseña de Cloud SQL para que coincida

Si conoces la contraseña que está en el secret, cambia Cloud SQL para que coincida:

```bash
gcloud sql users set-password postgres \
  --instance=residencias \
  --password="LA_CONTRASEÑA_QUE_ESTÁ_EN_EL_SECRET" \
  --project=residencias-479706
```

---

## 🧪 Probar la Conexión

Después de actualizar, espera unos minutos y prueba el login en producción:

```bash
# Ver logs en tiempo real para verificar
gcloud run services logs read violetas-app \
  --region europe-west9 \
  --project residencias-479706 \
  --limit 20
```

O simplemente intenta hacer login en: https://violetas-app-621063984498.europe-west9.run.app

---

## 🔐 Generar Contraseña Segura

Si necesitas generar una contraseña segura:

```bash
# Método 1: Con OpenSSL
openssl rand -base64 32

# Método 2: Con Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

**Ejemplo de contraseña segura:** 
- Mínimo 16 caracteres
- Mezcla de mayúsculas, minúsculas, números y símbolos
- Ejemplo: `K7#mP9@xQ2$vL4&nR6!wT8`

---

## 📋 Comandos Completos (Copia y Pega)

Si prefieres hacerlo todo de una vez, aquí están los comandos completos:

```bash
# 1. Generar nueva contraseña (guarda el resultado)
NUEVA_PASSWORD=$(openssl rand -base64 32)
echo "Nueva contraseña: $NUEVA_PASSWORD"
echo "⚠️  GUARDA ESTA CONTRASEÑA, la necesitarás después"

# 2. Cambiar contraseña en Cloud SQL
gcloud sql users set-password postgres \
  --instance=residencias \
  --password="$NUEVA_PASSWORD" \
  --project=residencias-479706

# 3. Actualizar el secret
echo -n "$NUEVA_PASSWORD" | gcloud secrets versions add db-password \
  --data-file=- \
  --project=residencias-479706

# 4. Verificar
echo "✅ Contraseña actualizada"
echo "Espera 1-2 minutos y prueba el login en producción"
```

---

## ⚠️ Notas Importantes

1. **Espera unos minutos:** Los cambios pueden tardar 1-2 minutos en propagarse.

2. **Verifica la conexión:** Después de cambiar, intenta hacer login en la aplicación.

3. **Si sigue fallando:**
   - Verifica que usaste la misma contraseña en ambos lugares
   - Verifica que el secret tiene permisos correctos
   - Revisa los logs de Cloud Run

4. **Backup:** Si tienes datos importantes, considera hacer un backup antes de cambiar la contraseña (aunque este cambio no afecta los datos, solo la autenticación).

---

## 🆘 Si Tienes Problemas

### Error: "Permission denied"
```bash
# Verifica que tienes permisos para modificar Cloud SQL
gcloud projects get-iam-policy residencias-479706 \
  --flatten="bindings[].members" \
  --filter="bindings.members:$(gcloud config get-value account)"
```

### Error: "Instance not found"
```bash
# Verifica que la instancia existe
gcloud sql instances list --project=residencias-479706
```

### Ver estado de Cloud SQL
```bash
gcloud sql instances describe residencias \
  --project=residencias-479706 \
  --format="table(name,state)"
```

---

**¿Listo para solucionarlo?** Ejecuta los comandos del Paso 1 y 2 de la Opción 1 (recomendada).
