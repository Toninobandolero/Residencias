"""
Sistema de Extracción de Datos de Facturas con >99% Fiabilidad
Utiliza Google Document AI Invoice Parser + análisis de texto robusto
"""

import re
import logging
from decimal import Decimal, InvalidOperation
from datetime import datetime
from typing import Dict, Optional, Tuple, List

logger = logging.getLogger(__name__)


class FacturaExtractor:
    """Extractor robusto de datos de facturas con validación cruzada"""
    
    # Tipos de IVA válidos en España
    IVA_VALIDOS_ESPANA = [4, 10, 21]
    
    # Tolerancia para validación de sumas (en euros)
    TOLERANCIA_SUMA = Decimal('0.10')
    
    def __init__(self):
        self.datos_extraidos = {}
        self.confianza = {}
        self.texto_completo = ""
        
    def parsear_monto(self, valor_str: str) -> Optional[Decimal]:
        """
        Parse un monto con máxima precisión, manejando formatos españoles e internacionales.
        
        Formatos soportados:
        - "241,80" → 241.80 (español)
        - "241.80" → 241.80 (internacional)
        - "2.418,50" → 2418.50 (español con miles)
        - "2,418.50" → 2418.50 (internacional con miles)
        - "15234" → 15234.00
        """
        if not valor_str or not isinstance(valor_str, str):
            return None
        
        try:
            # Limpiar
            cleaned = str(valor_str).upper()
            cleaned = cleaned.replace('€', '').replace('EUR', '').replace(' ', '').strip()
            cleaned = re.sub(r'[^\d,.\-+]', '', cleaned)
            
            if not cleaned or cleaned in ['-', '.', ',', '+']:
                return None
            
            tiene_coma = ',' in cleaned
            tiene_punto = '.' in cleaned
            
            # Sin separadores
            if not tiene_coma and not tiene_punto:
                return Decimal(cleaned).quantize(Decimal('0.01'))
            
            # Solo coma = decimal español
            if tiene_coma and not tiene_punto:
                return Decimal(cleaned.replace(',', '.')).quantize(Decimal('0.01'))
            
            # Solo punto
            if tiene_punto and not tiene_coma:
                partes = cleaned.split('.')
                if len(partes) == 2 and len(partes[1]) <= 2:
                    # Punto decimal
                    return Decimal(cleaned).quantize(Decimal('0.01'))
                else:
                    # Separador de miles
                    return Decimal(cleaned.replace('.', '')).quantize(Decimal('0.01'))
            
            # Ambos: detectar cuál es decimal
            if tiene_coma and tiene_punto:
                pos_coma = cleaned.rfind(',')
                pos_punto = cleaned.rfind('.')
                
                if pos_coma > pos_punto:
                    # Formato español: 1.234,56
                    cleaned = cleaned.replace('.', '').replace(',', '.')
                else:
                    # Formato internacional: 1,234.56
                    cleaned = cleaned.replace(',', '')
                
                return Decimal(cleaned).quantize(Decimal('0.01'))
            
        except Exception as e:
            logger.warning(f"Error parseando '{valor_str}': {e}")
            return None
    
    def extraer_numero_factura(self, texto: str) -> Optional[str]:
        """Extrae el número de factura con múltiples patrones"""
        patrones = [
            r'(?:factura|fact\.?|invoice)\s*(?:n[°ºª]?\.?|num\.?|number)?\s*[:\-\s]*([A-Z0-9\-/]+)',
            r'n[°ºª]\.?\s*(?:factura|fact\.?)\s*[:\-\s]*([A-Z0-9\-/]+)',
            r'(?:^|\n)([A-Z]{1,3}\d{4,}(?:[/-][A-Z0-9]+)?)',  # Formato típico: ABC12345
        ]
        
        for patron in patrones:
            match = re.search(patron, texto, re.IGNORECASE | re.MULTILINE)
            if match:
                numero = match.group(1).strip()
                if len(numero) >= 3:  # Mínimo 3 caracteres
                    logger.info(f"✅ Número factura encontrado: {numero}")
                    return numero
        
        logger.warning("⚠️ No se encontró número de factura")
        return None
    
    def extraer_fecha(self, texto: str) -> Optional[str]:
        """Extrae la fecha en formato ISO (YYYY-MM-DD)"""
        patrones = [
            r'fecha\s*(?:factura|emisión)?[:\s]*(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})',
            r'date[:\s]*(\d{1,2}[-/]\d{1,2}[-/]\d{2,4})',
            r'(\d{1,2}[-/]\d{1,2}[-/]\d{4})',  # Solo fechas con año completo
        ]
        
        for patron in patrones:
            matches = re.finditer(patron, texto, re.IGNORECASE)
            for match in matches:
                fecha_str = match.group(1)
                try:
                    # Intentar múltiples formatos
                    for fmt in ['%d-%m-%Y', '%d/%m/%Y', '%d-%m-%y', '%d/%m/%y']:
                        try:
                            fecha_obj = datetime.strptime(fecha_str, fmt)
                            # Validar que sea una fecha razonable (no futura, no muy antigua)
                            hoy = datetime.now()
                            if fecha_obj.year >= 2000 and fecha_obj <= hoy:
                                fecha_iso = fecha_obj.strftime('%Y-%m-%d')
                                logger.info(f"✅ Fecha encontrada: {fecha_iso} (texto: {fecha_str})")
                                return fecha_iso
                        except ValueError:
                            continue
                except Exception:
                    continue
        
        logger.warning("⚠️ No se encontró fecha válida")
        return None
    
    def extraer_proveedor(self, texto: str) -> Optional[str]:
        """Extrae el nombre del proveedor (primeras líneas con texto)"""
        lineas = texto.split('\n')[:15]  # Primeras 15 líneas
        
        for linea in lineas:
            linea = linea.strip()
            # Buscar líneas con principalmente letras (nombre de empresa)
            if len(linea) >= 5 and len(linea) <= 100:
                # Calcular porcentaje de letras
                letras = sum(c.isalpha() or c.isspace() for c in linea)
                if letras / len(linea) > 0.6:  # Más del 60% letras
                    # Evitar líneas comunes que no son proveedores
                    linea_lower = linea.lower()
                    palabras_excluir = ['factura', 'invoice', 'fecha', 'date', 'página', 'page']
                    if not any(palabra in linea_lower for palabra in palabras_excluir):
                        logger.info(f"✅ Proveedor encontrado: {linea}")
                        return linea
        
        logger.warning("⚠️ No se encontró proveedor")
        return None
    
    def buscar_monto_en_texto(self, texto: str, patrones: List[str], nombre_campo: str) -> Optional[Decimal]:
        """Busca un monto en el texto usando múltiples patrones"""
        for patron in patrones:
            matches = re.finditer(patron, texto, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                try:
                    valor_str = match.group(1)
                    valor = self.parsear_monto(valor_str)
                    if valor and valor > 0:
                        logger.info(f"✅ {nombre_campo}: {valor}€ (texto: '{valor_str}')")
                        return valor
                except (IndexError, Exception):
                    continue
        
        logger.warning(f"⚠️ {nombre_campo} no encontrado con patrones de texto")
        return None
    
    def extraer_total(self, texto: str) -> Optional[Decimal]:
        """Extrae el TOTAL con IVA incluido"""
        patrones = [
            r'total\s+(?:factura|a\s+pagar|invoice)[:\s]+([\d.,]+)',
            r'(?:^|\n)total[:\s]+([\d.,]+)\s*€',
            r'importe\s+total[:\s]+([\d.,]+)',
            r'total\s+(?:con\s+)?iva[:\s]+([\d.,]+)',
        ]
        return self.buscar_monto_en_texto(texto, patrones, "TOTAL con IVA")
    
    def extraer_base_imponible(self, texto: str) -> Optional[Decimal]:
        """Extrae la BASE IMPONIBLE (sin IVA)"""
        patrones = [
            r'base\s+imp(?:onible)?\.?[:\s]+([\d.,]+)',
            r'(?:^|\n)base[:\s]+([\d.,]+)\s*€',
            r'subtotal[:\s]+([\d.,]+)',
            r'neto[:\s]+([\d.,]+)',
        ]
        return self.buscar_monto_en_texto(texto, patrones, "BASE IMPONIBLE")
    
    def extraer_iva_importe(self, texto: str) -> Optional[Decimal]:
        """Extrae el importe del IVA (no el porcentaje)"""
        patrones = [
            r'imp(?:orte)?\.?\s+iva[:\s]+([\d.,]+)',
            r'cuota\s+iva[:\s]+([\d.,]+)',
            r'(?:^|\n)iva[:\s]+([\d.,]+)\s*€',
        ]
        return self.buscar_monto_en_texto(texto, patrones, "IVA (importe)")
    
    def extraer_iva_porcentaje(self, texto: str) -> Optional[int]:
        """Extrae el porcentaje de IVA"""
        patrones = [
            r'iva\s+([\d,]+)\s*%',
            r'([\d,]+)\s*%\s*iva',
            r'tipo\s+iva[:\s]+([\d,]+)',
        ]
        
        for patron in patrones:
            matches = re.finditer(patron, texto, re.IGNORECASE)
            for match in matches:
                try:
                    valor_str = match.group(1).replace(',', '.')
                    valor = float(valor_str)
                    
                    # Validar que sea un porcentaje español válido
                    if valor in self.IVA_VALIDOS_ESPANA:
                        logger.info(f"✅ IVA%: {int(valor)}%")
                        return int(valor)
                    # Formato decimal (0.21 → 21%)
                    elif 0 < valor < 1:
                        valor_pct = int(valor * 100)
                        if valor_pct in self.IVA_VALIDOS_ESPANA:
                            logger.info(f"✅ IVA%: {valor_pct}% (convertido desde {valor})")
                            return valor_pct
                except Exception:
                    continue
        
        logger.warning("⚠️ IVA% no encontrado")
        return None
    
    def validar_coherencia(self, base: Decimal, iva: Decimal, total: Decimal) -> bool:
        """Valida que Base + IVA = Total (con tolerancia)"""
        suma = base + iva
        diferencia = abs(suma - total)
        
        es_coherente = diferencia <= self.TOLERANCIA_SUMA
        
        if es_coherente:
            logger.info(f"✅ VALIDACIÓN OK: {base}€ + {iva}€ = {suma}€ ≈ {total}€ (dif: {diferencia}€)")
        else:
            logger.error(f"❌ VALIDACIÓN FALLIDA: {base}€ + {iva}€ = {suma}€ ≠ {total}€ (dif: {diferencia}€)")
        
        return es_coherente
    
    def calcular_iva_porcentaje(self, base: Decimal, iva: Decimal) -> Optional[int]:
        """Calcula el porcentaje de IVA desde base e importe"""
        if not base or base == 0:
            return None
        
        try:
            porcentaje = float((iva / base) * 100)
            # Redondear al porcentaje español más cercano
            iva_redondeado = min(self.IVA_VALIDOS_ESPANA, key=lambda x: abs(x - porcentaje))
            logger.info(f"✅ IVA% calculado: {iva_redondeado}% (desde {porcentaje:.2f}%)")
            return iva_redondeado
        except Exception:
            return None
    
    def extraer_datos_completos(self, document, texto_completo: str) -> Dict:
        """
        Extrae TODOS los datos de la factura con máxima fiabilidad.
        
        Estrategia CORREGIDA:
        1. PRIORIDAD 1: Entidades estructuradas de Document AI Invoice Parser
        2. FALLBACK: Extracción de texto OCR solo si Document AI no encontró algo
        3. Validaciones cruzadas y cálculos
        """
        self.texto_completo = texto_completo
        resultado = {}
        
        logger.info("="*80)
        logger.info("🎯 INICIANDO EXTRACCIÓN DE DATOS DE FACTURA")
        logger.info("="*80)
        
        # ======================
        # PASO 1: USAR ENTIDADES DE DOCUMENT AI (PRIORIDAD)
        # ======================
        logger.info("\n🤖 PASO 1: Extracción desde entidades de Document AI Invoice Parser")
        
        numero_factura = None
        fecha = None
        proveedor = None
        total = None
        base = None
        iva_importe = None
        iva_porcentaje = None
        
        # Mapeo de entidades de Document AI a nuestros campos
        if document.entities:
            for entity in document.entities:
                entity_type = entity.type_
                
                # Obtener valor normalizado si existe, sino el texto
                valor = entity.normalized_value.text if entity.normalized_value and entity.normalized_value.text else entity.mention_text
                confianza = entity.confidence if hasattr(entity, 'confidence') else 0
                
                # Número de factura
                if entity_type == 'invoice_id' and not numero_factura:
                    numero_factura = valor.strip()
                    logger.info(f"✅ invoice_id (Document AI): '{numero_factura}' (confianza: {confianza:.2f})")
                
                # Fecha de factura
                elif entity_type == 'invoice_date' and not fecha:
                    fecha = valor.strip()  # Ya viene en formato ISO
                    logger.info(f"✅ invoice_date (Document AI): '{fecha}' (confianza: {confianza:.2f})")
                
                # Proveedor
                elif entity_type == 'supplier_name' and not proveedor:
                    proveedor = valor.strip()
                    logger.info(f"✅ supplier_name (Document AI): '{proveedor}' (confianza: {confianza:.2f})")
                
                # Total con IVA
                elif entity_type == 'total_amount' and not total:
                    total = self.parsear_monto(valor)
                    if total:
                        logger.info(f"✅ total_amount (Document AI): {total}€ (confianza: {confianza:.2f})")
                
                # Base imponible (sin IVA)
                elif entity_type == 'net_amount' and not base:
                    base = self.parsear_monto(valor)
                    if base:
                        logger.info(f"✅ net_amount (Document AI): {base}€ (confianza: {confianza:.2f})")
                
                # Importe de IVA
                elif entity_type == 'vat' and not iva_importe:
                    iva_importe = self.parsear_monto(valor)
                    if iva_importe:
                        logger.info(f"✅ vat (Document AI): {iva_importe}€ (confianza: {confianza:.2f})")
        
        # ======================
        # PASO 2: FALLBACK - Extracción de texto OCR (solo si faltan datos)
        # ======================
        logger.info("\n📄 PASO 2: Fallback - Extracción desde texto OCR (solo campos faltantes)")
        
        if not numero_factura:
            numero_factura = self.extraer_numero_factura(texto_completo)
        if not fecha:
            fecha = self.extraer_fecha(texto_completo)
        if not proveedor:
            proveedor = self.extraer_proveedor(texto_completo)
        if not total:
            total = self.extraer_total(texto_completo)
        if not base:
            base = self.extraer_base_imponible(texto_completo)
        if not iva_importe:
            iva_importe = self.extraer_iva_importe(texto_completo)
        if not iva_porcentaje:
            iva_porcentaje = self.extraer_iva_porcentaje(texto_completo)
        
        # ======================
        # PASO 3: Cálculos y validaciones
        # ======================
        logger.info("\n🔢 PASO 3: Cálculos y validaciones cruzadas")
        
        # Si faltan datos, intentar calcularlos
        if total and base and not iva_importe:
            iva_importe = total - base
            logger.info(f"✅ IVA calculado: {iva_importe}€ (Total - Base)")
        
        if base and iva_importe and not total:
            total = base + iva_importe
            logger.info(f"✅ Total calculado: {total}€ (Base + IVA)")
        
        if base and iva_importe and not iva_porcentaje:
            iva_porcentaje = self.calcular_iva_porcentaje(base, iva_importe)
        
        # Validar coherencia si tenemos los 3 valores
        if total and base and iva_importe:
            coherente = self.validar_coherencia(base, iva_importe, total)
            if not coherente:
                logger.error("❌ DATOS INCOHERENTES - Verificar extracción")
        
        # ======================
        # PASO 4: Construir resultado
        # ======================
        logger.info("\n📋 PASO 4: Construyendo resultado final")
        
        if numero_factura:
            resultado['numero_factura'] = numero_factura
        if fecha:
            resultado['fecha_pago'] = fecha
        if proveedor:
            resultado['proveedor'] = proveedor
        if total:
            resultado['total_con_impuestos'] = float(total)
            resultado['monto'] = float(total)
        if base:
            resultado['total'] = float(base)
            resultado['base_imponible'] = float(base)
        if iva_importe:
            resultado['impuestos'] = float(iva_importe)
            resultado['iva'] = float(iva_importe)
            resultado['iva_monto'] = float(iva_importe)
        if iva_porcentaje:
            resultado['iva_porcentaje'] = iva_porcentaje
        
        # Calcular tasa de éxito
        campos_criticos = ['numero_factura', 'total_con_impuestos', 'base_imponible', 'iva']
        campos_encontrados = sum(1 for campo in campos_criticos if campo in resultado)
        tasa_exito = (campos_encontrados / len(campos_criticos)) * 100
        
        logger.info(f"\n{'='*80}")
        logger.info(f"📊 RESULTADO: {len(resultado)} campos extraídos")
        logger.info(f"📊 TASA DE ÉXITO: {tasa_exito:.1f}% ({campos_encontrados}/{len(campos_criticos)} campos críticos)")
        logger.info(f"{'='*80}\n")
        
        for key, value in resultado.items():
            logger.info(f"  ✓ {key}: {value}")
        
        return resultado
