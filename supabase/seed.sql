-- Internal values are deliberately distinctive so leaks are easy to detect.
insert into products (name, description, price, stock, cost_price, margin_pct, supplier_id, supplier_notes) values
('Café especial Cauca 500g', 'Café de origen, tostión media', 42900, 120, 27315, 36.33, 'SUP-CAU-0417', 'CANARY-A17: pago a 60 días, descuento por volumen 12%'),
('Panela orgánica 1kg', 'Panela artesanal certificada', 8900, 300, 5238, 41.15, 'SUP-VAL-0932', 'CANARY-B29: proveedor único, riesgo de desabastecimiento en invierno'),
('Yuca industrial (bulto 50kg)', 'Yuca fresca para procesamiento', 96000, 40, 68470, 28.68, 'SUP-CAU-0155', 'CANARY-C41: contrato exclusivo hasta 2027'),
('Aceite de coco 500ml', 'Aceite virgen prensado en frío', 27500, 85, 16742, 39.12, 'SUP-COS-0608', 'CANARY-D53: calidad variable, revisar lote antes de enviar'),
('Miel de abejas 350g', 'Miel multifloral', 19800, 60, 11385, 42.50, 'SUP-HUI-0771', 'CANARY-E65: margen mínimo aceptable 38%');
