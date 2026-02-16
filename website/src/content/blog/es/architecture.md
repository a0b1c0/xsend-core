---
title: "La Arquitectura de un Sistema de Transferencia de Archivos P2P Seguro"
description: "Profundizando en cómo xSend utiliza Rust, Tokio y X25519 para ofrecer transferencias de archivos seguras y de alto rendimiento."
pubDate: 2026-02-15
tags: ["rust", "p2p", "seguridad", "arquitectura"]
---

## Introducción

En una era donde domina el almacenamiento en la nube, enviar un archivo a la persona sentada a tu lado a menudo implica subirlo a un servidor al otro lado del mundo, solo para descargarlo de nuevo. Esto es ineficiente y menos privado.

xSend resuelve esto creando un túnel directo y cifrado entre dispositivos.

## La Tecnología Principal

Elegimos **Rust** por su seguridad de memoria y rendimiento sin recolector de basura. El tiempo de ejecución asíncrono es proporcionado por **Tokio**, lo que nos permite manejar miles de conexiones concurrentes con un uso mínimo de recursos.

### Apretón de Manos de Cifrado (Encryption Handshake)

Cada sesión comienza con un intercambio de claves **X25519**. Este apretón de manos Diffie-Hellman asegura que se establezca un secreto compartido sin transmitirlo nunca por la red. De este secreto compartido, derivamos claves de sesión usando **HKDF-SHA256**.

Todo el tráfico posterior se cifra utilizando **ChaCha20Poly1305**, un cifrado autenticado de alto rendimiento que funciona eficientemente incluso en procesadores móviles.

## Descubrimiento vía UDP

Para evitar la entrada manual de IP, xSend transmite paquetes de presencia en el puerto UDP `49872`. Cuando un par recibe este paquete, puede iniciar una conexión TCP al puerto anunciado por el remitente.

> Nota: Esto solo funciona dentro de la misma subred. Para transferencias WAN, estamos introduciendo un servidor Relay.

## Conclusión

Al aprovechar la criptografía moderna y la programación de sistemas, xSend proporciona una herramienta que es tanto simple de usar como matemáticamente segura.
