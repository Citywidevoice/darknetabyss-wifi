# WiFi Manager para Kali Linux

Una herramienta de red completa para el análisis WiFi, escaneo de dispositivos y desconexión selectiva de dispositivos. Esta herramienta proporciona una interfaz simple basada en terminal para monitorear tu red WiFi, identificar dispositivos conectados y desconectar selectivamente dispositivos no deseados.

## Características

- **Información WiFi**: Muestra información detallada sobre la red WiFi actualmente conectada, incluyendo SSID, BSSID, canal, intensidad de señal y tipo de seguridad.
- **Escaneo de Dispositivos**: Escanea e identifica todos los dispositivos conectados a tu red WiFi.
- **Identificación de Dispositivos**: Intenta identificar el tipo y fabricante de los dispositivos conectados.
- **Desconexión Selectiva**: Desconecta selectivamente dispositivos específicos de tu red utilizando paquetes de desautenticación.

## Prerrequisitos

Esta herramienta está diseñada específicamente para Kali Linux y requiere privilegios de root para funcionar correctamente. Utiliza varias herramientas potentes de red que vienen preinstaladas con Kali Linux.

### Dependencias Requeridas

- **Suite aircrack-ng** (airmon-ng, airodump-ng, aireplay-ng): Para monitoreo inalámbrico e inyección de paquetes
- **nmap**: Para escaneo de red e identificación de dispositivos
- **macchanger**: Para operaciones de direcciones MAC e identificación de fabricantes
- **Network Manager (nmcli)**: Para información de conexión WiFi
- **ip**: Para información de interfaces de red

## Instalación

1. Clona o descarga el script en tu sistema Kali Linux.
2. Haz el script ejecutable:
   ```bash
   chmod +x wifimanager.sh
   ```

3. Asegúrate de que todas las dependencias estén instaladas:
   ```bash
   sudo apt update
   sudo apt install aircrack-ng nmap macchanger network-manager
   ```

## Uso

Ejecuta el script con privilegios de root:

```bash
sudo ./wifimanager.sh
```

## Funcionamiento

1. Al iniciar, el script muestra información detallada sobre tu conexión WiFi actual.
2. Desde el menú principal, puedes:
   - Actualizar la información WiFi
   - Escanear dispositivos conectados a tu red
   - Salir del programa

3. Al escanear dispositivos, la herramienta:
   - Cambia temporalmente tu interfaz WiFi a modo monitor
   - Captura tráfico de red para identificar dispositivos conectados
   - Intenta identificar el tipo/fabricante de cada dispositivo
   - Muestra una lista numerada de todos los dispositivos encontrados

4. Después del escaneo, puedes seleccionar un dispositivo para desconectarlo:
   - Introduce el número del dispositivo que deseas desconectar
   - Configura el número de paquetes de desautenticación a enviar
   - El script enviará los paquetes, desconectando temporalmente el dispositivo

## Consideraciones Legales

⚠️ **ADVERTENCIA**: El uso de esta herramienta para desconectar dispositivos de redes que no sean de tu propiedad puede ser ilegal en muchas jurisdicciones. Esta herramienta está destinada únicamente a fines educativos y de pruebas en redes de tu propiedad o en las que tengas permiso explícito para realizar pruebas.

## Solución de Problemas

- Si encuentras errores relacionados con dependencias faltantes, asegúrate de instalar todos los paquetes requeridos.
- Si tu adaptador WiFi no es compatible con el modo monitor, esta herramienta no funcionará correctamente.
- Para adaptadores WiFi externos, asegúrate de que sean compatibles con la inyección de paquetes.