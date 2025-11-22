# Sistema de Autenticación HMAC

Sistema web de autenticación segura que implementa HMAC (Hash-based
Message Authentication Code) para verificar la integridad de mensajes.

## Requisitos

-   Python 3.7+
-   Flask
-   SQLite3 (incluido en Python)

## Instalación

1.  Clonar o descargar el proyecto:

    ``` bash
    cd c:\Users\Lenovo\Downloads\proyecto_hmac
    ```

2.  Instalar dependencias:

    ``` bash
    pip install flask
    ```

## Ejecución

Iniciar la aplicación:

``` bash
python app.py
```

Abrir en el navegador:

    http://127.0.0.1:5000

## Usuarios Precargados

  Usuario   Contraseña
  --------- ---------------
  alice     AlicePass123
  bob       BobSecure456
  charlie   Charlie789!
  diana     Diana@2024
  eve       EveHacker\$\$
  frank     Frank#Pass1
  grace     Grace_2024
  henry     Henry!Secure
  iris      Iris@Pass99
  jack      Jack\$2024!

## Funcionalidades

-   Registro de usuarios: validación de campos y hash SHA-256 con salt
    aleatorio.
-   Autenticación: login con generación de HMAC y verificación manual.
-   Visualización de base de datos: mostrar usuarios, hashes y salt.

## Flujo de Autenticación

1.  Usuario ingresa credenciales.
2.  Sistema verifica hash de contraseña con salt.
3.  Genera mensaje `usuario|timestamp`.
4.  Calcula HMAC del mensaje.
5.  Muestra HMAC generado para verificación.

## Verificación de HMAC

-   **Automática:** campo HMAC vacío, login exitoso muestra HMAC.
-   **Manual:** ingresar HMAC incorrecto para simular ataque; resultado
    en consola.

## Estructura del Proyecto

    proyecto_hmac/
    ├── app.py                    # Aplicación principal Flask
    ├── users.db                  # Base de datos SQLite
    ├── database/
    │   └── db.py                 # Gestión de base de datos
    ├── services/
    │   └── hmac_service.py       # Lógica de HMAC
    └── templates/
        ├── index.html            # Página de registro
        ├── login.html            # Página de login
        └── db.html               # Vista de base de datos

## Seguridad

-   Hash SHA-256 con salt único.
-   HMAC para integridad de mensajes.
-   Timestamps para prevenir replay attacks.
-   Validación de credenciales.

## Pruebas Sugeridas

-   Login exitoso: alice / AlicePass123.
-   Login fallido: alice / wrongpassword.
-   Usuario inexistente: noexiste / cualquierpass.
-   HMAC inválido: login con HMAC manual incorrecto.
-   Registro nuevo: crear usuario con contraseña válida.

## Notas

-   La base de datos se crea automáticamente al iniciar.
-   Logs solo se muestran en consola.
-   Para reiniciar la BD, eliminar `users.db` y reiniciar la app.

## Soporte

Más información sobre HMAC: RFC 2104
