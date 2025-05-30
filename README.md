# Simulación de Envío y Recepción con Cifrado Asimétrico y Simétrico

Este proyecto simula un sistema de registro, autenticación y envío de mensajes cifrados entre dos partes utilizando cifrado híbrido: una combinación de criptografía simétrica (AES) y asimétrica (RSA). La solución se implementa en C# y tiene como objetivo demostrar el proceso completo de comunicación segura en una red no confiable.

---

## 🛠 Estructura del Proyecto

El proyecto consta de tres componentes principales:

- **ClaveSimetricaClass**: Clase que gestiona el cifrado y descifrado simétrico usando AES.
- **ClaveAsimetricaClass**: Clase que gestiona el cifrado y descifrado asimétrico con RSA, incluyendo la firma digital.
- **SimulacionEnvioRecepcion**: Clase principal que gestiona el flujo completo: registro/login, generación y envío del mensaje cifrado y firmado, y su posterior verificación.

---

## 🔐 Registro y Login

### Registro
El sistema permite al usuario registrarse proporcionando un nombre de usuario y una contraseña. Esta información se guarda en memoria en un diccionario. En una implementación real, estos datos deberían persistirse en una base de datos.

### Login
Para acceder al sistema, el usuario debe autenticarse con las credenciales previamente registradas. Solo tras un inicio de sesión exitoso se puede proceder a la simulación de comunicación segura.

---

## 📬 Simulación de Comunicación Segura

Una vez autenticado, se lleva a cabo el proceso de envío y recepción del mensaje entre un **emisor** y un **receptor** siguiendo el estándar de cifrado híbrido:

### 1. **Firma Digital (RSA)**
El emisor firma el mensaje original con su clave privada. Esto garantiza la autenticidad e integridad del mensaje.

### 2. **Cifrado del Mensaje (AES)**
El mensaje original se cifra usando una clave simétrica generada con AES. Esta técnica es mucho más eficiente para manejar bloques grandes de datos.

### 3. **Cifrado de la Clave Simétrica (RSA)**
La clave AES (compuesta por la clave y el vector de inicialización - IV) se concatena y cifra utilizando la clave pública del receptor. Esto garantiza que solo el receptor pueda descifrarla con su clave privada.

### 4. **Transmisión**
Se envían tres componentes cifrados:
- El mensaje cifrado
- La firma digital
- La clave AES cifrada con RSA

### 5. **Recepción**
El receptor realiza las siguientes acciones:
- Descifra la clave simétrica con su clave privada.
- Usa la clave e IV para descifrar el mensaje con AES.
- Verifica la firma digital usando la clave pública del emisor.

---

## ✅ Cumplimiento del Estándar de Seguridad

Este proyecto demuestra el uso correcto de:
- **RSA (asimétrico)** para el intercambio seguro de claves y la firma digital.
- **AES (simétrico)** para el cifrado eficiente de datos.
- **SHA-512** como algoritmo de hash para la firma digital.

Este modelo sigue las mejores prácticas de cifrado híbrido, el mismo enfoque que se utiliza en estándares como SSL/TLS para la comunicación segura en la web.

---

## 👥 Créditos

- La lógica de las clases `ClaveSimetrica` y `ClaveAsimetrica` fue proporcionada por el profesor.
- La clase `SimulacionEnvioRecepcion` fue parcialmente implementada por el profesor, pero se ha complementado con lógica adicional por los estudiantes para completar la simulación completa.

---

## 🧪 Ejemplo de uso

El sistema pregunta al usuario si desea registrarse. Si ya está registrado, puede iniciar sesión. Tras el login:
1. Se firma y cifra un mensaje.
2. Se cifra la clave AES con RSA.
3. El receptor descifra y verifica la firma del mensaje.

La consola muestra los datos cifrados y descifrados para su validación visual.

---

## 🔎 Preguntas teóricas
### 1. Explica el mecanismo de Registro / Login utilizado (máximo 5 líneas)

En el registro, el usuario introduce su contraseña y se genera un salt aleatorio. Luego se crea un hash seguro usando Rfc289DeriveBytes con SHA512 y 100.000 iteraciones. El hash y salt se almacenan en un diccionario. En el Login, se vuelve a calcular el hash con la contraseña introducida y el salt almacenado, y se compara con el hash guardado para autenticar al usuario.

---

### 2. Realiza una pequeña explicación de cada uno de los pasos que has hecho especificando el procedimiento que empleas en cada uno de ellos.

**LADO EMISOR**
1. Firmar mensaje.
```csharp
byte[] SignedMessage = Emisor.FirmarMensaje(TextoAEnviar_Bytes);
```
El emisor cifra el contenido del mensaje original con su propia clave privada de  la clase RSA. En esta función se genera un hash SHA-512 del mensaje y se cifra el hash con la clave privada del emisor (solo descifrable con su clave pública).
Esto garantiza la autenticidad e integridad del mensaje.

2. Cifrar mensaje.
```csharp
byte[] EncryptedMessage = ClaveSimetricaEmisor.CifrarMensaje(TextoAEnviar);
```
El mensaje original se cifra mediante criptografía simétrica (AES). Esto supone confidencialidad, ya que solo aquella persona que tenga acceso a la clave  e IV utilizados (es decir, la key e IV de ClaveSimetricaEmisor) tendrá la posibilidad de conocer el contenido del mensaje original.

3. Cifrar clave simétrica.
```csharp
byte [] SimetricKey = ClaveSimetricaEmisor.Key.Concat(ClaveSimetricaEmisor.IV).ToArray();
RSAParameters RPublicKey = Receptor.RSA.ExportParameters(false);
byte [] EncryptedSimetricKey = Emisor.CifrarMensaje(SimetricKey, RPublicKey);
```
Si enviáramos la clave simétrica utilizada con texto plano, la confidencialidad del mensaje sería comprometida. Por ello, enviamos la clave utilizando criptografía asimétrica (RSA). Se concatenan la clave (largo fijo de 32 bytes) y el IV (largo fijo de 16 bytes) en un solo array, y después se cifra con la clave pública del receptor (RPublicKey).
Al hacerlo de esta manera, solo el receptor (quién posee la clave privada) podrá descifrar el contenido de la clave simétrica.

**LADO RECEPTOR**
1. Descifrar clave simétrica.
```csharp
byte[] DecryptedSimetricKey = Receptor.DescifrarMensaje(EncryptedSimetricKey);
byte[] Key = new byte[32];
byte[] IV = new byte[16];
Array.Copy(DecryptedSimetricKey, 0, Key, 0, Key.Length);
Array.Copy(DecryptedSimetricKey, Key.Length, IV, 0, IV.Length);
```
El receptor usa la clave privada para descifrar la clave simétrica enviada. Tras descifrarla, extrae del array la key y el IV por separado.

2. Descifrar mensaje.
```csharp
string DecryptedMessage = ClaveSimetricaReceptor.DescifrarMensaje(EncryptedMessage, Key, IV);
```
Una vez contamos con la clave y el IV utilizados para cifrar el mensaje original, el receptor descifra el mensaje.

3. Comprobar firma y mostrar el mensaje.
```csharp
RSAParameters EPublicKey = Emisor.RSA.ExportParameters(false);
bool IsValidSign = Receptor.ComprobarFirma(SignedMessage, Encoding.UTF8.GetBytes(DecryptedMessage), EPublicKey);

Console.WriteLine("\nDATOS RECIBIDOS");
if (IsValidSign)
{
	Console.WriteLine("\tFirma verificada correctamente: OK");
	Console.WriteLine($"\tClave Simétrica (descifrada): {BytesToStringHex(DecryptedSimetricKey)}");
    Console.WriteLine($"\tMensaje recibido: {DecryptedMessage}");
}
else
{
	Console.WriteLine("\tFirma no válida");
}
```

Finalmente, el receptor verifica la validez de la firma digital usando la clave pública del emisor, el mensaje descifrado y la firma recibida.
Este paso garantiza que el mensaje no ha sido modificado.

---

### 3. Una vez realizada la práctica, ¿crees que alguno de los métodos programado en la clase asimétrica se podría eliminar por carecer de una utilidad real?
Sí, eliminaría dos métodos:
1. `FirmarMensaje (byte[] MensajeBytes, RSAParameters ClavePublicaExterna)`.
**Explicación:** No se puede realizar una firma con una clave pública.

2. `DescifrarMensaje (byte[] MensajeCifradoBytes, RSAParameters ClavePublicaExterna)`.
**Explicación:** No tiene sentido en una comunicación segura y confidencial que se pueda descifrar el contenido de la comunicación con una clave conocida por cualquier usuario de la red.

Por otro lado, la clase `CifrarMensaje (byte[] MensajeBytes, RSAParameters ClavePublicaExterna)` sí es necesaria, pues queremos cifrar la clave simétrica con la clave pública del receptor, pero la línea `byte [] textoPlanoBytes = Encoding.UTF8.GetBytes("hola");` carece totalmente de utilidad.
