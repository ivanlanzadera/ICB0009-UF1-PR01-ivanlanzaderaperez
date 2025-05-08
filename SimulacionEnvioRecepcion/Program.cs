using System;
using System.Text;
using System.Security.Cryptography;
using ClaveSimetricaClass;
using ClaveAsimetricaClass;

namespace SimulacionEnvioRecepcion
{
    class Program
    {   
        static Dictionary<string, string> credentials = []; 
        static ClaveAsimetrica Emisor = new ClaveAsimetrica();
        static ClaveAsimetrica Receptor = new ClaveAsimetrica();
        static ClaveSimetrica ClaveSimetricaEmisor = new ClaveSimetrica();
        static ClaveSimetrica ClaveSimetricaReceptor = new ClaveSimetrica();

        static string TextoAEnviar = "Me he dado cuenta que incluso las personas que dicen que todo está predestinado y que no podemos hacer nada para cambiar nuestro destino igual miran antes de cruzar la calle. Stephen Hawking.";
        
        static void Main(string[] args)
        {

            /****PARTE 1****/
            //Login / Registro
            Console.WriteLine ("¿Deseas registrarte? (S/N)");
            string registro = Console.ReadLine()!.ToUpper();

            if (registro == "S")
            {
                //Realizar registro del cliente
                Registro();                
            }

            //Realizar login
            bool login = Login();

            /***FIN PARTE 1***/

            if (login)
            {                  
                byte[] TextoAEnviar_Bytes = Encoding.UTF8.GetBytes(TextoAEnviar); 
                
                /**** LADO EMISOR ****/
                //Firmar mensaje
                byte[] SignedMessage = Emisor.FirmarMensaje(TextoAEnviar_Bytes);

                //Cifrar mensaje con la clave simétrica
                byte[] EncryptedMessage = ClaveSimetricaEmisor.CifrarMensaje(TextoAEnviar);

                //Cifrar clave simétrica con la clave pública del receptor
                /**
                    Para cifrar y enviar el key y el IV concatenamos los bytes en un mismo array y lo enviamos cifrado.
                    Cuando el receptor lo recoja y descifre, tendrá que tener en cuenta que el lenght de los elementos es fijo:
                        - Key: 32 bytes long
                        - IV: 16 bytes long
                */

                byte [] SimetricKey = ClaveSimetricaEmisor.Key.Concat(ClaveSimetricaEmisor.IV).ToArray();
                RSAParameters RPublicKey = Receptor.RSA.ExportParameters(false);
                byte [] EncryptedSimetricKey = Emisor.CifrarMensaje(SimetricKey, RPublicKey);

                Console.WriteLine("DATOS A ENVIAR (Encriptados)");
                Console.WriteLine($"\tFirma: {BytesToStringHex(SignedMessage)}");
                Console.WriteLine($"\tMensaje: {BytesToStringHex(EncryptedMessage)}");
                Console.WriteLine($"\tClave Simétrica: {BytesToStringHex(EncryptedSimetricKey)}");

                Console.WriteLine("\nPresiona Enter para ver los datos recibidos...");
                Console.ReadLine();
                
                
                
                /**** LADO RECEPTOR ****/
                //Descifrar clave simétrica
                byte[] DecryptedSimetricKey = Receptor.DescifrarMensaje(EncryptedSimetricKey);
                byte[] Key = new byte[32];
                byte[] IV = new byte[16];

                Array.Copy(DecryptedSimetricKey, 0, Key, 0, Key.Length);
                Array.Copy(DecryptedSimetricKey, Key.Length, IV, 0, IV.Length);

                //Descifrar mensaje con la clave simétrica
                string DecryptedMessage = ClaveSimetricaReceptor.DescifrarMensaje(EncryptedMessage, Key, IV);

                //Comprobar firma
                // Obtener las claves publicas del emisor
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
            }
        }

        public static void Registro()
        {
            Console.WriteLine ("Indica tu nombre de usuario:");
            string UserName = Console.ReadLine()!;
            //Una vez obtenido el nombre de usuario lo guardamos en la variable UserName y este ya no cambiará 

            Console.WriteLine ("Indica tu password:");
            string passwordRegister = Console.ReadLine()!;
            //Una vez obtenido el passoword de registro debemos tratarlo como es debido para almacenarlo correctamente a la variable SecurePass

            /***PARTE 1***/
            /*Añadir el código para poder almacenar el password de manera segura*/
            // Obtener Salt y conservar el salt
            string Salt = SaltGenerator();

            // Generamos Hash de la contraseña con salt
            string HashedCredential = GenerateHash(Salt, passwordRegister);

            // Registramos los datos de acceso en nuestro diccionario global
            credentials["username"] = UserName;
            credentials["salt"] = Salt;
            credentials["hash"] = HashedCredential;
        }


        public static bool Login()
        {
            bool auxlogin = false;
            do
            {
                Console.WriteLine ("\nAcceso a la aplicación");
                Console.WriteLine ("Usuario: ");
                string userName = Console.ReadLine()!;

                Console.WriteLine ("Password: ");
                string Password = Console.ReadLine()!;

                /***PARTE 1***/
                /*Modificar esta parte para que el login se haga teniendo en cuenta que el registro se realizó con SHA512 y salt*/
                try
                {
                    if (credentials["username"] == userName)
                    {
                        // Verificar contraseña introducida
                        string hash = GenerateHash(credentials["salt"], Password);
                        if (hash == credentials["hash"])
                        {
                            auxlogin = true;
                            Console.WriteLine($"\nLogin Correcto. ¡Bienvenido, {credentials["username"]}!\n");
                        } else
                        {
                            Console.WriteLine("Error: La contraseña introducida no es válida.");
                        }
                    } else 
                    {
                        Console.WriteLine("Error: El nombre de usuario introducido no es válido.");
                    }
                } catch (Exception)
                {
                    Console.WriteLine("\nERROR: No puedes iniciar sesión, pues no te has registrado en la plataforma");
                    return false;
                }
            }while (!auxlogin);

            return auxlogin;
        }

        static string BytesToStringHex (byte[] result)
        {
            StringBuilder stringBuilder = new StringBuilder();

            foreach (byte b in result)
                stringBuilder.AppendFormat("{0:x2}", b);

            return stringBuilder.ToString();
        }

        static string SaltGenerator ()
        {
            byte[] salt = new byte[32];
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);
            return BytesToStringHex(salt);;
        }

        static string GenerateHash (string salt, string credential)
        {
            /** BCRYPT con SHA512 **/
            int iterations = 100000;
            Rfc2898DeriveBytes bcrypt = new (
                Encoding.UTF8.GetBytes(credential),
                Encoding.UTF8.GetBytes(salt),
                iterations,
                hashAlgorithm: HashAlgorithmName.SHA512);
            
            byte[] hash = bcrypt.GetBytes(32);
            
            return BytesToStringHex(hash);
        }
    }
}
