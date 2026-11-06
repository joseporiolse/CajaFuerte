/*
Formato del archivo .caja:
Bytes 0 al 15: sal (16 bytes).
Bytes 16 al 31: IV (16 bytes).
Bytes 32 al 63: HMAC-SHA256 (32 bytes).
Desde el byte 64: contenido cifrado con AES-256 CBC.

El tamaño del contenido cifrado es variable y múltiplo de 16 bytes.
La sal y el IV se generan de nuevo cada vez que se cifra.
*/

using System;
using System.IO;
using System.Security.Cryptography;

class Program
{
    static void Main(string[] args)
    {
        //Comprobamos que el usuario haya introducido 4 argumentos
        if (args.Length != 4)
        {
            MostrarAyuda();
            return;
        }

        //Guardamos los argumentos introducidos por el usuario
        string accion = args[0].ToLower(); //cifrar o descifrar
        string entrada = args[1]; //ruta archivo original
        string salida = args[2]; //ruta donde se guardara el resultado
        string contrasena = args[3]; //contiene la contraseña

        //Comprobamos que la contraseña sea válida y que los archivos existan o no según corresponda
        if (string.IsNullOrWhiteSpace(contrasena))
        {
            Console.WriteLine("Error: debes indicar una contraseña.");
            return;
        }

        if (!File.Exists(entrada))
        {
            Console.WriteLine("Error: el archivo de entrada no existe.");
            return;
        }

        if (File.Exists(salida))
        {
            Console.WriteLine("Error: el archivo de salida ya existe.");
            return;
        }

        //Intentamos ejecutar y controlamos los errores
        try
        {
            if (accion == "cifrar")
            {
                //Comprobamos que la entrada sea .txt y la salida .caja
                if (Path.GetExtension(entrada).ToLower() != ".txt" ||
                    Path.GetExtension(salida).ToLower() != ".caja")
                {
                    Console.WriteLine("Error: para cifrar necesitas un .txt y una salida .caja.");
                    return;
                }

                Cifrar(entrada, salida, contrasena);
            }
            else if (accion == "descifrar")
            {
                //Comprobamos que el archivo de entrada sea .caja
                if (Path.GetExtension(entrada).ToLower() != ".caja")
                {
                    Console.WriteLine("Error: el archivo de entrada debe ser .caja.");
                    return;
                }

                Descifrar(entrada, salida, contrasena);
            }
            else
            {
                MostrarAyuda();
            }
        }
        catch (IOException)
        {
            Console.WriteLine("Error: no se ha podido leer o guardar el archivo.");
        }
        catch (UnauthorizedAccessException)
        {
            Console.WriteLine("Error: no tienes permiso para acceder al archivo.");
        }
        catch (CryptographicException)
        {
            Console.WriteLine("Error: no se ha podido procesar el archivo.");
        }
        catch (ArgumentException)
        {
            Console.WriteLine("Error: la ruta del archivo no es válida.");
        }
    }

    //Ciframos el archivo utilizando AES-256
    static void Cifrar(string entrada, string salida, string contrasena)
    {
        byte[] datos = File.ReadAllBytes(entrada);

        byte[] sal = new byte[16]; //Para conseguir una clave diferente en cada archivo
        byte[] iv = new byte[16]; //Para que el cifrado no sea siempre igual

        //Generamos la sal y el IV de forma aleatoria y segura
        using (RandomNumberGenerator generadorAleatorio = RandomNumberGenerator.Create())
        {
            generadorAleatorio.GetBytes(sal);
            generadorAleatorio.GetBytes(iv);
        }

        //Sacamos 64 bytes de la contraseña y la sal usando PBKDF2 con SHA256 y 600000 iteraciones
        byte[] claves;
        using (Rfc2898DeriveBytes generadorClaves = new Rfc2898DeriveBytes(
            contrasena, sal, 600000, HashAlgorithmName.SHA256))
        {
            claves = generadorClaves.GetBytes(64);
        }

        //Separamos los 64 bytes en dos claves diferentes
        byte[] claveAes = new byte[32]; //Para cifrar
        byte[] claveHmac = new byte[32]; //Para comprobar modificaciones

        Array.Copy(claves, 0, claveAes, 0, 32);
        Array.Copy(claves, 32, claveHmac, 0, 32);

        byte[] cifrado;

        //Configuramos AES con una clave de 256 bits y el modo CBC
        using (Aes aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.Key = claveAes;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            //Ciframos los datos y guardamos el resultado en memoria
            using (MemoryStream memoria = new MemoryStream())
            {
                using (CryptoStream procesoCifrado = new CryptoStream(
                    memoria, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    procesoCifrado.Write(datos, 0, datos.Length);
                    procesoCifrado.FlushFinalBlock();
                    cifrado = memoria.ToArray();
                }
            }
        }

        //Preparamos la sal, el IV y el cifrado para comprobar su integridad
        byte[] datosHmac = new byte[32 + cifrado.Length];

        Array.Copy(sal, 0, datosHmac, 0, 16);
        Array.Copy(iv, 0, datosHmac, 16, 16);
        Array.Copy(cifrado, 0, datosHmac, 32, cifrado.Length);

        //Calculamos el HMAC para detectar posibles modificaciones
        byte[] firma;
        using (HMACSHA256 hmac = new HMACSHA256(claveHmac))
        {
            firma = hmac.ComputeHash(datosHmac);
        }

        //Preparamos el archivo final con la sal, IV, HMAC y contenido cifrado
        byte[] archivoFinal = new byte[64 + cifrado.Length];

        Array.Copy(sal, 0, archivoFinal, 0, 16);
        Array.Copy(iv, 0, archivoFinal, 16, 16);
        Array.Copy(firma, 0, archivoFinal, 32, 32);
        Array.Copy(cifrado, 0, archivoFinal, 64, cifrado.Length);

        //Guardamos el archivo .caja sin sobrescribir otros archivos
        using (FileStream fichero = new FileStream(salida, FileMode.CreateNew))
        {
            fichero.Write(archivoFinal, 0, archivoFinal.Length);
        }

        Console.WriteLine("Archivo cifrado correctamente.");
    }

    //Desciframos el archivo para recuperar el contenido original
    static void Descifrar(string entrada, string salida, string contrasena)
    {
        byte[] archivo = File.ReadAllBytes(entrada);

        //Comprobamos que tenga un tamaño correcto y bloques de 16 bytes
        if (archivo.Length < 80 || (archivo.Length - 64) % 16 != 0)
        {
            Console.WriteLine("Error: el archivo .caja no tiene el formato correcto.");
            return;
        }

        //Separamos los datos que contiene el archivo
        byte[] sal = new byte[16];
        byte[] iv = new byte[16];
        byte[] firmaGuardada = new byte[32];
        byte[] cifrado = new byte[archivo.Length - 64];

        Array.Copy(archivo, 0, sal, 0, 16);
        Array.Copy(archivo, 16, iv, 0, 16);
        Array.Copy(archivo, 32, firmaGuardada, 0, 32);
        Array.Copy(archivo, 64, cifrado, 0, cifrado.Length);

        //Sacamos las mismas claves usando la contraseña y la sal guardada
        byte[] claves;
        using (Rfc2898DeriveBytes generadorClaves = new Rfc2898DeriveBytes(
            contrasena, sal, 600000, HashAlgorithmName.SHA256))
        {
            claves = generadorClaves.GetBytes(64);
        }

        byte[] claveAes = new byte[32];
        byte[] claveHmac = new byte[32];

        Array.Copy(claves, 0, claveAes, 0, 32);
        Array.Copy(claves, 32, claveHmac, 0, 32);

        //Preparamos los datos para comprobar si se han modificado
        byte[] datosHmac = new byte[32 + cifrado.Length];

        Array.Copy(sal, 0, datosHmac, 0, 16);
        Array.Copy(iv, 0, datosHmac, 16, 16);
        Array.Copy(cifrado, 0, datosHmac, 32, cifrado.Length);

        //Calculamos el HMAC y lo comparamos con el que estaba guardado
        byte[] firmaCalculada;
        using (HMACSHA256 hmac = new HMACSHA256(claveHmac))
        {
            firmaCalculada = hmac.ComputeHash(datosHmac);
        }

        //Comparamos todos los bytes sin detenernos antes de tiempo
        int diferencia = 0;

        for (int i = 0; i < 32; i++)
        {
            diferencia |= firmaGuardada[i] ^ firmaCalculada[i];
        }

        //Si no coinciden rechazamos el archivo
        if (diferencia != 0)
        {
            Console.WriteLine("Error: contraseña incorrecta o archivo modificado.");
            return;
        }

        byte[] recuperado;

        //Desciframos usando la misma configuración AES
        using (Aes aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.Key = claveAes;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (MemoryStream memoria = new MemoryStream(cifrado))
            using (CryptoStream procesoDescifrado = new CryptoStream(
                memoria, aes.CreateDecryptor(), CryptoStreamMode.Read))
            using (MemoryStream resultado = new MemoryStream())
            {
                procesoDescifrado.CopyTo(resultado);
                recuperado = resultado.ToArray();
            }
        }

        //Guardamos el archivo descifrado sin sobrescribir otros archivos
        using (FileStream fichero = new FileStream(salida, FileMode.CreateNew))
        {
            fichero.Write(recuperado, 0, recuperado.Length);
        }

        Console.WriteLine("Archivo descifrado correctamente.");
    }

    //Mostramos las instrucciones para utilizar el programa
    static void MostrarAyuda()
    {
        Console.WriteLine("Uso del programa:");
        Console.WriteLine("CajaFuerte_Zaidi_Sert cifrar archivo.txt archivo.caja contraseña");
        Console.WriteLine("CajaFuerte_Zaidi_Sert descifrar archivo.caja recuperado.txt contraseña");
    }
}
