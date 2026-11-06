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
        if (args.Length != 4)
        {
            MostrarAyuda();
            return;
        }

        string accion = args[0].ToLower();
        string entrada = args[1];
        string salida = args[2];
        string contrasena = args[3];

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

        try
        {
            if (accion == "cifrar")
            {
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

    static void Cifrar(string entrada, string salida, string contrasena)
    {
        byte[] datos = File.ReadAllBytes(entrada);

        // Generamos una sal y un IV aleatorios.
        byte[] sal = new byte[16];
        byte[] iv = new byte[16];

        using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(sal);
            rng.GetBytes(iv);
        }

        // Sacamos dos claves diferentes a partir de la contraseña.
        byte[] claves;
        using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(
            contrasena, sal, 600000, HashAlgorithmName.SHA256))
        {
            claves = pbkdf2.GetBytes(64);
        }

        byte[] claveAes = new byte[32];
        byte[] claveHmac = new byte[32];
        Array.Copy(claves, 0, claveAes, 0, 32);
        Array.Copy(claves, 32, claveHmac, 0, 32);

        // Ciframos con AES-256 en modo CBC.
        byte[] cifrado;
        using (Aes aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.Key = claveAes;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (MemoryStream memoria = new MemoryStream())
            {
                using (CryptoStream crypto = new CryptoStream(
                    memoria, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    crypto.Write(datos, 0, datos.Length);
                    crypto.FlushFinalBlock();
                    cifrado = memoria.ToArray();
                }
            }
        }

        // Hacemos el HMAC con la sal, el IV y el contenido cifrado.
        byte[] datosHmac = new byte[32 + cifrado.Length];
        Array.Copy(sal, 0, datosHmac, 0, 16);
        Array.Copy(iv, 0, datosHmac, 16, 16);
        Array.Copy(cifrado, 0, datosHmac, 32, cifrado.Length);

        byte[] firma;
        using (HMACSHA256 hmac = new HMACSHA256(claveHmac))
        {
            firma = hmac.ComputeHash(datosHmac);
        }

        // Guardamos: sal + IV + HMAC + contenido cifrado.
        byte[] archivoFinal = new byte[64 + cifrado.Length];
        Array.Copy(sal, 0, archivoFinal, 0, 16);
        Array.Copy(iv, 0, archivoFinal, 16, 16);
        Array.Copy(firma, 0, archivoFinal, 32, 32);
        Array.Copy(cifrado, 0, archivoFinal, 64, cifrado.Length);

        using (FileStream fichero = new FileStream(salida, FileMode.CreateNew))
        {
            fichero.Write(archivoFinal, 0, archivoFinal.Length);
        }

        Console.WriteLine("Archivo cifrado correctamente.");
    }

    static void Descifrar(string entrada, string salida, string contrasena)
    {
        byte[] archivo = File.ReadAllBytes(entrada);

        if (archivo.Length < 80 || (archivo.Length - 64) % 16 != 0)
        {
            Console.WriteLine("Error: el archivo .caja no tiene el formato correcto.");
            return;
        }

        // Separamos los cuatro bloques del archivo.
        byte[] sal = new byte[16];
        byte[] iv = new byte[16];
        byte[] firmaGuardada = new byte[32];
        byte[] cifrado = new byte[archivo.Length - 64];
        Array.Copy(archivo, 0, sal, 0, 16);
        Array.Copy(archivo, 16, iv, 0, 16);
        Array.Copy(archivo, 32, firmaGuardada, 0, 32);
        Array.Copy(archivo, 64, cifrado, 0, cifrado.Length);

        // Obtenemos las mismas claves usando la contraseña y la sal guardada.
        byte[] claves;
        using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(
            contrasena, sal, 600000, HashAlgorithmName.SHA256))
        {
            claves = pbkdf2.GetBytes(64);
        }

        byte[] claveAes = new byte[32];
        byte[] claveHmac = new byte[32];
        Array.Copy(claves, 0, claveAes, 0, 32);
        Array.Copy(claves, 32, claveHmac, 0, 32);

        // Primero comprobamos el HMAC. Si no coincide, no desciframos.
        byte[] datosHmac = new byte[32 + cifrado.Length];
        Array.Copy(sal, 0, datosHmac, 0, 16);
        Array.Copy(iv, 0, datosHmac, 16, 16);
        Array.Copy(cifrado, 0, datosHmac, 32, cifrado.Length);

        byte[] firmaCalculada;
        using (HMACSHA256 hmac = new HMACSHA256(claveHmac))
        {
            firmaCalculada = hmac.ComputeHash(datosHmac);
        }

        // Comparamos todos los bytes del HMAC, sin salir a mitad del bucle.
        int diferencia = 0;
        for (int i = 0; i < 32; i++)
        {
            diferencia |= firmaGuardada[i] ^ firmaCalculada[i];
        }

        if (diferencia != 0)
        {
            Console.WriteLine("Error: contraseña incorrecta o archivo modificado.");
            return;
        }

        // Solo desciframos cuando el HMAC es correcto.
        byte[] recuperado;
        using (Aes aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.Key = claveAes;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (MemoryStream memoria = new MemoryStream(cifrado))
            using (CryptoStream crypto = new CryptoStream(
                memoria, aes.CreateDecryptor(), CryptoStreamMode.Read))
            using (MemoryStream resultado = new MemoryStream())
            {
                crypto.CopyTo(resultado);
                recuperado = resultado.ToArray();
            }
        }

        using (FileStream fichero = new FileStream(salida, FileMode.CreateNew))
        {
            fichero.Write(recuperado, 0, recuperado.Length);
        }

        Console.WriteLine("Archivo descifrado correctamente.");
    }

    static void MostrarAyuda()
    {
        Console.WriteLine("Uso del programa:");
        Console.WriteLine("CajaFuerte_Zaidi_Sert cifrar archivo.txt archivo.caja contraseña");
        Console.WriteLine("CajaFuerte_Zaidi_Sert descifrar archivo.caja recuperado.txt contraseña");
    }
}