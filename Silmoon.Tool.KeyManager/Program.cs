// See https://aka.ms/new-console-template for more information
using Silmoon;
using Silmoon.Core.Authorization;
using Silmoon.Core;
using Silmoon.Extension;
using Silmoon.Secure;
using System;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Text.Json;
using System.Runtime.InteropServices;

internal class Program
{
    public static string DefaultKeyFilePath
    {
        get
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return "C:\\_smkey.raw";
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return "/var/_smkey.raw";
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return "/usr/local/_smkey.raw";
            }

            throw new PlatformNotSupportedException("Unsupported operating system.");
        }
    }
    private static void Main(string[] args)
    {
        Entry(args);
    }

    static void Entry(string[] args)
    {
        Args.ParseArgs(args);
        if (Args.ArgsArray.IsNullOrEmpty())
            Help();
        else
        {
            switch (Args.ArgsArray[0].ToLower())
            {
                case "help":
                    Help();
                    break;
                case "generatekey":
                    GenerateKeyFile(Args.GetParameter("force") is not null);
                    break;
                case "view":
                    ViewKeyFile();
                    break;
                case "removekey":
                    RemoveKeyFile();
                    break;
                case "encodeuri":
                    EncodeUri();
                    break;
                case "decodeuri":
                    DecodeUri();
                    break;
                default:
                    Console.WriteLine($"Unknown command: {Args.ArgsArray[0]}");
                    break;
            }
        }
    }

    static void GenerateKeyFile(bool? noCheckFileExists)
    {
        if (File.Exists(DefaultKeyFilePath) && noCheckFileExists.HasValue && !noCheckFileExists.Value)
        {
            Console.WriteLine("Key file already exists! Overwrite? [y/n]");
            var readLine = Console.ReadLine().ToLower();
            if (readLine == "y")
            {
                File.SetAttributes(DefaultKeyFilePath, FileAttributes.Normal);
                GenerateKeyFile(true);
            }
            else
            {
                Console.WriteLine("Operation cancelled.");
            }
        }
        else
        {
            var password = Args.GetParameter("password");
            if (password.IsNullOrEmpty()) password = HashHelper.RandomChars(32);

            var keyFile = KeyManager.GenerateEncryptedKeyString(password);

            File.WriteAllText(DefaultKeyFilePath, keyFile);
            File.SetAttributes(DefaultKeyFilePath, FileAttributes.Hidden);
            Console.WriteLine("Key file generated successfully.");
            Console.WriteLine($"Password: {password}");
            Console.WriteLine($"Key file saved to {DefaultKeyFilePath}");
            Console.WriteLine("Press any key to close.");
            Console.ReadKey();
        }
    }
    static void ViewKeyFile()
    {
        if (File.Exists(DefaultKeyFilePath))
        {
            var password = Args.GetParameter("password");
            if (password.IsNullOrEmpty())
            {
                Console.WriteLine("Password is required to view the key file.");
            }
            else
            {
                var fileContent = File.ReadAllText(DefaultKeyFilePath);
                var result = KeyManager.DecodeEncryptedKeyString(fileContent, password);
                if (result.State)
                {
                    Console.WriteLine($"Name:\n{result.Data.Name}\n");
                    Console.WriteLine($"HashId:\n{result.Data.HashId}\n");
                    Console.WriteLine($"PublicKey:\n{result.Data.PublicKey}\n");
                    Console.WriteLine($"PrivateKey:\n{result.Data.PrivateKey}\n");
                }
                else
                    Console.WriteLine($"[ERROR] {result.Message}");
            }
        }
        else
        {
            Console.WriteLine("No key file found.");
        }
    }

    static void RemoveKeyFile(bool force = false)
    {
        if (File.Exists(DefaultKeyFilePath))
        {
            if (!force)
            {
                Console.WriteLine("Are you sure you want to remove the key file? [y/n]");
                var readLine = Console.ReadLine().ToLower();
                if (readLine == "n")
                {
                    Console.WriteLine("Operation cancelled.");
                    return;
                }
            }
            File.Delete(DefaultKeyFilePath);
            Console.WriteLine("Key file removed successfully.");
        }
        else
        {
            Console.WriteLine("No key file found.");
        }
    }
    static void EncodeUri()
    {
        if (File.Exists(DefaultKeyFilePath))
        {
            var password = Args.GetParameter("password");
            var clearData = Args.GetParameter("data");

            if (password.IsNullOrEmpty() || clearData.IsNullOrEmpty())
            {
                Console.WriteLine("Use the parameter --password or -p to specify the key password, and use the parameter --data or -d to specify the encrypted plaintext information.\r\nFor example: smkm encodeuri -p \"PASSWORD\" -d \"PLAINTEXT\"");
                return;
            }

            var fileContent = File.ReadAllText(DefaultKeyFilePath);

            var result = KeyManager.DecodeEncryptedKeyString(fileContent, password);
            if (result.State)
            {
                var uri = clearData.KeyFileEncryptToSmkmUri(password);
                Console.WriteLine(uri);
            }
            else
                Console.WriteLine($"[ERROR] {result.Message}");
        }
        else
            Console.WriteLine("No key file found.");
    }
    static void DecodeUri()
    {
        var cipherText = Args.GetParameter("data");

        if (cipherText.IsNullOrEmpty())
        {
            Console.WriteLine("Use the parameter --data or -d to specify the ciphertext in smkm uri format.\r\nFor example: smkm decodeuri -d \"smkm://CIPHERTEXT\"");
            return;
        }
        var result = cipherText.TryKeyFileDecryptSmkmUri();
        Console.WriteLine(result);
    }
    static void Help()
    {
        Console.WriteLine("Silmoon authorization/license key management utility.");
        Console.WriteLine();
        Console.WriteLine("generatekey\tGenerates a key file on the local machine at the default path.");
        Console.WriteLine("\t\t--force\t\tForce overwrite if the file already exists.");
        Console.WriteLine();
        Console.WriteLine("removekey\tRemoves the key file from the local machine's default path.");
        Console.WriteLine("\t\t--force\t\tForce removal.");
        Console.WriteLine();
        Console.WriteLine("view\t\tDisplays the key file from the local machine's default path.");
        Console.WriteLine();
        Console.WriteLine("encodeuri\tGenerates an SMKMURI.");
        Console.WriteLine();
        Console.WriteLine("decodeuri\tDecodes an SMKMURI.");
    }
}
