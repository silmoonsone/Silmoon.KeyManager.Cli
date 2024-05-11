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


Entry(args);

static void Entry(string[] args)
{
    Args.ParseArgs(args);
    if (Args.ArgsArray.IsNullOrEmpty()) Console.WriteLine("Silmoon key file tool. \"smkm help\" for help information.");
    else
    {
        switch (Args.ArgsArray[0])
        {
            case "help":
                Help();
                break;
            case "generatekey":
                GenerateKeyFile(args.Contains("--force"));
                break;
            case "view":
                ViewKeyFile();
                break;
            case "removekey":
                RemoveKeyFile();
                break;
            case "encode":
                GenSMKMUri();
                break;
            case "decode":
                DecodeSMKMUri();
                break;
            default:
                Console.WriteLine("Unknown command (" + Args.ArgsArray[0] + ")");
                break;
        }
    }
}

static void GenerateKeyFile(bool? noCheckFileExists)
{
    if (File.Exists("C:\\_smkey.raw") && noCheckFileExists.HasValue && !noCheckFileExists.Value)
    {
        Console.WriteLine("id file is exists! overwrite? [y/n]");
        var readLine = Console.ReadLine().ToLower();
        if (readLine == "y")
        {
            File.SetAttributes("C:\\_smkey.raw", FileAttributes.Normal);
            GenerateKeyFile(true);
        }
        else
            Console.WriteLine("cancel.");
    }
    else
    {

        //var password = HashHelper.RandomChars(32);
        var password = Args.GetParameter("password");
        if (password.IsNullOrEmpty()) password = HashHelper.RandomChars(32);

        var keyFile = KeyManager.GenerateEncryptedKeyString(password);

        File.WriteAllText(@"C:\_smkey.raw", keyFile);
        File.SetAttributes(@"C:\_smkey.raw", FileAttributes.Hidden);
        Console.WriteLine("Password: " + password);
        Console.WriteLine("Success.");
        Console.WriteLine("push any key to close");
        Console.ReadKey();
    }
}
static void ViewKeyFile()
{
    if (File.Exists(@"C:\_smkey.raw"))
    {
        var password = Args.GetParameter("password");
        Console.WriteLine("password is " + password);
        var fileContent = File.ReadAllText(@"C:\_smkey.raw");

        var result = KeyManager.DecodeEncryptedKeyString(fileContent, password);
        if (result.State)
        {
            Console.WriteLine("Name:\r\n" + result.Data.Name + "\r\n");
            Console.WriteLine("HashId:\r\n" + result.Data.HashId + "\r\n");
            Console.WriteLine("PublicKey:\r\n" + result.Data.PublicKey + "\r\n");
            Console.WriteLine("PrivateKey:\r\n" + result.Data.PrivateKey + "\r\n");
        }
        else
            Console.WriteLine("[ERROR] " + result.Message);
    }
    else
        Console.WriteLine("No id file.");
}
static void RemoveKeyFile(bool force = false)
{
    if (File.Exists(@"C:\_smkey.raw"))
    {
        if (!force)
        {
            Console.WriteLine("Are you sure to remove id file? [y/n]");
            var readLine = Console.ReadLine().ToLower();
            if (readLine == "n")
            {
                Console.WriteLine("cancel.");
                return;
            }
        }
        File.Delete(@"C:\_smkey.raw");
        Console.WriteLine("Success.");
    }
    else
    {
        Console.WriteLine("No id file.");
    }
}
static void GenSMKMUri()
{
    if (File.Exists("C:\\_smkey.raw"))
    {
        var password = Args.GetParameter("password");
        var fileContent = File.ReadAllText(@"C:\_smkey.raw");

        var result = KeyManager.DecodeEncryptedKeyString(fileContent, password);
        if (result.State)
        {
            var clearData = Args.GetParameter("data");
            var uri = clearData.KeyFileEncryptToSmkmUri(password);
            Console.WriteLine(uri);
        }
        else
            Console.WriteLine("[ERROR] " + result.Message);
    }
    else
        Console.WriteLine("No id file.");
}
static void DecodeSMKMUri()
{
    var cipherText = Args.GetParameter("data");
    var s = cipherText.TryKeyFileDecryptSmkmUri();
    Console.WriteLine(s);
}
static void Help()
{
    Console.WriteLine("Silmoon authorization/license key manager utility.");
    Console.WriteLine();
    Console.WriteLine("generatekey\tCreate a key file to local machine to default path.");
    Console.WriteLine("\t\t--force\t\tForce overwrite if file exists.");
    Console.WriteLine();
    Console.WriteLine("removekey\tRemove local machine default path key file.");
    Console.WriteLine("\t\t--force\t\tForce remove.");
    Console.WriteLine();
    Console.WriteLine("view\t\tShow local machine default path key file.");
    Console.WriteLine("\t\t--password give password");
    Console.WriteLine();
    Console.WriteLine("encode\t\tGenerate a smkmuri.");
    Console.WriteLine("\t\t--data\t\tData to encode.");
    Console.WriteLine("decode\t\tDecode a smkmuri.");
}
