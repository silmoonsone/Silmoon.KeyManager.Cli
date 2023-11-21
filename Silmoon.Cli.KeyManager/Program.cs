// See https://aka.ms/new-console-template for more information
using Silmoon;
using Silmoon.Core.Authorization;
using Silmoon.Extension;
using Silmoon.Secure;
using System.Collections.Specialized;
using System.Security.Cryptography;
using System.Text.Json;


Entry(args);

static void Entry(string[] args)
{
    start:
    if (args.Length == 0)
    {
        Console.WriteLine("Please input command, or --help.");
        var readLine = Console.ReadLine();
        if (readLine.IsNullOrEmpty()) goto start;

        args = readLine.Split(' ');
        if (args.IsNullOrEmpty()) goto start;
        goto start;
    }
    else
    {
        NameValueCollection param = StringHelper.AnalyzeNameValue(args, "=", "--");
        if (param.Count == 0)
        {
            Help(param);
        }
        else
        {
            switch (param.AllKeys[0])
            {
                case "--help":
                    Help(param);
                    break;
                case "--generatekey":
                    GenerateKeyFile(param, args.Contains("--force"));
                    break;
                case "--showkey":
                    ShowKeyFile(param);
                    break;
                case "--removekey":
                    RemoveKeyFile(param);
                    break;
                case "--install":
                    InstallToPath();
                    break;
                default:
                    Console.WriteLine("Unknown command (" + param[0] + "), or --help.");
                    break;
            }
        }
    }
}

static void InstallToPath()
{
    var currentPath = System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName;
    var system32Path = Environment.GetFolderPath(Environment.SpecialFolder.System);
    File.Copy(currentPath, system32Path + "\\smkm.exe", true);
    Console.WriteLine(system32Path + "\\smkm.exe, " + "Success. ");
}
static void GenerateKeyFile(NameValueCollection param, bool noCheckFileExists)
{
    if (File.Exists("C:\\_smkey.raw") && !noCheckFileExists)
    {
        Console.WriteLine("id file is exists! overwrite? [y/n]");
        var readLine = Console.ReadLine().ToLower();
        if (readLine == "y")
        {
            File.SetAttributes("C:\\_smkey.raw", FileAttributes.Normal);
            GenerateKeyFile(param, true);
        }
        else
            Console.WriteLine("cancel.");
    }
    else
    {

        var password = HashHelper.RandomChars(32);
        if (param.AllKeys.Contains("--password") && !param["--password"].IsNullOrEmpty()) password = param["--password"];

        var keyFile = KeyManager.GenerateEncryptedKeyString(password);

        File.WriteAllText("C:\\_smkey.raw", keyFile);
        File.SetAttributes("C:\\_smkey.raw", FileAttributes.Hidden);
        Console.WriteLine("Password: " + password);
        Console.WriteLine("Success.");
        Console.WriteLine("push any key to close");
        Console.ReadKey();
    }
}
static void ShowKeyFile(NameValueCollection param)
{
    if (File.Exists("C:\\_smkey.raw"))
    {
        var password = param["--password"];
        if (password.IsNullOrEmpty())
        {
            Console.WriteLine("Please input password.");
            password = Console.ReadLine();
        }
        var fileContent = File.ReadAllText("C:\\_smkey.raw");

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
static void RemoveKeyFile(NameValueCollection param, bool force = false)
{
    if (File.Exists("C:\\_smkey.raw"))
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
        File.Delete("C:\\_smkey.raw");
        Console.WriteLine("Success.");
    }
    else
    {
        Console.WriteLine("No id file.");
    }
}
static void Help(NameValueCollection param)
{
    Console.WriteLine("Silmoon authorization/license key manager utility.");
    Console.WriteLine();
    Console.WriteLine("[--generatekey]\tto generate a local machine id to default path.");
    Console.WriteLine("[--showkey]\tto show local machine id.");
    Console.WriteLine("[--removekey]\tto remove local machine id.");
    Console.WriteLine("push any key to close");
    Console.ReadKey();
}
