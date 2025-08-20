/*

Stewart CLI
/Program.cs - Entry point for executable
JohnDavid Abe 

*/



class Program
{
    static void Main(string[] args)
    {
        // Route arguments from command to the router
        var router = new Router();
        router.Route(args);
    }
}
















//         RegistryCheck myRegCheck1 = new RegistryCheck
//         {
//             ID = "1",
//             Key = @"HKLM\HARDWARE\DESCRIPTION\System",
//             Value = "PreferredProfile",
//             FindData = "0",
//             Operator = "Contains"
//         };

//         List<RegistryCheck> myChecks = new List<RegistryCheck> { myRegCheck1 };

//         List<RegistryResult> myResults = RegistryRunner.ExecuteRegistryChecks(myChecks);

//         foreach (RegistryResult result in myResults)
//         {
//             Console.WriteLine(result.Data);
//             Console.WriteLine(result.CheckPass);
//         }

//     }
// }





//         // using var pool = new PowerShellPool(poolSize: 15);

//         // if (!await pool.InitializeAsync())
//         // {
//         //     Console.WriteLine("Failed to initialize PowerShell pool");
//         //     return;
//         // }

//         // PowerShellCheck myCheck1 = new PowerShellCheck
//         // {
//         //     ID = "1",
//         //     CheckCommand = "Get-NetFirewallProfile -Profile Public | Select-Object -ExpandProperty LogMaxSizeKilobytes",
//         //     FindData = "4097",
//         //     Operator = "EqualTo"
//         // };


//         // var checks = new List<PowerShellCheck> { myCheck1 };

//         // var results = await pool.ExecuteCommandsBatchAsync(checks);

//         // foreach (PowerShellResult result in results)
//         // {
//         //     Console.WriteLine($"Output: {result.Output}\n");
//         //     Console.WriteLine($"Errors: {result.Errors}\n");
//         //     Console.WriteLine($"Success: {result.Success}\n");
//         //     Console.WriteLine($"CHECK PASS: {result.CheckPass}\n");
//         // }

//         // Create the Pool, Initalize it all, create a list of checks, execute the commands in batch, handle the output