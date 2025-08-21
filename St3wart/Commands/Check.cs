/*

Stewart CLI
/Commands/Check.cs - Check command, checks for vulns on machine and/or services
JohnDavid Abe 

*/



// Packages
using System.Runtime.Versioning;



/// <summary>
/// Check command, checks for vulns on machine and/or services
/// </summary>
[SupportedOSPlatform("Windows")]
public class CheckCommand : ICommand {

    /// <summary>
    /// Method run on execution of the command
    /// </summary>
    /// <param name="args">CLI arguments for the command</param>
    public async void Execute(string[] args) {

        // Get the specified file path of the vuln bank
        string filePath = args[1];

        // Get all vulns from the file
        Dictionary<string, Check> checks = DataHandler.VulnsFromFile(filePath);

        // Ensure checks populated
        if (checks == null) { Errors.PrintError("Can not retrieve vulns from JSON database"); return; }

        // Organize checks into lists of their types
        List<PowerShellCheck> psChecks = new List<PowerShellCheck>();
        List<RegistryCheck> regChecks = new List<RegistryCheck>();
        foreach (KeyValuePair<string, Check> check in checks) {
            if (check.Value is PowerShellCheck psCheck) {
                psChecks.Add(psCheck);
            } else if (check.Value is RegistryCheck regCheck) {
                regChecks.Add(regCheck);
            }
        }

        // Start the PS pool
        using var pool = new PowerShellPool(poolSize: 15);
        if (!await pool.InitializeAsync()) {
            Console.WriteLine("Failed to initialize PowerShell pool");
            return;
        }


        // Run the two types of checks concurrently
        Task<List<PowerShellResult>> psTask = pool.ExecuteCommandsBatchAsync(psChecks);
        Task<List<RegistryResult>> regTask = Task.Run(() => RegistryRunner.ExecuteRegistryChecks(regChecks));
        await Task.WhenAll(psTask, regTask);

        // Extract the reuslts of both sets of checks
        List<PowerShellResult> psResults = await psTask;
        List<RegistryResult> regResults = await regTask;

        // Display info on both sets of results
        foreach(PowerShellResult psResult in psResults) {

            // Format the result to a readable string
            string strResult = psResult.Print();

            // Set the output color based on if the check passed
            if (psResult.CheckPass == true) { Console.ForegroundColor = ConsoleColor.Green; } else { Console.ForegroundColor = ConsoleColor.Red; }

            // Write the output to the console
            Console.WriteLine(strResult);
        }
        
        foreach(RegistryResult regResult in regResults) {

            // Format the result to a readable string
            string strResult = regResult.Print();

            // Set the output color based on if the check passed
            if (regResult.CheckPass == true) { Console.ForegroundColor = ConsoleColor.Green; } else { Console.ForegroundColor = ConsoleColor.Red; }

            // Write the output to the console
            Console.WriteLine(strResult);
        }

        // Reset the foreground color after printing all of the vulns
        Console.ResetColor();
    }



    /// <summary>
    /// Displays help information on the command
    /// </summary>
    public void Help()
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("St3wart Check");
        Console.WriteLine("Usage: St3wart.exe check [OPTIONS] <JSON BANK PATH>");
        Console.WriteLine("Example: St3wart.exe check C:/vulns.json");
        Console.ResetColor();
    }
}



        // Will need to add exempt stuff later
        

        // Then check if there was a last check in the xml file, if there was, remove it
        // Add the results of each check to the xml