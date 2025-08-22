/*

Stewart CLI
/Commands/Check.cs - Check command, checks for vulns on machine and/or services
JohnDavid Abe 

*/



// Packages
using System.Runtime.Versioning;
using System.Xml.Linq;



/// <summary>
/// Check command, checks for vulns on machine and/or services
/// </summary>
[SupportedOSPlatform("Windows")]
public class CheckCommand : ICommand {

    /// <summary>
    /// Method run on execution of the command
    /// </summary>
    /// <param name="args">CLI arguments for the command</param>
    public async Task Execute(string[] args) {
        
        try {

            // Get the specified file path of the vuln bank
            string filePath = args[1];

            // The path to the config file
            string configFile = Directory.GetCurrentDirectory() + "/St3wart.xml";

            // Check if the configuration file has been created and create one if not
            if (!File.Exists(configFile)) { if(!Config.CreateConfig(configFile)) { Errors.PrintError("Can not create configuration file"); return; } }

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
            using var pool = new PowerShellPool(poolSize: 2);
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
            
            // Get all the exemptions from the XML config file
            List<XElement> exceptions = Config.FetchElements(configFile, "exemptions");
            List<string> exceptionIDs = new List<string>();
            foreach (XElement e in exceptions) {
                string? id = (string?) e.Attribute("ID");
                if (id is string idStr) { exceptionIDs.Add(idStr); }
            }
            
            // Get the date to log the check
            DateTime currentTime = DateTime.Now;
            string formattedDateTime = currentTime.ToString("yyyy-MM-dd-HH:mm:ss");

            // Log the check
            string checkName = $"check{Guid.NewGuid():N}";
            Config.WriteElement(configFile, "checks", new XElement(checkName, new XAttribute("Date", formattedDateTime), new XAttribute("File", args[1])));
            
            // Display info on both sets of results and log said results
            foreach(PowerShellResult psResult in psResults) {

                // Ensure the vuln is not marked as an exemption
                string? id = psResult.Check.ID;
                if (id is string checkID) {
                    if (exceptionIDs.Contains(checkID)) { continue; }

                    // Cache the result
                    Config.WriteElement(configFile, checkName, new XElement("vuln", new XAttribute("ID", checkID), new XAttribute("CheckPass", psResult.CheckPass.ToString())));
                }

                // Format the result to a readable string
                string strResult = psResult.Print();

                // Set the output color based on if the check passed
                if (psResult.CheckPass == true) { Console.ForegroundColor = ConsoleColor.Green; } else { Console.ForegroundColor = ConsoleColor.Red; }

                // Write the output to the console
                Console.WriteLine(strResult);
            }

            foreach(RegistryResult regResult in regResults) {

                // Ensure the vuln is not marked as an exemption
                string? id = regResult.Check.ID;
                if (id is string checkID) {
                    if (exceptionIDs.Contains(checkID)) { continue; }
                }
                
                // Format the result to a readable string
                string strResult = regResult.Print();

                // Set the output color based on if the check passed
                if (regResult.CheckPass == true) { Console.ForegroundColor = ConsoleColor.Green; } else { Console.ForegroundColor = ConsoleColor.Red; }

                // Write the output to the console
                Console.WriteLine(strResult);
            }

            // Reset the foreground color after printing all of the vulns
            Console.ResetColor();
            
            
            // Write the new section to the config file

        } catch {
            Errors.PrintError("Error");
            Help();
        }
    }



    /// <summary>
    /// Displays help information on the command
    /// </summary>
    public void Help() {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("St3wart Check");
        Console.WriteLine("Usage: St3wart.exe check [OPTIONS] <JSON BANK PATH>");
        Console.WriteLine("Example: St3wart.exe check C:/vulns.json");
        Console.ResetColor();
    }
}
