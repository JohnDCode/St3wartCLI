/*

Stewart CLI
/Commands/Check.cs - Check command, checks for deignated vulns on machine
JohnDavid Abe 

*/



// Packages
using System.Runtime.Versioning;
using System.Xml.Linq;



/// <summary>
/// Check command, checks for deignated vulns on machine
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
            if (!File.Exists(filePath)) { Errors.PrintError("Unable to find configuration file"); Help(); return; }
            
            // Get all vulns from the file
            Dictionary<string, Check> checks = DataHandler.VulnsFromFile(filePath);

            // Ensure checks populated
            if (checks == null) { Errors.PrintError("Can not retrieve vulns from JSON database");Help(); return; }
            
            // Organize checks into lists of their types
            List<PowerShellCheck> psChecks = new List<PowerShellCheck>();
            List<RegistryCheck> regChecks = new List<RegistryCheck>();
            List<FileCheck> fileChecks = new List<FileCheck>();
            foreach (KeyValuePair<string, Check> check in checks) {
                if (check.Value is PowerShellCheck psCheck) {
                    psChecks.Add(psCheck);
                } else if (check.Value is RegistryCheck regCheck) {
                    regChecks.Add(regCheck);
                } else if (check.Value is FileCheck fileCheck) {
                    fileChecks.Add(fileCheck);
                }
            }
            
            // Determine the number of PS instances to spawn (very jank, note: update this)
            int numInstances;
            if (psChecks.Count() < 5) {
                numInstances = 1;
            } else if (psChecks.Count() < 15) {
                numInstances = 5;
            } else {
                numInstances = 10;
            }
                

            // Start the PS pool
            using var pool = new PowerShellPool(poolSize: numInstances);
            if (!await pool.InitializeAsync()) {
                Errors.PrintError("Failed to initialize PowerShell pool");
                Help();
                return;
            }

            // Run the two types of checks concurrently
            Task<List<PowerShellResult>> psTask = pool.ExecuteCommandsBatchAsync(psChecks);
            Task<List<RegistryResult>> regTask = Task.Run(() => RegistryRunner.ExecuteRegistryChecks(regChecks));
            Task<List<FileResult>> fileTask = Task.Run(() => FileRunner.ExecuteFileChecks(fileChecks));
            await Task.WhenAll(psTask, regTask, fileTask);

            // Extract the reuslts of both sets of checks
            List<PowerShellResult> psResults = await psTask;
            List<RegistryResult> regResults = await regTask;
            List<FileResult> fileResults = await fileTask;
            
            // Get all the exemptions from the XML config file
            List<XElement> exceptions = Config.FetchElements(configFile, "exemptions");
            List<string> exceptionIDs = new List<string>();
            if (exceptions == null) { Errors.PrintError("Unable to retrieve exemptions, logging all checks"); } else {
                foreach (XElement e in exceptions) {
                    string? id = (string?) e.Attribute("ID");
                    if (id is string idStr) { exceptionIDs.Add(idStr); }
                }
            }
            
            // Get the date to log the check
            DateTime currentTime = DateTime.Now;
            string formattedDateTime = currentTime.ToString("yyyy-MM-dd-HH:mm:ss");

            // Log the check
            string checkName = $"check{Guid.NewGuid():N}";
            Config.WriteElement(configFile, "checks", new XElement(checkName, new XAttribute("Date", formattedDateTime), new XAttribute("File", args[1])));
            

            // Display info on both sets of results and log each result
            List<object> combinedResults = [.. psResults, .. regResults, .. fileResults];
            foreach (object objResult in combinedResults) {

                // Get the details of the check
                string? id = null;
                bool? checkPass = null;
                string? details = null;
                if (objResult is PowerShellResult psResult) {
                    id = psResult.Check.ID; checkPass = psResult.CheckPass; details = psResult.Print();
                } else if (objResult is RegistryResult regResult) {
                    id = regResult.Check.ID; checkPass = regResult.CheckPass; details = regResult.Print();
                } else if (objResult is FileResult fileResult) {
                    id = fileResult.Check.ID; checkPass = fileResult.CheckPass; details = fileResult.Print();
                } else { continue; }
        
                // Ensure the details populated
                if (id == null || checkPass == null || details == null) { continue; }

                // Ensure the vuln is not marked as an exemption
                if (exceptionIDs.Contains(id)) { continue; }

                // Cache the result of the result
                Config.WriteElement(configFile, checkName, new XElement("vuln", new XAttribute("ID", id), new XAttribute("CheckPass", checkPass)));

                // Set the output color based on if the check passed
                if (checkPass == true) { Console.ForegroundColor = ConsoleColor.Green; } else { Console.ForegroundColor = ConsoleColor.Red; }

                // Write the output to the console
                Console.WriteLine(details);
                Console.WriteLine("----------------------------------------------");
            }

            // Reset the foreground color after printing all of the vulns
            Console.ResetColor();

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
        Console.WriteLine("Checks for deignated vulns on machine");
        Console.WriteLine("Usage: St3wart.exe check [OPTIONS] <JSON BANK PATH>");
        Console.WriteLine("Example: St3wart.exe check C:/vulns.json");
        Console.ResetColor();
    }
}
