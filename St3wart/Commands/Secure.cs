/*

Stewart CLI
/Commands/Secure.cs - Secure command, attempts to secure any vulns identified by most recent check command
JohnDavid Abe 

*/



// Namespaces
using System.Reflection.PortableExecutable;
using System.Runtime.Versioning;
using System.Xml.Linq;



/// <summary>
/// Secure command, attempts to secure any vulns identified by most recent check command
/// </summary>
[SupportedOSPlatform("Windows")]
public class SecureCommand : ICommand {
    // Execute method (ran upon command)
    public async Task Execute(string[] args) {

        try {

            // Get the specified file path of the vuln bank
            string filePath = args[1];

            // The path to the config file
            string configFile = Directory.GetCurrentDirectory() + "/St3wart.xml";
            if (!File.Exists(configFile)) { Errors.PrintError("Unable to find configuration file"); Help(); return; }

            // Get all vulns from the file
            Dictionary<string, Check> checks = DataHandler.VulnsFromFile(filePath);

            // Ensure checks populated
            if (checks == null) { Errors.PrintError("Can not retrieve vulns from JSON database"); Help(); return; }

            // Use the GUID to compile the check name
            string checkName = $"check{args[2]}";

            // Get all of the check IDs that failed from the XML
            List<XElement> loggedChecks = Config.FetchElements(configFile, checkName);
            List<string> loggedIDs = new List<string>();
            if (loggedChecks == null) { Errors.PrintError("Unable to retrieve logs of check)"); return; } else {
                foreach (XElement e in loggedChecks) {
                    string? id = (string?) e.Attribute("ID");
                    bool? pass = (bool?)e.Attribute("CheckPass");
                    if (id is string idStr && pass is bool checkPass) {
                        if (!checkPass) { loggedIDs.Add(idStr); }
                    }
                }
            }

            // Get all of the checks that failed
            List<Check> failedChecks = new List<Check>();
            foreach(string id in loggedIDs) {
                failedChecks.Add(checks[id]);
            }
            
            // Organize checks into lists of their types
            List<PowerShellCheck> psChecks = new List<PowerShellCheck>();
            List<RegistryCheck> regChecks = new List<RegistryCheck>();
            List<FileCheck> fileChecks = new List<FileCheck>();
            foreach (Check check in failedChecks) {
                if (check is PowerShellCheck psCheck) {
                    psChecks.Add(psCheck);
                } else if (check is RegistryCheck regCheck) {
                    regChecks.Add(regCheck);
                } else if (check is FileCheck fileCheck) {
                    fileChecks.Add(fileCheck);
                }
            }

            // Allocate resources to PS and File remediation processes concurrency
            int psPoolSize;
            int filePoolSizes;
            
            if (psChecks.Count() < 5) {
                psPoolSize = 1;
            } else if (psChecks.Count() < 15) {
                psPoolSize = 5;
            } else {
                psPoolSize = 10;
            }
            
            if (fileChecks.Count() < 5) {
                filePoolSizes = 1;
            } else if (fileChecks.Count() < 15) {
                filePoolSizes = 5;
            } else {
                filePoolSizes = 10;
            }

            // Start the PS pool
            using var pool = new PowerShellPool(poolSize: psPoolSize);
            if (!await pool.InitializeAsync()) {
                Errors.PrintError("Failed to initialize PowerShell pool");
                Help();
                return;
            }
            
           // Run the three types of secure procedures concurrently
            Task<List<(string, bool)>> psTask = pool.ExecuteSecureBatchAsync(psChecks);
            Task<List<(string, bool)>> regTask = Task.Run(() => RegistryRunner.ExecuteRegistrySecure(regChecks));
            Task<List<(string, bool)>> fileTask = FileRunner.ExecuteFileSecure(fileChecks, filePoolSizes);
            await Task.WhenAll(psTask, regTask, fileTask);

            // Extract the reuslts of both sets of checks
            List<(string, bool)> psResults = await psTask;
            List<(string, bool)> regResults = await regTask;
            List<(string, bool)> fileResults = await fileTask;
            
            // Get the date to log the secure
            DateTime currentTime = DateTime.Now;
            string formattedDateTime = currentTime.ToString("yyyy-MM-dd-HH:mm:ss");

            // Log the secure
            string secureName = $"secure{args[2]}";
            Config.WriteElement(configFile, "secures", new XElement(secureName, new XAttribute("Date", formattedDateTime), new XAttribute("File", args[1])));
            

            // Display info on all three sets of results and log each remediation result
            List<(string, bool)> combinedResults = [.. psResults, .. regResults, .. fileResults];
            foreach ((string, bool) result in combinedResults) {

                // Lookup the check that corresponds to the current result
                Check checkResult = checks[result.Item1];

                string details = checkResult.Print() + $"\nRemediation Success: {result.Item2}";
        
                // Ensure the details populated
                if ( details == null) { continue; }

                // Cache the result of the result
                Config.WriteElement(configFile, secureName, new XElement("remediation", new XAttribute("ID", result.Item1), new XAttribute("ProperlyRemediated", result.Item2)));

                // Set the output color based on if the check passed
                if (result.Item2 == true) { Console.ForegroundColor = ConsoleColor.Green; } else { Console.ForegroundColor = ConsoleColor.Red; }

                // Write the output to the console
                Console.WriteLine(details);
                Console.WriteLine("----------------------------------------------");
            }

            // Reset the foreground color after printing all of the vulns
            Console.ResetColor();


            // Output the GUID of the check
            Console.WriteLine($"Secured check ID {checkName.Substring(5)}");
            
        }
        catch {
            Errors.PrintError("Error");
            Help();

        }
    } 
    


    /// <summary>
    /// Displays help information on the command
    /// </summary>
    public void Help() {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("St3wart Secure");
        Console.WriteLine("Remediates findings from previous check");
        Console.WriteLine("Usage: St3wart.exe secure [OPTIONS] <JSON BANK PATH> <CHECK GUID>");
        Console.WriteLine("Example: St3wart.exe secure aa2120aadb464c6fb9c1f4ec6a7806bf C:/vulns.json");
        Console.ResetColor();
    }
}
