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
            
            // SDFDSF --> NOW WE HAVE ALL THE FAILED CHECKS, REMEDIATE THEM HERE
            
            
            
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
