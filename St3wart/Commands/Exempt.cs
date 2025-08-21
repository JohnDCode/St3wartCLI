/*

Stewart CLI
/Commands/Exempt.cs - Exempt command, exempts vulns from being checked, secured, or otherwise noted by St3wart
JohnDavid Abe 

*/



// Packages
using System.Xml.Linq;



/// <summary>
/// Exempt command, exempts vulns from being checked, secured, or otherwise noted by St3wart
/// </summary>
public class ExemptCommand : ICommand {

    /// <summary>
    /// Method run on execution of the command
    /// </summary>
    /// <param name="args">CLI arguments for the command</param>
    public async Task Execute(string[] args) {

        try {

            // Check if the configuration file has been created and create one if not
            string filePath = Directory.GetCurrentDirectory() + "/St3wart.xml";
            if (!File.Exists(filePath)) { if(!Config.CreateConfig(filePath)) { Errors.PrintError("Can not create configuration file"); return; } }

            // Create the exception element corresponding to the exempt request
            XElement e = new XElement("exemption", new XAttribute("ID", args[2]));

            // Get the action to perform on the provided exception
            string action = args[1].ToLower();

            // Add or remove the exemption according to the command arguments
            if (action == "add") {
                Config.WriteElement(filePath, "exemptions", e);
            } else if (action == "remove") {
                Config.RemoveElement(filePath, "exemptions", e);
            } else {
                Help();
            }
            
        } catch {
            Help();
        }
    }
    
    
    
    /// <summary>
    /// Displays help information on the command
    /// </summary>
    public void Help() {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("St3wart Exempt");
        Console.WriteLine("Usage: St3wart.exe exempt [OPTIONS] <ACTION> <VULN ID>");
        Console.WriteLine("Example: St3wart.exe exempt add OS-001");
        Console.ResetColor();
    }
}
