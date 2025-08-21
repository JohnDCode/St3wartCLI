/*

Stewart CLI
/Commands/Vuln.cs - Vuln command, acts as vuln lookup to display information on any particular vuln in any database
JohnDavid Abe 

*/



/// <summary>
/// Vuln command, acts as vuln lookup to display information on any particular vuln in any database
/// </summary>
public class VulnCommand : ICommand {

    /// <summary>
    /// Method run on execution of the command
    /// </summary>
    /// <param name="args">CLI arguments for the command</param>
    public void Execute(string[] args) {

        try {

            // Get the specified file path of the vuln bank
            string filePath = args[1];

            // Get all vulns from the file
            Dictionary<string, Check> checks = DataHandler.VulnsFromFile(filePath);

            // Ensure checks populated
            if (checks == null) { Errors.PrintError("Can not retrieve vulns from JSON database"); return; }

            // Find the specific check by looking up the ID in the bank
            Check vuln = checks[args[2]];

            // Check if vuln was found
            if (vuln == null) { Errors.PrintError($"Can not retrieve vuln {args[2]} from JSON database"); return; }
            
            // Set the text color for cool output of the vuln
            Console.ForegroundColor = ConsoleColor.Green;

            // Check the type of the check and print data on the vuln accordingly
            if (vuln is RegistryCheck regCheck) {
                Console.WriteLine(regCheck.Print());
            } else if (vuln is PowerShellCheck psCheck) {
                Console.WriteLine(psCheck.Print());
            } else {
                Errors.PrintError("Unknown check type");
            }

            // Reset the foreground color
            Console.ResetColor();
        } catch {
            Help();
        }
    }



    /// <summary>
    /// Displays help information on the command
    /// </summary>
    public void Help() {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("St3wart Vuln");
        Console.WriteLine("Usage: St3wart.exe vuln [OPTIONS] <JSON BANK PATH> <VULN ID>");
        Console.WriteLine("Example: St3wart.exe vuln C:/vulns.json OS-001");
        Console.ResetColor();
    }
}
