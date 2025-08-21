/*

Stewart CLI
/Commands/Vuln.cs - Vuln command, acts as vuln lookup to display information on any particular vuln in database
JohnDavid Abe 

*/



/// <summary>
/// Vuln command, acts as vuln lookup to display information on any particular vuln in any database
/// </summary>
public class VulnCommand : ICommand
{

    /// <summary>
    /// Method run on execution of the command
    /// </summary>
    /// <param name="args">CLI arguments for the command</param>
    public void Execute(string[] args)
    {

        // Get the specified file path of the vuln bank
        string filePath = args[1];

        // Get all vulns from the file
        var checks = DataHandler.VulnsFromFile(filePath);

        // Find the specific check by looking up the ID in the bank
        var vuln = checks[args[2]];

        // Set the text color for cool output of the vuln
        Console.ForegroundColor = ConsoleColor.Green;

        // Check the type of the check and print data on the vuln accordingly
        if (vuln is RegistryCheck regCheck)
        {
            Console.WriteLine(regCheck.Print());
        }
        else if (vuln is PowerShellCheck psCheck)
        {
            Console.WriteLine(psCheck.Print());
        }

        // Reset the foreground color
        Console.ResetColor();
    }

    public void Help()
    {
        Console.Write("HI");
    }
}
