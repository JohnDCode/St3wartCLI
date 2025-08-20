/*

Stewart CLI
/Commands/Vuln.cs - Vuln command, acts as vuln lookup to display information on any particular vuln in database
JohnDavid Abe 

*/



public class VulnCommand : ICommand
{
    // Execute method (ran upon command)
    public void Execute(string[] args)
    {
        // Get the specified file path
        string filePath = args[1];

        // Get all vulns from the file
        var checks = DataHandler.VulnsFromFile(filePath);

        // Find the specific check
        var vuln = checks[args[2]];

        Console.ForegroundColor = ConsoleColor.Green;


        if (vuln is RegistryCheck regCheck)
        {
            Console.WriteLine(regCheck.Print());
        }
        else if (vuln is PowerShellCheck psCheck)
        {
            Console.WriteLine(psCheck.Print());
        }

        Console.ResetColor();


    }
}
