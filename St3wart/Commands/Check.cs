/*

Stewart CLI
/Commands/Check.cs - Check command, checks for vulns on machine and/or services
JohnDavid Abe 

*/



public class CheckCommand : ICommand
{
    // Execute method (ran upon command)
    public void Execute()
    {
        // Debug console out
        var checks = DataHandler.VulnsFromFile(@"C:\Users\John\Desktop\St3wartCLI\St3wartCLI\St3wart\Vulns\System\test.json");
        Console.WriteLine(checks[0]);
        Console.WriteLine(checks[1]);
        Console.Write("Running Check Command");

    }
}
