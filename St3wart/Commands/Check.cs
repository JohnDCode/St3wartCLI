/*

Stewart CLI
/Commands/Check.cs - Check command, checks for vulns on machine and/or services
JohnDavid Abe 

*/



public class CheckCommand : ICommand
{
    // Execute method (ran upon command)
    public void Execute(string[] args)
    {
        // Debug console out
        var checks = DataHandler.VulnsFromFile(@"C:\Users\John\Desktop\St3wartCLI\St3wartCLI\St3wart\Vulns\System\test.json");
        Console.WriteLine(checks["OS-002"].Description);
        Console.Write("Running Check Command");
    }
}
