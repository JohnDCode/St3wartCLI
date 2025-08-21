/*

Stewart CLI
/Commands/Check.cs - Check command, checks for vulns on machine and/or services
JohnDavid Abe 

*/



public class CheckCommand : ICommand
{
    // Execute method (ran upon command)
    public void Execute(string[] args) { 
        
        // Need to load all of the checks into a list (just like with Vuln)
        // Then loop through and split the checks into a list of ps checks and a list of Registry checks
        // Then call the respective batch execute commands for each to obtain two lists
        // Call a display command for each of them
        // Then check if there was a last check in the xml file, if there was, remove it
        // Add the results of each check to the xml
    }
    public void Help() { 
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("St3wart Check");
        Console.WriteLine("Usage: St3wart.exe check [OPTIONS] <JSON BANK PATH>");
        Console.WriteLine("Example: St3wart.exe check C:/vulns.json");
        Console.ResetColor();
    }
}
