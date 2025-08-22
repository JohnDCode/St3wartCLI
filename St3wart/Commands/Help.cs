/*

Stewart CLI
/Commands/Help.cs - Displays usage and help menu
JohnDavid Abe 

*/



public class HelpCommand : ICommand
{
    // Execute method (ran upon command)
    public async Task Execute(string[] args) { Help(); } 
    public void Help() { 
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("St3wart - Simplifying Systems Management\n");
        Console.WriteLine("A general purpose Windows security auditing tool");

        Console.WriteLine("Usage: St3wart.exe <COMMAND>");
        Console.WriteLine("Commands: ");
        Console.WriteLine("check");
        Console.WriteLine("exempt");
        Console.WriteLine("help");
        Console.WriteLine("log");
        Console.WriteLine("report");
        Console.WriteLine("restore");
        Console.WriteLine("schedule");
        Console.WriteLine("secure");
        Console.WriteLine("snap");
        Console.WriteLine("vuln");
        Console.ResetColor();
    }
}
