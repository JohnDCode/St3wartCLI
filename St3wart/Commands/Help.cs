/*

Stewart CLI
/Commands/Help.cs - Displays usage and help menu
JohnDavid Abe 

*/



public class HelpCommand : ICommand
{
    // Execute method (ran upon command)
    public void Execute(string[] args)
    {
        // Debug console out
        Console.Write("Running Help Command");

    }
}
