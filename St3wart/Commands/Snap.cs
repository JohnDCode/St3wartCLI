/*

Stewart CLI
/Commands/Snap.cs - Snap command, takes snapshot of system policies to later be imported with St3wart restore
JohnDavid Abe 

*/



public class SnapCommand : ICommand
{
    // Execute method (ran upon command)
    public void Execute(string[] args)
    {
        // Debug console out
        Console.Write("Running Snap Command");

    }
}
