/*

Stewart CLI
/Commands/Secure.cs - Secure command, attempts to secure any vulns identified by most recent check command
JohnDavid Abe 

*/



public class SecureCommand : ICommand
{
    // Execute method (ran upon command)
    public async Task Execute(string[] args) { } 
    public void Help() { }
}



/*

Idk how to implement SecureCommand

FIrst of all, have it secure by GUID
Command parameters will specify a GUID

Load all vulns that were marked as findings

Will need tm modify all current runners to not just execute checks but also be able to just run secure / modify data instead of just reading it (will be easiest for powershell, hardest for files but not that hard)

*/