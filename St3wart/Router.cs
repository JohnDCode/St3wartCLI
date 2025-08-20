/*

Stewart CLI
/Router.cs - Delegates commands to the appropriate classes
JohnDavid Abe 

*/



public class Router
{
    public void Route(string[] args)
    {
        // Check that a command has been called
        if (args.Length == 0)
        {
            // If no command has been called, print info and display help command
            ICommand helpCmd = new HelpCommand();
            helpCmd.Execute();
            return;
        }

        // Extract inital command (first argument in executable call)
        string command = args[0].ToLower();

        // Get the command (must follow the ICommand interface) and delegate appropriately
        ICommand? cmd = command switch
        {
            //"a" => new ACommand(),
            "check" => new CheckCommand(),
            "exempt" => new ExemptCommand(),
            "log" => new LogCommand(),
            "report" => new ReportCommand(),
            "restore" => new RestoreCommand(),
            "schedule" => new ScheduleCommand(),
            "secure" => new SecureCommand(),
            "snap" => new SnapCommand(),
            "vuln" => new VulnCommand(),
            _ => null
        };

        // If no command can be delegated, command is unknown
        if (cmd == null)
        {
            Console.WriteLine($"Unknown command: {command}");
            return;
        }

        // Execute the delegated command
        cmd.Execute();
    }
}
