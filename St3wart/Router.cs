/*

Stewart CLI
/Router.cs - Delegates commands to the appropriate classes
JohnDavid Abe 

*/



// Packages
using System.Runtime.Versioning;



/// <summary>
/// Delegates commands to the appropriate classes
/// </summary>
[SupportedOSPlatform("Windows")]
public static class Router {

    /// <summary>
    /// Delegates commands to the appropriate classes
    /// </summary>
    /// <param name="args">CLI arguments for the command</param>
    public static async Task Route(string[] args) {

        // Check that a command has been called
        if (args.Length == 0) {
            // If no command has been called, print info and display help command
            ICommand helpCmd = new HelpCommand();
            await helpCmd.Execute(args);
            return;
        }

        // Extract inital command (first argument in executable call)
        string command = args[0].ToLower();

        // Create the config file if none is found
        string filePath = Directory.GetCurrentDirectory() + "/St3wart.xml";
        if (!File.Exists(filePath)) { if(!Config.CreateConfig(filePath)) { Errors.PrintError("Can not create configuration file"); return; } }

        // Get the command and delegate appropriately
        ICommand? cmd = command switch {
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
        if (cmd == null) {
            Errors.PrintError("Unknown command");
            ICommand helpCmd = new HelpCommand();
            await helpCmd.Execute(args);
            return;
        }

        // Execute the delegated command
        await cmd.Execute(args);
    }
}
