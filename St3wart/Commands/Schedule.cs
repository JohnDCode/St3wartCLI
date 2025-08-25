/*

Stewart CLI
/Commands/Schedule.cs - Schedule command, schedules the running of St3wart commands
JohnDavid Abe 

*/



// Packages
using Microsoft.Win32.TaskScheduler;



// Schedule command, schedules the running of St3wart commands
public class ScheduleCommand : ICommand {

    /// <summary>
    /// Method run on execution of the command
    /// </summary>
    /// <param name="args">CLI arguments for the command</param>
    public async System.Threading.Tasks.Task Execute(string[] args) {

        try {

            // Open an instance of the task scheudler
            using (TaskService ts = new TaskService()) {

                // Attempt to open the St3wart task scheduler folder, create it if it does not exist
                TaskFolder? folder = ts.GetFolder(@"\St3wart");
                if (folder == null) { folder = ts.RootFolder.CreateFolder("St3wart"); }

                // Create a new task definition and assign properties
                TaskDefinition td = ts.NewTask();
                
                // Create a trigger that will fire the task at this time every x days, as specified
                td.Triggers.Add(new DailyTrigger { DaysInterval = short.Parse(args[2]) });
                
                // Create an action that will launch the command when the task fires
                td.Actions.Add(new ExecAction(Directory.GetCurrentDirectory() + "/St3wart.exe", args[1]));
                
                // Compile the name for the task
                string name = $"St3wart-{args[1]}";
                string checkName = name.Substring(0, name.IndexOf(" ")) + $"-{Guid.NewGuid():N}";

                // Register the task in the St3wart folder
                if (ts.RootFolder.SubFolders.Contains(folder)) { folder.RegisterTaskDefinition(checkName, td, TaskCreation.CreateOrUpdate, "SYSTEM", null, TaskLogonType.ServiceAccount); } else {
                    Errors.PrintError("Unable to create task scheduler folder");
                    return;
                }
                
                // Print success
                Console.WriteLine($"Scheduled St3wart action {checkName}");
            }
        } catch {
            Errors.PrintError("Error");
            Help();
        }
        return;
    }



    /// <summary>
    /// Displays help information on the command
    /// </summary>
    public void Help() {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("St3wart Schedule");
        Console.WriteLine("Schedules the running of St3wart commands");
        Console.WriteLine("Usage: St3wart.exe schedule [OPTIONS] <COMMAND> <TIME>");
        Console.WriteLine("Example: St3wart.exe schedule \"check C:/vulns.json\" 1");
        Console.ResetColor();
    }
}