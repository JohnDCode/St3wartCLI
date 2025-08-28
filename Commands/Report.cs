/*

Stewart CLI
/Commands/Report.cs - Report command, generates a report of an action taken by St3wart
JohnDavid Abe 

*/



// Namespaces
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using System.Xml.Linq;



/// <summary>
/// Enum to hold the type of report
/// </summary>
enum ReportType { Check, Secure }



// Report command, generates a report of an action taken by St3wart
public class ReportCommand : ICommand {

    /// <summary>
    /// Method run on execution of the command
    /// </summary>
    /// <param name="args">CLI arguments for the command</param>
    public async Task Execute(string[] args) {
        
        // QuestPDF License
        QuestPDF.Settings.License = LicenseType.Community;

        try {

            // The path to the config file
            string configFile = Directory.GetCurrentDirectory() + "/St3wart.xml";
            if (!File.Exists(configFile)) { Errors.PrintError("Unable to find configuration file"); Help(); return; }

            // The type of report to generate
            ReportType reportType;
            if (args[1] == "check") { reportType = ReportType.Check; } else if (args[1] == "secure") { reportType = ReportType.Secure; } else { Errors.PrintError("Unknown action type"); Help(); return; }


            // Get the ID and pass state / secure state of each action
            List<XElement> entries = Config.FetchElements(configFile, (args[1] + args[2]).ToLower());
            List<(string, bool)> actionData = new List<(string, bool)>();
            if (entries == null) { Errors.PrintError("Unable to retrieve entries from action"); Help(); return; } else {
                foreach (XElement e in entries) {
                    string? id = (string?)e.Attribute("ID");
                    bool? pass;
                    if (reportType == ReportType.Check) { pass = (bool?)e.Attribute("CheckPass"); } else { pass = (bool?)e.Attribute("ProperlyRemediated"); }

                    if (id is string idStr && pass is bool chkPass) {
                        actionData.Add((idStr, chkPass));
                    }
                }
            }

            
            Document.Create(container => {
                container.Page(page => {
                    page.Margin(40);
                    page.Header()
                    .Text($"St3wart Action Report - ID: {args[2]}")
                    .SemiBold().FontSize(16).AlignCenter();

                    page.Content().Table(table => {

                        table.ColumnsDefinition(columns => {
                            columns.RelativeColumn();
                            columns.RelativeColumn();
                        });

                        table.Header(header => {
                            header.Cell().Text("ID");
                            if (reportType == ReportType.Check) { header.Cell().Text("Check Pass"); } else {header.Cell().Text("Vuln Secured"); }
                        });

                        foreach((string, bool) action in actionData) {
                            table.Cell().Text(action.Item1);
                            table.Cell().Text(action.Item2.ToString());
                        }
                    
                    });
                });
            })
            
            .GeneratePdf($"St3wart{args[2]}.pdf");

        } catch {
            Errors.PrintError("Error");
            Help();
        }
    }



    /// <summary>
    /// Displays help information on the command
    /// </summary>
    public void Help() {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("St3wart Report");
        Console.WriteLine("Generates a report of an action taken by St3wart");
        Console.WriteLine("Usage: St3wart.exe report [OPTIONS] <ACTION TYPE> <ACTION GUID>");
        Console.WriteLine("Example: St3wart.exe report secure abcdefghijklmnopqrstuvwxyz012345");
        Console.ResetColor();
    }
}
