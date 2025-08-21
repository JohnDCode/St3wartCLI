/*

Stewart CLI
/Commands/Exempt.cs - Exempt command, exempts vulns from being checked, secured, or otherwise noted by St3wart
JohnDavid Abe 

*/



// Packages
using System.Xml.Linq;


public class ExemptCommand : ICommand
{
    // Execute method (ran upon command)
    public void Execute(string[] args)
    {
        
        Console.WriteLine("HERE 1");
        // Check if configuration file has been created and create it if not
        string filePath = Directory.GetCurrentDirectory() + "/config.xml";
        if (!File.Exists(filePath)) { Config.CreateConfig(filePath); }

        Console.WriteLine("HERE 2");


        XElement e = new XElement("exemption", new XAttribute("ID", args[2]));

        if (args[1].ToLower() == "add")
        {
            Config.WriteElement(filePath, "exemptions", e);
        }
        else if (args[1].ToLower() == "remove")
        {
            Config.RemoveElement(filePath, "exemptions", e);
        }


    }
}
