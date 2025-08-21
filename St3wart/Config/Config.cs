/*

Stewart CLI
/Config/Config.cs - Handles the configuration file for configuring the CLI tool 
JohnDavid Abe 

*/



// Packages
using System.Xml.Linq;



public static class Config
{
    public static void CreateConfig(string filePath)
    {

        Console.WriteLine(filePath);
        
        var doc = new XDocument(new XElement("config", new XElement("exemptions")));

        doc.Save(filePath);
    }

    public static void WriteElement(string filePath, string section, XElement newElement)
    {
        // Load the XML document
        XDocument doc = XDocument.Load(filePath);

        // Find the section (first occurrence of sectionName)
        XElement XMLSection = doc.Root.Element(section);

        // Add the new element
        XMLSection.Add(newElement);

        // Save changes back to file
        doc.Save(filePath);
    }

    public static void RemoveElement(string filePath, string section, XElement removeElement)
    {
        // Load the XML document
        XDocument doc = XDocument.Load(filePath);

        // Find the section (first occurrence of sectionName)
        XElement XMLSection = doc.Root.Element(section);

        XElement? match = XMLSection.Elements().FirstOrDefault(e => XNode.DeepEquals(e, removeElement));

        if (match != null) {
            match.Remove();
            doc.Save(filePath);
        }

    }
}