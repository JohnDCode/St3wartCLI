/*

Stewart CLI
/Config/Config.cs - Handles the configuration file for configuring the CLI tool 
JohnDavid Abe 

*/



// Packages
using System.Xml.Linq;



/// <summary>
/// Used to handle all interactions with the config.xml file
/// </summary>
public static class Config {

    /// <summary>
    /// Creates the configuration file
    /// </summary>
    /// <param name="filePath">Path to store the configuration file</param>
    public static void CreateConfig(string filePath) {

        // Create (with default St3wart config layout) and save the configuration file
        var doc = new XDocument(new XElement("config", new XElement("exemptions")));
        doc.Save(filePath);
    }

    /// <summary>
    /// Write an element to the configuration file
    /// </summary>
    /// <param name="filePath">Path to the configuration file</param>
    /// <param name="section">Section to insert the new element in</param>
    /// <param name="newElement">Element to insert to the configuration file</param>
    public static void WriteElement(string filePath, string section, XElement newElement) {

        // Load the XML config
        XDocument doc = XDocument.Load(filePath);

        // Find the section (or the first occurrence)
        XElement XMLSection = doc.Root.Element(section);

        // Add the new element to the section
        XMLSection.Add(newElement);

        // Save changes back to the file
        doc.Save(filePath);
    }

    /// <summary>
    /// Remove an element from the configuration file
    /// </summary>
    /// <param name="filePath">Path to the configuration file</param>
    /// <param name="section">Section to remove the element from</param>
    /// <param name="removeElement">Element to remove from the configuration file</param>
    public static void RemoveElement(string filePath, string section, XElement removeElement) {

        // Load the XML config
        XDocument doc = XDocument.Load(filePath);

        // Find the section (or the first occurrence)
        XElement XMLSection = doc.Root.Element(section);

        // Find the element within the section
        XElement match = XMLSection.Elements().FirstOrDefault(e => XNode.DeepEquals(e, removeElement));

        // Remove the element and save changes back to the file
        match.Remove();
        doc.Save(filePath);
    }
}
