/*

Stewart CLI
/Config/Config.cs - Handles the configuration file for configuring the CLI tool 
JohnDavid Abe 

*/



// Packages
using System.Xml.Linq;



/// <summary>
/// Handles all interactions with the config.xml file
/// </summary>
public static class Config {

    /// <summary>
    /// Creates the configuration file
    /// </summary>
    /// <param name="filePath">Path to store the configuration file</param>
    /// <returns>
    /// Success of creating the file
    /// </returns>
    public static bool CreateConfig(string filePath) {
        
        try {
            // Create (with default St3wart config layout) and save the configuration file
            var doc = new XDocument(new XElement("st3wart", new XElement("config", new XElement("exemptions")), new XElement("logs", new XElement("checks"), new XElement("secures"))));
            doc.Save(filePath);
        } catch {
            return false;
        }
        return true;
    }



    /// <summary>
    /// Write an element to the configuration file
    /// </summary>
    /// <param name="filePath">Path to the configuration file</param>
    /// <param name="section">Section to insert the new element in</param>
    /// <param name="newElement">Element to insert to the configuration file</param>
    /// <returns>
    /// Success of writing the element to the config file
    /// </returns>
    public static bool WriteElement(string filePath, string section, XElement newElement) {

        try {
            // Load the XML config
            XDocument? doc = XDocument.Load(filePath);

            // Ensure the doc exists and is valid
            if (doc == null || doc.Root == null) { return false; }

            // Find the section (or the first occurrence)
            XElement? XMLSection = doc.Descendants(section).FirstOrDefault();

            // Check that the section was found
            if (XMLSection == null) { return false; }

            // Add the new element to the section
            XMLSection.Add(newElement);

            // Save changes back to the file
            doc.Save(filePath);
            
        } catch {
            return false;
        }
        return true;
    }



    /// <summary>
    /// Remove an element from the configuration file
    /// </summary>
    /// <param name="filePath">Path to the configuration file</param>
    /// <param name="section">Section to remove the element from</param>
    /// <param name="removeElement">Element to remove from the configuration file</param>
    /// <returns>
    /// Success of removing the element from the config file
    /// </returns>
    public static bool RemoveElement(string filePath, string section, XElement removeElement) {

        try {
            // Load the XML config
            XDocument? doc = XDocument.Load(filePath);

            // Ensure the doc exists and is valid
            if (doc == null || doc.Root == null) { return false; }

            // Find the section (or the first occurrence)
            XElement? XMLSection = doc.Descendants(section).FirstOrDefault();

            // Check that the section was found
            if (XMLSection == null) { return false; }

            // Find the element within the section
            XElement? match = XMLSection.Elements().FirstOrDefault(e => XNode.DeepEquals(e, removeElement));

            // Check if a match was found to the element
            if (match == null) { return false; }

            // Remove the element and save changes back to the file
            match.Remove();

            // Save changes back to the file
            doc.Save(filePath);
            
        } catch {
            return false;
        }
        return true;
    }
    
    
    
    /// <summary>
    /// Fetch all elements from a section of the configuration file
    /// </summary>
    /// <param name="filePath">Path to the configuration file</param>
    /// <param name="section">Section to fetch elements from</param>
    /// <returns></returns>
    public static List<XElement> FetchElements(string filePath, string section) {
        
        try {
            // Load the XML config
            XDocument? doc = XDocument.Load(filePath);

            // Ensure the doc exists and is valid
            if (doc == null || doc.Root == null) { return new List<XElement>(); }
            
            // Find the section (or the first occurrence of the section)
            XElement? XMLSection = doc.Descendants(section).FirstOrDefault();

            // Check that the section was found
            if (XMLSection == null) { return new List<XElement>(); }

            // Retrieve the elements within the section
            List<XElement> elements = [.. XMLSection.Elements()];
            
            // Ensure the elements were found and return accordingly
            if (elements == null) { return new List<XElement>(); }
            return elements;
            
        } catch {
            return new List<XElement>();
        }
    }
}
