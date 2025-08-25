/*

Stewart CLI
/Vulns/LoadVulns.cs - Load vulns from a JSON vuln database
JohnDavid Abe 

*/



// Namespaces
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;



/// <summary>
/// Handles retrieving data from a JSON vuln database
/// </summary>
public static class DataHandler {

    /// <summary>
    /// Loads data from a JSON vuln database
    /// </summary>
    /// <param name="filePath">Path to the JSON file</param>
    /// <returns>
    /// A dictionary of ID/Check key/value pairs
    /// </returns>
    public static Dictionary<string, Check> VulnsFromFile(string filePath) {
        
        // Create a dictionary of the Checks where the Check ID the key and the Check itself is the value 
        var dict = new Dictionary<string, Check>();

        try {

            // Read the entire file
            string jsonFromFile = File.ReadAllText(filePath);
            if (jsonFromFile == null) { return dict; }

            // Compile the JSON into a list of Checks
            var settings = new JsonSerializerSettings {
                Converters = { new CheckConverter() }
            };
            var checks = JsonConvert.DeserializeObject<List<Check>>(jsonFromFile, settings);
            if (checks == null) { return dict;  }
            
            // Loop through the Check from JSON and compile a dict using the ID's of each Check
            foreach (var check in checks) {
                if(check.ID != null) {
                    dict[check.ID] = check;
                }
            }
            
        } catch { }

        // Return the compiled dict
        return dict;
    }



    /// <summary>
    /// Custom JSON Converter for deseralizing JSON data
    /// </summary>
    private class CheckConverter : JsonConverter {

        // Override to set the object to deseralize to type Check
        public override bool CanConvert(Type objectType) => objectType == typeof(Check);
        
        // Override to change how deseralized JSON data is handled
        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer) {

            try {
                // Load the current JSON object
                JObject jo = JObject.Load(reader);
                if (jo == null) { return new Check(); }
                
                // Get the type of the check
                string? checkType = jo["CheckType"]?.ToString();
                
                // Assign accordingly to the new Check object
                Check check;
                switch (checkType) {
                    case "PowerShell":
                        check = new PowerShellCheck();
                        break;
                    case "Registry":
                        check = new RegistryCheck();
                        break;
                    case "File":
                        check = new FileCheck();
                        break;
                    default:
                        // Return an empty, general Check if the type of the Check is unidentified
                        return new Check();
                }
                
                // Populate the particular Check object and return it
                serializer.Populate(jo.CreateReader(), check);
                return check;
            
            // Return an empty, general Check if any errors occur
            } catch { return new Check();  }
        }

        // Override to write the object as JSON
        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer) {
            serializer.Serialize(writer, value);
        }
    }
}
