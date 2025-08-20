/*

Stewart CLI
/Vulns/LoadVulns.cs - Load vulns from a file
JohnDavid Abe 

*/



// Packages
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;



public static class DataHandler
{
    public static Dictionary<string, Check> VulnsFromFile(string filePath)
    {
        string jsonFromFile = File.ReadAllText(filePath);

        var settings = new JsonSerializerSettings
        {
            Converters = { new CheckConverter() }
        };

        var checks = JsonConvert.DeserializeObject<List<Check>>(jsonFromFile, settings);

        var dict = new Dictionary<string, Check>();
        foreach (var check in checks)
        {
            dict[check.ID] = check;
        }

        return dict;
    }

    private class CheckConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType) => objectType == typeof(Check);

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            JObject jo = JObject.Load(reader);
            string checkType = jo["CheckType"]?.ToString();

            Check check;
            switch (checkType)
            {
                case "PowerShell":
                    check = new PowerShellCheck();
                    break;
                case "Registry":
                    check = new RegistryCheck();
                    break;
                default:
                    throw new NotSupportedException($"Unknown CheckType: {checkType}");
            }

            serializer.Populate(jo.CreateReader(), check);
            return check;
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            serializer.Serialize(writer, value);
        }
    }
}
