/*

Stewart CLI
/System/PS.cs - Handles all Registry requests
JohnDavid Abe 

*/



// Packages
using Microsoft.Win32;



public class RegistryRunner
{

    private static RegistryResult CheckRegistry(RegistryCheck check)
    {
        try
        {

            // Split the key into the root key and its subkey
            int firstSlash = check.Key.IndexOf(@"\");
            if (firstSlash == -1) { return null; }
            string baseKey = check.Key.Substring(0, firstSlash);
            string subKey = check.Key.Substring(firstSlash + 1);

            Console.WriteLine(baseKey);
            Console.WriteLine(subKey);

            // Determine the root key and open the root key
            RegistryKey baseRk;
            if (baseKey.Contains("HKEY_CLASSES_ROOT") || baseKey.Contains("HKCR"))
            {
                baseRk = Registry.ClassesRoot;
            }
            else if (baseKey.Contains("HKEY_CURRENT_USER") || baseKey.Contains("HKCU"))
            {
                baseRk = Registry.CurrentUser;
            }
            else if (baseKey.Contains("HKEY_LOCAL_MACHINE") || baseKey.Contains("HKLM"))
            {
                baseRk = Registry.LocalMachine;
            }
            else if (baseKey.Contains("HKEY_USERS") || baseKey.Contains("HKU"))
            {
                baseRk = Registry.Users;
            }
            else if (baseKey.Contains("HKEY_CURRENT_CONFIG") || baseKey.Contains("HKCC"))
            {
                baseRk = Registry.CurrentConfig;
            }
            else { return null; }



            // Attempt to open the key, return if not able to open
            using var rk = baseRk.OpenSubKey(subKey);
            if (rk == null) { return null; }

            Console.WriteLine("HERE");

            // Attempt to access the value
            var value = rk.GetValue(check.Value);
            if (value == null) { return null; }

            Console.WriteLine("HERE 2");

            // Close the root and specific key
            baseRk.Close();
            rk.Close();

            // Test the check pass based on the specific operator 
            bool checkPass = false;
            switch (check.Operator) {
                case "GreaterThan": 
                    checkPass = !(int.Parse(value.ToString().TrimEnd('\r', '\n')) > int.Parse(check.FindData));
                    break;
                case "LessThan":
                    checkPass = !(int.Parse(value.ToString().TrimEnd('\r', '\n')) < int.Parse(check.FindData));
                    break;
                case "EqualTo":
                    checkPass = !(int.Parse(value.ToString().TrimEnd('\r', '\n')) == int.Parse(check.FindData) || value.ToString().TrimEnd('\r', '\n') == check.FindData);
                    break;
                case "Contains":
                    checkPass = !value.ToString().TrimEnd('\r', '\n').Contains(check.FindData);
                    break;
                default:
                    break;
            }


            // Construct a struct to hold all relevant info of the command and return
            return new RegistryResult
            {
                Data = value.ToString(),
                CheckPass = checkPass
            };

        }
        catch (Exception e) { return null; }
    }

    public static List<RegistryResult> ExecuteRegistryChecks(List<RegistryCheck> checks)
    {
        List<RegistryResult> results = new List<RegistryResult>();

        foreach (RegistryCheck check in checks)
        {
            results.Add(CheckRegistry(check));
        }

        return results;
    }
}

   



public class RegistryResult
{
    /// <summary>
    /// The data from the registry value
    /// </summary>
    public string Data { get; set; } = string.Empty;

    /// <summary>
    /// The success of the check
    /// </summary>
    public bool CheckPass { get; set; }
}



public class RegistryCheck {

    /// <summary>
    /// The ID of the vuln to check
    /// </summary>
    public required string ID { get; set; }

    /// <summary>
    /// The key to check within the registry
    /// </summary>
    public required string Key { get; set; }

    /// <summary>
    /// The value to check within the specific registry key
    /// </summary>
    public required string Value { get; set; }

    /// <summary>
    /// The data which if identified within the key/value pair, indicates a finding
    /// </summary>
    public required string FindData { get; set; }
    
    /// <summary>
    /// The operator to perform on the data with the output of the command to get a finding
    /// </summary>
    /// <regards>
    /// Options for operators are: GreaterThan (numerical data), LessThan (numerical data), EqualTo (numerical or textual data), Contains (numerical or textual data)
    /// </regards>
    public required string Operator { get; set; }
}




