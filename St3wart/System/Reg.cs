/*

Stewart CLI
/System/Reg.cs - Handles batch Registry requests
JohnDavid Abe 

*/



// Packages
using Microsoft.Win32;



/// <summary>
/// Used to execute batch checks to the Windows registry
/// </summary>
public class RegistryRunner {

    /// <summary>
    /// Executes a single Registry check and returns the result of the finding / check
    /// </summary>
    /// <param name="check">The Registry check to execute</param>
    /// <returns>The result of the check with the retrieved data and the findings of the check</returns>
    private static RegistryResult CheckRegistry(RegistryCheck check) {
        
        // Define a blank result object to return if check does not complete
        RegistryResult result = new RegistryResult {
            Check = check,
            Data = "",
            CheckPass = false,
            Success = false
        };
        
        try {

            // Split the key into the root key and its subkey
            int firstSlash = check.Key.IndexOf(@"\");
            if (firstSlash == -1) { return result; }
            string baseKey = check.Key.Substring(0, firstSlash);
            string subKey = check.Key.Substring(firstSlash + 1);


            // Determine the base key and open the root key accordingly (allows for abbreviation in root key)
            RegistryKey baseRk;
            if (baseKey.Contains("HKEY_CLASSES_ROOT") || baseKey.Contains("HKCR")) {
                baseRk = Registry.ClassesRoot;
            } else if (baseKey.Contains("HKEY_CURRENT_USER") || baseKey.Contains("HKCU")) {
                baseRk = Registry.CurrentUser;
            } else if (baseKey.Contains("HKEY_LOCAL_MACHINE") || baseKey.Contains("HKLM")) {
                baseRk = Registry.LocalMachine;
            } else if (baseKey.Contains("HKEY_USERS") || baseKey.Contains("HKU")) {
                baseRk = Registry.Users;
            } else if (baseKey.Contains("HKEY_CURRENT_CONFIG") || baseKey.Contains("HKCC")) {
                baseRk = Registry.CurrentConfig;
            } else { return result; }


            // Open the subkey
            using var subRk = baseRk.OpenSubKey(subKey);
            if (subRk == null) { return result; }

            // Access the value within the subkey
            var value = subRk.GetValue(check.Value);
            if (value == null) { return result; }

            // Close the base and sub key
            baseRk.Close();
            subRk.Close();

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
                case "NotEqualTo":
                    checkPass = int.Parse(value.ToString().TrimEnd('\r', '\n')) == int.Parse(check.FindData) || value.ToString().TrimEnd('\r', '\n') == check.FindData;
                    break;
                case "NotContains":
                    checkPass = value.ToString().TrimEnd('\r', '\n').Contains(check.FindData);
                    break;
                default:
                    break;
            }


            // Construct a struct to hold all relevant info of the command and return
            return new RegistryResult {
                Check = check,
                Data = value.ToString(),
                CheckPass = checkPass,
                Success = true
            };

        }
        catch (Exception e) { return result; }
    }



    /// <summary>
    /// Executes batch Registry checks
    /// </summary>
    /// <param name="checks">The list of Registry checks to execute</param>
    /// <returns>A list of Registry results</returns>
    public static List<RegistryResult> ExecuteRegistryChecks(List<RegistryCheck> checks) {

        // Loop through the checks, perform each, and add the result to the list
        List<RegistryResult> results = new List<RegistryResult>();
        foreach (RegistryCheck check in checks) {
            results.Add(CheckRegistry(check));
        }

        // Return the list of results
        return results;
    }
}



/// <summary>
///  Handles information for the result of a single Powershell check
/// </summary>
public class RegistryCheck {

    /// <summary>
    /// The ID of the vuln to check
    /// </summary>
    public required string ID { get; set; }

    /// <summary>
    /// A description of the vuln to check
    /// </summary>
    public required string Description { get; set; }

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
    /// // Options for operators are: GreaterThan (numerical data), LessThan (numerical data), EqualTo (numerical or textual data), Contains (numerical or textual data), NotEqualTo (numerical or textual data), NotContains (numerical or textual data)
    /// </regards>
    public required string Operator { get; set; }
    
    /// <summary>
    /// The value to set within the specific registry key to secure the vuln
    /// </summary>
    public required string SecureValue { get; set; }
}



/// <summary>
/// Handles information for the result of a single Powershell check
/// </summary>
public class RegistryResult
{

    /// <summary>
    /// The check which this result object contains data on the success of
    /// </summary>
    public required RegistryCheck Check { get; set; }

    /// <summary>
    /// The data from the registry value
    /// </summary>
    public required string Data { get; set; } = string.Empty;

    /// <summary>
    /// The success of the check
    /// </summary>
    public required bool CheckPass { get; set; }
    
    /// <summary>
    /// The success state of the registry request
    /// </summary>
    public required bool Success { get; set; }
}
