/*

Stewart CLI
/System/Reg.cs - Handles batch Registry requests
JohnDavid Abe 

*/



// Packages
using Microsoft.Win32;
using System.Runtime.Versioning;



/// <summary>
/// Used to execute batch checks to the Windows registry
/// </summary>
[SupportedOSPlatform("Windows")]
public static class RegistryRunner {

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

            // Ensure check and value exists in Check
            if (check.Key == null || check.Value == null) { return result; }

            // Split the key into the root key and its subkey
            int firstSlash = check.Key.IndexOf(@"\");
            if (firstSlash == -1) { return result; }

            // Seperate the key into the base and subkey
            string baseKey = check.Key.Substring(0, firstSlash);
            string subKey = check.Key.Substring(firstSlash + 1);

            // Determine the base key and load accordingly (allows for abbreviation in JSON)
            RegistryKey? baseRk;
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

            // Check that the base key opened
            if (baseRk == null) { return result; }

            // Open the subkey
            RegistryKey? subRk = baseRk.OpenSubKey(subKey);

            // Check that the subkey opened
            if (subRk == null) { return result; }

            // Access the value within the subkey
            var value = subRk.GetValue(check.Value);
            if (value == null) { return result; }

            // Close the base and sub key
            baseRk.Close();
            subRk.Close();

            // Define if the check passed or not
            bool checkPass = false;

            // Ensure check data was populated in the given check
            if (value is object regVal) {

                // Get the Registry value as a string
                string? strValue = value.ToString();

                // Ensure the value and the data to compare to are populated
                if (strValue == null || check.FindData == null) { return result; }

                // Test the check pass based on the specific operator
                switch (check.Operator) {
                    case "GreaterThan":
                        checkPass = !(int.Parse(strValue.TrimEnd('\r', '\n')) > int.Parse(check.FindData));
                        break;
                    case "LessThan":
                        checkPass = !(int.Parse(strValue.TrimEnd('\r', '\n')) < int.Parse(check.FindData));
                        break;
                    case "EqualTo":
                        checkPass = !(int.Parse(strValue.TrimEnd('\r', '\n')) == int.Parse(check.FindData) || strValue.TrimEnd('\r', '\n') == check.FindData);
                        break;
                    case "Contains":
                        checkPass = !strValue.TrimEnd('\r', '\n').Contains(check.FindData);
                        break;
                    case "NotEqualTo":
                        checkPass = int.Parse(strValue.TrimEnd('\r', '\n')) == int.Parse(check.FindData) || strValue.TrimEnd('\r', '\n') == check.FindData;
                        break;
                    case "NotContains":
                        checkPass = strValue.TrimEnd('\r', '\n').Contains(check.FindData);
                        break;
                    default:
                        break;
                }
                
                // Construct a struct to hold all relevant info of the command and return
                return new RegistryResult {
                    Check = check,
                    Data = strValue,
                    CheckPass = checkPass,
                    Success = true
                };
            
            
            
            // If the value did not populate properly, return blank RegistryResult
            } else { return result; }
        }
        catch (Exception) { return result; }
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
///  Holds information on a single vuln whos presence can be checked with the Registry
/// </summary>
public class RegistryCheck : Check {

    /// <summary>
    /// The key to check within the registry
    /// </summary>
    public string? Key { get; set; }

    /// <summary>
    /// The value to check within the specific registry key
    /// </summary>
    public string? Value { get; set; }
    
    /// <summary>
    /// The data to write within the specific registry key/value to remediate the vuln
    /// </summary>
    public string? SecureValue { get; set; }
        
    public override string Print() {
        return $"Vuln: {this.ID}\nDescription: {this.Description}\nKey: {this.Key}\nValue: {this.Value}\nFind Data: {this.FindData}\nSecure Value: {this.SecureValue}\nOperator: {this.Operator}";
    }
}



/// <summary>
/// Handles information for the result of a single Registry check
/// </summary>
public class RegistryResult {

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
