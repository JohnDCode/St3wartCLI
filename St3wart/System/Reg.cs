/*

Stewart CLI
/System/Reg.cs - Handles batch Registry checks
JohnDavid Abe 

*/



// Packages
using Microsoft.Win32;
using System.Runtime.Versioning;



/// <summary>
/// Used to execute batch checks to the Windows Registry
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
        RegistryResult blank = new RegistryResult {
            Check = check,
            Data = "",
            CheckPass = false,
            Success = false
        };
        
        try {

            // Ensure check and value exists in Check
            if (check.Key == null || check.Value == null) { return blank; }

            // Split the key into the root key and its subkey
            int firstSlash = check.Key.IndexOf(@"\");
            if (firstSlash == -1) { return blank; }

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
            } else { return blank; }

            // Check that the base key opened
            if (baseRk == null) { return blank; }

            // Stores if the key/value actually exists as a path
            bool valExists = true;

            // Open the subkey
            RegistryKey? subRk = baseRk.OpenSubKey(subKey);

            // Save the value within the subkey
            object? value = null;

            // Check that the subkey opened and attempt to access value
            if (subRk == null) { valExists = false; } else {
                value = subRk.GetValue(check.Value);

                // Close the subkey
                subRk.Close();
            }

            // Check if the value was extracted
            if (value == null) { valExists = false; }

            // Close the base key
            baseRk.Close();
            

            // If the registry path does not exist and the operator is a positive operator, the check passes -->
                // If text within a file results in a finding, the file not existing results in a non finding and a successful check
            
            // Also check for Exists and NotExists operators here (crazy logic here)
            
            if (!valExists) {
                
                if (check.Operator == "Exists" || check.Operator == "Contains" || check.Operator == "EqualTo") {
                    blank.CheckPass = true;
                    blank.Success = true;
                } else if (check.Operator == "NotExists") {
                    blank.Success = true;
                }
                return blank;
                
            } else {
                if (check.Operator == "Exists") {
                    blank.Success = true;
                    return blank;
                } else if (check.Operator == "NotExists") {
                    blank.CheckPass = true;
                    blank.Success = true;
                    return blank;
                }
            }

            // Define if the check passed or not
            bool checkPass = false;

            // Ensure check data was populated in the given check
            if (value is object regVal) {

                // Get the Registry value as a string
                string? strValue = value.ToString();

                // Ensure the value and the data to compare to are populated
                if (strValue == null || check.FindData == null) { return blank; }

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
            } else { return blank; }
        }
        catch (Exception) { return blank; }
    }



    /// <summary>
    /// Executes batch Registry checks
    /// </summary>
    /// <param name="checks">The list of Registry checks to execute</param>
    /// <returns>A list of RegistryResults from the checks</returns>
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
    /// The key to check within the Registry
    /// </summary>
    public string? Key { get; set; }

    /// <summary>
    /// The value to check within the specific Registry key
    /// </summary>
    public string? Value { get; set; }
    
    /// <summary>
    /// The data to write within the specific Registry key/value to remediate the vuln
    /// </summary>
    public string? SecureValue { get; set; }
        
    public override string Print() {
        return $"Vuln: {this.ID}\nCheck Type: Registry\nDescription: {this.Description}\nKey: {this.Key}\nValue: {this.Value}\nFind Data: {this.FindData}\nSecure Value: {this.SecureValue}\nOperator: {this.Operator}";
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
    /// The data from the Registry value
    /// </summary>
    public required string Data { get; set; } = string.Empty;

    /// <summary>
    /// The success of the check
    /// </summary>
    public required bool CheckPass { get; set; }
    
    /// <summary>
    /// The success state of the Registry request
    /// </summary>
    public required bool Success { get; set; }
    
    /// <summary>
    /// Formats the result to a single string
    /// </summary>
    /// <returns>A formatted string with the RegistryResult data</returns>
    public string Print() {
        return $"ID: {this.Check.ID}\nDescription: {this.Check.Description}\nCheck Pass: {this.CheckPass}";
    }
}
