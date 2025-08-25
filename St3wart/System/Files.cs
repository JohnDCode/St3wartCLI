/*

Stewart CLI
/System/Files.cs - Handles batch file checks
JohnDavid Abe 

*/



// Namespaces
using System.Data.Common;
using System.Runtime.Versioning;



/// <summary>
/// Used to execute batch checks to files within the NTFS
/// </summary>
[SupportedOSPlatform("Windows")]
public static class FileRunner {

    /// <summary>
    /// Executes a single file check and returns the result of the finding / check
    /// </summary>
    /// <param name="check">The file check to execute</param>
    /// <returns>The result of the check with the retrieved data and the findings of the check</returns>
    private async static Task<FileResult> CheckFile(FileCheck check) {
        
        // Define a blank result object to return if check does not complete
        FileResult blank = new FileResult {
            Check = check,
            CheckPass = false,
            Success = false
        };
        
        try {

            // Ensure the file path exists (if the file path does not exist and the operator is a positive operator, the check passes -->
                // If text within a file results in a finding, the file not existing results in a non finding and a successful check
            
            // Also check for Exists and NotExists operators here (crazy logic here)
            
            if (!File.Exists(check.Path)) {
                
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

            // Read the data from the file
            string? data = File.ReadAllText(check.Path);

            // Ensure data from file and data to compare to populated
            if (data == null || check.FindData == null) { return blank; }

            // Define if the check passed or not
            bool checkPass = false;

            // Test the check pass based on the specific operator
            switch (check.Operator) {
                // Operators greater than and less than can not apply in file checks (use powershell for more advanced file checks)
                case "GreaterThan":
                case "LessThan":
                    return blank;
                case "EqualTo":
                    checkPass = !(data == check.FindData);
                    break;
                case "Contains":
                    checkPass = !data.Contains(check.FindData);
                    break;
                case "NotEqualTo":
                    checkPass = data == check.FindData;
                    break;
                case "NotContains":
                    checkPass = data.Contains(check.FindData);
                    break;
                default:
                    break;
            }
                
            // Construct a struct to hold all relevant info of the command and return
            return new FileResult {
                Check = check,
                CheckPass = checkPass,
                Success = true
            };
        }

        // If the value did not populate properly, return blank FileResult
        catch (Exception) { return blank; }
    }
    
    
    
    /// <summary>
    /// Attempts to remediate a single File check
    /// </summary>
    /// <param name="check">The file check to remediate</param>
    /// <returns>The ID and success of the remediation attempt</returns>
    private async static Task<(string, bool)> SecureFile(FileCheck check) {
        
        // Get the ID of the check
        string id = "";
        if (check.ID is string temp) { id = temp; } else { return (id, false); }

        try {

            // Ensure check data populated
            if (check.Path == null || check.SecureText == null || check.FindData == null) { return (id, false); }

            
            // If the operator is exists, delete the file
            if (check.Operator == "Exists") {
                // Check if the file exists and then delete
                if (File.Exists(check.Path)) { File.Delete(check.Path); } else { return (id, false); }
            
            // If the operator is not exists, create the file
            } else if (check.Operator == "NotExists") {
                // Check if the file exists and then create it
                if (!File.Exists(check.Path)) { File.Create(check.Path); } else { return (id, false); }

                // Write the secure data to the file
                File.WriteAllText(check.Path, check.SecureText);

            // If just typical check, just replace the insecure data with secure data
            } else {
                // Get the file data
                string? data = File.ReadAllText(check.Path);
                
                // Ensure data from file and data to compare to populated
                if (data == null) { return (id, false); }

                // Replace all occurrences of the insecure text with secure text and save back to file
                string updatedData = data.Replace(check.FindData, check.SecureText);
                File.WriteAllText(check.Path, updatedData);
            }

            // If no issues, return as successful remediation
            return (id, true);
        }

        // If the value did not populate properly, return blank FileResult
        catch (Exception) { return (id, false); }
    }



    /// <summary>
    /// Executes batch file checks
    /// </summary>
    /// <param name="checks">The list of file checks to execute</param>
    /// <returns>A list of FileResults from the checks</returns>
    public async static Task<List<FileResult>> ExecuteFileChecks(List<FileCheck> checks, int poolSize) {

        // Create the Semaphore to handle concurrency
        var semaphore = new SemaphoreSlim(poolSize, poolSize);

        // Run all the tasks with the Sempahore
        var tasks = checks.Select(async check => {

            // Enter the Semaphore
            await semaphore.WaitAsync();
            try {
                // Get the results of this check
                return await CheckFile(check);
            }

            // Release the Semaphore and allow it to move to the next task
            finally { semaphore.Release(); }
        });

        // Return the results of each check as a list
        return (await Task.WhenAll(tasks)).ToList();
    }
    
    
    
    /// <summary>
    /// Executes batch file remediation attempts
    /// </summary>
    /// <param name="checks">The list of file checks to remediate</param>
    /// <returns>A list of ID and success tupples for each remediation attempt</returns>
    public async static Task<List<(string, bool)>> ExecuteFileSecure(List<FileCheck> checks, int poolSize) {

        // Create the Semaphore to handle concurrency
        var semaphore = new SemaphoreSlim(poolSize, poolSize);

        // Run all the tasks with the Sempahore
        var tasks = checks.Select(async check => {

            // Enter the Semaphore
            await semaphore.WaitAsync();
            try {
                // Get the results of this check
                return await SecureFile(check);
            }

            // Release the Semaphore and allow it to move to the next task
            finally { semaphore.Release(); }
        });

        // Return the results of each check as a list
        return (await Task.WhenAll(tasks)).ToList();
    }
}



/// <summary>
///  Holds information on a single vuln whos presence can be checked within some file
/// </summary>
public class FileCheck : Check {

    /// <summary>
    /// The absolute path of the file to check
    /// </summary>
    public string? Path { get; set; }
    
    /// <summary>
    /// The text to replace the lines where the finding occurred to remediate the vuln
    /// </summary>
    public string? SecureText { get; set; }
        
    public override string Print() {
        return $"Vuln: {this.ID}\nCheck Type: File\nDescription: {this.Description}\nPath: {this.Path}\nFind Data: {this.FindData}\nSecure Text: {this.SecureText}";
    }
}



/// <summary>
/// Handles information for the result of a single file check
/// </summary>
public class FileResult {

    /// <summary>
    /// The check which this result object contains data on the success of
    /// </summary>
    public required FileCheck Check { get; set; }

    /// <summary>
    /// The success of the check
    /// </summary>
    public required bool CheckPass { get; set; }
    
    /// <summary>
    /// The success of the file read
    /// </summary>
    public required bool Success { get; set; }
    
    /// <summary>
    /// Formats the result to a single string
    /// </summary>
    /// <returns>A formatted string with the FileResult data</returns>
    public string Print() {
        return $"ID: {this.Check.ID}\nDescription: {this.Check.Description}\nCheck Pass: {this.CheckPass}";
    }
}
