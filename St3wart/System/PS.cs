/*

Stewart CLI
/System/PS.cs - Handles batch PowerShell checks
JohnDavid Abe 

*/



// Packages
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;



/// <summary>
/// Represents and handles one specific PowerShell instance / process
/// </summary>
public class PowerShellInstance : IDisposable {

    /// <summary>
    /// The powershell.exe process for this instance
    /// </summary>
    private Process? _process;

    /// <summary>
    /// The input stream to send commands to the process
    /// </summary>
    private StreamWriter? _inputWriter;

    /// <summary>
    /// Output stream to capture output from commands
    /// </summary>
    private StreamReader? _outputReader;

    /// <summary>
    /// Error stream
    /// </summary>
    private StreamReader? _errorReader;

    /// <summary>
    /// SemaphoreSlim for releasing commands
    /// </summary>
    private readonly SemaphoreSlim _semaphore = new(1, 1);

    /// <summary>
    /// The delimiter to mark the end to each command output in the output streams
    /// </summary>
    private readonly string _delimiter = $"###END_ST3WART_COMMAND_{Guid.NewGuid():N}###";

    /// <summary>
    /// Tracks if the resources have been cleared and freed after execution
    /// </summary>
    private volatile bool _disposed = false;



    /// <summary>
    /// Spawns the new PowerShell process
    /// </summary>
    /// <returns>
    /// The success state of initalizing the new PowerShell process
    /// </returns>
    public async Task<bool> InitializeAsync() {

        try {
            // Initalize the process
            var psi = new ProcessStartInfo {

                // NoProfile for faster startup, NoExit so the process doesn't kill after first command execution
                FileName = "powershell.exe",
                Arguments = "-NoExit -NoProfile -Command -",
                UseShellExecute = false,

                // Redirecting output to custom capture streams
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,

                // No new window (tool is meant to be run from single CLI window)
                CreateNoWindow = true
            };

            // Start the process
            _process = Process.Start(psi);

            // Ensure the process spawned
            if (_process == null) { return false; }

            // I/O Streams
            _inputWriter = _process.StandardInput;
            _outputReader = _process.StandardOutput;
            _errorReader = _process.StandardError;

            // Initialize the delimiter
            await _inputWriter.WriteLineAsync($"$delimiter = '{_delimiter}'");
            await _inputWriter.FlushAsync();

            // Instance has been properly initalized
            return true;
        }
        catch {
            // Free resources and return false if error was caught
            Dispose();
            return false;
        }
    }



    /// <summary>
    /// Execute a single command within the PowerShell instance and checks for the vuln finding according to the output
    /// </summary>
    /// <param name="check">The PowerShell check to execute</param>
    /// <param name="timeoutMs">The timeout (in ms) allotted for the command to run</param>
    /// <returns>
    /// The output and details of the check as a PowerShellResult object
    /// </returns>
    public async Task<PowerShellResult> ExecuteCheckAsync(PowerShellCheck check, int timeoutMs = 30000) {

        // Ensure the process resources have not been disposed of
        if (_disposed) throw new ObjectDisposedException(nameof(PowerShellInstance));

        // Wait to enter the semaphore slim
        await _semaphore.WaitAsync();
        try {

            // Handle cancellation state for the command
            using var cts = new CancellationTokenSource(timeoutMs);

            // Send command
            await _inputWriter!.WriteLineAsync(check.CheckCommand);
            await _inputWriter.WriteLineAsync($"Write-Output $delimiter");
            await _inputWriter.FlushAsync();

            // Build the output and error strings from the general output stream
            var output = new StringBuilder();
            var errors = new List<string>();

            // Define a blank result object to return if check does not complete
            PowerShellResult blank = new PowerShellResult {
                Check = check,
                Output = "",
                Errors = new List<string>(),
                TimedOut = false,
                CheckPass = false,
                Success = false
            };
            
            // Ensure streams populated
            if (_outputReader == null || _errorReader == null) { return blank; }

            try {
                
                // Read output until cancellation object cancels operation
                while (!cts.Token.IsCancellationRequested) {

                    // Read the next line
                    var line = await ReadLineWithTimeoutAsync(_outputReader, cts.Token, false);

                    // If the line is empty or the delimeter is reached, stop reading
                    if (line == null) break;
                    if (line == _delimiter) break;

                    // Log general output stream to output list
                    output.AppendLine(line);
                }

                // Read error stream until cancellation object cancels operation OR we reach 5 error lines (to save resources)
                for (int i = 0; i < 5 && !cts.Token.IsCancellationRequested; i++) {

                    // Read the next line
                    var line = await ReadLineWithTimeoutAsync(_errorReader, cts.Token, true);

                    // If the line is empty or the delimeter is reached, stop reading
                    if (line == null) break;
                    if (line == _delimiter) break;

                    // Log general output stream to output list
                    errors.Add(line);
                }

                // Get the output in the form of a trimmed string
                string outputStr = output.ToString().TrimEnd('\r', '\n');

                // Ensure the output and the data to compare to are populated
                if (outputStr == null || check.FindData == null) { return blank; }


                // Test the check pass based on the specific operator and PowerShell output
                bool checkPass = false;
                switch (check.Operator) {
                    case "GreaterThan": 
                        checkPass = !(int.Parse(outputStr) > int.Parse(check.FindData));
                        break;
                    case "LessThan":
                        checkPass = !(int.Parse(outputStr) < int.Parse(check.FindData));
                        break;
                    case "EqualTo":
                        checkPass = !(int.Parse(outputStr) == int.Parse(check.FindData) || outputStr == check.FindData);
                        break;
                    case "Contains":
                        checkPass = !outputStr.Contains(check.FindData);
                        break;
                    case "NotEqualTo":
                        checkPass = int.Parse(outputStr) == int.Parse(check.FindData) || outputStr == check.FindData;
                        break;
                    case "NotContains":
                        checkPass = outputStr.Contains(check.FindData);
                        break;
                    default:
                        break;
                }



                // Construct a result object to hold all relevant info of the check and return
                return new PowerShellResult {
                    Check = check,
                    Output = outputStr,
                    Errors = errors,
                    Success = errors.Count == 0,
                    TimedOut = cts.Token.IsCancellationRequested,
                    CheckPass = checkPass
                };
            }

            // If the check failed, return blank result
            catch (Exception) { return blank; }
        }

        finally {
            // Release semaphore slim so next command can enter
            _semaphore.Release();
        }
    }



    /// <summary>
    /// Attempt to remediate a single vulnerability using PowerShell
    /// </summary>
    /// <param name="check">The PowerShell check to secure</param>
    /// <param name="timeoutMs">The timeout (in ms) allotted for the command to run</param>
    /// <returns>
    /// The success and ID of the remediation attempt
    /// </returns>
    public async Task<(string, bool)> ExecuteSecureAsync(PowerShellCheck check, int timeoutMs = 30000) {

        // Ensure the process resources have not been disposed of
        if (_disposed) throw new ObjectDisposedException(nameof(PowerShellInstance));

        // Wait to enter the semaphore slim
        await _semaphore.WaitAsync();
        try {

            // Handle cancellation state for the command
            using var cts = new CancellationTokenSource(timeoutMs);

            // Send command
            await _inputWriter!.WriteLineAsync(check.SecureCommand);
            await _inputWriter.WriteLineAsync($"Write-Output $delimiter");
            await _inputWriter.FlushAsync();

            // Build the output and error strings from the general output stream
            var errors = new List<string>();

            // Get the ID of the check
            string id = "";
            if (check.ID is string temp) { id = temp; } else { return (id, false); }

            // Ensure streams populated
            if (_outputReader == null || _errorReader == null) { return (id, false); }

            try {
                
                // Read error stream until cancellation object cancels operation OR we reach 5 error lines (to save resources)
                for (int i = 0; i < 5 && !cts.Token.IsCancellationRequested; i++) {

                    // Read the next line
                    var line = await ReadLineWithTimeoutAsync(_errorReader, cts.Token, true);

                    // If the line is empty or the delimeter is reached, stop reading
                    if (line == null) break;
                    if (line == _delimiter) break;

                    // Log general output stream to output list
                    errors.Add(line);
                }

                // Return if the remediation was successful or not based on errors from PS SecureCommand
                return (id, errors.Count == 0);
            }

            // If the check failed, return blank result
            catch (Exception) { return (id, false); }
        }

        finally {
            // Release semaphore slim so next command can enter
            _semaphore.Release();
        }
    }
    
    

    /// <summary>
    /// Read the next line of a particular data stream
    /// </summary>
    /// <param name="reader">The stream to read output from</param>
    /// <param name="cancellationToken">The cancellation object to handle early execution exit</param>
    /// <returns>
    /// The compiled string representing the next line in the stream
    /// </returns>
    private async Task<string?> ReadLineWithTimeoutAsync(StreamReader reader, CancellationToken cancellationToken, bool readingError) {

        try {
            
            // Set the timeout based on if the output or error stream is being read (longer timeout for reading the output stream)
            int timeOut;
            if (readingError) {
                timeOut = 2000;
            } else {
                timeOut = 30000;
            }

            // Timeout task to cap time to retrieve next line
            var shortTimeoutTask = Task.Delay(timeOut, cancellationToken);

            // Read the line
            var readTask = reader.ReadLineAsync();

            // If reading from the output stream occurs first before the timeout expires
            if (await Task.WhenAny(readTask, shortTimeoutTask) == readTask) {

                // Return the stream output line
                return await readTask;
                
            // Return null as the cancellation task finished and retrieving the next stream line stalled
            } else { return null; }
        }

        // Read errors do not necessairly mean command errors, so simply return null
        catch (Exception) { return null; }
    }



    /// <summary>
    /// Free the resources from the process and kill the process
    /// </summary>
    public void Dispose() {

        // If already disposed no need to modify any resources
        if (_disposed) { return; }
        _disposed = true;

        // Attempt to run the exit command to PowerShell instance
        try {
            _inputWriter?.WriteLine("exit");
            _inputWriter?.Flush();
            _process?.WaitForExit(2000);

        // If there are any errors, resources will be freed forcibly anyways
        }
        catch { }

        // Kill the process and dispose/free all resources
        _process?.Kill();
        _process?.Dispose();
        _inputWriter?.Dispose();
        _outputReader?.Dispose();
        _errorReader?.Dispose();
        _semaphore?.Dispose();
    }
}



/// <summary>
/// Pool to handle multiple Powershell instances and releasing commands and checks to each concurrently via a Semaphore Slim
/// </summary>
public class PowerShellPool : IDisposable {

    /// <summary>
    /// The queue of processes / PowerShell instances to release commands/checks to
    /// </summary>
    private readonly ConcurrentQueue<PowerShellInstance> _availableInstances = new();

    /// <summary>
    /// The list of all processes / PowerShell instances maintained within the pool
    /// </summary>
    private readonly List<PowerShellInstance> _allInstances = new();

    /// <summary>
    /// Semaphore Slim object to handle concurrency
    /// </summary>
    private readonly SemaphoreSlim _semaphore;

    /// <summary>
    /// Size of the pool / the total number of maintained processes
    /// </summary>
    private readonly int _poolSize;

    /// <summary>
    /// Overall disposed state representing if all memory from all processes / PowerShell instances has been disposed and released
    /// </summary>
    private volatile bool _disposed = false;



    /// <summary>
    /// Constructor of the PowerShellPool object
    /// </summary>
    /// <param name="poolSize">Number to set the pool size of the overall pool to</param>
    public PowerShellPool(int poolSize = 5) {

        // Set the pool size and initalize the Semaphore with the new pool size
        _poolSize = poolSize;
        _semaphore = new SemaphoreSlim(poolSize, poolSize);
    }



    /// <summary>
    /// Initalize {_poolSize} number of PowerShell instances
    /// </summary>
    /// <returns>
    /// The overall success state of creating the instances
    /// </returns>
    public async Task<bool> InitializeAsync() {

        // Initalize each individual instance
        var tasks = new Task<PowerShellInstance>[_poolSize];
        for (int i = 0; i < _poolSize; i++) {
            tasks[i] = CreateInstanceAsync();
        }

        // Wait for all instances to be spawned and count the number of successfully launched instances
        var instances = await Task.WhenAll(tasks);
        var successfulInstances = instances.Where(i => i != null).ToList();

        // Ensure at least a single process succesfully spawned
        if (successfulInstances.Count == 0) { return false; }

        // Set the all instances list to the processes that were successfully spawned
        _allInstances.AddRange(successfulInstances);

        // Add each process to the queue to recieve commands
        foreach (var instance in successfulInstances) {
            _availableInstances.Enqueue(instance);
        }

        // Adjust Semaphore to number of sucessfully spawned instances
        var actualCount = successfulInstances.Count;

        // If some processes did not actually spawn
        if (actualCount < _poolSize) {
            // Release the difference to match actual instances
            _semaphore.Release(_poolSize - actualCount);
        }

        // Return true if some processes succesfully spawned and resources were delegated accordingly
        return true;
    }



    /// <summary>
    /// Create an object of and spawn a specific PowerShell instance
    /// </summary>
    /// <returns>
    /// The initalized PowerShellInstance object
    /// </returns>
    private async Task<PowerShellInstance> CreateInstanceAsync() {

        // Create the instance and spawn the instance
        var instance = new PowerShellInstance();
        var success = await instance.InitializeAsync();

        // If the process did not spawn properly, release the resources and do not return any instance object
        if (!success) {
            instance.Dispose();
            return null;
        }

        // Return the initalized object
        return instance;
    }



    /// <summary>
    /// Dispatch a single PowerShell check to the next available PowerShell instance to check for vuln
    /// </summary>
    /// <param name="check">The PowerShell check to execute and check</param>
    /// <param name="timeoutMs">The timeout (in ms) allotted for the command to run</param>
    /// <returns>
    /// The output and details of the check as a PowerShellResult object
    /// </returns>
    public async Task<PowerShellResult> ExecuteCheckAsync(PowerShellCheck check, int timeoutMs = 30000) {

        // If the pool resources have been disposed/released, can not execute command
        if (_disposed) { throw new ObjectDisposedException(nameof(PowerShellPool)); }

        // Wait in queue to enter the Sempahore Slim
        await _semaphore.WaitAsync();

        try {
            // Attempt to remove and then utilize the available PowerShell instance at the top of the queue
            if (_availableInstances.TryDequeue(out var instance)) {

                // Execute the command using the PowerShell instance and return the output
                try { return await instance.ExecuteCheckAsync(check, timeoutMs); }

                // Requeue the PowerShell instance to be used again
                finally { _availableInstances.Enqueue(instance); }
            }

            // Throw if can not remove any available instance of the top of the stack
            else { throw new InvalidOperationException("No PowerShell instance available"); }
        }

        // Release the Semaphore to move to the next command
        finally { _semaphore.Release(); }
    }


    
    /// <summary>
    /// Dispatch a single PowerShell check to the next available PowerShell instance for remediation
    /// </summary>
    /// <param name="check">The PowerShell check to secure</param>
    /// <param name="timeoutMs">The timeout (in ms) allotted for the command to run</param>
    /// <returns>
    /// The ID and success of the PowerShell remediation attempt
    /// </returns>
    public async Task<(string, bool)> ExecuteSecureAsync(PowerShellCheck check, int timeoutMs = 30000) {

        // If the pool resources have been disposed/released, can not execute command
        if (_disposed) { throw new ObjectDisposedException(nameof(PowerShellPool)); }

        // Wait in queue to enter the Sempahore Slim
        await _semaphore.WaitAsync();

        try {
            // Attempt to remove and then utilize the available PowerShell instance at the top of the queue
            if (_availableInstances.TryDequeue(out var instance)) {

                // Execute the command using the PowerShell instance and return the output
                try { return await instance.ExecuteSecureAsync(check, timeoutMs); }

                // Requeue the PowerShell instance to be used again
                finally { _availableInstances.Enqueue(instance); }
            }

            // Throw if can not remove any available instance of the top of the stack
            else { throw new InvalidOperationException("No PowerShell instance available"); }
        }

        // Release the Semaphore to move to the next command
        finally { _semaphore.Release(); }
    }
    
    

    /// <summary>
    /// Dispatch multiple PowerShell checks to all maintained PowerShell instances within the pool
    /// </summary>
    /// <param name="checks">The list of PowerShell checks to execute and check for findings</param>
    /// <param name="maxConcurrency">The number of checks that can run at once within this batch</param>
    /// <param name="timeoutMs">The timeout (in ms) allotted for the command for the check to run</param>
    public async Task<List<PowerShellResult>> ExecuteChecksBatchAsync(List<PowerShellCheck> checks, int maxConcurrency = -1, int timeoutMs = 30000) {

        // If set to -1, then just set the Semaphore Slim to use all available resources
        if (maxConcurrency == -1) maxConcurrency = _poolSize;

        // Start the Semaphore to handle the batch
        var semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);

        // Add all tasks to the Semaphore
        var tasks = checks.Select(async check => {

            // Enter the Semaphore
            await semaphore.WaitAsync();
            try {
                // Extract the output of the singular command
                return await ExecuteCheckAsync(check, timeoutMs);
            }

            // Release the Semaphore and allow it to move to the next task
            finally { semaphore.Release(); }
        });

        // Return the outputs of the commands (individual tasks) as a list
        return (await Task.WhenAll(tasks)).ToList();
    }
    
    
    
    /// <summary>
    /// Dispatch multiple PowerShell remediation attempts to all maintained PowerShell instances within the pool
    /// </summary>
    /// <param name="checks">The list of PowerShell checks to remediate</param>
    /// <param name="maxConcurrency">The number of checks that can run at once within this batch</param>
    /// <param name="timeoutMs">The timeout (in ms) allotted for the command for the check to run</param>
    public async Task<List<(string, bool)>> ExecuteSecureBatchAsync(List<PowerShellCheck> checks, int maxConcurrency = -1, int timeoutMs = 30000) {

        // If set to -1, then just set the Semaphore Slim to use all available resources
        if (maxConcurrency == -1) maxConcurrency = _poolSize;

        // Start the Semaphore to handle the batch
        var semaphore = new SemaphoreSlim(maxConcurrency, maxConcurrency);

        // Add all tasks to the Semaphore
        var tasks = checks.Select(async check => {

            // Enter the Semaphore
            await semaphore.WaitAsync();
            try {
                // Extract the output of the singular command
                return await ExecuteSecureAsync(check, timeoutMs);
            }

            // Release the Semaphore and allow it to move to the next task
            finally { semaphore.Release(); }
        });

        // Return the outputs of the commands (individual tasks) as a list
        return (await Task.WhenAll(tasks)).ToList();
    }



    /// <summary>
    /// Free the resources from all processes and kills all processes
    /// </summary>
    public void Dispose() {

        // If already freed resources no need to modify
        if (_disposed) return;
        _disposed = true;

        // Release all of the Powershell instances resources
        foreach (var instance in _allInstances) {
            instance.Dispose();
        }

        // End the Semaphore
        _semaphore?.Dispose();
    }
}



/// <summary>
/// Holds information on a single vuln whos presence can be checked with PowerShell
/// </summary>
public class PowerShellCheck : Check {

    /// <summary>
    /// The command to check the vuln's state
    /// </summary>
    public string? CheckCommand { get; set; }
    
    /// <summary>
    /// The command to remediate the vuln
    /// </summary>
    public string? SecureCommand { get; set; }
    
    public override string Print() {
        return $"Vuln: {this.ID}\nCheck Type: PowerShell\nDescription: {this.Description}\nCheck Command: {this.CheckCommand}\nSecure Command: {this.SecureCommand}\nFind Data: {this.FindData}\nOperator: {this.Operator}";
    }
}



/// <summary>
/// Handles information for the result of a single PowerShell check
/// </summary>
public class PowerShellResult {

    /// <summary>
    /// The check which this result object contains data on the success of
    /// </summary>
    public required PowerShellCheck Check { get; set; }

    /// <summary>
    /// The output of the command
    /// </summary>
    public required string Output { get; set; } = string.Empty;

    /// <summary>
    /// The error output of the command
    /// </summary>
    public required List<string> Errors { get; set; } = new();

    /// <summary>
    /// The success state of the command
    /// </summary>
    public required bool Success { get; set; }

    /// <summary>
    /// The state if the command timed out (execution did not complete)
    /// </summary>
    public required bool TimedOut { get; set; }

    /// <summary>
    /// The success of the check
    /// </summary>
    public required bool CheckPass { get; set; }
    
    /// <summary>
    /// Formats the result to a single string
    /// </summary>
    /// <returns>A formatted string with the PowerShellResult data</returns>
    public string Print() {
        return $"ID: {this.Check.ID}\nDescription: {this.Check.Description}\nCheck Pass: {this.CheckPass}";
    }
}
