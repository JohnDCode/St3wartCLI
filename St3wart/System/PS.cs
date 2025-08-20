/*

Stewart CLI
/System/PS.cs - Handles batch Powershell requests
JohnDavid Abe 

*/



// Packages
using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Text;



/// <summary>
/// Represents and handles one specific Powershell instance / process
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
    /// Seaphmore slim, controls releasing new commands
    /// </summary>
    private readonly SemaphoreSlim _semaphore = new(1, 1);

    /// <summary>
    /// The delimiter to mark the end to each command output in the output streams
    /// </summary>
    private readonly string _delimiter = $"###END_COMMAND_{Guid.NewGuid():N}###";

    /// <summary>
    /// Tracks if the resources have been cleared and freed after execution
    /// </summary>
    private volatile bool _disposed = false;



    /// <summary>
    /// Spawns the new Powershell process
    /// </summary>
    /// <returns>
    /// The success state of initalizing the new Powershell process
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
            if (_process == null) return false;

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
    /// Execute a single command within the Powershell instance and checks for the appropriate vuln finding
    /// </summary>
    /// <param name="check">The Powershell check to execute</param>
    /// <param name="timeoutMs">The timeout (in ms) allotted for the command to run</param>
    /// <returns>
    /// The output and details of the check as a PowershellResult object
    /// </returns>
    public async Task<PowerShellResult> ExecuteCommandAsync(PowerShellCheck check, int timeoutMs = 30000) {

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

                // Test the check pass based on the specific operator and PowerShell output
                bool checkPass = false;
                switch (check.Operator) {
                    case "GreaterThan": 
                        checkPass = !(int.Parse(output.ToString().TrimEnd('\r', '\n')) > int.Parse(check.FindData));
                        break;
                    case "LessThan":
                        checkPass = !(int.Parse(output.ToString().TrimEnd('\r', '\n')) < int.Parse(check.FindData));
                        break;
                    case "EqualTo":
                        checkPass = !(int.Parse(output.ToString().TrimEnd('\r', '\n')) == int.Parse(check.FindData) || output.ToString().TrimEnd('\r', '\n') == check.FindData);
                        break;
                    case "Contains":
                        checkPass = !output.ToString().TrimEnd('\r', '\n').Contains(check.FindData);
                        break;
                    case "NotEqualTo":
                        checkPass = int.Parse(output.ToString().TrimEnd('\r', '\n')) == int.Parse(check.FindData) || output.ToString().TrimEnd('\r', '\n') == check.FindData;
                        break;
                    case "NotContains":
                        checkPass = output.ToString().TrimEnd('\r', '\n').Contains(check.FindData);
                        break;
                    default:
                        break;
                }


                // Construct a struct to hold all relevant info of the check and return
                return new PowerShellResult {
                    Check = check,
                    Output = output.ToString().TrimEnd('\r', '\n'),
                    Errors = errors,
                    Success = errors.Count == 0,
                    TimedOut = cts.Token.IsCancellationRequested,
                    CheckPass = checkPass
                };
            }

            // If  the cancellation object requested early exit, log the timeout
            catch (OperationCanceledException) {
                return new PowerShellResult {
                    Check = check,
                    Output = output.ToString(),
                    Errors = new List<string> { "Command timed out" },
                    Success = false,
                    TimedOut = true,
                    CheckPass = false
                };
            }
        }


        finally {
            // Release semaphore slim so next command on the process can enter
            _semaphore.Release();
        }
    }



    /// <summary>
    /// Read the next line of a particular data stream
    /// </summary>
    /// <param name="reader">The stream to read output from</param>
    /// <param name="cancellationToken">The cancellation object to catch errors and exit the current command execution</param>
    /// <returns>
    /// The compiled string representing the next line in the stream
    /// </returns>
    private async Task<string?> ReadLineWithTimeoutAsync(StreamReader reader, CancellationToken cancellationToken, bool readingError) {

        try {
            
            // Set the timeout based on if the output or error stream is being read
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

                // Return null as the cancellation was requested by the CancellationToken object
            } else { return null; }
        }

        // Read errors do not necessairly mean command errors, so simply return null
        catch (OperationCanceledException) { throw; }
        catch { return null; }
    }

    /// <summary>
    /// Free the resources from the process and kill the process
    /// </summary>
    public void Dispose() {

        // If already disposed no need to modify any resources
        if (_disposed) return;
        _disposed = true;

        // Attempt to run the exit command to powershell instance
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
    /// The queue of processes / Powershell instances to release commands/checks to
    /// </summary>
    private readonly ConcurrentQueue<PowerShellInstance> _availableInstances = new();

    /// <summary>
    /// The list of all processes / Powershell instances maintained within the pool
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
    /// Overall disposed state representing if all memory from all processes / Powershell instances has been disposed and released
    /// </summary>
    private volatile bool _disposed = false;



    /// <summary>
    /// Set the total pool size of the overall pool
    /// </summary>
    /// <param name="poolSize">Number to set the pool size of the overall pool to</param>
    public PowerShellPool(int poolSize = 5) {

        // Set the pool size and reinitalize the Semaphore with the new pool size
        _poolSize = poolSize;
        _semaphore = new SemaphoreSlim(poolSize, poolSize);
    }



    /// <summary>
    /// Initalize {_poolSize} number of Powershell instances
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
    /// Create an object of and spawn a specific Powershell instance
    /// </summary>
    /// <returns>
    /// The initalized PowershellInstance object
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
    /// Dispatch a single Powershell check to the next available Powershell instance
    /// </summary>
    /// <param name="check">The Powershell check to execute and check</param>
    /// <param name="timeoutMs">The timeout (in ms) allotted for the command to run</param>
    /// <returns>
    /// The output and details of the check as a PowershellResult object
    /// </returns>
    public async Task<PowerShellResult> ExecuteCommandAsync(PowerShellCheck check, int timeoutMs = 30000) {

        // If the pool resources have been disposed/released, can not execute command
        if (_disposed) { throw new ObjectDisposedException(nameof(PowerShellPool)); }

        // Wait in queue to enter the Sempahore Slim
        await _semaphore.WaitAsync();

        try {
            // Attempt to remove and then utilize the available Powershell instance at the top of the queue
            if (_availableInstances.TryDequeue(out var instance)) {

                // Execute the command using the Powershell instance and return the output
                try { return await instance.ExecuteCommandAsync(check, timeoutMs); }

                // Requeue the Powershell instance to be used again
                finally { _availableInstances.Enqueue(instance); }
            }

            // Throw if can not remove any available instance of the top of the stack
            else { throw new InvalidOperationException("No PowerShell instance available"); }
        }

        // Release the Semaphore to move to the next command
        finally { _semaphore.Release(); }
    }



    /// <summary>
    /// Dispatch multiple Powershell checks to all maintained Powershell instances within the pool
    /// </summary>
    /// <param name="checks">The list of Powershell checks to execute and check for findings</param>
    /// <param name="maxConcurrency">The number of commands that can run at once within this batch</param>
    /// <param name="timeoutMs">The timeout (in ms) allotted for the command to run</param>
    public async Task<List<PowerShellResult>> ExecuteCommandsBatchAsync(List<PowerShellCheck> checks, int maxConcurrency = -1, int timeoutMs = 30000) {

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
                return await ExecuteCommandAsync(check, timeoutMs);
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
/// Holds information on a single vuln whos presence can be checked with Powershell
/// </summary>
public class PowerShellCheck : Check {

    /// <summary>
    /// The command to check the vuln's state
    /// </summary>
    public string CheckCommand { get; set; }
    
    /// <summary>
    /// The command to secure the vuln on the system
    /// </summary>
    public string SecureCommand { get; set; }
}



/// <summary>
/// Handles information for the result of a single Powershell check
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
}
