﻿/*

Stewart CLI
/Program.cs - Entry point for executable
JohnDavid Abe 

*/



// Packages
using System.Runtime.InteropServices;
using System.Runtime.Versioning;



/// <summary>
/// Entry point for executable
/// </summary>
[SupportedOSPlatform("Windows")]
class Program {

    /// <summary>
    /// Entry point for executable
    /// </summary>
    /// <param name="args">CLI arguments for the command</param>
    static async Task Main(string[] args) {

        // Ensure Windows is the call site
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) { Errors.PrintError("This application is not cross-platform, please run on a Windows machine"); }

        // Call router to route commands with CLI arguments
        await Router.Route(args);
    }
}
// Implement file checks, add concurrency for all types of checks (Friday)
// Impleemnt secure command (Friday)
// Implement schedule command (Saturday)
// Implement Snap and Restore commands (generate a seperate xml file for those backups, idk how I want this to actually function yet through) (Saturday)
// Implement report command (Saturday)
// Make some json (Onward)
// Blog post (Onward)