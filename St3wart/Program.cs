/*

Stewart CLI
/Program.cs - Entry point for executable
JohnDavid Abe 

*/



// Packages
using System.Runtime.InteropServices;



/// <summary>
/// Entry point for executable
/// </summary>
class Program {

    /// <summary>
    /// Entry point for executable
    /// </summary>
    /// <param name="args">CLI arguments for the command</param>
    static void Main(string[] args) {

        // Ensure Windows is the call site
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) { Errors.PrintError("This application is not cross-platform, please run on a Windows machine"); }

        // Call router to route commands with CLI arguments
        var router = new Router();
        router.Route(args);
    }
}
