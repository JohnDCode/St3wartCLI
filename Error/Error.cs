/*

Stewart CLI
/Error/Error.cs - Handles custom runtime error reporting
JohnDavid Abe

*/



/// <summary>
/// Handles custom error reporting
/// </summary>
public static class Errors {

    /// <summary>
    /// Writes custom error to the console
    /// </summary>
    /// <param name="msg">Error message</param>
    public static void PrintError(string msg) {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("ERROR: " + msg);
        Console.ResetColor();
    }
}
