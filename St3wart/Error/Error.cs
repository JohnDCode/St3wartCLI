/*

Stewart CLI
/Error/Error.cs - Handles runtime issues
JohnDavid Abe

*/



public static class Errors {

    public static void PrintError(string msg) {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("ERROR: " + msg);
        Console.ResetColor();
    }
}