/*

Stewart CLI
/Program.cs - Entry point for executable
JohnDavid Abe 

*/



/// <summary>
/// Entry point for executable
/// </summary>
class Program {
    
    /// <summary>
    /// Entry point for executable
    /// </summary>
    /// <param name="args">CLI arguments for the command</param>
    static void Main(string[] args) {
        // Call router to route commands with CLI arguments
        var router = new Router();
        router.Route(args);
    }
}
