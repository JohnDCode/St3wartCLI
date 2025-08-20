/*

Stewart CLI
/Program.cs - Entry point for executable
JohnDavid Abe 

*/



class Program
{
    static void Main(string[] args)
    {
        // Route arguments from command to the router
        var router = new Router();
        router.Route(args);
    }
}



// Need to add not operators
// Need to change the check and result objects to contain all the required JSON data