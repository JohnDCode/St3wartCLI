/*

Stewart CLI
/Interfaces/ICommand.cs - Interface for each command
JohnDavid Abe 

*/

public interface ICommand
{
    // Method to perform on execution of each command
    void Execute(string[] args);
}
