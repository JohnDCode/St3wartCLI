/*

Stewart CLI
/Interfaces/ICommand.cs - Interface for each command
JohnDavid Abe 

*/



/// <summary>
/// Interface applied to each of the CLI commands
/// </summary> 
public interface ICommand {
    Task Execute(string[] args);
    void Help();
}
