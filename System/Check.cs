/*

Stewart CLI
/System/Check.cs - Generic Check object
JohnDavid Abe 

*/



/// <summary>
/// Holds information on a single vuln
/// </summary>
public class Check {

    /// <summary>
    /// The ID of the vuln to check
    /// </summary>
    public string? ID { get; set; }

    /// <summary>
    /// A description of the vuln to check
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// The data, if which is matched to the output using the operator of the CheckCommand, marks the vuln as found
    /// </summary>
    public string? FindData { get; set; }

    /// <summary>
    /// The operator to perform on the FindData with the output of the system query to get a finding
    /// </summary>
    /// <regards>
    /// Options for operators are: GreaterThan (numerical data), LessThan (numerical data), EqualTo (numerical or textual data), Contains (numerical or textual data), NotEqualTo (numerical or textual data), NotContains (numerical or textual data), Exists (registry values and files), NotExists (registry values and files)
    /// </regards>
    public string? Operator { get; set; }

    /// <summary>
    /// Formats the check to a single string
    /// </summary>
    /// <returns>A formatted string with the check data</returns>
    public virtual string Print() {
        return $"ID: {this.ID}\nDescription: {this.Description}";
    }
}
