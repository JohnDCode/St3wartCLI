/*

Stewart CLI
/System/Check.cs - Check parent object of which PS and Registry check objects inherit from
JohnDavid Abe 

*/



public class Check {

    /// <summary>
    /// The ID of the vuln to check
    /// </summary>
    public string ID { get; set; }

    /// <summary>
    /// A description of the vuln to check
    /// </summary>
    public string Description { get; set; }

    /// <summary>
    /// The data, if which is matched to the output using the operator of the CheckCommand, marks the vuln as found
    /// </summary>
    public string FindData { get; set; }

    /// <summary>
    /// The operator to perform on the data with the output of the command to get a finding
    /// </summary>
    /// <regards>
    /// Options for operators are: GreaterThan (numerical data), LessThan (numerical data), EqualTo (numerical or textual data), Contains (numerical or textual data), NotEqualTo (numerical or textual data), NotContains (numerical or textual data)
    /// </regards>
    public string Operator { get; set; }


    public string Print() {
        return $"Vuln: {this.ID}\nDescription: {this.Description}";
    }
}
