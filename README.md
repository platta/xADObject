# xADObject
PowerShell DSC Resource for managing properties on any Active Directory Object.

# Example

```PowerShell
# Define the configuration.
Configuration ADObjectExample {
  
  Import-DscResource -Name xADObjectResource
  
  Node $AllNodes.NodeName {
    xADObject ExampleADObject {
      DistinguishedName = $Node.DistinguishedName
      Property = $Node.Property
      Credential = $ConfigurationData.NonNodeData.Credential
    }
  }
}

# Define the configuration data to pass in.
$ConfigurationData = @{
  AllNodes = @(
    @{
      NodeName = "FABRIKAM-DC1"
      DistinguishedName = "CN=Jeff Smith,OU=Sales,DC=Fabrikam,DC=COM"
      Property = @{
        Description = "Jeff is a great guy!"
        GivenName = "Jeff"
        Surname = "Smith"
      }
    }
  )
  
  NonNodeData = @{
    Credential = (Get-Credential)
  }
}

# Create the MOF file.
ADObjectExample -ConfigurationData $ConfigurationData -OutputPath = C:\FabrikamExample

# Execute the configuration.
Start-DscConfiguration -Path C:\FabrikamExample -Wait -Verbose
```
