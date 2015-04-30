# Make sure the module is not loaded already
if (Get-Module xADObject) {
    Remove-Module xADObject
}

#Load the module
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module "$Here\..\xADObject"


Describe Get-xADObjectResource {
    # Mock up the behavior of Get-ADObject
    Mock Get-ADObject {
        if ($Credential.Username -eq "Administrator") {
            if ($Identity.ToString() -eq "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM") {
                return [pscustomobject][ordered] @{
                    DistinguishedName = "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"
                    ObjectClass = "user"
                }
            } else {
                throw New-Object -TypeName Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
            }
        } elseif($Credential.Username -eq "Unauthorized") {
            # Unauthorized
            throw "Access denied."
        } else {
            # Invalid
            throw "The server has rejected the client credentials."
        }
    }

    InModuleScope xADObject {
        # Create some dummy credentials
        $AuthorizedCredential = New-Object System.Management.Automation.PSCredential("Administrator", (ConvertTo-SecureString -String "foo" -AsPlainText -Force))
        $UnauthorizedCredential = New-Object System.Management.Automation.PSCredential("Unauthorized", (ConvertTo-SecureString -String "foo" -AsPlainText -Force))
        $InvalidCredential = New-Object System.Management.Automation.PSCredential("Invalid", (ConvertTo-SecureString -String "foo" -AsPlainText -Force))

        Context "Not on a domain controller" {
            Mock Test-ADDomainController { return $false }

            It "Throws an exception when called with authorized credentials" {
                { Get-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $AuthorizedCredential } | Should Throw "localhost is not a domain controller"
            }

            It "Throws an exception when called with unauthorized credentials" {
                { Get-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $UnauthorizedCredential } | Should Throw "localhost is not a domain controller"
            }

            It "Throws an exception when called with invalid credentials" {
                { Get-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $InvalidCredential } | Should Throw "localhost is not a domain controller"
            }
        }

        Context "On a domain controller" {
            Mock Test-ADDomainController { return $true }

            It "Throws an exception when called with unauthorized credentials" {
                { Get-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $UnauthorizedCredential } | Should Throw "Access denied."
            }

            It "Throws an exception when called with invalid credentials" {
                { Get-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $InvalidCredential } | Should Throw "The server has rejected the client credentials."
            }

            It "Returns data when AD Object is found" {
                $Result = Get-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $AuthorizedCredential
                $Result.DistinguishedName | Should Be "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"
                $Result.Ensure | Should Be "Present"
                $Result.Type | Should Be "user"
                $Result.Property.Count | Should Be 2
                $Result.Property["DistinguishedName"] | Should Be "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"
                $Result.Property["ObjectClass"] | Should Be "user"   
            }

            It "Returns data when AD Object is not found" {
                $Result = Get-xADObjectResource -DistinguishedName "CN=John Doe,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $AuthorizedCredential
                $Result.DistinguishedName | Should Be "CN=John Doe,OU=Sales,DC=FABRIKAM,DC=COM"
                $Result.Ensure | Should Be "Absent"
                $Result.Type | Should BeNullOrEmpty
                $Result.Property.Count | Should Be 0
            }
        }
    }
}


Describe Set-xADObjectResource {
    # Mock up the behavior of Get-ADObject
    Mock Get-ADObject {
        if ($Credential.Username -eq "Administrator") {
            if ($Identity.ToString() -eq "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM") {
                return [pscustomobject][ordered] @{
                    DistinguishedName = "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"
                    ObjectClass = "user"
                    GivenName = "Jeff"
                    Surname = "Smith"
                }
            } else {
                throw New-Object -TypeName Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
            }
        } elseif($Credential.Username -eq "Unauthorized") {
            # Unauthorized
            throw "Access denied."
        } else {
            # Invalid
            throw "The server has rejected the client credentials."
        }
    }

    InModuleScope xADObject {
        Mock Remove-ADObject {}
        Mock New-ADObject {}
        Mock Set-ADObject {}

        # Create some dummy credentials
        $AuthorizedCredential = New-Object System.Management.Automation.PSCredential("Administrator", (ConvertTo-SecureString -String "foo" -AsPlainText -Force))
        $UnauthorizedCredential = New-Object System.Management.Automation.PSCredential("Unauthorized", (ConvertTo-SecureString -String "foo" -AsPlainText -Force))
        $InvalidCredential = New-Object System.Management.Automation.PSCredential("Invalid", (ConvertTo-SecureString -String "foo" -AsPlainText -Force))

        Context "Not on a domain controller" {
            Mock Test-ADDomainController { return $false }

            It "Throws an exception when called with authorized credentials" {
                { Set-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $AuthorizedCredential } | Should Throw "localhost is not a domain controller"
            }

            It "Throws an exception when called with unauthorized credentials" {
                { Set-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $UnauthorizedCredential } | Should Throw "localhost is not a domain controller"
            }

            It "Throws an exception when called with invalid credentials" {
                { Set-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $InvalidCredential } | Should Throw "localhost is not a domain controller"
            }
        }

         Context "On a domain controller" {
            Mock Test-ADDomainController { return $true }

            It "Throws an exception when called with unauthorized credentials" {
                { Set-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $UnauthorizedCredential } | Should Throw "Access denied."
            }

            It "Throws an exception when called with invalid credentials" {
                { Set-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $InvalidCredential } | Should Throw "The server has rejected the client credentials."
            }

            It "Throws an exception when type is not specified for a new object" {
                $Property = @(
                    [pscustomobject][ordered]@{Key = "DistinguishedName"; Value = "CN=John Doe,OU=Sales,DC=FABRIKAM,DC=COM"}
                    [pscustomobject][ordered]@{Key = "ObjectClass"; Value = "user"}
                )

                { Set-xADObjectResource -DistinguishedName "CN=John Doe,OU=Sales,DC=FABRIKAM,DC=COM" -Ensure Present -Property $Property -Credential $AuthorizedCredential } | Should Throw "In order to create a new AD Object, you must specify a Type."
            }

            It "Throws an exception when attempting to set a property that doesn't exist" {
                $Property = @(
                    [pscustomobject][ordered]@{Key = "DistinguishedName"; Value = "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"}
                    [pscustomobject][ordered]@{Key = "ObjectClass"; Value = "user"}
                    [pscustomobject][ordered]@{Key = "FAILURE"; Value = "VERY"}
                )

                { Set-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Ensure Present -Property $Property -Credential $AuthorizedCredential } | Should Throw "Property FAILURE does not exist on object CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"
            }

            It "Creates an AD Object" {
                $Property = @(
                    [pscustomobject][ordered]@{Key = "DistinguishedName"; Value = "CN=John Doe,OU=Sales,DC=FABRIKAM,DC=COM"}
                    [pscustomobject][ordered]@{Key = "ObjectClass"; Value = "user"}
                )

                Set-xADObjectResource -DistinguishedName "CN=John Doe,OU=Sales,DC=FABRIKAM,DC=COM" -Ensure Present -Type User -Property $Property -Credential $AuthorizedCredential | Should BeNullOrEmpty
                Assert-MockCalled -CommandName New-ADObject -Scope It -Times 1 -Exactly
            }

            It "Removes an AD Object" {
                Set-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Ensure Absent -Credential $AuthorizedCredential | Should BeNullOrEmpty
                Assert-MockCalled -CommandName Remove-ADObject -Scope It -Times 1 -Exactly
            }

            It "Updates an AD Object" {
                $Property = @(
                    [pscustomobject][ordered]@{Key = "DistinguishedName"; Value = "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"}
                    [pscustomobject][ordered]@{Key = "ObjectClass"; Value = "user"}
                    [pscustomobject][ordered]@{Key = "GivenName"; Value = "Jeffrey"}
                    [pscustomobject][ordered]@{Key = "Surname"; Value = "Smith"}
                )

                Set-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Ensure Present -Property $Property -Credential $AuthorizedCredential | Should BeNullOrEmpty
                Assert-MockCalled -CommandName Set-ADObject -Scope It -Times 1 -Exactly
            }

            It "Skips updating an AD Object if no property values were changed" {
                $Property = @(
                    [pscustomobject][ordered]@{Key = "DistinguishedName"; Value = "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"}
                    [pscustomobject][ordered]@{Key = "ObjectClass"; Value = "user"}
                    [pscustomobject][ordered]@{Key = "GivenName"; Value = "Jeff"}
                    [pscustomobject][ordered]@{Key = "Surname"; Value = "Smith"}
                )

                Set-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Ensure Present -Property $Property -Credential $AuthorizedCredential | Should BeNullOrEmpty
                Assert-MockCalled -CommandName Set-ADObject -Scope It -Times 0 -Exactly
            }
        }
    }
}


Describe Test-xADObjectResource {
    # Mock up the behavior of Get-ADObject
    Mock Get-ADObject {
        if ($Credential.Username -eq "Administrator") {
            if ($Identity.ToString() -eq "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM") {
                return [pscustomobject][ordered] @{
                    DistinguishedName = "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"
                    ObjectClass = "user"
                }
            } else {
                throw New-Object -TypeName Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException
            }
        } elseif($Credential.Username -eq "Unauthorized") {
            # Unauthorized
            throw "Access denied."
        } else {
            # Invalid
            throw "The server has rejected the client credentials."
        }
    }

    InModuleScope xADObject {
        # Create some dummy credentials
        $AuthorizedCredential = New-Object System.Management.Automation.PSCredential("Administrator", (ConvertTo-SecureString -String "foo" -AsPlainText -Force))
        $UnauthorizedCredential = New-Object System.Management.Automation.PSCredential("Unauthorized", (ConvertTo-SecureString -String "foo" -AsPlainText -Force))
        $InvalidCredential = New-Object System.Management.Automation.PSCredential("Invalid", (ConvertTo-SecureString -String "foo" -AsPlainText -Force))

        Context "Not on a domain controller" {
            Mock Test-ADDomainController { return $false }

            It "Throws an exception when called with authorized credentials" {
                { Test-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $AuthorizedCredential } | Should Throw "localhost is not a domain controller"
            }

            It "Throws an exception when called with unauthorized credentials" {
                { Test-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $UnauthorizedCredential } | Should Throw "localhost is not a domain controller"
            }

            It "Throws an exception when called with invalid credentials" {
                { Test-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $InvalidCredential } | Should Throw "localhost is not a domain controller"
            }
        }

        Context "On a domain controller" {
            Mock Test-ADDomainController { return $true }

            It "Throws an exception when called with unauthorized credentials" {
                { Test-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $UnauthorizedCredential } | Should Throw "Access denied."
            }

            It "Throws an exception when called with invalid credentials" {
                { Test-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Credential $InvalidCredential } | Should Throw "The server has rejected the client credentials."
            }

            It "Returns true when everything matches" {
                $Property = @(
                    [pscustomobject][ordered]@{Key = "DistinguishedName"; Value = "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"}
                    [pscustomobject][ordered]@{Key = "ObjectClass"; Value = "user"}
                )

                Test-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Ensure Present -Type User -Property $Property -Credential $AuthorizedCredential | Should Be $true

                $Property = @(
                    [pscustomobject][ordered]@{Key = "DistinguishedName"; Value = "CN=John Doe,OU=Sales,DC=FABRIKAM,DC=COM"}
                    [pscustomobject][ordered]@{Key = "ObjectClass"; Value = "user"}
                )

                Test-xADObjectResource -DistinguishedName "CN=John Doe,OU=Sales,DC=FABRIKAM,DC=COM" -Ensure Absent -Type User -Property $Property -Credential $AuthorizedCredential | Should Be $true
            }

            It "Returns true when everything matches and fewer properties are specified than exist." {
                $Property = @(
                    [pscustomobject][ordered]@{Key = "DistinguishedName"; Value = "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"}
                )

                Test-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Ensure Present -Type User -Property $Property -Credential $AuthorizedCredential | Should Be $true
            }

            It "Returns false when ensure does not match" {
                $Property = @(
                    [pscustomobject][ordered]@{Key = "DistinguishedName"; Value = "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"}
                    [pscustomobject][ordered]@{Key = "ObjectClass"; Value = "user"}
                )

                Test-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Ensure Absent -Type User -Property $Property -Credential $AuthorizedCredential | Should Be $false

                $Property = @(
                    [pscustomobject][ordered]@{Key = "DistinguishedName"; Value = "CN=John Doe,OU=Sales,DC=FABRIKAM,DC=COM"}
                    [pscustomobject][ordered]@{Key = "ObjectClass"; Value = "user"}
                )

                Test-xADObjectResource -DistinguishedName "CN=John Doe,OU=Sales,DC=FABRIKAM,DC=COM" -Ensure Present -Type User -Property $Property -Credential $AuthorizedCredential | Should Be $false
            }

            It "Returns true when type is not specified and everything else matches" {
                $Property = @(
                    [pscustomobject][ordered]@{Key = "DistinguishedName"; Value = "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"}
                    [pscustomobject][ordered]@{Key = "ObjectClass"; Value = "user"}
                )

                Test-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Ensure Present -Type $null -Property $Property -Credential $AuthorizedCredential | Should Be $true
            }

            It "Returns false when type does not match" {
                $Property = @(
                    [pscustomobject][ordered]@{Key = "DistinguishedName"; Value = "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"}
                    [pscustomobject][ordered]@{Key = "ObjectClass"; Value = "user"}
                )

                Test-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Ensure Present -Type "FAILURE" -Property $Property -Credential $AuthorizedCredential | Should Be $false
            }

            It "Returns false when a property does not match" {
                $Property = @(
                    [pscustomobject][ordered]@{Key = "DistinguishedName"; Value = "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"}
                    [pscustomobject][ordered]@{Key = "ObjectClass"; Value = "FAILURE"}
                )

                Test-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Ensure Present -Type User -Property $Property -Credential $AuthorizedCredential | Should Be $false
            }

            It "Returns false when a property is specified that doesn't exist" {
                $Property = @(
                    [pscustomobject][ordered]@{Key = "DistinguishedName"; Value = "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM"}
                    [pscustomobject][ordered]@{Key = "FAILURE"; Value = "VERY"}
                )

                Test-xADObjectResource -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Ensure Present -Type User -Property $Property -Credential $AuthorizedCredential | Should Be $false
            }
        }
    }
}


Describe Test-ADDomainController {
    InModuleScope xADObject {
        Mock Get-WindowsFeature {
            return [pscustomobject] @{
                Name = "AD-Domain-Services"
                Installed = $false
            }
        }

        It "Detects AD-Domain-Services absent" {
            Test-ADDomainController | Should Be $false
        }


        Mock Get-WindowsFeature {
            return [pscustomobject] @{
                Name = "AD-Domain-Services"
                Installed = $true
            }
        }

        It "Detects AD-Domain-Services present" {
            Test-ADDomainController | Should Be $true
        }


        Mock Get-WindowsFeature {
            return $null
        }

        It "Detects AD-Domain-Services feature does not exist" {
            Test-ADDomainController | Should Be $false
        }


        Mock Get-WindowsFeature {
            throw "This is a test"
        }

        Mock Write-Error {}

        It "Handles an exception" {
            Test-ADDomainController | Should Be $false
            Assert-MockCalled Write-Error -Exactly 1
        }
    }
}


Describe Split-DistinguishedName {
    InModuleScope xADObject {
        It "Returns Name implicitly" {
            Split-DistinguishedName -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" | Should Be "Jeff Smith"
        }

        It "Returns Name explicitly" {
            Split-DistinguishedName -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Name | Should Be "Jeff Smith"
        }

        It "Returns Path explicitly" {
            Split-DistinguishedName -DistinguishedName "CN=Jeff Smith,OU=Sales,DC=FABRIKAM,DC=COM" -Path | Should Be "OU=Sales,DC=FABRIKAM,DC=COM"
        }

        It "Gets name from input with no commas" {
            Split-DistinguishedName -DistinguishedName "CN=Jeff Smith" -Name | Should Be "Jeff Smith"
        }

        It "Gets path from input with no commas" {
            Split-DistinguishedName -DistinguishedName "CN=Jeff Smith" -Path | Should BeNullOrEmpty
        }
    }
}


Remove-Module xADObject