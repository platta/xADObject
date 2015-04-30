<#
.SYNOPSIS
Internal method for the Get-TargetResource call of xADObjectResource.

.DESCRIPTION
This method does the actual work of the Get-TargetResource method of the
xADObjectResource DSC Resource included in the module. It uses the Distinguished
Name as a key to uniquely identify an AD object and then returns a hashtable
containing all of the properties on that object.

.NOTES
This resource expects the target node to have the AD-Domain-Services role
installed.
#>
function Get-xADObjectResource {
	[CmdletBinding()]
	[OutputType([System.Collections.Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$DistinguishedName,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential
	)

	Begin {
        # Set ErrorAction preference, and store current value so we can restore
        # it later.
        $EaBefore = $ErrorActionPreference
        $ErrorActionPreference = "Stop"
    
        # Do not continue if this machine is not a Domain Controller.
        if (-not (Test-ADDomainController)) {
            throw "localhost is not a domain controller"
        }
    }

    Process {
        # Build the return value.
        $ReturnValue = @{
            DistinguishedName = $DistinguishedName
            Ensure = $null
            Type = $null
            Property = @{}
        }

        try {
            # Try to get the object.
            $Object = Get-ADObject -Identity $DistinguishedName -Properties * -Credential $Credential

            # If we got this far, we know the object exists in AD
            $ReturnValue.Ensure = "Present"

            $ReturnValue.Type = $Object.ObjectClass

            # Build the hashtable of properties, excluding some that are
            # constants.
            $Properties = $Object | Get-Member -MemberType Properties
            foreach ($Item in $Properties) {
                $ReturnValue.Property[$Item.Name] = $Object."$($Item.Name)"
            }

            return $ReturnValue

        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            # If this type of error is thrown, it means the object was not
            # found.
            $ReturnValue.Ensure = "Absent"
            return $ReturnValue
        } catch {
            # Any other error, just quit.
            Write-Error $_.Exception.Message
        }
    }

    End {
        # Restore ErrorAction preference.
        $ErrorActionPreference = $EaBefore
    }
}


<#
.SYNOPSIS
Internal method for the Set-TargetResource call of xADObjectResource.

.DESCRIPTION
This method does the actual work of the Set-TargetResource method of the
xADObjectResource DSC Resource included in the module. It uses the Distinguished
Name as a key to uniquely identify an AD object and uses the provided hashtable
to update properties on that object in AD.

.NOTES
This resource expects the target node to have the AD-Domain-Services role
installed.

The type on the Property parameter is CimInstance[] because of the way DSC
handles the hashtable variable through serialization/deserialization. The array
can be treated as an array of objects with properties Key and Value, matching
the hashtable that was passed in the Configuration.
#>
function Set-xADObjectResource {
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$DistinguishedName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [System.String]
        $Type,

		#[Microsoft.Management.Infrastructure.CimInstance[]]
		$Property,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential
	)

	Begin {
        # Set ErrorAction preference, and store current value so we can restore
        # it later.
        $EaBefore = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'

        # Do not continue if this machine is not a Domain Controller.
        if (-not (Test-ADDomainController)) {
            throw 'localhost is not a domain controller'
        }
    }

    Process {
        try {
            # Get the object.
            $Object = Get-ADObject -Identity $DistinguishedName -Properties * -Credential $Credential

            if ($Ensure -eq "Present") {
                # Make sure the types match if a type was specified.
                if ($Type -and $Type -ne $Object.ObjectClass) {
                    throw "Object $DistinguishedName is type '$($Object.ObjectClass)', not '$Type'"
                }

                if ($Property) {
                    # Build an array of property names.
                    $Properties = $Object | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name
                    
                    # Build a hashtable to pass to Set-ADObject.
                    $Replace = @{}
                    foreach ($Item in $Property) {
                        if ($Item.Key -notin $Properties) {
                            throw "Property $($Item.Key) does not exist on object $DistinguishedName"
                        }

                        if ($Object."$($Item.Key)" -ne $Item.Value) {
                            $Replace[$Item.Key] = $Item.Value
                        }
                    }

                    # Update the object.
                    if ($Replace.Count -gt 0) {
                        Set-ADObject -Identity $DistinguishedName -Replace $Replace -Credential $Credential
                    }
                }
            } else {
                # Remove the object.
                Remove-ADObject -Identity $DistinguishedName -Credential $Credential
            }
        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            if ($Ensure -eq "Present") {
                # Object does not exist but ensure is present. Create
                # a new object.

                # First make sure the type is set, this is required when
                # creating an object.
                if (!$Type) {
                    Write-Error "In order to create a new AD Object, you must specify a Type."
                } else {
                    # Separate the Name from the Path in the
                    # Distinguished Name.
                    $Name = Split-DistinguishedName -DistinguishedName $DistinguishedName -Name
                    $Path = Split-DistinguishedName -DistinguishedName $DistinguishedName -Path

                    if ($Property) {
                        # Other attributes specified.
                        $OtherAttributes = @{}

                        foreach ($Item in $Property) {
                            $OtherAttributes[$Item.Key] = $Item.Value
                        }

                        New-ADObject -Name $Name -Path $Path -Type $Type -Credential $Credential -OtherAttributes $OtherAttributes
                    } else {
                        # No attributes specified, just create.
                        New-ADObject -Name $Name -Path $Path -Type $Type -Credential $Credential
                    }
                }
            }
        } catch {
            Write-Error $_.Exception.Message
        }
    }

    End {
        # Restore ErrorAction preference.
        $ErrorActionPreference = $EaBefore
    }

}


<#
.SYNOPSIS
Internal method for the Test-TargetResource call of xADObjectResource.

.DESCRIPTION
This method does the actual work of the Test-TargetResource method of the
xADObjectResource DSC Resource included in the module. It uses the Distinguished
Name as a key to uniquely identify an AD object and uses the provided hashtable
to verify properties on that object.

.NOTES
This resource expects the target node to have the AD-Domain-Services role
installed.

The type on the Property parameter is CimInstance[] because of the way DSC
handles the hashtable variable through serialization/deserialization. The array
can be treated as an array of objects with properties Key and Value, matching
the hashtable that was passed in the Configuration.
#>
function Test-xADObjectResource {
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$DistinguishedName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure,

        [System.String]
        $Type,

		#[Microsoft.Management.Infrastructure.CimInstance[]]
		$Property,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential
	)

	# Get the current state.
    $Current = Get-xADObjectResource -DistinguishedName $DistinguishedName -Credential $Credential
    if ($Current -and $Current["Ensure"] -eq "Present") {
        # Object is present.
        if ($Ensure -eq "Present") {
            # Check the type
            if ($Type -and $Type -ne $Current.Type) {
                return $false
            }

            # Check properties
            foreach ($Item in $Property) {
                if (-not ($Current["Property"].ContainsKey($Item.Key)) -or $Current["Property"][$Item.Key] -ne $Item.Value) {
                    # Found a property that does not exist or does not match.
                    return $false
                }
            }

            # If no failures by now, we passed all tests.
            return $true
        } else {
            # Object was not supposed to exist, fail.
            return $false
        }
    } else {
        # Object is not present or nothing returned. Pass as long as that's what
        # we were expecting.
        return $Ensure -eq "Absent"
    }
}


<#
.SYNOPSIS
Determines whether the local computer is a domain controller.

.DESCRIPTION
Determines whether the local computer is a domain controller by checking for the
AD-Domain-Services role.
#>
function Test-ADDomainController {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()

    try {
        # Check whether or not the AD-Domain-Services feature is installed.
        $ADDS = Get-WindowsFeature -Name AD-Domain-Services
        if ($ADDS) {
            return $ADDS.Installed
        } else {
            return $false
        }
    } catch {
        Write-Error $_.Exception.Message
        return $false
    }
}

function Split-DistinguishedName {
    [CmdletBinding(
        DefaultParameterSetName = "ReturnName"
    )]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,

        [Parameter(ParameterSetName = "ReturnName")]
        [switch]$Name,

        [Parameter(ParameterSetName = "ReturnPath")]
        [switch]$Path
    )

    process {
        $FirstComma = $DistinguishedName.IndexOf(",")

        switch ($PSCmdlet.ParameterSetName) {
            "ReturnName" {
                if ($FirstComma -eq -1) {
                    $FirstComma = $DistinguishedName.Length
                }
                return $DistinguishedName.Substring(3, $FirstComma - 3)
            }

            "ReturnPath" {
                if ($FirstComma -ne -1) {
                    return $DistinguishedName.Substring($FirstComma + 1)
                }
            }
        }
    }
}