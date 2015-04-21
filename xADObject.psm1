﻿function Test-ADDomainController {
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param ()

    try {
        # Check whether or not the AD-Domain-Services feature is installed.
        $ADDS = Get-WindowsFeature -Name AD-Domain-Services
        return $ADDS.Installed
    } catch {
        Write-Error $_.Exception.Message
    }
}


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
            Property = @{}
        }

        try {
            # Try to get the object.
            $Object = Get-ADObject -Identity $DistinguishedName -Properties * -Credential $Credential

            # If we got this far, we know the object exists
            $ReturnValue.Ensure = "Present"

            # Build the hashtable of properties, excluding some that are
            # constants.
            $Properties = $Object | Get-Member -MemberType Properties | Where-Object -Property Name -NotIn DistinguishedName, ObjectClass, ObjectGUID
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

		[Microsoft.Management.Infrastructure.CimInstance[]]
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
                # Build an array of property names
                $Properties = $Object | Get-Member -MemberType Properties | Where-Object -Property Name -NotIn DistinguishedName, ObjectClass, ObjectGUID | Select-Object -ExpandProperty Name

                # Build a hashtable to pass to Set-ADObject.
                $Replace = @{}
                foreach ($Item in $Property) {
                    if ($Item.Key -notin $Properties) {
                        throw "Property $($Item.Key) does not exist on object $DistinguishedName"
                    }

                    $Replace[$Item.Key] = $Item.Value
                }

                # Update the object.
                Set-ADObject -Identity $DistinguishedName -Replace $Replace -Credential $Credential
            } else {
                # Remove the object.
                Remove-ADObject -Identity $DistinguishedName -Credential $Credential
            }
        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            if ($Ensure -eq "Present") {
                # Object does not exist but ensure is present. We can't do that.
                Write-Error "Operation not supported. Cannot create a new AD Object."
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

		[Microsoft.Management.Infrastructure.CimInstance[]]
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