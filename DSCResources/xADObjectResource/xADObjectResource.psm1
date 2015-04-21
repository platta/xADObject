#Requires -Modules xADObject

function Get-TargetResource {
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

    Process {
        Return Get-xADObjectResource -DistinguishedName $DistinguishedName -Credential $Credential
    }
}


function Set-TargetResource {
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$DistinguishedName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure = "Present",

		[Microsoft.Management.Infrastructure.CimInstance[]]
		$Property,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential
	)

	Process {
        return Set-xADObjectResource -DistinguishedName $DistinguishedName -Ensure $Ensure -Property $Property -Credential $Credential
    }
}


function Test-TargetResource {
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$DistinguishedName,

		[ValidateSet("Present","Absent")]
		[System.String]
		$Ensure = "Present",

		[Microsoft.Management.Infrastructure.CimInstance[]]
		$Property,

        [parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential
	)

    return Test-xADObjectResource -DistinguishedName $DistinguishedName -Ensure $Ensure -Property $Property -Credential $Credential
}


Export-ModuleMember -Function *-TargetResource

