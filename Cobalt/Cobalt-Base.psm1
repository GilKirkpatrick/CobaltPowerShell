[System.Guid]$script:nullGUID = New-Object System.Guid 

Function Invoke-CobaltQuery
{
[CmdletBinding(SupportsShouldProcess=$True)]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(Position=0, HelpMessage="The path and query parameters to append to the base OData URL")][string]$Path,
	[Parameter(Position=1, HelpMessage="The HTTP method to use, default is GET")][ValidateSet('GET','POST','PUT','DELETE','PATCH')][string]$Method = 'GET',
	[Parameter(HelpMessage="The body of the message as a PSObject")][PSObject]$BodyParameters
)
	if($Path.StartsWith('/')){
		$Path = $Path.Substring(1);
	}
	$Uri = "$($Connection.Uri)/$Path"
	if(-not [String]::IsNullOrEmpty($Connection.AccessToken)){
		$AuthzHeader = "Bearer $($Connection.AccessToken)"
	}
	else {
		$AuthzHeader = Convert-CredentialToAuthHeader -Credential ($Connection.Credential)
	}
	Write-Verbose "Authorization header: $AuthzHeader"
	if($Method -eq 'GET'){
		# If the GET fails, we will catch the error and return $null
		Try {
			Invoke-RestMethod -Uri $Uri -Credential ($Connection.Credential) -Method $Method -Headers @{'Authorization'=$AuthzHeader} -ErrorAction Stop
		}
		Catch {
			return $null
		}
	}
	elseif ($Method -eq 'DELETE'){
		Invoke-RestMethod -Uri $Uri -Credential ($Connection.Credential) -Method $Method -Headers @{'Authorization'="$(Convert-CredentialToAuthHeader -Credential ($Connection.Credential))"} -ErrorAction Stop
	}
	else {
		$Body = $BodyParameters | ConvertTo-JSON -Depth 6
		Write-Verbose $Body
		if($PSCmdlet.ShouldProcess($Uri)){
			Invoke-RestMethod -Uri $Uri -Credential ($Credential.Credential) -Method $Method -Headers @{'Authorization'=$(Convert-CredentialToAuthHeader -Credential ($Connection.Credential))} -Body $Body
		}
	}
}

Function Get-CobaltEntity
{
[CmdletBinding()]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
    [Parameter(Position=0, Mandatory=$True, HelpMessage="The UUID of the OData entity to get", ValueFromPipelineByPropertyName=$True)][System.Guid]$EntityUUID,
	[Parameter(HelpMessage="The type of OData entity to retrieve")][string]$ODataType
	#TODO: Add ability to chase navigation properties
)
	Process {
		$Path = "/Entities($EntityUUID)"
		if(-not [string]::IsNullOrEmpty($ODataType)) {
			$Path += "/$(ConvertTo-CanonicalODataType($ODataType))"
		}
		Invoke-CobaltQuery -Connection $Connection -Method 'GET' -Path $Path -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	}
}

Function Get-CobaltEntities {
[CmdletBinding()]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
    [Parameter(HelpMessage="The type of OData entity to retrieve")][string]$ODataType,
    [Parameter(HelpMessage="An OData filter string to qualify the returned entities")][string]$ODataFilter,
	[Parameter(HelpMessage="An array of navigation properties that should be expanded")][string[]]$Expand = @()
)
    $Path = "/Entities"
    if(-not [string]::IsNullOrEmpty($ODataType)){
        $Path += "/$(ConvertTo-CanonicalODataType($ODataType))"
    }
	$QueryString = ""

    if(-not [string]::IsNullOrEmpty($ODataFilter)) {
        $QueryString += "`$filter=$ODataFilter"
    }
	if($Expand.Count -gt 0){
		if($QueryString -ne ''){
			$QueryString += '&'
		}
		$QueryString += '$expand=' + [String]::Join(',', $Expand)
	}
	if($QueryString -ne "") {
		$Path += '?' + $QueryString
	}
	(Invoke-CobaltQuery -Connection $Connection -Path $Path -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)).value
}

Function Get-CobaltProperty
{
[CmdletBinding()]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
    [Parameter(Position=0, Mandatory=$True, HelpMessage="The UUID of the OData entity to get")][System.Guid]$EntityUUID,
    [Parameter(Position=1, Mandatory=$True, HelpMessage="The name of the property to retrieve")][string]$PropertyName
)
	(Get-CobaltEntity -Connection $Connection -EntityUUID $EntityUUID -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent))."$PropertyName"
}

Function Set-CobaltProperty {
[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact="Medium")]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
    [Parameter(Position=0, Mandatory=$True, HelpMessage="The EntityUUID of the OData entity to modify", ValueFromPipelineByPropertyName=$True)][ValidateNotNullOrEmpty()][System.Guid]$EntityUUID,
    [Parameter(ParameterSetName="SingleProperty", Position=1, Mandatory=$True, HelpMessage="The name of the OData property to modify")][string]$PropertyName,
    [Parameter(ParameterSetName="SingleProperty", Position=2, HelpMessage="The value to set the OData property to")]$PropertyValue,
	[Parameter(ParameterSetName="MultipleProperties", Position=1, Mandatory=$True, HelpMessage="A hash map containing the name/value pairs to use as property names and values")]$Properties,
	[Parameter(HelpMessage="Switch to indicate to add the new values to a multivalued property")][Switch]$UsePost
)
	Process {
		if([string]::IsNullOrEmpty($EntityUUID)) { # ValidateNotNullOrEmpty does not seem to catch this case...
			Throw "EntityUUID of entry to modify is null or empty"
		}

		if($PsCmdlet.ParameterSetName -eq "SingleProperty"){
			$Properties = @{}
			$Properties.Add($PropertyName, $PropertyValue)
			$ShouldProcess = $PsCmdlet.ShouldProcess($EntityUUID, "Set the $PropertyName property to $PropertyValue")
		}
		elseif ($PsCmdlet.ParameterSetName -eq 'MultipleProperties') {
			$Message = $null
			foreach($Entry in $Properties.GetEnumerator()){
				if($Message -eq $null){
					$Message = "Set the $($Entry.Name)"
				
				}
				else {
					$Message += ',' + $Entry.Name
				}
			}
			if($Message -ne $null){
				$Message += ' properties'
			}
			$ShouldProcess = $PsCmdlet.ShouldProcess($EntityUUID, $Message)
		}

		if($ShouldProcess){
			if($UsePost){
				$Method = "POST"
			}
			else {
				$Method = "PATCH"
			}
			Invoke-CobaltQuery -Connection $Connection -Path "/Entities($EntityUUID)" -Method $Method -BodyParameters $Properties -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
		}
	}
}

Function New-CobaltEntity {
[CmdletBinding(SupportsShouldProcess=$True)]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
    [Parameter(ParameterSetName="Hashtable", Mandatory=$True, HelpMessage="A hash map of property names and values to use for the new OData entity")][Hashtable]$Properties,
    [Parameter(ParameterSetName="Object", Mandatory=$True, HelpMessage="A PSCustomObject representing the new OData entity")][PSCustomObject]$Object,
	[Parameter(Mandatory=$True, HelpMessage="The OData type of the new entity")][string]$ODataType,
	[Parameter(HelpMessage="A set of additional properties to add to the new entity")][Hashtable]$AdditionalProperties = @{}
)
	$NewProperties = @{}

	if(-not [string]::IsNullOrEmpty($ODataType)) {
		$NewProperties.Add('@odata.type', '#' + (ConvertTo-CanonicalODataType($ODataType)))
	}

	if($PsCmdlet.ParameterSetName -eq 'Hashtable') {
		ForEach($p in $Properties.GetEnumerator()) {
			$NewProperties.Add($p.Name, $p.Value)
		}
	}
	elseif($PsCmdlet.ParameterSetName -eq 'Object') {
		ForEach($p in $Object.PSObject.Properties) {
			$NewProperties.Add($p.Name, $p.Value)
		}
	}
	if($AdditionalProperties -ne $null){
		$AdditionalProperties.GetEnumerator() | %{if(-not $NewProperties.ContainsKey($_.Key)){$NewProperties.Add($_.Key, $_.Value)}}
	}
	if($PSCmdlet.ShouldProcess($Connection.Uri, "Create new $(ConvertTo-CanonicalODataType($ODataType)) entity")){
		(Invoke-CobaltQuery -Connection $Connection -Path "/Entities" -BodyParameters $NewProperties -Method POST -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent))
	}
}

Function Remove-CobaltEntity {
	[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High")]
	Param (
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(Position=0,Mandatory=$True,HelpMessage="The UUID of the entity to delete",ValueFromPipelineByPropertyName=$True)][ValidateNotNullOrEmpty()][System.Guid]$EntityUUID
	)
	Process {
		if($PsCmdlet.ShouldProcess("$EntityUUID")){
			Invoke-CobaltQuery -Connection $Connection -Path "Entities($EntityUUID)" -Method Delete -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
		}
	}
}

Function Invoke-CobaltAction {
	[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="Medium")]
	Param (
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(Position=0, Mandatory=$True,HelpMessage="The name of the action to invoke")][string]$ActionName,
		[Parameter(Position=1,HelpMessage="A hashtable of the parameters to pass to the action call")][Hashtable]$Parameters = @{},
		[Parameter(HelpMessage="The EntityUUID to apply the action to if it is a bound action", ValueFromPipelineByPropertyName='EntityUUID')][System.Guid]$EntityUUID
	)
	Process {
		if($EntityUUID -ne $null){ # Is this action being applied to a specific entity (a 'bound' action)?
			$Path = "Entities($EntityUUID)"
			$ActionName = ConvertTo-CanonicalODataType $ActionName
		}
#		if($ActionName -notcontains '.'){ # No namespace provided for ActionName?
#			$ActionName = "com.viewds.cobalt." + $ActionName
#		}
		$Path += "/$ActionName"
		if($PSCmdlet.ShouldProcess("$ActionName")){
			(Invoke-CobaltQuery -Connection $Connection -Path $Path -Method POST -BodyParameters $Parameters -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)).value
		}
	}
}

Function Invoke-CobaltFunction {
	[CmdletBinding()]
	Param (
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(Position=0,Mandatory=$True,HelpMessage="The name of the function to invoke")][string]$FunctionName,
		[Parameter(Position=1,HelpMessage="A hashtable of the parameters to pass to the action call")][Hashtable]$Parameters
	)
	Process {
		$Path = "/$FunctionName()"
		(Invoke-CobaltQuery -Path $Path -Method GET -BodyParameters $Parameters -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent).value)
	}
}

Function Convert-CredentialToAuthHeader {
[CmdletBinding()]
Param(
    [Parameter(HelpMessage="The PSCredential object to use convert to a basic authentication Authorization header string")][PSCredential]$Credential
)
	if($Credential -eq $null){
		Throw "Credential is null"
	}
    $authHeader = "{0}:{1}" -f ($Credential.GetNetworkCredential().username),($Credential.GetNetworkCredential().password)
    "Basic " + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($authHeader))
}

Function ConvertTo-CanonicalODataType {
Param(
    [Parameter(HelpMessage="The ODataType string to canonicalize")][string]$ODataType
)
	if(-not [string]::IsNullOrEmpty($ODataType)) {
		if($ODataType[0] -eq '#') {
			$ODataType = $ODataType.Substring(1)
		}
		if(-not $ODataType.Contains('.')) {
			$ODataType = 'com.viewds.cobalt.' + $ODataType
		}
	}
	return $ODataType
}

# Useful filter function when generating custom properties via Select-Object, and the resulting property should be an array, but Select-Object screws it up
# See Michael Klement's answers at https://powershell.org/forums/topic/convertto-json-adds-count-and-value-property-names/ and 
# http://stackoverflow.com/questions/20848507/why-does-powershell-give-different-result-in-one-liner-than-two-liner-when-conve/38212718#38212718

filter Convert-ArrayProperties {
  # Loop over all properties of the input object at hand...
  foreach ($prop in (Get-Member -InputObject $_ -Type Properties)) {
    # ... and, for array-typed properties, simply reassign the existing 
    # property value via @(...), the array subexpression operator, which makes
    # such properties behave like regular collections again.
    if (($val = $_.$($prop.Name)) -is [array]) {
      $_.$($prop.Name) = @($val)
    }
  }
  # Pass out the (potentially) modified object.
  $_
}