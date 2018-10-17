Function Add-CobaltMetadataProperty {
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(Mandatory=$true, HelpMessage="The fully namespace-qualified name of the entity type this property is part of")][string]$ODataType,
	[Parameter(Mandatory=$true, HelpMessage="The name of the property")][string]$Name,
	[Parameter(HelpMessage="The OData primitive type of the property, e.g. Edm.String")][string]$DataType = 'Edm.String',
	[Parameter(HelpMessage="The default value of the property")][string]$DefaultValue = $null,
	[Parameter(HelpMessage="A switch indicating that the property is nullable")][switch]$IsNullable,
	[Parameter(HelpMessage="A switch indicating that the property is a collection")][switch]$IsCollection,
	[Parameter(HelpMessage="A switch indicating that the property values must be unique")][switch]$UniqueValues,
	[Parameter(HelpMessage="The namespace the property is defined in")][string]$Namespace
)
	$Property = New-CobaltMetadataProperty -ODataType $ODataType -Name $Name -DataType $DataType -DefaultValue $DefaultValue -Namespace $Namespace -IsNullable:([bool]$PSBoundParameters['IsNullable'].IsPresent) -IsCollection:([bool]$PSBoundParameters['IsCollection'].IsPresent) -UniqueValues:([bool]$PSBoundParameters['UniqueValues'].IsPresent)
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		Invoke-CobaltQuery -Connection $Connection -Path '`$metadata/Properties' -Method POST -BodyParameters $Property -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$False
	}
}

Function New-CobaltMetadataProperty {
[CmdletBinding()]
Param(
	[Parameter(Mandatory=$True, HelpMessage="The fully namespace-qualified name of the entity type this property is part of")][string]$ODataType,
	[Parameter(Mandatory=$True, HelpMessage="The name of the property")][string]$Name,
	[Parameter(HelpMessage="The OData primitive type of the property, e.g. Edm.String")][string]$DataType = 'Edm.String',
	[Parameter(HelpMessage="The default value of the property")][string]$DefaultValue = $null,
	[Parameter(HelpMessage="A switch indicating that the property is nullable")][switch]$IsNullable,
	[Parameter(HelpMessage="A switch indicating that the property is a collection")][switch]$IsCollection,
	[Parameter(HelpMessage="A switch indicating that the property values must be unique")][switch]$UniqueValues,
	[Parameter(HelpMessage="The namespace the property is defined in")][string]$Namespace
)
	# Return a hash table of the new property definition
	$Properties = @{
		'@odata.type'='#Edm.Metadata.Property';
		'Fullname'="$ODataType/$Name";
		'Name'=$Name;
		'Nullable'=[boolean]$IsNullable;
		'IsCollection'=[boolean]$IsCollection;
		'UniqueValues'=[boolean]$UniqueValues;
		'Type@odata.bind'="Types('$DataType')";
	}
	if(-not [string]::IsNullOrEmpty($Namespace)){
		$Properties['Namespace'] = $Namespace
	}
	return $Properties
}

Function Add-CobaltMetadataNavigationProperty {
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(Mandatory=$true, HelpMessage="The fully namespace-qualified name of the entity type this property is part of")][string]$ODataType,
	[Parameter(Mandatory=$true, HelpMessage="The name of the property")][string]$Name,
	[Parameter(HelpMessage="A switch indicating that the property is nullable")][switch]$IsNullable,
	[Parameter(HelpMessage="A switch indicating that the property is a collection")][switch]$IsCollection,
	[Parameter(HelpMessage="The namespace the property is defined in")][string]$Namespace
)
	$Property = New-CobaltMetadataNavigationProperty -ODataType $ODataType -Name $Name -Namespace $Namespace -IsNullable:([bool]$PSBoundParameters['IsNullable'].IsPresent) -IsCollection:([bool]$PSBoundParameters['IsCollection'].IsPresent)
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		Invoke-CobaltQuery -Connection $Connection -Path `$metadata/NavigationProperties -Method Post -BodyParameters $Property -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$false
	}
}
	
Function New-CobaltMetadataNavigationProperty {
[CmdletBinding()]
Param(
	[Parameter(Mandatory=$True, HelpMessage="The fully namespace-qualified name of the entity type this property is part of")][string]$ODataType,
	[Parameter(Mandatory=$True, HelpMessage="The name of the property")][string]$Name,
	[Parameter(HelpMessage="A switch indicating that the property is nullable")][switch]$IsNullable,
	[Parameter(HelpMessage="A switch indicating that the property is a collection")][switch]$IsCollection,
	[Parameter(HelpMessage="The namespace the property is defined in")][string]$Namespace
)
	# Return a hash table of the new property definition
	$Properties = @{
		'@odata.type'='#Edm.Metadata.NavigationProperty';
		'Fullname'="$ODataType/$Name";
		'Name'=$Name;
		'Nullable'=[boolean]$IsNullable;
		'IsCollection'=[boolean]$IsCollection;
	}
	if(-not [string]::IsNullOrEmpty($Namespace)){
		$Properties['Namespace'] = $Namespace
	}
	return $Properties
}

Function New-CobaltMetadataType {
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(HelpMessage="The namespace-qualified name of the new entity type", Mandatory=$True)][string]$QualifiedName,
	[Parameter(HelpMessage="The short name of the new entity type")][string]$ShortName = $QualifiedName.Split('.')[-1],
	[Parameter(HelpMessage="The namespace-qualified name of the entity type the new type inherits from, e.g. com.viewds.cobalt.User")][string]$BaseType = '',
	[Parameter(HelpMessage="An array of CobaltMetadataProperty objects to that make up the new entity type")][array]$Properties = @(),
	[Parameter(HelpMessage="An array of CobaltMetadataNavigationProperty objects to that make up the new entity type")][array]$NavigationProperties = @(),
	[Parameter(HelpMessage="Switch indicating that the entity type is abstract")][Switch]$Abstract,
	[Parameter(HelpMessage="Switch indicating that the entity type is open")][Switch]$OpenType,
	[Parameter(HelpMessage="Switch indicating that the entity type has a string")][Switch]$HasStream
)
	$TypeProperties = @{
		'@odata.type'='#Edm.Metadata.EntityType';
		'QualifiedName'=$QualifiedName;
		'Name'=$ShortName;
		'Properties'=$Properties;
		'NavigationProperties'=$NavigationProperties;
		'Abstract'=[boolean]$Abstract;
		'OpenType'=[boolean]$OpenType;
		'HasStream'=[boolean]$HasStream;
	}

	if(-not [string]::IsNullOrEmpty($BaseType)){
		$TypeProperties.Add('BaseType@odata.bind', "Types('" + $BaseType + "')")
	}

	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		Invoke-CobaltQuery -Connection $Connection -Path '$metadata/Types' -Method Post -BodyParameters $TypeProperties -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$false
	}
}

Function Get-CobaltMetadataProperty {
[CmdletBinding()]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(HelpMessage="Return the type information of the property")][switch]$Types
)
	$Path = '$metadata/Properties'
	if($Types){
		$Path += '?$expand=Type'
	}

    (Invoke-CobaltQuery -Connection $Connection -Path $Path -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)).value
}

Function Get-CobaltMetadataNavigationProperty {
[CmdletBinding()]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection)
)
		(Invoke-CobaltQuery -Connection $Connection -Path '$metadata/NavigationProperties' -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)).value
}
	
Function Get-CobaltMetadataType {
[CmdletBinding()]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(Position=0, HelpMessage="The name of the entity type to return")][string]$ODataType,
	[Parameter(HelpMessage="A switch indicating to expand the derived types navigation property")][Switch]$DerivedTypes,
	[Parameter(HelpMessage="A switch indicating to expand the base type navigation property")][Switch]$BaseType,
	[Parameter(HelpMessage="A switch indicating to expand the properties navigation property")][Switch]$Properties
)
	if([String]::IsNullOrEmpty($ODataType)){
		$Path = '$metadata/Types/Edm.Metadata.EntityType'
		$singleEntity = $false
	}
	else {
		$Path = "`$metadata/Types(`'$(ConvertTo-CanonicalODataType($ODataType))`')/Edm.Metadata.EntityType"
		$singleEntity = $true
	}
	if($DerivedTypes -or $BaseType -or $Properties){
		$Path += '?$expand='
		$firstItem = $true
		if($DerivedTypes){
			if(-not $firstItem) {$Path += ','}
			$Path += 'DerivedTypes'
			$firstItem = $false
		}
		if($BaseType){
			if(-not $firstItem) {$Path += ','}
			$Path += 'BaseType'
			$firstItem = $false
		}
		if($Properties){
			if(-not $firstItem) {$Path += ','}
			$Path += 'Properties,NavigationProperties'
			$firstItem = $false
		}
		if($NavigationProperties){
			if(-not $firstItem) {$Path += ','}
			$Path += 'NavigationProperties'
			$firstItem = $false
		}
	}
	if($singleEntity){
		Invoke-CobaltQuery -Connection $Connection -Path $Path -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	}
	else {
		(Invoke-CobaltQuery -Connection $Connection -Path $Path -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)).value
	}
}

Function Get-CobaltMetadataFunction {
[CmdletBinding()]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection)
)
    (Invoke-CobaltQuery -Connection $Connection -Path '$metadata/Functions' -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)).value
}
Function Get-CobaltMetadataAction {
[CmdletBinding()]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection)
	)
	(Invoke-CobaltQuery -Connection $Connection -Path '$metadata/Actions' -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)).value
}

Function Remove-CobaltMetadataType {
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(Mandatory=$True, Position=0, HelpMessage="The namespace-qualified name of the entity type to remove")][string]$ODataType
	)
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		Invoke-CobaltQuery -Connection $Connection "`$metadata/Types('$ODataType')" -Method Delete -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$false
	}
}

Function Remove-CobaltMetadataProperty {
[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact="High")]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(Mandatory=$True, Position=0, HelpMessage="The namespace-qualified name of the property type to remove")][string]$PropertyName
	)
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		Invoke-CobaltQuery -Connection $Connection -Path "`$metadata/Properties('$PropertyName')" -Method Delete -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$false
	}
}
