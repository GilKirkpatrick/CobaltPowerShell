Function New-CobaltServiceProvider {
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
    [Parameter(HelpMessage="The OData type of the new entity")][string]$ODataType = 'com.viewds.cobalt.ServiceProvider',
    [Parameter(Mandatory=$True, HelpMessage="The name of the service provider")][string]$Name,
    [Parameter(HelpMessage="The description of the service provider")][string[]]$Description = @(),
    [Parameter(Mandatory=$True, HelpMessage="The callback URL for the application")][string[]]$Callback,
    [Parameter(HelpMessage="The encryption algorithm to use")][string]$Algorithm = 'HS256',
    [Parameter(HelpMessage="The application secret")][string]$ClientSecret = (New-Guid).Guid,
    [Parameter(HelpMessage="An array of OAuth scopes for which user consent is assumed")][string[]]$ConsentAssumed = @(),
    [Parameter(HelpMessage="The lifetime in seconds for any security token issued")][int]$Duration = 3600,
    [Parameter(HelpMessage="Don't know")][string[]]$Entity = @(),
    [Parameter(HelpMessage="A JSON-encoded string describing the SAML attribute assertions to be provided with the authentication message")][string[]]$SamlAttributeConsumingService=@(),
    [Parameter(HelpMessage="A flag indicating that the IdP should use the SHA1 hashing algorithm")][Boolean]$UseSHA1 = $False,
    [Parameter(HelpMessage="The name of the external authentication service for Cobalt to use")][string]$AuthMode = "simple",
    [Parameter(HelpMessage="A flag indicating that the IdP should return errors to the application")][Boolean]$ReturnError = $False
)
    $properties = @{
        'Name'=$Name;
        'Description'=$Description;
        'Callback'=$Callback;
        'Algorithm'=$Algorithm;
        'ClientSecret'=$ClientSecret;
        'ConsentAssumed'=$ConsentAssumed;
        'Duration'=$Duration;
        'Entity'=$Entity;
        'SAMLAttributeConsumingService'=$SAMLAttributeConsumingService;
        'UseSHA1'=$UseSHA1;
        'ReturnError'=$ReturnError;
		'AuthMode'=$AuthMode;
		'UserCertificate'=@()
    }
	# AuthMode can't be an empty string; it has to be either $null or a non-zero length string
	# if($AuthMode -eq "") {
	#	$properties['AuthMode'] = $null
	# }
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType $ODataType -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$False
	}
}

Function Get-CobaltServiceProvider {
[CmdletBinding()]
param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.ServiceProvider',
	[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
	[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function New-CobaltRule {
[CmdletBinding()]
param(
    [Parameter(Position=0, HelpMessage="The effect of the rule, either 'Permit' or 'Deny'")][ValidateSet('Permit', 'Deny', 'Include', 'Exclude')][string]$Effect = 'Permit',
    [Parameter(Position=1, HelpMessage="The rule expression")][string]$Condition
)
	$properties = @{
		'PsTypeName'='CobaltRule'; 
		'Effect'=$Effect
	}
	if(-not [string]::IsNullOrEmpty($Condition)){
		$properties.Add('Condition', $Condition)
	}
	New-Object PsCustomObject -Property $properties
}

Function New-CobaltAccessPolicy {
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
    [Parameter(HelpMessage="The OData type of the new entity")][string]$ODataType = 'com.viewds.cobalt.AccessPolicy',
	[Parameter(HelpMessage="The precedence of the new policy")][int]$Precedence = 2,
	[Parameter(HelpMessage="A description of the new policy")][string[]]$Description = @("New AccessPolicy created $(Get-Date)"),
	[Parameter(HelpMessage="Indicates that the policy is enabled")][Switch]$Enabled,
	[Parameter(Mandatory=$True, HelpMessage="The name of the policy")][string]$Name,
	[Parameter(HelpMessage="The target of policy")][string]$Target = $null,
	[Parameter(HelpMessage="The rules that define the policy")][PsCustomObject[]]$Rules = @((New-CobaltRule -Effect 'Permit')),
	[Parameter(HelpMessage="A set of additional properties for the new policy")][Hashtable]$AdditionalProperties = @{}
)
	if([String]::IsNullOrWhiteSpace($Name)) {
		Throw "Name must not be null or all whitespace"
	}
	$properties = @{
		'Precedence'=$Precedence;
		'Description'=$Description;
		'Enabled'=[bool]$Enabled;
		'Name'=$Name;
		'Rules'=$Rules;
	}

	# Necessary siliness so that we provide null instead of "" in Target
	if([String]::IsNullOrEmpty($Target)){
		$properties['Target'] = $null
	}
	else {
		$properties['Target'] = $Target
	}
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType $ODataType -AdditionalProperties $AdditionalProperties -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$False
	}
}

Function Get-CobaltAccessPolicy {
[CmdletBinding()]
param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.AccessPolicy',
	[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
	[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function New-CobaltUser {
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
    [Parameter(HelpMessage="The OData type of the new entity")][string]$ODataType = 'com.viewds.cobalt.User',
    [Parameter(HelpMessage="The name the user will use to authenticate")][string]$Username,
    [Parameter(Mandatory=$True, HelpMessage="The password the user will use to authenticate")][string]$Password,
	[Parameter(HelpMessage="The administrator level for the new user")][int]$AdministratorLevel,
	[Parameter(HelpMessage="Enables the user to authenticate")][Switch]$Enabled,
	[Parameter(HelpMessage="A set of additional properties for the new policy")][Hashtable]$AdditionalProperties = @{}
)
	$properties = @{
		'Enabled'=[bool]$Enabled;
		'AdministratorLevel'=$AdministratorLevel;
		'Username'=$Username;
		'Password'=(Invoke-CobaltAction -Connection $Connection -ActionName 'HashPassword' -Parameters @{'Password'=$Password})
	}

	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType $ODataType -AdditionalProperties $AdditionalProperties -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$False
	}
}

Function Get-CobaltUser {
[CmdletBinding()]
param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.User',
	[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
	[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function Get-CobaltRole {
[CmdletBinding()]
param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.Role',
	[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
	[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function New-CobaltRole {
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(HelpMessage="The OData type of the new entity")][string]$ODataType = 'com.viewds.cobalt.Role',
	[Parameter(HelpMessage="The names the role is known by")][string[]]$Names = @(,"New role created at $(Get-Date)"),
	[Parameter(HelpMessage="A description of the role")][string[]]$Description = @(),
	[Parameter(HelpMessage="The precedence level of the role, 0=system, 1=csp, 2=tenant")][int]$Precedence=2,
	[Parameter(HelpMessage="Enables the role definition")][Switch]$Enabled,
	[Parameter(HelpMessage="The condition expression that determines when this role applies")][string]$Condition = $null,
	[Parameter(HelpMessage="The permission expressions that are granted to members of this role")][string[]]$Permissions,
	[Parameter(HelpMessage="The roles this role inherits permissions from")][System.Guid[]]$Inherits,
	[Parameter(HelpMessage="A set of additional properties for the new role")][Hashtable]$AdditionalProperties = @{}
)
	$properties = @{
		'Names'=$Names;
		'Description'=$Description;
		'Precedence'=$Precedence;
		'Enabled'=[bool]$Enabled;
		'Permissions'=$Permissions;
	}
	# Necessary siliness so that we provide null instead of "" in Condition
	if([String]::IsNullOrEmpty($Condition)){
		$properties['Condition'] = $null
	}
	else {
		$properties['Condition'] = $Condition
	}

	if($Inherits.Count -gt 0){
		$Values = @()
		$Inherits | ForEach-Object {$Values += @{'@odata.id'="Entities($_)"}}
		$properties['Inherits'] = $Values
	}
 
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType $ODataType -AdditionalProperties $AdditionalProperties -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$False
	}
}

Function Get-CobaltOrganization {
	[CmdletBinding()]
	param(
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.Organization',
		[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
		[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
	)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}
Function Get-CobaltApplicationEntitlementPolicy {
	[CmdletBinding()]
	param(
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.ApplicationEntitlementPolicy',
		[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
		[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
	)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function New-CobaltApplicationEntitlementPolicy {
	[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
	param(
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type of the new entity")][string]$ODataType = 'com.viewds.cobalt.ApplicationEntitlementPolicy',
		[Parameter(Mandatory=$True, HelpMessage="The name of the new application entitlement policy")][string]$Name,
		[Parameter(HelpMessage="A description of the new application entitlement policy")][string[]]$Description = @("New entitlement policy created $(Get-Date)"),
		[Parameter(HelpMessage="An array of roles to which the policy applies")][string[]]$Roles = @(),
		[Parameter(HelpMessage="An array of user expressions to which the policy applies")][string[]]$UserExpressions = @(),
		[Parameter(HelpMessage="An array of application expressions to which the policy applies")][string[]]$ApplicationExpressions = @(),
		[Parameter(HelpMessage="A flag indicating that the application entitlement policy should be enabled when created")][Switch]$Enabled,
		[Parameter(HelpMessage="The precedence of the application entitlement policy")][int]$Precedence = 2,
		[Parameter(HelpMessage="A set of additional properties for the new policy")][Hashtable]$AdditionalProperties = @{}
)
		$properties = @{
			'Names'=$Names;
			'Description'=$Description;
			'Precedence'=$Precedence;
			'Enabled'=[bool]$Enabled;
			'Roles'=$Roles;
			'UserExpressions'=$UserExpressions;
			'ApplicationExpressions'=$ApplicationExpressions;
		}
		if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
			New-CobaltEntity -Connection $Connection -Properties $properties -ODataType $ODataType -AdditionalProperties $AdditionalProperties -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$false
		}
	}

	Function Get-CobaltPasswordPolicy {
		[CmdletBinding()]
		param (
			[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
			[Parameter(HelpMessage="The OData type of the new entity")][string]$ODataType = 'com.viewds.cobalt.PasswordPolicy',
			[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
			[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
			)
		Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	}
	
Function New-CobaltPasswordPolicy {
	[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Medium')]
	param (
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type of the new entity")][string]$ODataType = 'com.viewds.cobalt.PasswordPolicy',
		[Parameter(Mandatory=$True, HelpMessage="The name of the password policy")][string]$Name,
		[Parameter(HelpMessage="The names of the roles to which this password policy applies")][string[]]$Roles=@(),
		[Parameter(HelpMessage="The user expressions to which this policy applies")][string[]]$UserExpressions=@(),
		[Parameter(HelpMessage="The description of the password policy")][string[]]$Description = @(),
		[Parameter(HelpMessage="The minimum number of uppercase characters required in a password")][int]$MinimumUppercaseCharacters,
		[Parameter(HelpMessage="The minimum number of lowercase characters required in a password")][int]$MinimumLowercaseCharacters,
		[Parameter(HelpMessage="The minimum number of digits required in a password")][int]$MinimumDigitCharacters,
		[Parameter(HelpMessage="The minimum number of special characters required in a password")][int]$MinimumOtherCharacters,
		[Parameter(HelpMessage="The minimum number of total characters required in a password")][int]$MinimumLength,
		[Parameter(HelpMessage="The minimum lexical distance between a new password and the current password ")][int]$MinimumDistance,
		[Parameter(HelpMessage="The number of passwords that will be kept in the password history")][int]$PasswordHistoryLength,
		[Parameter(HelpMessage="The maximum age of a password (in days) before it needs to be reset")][int]$MaximumPasswordAge,
		[Parameter(HelpMessage="The number of days before the password needs to be reset that a notification will be sent to the user")][int]$PasswordExpiryWarning,
		[Parameter(HelpMessage="The interval (in seconds) during which a maximum number of incorrect password attempts will be checked")][int]$InvalidPasswordInterval,
		[Parameter(HelpMessage="The number of incorrect password attempts that will result in the account being locked")][int]$InvalidPasswordCount,
		[Parameter(HelpMessage="The number of seconds that the account will be locked if the maximum number of invalid password attempts is encountered within the invalid password interval")][int]$LockoutDuration,
		[Parameter(HelpMessage="A set of additional properties for the new IdP endpoint")][Hashtable]$AdditionalProperties = @{}
	)

	$properties = @{
		'Name'=$Name;
		'Description'=$Description;
		'Enabled'=[bool]$Enabled;
		'Roles'=$Roles;
		'UserExpressions'=$UserExpressions;
		'Precedence'=$Precedence;
	}
	if($MinimumUppercaseCharacters -ne $null){
		$properties.Add('MinimumUppercaseCharacters', $MinimumUppercaseCharacters)
	}
	if($MinimumLowercaseCharacters -ne $null){
		$properties.Add('MinimumLowercaseCharacters', $MinimumLowercaseCharacters)
	}
	if($MinimumDigitCharacters -ne $null){
		$properties.Add('MinimumDigitCharacters', $MinimumDigitCharacters)
	}
	if($MinimumOtherCharacters -ne $null){
		$properties.Add('MinimumOtherCharacters', $MinimumOtherCharacters)
	}
	if($MinimumLength -ne $null){
		$properties.Add('MinimumLength', $MinimumLength)
	}
	if($MinimumDistance -ne $null){
		$properties.Add('MinimumDistance', $MinimumDistance)
	}
	if($PasswordHistoryLength -ne $null) {
		$properties.Add('PasswordHistoryLength', $PasswordHistoryLength)
	}
	if($MaximumPasswordAge -ne $null){
		$properties.Add('MaximumPasswordAge', $MaximumPasswordAge)
	}
	if($PasswordExpiryWarning -ne $null){
		$properties.Add('PasswordExpiryWarning', $PasswordExpiryWarning)
	}
	if($InvalidPasswordInterval -ne $null){
		$properties.Add('InvalidPasswordInterval', $InvalidPasswordInterval)
	}
	if($InvalidPasswordCount -ne $null){
		$properties.Add('InvalidPasswordCount', $InvalidPasswordCount)
	}
	if($LockoutDuration -ne $null){
		$properties.Add('LockoutDuration', $LockoutDuration)
	}

	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType $ODataType -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -AdditionalProperties $AdditionalProperties -Confirm:$false
	}
}
	
Function New-CobaltFileLoggingService {
	[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Medium')]
	param (
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type of the new entity")][string]$ODataType = 'com.viewds.cobalt.FileLoggingService',
		[Parameter(Mandatory=$True, HelpMessage="The name of the logging service")][string]$Name,
		[Parameter(HelpMessage="The description of the logging service")][string[]]$Description = @(),
		[Parameter(Mandatory=$True, HelpMessage="The Zone for which this logging service will handle log messages")][string]$Zone,
		[Parameter(Mandatory=$True, HelpMessage="The container file path to log the messages to")][string]$LogFilePath
	)
	$properties = @{
		'Name'=$Name;
		'Description'=$Description;
		'Zone'=$Zone;
		'LogFilePath'=$LogFilePath
	}
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType $ODataType -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -AdditionalProperties $AdditionalProperties -Confirm:$false
	}
}

Function Get-CobaltFileLoggingService {
	[CmdletBinding()]
	param(
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.FileLoggingService',
		[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
		[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
	)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function New-CobaltCEFLoggingService {
	[CmdletBinding()]
	param (
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type of the new entity")][string]$ODataType = 'com.viewds.cobalt.FileLoggingService',
		[Parameter(Mandatory=$True, HelpMessage="The name of the logging service")][string]$Name,
		[Parameter(HelpMessage="The description of the logging service")][string[]]$Description = @(),
		[Parameter(Mandatory=$True, HelpMessage="The Zone for which this logging service will handle log messages")][string]$Zone
	)
	$properties = @{
		'Name'=$Name;
		'Description'=$Description;
		'Zone'=$Zone;
	}
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType $ODataType -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -AdditionalProperties $AdditionalProperties -Confirm:$false
	}
}

Function Get-CobaltCEFLoggingService {
	[CmdletBinding()]
	param(
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.CEFLoggingService',
		[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
		[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
	)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function Get-CobaltAuditPolicy {
	[CmdletBinding()]
	param(
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.AuditPolicy',
		[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
		[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
	)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function New-CobaltAuditPolicy {
	[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Medium')]
	param(
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type of the new entity")][string]$ODataType = 'com.viewds.cobalt.AuditPolicy',
		[Parameter(HelpMessage="The precedence of the new policy")][int]$Precedence = 2,
		[Parameter(HelpMessage="A description of the new policy")][string[]]$Description = @("New AuditPolicy created $(Get-Date)"),
		[Parameter(HelpMessage="Indicates that the policy is enabled")][Switch]$Enabled,
		[Parameter(Mandatory=$True, HelpMessage="The name of the policy")][string]$Name,
		[Parameter(HelpMessage="The target of policy")][string]$Target = $null,
		[Parameter(HelpMessage="The rules that define the policy")][PsCustomObject[]]$Rules = @((New-CobaltRule -Effect 'Include')),
		[Parameter(HelpMessage="A set of additional properties for the new policy")][Hashtable]$AdditionalProperties = @{}
	)
	if([String]::IsNullOrWhiteSpace($Name)) {
		Throw "Name must not be null or all whitespace"
	}
	$properties = @{
		'Precedence'=$Precedence;
		'Description'=$Description;
		'Enabled'=[bool]$Enabled;
		'Name'=$Name;
		'Rules'=$Rules;
	}

	# Necessary siliness so that we provide null instead of "" in Target
	if([String]::IsNullOrEmpty($Target)){
		$properties['Target'] = $null
	}
	else {
		$properties['Target'] = $Condition
	}
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType $ODataType -AdditionalProperties $AdditionalProperties -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$False
	}
}
