
Function Get-CobaltIDPEndpoint {
[CmdletBinding()]
Param(
	[Parameter(HelpMessage='The Cobalt connection object to use for the OData operation')][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.IDPEndpoint',
	[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
	[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function New-CobaltIDPEndpoint {
[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Medium')]
param (
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
    [Parameter(Mandatory=$True, HelpMessage="The name of the new IDP endpoint")][string]$Name,
	[Parameter(Mandatory=$True, HelpMessage="The name of the tenant this IDP endpoint is associated with")][string]$Tenant,
	[Parameter(Mandatory=$True, HelpMessage="The zone this identity service is associated with")][string]$Zone,
    [Parameter(HelpMessage="The name of the OData User entity property used to contain consented OAuth scopes")][string]$ConsentProperty,
	[Parameter(HelpMessage="The name of the OData User entity property used to indicate that it is enabled")][string]$EnabledProperty = 'Enabled',
	[Parameter(HelpMessage="The URL path for the identity provider endpoint, e.g. /csp/identity/")][string]$Path,
	[Parameter(HelpMessage="The name of the OData User property to use as a subject identifier")][string]$SubjectIDProperty = 'Username',
	[Parameter(HelpMessage="The name of the OData User property to use as a username")][string]$UsernameProperty = 'Username',
    [Parameter(HelpMessage="The description of the new IDP endpoint")][string[]]$Description = @("New IDPEndpoint created $(Get-Date)"),
    [Parameter(HelpMessage="The public key to use for this endpoint in JSON string format")][string[]]$Public,
	[Parameter(HelpMessage="The private key to use for this endpoint in JSON string format")][string]$Private,
    [Parameter(HelpMessage="The Base-64 encoded representation of the certificates to provide as the certificate path in a SAML signature")][string[]]$CACertificate = @(),
    [Parameter(HelpMessage="Flag indicating whether authentication errors should be returned to the application")][Switch]$ReturnError,
    [Parameter(HelpMessage="The supported OAuth scopes")]$SupportedScopes = @(),
    [Parameter(HelpMessage="Flag indicating whenther SAML responses should be signed or not")][Switch]$SignSAMLResponse,
    [Parameter(HelpMessage="The default lifetime of tokens issued by the IDP endpoint, in seconds")][int]$Duration = 3600,
    [Parameter(HelpMessage="The attribute used to store the time-based one time password secret")][string]$TOTPProperty,
    [Parameter(HelpMessage="Flag indicating that one time password use is optional")][Boolean]$TOTPOptional = $True,
    [Parameter(HelpMessage="The URL to use for identity data")][string]$Endpoint,
	[Parameter(HelpMessage="Use the default public and private keys for token signing")][Switch]$UseDefaultKeys,
	[Parameter(HelpMessage="Use the default certificate")][Switch]$UseDefaultCertificate,
	[Parameter(HelpMessage="Use the default OAuth scopes")][Switch]$UseDefaultScopes,
	[Parameter(HelpMessage="Provide user claims in the OpenID Connect id token")][Switch]$ClaimsInIDToken,
	[Parameter(HelpMessage="The attribute to use for checking passwords")][string]$PasswordProperty = 'Password',
	[Parameter(HelpMessage="The namespace-qualified name of the entity type to use for authentication")]$UserEntityType = 'com.viewds.cobalt.User',
	[Parameter(HelpMessage="Use authentication policy to determine if user is allowed to authenticate (no one can authenticate until policy is created)")][Switch]$UsePolicy,
	[Parameter(HelpMessage="A set of additional properties for the new IdP endpoint")][Hashtable]$AdditionalProperties = @{}
)
    $properties = @{
        'Name'=$Name;
		'Description'=$Description;
		'Path'=$Path;
		'CACertificate'=$CaCertificate;
		'SignSAMLResponse'=[bool]$SignSAMLResponse;
		'Duration'=$Duration;
		'TOTPOptional'=$TOTPOptional;
		'Tenant'= $Tenant;
		'ClaimsInIDToken'= [bool]$ClaimsInIDToken;
		'SupportedScopes'=$SupportedScopes;
		'Policy'=[bool]$UsePolicy;
		'UserEntityType'=$UserEntityType;
		'Zone'=$Zone
	}

	if($ReturnError){
		$properties['ReturnError'] = [bool]$ReturnError
	}

	if([String]::IsNullOrEmpty($Path)){
		$properties['Path'] = "/$Tenant/Identity"
	}

	if(-not [String]::IsNullOrEmpty($PasswordProperty)){
		$properties.Add('PasswordProperty', $PasswordProperty)
	}
	if(-not [String]::IsNullOrEmpty($ConsentProperty)){
		$properties.Add('ConsentProperty', $ConsentProperty)
	}
	if(-not [String]::IsNullOrEmpty($EnabledProperty)){
		$properties.Add('EnabledProperty', $EnabledProperty)
	}
	if(-not [String]::IsNullOrEmpty($TOTPProperty)){
		$properties.Add('TOTPProperty', $TOTPProperty)
	}
	if(-not [String]::IsNullOrEmpty($SubjectIDProperty)){
		$properties.Add('SubjectIDProperty', $SubjectIDProperty)
	}
	if(-not [String]::IsNullOrEmpty($UsernameProperty)){
		$properties.Add('UsernameProperty', $UsernameProperty)
	}
	if($PublicKeys -ne $null){
		$properties.Add('Public', $Public)
	}
	if(-not [String]::IsNullOrEmpty($Private)){
		$properties.Add('Private', $Private)
	}
	if(-not [String]::IsNullOrEmpty($Endpoint)){
		$properties.Add('Endpoint', $Endpoint)
	}
	if($UseDefaultKeys){
		$properties.Add('Public', $script:DefaultPublicKey)
		$properties.Add('Private'. $script:DefaultPrivateKey)
	}
	if($UseDefaultCertificate){
		$properties.Add('CACertificate', $script:DefaultCACertificate)
	}
	if($UseDefaultScopes){
		# Already added to hashtable
		$properties.SupportedScopes = $script:DefaultScopes
	}
	
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType "com.viewds.cobalt.IDPEndpoint" -AdditionalProperties $AdditionalProperties -Verbose:([bool]$PSBoundParameters["Verbose"].IsPresent) -Confirm:$false
	}
}

Function Get-CobaltTemplate {
	[CmdletBinding()]
	Param(
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.Template',
		[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
		[Parameter(HelpMessage="Expand the ServiceProvider navigation property")][Switch]$ServiceProvider
	)
	if([bool]$ServiceProvider){
		$Expand = 'ServiceProvider'
	}
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function New-CobaltTemplate {
	[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Medium')]
	Param (
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type of the new entity")][string]$ODataType = 'com.viewds.cobalt.Template',
		[Parameter(HelpMessage="The name of the new entity")][string]$Name,
		[Parameter(HelpMessage="The description of the new entity")][string[]]$Description = @(),
		[Parameter(Mandatory=$True, HelpMessage="The type of the new template")][ValidateSet('account','authenticator','consent','error','login','revoke-consent','status')][string]$TemplateType,
		[Parameter(HelpMessage="The display parameter for the template")][string]$Display = "",
		[Parameter(Mandatory=$True, HelpMessage="The MVEL text of the template", ParameterSetName='TemplateString')][string]$TemplateString,
		[Parameter(Mandatory=$True, HelpMessage="The name of the file containing the MVEL text of the template", ParameterSetName='TemplateFile')][string]$TemplateFile,
		[Parameter(Mandatory=$True, HelpMessage="The EntityUUID of the service entity this template is associated with")][System.Guid]$ServiceProvider,
		[Parameter(HelpMessage="A set of additional properties for the new IdP endpoint")][Hashtable]$AdditionalProperties = @{}
	)
	if($PSCmdlet.ParameterSetName -eq 'TemplateFile'){
		$TemplateString = Get-Content -Path $TemplateFile
	}
	$properties = @{
		'Name'=$Name;
		'Description'=$Description;
		'TemplateType'=$TemplateType;
		'Content'=$TemplateString;
		'ServiceProvider@odata.bind'="Entities($ServiceProvider)";
	}
	if(-not [string]::IsNullOrEmpty($Display)){
		$Properties['Display'] = $Display
	}
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType $ODataType -AdditionalProperties $AdditionalProperties -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$false
	}
}

Function Get-CobaltODataEndpoint {
	[CmdletBinding()]
	Param(
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.ODataEndpoint',
		[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
		[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
	)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function Get-CobaltTenant {
	[CmdletBinding()]
	Param(
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.Tenant',
		[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
		[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
	)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}
	
Function New-CobaltTenant {
[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Medium')]
param (
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(Mandatory=$True, HelpMessage="The name of the new tenant")][string]$Name,
	[Parameter(Mandatory=$True, HelpMessage="The fully qualified namespace string for the tenant")][string]$NamespaceName,
	[Parameter(Mandatory=$True, HelpMessage="A short alias for the tenant namespace")][string]$NamespaceAlias,
	[Parameter(Mandatory=$True, HelpMessage="The initial username")][string]$Username,
	#TODO: Check how the password should be encoded, and properly handled in PoSh
	[Parameter(Mandatory=$True, HelpMessage="The initial password")][string]$Password,
	[Parameter(HelpMessage="A hashtable of additional attributes to add to the new Tenant entity")][Hashtable]$AdditionalProperties,
	[Parameter(HelpMessage="A switch indicating the tenant should be enabled immediately")][Switch]$Enabled

)
	$properties = @{
		'Name'=$Name;
		'NamespaceName'=$NamespaceName;
		'NamespaceAlias'=$NamespaceAlias;
		'Username'=$Username;
		'Password'=$Password;
		'Enabled'=[Boolean]$Enabled;
	}
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType 'com.viewds.cobalt.Tenant' -AdditionalProperties $AdditionalProperties -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$false
	}
}

Function Get-CobaltDatastoreContainer {
[CmdletBinding()]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.DatastoreContainer',
	[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
	[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function New-CobaltDatastoreContainer {
[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Medium')]
param (
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(Mandatory=$True, HelpMessage="The hostname of the host to create the new datastore on ")][string]$Hostname,
	[Parameter(HelpMessage="The hostname where the master datastore for the tenant lives")][string]$Master = $null,
	[Parameter(Mandatory=$True, HelpMessage="The name of the tenant that this datastore is for")][string]$Tenant
)
	#TODO: Get the hostname of the master from the directory?
	$properties = @{
		'Hostname'=$Hostname;
		'Master'=$Master;
		'Tenant'=$Tenant;
		'Promote'=$False;
	}
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType 'com.viewds.cobalt.DatastoreContainer' -AdditionalProperties $AdditionalProperties -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$false
	}
}

Function Get-CobaltStaticContentEndpoint {
	[CmdletBinding()]
	Param(
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.StaticContentEndpoint',
		[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter
	)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function New-CobaltStaticContentEndpoint {
	[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Medium')]
	param (
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type of the new entity")][string]$ODataType = 'com.viewds.cobalt.StaticContentEndpoint',
		[Parameter(HelpMessage="The name of the new entity")][string]$Name,
		[Parameter(HelpMessage="The description of the new entity")][string[]]$Description = @(),
		[Parameter(Mandatory=$True, HelpMessage="The HTTP path of the endpoint")][string]$Path,
		[Parameter(Mandatory=$True, HelpMessage="The file system path containing the static content")][string]$Content,
		[Parameter(Mandatory=$True, HelpMessage="The EntityUUID of the HTTPServer that exposes this endpoint")][System.Guid]$HTTPServerUUID,
		[Parameter(HelpMessage="A hashtable of additional attributes to add to the new StaticContentEndpoint entity")][Hashtable]$AdditionalProperties = @{}
	)
	$properties = @{
		'Name'=$Name;
		'Description'=$Description;
		'Path'=$Path;
		'Content'=$Content;
		'HTTPServer@odata.bind'="Entities($HTTPServerUUID)"
	}
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType $ODataType -AdditionalProperties $AdditionalProperties -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$false
	}
}
	

Function Get-CobaltHttpServer {
[CmdletBinding()]
Param(
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
	[Parameter(HelpMessage="The OData type to get")][string]$ODataType = 'com.viewds.cobalt.HTTPServer',
	[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
	[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function New-CobaltHttpServer {
[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Medium')]
param (
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
    [Parameter(HelpMessage="The OData type of the new entity")][string]$ODataType = 'com.viewds.cobalt.HTTPServer',
	[Parameter(Mandatory=$True, HelpMessage="The name of the HTTP server")][string]$Name,
	[Parameter(Mandatory=$True, HelpMessage="The zone of the HTTP server")][string]$Zone,
	[Parameter(HelpMessage="A description of the new HTTP server")][string[]]$Description = @("New HTTP server created $(Get-Date)"),
	[Parameter(HelpMessage="The TCP/IP port of the HTTP server")][int]$Port=8080,
	[Parameter(HelpMessage="The hostname of the HTTP server")][string]$Hostname = 'localhost',
	[Parameter(HelpMessage="The PKCS12 file containing the certificate and private key for HTTPS")][string]$CertFile,
    [Parameter(HelpMessage="The certificates to provide as the certificate path for validating peer credentials")][string[]]$CAPath = @(),
	[Parameter(HelpMessage="A flag indicating to use Cross-origin Resource Sharing (CORS) headers")][Switch]$UseCors,
	[Parameter(HelpMessage="A set of HTTP headers that a Javascript client is allowed manage")][string[]]$CorsAllowedHeaders=@(),
	[Parameter(HelpMessage="A set of HTTP headers that a JavaScript client is allowed to access")][string[]]$CorsExposedHeaders=@(),
	[Parameter(HelpMessage="A set of HTTP headers that will be present in the response")][string[]]$StaticHeaders=@(),
	[Parameter(HelpMessage="A flag indicate that the HTTP server should log all requests")][Switch]$Logging,
	[Parameter(HelpMessage="A flag indicaing that the HTTP server should require peer credentials to be provided when a TLS session is established")][Switch]$PeerAuthentication,
	[Parameter(HelpMessage="Base URI to use when configuring service URIs mounted on this server")][string]$AccessURI,
	[Parameter(HelpMessage="A set of additional properties for the new IdP endpoint")][Hashtable]$AdditionalProperties = @{}
)
	$properties = @{
        'Name'=$Name;
		'Description'=$Description;
		'Zone'=$Zone;
		'Hostname'=$Hostname;
		'Port'=$Port;
		'CAPath'=$CAPath;
		'UseCORS'=[bool]$UseCors;
		'Logging'=[bool]$Logging;
		'PeerAuthn'=[bool]$PeerAuthentication;
		'StaticHeaders'=$StaticHeaders;
		'CORSAllowedHeaders'= $CorsAllowedHeaders;
		'CORSExposedHeaders'=$CorsExposedHeaders;
	}

	if(-not [String]::IsNullOrEmpty($CertFile)){
		$properties.Add('Keys', [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes((Join-Path $pwd $CertFile))))
	}
	if(-not [String]::IsNullOrEmpty($AccessURI)){
		$properties.Add('AccessURI', $AccessURI)
	}
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType $ODataType -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -AdditionalProperties $AdditionalProperties -Confirm:$false
	}
}

Function New-CobaltODataEndpoint {
[CmdletBinding(SupportsShouldProcess=$True, ConfirmImpact='Medium')]
param (
	[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
    [Parameter(HelpMessage="The OData type of the new entity")][string]$ODataType = 'com.viewds.cobalt.ODataEndpoint',
	[Parameter(Mandatory=$True, HelpMessage="The name of the OData endpoint")][string]$Name,
	[Parameter(Mandatory=$True, HelpMessage="The tenant of the OData endpoint")][string]$Tenant,
	[Parameter(Mandatory=$True, HelpMessage="The name of the property to use as a unique identifier for authentication")][string]$PrincipalAttribute,
	[Parameter(Mandatory=$True, HelpMessage="The zone this OData service is associated with")][string]$Zone,
	[Parameter(HelpMessage="A description of the new OData endpoint")][string[]]$Description = @("New OData endpoint created $(Get-Date)"),
	[Parameter(HelpMessage="The name of the property to determine if an account is enabled for authentication")][string]$EnabledAttribute,
	[Parameter(HelpMessage="Enables fine-grained password policy")][Switch]$Policy,
	[Parameter(Mandatory=$True, HelpMessage="The path to append to the HTTP server path to access the OData endpoint")][string]$Path,
	[Parameter(HelpMessage="Indicates that anonymous access is permitted on this endpoint")][Switch]$AnonymousPermitted,
	[Parameter(HelpMessage="A set of additional properties for the new OData endpoint")][Hashtable]$AdditionalProperties = @{}
)

	$properties = @{
        'Name'=$Name;
		'Description'=$Description;
		'Tenant'=$Tenant;
		'Path'=$Path;
		'Policy'=[bool]$Policy;
		'PrincipalAttribute'=$PrincipalAttribute;
		'Zone'=$Zone;
		'AnonymousPermitted'=[bool]$AnonymousPermitted;
	}
	if(-not [String]::IsNullOrEmpty($EnabledAttribute)){
		$properties.Add('EnabledAttribute', $EnabledAttribute)
	}
    if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType $ODataType -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$false
	}
}

Function Get-CobaltDirectoryService {
	[CmdletBinding()]
	param (
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type of the entity to get")][string]$ODataType = 'com.viewds.cobalt.DirectoryService',
		[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
		[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
		)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function New-CobaltCommandServiceProvider {
	param (
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type of the new entity")][string]$ODataType = 'com.viewds.cobalt.CommandServiceProvider',
		[Parameter(Mandatory=$True, HelpMessage="The IDP endpoint URI for Command to use for authentication")][string]$IDPEndpoint,
		[Parameter(Mandatory=$True, HelpMessage="The OData endpoint URI for Command use for data access")][string]$ODataEndpoint,
		[Parameter(HelpMessage="The operation mode for Command, either CSP or Tenant")][string][ValidateSet('CSP', 'Tenant')]$Mode = 'CSP',
		[Parameter(Mandatory=$True, HelpMessage="The name of the tenant this instance applies to")][string]$Tenant,
		[Parameter(Mandatory=$True, HelpMessage="The name of the zone this instance should run in")][string]$Zone,
		[Parameter(HelpMessage="The name of the Cobalt Command instance")][string]$Name = "Cobalt Command",
		[Parameter(HelpMessage="The description of the Cobalt Command instance")][string[]]$Description = @(),
		[Parameter(Mandatory=$True, HelpMessage="The callback URL for the application")][string[]]$Callback,
		[Parameter(HelpMessage="The encryption algorithm to use")][string]$Algorithm = 'HS256',
		[Parameter(HelpMessage="The application secret")][string]$ClientSecret = (New-Guid).Guid,
		[Parameter(HelpMessage="An array of OAuth scopes for which user consent is assumed")][string[]]$ConsentAssumed = @(),
		[Parameter(HelpMessage="The lifetime in seconds for any security token issued")][int]$Duration = 3600,
		[Parameter(HelpMessage="Don't know")][string[]]$Entity = @(),
		[Parameter(HelpMessage="A JSON-encoded string describing the SAML attribute assertions to be provided with the authentication message")][string[]]$SamlAttributeConsumingService=@(),
		[Parameter(HelpMessage="A flag indicating that the IdP should use the SHA1 hashing algorithm")][Boolean]$UseSHA1 = $False,
		[Parameter(HelpMessage="The name of the external authentication service for Cobalt to use")][string]$AuthMode = 'simple',
		[Parameter(HelpMessage="A flag indicating that the IdP should return errors to the application")][Boolean]$ReturnError = $False,
		[Parameter(HelpMessage="A set of additional properties for the new CommandServiceProvider")][Hashtable]$AdditionalProperties = @{}
	)
	
	if($Mode -eq 'CSP'){
		$Mapping = '1'
	}
	else {
		$Mapping = '2';
	}
	$properties = @{
		'CommandIDPEndpoint'=$IDPEndpoint;
		'CommandODataEndpoint'=$ODataEndpoint;
		'Tenant'=$Tenant;
		'Mapping'=$Mapping;
		'Zone'=$Zone;
	}
	if(-not [String]::IsNullOrEmpty($EnabledAttribute)){
		$properties.Add('EnabledAttribute', $EnabledAttribute)
	}
	$AdditionalProperties.GetEnumerator() | %{if(-not $properties.ContainsKey($_.Key)){$properties.Add($_.Key, $_.Value)}}
	if($PSCmdlet.ShouldProcess("Add new $ODataType to $($Connection.Uri)")){
		New-CobaltEntity -Connection $Connection -Properties $properties -ODataType $ODataType -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent) -Confirm:$false
	}
}

Function Get-CobaltCommandServiceProvider {
	[CmdletBinding()]
	param (
		[Parameter(HelpMessage="The Cobalt connection object to use for the OData operation")][PSObject]$Connection = (Get-DefaultCobaltConnection),
		[Parameter(HelpMessage="The OData type of the entity to get")][string]$ODataType = 'com.viewds.cobalt.CommandServiceProvider',
		[Parameter(HelpMessage="The OData filter string to use")][string]$ODataFilter,
		[Parameter(HelpMessage="The navigation properties to expand")][string[]]$Expand = @()
		)
	Get-CobaltEntities -Connection $Connection -ODataType $ODataType -ODataFilter $ODataFilter -Expand $Expand -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

$script:DefaultPublicKey = @'
{
    'kty'='RSA',
    'alg'='RS256',
    'use'='sig',
    'kid'='468b1763-142a-43da-96e0-53f2b6e1a7ac',
    'n'='AM_U2ExHALTmiq8KLBZC7pKylVyr-r6oZrnwaUxQEMxZ6W8D0j_ijYmtj33qFqLCZ7iiAXC5DFDe96UxqxzAAsXUrqEHkhp2KWOZeXiyi0d-94jhZRLdpv9f_imWH-61d_Wj51XkXBSwUIZiwMYjP9ZeMK0gU5fU4fONBCnrIG6y-fbNSFsTiM-QvWG-KMU88o26XQNK924678_sgpVLYoeuKcEtEdvpNCGamttMMhi2B_vzVxn_dIbpsAGf5GbxCfyKw1w4Y9-bYX7YbV0GW25tjnh2Setfoo0EjImMeSQpXO-FYZgI39tSSF2Gm1d1aFu7bBlGYT9W1HUG3rRgUxs',
    'e'='AQAB'
}
'@

$script:DefaultPrivateKey = @'
{
    'n'='AM_U2ExHALTmiq8KLBZC7pKylVyr-r6oZrnwaUxQEMxZ6W8D0j_ijYmtj33qFqLCZ7iiAXC5DFDe96UxqxzAAsXUrqEHkhp2KWOZeXiyi0d-94jhZRLdpv9f_imWH-61d_Wj51XkXBSwUIZiwMYjP9ZeMK0gU5fU4fONBCnrIG6y-fbNSFsTiM-QvWG-KMU88o26XQNK924678_sgpVLYoeuKcEtEdvpNCGamttMMhi2B_vzVxn_dIbpsAGf5GbxCfyKw1w4Y9-bYX7YbV0GW25tjnh2Setfoo0EjImMeSQpXO-FYZgI39tSSF2Gm1d1aFu7bBlGYT9W1HUG3rRgUxs',
    'e'='AQAB',
    'd'='d5VDo5gTKwOf9pmGxoRam6QP1xPJohxph0FyhQtorvxpGYx8VG_5-qcX8l5YCeyMG6tz4rVHBd1VZwLOLyu4LLZ0iIk_ouQsanercixhgZDnwyXVr2ZEKZrFNo5_7y0RShC2EjDkXq8YlkqKGze7CpCFt4frMWi3XhjctXXp4mckNqeYO_RUwc_kAgQzBY-dIdx10X8v0F8ow9WlwaTjpS9yWaxHNKnMG3miRRc3zv8REx0S7o1CF2XdaBMLylOVINYFqrCEg4bMD57ufDJXwnS-2AkUOIP4Dca6KE6FIiV6Njf8zQhHAJdz17TI5AupmhSfHArNBYgMAOhZRKzzMQ',
    'p'='AP65HcVdQA91UehDLzJdfaZgMsoNUTvjXebtHBspnjavmcOO8Eya4ed3Z-9c3_52DGUS2aVFdfgHJQVMJ6Ium25BOV9FkTng7Jz2t0dpdf1P36CPlRFZ7Eq0hGiCatH_tf-UYsA1FMGhBEooPbP_oyNxC-T7mgbY-IRjXOlcRwtz',
    'q'='ANDfjY--dkrhyypmuqX8hSj89VFTpBbh4gDSJsfy8kCfyTyGjOZgitByoFag6Bd8yeIBNNz9RomMsAsvcsms0ItOgygOi74ZhE5uMH2DTFgH-KlKKE4ZKi7PF7xa-4Rdj5jUBcqUvgm7sJyEC2ZNV6pSwAe4EMCxFDq7ZVXveX-5',
    'dp'='ANn_Y9M9c03Hgknc9c-M47Q4MD9sFlHCzOKNmrhEbfsvXdFXy6BEDYIjVvgr7CfCr-jwsQQY5lVXB__4pRLQAIXjnE5FI3z9WoMbQtADGc-pRCINv-4Rn4Bv7cHjm7gNuJz7SWhmBVWRkDJHLkeWSPBUF3HpQnEJz-a9gw7Uwpix',
    'dq'='AJPgEVrZHup43NtSC4aENsoD_LHtI1jH5rdqEOayS2wRM-lT4OEhLGXTIUzzch1ezZbh_8kMzymGnwPsPbomTSazGQv88FZPvmnAfTf_Ase4LQW9aLeR_VlSaJ2DVFor2wP553e6wqglZy4IFgIBc7U0DJvqZoHlXEsQbPfgKQaR',
    'qi'='ANxvVo0VYRVoboQWQEUQmUeGuCV2daBlIYXYwfEFdmc5mFDcZlrfttMwhIgyvUwXqPxGkMqZei4Q85Tm9Mz59ZkUejBiu6kQ_p6tyoXA0vxYF8DvgC4yXo9RxIMzsw1Ls5m7EwTo8q7bRZu3BDQKkoVRwj4gbIg5l_eSAb6KJmTn'
}
'@

$script:DefaultCACertificate = 'MIIDgTCCAmmgAwIBAgIJAP4CYracDkWdMA0GCSqGSIb3DQEBBQUAMHcxCzAJBgNVBAYTAkFVMTYwNAYDVQQKEy1lTml0aWF0aXZlcy5jb20gUHR5LiBMdGQuLCBBQk4gMTkgMDkyIDQyMiA0NzYxFDASBgNVBAsTC0RldmVsb3BtZW50MRowGAYDVQQDExFWaWV3RFMgVGVzdGluZyBDQTAeFw0xMjA0MDIwMjQ3MjJaFw0yMjAzMzEwMjQ3MjJaMHcxCzAJBgNVBAYTAkFVMTYwNAYDVQQKEy1lTml0aWF0aXZlcy5jb20gUHR5LiBMdGQuLCBBQk4gMTkgMDkyIDQyMiA0NzYxFDASBgNVBAsTC0RldmVsb3BtZW50MRowGAYDVQQDExFWaWV3RFMgVGVzdGluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ9_mORqQ7B2JNjjLTu89RPigZc-It84TpVJ0OuYAjK_UbfD_AUrt37dvMtS_kSZRSqRJXHnLmv3ZPLrCsiE-VGk6FHDtkTB6Y9zZ8Fl47RVCERQq-WZvDBK2H-lHZhRiz7wc_KO8dxfETXB0HOXmT0rSWytymnZaUQkui5NEcQsFjet7RyBL1_uTBbMVnX1M6O5-ZF50wxFi1u8sDVroDEcWhhDleEnbGkP3qatjd5Aw-yH8T5dEhlVGn_dafC72JJ-IxwXGwvbZrIBBmsekZX4NBDLUcXtpPr9-o5eN5sQZRWtbEbzAKFUZyqpxU2Jp7cV6qZ_7OIStE0wBxNy1ykCAwEAAaMQMA4wDAYDVR0TBAUwAwEB_zANBgkqhkiG9w0BAQUFAAOCAQEAZzBKNFIetAsL4NAOfbWTtcmznMZ28Dwmf0YBQ-vz2Zqzrwxfsz38zaclKT0ADVn10WpjWo_ko1filg6CjM5HdsDMUSnKov7o4Rk7izyk1nQmbYXKMk78vj3OrKa4v4FItr3Dbr7KK2ZPP3uykNqdVFK-jf-Pg1AyvDS3I7txOWP30j6jcfFNjOEse4VPE0q3byYCLs7wKGemF9c-TAZ4VZmdWuGDGLf94_2-wrtpiDZ2WqUinQ_osLS1aYTc60mE80EmIlJBz2z1jX1adc8DV3DME0AnWdIymJQyxOQ4qlYJxIQKcdSNgtqJ-XAlqpnLjEKMmw_UagCeJkVEbYnvfg'

$script:DefaultScopes = @(@{
	'Scope'='openid';
	'Claims'=@(@{
	  '@odata.type'='#com.viewds.cobalt.SimpleField';
	  'Name'='sub';
	  'Property'='EntityUUID'
	})
  }, @{
	'Scope'='address';
	'Claims'= @(@{
		'@odata.type'='#com.viewds.cobalt.ComplexField';
		'Name'='address';
		'Fields'=@(@{
			'Name'='formatted';
		}, @{
			'Name'='street_address';
		}, @{
			'Name'='locality';
		}, @{
			'Name'='region';
		}, @{
			'Name'='postal_code';
	  	}, @{
			'Name'='country';
		});
	});
  }, @{
	'Scope'='email';
	'Claims'=@(@{
	  '@odata.type'='#com.viewds.cobalt.SimpleField';
	  'Name'='email';
	  'Property'='Email';
	}, @{
	  'Name'='email_verified';
	})
  }, @{
	'Scope'='phone';
	'Claims'=@(@{
	  '@odata.type'='#com.viewds.cobalt.SimpleField';
	  'Name'='phone_number';
	  'Property'='TelephoneNumber';
	}, @{
	  'Name'='phone_number_verified';
	})
  }, @{
	'Scope'='profile';
	'Claims'=@(@{
	  '@odata.type'='#com.viewds.cobalt.SimpleField';
	  'Name'='name';
	  'Property'='DisplayName';
	}, @{
	  '@odata.type'='#com.viewds.cobalt.SimpleField';
	  'Name'='family_name';
	  'Property'='Surname';
	}, @{
	  '@odata.type'='#com.viewds.cobalt.SimpleField';
	  'Name'='given_name';
	  'Property'='GivenName';
	}, @{
	  'Name'='middle_name';
	}, @{
	  'Name'='nickname';
	}, @{
	  '@odata.type'='#com.viewds.cobalt.SimpleField';
	  'Name'='preferred_username';
	  'Property'='Email';
	}, @{
	  'Name'='profile';
	}, @{
	  'Name'='picture';
	}, @{
	  'Name'='website';
	}, @{
	  'Name'='gender';
	}, @{
	  'Name'='birthdate';
	}, @{
	  'Name'='zoneinfo';
	}, @{
	  'Name'='locale';
	}, @{
	  'Name'='updated_at';
	})
  })
