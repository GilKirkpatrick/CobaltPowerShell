Function New-CobaltConnection {
param(
    [Parameter(Mandatory=$True, HelpMessage="The OData URI actions on this connection will be sent to")][string]$Uri,
    [Parameter(ParameterSetName="Credential", HelpMessage="The credentials to use on this connection")][PSCredential]$Credential,
    [Parameter(ParameterSetName="Token", HelpMessage="The access token to use on this connection")][string]$AccessToken,
    [Parameter(HelpMessage="Switch indicating whether to check SSL certificates when establishing this connection")][Switch]$CheckSSL
)

    if($Uri.EndsWith('/')) { # Remove trailing slash if present
        $Uri = $Uri.Remove($Uri.Length - 1)
    }
    New-Object -TypeName PSObject -Property @{
        'Uri'=$Uri;
        'Credential'=$Credential;
        'CheckSSL'=[Boolean]$CheckSSL;
        'Password'=$null;
        'AccessToken'=$AccessToken;
    }
}

Function Read-CobaltConnection {
[CmdletBinding()]
param(
    [Parameter(Mandatory=$True, HelpMessage="The file path to read the connection from")][string]$FilePath
)
    $Connection = (Get-Content -Path $FilePath) | ConvertFrom-Json
    if($Connection.Uri -eq $null){
        Throw "No Uri present in connection"
    }
    if($Connection.Credential -eq $null){
        if([String]::IsNullOrEmpty($Connection.AccessToken)){
            Throw "No credential and no access token in connection"
        }
    }
    else {
        if($Connection.Credential.UserName -eq $null -or $Connection.Password -eq $null){
            Throw "Invalid credential in connection"
        }
        $SecurePassword = ConvertTo-SecureString -String $Connection.Password
        $Connection.Credential = New-Object -TypeName 'PSCredential' ($Connection.Credential.UserName, $SecurePassword)
        $Connection.Password = $null
    }

    $Connection
}

Function Write-CobaltConnection {
[CmdletBinding()]
param (
    [Parameter(Mandatory=$True, HelpMessage="The name of the file to save the connection information in")][string]$FilePath,
    [Parameter(Mandatory=$True, HelpMessage="The Cobalt connection object to write to file")][PSObject]$Connection
)
    $Connection.Password = ConvertFrom-SecureString -SecureString $Connection.Credential.Password
    $Connection | ConvertTo-JSON | Out-File $FilePath
}

Function Set-DefaultCobaltConnection {
[CmdletBinding()]
param (
    [Parameter(ParameterSetName="CommandCred", Mandatory=$True, HelpMessage="The OData URI to use by default to connect to Cobalt if no URI is specified")]
    [Parameter(ParameterSetName="CommandToken")][string]$Uri,
    [Parameter(ParameterSetName="CommandCred", Mandatory=$true, HelpMessage="The credentials to use by default to connect to Cobalt if no credentials are specified")][PSCredential]$Credential,
    [Parameter(ParameterSetName="CommandToken", Mandatory=$true, HelpMessage="The access token returned from a previous authentication operation")][string]$AccessToken,
    [Parameter(ParameterSetName="CommandCred", HelpMessage="Flag indicating whether to check SSL certificates when connecting to OData service, `$True = check certs, `$False = ignore untrusted certs")]
    [Parameter(ParameterSetName="CommandToken")][Switch]$CheckSSL,
    [Parameter(ParameterSetName="File", Mandatory=$True, HelpMessage="The name of the file containing the previously saved connection information")][string]$FilePath,
    [Parameter(ParameterSetName="Connection", Mandatory=$True, HelpMessage="The Cobalt connection object to use as the default connection")][PSObject]$Connection
)
    # Save the specified URI and credentials for use by other cmdlets
    if($PsCmdlet.ParameterSetName -eq 'CommandCred') {
        $global:_DefaultCobaltConnection = New-CobaltConnection -Uri $Uri -Credential $Credential -CheckSSL:([bool]$PSBoundParameters['CheckSSL'].IsPresent)
    }
    elseif($PsCmdlet.ParameterSetName -eq 'CommandToken'){
        $global:_DefaultCobaltConnection = New-CobaltConnection -Uri $Uri -AccessToken $AccessToken -CheckSSL:([bool]$PSBoundParameters['CheckSSL'].IsPresent)
    }
    elseif($PsCmdlet.ParameterSetName -eq 'File') {
        $global:_DefaultCobaltConnection = Read-CobaltConnection -FilePath $FilePath
    }        
    elseif($PsCmdlet.ParameterSetName -eq 'Connection') {
        $global:_DefaultCobaltConnection = $Connection
    }
    Write-Verbose "Default Uri: $($global:_DefaultCobaltConnection.Uri)"
    Write-Verbose "Default Username: $($global:_DefaultCobaltConnection.Credential.UserName)"
    Write-Verbose "Access token: $($global:_DefaultCobaltConnection.AccessToken)"
    Write-Verbose "Default CheckSSL: $($global:_DefaultCobaltConnection.CheckSSL)"
    [Console]::Title = "Cobalt $($global:_DefaultCobaltConnection.Uri) ($($global:_DefaultCobaltConnection.Credential.UserName))"
}

Function Get-DefaultCobaltConnection {
    return $global:_DefaultCobaltConnection;
}
    
Function Set-CobaltCheckSSL {
[CmdletBinding()]
param(
    [Parameter(Mandatory=$True,HelpMessage="Flag indicating whether to check SSL certificates when connecting to OData service, `$True = check certs, `$False = ignore untrusted certs")][Boolean]$Flag
)
    Write-Verbose "Setting Check SSL flag to $Flag"

    if ($Flag -eq $False) {
        add-type @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy {
                public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                    return true;
                }
            }
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }
    else {
        # Not entirely sure this works
        [System.Net.ServicePointManager]::CertificatePolicy = $null
    }
}

