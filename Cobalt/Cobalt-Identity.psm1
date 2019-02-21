Function Get-CobaltOIDCConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(HelpMessage="The Cobalt connection object to use to retrieve configuration data (not for authentication)")][PSObject]$Connection = (Get-DefaultCobaltConnection),
        [Parameter(HelpMessage="The EntityUUID of the IdP to authentication with. If not specified, the command will pick one")][System.Guid]$IDPId
    )

    if($IDPId -eq $null){
        $IDP = (Get-CobaltIDPEndpoint -Connection $Connection | Select-Object -First 1)
        if($null -eq $IDP){
            Throw "Could not find an IDP Endpoint to authenticate with"
        }
    }
    $URI = [URI]($Connection.Uri)
    $IDPEndpoint = $URI.AbsoluteUri.Remove($URI.AbsoluteUri.IndexOf($URI.AbsolutePath)) + $IDP.Path
    if($IDPEndpoint.Length -eq 0){
        Throw "Error creating IDP endpoint URI"
    }
    $IDPEndpoint = $IDPEndpoint.TrimEnd('/')

    $OpenIDConfig = Invoke-RestMethod -Uri "$IDPEndpoint/.well-known/openid-configuration"
    if($null -eq $OpenIDConfig){
        Throw "Unable to retrieve $IDPEndpoint/.well-known/openid-configuration"
    }
    $OpenIDConfig
}

Function Get-CobaltAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(HelpMessage="The Cobalt connection object to use to retrieve configuration data (not for authentication)")][PSObject]$Connection = (Get-DefaultCobaltConnection),
        [Parameter(HelpMessage="The credentials to use to authenticate")][PSCredential]$Credential = (Get-Credential -Username "" -Message "Enter username and password for access token"),
        [Parameter(HelpMessage="The EntityUUID of the IdP to authentication with. If not specified, the command will pick one")][System.Guid]$IDPId,
        [Parameter(HelpMessage="The EntityUUID of the application to authenticate with. If not specified, the command will pick one")][System.Guid]$SPId
    )

    if($null -eq $Credential -or $null -eq $Credential.UserName){
        Throw "You must provide a username and password to authenticate with"
    }

    if($null -eq $IDPId){
        $IDP = (Get-CobaltIDPEndpoint -Connection $Connection | Select-Object -First 1)
        if($null -eq $IDP){
            Throw "Could not find an IDP Endpoint to authenticate with"
        }
        Write-Verbose "IDPEndpoint...`n$($IDP | ConvertTo-JSON -Depth 6)"
    }
    if($null -eq $SPId){
        $SP = (Get-CobaltServiceProvider -Connection $Connection | Select-Object -First 1)
        if($null -eq $SP){
            Throw "Could not find an ServiceProvider to authenticate with"
        }
        Write-Verbose "ServiceProvider...`n$($SP | ConvertTo-JSON -Depth 6)"
    }

    # Compose the full path of the IDP using the OData URI minus the 'tenant/odata' part
    $URI = [URI]($Connection.Uri)
    $IDPEndpoint = $URI.AbsoluteUri.Remove($URI.AbsoluteUri.IndexOf($URI.AbsolutePath)) + $IDP.Path
    if($IDPEndpoint.Length -eq 0){
        Throw "Error creating IDP endpoint URI"
    }
    $IDPEndpoint = $IDPEndpoint.TrimEnd('/')

    $OpenIDConfig = Invoke-RestMethod -Uri "$IDPEndpoint/.well-known/openid-configuration"
    if($null -eq $OpenIDConfig){
        Throw "Unable to retrieve $IDPEndpoint/.well-known/openid-configuration"
    }
    Write-Verbose "IDP metadata...`n$($OpenIDConfig | ConvertTo-JSON)"

    $Password = $Credential.GetNetworkCredential().password
    $AuthNRequest = "client_id=$([System.Web.HttpUtility]::UrlEncode($SP.EntityUUID))" +
        "&redirect_uri=$([System.Web.HttpUtility]::UrlEncode($SP.Callback[0]))" +
        "&response_type=code token id_token" +
        "&scope=openid" +
        "&state=$([System.Web.HttpUtility]::UrlEncode([System.Guid]::NewGuid().Guid))" +
        "&nonce=$([System.Web.HttpUtility]::UrlEncode([System.Guid]::NewGuid().Guid))" +
        "&username=$($Credential.UserName)" +
        "&password=$Password"

    Write-Verbose "Authentication URI...`n$AuthNRequest"
    $Session = $null
    $Response = Invoke-WebRequest -URI $OpenIDConfig.authorization_endpoint -Method Post -Body $AuthNRequest -SessionVariable 'Session' -MaximumRedirection 0 -ErrorAction Ignore -ContentType "application/x-www-form-urlencoded" -UseBasicParsing
    if($Response.StatusCode -ne 302){
        Write-Output $Response
        Throw "Expected 302 redirect from login request and got $($Response.StatusCode) instead."
    }

    Write-Verbose "Redirect URI...`n$($Response.Headers["Location"])"
    # The access token is provided as query parameter in the Location URI
    $ApplicationLoginURI = New-Object -TypeName 'System.URI' -ArgumentList ($Response.Headers["Location"])
    if($ApplicationLoginURI.Fragment -notmatch '(#|&)access_token=(?<token>([^&]*))'){
        Throw "Unexpected application redirect URI"
    }
    $Token = $Matches.token
    $Token
}
