# CobaltPowerShell

PowerShell commands for managing the ViewDS Cobalt identity platform

Cobalt is a modern multi-tenant identity platform built using a microservice architecture and an API-first design. These PowerShell allow you to manage all aspects of Cobalt from the PowerShell command prompt.

## Installation

The Cobalt PowerShell commands are implemented as a PowerShell script module. Once you've cloned the repository, simply set your $PSModulePath environment variable to include the ~/CobaltPowerShell/Cobalt directory.

## Quick Start

Assuming you have an instance of Cobalt set up and running with at least a management tenant, run the following:

    PS> Set-DefaultCobaltConnection -Uri "http://yourhost:8080/whateveryourtenantis/odata" -Credential Get-Credential

When prompted, enter in the initial administrator username and password.

    PS> Get-CobaltEntities

should list all of the entities you have access to.

    PS> Get-CobaltUser -ODataFilter "Username eq 'someusername'"

should retrieve the user entity with Username property equal to "someusername".

    PS> Get-CobaltUser -ODataFilter "Username eq 'someusername'" | Set-CobaltProperty -PropertyName GivenName -PropertyValue Jane

will set the GivenName property of that user to "Jane".

    PS> Get-CobaltUser -ODataFilter "Username eq 'someusername'" | Remove-CobaltEntity

will delete that user.

## Connections

All of the Cobalt PowerShell commands use the notion of a "connection". A connection is simply an OData URI and a set of credentials to use with that URI. The credentials can be either a username and password (stored in a PowerShell PSCredential object) or an OpenID Connect access token obtained through a separate authentication process. In addition, almost all of the commands can use a "default" Cobalt connection. Each PowerShell session can have one default connection, and you use the Set-DefaultCobaltConnection command to set it.
You can also save Cobalt connections in the file system using Write-CobaltConnection and retrieve them using Read-CobaltConnection. This provides a lot of flexibility in managing multiple Cobalt tenants. The following are the connection management commands:

* New-CobaltConnection
* Read-CobaltConnection
* Write-CobaltConnection
* Set-DefaultCobaltConnection
* Get-DefaultCobaltConnection

## Generic commands

While Cobalt provides entity type-specific commands for creating new entities and searching for existing entities, there are a set of commands that you use to manage any type of Cobalt entity without regard to the entity type. And if you want to modify or delete an existing Cobalt entity, you always use the appropriate generic command.

* Invoke-CobaltQuery
* Get-CobaltEntities
* Get-CobaltEntity
* Get-CobaltProperty
* Set-CobaltProperty
* Remove-CobaltEntity

## Metadata (schema) commands

Each Cobalt directory (OData) service has a fully configurable schema (OData uses the term 'metadata'). You can use the Cobalt metadata commands to inspect and modify the Cobalt schema.

* New-CobaltMetadataProperty
* Add-CobaltMetadataProperty
* New-CobaltMetadataNavigationProperty
* Add-CobaltMetadataNavigationProperty
* New-CobaltMetadataType
* Get-CobaltMetadataProperty
* Get-CobaltMetadataNavigationProperty
* Get-CobaltMetadataType
* Get-CobaltMetadataFunction
* Get-CobaltMetadataAction
* Remove-CobaltMetadataType
* Remove-CobaltMetadataProperty

## Functions and Actions

Cobalt defines a set of functions and actions, e.g. to reset a user's password. You invoke these using

* Invoke-CobaltAction
* Invoke-CobaltFunction

## Service Management Commands

There are typically at least two separate tenants in a Cobalt environment, the management tenant (sometimes called the CSP tenant) and one or more customer tenants. All of the service configuration information lives in the management tenant, and each type of tenant has a directory containing users, policies, templates and so forth.

* New-CobaltHTTPServer
* Get-CobaltHTTPServer
* New-CobaltIdPEndpoint
* Get-CobaltIdpEndpoint
* New-CobaltODataEndpoint
* Get-CobaltODataEndpoint
* New-CobaltStaticContentEndpoint
* Get-CobaltStaticContentEndpoint

## Template Management Commands

Each Cobalt identity provider service can present various web pages to the user, including login, password change, consent management, and so on. Each of these pages is defined using an MVEL2 template that you can manage using these commands.

* New-CobaltTemplate
* Get-CobaltTemplate

## User Management Commands

Use the following commands to manage user entities in a Cobalt directory:

* New-CobaltUser
* Get-CobaltUser

## Access Policy and Role Management Commands

These Cobalt PowerShell commands manage access controls, roles, application entitlements, and password policies.

* New-CobaltRole
* Get-CobaltRole
* New-CobaltAccessPolicy
* Get-CobaltAccessPolicy
* New-CobaltApplicationEntitlementPolicy
* Get-CobaltApplicationEntitlementPolicy
* New-CobaltPasswordPolicy
* Get-CobaltPasswordPolicy
* New-CobaltRule

## Application Management Commands

Cobalt allows applications to use its authentication services (OpenID Connect, OAuth, SAML, PKI and so on). You manage these applications within Cobalt using the following commands:

* New-CobaltServiceProvicer
* Get-CobaltServiceProvider

## Tenant Management Commands

* New-CobaltTenant
* Get-CobaltTenant
* New-CobaltDirectoryService
* Get-CobaltDirectoryService

## Host and container management commands

Cobalt runs as a set of clustered containers running on host machines running Docker. You manage and configure these using the following commands.

* New-CobaltDatastoreContainer
* Get-CobaltDataStoreContainer
* New-CobaltServicesContainer
* Get-CobaltServicesContainer
* New-CobaltServiceHost
* Get-CobaltServiceHost
