# CobaltPowerShell
PowerShell commands for managing the ViewDS Cobalt identity platform

Cobalt is a modern multi-tenant identity platform built using a microservice architecture and an API-first design. These PowerShell allow you to manage all aspects of Cobalt from the PowerShell command prompt.

## Connections
All of the Cobalt PowerShell commands use the notion of a "connection". A connection is simply an OData URI and a set of credentials to use with that URI. The credentials can be either a username and password (stored in a PowerShell PSCredential object) or an OpenID Connect access token obtained through a separate authentication process. In addition, almost all of the commands can use a "default" Cobalt connection. Each PowerShell session can have one default connection, and you use the Set-DefaultCobaltConnection command to set it.
You can also save Cobalt connections in the file system using Write-CobaltConnection and retrieve them using Read-CobaltConnection. This provides a lot of flexibility in managing multiple Cobalt tenants. The following are the connection management commands:
* New-CobaltConnection
* Read-CobaltConnection
* Write-CobaltConnection
* Set-DefaultCobaltConnection
* Get-DefaultCobaltConnection

## Generic commands
There are a set of commands that you use to manage any type of Cobalt entity
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

## Service and Tenant Management Commands
There are typically at least two separate tenants in a Cobalt environment, the management tenant (sometimes called the CSP tenant) and one or more customer tenants. All of the service configuration information lives in the management tenant, and each type of tenant has a directory containing users, policies, templates and so forth.

There are commands for creating new services in Cobalt
## Configuration and Data Management Commands
