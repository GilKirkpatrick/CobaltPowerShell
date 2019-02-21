#
# Module manifest for module 'Cobalt'
#
# Generated by: Gil
#
# Generated on: 5 Oct 2016
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'Cobalt-Base.psm1'

# Version number of this module.
ModuleVersion = '1.0'

# ID used to uniquely identify this module
GUID = 'b7d45746-3d3f-427d-8191-ef1272d4cdb7'

# Author of this module
Author = 'Gil Kirkpatrick'

# Company or vendor of this module
CompanyName = 'ViewDS Identity Solutions'

# Copyright statement for this module
Copyright = '(c) 2016 eNitiatives.com Pty. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Provides PowerShell commands for access Cobalt identity data'

# Minimum version of the Windows PowerShell engine required by this module
# PowerShellVersion = ''

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
#RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @('Cobalt-Connection.psm1', 'Cobalt-Metadata.psm1', 'Cobalt-TenantManagement.psm1', 'Cobalt-ServiceManagement.psm1', 'Cobalt-Identity.psm1')

# Functions to export from this module
FunctionsToExport = @(
	# Cobalt connection operations
	'New-CobaltConnection',
	'Read-CobaltConnection',
	'Write-CobaltConnection',
	'Set-DefaultCobaltConnection',
	'Get-DefaultCobaltConnection',
	# Cobalt-Base functions
	'Get-CobaltProperty',
	'Invoke-CobaltQuery',
	'Get-CobaltEntity',
	'Get-CobaltEntities',
	'Set-CobaltCheckSSL',
	'Set-CobaltProperty',
	'Get-CobaltSubtree',
	'New-CobaltEntity',
	'Remove-CobaltEntity',
	'Convert-CredentialToAuthHeader',
	'Convert-ArrayProperties',
	'ConvertTo-CanonicalODataType',
	'Invoke-CobaltAction',
	'Invoke-CobaltFunction',
    # Cobalt-Metadata functions
	'Get-CobaltMetadataType',
	'Get-CobaltMetadataProperty',
	'Get-CobaltMetadataFunction',
	'Get-CobaltMetadataAction',
	'Get-CobaltMetadataNavigationProperty',
	'New-CobaltMetadataType',
	'Remove-CobaltMetadataType',
	'New-CobaltMetadataProperty', 
	'New-CobaltMetadataNavigationProperty',
	'Add-CobaltMetadataProperty', 
	'Add-CobaltMetadataNavigationProperty', 
	'Remove-CobaltMetadataProperty',
	# Cobalt-TenantManagement functions
	'Get-CobaltServiceProvider',
	'New-CobaltServiceProvider',
    # 'Get-CobaltConfigurationContainer',
	# 'Get-CobaltConfiguration',
	'Get-CobaltHTTPServer',
	'New-CobaltHTTPServer',
	'Get-CobaltUser',
	'New-CobaltUser',
	'Get-CobaltStaticContentEndpoint',
	'New-CobaltStaticContentEndpoint',
    'Get-CobaltODataEndpoint',
    'New-CobaltODataEndpoint',
    'Get-CobaltIDPEndpoint',
	'New-CobaltIDPEndpoint',
	'New-CobaltTemplate',
	'Get-CobaltTemplate',
	'New-NewCobaltIDPEndpoint',
	'Get-CobaltDatastoreContainer',
	'New-CobaltDatastoreContainer',
	'Get-CobaltTenant',
	'New-CobaltTenant',
	'Get-CobaltZone',
	'New-CobaltZone',
	# 'Get-CobaltTemplate',
	# 'New-CobaltTemplate',
	# 'Get-CobaltDataModel', 
	'Get-CobaltDirectoryService',
    'Get-CobaltAccessPolicy',
	'New-CobaltAccessPolicy',
	'New-CobaltRule',
	'Get-CobaltPasswordPolicy',
	'New-CobaltPasswordPolicy',
	'New-CobaltAuditPolicy',
	'Get-CobaltAuditPolicy',
	'New-CobaltCommandServiceProvider',
	'Get-CobaltCommandServiceProvider',
    # 'Get-CobaltScheduleService',
	# 'New-CobaltScheduleService',
    # 'Get-CobaltScheduleEntry',
	# 'New-CobaltScheduleEntry',
	'Get-CobaltRole',
	'New-CobaltRole',
	'Get-CobaltApplicationEntitlementPolicy',
	'New-CobaltApplicationEntitlementPolicy',
	'Get-CobaltOrganization',
	'New-CobaltFileLoggingService',
	'Get-CobaltFileLoggingService',
	'New-CobaltCEFLoggingService',
	'Get-CobaltCEFLoggingService',
	'Get-CobaltAccessToken',
	'Get-CobaltOIDCConfiguration',
	'Get-CobaltAccessToken',
	'Find-OrCreateIdentityProvider',
	'Test-OrAddMetadata',
	'Find-OrCreateServiceProvider',
	'Find-OrCreateTestUser'

    )

# Cmdlets to export from this module
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = ''

# Aliases to export from this module
AliasesToExport = ''

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
ModuleList = @()

# List of all files packaged with this module
FileList = @('Cobalt-Connection.psm1', 'Cobalt-Base.psm1', 'Cobalt-Metadata.psm1', 'Cobalt-TenantManagement.psm1', 'Cobalt-Identity.psm1')

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        # ProjectUri = ''

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

