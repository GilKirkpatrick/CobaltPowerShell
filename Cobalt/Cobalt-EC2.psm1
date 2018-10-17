Function New-CobaltEnvironment {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True, HelpMessage="The name of the new Cobalt environment to create")][string]$EnvName
	)

	$EnvName += " - created $([DateTime]::Now.ToString())"
	#TODO: Figure out how to set the name of the VPC

	$vpc = New-EC2Vpc -CidrBlock '10.0.0.0/28' -InstanceTenancy default
	if($vpc -eq $null){
		Throw "Could not create VPC"
	}
	Write-Verbose "Created new VPC with id: $($vpc.VpcId)"

	# Create internet gateway for vpc
	$gateway = New-EC2InternetGateway
	if($gateway -eq $null){
		Throw "Could not create internet gateway"
	}
	Write-Verbose "Created new internet gateway with id: $($gateway.InternetGatewayId)"
	[void](Add-EC2InternetGateway -VpcId $vpc.VpcId -InternetGatewayId $gateway.InternetGatewayId)
	
	# Create route in VPC default route table
	$vpcFilter = @(,@{'name'='vpc-id';'values'=$vpc.VpcId})
	$routeTable = Get-EC2RouteTable -Filter $vpcFilter
	Write-Verbose "Route table: $($routeTable.RouteTableId)"
	[void](New-EC2Route -RouteTableId $routeTable.RouteTableId -DestinationCidrBlock '0.0.0.0/0' -GatewayId $gateway.InternetGatewayId)
	
	# Create subnet for the VPC and associate with the route table
	$subnet = New-EC2Subnet -VpcId $vpc.VpcId -CidrBlock '10.0.0.0./28'
	if($subnet -eq $null){
		Throw "Could not create subnet for VPC $($vpc.VpcId)"
	}
	Write-Host "Subnet: $($subnet.SubnetId)"
	$subnet.MapPublicIpOnLaunch = $true

	# Get the default security group
	$securityGroup = Get-EC2SecurityGroup $vpcFilter
	if($securityGroup -eq $null){
		Throw "Could not retrieve default security group for VPC $($vpc.VpcId)"
	}
	Write-Host "Security group: $($securityGroup.groupId)"
	
	Grant-EC2SecurityGroupIngress -GroupId $groupId -IpPermissions @{IpProtocol = “tcp”; FromPort = 80; ToPort = 65535; IpRanges = @(“0.0.0.0/0”)}
	Grant-EC2SecurityGroupIngress -GroupId $groupId -IpPermissions @{IpProtocol = “tcp”; FromPort = 8080; ToPort = 65535; IpRanges = @(“0.0.0.0/0”)}
	Grant-EC2SecurityGroupIngress -GroupId $groupId -IpPermissions @{IpProtocol = “tcp”; FromPort = 22; ToPort = 65535; IpRanges = @(“0.0.0.0/0”)}
	Grant-EC2SecurityGroupIngress -GroupId $groupId -IpPermissions @{IpProtocol = “tcp”; FromPort = 7070; ToPort = 65535; IpRanges = @(“0.0.0.0/0”)}
	
# Create master centos host with connection to subnet
# Create shadow centos host 
# Create administrative tenant
# 
}

Function New-CobaltCentosHost {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True, HelpMessage="The Name tag to associate with this instance")][string]$Name,
		[Parameter(HelpMessage="The id of the AMI to use")][string]$AmiId = 'ami-4bc13733',
		[Parameter(HelpMessage="The name of the key to use")][string]$KeyName = 'gilk-viewds-ec2',
		[Parameter(Mandatory=$True, HelpMessage="The id of the subnet to connect the new instance to")][string]$SubnetId,
		[Parameter(Mandatory=$True, HelpMessage="The id of the EC2 security group to associate with this instance")][string]$SecurityGroupId,
		[Parameter(HelpMessage="The instance type to provision")][string]$InstanceType = 't2.micro'
	)

	try {
		#$networkInterface = New-EC2NetworkInterface -SubnetId $subnetId -Description 'Primary network interface'
		#$interfaceSpec = New-Object Amazon.EC2.Model.InstanceNetworkInterfaceSpecification -property @{'NetworkInterfaceId'=$networkInterface.NetworkInterfaceId}

		$reservation = New-EC2Instance -ImageId $AmiId -MinCount 1 -MaxCount 1 -ProfileName 'CobaltAdminPoSh' -SecurityGroupId $SecurityGroupId -InstanceType $InstanceType -KeyName $KeyName -AssociatePublicIp $True -SubnetId $SubnetId
		$id = $reservation.Instances[0].InstanceId
		while((Get-EC2Instance -InstanceId $id).Instances[0].State.Name.Value -ne 'running'){
			Start-Sleep -Seconds 5
			Write-Verbose "Waiting for instance $id to change state to running"
		}

		if([string]::IsNullOrEmpty($Name)) {
			$Name = 'Created by New-CobaltCentosHost PowerShell command'
		}

		New-EC2Tag -Resource $id -Tag @{'key'='Name';'value'=$Name}
		$dnsName = (Get-EC2Instance -InstanceId $id).Instances[0].PublicDnsName
		Write-Verbose "Created EC2 instance $dnsName"
	}
	catch {
		Write-Error "Error creating EC2 instance. $_"
		Throw $_
	}
	return $dnsName
}

Function New-CobaltSshConnection {
[CmdletBinding()]
param (
	[Parameter(Mandatory=$True, HelpMessage="The DNS name of the host to create a connection with")][string]$Name,
	[Parameter(Mandatory=$False, HelpMessage="The Linux account name to authenticate the session with")][string]$User
)
	if([string]::IsNullOrEmpty($User)){
		$User = 'centos'
	}
	$creds = New-Object PSCredential -ArgumentList ([pscustomobject] @{
		UserName = $User
		Password = (ConvertTo-SecureString -AsPlainText -Force -String 'dirtcolliereesesskytraindredge')[0]
	})
	New-SSHSession -ComputerName $Name -KeyFile 'C:\Users\Gil\OneDrive\Keys\gil@gilkirkpatrick.com-ec2.openssh' -Credential $creds -ConnectionTimeout 20
}

Function Remove-Firewall {
param (
	[Parameter(Mandatory=$True)]$Session
)
	try {
		Invoke-CobaltSSHCommand -SSHSession $Session -Command 'sudo yum list installed firewalld' -Expect '' -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	}
	catch {
		Invoke-CobaltSSHCommand -SSHSession $Session -Command 'sudo yum -y autoremove firewalld' -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	}
}

Function Update-Yum {
param (
	[Parameter(Mandatory=$True)]$Session
)
	Invoke-CobaltSSHCommand -SSHSession $Session -Command 'yum -y install deltarpm' -ExpectExact 'Loaded plugins: fastestmirror' -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	Invoke-CobaltSSHCommand -SSHSession $Session -Command 'yum list | grep deltarpm' -ExpectContains 'deltarpm.x86_64' -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	Invoke-CobaltSSHCommand -SSHSession $Session -Command 'yum update' -ExpectExact 'Loaded plugins: fastestmirror' -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	Invoke-CobaltSSHCommand -SSHSession $Session -Command 'yum -y install net-tools bind-utils lsof vim-enhanced' -ExpectExact 'Loaded plugins: fastestmirror' -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	Invoke-CobaltSSHCommand -SSHSession $Session -Command 'yum -y install yum-utils' -ExpectExact 'Loaded plugins: fastestmirror' -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	Invoke-CobaltSSHCommand -SSHSession $Session -Command 'shutdown -r now' -ExpectExact '' -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function Install-Docker {
param (
	[Parameter(Mandatory=$True)]$Session
)
	Invoke-CobaltSSHCommand -SSHSession $Session -Command 'yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo' -Sudo -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	Invoke-CobaltSSHCommand -SSHSession $Session -Command 'yum -y install docker-ce' -Sudo -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	Invoke-CobaltSSHCommand -SSHSession $Session -Command 'systemctl enable docker.service' -Sudo -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	Invoke-CobaltSSHCommand -SSHSession $Session -Command 'systemctl start docker.service' -Sudo -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	Invoke-CobaltSSHCommand -SSHSession $Session -Command 'curl -L git.io/weave -o /usr/local/bin/weave' -Sudo -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	Invoke-CobaltSSHCommand -SSHSession $Session -Command 'chown root:docker /usr/local/bin/weave' -Sudo -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
	Invoke-CobaltSSHCommand -SSHSession $Session -Command 'chmod 754 /usr/local/bin/weave' -Sudo -Verbose:([bool]$PSBoundParameters['Verbose'].IsPresent)
}

Function Invoke-CobaltSSHCommand {
[CmdletBinding(DefaultParameterSetName="Ignore")]
param (
	[Parameter(Mandatory=$True, HelpMessage="The SSHSession object to send the command to")]$SSHSession,
	[Parameter(Mandatory=$True, HelpMessage="The command to send")]$Command,
	[Parameter(Mandatory=$False, HelpMessage="Ignore the returned exist status")][Switch]$IgnoreExitStatus,
	[Parameter(ParameterSetName="Exact", Mandatory=$True, HelpMessage="A string that should be returned")]$ExpectExact,
	[Parameter(ParameterSetName="Like", Mandatory=$True, HelpMessage="A string that should be contained in the returned string")]$ExpectLike,
	[Parameter(ParameterSetName="Pattern", Mandatory=$True, HelpMessage="A regex pattern that the returned string should match")]$ExpectPattern,
	[Parameter(ParameterSetName="Ignore", HelpMessage="Ignore the results returned from the command")][switch]$Ignore,
	[Parameter(Mandatory=$False, HelpMessage="Write the output of the command to the pipeline")][Switch]$Output,
	[Parameter(Mandatory=$False, HelpMessage="Issue the command using sudo")][Switch]$Sudo
)
	Write-Verbose "Sending command '$Command'"
	if($Sudo) {
		# This is a bit of a mystery as to why this is necessary, particularly when no password is required.
		$stream = $SSHSession.Session.CreateShellStream("cobalt-sudo", 0, 0, 0, 0, 1024)
		$stream.Read() # flush the logon message and prompt
		$stream.WriteLine('sudo ' + $Command)
		$r = New-Object PSCustomObject -Property @{'ExitStatus'=0; 'Output'=@()}
		do {
			$line = $stream.ReadLine([TimeSpan]::FromSeconds(1))
			if($line -ne $null){
				$r.Output += $line
				Write-Verbose("Output line: $line")
			}
		} while($line -ne $null)
	}
	else {
		$r = Invoke-SSHCommand -SSHSession $SSHSession -Command $Command
	}
	if(-not $IgnoreExitStatus -and ($r.ExitStatus -ne 0)) {
		Throw "ExitStatus '$($r.ExistStatus)' not zero"
	}
	Write-Verbose "Exit status '$($r.ExitStatus)'. Output was '$([string]::Join("`n", $r.Output))'"
	if($PSCmdlet.ParameterSetName -eq 'Exact') {
		Write-Verbose "Comparing output exactly to '$ExpectExact'"
		if($r.Output -ne $ExpectExact) {
			Throw "Result '$($r.Output)' does not equal expected '$ExpectExact'"
		}
	} elseif($PSCmdlet.ParameterSetName -eq 'Like') {
		Write-Verbose "Comparing output to '$ExpectLike'";
		$success = $false
		$r.Output | %{if($_ -like $ExpectLike) {$success = $true; break;}}
		if($success -eq $false) {
			Throw "Result '$($r.Output)' is not like expected '$ExpectLike'"
		}
	} elseif($PSCmdlet.ParameterSetName -eq 'Pattern') {
		Write-Verbose "Matching output to '$ExpectPattern'"
		$resultString = [string]::Join('`n', $r.Output)
		if($resultString -notmatch $ExpectPattern) {
			Throw "Result '$($r.Output)' does not match expected '$ExpectPattern'"
		}
	}
	if($Output) {
		$r.Output | %{$_}
	}
}