<#
This script is design for a lab environment using the root domain (not a child domain) and the ActiveDirectory Module
must already exist. If you execute this PowerShell script from a domain controller the Module will already exist.
#>

## Import the CSV File. This will request the user to input the location of the file.
$Content = Get-Content (Read-Host "Enter the path the ActiveDirectoryConfig CSV file: ") 
$ADConfig = ConvertFrom-Csv $Content

## Get the default Root domain configuration details
$DNSRoot = (Get-ADDomain).DNSRoot
$DNRoot = (Get-ADDomain).DistinguishedName

## Set the DN of the Groups and Users to be created 
ForEach ($Param in $ADConfig){
    If ($Param.BaseDNGroups){$GroupDN = $Param.BaseDNGroups}
    If ($Param.BaseDNAccounts){$AccountDN = $Param.BaseDNAccounts}
}
Write-Host
Write-Host "Group DN is: " $GroupDN -BackgroundColor Yellow -ForegroundColor Black
Write-Host "Account DN is: " $AccountDN -BackgroundColor Yellow -ForegroundColor Black

## Create new DNS Reverse Lookup Primary Zones
Write-Host
Write-Host "Now creating Reverse Lookup Zones" -foregroundcolor "yellow"
ForEach ($Param in $ADConfig){
    if ($Param.DNSZones -eq "n/a"){Continue}
	if ($Param.DNSZones){
        Try {Add-DnsServerPrimaryZone -NetworkId $Param.DNSZones -ReplicationScope Forest -DynamicUpdate NonsecureAndSecure -ErrorAction Stop}
	    Catch [System.Exception] {Write-Host "Failed to create DNS Reverse Lookup Zone" $Param.DNSZones". It may already exist" -ForegroundColor Yellow -BackgroundColor Red}
        If ($Error.Count -eq 0){Write-Host "Successfully created Reverse Lookup Zone for" $Param.DNSZones}
        $error.Clear()
    }
}

## Create the new DNS A Records within the root DNS Zone
Write-Host 
Write-Host "Now creating DNS A Records" -foregroundcolor "yellow"
ForEach ($Param in $ADConfig){
    if ($Param.DNSName -eq "n/a"){Continue}
	if ($Param.DNSName){
        Try {Add-DnsServerResourceRecordA -Name $Param.DNSName -ZoneName $DNSRoot -AllowUpdateAny -IPv4Address $Param.IPAddress -CreatePtr -ErrorAction Stop}
        Catch [System.Exception] {Write-Host "Failed to create DNS A record for" $Param.DNSName ". It may already exist" -ForegroundColor Yellow -BackgroundColor Red}
        If ($Error.Count -eq 0){Write-Host "Successfully created A record for" $Param.DNSName}
        $error.Clear()
	}
}

## Create Universal Security Groups
Write-Host
Write-Host "Now creating Universal Security Groups" -foregroundcolor "yellow"
ForEach ($Param in $ADConfig){
	if ($Param.SecurityGroupToCreate -eq "n/a"){Continue}
    if ($Param.SecurityGroupToCreate){
		Try {New-ADGroup -Name $Param.SecurityGroupToCreate -GroupCategory Security -GroupScope Universal -path $GroupDN -ErrorAction Stop}
        Catch [System.Exception] {Write-Host "Failed to create Security Group" $Param.SecurityGroupToCreate ". It may already exist" -ForegroundColor Yellow -BackgroundColor Red}
        If ($Error.Count -eq 0){Write-Host "Successfully created Universal Security Group for" $Param.SecurityGroupToCreate}
        $error.Clear()
	}
}

## Create the Service Accounts within the requested OU Container
Write-Host
Write-Host "Now creating Service Accounts" -foregroundcolor "yellow"
ForEach ($Param in $ADConfig){
    if ($Param.SvcUserName -eq "n/a"){Continue}
	if ($Param.SvcUserName){
		Try {
            $Password = $Param.Password | ConvertTo-SecureString -AsPlainText -Force 
		    $UPN = $Param.SvcUserName+"@"+$DNSRoot
		    New-ADUser -Name $Param.SvcUserName -GivenName $Param.SvcUserName -UserPrincipalName $UPN -SamAccountName $Param.SvcUserName -AccountPassword $Password -PasswordNeverExpires $true -CannotChangePassword $true -Path $AccountDN -enabled $true -ErrorAction Stop}
        Catch [System.Exception] {Write-Host "Failed to create User Account" $Param.SvcUserName ". It may already exist" -ForegroundColor Yellow -BackgroundColor Red}
        If ($Error.Count -eq 0){Write-Host "Successfully created Service Account for" $Param.SvcUserName}
        $error.Clear()
    }
}

## Add the Service Accounts as members of the required Security Groups
Write-Host
Write-Host "Attempting to add Service Accounts to the required Universal Security Groups" -foregroundcolor "yellow"
ForEach ($Param in $ADConfig){
	if ($Param.SecurityGroupName -eq "n/a"){Continue}
    if ($Param.SecurityGroupName){
        Try {Add-ADGroupMember -Identity $Param.SecurityGroupName -Members $Param.MembersOfSecurityGroup -ErrorAction Stop}
	    Catch {Write-Host "Failed to add User Account" $Param.MembersOfSecurityGroup "to Security Group" $Param.SecurityGroupName -ForegroundColor Yellow -BackgroundColor Red}
        If ($Error.Count -eq 0){Write-Host "Successfully added" $Param.MembersOfSecurityGroup "to Universal Security Group" $Param.SecurityGroupName}
        $error.Clear()
    }
}
