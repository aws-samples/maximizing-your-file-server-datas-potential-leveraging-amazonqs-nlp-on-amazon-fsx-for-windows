<#
# Allow outbound connections for PowerShell and Package Management
New-NetFirewallRule -DisplayName "Allow PowerShell Outbound" -Direction Outbound -Program "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -Action Allow
New-NetFirewallRule -DisplayName "Allow Package Management Outbound" -Direction Outbound -Program "%SystemRoot%\System32\PackageManagement\PkgMgr.exe" -Action Allow

# Configure TLS 1.2 and set up NuGet package source
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Register-PackageSource -Provider NuGet -Name nugetRepository -Location https://www.nuget.org/api/v2 -Force

# Install required Windows features and PowerShell modules
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Install-Module -Name AWS.Tools.IdentityManagement, AWS.Tools.SecretsManager -Force -AllowClobber
Install-Module -Name AWSPowerShell -Force

# Import logging module
Import-Module Microsoft.PowerShell.Management
#>
# Function to log messages with timestamp and log level
function Write-Log {
    param (
        [string]$Message,
        [string]$LogLevel = "Info"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$LogLevel] $Message"
    Write-Output $logEntry
    Add-Content -Path "$PSScriptRoot\script_log.txt" -Value $logEntry
}

# Get the current AWS region from EC2 instance metadata
try {
    $currentRegion = (Get-EC2InstanceMetadata -Category Region).SystemName
}
catch {
    Write-Log "Error retrieving AWS region: $_" -LogLevel "Error"
    exit 1
}

# Retrieve domain administrator credentials from AWS Secrets Manager
try {
    $secretName = "QBusiness-fsx-creds"
    $secret = Get-SECSecretValue -SecretId $secretName -Region $currentRegion
    $secretJson = $secret.SecretString | ConvertFrom-Json
    $username = $secretJson.username
    $password = $secretJson.password | ConvertTo-SecureString -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($username, $password)
    Write-Log "Successfully retrieved credentials from AWS Secrets Manager"
}
catch {
    Write-Log "Error retrieving credentials from AWS Secrets Manager: $_" -LogLevel "Error"
    exit 1
}

# Define configuration for domain, groups, and users
$config = @{
    AwsRegion = $currentRegion
    Domain = "example.com"
    Groups = @("ml-engineers", "security-engineers")
    Users = @(
        @{
            GivenName = "John"
            Surname = "Doe"
            GroupMembership = "ml-engineers"
            EmailAddress = "jdoe@example.com"
        },
        @{
            GivenName = "Jane"
            Surname = "Smith"
            GroupMembership = "security-engineers"
            EmailAddress = "jsmith@example.com"
        }
    )
}

# Function to generate SamAccountName from given name and surname
function Get-SamAccountName {
    param (
        [string]$GivenName,
        [string]$Surname
    )
    return ($GivenName.Substring(0,1) + $Surname).ToLower()
}

# Function to generate a random password
function Get-RandomPassword {
    param (
        [int]$Length = 16,
        [switch]$IncludeSpecialCharacters
    )

    $charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    if ($IncludeSpecialCharacters) {
        $charSet += "!@#$%^&*()-_=+[{]}\|;:,<.>/?`~"
    }

    -join (1..$Length | ForEach-Object { $charSet[(Get-Random -Maximum $charSet.Length)] })
}

# Create groups and users
try {
    # Create groups
    foreach ($group in $config.Groups) {
        try {
            New-ADGroup -Name $group -GroupCategory Security -GroupScope Global -DisplayName $group -Description "Members of this group are RODC Administrators"
            Write-Log "Group '$group' created successfully."
        }
        catch {
            Write-Log "Error creating group '$group': $_" -LogLevel "Error"
        }
    }

    # Create users
    foreach ($user in $config.Users) {
        try {
            $samAccountName = Get-SamAccountName -GivenName $user.GivenName -Surname $user.Surname
            $password = Get-RandomPassword -Length 16 -IncludeSpecialCharacters
            $userProperties = @{
                GivenName = $user.GivenName
                Surname = $user.Surname
                Name = "$($user.GivenName) $($user.Surname)"
                SamAccountName = $samAccountName
                EmailAddress = $user.EmailAddress
                UserPrincipalName = "$samAccountName@$($config.Domain)"
                AccountPassword = (ConvertTo-SecureString -AsPlainText $password -Force)
                Enabled = $true
                PasswordNeverExpires = $true
                ChangePasswordAtLogon = $false
            }

            New-ADUser @userProperties -Credential $cred
            Write-Log "User '$($user.GivenName) $($user.Surname)' created successfully with SamAccountName '$samAccountName'."

            Add-ADGroupMember -Identity $user.GroupMembership -Members $samAccountName
            Write-Log "User '$samAccountName' added to group '$($user.GroupMembership)'."

            # Store user details in AWS Secrets Manager
            $userSecrets = @{
                Username = $samAccountName
                Password = $password
            } | ConvertTo-Json

            New-SECSecret -Name $samAccountName -SecretString $userSecrets -Region $config.AwsRegion
            Write-Log "User details for '$samAccountName' stored in AWS Secrets Manager."
        }
        catch {
            Write-Log "Error processing user '$($user.GivenName) $($user.Surname)': $_" -LogLevel "Error"
        }
    }

    Write-Log "Script execution completed successfully."
}
catch {
    Write-Log "Unhandled error occurred: $_" -LogLevel "Error"
}

# Mount Amazon FSx for Windows File Server
$currentRegion = (Get-EC2InstanceMetadata -Category Region).SystemName
$windowsFileSystemId = (Get-FSXFileSystem | Where-Object {$_.Tags.Key -eq "Name" -and $_.Tags.Value -eq "amazonq-windows-fsx-workshop"}).FileSystemId
$secretName = "QBusiness-fsx-creds"  # Assuming this is the correct name of your secret

# Get file system information and credentials
$fileSystemInfo = Get-FSxFileSystem -FileSystemId $windowsFileSystemId
$preferredFileServerIP = $fileSystemInfo.WindowsConfiguration.PreferredFileServerIp
$password = (Get-SECSecretValue -SecretId $secretName).SecretString | ConvertFrom-Json | Select-Object -ExpandProperty password

# Mount the FSx file system
try {
    New-SmbMapping -LocalPath "X:" -RemotePath "\\$preferredFileServerIP\share" -UserName "admin@example.com" -Password $password -ErrorAction Stop
}
catch {
    Write-Error "Failed to mount the FSx file system: $_"
    return
}

# Download PDF files and set permissions
$pdfUrls = @(
    "https://docs.aws.amazon.com/pdfs/decision-guides/latest/generative-ai-on-aws-how-to-choose/generative-ai-on-aws-how-to-choose.pdf",
    "https://docs.aws.amazon.com/pdfs/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.pdf"
)

$pdfPaths = @(
    "X:\generative-ai-on-aws-how-to-choose.pdf",
    "X:\aws-security-incident-response-guide.pdf"
)

foreach ($i in 0..($pdfUrls.Length - 1)) {
    try {
        Invoke-WebRequest -Uri $pdfUrls[$i] -OutFile $pdfPaths[$i] -ErrorAction Stop
        Write-Host "Downloaded $($pdfPaths[$i])"

        # Set permissions for the downloaded files
        if ($i -eq 0) {
            # Set permissions for the first PDF file
            $acl = Get-Acl -Path $pdfPaths[$i]
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("jdoe", "FullControl", "Allow")))
            $acl.SetOwner([System.Security.Principal.NTAccount]"jdoe")
            Set-Acl -Path $pdfPaths[$i] -AclObject $acl
        } elseif ($i -eq 1) {
            # Set permissions for the second PDF file
            $acl = Get-Acl -Path $pdfPaths[$i]
            $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("jsmith", "FullControl", "Allow")))
            $acl.SetOwner([System.Security.Principal.NTAccount]"jsmith")
            Set-Acl -Path $pdfPaths[$i] -AclObject $acl
        }
    }
    catch {
        Write-Error "Failed to download $($pdfUrls[$i]): $_"
    }
}

# Cleanup: Unmount the FSx file system

try {
    Remove-SmbMapping -LocalPath "X:" -RemotePath "\\$preferredFileServerIP\share" -Force -ErrorAction Stop
    Write-Host "Unmounted the FSx file system"
}
catch {
    Write-Error "Failed to unmount the FSx file system: $_"
}
