<#
 .SYNOPSIS
   Retrieve secrets from Azure Key Vault Via PowerShell
 .DESCRIPTION
   Azure Key Vault is used to safeguard and manage cryptographic keys, certificates and secrets used by cloud applications and services. 
   This allows other application, services or users in an Azure subscription to store and retrieve these cryptographic keys, certificates and secrets
   This is example PowerShell script to retrieve secrets from Azure Key Vault using Key Vault REST API
 .PARAMETER tenantID
   Mandatory. Azure Active Directory tenant id 
 .PARAMETER clientID
   Mandatory. Azure Active Directory client id
 .PARAMETER clientSecret
   Mandatory. Azure Active Directory client secret
 .PARAMETER keyvaultName
   Mandatory. Name of the vault
 .PARAMETER secretName
   Mandatory. The name of the secret
 .PARAMETER secretVersion
   Mandatory. The version of the secret
 .OUTPUTS
   Retrieve a specified secret from a given key vault.
 .EXAMPLE
   .\get-azure-keyvault-secret.ps1 -tenantID <tenant_id> -clientID <client_id> -clientSecret <client_secret> -keyvaultName <keyvalut_name>
     -secretName <secret_name>  -secretVersion <secret_version>
#>

[CmdletBinding()]
  
Param (
   
    [Parameter(Mandatory=$true,Position=0)][string]$tenantID,
    [Parameter(Mandatory=$true,Position=1)][string]$clientID,
    [Parameter(Mandatory=$true,Position=2)][string]$clientSecret,
    [Parameter(Mandatory=$true,Position=3)][string]$keyvaultName,
    [Parameter(Mandatory=$true,Position=4)][string]$secretName,
    [Parameter(Mandatory=$true,Position=5)][string]$secretVersion
  )
  
Set-StrictMode -Version Latest
  
$LogFile = 'C:\Windows\Logs\get-azure-keyvault-secret.log'

Function Main {

# Creates a new log file so that the script will log info, warning, error in the logfile.
Start-Log -LogPath "C:\Windows\Logs" -LogName "get-azure-keyvault-secret.log" 

Write-LogInfo -LogPath $LogFile -Message "Trying to get Azure AD Access Token"

$tenant_id = $tenantID

$client_id = $clientID

$client_secret = $clientSecret

$vault_name = $keyvaultName

$access_token = Get-AccessToken -tenantId $tenant_id -vaultName $vault_name -aadClientId $client_id `
               -aadClientSecret $client_secret

Write-LogInfo -LogPath $LogFile -Message "Get Azure AD Access Token successfull"

Write-LogInfo -LogPath $LogFile -Message "Trying retrieve secrets from Azure Key Vault"

$secret_name = $secretName

$secret_version = $secretVersion

$secretValue = Get-Secret -Token $access_token -vaultName $vault_name -secretName $secret_name `
                  -secretVersion $secret_version 

Write-Host "The specified version of a secret is: $secretValue"

Write-LogInfo -LogPath $LogFile -Message "REST API call to retrieve secrets from Azure Key Vault is successfull"

}

Function Start-Log {
  <#
  .SYNOPSIS
    Creates a new log file
  .DESCRIPTION
    Creates a log file with the path and name specified in the parameters. Checks if log file exists, and if it does deletes it and creates a new one.
    Once created, writes initial logging data
  .PARAMETER LogPath
    Mandatory. Path of where log is to be created. Example: C:\Windows\Log
  .PARAMETER LogName
    Mandatory. Name of log file to be created. Example: get-azure-keyvault-secret.log
  .INPUTS
    Parameters above
  .OUTPUTS
    Log file created
  .EXAMPLE
    Start-Log -LogPath "C:\Windows\Logs" -LogName "C:\Windows\Logs\get-azure-keyvault-secret.log"
    Creates a new log file with the file path of C:\Windows\Logs\get-azure-keyvault-secret.log. Initialises the log file with
    the date and time the log was created (or the calling script started executing).
  #>

  [CmdletBinding()]

  Param (
    [Parameter(Mandatory=$true,Position=0)][string]$LogPath,
    [Parameter(Mandatory=$true,Position=1)][string]$LogName
  )

  Process {
    $sFullPath = Join-Path -Path $LogPath -ChildPath $LogName

    #Check if file exists and delete if it does
    If ( (Test-Path -Path $sFullPath) ) {
      Remove-Item -Path $sFullPath -Force
    }

    #Create file and start logging
    New-Item -Path $sFullPath -ItemType File

    Add-Content -Path $sFullPath -Value "***************************************************************************************************"
    Add-Content -Path $sFullPath -Value "Started processing at [$([DateTime]::Now)]."
    Add-Content -Path $sFullPath -Value "***************************************************************************************************"
    Add-Content -Path $sFullPath -Value ""
  }
}

Function Write-LogInfo {
  <#
  .SYNOPSIS
    Writes informational message to specified log file
  .DESCRIPTION
    Appends a new informational message to the specified log file
  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write to. Example: C:\Windows\Logs\get-azure-keyvault-secret.log
  .PARAMETER Message
    Mandatory. The string that you want to write to the log
  .PARAMETER TimeStamp
    Optional. When parameter specified will append the current date and time to the end of the line. Useful for knowing
    when a task started and stopped.
  .INPUTS
    Parameters above
  .OUTPUTS
    None
  .EXAMPLE
    Write-LogInfo -LogPath "C:\Windows\Logs\get-azure-keyvault-secret.log" -Message "This is a new line which I am appending to the end of the log file."
    Writes a new informational log message to a new line in the specified log file.
  #>

  [CmdletBinding()]

  Param (
    [Parameter(Mandatory=$true,Position=0)][string]$LogPath,
    [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true)][string]$Message,
    [Parameter(Mandatory=$false,Position=2)][switch]$TimeStamp
  )

  Process {
    #Add TimeStamp to message if specified
    If ( $TimeStamp -eq $True ) {
      $Message = "$Message  [$([DateTime]::Now)]"
    }

    #Write Content to Log
    Add-Content -Path $LogPath -Value $Message

  }
}

Function Write-LogWarning {
  <#
  .SYNOPSIS
    Writes warning message to specified log file
  .DESCRIPTION
    Appends a new warning message to the specified log file. Automatically prefixes line with WARNING:
  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write to. Example: C:\Windows\Logs\get-azure-keyvault-secret.log
  .PARAMETER Message
    Mandatory. The string that you want to write to the log
  .PARAMETER TimeStamp
    Optional. When parameter specified will append the current date and time to the end of the line. Useful for knowing
    when a task started and stopped.
  .INPUTS
    Parameters above
  .OUTPUTS
    None
  .EXAMPLE
    Write-LogWarning -LogPath "C:\Windows\Logs\get-azure-keyvault-secret.log" -Message "This is a warning message."
    Writes a new warning log message to a new line in the specified log file.
  #>

  [CmdletBinding()]

  Param (
    [Parameter(Mandatory=$true,Position=0)][string]$LogPath,
    [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true)][string]$Message,
    [Parameter(Mandatory=$false,Position=2)][switch]$TimeStamp
  )

  Process {
    #Add TimeStamp to message if specified
    If ( $TimeStamp -eq $True ) {
      $Message = "$Message  [$([DateTime]::Now)]"
    }

    #Write Content to Log
    Add-Content -Path $LogPath -Value "WARNING: $Message"

  }
}

Function Write-LogError {
  <#
  .SYNOPSIS
    Writes error message to specified log file
  .DESCRIPTION
    Appends a new error message to the specified log file. Automatically prefixes line with ERROR:
  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write to. Example: C:\Windows\Logs\get-azure-keyvault-secret.log
  .PARAMETER Message
    Mandatory. The description of the error you want to pass (pass your own or use $_.Exception)
  .PARAMETER TimeStamp
    Optional. When parameter specified will append the current date and time to the end of the line. Useful for knowing
    when a task started and stopped.
  .PARAMETER ExitGracefully
    Optional. If parameter specified, then runs Stop-Log and then exits script
  .INPUTS
    Parameters above
  .OUTPUTS
    None
  .EXAMPLE
    Write-LogError -LogPath "C:\Windows\Logs\get-azure-keyvault-secret.log" -Message $_.Exception -ExitGracefully
    Writes a new error log message to a new line in the specified log file. Once the error has been written,
    the Stop-Log function is excuted and the calling script is exited.
  .EXAMPLE
    Write-LogError -LogPath "C:\Windows\Logs\get-azure-keyvault-secret.log" -Message $_.Exception
    Writes a new error log message to a new line in the specified log file, but does not execute the Stop-Log
    function, nor does it exit the calling script. In other words, the only thing that occurs is an error message
    is written to the log file and that is it.
    Note: If you don't specify the -ExitGracefully parameter, then the script will not exit on error.
  #>

  [CmdletBinding()]

  Param (
    [Parameter(Mandatory=$true,Position=0)][string]$LogPath,
    [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true)][string]$Message,
    [Parameter(Mandatory=$false,Position=3)][switch]$TimeStamp,
    [Parameter(Mandatory=$false,Position=4)][switch]$ExitGracefully
  )

  Process {
    #Add TimeStamp to message if specified
    If ( $TimeStamp -eq $True ) {
      $Message = "$Message  [$([DateTime]::Now)]"
    }

    #Write Content to Log
    Add-Content -Path $LogPath -Value "ERROR: $Message"

    #If $ExitGracefully = True then run Log-Finish and exit script
    If ( $ExitGracefully -eq $True ){
      Add-Content -Path $LogPath -Value " "
      Stop-Log -LogPath $LogPath
      Break
    }
  }
}

Function Stop-Log {
  <#
  .SYNOPSIS
    Write closing data to log file & exits the calling script
  .DESCRIPTION
    Writes finishing logging data to specified log file and then exits the calling script
  .PARAMETER LogPath
    Mandatory. Full path of the log file you want to write finishing data to. Example: C:\Windows\Logs\get-azure-keyvault-secret.log
  .PARAMETER NoExit
    Optional. If parameter specified, then the function will not exit the calling script, so that further execution can occur 
  .PARAMETER ToScreen
    Optional. When parameter specified will display the content to screen as well as write to log file. This provides an additional
    another option to write content to screen as opposed to using debug mode.
  .INPUTS
    Parameters above
  .OUTPUTS
    None
  .EXAMPLE
    Stop-Log -LogPath "C:\Windows\Logs\get-azure-keyvault-secret.log"
    Writes the closing logging information to the log file and then exits the calling script.
    Note: If you don't specify the -NoExit parameter, then the script will exit the calling script.
  .EXAMPLE
    Stop-Log -LogPath "C:\Windows\Logs\get-azure-keyvault-secret.log" -NoExit
    Writes the closing logging information to the log file but does not exit the calling script. This then
    allows you to continue executing additional functionality in the calling script (such as calling the
    Send-Log function to email the created log to users).
  #>

  [CmdletBinding()]

  Param (
    [Parameter(Mandatory=$true,Position=0)][string]$LogPath,
    [Parameter(Mandatory=$false,Position=1)][switch]$NoExit
  )

  Process {
    Add-Content -Path $LogPath -Value ""
    Add-Content -Path $LogPath -Value "***************************************************************************************************"
    Add-Content -Path $LogPath -Value "Finished processing at [$([DateTime]::Now)]."
    Add-Content -Path $LogPath -Value "***************************************************************************************************"

    #Exit calling script if NoExit has not been specified or is set to False
    If( !($NoExit) -or ($NoExit -eq $False) ){
      Exit
    }
  }
}

Function Get-AccessToken {
  <#
  .SYNOPSIS
    A method to Get new OAuth2 access  token for REST API call
  .DESCRIPTION
    A method to Get new OAuth2 access token for REST API call using your tenantId, Client Id and Client Secret
  .PARAMETER tenantId
    Mandatory. Azure Active Directory tenant id 
  .PARAMETER vaultName
    Mandatory. Name of the vault
  .PARAMETER aadClientId
    Mandatory. Azure Active Directory client id
  .PARAMETER aadClientSecret
    Mandatory. Azure Active Directory client secret
  .INPUTS
    Parameters above
  .OUTPUTS
    Return an access token on success
  .EXAMPLE
    Get-AccessToken -tenantId <tenant_name> -vaultName <vault_name> -aadClientId <client_id>
               -aadClientSecret <client_secret> 
  #>

  [CmdletBinding()]

  Param (
    [Parameter(Mandatory=$true,Position=0)][string]$tenantId,
    [Parameter(Mandatory=$true,Position=1)][string]$vaultName,
    [Parameter(Mandatory=$true,Position=2)][string]$aadClientId,
    [Parameter(Mandatory=$true,Position=3)][string]$aadClientSecret
  )
  
  $oath2Uri = "https://login.windows.net/$tenantId/oauth2/token"
  
  $body = 'grant_type=client_credentials'
  
  $body += '&client_id=' + $aadClientId
  
  $body += '&client_secret=' + [Uri]::EscapeDataString($aadClientSecret)
  
  $body += '&resource=' + [Uri]::EscapeDataString("https://vault.azure.net")

  $response = Invoke-RestMethod -Method POST -Uri $oath2Uri -Headers @{} -Body $body

  return $response.access_token
  
}

Function Get-Secret {
  <#
  .SYNOPSIS
    Get a specified secret from a given key vault 
  .DESCRIPTION
    Get a specified secret from a given key vault using REST API
  .PARAMETER Token
    Mandatory. Access Token
  .PARAMETER vaultName
    Mandatory. Name of the vault
  .PARAMETER secretName
    Mandatory. The name of the secret you want to retrieve.
  .PARAMETER secretVersion
    Mandatory. The version of the secret you want to retrieve. 
    Secret version may be excluded in which case the current version is retrieved.
  .INPUTS
    Parameters above
  .OUTPUTS
    200 response. The secret value.
  .EXAMPLE
    Get-Secret -Token <access_token> -vaultName <vault_name> -secretName <secret_name>
    -secretVersion <secret_version> 
  #>

  [CmdletBinding()]

  Param (
    
    [Parameter(Mandatory=$true,Position=0)][string]$Token,
    [Parameter(Mandatory=$true,Position=1)][string]$vaultName,
    [Parameter(Mandatory=$true,Position=2)][string]$secretName,
    [Parameter(Mandatory=$true,Position=3)][string]$secretVersion
  )

  $headers = @{ 'Authorization' = "Bearer $Token" }

  $queryUrl = "https://$vaultName.vault.azure.net/secrets/$secretName/$secretVersion" + '?api-version=2016-10-01'

  $keyResponse = Invoke-RestMethod -Method GET -Uri $queryUrl -Headers $headers

  return $keyResponse.value

}


#Entry point 
Main
