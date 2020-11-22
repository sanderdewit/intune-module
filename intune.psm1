########################################
#Sander is writing an Intune module
#v0.0002
########################################
#Requires -Version 3.0
#Requires -Modules @{Modulename='AzureAD';ModuleVersion='2.0.0.131'}
Set-StrictMode -Version latest
function connect-IntuneService {
  <#
      .SYNOPSIS
      This function is used to authenticate with the Graph API REST interface
 
      .DESCRIPTION
      The function authenticate with the Graph API Interface with the tenant name
      .EXAMPLE
 
      Connect-IntuneService and sets it in the intuneauthtoken variable
 
      Authenticates you with the Graph API interface
 
      .NOTES
 
      NAME: Connect-IntuneService
 
  #>
 
  [cmdletbinding()]
  param
  (
    [Parameter(Mandatory=$true)]$User,
    [Parameter(Mandatory=$false)][switch]$silent
  )
  process {
  #$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
  #$tenant = $userUpn.Host
  Write-Verbose "Checking for AzureAD module..."
  $AadModule = Get-Module -Name "AzureAD" -ListAvailable
  # Getting path to ActiveDirectory Assemblies
  # If the module count is greater than 1 find the latest version
    $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
    $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
  [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
  [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
  $clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
  $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
  $resourceAppIdURI = "https://graph.microsoft.com"
  $authority = 'https://login.windows.net/common'
  try {
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Always"
    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
    #New-Object 'Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationParameters'
    if ($silent){$authResult = $authContext.AcquireTokenSilentAsync($resourceAppIdURI,$clientId,$userid,$platformParameters).Result}
    else {
    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result}
    # If the accesstoken is valid then create the authentication header
    if($authResult.AccessToken){
      # Creating header for Authorization token
      $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'="Bearer " + $authResult.AccessToken
        'ExpiresOn'=$authResult.ExpiresOn
      }
      $global:IntuneAuthToken = $authHeader
    }
    else {
      Write-Warning "Authorization Access Token is null, please re-run authentication..."
      break
    }
  }
 
  catch {
    write-error $_.Exception.Message
    write-error $_.Exception.ItemName
    break
  }
}}

####################################################
function get-IntuneManagedDevices {
  [cmdletbinding()]
  param
  (
    [Parameter(Mandatory=$false)]$all,
    [Parameter(Mandatory=$false)]$resultsize
  )
  if (!($IntuneAuthToken)){throw 'please run connect-IntuneService first'}
  $processnextlinks = $true
  $idevices = Invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/managedDevices' -Headers $IntuneAuthToken -Method get
  while ($processnextlinks -eq $true){
    if ($($idevices.'@odata.nextLink') -ne $null){
      $results = $idevices.value
      $idevices = Invoke-RestMethod -Uri $($idevices.'@odata.nextLink') -Headers $IntuneAuthToken -Method get
    }
    if ($($idevices.'@odata.nextLink') -eq $null){
      $results = $idevices.value
      $idevices = $null
    $processnextlinks = $false}
    write-debug "getting info $idevices"
    $objects += $results
  }
  $objects
}
####################################################
####################################################
Function Invoke-IntuneDeviceAction(){
  <#
      .SYNOPSIS
      This function is used to set a generic intune resources from the Graph API REST interface
      .DESCRIPTION
      The function connects to the Graph API Interface and sets a generic Intune Resource
      .EXAMPLE
      Invoke-DeviceAction -DeviceID $DeviceID -remoteLock
      Resets a managed device passcode
      .NOTES
      NAME: Invoke-DeviceAction
  #>
  [cmdletbinding(SupportsShouldProcess=$true)]
  param
  (
    [switch]$RemoteLock,
    [switch]$ResetPasscode,
    [switch]$Wipe,
    [switch]$Retire,
    [Parameter(Mandatory=$true,HelpMessage="DeviceId (guid) for the Device you want to take action on must be specified:")]$DeviceID,
  )
  if (!($IntuneAuthToken)){throw 'please run connect-IntuneService first'} 
  $graphApiVersion = "Beta"
    try {
        $Count_Params = 0
        if($RemoteLock.IsPresent){ $Count_Params++ }
        if($ResetPasscode.IsPresent){ $Count_Params++ }
        if($Wipe.IsPresent){ $Count_Params++ }
        if($Retire.IsPresent){ $Count_Params++ }
        if($Count_Params -eq 0){
          Write-Warning "No parameter set, specify -RemoteLock -ResetPasscode or -Wipe against the function" -f Red
        }
        elseif($Count_Params -gt 1){
          Write-Warning "Multiple parameters set, specify a single parameter -RemoteLock -ResetPasscode or -Wipe against the function" -f Red
        }
        elseif($RemoteLock){
          if($PSCmdlet.ShouldProcess("Enable Remote Lock for: '$DeviceID'")){
          $Resource = "managedDevices/$DeviceID/remoteLock"
          $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
          write-verbose $uri
          Write-Verbose "Sending remoteLock command to $DeviceID"
          Invoke-RestMethod -Uri $uri -Headers $IntuneAuthToken -Method Post
        }}
        elseif($ResetPasscode){
          if($PSCmdlet.ShouldProcess("Reset Passcode '$DeviceID'")){
            $Resource = "managedDevices/$DeviceID/resetPasscode"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending remotePasscode command to $DeviceID"
            Invoke-RestMethod -Uri $uri -Headers $IntuneAuthToken -Method Post
          }
          else {
            Write-output "Reset of the Passcode for the device $DeviceID was cancelled..."
          }
        }
        elseif($Wipe){
          if($PSCmdlet.ShouldProcess("Wipe Device '$DeviceID'")){
            $Resource = "managedDevices/$DeviceID/wipe"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
            write-verbose $uri
            Write-Verbose "Sending wipe command to $DeviceID"
            Invoke-RestMethod -Uri $uri -Headers $IntuneAuthToken -Method Post
          }
          else {
            Write-Output "Wipe of the device $DeviceID was cancelled..."
          }
        }
        elseif($Retire){
          if($PSCmdlet.ShouldProcess("Retire Device '$DeviceID'")){
              $Resource = "managedDevices/$DeviceID/retire"
             $uri = "https://graph.microsoft.com/$graphApiVersion/$($resource)"
              write-verbose $uri
              Write-Verbose "Sending retire command to $DeviceID"
              Write-Verbose $verbose
              Invoke-RestMethod -Uri $uri -Headers $IntuneAuthToken -Method Post
            }
            else {
              Write-output "Retire of the device $DeviceID was cancelled..."
            }
          }
    }
    catch {
    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-output "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    break
    }
}
export-modulemember -function connect-IntuneService, get-IntuneManagedDevices, Invoke-IntuneDeviceAction
