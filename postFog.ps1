function Get-TimeStamp {    
    return "[{0:yyyy/MM/dd} {0:HH:mm:ss}]" -f (Get-Date)    
}


## Starting a Transcript instead of using a log
Start-Transcript

# Start Write-host and script
Write-host "PXE-Win script has started."

$USER_PASS = "test123"
$USER_NAME = "temp"
$DOMAIN_NAME = "lucidauth"
$SERVER_NAME = "fog.office.lucidchart.com"

##########################
#### Helper Functions ####

function setRegistryProperty([String] $regPath, [String] $propName, $propType, [String] $value){
  if ($(Get-Item $regPath).Property -contains $propName ){
   # Update the property instead of creating a new one
    Set-ItemProperty -Path $regPath -Name $propName -Type $propType -Value $value
  }else{
    New-ItemProperty -Path $regPath -Name $propName -PropertyType $propType -Value $value
  }
}

function setAutoLogin($bool, $username, $password){
  setRegistryProperty -regPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -propName 'AutoAdminLogon' -propType String -value $bool
  setRegistryProperty -regPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -propName 'DefaultUserName' -propType String -value $username
  setRegistryProperty -regPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -propName 'DefaultPassword' -propType String -value $password
  Write-host ("Done")
}

function setTempAutoLogin($bool){
  if($bool){
    setAutoLogin -bool '1' -username "LUCID\${USER_NAME}" -password $USER_PASS
  }else{
    setAutoLogin('0', "", "")
  }
}



function verifyAdmin(){

# Verify we are running as Super-Admin
  Write-Host "Checking you are an administrator"
  If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    pause("This script needs to be run As Admin")
    Write-Host "User is not Admin."
    Break
  }
  Write-Host "Done"
  Write-Host "User is Admin."

  # Verify that the current username is correct for provisioning (Abort if not)
  Write-Host "Checking username..."
  if ([Environment]::UserName -ne 'temp'){
    pause('User must be named "temp". Aborting...')
    Write-Host "Username is incorrect. Should be 'temp'."
    Break
  }
  Write-Host "Done"
  Write-Host "Username 'temp' correct."
}

function pause([String] $message){
  if (-not ($message)){
    $message = "Press any key to continue"
  }
  Write-Host $message
  $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function setRunOnce([String] $value){
  setRegistryProperty -regPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -propName 'pxe-win' -propType String -value "C:\windows\System32\WindowsPowerShell\v1.0\powershell.exe C:\Users\temp\Desktop\pxe-win.ps1 ${value}"
}


Write-Host "################################ Functions have been set ################################"




##################################################################################################################################
########## Main ##########
verifyAdmin
#cd "C:\Users\temp\Desktop"
Set-Location "C:\Users\temp\Desktop"

###### - - - - -- - - - - ######

# init phase    

    Write-Host "Running Initial Phase..." -color "green"

    Set-ExecutionPolicy RemoteSigned -Force

    setTempAutoLogin($TRUE)

    # Set screensave timeout
    Write-Host "Configuring LockScreen..."
    setRegistryProperty -regPath 'HKCU:\Control Panel\Desktop' -propName 'ScreenSaveTimeout' -propType String -value '300'
    setRegistryProperty -regPath 'HKCU:\Control Panel\Desktop' -propName 'ScreenSaverIsSecure' -propType String -value '1'
    setRegistryProperty -regPath 'HKCU:\Control Panel\Desktop' -propName 'LockScreenAutoLockActive' -propType String -value '0'
    setRegistryProperty -regPath 'HKCU:\Control Panel\Desktop' -propName 'SCRNSAVE.EXE' -propType String -value 'C:\Windows\system32\scrnsave.scr'
    Write-Host "LockScreen has been configured." 
    Write-Host "Done"

    Write-Host "TODO: Disable multi-homed name resolution?"

    Write-Host "TODO: Import pre-defined local security policy"
  

# user phase 

    setRunOnce -value "user"

    Write-Host "Prompting for user input." 

    $username = Read-Host -Prompt 'Input the username (CTRL+C or "quit" to exit)'
    if($userDisplayName -eq "quit"){
      exit(0)
    }
    $userDisplayName = Read-Host -Prompt "Input the new user's DisplayName (CTRL+C or 'quit' to exit)"
    if($username -eq "quit"){
      exit(0)
    }




   


# Final phase 




    # Add User to the LucidAuth domain


    Write-Host "User has been added to the domain." 

    # The BitLocker password is stored in LastPass, where the Asset Manager should know to find it
    # BitLocker Requires reboot

    #Enable Bitlocker
    Write-Host "Enabling BitLocker..."
    manage-bde -protectors -add -RecoveryPassword C:
    manage-bde -protectors -add -TPM C:
    manage-bde -on C:
    Write-Host "Bitlocker is now enabled."

    Write-Host "Setting up current user as default user..."
    setRegistryProperty -regPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -propName 'LastLoggedOnUser' -propType String -value $DOMAIN_NAME\$username
    setRegistryProperty -regPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -propName 'LastLoggedOnSAMUser' -propType String -value $DOMAIN_NAME\$username
    setRegistryProperty -regPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' -propName 'LastLoggedOnDisplayName' -propType String -value $userDisplayName
    Write-Host "Done"


    # Clean-up
   # Write-Host "Clean up time"
    #del pxe-win.ps1
    #del username.txt
    #del userDisplayName.txt
    #Remove-Item -LiteralPath 'C:\Users\Public\Desktop\Boxstarter Shell.lnk'

    Write-Host "Disabling auto-login..."
    setTempAutoLogin($FALSE)
    Write-Host "Done"   

    # Disable the image user
    NET USER $USER_NAME /active:no
    setRunOnce -value ""
