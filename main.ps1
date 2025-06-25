# Requires Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as Administrator!"
    break
}

# Set execution policy to allow script execution (temporarily)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Write-Host "Starting Windows 11 Debloat and Telemetry Reduction..." -ForegroundColor Cyan

# List of built-in apps to remove (common bloatware)
$appsToRemove = @(
    # Microsoft apps
    "Microsoft.BingNews"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.People"
    "Microsoft.PowerAutomateDesktop"
    "Microsoft.Todos"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsAlarms"
    "Microsoft.WindowsCamera"
    "microsoft.windowscommunicationsapps" # Mail & Calendar
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.YourPhone"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    
    # Third-party apps
    "Clipchamp.Clipchamp"
    "Disney.37853FC22B2CE"
    "Facebook.Facebook"
    "Twitter.44084829"
    "PandoraMediaInc.29680B314EFC2"
    "CandyCrushSaga.Soda"
    "king.com.CandyCrushSaga"
    "king.com.CandyCrushSodaSaga"
    "king.com.FarmHeroesSaga"
    "AdobeSystemsIncorporated.AdobePhotoshopExpress"
    "DolbyLaboratories.DolbyAccess"
    "A278AB0D.MarchofEmpires"
    "KeeperSecurityInc.Keeper"
    "WinZipComputing.WinZipUniversal"
    "ActiproSoftwareLLC.562882FEEB491"
    
    # Other unnecessary apps
    "Microsoft.MixedReality.Portal"
    "Microsoft.SkypeApp"
    "Microsoft.549981C3F5F10" # Cortana
    "Microsoft.Microsoft3DViewer"
    "Microsoft.OneConnect"
    "Microsoft.Print3D"
    "Microsoft.Wallet"
    "MicrosoftCorporationII.QuickAssist"
)

# Remove provisioned apps (will prevent reinstallation on new user creation)
Write-Host "Removing provisioned apps..." -ForegroundColor Yellow
foreach ($app in $appsToRemove) {
    try {
        $package = Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like "*$app*" }
        if ($package) {
            Write-Host "Removing provisioned package: $($package.DisplayName)"
            Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName | Out-Null
        }
    } catch {
        Write-Warning "Failed to remove provisioned package: $app"
    }
}

# Remove installed apps for current user
Write-Host "Removing installed apps for current user..." -ForegroundColor Yellow
foreach ($app in $appsToRemove) {
    try {
        $installed = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*$app*" }
        if ($installed) {
            Write-Host "Removing installed app: $($installed.Name)"
            Remove-AppxPackage -Package $installed.PackageFullName -AllUsers | Out-Null
        }
    } catch {
        Write-Warning "Failed to remove installed app: $app"
    }
}

# Remove leftover app data
Write-Host "Cleaning up leftover app data..." -ForegroundColor Yellow
Get-ChildItem -Path "C:\Program Files\WindowsApps\" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "Microsoft.(Bing|Xbox|Zune|GetHelp|GetStarted|People|Skype|Solitaire|Todos|WindowsFeedbackHub|WindowsMaps|WindowsAlarms|WindowsCamera|WindowsCommunicationsApps|WindowsSoundRecorder|YourPhone)" } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# Disable telemetry and data collection
Write-Host "Configuring privacy settings and disabling telemetry..." -ForegroundColor Yellow

# Set telemetry to minimal (0 = Security, 1 = Basic, 2 = Enhanced, 3 = Full)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

# Disable Cortana
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0

# Disable activity history and tracking
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

# Disable advertising ID
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

# Disable tailored experiences
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1

# Disable feedback requests
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1

# Disable Windows Spotlight features
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightOnActionCenter" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightWindowsWelcomeExperience" -Type DWord -Value 1

# Disable pre-installed apps
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1

# Disable automatic maps updates
Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0

# Disable location tracking
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

# Disable biometrics and Windows Hello
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Type DWord -Value 0

# Disable Windows Update automatic restart
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1

# Disable Wi-Fi Sense
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0

# Disable Live Tiles
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Type DWord -Value 1

# Disable Web Search in Start Menu
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1

# Disable Game Bar and Game DVR
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0

# Disable People icon in taskbar
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HidePeopleBar" -Type DWord -Value 1

# Disable Timeline
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

# Disable Background Apps
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Type DWord -Value 2

# Disable diagnostic data viewer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowDiagnosticDataViewer" -Type DWord -Value 0

# Disable suggested content in settings
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Type DWord -Value 0

# Disable handwriting data sharing
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1

# Disable Windows Tips
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Type DWord -Value 0

# Disable automatic installation of suggested apps
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1

# Disable automatic installation of sponsored apps
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableThirdPartySuggestions" -Type DWord -Value 1

# Disable automatic installation of paid network apps
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup" -Name "AllowNetworkAppsAtOOBE" -Type DWord -Value 0

# Disable Windows Ink Workspace
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Type DWord -Value 0

# Disable Windows Media Player sharing
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventLibrarySharing" -Type DWord -Value 1

# Disable Windows Error Reporting
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1

# Disable CEIP (Customer Experience Improvement Program)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0

# Disable P2P update sharing outside of local network
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0

# Disable automatic installation of network devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network printers
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Public" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network projectors
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Projector" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network TVs
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\TV" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network media devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Media" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network game devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Game" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network scanner devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Scanner" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network camera devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Camera" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network phone devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Phone" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network fax devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Fax" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network pager devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Pager" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network modem devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Modem" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network ISDN devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\ISDN" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network ATM devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\ATM" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network Frame Relay devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\FrameRelay" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network X.25 devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\X25" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PPP devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PPP" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network SLIP devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\SLIP" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network VPN devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\VPN" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network Direct Cable Connection devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\DirectCableConnection" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network Infrared devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Infrared" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network Bluetooth devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Bluetooth" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network 1394 devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\1394" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network USB devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\USB" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PCMCIA devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PCMCIA" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network CardBus devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\CardBus" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PCI devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PCI" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network AGP devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\AGP" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network ISA devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\ISA" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network EISA devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\EISA" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network MCA devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\MCA" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network VLB devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\VLB" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PnP devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PnP" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network non-PnP devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\nonPnP" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network unknown devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Unknown" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network other devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Other" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network custom devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Custom" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network legacy devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Legacy" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network virtual devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Virtual" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network emulated devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Emulated" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network software devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Software" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network hardware devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Hardware" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network composite devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Composite" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network volume devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Volume" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network port devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Port" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network keyboard devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Keyboard" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network mouse devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Mouse" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network joystick devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Joystick" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network gameport devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Gameport" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network HID devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\HID" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network biometric devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Biometric" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network smart card devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\SmartCard" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network media devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Media" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network modem devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Modem" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network monitor devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Monitor" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network printer devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Printer" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network scanner devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Scanner" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network camera devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Camera" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network storage devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Storage" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network volume devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Volume" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network battery devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Battery" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network UPS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\UPS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network processor devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Processor" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network memory devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Memory" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network bridge devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Bridge" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network adapter devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Adapter" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network controller devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Controller" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network enumerator devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Enumerator" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network filter devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Filter" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network bus devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Bus" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network root devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Root" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network system devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\System" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network computer devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Computer" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network ACPI devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\ACPI" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network HAL devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\HAL" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PnP BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PnPBIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network ACPI BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\ACPIBIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network EISA BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\EISABIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network ISA BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\ISABIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network MCA BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\MCABIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PnP ISA BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PnPISABIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PnP EISA BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PnPEISABIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PnP MCA BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PnPMCABIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PnP PCI BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PnPPCIBIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PnP AGP BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PnPAGPBIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PnP VLB BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PnPVLBBIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PnP CardBus BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PnPCardBusBIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PnP PCMCIA BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PnPPCMCIABIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PnP USB BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PnPUSBBios" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PnP 1394 BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PnP1394BIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PnP Bluetooth BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PnPBluetoothBIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PnP Infrared BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PnPInfraredBIOS" -Name "AutoSetup" -Type DWord -Value 0

# Disable automatic installation of network PnP Direct Cable Connection BIOS devices
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\PnPDirectCableConnectionBIOS" -Name "AutoSetup"

Write-Host "Done! :)" -ForegroundColor Cyan
