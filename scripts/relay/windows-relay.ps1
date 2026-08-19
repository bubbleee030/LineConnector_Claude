<#
.SYNOPSIS
    Windows notification relay for line-connector.

.DESCRIPTION
    Reads LINE notifications from Windows Action Center using the
    UserNotificationListener API and POSTs them to the connector's
    /notify endpoint. This captures personal LINE messages without
    opening the chat — no read receipt is sent, nothing here ever
    talks to LINE's servers.

    Uses only built-in Windows APIs — nothing to install.

.PARAMETER Once
    Process current notifications once and exit (for testing).

.PARAMETER PollSeconds
    How often to check for new notifications (default 5).

.EXAMPLE
    $env:LINE_CONNECTOR_NOTIFY_SECRET = "your-secret"
    $env:LINE_CONNECTOR_NOTIFY_URL = "https://your-host/notify"
    .\windows-relay.ps1

.EXAMPLE
    .\windows-relay.ps1 -Once -Verbose

.NOTES
    Requirements:
    - Windows 10 version 1709+ (Fall Creators Update, build 16299)
    - LINE desktop app installed and running
    - First run prompts for notification access — grant it in
      Settings > Privacy > Notifications
    - PowerShell 5.1+ (ships with Windows 10)
#>
[CmdletBinding()]
param(
    [switch]$Once,
    [int]$PollSeconds = 5
)

$ErrorActionPreference = "Stop"

# ---- configuration ----------------------------------------------------------

$notifySecret = $env:LINE_CONNECTOR_NOTIFY_SECRET
$notifyUrl    = $env:LINE_CONNECTOR_NOTIFY_URL

if (-not $notifySecret -or -not $notifyUrl) {
    Write-Error "Set LINE_CONNECTOR_NOTIFY_SECRET and LINE_CONNECTOR_NOTIFY_URL first."
    exit 1
}

$statePath = Join-Path $env:USERPROFILE ".line-connector-windows-relay.state"

# ---- WinRT interop ----------------------------------------------------------

# Load the WinRT notification types. This fails on Windows versions before 1709.
try {
    [void][Windows.UI.Notifications.Management.UserNotificationListener,
        Windows.UI.Notifications, ContentType = WindowsRuntime]
    [void][Windows.UI.Notifications.NotificationKinds,
        Windows.UI.Notifications, ContentType = WindowsRuntime]
    [void][Windows.UI.Notifications.KnownNotificationBindings,
        Windows.UI.Notifications, ContentType = WindowsRuntime]
} catch {
    Write-Error (
        "Could not load UserNotificationListener.`n" +
        "This requires Windows 10 version 1709 (build 16299) or later."
    )
    exit 1
}

Add-Type -AssemblyName System.Runtime.WindowsRuntime

# PowerShell cannot directly await IAsyncOperation<T>. This bridges WinRT
# async to .NET Task so we can wait synchronously.
$_asTaskMethods = [System.WindowsRuntimeSystemExtensions].GetMethods()
$_asTaskGeneric = ($_asTaskMethods | Where-Object {
    $_.Name -eq 'AsTask' -and
    $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
})[0]

function Invoke-Async($asyncOp, [Type]$resultType) {
    $task = $_asTaskGeneric.MakeGenericMethod($resultType).Invoke($null, @($asyncOp))
    $task.Wait(-1) | Out-Null
    return $task.Result
}

# ---- listener setup ---------------------------------------------------------

$listener = [Windows.UI.Notifications.Management.UserNotificationListener]::Current

$accessType = [Windows.UI.Notifications.Management.UserNotificationListenerAccessStatus]
$access = Invoke-Async $listener.RequestAccessAsync() $accessType

if ($access -ne 'Allowed') {
    Write-Error (
        "Notification access denied ($access).`n" +
        "Grant it in Settings > Privacy > Notifications, then re-run."
    )
    exit 1
}

# ---- state tracking ---------------------------------------------------------

function Get-LastId {
    if (Test-Path $statePath) {
        return [uint32]((Get-Content $statePath -Raw).Trim())
    }
    return [uint32]0
}

function Save-LastId([uint32]$id) {
    Set-Content -Path $statePath -Value $id -NoNewline
}

# ---- POST to /notify --------------------------------------------------------

function Send-ToRelay([string]$chat, [string]$text, [long]$postedAtMs) {
    $payload = @{
        app      = "jp.naver.line.android"
        chat     = $chat
        text     = $text
        postedAt = $postedAtMs
    } | ConvertTo-Json -Compress

    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)

    try {
        $resp = Invoke-RestMethod -Uri $notifyUrl -Method POST `
            -Body $bodyBytes `
            -Headers @{
                "Authorization" = "Bearer $notifySecret"
                "Content-Type"  = "application/json; charset=utf-8"
            } `
            -TimeoutSec 10
        Write-Verbose "  -> stored=$($resp.stored)"
    } catch {
        Write-Warning "  -> POST failed: $_"
    }
}

# ---- main loop --------------------------------------------------------------

function Read-Notifications {
    $lastId   = Get-LastId
    $highestId = $lastId
    $count    = 0

    $listType = [System.Collections.Generic.IReadOnlyList[Windows.UI.Notifications.UserNotification]]
    $toastKind = [Windows.UI.Notifications.NotificationKinds]::Toast
    $notifications = Invoke-Async ($listener.GetNotificationsAsync($toastKind)) $listType

    foreach ($n in $notifications) {
        if ($n.Id -le $lastId) { continue }
        $highestId = [Math]::Max($highestId, $n.Id)

        # Filter for LINE — check the app's display name so both the Store
        # version and the standalone installer are covered.
        try {
            $appName = $n.AppInfo.DisplayInfo.DisplayName
        } catch { continue }
        if ($appName -ne "LINE") { continue }

        # Extract title (chat name) and body (message text) from the toast XML.
        try {
            $binding = $n.Notification.Visual.GetBinding(
                [Windows.UI.Notifications.KnownNotificationBindings]::ToastGeneric
            )
            if (-not $binding) { continue }

            $texts = $binding.GetTextElements()
            $title = if ($texts.Count -gt 0) { $texts[0].Text } else { $null }
            $body  = if ($texts.Count -gt 1) { $texts[1].Text } else { $null }
        } catch { continue }

        if (-not $title -or -not $body) { continue }

        $postedMs = [long]$n.CreationTime.ToUnixTimeMilliseconds()

        if ($VerbosePreference -eq 'Continue') {
            $preview = if ($body.Length -gt 60) { $body.Substring(0, 60) + "..." } else { $body }
            Write-Host "$($n.Id): ${title}: $preview"
        }

        Send-ToRelay -chat $title -text $body -postedAtMs $postedMs
        $count++
    }

    if ($highestId -gt $lastId) {
        Save-LastId $highestId
    }

    return $count
}

# ---- entry point ------------------------------------------------------------

if ($Once) {
    $n = Read-Notifications
    Write-Host "Forwarded $n LINE notification(s)."
} else {
    Write-Host "Relaying LINE notifications. Ctrl-C to stop."
    try {
        while ($true) {
            Read-Notifications | Out-Null
            Start-Sleep -Seconds $PollSeconds
        }
    } catch {
        Write-Host "`nStopped."
    }
}
