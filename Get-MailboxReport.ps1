﻿<#
.SYNOPSIS
Get-MailboxReport.ps1 - Mailbox report generation script.

.DESCRIPTION 
Generates a report of useful information for
the specified server, database, mailbox or list of mailboxes.
Use only one parameter at a time depending on the scope of
your mailbox report.

.OUTPUTS
Single mailbox reports are output to the console, while all other
reports are output to a CSV file.

.PARAMETER All
Generates a report for all mailboxes in the organization.

.PARAMETER Server
Generates a report for all mailboxes on the specified server.

.PARAMETER Database
Generates a report for all mailboxes on the specified database.

.PARAMETER File
Generates a report for mailbox names listed in the specified text file.

.PARAMETER Mailbox
Generates a report only for the specified mailbox.

.PARAMETER Filename
(Optional) Specifies the CSV file name to be used for the report.
If no file name specificed then a unique file name is generated by the script.

.PARAMETER SendEmail
Specifies that an email report with the CSV file attached should be sent.

.PARAMETER MailFrom
The SMTP address to send the email from.

.PARAMETER MailTo
The SMTP address to send the email to.

-MailServer The SMTP server to send the email through.

.EXAMPLE
.\Get-MailboxReport.ps1 -Database DB01
Returns a report with the mailbox statistics for all mailbox users in
database HO-MB-01

.EXAMPLE
.\Get-MailboxReport.ps1 -All -SendEmail -MailFrom exchangereports@exchangeserverpro.net -MailTo alan.reid@exchangeserverpro.net -MailServer smtp.exchangeserverpro.net
Returns a report with the mailbox statistics for all mailbox users and
sends an email report to the specified recipient.

.LINK
http://exchangeserverpro.com/powershell-script-create-mailbox-size-report-exchange-server-2010


* Website:	http://exchangeserverpro.com
* Twitter:	http://twitter.com/exchservpro

Additional Credits:
Chris Brown, http://www.flamingkeys.com
Boe Prox, http://learn-powershell.net/

Change Log
V1.00, 2/2/2012 - Initial version
V1.01, 27/2/2012 - Improved recipient scope settings, exception handling, and custom file name parameter.
V1.02, 16/10/2012 - Reordered report fields, added OU, primary SMTP, some specific folder stats,
                    archive mailbox info, and updated to show DAG name for databases when applicable.
V1.03, 27/05/2015 - Modified behavior of Server parameter
                - Added UseDatabaseQuotaDefaults, AuditEnabled, HiddenFromAddressListsEnabled, IssueWarningQuota, ProhibitSendQuota, ProhibitSendReceiveQuota
                - Added email functionality
                - Added auto-loading of snapin for simpler command lines in Task Scheduler
V1.04, 31/05/2015 - Fixed bug reported by some Exchange 2010 users
V1.05, 10/06/2015 - Fixed bug with date in email subject line

#>

#requires -version 2

param(
	[Parameter(ParameterSetName='database')]
    [string]$Database,

	[Parameter(ParameterSetName='file')]
    [string]$File,

	[Parameter(ParameterSetName='server')]
    [string]$Server,

	[Parameter(ParameterSetName='mailbox')]
    [string]$Mailbox,

	[Parameter(ParameterSetName='all')]
    [switch]$All,

    [Parameter( Mandatory=$false)]	
    [string]$Filename,

    [Parameter( Mandatory=$false)]
	[switch]$SendEmail,

	[Parameter( Mandatory=$false)]
	[string]$MailFrom,

	[Parameter( Mandatory=$false)]
	[string]$MailTo,

	[Parameter( Mandatory=$false)]
	[string]$MailServer,

    [Parameter( Mandatory=$false)]
    [int]$Top = 10

)

#...................................
# Variables
#...................................

$now = Get-Date

$ErrorActionPreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"

$reportemailsubject = "Exchange Mailbox Size Report - $now"
$myDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$report = @()


#...................................
# Email Settings
#...................................

$smtpsettings = @{
	To =  $MailTo
	From = $MailFrom
    Subject = $reportemailsubject
	SmtpServer = $MailServer
	}


#...................................
# Initialize
#...................................

#Try Exchange 2007 snapin first

$2007snapin = Get-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.Admin -Registered
if ($2007snapin)
{
    if (!(Get-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.Admin -ErrorAction SilentlyContinue))
    {
		Add-PSSnapin Microsoft.Exchange.Management.PowerShell.Admin
	}

	$AdminSessionADSettings.ViewEntireForest = 1
}
else
{
    #Add Exchange 2010 snapin if not already loaded in the PowerShell session
    if (Test-Path $env:ExchangeInstallPath\bin\RemoteExchange.ps1)
    {
	    . $env:ExchangeInstallPath\bin\RemoteExchange.ps1
	    Connect-ExchangeServer -auto -AllowClobber
    }
    else
    {
        Write-Warning "Exchange Server management tools are not installed on this computer."
        EXIT
    }

    Set-ADServerSettings -ViewEntireForest $true
}


#If no filename specified, generate report file name with random strings for uniqueness
#Thanks to @proxb and @chrisbrownie for the help with random string generation

if ($filename)
{
	$reportfile = $filename
}
else
{
	$timestamp = Get-Date -UFormat %Y%m%d-%H%M
	$random = -join(48..57+65..90+97..122 | ForEach-Object {[char]$_} | Get-Random -Count 6)
	$reportfile = "$mydir\MailboxReport-$timestamp-$random.csv"
}


#...................................
# Script
#...................................

#Add dependencies
Import-Module ActiveDirectory -ErrorAction STOP


#Get the mailbox list

Write-Host -ForegroundColor White "Collecting mailbox list"

if($all) { $mailboxes = @(Get-Mailbox -resultsize unlimited -IgnoreDefaultScope) }

if($server)
{
    $databases = @(Get-MailboxDatabase -Server $server)
    $mailboxes = @($databases | Get-Mailbox -resultsize unlimited -IgnoreDefaultScope)
}

if($database){ $mailboxes = @(Get-Mailbox -database $database -resultsize unlimited -IgnoreDefaultScope) }

if($file) {	$mailboxes = @(Get-Content $file | Get-Mailbox -resultsize unlimited) }

if($mailbox) { $mailboxes = @(Get-Mailbox $mailbox) }

#Get the report

Write-Host -ForegroundColor White "Collecting report data"

$mailboxcount = $mailboxes.count
$i = 0

$mailboxdatabases = @(Get-MailboxDatabase)

#Loop through mailbox list and collect the mailbox statistics
foreach ($mb in $mailboxes)
{
	$i = $i + 1
	$pct = $i/$mailboxcount * 100
	Write-Progress -Activity "Collecting mailbox details" -Status "Processing mailbox $i of $mailboxcount - $mb" -PercentComplete $pct

	$stats = $mb | Get-MailboxStatistics | Select-Object TotalItemSize,TotalDeletedItemSize,ItemCount,LastLogonTime,LastLoggedOnUserAccount
    
    if ($mb.ArchiveDatabase)
    {
        $archivestats = $mb | Get-MailboxStatistics -Archive | Select-Object TotalItemSize,TotalDeletedItemSize,ItemCount
    }
    else
    {
        $archivestats = "n/a"
    }

    $inboxstats = Get-MailboxFolderStatistics $mb -FolderScope Inbox | Where {$_.FolderPath -eq "/Inbox"}
    $sentitemsstats = Get-MailboxFolderStatistics $mb -FolderScope SentItems | Where {$_.FolderPath -eq "/Sent Items"}
    $deleteditemsstats = Get-MailboxFolderStatistics $mb -FolderScope DeletedItems | Where {$_.FolderPath -eq "/Deleted Items"}
    #FolderandSubFolderSize.ToMB()

	$lastlogon = $stats.LastLogonTime

	$user = Get-User $mb
	$aduser = Get-ADUser $mb.samaccountname -Properties Enabled,AccountExpirationDate
    
    $primarydb = $mailboxdatabases | where {$_.Name -eq $mb.Database.Name}
    $archivedb = $mailboxdatabases | where {$_.Name -eq $mb.ArchiveDatabase.Name}

	#Create a custom PS object to aggregate the data we're interested in
	
	$userObj = New-Object PSObject
	$userObj | Add-Member NoteProperty -Name "DisplayName" -Value $mb.DisplayName
	$userObj | Add-Member NoteProperty -Name "Mailbox Type" -Value $mb.RecipientTypeDetails
	$userObj | Add-Member NoteProperty -Name "Title" -Value $user.Title
    $userObj | Add-Member NoteProperty -Name "Department" -Value $user.Department
    $userObj | Add-Member NoteProperty -Name "Office" -Value $user.Office

    $userObj | Add-Member NoteProperty -Name "Total Mailbox Size (Mb)" -Value ($stats.TotalItemSize.Value.ToMB() + $stats.TotalDeletedItemSize.Value.ToMB())
	$userObj | Add-Member NoteProperty -Name "Mailbox Size (Mb)" -Value $stats.TotalItemSize.Value.ToMB()
	$userObj | Add-Member NoteProperty -Name "Mailbox Recoverable Item Size (Mb)" -Value $stats.TotalDeletedItemSize.Value.ToMB()
	$userObj | Add-Member NoteProperty -Name "Mailbox Items" -Value $stats.ItemCount

    $userObj | Add-Member NoteProperty -Name "Inbox Folder Size (Mb)" -Value $inboxstats.FolderandSubFolderSize.ToMB()
    $userObj | Add-Member NoteProperty -Name "Sent Items Folder Size (Mb)" -Value $sentitemsstats.FolderandSubFolderSize.ToMB()
    $userObj | Add-Member NoteProperty -Name "Deleted Items Folder Size (Mb)" -Value $deleteditemsstats.FolderandSubFolderSize.ToMB()

    if ($archivestats -eq "n/a")
    {
        $userObj | Add-Member NoteProperty -Name "Total Archive Size (Mb)" -Value "n/a"
	    $userObj | Add-Member NoteProperty -Name "Archive Size (Mb)" -Value "n/a"
	    $userObj | Add-Member NoteProperty -Name "Archive Deleted Item Size (Mb)" -Value "n/a"
	    $userObj | Add-Member NoteProperty -Name "Archive Items" -Value "n/a"
    }
    else
    {
        $userObj | Add-Member NoteProperty -Name "Total Archive Size (Mb)" -Value ($archivestats.TotalItemSize.Value.ToMB() + $archivestats.TotalDeletedItemSize.Value.ToMB())
	    $userObj | Add-Member NoteProperty -Name "Archive Size (Mb)" -Value $archivestats.TotalItemSize.Value.ToMB()
	    $userObj | Add-Member NoteProperty -Name "Archive Deleted Item Size (Mb)" -Value $archivestats.TotalDeletedItemSize.Value.ToMB()
	    $userObj | Add-Member NoteProperty -Name "Archive Items" -Value $archivestats.ItemCount
    }

    $userObj | Add-Member NoteProperty -Name "Audit Enabled" -Value $mb.AuditEnabled
    $userObj | Add-Member NoteProperty -Name "Email Address Policy Enabled" -Value $mb.EmailAddressPolicyEnabled
    $userObj | Add-Member NoteProperty -Name "Hidden From Address Lists" -Value $mb.HiddenFromAddressListsEnabled
    $userObj | Add-Member NoteProperty -Name "Use Database Quota Defaults" -Value $mb.UseDatabaseQuotaDefaults
    
    if ($mb.UseDatabaseQuotaDefaults -eq $true)
    {
        $userObj | Add-Member NoteProperty -Name "Issue Warning Quota" -Value $primarydb.IssueWarningQuota
        $userObj | Add-Member NoteProperty -Name "Prohibit Send Quota" -Value $primarydb.ProhibitSendQuota
        $userObj | Add-Member NoteProperty -Name "Prohibit Send Receive Quota" -Value $primarydb.ProhibitSendReceiveQuota
    }
    elseif ($mb.UseDatabaseQuotaDefaults -eq $false)
    {
        $userObj | Add-Member NoteProperty -Name "Issue Warning Quota" -Value $mb.IssueWarningQuota
        $userObj | Add-Member NoteProperty -Name "Prohibit Send Quota" -Value $mb.ProhibitSendQuota
        $userObj | Add-Member NoteProperty -Name "Prohibit Send Receive Quota" -Value $mb.ProhibitSendReceiveQuota
    }

	$userObj | Add-Member NoteProperty -Name "Account Enabled" -Value $aduser.Enabled
	$userObj | Add-Member NoteProperty -Name "Account Expires" -Value $aduser.AccountExpirationDate
	$userObj | Add-Member NoteProperty -Name "Last Mailbox Logon" -Value $lastlogon
	$userObj | Add-Member NoteProperty -Name "Last Logon By" -Value $stats.LastLoggedOnUserAccount
    

	$userObj | Add-Member NoteProperty -Name "Primary Mailbox Database" -Value $mb.Database
	$userObj | Add-Member NoteProperty -Name "Primary Server/DAG" -Value $primarydb.MasterServerOrAvailabilityGroup

	$userObj | Add-Member NoteProperty -Name "Archive Mailbox Database" -Value $mb.ArchiveDatabase
	$userObj | Add-Member NoteProperty -Name "Archive Server/DAG" -Value $archivedb.MasterServerOrAvailabilityGroup

    $userObj | Add-Member NoteProperty -Name "Primary Email Address" -Value $mb.PrimarySMTPAddress
    $userObj | Add-Member NoteProperty -Name "Organizational Unit" -Value $user.OrganizationalUnit

	
	#Add the object to the report
	$report = $report += $userObj
}

#Catch zero item results
$reportcount = $report.count

if ($reportcount -eq 0)
{
	Write-Host -ForegroundColor Yellow "No mailboxes were found matching that criteria."
}
else
{
	#Output single mailbox report to console, otherwise output to CSV file
	if ($mailbox) 
	{
		$report | Format-List
	}
	else
	{
		$report | Export-Csv -Path $reportfile -NoTypeInformation -Encoding UTF8
		Write-Host -ForegroundColor White "Report written to $reportfile in current path."
		Get-Item $reportfile
	}
}


if ($SendEmail)
{

    $topmailboxeshtml = $report | Sort "Total Mailbox Size (Mb)" -Desc | Select -First $top | Select DisplayName,Title,Department,Office,"Total Mailbox Size (Mb)" | ConvertTo-Html -Fragment

    $reporthtml = $report | ConvertTo-Html -Fragment

	$htmlhead="<html>
				<style>
				BODY{font-family: Arial; font-size: 8pt;}
				H1{font-size: 22px; font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;}
				H2{font-size: 18px; font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;}
				H3{font-size: 16px; font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;}
				TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
				TH{border: 1px solid #969595; background: #dddddd; padding: 5px; color: #000000;}
				TD{border: 1px solid #969595; padding: 5px; }
				td.pass{background: #B7EB83;}
				td.warn{background: #FFF275;}
				td.fail{background: #FF2626; color: #ffffff;}
				td.info{background: #85D4FF;}
				</style>
				<body>
                <h1 align=""center"">Exchange Server Mailbox Report</h1>
                <h3 align=""center"">Generated: $now</h3>
                <p>Report of Exchange mailboxes. Top $top mailboxes are listed below. Full list of mailboxes is in the CSV file attached to this email.</p>"
    
    $spacer = "<br />"

	$htmltail = "</body></html>"

	$htmlreport = $htmlhead + $topmailboxeshtml + $htmltail

	try
    {
        Write-Host "Sending email report..."
        Send-MailMessage @smtpsettings -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8) -Attachments $reportfile -ErrorAction STOP
        Write-Host "Finished."
    }
    catch
    {
        Write-Warning "An SMTP error has occurred, refer to log file for more details."
        $_.Exception.Message | Out-File "$myDir\get-mailboxreport-error.log"
        EXIT
    }
}