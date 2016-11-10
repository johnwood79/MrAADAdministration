<#
.Synopsis
   Send-ADUserPasswordExpirationNotification gets a list of users whose passwords are expiring
   and sends the user a email notification.
.DESCRIPTION
   Send-ADUserPasswordExpirationNotification gets a list of users whose passwords are expiring
   within a given number of days. The function outputs ADUser objects and requires 
   the ActiveDirectory PowerShell module. You can use this script to run a report 
   and then send a notification to users who need to change their passwords which 
   would be particularly helpful to users who do not regularly log on to a domain 
   computer.
.NOTES
   Created by: Jason Wasser @wasserja
   Modified: 5/13/2015 03:44:26 PM 
   Changelog: 
    * rewrite to use Get-ADUserPasswordExpiration instead of internal logic
.PARAMETER Username
   Defaults to wildcard *, but you can specify a username or pattern to search for specific
   usernames.
.PARAMETER NotificationStartDay
   Specify how many days prior to expiration to trigger the notification. Default is ten.
.PARAMETER SearchBaseDN
   Specify your domain or orgranization unit by distinguished name. Defaults to current 
   domain DN.
.EXAMPLE
   Send-ADUserPasswordExpirationNotification
   Gets a list of all users in the current domain whose passwords are expiring within
   ten days and sends a notification. 
.EXAMPLE
   Send-ADUserPasswordExpirationNotification -IncludePasswordNeverExpires
   Gets a list of all users in the current domain whose passwords are expiring within
   ten days and sends a notification including users whose password never expire. 
.EXAMPLE
   Send-ADUserPasswordExpirationNotification -IncludePasswordNeverExpires -SearchBaseDN "OU=Departments,DC=Domain,DC=com"
   Gets a list of all users in the OU Departments whose passwords are expiring within
   ten days and sends a notification including users whose password never expire. 
.LINK
    Send-ADUserPasswordExpirationNotification - https://gallery.technet.microsoft.com/scriptcenter/Send-PasswordExpirationNoti-f8eb2948
.LINK
    Get-ADUserPasswordExpiration - https://gallery.technet.microsoft.com/scriptcenter/Get-ADUserPasswordExpiratio-78bdea02
.LINK
    Write-Log - https://gallery.technet.microsoft.com/scriptcenter/Write-Log-PowerShell-999c32d0
#>
function Send-ADUserPasswordExpirationNotification
{
    [CmdletBinding()]
    [Alias()]
    Param
    (
        # Username
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$Username='*',

        # How many days prior to expiration to trigger notification
        [int]$NotificationStartDay = 10,
        [string]$NotificationSenderAddress='no-reply@domain.com',
        [string]$NotificationSubject='Your password is about to expire',
        [string]$SMTPServer='smtp.domain.com',
        [string]$SearchBaseDN,
        [string[]]$ExpiringPasswordUserList = @(),
        [string]$SMTPUsername = 'anonymous',
        [string]$SMTPPassword = 'anonymous',
        [string]$ReportMessageBody = 'Please see attached for a list of users with an expiring password',
        [string]$ReportSubject='List of Users with Expiring Password',
        [string]$ReportTo='it@domain.com',
        [string]$ReportFrom='mrautomaton@domain.com',
        [string]$LogFileName = "C:\Logs\Send-PasswordExpiringNotification-$(Get-Date -Format 'yyyyMMddhhmmss').log",
        [switch]$IncludePasswordNeverExpires=$false
    )

    Begin
    {
        # Begin Logging
        Write-Log "--------------------------------------------" -Path $LogFileName
        Write-Log "Beginning $($MyInvocation.InvocationName) on $($env:COMPUTERNAME) by $env:USERDOMAIN\$env:USERNAME" -Path $LogFileName
                 
        # SMTP Authentication
        $SecurePassword = ConvertTo-SecureString -String $SMTPPassword -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential($SMTPUsername,$SecurePassword)
    }
    Process
    {
        
        Write-Log -Message "Getting list of users." -Path $LogFileName
        $Users = Get-ADUserPasswordExpiration -Username $Username -NotificationStartDay $NotificationStartDay -SearchBaseDN $SearchBaseDN -IncludePasswordNeverExpires $IncludePasswordNeverExpires
                
        Write-Log -Message "Processing list of users for password expiration notification" -LogPath $LogFileName
        foreach ($User in $Users) {
            $samaccountname = $user.samaccountname

            # Checking for Password Policy for user to calculate when password expires.
            $PSO = Get-ADUserResultantPasswordPolicy -Identity $samaccountname
            if ($PSO) {
                $expirydate = ($User.PasswordLastSet).AddDays($PSOMaxPasswordAge)
                }
            else {
                $expirydate = ($User.PasswordLastSet).AddDays((Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days)            
                }
            $delta = ($expirydate - (Get-Date)).Days


            Write-Log "$samaccountname password is expiring within $delta days." -LogPath $LogFileName          
            $expiringpassusers += $samaccountname
            if ($User.mail) {
                Write-Log "$samaccountname has email. Sending notification." -LogPath $LogFileName
                $mailBody = "Dear " + $user.GivenName + ",`r`n`r`n"            
                $mailBody += "Your Windows password for account $samaccountname will expire after $delta days. You will need to change your password to keep using your account. You will continue to receive a daily reminder until you do change it. `r`n`r`n"            
                $mailBody += "If you need any help resetting your password please contact our helpdesk at 555.555.5555 or internally at ext. 5555. `r`n`r`n" 
                $mailBody += "`r`n`r`n IT Department"     
                $usermailaddress = $user.mail            
                Send-MailMessage -To $usermailaddress -From $NotificationSenderAddress -Subject $NotificationSubject -SmtpServer $SMTPserver -Body $mailBody -Credential $Credential
                }
            else {
                Write-Log -Message "$samaccountname does not have an email address." -LogPath $LogFileName
                }
            }            
    }
    
    End
    {       
        # Clean up
        Write-Log "$($MyInvocation.InvocationName) complete." -Path $LogFileName -Level Info
        Write-Log "--------------------------------------------" -Path $LogFileName -Level Info
        
        # Sending Report
        if ($expiringpassusers) {
            Write-Log "Sending report of all users with expiring passwords to $ReportTo" -LogPath $LogFileName
            Send-MailMessage -To $ReportTo -From $ReportFrom -Subject $ReportSubject -Body $ReportMessageBody -SmtpServer $SMTPserver -Credential $Credential -Attachments $LogFileName
            }
        else {
            Write-Log -Message "No Users with expiring passwords." -LogPath $LogFileName
            }
    }
}