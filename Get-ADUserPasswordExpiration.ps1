<#
.Synopsis
   Get-ADUserPasswordExpiration gets a list of users whose passwords are expiring.
.DESCRIPTION
   Get-ADUserPasswordExpiration gets a list of users whose passwords are expiring
   within a given number of days. The function outputs ADUser objects and requires 
   the ActiveDirectory PowerShell module. You can use this script to run a report 
   and then send a notification to users who need to change their passwords which 
   would be particularly helpful to users who do not regularly log on to a domain 
   computer.
.NOTES
   Created by: Jason Wasser
   Modified: 5/13/2015 
.PARAMETER Username
   Defaults to wildcard *, but you can specify a username or pattern to search for specific
   usernames.
.PARAMETER NotificationStartDay
   Specify how many days prior to expiration to trigger the notification. Default is ten.
.PARAMETER SearchBaseDN
   Specify your domain or orgranization unit by distinguished name. Defaults to current 
   domain DN.
.PARAMETER IncludePasswordNeverExpires
   By default accounts whose password never expires are excluded. Set this to true to
   include accounts that don't expire.
.EXAMPLE
   Get-ADUserPasswordExpiration
   Gets a list of all users in the current domain whose passwords are expiring within
   ten days and sends a notification. 
.EXAMPLE
   Get-ADUserPasswordExpiration -NotificationStartDay 30
   Gets a list of all users in the current domain whose passwords are expiring within
   thirty days and sends a notification. 
.EXAMPLE
   Get-ADUserPasswordExpiration -IncludePasswordNeverExpires $true
   Gets a list of all users in the current domain whose passwords are expiring within
   ten days and sends a notification including users whose password never expire. 
.EXAMPLE
   Get-ADUserPasswordExpiration -IncludePasswordNeverExpires $true -SearchBaseDN "OU=Departments,DC=Domain,DC=com"
   Gets a list of all users in the OU Departments whose passwords are expiring within
   ten days and sends a notification including users whose password never expire. 
.OUTPUTS
    Microsoft.ActiveDirectory.Management.ADUser
.LINK
    https://gallery.technet.microsoft.com/scriptcenter/Get-ADUserPasswordExpiratio-78bdea02
#>
#Requires -Modules ActiveDirectory
function Get-ADUserPasswordExpiration
{
    [CmdletBinding()]
    [Alias()]
    Param
    (
        # Username
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   ValueFromPipeline=$true,
                   Position=0)]
        [string]$Username='*',
        # How many days prior to expiration to trigger notification
        [Parameter(Mandatory=$false,
                    ValueFromPipelineByPropertyName=$false,
                    Position=1)]
        [int]$NotificationStartDay = 10,
        [Parameter(Mandatory=$false,
                    ValueFromPipelineByPropertyName=$false,
                    Position=2)]
        [string]$SearchBaseDN, 
        [Parameter(Mandatory=$false,
                    ValueFromPipelineByPropertyName=$false,
                    Position=3)]
        [bool]$IncludePasswordNeverExpires=$false
    )

    Begin
    {
        # Begin Logging
        Write-Verbose "Beginning $($MyInvocation.InvocationName) on $($env:COMPUTERNAME) by $env:USERDOMAIN\$env:USERNAME"
        
        # Get Current Domain Distinguished name if SearchBaseDN wasn't provided.
        if (!$SearchBaseDN) {
            $SearchBaseDN = (Get-ADDomain).DistinguishedName
            Write-Verbose "`$SearchBaseDN not specified, setting to $SearchBaseDN"
            }
                
        # Get Default Domain Policy
        Write-Verbose -Message "Get default domain password policy"
        $domainPolicy = Get-ADDefaultDomainPasswordPolicy            
        $passwordexpirydefaultdomainpolicy = $domainPolicy.MaxPasswordAge.Days -ne 0            

        if($passwordexpirydefaultdomainpolicy) {            
            $defaultdomainpolicyMaxPasswordAge = $domainPolicy.MaxPasswordAge.Days
            }
    }
    Process
    {
        
        # Get a list of users excluding those whose password never expires
        if ($IncludePasswordNeverExpires) {
            Write-Verbose -Message "Getting list of users excluding those whose password never expires."
            $Users = Get-ADUser -SearchBase $SearchBaseDN -Filter {Enabled -eq $true -and samaccountname -like $Username -and PasswordNeverExpires -eq $true} -Properties mail,passwordlastset,passwordneverexpires,passwordexpired
            }
        # Get a list of all users including those whose password never expires
        else {
            Write-Verbose -Message "Getting list of users."
            $Users = Get-ADUser -SearchBase $SearchBaseDN -Filter {Enabled -eq $true -and samaccountname -like $Username -and PasswordNeverExpires -eq $false} -Properties mail,passwordlastset,passwordneverexpires,passwordexpired
            }
        
        Write-Verbose -Message "Processing list of users for password expiration"
        foreach ($User in $Users) {
            $samaccountname = $user.samaccountname
            Write-Verbose -Message "Checking password policy for $samaccountname"
            $PSO = Get-ADUserResultantPasswordPolicy -Identity $samaccountname            
            if ($PSO) {                         
                $PSOpolicy = Get-ADUserResultantPasswordPolicy -Identity $samaccountname            
                $PSOMaxPasswordAge = $PSOpolicy.MaxPasswordAge.days            
                $pwdlastset = $User.PasswordLastSet
                $expirydate = ($pwdlastset).AddDays($PSOMaxPasswordAge)
                $delta = ($expirydate - (Get-Date)).Days
                $comparisonresults = (($expirydate - (Get-Date)).Days -le $notificationstartday) -AND ($delta -ge 1)
                }
            else {            
                if($passwordexpirydefaultdomainpolicy) {            
                    $pwdlastset = $User.PasswordLastSet
                    if ($pwdlastset) {
                        $expirydate = ($pwdlastset).AddDays($defaultdomainpolicyMaxPasswordAge)            
                        $delta = ($expirydate - (Get-Date)).Days            
                        $comparisonresults = (($expirydate - (Get-Date)).Days -le $notificationstartday) -AND ($delta -ge 1)                    
                        }
                    else {
                        Write-Verbose "$samaccountname has never set a password."
                        }
                    }
                }
                Write-Verbose "Checking if $samaccountname password is expiring within $NotificationStartDay days."
                if ($comparisonresults) {  
                    Write-Verbose "$samaccountname password is expiring within $NotificationStartDay days."          
                    $User
                    }
               else {
                    Write-Verbose "$samaccountname is not expiring within $NotificationStartDay days."
                    }            
            }
    }
    End
    {
        # Clean up
        Write-Verbose "$($MyInvocation.InvocationName) complete."
    }
}