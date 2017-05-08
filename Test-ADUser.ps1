function Test-ADUser {
    [CmdletBinding()]
    param (
        [alias('UserName')]
        [Parameter(Mandatory=$false,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string[]]$Identity = $env:USERNAME
        )

    begin {
        Write-Verbose -Message 'Gathering a list of expired user accounts.'
        $ExpiredUsers = Search-ADAccount -AccountExpired -UsersOnly -ResultSetSize $null
        }
    process {
    
        foreach ($Id in $Identity) {
            try {
                Write-Verbose -Message "Querying for user $Id"
                $User = Get-ADUser -Identity $Id -ErrorAction Stop
                $UserProperties = [ordered]@{
                    Username = $User.samaccountname
                    Exists = $true
                    Enabled = $User.Enabled
                    Expired = $ExpiredUsers.samaccountname -contains $User.samaccountname
                    }
                $UserObject = New-Object -TypeName PSCustomObject -Property $UserProperties
                }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                Write-Warning "$Id does not exist in Active Directory"
                $UserProperties = [ordered]@{
                    Username = $Id
                    Exists = $false
                    Enabled = $null
                    Expired = $null
                    }
                $UserObject = New-Object -TypeName PSCustomObject -Property $UserProperties

                }
            catch {
                Write-Error "Some other error $Error[0].Exception.Message"
                }

            $UserObject        
        
            }
    
        }
    end {}
}