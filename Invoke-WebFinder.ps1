<#
Quick and Easy Web Interface Scanner.
This script scans a given vlan for web interfaces and outputs a HTML file containing links to all available sites, including the title of the site and the engine on which it is built.
this is designed to enable a quick overview of all websites in a network, potentially finding sites with default credentials \ vulnerable versions.
the script also supports AD enumiration for web scaninig of computer accounts

notes:
    default ports are 80 and 443
    recommeded to run with -noPing option if the number of ports is less than 5 (faster)
    output is at C:\Temp\WebFinder

usage:
    scan vlan
        Invoke-WebFinder -List c:\ListofIps.txt 
        Invoke-WebFinder -Range 10.0.10.1-255 -NoPing
        Invoke-WebFInder -Range 10.0.10.1-255 -HttpPorts 80,8080 -HttpsPorts 443,8443

    scan computer names taken from AD:
        Invoke-WebFinder

#>



function New-InMemoryModule
{
    [OutputType([Reflection.Emit.ModuleBuilder])]
    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

function Test-Server {
    <#
        .SYNOPSIS
        Tests a connection to a remote server.
        
        .DESCRIPTION
        This function uses either ping (test-connection) or RPC
        (through WMI) to test connectivity to a remote server.

        .PARAMETER Server
        The hostname/IP to test connectivity to.

        .OUTPUTS
        $True/$False
        
        .EXAMPLE
        > Test-Server -Server WINDOWS7
        Tests ping connectivity to the WINDOWS7 server.

        .EXAMPLE
        > Test-Server -RPC -Server WINDOWS7
        Tests RPC connectivity to the WINDOWS7 server.

        .LINK
        http://gallery.technet.microsoft.com/scriptcenter/Enhanced-Remote-Server-84c63560
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)] 
        [String] 
        $Server,
        
        [Switch]
        $RPC
    )
    
    if ($RPC){
        $WMIParameters = @{
                        namespace = 'root\cimv2'
                        Class = 'win32_ComputerSystem'
                        ComputerName = $Name
                        ErrorAction = 'Stop'
                      }
        if ($Credential -ne $null)
        {
            $WMIParameters.Credential = $Credential
        }
        try
        {
            Get-WmiObject @WMIParameters
        }
        catch { 
            Write-Verbose -Message 'Could not connect via WMI'
        } 
    }
    # otherwise, use ping
    else{
        Test-Connection -ComputerName $Server -count 1 -Quiet
    }
}


function Get-ShuffledArray {
    <#
        .SYNOPSIS
        Returns a randomly-shuffled version of a passed array.
        
        .DESCRIPTION
        This function takes an array and returns a randomly-shuffled
        version.
        
        .PARAMETER Array
        The passed array to shuffle.

        .OUTPUTS
        System.Array. The passed array but shuffled.
        
        .EXAMPLE
        > $shuffled = Get-ShuffledArray $array
        Get a shuffled version of $array.

        .LINK
        http://sqlchow.wordpress.com/2013/03/04/shuffle-the-deck-using-powershell/
    #>
    [CmdletBinding()]
    param( 
        [Array]$Array 
    )
    Begin{}
    Process{
        $len = $Array.Length
        while($len){
            $i = Get-Random ($len --)
            $tmp = $Array[$len]
            $Array[$len] = $Array[$i]
            $Array[$i] = $tmp
        }
        $Array;
    }
}


function Get-NetCurrentUser {
    <#
        .SYNOPSIS
        Gets the name of the current user.
        
        .DESCRIPTION
        This function returns the username of the current user context,
        with the domain appended if appropriate.
        
        .OUTPUTS
        System.String. The current username.
        
        .EXAMPLE
        > Get-NetCurrentUser
        Return the current user.
    #>
    
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}


function Get-NetDomain {
    <#
        .SYNOPSIS
        Returns the name of the current user's domain.
        
        .DESCRIPTION
        This function utilizes ADSI (Active Directory Service Interface) to
        get the currect domain root and return its distinguished name.
        It then formats the name into a single string.
        
        .PARAMETER Base
        Just return the base of the current domain (i.e. no .com)

        .OUTPUTS
        System.String. The full domain name.
        
        .EXAMPLE
        > Get-NetDomain
        Return the current domain.

        .EXAMPLE
        > Get-NetDomain -base
        Return just the base of the current domain.

        .LINK
        http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
    #>
    
    [CmdletBinding()]
    param(
        [Switch]
        $Base
    )
    
    # just get the base of the domain name
    if ($Base){
        $temp = [string] ([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.'
        $parts = $temp.split('.')
        $parts[0..($parts.length-2)] -join '.'
    }
    else{
        ([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.'
    }
}


function Get-NetComputers {
    <#
        .SYNOPSIS
        Gets an array of all current computers objects in a domain.
        
        .DESCRIPTION
        This function utilizes adsisearcher to query the current AD context 
        for current computer objects. Based off of Carlos Perez's Audit.psm1 
        script in Posh-SecMod (link below).
        
        .PARAMETER HostName
        Return computers with a specific name, wildcards accepted.

        .PARAMETER SPN
        Return computers with a specific service principal name, wildcards accepted.

        .PARAMETER OperatingSystem
        Return computers with a specific operating system, wildcards accepted.

        .PARAMETER ServicePack
        Return computers with a specific service pack, wildcards accepted.

        .PARAMETER FullData
        Return full user computer objects instead of just system names (the default).

        .PARAMETER Domain
        The domain to query for computers.

        .OUTPUTS
        System.Array. An array of found system objects.

        .EXAMPLE
        > Get-NetComputers
        Returns the current computers in current domain.

        .EXAMPLE
        > Get-NetComputers -SPN mssql*
        Returns all MS SQL servers on the domain.

        .EXAMPLE
        > Get-NetComputers -Domain testing
        Returns the current computers in 'testing' domain.

        > Get-NetComputers -Domain testing -FullData
        Returns full computer objects in the 'testing' domain.

        .LINK
        https://github.com/darkoperator/Posh-SecMod/blob/master/Audit/Audit.psm1
    #>
    
    [CmdletBinding()]
    Param (
        [string]
        $HostName = '*',

        [string]
        $SPN = '*',

        [string]
        $OperatingSystem = '*',

        [string]
        $ServicePack = '*',

        [Switch]
        $FullData,

        [string]
        $Domain
    )

    # if a domain is specified, try to grab that domain
    if ($Domain){

        # try to grab the primary DC for the current domain
        try{
            $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
        }
        catch{
            $PrimaryDC = $Null
        }

        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"

            # if we could grab the primary DC for the current domain, use that for the query
            if($PrimaryDC){
                $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn") 
            }
            else{
                # otherwise try to connect to the DC for the target domain
                $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            }

            # create the searcher object with our specific filters
            if ($ServicePack -ne '*'){
                $CompSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack)(servicePrincipalName=$SPN))"
            }
            else{
                # server 2012 peculiarity- remove any mention to service pack
                $CompSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(servicePrincipalName=$SPN))"
            }
            
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        # otherwise, use the current domain
        if ($ServicePack -ne '*'){
            $CompSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack)(servicePrincipalName=$SPN))"
        }
        else{
            # server 2012 peculiarity- remove any mention to service pack
            $CompSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(servicePrincipalName=$SPN))"
        }
    }
    
    if ($CompSearcher){
        
        # eliminate that pesky 1000 system limit
        $CompSearcher.PageSize = 200
        
        $CompSearcher.FindAll() | ForEach-Object {
            # return full data objects
            if ($FullData){
                $_.properties
            }
            else{
                # otherwise we're just returning the DNS host name
                $_.properties.dnshostname
            }
        }
    }
}

function Invoke-WebFinder{

    [CmdletBinding()]
    param(
        [String]
        $Range,

        [Switch]
        $NoPing,

        [String]
        $List,

        [String[]]
        $HttpPorts=80,

        [String[]]
        $HttpsPorts=443,

        [Int]
        $MaxThreads = 255
    )

    #########################################################################################################################################################################
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $Hosts = @()
    if($List)
    {
        $Hosts = ReadTargetsFromFile -file $List
        Write-Output $Hosts
    }  
    if($Range)
    {
        $Hosts = Range-toHosts -ip_range $Range
    }    

    if($Range){
        $temp_file = "c:\temp\WebFinder\$Range.txt"
        $final_result_file = "c:\temp\WebFinder\$Range.htm"}
    if($list){
        $temp_file = "c:\temp\WebFinder\FromFile.txt"
        $final_result_file = "c:\temp\WebFinder\FromFile.htm"
    }
    if(!$list -and !$Range){
        $temp_file = "c:\temp\WebFinder\domain.txt"
        $final_result_file = "c:\temp\WebFinder\$domain.htm"}

    New-Item -Path "c:\temp\WebFinder" -ItemType Directory -Force | out-null
    New-item -Path "$temp_file" -ItemType File -Force > $null   
    #########################################################################################################################################################################

    $CurrentUser = Get-NetCurrentUser
    $targetDomain = Get-NetDomain
    $servers = @()
    
    # IP range or domain enum
    if($Range){
        Write-Output "Hosts taken from IP range"
        $servers = $Hosts
    }
    if($list){
         Write-Output "Hosts taken from List"
         Write-Output $Hosts
        $servers = $Hosts
    }
    if(!$list -and !$Range){
        Write-Output "Quering Hosts from domain"
        $servers = Get-NetComputers -Domain $targetDomain
    }
    
    # randomize the server list
    $servers = Get-ShuffledArray $servers
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        return $null
    }

    # THIS SCRIPT BLOCK WILL RUN ON ONE TARGET (not multiple)
    $EnumServerBlock = {
        param($Server, $NoPing, $temp_file, $HttpPorts, $HttpsPorts)
        # optionally check if the server is up first
        $up = $true
        if(-not $NoPing){
            $up = Test-Connection -ComputerName $Server -count 1 -Quiet
        }
        if($up){
            foreach($HttpPort in $HttpPorts)
            {
                $HTTP_URI = "http://$server"+':'+"$HttpPort/"
                try
                {
                    $Response1 = Invoke-WebRequest -URI $HTTP_URI -TimeoutSec 10
                    if ($Response1.StatusCode -eq "200")
                    {
                        $service = $Response1.Headers["Server"]
                        $Response1.Content -match "<title>(?<title>.*)</title>"
                        $Titel = $matches['title']
                        Write-Output "$HTTP_URI|$Titel ($service)" >> $temp_file
                    }
                }
                catch{}
            }

            foreach($HttpsPort in $HttpsPorts)
            {
                $HTTPs_URI = "https://$server"+':'+"$HttpsPort/"
                try
                {
                   add-type "using System.Net; using System.Security.Cryptography.X509Certificates; public class TrustAllCertsPolicy : ICertificatePolicy {public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {return true;}}"
                  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                  $Response2 = Invoke-WebRequest -URI $HTTPS_URI -TimeoutSec 10

                    if ($Response2.StatusCode -eq "200")
                    {
                        $service = $Response2.Headers["Server"]
                        $Response2.Content -match "<title>(?<title>.*)</title>" 
                        $Titel = $matches['title']
                        Write-Output "$HTTPS_URI|$Titel ($service)" >>  $temp_file
                    }
                }
                catch{}
            }
        }
        }

        $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)   
        $pool.Open()
        $jobs = @()   
        $ps = @()   
        $wait = @()
        $i = 0
        # How many servers
        $record_count = $servers.Length
        Write-Output "Scanning $record_count Hosts"

        #Loop through the endpoints starting a background job for each endpoint
        foreach ($server in $servers)
        {
            # Show Progress
            $record_progress = [int][Math]::Ceiling((($i / $record_count) * 100))
            Write-Progress -Activity "Scanning" -PercentComplete $record_progress -Status "Scan - $record_progress%" -Id 1;

            while ($($pool.GetAvailableRunspaces()) -le 0) 
            {
                Start-Sleep -milliseconds 500
            }
    
            # create a "powershell pipeline runner"   
            $ps += [powershell]::create()

            # assign our pool of 3 runspaces to use   
            $ps[$i].runspacepool = $pool

            # command to run
            [void]$ps[$i].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('NoPing', $NoPing).AddParameter('temp_file', $temp_file).AddParameter('HTTPPorts', $HttpPorts).AddParameter('HTTPsPorts', $HttpsPorts)
            #[void]$ps[$i].AddParameter('ping', $ping)
    
            # start job
            $jobs += $ps[$i].BeginInvoke();
     
            # store wait handles for WaitForAll call   
            $wait += $jobs[$i].AsyncWaitHandle
    
            $i++
        }

        $waitTimeout = get-date

        while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(get-date) - $waitTimeout).totalSeconds) -gt 60) {
                Start-Sleep -milliseconds 500
            } 
  
        # end async call   
        for ($y = 0; $y -lt $i; $y++) {     
  
            try 
            {   
                # complete async job   
                $ScanResults += $ps[$y].EndInvoke($jobs[$y])   
  
            } 
            catch 
            {   
       
                # oops-ee!   
                write-warning "error: $_"  
            }
    
            finally 
            {
                $ps[$y].Dispose()
            }    
        }
        #########################################################################################################################################################################
        Write-Output "finished ALL"
        $html = ConvertToHTMLLink($temp_file, $output_file)
        Add-Type -AssemblyName System.Web
        [System.Web.HttpUtility]::HtmlDecode($html) | Out-File  "$final_result_file"
        $sw.Stop()
        $time=$sw.Elapsed.TotalSeconds 
        Write-Output "Execution time: $time"
        #########################################################################################################################################################################

        $pool.Dispose()
    }

Function ConvertToHTMLLink($path, $output_file){
    # create an html page with links to all found web pages
    # (reads C:\temp\WebFinder\$ip_range.txt and creates C:\temp\WebFinder\$ip_range.htm)
    $Links_hashtable = @{}
    foreach($Line in Get-Content -Path  "$path")
    {
       $Links_hashtable[$Line.Split("|")[0]] = $Line.Split("|")[1]
    }
    $Header = "<style>TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}TD {border-width: 1px; padding: 15px; border-style: solid; border-color: black;}</style>"
    $Links_hashtable.GetEnumerator() | Select-Object Name, Value | ConvertTo-HTML -Property *,@{Label="Link";Expression={"<a href='$($_.Name)'>$($_.Name)</a>"}} -Head $Header
}


Function Range-toHosts{
    # takes user input and returns a list of nodes that represent the ranges of scans (allways 8 in length)
    Param
    (
        [parameter(Position=0, Mandatory=$true)]
        [String]
        $ip_range
    )

    New-Item -Path "c:\temp\WebFinder" -ItemType Directory -Force | out-null
    $Nodes = @()
    foreach($Node in $ip_range.Split("."))
    {
        if($Node -like '*-*')
        {
            $Nodes+=$Node.Split("-")[0]
            $Nodes+=$Node.Split("-")[1]
        }
        else
        {
            $Nodes+=$Node
            $Nodes+=$Node
        }
    }
    $Hosts=@()
    if($Nodes.count -ne 8){Write-Output "Bad Input"; exit}
    foreach ($nodeA in $Nodes[0]..$Nodes[1])
    {
        foreach ($nodeB in $Nodes[2]..$Nodes[3])
        {
            foreach ($nodeC in $Nodes[4]..$Nodes[5])
            {
                foreach ($nodeD in $Nodes[6]..$Nodes[7])
                {
                    $Hosts += "$nodeA.$nodeB.$nodeC.$nodeD"
                }
            }
        }
    }
    return $Hosts

}

Function ReadTargetsFromFile{
    Param
    (
        [parameter(Position=0, Mandatory=$true)]
        [String]
        $file
    )
    $Hosts=@()
    foreach($line in Get-Content $file) {
        $Hosts += "$line"
    }
    return $Hosts
}



