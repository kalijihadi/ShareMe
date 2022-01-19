
Param
(
    [parameter(Position=0, Mandatory=$true)]
    [String]
    $ip_range
)

$Links = @{}
Get-job | Remove-Job
New-Item -Path "c:\temp\WebFinder" -ItemType Directory -Force | out-null
Write-Output '' > C:\temp\WebFinder\$ip_range.txt

$SCAN_Class_C=
{
    #scans Class C given range for http and https, extracts Title and Server headers from responce
    param($Base, $nodeA, $nodeB, $Node_C_Start, $Node_C_End, $ip_range)
    foreach ($nodeC in $Node_C_Start..$Node_C_End)
        {
            $ip = "$Base.$nodeA.$nodeB.$nodeC"
            $HTTP_URI = "http://$ip/"
            $HTTPS_URI = "https://$ip/"

            try
            {
                $Response1 = Invoke-WebRequest -URI $HTTP_URI -TimeoutSec 1
                if ($Response1.StatusCode -eq "200")
                {
                    $service = $Response1.Headers["Server"]
                    $Response1.Content -match "<title>(?<title>.*)</title>"
                    $Titel = $matches['title']
                    Write-Output "$HTTP_URI|$Titel ($service)" >>  C:\temp\WebFinder\$ip_range.txt
                }
            }
            catch{}
            try
            {
                add-type "using System.Net; using System.Security.Cryptography.X509Certificates; public class TrustAllCertsPolicy : ICertificatePolicy {public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {return true;}}"
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                $Response2 = Invoke-WebRequest -URI $HTTPS_URI -TimeoutSec 1

                if ($Response2.StatusCode -eq "200")
                {
                    $service = $Response2.Headers["Server"]
                    $Response2.Content -match "<title>(?<title>.*)</title>" 
                    $Titel = $matches['title']
                    Write-Output "$HTTPS_URI|$Titel ($service)" >>  C:\temp\WebFinder\$ip_range.txt
                }
            }
            catch{}
        }
}

Function StartScan($Nodes,$output_file){
    # scarts scaning with multithreading for each class C
    # (the speed of 1 class c scan is equivilant to 254 scans)
    
    foreach ($Base in $Nodes[0]..$Nodes[1])
    {
        foreach ($nodeA in $Nodes[2]..$Nodes[3])
        {
            foreach ($nodeB in $Nodes[4]..$Nodes[5])
            {
                $Node_C_Start = $Nodes[6]
                $Node_C_End = $Nodes[7]
                Start-Job -Scriptblock $SCAN_Class_C -ArgumentList $Base, $nodeA, $nodeB, $Node_C_Start, $Node_C_End, $ip_range -Name "$Base.$nodeA.$nodeB.$Node_C_Start-$Node_C_End"
            }
            While (Get-Job -State "Running")
            {
                Start-Sleep 3
            }
            Get-job | Remove-Job
        }
    }
}


Function ConvertToHTMLLink($output_file){
    # create an html page with links to all found web pages
    # (reads C:\temp\WebFinder\$ip_range.txt and creates C:\temp\WebFinder\$ip_range.htm)
    $Links_hashtable = @{}
    foreach($Line in Get-Content -Path  C:\temp\WebFinder\$ip_range.txt)
    {
       $Links_hashtable[$Line.Split("|")[0]] = $Line.Split("|")[1]
    }
    $Header = "<style>TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}TD {border-width: 1px; padding: 15px; border-style: solid; border-color: black;}</style>"
    $Links_hashtable.GetEnumerator() | Select-Object Name, Value | ConvertTo-HTML -Property *,@{Label="Link";Expression={"<a href='$($_.Name)'>$($_.Name)</a>"}} -Head $Header
}

Function ParseInput{
    # takes user input and returns a list of nodes that represent the ranges of scans (allways 8 in length)
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
    if($Nodes.count -ne 8){Write-Output "Bad Input"; exit}
    return $Nodes
}

$Nodes = ParseInput
StartScan $Nodes $output_file
Write-Output "finished ALL"
$html = ConvertToHTMLLink($output_file)
Add-Type -AssemblyName System.Web
[System.Web.HttpUtility]::HtmlDecode($html) | Out-File  C:\temp\WebFinder\$ip_range.htm
