function ListItems {
    param (
        [Parameter(Mandatory=$true)] $startDate,
        [Parameter(Mandatory=$true)] $endDate,
        [Parameter(Mandatory=$false)] $cvssV3Severity,
        [Parameter(Mandatory=$false)] $descFilter

    )

    $allValues = @()
    try {
        $startIndex = 0
        $resultsPerPage = 2000
        $page = 0

        $params = @{}
        $params.Add("startIndex",$startIndex)
        $params.Add("resultsPerPage",$resultsPerPage)
        $params.Add("addOns","dictionaryCpes")
        $params.Add("pubStartDate",$startDate)
        $params.Add("pubEndDate",$endDate)
        $params.Add("cvssV3Severity",$cvssV3Severity)

        $shortBatch = $False

        while (!$shortBatch) {
            ## params
            $startIndex = ($resultsPerPage * $page) 
            $params.startIndex = $startIndex
            $url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
            $response = Invoke-RestMethod -Uri $url -Method GET -Body $params
            $valuesCount = $response.result.CVE_Items.Count
            $values = $response.result.CVE_Items
            
            ## pagination
            $shortBatch = ($resultsPerPage - $valuesCount) -ne 0
            
            ## append values
            $allValues += $values
            $page += 1
        }
    }
    catch {
        $null
    }
    
    #save raw CVE list
    $cveJson = $allValues | ConvertTo-Json -Depth 10
    $cveJson | Set-Content -Path '2-CVE-raw.json'
    $cleanCves = @()

    #build clean CVE list
    foreach($item in $allValues){
        $cve = $item.cve
        $impact = $item.impact
        $v3Metrics = $impact.baseMetricV3.cvssV3

        $id = $cve.CVE_data_meta.ID
        $desc = $cve.description.description_data.value
        $attackVector = $v3metrics.attackVector
        $vectorString = $v3metrics.vectorString
        $attackVector = $v3metrics.attackVector
        $attackComplexity = $v3metrics.attackComplexity
        $privilegesRequired = $v3metrics.privilegesRequired
        $userInteraction = $v3metrics.userInteraction
        $confidentialityImpact = $v3metrics.confidentialityImpact
        $baseScore = $v3metrics.baseScore
        $baseSeverity = $v3metrics.baseSeverity


        $body = [ordered]@{
            id = $id
            description = $desc
            vectorString = $vectorString
            attackVector = $attackVector
            attackComplexity = $attackComplexity
            privilegesRequired = $privilegesRequired
            userInteraction = $userInteraction
            confidentialityImpact = $confidentialityImpact
            baseScore = $baseScore
            baseSeverity = $baseSeverity
        }
        $cleanCves += $body

    }

    $cleanCvesJSON = $cleanCves | ConvertTo-Json -Depth 10
    $cleanCvesJSON | Set-Content -Path '3-CVE-clean.json'

    #build filtered CVE list
    if(!$descFilter){$descFilter = "*"}
    $filteredCves = $cleanCves | Where-Object {$_.description  -Like "$($descFilter)"}
    $filteredCvesJSON = $filteredCves | ConvertTo-Json -Depth 10
    $filteredCvesJSON | Set-Content -Path '4-CVE-filtered.json'

    # $allValues
}
