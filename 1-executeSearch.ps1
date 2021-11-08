
$base = $PSScriptRoot
. "$base\Utilities.ps1"

## parameters are: 
    # published start date
    # published end date
    # Severity (optional)
    # Description (optional, use * to denote a wildcard search)

ListItems `
    "2021-11-04T13:00:00:000 UTC-05:00" `
    "2021-11-08T13:36:00:000 UTC-05:00" `
    "HIGH" `
    $null