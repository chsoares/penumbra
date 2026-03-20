$greeting = "Hello World"
$count = 5
function Get-Message {
    param($Name)
    # Return a greeting message
    return "Welcome $Name"
}
Write-Host $greeting
for ($i = 0; $i -lt $count; $i++) {
    Get-Message -Name "User"
}
