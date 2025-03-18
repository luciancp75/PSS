$CustomResults=@()
$Groups = (Get-ADGroup -filter {Name -like "*group_name*"}).NAME

$Groups | ForEach-Object {
$Group = $_

Get-AdGroupMember -Identity $Group -Recursive | Select Name,objectClass,DisplayName,EmailAddress,SAMAccountName | ForEachObject {
$CustomResult += [PSCustomObject] @{
  GroupName = $Group
  Member = $_.Name
  DisplayName = $_.DisplayName
  Class = $_.objectClass
    }
  }
}
$CustomResult | Export-CSV ".\ADGroup-members.csv" -NoTypeInformation -Encoding UTF8
