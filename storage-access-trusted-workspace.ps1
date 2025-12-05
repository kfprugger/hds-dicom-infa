$resourceId = "/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/Fabric/providers/Microsoft.Fabric/workspaces/93acd72f-a23e-4b93-968d-c139600891e7"
$tenantId = "8d038e6a-9b7d-4cb8-bbcf-e84dff156478"
$resourceGroupName = "rg-dicom"
$accountName = "saimgdcmwu3"
Add-AzStorageAccountNetworkRule -ResourceGroupName $resourceGroupName -Name $accountName -TenantId $tenantId -ResourceId $resourceId