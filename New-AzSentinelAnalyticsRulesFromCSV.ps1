#requires -version 6.2
<#
    .SYNOPSIS
        This command will read a CSV file generated from New-RuleTemplateFile.ps1 and create
        the rules from the selected template entries. It will look for an "X" in the first column
        of each row in the file and if found it will generate a new Analytic rule from the
        selected template.
    .DESCRIPTION
        This command will read a CSV file generated from New-RuleTemplateFile.ps1 and create
        the rules from the selected template entries. It will look for an X in the first column
        of each row in the file and if found it will generate a new Analytic rule from the
        selected template.
    .PARAMETER WorkSpaceName
        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER ResourceGroupName
        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER FileName
        Enter the file name to read.  Defaults to "ruletemplates.csv"  
    .NOTES
        AUTHOR: Gary Bushey
        LASTEDIT: 16 Jan 2020
    .EXAMPLE
        New-AzSentinelAnalyticsRulesFromCSV -WorkspaceName "workspacename" -ResourceGroupName "rgname"
        In this example you will get the file named "ruletemplates.csv" generated containing all the rule templates
    .EXAMPLE
        New-AzSentinelAnalyticsRulesFromCSV -WorkspaceName "workspacename" -ResourceGroupName "rgname" -fileName "test"
        In this example you will get the file named "test.csv" generated containing all the rule templates
   
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$WorkSpaceName,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,

    [string]$FileName = "rulestemplate.csv"
)

Function New-AzSentinelAnalyticsRulesFromCSV ($workspaceName, $resourceGroupName, $filename) {
    #Set up the authentication header
    $context = Get-AzContext
    $profile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($profile)
    $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json' 
        'Authorization' = 'Bearer ' + $token.AccessToken 
    }
    
    $SubscriptionId = $context.Subscription.Id

    #Load all the rule templates so we can copy the information as needed.
    $url = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($WorkspaceName)/providers/Microsoft.SecurityInsights/alertruletemplates?api-version=2019-01-01-preview"
    $results = (Invoke-RestMethod -Method "Get" -Uri $url -Headers $authHeader ).value

    #Load the file information

    $fileContents = Import-csv  $FileName

    #Iterate through all the lines in the file
    $fileContents | ForEach-object {
        #Read the selected column (the first column in the file)
        $selected = $_.Selected

        #If this entry has been marked to be used...
        if ($selected.ToUpper() -eq "X") {
            $name = $_.Name
            $kind = $_.Kind
            $displayName = $_.DisplayName
            #Check to see if there is a template that matches the name (there better be!)
            $template = $results | Where-Object { $_.name -eq $name }
            #If we did find a match....
            if ($null -ne $template) {
                $body = ""
                #Depending on the type of alert we are creating, the body has different parameters
                switch ($kind) {
                    "MicrosoftSecurityIncidentCreation" {  
                        $body = @{
                            "kind"       = "MicrosoftSecurityIncidentCreation"
                            "properties" = @{
                                "enabled"       = "true"
                                "productFilter" = $template.properties.productFilter
                                "displayName"   = $template.properties.displayName
                            }
                        }
                    }
                    "Scheduled" {
                        $body = @{
                            "kind"       = "Scheduled"
                            "properties" = @{
                                "enabled"               = "true"
                                "alertRuleTemplateName" = $template.name
                                "displayName"           = $template.properties.displayName
                                "description"           = $template.properties.description
                                "severity"              = $template.properties.severity
                                "tactics"               = $template.properties.tactics
                                "query"                 = $template.properties.query
                                "queryFrequency"        = $template.properties.queryFrequency
                                "queryPeriod"           = $template.properties.queryPeriod
                                "triggerOperator"       = $template.properties.triggerOperator
                                "triggerThreshold"      = $template.properties.triggerThreshold
                                "suppressionDuration"   = "PT5H"  #Azure Sentinel requires a value here 
                                "suppressionEnabled"    = $false
                            }
                        }
                    }
                    "MLBehaviorAnalytics" {
                        if ($template.properties.status -eq "Available") {
                            $body = @{
                                "kind"       = "MLBehaviorAnalytics"
                                "properties" = @{
                                    "enabled"               = "true"
                                    "alertRuleTemplateName" = $template.name
                                }
                            }
                        }
                    }
                    "Fusion" {
                        if ($template.properties.status -eq "Available") {
                            $body = @{
                                "kind"       = "Fusion"
                                "properties" = @{
                                    "enabled"               = "true"
                                    "alertRuleTemplateName" = $template.name
                                }
                            }
                        }
                    }
                    Default { }
                }
                #If we have created the body...
                if ("" -ne $body) {
                    #Create the GUId for the alert and create it.
                    $guid = (New-Guid).Guid
                    #Create the URI we need to create the alert.
                    $uri = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/alertRules/$($guid)?api-version=2019-01-01-preview"
                    try {
                        Write-Host "Attempting to create rule $($displayName)"
                        $verdict = Invoke-RestMethod -Uri $uri -Method Put -Headers $authHeader -Body ($body | ConvertTo-Json -EnumsAsStrings)
                        Write-Output "Succeeded"
                    }
                    catch {
                        #The most likely error is that there is a missing dataset. There is a new
                        #addition to the REST API to check for the existance of a dataset but
                        #it only checks certain ones.  Hope to modify this to do the check
                        #before trying to create the alert.
                        $errorReturn = $_
                        Write-Error $errorReturn
                    }
                    #This pauses for 5 second so that we don't overload the workspace.
                    Start-Sleep -Seconds 5
                }
            }
        }
    }
}

#Execute the code
if (! $Filename.EndsWith(".csv")) {
    $FileName += ".csv"
}
New-AzSentinelAnalyticsRulesFromCSV $WorkSpaceName $ResourceGroupName $FileName 

