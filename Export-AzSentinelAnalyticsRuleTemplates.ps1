<#
    .SYNOPSIS
        This command will generate a CSV file containing the information about all the Azure Sentinel
        Analytic rules templates.  Place an X in the first column of the CSV file for any template
        that should be used to create a rule and then call New-RulesFromTemplateCSV.ps1 to generate
        the rules.
    .DESCRIPTION
        This command will generate a CSV file containing the information about all the Azure Sentinel
        Analytic rules templates. Place an X in the first column of the CSV file for any template
        that should be used to create a rule and then call New-RulesFromTemplateCSV.ps1 to generate
        the rules.
    .PARAMETER WorkSpaceName
        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER ResourceGroupName
        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER FileName
        Enter the file name to use.  Defaults to "ruletemplates"  ".csv" will be appended to all filenames
    .NOTES
        AUTHOR: Gary Bushey
        LASTEDIT: 16 Jan 2020
    .EXAMPLE
        Export-AzSentinelAnalyticsRuleTemplates -WorkspaceName "workspacename" -ResourceGroupName "rgname"
        In this example you will get the file named "ruletemplates.csv" generated containing all the rule templates
    .EXAMPLE
        Export-AzSentinelAnalyticsRuleTemplates -WorkspaceName "workspacename" -ResourceGroupName "rgname" -fileName "test"
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
Function Export-AzSentinelAnalyticsRuleTemplates ($workspaceName, $resourceGroupName, $filename) {

    #Setup the header for the file
    #$output = "Selected,Severity,DisplayName,Kind,Name,Description,Tactics,RequiredDataConnectors,RuleFrequency,RulePeriod,RuleThreshold,Status"
    #$output >> $filename
    
    #Setup the Authentication header needed for the REST calls
    $context = Get-AzContext
    $profile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($profile)
    $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json' 
        'Authorization' = 'Bearer ' + $token.AccessToken 
    }
    
    $SubscriptionId = (Get-AzContext).Subscription.Id

    #Load the templates so that we can copy the information as needed
    #$url = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/alertruletemplates?api-version=2020-05-01"
    $url = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/alertruletemplates?api-version=2019-01-01-preview"
	#echo $url
    $results = (Invoke-RestMethod -Method "Get" -Uri $url -Headers $authHeader ).value

    foreach ($result in $results) {
        #Escape the description field so it does not cause any issues with the CSV file
        $description = $result.properties.Description
        #Replace any double quotes.  Commas are already taken care of
        $description = $description -replace '"', '""'

        #Generate the list of data connectors.  Using the pipe as the 
        #delimiter since it does not appear in any data connector name
        $requiredDataConnectors = ""
        foreach ($dc in $result.properties.requiredDataConnectors) {
            $requiredDataConnectors += $dc.connectorId + "|" 
        }
        #If we have an entry, remove the last pipe character
        if ("" -ne $requiredDataConnectors) {
            $requiredDataConnectors = $requiredDataConnectors.Substring(0, $requiredDataConnectors.length - 1)
        }

        #Generate the list of tactics.  Using the pipe as the 
        #delimiter since it does not appear in any data connector name
        $tactics = ""
        foreach ($tactic in $result.properties.tactics) { $tactics += $tactic + "|" }
        #If we have an entry, remove the last pipe character
        if ("" -ne $tactics) {
            $tactics = $tactics.Substring(0, $tactics.length - 1)
        }

        #Translate the query frequency and period text into something a bit more readable.  
        #Handles simple translations only.
        $frequencyText = ConvertISO8601ToText -queryFrequency $result.properties.queryFrequency  -type "Frequency"
        $queryText = ConvertISO8601ToText -queryFrequency $result.properties.queryPeriod -type "Query"

        #Translate the threshold values into some more readable.
        $ruleThresholdText = RuleThresholdText -triggerOperator $result.properties.triggerOperator -triggerThreshold $result.properties.triggerThreshold

        #Create and output the line of information.
		$severity = $result.properties.severity
		$displayName = $result.properties.displayName
		$kind = $result.kind
		$name = $result.Name
		
		[pscustomobject]@{ Selected =" ";Severity=$severity;DisplayName=$displayName;Kind=$kind;Name=$name;Description=$description;Tactics=$tactics;RequiredDataConnectors=$requiredDataConnectors;RuleFrequency=$frequencyText;RulePeriod=$queryText;RuleThreshold=$ruleThresholdText;Status=$result.properties.status }  | Export-Csv $filename -Append -NoTypeInformation
    }
}

function ConvertISO8601ToText($queryFrequency, $type) {
    $returnText = ""
    if ($null -ne $queryFrequency) {
        #Don't need the first character since it will always be a "P"
        $tmp = $queryFrequency.Substring(1, $queryFrequency.length - 1)
        #Check the first character now.  If it is a "T" remove it
        if ($tmp.SubString(0, 1) -eq "T") {
            $tmp = $tmp.Substring(1, $tmp.length - 1)
        }
        #Get the last character to determine if we are dealing with minutes, hours, or days, and then strip it out
        $timeDesignation = $tmp.Substring($tmp.length - 1)
        $timeLength = $tmp.Substring(0, $tmp.length - 1)

        $returnText = "Every " + $timeLength
        if ($type -eq "Query") {
            $returnText = "Last " + $timeLength
        }
        switch ($timeDesignation) {
            "M" {
                $returnText += " minute"
                if ([int]$timeLength -gt 1) { $returnText += "s" }
            }
            "H" {
                $returnText += " hour" 
                if ([int]$timeLength -gt 1) { $returnText += "s" }
            }
            "D" {
                $returnText += " day" 
                if ([int]$timeLength -gt 1) { $returnText += "s" }
            }
            Default { }
        }
    }
    return $returnText
}


Function RuleThresholdText($triggerOperator, $triggerThreshold) {
    $returnText = ""
    if ($null -ne $triggerOperator) {
        $returnText = "Trigger alert if query returns "

        switch ($triggerOperator) {
            "GreaterThan" {
                $returnText += "more than"
                
            }
            "FewerThan" {
                $returnText += "less than" 
                
            }
            "EqualTo" {
                $returnText += "exactly" 
                
            }
            "NotEqualTo" {
                $returnText += "different than" 
                
            }
            Default { }
        }
        $returnText += " " + $triggerThreshold + " results"
    }
    return $returnText
}

#Execute the code
if (! $Filename.EndsWith(".csv")) {
    $FileName += ".csv"
}
Export-AzSentinelAnalyticsRuleTemplates $WorkSpaceName $ResourceGroupName $FileName 
