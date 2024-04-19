# Required Inputs: 
				#policyList=Comma seperated string List of WAF Policies to be updated e.g policyList=@("wafpolicy1",...)
				#policyResourceGroupsList= Comma seperated string List of Resource Groups where WAF policies are
				#rules= Comma seperated string List of WAF policy Custom Rules that needs to be updated
				#inputFileURL= URL of the input text file containing ip addresses
                $policyList=@()
                $policyResourceGroupsList=@()
                $allCustomRules=@()
                $rules=@('BlockMaliciousIP7','SIRTIPBlock6')
               # $inputFileURL=""
                #Outlook Incoming webhook url
                $teamsUrl=""
                
                # Getting IPs from a Remote file
                #$Response = Invoke-WebRequest -URI $inputFileURL -UseBasicParsing
                $localIps=Get-Content "sirt-test.txt"
                $RemoteIPsClean=@()
                $ipsNotAdded=@()
				$ipValues=@()
                #$RawIPList=$Response.Content.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)
                $RawIPList=$localIps.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)
                
                foreach($ip in $RawIPList){
                    $RemoteIPsClean +=$ip.Trim()
                }
                
                
                #Removes Duplicates if on list
                #Clean list of IP Addresses from Remote file
                $RemoteIPsClean=$RemoteIPsClean | select -Unique
                #Get list of subscriptions and set the scop to each of the subscription
                $Subscriptions=az account list | ConvertFrom-Json
                $SubscriptionId=$Subscriptions.id
                foreach($sub in $SubscriptionId){
                    # For each subscription set the scope to current Subscription & get a list of WAF's in the Current sub
                    az account set --subscription $sub
                    $rg=az group list | ConvertFrom-Json
                    $WAFList=(az network application-gateway waf-policy list | ConvertFrom-Json)
                    # Check at each WAF policy in the current sub; 
                    # If policy matches policies in the policy List and if is in specified resource-group
                    # then get the policies' Custom Rules
                    
                    
                    foreach($policy in $WAFList){
                        foreach ($rg in $policyResourceGroupsList){
                            if(($policyList -contains $policy.name) -and ($rg -eq $policy.resourceGroup)){
                                $CustomRuleList=az network application-gateway waf-policy custom-rule list --policy-name $policy.name --resource-group $rg | ConvertFrom-Json
                                ###
                                #$policy.name
                                #$rg
                                #Check every Ips based custom rule match values:
                                foreach($allrule in $allCustomRules){
                                    $allCustomRulesList=$CustomRuleList | Where name -eq $allrule
                                    $allCustomRuleName=$allCustomRulesList.name
                                    $allRulesmatchVals=$allCustomRulesList.matchConditions.matchValues
									#Remove any Duplicate Ips in Match Vals
									$allRulesmatchVals=$allRulesmatchVals | select -Unique
									$ipValues +=$allRulesmatchVals	
								}
                                # Iterate through each custom rule and get the rule that matches rule to update
                                
                                foreach($rule in $rules){
                                    $CustomRulesList=$CustomRuleList | Where name -eq $rule
                                    $CustomRuleName=$CustomRulesList.name
                                    $CustomRuleName
                                    $matchVals=$CustomRulesList.matchConditions.matchValues
                                    
                                    #newlistIP= Place Holder variable for list of new Ips to be added to the policy
                                    $newlistIP=@() 
                                    #For each of the Custom Rules names, check if any addressfrom remote file is in matchValues
                                    # if not, add Address to the new list
                                    
                                    foreach($cname in $CustomRuleName){
                                        foreach($Address in $RemoteIPsClean){
                                            if(($matchVals -notcontains $Address) -and ($ipValues -notcontains $Address)){
                                                $newlistIP +=$Address
                                            }
                                        }
                                        ###only add IPS not existing in all /current policies:
                                        #foreach($newIP in $newlistIP){
                                        #  if($ipValues -notcontains $newIP){
                                        #       $ipsNotAdded +=$newIP
                                        #   }
                                        #}
                                        #Remove Duplicates
                                        $newlistIP = $newlistIP | select -Unique
                                        #$ipsNotAdded = $ipsNotAdded | select -Unique
                                        #if no values to add to the list
                                        if(($newlistIP.length) -eq 0){
                                            $message="No updates to make for WAF Policy : "+$policy.name+" Custom Rule: "+$cname
                                            $payload=@{"Text"=$message}
                                            Invoke-RestMethod -Method post -ContentType 'Application/Json' -Body (ConvertTo-Json -Compress -InputObject $payload) -Uri $teamsUrl
                                        }
                                        #$newlistIP
                                        #Append addresses in the new list to the match Values
                                        # checks if the values are more than 590 then throw exception else add IPs to match values
                                        elseif((($newlistIP.length)+($matchVals.length)) -le 590){
                                            az network application-gateway waf-policy custom-rule update --name $cname --policy-name $policy.name --resource-group $rg --add matchConditions[0].matchValues $newlistIP
                                            $message="WAF Policy: "+$policy.name + "Custom Rule: "+$cname + "  Rule updated Successfully with IPs: "+$newlistIP
                                            $payload=@{"Text"=$message}
                                            Invoke-RestMethod -Method post -ContentType 'Application/Json' -Body (ConvertTo-Json -Compress -InputObject $payload) -Uri $teamsUrl
                                        }
                                        
                                        else{
                                            $message="WAF Policy: "+$policy.name + " Custom Rule: "+$cname+"  Could not be updated as it exceeds required policy Rule Length"
                                            $payload=@{"Text"=$message}
                                            Invoke-RestMethod -Method post -ContentType 'Application/Json' -Body (ConvertTo-Json -Compress -InputObject $payload) -Uri $teamsUrl
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                
                
                
                
                
