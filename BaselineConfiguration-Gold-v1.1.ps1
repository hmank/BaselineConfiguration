# Generated with Microsoft365DSC version 1.21.505.1
# For additional information on how to use Microsoft365DSC, please visit https://aka.ms/M365DSC
param (
    [parameter()]
    [System.Management.Automation.PSCredential]
    $GlobalAdminAccount
)

Configuration Tenantid-GC-2021-May-27-1205PM-runbook_2021-May-27-1205PM
{
    param (
        [parameter()]
        [System.Management.Automation.PSCredential]
        $GlobalAdminAccount
    )

    if ($null -eq $GlobalAdminAccount)
    {
        <# Credentials #>
        $Credsglobaladmin = Get-Credential -Message "Global Admin credentials"

    }
    else
    {
        $Credsglobaladmin = $GlobalAdminAccount
    }

    $OrganizationName = $Credsglobaladmin.UserName.Split('@')[1]
    Import-DscResource -ModuleName 'Microsoft365DSC' -ModuleVersion '1.21.505.1'

    Node localhost
    {
        AADConditionalAccessPolicy 6f756624-d138-4fde-b170-98777d0b1622
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @("Block");
            ClientAppTypes                           = @("ExchangeActiveSync","Browser","MobileAppsAndDesktopClients","Other");
            CloudAppSecurityIsEnabled                = $False;
            CloudAppSecurityType                     = "";
            DisplayName                              = "High Risky users";
            Ensure                                   = "Present";
            ExcludeApplications                      = @();
            ExcludeDevices                           = @();
            ExcludeGroups                            = @();
            ExcludeLocations                         = @();
            ExcludePlatforms                         = @();
            ExcludeRoles                             = @("Global Administrator");
            ExcludeUsers                             = @();
            GlobalAdminAccount                       = $Credsglobaladmin;
            GrantControlOperator                     = "OR";
            Id                                       = "20c98979-ce6b-4033-8e37-30a1acccd2e8";
            IncludeApplications                      = @("All");
            IncludeDevices                           = @("All");
            IncludeGroups                            = @();
            IncludeLocations                         = @("All");
            IncludePlatforms                         = @("All");
            IncludeRoles                             = @();
            IncludeUserActions                       = @();
            IncludeUsers                             = @("All");
            PersistentBrowserIsEnabled               = $False;
            PersistentBrowserMode                    = "";
            SignInFrequencyIsEnabled                 = $False;
            SignInFrequencyType                      = "";
            SignInRiskLevels                         = @("High");
            State                                    = "enabled";
            UserRiskLevels                           = @();
        }
        AADConditionalAccessPolicy 9a1dd49b-cdae-4016-84c1-c4faf4676a72
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @("Mfa");
            ClientAppTypes                           = @("Browser","MobileAppsAndDesktopClients");
            CloudAppSecurityIsEnabled                = $False;
            CloudAppSecurityType                     = "";
            DisplayName                              = "AAD_PrivRoles";
            Ensure                                   = "Present";
            ExcludeApplications                      = @();
            ExcludeDevices                           = @();
            ExcludeGroups                            = @();
            ExcludeLocations                         = @();
            ExcludePlatforms                         = @();
            ExcludeRoles                             = @();
            ExcludeUsers                             = @();
            GlobalAdminAccount                       = $Credsglobaladmin;
            GrantControlOperator                     = "OR";
            Id                                       = "0b4abc5a-e52d-4d39-9903-77bd152d13d9";
            IncludeApplications                      = @("All");
            IncludeDevices                           = @();
            IncludeGroups                            = @();
            IncludeLocations                         = @();
            IncludePlatforms                         = @();
            IncludeRoles                             = @("Global Administrator");
            IncludeUserActions                       = @();
            IncludeUsers                             = @();
            PersistentBrowserIsEnabled               = $False;
            PersistentBrowserMode                    = "";
            SignInFrequencyIsEnabled                 = $False;
            SignInFrequencyType                      = "";
            SignInRiskLevels                         = @();
            State                                    = "enabledForReportingButNotEnforced";
            UserRiskLevels                           = @();
        }
        AADConditionalAccessPolicy b1c813b7-2588-4dec-aa4f-c1953a95fa07
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @("Mfa");
            ClientAppTypes                           = @("Browser","MobileAppsAndDesktopClients","Other");
            CloudAppSecurityIsEnabled                = $True;
            CloudAppSecurityType                     = "McasConfigured";
            DisplayName                              = "Mobile Enforce Policies";
            Ensure                                   = "Present";
            ExcludeApplications                      = @();
            ExcludeDevices                           = @();
            ExcludeGroups                            = @("Exclude CA");
            ExcludeLocations                         = @();
            ExcludePlatforms                         = @("Windows","WindowsPhone");
            ExcludeRoles                             = @();
            ExcludeUsers                             = @();
            GlobalAdminAccount                       = $Credsglobaladmin;
            GrantControlOperator                     = "OR";
            Id                                       = "957750b7-925f-4240-95fa-870d8563da0f";
            IncludeApplications                      = @("All");
            IncludeDevices                           = @();
            IncludeGroups                            = @("Mobile users for WAP");
            IncludeLocations                         = @();
            IncludePlatforms                         = @("All");
            IncludeRoles                             = @();
            IncludeUserActions                       = @();
            IncludeUsers                             = @();
            PersistentBrowserIsEnabled               = $False;
            PersistentBrowserMode                    = "";
            SignInFrequencyIsEnabled                 = $False;
            SignInFrequencyType                      = "";
            SignInRiskLevels                         = @();
            State                                    = "enabled";
            UserRiskLevels                           = @();
        }
       
        AADConditionalAccessPolicy 85ea98d9-42a4-42e8-8102-32d90dd3ef95
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @("Block");
            ClientAppTypes                           = @("Browser","MobileAppsAndDesktopClients");
            CloudAppSecurityIsEnabled                = $False;
            CloudAppSecurityType                     = "";
            DisplayName                              = "Blocked Users -BlockedUsers";
            Ensure                                   = "Present";
            ExcludeApplications                      = @();
            ExcludeDevices                           = @();
            ExcludeGroups                            = @("Exclude CA");
            ExcludeLocations                         = @();
            ExcludePlatforms                         = @();
            ExcludeRoles                             = @();
            ExcludeUsers                             = @();
            GlobalAdminAccount                       = $Credsglobaladmin;
            GrantControlOperator                     = "OR";
            Id                                       = "8e5e1676-da49-4051-850d-550afca9785d";
            IncludeApplications                      = @("All");
            IncludeDevices                           = @("All");
            IncludeGroups                            = @("BlockedUsers");
            IncludeLocations                         = @();
            IncludePlatforms                         = @();
            IncludeRoles                             = @();
            IncludeUserActions                       = @();
            IncludeUsers                             = @();
            PersistentBrowserIsEnabled               = $False;
            PersistentBrowserMode                    = "";
            SignInFrequencyIsEnabled                 = $False;
            SignInFrequencyType                      = "";
            SignInRiskLevels                         = @();
            State                                    = "enabled";
            UserRiskLevels                           = @();
        }
        AADConditionalAccessPolicy bddf0861-a701-468f-af48-80d22eee0b82
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @("Mfa","CompliantDevice","DomainJoinedDevice");
            ClientAppTypes                           = @("ExchangeActiveSync","Browser","MobileAppsAndDesktopClients","Other");
            CloudAppSecurityIsEnabled                = $False;
            CloudAppSecurityType                     = "";
            DisplayName                              = "Medium Risk Users";
            Ensure                                   = "Present";
            ExcludeApplications                      = @();
            ExcludeDevices                           = @();
            ExcludeGroups                            = @("Exclude CA");
            ExcludeLocations                         = @("AllTrusted");
            ExcludePlatforms                         = @("Android","IOS","MacOS");
            ExcludeRoles                             = @();
            ExcludeUsers                             = @("GuestsOrExternalUsers");
            GlobalAdminAccount                       = $Credsglobaladmin;
            GrantControlOperator                     = "OR";
            Id                                       = "fd32e9a9-5121-46e3-b4b7-2c0c293b7f05";
            IncludeApplications                      = @("All");
            IncludeDevices                           = @("All");
            IncludeGroups                            = @();
            IncludeLocations                         = @("All");
            IncludePlatforms                         = @("All");
            IncludeRoles                             = @();
            IncludeUserActions                       = @();
            IncludeUsers                             = @("All");
            PersistentBrowserIsEnabled               = $False;
            PersistentBrowserMode                    = "";
            SignInFrequencyIsEnabled                 = $False;
            SignInFrequencyType                      = "";
            SignInRiskLevels                         = @();
            State                                    = "enabledForReportingButNotEnforced";
            UserRiskLevels                           = @("Medium");
        }
        AADConditionalAccessPolicy edf93048-de79-4ac8-bf0e-f7884c3a1f34
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @("Mfa");
            ClientAppTypes                           = @("ExchangeActiveSync","Browser","MobileAppsAndDesktopClients","Other");
            CloudAppSecurityIsEnabled                = $False;
            CloudAppSecurityType                     = "";
            DisplayName                              = "DevOpws Guest Access";
            Ensure                                   = "Present";
            ExcludeApplications                      = @();
            ExcludeDevices                           = @();
            ExcludeGroups                            = @();
            ExcludeLocations                         = @();
            ExcludePlatforms                         = @();
            ExcludeRoles                             = @();
            ExcludeUsers                             = @();
            GlobalAdminAccount                       = $Credsglobaladmin;
            GrantControlOperator                     = "OR";
            Id                                       = "54c5ab90-5aae-47be-93dd-6d1b7dfba8aa";
            IncludeApplications                      = @("7d8d8e2d-8acf-4881-a6b8-4cffa9088300","f13e5d81-b685-4eb1-a9ed-f95c40e93ce2","7e9419e3-f54c-4fa4-b1e6-a1a74b451544","e093dc36-bcbe-4c5e-ab13-0625b8bd2cd0","7d1ca907-b38a-4b1a-b2ea-061e7646962d","624741d4-e575-45a6-a45a-c47f4eb76789","c15b85ef-14e7-4ba7-bbee-118f3231da5a","1139a879-4f62-4e3d-a542-ee8d91914cfd","8b1433ae-5225-4c78-8ef2-9e003284f118","25cfe3b2-3575-4bce-a052-c2dda09a6f39","f89efd85-2fb2-4445-bde7-8a3473bdc779","c6aa8254-b8d7-4663-bb5e-b90c28cbc468","67b37b33-560b-4f6d-a99b-00d58c5ff3b8");
            IncludeDevices                           = @();
            IncludeGroups                            = @();
            IncludeLocations                         = @();
            IncludePlatforms                         = @("All");
            IncludeRoles                             = @();
            IncludeUserActions                       = @();
            IncludeUsers                             = @("GuestsOrExternalUsers");
            PersistentBrowserIsEnabled               = $False;
            PersistentBrowserMode                    = "";
            SignInFrequencyIsEnabled                 = $False;
            SignInFrequencyType                      = "";
            SignInRiskLevels                         = @();
            State                                    = "enabledForReportingButNotEnforced";
            UserRiskLevels                           = @();
        }
        AADConditionalAccessPolicy d44680d8-4a15-481a-aa58-bb2922365f1c
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @();
            ClientAppTypes                           = @("All");
            CloudAppSecurityIsEnabled                = $True;
            CloudAppSecurityType                     = "McasConfigured";
            DisplayName                              = "Secure tenant access";
            Ensure                                   = "Present";
            ExcludeApplications                      = @();
            ExcludeDevices                           = @("Compliant","DomainJoined");
            ExcludeGroups                            = @("Exclude CA","PARTNER-Resources","Partner exemption ","MCAS and CA Exemption");
            ExcludeLocations                         = @("AllTrusted");
            ExcludePlatforms                         = @("Android","IOS","MacOS");
            ExcludeRoles                             = @();
            ExcludeUsers                             = @();
            GlobalAdminAccount                       = $Credsglobaladmin;
            Id                                       = "f5628efe-14d8-4b98-ae1b-8637b1ad623b";
            IncludeApplications                      = @("All");
            IncludeDevices                           = @("All");
            IncludeGroups                            = @();
            IncludeLocations                         = @("All");
            IncludePlatforms                         = @("All");
            IncludeRoles                             = @();
            IncludeUserActions                       = @();
            IncludeUsers                             = @("All");
            PersistentBrowserIsEnabled               = $False;
            PersistentBrowserMode                    = "";
            SignInFrequencyIsEnabled                 = $True;
            SignInFrequencyType                      = "Days";
            SignInFrequencyValue                     = 5;
            SignInRiskLevels                         = @();
            State                                    = "enabled";
            UserRiskLevels                           = @();
        }
        AADConditionalAccessPolicy 5c0ec64f-be87-4259-82b3-ee85a089db9e
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @("Mfa");
            ClientAppTypes                           = @("Browser","MobileAppsAndDesktopClients","Other");
            CloudAppSecurityIsEnabled                = $False;
            CloudAppSecurityType                     = "";
            DisplayName                              = "MFA for all";
            Ensure                                   = "Present";
            ExcludeApplications                      = @();
            ExcludeDevices                           = @();
            ExcludeGroups                            = @("MCAS and CA Exemption");
            ExcludeLocations                         = @();
            ExcludePlatforms                         = @("Android","IOS","WindowsPhone");
            ExcludeRoles                             = @();
            ExcludeUsers                             = @();
            GlobalAdminAccount                       = $Credsglobaladmin;
            GrantControlOperator                     = "OR";
            Id                                       = "1c499dec-bbd0-4153-8c58-d5d4dd8e31bc";
            IncludeApplications                      = @("All");
            IncludeDevices                           = @();
            IncludeGroups                            = @();
            IncludeLocations                         = @();
            IncludePlatforms                         = @("All");
            IncludeRoles                             = @();
            IncludeUserActions                       = @();
            IncludeUsers                             = @("All");
            PersistentBrowserIsEnabled               = $False;
            PersistentBrowserMode                    = "";
            SignInFrequencyIsEnabled                 = $False;
            SignInFrequencyType                      = "";
            SignInRiskLevels                         = @();
            State                                    = "enabled";
            UserRiskLevels                           = @();
        }
        AADConditionalAccessPolicy 20162b87-af3a-4b17-b52e-27516bedbc80
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @("Block");
            ClientAppTypes                           = @("All");
            CloudAppSecurityIsEnabled                = $False;
            CloudAppSecurityType                     = "";
            DisplayName                              = "Negate Mobile ";
            Ensure                                   = "Present";
            ExcludeApplications                      = @();
            ExcludeDevices                           = @();
            ExcludeGroups                            = @("Mobile users for WAP","Exclude CA");
            ExcludeLocations                         = @();
            ExcludePlatforms                         = @();
            ExcludeRoles                             = @();
            ExcludeUsers                             = @();
            GlobalAdminAccount                       = $Credsglobaladmin;
            GrantControlOperator                     = "OR";
            Id                                       = "48abf800-c583-4129-88c5-6848d55d5e76";
            IncludeApplications                      = @("All");
            IncludeDevices                           = @();
            IncludeGroups                            = @();
            IncludeLocations                         = @();
            IncludePlatforms                         = @("Android","IOS");
            IncludeRoles                             = @();
            IncludeUserActions                       = @();
            IncludeUsers                             = @("All");
            PersistentBrowserIsEnabled               = $False;
            PersistentBrowserMode                    = "";
            SignInFrequencyIsEnabled                 = $False;
            SignInFrequencyType                      = "";
            SignInRiskLevels                         = @();
            State                                    = "enabled";
            UserRiskLevels                           = @();
        }
       
        AADGroupsSettings 55417aed-8f66-4734-bc64-84d29d7f375a
        {
            AllowGuestsToAccessGroups     = $True;
            AllowGuestsToBeGroupOwner     = $False;
            AllowToAddGuests              = $True;
            EnableGroupCreation           = $False;
            Ensure                        = "Present";
            GlobalAdminAccount            = $Credsglobaladmin;
            GroupCreationAllowedGroupName = "GRP-GroupCreators";
            GuestUsageGuidelinesUrl       = "";
            IsSingleInstance              = "Yes";
            UsageGuidelinesUrl            = "";
        }
        AADPolicy 6d36a593-71d3-40d8-ae6e-8355d3dce689
        {
            Definition            = @("{`"B2BManagementPolicy`":{`"InvitationsAllowedAndBlockedDomainsPolicy`":{`"BlockedDomains`":[]},`"AutoRedeemPolicy`":{`"AdminConsentedForUsersIntoTenantIds`":[],`"NoAADConsentForUsersFromTenantsIds`":[]}}}");
            DisplayName           = "B2BManagementPolicy";
            Ensure                = "Present";
            GlobalAdminAccount    = $Credsglobaladmin;
            Id                    = "58d5733e-5387-446e-9359-a4cf3e040195";
            IsOrganizationDefault = $True;
            Type                  = "B2BManagementPolicy";
        }
        AADTenantDetails 94769ae1-1793-449b-86e2-eeee203a02d6
        {
            GlobalAdminAccount                   = $Credsglobaladmin;
            IsSingleInstance                     = "Yes";
            MarketingNotificationEmails          = @();
            SecurityComplianceNotificationMails  = @();
            SecurityComplianceNotificationPhones = @();
            TechnicalNotificationMails           = @();
        }
        EXOAntiPhishPolicy 10f0fc30-8260-4d00-8d19-6152afc69bfb
        {
            AdminDisplayName                              = "";
            AuthenticationFailAction                      = "MoveToJmf";
            Enabled                                       = $True;
            EnableMailboxIntelligence                     = $True;
            EnableMailboxIntelligenceProtection           = $True;
            EnableOrganizationDomainsProtection           = $True;
            EnableSimilarDomainsSafetyTips                = $True;
            EnableSimilarUsersSafetyTips                  = $True;
            EnableSpoofIntelligence                       = $True;
            EnableTargetedDomainsProtection               = $True;
            EnableTargetedUserProtection                  = $True;
            EnableUnauthenticatedSender                   = $True;
            EnableUnusualCharactersSafetyTips             = $True;
            Ensure                                        = "Present";
            ExcludedDomains                               = @();
            ExcludedSenders                               = @();
            GlobalAdminAccount                            = $Credsglobaladmin;
            Identity                                      = "Standard Preset Security Policy1621971911633";
            ImpersonationProtectionState                  = "Automatic";
            MailboxIntelligenceProtectionAction           = "MoveToJmf";
            MailboxIntelligenceProtectionActionRecipients = @();
            PhishThresholdLevel                           = 2;
            TargetedDomainActionRecipients                = @();
            TargetedDomainProtectionAction                = "Quarantine";
            TargetedDomainsToProtect                      = @();
            TargetedUserActionRecipients                  = @();
            TargetedUserProtectionAction                  = "Quarantine";
            TargetedUsersToProtect                        = @();
        }
        EXOAntiPhishPolicy cf2e27b1-5df3-42f4-9e86-c4b1b67f00d7
        {
            AdminDisplayName                              = "";
            AuthenticationFailAction                      = "MoveToJmf";
            Enabled                                       = $True;
            EnableMailboxIntelligence                     = $True;
            EnableMailboxIntelligenceProtection           = $True;
            EnableOrganizationDomainsProtection           = $True;
            EnableSimilarDomainsSafetyTips                = $True;
            EnableSimilarUsersSafetyTips                  = $True;
            EnableSpoofIntelligence                       = $True;
            EnableTargetedDomainsProtection               = $False;
            EnableTargetedUserProtection                  = $True;
            EnableUnauthenticatedSender                   = $True;
            EnableUnusualCharactersSafetyTips             = $True;
            Ensure                                        = "Present";
            ExcludedDomains                               = @();
            ExcludedSenders                               = @();
            GlobalAdminAccount                            = $Credsglobaladmin;
            Identity                                      = "Office365 AntiPhish Default";
            ImpersonationProtectionState                  = "Automatic";
            MailboxIntelligenceProtectionAction           = "Quarantine";
            MailboxIntelligenceProtectionActionRecipients = @();
            PhishThresholdLevel                           = 2;
            TargetedDomainActionRecipients                = @();
            TargetedDomainProtectionAction                = "Quarantine";
            TargetedDomainsToProtect                      = @();
            TargetedUserActionRecipients                  = @();
            TargetedUserProtectionAction                  = "Quarantine";
            TargetedUsersToProtect                        = @();
        }
        EXOAntiPhishPolicy 0283a828-2b48-4a9b-9f9f-b86ef1626850
        {
            AdminDisplayName                              = "";
            AuthenticationFailAction                      = "MoveToJmf";
            Enabled                                       = $True;
            EnableMailboxIntelligence                     = $True;
            EnableMailboxIntelligenceProtection           = $True;
            EnableOrganizationDomainsProtection           = $True;
            EnableSimilarDomainsSafetyTips                = $True;
            EnableSimilarUsersSafetyTips                  = $True;
            EnableSpoofIntelligence                       = $True;
            EnableTargetedDomainsProtection               = $False;
            EnableTargetedUserProtection                  = $True;
            EnableUnauthenticatedSender                   = $True;
            EnableUnusualCharactersSafetyTips             = $True;
            Ensure                                        = "Present";
            ExcludedDomains                               = @();
            ExcludedSenders                               = @();
            GlobalAdminAccount                            = $Credsglobaladmin;
            Identity                                      = "VIP Policy";
            ImpersonationProtectionState                  = "Manual";
            MailboxIntelligenceProtectionAction           = "Quarantine";
            MailboxIntelligenceProtectionActionRecipients = @();
            PhishThresholdLevel                           = 2;
            TargetedDomainActionRecipients                = @();
            TargetedDomainProtectionAction                = "Quarantine";
            TargetedDomainsToProtect                      = @();
            TargetedUserActionRecipients                  = @();
            TargetedUserProtectionAction                  = "Quarantine";
            TargetedUsersToProtect                        = @();
        }
        EXOAtpPolicyForO365 90965eba-a959-489e-ba31-028d3c22849e
        {
            AllowClickThrough             = $False;
            BlockUrls                     = @();
            EnableATPForSPOTeamsODB       = $True;
            EnableSafeDocs                = $False;
            EnableSafeLinksForO365Clients = $True;
            Ensure                        = "Present";
            GlobalAdminAccount            = $Credsglobaladmin;
            Identity                      = "Default";
            IsSingleInstance              = "Yes";
            TrackClicks                   = $False;
        }
        EXODkimSigningConfig ef7d3274-96e7-42c2-9e81-566dc372b520
        {
            AdminDisplayName       = "";
            BodyCanonicalization   = "Relaxed";
            Enabled                = $True;
            Ensure                 = "Present";
            GlobalAdminAccount     = $Credsglobaladmin;
            HeaderCanonicalization = "Relaxed";
            Identity               = "$OrganizationName";
            KeySize                = 1024;
        }
        EXODkimSigningConfig 526470c2-5f2c-4d6a-bd38-e459b323c2a0
        {
            AdminDisplayName       = "";
            BodyCanonicalization   = "Relaxed";
            Enabled                = $True;
            Ensure                 = "Present";
            GlobalAdminAccount     = $Credsglobaladmin;
            HeaderCanonicalization = "Relaxed";
            Identity               = "gc.mail.onmicrosoft.com";
            KeySize                = 1024;
        }
        EXODkimSigningConfig fdf5d36f-e435-4b5e-bddf-c8447582d447
        {
            AdminDisplayName       = "";
            BodyCanonicalization   = "Relaxed";
            Enabled                = $True;
            Ensure                 = "Present";
            GlobalAdminAccount     = $Credsglobaladmin;
            HeaderCanonicalization = "Relaxed";
            Identity               = "gc.onmicrosoft.com";
            KeySize                = 1024;
        }
        EXODkimSigningConfig 03823204-8904-484e-9df3-8e601e97073c
        {
            AdminDisplayName       = "";
            BodyCanonicalization   = "Relaxed";
            Enabled                = $False;
            Ensure                 = "Present";
            GlobalAdminAccount     = $Credsglobaladmin;
            HeaderCanonicalization = "Relaxed";
            Identity               = "Domain.ca";
            KeySize                = 1024;
        }
        EXOHostedConnectionFilterPolicy aa3d7c01-52ee-4329-a37d-d833d06d6f8d
        {
            AdminDisplayName     = "";
            EnableSafeList       = $False;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Default";
            IPAllowList          = @();
            IPBlockList          = @();
            MakeDefault          = $False;
        }
        EXOHostedOutboundSpamFilterPolicy 556eca78-579d-46a2-ba67-89659ab6d521
        {
            AdminDisplayName                          = "Spam #34";
            BccSuspiciousOutboundAdditionalRecipients = @();
            BccSuspiciousOutboundMail                 = $True;
            Ensure                                    = "Present";
            GlobalAdminAccount                        = $Credsglobaladmin;
            Identity                                  = "Default";
            NotifyOutboundSpam                        = $True;
            NotifyOutboundSpamRecipients              = @();
        }
        EXOMalwareFilterPolicy a474e3b1-6570-41fd-b0df-f475904cb24d
        {
            Action                                 = "DeleteAttachmentAndUseDefaultAlert";
            CustomNotifications                    = $False;
            EnableExternalSenderAdminNotifications = $False;
            EnableExternalSenderNotifications      = $False;
            EnableFileFilter                       = $True;
            EnableInternalSenderAdminNotifications = $True;
            EnableInternalSenderNotifications      = $False;
            Ensure                                 = "Present";
            FileTypes                              = @("ace","ani","app","docm","exe","jar","reg","scr","vbe","vbs","ace","ade","adp","ani","app","bas","bat","chm","cmd","com","cpl","crt","docm","exe","hlp","ht","hta","inf","ins","isp","jar","job","js","jse","lnk","mda","mdb","mde","mdz","msc","msi","msp","mst","pcd","pif","reg","scr","sct","shs","url","vb","vbe","vbs","wsc","wsf","wsh");
            GlobalAdminAccount                     = $Credsglobaladmin;
            Identity                               = "Default";
            InternalSenderAdminAddress             = @();
            ZapEnabled                             = $True;
        }
        EXOMalwareFilterPolicy d8d73e9f-9c70-41a0-9bb1-c2ebdaf7b715
        {
            Action                                 = "DeleteMessage";
            CustomNotifications                    = $False;
            EnableExternalSenderAdminNotifications = $False;
            EnableExternalSenderNotifications      = $False;
            EnableFileFilter                       = $True;
            EnableInternalSenderAdminNotifications = $False;
            EnableInternalSenderNotifications      = $False;
            Ensure                                 = "Present";
            FileTypes                              = @("ace","ani","app","docm","exe","jar","reg","scr","vbe","vbs");
            GlobalAdminAccount                     = $Credsglobaladmin;
            Identity                               = "Standard Preset Security Policy1621971914952";
            ZapEnabled                             = $True;
        }
        EXOSafeAttachmentPolicy 94aa3304-e61c-4a44-a386-cac76da0df0d
        {
            Action               = "Block";
            ActionOnError        = $True;
            AdminDisplayName     = "";
            Enable               = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Default";
            Redirect             = $True;
            RedirectAddress      = @();
        }
        EXOSafeAttachmentPolicy 9342de95-e9f5-4e2a-a12a-986acf1ce031
        {
            Action               = "Block";
            ActionOnError        = $True;
            AdminDisplayName     = "";
            Enable               = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Standard Preset Security Policy1621971915343";
            Redirect             = $False;
            RedirectAddress      = "";
        }
        EXOSafeLinksPolicy ec2774e1-e15c-45a9-b1dc-1f22a411e9cf
        {
            AdminDisplayName         = "";
            DeliverMessageAfterScan  = $True;
            DoNotAllowClickThrough   = $True;
            DoNotRewriteUrls         = @();
            DoNotTrackUserClicks     = $False;
            EnableForInternalSenders = $True;
            EnableSafeLinksForTeams  = $True;
            Ensure                   = "Present";
            GlobalAdminAccount       = $Credsglobaladmin;
            Identity                 = "Standard Preset Security Policy1621971917212";
            IsEnabled                = $True;
            ScanUrls                 = $True;
        }
        EXOSafeLinksPolicy 6b085393-8790-473d-9548-de85a7a33b64
        {
            AdminDisplayName         = "";
            DeliverMessageAfterScan  = $True;
            DoNotAllowClickThrough   = $True;
            DoNotRewriteUrls         = @();
            DoNotTrackUserClicks     = $False;
            EnableForInternalSenders = $True;
            EnableSafeLinksForTeams  = $False;
            Ensure                   = "Present";
            GlobalAdminAccount       = $Credsglobaladmin;
            Identity                 = "Default";
            IsEnabled                = $True;
            ScanUrls                 = $True;
        }
        EXOSharingPolicy 1458fb69-c3b2-4244-bb2a-f8c0fc1ea846
        {
            Default              = $True;
            Domains              = @("Anonymous:CalendarSharingFreeBusyReviewer","*:CalendarSharingFreeBusySimple");
            Enabled              = $False;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Default Sharing Policy";
        }
        O365AdminAuditLogConfig 2f6b900d-bbbb-4ccd-91de-60696791890c
        {
            Ensure                          = "Present";
            GlobalAdminAccount              = $Credsglobaladmin;
            IsSingleInstance                = "Yes";
            UnifiedAuditLogIngestionEnabled = "Enabled";
        }
        O365OrgCustomizationSetting cbfb69d6-511a-4f76-8d3a-02ebd95e9b86
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            IsSingleInstance     = "Yes";
        }
        SCLabelPolicy 36689d0f-731e-4345-b448-f3d07a3abeea
        {
            AdvancedSettings     = @(
                MSFT_SCLabelSetting
                {
                    Key   = 'requiredowngradejustification'
                    Value = 'false'
                }
                MSFT_SCLabelSetting
                {
                    Key   = 'mandatory'
                    Value = 'false'
                }
                MSFT_SCLabelSetting
                {
                    Key   = 'siteandgroupmandatory'
                    Value = 'false'
                }
            );
            Comment              = "";
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Labels               = @("Test - Protected A","Test - Protected B","Test - Unclassified");
            ModernGroupLocation  = "Lab@gc.onmicrosoft.com";
            Name                 = "Test  series";
        }
        SCSensitivityLabel 92820a36-6f61-4ee5-b14d-87a2582fed6a
        {
            AdvancedSettings                   = @(
                MSFT_SCLabelSetting
                {
                    Key   = 'tooltip'
                    Value = 'Unclassified | Non classifié'
                }
                MSFT_SCLabelSetting
                {
                    Key   = 'contenttype'
                    Value = 'File  Email'
                }
            );
            ApplyContentMarkingHeaderAlignment = "Right";
            ApplyContentMarkingHeaderEnabled   = $True;
            ApplyContentMarkingHeaderFontColor = "#0000FF";
            ApplyContentMarkingHeaderFontSize  = 10;
            ApplyContentMarkingHeaderMargin    = 5;
            ApplyContentMarkingHeaderText      = "Unclassified | Non classifié";
            Comment                            = "Unclassified: of no security importance, knowledge of which, if acquired by unauthorised persons, would not result in any disadvantage or detriment to Canada or her allies.";
            Disabled                           = $False;
            DisplayName                        = "Test - Unclassified";
            Ensure                             = "Present";
            GlobalAdminAccount                 = $Credsglobaladmin;
            LocaleSettings                     = @(
                MSFT_SCLabelLocaleSettings
                {
                    LocaleKey = 'displayName'
                    Settings  = @(
                        MSFT_SCLabelSetting
                        {
                            Key   = 'default'
                            Value = 'Test - Unclassified'
                        }
                    )
                }
                MSFT_SCLabelLocaleSettings
                {
                    LocaleKey = 'tooltip'
                    Settings  = @(
                        MSFT_SCLabelSetting
                        {
                            Key   = 'default'
                            Value = 'Unclassified | Non classifié'
                        }
                    )
                }
            );
            Name                               = "Test - Unclassified";
            Priority                           = 0;
            SiteAndGroupProtectionEnabled      = $True;
            Tooltip                            = "Unclassified | Non classifié";
        }
        SCSensitivityLabel d19bbb00-3057-48f4-9aec-4ce2c64b86b4
        {
            AdvancedSettings                               = @(
                MSFT_SCLabelSetting
                {
                    Key   = 'aiplabelversion'
                    Value = '808e9a23-4f0c-448c-a454-80c0b1a5bccd'
                }
                MSFT_SCLabelSetting
                {
                    Key   = 'color'
                    Value = '#FF8C00'
                }
                MSFT_SCLabelSetting
                {
                    Key   = 'tooltip'
                    Value = 'Protected A | Protégé A'
                }
                MSFT_SCLabelSetting
                {
                    Key   = 'contenttype'
                    Value = 'File  Email  Site  UnifiedGroup'
                }
            );
            ApplyContentMarkingFooterAlignment             = "Right";
            ApplyContentMarkingFooterEnabled               = $False;
            ApplyContentMarkingFooterFontColor             = "#000000";
            ApplyContentMarkingFooterFontSize              = 10;
            ApplyContentMarkingFooterMargin                = 15;
            ApplyContentMarkingFooterText                  = "Protected A";
            ApplyContentMarkingHeaderAlignment             = "Right";
            ApplyContentMarkingHeaderEnabled               = $True;
            ApplyContentMarkingHeaderFontColor             = "#0000FF";
            ApplyContentMarkingHeaderFontSize              = 12;
            ApplyContentMarkingHeaderMargin                = 5;
            ApplyContentMarkingHeaderText                  = "Protected A | Protégé A";
            ApplyWaterMarkingEnabled                       = $False;
            ApplyWaterMarkingFontColor                     = "#000000";
            ApplyWaterMarkingFontSize                      = 1;
            ApplyWaterMarkingLayout                        = "Diagonal";
            ApplyWaterMarkingText                          = "Protected A";
            Comment                                        = "Protected: Information is categorized as `"Protected A,`" `"Protected B`" or `"Protected C`" when unauthorized disclosure could reasonably be expected to cause injury outside of the national interest: https://www.tbs-sct.gc.ca/pol/doc-eng.aspx?id=32614";
            Disabled                                       = $False;
            DisplayName                                    = "Test - Protected A";
            EncryptionDoNotForward                         = $True;
            EncryptionEnabled                              = $False;
            EncryptionPromptUser                           = $True;
            EncryptionProtectionType                       = "UserDefined";
            Ensure                                         = "Present";
            GlobalAdminAccount                             = $Credsglobaladmin;
            LocaleSettings                                 = @(
                MSFT_SCLabelLocaleSettings
                {
                    LocaleKey = 'displayName'
                    Settings  = @(
                        MSFT_SCLabelSetting
                        {
                            Key   = 'default'
                            Value = 'Test - Protected A'
                        }
                    )
                }
                MSFT_SCLabelLocaleSettings
                {
                    LocaleKey = 'tooltip'
                    Settings  = @(
                        MSFT_SCLabelSetting
                        {
                            Key   = 'default'
                            Value = 'Protected A | Protégé A'
                        }
                    )
                }
                MSFT_SCLabelLocaleSettings
                {
                    LocaleKey = 'autotooltip'
                    Settings  = @(
                        MSFT_SCLabelSetting
                        {
                            Key   = 'default'
                            Value = 'This file looks like it contains Protected A information, please review the file''s content and add the Protect A label if applicable.'
                        }
                    )
                }
            );
            Name                                           = "Test - Protected A";
            Priority                                       = 1;
            SiteAndGroupProtectionAllowAccessToGuestUsers  = $False;
            SiteAndGroupProtectionAllowEmailFromGuestUsers = $False;
            SiteAndGroupProtectionAllowFullAccess          = $True;
            SiteAndGroupProtectionAllowLimitedAccess       = $False;
            SiteAndGroupProtectionBlockAccess              = $False;
            SiteAndGroupProtectionEnabled                  = $True;
            SiteAndGroupProtectionPrivacy                  = "Private";
            Tooltip                                        = "Protected A | Protégé A";
        }
        SCSensitivityLabel 0912ecad-2508-4c4b-9168-40d45386ad6e
        {
            AdvancedSettings                               = @(
                MSFT_SCLabelSetting
                {
                    Key   = 'tooltip'
                    Value = 'Protected B | Protégé B'
                }
            );
            ApplyContentMarkingHeaderAlignment             = "Right";
            ApplyContentMarkingHeaderEnabled               = $True;
            ApplyContentMarkingHeaderFontColor             = "#0000FF";
            ApplyContentMarkingHeaderFontSize              = 12;
            ApplyContentMarkingHeaderMargin                = 5;
            ApplyContentMarkingHeaderText                  = "Protected B | Protégé B";
            Comment                                        = "Applies to information when unauthorized disclosure could reasonably be expected to cause serious injury outside the national interest, for example, loss of reputation or competitive advantage;
e.g. Treasury Board submissions, Personnel Screening Consent & Authorization, Test results, character references, conflicts of interests, eligibility for social benefits, etc.";
            Disabled                                       = $False;
            DisplayName                                    = "Test - Protected B";
            EncryptionDoNotForward                         = $True;
            EncryptionEnabled                              = $False;
            EncryptionPromptUser                           = $True;
            EncryptionProtectionType                       = "UserDefined";
            Ensure                                         = "Present";
            GlobalAdminAccount                             = $Credsglobaladmin;
            LocaleSettings                                 = @(
                MSFT_SCLabelLocaleSettings
                {
                    LocaleKey = 'displayName'
                    Settings  = @(
                        MSFT_SCLabelSetting
                        {
                            Key   = 'default'
                            Value = 'Test - Protected B'
                        }
                    )
                }
                MSFT_SCLabelLocaleSettings
                {
                    LocaleKey = 'tooltip'
                    Settings  = @(
                        MSFT_SCLabelSetting
                        {
                            Key   = 'default'
                            Value = 'Protected B | Protégé B'
                        }
                    )
                }
            );
            Name                                           = "Test - Protected B";
            Priority                                       = 2;
            SiteAndGroupProtectionAllowAccessToGuestUsers  = $True;
            SiteAndGroupProtectionAllowEmailFromGuestUsers = $False;
            SiteAndGroupProtectionAllowFullAccess          = $True;
            SiteAndGroupProtectionAllowLimitedAccess       = $False;
            SiteAndGroupProtectionBlockAccess              = $False;
            SiteAndGroupProtectionEnabled                  = $True;
            SiteAndGroupProtectionPrivacy                  = "Private";
            Tooltip                                        = "Protected B | Protégé B";
        }
        TeamsCallingPolicy f8b28f74-d693-46a1-ac9e-dbd0cd03d811
        {
            AllowCallForwardingToPhone        = $True;
            AllowCallForwardingToUser         = $True;
            AllowCallGroups                   = $True;
            AllowCloudRecordingForCalls       = $False;
            AllowDelegation                   = $True;
            AllowPrivateCalling               = $True;
            AllowTranscriptionForCalling      = $False;
            AllowVoicemail                    = "UserOverride";
            AllowWebPSTNCalling               = $True;
            AutoAnswerEnabledType             = "Disabled";
            BusyOnBusyEnabledType             = "Disabled";
            Ensure                            = "Present";
            GlobalAdminAccount                = $Credsglobaladmin;
            Identity                          = "Global";
            LiveCaptionsEnabledTypeForCalling = "DisabledUserOverride";
            MusicOnHoldEnabledType            = "Enabled";
            PreventTollBypass                 = $False;
            SafeTransferEnabled               = "Disabled";
            SpamFilteringEnabledType          = "Enabled";
        }
        TeamsCallingPolicy bdfd47cd-2739-4d6d-824a-84f261d6b4e2
        {
            AllowCallForwardingToPhone        = $False;
            AllowCallForwardingToUser         = $False;
            AllowCallGroups                   = $True;
            AllowCloudRecordingForCalls       = $False;
            AllowDelegation                   = $True;
            AllowPrivateCalling               = $True;
            AllowTranscriptionForCalling      = $False;
            AllowVoicemail                    = "AlwaysDisabled";
            AllowWebPSTNCalling               = $True;
            AutoAnswerEnabledType             = "Disabled";
            BusyOnBusyEnabledType             = "Disabled";
            Description                       = "This is a Frontline_Worker Calling policy";
            Ensure                            = "Present";
            GlobalAdminAccount                = $Credsglobaladmin;
            Identity                          = "Tag:Frontline_Worker";
            LiveCaptionsEnabledTypeForCalling = "DisabledUserOverride";
            MusicOnHoldEnabledType            = "Enabled";
            PreventTollBypass                 = $False;
            SafeTransferEnabled               = "Disabled";
            SpamFilteringEnabledType          = "Enabled";
        }
        TeamsCallingPolicy 95e41781-cfe8-4c52-8751-483f1dafe04c
        {
            AllowCallForwardingToPhone        = $True;
            AllowCallForwardingToUser         = $True;
            AllowCallGroups                   = $True;
            AllowCloudRecordingForCalls       = $False;
            AllowDelegation                   = $True;
            AllowPrivateCalling               = $True;
            AllowTranscriptionForCalling      = $False;
            AllowVoicemail                    = "UserOverride";
            AllowWebPSTNCalling               = $True;
            AutoAnswerEnabledType             = "Disabled";
            BusyOnBusyEnabledType             = "Disabled";
            Ensure                            = "Present";
            GlobalAdminAccount                = $Credsglobaladmin;
            Identity                          = "Tag:AllowCalling";
            LiveCaptionsEnabledTypeForCalling = "DisabledUserOverride";
            MusicOnHoldEnabledType            = "Enabled";
            PreventTollBypass                 = $False;
            SafeTransferEnabled               = "Disabled";
            SpamFilteringEnabledType          = "Enabled";
        }
        TeamsCallingPolicy 9bb910c1-8314-4218-9802-c959a5cd0e25
        {
            AllowCallForwardingToPhone        = $False;
            AllowCallForwardingToUser         = $False;
            AllowCallGroups                   = $False;
            AllowCloudRecordingForCalls       = $False;
            AllowDelegation                   = $False;
            AllowPrivateCalling               = $False;
            AllowTranscriptionForCalling      = $False;
            AllowVoicemail                    = "AlwaysDisabled";
            AllowWebPSTNCalling               = $True;
            AutoAnswerEnabledType             = "Disabled";
            BusyOnBusyEnabledType             = "Disabled";
            Ensure                            = "Present";
            GlobalAdminAccount                = $Credsglobaladmin;
            Identity                          = "Tag:DisallowCalling";
            LiveCaptionsEnabledTypeForCalling = "DisabledUserOverride";
            MusicOnHoldEnabledType            = "Enabled";
            PreventTollBypass                 = $False;
            SafeTransferEnabled               = "Disabled";
            SpamFilteringEnabledType          = "Enabled";
        }
        TeamsCallingPolicy 1709b5a6-858e-44f0-acdd-92279972ca97
        {
            AllowCallForwardingToPhone        = $True;
            AllowCallForwardingToUser         = $True;
            AllowCallGroups                   = $True;
            AllowCloudRecordingForCalls       = $False;
            AllowDelegation                   = $True;
            AllowPrivateCalling               = $True;
            AllowTranscriptionForCalling      = $False;
            AllowVoicemail                    = "UserOverride";
            AllowWebPSTNCalling               = $True;
            AutoAnswerEnabledType             = "Disabled";
            BusyOnBusyEnabledType             = "Disabled";
            Ensure                            = "Present";
            GlobalAdminAccount                = $Credsglobaladmin;
            Identity                          = "Tag:AllowCallingPreventTollBypass";
            LiveCaptionsEnabledTypeForCalling = "DisabledUserOverride";
            MusicOnHoldEnabledType            = "Enabled";
            PreventTollBypass                 = $True;
            SafeTransferEnabled               = "Disabled";
            SpamFilteringEnabledType          = "Enabled";
        }
        TeamsCallingPolicy af3c8427-e0fb-4630-9263-5cc4335be2d1
        {
            AllowCallForwardingToPhone        = $False;
            AllowCallForwardingToUser         = $True;
            AllowCallGroups                   = $True;
            AllowCloudRecordingForCalls       = $False;
            AllowDelegation                   = $True;
            AllowPrivateCalling               = $True;
            AllowTranscriptionForCalling      = $False;
            AllowVoicemail                    = "UserOverride";
            AllowWebPSTNCalling               = $True;
            AutoAnswerEnabledType             = "Disabled";
            BusyOnBusyEnabledType             = "Disabled";
            Ensure                            = "Present";
            GlobalAdminAccount                = $Credsglobaladmin;
            Identity                          = "Tag:AllowCallingPreventForwardingtoPhone";
            LiveCaptionsEnabledTypeForCalling = "DisabledUserOverride";
            MusicOnHoldEnabledType            = "Enabled";
            PreventTollBypass                 = $False;
            SafeTransferEnabled               = "Disabled";
            SpamFilteringEnabledType          = "Enabled";
        }
        TeamsChannelsPolicy 7307a41a-751b-4d63-8cde-d19168a8c2a1
        {
            AllowOrgWideTeamCreation    = $True;
            AllowPrivateChannelCreation = $True;
            AllowPrivateTeamDiscovery   = $True;
            Ensure                      = "Present";
            GlobalAdminAccount          = $Credsglobaladmin;
            Identity                    = "Global";
        }
        TeamsChannelsPolicy 6a9bf15e-cbea-4fdc-bf65-11789e5fd119
        {
            AllowOrgWideTeamCreation    = $True;
            AllowPrivateChannelCreation = $True;
            AllowPrivateTeamDiscovery   = $True;
            Ensure                      = "Present";
            GlobalAdminAccount          = $Credsglobaladmin;
            Identity                    = "Tag:Default";
        }
        TeamsEmergencyCallingPolicy 1db63793-45f8-462a-ac04-12e62218273e
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Global";
        }
        TeamsEmergencyCallRoutingPolicy 80a3946f-4ace-47aa-9764-9582d7a23119
        {
            AllowEnhancedEmergencyServices = $False;
            Ensure                         = "Present";
            GlobalAdminAccount             = $Credsglobaladmin;
            Identity                       = "Global";
        }
        TeamsGuestCallingConfiguration 658dff5c-d192-4acc-acb5-66278b5b1b85
        {
            AllowPrivateCalling  = $False;
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Global";
        }
        TeamsGuestMeetingConfiguration 32dd669b-1a1e-442f-83ce-b50fcbbda3e1
        {
            AllowIPVideo         = $True;
            AllowMeetNow         = $True;
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Global";
            ScreenSharingMode    = "EntireScreen";
        }
        TeamsGuestMessagingConfiguration 46bab006-a5ed-4ca2-b377-550bcaa9515b
        {
            AllowGiphy             = $True;
            AllowImmersiveReader   = $True;
            AllowMemes             = $True;
            AllowStickers          = $True;
            AllowUserChat          = $True;
            AllowUserDeleteMessage = $True;
            AllowUserEditMessage   = $True;
            GiphyRatingType        = "Strict";
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "Global";
        }
        TeamsMeetingBroadcastConfiguration d2fc6876-3160-4f06-b2a9-9f0ebece20c1
        {
            AllowSdnProviderForBroadcastMeeting = $False;
            GlobalAdminAccount                  = $Credsglobaladmin;
            Identity                            = "Global";
            SdnApiTemplateUrl                   = "";
            SdnApiToken                         = $ConfigurationData.Settings.SdnApiToken;
            SdnLicenseId                        = "";
            SdnProviderName                     = "";
            SupportURL                          = "https://support.office.com/home/contact";
        }
        TeamsMeetingBroadcastPolicy ea5ce03a-dd26-42de-bd8d-71ac761652b0
        {
            AllowBroadcastScheduling        = $False;
            AllowBroadcastTranscription     = $False;
            BroadcastAttendeeVisibilityMode = "InvitedUsersInCompany";
            BroadcastRecordingMode          = "UserOverride";
            Ensure                          = "Present";
            GlobalAdminAccount              = $Credsglobaladmin;
            Identity                        = "Global";
        }
        TeamsMeetingBroadcastPolicy a5c68862-6d26-42d7-9845-069a61bdae8f
        {
            AllowBroadcastScheduling        = $True;
            AllowBroadcastTranscription     = $True;
            BroadcastAttendeeVisibilityMode = "Everyone";
            BroadcastRecordingMode          = "UserOverride";
            Ensure                          = "Present";
            GlobalAdminAccount              = $Credsglobaladmin;
            Identity                        = "Tag:CIO";
        }
        TeamsMeetingBroadcastPolicy e95aff95-6501-4b50-b31c-efb32d6eae87
        {
            AllowBroadcastScheduling        = $False;
            AllowBroadcastTranscription     = $True;
            BroadcastAttendeeVisibilityMode = "InvitedUsersInCompany";
            BroadcastRecordingMode          = "UserOverride";
            Ensure                          = "Present";
            GlobalAdminAccount              = $Credsglobaladmin;
            Identity                        = "Tag:Frontline_Worker";
        }
        TeamsMeetingBroadcastPolicy 9bd8508f-54fe-4759-8ed2-4b506b8f9b59
        {
            AllowBroadcastScheduling        = $True;
            AllowBroadcastTranscription     = $False;
            BroadcastAttendeeVisibilityMode = "EveryoneInCompany";
            BroadcastRecordingMode          = "AlwaysEnabled";
            Ensure                          = "Present";
            GlobalAdminAccount              = $Credsglobaladmin;
            Identity                        = "Tag:Default";
        }
        TeamsMeetingPolicy 2d5e5f39-f25c-486f-b094-677d56893017
        {
            AllowAnonymousUsersToDialOut               = $False;
            AllowAnonymousUsersToStartMeeting          = $False;
            AllowBreakoutRooms                         = $True;
            AllowChannelMeetingScheduling              = $True;
            AllowCloudRecording                        = $True;
            AllowEngagementReport                      = "Enabled";
            AllowExternalParticipantGiveRequestControl = $False;
            AllowIPAudio                               = $True;
            AllowIPVideo                               = $True;
            AllowMeetingReactions                      = $True;
            AllowMeetNow                               = $True;
            AllowNDIStreaming                          = $False;
            AllowOrganizersToOverrideLobbySettings     = $False;
            AllowOutlookAddIn                          = $True;
            AllowParticipantGiveRequestControl         = $True;
            AllowPowerPointSharing                     = $True;
            AllowPrivateMeetingScheduling              = $True;
            AllowPrivateMeetNow                        = $True;
            AllowPSTNUsersToBypassLobby                = $False;
            AllowRecordingStorageOutsideRegion         = $False;
            AllowSharedNotes                           = $True;
            AllowTranscription                         = $False;
            AllowUserToJoinExternalMeeting             = "Disabled";
            AllowWhiteboard                            = $True;
            AutoAdmittedUsers                          = "EveryoneInCompany";
            DesignatedPresenterRoleMode                = "EveryoneUserOverride";
            EnrollUserOverride                         = "Disabled";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Global";
            IPAudioMode                                = "EnabledOutgoingIncoming";
            IPVideoMode                                = "EnabledOutgoingIncoming";
            LiveCaptionsEnabledType                    = "DisabledUserOverride";
            MediaBitRateKb                             = 2000;
            MeetingChatEnabledType                     = "Enabled";
            PreferredMeetingProviderForIslandsMode     = "TeamsAndSfb";
            RecordingStorageMode                       = "Stream";
            ScreenSharingMode                          = "EntireScreen";
            StreamingAttendeeMode                      = "Enabled";
            TeamsCameraFarEndPTZMode                   = "Disabled";
            VideoFiltersMode                           = "AllFilters";
        }
        TeamsMeetingPolicy de78c82a-d2ba-45a7-8a54-e77e37b42fa1
        {
            AllowAnonymousUsersToDialOut               = $False;
            AllowAnonymousUsersToStartMeeting          = $False;
            AllowBreakoutRooms                         = $True;
            AllowChannelMeetingScheduling              = $True;
            AllowCloudRecording                        = $True;
            AllowEngagementReport                      = "Enabled";
            AllowExternalParticipantGiveRequestControl = $False;
            AllowIPAudio                               = $True;
            AllowIPVideo                               = $True;
            AllowMeetingReactions                      = $True;
            AllowMeetNow                               = $True;
            AllowNDIStreaming                          = $False;
            AllowOrganizersToOverrideLobbySettings     = $False;
            AllowOutlookAddIn                          = $True;
            AllowParticipantGiveRequestControl         = $True;
            AllowPowerPointSharing                     = $True;
            AllowPrivateMeetingScheduling              = $True;
            AllowPrivateMeetNow                        = $True;
            AllowPSTNUsersToBypassLobby                = $False;
            AllowRecordingStorageOutsideRegion         = $False;
            AllowSharedNotes                           = $True;
            AllowTranscription                         = $False;
            AllowUserToJoinExternalMeeting             = "Disabled";
            AllowWhiteboard                            = $True;
            AutoAdmittedUsers                          = "EveryoneInCompany";
            Description                                = "This is a Frontline_Worker TeamsMeeting policy";
            DesignatedPresenterRoleMode                = "EveryoneUserOverride";
            EnrollUserOverride                         = "Disabled";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Tag:Frontline_Worker";
            IPAudioMode                                = "EnabledOutgoingIncoming";
            IPVideoMode                                = "EnabledOutgoingIncoming";
            LiveCaptionsEnabledType                    = "DisabledUserOverride";
            MediaBitRateKb                             = 2000;
            MeetingChatEnabledType                     = "Enabled";
            PreferredMeetingProviderForIslandsMode     = "TeamsAndSfb";
            RecordingStorageMode                       = "Stream";
            ScreenSharingMode                          = "EntireScreen";
            StreamingAttendeeMode                      = "Disabled";
            TeamsCameraFarEndPTZMode                   = "Disabled";
            VideoFiltersMode                           = "AllFilters";
        }
        TeamsMeetingPolicy 09e41173-2bb0-4fb5-b230-68e9753eaef5
        {
            AllowAnonymousUsersToDialOut               = $False;
            AllowAnonymousUsersToStartMeeting          = $False;
            AllowBreakoutRooms                         = $True;
            AllowChannelMeetingScheduling              = $True;
            AllowCloudRecording                        = $True;
            AllowEngagementReport                      = "Enabled";
            AllowExternalParticipantGiveRequestControl = $False;
            AllowIPAudio                               = $True;
            AllowIPVideo                               = $True;
            AllowMeetingReactions                      = $True;
            AllowMeetNow                               = $True;
            AllowNDIStreaming                          = $False;
            AllowOrganizersToOverrideLobbySettings     = $False;
            AllowOutlookAddIn                          = $True;
            AllowParticipantGiveRequestControl         = $True;
            AllowPowerPointSharing                     = $True;
            AllowPrivateMeetingScheduling              = $True;
            AllowPrivateMeetNow                        = $True;
            AllowPSTNUsersToBypassLobby                = $False;
            AllowRecordingStorageOutsideRegion         = $False;
            AllowSharedNotes                           = $True;
            AllowTranscription                         = $False;
            AllowUserToJoinExternalMeeting             = "Disabled";
            AllowWhiteboard                            = $True;
            AutoAdmittedUsers                          = "EveryoneInCompany";
            Description                                = "Do not assign. This policy is same as global defaults and would be deprecated";
            DesignatedPresenterRoleMode                = "EveryoneUserOverride";
            EnrollUserOverride                         = "Disabled";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Tag:AllOn";
            IPAudioMode                                = "EnabledOutgoingIncoming";
            IPVideoMode                                = "EnabledOutgoingIncoming";
            LiveCaptionsEnabledType                    = "DisabledUserOverride";
            MediaBitRateKb                             = 50000;
            MeetingChatEnabledType                     = "Enabled";
            PreferredMeetingProviderForIslandsMode     = "TeamsAndSfb";
            RecordingStorageMode                       = "OneDriveForBusiness";
            ScreenSharingMode                          = "EntireScreen";
            StreamingAttendeeMode                      = "Disabled";
            TeamsCameraFarEndPTZMode                   = "Disabled";
            VideoFiltersMode                           = "AllFilters";
        }
        TeamsMeetingPolicy c8c3b8c9-76f4-433d-8304-26c98cc0db27
        {
            AllowAnonymousUsersToDialOut               = $False;
            AllowAnonymousUsersToStartMeeting          = $False;
            AllowBreakoutRooms                         = $True;
            AllowChannelMeetingScheduling              = $True;
            AllowCloudRecording                        = $True;
            AllowEngagementReport                      = "Enabled";
            AllowExternalParticipantGiveRequestControl = $False;
            AllowIPAudio                               = $True;
            AllowIPVideo                               = $True;
            AllowMeetingReactions                      = $True;
            AllowMeetNow                               = $True;
            AllowNDIStreaming                          = $False;
            AllowOrganizersToOverrideLobbySettings     = $False;
            AllowOutlookAddIn                          = $True;
            AllowParticipantGiveRequestControl         = $True;
            AllowPowerPointSharing                     = $True;
            AllowPrivateMeetingScheduling              = $True;
            AllowPrivateMeetNow                        = $True;
            AllowPSTNUsersToBypassLobby                = $False;
            AllowRecordingStorageOutsideRegion         = $False;
            AllowSharedNotes                           = $True;
            AllowTranscription                         = $False;
            AllowUserToJoinExternalMeeting             = "Disabled";
            AllowWhiteboard                            = $True;
            AutoAdmittedUsers                          = "EveryoneInCompany";
            Description                                = "Do not assign. This policy is same as global defaults and would be deprecated";
            DesignatedPresenterRoleMode                = "EveryoneUserOverride";
            EnrollUserOverride                         = "Disabled";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Tag:RestrictedAnonymousAccess";
            IPAudioMode                                = "EnabledOutgoingIncoming";
            IPVideoMode                                = "EnabledOutgoingIncoming";
            LiveCaptionsEnabledType                    = "Disabled";
            MediaBitRateKb                             = 50000;
            MeetingChatEnabledType                     = "Enabled";
            PreferredMeetingProviderForIslandsMode     = "TeamsAndSfb";
            RecordingStorageMode                       = "OneDriveForBusiness";
            ScreenSharingMode                          = "EntireScreen";
            StreamingAttendeeMode                      = "Disabled";
            TeamsCameraFarEndPTZMode                   = "Disabled";
            VideoFiltersMode                           = "AllFilters";
        }
        TeamsMeetingPolicy fa74ac74-5468-47f6-8182-b39a523efc46
        {
            AllowAnonymousUsersToDialOut               = $False;
            AllowAnonymousUsersToStartMeeting          = $False;
            AllowBreakoutRooms                         = $True;
            AllowChannelMeetingScheduling              = $False;
            AllowCloudRecording                        = $False;
            AllowEngagementReport                      = "Enabled";
            AllowExternalParticipantGiveRequestControl = $False;
            AllowIPAudio                               = $True;
            AllowIPVideo                               = $False;
            AllowMeetingReactions                      = $True;
            AllowMeetNow                               = $False;
            AllowNDIStreaming                          = $False;
            AllowOrganizersToOverrideLobbySettings     = $False;
            AllowOutlookAddIn                          = $False;
            AllowParticipantGiveRequestControl         = $False;
            AllowPowerPointSharing                     = $False;
            AllowPrivateMeetingScheduling              = $False;
            AllowPrivateMeetNow                        = $False;
            AllowPSTNUsersToBypassLobby                = $False;
            AllowRecordingStorageOutsideRegion         = $False;
            AllowSharedNotes                           = $False;
            AllowTranscription                         = $False;
            AllowUserToJoinExternalMeeting             = "Disabled";
            AllowWhiteboard                            = $False;
            AutoAdmittedUsers                          = "EveryoneInCompany";
            DesignatedPresenterRoleMode                = "EveryoneUserOverride";
            EnrollUserOverride                         = "Disabled";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Tag:AllOff";
            IPAudioMode                                = "EnabledOutgoingIncoming";
            IPVideoMode                                = "EnabledOutgoingIncoming";
            LiveCaptionsEnabledType                    = "Disabled";
            MediaBitRateKb                             = 50000;
            MeetingChatEnabledType                     = "Disabled";
            PreferredMeetingProviderForIslandsMode     = "TeamsAndSfb";
            RecordingStorageMode                       = "OneDriveForBusiness";
            ScreenSharingMode                          = "Disabled";
            StreamingAttendeeMode                      = "Disabled";
            TeamsCameraFarEndPTZMode                   = "Disabled";
            VideoFiltersMode                           = "AllFilters";
        }
        TeamsMeetingPolicy 36f4a3be-7201-409f-9837-e8b3d76b70f3
        {
            AllowAnonymousUsersToDialOut               = $False;
            AllowAnonymousUsersToStartMeeting          = $False;
            AllowBreakoutRooms                         = $True;
            AllowChannelMeetingScheduling              = $True;
            AllowCloudRecording                        = $False;
            AllowEngagementReport                      = "Enabled";
            AllowExternalParticipantGiveRequestControl = $False;
            AllowIPAudio                               = $True;
            AllowIPVideo                               = $True;
            AllowMeetingReactions                      = $True;
            AllowMeetNow                               = $True;
            AllowNDIStreaming                          = $False;
            AllowOrganizersToOverrideLobbySettings     = $False;
            AllowOutlookAddIn                          = $True;
            AllowParticipantGiveRequestControl         = $True;
            AllowPowerPointSharing                     = $True;
            AllowPrivateMeetingScheduling              = $True;
            AllowPrivateMeetNow                        = $True;
            AllowPSTNUsersToBypassLobby                = $False;
            AllowRecordingStorageOutsideRegion         = $False;
            AllowSharedNotes                           = $True;
            AllowTranscription                         = $False;
            AllowUserToJoinExternalMeeting             = "Disabled";
            AllowWhiteboard                            = $True;
            AutoAdmittedUsers                          = "EveryoneInCompany";
            Description                                = "Do not assign. This policy is similar to global defaults and would be deprecated";
            DesignatedPresenterRoleMode                = "EveryoneUserOverride";
            EnrollUserOverride                         = "Disabled";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Tag:RestrictedAnonymousNoRecording";
            IPAudioMode                                = "EnabledOutgoingIncoming";
            IPVideoMode                                = "EnabledOutgoingIncoming";
            LiveCaptionsEnabledType                    = "Disabled";
            MediaBitRateKb                             = 50000;
            MeetingChatEnabledType                     = "Enabled";
            PreferredMeetingProviderForIslandsMode     = "TeamsAndSfb";
            RecordingStorageMode                       = "OneDriveForBusiness";
            ScreenSharingMode                          = "EntireScreen";
            StreamingAttendeeMode                      = "Disabled";
            TeamsCameraFarEndPTZMode                   = "Disabled";
            VideoFiltersMode                           = "AllFilters";
        }
        TeamsMeetingPolicy 08bb3354-588a-4db7-b2ff-5a97991a3299
        {
            AllowAnonymousUsersToDialOut               = $False;
            AllowAnonymousUsersToStartMeeting          = $False;
            AllowBreakoutRooms                         = $True;
            AllowChannelMeetingScheduling              = $True;
            AllowCloudRecording                        = $True;
            AllowEngagementReport                      = "Enabled";
            AllowExternalParticipantGiveRequestControl = $False;
            AllowIPAudio                               = $True;
            AllowIPVideo                               = $True;
            AllowMeetingReactions                      = $True;
            AllowMeetNow                               = $True;
            AllowNDIStreaming                          = $False;
            AllowOrganizersToOverrideLobbySettings     = $False;
            AllowOutlookAddIn                          = $True;
            AllowParticipantGiveRequestControl         = $True;
            AllowPowerPointSharing                     = $True;
            AllowPrivateMeetingScheduling              = $True;
            AllowPrivateMeetNow                        = $True;
            AllowPSTNUsersToBypassLobby                = $False;
            AllowRecordingStorageOutsideRegion         = $False;
            AllowSharedNotes                           = $True;
            AllowTranscription                         = $False;
            AllowUserToJoinExternalMeeting             = "Disabled";
            AllowWhiteboard                            = $True;
            AutoAdmittedUsers                          = "EveryoneInCompany";
            DesignatedPresenterRoleMode                = "EveryoneUserOverride";
            EnrollUserOverride                         = "Disabled";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Tag:Default";
            IPAudioMode                                = "EnabledOutgoingIncoming";
            IPVideoMode                                = "EnabledOutgoingIncoming";
            LiveCaptionsEnabledType                    = "DisabledUserOverride";
            MediaBitRateKb                             = 50000;
            MeetingChatEnabledType                     = "Enabled";
            PreferredMeetingProviderForIslandsMode     = "TeamsAndSfb";
            RecordingStorageMode                       = "OneDriveForBusiness";
            ScreenSharingMode                          = "EntireScreen";
            StreamingAttendeeMode                      = "Disabled";
            TeamsCameraFarEndPTZMode                   = "Disabled";
            VideoFiltersMode                           = "AllFilters";
        }
        TeamsMeetingPolicy d9ca1fc6-95b5-4fd1-bb22-6cb99adcac51
        {
            AllowAnonymousUsersToDialOut               = $False;
            AllowAnonymousUsersToStartMeeting          = $False;
            AllowBreakoutRooms                         = $True;
            AllowChannelMeetingScheduling              = $False;
            AllowCloudRecording                        = $False;
            AllowEngagementReport                      = "Enabled";
            AllowExternalParticipantGiveRequestControl = $False;
            AllowIPAudio                               = $True;
            AllowIPVideo                               = $True;
            AllowMeetingReactions                      = $True;
            AllowMeetNow                               = $True;
            AllowNDIStreaming                          = $False;
            AllowOrganizersToOverrideLobbySettings     = $False;
            AllowOutlookAddIn                          = $False;
            AllowParticipantGiveRequestControl         = $True;
            AllowPowerPointSharing                     = $True;
            AllowPrivateMeetingScheduling              = $False;
            AllowPrivateMeetNow                        = $True;
            AllowPSTNUsersToBypassLobby                = $False;
            AllowRecordingStorageOutsideRegion         = $False;
            AllowSharedNotes                           = $True;
            AllowTranscription                         = $False;
            AllowUserToJoinExternalMeeting             = "Disabled";
            AllowWhiteboard                            = $True;
            AutoAdmittedUsers                          = "EveryoneInCompany";
            DesignatedPresenterRoleMode                = "EveryoneUserOverride";
            EnrollUserOverride                         = "Disabled";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Tag:Kiosk";
            IPAudioMode                                = "EnabledOutgoingIncoming";
            IPVideoMode                                = "EnabledOutgoingIncoming";
            LiveCaptionsEnabledType                    = "Disabled";
            MediaBitRateKb                             = 50000;
            MeetingChatEnabledType                     = "Enabled";
            PreferredMeetingProviderForIslandsMode     = "TeamsAndSfb";
            RecordingStorageMode                       = "OneDriveForBusiness";
            ScreenSharingMode                          = "EntireScreen";
            StreamingAttendeeMode                      = "Disabled";
            TeamsCameraFarEndPTZMode                   = "Disabled";
            VideoFiltersMode                           = "AllFilters";
        }
        TeamsMessagingPolicy fe3805f9-a4d3-42a7-8c4a-76613d7b62a5
        {
            AllowGiphy                    = $True;
            AllowImmersiveReader          = $True;
            AllowMemes                    = $True;
            AllowOwnerDeleteMessage       = $False;
            AllowPriorityMessages         = $True;
            AllowRemoveUser               = $True;
            AllowStickers                 = $True;
            AllowUrlPreviews              = $True;
            AllowUserChat                 = $True;
            AllowUserDeleteMessage        = $True;
            AllowUserEditMessage          = $True;
            AllowUserTranslation          = $True;
            AudioMessageEnabledType       = "ChatsAndChannels";
            ChannelsInChatListEnabledType = "EnabledUserOverride";
            Ensure                        = "Present";
            GiphyRatingType               = "Strict";
            GlobalAdminAccount            = $Credsglobaladmin;
            Identity                      = "Global";
            ReadReceiptsEnabledType       = "UserPreference";
        }
        TeamsMessagingPolicy ea6a5abb-cbe7-48e4-a070-a2f7913af59c
        {
            AllowGiphy                    = $True;
            AllowImmersiveReader          = $True;
            AllowMemes                    = $True;
            AllowOwnerDeleteMessage       = $True;
            AllowPriorityMessages         = $False;
            AllowRemoveUser               = $True;
            AllowStickers                 = $True;
            AllowUrlPreviews              = $True;
            AllowUserChat                 = $True;
            AllowUserDeleteMessage        = $True;
            AllowUserEditMessage          = $True;
            AllowUserTranslation          = $True;
            AudioMessageEnabledType       = "ChatsAndChannels";
            ChannelsInChatListEnabledType = "EnabledUserOverride";
            Description                   = "This is a Frontline_Worker Messaging policy";
            Ensure                        = "Present";
            GiphyRatingType               = "Moderate";
            GlobalAdminAccount            = $Credsglobaladmin;
            Identity                      = "Frontline_Worker";
            ReadReceiptsEnabledType       = "Everyone";
        }
        TeamsMessagingPolicy becc10da-9058-46a2-bf1c-35cbc1b97e55
        {
            AllowGiphy                    = $True;
            AllowImmersiveReader          = $True;
            AllowMemes                    = $True;
            AllowOwnerDeleteMessage       = $False;
            AllowPriorityMessages         = $True;
            AllowRemoveUser               = $True;
            AllowStickers                 = $True;
            AllowUrlPreviews              = $True;
            AllowUserChat                 = $True;
            AllowUserDeleteMessage        = $True;
            AllowUserEditMessage          = $True;
            AllowUserTranslation          = $True;
            AudioMessageEnabledType       = "ChatsAndChannels";
            ChannelsInChatListEnabledType = "DisabledUserOverride";
            Ensure                        = "Present";
            GiphyRatingType               = "Moderate";
            GlobalAdminAccount            = $Credsglobaladmin;
            Identity                      = "Default";
            ReadReceiptsEnabledType       = "UserPreference";
        }
        TeamsMessagingPolicy 253d6da7-62aa-425f-881f-d4ce513d5ab8
        {
            AllowGiphy                    = $False;
            AllowImmersiveReader          = $True;
            AllowMemes                    = $True;
            AllowOwnerDeleteMessage       = $True;
            AllowPriorityMessages         = $True;
            AllowRemoveUser               = $True;
            AllowStickers                 = $True;
            AllowUrlPreviews              = $True;
            AllowUserChat                 = $True;
            AllowUserDeleteMessage        = $True;
            AllowUserEditMessage          = $True;
            AllowUserTranslation          = $True;
            AudioMessageEnabledType       = "ChatsAndChannels";
            ChannelsInChatListEnabledType = "DisabledUserOverride";
            Ensure                        = "Present";
            GiphyRatingType               = "Strict";
            GlobalAdminAccount            = $Credsglobaladmin;
            Identity                      = "EduFaculty";
            ReadReceiptsEnabledType       = "UserPreference";
        }
        TeamsMessagingPolicy 96f92913-8931-4dee-b944-3b117b3c5a1c
        {
            AllowGiphy                    = $False;
            AllowImmersiveReader          = $True;
            AllowMemes                    = $True;
            AllowOwnerDeleteMessage       = $False;
            AllowPriorityMessages         = $True;
            AllowRemoveUser               = $True;
            AllowStickers                 = $True;
            AllowUrlPreviews              = $True;
            AllowUserChat                 = $True;
            AllowUserDeleteMessage        = $True;
            AllowUserEditMessage          = $True;
            AllowUserTranslation          = $True;
            AudioMessageEnabledType       = "ChatsAndChannels";
            ChannelsInChatListEnabledType = "DisabledUserOverride";
            Ensure                        = "Present";
            GiphyRatingType               = "Strict";
            GlobalAdminAccount            = $Credsglobaladmin;
            Identity                      = "EduStudent";
            ReadReceiptsEnabledType       = "UserPreference";
        }
        TeamsTenantDialPlan 9393fe08-c559-43df-987d-268c51ff875f
        {
            Description           = "DialPlan";
            Ensure                = "Present";
            GlobalAdminAccount    = $Credsglobaladmin;
            Identity              = "Global";
            NormalizationRules    = @();
            OptimizeDeviceDialing = $False;
            SimpleName            = "DefaultTenantDialPlan";
        }
        TeamsUpgradeConfiguration 74c1e5c7-9234-49ee-80da-2a93de7d715a
        {
            DownloadTeams        = $True;
            GlobalAdminAccount   = $Credsglobaladmin;
            IsSingleInstance     = "Yes";
            SfBMeetingJoinUx     = "SkypeMeetingsApp";
        }
        TeamsUpgradePolicy 64c7fbc5-6d6e-4cca-a752-4923d988e795
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "Global";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy e8cd4429-883c-4420-8190-c52fd3fc5368
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "UpgradeToTeams";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 6000c205-4f1d-4d2e-bba3-5c5f50401cc1
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "Islands";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 17588a80-eb48-4062-9ce0-135a6b190219
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "IslandsWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 90a8e7ee-510f-4ee9-b167-e9da037390c6
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBOnly";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy e9680f0b-bb29-43c5-8ca4-b607154f2caa
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBOnlyWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy e59a020a-a407-4b9c-b67a-958d08dde9f5
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollab";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 4632c996-b5b4-4a1d-92e5-4cc8ecc1bf49
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollabWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 6299c949-0236-4680-8b38-263e7a50a3e0
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollabAndMeetings";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 177dbe97-103a-4863-a8d8-c3fee26dddee
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollabAndMeetingsWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsVoiceRoute c9b0c6fd-c32b-46be-82c8-fc319a6f3209
        {
            Ensure                = "Present";
            GlobalAdminAccount    = $Credsglobaladmin;
            Identity              = "LocalRoute";
            NumberPattern         = "^(\+1[0-9]{10})$";
            OnlinePstnGatewayList = @();
            OnlinePstnUsages      = @();
            Priority              = 0;
        }
        TeamsVoiceRoutingPolicy dbb7d5fc-4b4a-4ab4-8e56-728c390c390b
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Global";
            OnlinePstnUsages     = @();
        }
    }
}
Tenantid-GC-2021-May-27-1205PM-runbook_2021-May-27-1205PM -ConfigurationData .\ConfigurationData.psd1 -GlobalAdminAccount $GlobalAdminAccount
