# Generated with Microsoft365DSC version 1.21.922.1
# For additional information on how to use Microsoft365DSC, please visit https://aka.ms/M365DSC
param (
    [parameter()]
    [System.Management.Automation.PSCredential]
    $GlobalAdminAccount
)

Configuration GoldExport-2021-Jun-03-0806AM-runbook_2021-Jun-03-0806AM
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
    Import-DscResource -ModuleName 'Microsoft365DSC' -ModuleVersion '1.21.922.1'

    Node localhost
    {
        AADConditionalAccessPolicy 5fe981d3-1ab4-4242-9855-2d1c714f4668
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @("Block");
            ClientAppTypes                           = @("ExchangeActiveSync","Other");
            CloudAppSecurityIsEnabled                = $False;
            CloudAppSecurityType                     = "";
            DisplayName                              = "BLOCK-Legacy Authentication";
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
            Id                                       = "e101de13-7119-45a6-bd6a-6ac3645dae57";
            IncludeApplications                      = @("All");
            IncludeDevices                           = @();
            IncludeGroups                            = @();
            IncludeLocations                         = @();
            IncludePlatforms                         = @();
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
        AADConditionalAccessPolicy af359656-4115-4843-bde4-1ffb6d2ae6ab
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @("Mfa");
            ClientAppTypes                           = @("All");
            CloudAppSecurityIsEnabled                = $False;
            CloudAppSecurityType                     = "";
            DisplayName                              = "Enable - Multi Factor Authentication - All Users";
            Ensure                                   = "Present";
            ExcludeApplications                      = @();
            ExcludeDevices                           = @();
            ExcludeGroups                            = @();
            ExcludeLocations                         = @();
            ExcludePlatforms                         = @();
            ExcludeRoles                             = @();
            ExcludeUsers                             = @("admin@$OrganizationName");
            GlobalAdminAccount                       = $Credsglobaladmin;
            GrantControlOperator                     = "OR";
            Id                                       = "12c380d5-2aa1-420c-896e-89e1e309ed14";
            IncludeApplications                      = @("All");
            IncludeDevices                           = @();
            IncludeGroups                            = @();
            IncludeLocations                         = @();
            IncludePlatforms                         = @();
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
        AADConditionalAccessPolicy 1e9ba92c-1350-4b49-85ae-26dd1ca7e286
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @("Mfa");
            ClientAppTypes                           = @("All");
            CloudAppSecurityIsEnabled                = $False;
            CloudAppSecurityType                     = "";
            DisplayName                              = "Enable - Multi Factor Authentication -Devices";
            Ensure                                   = "Present";
            ExcludeApplications                      = @();
            ExcludeDevices                           = @();
            ExcludeGroups                            = @();
            ExcludeLocations                         = @();
            ExcludePlatforms                         = @();
            ExcludeRoles                             = @();
            ExcludeUsers                             = @("admin@$OrganizationName");
            GlobalAdminAccount                       = $Credsglobaladmin;
            GrantControlOperator                     = "OR";
            Id                                       = "d93ebb75-1dbd-43eb-afca-6ea271ac2987";
            IncludeApplications                      = @("All");
            IncludeDevices                           = @();
            IncludeGroups                            = @();
            IncludeLocations                         = @();
            IncludePlatforms                         = @();
            IncludeRoles                             = @();
            IncludeUserActions                       = @();
            IncludeUsers                             = @("GuestsOrExternalUsers");
            PersistentBrowserIsEnabled               = $False;
            PersistentBrowserMode                    = "";
            SignInFrequencyIsEnabled                 = $False;
            SignInFrequencyType                      = "";
            SignInRiskLevels                         = @();
            State                                    = "enabled";
            UserRiskLevels                           = @();
        }
        AADConditionalAccessPolicy dfe892a9-cd22-4d26-8277-8c7f54ded795
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @("Mfa");
            ClientAppTypes                           = @("All");
            CloudAppSecurityIsEnabled                = $False;
            CloudAppSecurityType                     = "";
            DisplayName                              = "Enable - Multi Factor Authentication - Administrators";
            Ensure                                   = "Present";
            ExcludeApplications                      = @();
            ExcludeDevices                           = @();
            ExcludeGroups                            = @();
            ExcludeLocations                         = @();
            ExcludePlatforms                         = @();
            ExcludeRoles                             = @();
            ExcludeUsers                             = @("admin@$OrganizationName");
            GlobalAdminAccount                       = $Credsglobaladmin;
            GrantControlOperator                     = "OR";
            Id                                       = "6e07e888-89f6-4750-b131-58c013f259be";
            IncludeApplications                      = @("All");
            IncludeDevices                           = @();
            IncludeGroups                            = @();
            IncludeLocations                         = @();
            IncludePlatforms                         = @();
            IncludeRoles                             = @("User Administrator","Usage Summary Reports Reader","Teams Devices Administrator","Teams Communications Support Engineer","Teams Communications Support Specialist","Teams Communications Administrator","Teams Administrator","Skype for Business Administrator","SharePoint Administrator","Service Support Administrator","Security Reader","Security Operator","Security Administrator","Search Editor","Search Administrator","Reports Reader","Privileged Role Administrator","Privileged Authentication Administrator","Printer Technician","Printer Administrator","Power Platform Administrator","Power BI Administrator","Password Administrator","Office Apps Administrator","Network Administrator","Message Center Reader","Message Center Privacy Reader","License Administrator","Kaizala Administrator","Intune Administrator","Insights Business Leader","Insights Administrator","Hybrid Identity Administrator","Helpdesk Administrator","Guest Inviter","Groups Administrator","Global Reader","Global Administrator","External Identity Provider Administrator","External ID User Flow Attribute Administrator","External ID User Flow Administrator","Exchange Administrator","Dynamics 365 Administrator","Domain Name Administrator","Directory Writers","Directory Synchronization Accounts","Directory Readers","Desktop Analytics Administrator","Customer LockBox Access Approver","Conditional Access Administrator","Compliance Data Administrator","Compliance Administrator","Cloud Device Administrator","Cloud Application Administrator","Billing Administrator","B2C IEF Policy Administrator","B2C IEF Keyset Administrator","Azure Information Protection Administrator","Azure DevOps Administrator","Azure AD Joined Device Local Administrator","Authentication Policy Administrator","Authentication Administrator","Attack Simulation Administrator","Attack Payload Author","Application Developer","Application Administrator");
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
        AADConditionalAccessPolicy 852f9701-f95d-42c0-9b0d-9e7cad9a6e89
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @("Block");
            ClientAppTypes                           = @("All");
            CloudAppSecurityIsEnabled                = $False;
            CloudAppSecurityType                     = "";
            DisplayName                              = "Block-High-Risk-Sign-Ins";
            Ensure                                   = "Present";
            ExcludeApplications                      = @();
            ExcludeDevices                           = @();
            ExcludeGroups                            = @();
            ExcludeLocations                         = @();
            ExcludePlatforms                         = @();
            ExcludeRoles                             = @();
            ExcludeUsers                             = @("admin@$OrganizationName");
            GlobalAdminAccount                       = $Credsglobaladmin;
            GrantControlOperator                     = "OR";
            Id                                       = "af60536f-ef31-474c-9acf-4f52d5d607c6";
            IncludeApplications                      = @("All");
            IncludeDevices                           = @();
            IncludeGroups                            = @();
            IncludeLocations                         = @();
            IncludePlatforms                         = @();
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
        AADConditionalAccessPolicy 6b0ec8d4-4c13-4ca2-9fd3-3b46051f07e7
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @("Mfa");
            ClientAppTypes                           = @("All");
            CloudAppSecurityIsEnabled                = $False;
            CloudAppSecurityType                     = "";
            DisplayName                              = "BLOCK - External Locations require MFA";
            Ensure                                   = "Present";
            ExcludeApplications                      = @();
            ExcludeDevices                           = @();
            ExcludeGroups                            = @();
            ExcludeLocations                         = @();
            ExcludePlatforms                         = @();
            ExcludeRoles                             = @();
            ExcludeUsers                             = @("admin@$OrganizationName");
            GlobalAdminAccount                       = $Credsglobaladmin;
            GrantControlOperator                     = "OR";
            Id                                       = "dbb62dd4-7dc1-4050-b2fa-fca0ad609efc";
            IncludeApplications                      = @("All");
            IncludeDevices                           = @();
            IncludeGroups                            = @();
            IncludeLocations                         = @("AllTrusted");
            IncludePlatforms                         = @();
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
        AADConditionalAccessPolicy 4f018187-e784-4e3a-be01-c208a2f46799
        {
            ApplicationEnforcedRestrictionsIsEnabled = $False;
            BuiltInControls                          = @("Block");
            ClientAppTypes                           = @("All");
            CloudAppSecurityIsEnabled                = $False;
            CloudAppSecurityType                     = "";
            DisplayName                              = "BLOCK - Countries not Allowed";
            Ensure                                   = "Present";
            ExcludeApplications                      = @();
            ExcludeDevices                           = @();
            ExcludeGroups                            = @();
            ExcludeLocations                         = @("AllTrusted");
            ExcludePlatforms                         = @();
            ExcludeRoles                             = @();
            ExcludeUsers                             = @("admin@$OrganizationName");
            GlobalAdminAccount                       = $Credsglobaladmin;
            GrantControlOperator                     = "OR";
            Id                                       = "dea778a6-d12e-44e8-b3c5-d557632330bc";
            IncludeApplications                      = @("All");
            IncludeDevices                           = @();
            IncludeGroups                            = @();
            IncludeLocations                         = @("All");
            IncludePlatforms                         = @();
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
        AADGroupsSettings 65c2e8a9-b424-46f7-ba6c-a6fc05901df3
        {
            Ensure               = "Absent";
            GlobalAdminAccount   = $Credsglobaladmin;
            IsSingleInstance     = "Yes";
        }
        AADPolicy 037dedd0-4a1e-4aa2-abe8-defb12d4cbb4
        {
            Definition            = @("{`"B2BManagementPolicy`":{`"InvitationsAllowedAndBlockedDomainsPolicy`":{`"BlockedDomains`":[]},`"AutoRedeemPolicy`":{`"AdminConsentedForUsersIntoTenantIds`":[],`"NoAADConsentForUsersFromTenantsIds`":[]}}}");
            DisplayName           = "B2BManagementPolicy";
            Ensure                = "Present";
            GlobalAdminAccount    = $Credsglobaladmin;
            Id                    = "efd617a3-544e-46da-963d-2782d33250c6";
            IsOrganizationDefault = $True;
            Type                  = "B2BManagementPolicy";
        }
        AADTenantDetails 843f67bc-1ddd-45b1-a8ce-18cd09bbee32
        {
            GlobalAdminAccount                   = $Credsglobaladmin;
            IsSingleInstance                     = "Yes";
            MarketingNotificationEmails          = @();
            SecurityComplianceNotificationMails  = @();
            SecurityComplianceNotificationPhones = @();
            TechnicalNotificationMails           = @("stockpiling@valorem.com");
        }
        EXOAntiPhishPolicy f11dee11-1f96-4a94-a7b1-d8ade33d5c94
        {
            AdminDisplayName                              = "";
            AuthenticationFailAction                      = "MoveToJmf";
            Enabled                                       = $True;
            EnableMailboxIntelligence                     = $True;
            EnableMailboxIntelligenceProtection           = $False;
            EnableOrganizationDomainsProtection           = $False;
            EnableSimilarDomainsSafetyTips                = $False;
            EnableSimilarUsersSafetyTips                  = $False;
            EnableSpoofIntelligence                       = $True;
            EnableTargetedDomainsProtection               = $False;
            EnableTargetedUserProtection                  = $False;
            EnableUnauthenticatedSender                   = $True;
            EnableUnusualCharactersSafetyTips             = $False;
            Ensure                                        = "Present";
            ExcludedDomains                               = @();
            ExcludedSenders                               = @();
            GlobalAdminAccount                            = $Credsglobaladmin;
            Identity                                      = "Office365 AntiPhish Default";
            ImpersonationProtectionState                  = "Automatic";
            MailboxIntelligenceProtectionAction           = "NoAction";
            MailboxIntelligenceProtectionActionRecipients = @();
            PhishThresholdLevel                           = 1;
            TargetedDomainActionRecipients                = @();
            TargetedDomainProtectionAction                = "NoAction";
            TargetedDomainsToProtect                      = @();
            TargetedUserActionRecipients                  = @();
            TargetedUserProtectionAction                  = "NoAction";
            TargetedUsersToProtect                        = @();
        }
        EXOAntiPhishPolicy 97ff82a3-0abd-4ea7-9a17-6ae8e2b60578
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
            EnableTargetedUserProtection                  = $False;
            EnableUnauthenticatedSender                   = $True;
            EnableUnusualCharactersSafetyTips             = $True;
            Ensure                                        = "Present";
            ExcludedDomains                               = @();
            ExcludedSenders                               = @();
            GlobalAdminAccount                            = $Credsglobaladmin;
            Identity                                      = "ATP-AntiPhishingPolicy";
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
        EXOAntiPhishRule 56c07087-f027-4a0d-9e2a-ed9ea35104ae
        {
            AntiPhishPolicy      = "ATP-AntiPhishingPolicy";
            Enabled              = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "ATP-AntiPhishingPolicy";
            Priority             = 0;
            RecipientDomainIs    = @("$OrganizationName");
        }
        EXOAtpPolicyForO365 cb05ab84-d9bc-4b56-bdd6-a5d2a524f8f0
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
        EXOHostedConnectionFilterPolicy 3c0320c5-94e5-4640-986c-9741b3368562
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
        EXOHostedOutboundSpamFilterPolicy 547929f6-51f1-4971-a181-d61f0b464c0d
        {
            AdminDisplayName                          = "";
            BccSuspiciousOutboundAdditionalRecipients = @();
            BccSuspiciousOutboundMail                 = $False;
            Ensure                                    = "Present";
            GlobalAdminAccount                        = $Credsglobaladmin;
            Identity                                  = "Default";
            NotifyOutboundSpam                        = $False;
            NotifyOutboundSpamRecipients              = @();
        }
        EXOMalwareFilterPolicy e0da6084-16ca-4a96-a729-b61c8d25020d
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
            Identity                               = "Default";
            ZapEnabled                             = $True;
        }
        EXOSafeAttachmentPolicy dd4cb9cb-35cb-48a7-a6e0-394429268f0a
        {
            Action               = "DynamicDelivery";
            ActionOnError        = $True;
            AdminDisplayName     = "";
            Enable               = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "ATP-SafeAttachementsPolicy";
            Redirect             = $True;
            RedirectAddress      = "admin@$OrganizationName";
        }
        EXOSafeAttachmentRule 329cabd0-1239-4c85-bc12-1c12b66d34c7
        {
            Enabled              = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "ATP-SafeAttachementsPolicy";
            Priority             = 0;
            RecipientDomainIs    = @("$OrganizationName");
            SafeAttachmentPolicy = "ATP-SafeAttachementsPolicy";
        }
        EXOSafeLinksPolicy 85f3b2fb-cdcb-4c19-9009-e0e6f7be182e
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
            Identity                 = "ATP-SafeLinksPolicy";
            IsEnabled                = $True;
            ScanUrls                 = $True;
        }
        EXOSafeLinksRule 8cd46ce6-ad8b-4a40-b15c-28893ed7338a
        {
            Enabled              = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "ATP-SafeLinksPolicy";
            Priority             = 0;
            RecipientDomainIs    = @("$OrganizationName");
            SafeLinksPolicy      = "ATP-SafeLinksPolicy";
        }
        EXOSharingPolicy 6d1a21e5-fb7d-4d1d-b34c-f8e898724f80
        {
            Default              = $True;
            Domains              = @("Anonymous:CalendarSharingFreeBusyReviewer","*:CalendarSharingFreeBusySimple");
            Enabled              = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Default Sharing Policy";
        }
        O365AdminAuditLogConfig 89987587-bf0b-41ca-adc4-d24383466744
        {
            Ensure                          = "Present";
            GlobalAdminAccount              = $Credsglobaladmin;
            IsSingleInstance                = "Yes";
            UnifiedAuditLogIngestionEnabled = "Enabled";
        }
        O365OrgCustomizationSetting 33881595-903e-4e72-86fc-b727d7ad595e
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            IsSingleInstance     = "Yes";
        }
        TeamsCallingPolicy 4ac659d2-6531-49c3-93ef-6643f7754a28
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
        TeamsCallingPolicy 0302c31d-8b2c-4d0b-bdbd-799da4403514
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
        TeamsCallingPolicy e4fcc546-c73a-4cbe-9168-cb12c6e71e55
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
        TeamsCallingPolicy 1bd2f31d-e9e9-45ea-8f9b-490c68a744b5
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
        TeamsCallingPolicy 370c9229-83ac-4210-98d5-ebc334f30ecc
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
        TeamsChannelsPolicy d6877bee-990b-41b0-a076-cc560061363e
        {
            AllowOrgWideTeamCreation    = $True;
            AllowPrivateChannelCreation = $True;
            AllowPrivateTeamDiscovery   = $True;
            Ensure                      = "Present";
            GlobalAdminAccount          = $Credsglobaladmin;
            Identity                    = "Global";
        }
        TeamsChannelsPolicy 1aba798e-cca2-4804-89c4-e804835f2125
        {
            AllowOrgWideTeamCreation    = $True;
            AllowPrivateChannelCreation = $True;
            AllowPrivateTeamDiscovery   = $True;
            Ensure                      = "Present";
            GlobalAdminAccount          = $Credsglobaladmin;
            Identity                    = "Tag:Default";
        }
        TeamsEmergencyCallingPolicy e05da7f6-8a67-4acc-bd6c-4307b64140a6
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Global";
        }
        TeamsEmergencyCallRoutingPolicy 00f48be3-f9c4-47ad-b094-82b343ac7126
        {
            AllowEnhancedEmergencyServices = $False;
            Ensure                         = "Present";
            GlobalAdminAccount             = $Credsglobaladmin;
            Identity                       = "Global";
        }
        TeamsGuestCallingConfiguration ec214209-c64b-4195-92bb-a10ef8118775
        {
            AllowPrivateCalling  = $False;
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Global";
        }
        TeamsGuestMeetingConfiguration a132901d-2a69-42a6-b5d6-1c9b4d29db28
        {
            AllowIPVideo         = $True;
            AllowMeetNow         = $True;
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Global";
            ScreenSharingMode    = "EntireScreen";
        }
        TeamsGuestMessagingConfiguration 8c7553dd-bd14-4ee9-acee-8bb158bfa03d
        {
            AllowGiphy             = $True;
            AllowImmersiveReader   = $True;
            AllowMemes             = $True;
            AllowStickers          = $True;
            AllowUserChat          = $True;
            AllowUserDeleteMessage = $False;
            AllowUserEditMessage   = $True;
            GiphyRatingType        = "Strict";
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "Global";
        }
        TeamsMeetingBroadcastConfiguration 69f0850d-92ff-441c-a511-d8906de01695
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
        TeamsMeetingBroadcastPolicy 95e04307-5e45-4b67-812b-a9024744466b
        {
            AllowBroadcastScheduling        = $True;
            AllowBroadcastTranscription     = $True;
            BroadcastAttendeeVisibilityMode = "EveryoneInCompany";
            BroadcastRecordingMode          = "UserOverride";
            Ensure                          = "Present";
            GlobalAdminAccount              = $Credsglobaladmin;
            Identity                        = "Global";
        }
        TeamsMeetingBroadcastPolicy 4dd13121-ec02-491e-90f3-3fda63d0e118
        {
            AllowBroadcastScheduling        = $True;
            AllowBroadcastTranscription     = $False;
            BroadcastAttendeeVisibilityMode = "EveryoneInCompany";
            BroadcastRecordingMode          = "AlwaysEnabled";
            Ensure                          = "Present";
            GlobalAdminAccount              = $Credsglobaladmin;
            Identity                        = "Tag:Default";
        }
        TeamsMeetingPolicy 214d1bca-47c0-49c5-a1b6-80dc387ac9f0
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
            DesignatedPresenterRoleMode                = "EveryoneInCompanyUserOverride";
            EnrollUserOverride                         = "Disabled";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Global";
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
        TeamsMeetingPolicy 604ce4d3-a19e-442c-811f-3ed8e6065a7f
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
        TeamsMeetingPolicy 4cd17e4f-a751-4914-a4f7-d52c0b9c0c2f
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
        TeamsMeetingPolicy 518ba167-a2f6-46e8-9253-184b4c17b2db
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
        TeamsMeetingPolicy 8ca666a0-09c7-41b9-9229-44d03768aa89
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
        TeamsMeetingPolicy 5a752383-73cc-423e-87d0-69867b8a932f
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
        TeamsMeetingPolicy 9fdac7ad-832e-479a-876e-9345e7cfce7c
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
        TeamsMessagingPolicy bbabb287-c0a0-491b-8ce9-c03afa3494d8
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
            AudioMessageEnabledType       = "Disabled";
            ChannelsInChatListEnabledType = "DisabledUserOverride";
            Ensure                        = "Present";
            GiphyRatingType               = "Strict";
            GlobalAdminAccount            = $Credsglobaladmin;
            Identity                      = "Global";
            ReadReceiptsEnabledType       = "UserPreference";
        }
        TeamsMessagingPolicy 35904d2d-cf13-4848-987f-21f5e6dc41a6
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
        TeamsMessagingPolicy bdeeb083-2512-4770-a025-f334657b5d32
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
        TeamsMessagingPolicy 9536d70c-1d86-46d8-aca6-08f4732e5841
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
        TeamsTenantDialPlan 45108159-0099-40d8-a9c2-dc5ad97c7dc3
        {
            Ensure                = "Present";
            GlobalAdminAccount    = $Credsglobaladmin;
            Identity              = "Global";
            NormalizationRules    = @();
            OptimizeDeviceDialing = $False;
            SimpleName            = "DefaultTenantDialPlan";
        }
        TeamsUpgradeConfiguration a93f4f27-d93c-44ff-9b3e-01bf17bf4594
        {
            DownloadTeams        = $True;
            GlobalAdminAccount   = $Credsglobaladmin;
            IsSingleInstance     = "Yes";
            SfBMeetingJoinUx     = "NativeLimitedClient";
        }
        TeamsUpgradePolicy a642b04a-b68b-4327-b5a5-c75f6c6b6450
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "Global";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy ac57d92a-469d-45dd-9bf0-9c447f1e06e4
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "UpgradeToTeams";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 92f3d06f-4d16-493b-bd5b-1b0d2d6dc81d
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "Islands";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy effd1d34-f67c-4d45-ab35-6e74e48357f4
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "IslandsWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 1bd24df3-c140-4bf0-8af1-85074bd2437f
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBOnly";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 695decd5-4b82-436e-bd62-cc97ba9986a0
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBOnlyWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 87d5d4b0-76fb-4f02-a817-9207f42f663b
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollab";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 2ad18398-782d-4406-8754-0811ac4cfa0d
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollabWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 0cb9dbb6-dc40-4724-b7e5-10b05113de74
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollabAndMeetings";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 0043c01c-2271-40d3-97f1-57590d2451be
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollabAndMeetingsWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsVoiceRoute 6f0d495b-809a-4b57-a3c6-8e7bdd154418
        {
            Ensure                = "Present";
            GlobalAdminAccount    = $Credsglobaladmin;
            Identity              = "LocalRoute";
            NumberPattern         = "^(\+1[0-9]{10})$";
            OnlinePstnGatewayList = @();
            OnlinePstnUsages      = @();
            Priority              = 0;
        }
        TeamsVoiceRoutingPolicy 80dc2472-4976-48e4-87ea-9903002f7ca9
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Global";
            OnlinePstnUsages     = @();
        }
    }
}
GoldExport-2021-Jun-03-0806AM-runbook_2021-Jun-03-0806AM -ConfigurationData .\ConfigurationData.psd1 -GlobalAdminAccount $GlobalAdminAccount
