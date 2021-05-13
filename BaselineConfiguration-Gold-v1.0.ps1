# Generated with Microsoft365DSC version 1.21.505.1
# For additional information on how to use Microsoft365DSC, please visit https://aka.ms/M365DSC
param (
    [parameter()]
    [System.Management.Automation.PSCredential]
    $GlobalAdminAccount
)

Configuration BaselineConfiguration-2021-Feb-11-1402PM-runbook_2021-Feb-11-1402PM
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
        AADConditionalAccessPolicy 60baa792-d2bf-439a-b709-2789c1fc96db
        {
            BuiltInControls       = @("Block");
            ClientAppTypes        = @("ExchangeActiveSync","Other");
            CloudAppSecurityType  = "";
            DisplayName           = "BLOCK-Legacy Authentication";
            Ensure                = "Present";
            ExcludeApplications   = @();
            ExcludeRoles          = @("Global Administrator");
            GlobalAdminAccount    = $Credsglobaladmin;
            GrantControlOperator  = "OR";
            Id                    = "6821cb49-7896-44da-aca8-d62d83e8e0e9";
            IncludeApplications   = @("All");
            IncludeUserActions    = @();
            IncludeUsers          = @("All");
            PersistentBrowserMode = "";
            SignInFrequencyType   = "";
            SignInRiskLevels      = @();
            State                 = "enabled";
            UserRiskLevels        = @();
        }
        AADConditionalAccessPolicy 7c516f81-77f9-411c-85e3-9360d63cf2a5
        {
            BuiltInControls       = @("Mfa");
            ClientAppTypes        = @("All");
            CloudAppSecurityType  = "";
            DisplayName           = "Enable - Multi Factor Authentication - All Users";
            Ensure                = "Present";
            ExcludeApplications   = @();
            ExcludeUsers          = @("admin@$OrganizationName");
            GlobalAdminAccount    = $Credsglobaladmin;
            GrantControlOperator  = "OR";
            Id                    = "1d7834d3-e769-495f-b45f-7b0f70116277";
            IncludeApplications   = @("All");
            IncludeUserActions    = @();
            IncludeUsers          = @("All");
            PersistentBrowserMode = "";
            SignInFrequencyType   = "";
            SignInRiskLevels      = @();
            State                 = "enabled";
            UserRiskLevels        = @();
        }
        AADConditionalAccessPolicy ce45835e-cb7c-47dd-b232-802c5556d822
        {
            BuiltInControls       = @("Mfa");
            ClientAppTypes        = @("All");
            CloudAppSecurityType  = "";
            DisplayName           = "Enable - Multi Factor Authentication -Devices";
            Ensure                = "Present";
            ExcludeApplications   = @();
            ExcludeUsers          = @("admin@$OrganizationName");
            GlobalAdminAccount    = $Credsglobaladmin;
            GrantControlOperator  = "OR";
            Id                    = "fe5c4ed0-ee0d-422f-a23a-cd0c2302d9b7";
            IncludeApplications   = @("All");
            IncludeUserActions    = @();
            IncludeUsers          = @("GuestsOrExternalUsers");
            PersistentBrowserMode = "";
            SignInFrequencyType   = "";
            SignInRiskLevels      = @();
            State                 = "enabled";
            UserRiskLevels        = @();
        }
        AADConditionalAccessPolicy 0617c31c-ed37-4172-8fe1-efff24bd8498
        {
            BuiltInControls       = @("Mfa");
            ClientAppTypes        = @("All");
            CloudAppSecurityType  = "";
            DisplayName           = "Enable - Multi Factor Authentication - Administrators";
            Ensure                = "Present";
            ExcludeApplications   = @();
            ExcludeUsers          = @("admin@$OrganizationName");
            GlobalAdminAccount    = $Credsglobaladmin;
            GrantControlOperator  = "OR";
            Id                    = "0cd1125c-3574-4e4f-a4fb-35baf09d57e4";
            IncludeApplications   = @("All");
            IncludeRoles          = @("User Administrator","Usage Summary Reports Reader","Teams Devices Administrator","Teams Communications Support Engineer","Teams Communications Support Specialist","Teams Communications Administrator","Teams Administrator","Skype for Business Administrator","SharePoint Administrator","Service Support Administrator","Security Reader","Security Operator","Security Administrator","Search Editor","Search Administrator","Reports Reader","Privileged Role Administrator","Privileged Authentication Administrator","Printer Technician","Printer Administrator","Power Platform Administrator","Power BI Administrator","Password Administrator","Office Apps Administrator","Network Administrator","Message Center Reader","Message Center Privacy Reader","License Administrator","Kaizala Administrator","Intune Administrator","Insights Business Leader","Insights Administrator","Hybrid Identity Administrator","Helpdesk Administrator","Guest Inviter","Groups Administrator","Global Reader","Global Administrator","External Identity Provider Administrator","External ID User Flow Attribute Administrator","External ID User Flow Administrator","Exchange Administrator","Dynamics 365 Administrator","Domain Name Administrator","Directory Writers","Directory Synchronization Accounts","Directory Readers","Desktop Analytics Administrator","Customer LockBox Access Approver","Conditional Access Administrator","Compliance Data Administrator","Compliance Administrator","Cloud Device Administrator","Cloud Application Administrator","Billing Administrator","B2C IEF Policy Administrator","B2C IEF Keyset Administrator","Azure Information Protection Administrator","Azure DevOps Administrator","Azure AD Joined Device Local Administrator","Authentication Policy Administrator","Authentication Administrator","Attack Simulation Administrator","Attack Payload Author","Application Developer","Application Administrator");
            IncludeUserActions    = @();
            PersistentBrowserMode = "";
            SignInFrequencyType   = "";
            SignInRiskLevels      = @();
            State                 = "enabled";
            UserRiskLevels        = @();
        }
        AADConditionalAccessPolicy 2fd21124-407f-4248-aac7-2d5bd85d11e3
        {
            BuiltInControls       = @("Block");
            ClientAppTypes        = @("All");
            CloudAppSecurityType  = "";
            DisplayName           = "Block-High-Risk-Sign-Ins";
            Ensure                = "Present";
            ExcludeApplications   = @();
            ExcludeUsers          = @("admin@$OrganizationName");
            GlobalAdminAccount    = $Credsglobaladmin;
            GrantControlOperator  = "OR";
            Id                    = "8a951ad5-9919-48c2-9870-22acc5a73dd4";
            IncludeApplications   = @("All");
            IncludeUserActions    = @();
            IncludeUsers          = @("All");
            PersistentBrowserMode = "";
            SignInFrequencyType   = "";
            SignInRiskLevels      = @("High");
            State                 = "enabled";
            UserRiskLevels        = @();
        }
        AADConditionalAccessPolicy 767cb5b1-5ee6-4393-816c-60e1da214b00
        {
            BuiltInControls       = @("Mfa");
            ClientAppTypes        = @("All");
            CloudAppSecurityType  = "";
            DisplayName           = "BLOCK - External Locations require MFA";
            Ensure                = "Present";
            ExcludeApplications   = @();
            ExcludeUsers          = @("admin@$OrganizationName");
            GlobalAdminAccount    = $Credsglobaladmin;
            GrantControlOperator  = "OR";
            Id                    = "79e2ae57-a6ab-4749-8817-1725649a2d9e";
            IncludeApplications   = @("All");
            IncludeLocations      = @("AllTrusted");
            IncludeUserActions    = @();
            IncludeUsers          = @("All");
            PersistentBrowserMode = "";
            SignInFrequencyType   = "";
            SignInRiskLevels      = @();
            State                 = "enabled";
            UserRiskLevels        = @();
        }
        AADConditionalAccessPolicy e1a40a33-19a5-43ff-9307-9ecc0b4949b8
        {
            BuiltInControls       = @("Block");
            ClientAppTypes        = @("All");
            CloudAppSecurityType  = "";
            DisplayName           = "BLOCK - Countries not Allowed";
            Ensure                = "Present";
            ExcludeApplications   = @();
            ExcludeLocations      = @("AllTrusted");
            ExcludeUsers          = @("admin@$OrganizationName");
            GlobalAdminAccount    = $Credsglobaladmin;
            GrantControlOperator  = "OR";
            Id                    = "2837e70f-6c5e-426c-a109-10a3ff165e95";
            IncludeApplications   = @("All");
            IncludeLocations      = @("All");
            IncludeUserActions    = @();
            IncludeUsers          = @("All");
            PersistentBrowserMode = "";
            SignInFrequencyType   = "";
            SignInRiskLevels      = @();
            State                 = "enabled";
            UserRiskLevels        = @();
        }
        AADGroupsSettings ca6df38f-d85f-4094-b812-56ce8bcd819d
        {
            Ensure               = "Absent";
            GlobalAdminAccount   = $Credsglobaladmin;
            IsSingleInstance     = "Yes";
        }
        AADPolicy fd96d761-24d2-4d3f-9a35-06d317f2b8fc
        {
            Definition            = @("{`"B2BManagementPolicy`":{`"InvitationsAllowedAndBlockedDomainsPolicy`":{`"BlockedDomains`":[]},`"AutoRedeemPolicy`":{`"AdminConsentedForUsersIntoTenantIds`":[],`"NoAADConsentForUsersFromTenantsIds`":[]}}}");
            DisplayName           = "B2BManagementPolicy";
            Ensure                = "Present";
            GlobalAdminAccount    = $Credsglobaladmin;
            Id                    = "6ce7c380-e23e-4051-a519-ada98cbf03c2";
            IsOrganizationDefault = $True;
            Type                  = "B2BManagementPolicy";
        }
        AADTenantDetails 5b064611-91f7-4177-9be2-8a02ee2388fa
        {
            GlobalAdminAccount                   = $Credsglobaladmin;
            IsSingleInstance                     = "Yes";
            MarketingNotificationEmails          = @();
            SecurityComplianceNotificationMails  = @();
            SecurityComplianceNotificationPhones = @();
            TechnicalNotificationMails           = @("stockpiling@valorem.com");
        }
        EXOAntiPhishPolicy 97fa383d-c21b-4516-9f6d-8495f59b4cba
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
        EXOAntiPhishPolicy f84f43fa-1b1d-4e9d-b380-e69551f24119
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
        EXOAntiPhishRule 7b01f005-28ac-4cb1-9669-562056c7e5e4
        {
            AntiPhishPolicy      = "ATP-AntiPhishingPolicy";
            Enabled              = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "ATP-AntiPhishingPolicy";
            Priority             = 0;
            RecipientDomainIs    = @("$OrganizationName");
        }
        EXOAtpPolicyForO365 8b6235ae-9093-4eb5-9ddd-9e40770067f8
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
        EXOHostedConnectionFilterPolicy b35e5c19-68fa-43c6-a777-d45fbe969bd3
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
        EXOHostedContentFilterPolicy 8a839b1e-3ff3-4a34-8540-c05e339f43d8
        {
            AddXHeaderValue                      = "";
            AdminDisplayName                     = "";
            AllowedSenderDomains                 = @();
            AllowedSenders                       = @();
            BlockedSenderDomains                 = @();
            BlockedSenders                       = @();
            BulkSpamAction                       = "MoveToJmf";
            BulkThreshold                        = 7;
            DownloadLink                         = $False;
            EnableEndUserSpamNotifications       = $False;
            EnableLanguageBlockList              = $False;
            EnableRegionBlockList                = $False;
            EndUserSpamNotificationCustomSubject = "";
            EndUserSpamNotificationFrequency     = 3;
            EndUserSpamNotificationLanguage      = "Default";
            Ensure                               = "Present";
            GlobalAdminAccount                   = $Credsglobaladmin;
            HighConfidenceSpamAction             = "MoveToJmf";
            Identity                             = "Default";
            IncreaseScoreWithBizOrInfoUrls       = "Off";
            IncreaseScoreWithImageLinks          = "Off";
            IncreaseScoreWithNumericIps          = "Off";
            IncreaseScoreWithRedirectToOtherPort = "Off";
            InlineSafetyTipsEnabled              = $True;
            LanguageBlockList                    = @();
            MakeDefault                          = $True;
            MarkAsSpamBulkMail                   = "On";
            MarkAsSpamEmbedTagsInHtml            = "Off";
            MarkAsSpamEmptyMessages              = "Off";
            MarkAsSpamFormTagsInHtml             = "Off";
            MarkAsSpamFramesInHtml               = "Off";
            MarkAsSpamFromAddressAuthFail        = "Off";
            MarkAsSpamJavaScriptInHtml           = "Off";
            MarkAsSpamNdrBackscatter             = "Off";
            MarkAsSpamObjectTagsInHtml           = "Off";
            MarkAsSpamSensitiveWordList          = "Off";
            MarkAsSpamSpfRecordHardFail          = "Off";
            MarkAsSpamWebBugsInHtml              = "Off";
            ModifySubjectValue                   = "";
            PhishSpamAction                      = "MoveToJmf";
            PhishZapEnabled                      = $True;
            QuarantineRetentionPeriod            = 15;
            RedirectToRecipients                 = @();
            RegionBlockList                      = @();
            SpamAction                           = "MoveToJmf";
            SpamZapEnabled                       = $True;
            TestModeAction                       = "None";
            TestModeBccToRecipients              = @();
        }
        EXOHostedOutboundSpamFilterPolicy 22a160a3-280b-45b0-8a3d-dd77150b785a
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
        EXOMalwareFilterPolicy 433863eb-739b-4fc2-b46a-0d70bc53a32f
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
        EXOSafeAttachmentPolicy 9e479ed2-1eec-408f-be6e-c9992a14c813
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
        EXOSafeAttachmentRule 5368199c-f20e-4bf6-8d1a-f14309f80f2b
        {
            Enabled              = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "ATP-SafeAttachementsPolicy";
            Priority             = 0;
            RecipientDomainIs    = @("$OrganizationName");
            SafeAttachmentPolicy = "ATP-SafeAttachementsPolicy";
        }
        EXOSafeLinksPolicy 2299aff9-62db-4da9-98f0-0269775ded25
        {
            AdminDisplayName         = "";
            DeliverMessageAfterScan  = $False;
            DoNotAllowClickThrough   = $True;
            DoNotRewriteUrls         = @();
            DoNotTrackUserClicks     = $False;
            EnableForInternalSenders = $True;
            EnableSafeLinksForTeams  = $False;
            Ensure                   = "Present";
            GlobalAdminAccount       = $Credsglobaladmin;
            Identity                 = "Safe Links";
            IsEnabled                = $True;
            ScanUrls                 = $True;
        }
        EXOSafeLinksPolicy aa7d4db3-ccb1-40ff-9e4e-83ba9b4e422e
        {
            AdminDisplayName         = "ATP-SafeLinks";
            DeliverMessageAfterScan  = $False;
            DoNotAllowClickThrough   = $True;
            DoNotRewriteUrls         = @();
            DoNotTrackUserClicks     = $True;
            EnableForInternalSenders = $False;
            EnableSafeLinksForTeams  = $False;
            Ensure                   = "Present";
            GlobalAdminAccount       = $Credsglobaladmin;
            Identity                 = "ATP-SafeLinks";
            IsEnabled                = $True;
            ScanUrls                 = $True;
        }
        EXOSafeLinksRule 7d750204-26f1-4731-90b7-6a72116f94ec
        {
            Enabled              = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "ATP-SafeLinks";
            Priority             = 0;
            RecipientDomainIs    = @("$OrganizationName");
            SafeLinksPolicy      = "ATP-SafeLinks";
        }
        EXOSharingPolicy b5a7ca31-a942-4cf4-9e0a-3f13065881cf
        {
            Default              = $True;
            Domains              = @("Anonymous:CalendarSharingFreeBusyReviewer","*:CalendarSharingFreeBusySimple");
            Enabled              = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Default Sharing Policy";
        }
        O365AdminAuditLogConfig 24eaead4-b4ab-472f-9f58-b8fa8a5e0a26
        {
            Ensure                          = "Present";
            GlobalAdminAccount              = $Credsglobaladmin;
            IsSingleInstance                = "Yes";
            UnifiedAuditLogIngestionEnabled = "Enabled";
        }
        O365OrgCustomizationSetting acc4f38a-3011-419b-8a59-b176d0045c2f
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            IsSingleInstance     = "Yes";
        }
        ODSettings 5a3ce948-f2c5-43df-9234-c9a96ae6cf59
        {
            BlockMacSync                              = $False;
            DisableReportProblemDialog                = $False;
            DomainGuids                               = @();
            Ensure                                    = "Present";
            ExcludedFileExtensions                    = @();
            GlobalAdminAccount                        = $Credsglobaladmin;
            IsSingleInstance                          = "Yes";
            NotificationsInOneDriveForBusinessEnabled = $True;
            NotifyOwnersWhenInvitationsAccepted       = $True;
            ODBAccessRequests                         = "Unspecified";
            ODBMembersCanShare                        = "Unspecified";
            OneDriveForGuestsEnabled                  = $False;
            OneDriveStorageQuota                      = 1048576;
            OrphanedPersonalSitesRetentionPeriod      = 30;
        }
        SPOAccessControlSettings f39629fb-d535-444f-8776-3f7f20dacaf3
        {
            CommentsOnSitePagesDisabled  = $False;
            DisallowInfectedFileDownload = $False;
            DisplayStartASiteOption      = $True;
            EmailAttestationReAuthDays   = 30;
            EmailAttestationRequired     = $False;
            ExternalServicesEnabled      = $True;
            GlobalAdminAccount           = $Credsglobaladmin;
            IPAddressAllowList           = "";
            IPAddressEnforcement         = $False;
            IPAddressWACTokenLifetime    = 15;
            IsSingleInstance             = "Yes";
            SocialBarOnSitePagesDisabled = $False;
        }
        SPOSharingSettings aeaa7155-561a-40de-a8d7-8b59461d0d06
        {
            BccExternalSharingInvitations              = $False;
            DefaultLinkPermission                      = "Edit";
            DefaultSharingLinkType                     = "Direct";
            EnableGuestSignInAcceleration              = $False;
            FileAnonymousLinkType                      = "View";
            FolderAnonymousLinkType                    = "Edit";
            GlobalAdminAccount                         = $Credsglobaladmin;
            IsSingleInstance                           = "Yes";
            NotifyOwnersWhenItemsReshared              = $True;
            PreventExternalUsersFromResharing          = $True;
            ProvisionSharedWithEveryoneFolder          = $False;
            RequireAcceptingAccountMatchInvitedAccount = $True;
            RequireAnonymousLinksExpireInDays          = 30;
            SharingCapability                          = "ExternalUserAndGuestSharing";
            SharingDomainRestrictionMode               = "None";
            ShowAllUsersClaim                          = $False;
            ShowEveryoneClaim                          = $False;
            ShowEveryoneExceptExternalUsersClaim       = $True;
            ShowPeoplePickerSuggestionsForGuestUsers   = $False;
        }
        SPOTenantCdnPolicy bb7931a5-d10e-4b20-ab3c-b0ef7eca9b81
        {
            CDNType                              = "Public";
            ExcludeRestrictedSiteClassifications = @();
            GlobalAdminAccount                   = $Credsglobaladmin;
            IncludeFileExtensions                = @();
        }
        SPOTenantSettings 71e1abea-2267-4e62-9807-9683e3737bdb
        {
            ApplyAppEnforcedRestrictionsToAdHocRecipients = $True;
            FilePickerExternalImageSearchEnabled          = $True;
            GlobalAdminAccount                            = $Credsglobaladmin;
            HideDefaultThemes                             = $False;
            IsSingleInstance                              = "Yes";
            LegacyAuthProtocolsEnabled                    = $False;
            MaxCompatibilityLevel                         = "15";
            MinCompatibilityLevel                         = "15";
            NotificationsInSharePointEnabled              = $True;
            OfficeClientADALDisabled                      = $False;
            OwnerAnonymousNotification                    = $True;
            PublicCdnAllowedFileTypes                     = "CSS,EOT,GIF,ICO,JPEG,JPG,JS,MAP,PNG,SVG,TTF,WOFF";
            PublicCdnEnabled                              = $False;
            SearchResolveExactEmailOrUPN                  = $False;
            SignInAccelerationDomain                      = "";
            UseFindPeopleInPeoplePicker                   = $False;
            UsePersistentCookiesForExplorerView           = $False;
            UserVoiceForFeedbackEnabled                   = $True;
        }
        TeamsCallingPolicy 43003b3a-ce07-47d4-9cfc-c951711c3fff
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
        TeamsCallingPolicy 7e1b57fa-bc23-4663-8eac-6656d961ae9c
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
        TeamsCallingPolicy 117ed351-d541-49ea-bfd7-3ce804c0ce03
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
        TeamsCallingPolicy 749138fc-82dc-4689-819b-c6d01b7f22c6
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
        TeamsCallingPolicy 9c49cadc-cc54-40ef-a899-541026187e3e
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
        TeamsClientConfiguration 2ad518b9-ce1f-4bc3-aece-0d6f0e721953
        {
            AllowBox                         = $False;
            AllowDropBox                     = $False;
            AllowEgnyte                      = $False;
            AllowEmailIntoChannel            = $False;
            AllowGoogleDrive                 = $False;
            AllowGuestUser                   = $False;
            AllowOrganizationTab             = $True;
            AllowResourceAccountSendMessage  = $True;
            AllowScopedPeopleSearchandAccess = $False;
            AllowShareFile                   = $False;
            AllowSkypeBusinessInterop        = $True;
            ContentPin                       = "RequiredOutsideScheduleMeeting";
            GlobalAdminAccount               = $Credsglobaladmin;
            Identity                         = "Global";
            ResourceAccountContentAccess     = "NoAccess";
        }
        TeamsGuestCallingConfiguration ca54531b-7ca8-478e-a489-5ce69e31a19f
        {
            AllowPrivateCalling  = $False;
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Global";
        }
        TeamsGuestMeetingConfiguration 95a0c200-78ea-4cbe-b673-533fb12e152a
        {
            AllowIPVideo         = $True;
            AllowMeetNow         = $True;
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Global";
            ScreenSharingMode    = "EntireScreen";
        }
        TeamsGuestMessagingConfiguration 2114e59e-0522-492e-a377-0ae44b162f50
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
        TeamsMeetingBroadcastConfiguration c07320ae-4764-49bd-87d0-c392d7886e8c
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
        TeamsMeetingBroadcastPolicy ca29d05b-e321-4f61-a642-59a38254a478
        {
            AllowBroadcastScheduling        = $True;
            AllowBroadcastTranscription     = $True;
            BroadcastAttendeeVisibilityMode = "EveryoneInCompany";
            BroadcastRecordingMode          = "UserOverride";
            Ensure                          = "Present";
            GlobalAdminAccount              = $Credsglobaladmin;
            Identity                        = "Global";
        }
        TeamsMeetingBroadcastPolicy 28d90cc9-8797-4e8d-872c-812009094697
        {
            AllowBroadcastScheduling        = $True;
            AllowBroadcastTranscription     = $False;
            BroadcastAttendeeVisibilityMode = "EveryoneInCompany";
            BroadcastRecordingMode          = "AlwaysEnabled";
            Ensure                          = "Present";
            GlobalAdminAccount              = $Credsglobaladmin;
            Identity                        = "Tag:Default";
        }
        TeamsMeetingConfiguration 6fbc39b5-ede2-4fcb-a8c4-ebf29d36dd93
        {
            ClientAppSharingPort        = 50040;
            ClientAppSharingPortRange   = 20;
            ClientAudioPort             = 50000;
            ClientAudioPortRange        = 20;
            ClientMediaPortRangeEnabled = $True;
            ClientVideoPort             = 50020;
            ClientVideoPortRange        = 20;
            DisableAnonymousJoin        = $False;
            EnableQoS                   = $False;
            GlobalAdminAccount          = $Credsglobaladmin;
            Identity                    = "Global";
        }
        TeamsMeetingPolicy d4df6bf6-a818-4327-ab84-902a30a250bd
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
        TeamsMeetingPolicy 7bcc1195-032e-4030-9ccd-e32190282baf
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
        TeamsMeetingPolicy 5d4d3677-784b-4e04-bf9f-2e72909b350a
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
        TeamsMeetingPolicy 3c61f205-0753-4481-bdaa-d2738d3cc5dd
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
        TeamsMeetingPolicy c03c4090-e1d4-4ab1-81a6-bd3527612b4d
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
        TeamsMeetingPolicy d7df2c5e-a3df-4b4e-b8a9-04eb9fe5cb9a
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
        TeamsMeetingPolicy d3b883c2-3c68-4e14-9f53-91bbd02a9a97
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
        TeamsMessagingPolicy 4d9f9983-c43b-4b04-b33e-1c50c6d08f02
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
        TeamsMessagingPolicy 9f0c0a07-7a2b-4a8c-8313-acc8a28a1c13
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
        TeamsMessagingPolicy 0de3bccd-d5c6-4c87-9ab5-242c144190ca
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
        TeamsMessagingPolicy e7d80167-2cfe-4371-b8a8-96381dc59e34
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
        TeamsUpgradeConfiguration 3c1ef218-03d1-4474-bb08-b11704e9e267
        {
            DownloadTeams        = $True;
            GlobalAdminAccount   = $Credsglobaladmin;
            IsSingleInstance     = "Yes";
            SfBMeetingJoinUx     = "NativeLimitedClient";
        }
        TeamsUpgradePolicy 61f71c0f-5956-47fb-a8c0-ca0798ba54c4
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "Global";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 38a93f53-1fd7-4a0a-9bf3-a7c8bb0286c2
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "UpgradeToTeams";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 863a1e78-edb0-473a-9d0f-a48137c23704
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "Islands";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy e1998a36-712d-42d8-8eb3-90598a0f2e9e
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "IslandsWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 982bc842-8098-4512-a253-4acda72ffb20
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBOnly";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy a015e566-9ce6-4ebb-84a4-b0f641ee42e9
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBOnlyWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy b96f331b-d9e6-4063-b038-138712e8eea8
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollab";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 5a0118d5-30bf-4caa-af42-c1358e8787df
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollabWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 18ddbf76-df0c-4000-b0c6-03ab8648bc40
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollabAndMeetings";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 2f5560e1-fdc7-4671-9b4c-df2a3c6a59a1
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollabAndMeetingsWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
    }
}
BaselineConfiguration-2021-Feb-11-1402PM-runbook_2021-Feb-11-1402PM -ConfigurationData .\ConfigurationData.psd1 -GlobalAdminAccount $GlobalAdminAccount
