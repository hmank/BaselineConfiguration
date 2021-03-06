# Generated with Microsoft365DSC version 1.20.909.1
# For additional information on how to use Microsoft365DSC, please visit https://aka.ms/M365DSC
param (
    [parameter()]
    [System.Management.Automation.PSCredential]
    $GlobalAdminAccount
)

Configuration M365TenantConfig
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
    Import-DscResource -ModuleName Microsoft365DSC

    Node localhost
    {
        AADGroupsSettings e5f899d1-065e-4b57-b278-bbcbc00d9525
        {
            Ensure               = "Absent";
            GlobalAdminAccount   = $Credsglobaladmin;
            IsSingleInstance     = "Yes";
        }
        EXOAcceptedDomain 48144254-4df0-4fb5-b910-5ba48b5ab93b
        {
            DomainType           = "Authoritative";
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "$OrganizationName";
            MatchSubDomains      = $False;
            OutboundOnly         = $False;
        }
        EXOAntiPhishPolicy 5b2c884f-7633-4f71-b5f2-d6598b2e8ef4
        {
            AdminDisplayName                    = "";
            AuthenticationFailAction            = "MoveToJmf";
            EnableAntispoofEnforcement          = $True;
            Enabled                             = $True;
            EnableMailboxIntelligence           = $True;
            EnableOrganizationDomainsProtection = $True;
            EnableSimilarDomainsSafetyTips      = $True;
            EnableSimilarUsersSafetyTips        = $True;
            EnableTargetedDomainsProtection     = $False;
            EnableTargetedUserProtection        = $True;
            EnableUnusualCharactersSafetyTips   = $True;
            Ensure                              = "Present";
            ExcludedDomains                     = @();
            ExcludedSenders                     = @();
            GlobalAdminAccount                  = $Credsglobaladmin;
            Identity                            = "GoC-AntiPhishingPolicy";
            PhishThresholdLevel                 = 2;
            TargetedDomainActionRecipients      = @();
            TargetedDomainProtectionAction      = "NoAction";
            TargetedDomainsToProtect            = @();
            TargetedUserActionRecipients        = @();
            TargetedUserProtectionAction        = "Quarantine";
            TargetedUsersToProtect              = @("alex wilber;alexw@$OrganizationName");
        }
        EXOAntiPhishPolicy 7671f47a-436b-47a4-83db-e166dd6284a5
        {
            AdminDisplayName                    = "";
            AuthenticationFailAction            = "MoveToJmf";
            EnableAntispoofEnforcement          = $True;
            Enabled                             = $True;
            EnableMailboxIntelligence           = $True;
            EnableOrganizationDomainsProtection = $False;
            EnableSimilarDomainsSafetyTips      = $False;
            EnableSimilarUsersSafetyTips        = $False;
            EnableTargetedDomainsProtection     = $False;
            EnableTargetedUserProtection        = $False;
            EnableUnusualCharactersSafetyTips   = $False;
            Ensure                              = "Present";
            ExcludedDomains                     = @();
            ExcludedSenders                     = @();
            GlobalAdminAccount                  = $Credsglobaladmin;
            Identity                            = "Office365 AntiPhish Default";
            PhishThresholdLevel                 = 1;
            TargetedDomainActionRecipients      = @();
            TargetedDomainProtectionAction      = "NoAction";
            TargetedDomainsToProtect            = @();
            TargetedUserActionRecipients        = @();
            TargetedUserProtectionAction        = "NoAction";
            TargetedUsersToProtect              = @();
        }
        EXOAntiPhishRule f5d389b8-61ce-4385-bee5-cf9e074ca5b5
        {
            AntiPhishPolicy      = "GoC-AntiPhishingPolicy";
            Enabled              = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "GoC-AntiPhishingPolicy";
            Priority             = 0;
            RecipientDomainIs    = @("$OrganizationName");
        }
        EXOAtpPolicyForO365 cb8cdd1e-c7de-458d-bcf2-448cb936b5f1
        {
            AllowClickThrough         = $False;
            BlockUrls                 = @();
            EnableATPForSPOTeamsODB   = $False;
            EnableSafeLinksForClients = $False;
            Ensure                    = "Present";
            GlobalAdminAccount        = $Credsglobaladmin;
            Identity                  = "$OrganizationName\Default";
            IsSingleInstance          = "Yes";
            TrackClicks               = $False;
        }
        EXOCASMailboxPlan b4179eaf-175d-4a04-b0a3-ff7e98c50c09
        {
            ActiveSyncEnabled    = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "ExchangeOnline-e4e8c944-f15d-4381-b337-1e9236f9c8eb";
            ImapEnabled          = $True;
            OwaMailboxPolicy     = "OwaMailboxPolicy-Default";
            PopEnabled           = $True;
        }
        EXOCASMailboxPlan 2c913616-b6b6-43bf-a888-691f6645ab27
        {
            ActiveSyncEnabled    = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "ExchangeOnlineEnterprise-c00c4f48-8b73-4db3-b188-34ac31a2293e";
            ImapEnabled          = $True;
            OwaMailboxPolicy     = "OwaMailboxPolicy-Default";
            PopEnabled           = $True;
        }
        EXOCASMailboxPlan 4cdcaec5-3399-47b5-be66-2c3106c1a9e1
        {
            ActiveSyncEnabled    = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "ExchangeOnlineDeskless-5b48112a-f912-4007-a06e-d416ce5206a6";
            ImapEnabled          = $False;
            OwaMailboxPolicy     = "OwaMailboxPolicy-Default";
            PopEnabled           = $True;
        }
        EXOCASMailboxPlan a11eaf34-bea7-4d35-b11b-3cc9da97754c
        {
            ActiveSyncEnabled    = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "ExchangeOnlineEssentials-cb5b2b80-c312-48b2-a533-3fd8e7805830";
            ImapEnabled          = $True;
            OwaMailboxPolicy     = "OwaMailboxPolicy-Default";
            PopEnabled           = $True;
        }
        EXOEmailAddressPolicy 0123bc6d-be4b-4450-b5d8-0c11b872a300
        {
            EnabledEmailAddressTemplates      = @("SMTP:@$OrganizationName");
            EnabledPrimarySMTPAddressTemplate = "@$OrganizationName";
            Ensure                            = "Present";
            GlobalAdminAccount                = $Credsglobaladmin;
            ManagedByFilter                   = "";
            Name                              = "Default Policy";
            Priority                          = "Lowest";
        }
        EXOHostedConnectionFilterPolicy d6cdc5f5-7c30-490d-a099-aa69d6fdcb53
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
        EXOHostedContentFilterPolicy 66e825cd-79cb-400a-a6a4-8fc4ef1459e0
        {
            AddXHeaderValue                          = "";
            AdminDisplayName                         = "";
            AllowedSenderDomains                     = @();
            AllowedSenders                           = @();
            BlockedSenderDomains                     = @();
            BlockedSenders                           = @();
            BulkSpamAction                           = "MoveToJmf";
            BulkThreshold                            = 7;
            DownloadLink                             = $False;
            EnableEndUserSpamNotifications           = $False;
            EnableLanguageBlockList                  = $False;
            EnableRegionBlockList                    = $False;
            EndUserSpamNotificationCustomFromAddress = "";
            EndUserSpamNotificationCustomFromName    = "";
            EndUserSpamNotificationCustomSubject     = "";
            EndUserSpamNotificationFrequency         = 3;
            EndUserSpamNotificationLanguage          = "Default";
            Ensure                                   = "Present";
            GlobalAdminAccount                       = $Credsglobaladmin;
            HighConfidenceSpamAction                 = "MoveToJmf";
            Identity                                 = "Default";
            IncreaseScoreWithBizOrInfoUrls           = "Off";
            IncreaseScoreWithImageLinks              = "Off";
            IncreaseScoreWithNumericIps              = "Off";
            IncreaseScoreWithRedirectToOtherPort     = "Off";
            InlineSafetyTipsEnabled                  = $True;
            LanguageBlockList                        = @();
            MakeDefault                              = $True;
            MarkAsSpamBulkMail                       = "On";
            MarkAsSpamEmbedTagsInHtml                = "Off";
            MarkAsSpamEmptyMessages                  = "Off";
            MarkAsSpamFormTagsInHtml                 = "Off";
            MarkAsSpamFramesInHtml                   = "Off";
            MarkAsSpamFromAddressAuthFail            = "Off";
            MarkAsSpamJavaScriptInHtml               = "Off";
            MarkAsSpamNdrBackscatter                 = "Off";
            MarkAsSpamObjectTagsInHtml               = "Off";
            MarkAsSpamSensitiveWordList              = "Off";
            MarkAsSpamSpfRecordHardFail              = "Off";
            MarkAsSpamWebBugsInHtml                  = "Off";
            ModifySubjectValue                       = "";
            PhishSpamAction                          = "MoveToJmf";
            QuarantineRetentionPeriod                = 15;
            RedirectToRecipients                     = @();
            RegionBlockList                          = @();
            SpamAction                               = "MoveToJmf";
            TestModeAction                           = "None";
            TestModeBccToRecipients                  = @();
            ZapEnabled                               = $True;
        }
        EXOHostedOutboundSpamFilterPolicy 9de0b75f-935c-4e7a-ac05-01571e469c37
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
        EXOMailTips b46ef3d6-973a-4a67-b7b0-8216c284f8f3
        {
            Ensure                                = "Present";
            GlobalAdminAccount                    = $Credsglobaladmin;
            MailTipsAllTipsEnabled                = $True;
            MailTipsExternalRecipientsTipsEnabled = $False;
            MailTipsGroupMetricsEnabled           = $True;
            MailTipsLargeAudienceThreshold        = 25;
            MailTipsMailboxSourcedTipsEnabled     = $True;
            Organization                          = "$OrganizationName";
        }
        EXOMalwareFilterPolicy 98a1a78f-ce97-4c5f-ac04-e48f8daf2d7a
        {
            Action                                 = "DeleteMessage";
            AdminDisplayName                       = "";
            CustomAlertText                        = "";
            CustomExternalBody                     = "";
            CustomExternalSubject                  = "";
            CustomFromAddress                      = "";
            CustomFromName                         = "";
            CustomInternalBody                     = "";
            CustomInternalSubject                  = "";
            CustomNotifications                    = $False;
            EnableExternalSenderAdminNotifications = $False;
            EnableExternalSenderNotifications      = $False;
            EnableFileFilter                       = $True;
            EnableInternalSenderAdminNotifications = $True;
            EnableInternalSenderNotifications      = $False;
            Ensure                                 = "Present";
            ExternalSenderAdminAddress             = "";
            FileTypes                              = @("ace","ani","app","docm","exe","jar","reg","scr","vbe","vbs");
            GlobalAdminAccount                     = $Credsglobaladmin;
            Identity                               = "Default";
            InternalSenderAdminAddress             = "domadmin@wavecoreinnovations.com";
            ZapEnabled                             = $True;
        }
        EXOMobileDeviceMailboxPolicy 3143553e-6940-4151-9f79-7c9555b1e43f
        {
            AllowApplePushNotifications              = $True;
            AllowBluetooth                           = "Allow";
            AllowBrowser                             = $True;
            AllowCamera                              = $True;
            AllowConsumerEmail                       = $True;
            AllowDesktopSync                         = $True;
            AllowExternalDeviceManagement            = $False;
            AllowGooglePushNotifications             = $True;
            AllowHTMLEmail                           = $True;
            AllowInternetSharing                     = $True;
            AllowIrDA                                = $True;
            AllowMicrosoftPushNotifications          = $True;
            AllowMobileOTAUpdate                     = $True;
            AllowNonProvisionableDevices             = $True;
            AllowPOPIMAPEmail                        = $True;
            AllowRemoteDesktop                       = $True;
            AllowSimplePassword                      = $True;
            AllowSMIMEEncryptionAlgorithmNegotiation = "AllowAnyAlgorithmNegotiation";
            AllowSMIMESoftCerts                      = $True;
            AllowStorageCard                         = $True;
            AllowTextMessaging                       = $True;
            AllowUnsignedApplications                = $True;
            AllowUnsignedInstallationPackages        = $True;
            AllowWiFi                                = $True;
            AlphanumericPasswordRequired             = $False;
            ApprovedApplicationList                  = @();
            AttachmentsEnabled                       = $True;
            DeviceEncryptionEnabled                  = $False;
            DevicePolicyRefreshInterval              = "Unlimited";
            Ensure                                   = "Present";
            GlobalAdminAccount                       = $Credsglobaladmin;
            IrmEnabled                               = $True;
            IsDefault                                = $True;
            MaxAttachmentSize                        = "Unlimited";
            MaxCalendarAgeFilter                     = "All";
            MaxEmailAgeFilter                        = "All";
            MaxEmailBodyTruncationSize               = "Unlimited";
            MaxEmailHTMLBodyTruncationSize           = "Unlimited";
            MaxInactivityTimeLock                    = "Unlimited";
            MaxPasswordFailedAttempts                = "Unlimited";
            MinPasswordComplexCharacters             = 1;
            Name                                     = "Default";
            PasswordEnabled                          = $False;
            PasswordExpiration                       = "Unlimited";
            PasswordHistory                          = 0;
            PasswordRecoveryEnabled                  = $False;
            RequireDeviceEncryption                  = $False;
            RequireEncryptedSMIMEMessages            = $False;
            RequireEncryptionSMIMEAlgorithm          = "TripleDES";
            RequireManualSyncWhenRoaming             = $False;
            RequireSignedSMIMEAlgorithm              = "SHA1";
            RequireSignedSMIMEMessages               = $False;
            RequireStorageCardEncryption             = $False;
            UnapprovedInROMApplicationList           = @();
            UNCAccessEnabled                         = $True;
            WSSAccessEnabled                         = $True;
        }
        EXOOrganizationConfig b2272dac-6c3f-4e02-8b3d-aca7ae9cc08c
        {
            ActivityBasedAuthenticationTimeoutEnabled                 = $True;
            ActivityBasedAuthenticationTimeoutInterval                = "06:00:00";
            ActivityBasedAuthenticationTimeoutWithSingleSignOnEnabled = $True;
            AppsForOfficeEnabled                                      = $True;
            AsyncSendEnabled                                          = $True;
            AuditDisabled                                             = $False;
            AutoExpandingArchive                                      = $False;
            BookingsEnabled                                           = $True;
            BookingsPaymentsEnabled                                   = $False;
            BookingsSocialSharingRestricted                           = $False;
            ByteEncoderTypeFor7BitCharsets                            = 0;
            ConnectorsActionableMessagesEnabled                       = $True;
            ConnectorsEnabled                                         = $True;
            ConnectorsEnabledForOutlook                               = $True;
            ConnectorsEnabledForSharepoint                            = $True;
            ConnectorsEnabledForTeams                                 = $True;
            ConnectorsEnabledForYammer                                = $True;
            DefaultGroupAccessType                                    = "Private";
            DefaultPublicFolderDeletedItemRetention                   = "30.00:00:00";
            DefaultPublicFolderIssueWarningQuota                      = "1.7 GB (1,825,361,920 bytes)";
            DefaultPublicFolderMaxItemSize                            = "Unlimited";
            DefaultPublicFolderMovedItemRetention                     = "7.00:00:00";
            DefaultPublicFolderProhibitPostQuota                      = "2 GB (2,147,483,648 bytes)";
            DirectReportsGroupAutoCreationEnabled                     = $False;
            DistributionGroupNameBlockedWordsList                     = @();
            DistributionGroupNamingPolicy                             = "";
            ElcProcessingDisabled                                     = $False;
            EndUserDLUpgradeFlowsDisabled                             = $False;
            ExchangeNotificationEnabled                               = $True;
            ExchangeNotificationRecipients                            = @();
            GlobalAdminAccount                                        = $Credsglobaladmin;
            IPListBlocked                                             = @();
            IsSingleInstance                                          = "Yes";
            LeanPopoutEnabled                                         = $False;
            LinkPreviewEnabled                                        = $True;
            MailTipsAllTipsEnabled                                    = $True;
            MailTipsExternalRecipientsTipsEnabled                     = $False;
            MailTipsGroupMetricsEnabled                               = $True;
            MailTipsLargeAudienceThreshold                            = 25;
            MailTipsMailboxSourcedTipsEnabled                         = $True;
            OAuth2ClientProfileEnabled                                = $True;
            OutlookMobileGCCRestrictionsEnabled                       = $False;
            OutlookPayEnabled                                         = $True;
            PublicComputersDetectionEnabled                           = $False;
            PublicFoldersEnabled                                      = "Local";
            PublicFolderShowClientControl                             = $False;
            ReadTrackingEnabled                                       = $False;
            RemotePublicFolderMailboxes                               = @();
            SmtpActionableMessagesEnabled                             = $True;
            VisibleMeetingUpdateProperties                            = "Location,AllProperties:15";
            WebPushNotificationsDisabled                              = $False;
            WebSuggestedRepliesDisabled                               = $False;
        }
        EXOOwaMailboxPolicy 6b6aff31-a4d1-4aeb-b3e8-9f902b64e2a3
        {
            ActionForUnknownFileAndMIMETypes                     = "Allow";
            ActiveSyncIntegrationEnabled                         = $True;
            AdditionalStorageProvidersAvailable                  = $True;
            AllAddressListsEnabled                               = $True;
            AllowCopyContactsToDeviceAddressBook                 = $True;
            AllowedFileTypes                                     = @(".rpmsg",".xlsx",".xlsm",".xlsb",".vstx",".vstm",".vssx",".vssm",".vsdx",".vsdm",".tiff",".pptx",".pptm",".ppsx",".ppsm",".docx",".docm",".zip",".xls",".wmv",".wma",".wav",".vtx",".vsx",".vst",".vss",".vsd",".vdx",".txt",".tif",".rtf",".pub",".ppt",".png",".pdf",".one",".mp3",".jpg",".gif",".doc",".csv",".bmp",".avi");
            AllowedMimeTypes                                     = @("image/jpeg","image/png","image/gif","image/bmp");
            BlockedFileTypes                                     = @(".settingcontent-ms",".printerexport",".appcontent-ms",".appref-ms",".vsmacros",".website",".msh2xml",".msh1xml",".diagcab",".webpnp",".ps2xml",".ps1xml",".mshxml",".gadget",".theme",".psdm1",".mhtml",".cdxml",".xbap",".vhdx",".pyzw",".pssc",".psd1",".psc2",".psc1",".msh2",".msh1",".jnlp",".aspx",".appx",".xnk",".xll",".wsh",".wsf",".wsc",".wsb",".vsw",".vhd",".vbs",".vbp",".vbe",".url",".udl",".tmp",".shs",".shb",".sct",".scr",".scf",".reg",".pyz",".pyw",".pyo",".pyc",".pst",".ps2",".ps1",".prg",".prf",".plg",".pif",".pcd",".osd",".ops",".msu",".mst",".msp",".msi",".msh",".msc",".mht",".mdz",".mdw",".mdt",".mde",".mdb",".mda",".mcf",".maw",".mav",".mau",".mat",".mas",".mar",".maq",".mam",".mag",".maf",".mad",".lnk",".ksh",".jse",".jar",".its",".isp",".ins",".inf",".htc",".hta",".hpj",".hlp",".grp",".fxp",".exe",".der",".csh",".crt",".cpl",".com",".cnt",".cmd",".chm",".cer",".bat",".bas",".asx",".asp",".app",".apk",".adp",".ade",".ws",".vb",".py",".pl",".js");
            BlockedMimeTypes                                     = @("application/x-javascript","application/javascript","application/msaccess","x-internet-signup","text/javascript","application/prg","application/hta","text/scriplet");
            ClassicAttachmentsEnabled                            = $True;
            ConditionalAccessPolicy                              = "Off";
            DefaultTheme                                         = "";
            DirectFileAccessOnPrivateComputersEnabled            = $True;
            DirectFileAccessOnPublicComputersEnabled             = $True;
            DisplayPhotosEnabled                                 = $True;
            Ensure                                               = "Present";
            ExplicitLogonEnabled                                 = $True;
            ExternalImageProxyEnabled                            = $True;
            ForceSaveAttachmentFilteringEnabled                  = $False;
            ForceSaveFileTypes                                   = @(".svgz",".html",".xml",".swf",".svg",".spl",".htm",".dir",".dcr");
            ForceSaveMimeTypes                                   = @("Application/x-shockwave-flash","Application/octet-stream","Application/futuresplash","Application/x-director","application/xml","image/svg+xml","text/html","text/xml");
            ForceWacViewingFirstOnPrivateComputers               = $False;
            ForceWacViewingFirstOnPublicComputers                = $False;
            FreCardsEnabled                                      = $True;
            GlobalAddressListEnabled                             = $True;
            GlobalAdminAccount                                   = $Credsglobaladmin;
            GroupCreationEnabled                                 = $True;
            InstantMessagingEnabled                              = $True;
            InstantMessagingType                                 = "Ocs";
            InterestingCalendarsEnabled                          = $True;
            IRMEnabled                                           = $True;
            IsDefault                                            = $True;
            JournalEnabled                                       = $True;
            LocalEventsEnabled                                   = $False;
            LogonAndErrorLanguage                                = 0;
            Name                                                 = "OwaMailboxPolicy-Default";
            NotesEnabled                                         = $True;
            NpsSurveysEnabled                                    = $True;
            OnSendAddinsEnabled                                  = $False;
            OrganizationEnabled                                  = $True;
            OutboundCharset                                      = "AutoDetect";
            OutlookBetaToggleEnabled                             = $True;
            OWALightEnabled                                      = $True;
            PersonalAccountCalendarsEnabled                      = $True;
            PhoneticSupportEnabled                               = $False;
            PlacesEnabled                                        = $True;
            PremiumClientEnabled                                 = $True;
            PrintWithoutDownloadEnabled                          = $True;
            PublicFoldersEnabled                                 = $True;
            RecoverDeletedItemsEnabled                           = $True;
            ReferenceAttachmentsEnabled                          = $True;
            RemindersAndNotificationsEnabled                     = $True;
            ReportJunkEmailEnabled                               = $True;
            RulesEnabled                                         = $True;
            SatisfactionEnabled                                  = $True;
            SaveAttachmentsToCloudEnabled                        = $True;
            SearchFoldersEnabled                                 = $True;
            SetPhotoEnabled                                      = $True;
            SetPhotoURL                                          = "";
            SignaturesEnabled                                    = $True;
            SkipCreateUnifiedGroupCustomSharepointClassification = $True;
            TeamSnapCalendarsEnabled                             = $True;
            TextMessagingEnabled                                 = $True;
            ThemeSelectionEnabled                                = $True;
            UMIntegrationEnabled                                 = $True;
            UseGB18030                                           = $False;
            UseISO885915                                         = $False;
            UserVoiceEnabled                                     = $True;
            WacEditingEnabled                                    = $True;
            WacExternalServicesEnabled                           = $True;
            WacOMEXEnabled                                       = $False;
            WacViewingOnPrivateComputersEnabled                  = $True;
            WacViewingOnPublicComputersEnabled                   = $True;
            WeatherEnabled                                       = $True;
            WebPartsFrameOptionsType                             = "SameOrigin";
        }
        EXORemoteDomain d24e3086-6c67-4dd7-8288-7c78f0b6a6c8
        {
            AllowedOOFType                       = "External";
            AutoForwardEnabled                   = $True;
            AutoReplyEnabled                     = $True;
            ByteEncoderTypeFor7BitCharsets       = "Undefined";
            CharacterSet                         = "iso-8859-1";
            ContentType                          = "MimeHtmlText";
            DeliveryReportEnabled                = $True;
            DisplaySenderName                    = $True;
            DomainName                           = "*";
            Ensure                               = "Present";
            GlobalAdminAccount                   = $Credsglobaladmin;
            Identity                             = "Default";
            IsInternal                           = $False;
            LineWrapSize                         = "Unlimited";
            MeetingForwardNotificationEnabled    = $False;
            Name                                 = "Default";
            NonMimeCharacterSet                  = "iso-8859-1";
            PreferredInternetCodePageForShiftJis = "Undefined";
            TargetDeliveryDomain                 = $False;
            TrustedMailInboundEnabled            = $False;
            TrustedMailOutboundEnabled           = $False;
            UseSimpleDisplayName                 = $False;
        }
        EXORoleAssignmentPolicy 14a7bcdd-5758-4893-9e44-8f2546fff2d1
        {
            Description          = "This policy grants end users the permission to set their options in Outlook on the web and perform other self-administration tasks.";
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            IsDefault            = $True;
            Name                 = "Default Role Assignment Policy";
            Roles                = @("MyTeamMailboxes","My Custom Apps","My Marketplace Apps","My ReadWriteMailbox Apps","MyBaseOptions","MyContactInformation","MyMailSubscriptions","MyProfileInformation","MyRetentionPolicies","MyTextMessaging","MyVoiceMail","MyDistributionGroupMembership","MyDistributionGroups");
        }
        EXOSafeLinksPolicy 1fb6e81e-0b7e-4bb6-9e92-95faa53e94ea
        {
            AdminDisplayName         = "";
            DoNotAllowClickThrough   = $True;
            DoNotRewriteUrls         = @();
            DoNotTrackUserClicks     = $False;
            EnableForInternalSenders = $True;
            Ensure                   = "Present";
            GlobalAdminAccount       = $Credsglobaladmin;
            Identity                 = "GoC-Safe Links";
            IsEnabled                = $True;
            ScanUrls                 = $True;
        }
        EXOSharingPolicy a68b731e-45c3-4468-aa4b-4f1a1ba15e58
        {
            Default              = $True;
            Domains              = @("Anonymous:CalendarSharingFreeBusyReviewer","*:CalendarSharingFreeBusySimple");
            Enabled              = $True;
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Default Sharing Policy";
        }
        O365AdminAuditLogConfig 4058901f-78d0-4714-9e13-633dbf06bf46
        {
            Ensure                          = "Present";
            GlobalAdminAccount              = $Credsglobaladmin;
            IsSingleInstance                = "Yes";
            UnifiedAuditLogIngestionEnabled = "Enabled";
        }
        ODSettings 83b5ca42-bffe-472d-a6e4-171a4798b965
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
        SCFilePlanPropertyAuthority f1c05e2f-ed91-4295-8277-733909e0f7f2
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Business";
        }
        SCFilePlanPropertyAuthority 06be650c-632a-4026-9622-8ee6f774f2f6
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Legal";
        }
        SCFilePlanPropertyAuthority 7fa7359b-1f18-4c94-bb03-324212fca687
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Regulatory";
        }
        SCFilePlanPropertyCategory c8fccf1f-7ff5-4cfa-86a2-dea3e5ba9715
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Accounts payable";
        }
        SCFilePlanPropertyCategory d0e969b7-1f01-41bb-aa9b-64b204a61296
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Accounts receivable";
        }
        SCFilePlanPropertyCategory 2a3aa575-d86e-440a-bcff-9493956fd70a
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Administration";
        }
        SCFilePlanPropertyCategory 8c7597a3-6f43-43dd-9602-091978ade2d5
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Compliance";
        }
        SCFilePlanPropertyCategory db70e77c-1896-48bd-a478-63afa281c4ad
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Contracting";
        }
        SCFilePlanPropertyCategory 54ec7b75-c24e-4fa4-a9cc-03ba8364cd7d
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Financial statements";
        }
        SCFilePlanPropertyCategory 07700afb-b241-4ea4-b7a7-e44f3dc60f5d
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Learning and development";
        }
        SCFilePlanPropertyCategory 7a103139-def8-49eb-8733-a8289983de81
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Planning";
        }
        SCFilePlanPropertyCategory 2dd3dab4-cb5a-418d-bcbb-e85b5ef166f2
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Payroll";
        }
        SCFilePlanPropertyCategory 44107951-1ad0-4d35-9c25-bc56c8ad0e87
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Policies and procedures";
        }
        SCFilePlanPropertyCategory b89595dd-d956-473e-a16b-b2c66e98ef1d
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Procurement";
        }
        SCFilePlanPropertyCategory 4d1b4db9-9cbe-4355-b324-429b7ad45d24
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Recruiting and hiring";
        }
        SCFilePlanPropertyCategory c2c2cecf-0c11-4e1a-973b-430086a42e97
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Research and development";
        }
        SCFilePlanPropertyCitation a7a1c1ea-7bfd-4550-9ed0-0ec4f6285a52
        {
            CitationJurisdiction = "U.S. Futures Commodity Trading Commission (UCFTC)";
            CitationUrl          = "https://www.cftc.gov/LawRegulation/CommodityExchangeAct/index.htm";
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Commodity Exchange Act";
        }
        SCFilePlanPropertyCitation 6e8eb7dc-cb1e-4fe6-9285-bf466ca43b23
        {
            CitationJurisdiction = "U.S. Securities and Exchange Commission (SEC)";
            CitationUrl          = "https://www.sec.gov/answers/about-lawsshtml.html#sox2002";
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Sarbanes-Oxley Act of 2002";
        }
        SCFilePlanPropertyCitation 5e867db6-d0ee-4b0f-96be-468879d65b04
        {
            CitationJurisdiction = "Federal Trade Commission (FTC)";
            CitationUrl          = "https://www.ftc.gov/enforcement/statutes/truth-lending-act";
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Truth in lending Act";
        }
        SCFilePlanPropertyCitation e878d876-8054-4ee0-aec4-2dd5b8d8e960
        {
            CitationJurisdiction = "U.S. Department of Health & Human Services (HHS)";
            CitationUrl          = "https://aspe.hhs.gov/report/health-insurance-portability-and-accountability-act-1996";
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Health Insurance Portability and Accountability Act of 1996";
        }
        SCFilePlanPropertyCitation 87dc8e6f-ff25-4581-bbf7-9ac7e5d0fe04
        {
            CitationJurisdiction = "U.S. Department of Labor (DOL)";
            CitationUrl          = "https://www.osha.gov/recordkeeping/index.html";
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "OSHA Injury and Illness Recordkeeping and Reporting Requirements";
        }
        SCFilePlanPropertyDepartment f3e8afe1-d538-41f2-8d2c-38d8d684c8e2
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Finance";
        }
        SCFilePlanPropertyDepartment 722dc27a-52e9-4095-ba13-da12a2656fac
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Human resources";
        }
        SCFilePlanPropertyDepartment 43c872d7-08ba-4e2b-a218-89a07e90eb27
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Information technology";
        }
        SCFilePlanPropertyDepartment efcb6b76-7d32-4872-8ec7-9da8fe7810c8
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Legal";
        }
        SCFilePlanPropertyDepartment 86a08dca-b393-47cb-b6e4-6b73605536b1
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Marketing";
        }
        SCFilePlanPropertyDepartment 0205fff3-32bc-42aa-814d-4282bf870d9e
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Operations";
        }
        SCFilePlanPropertyDepartment f895e9d0-6c62-4624-a4f3-ef652b21fa0a
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Procurement";
        }
        SCFilePlanPropertyDepartment a639157c-cd1b-44e9-9cf4-940481bbd0e4
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Products";
        }
        SCFilePlanPropertyDepartment 3029d0ff-652c-46cc-9e9d-57b950a5338a
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Sales";
        }
        SCFilePlanPropertyDepartment d9f42f32-82cb-4faf-a16e-6529af7a539a
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Name                 = "Services";
        }
        SCSensitivityLabel d8d7e5cc-b8e2-4c8a-9bec-ff19aaeae038
        {
            AdvancedSettings     = @(
                MSFT_SCLabelSetting
                {
                    Key   = 'tooltip'
                    Value = '`Non sensitive and non-personal information whose disclosure would not reasonably be expected to cause injury. Unclassified publicly available information is disclosed to the public through various means  such as the Internet  publication distribution  and public hearings
This information that does not fall within or merit protection of the classification categories for Protected information. This is Information that is not sensitive  non-personal and not in the national interest.
Examples of Unclassified information: 
•	General announcements
•	Guidelines and Procedures Manuals
•	News Releases
•	Published Research Reports
•	Inventories
•	Company/product literature and general correspondence
•	Policy and general information`'
                }
            );
            Comment              = "`"Non sensitive and non-personal information whose disclosure would not reasonably be expected to cause injury. Unclassified publicly available information is disclosed to the public through various means, such as the Internet, publication distribution, and public hearings
This information that does not fall within or merit protection of the classification categories for Protected information. This is Information that is not sensitive, non-personal and not in the national interest.
Examples of Unclassified information: 
•	General announcements
•	Guidelines and Procedures Manuals
•	News Releases
•	Published Research Reports
•	Inventories
•	Company/product literature and general correspondence
•	Policy and general information`"
";
            Disabled             = $False;
            DisplayName          = "UNCLASSIFIED";
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            LocaleSettings       = @(
                MSFT_SCLabelLocaleSettings
                {
                    LocaleKey = 'displayName'
                    Settings  = @(
                        MSFT_SCLabelSetting
                        {
                            Key   = 'default'
                            Value = 'UNCLASSIFIED'
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
                            Value = '`Non sensitive and non-personal information whose disclosure would not reasonably be expected to cause injury. Unclassified publicly available information is disclosed to the public through various means, such as the Internet, publication distribution, and public hearings
This information that does not fall within or merit protection of the classification categories for Protected information. This is Information that is not sensitive, non-personal and not in the national interest.
Examples of Unclassified information: 
•	General announcements
•	Guidelines and Procedures Manuals
•	News Releases
•	Published Research Reports
•	Inventories
•	Company/product literature and general correspondence
•	Policy and general information`'
                        }
                    )
                }
            );
            Name                 = "UNCLASSIFIED";
            Priority             = 0;
            Tooltip              = "`"Non sensitive and non-personal information whose disclosure would not reasonably be expected to cause injury. Unclassified publicly available information is disclosed to the public through various means, such as the Internet, publication distribution, and public hearings
This information that does not fall within or merit protection of the classification categories for Protected information. This is Information that is not sensitive, non-personal and not in the national interest.
Examples of Unclassified information: 
•	General announcements
•	Guidelines and Procedures Manuals
•	News Releases
•	Published Research Reports
•	Inventories
•	Company/product literature and general correspondence
•	Policy and general information`"";
        }
        SCSensitivityLabel f7580b7e-4241-4ee4-9b3b-31b1cb366317
        {
            AdvancedSettings     = @(
                MSFT_SCLabelSetting
                {
                    Key   = 'tooltip'
                    Value = '`Protected A` applies to information whose compromise could reasonably be expected to limited injury to non-national interests.  Unauthorized disclosure could result in:
•	 A privacy breach

Examples of Protected A information:
•	Date of birth
•	Home address and telephone number
•	Contracts and tenders
•	Exact salary 
•	SIN with no other personal identifiers
•	Letters of offer
•	Personnel Record Identifier (PRI)
•	Individual Learning Plan
•	An individuals linguistic profile 
•	Political affiliation
•	Third party business information provided in confidence (where compromise could result in injury) 
•	Purchase requisitions
•	Contracts

NOTE: Individually  these data elements are Protected A.  However  these data elements constitute Protected B when compiled  such as in an employee or client file.'
                }
            );
            Comment              = "`"Protected A`" applies to information whose compromise could reasonably be expected to limited injury to non-national interests.  Unauthorized disclosure could result in:
•	 A privacy breach

Examples of Protected A information:
•	Date of birth
•	Home address and telephone number
•	Contracts and tenders
•	Exact salary 
•	SIN with no other personal identifiers
•	Letters of offer
•	Personnel Record Identifier (PRI)
•	Individual Learning Plan
•	An individual’s linguistic profile 
•	Political affiliation
•	Third party business information provided in confidence (where compromise could result in injury) 
•	Purchase requisitions
•	Contracts

NOTE: Individually, these data elements are Protected A.  However, these data elements constitute Protected B when compiled, such as in an employee or client file.  ";
            Disabled             = $False;
            DisplayName          = "PROTECTED A";
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            LocaleSettings       = @(
                MSFT_SCLabelLocaleSettings
                {
                    LocaleKey = 'displayName'
                    Settings  = @(
                        MSFT_SCLabelSetting
                        {
                            Key   = 'default'
                            Value = 'PROTECTED A'
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
                            Value = '`Protected A` applies to information whose compromise could reasonably be expected to limited injury to non-national interests.  Unauthorized disclosure could result in:
•	 A privacy breach

Examples of Protected A information:
•	Date of birth
•	Home address and telephone number
•	Contracts and tenders
•	Exact salary 
•	SIN with no other personal identifiers
•	Letters of offer
•	Personnel Record Identifier (PRI)
•	Individual Learning Plan
•	An individuals linguistic profile 
•	Political affiliation
•	Third party business information provided in confidence (where compromise could result in injury) 
•	Purchase requisitions
•	Contracts

NOTE: Individually, these data elements are Protected A.  However, these data elements constitute Protected B when compiled, such as in an employee or client file.'
                        }
                    )
                }
            );
            Name                 = "PROTECTED A";
            Priority             = 1;
            Tooltip              = "`"Protected A`" applies to information whose compromise could reasonably be expected to limited injury to non-national interests.  Unauthorized disclosure could result in:
•	 A privacy breach

Examples of Protected A information:
•	Date of birth
•	Home address and telephone number
•	Contracts and tenders
•	Exact salary 
•	SIN with no other personal identifiers
•	Letters of offer
•	Personnel Record Identifier (PRI)
•	Individual Learning Plan
•	An individual’s linguistic profile 
•	Political affiliation
•	Third party business information provided in confidence (where compromise could result in injury) 
•	Purchase requisitions
•	Contracts

NOTE: Individually, these data elements are Protected A.  However, these data elements constitute Protected B when compiled, such as in an employee or client file.";
        }
        SCSensitivityLabel 4c8fd236-832c-40f5-b1a9-8a8e1211be58
        {
            AdvancedSettings     = @(
                MSFT_SCLabelSetting
                {
                    Key   = 'tooltip'
                    Value = '`Protected B` applies to information whose compromise could result in grave injury such as loss of reputation or competitive advantage.

Examples of Protected B information:
•	Solicitor-client privilege
•	Contract negotiations
•	Treasury Board submissions  unless the contents dictate otherwise
•	Government decision-making documents
•	Performance evaluations and character references
•	Trade secrets
•	Information gathered in the course of an investigation  criminal  medical  psychiatric or psychological records
•	Tax returns (when completed)
•	SIN plus another personal identifier (e.g. name)
•	Auditing techniques and thresholds
•	Internal SSC procedures that are not publicly available
•	Employee performance evaluations
•	Medical  psychiatric or psychological reports
•	Reports compiled and identifiable as part of an investigation into a possible law violation
•	Reports describing an individual''s finances (i.e.  income  assets  liabilities  net worth  bank balances)  financial history or a'
                }
            );
            Comment              = "`"Protected B`" applies to information whose compromise could result in grave injury such as loss of reputation or competitive advantage.

Examples of Protected B information:
•	Solicitor-client privilege
•	Contract negotiations
•	Treasury Board submissions, unless the contents dictate otherwise
•	Government decision-making documents
•	Performance evaluations and character references
•	Trade secrets
•	Information gathered in the course of an investigation, criminal, medical, psychiatric or psychological records
•	Tax returns (when completed)
•	SIN plus another personal identifier (e.g. name)
•	Auditing techniques and thresholds
•	Internal SSC procedures that are not publicly available
•	Employee performance evaluations
•	Medical, psychiatric or psychological reports
•	Reports compiled and identifiable as part of an investigation into a possible law violation
•	Reports describing an individual's finances (i.e., income, assets, liabilities, net worth, bank balances), financial history or a";
            Disabled             = $False;
            DisplayName          = "PROTECTED B";
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            LocaleSettings       = @(
                MSFT_SCLabelLocaleSettings
                {
                    LocaleKey = 'displayName'
                    Settings  = @(
                        MSFT_SCLabelSetting
                        {
                            Key   = 'default'
                            Value = 'PROTECTED B'
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
                            Value = '`Protected B` applies to information whose compromise could result in grave injury such as loss of reputation or competitive advantage.

Examples of Protected B information:
•	Solicitor-client privilege
•	Contract negotiations
•	Treasury Board submissions, unless the contents dictate otherwise
•	Government decision-making documents
•	Performance evaluations and character references
•	Trade secrets
•	Information gathered in the course of an investigation, criminal, medical, psychiatric or psychological records
•	Tax returns (when completed)
•	SIN plus another personal identifier (e.g. name)
•	Auditing techniques and thresholds
•	Internal SSC procedures that are not publicly available
•	Employee performance evaluations
•	Medical, psychiatric or psychological reports
•	Reports compiled and identifiable as part of an investigation into a possible law violation
•	Reports describing an individual''s finances (i.e., income, assets, liabilities, net worth, bank balances), financial history or a'
                        }
                    )
                }
            );
            Name                 = "PROTECTED B";
            Priority             = 2;
            Tooltip              = "`"Protected B`" applies to information whose compromise could result in grave injury such as loss of reputation or competitive advantage.

Examples of Protected B information:
•	Solicitor-client privilege
•	Contract negotiations
•	Treasury Board submissions, unless the contents dictate otherwise
•	Government decision-making documents
•	Performance evaluations and character references
•	Trade secrets
•	Information gathered in the course of an investigation, criminal, medical, psychiatric or psychological records
•	Tax returns (when completed)
•	SIN plus another personal identifier (e.g. name)
•	Auditing techniques and thresholds
•	Internal SSC procedures that are not publicly available
•	Employee performance evaluations
•	Medical, psychiatric or psychological reports
•	Reports compiled and identifiable as part of an investigation into a possible law violation
•	Reports describing an individual's finances (i.e., income, assets, liabilities, net worth, bank balances), financial history or a";
        }
        SPOAccessControlSettings d60a3952-703d-4b83-b297-c4f91b1f0f0e
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
        SPOSharingSettings 0fb82701-f0e3-4ab7-908d-6d1d958a953c
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
        SPOTenantCdnPolicy ea000e0b-b91d-4114-849b-ae89735756a4
        {
            CDNType                              = "Public";
            ExcludeRestrictedSiteClassifications = @();
            GlobalAdminAccount                   = $Credsglobaladmin;
            IncludeFileExtensions                = @();
        }
        SPOTenantSettings 448c2978-606e-4790-b9b9-20b3816d98c3
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
            RequireAcceptingAccountMatchInvitedAccount    = $True;
            SearchResolveExactEmailOrUPN                  = $False;
            SignInAccelerationDomain                      = "";
            UseFindPeopleInPeoplePicker                   = $False;
            UsePersistentCookiesForExplorerView           = $False;
            UserVoiceForFeedbackEnabled                   = $True;
        }
        TeamsCallingPolicy 800bad60-f851-4c54-9244-a1126d66957a
        {
            AllowCallForwardingToPhone = $True;
            AllowCallForwardingToUser  = $True;
            AllowCallGroups            = $True;
            AllowDelegation            = $True;
            AllowPrivateCalling        = $True;
            AllowVoicemail             = "UserOverride";
            AllowWebPSTNCalling        = $True;
            BusyOnBusyEnabledType      = "Disabled";
            Ensure                     = "Present";
            GlobalAdminAccount         = $Credsglobaladmin;
            Identity                   = "Global";
            PreventTollBypass          = $False;
        }
        TeamsCallingPolicy 8976d931-e33d-4054-9997-fb548e765f73
        {
            AllowCallForwardingToPhone = $True;
            AllowCallForwardingToUser  = $True;
            AllowCallGroups            = $True;
            AllowDelegation            = $True;
            AllowPrivateCalling        = $True;
            AllowVoicemail             = "UserOverride";
            AllowWebPSTNCalling        = $True;
            BusyOnBusyEnabledType      = "Disabled";
            Ensure                     = "Present";
            GlobalAdminAccount         = $Credsglobaladmin;
            Identity                   = "Tag:AllowCalling";
            PreventTollBypass          = $False;
        }
        TeamsCallingPolicy f5db43da-3dfc-42c6-8f66-034061fef076
        {
            AllowCallForwardingToPhone = $False;
            AllowCallForwardingToUser  = $False;
            AllowCallGroups            = $False;
            AllowDelegation            = $False;
            AllowPrivateCalling        = $False;
            AllowVoicemail             = "AlwaysDisabled";
            AllowWebPSTNCalling        = $True;
            BusyOnBusyEnabledType      = "Disabled";
            Ensure                     = "Present";
            GlobalAdminAccount         = $Credsglobaladmin;
            Identity                   = "Tag:DisallowCalling";
            PreventTollBypass          = $False;
        }
        TeamsCallingPolicy 1449e0c6-cc68-4131-b8d1-2c6df4a09f60
        {
            AllowCallForwardingToPhone = $True;
            AllowCallForwardingToUser  = $True;
            AllowCallGroups            = $True;
            AllowDelegation            = $True;
            AllowPrivateCalling        = $True;
            AllowVoicemail             = "UserOverride";
            AllowWebPSTNCalling        = $True;
            BusyOnBusyEnabledType      = "Disabled";
            Ensure                     = "Present";
            GlobalAdminAccount         = $Credsglobaladmin;
            Identity                   = "Tag:AllowCallingPreventTollBypass";
            PreventTollBypass          = $True;
        }
        TeamsCallingPolicy fcd32424-a06a-46eb-92c1-f3a9f559ef03
        {
            AllowCallForwardingToPhone = $False;
            AllowCallForwardingToUser  = $True;
            AllowCallGroups            = $True;
            AllowDelegation            = $True;
            AllowPrivateCalling        = $True;
            AllowVoicemail             = "UserOverride";
            AllowWebPSTNCalling        = $True;
            BusyOnBusyEnabledType      = "Disabled";
            Ensure                     = "Present";
            GlobalAdminAccount         = $Credsglobaladmin;
            Identity                   = "Tag:AllowCallingPreventForwardingtoPhone";
            PreventTollBypass          = $False;
        }
        TeamsChannelsPolicy 7c7e47ac-91d9-4081-a59f-fcde510b5daa
        {
            AllowOrgWideTeamCreation    = $True;
            AllowPrivateChannelCreation = $True;
            AllowPrivateTeamDiscovery   = $True;
            Ensure                      = "Present";
            GlobalAdminAccount          = $Credsglobaladmin;
            Identity                    = "Global";
        }
        TeamsChannelsPolicy 687a52c5-83eb-403f-9b2d-4153f763b4ff
        {
            AllowOrgWideTeamCreation    = $True;
            AllowPrivateChannelCreation = $True;
            AllowPrivateTeamDiscovery   = $True;
            Ensure                      = "Present";
            GlobalAdminAccount          = $Credsglobaladmin;
            Identity                    = "Tag:Default";
        }
        TeamsClientConfiguration 9d628189-57f1-4a9c-a934-7b7623e878d3
        {
            AllowBox                         = $False;
            AllowDropBox                     = $False;
            AllowEgnyte                      = $False;
            AllowEmailIntoChannel            = $True;
            AllowGoogleDrive                 = $False;
            AllowGuestUser                   = $True;
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
        TeamsEmergencyCallingPolicy 2cb0334c-d20d-4206-9088-b7a5baf9ee7d
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Global";
        }
        TeamsEmergencyCallRoutingPolicy 606cf674-46ca-44b8-9605-f81bb2bcce44
        {
            AllowEnhancedEmergencyServices = $False;
            Ensure                         = "Present";
            GlobalAdminAccount             = $Credsglobaladmin;
            Identity                       = "Global";
        }
        TeamsGuestCallingConfiguration 5995693f-7998-4e8a-af8c-3503a5b2837f
        {
            AllowPrivateCalling  = $False;
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Global";
        }
        TeamsGuestMeetingConfiguration 11548bb3-d382-439a-83cf-494bb4b9ff24
        {
            AllowIPVideo         = $True;
            AllowMeetNow         = $True;
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Global";
            ScreenSharingMode    = "EntireScreen";
        }
        TeamsGuestMessagingConfiguration 766d04dc-5f04-4b3f-8c92-8f6426512922
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
        TeamsMeetingBroadcastConfiguration a34f316e-c102-48eb-9f38-9de3326ca251
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
        TeamsMeetingBroadcastPolicy 05784eb9-d8ef-443a-963f-35cc51c17d42
        {
            AllowBroadcastScheduling        = $True;
            AllowBroadcastTranscription     = $True;
            BroadcastAttendeeVisibilityMode = "EveryoneInCompany";
            BroadcastRecordingMode          = "UserOverride";
            Ensure                          = "Present";
            GlobalAdminAccount              = $Credsglobaladmin;
            Identity                        = "Global";
        }
        TeamsMeetingBroadcastPolicy 143d0e4b-0b18-4577-b171-a708c3f50588
        {
            AllowBroadcastScheduling        = $True;
            AllowBroadcastTranscription     = $False;
            BroadcastAttendeeVisibilityMode = "EveryoneInCompany";
            BroadcastRecordingMode          = "AlwaysEnabled";
            Ensure                          = "Present";
            GlobalAdminAccount              = $Credsglobaladmin;
            Identity                        = "Tag:Default";
        }
        TeamsMeetingConfiguration a0880f0a-626c-4ee5-b411-28ea22047e2f
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
        TeamsMeetingPolicy c1c10ad8-2e16-4df7-8eab-8f3fae1c0a18
        {
            AllowAnonymousUsersToStartMeeting          = $False;
            AllowChannelMeetingScheduling              = $True;
            AllowCloudRecording                        = $True;
            AllowExternalParticipantGiveRequestControl = $False;
            AllowIPVideo                               = $True;
            AllowMeetNow                               = $True;
            AllowOutlookAddIn                          = $True;
            AllowParticipantGiveRequestControl         = $True;
            AllowPowerPointSharing                     = $True;
            AllowPrivateMeetingScheduling              = $True;
            AllowPSTNUsersToBypassLobby                = $False;
            AllowSharedNotes                           = $True;
            AllowTranscription                         = $False;
            AllowWhiteboard                            = $True;
            AutoAdmittedUsers                          = "EveryoneInCompany";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Global";
            MediaBitRateKb                             = 50000;
            ScreenSharingMode                          = "EntireScreen";
        }
        TeamsMeetingPolicy 00feeb35-4ac2-4eb1-b0dd-1c87306b408c
        {
            AllowAnonymousUsersToStartMeeting          = $False;
            AllowChannelMeetingScheduling              = $True;
            AllowCloudRecording                        = $True;
            AllowExternalParticipantGiveRequestControl = $False;
            AllowIPVideo                               = $True;
            AllowMeetNow                               = $True;
            AllowOutlookAddIn                          = $True;
            AllowParticipantGiveRequestControl         = $True;
            AllowPowerPointSharing                     = $True;
            AllowPrivateMeetingScheduling              = $True;
            AllowPSTNUsersToBypassLobby                = $False;
            AllowSharedNotes                           = $True;
            AllowTranscription                         = $False;
            AllowWhiteboard                            = $True;
            AutoAdmittedUsers                          = "EveryoneInCompany";
            Description                                = "Do not assign. This policy is same as global defaults and would be deprecated";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Tag:AllOn";
            MediaBitRateKb                             = 50000;
            ScreenSharingMode                          = "EntireScreen";
        }
        TeamsMeetingPolicy b65e00e0-3ea7-41f2-9fc2-4cd4f8b499c6
        {
            AllowAnonymousUsersToStartMeeting          = $False;
            AllowChannelMeetingScheduling              = $True;
            AllowCloudRecording                        = $True;
            AllowExternalParticipantGiveRequestControl = $False;
            AllowIPVideo                               = $True;
            AllowMeetNow                               = $True;
            AllowOutlookAddIn                          = $True;
            AllowParticipantGiveRequestControl         = $True;
            AllowPowerPointSharing                     = $True;
            AllowPrivateMeetingScheduling              = $True;
            AllowPSTNUsersToBypassLobby                = $False;
            AllowSharedNotes                           = $True;
            AllowTranscription                         = $False;
            AllowWhiteboard                            = $True;
            AutoAdmittedUsers                          = "EveryoneInCompany";
            Description                                = "Do not assign. This policy is same as global defaults and would be deprecated";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Tag:RestrictedAnonymousAccess";
            MediaBitRateKb                             = 50000;
            ScreenSharingMode                          = "EntireScreen";
        }
        TeamsMeetingPolicy 9ed2e2e6-b704-47e4-b9ce-68de03d1617d
        {
            AllowAnonymousUsersToStartMeeting          = $False;
            AllowChannelMeetingScheduling              = $False;
            AllowCloudRecording                        = $False;
            AllowExternalParticipantGiveRequestControl = $False;
            AllowIPVideo                               = $False;
            AllowMeetNow                               = $False;
            AllowOutlookAddIn                          = $False;
            AllowParticipantGiveRequestControl         = $False;
            AllowPowerPointSharing                     = $False;
            AllowPrivateMeetingScheduling              = $False;
            AllowPSTNUsersToBypassLobby                = $False;
            AllowSharedNotes                           = $False;
            AllowTranscription                         = $False;
            AllowWhiteboard                            = $False;
            AutoAdmittedUsers                          = "EveryoneInCompany";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Tag:AllOff";
            MediaBitRateKb                             = 50000;
            ScreenSharingMode                          = "Disabled";
        }
        TeamsMeetingPolicy 2416b910-2ec1-4d46-9993-3b6cebb324a1
        {
            AllowAnonymousUsersToStartMeeting          = $False;
            AllowChannelMeetingScheduling              = $True;
            AllowCloudRecording                        = $False;
            AllowExternalParticipantGiveRequestControl = $False;
            AllowIPVideo                               = $True;
            AllowMeetNow                               = $True;
            AllowOutlookAddIn                          = $True;
            AllowParticipantGiveRequestControl         = $True;
            AllowPowerPointSharing                     = $True;
            AllowPrivateMeetingScheduling              = $True;
            AllowPSTNUsersToBypassLobby                = $False;
            AllowSharedNotes                           = $True;
            AllowTranscription                         = $False;
            AllowWhiteboard                            = $True;
            AutoAdmittedUsers                          = "EveryoneInCompany";
            Description                                = "Do not assign. This policy is similar to global defaults and would be deprecated";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Tag:RestrictedAnonymousNoRecording";
            MediaBitRateKb                             = 50000;
            ScreenSharingMode                          = "EntireScreen";
        }
        TeamsMeetingPolicy f94ac8c9-5414-4c25-8708-c8cd5c811d63
        {
            AllowAnonymousUsersToStartMeeting          = $False;
            AllowChannelMeetingScheduling              = $True;
            AllowCloudRecording                        = $True;
            AllowExternalParticipantGiveRequestControl = $False;
            AllowIPVideo                               = $True;
            AllowMeetNow                               = $True;
            AllowOutlookAddIn                          = $True;
            AllowParticipantGiveRequestControl         = $True;
            AllowPowerPointSharing                     = $True;
            AllowPrivateMeetingScheduling              = $True;
            AllowPSTNUsersToBypassLobby                = $False;
            AllowSharedNotes                           = $True;
            AllowTranscription                         = $False;
            AllowWhiteboard                            = $True;
            AutoAdmittedUsers                          = "EveryoneInCompany";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Tag:Default";
            MediaBitRateKb                             = 50000;
            ScreenSharingMode                          = "EntireScreen";
        }
        TeamsMeetingPolicy f111bdbb-315f-4b8c-bd27-ef25584b0aaa
        {
            AllowAnonymousUsersToStartMeeting          = $False;
            AllowChannelMeetingScheduling              = $False;
            AllowCloudRecording                        = $False;
            AllowExternalParticipantGiveRequestControl = $False;
            AllowIPVideo                               = $True;
            AllowMeetNow                               = $True;
            AllowOutlookAddIn                          = $False;
            AllowParticipantGiveRequestControl         = $True;
            AllowPowerPointSharing                     = $True;
            AllowPrivateMeetingScheduling              = $False;
            AllowPSTNUsersToBypassLobby                = $False;
            AllowSharedNotes                           = $True;
            AllowTranscription                         = $False;
            AllowWhiteboard                            = $True;
            AutoAdmittedUsers                          = "EveryoneInCompany";
            Ensure                                     = "Present";
            GlobalAdminAccount                         = $Credsglobaladmin;
            Identity                                   = "Tag:Kiosk";
            MediaBitRateKb                             = 50000;
            ScreenSharingMode                          = "EntireScreen";
        }
        TeamsMessagingPolicy bacea758-9ee1-48b6-b750-2d1d2784fb98
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
            AllowUserTranslation          = $True;
            AudioMessageEnabledType       = "ChatsAndChannels";
            ChannelsInChatListEnabledType = "DisabledUserOverride";
            Ensure                        = "Present";
            GiphyRatingType               = "Moderate";
            GlobalAdminAccount            = $Credsglobaladmin;
            Identity                      = "Global";
            ReadReceiptsEnabledType       = "UserPreference";
        }
        TeamsMessagingPolicy daa6e193-1ad6-4b98-a8bb-87685a2a23c3
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
            AllowUserTranslation          = $True;
            AudioMessageEnabledType       = "ChatsAndChannels";
            ChannelsInChatListEnabledType = "DisabledUserOverride";
            Ensure                        = "Present";
            GiphyRatingType               = "Moderate";
            GlobalAdminAccount            = $Credsglobaladmin;
            Identity                      = "Default";
            ReadReceiptsEnabledType       = "UserPreference";
        }
        TeamsMessagingPolicy e6dcbd38-be50-411b-83d3-8896b28e29d8
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
            AllowUserTranslation          = $True;
            AudioMessageEnabledType       = "ChatsAndChannels";
            ChannelsInChatListEnabledType = "DisabledUserOverride";
            Ensure                        = "Present";
            GiphyRatingType               = "Strict";
            GlobalAdminAccount            = $Credsglobaladmin;
            Identity                      = "EduFaculty";
            ReadReceiptsEnabledType       = "UserPreference";
        }
        TeamsMessagingPolicy 57e76e46-579d-4a1a-9c4b-cdd53746e50e
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
            AllowUserTranslation          = $True;
            AudioMessageEnabledType       = "ChatsAndChannels";
            ChannelsInChatListEnabledType = "DisabledUserOverride";
            Ensure                        = "Present";
            GiphyRatingType               = "Strict";
            GlobalAdminAccount            = $Credsglobaladmin;
            Identity                      = "EduStudent";
            ReadReceiptsEnabledType       = "UserPreference";
        }
        TeamsTenantDialPlan b8ab0712-cd1b-4421-8613-b1dcfb41f0b0
        {
            Ensure                = "Present";
            GlobalAdminAccount    = $Credsglobaladmin;
            Identity              = "Global";
            NormalizationRules    = @();
            OptimizeDeviceDialing = $False;
            SimpleName            = "DefaultTenantDialPlan";
        }
        TeamsUpgradeConfiguration 8a280646-855d-4634-a3e3-de374d7da73c
        {
            DownloadTeams        = $True;
            GlobalAdminAccount   = $Credsglobaladmin;
            IsSingleInstance     = "Yes";
            SfBMeetingJoinUx     = "NativeLimitedClient";
        }
        TeamsUpgradePolicy 7c7e6263-97c4-4a55-bdba-38ad82cc822a
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "Global";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy c8d37f47-9463-4edd-95ac-8f53c039f1fd
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "UpgradeToTeams";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy e893ef25-0831-4558-a08b-c0a79da2454e
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "Islands";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy fdea99f0-04f9-489f-9708-79ec16cf0607
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "IslandsWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy deb243ac-18d7-46b0-865d-e9463b8c03df
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBOnly";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 520855e7-15e3-495f-9b9a-dcf7053bff01
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBOnlyWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 4a8b8dd2-f5f8-4ee7-8185-0e9dd78b914f
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollab";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 4797c2b4-d9d1-48e5-a5ca-3dd813934df5
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollabWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 96dc6104-2a98-4011-a06c-54b7414f7913
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollabAndMeetings";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsUpgradePolicy 7aea1739-01ac-48d8-88ea-6187bd190c07
        {
            GlobalAdminAccount     = $Credsglobaladmin;
            Identity               = "SfBWithTeamsCollabAndMeetingsWithNotify";
            MigrateMeetingsToTeams = $False;
            Users                  = @();
        }
        TeamsVoiceRoutingPolicy 1e8e36b9-f6d2-4ecf-b0c1-92fc45a460de
        {
            Ensure               = "Present";
            GlobalAdminAccount   = $Credsglobaladmin;
            Identity             = "Global";
            OnlinePstnUsages     = @();
        }
    }
}
M365TenantConfig -ConfigurationData .\ConfigurationData.psd1 -GlobalAdminAccount $GlobalAdminAccount
