# coding = 'utf-8'

import enum
from method.System.winnt import *
from method.System.winusutypes import *
from method.System.public_dll import ntdll
from method.System.errcheck import ntstatus_to_errcheck

USER_THREAD_START_ROUTINE = WINFUNCTYPE(NTSTATUS, PVOID)
PUSER_THREAD_START_ROUTINE = POINTER(USER_THREAD_START_ROUTINE)

class _PS_ATTRIBUTE(Structure):
    class AnonymousUnion(Union):
        _fields_ = [
            ('Value', ULONG_PTR),
            ('ValuePtr', PVOID)
        ]

    _anonymous_ = ['AnonymousUnion']
    _fields_ = [
        ('Attribute', ULONG_PTR),
        ('Size', SIZE_T),
        ('AnonymousUnion', AnonymousUnion),
        ('ReturnLength', PSIZE_T)
    ]

PS_ATTRIBUTE = _PS_ATTRIBUTE
PPS_ATTRIBUTE = POINTER(PS_ATTRIBUTE)

class _PS_ATTRIBUTE_LIST(Structure):
    _fields_ = [
        ('TotalLength', SIZE_T),
        ('Attributes', PS_ATTRIBUTE * 1)
    ]

PS_ATTRIBUTE_LIST = _PS_ATTRIBUTE_LIST
PPS_ATTRIBUTE_LIST = POINTER(PS_ATTRIBUTE_LIST)

class _INITIAL_TEB(Structure):
    class OldInitialTeb(Structure):
        _fields_ = [
            ('OldStackBase', PVOID),
            ('OldStackLimit', PVOID)
        ]
    
    _anonymous_ = ['OldInitialTeb']
    _fields_ = [
        ('OldInitialTeb', OldInitialTeb),
        ('StackBase', PVOID),
        ('StackLimit', PVOID),
        ('StackAllocationBase', PVOID)
    ]

INITIAL_TEB = _INITIAL_TEB
PINITIAL_TEB = POINTER(INITIAL_TEB)

##########################################################
def NtRaiseHardError(
    ErrorStatus: int, 
    NumberOfParameters: int, 
    UnicodeStringParameterMask: int, 
    Parameters: int, 
    ValidResponseOptions: int, 
    Response: int,
    errcheck: bool = True
) -> NoReturn:        # BSOD function
    
    NtRaiseHardError = ntdll.NtRaiseHardError
    NtRaiseHardError.argtypes = [
        NTSTATUS,
        ULONG,
        ULONG,
        PULONG_PTR,
        ULONG,
        PULONG
    ]

    NtRaiseHardError.restype = NTSTATUS
    res = NtRaiseHardError(
        ErrorStatus, 
        NumberOfParameters, 
        UnicodeStringParameterMask, 
        Parameters, 
        ValidResponseOptions, 
        Response
    )

    return ntstatus_to_errcheck(res, errcheck)
    

def NtCreateThread(
    ThreadHandle, 
    DesiredAccess, 
    ObjectAttributes, 
    ProcessHandle, 
    ClientId, 
    ThreadContext, 
    InitialTeb, 
    CreateSuspended,
    errcheck: bool = True
):
    
    NtCreateThread = ntdll.NtCreateThread
    NtCreateThread.argtypes = [
        PHANDLE,
        ACCESS_MASK,
        PCOBJECT_ATTRIBUTES,
        HANDLE,
        PCLIENT_ID,
        PCONTEXT,
        PINITIAL_TEB,
        BOOLEAN
    ]

    NtCreateThread.restype = NTSTATUS
    res = NtCreateThread(
        ThreadHandle, 
        DesiredAccess, 
        ObjectAttributes, 
        ProcessHandle, 
        ClientId, 
        ThreadContext, 
        InitialTeb, 
        CreateSuspended
    )

    return ntstatus_to_errcheck(res, errcheck)
        

def NtCreateThreadEx(
    ThreadHandle, 
    DesiredAccess, 
    ObjectAttributes, 
    ProcessHandle, 
    StartRoutine, 
    Argument, 
    CreateFlags, 
    ZeroBits, 
    StackSize, 
    MaximumStackSize, 
    AttributeList,
    errcheck: bool = True
):
    
    NtCreateThreadEx = ntdll.NtCreateThreadEx
    NtCreateThreadEx.argtypes = [
        PHANDLE,
        ACCESS_MASK,
        PCOBJECT_ATTRIBUTES,
        HANDLE,
        PUSER_THREAD_START_ROUTINE,
        PVOID,
        ULONG,
        SIZE_T,
        SIZE_T,
        SIZE_T,
        PPS_ATTRIBUTE_LIST
    ]

    NtCreateThreadEx.restype = NTSTATUS
    res = NtCreateThreadEx(
        ThreadHandle, 
        DesiredAccess, 
        ObjectAttributes, 
        ProcessHandle, 
        StartRoutine, 
        Argument, 
        CreateFlags, 
        ZeroBits, 
        StackSize, 
        MaximumStackSize, 
        AttributeList
    )

    return ntstatus_to_errcheck(res, errcheck)


def RtlAdjustPrivilege(
    Privilege: int, 
    Enable: int, 
    CurrentThread: int, 
    OldValue: int,
    errcheck: bool = True
) -> None:
    
    RtlAdjustPrivilege = ntdll.RtlAdjustPrivilege
    RtlAdjustPrivilege.argtypes = [
        ULONG,
        BOOLEAN,
        BOOLEAN,
        PBOOLEAN
    ]

    RtlAdjustPrivilege.restype = NTSTATUS
    res = RtlAdjustPrivilege(
        Privilege, 
        Enable, 
        CurrentThread, 
        OldValue
    )

    return ntstatus_to_errcheck(res, errcheck)


class _SYSTEM_PROCESS_ID_INFORMATION(Structure):
    _fields_ = [
        ('ProcessId', HANDLE),
        ('ImageName', UNICODE_STRING)
    ]

SYSTEM_PROCESS_ID_INFORMATION = _SYSTEM_PROCESS_ID_INFORMATION
PSYSTEM_PROCESS_ID_INFORMATION = POINTER(SYSTEM_PROCESS_ID_INFORMATION)

class _SYSTEM_BASICPROCESS_INFORMATION(Structure):
    _fields_ = [
        ('NextEntryOffset', ULONG),
        ('UniqueProcessId', HANDLE),
        ('InheritedFromUniqueProcessId', HANDLE),
        ('SequenceNumber', ULONG64),
        ('ImageName', UNICODE_STRING)
    ]

SYSTEM_BASICPROCESS_INFORMATION = _SYSTEM_BASICPROCESS_INFORMATION
PSYSTEM_BASICPROCESS_INFORMATION = POINTER(SYSTEM_BASICPROCESS_INFORMATION)

SystemBasicInformation = 0
SystemProcessorInformation = 1
SystemPerformanceInformation = 2
SystemTimeOfDayInformation = 3
SystemPathInformation = 4
SystemProcessInformation = 5
SystemCallCountInformation = 6
SystemDeviceInformation = 7
SystemProcessorPerformanceInformation = 8
SystemFlagsInformation = 9
SystemCallTimeInformation = 10
SystemModuleInformation = 11
SystemLocksInformation = 12
SystemStackTraceInformation = 13
SystemPagedPoolInformation = 14
SystemNonPagedPoolInformation = 15
SystemHandleInformation = 16
SystemObjectInformation = 17
SystemPageFileInformation = 18
SystemVdmInstemulInformation = 19
SystemVdmBopInformation = 20
SystemFileCacheInformation = 21
SystemPoolTagInformation = 22
SystemInterruptInformation = 23
SystemDpcBehaviorInformation = 24
SystemFullMemoryInformation = 25
SystemLoadGdiDriverInformation = 26
SystemUnloadGdiDriverInformation = 27
SystemTimeAdjustmentInformation = 28
SystemSummaryMemoryInformation = 29
SystemMirrorMemoryInformation = 30
SystemPerformanceTraceInformation = 31
SystemObsolete0 = 32
SystemExceptionInformation = 33
SystemCrashDumpStateInformation = 34
SystemKernelDebuggerInformation = 35
SystemContextSwitchInformation = 36
SystemRegistryQuotaInformation = 37
SystemExtendServiceTableInformation = 38
SystemPrioritySeparation = 39
SystemVerifierAddDriverInformation = 40
SystemVerifierRemoveDriverInformation = 41
SystemProcessorIdleInformation = 42
SystemLegacyDriverInformation = 43
SystemCurrentTimeZoneInformation = 44
SystemLookasideInformation = 45
SystemTimeSlipNotification = 46
SystemSessionCreate = 47
SystemSessionDetach = 48
SystemSessionInformation = 49
SystemRangeStartInformation = 50
SystemVerifierInformation = 51
SystemVerifierThunkExtend = 52
SystemSessionProcessInformation = 53
SystemLoadGdiDriverInSystemSpace = 54
SystemNumaProcessorMap = 55
SystemPrefetcherInformation = 56
SystemExtendedProcessInformation = 57
SystemRecommendedSharedDataAlignment = 58
SystemComPlusPackage = 59
SystemNumaAvailableMemory = 60
SystemProcessorPowerInformation = 61
SystemEmulationBasicInformation = 62
SystemEmulationProcessorInformation = 63
SystemExtendedHandleInformation = 64
SystemLostDelayedWriteInformation = 65
SystemBigPoolInformation = 66
SystemSessionPoolTagInformation = 67
SystemSessionMappedViewInformation = 68
SystemHotpatchInformation = 69
SystemObjectSecurityMode = 70
SystemWatchdogTimerHandler = 71
SystemWatchdogTimerInformation = 72
SystemLogicalProcessorInformation = 73
SystemWow64SharedInformationObsolete = 74
SystemRegisterFirmwareTableInformationHandler = 75
SystemFirmwareTableInformation = 76
SystemModuleInformationEx = 77
SystemVerifierTriageInformation = 78
SystemSuperfetchInformation = 79
SystemMemoryListInformation = 80
SystemFileCacheInformationEx = 81
SystemThreadPriorityClientIdInformation = 82
SystemProcessorIdleCycleTimeInformation = 83
SystemVerifierCancellationInformation = 84
SystemProcessorPowerInformationEx = 85
SystemRefTraceInformation = 86
SystemSpecialPoolInformation = 87
SystemProcessIdInformation = 88
SystemErrorPortInformation = 89
SystemBootEnvironmentInformation = 90
SystemHypervisorInformation = 91
SystemVerifierInformationEx = 92
SystemTimeZoneInformation = 93
SystemImageFileExecutionOptionsInformation = 94
SystemCoverageInformation = 95
SystemPrefetchPatchInformation = 96
SystemVerifierFaultsInformation = 97
SystemSystemPartitionInformation = 98
SystemSystemDiskInformation = 99
SystemProcessorPerformanceDistribution = 100
SystemNumaProximityNodeInformation = 101
SystemDynamicTimeZoneInformation = 102
SystemCodeIntegrityInformation = 103
SystemProcessorMicrocodeUpdateInformation = 104
SystemProcessorBrandString = 105
SystemVirtualAddressInformation = 106
SystemLogicalProcessorAndGroupInformation = 107
SystemProcessorCycleTimeInformation = 108
SystemStoreInformation = 109
SystemRegistryAppendString =110 
SystemAitSamplingValue = 111
SystemVhdBootInformation = 112
SystemCpuQuotaInformation = 113
SystemNativeBasicInformation = 114
SystemErrorPortTimeouts = 115
SystemLowPriorityIoInformation = 116
SystemTpmBootEntropyInformation = 117
SystemVerifierCountersInformation = 118
SystemPagedPoolInformationEx = 119
SystemSystemPtesInformationEx = 120
SystemNodeDistanceInformation = 121
SystemAcpiAuditInformation = 122
SystemBasicPerformanceInformation = 123
SystemQueryPerformanceCounterInformation = 124
SystemSessionBigPoolInformation = 125
SystemBootGraphicsInformation = 126
SystemScrubPhysicalMemoryInformation = 127
SystemBadPageInformation = 128
SystemProcessorProfileControlArea = 129
SystemCombinePhysicalMemoryInformation = 130
SystemEntropyInterruptTimingInformation = 131
SystemConsoleInformation = 132
SystemPlatformBinaryInformation = 133
SystemPolicyInformation = 134
SystemHypervisorProcessorCountInformation = 135
SystemDeviceDataInformation = 136
SystemDeviceDataEnumerationInformation = 137
SystemMemoryTopologyInformation = 138
SystemMemoryChannelInformation = 139
SystemBootLogoInformation = 140
SystemProcessorPerformanceInformationEx = 141
SystemCriticalProcessErrorLogInformation = 142
SystemSecureBootPolicyInformation = 143
SystemPageFileInformationEx = 144
SystemSecureBootInformation = 145
SystemEntropyInterruptTimingRawInformation = 146
SystemPortableWorkspaceEfiLauncherInformation = 147
SystemFullProcessInformation = 148
SystemKernelDebuggerInformationEx = 149
SystemBootMetadataInformation = 150
SystemSoftRebootInformation = 151
SystemElamCertificateInformation = 152
SystemOfflineDumpConfigInformation = 153
SystemProcessorFeaturesInformation = 154
SystemRegistryReconciliationInformation = 155
SystemEdidInformation = 156
SystemManufacturingInformation = 157
SystemEnergyEstimationConfigInformation = 158
SystemHypervisorDetailInformation = 159
SystemProcessorCycleStatsInformation = 160
SystemVmGenerationCountInformation = 161
SystemTrustedPlatformModuleInformation = 162
SystemKernelDebuggerFlags = 163
SystemCodeIntegrityPolicyInformation = 164
SystemIsolatedUserModeInformation = 165
SystemHardwareSecurityTestInterfaceResultsInformation = 166
SystemSingleModuleInformation = 167
SystemAllowedCpuSetsInformation = 168
SystemVsmProtectionInformation = 169
SystemInterruptCpuSetsInformation = 170
SystemSecureBootPolicyFullInformation = 171
SystemCodeIntegrityPolicyFullInformation = 172
SystemAffinitizedInterruptProcessorInformation = 173
SystemRootSiloInformation = 174
SystemCpuSetInformation = 175
SystemCpuSetTagInformation = 176
SystemWin32WerStartCallout = 177
SystemSecureKernelProfileInformation = 178
SystemCodeIntegrityPlatformManifestInformation = 179
SystemInterruptSteeringInformation = 180
SystemSupportedProcessorArchitectures = 181
SystemMemoryUsageInformation = 182
SystemCodeIntegrityCertificateInformation = 183
SystemPhysicalMemoryInformation = 184
SystemControlFlowTransition = 185
SystemKernelDebuggingAllowed = 186
SystemActivityModerationExeState = 187
SystemActivityModerationUserSettings = 188
SystemCodeIntegrityPoliciesFullInformation = 189
SystemCodeIntegrityUnlockInformation = 190
SystemIntegrityQuotaInformation = 191
SystemFlushInformation = 192
SystemProcessorIdleMaskInformation = 193
SystemSecureDumpEncryptionInformation = 194
SystemWriteConstraintInformation = 195
SystemKernelVaShadowInformation = 196
SystemHypervisorSharedPageInformation = 197
SystemFirmwareBootPerformanceInformation = 198
SystemCodeIntegrityVerificationInformation = 199
SystemFirmwarePartitionInformation = 200
SystemSpeculationControlInformation = 201
SystemDmaGuardPolicyInformation = 202
SystemEnclaveLaunchControlInformation = 203
SystemWorkloadAllowedCpuSetsInformation = 204
SystemCodeIntegrityUnlockModeInformation = 205
SystemLeapSecondInformation = 206
SystemFlags2Information = 207
SystemSecurityModelInformation = 208
SystemCodeIntegritySyntheticCacheInformation = 209
SystemFeatureConfigurationInformation = 210
SystemFeatureConfigurationSectionInformation = 211
SystemFeatureUsageSubscriptionInformation = 212
SystemSecureSpeculationControlInformation = 213
SystemSpacesBootInformation = 214
SystemFwRamdiskInformation = 215
SystemWheaIpmiHardwareInformation = 216
SystemDifSetRuleClassInformation = 217
SystemDifClearRuleClassInformation = 218
SystemDifApplyPluginVerificationOnDriver = 219
SystemDifRemovePluginVerificationOnDriver = 220
SystemShadowStackInformation = 221
SystemBuildVersionInformation = 222
SystemPoolLimitInformation = 223
SystemCodeIntegrityAddDynamicStore = 224
SystemCodeIntegrityClearDynamicStores = 225
SystemDifPoolTrackingInformation = 226
SystemPoolZeroingInformation = 227
SystemDpcWatchdogInformation = 228
SystemDpcWatchdogInformation2 = 229
SystemSupportedProcessorArchitectures2 = 230
SystemSingleProcessorRelationshipInformation = 231
SystemXfgCheckFailureInformation = 232
SystemIommuStateInformation = 233
SystemHypervisorMinrootInformation = 234
SystemHypervisorBootPagesInformation = 235
SystemPointerAuthInformation = 236
SystemSecureKernelDebuggerInformation = 237
SystemOriginalImageFeatureInformation = 238
SystemMemoryNumaInformation = 239
SystemMemoryNumaPerformanceInformation = 240
SystemCodeIntegritySignedPoliciesFullInformation = 241
SystemSecureCoreInformation = 242
SystemTrustedAppsRuntimeInformation = 243
SystemBadPageInformationEx = 244
SystemResourceDeadlockTimeout = 245
SystemBreakOnContextUnwindFailureInformation = 246
SystemOslRamdiskInformation = 247
SystemCodeIntegrityPolicyManagementInformation = 248
SystemMemoryNumaCacheInformation = 249
SystemProcessorFeaturesBitMapInformation = 250
SystemRefTraceInformationEx = 251
SystemBasicProcessInformation = 252
SystemHandleCountInformation = 253
SystemRuntimeAttestationReport = 254
SystemPoolTagInformation2 = 255
MaxSystemInfoClass = 256

class _SYSTEM_INFORMATION_CLASS(enum.Enum):
    SystemBasicInformation = 0
    SystemProcessorInformation = 1
    SystemPerformanceInformation = 2
    SystemTimeOfDayInformation = 3
    SystemPathInformation = 4
    SystemProcessInformation = 5
    SystemCallCountInformation = 6
    SystemDeviceInformation = 7
    SystemProcessorPerformanceInformation = 8
    SystemFlagsInformation = 9
    SystemCallTimeInformation = 10
    SystemModuleInformation = 11
    SystemLocksInformation = 12
    SystemStackTraceInformation = 13
    SystemPagedPoolInformation = 14
    SystemNonPagedPoolInformation = 15
    SystemHandleInformation = 16
    SystemObjectInformation = 17
    SystemPageFileInformation = 18
    SystemVdmInstemulInformation = 19
    SystemVdmBopInformation = 20
    SystemFileCacheInformation = 21
    SystemPoolTagInformation = 22
    SystemInterruptInformation = 23
    SystemDpcBehaviorInformation = 24
    SystemFullMemoryInformation = 25
    SystemLoadGdiDriverInformation = 26
    SystemUnloadGdiDriverInformation = 27
    SystemTimeAdjustmentInformation = 28
    SystemSummaryMemoryInformation = 29
    SystemMirrorMemoryInformation = 30
    SystemPerformanceTraceInformation = 31
    SystemObsolete0 = 32
    SystemExceptionInformation = 33
    SystemCrashDumpStateInformation = 34
    SystemKernelDebuggerInformation = 35
    SystemContextSwitchInformation = 36
    SystemRegistryQuotaInformation = 37
    SystemExtendServiceTableInformation = 38
    SystemPrioritySeparation = 39
    SystemVerifierAddDriverInformation = 40
    SystemVerifierRemoveDriverInformation = 41
    SystemProcessorIdleInformation = 42
    SystemLegacyDriverInformation = 43
    SystemCurrentTimeZoneInformation = 44
    SystemLookasideInformation = 45
    SystemTimeSlipNotification = 46
    SystemSessionCreate = 47
    SystemSessionDetach = 48
    SystemSessionInformation = 49
    SystemRangeStartInformation = 50
    SystemVerifierInformation = 51
    SystemVerifierThunkExtend = 52
    SystemSessionProcessInformation = 53
    SystemLoadGdiDriverInSystemSpace = 54
    SystemNumaProcessorMap = 55
    SystemPrefetcherInformation = 56
    SystemExtendedProcessInformation = 57
    SystemRecommendedSharedDataAlignment = 58
    SystemComPlusPackage = 59
    SystemNumaAvailableMemory = 60
    SystemProcessorPowerInformation = 61
    SystemEmulationBasicInformation = 62
    SystemEmulationProcessorInformation = 63
    SystemExtendedHandleInformation = 64
    SystemLostDelayedWriteInformation = 65
    SystemBigPoolInformation = 66
    SystemSessionPoolTagInformation = 67
    SystemSessionMappedViewInformation = 68
    SystemHotpatchInformation = 69
    SystemObjectSecurityMode = 70
    SystemWatchdogTimerHandler = 71
    SystemWatchdogTimerInformation = 72
    SystemLogicalProcessorInformation = 73
    SystemWow64SharedInformationObsolete = 74
    SystemRegisterFirmwareTableInformationHandler = 75
    SystemFirmwareTableInformation = 76
    SystemModuleInformationEx = 77
    SystemVerifierTriageInformation = 78
    SystemSuperfetchInformation = 79
    SystemMemoryListInformation = 80
    SystemFileCacheInformationEx = 81
    SystemThreadPriorityClientIdInformation = 82
    SystemProcessorIdleCycleTimeInformation = 83
    SystemVerifierCancellationInformation = 84
    SystemProcessorPowerInformationEx = 85
    SystemRefTraceInformation = 86
    SystemSpecialPoolInformation = 87
    SystemProcessIdInformation = 88
    SystemErrorPortInformation = 89
    SystemBootEnvironmentInformation = 90
    SystemHypervisorInformation = 91
    SystemVerifierInformationEx = 92
    SystemTimeZoneInformation = 93
    SystemImageFileExecutionOptionsInformation = 94
    SystemCoverageInformation = 95
    SystemPrefetchPatchInformation = 96
    SystemVerifierFaultsInformation = 97
    SystemSystemPartitionInformation = 98
    SystemSystemDiskInformation = 99
    SystemProcessorPerformanceDistribution = 100
    SystemNumaProximityNodeInformation = 101
    SystemDynamicTimeZoneInformation = 102
    SystemCodeIntegrityInformation = 103
    SystemProcessorMicrocodeUpdateInformation = 104
    SystemProcessorBrandString = 105
    SystemVirtualAddressInformation = 106
    SystemLogicalProcessorAndGroupInformation = 107
    SystemProcessorCycleTimeInformation = 108
    SystemStoreInformation = 109
    SystemRegistryAppendString =110 
    SystemAitSamplingValue = 111
    SystemVhdBootInformation = 112
    SystemCpuQuotaInformation = 113
    SystemNativeBasicInformation = 114
    SystemErrorPortTimeouts = 115
    SystemLowPriorityIoInformation = 116
    SystemTpmBootEntropyInformation = 117
    SystemVerifierCountersInformation = 118
    SystemPagedPoolInformationEx = 119
    SystemSystemPtesInformationEx = 120
    SystemNodeDistanceInformation = 121
    SystemAcpiAuditInformation = 122
    SystemBasicPerformanceInformation = 123
    SystemQueryPerformanceCounterInformation = 124
    SystemSessionBigPoolInformation = 125
    SystemBootGraphicsInformation = 126
    SystemScrubPhysicalMemoryInformation = 127
    SystemBadPageInformation = 128
    SystemProcessorProfileControlArea = 129
    SystemCombinePhysicalMemoryInformation = 130
    SystemEntropyInterruptTimingInformation = 131
    SystemConsoleInformation = 132
    SystemPlatformBinaryInformation = 133
    SystemPolicyInformation = 134
    SystemHypervisorProcessorCountInformation = 135
    SystemDeviceDataInformation = 136
    SystemDeviceDataEnumerationInformation = 137
    SystemMemoryTopologyInformation = 138
    SystemMemoryChannelInformation = 139
    SystemBootLogoInformation = 140
    SystemProcessorPerformanceInformationEx = 141
    SystemCriticalProcessErrorLogInformation = 142
    SystemSecureBootPolicyInformation = 143
    SystemPageFileInformationEx = 144
    SystemSecureBootInformation = 145
    SystemEntropyInterruptTimingRawInformation = 146
    SystemPortableWorkspaceEfiLauncherInformation = 147
    SystemFullProcessInformation = 148
    SystemKernelDebuggerInformationEx = 149
    SystemBootMetadataInformation = 150
    SystemSoftRebootInformation = 151
    SystemElamCertificateInformation = 152
    SystemOfflineDumpConfigInformation = 153
    SystemProcessorFeaturesInformation = 154
    SystemRegistryReconciliationInformation = 155
    SystemEdidInformation = 156
    SystemManufacturingInformation = 157
    SystemEnergyEstimationConfigInformation = 158
    SystemHypervisorDetailInformation = 159
    SystemProcessorCycleStatsInformation = 160
    SystemVmGenerationCountInformation = 161
    SystemTrustedPlatformModuleInformation = 162
    SystemKernelDebuggerFlags = 163
    SystemCodeIntegrityPolicyInformation = 164
    SystemIsolatedUserModeInformation = 165
    SystemHardwareSecurityTestInterfaceResultsInformation = 166
    SystemSingleModuleInformation = 167
    SystemAllowedCpuSetsInformation = 168
    SystemVsmProtectionInformation = 169
    SystemInterruptCpuSetsInformation = 170
    SystemSecureBootPolicyFullInformation = 171
    SystemCodeIntegrityPolicyFullInformation = 172
    SystemAffinitizedInterruptProcessorInformation = 173
    SystemRootSiloInformation = 174
    SystemCpuSetInformation = 175
    SystemCpuSetTagInformation = 176
    SystemWin32WerStartCallout = 177
    SystemSecureKernelProfileInformation = 178
    SystemCodeIntegrityPlatformManifestInformation = 179
    SystemInterruptSteeringInformation = 180
    SystemSupportedProcessorArchitectures = 181
    SystemMemoryUsageInformation = 182
    SystemCodeIntegrityCertificateInformation = 183
    SystemPhysicalMemoryInformation = 184
    SystemControlFlowTransition = 185
    SystemKernelDebuggingAllowed = 186
    SystemActivityModerationExeState = 187
    SystemActivityModerationUserSettings = 188
    SystemCodeIntegrityPoliciesFullInformation = 189
    SystemCodeIntegrityUnlockInformation = 190
    SystemIntegrityQuotaInformation = 191
    SystemFlushInformation = 192
    SystemProcessorIdleMaskInformation = 193
    SystemSecureDumpEncryptionInformation = 194
    SystemWriteConstraintInformation = 195
    SystemKernelVaShadowInformation = 196
    SystemHypervisorSharedPageInformation = 197
    SystemFirmwareBootPerformanceInformation = 198
    SystemCodeIntegrityVerificationInformation = 199
    SystemFirmwarePartitionInformation = 200
    SystemSpeculationControlInformation = 201
    SystemDmaGuardPolicyInformation = 202
    SystemEnclaveLaunchControlInformation = 203
    SystemWorkloadAllowedCpuSetsInformation = 204
    SystemCodeIntegrityUnlockModeInformation = 205
    SystemLeapSecondInformation = 206
    SystemFlags2Information = 207
    SystemSecurityModelInformation = 208
    SystemCodeIntegritySyntheticCacheInformation = 209
    SystemFeatureConfigurationInformation = 210
    SystemFeatureConfigurationSectionInformation = 211
    SystemFeatureUsageSubscriptionInformation = 212
    SystemSecureSpeculationControlInformation = 213
    SystemSpacesBootInformation = 214
    SystemFwRamdiskInformation = 215
    SystemWheaIpmiHardwareInformation = 216
    SystemDifSetRuleClassInformation = 217
    SystemDifClearRuleClassInformation = 218
    SystemDifApplyPluginVerificationOnDriver = 219
    SystemDifRemovePluginVerificationOnDriver = 220
    SystemShadowStackInformation = 221
    SystemBuildVersionInformation = 222
    SystemPoolLimitInformation = 223
    SystemCodeIntegrityAddDynamicStore = 224
    SystemCodeIntegrityClearDynamicStores = 225
    SystemDifPoolTrackingInformation = 226
    SystemPoolZeroingInformation = 227
    SystemDpcWatchdogInformation = 228
    SystemDpcWatchdogInformation2 = 229
    SystemSupportedProcessorArchitectures2 = 230
    SystemSingleProcessorRelationshipInformation = 231
    SystemXfgCheckFailureInformation = 232
    SystemIommuStateInformation = 233
    SystemHypervisorMinrootInformation = 234
    SystemHypervisorBootPagesInformation = 235
    SystemPointerAuthInformation = 236
    SystemSecureKernelDebuggerInformation = 237
    SystemOriginalImageFeatureInformation = 238
    SystemMemoryNumaInformation = 239
    SystemMemoryNumaPerformanceInformation = 240
    SystemCodeIntegritySignedPoliciesFullInformation = 241
    SystemSecureCoreInformation = 242
    SystemTrustedAppsRuntimeInformation = 243
    SystemBadPageInformationEx = 244
    SystemResourceDeadlockTimeout = 245
    SystemBreakOnContextUnwindFailureInformation = 246
    SystemOslRamdiskInformation = 247
    SystemCodeIntegrityPolicyManagementInformation = 248
    SystemMemoryNumaCacheInformation = 249
    SystemProcessorFeaturesBitMapInformation = 250
    SystemRefTraceInformationEx = 251
    SystemBasicProcessInformation = 252
    SystemHandleCountInformation = 253
    SystemRuntimeAttestationReport = 254
    SystemPoolTagInformation2 = 255
    MaxSystemInfoClass = 256

SYSTEM_INFORMATION_CLASS = _SYSTEM_INFORMATION_CLASS


def NtQuerySystemInformation(
    SystemInformationClass: int,
    SystemInformation,
    SystemInformationLength: int,
    ReturnLength,
    errcheck: bool = True
):
    
    NtQuerySystemInformation = ntdll.NtQuerySystemInformation
    NtQuerySystemInformation.argtypes = [UINT, PVOID, ULONG, PULONG]
    NtQuerySystemInformation.restype = NTSTATUS
    res = NtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    )

    return ntstatus_to_errcheck(res, errcheck)

