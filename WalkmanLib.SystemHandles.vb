' Get all system open handles method - uses NTQuerySystemInformation and NTQueryObject
'https://gist.github.com/i-e-b/2290426
'https://stackoverflow.com/a/13735033/2999220
'https://stackoverflow.com/a/6351168/2999220

Imports System
Imports System.Collections.Concurrent
Imports System.Collections.Generic
Imports System.ComponentModel
Imports System.Diagnostics
Imports System.IO
Imports System.Runtime.ConstrainedExecution
Imports System.Runtime.InteropServices
Imports System.Text
Imports System.Threading

Namespace WalkmanLib
    Class SystemHandles
        #Region "Native Methods"

        #Region "Enums"

        'https://pinvoke.net/default.aspx/Enums.NtStatus
        'https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
        Protected Enum NTSTATUS As UInteger
            STATUS_SUCCESS =              &H0
            STATUS_BUFFER_OVERFLOW =      &H80000005UI
            STATUS_INFO_LENGTH_MISMATCH = &HC0000004UI
        End Enum

        'https://www.pinvoke.net/default.aspx/ntdll/SYSTEM_INFORMATION_CLASS.html
        Protected Enum SYSTEM_INFORMATION_CLASS
            SystemBasicInformation =                                &H0
            SystemProcessorInformation =                            &H1
            SystemPerformanceInformation =                          &H2
            SystemTimeOfDayInformation =                            &H3
            SystemPathInformation =                                 &H4
            SystemProcessInformation =                              &H5
            SystemCallCountInformation =                            &H6
            SystemDeviceInformation =                               &H7
            SystemProcessorPerformanceInformation =                 &H8
            SystemFlagsInformation =                                &H9
            SystemCallTimeInformation =                             &HA
            SystemModuleInformation =                               &HB
            SystemLocksInformation =                                &HC
            SystemStackTraceInformation =                           &HD
            SystemPagedPoolInformation =                            &HE
            SystemNonPagedPoolInformation =                         &HF
            SystemHandleInformation =                               &H10
            SystemObjectInformation =                               &H11
            SystemPageFileInformation =                             &H12
            SystemVdmInstemulInformation =                          &H13
            SystemVdmBopInformation =                               &H14
            SystemFileCacheInformation =                            &H15
            SystemPoolTagInformation =                              &H16
            SystemInterruptInformation =                            &H17
            SystemDpcBehaviorInformation =                          &H18
            SystemFullMemoryInformation =                           &H19
            SystemLoadGdiDriverInformation =                        &H1A
            SystemUnloadGdiDriverInformation =                      &H1B
            SystemTimeAdjustmentInformation =                       &H1C
            SystemSummaryMemoryInformation =                        &H1D
            SystemMirrorMemoryInformation =                         &H1E
            SystemPerformanceTraceInformation =                     &H1F
            SystemObsolete0 =                                       &H20
            SystemExceptionInformation =                            &H21
            SystemCrashDumpStateInformation =                       &H22
            SystemKernelDebuggerInformation =                       &H23
            SystemContextSwitchInformation =                        &H24
            SystemRegistryQuotaInformation =                        &H25
            SystemExtendServiceTableInformation =                   &H26
            SystemPrioritySeperation =                              &H27
            SystemVerifierAddDriverInformation =                    &H28
            SystemVerifierRemoveDriverInformation =                 &H29
            SystemProcessorIdleInformation =                        &H2A
            SystemLegacyDriverInformation =                         &H2B
            SystemCurrentTimeZoneInformation =                      &H2C
            SystemLookasideInformation =                            &H2D
            SystemTimeSlipNotification =                            &H2E
            SystemSessionCreate =                                   &H2F
            SystemSessionDetach =                                   &H30
            SystemSessionInformation =                              &H31
            SystemRangeStartInformation =                           &H32
            SystemVerifierInformation =                             &H33
            SystemVerifierThunkExtend =                             &H34
            SystemSessionProcessInformation =                       &H35
            SystemLoadGdiDriverInSystemSpace =                      &H36
            SystemNumaProcessorMap =                                &H37
            SystemPrefetcherInformation =                           &H38
            SystemExtendedProcessInformation =                      &H39
            SystemRecommendedSharedDataAlignment =                  &H3A
            SystemComPlusPackage =                                  &H3B
            SystemNumaAvailableMemory =                             &H3C
            SystemProcessorPowerInformation =                       &H3D
            SystemEmulationBasicInformation =                       &H3E
            SystemEmulationProcessorInformation =                   &H3F
            SystemExtendedHandleInformation =                       &H40
            SystemLostDelayedWriteInformation =                     &H41
            SystemBigPoolInformation =                              &H42
            SystemSessionPoolTagInformation =                       &H43
            SystemSessionMappedViewInformation =                    &H44
            SystemHotpatchInformation =                             &H45
            SystemObjectSecurityMode =                              &H46
            SystemWatchdogTimerHandler =                            &H47
            SystemWatchdogTimerInformation =                        &H48
            SystemLogicalProcessorInformation =                     &H49
            SystemWow64SharedInformationObsolete =                  &H4A
            SystemRegisterFirmwareTableInformationHandler =         &H4B
            SystemFirmwareTableInformation =                        &H4C
            SystemModuleInformationEx =                             &H4D
            SystemVerifierTriageInformation =                       &H4E
            SystemSuperfetchInformation =                           &H4F
            SystemMemoryListInformation =                           &H50
            SystemFileCacheInformationEx =                          &H51
            SystemThreadPriorityClientIdInformation =               &H52
            SystemProcessorIdleCycleTimeInformation =               &H53
            SystemVerifierCancellationInformation =                 &H54
            SystemProcessorPowerInformationEx =                     &H55
            SystemRefTraceInformation =                             &H56
            SystemSpecialPoolInformation =                          &H57
            SystemProcessIdInformation =                            &H58
            SystemErrorPortInformation =                            &H59
            SystemBootEnvironmentInformation =                      &H5A
            SystemHypervisorInformation =                           &H5B
            SystemVerifierInformationEx =                           &H5C
            SystemTimeZoneInformation =                             &H5D
            SystemImageFileExecutionOptionsInformation =            &H5E
            SystemCoverageInformation =                             &H5F
            SystemPrefetchPatchInformation =                        &H60
            SystemVerifierFaultsInformation =                       &H61
            SystemSystemPartitionInformation =                      &H62
            SystemSystemDiskInformation =                           &H63
            SystemProcessorPerformanceDistribution =                &H64
            SystemNumaProximityNodeInformation =                    &H65
            SystemDynamicTimeZoneInformation =                      &H66
            SystemCodeIntegrityInformation =                        &H67
            SystemProcessorMicrocodeUpdateInformation =             &H68
            SystemProcessorBrandString =                            &H69
            SystemVirtualAddressInformation =                       &H6A
            SystemLogicalProcessorAndGroupInformation =             &H6B
            SystemProcessorCycleTimeInformation =                   &H6C
            SystemStoreInformation =                                &H6D
            SystemRegistryAppendString =                            &H6E
            SystemAitSamplingValue =                                &H6F
            SystemVhdBootInformation =                              &H70
            SystemCpuQuotaInformation =                             &H71
            SystemNativeBasicInformation =                          &H72
            SystemErrorPortTimeouts =                               &H73
            SystemLowPriorityIoInformation =                        &H74
            SystemBootEntropyInformation =                          &H75
            SystemVerifierCountersInformation =                     &H76
            SystemPagedPoolInformationEx =                          &H77
            SystemSystemPtesInformationEx =                         &H78
            SystemNodeDistanceInformation =                         &H79
            SystemAcpiAuditInformation =                            &H7A
            SystemBasicPerformanceInformation =                     &H7B
            SystemQueryPerformanceCounterInformation =              &H7C
            SystemSessionBigPoolInformation =                       &H7D
            SystemBootGraphicsInformation =                         &H7E
            SystemScrubPhysicalMemoryInformation =                  &H7F
            SystemBadPageInformation =                              &H80
            SystemProcessorProfileControlArea =                     &H81
            SystemCombinePhysicalMemoryInformation =                &H82
            SystemEntropyInterruptTimingInformation =               &H83
            SystemConsoleInformation =                              &H84
            SystemPlatformBinaryInformation =                       &H85
            SystemPolicyInformation =                               &H86
            SystemHypervisorProcessorCountInformation =             &H87
            SystemDeviceDataInformation =                           &H88
            SystemDeviceDataEnumerationInformation =                &H89
            SystemMemoryTopologyInformation =                       &H8A
            SystemMemoryChannelInformation =                        &H8B
            SystemBootLogoInformation =                             &H8C
            SystemProcessorPerformanceInformationEx =               &H8D
            SystemCriticalProcessErrorLogInformation =              &H8E
            SystemSecureBootPolicyInformation =                     &H8F
            SystemPageFileInformationEx =                           &H90
            SystemSecureBootInformation =                           &H91
            SystemEntropyInterruptTimingRawInformation =            &H92
            SystemPortableWorkspaceEfiLauncherInformation =         &H93
            SystemFullProcessInformation =                          &H94
            SystemKernelDebuggerInformationEx =                     &H95
            SystemBootMetadataInformation =                         &H96
            SystemSoftRebootInformation =                           &H97
            SystemElamCertificateInformation =                      &H98
            SystemOfflineDumpConfigInformation =                    &H99
            SystemProcessorFeaturesInformation =                    &H9A
            SystemRegistryReconciliationInformation =               &H9B
            SystemEdidInformation =                                 &H9C
            SystemManufacturingInformation =                        &H9D
            SystemEnergyEstimationConfigInformation =               &H9E
            SystemHypervisorDetailInformation =                     &H9F
            SystemProcessorCycleStatsInformation =                  &HA0
            SystemVmGenerationCountInformation =                    &HA1
            SystemTrustedPlatformModuleInformation =                &HA2
            SystemKernelDebuggerFlags =                             &HA3
            SystemCodeIntegrityPolicyInformation =                  &HA4
            SystemIsolatedUserModeInformation =                     &HA5
            SystemHardwareSecurityTestInterfaceResultsInformation = &HA6
            SystemSingleModuleInformation =                         &HA7
            SystemAllowedCpuSetsInformation =                       &HA8
            SystemDmaProtectionInformation =                        &HA9
            SystemInterruptCpuSetsInformation =                     &HAA
            SystemSecureBootPolicyFullInformation =                 &HAB
            SystemCodeIntegrityPolicyFullInformation =              &HAC
            SystemAffinitizedInterruptProcessorInformation =        &HAD
            SystemRootSiloInformation =                             &HAE
            SystemCpuSetInformation =                               &HAF
            SystemCpuSetTagInformation =                            &HB0
            SystemWin32WerStartCallout =                            &HB1
            SystemSecureKernelProfileInformation =                  &HB2
            SystemCodeIntegrityPlatformManifestInformation =        &HB3
            SystemInterruptSteeringInformation =                    &HB4
            SystemSuppportedProcessorArchitectures =                &HB5
            SystemMemoryUsageInformation =                          &HB6
            SystemCodeIntegrityCertificateInformation =             &HB7
            SystemPhysicalMemoryInformation =                       &HB8
            SystemControlFlowTransition =                           &HB9
            SystemKernelDebuggingAllowed =                          &HBA
            SystemActivityModerationExeState =                      &HBB
            SystemActivityModerationUserSettings =                  &HBC
            SystemCodeIntegrityPoliciesFullInformation =            &HBD
            SystemCodeIntegrityUnlockInformation =                  &HBE
            SystemIntegrityQuotaInformation =                       &HBF
            SystemFlushInformation =                                &HC0
            SystemProcessorIdleMaskInformation =                    &HC1
            SystemSecureDumpEncryptionInformation =                 &HC2
            SystemWriteConstraintInformation =                      &HC3
            SystemKernelVaShadowInformation =                       &HC4
            SystemHypervisorSharedPageInformation =                 &HC5
            SystemFirmwareBootPerformanceInformation =              &HC6
            SystemCodeIntegrityVerificationInformation =            &HC7
            SystemFirmwarePartitionInformation =                    &HC8
            SystemSpeculationControlInformation =                   &HC9
            SystemDmaGuardPolicyInformation =                       &HCA
            SystemEnclaveLaunchControlInformation =                 &HCB
            SystemWorkloadAllowedCpuSetsInformation =               &HCC
            SystemCodeIntegrityUnlockModeInformation =              &HCD
            SystemLeapSecondInformation =                           &HCE
            SystemFlags2Information =                               &HCF
            SystemSecurityModelInformation =                        &HD0
            SystemCodeIntegritySyntheticCacheInformation =          &HD1
            MaxSystemInfoClass =                                    &HD2
        End Enum

        'https://www.pinvoke.net/default.aspx/Enums.OBJECT_INFORMATION_CLASS
        Protected Enum OBJECT_INFORMATION_CLASS
            ObjectBasicInformation =    0
            ObjectNameInformation =     1
            ObjectTypeInformation =     2
            ObjectAllTypesInformation = 3
            ObjectHandleInformation =   4
        End Enum

        'https://docs.microsoft.com/en-za/windows/win32/procthread/process-security-and-access-rights
        'https://www.pinvoke.net/default.aspx/Enums.ProcessAccess
        Protected Enum PROCESS_ACCESS_RIGHTS
            PROCESS_TERMINATE =                 &H00000001
            PROCESS_CREATE_THREAD =             &H00000002
            PROCESS_SET_SESSION_ID =            &H00000004
            PROCESS_VM_OPERATION =              &H00000008
            PROCESS_VM_READ =                   &H00000010
            PROCESS_VM_WRITE =                  &H00000020
            PROCESS_DUP_HANDLE =                &H00000040
            PROCESS_CREATE_PROCESS =            &H00000080
            PROCESS_SET_QUOTA =                 &H00000100
            PROCESS_SET_INFORMATION =           &H00000200
            PROCESS_QUERY_INFORMATION =         &H00000400
            PROCESS_SUSPEND_RESUME =            &H00000800
            PROCESS_QUERY_LIMITED_INFORMATION = &H00001000
            DELETE =                            &H00010000
            READ_CONTROL =                      &H00020000
            WRITE_DAC =                         &H00040000
            WRITE_OWNER =                       &H00080000
            STANDARD_RIGHTS_REQUIRED =          &H000F0000
            SYNCHRONIZE =                       &H00100000

            PROCESS_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED Or SYNCHRONIZE Or &HFFFF
        End Enum

        'https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle#DUPLICATE_CLOSE_SOURCE
        Protected Enum DUPLICATE_HANDLE_OPTIONS
            DUPLICATE_CLOSE_SOURCE = &H00000001
            DUPLICATE_SAME_ACCESS =  &H00000002
        End Enum

        'http://www.jasinskionline.com/TechnicalWiki/SYSTEM_HANDLE_INFORMATION-WinApi-Struct.ashx
        Friend Enum SYSTEM_HANDLE_FLAGS As Byte
            PROTECT_FROM_CLOSE = &H01
            INHERIT =            &H02
        End Enum

        'https://www.winehq.org/pipermail/wine-patches/2005-October/021642.html
        'https://github.com/olimsaidov/autorun-remover/blob/b558df6487ae1cb4cb998fab3330c07bb7de0f21/NativeAPI.pas#L108
        Friend Enum SYSTEM_HANDLE_TYPE
            UNKNOWN =        00
            TYPE =           01
            DIRECTORY =      02
            SYMBOLIC_LINK =  03
            TOKEN =          04
            PROCESS =        05
            THREAD =         06
            JOB =            07
            [EVENT] =        08
            EVENT_PAIR =     09
            MUTANT =         10
            UNKNOWN_11 =     11
            SEMAPHORE =      12
            TIMER =          13
            PROFILE =        14
            WINDOW_STATION = 15
            DESKTOP =        16
            SECTION =        17
            KEY =            18
            PORT =           19
            WAITABLE_PORT =  20
            ADAPTER =        21
            CONTROLLER =     22
            DEVICE =         23
            DRIVER =         24
            IO_COMPLETION =  25
            FILE =           28

            ' From my own research
            TP_WORKER_FACTORY
            ALPC_PORT
            KEYED_EVENT
            SESSION
            IO_COMPLETION_RESERVE
            WMI_GUID
            USER_APC_RESERVE
            IR_TIMER
            COMPOSITION
            WAIT_COMPLETION_PACKET
            DXGK_SHARED_RESOURCE
            DXGK_SHARED_SYNC_OBJECT
            DXGK_DISPLAY_MANAGER_OBJECT
            DXGK_COMPOSITION_OBJECT
            OTHER
        End Enum

        #End Region

        #Region "Structs"

        'https://www.codeproject.com/script/Articles/ViewDownloads.aspx?aid=18975&zep=OpenedFileFinder%2fUtils.h&rzp=%2fKB%2fshell%2fOpenedFileFinder%2f%2fopenedfilefinder_src.zip
        <StructLayout(LayoutKind.Sequential)>
        Protected Structure SYSTEM_HANDLE_INFORMATION
            'Public dwCount As IntPtr
            Public dwCount As UInteger

            ' see https://stackoverflow.com/a/38884095/2999220 - MarshalAs doesn't allow variable sized arrays
            '<MarshalAs(UnmanagedType.ByValArray, ArraySubType := UnmanagedType.Struct)>
            'Public [Handles] As SYSTEM_HANDLE()
            Public [Handles] As IntPtr
        End Structure

        'https://stackoverflow.com/a/5163277/2999220
        'http://www.jasinskionline.com/TechnicalWiki/SYSTEM_HANDLE_INFORMATION-WinApi-Struct.ashx
        <StructLayout(LayoutKind.Sequential)>
        Friend Structure SYSTEM_HANDLE
            ''' <summary>Handle Owner Process ID</summary>
            Public dwProcessId As UInteger
            ''' <summary>Object Type</summary>
            Public bObjectType As Byte
            ''' <summary>Handle Flags</summary>
            Public bFlags As SYSTEM_HANDLE_FLAGS
            ''' <summary>Handle Value</summary>
            Public wValue As UShort
            ''' <summary>Object Pointer</summary>
            Private ReadOnly pAddress As IntPtr
            ''' <summary>Access Mask</summary>
            Public dwGrantedAccess As UInteger
        End Structure

        'https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_unicode_string
        'https://www.pinvoke.net/default.aspx/Structures/UNICODE_STRING.html
        <StructLayout(LayoutKind.Sequential, CharSet:=CharSet.Unicode)>
        Protected Structure UNICODE_STRING
            Public ReadOnly Length As UShort
            Public ReadOnly MaximumLength As UShort
            <MarshalAs(UnmanagedType.LPWStr)>
            Public ReadOnly Buffer As String

            Public Sub New(s As String)
                Length = CType(s.Length * 2, UShort)
                MaximumLength = CType(Length + 2, UShort)
                Buffer = s
            End Sub
        End Structure

        'https://www.pinvoke.net/default.aspx/Structures.GENERIC_MAPPING
        'http://www.jasinskionline.com/technicalwiki/GENERIC_MAPPING-WinApi-Struct.ashx
        <StructLayout(LayoutKind.Sequential)>
        Protected Structure GENERIC_MAPPING
            Public GenericRead As    UInteger
            Public GenericWrite As   UInteger
            Public GenericExecute As UInteger
            Public GenericAll As     UInteger
        End Structure

        'http://www.jasinskionline.com/technicalwiki/OBJECT_NAME_INFORMATION-WinApi-Struct.ashx
        <StructLayout(LayoutKind.Sequential)>
        Protected Structure OBJECT_NAME_INFORMATION
            Public Name As UNICODE_STRING
        End Structure

        'https://docs.microsoft.com/en-za/windows-hardware/drivers/ddi/ntifs/ns-ntifs-__public_object_type_information
        'http://www.jasinskionline.com/technicalwiki/OBJECT_TYPE_INFORMATION-WinApi-Struct.ashx
        <StructLayout(LayoutKind.Sequential)>
        Protected Structure OBJECT_TYPE_INFORMATION
            Public TypeName As               UNICODE_STRING
            Public ObjectCount As            Integer
            Public HandleCount As            Integer
            Private ReadOnly Reserved1 As    Integer
            Private ReadOnly Reserved2 As    Integer
            Private ReadOnly Reserved3 As    Integer
            Private ReadOnly Reserved4 As    Integer
            Public PeakObjectCount As        Integer
            Public PeakHandleCount As        Integer
            Private ReadOnly Reserved5 As    Integer
            Private ReadOnly Reserved6 As    Integer
            Private ReadOnly Reserved7 As    Integer
            Private ReadOnly Reserved8 As    Integer
            Public InvalidAttributes As      Integer
            Public GenericMapping As         GENERIC_MAPPING
            Public ValidAccess As            Integer
            Private ReadOnly Unknown As      Byte
            Public MaintainHandleDatabase As Byte
            Public PoolType As               Integer
            Public PagedPoolUsage As         Integer
            Public NonPagedPoolUsage As      Integer
        End Structure

        #End Region

        #Region "Methods"

        'https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
        <DllImport("ntdll.dll")>
        Protected Shared Function NtQuerySystemInformation(
            <[In]> SystemInformationClass As SYSTEM_INFORMATION_CLASS,
            <Out>  SystemInformation As IntPtr,
            <[In]> SystemInformationLength As UInteger,
            <Out>  ByRef ReturnLength As UInteger
                ) As NTSTATUS
        End Function

        'https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject
        <DllImport("ntdll.dll")>
        Protected Shared Function NtQueryObject(
            <[In]> Handle As IntPtr,
            <[In]> ObjectInformationClass As OBJECT_INFORMATION_CLASS,
            <[In]> ObjectInformation As IntPtr,
            <[In]> ObjectInformationLength As UInteger,
            <Out>  ByRef ReturnLength As UInteger
                ) As NTSTATUS
        End Function

        'https://docs.microsoft.com/en-za/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        <DllImport("kernel32.dll", SetLastError:=True)>
        Protected Shared Function OpenProcess(
            <[In]> dwDesiredAccess As PROCESS_ACCESS_RIGHTS,
            <[In], MarshalAs(UnmanagedType.Bool)> bInheritHandle As Boolean,
            <[In]> dwProcessId As UInteger
                ) As IntPtr
        End Function

        'https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
        <DllImport("kernel32.dll", SetLastError:=True)>
        Protected Shared Function DuplicateHandle(
            <[In]> hSourceProcessHandle As IntPtr,
            <[In]> hSourceHandle As IntPtr,
            <[In]> hTargetProcessHandle As IntPtr,
            <Out>  ByRef lpTargetHandle As IntPtr,
            <[In]> dwDesiredAccess As UInteger,
            <[In], MarshalAs(UnmanagedType.Bool)> bInheritHandle As Boolean,
            <[In]> dwOptions As DUPLICATE_HANDLE_OPTIONS
                ) As <MarshalAs(UnmanagedType.Bool)> Boolean
        End Function

        'https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
        <DllImport("kernel32.dll")>
        Protected Shared Function GetCurrentProcess() As IntPtr
        End Function

        'https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
        <ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)>
        <DllImport("kernel32.dll", SetLastError:=True)>
        Protected Shared Function CloseHandle(
            <[In]> hObject As IntPtr
                ) As <MarshalAs(UnmanagedType.Bool)> Boolean
        End Function

        'https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-querydosdevicea
        'https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-querydosdevicew
        <DllImport("kernel32.dll", SetLastError:=True)>
        Protected Shared Function QueryDosDevice(
            <[In]> lpDeviceName As String,
            <Out>  lpTargetPath As StringBuilder,
            <[In]> ucchMax As UInteger
                ) As UInteger
        End Function

        #End Region

        #End Region

        #Region "Public Methods"

        #Region "GetSystemHandles"

        ''' <summary>Gets all the open handles on the system. Use GetHandleInfo to retrieve proper type and name information.</summary>
        ''' <returns>Enumerable list of system handles</returns>
        Friend Shared Iterator Function GetSystemHandles() As IEnumerable(Of SYSTEM_HANDLE)
            Dim length As UInteger = &H1000
            Dim ptr As IntPtr = IntPtr.Zero
            Try
                While True
                    ptr = Marshal.AllocHGlobal(CType(length, Integer))
                    Dim wantedLength As UInteger
                    Select Case NtQuerySystemInformation(
                            SYSTEM_INFORMATION_CLASS.SystemHandleInformation,
                            ptr, length, wantedLength)
                        Case NTSTATUS.STATUS_SUCCESS
                            Exit While
                        Case NTSTATUS.STATUS_INFO_LENGTH_MISMATCH
                            length = Math.Max(length, wantedLength)
                            Marshal.FreeHGlobal(ptr)
                            ptr = IntPtr.Zero
                        Case Else
                            Throw New Exception("Failed to retrieve system handle information.", New Win32Exception())
                    End Select
                End While

                Dim handleCount As Long = If(IntPtr.Size = 4, Marshal.ReadInt32(ptr), Marshal.ReadInt64(ptr))
                Dim offset As Long = IntPtr.Size
                Dim size As Long = Marshal.SizeOf(GetType(SYSTEM_HANDLE))

                For i As Long = 0 To handleCount - 1
                    Dim struc As SYSTEM_HANDLE = Marshal.PtrToStructure(Of SYSTEM_HANDLE)(ptr + offset)
                    ' `ptr + offset` above was: `CType(CType(ptr, Long) + offset, IntPtr)` but it seems to work...
                    Yield struc

                    offset += size
                Next
            Finally
                If ptr <> IntPtr.Zero Then
                    Marshal.FreeHGlobal(ptr)
                End If
            End Try
        End Function

        #End Region

        #Region "GetHandleInfo"

        Friend Structure HandleInfo
            Public ProcessID As UInteger
            Public HandleID As UShort
            Public GrantedAccess As UInteger
            Public RawType As Byte
            Public Flags As SYSTEM_HANDLE_FLAGS
            Public Name As String
            Public TypeString As String
            Public Type As SYSTEM_HANDLE_TYPE
        End Structure

        Private Shared rawTypeMap As New ConcurrentDictionary(Of Byte, String)()

        Private Shared Function HandleTypeFromString(typeString As String) As SYSTEM_HANDLE_TYPE
            Select Case typeString
                Case Nothing
                    Return SYSTEM_HANDLE_TYPE.UNKNOWN
                Case "Directory"
                    Return SYSTEM_HANDLE_TYPE.DIRECTORY
                Case "SymbolicLink"
                    Return SYSTEM_HANDLE_TYPE.SYMBOLIC_LINK
                Case "Token"
                    Return SYSTEM_HANDLE_TYPE.TOKEN
                Case "Process"
                    Return SYSTEM_HANDLE_TYPE.PROCESS
                Case "Thread"
                    Return SYSTEM_HANDLE_TYPE.THREAD
                Case "Job"
                    Return SYSTEM_HANDLE_TYPE.JOB
                Case "Event"
                    Return SYSTEM_HANDLE_TYPE.EVENT
                Case "Mutant"
                    Return SYSTEM_HANDLE_TYPE.MUTANT
                Case "Semaphore"
                    Return SYSTEM_HANDLE_TYPE.SEMAPHORE
                Case "Timer"
                    Return SYSTEM_HANDLE_TYPE.TIMER
                Case "WindowStation"
                    Return SYSTEM_HANDLE_TYPE.WINDOW_STATION
                Case "Desktop"
                    Return SYSTEM_HANDLE_TYPE.DESKTOP
                Case "Section"
                    Return SYSTEM_HANDLE_TYPE.SECTION
                Case "Key"
                    Return SYSTEM_HANDLE_TYPE.KEY
                Case "IoCompletion"
                    Return SYSTEM_HANDLE_TYPE.IO_COMPLETION
                Case "File"
                    Return SYSTEM_HANDLE_TYPE.FILE
                Case "TpWorkerFactory"
                    Return SYSTEM_HANDLE_TYPE.TP_WORKER_FACTORY
                Case "ALPC Port"
                    Return SYSTEM_HANDLE_TYPE.ALPC_PORT
                Case "KeyedEvent"
                    Return SYSTEM_HANDLE_TYPE.KEYED_EVENT
                Case "Session"
                    Return SYSTEM_HANDLE_TYPE.SESSION
                Case "IoCompletionReserve"
                    Return SYSTEM_HANDLE_TYPE.IO_COMPLETION_RESERVE
                Case "WmiGuid"
                    Return SYSTEM_HANDLE_TYPE.WMI_GUID
                Case "UserApcReserve"
                    Return SYSTEM_HANDLE_TYPE.USER_APC_RESERVE
                Case "IRTimer"
                    Return SYSTEM_HANDLE_TYPE.IR_TIMER
                Case "Composition"
                    Return SYSTEM_HANDLE_TYPE.COMPOSITION
                Case "WaitCompletionPacket"
                    Return SYSTEM_HANDLE_TYPE.WAIT_COMPLETION_PACKET
                Case "DxgkSharedResource"
                    Return SYSTEM_HANDLE_TYPE.DXGK_SHARED_RESOURCE
                Case "DxgkSharedSyncObject"
                    Return SYSTEM_HANDLE_TYPE.DXGK_SHARED_SYNC_OBJECT
                Case "DxgkDisplayManagerObject"
                    Return SYSTEM_HANDLE_TYPE.DXGK_DISPLAY_MANAGER_OBJECT
                Case "DxgkCompositionObject"
                    Return SYSTEM_HANDLE_TYPE.DXGK_COMPOSITION_OBJECT
                Case Else
                    Return SYSTEM_HANDLE_TYPE.OTHER
            End Select
        End Function

        ''' <summary>
        ''' Gets the handle type and name, and puts the other properties into more user-friendly fields.
        ''' 
        ''' This function gets typeInfo from an internal type map (rawType to typeString) that is built as types are retrieved.
        ''' To get full type information of handle types that could not be retrieved,
        ''' either put the handles into a list, build a second map and apply them retroactively,
        ''' or call this function on all System Handles beforehand with getting names Disabled.
        ''' </summary>
        ''' <param name="handle">Handle struct returned by GetSystemHandles</param>
        ''' <param name="getAllNames">False (default) to ignore certain names that cause the system query to hang. Only set to true in a thread that can be killed.</param>
        ''' <param name="onlyGetNameFor">Set this to only attempt to get Handle names for a specific handle type. Set to int.MaxValue to disable getting file names.</param>
        ''' <returns>HandleInfo struct with retrievable information populated.</returns>
        Friend Shared Function GetHandleInfo(handle As SYSTEM_HANDLE, Optional getAllNames As Boolean = False, Optional onlyGetNameFor As SYSTEM_HANDLE_TYPE = SYSTEM_HANDLE_TYPE.UNKNOWN) As HandleInfo
            Dim handleInfo As New HandleInfo() With {
                .ProcessID = handle.dwProcessId,
                .HandleID = handle.wValue,
                .GrantedAccess = handle.dwGrantedAccess,
                .RawType = handle.bObjectType,
                .Flags = handle.bFlags,
                .Name = Nothing,
                .TypeString = Nothing,
                .Type = SYSTEM_HANDLE_TYPE.UNKNOWN
            }

            ' get type from cached map if it exists
            If rawTypeMap.ContainsKey(handleInfo.RawType) Then
                handleInfo.TypeString = rawTypeMap(handleInfo.RawType)
                handleInfo.Type = HandleTypeFromString(handleInfo.TypeString)
            End If

            Dim sourceProcessHandle As IntPtr = IntPtr.Zero
            Dim handleDuplicate As IntPtr = IntPtr.Zero
            Try
                sourceProcessHandle = OpenProcess(PROCESS_ACCESS_RIGHTS.PROCESS_DUP_HANDLE, True, handleInfo.ProcessID)

                ' To read info about a handle owned by another process we must duplicate it into ours
                ' For simplicity, current process handles will also get duplicated; remember that process handles cannot be compared for equality
                If Not DuplicateHandle(sourceProcessHandle, CType(handleInfo.HandleID, IntPtr), GetCurrentProcess(), handleDuplicate, 0, False, DUPLICATE_HANDLE_OPTIONS.DUPLICATE_SAME_ACCESS) Then
                    Return handleInfo
                End If

                ' Get the object type if it hasn't been retrieved from cache map above
                If Not rawTypeMap.ContainsKey(handleInfo.RawType) Then
                    Dim length As UInteger
                    NtQueryObject(handleDuplicate, OBJECT_INFORMATION_CLASS.ObjectTypeInformation, IntPtr.Zero, 0, length)

                    Dim ptr As IntPtr = IntPtr.Zero
                    Try
                        ptr = Marshal.AllocHGlobal(CType(length, Integer))
                        If NtQueryObject(handleDuplicate, OBJECT_INFORMATION_CLASS.ObjectTypeInformation, ptr, length, length) <> NTSTATUS.STATUS_SUCCESS Then
                            Return handleInfo
                        End If

                        Dim typeInfo As OBJECT_TYPE_INFORMATION = Marshal.PtrToStructure(Of OBJECT_TYPE_INFORMATION)(ptr)
                        handleInfo.TypeString = typeInfo.TypeName.Buffer
                    Finally
                        Marshal.FreeHGlobal(ptr)
                    End Try

                    rawTypeMap.TryAdd(handleInfo.RawType, handleInfo.TypeString)
                    handleInfo.Type = HandleTypeFromString(handleInfo.TypeString)
                End If

                ' Get the object name
                '     only check onlyGetNameFor if it isn't UNKNOWN
                '         this type can hang for ~15 mins, but excluding it cuts a lot of results, and it does eventually resolve...
                '        Not (handleInfo.Type = SYSTEM_HANDLE_TYPE.FILE AndAlso handleInfo.GrantedAccess = &H120089 AndAlso handleInfo.Flags = &H00                       ) AndAlso
                If handleInfo.TypeString IsNot Nothing AndAlso
                    (onlyGetNameFor = SYSTEM_HANDLE_TYPE.UNKNOWN OrElse handleInfo.Type = onlyGetNameFor) AndAlso
                    (getAllNames = True OrElse (
                        Not (handleInfo.Type = SYSTEM_HANDLE_TYPE.FILE AndAlso handleInfo.GrantedAccess = &H1F01FF AndAlso handleInfo.Flags = SYSTEM_HANDLE_FLAGS.INHERIT) AndAlso
                        Not (handleInfo.Type = SYSTEM_HANDLE_TYPE.FILE AndAlso handleInfo.GrantedAccess = &H120089 AndAlso handleInfo.Flags = SYSTEM_HANDLE_FLAGS.INHERIT) AndAlso
                        Not (handleInfo.Type = SYSTEM_HANDLE_TYPE.FILE AndAlso handleInfo.GrantedAccess = &H120189 AndAlso handleInfo.Flags = &H00                       ) AndAlso
                        Not (handleInfo.Type = SYSTEM_HANDLE_TYPE.FILE AndAlso handleInfo.GrantedAccess = &H120189 AndAlso handleInfo.Flags = SYSTEM_HANDLE_FLAGS.INHERIT) AndAlso
                        Not (handleInfo.Type = SYSTEM_HANDLE_TYPE.FILE AndAlso handleInfo.GrantedAccess = &H12019F AndAlso handleInfo.Flags = &H00                       ) AndAlso
                        Not (handleInfo.Type = SYSTEM_HANDLE_TYPE.FILE AndAlso handleInfo.GrantedAccess = &H12019F AndAlso handleInfo.Flags = SYSTEM_HANDLE_FLAGS.INHERIT) AndAlso
                        Not (handleInfo.Type = SYSTEM_HANDLE_TYPE.FILE AndAlso handleInfo.GrantedAccess = &H1A019F AndAlso handleInfo.Flags = &H00                       ) AndAlso
                        Not (handleInfo.Type = SYSTEM_HANDLE_TYPE.FILE AndAlso handleInfo.GrantedAccess = &H1A019F AndAlso handleInfo.Flags = SYSTEM_HANDLE_FLAGS.INHERIT)
                            )) Then ' don't query some objects that get stuck (NtQueryObject hangs on NamedPipes)
                    Dim length As UInteger
                    NtQueryObject(handleDuplicate, OBJECT_INFORMATION_CLASS.ObjectNameInformation, IntPtr.Zero, 0, length)

                    Dim ptr As IntPtr = IntPtr.Zero
                    Try
                        ptr = Marshal.AllocHGlobal(CType(length, Integer))
                        If NtQueryObject(handleDuplicate, OBJECT_INFORMATION_CLASS.ObjectNameInformation, ptr, length, length) <> NTSTATUS.STATUS_SUCCESS Then
                            Return handleInfo
                        End If

                        Dim nameInfo As OBJECT_NAME_INFORMATION = Marshal.PtrToStructure(Of OBJECT_NAME_INFORMATION)(ptr)
                        handleInfo.Name = nameInfo.Name.Buffer
                    Finally
                        Marshal.FreeHGlobal(ptr)
                    End Try
                End If
            Finally
                CloseHandle(sourceProcessHandle)
                If handleDuplicate <> IntPtr.Zero Then
                    CloseHandle(handleDuplicate)
                End If
            End Try

            Return handleInfo
        End Function

        #End Region

        #Region "CloseSystemHandle"

        ' https://www.codeproject.com/Articles/18975/Listing-Used-Files
        ''' <summary>Attempts to close a handle in a different process. Fails silently if the handle exists but could not be closed.</summary>
        ''' <param name="ProcessID">Process ID of the process containing the handle to close</param>
        ''' <param name="HandleID">Handle value in the target process to close</param>
        Friend Shared Sub CloseSystemHandle(ProcessID As UInteger, HandleID As UShort)
            Dim sourceProcessHandle As IntPtr = IntPtr.Zero
            Dim handleDuplicate As IntPtr = IntPtr.Zero
            Try
                sourceProcessHandle = OpenProcess(PROCESS_ACCESS_RIGHTS.PROCESS_DUP_HANDLE, True, ProcessID)
                If CType(sourceProcessHandle, Integer) < 1 Then
                    Throw New ArgumentException("Process ID Not Found!", "ProcessID", New Win32Exception())
                End If

                ' always returns false, no point in checking
                DuplicateHandle(sourceProcessHandle, CType(HandleID, IntPtr), GetCurrentProcess(), handleDuplicate, 0, False, DUPLICATE_HANDLE_OPTIONS.DUPLICATE_CLOSE_SOURCE)
                If CType(handleDuplicate, Integer) < 1 AndAlso Marshal.GetLastWin32Error() = 6 Then ' ERROR_INVALID_HANDLE: The handle is invalid.
                    Throw New ArgumentException("Handle ID Not Found!", "HandleID", New Win32Exception(6))
                End If
            Finally
                CloseHandle(sourceProcessHandle)
                If handleDuplicate <> IntPtr.Zero Then
                    CloseHandle(handleDuplicate)
                End If
            End Try
        End Sub

        #End Region

        #Region "ConvertDevicePathToDosPath"

        Private Shared deviceMap As Dictionary(Of String, String)
        Private Const networkDeviceQueryDosDevicePrefix As String = "\Device\LanmanRedirector\"
        Private Const networkDeviceSystemHandlePrefix As String = "\Device\Mup\"
        Private Const MAX_PATH As Integer = 260

        Private Shared Function NormalizeDeviceName(deviceName As String) As String
            ' If deviceName.StartsWith(networkDeviceQueryDosDevicePrefix)
            If String.Compare(
                    deviceName, 0,
                    networkDeviceQueryDosDevicePrefix, 0,
                    networkDeviceQueryDosDevicePrefix.Length, StringComparison.InvariantCulture) = 0 Then
                Dim shareName As String = deviceName.Substring(deviceName.IndexOf("\"c, networkDeviceQueryDosDevicePrefix.Length) + 1)
                Return String.Concat(networkDeviceSystemHandlePrefix, shareName)
            End If
            Return deviceName
        End Function

        Private Shared Function BuildDeviceMap() As Dictionary(Of String, String)
            Dim logicalDrives As String() = Environment.GetLogicalDrives()
            Dim localDeviceMap As New Dictionary(Of String, String)(logicalDrives.Length)

            Dim lpTargetPath As New StringBuilder(MAX_PATH)
            For Each drive As String In logicalDrives
                Dim lpDeviceName As String = drive.Substring(0, 2)

                QueryDosDevice(lpDeviceName, lpTargetPath, MAX_PATH)

                localDeviceMap.Add(
                    NormalizeDeviceName(lpTargetPath.ToString()),
                    lpDeviceName)
            Next
            ' add a map so \\COMPUTER\ shares get picked up correctly - these will come as \Device\Mup\COMPUTER\share
            '     remove the last slash from networkDeviceSystemHandlePrefix:
            localDeviceMap.Add(
                networkDeviceSystemHandlePrefix.Substring(0, networkDeviceSystemHandlePrefix.Length - 1),
                "\")
            Return localDeviceMap
        End Function

        Private Shared Sub EnsureDeviceMap()
            If deviceMap Is Nothing Then
                Dim localDeviceMap As Dictionary(Of String, String) = BuildDeviceMap()
                Interlocked.CompareExchange(deviceMap, localDeviceMap, Nothing)
            End If
        End Sub

        ''' <summary>
        ''' Converts a device path to a DOS path. Requires a trailing slash if just the device path is passed.
        ''' Returns string.Empty if no device is found.
        ''' </summary>
        ''' <param name="devicePath">Full path including a device. Device paths usually start with \Device\HarddiskVolume[n]\</param>
        ''' <returns>DOS Path or string.Empty if none found</returns>
        Public Shared Function ConvertDevicePathToDosPath(devicePath As String) As String
            EnsureDeviceMap()
            Dim i As Integer = devicePath.Length

            ' search in reverse, to catch network shares that are mapped before returning general network path
            While i > 0 AndAlso devicePath.LastIndexOf("\"c, i - 1) <> -1
                i = devicePath.LastIndexOf("\"c, i - 1)
                Dim drive As String = ""
                If deviceMap.TryGetValue(devicePath.Remove(i), drive) Then
                    Return String.Concat(drive, devicePath.Substring(i))
                End If
            End While
            Return devicePath
        End Function

        #End Region

        #Region "GetFileHandles / GetLockingProcesses"

        ''' <summary>
        ''' Searches through all the open handles on the system, and returns handles with a path containing <paramref name="filePath"/>.
        ''' If on a network share, <paramref name="filePath"/> should refer to the deepest mapped drive.
        ''' </summary>
        ''' <param name="filePath">Path to look for handles to.</param>
        ''' <returns>Enumerable list of handles matching <paramref name="filePath"/></returns>
        Friend Shared Iterator Function GetFileHandles(filePath As String) As IEnumerable(Of HandleInfo)
            If File.Exists(filePath) Then
                filePath = New FileInfo(filePath).FullName
            ElseIf Directory.Exists(filePath) Then
                filePath = New DirectoryInfo(filePath).FullName
            End If

            For Each systemHandle As SYSTEM_HANDLE In GetSystemHandles()
                Dim handleInfo As HandleInfo = GetHandleInfo(systemHandle, onlyGetNameFor:=SYSTEM_HANDLE_TYPE.FILE)
                If handleInfo.Type = SYSTEM_HANDLE_TYPE.FILE AndAlso handleInfo.Name IsNot Nothing Then
                    handleInfo.Name = ConvertDevicePathToDosPath(handleInfo.Name)
                    If handleInfo.Name.Contains(filePath) Then
                        Yield handleInfo
                    End If
                End If
            Next
        End Function

        ''' <summary>
        ''' Gets a list of processes locking <paramref name="filePath"/>.
        ''' Processes that can't be retrieved by PID (if they have exited) will be excluded.
        ''' If on a network share, <paramref name="filePath"/> should refer to the deepest mapped drive.
        ''' </summary>
        ''' <param name="filePath">Path to look for locking processes.</param>
        ''' <returns>List of processes locking <paramref name="filePath"/>.</returns>
        Public Shared Function GetLockingProcesses(filePath As String) As List(Of Process)
            Dim processes As New List(Of Process)()
            For Each handleInfo As HandleInfo In GetFileHandles(filePath)
                Try
                    Dim processToAdd As Process = Process.GetProcessById(CType(handleInfo.ProcessID, Integer))
                    processes.Add(processToAdd)
                Catch ex As ArgumentException
                    ' process has exited
                End Try
            Next
            Return processes
        End Function

        #End Region

        #End Region
    End Class
End Namespace
