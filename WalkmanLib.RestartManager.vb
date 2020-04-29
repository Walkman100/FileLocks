' RestartManager method
'https://stackoverflow.com/a/3504251/2999220
'https://stackoverflow.com/a/20623311/2999220
'https://stackoverflow.com/a/20623302/2999220
'https://gist.github.com/mlaily/9423f1855bb176d52a327f5874915a97
'https://docs.microsoft.com/en-us/archive/msdn-magazine/2007/april/net-matters-restart-manager-and-generic-method-compilation
'https://devblogs.microsoft.com/oldnewthing/?p=8283


Imports System.Collections.Generic
Imports System.Runtime.InteropServices
Imports System.Diagnostics
Imports System.ComponentModel

Namespace WalkmanLib
    Public NotInheritable Class RestartManager
        Const CCH_RM_MAX_APP_NAME As Integer = 255
        Const CCH_RM_MAX_SVC_NAME As Integer = 63
        Const ERROR_MORE_DATA As Integer = 234

        'https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/ns-restartmanager-rm_process_info
        <StructLayout(LayoutKind.Sequential, CharSet := CharSet.Unicode)>
        Public Structure ProcessInfo
            Public Process As UniqueProcess

            <MarshalAs(UnmanagedType.ByValTStr, SizeConst := CCH_RM_MAX_APP_NAME + 1)>
            Public AppName As String

            <MarshalAs(UnmanagedType.ByValTStr, SizeConst := CCH_RM_MAX_SVC_NAME + 1)>
            Public ServiceShortName As String

            Public ApplicationType As AppType
            Public AppStatus As UInteger
            Public TSSessionId As UInteger
            <MarshalAs(UnmanagedType.Bool)>
            Public Restartable As Boolean
        End Structure

        'https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/ns-restartmanager-rm_unique_process
        <StructLayout(LayoutKind.Sequential)>
        Public Structure UniqueProcess
            Public ProcessID As UInteger
            Private ProcessStartTime As ComTypes.FILETIME
        End Structure

        'https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/ne-restartmanager-rm_app_type
        ' values: https://github.com/microsoft/msbuild/blob/2791d9d93e88325011eb6907579d6fdac0b1b62e/src/Tasks/LockCheck.cs#L101
        Public Enum AppType
            RmUnknownApp = 0
            RmMainWindow = 1
            RmOtherWindow = 2
            RmService = 3
            RmExplorer = 4
            RmConsole = 5
            RmCritical = 1000
        End Enum

        'https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmregisterresources
        <DllImport("rstrtmgr.dll", SetLastError := True, CharSet := CharSet.Unicode)>
        Private Shared Function RmRegisterResources(pSessionHandle As UInteger,
                                                    nFiles As UInteger,
                                                    rgsFilenames As String(),
                                                    nApplications As UInteger,
                                                    <[In]> rgApplications As UniqueProcess(),
                                                    nServices As UInteger,
                                                    rgsServiceNames As String()
        ) As Integer
        End Function

        'https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmstartsession
        <DllImport("rstrtmgr.dll", SetLastError := True, CharSet := CharSet.Auto)>
        Private Shared Function RmStartSession(ByRef pSessionHandle As UInteger,
                                               dwSessionFlags As Integer,
                                               strSessionKey As String
        ) As Integer
        End Function

        'https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmendsession
        <DllImport("rstrtmgr.dll", SetLastError := True)>
        Private Shared Function RmEndSession(pSessionHandle As UInteger) As Integer
        End Function

        'https://docs.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmgetlist
        <DllImport("rstrtmgr.dll", SetLastError := True)>
        Private Shared Function RmGetList(dwSessionHandle As UInteger,
                                          ByRef pnProcInfoNeeded As UInteger,
                                          ByRef pnProcInfo As UInteger,
                                          <[In], Out> rgAffectedApps As ProcessInfo(),
                                          ByRef lpdwRebootReasons As UInteger
        ) As Integer
        End Function

        Public Shared Function GetLockingProcessInfos(path As String) As ProcessInfo()
            Dim handle As UInteger
            If RmStartSession(handle, 0, Guid.NewGuid().ToString()) <> 0 Then
                Throw New Exception("Could not begin session. Unable to determine file lockers.", New Win32Exception())
            End If

            Try
                Dim ArrayLengthNeeded As UInteger = 0,
                    ArrayLength As UInteger = 0,
                    lpdwRebootReasons As UInteger = 0 'RmRebootReasonNone
                
                Dim resources As String() = { path } ' Just checking on one resource.
                
                If RmRegisterResources(handle, CUInt(resources.Length), resources, 0, Nothing, 0, Nothing) <> 0 Then
                    Throw New Exception("Could not register resource.", New Win32Exception())
                End If

                Select Case RmGetList(handle, ArrayLengthNeeded, ArrayLength, Nothing, lpdwRebootReasons)
                    Case ERROR_MORE_DATA
                        Dim processInfos As ProcessInfo() = New ProcessInfo(ArrayLengthNeeded - 1) {}
                        ArrayLength = ArrayLengthNeeded

                        If RmGetList(handle, ArrayLengthNeeded, ArrayLength, processInfos, lpdwRebootReasons) <> 0 Then
                            Throw New Exception("Could not list processes locking resource.", New Win32Exception())
                        End If

                        Return processInfos
                    Case 0
                        Return New ProcessInfo(-1) {}
                    Case Else
                        Throw New Exception("Could not list processes locking resource. Failed to get size of result.", New Win32Exception())
                End Select
            Finally
                RmEndSession(handle)
            End Try
        End Function

        Public Shared Function GetLockingProcesses(path As String) As List(Of Process)
            Dim processes As New List(Of Process)
            For Each pI As ProcessInfo In GetLockingProcessInfos(path)
                Try
                    Dim process__1 As Process = Process.GetProcessById(CInt(pI.Process.ProcessID))
                    processes.Add(process__1)
                Catch generatedExceptionName As ArgumentException
                End Try
            Next
            Return processes
        End Function
    End Class
End Namespace
