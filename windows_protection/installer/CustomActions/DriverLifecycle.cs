using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32;
using System.Web.Script.Serialization;
using WixToolset.Dtf.WindowsInstaller;

namespace StaiProtectionCustomActions
{
    public static class DriverLifecycle
    {
        private const string ServiceName = "STAIProtection";
        private const string DriverName = "StaiProtection";
        private const string PipeName = "STAI.Protection.v1";
        private const string UpdateRecoveryTaskName = "STAI Protection Update Recovery";
        private const string InstallRollbackRecoveryTaskName = "STAI Protection Install Rollback Recovery";
        private const string InstallRollbackRecoveryScriptName = "InstallRollbackRecovery.ps1";
        private const string InstallMarkerName = ".stai-install-in-progress";
        private const int MaxFrameBytes = 64 * 1024;
        private static readonly TimeSpan ProcessTimeout = TimeSpan.FromSeconds(90);
        private static readonly JavaScriptSerializer Json = new JavaScriptSerializer();

        [CustomAction]
        public static ActionResult CaptureDashboardSid(Session session)
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    string sid = identity.User == null ? null : identity.User.Value;
                    if (identity.User == null || identity.User.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
                        String.IsNullOrWhiteSpace(sid) || !sid.StartsWith("S-1-", StringComparison.Ordinal))
                    {
                        session.Log("Install from an elevated interactive administrator account so the dashboard user can be authorized.");
                        return ActionResult.Failure;
                    }
                    session["DASHBOARDSID"] = sid;
                    session.Log("Captured the dashboard client SID for the local protection pipe ACL.");
                }
                return ActionResult.Success;
            }
            catch (Exception ex)
            {
                session.Log("Dashboard identity capture failed: {0}", ex.Message);
                return ActionResult.Failure;
            }
        }

        [CustomAction]
        public static ActionResult InstallProtection(Session session)
        {
            try
            {
                string protectionDir = FullPath(session.CustomActionData["ProtectionDir"]);
                string dashboardSid = session.CustomActionData["DashboardSid"];
                if (String.IsNullOrWhiteSpace(dashboardSid) || !dashboardSid.StartsWith("S-1-", StringComparison.Ordinal))
                    throw new InvalidOperationException("The dashboard client SID is missing or invalid.");

                string serviceExe = Path.Combine(protectionDir, "STAIProtectionService.exe");
                string driverDir = Path.Combine(protectionDir, "driver");
                string recoveryScriptSource = Path.Combine(protectionDir, InstallRollbackRecoveryScriptName);
                string infPath = Path.Combine(driverDir, "StaiProtection.inf");
                string sysPath = Path.Combine(driverDir, "StaiProtection.sys");
                string catPath = Path.Combine(driverDir, "StaiProtection.cat");
                RequireFile(serviceExe);
                RequireFile(recoveryScriptSource);
                RequireFile(infPath);
                RequireFile(sysPath);
                RequireFile(catPath);
                if (ServiceExists(ServiceName) || ServiceExists(DriverName))
                    throw new InvalidOperationException("A protection service or minifilter with the STAI service name is already registered.");
                SecureDataDirectory();
                string marker = GetInstallMarkerPath();
                if (File.Exists(marker))
                    throw new InvalidOperationException("A previous STAI installation rollback still requires recovery.");
                string recoveryScript = GetInstallRollbackRecoveryScriptPath();
                File.Copy(recoveryScriptSource, recoveryScript, true);
                SecureDataDirectory();
                RegisterInstallRollbackRecoveryTask(protectionDir, recoveryScript);
                File.WriteAllText(marker, "installing");
                SecureDataDirectory();
                VerifyDashboardSid(dashboardSid);

                RunServiceCommand(session, serviceExe, "install --startup=auto", protectionDir, false);
                ConfigureServiceRecovery(protectionDir);
                RunServiceCommand(session, serviceExe, "start", protectionDir, false);
                WaitForServiceRunning(TimeSpan.FromSeconds(30));

                InstallMinifilter(session, infPath, driverDir);
                if (!ServiceRunning(DriverName))
                {
                    int loadResult = FilterLoad(DriverName);
                    uint driverState = ServiceState(DriverName);
                    if (loadResult < 0 && driverState != 2 && driverState != 4)
                        Marshal.ThrowExceptionForHR(loadResult);
                }
                WaitForDriverRunning(TimeSpan.FromSeconds(15));

                if (!WaitForHealthyPipe(TimeSpan.FromSeconds(45)))
                    throw new InvalidOperationException("The service did not report active health after the filter loaded.");

                session.Log("STAI service, signed rules, and minifilter passed the local health handshake.");
                return ActionResult.Success;
            }
            catch (Exception ex)
            {
                session.Log("STAI protection installation failed: {0}", ex.Message);
                return ActionResult.Failure;
            }
        }

        [CustomAction]
        public static ActionResult RollbackProtection(Session session)
        {
            string protectionDir = null;
            string marker = GetInstallMarkerPath();
            try
            {
                protectionDir = FullPath(session.CustomActionData["ProtectionDir"]);
                if (File.Exists(marker))
                {
                    Cleanup(session, protectionDir, true);
                    File.Delete(marker);
                    try { RemoveInstallRollbackRecoveryArtifacts(protectionDir); }
                    catch (Exception cleanupError) { session.Log("Recovery-task cleanup will finish on the next boot: {0}", cleanupError.Message); }
                }
            }
            catch (Exception ex)
            {
                session.Log("Rollback cleanup was incomplete: {0}", ex.Message);
                if (File.Exists(marker) && !String.IsNullOrEmpty(protectionDir))
                {
                    try { DisableProtectionStartup(session, protectionDir); }
                    catch (Exception disableError) { session.Log("Could not disable automatic service/filter start before reboot recovery: {0}", disableError.Message); }
                }
            }
            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult CommitProtection(Session session)
        {
            try
            {
                string marker = GetInstallMarkerPath();
                if (File.Exists(marker))
                {
                    try
                    {
                        File.WriteAllText(marker, "committed");
                    }
                    catch
                    {
                        try
                        {
                            DeleteScheduledTask(InstallRollbackRecoveryTaskName, GetProtectionDataRoot());
                            if (File.Exists(marker)) File.Delete(marker);
                            string recoveryScript = GetInstallRollbackRecoveryScriptPath();
                            if (File.Exists(recoveryScript)) File.Delete(recoveryScript);
                        }
                        catch (Exception taskError)
                        {
                            session.Log("Could not disarm install recovery after its commit marker failed: {0}", taskError.Message);
                        }
                        throw;
                    }
                    File.Delete(marker);
                }
                string protectionDir = FullPath(session.CustomActionData["ProtectionDir"]);
                try { RemoveInstallRollbackRecoveryArtifacts(protectionDir); }
                catch (Exception cleanupError) { session.Log("Committed install recovery-task cleanup will finish on the next boot: {0}", cleanupError.Message); }
            }
            catch (Exception ex)
            {
                session.Log("Could not clear the successful-install marker: {0}", ex.Message);
            }
            return ActionResult.Success;
        }

        [CustomAction]
        public static ActionResult UninstallProtection(Session session)
        {
            try
            {
                string protectionDir = FullPath(session.CustomActionData["ProtectionDir"]);
                Cleanup(session, protectionDir, false);
                try { RemoveInstallRollbackRecoveryArtifacts(protectionDir); }
                catch (Exception cleanupError) { session.Log("Recovery-task cleanup after uninstall was incomplete: {0}", cleanupError.Message); }
                return ActionResult.Success;
            }
            catch (Exception ex)
            {
                session.Log("Protection component cleanup was incomplete: {0}", ex.Message);
                return ActionResult.Failure;
            }
        }

        private static void InstallMinifilter(Session session, string infPath, string driverDir)
        {
            string arguments = "setupapi.dll,InstallHinfSection DefaultInstall 132 " + Quote(infPath);
            RunProcess(Path.Combine(Environment.SystemDirectory, "rundll32.exe"), arguments, driverDir, ProcessTimeout, false);
            if (!ServiceExists(DriverName))
                throw new InvalidOperationException("The minifilter INF did not register the driver service.");
            session.Log("Installed the minifilter from its staged Windows INF package.");
        }

        private static void Cleanup(Session session, string protectionDir, bool rollback)
        {
            FileStream updateGuard = null;
            try
            {
            if (!rollback)
            {
                updateGuard = EnsureNoUpdateInProgress();
                RunProcess(Path.Combine(Environment.SystemDirectory, "schtasks.exe"),
                    "/Delete /TN \"" + UpdateRecoveryTaskName + "\" /F",
                    protectionDir, TimeSpan.FromSeconds(20), true);
            }
            string serviceExe = Path.Combine(protectionDir, "STAIProtectionService.exe");
            if (File.Exists(serviceExe) && ServiceExists(ServiceName) && ServiceState(ServiceName) != 1)
            {
                if (rollback)
                {
                    TryServiceCommand(session, serviceExe, "stop", protectionDir);
                    try { WaitForServiceStopped(TimeSpan.FromSeconds(30)); }
                    catch (Exception ex) { session.Log("Protection service did not stop during rollback: {0}", ex.Message); }
                }
                else
                {
                    RunServiceCommand(session, serviceExe, "stop", protectionDir, false);
                    WaitForServiceStopped(TimeSpan.FromSeconds(30));
                }
            }

            try
            {
                int result = FilterUnload(DriverName);
                if (result < 0 && ServiceRunning(DriverName) && !rollback)
                    throw new InvalidOperationException("The minifilter could not be unloaded; MSI uninstall has been stopped safely.");
                if (result < 0 && rollback && ServiceRunning(DriverName))
                    throw new InvalidOperationException("Rollback could not unload the minifilter; service registration, image, and recovery marker are being retained.");
                if (result < 0)
                    session.Log("FilterUnload returned 0x{0:X8}; continuing cleanup.", result);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Windows could not verify minifilter unload; cleanup is retaining the driver image and install recovery marker.", ex);
            }

            if (ServiceExists(DriverName) && ServiceState(DriverName) != 1)
            {
                if (!rollback)
                    throw new InvalidOperationException("The minifilter remains loaded; MSI uninstall has been stopped safely.");
                throw new InvalidOperationException("The minifilter remains loaded; rollback is retaining its registration, driver image, and recovery marker.");
            }

            if (ServiceExists(ServiceName) && ServiceState(ServiceName) != 1)
            {
                if (!rollback)
                    throw new InvalidOperationException("The protection service remains active; MSI uninstall has been stopped safely.");
                throw new InvalidOperationException("The protection service remains active; rollback is retaining its registration and recovery marker.");
            }

            if (File.Exists(serviceExe) && ServiceExists(ServiceName))
            {
                if (rollback)
                {
                    TryServiceCommand(session, serviceExe, "remove", protectionDir);
                    if (ServiceExists(ServiceName))
                        throw new InvalidOperationException("Rollback could not remove the protection service; its recovery marker is being retained.");
                }
                else
                {
                    RunServiceCommand(session, serviceExe, "remove", protectionDir, false);
                    if (ServiceExists(ServiceName))
                        throw new InvalidOperationException("The protection service is still registered after removal.");
                }
            }

            if (ServiceExists(DriverName))
            {
                int result = RunProcess(Path.Combine(Environment.SystemDirectory, "sc.exe"), "delete " + DriverName, protectionDir, TimeSpan.FromSeconds(20), rollback);
                if (result != 0)
                    throw new InvalidOperationException("Windows could not unregister the minifilter service; the driver image and recovery marker are being retained.");
                if (ServiceExists(DriverName))
                    throw new InvalidOperationException("The minifilter service registration is still pending removal; rollback recovery will retry after reboot.");
            }

            string installedDriver = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", DriverName + ".sys");
            TryDeleteDriverImage(session, installedDriver);

            if (rollback)
                session.Log("Rollback removed the service and driver registration; ProgramData quarantine was preserved.");
            else
                session.Log("Uninstall removed service and driver registration; ProgramData quarantine was preserved.");
            }
            finally
            {
                if (updateGuard != null) updateGuard.Dispose();
            }
        }

        private static FileStream EnsureNoUpdateInProgress()
        {
            string updateRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "STAI", "Protection", "updates");
            Directory.CreateDirectory(updateRoot);
            string lockPath = Path.Combine(updateRoot, "update.lock");
            string journalPath = Path.Combine(updateRoot, "active-update.json");
            string installMarkerPath = GetInstallMarkerPath();
            FileStream updateGuard;
            try
            {
                updateGuard = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException)
            {
                throw new InvalidOperationException("An STAI update is in progress; wait for it to finish before uninstalling.");
            }
            if (File.Exists(journalPath))
            {
                updateGuard.Dispose();
                throw new InvalidOperationException("An interrupted STAI update requires recovery; allow the startup recovery task to complete before uninstalling.");
            }
            if (File.Exists(installMarkerPath))
            {
                updateGuard.Dispose();
                throw new InvalidOperationException("An interrupted STAI installation rollback requires startup recovery before uninstalling.");
            }
            return updateGuard;
        }

        private static string GetProtectionDataRoot()
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "STAI", "Protection");
        }

        private static string GetInstallRollbackRecoveryScriptPath()
        {
            return Path.Combine(GetProtectionDataRoot(), InstallRollbackRecoveryScriptName);
        }

        private static void RegisterInstallRollbackRecoveryTask(string protectionDir, string recoveryScript)
        {
            RequireFile(recoveryScript);
            string powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            if (!File.Exists(powershell))
                throw new FileNotFoundException("Windows PowerShell is required to register install rollback recovery.", powershell);

            string taskCommand = QuoteCommandLineArgument(powershell) +
                " -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File " +
                QuoteCommandLineArgument(recoveryScript);
            string arguments = "/Create /TN " + QuoteCommandLineArgument(InstallRollbackRecoveryTaskName) +
                " /SC ONSTART /RU SYSTEM /RL HIGHEST /TR " + QuoteCommandLineArgument(taskCommand) + " /F";
            RunProcess(Path.Combine(Environment.SystemDirectory, "schtasks.exe"), arguments,
                protectionDir, TimeSpan.FromSeconds(20), false);
            int queryResult = RunProcess(Path.Combine(Environment.SystemDirectory, "schtasks.exe"),
                "/Query /TN " + QuoteCommandLineArgument(InstallRollbackRecoveryTaskName),
                protectionDir, TimeSpan.FromSeconds(20), true);
            if (queryResult != 0)
                throw new InvalidOperationException("The install rollback recovery task was not registered successfully.");
        }

        private static void RemoveInstallRollbackRecoveryArtifacts(string protectionDir)
        {
            DeleteScheduledTask(InstallRollbackRecoveryTaskName, protectionDir);
            string recoveryScript = GetInstallRollbackRecoveryScriptPath();
            if (File.Exists(recoveryScript))
            {
                File.Delete(recoveryScript);
                if (File.Exists(recoveryScript))
                    throw new IOException("The install rollback recovery script is still present after cleanup.");
            }
        }

        private static void DeleteScheduledTask(string taskName, string workingDirectory)
        {
            string schtasks = Path.Combine(Environment.SystemDirectory, "schtasks.exe");
            RunProcess(schtasks,
                "/Delete /TN " + QuoteCommandLineArgument(taskName) + " /F",
                workingDirectory, TimeSpan.FromSeconds(20), true);
            int queryResult = RunProcess(schtasks,
                "/Query /TN " + QuoteCommandLineArgument(taskName),
                workingDirectory, TimeSpan.FromSeconds(20), true);
            if (queryResult == 0)
                throw new InvalidOperationException("The scheduled task '" + taskName + "' is still registered.");
        }

        private static void DisableProtectionStartup(Session session, string workingDirectory)
        {
            string sc = Path.Combine(Environment.SystemDirectory, "sc.exe");
            foreach (string name in new[] { ServiceName, DriverName })
            {
                if (!ServiceExists(name)) continue;
                RunProcess(sc, "config " + name + " start= disabled", workingDirectory,
                    TimeSpan.FromSeconds(20), false);
            }
            session.Log("Disabled automatic service and minifilter startup while install rollback recovery remains pending.");
        }

        private static string QuoteCommandLineArgument(string value)
        {
            if (value == null) throw new ArgumentNullException("value");
            var result = new StringBuilder("\"");
            int backslashes = 0;
            foreach (char character in value)
            {
                if (character == '\\')
                {
                    backslashes++;
                    continue;
                }
                if (character == '\"')
                {
                    result.Append('\\', backslashes * 2 + 1).Append('\"');
                    backslashes = 0;
                    continue;
                }
                result.Append('\\', backslashes).Append(character);
                backslashes = 0;
            }
            result.Append('\\', backslashes * 2).Append('\"');
            return result.ToString();
        }

        private static void SecureDataDirectory()
        {
            string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "STAI", "Protection");
            Directory.CreateDirectory(root);
            Directory.CreateDirectory(Path.Combine(root, "rules"));
            Directory.CreateDirectory(Path.Combine(root, "quarantine"));

            var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            foreach (string directory in Directory.GetDirectories(root, "*", SearchOption.AllDirectories))
                SetPrivateDirectoryAcl(directory, systemSid, adminsSid);
            SetPrivateDirectoryAcl(root, systemSid, adminsSid);
            foreach (string file in Directory.GetFiles(root, "*", SearchOption.AllDirectories))
                SetPrivateFileAcl(file, systemSid, adminsSid);
        }

        private static void SetPrivateDirectoryAcl(string path, SecurityIdentifier systemSid, SecurityIdentifier adminsSid)
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);
            InheritanceFlags inherited = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            security.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, inherited, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(adminsSid, FileSystemRights.FullControl, inherited, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(path).SetAccessControl(security);
        }

        private static void SetPrivateFileAcl(string path, SecurityIdentifier systemSid, SecurityIdentifier adminsSid)
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(systemSid, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(adminsSid, FileSystemRights.FullControl, AccessControlType.Allow));
            File.SetAccessControl(path, security);
        }

        private static void VerifyDashboardSid(string expectedSid)
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\STAI\Protection", false))
            {
                object installedSid = key == null ? null : key.GetValue("DashboardClientSid");
                if (!String.Equals(installedSid as string, expectedSid, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("The protected dashboard client SID was not installed correctly.");
            }
        }

        private static bool WaitForHealthyPipe(TimeSpan timeout)
        {
            DateTime until = DateTime.UtcNow + timeout;
            while (DateTime.UtcNow < until)
            {
                try
                {
                    Dictionary<string, object> response = RequestStatus();
                    object ok;
                    object dataValue;
                    if (response.TryGetValue("ok", out ok) && ok is bool && (bool)ok &&
                        response.TryGetValue("data", out dataValue))
                    {
                        var data = dataValue as Dictionary<string, object>;
                        object state;
                        object driverState;
                        object serviceState;
                        object rulesVersion;
                        if (data != null && data.TryGetValue("state", out state) && Equals(state, "active") &&
                            data.TryGetValue("driver_state", out driverState) && Equals(driverState, "running") &&
                            data.TryGetValue("service_state", out serviceState) && Equals(serviceState, "running") &&
                            data.TryGetValue("rules_version", out rulesVersion) &&
                            rulesVersion != null && !Equals(rulesVersion, "unknown"))
                            return true;
                    }
                }
                catch (Exception)
                {
                    // Service/filter startup is asynchronous; retry until the bounded deadline.
                }
                Thread.Sleep(500);
            }
            return false;
        }

        private static Dictionary<string, object> RequestStatus()
        {
            string requestId = Guid.NewGuid().ToString("N");
            var request = new Dictionary<string, object>
            {
                { "version", 1 },
                { "request_id", requestId },
                { "operation", "get_status" },
                { "payload", new Dictionary<string, object>() }
            };
            byte[] body = Encoding.UTF8.GetBytes(Json.Serialize(request));
            if (body.Length == 0 || body.Length > MaxFrameBytes)
                throw new InvalidDataException("Status request exceeded the local IPC frame limit.");

            using (var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.None))
            {
                pipe.Connect(1500);
                pipe.ReadTimeout = 3000;
                pipe.WriteTimeout = 3000;
                byte[] header = BitConverter.GetBytes(body.Length);
                pipe.Write(header, 0, header.Length);
                pipe.Write(body, 0, body.Length);
                pipe.Flush();
                byte[] responseHeader = ReadExactly(pipe, 4);
                int responseSize = BitConverter.ToInt32(responseHeader, 0);
                if (responseSize <= 0 || responseSize > MaxFrameBytes)
                    throw new InvalidDataException("Service response exceeded the local IPC frame limit.");
                byte[] responseBody = ReadExactly(pipe, responseSize);
                return Json.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(responseBody));
            }
        }

        private static byte[] ReadExactly(Stream stream, int size)
        {
            byte[] result = new byte[size];
            int offset = 0;
            while (offset < size)
            {
                int count = stream.Read(result, offset, size - offset);
                if (count <= 0)
                    throw new EndOfStreamException("Protection service closed the status pipe early.");
                offset += count;
            }
            return result;
        }

        private static void RunServiceCommand(Session session, string serviceExe, string arguments, string workingDirectory, bool ignoreFailure)
        {
            RunProcess(serviceExe, arguments, workingDirectory, ProcessTimeout, ignoreFailure);
            session.Log("Ran protection service lifecycle command: {0}.", arguments.Split(' ')[0]);
        }

        private static void TryServiceCommand(Session session, string serviceExe, string arguments, string workingDirectory)
        {
            try { RunServiceCommand(session, serviceExe, arguments, workingDirectory, true); }
            catch (Exception ex) { session.Log("Service {0} cleanup was incomplete: {1}", arguments, ex.Message); }
        }

        private static int RunProcess(string fileName, string arguments, string workingDirectory, TimeSpan timeout, bool ignoreFailure)
        {
            var start = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                WorkingDirectory = workingDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };
            using (Process process = Process.Start(start))
            {
                if (process == null)
                    throw new InvalidOperationException("Could not start " + Path.GetFileName(fileName) + ".");
                int milliseconds = (int)Math.Min(Int32.MaxValue, timeout.TotalMilliseconds);
                if (!process.WaitForExit(milliseconds))
                {
                    try { process.Kill(); } catch { }
                    throw new TimeoutException(Path.GetFileName(fileName) + " exceeded its time limit.");
                }
                if (process.ExitCode != 0 && !ignoreFailure)
                    throw new InvalidOperationException(Path.GetFileName(fileName) + " returned exit code " + process.ExitCode + ".");
                return process.ExitCode;
            }
        }

        private static void WaitForServiceRunning(TimeSpan timeout)
        {
            DateTime until = DateTime.UtcNow + timeout;
            while (DateTime.UtcNow < until)
            {
                if (ServiceRunning(ServiceName))
                    return;
                Thread.Sleep(250);
            }
            throw new TimeoutException("The STAI protection service did not reach RUNNING state.");
        }

        private static void WaitForServiceStopped(TimeSpan timeout)
        {
            DateTime until = DateTime.UtcNow + timeout;
            while (DateTime.UtcNow < until)
            {
                if (!ServiceExists(ServiceName) || ServiceState(ServiceName) == 1) return;
                Thread.Sleep(250);
            }
            throw new TimeoutException("The STAI protection service did not stop before uninstall.");
        }

        private static void WaitForDriverRunning(TimeSpan timeout)
        {
            DateTime until = DateTime.UtcNow + timeout;
            while (DateTime.UtcNow < until)
            {
                if (ServiceRunning(DriverName)) return;
                Thread.Sleep(250);
            }
            throw new TimeoutException("The STAI minifilter did not reach RUNNING state.");
        }

        private static void ConfigureServiceRecovery(string workingDirectory)
        {
            string sc = Path.Combine(Environment.SystemDirectory, "sc.exe");
            RunProcess(sc, "failure " + ServiceName + " reset= 86400 actions= restart/5000/restart/15000/restart/60000", workingDirectory, TimeSpan.FromSeconds(20), false);
            RunProcess(sc, "failureflag " + ServiceName + " 1", workingDirectory, TimeSpan.FromSeconds(20), false);
        }

        private static bool ServiceExists(string serviceName)
        {
            IntPtr manager = OpenSCManager(null, null, 0x0001);
            if (manager == IntPtr.Zero) return false;
            try
            {
                IntPtr service = OpenService(manager, serviceName, 0x0004);
                if (service == IntPtr.Zero) return false;
                CloseServiceHandle(service);
                return true;
            }
            finally { CloseServiceHandle(manager); }
        }

        private static bool ServiceRunning(string serviceName)
        {
            return ServiceState(serviceName) == 4;
        }

        private static uint ServiceState(string serviceName)
        {
            IntPtr manager = OpenSCManager(null, null, 0x0001);
            if (manager == IntPtr.Zero) return 0;
            try
            {
                IntPtr service = OpenService(manager, serviceName, 0x0004);
                if (service == IntPtr.Zero) return 0;
                try
                {
                    ServiceStatus status;
                    return QueryServiceStatus(service, out status) ? status.CurrentState : 0;
                }
                finally { CloseServiceHandle(service); }
            }
            finally { CloseServiceHandle(manager); }
        }

        private static void TryDeleteDriverImage(Session session, string path)
        {
            try
            {
                if (!File.Exists(path)) return;
                File.Delete(path);
            }
            catch (Exception ex)
            {
                const int MoveFileDelayUntilReboot = 0x4;
                if (MoveFileEx(path, null, MoveFileDelayUntilReboot))
                    session.Log("Scheduled the unloaded driver image for removal at reboot.");
                else
                    session.Log("Could not remove the driver image ({0}); it may require manual cleanup.", ex.Message);
            }
        }

        private static string FullPath(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) throw new InvalidDataException("A required installer path is missing.");
            return Path.GetFullPath(path);
        }

        private static string GetInstallMarkerPath()
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "STAI", "Protection", InstallMarkerName);
        }

        private static void RequireFile(string path)
        {
            if (!File.Exists(path)) throw new FileNotFoundException("A required installed payload file is missing.", Path.GetFileName(path));
        }

        private static string Quote(string value)
        {
            if (value.IndexOf('"') >= 0)
                throw new InvalidDataException("The installer path contains an unsupported quote character.");
            return "\"" + value + "\"";
        }

        [DllImport("fltlib.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int FilterLoad(string lpFilterName);

        [DllImport("fltlib.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int FilterUnload(string lpFilterName);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint desiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(IntPtr manager, string serviceName, uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryServiceStatus(IntPtr service, out ServiceStatus status);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr handle);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool MoveFileEx(string existingName, string newName, int flags);

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceStatus
        {
            public uint ServiceType;
            public uint CurrentState;
            public uint ControlsAccepted;
            public uint Win32ExitCode;
            public uint ServiceSpecificExitCode;
            public uint CheckPoint;
            public uint WaitHint;
        }
    }
}
