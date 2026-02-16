/**
 * SystemAPIs.cs
 * Windows Native API Integration
 * 
 * Features:
 * - Task Scheduler integration
 * - Registry management
 * - Windows notifications
 * - System tray integration
 * - Cortana voice commands
 */

using System;
using System.Runtime.InteropServices;
using System.Speech.Recognition;
using System.Speech.Synthesis;
using Microsoft.Toolkit.Uwp.Notifications;
using Microsoft.Win32.TaskScheduler;

namespace AetherSharp.WindowsIntegration
{
    /// <summary>
    /// Windows System API wrapper for Aether AI
    /// </summary>
    public class SystemAPIs
    {
        private readonly SpeechSynthesizer _synthesizer;
        private readonly SpeechRecognitionEngine? _recognizer;

        public SystemAPIs()
        {
            _synthesizer = new SpeechSynthesizer();
            _synthesizer.SetOutputToDefaultAudioDevice();

            try
            {
                _recognizer = new SpeechRecognitionEngine();
                _recognizer.SetInputToDefaultAudioDevice();
            }
            catch
            {
                Console.WriteLine("Speech recognition not available");
            }
        }

        #region Windows Notifications

        /// <summary>
        /// Show Windows toast notification
        /// </summary>
        public void ShowNotification(string title, string message, string? iconPath = null)
        {
            var builder = new ToastContentBuilder()
                .AddText(title)
                .AddText(message);

            if (!string.IsNullOrEmpty(iconPath))
            {
                builder.AddInlineImage(new Uri(iconPath));
            }

            builder.Show();
        }

        /// <summary>
        /// Show notification with actions
        /// </summary>
        public void ShowActionableNotification(
            string title,
            string message,
            Dictionary<string, string> actions)
        {
            var builder = new ToastContentBuilder()
                .AddText(title)
                .AddText(message);

            foreach (var action in actions)
            {
                builder.AddButton(
                    new ToastButton()
                        .SetContent(action.Key)
                        .AddArgument("action", action.Value)
                );
            }

            builder.Show();
        }

        #endregion

        #region Speech Synthesis

        /// <summary>
        /// Text-to-speech using Windows voices
        /// </summary>
        public void Speak(string text, VoiceGender gender = VoiceGender.Female)
        {
            _synthesizer.SelectVoiceByHints(gender);
            _synthesizer.SpeakAsync(text);
        }

        /// <summary>
        /// Stop speech synthesis
        /// </summary>
        public void StopSpeaking()
        {
            _synthesizer.SpeakAsyncCancelAll();
        }

        /// <summary>
        /// Get available voices
        /// </summary>
        public List<string> GetInstalledVoices()
        {
            return _synthesizer.GetInstalledVoices()
                .Select(v => v.VoiceInfo.Name)
                .ToList();
        }

        #endregion

        #region Task Scheduler

        /// <summary>
        /// Create Windows scheduled task
        /// </summary>
        public void CreateScheduledTask(
            string taskName,
            string executablePath,
            DateTime startTime,
            TimeSpan? repeatInterval = null)
        {
            using var ts = new TaskService();
            var td = ts.NewTask();

            td.RegistrationInfo.Description = $"Aether AI - {taskName}";
            
            td.Triggers.Add(new TimeTrigger
            {
                StartBoundary = startTime,
                Repetition = repeatInterval.HasValue
                    ? new RepetitionPattern(repeatInterval.Value, TimeSpan.Zero)
                    : null
            });

            td.Actions.Add(new ExecAction(executablePath));
            
            ts.RootFolder.RegisterTaskDefinition(taskName, td);
        }

        /// <summary>
        /// Delete scheduled task
        /// </summary>
        public void DeleteScheduledTask(string taskName)
        {
            using var ts = new TaskService();
            ts.RootFolder.DeleteTask(taskName, false);
        }

        /// <summary>
        /// Get all Aether AI tasks
        /// </summary>
        public List<string> GetAetherTasks()
        {
            using var ts = new TaskService();
            return ts.RootFolder.Tasks
                .Where(t => t.Name.StartsWith("Aether"))
                .Select(t => t.Name)
                .ToList();
        }

        #endregion

        #region System Information

        [DllImport("kernel32.dll")]
        private static extern void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_INFO
        {
            public ushort processorArchitecture;
            ushort reserved;
            public uint pageSize;
            public IntPtr minimumApplicationAddress;
            public IntPtr maximumApplicationAddress;
            public IntPtr activeProcessorMask;
            public uint numberOfProcessors;
            public uint processorType;
            public uint allocationGranularity;
            public ushort processorLevel;
            public ushort processorRevision;
        }

        /// <summary>
        /// Get system CPU information
        /// </summary>
        public (int cores, string architecture) GetCPUInfo()
        {
            GetSystemInfo(out var sysInfo);
            
            string arch = sysInfo.processorArchitecture switch
            {
                9 => "AMD64",
                5 => "ARM",
                12 => "ARM64",
                0 => "x86",
                _ => "Unknown"
            };

            return ((int)sysInfo.numberOfProcessors, arch);
        }

        #endregion

        #region Power Management

        [DllImport("powrprof.dll", SetLastError = true)]
        private static extern uint PowerReadFriendlyName(
            IntPtr RootPowerKey,
            ref Guid SchemeGuid,
            IntPtr SubGroupOfPowerSettingsGuid,
            IntPtr PowerSettingGuid,
            IntPtr Buffer,
            ref uint BufferSize);

        /// <summary>
        /// Prevent system sleep while processing
        /// </summary>
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern EXECUTION_STATE SetThreadExecutionState(EXECUTION_STATE esFlags);

        [FlagsAttribute]
        private enum EXECUTION_STATE : uint
        {
            ES_AWAYMODE_REQUIRED = 0x00000040,
            ES_CONTINUOUS = 0x80000000,
            ES_DISPLAY_REQUIRED = 0x00000002,
            ES_SYSTEM_REQUIRED = 0x00000001
        }

        public void PreventSleep()
        {
            SetThreadExecutionState(
                EXECUTION_STATE.ES_CONTINUOUS |
                EXECUTION_STATE.ES_SYSTEM_REQUIRED
            );
        }

        public void AllowSleep()
        {
            SetThreadExecutionState(EXECUTION_STATE.ES_CONTINUOUS);
        }

        #endregion

        #region Cleanup

        public void Dispose()
        {
            _synthesizer?.Dispose();
            _recognizer?.Dispose();
        }

        #endregion
    }

    /// <summary>
    /// Cortana voice command handler
    /// </summary>
    public class CortanaIntegration
    {
        private readonly SpeechRecognitionEngine _recognizer;

        public CortanaIntegration()
        {
            _recognizer = new SpeechRecognitionEngine();
            
            // Add Aether voice commands
            var commands = new Choices();
            commands.Add("Hey Aether");
            commands.Add("Open Aether");
            commands.Add("Aether help");
            commands.Add("Aether status");

            var gb = new GrammarBuilder();
            gb.Append(commands);

            var grammar = new Grammar(gb);
            _recognizer.LoadGrammar(grammar);

            _recognizer.SpeechRecognized += OnSpeechRecognized;
        }

        private void OnSpeechRecognized(object? sender, SpeechRecognizedEventArgs e)
        {
            Console.WriteLine($"Cortana recognized: {e.Result.Text}");
            // Handle command
        }

        public void Start()
        {
            _recognizer.SetInputToDefaultAudioDevice();
            _recognizer.RecognizeAsync(RecognizeMode.Multiple);
        }

        public void Stop()
        {
            _recognizer.RecognizeAsyncCancel();
        }
    }
}
