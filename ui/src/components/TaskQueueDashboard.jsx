import './TaskQueueDashboard.css';
import LanguageStatusHUD from './LanguageStatusHUD';

/**
 * Task Queue Dashboard (Upgrade #14: Task Queue Dashboard)
 * 
 * Real-time dashboard showing:
 * - Active God Mode tasks with step progress
 * - Bug bounty hunt status
 * - Bugs found counter
 * - Live narration text
 * 
 * Reads `hud_update` messages from the backend via WebSocket/IPC.
 */

const TaskQueueDashboard = ({ hudState = null, isVisible = true }) => {
    const [tasks, setTasks] = useState([]);
    const [latestNarration, setLatestNarration] = useState('');
    const [bugsFound, setBugsFound] = useState(0);
    const [scanProgress, setScanProgress] = useState(0);
    const [currentStatus, setCurrentStatus] = useState('idle');
    const [currentLanguage, setCurrentLanguage] = useState('en');
    const narrationRef = useRef(null);

    // Listen for HUD updates from parent App or IPC
    useEffect(() => {
        if (hudState) {
            handleHudUpdate(hudState);
        }
    }, [hudState]);

    // Also listen for IPC messages from Electron backend
    useEffect(() => {
        const handleIpcMessage = (event, data) => {
            if (data?.type === 'hud_update') {
                handleHudUpdate(data);
            }
        };

        if (window.electron?.ipcRenderer) {
            window.electron.ipcRenderer.on('aether-status', handleIpcMessage);
            return () => {
                window.electron.ipcRenderer.removeListener('aether-status', handleIpcMessage);
            };
        }
    }, []);

    const handleHudUpdate = (data) => {
        if (!data) return;

        if (data.narration) {
            setLatestNarration(data.narration);
        }
        if (data.bugs_found !== undefined) {
            setBugsFound(data.bugs_found);
        }
        if (data.status) {
            setCurrentStatus(data.status);
        }
        if (data.language) {
            setCurrentLanguage(data.language);
        }
        if (data.task) {
            setTasks(prev => {
                const existing = prev.findIndex(t => t.task_id === data.task_id);
                const updated = {
                    task_id: data.task_id || `task_${Date.now()}`,
                    name: data.task || 'Running Task',
                    step: data.step || 0,
                    total: data.total || 0,
                    status: data.status || 'executing',
                    narration: data.narration || '',
                    bugs: data.bugs_found || 0,
                };
                if (existing >= 0) {
                    const next = [...prev];
                    next[existing] = updated;
                    return next;
                }
                return [...prev.slice(-4), updated]; // Keep last 5 tasks
            });
        }
        if (data.scan_progress !== undefined) {
            setScanProgress(data.scan_progress);
        }
    };

    if (!isVisible || currentStatus === 'idle') return null;

    const getStatusColor = (status) => {
        const colors = {
            executing: '#00d4ff',
            complete: '#00ff88',
            error: '#ff4444',
            bug_found: '#ff8c00',
            thinking: '#a855f7',
            narrating: '#00d4ff',
        };
        return colors[status] || '#fff';
    };

    const getStatusIcon = (status) => {
        const icons = {
            executing: '⚡',
            complete: '✅',
            error: '❌',
            bug_found: '🚨',
            thinking: '🧠',
            narrating: '🔊',
        };
        return icons[status] || '•';
    };

    return (
        <div className="task-dashboard" id="task-queue-dashboard">
            {/* Header */}
            <div className="dashboard-header">
                <div className="header-left">
                    <span className="jarvis-logo">⚡ AETHER</span>
                    <span className="status-badge" style={{ color: getStatusColor(currentStatus) }}>
                        {getStatusIcon(currentStatus)} {currentStatus.toUpperCase()}
                    </span>
                </div>
                {bugsFound > 0 && (
                    <div className="bugs-badge">
                        🐛 {bugsFound} Bug{bugsFound !== 1 ? 's' : ''} Found
                    </div>
                )}
            </div>

            {/* Live narration */}
            {latestNarration && (
                <div className="narration-bar" ref={narrationRef}>
                    <span className="narration-icon">🔊</span>
                    <span className="narration-text">{latestNarration}</span>
                </div>
            )}

            {/* Active tasks */}
            <div className="task-list">
                {tasks.map((task) => (
                    <div
                        key={task.task_id}
                        className={`task-item ${task.status === 'complete' ? 'task-complete' : ''} ${task.status === 'error' ? 'task-error' : ''}`}
                    >
                        <div className="task-header">
                            <span className="task-status-icon">{getStatusIcon(task.status)}</span>
                            <span className="task-name">{task.name}</span>
                            {task.total > 0 && (
                                <span className="task-step-count">{task.step}/{task.total}</span>
                            )}
                        </div>

                        {/* Progress bar */}
                        {task.total > 0 && (
                            <div className="task-progress-bar">
                                <div
                                    className="task-progress-fill"
                                    style={{
                                        width: `${(task.step / task.total) * 100}%`,
                                        backgroundColor: getStatusColor(task.status),
                                    }}
                                />
                            </div>
                        )}

                        {task.narration && (
                            <div className="task-narration">{task.narration}</div>
                        )}
                    </div>
                ))}
            </div>

            {/* Scan progress bar (for bug bounty) */}
            {scanProgress > 0 && scanProgress < 100 && (
                <div className="scan-progress">
                    <span className="scan-label">🕷️ Scan Progress</span>
                    <div className="scan-bar">
                        <div className="scan-fill" style={{ width: `${scanProgress}%` }} />
                    </div>
                    <span className="scan-pct">{scanProgress}%</span>
                </div>
            )}

            {/* Language & Reasoning Status */}
            <LanguageStatusHUD language={currentLanguage} status={currentStatus} />
        </div>
    );
};

export default TaskQueueDashboard;
