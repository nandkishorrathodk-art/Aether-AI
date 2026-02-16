import { spawn, ChildProcess } from 'child_process';
import { EventEmitter } from 'events';

export class PythonBridge extends EventEmitter {
    private pythonProcess: ChildProcess | null = null;

    constructor() {
        super();
    }

    start() {
        // Path to python executable (use venv if available)
        // Assuming running from root
        const pythonPath = process.platform === 'win32'
            ? 'venv\\Scripts\\python.exe'
            : 'venv/bin/python';

        const scriptPath = 'src/main.py';

        console.log(`Starting Python Bridge: ${pythonPath} ${scriptPath}`);

        this.pythonProcess = spawn(pythonPath, [scriptPath], {
            cwd: process.cwd(),
            stdio: ['pipe', 'pipe', 'pipe']
        });

        this.pythonProcess.stdout?.on('data', (data) => {
            const message = data.toString();
            this.emit('message', message);

            // Try to parse JSON messages from Python
            try {
                const json = JSON.parse(message);
                this.emit('json', json);
            } catch (e) {
                // Not JSON, just plain text log
                this.emit('log', message);
            }
        });

        this.pythonProcess.stderr?.on('data', (data) => {
            this.emit('error', data.toString());
        });

        this.pythonProcess.on('close', (code) => {
            console.log(`Python process exited with code ${code}`);
            this.emit('exit', code);
        });
    }

    sendCommand(command: string, args: any = {}) {
        if (this.pythonProcess && this.pythonProcess.stdin) {
            const payload = JSON.stringify({ command, ...args }) + '\n';
            this.pythonProcess.stdin.write(payload);
        } else {
            console.error("Python process not running");
        }
    }

    stop() {
        if (this.pythonProcess) {
            this.pythonProcess.kill();
        }
    }
}
