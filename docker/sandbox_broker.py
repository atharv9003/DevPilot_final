"""Internal broker: run uploaded test inputs in disposable Docker containers."""
import base64
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock

JOBS = Path('/jobs')
TOKEN = os.environ['SANDBOX_BROKER_TOKEN']
VOLUME = 'devpilot_sandbox_jobs'
IMAGE = 'devpilot-sandbox:latest'
CPP_IMAGE = 'devpilot-cpp-sandbox:latest'
RUN_LOCK = Lock()


class Handler(BaseHTTPRequestHandler):
    def _reply(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != '/health':
            self._reply(404, {})
            return
        try:
            ready = (
                subprocess.run(['docker', 'info'], capture_output=True, timeout=5).returncode == 0
                and subprocess.run(['docker', 'image', 'inspect', IMAGE], capture_output=True, timeout=5).returncode == 0
            )
        except Exception:
            ready = False
        self._reply(200 if ready else 503, {'status': 'ready' if ready else 'unavailable'})

    def do_POST(self):
        if self.path != '/run' or self.headers.get('Authorization') != f'Bearer {TOKEN}':
            self._reply(403, {'error': 'Forbidden'})
            return
        # A single read-only volume holds staged inputs. Serialize jobs so one
        # untrusted container cannot inspect another job's files.
        with RUN_LOCK:
            self._run_job()

    def _run_job(self):
        job = JOBS / uuid.uuid4().hex
        container_name = f'devpilot-sandbox-{job.name}'
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if length < 1 or length > 8_000_000:
                raise ValueError('Invalid request size')
            request = json.loads(self.rfile.read(length))
            raw = base64.b64decode(request['archive'], validate=True)
            args = request['args']
            image = request.get('image', IMAGE)
            if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
                raise ValueError('Invalid test command')
            verifier = (len(args) == 5 and args[:4] == ['python', '-I', '-B', '/workspace/verifier.py']
                        and args[4].startswith('/workspace/source/'))
            pytest_run = (args[:7] == ['python', '-m', 'pytest', '-v', '--no-header', '-p', 'no:cacheprovider']
                          and (len(args) == 7 or (len(args) == 9 and args[7] == '--')))
            cpp_run = args == ['sh', '-c', 'g++ -std=c++17 test_runner.cpp -o /tmp/test_bin && /tmp/test_bin']
            if not ((image == IMAGE and (verifier or pytest_run)) or (image == CPP_IMAGE and cpp_run)):
                raise ValueError('Unsupported sandbox image or verification command')
            job.mkdir(mode=0o755)
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                members = archive.infolist()
                if len(members) > 1000 or sum(member.file_size for member in members) > 20_000_000:
                    raise ValueError('Input archive too large')
                for member in members:
                    name = Path(member.filename)
                    if name.is_absolute() or '..' in name.parts or member.is_dir() or not member.filename:
                        raise ValueError('Invalid archive path')
                    target = job / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(member) as source, target.open('wb') as dest:
                        shutil.copyfileobj(source, dest)
            inner = f'/jobs/{job.name}'
            mapped = [arg.replace('/workspace/', inner + '/') for arg in args]
            cmd = [
                'docker', 'run', '--rm', '--network', 'none', '--read-only',
                '--name', container_name,
                '--security-opt', 'no-new-privileges', '--cap-drop=ALL',
                '--pids-limit', '128', '-m', '512m', '--cpus=1',
                '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m',
                '--mount', f'type=volume,source={VOLUME},target=/jobs,readonly',
                '-w', inner, image, *mapped,
            ]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True, timeout=5)
                raise TimeoutError('Sandbox run timed out after 60 seconds')
            self._reply(200, {'exit_code': result.returncode, 'stdout': result.stdout[-100000:], 'stderr': result.stderr[-100000:]})
        except Exception as exc:
            self._reply(400, {'exit_code': -1, 'stdout': '', 'stderr': str(exc)})
        finally:
            shutil.rmtree(job, ignore_errors=True)


if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', 8750), Handler).serve_forever()
