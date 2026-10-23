"""Build and validate the owned Windows Python protection/recovery case."""
import argparse
import base64
import compileall
import hashlib
from html import escape
import io
import json
import os
from pathlib import Path
import random
import shutil
import statistics
import subprocess
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "cases/python-protection"
SCRIPTS = ROOT / "skills/python-leakage-audit/scripts"
CORPUS = ["MeridianMixer", "MeridianInputError", "MERIDIAN_PRIVATE_INPUT_LIMIT", "MERIDIAN_RESOURCE_PRIVATE_MODEL"]
HEADER = b"ANTI-REA-PY-AES1\0"


class Trial:
    def __init__(self, args):
        self.args = args
        self.root = args.out.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.state_path = self.root / "result.json"
        self.state = json.loads(self.state_path.read_text()) if self.state_path.exists() else dict(
            schema=1, status="in-progress", profiles={}, checks=[], commands=[],
            recovery_model="Release-input isolation; analyst knows case design, not an independent blind trial.",
            analysis_budget_seconds=900, corpus=CORPUS)
        self.env = dict(os.environ)
        self.env.pop("PYTHONPATH", None)
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.env["PYTHONHASHSEED"] = "0"

    def save(self):
        self.state_path.write_text(json.dumps(self.state, indent=2), encoding="utf-8")

    def assert_packages(self):
        for name, profile in self.state["profiles"].items():
            if "artifacts" in profile:
                self.check(name + " final release hashes unchanged", inventory(self.root / "packages" / name) == profile["artifacts"])

    def run(self, command, cwd=None, input=None, timeout=120, allowed=(0,), native=False):
        command = list(map(str, command))
        original = command[:]
        if native:
            import subprocess as sp
            # The generated batch contains only operator-selected paths and argv.
            batch = self.root / "private" / "build-native.cmd"
            batch.parent.mkdir(exist_ok=True)
            linker_bin = self.args.environment.parent / "compiler/latest/bin/compiler"
            if not (linker_bin / "lld-link.exe").exists():
                raise ValueError("Nuitka clang mode requires lld-link; expected Intel compiler linker directory")
            batch.write_text('@echo off\ncall "' + str(self.args.environment) + '" >nul\n' +
                             'set "PATH=' + str(self.args.llvm_bin) + ';' + str(linker_bin) + ';%PATH%"\n' +
                             'clang-cl --version\nlld-link --version\n' +
                             sp.list2cmdline(command) + '\nexit /b %errorlevel%\n', encoding="utf-8")
            command = [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(batch)]
        number = len(self.state["commands"])
        log = self.root / ("command-%04d.log" % number)
        start = time.perf_counter()
        try:
            process = subprocess.Popen(command, cwd=cwd or self.root, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, encoding="utf-8", errors="replace", env=self.env)
            try:
                stdout, stderr = process.communicate(input=input, timeout=timeout)
            except subprocess.TimeoutExpired:
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=15)
                process.communicate(timeout=15)
                raise
            run = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
            result = dict(command=original, cwd=str(cwd or self.root), seconds=time.perf_counter()-start,
                          returncode=run.returncode, log=log.name)
            log.write_text(run.stdout + "\n--- STDERR ---\n" + run.stderr, encoding="utf-8")
            self.state["commands"].append(result)
            self.save()
            if allowed is not None and run.returncode not in allowed:
                raise RuntimeError("command failed: " + str(original) + "; see " + str(log))
            return run, result["seconds"]
        except subprocess.TimeoutExpired as error:
            self.state["commands"].append(dict(command=original, timeout=timeout, log=log.name))
            log.write_text(str(error), encoding="utf-8")
            self.save()
            raise

    def check(self, name, passed, **details):
        self.state["checks"].append(dict(name=name, passed=bool(passed), **details))
        self.save()
        if not passed:
            raise AssertionError(name)

    def build(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        source = self.root / "source"
        if source.exists():
            raise ValueError("build requires a fresh output directory; use another phase to resume")
        shutil.copytree(CASE, source, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "requirements.txt", "sealed_bootstrap.py"))
        self.state["source_hashes"] = inventory(source)
        run, _ = self.run([sys.executable, "-m", "pip", "freeze"])
        self.state["versions"] = run.stdout.splitlines()
        self.state["python"] = sys.version
        self.state["python_executable"] = sys.executable
        packages = self.root / "packages"
        packages.mkdir()
        for name in ("source", "pyc", "aes", "pyinstaller", "pyarmor", "nuitka"):
            self.state["profiles"][name] = dict(status="building")
            self.save()
            start = time.perf_counter()
            package = packages / name
            if name in {"source", "pyc"}:
                shutil.copytree(source, package)
                if name == "pyc":
                    self.check("compile pyc", compileall.compile_dir(package, quiet=2, legacy=True,
                        ddir="/private/python-protection", force=True))
                    for path in package.rglob("*.py"):
                        path.unlink()
            elif name == "aes":
                package.mkdir()
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    for path in source.rglob("*"):
                        if path.is_file():
                            archive.writestr(path.relative_to(source).as_posix(), path.read_bytes())
                key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
                private = self.root / "private"
                private.mkdir(exist_ok=True)
                (private / "aes-key.bin").write_bytes(key)
                (package / "payload.aes").write_bytes(HEADER + nonce + AESGCM(key).encrypt(nonce, buffer.getvalue(), HEADER))
                (package / "runtime.json").write_text(json.dumps(dict(key=base64.b64encode(key).decode())), encoding="utf-8")
                shutil.copy2(CASE / "sealed_bootstrap.py", package / "main.py")
            elif name == "pyinstaller":
                _, seconds = self.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile",
                    "--name", "python-demo", "--distpath", package, "--workpath", self.root / "build-pyinstaller",
                    "--specpath", self.root / "private", "--paths", source,
                    "--hidden-import", "probeapp.plugins.twist", "--hidden-import", "probeapp.plugins.identity",
                    "--add-data", str(source / "probeapp/resources") + ";probeapp/resources", source / "main.py"], timeout=900)
            elif name == "pyarmor":
                result, _ = self.run([sys.executable, "-m", "pyarmor.cli", "gen", "-r", "-O", package,
                                     source / "main.py", source / "probeapp"], cwd=source, timeout=300, allowed=(0,1,2))
                if result.returncode:
                    self.state["profiles"][name] = dict(status="unavailable", reason="Official trial generation failed; see command log")
                    continue
                shutil.copytree(source / "probeapp/resources", package / "probeapp/resources", dirs_exist_ok=True)
            elif name == "nuitka":
                self.run([sys.executable, "-m", "nuitka", "--standalone", "--clang", "--msvc=latest",
                    "--jobs=" + str(self.args.jobs), "--assume-yes-for-downloads", "--include-package=probeapp",
                    "--include-data-dir=" + str(source / "probeapp/resources") + "=probeapp/resources",
                    "--output-dir=" + str(self.root / "build-nuitka"), "--output-filename=python-demo.exe",
                    "--report=" + str(self.root / "private/nuitka-report.xml"), source / "main.py"],
                    cwd=source, timeout=1800, native=True)
                shutil.copytree(self.root / "build-nuitka/main.dist", package)
            command = [str(package / "python-demo.exe")] if name in {"pyinstaller", "nuitka"} else [sys.executable, "-B", str(package / ("main.pyc" if name == "pyc" else "main.py"))]
            self.state["profiles"][name] = dict(status="built", command=command, build_seconds=time.perf_counter()-start,
                                               artifacts=inventory(package), package_bytes=sum(p.stat().st_size for p in package.rglob("*") if p.is_file()))
            self.save()
        self.state["status"] = "built"
        self.save()

    def requests(self):
        path = self.root / "private/inputs.json"
        if path.exists():
            return json.loads(path.read_text())
        rng = random.Random(0x20261023)
        cases = [dict(values=[rng.randrange(-2**40, 2**40) for _ in range(rng.randrange(0, 40))],
                      seed=rng.randrange(-2**48, 2**48), plugin=rng.choice(["identity", "twist"])) for _ in range(256)]
        cases += [dict(values=[]), dict(values=[0, -1, 2**32-1, 2**100], seed=-2**100),
                  dict(values=[0]*4096), dict(values=[0]*4097), dict(values=True),
                  dict(values=[True]), dict(values=[1], seed="bad"), dict(values=[1], plugin="missing"), {}]
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(cases), encoding="utf-8")
        return cases

    def verify(self):
        cases = self.requests()
        data = ''.join(json.dumps(case) + '\n' for case in cases)
        baseline, _ = self.run(self.state["profiles"]["source"]["command"], input=data)
        expected = [json.loads(line)["answer"] for line in baseline.stdout.splitlines()]
        self.check("baseline response count", len(expected) == len(cases))
        (self.root / "private/answers.json").write_text(json.dumps(expected), encoding="utf-8")
        for name, profile in self.state["profiles"].items():
            if profile["status"] == "unavailable":
                continue
            package = self.root / "packages" / name
            self.check(name + " immutable package before execution", inventory(package) == profile["artifacts"])
            run, _ = self.run(profile["command"], input=data)
            answers = [json.loads(line)["answer"] for line in run.stdout.splitlines()]
            self.check(name + " original behavior", answers == expected, cases=len(cases))
            moved = self.root / "relocated" / name
            if not moved.exists():
                shutil.copytree(package, moved)
            command = [s.replace(str(package), str(moved)) for s in profile["command"]]
            run, _ = self.run(command, cwd=self.root / "private", input=data)
            self.check(name + " relocated package", [json.loads(line)["answer"] for line in run.stdout.splitlines()] == expected)
            profile["behavior"] = "passed"
            package_files = list(package.rglob("*"))
            self.check(name + " private artifact isolation", not any(p.suffix.lower() in {".pdb", ".log"} or p.name in {"aes-key.bin", "inputs.json", "answers.json"} for p in package_files))
            self.save()
        aes = self.root / "packages/aes"
        envelope = (aes / "payload.aes").read_bytes()
        for mode in ("tag", "header", "truncated", "wrong-key"):
            broken = self.root / "negative" / mode
            shutil.copytree(aes, broken)
            if mode == "wrong-key":
                (broken / "runtime.json").write_text(json.dumps(dict(key=base64.b64encode(bytes(32)).decode())))
            else:
                body = bytearray(envelope)
                if mode == "truncated":
                    body = body[:20]
                else:
                    body[-1 if mode == "tag" else 0] ^= 1
                (broken / "payload.aes").write_bytes(body)
            run, _ = self.run([sys.executable, "-B", broken / "main.py"], input=data[:data.find('\n')+1], allowed=(1,))
            self.check("AES rejects " + mode + " before target output", not run.stdout.strip())
        self.state["status"] = "verified"
        self.save()

    def analyze(self):
        for name, profile in self.state["profiles"].items():
            if profile["status"] == "unavailable":
                continue
            start = time.perf_counter()
            prefix = self.root / self.args.analysis_label / name
            profile["analysis_dir"] = prefix.relative_to(self.root).as_posix()
            package = self.root / "packages" / name
            command = [sys.executable, SCRIPTS / "audit.py", "--package", package, "--out", prefix / "release"]
            for word in CORPUS:
                command += ["--deny", word]
            if name != "source":
                command += ["--baseline", self.root / self.args.analysis_label / "source/release.json"]
            self.run(command, timeout=90, allowed=(0,2))
            if name in {"pyc", "aes", "pyarmor", "source"}:
                entry = package / ("main.pyc" if name == "pyc" else "main.py")
                capture = [sys.executable, SCRIPTS / "capture.py", "--entry", entry,
                    "--module-prefix", "probeapp", "--out", prefix / "captured", "--execute"]
                if name != "pyarmor":
                    capture.append("--dump-code")
                run, _ = self.run(capture, input=json.dumps(dict(values=[1,2,3], seed=7))+'\n', timeout=30, allowed=None)
                profile["capture_returncode"] = run.returncode
                if (prefix / "captured").exists():
                    runtime_audit = [sys.executable, SCRIPTS / "audit.py", "--package", prefix / "captured", "--out", prefix / "runtime"]
                    for word in CORPUS:
                        runtime_audit += ["--deny", word]
                    self.run(runtime_audit, timeout=90, allowed=(0,2))
            if name == "aes":
                # This countertest reads only decryption material shipped in the release.
                script = ("import base64,json,sys; from pathlib import Path; "
                          "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; "
                          "p=Path(sys.argv[1]); b=(p/'payload.aes').read_bytes(); h=b'ANTI-REA-PY-AES1\\0'; "
                          "k=base64.b64decode(json.loads((p/'runtime.json').read_text())['key']); "
                          "Path(sys.argv[2]).write_bytes(AESGCM(k).decrypt(b[len(h):len(h)+12],b[len(h)+12:],h))")
                self.run([sys.executable, "-c", script, package, prefix / "decrypted.zip"])
                self.run([sys.executable, SCRIPTS / "extract.py", "--input", prefix / "decrypted.zip", "--out", prefix / "decrypted"])
            if name == "pyinstaller":
                extracted = prefix / "carchive"
                self.run([sys.executable, SCRIPTS / "extract.py", "--input", package / "python-demo.exe", "--out", extracted], timeout=30)
                pyz = next(extracted.glob("*.pyz"))
                self.run([sys.executable, SCRIPTS / "extract.py", "--input", pyz, "--out", prefix / "pyz"], timeout=30)
                self.run([sys.executable, SCRIPTS / "audit.py", "--package", prefix / "pyz/probeapp", "--out", prefix / "extracted"], timeout=90, allowed=(0,2))
            profile["automated_analysis_seconds"] = time.perf_counter() - start
            self.check(name + " automated analysis within budget", profile["automated_analysis_seconds"] < 900)
            self.save()

    def recover(self):
        if not self.args.recovery_manifest:
            raise ValueError("recover phase requires --recovery-manifest")
        manifest = json.loads(self.args.recovery_manifest.read_text(encoding="utf-8"))
        expected = json.loads((self.root / "private/answers.json").read_text())
        data = ''.join(json.dumps(case)+'\n' for case in self.requests())
        for name, recovery in manifest["profiles"].items():
            allowed_roots = [self.root / "analysis", self.root / "packages", *[
                self.root / p["analysis_dir"] for p in self.state["profiles"].values() if "analysis_dir" in p]]
            for evidence in recovery["evidence"]:
                path = Path(evidence["path"]).resolve()
                if not any(path.is_relative_to(root) for root in allowed_roots):
                    raise ValueError("recovery evidence must be release or analysis artifacts")
                if hashlib.sha256(path.read_bytes()).hexdigest() != evidence["sha256"]:
                    raise ValueError("recovery evidence fingerprint changed")
            command = recovery["command"]
            self.check(name + " recovery command excludes source/private tree", not any(
                str(self.root / "source") in arg or str(self.root / "private") in arg for arg in command))
            run, _ = self.run(command, input=data)
            answers = [json.loads(line)["answer"] for line in run.stdout.splitlines()]
            self.check(name + " recovered implementation matches private cases", answers == expected, cases=len(expected))
            self.state["profiles"][name]["recovery"] = dict(status="validated-for-tested-domain", cases=len(expected),
                kind=recovery["kind"], evidence=recovery["evidence"], command=command,
                implementation_sha256=hashlib.sha256(Path(command[-1]).read_bytes()).hexdigest())
            self.save()

    def measure(self):
        workload = dict(values=list(range(4096)), seed=123, _benchmark=True)
        data = json.dumps(workload)+'\n'
        for name, profile in self.state["profiles"].items():
            if profile["status"] == "unavailable":
                continue
            times, internal, compute = [], [], []
            for i in range(self.args.samples + self.args.warmups + 1):
                run, seconds = self.run(profile["command"], input=data)
                answer = json.loads(run.stdout)
                if i == 0:
                    profile["first_measured_startup_ms"] = seconds * 1000
                elif i > self.args.warmups:
                    times.append(seconds * 1000)
                    internal.append(answer["elapsed_ns"]/1e6)
                    compute.append(answer["answer"]["transform_ns"]/1e6)
            profile["timing"] = dict(samples=self.args.samples, warmups=self.args.warmups,
                wall_ms=times, internal_ms=internal, median_wall_ms=statistics.median(times),
                min_wall_ms=min(times), max_wall_ms=max(times), median_internal_ms=statistics.median(internal),
                transform_ms=compute, median_transform_ms=statistics.median(compute),
                note="Wall includes startup; internal includes resources/plugin; transform excludes both. No OS or compiler cache flush.")
            self.save()

    def summarize(self, phase):
        rows = []
        for name, profile in self.state["profiles"].items():
            analysis_dir = profile.get("analysis_dir", "analysis/" + name)
            report_path = self.root / analysis_dir / "release.json"
            report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
            hits = sorted({v["value"] for v in report.get("findings", []) if v["category"] == "corpus"})
            timing = profile.get("timing", {})
            links = []
            for stem in ("release", "runtime", "extracted"):
                if (report_path.parent / (stem + ".html")).exists():
                    links.append('<a href="' + escape(analysis_dir, quote=True) + '/' + stem + '.html">' + stem + '</a>')
            recovery = profile.get("recovery", {})
            rows.append('<tr><th>' + name + '</th><td>' + escape(profile.get("behavior", profile["status"])) +
                        '</td><td>' + escape(', '.join(hits) or "No selected raw hits") + '</td><td>' +
                        escape(recovery.get("kind", "No validated reconstruction")) + '</td><td>' +
                        str(profile.get("package_bytes", "?")) + '</td><td>' +
                        ('%.3f' % timing["median_wall_ms"] if timing else '?') + '</td><td>' + ' / '.join(links) + '</td></tr>')
        text = '''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Python 攻防验收</title>
<style>body{font:14px/1.6 'Segoe UI','Microsoft YaHei',sans-serif;color:#253037;max-width:1500px;margin:24px auto;padding:0 16px;letter-spacing:0}h1{font-size:24px}h2{font-size:18px}table{border-collapse:collapse;width:100%}td,th{text-align:left;vertical-align:top;border-bottom:1px solid #ccd5d8;padding:10px;overflow-wrap:anywhere}a{color:#08746f}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f2f5f6;padding:14px}.table{overflow:auto}</style>
<h1>Python 攻防验收</h1><p>''' + escape(self.state["recovery_model"]) + '''</p><div class="table"><table><thead><tr><th>方案</th><th>运行</th><th>原始字节命中</th><th>恢复证据</th><th>包字节数</th><th>启动中位 ms</th><th>泄露定位</th></tr></thead><tbody>''' + ''.join(rows) + '''</tbody></table></div><h2>解释边界</h2><p>15 分钟是每方案分析上限，未恢复不代表不可破解。恢复验真覆盖 256 组固定随机输入及 9 组边界/错误用例，不证明全部 Python 行为。包体积未统一包含解释器：源码、pyc、AES、PyArmor 依赖外部 Python，AES 还依赖 cryptography。首次测量未清空操作系统缓存；内部时间包含资源和插件加载，不能当成纯算法耗时。</p><h2>恢复记录</h2><pre>''' + escape(json.dumps({n: p.get("recovery", {}) for n,p in self.state["profiles"].items()}, ensure_ascii=False, indent=2)) + '</pre><h2>命令与检查</h2><p><a href="result.json">完整 JSON 记录</a> / <a href="recovery-manifest.json">恢复输入清单</a></p></html>'
        (self.root / ("summary-" + phase + ".html")).write_text(text, encoding="utf-8")


def inventory(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*")) if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--phase", choices=("build", "verify", "analyze", "measure", "recover", "all"), default="all")
    parser.add_argument("--recovery-manifest", type=Path)
    parser.add_argument("--analysis-label", default="analysis", help="New analysis revision directory within the run")
    parser.add_argument("--llvm-bin", type=Path, default=Path("F:/Program_Professional/xollvm-windows-llvm23-Release/bin"))
    parser.add_argument("--environment", type=Path, default=Path("F:/Intel/oneAPI/setvars.bat"))
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--samples", type=int, default=11)
    parser.add_argument("--warmups", type=int, default=3)
    args = parser.parse_args()
    if os.name != "nt" or sys.version_info[:2] != (3,12):
        parser.error("the native acceptance case requires Windows Python 3.12")
    if not 1 <= args.jobs <= 8 or args.samples < 1 or args.warmups < 0:
        parser.error("jobs 1..8, positive samples and nonnegative warmups required")
    if not args.analysis_label or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in args.analysis_label):
        parser.error("analysis-label must be a simple directory name")
    destination = args.out.resolve()
    if destination.is_relative_to(ROOT) or ROOT.is_relative_to(destination):
        parser.error("private run directory must be outside and must not contain the checkout")
    trial = Trial(args)
    try:
        for phase in ("build", "verify", "analyze", "measure"):
            if args.phase in (phase, "all"):
                getattr(trial, phase)()
        if args.phase == "recover":
            trial.recover()
        trial.assert_packages()
        trial.state.setdefault("phase_history", []).append(dict(phase=args.phase,
            validator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            analysis_tools=inventory(SCRIPTS)))
        trial.summarize(args.phase)
        trial.state["status"] = "completed" if args.phase == "all" else args.phase + "-completed"
        trial.save()
        print(json.dumps(dict(status=trial.state["status"], checks=len(trial.state["checks"]))))
    except Exception as error:
        trial.state["status"] = "failed"
        trial.state["error"] = str(error)
        trial.save()
        raise


if __name__ == "__main__":
    main()
