"""`cloakpipe prove --sandbox e2b`: drive E2B sandboxes with the e2b SDK.

Written next to the prove report and run by `cloakpipe prove`; not meant to
be run by hand. Every path is mirrored at its host path inside the sandbox,
so the gate command prove wrote works unchanged.

    prepare SPEC   template -> install binary + agent + setup -> snapshot
    run SPEC       snapshot -> upload run dir -> run agent -> download run dir
    cleanup SPEC   delete the snapshot

The result is written as JSON to $CLOAKPIPE_E2B_RESULT. Needs E2B_API_KEY.
"""
import io
import json
import os
import shlex
import shutil
import sys
import tarfile
import tempfile

from e2b import CommandExitException, Sandbox, TimeoutException


def upload(sbx, path):
    """Mirror a host file or directory at the same path in the sandbox."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        tar.add(path, arcname=path.lstrip("/"))
    sbx.files.write("/tmp/cloakpipe-upload.tgz", buf.getvalue())
    sh(sbx, "sudo tar -xzf /tmp/cloakpipe-upload.tgz -C / && sudo chown -R \"$(id -u):$(id -g)\" %s && rm /tmp/cloakpipe-upload.tgz"
       % shlex.quote(path), 600)


MAX_DOWNLOAD = 512 * 1024 * 1024  # bytes, unpacked


def download(sbx, path):
    """Bring a sandbox directory back over the same host path.

    The archive comes from a sandbox the agent controls, so it is untrusted:
    only regular files and directories under `path` are taken (no links,
    devices or `..`), unpacked into a fresh directory first, size-capped,
    then copied into place.
    """
    rel = path.lstrip("/")
    sh(sbx, "tar -czf /tmp/cloakpipe-download.tgz -C / %s" % shlex.quote(rel), 600)
    data = sbx.files.read("/tmp/cloakpipe-download.tgz", format="bytes")
    with tarfile.open(fileobj=io.BytesIO(bytes(data)), mode="r:gz") as tar, tempfile.TemporaryDirectory() as tmp:
        total = 0
        for m in tar.getmembers():
            parts = m.name.split("/")
            if not (m.name == rel or m.name.startswith(rel + "/")) or ".." in parts or not (m.isfile() or m.isdir()):
                continue
            total += m.size
            if total > MAX_DOWNLOAD:
                raise RuntimeError("the run directory came back larger than %d bytes" % MAX_DOWNLOAD)
            dest = os.path.join(tmp, *parts)
            if m.isdir():
                os.makedirs(dest, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            src = tar.extractfile(m)
            with open(dest, "wb") as out:
                shutil.copyfileobj(src, out)
        staged = os.path.join(tmp, *rel.split("/"))
        if os.path.isdir(staged):
            shutil.copytree(staged, path, dirs_exist_ok=True, symlinks=False)


def sh(sbx, cmd, timeout, **kw):
    return sbx.commands.run(cmd, timeout=timeout, **kw)


def prepare(spec):
    sbx = Sandbox.create(template=spec["template"], timeout=1800)
    try:
        exe = spec["exe"]
        sh(sbx, "sudo mkdir -p %s" % shlex.quote(os.path.dirname(exe)), 60)
        upload(sbx, exe)
        for path in spec["upload"]:
            upload(sbx, path)
        if spec.get("setup"):
            sh(sbx, spec["setup"], 1500, cwd=spec["upload"][0])
        sh(sbx, "%s --version" % shlex.quote(exe), 60)
        info = sbx.create_snapshot()
        return {"snapshot": info.snapshot_id}
    finally:
        sbx.kill()


def run(spec):
    timeout = int(spec["timeout"])
    sbx = Sandbox.create(spec["snapshot"], timeout=timeout + 600)
    try:
        run_dir = spec["run_dir"]
        upload(sbx, run_dir)
        cmd = "cd %s && %s > %s 2> %s" % (
            shlex.quote(spec["cwd"]),
            " ".join(shlex.quote(c) for c in spec["command"]),
            shlex.quote(os.path.join(run_dir, "agent.out")),
            shlex.quote(os.path.join(run_dir, "agent.err")),
        )
        env = dict(spec["env"], HOME=os.path.join(run_dir, "home"))
        result = {"exit": 0, "timed_out": False}
        try:
            sh(sbx, cmd, timeout, envs=env)
        except CommandExitException as e:
            result["exit"] = getattr(e, "exit_code", 1)
        except TimeoutException:
            result = {"exit": None, "timed_out": True}
        download(sbx, run_dir)
        return result
    finally:
        sbx.kill()


def cleanup(spec):
    return {"deleted": bool(Sandbox.delete_snapshot(spec["snapshot"]))}


def main():
    mode, spec_path = sys.argv[1], sys.argv[2]
    with open(spec_path) as f:
        spec = json.load(f)
    result = {"prepare": prepare, "run": run, "cleanup": cleanup}[mode](spec)
    with open(os.environ["CLOAKPIPE_E2B_RESULT"], "w") as f:
        json.dump(result, f)


if __name__ == "__main__":
    main()
