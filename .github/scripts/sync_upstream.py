"""Prepare an upstream release PR; never push to the protected base branch."""
import json
import os
from pathlib import Path
import re
import subprocess

# These names are the GitHub Actions job contexts, not workflow display names.
# All platform tests and code generation checks must pass before upstream auto-merge.
REQUIRED = (
    {"check-assets", "check-format-and-proto"}
    | {f"test ({system}-latest)" for system in ("ubuntu", "windows", "macos")}
    | {f"local-regression ({system}-latest)" for system in ("ubuntu", "windows", "macos")}
)


def command(*args, check=True):
    return subprocess.run(args, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def gh_json(*args):
    return json.loads(command("gh", *args).stdout)


def protected(rules):
    checks = set()
    strict = False
    for rule in rules:
        if rule.get("type") == "required_status_checks":
            params = rule.get("parameters", {})
            checks.update(item["context"] for item in params.get("required_status_checks", []))
            strict |= params.get("strict_required_status_checks_policy", False)
    return REQUIRED <= checks and strict and any(r.get("type") == "pull_request" for r in rules)


def sync(repo, upstream="XTLS/Xray-core", base="main"):
    release = gh_json("api", f"repos/{upstream}/releases/latest")
    tag = release["tag_name"]
    if release.get("draft") or release.get("prerelease") or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", tag):
        raise ValueError("Expected a stable release with a safe tag name")
    pending = gh_json("pr", "list", "--repo", repo, "--state", "open", "--limit", "100", "--json", "headRefName,url")
    if any(p["headRefName"].startswith("updates/xray-") for p in pending):
        print("An upstream update PR is already open; finish it first.")
        return
    command("git", "fetch", "--no-tags", f"https://github.com/{upstream}.git", f"refs/tags/{tag}")
    sha = command("git", "rev-parse", "FETCH_HEAD^{commit}").stdout.strip()
    ancestor = command("git", "merge-base", "--is-ancestor", sha, "HEAD", check=False)
    if ancestor.returncode == 0:
        print(f"Release {tag} is already included.")
        return
    if ancestor.returncode != 1:
        raise RuntimeError(ancestor.stderr)
    branch = f"updates/xray-{sha[:12]}"
    remote = command("git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}")
    if remote.stdout.strip():
        print("This release already has an update branch; inspect its closed PR before retrying.")
        return
    command("git", "config", "user.name", "ElXray Upstream Sync")
    command("git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
    command("git", "checkout", "-b", branch)
    result = command("git", "merge", "--no-ff", "-m", f"Merge Xray-core release {tag}", sha, check=False)
    draft = result.returncode != 0
    if draft:
        conflicts = command("git", "diff", "--name-only", "--diff-filter=U").stdout.splitlines()
        if not conflicts:
            raise RuntimeError(result.stderr or result.stdout)
        command("git", "merge", "--abort")
        marker = Path(".github/upstream-conflict.json")
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(json.dumps({"upstream": upstream, "tag": tag, "commit": sha, "conflicts": conflicts}, indent=2) + "\n")
        command("git", "add", str(marker))
        command("git", "commit", "-m", f"Record conflicts for Xray-core release {tag}")
        body = f"Upstream {tag} ({sha}) could not be merged. This draft contains ONLY a conflict record, not the update. Merge the recorded upstream commit into this branch locally, resolve conflicts, remove .github/upstream-conflict.json, and push. Run CI before marking ready.\n\nConflicting files:\n" + "\n".join(f"- `{p}`" for p in conflicts)
    else:
        # Upstream can upgrade protoc-gen-go and protoc-gen-go-grpc without knowing
        # about this fork's extra .proto files. Regenerate all tracked/new outputs
        # on the update branch *before* opening the PR, so strict CI remains useful.
        # A failure stops the update; never bypass the check or push to main.
        command("go", "run", "./infra/vprotogen/main.go", "-mode", "generate", "-pwd", "./")
        command("git", "add", "-A", "--", ":(glob)**/*.pb.go")
        staged = command("git", "diff", "--cached", "--quiet", check=False)
        if staged.returncode == 1:
            command("git", "commit", "-m", f"Regenerate Protobuf after Xray-core {tag}")
        elif staged.returncode != 0:
            raise RuntimeError(staged.stderr)
        body = f"Merge stable Xray-core release {tag}, commit {sha}, into ElXray. Regenerated local Protobuf files if needed. Existing fork commits are retained. Required CI and branch rules must pass before merging. This PR does not deploy to servers or publish a GitHub Release."
    command("git", "push", "origin", f"HEAD:refs/heads/{branch}")
    args = ["pr", "create", "--repo", repo, "--base", base, "--head", branch, "--title", f"Update Xray-core to {tag}", "--body", body]
    if draft:
        args.append("--draft")
    url = command("gh", *args).stdout.strip()
    print(url)
    if draft:
        print("Conflicts require manual resolution; auto-merge is disabled.")
        return
    try:
        rules = gh_json("api", f"repos/{repo}/rules/branches/{base}")
        if not protected(rules):
            print("::warning::Auto-merge not enabled: require PRs, all eight required status checks and up-to-date branches in an active ruleset.")
            return
        node = gh_json("pr", "view", url, "--repo", repo, "--json", "id")["id"]
        # Unlike `gh pr merge --auto`, this never falls back to an immediate merge.
        command("gh", "api", "graphql", "-f", "query=mutation($id:ID!){enablePullRequestAutoMerge(input:{pullRequestId:$id,mergeMethod:MERGE}){pullRequest{id}}}", "-f", f"id={node}")
        print("Auto-merge enabled; GitHub enforces the required checks.")
    except subprocess.CalledProcessError:
        print("::warning::Could not enable auto-merge. The update PR remains available for manual review.")


if __name__ == "__main__":
    if not os.environ.get("GH_TOKEN"):
        raise SystemExit("Configure the UPSTREAM_SYNC_TOKEN Actions secret first.")
    sync(os.environ["GITHUB_REPOSITORY"])
