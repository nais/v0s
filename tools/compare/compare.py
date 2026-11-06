#!/usr/bin/env python3
"""Compare v0s and v13s findings per workload in one cluster.

Both APIs are reached through port-forwards (v0s on :15051, v13s on :13001) with
Google ID tokens in /tmp/v0s-tok and /tmp/v13s-tok. Writes compare-out/*.json and
prints a summary. Read-only.
"""
import json, os, re, subprocess, sys, urllib.parse
from collections import Counter, defaultdict

CLUSTER = sys.argv[1] if len(sys.argv) > 1 else "dev"
GRPCURL = "/tmp/bin/grpcurl"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "compare-out")
V13S_PROTO = ["-import-path", "/tmp/v13s-proto", "-proto", "vulnerabilities.proto"]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def call(addr, token, method, req, proto=()):
    out = subprocess.run(
        [GRPCURL, "-plaintext", "-emit-defaults", "-max-msg-sz", str(64 << 20), *proto,
         "-H", f"authorization: Bearer {token}", "-d", json.dumps(req), addr, method],
        capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"{method} {req}: {out.stderr.strip()}")
    return json.loads(out.stdout or "{}")


def v0s(method, req):
    return call("localhost:15051", open("/tmp/v0s-tok").read().strip(), f"v0s.v1.{method}", req)


def v13s(method, req):
    return call("localhost:13001", open("/tmp/v13s-tok").read().strip(),
                f"v13s.api.protobuf.Vulnerabilities/{method}", req, V13S_PROTO)


def package_key(purl):
    """pkg:type/ns/name@version?q#s -> pkg:type/ns/name, with %40 decoded."""
    p = purl.split("#", 1)[0].split("?", 1)[0]
    head, _, rest = p.partition("/")
    name = rest.rsplit("@", 1)[0] if "@" in rest.rsplit("/", 1)[-1] else rest
    return f"{head.lower()}/{urllib.parse.unquote(name)}"


def digest_of(ref):
    out = subprocess.run([os.path.expanduser("~/.local/share/mise/installs/crane/0.22/crane"), "digest", ref],
                         capture_output=True, text=True,
                         env={**os.environ, "DOCKER_CONFIG": os.environ.get("CRANE_DOCKER_CONFIG", "")})
    return out.stdout.strip() if out.returncode == 0 else None


def main():
    os.makedirs(OUT, exist_ok=True)

    # v0s: workloads, then findings per image digest.
    workloads = v0s("VulnerabilityService/ListWorkloads", {"cluster": CLUSTER, "pageSize": 1000})["workloads"]
    v0s_wl = {}
    for w in workloads:
        v0s_wl[(w["namespace"], w["name"])] = [c["image"] for c in w.get("containers", [])]

    aliases = {}

    def ids_for(vid):
        if vid not in aliases:
            v = v0s("VulnerabilityService/GetVulnerability", {"id": vid}).get("vulnerability", {})
            aliases[vid] = {vid, *v.get("aliases", [])}
        return aliases[vid]

    v0s_findings = {}
    for imgs in v0s_wl.values():
        for img in imgs:
            d = img["digest"]
            if d in v0s_findings:
                continue
            fs, tok = [], ""
            while True:
                r = v0s("VulnerabilityService/ListFindings",
                        {"filter": {"imageDigest": d, "suppressed": "SUPPRESSED_FILTER_INCLUDE"} , "pageSize": 1000, "pageToken": tok})
                fs += r.get("findings", [])
                tok = r.get("nextPageToken", "")
                if not tok:
                    break
            v0s_findings[d] = fs

    # v13s: workloads in the cluster, then vulnerabilities per image name:tag.
    v13s_wl, off = {}, 0
    while True:
        r = v13s("ListVulnerabilitySummaries", {"filter": {"cluster": CLUSTER}, "limit": 200, "offset": off})
        for n in r.get("nodes", []):
            w = n["workload"]
            v13s_wl.setdefault((w["namespace"], w["name"]), []).append({
                "name": w["imageName"], "tag": w["imageTag"], "type": w.get("type"),
                "sbom": (n.get("sbomStatus") or {}).get("status"),
                "has_sbom": (n.get("vulnerabilitySummary") or {}).get("hasSbom", False)})
        if not r.get("pageInfo", {}).get("hasNextPage"):
            break
        off += 200

    v13s_findings = {}
    for imgs in v13s_wl.values():
        for img in imgs:
            key = (img["name"], img["tag"])
            if key in v13s_findings:
                continue
            vs, off = [], 0
            while True:
                r = v13s("ListVulnerabilitiesForImage", {"imageName": img["name"], "imageTag": img["tag"],
                                                       "includeSuppressed": True, "limit": 500, "offset": off})
                vs += r.get("nodes", [])
                if not r.get("pageInfo", {}).get("hasNextPage"):
                    break
                off += 500
            v13s_findings[key] = vs

    # Compare per workload and image name.
    totals = defaultdict(Counter)
    per_workload = defaultdict(Counter)
    diffs, coverage = [], []
    for wk in sorted(set(v0s_wl) | set(v13s_wl)):
        a_imgs, b_imgs = v0s_wl.get(wk, []), v13s_wl.get(wk, [])
        if not a_imgs or not b_imgs:
            coverage.append({"workload": "/".join(wk), "only_in": "v0s" if a_imgs else "v13s",
                             "images": [i["name"] for i in a_imgs] or [f'{i["name"]}:{i["tag"]}' for i in b_imgs]})
            continue
        for b in b_imgs:
            same = [a for a in a_imgs if a["name"] == b["name"]]
            if not same:
                coverage.append({"workload": "/".join(wk), "only_in": "v13s-image", "images": [f'{b["name"]}:{b["tag"]}'],
                                 "v0s_images": [a["name"] for a in a_imgs]})
                continue
            a = same[0]
            tag_digest = digest_of(f'{b["name"]}:{b["tag"]}')
            row = {"workload": "/".join(wk), "image": b["name"], "tag": b["tag"], "v0s_digest": a["digest"],
                   "tag_digest": tag_digest, "same_image": tag_digest == a["digest"],
                   "v0s_sbom": a.get("sbomState"), "v13s_sbom": b["sbom"]}
            coverage.append(row)
            if a.get("sbomState") != "SBOM_STATE_FETCHED" or not b["has_sbom"]:
                continue

            av = v0s_findings.get(a["digest"], [])
            bv = v13s_findings.get((b["name"], b["tag"]), [])
            b_index = defaultdict(list)
            for i, f in enumerate(bv):
                b_index[package_key(f["package"])].append(i)
            b_used = set()
            for f in av:
                ids = ids_for(f["vulnerabilityId"])
                sev = f.get("severity", "SEVERITY_UNKNOWN").replace("SEVERITY_", "")
                hit = next((i for i in b_index.get(package_key(f["purl"]), [])
                            if i not in b_used and bv[i]["cve"]["id"] in ids), None)
                unfixed = not f.get("fixedVersion")
                if hit is not None:
                    b_used.add(hit)
                    totals[sev]["matched"] += 1
                    per_workload[row["workload"] + ":" + b["tag"]]["matched"] += 1
                else:
                    totals[sev]["v0s_only_unfixed" if unfixed else "v0s_only_fixable"] += 1
                    per_workload[row["workload"] + ":" + b["tag"]]["v0s_only"] += 1
                    if sev in ("CRITICAL", "HIGH"):
                        diffs.append({"side": "v0s_only", "workload": row["workload"], "image": b["name"],
                                      "id": f["vulnerabilityId"], "aliases": sorted(ids - {f["vulnerabilityId"]}),
                                      "purl": f["purl"], "severity": sev, "status": f.get("status"),
                                      "fixed": f.get("fixedVersion"), "source": f.get("dataSource"),
                                      "same_image": row["same_image"]})
            for i, f in enumerate(bv):
                if i in b_used:
                    continue
                sev = f["cve"].get("severity", "UNASSIGNED")
                sev = {"UNASSIGNED": "UNKNOWN"}.get(sev, sev)
                totals[sev]["v13s_only"] += 1
                per_workload[row["workload"] + ":" + b["tag"]]["v13s_only"] += 1
                if sev in ("CRITICAL", "HIGH"):
                    diffs.append({"side": "v13s_only", "workload": row["workload"], "image": b["name"],
                                  "id": f["cve"]["id"], "purl": f["package"], "severity": sev,
                                  "fixed": f.get("fixVersion"), "suppressed": bool((f.get("suppression") or {}).get("suppressed")),
                                  "same_image": row["same_image"]})

    json.dump(coverage, open(f"{OUT}/coverage.json", "w"), indent=1)
    json.dump(diffs, open(f"{OUT}/diffs-high-critical.json", "w"), indent=1)

    print(f"workloads: v0s={len(v0s_wl)} v13s={len(v13s_wl)}")
    compared = [c for c in coverage if "same_image" in c]
    print(f"workload images in both: {len(compared)}, same digest: {sum(c['same_image'] for c in compared)}")
    print("sbom (v0s, v13s):", dict(Counter((c["v0s_sbom"], c["v13s_sbom"]) for c in compared)))
    print("only in one:", dict(Counter(c["only_in"] for c in coverage if "only_in" in c)))
    cols = ["matched", "v0s_only_fixable", "v0s_only_unfixed", "v13s_only"]
    print(f'{"severity":9}' + "".join(f"{c:>18}" for c in cols))
    for s in SEVERITIES:
        print(f"{s:9}" + "".join(f"{totals[s][c]:>18}" for c in cols))
    print("per workload:tag (matched / v0s-only / v13s-only):")
    for k in sorted(per_workload):
        c = per_workload[k]
        print(f"  {k:70} {c['matched']:>4} {c['v0s_only']:>4} {c['v13s_only']:>4}")
    print(f"high/critical differences: {len(diffs)} -> {OUT}/diffs-high-critical.json")


if __name__ == "__main__":
    main()
