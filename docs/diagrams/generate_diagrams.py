"""Generates the architecture diagrams in docs/images/ (python docs/diagrams/generate_diagrams.py).

Pure matplotlib so it runs anywhere. Colours follow the AWS architecture icon
category palette (compute orange, storage green, security red, integration pink,
management/governance purple, networking violet).
"""
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "images")
os.makedirs(OUT, exist_ok=True)
plt.rcParams["font.family"] = "DejaVu Sans"

C = {
    "compute": "#ED7100",
    "storage": "#7AA116",
    "security": "#DD344C",
    "integration": "#E7157B",
    "mgmt": "#7B45D6",
    "network": "#8C4FFF",
    "database": "#C925D1",
    "user": "#232F3E",
    "ink": "#16191F",
    "muted": "#5F6B7A",
    "line": "#414D5C",
}


def canvas(w, h, title, subtitle=None):
    fig, ax = plt.subplots(figsize=(w, h), dpi=160)
    ax.set_xlim(0, w * 10)
    ax.set_ylim(0, h * 10)
    ax.axis("off")
    fig.patch.set_facecolor("white")
    ax.text(3, h * 10 - 3.5, title, fontsize=17, fontweight="bold", color=C["ink"], va="top")
    if subtitle:
        ax.text(3, h * 10 - 7.6, subtitle, fontsize=10.5, color=C["muted"], va="top")
    return fig, ax


def group(ax, x, y, w, h, label, color, dashed=False, fill="#FFFFFF", label_color=None):
    box = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=1.2",
                         linewidth=1.6, edgecolor=color, facecolor=fill,
                         linestyle=(0, (5, 3)) if dashed else "solid", zorder=1)
    ax.add_patch(box)
    tag = FancyBboxPatch((x, y + h - 3.4), min(len(label) * 1.05 + 3, w), 3.4,
                         boxstyle="round,pad=0,rounding_size=1.0", linewidth=0, facecolor=color, zorder=2)
    ax.add_patch(tag)
    ax.text(x + 1.4, y + h - 1.7, label, fontsize=9.5, color="white", fontweight="bold", va="center", zorder=3)


def service(ax, x, y, name, detail, color, code, w=None, h=9.5):
    """A service card: coloured icon tile with a short code, name and detail line."""
    need = 7.8 + max(0.82 * len(name), 0.64 * len(detail))
    w = max(w or 0, need)
    card = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.9",
                          linewidth=1.1, edgecolor="#D5DBDB", facecolor="white", zorder=4)
    ax.add_patch(card)
    tile = FancyBboxPatch((x + 0.9, y + h - 5.3), 4.4, 4.4, boxstyle="round,pad=0,rounding_size=0.6",
                          linewidth=0, facecolor=color, zorder=5)
    ax.add_patch(tile)
    ax.text(x + 3.1, y + h - 3.1, code, fontsize=8.2, color="white", ha="center", va="center", fontweight="bold", zorder=6)
    ax.text(x + 6.1, y + h - 2.1, name, fontsize=8.8, color=C["ink"], fontweight="bold", va="center", zorder=6)
    ax.text(x + 6.1, y + h - 4.4, detail, fontsize=7.2, color=C["muted"], va="center", zorder=6)
    return (x, y, w, h)


def anchor(b, side):
    x, y, w, h = b
    return {"l": (x, y + h / 2), "r": (x + w, y + h / 2), "t": (x + w / 2, y + h), "b": (x + w / 2, y)}[side]


def arrow(ax, a, b, label=None, color=None, rad=0.0, dashed=False, lx=0, ly=0, num=None, fs=7.6):
    color = color or C["line"]
    p = FancyArrowPatch(a, b, arrowstyle="-|>", mutation_scale=11, linewidth=1.3, color=color,
                        connectionstyle=f"arc3,rad={rad}", linestyle=(0, (4, 3)) if dashed else "solid", zorder=3)
    ax.add_patch(p)
    mx, my = (a[0] + b[0]) / 2 + lx, (a[1] + b[1]) / 2 + ly
    if num is not None:
        ax.add_patch(plt.Circle((mx, my), 1.35, color=C["user"], zorder=7))
        ax.text(mx, my, str(num), color="white", fontsize=7.5, ha="center", va="center", fontweight="bold", zorder=8)
        if label:
            ax.text(mx + 1.9, my, label, fontsize=fs, color=C["ink"], va="center", zorder=8,
                    bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="none", alpha=0.9))
    elif label:
        ax.text(mx, my, label, fontsize=fs, color=C["ink"], ha="center", va="center", zorder=8,
                bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="none", alpha=0.9))


def path(ax, pts, label=None, color=None, dashed=False, num=None, at=0, lx=0, ly=0, fs=7.6):
    """Orthogonal connector through the given points; arrow head on the last segment."""
    color = color or C["line"]
    ls = (0, (4, 3)) if dashed else "solid"
    xs, ys = zip(*pts[:-1])
    ax.plot(list(xs) + [pts[-1][0]], list(ys) + [pts[-1][1]], color=color, linewidth=1.3, linestyle=ls,
            zorder=3, solid_capstyle="round")
    ax.add_patch(FancyArrowPatch(pts[-2], pts[-1], arrowstyle="-|>", mutation_scale=11, linewidth=0,
                                 color=color, zorder=3))
    a, b = pts[at], pts[at + 1]
    mx, my = (a[0] + b[0]) / 2 + lx, (a[1] + b[1]) / 2 + ly
    if num is not None:
        badge(ax, mx, my, num)
        if label:
            ax.text(mx + 1.9, my, label, fontsize=fs, color=C["ink"], va="center", zorder=8,
                    bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="none", alpha=0.9))
    elif label:
        ax.text(mx, my, label, fontsize=fs, color=C["ink"], ha="center", va="center", zorder=8,
                bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="none", alpha=0.9))


def badge(ax, x, y, num):
    ax.add_patch(plt.Circle((x, y), 1.45, color=C["user"], zorder=9))
    ax.text(x, y, str(num), color="white", fontsize=7.8, ha="center", va="center", fontweight="bold", zorder=10)


def save(fig, name):
    path = os.path.join(OUT, name)
    fig.savefig(path, bbox_inches="tight", pad_inches=0.25, facecolor="white")
    plt.close(fig)
    print("wrote", os.path.relpath(path))


# ------------------------------------------------------------------ 1. overview
def overview():
    fig, ax = canvas(17, 11.5, "Automated EC2 Forensics on AWS: solution architecture",
                     "Single-account lab deployment with Terraform. Numbered badges follow one investigation end to end.")
    group(ax, 2, 27, 166, 76, "AWS account (one region)", "#232F3E")

    soc = service(ax, 5, 84, "SOC analyst", "CLI / console / script", C["user"], "SOC")
    gd = service(ax, 5, 68, "Amazon GuardDuty", "optional auto trigger", C["security"], "GD")
    eb = service(ax, 5, 52, "Amazon EventBridge", "finding >= severity", C["integration"], "EB")
    apr = service(ax, 5, 35, "Approver", "email link", C["user"], "APR", w=20.8)

    group(ax, 34, 32, 64, 67, "Orchestration (serverless)", C["integration"], dashed=True, fill="#FFF7FB")
    sfn = service(ax, 37, 84, "AWS Step Functions", "Standard workflow", C["integration"], "SFN", w=28)
    lam = service(ax, 67, 84, "AWS Lambda (15 fns)", "Python 3.12 steps", C["compute"], "λ", w=28)
    sns = service(ax, 37, 66, "Amazon SNS", "approval and reports", C["integration"], "SNS", w=28)
    service(ax, 67, 66, "Amazon DynamoDB", "cases + approvals", C["database"], "DDB", w=28)
    api = service(ax, 37, 35, "API Gateway (HTTP)", "approve / reject page", C["network"], "API", w=28)
    service(ax, 67, 35, "AWS KMS (CMK)", "one evidence key", C["security"], "KMS", w=28)
    ax.text(66, 57, "Lambdas read and write DynamoDB,\npublish to SNS and use the CMK",
            fontsize=7.4, color=C["muted"], ha="center", va="center")

    group(ax, 101, 61, 66, 38, "Forensics VPC: workstation subnet (no inbound)", C["network"], fill="#F8F5FF")
    ssm = service(ax, 104, 84, "Systems Manager", "Run Command, no SSH", C["mgmt"], "SSM", w=28)
    ws = service(ax, 136, 84, "Forensic workstation", "TSK, ClamAV, YARA", C["compute"], "EC2", w=29)
    service(ax, 104, 64, "VPC Flow Logs", "CloudWatch Logs", C["mgmt"], "VFL", w=28)
    av = service(ax, 136, 64, "Analysis volumes", "disposable, attached RO", C["storage"], "EBS", w=29)

    group(ax, 101, 29, 31, 29, "Workload subnet (no internet)", C["storage"], fill="#F7FBEF")
    tgt = service(ax, 103.5, 43.5, "Suspect EC2", "demo target / any EC2", C["compute"], "EC2", w=26)
    snp = service(ax, 103.5, 31.5, "EBS snapshots", "root + data volume", C["storage"], "SNP", w=26)
    s3 = service(ax, 136, 45.5, "Amazon S3 evidence", "SSE-KMS, versioned", C["storage"], "S3", w=29)
    service(ax, 136, 34, "Amazon CloudWatch", "logs, X-Ray, alarms", C["mgmt"], "CW", w=29)

    y1 = soc[1] + 4.75
    path(ax, [anchor(soc, "r"), (sfn[0], y1)], num=1, lx=-1)
    path(ax, [anchor(gd, "b"), anchor(eb, "t")])
    path(ax, [anchor(eb, "r"), (29.5, eb[1] + 4.75), (29.5, sfn[1] + 2.5), (sfn[0], sfn[1] + 2.5)],
         label="or", at=1, lx=1.8)
    path(ax, [anchor(sfn, "r"), anchor(lam, "l")])
    path(ax, [anchor(sns, "l"), (32, sns[1] + 4.75), (32, 47), (apr[0] + 10, 47), (apr[0] + 10, apr[1] + apr[3])],
         num=2, at=1)
    path(ax, [anchor(apr, "r"), anchor(api, "l")], num=3, lx=-1)
    path(ax, [anchor(lam, "r"), (99.5, y1), (99.5, tgt[1] + 4.75), (tgt[0], tgt[1] + 4.75)], num=4, at=1)
    path(ax, [anchor(snp, "r"), (134, snp[1] + 4.75), (134, av[1] + 4.75), (av[0], av[1] + 4.75)], num=5, at=1, ly=6)
    path(ax, [anchor(lam, "t"), (lam[0] + lam[2] / 2, 101), (ssm[0] + ssm[2] / 2, 101), anchor(ssm, "t")], num=6, at=1)
    path(ax, [anchor(ssm, "r"), anchor(ws, "l")])
    path(ax, [anchor(av, "t"), anchor(ws, "b")], label="attach")
    path(ax, [anchor(ws, "r"), (166.5, y1), (166.5, s3[1] + 4.75), (s3[0] + s3[2], s3[1] + 4.75)], num=7, at=1)
    badge(ax, s3[0] + s3[2] - 1.5, s3[1] + s3[3] - 1.2, 8)
    badge(ax, tgt[0] + tgt[2] - 1.5, tgt[1] + tgt[3] - 1.2, 9)

    steps = [
        "1  Analyst (or a GuardDuty finding via EventBridge) starts the workflow with an instance id.",
        "2  The instance is validated and an approval email with a single-use link is sent through SNS.",
        "3  The approver confirms on the API Gateway page; the callback resumes the paused workflow.",
        "4  Termination protection is enabled and every EBS volume is snapshotted.",
        "5  Snapshots are re-encrypted with the forensics CMK; disposable volumes are made from them.",
        "6  SSM Run Command starts the scan on the workstation (no SSH, no inbound ports).",
        "7  Hash, timeline, ClamAV, YARA and artifact collection results go to S3 (gateway endpoint).",
        "8  A chain-of-custody manifest is written, its SHA-256 recorded, and a report email is sent.",
        "9  Optional: the suspect ENIs are moved into a quarantine security group with no rules.",
    ]
    for i, line in enumerate(steps):
        col, row = divmod(i, 5)
        ax.text(4 + col * 84, 22 - row * 4.6, line, fontsize=8.3, color=C["ink"], va="center")
    save(fig, "architecture-overview.png")


# ------------------------------------------------------------------ 2. workflow
def workflow():
    fig, ax = canvas(17, 9.6, "Step Functions workflow",
                     "Every task is a small Lambda; the approval task uses the callback (waitForTaskToken) pattern.")

    def st(x, y, name, kind="task", w=19, h=7):
        color = {"task": C["integration"], "choice": C["network"], "wait": C["muted"], "ok": C["storage"],
                 "fail": C["security"], "cb": C["compute"]}[kind]
        box = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=1.5",
                             linewidth=1.4, edgecolor=color, facecolor="white" if kind != "choice" else "#F8F5FF", zorder=4)
        ax.add_patch(box)
        ax.add_patch(FancyBboxPatch((x, y), 1.2, h, boxstyle="square,pad=0", linewidth=0, facecolor=color, zorder=5))
        ax.text(x + w / 2 + 0.6, y + h / 2, name, fontsize=8.2, ha="center", va="center", color=C["ink"],
                fontweight="bold", zorder=6)
        return (x, y, w, h)

    y1, y2, y3 = 66, 38, 10
    v = st(3, y1, "ValidateRequest")
    a = st(26, y1, "RequestApproval\n(.waitForTaskToken)", "cb", w=22)
    d = st(53, y1, "Approved?", "choice", w=14)
    r = st(51, y1 + 13, "NotifyRejected", w=18)
    c = st(72, y1, "CreateSnapshots")
    w1 = st(96, y1, "Wait 30s", "wait", w=13)
    ck = st(114, y1, "CheckSnapshots")
    rt = st(138, y1, "Snapshot phase?", "choice", w=20)
    re_ = st(114, y1 - 15, "ReEncryptWith\nForensicsKey", w=19)
    sh = st(138, y1 - 15, "ShareTo\nForensicsAccount", w=20)

    at = st(138, y2 - 6, "AttachTo\nWorkstation", w=20)
    ss = st(114, y2 - 6, "StartForensicScan", w=19)
    w2 = st(96, y2 - 6, "Wait 60s", "wait", w=13)
    cs = st(72, y2 - 6, "CheckScan")
    sr = st(53, y2 - 6, "Scan done?", "choice", w=14)
    cl = st(29, y2 - 6, "Cleanup", w=19)
    fn = st(3, y2 - 6, "FinalizeCase\n(custody + notify)", w=21)

    iso_d = st(3, y3, "Isolate?", "choice", w=14)
    iso = st(22, y3, "IsolateInstance")
    ok = st(46, y3, "Complete", "ok", w=14)
    cof = st(96, y3, "CleanupOnFailure", "fail", w=19)
    nf = st(120, y3, "NotifyFailure", "fail", w=17)
    fl = st(142, y3, "Failed", "fail", w=13)

    for p, q in [(v, a), (a, d), (d, c), (c, w1), (w1, ck), (ck, rt), (cof, nf), (nf, fl), (iso, ok),
                 (at, ss), (ss, w2), (w2, cs), (cs, sr), (cl, fn)]:
        path(ax, [anchor(p, "r") if p[0] < q[0] else anchor(p, "l"), anchor(q, "l") if p[0] < q[0] else anchor(q, "r")])
    path(ax, [anchor(d, "t"), (d[0] + 7, r[1])], label="no", lx=2.5)
    top = y1 + 10
    path(ax, [anchor(rt, "t"), (rt[0] + 10, top), (w1[0] + 6.5, top), anchor(w1, "t")], label="not ready", at=1)
    path(ax, [(rt[0] + 5, rt[1]), (rt[0] + 5, rt[1] - 3), (re_[0] + 9.5, rt[1] - 3), anchor(re_, "t")], label="source", at=1)
    path(ax, [(rt[0] + 14, rt[1]), anchor(sh, "t")], label="encrypted +\ncross-account", lx=7)
    path(ax, [anchor(re_, "l"), (w1[0] + 6.5, re_[1] + 3.5), anchor(w1, "b")])
    path(ax, [anchor(sh, "b"), (sh[0] + 10, sh[1] - 3), (w1[0] + 4, sh[1] - 3), (w1[0] + 4, w1[1])])
    path(ax, [anchor(rt, "r"), (162, rt[1] + 3.5), (162, at[1] + 3.5), anchor(at, "r")], label="evidence ready", at=1, ly=-9)
    path(ax, [anchor(sr, "b"), (sr[0] + 7, sr[1] - 4), (w2[0] + 6.5, sr[1] - 4), anchor(w2, "b")], label="running", at=1)
    path(ax, [anchor(sr, "l"), anchor(cl, "r")], label="success")
    path(ax, [anchor(fn, "b"), anchor(iso_d, "t")])
    path(ax, [anchor(iso_d, "r"), anchor(iso, "l")])
    path(ax, [anchor(iso_d, "b"), (iso_d[0] + 7, y3 - 4), (ok[0] + 7, y3 - 4), anchor(ok, "b")], label="no", at=1)
    ax.text(96, y3 + 11, "Any error after approval  ->  CleanupOnFailure (evidence snapshots are kept)",
            fontsize=8.2, color=C["security"])
    save(fig, "stepfunctions-workflow.png")


# ------------------------------------------------------------------ 3. evidence chain
def evidence():
    fig, ax = canvas(17, 7.6, "Evidence handling and chain of custody",
                     "Snapshots under the default aws/ebs key can never be shared across accounts, so evidence is re-encrypted with a forensics CMK.")
    group(ax, 2, 4, 74, 60, "Workload account", C["storage"], fill="#F7FBEF")
    group(ax, 84, 4, 84, 60, "Forensics (security tooling) account", C["security"], fill="#FDF3F4")
    v = service(ax, 6, 46, "Source EBS volume", "aws/ebs key or app CMK", C["storage"], "EBS", w=27)
    s1 = service(ax, 6, 27, "Snapshot (original)", "point in time", C["storage"], "SNP", w=27)
    s2 = service(ax, 6, 8, "Snapshot (transfer)", "re-encrypted, forensics CMK", C["security"], "SNP", w=27)
    s3 = service(ax, 88, 8, "Snapshot (EVIDENCE)", "CMK, tagged with SHA-256", C["security"], "SNP", w=28)
    av = service(ax, 88, 27, "Analysis volume", "disposable copy", C["storage"], "EBS", w=28)
    ws = service(ax, 88, 46, "Forensic workstation", "blockdev --setro, mount ro", C["compute"], "EC2", w=28)
    rep = service(ax, 134, 46, "S3 evidence bucket", "reports, timelines, artifacts", C["storage"], "S3", w=30)
    cc = service(ax, 134, 27, "chain-of-custody.json", "SHA-256 kept in DynamoDB", C["database"], "CoC", w=30)
    path(ax, [anchor(v, "b"), anchor(s1, "t")], label="CreateSnapshot", lx=14)
    path(ax, [anchor(s1, "b"), anchor(s2, "t")], label="CopySnapshot (CMK)", lx=16)
    path(ax, [anchor(s2, "r"), anchor(s3, "l")], label="share + copy", ly=2.2)
    path(ax, [anchor(s3, "t"), anchor(av, "b")], label="CreateVolume", lx=13)
    path(ax, [anchor(av, "t"), anchor(ws, "b")], label="attach", lx=8)
    path(ax, [anchor(ws, "r"), anchor(rep, "l")], label="scan output", ly=2.2)
    path(ax, [anchor(rep, "b"), anchor(cc, "t")], label="finalize", lx=9)
    ax.text(40, 36, "Single-account mode: the re-encrypted\ncopy IS the evidence snapshot\n(no share step).",
            fontsize=8, color=C["muted"], va="center")
    ax.text(122, 17, "IAM denies DeleteSnapshot on ForensicsStage=evidence.\nIntermediate copies are deleted after success.\n"
                     "Raw image hash + manifest hash prove integrity.", fontsize=8, color=C["muted"], va="center")
    save(fig, "evidence-chain.png")


# ------------------------------------------------------------------ 4. enterprise
def enterprise():
    fig, ax = canvas(17, 10, "Enterprise deployment: AWS Organizations, multi-account",
                     "Central forensics in the Security Tooling account; a responder role in every workload account.")
    group(ax, 2, 2, 166, 82, "AWS Organization (Control Tower landing zone)", "#232F3E")

    group(ax, 4, 52, 52, 28, "Management account", C["mgmt"], fill="#F7F3FD")
    service(ax, 6.5, 64, "AWS Organizations", "SCPs, delegated admin", C["mgmt"], "ORG")
    service(ax, 31, 64, "IAM Identity Center", "SOC permission sets", C["security"], "IdC")
    service(ax, 6.5, 54, "Control Tower / AFT", "account vending", C["mgmt"], "CT")
    service(ax, 31, 54, "CloudFormation", "StackSets", C["mgmt"], "CFN")

    group(ax, 4, 6, 52, 42, "Log Archive account", C["storage"], fill="#F7FBEF")
    service(ax, 6.5, 32, "Org CloudTrail", "immutable trail", C["mgmt"], "CT")
    service(ax, 31, 32, "S3 Object Lock", "compliance mode", C["storage"], "S3")
    service(ax, 6.5, 20, "VPC Flow Logs", "centralised", C["network"], "VFL")
    service(ax, 31, 20, "Evidence replica", "cross-region CRR", C["storage"], "S3")

    group(ax, 60, 6, 56, 74, "Security Tooling account (forensics)", C["security"], fill="#FDF3F4")
    service(ax, 64, 64, "Security Hub", "findings + ASFF", C["security"], "SH", w=23)
    gd = service(ax, 90, 64, "GuardDuty", "delegated admin", C["security"], "GD", w=23)
    ch = service(ax, 64, 50, "ChatOps / ITSM", "Slack, ServiceNow", C["integration"], "OPS", w=23)
    sfn = service(ax, 90, 50, "Step Functions", "this workflow", C["integration"], "SFN", w=23)
    ws = service(ax, 64, 36, "Workstation fleet", "private + endpoints", C["compute"], "EC2", w=23)
    service(ax, 90, 36, "KMS CMK", "multi-account policy", C["security"], "KMS", w=23)
    s3 = service(ax, 64, 22, "Evidence bucket", "Object Lock", C["storage"], "S3", w=23)
    service(ax, 90, 22, "Detective / Athena", "investigation queries", C["security"], "DET", w=23)
    service(ax, 64, 9, "Golden AMI pipeline", "EC2 Image Builder (SANS SIFT, hardened)", C["compute"], "IB", w=49, h=9)

    group(ax, 122, 6, 44, 74, "Workload accounts (100s)", C["compute"], fill="#FFF8F1")
    bus = 119
    for i, (yy, nm) in enumerate([(62, "Prod account A"), (44, "Prod account B"), (26, "Dev / test accounts")]):
        group(ax, 125, yy - 4, 38, 17, nm, C["compute"], fill="white")
        r = service(ax, 127, yy - 2, "ForensicsResponderRole", "assumed by SFN", C["security"], "IAM", w=34, h=9)
        path(ax, [(bus, sfn[1] + 4.75), (bus, r[1] + 4.5), (r[0], r[1] + 4.5)])
    ax.text(bus - 1.2, 40, "sts:AssumeRole", fontsize=7.6, color=C["ink"], rotation=90, ha="center", va="center",
            bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="none"))
    ax.text(125, 12, "Snapshots re-encrypted with the central\nCMK, shared, copied into the tooling account.",
            fontsize=8, color=C["muted"])
    path(ax, [anchor(gd, "b"), anchor(sfn, "t")], label="EventBridge")
    path(ax, [anchor(sfn, "l"), anchor(ch, "r")], label="approval")
    path(ax, [(sfn[0] + 11.5, sfn[1]), (sfn[0] + 11.5, 47.5), (ws[0] + 11.5, 47.5), anchor(ws, "t")], label="scan", at=1)
    path(ax, [anchor(ws, "b"), anchor(s3, "t")])
    path(ax, [anchor(s3, "l"), (56.5, s3[1] + 4.75)], label="replicate", dashed=True)
    save(fig, "enterprise-multi-account.png")


if __name__ == "__main__":
    overview()
    workflow()
    evidence()
    enterprise()
