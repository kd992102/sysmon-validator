#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""generate_slides_assets.py — 產生簡報 PNG 圖表（v2）"""

import sys
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.patches import FancyBboxPatch, Rectangle
    import numpy as np
except ImportError:
    print("[-] pip install matplotlib")
    sys.exit(1)

OUT = Path(__file__).parent / "slides_assets"
OUT.mkdir(exist_ok=True)

plt.rcParams["font.family"] = ["Microsoft JhengHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False

C_GREEN  = "#1e8449"
C_ORANGE = "#d4821a"
C_BLUE   = "#1a5276"
C_RED    = "#c0392b"
C_GRAY   = "#aaaaaa"


# ══════════════════════════════════════════════════════════════════════════════
# 圖 1：偵測覆蓋率 — Dashboard 表格樣式
# ══════════════════════════════════════════════════════════════════════════════
def make_coverage_chart():
    data = [
        ("T1134.004", "Parent PID Spoofing",        "PASS",   [1, 10], []),
        ("T1055.012", "Process Hollowing",           "PASS",   [10, 25],[]),
        ("T1055.012", "Process Hollowing (Evasion)", "EVADED", [10],    [25]),
        ("T1218.011", "Rundll32 LOLBin",             "PASS",   [1],     []),
        ("T1059.001", "PowerShell Fileless",         "PASS",   [1],     []),
        ("T1547.001", "Registry Run Key",            "PASS",   [13],    []),
        ("T1053.005", "Scheduled Task",              "PASS",   [1],     []),
        ("T1053.005", "Sched. Task (Evasion)",       "EVADED", [],      [1]),
    ]

    n   = len(data)
    ROW = 0.72
    fig, ax = plt.subplots(figsize=(13, n * ROW + 2.5))
    ax.set_xlim(0, 13)
    ax.set_ylim(-1.15, n + 1.1)
    ax.axis("off")
    fig.patch.set_facecolor("white")

    # ── 標題 ──────────────────────────────────────────────────────────────────
    ax.text(0.15, n + 0.72, "Sysmon 偵測覆蓋率 — 8 Test Cases",
            ha="left", va="center", fontsize=13, fontweight="bold", color=C_BLUE)
    ax.text(12.85, n + 0.72, "Sysmon v15.20 | sysmon-modular.xml  ff0f7a3091ab",
            ha="right", va="center", fontsize=8, color="#888")

    # ── 欄位標頭（緊接第一列上方）────────────────────────────────────────────
    HEADER_Y = n - 0.62   # = first-row top (n-1+0.38)
    ax.add_patch(Rectangle((0, HEADER_Y), 13, 0.52,
                            facecolor=C_BLUE, edgecolor="none", zorder=2))
    for x, txt in [(0.2, "MITRE ID"), (1.9, "Technique"),
                   (7.4, "偵測到"), (9.6, "缺口"), (11.4, "結果")]:
        ax.text(x, HEADER_Y + 0.26, txt, ha="left", va="center",
                fontsize=9, color="white", fontweight="bold", zorder=3)

    # ── 每列 ──────────────────────────────────────────────────────────────────
    STATUS_COLOR = {"PASS": C_GREEN, "EVADED": C_ORANGE}
    STATUS_LABEL = {"PASS": "PASS ✓",  "EVADED": "EVADED ✓"}

    for i, (tid, name, status, detected, gap) in enumerate(data):
        y  = n - 1 - i
        bg = "#f4f8fc" if i % 2 == 0 else "white"

        ax.add_patch(Rectangle((0, y - 0.38), 13, 0.76,
                                facecolor=bg, edgecolor="#e0e8f0",
                                linewidth=0.6, zorder=1))
        # 左側彩色條紋
        ax.add_patch(Rectangle((0, y - 0.38), 0.09, 0.76,
                                facecolor=STATUS_COLOR[status],
                                edgecolor="none", zorder=2))

        # MITRE ID chip
        ax.add_patch(FancyBboxPatch((0.18, y - 0.2), 1.5, 0.4,
                                    boxstyle="round,pad=0.05",
                                    facecolor="#e8f0fe", edgecolor="none", zorder=3))
        ax.text(0.93, y, tid, ha="center", va="center",
                fontsize=8.5, color=C_BLUE, fontweight="bold", zorder=4)

        # 名稱
        ax.text(1.88, y, name, ha="left", va="center",
                fontsize=9.5, color="#1a1a2e", zorder=3)

        # 偵測到的 Event 徽章（綠）
        bx = 7.4
        for eid in detected:
            ax.add_patch(FancyBboxPatch((bx, y - 0.21), 0.92, 0.42,
                                        boxstyle="round,pad=0.05",
                                        facecolor=C_GREEN, edgecolor="none", zorder=3))
            ax.text(bx + 0.46, y, f"Ev {eid}", ha="center", va="center",
                    fontsize=8.5, color="white", fontweight="bold", zorder=4)
            bx += 1.02
        if not detected:
            ax.text(7.85, y, "—", ha="center", va="center",
                    fontsize=11, color="#bbb", zorder=3)

        # 缺口 Event 徽章（紅虛線）
        bx = 9.6
        for eid in gap:
            ax.add_patch(FancyBboxPatch((bx, y - 0.21), 0.92, 0.42,
                                        boxstyle="round,pad=0.05",
                                        facecolor="#fef0ee",
                                        edgecolor=C_RED, linewidth=1.3,
                                        linestyle="--", zorder=3))
            ax.text(bx + 0.46, y, f"Ev {eid}", ha="center", va="center",
                    fontsize=8.5, color=C_RED, fontweight="bold", zorder=4)
            bx += 1.02
        if not gap:
            ax.text(10.05, y, "—", ha="center", va="center",
                    fontsize=11, color="#bbb", zorder=3)

        # 狀態徽章
        sc = STATUS_COLOR[status]
        ax.add_patch(FancyBboxPatch((11.1, y - 0.23), 1.65, 0.46,
                                    boxstyle="round,pad=0.05",
                                    facecolor=sc, edgecolor="none", zorder=3))
        ax.text(11.93, y, STATUS_LABEL[status], ha="center", va="center",
                fontsize=9, color="white", fontweight="bold", zorder=4)

    # ── 底部摘要 ──────────────────────────────────────────────────────────────
    # ── 底部摘要（y 從 -1.0 開始，與最後一列留 0.62 gap）────────────────────
    ax.add_patch(Rectangle((0, -1.0), 13, 0.52,
                            facecolor="#f0f4f8", edgecolor="#dde6ee",
                            linewidth=0.8, zorder=1))

    # 6 PASS 色塊
    ax.add_patch(FancyBboxPatch((0.2, -0.83), 0.16, 0.32,
                                boxstyle="round,pad=0.02",
                                facecolor=C_GREEN, edgecolor="none", zorder=2))
    ax.text(0.55, -0.67, "6  PASS ✓", ha="left", va="center",
            fontsize=9.5, color=C_GREEN, fontweight="bold", zorder=3)

    ax.add_patch(FancyBboxPatch((3.0, -0.83), 0.16, 0.32,
                                boxstyle="round,pad=0.02",
                                facecolor=C_ORANGE, edgecolor="none", zorder=2))
    ax.text(3.35, -0.67, "2  EVADED ✓  （正確揭露規避缺口）",
            ha="left", va="center", fontsize=9.5, color=C_ORANGE,
            fontweight="bold", zorder=3)

    plt.tight_layout(pad=0.3)
    path = OUT / "coverage_chart.png"
    fig.savefig(path, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"[+] {path}")


# ══════════════════════════════════════════════════════════════════════════════
# 圖 2：Oracle 時間軸（重設計）
# ══════════════════════════════════════════════════════════════════════════════
def make_oracle_timeline():
    """兩列對比：修正前（test window 內 keyword 污染）vs 修正後（正確 EVADED）"""
    fig, (ax_top, ax_bot) = plt.subplots(
        2, 1, figsize=(12, 5.6),
        gridspec_kw={"hspace": 0.55})
    fig.patch.set_facecolor("white")

    XL, XR = -34, 70   # 圖面 x 範圍

    def draw_row(ax, row_label, label_color,
                 noise_event,       # (x, txt) or None — test window 內的雜訊事件
                 result_txt, result_color,
                 keyword_note):
        ax.set_xlim(XL, XR)
        ax.set_ylim(-1.8, 3.0)
        ax.axis("off")
        ax.set_facecolor("white")

        # ── 區段填色 ──────────────────────────────────────────────────────────
        ax.add_patch(Rectangle((-30, -0.38), 30, 1.5,
                               facecolor="#f8f8f8", edgecolor="none", zorder=1))
        ax.add_patch(Rectangle((0, -0.38), 65, 1.5,
                               facecolor="#eafaf1", edgecolor="none", zorder=1))

        # ── 時間軸（只畫到 x=66，badge 放在更右邊不與軸重疊）────────────────
        ax.annotate("", xy=(67, 0.37), xytext=(-32, 0.37),
                    arrowprops=dict(arrowstyle="-|>", color="#555", lw=1.8),
                    zorder=4)

        # ── 邊界線 ────────────────────────────────────────────────────────────
        ax.plot([-30, -30], [-0.38, 1.12], color="#ccc", lw=1.5, ls="--", zorder=3)
        ax.plot([0, 0], [-0.38, 2.45], color=C_RED, lw=2.0, ls="-", zorder=3)
        ax.plot([65, 65], [-0.38, 2.45], color="#2e86c1", lw=1.5, ls="--", zorder=3)

        # ── 刻度 ──────────────────────────────────────────────────────────────
        for x in range(-30, 66, 15):
            lbl = f"{x:+d}s" if x != 0 else "exec_ts"
            ax.text(x, -0.58, lbl, ha="center", va="top",
                    fontsize=7.5, color="#888")
            ax.plot([x, x], [0.28, 0.46], color="#ccc", lw=0.8, zorder=3)

        # ── 區段標籤（上方，避免與 keyword 注記重疊）──────────────────────────
        ax.text(-15, 2.65, "Baseline Window（30s 前）",
                ha="center", va="center", fontsize=8.5, color="#aaa")
        ax.text(32, 2.65, "Test Window（exec_ts → exec_ts + 65s）",
                ha="center", va="center", fontsize=9.5, color="#1a5276",
                fontweight="bold")

        # ── 列標籤（左上角）──────────────────────────────────────────────────
        ax.text(XL + 0.5, 2.2, row_label, ha="left", va="center",
                fontsize=11, color=label_color, fontweight="bold")

        # ── keyword 說明（底部）───────────────────────────────────────────────
        ax.text(17, -1.4, keyword_note, ha="left", va="center",
                fontsize=8.5, color="#555", style="italic")

        # ── 雜訊事件（test window 內，僅修正前有）────────────────────────────
        if noise_event is not None:
            nx, ntxt = noise_event
            # 用 text+bbox 自動適配文字尺寸，不會 overflow
            ev_txt = ax.text(
                nx + 2.25, 0.15, ntxt,
                ha="center", va="center", fontsize=8.5,
                color=C_RED, fontweight="bold", zorder=5,
                bbox=dict(facecolor="#fdecea", edgecolor=C_RED,
                          boxstyle="round,pad=0.25", linewidth=1.4,
                          linestyle="--"))
            # keyword match 注記（事件上方）
            ax.annotate("", xy=(nx + 2.25, 0.55), xytext=(nx + 2.25, 1.55),
                        arrowprops=dict(arrowstyle="-|>", color=C_RED, lw=1.2),
                        zorder=5)
            ax.text(nx + 2.25, 1.65, "keyword 命中！", ha="center", va="bottom",
                    fontsize=8, color=C_RED, fontweight="bold")
        else:
            ax.text(32, 0.25, "（無命中事件）", ha="center", va="center",
                    fontsize=9, color="#bbb", style="italic")

        # ── 結果徽章（右側，貼在邊界線上方，text+bbox 自動定尺寸）────────────
        ax.text(65.5, 2.0, result_txt,
                ha="left", va="center", fontsize=9.5,
                color="white", fontweight="bold", zorder=5,
                bbox=dict(facecolor=result_color, edgecolor="none",
                          boxstyle="round,pad=0.35", zorder=4))

    # ── 修正前 ────────────────────────────────────────────────────────────────
    draw_row(
        ax_top,
        row_label="修正前（Bug）",
        label_color=C_RED,
        noise_event=(18, "schtasks.exe\n背景行程"),
        result_txt="PASS ✓  （誤判）",
        result_color=C_RED,
        keyword_note='keywords: ["T1053005_COM_EVASION",  "schtasks"]',
    )

    # ── 修正後 ────────────────────────────────────────────────────────────────
    draw_row(
        ax_bot,
        row_label="修正後（Fix）",
        label_color=C_GREEN,
        noise_event=None,
        result_txt="EVADED ✓  （正確）",
        result_color=C_ORANGE,
        keyword_note='keywords: ["T1053005_COM_EVASION"]  — 移除通用字串，只保留專屬 marker',
    )

    fig.suptitle(
        "T1053.005 Evasion — Test Oracle Keyword 污染導致 False Positive",
        fontsize=12.5, fontweight="bold", color="#1a1a2e", y=0.99)

    plt.tight_layout(pad=0.4, rect=[0, 0, 1, 0.97])
    path = OUT / "oracle_timeline.png"
    fig.savefig(path, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"[+] {path}")


# ══════════════════════════════════════════════════════════════════════════════
# 圖 3：Evasion 對比（含 bypass arrow）
# ══════════════════════════════════════════════════════════════════════════════
def make_evasion_comparison():
    fig, axes = plt.subplots(1, 2, figsize=(13, 5.2))
    fig.patch.set_facecolor("white")

    for ax in axes:
        ax.set_xlim(0, 10)
        ax.set_ylim(0.5, 10.5)
        ax.axis("off")
        ax.set_facecolor("white")

    # ── 共用函式 ──────────────────────────────────────────────────────────────
    def step_box(ax, x, y, w, h, txt, fc, tc="white", alpha=1.0, ls="-"):
        ax.add_patch(FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0.18",
            facecolor=fc, edgecolor="#555", linewidth=1.2,
            alpha=alpha, linestyle=ls, zorder=3))
        ax.text(x + w/2, y + h/2, txt,
                ha="center", va="center", fontsize=10,
                color=tc, fontweight="bold", zorder=4)

    def straight_arrow(ax, x, y1, y2, color="#555", lw=1.6):
        ax.annotate("", xy=(x, y2), xytext=(x, y1),
                    arrowprops=dict(arrowstyle="-|>", color=color, lw=lw),
                    zorder=5)

    # ── 步驟座標 ──────────────────────────────────────────────────────────────
    # box: (x, y_bottom, w, h)  —  y_top = y_bottom + h
    BX, BW, BH = 2.0, 6.0, 1.3
    steps = [
        (BX, 8.0, BW, BH, "CreateProcess(SUSPENDED)"),
        (BX, 6.0, BW, BH, "NtUnmapViewOfSection"),
        (BX, 4.0, BW, BH, "WriteProcessMemory"),
        (BX, 2.0, BW, BH, "SetThreadContext + ResumeThread"),
    ]

    # ── 左：正常版 ────────────────────────────────────────────────────────────
    ax = axes[0]
    ax.text(5, 10.2, "T1055.012  正常版", ha="center", va="center",
            fontsize=12, fontweight="bold", color=C_GREEN)
    ax.text(5, 9.65, "PASS ✓", ha="center", va="center",
            fontsize=10, color=C_GREEN)

    colors = ["#2e86c1", "#7d3c98", "#2e86c1", "#2e86c1"]
    for (x, y, w, h, txt), fc in zip(steps, colors):
        step_box(ax, x, y, w, h, txt, fc)

    for i in range(len(steps)-1):
        _, y_top, _, h_top, _ = steps[i]
        _, y_bot, _, h_bot, _ = steps[i+1]
        straight_arrow(ax, 5.0, y_top, y_bot + h_bot, color="#444")

    # Event 25 標籤（NtUnmapViewOfSection 右側）
    ax.add_patch(FancyBboxPatch(
        (8.2, 6.3), 1.55, 0.78,
        boxstyle="round,pad=0.1",
        facecolor="#f5eef8", edgecolor="#7d3c98", linewidth=1.5, zorder=4))
    ax.text(8.98, 6.68, "Event 25\n觸發 ✓", ha="center", va="center",
            fontsize=8.5, color="#7d3c98", fontweight="bold", zorder=5)
    ax.annotate("", xy=(8.2, 6.68), xytext=(8.0, 6.68),
                arrowprops=dict(arrowstyle="<-", color="#7d3c98", lw=1.5),
                zorder=5)

    # ── 右：Evasion 版 ────────────────────────────────────────────────────────
    ax = axes[1]
    ax.text(5, 10.2, "T1055.012  Evasion", ha="center", va="center",
            fontsize=12, fontweight="bold", color=C_ORANGE)
    ax.text(5, 9.65, "EVADED ✓   gap=[25]", ha="center", va="center",
            fontsize=10, color=C_ORANGE)

    evasion_colors = ["#2e86c1", C_GRAY, "#2e86c1", "#2e86c1"]
    for (x, y, w, h, txt), fc in zip(steps, evasion_colors):
        if fc == C_GRAY:
            step_box(ax, x, y, w, h, txt + "  —  跳過",
                     fc, tc="#666", alpha=0.5, ls="--")
        else:
            step_box(ax, x, y, w, h, txt, fc)

    # Evasion 版只保留 WriteProcessMemory → SetThreadContext 箭頭
    # CreateProcess→NtUnmap 和 NtUnmap→WriteProcessMemory 的箭頭不畫，
    # 由 bypass arrow 取代，避免讓觀眾以為流程仍穿過 skip box
    straight_arrow(ax, 5.0, steps[2][1], steps[3][1] + steps[3][3],
                   color="#444")

    # ── Bypass Arrow ─────────────────────────────────────────────────────────
    # 路徑：bottom of CreateProcess → 左繞 → top of WriteProcessMemory
    BY_X  = 1.2   # 繞道 x 座標
    START = (5.0, steps[0][1])              # CreateProcess 底部
    P1    = (5.0, steps[0][1] - 0.2)       # 稍往下
    P2    = (BY_X, steps[0][1] - 0.2)      # 往左
    P3    = (BY_X, steps[2][1] + steps[2][3] + 0.1)  # 往下（WriteProcessMemory 上方）
    END   = (steps[2][0], steps[2][1] + steps[2][3] * 0.5)  # WriteProcessMemory 左緣

    bypass_xs = [START[0], P1[0], P2[0], P3[0], P3[0]]
    bypass_ys = [START[1], P1[1], P2[1], P3[1], END[1]]

    ax.plot(bypass_xs, bypass_ys,
            color=C_ORANGE, lw=2.0, ls="--", zorder=5,
            solid_capstyle="round")
    ax.annotate("", xy=END, xytext=(P3[0], END[1]),
                arrowprops=dict(arrowstyle="-|>", color=C_ORANGE, lw=2.0),
                zorder=6)

    # "SKIP" 標籤貼在繞道旁
    ax.text(BY_X - 0.08, (steps[0][1] + steps[2][1] + steps[2][3]) / 2,
            "SKIP", ha="right", va="center",
            fontsize=9, color=C_ORANGE, fontweight="bold",
            rotation=90, zorder=6)

    # Event 25 NOT 標籤（打叉）
    ax.add_patch(FancyBboxPatch(
        (8.2, 6.3), 1.55, 0.78,
        boxstyle="round,pad=0.1",
        facecolor="#fef0ee", edgecolor=C_RED, linewidth=1.5, zorder=4))
    ax.text(8.98, 6.68, "Event 25\n不觸發 ✗", ha="center", va="center",
            fontsize=8.5, color=C_RED, fontweight="bold", zorder=5)

    plt.tight_layout(pad=1.2)
    path = OUT / "evasion_comparison.png"
    fig.savefig(path, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"[+] {path}")


# ══════════════════════════════════════════════════════════════════════════════
# 圖 4：系統架構圖
# ══════════════════════════════════════════════════════════════════════════════
def make_architecture_diagram():
    """
    figsize=(14,6) dpi=100 → PNG 1400px；slide w:1050 → scale 0.75
    PNG 內用 24pt → slide 顯示 ≈ 18pt；4 box × w=3.0 gap=0.5 有足夠呼吸空間
    """
    fig, ax = plt.subplots(figsize=(14, 6.0))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 6.0)
    ax.axis("off")
    fig.patch.set_facecolor("white")

    C_ATK = "#c0392b"; C_LOG = "#0e6655"
    C_VAL = "#6c3483"; C_RPT = "#5d6d7e"
    C_SUT = "#1f618d"; C_ORC = "#7d3c98"

    def box(x, y, w, h, title, body, fc, bg,
            cap_fs=24, body_fs=19, lw=2.5, ls="-"):
        ax.add_patch(FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0.18",
            facecolor=bg, edgecolor=fc, linewidth=lw, linestyle=ls, zorder=3))
        cap_h = 0.55
        ax.add_patch(Rectangle(
            (x + 0.15, y + h - cap_h), w - 0.30, cap_h,
            facecolor=fc, edgecolor="none", zorder=4))
        ax.text(x + w/2, y + h - cap_h/2, title,
                ha="center", va="center", fontsize=cap_fs,
                color="white", fontweight="bold", zorder=5)
        if body:
            ax.text(x + w/2, y + (h - cap_h) * 0.5, body,
                    ha="center", va="center", fontsize=body_fs,
                    color=fc, zorder=5, linespacing=1.5)

    def harrow(x1, x2, y, col, lbl="", lw=2.2):
        ax.annotate("", xy=(x2, y), xytext=(x1, y),
                    arrowprops=dict(arrowstyle="-|>", color=col, lw=lw), zorder=6)
        if lbl:
            ax.text((x1 + x2) / 2, y + 0.15, lbl,
                    ha="center", va="bottom", fontsize=22,
                    color=col, fontweight="bold")

    def dashed_up(x, y_bot, y_top, col, lw=2.0):
        ax.plot([x, x], [y_bot, y_top - 0.10], "--", color=col, lw=lw, zorder=5)
        ax.annotate("", xy=(x, y_top), xytext=(x, y_top - 0.10),
                    arrowprops=dict(arrowstyle="-|>", color=col, lw=lw), zorder=6)

    # ══════════════════════════════════════════════════════════════════════
    # 4 box × w=3.0，gap=0.5，xlim=14
    # PNG 24pt → slide scale 0.75 → 顯示 18pt ✓
    # ══════════════════════════════════════════════════════════════════════
    BH = 2.60; BY = 2.50
    MID = BY + BH / 2  # y = 3.80

    box(0.25, BY, 3.0, BH, "run_all.py",    "Orchestrator",             C_VAL, "#f5eef8")
    box(3.75, BY, 3.0, BH, "technique.py",  "攻擊模擬\nPython/C#/PS",   C_ATK, "#fdf2e9")
    box(7.25, BY, 3.0, BH, "Sysmon Log",    "kernel callback\n→ XML",    C_LOG, "#e8f8f5")
    box(10.75, BY, 3.0, BH, "check_logs.py",
        "XPath 查詢\nEvent ID 比對\n→ report.html", C_VAL, "#f5eef8")

    harrow(3.25,  3.75,  MID, C_VAL, "calls")
    harrow(6.75,  7.25,  MID, C_ATK, "寫入 Log")
    harrow(10.25, 10.75, MID, C_LOG, "reads")

    # ── config boxes（虛線↑）──────────────────────────────────────────────
    SH = 1.30; SY = 0.85

    box(7.25, SY, 3.0, SH, "SUT Config",  "sysmon-modular.xml",   C_SUT, "#d6eaf8",
        cap_fs=22, body_fs=17, lw=2.0, ls="--")
    box(10.75, SY, 3.0, SH, "Oracle Spec", "expected_events.json", C_ORC, "#f0e6fa",
        cap_fs=22, body_fs=17, lw=2.0, ls="--")

    dashed_up(8.75,  SY + SH, BY, C_SUT)   # Sysmon Log 中心 x
    dashed_up(12.25, SY + SH, BY, C_ORC)   # check_logs 中心 x

    ax.set_title("Sysmon 驗測框架 — 系統架構",
                 fontsize=28, fontweight="bold", color="#1a1a2e", pad=14)

    plt.tight_layout(pad=0.4)
    path = OUT / "architecture.png"
    fig.savefig(path, dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"[+] {path}")


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("[*] 產生簡報圖表 v2...")
    make_coverage_chart()
    make_oracle_timeline()
    make_evasion_comparison()
    make_architecture_diagram()
    print("[*] 完成 → slides_assets/")
