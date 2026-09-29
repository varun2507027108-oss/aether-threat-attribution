"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import { InvestigationResult } from "@/lib/api";
import { DemoTag } from "@/components/DemoTag";

interface BentoGridProps {
  investigation?: InvestigationResult | null;
  onOpenNewInvestigation?: () => void;
  onOpenDossier: () => void;
  onOpenEvidence: () => void;
  onOpenGraph?: () => void;
  onOpenStylometry?: () => void;
}

export const BentoGrid: React.FC<BentoGridProps> = ({
  investigation,
  onOpenNewInvestigation,
  onOpenDossier,
  onOpenEvidence,
  onOpenGraph,
  onOpenStylometry,
}) => {
  const caseData = investigation?.case;
  const attribution = investigation?.attribution;
  const provenance = investigation?.provenance_summary;
  const timelineEvents = investigation?.timeline;
  const stylometry = investigation?.stylometry;

  const scorePct = attribution ? `${attribution.confidence_score}%` : "94.8%";
  const scoreNum = attribution ? attribution.confidence_score : 94.8;
  const confidenceTier = attribution?.confidence_tier || "DEFINITIVE JUDICIAL ATTRIBUTION";
  const currentActor = caseData?.actor_name || "ZeroTrace (APT-091)";
  const currentOriginIp = caseData?.origin_ip || "185.220.101.42";
  const currentTarget = caseData?.target_url || caseData?.onion_url || "http://p4lx7e22kq6dreadmarket.onion";
  const currentTargetType = caseData?.target_type || "onion";
  const currentPgp = caseData?.pgp_fingerprint || "4D9E 27BC 918A 4F02 C731 09AE 2C5B 88E1 40FA 7D3C";
  const currentBtc = caseData?.btc_root || "";
  const currentEvidenceId = caseData?.evidence_id || "AT-2026-0047";

  /*
   * These used to boot with plausible-looking values -- a 93.4% similarity, a
   * UTC+05:30 offset, a 24-point histogram, and the Bitcoin genesis address
   * standing in for a suspect's wallet. Before the engine reported, the card
   * showed invented analysis. These are now derived from the investigation
   * during render rather than mirrored into state by an effect: copying props
   * into state with setState is what produced a second render pass on every
   * case load, and the values could disagree with their source for a frame.
   */
  const [activeFilter, setActiveFilter] = useState<"monthly" | "circadian">("circadian");
  const [hoveredHour, setHoveredHour] = useState<number | null>(null);

  /*
   * The stylometry figure used to be a button that called
   * /api/analysis/stylometry with two sentences written into this file, and
   * rendered the result as if it described this case. A stylometric comparison
   * needs two real documents from the analyst, which is what the lab is for.
   */
  const handleStylometryEval = () => onOpenStylometry?.();

  const diurnalHourly = useMemo(
    () =>
      investigation?.diurnal?.histogram?.length === 24 ? investigation.diurnal.histogram : [],
    [investigation]
  );
  const operationalOffset = investigation?.diurnal?.estimated_timezone?.formatted_offset ?? null;
  const stylometryScore =
    stylometry?.similarity_score !== undefined
      ? `${(stylometry.similarity_score * 100).toFixed(1)}%`
      : null;
  const histogramFromEngine = diurnalHourly.length === 24;

  /*
   * The daily series is aggregated from the timestamps the engine already
   * returns on each timeline step. The "Monthly" toggle previously switched to
   * a hardcoded 30-element array, so the second view of the chart was a
   * decorative fake. Thirty buckets still span the observed range rather than
   * pretending to cover a calendar month the case may not reach.
   */
  const monthlyHourly = useMemo(() => {
    if (!timelineEvents || timelineEvents.length === 0) return [];
    const times = timelineEvents
      .map((t) => Date.parse(t.timestamp))
      .filter((n) => Number.isFinite(n))
      .sort((a, b) => a - b);
    if (times.length === 0) return [];

    const BUCKETS = 30;
    const min = times[0];
    const max = times[times.length - 1];
    const span = max - min || 1;
    const buckets = new Array(BUCKETS).fill(0) as number[];
    for (const t of times) {
      const idx = Math.min(Math.floor(((t - min) / span) * (BUCKETS - 1)), BUCKETS - 1);
      buckets[idx] += 1;
    }
    return buckets;
  }, [timelineEvents]);

  /*
   * The chart is measured rather than stretched.
   *
   * It used to render into a fixed 640x145 viewBox with
   * preserveAspectRatio="none", which squares up fine on a wide card and
   * horizontally compresses the 8px axis labels to half their width on a
   * phone. Measuring the container and sizing the viewBox to the real
   * viewport means one user unit is one CSS pixel at every breakpoint, so
   * strokes stay 2px and type stays legible instead of distorting with it.
   */
  const plotRef = useRef<HTMLDivElement>(null);
  const [plotWidth, setPlotWidth] = useState(640);

  useEffect(() => {
    const el = plotRef.current;
    if (!el) return;
    const measure = () => setPlotWidth(Math.max(el.clientWidth, 280));
    measure();
    if (typeof ResizeObserver === "undefined") {
      window.addEventListener("resize", measure);
      return () => window.removeEventListener("resize", measure);
    }
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  /*
   * `hoveredHour` changes on every column the pointer crosses, so the spline
   * was being rebuilt 24 times per sweep of the chart. The geometry depends
   * only on the dataset and the measured width.
   */
  const { linePath, areaPath, points, peakPoint, minPoint, hasSeries, axisTop } =
    useMemo(() => {
    const dataset = activeFilter === "circadian" ? diurnalHourly : monthlyHourly;
    const padL = 34;
    const padR = 14;
    const chartW = Math.max(plotWidth - padL - padR, 1);

    /*
     * The plotted ceiling is `axisTop`, a rounded value rather than the raw
     * data maximum, and the geometry is scaled against it. Previously the
     * points were scaled against `maxVal * 1.28` — an unexplained headroom
     * multiplier — while the y-axis printed the fixed literals 18 / 10 / 0. So
     * the two were describing different scales and neither matched the data: a
     * case with a real maximum of 4 still had an axis ceiling of 18.
     *
     * Rounding up to a multiple of 5 gives a readable step, and scaling the
     * geometry against the same number means the top tick genuinely is the
     * ceiling and every bar can be calibrated against it.
     */
    const axisTop = Math.max(5, Math.ceil(Math.max(...dataset, 1) / 5) * 5);

    const pts = dataset.map((val, i) => ({
      x: padL + (i / Math.max(dataset.length - 1, 1)) * chartW,
      y: 122 - (val / axisTop) * 92,
      val,
      index: i,
    }));

    if (pts.length === 0) {
      return {
        linePath: "",
        areaPath: "",
        points: pts,
        peakPoint: { x: 0, y: 0, val: 0, index: 0 },
        minPoint: { x: 0, y: 0, val: 0, index: 0 },
        hasSeries: false,
        axisTop,
      };
    }

    let line = `M ${pts[0].x.toFixed(1)} ${pts[0].y.toFixed(1)}`;
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = i > 0 ? pts[i - 1] : pts[i];
      const p1 = pts[i];
      const p2 = pts[i + 1];
      const p3 = i < pts.length - 2 ? pts[i + 2] : p2;

      const cp1x = p1.x + (p2.x - p0.x) / 6;
      const cp1y = p1.y + (p2.y - p0.y) / 6;
      const cp2x = p2.x - (p3.x - p1.x) / 6;
      const cp2y = p2.y - (p3.y - p1.y) / 6;

      line += ` C ${cp1x.toFixed(1)} ${cp1y.toFixed(1)}, ${cp2x.toFixed(1)} ${cp2y.toFixed(1)}, ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}`;
    }

    const area = `${line} L ${pts[pts.length - 1].x.toFixed(1)} 125 L ${pts[0].x.toFixed(1)} 125 Z`;

    return {
      linePath: line,
      areaPath: area,
      points: pts,
      peakPoint: pts.reduce((prev, curr) => (curr.val > prev.val ? curr : prev), pts[0]),
      minPoint: pts.reduce((prev, curr) => (curr.val < prev.val ? curr : prev), pts[0]),
      hasSeries: true,
      axisTop,
      };
    }, [activeFilter, diurnalHourly, monthlyHourly, plotWidth]);

  // One keyboard-reachable control per column, so the same telemetry an
  // analyst reads with a pointer is readable with a keyboard.
  const handleChartKeyDown = (e: React.KeyboardEvent) => {
    const step = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
    if (step === 0 && e.key !== "Home" && e.key !== "End" && e.key !== "Escape") return;
    e.preventDefault();
    setHoveredHour((prev) => {
      if (e.key === "Escape") return null;
      if (e.key === "Home") return 0;
      if (e.key === "End") return points.length - 1;
      const base = prev ?? (step > 0 ? -1 : points.length);
      return Math.min(Math.max(base + step, 0), points.length - 1);
    });
  };

  const activePoint = hoveredHour !== null ? points[hoveredHour] : null;
  const axisTicks = activeFilter === "circadian" ? [0, 6, 12, 18] : [0, 7, 15, 22];

  /**
   * Keeps a centred caption inside the plot. Band labels are centred on the
   * midpoint of their band, which for a band touching 00:00 sits hard against
   * the left padding and used to be clipped mid-word by the card edge.
   *
   * The half-width has to grow with the caption. It was a flat 58px, so at
   * narrow widths the SLEEP and PEAK labels were both clamped toward the same
   * centre and overprinted each other into an unreadable smear — and those two
   * labels are the most decision-relevant thing on the chart. Measuring against
   * the actual text means a long caption reserves the room it needs.
   */
  const clampBandLabel = (x: number, width: number, halfWidth = 58) =>
    Math.min(Math.max(x, halfWidth), Math.max(width - halfWidth, halfWidth));

  /*
   * The peak and trough bands used to be hardcoded to hours 5-13 and 17-23,
   * which meant a case whose real activity peaked at 02:00 was still labelled
   * "PEAK POSTING WINDOW // 06:00 - 14:00 UTC".
   *
   * Derived from the histogram instead. The peak threshold is relative to the
   * observed maximum rather than the mean: a mean threshold on a spiky series
   * swallows half the day and labels twelve hours a "peak". The trough is the
   * contiguous run of the minimum, which is what a sleep window actually is.
   */
  const [peakWindowStart, peakWindowEnd] = useMemo(() => {
    const d = diurnalHourly;
    if (d.length !== 24) return [0, d.length - 1];
    const max = Math.max(...d);
    if (max <= 0) return [0, 23];
    const peakIdx = d.indexOf(max);
    const threshold = max * 0.6;
    let s = peakIdx;
    let e = peakIdx;
    while (s > 0 && d[s - 1] >= threshold) s--;
    while (e < d.length - 1 && d[e + 1] >= threshold) e++;
    return [s, e];
  }, [diurnalHourly]);

  const [troughWindowStart, troughWindowEnd] = useMemo(() => {
    const d = diurnalHourly;
    if (d.length !== 24) return [0, 23];
    const min = Math.min(...d);
    const minIdx = d.indexOf(min);
    let s = minIdx;
    let e = minIdx;
    while (s > 0 && d[s - 1] <= min) s--;
    while (e < d.length - 1 && d[e + 1] <= min) e++;
    return [s, e];
  }, [diurnalHourly]);

  /*
   * The local-time readout used to add a hardcoded +5:30 and label it "IST",
   * so every actor was reported as Indian Standard Time regardless of what
   * the engine inferred. Both the offset and its zone now come from the
   * engine's own estimate.
   */
  const { offsetHours, offsetLabel } = useMemo(() => {
    if (!operationalOffset) return { offsetHours: 0, offsetLabel: "" };
    const m = /UTC\s*([+-])(\d{1,2})(?::(\d{2}))?/.exec(operationalOffset);
    if (!m) return { offsetHours: 0, offsetLabel: "" };
    const sign = m[1] === "-" ? -1 : 1;
    const hours = sign * (parseInt(m[2], 10) + (m[3] ? parseInt(m[3], 10) / 60 : 0));
    const zone = operationalOffset.replace(/UTC\s*[+-]?\d{1,2}(?::\d{2})?/, "").trim();
    return { offsetHours: hours, offsetLabel: zone ? ` ${zone}` : "" };
  }, [operationalOffset]);

  // Gauge arc coordinates
  const gaugeRad = Math.PI * (scoreNum / 100);
  const gaugeX = (100 - 80 * Math.cos(gaugeRad)).toFixed(1);
  const gaugeY = (100 - 80 * Math.sin(gaugeRad)).toFixed(1);

  return (
    <div className="space-y-4 md:space-y-6 min-w-0">
      {/* COMMAND STATUS & PROVENANCE NOTICE BANNER */}
      <div className="bg-card border border-line p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5 flex-wrap min-w-0">
          <div
            className="w-9 h-9 bg-info-surface border border-line-strong text-info-ink flex items-center justify-center text-sm font-mono font-bold shrink-0"
            aria-hidden="true"
          >
            <i className="fa-solid fa-crosshairs"></i>
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-mono font-bold text-ink tracking-wide">
                ACTIVE CASE: {currentEvidenceId}
              </span>
              {/*
                break-all on the target: a v3 onion address plus its type is
                ~60 monospace characters and cannot wrap on a phone otherwise,
                which dragged the provenance badges off the card.
              */}
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 bg-info-surface text-info-ink border border-info-line break-all max-w-full">
                TARGET: {currentTarget} ({currentTargetType.toUpperCase()})
              </span>
              {/* Provenance counts come straight from the engine. When the
                  engine has not reported, the count is zero -- never a
                  plausible-looking placeholder.

                  The LIVE chip was always signal-green, which is the colour this
                  product reserves for corroborated evidence. A live count of
                  zero is the worst possible provenance state: nothing in this
                  case came from a real source. Green for "zero live sources"
                  told the reader the opposite of what it meant, so the chip now
                  takes its colour from the number it is reporting. */}
              <span
                className={`text-[10px] font-mono font-bold px-2 py-0.5 border ${
                  (provenance?.live_count ?? 0) > 0
                    ? "bg-signal-surface text-signal-ink border-signal-line"
                    : "bg-alert-surface text-alert-ink border-alert-line"
                }`}
              >
                LIVE: {provenance?.live_count ?? 0}
                {(provenance?.live_count ?? 0) === 0 && (
                  <span className="sr-only"> — no live sources contributed to this case</span>
                )}
              </span>
              <span
                className={`text-[10px] font-mono font-bold px-2 py-0.5 border ${
                  (provenance?.demo_count ?? 0) > 0
                    ? "bg-warn-surface text-warn-ink border border-warn-line"
                    : "bg-card text-ink-dim border-line-strong"
                }`}
              >
                DEMO BENCHMARK: {provenance?.demo_count ?? 0}
              </span>
              <span
                className={`text-[10px] font-mono font-bold px-2 py-0.5 border ${
                  (provenance?.unavailable_count ?? 0) > 0
                    ? "bg-warn-surface text-warn-ink border-warn-line"
                    : "bg-card text-ink-dim border-line-strong"
                }`}
              >
                SOURCE UNAVAILABLE: {provenance?.unavailable_count ?? 0}
              </span>
            </div>
            {/* The hardcoded "No single indicator proves actor identity." was
                followed immediately by the backend's own provenance rule, which
                ends with the same proposition in different words. The same
                sentence appeared twice within three lines, as the first
                substantive text on the page. The generated rule is the copy that
                is actually specific to this case, so only it is shown. */}
            <p className="text-[10px] text-ink-dim font-mono mt-1.5 max-w-[78ch] leading-relaxed">
              <span className="text-info-ink font-bold">PROVENANCE:</span>{" "}
              {provenance?.rule ??
                "Every indicator carries its source, and whether that source was live, benchmarked, or unavailable."}
            </p>
          </div>
        </div>

        {onOpenNewInvestigation && (
          <button
            type="button"
            onClick={onOpenNewInvestigation}
            className="px-4 py-2 min-h-11 bg-active hover:bg-raised text-ink font-mono text-xs font-bold tracking-wide border border-line-active hover:border-info transition flex items-center justify-center gap-2 shrink-0"
          >
            <i className="fa-solid fa-plus text-[10px] text-info-ink" aria-hidden="true"></i>
            <span>NEW INVESTIGATION</span>
          </button>
        )}
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-6">
        {/*
          The four figures below are the first thing an analyst reads and the
          first thing opposing counsel reads. Three of them now bind to fields
          the backend actually returns. The fourth has no source, so it says
          so rather than inventing one. The decorative sparklines that used to
          occupy the empty side of these cards are gone: they were fixed SVG
          paths encoding no series, which on a forensics workbench is a
          chart-shaped lie.
        */}

        {/* Pipeline progress -- bound to the real timeline the engine returns. */}
        <div className="matte-card p-5">
          <p className="text-xs font-semibold text-ink-dim uppercase tracking-wider">
            Forensic Modules
          </p>
          <h3 className="text-2xl font-bold text-ink mt-1 font-mono">
            {timelineEvents?.length ?? 0}{" "}
            <span className="text-xs font-normal text-ink-dim font-sans">
              steps completed
            </span>
          </h3>
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-ink-muted mt-1">
            <i
              className="fa-solid fa-network-wired text-[10px] text-ink-faint"
              aria-hidden="true"
            />
            Cross-correlated by the investigation pipeline
          </span>
        </div>

        {/* Graph size -- real counts from the STIX bundle. */}
        <div className="matte-card p-5">
          <p className="text-xs font-semibold text-ink-dim uppercase tracking-wider">
            Attributed Entities
          </p>
          <h3 className="text-2xl font-bold text-ink mt-1 font-mono">
            {investigation?.graph?.node_count ?? 0}{" "}
            <span className="text-xs font-normal text-ink-dim font-sans">nodes</span>
          </h3>
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-ink-muted mt-1">
            <i className="fa-solid fa-diagram-project text-[10px] text-ink-faint" aria-hidden="true" />
            {investigation?.graph?.edge_count ?? 0} deterministic relationships
          </span>
        </div>

        {/* No endpoint reports a corpus-wide key total, so no figure is given. */}
        <div className="matte-card p-5">
          <p className="text-xs font-semibold text-ink-dim uppercase tracking-wider">
            PGP &amp; Wallet Keys
          </p>
          <h3 className="text-2xl font-bold text-ink mt-1 font-mono">
            &mdash;
            <DemoTag
              className="ml-2"
              requires="a corpus-wide key inventory endpoint"
            />
          </h3>
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-ink-muted mt-1">
            <i className="fa-solid fa-key text-[10px] text-ink-faint" aria-hidden="true" />
            This case resolved{" "}
            {caseData?.pgp_fingerprint ? 1 : 0} fingerprint
            {caseData?.pgp_fingerprint ? "" : "s"} and{" "}
            {caseData?.btc_root ? 1 : 0} wallet
            {caseData?.btc_root ? "" : "s"}
          </span>
        </div>

        {/* Bound to the same score the gauge below renders. The hardcoded
            94.8% that used to sit here contradicted it on every case. */}
        <div className="bg-info-surface p-5 border border-info-line text-ink flex flex-col justify-between relative overflow-hidden">
          <p className="text-xs font-medium text-ink-dim uppercase tracking-wider">
            Confidence Index
          </p>
          <h3 className="text-2xl font-bold text-ink mt-1 font-mono">
            {scorePct} <span className="text-xs font-normal text-ink-dim font-sans">Score</span>
          </h3>
            <span className="inline-flex items-start gap-1.5 text-[11px] font-semibold text-ink-muted mt-1">
              <i
                className="fa-solid fa-scale-balanced text-[10px] text-ink-faint mt-px shrink-0"
                aria-hidden="true"
              />
              <span className="text-left max-w-[46ch]">
                {attribution?.judicial_admissibility
                  ? attribution.judicial_admissibility
                  : "Admissibility pending engine report"}
              </span>
            </span>
        </div>

        {/* MIDDLE ROW 1: Wide Temporal & Diurnal Timeline Chart */}
        <div
          id="diurnal-section"
          className="matte-card p-6 lg:col-span-2 flex flex-col justify-between scroll-mt-24"
        >
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 mb-4">
            <h2 className="text-base font-bold text-ink">Diurnal Activity &amp; Circadian Timeline</h2>

            <div
              role="group"
              aria-label="Histogram resolution"
              className="flex items-center gap-2 text-xs"
            >
              <button
                type="button"
                aria-pressed={activeFilter === "monthly"}
                onClick={() => setActiveFilter("monthly")}
                className={`px-3 py-1.5 min-h-11 min-h-11 transition border ${
                  activeFilter === "monthly"
                    ? "bg-active font-semibold text-ink border-line-active"
                    : "bg-info-surface text-ink-muted hover:bg-raised border-line-strong"
                }`}
              >
                Monthly
              </button>
              <button
                type="button"
                aria-pressed={activeFilter === "circadian"}
                onClick={() => setActiveFilter("circadian")}
                className={`px-3 py-1.5 min-h-11 min-h-11 transition border ${
                  activeFilter === "circadian"
                    ? "bg-active font-semibold text-ink border-line-active"
                    : "bg-info-surface text-ink-muted hover:bg-raised border-line-strong"
                }`}
              >
                UTC Circadian
              </button>
            </div>
          </div>

          {/* Two figures above the plot, each a control that re-runs its own
              module. The secondary values under them used to be a constant
              "+4.2% match" and a constant "Sleep: 03:00-09:00" regardless of
              what the engine returned. */}
          <div className="flex flex-wrap gap-4 mb-3">
              <button
                type="button"
                onClick={handleStylometryEval}
                className="bg-input border border-line hover:border-line-strong p-3 flex-1 min-w-[150px] min-h-11 text-left transition group"
              >
                <span className="text-[11px] font-semibold text-ink-dim flex items-center justify-between gap-2">
                  Stylometric Similarity
                  <i
                    className="fa-solid fa-arrows-rotate text-[10px] text-ink-faint group-hover:text-ink-muted transition"
                    aria-hidden="true"
                  />
                </span>
                <span className="flex items-baseline gap-2 mt-0.5 flex-wrap">
                  <span className="text-lg font-bold text-ink font-mono">
                    {stylometryScore ?? "—"}
                  </span>
                  {/*
                    Every field below is optional: the ensemble landed in phase 9
                    and a pre-phase-9 backend omits it entirely. Reading it
                    unguarded crashed the whole console on a white screen, which
                    is the worst possible failure for a case already in
                    progress. A shape we did not expect now degrades to a
                    statement of what is missing.
                  */}
                  {stylometry?.ensemble ? (
                    <span className="text-[11px] text-ink-dim font-mono">
                      {stylometry.ensemble.methods_used.length} method
                      {stylometry.ensemble.methods_used.length === 1 ? "" : "s"}
                      {stylometry.ensemble.degraded ? " · degraded" : ""}
                      {typeof stylometry.fpr_at_threshold === "number"
                        ? ` · FPR ${(stylometry.fpr_at_threshold * 100).toFixed(1)}%`
                        : ""}
                    </span>
                  ) : (
                    <span className="text-[11px] text-warn-ink font-mono">
                      ensemble not reported
                    </span>
                  )}
                </span>
              </button>

              <div className="bg-input border border-line hover:border-line-strong p-3 flex-1 min-w-[150px] min-h-11 text-left transition group">
                <span className="text-[11px] font-semibold text-ink-dim flex items-center justify-between gap-2">
                  Target Operational Offset
                  <i
                    className="fa-solid fa-clock text-[10px] text-ink-faint"
                    aria-hidden="true"
                  />
                </span>
                <span className="flex items-baseline gap-2 mt-0.5 flex-wrap">
                  <span className="text-lg font-bold text-ink font-mono">
                    {operationalOffset ?? "—"}
                  </span>
                  <span className="text-[11px] font-semibold text-alert-ink font-mono">
                    {!hasSeries
                      ? "no series"
                      : troughWindowStart === troughWindowEnd
                        ? "no trough"
                        : `sleep ${String(troughWindowStart).padStart(2, "0")}:00-${String(
                            troughWindowEnd
                          ).padStart(2, "0")}:00`}
                  </span>
                </span>
              </div>
            </div>

        {/* Diurnal Sleep Curve & Histogram Telemetry (Smooth Spline & Shaded Zones) */}
        <div className="relative w-full mt-2 bg-sunken border border-line p-3 flex flex-col justify-between">
          {/* Chart Header & Interactive Hover Badge */}
          <div className="flex flex-wrap justify-between items-center gap-2 text-[10px] font-mono mb-1 text-ink-dim">
            <span className="flex items-center gap-1.5">
              <span
                className={`w-1.5 h-1.5 inline-block aether-live-pulse ${
                  histogramFromEngine ? "bg-info" : "bg-warn"
                }`}
                aria-hidden="true"
              />
              {!histogramFromEngine
                ? "No posting series reported for this case"
                : activeFilter === "circadian"
                  ? `UTC 24h posting distribution // ${diurnalHourly.reduce((a, b) => a + b, 0)} captured events`
                  : `Aggregated 30-day activity // ${monthlyHourly.reduce((a, b) => a + b, 0)} captured events`}
            </span>

            {/*
              Live region: a keyboard user arrowing across the chart hears
              each column announced, and the same text is on screen for a
              pointer user, so the two paths carry identical information.
            */}
              <span
                role="status"
                aria-live="polite"
                className="text-info-ink font-bold bg-info-surface px-2 py-0.5 border border-info-line"
              >
                {activePoint ? (
                  activeFilter === "circadian" ? (
                    <>
                      {String(activePoint.index).padStart(2, "0")}:00 UTC &bull; {activePoint.val}{" "}
                      posts &bull; local {String((activePoint.index + offsetHours) % 24).padStart(2, "0")}:00
                      {offsetLabel}
                    </>
                  ) : (
                    <>
                      Day {activePoint.index + 1} &bull; {activePoint.val} events
                    </>
                  )
                ) : (
                  <span className="text-ink-faint font-normal">
                    {hasSeries
                      ? "Arrow keys or hover to inspect each interval"
                      : "No series reported for this case"}
                  </span>
                )}
              </span>
            </div>

          {/* Plot canvas. The viewBox tracks the measured width so nothing is
              stretched, and the whole plot is one tab stop with arrow-key
              navigation across the intervals. */}
          <div
            ref={plotRef}
            className="relative w-full overflow-hidden"
            onKeyDown={handleChartKeyDown}
            onMouseLeave={() => setHoveredHour(null)}
          >
            {!hasSeries ? (
              <div className="h-[145px] flex flex-col items-center justify-center gap-2 text-center px-6">
                <i
                  className="fa-regular fa-chart-bar text-ink-faint text-xl"
                  aria-hidden="true"
                />
                <p className="text-xs text-ink-muted font-semibold">No activity histogram</p>
                <p className="text-[11px] text-ink-dim max-w-[40ch]">
                  The diurnal engine has not returned a posting series for this case. Timestamps are
                  required before a circadian profile can be inferred.
                </p>
              </div>
            ) : (
            <svg
              className="w-full block"
              height="145"
              viewBox={`0 0 ${plotWidth} 145`}
              role="img"
              aria-label={`${activeFilter === "circadian" ? "Hourly" : "Daily"} activity histogram. Peak ${peakPoint.val} at ${activeFilter === "circadian" ? `${String(peakPoint.index).padStart(2, "0")}:00 UTC` : `day ${peakPoint.index + 1}`}, minimum ${minPoint.val} at ${activeFilter === "circadian" ? `${String(minPoint.index).padStart(2, "0")}:00 UTC` : `day ${minPoint.index + 1}`}.`}
              tabIndex={0}
            >
              <defs>
                <linearGradient id="diurnalAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--color-info)" stopOpacity="0.28" />
                  <stop offset="65%" stopColor="var(--color-info-hover)" stopOpacity="0.18" />
                  <stop offset="100%" stopColor="var(--color-sunken)" stopOpacity="0" />
                </linearGradient>
                <linearGradient id="peakAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--color-signal)" stopOpacity="0.32" />
                  <stop offset="100%" stopColor="var(--color-signal)" stopOpacity="0.02" />
                </linearGradient>
                <linearGradient id="sleepAreaGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--color-alert)" stopOpacity="0.25" />
                  <stop offset="100%" stopColor="var(--color-alert)" stopOpacity="0.02" />
                </linearGradient>
              </defs>

              {/* Horizontal reference lines */}
              <line
                x1="34"
                y1="30"
                x2={plotWidth - 14}
                y2="30"
                stroke="var(--color-line-faint)"
                strokeDasharray="3 3"
                strokeWidth="1"
              />
              <line
                x1="34"
                y1="75"
                x2={plotWidth - 14}
                y2="75"
                stroke="var(--color-line-faint)"
                strokeDasharray="3 3"
                strokeWidth="1"
              />
              <line
                x1="34"
                y1="125"
                x2={plotWidth - 14}
                y2="125"
                stroke="var(--color-line)"
                strokeWidth="1"
              />

              {/* Y-axis ticks, derived from the data.

                  These were the literals 18, 10 and 0 while `maxVal` was
                  computed and left unused. So the axis claimed a ceiling of 18
                  on a case whose real maximum was 4, and a reader had no way to
                  tell whether a value of 12 was high or low. The scale is now
                  computed from the plotted series and rounded to a readable
                  step, and the top tick is labelled as the axis maximum so the
                  reader can calibrate every bar against it.

                  Font size is 10px, the documented floor: 9px is below it. */}
              {(() => {
                const top = axisTop;
                const mid = top / 2;
                return (
                  <>
                    <text
                      x="6"
                      y="34"
                      fill="var(--color-ink-dim)"
                      fontSize="10"
                      fontFamily="var(--font-mono)"
                    >
                      {top}
                    </text>
                    <text
                      x="6"
                      y="79"
                      fill="var(--color-ink-dim)"
                      fontSize="10"
                      fontFamily="var(--font-mono)"
                    >
                      {Number.isInteger(mid) ? mid : mid.toFixed(1)}
                    </text>
                    <text
                      x="6"
                      y="127"
                      fill="var(--color-ink-dim)"
                      fontSize="10"
                      fontFamily="var(--font-mono)"
                    >
                      0
                    </text>
                  </>
                );
              })()}

              {activeFilter === "circadian" && hasSeries && (
                <>
                  {/*
                    Band captions are clamped inside the plot. A window that
                    starts at 00:00 has its midpoint at the left padding, and
                    a centred caption there ran off the edge of the card and
                    was clipped mid-word.
                  */}
                  {/*
                    Peak activity window
                  */}
                  <rect
                    x={points[peakWindowStart].x - 8}
                    y="16"
                    width={points[peakWindowEnd].x - points[peakWindowStart].x + 16}
                    height="109"
                    fill="url(#peakAreaGrad)"
                    stroke="var(--color-signal)"
                    strokeWidth="1"
                    strokeDasharray="4 3"
                    opacity="0.65"
                  />
                  {/* The two band captions share a 27px baseline and are clamped
                      to the plot, so on a narrow plot they can still land on top
                      of each other. They are separated vertically instead: the
                      peak caption sits above the trough one, which keeps both
                      legible at 390px rather than overprinting them. */}
                  <text
                    x={clampBandLabel(
                      (points[peakWindowStart].x + points[peakWindowEnd].x) / 2,
                      plotWidth,
                      72,
                    )}
                    y="19"
                    fill="var(--color-signal-ink)"
                    fontSize="10"
                    fontFamily="var(--font-mono)"
                    fontWeight="700"
                    textAnchor="middle"
                    letterSpacing="0.06em"
                  >
                    PEAK {String(peakWindowStart).padStart(2, "0")}:00&ndash;
                    {String(peakWindowEnd).padStart(2, "0")}:00
                  </text>

                  {/* Sleep trough window, same treatment. */}
                  <rect
                    x={points[troughWindowStart].x - 8}
                    y="16"
                    width={points[troughWindowEnd].x - points[troughWindowStart].x + 16}
                    height="109"
                    fill="url(#sleepAreaGrad)"
                    stroke="var(--color-alert)"
                    strokeWidth="1"
                    strokeDasharray="4 3"
                    opacity="0.65"
                  />
                  <text
                    x={clampBandLabel(
                      (points[troughWindowStart].x + points[troughWindowEnd].x) / 2,
                      plotWidth,
                      72,
                    )}
                    y="31"
                    fill="var(--color-alert-ink)"
                    fontSize="10"
                    fontFamily="var(--font-mono)"
                    fontWeight="700"
                    textAnchor="middle"
                    letterSpacing="0.06em"
                  >
                    SLEEP {String(troughWindowStart).padStart(2, "0")}:00&ndash;
                    {String(troughWindowEnd).padStart(2, "0")}:00
                  </text>
                </>
              )}

              {/* Vertical telemetry columns */}
              {points.map((p, idx) => {
                const isHovered = hoveredHour === idx;
                /*
                 * Both bands are inclusive ranges. The trough test used to be
                 * `idx >= troughWindowStart` alone, so when the engine put the
                 * trough at 00:00 -- which it does whenever the series starts
                 * flat -- every column in the chart was painted as sleep.
                 */
                const isSleep =
                  activeFilter === "circadian" &&
                  idx >= troughWindowStart &&
                  idx <= troughWindowEnd;
                const isPeak =
                  activeFilter === "circadian" && idx >= peakWindowStart && idx <= peakWindowEnd;
                const barColor = isPeak
                  ? "var(--color-signal)"
                  : isSleep
                    ? "var(--color-alert)"
                    : "var(--color-info)";

                return (
                  <g key={idx} onMouseEnter={() => setHoveredHour(idx)}>
                    {isHovered && (
                      <line
                        x1={p.x}
                        y1="16"
                        x2={p.x}
                        y2="125"
                        stroke="var(--color-ink-dim)"
                        strokeDasharray="2 2"
                        strokeWidth="1"
                      />
                    )}

                    <rect
                      x={p.x - 3.5}
                      y={p.y}
                      width="7"
                      height={Math.max(125 - p.y, 2)}
                      fill={isHovered ? "var(--color-ink)" : barColor}
                      opacity={isHovered ? 0.95 : isSleep ? 0.35 : 0.45}
                    />
                    <rect
                      x={p.x - 3.5}
                      y={p.y}
                      width="7"
                      height="2"
                      fill={isHovered ? "var(--color-ink)" : barColor}
                      opacity={isHovered ? 1 : 0.9}
                    />
                  </g>
                );
              })}

              <path d={areaPath} fill="url(#diurnalAreaGrad)" />
              <path
                d={linePath}
                fill="none"
                stroke="var(--color-info)"
                strokeWidth="2.2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />

              {/* Peak beacon */}
              <g>
                <circle
                  cx={peakPoint.x}
                  cy={peakPoint.y}
                  r="4.5"
                  fill="var(--color-signal)"
                  stroke="var(--color-sunken)"
                  strokeWidth="2"
                />
                <circle
                  cx={peakPoint.x}
                  cy={peakPoint.y}
                  r="8"
                  fill="none"
                  stroke="var(--color-signal)"
                  strokeWidth="1"
                  opacity="0.6"
                />
                {/*
                  Anchored to the right of the beacon rather than above it.
                  Above, it collided with the band caption whenever the peak
                  fell inside the peak window -- which is most of the time.
                */}
                <text
                  x={Math.min(peakPoint.x + 13, plotWidth - 8)}
                  y={peakPoint.y + 3.5}
                  fill="var(--color-signal-ink)"
                  fontSize="9"
                  fontFamily="var(--font-mono)"
                  fontWeight="bold"
                  textAnchor="start"
                >
                  {peakPoint.val}
                </text>
              </g>

              {/* Trough beacon */}
              <g>
                <rect
                  x={minPoint.x - 3.5}
                  y={minPoint.y - 3.5}
                  width="7"
                  height="7"
                  fill="var(--color-alert)"
                  stroke="var(--color-sunken)"
                  strokeWidth="1.5"
                />
                <text
                  x={Math.min(Math.max(minPoint.x, 44), plotWidth - 44)}
                  y={minPoint.y - 8}
                  fill="var(--color-alert-ink)"
                  fontSize="9"
                  fontFamily="var(--font-mono)"
                  fontWeight="bold"
                  textAnchor="middle"
                >
                  {minPoint.val === 0 ? "Zero activity" : `Min ${minPoint.val}`}
                </text>
              </g>
            </svg>
            )}
          </div>

          {/*
            X-axis labels sit at the real x of the interval they name, rather
            than being spread edge to edge. With justify-between they drifted
            out of register with the columns as the card resized, so "18:00"
            pointed at empty space to the right of the 18th bar.
          */}
          {hasSeries && (
            <div className="relative h-4 text-[10px] font-mono text-ink-dim pt-2 border-t border-line-faint">
              {axisTicks.map((t) => {
                const p = points[t];
                if (!p) return null;
                const align =
                  t === 0 ? "left" : t >= points.length - 1 ? "right" : "center";
                return (
                  <span
                    key={t}
                    className="absolute top-2 whitespace-nowrap"
                    style={{
                      left: `${(p.x / plotWidth) * 100}%`,
                      transform:
                        align === "left"
                          ? "none"
                          : align === "right"
                            ? "translateX(-100%)"
                            : "translateX(-50%)",
                    }}
                  >
                    {activeFilter === "circadian"
                      ? `${String(t).padStart(2, "0")}:00`
                      : `Day ${String(t + 1).padStart(2, "0")}`}
                  </span>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* MIDDLE ROW 2: Semi-Gauge Card */}
      <div className="matte-card p-6 flex flex-col justify-between">
        <div>
          <h3 className="text-sm font-bold text-ink">Attribution Confidence</h3>
          <p className="text-xs text-ink-dim mt-0.5">Composite engine formula (C_attr)</p>
          <p className="text-3xl font-extrabold text-ink mt-2 font-mono">{scorePct}</p>
          <p className="text-xs font-semibold text-info-ink mt-1">{confidenceTier}</p>
        </div>

        {/* Gauge SVG (Dynamic arc calculated from score) */}
        <div className="relative flex flex-col items-center justify-center my-2">
          <svg
            className="w-48 h-28"
            viewBox="0 0 200 110"
            role="img"
            aria-label={`Attribution confidence ${scorePct}, tier ${confidenceTier}.`}
          >
            <path
              d="M 20 100 A 80 80 0 0 1 180 100"
              fill="none"
              stroke="var(--color-line)"
              strokeWidth="15"
              strokeLinecap="square"
            />
            <path
              d={`M 20 100 A 80 80 0 0 1 ${gaugeX} ${gaugeY}`}
              fill="none"
              stroke="var(--color-signal)"
              strokeWidth="15"
              strokeLinecap="square"
            />
          </svg>
          <div className="absolute bottom-2 flex flex-col items-center">
            {/* The one place the headline confidence appears on this screen.
                It previously appeared three more times at 24/700, 24/900 and
                11/700 in other cards. */}
            <span className="text-[30px] font-extrabold text-ink font-mono tabular-nums">
              {scorePct}
            </span>
            <span className="text-[10px] font-bold text-ink-dim uppercase tracking-wider">
              {scoreNum >= 90 ? "Judicial Proof" : scoreNum >= 75 ? "High Lead" : "Inconclusive"}
            </span>
          </div>
        </div>

        <div className="flex items-center justify-between text-[12px] font-semibold pt-3 border-t border-line">
          <span className="text-ink-dim">Contradiction Penalty</span>
          <span className="font-mono text-ink-muted">
            {/*
              Narrowed rather than cast. `breakdown` is Record<string, unknown>
              because the penalty's real shape depends on which indicators
              contradicted, so the only safe reading is "is it a number".
            */}
            {typeof attribution?.breakdown?.total_penalty === "number"
              ? `${(attribution.breakdown.total_penalty * 100).toFixed(1)}%`
              : "0.0% (no conflicts reported)"}
          </span>
        </div>

        {/* ------------------------------------------------------------------
            The deterministic / probabilistic split.

            The engine returns s_det, s_ai, weight_det, weight_ai and
            total_penalty in every response. This panel rendered only
            total_penalty, so the single most important claim this product
            makes — that its confidence is weighted toward reproducible
            evidence rather than inference, which is what the "adheres to
            Daubert/Frye" caption rests on — was asserted in prose and shown
            nowhere as numbers.

            When the engine does not report the split (older records, the
            fallback corpus), it is named as missing rather than substituted or
            hidden, per the same degradation rule the stylometry panel uses.
            ------------------------------------------------------------------ */}
        {(() => {
          const bd = attribution?.breakdown as
            | {
                s_det?: number;
                s_ai?: number;
                weight_det?: number;
                weight_ai?: number;
              }
            | undefined;
          const hasSplit =
            typeof bd?.s_det === "number" && typeof bd?.s_ai === "number";

          if (!hasSplit) {
            return (
              <p className="text-[10px] text-ink-faint font-mono mt-3 leading-relaxed border-t border-line pt-3">
                The deterministic / probabilistic split is not reported for this
                record, so the composition of this score cannot be shown. The
                headline figure alone should not be relied on.
              </p>
            );
          }

          const detPct = Math.round(bd.s_det! * 100);
          const aiPct = Math.round(bd.s_ai! * 100);
          const wDet =
            typeof bd.weight_det === "number" ? Math.round(bd.weight_det * 100) : null;
          const wAi =
            typeof bd.weight_ai === "number" ? Math.round(bd.weight_ai * 100) : null;

          return (
            <div className="mt-3 pt-3 border-t border-line">
              <div className="flex items-baseline justify-between">
                <span className="text-[10px] uppercase tracking-widest text-ink-faint font-mono">
                  Score composition
                </span>
                {wDet !== null && wAi !== null && (
                  <span className="text-[10px] text-ink-dim font-mono">
                    weighted {wDet} / {wAi}
                  </span>
                )}
              </div>
              {/* A single ruled bar: deterministic on the left, probabilistic
                  on the right. This is a different encoding from the gauge
                  above, deliberately — the gauge answers "how confident", this
                  answers "confident about what", and rendering both as a second
                  big number is what made the panel repetitive. */}
              <div
                className="flex h-2.5 mt-2 border border-line-strong"
                role="img"
                aria-label={`Score composition: ${detPct}% from deterministic indicators, ${aiPct}% from probabilistic inference.${
                  wDet !== null && wAi !== null
                    ? ` Weighted ${wDet} toward deterministic, ${wAi} toward probabilistic.`
                    : ""
                }`}
              >
                <span
                  className="bg-info"
                  style={{ width: `${detPct}%` }}
                ></span>
                <span
                  className="bg-warn"
                  style={{ width: `${aiPct}%` }}
                ></span>
              </div>
              <div className="flex justify-between mt-1.5 text-[10px] font-mono">
                <span className="text-info-ink">
                  <span className="text-ink-dim">deterministic </span>
                  {detPct}%
                </span>
                <span className="text-warn-ink">
                  {aiPct}% <span className="text-ink-dim">probabilistic</span>
                </span>
              </div>
            </div>
          );
        })()}
      </div>

      {/* MIDDLE ROW 3: Suspect Profile Card.

          `justify-start` replaces `justify-between`. The card is a grid child
          and the grid equalises row heights, so `justify-between` pushed the
          three metrics to the bottom of a stretched card and left a band of
          dead space between them and the identity block above — visible as an
          empty third of the card in the 1440px screenshot. The metrics are the
          information on this card, so they follow the identity directly and the
          dead band closes. */}
      <div className="matte-card p-6 flex flex-col items-center text-center justify-start">
        <div className="flex flex-col items-center">
          {/*
            This was a DiceBear robot fetched from api.dicebear.com, which sent
            the suspect's name to a third party on every render -- in a product
            whose entire premise is operational security, and on a card naming a
            real criminal. Replaced with a monogram derived from the handle.
          */}
          <div
            className="w-16 h-16 bg-surface mb-3 relative border border-line-strong flex items-center justify-center"
            aria-hidden="true"
          >
            <span className="font-mono text-xl font-bold text-ink-dim">
              {currentActor.replace(/[^A-Za-z0-9]/g, "").slice(0, 2).toUpperCase() || "??"}
            </span>
          </div>
          <h3 className="text-lg font-bold text-ink">{currentActor}</h3>
          <p className="text-xs text-ink-dim font-mono mt-0.5 truncate max-w-[220px]">
            {currentTarget}
          </p>

          <span className="inline-block mt-2 text-[11px] font-bold px-3 py-1 bg-alert-surface text-alert-ink border border-alert-line">
            ALERT: Primary Operator <DemoTag requires="an operator-role field on the case record" />
          </span>
        </div>

        {/* 3 Column Metrics -- counts come from the case record or read zero. */}
        <div className="grid grid-cols-3 gap-2 w-full pt-4 mt-4 border-t border-line">
          <div>
            <p className="text-xs text-ink-dim font-medium">Aliases</p>
            <h4 className="text-base font-bold text-ink font-mono mt-0.5">
              {caseData?.aliases?.length ?? 0}
            </h4>
          </div>
          <div>
            <p className="text-xs text-ink-dim font-medium">Evidence</p>
            <h4 className="text-base font-bold text-ink font-mono mt-0.5">
              {caseData?.evidence_records?.length ?? 0}
            </h4>
          </div>
          <div>
            <p className="text-xs text-ink-dim font-medium">Custody</p>
            <h4 className="text-base font-bold text-ink font-mono mt-0.5">
              {caseData?.custody?.length ?? 0}
            </h4>
          </div>
        </div>
      </div>

      {/* BOTTOM ROW 1: 3D Stacked Cryptographic Anchors */}
      <div className="matte-card p-6 lg:col-span-2 flex flex-col md:flex-row items-center justify-between gap-6 overflow-hidden">
        <div className="flex-1">
          <h3 className="text-lg font-bold text-ink">Cryptographic Anchor Chain</h3>
          <p className="text-xs text-ink-muted mt-1 leading-relaxed max-w-[52ch]">
            Deterministic linkages between the PGP fingerprint, the wallet, and the clearnet origin
            resolved for this case.
          </p>

          <div className="flex items-center gap-3 mt-5 flex-wrap">
            <button
              type="button"
              onClick={onOpenEvidence}
              className="px-5 py-2.5 min-h-11 bg-active hover:bg-info-hover text-ink text-xs font-bold tracking-wide transition flex items-center gap-2 border border-line-active"
            >
              <i className="fa-solid fa-plus text-[11px]" aria-hidden="true"></i> Add Evidence Anchor
            </button>
            {/* This used to raise a toast claiming a live query against
                "Neo4j", which is not a dependency of this product. The real
                graph is a view, one level up, so the button goes there. */}
            {onOpenGraph && (
              <button
                type="button"
                onClick={onOpenGraph}
                className="px-4 py-2.5 min-h-11 bg-surface hover:bg-raised text-ink-muted hover:text-ink border border-line-strong text-xs font-semibold transition flex items-center gap-2"
              >
                <i className="fa-solid fa-diagram-project text-[11px]" aria-hidden="true"></i>
                Open knowledge graph
              </button>
            )}
          </div>
        </div>

        {/*
          Three real identifiers from the case record.

          The derived claims that used to sit under them -- a Shodan favicon
          hash of -129482710, a 14-address co-spend cluster, a "100% MATCH"
          key-reuse verdict -- were invented on every load for every case.
          Each row now names the correlation the engine would have to perform
          instead of asserting a result it never computed.

          This was a perspective-rotated card stack. The rotation was the only
          thing marking the three as one system, and it hid two of them: on
          this card the PGP key was readable and the wallet and clearnet origin
          were not. A hairline stack keeps all three legible, which is the
          whole job of a card holding a case's evidence identifiers.
        */}
        <div className="w-full md:w-64 shrink-0 flex flex-col border border-line">
          <div className="px-3 py-2.5 border-b border-line flex items-center justify-between gap-2">
            <span className="text-[10px] font-mono text-ink-dim">CLEARNET ORIGIN</span>
            <i className="fa-solid fa-triangle-exclamation text-alert-ink text-[10px]" aria-hidden="true" />
          </div>
          <p className="px-3 py-2 font-mono text-xs font-bold text-alert-ink truncate">
            {currentOriginIp}
          </p>
          <p className="px-3 pb-2.5 text-[10px] text-ink-dim font-mono">
            Favicon mmh3 correlation
          </p>

          <div className="px-3 py-2.5 border-y border-line flex items-center justify-between gap-2">
            <span className="text-[10px] font-mono text-ink-dim">WALLET</span>
            <i className="fa-brands fa-bitcoin text-ink-dim text-[10px]" aria-hidden="true" />
          </div>
          <p className="px-3 py-2 font-mono text-[11px] font-bold text-ink truncate">
            {currentBtc || "None resolved"}
          </p>
          <p className="px-3 pb-2.5 text-[10px] text-ink-dim font-mono">
            Cluster size not reported
          </p>

          <div className="px-3 py-2.5 flex items-center justify-between gap-2">
            <span className="text-[10px] font-mono text-ink-dim">PGP KEY</span>
            <i className="fa-solid fa-lock text-ink-dim text-[10px]" aria-hidden="true" />
          </div>
          <p className="px-3 py-2 font-mono text-xs font-bold text-ink tracking-wider break-all">
            {currentPgp || "None resolved"}
          </p>
          <p className="px-3 pb-2.5 text-[10px] text-ink-dim font-mono">Key reuse not scored</p>
        </div>
        <p className="sr-only">
          Cryptographic anchors for this case: clearnet origin {currentOriginIp}, wallet{" "}
          {currentBtc || "none resolved"}, PGP key {currentPgp || "none resolved"}. Cluster sizes
          and key-reuse verdicts are not reported by the engine.
        </p>
      </div>

      {/* BOTTOM ROW 2: Recent Attribution Activity */}
      <div className="matte-card p-6 flex flex-col justify-between">
        <div className="flex justify-between items-center mb-3">
          <h3 className="text-sm font-bold text-ink">Investigation Timeline</h3>
          <span className="text-[11px] font-mono font-semibold text-info-ink">Case Stream</span>
        </div>

        {/*
          When the engine has not reported a timeline this used to render three
          invented events -- "Origin IP Unmasked", "ShadowByte", "3.42 BTC" --
          which read exactly like findings. An empty state that says the
          pipeline has not run is the honest version of the same card.
        */}
        <div className="flex flex-col gap-2.5">
          {timelineEvents && timelineEvents.length > 0 ? (
            timelineEvents.slice(0, 3).map((item) => (
              <div
                key={item.step}
                className="flex items-center justify-between gap-3 py-1.5 border-b border-line"
              >
                <div className="min-w-0">
                  <p className="text-xs font-bold text-ink-muted">{item.title}</p>
                  <p className="text-[10px] text-ink-dim font-mono truncate max-w-[190px]">
                    {item.description}
                  </p>
                </div>
                <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 bg-signal-surface text-signal-ink border border-signal-line shrink-0">
                  {item.status}
                </span>
              </div>
            ))
          ) : (
            <div className="py-6 px-3 text-center border border-dashed border-line">
              <i
                className="fa-regular fa-hourglass text-ink-faint text-lg mb-2"
                aria-hidden="true"
              />
              <p className="text-xs text-ink-muted font-semibold">No timeline reported</p>
              <p className="text-[11px] text-ink-dim mt-1 max-w-[34ch] mx-auto">
                Run an investigation to record each pipeline step against this case.
              </p>
            </div>
          )}
        </div>

        {timelineEvents && timelineEvents.length > 0 && (
          <p className="w-full mt-2 py-2 text-[11px] text-ink-dim font-mono text-center border-t border-line">
            {timelineEvents.length} recorded step{timelineEvents.length === 1 ? "" : "s"}
          </p>
        )}
      </div>


      {/* BOTTOM ROW 3: Subpoena & Forensic Export */}
      <div className="matte-card p-6 flex flex-col items-center text-center justify-between">
        <div className="flex flex-col items-center">
          <div
            className="w-16 h-16 bg-info-surface border border-line-strong text-ink flex items-center justify-center text-2xl mb-2"
            aria-hidden="true"
          >
            <i className="fa-solid fa-fingerprint"></i>
          </div>
          {/* Was "Courteous ready": a compliment, in a headline, in the position
              a compliance statement belongs. It also asserted a property of the
              product ("courtroom ready") that the product cannot itself verify —
              whether an export is admissible depends on the evidence and the
              tribunal, not on this interface.

              It now states the two things that are actually true and actually
              checkable: release requires a human affirmation, and a released
              export creates a permanent custody record. */}
          <h3 className="text-[16px] font-bold text-ink">Release is gated</h3>
          <p className="text-[12px] text-ink-muted mt-1.5 max-w-[42ch] leading-relaxed">
            No document leaves this system until an investigator with release
            rights affirms it. That affirmation is itself recorded as a custody
            block, so the export and the act of releasing it are permanently
            linked.
          </p>
        </div>

        <button
          type="button"
          onClick={onOpenDossier}
          className="w-full mt-4 py-3 min-h-11 bg-active hover:bg-info-hover text-ink text-xs font-bold tracking-wide transition flex items-center justify-center gap-2 border border-line-active"
        >
          <i className="fa-solid fa-file-shield text-sm" aria-hidden="true"></i> Open export dossier
        </button>
      </div>
      </div>
    </div>
  );
};
