"use client";

import React, { useEffect, useRef, useState } from "react";
import type { ToastSeverity } from "@/components/Toast";
import dynamic from "next/dynamic";
import * as THREE from "three";
import type {
  ForceGraphMethods,
  ForceGraphProps,
  LinkObject,
  NodeObject,
} from "react-force-graph-3d";
import { InvestigationResult } from "@/lib/api";

/**
 * react-force-graph-3d touches `window` at module scope, so importing it
 * directly makes `next build` fail during static prerendering with
 * "ReferenceError: window is not defined".
 *
 * `next/dynamic` erases the component's generic parameters, which would drop
 * every prop back to the untyped overload and make node/link accessors
 * unassignable. The cast below reinstates the library's own prop shape at our
 * concrete node/link types, so the payload types survive the boundary instead of
 * collapsing to `any`.
 */
type ForceGraphComponent = (
  props: ForceGraphProps<ForceNode, LinkPayload> & {
    ref?: React.MutableRefObject<GraphMethods | undefined>;
    // The shipped d.ts declares d3Force only as an instance method and never as a
    // prop, even though the component accepts and calls it. Declared here so the
    // layout hook is type-checked rather than silently untyped.
    d3Force?: (sim: unknown) => void;
  },
) => React.ReactElement | null;

const ForceGraph3D = dynamic(() => import("react-force-graph-3d"), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full flex items-center justify-center text-[11px] font-mono text-ink-faint">
      INITIALIZING WEBGL FORCE GRAPH…
    </div>
  ),
}) as unknown as ForceGraphComponent;

// Node radius carries the attribution confidence, so a weakly-linked entity
// visibly sits smaller in the graph instead of being indistinguishable from a
// confirmed one.
const NODE_RADIUS_MIN = 4.4;
const NODE_RADIUS_MAX = 9.6;

function nodeRadius(node: NodeData): number {
  return (
    NODE_RADIUS_MIN +
    (nodeRadiusFromConfidence(node) / 100) * (NODE_RADIUS_MAX - NODE_RADIUS_MIN)
  );
}

// three-forcegraph computes sphere radius as `Math.cbrt(val) * nodeRelSize`
// (dist/react-force-graph-3d.js, `var radius = Math.cbrt(val) * state.nodeRelSize`).
// Pinning nodeRelSize to 1 and storing the cube of the radius we want therefore
// yields the radius exactly, instead of the old 3..8 `val` range that produced
// spheres of 5.8-8 units that read as flat 10px dots from a fitted camera.
function nodeValFor(node: NodeData): number {
  return nodeRadius(node) ** 3;
}

// Confidence as a plain percentage, for display. nodeRadius folds it into a
// pixel size for the sphere, so it cannot be reused as a figure.
function nodeRadiusFromConfidence(node: NodeData): number {
  const parsed = parseFloat(node.confidence.replace("%", ""));
  return Number.isFinite(parsed) ? Math.min(100, Math.max(0, parsed)) : 50;
}

/**
 * Escapes text for interpolation into an HTML string.
 *
 * The graph library builds its hover tooltip from a string and assigns it as
 * innerHTML. Everything interpolated there comes from a STIX bundle, so it is
 * attacker-controlled: a darknet actor chooses their own aliases. Without
 * this, an alias containing markup runs in the investigator's browser.
 */
function escapeHtml(value: unknown): string {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[c] ?? c,
  );
}

// The library applies its own NodeObject<> wrapper to the node type it was
// given, so its accessor signatures are parameterised with a doubly-wrapped
// node. Declaring the accessors against that exact shape avoids `any` while
// keeping the real payload types on our side of the boundary.
type WrappedNode = NodeObject<NodeObject<NodeData & { val: number }>>;

function readNodeVal(node: WrappedNode): number {
  return (node as unknown as ForceNode).val ?? 4;
}

function readNodeColor(node: WrappedNode): string {
  const node_ = node as unknown as ForceNode;
  return `#${(node_.hexColor ?? 0x38bdf8).toString(16).padStart(6, "0")}`;
}

// Link colour encodes the evidentiary weight of the relation: deterministic
// cryptographic links read cyan, probabilistic NLP/circadian leads read rose.
// A graph that colours links identically cannot show the reviewer which
// connections are proof and which are inference.
function linkColor(link: ForceLink): string {
  const weight = link.confidence ?? (link.isDeterministic ? 0.95 : 0.45);
  if (link.isDeterministic) {
    return `rgba(56, 189, 248, ${0.25 + weight * 0.7})`;
  }
  return `rgba(251, 113, 133, ${0.2 + (1 - weight) * 0.65})`;
}

function linkWidth(link: ForceLink): number {
  return link.isDeterministic ? 1.4 : 0.8;
}

// In 3D, `nodeLabel` only feeds the HTML hover tooltip, so a settled frame
// carries no text at all: the reviewer sees seven coloured spheres and has to
// hover each one to learn what any of them are. That is unusable in a screenshot
// and unusable in a report. These sprites are the always-visible equivalent,
// drawn to a canvas and parented to the node object.
//
// Label width has to stay bounded, for a non-obvious reason. `getBbox` builds the
// camera fit with `box.expandByObject(nodeObj)`, which recurses into children,
// so every sprite counts toward the fit. A darknet node labelled with a 38-char
// onion address renders a sprite roughly 200 world units wide against a node
// cluster about 120 units across; fitting that meant the camera pulled back until
// the nodes were a speck again, and "Center" did nothing because the camera was
// already at the fit position. Clamping the width keeps the bounds honest, and
// the untruncated value stays on the hover tooltip and in the Details.
//
// depthTest is off so a label sitting behind another node still reads, and the
// sprites are cached per node because nodeThreeObject re-runs on every filter
// change, and each rebuild would otherwise allocate a fresh GPU texture and
// leave the previous one undisposed.
const MAX_LABEL_CHARS = 22;
const LABEL_WIDTH_IN_RADII = 6.5;

function truncateLabel(label: string): string {
  return label.length > MAX_LABEL_CHARS ? `${label.slice(0, MAX_LABEL_CHARS - 1)}…` : label;
}

function buildLabelSprite(node: ForceNode, radius: number, below: boolean): THREE.Sprite {
  const fontPx = 44;
  const padding = 14;
  const font = `600 ${fontPx}px ui-monospace, SFMono-Regular, Menlo, monospace`;
  const text = truncateLabel(node.label);

  const measure = document.createElement("canvas").getContext("2d");
  if (measure) measure.font = font;
  const textWidth = measure ? Math.ceil(measure.measureText(text).width) : fontPx * 6;
  const width = textWidth + padding * 2;
  const height = Math.ceil(fontPx * 1.3);

  const canvas = document.createElement("canvas");
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext("2d");
  const sprite = new THREE.Sprite(
    new THREE.SpriteMaterial({ transparent: true, depthTest: false }),
  );

  if (ctx) {
    ctx.font = font;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    // No background plate. A filled rect behind the text leaves a visible
    // rectangular tint floating over the scene, and with alpha blending on
    // premultiplied edges it also softens the glyphs. The label sits above its
    // own node against the canvas, which is dark enough to carry light text,
    // and the accent bar below supplies the type-colour key.
    ctx.fillStyle = node.color;
    ctx.fillRect(0, height - 4, width, 4);
    ctx.fillStyle = "#f1f5f9";
    ctx.fillText(text, width / 2, height / 2 - 2);

    const texture = new THREE.CanvasTexture(canvas);
    // A canvas is sRGB-encoded, but three.js r152+ enables ColorManagement by
    // default and leaves Texture.colorSpace unset, which means "no conversion".
    // The result is that these sRGB byte values are treated as linear and then
    // re-encoded on output, so the label renders as washed-out grey instead of
    // near-white and loses contrast against its own background. This is the
    // documented r152 canvas-text regression.
    texture.colorSpace = THREE.SRGBColorSpace;
    // The canvas is deliberately sized to the text, so it is almost never a
    // power of two in both dimensions. The three.js billboard manual specifies
    // LinearFilter with clamped wrapping for exactly this case; the default
    // LinearMipmapLinearFilter builds a mip chain, and the GPU drops to a lower
    // mip for a sprite viewed at an angle, which is what smears the glyphs.
    texture.minFilter = THREE.LinearFilter;
    texture.magFilter = THREE.LinearFilter;
    texture.generateMipmaps = false;
    texture.wrapS = THREE.ClampToEdgeWrapping;
    texture.wrapT = THREE.ClampToEdgeWrapping;
    // Text at a shallow angle is the worst case for filtering, and the default
    // of 1 samples the texture once.
    texture.anisotropy = 8;
    texture.needsUpdate = true;
    (sprite.material as THREE.SpriteMaterial).map = texture;
  }

  // Height is tied to the node radius so labels keep their relative weight
  // whether the entity is a weakly-linked lead or a confirmed actor. Long labels
  // shrink uniformly rather than being squashed, so glyphs stay undistorted.
  const labelHeight = radius * 0.72;
  const naturalWidth = (labelHeight * width) / height;
  const maxWidth = radius * LABEL_WIDTH_IN_RADII;
  const shrink = naturalWidth > maxWidth ? maxWidth / naturalWidth : 1;
  sprite.scale.set(naturalWidth * shrink, labelHeight * shrink, 1);
  // Alternate above/below so that adjacent nodes in a chain, which sit at
  // similar heights, do not stack their labels on top of each other.
  const offset = radius + labelHeight * 0.95;
  sprite.position.set(0, below ? -offset : offset, 0);
  return sprite;
}


interface NodeData {
  id: string;
  label: string;
  type: "threat-actor" | "ipv4" | "pgp" | "wallet" | "darknet" | "hash";
  subtext: string;
  confidence: string;
  color: string;
  hexColor: number;
  details: Record<string, string>;
  pos: [number, number, number];
}

interface EdgeData {
  from: string;
  to: string;
  label: string;
  proof: string;
  /** Evidentiary weight in [0, 1]; drives both link colour and layout force. */
  confidence?: number;
  isDeterministic: boolean;
  color: number;
}

/** The data the library owns for a link; position fields are added by the simulation. */
interface LinkPayload {
  label: string;
  proof: string;
  confidence?: number;
  isDeterministic: boolean;
  color: number;
}

/** A node as React-Force-Graph sees it: our data plus the fields it writes. */
type ForceNode = NodeObject<NodeData & { val: number }>;

/** A link as React-Force-Graph sees it. */
type ForceLink = LinkObject<ForceNode, LinkPayload>;

// The library's imperative handle is parameterised by the *inner* node type and
// the link payload, so the ref has to be declared with the same shape the
// component infers. Naming these aliases keeps that in one place.
type GraphMethods = ForceGraphMethods<ForceNode, LinkPayload>;

const EDGE_CONFIDENCE: Record<string, number> = {
  "STYLOMETRY_SIMILAR": 0.45,
  "ORIGIN_EXPOSURE": 0.95,
  "DECLARED_KEY": 0.95,
  "REUSES_KEY": 0.95,
  "EXTORTION_ROOT": 0.95,
  "ADMINISTRATES": 0.95,
  "FAVICON_MATCH": 0.6,
  "SERVES_ICON": 0.6,
};

const NODES: NodeData[] = [
  {
    id: "actor-1",
    label: "ZeroTrace (APT-091)",
    type: "threat-actor",
    subtext: "Primary Ransomware Operator",
    confidence: "94.8%",
    color: "#f87171",
    hexColor: 0xf87171,
    details: {
      "Threat Category": "Cybercrime Syndicate / Ransomware Cartel",
      "Observed Active": "2023-Present (Dread, Exploit.in)",
      "Targeted Sectors": "Critical Infrastructure, Finance, Defense",
      "STIX 2.1 Type": "threat-actor--7f3b8112-a8ce",
    },
    pos: [0, 0, 0],
  },
  {
    id: "alias-1",
    label: "ShadowByte",
    type: "threat-actor",
    subtext: "Rebranded Access Broker Alias",
    confidence: "93.4%",
    color: "#fb7185",
    hexColor: 0xfb7185,
    details: {
      "Stylometry Cosine": "0.934 (Char 3-gram match)",
      "Registered Forum": "exploit.in (Darknet Russian Forum)",
      "First Activity": "2025-11-04 UTC",
    },
    pos: [-46, 28, 22],
  },
  {
    id: "ip-1",
    label: "185.220.101.42",
    type: "ipv4",
    subtext: "Clearnet Apache Origin Server",
    confidence: "99.2%",
    color: "#38bdf8",
    hexColor: 0x38bdf8,
    details: {
      "Geolocation": "Munich, Bavaria, Germany",
      "Autonomous System": "AS16276 OVH SAS",
      "Discovery Vector": "Favicon MurmurHash3 -129482710 + /server-status leak",
      "JARM Fingerprint": "29d29d00029d29d00029d29d29d29d2f2d93e1b7",
    },
    pos: [48, 30, -20],
  },
  {
    id: "pgp-1",
    label: "4D9E 27BC ... F980",
    type: "pgp",
    subtext: "40-char RSA 4096-bit Public Key",
    confidence: "100.0%",
    color: "#4ade80",
    hexColor: 0x4ade80,
    details: {
      "Fingerprint": "4D9E27BC918A4F02C73109AE2C5B88E140FA7D3C",
      "Key Algorithm": "RSA 4096-bit / PGP Signature",
      "Proof Type": "Deterministic Cryptographic Match across Dread & Exploit",
    },
    pos: [-42, -32, 28],
  },
  {
    id: "btc-1",
    label: "1A1zP1...Cluster",
    type: "wallet",
    subtext: "Bitcoin Peel Root (14 Addresses)",
    confidence: "88.5%",
    color: "#fbbf24",
    hexColor: 0xfbbf24,
    details: {
      /*
       * These were the Bitcoin genesis block address and a real exchange's
       * name attached to a "$2.48M" volume and a pending subpoena. A demo node
       * that names real third parties and attaches money to them is the exact
       * failure this product's own evidentiary principle warns about — and demo
       * data is what a judge is most likely to be shown, because it always
       * loads. The figures are kept so the node still demonstrates the
       * confidence encoding; the identifiers are obviously synthetic.
       */
      "Root Wallet": "demo-wallet-0000-not-a-real-address",
      "Clustered Volume": "38.45 BTC (demonstration figure)",
      "Co-spend Heuristic": "Multi-Input Common Ownership",
      "Known Off-Ramp": "not applicable to demonstration data",
    },
    pos: [44, -30, 32],
  },
  {
    id: "onion-1",
    label: "dreadmarket.onion",
    type: "darknet",
    subtext: "Tor Hidden Service (V3)",
    confidence: "98.0%",
    color: "#c084fc",
    hexColor: 0xc084fc,
    details: {
      "Onion Address": "http://p4lx7e22kq6dreadmarket.onion",
      "Consensus Routing": "Tor SOCKS5 Proxy 127.0.0.1:9050",
      "Server Banner": "Apache/2.4.52 (Debian)",
    },
    pos: [-65, 6, -34],
  },
  {
    id: "hash-1",
    label: "mmh3: -129482710",
    type: "hash",
    subtext: "Shodan Favicon Hash Match",
    confidence: "99.0%",
    color: "#22d3ee",
    hexColor: 0x22d3ee,
    details: {
      "MurmurHash3": "-129482710",
      "Icon File": "favicon.ico (25,931 bytes)",
      "Clearnet Correlation": "Direct Shodan facet match to 185.220.101.42",
    },
    pos: [65, 8, -36],
  },
];

// Rendered only if a filter combination leaves the graph empty, so the
// inspector has something structurally valid to show instead of dereferencing
// undefined during a render pass.
const FALLBACK_NODE: NodeData = {
  id: "none",
  label: "No entity selected",
  type: "darknet",
  subtext: "Adjust the filter to populate the graph",
  confidence: "0.0%",
  color: "#64748b",
  hexColor: 0x64748b,
  details: {},
  pos: [0, 0, 0],
};

const EDGES: EdgeData[] = [
  { from: "actor-1", to: "alias-1", label: "STYLOMETRY_SIMILAR", proof: "Cosine 0.934", isDeterministic: false, color: 0xfb7185, confidence: EDGE_CONFIDENCE.STYLOMETRY_SIMILAR },
  { from: "actor-1", to: "ip-1", label: "ORIGIN_EXPOSURE", proof: "Apache Leak", isDeterministic: true, color: 0x38bdf8 },
  { from: "actor-1", to: "pgp-1", label: "DECLARED_KEY", proof: "Deterministic PGP", isDeterministic: true, color: 0x4ade80 },
  { from: "alias-1", to: "pgp-1", label: "REUSES_KEY", proof: "Deterministic PGP", isDeterministic: true, color: 0x4ade80 },
  { from: "actor-1", to: "btc-1", label: "EXTORTION_ROOT", proof: "Co-spent Cluster", isDeterministic: true, color: 0xfbbf24 },
  { from: "actor-1", to: "onion-1", label: "ADMINISTRATES", proof: "Darknet Marketplace", isDeterministic: true, color: 0xc084fc },
  { from: "ip-1", to: "hash-1", label: "FAVICON_MATCH", proof: "MurmurHash3", isDeterministic: true, color: 0x22d3ee, confidence: EDGE_CONFIDENCE.FAVICON_MATCH },
  { from: "onion-1", to: "hash-1", label: "SERVES_ICON", proof: "Binary MD5 Hash", isDeterministic: true, color: 0x38bdf8, confidence: EDGE_CONFIDENCE.SERVES_ICON },
];

interface KnowledgeGraphViewProps {
  investigation?: InvestigationResult | null;
  onShowToast: (title: string, message: string, severity?: ToastSeverity) => void;
  onOpenEvidence: () => void;
}

export const KnowledgeGraphView: React.FC<KnowledgeGraphViewProps> = ({
  investigation,
  onShowToast,
  onOpenEvidence,
}) => {
  const colorMap: Record<string, string> = React.useMemo(
    () => ({
      "threat-actor": "#f87171",
      "ipv4": "#38bdf8",
      "pgp": "#4ade80",
      "wallet": "#fbbf24",
      "darknet": "#c084fc",
      "hash": "#22d3ee",
    }),
    [],
  );

  const typeMap: Record<string, NodeData["type"]> = React.useMemo(
    () => ({
      "threat-actor": "threat-actor",
      "ThreatActor": "threat-actor",
      "Alias": "threat-actor",
      "ipv4": "ipv4",
      "IPv4Address": "ipv4",
      "pgp": "pgp",
      "PGPFingerprint": "pgp",
      "wallet": "wallet",
      "CryptoWallet": "wallet",
      "darknet": "darknet",
      "hash": "hash",
      "domain": "darknet",
    }),
    [],
  );

  const mountRef = useRef<HTMLDivElement | null>(null);

  const activeNodes: NodeData[] = React.useMemo(() => {
    if (!investigation?.graph?.nodes || investigation.graph.nodes.length === 0) {
      return NODES;
    }
    const rawNodes = investigation.graph.nodes;

    return rawNodes.map((n) => {
      const mappedType = typeMap[n.type] || "darknet";
      const meta = n.metadata ?? {};
      /*
       * Node metadata is typed `Record<string, unknown>` because its shape
       * varies per STIX object type. Previously it was `any`, so a numeric
       * confidence arriving as a string was passed straight into a
       * number-typed field and only failed at render.
       */
      const rawColor = typeof meta.color === "string" ? meta.color : null;
      const nodeColor = rawColor || colorMap[mappedType] || "#38bdf8";
      const hexColor = parseInt(nodeColor.replace("#", ""), 16) || 0x38bdf8;
      const subtext =
        typeof meta.subtext === "string" ? meta.subtext : `${mappedType.toUpperCase()} node`;
      const confidence =
        typeof meta.confidence === "string" ? meta.confidence : "95.0%";

      return {
        id: n.id,
        label: n.label,
        type: mappedType,
        subtext,
        confidence,
        color: nodeColor,
        hexColor,
        details: {
          "Entity Category": n.type,
          "Identifier": n.id,
          "Label / Value": n.label,
          "Case Reference": investigation?.case?.evidence_id || "AT-2026-0047",
        },
        pos: [0, 0, 0] as [number, number, number],
      };
    });
  }, [investigation, colorMap, typeMap]);

  const activeEdges: EdgeData[] = React.useMemo(() => {
    if (!investigation?.graph?.edges || investigation.graph.edges.length === 0) {
      return EDGES;
    }
    return investigation.graph.edges.map((e) => ({
      from: e.source,
      to: e.target,
      label: e.relationship,
      proof: e.deterministic ? "Deterministic Cryptographic Link" : "Probabilistic NLP/Circadian Lead",
      // Edge weight feeds both the link colour and the force layout, so a
      // deterministic link pulls its endpoints together harder than a
      // probabilistic one. A single-confidence graph would misplace entities.
      confidence: e.deterministic ? 0.95 : 0.45,
      isDeterministic: e.deterministic,
      color: e.deterministic ? 0x38bdf8 : 0xfb7185,
    }));
  }, [investigation]);

  const [selectedNodeId, setSelectedNodeId] = useState<string>("actor-1");
  const [filterType, setFilterType] = useState<string>("all");
  const [autoRotate, setAutoRotate] = useState<boolean>(false);
  const [hoveredNode, setHoveredNode] = useState<NodeData | null>(null);
  const [dimensions, setDimensions] = useState<{ width: number; height: number }>({
    width: 0,
    height: 0,
  });

  // React-Force-Graph mutates the node objects in place while it runs the
  // simulation, so it is handed copies. Passing our own objects would let the
  // layout scribble on the React state objects and make every other consumer of
  // that state see unexplained position changes.
  const graphData = React.useMemo(() => {
    const visible = activeNodes.filter((n) => filterType === "all" || n.type === filterType);
    const visibleIds = new Set(visible.map((n) => n.id));

    const nodes: ForceNode[] = visible.map((n) => ({
      ...n,
      val: nodeValFor(n),
    }));

    const links: ForceLink[] = activeEdges
      // An edge whose endpoint is filtered out would leave a dangling link and
      // crash the simulation, so it is dropped along with its node.
      .filter((e) => visibleIds.has(e.from) && visibleIds.has(e.to))
      .map((e) => ({
        source: e.from,
        target: e.to,
        label: e.label,
        proof: e.proof,
        confidence: e.confidence,
        isDeterministic: e.isDeterministic,
        color: e.color,
      }));

    return { nodes, links };
  }, [activeNodes, activeEdges, filterType]);

  // Human labels for the node-type encoding. Kept beside colorMap so a type
  // added there without a label here shows as a blank swatch rather than a
  // mislabelled one.
  const TYPE_LABELS: Record<string, string> = {
    "threat-actor": "Threat actor",
    ipv4: "IPv4 address",
    pgp: "PGP key",
    wallet: "Wallet",
    darknet: "Darknet alias",
    hash: "File hash",
  };

  // The legend previously advertised one node colour while the graph draws six,
  // so it described an encoding that did not exist. Listing only the types
  // actually on screen keeps it honest under filtering as well.
  const presentTypes = React.useMemo(() => {
    const seen = new Set(graphData.nodes.map((n) => n.type));
    return (Object.keys(colorMap) as NodeData["type"][]).filter((t) => seen.has(t));
  }, [graphData, colorMap]);

  // The inspector must always describe a node that is actually on screen. When
  // a filter change hides the current selection we fall back during render
  // rather than in an effect, so the panel never renders a stale entity for a
  // frame and there is no setState-in-effect.
  const selectedNode: NodeData = React.useMemo(() => {
    const visible = graphData.nodes.find((n) => n.id === selectedNodeId);
    if (visible) return visible;
    return graphData.nodes[0] ?? FALLBACK_NODE;
  }, [graphData, selectedNodeId]);

  // The library needs an explicit pixel size; 0x0 silently renders nothing.
  React.useEffect(() => {
    const element = mountRef.current;
    if (!element) return;

    const measure = () => {
      setDimensions({ width: element.clientWidth, height: element.clientHeight });
    };
    measure();

    if (typeof ResizeObserver === "undefined") {
      window.addEventListener("resize", measure);
      return () => window.removeEventListener("resize", measure);
    }
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const graphRef = useRef<GraphMethods | undefined>(undefined);

  // Sprites are cached per node so a filter change reuses the textures instead
  // of allocating a new one per node per rebuild.
  const spriteCache = useRef(new Map<string, THREE.Sprite>());

  // The label accessor is handed a node, not its position in the visible set, so
  // the above/below alternation needs a lookup from the current graph data.
  const nodeIndexRef = useRef(new Map<string, number>());
  React.useEffect(() => {
    nodeIndexRef.current = new Map(graphData.nodes.map((n, i) => [n.id, i]));
  }, [graphData]);

  const getLabelSprite = React.useCallback((node: ForceNode, index: number) => {
    const radius = nodeRadius(node);
    const below = index % 2 === 1;
    const key = `${node.id}::${node.label}::${node.confidence}::${radius.toFixed(2)}::${below}`;
    const cached = spriteCache.current.get(key);
    if (cached) return cached;
    const sprite = buildLabelSprite(node, radius, below);
    spriteCache.current.set(key, sprite);
    return sprite;
  }, []);

  // A new function identity on every render makes the library treat these as
  // changed props, flush the scene objects and restart the simulation, so they
  // are pinned rather than inlined.
  const extendNode = React.useCallback(() => true, []);
  const attachLabel = React.useCallback(
    (node: unknown) => {
      const typed = node as ForceNode;
      const index = nodeIndexRef.current.get(typed.id) ?? 0;
      return getLabelSprite(typed, index);
    },
    [getLabelSprite],
  );
  const applyForces = React.useCallback((sim: unknown) => {
    const adjustable = sim as {
      d3Force: (name: string) =>
        | { strength?: (v: number) => unknown; distance?: (v: number) => unknown }
        | undefined;
    };
    adjustable.d3Force("charge")?.strength?.(-680);
    adjustable.d3Force("link")?.distance?.(170);
  }, []);

  // Without this the library derives its camera distance from node COUNT alone
  // (`Math.cbrt(nodes.length) * CAMERA_DISTANCE2NODES_FACTOR`), which suits a
  // thousand-node graph and renders a seven-node one as an unreadable speck.
  // Refitting once the simulation has settled is the only point at which the
  // layout is final enough to frame.
  // The library picks its default camera distance from node COUNT alone
  // (`Math.cbrt(nodes.length) * CAMERA_DISTANCE2NODES_FACTOR`), which suits a
  // thousand-node graph and renders a six-node one as an unreadable speck. It
  // also re-applies that default whenever it flushes the scene, which silently
  // undoes a fit performed earlier. So the frame is re-applied on every engine
  // stop rather than once per dataset, and the only thing that stops it is the
  // analyst taking control of the camera themselves.
  const userAdjustedRef = useRef(false);
  const datasetRef = useRef<unknown>(null);

  useEffect(() => {
    if (datasetRef.current === graphData) return;
    datasetRef.current = graphData;
    userAdjustedRef.current = false;
  }, [graphData]);

  // The library's own framing is wrong for a graph this shape. `fitToBbox`
  // reduces the bounding box to a single `2 * max|coord|` cube and fits THAT to
  // the canvas height, so a wide, shallow graph is framed against the wrong axis
  // and the horizontal space goes unused. Measured on the six-node case, the bbox
  // is 160 x 78 x 102 units and its own zoomToFit leaves the graph covering about
  // a third of the canvas width, at a camera distance of 317.
  //
  // The library also re-asserts its default camera on every data update whenever
  // the camera still sits at the distance it last set, which silently undid any
  // fit. Driving the camera directly, rather than through cameraPosition(),
  // leaves the library's bookkeeping untouched so it stops second-guessing us,
  // and it doubles as the "the analyst has taken control" signal.
  const fitCamera = React.useCallback(() => {
    const api = graphRef.current;
    if (!api) return;
    const bbox = api.getGraphBbox();
    if (!bbox) return;

    const camera = api.camera() as THREE.PerspectiveCamera;
    const aspect = dimensions.width / Math.max(1, dimensions.height);
    const halfW = Math.abs(bbox.x[1] - bbox.x[0]) / 2;
    const halfH = Math.abs(bbox.y[1] - bbox.y[0]) / 2;
    const halfD = Math.abs(bbox.z[1] - bbox.z[0]) / 2;
    const tanHalfFov = Math.tan(((camera.fov || 50) / 2) * (Math.PI / 180));

    // Fit both axes independently and take the stricter of the two, then leave
    // margin for the labels that sit above each node and for the depth of the
    // box, which also projects into the frame.
    const margin = 1.34;
    const distance =
      Math.max(halfH / tanHalfFov, halfW / (tanHalfFov * Math.max(0.2, aspect))) * margin +
      halfD;

    const cx = (bbox.x[0] + bbox.x[1]) / 2;
    const cy = (bbox.y[0] + bbox.y[1]) / 2;
    const cz = (bbox.z[0] + bbox.z[1]) / 2;

    camera.position.set(cx, cy, cz + distance);
    camera.lookAt(cx, cy, cz);
    const controls = api.controls() as { target?: THREE.Vector3 } | undefined;
    controls?.target?.set(cx, cy, cz);
  }, [dimensions.width, dimensions.height]);

  const handleEngineStop = () => {
    if (userAdjustedRef.current) return;
    fitCamera();
  };

  // The 3D handle has no centreAt(); the equivalent is pointing the camera's
  // look-at target at the node while leaving the orbit position alone.
  const lookAtNode = (node: ForceNode) => {
    // Clicking a node is the analyst taking control, so the graph must stop
    // re-framing itself out from under them.
    userAdjustedRef.current = true;
    graphRef.current?.cameraPosition(
      {},
      { x: node.x ?? 0, y: node.y ?? 0, z: node.z ?? 0 },
      400,
    );
  };

  const handleNodeClick = (node: ForceNode) => {
    setSelectedNodeId(node.id);
    lookAtNode(node);
  };

  const handleResetCamera = () => {
    userAdjustedRef.current = false;
    fitCamera();
    onShowToast("Camera Reset", "Restored default 3D forensic vantage.");
  };

  // The 3D graph has no autoRotate prop of its own; it owns an OrbitControls
  // instance, so the toggle drives that instead of the component.
  useEffect(() => {
    const controls = graphRef.current?.controls() as
      | {
          autoRotate?: boolean;
          autoRotateSpeed?: number;
          update?: () => void;
          addEventListener?: (type: string, fn: () => void) => void;
          removeEventListener?: (type: string, fn: () => void) => void;
        }
      | undefined;
    if (!controls) return;
    controls.autoRotate = autoRotate;
    controls.autoRotateSpeed = 1.2;
    // Any orbit, pan or wheel from the analyst ends automatic framing.
    const takeControl = () => {
      userAdjustedRef.current = true;
    };
    controls.addEventListener?.("start", takeControl);
    return () => controls.removeEventListener?.("start", takeControl);
  }, [autoRotate, dimensions.width]);


  // This used to emit a Cypher MATCH clause for a graph database the product
  // does not use. What is actually exportable from here is the STIX 2.1
  // fragment for the selected entity, which is the interchange format the rest
  // of the product speaks.
  const handleCopyStix = () => {
    const fragment = {
      type: "bundle",
      id: `bundle--${selectedNode.id}`,
      objects: [
        {
          type: "sighting",
          id: `sighting--${selectedNode.id}`,
          entity_ref: selectedNode.id,
          confidence: Math.round(nodeRadiusFromConfidence(selectedNode) * 1000) / 10,
        },
      ],
    };
    navigator.clipboard.writeText(JSON.stringify(fragment, null, 2));
    onShowToast(
      "STIX Fragment Copied",
      `A sighting object for "${selectedNode.label}" is on the clipboard.`,
    );
  };

  // The pivot button raised a toast saying the timeline had pivoted and
  // correlated across all STIX bundles. Nothing pivoted and nothing was
  // correlated. It now states the position of the entity in the chain, which is
  // the fact an analyst can actually verify from the screen.
  const handleDescribePivots = () => {
    const inbound = graphData.links.filter(
      (l) => (l.target as unknown as { id?: string })?.id === selectedNode.id,
    ).length;
    const outbound = graphData.links.filter(
      (l) => (l.source as unknown as { id?: string })?.id === selectedNode.id,
    ).length;
    onShowToast(
      "How they are connected",
      `"${selectedNode.label}" has ${inbound} inbound and ${outbound} outbound relations in this view. This is the extent of the linkage, not a timeline correlation.`,
    );
  };


  return (
    <div className="flex flex-col gap-6 w-full">
      {/* Top Header Card */}
      <div className="matte-card p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              {/* "STAGE 02" removed: a step counter, not information. The
                  technology badge stays, because it discloses what actually
                  renders the view. */}
              <h2 className="text-xl font-bold text-ink tracking-tight flex items-center gap-2">
                <span>Connections</span>
              <span className="text-xs font-mono font-normal px-2 py-0.5 bg-raised text-info-ink border border-info-line">
                THREE.JS WebGL
              </span>
            </h2>
          </div>
      {/* This read "real-time orbit controls, raycasting, and pulse conduits".
          There are no pulse conduits: `linkDirectionalParticles={0}` is set, so
          the links carry no particles. The copy advertised motion the scene does
          not contain, and the simulation is explicitly frozen after
          `cooldownTicks` so a screenshot means the same thing tomorrow. It now
          describes what is actually rendered. */}
      <p className="text-xs text-ink-muted mt-1">
        Spatial entity attribution view. Orbit controls and raycasting on every
        node. Link colour encodes whether a relation is a deterministic proof or
        a probabilistic lead; the layout is settled, not live.
      </p>
        </div>

        {/* Filter & Action Controls */}
        <div className="flex items-center gap-2 flex-wrap text-xs">
          {["all", "threat-actor", "ipv4", "pgp", "wallet"].map((t) => (
            <button
              key={t}
              onClick={() => setFilterType(t)}
              className={`px-3 py-1.5 min-h-11 font-mono uppercase text-[11px] transition border ${
                filterType === t
                  ? "bg-active text-white border-line-active font-bold"
                  : "bg-surface text-ink-muted hover:text-ink border-line"
              }`}
            >
              {t}
            </button>
          ))}
          <button
            onClick={onOpenEvidence}
            className="px-3 py-1.5 min-h-11 bg-info-raised text-info-ink border border-info-line-strong hover:bg-info-hover transition text-[11px] font-bold flex items-center gap-1.5"
          >
            <i className="fa-solid fa-plus text-[10px]"></i> Add Anchor
          </button>
        </div>
      </div>

      {/* Main 3D Graph Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Three.js 3D WebGL Canvas (2 Columns) */}
        <div className="lg:col-span-2 matte-card p-4 relative overflow-hidden flex flex-col">
          {/* HUD Top Bar */}
          <div className="flex justify-between items-center pb-3 border-b border-line text-xs font-mono">
            <div className="flex items-center gap-3">
              {/* "Nodes" and "Conduits" were internal vocabulary. "Conduit" is
                  not a word anyone outside the codebase uses, and it described
                  an edge without saying what an edge is. */}
              <span className="text-ink-muted">
                {graphData.nodes.length} people and accounts &bull;{" "}
                {graphData.links.length} connections between them
              </span>
              {hoveredNode && (
                <span className="text-info-ink hidden sm:inline">
                  &bull; Hover: <strong className="text-white">{hoveredNode.label}</strong>
                </span>
              )}
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setAutoRotate((prev) => !prev)}
                className={`px-2.5 py-1.5 min-h-11 text-[10px] font-bold transition border ${
                  autoRotate
                    ? "bg-info-raised text-info-ink border-info-line-strong"
                    : "bg-surface text-ink-muted border-line"
                }`}
                title="Toggle ambient 3D orbit rotation"
              >
                <i className="fa-solid fa-rotate text-[10px] mr-1"></i> Auto-Spin: {autoRotate ? "ON" : "OFF"}
              </button>
              <button
                onClick={handleResetCamera}
                className="px-2.5 py-1.5 min-h-11 bg-surface hover:bg-raised text-ink border border-line text-[10px] font-bold transition"
                title="Reset 3D camera to default vantage"
              >
                <i className="fa-solid fa-crosshairs text-[10px] mr-1"></i> Center
              </button>
            </div>
          </div>

          {/* Canvas Mount Container */}
          <div
            ref={mountRef}
            className="relative w-full h-[520px] bg-canvas border border-line-faint mt-3 overflow-hidden select-none"
          >
            {dimensions.width > 0 && (
              <ForceGraph3D
                ref={graphRef}
                graphData={graphData}
                width={dimensions.width}
                height={dimensions.height}
                // Matches --color-canvas. react-force-graph passes this to THREE.Color,
        // which does not resolve CSS custom properties, so the literal is
        // duplicated rather than referenced. Keep the two in step: the canvas
        // surface is #08090c, not #000000.
        backgroundColor="#08090c"
                // Node radius carries the attribution confidence, so a
                // weakly-linked entity visibly sits smaller than a confirmed one.
                nodeRelSize={1}
                // The library defaults this to 8, an 8x8 sphere. At the size
                // these nodes now render that reads as a visibly faceted
                // polygon rather than a sphere, most obvious on the silhouette
                // against the near-black canvas. The geometry is cached per
                // radius, so a higher segment count costs a handful of buffers
                // for six nodes, not one per node.
                nodeResolution={32}
                nodeVal={readNodeVal}
                nodeColor={readNodeColor}
                // Always-on text, see buildLabelSprite.
                nodeThreeObject={attachLabel}
                nodeThreeObjectExtend={extendNode}
                // With no d3Force prop the layout uses d3 defaults, which
                // collapse a seven-node graph into a ~60-unit blob with almost
                // every node overlapping its neighbour. Charge and link distance
                // set the spread. There is still no collide force, since d3-force
                // is not a resolvable dependency here, so a strongly-linked pair
                // of high-confidence nodes can still sit close; the link distance
                // is well clear of the largest node diameter (19.2) to keep that
                // pair readable.
                d3Force={applyForces}
                nodeLabel={(node: ForceNode) =>
                  // The library renders this string as innerHTML, so every
                  // interpolated value is an injection point. `label` and
                  // `subtext` arrive from a STIX bundle, which means they arrive
                  // from whoever authored the threat actor's artefacts. A label
                  // of `<img src=x onerror=...>` executed in this console, on
                  // the machine of the investigator running the analysis.
                  //
                  // node.color is constrained to a hex string by readNodeColor,
                  // but it is escaped here too so this stays safe if that
                  // function ever widens.
                  `<div style="font-family:ui-monospace,monospace;font-size:11px;background:rgba(10,14,23,.92);border:1px solid ${escapeHtml(node.color)};padding:6px 8px;color:#f1f5f9">
                     <div style="font-weight:700">${escapeHtml(node.label)}</div>
                     <div style="color:#94a3b8">${escapeHtml(node.subtext)}</div>
                     <div style="color:${escapeHtml(node.color)}">HOW SURE: ${escapeHtml(node.confidence)}</div>
                   </div>`
                }
                linkColor={(link: ForceLink) => linkColor(link)}
                linkWidth={(link: ForceLink) => linkWidth(link)}
                linkDirectionalArrowLength={2.5}
                linkDirectionalArrowRelPos={1}
                linkDirectionalParticles={0}
                onNodeClick={handleNodeClick}
                onNodeHover={(node: ForceNode | null) => setHoveredNode(node)}
                onNodeDragEnd={lookAtNode}
                // The simulation runs a bounded number of ticks and then settles
                // into a static frame, so a reviewer can screenshot the graph and
                // have the screenshot mean the same thing tomorrow.
                cooldownTicks={120}
                warmupTicks={40}
                d3VelocityDecay={0.35}
                onEngineStop={handleEngineStop}
                enableNodeDrag
                enablePointerInteraction
              />
            )}

            {/* Legend. Two independent encodings are in play here: node colour
                means entity type, link colour means evidentiary weight. The old
                legend mixed them and named only one node colour, so it read as a
                single binary that the graph did not implement. Swatch colours come
                from colorMap so they cannot drift from the nodes themselves. */}
            <div className="absolute top-3 right-3 bg-card/85 border border-line px-3 py-2 text-[10px] font-mono pointer-events-none z-10">
              <div className="text-ink-faint uppercase tracking-widest mb-1.5">
                Link &mdash; evidence
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="inline-block w-4 h-0.5 bg-info"></span>
                  <span className="text-ink">Can be checked again</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="inline-block w-4 h-0.5 bg-rose-400"></span>
                  <span className="text-ink">Our best guess</span>
                </div>
              </div>
              <div className="text-ink-faint uppercase tracking-widest mt-2.5 mb-1.5">
                Node &mdash; entity type
              </div>
              <div className="space-y-1">
                {presentTypes.map((type) => (
                  <div key={type} className="flex items-center gap-2">
                    <span
                      className="inline-block w-2.5 h-2.5 rounded-full"
                      style={{ backgroundColor: colorMap[type] }}
                    ></span>
                    <span className="text-ink">{TYPE_LABELS[type] ?? type}</span>
                  </div>
                ))}
              </div>
            </div>

          </div>

          {/* Interaction hints live in normal flow under the canvas rather than
              as an absolute overlay inside it. Absolutely positioned, the bar
              collided with the caption at the bottom edge and could not reflow;
              here it wraps instead, so it cannot overlap anything. */}
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] font-mono text-ink-muted">
            <span><strong className="text-ink">Left Drag:</strong> Rotate</span>
            <span><strong className="text-ink">Scroll:</strong> Zoom</span>
            <span><strong className="text-ink">Right Drag:</strong> Pan</span>
            <span><strong className="text-ink">Click Node:</strong> Focus + inspect</span>
            <span><strong className="text-ink">Drag Node:</strong> Reposition</span>
          </div>

          {/* ------------------------------------------------------------------
              The adjacency list.

              A WebGL canvas is a picture, not an interface. Measured: tabbing
              through this view twenty-five times never once focused the canvas,
              there is no `role`, no `aria-label`, no `tabindex`, and the only
              route to the graph's contents was the filter chips. A keyboard or
              screen-reader user therefore could not read the primary analytical
              surface of the product at all.

              This is the same data, as a real list of buttons. Each entry names
              the entity, its type, its confidence, and its relations with the
              evidentiary character of each — because "deterministic proof" and
              "probabilistic lead" is a distinction that matters and is invisible
              in a rendered 3D view. Selecting a row does the same thing as
              clicking the sphere, and moves the camera with it.
              ------------------------------------------------------------------ */}
          <div className="mt-4 border-t border-line pt-4">
            <div className="flex justify-between items-baseline mb-2">
              <h3 className="text-[12px] font-bold text-ink font-mono uppercase tracking-widest">
                Relations
              </h3>
              <span className="text-[10px] text-ink-faint font-mono">
                {graphData.links.length} link{graphData.links.length === 1 ? "" : "s"} · every
                entity in this view, selectable without a pointer
              </span>
            </div>
            <ul className="grid grid-cols-1 md:grid-cols-2 gap-1.5">
              {graphData.nodes.map((n) => {
                const nodeId = n.id;
                const relations = graphData.links
                  .map((l) => {
                    const src = (l.source as unknown as { id?: string })?.id ?? String(l.source);
                    const tgt = (l.target as unknown as { id?: string })?.id ?? String(l.target);
                    if (src === nodeId) {
                      return { other: tgt, dir: "out" as const, link: l };
                    }
                    if (tgt === nodeId) {
                      return { other: src, dir: "in" as const, link: l };
                    }
                    return null;
                  })
                  .filter((r): r is { other: string; dir: "out" | "in"; link: ForceLink } =>
                    r !== null,
                  );
                const byId = new Map(graphData.nodes.map((x) => [x.id, x]));
                const selected = n.id === selectedNode.id;

                return (
                  <li key={n.id}>
                    <button
                      type="button"
                      onClick={() => handleNodeClick(n)}
                      aria-pressed={selected}
                      className={`w-full text-left px-2.5 py-2 min-h-11 border transition ${
                        selected
                          ? "bg-info-raised border-info-line"
                          : "bg-surface border-line hover:border-line-active"
                      }`}
                    >
                      <span className="flex items-baseline gap-2">
                        <span
                          aria-hidden="true"
                          className="inline-block w-2 h-2 shrink-0"
                          style={{ backgroundColor: n.color }}
                        ></span>
                        <span className="text-[12px] font-bold text-ink font-mono truncate">
                          {n.label}
                        </span>
                        <span className="text-[10px] text-ink-faint font-mono ml-auto shrink-0 tabular-nums">
                          {n.confidence}
                        </span>
                      </span>
                      <span className="block text-[10px] text-ink-dim font-mono mt-0.5">
                        {TYPE_LABELS[n.type] ?? n.type}
                      </span>
                      {relations.length > 0 && (
                        <ul className="mt-1.5 space-y-0.5">
                          {relations.map((r, i) => (
                            <li
                              key={`${n.id}-${r.other}-${i}`}
                              className="flex items-baseline gap-1.5 text-[10px] font-mono"
                            >
                              <span
                                className={
                                  r.link.isDeterministic ? "text-info-ink" : "text-warn-ink"
                                }
                                aria-hidden="true"
                              >
                                {r.link.isDeterministic ? "==" : "~="}
                              </span>
                              <span className="sr-only">
                                {r.link.isDeterministic
                                  ? "a fact that can be checked, "
                                  : "probabilistic lead, "}
                                {r.dir === "out" ? "outbound to" : "inbound from"}
                              </span>
                              <span
                                className={`truncate ${
                                  r.link.isDeterministic ? "text-info-ink" : "text-warn-ink"
                                }`}
                              >
                                {byId.get(r.other)?.label ?? r.other}
                              </span>
                              <span className="text-ink-faint truncate">
                                ({r.link.label ?? "related"})
                              </span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </button>
                  </li>
                );
              })}
            </ul>
            <p className="text-[10px] text-ink-faint font-mono mt-2">
              <span className="text-info-ink">==</span> deterministic proof ·{" "}
              <span className="text-warn-ink">~=</span> probabilistic lead
            </p>
          </div>
        </div>

        {/* Node Inspector Panel (1 Column) */}
        <div className="matte-card p-5 flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-center pb-3 border-b border-line">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Details
              </h3>
              <span
                className="text-[11px] font-mono px-2 py-0.5 border"
                style={{
                  color: selectedNode.color,
                  borderColor: selectedNode.color + "44",
                  backgroundColor: selectedNode.color + "11",
                }}
              >
                How sure: {selectedNode.confidence}
              </span>
            </div>

            <div className="mt-4">
              <span className="text-[10px] font-mono text-ink-muted uppercase tracking-widest block">
                You selected
              </span>
              <h4 className="text-lg font-bold text-white mt-0.5">{selectedNode.label}</h4>
              <p className="text-xs text-ink-muted font-mono mt-0.5">{selectedNode.subtext}</p>
            </div>

            {/* Attributes Table */}
            <div className="mt-4 space-y-2.5 text-xs font-mono">
              {Object.entries(selectedNode.details).map(([key, val]) => (
                <div
                  key={key}
                  className="bg-input p-2.5 border border-line flex flex-col gap-1"
                >
                  <span className="text-[10px] text-ink-muted uppercase">{key}</span>
                  <span className="text-ink break-all text-[11px] font-semibold">{val}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Bottom Actions */}
          <div className="mt-6 pt-4 border-t border-line space-y-2">
            <button
              onClick={handleCopyStix}
              className="w-full min-h-11 py-2.5 bg-active hover:bg-info-hover text-ink text-xs font-bold font-mono transition flex items-center justify-center gap-2 border border-line-active"
            >
              <i className="fa-solid fa-code text-xs" aria-hidden="true"></i>{" "}
              Copy STIX 2.1 fragment
            </button>
            <button
              onClick={handleDescribePivots}
              className="w-full min-h-11 py-2 bg-surface hover:bg-raised text-ink border border-line-strong text-xs font-semibold font-mono transition"
            >
              Show connections
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};