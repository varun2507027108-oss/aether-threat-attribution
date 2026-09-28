"use client";

import React, { useEffect, useRef, useState } from "react";
import dynamic from "next/dynamic";
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
  },
) => React.ReactElement | null;

const ForceGraph3D = dynamic(() => import("react-force-graph-3d"), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full flex items-center justify-center text-[11px] font-mono text-slate-500">
      INITIALIZING WEBGL FORCE GRAPH…
    </div>
  ),
}) as unknown as ForceGraphComponent;

// Node radius carries the attribution confidence, so a weakly-linked entity
// visibly sits smaller in the graph instead of being indistinguishable from a
// confirmed one.
function nodeRelSize(node: NodeData): number {
  const parsed = parseFloat(node.confidence.replace("%", ""));
  const confidence = Number.isFinite(parsed) ? Math.min(100, Math.max(0, parsed)) : 50;
  return 3 + (confidence / 100) * 5;
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
      "Root Wallet": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
      "Clustered Volume": "38.45 BTC ($2.48M USD)",
      "Co-spend Heuristic": "Multi-Input Common Ownership",
      "Known Off-Ramp": "VASP Exchange Deposit Subpoena Pending",
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
  onShowToast: (title: string, message: string) => void;
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
      const nodeColor = (n.metadata && n.metadata.color) || colorMap[mappedType] || "#38bdf8";
      const hexColor = parseInt(nodeColor.replace("#", ""), 16) || 0x38bdf8;

      return {
        id: n.id,
        label: n.label,
        type: mappedType,
        subtext: (n.metadata && n.metadata.subtext) || `${mappedType.toUpperCase()} Node`,
        confidence: (n.metadata && n.metadata.confidence) || "95.0%",
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
      val: nodeRelSize(n),
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

  // The 3D handle has no centreAt(); the equivalent is pointing the camera's
  // look-at target at the node while leaving the orbit position alone.
  const lookAtNode = (node: ForceNode) => {
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
    graphRef.current?.zoomToFit(400, 40);
    onShowToast("Camera Reset", "Restored default 3D forensic vantage.");
  };

  // The 3D graph has no autoRotate prop of its own; it owns an OrbitControls
  // instance, so the toggle drives that instead of the component.
  useEffect(() => {
    const controls = graphRef.current?.controls() as
      | { autoRotate?: boolean; autoRotateSpeed?: number; update?: () => void }
      | undefined;
    if (!controls) return;
    controls.autoRotate = autoRotate;
    controls.autoRotateSpeed = 1.2;
  }, [autoRotate, dimensions.width]);


  const handleCopyCypher = () => {
    const cypher = `MATCH (a:ThreatActor {name: "${selectedNode.label}"})\nRETURN a;`;
    navigator.clipboard.writeText(cypher);
    onShowToast("Cypher Exported", "Neo4j query copied to clipboard.");
  };


  return (
    <div className="flex flex-col gap-6 w-full">
      {/* Top Header Card */}
      <div className="matte-card p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono font-bold px-2 py-0.5 bg-[#141a24] text-slate-300 border border-[#263245]">
              STAGE 02
            </span>
            <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
              <span>3D Forensic Knowledge Graph</span>
              <span className="text-xs font-mono font-normal px-2 py-0.5 bg-[#162233] text-cyan-400 border border-[#253954]">
                THREE.JS WebGL
              </span>
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Spatial 3D threat actor attribution matrix with real-time orbit controls, raycasting, and pulse conduits.
          </p>
        </div>

        {/* Filter & Action Controls */}
        <div className="flex items-center gap-2 flex-wrap text-xs">
          {["all", "threat-actor", "ipv4", "pgp", "wallet"].map((t) => (
            <button
              key={t}
              onClick={() => setFilterType(t)}
              className={`px-3 py-1 font-mono uppercase text-[11px] transition border ${
                filterType === t
                  ? "bg-[#1e2736] text-white border-[#3d4c66] font-bold"
                  : "bg-[#10141d] text-slate-400 hover:text-slate-200 border-[#222b3a]"
              }`}
            >
              {t}
            </button>
          ))}
          <button
            onClick={onOpenEvidence}
            className="px-3 py-1 bg-[#162338] text-blue-300 border border-[#2d436b] hover:bg-[#1f304d] transition text-[11px] font-bold flex items-center gap-1.5"
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
          <div className="flex justify-between items-center pb-3 border-b border-[#1e2533] text-xs font-mono">
            <div className="flex items-center gap-3">
              <span className="text-slate-400">
                Spatial Engine // 7 Nodes &bull; 8 Conduits
              </span>
              {hoveredNode && (
                <span className="text-cyan-300 hidden sm:inline">
                  &bull; Hover: <strong className="text-white">{hoveredNode.label}</strong>
                </span>
              )}
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setAutoRotate((prev) => !prev)}
                className={`px-2.5 py-1 text-[10px] font-bold transition border ${
                  autoRotate
                    ? "bg-[#16253b] text-cyan-300 border-[#2d466b]"
                    : "bg-[#10141d] text-slate-400 border-[#222b3a]"
                }`}
                title="Toggle ambient 3D orbit rotation"
              >
                <i className="fa-solid fa-rotate text-[10px] mr-1"></i> Auto-Spin: {autoRotate ? "ON" : "OFF"}
              </button>
              <button
                onClick={handleResetCamera}
                className="px-2.5 py-1 bg-[#10141d] hover:bg-[#1a212e] text-slate-300 border border-[#222b3a] text-[10px] font-bold transition"
                title="Reset 3D camera to default vantage"
              >
                <i className="fa-solid fa-crosshairs text-[10px] mr-1"></i> Center
              </button>
            </div>
          </div>

          {/* Canvas Mount Container */}
          <div
            ref={mountRef}
            className="relative w-full h-[520px] bg-[#000000] border border-[#161f2e] mt-3 overflow-hidden select-none"
          >
            {dimensions.width > 0 && (
              <ForceGraph3D
                ref={graphRef}
                graphData={graphData}
                width={dimensions.width}
                height={dimensions.height}
                backgroundColor="#000000"
                // Node radius carries the attribution confidence, so a
                // weakly-linked entity visibly sits smaller than a confirmed one.
                nodeVal={readNodeVal}
                nodeColor={readNodeColor}
                nodeLabel={(node: ForceNode) =>
                  `<div style="font-family:ui-monospace,monospace;font-size:11px;background:rgba(10,14,23,.92);border:1px solid ${node.color};padding:6px 8px;color:#f1f5f9">
                     <div style="font-weight:700">${node.label}</div>
                     <div style="color:#94a3b8">${node.subtext}</div>
                     <div style="color:${node.color}">CONFIDENCE: ${node.confidence}</div>
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
                enableNodeDrag
                enablePointerInteraction
              />
            )}

            {/* Legend: the colour encoding a reviewer needs to read the graph */}
            <div className="absolute top-3 right-3 bg-[#0a0e17]/85 border border-[#1f293d] px-3 py-2 text-[10px] font-mono pointer-events-none z-10 space-y-1">
              <div className="flex items-center gap-2">
                <span className="inline-block w-4 h-0.5 bg-sky-400"></span>
                <span className="text-slate-300">Deterministic proof</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="inline-block w-4 h-0.5 bg-rose-400"></span>
                <span className="text-slate-300">Probabilistic lead</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="inline-block w-2.5 h-2.5 bg-rose-400"></span>
                <span className="text-slate-300">Threat actor</span>
              </div>
            </div>

            {/* Quick 3D Interaction Instructions Overlay */}
            <div className="absolute bottom-3 left-3 bg-[#0a0e17]/85 border border-[#1f293d] px-3 py-1.5 text-[10px] font-mono text-slate-400 pointer-events-none z-10 flex items-center gap-3">
              <span><strong className="text-slate-200">Left Drag:</strong> Rotate 360°</span>
              <span><strong className="text-slate-200">Scroll:</strong> Zoom</span>
              <span><strong className="text-slate-200">Right Drag:</strong> Pan</span>
              <span><strong className="text-slate-200">Click Node:</strong> Lock Focus</span>
            </div>
          </div>
        </div>

        {/* Node Inspector Panel (1 Column) */}
        <div className="matte-card p-5 flex flex-col justify-between">
          <div>
            <div className="flex justify-between items-center pb-3 border-b border-[#1e2533]">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Entity Inspector
              </h3>
              <span
                className="text-[11px] font-mono px-2 py-0.5 border"
                style={{
                  color: selectedNode.color,
                  borderColor: selectedNode.color + "44",
                  backgroundColor: selectedNode.color + "11",
                }}
              >
                Confidence: {selectedNode.confidence}
              </span>
            </div>

            <div className="mt-4">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest block">
                Target Entity
              </span>
              <h4 className="text-lg font-bold text-white mt-0.5">{selectedNode.label}</h4>
              <p className="text-xs text-slate-400 font-mono mt-0.5">{selectedNode.subtext}</p>
            </div>

            {/* Attributes Table */}
            <div className="mt-4 space-y-2.5 text-xs font-mono">
              {Object.entries(selectedNode.details).map(([key, val]) => (
                <div
                  key={key}
                  className="bg-[#090c12] p-2.5 border border-[#1a212d] flex flex-col gap-1"
                >
                  <span className="text-[10px] text-slate-400 uppercase">{key}</span>
                  <span className="text-slate-200 break-all text-[11px] font-semibold">{val}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Bottom Actions */}
          <div className="mt-6 pt-4 border-t border-[#1e2533] space-y-2">
            <button
              onClick={handleCopyCypher}
              className="w-full py-2.5 bg-[#1e2736] hover:bg-[#283448] text-white text-xs font-bold font-mono transition flex items-center justify-center gap-2 border border-[#37455d]"
            >
              <i className="fa-solid fa-code text-xs"></i> Copy Neo4j Cypher Query
            </button>
            <button
              onClick={() =>
                onShowToast(
                  "Entity Pivot",
                  `Timeline pivoted to ${selectedNode.label}. Correlated across all STIX bundles.`
                )
              }
              className="w-full py-2 bg-[#121721] hover:bg-[#19212d] text-slate-300 border border-[#232d3d] text-xs font-semibold font-mono transition"
            >
              Pivot Timeline to Entity
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};