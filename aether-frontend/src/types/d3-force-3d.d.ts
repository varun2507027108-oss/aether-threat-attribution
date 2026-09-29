// d3-force-3d ships no type declarations and there is no @types package for it
// (npm 404s), so the two forces the entity graph installs are declared here.
//
// This is deliberately narrow: only the surface KnowledgeGraphView actually
// calls is described, so that adding a force without declaring it is a compile
// error rather than an implicit `any` that silently un-types itself.

declare module "d3-force-3d" {
  /** Every d3 force is a function of alpha, initialised against the node set. */
  export interface Force<Node> {
    (alpha: number): void;
    initialize(nodes: Node[]): void;
  }

  interface ForceWithStrength<Node> extends Force<Node> {
    strength(): number;
    strength(strength: number): this;
  }

  type Positioned = { x?: number; y?: number; z?: number };

  /**
   * Resolves nodes apart so their padded circles do not intersect. The circle
   * radius is what decides legibility here: measured against the sphere it
   * leaves the label sprites free to overprint, so the graph passes the label
   * footprint instead.
   */
  export interface ForceCollide<Node extends Positioned> extends Force<Node> {
    radius(): (node: Node, i: number, nodes: Node[]) => number;
    radius(
      radius: number | ((node: Node, i: number, nodes: Node[]) => number),
    ): this;
    strength(): number;
    strength(strength: number): this;
    iterations(): number;
    iterations(iterations: number): this;
  }

  export function forceCollide<Node extends Positioned>(): ForceCollide<Node>;

  /** Pulls nodes toward a target coordinate on one axis. */
  export function forceX<Node extends Positioned>(x?: number): ForceWithStrength<Node>;
  export function forceY<Node extends Positioned>(y?: number): ForceWithStrength<Node>;
  export function forceZ<Node extends Positioned>(z?: number): ForceWithStrength<Node>;

  export function forceLink<Node extends Positioned>(force?: unknown): Force<Node>;
  export function forceManyBody<Node extends Positioned>(): ForceWithStrength<Node>;
  export function forceCenter<Node extends Positioned>(
    x?: number,
    y?: number,
    z?: number,
  ): Force<Node>;
}
