import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /**
   * Emits .next/standalone with a self-contained server.js and only the
   * node_modules actually imported, which is what the Docker image runs.
   */
  output: "standalone",
};

export default nextConfig;
