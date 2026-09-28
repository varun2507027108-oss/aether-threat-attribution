"use client";

import React, { useState } from "react";
import { Modal } from "@/components/Modal";
import { checkBackendHealth } from "@/lib/api";

interface EngineConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onShowToast: (title: string, message: string) => void;
}

export const EngineConfigModal: React.FC<EngineConfigModalProps> = ({
  isOpen,
  onClose,
  onShowToast,
}) => {
  const [torHost, setTorHost] = useState<string>("127.0.0.1");
  const [torPort, setTorPort] = useState<string>("9050");
  const [torEnabled, setTorEnabled] = useState<boolean>(true);
  const [backendUrl, setBackendUrl] = useState<string>("http://localhost:8000");
  const [neo4jUrl, setNeo4jUrl] = useState<string>("bolt://localhost:7687");
  const [pinging, setPinging] = useState<boolean>(false);
  const [pingResult, setPingResult] = useState<{ status: string; latency: number } | null>(null);

  const handlePing = async () => {
    setPinging(true);
    const start = performance.now();
    try {
      const res = await checkBackendHealth();
      const latency = Math.round(performance.now() - start);
      if (res.online) {
        setPingResult({ status: "ONLINE (HTTP 200)", latency });
        onShowToast("Backend Gateway Connected", `FastAPI responding at ${backendUrl} (${latency}ms).`);
      } else {
        setPingResult({ status: "UNREACHABLE", latency });
        onShowToast("Connection Warning", "FastAPI backend did not respond at target URL.");
      }
    } catch {
      setPingResult({ status: "ERROR", latency: 0 });
    } finally {
      setPinging(false);
    }
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    onShowToast(
      "Configuration Saved",
      `Tor Proxy: ${torHost}:${torPort} | Backend: ${backendUrl}`
    );
    onClose();
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Engine configuration"
      size="sm"
    >
        {/* Modal Header */}
        <div className="flex justify-between items-center border-b border-line pb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 bg-active text-white flex items-center justify-center text-xs border border-line-active">
              <i className="fa-solid fa-sliders"></i>
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Engine Configuration</h3>
              <p className="text-[11px] text-ink-muted font-mono">Gateway &amp; Recon Proxy Settings</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 bg-info-surface text-ink-muted flex items-center justify-center hover:bg-active hover:text-white border border-line-strong transition"
            title="Close"
          >
            <i className="fa-solid fa-xmark text-xs"></i>
          </button>
        </div>

        {/* Configuration Form */}
        <form onSubmit={handleSave} className="py-4 space-y-4 text-xs font-mono">
          {/* Tor SOCKS5 Settings */}
          <div>
            <div className="flex justify-between items-center mb-1">
              <label className="text-ink uppercase text-[10px] font-bold">
                Tor SOCKS5 Proxy Circuit
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer text-[10px] text-ink-muted">
                <input
                  type="checkbox"
                  checked={torEnabled}
                  onChange={(e) => setTorEnabled(e.target.checked)}
                  className="accent-ink"
                />
                Enabled
              </label>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <input
                type="text"
                value={torHost}
                onChange={(e) => setTorHost(e.target.value)}
                placeholder="Host"
                className="col-span-2 bg-input border border-line-strong p-2 text-ink"
              />
              <input
                type="text"
                value={torPort}
                onChange={(e) => setTorPort(e.target.value)}
                placeholder="Port"
                className="bg-input border border-line-strong p-2 text-ink"
              />
            </div>
          </div>

          {/* FastAPI Backend URL */}
          <div>
            <label className="text-ink block mb-1 uppercase text-[10px] font-bold">
              FastAPI Forensic Backend URL
            </label>
            <input
              type="text"
              value={backendUrl}
              onChange={(e) => setBackendUrl(e.target.value)}
              placeholder="http://localhost:8000"
              className="w-full bg-input border border-line-strong p-2 text-ink"
            />
          </div>

          {/* Neo4j Bolt URL */}
          <div>
            <label className="text-ink block mb-1 uppercase text-[10px] font-bold">
              Neo4j Graph Database
            </label>
            <input
              type="text"
              value={neo4jUrl}
              onChange={(e) => setNeo4jUrl(e.target.value)}
              placeholder="bolt://localhost:7687"
              className="w-full bg-input border border-line-strong p-2 text-ink"
            />
          </div>

          {/* Gateway Ping Status */}
          <div className="bg-input border border-line p-3 flex justify-between items-center">
            <div>
              <span className="text-[10px] text-ink-muted block uppercase">Gateway Telemetry</span>
              <span className="text-xs font-bold text-signal-ink">
                {pingResult ? `${pingResult.status} (${pingResult.latency}ms)` : "127.0.0.1:8000"}
              </span>
            </div>
            <button
              type="button"
              onClick={handlePing}
              disabled={pinging}
              className="px-3 py-1.5 bg-raised hover:bg-active text-info-ink border border-line-active text-[11px] font-bold transition flex items-center gap-1.5"
            >
              {pinging ? (
                <span className="inline-block w-3 h-3 border-2 border-white border-t-transparent animate-spin"></span>
              ) : (
                <i className="fa-solid fa-satellite-dish text-[10px]"></i>
              )}
              Ping Gateway
            </button>
          </div>

          {/* Form Actions */}
          <div className="flex gap-2 pt-2">
            <button
              type="submit"
              className="w-full py-2.5 bg-active hover:bg-info-hover text-white font-bold transition border border-line-active flex items-center justify-center gap-2"
            >
              <i className="fa-solid fa-check text-xs"></i> Save &amp; Apply
            </button>
          </div>
        </form>
    </Modal>
  );
};
