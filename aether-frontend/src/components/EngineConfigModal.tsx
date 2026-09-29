"use client";

import React, { useState } from "react";
import type { ToastSeverity } from "@/components/Toast";
import { Modal } from "@/components/Modal";
import { checkBackendHealth, API_BASE } from "@/lib/api";

interface EngineConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onShowToast: (title: string, message: string, severity?: ToastSeverity) => void;
}

export const EngineConfigModal: React.FC<EngineConfigModalProps> = ({
  isOpen,
  onClose,
  onShowToast,
}) => {
  const [torHost, setTorHost] = useState<string>("127.0.0.1");
  const [torPort, setTorPort] = useState<string>("9050");
  const [torEnabled, setTorEnabled] = useState<boolean>(true);
  const [backendUrl, setBackendUrl] = useState<string>(API_BASE);
  const [pinging, setPinging] = useState<boolean>(false);
  const [pingResult, setPingResult] = useState<{ status: string; latency: number } | null>(null);

  // This pings the URL the bundle was compiled with (API_BASE), NOT the URL in
  // the form. It used to report the typed value back as the dialled address,
  // which is a claim the code never tested.
  const handlePing = async () => {
    setPinging(true);
    const start = performance.now();
    try {
      const res = await checkBackendHealth();
      const latency = Math.round(performance.now() - start);
      if (res.online) {
        setPingResult({ status: "ONLINE (HTTP 200)", latency });
        onShowToast("Backend Gateway Connected", `FastAPI responding at ${API_BASE} (${latency}ms).`);
      } else {
        setPingResult({ status: "UNREACHABLE", latency });
        onShowToast("Connection Warning", `FastAPI did not respond at the compiled gateway ${API_BASE}.`);
      }
    } catch {
      setPingResult({ status: "ERROR", latency: 0 });
    } finally {
      setPinging(false);
    }
  };

  // The fields below are a display of the engine's configuration; there is no
  // server-side settings endpoint, so nothing here can be applied. The old
  // handler toasted "Configuration Saved", which asserted a persistence that
  // does not exist. It now says plainly that the values are read-only.
  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    onShowToast(
      "Not Persisted",
      `Tor proxy ${torHost}:${torPort} and backend ${backendUrl} are display-only — this build has no settings endpoint, so nothing was saved.`
    );
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
            <div className="w-8 h-8 bg-active text-ink flex items-center justify-center text-xs border border-line-active">
              <i className="fa-solid fa-sliders"></i>
            </div>
            <div>
              <h3 className="text-base font-bold text-ink">Engine Configuration</h3>
              <p className="text-[11px] text-ink-muted font-mono">Gateway &amp; Recon Proxy Settings</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-11 h-11 bg-info-surface text-ink-muted flex items-center justify-center hover:bg-active hover:text-ink border border-line-strong transition"
            title="Close"
            aria-label="Close engine configuration"
          >
            <i className="fa-solid fa-xmark text-xs" aria-hidden="true"></i>
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

          {/* Gateway Ping Status. The placeholder used to be a hardcoded
              "127.0.0.1:8000" shown in signal green before any ping had run,
              which read as a live result. It now states the compiled-in gateway
              and says it has not been contacted. */}
          <div className="bg-input border border-line p-3 flex justify-between items-center">
            <div>
              <span className="text-[10px] text-ink-muted block uppercase">Gateway Telemetry</span>
              <span
                className={`text-xs font-bold ${pingResult ? "text-signal-ink" : "text-ink-dim"}`}
              >
                {pingResult
                  ? `${pingResult.status} (${pingResult.latency}ms)`
                  : `Not yet contacted — ${API_BASE}`}
              </span>
            </div>
            <button
              type="button"
              onClick={handlePing}
              disabled={pinging}
              className="px-3 py-1.5 bg-raised hover:bg-active text-info-ink border border-line-active text-[11px] font-bold transition flex items-center gap-1.5"
            >
              {pinging ? (
                <span className="inline-block w-3 h-3 border-2 border-ink border-t-transparent animate-spin"></span>
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
              className="w-full min-h-11 py-2.5 bg-active hover:bg-info-hover text-ink font-bold transition border border-line-active flex items-center justify-center gap-2"
            >
              <i className="fa-solid fa-circle-info text-xs" aria-hidden="true"></i>{" "}
              Explain these values
            </button>
          </div>
        </form>
    </Modal>
  );
};
