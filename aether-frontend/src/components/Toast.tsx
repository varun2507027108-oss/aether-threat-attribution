"use client";

import React from "react";

export interface ToastData {
  title: string;
  message: string;
  visible: boolean;
}

interface ToastProps {
  toast: ToastData;
  onDismiss: () => void;
}

export const Toast: React.FC<ToastProps> = ({ toast, onDismiss }) => {
  return (
    <div
      onClick={onDismiss}
      className={`fixed bottom-6 right-6 bg-card border border-line-strong text-white px-4 py-3 transform transition-all duration-300 z-50 flex items-center gap-3 cursor-pointer shadow-none ${
        toast.visible
          ? "translate-y-0 opacity-100"
          : "translate-y-24 opacity-0 pointer-events-none"
      }`}
    >
      <div className="w-8 h-8 bg-info-surface text-ink flex items-center justify-center shrink-0 border border-line-strong">
        <i className="fa-solid fa-satellite-dish text-xs"></i>
      </div>
      <div>
        <h4 className="text-xs font-bold text-white tracking-wide">{toast.title}</h4>
        <p className="text-[11px] text-ink-muted mt-0.5 leading-snug">{toast.message}</p>
      </div>
    </div>
  );
};
