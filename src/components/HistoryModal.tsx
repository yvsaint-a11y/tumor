import React from 'react';
import { ScanReport } from '../types/scanner.js';
import { X, Trash2, History, ArrowRight } from 'lucide-react';

interface HistoryModalProps {
  isOpen: boolean;
  onClose: () => void;
  history: ScanReport[];
  onSelectReport: (report: ScanReport) => void;
  onClearHistory: () => void;
  onGoHome?: () => void;
}

export const HistoryModal: React.FC<HistoryModalProps> = ({
  isOpen,
  onClose,
  history,
  onSelectReport,
  onClearHistory,
  onGoHome,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm">
      <div className="bg-[#1D1713] border border-[#382D25] rounded-2xl max-w-lg w-full p-6 shadow-2xl relative max-h-[85vh] flex flex-col">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-2 text-[#A39382] hover:text-[#F2E9DF] rounded-lg hover:bg-[#382D25]/40 transition"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 rounded-xl bg-[#382D25]/40 border border-[#382D25] text-[#F2E9DF]">
            <History className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-[#F2E9DF]">Scan history</h3>
            <p className="text-xs text-[#A39382]">Previous reports stored safely in your browser</p>
          </div>
        </div>

        {history.length === 0 ? (
          <div className="py-12 text-center px-4">
            <p className="text-xs text-[#A39382]">You haven't run any scans yet.</p>
            <button
              type="button"
              onClick={() => {
                onClose();
                if (onGoHome) onGoHome();
              }}
              className="mt-3 text-xs text-[#F2E9DF] underline underline-offset-4 hover:text-white transition cursor-pointer"
            >
              Back to Home
            </button>
          </div>
        ) : (
          <div className="space-y-2.5 overflow-y-auto flex-1 my-2">
            {history.map((rep) => {
              const gradeColors = {
                A: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
                B: 'text-[#D9822B] bg-[#D9822B]/10 border-[#D9822B]/30',
                C: 'text-[#D9B84A] bg-[#D9B84A]/10 border-[#D9B84A]/30',
                D: 'text-[#D96B43] bg-[#D96B43]/10 border-[#D96B43]/30',
                F: 'text-[#D9534F] bg-[#D9534F]/10 border-[#D9534F]/30',
              }[rep.rubric.grade];

              return (
                <div
                  key={rep.id}
                  onClick={() => {
                    onSelectReport(rep);
                    onClose();
                  }}
                  className="p-3.5 rounded-xl bg-[#14100D] border border-[#382D25] hover:border-[#A39382]/60 cursor-pointer transition flex items-center justify-between group"
                >
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-9 h-9 rounded-lg border font-bold flex items-center justify-center text-sm ${gradeColors}`}
                    >
                      {rep.rubric.grade}
                    </div>
                    <div>
                      <p className="text-xs font-bold text-[#F2E9DF] group-hover:text-[#F2E9DF] transition">
                        {rep.repoName}
                      </p>
                      <div className="flex items-center gap-3 mt-0.5 text-[11px] text-[#A39382]">
                        <span>{rep.rubric.score}/100</span>
                        <span>{rep.findings.length} findings</span>
                        <span>{new Date(rep.scannedAt).toLocaleDateString()}</span>
                      </div>
                    </div>
                  </div>

                  <ArrowRight className="w-4 h-4 text-[#A39382] group-hover:text-[#F2E9DF] group-hover:translate-x-0.5 transition" />
                </div>
              );
            })}
          </div>
        )}

        <div className="mt-4 pt-4 border-t border-[#382D25] flex items-center justify-between">
          {history.length > 0 && (
            <button
              onClick={onClearHistory}
              className="flex items-center gap-1.5 text-xs text-[#D9534F] hover:text-[#D9534F]/80 transition"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear history</span>
            </button>
          )}
          <button
            onClick={onClose}
            className="ml-auto px-4 py-2 text-xs font-medium rounded-xl bg-[#14100D] border border-[#382D25] hover:bg-[#382D25]/40 text-[#F2E9DF] transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
