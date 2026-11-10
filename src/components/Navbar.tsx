import React from 'react';
import { ShieldCheck, History, BookOpen } from 'lucide-react';

interface NavbarProps {
  onOpenRules: () => void;
  onOpenHistory: () => void;
  historyCount: number;
  onGoHome?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  onOpenRules,
  onOpenHistory,
  historyCount,
  onGoHome,
}) => {
  return (
    <header className="border-b border-[#382D25] bg-[#14100D]/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-5xl mx-auto px-3 sm:px-6 h-14 sm:h-15 flex items-center justify-between gap-2">
        <button
          onClick={onGoHome}
          className="flex items-center gap-2 sm:gap-2.5 text-left group transition cursor-pointer shrink-0"
        >
          <div className="w-6 h-6 sm:w-7 sm:h-7 rounded-md bg-[#1D1713] border border-[#382D25] flex items-center justify-center text-[#F2E9DF] group-hover:border-[#A39382]/40 transition shrink-0">
            <ShieldCheck className="w-3.5 h-3.5 sm:w-4 sm:h-4 text-[#F2E9DF]" />
          </div>
          <span className="font-headline font-semibold text-[#F2E9DF] text-sm sm:text-base tracking-tight whitespace-nowrap">
            <span className="sm:hidden">Vibe Scanner</span>
            <span className="hidden sm:inline">Vibe Code Health Scanner</span>
          </span>
        </button>

        <div className="flex items-center gap-1 sm:gap-2 shrink-0">
          <button
            onClick={onOpenRules}
            className="flex items-center gap-1 sm:gap-1.5 px-2 sm:px-3 py-1.5 text-xs text-[#A39382] hover:text-[#F2E9DF] hover:bg-[#1D1713] rounded-md border border-transparent hover:border-[#382D25] transition cursor-pointer whitespace-nowrap shrink-0"
          >
            <BookOpen className="w-3.5 h-3.5 shrink-0" />
            <span className="whitespace-nowrap">Agent rules</span>
          </button>

          <button
            onClick={onOpenHistory}
            className="flex items-center gap-1 sm:gap-1.5 px-2 sm:px-3 py-1.5 text-xs text-[#A39382] hover:text-[#F2E9DF] hover:bg-[#1D1713] rounded-md border border-transparent hover:border-[#382D25] transition cursor-pointer whitespace-nowrap shrink-0"
          >
            <History className="w-3.5 h-3.5 shrink-0" />
            <span className="whitespace-nowrap">History</span>
            {historyCount > 0 && (
              <span className="ml-0.5 px-1.5 py-0.2 rounded bg-[#1D1713] border border-[#382D25] text-[10px] text-[#A39382] shrink-0">
                {historyCount}
              </span>
            )}
          </button>
        </div>
      </div>
    </header>
  );
};
