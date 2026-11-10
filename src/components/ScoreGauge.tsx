import React from 'react';
import { RubricScore, StackDetection, ScanCoverage } from '../types/scanner.js';
import { FileCode, OctagonAlert, TriangleAlert, CircleAlert, Info } from 'lucide-react';

interface ScoreGaugeProps {
  rubric: RubricScore;
  stack: StackDetection;
  coverage: ScanCoverage;
  repoName: string;
  isSampleRepo?: boolean;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({
  rubric,
  stack,
  coverage,
  repoName,
  isSampleRepo,
}) => {
  const getGradeColor = (grade: string) => {
    switch (grade) {
      case 'A':
        return 'text-[#F2E9DF]';
      case 'B':
        return 'text-[#7FA6C9]';
      case 'C':
        return 'text-[#D9B84A]';
      case 'D':
        return 'text-[#F2874B]';
      case 'F':
      default:
        return 'text-[#E5484D]';
    }
  };

  const filesScanned = coverage?.filesScanned || stack.totalFilesScanned || 0;
  const totalScannable = coverage?.totalScannableFiles || coverage?.totalFilesInRepo || filesScanned;
  const skippedSize = coverage?.skippedSummary?.tooLarge || 0;
  const skippedCap = coverage?.skippedSummary?.overCap || 0;

  const getPartialDescription = () => {
    if (skippedSize > 0 && skippedCap > 0) {
      return `${skippedCap} source file${skippedCap === 1 ? '' : 's'} over cap and ${skippedSize} file${skippedSize === 1 ? '' : 's'} skipped because of the size limit; this score may be too optimistic.`;
    }
    if (skippedSize > 0) {
      return `${skippedSize} source file${skippedSize === 1 ? '' : 's'} skipped because of the size limit; this score may be too optimistic.`;
    }
    if (skippedCap > 0) {
      return `${skippedCap} source file${skippedCap === 1 ? '' : 's'} skipped because of the file cap; this score may be too optimistic.`;
    }
    return `Scanned ${filesScanned} of ${totalScannable} scannable files; this score may be too optimistic.`;
  };

  return (
    <div className="p-6 sm:p-8 rounded-xl bg-[#1D1713] border border-[#382D25] panel-corner-glow">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 pb-6 border-b border-[#382D25]">
        {/* Left: Memorable Grade Element & Verdict */}
        <div className="flex items-start sm:items-center gap-6 sm:gap-8">
          <div className="flex flex-col items-center">
            <span
              className={`text-7xl sm:text-8xl font-headline font-normal tracking-tight leading-none animate-grade-settle select-none ${getGradeColor(
                rubric.grade
              )}`}
            >
              {rubric.grade}
            </span>
            <span className="text-xs text-[#A39382] font-sans mt-1">Grade</span>
          </div>

          <div className="max-w-xl">
            <div className="flex items-baseline gap-3 flex-wrap">
              <span className="text-2xl sm:text-3xl font-headline font-medium text-[#F2E9DF]">
                {rubric.score} <span className="text-base text-[#A39382] font-normal">/ 100</span>
              </span>
              {isSampleRepo && (
                <span className="text-xs text-[#A39382] border border-[#382D25] px-2 py-0.5 rounded-md font-sans">
                  Demo app
                </span>
              )}
            </div>

            <p className="text-base sm:text-lg font-headline font-normal text-[#F2E9DF] mt-1.5 leading-snug">
              {rubric.verdict}
            </p>

            <p className="text-xs text-[#A39382] font-sans mt-1">
              Scanned {filesScanned} of {totalScannable} scannable files
            </p>

            {/* Calm single-line partial scan notice under the grade in sentence case */}
            {coverage?.isPartial && (
              <p className="text-xs text-[#A39382] font-sans mt-1.5">
                {getPartialDescription()}
              </p>
            )}

            {coverage?.notes && coverage.notes.length > 0 && (
              <div className="mt-1.5 space-y-0.5">
                {coverage.notes.map((note, idx) => (
                  <p key={idx} className="text-xs text-[#A39382] font-sans">
                    {note}
                  </p>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right: Deductions Breakdown */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 w-full md:w-auto">
          <div className="p-2.5 rounded-lg bg-[#14100D] border border-[#382D25] text-left">
            <div className="flex items-center gap-1.5 text-xs text-[#E5484D] font-sans font-medium">
              <OctagonAlert className="w-3.5 h-3.5 shrink-0" />
              <span>Critical</span>
            </div>
            <p className="text-lg font-headline font-medium text-[#F2E9DF] mt-0.5">
              {rubric.counts.critical}
            </p>
            <p className="text-[11px] text-[#A39382] font-sans">-{rubric.deductions.critical} pts</p>
          </div>

          <div className="p-2.5 rounded-lg bg-[#14100D] border border-[#382D25] text-left">
            <div className="flex items-center gap-1.5 text-xs text-[#F2874B] font-sans font-medium">
              <TriangleAlert className="w-3.5 h-3.5 shrink-0" />
              <span>High</span>
            </div>
            <p className="text-lg font-headline font-medium text-[#F2E9DF] mt-0.5">
              {rubric.counts.high}
            </p>
            <p className="text-[11px] text-[#A39382] font-sans">-{rubric.deductions.high} pts</p>
          </div>

          <div className="p-2.5 rounded-lg bg-[#14100D] border border-[#382D25] text-left">
            <div className="flex items-center gap-1.5 text-xs text-[#D9B84A] font-sans font-medium">
              <CircleAlert className="w-3.5 h-3.5 shrink-0" />
              <span>Medium</span>
            </div>
            <p className="text-lg font-headline font-medium text-[#F2E9DF] mt-0.5">
              {rubric.counts.medium}
            </p>
            <p className="text-[11px] text-[#A39382] font-sans">-{rubric.deductions.medium} pts</p>
          </div>

          <div className="p-2.5 rounded-lg bg-[#14100D] border border-[#382D25] text-left">
            <div className="flex items-center gap-1.5 text-xs text-[#7FA6C9] font-sans font-medium">
              <Info className="w-3.5 h-3.5 shrink-0" />
              <span>Low</span>
            </div>
            <p className="text-lg font-headline font-medium text-[#F2E9DF] mt-0.5">
              {rubric.counts.low}
            </p>
            <p className="text-[11px] text-[#A39382] font-sans">-{rubric.deductions.low} pts</p>
          </div>
        </div>
      </div>

      {/* Tech Stack Chips (Sans font, sentence case, wrapping) */}
      <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 pt-4 text-xs font-sans text-[#A39382]">
        <span className="text-[#A39382] shrink-0">Detected stack:</span>
        {stack.languages.map((lang) => (
          <span
            key={lang}
            className="px-2 py-0.5 rounded-md bg-[#14100D] border border-[#382D25] text-[#F2E9DF] capitalize font-sans whitespace-nowrap"
          >
            {lang}
          </span>
        ))}
        {stack.frameworks.map((fw) => (
          <span
            key={fw}
            className="px-2 py-0.5 rounded-md bg-[#14100D] border border-[#382D25] text-[#F2E9DF] font-sans whitespace-nowrap"
          >
            {fw}
          </span>
        ))}
      </div>
    </div>
  );
};
