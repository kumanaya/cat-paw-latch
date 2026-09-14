/**
 * Window geometry helpers — pure, Electron-free, so the suite can test them
 * without a display.
 *
 * Every window opens at a frame sized for a roomy display (the setup wizard is
 * 660x840). On a small panel that frame is taller than the work area, which
 * used to leave its bottom edge — where the wizard's Continue button lives —
 * off-screen and unreachable. Frames are clamped to the display they land on
 * before they are handed to Electron.
 */

export interface Frame {
  x: number;
  y: number;
  width: number;
  height: number;
}

/** Shrink a frame to fit the work area, then pull it fully back inside. */
export function fitFrame(frame: Frame, workArea: Frame): Frame {
  const width = Math.max(1, Math.min(frame.width, workArea.width));
  const height = Math.max(1, Math.min(frame.height, workArea.height));
  const x = Math.min(Math.max(frame.x, workArea.x), workArea.x + workArea.width - width);
  const y = Math.min(Math.max(frame.y, workArea.y), workArea.y + workArea.height - height);
  return { x, y, width, height };
}

/** Fit a requested size to the work area and center it there. */
export function centeredFrame(width: number, height: number, workArea: Frame): Frame {
  const fitted = fitFrame({ x: workArea.x, y: workArea.y, width, height }, workArea);
  return {
    ...fitted,
    x: workArea.x + Math.round((workArea.width - fitted.width) / 2),
    y: workArea.y + Math.round((workArea.height - fitted.height) / 2),
  };
}
