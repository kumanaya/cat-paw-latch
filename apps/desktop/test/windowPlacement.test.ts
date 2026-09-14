/**
 * The small-screen case these helpers exist for: the 1366x768 laptop panel
 * (742px of work area under a top bar) that a 660x840 wizard does not fit on.
 */
import { describe, expect, it } from "vitest";
import { centeredFrame, fitFrame } from "../src/windowPlacement.js";

const smallPanel = { x: 0, y: 26, width: 1366, height: 742 };

describe("fitFrame", () => {
  it("leaves a frame that already fits where it is", () => {
    const frame = { x: 100, y: 40, width: 660, height: 700 };
    expect(fitFrame(frame, smallPanel)).toEqual(frame);
  });

  it("shrinks a frame taller and wider than the work area", () => {
    expect(fitFrame({ x: 0, y: 0, width: 2000, height: 900 }, smallPanel)).toEqual({
      x: 0,
      y: 26,
      width: 1366,
      height: 742,
    });
  });

  it("pulls a frame sitting above and left of the work area fully inside", () => {
    // The exact shape observed in the wild: Hyprland centered the 660x870
    // wizard on a 768px panel and placed it at y = -38.
    expect(fitFrame({ x: 353, y: -38, width: 660, height: 870 }, smallPanel)).toEqual({
      x: 353,
      y: 26,
      width: 660,
      height: 742,
    });
  });

  it("pulls a frame hanging off the bottom-right corner fully inside", () => {
    expect(fitFrame({ x: 1200, y: 700, width: 400, height: 300 }, smallPanel)).toEqual({
      x: 966,
      y: 468,
      width: 400,
      height: 300,
    });
  });

  it("never returns a zero-sized frame", () => {
    expect(fitFrame({ x: 0, y: 0, width: 0, height: 0 }, smallPanel)).toEqual({
      x: 0,
      y: 26,
      width: 1,
      height: 1,
    });
  });
});

describe("centeredFrame", () => {
  it("centers the requested frame on the work area", () => {
    expect(centeredFrame(660, 840, smallPanel)).toEqual({
      x: 353,
      y: 26,
      width: 660,
      height: 742,
    });
  });

  it("centers a frame that fits without resizing it", () => {
    expect(centeredFrame(940, 620, smallPanel)).toEqual({
      x: 213,
      y: 87,
      width: 940,
      height: 620,
    });
  });

  it("never leaves the work area when asked for a huge frame", () => {
    const frame = centeredFrame(4000, 4000, smallPanel);
    expect(frame).toEqual({ x: 0, y: 26, width: 1366, height: 742 });
  });
});
