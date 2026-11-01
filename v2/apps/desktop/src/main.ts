import "./design/assets/keep.css";
import "./design/assets/keep-components.css";
import "./design/app.css";
// The :hover rules compiled from style-hover attributes (build-time, so no runtime <style> element is needed).
import "virtual:dc-pseudo.css";

import { createElement } from "react";
import { createRoot } from "react-dom/client";

import { DCBoundary, DCHost, describeError } from "./dc/runtime";
import render from "./design/app.template.html?dc";
import Component from "./design/logic/core.js";

const container = document.getElementById("dc-root");
if (!container) throw new Error("index.html has no #dc-root");

// React's default reporter prints the error object and a component stack; both can name vault objects.  Log the message only.
const root = createRoot(container, {
  onCaughtError: (error) => console.error("CredMgr render error:", describeError(error)),
  onUncaughtError: (error) => console.error("CredMgr uncaught error:", describeError(error)),
});

// `mode` is the only editor knob the app reads from props.  The other knobs (theme, colourOn, hue, ...) are NOT
// passed: their defaults would override the logic's own detection of the operating system's colour scheme.
// The boundary sits ABOVE the host: a boundary only catches what its children throw, so the host's own render() and the
// logic's lifecycle methods are covered only by something that wraps the host.
root.render(
  createElement(
    DCBoundary,
    { name: "CredMgr App" },
    createElement(DCHost, { Logic: Component, render, props: { mode: "pro" }, name: "CredMgr App" }),
  ),
);
