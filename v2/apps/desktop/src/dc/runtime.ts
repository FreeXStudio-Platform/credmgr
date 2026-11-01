/**
 * The tiny runtime the precompiled design needs.  Clean-room: it implements the documented contract of the
 * design's logic class (state, setState, lifecycle, renderVals), not the upstream loader.
 *
 * What is deliberately NOT here: any parsing, any eval, any network access, the editor bridge, streaming
 * placeholders, hot-swap, helmet management.  The template is compiled to React.createElement calls at build
 * time (scripts/dc/compile.mjs); this file only provides the helpers those calls use plus the host component
 * that connects a `DCLogic` subclass to React.
 *
 * Documented deviation from the upstream runtime (ADR-075): `componentDidUpdate` receives the logic's PREVIOUS
 * STATE as its second argument.  The upstream host passes only the previous props, so the design's
 * "a dialog just opened" check (`prevState.dialog`) always saw `undefined` and re-ran its focus-first-field
 * routine on every re-render while a dialog was open.
 */
import { Component, Fragment, createElement, isValidElement } from "react";
import type { ReactNode } from "react";

// ───────────────────────────── helpers used by generated code ─────────────────────────────

export const h = createElement;

/** A keyed Fragment around an array of children (sc-if / sc-for / interpolated text). */
export function F(key: number | string, children: ReactNode): ReactNode {
  return createElement(Fragment, { key }, children);
}

/** `<sc-for list>` accepts only an array; anything else renders nothing. */
export function L(list: unknown): unknown[] {
  return Array.isArray(list) ? list : [];
}

/** One `{{ x }}` hole inside text.  Elements and arrays pass through; null/boolean/undefined render nothing. */
export function interp(value: unknown, key: number): ReactNode {
  if (value === undefined || value === null || typeof value === "boolean") return null;
  if (isValidElement(value) || Array.isArray(value)) return createElement(Fragment, { key }, value as ReactNode);
  return createElement("span", { key, className: "sc-interp" }, String(value));
}

const kebabToCamel = (s: string): string => s.replace(/-([a-z])/g, (_, c: string) => c.toUpperCase());
const cssCache = new Map<string, Record<string, string>>();

/** A `style` attribute given as a string becomes a style object (set through the CSSOM, which a strict CSP allows). */
export function css(value: unknown): unknown {
  if (typeof value !== "string") return value;
  let obj = cssCache.get(value);
  if (!obj) {
    obj = {};
    for (const decl of value.split(";")) {
      const i = decl.indexOf(":");
      if (i < 0) continue;
      const prop = decl.slice(0, i).trim();
      obj[prop.startsWith("--") ? prop : kebabToCamel(prop)] = decl.slice(i + 1).trim();
    }
    if (cssCache.size > 500) cssCache.clear();
    cssCache.set(value, obj);
  }
  return obj;
}

/** className join that skips empty parts. */
export function cx(...parts: unknown[]): string {
  return parts.filter(Boolean).join(" ");
}

// ───────────────────────────── the logic base class ─────────────────────────────

export type LogicState = Record<string, any>;
type StateUpdate = LogicState | ((prev: LogicState) => LogicState | null | undefined) | null | undefined;

/**
 * Base class for the design's logic.  `state` is a plain object that `setState` replaces SYNCHRONOUSLY (the logic
 * reads `this.state` right after calling `setState`), then asks the host to re-render.
 */
export class DCLogic {
  props: Record<string, any>;
  state: LogicState = {};
  /** Installed by DCHost right after construction. */
  __host: DCHost | null = null;

  constructor(props?: Record<string, any>) {
    this.props = props || {};
  }

  setState(update: StateUpdate, cb?: () => void): void {
    this.__host?.setLogicState(update, cb);
  }

  forceUpdate(): void {
    this.__host?.forceUpdate();
  }

  componentDidMount(): void {}
  componentDidUpdate(_prevProps?: Record<string, any>, _prevState?: LogicState): void {}
  componentWillUnmount(): void {}

  /** The flat object the compiled template renders against (merged over the props). */
  renderVals(): Record<string, unknown> {
    return {};
  }
}

// ───────────────────────────── the host component ─────────────────────────────

type LogicClass = new (props: Record<string, any>) => DCLogic;

export interface DCHostProps {
  Logic: LogicClass;
  /** The compiled template. */
  render: (vals: Record<string, any>) => ReactNode[];
  /** Props the design's logic sees as `this.props` (the editor knobs; only `mode` is used in the app). */
  props?: Record<string, any>;
  /** Written on the host element as `data-sc-name`. */
  name?: string;
}

interface DCHostState {
  tick: number;
}

/**
 * Connects a `DCLogic` subclass to React.  It does NOT catch render errors itself: a React error boundary only catches
 * what its CHILDREN throw, never what its own render() throws, so a boundary inside this class would be dead code (it
 * was, in the first version of this file: a throwing renderVals() left an empty window).  The boundary is the separate
 * {@link DCBoundary} that wraps this component in main.ts, so it also catches errors from the logic's lifecycle methods.
 */
export class DCHost extends Component<DCHostProps, DCHostState> {
  logic: DCLogic;
  private committedState: LogicState;

  constructor(props: DCHostProps) {
    super(props);
    this.state = { tick: 0 };
    this.logic = new props.Logic(props.props || {});
    this.logic.__host = this;
    this.committedState = this.logic.state;
  }

  /** Synchronous merge into logic.state, then one React re-render. */
  setLogicState(update: StateUpdate, cb?: () => void): void {
    const prev = this.logic.state;
    const patch = typeof update === "function" ? update(prev) : update;
    this.logic.state = { ...prev, ...patch };
    this.setState((s) => ({ tick: s.tick + 1 }), cb);
  }

  componentDidMount(): void {
    this.logic.componentDidMount();
    this.committedState = this.logic.state;
  }

  componentDidUpdate(prevProps: DCHostProps): void {
    const before = this.committedState;
    this.committedState = this.logic.state;
    this.logic.props = this.props.props || {};
    this.logic.componentDidUpdate(prevProps.props || {}, before);
  }

  componentWillUnmount(): void {
    this.logic.componentWillUnmount();
  }

  render(): ReactNode {
    const name = this.props.name || "CredMgr";
    this.logic.props = this.props.props || {};
    const vals = { ...(this.props.props || {}), ...this.logic.renderVals() };
    return createElement("div", { className: "sc-host", "data-sc-name": name }, this.props.render(vals));
  }
}

/** What an error becomes in the log: its message only.  Never props, logic state or a component stack (they can hold vault names). */
export function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

interface DCBoundaryProps {
  children?: ReactNode;
  name?: string;
}

/**
 * The production error boundary.  If anything below it throws while rendering (or in a lifecycle method) the window
 * shows a plain KEEP panel instead of going blank.  It offers no retry: the state that threw is still there, so the
 * honest instruction is to restart the app.  Mount it ABOVE {@link DCHost}, never inside it.
 */
export class DCBoundary extends Component<DCBoundaryProps, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  // No componentDidCatch: main.ts creates the root with onCaughtError, which logs the message once.  A second log here would double it.

  render(): ReactNode {
    if (!this.state.failed) return this.props.children;
    return createElement(
      "div",
      { className: "sc-host", "data-sc-name": this.props.name || "CredMgr" },
      // No data-screen-label here on purpose: the headless gates treat "a screen label is on the page" as "the app rendered".
      createElement("div", { className: "k-empty", role: "alert", "data-error-boundary": "true" }, "Something went wrong. Restart CredMgr."),
    );
  }
}
