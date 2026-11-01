/// <reference types="vite/client" />

declare module "*.template.html?dc" {
  import type { ReactNode } from "react";
  /** The compiled template (scripts/dc/compile.mjs). */
  const render: (vals: Record<string, any>) => ReactNode[];
  export const bindings: string[];
  export default render;
}

declare module "virtual:dc-pseudo.css";
