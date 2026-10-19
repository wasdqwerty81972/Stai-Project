import React from "react";
import ReactDOM from "react-dom/client";
import App from "./app/App";
import "./styles/app.css";

const rootEl = document.getElementById("root")!;
const root = ReactDOM.createRoot(rootEl);

function applyReducedMotion() {
  const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  document.documentElement.classList.toggle("reduced-motion", prefersReduced);
}

window.matchMedia("(prefers-reduced-motion: reduce)").addEventListener("change", applyReducedMotion);
applyReducedMotion();

root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/src/sw/service-worker.ts").catch(() => {});
  });
}
