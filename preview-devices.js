(() => {
"use strict";
// Simulazione locale: nessuna chiamata API, Worker o Shelly.
const states = { yard: false, stairs: false };
const labels = {
  yard: { on: "Accesi", off: "Spenti" },
  stairs: { on: "Acceso", off: "Spento" }
};
function render() {
  document.querySelectorAll("[data-device]").forEach(card => {
    const id = card.dataset.device;
    const state = card.querySelector(".device-state");
    const button = card.querySelector("button[data-action]");
    if (!state || !button) return;
    if (id === "gate") {
      if (!card.dataset.pulsing) state.textContent = "SIMULAZIONE · Pronto";
      button.textContent = "SIMULA APERTURA";
      return;
    }
    state.textContent = "SIMULAZIONE · " + labels[id][states[id] ? "on" : "off"];
    button.textContent = states[id] ? "SPEGNI" : "ACCENDI";
    button.setAttribute("aria-pressed", String(states[id]));
  });
}
document.addEventListener("click", event => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  const card = button.closest("[data-device]");
  if (!card) return;
  const id = card.dataset.device;
  if (id === "gate") {
    if (card.dataset.pulsing === "1") return;
    card.dataset.pulsing = "1";
    card.querySelector(".device-state").textContent = "SIMULAZIONE · Impulso di apertura";
    button.disabled = true;
    button.textContent = "IN CORSO…";
    window.setTimeout(() => {
      delete card.dataset.pulsing;
      button.disabled = false;
      render();
    }, 1800);
    return;
  }
  if (id in states) {
    states[id] = !states[id];
    render();
  }
});
render();
})();