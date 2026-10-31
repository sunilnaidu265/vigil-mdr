// Small page helpers: keyboard shortcuts, copy buttons and the evidence checklist.
(function () {
  let selected = -1;

  function rows() {
    return Array.from(document.querySelectorAll(".queue-row"));
  }

  function select(index) {
    const all = rows();
    if (!all.length) return;
    selected = Math.max(0, Math.min(index, all.length - 1));
    all.forEach((row, i) => row.classList.toggle("selected", i === selected));
    all[selected].scrollIntoView({ block: "nearest" });
  }

  function typing(target) {
    return ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName) || target.isContentEditable;
  }

  document.addEventListener("keydown", (event) => {
    if (typing(event.target) || event.ctrlKey || event.metaKey || event.altKey) return;
    if (event.key === "j") select(selected + 1);
    else if (event.key === "k") select(selected - 1);
    else if (event.key === "Enter" && selected >= 0 && rows()[selected]) window.location = rows()[selected].dataset.href;
    else if (event.key === "a") document.getElementById("approve-button")?.click();
    else if (event.key === "r") document.getElementById("reason")?.focus();
  });

  document.body.addEventListener("htmx:afterSwap", () => {
    if (selected >= 0) select(selected);
  });

  document.addEventListener("click", async (event) => {
    const button = event.target.closest(".copy");
    if (!button) return;
    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      button.textContent = "Copied";
    } catch {
      button.textContent = "Copy failed";
    }
    setTimeout(() => { button.textContent = "Copy"; }, 1500);
  });

  // one shared chart tooltip; text comes from data attributes, never as HTML
  const tip = document.createElement("div");
  tip.className = "viz-tip";
  const tipValue = document.createElement("strong");
  const tipLabel = document.createElement("span");
  tip.append(tipValue, tipLabel);
  document.body.append(tip);

  function showTip(mark, x, y) {
    tipValue.textContent = mark.dataset.tipValue;
    tipLabel.textContent = mark.dataset.tipLabel;
    tip.style.display = "block";
    const left = Math.min(x + 14, window.innerWidth - tip.offsetWidth - 8);
    const top = y - tip.offsetHeight - 10;
    tip.style.left = Math.max(8, left) + "px";
    tip.style.top = (top < 8 ? y + 16 : top) + "px";
  }

  document.addEventListener("pointermove", (event) => {
    const mark = event.target.closest?.(".mark[data-tip-value]");
    if (mark) showTip(mark, event.clientX, event.clientY);
    else tip.style.display = "none";
  });
  document.addEventListener("focusin", (event) => {
    const mark = event.target.closest?.(".mark[data-tip-value]");
    if (!mark) { tip.style.display = "none"; return; }
    const box = mark.getBoundingClientRect();
    showTip(mark, box.left + box.width / 2, box.top);
  });
  document.addEventListener("focusout", () => { tip.style.display = "none"; });

  // ticks are a per-browser convenience, so failed storage is ignored
  document.querySelectorAll("[data-check]").forEach((box) => {
    const key = "vigil-check-" + box.dataset.check;
    try { box.checked = localStorage.getItem(key) === "1"; } catch { /* storage blocked */ }
    box.addEventListener("change", () => {
      try { localStorage.setItem(key, box.checked ? "1" : "0"); } catch { /* storage blocked */ }
    });
  });
})();
