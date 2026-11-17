"use strict";
const $ = (id) => document.getElementById(id);
let token =
  location.hash.slice(1) || sessionStorage.getItem("locklane-token") || "";
if (token) {
  sessionStorage.setItem("locklane-token", token);
  history.replaceState(null, "", location.pathname + location.search);
}
let state = null,
  hydrated = false,
  wireguard = "",
  polling = false,
  requestBusy = false,
  dirty = false,
  lastError = "",
  pendingSave = false;
const provider = () => document.querySelector("[name=provider]:checked").value;
const dialog = $("settings-dialog");
function notice(s, error = false) {
  for (const id of ["notice", "main-notice"]) {
    $(id).hidden = !s;
    $(id).textContent = s;
    $(id).classList.toggle("error", error);
  }
}
async function api(path, data) {
  const r = await fetch("/api/" + path, {
    method: data === undefined ? "GET" : "POST",
    headers: { "Content-Type": "application/json", "X-Locklane-Token": token },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
  let b;
  try {
    b = await r.json();
  } catch {
    throw Error("Панель недоступна. Открой Locklane заново.");
  }
  if (!r.ok) throw Error(b.error || "Операция не выполнена");
  return b;
}
function tab(name) {
  if (!["connection", "workspace", "activity"].includes(name))
    name = "connection";
  document.querySelectorAll("[data-tab]").forEach((x) => {
    const active = x.dataset.tab === name;
    x.setAttribute("aria-selected", String(active));
    x.tabIndex = active ? 0 : -1;
  });
  for (const n of ["connection", "workspace", "activity"])
    $("panel-" + n).hidden = n !== name;
  const u = new URL(location.href);
  u.searchParams.set("settings", name);
  history.replaceState(null, "", u);
}
function openSettings(name = "connection") {
  tab(name);
  if (!dialog.open) dialog.showModal();
}
function closeSettings() {
  dialog.close();
  const u = new URL(location.href);
  u.searchParams.delete("settings");
  history.replaceState(null, "", u);
}
$("open-settings").addEventListener("click", () => openSettings());
$("close-settings").addEventListener("click", closeSettings);
dialog.addEventListener("cancel", (e) => {
  e.preventDefault();
  closeSettings();
});
dialog.addEventListener("click", (e) => {
  if (e.target === dialog) {
    const r = dialog.getBoundingClientRect();
    if (
      e.clientX < r.left ||
      e.clientX > r.right ||
      e.clientY < r.top ||
      e.clientY > r.bottom
    )
      closeSettings();
  }
});
document.querySelectorAll("[data-tab]").forEach((x) => {
  x.addEventListener("click", () => tab(x.dataset.tab));
  x.addEventListener("keydown", (e) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
    e.preventDefault();
    const all = [...document.querySelectorAll("[data-tab]")];
    let n = all.indexOf(x) + (e.key === "ArrowRight" ? 1 : -1);
    if (e.key === "Home") n = 0;
    if (e.key === "End") n = all.length - 1;
    const next = all[(n + all.length) % all.length];
    tab(next.dataset.tab);
    next.focus();
  });
});
function toggle() {
  const p = provider();
  $("tailscale-fields").hidden = p !== "tailscale";
  $("wireguard-fields").hidden = p !== "wireguard";
  $("proxy-fields").hidden = p !== "proxy";
}
document
  .querySelectorAll("[name=provider]")
  .forEach((x) => x.addEventListener("change", toggle));
$("settings").addEventListener("input", () => (dirty = true));
$("import").addEventListener("click", async () => {
  try {
    $("import").disabled = true;
    $("import").textContent = "Читаем…";
    const data = await api("import", {
      source: $("subscription").value.trim(),
    });
    $("subscription").value = "";
    $("server").replaceChildren(
      ...data.nodes.map((n) => new Option(n.name + " / " + n.protocol, n.id)),
    );
    $("import-info").textContent =
      "Серверов: " +
      data.nodes.length +
      ". Выбери один." +
      (data.skipped?.length
        ? " Часть профилей пропущена: " + data.skipped[0]
        : "");
    dirty = true;
    notice("Подключение импортировано. Выбери сервер и сохрани.");
  } catch (e) {
    notice(e.message, true);
  } finally {
    $("import").disabled = false;
    $("import").textContent = "Импорт";
  }
});
$("wg-file").addEventListener("change", async () => {
  const f = $("wg-file").files[0];
  if (!f) return;
  if (f.size > 32768) {
    notice("Профиль слишком большой.", true);
    return;
  }
  wireguard = await f.text();
  $("wg-hint").textContent = "Профиль выбран. Ключ хранится только локально.";
  dirty = true;
});
$("pick-folder").addEventListener("click", async () => {
  try {
    $("pick-folder").disabled = true;
    const v = await api("folder", {});
    if (v.path) {
      $("project").value = v.path;
      dirty = true;
    }
  } catch (e) {
    notice(e.message, true);
  } finally {
    $("pick-folder").disabled = false;
  }
});
$("settings").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!$("project").value.trim()) {
    tab("workspace");
    $("project").focus();
    notice("Выбери папку проекта.", true);
    return;
  }
  try {
    $("save").disabled = true;
    await api("config", {
      provider: provider(),
      expected_ip: $("expected-ip").value.trim(),
      exit_node: $("exit-node").value.trim(),
      project: $("project").value.trim(),
      wireguard,
      profile_id: $("server").value,
    });
    wireguard = "";
    $("wg-file").value = "";
    dirty = false;
    hydrated = false;
    pendingSave = true;
    notice("Сохраняем настройки…");
    await poll();
  } catch (e) {
    notice(e.message, true);
  } finally {
    render();
  }
});
async function action(path, message) {
  try {
    requestBusy = true;
    render();
    await api(path, {});
    notice(message);
    await poll();
  } catch (e) {
    notice(e.message, true);
  } finally {
    requestBusy = false;
    render();
  }
}
$("power").addEventListener("click", () => {
  if (!state?.config?.project) {
    openSettings();
    return;
  }
  const t = state.tunnel || {};
  if (
    state.busy ||
    t.ready ||
    (t.checked_at && Date.now() / 1000 - t.checked_at < 12)
  ) {
    action("stop", "Среда остановлена.");
  } else {
    action(
      "start",
      "Подключаем среду. Первая сборка может занять несколько минут.",
    );
  }
});
$("launch").addEventListener("click", () =>
  action("launch", "Открываем защищённый терминал."),
);
$("pin").addEventListener("click", () =>
  action("pin", "Закрепляем этот IP и проверяем подключение."),
);
$("verify-ip").addEventListener("click", async () => {
  if (!state?.tunnel?.checked_at) {
    notice("Сначала включи среду.");
    return;
  }
  await action("ip", "IP проверен через выбранное подключение.");
});
$("check").addEventListener("click", () =>
  action("check", "Проводим самопроверку. Результат появится здесь."),
);
$("quit").addEventListener("click", async () => {
  try {
    $("quit").disabled = true;
    await api("quit", {});
    clearInterval(pollTimer);
    notice("Среда остановлена. Locklane закрыт.");
    closeSettings();
    $("power").disabled = true;
  } catch (e) {
    notice(e.message, true);
    $("quit").disabled = false;
  }
});
const reasons = {
  "Starting isolated gateway": "Запускаем защищённую среду",
  "Sign in to Tailscale": "Нужен вход в Tailscale",
  "Exit node unavailable or not permitted":
    "Сервер недоступен или нет разрешения",
  "Exit node is offline": "Сервер не в сети",
  "Cannot verify tunnel exit IP": "Не удаётся подтвердить IP",
  "Exit IP does not match the pinned address": "IP изменился. Доступ закрыт",
  "Tunnel and exit IP verified": "Туннель и IP подтверждены",
  "Pin this observed exit IP": "Закрепи найденный IP",
  "Gateway stopped": "Среда остановлена",
};
function render() {
  if (!state) return;
  const c = state.config || {},
    t = state.tunnel || {};
  const age = Date.now() / 1000 - t.checked_at;
  const ready = !!t.ready && age >= 0 && age < 8,
    busy = state.busy || requestBusy;
  const configured = !!c.project;
  const running = !!t.checked_at && Date.now() / 1000 - t.checked_at < 12;
  $("power-area").classList.toggle("ready", ready);
  $("power-area").classList.toggle("busy", !!state.busy);
  $("power").disabled = requestBusy;
  $("power").setAttribute("aria-pressed", String(ready));
  $("power").setAttribute(
    "aria-label",
    ready || state.busy || running ? "Выключить среду" : "Включить защиту",
  );
  $("power-label").textContent = state.busy
    ? "Остановить"
    : ready || running
      ? "Выключить"
      : "Включить";
  $("status").textContent = state.busy
    ? "Подготавливаем среду"
    : ready
      ? "Защита включена"
      : running
        ? reasons[t.reason] || "Подключение не готово"
        : "Среда выключена";
  document.querySelector(".connection-status").classList.toggle("ready", ready);
  $("actual-ip").textContent = t.ip || "Не определён";
  $("verify-ip").disabled = busy;
  $("launch").hidden = !ready;
  $("launch").disabled = !ready || busy;
  const canPin =
    !c.expected_ip && t.reason === "Pin this observed exit IP" && !!t.ip;
  $("pin").hidden = !canPin;
  $("pin").disabled = busy;
  $("verify-ip").hidden = canPin;
  $("main-hint").textContent = !configured
    ? "Добавь подключение в настройках"
    : state.busy
      ? "Сборка и подключение доступны в журнале"
      : ready
        ? c.profile_name || "Постоянный выходной IP"
        : "Все параметры подключения в настройках";
  $("check").disabled = !ready || busy;
  $("save").disabled = busy;
  $("saved").textContent = configured
    ? "Сохранение остановит текущую среду"
    : "Настройка с нуля";
  $("version").textContent = "Locklane " + state.version;
  $("pinned-summary").textContent =
    c.expected_ip || "Определим при подключении";
  $("logs").textContent = state.logs?.length
    ? state.logs.join("\n\n")
    : "Здесь появятся результаты подключения и проверок.";
  $("login").hidden = !t.login_url;
  if (t.login_url) $("login").href = t.login_url;
  if (!hydrated && !state.busy && !dirty) {
    $("expected-ip").value = c.expected_ip || "";
    $("exit-node").value = c.exit_node || "";
    $("project").value = c.project || "";
    if (c.provider)
      $(
        c.provider === "tailscale"
          ? "ts"
          : c.provider === "proxy"
            ? "proxy"
            : "wg",
      ).checked = true;
    if (
      c.provider === "proxy" &&
      c.profile_name &&
      $("server").options.length <= 1
    )
      $("server").replaceChildren(
        new Option(c.profile_name + " / " + c.protocol, ""),
      );
    toggle();
    hydrated = true;
  }
  if (state.error && state.error !== lastError) {
    notice(state.error, true);
    lastError = state.error;
  }
  if (!state.error) lastError = "";
  if (pendingSave && !state.busy) {
    pendingSave = false;
    if (!state.error) {
      closeSettings();
      notice("Настройки сохранены. Можно включить защиту.");
    }
  }
}
async function poll() {
  if (polling) return;
  polling = true;
  try {
    state = await api("state");
    render();
  } catch (e) {
    state = null;
    $("status").textContent = "Статус неизвестен";
    $("main-hint").textContent = "Проверка недоступна. Запуск запрещён.";
    $("power-area").classList.remove("ready");
    $("launch").hidden = true;
    $("pin").hidden = true;
    notice(e.message, true);
  } finally {
    polling = false;
  }
}
poll();
const pollTimer = setInterval(poll, 2500);
const initialTab = new URL(location.href).searchParams.get("settings");
if (initialTab) openSettings(initialTab);

document.addEventListener("visibilitychange", () => {
  if (!document.hidden) poll();
});
