const screen = document.querySelector("#screen");
const runtime = document.querySelector("#runtime-status");
const routes = new Set(["home", "onboarding", "call"]);
let name = localStorage.getItem("slouching.preview.name") || "";
let familiar = localStorage.getItem("slouching.preview.familiar") || "ava-gnome1.jpg";
let demoMuted = true;
let demoCamera = false;

const avatarChoices = [
  ["ava-gnome1.jpg", "Mago"],
  ["ava-frog1.jpg", "Sapo mago"],
  ["ava-orb.jpg", "Orbe"],
  ["ava-pipe.jpg", "Cachimbo"],
];
if (!avatarChoices.some(([file]) => file === familiar)) familiar = "ava-gnome1.jpg";

function home() {
  screen.className = "home-screen";
  screen.innerHTML = `
    <section class="home-hero" aria-labelledby="hero-title">
      <div class="hero-shade"></div>
      <div class="hero-copy">
        <p class="eyebrow">UMA FOGUEIRA PARA A SUA CREW</p>
        <h1 id="hero-title">slouching</h1>
        <p class="hero-subtitle">P2P voice &amp; video<br />for you and your crew</p>
        <div class="hero-actions">
          <button class="button button-primary" id="join-button">♫ &nbsp; Join a call</button>
          <button class="button button-secondary" id="create-button">♟ &nbsp; Create a call</button>
        </div>
        <form class="invite-form" id="invite-form">
          <label for="invite-input">Have an invite link?</label>
          <input id="invite-input" type="text" placeholder="slouch://" autocomplete="off" spellcheck="false" />
          <button type="submit" aria-label="Abrir convite">→</button>
        </form>
        <p class="action-message" id="home-message" role="status"></p>
      </div>
      <div class="home-feature-strip">
        <div><span class="feature-icon">↯</span><strong>P2P</strong><small>Conexão entre amigos</small></div>
        <div><span class="feature-icon">♙</span><strong>Private</strong><small>Chaves em cada dispositivo</small></div>
        <div><span class="feature-icon">♟</span><strong>For your crew</strong><small>Voice, video, screen</small></div>
        <div><span class="feature-icon">✦</span><strong>Just vibes</strong><small>Always</small></div>
      </div>
    </section>`;
  const input = document.querySelector("#invite-input");
  const message = document.querySelector("#home-message");
  document.querySelector("#join-button").addEventListener("click", () => input.focus());
  document.querySelector("#create-button").addEventListener("click", () => {
    message.textContent = "Criação de chamada ainda não implementada. Veja a prévia visual em “Chamada”.";
  });
  document.querySelector("#invite-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const value = input.value.trim();
    message.textContent = value
      ? "Convites ainda não são processados: nenhum link foi enviado ou aberto."
      : "Cole um convite quando o protocolo estiver disponível.";
  });
}

function onboarding() {
  screen.className = "onboarding-screen";
  const options = avatarChoices.map(([file, label]) => `
    <button class="familiar-option ${familiar === file ? "selected" : ""}" type="button" data-familiar="${file}" aria-pressed="${familiar === file}">
      <img src="/avatars/${file}" alt="" /><span>${label}</span>
    </button>`).join("");
  screen.innerHTML = `
    <section class="onboarding-card">
      <div class="card-illustration" role="img" aria-label="Dois magos caminhando juntos à noite"></div>
      <div class="card-content">
        <p class="eyebrow">PRIMEIROS PASSOS · PRÉVIA</p>
        <h1>Quem senta na fogueira?</h1>
        <p>Escolha um nome e um familiar para experimentar a interface. Isto ainda não cria uma identidade criptográfica.</p>
        <label class="field-label" for="display-name">SEU NOME</label>
        <input id="display-name" maxlength="32" placeholder="Como seus amigos vão te chamar?" />
        <div class="field-label">SEU FAMILIAR</div>
        <div class="familiar-grid">${options}</div>
        <button class="button button-primary" id="save-preview">Guardar prévia local</button>
        <p class="small-note" id="onboarding-message" role="status">A geração da chave Ed25519, o armazenamento seguro e a verificação de identidade ainda estão pendentes.</p>
      </div>
    </section>`;
  document.querySelector("#display-name").value = name;
  document.querySelectorAll("[data-familiar]").forEach((button) => {
    button.addEventListener("click", () => {
      familiar = button.dataset.familiar;
      document.querySelectorAll("[data-familiar]").forEach((item) => {
        const selected = item === button;
        item.classList.toggle("selected", selected);
        item.setAttribute("aria-pressed", String(selected));
      });
    });
  });
  document.querySelector("#save-preview").addEventListener("click", () => {
    name = document.querySelector("#display-name").value.trim();
    if (!name) {
      document.querySelector("#onboarding-message").textContent = "Informe um nome para guardar a prévia.";
      return;
    }
    localStorage.setItem("slouching.preview.name", name);
    localStorage.setItem("slouching.preview.familiar", familiar);
    document.querySelector("#onboarding-message").textContent = "Prévia local guardada. Nenhuma chave ou conta foi criada.";
  });
}

function call() {
  screen.className = "call-screen";
  const displayName = name || "Você";
  screen.innerHTML = `
    <section class="call-layout" aria-label="Prévia visual de chamada">
      <div class="call-main">
        <div class="call-heading"><div><span class="eyebrow">THE MOSSY STUMP</span><h1>À beira da fogueira</h1></div><span class="route-label">SEM CONEXÃO · PRÉVIA</span></div>
        <div class="stage">
          <img src="/art/scene-orb.jpg" alt="Cena de fantasia com um orbe luminoso; imagem de demonstração" />
          <span class="tile-label">Arte de referência · sem vídeo ao vivo</span>
        </div>
        <div class="filmstrip">
          <div class="tile"><img src="/art/scene-frog1.jpg" alt="Cena ilustrativa de sapo mago" /><span class="tile-label">Sapo · exemplo</span></div>
          <div class="tile"><img src="/art/scene-gnome1.jpg" alt="Cena ilustrativa de gnomo" /><span class="tile-label">Gnomo · exemplo</span></div>
          <div class="tile tile-self"><img src="/avatars/${familiar}" alt="" /><span class="tile-label">${escapeHtml(displayName)} · câmera desligada</span></div>
        </div>
        <div class="call-controls">
          <button type="button" id="mute-control" aria-pressed="${demoMuted}" aria-label="Alternar microfone de demonstração">${demoMuted ? "◉" : "◎"} <span>${demoMuted ? "Mudo" : "Microfone"}</span></button>
          <button type="button" id="camera-control" aria-pressed="${demoCamera}" aria-label="Alternar câmera de demonstração">▣ <span>${demoCamera ? "Câmera (prévia)" : "Câmera off"}</span></button>
          <button type="button" id="share-control">▤ <span>Compartilhar</span></button>
          <button type="button" class="leave-control" id="leave-control">Sair da prévia</button>
        </div>
        <p class="call-message" id="call-message" role="status">Controles demonstram o layout; nenhum microfone, câmera ou rede está ativo.</p>
      </div>
      <aside class="call-sidebar">
        <section class="panel"><h2>IN THE ROOM · EXEMPLO</h2><div class="roster-row"><span>Odo</span><small>imagem de referência</small></div><div class="roster-row"><span>Mara</span><small>imagem de referência</small></div><div class="roster-row"><span>${escapeHtml(displayName)}</span><small>prévia local</small></div></section>
        <section class="panel chat-panel"><h2>CAMPFIRE CHAT</h2><div class="chat-placeholder"><span class="campfire">✦</span><p>As conversas aparecerão aqui quando o core de mensagens estiver pronto.</p></div><form id="chat-form"><input aria-label="Mensagem de demonstração" placeholder="say something..." /><button type="submit" aria-label="Enviar mensagem">→</button></form></section>
      </aside>
    </section>`;
  const note = document.querySelector("#call-message");
  document.querySelector("#mute-control").addEventListener("click", (event) => {
    demoMuted = !demoMuted;
    event.currentTarget.setAttribute("aria-pressed", String(demoMuted));
    event.currentTarget.querySelector("span").textContent = demoMuted ? "Mudo" : "Microfone (prévia)";
    note.textContent = "Estado visual alterado. Nenhum microfone foi aberto.";
  });
  document.querySelector("#camera-control").addEventListener("click", (event) => {
    demoCamera = !demoCamera;
    event.currentTarget.setAttribute("aria-pressed", String(demoCamera));
    event.currentTarget.querySelector("span").textContent = demoCamera ? "Câmera (prévia)" : "Câmera off";
    note.textContent = "Estado visual alterado. Nenhuma câmera foi aberta.";
  });
  document.querySelector("#share-control").addEventListener("click", () => note.textContent = "Compartilhamento ainda não implementado.");
  document.querySelector("#leave-control").addEventListener("click", () => location.hash = "#home");
  document.querySelector("#chat-form").addEventListener("submit", (event) => {
    event.preventDefault();
    note.textContent = "Mensagens ainda não são enviadas.";
  });
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

function render() {
  const route = location.hash.slice(1) || "home";
  if (!routes.has(route)) {
    location.hash = "#home";
    return;
  }
  document.querySelectorAll("[data-route]").forEach((link) => {
    link.setAttribute("aria-current", link.dataset.route === route ? "page" : "false");
  });
  ({ home, onboarding, call })[route]();
}

async function loadStatus() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const state = await response.json();
    runtime.textContent = state.mode === "local_scaffold"
      ? "Core local ativo · identidade, mensagens e chamadas pendentes"
      : "Estado do core desconhecido";
  } catch {
    runtime.textContent = "Core local indisponível · prévia visual";
  }
}

addEventListener("hashchange", render);
render();
loadStatus();
