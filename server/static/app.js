let selectedClientId = null;
let authToken = localStorage.getItem('authToken') || '';
let notificationHistory = [];
let audioEnabled = localStorage.getItem('audioEnabled') === 'true';
let clientResources = {}; // Store latest resource data for each client
let blockedUrls = [];

const el = (id) => document.getElementById(id);

function onClick(id, fn) {
  const node = el(id);
  if (!node) return;
  node.onclick = fn;
}

function setConnStatus(text, ok) {
  const s = el('connStatus');
  s.textContent = text;
  s.style.background = ok ? '#144c2d' : '#4b1c1c';
}

function adminHeaders() {
  const h = { 'Content-Type': 'application/json' };
  if (authToken) h['Authorization'] = `Bearer ${authToken}`;
  return h;
}

// Toast notification system
function showToast(message, type = 'info') {
  const container = el('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  // Play sound if enabled
  if (audioEnabled && (type === 'success' || type === 'warning' || type === 'error')) {
    playNotificationSound(type);
  }

  // Auto-remove after 5 seconds
  setTimeout(() => {
    toast.classList.add('fade-out');
    setTimeout(() => toast.remove(), 300);
  }, 5000);
}

function playNotificationSound(type) {
  const audioContext = new (window.AudioContext || window.webkitAudioContext)();
  const oscillator = audioContext.createOscillator();
  const gainNode = audioContext.createGain();

  oscillator.connect(gainNode);
  gainNode.connect(audioContext.destination);

  oscillator.frequency.value = type === 'error' ? 200 : type === 'warning' ? 400 : 600;
  gainNode.gain.value = 0.1;

  oscillator.start();
  oscillator.stop(audioContext.currentTime + 0.1);
}

function addNotification(message, type = 'info') {
  const notification = {
    message,
    type,
    timestamp: new Date().toISOString()
  };
  notificationHistory.unshift(notification);
  if (notificationHistory.length > 50) notificationHistory.pop();
  updateNotificationHistory();
  showToast(message, type);
}

function updateNotificationHistory() {
  const container = el('notificationHistory');
  if (!container) return;

  container.innerHTML = '';
  for (const notif of notificationHistory.slice(0, 20)) {
    const div = document.createElement('div');
    div.className = `notification notification-${notif.type}`;
    const time = new Date(notif.timestamp).toLocaleTimeString();
    div.innerHTML = `<span class="time">${time}</span> ${notif.message}`;
    container.appendChild(div);
  }
}

async function login() {
  const u = (el('adminUser')?.value || '').trim();
  const p = (el('adminPass')?.value || '');
  if (!u || !p) throw new Error('Enter username and password');
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: u, password: p }),
  });
  if (!res.ok) throw new Error('Login failed');
  const data = await res.json();
  authToken = data.token;
  localStorage.setItem('authToken', authToken);
  await loadClients();
  await loadBlockedUrls();
  showToast('Logged in successfully', 'success');
}

function fmtAgo(iso) {
  if (!iso) return 'never';
  const t = Date.parse(iso);
  const diff = Math.max(0, Date.now() - t);
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  return `${hr}h ago`;
}

function isOnline(lastSeenIso) {
  if (!lastSeenIso) return false;
  const t = Date.parse(lastSeenIso);
  return (Date.now() - t) < 15000;
}

async function loadClients() {
  const res = await fetch('/api/admin/clients', { headers: adminHeaders() });
  if (res.status === 401) throw new Error('Please login');
  if (!res.ok) throw new Error('Server error');
  const data = await res.json();
  const wrap = el('clients');
  wrap.innerHTML = '';
  for (const c of data.clients) {
    const div = document.createElement('div');
    div.className = 'client' + (selectedClientId === c.id ? ' selected' : '');
    div.onclick = () => {
      selectedClientId = c.id;
      for (const n of wrap.querySelectorAll('.client')) n.classList.remove('selected');
      div.classList.add('selected');
      updateActionButtons();
    };

    const online = isOnline(c.last_seen);
    const status = document.createElement('div');
    status.className = 'status ' + (online ? 'online' : 'offline');
    status.textContent = online ? 'online' : 'offline';

    // Get resource data for this client
    const resources = clientResources[c.id] || {};
    const resourceHtml = resources.cpu !== undefined ? `
      <div class="resources">
        <div class="resource-bar">
          <span>CPU</span>
          <div class="bar"><div class="fill" style="width: ${resources.cpu || 0}%"></div></div>
          <span>${Math.round(resources.cpu || 0)}%</span>
        </div>
        <div class="resource-bar">
          <span>RAM</span>
          <div class="bar"><div class="fill" style="width: ${resources.ram || 0}%"></div></div>
          <span>${Math.round(resources.ram || 0)}%</span>
        </div>
        <div class="resource-bar">
          <span>Disk</span>
          <div class="bar"><div class="fill" style="width: ${resources.disk || 0}%"></div></div>
          <span>${Math.round(resources.disk || 0)}%</span>
        </div>
      </div>
    ` : '';

    div.innerHTML = `
      <div class="row"><div><div><b>${c.name}</b></div><div class="muted">id: ${c.id} ${c.enrolled ? '' : '(not enrolled)'}</div></div></div>
      <div class="row"><div class="muted">${c.hostname || ''}</div><div>${status.outerHTML}</div></div>
      <div class="row"><div class="muted">last seen</div><div class="muted">${fmtAgo(c.last_seen)}</div></div>
      ${resourceHtml}
      <div class="row" style="margin-top: 8px;">
        <button class="btn-small btn-success" onclick="viewScreenshots(${c.id}, '${c.name}')">🖼 View Gallery</button>
      </div>
    `;
    wrap.appendChild(div);
  }
  updateActionButtons();
}

function updateActionButtons() {
  const enabled = !!selectedClientId;
  el('cmdLock').disabled = !enabled;
  el('cmdExamOn').disabled = !enabled;
  el('cmdExamOff').disabled = !enabled;
  el('cmdScreenshot').disabled = !enabled;
}

function appendLog(item) {
  const logs = el('logs');
  const div = document.createElement('div');
  div.className = 'log';
  div.innerHTML = `
    <div class="meta"><div>${item.client.name} • ${item.level}</div><div>${item.ts}</div></div>
    <div class="evt">${item.event_type}</div>
    <div class="mono">${JSON.stringify(item.data, null, 2)}</div>
  `;
  logs.prepend(div);
}

async function loadRecentLogs() {
  const res = await fetch('/api/admin/logs?limit=200', { headers: adminHeaders() });
  if (res.status === 401) throw new Error('Please login');
  if (!res.ok) throw new Error('Server error');
  const data = await res.json();
  el('logs').innerHTML = '';
  for (const l of data.logs.reverse()) appendLog(l);
}

async function addClient() {
  const name = el('newClientName').value.trim();
  const hostname = el('newClientHost').value.trim();
  if (!name) return;
  const res = await fetch('/api/admin/clients', {
    method: 'POST',
    headers: adminHeaders(),
    body: JSON.stringify({ name, hostname: hostname || null }),
  });
  if (res.status === 401) throw new Error('Please login');
  if (!res.ok) throw new Error('Server error');
  const data = await res.json();
  el('enrollOut').textContent = `Client ID: ${data.client_id}\nEnrollment Code:\n${data.enrollment_code}`;
  await loadClients();
  showToast(`Client "${name}" added`, 'success');
}

async function sendCommand(command_type, payload = {}) {
  if (!selectedClientId) return;
  const res = await fetch(`/api/admin/clients/${selectedClientId}/commands`, {
    method: 'POST',
    headers: adminHeaders(),
    body: JSON.stringify({ command_type, payload }),
  });
  if (res.status === 401) throw new Error('Please login');
  if (!res.ok) throw new Error('Server error');
  showToast(`Command "${command_type}" sent`, 'success');
}

async function broadcastCommand(command_type, payload = {}) {
  if (!confirm(`Send "${command_type}" to ALL online clients?`)) return;
  const res = await fetch('/api/admin/commands/broadcast', {
    method: 'POST',
    headers: adminHeaders(),
    body: JSON.stringify({ command_type, payload }),
  });
  if (res.status === 401) throw new Error('Please login');
  if (!res.ok) {
    const error = await res.text();
    throw new Error(error || 'Server error');
  }
  const data = await res.json();
  showToast(`Command sent to ${data.client_count} clients`, 'success');
}

async function loadBlockedUrls() {
  const res = await fetch('/api/admin/blocked-urls', { headers: adminHeaders() });
  if (res.status === 401) return;
  if (!res.ok) return;
  const data = await res.json();
  blockedUrls = data.blocked_urls || [];
  updateBlockedUrlsList();
}

function updateBlockedUrlsList() {
  const container = el('blockedUrlsList');
  if (!container) return;

  container.innerHTML = '';
  for (const url of blockedUrls) {
    const div = document.createElement('div');
    div.className = 'blocked-url-item';
    div.innerHTML = `
      <span>${url.pattern}</span>
      <button class="btn-small btn-danger" onclick="removeBlockedUrl(${url.id})">Remove</button>
    `;
    container.appendChild(div);
  }
}

async function addBlockedUrl() {
  const pattern = el('newBlockedUrl').value.trim();
  if (!pattern) return;

  const res = await fetch('/api/admin/blocked-urls', {
    method: 'POST',
    headers: adminHeaders(),
    body: JSON.stringify({ pattern }),
  });
  if (res.status === 401) throw new Error('Please login');
  if (!res.ok) {
    const error = await res.text();
    throw new Error(error || 'Failed to add URL');
  }

  el('newBlockedUrl').value = '';
  await loadBlockedUrls();
  showToast(`Blocked URL added: ${pattern}`, 'success');
}

async function removeBlockedUrl(urlId) {
  const res = await fetch(`/api/admin/blocked-urls/${urlId}`, {
    method: 'DELETE',
    headers: adminHeaders(),
  });
  if (res.status === 401) throw new Error('Please login');
  if (!res.ok) throw new Error('Server error');

  await loadBlockedUrls();
  showToast('Blocked URL removed', 'success');
}

async function viewScreenshots(clientId, clientName) {
  try {
    const res = await fetch(`/api/admin/screenshots/${clientId}`, { headers: adminHeaders() });
    if (res.status === 401) throw new Error('Please login');
    const data = await res.json();

    const modal = el('screenshotModal');
    const gallery = el('screenshotGallery');
    const title = el('modalTitle');

    title.textContent = `Screenshots: ${clientName}`;
    gallery.innerHTML = '';

    if (!data.screenshots || data.screenshots.length === 0) {
      gallery.innerHTML = '<div class="muted" style="padding: 20px;">No screenshots found for this client.</div>';
    } else {
      for (const s of data.screenshots) {
        const item = document.createElement('div');
        item.className = 'gallery-item';
        item.innerHTML = `
          <img src="/static/screenshots/${s.filename}" alt="Screenshot" onclick="window.open(this.src)">
          <div class="muted" style="font-size: 10px; margin-top: 4px;">${s.ts}</div>
        `;
        gallery.appendChild(item);
      }
    }

    modal.style.display = 'flex';
  } catch (e) {
    alert(e.message);
  }
}

function closeModal() {
  el('screenshotModal').style.display = 'none';
}

function connectWS() {
  const ws = new WebSocket(`ws://${location.host}/ws/admin`);
  ws.onopen = () => setConnStatus('connected', true);
  ws.onclose = () => {
    setConnStatus('disconnected', false);
    setTimeout(connectWS, 1000);
  };
  ws.onmessage = async (ev) => {
    try {
      const msg = JSON.parse(ev.data);

      // Handle heartbeat with resource data
      if (msg.type === 'heartbeat') {
        if (msg.resources) {
          clientResources[msg.client_id] = msg.resources;
          await loadClients();
        }
        if (msg.url_violations && msg.url_violations.length > 0) {
          for (const url of msg.url_violations) {
            addNotification(`⚠️ Blocked URL accessed: ${url}`, 'warning');
          }
        }
      }

      // Handle client connection events
      if (msg.type === 'client_enrolled' || msg.type === 'client_added') {
        await loadClients();
        addNotification(`✅ Client connected (ID: ${msg.client_id})`, 'success');
      }

      // Handle screenshot captured
      if (msg.type === 'screenshot_captured') {
        addNotification(`📸 Screenshot captured from client ${msg.client_id}`, 'info');
      }

      // Handle bulk commands
      if (msg.type === 'commands_broadcast') {
        addNotification(`📢 Command "${msg.command_type}" sent to ${msg.client_count} clients`, 'info');
      }

      // Handle URL blocking updates
      if (msg.type === 'blocked_url_added' || msg.type === 'blocked_url_removed') {
        await loadBlockedUrls();
      }

      if (msg.type === 'logs') {
        await loadRecentLogs();
      }
    } catch (_) { }
  };
}

// Event listeners
onClick('refreshClients', async () => {
  try {
    await loadClients();
  } catch (e) {
    alert(e.message);
  }
});

onClick('addClient', async () => {
  try {
    await addClient();
  } catch (e) {
    alert(e.message);
  }
});

onClick('loadLogs', async () => {
  try {
    await loadRecentLogs();
  } catch (e) {
    alert(e.message);
  }
});

onClick('cmdLock', async () => {
  try {
    await sendCommand('lock_screen');
  } catch (e) {
    alert(e.message);
  }
});

onClick('cmdExamOn', async () => {
  try {
    await sendCommand('exam_mode', { enabled: true });
  } catch (e) {
    alert(e.message);
  }
});

onClick('cmdExamOff', async () => {
  try {
    await sendCommand('exam_mode', { enabled: false });
  } catch (e) {
    alert(e.message);
  }
});

onClick('cmdScreenshot', async () => {
  try {
    await sendCommand('capture_screenshot');
  } catch (e) {
    alert(e.message);
  }
});

onClick('cmdLockAll', async () => {
  try {
    await broadcastCommand('lock_screen');
  } catch (e) {
    alert(e.message);
  }
});

onClick('cmdExamOnAll', async () => {
  try {
    await broadcastCommand('exam_mode', { enabled: true });
  } catch (e) {
    alert(e.message);
  }
});

onClick('cmdExamOffAll', async () => {
  try {
    await broadcastCommand('exam_mode', { enabled: false });
  } catch (e) {
    alert(e.message);
  }
});

onClick('addBlockedUrlBtn', async () => {
  try {
    await addBlockedUrl();
  } catch (e) {
    alert(e.message);
  }
});

onClick('toggleAudio', () => {
  audioEnabled = !audioEnabled;
  localStorage.setItem('audioEnabled', audioEnabled);
  el('toggleAudio').textContent = audioEnabled ? '🔊 Audio On' : '🔇 Audio Off';
  showToast(audioEnabled ? 'Audio alerts enabled' : 'Audio alerts disabled', 'info');
});

onClick('loginBtn', async () => {
  try {
    await login();
  } catch (e) {
    alert(e.message);
  }
});

// Initialize
(async () => {
  setConnStatus('disconnected', false);
  if (el('toggleAudio')) {
    el('toggleAudio').textContent = audioEnabled ? '🔊 Audio On' : '🔇 Audio Off';
  }
  try {
    await loadClients();
    await loadBlockedUrls();
  } catch (_) { }
  connectWS();
})();
