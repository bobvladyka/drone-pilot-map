<!DOCTYPE html>
<html lang="cs">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Můj chat | NajdiPilota.cz</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    .chat-container {
      height: calc(100vh - 200px);
    }
    .conversation-list {
      height: 100%;
      overflow-y: auto;
    }
    .chat-window {
      height: 100%;
      display: flex;
      flex-direction: column;
    }
    .chat-messages {
      flex: 1;
      overflow-y: auto;
    }
    .message {
      padding: 8px 12px;
      margin-bottom: 8px;
      border-radius: 18px;
      max-width: 80%;
    }
    .message.sent {
      background-color: #007bff;
      color: white;
      margin-left: auto;
    }
    .message.received {
      background-color: #e9ecef;
      margin-right: auto;
    }
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg navbar-light bg-light">
    <div class="container">
      <a class="navbar-brand" href="/">
        <img src="/icons/logo.png" alt="Logo" height="40"> Můj chat
      </a>
    </div>
  </nav>

  <div class="container mt-4">
    <div class="row chat-container">
      <!-- Seznam konverzací -->
      <div class="col-md-4">
        <div class="card h-100">
          <div class="card-header">
            <h5>Konverzace</h5>
          </div>
          <div class="card-body conversation-list" id="conversationList"></div>
        </div>
      </div>
      
      <!-- Chatovací okno -->
      <div class="col-md-8">
        <div class="card h-100">
          <div class="card-header d-flex justify-content-between">
            <h5 id="chatPartnerName">Vyberte konverzaci</h5>
          </div>
          <div class="card-body chat-window">
            <div class="chat-messages" id="chatMessages"></div>
            <div class="chat-input mt-3">
              <textarea id="messageInput" class="form-control" placeholder="Napište zprávu..." disabled></textarea>
              <button id="sendMessage" class="btn btn-primary mt-2" disabled>Odeslat</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    let currentConversationId = null;
    const pilotId = localStorage.getItem('pilotId');
    const pilotEmail = localStorage.getItem('pilotEmail');

    if (!pilotId) {
      window.location.href = '/login.html';
    }

    // Načíst konverzace
    async function loadConversations() {
      try {
        const response = await fetch(`/api/conversations?userEmail=${pilotEmail}&userType=pilot`);
        const conversations = await response.json();
        
        const container = document.getElementById('conversationList');
        container.innerHTML = '';
        
        conversations.forEach(conv => {
          const convElement = document.createElement('div');
          convElement.className = 'p-3 border-bottom conversation-item';
          convElement.style.cursor = 'pointer';
          convElement.innerHTML = `
            <div class="fw-bold">${conv.partnerName}</div>
            <div class="small text-muted">${conv.lastMessage || 'Žádné zprávy'}</div>
            <div class="small text-muted">${new Date(conv.lastMessageTime).toLocaleString()}</div>
          `;
          
          convElement.addEventListener('click', () => openConversation(conv.id, conv.partnerEmail, conv.partnerName));
          container.appendChild(convElement);
        });
      } catch (error) {
        console.error('Chyba při načítání konverzací:', error);
      }
    }

    // Otevřít konverzaci
    async function openConversation(conversationId, partnerEmail, partnerName) {
      currentConversationId = conversationId;
      document.getElementById('chatPartnerName').textContent = partnerName;
      document.getElementById('messageInput').disabled = false;
      document.getElementById('sendMessage').disabled = false;
      
      // Načíst zprávy
      const response = await fetch(`/api/messages?conversationId=${conversationId}`);
      const messages = await response.json();
      
      const messagesContainer = document.getElementById('chatMessages');
      messagesContainer.innerHTML = '';
      
      messages.forEach(msg => {
        const isMe = msg.sender_email === pilotEmail;
        const messageElement = document.createElement('div');
        messageElement.className = `message ${isMe ? 'sent' : 'received'}`;
        messageElement.innerHTML = `
          <div class="message-text">${msg.message}</div>
          <div class="message-time small text-muted">
            ${new Date(msg.created_at).toLocaleString()}
          </div>
        `;
        messagesContainer.appendChild(messageElement);
      });
      
      messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    // Odeslat zprávu
    async function sendMessage() {
      const input = document.getElementById('messageInput');
      const message = input.value.trim();
      
      if (!message || !currentConversationId) return;

      try {
        const response = await fetch('/api/messages', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            conversation_id: currentConversationId,
            sender_id: pilotId,
            sender_type: 'pilot',
            message: message
          })
        });
        
        const newMessage = await response.json();
        
        // Přidat zprávu do chatu
        const messagesContainer = document.getElementById('chatMessages');
        const messageElement = document.createElement('div');
        messageElement.className = 'message sent';
        messageElement.innerHTML = `
          <div class="message-text">${newMessage.message}</div>
          <div class="message-time small text-muted">
            ${new Date().toLocaleString()}
          </div>
        `;
        messagesContainer.appendChild(messageElement);
        
        // Vyčistit input a scrollnout dolů
        input.value = '';
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
        
        // Aktualizovat seznam konverzací
        loadConversations();
      } catch (error) {
        console.error('Chyba při odesílání zprávy:', error);
      }
    }

    // Event listeners
    document.getElementById('sendMessage').addEventListener('click', sendMessage);
    document.getElementById('messageInput').addEventListener('keypress', function(e) {
      if (e.key === 'Enter') sendMessage();
    });

    // Načíst konverzace při startu
    document.addEventListener('DOMContentLoaded', loadConversations);
  </script>
</body>
</html>