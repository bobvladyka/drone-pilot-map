// Připojení k SendBird
const appId = '1B842DAB-6AE6-4FFD-B331-E026CA9F63C5';  // Nahraďte vlastním SendBird App ID
const userId = 'drboom';     // Nahraďte ID uživatele

const sendBird = new SendBird({ appId: appId });

// Připojení uživatele
sendBird.connect(userId, function(user, error) {
  if (error) {
    console.log('Chyba při připojování k SendBird:', error);
    return;
  }
  console.log('Připojeno k SendBird');
});

// Odesílání zpráv
const messageInput = document.getElementById('message-input');
const sendButton = document.getElementById('send-button');
const messageList = document.getElementById('message-list');

sendButton.addEventListener('click', function() {
  const message = messageInput.value;
  if (message) {
    sendMessage(message);
  }
});

function sendMessage(message) {
  const messageDiv = document.createElement('div');
  messageDiv.textContent = message;
  messageList.appendChild(messageDiv);
  messageInput.value = '';

  // Odesílání zprávy přes SendBird
  sendBird.sendMessage('CHANNEL_URL', message, function(message, error) {
    if (error) {
      console.log('Chyba při odesílání zprávy:', error);
      return;
    }
    console.log('Zpráva odeslána:', message);
  });
}

// Příjem zpráv
sendBird.addChannelHandler('UNIQUE_HANDLER_ID', {
  onMessageReceived: function(channel, message) {
    const messageDiv = document.createElement('div');
    messageDiv.textContent = message.message;
    messageList.appendChild(messageDiv);
  }
});

// Funkce pro vytvoření unikátního kanálu
function createUniqueChannel(pilotId, advertiserId) {
  const channelUrl = `${pilotId}-${advertiserId}`; // Unikátní URL kanálu
  const params = new sb.OpenChannelParams();
  params.name = `Chat between ${pilotId} and ${advertiserId}`;

  // Vytvoření kanálu
  sb.OpenChannel.createChannel(params, function(channel, error) {
    if (error) {
      console.log('Chyba při vytváření kanálu:', error);
      return;
    }
    console.log('Kanál vytvořen:', channel);
    // Připojení k kanálu
    joinChannel(channelUrl);
  });
}

// Funkce pro připojení k kanálu
function joinChannel(channelUrl) {
  sb.OpenChannel.getChannel(channelUrl, function(channel, error) {
    if (error) {
      console.log('Chyba při připojování k kanálu:', error);
      return;
    }
    console.log('Připojení k kanálu:', channel);
    // Zde můžeš zobrazit zprávy a začít chatování
  });
}

