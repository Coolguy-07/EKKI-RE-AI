/**
 * EKKI-RE-AI Frontend Application Controller
 * Handles user interactions, API communication, and dynamic UI rendering.
 */

// Configuration Options
const CONFIG = {
    API_URL: 'http://127.0.0.1:8000/chat',
    STREAM_API_URL: 'http://127.0.0.1:8000/chat/stream',
    STATUS: {
        READY: 'Ready',
        THINKING: 'Thinking...',
        ERROR: 'Error'
    }
};

// DOM Element References
const chatForm = document.getElementById('chat-form');
const promptInput = document.getElementById('prompt-input');
const sendButton = document.getElementById('send-button');
const messagesList = document.getElementById('messages-list');
const statusBadge = document.getElementById('status-badge');
const chatContainer = document.getElementById('chat-container');

/**
 * Formats current time into a human-readable string.
 * @returns {string} Formatted timestamp (e.g., "10:42 AM")
 */
function getCurrentTimestamp() {
    const now = new Date();
    return now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/**
 * Updates the application status badge text.
 * @param {string} status - Status message to display
 */
function updateStatus(status) {
    if (statusBadge) {
        statusBadge.textContent = status;
    }
}

/**
 * Toggles the interactive state of input controls during API calls.
 * @param {boolean} isLoading - Loading state flag
 */
function setFormDisabledState(isLoading) {
    if (sendButton) sendButton.disabled = isLoading;
    if (promptInput) promptInput.disabled = isLoading;
}

/**
 * Automatically scrolls the chat container to the newest message.
 */
function scrollToBottom() {
    if (chatContainer) {
        chatContainer.scrollTop = chatContainer.scrollHeight;
    } else if (messagesList) {
        messagesList.scrollTop = messagesList.scrollHeight;
    }
}

/**
 * Creates and appends a message container placeholder to the DOM.
 * @param {string} sender - Identifier for sender ('User' or 'Assistant')
 * @param {boolean} isUser - True if sender is user, false if assistant
 * @returns {HTMLElement} The message content DOM element for appending text
 */
function appendMessagePlaceholder(sender, isUser = false) {
    const messageElement = document.createElement('div');
    messageElement.className = `message ${isUser ? 'user-message' : 'assistant-message'}`;

    const headerElement = document.createElement('div');
    headerElement.className = 'message-header';

    const senderSpan = document.createElement('span');
    senderSpan.className = 'message-sender';
    senderSpan.textContent = sender;

    const timeSpan = document.createElement('span');
    timeSpan.className = 'message-time';
    timeSpan.textContent = getCurrentTimestamp();

    headerElement.appendChild(senderSpan);
    headerElement.appendChild(timeSpan);

    const contentElement = document.createElement('div');
    contentElement.className = 'message-content';

    messageElement.appendChild(headerElement);
    messageElement.appendChild(contentElement);

    messagesList.appendChild(messageElement);
    scrollToBottom();

    return contentElement;
}

/**
 * Creates and appends a static chat message element to the DOM safely.
 * @param {string} sender - Identifier for sender ('User' or 'Assistant')
 * @param {string} content - Message text content
 * @param {boolean} isUser - True if sender is user, false if assistant
 */
function appendMessage(sender, content, isUser = false) {
    const contentElement = appendMessagePlaceholder(sender, isUser);
    contentElement.textContent = content;
}

/**
 * Sends prompt text to backend streaming endpoint and yields tokens in real time via SSE.
 * @param {string} userMessage - Text prompt submitted by user
 * @param {function(string): void} onChunkCallback - Called on each received token chunk
 */
async function fetchAiResponseStream(userMessage, onChunkCallback) {
    const response = await fetch(CONFIG.STREAM_API_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ message: userMessage })
    });

    if (!response.ok) {
        throw new Error(`Server returned error status: ${response.status}`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8');
    let buffer = '';

    while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
            const trimmedLine = line.trim();
            if (!trimmedLine.startsWith('data:')) continue;

            const jsonStr = trimmedLine.slice(5).trim();
            if (!jsonStr) continue;

            try {
                const parsed = JSON.parse(jsonStr);

                if (parsed.error) {
                    throw new Error(parsed.error);
                }

                if (parsed.content) {
                    onChunkCallback(parsed.content);
                }

                if (parsed.done) {
                    return;
                }
            } catch (err) {
                if (err.message && !err.message.includes('Unexpected token')) {
                    throw err;
                }
            }
        }
    }
}

/**
 * Handles message submission lifecycle with real-time SSE streaming.
 * @param {string} messageText - Input text from user
 */
async function handleUserSubmit(messageText) {
    // Render User Message
    appendMessage('You', messageText, true);

    // Clear Textarea
    promptInput.value = '';
    promptInput.style.height = 'auto';

    // Set UI Loading State
    setFormDisabledState(true);
    updateStatus(CONFIG.STATUS.THINKING);

    // Create Assistant Message Placeholder element for streaming
    const assistantContentEl = appendMessagePlaceholder('EKKI-RE-AI', false);

    try {
        await fetchAiResponseStream(messageText, (chunk) => {
            assistantContentEl.textContent += chunk;
            scrollToBottom();
        });

        updateStatus(CONFIG.STATUS.READY);
    } catch (error) {
        console.error('API Interaction Error:', error);

        // Remove empty placeholder if nothing was streamed yet
        if (!assistantContentEl.textContent && assistantContentEl.parentElement) {
            assistantContentEl.parentElement.remove();
        }

        appendMessage(
            'System Error',
            'Unable to connect to local AI service. Ensure FastAPI & Ollama server are running.',
            false
        );
        updateStatus(CONFIG.STATUS.ERROR);

        setTimeout(() => updateStatus(CONFIG.STATUS.READY), 4000);
    } finally {
        setFormDisabledState(false);
        promptInput.focus();
    }
}

/**
 * Form Submit Event Handler
 * @param {Event} event - Submit Event Object
 */
function onFormSubmit(event) {
    event.preventDefault();

    const trimmedInput = promptInput.value.trim();
    if (!trimmedInput) return;

    handleUserSubmit(trimmedInput);
}

/**
 * Keyboard Shortcuts Handler (Allows Enter to submit, Shift+Enter for newline)
 * @param {KeyboardEvent} event 
 */
function onInputKeyDown(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        chatForm.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
    }
}

/**
 * Automatically adjusts textarea height to match content.
 */
function autoResizeInput() {
    promptInput.style.height = 'auto';
    promptInput.style.height = `${promptInput.scrollHeight}px`;
}

/**
 * Application Entry Point & Listener Registration
 */
function init() {
    if (chatForm) {
        chatForm.addEventListener('submit', onFormSubmit);
    }

    if (promptInput) {
        promptInput.addEventListener('keydown', onInputKeyDown);
        promptInput.addEventListener('input', autoResizeInput);
    }

    updateStatus(CONFIG.STATUS.READY);
}

// Initialize application when DOM is completely loaded
document.addEventListener('DOMContentLoaded', init);