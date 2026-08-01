/**
 * EKKI-RE-AI Frontend Application Controller
 * Handles user interactions, API communication, and dynamic UI rendering.
 */

// Configuration Options
const CONFIG = {
    API_URL: 'http://127.0.0.1:8000/chat',
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
 * Creates and appends a chat message element to the DOM safely.
 * @param {string} sender - Identifier for sender ('User' or 'Assistant')
 * @param {string} content - Message text content
 * @param {boolean} isUser - True if sender is user, false if assistant
 */
function appendMessage(sender, content, isUser = false) {
    // Parent Message Container
    const messageElement = document.createElement('div');
    messageElement.className = `message ${isUser ? 'user-message' : 'assistant-message'}`;

    // Header Area (Sender Name & Timestamp)
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

    // Body Area (Text Content)
    const contentElement = document.createElement('div');
    contentElement.className = 'message-content';
    
    // Security: Safely render text to prevent XSS attacks
    contentElement.textContent = content;

    // Assemble components
    messageElement.appendChild(headerElement);
    messageElement.appendChild(contentElement);

    // Append to conversation list
    messagesList.appendChild(messageElement);

    // Auto scroll to latest entry
    scrollToBottom();
}

/**
 * Sends prompt text to backend FastAPI endpoint.
 * @param {string} userMessage - Text prompt submitted by user
 * @returns {Promise<string>} Response text from the model
 */
async function fetchAiResponse(userMessage) {
    const response = await fetch(CONFIG.API_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ message: userMessage })
    });

    if (!response.ok) {
        throw new Error(`Server returned error status: ${response.status}`);
    }

    const data = await response.json();
    return data.response;
}

/**
 * Handles message submission lifecycle.
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

    try {
        // Request response from backend
        const aiResponse = await fetchAiResponse(messageText);
        
        // Render AI Message
        appendMessage('EKKI-RE-AI', aiResponse, false);
        updateStatus(CONFIG.STATUS.READY);
    } catch (error) {
        console.error('API Interaction Error:', error);
        
        // Display friendly error message in conversation
        appendMessage(
            'System Error', 
            'Unable to connect to local AI service. Ensure FastAPI & Ollama server are running.', 
            false
        );
        updateStatus(CONFIG.STATUS.ERROR);
        
        // Reset status to ready after delay on error
        setTimeout(() => updateStatus(CONFIG.STATUS.READY), 4000);
    } finally {
        // Re-enable form controls
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