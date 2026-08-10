/**
 * EKKI-RE-AI Frontend Application Controller
 * Production-Grade Stability Edition with Session Isolation, Streaming Abort Controllers,
 * Project Workspace Explorer, Secure HTML Escaping, and Throttled Render Buffering.
 */

// Configuration Options
const CONFIG = {
    API_URL: 'http://127.0.0.1:8000/chat',
    STREAM_API_URL: 'http://127.0.0.1:8000/chat/stream',
    ORCHESTRATE_API_URL: 'http://127.0.0.1:8000/chat/orchestrate',
    PROJECTS_API_URL: 'http://127.0.0.1:8000/api/projects',
    PERMISSIONS_API_URL: 'http://127.0.0.1:8000/api/security/permissions',
    APPROVALS_API_URL: 'http://127.0.0.1:8000/api/security/approvals',
    STATUS: {
        READY: 'Ready',
        THINKING: 'Thinking...',
        ERROR: 'Error'
    }
};

// LocalStorage Keys
const STORAGE_KEYS = {
    CONVERSATIONS: 'ekki_conversations',
    ACTIVE_ID: 'ekki_active_conversation_id'
};

// State Data
let conversations = [];
let activeConversationId = null;
let activeStreamController = null;
let activeRenderFrameId = null;

// Project Workspace State
let projectsList = [];
let activeProjectId = null;
let activeProjectMetadata = null;
let expandedProjectIds = new Set();
let selectedFileMeta = null;
let selectedFileProjectId = null;

// DOM Element References
const chatForm = document.getElementById('chat-form');
const promptInput = document.getElementById('prompt-input');
const sendButton = document.getElementById('send-button');
const messagesList = document.getElementById('messages-list');
const statusBadge = document.getElementById('status-badge');
const chatContainer = document.getElementById('chat-container');

// Sidebar DOM References
const sidebar = document.getElementById('sidebar');
const sidebarToggleBtn = document.getElementById('sidebar-toggle-btn');
const sidebarOverlay = document.getElementById('sidebar-overlay');
const newChatBtn = document.getElementById('new-chat-btn');
const conversationList = document.getElementById('conversation-list');

// Project Workspace DOM References
const projectsTreeContainer = document.getElementById('projects-tree-container');
const newProjectBtn = document.getElementById('new-project-btn');
const headerProjectName = document.getElementById('header-project-name');
const createProjectModal = document.getElementById('create-project-modal');
const createProjectForm = document.getElementById('create-project-form');
const fileDetailsModal = document.getElementById('file-details-modal');

/**
 * Formats current time into a human-readable string.
 * @returns {string} Formatted timestamp (e.g., "10:42 AM")
 */
function getCurrentTimestamp() {
    const now = new Date();
    return now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/**
 * Formats file size in bytes to human-readable string (KB, MB).
 * @param {number} bytes 
 * @returns {string} Formatted size
 */
function formatFileSize(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Escapes HTML entity characters to prevent XSS vulnerabilities.
 * @param {string} str - Raw input text
 * @returns {string} HTML-escaped string
 */
function escapeHtml(str) {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
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
 * Aborts any currently active streaming HTTP request cleanly.
 */
function abortActiveStream() {
    if (activeRenderFrameId) {
        cancelAnimationFrame(activeRenderFrameId);
        activeRenderFrameId = null;
    }
    if (activeStreamController) {
        activeStreamController.abort();
        activeStreamController = null;
    }
    setFormDisabledState(false);
    updateStatus(CONFIG.STATUS.READY);
}

/**
 * Loads conversation state from localStorage.
 */
function loadStateFromStorage() {
    try {
        const storedConv = localStorage.getItem(STORAGE_KEYS.CONVERSATIONS);
        conversations = storedConv ? JSON.parse(storedConv) : [];
        activeConversationId = localStorage.getItem(STORAGE_KEYS.ACTIVE_ID) || null;
    } catch (e) {
        console.error('Failed to load conversations from localStorage:', e);
        conversations = [];
        activeConversationId = null;
    }
}

/**
 * Persists conversations and active ID state into localStorage with quota overflow protection.
 */
function saveStateToStorage() {
    try {
        localStorage.setItem(STORAGE_KEYS.CONVERSATIONS, JSON.stringify(conversations));
        if (activeConversationId) {
            localStorage.setItem(STORAGE_KEYS.ACTIVE_ID, activeConversationId);
        } else {
            localStorage.removeItem(STORAGE_KEYS.ACTIVE_ID);
        }
    } catch (e) {
        if (e.name === 'QuotaExceededError' || e.code === 22 || e.code === 1014) {
            console.warn('localStorage quota exceeded. Auto-pruning oldest conversation history...');
            if (conversations.length > 1) {
                const activeConvIndex = conversations.findIndex(c => c.id === activeConversationId);
                for (let i = conversations.length - 1; i >= 0; i--) {
                    if (i !== activeConvIndex) {
                        conversations.splice(i, 1);
                        break;
                    }
                }
                saveStateToStorage();
            }
        } else {
            console.error('Failed to save state to localStorage:', e);
        }
    }
}

/**
 * Generates a clean title string from user prompt text.
 * @param {string} promptText 
 * @returns {string} Truncated title string
 */
function generateTitleFromPrompt(promptText) {
    if (!promptText) return 'New Conversation';
    const cleaned = promptText.trim().replace(/\s+/g, ' ');
    return cleaned.length > 28 ? `${cleaned.slice(0, 28)}...` : cleaned;
}

/**
 * Renders the list of conversations inside the left sidebar.
 */
function renderSidebarList() {
    if (!conversationList) return;
    conversationList.innerHTML = '';

    if (conversations.length === 0) {
        const emptyItem = document.createElement('li');
        emptyItem.className = 'conversation-item';
        emptyItem.style.color = 'var(--text-muted)';
        emptyItem.style.cursor = 'default';
        emptyItem.textContent = 'No previous chats';
        conversationList.appendChild(emptyItem);
        return;
    }

    conversations.forEach((conv) => {
        const item = document.createElement('li');
        item.className = `conversation-item ${conv.id === activeConversationId ? 'active' : ''}`;
        item.dataset.id = conv.id;

        const titleWrapper = document.createElement('div');
        titleWrapper.className = 'conv-title-wrapper';

        const titleSpan = document.createElement('span');
        titleSpan.className = 'conv-title';
        titleSpan.textContent = conv.title || 'New Conversation';

        titleWrapper.appendChild(titleSpan);

        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'conv-actions';

        const editBtn = document.createElement('button');
        editBtn.type = 'button';
        editBtn.className = 'conv-action-btn edit-btn';
        editBtn.setAttribute('aria-label', 'Rename conversation');
        editBtn.innerHTML = `
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 20h9"></path>
                <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path>
            </svg>
        `;

        const deleteBtn = document.createElement('button');
        deleteBtn.type = 'button';
        deleteBtn.className = 'conv-action-btn delete-btn';
        deleteBtn.setAttribute('aria-label', 'Delete conversation');
        deleteBtn.innerHTML = `
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="3 6 5 6 21 6"></polyline>
                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
            </svg>
        `;

        actionsDiv.appendChild(editBtn);
        actionsDiv.appendChild(deleteBtn);

        item.appendChild(titleWrapper);
        item.appendChild(actionsDiv);

        conversationList.appendChild(item);
    });
}

/**
 * Switches active chat session to specified conversation ID.
 * @param {string} id - Conversation ID to display
 */
function loadConversation(id) {
    abortActiveStream();

    const targetConv = conversations.find(c => c.id === id);
    if (!targetConv) return;

    activeConversationId = id;
    saveStateToStorage();
    renderSidebarList();

    messagesList.innerHTML = '';
    targetConv.messages.forEach(msg => {
        appendMessage(msg.sender, msg.content, msg.isUser, msg.timestamp);
    });

    updateWelcomeScreenState();
    scrollToBottom();
}

/**
 * Resets active conversation state to start a clean chat session.
 */
function startNewChat() {
    abortActiveStream();

    activeConversationId = null;
    saveStateToStorage();
    messagesList.innerHTML = '';
    renderSidebarList();
    updateWelcomeScreenState();

    if (window.innerWidth <= 768) {
        closeSidebar();
    }
    if (promptInput) promptInput.focus();
}

function renameConversation(id) {
    const conv = conversations.find(c => c.id === id);
    if (!conv) return;

    const newTitle = prompt('Enter new conversation title:', conv.title);
    if (newTitle !== null && newTitle.trim() !== '') {
        conv.title = newTitle.trim();
        saveStateToStorage();
        renderSidebarList();
    }
}

function deleteConversation(id) {
    if (activeConversationId === id) {
        abortActiveStream();
    }

    const confirmDelete = confirm('Are you sure you want to delete this conversation?');
    if (!confirmDelete) return;

    conversations = conversations.filter(c => c.id !== id);

    if (activeConversationId === id) {
        activeConversationId = conversations.length > 0 ? conversations[0].id : null;
        messagesList.innerHTML = '';
        if (activeConversationId) {
            loadConversation(activeConversationId);
        }
    }

    saveStateToStorage();
    renderSidebarList();
}

function toggleSidebar() {
    if (!sidebar) return;
    if (window.innerWidth <= 768) {
        sidebar.classList.toggle('open');
        if (sidebarOverlay) sidebarOverlay.classList.toggle('open');
    } else {
        sidebar.classList.toggle('collapsed');
    }
}

function closeSidebar() {
    if (sidebar) sidebar.classList.remove('open');
    if (sidebarOverlay) sidebarOverlay.classList.remove('open');
}

function setupSidebarListeners() {
    if (sidebarToggleBtn) sidebarToggleBtn.addEventListener('click', toggleSidebar);
    if (sidebarOverlay) sidebarOverlay.addEventListener('click', closeSidebar);
    if (newChatBtn) newChatBtn.addEventListener('click', startNewChat);

    if (conversationList) {
        conversationList.addEventListener('click', (e) => {
            const item = e.target.closest('.conversation-item');
            if (!item || !item.dataset.id) return;
            const id = item.dataset.id;

            if (e.target.closest('.edit-btn')) {
                e.stopPropagation();
                renameConversation(id);
                return;
            }
            if (e.target.closest('.delete-btn')) {
                e.stopPropagation();
                deleteConversation(id);
                return;
            }

            loadConversation(id);
            if (window.innerWidth <= 768) closeSidebar();
        });
    }
}

/* ==========================================================================
   Project Workspace Frontend API & Tree Explorer
   ========================================================================== */

/**
 * Fetches lightweight project summaries from backend REST API.
 */
async function fetchProjectsList() {
    try {
        const response = await fetch(CONFIG.PROJECTS_API_URL);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        projectsList = await response.json();
        await fetchActiveProjectForSession();
    } catch (err) {
        console.warn('Workspace projects API unavailable:', err.message);
        projectsList = [];
        renderProjectsTree();
    }
}

/**
 * Fetches active project workspace metadata for default session.
 */
async function fetchActiveProjectForSession() {
    try {
        const sessionId = activeConversationId || 'default';
        const response = await fetch(`${CONFIG.PROJECTS_API_URL}/active/${sessionId}`);
        if (response.ok) {
            const data = await response.json();
            if (data && data.project_id) {
                activeProjectId = data.project_id;
                activeProjectMetadata = data;
                expandedProjectIds.add(data.project_id);
            } else if (!activeProjectId) {
                activeProjectId = null;
                activeProjectMetadata = null;
            }
        }
    } catch (err) {
        console.warn('Could not fetch active project session:', err.message);
    }
    updateActiveProjectHeaderUI();
    renderProjectsTree();
}

/**
 * Updates header project badge indicator text and tooltip.
 */
function updateActiveProjectHeaderUI() {
    if (headerProjectName) {
        if (activeProjectMetadata) {
            headerProjectName.textContent = activeProjectMetadata.name;
            headerProjectName.parentElement.title = `Active Workspace: ${activeProjectMetadata.name} (${activeProjectMetadata.project_id})`;
            headerProjectName.parentElement.classList.add('active');
        } else {
            headerProjectName.textContent = 'No Active Project';
            headerProjectName.parentElement.title = 'No project currently active';
            headerProjectName.parentElement.classList.remove('active');
        }
    }
}

/**
 * Renders the sidebar tree view for Project Workspaces.
 */
async function renderProjectsTree() {
    if (!projectsTreeContainer) return;
    projectsTreeContainer.innerHTML = '';

    if (projectsList.length === 0) {
        const emptyMsg = document.createElement('div');
        emptyMsg.className = 'empty-files-tree';
        emptyMsg.innerHTML = '<span>No projects yet. Click <strong>+</strong> to create one.</span>';
        projectsTreeContainer.appendChild(emptyMsg);
        return;
    }

    for (const proj of projectsList) {
        const projItem = document.createElement('div');
        const isActive = proj.project_id === activeProjectId;
        const isExpanded = expandedProjectIds.has(proj.project_id);

        projItem.className = `project-tree-item ${isActive ? 'active' : ''}`;

        const headerDiv = document.createElement('div');
        headerDiv.className = 'project-item-header';
        headerDiv.dataset.id = proj.project_id;

        headerDiv.innerHTML = `
            <div class="project-item-left">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="${isActive ? '#00f2fe' : 'currentColor'}" stroke-width="2">
                    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
                </svg>
                <span class="project-item-title">${escapeHtml(proj.name)}</span>
            </div>
            <div class="project-actions">
                <button type="button" class="icon-btn-sm toggle-open-proj-btn" title="${isActive ? 'Close Project' : 'Open Project'}">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="${isActive ? '#00f2fe' : 'currentColor'}" stroke-width="2">
                        ${isActive ? '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>' : '<polygon points="5 3 19 12 5 21 5 3"/>'}
                    </svg>
                </button>
                <button type="button" class="icon-btn-sm delete-proj-btn" title="Delete Project">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="3 6 5 6 21 6"></polyline>
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"></path>
                    </svg>
                </button>
            </div>
        `;

        headerDiv.addEventListener('click', (e) => {
            if (e.target.closest('.toggle-open-proj-btn')) {
                e.stopPropagation();
                if (isActive) closeProjectSession(proj.project_id);
                else openProjectSession(proj.project_id);
                return;
            }
            if (e.target.closest('.delete-proj-btn')) {
                e.stopPropagation();
                deleteProjectWorkspace(proj.project_id);
                return;
            }

            // Expand/collapse tree files
            if (expandedProjectIds.has(proj.project_id)) {
                expandedProjectIds.delete(proj.project_id);
            } else {
                expandedProjectIds.add(proj.project_id);
            }
            renderProjectsTree();
        });

        projItem.appendChild(headerDiv);

        // Render Tree Sub-list if expanded or active
        if (isExpanded || isActive) {
            const filesUl = document.createElement('ul');
            filesUl.className = 'project-files-tree';

            try {
                // Fetch full project metadata to list files
                const projRes = await fetch(`${CONFIG.PROJECTS_API_URL}/${proj.project_id}`);
                if (projRes.ok) {
                    const projMeta = await projRes.json();
                    const filesMap = projMeta.files || {};
                    const filesList = Object.values(filesMap);

                    if (filesList.length === 0) {
                        const emptyFileLi = document.createElement('li');
                        emptyFileLi.className = 'empty-files-tree';
                        emptyFileLi.textContent = 'No files uploaded yet';
                        filesUl.appendChild(emptyFileLi);
                    } else {
                        filesList.forEach((file) => {
                            const fileLi = document.createElement('li');
                            fileLi.className = 'file-tree-item';
                            fileLi.innerHTML = `
                                <div class="file-tree-left">
                                    <span>📄</span>
                                    <span class="file-name">${escapeHtml(file.filename)}</span>
                                    <span class="file-id-tag">${escapeHtml(file.file_id)}</span>
                                </div>
                                <span class="file-size">${formatFileSize(file.size_bytes)}</span>
                            `;

                            fileLi.addEventListener('click', () => {
                                openFileDetailsModal(proj.project_id, file);
                            });

                            filesUl.appendChild(fileLi);
                        });
                    }

                    // Add "+ Upload File" button under active/expanded project
                    const uploadBtnLi = document.createElement('li');
                    const uploadBtn = document.createElement('button');
                    uploadBtn.type = 'button';
                    uploadBtn.className = 'upload-file-tree-btn';
                    uploadBtn.innerHTML = `
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="12" y1="5" x2="12" y2="19"></line>
                            <line x1="5" y1="12" x2="19" y2="12"></line>
                        </svg>
                        <span>Upload File to Project</span>
                    `;
                    uploadBtn.addEventListener('click', () => {
                        const projFileInput = document.getElementById('project-file-input');
                        if (projFileInput) {
                            projFileInput.dataset.targetProjectId = proj.project_id;
                            projFileInput.click();
                        }
                    });

                    uploadBtnLi.appendChild(uploadBtn);
                    filesUl.appendChild(uploadBtnLi);
                }
            } catch (err) {
                console.warn(`Could not load files for project ${proj.project_id}:`, err);
            }

            projItem.appendChild(filesUl);
        }

        projectsTreeContainer.appendChild(projItem);
    }
}

/**
 * Binds active project workspace for current session.
 */
async function openProjectSession(projectId) {
    logDiagnosticState('openProjectSession', 'ENTER', `projectId=${projectId}`);
    try {
        const sessionId = activeConversationId || 'default';
        const res = await fetch(`${CONFIG.PROJECTS_API_URL}/${projectId}/open`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId })
        });
        if (res.ok) {
            const data = await res.json();
            activeProjectId = projectId;
            activeProjectMetadata = data.active_project;
            expandedProjectIds.add(projectId);
            logDiagnosticState('openProjectSession', 'SESSION_OPENED', `activeProjId=${activeProjectId}`);
            updateActiveProjectHeaderUI();
            await fetchProjectsList();
        }
    } catch (err) {
        console.error('Failed to open project workspace session:', err);
    }
    logDiagnosticState('openProjectSession', 'EXIT');
}

/**
 * Unbinds active project workspace for current session.
 */
async function closeProjectSession(projectId) {
    logDiagnosticState('closeProjectSession', 'ENTER', `projectId=${projectId}`);
    console.trace('[DIAGNOSTIC STACK TRACE] closeProjectSession caller');
    try {
        const sessionId = activeConversationId || 'default';
        await fetch(`${CONFIG.PROJECTS_API_URL}/${projectId}/close`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId })
        });
        activeProjectId = null;
        activeProjectMetadata = null;
        updateActiveProjectHeaderUI();
        await fetchProjectsList();
    } catch (err) {
        console.error('Failed to close project workspace session:', err);
    }
    logDiagnosticState('closeProjectSession', 'EXIT');
}

/**
 * Permanently deletes a project workspace.
 */
async function deleteProjectWorkspace(projectId) {
    const confirmDel = confirm(`Are you sure you want to permanently delete project workspace '${projectId}'?`);
    if (!confirmDel) return;

    try {
        const res = await fetch(`${CONFIG.PROJECTS_API_URL}/${projectId}`, { method: 'DELETE' });
        if (res.ok) {
            if (activeProjectId === projectId) {
                activeProjectId = null;
                activeProjectMetadata = null;
                updateActiveProjectHeaderUI();
            }
            await fetchProjectsList();
        }
    } catch (err) {
        console.error('Failed to delete project workspace:', err);
    }
}

/**
 * Uploads a file to a project workspace via REST API.
 */
async function uploadFileToWorkspace(file, targetProjectId = null) {
    const projId = targetProjectId || activeProjectId;
    if (!projId) {
        alert('Please open or create a Project Workspace in the sidebar before uploading files.');
        openCreateProjectModal();
        return;
    }

    const formData = new FormData();
    formData.append('file', file);
    formData.append('tags', 'uploaded');

    try {
        updateStatus('Uploading file...');
        const res = await fetch(`${CONFIG.PROJECTS_API_URL}/${projId}/files`, {
            method: 'POST',
            body: formData
        });

        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        const fileMeta = await res.json();
        updateStatus(CONFIG.STATUS.READY);

        // Automatically append clean attachment reference to prompt textarea
        attachFileReferenceToPrompt(fileMeta.filename, fileMeta.file_id);
        await fetchProjectsList();
    } catch (err) {
        console.error('File upload failed:', err);
        alert(`Failed to upload file: ${err.message}`);
        updateStatus(CONFIG.STATUS.ERROR);
    }
}

/**
 * Inserts a clean reference token into prompt input text.
 */
function attachFileReferenceToPrompt(filename, fileId) {
    if (!promptInput) return;
    const refToken = `[Attached: ${filename} (id: ${fileId})]`;
    if (!promptInput.value.includes(refToken)) {
        promptInput.value = (promptInput.value ? promptInput.value + ' ' + refToken : refToken).trim();
        autoResizeInput();
        promptInput.focus();
    }
}

/**
 * Opens Create Project modal dialog.
 */
function openCreateProjectModal() {
    if (createProjectModal) createProjectModal.classList.remove('hidden');
}

function closeCreateProjectModal() {
    if (createProjectModal) createProjectModal.classList.add('hidden');
}

/**
 * Handles Create Project Form Submission.
 */
async function handleCreateProjectSubmit(e) {
    e.preventDefault();
    const nameInput = document.getElementById('project-name-input');
    const descInput = document.getElementById('project-desc-input');
    const tagsInput = document.getElementById('project-tags-input');

    if (!nameInput || !nameInput.value.trim()) return;

    const tags = tagsInput && tagsInput.value.trim() ? tagsInput.value.split(',').map(t => t.trim()) : [];

    try {
        const payload = { name: nameInput.value.trim() };
        if (descInput && descInput.value.trim()) {
            payload.description = descInput.value.trim();
        }
        if (tags && tags.length > 0) {
            payload.tags = tags;
        }

        const res = await fetch(CONFIG.PROJECTS_API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const errData = await res.text();
            throw new Error(`HTTP ${res.status}: ${errData}`);
        }

        const newProj = await res.json();
        closeCreateProjectModal();
        nameInput.value = '';
        if (descInput) descInput.value = '';
        if (tagsInput) tagsInput.value = '';

        await openProjectSession(newProj.project_id);
    } catch (err) {
        console.error('Failed to create project:', err);
        alert(`Could not create project workspace: ${err.message}`);
    }
}

/**
 * Opens File Details Metadata Modal with Tab Support & PE Information Rendering.
 */
async function openFileDetailsModal(projectId, fileMeta) {
    if (!fileDetailsModal) return;

    selectedFileProjectId = projectId;
    selectedFileMeta = fileMeta;

    // Reset tab state to default "General Metadata"
    switchFileModalTab('tab-general');

    document.getElementById('modal-file-display-name').textContent = fileMeta.filename;
    document.getElementById('modal-file-id').textContent = fileMeta.file_id;
    document.getElementById('modal-file-size').textContent = formatFileSize(fileMeta.size_bytes);
    document.getElementById('modal-file-mime').textContent = fileMeta.mime_type || 'application/octet-stream';
    
    // 1. Initial UI binding from cached fileMeta.metadata (if valid and non-empty)
    const hasValidCachedMetadata = Boolean(
        fileMeta &&
        fileMeta.metadata &&
        typeof fileMeta.metadata === 'object' &&
        Object.keys(fileMeta.metadata).length > 0 &&
        fileMeta.metadata.md5
    );

    if (hasValidCachedMetadata) {
        renderGeneralMetadata({
            ...fileMeta.metadata,
            sha256: fileMeta.metadata.sha256 || fileMeta.sha256
        });
    } else {
        document.getElementById('modal-file-sha256').textContent = fileMeta.sha256 || '---';
        document.getElementById('modal-detected-type').textContent = 'Detecting...';
        document.getElementById('modal-detected-arch').textContent = 'N/A';
        document.getElementById('modal-file-md5').textContent = '---';
        document.getElementById('modal-file-sha1').textContent = '---';
        document.getElementById('modal-file-sha512').textContent = '---';
        document.getElementById('modal-file-entropy').textContent = 'Analyzing...';
        const entropyFill = document.getElementById('modal-entropy-fill');
        if (entropyFill) entropyFill.style.width = '0%';
        const statusBadge = document.getElementById('modal-analysis-status');
        if (statusBadge) {
            statusBadge.textContent = 'analyzing...';
            statusBadge.className = 'badge-tag yellow';
        }
    }

    fileDetailsModal.classList.remove('hidden');
    switchFileModalTab('tab-general');

    // 2. Fetch full versioned metadata from REST API endpoint
    try {
        const res = await fetch(`${CONFIG.PROJECTS_API_URL}/${projectId}/files/${fileMeta.file_id}/metadata`);
        if (res.ok) {
            const meta = await res.json();
            if (meta && (meta.md5 || meta.sha256)) {
                renderGeneralMetadata(meta);
            }
        }
    } catch (err) {
        console.error('Failed to fetch file analysis metadata:', err);
    }

    // 3. Fetch PE, ELF, Mach-O, Disassembly, and Ghidra payload endpoints in parallel
    const peTabBtn = document.getElementById('tab-btn-pe');
    const elfTabBtn = document.getElementById('tab-btn-elf');
    const machoTabBtn = document.getElementById('tab-btn-macho');
    const disasmTabBtn = document.getElementById('tab-btn-disasm');
    const ghidraTabBtn = document.getElementById('tab-btn-ghidra');
    const yaraTabBtn = document.getElementById('tab-btn-yara');

    const fileUrl = `${CONFIG.PROJECTS_API_URL}/${projectId}/files/${fileMeta.file_id}`;

    const [peRes, elfRes, machoRes, disasmRes, ghidraRes, yaraRes] = await Promise.allSettled([
        fetch(`${fileUrl}/pe`).then(r => r.ok ? r.json() : null),
        fetch(`${fileUrl}/elf`).then(r => r.ok ? r.json() : null),
        fetch(`${fileUrl}/macho`).then(r => r.ok ? r.json() : null),
        fetch(`${fileUrl}/disassembly`).then(r => r.ok ? r.json() : null),
        fetch(`${fileUrl}/ghidra`).then(r => r.ok ? r.json() : null),
        fetch(`${fileUrl}/yara`).then(r => r.ok ? r.json() : null),
    ]);

    // Handle PE payload
    if (peRes.status === 'fulfilled' && peRes.value && peRes.value.is_pe) {
        if (peTabBtn) peTabBtn.classList.remove('hidden');
        renderPeInformationUI(peRes.value);
    } else if (peTabBtn) {
        peTabBtn.classList.add('hidden');
    }

    // Handle ELF payload
    if (elfRes.status === 'fulfilled' && elfRes.value && elfRes.value.is_elf) {
        if (elfTabBtn) elfTabBtn.classList.remove('hidden');
        renderElfInformationUI(elfRes.value);
    } else if (elfTabBtn) {
        elfTabBtn.classList.add('hidden');
    }

    // Handle Mach-O payload
    if (machoRes.status === 'fulfilled' && machoRes.value && machoRes.value.is_macho) {
        if (machoTabBtn) machoTabBtn.classList.remove('hidden');
        renderMachoInformationUI(machoRes.value);
    } else if (machoTabBtn) {
        machoTabBtn.classList.add('hidden');
    }

    // Handle Disassembly payload
    if (disasmRes.status === 'fulfilled' && disasmRes.value && disasmRes.value.has_disassembly !== false && disasmRes.value.total_instructions > 0) {
        if (disasmTabBtn) disasmTabBtn.classList.remove('hidden');
        renderDisassemblyUI(disasmRes.value);
    } else if (disasmTabBtn) {
        disasmTabBtn.classList.add('hidden');
    }

    // Handle Ghidra payload
    if (ghidraRes.status === 'fulfilled' && ghidraRes.value && (ghidraRes.value.ghidra_available || ghidraRes.value.function_count > 0 || ghidraRes.value.status === 'analyzed')) {
        if (ghidraTabBtn) ghidraTabBtn.classList.remove('hidden');
        renderGhidraUI(ghidraRes.value);
    } else if (ghidraTabBtn) {
        ghidraTabBtn.classList.add('hidden');
    }

    // Handle YARA payload
    if (yaraRes.status === 'fulfilled' && yaraRes.value && yaraRes.value.engine === 'yara_analysis') {
        if (yaraTabBtn) yaraTabBtn.classList.remove('hidden');
        renderYaraUI(yaraRes.value);
    } else if (yaraTabBtn) {
        yaraTabBtn.classList.add('hidden');
    }
}

function closeFileDetailsModal() {
    const timestamp = new Date().toISOString().split('T')[1];
    console.log(
        `%c[MODAL TRACE ${timestamp}] closeFileDetailsModal() CALLED | activeProj=${activeProjectId} | conv=${activeConversationId} | selProj=${selectedFileProjectId} | selFile=${selectedFileMeta?.filename} | modalClass=${fileDetailsModal?.className} | modalHidden=${fileDetailsModal?.classList.contains('hidden')}`,
        'color: #ff0055; font-weight: bold; background: #330011; padding: 4px 8px; font-size: 14px;'
    );
    console.trace('[MODAL TRACE CALLSTACK] closeFileDetailsModal invocation');
    if (fileDetailsModal) fileDetailsModal.classList.add('hidden');
}

/**
 * Renders YARA Pattern Scanning Tab UI elements.
 */
function renderYaraUI(yaraData) {
    if (!yaraData) return;

    const statusBadge = document.getElementById('yara-val-status');
    if (statusBadge) {
        statusBadge.textContent = yaraData.scan_status || 'unknown';
        statusBadge.className = yaraData.scan_status === 'failed' ? 'badge-tag red' : 'badge-tag green';
    }

    document.getElementById('yara-val-loaded').textContent = yaraData.rules_loaded || 0;
    document.getElementById('yara-val-matches').textContent = yaraData.match_count || 0;
    document.getElementById('yara-val-time').textContent = `${yaraData.execution_time_ms || 0}ms`;

    const container = document.getElementById('yara-matches-container');
    if (!container) return;
    container.innerHTML = '';

    if (!yaraData.matches || yaraData.matches.length === 0) {
        container.innerHTML = `<p class="disasm-no-data">No YARA pattern matches detected.</p>`;
        return;
    }

    yaraData.matches.forEach(match => {
        const item = document.createElement('div');
        item.className = 'pe-import-card';
        
        let metaHtml = '';
        if (match.meta) {
            metaHtml = Object.entries(match.meta).map(([k, v]) => `<span class="badge-tag cyan">${escapeHtml(k)}: ${escapeHtml(String(v))}</span>`).join(' ');
        }
        let stringsHtml = '';
        if (match.strings && match.strings.length > 0) {
            stringsHtml = '<div style="margin-top: 8px;">';
            match.strings.forEach(s => {
                const offsets = s.instances.map(i => `0x${i.offset.toString(16)}`).join(', ');
                stringsHtml += `<div class="font-mono" style="font-size: 0.85rem; color: #a0aec0;">${escapeHtml(s.identifier)}: ${escapeHtml(offsets)}</div>`;
            });
            stringsHtml += '</div>';
        }

        item.innerHTML = `
            <div class="pe-import-header">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#00f2fe" stroke-width="2">
                    <path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"></path>
                    <line x1="4" y1="22" x2="4" y2="15"></line>
                </svg>
                <span>${escapeHtml(match.rule)} <span style="color:#a0aec0;font-size:0.9rem;">(Namespace: ${escapeHtml(match.namespace)})</span></span>
            </div>
            <div class="pe-import-funcs" style="padding-left: 24px; padding-bottom: 12px;">
                ${metaHtml}
                ${stringsHtml}
            </div>
        `;
        container.appendChild(item);
    });
}

/**
 * Renders General Metadata Tab UI elements.
 */
function renderGeneralMetadata(meta) {
    if (!meta) return;

    if (document.getElementById('modal-detected-type')) {
        document.getElementById('modal-detected-type').textContent = meta.detected_type || 'Unknown';
    }
    if (document.getElementById('modal-detected-arch')) {
        document.getElementById('modal-detected-arch').textContent = meta.detected_architecture || 'N/A';
    }

    const statusBadge = document.getElementById('modal-analysis-status');
    if (statusBadge) {
        statusBadge.textContent = meta.status || 'analyzed';
        statusBadge.className = meta.status === 'failed' ? 'badge-tag red' : 'badge-tag green';
    }

    // Cryptographic Hashes (MD5, SHA-1, SHA-256, SHA-512)
    if (document.getElementById('modal-file-md5')) {
        document.getElementById('modal-file-md5').textContent = meta.md5 || '---';
    }
    if (document.getElementById('modal-file-sha1')) {
        document.getElementById('modal-file-sha1').textContent = meta.sha1 || '---';
    }
    if (document.getElementById('modal-file-sha256')) {
        document.getElementById('modal-file-sha256').textContent = meta.sha256 || '---';
    }
    if (document.getElementById('modal-file-sha512')) {
        document.getElementById('modal-file-sha512').textContent = meta.sha512 || '---';
    }

    // Shannon Entropy Calculation & Progress Bar Rendering
    const entropyVal = typeof meta.entropy === 'number' ? meta.entropy : 0;
    const entropyText = document.getElementById('modal-file-entropy');
    const entropyFill = document.getElementById('modal-entropy-fill');
    
    if (entropyText) {
        entropyText.textContent = `${entropyVal.toFixed(4)} / 8.0000`;
    }

    if (entropyFill) {
        const percentage = Math.min(100, Math.max(0, (entropyVal / 8.0) * 100));
        entropyFill.style.width = `${percentage}%`;

        if (entropyVal > 7.2) {
            entropyFill.style.background = 'linear-gradient(90deg, #ff0055, #ff5500)';
        } else if (entropyVal > 6.0) {
            entropyFill.style.background = 'linear-gradient(90deg, #ffaa00, #ffff00)';
        } else {
            entropyFill.style.background = 'linear-gradient(90deg, #00f2fe, #4facfe)';
        }
    }
}

/**
 * Renders PE Information Tab UI elements.
 */
function renderPeInformationUI(peData) {
    const summary = peData.summary || {};
    
    document.getElementById('pe-val-arch').textContent = summary.architecture || 'N/A';
    document.getElementById('pe-val-subsystem').textContent = summary.subsystem || 'N/A';
    document.getElementById('pe-val-entrypoint').textContent = summary.entry_point || '0x00000000';
    document.getElementById('pe-val-imagebase').textContent = summary.image_base || '0x00000000';
    document.getElementById('pe-val-timestamp').textContent = summary.timestamp_iso || 'N/A';
    document.getElementById('pe-val-sections-count').textContent = summary.number_of_sections || 0;
    document.getElementById('pe-val-import-count').textContent = `${summary.imported_dll_count || 0} DLLs (${summary.total_import_count || 0} functions)`;
    document.getElementById('pe-val-export-count').textContent = summary.export_count || 0;

    // Render Section Table
    const tbody = document.getElementById('pe-sections-tbody');
    if (tbody) {
        tbody.innerHTML = '';
        const sections = peData.sections || [];
        
        if (sections.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No sections found</td></tr>`;
        } else {
            sections.forEach(sec => {
                const tr = document.createElement('tr');
                const entropyVal = typeof sec.entropy === 'number' ? sec.entropy : 0;
                
                tr.innerHTML = `
                    <td class="font-mono cyan-text"><strong>${escapeHtml(sec.name)}</strong></td>
                    <td class="font-mono">${formatFileSize(sec.virtual_size)}</td>
                    <td class="font-mono">${formatFileSize(sec.raw_size)}</td>
                    <td class="font-mono">${sec.virtual_address}</td>
                    <td class="font-mono">
                        <div class="table-entropy-cell">
                            <span>${entropyVal.toFixed(2)}</span>
                            <div class="mini-entropy-bar"><div class="mini-entropy-fill" style="width: ${(entropyVal / 8.0) * 100}%;"></div></div>
                        </div>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
    }

    // Render Imported DLLs List
    const importsList = document.getElementById('pe-imports-list');
    if (importsList) {
        importsList.innerHTML = '';
        const imports = peData.imports || [];

        if (imports.length === 0) {
            importsList.innerHTML = `<div class="pe-empty-notice">No imported DLLs recorded.</div>`;
        } else {
            imports.forEach(imp => {
                const item = document.createElement('div');
                item.className = 'pe-import-card';

                const funcsCount = imp.functions ? imp.functions.length : 0;
                const funcsSample = (imp.functions || []).slice(0, 10).map(f => f.name || `Ordinal #${f.ordinal}`).join(', ');
                const truncatedHint = funcsCount > 10 ? `... (+${funcsCount - 10} more)` : '';

                item.innerHTML = `
                    <div class="pe-import-header">
                        <span class="pe-dll-name font-mono">${escapeHtml(imp.dll)}</span>
                        <span class="badge-tag cyan">${funcsCount} functions</span>
                    </div>
                    <div class="pe-import-funcs-sample font-mono">${escapeHtml(funcsSample)}${truncatedHint}</div>
                `;
                importsList.appendChild(item);
            });
        }
    }
}

/**
 * Renders ELF Information Tab UI elements.
 */
function renderElfInformationUI(elfData) {
    const summary = elfData.summary || {};
    
    document.getElementById('elf-val-arch').textContent = summary.architecture || 'N/A';
    document.getElementById('elf-val-type').textContent = summary.type || 'N/A';
    document.getElementById('elf-val-bitness').textContent = `${summary.bitness || 0}-bit (${summary.endianness || 'N/A'})`;
    document.getElementById('elf-val-osabi').textContent = summary.os_abi || 'N/A';
    document.getElementById('elf-val-entrypoint').textContent = summary.entry_point || '0x00000000';
    document.getElementById('elf-val-interp').textContent = elfData.interpreter || 'None';
    document.getElementById('elf-val-sections-count').textContent = summary.section_count || 0;
    document.getElementById('elf-val-needed-count').textContent = summary.needed_libraries_count || 0;

    // Render ELF Section Table
    const tbody = document.getElementById('elf-sections-tbody');
    if (tbody) {
        tbody.innerHTML = '';
        const sections = elfData.section_headers || [];

        if (sections.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No section headers found</td></tr>`;
        } else {
            sections.forEach(sec => {
                const tr = document.createElement('tr');
                const entropyVal = typeof sec.entropy === 'number' ? sec.entropy : 0;
                
                tr.innerHTML = `
                    <td class="font-mono cyan-text"><strong>${escapeHtml(sec.name || '.unnamed')}</strong></td>
                    <td class="font-mono">${escapeHtml(sec.type)}</td>
                    <td class="font-mono">${sec.address}</td>
                    <td class="font-mono">${formatFileSize(sec.size)}</td>
                    <td class="font-mono">
                        <div class="table-entropy-cell">
                            <span>${entropyVal.toFixed(2)}</span>
                            <div class="mini-entropy-bar"><div class="mini-entropy-fill" style="width: ${(entropyVal / 8.0) * 100}%;"></div></div>
                        </div>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
    }

    // Render ELF Needed Libraries List
    const libsList = document.getElementById('elf-libraries-list');
    if (libsList) {
        libsList.innerHTML = '';
        const libs = elfData.dynamic_libraries || [];

        if (libs.length === 0) {
            libsList.innerHTML = `<div class="pe-empty-notice">No DT_NEEDED dynamic libraries recorded.</div>`;
        } else {
            libs.forEach(lib => {
                const item = document.createElement('div');
                item.className = 'pe-import-card';
                item.innerHTML = `<div class="pe-import-header"><span class="pe-dll-name font-mono">${escapeHtml(lib)}</span></div>`;
                libsList.appendChild(item);
            });
        }
    }
}

/**
 * Renders Mach-O Information Tab UI elements.
 */
function renderMachoInformationUI(machoData) {
    const summary = machoData.summary || {};

    document.getElementById('macho-val-arch').textContent = summary.architecture || 'N/A';
    document.getElementById('macho-val-filetype').textContent = summary.file_type || 'N/A';
    document.getElementById('macho-val-entrypoint').textContent = summary.entry_point || '0x00000000';
    document.getElementById('macho-val-uuid').textContent = summary.uuid || 'N/A';
    document.getElementById('macho-val-segment-count').textContent = summary.segment_count || 0;
    document.getElementById('macho-val-section-count').textContent = summary.section_count || 0;
    document.getElementById('macho-val-dylib-count').textContent = summary.dylib_count || 0;
    document.getElementById('macho-val-symbol-count').textContent = summary.symbol_count || 0;

    // Render Mach-O Sections Table
    const tbody = document.getElementById('macho-sections-tbody');
    if (tbody) {
        tbody.innerHTML = '';
        const sections = machoData.sections || [];

        if (sections.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No sections found</td></tr>`;
        } else {
            sections.forEach(sec => {
                const tr = document.createElement('tr');
                const entropyVal = typeof sec.entropy === 'number' ? sec.entropy : 0;

                tr.innerHTML = `
                    <td class="font-mono cyan-text"><strong>${escapeHtml(sec.section_name)}</strong></td>
                    <td class="font-mono">${escapeHtml(sec.segment_name)}</td>
                    <td class="font-mono">${sec.address}</td>
                    <td class="font-mono">${formatFileSize(sec.size)}</td>
                    <td class="font-mono">
                        <div class="table-entropy-cell">
                            <span>${entropyVal.toFixed(2)}</span>
                            <div class="mini-entropy-bar"><div class="mini-entropy-fill" style="width: ${(entropyVal / 8.0) * 100}%;"></div></div>
                        </div>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
    }

    // Render Mach-O Dynamic Libraries List
    const dylibList = document.getElementById('macho-libraries-list');
    if (dylibList) {
        dylibList.innerHTML = '';
        const dylibs = machoData.dynamic_libraries || [];

        if (dylibs.length === 0) {
            dylibList.innerHTML = `<div class="pe-empty-notice">No LC_LOAD_DYLIB dynamic libraries recorded.</div>`;
        } else {
            dylibs.forEach(lib => {
                const item = document.createElement('div');
                item.className = 'pe-import-card';
                item.innerHTML = `<div class="pe-import-header"><span class="pe-dll-name font-mono">${escapeHtml(lib)}</span></div>`;
                dylibList.appendChild(item);
            });
        }
    }
}

/**
 * Renders Disassembly Tab UI elements (Phase 2.5).
 */
function renderDisassemblyUI(data) {
    if (!data) return;

    // Summary fields
    const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    };

    setVal('disasm-val-arch', data.architecture || 'N/A');
    setVal('disasm-val-bitness', data.bitness ? `${data.bitness}-bit` : 'N/A');
    setVal('disasm-val-endian', data.endianness || 'N/A');
    setVal('disasm-val-entry', data.entry_point_hex || '---');
    setVal('disasm-val-capstone-ver', data.capstone_version || 'N/A');
    setVal('disasm-val-exec-time', data.execution_time_ms ? `${data.execution_time_ms}ms` : '---');

    // Statistics
    setVal('disasm-val-total-insn', data.total_instructions || 0);
    setVal('disasm-val-total-blocks', data.total_basic_blocks || 0);
    setVal('disasm-val-total-loops', data.total_loops_detected || 0);

    const sections = data.sections || {};
    const sectionNames = Object.keys(sections);
    setVal('disasm-val-sections-count', sectionNames.length);

    // Sections summary table
    const secTbody = document.getElementById('disasm-sections-tbody');
    if (secTbody) {
        secTbody.innerHTML = '';
        if (sectionNames.length === 0) {
            secTbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color: var(--text-muted);">No sections disassembled</td></tr>`;
        } else {
            sectionNames.forEach(name => {
                const sec = sections[name];
                const tr = document.createElement('tr');
                const coveragePct = typeof sec.coverage_percent === 'number' ? sec.coverage_percent.toFixed(1) + '%' : 'N/A';
                tr.innerHTML = `
                    <td class="font-mono cyan-text"><strong>${escapeHtml(name)}</strong></td>
                    <td class="font-mono">${sec.virtual_address_hex || '---'}</td>
                    <td class="font-mono">${formatFileSize(sec.raw_size || 0)}</td>
                    <td class="font-mono">${sec.total_instructions || 0}</td>
                    <td class="font-mono">${sec.total_basic_blocks || 0}</td>
                    <td class="font-mono">${sec.total_loops_detected || 0}</td>
                    <td class="font-mono">${coveragePct}</td>
                `;
                secTbody.appendChild(tr);
            });
        }
    }

    // Instruction listing — render first section, capped at 500 instructions for DOM performance
    const listingContainer = document.getElementById('disasm-listing-container');
    const listingSectionLabel = document.getElementById('disasm-listing-section-name');
    if (listingContainer) {
        listingContainer.innerHTML = '';
        const MAX_RENDER_INSTRUCTIONS = 500;
        const firstSectionName = sectionNames[0];
        if (firstSectionName && sections[firstSectionName]) {
            const sec = sections[firstSectionName];
            if (listingSectionLabel) listingSectionLabel.textContent = `(${firstSectionName})`;
            const instructions = sec.instructions || [];
            const renderCount = Math.min(instructions.length, MAX_RENDER_INSTRUCTIONS);

            for (let i = 0; i < renderCount; i++) {
                const insn = instructions[i];
                const row = document.createElement('div');
                row.className = 'disasm-insn-row';
                if (insn.is_branch || insn.is_call || insn.is_ret) {
                    row.classList.add('disasm-insn-branch');
                }
                if (insn.is_call) {
                    row.classList.add('disasm-insn-call');
                }

                const addrSpan = `<span class="disasm-addr">${insn.address_hex || '---'}</span>`;
                const bytesSpan = `<span class="disasm-bytes">${(insn.bytes_hex || '').substring(0, 24)}</span>`;
                const mnemonicSpan = `<span class="disasm-mnemonic">${escapeHtml(insn.mnemonic || '')}</span>`;
                const operandSpan = `<span class="disasm-operand">${escapeHtml(insn.op_str || '')}</span>`;

                let annotation = '';
                if (insn.branch_type) {
                    annotation = `<span class="disasm-annotation">${escapeHtml(insn.branch_type)}</span>`;
                }

                row.innerHTML = `${addrSpan}${bytesSpan}${mnemonicSpan}${operandSpan}${annotation}`;
                listingContainer.appendChild(row);
            }

            if (instructions.length > MAX_RENDER_INSTRUCTIONS) {
                const notice = document.createElement('div');
                notice.className = 'disasm-truncated-notice';
                notice.textContent = `Showing ${MAX_RENDER_INSTRUCTIONS} of ${instructions.length} instructions. Full data available via API.`;
                listingContainer.appendChild(notice);
            }
        } else {
            listingContainer.innerHTML = '<p class="disasm-no-data">No instructions decoded.</p>';
        }
    }

    // Loop detection results
    const loopsContainer = document.getElementById('disasm-loops-container');
    const noLoopsNotice = document.getElementById('disasm-no-loops');
    if (loopsContainer) {
        // Collect all loops from all sections
        const allLoops = [];
        sectionNames.forEach(name => {
            const sec = sections[name];
            if (sec.loops && sec.loops.length > 0) {
                sec.loops.forEach(loop => allLoops.push({ sectionName: name, ...loop }));
            }
        });

        if (allLoops.length === 0) {
            if (noLoopsNotice) noLoopsNotice.style.display = '';
        } else {
            if (noLoopsNotice) noLoopsNotice.style.display = 'none';
            // Clear previous content except the no-loops notice
            const existing = loopsContainer.querySelectorAll('.disasm-loop-card');
            existing.forEach(el => el.remove());

            allLoops.forEach((loop, idx) => {
                const card = document.createElement('div');
                card.className = 'disasm-loop-card';

                const headerAddr = loop.loop_header_address != null ? `0x${loop.loop_header_address.toString(16).padStart(16, '0')}` : '---';
                const latchAddr = loop.loop_latch_address != null ? `0x${loop.loop_latch_address.toString(16).padStart(16, '0')}` : '---';
                const boundStr = loop.bound_type === 'constant'
                    ? `Constant: ${loop.loop_bound_immediate}`
                    : loop.bound_type === 'variable'
                        ? `Variable: ${loop.loop_bound_register || 'N/A'}`
                        : 'Unknown';
                const anomalies = (loop.anomalies || []).join(', ') || 'None';

                card.innerHTML = `
                    <div class="disasm-loop-header">Loop #${idx + 1} <span class="disasm-loop-section">[${escapeHtml(loop.sectionName)}]</span></div>
                    <div class="meta-grid">
                        <div class="meta-item"><span class="meta-label">Header:</span><span class="meta-value font-mono cyan-text">${headerAddr}</span></div>
                        <div class="meta-item"><span class="meta-label">Latch:</span><span class="meta-value font-mono">${latchAddr}</span></div>
                        <div class="meta-item"><span class="meta-label">Branch:</span><span class="meta-value font-mono">${escapeHtml(loop.branch_mnemonic || '---')}</span></div>
                        <div class="meta-item"><span class="meta-label">Type:</span><span class="meta-value">${escapeHtml(loop.branch_type || '---')}</span></div>
                        <div class="meta-item"><span class="meta-label">Comparison:</span><span class="meta-value font-mono">${escapeHtml(loop.cmp_mnemonic || '---')} ${escapeHtml(loop.cmp_lhs || '')} ${loop.cmp_rhs ? ', ' + escapeHtml(loop.cmp_rhs) : ''}</span></div>
                        <div class="meta-item"><span class="meta-label">Bound:</span><span class="meta-value">${boundStr}</span></div>
                        <div class="meta-item"><span class="meta-label">Signed:</span><span class="meta-value">${loop.is_signed_comparison ? 'Yes' : 'No'}</span></div>
                        <div class="meta-item"><span class="meta-label">Anomalies:</span><span class="meta-value ${anomalies !== 'None' ? 'warning-text' : ''}">${anomalies}</span></div>
                    </div>
                `;
                loopsContainer.appendChild(card);
            });
        }
    }
}

/**
 * Renders Ghidra Decompiler Tab UI elements (Phase 2.6).
 */
function renderGhidraUI(data) {
    if (!data) return;

    const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    };

    setVal('ghidra-val-processor', data.processor || 'N/A');
    setVal('ghidra-val-language', data.language_id || 'N/A');
    setVal('ghidra-val-compiler', data.compiler_spec || 'N/A');
    setVal('ghidra-val-base', data.base_address || '0x00000000');
    setVal('ghidra-val-entry', data.entry_point || '0x00000000');
    setVal('ghidra-val-status', data.status || 'analyzed');
    setVal('ghidra-val-func-count', data.function_count || (data.functions ? data.functions.length : 0));
    setVal('ghidra-val-sym-count', data.symbol_count || (data.symbols ? data.symbols.length : 0));
    setVal('ghidra-val-exec-time', data.execution_time_ms ? `${data.execution_time_ms}ms` : '0ms');

    // Render Function List & Decompiler Viewer
    const funcListContainer = document.getElementById('ghidra-func-list-container');
    const decompCodeElement = document.getElementById('ghidra-decompiled-code');
    const selectedFuncNameElement = document.getElementById('ghidra-selected-func-name');

    if (funcListContainer) {
        funcListContainer.innerHTML = '';
        const functions = data.functions || [];

        if (functions.length === 0) {
            funcListContainer.innerHTML = `<div class="disasm-no-data">No functions recovered by Ghidra.</div>`;
            if (decompCodeElement) decompCodeElement.textContent = '// No decompiled code available.';
        } else {
            functions.forEach((func, idx) => {
                const item = document.createElement('div');
                item.className = 'ghidra-func-item' + (idx === 0 ? ' active' : '');
                item.innerHTML = `
                    <span class="font-mono cyan-text">${escapeHtml(func.name)}</span>
                    <span class="ghidra-func-addr font-mono">${escapeHtml(func.address)}</span>
                `;

                item.addEventListener('click', () => {
                    document.querySelectorAll('.ghidra-func-item').forEach(el => el.classList.remove('active'));
                    item.classList.add('active');
                    if (selectedFuncNameElement) selectedFuncNameElement.textContent = `Function: ${func.name} (${func.address})`;
                    if (decompCodeElement) decompCodeElement.textContent = func.decompiled_c_code || '// No decompiled pseudocode available for this function.';
                });

                funcListContainer.appendChild(item);
            });

            // Select first function by default
            if (functions[0]) {
                if (selectedFuncNameElement) selectedFuncNameElement.textContent = `Function: ${functions[0].name} (${functions[0].address})`;
                if (decompCodeElement) decompCodeElement.textContent = functions[0].decompiled_c_code || '// No decompiled pseudocode available for this function.';
            }
        }
    }

    // Render Symbols Table
    const symTbody = document.getElementById('ghidra-symbols-tbody');
    if (symTbody) {
        symTbody.innerHTML = '';
        const symbols = data.symbols || [];
        if (symbols.length === 0) {
            symTbody.innerHTML = `<tr><td colspan="3" style="text-align:center; color: var(--text-muted);">No symbols recovered</td></tr>`;
        } else {
            symbols.slice(0, 100).forEach(sym => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="font-mono cyan-text"><strong>${escapeHtml(sym.name)}</strong></td>
                    <td class="font-mono">${escapeHtml(sym.address)}</td>
                    <td class="font-mono">${escapeHtml(sym.type || 'DEFAULT')}</td>
                `;
                symTbody.appendChild(tr);
            });
        }
    }
}

/**
 * Switches File Details Modal Tabs.
 */
function switchFileModalTab(targetTabId) {
    if (!fileDetailsModal) return;

    const tabBtns = fileDetailsModal.querySelectorAll('.modal-tab-btn');
    const tabPanes = fileDetailsModal.querySelectorAll('.modal-tab-pane');

    tabBtns.forEach(btn => {
        if (btn.dataset.tab === targetTabId) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    tabPanes.forEach(pane => {
        if (pane.id === targetTabId) {
            pane.classList.remove('hidden');
            pane.classList.add('active');
        } else {
            pane.classList.add('hidden');
            pane.classList.remove('active');
        }
    });
}

function closeFileDetailsModal() {
    if (fileDetailsModal) fileDetailsModal.classList.add('hidden');
}

/**
 * Setup Event Listeners for Modals and Workspace Controls.
 */
function setupWorkspaceListeners() {
    if (newProjectBtn) newProjectBtn.addEventListener('click', openCreateProjectModal);

    const closeCreateBtn = document.getElementById('close-create-project-modal');
    const cancelCreateBtn = document.getElementById('cancel-create-project');
    if (closeCreateBtn) closeCreateBtn.addEventListener('click', closeCreateProjectModal);
    if (cancelCreateBtn) cancelCreateBtn.addEventListener('click', closeCreateProjectModal);

    if (createProjectForm) createProjectForm.addEventListener('submit', handleCreateProjectSubmit);

    const closeFileBtn = document.getElementById('close-file-modal');
    if (closeFileBtn) closeFileBtn.addEventListener('click', closeFileDetailsModal);

    // Modal Tab Click Delegator
    if (fileDetailsModal) {
        fileDetailsModal.addEventListener('click', (e) => {
            const tabBtn = e.target.closest('.modal-tab-btn');
            if (tabBtn && tabBtn.dataset.tab) {
                switchFileModalTab(tabBtn.dataset.tab);
            }
        });
    }

    // Copy hash button delegator
    if (fileDetailsModal) {
        fileDetailsModal.addEventListener('click', (e) => {
            const btn = e.target.closest('.copy-hash-btn');
            if (!btn) return;
            const targetId = btn.dataset.hashTarget;
            if (!targetId) return;
            const targetElem = document.getElementById(targetId);
            if (targetElem && targetElem.textContent && targetElem.textContent !== '---') {
                navigator.clipboard.writeText(targetElem.textContent.trim());
                alert(`Hash copied to clipboard!`);
            }
        });
    }

    const attachBtn = document.getElementById('btn-attach-to-chat');
    if (attachBtn) {
        attachBtn.addEventListener('click', () => {
            if (selectedFileMeta) {
                attachFileReferenceToPrompt(selectedFileMeta.filename, selectedFileMeta.file_id);
                closeFileDetailsModal();
            }
        });
    }

    const downloadBtn = document.getElementById('btn-download-file');
    if (downloadBtn) {
        downloadBtn.addEventListener('click', () => {
            if (selectedFileProjectId && selectedFileMeta) {
                window.open(`${CONFIG.PROJECTS_API_URL}/${selectedFileProjectId}/files/${selectedFileMeta.file_id}`);
            }
        });
    }

    const renameBtn = document.getElementById('btn-rename-file');
    if (renameBtn) {
        renameBtn.addEventListener('click', async () => {
            if (!selectedFileProjectId || !selectedFileMeta) return;
            const newName = prompt('Enter new display filename:', selectedFileMeta.filename);
            if (newName && newName.trim()) {
                try {
                    const res = await fetch(`${CONFIG.PROJECTS_API_URL}/${selectedFileProjectId}/files/${selectedFileMeta.file_id}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ new_filename: newName.trim() })
                    });
                    if (res.ok) {
                        const updated = await res.json();
                        selectedFileMeta = updated;
                        document.getElementById('modal-file-display-name').textContent = updated.filename;
                        await fetchProjectsList();
                    }
                } catch (err) {
                    console.error('Rename failed:', err);
                }
            }
        });
    }

    const deleteFileBtn = document.getElementById('btn-delete-file');
    if (deleteFileBtn) {
        deleteFileBtn.addEventListener('click', async () => {
            if (!selectedFileProjectId || !selectedFileMeta) return;
            const confirmDel = confirm(`Delete file '${selectedFileMeta.filename}' from project workspace?`);
            if (confirmDel) {
                try {
                    const res = await fetch(`${CONFIG.PROJECTS_API_URL}/${selectedFileProjectId}/files/${selectedFileMeta.file_id}`, {
                        method: 'DELETE'
                    });
                    if (res.ok) {
                        closeFileDetailsModal();
                        await fetchProjectsList();
                    }
                } catch (err) {
                    console.error('Delete file failed:', err);
                }
            }
        });
    }

    // Hidden input file listeners for project uploads
    const projFileInput = document.getElementById('project-file-input');
    if (projFileInput) {
        projFileInput.addEventListener('change', (e) => {
            if (e.target.files && e.target.files.length > 0) {
                const targetProjId = projFileInput.dataset.targetProjectId || activeProjectId;
                Array.from(e.target.files).forEach(f => uploadFileToWorkspace(f, targetProjId));
            }
        });
    }
}

/* ==========================================================================
   Chat & Message Rendering Logic
   ========================================================================== */

function appendMessagePlaceholder(sender, isUser = false, timestamp = null) {
    const messageElement = document.createElement('div');
    messageElement.className = `message ${isUser ? 'user-message' : 'assistant-message'}`;

    const headerElement = document.createElement('div');
    headerElement.className = 'message-header';

    const senderSpan = document.createElement('span');
    senderSpan.className = 'message-sender';
    senderSpan.textContent = sender;

    const timeSpan = document.createElement('span');
    timeSpan.className = 'message-time';
    timeSpan.textContent = timestamp || getCurrentTimestamp();

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

function renderMarkdown(markdownText) {
    if (!markdownText) return '';
    let rawHtml = markdownText;
    if (window.marked && typeof window.marked.parse === 'function') {
        rawHtml = window.marked.parse(markdownText);
    } else {
        return `<p>${escapeHtml(markdownText)}</p>`;
    }
    if (window.DOMPurify && typeof window.DOMPurify.sanitize === 'function') {
        return window.DOMPurify.sanitize(rawHtml);
    }
    return escapeHtml(markdownText);
}

function formatLangName(lang) {
    if (!lang) return 'Code';
    const l = lang.toLowerCase().trim();
    const map = {
        'js': 'JavaScript', 'py': 'Python', 'c': 'C', 'cpp': 'C++', 'json': 'JSON', 'sql': 'SQL', 'sh': 'Shell', 'asm': 'Assembly'
    };
    return map[l] || (l.charAt(0).toUpperCase() + l.slice(1));
}

function wrapCodeBlocksWithHeader(containerElement) {
    if (!containerElement) return;
    const preElements = containerElement.querySelectorAll('pre');
    preElements.forEach((preElement) => {
        if (preElement.parentElement.classList.contains('code-block-wrapper')) return;

        const codeElement = preElement.querySelector('code');
        let language = '';
        if (codeElement) {
            codeElement.classList.forEach((className) => {
                if (className.startsWith('language-')) {
                    language = className.replace('language-', '');
                }
            });
        }

        const wrapper = document.createElement('div');
        wrapper.className = 'code-block-wrapper';

        const header = document.createElement('div');
        header.className = 'code-block-header';

        const langSpan = document.createElement('span');
        langSpan.className = 'code-block-lang';
        langSpan.textContent = formatLangName(language);

        const copyBtn = document.createElement('button');
        copyBtn.type = 'button';
        copyBtn.className = 'copy-code-btn';
        copyBtn.setAttribute('aria-label', 'Copy code snippet to clipboard');
        copyBtn.innerHTML = `
            <svg class="copy-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
            <span class="copy-text">Copy code</span>
        `;

        header.appendChild(langSpan);
        header.appendChild(copyBtn);

        preElement.parentNode.insertBefore(wrapper, preElement);
        wrapper.appendChild(header);
        wrapper.appendChild(preElement);

        if (window.hljs && codeElement && !codeElement.classList.contains('hljs')) {
            window.hljs.highlightElement(codeElement);
        }
    });
}

function appendMessage(sender, text, isUser = false, timestamp = null) {
    const contentElement = appendMessagePlaceholder(sender, isUser, timestamp);
    contentElement.innerHTML = renderMarkdown(text);
    wrapCodeBlocksWithHeader(contentElement);
    updateWelcomeScreenState();
    scrollToBottom();
}

function updateWelcomeScreenState() {
    const emptyScreen = document.getElementById('empty-chat-screen');
    if (!emptyScreen) return;
    const hasMessages = messagesList && messagesList.children.length > 0;
    emptyScreen.style.display = hasMessages ? 'none' : 'flex';
}

function setupCopyButtonListener() {
    if (!messagesList) return;
    messagesList.addEventListener('click', (event) => {
        const copyBtn = event.target.closest('.copy-code-btn');
        if (!copyBtn) return;

        const wrapper = copyBtn.closest('.code-block-wrapper');
        if (!wrapper) return;

        const codeElement = wrapper.querySelector('pre code') || wrapper.querySelector('pre');
        if (!codeElement) return;

        const codeText = codeElement.innerText || codeElement.textContent;
        navigator.clipboard.writeText(codeText)
            .then(() => {
                const copyTextSpan = copyBtn.querySelector('.copy-text');
                const originalText = copyTextSpan ? copyTextSpan.textContent : 'Copy code';
                if (copyTextSpan) copyTextSpan.textContent = 'Copied!';
                copyBtn.classList.add('copied');

                setTimeout(() => {
                    if (copyTextSpan) copyTextSpan.textContent = originalText;
                    copyBtn.classList.remove('copied');
                }, 2000);
            })
            .catch((err) => console.error('Failed to copy code:', err));
    });
}

async function fetchAiResponse(promptText) {
    abortActiveStream();
    activeStreamController = new AbortController();

    setFormDisabledState(true);
    updateStatus(CONFIG.STATUS.THINKING);

    const assistantContentElement = appendMessagePlaceholder('Assistant', false);
    let rawAccumulatedText = '';
    let pendingRenderText = '';

    const processBuffer = () => {
        if (pendingRenderText !== rawAccumulatedText) {
            pendingRenderText = rawAccumulatedText;
            assistantContentElement.innerHTML = renderMarkdown(pendingRenderText);
            wrapCodeBlocksWithHeader(assistantContentElement);
            scrollToBottom();
        }
        activeRenderFrameId = null;
    };

    const scheduleRender = () => {
        if (!activeRenderFrameId) {
            activeRenderFrameId = requestAnimationFrame(processBuffer);
        }
    };

    try {
        const response = await fetch(CONFIG.ORCHESTRATE_API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: promptText,
                session_id: activeConversationId || 'default'
            }),
            signal: activeStreamController.signal
        });

        if (!response.ok) {
            throw new Error(`Server returned error status ${response.status}`);
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
                const trimmed = line.trim();
                if (!trimmed || !trimmed.startsWith('data:')) continue;
                const dataStr = trimmed.slice(5).trim();

                if (dataStr === '[DONE]') break;

                try {
                    const parsed = JSON.parse(dataStr);
                    if (parsed.content) {
                        rawAccumulatedText += parsed.content;
                        scheduleRender();
                    } else if (parsed.error) {
                        rawAccumulatedText += `\n\n**Error:** ${parsed.error}`;
                        scheduleRender();
                    }
                } catch (e) {
                    console.warn('Failed to parse SSE JSON chunk:', dataStr);
                }
            }
        }

        if (activeRenderFrameId) cancelAnimationFrame(activeRenderFrameId);
        processBuffer();

        if (activeConversationId) {
            const currentConv = conversations.find(c => c.id === activeConversationId);
            if (currentConv) {
                currentConv.messages.push({ sender: 'Assistant', content: rawAccumulatedText, isUser: false, timestamp: getCurrentTimestamp() });
                saveStateToStorage();
            }
        }

        setFormDisabledState(false);
        updateStatus(CONFIG.STATUS.READY);

    } catch (error) {
        if (error.name === 'AbortError') return;

        if (activeRenderFrameId) cancelAnimationFrame(activeRenderFrameId);
        assistantContentElement.innerHTML = `<p style="color: var(--status-danger);"><strong>Error:</strong> Failed to connect to local AI assistant API.</p>`;
        setFormDisabledState(false);
        updateStatus(CONFIG.STATUS.ERROR);
    } finally {
        activeStreamController = null;
    }
}

function handleUserSubmit(promptText) {
    if (!activeConversationId) {
        activeConversationId = `conv-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
        const newConv = {
            id: activeConversationId,
            title: generateTitleFromPrompt(promptText),
            createdAt: new Date().toISOString(),
            messages: []
        };
        conversations.unshift(newConv);
        saveStateToStorage();
        renderSidebarList();
    } else {
        const currentConv = conversations.find(c => c.id === activeConversationId);
        if (currentConv && currentConv.messages.length === 0) {
            currentConv.title = generateTitleFromPrompt(promptText);
            saveStateToStorage();
            renderSidebarList();
        }
    }

    const currentConv = conversations.find(c => c.id === activeConversationId);
    if (currentConv) {
        currentConv.messages.push({ sender: 'User', content: promptText, isUser: true, timestamp: getCurrentTimestamp() });
        saveStateToStorage();
    }

    appendMessage('User', promptText, true);

    if (promptInput) promptInput.value = '';
    autoResizeInput();

    fetchAiResponse(promptText);
}

function onFormSubmit(event) {
    event.preventDefault();
    const rawInput = promptInput ? promptInput.value : '';
    const trimmedInput = rawInput.trim();
    if (!trimmedInput) return;
    updateWelcomeScreenState();
    handleUserSubmit(trimmedInput);
}

function onInputKeyDown(event) {
    event.preventDefault ? null : null;
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        chatForm.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
    }
}

function autoResizeInput() {
    if (!promptInput) return;
    promptInput.style.height = 'auto';
    promptInput.style.height = `${promptInput.scrollHeight}px`;
}

function setupTelemetryDashboard() {
    const monitorBtn = document.getElementById('monitor-toggle-btn');
    const closeBtn = document.getElementById('close-monitor-btn');
    const dashboard = document.getElementById('status-dashboard');

    if (!monitorBtn || !dashboard) return;

    const toggle = () => dashboard.classList.toggle('open');
    monitorBtn.addEventListener('click', toggle);
    if (closeBtn) closeBtn.addEventListener('click', () => dashboard.classList.remove('open'));

    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
            e.preventDefault();
            toggle();
        }
    });
}

async function fetchHealthTelemetry() {
    const connVal = document.getElementById('telemetry-conn-val');
    const modelVal = document.getElementById('telemetry-model-val');
    const connDot = document.getElementById('telemetry-conn-dot');

    try {
        const res = await fetch('http://127.0.0.1:8000/health');
        if (res.ok) {
            const data = await res.json();
            if (connVal) connVal.textContent = '127.0.0.1:8000 (Healthy)';
            if (modelVal) modelVal.textContent = data.model || 'mannix-re:latest';
            if (connDot) connDot.className = 'telemetry-status-dot connected';
        }
    } catch (e) {
        if (connVal) connVal.textContent = '127.0.0.1:8000 (Offline)';
        if (connDot) connDot.className = 'telemetry-status-dot';
    }
}

function setupDragAndDropZone() {
    const dropzoneOverlay = document.getElementById('dropzone-overlay');
    const fileUploadBtn = document.getElementById('file-upload-btn');
    const fileInput = document.getElementById('file-input');

    if (!dropzoneOverlay || !promptInput) return;

    let dragTimer;

    window.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzoneOverlay.classList.add('drag-active');
        clearTimeout(dragTimer);
    });

    window.addEventListener('dragleave', (e) => {
        e.preventDefault();
        dragTimer = setTimeout(() => dropzoneOverlay.classList.remove('drag-active'), 100);
    });

    window.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzoneOverlay.classList.remove('drag-active');
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            Array.from(e.dataTransfer.files).forEach(f => uploadFileToWorkspace(f));
        }
    });

    if (fileUploadBtn && fileInput) {
        fileUploadBtn.addEventListener('click', () => {
            if (!activeProjectId) {
                openCreateProjectModal();
            } else {
                fileInput.click();
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files && e.target.files.length > 0) {
                Array.from(e.target.files).forEach(f => uploadFileToWorkspace(f));
            }
        });
    }
}

// --- Security Permission & Approval Controller Functions ---
let activeApprovalRequestId = null;

async function fetchPermissionStatus() {
    try {
        const response = await fetch(CONFIG.PERMISSIONS_API_URL);
        if (!response.ok) return;
        const data = await response.json();
        
        const modeSelect = document.getElementById('permission-mode-select');
        if (modeSelect && data.mode) {
            modeSelect.value = data.mode;
        }

        if (data.pending_approvals && data.pending_approvals.length > 0) {
            showApprovalModal(data.pending_approvals[0]);
        }
    } catch (e) {
        console.warn('[SECURITY] Failed to fetch permission status:', e);
    }
}

async function updatePermissionMode(mode) {
    try {
        const response = await fetch(`${CONFIG.PERMISSIONS_API_URL}/mode`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode: mode })
        });
        if (response.ok) {
            console.log(`[SECURITY] Execution mode updated to ${mode}`);
            fetchPermissionStatus();
        }
    } catch (e) {
        console.error('[SECURITY] Failed to update permission mode:', e);
    }
}

function showApprovalModal(req) {
    if (!req) return;
    activeApprovalRequestId = req.request_id;

    const modal = document.getElementById('approval-modal');
    const toolVal = document.getElementById('approval-tool-val');
    const cmdVal = document.getElementById('approval-command-val');
    const cwdVal = document.getElementById('approval-cwd-val');
    const srcVal = document.getElementById('approval-source-val');
    const timeoutVal = document.getElementById('approval-timeout-val');

    if (toolVal) toolVal.textContent = req.tool || '-';
    if (cmdVal) cmdVal.textContent = req.command || '-';
    if (cwdVal) cwdVal.textContent = req.cwd || '-';
    if (srcVal) srcVal.textContent = req.request_source || '-';
    if (timeoutVal) timeoutVal.textContent = `${req.timeout_seconds || 120} seconds`;

    if (modal) modal.classList.remove('hidden');
}

function hideApprovalModal() {
    activeApprovalRequestId = null;
    const modal = document.getElementById('approval-modal');
    if (modal) modal.classList.add('hidden');
}

async function submitApprovalDecision(action, scope = 'once') {
    if (!activeApprovalRequestId) return;
    try {
        const url = `${CONFIG.APPROVALS_API_URL}/${activeApprovalRequestId}/decision`;
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: action, scope: scope, session_id: activeConversationId || 'default' })
        });
        if (response.ok) {
            console.log(`[SECURITY] Submitted decision '${action}' (scope: ${scope}) for request ${activeApprovalRequestId}`);
            hideApprovalModal();
            fetchPermissionStatus();
        }
    } catch (e) {
        console.error('[SECURITY] Failed to submit approval decision:', e);
    }
}

function setupPermissionListeners() {
    const modeSelect = document.getElementById('permission-mode-select');
    if (modeSelect) {
        modeSelect.addEventListener('change', (e) => {
            updatePermissionMode(e.target.value);
        });
    }

    const onceBtn = document.getElementById('approval-once-btn');
    if (onceBtn) onceBtn.addEventListener('click', () => submitApprovalDecision('approve', 'once'));

    const sessionBtn = document.getElementById('approval-session-btn');
    if (sessionBtn) sessionBtn.addEventListener('click', () => submitApprovalDecision('approve', 'session'));

    const denyBtn = document.getElementById('approval-deny-btn');
    if (denyBtn) denyBtn.addEventListener('click', () => submitApprovalDecision('deny', 'once'));

    const closeBtn = document.getElementById('close-approval-modal-btn');
    if (closeBtn) closeBtn.addEventListener('click', hideApprovalModal);
}

function init() {
    if (window.marked && typeof window.marked.setOptions === 'function') {
        window.marked.setOptions({ gfm: true, breaks: true });
    }

    // FORENSIC DIAGNOSTIC SUITE
    window.addEventListener('error', (e) => {
        console.error('%c[GLOBAL ERROR CAUGHT]', 'color: #ff0055; font-weight: bold;', e.error || e.message, e.filename, `L${e.lineno}:${e.colno}`);
    });
    window.addEventListener('unhandledrejection', (e) => {
        console.error('%c[UNHANDLED REJECTION CAUGHT]', 'color: #ff0055; font-weight: bold;', e.reason);
    });

    if (fileDetailsModal) {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((m) => {
                const timestamp = new Date().toISOString().split('T')[1];
                console.log(
                    `%c[MUTATION OBSERVER ${timestamp}] type=${m.type} target=${m.target.id || m.target.className} attr=${m.attributeName} oldVal=${m.oldValue} isConnected=${fileDetailsModal.isConnected} isHidden=${fileDetailsModal.classList.contains('hidden')}`,
                    'color: #00ffaa; font-weight: bold; background: #002211; padding: 4px 8px; font-size: 14px;'
                );
                console.trace('[MUTATION OBSERVER CALLSTACK] DOM mutation trigger');
            });
        });
        observer.observe(fileDetailsModal, { attributes: true, attributeFilter: ['class', 'style', 'hidden'], childList: true, subtree: true, attributeOldValue: true });
        console.log('%c[DIAGNOSTIC] Comprehensive MutationObserver attached to #file-details-modal', 'color: #00f2fe; font-weight: bold;');
    }

    document.addEventListener('click', (e) => {
        const timestamp = new Date().toISOString().split('T')[1];
        if (fileDetailsModal && !fileDetailsModal.classList.contains('hidden')) {
            console.log(
                `%c[DOCUMENT CLICK ${timestamp}] target=${e.target.tagName}#${e.target.id}.${e.target.className} | modalContainsTarget=${fileDetailsModal.contains(e.target)}`,
                'color: #ffaa00;'
            );
        }
    }, true);

    loadStateFromStorage();
    setupSidebarListeners();
    setupWorkspaceListeners();
    setupPermissionListeners();
    setupCopyButtonListener();
    setupTelemetryDashboard();
    setupDragAndDropZone();

    renderSidebarList();
    fetchProjectsList();
    fetchPermissionStatus();

    if (activeConversationId) {
        loadConversation(activeConversationId);
    }
    updateWelcomeScreenState();

    if (chatForm) chatForm.addEventListener('submit', onFormSubmit);
    if (promptInput) {
        promptInput.addEventListener('keydown', onInputKeyDown);
        promptInput.addEventListener('input', autoResizeInput);
    }

    fetchHealthTelemetry();
    setInterval(fetchHealthTelemetry, 15000);
    updateStatus(CONFIG.STATUS.READY);
}

document.addEventListener('DOMContentLoaded', init);