function readNotesFromStorage() {
    try {
        return JSON.parse(localStorage.getItem('myMessagesMeta') || '[]');
    } catch (_) {
        return [];
    }
}

function writeNotesToStorage(notes) {
    localStorage.setItem('myMessagesMeta', JSON.stringify(notes));
}

function renderNotes() {
    const list = document.getElementById('messagesList');
    if (!list) return;
    const notes = readNotesFromStorage();
    list.innerHTML = '';
    if (notes.length === 0) {
        list.innerHTML = '<div class="text-sm text-neutral-600">No messages yet.</div>';
        return;
    }
        notes
            .sort((a,b) => b.ts - a.ts)
            .forEach((n, idx) => {
            const row = document.createElement('div');
            row.className = 'flex items-center justify-between px-4 py-3' + (idx === 0 ? '' : ' border-t border-neutral-200');

                const left = document.createElement('div');
                left.className = 'text-sm text-neutral-800 truncate';
                const date = new Date(n.ts).toLocaleString();
                left.textContent = `[${date}] Message added`;

            const btn = document.createElement('button');
            btn.className = 'text-xs px-2 py-1 rounded-md border border-neutral-300 bg-white hover:bg-neutral-100';
                btn.textContent = 'View message';
                btn.addEventListener('click', () => {
                        window.location.href = '/' + encodeURIComponent(n.id);
                });

                row.appendChild(left);
                row.appendChild(btn);
                list.appendChild(row);
            });
}

function addNote() {
    const noteEl = document.getElementById('note');
    const note = (noteEl && noteEl.value) || '';

    fetch('/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note })
    })
    .then((response) => response.json())
    .then((data) => {
        if (!data || !data.id) return;
    // Add meta entry and re-render list; no redirect, no alert
        const notes = readNotesFromStorage();
        notes.push({ id: data.id, ts: Date.now() });
        writeNotesToStorage(notes);
        renderNotes();
        if (noteEl) noteEl.value = '';
    });
}

const submit = document.getElementById('submit');
if (submit) {
    submit.addEventListener('click', addNote);
}

document.addEventListener('DOMContentLoaded', renderNotes);