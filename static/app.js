document.addEventListener("DOMContentLoaded", function() {
    const currentPage = localStorage.getItem('currentPage') || 1;
    fetchLists(currentPage);
    setupSearch();
});

function fetchLists(page = 1) {
    fetch(`/api/list?page=${page}`)
        .then(response => response.json())
        .then(data => {
            updateList('blocklistItems', data.blocklist);
            updateList('allowlistItems', data.allowlist);
            updatePagination(data.totalPages, page);
        })
        .catch(error => console.error('Error fetching lists:', error));
}

function updateList(listId, items) {
    const listElement = document.getElementById(listId);
    listElement.innerHTML = '';

    items.forEach(item => {
        const listItem = document.createElement('li');
        listItem.textContent = item;

        const removeButton = document.createElement('button');
        removeButton.textContent = '×';
        removeButton.className = 'remove-button';
        removeButton.onclick = () => removeDomain(item);

        listItem.appendChild(removeButton);
        listElement.appendChild(listItem);
    });
}

function addDomain() {
    const inputElement = document.getElementById('blocklistInput');
    const domain = inputElement.value.trim();
    if (domain) {
        fetch('/api/add', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ domain, list: 'blocklist' }),
        }).then(() => fetchLists());
        inputElement.value = '';
    }
}

function removeDomain(domain) {
    fetch('/api/remove', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ domain, list: 'blocklist' }),
    }).then(() => fetchLists());
}

function downloadList() {
    window.location.href = `/api/download?list=blocklist`;
}

function uploadList() {
    const fileInput = document.getElementById('blocklistUpload');
    const file = fileInput.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    fetch('/api/upload?list=blocklist', {
        method: 'POST',
        body: formData,
    })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to upload list');
            }
            fetchLists(); // Обновляем списки после загрузки
        })
        .catch(error => console.error('Error uploading list:', error));
}

function setupSearch() {
    const searchInput = document.getElementById('blocklistSearch');
    searchInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
            const searchQuery = searchInput.value.trim();
            fetchLists(1, searchQuery); // Сброс пагинации при поиске
        }
    });
}

function updatePagination(listId, currentPage, totalCount) {
    const paginationContainer = document.getElementById(`${listId}Pagination`);
    paginationContainer.innerHTML = '';

    const totalPages = Math.ceil(totalCount / 50);
    for (let i = 1; i <= totalPages; i++) {
        const button = document.createElement('button');
        button.textContent = i;
        button.className = 'pagination-button';
        button.dataset.page = i;
        if (i === currentPage) {
            button.disabled = true;
        }
        button.addEventListener('click', () => fetchLists(i, document.getElementById('blocklistSearch').value.trim()));
        paginationContainer.appendChild(button);
    }
}
