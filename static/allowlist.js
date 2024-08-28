document.addEventListener("DOMContentLoaded", function() {
    fetchLists();
    setupSearch();
});

function fetchLists(page = 1, search = '') {
    fetch(`/api/paginated-list?list=allowlist&page=${page}&search=${search}`)
        .then(response => response.json())
        .then(data => {
            updateList('allowlistItems', data.list);
            updatePagination('allowlist', page, data.totalCount);
        })
        .catch(error => console.error('Error fetching allowlist:', error));
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
    const inputElement = document.getElementById('allowlistInput');
    const domain = inputElement.value.trim();
    if (domain) {
        fetch('/api/add', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ domain, list: 'allowlist' }),
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
        body: JSON.stringify({ domain, list: 'allowlist' }),
    }).then(() => fetchLists());
}

function downloadList() {
    window.location.href = `/api/download?list=allowlist`;
}

function uploadList() {
    const fileInput = document.getElementById('allowlistUpload');
    const file = fileInput.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    fetch('/api/upload?list=allowlist', {
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
    const searchInput = document.getElementById('allowlistSearch');
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
        button.addEventListener('click', () => fetchLists(i, document.getElementById('allowlistSearch').value.trim()));
        paginationContainer.appendChild(button);
    }
}
