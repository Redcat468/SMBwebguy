function addServer() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const server_ip = document.getElementById('server_ip').value;
    const nickname = document.getElementById('nickname').value;

    fetch('/add_server', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username: username,
            password: password,
            server_ip: server_ip,
            nickname: nickname
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            loadServers();
        } else {
            alert(`Error: ${data.message}`);
        }
    });
}

function deleteServer(serverIp) {
    fetch('/delete_server', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            server_ip: serverIp
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            loadServers();
        } else {
            alert(`Error: ${data.message}`);
        }
    });
}

function loadServers() {
    fetch('/get_servers', {
        method: 'GET'
    })
    .then(response => response.json())
    .then(data => {
        const serversBody = document.getElementById('servers_body');
        serversBody.innerHTML = '';
        data.forEach(server => {
            const row = document.createElement('tr');

            const ipCell = document.createElement('td');
            ipCell.textContent = server.server_ip;
            row.appendChild(ipCell);

            const userCell = document.createElement('td');
            userCell.textContent = server.username;
            row.appendChild(userCell);

            const nicknameCell = document.createElement('td');
            nicknameCell.textContent = server.nickname;
            row.appendChild(nicknameCell);

            const actionsCell = document.createElement('td');
            const deleteButton = document.createElement('button');
            
            const deleteIcon = document.createElement('img');
            deleteIcon.src = '/static/images/delete.png';
            deleteIcon.alt = 'Delete';
            deleteIcon.style.height = '20px';
            deleteIcon.style.marginRight = '5px';
            
            deleteButton.appendChild(deleteIcon);
            deleteButton.appendChild(document.createTextNode('Remove'));
            deleteButton.className = 'btn btn-danger btn-custom';
            deleteButton.onclick = () => deleteServer(server.server_ip);
            
            actionsCell.appendChild(deleteButton);
            row.appendChild(actionsCell);

            serversBody.appendChild(row);
        });
    });
}

function goToListShares() {
    window.location.href = '/list_shares';
}

document.addEventListener('DOMContentLoaded', loadServers);
