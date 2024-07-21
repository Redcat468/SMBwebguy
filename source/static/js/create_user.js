document.addEventListener('DOMContentLoaded', function() {
    function fetchUsers() {
        fetch('/get_users')
            .then(response => response.json())
            .then(data => {
                const usersBody = document.getElementById('users_body');
                usersBody.innerHTML = '';
                data.users.forEach(user => {
                    const row = document.createElement('tr');

                    const usernameCell = document.createElement('td');
                    usernameCell.textContent = user.username;
                    row.appendChild(usernameCell);

                    const actionsCell = document.createElement('td');
                    const deleteButton = document.createElement('button');
                    deleteButton.textContent = 'Delete';
                    deleteButton.onclick = () => deleteUser(user.username);
                    actionsCell.appendChild(deleteButton);
                    row.appendChild(actionsCell);

                    usersBody.appendChild(row);
                });
            })
            .catch(error => console.error('Error fetching users:', error));
    }

    function createUser() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const encodedPassword = btoa(password);  // Encode password to base64

        fetch('/create_user', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: encodedPassword  // Use the encoded password
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                fetchUsers();
            } else {
                alert('Failed to create user: ' + data.message);
            }
        })
        .catch(error => console.error('Error creating user:', error));
    }

    function deleteUser(username) {
        if (confirm(`Are you sure you want to delete the user '${username}'?`)) {
            fetch('/delete_user', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username: username })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    fetchUsers();
                } else {
                    alert('Failed to delete user: ' + data.message);
                }
            })
            .catch(error => console.error('Error deleting user:', error));
        }
    }

    fetchUsers();

    window.createUser = createUser;
});
