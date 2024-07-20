function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const encodedPassword = btoa(password); // Encode the password to base64

    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username: username,
            password: encodedPassword
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            window.location.href = '/list_shares';
        } else {
            alert('Login failed: ' + data.message);
        }
    });
}
