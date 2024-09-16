document.getElementById('register-form').addEventListener('submit', async function(event) {
    event.preventDefault();
    
    const username = document.getElementById('reg-username').value;
    const email = document.getElementById('reg-email').value;
    const password = document.getElementById('reg-password').value;

    try {
        const response = await fetch('http://localhost:5000/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, email, password })
        });

        const result = await response.json();
        document.getElementById('message').innerText = result.message;
    } catch (error) {
        document.getElementById('message').innerText = 'Error: ' + error.message;
    }
});

document.getElementById('login-form').addEventListener('submit', async function(event) {
    event.preventDefault();
    
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;

    try {
        const response = await fetch('http://localhost:5000/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        const result = await response.json();
        if (response.ok) {
            document.getElementById('message').innerText = 'Login successful! Access token: ' + result.access_token;
        } else {
            document.getElementById('message').innerText = result.message;
        }
    } catch (error) {
        document.getElementById('message').innerText = 'Error: ' + error.message;
    }
});

