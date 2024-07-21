document.addEventListener('DOMContentLoaded', function() {
    function listShares() {
        fetch('/list_all_shares', {
            method: 'GET'
        })
        .then(response => response.json())
        .then(data => {
            if (data.status !== 'success' || !Array.isArray(data.shares)) {
                throw new Error('Invalid data format');
            }

            const sharesBody = document.getElementById('shares_body');
            sharesBody.innerHTML = '';

            data.shares.forEach(share => {
                const row = document.createElement('tr');

                const ipCell = document.createElement('td');
                ipCell.textContent = share.server_ip;
                row.appendChild(ipCell);

                const nicknameCell = document.createElement('td');
                nicknameCell.textContent = share.nickname;
                row.appendChild(nicknameCell);

                const nameCell = document.createElement('td');
                nameCell.textContent = share.name;
                row.appendChild(nameCell);

                const letterCell = document.createElement('td');
                const select = document.createElement('select');
                fetch('/available_drive_letters', {
                    method: 'GET'
                })
                .then(response => response.json())
                .then(lettersData => {
                    if (lettersData.status === 'success') {
                        lettersData.letters.forEach(letter => {
                            const option = document.createElement('option');
                            option.value = letter;
                            option.textContent = letter;
                            select.appendChild(option);
                        });
                    }
                });
                letterCell.appendChild(select);
                row.appendChild(letterCell);

                const mountCell = document.createElement('td');
                const mountButton = document.createElement('button');
                
                const mountIcon = document.createElement('img');
                mountIcon.src = '/static/images/mount.png';
                mountIcon.alt = 'Mount';
                mountIcon.style.height = '20px';
                mountIcon.style.marginRight = '5px';
                
                mountButton.appendChild(mountIcon);
                mountButton.appendChild(document.createTextNode('Mount'));
                mountButton.onclick = () => mountShare(share.server_ip, share.name, select.value);
                
                mountCell.appendChild(mountButton);
                row.appendChild(mountCell);

                sharesBody.appendChild(row);
            });
        })
        .catch(error => {
            const sharesBody = document.getElementById('shares_body');
            sharesBody.innerHTML = '';
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.textContent = `Fetch error: ${error.message}`;
            cell.colSpan = 5;
            row.appendChild(cell);
            sharesBody.appendChild(row);
        });
    }

    function listMountedShares() {
        fetch('/list_mounted_shares', {
            method: 'GET'
        })
        .then(response => response.json())
        .then(data => {
            if (!Array.isArray(data)) {
                throw new Error('Invalid data format');
            }

            const mountedSharesBody = document.getElementById('mounted_shares_body');
            mountedSharesBody.innerHTML = '';

            data.forEach(share => {
                const row = document.createElement('tr');

                const ipCell = document.createElement('td');
                ipCell.textContent = share.server_ip;
                row.appendChild(ipCell);

                const nicknameCell = document.createElement('td');
                nicknameCell.textContent = share.nickname;
                row.appendChild(nicknameCell);

                const nameCell = document.createElement('td');
                nameCell.textContent = share.name;
                nameCell.classList.add('bold');
                row.appendChild(nameCell);

                const letterCell = document.createElement('td');
                const driveLetterSpan = document.createElement('span');
                driveLetterSpan.classList.add('bold');
                driveLetterSpan.textContent = share.drive_letter;
                letterCell.appendChild(driveLetterSpan);
                row.appendChild(letterCell);

                const unmountCell = document.createElement('td');
                const unmountButton = document.createElement('button');
                
                const unmountIcon = document.createElement('img');
                unmountIcon.src = '/static/images/unmount.png';
                unmountIcon.alt = 'Unmount';
                unmountIcon.style.height = '20px';
                unmountIcon.style.marginRight = '5px';
                
                unmountButton.appendChild(unmountIcon);
                unmountButton.appendChild(document.createTextNode('Unmount'));
                unmountButton.onclick = () => unmountShare(share.drive_letter);
                unmountCell.appendChild(unmountButton);
                row.appendChild(unmountCell);

                mountedSharesBody.appendChild(row);
            });
        })
        .catch(error => {
            const mountedSharesBody = document.getElementById('mounted_shares_body');
            mountedSharesBody.innerHTML = '';
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.textContent = `Fetch error: ${error.message}`;
            cell.colSpan = 5;
            row.appendChild(cell);
            mountedSharesBody.appendChild(row);
        });
    }

    function mountShare(serverIp, shareName, driveLetter) {
        fetch('/get_servers', {
            method: 'GET'
        })
        .then(response => response.json())
        .then(servers => {
            const server = servers.find(s => s.server_ip === serverIp);
            if (server) {
                fetch('/mount_share', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        username: server.username,
                        password: server.password,
                        server_ip: serverIp,
                        share_name: shareName,
                        drive_letter: driveLetter
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        listShares();
                        listMountedShares();
                    } else {
                        alert(`Error: ${data.output}`);
                    }
                });
            }
        });
    }

    function unmountShare(driveLetter) {
        if (driveLetter) {
            fetch('/unmount_share', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    drive_letter: driveLetter
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    listShares();
                    listMountedShares();
                } else {
                    alert(`Error: ${data.output}`);
                }
            });
        } else {
            alert('No drive letter assigned to this share.');
        }
    }

    function saveAsDefaultMappings() {
        fetch('/save_mapping_preset', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ preset_name: 'default' })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                alert('Mapping saved as default.');
            } else {
                alert(`Error: ${data.message}`);
            }
        });
    }

    function resetToDefaultMappings() {
        fetch('/load_default', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ preset_name: 'default' })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                listShares();
                listMountedShares();
            } else {
                alert(`Error: ${data.message}`);
            }
        });
    }

    function goToConfigServers() {
        window.location.href = '/config_servers';
    }

    listShares();
    listMountedShares();
    setInterval(listMountedShares, 5000); // Refresh mounted shares every 5 seconds

    window.saveAsDefaultMappings = saveAsDefaultMappings;
    window.resetToDefaultMappings = resetToDefaultMappings;
    window.goToConfigServers = goToConfigServers;
});
