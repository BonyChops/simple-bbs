document.body.onload = () => {
    var elements = document.getElementsByClassName("fade-in");
    for (const element of elements) {
        element.classList.add("fade-in-active");
        element.classList.remove("fade-in");
    }
    elements = document.getElementsByClassName("dropdown");
    for (const element of elements) {
        element.classList.add("dropdown-active");
        element.classList.remove("dropdown");
    }
}

function toggleLike(id) {
    console.log(id);
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
        switch (xhr.readyState) {
            case 0:
                // 未初期化状態.
                console.log('uninitialized!');
                break;
            case 1: // データ送信中.
                console.log('loading...');
                break;
            case 2: // 応答待ち.
                console.log('loaded.');
                break;
            case 3: // データ受信中.
                console.log('interactive... ' + xhr.responseText.length + ' bytes.');
                break;
            case 4: // データ受信完了.
                if (xhr.status == 200 || xhr.status == 304) {
                    var data = xhr.responseText; // responseXML もあり
                    console.log('COMPLETE! :' + data);
                } else {
                    console.log('Failed. HttpStatus: ' + xhr.statusText);
                }
                break;
        }
    }
    xhr.open('POST', `/api/post/${id}/like/toggle`, false);
    // POST 送信の場合は Content-Type は固定.
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.send('');
    xhr.abort();
}