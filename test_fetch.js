fetch('http://127.0.0.1:8000/api/projects', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        name: 'TEST_JS_DOM',
        description: '',
        tags: []
    })
}).then(async r => {
    console.log('STATUS:', r.status);
    console.log('BODY:', await r.text());
}).catch(err => {
    console.error('ERROR:', err);
});
