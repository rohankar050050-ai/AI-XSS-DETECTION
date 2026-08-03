let currentMode = 'vulnerable';

function setMode(mode) {
    currentMode = mode;
    const buttons = document.querySelectorAll('.mode-btn');
    buttons.forEach(btn => {
        btn.classList.remove('active');
        if (btn.classList.contains(mode)) {
            btn.classList.add('active');
        }
    });
}

function testAttack(event) {
    event.preventDefault();
    const input = document.getElementById('attackInput').value;
    const encodedInput = encodeURIComponent(input);
    const url = `/search?mode=${currentMode}&q=${encodedInput}`;
    window.location.href = url;
}

function loadExample(payload) {
    document.getElementById('attackInput').value = payload;
}

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('testForm');
    const btnVulnerable = document.getElementById('btn-vulnerable');
    const btnSecure = document.getElementById('btn-secure');
    const exampleButtons = document.querySelectorAll('.example-btn');

    if (btnVulnerable) {
        btnVulnerable.addEventListener('click', () => setMode('vulnerable'));
    }

    if (btnSecure) {
        btnSecure.addEventListener('click', () => setMode('secure'));
    }

    if (form) {
        form.addEventListener('submit', testAttack);
    }

    exampleButtons.forEach(btn => {
        const payload = btn.getAttribute('data-example');
        if (payload) {
            btn.addEventListener('click', () => loadExample(payload));
        }
    });
});

