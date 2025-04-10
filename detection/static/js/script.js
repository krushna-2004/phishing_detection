
// JavaScript to handle form validation
function validateForm(event) {
    var urlInput = document.getElementById("url-input").value;
    if (!urlInput) {
        event.preventDefault();  // Prevent form submission
        document.getElementById("error-message").textContent = "Please enter a URL to scan.";
    }
}
function togglePopup() {
    const popupOverlay = document.getElementById('popupOverlay');
    popupOverlay.classList.toggle('active');
}

function showSignIn() {
    document.getElementById('signinTab').classList.add('active');
    document.getElementById('signupTab').classList.remove('active');
    document.getElementById('signinContent').classList.add('active');
    document.getElementById('signupContent').classList.remove('active');
}

function showSignUp() {
    document.getElementById('signupTab').classList.add('active');
    document.getElementById('signinTab').classList.remove('active');
    document.getElementById('signupContent').classList.add('active');
    document.getElementById('signinContent').classList.remove('active');
}
