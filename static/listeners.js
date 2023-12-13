window.addEventListener('load', function () {
    document.getElementById("toggle-password").addEventListener("change", function () {
        var current_password = document.getElementById("current_password");
        if (this.checked) {
            current_password.type = "text";
        } else {
            current_password.type = "password";
        }
    });
});