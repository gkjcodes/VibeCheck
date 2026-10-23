// Synthetic vulnerable JavaScript sample for VibeCheck static analysis
const STRIPE_SECRET = "sk_test_51MzXYZ1234567890abcdef";

function renderUserData(userInput) {
    // Dangerous eval
    const computed = eval(userInput);

    // Unsafe innerHTML assignment
    const container = document.getElementById("profile");
    container.innerHTML = "<div>" + userInput + "</div>";

    return computed;
}
