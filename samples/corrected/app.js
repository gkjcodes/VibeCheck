// Corrected JavaScript sample conforming to secure patterns
const STRIPE_SECRET = process.env.STRIPE_SECRET;

function renderUserData(userInput) {
    // Safe structured parsing
    const parsed = JSON.parse(userInput);

    // Safe textContent assignment
    const container = document.getElementById("profile");
    container.textContent = userInput;

    return parsed;
}
