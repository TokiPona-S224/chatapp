const inputMsg = document.querySelector(".chat-input");
const sendButton = document.querySelector(".send-button");
const chatMessages = document.querySelector(".chat-messages");
const currentUserName = document.getElementById("current-user-name");
const currentUserImage = document.getElementById("current-user-image");

// function to send a message
function sendMessage() {
    const message = inputMsg.value.trim();
    if (!message) return;
    inputMsg.value = "";
    chatMessages.appendChild(createMessageElement(message, "user"));
}

// create a message element
const createMessageElement = (message, className) => {
    const messageElmt = document.createElement("div");
    messageElmt.classList.add("chat-message", className);
    messageElmt.innerHTML = `<p>${message}</p>`;
    return messageElmt;
};

// sends a message on button click
sendButton.addEventListener("click", sendMessage);

// Send message on Enter key press
inputMsg.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        sendMessage();
    }
});

// add function for file transfer

// change the current user when a user item is clicked
document.querySelectorAll('.user-item').forEach(item => {
    item.addEventListener('click', function() {
        const username = this.querySelector('p').textContent;
        const userImage = this.querySelector('img').src;
        
        currentUserName.textContent = username;
        currentUserImage.src = userImage;
    });
});
