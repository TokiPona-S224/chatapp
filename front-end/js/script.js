
const inputMsg = document.querySelector(".chatinput");
const sendButton = document.querySelector(".fa-paper-plane"); // check if this is the correct name
const chatBody = document.querySelector(".chatsection-middle");
// variable to store the users message
let storeChat; 

// function to send a chat to the chat body
function sendMessage() {
    storeChat = inputMsg.value.trim(); 
    if (!storeChat) return;
    inputMsg.value = "";
    chatBody.appendChild(messageEl(storeChat, "user")); 
}

// displaying the sent message
const messageEl = (message, className) => {
    const chatElmt = document.createElement("div");
    chatElmt.classList.add("chat", `${className}`); 
    let chatContent = `<p>${message}</p>`;
    chatElmt.innerHTML = chatContent; // to set inner html of code
    return chatElmt;
};

// this isnt functioning as expected *fix this
sendButton.addEventListener("click", sendMessage);

inputMsg.addEventListener("input", (e) => {
    e.preventDefault();
    e.target.addEventListener("keydown", (keyboard) => {
      if (keyboard.key === "Enter") {
        sendMessage();
      }
    });
});

// Update the current user and handle clicks on sidebar
document.querySelectorAll('.username').forEach(item => {
    item.addEventListener('click', function() {
        const username = this.querySelector('p').textContent;
        document.getElementById('current-user').textContent = username;
    });
});