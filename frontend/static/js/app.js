let ws;
let myName;

function joinChat() {
  myName = document.getElementById("username").value.trim();
  const room = document.getElementById("room").value.trim() || "general";
  if (!myName) return alert("Please enter your name");

  document.getElementById("setup").style.display = "none";
  document.getElementById("chatbox").style.display = "flex";
  document.getElementById("roomLabel").textContent = room;

  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(
    proto + "://" + location.host + "/ws?name=" + encodeURIComponent(myName) +
    "&room=" + encodeURIComponent(room)
  );

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    addMessage(data);
  };
}

function addMessage(data) {
  const li = document.createElement("li");

  if (data.type === "system") {
    li.className = "system";
    li.textContent = data.text;
  } else {
    li.className = data.user === myName ? "me" : "";

    let sigHtml = "";
    if (data.verified === true) {
      sigHtml = '<span class="sig-badge sig-ok">&#10003; verified</span>';
    } else if (data.verified === false) {
      sigHtml = '<span class="sig-badge sig-bad">&#9888; unverified</span>';
    }

    li.innerHTML =
      (data.user !== myName ? "<b>" + data.user + "</b><br>" : "") +
      data.text +
      '<span class="meta">' + data.time + sigHtml + "</span>";
  }

  document.getElementById("messages").appendChild(li);
  document.getElementById("messages").scrollTop = document.getElementById("messages").scrollHeight;
}

function send() {
  const input = document.getElementById("msg");
  if (input.value.trim() !== "") {
    ws.send(input.value);
    input.value = "";
  }
}
