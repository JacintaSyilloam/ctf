function addNote() {
    const note = document.getElementById("note").value;

    fetch("/", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            note: note
        })
    })
    .then((response) => response.json())
    .then((data) => {
        return window.location.href = `/${data.id}`;
    });
}

const submit = document.getElementById("submit");
if(submit) {
    submit.addEventListener("click", addNote);
}