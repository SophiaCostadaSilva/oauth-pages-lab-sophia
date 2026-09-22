fetch("/api/me", {
  credentials: "same-origin"
})
  .then((response) =>
    response.ok
      ? response.json()
      : null
  )
  .then((user) => {
    const status =
      document.getElementById("status");

    const login =
      document.getElementById("login");

    const logout =
      document.getElementById("logout");

    if (user) {
      status.textContent =
        `Sessão de ${
          user.email ??
          user.displayName ??
          user.subject
        }.`;

      if (login) {
        login.hidden = true;
      }

      if (logout) {
        logout.hidden = false;
      }
    } else {
      status.textContent =
        "Nenhuma sessão neste navegador.";

      if (login) {
        login.hidden = false;
      }

      if (logout) {
        logout.hidden = true;
      }
    }
  })
  .catch(() => {
    const status =
      document.getElementById("status");

    if (status) {
      status.textContent =
        "Não foi possível consultar a sessão.";
    }
  });


const logout =
  document.getElementById("logout");

if (logout) {
  logout.addEventListener("click", async () => {
    const response =
      await fetch("/oauth/logout", {
        method: "POST",
        credentials: "same-origin"
      });

    if (response.ok) {
      window.location.href = "/";
    }
  });
}