"use strict";
/* Thème appliqué avant l'affichage (chargé dans <head>) : choix enregistré, sinon préférence système. */
(() => {
  const KEY = "pp-theme";
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  const saved = () => {
    try {
      return localStorage.getItem(KEY);
    } catch {
      return null;
    }
  };
  const apply = (theme) => {
    document.documentElement.dataset.theme = theme || (media.matches ? "dark" : "light");
  };

  apply(saved());
  media.addEventListener("change", () => saved() || apply(null));

  window.ppTheme = {
    get current() {
      return document.documentElement.dataset.theme;
    },
    toggle() {
      const next = this.current === "dark" ? "light" : "dark";
      try {
        localStorage.setItem(KEY, next);
      } catch {
        /* stockage indisponible : le choix vaut pour cette page seulement */
      }
      apply(next);
      return next;
    },
  };
})();
