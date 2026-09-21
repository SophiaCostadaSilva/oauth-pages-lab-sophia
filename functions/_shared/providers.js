export const PROVIDERS = {
  google: {
    authorizationEndpoint:
      "https://accounts.google.com/o/oauth2/v2/auth",

    tokenEndpoint:
      "https://oauth2.googleapis.com/token",

    issuer:
      "https://accounts.google.com"
  },

  github: {
    authorizationEndpoint:
      "https://github.com/login/oauth/authorize",

    tokenEndpoint:
      "https://github.com/login/oauth/access_token",

    issuer:
      "https://github.com"
  }
};

export function isSupportedProvider(provider) {
  return provider === "google" || provider === "github";
}