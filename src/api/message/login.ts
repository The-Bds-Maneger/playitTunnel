import { ApiClient } from "../apiClient";

export type SessionStatus = {
  account_id: number,
  is_guest: boolean,
  email_verified: boolean,
  agent_id: string,
  notice?: {
    url: string,
    message: string
  },
};

export type WebSession = {
  account_id: number,
  session_key: string,
  is_guest: boolean,
  email_verified: boolean,
};

export default class login extends ApiClient {
  path = "login";
  async GetSession() {
    const data = await this.req<{SessionStatus}>("get-session");
    delete data["type"];
    return data;
  }
  async CreateGuestSession() {
    return this.req<WebSession>("create-guest-session");
  }
}