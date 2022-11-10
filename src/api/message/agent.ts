import { httpRequest } from "@the-bds-maneger/core-utils";
import { randomBytes } from "crypto";
import { format } from "util";
import { ApiClient } from "../apiClient";

export type playitAgentAccountStatus = {type: "agent-account-status"} & ({status: "no-account"}|{status: "guest-account", account_id: number, web_session_key: string}|{status: "unverified-account", account_id: number}|{status: "verified-account", account_id: number}|{
  status: "user-notice",
  message: string,
  notice_url: string,
  important: boolean,
  prevent_usage: boolean,
});

export class AgentApiRequest extends ApiClient {
  public path = "agent";
  public async get_control_addr() {
    return (await this.req<{control_address: string}>("get-control-address")).control_address;
  }

  public async sign_and_register(detail: {agent_version: 1, client_addr: string, tunnel_addr: string}) {
    return (await this.req<{data: string}>("sign-agent-register", detail)).data;
  }

  public async get_agent_account_status(){
    return this.req<playitAgentAccountStatus>("get-agent-account-status");
  }

  public async claim_agent_secret(clainUrlCallback: (url: string) => void) {
    const claimCode = randomBytes(5).toString("hex");
    const url = format("https://playit.gg/claim/%s?type=%s&name=%s", claimCode, "self-managed", `bdscore_agent`);
    if (clainUrlCallback) clainUrlCallback(url); else console.log("Playit claim url: %s", url);

    // Register to API
    let waitAuth = 0;
    let authAttempts = 0;
    async function getSecret(): Promise<{secret_key: string}> {
      return httpRequest.getJSON({url: `${this.api_base}/agent`, method: "POST", body: {type: "exchange-claim-for-secret", claim_key: claimCode}}).catch(async (err) => {
        if (err?.response?.statusCode === 404||err?.response?.statusCode === 401) {
          if (err.response.statusCode === 404) if (authAttempts++ > 225) throw new Error("client not open auth url");
          if (err.response.statusCode === 401) if (waitAuth++ > 16) throw new Error("Claim code not authorized per client");
          await new Promise(resolve => setTimeout(resolve, 500));
          return getSecret();
        }
        throw err;
      });
    }

    return (await getSecret()).secret_key;
  }

};