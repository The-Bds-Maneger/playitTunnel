import type { HTTPError } from "got";
import { httpRequest } from "@the-bds-maneger/core-utils";
import { format } from "node:util";
import { EventEmitter } from "node:events";
import crypto from "node:crypto";
// import dgram from "node:dgram";
// import net from "node:net";

export type agentSecret = {type: "agent-secret", secret_key: string};
export type tunnelType = "minecraft-java"|"minecraft-bedrock"|"valheim"|"terraria"|"starbound"|"rust"|"7days"|"unturned";

export type playitTunnelOptions = {secretKey: string, apiUrl?: string, controlAddress?: string, clientVersion?: string};
export type tunnelList = {
  type: "account-tunnels",
  agent_id: string,
  tunnels: {
    id: string,
    enabled: boolean,
    name?: string,
    ip_address: string,
    ip_hostname: string,
    custom_domain?: string,
    assigned_domain: string,
    display_address: string,
    is_dedicated_ip: boolean,
    from_port: number,
    to_port: number,
    tunnel_type: "minecraft-bedrock"|"minecraft-java",
    port_type: "udp"|"tcp"|"both",
    firewall_id?: string,
    protocol: {
      protocol: "to-agent",
      local_ip: string,
      local_port: number,
      agent_id: number
    }
  }[]
}

export type playitAgentAccountStatus = {type: "agent-account-status"} & ({status: "no-account"}|{status: "guest-account", account_id: number, web_session_key: string}|{status: "unverified-account", account_id: number}|{status: "verified-account", account_id: number}|{
  status: "user-notice",
  message: string,
  notice_url: string,
  important: boolean,
  prevent_usage: boolean,
});

export type agentConfig = {
  type: "agent-config",
  last_update: number,
  ping_targets: string[],
  ping_target_addresses: string[],
  control_address: string,
  refresh_from_api: true,
  secret_key: string,
  mappings: []
};

export type playitTunnelAuth = {
  type: "signed-tunnel-request",
  auth: {
    details: {
      account_id: number,
      request_timestamp: number,
      session_id: number
    },
    signature: {
      System: {
        signature: number[]
      }
    }
  },
  content: number[]
}


/**
 * Create a key to asynchronously authenticate playit.gg clients
 */
export async function playitClainSecret(clainUrlCallback?: (url: string) => void) {
  const claimCode = crypto.pseudoRandomBytes(5).toString("hex");
  const url = format("https://playit.gg/claim/%s?type=%s&name=%s", claimCode, "self-managed", `bdscore_agent`);
  if (clainUrlCallback) clainUrlCallback(url); else console.log("Playit claim url: %s", url);

  // Register to API
  let waitAuth = 0;
  let authAttempts = 0;
  async function getSecret(): Promise<agentSecret> {
    return httpRequest.getJSON({url: "https://api.playit.cloud/agent", method: "POST", headers: {}, body: {type: "exchange-claim-for-secret", claim_key: claimCode}}).catch(async (err: HTTPError) => {
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

export declare interface playit {
  // Error emit
  /** if an error occurs, it will be issued here, and if a callback is not added, an error will be thrown to the Nodejs process (`process.on("unhandledRejection")`) */
  on(act: "error", fn: (data: any) => void): this;
  /** if an error occurs, it will be issued here, and if a callback is not added, an error will be thrown to the Nodejs process (`process.once("unhandledRejection")`) */
  once(act: "error", fn: (data: any) => void): this;
  emit(act: "error", data: any): boolean;

  // User messages
  on(act: "message", fn: (data: string) => void): this;
  emit(act: "message", data: string): boolean;

  // Ping
  on(act: "ping", fn: (ms: number) => void): this;
  emit(act: "ping", ms: number): boolean;

  // Agent connect
  /** When the agent successfully authenticates, the agentConfig event will be emitted with the agent's information */
  on(act: "agentConfig", fn: (data: agentConfig) => void): this;
  /** When the agent successfully authenticates, the agentConfig event will be emitted with the agent's information */
  once(act: "agentConfig", fn: (data: agentConfig) => void): this;
  emit(act: "agentConfig", data: agentConfig): boolean;
}

/**
 * Create agent connection to playit
*/
export class playit extends EventEmitter {
  // Agent status
  public status: "conneted"|"waitting"|"disconnected" = "waitting";

  // url APIs
  public apiUrl = "api.playit.cloud";
  public controlAddress = "control.playit.gg";
  public clientVersion = "0.2.3";
  #Authorization: string
  // #secretKey: string;

  // agent Configs
  public agentConfig?: agentConfig;
  public playitTunnelAuth?: playitTunnelAuth;

  constructor(options: playitTunnelOptions) {
    super({captureRejections: false});
    options = {apiUrl: "api.playit.cloud", controlAddress: "control.playit.gg", clientVersion: "0.2.3", ...options};
    if (!options.secretKey) throw new Error("Required secret key to auth in playit.gg");
    // this.#secretKey = options.secretKey;
    this.#Authorization = format("agent-key %s", options.secretKey);
    this.apiUrl = options.apiUrl;
    this.controlAddress = options.controlAddress;
    this.clientVersion = options.clientVersion;
    const agent = format("https://%s/agent", this.apiUrl);

    // Agent
    (async () => {
      const Authorization = format("agent-key %s", options.secretKey);
      const accountInfo = await httpRequest.getJSON<playitAgentAccountStatus>({url: agent, method: "POST", headers: {Authorization}, body: {type: "get-agent-account-status", client_version: options.clientVersion}}).catch((err: HTTPError) => {
        try {
          const data: playitAgentAccountStatus = JSON.parse(err.response.body.toString());
          if (data.status === "no-account") return Promise.reject(new Error("No account registred"));
          else if (data.status === "user-notice") return Promise.reject(new Error(JSON.stringify(data)));
          else if (err.response.statusCode === 400) return Promise.reject(new Error("Secret key is invalid or not registred"));
        } catch {}
        throw err;
      });

      if (!(accountInfo.status === "verified-account"||accountInfo.status === "guest-account"||accountInfo.status === "user-notice")) throw new Error("Verify account fist");
      else if (accountInfo.status === "guest-account") this.emit("message", "Using guest account");
      else if (accountInfo.status === "user-notice") this.emit("message", accountInfo.message);

      // Load agent config
      this.agentConfig = await httpRequest.getJSON<agentConfig>({url: agent, method: "POST", headers: {Authorization}, body: {type: "get-agent-config", client_version: options.clientVersion}});
      this.emit("agentConfig", this.agentConfig);

      // ?
      this.playitTunnelAuth = await httpRequest.getJSON<playitTunnelAuth>({url: agent, method: "POST", headers: {Authorization}, body: { type: "sign-tunnel-request", RegisterAgent: null }}).catch(err => Promise.reject(err.response?.body?.toString()||err));
    })().catch(err => {
      this.status = "disconnected";
      return this.emit("error", err);
    }).then(() => {
      if (this.status !== "conneted") return;
      (async() => {
        while (true) {
          if (this.status !== "conneted") break;
          const data = (await httpRequest.bufferFetch(format("http://%s/", this.agentConfig.ping_target_addresses[0]||"ping.playit.gg"))).data.toString("utf8").split(/\r?\n/).map(line => line.trim().match(/^([a-z_0-9]+):\s(|[\s\S\W]+)$/)).map(data => {if (!data) return null; return {key: data[1], value: data[2]}}).reduce((mount, data) => {if (!data) return mount; mount[data.key] = data.value; return mount;}, {} as {[key: string]: string});
          this.emit("ping", parseInt(data.ping?.replace("ms", "")||"NaN"));
          await new Promise(done => setTimeout(done, 1200));
        }
      })();
    });
  }

  // Account
  async listTunnels() {
    const account = format("https://%s/account", this.apiUrl);
    const data = await httpRequest.getJSON<tunnelList>({
      url: account,
      method: "POST",
      headers: {Authorization: this.#Authorization},
      body: {
        type: "list-account-tunnels"
      }
    }).catch(err => Promise.reject(JSON.parse(err.response?.body?.toString())));
    data.tunnels = data.tunnels.filter(tunnel => (["minecraft-bedrock", "minecraft-java"]).includes(tunnel.tunnel_type));
    return data;
  }
  async createTunnel(options: {tunnelType?: tunnelType, name: string, portType: "tcp"|"udp"|"both", local: {ip?: string, port: number, count?: number}}) {
    const account = format("https://%s/account", this.apiUrl);
    const agent_id = (await this.listTunnels()).agent_id;
    const tunnelCreated = await httpRequest.getJSON<{ type: "created", id: string }>({
      url: account,
      method: "POST",
      headers: {Authorization: this.#Authorization},
      body: {
        // Agent request
        type: "create-tunnel",
        agent_id,

        // Tunnel to
        tunnel_type: options.tunnelType||null,
        name: options.name||crypto.randomBytes(8).toString("hex"),

        // Port config
        port_type: options.portType||"both",
        port_count: options?.local?.count||1,
        local_ip: options?.local?.ip||"0.0.0.0",
        local_port: options?.local?.port||null,
      }
    });
    return (await this.listTunnels()).tunnels.find(tunnel => tunnel.id === tunnelCreated.id);
  }

  async deleteTunnel(tunnelId: string) {
    if (!tunnelId) throw new Error("No tunnnel id");
    const account = format("https://%s/account", this.apiUrl);
    await httpRequest.getJSON<{ type: "created", id: string }>({
      url: account,
      method: "POST",
      headers: {Authorization: this.#Authorization},
      body: {
        type: "delete-tunnel",
        id: tunnelId
      }
    });
  }
};